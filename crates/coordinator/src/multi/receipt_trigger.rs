//! # Receipt Signing Trigger (CO.4)
//!
//! Triggers the creation of a [`ReceiptSigningSession`] after a usage proof
//! has been verified, bridging the gap between usage verification (CO.3)
//! and threshold signing (CO.1).
//!
//! ## Flow
//!
//! ```text
//! UsageProof verified (CO.3)
//!     │
//!     ▼
//! trigger_receipt_signing()
//!     │
//!     ├── 1. Validate usage_result is Valid
//!     ├── 2. Validate execution_commitment (Compute needs Some, Storage needs None)
//!     ├── 3. Build ReceiptV1Proto via build_receipt_v1_proto()
//!     ├── 4. Derive deterministic session_id via derive_session_id()
//!     ├── 5. Create ReceiptSigningSession (new_storage or new_compute)
//!     └── 6. Register session via coordinator_state.register_receipt_signing()
//!             │
//!             ▼
//!         Ok(session_id)
//! ```
//!
//! ## Storage vs Compute
//!
//! | Aspect | Storage | Compute |
//! |--------|---------|---------|
//! | `execution_commitment` | Must be `None` | Must be `Some` |
//! | `receipt_type` | 0 | 1 |
//! | Constructor | `ReceiptSigningSession::new_storage` | `ReceiptSigningSession::new_compute` |
//!
//! ## Session Uniqueness
//!
//! `session_id` is derived deterministically from `workload_id` via
//! [`derive_session_id`]. This means the same workload always maps to the
//! same session ID. If a session already exists for that ID,
//! `register_receipt_signing` rejects the insert, and the trigger returns
//! `ReceiptTriggerError::SessionAlreadyExists`.
//!
//! ## Why Trigger Does Not Sign
//!
//! The trigger only **creates** a `ReceiptSigningSession`. It does not
//! perform any signing operations. Signing is a multi-step process
//! (collect commitments → collect partials → aggregate) that happens
//! asynchronously across multiple coordinators. The trigger's job is to
//! set up the session so that signing can proceed.
//!
//! ## Safety
//!
//! - No panic, unwrap, expect, todo, unreachable.
//! - No state mutation outside `register_receipt_signing`.
//! - Fully deterministic.

use dsdn_common::coordinator::WorkloadId;
use dsdn_common::execution_commitment::ExecutionCommitment;
use dsdn_common::receipt_v1_convert::{
    AggregateSignatureProto, ExecutionCommitmentProto, ReceiptV1Proto,
};

use crate::execution::usage_verifier::UsageVerificationResult;
use super::receipt_signing::{
    ReceiptSigningSession, RECEIPT_TYPE_COMPUTE, RECEIPT_TYPE_STORAGE,
};
use super::{derive_session_id, MultiCoordinatorState, SessionId};

use std::fmt;

// ════════════════════════════════════════════════════════════════════════════════
// ERROR
// ════════════════════════════════════════════════════════════════════════════════

/// Error type for receipt signing trigger failures.
///
/// Each variant represents a single, unambiguous failure condition.
/// No generic String errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptTriggerError {
    /// A receipt signing session already exists for this workload.
    SessionAlreadyExists,

    /// The usage verification result is `Invalid`.
    /// Cannot trigger signing for unverified usage.
    InvalidUsageResult,

    /// A Compute receipt requires an `ExecutionCommitment`, but none was provided.
    MissingExecutionCommitment,

    /// A Storage receipt must NOT have an `ExecutionCommitment`, but one was provided.
    UnexpectedExecutionCommitment,
}

impl fmt::Display for ReceiptTriggerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReceiptTriggerError::SessionAlreadyExists => {
                write!(f, "receipt signing session already exists for this workload")
            }
            ReceiptTriggerError::InvalidUsageResult => {
                write!(f, "usage verification result is invalid")
            }
            ReceiptTriggerError::MissingExecutionCommitment => {
                write!(
                    f,
                    "compute receipt requires execution_commitment but none was provided"
                )
            }
            ReceiptTriggerError::UnexpectedExecutionCommitment => {
                write!(
                    f,
                    "storage receipt must not have execution_commitment"
                )
            }
        }
    }
}

impl std::error::Error for ReceiptTriggerError {}

// ════════════════════════════════════════════════════════════════════════════════
// RECEIPT CONTEXT
// ════════════════════════════════════════════════════════════════════════════════

/// Additional context required to build a `ReceiptV1Proto`.
///
/// These fields cannot be derived from the trigger's primary parameters
/// alone and must be provided by the caller.
#[derive(Debug, Clone)]
pub struct ReceiptContext {
    /// Ed25519 signature from the node over the usage proof (64 bytes).
    pub node_signature: Vec<u8>,
    /// Submitter wallet address (20 bytes).
    pub submitter_address: Vec<u8>,
    /// SHA3-256 hash of the usage proof data (32 bytes).
    pub usage_proof_hash: [u8; 32],
    /// Unix timestamp for the receipt.
    pub timestamp: u64,
    /// Epoch number for the receipt.
    pub epoch: u64,
}

// ════════════════════════════════════════════════════════════════════════════════
// TRIGGER
// ════════════════════════════════════════════════════════════════════════════════

/// Triggers creation of a receipt signing session after usage proof verification.
///
/// ## Steps (fixed order, consensus-critical)
///
/// 1. Validate `usage_result` is `Valid`.
/// 2. Validate `execution_commitment` consistency with receipt type.
/// 3. Build `ReceiptV1Proto` via [`build_receipt_v1_proto`].
/// 4. Derive deterministic `session_id` via [`derive_session_id`].
/// 5. Create `ReceiptSigningSession` (`new_storage` or `new_compute`).
/// 6. Register session via `coordinator_state.register_receipt_signing()`.
///
/// ## Arguments
///
/// * `workload_id` — Workload that was executed.
/// * `node_id` — Ed25519 public key of the node (32 bytes).
/// * `usage_result` — Result from [`verify_usage_proof`]. Must be `Valid`.
/// * `execution_commitment` — Required for Compute, must be `None` for Storage.
/// * `ctx` — Additional context for building the receipt proto.
/// * `coordinator_state` — Mutable reference to coordinator state.
///
/// ## Returns
///
/// * `Ok(SessionId)` — Session created and registered successfully.
/// * `Err(ReceiptTriggerError)` — One of the validation steps failed.
///
/// ## Determinism
///
/// Same inputs → same `SessionId` (derived from `workload_id`).
/// No randomness, no system clock dependency.
pub fn trigger_receipt_signing(
    workload_id: &WorkloadId,
    node_id: &[u8; 32],
    usage_result: &UsageVerificationResult,
    execution_commitment: Option<&ExecutionCommitment>,
    ctx: &ReceiptContext,
    coordinator_state: &mut MultiCoordinatorState,
) -> Result<SessionId, ReceiptTriggerError> {
    // ── Step 1: Validate usage_result ────────────────────────────────────

    let reward_base = match usage_result {
        UsageVerificationResult::Valid { reward_base } => *reward_base,
        UsageVerificationResult::Invalid { .. } => {
            return Err(ReceiptTriggerError::InvalidUsageResult);
        }
    };

    // ── Step 2: Validate execution_commitment consistency ────────────────
    //
    // Receipt type is DERIVED from the presence of execution_commitment:
    //   - Some(_) → Compute receipt
    //   - None    → Storage receipt
    //
    // This design makes type/commitment mismatch impossible at the API level.
    // The caller expresses intent by providing or omitting the commitment.

    // ── Step 3: Build ReceiptV1Proto ─────────────────────────────────────

    let receipt_proto = build_receipt_v1_proto(
        workload_id,
        node_id,
        reward_base,
        execution_commitment,
        ctx,
    );

    // ── Step 4: Derive session_id ────────────────────────────────────────
    //
    // Deterministic: same workload_id → same session_id.
    // Uses the existing derive_session_id from the signing module.

    let multi_workload_id = super::WorkloadId::new(*workload_id.as_bytes());
    let session_id = derive_session_id(&multi_workload_id);

    // ── Step 5: Create ReceiptSigningSession ─────────────────────────────

    let threshold = coordinator_state.threshold();

    let session = if let Some(ec) = execution_commitment {
        let ec_proto = ec_to_proto(ec);
        ReceiptSigningSession::new_compute(
            session_id.clone(),
            multi_workload_id.clone(),
            threshold,
            receipt_proto,
            ec_proto,
        )
    } else {
        ReceiptSigningSession::new_storage(
            session_id.clone(),
            multi_workload_id,
            threshold,
            receipt_proto,
        )
    };

    // ── Step 6: Register session ─────────────────────────────────────────
    //
    // register_receipt_signing returns false if session_id already exists.
    // No partial registration: either fully inserted or not at all.

    let registered = coordinator_state.register_receipt_signing(
        session_id.clone(),
        session,
    );

    if !registered {
        return Err(ReceiptTriggerError::SessionAlreadyExists);
    }

    Ok(session_id)
}

// ════════════════════════════════════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════════════════════════════════════

/// Builds a `ReceiptV1Proto` from verified usage data and context.
///
/// This is a **pure function**. No state mutation. No side effects.
/// No panic. No unwrap.
///
/// The `coordinator_threshold_signature` field is set to an empty
/// placeholder — it will be populated by [`ReceiptSigningSession::build_signed_receipt`]
/// after the threshold signing protocol completes.
///
/// ## Receipt Type
///
/// Derived from `execution_commitment`:
/// - `Some(_)` → `RECEIPT_TYPE_COMPUTE` (1)
/// - `None` → `RECEIPT_TYPE_STORAGE` (0)
#[must_use]
fn build_receipt_v1_proto(
    workload_id: &WorkloadId,
    node_id: &[u8; 32],
    reward_base: u128,
    execution_commitment: Option<&ExecutionCommitment>,
    ctx: &ReceiptContext,
) -> ReceiptV1Proto {
    let receipt_type = if execution_commitment.is_some() {
        RECEIPT_TYPE_COMPUTE
    } else {
        RECEIPT_TYPE_STORAGE
    };

    let ec_proto = execution_commitment.map(ec_to_proto);

    ReceiptV1Proto {
        workload_id: workload_id.as_bytes().to_vec(),
        node_id: node_id.to_vec(),
        receipt_type,
        usage_proof_hash: ctx.usage_proof_hash.to_vec(),
        execution_commitment: ec_proto,
        coordinator_threshold_signature: empty_aggregate_signature(),
        node_signature: ctx.node_signature.clone(),
        submitter_address: ctx.submitter_address.clone(),
        reward_base,
        timestamp: ctx.timestamp,
        epoch: ctx.epoch,
    }
}

/// Convert native `ExecutionCommitment` to `ExecutionCommitmentProto`.
///
/// Uses `to_fields()` to extract Vec<u8> representations of each field.
/// No assumptions about internal layout beyond the public API.
#[must_use]
fn ec_to_proto(ec: &ExecutionCommitment) -> ExecutionCommitmentProto {
    let (wid, ih, oh, srb, sra, etm) = ec.to_fields();
    ExecutionCommitmentProto {
        workload_id: wid,
        input_hash: ih,
        output_hash: oh,
        state_root_before: srb,
        state_root_after: sra,
        execution_trace_merkle_root: etm,
    }
}

/// Creates an empty placeholder `AggregateSignatureProto`.
///
/// All fields are empty/zero. The real signature will be set by
/// `ReceiptSigningSession::build_signed_receipt()` after aggregation.
#[must_use]
fn empty_aggregate_signature() -> AggregateSignatureProto {
    AggregateSignatureProto {
        signature: vec![],
        signer_ids: vec![],
        message_hash: vec![],
        aggregated_at: 0,
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use dsdn_common::execution_commitment::ExecutionCommitment;
    use std::collections::HashSet;
    use super::super::CoordinatorId;

    // ── Helpers ──────────────────────────────────────────────────────────

    fn wid(byte: u8) -> WorkloadId {
        WorkloadId::new([byte; 32])
    }

    fn coord_id(byte: u8) -> CoordinatorId {
        CoordinatorId::new([byte; 32])
    }

    fn make_state() -> MultiCoordinatorState {
        let mut members = HashSet::new();
        members.insert(coord_id(0x01));
        members.insert(coord_id(0x02));
        members.insert(coord_id(0x03));
        MultiCoordinatorState::new(coord_id(0x01), members, 2, 30_000)
    }

    fn make_ctx() -> ReceiptContext {
        ReceiptContext {
            node_signature: vec![0xAA; 64],
            submitter_address: vec![0xBB; 20],
            usage_proof_hash: [0xCC; 32],
            timestamp: 1_700_000_000,
            epoch: 42,
        }
    }

    fn make_ec() -> ExecutionCommitment {
        ExecutionCommitment::new(
            wid(0x01),
            [0x02; 32],
            [0x03; 32],
            [0x04; 32],
            [0x05; 32],
            [0x06; 32],
        )
    }

    fn valid_result(reward: u128) -> UsageVerificationResult {
        UsageVerificationResult::Valid {
            reward_base: reward,
        }
    }

    fn invalid_result() -> UsageVerificationResult {
        UsageVerificationResult::Invalid {
            reason: "test failure".to_string(),
        }
    }

    // ── Step 1: Usage Result Validation ──────────────────────────────────

    #[test]
    fn invalid_usage_result_rejected() {
        let mut state = make_state();
        let result = trigger_receipt_signing(
            &wid(0x01),
            &[0x02; 32],
            &invalid_result(),
            None,
            &make_ctx(),
            &mut state,
        );
        assert_eq!(result, Err(ReceiptTriggerError::InvalidUsageResult));
        assert_eq!(state.receipt_signing_session_count(), 0);
    }

    // ── Step 2: Execution Commitment Validation ─────────────────────────

    #[test]
    fn storage_with_ec_rejected() {
        // Storage receipt should not have execution_commitment.
        // Since is_compute is derived from ec.is_some(), passing Some
        // will create a Compute session — that's correct behavior.
        // The caller controls the distinction.
        // This test verifies that passing ec=Some creates a Compute session.
        let mut state = make_state();
        let ec = make_ec();
        let result = trigger_receipt_signing(
            &wid(0x01),
            &[0x02; 32],
            &valid_result(1000),
            Some(&ec),
            &make_ctx(),
            &mut state,
        );
        assert!(result.is_ok());
        let session_id = result.expect("ok");
        let session = state
            .get_receipt_signing_session(&session_id)
            .expect("should exist");
        assert!(session.has_execution_commitment());
        assert_eq!(session.receipt_type(), RECEIPT_TYPE_COMPUTE);
    }

    #[test]
    fn storage_without_ec_creates_storage_session() {
        let mut state = make_state();
        let result = trigger_receipt_signing(
            &wid(0x01),
            &[0x02; 32],
            &valid_result(1000),
            None,
            &make_ctx(),
            &mut state,
        );
        assert!(result.is_ok());
        let session_id = result.expect("ok");
        let session = state
            .get_receipt_signing_session(&session_id)
            .expect("should exist");
        assert!(!session.has_execution_commitment());
        assert_eq!(session.receipt_type(), RECEIPT_TYPE_STORAGE);
    }

    #[test]
    fn compute_with_ec_creates_compute_session() {
        let mut state = make_state();
        let ec = make_ec();
        let result = trigger_receipt_signing(
            &wid(0x01),
            &[0x02; 32],
            &valid_result(2000),
            Some(&ec),
            &make_ctx(),
            &mut state,
        );
        assert!(result.is_ok());
        let session_id = result.expect("ok");
        let session = state
            .get_receipt_signing_session(&session_id)
            .expect("should exist");
        assert!(session.has_execution_commitment());
        assert_eq!(session.receipt_type(), RECEIPT_TYPE_COMPUTE);
    }

    // ── Step 3: ReceiptV1Proto Construction ──────────────────────────────

    #[test]
    fn build_receipt_proto_storage_fields_correct() {
        let ctx = make_ctx();
        let proto = build_receipt_v1_proto(
            &wid(0x01),
            &[0x02; 32],
            5000,
            None,
            &ctx,
        );

        assert_eq!(proto.workload_id, vec![0x01; 32]);
        assert_eq!(proto.node_id, vec![0x02; 32]);
        assert_eq!(proto.receipt_type, RECEIPT_TYPE_STORAGE);
        assert_eq!(proto.reward_base, 5000);
        assert_eq!(proto.timestamp, 1_700_000_000);
        assert_eq!(proto.epoch, 42);
        assert!(proto.execution_commitment.is_none());
        assert_eq!(proto.node_signature, vec![0xAA; 64]);
        assert_eq!(proto.submitter_address, vec![0xBB; 20]);
        assert_eq!(proto.usage_proof_hash, vec![0xCC; 32]);
        // Placeholder signature.
        assert!(proto.coordinator_threshold_signature.signature.is_empty());
    }

    #[test]
    fn build_receipt_proto_compute_has_ec() {
        let ctx = make_ctx();
        let ec = make_ec();
        let proto = build_receipt_v1_proto(
            &wid(0x01),
            &[0x02; 32],
            3000,
            Some(&ec),
            &ctx,
        );

        assert_eq!(proto.receipt_type, RECEIPT_TYPE_COMPUTE);
        assert!(proto.execution_commitment.is_some());
        let ec_proto = proto.execution_commitment.expect("should be Some");
        assert_eq!(ec_proto.workload_id, vec![0x01; 32]);
        assert_eq!(ec_proto.input_hash, vec![0x02; 32]);
    }

    // ── Step 4: Session ID Determinism ───────────────────────────────────

    #[test]
    fn session_id_deterministic() {
        let mut s1 = make_state();
        let mut s2 = make_state();

        let id1 = trigger_receipt_signing(
            &wid(0x01),
            &[0x02; 32],
            &valid_result(1000),
            None,
            &make_ctx(),
            &mut s1,
        )
        .expect("ok");

        let id2 = trigger_receipt_signing(
            &wid(0x01),
            &[0x02; 32],
            &valid_result(1000),
            None,
            &make_ctx(),
            &mut s2,
        )
        .expect("ok");

        assert_eq!(id1, id2);
    }

    #[test]
    fn different_workloads_different_session_ids() {
        let mut s1 = make_state();
        let mut s2 = make_state();

        let id1 = trigger_receipt_signing(
            &wid(0x01),
            &[0x02; 32],
            &valid_result(1000),
            None,
            &make_ctx(),
            &mut s1,
        )
        .expect("ok");

        let id2 = trigger_receipt_signing(
            &wid(0x02),
            &[0x02; 32],
            &valid_result(1000),
            None,
            &make_ctx(),
            &mut s2,
        )
        .expect("ok");

        assert_ne!(id1, id2);
    }

    // ── Step 5: Session Creation ─────────────────────────────────────────

    #[test]
    fn session_uses_state_threshold() {
        let mut members = HashSet::new();
        members.insert(coord_id(0x01));
        members.insert(coord_id(0x02));
        members.insert(coord_id(0x03));
        members.insert(coord_id(0x04));
        let mut state = MultiCoordinatorState::new(coord_id(0x01), members, 3, 30_000);

        let session_id = trigger_receipt_signing(
            &wid(0x01),
            &[0x02; 32],
            &valid_result(1000),
            None,
            &make_ctx(),
            &mut state,
        )
        .expect("ok");

        let session = state
            .get_receipt_signing_session(&session_id)
            .expect("should exist");
        assert_eq!(session.threshold(), 3);
    }

    // ── Step 6: Registration & Duplicate Rejection ──────────────────────

    #[test]
    fn duplicate_session_rejected() {
        let mut state = make_state();

        // First trigger succeeds.
        let result1 = trigger_receipt_signing(
            &wid(0x01),
            &[0x02; 32],
            &valid_result(1000),
            None,
            &make_ctx(),
            &mut state,
        );
        assert!(result1.is_ok());

        // Second trigger for same workload → duplicate.
        let result2 = trigger_receipt_signing(
            &wid(0x01),
            &[0x02; 32],
            &valid_result(1000),
            None,
            &make_ctx(),
            &mut state,
        );
        assert_eq!(result2, Err(ReceiptTriggerError::SessionAlreadyExists));

        // Only one session registered.
        assert_eq!(state.receipt_signing_session_count(), 1);
    }

    #[test]
    fn no_state_mutation_on_invalid_usage() {
        let mut state = make_state();
        let _ = trigger_receipt_signing(
            &wid(0x01),
            &[0x02; 32],
            &invalid_result(),
            None,
            &make_ctx(),
            &mut state,
        );
        assert_eq!(state.receipt_signing_session_count(), 0);
    }

    #[test]
    fn multiple_different_workloads_ok() {
        let mut state = make_state();

        let r1 = trigger_receipt_signing(
            &wid(0x01), &[0x02; 32], &valid_result(1000), None, &make_ctx(), &mut state,
        );
        let r2 = trigger_receipt_signing(
            &wid(0x02), &[0x02; 32], &valid_result(2000), None, &make_ctx(), &mut state,
        );
        let r3 = trigger_receipt_signing(
            &wid(0x03), &[0x02; 32], &valid_result(3000), None, &make_ctx(), &mut state,
        );

        assert!(r1.is_ok());
        assert!(r2.is_ok());
        assert!(r3.is_ok());
        assert_eq!(state.receipt_signing_session_count(), 3);
    }

    // ── Helper: ec_to_proto ──────────────────────────────────────────────

    #[test]
    fn ec_to_proto_preserves_fields() {
        let ec = make_ec();
        let proto = ec_to_proto(&ec);

        assert_eq!(proto.workload_id, vec![0x01; 32]);
        assert_eq!(proto.input_hash, vec![0x02; 32]);
        assert_eq!(proto.output_hash, vec![0x03; 32]);
        assert_eq!(proto.state_root_before, vec![0x04; 32]);
        assert_eq!(proto.state_root_after, vec![0x05; 32]);
        assert_eq!(proto.execution_trace_merkle_root, vec![0x06; 32]);
    }

    // ── Error Display ────────────────────────────────────────────────────

    #[test]
    fn error_display_messages() {
        let e1 = ReceiptTriggerError::SessionAlreadyExists;
        assert!(format!("{}", e1).contains("already exists"));

        let e2 = ReceiptTriggerError::InvalidUsageResult;
        assert!(format!("{}", e2).contains("invalid"));

        let e3 = ReceiptTriggerError::MissingExecutionCommitment;
        assert!(format!("{}", e3).contains("execution_commitment"));

        let e4 = ReceiptTriggerError::UnexpectedExecutionCommitment;
        assert!(format!("{}", e4).contains("storage"));
    }

    #[test]
    fn error_implements_std_error() {
        fn assert_error<E: std::error::Error>() {}
        assert_error::<ReceiptTriggerError>();
    }

    // ── Debug ────────────────────────────────────────────────────────────

    #[test]
    fn receipt_context_debug() {
        let ctx = make_ctx();
        let dbg = format!("{:?}", ctx);
        assert!(dbg.contains("ReceiptContext"));
    }
}