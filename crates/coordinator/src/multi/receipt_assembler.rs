//! # Receipt Signing Completion & Assembly (CO.5)
//!
//! Assembles the final `ReceiptV1Proto` after a threshold signing session
//! reaches the `Completed` state, then validates the assembled receipt
//! before returning it.
//!
//! ## Flow
//!
//! ```text
//! ReceiptSigningSession (state == Completed)
//!     │
//!     ▼
//! assemble_signed_receipt()
//!     │
//!     ├── 1. Verify state == SigningState::Completed
//!     ├── 2. Extract aggregated signature bytes
//!     ├── 3. Extract signer IDs (in insertion order)
//!     ├── 4. Clone receipt_data and populate signature fields
//!     ├── 5. Validate assembled receipt
//!     └── 6. Return Ok(receipt)
//!             │
//!             ▼
//!         Final ReceiptV1Proto (immutable artifact, ready for DA publication)
//! ```
//!
//! ## Why Assembly Is Separate from Signing
//!
//! The signing session (`ReceiptSigningSession`) is a state machine that
//! manages the multi-step threshold signing protocol across coordinators.
//! Assembly is a **one-time finalization step** that:
//!
//! 1. Extracts the cryptographic result from the completed session.
//! 2. Populates the receipt's signature fields.
//! 3. Validates the assembled receipt for structural correctness.
//!
//! Separating assembly from the signing state machine keeps the session
//! focused on protocol mechanics and allows the assembler to enforce
//! additional validation constraints without coupling them to the
//! signing logic.
//!
//! ## Post-Assembly Invariants
//!
//! After `assemble_signed_receipt` returns `Ok(receipt)`:
//!
//! - The receipt contains a valid threshold signature that reached quorum.
//! - The `signer_ids` field lists exactly the coordinators who participated.
//! - The `message_hash` is derived from the receipt data.
//! - The receipt is a **final artifact**: it MUST NOT be modified further.
//! - The receipt is ready for publication to the DA layer.
//!
//! ## Safety
//!
//! - No panic, unwrap, expect, todo, unreachable.
//! - No mutation of session state.
//! - Assembly is `&self` only — session is borrowed immutably.
//! - Fully deterministic: same session → same receipt.

use dsdn_common::receipt_v1_convert::{
    AggregateSignatureProto, ReceiptV1Proto,
    compute_receipt_hash_from_proto,
};

use super::receipt_signing::ReceiptSigningSession;
use super::SigningState;

use std::fmt;

// ════════════════════════════════════════════════════════════════════════════════
// ERROR
// ════════════════════════════════════════════════════════════════════════════════

/// Error type for receipt assembly failures.
///
/// Each variant represents a single, unambiguous failure condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssemblyError {
    /// The signing session has not reached the `Completed` state.
    /// Assembly can only proceed after threshold aggregation succeeds.
    SessionNotCompleted,

    /// The signing session is `Completed` but has no aggregated signature.
    /// This indicates an internal inconsistency in the signing state machine.
    NoAggregatedSignature,

    /// The assembled receipt failed structural validation.
    /// Contains a human-readable description of the validation failure.
    ValidationFailed(String),
}

impl fmt::Display for AssemblyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AssemblyError::SessionNotCompleted => {
                write!(f, "signing session has not reached Completed state")
            }
            AssemblyError::NoAggregatedSignature => {
                write!(
                    f,
                    "signing session is Completed but has no aggregated signature"
                )
            }
            AssemblyError::ValidationFailed(reason) => {
                write!(f, "assembled receipt validation failed: {}", reason)
            }
        }
    }
}

impl std::error::Error for AssemblyError {}

// ════════════════════════════════════════════════════════════════════════════════
// ASSEMBLY
// ════════════════════════════════════════════════════════════════════════════════

/// Assembles a final signed `ReceiptV1Proto` from a completed signing session.
///
/// ## Steps (fixed order)
///
/// 1. Verify `session.state() == SigningState::Completed`.
/// 2. Extract aggregated signature bytes via `session.aggregated_signature()`.
/// 3. Extract signer IDs via `session.signers()`.
/// 4. Clone `session.receipt_data()` and populate the
///    `coordinator_threshold_signature` field.
/// 5. Validate the assembled receipt via [`validate_receipt_proto`].
/// 6. Return the validated receipt.
///
/// ## Arguments
///
/// * `session` — Immutable reference to a completed `ReceiptSigningSession`.
///
/// ## Returns
///
/// * `Ok(ReceiptV1Proto)` — Fully assembled and validated receipt.
/// * `Err(AssemblyError)` — One of the assembly/validation steps failed.
///
/// ## Determinism
///
/// Same session state → same assembled receipt.
/// Signer IDs are NOT reordered — they preserve the order from
/// `SigningSession::signers()`.
#[must_use]
pub fn assemble_signed_receipt(
    session: &ReceiptSigningSession,
) -> Result<ReceiptV1Proto, AssemblyError> {
    // ── Step 1: Verify session is Completed ──────────────────────────────

    if !matches!(session.state(), SigningState::Completed) {
        return Err(AssemblyError::SessionNotCompleted);
    }

    // ── Step 2: Extract aggregated signature ─────────────────────────────

    let signature_bytes = session
        .aggregated_signature()
        .ok_or(AssemblyError::NoAggregatedSignature)?;

    // ── Step 3: Extract signer IDs ───────────────────────────────────────

    let signers = session.signers();

    let signer_id_bytes: Vec<Vec<u8>> = signers
        .iter()
        .map(|coord_id| coord_id.as_bytes().to_vec())
        .collect();

    // ── Step 4: Build final receipt ──────────────────────────────────────
    //
    // Clone receipt_data (immutable source — session is &self).
    // Populate coordinator_threshold_signature with aggregation results.

    let mut receipt = session.receipt_data().clone();

    // Compute message_hash from the receipt proto (before signature is populated).
    // This can fail if execution_commitment fields have invalid lengths.
    let message_hash = compute_receipt_hash_from_proto(&receipt)
        .map_err(|e| AssemblyError::ValidationFailed(
            format!("failed to compute receipt hash: {}", e),
        ))?;

    receipt.coordinator_threshold_signature = AggregateSignatureProto {
        signature: signature_bytes.to_vec(),
        signer_ids: signer_id_bytes,
        message_hash: message_hash.to_vec(),
        aggregated_at: session.created_at(),
    };

    // ── Step 5: Validate assembled receipt ───────────────────────────────

    if let Err(reason) = validate_receipt_proto(&receipt) {
        return Err(AssemblyError::ValidationFailed(reason));
    }

    // ── Step 6: Return ───────────────────────────────────────────────────

    Ok(receipt)
}

// ════════════════════════════════════════════════════════════════════════════════
// VALIDATION
// ════════════════════════════════════════════════════════════════════════════════

/// Validates a fully assembled `ReceiptV1Proto` for structural correctness.
///
/// This function checks that all required fields are present and have
/// expected lengths. It does NOT verify cryptographic signatures — that
/// is the job of the chain layer during `ClaimReward` processing.
///
/// ## Checks
///
/// | Field | Rule |
/// |-------|------|
/// | `workload_id` | Exactly 32 bytes, not all-zero |
/// | `node_id` | Exactly 32 bytes |
/// | `receipt_type` | 0 (Storage) or 1 (Compute) |
/// | `usage_proof_hash` | Exactly 32 bytes |
/// | `node_signature` | Exactly 64 bytes |
/// | `coordinator_threshold_signature.signature` | Non-empty |
/// | `coordinator_threshold_signature.signer_ids` | Non-empty |
/// | `coordinator_threshold_signature.message_hash` | Exactly 32 bytes |
/// | `execution_commitment` | Must be `Some` if Compute, `None` if Storage |
/// | `reward_base` | Must be > 0 |
/// | `epoch` | Must be > 0 |
///
/// ## Returns
///
/// * `Ok(())` — All checks passed.
/// * `Err(String)` — Description of the first failing check.
pub fn validate_receipt_proto(receipt: &ReceiptV1Proto) -> Result<(), String> {
    // workload_id: 32 bytes, not all-zero.
    if receipt.workload_id.len() != 32 {
        return Err(format!(
            "workload_id: expected 32 bytes, got {}",
            receipt.workload_id.len()
        ));
    }
    if receipt.workload_id.iter().all(|&b| b == 0) {
        return Err("workload_id: all zero bytes".to_string());
    }

    // node_id: 32 bytes.
    if receipt.node_id.len() != 32 {
        return Err(format!(
            "node_id: expected 32 bytes, got {}",
            receipt.node_id.len()
        ));
    }

    // receipt_type: 0 or 1.
    if receipt.receipt_type > 1 {
        return Err(format!(
            "receipt_type: expected 0 or 1, got {}",
            receipt.receipt_type
        ));
    }

    // usage_proof_hash: 32 bytes.
    if receipt.usage_proof_hash.len() != 32 {
        return Err(format!(
            "usage_proof_hash: expected 32 bytes, got {}",
            receipt.usage_proof_hash.len()
        ));
    }

    // node_signature: 64 bytes.
    if receipt.node_signature.len() != 64 {
        return Err(format!(
            "node_signature: expected 64 bytes, got {}",
            receipt.node_signature.len()
        ));
    }

    // coordinator_threshold_signature: non-empty signature.
    let agg = &receipt.coordinator_threshold_signature;
    if agg.signature.is_empty() {
        return Err("coordinator_threshold_signature.signature: empty".to_string());
    }

    // coordinator_threshold_signature: non-empty signer_ids.
    if agg.signer_ids.is_empty() {
        return Err("coordinator_threshold_signature.signer_ids: empty".to_string());
    }

    // coordinator_threshold_signature: message_hash 32 bytes.
    if agg.message_hash.len() != 32 {
        return Err(format!(
            "coordinator_threshold_signature.message_hash: expected 32 bytes, got {}",
            agg.message_hash.len()
        ));
    }

    // execution_commitment consistency with receipt_type.
    let is_compute = receipt.receipt_type == 1;
    if is_compute && receipt.execution_commitment.is_none() {
        return Err(
            "compute receipt (type=1) missing execution_commitment".to_string(),
        );
    }
    if !is_compute && receipt.execution_commitment.is_some() {
        return Err(
            "storage receipt (type=0) has unexpected execution_commitment".to_string(),
        );
    }

    // Validate EC field lengths if present.
    if let Some(ref ec) = receipt.execution_commitment {
        if ec.workload_id.len() != 32 {
            return Err(format!(
                "execution_commitment.workload_id: expected 32 bytes, got {}",
                ec.workload_id.len()
            ));
        }
        if ec.input_hash.len() != 32 {
            return Err(format!(
                "execution_commitment.input_hash: expected 32 bytes, got {}",
                ec.input_hash.len()
            ));
        }
        if ec.output_hash.len() != 32 {
            return Err(format!(
                "execution_commitment.output_hash: expected 32 bytes, got {}",
                ec.output_hash.len()
            ));
        }
        if ec.state_root_before.len() != 32 {
            return Err(format!(
                "execution_commitment.state_root_before: expected 32 bytes, got {}",
                ec.state_root_before.len()
            ));
        }
        if ec.state_root_after.len() != 32 {
            return Err(format!(
                "execution_commitment.state_root_after: expected 32 bytes, got {}",
                ec.state_root_after.len()
            ));
        }
        if ec.execution_trace_merkle_root.len() != 32 {
            return Err(format!(
                "execution_commitment.execution_trace_merkle_root: expected 32 bytes, got {}",
                ec.execution_trace_merkle_root.len()
            ));
        }
    }

    // reward_base > 0.
    if receipt.reward_base == 0 {
        return Err("reward_base: must be > 0".to_string());
    }

    // epoch > 0.
    if receipt.epoch == 0 {
        return Err("epoch: must be > 0".to_string());
    }

    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use dsdn_common::receipt_v1_convert::{
        AggregateSignatureProto, ExecutionCommitmentProto, ReceiptV1Proto,
    };
    use dsdn_proto::tss::signing::{PartialSignatureProto, SigningCommitmentProto};
    use super::super::{
        CoordinatorId, SessionId, WorkloadId,
        ReceiptSigningSession, RECEIPT_TYPE_COMPUTE, RECEIPT_TYPE_STORAGE,
    };

    // ── Helpers ──────────────────────────────────────────────────────────

    fn make_coord_id(seed: u8) -> CoordinatorId {
        CoordinatorId::new([seed; 32])
    }

    fn make_session_id(seed: u8) -> SessionId {
        SessionId::new([seed; 32])
    }

    fn make_workload_id(seed: u8) -> WorkloadId {
        WorkloadId::new([seed; 32])
    }

    fn make_agg_sig_empty() -> AggregateSignatureProto {
        AggregateSignatureProto {
            signature: vec![],
            signer_ids: vec![],
            message_hash: vec![],
            aggregated_at: 0,
        }
    }

    fn make_storage_receipt_proto() -> ReceiptV1Proto {
        ReceiptV1Proto {
            workload_id: vec![0x01; 32],
            node_id: vec![0x02; 32],
            receipt_type: RECEIPT_TYPE_STORAGE,
            usage_proof_hash: vec![0x03; 32],
            execution_commitment: None,
            coordinator_threshold_signature: make_agg_sig_empty(),
            node_signature: vec![0x07; 64],
            submitter_address: vec![0x08; 20],
            reward_base: 1000,
            timestamp: 1_700_000_000,
            epoch: 42,
        }
    }

    fn make_ec_proto() -> ExecutionCommitmentProto {
        ExecutionCommitmentProto {
            workload_id: vec![0x01; 32],
            input_hash: vec![0x02; 32],
            output_hash: vec![0x03; 32],
            state_root_before: vec![0x04; 32],
            state_root_after: vec![0x05; 32],
            execution_trace_merkle_root: vec![0x06; 32],
        }
    }

    fn make_compute_receipt_proto() -> ReceiptV1Proto {
        ReceiptV1Proto {
            workload_id: vec![0x01; 32],
            node_id: vec![0x02; 32],
            receipt_type: RECEIPT_TYPE_COMPUTE,
            usage_proof_hash: vec![0x03; 32],
            execution_commitment: Some(make_ec_proto()),
            coordinator_threshold_signature: make_agg_sig_empty(),
            node_signature: vec![0x07; 64],
            submitter_address: vec![0x08; 20],
            reward_base: 2000,
            timestamp: 1_700_000_000,
            epoch: 42,
        }
    }

    fn make_commitment(byte: u8) -> SigningCommitmentProto {
        SigningCommitmentProto {
            session_id: vec![byte; 32],
            signer_id: vec![byte; 32],
            hiding: vec![byte; 32],
            binding: vec![byte; 32],
            timestamp: 0,
        }
    }

    fn make_partial(byte: u8) -> PartialSignatureProto {
        PartialSignatureProto {
            session_id: vec![byte; 32],
            signer_id: vec![byte; 32],
            commitment: make_commitment(byte),
            signature_share: vec![byte; 32],
        }
    }

    /// Drive a ReceiptSigningSession to Completed state.
    /// Returns the session with threshold=2, 2 commitments, 2 partials, aggregated.
    fn make_completed_storage_session() -> ReceiptSigningSession {
        let mut session = ReceiptSigningSession::new_storage(
            make_session_id(0x01),
            make_workload_id(0x01),
            2, // threshold
            make_storage_receipt_proto(),
        );

        // Add commitments until quorum.
        let _ = session.add_commitment(make_coord_id(0x0A), make_commitment(0x0A));
        let _ = session.add_commitment(make_coord_id(0x0B), make_commitment(0x0B));

        // Add partials until quorum.
        let _ = session.add_partial(make_coord_id(0x0A), make_partial(0x0A));
        let _ = session.add_partial(make_coord_id(0x0B), make_partial(0x0B));

        // Aggregate.
        let _ = session.try_aggregate();

        session
    }

    fn make_completed_compute_session() -> ReceiptSigningSession {
        let mut session = ReceiptSigningSession::new_compute(
            make_session_id(0x02),
            make_workload_id(0x02),
            2,
            make_compute_receipt_proto(),
            make_ec_proto(),
        );

        let _ = session.add_commitment(make_coord_id(0x0A), make_commitment(0x0A));
        let _ = session.add_commitment(make_coord_id(0x0B), make_commitment(0x0B));
        let _ = session.add_partial(make_coord_id(0x0A), make_partial(0x0A));
        let _ = session.add_partial(make_coord_id(0x0B), make_partial(0x0B));
        let _ = session.try_aggregate();

        session
    }

    // ── assemble_signed_receipt ──────────────────────────────────────────

    #[test]
    fn assemble_storage_receipt_success() {
        let session = make_completed_storage_session();
        let result = assemble_signed_receipt(&session);
        assert!(result.is_ok());

        let receipt = result.expect("ok");
        assert_eq!(receipt.receipt_type, RECEIPT_TYPE_STORAGE);
        assert_eq!(receipt.workload_id, vec![0x01; 32]);
        assert_eq!(receipt.reward_base, 1000);
        assert!(receipt.execution_commitment.is_none());

        // Signature fields populated.
        assert!(!receipt.coordinator_threshold_signature.signature.is_empty());
        assert!(!receipt.coordinator_threshold_signature.signer_ids.is_empty());
        assert_eq!(
            receipt.coordinator_threshold_signature.message_hash.len(),
            32
        );
    }

    #[test]
    fn assemble_compute_receipt_success() {
        let session = make_completed_compute_session();
        let result = assemble_signed_receipt(&session);
        assert!(result.is_ok());

        let receipt = result.expect("ok");
        assert_eq!(receipt.receipt_type, RECEIPT_TYPE_COMPUTE);
        assert!(receipt.execution_commitment.is_some());
        assert_eq!(receipt.reward_base, 2000);

        assert!(!receipt.coordinator_threshold_signature.signature.is_empty());
    }

    #[test]
    fn assemble_not_completed_rejected() {
        // Session in CollectingCommitments state.
        let session = ReceiptSigningSession::new_storage(
            make_session_id(0x01),
            make_workload_id(0x01),
            2,
            make_storage_receipt_proto(),
        );

        let result = assemble_signed_receipt(&session);
        assert_eq!(result, Err(AssemblyError::SessionNotCompleted));
    }

    #[test]
    fn assemble_collecting_signatures_rejected() {
        let mut session = ReceiptSigningSession::new_storage(
            make_session_id(0x01),
            make_workload_id(0x01),
            2,
            make_storage_receipt_proto(),
        );

        // Add commitments but no partials.
        let _ = session.add_commitment(make_coord_id(0x0A), make_commitment(0x0A));
        let _ = session.add_commitment(make_coord_id(0x0B), make_commitment(0x0B));

        let result = assemble_signed_receipt(&session);
        assert_eq!(result, Err(AssemblyError::SessionNotCompleted));
    }

    #[test]
    fn assemble_preserves_original_receipt_data() {
        let session = make_completed_storage_session();
        let original_receipt = session.receipt_data().clone();

        let result = assemble_signed_receipt(&session);
        assert!(result.is_ok());

        // Original receipt_data in session untouched.
        assert_eq!(*session.receipt_data(), original_receipt);
    }

    #[test]
    fn assemble_preserves_reward_base() {
        let session = make_completed_storage_session();
        let result = assemble_signed_receipt(&session);
        let receipt = result.expect("ok");
        assert_eq!(receipt.reward_base, 1000);
    }

    #[test]
    fn assemble_preserves_execution_commitment() {
        let session = make_completed_compute_session();
        let result = assemble_signed_receipt(&session);
        let receipt = result.expect("ok");

        let ec = receipt.execution_commitment.as_ref().expect("should be Some");
        assert_eq!(ec.workload_id, vec![0x01; 32]);
        assert_eq!(ec.input_hash, vec![0x02; 32]);
    }

    #[test]
    fn assemble_signer_ids_match_session_signers() {
        let session = make_completed_storage_session();
        let signers = session.signers();
        let result = assemble_signed_receipt(&session);
        let receipt = result.expect("ok");

        let signer_id_bytes: Vec<Vec<u8>> = signers
            .iter()
            .map(|c| c.as_bytes().to_vec())
            .collect();

        assert_eq!(
            receipt.coordinator_threshold_signature.signer_ids,
            signer_id_bytes
        );
    }

    #[test]
    fn assemble_deterministic() {
        let session = make_completed_storage_session();
        let r1 = assemble_signed_receipt(&session);
        let r2 = assemble_signed_receipt(&session);
        assert_eq!(r1, r2);
    }

    // ── validate_receipt_proto ────────────────────────────────────────────

    #[test]
    fn validate_valid_storage_receipt() {
        let mut receipt = make_storage_receipt_proto();
        receipt.coordinator_threshold_signature = AggregateSignatureProto {
            signature: vec![0xAA; 64],
            signer_ids: vec![vec![0x0A; 32]],
            message_hash: vec![0xBB; 32],
            aggregated_at: 100,
        };
        assert!(validate_receipt_proto(&receipt).is_ok());
    }

    #[test]
    fn validate_valid_compute_receipt() {
        let mut receipt = make_compute_receipt_proto();
        receipt.coordinator_threshold_signature = AggregateSignatureProto {
            signature: vec![0xAA; 64],
            signer_ids: vec![vec![0x0A; 32]],
            message_hash: vec![0xBB; 32],
            aggregated_at: 100,
        };
        assert!(validate_receipt_proto(&receipt).is_ok());
    }

    #[test]
    fn validate_bad_workload_id_length() {
        let mut receipt = make_storage_receipt_proto();
        receipt.workload_id = vec![0x01; 16]; // Wrong length.
        receipt.coordinator_threshold_signature.signature = vec![0xAA; 64];
        receipt.coordinator_threshold_signature.signer_ids = vec![vec![0x0A; 32]];
        receipt.coordinator_threshold_signature.message_hash = vec![0xBB; 32];
        let result = validate_receipt_proto(&receipt);
        assert!(result.is_err());
        assert!(result.err().map_or(false, |s| s.contains("workload_id")));
    }

    #[test]
    fn validate_all_zero_workload_id() {
        let mut receipt = make_storage_receipt_proto();
        receipt.workload_id = vec![0x00; 32];
        receipt.coordinator_threshold_signature.signature = vec![0xAA; 64];
        receipt.coordinator_threshold_signature.signer_ids = vec![vec![0x0A; 32]];
        receipt.coordinator_threshold_signature.message_hash = vec![0xBB; 32];
        let result = validate_receipt_proto(&receipt);
        assert!(result.is_err());
        assert!(result.err().map_or(false, |s| s.contains("zero")));
    }

    #[test]
    fn validate_bad_receipt_type() {
        let mut receipt = make_storage_receipt_proto();
        receipt.receipt_type = 5;
        receipt.coordinator_threshold_signature.signature = vec![0xAA; 64];
        receipt.coordinator_threshold_signature.signer_ids = vec![vec![0x0A; 32]];
        receipt.coordinator_threshold_signature.message_hash = vec![0xBB; 32];
        let result = validate_receipt_proto(&receipt);
        assert!(result.is_err());
        assert!(result.err().map_or(false, |s| s.contains("receipt_type")));
    }

    #[test]
    fn validate_empty_signature() {
        let mut receipt = make_storage_receipt_proto();
        // signature stays empty.
        receipt.coordinator_threshold_signature.signer_ids = vec![vec![0x0A; 32]];
        receipt.coordinator_threshold_signature.message_hash = vec![0xBB; 32];
        let result = validate_receipt_proto(&receipt);
        assert!(result.is_err());
        assert!(result.err().map_or(false, |s| s.contains("signature")));
    }

    #[test]
    fn validate_empty_signer_ids() {
        let mut receipt = make_storage_receipt_proto();
        receipt.coordinator_threshold_signature.signature = vec![0xAA; 64];
        // signer_ids stays empty.
        receipt.coordinator_threshold_signature.message_hash = vec![0xBB; 32];
        let result = validate_receipt_proto(&receipt);
        assert!(result.is_err());
        assert!(result.err().map_or(false, |s| s.contains("signer_ids")));
    }

    #[test]
    fn validate_zero_reward_base() {
        let mut receipt = make_storage_receipt_proto();
        receipt.reward_base = 0;
        receipt.coordinator_threshold_signature.signature = vec![0xAA; 64];
        receipt.coordinator_threshold_signature.signer_ids = vec![vec![0x0A; 32]];
        receipt.coordinator_threshold_signature.message_hash = vec![0xBB; 32];
        let result = validate_receipt_proto(&receipt);
        assert!(result.is_err());
        assert!(result.err().map_or(false, |s| s.contains("reward_base")));
    }

    #[test]
    fn validate_zero_epoch() {
        let mut receipt = make_storage_receipt_proto();
        receipt.epoch = 0;
        receipt.coordinator_threshold_signature.signature = vec![0xAA; 64];
        receipt.coordinator_threshold_signature.signer_ids = vec![vec![0x0A; 32]];
        receipt.coordinator_threshold_signature.message_hash = vec![0xBB; 32];
        let result = validate_receipt_proto(&receipt);
        assert!(result.is_err());
        assert!(result.err().map_or(false, |s| s.contains("epoch")));
    }

    #[test]
    fn validate_compute_without_ec() {
        let mut receipt = make_storage_receipt_proto();
        receipt.receipt_type = RECEIPT_TYPE_COMPUTE; // Compute but no EC.
        receipt.coordinator_threshold_signature.signature = vec![0xAA; 64];
        receipt.coordinator_threshold_signature.signer_ids = vec![vec![0x0A; 32]];
        receipt.coordinator_threshold_signature.message_hash = vec![0xBB; 32];
        let result = validate_receipt_proto(&receipt);
        assert!(result.is_err());
        assert!(result
            .err()
            .map_or(false, |s| s.contains("execution_commitment")));
    }

    #[test]
    fn validate_storage_with_ec() {
        let mut receipt = make_storage_receipt_proto();
        receipt.execution_commitment = Some(make_ec_proto());
        receipt.coordinator_threshold_signature.signature = vec![0xAA; 64];
        receipt.coordinator_threshold_signature.signer_ids = vec![vec![0x0A; 32]];
        receipt.coordinator_threshold_signature.message_hash = vec![0xBB; 32];
        let result = validate_receipt_proto(&receipt);
        assert!(result.is_err());
        assert!(result
            .err()
            .map_or(false, |s| s.contains("execution_commitment")));
    }

    // ── Error Display ────────────────────────────────────────────────────

    #[test]
    fn error_display_session_not_completed() {
        let e = AssemblyError::SessionNotCompleted;
        assert!(format!("{}", e).contains("Completed"));
    }

    #[test]
    fn error_display_no_aggregated_signature() {
        let e = AssemblyError::NoAggregatedSignature;
        assert!(format!("{}", e).contains("aggregated signature"));
    }

    #[test]
    fn error_display_validation_failed() {
        let e = AssemblyError::ValidationFailed("bad field".to_string());
        assert!(format!("{}", e).contains("bad field"));
    }

    #[test]
    fn error_implements_std_error() {
        fn assert_error<E: std::error::Error>() {}
        assert_error::<AssemblyError>();
    }
}