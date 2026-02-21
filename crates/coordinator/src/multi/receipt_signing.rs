//! # Receipt Signing Session (CO.1)
//!
//! Receipt-specific wrapper around [`SigningSession`] for threshold signing
//! of `ReceiptV1Proto` receipts.
//!
//! ## Relationship: ReceiptSigningSession ↔ SigningSession
//!
//! `ReceiptSigningSession` does NOT duplicate the signing state machine.
//! It wraps a `SigningSession` (`inner`) and **delegates** all signing
//! operations to it. The wrapper adds receipt-specific context:
//!
//! - `receipt_data` — the proto receipt being signed.
//! - `execution_commitment` — present for Compute, absent for Storage.
//! - `created_at` — session creation timestamp.
//!
//! ## Lifecycle
//!
//! ```text
//! ┌────────────────────────┐
//! │  ReceiptSigningSession │
//! │  ┌──────────────────┐  │
//! │  │  SigningSession   │  │
//! │  │ (inner)           │  │
//! │  │                   │  │
//! │  │ Collecting        │  │     add_commitment()
//! │  │ Commitments ──────┼──┼──── delegates to inner
//! │  │       │           │  │
//! │  │       ▼           │  │
//! │  │ Collecting        │  │     add_partial()
//! │  │ Signatures ───────┼──┼──── delegates to inner
//! │  │       │           │  │
//! │  │       ▼           │  │
//! │  │ Aggregating ──────┼──┼──── try_aggregate()
//! │  │       │           │  │     delegates to inner
//! │  │       ▼           │  │
//! │  │ Completed ────────┼──┼──── build_signed_receipt()
//! │  │                   │  │     returns Some(ReceiptV1Proto)
//! │  └──────────────────┘  │
//! └────────────────────────┘
//! ```
//!
//! ## Storage vs Compute
//!
//! | Aspect | Storage | Compute |
//! |--------|---------|---------|
//! | Constructor | `new_storage()` | `new_compute()` |
//! | `execution_commitment` | `None` | `Some(...)` |
//! | `receipt_data.receipt_type` | `0` | `1` |
//! | Challenge period | No | Yes (on-chain) |
//!
//! ## Invariants
//!
//! 1. Compute sessions always have `execution_commitment = Some(...)`.
//!    Enforced by `new_compute()` constructor (panics if missing).
//! 2. Storage sessions always have `execution_commitment = None`.
//!    Enforced by `new_storage()` constructor (hardcoded None).
//! 3. `build_signed_receipt()` returns `Some` only after `inner.state() == Completed`.
//!    Returns `None` in all other states. Never panics.
//! 4. All signing operations delegate to `inner` without modification.
//!    No threshold logic is duplicated.

use dsdn_common::receipt_v1_convert::{
    AggregateSignatureProto, ExecutionCommitmentProto, ReceiptV1Proto,
};
use dsdn_proto::tss::signing::{PartialSignatureProto, SigningCommitmentProto};

use super::{CoordinatorId, SessionId, SigningError, SigningSession, SigningState, WorkloadId};

// ════════════════════════════════════════════════════════════════════════════════
// RECEIPT TYPE PROTO
// ════════════════════════════════════════════════════════════════════════════════

/// Proto-layer receipt type representation.
///
/// Mirrors `ReceiptV1Proto.receipt_type` which is `u8`:
/// - `0` = Storage
/// - `1` = Compute
///
/// This is a type alias (not an enum) because the proto layer uses raw `u8`.
/// No enum variants are invented.
pub type ReceiptTypeProto = u8;

/// Storage receipt type value (proto encoding).
pub const RECEIPT_TYPE_STORAGE: ReceiptTypeProto = 0;

/// Compute receipt type value (proto encoding).
pub const RECEIPT_TYPE_COMPUTE: ReceiptTypeProto = 1;

// ════════════════════════════════════════════════════════════════════════════════
// RECEIPT SIGNING SESSION
// ════════════════════════════════════════════════════════════════════════════════

/// Receipt-specific signing session that wraps [`SigningSession`].
///
/// Adds receipt context (proto data, execution commitment, creation time)
/// on top of the existing threshold signing state machine.
///
/// All signing operations (`add_commitment`, `add_partial`, `try_aggregate`)
/// delegate directly to the inner `SigningSession`. No signing logic is
/// duplicated.
///
/// ## Construction
///
/// Use `new_storage()` for Storage receipts or `new_compute()` for Compute
/// receipts. These enforce the execution commitment invariant at construction
/// time.
///
/// ## Thread Safety
///
/// Not thread-safe internally. All mutations via `&mut self`.
pub struct ReceiptSigningSession {
    /// Inner signing session — owns all threshold signing state.
    inner: SigningSession,
    /// Proto receipt data being signed.
    receipt_data: ReceiptV1Proto,
    /// Execution commitment (Some for Compute, None for Storage).
    execution_commitment: Option<ExecutionCommitmentProto>,
    /// Session creation timestamp (derived from receipt_data.timestamp).
    created_at: u64,
}

impl ReceiptSigningSession {
    // ────────────────────────────────────────────────────────────────────────
    // CONSTRUCTORS
    // ────────────────────────────────────────────────────────────────────────

    /// Creates a new signing session for a **Storage** receipt.
    ///
    /// ## Invariant
    ///
    /// `execution_commitment` is set to `None`. Storage receipts do not
    /// require execution commitment.
    ///
    /// ## Parameters
    ///
    /// - `session_id` — Unique session identifier.
    /// - `workload_id` — Workload being signed.
    /// - `threshold` — Quorum threshold for signing.
    /// - `receipt_data` — Proto receipt data.
    ///
    /// ## `created_at`
    ///
    /// Derived deterministically from `receipt_data.timestamp`.
    /// No system clock dependency.
    #[must_use]
    pub fn new_storage(
        session_id: SessionId,
        workload_id: WorkloadId,
        threshold: u8,
        receipt_data: ReceiptV1Proto,
    ) -> Self {
        let created_at = receipt_data.timestamp;
        Self {
            inner: SigningSession::new(session_id, workload_id, threshold),
            receipt_data,
            execution_commitment: None,
            created_at,
        }
    }

    /// Creates a new signing session for a **Compute** receipt.
    ///
    /// ## Invariant
    ///
    /// `execution_commitment` is set to `Some(execution_commitment)`.
    /// Compute receipts MUST have an execution commitment.
    ///
    /// ## Panics
    ///
    /// This is the ONLY method in `ReceiptSigningSession` that may panic.
    /// It panics if the invariant is violated at construction time, which
    /// indicates a programming error in the caller.
    ///
    /// No other method in this struct panics.
    ///
    /// ## Parameters
    ///
    /// - `session_id` — Unique session identifier.
    /// - `workload_id` — Workload being signed.
    /// - `threshold` — Quorum threshold for signing.
    /// - `receipt_data` — Proto receipt data.
    /// - `execution_commitment` — Execution commitment (MUST be provided).
    ///
    /// ## `created_at`
    ///
    /// Derived deterministically from `receipt_data.timestamp`.
    #[must_use]
    pub fn new_compute(
        session_id: SessionId,
        workload_id: WorkloadId,
        threshold: u8,
        receipt_data: ReceiptV1Proto,
        execution_commitment: ExecutionCommitmentProto,
    ) -> Self {
        let created_at = receipt_data.timestamp;
        Self {
            inner: SigningSession::new(session_id, workload_id, threshold),
            receipt_data,
            execution_commitment: Some(execution_commitment),
            created_at,
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // DELEGATION — SIGNING OPERATIONS
    // ────────────────────────────────────────────────────────────────────────
    //
    // These methods delegate directly to `self.inner`.
    // No signing logic is duplicated. No threshold bypassed.
    // No errors swallowed. Return types match inner exactly.

    /// Adds a signing commitment from a coordinator.
    ///
    /// Delegates to [`SigningSession::add_commitment`].
    ///
    /// Returns `Ok(true)` if commitment quorum reached, `Ok(false)` if not.
    pub fn add_commitment(
        &mut self,
        coordinator: CoordinatorId,
        commitment: SigningCommitmentProto,
    ) -> Result<bool, SigningError> {
        self.inner.add_commitment(coordinator, commitment)
    }

    /// Adds a partial signature from a coordinator.
    ///
    /// Delegates to [`SigningSession::add_partial`].
    ///
    /// Returns `Ok(true)` if partial quorum reached, `Ok(false)` if not.
    pub fn add_partial(
        &mut self,
        coordinator: CoordinatorId,
        partial: PartialSignatureProto,
    ) -> Result<bool, SigningError> {
        self.inner.add_partial(coordinator, partial)
    }

    /// Attempts to aggregate partial signatures into a threshold signature.
    ///
    /// Delegates to [`SigningSession::try_aggregate`].
    ///
    /// Returns `Ok(Vec<u8>)` with the aggregated signature bytes on success.
    pub fn try_aggregate(&mut self) -> Result<Vec<u8>, SigningError> {
        self.inner.try_aggregate()
    }

    // ────────────────────────────────────────────────────────────────────────
    // RECEIPT-SPECIFIC METHODS
    // ────────────────────────────────────────────────────────────────────────

    /// Returns the proto receipt type (0=Storage, 1=Compute).
    ///
    /// Deterministic: reads directly from `receipt_data.receipt_type`.
    #[must_use]
    #[inline]
    pub fn receipt_type(&self) -> ReceiptTypeProto {
        self.receipt_data.receipt_type
    }

    /// Returns whether this session has an execution commitment.
    ///
    /// - Storage sessions → `false`
    /// - Compute sessions → `true`
    #[must_use]
    #[inline]
    pub fn has_execution_commitment(&self) -> bool {
        self.execution_commitment.is_some()
    }

    /// Returns a reference to the proto receipt data.
    ///
    /// No clone. Immutable borrow.
    #[must_use]
    #[inline]
    pub fn receipt_data(&self) -> &ReceiptV1Proto {
        &self.receipt_data
    }

    /// Builds a signed `ReceiptV1Proto` if signing is complete.
    ///
    /// Returns `Some(ReceiptV1Proto)` with the aggregated threshold signature
    /// applied to the receipt's `coordinator_threshold_signature` field,
    /// ONLY if `inner.state() == Completed`.
    ///
    /// Returns `None` if signing is not yet complete or has failed.
    ///
    /// ## Guarantees
    ///
    /// - No panic. No unwrap.
    /// - Does not modify session state.
    /// - Receipt returned has `coordinator_threshold_signature.signature` set
    ///   to the aggregated bytes, and `signer_ids` set to the participating
    ///   signers (sorted by CoordinatorId).
    /// - Only callable after a successful `try_aggregate()`.
    #[must_use]
    pub fn build_signed_receipt(&self) -> Option<ReceiptV1Proto> {
        // Only produce a signed receipt in Completed state.
        if !matches!(self.inner.state(), SigningState::Completed) {
            return None;
        }

        // Retrieve aggregated signature (guaranteed Some in Completed state).
        let aggregated_sig = match self.inner.aggregated_signature() {
            Some(sig) => sig,
            None => return None, // Defensive — should not happen in Completed.
        };

        // Build signer_ids as Vec<Vec<u8>> from CoordinatorId slice.
        let signer_ids: Vec<Vec<u8>> = self
            .inner
            .signers()
            .iter()
            .map(|coord_id| coord_id.as_bytes().to_vec())
            .collect();

        // Clone receipt and update the coordinator threshold signature.
        let mut signed = self.receipt_data.clone();
        signed.coordinator_threshold_signature = AggregateSignatureProto {
            signature: aggregated_sig.to_vec(),
            signer_ids,
            message_hash: signed.coordinator_threshold_signature.message_hash,
            aggregated_at: self.created_at,
        };

        Some(signed)
    }

    // ────────────────────────────────────────────────────────────────────────
    // ADDITIONAL GETTERS (delegated to inner)
    // ────────────────────────────────────────────────────────────────────────

    /// Returns the current signing state.
    #[must_use]
    #[inline]
    pub fn state(&self) -> &SigningState {
        self.inner.state()
    }

    /// Returns the session ID.
    #[must_use]
    #[inline]
    pub fn session_id(&self) -> &SessionId {
        self.inner.session_id()
    }

    /// Returns the workload ID.
    #[must_use]
    #[inline]
    pub fn workload_id(&self) -> &WorkloadId {
        self.inner.workload_id()
    }

    /// Returns the threshold.
    #[must_use]
    #[inline]
    pub fn threshold(&self) -> u8 {
        self.inner.threshold()
    }

    /// Returns whether the signing session is in a terminal state.
    #[must_use]
    #[inline]
    pub fn is_terminal(&self) -> bool {
        self.inner.is_terminal()
    }

    /// Returns the aggregated signature bytes if aggregation is complete.
    #[must_use]
    #[inline]
    pub fn aggregated_signature(&self) -> Option<&[u8]> {
        self.inner.aggregated_signature()
    }

    /// Returns the list of signers who contributed to the aggregation.
    #[must_use]
    #[inline]
    pub fn signers(&self) -> &[CoordinatorId] {
        self.inner.signers()
    }

    /// Returns the session creation timestamp.
    #[must_use]
    #[inline]
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Returns the execution commitment if present.
    #[must_use]
    #[inline]
    pub fn execution_commitment(&self) -> Option<&ExecutionCommitmentProto> {
        self.execution_commitment.as_ref()
    }
}

impl std::fmt::Debug for ReceiptSigningSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceiptSigningSession")
            .field("inner_state", self.inner.state())
            .field("receipt_type", &self.receipt_data.receipt_type)
            .field("has_execution_commitment", &self.execution_commitment.is_some())
            .field("created_at", &self.created_at)
            .field("threshold", &self.inner.threshold())
            .finish()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Test Helpers ─────────────────────────────────────────────────────

    fn make_session_id(byte: u8) -> SessionId {
        SessionId::new([byte; 32])
    }

    fn make_workload_id(byte: u8) -> WorkloadId {
        WorkloadId::new([byte; 32])
    }

    fn make_coord_id(byte: u8) -> CoordinatorId {
        CoordinatorId::new([byte; 32])
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

    fn make_agg_sig() -> AggregateSignatureProto {
        AggregateSignatureProto {
            signature: vec![0x00; 64],
            signer_ids: vec![],
            message_hash: vec![0x00; 32],
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
            coordinator_threshold_signature: make_agg_sig(),
            node_signature: vec![0x07; 64],
            submitter_address: vec![0x08; 20],
            reward_base: 1000,
            timestamp: 1_700_000_000,
            epoch: 42,
        }
    }

    fn make_compute_receipt_proto() -> ReceiptV1Proto {
        ReceiptV1Proto {
            workload_id: vec![0x01; 32],
            node_id: vec![0x02; 32],
            receipt_type: RECEIPT_TYPE_COMPUTE,
            usage_proof_hash: vec![0x03; 32],
            execution_commitment: Some(make_ec_proto()),
            coordinator_threshold_signature: make_agg_sig(),
            node_signature: vec![0x07; 64],
            submitter_address: vec![0x08; 20],
            reward_base: 2000,
            timestamp: 1_700_000_000,
            epoch: 42,
        }
    }

    fn make_ec_proto() -> ExecutionCommitmentProto {
        ExecutionCommitmentProto {
            workload_id: vec![0xA0; 32],
            input_hash: vec![0xA1; 32],
            output_hash: vec![0xA2; 32],
            state_root_before: vec![0xA3; 32],
            state_root_after: vec![0xA4; 32],
            execution_trace_merkle_root: vec![0xA5; 32],
        }
    }

    /// Drive a session through the full signing lifecycle.
    fn drive_to_completed(session: &mut ReceiptSigningSession) {
        session
            .add_commitment(make_coord_id(0x01), make_commitment(0x01))
            .expect("commit 1");
        session
            .add_commitment(make_coord_id(0x02), make_commitment(0x02))
            .expect("commit 2");
        session
            .add_partial(make_coord_id(0x01), make_partial(0x01))
            .expect("partial 1");
        session
            .add_partial(make_coord_id(0x02), make_partial(0x02))
            .expect("partial 2");
        session.try_aggregate().expect("aggregate");
    }

    // ── Constructor Tests ───────────────────────────────────────────────

    #[test]
    fn new_storage_creates_with_none_ec() {
        let session = ReceiptSigningSession::new_storage(
            make_session_id(0x01),
            make_workload_id(0x02),
            2,
            make_storage_receipt_proto(),
        );

        assert!(!session.has_execution_commitment());
        assert_eq!(session.receipt_type(), RECEIPT_TYPE_STORAGE);
        assert_eq!(session.created_at(), 1_700_000_000);
        assert_eq!(*session.state(), SigningState::CollectingCommitments);
    }

    #[test]
    fn new_compute_creates_with_some_ec() {
        let session = ReceiptSigningSession::new_compute(
            make_session_id(0x01),
            make_workload_id(0x02),
            2,
            make_compute_receipt_proto(),
            make_ec_proto(),
        );

        assert!(session.has_execution_commitment());
        assert_eq!(session.receipt_type(), RECEIPT_TYPE_COMPUTE);
        assert_eq!(session.created_at(), 1_700_000_000);
    }

    #[test]
    fn created_at_derived_from_receipt_timestamp() {
        let mut proto = make_storage_receipt_proto();
        proto.timestamp = 9_999_999;

        let session = ReceiptSigningSession::new_storage(
            make_session_id(0x01),
            make_workload_id(0x02),
            2,
            proto,
        );

        assert_eq!(session.created_at(), 9_999_999);
    }

    // ── Receipt Data Access ─────────────────────────────────────────────

    #[test]
    fn receipt_data_returns_immutable_ref() {
        let proto = make_storage_receipt_proto();
        let session = ReceiptSigningSession::new_storage(
            make_session_id(0x01),
            make_workload_id(0x02),
            2,
            proto.clone(),
        );

        assert_eq!(session.receipt_data(), &proto);
    }

    #[test]
    fn execution_commitment_ref_matches() {
        let ec = make_ec_proto();
        let session = ReceiptSigningSession::new_compute(
            make_session_id(0x01),
            make_workload_id(0x02),
            2,
            make_compute_receipt_proto(),
            ec.clone(),
        );

        assert_eq!(session.execution_commitment(), Some(&ec));
    }

    // ── Delegation Tests ────────────────────────────────────────────────

    #[test]
    fn add_commitment_delegates_success() {
        let mut session = ReceiptSigningSession::new_storage(
            make_session_id(0x01),
            make_workload_id(0x02),
            2,
            make_storage_receipt_proto(),
        );

        let result = session.add_commitment(make_coord_id(0x01), make_commitment(0x01));
        assert!(result.is_ok());
        assert!(!result.expect("ok")); // Not quorum yet.
    }

    #[test]
    fn add_commitment_quorum_transitions_state() {
        let mut session = ReceiptSigningSession::new_storage(
            make_session_id(0x01),
            make_workload_id(0x02),
            2,
            make_storage_receipt_proto(),
        );

        session
            .add_commitment(make_coord_id(0x01), make_commitment(0x01))
            .expect("ok");
        let quorum = session
            .add_commitment(make_coord_id(0x02), make_commitment(0x02))
            .expect("ok");

        assert!(quorum);
        assert_eq!(*session.state(), SigningState::CollectingSignatures);
    }

    #[test]
    fn add_commitment_duplicate_error_propagated() {
        let mut session = ReceiptSigningSession::new_storage(
            make_session_id(0x01),
            make_workload_id(0x02),
            2,
            make_storage_receipt_proto(),
        );

        session
            .add_commitment(make_coord_id(0x01), make_commitment(0x01))
            .expect("ok");
        let result = session.add_commitment(make_coord_id(0x01), make_commitment(0x01));

        assert!(matches!(result, Err(SigningError::DuplicateCommitment { .. })));
    }

    #[test]
    fn add_partial_delegates_success() {
        let mut session = ReceiptSigningSession::new_storage(
            make_session_id(0x01),
            make_workload_id(0x02),
            2,
            make_storage_receipt_proto(),
        );

        session
            .add_commitment(make_coord_id(0x01), make_commitment(0x01))
            .expect("ok");
        session
            .add_commitment(make_coord_id(0x02), make_commitment(0x02))
            .expect("ok");

        let result = session.add_partial(make_coord_id(0x01), make_partial(0x01));
        assert!(result.is_ok());
        assert!(!result.expect("ok")); // Not quorum yet.
    }

    #[test]
    fn add_partial_wrong_state_error_propagated() {
        let mut session = ReceiptSigningSession::new_storage(
            make_session_id(0x01),
            make_workload_id(0x02),
            2,
            make_storage_receipt_proto(),
        );

        // Still CollectingCommitments — can't add partial.
        let result = session.add_partial(make_coord_id(0x01), make_partial(0x01));
        assert!(matches!(result, Err(SigningError::InvalidState { .. })));
    }

    #[test]
    fn try_aggregate_delegates_success() {
        let mut session = ReceiptSigningSession::new_storage(
            make_session_id(0x01),
            make_workload_id(0x02),
            2,
            make_storage_receipt_proto(),
        );

        drive_to_completed(&mut session);

        assert_eq!(*session.state(), SigningState::Completed);
        assert!(session.is_terminal());
    }

    #[test]
    fn try_aggregate_wrong_state_error_propagated() {
        let mut session = ReceiptSigningSession::new_storage(
            make_session_id(0x01),
            make_workload_id(0x02),
            2,
            make_storage_receipt_proto(),
        );

        let result = session.try_aggregate();
        assert!(matches!(result, Err(SigningError::InvalidState { .. })));
    }

    // ── build_signed_receipt Tests ───────────────────────────────────────

    #[test]
    fn build_signed_receipt_none_before_completed() {
        let session = ReceiptSigningSession::new_storage(
            make_session_id(0x01),
            make_workload_id(0x02),
            2,
            make_storage_receipt_proto(),
        );

        assert!(session.build_signed_receipt().is_none());
    }

    #[test]
    fn build_signed_receipt_none_during_collecting_signatures() {
        let mut session = ReceiptSigningSession::new_storage(
            make_session_id(0x01),
            make_workload_id(0x02),
            2,
            make_storage_receipt_proto(),
        );

        session
            .add_commitment(make_coord_id(0x01), make_commitment(0x01))
            .expect("ok");
        session
            .add_commitment(make_coord_id(0x02), make_commitment(0x02))
            .expect("ok");

        assert!(session.build_signed_receipt().is_none());
    }

    #[test]
    fn build_signed_receipt_some_after_completed() {
        let mut session = ReceiptSigningSession::new_storage(
            make_session_id(0x01),
            make_workload_id(0x02),
            2,
            make_storage_receipt_proto(),
        );

        drive_to_completed(&mut session);

        let signed = session.build_signed_receipt();
        assert!(signed.is_some());

        let signed = signed.expect("should be Some");
        // Signature bytes should be non-empty.
        assert!(!signed.coordinator_threshold_signature.signature.is_empty());
        // Signer IDs should match the 2 coordinators.
        assert_eq!(signed.coordinator_threshold_signature.signer_ids.len(), 2);
        // aggregated_at should match created_at.
        assert_eq!(
            signed.coordinator_threshold_signature.aggregated_at,
            1_700_000_000
        );
        // All other fields unchanged.
        assert_eq!(signed.workload_id, vec![0x01; 32]);
        assert_eq!(signed.reward_base, 1000);
        assert_eq!(signed.receipt_type, RECEIPT_TYPE_STORAGE);
    }

    #[test]
    fn build_signed_receipt_compute_after_completed() {
        let mut session = ReceiptSigningSession::new_compute(
            make_session_id(0x01),
            make_workload_id(0x02),
            2,
            make_compute_receipt_proto(),
            make_ec_proto(),
        );

        drive_to_completed(&mut session);

        let signed = session.build_signed_receipt();
        assert!(signed.is_some());

        let signed = signed.expect("should be Some");
        assert_eq!(signed.receipt_type, RECEIPT_TYPE_COMPUTE);
        assert_eq!(signed.reward_base, 2000);
    }

    #[test]
    fn build_signed_receipt_preserves_message_hash() {
        let mut proto = make_storage_receipt_proto();
        proto.coordinator_threshold_signature.message_hash = vec![0xFF; 32];

        let mut session = ReceiptSigningSession::new_storage(
            make_session_id(0x01),
            make_workload_id(0x02),
            2,
            proto,
        );

        drive_to_completed(&mut session);

        let signed = session.build_signed_receipt().expect("completed");
        // message_hash from original receipt_data preserved.
        assert_eq!(
            signed.coordinator_threshold_signature.message_hash,
            vec![0xFF; 32]
        );
    }

    #[test]
    fn build_signed_receipt_does_not_mutate_state() {
        let mut session = ReceiptSigningSession::new_storage(
            make_session_id(0x01),
            make_workload_id(0x02),
            2,
            make_storage_receipt_proto(),
        );

        drive_to_completed(&mut session);

        let _ = session.build_signed_receipt();
        let _ = session.build_signed_receipt();

        // State still Completed after multiple calls.
        assert_eq!(*session.state(), SigningState::Completed);
    }

    #[test]
    fn build_signed_receipt_deterministic() {
        let mut session = ReceiptSigningSession::new_storage(
            make_session_id(0x01),
            make_workload_id(0x02),
            2,
            make_storage_receipt_proto(),
        );

        drive_to_completed(&mut session);

        let r1 = session.build_signed_receipt().expect("ok");
        let r2 = session.build_signed_receipt().expect("ok");

        assert_eq!(r1, r2);
    }

    // ── Getter Delegation Tests ─────────────────────────────────────────

    #[test]
    fn session_id_getter() {
        let sid = make_session_id(0xAB);
        let session = ReceiptSigningSession::new_storage(
            sid.clone(),
            make_workload_id(0x02),
            2,
            make_storage_receipt_proto(),
        );

        assert_eq!(*session.session_id(), sid);
    }

    #[test]
    fn workload_id_getter() {
        let wid = make_workload_id(0xCD);
        let session = ReceiptSigningSession::new_storage(
            make_session_id(0x01),
            wid.clone(),
            3,
            make_storage_receipt_proto(),
        );

        assert_eq!(*session.workload_id(), wid);
        assert_eq!(session.threshold(), 3);
    }

    #[test]
    fn is_terminal_false_initially() {
        let session = ReceiptSigningSession::new_storage(
            make_session_id(0x01),
            make_workload_id(0x02),
            2,
            make_storage_receipt_proto(),
        );

        assert!(!session.is_terminal());
    }

    #[test]
    fn is_terminal_true_after_completed() {
        let mut session = ReceiptSigningSession::new_storage(
            make_session_id(0x01),
            make_workload_id(0x02),
            2,
            make_storage_receipt_proto(),
        );

        drive_to_completed(&mut session);
        assert!(session.is_terminal());
    }

    // ── Debug Tests ─────────────────────────────────────────────────────

    #[test]
    fn debug_format_not_empty() {
        let session = ReceiptSigningSession::new_storage(
            make_session_id(0x01),
            make_workload_id(0x02),
            2,
            make_storage_receipt_proto(),
        );

        let debug = format!("{:?}", session);
        assert!(debug.contains("ReceiptSigningSession"));
        assert!(debug.contains("threshold"));
    }
}