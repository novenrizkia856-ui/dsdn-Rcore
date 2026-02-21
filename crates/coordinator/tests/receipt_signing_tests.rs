//! # Receipt Signing Integration Tests (CO.10)
//!
//! Covers the complete lifecycle of receipt signing sessions:
//! creation, commitment/partial collection, aggregation, assembly,
//! state extension, and error handling.

use std::collections::HashSet;

use dsdn_coordinator::multi::{
    // Types
    CoordinatorId, SessionId, WorkloadId,
    // Signing session
    ReceiptSigningSession,
    SigningState,
    // Assembly
    assemble_signed_receipt, AssemblyError,
    // State extension (CO.8)
    MultiCoordinatorState, RegisterError, CompleteError,
    // Constants
    RECEIPT_TYPE_STORAGE, RECEIPT_TYPE_COMPUTE,
};

use dsdn_common::receipt_v1_convert::{
    AggregateSignatureProto, ExecutionCommitmentProto, ReceiptV1Proto,
};
use dsdn_proto::tss::signing::{PartialSignatureProto, SigningCommitmentProto};

// ════════════════════════════════════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════════════════════════════════════

fn sid(seed: u8) -> SessionId {
    SessionId::new([seed; 32])
}

fn wid(seed: u8) -> WorkloadId {
    WorkloadId::new([seed; 32])
}

fn cid(seed: u8) -> CoordinatorId {
    CoordinatorId::new([seed; 32])
}

fn empty_agg() -> AggregateSignatureProto {
    AggregateSignatureProto {
        signature: vec![],
        signer_ids: vec![],
        message_hash: vec![],
        aggregated_at: 0,
    }
}

fn storage_receipt() -> ReceiptV1Proto {
    ReceiptV1Proto {
        workload_id: vec![0x01; 32],
        node_id: vec![0x02; 32],
        receipt_type: 0,
        usage_proof_hash: vec![0x03; 32],
        execution_commitment: None,
        coordinator_threshold_signature: empty_agg(),
        node_signature: vec![0x07; 64],
        submitter_address: vec![0x08; 20],
        reward_base: 1000,
        timestamp: 1_700_000_000,
        epoch: 42,
    }
}

fn compute_receipt() -> ReceiptV1Proto {
    let mut r = storage_receipt();
    r.receipt_type = 1;
    r.execution_commitment = Some(ExecutionCommitmentProto {
        workload_id: vec![0x01; 32],
        input_hash: vec![0x0A; 32],
        output_hash: vec![0x0B; 32],
        state_root_before: vec![0x0C; 32],
        state_root_after: vec![0x0D; 32],
        execution_trace_merkle_root: vec![0x0E; 32],
    });
    r
}

fn commitment(seed: u8, session_seed: u8) -> SigningCommitmentProto {
    SigningCommitmentProto {
        session_id: vec![session_seed; 32],
        signer_id: vec![seed; 32],
        hiding: vec![seed; 32],
        binding: vec![seed.wrapping_add(1); 32],
        timestamp: 0,
    }
}

fn partial(seed: u8, session_seed: u8) -> PartialSignatureProto {
    PartialSignatureProto {
        session_id: vec![session_seed; 32],
        signer_id: vec![seed; 32],
        commitment: commitment(seed, session_seed),
        signature_share: vec![seed; 32],
    }
}

/// Drive a session to Completed state with threshold=2.
fn drive_to_completed(session: &mut ReceiptSigningSession, sid_seed: u8) {
    session
        .add_commitment(cid(0x0A), commitment(0x0A, sid_seed))
        .expect("test: commitment A");
    session
        .add_commitment(cid(0x0B), commitment(0x0B, sid_seed))
        .expect("test: commitment B");
    session
        .add_partial(cid(0x0A), partial(0x0A, sid_seed))
        .expect("test: partial A");
    session
        .add_partial(cid(0x0B), partial(0x0B, sid_seed))
        .expect("test: partial B");
    let _sig = session.try_aggregate().expect("test: aggregate");
}

fn make_state() -> MultiCoordinatorState {
    let self_id = cid(0x00);
    let mut committee = HashSet::new();
    committee.insert(cid(0x00));
    committee.insert(cid(0x0A));
    committee.insert(cid(0x0B));
    MultiCoordinatorState::new(self_id, committee, 2, 30_000)
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

/// 1) Storage receipt signing: full lifecycle (happy path).
#[test]
fn test_storage_receipt_full_lifecycle() {
    let mut session = ReceiptSigningSession::new_storage(
        sid(0x01), wid(0x01), 2, storage_receipt(),
    );

    assert_eq!(session.receipt_type(), RECEIPT_TYPE_STORAGE);
    assert!(!session.has_execution_commitment());

    drive_to_completed(&mut session, 0x01);

    assert_eq!(session.state().name(), "Completed");
    assert!(session.is_terminal());
    assert!(session.aggregated_signature().is_some());

    // Assembly succeeds.
    let receipt = assemble_signed_receipt(&session);
    assert!(receipt.is_ok());
    let receipt = receipt.expect("test: assembly");
    assert_eq!(receipt.receipt_type, 0);
    assert_eq!(receipt.reward_base, 1000);
}

/// 2) Compute receipt signing with ExecutionCommitment (happy path).
#[test]
fn test_compute_receipt_with_ec_lifecycle() {
    let ec = ExecutionCommitmentProto {
        workload_id: vec![0x01; 32],
        input_hash: vec![0x0A; 32],
        output_hash: vec![0x0B; 32],
        state_root_before: vec![0x0C; 32],
        state_root_after: vec![0x0D; 32],
        execution_trace_merkle_root: vec![0x0E; 32],
    };
    let mut session = ReceiptSigningSession::new_compute(
        sid(0x02), wid(0x02), 2, compute_receipt(), ec,
    );

    assert_eq!(session.receipt_type(), RECEIPT_TYPE_COMPUTE);
    assert!(session.has_execution_commitment());
    assert!(session.execution_commitment().is_some());

    drive_to_completed(&mut session, 0x02);

    let receipt = assemble_signed_receipt(&session).expect("test: assembly");
    assert_eq!(receipt.receipt_type, 1);
    assert!(receipt.execution_commitment.is_some());
}

/// 3) Signing session state transitions.
#[test]
fn test_signing_state_transitions() {
    let mut session = ReceiptSigningSession::new_storage(
        sid(0x03), wid(0x03), 2, storage_receipt(),
    );

    // Initial state.
    assert_eq!(session.state().name(), "CollectingCommitments");

    // One commitment: still collecting.
    session.add_commitment(cid(0x0A), commitment(0x0A, 0x03))
        .expect("test: first commitment");
    assert_eq!(session.state().name(), "CollectingCommitments");

    // Threshold met → auto-transition to CollectingSignatures.
    session.add_commitment(cid(0x0B), commitment(0x0B, 0x03))
        .expect("test: second commitment");
    assert_eq!(session.state().name(), "CollectingSignatures");

    // Add partials.
    session.add_partial(cid(0x0A), partial(0x0A, 0x03))
        .expect("test: first partial");
    session.add_partial(cid(0x0B), partial(0x0B, 0x03))
        .expect("test: second partial");

    // Aggregate → Completed.
    let _sig = session.try_aggregate().expect("test: aggregate");
    assert_eq!(session.state().name(), "Completed");
}

/// 4) Commitment quorum → partial quorum → aggregate.
#[test]
fn test_commitment_partial_quorum_aggregate() {
    let mut session = ReceiptSigningSession::new_storage(
        sid(0x04), wid(0x04), 2, storage_receipt(),
    );
    drive_to_completed(&mut session, 0x04);

    let sig = session.aggregated_signature();
    assert!(sig.is_some());
    assert!(!sig.expect("test: sig").is_empty());
}

/// 5) Duplicate commitment rejection.
#[test]
fn test_duplicate_commitment_rejection() {
    let mut session = ReceiptSigningSession::new_storage(
        sid(0x05), wid(0x05), 2, storage_receipt(),
    );

    session.add_commitment(cid(0x0A), commitment(0x0A, 0x05))
        .expect("test: first commitment");

    // Same coordinator ID again → error.
    let result = session.add_commitment(cid(0x0A), commitment(0x0A, 0x05));
    assert!(result.is_err());
}

/// 15) Session state extension lifecycle (CO.8).
#[test]
fn test_session_state_extension_lifecycle() {
    let mut state = make_state();
    let mut session = ReceiptSigningSession::new_storage(
        sid(0x15), wid(0x15), 2, storage_receipt(),
    );
    drive_to_completed(&mut session, 0x15);

    state.register_receipt_signing(sid(0x15), session)
        .expect("test: register");
    assert_eq!(state.receipt_signing_session_count(), 1);

    let receipt = state.complete_receipt_signing(&sid(0x15))
        .expect("test: complete");
    assert_eq!(receipt.receipt_type, 0);

    // Session removed, receipt in completed queue.
    assert_eq!(state.receipt_signing_session_count(), 0);
    assert_eq!(state.completed_receipts_count(), 1);
    assert_eq!(state.total_receipts_signed(), 1);
}

/// 16) Double completion rejection.
#[test]
fn test_double_completion_rejection() {
    let mut state = make_state();
    let mut session = ReceiptSigningSession::new_storage(
        sid(0x16), wid(0x16), 2, storage_receipt(),
    );
    drive_to_completed(&mut session, 0x16);

    state.register_receipt_signing(sid(0x16), session)
        .expect("test: register");
    let _ = state.complete_receipt_signing(&sid(0x16))
        .expect("test: first complete");

    let result = state.complete_receipt_signing(&sid(0x16));
    assert_eq!(result, Err(CompleteError::SessionNotFound));
}

/// 17) Missing aggregated signature → assembly error.
#[test]
fn test_missing_aggregated_signature() {
    let mut session = ReceiptSigningSession::new_storage(
        sid(0x17), wid(0x17), 2, storage_receipt(),
    );
    // Add commitments + partials but do NOT aggregate.
    session.add_commitment(cid(0x0A), commitment(0x0A, 0x17))
        .expect("test");
    session.add_commitment(cid(0x0B), commitment(0x0B, 0x17))
        .expect("test");
    session.add_partial(cid(0x0A), partial(0x0A, 0x17))
        .expect("test");
    session.add_partial(cid(0x0B), partial(0x0B, 0x17))
        .expect("test");
    // No try_aggregate → still in CollectingSignatures.

    let result = assemble_signed_receipt(&session);
    assert!(result.is_err());
}

/// 18) SessionNotCompleted error.
#[test]
fn test_session_not_completed_error() {
    let session = ReceiptSigningSession::new_storage(
        sid(0x18), wid(0x18), 2, storage_receipt(),
    );
    // Still in CollectingCommitments → error.
    let result = assemble_signed_receipt(&session);
    assert!(matches!(result, Err(AssemblyError::SessionNotCompleted)));
}

/// 27) Signing session duplicate registration.
#[test]
fn test_duplicate_registration() {
    let mut state = make_state();
    let session1 = ReceiptSigningSession::new_storage(
        sid(0x27), wid(0x27), 2, storage_receipt(),
    );
    let session2 = ReceiptSigningSession::new_storage(
        sid(0x27), wid(0x27), 2, storage_receipt(),
    );

    state.register_receipt_signing(sid(0x27), session1)
        .expect("test: first register");
    let result = state.register_receipt_signing(sid(0x27), session2);
    assert_eq!(result, Err(RegisterError::SessionAlreadyExists));
}

/// 28) Missing execution commitment for compute receipt type.
#[test]
fn test_missing_ec_for_compute() {
    let mut r = storage_receipt();
    r.receipt_type = 1; // Compute type but NO execution_commitment.

    let mut session = ReceiptSigningSession::new_storage(
        sid(0x28), wid(0x28), 2, r,
    );
    drive_to_completed(&mut session, 0x28);

    // Assembly should fail because receipt_type=1 but EC is None.
    let result = assemble_signed_receipt(&session);
    assert!(result.is_err());
}

/// 29) Threshold not reached — aggregate fails.
#[test]
fn test_threshold_not_reached() {
    let mut session = ReceiptSigningSession::new_storage(
        sid(0x29), wid(0x29), 2, storage_receipt(),
    );
    // Only 1 commitment, 1 partial (threshold=2).
    session.add_commitment(cid(0x0A), commitment(0x0A, 0x29))
        .expect("test");
    // Can't add partial in CollectingCommitments state.
    let result = session.add_partial(cid(0x0A), partial(0x0A, 0x29));
    assert!(result.is_err()); // Wrong state.
}

/// 30) Partial signature ordering independence.
#[test]
fn test_partial_ordering_independence() {
    // Order A: partials A then B.
    let mut s1 = ReceiptSigningSession::new_storage(
        sid(0x30), wid(0x30), 2, storage_receipt(),
    );
    s1.add_commitment(cid(0x0A), commitment(0x0A, 0x30)).expect("test");
    s1.add_commitment(cid(0x0B), commitment(0x0B, 0x30)).expect("test");
    s1.add_partial(cid(0x0A), partial(0x0A, 0x30)).expect("test");
    s1.add_partial(cid(0x0B), partial(0x0B, 0x30)).expect("test");
    let sig1 = s1.try_aggregate().expect("test");

    // Order B: partials B then A.
    let mut s2 = ReceiptSigningSession::new_storage(
        sid(0x30), wid(0x30), 2, storage_receipt(),
    );
    s2.add_commitment(cid(0x0A), commitment(0x0A, 0x30)).expect("test");
    s2.add_commitment(cid(0x0B), commitment(0x0B, 0x30)).expect("test");
    s2.add_partial(cid(0x0B), partial(0x0B, 0x30)).expect("test");
    s2.add_partial(cid(0x0A), partial(0x0A, 0x30)).expect("test");
    let sig2 = s2.try_aggregate().expect("test");

    // Both produce valid aggregated signatures.
    assert!(!sig1.is_empty());
    assert!(!sig2.is_empty());
}

/// 31) Receipt builder correctness.
#[test]
fn test_receipt_builder_correctness() {
    let mut session = ReceiptSigningSession::new_storage(
        sid(0x31), wid(0x31), 2, storage_receipt(),
    );
    drive_to_completed(&mut session, 0x31);

    let receipt = session.build_signed_receipt();
    assert!(receipt.is_some());
    let receipt = receipt.expect("test");
    assert_eq!(receipt.workload_id, vec![0x01; 32]);
    assert_eq!(receipt.epoch, 42);
}

/// 32) ReceiptSigningSession accessor behavior.
#[test]
fn test_session_accessor_behavior() {
    let session = ReceiptSigningSession::new_storage(
        sid(0x32), wid(0x32), 2, storage_receipt(),
    );

    assert_eq!(*session.session_id(), sid(0x32));
    assert_eq!(*session.workload_id(), wid(0x32));
    assert_eq!(session.threshold(), 2);
    assert_eq!(session.receipt_type(), RECEIPT_TYPE_STORAGE);
    assert!(!session.is_terminal());
    assert!(session.aggregated_signature().is_none());
    assert!(session.signers().is_empty());
    assert!(!session.has_execution_commitment());
    assert!(session.execution_commitment().is_none());
}

/// 33) Cannot build_signed_receipt before completion.
#[test]
fn test_cannot_build_before_complete() {
    let session = ReceiptSigningSession::new_storage(
        sid(0x33), wid(0x33), 2, storage_receipt(),
    );
    assert!(session.build_signed_receipt().is_none());
}

/// 43) Signing state immutability after completion.
#[test]
fn test_signing_state_immutability_after_completion() {
    let mut session = ReceiptSigningSession::new_storage(
        sid(0x43), wid(0x43), 2, storage_receipt(),
    );
    drive_to_completed(&mut session, 0x43);

    assert_eq!(session.state().name(), "Completed");
    assert!(session.is_terminal());

    // State remains Completed — no further transitions.
    let sig = session.aggregated_signature();
    assert!(sig.is_some());
    assert_eq!(session.state().name(), "Completed");
}