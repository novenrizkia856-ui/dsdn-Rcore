//! # DA Publication & End-to-End Integration Tests (CO.10)
//!
//! Covers receipt assembly, DA publication, retrieval, encoding/decoding,
//! state extension counters, and the full pipeline from usage verification
//! through DA publication.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

use dsdn_coordinator::multi::{
    CoordinatorId, SessionId, WorkloadId,
    ReceiptSigningSession,
    assemble_signed_receipt, validate_receipt_proto, AssemblyError,
    MultiCoordinatorState, CompleteError,
};
use dsdn_coordinator::receipt_publisher::{
    DAClient, DABlobRef, DAError,
    ReceiptPublisher, PublishError, RetrieveError,
    encode_receipt, decode_receipt,
};
use dsdn_coordinator::execution::{
    verify_usage_proof, calculate_reward_base, build_signing_message,
    UsageProof, UsageVerificationResult,
};

use dsdn_common::coordinator::WorkloadId as CommonWorkloadId;
use dsdn_common::receipt_v1_convert::{
    AggregateSignatureProto, ReceiptV1Proto,
};
use dsdn_proto::tss::signing::{PartialSignatureProto, SigningCommitmentProto};

use ed25519_dalek::{Signer, SigningKey};

// ════════════════════════════════════════════════════════════════════════════════
// IN-MEMORY DA CLIENT FOR INTEGRATION TESTS
// ════════════════════════════════════════════════════════════════════════════════

/// Thread-safe in-memory DA client for integration testing.
struct TestDA {
    blobs: Mutex<Vec<(Vec<u8>, Vec<u8>)>>, // (namespace, data)
    fail_submit: Mutex<bool>,
    fail_get: Mutex<bool>,
}

impl TestDA {
    fn new() -> Self {
        Self {
            blobs: Mutex::new(Vec::new()),
            fail_submit: Mutex::new(false),
            fail_get: Mutex::new(false),
        }
    }

    fn set_fail_submit(&self, fail: bool) {
        *self.fail_submit.lock().expect("test: lock") = fail;
    }

    fn set_fail_get(&self, fail: bool) {
        *self.fail_get.lock().expect("test: lock") = fail;
    }
}

impl DAClient for TestDA {
    fn submit_blob(
        &self,
        namespace: &[u8],
        data: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<DABlobRef, DAError>> + Send + '_>> {
        let namespace = namespace.to_vec();
        let data = data.to_vec();
        Box::pin(async move {
            if *self.fail_submit.lock().expect("test: lock") {
                return Err(DAError {
                    message: "injected submit failure".to_string(),
                });
            }
            let mut blobs = self.blobs.lock().expect("test: lock");
            let height = (blobs.len() as u64) + 1;
            blobs.push((namespace.clone(), data));
            Ok(DABlobRef {
                height,
                namespace,
                commitment: vec![0xDA; 32],
            })
        })
    }

    fn get_blob(
        &self,
        blob_ref: &DABlobRef,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, DAError>> + Send + '_>> {
        let height = blob_ref.height;
        Box::pin(async move {
            if *self.fail_get.lock().expect("test: lock") {
                return Err(DAError {
                    message: "injected get failure".to_string(),
                });
            }
            let blobs = self.blobs.lock().expect("test: lock");
            let idx = (height as usize).checked_sub(1)
                .ok_or_else(|| DAError { message: "invalid height".to_string() })?;
            blobs.get(idx)
                .map(|(_, data)| data.clone())
                .ok_or_else(|| DAError { message: "blob not found".to_string() })
        })
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════════════════════════════════════

fn sid(seed: u8) -> SessionId { SessionId::new([seed; 32]) }
fn wid(seed: u8) -> WorkloadId { WorkloadId::new([seed; 32]) }
fn cid(seed: u8) -> CoordinatorId { CoordinatorId::new([seed; 32]) }

fn empty_agg() -> AggregateSignatureProto {
    AggregateSignatureProto {
        signature: vec![], signer_ids: vec![],
        message_hash: vec![], aggregated_at: 0,
    }
}

fn storage_receipt() -> ReceiptV1Proto {
    ReceiptV1Proto {
        workload_id: vec![0x01; 32], node_id: vec![0x02; 32],
        receipt_type: 0, usage_proof_hash: vec![0x03; 32],
        execution_commitment: None,
        coordinator_threshold_signature: empty_agg(),
        node_signature: vec![0x07; 64], submitter_address: vec![0x08; 20],
        reward_base: 1000, timestamp: 1_700_000_000, epoch: 42,
    }
}

fn commitment(seed: u8, ssid: u8) -> SigningCommitmentProto {
    SigningCommitmentProto {
        session_id: vec![ssid; 32], signer_id: vec![seed; 32],
        hiding: vec![seed; 32], binding: vec![seed.wrapping_add(1); 32],
        timestamp: 0,
    }
}

fn partial_sig(seed: u8, ssid: u8) -> PartialSignatureProto {
    PartialSignatureProto {
        session_id: vec![ssid; 32], signer_id: vec![seed; 32],
        commitment: commitment(seed, ssid), signature_share: vec![seed; 32],
    }
}

fn drive_session(s: &mut ReceiptSigningSession, ssid: u8) {
    s.add_commitment(cid(0x0A), commitment(0x0A, ssid)).expect("test");
    s.add_commitment(cid(0x0B), commitment(0x0B, ssid)).expect("test");
    s.add_partial(cid(0x0A), partial_sig(0x0A, ssid)).expect("test");
    s.add_partial(cid(0x0B), partial_sig(0x0B, ssid)).expect("test");
    let _ = s.try_aggregate().expect("test");
}

fn make_state() -> MultiCoordinatorState {
    let mut committee = HashSet::new();
    committee.insert(cid(0x00));
    committee.insert(cid(0x0A));
    committee.insert(cid(0x0B));
    MultiCoordinatorState::new(cid(0x00), committee, 2, 30_000)
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

/// 10) Receipt assembly from completed session.
#[test]
fn test_receipt_assembly_completed_session() {
    let mut session = ReceiptSigningSession::new_storage(
        sid(0x10), wid(0x10), 2, storage_receipt(),
    );
    drive_session(&mut session, 0x10);

    let receipt = assemble_signed_receipt(&session);
    assert!(receipt.is_ok());
    let receipt = receipt.expect("test");
    assert_eq!(receipt.epoch, 42);
    assert!(validate_receipt_proto(&receipt).is_ok());
}

/// 11) DA publication mock (integration).
#[tokio::test]
async fn test_da_publication_mock() {
    let da = TestDA::new();
    let publisher = ReceiptPublisher::new(b"dsdn_receipts".to_vec());

    let mut session = ReceiptSigningSession::new_storage(
        sid(0x11), wid(0x11), 2, storage_receipt(),
    );
    drive_session(&mut session, 0x11);
    let receipt = assemble_signed_receipt(&session).expect("test");

    let blob_ref = publisher.publish_receipt(&receipt, &da).await;
    assert!(blob_ref.is_ok());
    let blob_ref = blob_ref.expect("test");
    assert_eq!(blob_ref.height, 1);
}

/// 12) DA retrieval + decode (integration).
#[tokio::test]
async fn test_da_retrieval_decode() {
    let da = TestDA::new();
    let publisher = ReceiptPublisher::new(b"dsdn_receipts".to_vec());

    let mut session = ReceiptSigningSession::new_storage(
        sid(0x12), wid(0x12), 2, storage_receipt(),
    );
    drive_session(&mut session, 0x12);
    let original = assemble_signed_receipt(&session).expect("test");

    let blob_ref = publisher.publish_receipt(&original, &da).await.expect("test");
    let retrieved = publisher.retrieve_receipt(&blob_ref, &da).await.expect("test");

    assert_eq!(retrieved.workload_id, original.workload_id);
    assert_eq!(retrieved.epoch, original.epoch);
    assert_eq!(retrieved.reward_base, original.reward_base);
}

/// 25) DA client error propagation.
#[tokio::test]
async fn test_da_client_error_propagation() {
    let da = TestDA::new();
    da.set_fail_submit(true);
    let publisher = ReceiptPublisher::new(b"dsdn_receipts".to_vec());

    let mut session = ReceiptSigningSession::new_storage(
        sid(0x25), wid(0x25), 2, storage_receipt(),
    );
    drive_session(&mut session, 0x25);
    let receipt = assemble_signed_receipt(&session).expect("test");

    let result = publisher.publish_receipt(&receipt, &da).await;
    assert!(matches!(result, Err(PublishError::DASubmitFailed(_))));
}

/// 26) Invalid receipt validation failure.
#[test]
fn test_invalid_receipt_validation() {
    let mut receipt = storage_receipt();
    receipt.workload_id = vec![0x01; 16]; // Wrong length — should be 32.
    let result = validate_receipt_proto(&receipt);
    assert!(result.is_err());
}

/// 34) CoordinatorState counter increment correctness.
#[test]
fn test_counter_increment() {
    let mut state = make_state();
    for i in 0..3u8 {
        let mut s = ReceiptSigningSession::new_storage(
            sid(0xA0 + i), wid(0xA0 + i), 2, storage_receipt(),
        );
        drive_session(&mut s, 0xA0 + i);
        state.register_receipt_signing(sid(0xA0 + i), s).expect("test");
        let _ = state.complete_receipt_signing(&sid(0xA0 + i)).expect("test");
    }
    assert_eq!(state.total_receipts_signed(), 3);
}

/// 35) Completed receipt stored correctly.
#[test]
fn test_completed_receipt_stored() {
    let mut state = make_state();
    let mut session = ReceiptSigningSession::new_storage(
        sid(0x35), wid(0x35), 2, storage_receipt(),
    );
    drive_session(&mut session, 0x35);
    state.register_receipt_signing(sid(0x35), session).expect("test");
    let _ = state.complete_receipt_signing(&sid(0x35)).expect("test");

    let completed = state.completed_receipts();
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0].0, sid(0x35));
    assert_eq!(completed[0].1.epoch, 42);
}

/// 36) No session leak after completion.
#[test]
fn test_no_session_leak() {
    let mut state = make_state();
    let mut session = ReceiptSigningSession::new_storage(
        sid(0x36), wid(0x36), 2, storage_receipt(),
    );
    drive_session(&mut session, 0x36);
    state.register_receipt_signing(sid(0x36), session).expect("test");

    assert_eq!(state.receipt_signing_session_count(), 1);
    let _ = state.complete_receipt_signing(&sid(0x36)).expect("test");
    assert_eq!(state.receipt_signing_session_count(), 0);
    assert!(!state.has_receipt_signing_session(&sid(0x36)));
}

/// 37) Receipt retrieval integrity (encode → decode roundtrip).
#[tokio::test]
async fn test_receipt_retrieval_integrity() {
    let da = TestDA::new();
    let publisher = ReceiptPublisher::new(b"test_ns".to_vec());

    let mut session = ReceiptSigningSession::new_storage(
        sid(0x37), wid(0x37), 2, storage_receipt(),
    );
    drive_session(&mut session, 0x37);
    let original = assemble_signed_receipt(&session).expect("test");

    let blob_ref = publisher.publish_receipt(&original, &da).await.expect("test");
    let retrieved = publisher.retrieve_receipt(&blob_ref, &da).await.expect("test");

    // Full field-by-field comparison.
    assert_eq!(retrieved.workload_id, original.workload_id);
    assert_eq!(retrieved.node_id, original.node_id);
    assert_eq!(retrieved.receipt_type, original.receipt_type);
    assert_eq!(retrieved.usage_proof_hash, original.usage_proof_hash);
    assert_eq!(retrieved.node_signature, original.node_signature);
    assert_eq!(retrieved.reward_base, original.reward_base);
    assert_eq!(retrieved.timestamp, original.timestamp);
    assert_eq!(retrieved.epoch, original.epoch);
}

/// 38) Namespace consistency in DA publisher.
#[test]
fn test_namespace_consistency() {
    let publisher = ReceiptPublisher::new(b"my_namespace".to_vec());
    assert_eq!(publisher.namespace(), b"my_namespace");
}

/// 39) Encoding/decoding consistency.
#[test]
fn test_encoding_decoding_consistency() {
    let mut session = ReceiptSigningSession::new_storage(
        sid(0x39), wid(0x39), 2, storage_receipt(),
    );
    drive_session(&mut session, 0x39);
    let receipt = assemble_signed_receipt(&session).expect("test");

    let encoded = encode_receipt(&receipt).expect("test");
    let decoded = decode_receipt(&encoded).expect("test");
    assert_eq!(decoded.workload_id, receipt.workload_id);
    assert_eq!(decoded.epoch, receipt.epoch);
    assert_eq!(decoded.reward_base, receipt.reward_base);

    // Deterministic: same receipt → same bytes.
    let encoded2 = encode_receipt(&receipt).expect("test");
    assert_eq!(encoded, encoded2);
}

/// 45) End-to-end: usage → signing → assembly → DA publish → retrieve.
#[tokio::test]
async fn test_e2e_usage_signing_assembly_da() {
    // ── Step 1: Usage proof verification ──────────────────────────────
    let key = SigningKey::from_bytes(&{
        let mut s = [0u8; 32]; s[0] = 0x42; s
    });
    let vk = key.verifying_key();

    let mut proof = UsageProof {
        workload_id: CommonWorkloadId::new([0x01; 32]),
        node_id: vk.to_bytes(),
        cpu_cycles: 500,
        ram_bytes: 1024,
        chunk_count: 10,
        bandwidth_bytes: 2048,
        proof_data: vec![0xAB; 16],
        node_signature: vec![],
    };
    let msg = build_signing_message(&proof);
    proof.node_signature = key.sign(&msg).to_bytes().to_vec();

    let usage_result = verify_usage_proof(&proof);
    let reward_base = match usage_result {
        UsageVerificationResult::Valid { reward_base } => reward_base,
        UsageVerificationResult::Invalid { reason } => {
            panic!("test: usage verification failed: {}", reason);
        }
    };
    assert!(reward_base > 0);

    // ── Step 2: Create receipt data ────────────────────────────────────
    let mut receipt_data = storage_receipt();
    receipt_data.reward_base = reward_base;

    // ── Step 3: Signing session ────────────────────────────────────────
    let mut session = ReceiptSigningSession::new_storage(
        sid(0xE2), wid(0xE2), 2, receipt_data,
    );
    drive_session(&mut session, 0xE2);
    assert_eq!(session.state().name(), "Completed");

    // ── Step 4: Assembly ───────────────────────────────────────────────
    let receipt = assemble_signed_receipt(&session).expect("test: assembly");
    assert_eq!(receipt.reward_base, reward_base);
    assert!(validate_receipt_proto(&receipt).is_ok());

    // ── Step 5: DA publication ─────────────────────────────────────────
    let da = TestDA::new();
    let publisher = ReceiptPublisher::new(b"dsdn_e2e".to_vec());
    let blob_ref = publisher.publish_receipt(&receipt, &da).await
        .expect("test: publish");
    assert_eq!(blob_ref.height, 1);

    // ── Step 6: Retrieve + verify ──────────────────────────────────────
    let retrieved = publisher.retrieve_receipt(&blob_ref, &da).await
        .expect("test: retrieve");
    assert_eq!(retrieved.reward_base, reward_base);
    assert_eq!(retrieved.epoch, receipt.epoch);
    assert_eq!(retrieved.workload_id, receipt.workload_id);
}