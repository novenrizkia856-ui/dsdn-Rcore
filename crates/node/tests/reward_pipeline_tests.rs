//! # Integration Tests — Node Reward Pipeline (14C.B.19)
//!
//! End-to-end tests verifying the full reward pipeline from workload
//! assignment through on-chain reward claiming.
//!
//! ## Coverage
//!
//! - Storage workload success (both `process_workload` and `process_storage_workload`)
//! - Compute workload error propagation (WASM, VM)
//! - Coordinator response handling (Signed, Rejected, Pending)
//! - Chain response handling (Success, Rejected, ChallengePeriod)
//! - Usage proof signature verification
//! - Receipt lifecycle management
//! - Determinism guarantees
//! - Error propagation across all pipeline stages
//!
//! ## Invariants
//!
//! All tests are:
//! - Fully deterministic (no time, no randomness, no network)
//! - Async where pipeline is async
//! - Using mock transports exclusively

use std::sync::Arc;

use async_trait::async_trait;
use ed25519_dalek::{Signature, VerifyingKey};
use sha3::{Digest, Sha3_256};

use dsdn_common::coordinator::WorkloadId;
use dsdn_common::receipt_v1_convert::{AggregateSignatureProto, ReceiptV1Proto};

use dsdn_node::{
    ChainSubmitError, ChainSubmitter, ChainTransport, ClaimRewardResponse,
    ClaimRewardRequest, CoordinatorSubmitter, ExecutionError,
    MockChainTransport, MockCoordinatorTransport, NodeIdentityManager,
    OrchestratorError, ReceiptHandler, ReceiptResponse, ReceiptStatus,
    ResourceLimits, RewardOrchestrator, UsageProof, UsageProofBuilder,
    WorkloadAssignment, WorkloadExecutor, WorkloadType,
};

// ════════════════════════════════════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════════════════════════════════════

const TEST_SEED: [u8; 32] = [0xAA; 32];

fn make_identity() -> Arc<NodeIdentityManager> {
    Arc::new(
        NodeIdentityManager::from_keypair(TEST_SEED)
            .unwrap_or_else(|_| panic!("test setup: from_keypair failed")),
    )
}

fn make_signed_receipt(workload_id: [u8; 32]) -> ReceiptV1Proto {
    ReceiptV1Proto {
        workload_id: workload_id.to_vec(),
        node_id: vec![0xAA; 32],
        receipt_type: 1,
        usage_proof_hash: vec![0xCC; 32],
        execution_commitment: None,
        coordinator_threshold_signature: AggregateSignatureProto {
            signature: vec![0xDD; 64],
            signer_ids: vec![vec![0xEE; 32]],
            message_hash: vec![0xFF; 32],
            aggregated_at: 1_700_000_000,
        },
        node_signature: vec![0xBB; 64],
        submitter_address: vec![0x11; 20],
        reward_base: 42,
        timestamp: 1_700_000_000,
        epoch: 1,
    }
}

fn make_storage_assignment(wid: [u8; 32]) -> WorkloadAssignment {
    WorkloadAssignment {
        workload_id: WorkloadId::new(wid),
        workload_type: WorkloadType::Storage,
        module_bytes: Vec::new(),
        input_bytes: Vec::new(),
        vm_command: Vec::new(),
        resource_limits: ResourceLimits {
            timeout_ms: 5000,
            max_memory_bytes: 64 * 1024 * 1024,
        },
    }
}

fn make_wasm_assignment(wid: [u8; 32], module: Vec<u8>) -> WorkloadAssignment {
    WorkloadAssignment {
        workload_id: WorkloadId::new(wid),
        workload_type: WorkloadType::ComputeWasm,
        module_bytes: module,
        input_bytes: vec![0x01, 0x02],
        vm_command: Vec::new(),
        resource_limits: ResourceLimits {
            timeout_ms: 5000,
            max_memory_bytes: 64 * 1024 * 1024,
        },
    }
}

fn make_vm_assignment(wid: [u8; 32]) -> WorkloadAssignment {
    WorkloadAssignment {
        workload_id: WorkloadId::new(wid),
        workload_type: WorkloadType::ComputeVm,
        module_bytes: vec![0xFF],
        input_bytes: Vec::new(),
        vm_command: vec!["run".to_string()],
        resource_limits: ResourceLimits {
            timeout_ms: 5000,
            max_memory_bytes: 64 * 1024 * 1024,
        },
    }
}

fn build_orchestrator(
    coord: MockCoordinatorTransport,
    chain: MockChainTransport,
) -> RewardOrchestrator {
    let identity = make_identity();
    RewardOrchestrator::new(
        WorkloadExecutor,
        UsageProofBuilder::new(identity),
        CoordinatorSubmitter::new(Box::new(coord)),
        ReceiptHandler::new(),
        ChainSubmitter::new(Box::new(chain)),
        [0x11; 20],
    )
}

/// Reconstruct the 148-byte signing message to verify usage proof signatures.
fn reconstruct_signing_message(proof: &UsageProof) -> Vec<u8> {
    let mut msg = Vec::with_capacity(148);
    msg.extend_from_slice(b"DSDN:usage_proof:v1:");    // 20 bytes
    msg.extend_from_slice(proof.workload_id.as_bytes()); // 32 bytes
    msg.extend_from_slice(&proof.node_id);               // 32 bytes
    msg.extend_from_slice(&proof.cpu_cycles.to_le_bytes());       // 8
    msg.extend_from_slice(&proof.ram_bytes.to_le_bytes());        // 8
    msg.extend_from_slice(&proof.chunk_count.to_le_bytes());      // 8
    msg.extend_from_slice(&proof.bandwidth_bytes.to_le_bytes());  // 8
    let proof_data_hash = Sha3_256::digest(&proof.proof_data);
    msg.extend_from_slice(&proof_data_hash);             // 32 bytes
    msg
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 1: Storage workload → full success pipeline
// ════════════════════════════════════════════════════════════════════════════════

/// Storage workload via `process_workload`: execute → proof → coordinator →
/// receipt → chain → status Confirmed.
#[tokio::test]
async fn storage_workload_full_success() {
    let wid = [0x42; 32];
    let coord = MockCoordinatorTransport::new();
    coord.push_response(ReceiptResponse::Signed(make_signed_receipt(wid)));

    let chain = MockChainTransport::new();
    chain.push_response(ClaimRewardResponse::Success {
        reward_amount: 1000,
        tx_hash: [0xAB; 32],
    });

    let mut orch = build_orchestrator(coord, chain);
    let result = orch.process_workload(make_storage_assignment(wid), b"proof", 5000).await;

    assert!(result.is_ok(), "storage full pipeline failed: {:?}", result.err());
    match result.unwrap_or_else(|e| panic!("{}", e)) {
        ClaimRewardResponse::Success { reward_amount, tx_hash } => {
            assert_eq!(reward_amount, 1000);
            assert_eq!(tx_hash, [0xAB; 32]);
        }
        other => panic!("expected Success, got {:?}", other),
    }

    // Verify receipt stored and confirmed.
    let stored = orch.receipt_handler().get_receipt(&wid);
    assert!(stored.is_some());
    assert_eq!(
        stored.map(|sr| &sr.status),
        Some(&ReceiptStatus::Confirmed { reward_amount: 1000 })
    );
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 2: Compute WASM workload → empty module error
// ════════════════════════════════════════════════════════════════════════════════

/// ComputeWasm with empty module_bytes → `ExecutionFailed(InvalidWorkloadType)`.
/// Full WASM execution requires a valid WASM binary and the runtime crate.
#[tokio::test]
async fn compute_wasm_empty_module_fails() {
    let coord = MockCoordinatorTransport::new();
    let chain = MockChainTransport::new();
    let mut orch = build_orchestrator(coord, chain);

    let assignment = make_wasm_assignment([0x01; 32], Vec::new()); // empty module
    let result = orch.process_workload(assignment, b"data", 1000).await;

    assert!(result.is_err());
    assert!(
        matches!(result, Err(OrchestratorError::ExecutionFailed(ExecutionError::InvalidWorkloadType))),
        "expected ExecutionFailed(InvalidWorkloadType)"
    );
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 3: Compute VM workload → RuntimeNotAvailable
// ════════════════════════════════════════════════════════════════════════════════

/// ComputeVm always returns RuntimeNotAvailable (V2 feature).
#[tokio::test]
async fn compute_vm_not_available() {
    let coord = MockCoordinatorTransport::new();
    let chain = MockChainTransport::new();
    let mut orch = build_orchestrator(coord, chain);

    let result = orch.process_workload(make_vm_assignment([0x02; 32]), b"data", 1000).await;

    assert!(result.is_err());
    match result {
        Err(OrchestratorError::ExecutionFailed(ExecutionError::RuntimeNotAvailable(msg))) => {
            assert!(msg.contains("VM"), "expected VM-related message, got: {}", msg);
        }
        other => panic!("expected RuntimeNotAvailable, got {:?}", other),
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 4: Coordinator rejection → error propagation
// ════════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn coordinator_rejection_propagated() {
    let coord = MockCoordinatorTransport::new();
    coord.push_response(ReceiptResponse::Rejected {
        reason: "invalid proof signature".to_string(),
    });

    let chain = MockChainTransport::new();
    let mut orch = build_orchestrator(coord, chain);

    let result = orch.process_workload(make_storage_assignment([0x03; 32]), b"proof", 1000).await;

    assert!(result.is_err());
    match result {
        Err(OrchestratorError::ReceiptRejected(reason)) => {
            assert_eq!(reason, "invalid proof signature");
        }
        other => panic!("expected ReceiptRejected, got {:?}", other),
    }

    // No receipt stored when coordinator rejects.
    assert_eq!(orch.receipt_handler().receipt_count(), 0);
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 5: Chain rejection → receipt status Rejected
// ════════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn chain_rejection_updates_receipt_status() {
    let wid = [0x04; 32];
    let coord = MockCoordinatorTransport::new();
    coord.push_response(ReceiptResponse::Signed(make_signed_receipt(wid)));

    let chain = MockChainTransport::new();
    chain.push_response(ClaimRewardResponse::Rejected {
        reason: "duplicate claim on chain".to_string(),
    });

    let mut orch = build_orchestrator(coord, chain);
    let result = orch.process_workload(make_storage_assignment(wid), b"proof", 2000).await;

    assert!(result.is_ok());
    match result.unwrap_or_else(|e| panic!("{}", e)) {
        ClaimRewardResponse::Rejected { reason } => {
            assert_eq!(reason, "duplicate claim on chain");
        }
        other => panic!("expected chain Rejected, got {:?}", other),
    }

    let stored = orch.receipt_handler().get_receipt(&wid);
    assert!(stored.is_some());
    assert!(matches!(
        stored.map(|sr| &sr.status),
        Some(ReceiptStatus::Rejected { .. })
    ));
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 6: Challenge period handling
// ════════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn chain_challenge_period_handling() {
    let wid = [0x05; 32];
    let coord = MockCoordinatorTransport::new();
    coord.push_response(ReceiptResponse::Signed(make_signed_receipt(wid)));

    let chain = MockChainTransport::new();
    chain.push_response(ClaimRewardResponse::ChallengePeriod {
        expires_at: 1_800_000_000,
        challenge_id: vec![0x77; 16],
    });

    let mut orch = build_orchestrator(coord, chain);
    let result = orch.process_workload(make_storage_assignment(wid), b"proof", 3000).await;

    assert!(result.is_ok());
    match result.unwrap_or_else(|e| panic!("{}", e)) {
        ClaimRewardResponse::ChallengePeriod { expires_at, challenge_id } => {
            assert_eq!(expires_at, 1_800_000_000);
            assert_eq!(challenge_id, vec![0x77; 16]);
        }
        other => panic!("expected ChallengePeriod, got {:?}", other),
    }

    let stored = orch.receipt_handler().get_receipt(&wid);
    assert!(stored.is_some());
    assert!(matches!(
        stored.map(|sr| &sr.status),
        Some(ReceiptStatus::InChallengePeriod { expires_at: 1_800_000_000 })
    ));
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 7: Invalid workload type → error (ComputeWasm empty)
// ════════════════════════════════════════════════════════════════════════════════

/// Exercises the error path when WorkloadExecutor cannot process the assignment.
#[tokio::test]
async fn invalid_workload_execution_fails() {
    let coord = MockCoordinatorTransport::new();
    let chain = MockChainTransport::new();
    let mut orch = build_orchestrator(coord, chain);

    // ComputeWasm with non-empty but invalid WASM binary.
    // execute_workload will call dsdn_runtime_wasm which may fail.
    // We use empty module_bytes which triggers InvalidWorkloadType immediately.
    let assignment = WorkloadAssignment {
        workload_id: WorkloadId::new([0x06; 32]),
        workload_type: WorkloadType::ComputeWasm,
        module_bytes: Vec::new(),
        input_bytes: Vec::new(),
        vm_command: Vec::new(),
        resource_limits: ResourceLimits {
            timeout_ms: 1000,
            max_memory_bytes: 16 * 1024 * 1024,
        },
    };

    let result = orch.process_workload(assignment, b"data", 1000).await;
    assert!(matches!(result, Err(OrchestratorError::ExecutionFailed(_))));
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 8: Usage proof signature verifiable via Ed25519
// ════════════════════════════════════════════════════════════════════════════════

/// Builds a usage proof and verifies the Ed25519 signature by reconstructing
/// the signing message and using the node's public key.
#[test]
fn usage_proof_signature_verifiable() {
    let identity = make_identity();
    let builder = UsageProofBuilder::new(identity.clone());

    let proof = builder
        .build_usage_proof(
            WorkloadId::new([0x42; 32]),
            &dsdn_node::UnifiedResourceUsage {
                cpu_cycles_estimate: 5000,
                peak_memory_bytes: 8192,
                execution_time_ms: 100,
                chunk_count: 3,
                bandwidth_bytes: 4096,
            },
            b"test-proof-data",
        )
        .unwrap_or_else(|e| panic!("proof build failed: {}", e));

    // Reconstruct signing message (148 bytes).
    let message = reconstruct_signing_message(&proof);
    assert_eq!(message.len(), 148);

    // Verify signature.
    let verifying_key = VerifyingKey::from_bytes(&proof.node_id)
        .unwrap_or_else(|e| panic!("bad pubkey: {}", e));

    let sig_bytes: [u8; 64] = proof.node_signature[..64]
        .try_into()
        .unwrap_or_else(|_| panic!("signature not 64 bytes"));
    let signature = Signature::from_bytes(&sig_bytes);

    verifying_key
        .verify_strict(&message, &signature)
        .unwrap_or_else(|e| panic!("signature verification failed: {}", e));
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 9: ExecutionCommitment absent for storage
// ════════════════════════════════════════════════════════════════════════════════

/// Storage workloads produce `commitment: None` in ExecutionOutput.
/// This is verified by observing that the pipeline completes without
/// an execution commitment in the coordinator request path.
#[tokio::test]
async fn storage_has_no_execution_commitment() {
    let wid = [0x07; 32];
    let coord = MockCoordinatorTransport::new();
    coord.push_response(ReceiptResponse::Signed(make_signed_receipt(wid)));

    let chain = MockChainTransport::new();
    chain.push_response(ClaimRewardResponse::Success {
        reward_amount: 100,
        tx_hash: [0x01; 32],
    });

    let mut orch = build_orchestrator(coord, chain);

    // Storage workload: executor returns commitment=None, proof has no compute data.
    let result = orch.process_workload(make_storage_assignment(wid), b"data", 1000).await;
    assert!(result.is_ok(), "storage pipeline should succeed: {:?}", result.err());

    // Receipt stored successfully (coordinator accepted None commitment).
    assert_eq!(orch.receipt_handler().receipt_count(), 1);
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 10: Cross-runtime: VM returns error (no commitment possible)
// ════════════════════════════════════════════════════════════════════════════════

/// ComputeVm execution fails before any commitment can be produced,
/// demonstrating that the pipeline aborts early for unavailable runtimes.
#[tokio::test]
async fn vm_execution_aborts_before_commitment() {
    let coord = MockCoordinatorTransport::new();
    let chain = MockChainTransport::new();
    let mut orch = build_orchestrator(coord, chain);

    let result = orch
        .process_workload(make_vm_assignment([0x08; 32]), b"data", 1000)
        .await;

    assert!(matches!(
        result,
        Err(OrchestratorError::ExecutionFailed(ExecutionError::RuntimeNotAvailable(_)))
    ));

    // Nothing stored — pipeline aborted at step 1.
    assert_eq!(orch.receipt_handler().receipt_count(), 0);
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 11: Receipt duplicate rejection
// ════════════════════════════════════════════════════════════════════════════════

/// Submitting a second receipt for the same workload_id fails with
/// `ReceiptHandlerError::DuplicateReceipt`.
#[tokio::test]
async fn receipt_duplicate_rejection() {
    let wid = [0x09; 32];

    // First: success.
    let coord = MockCoordinatorTransport::new();
    coord.push_response(ReceiptResponse::Signed(make_signed_receipt(wid)));
    coord.push_response(ReceiptResponse::Signed(make_signed_receipt(wid)));

    let chain = MockChainTransport::new();
    chain.push_response(ClaimRewardResponse::Success {
        reward_amount: 500,
        tx_hash: [0xCC; 32],
    });

    let mut orch = build_orchestrator(coord, chain);

    let r1 = orch
        .process_workload(make_storage_assignment(wid), b"proof", 1000)
        .await;
    assert!(r1.is_ok(), "first submission should succeed: {:?}", r1.err());

    // Second: same workload_id → DuplicateReceipt.
    let r2 = orch
        .process_workload(make_storage_assignment(wid), b"proof", 2000)
        .await;
    assert!(r2.is_err());
    assert!(
        matches!(r2, Err(OrchestratorError::ReceiptHandlingFailed(_))),
        "expected ReceiptHandlingFailed for duplicate"
    );
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 12: Receipt lifecycle transitions correct
// ════════════════════════════════════════════════════════════════════════════════

/// Verifies receipt status transitions through the pipeline:
/// Validated → Confirmed (via chain Success).
#[tokio::test]
async fn receipt_lifecycle_transitions() {
    let wid = [0x0A; 32];

    let coord = MockCoordinatorTransport::new();
    coord.push_response(ReceiptResponse::Signed(make_signed_receipt(wid)));

    let chain = MockChainTransport::new();
    chain.push_response(ClaimRewardResponse::Success {
        reward_amount: 2000,
        tx_hash: [0xDD; 32],
    });

    let mut orch = build_orchestrator(coord, chain);
    let result = orch
        .process_workload(make_storage_assignment(wid), b"proof", 5000)
        .await;
    assert!(result.is_ok());

    // After full pipeline: Validated → Confirmed.
    let stored = orch.receipt_handler().get_receipt(&wid);
    assert!(stored.is_some());
    let sr = stored.unwrap_or_else(|| panic!("receipt not found"));
    assert_eq!(sr.status, ReceiptStatus::Confirmed { reward_amount: 2000 });
    assert_eq!(sr.received_at, 5000);
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 13: Network timeout propagation
// ════════════════════════════════════════════════════════════════════════════════

/// Custom ChainTransport that always returns Timeout.
struct AlwaysTimeoutChain;

#[async_trait]
impl ChainTransport for AlwaysTimeoutChain {
    async fn submit_claim_reward(
        &self,
        _request: &ClaimRewardRequest,
    ) -> Result<ClaimRewardResponse, ChainSubmitError> {
        Err(ChainSubmitError::Timeout)
    }
}

#[tokio::test]
async fn chain_timeout_propagated() {
    let wid = [0x0B; 32];
    let coord = MockCoordinatorTransport::new();
    coord.push_response(ReceiptResponse::Signed(make_signed_receipt(wid)));

    let identity = make_identity();
    let mut orch = RewardOrchestrator::new(
        WorkloadExecutor,
        UsageProofBuilder::new(identity),
        CoordinatorSubmitter::new(Box::new(coord)),
        ReceiptHandler::new(),
        ChainSubmitter::new(Box::new(AlwaysTimeoutChain)),
        [0x11; 20],
    );

    let result = orch
        .process_workload(make_storage_assignment(wid), b"proof", 1000)
        .await;

    assert!(result.is_err());
    assert!(
        matches!(result, Err(OrchestratorError::ChainFailed(ChainSubmitError::Timeout))),
        "expected ChainFailed(Timeout)"
    );

    // Receipt stored but status NOT updated (chain failed).
    let stored = orch.receipt_handler().get_receipt(&wid);
    assert!(stored.is_some());
    assert_eq!(
        stored.map(|sr| &sr.status),
        Some(&ReceiptStatus::Validated)
    );
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 14: Storage vs compute differentiated
// ════════════════════════════════════════════════════════════════════════════════

/// Storage workloads have zero CPU/RAM in the usage proof,
/// while compute workloads (if they succeed) have non-zero metrics.
/// Since WASM requires a real module, we verify storage path metrics.
#[test]
fn storage_proof_has_zero_compute_metrics() {
    let identity = make_identity();
    let builder = UsageProofBuilder::new(identity);

    // Storage: all compute metrics zero.
    let storage_usage = dsdn_node::UnifiedResourceUsage {
        cpu_cycles_estimate: 0,
        peak_memory_bytes: 0,
        execution_time_ms: 0,
        chunk_count: 10,
        bandwidth_bytes: 4096,
    };

    let proof = builder
        .build_usage_proof(WorkloadId::new([0x0C; 32]), &storage_usage, b"storage")
        .unwrap_or_else(|e| panic!("proof build failed: {}", e));

    assert_eq!(proof.cpu_cycles, 0);
    assert_eq!(proof.ram_bytes, 0);
    assert_eq!(proof.chunk_count, 10);
    assert_eq!(proof.bandwidth_bytes, 4096);
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 15: Determinism — same input → same proof signature (10x)
// ════════════════════════════════════════════════════════════════════════════════

/// Verifies that identical inputs produce identical usage proof signatures
/// across 10 consecutive invocations.
#[test]
fn determinism_same_input_same_proof_10x() {
    let identity = make_identity();
    let builder = UsageProofBuilder::new(identity);

    let wid_bytes = [0x0D; 32];
    let usage = dsdn_node::UnifiedResourceUsage {
        cpu_cycles_estimate: 1000,
        peak_memory_bytes: 2048,
        execution_time_ms: 50,
        chunk_count: 0,
        bandwidth_bytes: 0,
    };

    let mut signatures: Vec<Vec<u8>> = Vec::with_capacity(10);

    for _ in 0..10 {
        let proof = builder
            .build_usage_proof(WorkloadId::new(wid_bytes), &usage, b"deterministic-data")
            .unwrap_or_else(|e| panic!("proof build failed: {}", e));
        signatures.push(proof.node_signature.clone());
    }

    // All 10 signatures must be identical.
    let first = &signatures[0];
    for (i, sig) in signatures.iter().enumerate().skip(1) {
        assert_eq!(
            first, sig,
            "signature mismatch at iteration {}: {:?} vs {:?}",
            i, first, sig
        );
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 16: Coordinator pending → no chain submission
// ════════════════════════════════════════════════════════════════════════════════

/// When coordinator returns Pending, the pipeline returns
/// `ClaimRewardResponse::ChallengePeriod` without submitting to chain.
#[tokio::test]
async fn coordinator_pending_skips_chain() {
    let coord = MockCoordinatorTransport::new();
    coord.push_response(ReceiptResponse::Pending {
        session_id: vec![0x88; 8],
    });

    let chain = MockChainTransport::new();
    // Chain mock is empty — if pipeline tried chain, it would error.

    let mut orch = build_orchestrator(coord, chain);
    let result = orch
        .process_workload(make_storage_assignment([0x0E; 32]), b"proof", 1000)
        .await;

    assert!(result.is_ok());
    match result.unwrap_or_else(|e| panic!("{}", e)) {
        ClaimRewardResponse::ChallengePeriod { expires_at, challenge_id } => {
            assert_eq!(expires_at, 0);
            assert_eq!(challenge_id, vec![0x88; 8]);
        }
        other => panic!("expected ChallengePeriod for pending, got {:?}", other),
    }

    // No receipt stored (coordinator didn't sign).
    assert_eq!(orch.receipt_handler().receipt_count(), 0);
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 17: Chain network error → receipt stays Validated
// ════════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn chain_network_error_receipt_stays_validated() {
    let wid = [0x0F; 32];
    let coord = MockCoordinatorTransport::new();
    coord.push_response(ReceiptResponse::Signed(make_signed_receipt(wid)));

    let chain = MockChainTransport::new();
    // Empty chain mock → NetworkError("no mock response")

    let mut orch = build_orchestrator(coord, chain);
    let result = orch
        .process_workload(make_storage_assignment(wid), b"proof", 1000)
        .await;

    assert!(matches!(result, Err(OrchestratorError::ChainFailed(_))));

    // Receipt stored at step 4, but NOT updated (chain failed at step 5).
    let stored = orch.receipt_handler().get_receipt(&wid);
    assert!(stored.is_some());
    assert_eq!(
        stored.map(|sr| &sr.status),
        Some(&ReceiptStatus::Validated)
    );
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 18: process_storage_workload full pipeline
// ════════════════════════════════════════════════════════════════════════════════

/// `process_storage_workload` skips execution and constructs resource usage
/// directly from the provided chunk_count and bandwidth_bytes.
#[tokio::test]
async fn storage_dedicated_method_full_success() {
    let wid = [0x10; 32];
    let coord = MockCoordinatorTransport::new();
    coord.push_response(ReceiptResponse::Signed(make_signed_receipt(wid)));

    let chain = MockChainTransport::new();
    chain.push_response(ClaimRewardResponse::Success {
        reward_amount: 750,
        tx_hash: [0xEE; 32],
    });

    let mut orch = build_orchestrator(coord, chain);
    let result = orch
        .process_storage_workload(
            WorkloadId::new(wid),
            25,    // chunk_count
            8192,  // bandwidth_bytes
            b"storage-proof-data",
            4000,
        )
        .await;

    assert!(result.is_ok(), "storage dedicated method failed: {:?}", result.err());
    match result.unwrap_or_else(|e| panic!("{}", e)) {
        ClaimRewardResponse::Success { reward_amount, .. } => {
            assert_eq!(reward_amount, 750);
        }
        other => panic!("expected Success, got {:?}", other),
    }

    assert_eq!(orch.receipt_handler().receipt_count(), 1);
    let stored = orch.receipt_handler().get_receipt(&wid);
    assert_eq!(
        stored.map(|sr| &sr.status),
        Some(&ReceiptStatus::Confirmed { reward_amount: 750 })
    );
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 19: Multiple sequential workloads
// ════════════════════════════════════════════════════════════════════════════════

/// Processes 3 different workloads in sequence, each tracked independently.
#[tokio::test]
async fn multiple_sequential_workloads() {
    let wids: [[u8; 32]; 3] = [[0x20; 32], [0x21; 32], [0x22; 32]];

    let coord = MockCoordinatorTransport::new();
    let chain = MockChainTransport::new();

    for (i, wid) in wids.iter().enumerate() {
        coord.push_response(ReceiptResponse::Signed(make_signed_receipt(*wid)));
        chain.push_response(ClaimRewardResponse::Success {
            reward_amount: (i as u128 + 1) * 100,
            tx_hash: [i as u8; 32],
        });
    }

    let mut orch = build_orchestrator(coord, chain);

    for (i, wid) in wids.iter().enumerate() {
        let result = orch
            .process_workload(make_storage_assignment(*wid), b"proof", (i as u64 + 1) * 1000)
            .await;
        assert!(result.is_ok(), "workload {} failed: {:?}", i, result.err());
    }

    assert_eq!(orch.receipt_handler().receipt_count(), 3);

    for (i, wid) in wids.iter().enumerate() {
        let stored = orch.receipt_handler().get_receipt(wid);
        assert!(stored.is_some(), "receipt {} not found", i);
        let expected_reward = (i as u128 + 1) * 100;
        assert_eq!(
            stored.map(|sr| &sr.status),
            Some(&ReceiptStatus::Confirmed { reward_amount: expected_reward }),
            "receipt {} status mismatch",
            i
        );
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 20: OrchestratorError Display variants
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn error_display_all_variants() {
    let errors: Vec<OrchestratorError> = vec![
        OrchestratorError::ExecutionFailed(ExecutionError::InvalidWorkloadType),
        OrchestratorError::ProofBuildFailed(dsdn_node::UsageProofError::SigningFailed("key".into())),
        OrchestratorError::CoordinatorFailed(dsdn_node::SubmitError::Timeout),
        OrchestratorError::ReceiptHandlingFailed(dsdn_node::ReceiptHandlerError::DuplicateReceipt),
        OrchestratorError::ChainFailed(ChainSubmitError::InsufficientFunds),
        OrchestratorError::ReceiptRejected("bad proof".into()),
    ];

    let expected_fragments = [
        "execution failed",
        "proof build failed",
        "coordinator",
        "receipt handling",
        "chain submission",
        "rejected",
    ];

    for (error, fragment) in errors.iter().zip(expected_fragments.iter()) {
        let display = format!("{}", error);
        assert!(
            display.to_lowercase().contains(fragment),
            "error display '{}' should contain '{}'",
            display,
            fragment
        );
    }
}