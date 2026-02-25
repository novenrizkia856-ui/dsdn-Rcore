//! # RewardOrchestrator — Full Reward Pipeline (14C.B.18)
//!
//! Orchestrates the complete reward pipeline from workload execution
//! through on-chain reward claiming, integrating all node subsystems:
//!
//! ```text
//! WorkloadAssignment
//!      │
//!      ▼ (1) Execute
//! WorkloadExecutor::execute_workload()
//!      │
//!      ▼ (2) Build proof
//! UsageProofBuilder::build_usage_proof()
//!      │
//!      ▼ (3) Submit to coordinator
//! CoordinatorSubmitter::submit()
//!      │
//!      ├─ Signed(ReceiptV1Proto) ────────────────────┐
//!      ├─ Rejected { reason } → Err(ReceiptRejected) │
//!      └─ Pending { session_id } → Ok(Pending)       │
//!                                                     │
//!      ┌──────────────────────────────────────────────┘
//!      ▼ (4) Store receipt
//! ReceiptHandler::handle_receipt()
//!      │
//!      ▼ (5) Submit to chain
//! ChainSubmitter::submit_claim()
//!      │
//!      ▼ (6) Update receipt status
//! ReceiptHandler::update_status()
//!      │
//!      ▼
//! ClaimRewardResponse { Success | Rejected | ChallengePeriod }
//! ```
//!
//! ## Separation of Concerns
//!
//! `RewardOrchestrator` is a **glue layer only**. It does NOT:
//!
//! - Perform cryptographic operations (delegated to subsystems).
//! - Retry on failure (caller's responsibility).
//! - Transform data beyond constructing requests.
//! - Hold network connections (delegated to transport traits).
//!
//! ## Atomicity & State Consistency
//!
//! - Receipt status is only updated **after** chain response.
//! - If chain submission fails, receipt status remains `Validated`.
//! - No partial updates: either the full status transition succeeds
//!   or the receipt state is unchanged.
//!
//! ## Safety
//!
//! - No `panic!`, `unwrap()`, `expect()`.
//! - All errors are mapped to [`OrchestratorError`] variants.
//! - Deterministic given identical inputs and mock transports.

use std::fmt;

use dsdn_common::coordinator::WorkloadId;

use crate::chain_submitter::{ChainSubmitError, ChainSubmitter, ClaimRewardResponse};
use crate::coordinator_client::{
    CoordinatorSubmitter, ReceiptRequest, ReceiptResponse, SubmitError,
};
use crate::receipt_handler::{ReceiptHandler, ReceiptHandlerError, ReceiptStatus};
use crate::usage_proof_builder::{UsageProofBuilder, UsageProofError};
use crate::workload_executor::{
    ExecutionError, ExecutionOutput, UnifiedResourceUsage, WorkloadAssignment,
    WorkloadExecutor, WorkloadType,
};

// ════════════════════════════════════════════════════════════════════════════════
// ERROR
// ════════════════════════════════════════════════════════════════════════════════

/// Errors from the reward orchestration pipeline.
///
/// Each variant wraps the error from the specific subsystem that failed,
/// preserving the original error for diagnostics.
#[derive(Debug)]
pub enum OrchestratorError {
    /// Workload execution failed.
    ExecutionFailed(ExecutionError),
    /// Usage proof construction failed.
    ProofBuildFailed(UsageProofError),
    /// Coordinator submission failed (transport-level).
    CoordinatorFailed(SubmitError),
    /// Receipt storage or status update failed.
    ReceiptHandlingFailed(ReceiptHandlerError),
    /// Chain submission failed (transport-level).
    ChainFailed(ChainSubmitError),
    /// Coordinator explicitly rejected the receipt request.
    ReceiptRejected(String),
}

impl fmt::Display for OrchestratorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExecutionFailed(e) => write!(f, "execution failed: {}", e),
            Self::ProofBuildFailed(e) => write!(f, "proof build failed: {}", e),
            Self::CoordinatorFailed(e) => write!(f, "coordinator submission failed: {}", e),
            Self::ReceiptHandlingFailed(e) => write!(f, "receipt handling failed: {}", e),
            Self::ChainFailed(e) => write!(f, "chain submission failed: {}", e),
            Self::ReceiptRejected(reason) => {
                write!(f, "receipt rejected by coordinator: {}", reason)
            }
        }
    }
}

impl std::error::Error for OrchestratorError {}

impl From<ExecutionError> for OrchestratorError {
    fn from(e: ExecutionError) -> Self {
        Self::ExecutionFailed(e)
    }
}

impl From<UsageProofError> for OrchestratorError {
    fn from(e: UsageProofError) -> Self {
        Self::ProofBuildFailed(e)
    }
}

impl From<SubmitError> for OrchestratorError {
    fn from(e: SubmitError) -> Self {
        Self::CoordinatorFailed(e)
    }
}

impl From<ChainSubmitError> for OrchestratorError {
    fn from(e: ChainSubmitError) -> Self {
        Self::ChainFailed(e)
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// ORCHESTRATOR
// ════════════════════════════════════════════════════════════════════════════════

/// Full reward pipeline orchestrator.
///
/// Integrates all node subsystems into a single sequential pipeline:
/// execute → proof → coordinator → receipt → chain → status update.
///
/// ## Ownership
///
/// Owns all subsystem instances. The orchestrator is the single entry
/// point for reward processing — callers interact with it, not with
/// individual subsystems.
///
/// ## No Retry
///
/// Each method performs a single attempt. On failure, the error is
/// returned immediately. Retry logic belongs to the caller.
pub struct RewardOrchestrator {
    /// Stateless workload executor (routes to WASM/VM runtime).
    executor: WorkloadExecutor,
    /// Builds signed usage proofs from execution results.
    proof_builder: UsageProofBuilder,
    /// Submits proofs to the coordinator for receipt signing.
    coordinator: CoordinatorSubmitter,
    /// Stores and manages receipt lifecycle status.
    receipt_handler: ReceiptHandler,
    /// Submits signed receipts to the chain for reward claiming.
    chain_submitter: ChainSubmitter,
    /// 20-byte address for reward claim submissions.
    submitter_address: [u8; 20],
}

impl RewardOrchestrator {
    /// Creates a new orchestrator with all required subsystems.
    ///
    /// All subsystems are moved into the orchestrator and owned for
    /// its lifetime.
    #[must_use]
    pub fn new(
        executor: WorkloadExecutor,
        proof_builder: UsageProofBuilder,
        coordinator: CoordinatorSubmitter,
        receipt_handler: ReceiptHandler,
        chain_submitter: ChainSubmitter,
        submitter_address: [u8; 20],
    ) -> Self {
        Self {
            executor,
            proof_builder,
            coordinator,
            receipt_handler,
            chain_submitter,
            submitter_address,
        }
    }

    /// Processes a compute workload through the full reward pipeline.
    ///
    /// ## Pipeline Steps
    ///
    /// 1. **Execute**: Run the workload via `WorkloadExecutor`.
    /// 2. **Build proof**: Construct a signed `UsageProof` from execution results.
    /// 3. **Submit to coordinator**: Send proof for receipt signing.
    /// 4. **Handle response**:
    ///    - `Signed`: Store receipt, submit to chain, update status.
    ///    - `Rejected`: Return `OrchestratorError::ReceiptRejected`.
    ///    - `Pending`: Return `ClaimRewardResponse::ChallengePeriod`
    ///      (consensus in progress, no chain submission).
    /// 5. **Chain submission**: Claim reward on-chain (only for `Signed`).
    /// 6. **Status update**: Update receipt status based on chain response.
    ///
    /// ## Arguments
    ///
    /// - `assignment`: Workload to execute.
    /// - `proof_data`: Opaque data included in the usage proof (hashed).
    /// - `timestamp`: Caller-provided Unix timestamp for receipt storage.
    ///
    /// ## Errors
    ///
    /// Each pipeline stage maps to a specific [`OrchestratorError`] variant.
    /// On failure, earlier stages' side effects may persist (e.g., execution
    /// output is discarded, but receipt may already be stored).
    pub async fn process_workload(
        &mut self,
        assignment: WorkloadAssignment,
        proof_data: &[u8],
        timestamp: u64,
    ) -> Result<ClaimRewardResponse, OrchestratorError> {
        // ── Step 1: Execute workload ───────────────────────────────────
        let exec_output: ExecutionOutput = WorkloadExecutor::execute_workload(&assignment)
            .map_err(OrchestratorError::ExecutionFailed)?;

        // ── Step 2: Build usage proof ──────────────────────────────────
        let usage_proof = self.proof_builder.build_usage_proof(
            assignment.workload_id,
            &exec_output.resource_usage,
            proof_data,
        ).map_err(OrchestratorError::ProofBuildFailed)?;

        // ── Step 3: Submit to coordinator ──────────────────────────────
        let receipt_request = ReceiptRequest {
            usage_proof,
            execution_commitment: exec_output.commitment,
            workload_type: assignment.workload_type,
        };

        let coordinator_response = self.coordinator.submit(&receipt_request).await
            .map_err(OrchestratorError::CoordinatorFailed)?;

        // ── Step 4: Handle coordinator response ────────────────────────
        self.handle_coordinator_response(coordinator_response, timestamp).await
    }

    /// Processes a storage workload through the reward pipeline.
    ///
    /// Unlike [`process_workload`], this method **skips execution** because
    /// storage workloads have no runtime component. Resource usage is
    /// constructed directly from the caller-provided metrics.
    ///
    /// ## Arguments
    ///
    /// - `workload_id`: Identifier for this storage workload.
    /// - `chunk_count`: Number of storage chunks stored/served.
    /// - `bandwidth_bytes`: Network bandwidth consumed.
    /// - `proof_data`: Opaque data included in the usage proof.
    /// - `timestamp`: Caller-provided Unix timestamp.
    pub async fn process_storage_workload(
        &mut self,
        workload_id: WorkloadId,
        chunk_count: u64,
        bandwidth_bytes: u64,
        proof_data: &[u8],
        timestamp: u64,
    ) -> Result<ClaimRewardResponse, OrchestratorError> {
        // ── Step 1: Skip execution — build resource usage directly ─────
        let resource_usage = UnifiedResourceUsage {
            cpu_cycles_estimate: 0,
            peak_memory_bytes: 0,
            execution_time_ms: 0,
            chunk_count,
            bandwidth_bytes,
        };

        // ── Step 2: Build usage proof ──────────────────────────────────
        let usage_proof = self.proof_builder.build_usage_proof(
            workload_id,
            &resource_usage,
            proof_data,
        ).map_err(OrchestratorError::ProofBuildFailed)?;

        // ── Step 3: Submit to coordinator ──────────────────────────────
        let receipt_request = ReceiptRequest {
            usage_proof,
            execution_commitment: None, // Storage workloads have no execution commitment.
            workload_type: WorkloadType::Storage,
        };

        let coordinator_response = self.coordinator.submit(&receipt_request).await
            .map_err(OrchestratorError::CoordinatorFailed)?;

        // ── Step 4: Handle coordinator response ────────────────────────
        self.handle_coordinator_response(coordinator_response, timestamp).await
    }

    /// Common handler for coordinator response: store receipt, submit to
    /// chain, update status.
    ///
    /// Extracted to avoid duplication between `process_workload` and
    /// `process_storage_workload`.
    async fn handle_coordinator_response(
        &mut self,
        coordinator_response: ReceiptResponse,
        timestamp: u64,
    ) -> Result<ClaimRewardResponse, OrchestratorError> {
        match coordinator_response {
            // ── Signed: store → chain → status update ──────────────────
            ReceiptResponse::Signed(receipt) => {
                // Step 4a: Store receipt.
                self.receipt_handler
                    .handle_receipt(receipt.clone(), timestamp)
                    .map_err(OrchestratorError::ReceiptHandlingFailed)?;

                let workload_id_bytes = receipt.workload_id.clone();

                // Step 5: Submit to chain.
                let chain_response = self.chain_submitter
                    .submit_claim(&receipt, self.submitter_address)
                    .await
                    .map_err(OrchestratorError::ChainFailed)?;

                // Step 6: Update receipt status based on chain response.
                let new_status = match &chain_response {
                    ClaimRewardResponse::Success { reward_amount, .. } => {
                        ReceiptStatus::Confirmed {
                            reward_amount: *reward_amount,
                        }
                    }
                    ClaimRewardResponse::Rejected { reason } => {
                        ReceiptStatus::Rejected {
                            reason: reason.clone(),
                        }
                    }
                    ClaimRewardResponse::ChallengePeriod { expires_at, .. } => {
                        ReceiptStatus::InChallengePeriod {
                            expires_at: *expires_at,
                        }
                    }
                };

                self.receipt_handler
                    .update_status(&workload_id_bytes, new_status)
                    .map_err(|e| {
                        OrchestratorError::ReceiptHandlingFailed(
                            ReceiptHandlerError::ValidationFailed(e),
                        )
                    })?;

                // Step 7: Return chain response.
                Ok(chain_response)
            }

            // ── Rejected: error immediately ────────────────────────────
            ReceiptResponse::Rejected { reason } => {
                Err(OrchestratorError::ReceiptRejected(reason))
            }

            // ── Pending: no chain submission ───────────────────────────
            ReceiptResponse::Pending { session_id } => {
                Ok(ClaimRewardResponse::ChallengePeriod {
                    expires_at: 0,
                    challenge_id: session_id,
                })
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use async_trait::async_trait;
    use dsdn_common::receipt_v1_convert::{AggregateSignatureProto, ReceiptV1Proto};

    use crate::chain_submitter::{ChainTransport, MockChainTransport};
    use crate::coordinator_client::{
        CoordinatorTransport, MockCoordinatorTransport, SubmitError as CoordSubmitError,
    };
    use crate::identity_manager::NodeIdentityManager;

    // ── Helpers ──────────────────────────────────────────────────────────

    const TEST_SEED: [u8; 32] = [0xAA; 32];

    fn make_identity() -> Arc<NodeIdentityManager> {
        Arc::new(
            NodeIdentityManager::from_keypair(TEST_SEED)
                .unwrap_or_else(|_| panic!("test setup: from_keypair failed")),
        )
    }

    fn make_signed_receipt() -> ReceiptV1Proto {
        ReceiptV1Proto {
            workload_id: vec![0x42; 32],
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

    fn make_storage_assignment() -> WorkloadAssignment {
        WorkloadAssignment {
            workload_id: WorkloadId::new([0x42; 32]),
            workload_type: WorkloadType::Storage,
            module_bytes: Vec::new(),
            input_bytes: Vec::new(),
            vm_command: Vec::new(),
            resource_limits: crate::workload_executor::ResourceLimits {
                timeout_ms: 5000,
                max_memory_bytes: 64 * 1024 * 1024,
            },
        }
    }

    fn build_orchestrator(
        coord_mock: MockCoordinatorTransport,
        chain_mock: MockChainTransport,
    ) -> RewardOrchestrator {
        let identity = make_identity();
        RewardOrchestrator::new(
            WorkloadExecutor,
            UsageProofBuilder::new(identity),
            CoordinatorSubmitter::new(Box::new(coord_mock)),
            ReceiptHandler::new(),
            ChainSubmitter::new(Box::new(chain_mock)),
            [0x11; 20],
        )
    }

    // ── Test 1: Full pipeline success (storage path) ────────────────────

    /// Tests the complete pipeline: execute → proof → coordinator → receipt → chain.
    /// Uses Storage workload which skips runtime execution.
    #[tokio::test]
    async fn full_pipeline_success() {
        let coord = MockCoordinatorTransport::new();
        coord.push_response(ReceiptResponse::Signed(make_signed_receipt()));

        let chain = MockChainTransport::new();
        chain.push_response(ClaimRewardResponse::Success {
            reward_amount: 1000,
            tx_hash: [0xAB; 32],
        });

        let mut orch = build_orchestrator(coord, chain);

        let result = orch
            .process_workload(make_storage_assignment(), b"proof", 5000)
            .await;

        assert!(result.is_ok(), "full pipeline should succeed: {:?}", result.err());
        match result.unwrap_or_else(|e| panic!("unexpected: {}", e)) {
            ClaimRewardResponse::Success { reward_amount, tx_hash } => {
                assert_eq!(reward_amount, 1000);
                assert_eq!(tx_hash, [0xAB; 32]);
            }
            other => panic!("expected Success, got {:?}", other),
        }

        // Receipt should be stored and confirmed.
        assert_eq!(orch.receipt_handler.receipt_count(), 1);
        let stored = orch.receipt_handler.get_receipt(&[0x42; 32]);
        assert!(stored.is_some());
        assert_eq!(
            stored.map(|sr| &sr.status),
            Some(&ReceiptStatus::Confirmed { reward_amount: 1000 })
        );
    }

    // ── Test 2: Coordinator rejected ────────────────────────────────────

    #[tokio::test]
    async fn coordinator_rejected() {
        let coord = MockCoordinatorTransport::new();
        coord.push_response(ReceiptResponse::Rejected {
            reason: "invalid signature".to_string(),
        });

        let chain = MockChainTransport::new();
        let mut orch = build_orchestrator(coord, chain);

        let result = orch
            .process_workload(make_storage_assignment(), b"proof", 5000)
            .await;

        assert!(result.is_err());
        match result {
            Err(OrchestratorError::ReceiptRejected(reason)) => {
                assert_eq!(reason, "invalid signature");
            }
            other => panic!("expected ReceiptRejected, got {:?}", other),
        }

        // No receipt should be stored.
        assert_eq!(orch.receipt_handler.receipt_count(), 0);
    }

    // ── Test 3: Coordinator pending ─────────────────────────────────────

    #[tokio::test]
    async fn coordinator_pending() {
        let coord = MockCoordinatorTransport::new();
        coord.push_response(ReceiptResponse::Pending {
            session_id: vec![0x99; 16],
        });

        let chain = MockChainTransport::new();
        let mut orch = build_orchestrator(coord, chain);

        let result = orch
            .process_workload(make_storage_assignment(), b"proof", 5000)
            .await;

        assert!(result.is_ok());
        match result.unwrap_or_else(|e| panic!("unexpected: {}", e)) {
            ClaimRewardResponse::ChallengePeriod { expires_at, challenge_id } => {
                assert_eq!(expires_at, 0);
                assert_eq!(challenge_id, vec![0x99; 16]);
            }
            other => panic!("expected ChallengePeriod (pending), got {:?}", other),
        }

        // No receipt stored (no signed receipt received).
        assert_eq!(orch.receipt_handler.receipt_count(), 0);
    }

    // ── Test 4: Chain rejected ──────────────────────────────────────────

    #[tokio::test]
    async fn chain_rejected() {
        let coord = MockCoordinatorTransport::new();
        coord.push_response(ReceiptResponse::Signed(make_signed_receipt()));

        let chain = MockChainTransport::new();
        chain.push_response(ClaimRewardResponse::Rejected {
            reason: "duplicate claim".to_string(),
        });

        let mut orch = build_orchestrator(coord, chain);

        let result = orch
            .process_workload(make_storage_assignment(), b"proof", 5000)
            .await;

        assert!(result.is_ok());
        match result.unwrap_or_else(|e| panic!("unexpected: {}", e)) {
            ClaimRewardResponse::Rejected { reason } => {
                assert_eq!(reason, "duplicate claim");
            }
            other => panic!("expected Rejected, got {:?}", other),
        }

        // Receipt stored with Rejected status.
        let stored = orch.receipt_handler.get_receipt(&[0x42; 32]);
        assert!(stored.is_some());
        assert!(matches!(
            stored.map(|sr| &sr.status),
            Some(ReceiptStatus::Rejected { .. })
        ));
    }

    // ── Test 5: Chain challenge period ───────────────────────────────────

    #[tokio::test]
    async fn chain_challenge_period() {
        let coord = MockCoordinatorTransport::new();
        coord.push_response(ReceiptResponse::Signed(make_signed_receipt()));

        let chain = MockChainTransport::new();
        chain.push_response(ClaimRewardResponse::ChallengePeriod {
            expires_at: 1_700_100_000,
            challenge_id: vec![0x77; 8],
        });

        let mut orch = build_orchestrator(coord, chain);

        let result = orch
            .process_workload(make_storage_assignment(), b"proof", 5000)
            .await;

        assert!(result.is_ok());
        match result.unwrap_or_else(|e| panic!("unexpected: {}", e)) {
            ClaimRewardResponse::ChallengePeriod { expires_at, .. } => {
                assert_eq!(expires_at, 1_700_100_000);
            }
            other => panic!("expected ChallengePeriod, got {:?}", other),
        }

        // Receipt stored with InChallengePeriod status.
        let stored = orch.receipt_handler.get_receipt(&[0x42; 32]);
        assert!(stored.is_some());
        assert!(matches!(
            stored.map(|sr| &sr.status),
            Some(ReceiptStatus::InChallengePeriod { expires_at: 1_700_100_000 })
        ));
    }

    // ── Test 6: Execution failure ───────────────────────────────────────

    /// ComputeWasm with empty module_bytes → ExecutionFailed.
    #[tokio::test]
    async fn execution_failure() {
        let coord = MockCoordinatorTransport::new();
        let chain = MockChainTransport::new();
        let mut orch = build_orchestrator(coord, chain);

        let bad_assignment = WorkloadAssignment {
            workload_id: WorkloadId::new([0x01; 32]),
            workload_type: WorkloadType::ComputeWasm,
            module_bytes: Vec::new(), // Empty → InvalidWorkloadType
            input_bytes: Vec::new(),
            vm_command: Vec::new(),
            resource_limits: crate::workload_executor::ResourceLimits {
                timeout_ms: 5000,
                max_memory_bytes: 64 * 1024 * 1024,
            },
        };

        let result = orch.process_workload(bad_assignment, b"proof", 5000).await;

        assert!(result.is_err());
        assert!(matches!(result, Err(OrchestratorError::ExecutionFailed(_))));
    }

    // ── Test 7: Chain transport error ────────────────────────────────────

    #[tokio::test]
    async fn chain_transport_error() {
        let coord = MockCoordinatorTransport::new();
        coord.push_response(ReceiptResponse::Signed(make_signed_receipt()));

        // Empty chain mock → NetworkError
        let chain = MockChainTransport::new();

        let mut orch = build_orchestrator(coord, chain);

        let result = orch
            .process_workload(make_storage_assignment(), b"proof", 5000)
            .await;

        assert!(result.is_err());
        assert!(matches!(result, Err(OrchestratorError::ChainFailed(_))));

        // Receipt stored but status should still be Validated
        // (chain submission failed, no status update).
        let stored = orch.receipt_handler.get_receipt(&[0x42; 32]);
        assert!(stored.is_some());
        assert_eq!(
            stored.map(|sr| &sr.status),
            Some(&ReceiptStatus::Validated)
        );
    }

    // ── Test 8: Storage workload pipeline ───────────────────────────────

    #[tokio::test]
    async fn storage_workload_pipeline() {
        let coord = MockCoordinatorTransport::new();
        coord.push_response(ReceiptResponse::Signed(make_signed_receipt()));

        let chain = MockChainTransport::new();
        chain.push_response(ClaimRewardResponse::Success {
            reward_amount: 500,
            tx_hash: [0xCD; 32],
        });

        let mut orch = build_orchestrator(coord, chain);

        let result = orch
            .process_storage_workload(
                WorkloadId::new([0x42; 32]),
                10,   // chunk_count
                4096, // bandwidth_bytes
                b"storage-proof",
                6000,
            )
            .await;

        assert!(result.is_ok(), "storage pipeline should succeed: {:?}", result.err());
        match result.unwrap_or_else(|e| panic!("unexpected: {}", e)) {
            ClaimRewardResponse::Success { reward_amount, .. } => {
                assert_eq!(reward_amount, 500);
            }
            other => panic!("expected Success, got {:?}", other),
        }

        assert_eq!(orch.receipt_handler.receipt_count(), 1);
    }

    // ── Test 9: OrchestratorError Display ───────────────────────────────

    #[test]
    fn error_display() {
        let e = OrchestratorError::ReceiptRejected("bad proof".into());
        assert!(e.to_string().contains("bad proof"));

        let e2 = OrchestratorError::ChainFailed(ChainSubmitError::Timeout);
        assert!(e2.to_string().contains("timed out"));

        let e3 = OrchestratorError::CoordinatorFailed(CoordSubmitError::Timeout);
        assert!(e3.to_string().contains("timed out"));
    }
}