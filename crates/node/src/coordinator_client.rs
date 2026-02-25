//! # CoordinatorSubmitter — Receipt Submission Client (14C.B.15)
//!
//! Submits resource usage proofs and execution commitments to the coordinator
//! for receipt signing, using a trait-abstracted transport layer.
//!
//! ## Architecture
//!
//! ```text
//! UsageProof + ExecutionCommitment + WorkloadType
//!      │
//!      ▼
//! ReceiptRequest
//!      │
//!      ▼
//! CoordinatorSubmitter::submit()
//!      │
//!      ▼
//! dyn CoordinatorTransport::submit_receipt_request()
//!      │
//!      ▼
//! ReceiptResponse { Signed | Rejected | Pending }
//! ```
//!
//! ## Transport Abstraction
//!
//! [`CoordinatorTransport`] is an async trait that decouples the submission
//! logic from any specific network implementation. This enables:
//!
//! - **Unit testing** via [`MockCoordinatorTransport`] (no network required).
//! - **HTTP transport** (V2: production implementation).
//! - **gRPC transport** (V2: alternative production implementation).
//!
//! ## Error Propagation
//!
//! [`CoordinatorSubmitter::submit`] is a thin delegation layer. Transport
//! errors are propagated without transformation. No errors are swallowed.
//!
//! ## Safety
//!
//! - No `panic!`, `unwrap()`, `expect()` in production code.
//! - Mutex lock errors are handled explicitly.
//! - All types are `Send + Sync`.

use std::fmt;
use std::sync::Mutex;

use async_trait::async_trait;
use dsdn_common::ExecutionCommitment;
use dsdn_common::receipt_v1_convert::ReceiptV1Proto;

use crate::usage_proof_builder::UsageProof;
use crate::workload_executor::WorkloadType;

// ════════════════════════════════════════════════════════════════════════════════
// REQUEST
// ════════════════════════════════════════════════════════════════════════════════

/// Payload submitted to the coordinator for receipt generation.
///
/// Bundles the node's self-reported usage proof with the optional
/// execution commitment and workload classification.
///
/// - `usage_proof`: Signed resource usage claim (from [`UsageProofBuilder`]).
/// - `execution_commitment`: Present for `ComputeWasm`/`ComputeVm`, absent for `Storage`.
/// - `workload_type`: Determines receipt type on the coordinator side.
#[derive(Debug, Clone)]
pub struct ReceiptRequest {
    /// Signed usage proof from the node.
    pub usage_proof: UsageProof,
    /// Execution commitment (present for compute workloads, `None` for storage).
    pub execution_commitment: Option<ExecutionCommitment>,
    /// Workload classification.
    pub workload_type: WorkloadType,
}

// ════════════════════════════════════════════════════════════════════════════════
// RESPONSE
// ════════════════════════════════════════════════════════════════════════════════

/// Coordinator's response to a receipt request.
///
/// ## Variants
///
/// - `Signed`: Coordinator accepted the proof and produced a signed receipt.
/// - `Rejected`: Coordinator rejected the proof with a reason.
/// - `Pending`: Multi-coordinator consensus is in progress; the node should
///   poll using the provided `session_id`.
#[derive(Debug, Clone)]
pub enum ReceiptResponse {
    /// Coordinator accepted and signed the receipt.
    Signed(ReceiptV1Proto),
    /// Coordinator rejected the submission.
    Rejected {
        /// Human-readable rejection reason.
        reason: String,
    },
    /// Receipt is pending multi-coordinator consensus.
    Pending {
        /// Opaque session identifier for polling.
        session_id: Vec<u8>,
    },
}

// ════════════════════════════════════════════════════════════════════════════════
// ERROR
// ════════════════════════════════════════════════════════════════════════════════

/// Errors from receipt submission.
///
/// These represent transport-level failures, not coordinator rejections
/// (which are expressed as [`ReceiptResponse::Rejected`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitError {
    /// Transport-level network failure (connection refused, DNS, etc.).
    NetworkError(String),
    /// Response could not be parsed or was structurally invalid.
    InvalidResponse(String),
    /// Request timed out before a response was received.
    Timeout,
}

impl fmt::Display for SubmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NetworkError(msg) => write!(f, "network error: {}", msg),
            Self::InvalidResponse(msg) => write!(f, "invalid response: {}", msg),
            Self::Timeout => write!(f, "request timed out"),
        }
    }
}

impl std::error::Error for SubmitError {}

// ════════════════════════════════════════════════════════════════════════════════
// TRANSPORT TRAIT
// ════════════════════════════════════════════════════════════════════════════════

/// Async transport abstraction for coordinator communication.
///
/// Implementations provide the actual network mechanism (HTTP, gRPC, mock).
/// The trait is object-safe and requires `Send + Sync` for use across
/// async task boundaries.
///
/// ## Contract
///
/// - Implementations MUST NOT modify the request payload.
/// - Implementations MUST return `SubmitError::Timeout` for timeouts
///   (not `NetworkError`).
/// - Implementations MUST NOT panic.
#[async_trait]
pub trait CoordinatorTransport: Send + Sync {
    /// Submits a receipt request to the coordinator.
    ///
    /// ## Arguments
    ///
    /// - `request`: The receipt request to submit (borrowed, not consumed).
    ///
    /// ## Returns
    ///
    /// - `Ok(ReceiptResponse)` on successful communication (even if rejected).
    /// - `Err(SubmitError)` on transport-level failure.
    async fn submit_receipt_request(
        &self,
        request: &ReceiptRequest,
    ) -> Result<ReceiptResponse, SubmitError>;
}

// ════════════════════════════════════════════════════════════════════════════════
// SUBMITTER
// ════════════════════════════════════════════════════════════════════════════════

/// Client that submits receipt requests to the coordinator via a
/// pluggable [`CoordinatorTransport`].
///
/// ## Design
///
/// `CoordinatorSubmitter` is a thin delegation layer. It does not
/// transform the request or response — all logic lives in the transport
/// implementation and the coordinator.
///
/// ## Usage
///
/// ```rust,ignore
/// let transport = Box::new(HttpCoordinatorTransport::new(url));
/// let submitter = CoordinatorSubmitter::new(transport);
///
/// let response = submitter.submit(&request).await?;
/// match response {
///     ReceiptResponse::Signed(receipt) => { /* store receipt */ }
///     ReceiptResponse::Rejected { reason } => { /* log rejection */ }
///     ReceiptResponse::Pending { session_id } => { /* poll later */ }
/// }
/// ```
pub struct CoordinatorSubmitter {
    /// Pluggable transport implementation.
    transport: Box<dyn CoordinatorTransport>,
}

impl CoordinatorSubmitter {
    /// Creates a new submitter with the given transport.
    ///
    /// The transport is consumed (moved into the submitter) and owned
    /// for the lifetime of the submitter.
    #[must_use]
    pub fn new(transport: Box<dyn CoordinatorTransport>) -> Self {
        Self { transport }
    }

    /// Submits a receipt request to the coordinator.
    ///
    /// Delegates directly to the transport. No transformation is applied
    /// to the request or response. Errors are propagated without modification.
    ///
    /// ## Arguments
    ///
    /// - `request`: The receipt request to submit (borrowed).
    ///
    /// ## Returns
    ///
    /// - `Ok(ReceiptResponse)` on successful communication.
    /// - `Err(SubmitError)` on transport failure.
    pub async fn submit(
        &self,
        request: &ReceiptRequest,
    ) -> Result<ReceiptResponse, SubmitError> {
        self.transport.submit_receipt_request(request).await
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// MOCK TRANSPORT
// ════════════════════════════════════════════════════════════════════════════════

/// Mock transport for testing without network access.
///
/// Responses are pre-loaded and returned in FIFO order (first pushed,
/// first returned). When no responses remain, returns
/// `SubmitError::InvalidResponse("No mock response")`.
///
/// ## Thread Safety
///
/// Uses `std::sync::Mutex` for interior mutability. Lock errors
/// (poisoned mutex) are mapped to `SubmitError::InvalidResponse`
/// without panicking.
///
/// ## Usage
///
/// ```rust,ignore
/// let mock = MockCoordinatorTransport::new();
/// mock.push_response(ReceiptResponse::Rejected { reason: "test".into() });
///
/// let submitter = CoordinatorSubmitter::new(Box::new(mock));
/// let result = submitter.submit(&request).await;
/// // result == Ok(ReceiptResponse::Rejected { reason: "test" })
/// ```
pub struct MockCoordinatorTransport {
    /// Pre-loaded responses, consumed FIFO (index 0 is returned first).
    responses: Mutex<Vec<ReceiptResponse>>,
}

impl MockCoordinatorTransport {
    /// Creates a new mock transport with no pre-loaded responses.
    #[must_use]
    pub fn new() -> Self {
        Self {
            responses: Mutex::new(Vec::new()),
        }
    }

    /// Pushes a response to the end of the queue (FIFO order).
    ///
    /// Responses are returned in the order they were pushed.
    /// If the mutex is poisoned, the response is silently dropped.
    pub fn push_response(&self, response: ReceiptResponse) {
        if let Ok(mut queue) = self.responses.lock() {
            queue.push(response);
        }
    }
}

impl Default for MockCoordinatorTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CoordinatorTransport for MockCoordinatorTransport {
    async fn submit_receipt_request(
        &self,
        _request: &ReceiptRequest,
    ) -> Result<ReceiptResponse, SubmitError> {
        let mut queue = self.responses.lock().map_err(|e| {
            SubmitError::InvalidResponse(format!("mock mutex poisoned: {}", e))
        })?;

        if queue.is_empty() {
            return Err(SubmitError::InvalidResponse(
                "No mock response".to_string(),
            ));
        }

        // FIFO: remove from front.
        Ok(queue.remove(0))
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// COMPILE-TIME ASSERTIONS
// ════════════════════════════════════════════════════════════════════════════════

/// Compile-time assertion: `CoordinatorSubmitter` is `Send`.
const _: () = {
    fn assert_send<T: Send>() {}
    fn check() {
        assert_send::<CoordinatorSubmitter>();
    }
    let _ = check;
};

/// Compile-time assertion: `MockCoordinatorTransport` is `Send + Sync`.
const _: () = {
    fn assert_send_sync<T: Send + Sync>() {}
    fn check() {
        assert_send_sync::<MockCoordinatorTransport>();
    }
    let _ = check;
};

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use dsdn_common::coordinator::WorkloadId;

    // ── Helpers ──────────────────────────────────────────────────────────

    fn make_request() -> ReceiptRequest {
        ReceiptRequest {
            usage_proof: UsageProof {
                workload_id: WorkloadId::new([0x42; 32]),
                node_id: [0xAA; 32],
                cpu_cycles: 1_000_000,
                ram_bytes: 65_536,
                chunk_count: 3,
                bandwidth_bytes: 4096,
                proof_data: vec![1, 2, 3],
                node_signature: vec![0xBB; 64],
            },
            execution_commitment: None,
            workload_type: WorkloadType::ComputeWasm,
        }
    }

    fn make_signed_receipt() -> ReceiptV1Proto {
        ReceiptV1Proto {
            workload_id: vec![0x42; 32],
            node_id: vec![0xAA; 32],
            receipt_type: 1,
            usage_proof_hash: vec![0xCC; 32],
            execution_commitment: None,
            coordinator_threshold_signature:
                dsdn_common::receipt_v1_convert::AggregateSignatureProto {
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

    // ── Test 1: submit returns Signed ───────────────────────────────────

    /// Verifies that a Signed response from the transport is passed
    /// through to the caller without modification.
    #[tokio::test]
    async fn submit_returns_signed() {
        let mock = MockCoordinatorTransport::new();
        let receipt = make_signed_receipt();
        mock.push_response(ReceiptResponse::Signed(receipt.clone()));

        let submitter = CoordinatorSubmitter::new(Box::new(mock));
        let result = submitter.submit(&make_request()).await;

        assert!(result.is_ok(), "submit should succeed");
        match result.unwrap_or_else(|e| panic!("unexpected error: {}", e)) {
            ReceiptResponse::Signed(r) => {
                assert_eq!(r.workload_id, receipt.workload_id);
                assert_eq!(r.reward_base, receipt.reward_base);
            }
            other => panic!("expected Signed, got {:?}", other),
        }
    }

    // ── Test 2: submit returns Rejected ─────────────────────────────────

    /// Verifies that a Rejected response is faithfully propagated.
    #[tokio::test]
    async fn submit_returns_rejected() {
        let mock = MockCoordinatorTransport::new();
        mock.push_response(ReceiptResponse::Rejected {
            reason: "invalid signature".to_string(),
        });

        let submitter = CoordinatorSubmitter::new(Box::new(mock));
        let result = submitter.submit(&make_request()).await;

        assert!(result.is_ok());
        match result.unwrap_or_else(|e| panic!("unexpected error: {}", e)) {
            ReceiptResponse::Rejected { reason } => {
                assert_eq!(reason, "invalid signature");
            }
            other => panic!("expected Rejected, got {:?}", other),
        }
    }

    // ── Test 3: submit returns Pending ──────────────────────────────────

    /// Verifies that a Pending response with session_id is propagated.
    #[tokio::test]
    async fn submit_returns_pending() {
        let mock = MockCoordinatorTransport::new();
        mock.push_response(ReceiptResponse::Pending {
            session_id: vec![0x99; 16],
        });

        let submitter = CoordinatorSubmitter::new(Box::new(mock));
        let result = submitter.submit(&make_request()).await;

        assert!(result.is_ok());
        match result.unwrap_or_else(|e| panic!("unexpected error: {}", e)) {
            ReceiptResponse::Pending { session_id } => {
                assert_eq!(session_id, vec![0x99; 16]);
            }
            other => panic!("expected Pending, got {:?}", other),
        }
    }

    // ── Test 4: submit propagates network error ─────────────────────────

    /// Verifies that transport errors are propagated without modification.
    /// Uses an empty mock (no responses) to trigger InvalidResponse.
    #[tokio::test]
    async fn submit_network_error() {
        let mock = MockCoordinatorTransport::new();
        // No responses pushed → InvalidResponse("No mock response")

        let submitter = CoordinatorSubmitter::new(Box::new(mock));
        let result = submitter.submit(&make_request()).await;

        assert!(result.is_err());
        match result {
            Err(SubmitError::InvalidResponse(msg)) => {
                assert!(msg.contains("No mock response"), "msg: {}", msg);
            }
            other => panic!("expected InvalidResponse, got {:?}", other),
        }
    }

    // ── Test 5: FIFO ordering ───────────────────────────────────────────

    /// Verifies that responses are returned in FIFO order.
    #[tokio::test]
    async fn mock_fifo_ordering() {
        let mock = MockCoordinatorTransport::new();
        mock.push_response(ReceiptResponse::Rejected {
            reason: "first".to_string(),
        });
        mock.push_response(ReceiptResponse::Pending {
            session_id: vec![0x02],
        });
        mock.push_response(ReceiptResponse::Signed(make_signed_receipt()));

        let submitter = CoordinatorSubmitter::new(Box::new(mock));
        let req = make_request();

        // First: Rejected
        let r1 = submitter.submit(&req).await;
        assert!(matches!(
            r1.as_ref().unwrap_or_else(|e| panic!("{}", e)),
            ReceiptResponse::Rejected { .. }
        ));

        // Second: Pending
        let r2 = submitter.submit(&req).await;
        assert!(matches!(
            r2.as_ref().unwrap_or_else(|e| panic!("{}", e)),
            ReceiptResponse::Pending { .. }
        ));

        // Third: Signed
        let r3 = submitter.submit(&req).await;
        assert!(matches!(
            r3.as_ref().unwrap_or_else(|e| panic!("{}", e)),
            ReceiptResponse::Signed(_)
        ));

        // Fourth: empty → error
        let r4 = submitter.submit(&req).await;
        assert!(r4.is_err());
    }

    // ── Test 6: Custom transport implementation ─────────────────────────

    /// Verifies that a custom transport implementation works correctly,
    /// proving the trait is object-safe and usable.
    #[tokio::test]
    async fn custom_transport_works() {
        struct AlwaysTimeout;

        #[async_trait]
        impl CoordinatorTransport for AlwaysTimeout {
            async fn submit_receipt_request(
                &self,
                _request: &ReceiptRequest,
            ) -> Result<ReceiptResponse, SubmitError> {
                Err(SubmitError::Timeout)
            }
        }

        let submitter = CoordinatorSubmitter::new(Box::new(AlwaysTimeout));
        let result = submitter.submit(&make_request()).await;

        assert!(result.is_err());
        assert!(matches!(result, Err(SubmitError::Timeout)));
    }

    // ── Test 7: SubmitError Display ─────────────────────────────────────

    /// Verifies that all error variants produce meaningful Display output.
    #[test]
    fn submit_error_display() {
        let e1 = SubmitError::NetworkError("connection refused".to_string());
        assert!(e1.to_string().contains("connection refused"));

        let e2 = SubmitError::InvalidResponse("bad json".to_string());
        assert!(e2.to_string().contains("bad json"));

        let e3 = SubmitError::Timeout;
        assert!(e3.to_string().contains("timed out"));
    }
}