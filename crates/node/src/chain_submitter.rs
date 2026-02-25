//! # ChainSubmitter — On-Chain Reward Claim Client (14C.B.17)
//!
//! Submits `ClaimRewardRequest` to the blockchain for reward settlement,
//! using a trait-abstracted transport layer.
//!
//! ## Architecture
//!
//! ```text
//! ReceiptV1Proto + submitter_address
//!      │
//!      ▼
//! ChainSubmitter::submit_claim()
//!      │
//!      ├─ Construct ClaimRewardRequest
//!      └─ Delegate to dyn ChainTransport
//!      │
//!      ▼
//! ClaimRewardResponse { Success | Rejected | ChallengePeriod }
//! ```
//!
//! ## Transport Abstraction
//!
//! [`ChainTransport`] is an async trait that decouples submission logic
//! from any specific chain client implementation. This enables:
//!
//! - **Unit testing** via [`MockChainTransport`] (no network).
//! - **JSON-RPC transport** (V2: production chain client).
//! - **WebSocket transport** (V2: real-time chain interaction).
//!
//! ## No Implicit Retry
//!
//! `ChainSubmitter` performs a single submission attempt. It does NOT:
//!
//! - Retry on failure.
//! - Sleep or backoff.
//! - Transform the response.
//!
//! Retry logic belongs to the orchestration layer.
//!
//! ## Safety
//!
//! - No `panic!`, `unwrap()`, `expect()`.
//! - Mutex lock errors handled explicitly.
//! - All types are `Send + Sync`.

use std::fmt;
use std::sync::Mutex;

use async_trait::async_trait;
use dsdn_common::receipt_v1_convert::ReceiptV1Proto;

// ════════════════════════════════════════════════════════════════════════════════
// REQUEST
// ════════════════════════════════════════════════════════════════════════════════

/// Payload submitted to the chain for reward claiming.
///
/// Bundles a coordinator-signed receipt with the submitter's address.
/// The chain verifies the receipt's signatures and, if valid, initiates
/// the reward distribution process.
#[derive(Debug, Clone)]
pub struct ClaimRewardRequest {
    /// Coordinator-signed receipt proving resource usage.
    pub receipt: ReceiptV1Proto,
    /// 20-byte address of the submitter claiming the reward.
    pub submitter_address: [u8; 20],
}

// ════════════════════════════════════════════════════════════════════════════════
// RESPONSE
// ════════════════════════════════════════════════════════════════════════════════

/// Chain's response to a reward claim submission.
///
/// ## Variants
///
/// - `Success`: Claim accepted, reward distributed.
/// - `Rejected`: Claim rejected by chain validation.
/// - `ChallengePeriod`: Claim entered the fraud-proof challenge window.
#[derive(Debug, Clone)]
pub enum ClaimRewardResponse {
    /// Claim accepted. Reward distributed to the submitter.
    Success {
        /// Reward amount in base token units.
        reward_amount: u128,
        /// Transaction hash on-chain (32 bytes).
        tx_hash: [u8; 32],
    },
    /// Claim rejected by chain validation.
    Rejected {
        /// Human-readable rejection reason.
        reason: String,
    },
    /// Claim is in the on-chain challenge period.
    ChallengePeriod {
        /// Unix timestamp when the challenge period expires.
        expires_at: u64,
        /// Opaque challenge identifier for tracking.
        challenge_id: Vec<u8>,
    },
}

// ════════════════════════════════════════════════════════════════════════════════
// ERROR
// ════════════════════════════════════════════════════════════════════════════════

/// Errors from chain submission.
///
/// These represent transport-level or chain-level failures, not business
/// rejections (which are expressed as [`ClaimRewardResponse::Rejected`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainSubmitError {
    /// Transport-level network failure.
    NetworkError(String),
    /// Submitter account has insufficient funds for gas/fees.
    InsufficientFunds,
    /// The receipt is structurally invalid for chain submission.
    InvalidReceipt(String),
    /// Request timed out before chain responded.
    Timeout,
}

impl fmt::Display for ChainSubmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NetworkError(msg) => write!(f, "chain network error: {}", msg),
            Self::InsufficientFunds => write!(f, "insufficient funds for chain submission"),
            Self::InvalidReceipt(msg) => write!(f, "invalid receipt: {}", msg),
            Self::Timeout => write!(f, "chain submission timed out"),
        }
    }
}

impl std::error::Error for ChainSubmitError {}

// ════════════════════════════════════════════════════════════════════════════════
// TRANSPORT TRAIT
// ════════════════════════════════════════════════════════════════════════════════

/// Async transport abstraction for chain interaction.
///
/// Implementations provide the actual chain client mechanism.
/// The trait is object-safe and requires `Send + Sync` for use
/// across async task boundaries.
///
/// ## Contract
///
/// - Implementations MUST NOT modify the request payload.
/// - Implementations MUST NOT retry internally.
/// - Implementations MUST NOT panic.
/// - Implementations MUST return `ChainSubmitError::Timeout` for timeouts.
#[async_trait]
pub trait ChainTransport: Send + Sync {
    /// Submits a reward claim to the chain.
    ///
    /// ## Arguments
    ///
    /// - `request`: The claim request (borrowed, not consumed).
    ///
    /// ## Returns
    ///
    /// - `Ok(ClaimRewardResponse)` on successful communication.
    /// - `Err(ChainSubmitError)` on transport or chain-level failure.
    async fn submit_claim_reward(
        &self,
        request: &ClaimRewardRequest,
    ) -> Result<ClaimRewardResponse, ChainSubmitError>;
}

// ════════════════════════════════════════════════════════════════════════════════
// SUBMITTER
// ════════════════════════════════════════════════════════════════════════════════

/// Client that submits reward claims to the chain via a pluggable
/// [`ChainTransport`].
///
/// ## Design
///
/// `ChainSubmitter` is a thin delegation layer. It constructs a
/// [`ClaimRewardRequest`] from the provided receipt and submitter address,
/// then delegates to the transport. No retry, no transformation.
///
/// ## Usage
///
/// ```rust,ignore
/// let transport = Box::new(JsonRpcChainTransport::new(rpc_url));
/// let submitter = ChainSubmitter::new(transport);
///
/// let response = submitter.submit_claim(&receipt, address).await?;
/// match response {
///     ClaimRewardResponse::Success { reward_amount, tx_hash } => { /* done */ }
///     ClaimRewardResponse::ChallengePeriod { expires_at, .. } => { /* wait */ }
///     ClaimRewardResponse::Rejected { reason } => { /* log */ }
/// }
/// ```
pub struct ChainSubmitter {
    /// Pluggable transport implementation.
    transport: Box<dyn ChainTransport>,
}

impl ChainSubmitter {
    /// Creates a new submitter with the given transport.
    #[must_use]
    pub fn new(transport: Box<dyn ChainTransport>) -> Self {
        Self { transport }
    }

    /// Submits a reward claim for the given receipt.
    ///
    /// Constructs a [`ClaimRewardRequest`] and delegates to the transport.
    /// The receipt is cloned into the request (transport requires owned data
    /// for serialization). No retry. Errors propagated without modification.
    ///
    /// ## Arguments
    ///
    /// - `receipt`: The coordinator-signed receipt to claim.
    /// - `submitter`: 20-byte submitter address.
    ///
    /// ## Returns
    ///
    /// - `Ok(ClaimRewardResponse)` on successful communication.
    /// - `Err(ChainSubmitError)` on failure.
    pub async fn submit_claim(
        &self,
        receipt: &ReceiptV1Proto,
        submitter: [u8; 20],
    ) -> Result<ClaimRewardResponse, ChainSubmitError> {
        let request = ClaimRewardRequest {
            receipt: receipt.clone(),
            submitter_address: submitter,
        };

        self.transport.submit_claim_reward(&request).await
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// MOCK TRANSPORT
// ════════════════════════════════════════════════════════════════════════════════

/// Mock transport for testing without chain access.
///
/// Responses are pre-loaded and returned in FIFO order (first pushed,
/// first returned). When no responses remain, returns
/// `ChainSubmitError::NetworkError("no mock response")`.
///
/// ## Thread Safety
///
/// Uses `std::sync::Mutex` for interior mutability. Lock errors
/// (poisoned mutex) are mapped to `ChainSubmitError::NetworkError`
/// without panicking.
pub struct MockChainTransport {
    /// Pre-loaded responses, consumed FIFO (index 0 returned first).
    responses: Mutex<Vec<ClaimRewardResponse>>,
}

impl MockChainTransport {
    /// Creates a new mock transport with no pre-loaded responses.
    #[must_use]
    pub fn new() -> Self {
        Self {
            responses: Mutex::new(Vec::new()),
        }
    }

    /// Pushes a response to the end of the queue (FIFO order).
    ///
    /// If the mutex is poisoned, the response is silently dropped.
    pub fn push_response(&self, response: ClaimRewardResponse) {
        if let Ok(mut queue) = self.responses.lock() {
            queue.push(response);
        }
    }
}

impl Default for MockChainTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ChainTransport for MockChainTransport {
    async fn submit_claim_reward(
        &self,
        _request: &ClaimRewardRequest,
    ) -> Result<ClaimRewardResponse, ChainSubmitError> {
        let mut queue = self.responses.lock().map_err(|e| {
            ChainSubmitError::NetworkError(format!("mutex poisoned: {}", e))
        })?;

        if queue.is_empty() {
            return Err(ChainSubmitError::NetworkError(
                "no mock response".to_string(),
            ));
        }

        // FIFO: remove from front.
        Ok(queue.remove(0))
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// COMPILE-TIME ASSERTIONS
// ════════════════════════════════════════════════════════════════════════════════

const _: () = {
    fn assert_send<T: Send>() {}
    fn check() { assert_send::<ChainSubmitter>(); }
    let _ = check;
};

const _: () = {
    fn assert_send_sync<T: Send + Sync>() {}
    fn check() { assert_send_sync::<MockChainTransport>(); }
    let _ = check;
};

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use dsdn_common::receipt_v1_convert::AggregateSignatureProto;

    // ── Helpers ──────────────────────────────────────────────────────────

    fn make_receipt() -> ReceiptV1Proto {
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

    fn test_address() -> [u8; 20] {
        [0x11; 20]
    }

    // ── Test 1: Success response ────────────────────────────────────────

    #[tokio::test]
    async fn submit_success_response() {
        let mock = MockChainTransport::new();
        mock.push_response(ClaimRewardResponse::Success {
            reward_amount: 1000,
            tx_hash: [0xAB; 32],
        });

        let submitter = ChainSubmitter::new(Box::new(mock));
        let result = submitter.submit_claim(&make_receipt(), test_address()).await;

        assert!(result.is_ok());
        match result.unwrap_or_else(|e| panic!("unexpected: {}", e)) {
            ClaimRewardResponse::Success { reward_amount, tx_hash } => {
                assert_eq!(reward_amount, 1000);
                assert_eq!(tx_hash, [0xAB; 32]);
            }
            other => panic!("expected Success, got {:?}", other),
        }
    }

    // ── Test 2: Rejected response ───────────────────────────────────────

    #[tokio::test]
    async fn submit_rejected_response() {
        let mock = MockChainTransport::new();
        mock.push_response(ClaimRewardResponse::Rejected {
            reason: "duplicate claim".to_string(),
        });

        let submitter = ChainSubmitter::new(Box::new(mock));
        let result = submitter.submit_claim(&make_receipt(), test_address()).await;

        assert!(result.is_ok());
        match result.unwrap_or_else(|e| panic!("unexpected: {}", e)) {
            ClaimRewardResponse::Rejected { reason } => {
                assert_eq!(reason, "duplicate claim");
            }
            other => panic!("expected Rejected, got {:?}", other),
        }
    }

    // ── Test 3: ChallengePeriod response ────────────────────────────────

    #[tokio::test]
    async fn submit_challenge_period_response() {
        let mock = MockChainTransport::new();
        mock.push_response(ClaimRewardResponse::ChallengePeriod {
            expires_at: 1_700_100_000,
            challenge_id: vec![0x99; 16],
        });

        let submitter = ChainSubmitter::new(Box::new(mock));
        let result = submitter.submit_claim(&make_receipt(), test_address()).await;

        assert!(result.is_ok());
        match result.unwrap_or_else(|e| panic!("unexpected: {}", e)) {
            ClaimRewardResponse::ChallengePeriod { expires_at, challenge_id } => {
                assert_eq!(expires_at, 1_700_100_000);
                assert_eq!(challenge_id, vec![0x99; 16]);
            }
            other => panic!("expected ChallengePeriod, got {:?}", other),
        }
    }

    // ── Test 4: Timeout error via custom transport ──────────────────────

    #[tokio::test]
    async fn submit_timeout_error() {
        struct AlwaysTimeout;

        #[async_trait]
        impl ChainTransport for AlwaysTimeout {
            async fn submit_claim_reward(
                &self,
                _request: &ClaimRewardRequest,
            ) -> Result<ClaimRewardResponse, ChainSubmitError> {
                Err(ChainSubmitError::Timeout)
            }
        }

        let submitter = ChainSubmitter::new(Box::new(AlwaysTimeout));
        let result = submitter.submit_claim(&make_receipt(), test_address()).await;

        assert!(result.is_err());
        assert!(matches!(result, Err(ChainSubmitError::Timeout)));
    }

    // ── Test 5: Network error (empty mock) ──────────────────────────────

    #[tokio::test]
    async fn submit_network_error() {
        let mock = MockChainTransport::new();
        // No responses → NetworkError("no mock response")

        let submitter = ChainSubmitter::new(Box::new(mock));
        let result = submitter.submit_claim(&make_receipt(), test_address()).await;

        assert!(result.is_err());
        match result {
            Err(ChainSubmitError::NetworkError(msg)) => {
                assert!(msg.contains("no mock response"), "msg: {}", msg);
            }
            other => panic!("expected NetworkError, got {:?}", other),
        }
    }

    // ── Test 6: FIFO ordering ───────────────────────────────────────────

    #[tokio::test]
    async fn mock_fifo_ordering() {
        let mock = MockChainTransport::new();
        mock.push_response(ClaimRewardResponse::Rejected {
            reason: "first".to_string(),
        });
        mock.push_response(ClaimRewardResponse::Success {
            reward_amount: 42,
            tx_hash: [0x01; 32],
        });

        let submitter = ChainSubmitter::new(Box::new(mock));
        let receipt = make_receipt();
        let addr = test_address();

        // First: Rejected
        let r1 = submitter.submit_claim(&receipt, addr).await;
        assert!(matches!(
            r1.as_ref().unwrap_or_else(|e| panic!("{}", e)),
            ClaimRewardResponse::Rejected { .. }
        ));

        // Second: Success
        let r2 = submitter.submit_claim(&receipt, addr).await;
        assert!(matches!(
            r2.as_ref().unwrap_or_else(|e| panic!("{}", e)),
            ClaimRewardResponse::Success { .. }
        ));

        // Third: empty → error
        let r3 = submitter.submit_claim(&receipt, addr).await;
        assert!(r3.is_err());
    }

    // ── Test 7: ChainSubmitError Display ────────────────────────────────

    #[test]
    fn error_display() {
        assert!(ChainSubmitError::NetworkError("conn".into()).to_string().contains("conn"));
        assert!(ChainSubmitError::InsufficientFunds.to_string().contains("insufficient"));
        assert!(ChainSubmitError::InvalidReceipt("bad".into()).to_string().contains("bad"));
        assert!(ChainSubmitError::Timeout.to_string().contains("timed out"));
    }

    // ── Test 8: InsufficientFunds via custom transport ──────────────────

    #[tokio::test]
    async fn submit_insufficient_funds() {
        struct NoFunds;

        #[async_trait]
        impl ChainTransport for NoFunds {
            async fn submit_claim_reward(
                &self,
                _request: &ClaimRewardRequest,
            ) -> Result<ClaimRewardResponse, ChainSubmitError> {
                Err(ChainSubmitError::InsufficientFunds)
            }
        }

        let submitter = ChainSubmitter::new(Box::new(NoFunds));
        let result = submitter.submit_claim(&make_receipt(), test_address()).await;

        assert!(matches!(result, Err(ChainSubmitError::InsufficientFunds)));
    }
}