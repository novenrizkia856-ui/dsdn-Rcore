//! # ReceiptHandler — Receipt Storage & Lifecycle Management (14C.B.16)
//!
//! Receives coordinator-signed `ReceiptV1Proto`, performs structural
//! validation, stores receipts in memory, and manages their lifecycle
//! status from `Received` through `Confirmed` or `Rejected`.
//!
//! ## Receipt Lifecycle
//!
//! ```text
//! ReceiptV1Proto (from coordinator)
//!      │
//!      ▼
//! handle_receipt()
//!      │
//!      ├─ Structural validation
//!      ├─ Duplicate check
//!      └─ Store as StoredReceipt { status: Validated }
//!
//! Later:
//!      │
//!      ├─ update_status(SubmittedToChain)
//!      ├─ update_status(InChallengePeriod)
//!      ├─ update_status(Confirmed)
//!      └─ update_status(Rejected)
//! ```
//!
//! ## Determinism
//!
//! - Storage is keyed by `workload_id` bytes (deterministic).
//! - [`pending_submission`] returns receipts sorted by `received_at`
//!   ascending. `HashMap` iteration order is non-deterministic, so
//!   explicit sorting is required.
//! - No randomness, no system time dependency (timestamp is caller-provided).
//!
//! ## Separation of Concerns
//!
//! This module handles **storage and status** only. It does NOT:
//!
//! - Perform cryptographic signature verification (chain responsibility).
//! - Submit receipts to chain (handled by `CoordinatorSubmitter`).
//! - Interact with the network.
//!
//! ## Safety
//!
//! - No `panic!`, `unwrap()`, `expect()`.
//! - No silent error swallowing.
//! - All public items documented.

use std::collections::HashMap;
use std::fmt;

use dsdn_common::coordinator::WorkloadId;
use dsdn_common::receipt_v1_convert::ReceiptV1Proto;

// ════════════════════════════════════════════════════════════════════════════════
// RECEIPT STATUS
// ════════════════════════════════════════════════════════════════════════════════

/// Lifecycle status of a stored receipt.
///
/// Transitions follow a forward-only progression:
///
/// `Received → Validated → SubmittedToChain → InChallengePeriod → Confirmed`
///
/// At any point, a receipt may transition to `Rejected`.
///
/// ## Determinism
///
/// Status transitions are caller-driven (no implicit time-based changes).
/// The handler does not enforce transition ordering — that responsibility
/// belongs to the orchestration layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptStatus {
    /// Receipt received but not yet validated.
    Received,
    /// Structural validation passed. Ready for chain submission.
    Validated,
    /// Submitted to chain, awaiting confirmation.
    SubmittedToChain,
    /// Chain confirmed the receipt. Contains the final reward amount.
    Confirmed {
        /// Final reward amount in base units.
        reward_amount: u128,
    },
    /// Receipt rejected at some stage.
    Rejected {
        /// Human-readable rejection reason.
        reason: String,
    },
    /// Receipt is in the on-chain challenge period.
    InChallengePeriod {
        /// Unix timestamp when the challenge period expires.
        expires_at: u64,
    },
}

impl fmt::Display for ReceiptStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Received => write!(f, "Received"),
            Self::Validated => write!(f, "Validated"),
            Self::SubmittedToChain => write!(f, "SubmittedToChain"),
            Self::Confirmed { reward_amount } => {
                write!(f, "Confirmed(reward={})", reward_amount)
            }
            Self::Rejected { reason } => write!(f, "Rejected({})", reason),
            Self::InChallengePeriod { expires_at } => {
                write!(f, "InChallengePeriod(expires={})", expires_at)
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// STORED RECEIPT
// ════════════════════════════════════════════════════════════════════════════════

/// A receipt with its current lifecycle status and metadata.
///
/// Stored in [`ReceiptHandler`] keyed by `workload_id` bytes.
#[derive(Debug, Clone)]
pub struct StoredReceipt {
    /// The coordinator-signed receipt.
    pub receipt: ReceiptV1Proto,
    /// Current lifecycle status.
    pub status: ReceiptStatus,
    /// Unix timestamp when the receipt was received by this node.
    pub received_at: u64,
    /// Workload identifier extracted from the receipt.
    pub workload_id: WorkloadId,
}

// ════════════════════════════════════════════════════════════════════════════════
// ERROR
// ════════════════════════════════════════════════════════════════════════════════

/// Errors from receipt handling operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptHandlerError {
    /// Structural validation of the receipt failed.
    ValidationFailed(String),
    /// A receipt for this workload_id already exists.
    DuplicateReceipt,
}

impl fmt::Display for ReceiptHandlerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ValidationFailed(msg) => write!(f, "receipt validation failed: {}", msg),
            Self::DuplicateReceipt => write!(f, "duplicate receipt for workload_id"),
        }
    }
}

impl std::error::Error for ReceiptHandlerError {}

// ════════════════════════════════════════════════════════════════════════════════
// HANDLER
// ════════════════════════════════════════════════════════════════════════════════

/// In-memory receipt storage with lifecycle status management.
///
/// Receipts are keyed by `workload_id` bytes. Duplicate `workload_id`
/// submissions are rejected.
///
/// ## Determinism
///
/// - [`pending_submission`] results are sorted by `received_at` ascending.
///   `HashMap` iteration order is non-deterministic, so explicit sorting
///   is applied before returning.
/// - All operations are deterministic given the same inputs.
///
/// ## Thread Safety
///
/// `ReceiptHandler` is NOT internally synchronized. External
/// synchronization (e.g., `Mutex<ReceiptHandler>`) is required for
/// concurrent access.
pub struct ReceiptHandler {
    /// Receipts keyed by workload_id bytes.
    receipts: HashMap<Vec<u8>, StoredReceipt>,
}

impl ReceiptHandler {
    /// Creates a new empty handler.
    #[must_use]
    pub fn new() -> Self {
        Self {
            receipts: HashMap::new(),
        }
    }

    /// Receives, validates, and stores a coordinator-signed receipt.
    ///
    /// ## Flow
    ///
    /// 1. Extract `workload_id` from the receipt (must be 32 bytes).
    /// 2. Check for duplicate (same `workload_id` already stored).
    /// 3. Perform structural validation (field lengths, required fields).
    /// 4. Store as `StoredReceipt` with status `Validated`.
    ///
    /// ## Arguments
    ///
    /// - `receipt`: The coordinator-signed receipt to store.
    /// - `timestamp`: Caller-provided Unix timestamp (not derived from system clock).
    ///
    /// ## Errors
    ///
    /// - [`ReceiptHandlerError::ValidationFailed`] if structural checks fail.
    /// - [`ReceiptHandlerError::DuplicateReceipt`] if a receipt for this
    ///   workload already exists.
    pub fn handle_receipt(
        &mut self,
        receipt: ReceiptV1Proto,
        timestamp: u64,
    ) -> Result<(), ReceiptHandlerError> {
        // ── Step 1: Extract workload_id ────────────────────────────────
        let workload_id = WorkloadId::from_bytes(&receipt.workload_id).ok_or_else(|| {
            ReceiptHandlerError::ValidationFailed(format!(
                "invalid workload_id length: expected 32, got {}",
                receipt.workload_id.len()
            ))
        })?;

        let key = receipt.workload_id.clone();

        // ── Step 2: Duplicate check ────────────────────────────────────
        if self.receipts.contains_key(&key) {
            return Err(ReceiptHandlerError::DuplicateReceipt);
        }

        // ── Step 3: Structural validation ──────────────────────────────
        validate_receipt_proto(&receipt)?;

        // ── Step 4: Store ──────────────────────────────────────────────
        let stored = StoredReceipt {
            receipt,
            status: ReceiptStatus::Validated,
            received_at: timestamp,
            workload_id,
        };

        self.receipts.insert(key, stored);

        Ok(())
    }

    /// Returns a reference to the stored receipt for the given workload_id.
    ///
    /// Returns `None` if no receipt exists for this workload.
    /// No cloning — returns a reference.
    #[must_use]
    pub fn get_receipt(&self, workload_id: &[u8]) -> Option<&StoredReceipt> {
        self.receipts.get(workload_id)
    }

    /// Updates the lifecycle status of a stored receipt.
    ///
    /// ## Arguments
    ///
    /// - `workload_id`: The workload identifier (as bytes).
    /// - `new_status`: The new status to set.
    ///
    /// ## Errors
    ///
    /// Returns `Err("receipt not found")` if no receipt exists for this workload.
    pub fn update_status(
        &mut self,
        workload_id: &[u8],
        new_status: ReceiptStatus,
    ) -> Result<(), String> {
        match self.receipts.get_mut(workload_id) {
            Some(stored) => {
                stored.status = new_status;
                Ok(())
            }
            None => Err("receipt not found".to_string()),
        }
    }

    /// Returns all receipts with status `Validated`, sorted by
    /// `received_at` ascending (deterministic order).
    ///
    /// These are receipts that have passed structural validation and
    /// are ready for chain submission.
    ///
    /// ## Determinism
    ///
    /// `HashMap` iteration order is non-deterministic. This method
    /// collects matching receipts and sorts by `received_at` to
    /// guarantee a deterministic result regardless of map internals.
    #[must_use]
    pub fn pending_submission(&self) -> Vec<&StoredReceipt> {
        let mut pending: Vec<&StoredReceipt> = self
            .receipts
            .values()
            .filter(|sr| sr.status == ReceiptStatus::Validated)
            .collect();

        pending.sort_by_key(|sr| sr.received_at);

        pending
    }

    /// Returns the total number of stored receipts (all statuses).
    #[must_use]
    pub fn receipt_count(&self) -> usize {
        self.receipts.len()
    }
}

impl Default for ReceiptHandler {
    fn default() -> Self {
        Self::new()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// STRUCTURAL VALIDATION (private)
// ════════════════════════════════════════════════════════════════════════════════

/// Performs structural validation on a `ReceiptV1Proto`.
///
/// This is NOT cryptographic verification — it only checks that
/// required fields are present and have valid lengths.
///
/// ## Checks
///
/// 1. `node_id` must be 32 bytes.
/// 2. `node_signature` must be 64 bytes.
/// 3. `usage_proof_hash` must be 32 bytes.
/// 4. `coordinator_threshold_signature.signature` must be 64 bytes.
/// 5. `coordinator_threshold_signature.message_hash` must be 32 bytes.
/// 6. `submitter_address` must not be empty.
/// 7. If `execution_commitment` is present:
///    - `workload_id` must be 32 bytes.
///    - `input_hash` must be 32 bytes.
///    - `output_hash` must be 32 bytes.
///    - `state_root_before` must be 32 bytes.
///    - `state_root_after` must be 32 bytes.
///    - `execution_trace_merkle_root` must be 32 bytes.
fn validate_receipt_proto(receipt: &ReceiptV1Proto) -> Result<(), ReceiptHandlerError> {
    let err = |msg: String| ReceiptHandlerError::ValidationFailed(msg);

    // node_id: 32 bytes (Ed25519 public key).
    if receipt.node_id.len() != 32 {
        return Err(err(format!(
            "node_id length: expected 32, got {}",
            receipt.node_id.len()
        )));
    }

    // node_signature: 64 bytes (Ed25519 signature).
    if receipt.node_signature.len() != 64 {
        return Err(err(format!(
            "node_signature length: expected 64, got {}",
            receipt.node_signature.len()
        )));
    }

    // usage_proof_hash: 32 bytes (SHA3-256).
    if receipt.usage_proof_hash.len() != 32 {
        return Err(err(format!(
            "usage_proof_hash length: expected 32, got {}",
            receipt.usage_proof_hash.len()
        )));
    }

    // coordinator_threshold_signature: signature 64 bytes.
    if receipt.coordinator_threshold_signature.signature.len() != 64 {
        return Err(err(format!(
            "coordinator_threshold_signature.signature length: expected 64, got {}",
            receipt.coordinator_threshold_signature.signature.len()
        )));
    }

    // coordinator_threshold_signature: message_hash 32 bytes.
    if receipt.coordinator_threshold_signature.message_hash.len() != 32 {
        return Err(err(format!(
            "coordinator_threshold_signature.message_hash length: expected 32, got {}",
            receipt.coordinator_threshold_signature.message_hash.len()
        )));
    }

    // submitter_address: non-empty.
    if receipt.submitter_address.is_empty() {
        return Err(err("submitter_address is empty".to_string()));
    }

    // execution_commitment: if present, all hash fields must be 32 bytes.
    if let Some(ref ec) = receipt.execution_commitment {
        let fields: &[(&str, &[u8])] = &[
            ("execution_commitment.workload_id", &ec.workload_id),
            ("execution_commitment.input_hash", &ec.input_hash),
            ("execution_commitment.output_hash", &ec.output_hash),
            ("execution_commitment.state_root_before", &ec.state_root_before),
            ("execution_commitment.state_root_after", &ec.state_root_after),
            (
                "execution_commitment.execution_trace_merkle_root",
                &ec.execution_trace_merkle_root,
            ),
        ];

        for (name, data) in fields {
            if data.len() != 32 {
                return Err(err(format!(
                    "{} length: expected 32, got {}",
                    name,
                    data.len()
                )));
            }
        }
    }

    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use dsdn_common::receipt_v1_convert::AggregateSignatureProto;

    // ── Helpers ──────────────────────────────────────────────────────────

    fn make_valid_receipt() -> ReceiptV1Proto {
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

    fn make_receipt_with_wid(wid: u8) -> ReceiptV1Proto {
        let mut r = make_valid_receipt();
        r.workload_id = vec![wid; 32];
        r
    }

    // ── Test 1: Receive valid receipt ────────────────────────────────────

    #[test]
    fn receive_valid_receipt() {
        let mut handler = ReceiptHandler::new();
        let receipt = make_valid_receipt();

        let result = handler.handle_receipt(receipt, 1000);
        assert!(result.is_ok(), "valid receipt should be accepted");
        assert_eq!(handler.receipt_count(), 1);

        let stored = handler.get_receipt(&[0x42; 32]);
        assert!(stored.is_some());

        let sr = stored.unwrap_or_else(|| panic!("receipt should exist"));
        assert_eq!(sr.status, ReceiptStatus::Validated);
        assert_eq!(sr.received_at, 1000);
        assert_eq!(*sr.workload_id.as_bytes(), [0x42; 32]);
    }

    // ── Test 2: Reject invalid receipt ──────────────────────────────────

    #[test]
    fn reject_invalid_receipt() {
        let mut handler = ReceiptHandler::new();

        // Invalid: node_signature too short.
        let mut receipt = make_valid_receipt();
        receipt.node_signature = vec![0x00; 10];

        let result = handler.handle_receipt(receipt, 1000);
        assert!(result.is_err());
        match result {
            Err(ReceiptHandlerError::ValidationFailed(msg)) => {
                assert!(msg.contains("node_signature"), "msg: {}", msg);
            }
            other => panic!("expected ValidationFailed, got {:?}", other),
        }
        assert_eq!(handler.receipt_count(), 0);

        // Invalid: workload_id wrong length.
        let mut receipt2 = make_valid_receipt();
        receipt2.workload_id = vec![0x01; 16]; // 16 instead of 32

        let result2 = handler.handle_receipt(receipt2, 1000);
        assert!(result2.is_err());
        match result2 {
            Err(ReceiptHandlerError::ValidationFailed(msg)) => {
                assert!(msg.contains("workload_id"), "msg: {}", msg);
            }
            other => panic!("expected ValidationFailed, got {:?}", other),
        }

        // Invalid: empty submitter_address.
        let mut receipt3 = make_valid_receipt();
        receipt3.submitter_address = vec![];

        let result3 = handler.handle_receipt(receipt3, 1000);
        assert!(result3.is_err());
        match result3 {
            Err(ReceiptHandlerError::ValidationFailed(msg)) => {
                assert!(msg.contains("submitter_address"), "msg: {}", msg);
            }
            other => panic!("expected ValidationFailed, got {:?}", other),
        }
    }

    // ── Test 3: Duplicate rejection ─────────────────────────────────────

    #[test]
    fn duplicate_rejection() {
        let mut handler = ReceiptHandler::new();

        let r1 = handler.handle_receipt(make_valid_receipt(), 1000);
        assert!(r1.is_ok());

        // Same workload_id → DuplicateReceipt.
        let r2 = handler.handle_receipt(make_valid_receipt(), 2000);
        assert!(r2.is_err());
        assert_eq!(r2, Err(ReceiptHandlerError::DuplicateReceipt));
        assert_eq!(handler.receipt_count(), 1);
    }

    // ── Test 4: Status update success ───────────────────────────────────

    #[test]
    fn status_update_success() {
        let mut handler = ReceiptHandler::new();
        let wid = [0x42u8; 32];

        handler
            .handle_receipt(make_valid_receipt(), 1000)
            .unwrap_or_else(|e| panic!("setup: {}", e));

        // Update to SubmittedToChain.
        let r1 = handler.update_status(&wid, ReceiptStatus::SubmittedToChain);
        assert!(r1.is_ok());
        assert_eq!(
            handler.get_receipt(&wid).map(|sr| &sr.status),
            Some(&ReceiptStatus::SubmittedToChain)
        );

        // Update to InChallengePeriod.
        let r2 = handler.update_status(
            &wid,
            ReceiptStatus::InChallengePeriod { expires_at: 9999 },
        );
        assert!(r2.is_ok());

        // Update to Confirmed.
        let r3 = handler.update_status(
            &wid,
            ReceiptStatus::Confirmed { reward_amount: 42 },
        );
        assert!(r3.is_ok());
        assert_eq!(
            handler.get_receipt(&wid).map(|sr| &sr.status),
            Some(&ReceiptStatus::Confirmed { reward_amount: 42 })
        );

        // Non-existent workload_id.
        let r4 = handler.update_status(&[0xFF; 32], ReceiptStatus::Rejected {
            reason: "nope".into(),
        });
        assert!(r4.is_err());
        assert_eq!(r4, Err("receipt not found".to_string()));
    }

    // ── Test 5: Pending submission returns only Validated ────────────────

    #[test]
    fn pending_submission_returns_only_validated() {
        let mut handler = ReceiptHandler::new();

        // Insert 3 receipts.
        handler
            .handle_receipt(make_receipt_with_wid(0x01), 100)
            .unwrap_or_else(|e| panic!("setup: {}", e));
        handler
            .handle_receipt(make_receipt_with_wid(0x02), 200)
            .unwrap_or_else(|e| panic!("setup: {}", e));
        handler
            .handle_receipt(make_receipt_with_wid(0x03), 300)
            .unwrap_or_else(|e| panic!("setup: {}", e));

        // All 3 are Validated initially.
        assert_eq!(handler.pending_submission().len(), 3);

        // Transition one to SubmittedToChain.
        handler
            .update_status(&[0x02; 32], ReceiptStatus::SubmittedToChain)
            .unwrap_or_else(|e| panic!("setup: {}", e));

        // Now only 2 pending.
        let pending = handler.pending_submission();
        assert_eq!(pending.len(), 2);

        // Verify none of them have workload_id 0x02.
        for sr in &pending {
            assert_ne!(sr.workload_id.as_bytes(), &[0x02; 32]);
        }
    }

    // ── Test 6: Receipt count correct ───────────────────────────────────

    #[test]
    fn receipt_count_correct() {
        let mut handler = ReceiptHandler::new();
        assert_eq!(handler.receipt_count(), 0);

        handler
            .handle_receipt(make_receipt_with_wid(0x01), 100)
            .unwrap_or_else(|e| panic!("setup: {}", e));
        assert_eq!(handler.receipt_count(), 1);

        handler
            .handle_receipt(make_receipt_with_wid(0x02), 200)
            .unwrap_or_else(|e| panic!("setup: {}", e));
        assert_eq!(handler.receipt_count(), 2);

        // Duplicate doesn't increase count.
        let _ = handler.handle_receipt(make_receipt_with_wid(0x01), 300);
        assert_eq!(handler.receipt_count(), 2);
    }

    // ── Test 7: Pending sorted by timestamp ─────────────────────────────

    #[test]
    fn pending_sorted_by_timestamp() {
        let mut handler = ReceiptHandler::new();

        // Insert in non-chronological order.
        handler
            .handle_receipt(make_receipt_with_wid(0x03), 300)
            .unwrap_or_else(|e| panic!("setup: {}", e));
        handler
            .handle_receipt(make_receipt_with_wid(0x01), 100)
            .unwrap_or_else(|e| panic!("setup: {}", e));
        handler
            .handle_receipt(make_receipt_with_wid(0x02), 200)
            .unwrap_or_else(|e| panic!("setup: {}", e));

        let pending = handler.pending_submission();
        assert_eq!(pending.len(), 3);

        // Must be sorted by received_at ascending.
        assert_eq!(pending[0].received_at, 100);
        assert_eq!(pending[1].received_at, 200);
        assert_eq!(pending[2].received_at, 300);

        // Verify corresponding workload_ids.
        assert_eq!(pending[0].workload_id.as_bytes(), &[0x01; 32]);
        assert_eq!(pending[1].workload_id.as_bytes(), &[0x02; 32]);
        assert_eq!(pending[2].workload_id.as_bytes(), &[0x03; 32]);
    }

    // ── Test 8: Execution commitment validation ─────────────────────────

    #[test]
    fn execution_commitment_validation() {
        let mut handler = ReceiptHandler::new();

        // Valid execution commitment.
        let mut receipt = make_valid_receipt();
        receipt.execution_commitment =
            Some(dsdn_common::receipt_v1_convert::ExecutionCommitmentProto {
                workload_id: vec![0x42; 32],
                input_hash: vec![0xA1; 32],
                output_hash: vec![0xA2; 32],
                state_root_before: vec![0xA3; 32],
                state_root_after: vec![0xA4; 32],
                execution_trace_merkle_root: vec![0xA5; 32],
            });
        let r1 = handler.handle_receipt(receipt, 1000);
        assert!(r1.is_ok(), "valid execution commitment should pass");

        // Invalid: input_hash wrong length.
        let mut receipt2 = make_receipt_with_wid(0x99);
        receipt2.execution_commitment =
            Some(dsdn_common::receipt_v1_convert::ExecutionCommitmentProto {
                workload_id: vec![0x99; 32],
                input_hash: vec![0xA1; 16], // wrong!
                output_hash: vec![0xA2; 32],
                state_root_before: vec![0xA3; 32],
                state_root_after: vec![0xA4; 32],
                execution_trace_merkle_root: vec![0xA5; 32],
            });
        let r2 = handler.handle_receipt(receipt2, 2000);
        assert!(r2.is_err());
        match r2 {
            Err(ReceiptHandlerError::ValidationFailed(msg)) => {
                assert!(msg.contains("input_hash"), "msg: {}", msg);
            }
            other => panic!("expected ValidationFailed, got {:?}", other),
        }
    }

    // ── Test 9: ReceiptHandlerError Display ─────────────────────────────

    #[test]
    fn error_display() {
        let e1 = ReceiptHandlerError::ValidationFailed("bad field".into());
        assert!(e1.to_string().contains("bad field"));

        let e2 = ReceiptHandlerError::DuplicateReceipt;
        assert!(e2.to_string().contains("duplicate"));
    }

    // ── Test 10: ReceiptStatus Display ──────────────────────────────────

    #[test]
    fn status_display() {
        assert_eq!(ReceiptStatus::Received.to_string(), "Received");
        assert_eq!(ReceiptStatus::Validated.to_string(), "Validated");
        assert_eq!(ReceiptStatus::SubmittedToChain.to_string(), "SubmittedToChain");
        assert!(ReceiptStatus::Confirmed { reward_amount: 99 }
            .to_string()
            .contains("99"));
        assert!(ReceiptStatus::Rejected { reason: "bad".into() }
            .to_string()
            .contains("bad"));
        assert!(ReceiptStatus::InChallengePeriod { expires_at: 123 }
            .to_string()
            .contains("123"));
    }
}