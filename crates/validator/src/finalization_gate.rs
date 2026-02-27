//! # Finalization Gate + Epoch Accounting (14C.C.11)
//!
//! Receipt finalization checks with challenge-period gating and
//! per-epoch reward accounting.
//!
//! ## Receipt Finalization Rules
//!
//! | Receipt Type | Rule |
//! |-------------|------|
//! | **Storage** | Always [`Finalized`](ReceiptFinalizationStatus::Finalized) immediately |
//! | **Compute** | Must pass challenge period: `current_time >= expires_at` AND no active challenge |
//!
//! ## Epoch Accounting
//!
//! [`EpochAccounting`] tracks per-epoch distribution summaries. All
//! mutations are pre-checked before applying — if any overflow would
//! occur, the state is left unchanged.

use std::collections::HashMap;
use crate::reward_tracker::ValidatorRewardTracker;

// ════════════════════════════════════════════════════════════════════════════════
// RECEIPT TYPES
// ════════════════════════════════════════════════════════════════════════════════

/// Category of a service receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptType {
    /// Storage receipts — no challenge period required.
    Storage,
    /// Compute receipts — subject to challenge period and fraud proofs.
    Compute,
}

/// Metadata for a single service receipt stored on-chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptRecord {
    /// Whether this is a storage or compute receipt.
    pub receipt_type: ReceiptType,
    /// Timestamp (e.g. slot / unix seconds) when the receipt was submitted.
    pub submitted_at: u64,
    /// Duration of the challenge window (same unit as `submitted_at`).
    pub challenge_period: u64,
    /// Whether there is an active, unresolved challenge against this receipt.
    pub has_active_challenge: bool,
}

// ════════════════════════════════════════════════════════════════════════════════
// CHAIN STATE
// ════════════════════════════════════════════════════════════════════════════════

/// Minimal chain state required by the finalization gate.
///
/// Contains the receipt registry keyed by receipt hash.
#[derive(Debug, Clone)]
pub struct ChainState {
    receipts: HashMap<[u8; 32], ReceiptRecord>,
}

impl ChainState {
    /// Create an empty chain state.
    pub fn new() -> Self {
        Self {
            receipts: HashMap::new(),
        }
    }

    /// Look up a receipt by its hash.
    pub fn get_receipt(&self, hash: &[u8; 32]) -> Option<&ReceiptRecord> {
        self.receipts.get(hash)
    }

    /// Insert or overwrite a receipt record.
    pub fn insert_receipt(&mut self, hash: [u8; 32], record: ReceiptRecord) {
        self.receipts.insert(hash, record);
    }
}

impl Default for ChainState {
    fn default() -> Self {
        Self::new()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// FINALIZATION STATUS
// ════════════════════════════════════════════════════════════════════════════════

/// Outcome of evaluating a receipt's finalization readiness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptFinalizationStatus {
    /// The receipt has passed all checks and may be rewarded.
    Finalized,
    /// The receipt's challenge window has not yet expired.
    PendingChallenge {
        /// Timestamp at which the challenge period ends.
        expires_at: u64,
    },
    /// The receipt has an active, unresolved challenge.
    Challenged,
    /// The receipt was not found on-chain.
    Rejected,
}

// ════════════════════════════════════════════════════════════════════════════════
// FINALIZATION CHECK
// ════════════════════════════════════════════════════════════════════════════════

/// Evaluate whether a single receipt is eligible for reward distribution.
///
/// # Rules
///
/// 1. Receipt not found → [`Rejected`](ReceiptFinalizationStatus::Rejected)
/// 2. Storage receipt → [`Finalized`](ReceiptFinalizationStatus::Finalized)
/// 3. Compute receipt:
///    - Active challenge → [`Challenged`](ReceiptFinalizationStatus::Challenged)
///    - `current_time < expires_at` → [`PendingChallenge`](ReceiptFinalizationStatus::PendingChallenge)
///    - Otherwise → [`Finalized`](ReceiptFinalizationStatus::Finalized)
///
/// `expires_at` is computed as `submitted_at.saturating_add(challenge_period)`.
/// If the addition saturates to `u64::MAX`, the receipt is conservatively
/// held in `PendingChallenge` until `current_time` reaches `u64::MAX`.
pub fn check_finalization(
    receipt_hash: &[u8; 32],
    chain_state: &ChainState,
    current_time: u64,
) -> ReceiptFinalizationStatus {
    let record = match chain_state.get_receipt(receipt_hash) {
        Some(r) => r,
        None => return ReceiptFinalizationStatus::Rejected,
    };

    match record.receipt_type {
        ReceiptType::Storage => ReceiptFinalizationStatus::Finalized,
        ReceiptType::Compute => {
            if record.has_active_challenge {
                return ReceiptFinalizationStatus::Challenged;
            }

            let expires_at = record.submitted_at.saturating_add(record.challenge_period);

            if current_time >= expires_at {
                ReceiptFinalizationStatus::Finalized
            } else {
                ReceiptFinalizationStatus::PendingChallenge { expires_at }
            }
        }
    }
}

/// Evaluate finalization status for a batch of receipts.
///
/// # Determinism
///
/// The output is in the **same order** as the input `receipts` slice.
/// This function does not modify any state.
pub fn batch_check_finalization(
    receipts: &[[u8; 32]],
    chain_state: &ChainState,
    current_time: u64,
) -> Vec<([u8; 32], ReceiptFinalizationStatus)> {
    receipts
        .iter()
        .map(|hash| (*hash, check_finalization(hash, chain_state, current_time)))
        .collect()
}

// ════════════════════════════════════════════════════════════════════════════════
// EPOCH ACCOUNTING
// ════════════════════════════════════════════════════════════════════════════════

/// Per-epoch reward distribution summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochRewardSummary {
    /// Epoch number.
    pub epoch: u64,
    /// Number of receipts that reached `Finalized` status in this epoch.
    pub receipts_finalized: u64,
    /// Total tokens distributed to validators in this epoch.
    pub total_validator_reward: u128,
    /// Number of individual distribution operations in this epoch.
    pub distribution_count: u64,
}

/// Errors that can occur during epoch accounting operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochAccountingError {
    /// A checked arithmetic operation would overflow.
    Overflow,
    /// The provided epoch is invalid (e.g. epoch 0 is reserved for genesis).
    InvalidEpoch,
}

impl core::fmt::Display for EpochAccountingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Overflow => f.write_str("epoch accounting overflow"),
            Self::InvalidEpoch => f.write_str("invalid epoch"),
        }
    }
}

/// Accumulator for per-epoch reward distribution summaries.
///
/// Maintains a map of epoch → [`EpochRewardSummary`]. All mutation
/// methods are pre-checked: if any overflow would occur, the state
/// is left completely unchanged (atomic semantics).
#[derive(Debug, Clone)]
pub struct EpochAccounting {
    summaries: HashMap<u64, EpochRewardSummary>,
}

impl EpochAccounting {
    /// Create an empty epoch accounting state.
    pub fn new() -> Self {
        Self {
            summaries: HashMap::new(),
        }
    }

    /// Record a reward distribution for the given epoch.
    ///
    /// Updates both the per-epoch summary and the tracker's
    /// `total_distributed` counter. All overflow checks are performed
    /// before any mutation.
    ///
    /// # Errors
    ///
    /// * [`EpochAccountingError::InvalidEpoch`] if `epoch == 0`.
    /// * [`EpochAccountingError::Overflow`] if any checked addition
    ///   would overflow.
    pub fn record_distribution(
        &mut self,
        tracker: &mut ValidatorRewardTracker,
        epoch: u64,
        amount: u128,
    ) -> Result<(), EpochAccountingError> {
        if epoch == 0 {
            return Err(EpochAccountingError::InvalidEpoch);
        }

        // ── Pre-check tracker overflow ──────────────────────────────────
        tracker
            .total_distributed()
            .checked_add(amount)
            .ok_or(EpochAccountingError::Overflow)?;

        // ── Pre-check summary overflows ─────────────────────────────────
        let summary = self.summaries.entry(epoch).or_insert(EpochRewardSummary {
            epoch,
            receipts_finalized: 0,
            total_validator_reward: 0,
            distribution_count: 0,
        });

        let new_reward = summary
            .total_validator_reward
            .checked_add(amount)
            .ok_or(EpochAccountingError::Overflow)?;
        let new_count = summary
            .distribution_count
            .checked_add(1)
            .ok_or(EpochAccountingError::Overflow)?;

        // ── Apply tracker mutation ──────────────────────────────────────
        tracker
            .add_total_distributed(amount)
            .map_err(|_| EpochAccountingError::Overflow)?;

        // ── Apply summary mutations (safe: pre-checked) ────────────────
        summary.total_validator_reward = new_reward;
        summary.distribution_count = new_count;

        Ok(())
    }

    /// Record that a receipt was finalized in the given epoch.
    ///
    /// Increments `receipts_finalized` for the epoch.
    ///
    /// # Errors
    ///
    /// * [`EpochAccountingError::InvalidEpoch`] if `epoch == 0`.
    /// * [`EpochAccountingError::Overflow`] if the counter would overflow `u64`.
    pub fn record_finalized_receipt(
        &mut self,
        epoch: u64,
    ) -> Result<(), EpochAccountingError> {
        if epoch == 0 {
            return Err(EpochAccountingError::InvalidEpoch);
        }

        let summary = self.summaries.entry(epoch).or_insert(EpochRewardSummary {
            epoch,
            receipts_finalized: 0,
            total_validator_reward: 0,
            distribution_count: 0,
        });

        summary.receipts_finalized = summary
            .receipts_finalized
            .checked_add(1)
            .ok_or(EpochAccountingError::Overflow)?;

        Ok(())
    }

    /// Query the summary for a given epoch.
    pub fn get_summary(&self, epoch: u64) -> Option<&EpochRewardSummary> {
        self.summaries.get(&epoch)
    }
}

impl Default for EpochAccounting {
    fn default() -> Self {
        Self::new()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// STANDALONE FUNCTION (contract-required signature)
// ════════════════════════════════════════════════════════════════════════════════

/// Update the tracker's total distributed amount for a given epoch.
///
/// This is the standalone entry point required by the contract. For
/// full per-epoch accounting (receipts_finalized, distribution_count),
/// use [`EpochAccounting::record_distribution`].
///
/// # Errors
///
/// * [`EpochAccountingError::InvalidEpoch`] if `epoch == 0`.
/// * [`EpochAccountingError::Overflow`] if the tracker would overflow.
pub fn track_epoch_distribution(
    tracker: &mut ValidatorRewardTracker,
    epoch: u64,
    amount: u128,
) -> Result<(), EpochAccountingError> {
    if epoch == 0 {
        return Err(EpochAccountingError::InvalidEpoch);
    }
    tracker
        .add_total_distributed(amount)
        .map_err(|_| EpochAccountingError::Overflow)
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn rhash(n: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = n;
        h
    }

    fn storage_record() -> ReceiptRecord {
        ReceiptRecord {
            receipt_type: ReceiptType::Storage,
            submitted_at: 0,
            challenge_period: 0,
            has_active_challenge: false,
        }
    }

    fn compute_record(submitted: u64, period: u64, challenged: bool) -> ReceiptRecord {
        ReceiptRecord {
            receipt_type: ReceiptType::Compute,
            submitted_at: submitted,
            challenge_period: period,
            has_active_challenge: challenged,
        }
    }

    /// Extract Ok variant after asserting success; returns from test on Err.
    macro_rules! ok {
        ($e:expr) => {{
            let r = $e;
            assert!(r.is_ok(), "expected Ok, got {:?}", r);
            match r { Ok(v) => v, Err(_) => return }
        }};
    }

    // ── 1. storage_receipt_finalized_immediately ─────────────────────────
    #[test]
    fn storage_receipt_finalized_immediately() {
        let mut cs = ChainState::new();
        cs.insert_receipt(rhash(1), storage_record());

        let status = check_finalization(&rhash(1), &cs, 0);
        assert_eq!(status, ReceiptFinalizationStatus::Finalized);

        // Also finalized at any future time
        let status2 = check_finalization(&rhash(1), &cs, u64::MAX);
        assert_eq!(status2, ReceiptFinalizationStatus::Finalized);
    }

    // ── 2. compute_receipt_pending_before_expiry ─────────────────────────
    #[test]
    fn compute_receipt_pending_before_expiry() {
        let mut cs = ChainState::new();
        // submitted_at=100, challenge_period=50 → expires_at=150
        cs.insert_receipt(rhash(1), compute_record(100, 50, false));

        let status = check_finalization(&rhash(1), &cs, 120);
        assert_eq!(
            status,
            ReceiptFinalizationStatus::PendingChallenge { expires_at: 150 }
        );
    }

    // ── 3. compute_receipt_finalized_after_expiry ────────────────────────
    #[test]
    fn compute_receipt_finalized_after_expiry() {
        let mut cs = ChainState::new();
        cs.insert_receipt(rhash(1), compute_record(100, 50, false));

        // current_time = 200 > 150 (expires_at)
        let status = check_finalization(&rhash(1), &cs, 200);
        assert_eq!(status, ReceiptFinalizationStatus::Finalized);
    }

    // ── 4. compute_receipt_with_active_challenge ─────────────────────────
    #[test]
    fn compute_receipt_with_active_challenge() {
        let mut cs = ChainState::new();
        // Even though challenge period has expired, active challenge blocks finalization
        cs.insert_receipt(rhash(1), compute_record(100, 50, true));

        let status = check_finalization(&rhash(1), &cs, 999);
        assert_eq!(status, ReceiptFinalizationStatus::Challenged);
    }

    // ── 5. rejected_receipt ──────────────────────────────────────────────
    #[test]
    fn rejected_receipt() {
        let cs = ChainState::new(); // empty
        let status = check_finalization(&rhash(99), &cs, 0);
        assert_eq!(status, ReceiptFinalizationStatus::Rejected);
    }

    // ── 6. batch_check_deterministic_order ───────────────────────────────
    #[test]
    fn batch_check_deterministic_order() {
        let mut cs = ChainState::new();
        cs.insert_receipt(rhash(10), storage_record());
        cs.insert_receipt(rhash(20), compute_record(0, 1000, false));
        cs.insert_receipt(rhash(30), compute_record(0, 10, true));
        // rhash(40) not inserted → Rejected

        let hashes = [rhash(30), rhash(10), rhash(40), rhash(20)];
        let results = batch_check_finalization(&hashes, &cs, 5);

        // Must match input order exactly
        assert_eq!(results.len(), 4);
        assert_eq!(results[0].0, rhash(30));
        assert_eq!(results[0].1, ReceiptFinalizationStatus::Challenged);

        assert_eq!(results[1].0, rhash(10));
        assert_eq!(results[1].1, ReceiptFinalizationStatus::Finalized);

        assert_eq!(results[2].0, rhash(40));
        assert_eq!(results[2].1, ReceiptFinalizationStatus::Rejected);

        assert_eq!(results[3].0, rhash(20));
        assert_eq!(
            results[3].1,
            ReceiptFinalizationStatus::PendingChallenge { expires_at: 1000 }
        );

        // Repeat → identical output
        let results2 = batch_check_finalization(&hashes, &cs, 5);
        assert_eq!(results, results2);
    }

    // ── 7. epoch_accounting_increment ────────────────────────────────────
    #[test]
    fn epoch_accounting_increment() {
        let mut tracker = ValidatorRewardTracker::new();
        let mut acct = EpochAccounting::new();

        ok!(acct.record_distribution(&mut tracker, 1, 500));
        ok!(acct.record_distribution(&mut tracker, 1, 300));

        let summary = acct.get_summary(1);
        assert!(summary.is_some());
        if let Some(s) = summary {
            assert_eq!(s.total_validator_reward, 800);
            assert_eq!(s.distribution_count, 2);
            assert_eq!(s.epoch, 1);
        }
        assert_eq!(tracker.total_distributed(), 800);
    }

    // ── 8. epoch_accounting_overflow_error ────────────────────────────────
    #[test]
    fn epoch_accounting_overflow_error() {
        let mut tracker = ValidatorRewardTracker::new();
        let mut acct = EpochAccounting::new();

        // First: distribute near-max amount
        ok!(acct.record_distribution(&mut tracker, 1, u128::MAX - 10));

        // Second: this should overflow
        let result = acct.record_distribution(&mut tracker, 1, 20);
        assert_eq!(result, Err(EpochAccountingError::Overflow));
    }

    // ── 9. no_partial_update_on_error ────────────────────────────────────
    #[test]
    fn no_partial_update_on_error() {
        let mut tracker = ValidatorRewardTracker::new();
        let mut acct = EpochAccounting::new();

        // Seed with known state
        ok!(acct.record_distribution(&mut tracker, 1, 100));

        let tracker_before = tracker.total_distributed();
        let summary_before = acct.get_summary(1).cloned();

        // Attempt overflow
        let result = acct.record_distribution(&mut tracker, 1, u128::MAX);
        assert!(result.is_err());

        // State must be unchanged
        assert_eq!(tracker.total_distributed(), tracker_before);
        assert_eq!(acct.get_summary(1).cloned(), summary_before);
    }

    // ── 10. challenge_period_edge_boundary ───────────────────────────────
    #[test]
    fn challenge_period_edge_boundary() {
        let mut cs = ChainState::new();
        // expires_at = 100 + 50 = 150
        cs.insert_receipt(rhash(1), compute_record(100, 50, false));

        // current_time == 149 → still pending
        let before = check_finalization(&rhash(1), &cs, 149);
        assert_eq!(
            before,
            ReceiptFinalizationStatus::PendingChallenge { expires_at: 150 }
        );

        // current_time == 150 → EXACTLY at boundary → Finalized
        let at = check_finalization(&rhash(1), &cs, 150);
        assert_eq!(at, ReceiptFinalizationStatus::Finalized);

        // current_time == 151 → past boundary → Finalized
        let after = check_finalization(&rhash(1), &cs, 151);
        assert_eq!(after, ReceiptFinalizationStatus::Finalized);
    }

    // ── 11. finalized_receipt_count_correct ──────────────────────────────
    #[test]
    fn finalized_receipt_count_correct() {
        let mut acct = EpochAccounting::new();

        ok!(acct.record_finalized_receipt(5));
        ok!(acct.record_finalized_receipt(5));
        ok!(acct.record_finalized_receipt(5));

        let summary = acct.get_summary(5);
        assert!(summary.is_some());
        if let Some(s) = summary {
            assert_eq!(s.receipts_finalized, 3);
            assert_eq!(s.distribution_count, 0); // no distributions
            assert_eq!(s.total_validator_reward, 0);
        }
    }

    // ── 12. distribution_count_increment_correct ────────────────────────
    #[test]
    fn distribution_count_increment_correct() {
        let mut tracker = ValidatorRewardTracker::new();
        let mut acct = EpochAccounting::new();

        // 5 distributions across 2 epochs
        for _ in 0..3 {
            ok!(acct.record_distribution(&mut tracker, 1, 10));
        }
        for _ in 0..2 {
            ok!(acct.record_distribution(&mut tracker, 2, 20));
        }

        let s1 = acct.get_summary(1);
        assert!(s1.is_some(), "epoch 1 summary missing");
        if let Some(s) = s1 {
            assert_eq!(s.distribution_count, 3);
            assert_eq!(s.total_validator_reward, 30);
        }

        let s2 = acct.get_summary(2);
        assert!(s2.is_some(), "epoch 2 summary missing");
        if let Some(s) = s2 {
            assert_eq!(s.distribution_count, 2);
            assert_eq!(s.total_validator_reward, 40);
        }

        assert_eq!(tracker.total_distributed(), 70);
    }

    // ── 13. standalone_track_epoch_distribution ──────────────────────────
    #[test]
    fn standalone_track_epoch_distribution() {
        let mut tracker = ValidatorRewardTracker::new();

        ok!(track_epoch_distribution(&mut tracker, 1, 500));
        assert_eq!(tracker.total_distributed(), 500);

        ok!(track_epoch_distribution(&mut tracker, 2, 300));
        assert_eq!(tracker.total_distributed(), 800);
    }

    // ── 14. standalone_invalid_epoch_zero ─────────────────────────────────
    #[test]
    fn standalone_invalid_epoch_zero() {
        let mut tracker = ValidatorRewardTracker::new();
        let result = track_epoch_distribution(&mut tracker, 0, 100);
        assert_eq!(result, Err(EpochAccountingError::InvalidEpoch));
        assert_eq!(tracker.total_distributed(), 0); // unchanged
    }

    // ── 15. compute_receipt_challenge_blocks_even_if_expired ─────────────
    #[test]
    fn compute_receipt_challenge_blocks_even_if_expired() {
        let mut cs = ChainState::new();
        // Challenge period expired (100+50=150), but challenge is active
        cs.insert_receipt(rhash(1), compute_record(100, 50, true));

        // Even at time 999 (well past expiry), challenge overrides
        let status = check_finalization(&rhash(1), &cs, 999);
        assert_eq!(status, ReceiptFinalizationStatus::Challenged);
    }

    // ── 16. saturating_challenge_period_overflow ─────────────────────────
    #[test]
    fn saturating_challenge_period_overflow() {
        let mut cs = ChainState::new();
        // submitted_at near u64::MAX, period causes overflow → saturates
        cs.insert_receipt(
            rhash(1),
            compute_record(u64::MAX - 10, 100, false),
        );

        // expires_at saturates to u64::MAX
        let status = check_finalization(&rhash(1), &cs, u64::MAX - 5);
        assert_eq!(
            status,
            ReceiptFinalizationStatus::PendingChallenge { expires_at: u64::MAX }
        );

        // Only at u64::MAX can it finalize
        let status2 = check_finalization(&rhash(1), &cs, u64::MAX);
        assert_eq!(status2, ReceiptFinalizationStatus::Finalized);
    }
}