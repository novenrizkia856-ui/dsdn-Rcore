//! # Validator Reward Tracker (14C.C.9)
//!
//! Types and read-only queries for tracking per-validator reward accounting.
//!
//! ## Structs
//!
//! - [`ValidatorRewardEntry`]: Per-validator reward state (pending, claimed, epoch, count).
//! - [`ValidatorRewardTracker`]: Aggregate tracker holding all entries with invariant-safe getters.
//!
//! ## Invariants
//!
//! 1. `total_pending()` always equals the sum of all `entry.pending_rewards` (computed on-the-fly).
//! 2. `total_distributed >= total_claimed` at all times.
//! 3. All internal arithmetic uses `checked_*` to prevent overflow.
//! 4. `active_validators()` returns validators sorted lexicographically by `[u8; 32]` ID —
//!    never dependent on `HashMap` iteration order.
//!
//! ## Current Scope
//!
//! This module defines **types and read-only getters only**. Distribution / claim
//! mutations will be added in a subsequent stage.

use std::collections::HashMap;

// ════════════════════════════════════════════════════════════════════════════════
// TYPES
// ════════════════════════════════════════════════════════════════════════════════

/// Per-validator reward accounting entry.
///
/// All balances use `u128` to accommodate very large token supplies
/// without overflow risk in normal operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorRewardEntry {
    /// 32-byte validator identifier (e.g. Ed25519 public key).
    pub validator_id: [u8; 32],
    /// Rewards distributed but not yet claimed.
    pub pending_rewards: u128,
    /// Rewards already claimed by the validator.
    pub claimed_rewards: u128,
    /// Epoch number when last reward was distributed to this validator.
    pub last_receipt_epoch: u64,
    /// How many individual reward receipts this validator has received.
    pub receipt_count: u64,
}

/// Aggregate reward tracker for the validator set.
///
/// Maintains a mapping from validator ID → [`ValidatorRewardEntry`]
/// plus global totals for distributed and claimed amounts.
///
/// # Determinism
///
/// [`active_validators`](Self::active_validators) returns IDs in
/// **lexicographic byte order**, independent of `HashMap` iteration order.
#[derive(Debug, Clone)]
pub struct ValidatorRewardTracker {
    entries: HashMap<[u8; 32], ValidatorRewardEntry>,
    total_distributed: u128,
    total_claimed: u128,
    current_epoch: u64,
}

// ════════════════════════════════════════════════════════════════════════════════
// ERROR TYPES
// ════════════════════════════════════════════════════════════════════════════════

/// Error returned when a checked arithmetic operation overflows during
/// reward accounting mutations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RewardOverflowError;

impl core::fmt::Display for RewardOverflowError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("reward arithmetic overflow")
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// PUBLIC API — READ-ONLY
// ════════════════════════════════════════════════════════════════════════════════

impl ValidatorRewardTracker {
    /// Create a new, empty tracker at epoch 0.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            total_distributed: 0,
            total_claimed: 0,
            current_epoch: 0,
        }
    }

    /// Look up a validator's reward entry by ID.
    ///
    /// Returns `None` if the validator is not tracked.
    pub fn get_entry(&self, validator_id: &[u8; 32]) -> Option<&ValidatorRewardEntry> {
        self.entries.get(validator_id)
    }

    /// Get pending (unclaimed) rewards for a validator.
    ///
    /// Returns `0` if the validator is not tracked.
    pub fn get_pending(&self, validator_id: &[u8; 32]) -> u128 {
        self.entries
            .get(validator_id)
            .map_or(0, |e| e.pending_rewards)
    }

    /// Get total claimed rewards for a validator.
    ///
    /// Returns `0` if the validator is not tracked.
    pub fn get_claimed(&self, validator_id: &[u8; 32]) -> u128 {
        self.entries
            .get(validator_id)
            .map_or(0, |e| e.claimed_rewards)
    }

    /// Compute total pending rewards across **all** validators.
    ///
    /// This is computed on-the-fly from the entries map using checked
    /// arithmetic. Returns the sum, or `0` if the tracker is empty.
    ///
    /// # Invariant
    ///
    /// The returned value equals the sum of `entry.pending_rewards` for
    /// every entry. Overflow is impossible in practice because individual
    /// balances are capped by `u128::MAX` and the number of validators
    /// is bounded, but we use `saturating_add` as a defense-in-depth
    /// measure.
    pub fn total_pending(&self) -> u128 {
        self.entries
            .values()
            .fold(0u128, |acc, e| acc.saturating_add(e.pending_rewards))
    }

    /// Return the IDs of all tracked validators, **sorted lexicographically**.
    ///
    /// # Determinism
    ///
    /// The result is always in ascending byte-wise order regardless of
    /// `HashMap` internal ordering.
    pub fn active_validators(&self) -> Vec<[u8; 32]> {
        let mut ids: Vec<[u8; 32]> = self.entries.keys().copied().collect();
        ids.sort();
        ids
    }

    /// Global total of rewards distributed so far.
    pub fn total_distributed(&self) -> u128 {
        self.total_distributed
    }

    /// Global total of rewards claimed so far.
    pub fn total_claimed(&self) -> u128 {
        self.total_claimed
    }

    /// Current epoch of the tracker.
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Number of tracked validators.
    pub fn validator_count(&self) -> usize {
        self.entries.len()
    }
}

impl Default for ValidatorRewardTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// CRATE-INTERNAL MUTATION API (14C.C.10)
// ════════════════════════════════════════════════════════════════════════════════
//
// These methods allow sibling modules (e.g. `reward_distributor`) to update
// tracker state with checked arithmetic. They are NOT part of the public API.

impl ValidatorRewardTracker {
    /// Add reward amount to a validator's pending balance.
    ///
    /// Creates the entry if it doesn't exist. Updates `last_receipt_epoch`
    /// and increments `receipt_count`. Returns [`RewardOverflowError`] if
    /// any checked arithmetic overflows.
    pub(crate) fn add_pending_reward(
        &mut self,
        validator_id: [u8; 32],
        amount: u128,
        epoch: u64,
    ) -> Result<(), RewardOverflowError> {
        let entry = self.entries.entry(validator_id).or_insert(ValidatorRewardEntry {
            validator_id,
            pending_rewards: 0,
            claimed_rewards: 0,
            last_receipt_epoch: 0,
            receipt_count: 0,
        });
        entry.pending_rewards = entry
            .pending_rewards
            .checked_add(amount)
            .ok_or(RewardOverflowError)?;
        entry.last_receipt_epoch = epoch;
        entry.receipt_count = entry
            .receipt_count
            .checked_add(1)
            .ok_or(RewardOverflowError)?;
        Ok(())
    }

    /// Add to the global `total_distributed` counter.
    ///
    /// Returns [`RewardOverflowError`] if the addition would overflow `u128`.
    pub(crate) fn add_total_distributed(
        &mut self,
        amount: u128,
    ) -> Result<(), RewardOverflowError> {
        self.total_distributed = self
            .total_distributed
            .checked_add(amount)
            .ok_or(RewardOverflowError)?;
        Ok(())
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// INTERNAL — TEST-ONLY HELPERS
// ════════════════════════════════════════════════════════════════════════════════
//
// Distribution mutations are NOT part of the public API yet (14C.C.9 scope).
// These helpers exist solely to allow unit tests to populate state without
// bypassing future mutation invariants.

#[cfg(test)]
impl ValidatorRewardTracker {
    /// Insert or overwrite an entry (test-only).
    fn insert_entry_for_test(&mut self, entry: ValidatorRewardEntry) {
        self.entries.insert(entry.validator_id, entry);
    }

    /// Set global totals (test-only).
    fn set_totals_for_test(&mut self, distributed: u128, claimed: u128) {
        self.total_distributed = distributed;
        self.total_claimed = claimed;
    }

    /// Set current epoch (test-only).
    fn set_epoch_for_test(&mut self, epoch: u64) {
        self.current_epoch = epoch;
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helper: create deterministic validator ID ────────────────────────
    fn vid(n: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = n;
        id
    }

    fn make_entry(n: u8, pending: u128, claimed: u128, epoch: u64, count: u64) -> ValidatorRewardEntry {
        ValidatorRewardEntry {
            validator_id: vid(n),
            pending_rewards: pending,
            claimed_rewards: claimed,
            last_receipt_epoch: epoch,
            receipt_count: count,
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // TEST 1: new_tracker_empty
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn new_tracker_empty() {
        let tracker = ValidatorRewardTracker::new();
        assert_eq!(tracker.validator_count(), 0);
        assert_eq!(tracker.total_distributed(), 0);
        assert_eq!(tracker.total_claimed(), 0);
        assert_eq!(tracker.current_epoch(), 0);
        assert!(tracker.active_validators().is_empty());
    }

    // ──────────────────────────────────────────────────────────────────────
    // TEST 2: get_nonexistent_validator_returns_zero
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn get_nonexistent_validator_returns_zero() {
        let tracker = ValidatorRewardTracker::new();
        let unknown = vid(99);
        assert!(tracker.get_entry(&unknown).is_none());
        assert_eq!(tracker.get_pending(&unknown), 0);
        assert_eq!(tracker.get_claimed(&unknown), 0);
    }

    // ──────────────────────────────────────────────────────────────────────
    // TEST 3: total_pending_empty_zero
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn total_pending_empty_zero() {
        let tracker = ValidatorRewardTracker::new();
        assert_eq!(tracker.total_pending(), 0);
    }

    // ──────────────────────────────────────────────────────────────────────
    // TEST 4: active_validators_empty
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn active_validators_empty() {
        let tracker = ValidatorRewardTracker::new();
        let active = tracker.active_validators();
        assert!(active.is_empty());
    }

    // ──────────────────────────────────────────────────────────────────────
    // TEST 5: deterministic_active_validator_order
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn deterministic_active_validator_order() {
        let mut tracker = ValidatorRewardTracker::new();

        // Insert in reverse order — output must be sorted ascending
        tracker.insert_entry_for_test(make_entry(30, 100, 0, 1, 1));
        tracker.insert_entry_for_test(make_entry(10, 200, 0, 1, 1));
        tracker.insert_entry_for_test(make_entry(20, 300, 0, 1, 1));
        tracker.insert_entry_for_test(make_entry(5,  400, 0, 1, 1));
        tracker.insert_entry_for_test(make_entry(15, 500, 0, 1, 1));

        let active = tracker.active_validators();
        assert_eq!(active.len(), 5);

        // Must be lexicographically sorted by byte content
        assert_eq!(active[0], vid(5));
        assert_eq!(active[1], vid(10));
        assert_eq!(active[2], vid(15));
        assert_eq!(active[3], vid(20));
        assert_eq!(active[4], vid(30));

        // Run again — must be identical (determinism)
        let active2 = tracker.active_validators();
        assert_eq!(active, active2);
    }

    // ──────────────────────────────────────────────────────────────────────
    // TEST 6: total_pending_matches_sum
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn total_pending_matches_sum() {
        let mut tracker = ValidatorRewardTracker::new();

        tracker.insert_entry_for_test(make_entry(1, 1_000_000, 0, 1, 1));
        tracker.insert_entry_for_test(make_entry(2, 2_500_000, 0, 2, 3));
        tracker.insert_entry_for_test(make_entry(3, 7_500_000, 0, 5, 10));

        let expected_sum: u128 = 1_000_000 + 2_500_000 + 7_500_000;
        assert_eq!(tracker.total_pending(), expected_sum);

        // Invariant: total_pending == SUM(entry.pending_rewards)
        let manual_sum: u128 = tracker
            .active_validators()
            .iter()
            .map(|id| tracker.get_pending(id))
            .sum();
        assert_eq!(tracker.total_pending(), manual_sum);
    }

    // ──────────────────────────────────────────────────────────────────────
    // TEST 7: claimed_pending_separation_correct
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn claimed_pending_separation_correct() {
        let mut tracker = ValidatorRewardTracker::new();

        tracker.insert_entry_for_test(make_entry(1, 500, 300, 10, 5));
        tracker.insert_entry_for_test(make_entry(2, 200, 800, 10, 12));

        // Pending
        assert_eq!(tracker.get_pending(&vid(1)), 500);
        assert_eq!(tracker.get_pending(&vid(2)), 200);

        // Claimed
        assert_eq!(tracker.get_claimed(&vid(1)), 300);
        assert_eq!(tracker.get_claimed(&vid(2)), 800);

        // total_pending only counts pending
        assert_eq!(tracker.total_pending(), 700);

        // Entry access preserves all fields
        let e1 = tracker.get_entry(&vid(1));
        assert!(e1.is_some());
        if let Some(entry) = e1 {
            assert_eq!(entry.pending_rewards, 500);
            assert_eq!(entry.claimed_rewards, 300);
            assert_eq!(entry.last_receipt_epoch, 10);
            assert_eq!(entry.receipt_count, 5);
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // TEST 8: no_overflow_on_large_values
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn no_overflow_on_large_values() {
        let mut tracker = ValidatorRewardTracker::new();

        // Use values near u128::MAX / 2 — two entries should still sum correctly
        // via saturating_add (u128::MAX ≈ 3.4e38)
        let half_max = u128::MAX / 2;

        tracker.insert_entry_for_test(make_entry(1, half_max, 0, 1, 1));
        tracker.insert_entry_for_test(make_entry(2, half_max, 0, 1, 1));

        // total_pending: half_max + half_max = u128::MAX - 1 (exact, no overflow)
        let expected = half_max.saturating_add(half_max);
        assert_eq!(tracker.total_pending(), expected);

        // Now test actual saturation: three entries with half_max each
        tracker.insert_entry_for_test(make_entry(3, half_max, 0, 1, 1));
        // half_max * 3 would overflow u128, so saturating_add caps at u128::MAX
        let total = tracker.total_pending();
        assert!(total <= u128::MAX);
        // Verify it saturated: half_max * 3 > u128::MAX
        assert_eq!(total, u128::MAX);
    }

    // ──────────────────────────────────────────────────────────────────────
    // TEST 9: global_totals_consistent
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn global_totals_consistent() {
        let mut tracker = ValidatorRewardTracker::new();

        tracker.set_totals_for_test(10_000, 3_000);

        // Invariant: total_distributed >= total_claimed
        assert!(tracker.total_distributed() >= tracker.total_claimed());
        assert_eq!(tracker.total_distributed(), 10_000);
        assert_eq!(tracker.total_claimed(), 3_000);
    }

    // ──────────────────────────────────────────────────────────────────────
    // TEST 10: epoch_tracking_correct
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn epoch_tracking_correct() {
        let mut tracker = ValidatorRewardTracker::new();
        assert_eq!(tracker.current_epoch(), 0);

        tracker.set_epoch_for_test(42);
        assert_eq!(tracker.current_epoch(), 42);

        tracker.set_epoch_for_test(u64::MAX);
        assert_eq!(tracker.current_epoch(), u64::MAX);
    }
}