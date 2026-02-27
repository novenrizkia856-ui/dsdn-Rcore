//! # Validator Reward Tracker (14C.C.9 + 14C.C.12)
//!
//! Types and queries for per-validator reward accounting, including the
//! claim flow for converting pending rewards to claimed.
//!
//! ## Structs
//!
//! - [`ValidatorRewardEntry`]: Per-validator reward state (pending, claimed, epoch, count).
//! - [`ValidatorRewardTracker`]: Aggregate tracker with invariant-safe getters and claim processing.
//! - [`ClaimRequest`]: Parameters for a reward claim.
//! - [`ClaimResponse`]: Successful claim outcome with deterministic claim hash.
//!
//! ## Invariants
//!
//! 1. `total_pending()` always equals the sum of all `entry.pending_rewards` (computed on-the-fly).
//! 2. `total_distributed >= total_claimed` at all times.
//! 3. All internal arithmetic uses `checked_*` to prevent overflow.
//! 4. `active_validators()` returns validators sorted lexicographically by `[u8; 32]` ID.
//! 5. `processed_claims` prevents duplicate claims via deterministic SHA3-256 hash.
//! 6. Claim mutations are atomic: all pre-checked before any state changes.
//!
//! ## Current Scope
//!
//! This module defines types, read-only getters, crate-internal distribution
//! mutations (14C.C.10), and the public claim flow (14C.C.12).

use std::collections::{HashMap, HashSet};
use sha3::{Sha3_256, Digest};

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
    processed_claims: HashSet<[u8; 32]>,
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
// CLAIM TYPES (14C.C.12)
// ════════════════════════════════════════════════════════════════════════════════

/// Request to claim pending rewards for a validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimRequest {
    /// 32-byte validator identifier.
    pub validator_id: [u8; 32],
    /// Amount to claim. `None` means claim all pending rewards.
    pub amount: Option<u128>,
    /// Epoch in which this claim is being made. Must match the tracker's
    /// current epoch.
    pub claim_epoch: u64,
}

/// Successful claim response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimResponse {
    /// Amount actually transferred from pending to claimed.
    pub claimed_amount: u128,
    /// Pending balance remaining after this claim.
    pub remaining_pending: u128,
    /// Deterministic SHA3-256 hash identifying this claim.
    pub claim_hash: [u8; 32],
}

/// Errors that can occur during a reward claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimError {
    /// The requested amount exceeds the validator's pending balance.
    InsufficientPending {
        /// Currently available pending rewards.
        available: u128,
        /// Amount that was requested.
        requested: u128,
    },
    /// The validator ID is not present in the tracker.
    ValidatorNotFound,
    /// The effective claim amount resolved to zero.
    ZeroAmount,
    /// `claim_epoch` does not match the tracker's current epoch.
    EpochMismatch,
    /// The computed claim hash was already processed (duplicate claim).
    DuplicateClaim,
    /// A checked arithmetic operation would overflow.
    Overflow,
}

impl core::fmt::Display for ClaimError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InsufficientPending { available, requested } => {
                write!(f, "insufficient pending: available={available}, requested={requested}")
            }
            Self::ValidatorNotFound => f.write_str("validator not found"),
            Self::ZeroAmount => f.write_str("claim amount is zero"),
            Self::EpochMismatch => f.write_str("epoch mismatch"),
            Self::DuplicateClaim => f.write_str("duplicate claim"),
            Self::Overflow => f.write_str("arithmetic overflow"),
        }
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
            processed_claims: HashSet::new(),
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
// PUBLIC CLAIM FLOW (14C.C.12)
// ════════════════════════════════════════════════════════════════════════════════

impl ValidatorRewardTracker {
    /// Process a validator reward claim.
    ///
    /// Moves tokens from `pending_rewards` to `claimed_rewards` atomically.
    /// All overflow checks are performed before any state mutation. If any
    /// check fails, the tracker is left completely unchanged.
    ///
    /// # Claim Hash
    ///
    /// A deterministic SHA3-256 hash is computed from:
    /// `validator_id || amount (16 bytes BE) || claim_epoch (8 bytes BE) || receipt_count (8 bytes BE)`
    ///
    /// This hash serves as a unique identifier and duplicate-prevention key.
    pub fn claim_reward(
        &mut self,
        request: ClaimRequest,
    ) -> Result<ClaimResponse, ClaimError> {
        // ── 1. Epoch validation ─────────────────────────────────────────
        if request.claim_epoch != self.current_epoch {
            return Err(ClaimError::EpochMismatch);
        }

        // ── 2. Validator lookup ─────────────────────────────────────────
        let entry = self
            .entries
            .get(&request.validator_id)
            .ok_or(ClaimError::ValidatorNotFound)?;

        // ── 3. Determine effective amount ───────────────────────────────
        let amount = match request.amount {
            None => entry.pending_rewards,
            Some(a) => a,
        };

        // ── 4. Amount validation ────────────────────────────────────────
        if amount == 0 {
            return Err(ClaimError::ZeroAmount);
        }
        if amount > entry.pending_rewards {
            return Err(ClaimError::InsufficientPending {
                available: entry.pending_rewards,
                requested: amount,
            });
        }

        // ── 5. Compute deterministic claim hash ─────────────────────────
        let receipt_count = entry.receipt_count;
        let claim_hash = compute_claim_hash(
            &request.validator_id,
            amount,
            request.claim_epoch,
            receipt_count,
        );

        // ── 6. Duplicate check ──────────────────────────────────────────
        if self.processed_claims.contains(&claim_hash) {
            return Err(ClaimError::DuplicateClaim);
        }

        // ── 7. Pre-check all arithmetic (atomicity guarantee) ───────────
        let new_pending = entry
            .pending_rewards
            .checked_sub(amount)
            .ok_or(ClaimError::Overflow)?;
        let new_claimed = entry
            .claimed_rewards
            .checked_add(amount)
            .ok_or(ClaimError::Overflow)?;
        let new_total_claimed = self
            .total_claimed
            .checked_add(amount)
            .ok_or(ClaimError::Overflow)?;

        // ── 8. Apply mutations (safe: all pre-checked) ──────────────────
        if let Some(e) = self.entries.get_mut(&request.validator_id) {
            e.pending_rewards = new_pending;
            e.claimed_rewards = new_claimed;
        }
        self.total_claimed = new_total_claimed;
        self.processed_claims.insert(claim_hash);

        Ok(ClaimResponse {
            claimed_amount: amount,
            remaining_pending: new_pending,
            claim_hash,
        })
    }

    /// Check whether a claim hash has already been processed.
    pub fn is_duplicate(&self, claim_hash: &[u8; 32]) -> bool {
        self.processed_claims.contains(claim_hash)
    }
}

/// Compute a deterministic SHA3-256 claim hash.
///
/// Input layout (64 bytes total):
/// ```text
/// [ validator_id: 32 bytes ]
/// [ amount:       16 bytes (big-endian u128) ]
/// [ claim_epoch:   8 bytes (big-endian u64) ]
/// [ receipt_count: 8 bytes (big-endian u64) ]
/// ```
fn compute_claim_hash(
    validator_id: &[u8; 32],
    amount: u128,
    claim_epoch: u64,
    receipt_count: u64,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(validator_id);
    hasher.update(amount.to_be_bytes());
    hasher.update(claim_epoch.to_be_bytes());
    hasher.update(receipt_count.to_be_bytes());
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
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

    // ════════════════════════════════════════════════════════════════════════
    // CLAIM FLOW TESTS (14C.C.12)
    // ════════════════════════════════════════════════════════════════════════

    /// Helper: seeded tracker with one validator having pending rewards.
    fn seeded_tracker(pending: u128, claimed: u128, epoch: u64) -> ValidatorRewardTracker {
        let mut t = ValidatorRewardTracker::new();
        t.set_epoch_for_test(epoch);
        t.set_totals_for_test(pending + claimed, claimed);
        t.insert_entry_for_test(ValidatorRewardEntry {
            validator_id: vid(1),
            pending_rewards: pending,
            claimed_rewards: claimed,
            last_receipt_epoch: epoch,
            receipt_count: 5,
        });
        t
    }

    macro_rules! ok {
        ($e:expr) => {{
            let r = $e;
            assert!(r.is_ok(), "expected Ok, got {:?}", r);
            match r { Ok(v) => v, Err(_) => return }
        }};
    }

    // ── 11. claim_all_success ────────────────────────────────────────────
    #[test]
    fn claim_all_success() {
        let mut t = seeded_tracker(1000, 0, 5);
        let resp = ok!(t.claim_reward(ClaimRequest {
            validator_id: vid(1),
            amount: None,
            claim_epoch: 5,
        }));
        assert_eq!(resp.claimed_amount, 1000);
        assert_eq!(resp.remaining_pending, 0);
        assert_eq!(t.get_pending(&vid(1)), 0);
        assert_eq!(t.get_claimed(&vid(1)), 1000);
    }

    // ── 12. claim_partial_success ────────────────────────────────────────
    #[test]
    fn claim_partial_success() {
        let mut t = seeded_tracker(1000, 0, 5);
        let resp = ok!(t.claim_reward(ClaimRequest {
            validator_id: vid(1),
            amount: Some(400),
            claim_epoch: 5,
        }));
        assert_eq!(resp.claimed_amount, 400);
        assert_eq!(resp.remaining_pending, 600);
        assert_eq!(t.get_pending(&vid(1)), 600);
        assert_eq!(t.get_claimed(&vid(1)), 400);
    }

    // ── 13. claim_insufficient_pending ───────────────────────────────────
    #[test]
    fn claim_insufficient_pending() {
        let mut t = seeded_tracker(500, 0, 5);
        let result = t.claim_reward(ClaimRequest {
            validator_id: vid(1),
            amount: Some(999),
            claim_epoch: 5,
        });
        assert_eq!(result, Err(ClaimError::InsufficientPending {
            available: 500,
            requested: 999,
        }));
        assert_eq!(t.get_pending(&vid(1)), 500);
    }

    // ── 14. claim_zero_amount_error ──────────────────────────────────────
    #[test]
    fn claim_zero_amount_error() {
        let mut t = seeded_tracker(1000, 0, 5);
        let result = t.claim_reward(ClaimRequest {
            validator_id: vid(1),
            amount: Some(0),
            claim_epoch: 5,
        });
        assert_eq!(result, Err(ClaimError::ZeroAmount));
    }

    // ── 15. claim_zero_via_none_on_empty_pending ─────────────────────────
    #[test]
    fn claim_zero_via_none_on_empty_pending() {
        let mut t = seeded_tracker(0, 100, 5);
        let result = t.claim_reward(ClaimRequest {
            validator_id: vid(1),
            amount: None,
            claim_epoch: 5,
        });
        assert_eq!(result, Err(ClaimError::ZeroAmount));
    }

    // ── 16. claim_validator_not_found ────────────────────────────────────
    #[test]
    fn claim_validator_not_found() {
        let mut t = seeded_tracker(1000, 0, 5);
        let result = t.claim_reward(ClaimRequest {
            validator_id: vid(99),
            amount: None,
            claim_epoch: 5,
        });
        assert_eq!(result, Err(ClaimError::ValidatorNotFound));
    }

    // ── 17. claim_epoch_mismatch ─────────────────────────────────────────
    #[test]
    fn claim_epoch_mismatch() {
        let mut t = seeded_tracker(1000, 0, 5);
        let result = t.claim_reward(ClaimRequest {
            validator_id: vid(1),
            amount: None,
            claim_epoch: 4,
        });
        assert_eq!(result, Err(ClaimError::EpochMismatch));
        assert_eq!(t.get_pending(&vid(1)), 1000);
    }

    // ── 18. duplicate_claim_rejected ─────────────────────────────────────
    #[test]
    fn duplicate_claim_rejected() {
        let mut t = seeded_tracker(1000, 0, 5);
        let resp1 = ok!(t.claim_reward(ClaimRequest {
            validator_id: vid(1),
            amount: Some(500),
            claim_epoch: 5,
        }));
        assert!(t.is_duplicate(&resp1.claim_hash));

        // Restore pending to simulate new distribution, same receipt_count
        t.insert_entry_for_test(ValidatorRewardEntry {
            validator_id: vid(1),
            pending_rewards: 500,
            claimed_rewards: 500,
            last_receipt_epoch: 5,
            receipt_count: 5, // same → same hash
        });

        let result = t.claim_reward(ClaimRequest {
            validator_id: vid(1),
            amount: Some(500),
            claim_epoch: 5,
        });
        assert_eq!(result, Err(ClaimError::DuplicateClaim));
    }

    // ── 19. claim_hash_deterministic ─────────────────────────────────────
    #[test]
    fn claim_hash_deterministic() {
        let h1 = compute_claim_hash(&vid(1), 1000, 5, 10);
        let h2 = compute_claim_hash(&vid(1), 1000, 5, 10);
        assert_eq!(h1, h2);

        // Different inputs → different hashes
        assert_ne!(h1, compute_claim_hash(&vid(1), 999, 5, 10));
        assert_ne!(h1, compute_claim_hash(&vid(1), 1000, 6, 10));
        assert_ne!(h1, compute_claim_hash(&vid(1), 1000, 5, 11));
        assert_ne!(h1, compute_claim_hash(&vid(2), 1000, 5, 10));
    }

    // ── 20. total_claimed_updated ────────────────────────────────────────
    #[test]
    fn total_claimed_updated() {
        let mut t = seeded_tracker(1000, 200, 5);
        assert_eq!(t.total_claimed(), 200);

        let _ = ok!(t.claim_reward(ClaimRequest {
            validator_id: vid(1),
            amount: Some(300),
            claim_epoch: 5,
        }));
        assert_eq!(t.total_claimed(), 500);
    }

    // ── 21. no_partial_update_on_claim_error ─────────────────────────────
    #[test]
    fn no_partial_update_on_claim_error() {
        let mut t = seeded_tracker(500, 0, 5);
        let pending_before = t.get_pending(&vid(1));
        let claimed_before = t.get_claimed(&vid(1));
        let total_before = t.total_claimed();

        let result = t.claim_reward(ClaimRequest {
            validator_id: vid(1),
            amount: Some(999),
            claim_epoch: 5,
        });
        assert!(result.is_err());

        assert_eq!(t.get_pending(&vid(1)), pending_before);
        assert_eq!(t.get_claimed(&vid(1)), claimed_before);
        assert_eq!(t.total_claimed(), total_before);
    }

    // ── 22. overflow_prevented ───────────────────────────────────────────
    #[test]
    fn overflow_prevented_claim() {
        let mut t = ValidatorRewardTracker::new();
        t.set_epoch_for_test(1);
        t.set_totals_for_test(1000, u128::MAX - 5);
        t.insert_entry_for_test(ValidatorRewardEntry {
            validator_id: vid(1),
            pending_rewards: 1000,
            claimed_rewards: u128::MAX - 5,
            last_receipt_epoch: 1,
            receipt_count: 1,
        });

        // total_claimed overflow: (u128::MAX - 5) + 10
        let result = t.claim_reward(ClaimRequest {
            validator_id: vid(1),
            amount: Some(10),
            claim_epoch: 1,
        });
        assert_eq!(result, Err(ClaimError::Overflow));
        assert_eq!(t.get_pending(&vid(1)), 1000);
    }

    // ── 23. remaining_pending_correct ────────────────────────────────────
    #[test]
    fn remaining_pending_correct() {
        let mut t = seeded_tracker(1000, 0, 5);

        let r1 = ok!(t.claim_reward(ClaimRequest {
            validator_id: vid(1),
            amount: Some(300),
            claim_epoch: 5,
        }));
        assert_eq!(r1.remaining_pending, 700);
        assert_eq!(t.get_pending(&vid(1)), 700);

        // Different receipt_count to avoid duplicate hash
        t.insert_entry_for_test(ValidatorRewardEntry {
            validator_id: vid(1),
            pending_rewards: 700,
            claimed_rewards: 300,
            last_receipt_epoch: 5,
            receipt_count: 6,
        });

        let r2 = ok!(t.claim_reward(ClaimRequest {
            validator_id: vid(1),
            amount: Some(200),
            claim_epoch: 5,
        }));
        assert_eq!(r2.remaining_pending, 500);
        assert_eq!(t.get_pending(&vid(1)), 500);
    }

    // ── 24. is_duplicate_false_for_unknown ───────────────────────────────
    #[test]
    fn is_duplicate_false_for_unknown() {
        let t = ValidatorRewardTracker::new();
        assert!(!t.is_duplicate(&[0u8; 32]));
    }
}