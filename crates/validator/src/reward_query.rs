//! # Reward Query Interface (14C.C.13)
//!
//! Pure read-only query functions for validator reward state.
//!
//! ## Free Functions (contract-required signatures)
//!
//! | Function | Description |
//! |----------|-------------|
//! | `query_validator_rewards` | Single validator summary with `total_earned = pending + claimed` |
//! | `query_all_validators` | All validators sorted lexicographically by ID |
//! | `query_epoch_summary` | Per-epoch reward summary lookup (requires engine for data) |
//! | `query_distribution_history` | Distribution history with limit (requires engine for data) |
//!
//! ## RewardQueryEngine
//!
//! Full-featured query engine combining `ValidatorRewardTracker` access with
//! epoch summaries and distribution history storage. All methods are pure reads.
//!
//! ## Invariants
//!
//! 1. All functions are pure read-only — no state mutation.
//! 2. Deterministic output ordering (lexicographic for validators, descending epoch for history).
//! 3. Overflow-safe: `total_earned` uses `checked_add`; entries that overflow are skipped.
//! 4. No panic, no unwrap, no expect.

use std::collections::HashMap;
use crate::reward_tracker::ValidatorRewardTracker;
use crate::finalization_gate::EpochRewardSummary;

// ════════════════════════════════════════════════════════════════════════════════
// QUERY TYPES
// ════════════════════════════════════════════════════════════════════════════════

/// Summary view of a single validator's reward state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorRewardSummary {
    /// 32-byte validator identifier.
    pub validator_id: [u8; 32],
    /// Rewards distributed but not yet claimed.
    pub pending_rewards: u128,
    /// Rewards already claimed.
    pub claimed_rewards: u128,
    /// `pending_rewards + claimed_rewards` (checked).
    pub total_earned: u128,
    /// Number of individual reward receipts.
    pub receipt_count: u64,
    /// Epoch of the most recent distribution to this validator.
    pub last_distribution_epoch: u64,
}

/// A single entry in a validator's distribution history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewardHistoryEntry {
    /// Epoch in which this distribution occurred.
    pub epoch: u64,
    /// Hash identifying the specific receipt.
    pub receipt_hash: [u8; 32],
    /// Amount distributed.
    pub amount: u128,
    /// Timestamp of the distribution (chain time, not wall clock).
    pub timestamp: u64,
}

// ════════════════════════════════════════════════════════════════════════════════
// FREE FUNCTIONS — Contract-required signatures
// ════════════════════════════════════════════════════════════════════════════════

/// Query a single validator's reward summary.
///
/// Returns `None` if the validator is not tracked or if the
/// `total_earned` computation would overflow `u128`.
///
/// Pure read-only — no state mutation.
pub fn query_validator_rewards(
    tracker: &ValidatorRewardTracker,
    validator_id: &[u8; 32],
) -> Option<ValidatorRewardSummary> {
    let entry = tracker.get_entry(validator_id)?;
    let total_earned = entry.pending_rewards.checked_add(entry.claimed_rewards)?;
    Some(ValidatorRewardSummary {
        validator_id: entry.validator_id,
        pending_rewards: entry.pending_rewards,
        claimed_rewards: entry.claimed_rewards,
        total_earned,
        receipt_count: entry.receipt_count,
        last_distribution_epoch: entry.last_receipt_epoch,
    })
}

/// Query all tracked validators, sorted lexicographically by ID.
///
/// Validators whose `total_earned` would overflow `u128` are silently
/// excluded from the result (not panicked).
///
/// Output order is deterministic regardless of internal `HashMap` ordering.
pub fn query_all_validators(
    tracker: &ValidatorRewardTracker,
) -> Vec<ValidatorRewardSummary> {
    let ids = tracker.active_validators(); // already sorted lexicographically
    let mut result = Vec::with_capacity(ids.len());
    for id in &ids {
        if let Some(summary) = query_validator_rewards(tracker, id) {
            result.push(summary);
        }
    }
    result
}

/// Look up per-epoch reward summary.
///
/// The `ValidatorRewardTracker` does not store per-epoch summaries internally.
/// This function always returns `None` when called against the bare tracker.
/// For full epoch query support, use [`RewardQueryEngine::query_epoch_summary`].
pub fn query_epoch_summary(
    _tracker: &ValidatorRewardTracker,
    _epoch: u64,
) -> Option<EpochRewardSummary> {
    // The tracker does not store per-epoch summaries.
    // Use RewardQueryEngine::query_epoch_summary for full support.
    None
}

/// Query distribution history for a validator with a limit.
///
/// The `ValidatorRewardTracker` does not store distribution history internally.
/// This function always returns an empty `Vec` when called against the bare tracker.
/// For full history support, use [`RewardQueryEngine::query_distribution_history`].
pub fn query_distribution_history(
    _tracker: &ValidatorRewardTracker,
    _validator_id: &[u8; 32],
    _limit: usize,
) -> Vec<RewardHistoryEntry> {
    // The tracker does not store distribution history.
    // Use RewardQueryEngine::query_distribution_history for full support.
    Vec::new()
}

// ════════════════════════════════════════════════════════════════════════════════
// REWARD QUERY ENGINE
// ════════════════════════════════════════════════════════════════════════════════

/// Full-featured read-only query engine combining the reward tracker
/// with epoch summaries and distribution history.
///
/// All methods are pure reads — no tracker state is mutated.
#[derive(Debug, Clone)]
pub struct RewardQueryEngine {
    /// Per-epoch reward summaries (from `EpochAccounting` or equivalent).
    epoch_summaries: HashMap<u64, EpochRewardSummary>,
    /// Per-validator distribution history, keyed by validator ID.
    distribution_history: HashMap<[u8; 32], Vec<RewardHistoryEntry>>,
}

impl RewardQueryEngine {
    /// Create an empty query engine.
    pub fn new() -> Self {
        Self {
            epoch_summaries: HashMap::new(),
            distribution_history: HashMap::new(),
        }
    }

    /// Register an epoch summary (typically populated from `EpochAccounting`).
    pub fn insert_epoch_summary(&mut self, summary: EpochRewardSummary) {
        self.epoch_summaries.insert(summary.epoch, summary);
    }

    /// Append a distribution history entry for a validator.
    pub fn append_history(&mut self, validator_id: [u8; 32], entry: RewardHistoryEntry) {
        self.distribution_history
            .entry(validator_id)
            .or_default()
            .push(entry);
    }

    // ── Delegating query methods (validator rewards) ────────────────────

    /// Query a single validator's reward summary (delegates to free function).
    pub fn query_validator_rewards(
        &self,
        tracker: &ValidatorRewardTracker,
        validator_id: &[u8; 32],
    ) -> Option<ValidatorRewardSummary> {
        query_validator_rewards(tracker, validator_id)
    }

    /// Query all validators (delegates to free function).
    pub fn query_all_validators(
        &self,
        tracker: &ValidatorRewardTracker,
    ) -> Vec<ValidatorRewardSummary> {
        query_all_validators(tracker)
    }

    // ── Epoch and history query methods ─────────────────────────────────

    /// Look up per-epoch reward summary.
    ///
    /// Returns `None` if the epoch has no recorded summary.
    pub fn query_epoch_summary(&self, epoch: u64) -> Option<&EpochRewardSummary> {
        self.epoch_summaries.get(&epoch)
    }

    /// Query distribution history for a validator with a limit.
    ///
    /// Returns at most `limit` entries sorted descending by epoch
    /// (most recent first). Entries within the same epoch are sub-sorted
    /// descending by timestamp.
    ///
    /// If `limit == 0`, returns an empty `Vec`.
    /// If validator has no history, returns an empty `Vec`.
    pub fn query_distribution_history(
        &self,
        validator_id: &[u8; 32],
        limit: usize,
    ) -> Vec<RewardHistoryEntry> {
        if limit == 0 {
            return Vec::new();
        }
        let entries = match self.distribution_history.get(validator_id) {
            Some(v) => v,
            None => return Vec::new(),
        };
        let mut sorted: Vec<RewardHistoryEntry> = entries.clone();
        sorted.sort_by(|a, b| {
            b.epoch.cmp(&a.epoch).then_with(|| b.timestamp.cmp(&a.timestamp))
        });
        sorted.truncate(limit);
        sorted
    }
}

impl Default for RewardQueryEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS (16 tests ≥ 12 required)
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reward_tracker::ClaimRequest;

    // ── Helpers ──────────────────────────────────────────────────────────

    fn vid(n: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = n;
        id
    }

    fn rhash(n: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[31] = n;
        h
    }

    /// Create a tracker with validators having both pending and claimed.
    ///
    /// Each tuple: `(validator_n, pending, claimed)`.
    /// Uses `add_pending_reward` (pub(crate)) then `claim_reward` (pub).
    fn make_tracker(entries: &[(u8, u128, u128)]) -> ValidatorRewardTracker {
        let mut t = ValidatorRewardTracker::new();
        for &(n, pending, claimed) in entries {
            let total = match pending.checked_add(claimed) {
                Some(v) if v > 0 => v,
                _ => continue,
            };
            if t.add_pending_reward(vid(n), total, 0).is_err() {
                continue;
            }
            if claimed > 0 {
                let _ = t.claim_reward(ClaimRequest {
                    validator_id: vid(n),
                    amount: Some(claimed),
                    claim_epoch: 0,
                });
            }
        }
        t
    }

    // ── 1. query_single_validator_exists ─────────────────────────────────

    #[test]
    fn query_single_validator_exists() {
        let t = make_tracker(&[(1, 500, 300)]);
        let result = query_validator_rewards(&t, &vid(1));
        assert!(result.is_some());
        if let Some(s) = result {
            assert_eq!(s.validator_id, vid(1));
            assert_eq!(s.pending_rewards, 500);
            assert_eq!(s.claimed_rewards, 300);
            assert_eq!(s.total_earned, 800);
            assert_eq!(s.receipt_count, 1);
            assert_eq!(s.last_distribution_epoch, 0);
        }
    }

    // ── 2. query_single_validator_not_found ──────────────────────────────

    #[test]
    fn query_single_validator_not_found() {
        let t = make_tracker(&[(1, 100, 0)]);
        let result = query_validator_rewards(&t, &vid(99));
        assert!(result.is_none());
    }

    // ── 3. total_earned_correct ──────────────────────────────────────────

    #[test]
    fn total_earned_correct() {
        let t = make_tracker(&[(1, 1_000_000, 2_500_000)]);
        let s = query_validator_rewards(&t, &vid(1));
        assert!(s.is_some());
        if let Some(s) = s {
            assert_eq!(s.total_earned, 3_500_000);
            assert_eq!(s.total_earned, s.pending_rewards + s.claimed_rewards);
        }
    }

    // ── 4. total_earned_no_overflow ──────────────────────────────────────

    #[test]
    fn total_earned_no_overflow() {
        // pending=1, claimed=u128::MAX → checked_add overflows → None
        let mut t = ValidatorRewardTracker::new();
        let _ = t.add_pending_reward(vid(1), u128::MAX, 0);
        let _ = t.claim_reward(ClaimRequest {
            validator_id: vid(1),
            amount: None, // claim all → pending=0, claimed=u128::MAX
            claim_epoch: 0,
        });
        let _ = t.add_pending_reward(vid(1), 1, 0); // pending=1, claimed=u128::MAX
        let result = query_validator_rewards(&t, &vid(1));
        assert!(result.is_none(), "expected None due to overflow");
    }

    // ── 5. query_all_sorted ──────────────────────────────────────────────

    #[test]
    fn query_all_sorted() {
        let t = make_tracker(&[
            (30, 300, 0),
            (10, 100, 0),
            (20, 200, 0),
        ]);
        let all = query_all_validators(&t);
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].validator_id, vid(10));
        assert_eq!(all[1].validator_id, vid(20));
        assert_eq!(all[2].validator_id, vid(30));
        // Deterministic: repeat identical
        let all2 = query_all_validators(&t);
        assert_eq!(all, all2);
    }

    // ── 6. query_all_empty ───────────────────────────────────────────────

    #[test]
    fn query_all_empty() {
        let t = ValidatorRewardTracker::new();
        let all = query_all_validators(&t);
        assert!(all.is_empty());
    }

    // ── 7. query_epoch_summary_exists ────────────────────────────────────

    #[test]
    fn query_epoch_summary_exists() {
        let mut engine = RewardQueryEngine::new();
        engine.insert_epoch_summary(EpochRewardSummary {
            epoch: 5,
            receipts_finalized: 10,
            total_validator_reward: 5000,
            distribution_count: 3,
        });
        let result = engine.query_epoch_summary(5);
        assert!(result.is_some());
        if let Some(s) = result {
            assert_eq!(s.epoch, 5);
            assert_eq!(s.receipts_finalized, 10);
            assert_eq!(s.total_validator_reward, 5000);
            assert_eq!(s.distribution_count, 3);
        }
    }

    // ── 8. query_epoch_summary_not_found ─────────────────────────────────

    #[test]
    fn query_epoch_summary_not_found() {
        let engine = RewardQueryEngine::new();
        assert!(engine.query_epoch_summary(999).is_none());
        // Free function: tracker has no epoch data → always None
        let t = ValidatorRewardTracker::new();
        assert!(query_epoch_summary(&t, 999).is_none());
    }

    // ── 9. query_history_limit_respected ─────────────────────────────────

    #[test]
    fn query_history_limit_respected() {
        let mut engine = RewardQueryEngine::new();
        for i in 1..=10u64 {
            engine.append_history(vid(1), RewardHistoryEntry {
                epoch: i,
                receipt_hash: rhash(i as u8),
                amount: i as u128 * 100,
                timestamp: i * 1000,
            });
        }
        let result = engine.query_distribution_history(&vid(1), 3);
        assert_eq!(result.len(), 3);
        let result_all = engine.query_distribution_history(&vid(1), 100);
        assert_eq!(result_all.len(), 10);
    }

    // ── 10. query_history_zero_limit ─────────────────────────────────────

    #[test]
    fn query_history_zero_limit() {
        let mut engine = RewardQueryEngine::new();
        engine.append_history(vid(1), RewardHistoryEntry {
            epoch: 1, receipt_hash: rhash(1), amount: 100, timestamp: 1000,
        });
        let result = engine.query_distribution_history(&vid(1), 0);
        assert!(result.is_empty());
    }

    // ── 11. history_sorted_descending ────────────────────────────────────

    #[test]
    fn history_sorted_descending() {
        let mut engine = RewardQueryEngine::new();
        engine.append_history(vid(1), RewardHistoryEntry {
            epoch: 3, receipt_hash: rhash(3), amount: 300, timestamp: 3000,
        });
        engine.append_history(vid(1), RewardHistoryEntry {
            epoch: 1, receipt_hash: rhash(1), amount: 100, timestamp: 1000,
        });
        engine.append_history(vid(1), RewardHistoryEntry {
            epoch: 5, receipt_hash: rhash(5), amount: 500, timestamp: 5000,
        });
        engine.append_history(vid(1), RewardHistoryEntry {
            epoch: 2, receipt_hash: rhash(2), amount: 200, timestamp: 2000,
        });
        let result = engine.query_distribution_history(&vid(1), 10);
        assert_eq!(result.len(), 4);
        assert_eq!(result[0].epoch, 5);
        assert_eq!(result[1].epoch, 3);
        assert_eq!(result[2].epoch, 2);
        assert_eq!(result[3].epoch, 1);
    }

    // ── 12. no_mutation_after_query ──────────────────────────────────────

    #[test]
    fn no_mutation_after_query() {
        let t = make_tracker(&[(1, 500, 300)]);
        let pending_before = t.get_pending(&vid(1));
        let claimed_before = t.get_claimed(&vid(1));
        let dist_before = t.total_distributed();
        let claimed_total_before = t.total_claimed();
        let count_before = t.validator_count();

        let _ = query_validator_rewards(&t, &vid(1));
        let _ = query_all_validators(&t);
        let _ = query_epoch_summary(&t, 0);
        let _ = query_distribution_history(&t, &vid(1), 10);

        assert_eq!(t.get_pending(&vid(1)), pending_before);
        assert_eq!(t.get_claimed(&vid(1)), claimed_before);
        assert_eq!(t.total_distributed(), dist_before);
        assert_eq!(t.total_claimed(), claimed_total_before);
        assert_eq!(t.validator_count(), count_before);
    }

    // ── 13. query_all_skips_overflow_entries ──────────────────────────────

    #[test]
    fn query_all_skips_overflow_entries() {
        let mut t = ValidatorRewardTracker::new();
        // vid(2): normal entry
        let _ = t.add_pending_reward(vid(2), 500, 0);
        // vid(1): overflow setup (pending=1, claimed=u128::MAX)
        let _ = t.add_pending_reward(vid(1), u128::MAX, 0);
        let _ = t.claim_reward(ClaimRequest {
            validator_id: vid(1),
            amount: None,
            claim_epoch: 0,
        });
        let _ = t.add_pending_reward(vid(1), 1, 0);

        let all = query_all_validators(&t);
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].validator_id, vid(2));
        assert_eq!(all[0].total_earned, 500);
    }

    // ── 14. history_empty_validator ──────────────────────────────────────

    #[test]
    fn history_empty_validator() {
        let engine = RewardQueryEngine::new();
        let result = engine.query_distribution_history(&vid(99), 10);
        assert!(result.is_empty());
    }

    // ── 15. engine_delegates_correctly ───────────────────────────────────

    #[test]
    fn engine_delegates_correctly() {
        let t = make_tracker(&[(1, 1000, 500)]);
        let engine = RewardQueryEngine::new();
        let direct = query_validator_rewards(&t, &vid(1));
        let via_engine = engine.query_validator_rewards(&t, &vid(1));
        assert_eq!(direct, via_engine);
        let direct_all = query_all_validators(&t);
        let via_engine_all = engine.query_all_validators(&t);
        assert_eq!(direct_all, via_engine_all);
    }

    // ── 16. history_same_epoch_sub_sorted_by_timestamp ───────────────────

    #[test]
    fn history_same_epoch_sub_sorted_by_timestamp() {
        let mut engine = RewardQueryEngine::new();
        engine.append_history(vid(1), RewardHistoryEntry {
            epoch: 5, receipt_hash: rhash(1), amount: 100, timestamp: 1000,
        });
        engine.append_history(vid(1), RewardHistoryEntry {
            epoch: 5, receipt_hash: rhash(2), amount: 200, timestamp: 3000,
        });
        engine.append_history(vid(1), RewardHistoryEntry {
            epoch: 5, receipt_hash: rhash(3), amount: 300, timestamp: 2000,
        });
        let result = engine.query_distribution_history(&vid(1), 10);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].timestamp, 3000);
        assert_eq!(result[1].timestamp, 2000);
        assert_eq!(result[2].timestamp, 1000);
    }
}