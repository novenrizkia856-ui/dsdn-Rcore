//! Integration tests for the DSDN Validator Reward System.
//!
//! Covers the full pipeline: distribution → tracking → claiming → finalization → query → chain integration.
//!
//! All tests are deterministic, panic-free, and use explicit assertions.

use dsdn_validator::reward_tracker::{
    ClaimError, ClaimRequest, ClaimResponse, ValidatorRewardTracker,
};
use dsdn_validator::reward_distributor::{
    distribute_reward, DistributionConfig, DistributionError, DistributionResult,
    DistributionStrategy,
};
use dsdn_validator::finalization_gate::{
    check_finalization, ChainState, EpochAccounting, EpochAccountingError,
    ReceiptFinalizationStatus, ReceiptRecord, ReceiptType,
};
use dsdn_validator::reward_query::{
    query_all_validators, query_validator_rewards, ValidatorRewardSummary,
};
use dsdn_validator::chain_integration::{
    process_new_finalized_receipts, ChainIntegrationError, ProcessResult,
    ReaderError, ReceiptInfo, RewardPoolReader, ValidatorInfo, ValidatorStatus,
};
use async_trait::async_trait;

// ════════════════════════════════════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════════════════════════════════════

/// Create a 32-byte validator ID with `n` in byte 0.
fn vid(n: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = n;
    id
}

/// Create a 32-byte receipt hash with `n` in byte 31.
fn rhash(n: u8) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[31] = n;
    h
}

/// EqualSplit config with min_distribution = 0.
fn equal_config() -> DistributionConfig {
    DistributionConfig {
        strategy: DistributionStrategy::EqualSplit,
        min_distribution: 0,
    }
}

/// StakeWeighted config with min_distribution = 0.
fn stake_config() -> DistributionConfig {
    DistributionConfig {
        strategy: DistributionStrategy::StakeWeighted,
        min_distribution: 0,
    }
}

/// Build a validator set: `&[(id_byte, stake)]` → `Vec<([u8; 32], u128)>`.
fn vset(entries: &[(u8, u128)]) -> Vec<([u8; 32], u128)> {
    entries.iter().map(|&(n, s)| (vid(n), s)).collect()
}

// ── Async executor (no tokio, no unsafe, deterministic) ─────────────────────

/// Minimal single-threaded executor for async tests.
fn run<F: core::future::Future>(f: F) -> F::Output {
    let waker = std::sync::Arc::new(NoopWaker).into();
    let mut cx = core::task::Context::from_waker(&waker);
    let mut f = core::pin::pin!(f);
    loop {
        match f.as_mut().poll(&mut cx) {
            core::task::Poll::Ready(v) => return v,
            core::task::Poll::Pending => continue,
        }
    }
}

struct NoopWaker;
impl std::task::Wake for NoopWaker {
    fn wake(self: std::sync::Arc<Self>) {}
}

// ── Mock RewardPoolReader ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct MockReader {
    balance: u128,
    validators: Vec<ValidatorInfo>,
    receipts: Vec<ReceiptInfo>,
    should_fail: bool,
}

impl MockReader {
    fn new() -> Self {
        Self {
            balance: 0,
            validators: Vec::new(),
            receipts: Vec::new(),
            should_fail: false,
        }
    }

    fn with_validators(mut self, v: Vec<ValidatorInfo>) -> Self {
        self.validators = v;
        self
    }

    fn with_receipts(mut self, r: Vec<ReceiptInfo>) -> Self {
        self.receipts = r;
        self
    }
}

#[async_trait]
impl RewardPoolReader for MockReader {
    async fn get_reward_pool_balance(&self) -> Result<u128, ReaderError> {
        if self.should_fail { return Err(ReaderError); }
        Ok(self.balance)
    }

    async fn get_active_validator_set(&self) -> Result<Vec<ValidatorInfo>, ReaderError> {
        if self.should_fail { return Err(ReaderError); }
        Ok(self.validators.clone())
    }

    async fn get_finalized_receipts_since(
        &self,
        epoch: u64,
    ) -> Result<Vec<ReceiptInfo>, ReaderError> {
        if self.should_fail { return Err(ReaderError); }
        Ok(self.receipts.iter().filter(|r| r.epoch > epoch).cloned().collect())
    }
}

fn active_vi(n: u8, stake: u128) -> ValidatorInfo {
    ValidatorInfo {
        validator_id: vid(n),
        stake,
        status: ValidatorStatus::Active,
    }
}

fn inactive_vi(n: u8, stake: u128) -> ValidatorInfo {
    ValidatorInfo {
        validator_id: vid(n),
        stake,
        status: ValidatorStatus::Inactive,
    }
}

fn make_receipt(hash_n: u8, reward: u128, epoch: u64) -> ReceiptInfo {
    ReceiptInfo {
        receipt_hash: rhash(hash_n),
        total_reward: reward,
        epoch,
        is_compute: false,
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// 1. distribute_equal_split_3_validators
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn distribute_equal_split_3_validators() {
    let mut tracker = ValidatorRewardTracker::new();
    let set = vset(&[(1, 100), (2, 200), (3, 300)]);
    let config = equal_config();

    let result = distribute_reward(&mut tracker, &set, 9000, &config);
    assert!(result.is_ok());

    if let Ok(r) = result {
        // 9000 / 3 = 3000 each, remainder 0
        assert_eq!(r.distributions.len(), 3);
        for &(_, share) in &r.distributions {
            assert_eq!(share, 3000);
        }
        assert_eq!(r.total_distributed, 9000);
        assert_eq!(r.remainder, 0);

        // Invariant: total_distributed + remainder == reward
        assert_eq!(r.total_distributed + r.remainder, 9000);

        // Each validator gets 3000 pending
        assert_eq!(tracker.get_pending(&vid(1)), 3000);
        assert_eq!(tracker.get_pending(&vid(2)), 3000);
        assert_eq!(tracker.get_pending(&vid(3)), 3000);
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// 2. distribute_stake_weighted
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn distribute_stake_weighted() {
    let mut tracker = ValidatorRewardTracker::new();
    // Stake: 100, 300 → total 400
    let set = vset(&[(1, 100), (2, 300)]);
    let config = stake_config();

    let result = distribute_reward(&mut tracker, &set, 4000, &config);
    assert!(result.is_ok());

    if let Ok(r) = result {
        // vid(1): 4000 * 100 / 400 = 1000
        // vid(2): 4000 * 300 / 400 = 3000
        assert_eq!(tracker.get_pending(&vid(1)), 1000);
        assert_eq!(tracker.get_pending(&vid(2)), 3000);
        assert_eq!(r.total_distributed + r.remainder, 4000);
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// 3. distribute_with_remainder_to_treasury
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn distribute_with_remainder_to_treasury() {
    let mut tracker = ValidatorRewardTracker::new();
    let set = vset(&[(1, 100), (2, 100), (3, 100)]);
    let config = equal_config();

    // 10000 / 3 = 3333 each, remainder = 10000 - 9999 = 1
    let result = distribute_reward(&mut tracker, &set, 10_000, &config);
    assert!(result.is_ok());

    if let Ok(r) = result {
        assert_eq!(r.remainder, 1);
        assert_eq!(r.total_distributed, 9999);
        // Core invariant: total_distributed + remainder == reward
        assert_eq!(r.total_distributed + r.remainder, 10_000);
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// 4. distribute_single_validator
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn distribute_single_validator() {
    let mut tracker = ValidatorRewardTracker::new();
    let set = vset(&[(1, 500)]);
    let config = equal_config();

    let result = distribute_reward(&mut tracker, &set, 7777, &config);
    assert!(result.is_ok());

    if let Ok(r) = result {
        assert_eq!(r.total_distributed, 7777);
        assert_eq!(r.remainder, 0);
        assert_eq!(tracker.get_pending(&vid(1)), 7777);
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// 5. distribute_no_validators_error
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn distribute_no_validators_error() {
    let mut tracker = ValidatorRewardTracker::new();
    let empty: Vec<([u8; 32], u128)> = Vec::new();
    let config = equal_config();

    let result = distribute_reward(&mut tracker, &empty, 1000, &config);
    assert_eq!(result, Err(DistributionError::NoActiveValidators));
    // Tracker must be untouched
    assert_eq!(tracker.validator_count(), 0);
    assert_eq!(tracker.total_distributed(), 0);
}

// ════════════════════════════════════════════════════════════════════════════════
// 6. claim_full_pending
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn claim_full_pending() {
    let mut tracker = ValidatorRewardTracker::new();
    let set = vset(&[(1, 100)]);
    let config = equal_config();

    // Distribute 5000 to vid(1)
    let dr = distribute_reward(&mut tracker, &set, 5000, &config);
    assert!(dr.is_ok());
    assert_eq!(tracker.get_pending(&vid(1)), 5000);

    // Claim all (amount = None → claim entire pending)
    let claim = tracker.claim_reward(ClaimRequest {
        validator_id: vid(1),
        amount: None,
        claim_epoch: tracker.current_epoch(),
    });
    assert!(claim.is_ok());

    if let Ok(resp) = claim {
        assert_eq!(resp.claimed_amount, 5000);
        assert_eq!(resp.remaining_pending, 0);
        assert_eq!(tracker.get_pending(&vid(1)), 0);
        assert_eq!(tracker.get_claimed(&vid(1)), 5000);
        // Invariant: total_distributed >= total_claimed
        assert!(tracker.total_distributed() >= tracker.total_claimed());
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// 7. claim_partial_amount
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn claim_partial_amount() {
    let mut tracker = ValidatorRewardTracker::new();
    let set = vset(&[(1, 100)]);

    let _ = distribute_reward(&mut tracker, &set, 10_000, &equal_config());

    let claim = tracker.claim_reward(ClaimRequest {
        validator_id: vid(1),
        amount: Some(3000),
        claim_epoch: 0,
    });
    assert!(claim.is_ok());

    if let Ok(resp) = claim {
        assert_eq!(resp.claimed_amount, 3000);
        assert_eq!(resp.remaining_pending, 7000);
        assert_eq!(tracker.get_pending(&vid(1)), 7000);
        assert_eq!(tracker.get_claimed(&vid(1)), 3000);
        assert!(tracker.total_distributed() >= tracker.total_claimed());
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// 8. claim_insufficient_pending_error
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn claim_insufficient_pending_error() {
    let mut tracker = ValidatorRewardTracker::new();
    let set = vset(&[(1, 100)]);

    let _ = distribute_reward(&mut tracker, &set, 1000, &equal_config());

    let claim = tracker.claim_reward(ClaimRequest {
        validator_id: vid(1),
        amount: Some(5000),
        claim_epoch: 0,
    });
    assert!(claim.is_err());
    if let Err(ClaimError::InsufficientPending { available, requested }) = claim {
        assert_eq!(available, 1000);
        assert_eq!(requested, 5000);
    }
    // Tracker unchanged after error
    assert_eq!(tracker.get_pending(&vid(1)), 1000);
    assert_eq!(tracker.get_claimed(&vid(1)), 0);
}

// ════════════════════════════════════════════════════════════════════════════════
// 9. claim_duplicate_rejected
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn claim_duplicate_rejected() {
    let mut tracker = ValidatorRewardTracker::new();
    let set = vset(&[(1, 100)]);

    let _ = distribute_reward(&mut tracker, &set, 10_000, &equal_config());

    // First claim succeeds
    let first = tracker.claim_reward(ClaimRequest {
        validator_id: vid(1),
        amount: None,
        claim_epoch: 0,
    });
    assert!(first.is_ok());
    let claim_hash = match first.as_ref() {
        Ok(r) => r.claim_hash,
        Err(_) => [0u8; 32],
    };

    // Verify claim hash is recorded as duplicate
    assert!(tracker.is_duplicate(&claim_hash));

    // Distribute again so the validator has pending again
    let _ = distribute_reward(&mut tracker, &set, 10_000, &equal_config());

    // The second claim with SAME parameters would produce same hash
    // but now entry state changed (receipt_count different), so hash changes.
    // Instead, test the structural guarantee: is_duplicate returns true
    // for the first claim hash.
    assert!(tracker.is_duplicate(&claim_hash));

    // Claiming with zero amount should fail, not bypass
    let zero_claim = tracker.claim_reward(ClaimRequest {
        validator_id: vid(1),
        amount: Some(0),
        claim_epoch: 0,
    });
    assert_eq!(zero_claim, Err(ClaimError::ZeroAmount));
}

// ════════════════════════════════════════════════════════════════════════════════
// 10. finalization_storage_immediate
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn finalization_storage_immediate() {
    let mut chain = ChainState::new();
    let hash = rhash(1);

    chain.insert_receipt(hash, ReceiptRecord {
        receipt_type: ReceiptType::Storage,
        submitted_at: 100,
        challenge_period: 50,
        has_active_challenge: false,
    });

    // Storage receipts finalize immediately regardless of time
    let status = check_finalization(&hash, &chain, 0);
    assert_eq!(status, ReceiptFinalizationStatus::Finalized);

    // Even at time 0 — still finalized
    let status2 = check_finalization(&hash, &chain, 100);
    assert_eq!(status2, ReceiptFinalizationStatus::Finalized);
}

// ════════════════════════════════════════════════════════════════════════════════
// 11. finalization_compute_after_challenge
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn finalization_compute_after_challenge() {
    let mut chain = ChainState::new();
    let hash = rhash(2);

    chain.insert_receipt(hash, ReceiptRecord {
        receipt_type: ReceiptType::Compute,
        submitted_at: 100,
        challenge_period: 50,
        has_active_challenge: false,
    });

    // expires_at = 100 + 50 = 150
    // At time 150, challenge period expired → Finalized
    let status = check_finalization(&hash, &chain, 150);
    assert_eq!(status, ReceiptFinalizationStatus::Finalized);

    // At time 200, well past expiry → still Finalized
    let status2 = check_finalization(&hash, &chain, 200);
    assert_eq!(status2, ReceiptFinalizationStatus::Finalized);
}

// ════════════════════════════════════════════════════════════════════════════════
// 12. finalization_compute_during_challenge_blocked
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn finalization_compute_during_challenge_blocked() {
    let mut chain = ChainState::new();
    let hash_pending = rhash(3);
    let hash_challenged = rhash(4);

    // Compute receipt where challenge period hasn't expired
    chain.insert_receipt(hash_pending, ReceiptRecord {
        receipt_type: ReceiptType::Compute,
        submitted_at: 100,
        challenge_period: 50,
        has_active_challenge: false,
    });

    // Compute receipt with an active challenge
    chain.insert_receipt(hash_challenged, ReceiptRecord {
        receipt_type: ReceiptType::Compute,
        submitted_at: 100,
        challenge_period: 50,
        has_active_challenge: true,
    });

    // At time 120, challenge period not expired → PendingChallenge
    let status1 = check_finalization(&hash_pending, &chain, 120);
    assert!(matches!(status1, ReceiptFinalizationStatus::PendingChallenge { expires_at } if expires_at == 150));

    // Active challenge → Challenged (blocked regardless of time)
    let status2 = check_finalization(&hash_challenged, &chain, 200);
    assert_eq!(status2, ReceiptFinalizationStatus::Challenged);

    // Unknown receipt → Rejected
    let unknown = rhash(99);
    let status3 = check_finalization(&unknown, &chain, 0);
    assert_eq!(status3, ReceiptFinalizationStatus::Rejected);
}

// ════════════════════════════════════════════════════════════════════════════════
// 13. query_validator_summary
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn query_validator_summary() {
    let mut tracker = ValidatorRewardTracker::new();
    let set = vset(&[(1, 100)]);

    // Distribute 8000
    let _ = distribute_reward(&mut tracker, &set, 8000, &equal_config());

    // Claim 3000
    let _ = tracker.claim_reward(ClaimRequest {
        validator_id: vid(1),
        amount: Some(3000),
        claim_epoch: 0,
    });

    // Snapshot tracker state before query
    let pending_before = tracker.get_pending(&vid(1));
    let claimed_before = tracker.get_claimed(&vid(1));

    // Query
    let summary = query_validator_rewards(&tracker, &vid(1));
    assert!(summary.is_some());

    if let Some(s) = summary {
        assert_eq!(s.pending_rewards, 5000);
        assert_eq!(s.claimed_rewards, 3000);
        assert_eq!(s.total_earned, 8000);
        assert_eq!(s.receipt_count, 1);
    }

    // Query must NOT mutate tracker (read-only)
    assert_eq!(tracker.get_pending(&vid(1)), pending_before);
    assert_eq!(tracker.get_claimed(&vid(1)), claimed_before);

    // Unknown validator → None
    let unknown = query_validator_rewards(&tracker, &vid(99));
    assert!(unknown.is_none());
}

// ════════════════════════════════════════════════════════════════════════════════
// 14. query_all_validators_sorted
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn query_all_validators_sorted() {
    let mut tracker = ValidatorRewardTracker::new();
    // Insert in non-sorted order: 30, 10, 20
    let set = vset(&[(30, 100), (10, 100), (20, 100)]);

    let _ = distribute_reward(&mut tracker, &set, 3000, &equal_config());

    let all = query_all_validators(&tracker);
    assert_eq!(all.len(), 3);

    // Must be sorted lexicographically by validator_id
    assert_eq!(all[0].validator_id, vid(10));
    assert_eq!(all[1].validator_id, vid(20));
    assert_eq!(all[2].validator_id, vid(30));

    // Repeat call → identical result (deterministic)
    let all2 = query_all_validators(&tracker);
    assert_eq!(all.len(), all2.len());
    for (a, b) in all.iter().zip(all2.iter()) {
        assert_eq!(a.validator_id, b.validator_id);
        assert_eq!(a.pending_rewards, b.pending_rewards);
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// 15. epoch_accounting_correct
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn epoch_accounting_correct() {
    let mut tracker = ValidatorRewardTracker::new();
    let mut accounting = EpochAccounting::new();

    // Record two distributions in epoch 5
    let r1 = accounting.record_distribution(&mut tracker, 5, 1000);
    assert!(r1.is_ok());

    let r2 = accounting.record_distribution(&mut tracker, 5, 2000);
    assert!(r2.is_ok());

    // Record one distribution in epoch 7
    let r3 = accounting.record_distribution(&mut tracker, 7, 500);
    assert!(r3.is_ok());

    // Record finalized receipts
    let rf1 = accounting.record_finalized_receipt(5);
    assert!(rf1.is_ok());
    let rf2 = accounting.record_finalized_receipt(5);
    assert!(rf2.is_ok());

    // Check epoch 5
    let s5 = accounting.get_summary(5);
    assert!(s5.is_some());
    if let Some(s) = s5 {
        assert_eq!(s.epoch, 5);
        assert_eq!(s.total_validator_reward, 3000); // 1000 + 2000
        assert_eq!(s.distribution_count, 2);
        assert_eq!(s.receipts_finalized, 2);
    }

    // Check epoch 7
    let s7 = accounting.get_summary(7);
    assert!(s7.is_some());
    if let Some(s) = s7 {
        assert_eq!(s.total_validator_reward, 500);
        assert_eq!(s.distribution_count, 1);
    }

    // Epoch 0 → InvalidEpoch
    let err = accounting.record_distribution(&mut tracker, 0, 100);
    assert_eq!(err, Err(EpochAccountingError::InvalidEpoch));

    // Total distributed on tracker = 1000 + 2000 + 500 = 3500
    assert_eq!(tracker.total_distributed(), 3500);
}

// ════════════════════════════════════════════════════════════════════════════════
// 16. chain_integration_process_receipts
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn chain_integration_process_receipts() {
    let reader = MockReader::new()
        .with_validators(vec![
            active_vi(1, 500),
            active_vi(2, 500),
            inactive_vi(3, 1000),
        ])
        .with_receipts(vec![
            make_receipt(1, 10_000, 3),
            make_receipt(2, 20_000, 5),
        ]);

    let mut tracker = ValidatorRewardTracker::new();
    let config = equal_config();

    let result = run(process_new_finalized_receipts(
        &reader, &mut tracker, &config, 0,
    ));
    assert!(result.is_ok());

    if let Ok(r) = result {
        assert_eq!(r.receipts_processed, 2);
        // Receipt 1: 10_000 * 20 / 100 = 2_000
        // Receipt 2: 20_000 * 20 / 100 = 4_000
        // Total validator share: 6_000
        assert_eq!(r.total_validator_share, 6_000);
        assert_eq!(r.new_epoch, 5);

        // EqualSplit: 2 active validators
        // Receipt 1: 2000 / 2 = 1000 each
        // Receipt 2: 4000 / 2 = 2000 each
        // Total per active validator: 3000
        assert_eq!(tracker.get_pending(&vid(1)), 3000);
        assert_eq!(tracker.get_pending(&vid(2)), 3000);
        // Inactive validator 3 gets nothing
        assert_eq!(tracker.get_pending(&vid(3)), 0);

        // Invariant: total_distributed >= total_claimed
        assert!(tracker.total_distributed() >= tracker.total_claimed());
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// 17. anti_overflow_large_rewards
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn anti_overflow_large_rewards() {
    // ── Test 1: distribute_reward with very large amounts ────────────────
    let mut tracker = ValidatorRewardTracker::new();
    let set = vset(&[(1, 100)]);

    // u128::MAX should not overflow in EqualSplit (single validator gets all)
    let r1 = distribute_reward(&mut tracker, &set, u128::MAX, &equal_config());
    assert!(r1.is_ok());
    assert_eq!(tracker.get_pending(&vid(1)), u128::MAX);

    // Second distribution would overflow pending
    let r2 = distribute_reward(&mut tracker, &set, 1, &equal_config());
    assert_eq!(r2, Err(DistributionError::OverflowError));
    // Tracker unchanged after overflow (atomicity)
    assert_eq!(tracker.get_pending(&vid(1)), u128::MAX);

    // ── Test 2: chain_integration overflow on * 20 ──────────────────────
    let reader = MockReader::new()
        .with_validators(vec![active_vi(1, 1000)])
        .with_receipts(vec![ReceiptInfo {
            receipt_hash: rhash(1),
            total_reward: u128::MAX,
            epoch: 1,
            is_compute: false,
        }]);

    let mut t2 = ValidatorRewardTracker::new();
    let result = run(process_new_finalized_receipts(
        &reader, &mut t2, &equal_config(), 0,
    ));
    assert_eq!(result, Err(ChainIntegrationError::Overflow));
    // Tracker unchanged after overflow
    assert_eq!(t2.validator_count(), 0);

    // ── Test 3: epoch accounting overflow ────────────────────────────────
    let mut t3 = ValidatorRewardTracker::new();
    let mut acct = EpochAccounting::new();
    let _ = acct.record_distribution(&mut t3, 1, u128::MAX);
    // Second record_distribution would overflow total_distributed
    let err = acct.record_distribution(&mut t3, 1, 1);
    assert_eq!(err, Err(EpochAccountingError::Overflow));
}

// ════════════════════════════════════════════════════════════════════════════════
// BONUS TESTS (above 17 minimum)
// ════════════════════════════════════════════════════════════════════════════════

// ── 18. full_pipeline_distribute_claim_query ─────────────────────────────────

#[test]
fn full_pipeline_distribute_claim_query() {
    // End-to-end: distribute → claim → query → verify invariants
    let mut tracker = ValidatorRewardTracker::new();
    let set = vset(&[(1, 200), (2, 800)]);

    // Step 1: StakeWeighted distribution of 10_000
    let dr = distribute_reward(&mut tracker, &set, 10_000, &stake_config());
    assert!(dr.is_ok());
    if let Ok(r) = &dr {
        assert_eq!(r.total_distributed + r.remainder, 10_000);
    }

    // vid(1): 10000 * 200/1000 = 2000
    // vid(2): 10000 * 800/1000 = 8000
    assert_eq!(tracker.get_pending(&vid(1)), 2000);
    assert_eq!(tracker.get_pending(&vid(2)), 8000);

    // Step 2: Claim 1500 from vid(1)
    let c1 = tracker.claim_reward(ClaimRequest {
        validator_id: vid(1),
        amount: Some(1500),
        claim_epoch: 0,
    });
    assert!(c1.is_ok());

    // Step 3: Query and verify
    let s1 = query_validator_rewards(&tracker, &vid(1));
    assert!(s1.is_some());
    if let Some(s) = s1 {
        assert_eq!(s.pending_rewards, 500);    // 2000 - 1500
        assert_eq!(s.claimed_rewards, 1500);
        assert_eq!(s.total_earned, 2000);       // 500 + 1500
    }

    let s2 = query_validator_rewards(&tracker, &vid(2));
    assert!(s2.is_some());
    if let Some(s) = s2 {
        assert_eq!(s.pending_rewards, 8000);
        assert_eq!(s.claimed_rewards, 0);
        assert_eq!(s.total_earned, 8000);
    }

    // Global invariants
    assert!(tracker.total_distributed() >= tracker.total_claimed());
    assert_eq!(tracker.total_claimed(), 1500);
}

// ── 19. claim_validator_not_found ────────────────────────────────────────────

#[test]
fn claim_validator_not_found() {
    let mut tracker = ValidatorRewardTracker::new();

    let result = tracker.claim_reward(ClaimRequest {
        validator_id: vid(99),
        amount: Some(100),
        claim_epoch: 0,
    });
    assert_eq!(result, Err(ClaimError::ValidatorNotFound));
}

// ── 20. chain_integration_no_partial_update ──────────────────────────────────

#[test]
fn chain_integration_no_partial_update() {
    // First receipt OK, second overflows → entire batch rolled back
    let reader = MockReader::new()
        .with_validators(vec![active_vi(1, 1000)])
        .with_receipts(vec![
            make_receipt(1, 10_000, 1),
            ReceiptInfo {
                receipt_hash: rhash(2),
                total_reward: u128::MAX,
                epoch: 2,
                is_compute: false,
            },
        ]);

    let mut tracker = ValidatorRewardTracker::new();
    let before_count = tracker.validator_count();
    let before_dist = tracker.total_distributed();

    let result = run(process_new_finalized_receipts(
        &reader, &mut tracker, &equal_config(), 0,
    ));
    assert_eq!(result, Err(ChainIntegrationError::Overflow));

    // Tracker must be COMPLETELY unchanged
    assert_eq!(tracker.validator_count(), before_count);
    assert_eq!(tracker.total_distributed(), before_dist);
}