//! # Chain Integration — Reward Pool (14C.C.14)
//!
//! Connects the validator reward pipeline to the on-chain `reward_pool`.
//!
//! ## Trait
//!
//! | Trait | Description |
//! |-------|-------------|
//! | `RewardPoolReader` | Async read-only interface to chain reward pool state |
//!
//! ## Types
//!
//! | Type | Description |
//! |------|-------------|
//! | `ValidatorInfo` | Validator identity, stake, and activity status |
//! | `ValidatorStatus` | `Active` or `Inactive` |
//! | `ReceiptInfo` | Finalized receipt: hash, reward, epoch, compute flag |
//! | `ProcessResult` | Processing outcome: receipts processed, total share, new epoch |
//! | `ChainIntegrationError` | `ReaderError`, `DistributionError`, `Overflow` |
//!
//! ## Invariants
//!
//! 1. `validator_share = receipt.total_reward * 20 / 100` (checked arithmetic).
//! 2. Only `ValidatorStatus::Active` validators receive distributions.
//! 3. No mutation of chain state (read-only `RewardPoolReader`).
//! 4. No partial update: all receipts succeed or the tracker is unchanged.
//! 5. All async calls are explicitly awaited.
//! 6. Deterministic: receipts sorted by epoch before processing.

use async_trait::async_trait;
use crate::reward_tracker::ValidatorRewardTracker;
use crate::reward_distributor::{distribute_reward, DistributionConfig};

// ════════════════════════════════════════════════════════════════════════════════
// TYPES
// ════════════════════════════════════════════════════════════════════════════════

/// On-chain validator information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorInfo {
    /// 32-byte validator identifier.
    pub validator_id: [u8; 32],
    /// Staked token amount.
    pub stake: u128,
    /// Whether this validator is active or inactive.
    pub status: ValidatorStatus,
}

/// Validator activity status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorStatus {
    /// Validator is eligible for reward distributions.
    Active,
    /// Validator is not eligible (slashed, unbonding, offline, etc.).
    Inactive,
}

/// Finalized receipt from the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptInfo {
    /// Unique receipt identifier hash.
    pub receipt_hash: [u8; 32],
    /// Total reward amount locked in this receipt.
    pub total_reward: u128,
    /// Epoch in which this receipt was finalized.
    pub epoch: u64,
    /// Whether this receipt is for a compute task (vs. storage).
    pub is_compute: bool,
}

/// Successful result of processing finalized receipts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessResult {
    /// Number of receipts successfully processed.
    pub receipts_processed: u64,
    /// Cumulative validator share across all processed receipts.
    pub total_validator_share: u128,
    /// Highest epoch among processed receipts (or `last_processed_epoch` if none).
    pub new_epoch: u64,
}

/// Errors that can occur during chain integration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainIntegrationError {
    /// The `RewardPoolReader` returned an error.
    ReaderError,
    /// `distribute_reward` failed.
    DistributionError,
    /// Checked arithmetic overflowed.
    Overflow,
}

impl core::fmt::Display for ChainIntegrationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ReaderError => f.write_str("reward pool reader error"),
            Self::DistributionError => f.write_str("distribution error"),
            Self::Overflow => f.write_str("arithmetic overflow"),
        }
    }
}

/// Error returned by [`RewardPoolReader`] methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReaderError;

impl core::fmt::Display for ReaderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("reward pool reader error")
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TRAIT — Async read-only chain interface
// ════════════════════════════════════════════════════════════════════════════════

/// Async read-only interface to the on-chain reward pool.
///
/// Implementations MUST NOT mutate chain state.
/// All methods return explicit `Result` types.
#[async_trait]
pub trait RewardPoolReader: Send + Sync {
    /// Query the current reward pool balance.
    async fn get_reward_pool_balance(&self) -> Result<u128, ReaderError>;

    /// Query the full validator set (both active and inactive).
    async fn get_active_validator_set(&self) -> Result<Vec<ValidatorInfo>, ReaderError>;

    /// Query all finalized receipts since `epoch` (exclusive).
    async fn get_finalized_receipts_since(
        &self,
        epoch: u64,
    ) -> Result<Vec<ReceiptInfo>, ReaderError>;
}

// ════════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════════

/// Validator share numerator: validators receive 20% of each receipt's reward.
const VALIDATOR_SHARE_NUMERATOR: u128 = 20;

/// Validator share denominator.
const VALIDATOR_SHARE_DENOMINATOR: u128 = 100;

// ════════════════════════════════════════════════════════════════════════════════
// MAIN PROCESSING FUNCTION
// ════════════════════════════════════════════════════════════════════════════════

/// Process newly finalized receipts from the chain reward pool.
///
/// For each finalized receipt since `last_processed_epoch`:
///
/// 1. Compute `validator_share = total_reward * 20 / 100` (checked).
/// 2. Filter only `Active` validators from the reader's set.
/// 3. Distribute the `validator_share` among active validators using `config`.
///
/// # Atomicity
///
/// All receipts are processed on a **clone** of the tracker. If any receipt
/// fails, the original tracker is left completely unchanged.
///
/// # Determinism
///
/// Receipts are sorted by `(epoch, receipt_hash)` before processing to
/// guarantee deterministic ordering regardless of the reader's return order.
pub async fn process_new_finalized_receipts<R: RewardPoolReader>(
    reader: &R,
    tracker: &mut ValidatorRewardTracker,
    config: &DistributionConfig,
    last_processed_epoch: u64,
) -> Result<ProcessResult, ChainIntegrationError> {
    // ── 1. Query finalized receipts ─────────────────────────────────────
    let mut receipts = reader
        .get_finalized_receipts_since(last_processed_epoch)
        .await
        .map_err(|_| ChainIntegrationError::ReaderError)?;

    // ── 2. No receipts → no-op success ──────────────────────────────────
    if receipts.is_empty() {
        return Ok(ProcessResult {
            receipts_processed: 0,
            total_validator_share: 0,
            new_epoch: last_processed_epoch,
        });
    }

    // ── 3. Sort receipts deterministically: (epoch ASC, hash ASC) ───────
    receipts.sort_by(|a, b| {
        a.epoch.cmp(&b.epoch).then_with(|| a.receipt_hash.cmp(&b.receipt_hash))
    });

    // ── 4. Query active validator set ───────────────────────────────────
    let all_validators = reader
        .get_active_validator_set()
        .await
        .map_err(|_| ChainIntegrationError::ReaderError)?;

    // Filter: only Active validators
    let active_set: Vec<([u8; 32], u128)> = all_validators
        .iter()
        .filter(|v| v.status == ValidatorStatus::Active)
        .map(|v| (v.validator_id, v.stake))
        .collect();

    // ── 5. Process all receipts on a clone (atomicity) ──────────────────
    let mut working_tracker = tracker.clone();
    let mut receipts_processed: u64 = 0;
    let mut total_validator_share: u128 = 0;
    let mut new_epoch: u64 = last_processed_epoch;

    for receipt in &receipts {
        // ── 5a. Compute 20% validator share (checked) ───────────────────
        let validator_share = receipt
            .total_reward
            .checked_mul(VALIDATOR_SHARE_NUMERATOR)
            .ok_or(ChainIntegrationError::Overflow)?
            .checked_div(VALIDATOR_SHARE_DENOMINATOR)
            .ok_or(ChainIntegrationError::Overflow)?;

        // Skip zero-share receipts (no distribution needed)
        if validator_share == 0 {
            receipts_processed = receipts_processed
                .checked_add(1)
                .ok_or(ChainIntegrationError::Overflow)?;
            if receipt.epoch > new_epoch {
                new_epoch = receipt.epoch;
            }
            continue;
        }

        // ── 5b. Distribute among active validators ──────────────────────
        if active_set.is_empty() {
            // No active validators → skip distribution but still count receipt
            receipts_processed = receipts_processed
                .checked_add(1)
                .ok_or(ChainIntegrationError::Overflow)?;
            if receipt.epoch > new_epoch {
                new_epoch = receipt.epoch;
            }
            continue;
        }

        distribute_reward(
            &mut working_tracker,
            &active_set,
            validator_share,
            config,
        )
        .map_err(|_| ChainIntegrationError::DistributionError)?;

        // ── 5c. Accumulate results ──────────────────────────────────────
        receipts_processed = receipts_processed
            .checked_add(1)
            .ok_or(ChainIntegrationError::Overflow)?;

        total_validator_share = total_validator_share
            .checked_add(validator_share)
            .ok_or(ChainIntegrationError::Overflow)?;

        if receipt.epoch > new_epoch {
            new_epoch = receipt.epoch;
        }
    }

    // ── 6. Commit: replace tracker with successfully processed clone ────
    *tracker = working_tracker;

    Ok(ProcessResult {
        receipts_processed,
        total_validator_share,
        new_epoch,
    })
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reward_distributor::{DistributionStrategy, DistributionConfig};

    // ── Mock Reader ─────────────────────────────────────────────────────

    /// Deterministic mock implementation of [`RewardPoolReader`].
    ///
    /// No async sleep, no randomness, no network.
    #[derive(Debug, Clone)]
    struct MockRewardPoolReader {
        balance: u128,
        validators: Vec<ValidatorInfo>,
        receipts: Vec<ReceiptInfo>,
        should_fail: bool,
    }

    impl MockRewardPoolReader {
        fn new() -> Self {
            Self {
                balance: 0,
                validators: Vec::new(),
                receipts: Vec::new(),
                should_fail: false,
            }
        }

        fn with_balance(mut self, balance: u128) -> Self {
            self.balance = balance;
            self
        }

        fn with_validators(mut self, validators: Vec<ValidatorInfo>) -> Self {
            self.validators = validators;
            self
        }

        fn with_receipts(mut self, receipts: Vec<ReceiptInfo>) -> Self {
            self.receipts = receipts;
            self
        }

        fn failing(mut self) -> Self {
            self.should_fail = true;
            self
        }
    }

    #[async_trait]
    impl RewardPoolReader for MockRewardPoolReader {
        async fn get_reward_pool_balance(&self) -> Result<u128, ReaderError> {
            if self.should_fail {
                return Err(ReaderError);
            }
            Ok(self.balance)
        }

        async fn get_active_validator_set(&self) -> Result<Vec<ValidatorInfo>, ReaderError> {
            if self.should_fail {
                return Err(ReaderError);
            }
            Ok(self.validators.clone())
        }

        async fn get_finalized_receipts_since(
            &self,
            epoch: u64,
        ) -> Result<Vec<ReceiptInfo>, ReaderError> {
            if self.should_fail {
                return Err(ReaderError);
            }
            let filtered: Vec<ReceiptInfo> = self
                .receipts
                .iter()
                .filter(|r| r.epoch > epoch)
                .cloned()
                .collect();
            Ok(filtered)
        }
    }

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

    fn active_validator(n: u8, stake: u128) -> ValidatorInfo {
        ValidatorInfo {
            validator_id: vid(n),
            stake,
            status: ValidatorStatus::Active,
        }
    }

    fn inactive_validator(n: u8, stake: u128) -> ValidatorInfo {
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

    fn equal_split_config() -> DistributionConfig {
        DistributionConfig {
            strategy: DistributionStrategy::EqualSplit,
            min_distribution: 0,
        }
    }

    fn run<F: std::future::Future>(f: F) -> F::Output {
        // Minimal single-threaded executor for tests (no tokio dependency needed)
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

    /// No-op waker for the test executor (safe, no `unsafe`).
    struct NoopWaker;

    impl std::task::Wake for NoopWaker {
        fn wake(self: std::sync::Arc<Self>) {}
    }

    // ── 1. process_single_receipt_success ────────────────────────────────

    #[test]
    fn process_single_receipt_success() {
        let reader = MockRewardPoolReader::new()
            .with_balance(100_000)
            .with_validators(vec![active_validator(1, 1000)])
            .with_receipts(vec![make_receipt(1, 10_000, 5)]);

        let mut tracker = ValidatorRewardTracker::new();
        let config = equal_split_config();

        let result = run(process_new_finalized_receipts(
            &reader, &mut tracker, &config, 0,
        ));
        assert!(result.is_ok());
        if let Ok(r) = result {
            assert_eq!(r.receipts_processed, 1);
            // 10_000 * 20 / 100 = 2_000
            assert_eq!(r.total_validator_share, 2_000);
            assert_eq!(r.new_epoch, 5);
            // Validator should have received 2_000 pending
            assert_eq!(tracker.get_pending(&vid(1)), 2_000);
        }
    }

    // ── 2. process_multiple_receipts ─────────────────────────────────────

    #[test]
    fn process_multiple_receipts() {
        let reader = MockRewardPoolReader::new()
            .with_validators(vec![active_validator(1, 1000)])
            .with_receipts(vec![
                make_receipt(1, 10_000, 5),
                make_receipt(2, 20_000, 7),
                make_receipt(3, 5_000, 6),
            ]);

        let mut tracker = ValidatorRewardTracker::new();
        let config = equal_split_config();

        let result = run(process_new_finalized_receipts(
            &reader, &mut tracker, &config, 0,
        ));
        assert!(result.is_ok());
        if let Ok(r) = result {
            assert_eq!(r.receipts_processed, 3);
            // 2_000 + 4_000 + 1_000 = 7_000
            assert_eq!(r.total_validator_share, 7_000);
            assert_eq!(r.new_epoch, 7);
            assert_eq!(tracker.get_pending(&vid(1)), 7_000);
        }
    }

    // ── 3. skip_inactive_validators ──────────────────────────────────────

    #[test]
    fn skip_inactive_validators() {
        let reader = MockRewardPoolReader::new()
            .with_validators(vec![
                active_validator(1, 1000),
                inactive_validator(2, 2000),
            ])
            .with_receipts(vec![make_receipt(1, 10_000, 5)]);

        let mut tracker = ValidatorRewardTracker::new();
        let config = equal_split_config();

        let result = run(process_new_finalized_receipts(
            &reader, &mut tracker, &config, 0,
        ));
        assert!(result.is_ok());
        if let Ok(r) = result {
            assert_eq!(r.receipts_processed, 1);
            // 2_000 goes to validator 1 only
            assert_eq!(tracker.get_pending(&vid(1)), 2_000);
            // Inactive validator 2 gets nothing
            assert_eq!(tracker.get_pending(&vid(2)), 0);
        }
    }

    // ── 4. correct_20_percent_calculation ─────────────────────────────────

    #[test]
    fn correct_20_percent_calculation() {
        // Test various amounts for precise 20% calculation
        let test_cases: &[(u128, u128)] = &[
            (100, 20),
            (1, 0),         // 1 * 20 / 100 = 0 (integer division)
            (4, 0),         // 4 * 20 / 100 = 0
            (5, 1),         // 5 * 20 / 100 = 1
            (999, 199),     // 999 * 20 / 100 = 199
            (10_000, 2_000),
            (u128::MAX / 20, u128::MAX / 20 * 20 / 100),
        ];

        for &(reward, expected_share) in test_cases {
            let computed = reward
                .checked_mul(VALIDATOR_SHARE_NUMERATOR)
                .and_then(|v| v.checked_div(VALIDATOR_SHARE_DENOMINATOR));
            assert!(computed.is_some(), "overflow for reward={reward}");
            if let Some(share) = computed {
                assert_eq!(share, expected_share, "20% of {reward} should be {expected_share}");
            }
        }
    }

    // ── 5. no_receipts_no_distribution ────────────────────────────────────

    #[test]
    fn no_receipts_no_distribution() {
        let reader = MockRewardPoolReader::new()
            .with_validators(vec![active_validator(1, 1000)])
            .with_receipts(vec![]);

        let mut tracker = ValidatorRewardTracker::new();
        let config = equal_split_config();

        let result = run(process_new_finalized_receipts(
            &reader, &mut tracker, &config, 0,
        ));
        assert!(result.is_ok());
        if let Ok(r) = result {
            assert_eq!(r.receipts_processed, 0);
            assert_eq!(r.total_validator_share, 0);
            assert_eq!(r.new_epoch, 0); // unchanged
        }
    }

    // ── 6. reader_error_propagation ──────────────────────────────────────

    #[test]
    fn reader_error_propagation() {
        let reader = MockRewardPoolReader::new().failing();
        let mut tracker = ValidatorRewardTracker::new();
        let config = equal_split_config();

        let result = run(process_new_finalized_receipts(
            &reader, &mut tracker, &config, 0,
        ));
        assert_eq!(result, Err(ChainIntegrationError::ReaderError));
    }

    // ── 7. distribution_error_propagation ────────────────────────────────

    #[test]
    fn distribution_error_propagation() {
        // All validators have zero stake → StakeWeighted will fail
        let reader = MockRewardPoolReader::new()
            .with_validators(vec![ValidatorInfo {
                validator_id: vid(1),
                stake: 0,
                status: ValidatorStatus::Active,
            }])
            .with_receipts(vec![make_receipt(1, 10_000, 5)]);

        let mut tracker = ValidatorRewardTracker::new();
        let config = DistributionConfig {
            strategy: DistributionStrategy::StakeWeighted,
            min_distribution: 0,
        };

        let result = run(process_new_finalized_receipts(
            &reader, &mut tracker, &config, 0,
        ));
        assert_eq!(result, Err(ChainIntegrationError::DistributionError));
        // Tracker must be unchanged (atomicity)
        assert_eq!(tracker.validator_count(), 0);
    }

    // ── 8. overflow_detection ────────────────────────────────────────────

    #[test]
    fn overflow_detection() {
        // total_reward so large that * 20 overflows u128
        let reader = MockRewardPoolReader::new()
            .with_validators(vec![active_validator(1, 1000)])
            .with_receipts(vec![ReceiptInfo {
                receipt_hash: rhash(1),
                total_reward: u128::MAX,
                epoch: 5,
                is_compute: false,
            }]);

        let mut tracker = ValidatorRewardTracker::new();
        let config = equal_split_config();

        let result = run(process_new_finalized_receipts(
            &reader, &mut tracker, &config, 0,
        ));
        assert_eq!(result, Err(ChainIntegrationError::Overflow));
        // Tracker must be unchanged (atomicity)
        assert_eq!(tracker.validator_count(), 0);
    }

    // ── 9. epoch_update_correct ──────────────────────────────────────────

    #[test]
    fn epoch_update_correct() {
        let reader = MockRewardPoolReader::new()
            .with_validators(vec![active_validator(1, 1000)])
            .with_receipts(vec![
                make_receipt(1, 1000, 3),
                make_receipt(2, 1000, 7),
                make_receipt(3, 1000, 5),
            ]);

        let mut tracker = ValidatorRewardTracker::new();
        let config = equal_split_config();

        let result = run(process_new_finalized_receipts(
            &reader, &mut tracker, &config, 0,
        ));
        assert!(result.is_ok());
        if let Ok(r) = result {
            assert_eq!(r.new_epoch, 7); // highest epoch
        }
    }

    // ── 10. deterministic_behavior ───────────────────────────────────────

    #[test]
    fn deterministic_behavior() {
        let receipts = vec![
            make_receipt(3, 3000, 3),
            make_receipt(1, 1000, 1),
            make_receipt(2, 2000, 2),
        ];
        let validators = vec![
            active_validator(2, 500),
            active_validator(1, 500),
        ];
        let reader = MockRewardPoolReader::new()
            .with_validators(validators.clone())
            .with_receipts(receipts.clone());

        // Run twice with independent trackers
        let mut tracker1 = ValidatorRewardTracker::new();
        let mut tracker2 = ValidatorRewardTracker::new();
        let config = equal_split_config();

        let r1 = run(process_new_finalized_receipts(
            &reader, &mut tracker1, &config, 0,
        ));
        let r2 = run(process_new_finalized_receipts(
            &reader, &mut tracker2, &config, 0,
        ));

        assert_eq!(r1, r2);
        assert_eq!(tracker1.get_pending(&vid(1)), tracker2.get_pending(&vid(1)));
        assert_eq!(tracker1.get_pending(&vid(2)), tracker2.get_pending(&vid(2)));
    }

    // ── 11. active_only_filter ───────────────────────────────────────────

    #[test]
    fn active_only_filter() {
        let reader = MockRewardPoolReader::new()
            .with_validators(vec![
                active_validator(1, 500),
                inactive_validator(2, 1000),
                active_validator(3, 500),
                inactive_validator(4, 2000),
            ])
            .with_receipts(vec![make_receipt(1, 10_000, 5)]);

        let mut tracker = ValidatorRewardTracker::new();
        let config = equal_split_config();

        let result = run(process_new_finalized_receipts(
            &reader, &mut tracker, &config, 0,
        ));
        assert!(result.is_ok());
        // Only validators 1 and 3 are active → EqualSplit: 2000 / 2 = 1000 each
        assert_eq!(tracker.get_pending(&vid(1)), 1000);
        assert_eq!(tracker.get_pending(&vid(3)), 1000);
        assert_eq!(tracker.get_pending(&vid(2)), 0);
        assert_eq!(tracker.get_pending(&vid(4)), 0);
    }

    // ── 12. total_validator_share_correct ─────────────────────────────────

    #[test]
    fn total_validator_share_correct() {
        let reader = MockRewardPoolReader::new()
            .with_validators(vec![active_validator(1, 1000)])
            .with_receipts(vec![
                make_receipt(1, 50_000, 1),
                make_receipt(2, 30_000, 2),
            ]);

        let mut tracker = ValidatorRewardTracker::new();
        let config = equal_split_config();

        let result = run(process_new_finalized_receipts(
            &reader, &mut tracker, &config, 0,
        ));
        assert!(result.is_ok());
        if let Ok(r) = result {
            // 50_000 * 20% = 10_000; 30_000 * 20% = 6_000; total = 16_000
            assert_eq!(r.total_validator_share, 16_000);
            assert_eq!(tracker.get_pending(&vid(1)), 16_000);
        }
    }

    // ── 13. no_partial_update_on_failure ──────────────────────────────────

    #[test]
    fn no_partial_update_on_failure() {
        // First receipt succeeds, second overflows
        let reader = MockRewardPoolReader::new()
            .with_validators(vec![active_validator(1, 1000)])
            .with_receipts(vec![
                make_receipt(1, 10_000, 1),
                ReceiptInfo {
                    receipt_hash: rhash(2),
                    total_reward: u128::MAX, // overflow on * 20
                    epoch: 2,
                    is_compute: false,
                },
            ]);

        let mut tracker = ValidatorRewardTracker::new();
        let config = equal_split_config();

        // Capture tracker state before
        let pending_before = tracker.get_pending(&vid(1));
        let count_before = tracker.validator_count();

        let result = run(process_new_finalized_receipts(
            &reader, &mut tracker, &config, 0,
        ));
        assert_eq!(result, Err(ChainIntegrationError::Overflow));

        // Tracker must be completely unchanged (clone-swap atomicity)
        assert_eq!(tracker.get_pending(&vid(1)), pending_before);
        assert_eq!(tracker.validator_count(), count_before);
    }

    // ── 14. mock_reader_deterministic ────────────────────────────────────

    #[test]
    fn mock_reader_deterministic() {
        let reader = MockRewardPoolReader::new()
            .with_balance(50_000)
            .with_validators(vec![active_validator(1, 1000)])
            .with_receipts(vec![make_receipt(1, 10_000, 5)]);

        // Call multiple times — same results
        let b1 = run(reader.get_reward_pool_balance());
        let b2 = run(reader.get_reward_pool_balance());
        assert_eq!(b1, b2);

        let v1 = run(reader.get_active_validator_set());
        let v2 = run(reader.get_active_validator_set());
        assert_eq!(v1, v2);

        let r1 = run(reader.get_finalized_receipts_since(0));
        let r2 = run(reader.get_finalized_receipts_since(0));
        assert_eq!(r1, r2);
    }

    // ── 15. epoch_filter_respects_last_processed ─────────────────────────

    #[test]
    fn epoch_filter_respects_last_processed() {
        let reader = MockRewardPoolReader::new()
            .with_validators(vec![active_validator(1, 1000)])
            .with_receipts(vec![
                make_receipt(1, 10_000, 3),
                make_receipt(2, 10_000, 5),
                make_receipt(3, 10_000, 7),
            ]);

        let mut tracker = ValidatorRewardTracker::new();
        let config = equal_split_config();

        // Process from epoch 5 → only epoch 7 receipt
        let result = run(process_new_finalized_receipts(
            &reader, &mut tracker, &config, 5,
        ));
        assert!(result.is_ok());
        if let Ok(r) = result {
            assert_eq!(r.receipts_processed, 1);
            assert_eq!(r.total_validator_share, 2_000);
            assert_eq!(r.new_epoch, 7);
        }
    }

    // ── 16. zero_reward_receipt_skips_distribution ────────────────────────

    #[test]
    fn zero_reward_receipt_skips_distribution() {
        let reader = MockRewardPoolReader::new()
            .with_validators(vec![active_validator(1, 1000)])
            .with_receipts(vec![
                make_receipt(1, 0, 5),  // 0 * 20% = 0 → skip
                make_receipt(2, 100, 6),
            ]);

        let mut tracker = ValidatorRewardTracker::new();
        let config = equal_split_config();

        let result = run(process_new_finalized_receipts(
            &reader, &mut tracker, &config, 0,
        ));
        assert!(result.is_ok());
        if let Ok(r) = result {
            assert_eq!(r.receipts_processed, 2);
            assert_eq!(r.total_validator_share, 20); // only from 2nd receipt
            assert_eq!(r.new_epoch, 6);
        }
    }
}