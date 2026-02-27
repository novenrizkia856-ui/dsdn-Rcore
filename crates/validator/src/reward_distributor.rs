//! # Reward Distribution Logic (14C.C.10)
//!
//! Deterministic reward distribution across a validator set, supporting
//! equal-split and stake-weighted strategies.
//!
//! ## Invariant
//!
//! For every successful call to [`distribute_reward`]:
//!
//! ```text
//! result.total_distributed + result.remainder == reward_amount
//! ```
//!
//! ## Atomicity
//!
//! Tracker mutations are applied only after all overflow pre-checks pass.
//! If any check fails, the tracker is left unchanged and
//! [`DistributionError::OverflowError`] is returned.
//!
//! ## Determinism
//!
//! `distributions` in [`DistributionResult`] are always sorted by
//! validator ID in ascending lexicographic order.

use crate::reward_tracker::ValidatorRewardTracker;

// ════════════════════════════════════════════════════════════════════════════════
// TYPES
// ════════════════════════════════════════════════════════════════════════════════

/// Strategy for splitting rewards among validators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistributionStrategy {
    /// Every active validator receives an equal share.
    EqualSplit,
    /// Each validator receives a share proportional to their stake.
    StakeWeighted,
}

/// Configuration governing a distribution round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DistributionConfig {
    /// Strategy used to compute per-validator shares.
    pub strategy: DistributionStrategy,
    /// Minimum share a validator must receive; validators whose computed
    /// share is below this threshold receive zero for that round.
    pub min_distribution: u128,
}

/// Successful outcome of a distribution round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistributionResult {
    /// Per-validator distributions, sorted by validator ID (ascending).
    pub distributions: Vec<([u8; 32], u128)>,
    /// Undistributed remainder (goes to treasury / next round).
    pub remainder: u128,
    /// Sum of all individual distributions.
    pub total_distributed: u128,
}

/// Errors that can occur during reward distribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistributionError {
    /// The validator set is empty, or total stake is zero for stake-weighted.
    NoActiveValidators,
    /// `reward_amount` was zero.
    InvalidRewardAmount,
    /// Checked arithmetic overflowed during computation or tracker update.
    OverflowError,
}

impl core::fmt::Display for DistributionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoActiveValidators => f.write_str("no active validators"),
            Self::InvalidRewardAmount => f.write_str("reward amount is zero"),
            Self::OverflowError => f.write_str("arithmetic overflow"),
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// DISTRIBUTION LOGIC
// ════════════════════════════════════════════════════════════════════════════════

/// Distribute `reward_amount` across `validator_set` and update `tracker`.
///
/// # Errors
///
/// * [`DistributionError::InvalidRewardAmount`] if `reward_amount == 0`.
/// * [`DistributionError::NoActiveValidators`] if `validator_set` is empty
///   or (for `StakeWeighted`) total stake is zero.
/// * [`DistributionError::OverflowError`] if checked arithmetic overflows.
///
/// # Invariant
///
/// On success: `result.total_distributed + result.remainder == reward_amount`.
pub fn distribute_reward(
    tracker: &mut ValidatorRewardTracker,
    validator_set: &[([u8; 32], u128)],
    reward_amount: u128,
    config: &DistributionConfig,
) -> Result<DistributionResult, DistributionError> {
    // ── Validation ───────────────────────────────────────────────────────
    if reward_amount == 0 {
        return Err(DistributionError::InvalidRewardAmount);
    }
    if validator_set.is_empty() {
        return Err(DistributionError::NoActiveValidators);
    }

    // ── Compute shares (pure, no side effects) ──────────────────────────
    let mut distributions = match config.strategy {
        DistributionStrategy::EqualSplit => {
            compute_equal_split(validator_set, reward_amount, config.min_distribution)?
        }
        DistributionStrategy::StakeWeighted => {
            compute_stake_weighted(validator_set, reward_amount, config.min_distribution)?
        }
    };

    // ── Deterministic sort by validator_id (lexicographic) ──────────────
    distributions.sort_by(|a, b| a.0.cmp(&b.0));

    // ── Compute totals ──────────────────────────────────────────────────
    let total_distributed = distributions
        .iter()
        .try_fold(0u128, |acc, &(_, share)| acc.checked_add(share))
        .ok_or(DistributionError::OverflowError)?;

    let remainder = reward_amount
        .checked_sub(total_distributed)
        .ok_or(DistributionError::OverflowError)?;

    // ── Pre-check tracker mutations (atomicity guarantee) ───────────────
    tracker
        .total_distributed()
        .checked_add(total_distributed)
        .ok_or(DistributionError::OverflowError)?;

    let epoch = tracker.current_epoch();
    for &(vid, share) in &distributions {
        if share == 0 {
            continue;
        }
        tracker
            .get_pending(&vid)
            .checked_add(share)
            .ok_or(DistributionError::OverflowError)?;
    }

    // ── Apply mutations (safe: pre-checked above) ───────────────────────
    for &(vid, share) in &distributions {
        if share == 0 {
            continue;
        }
        if tracker.add_pending_reward(vid, share, epoch).is_err() {
            return Err(DistributionError::OverflowError);
        }
    }
    if tracker.add_total_distributed(total_distributed).is_err() {
        return Err(DistributionError::OverflowError);
    }

    Ok(DistributionResult {
        distributions,
        remainder,
        total_distributed,
    })
}

// ════════════════════════════════════════════════════════════════════════════════
// STRATEGY IMPLEMENTATIONS (pure computation)
// ════════════════════════════════════════════════════════════════════════════════

fn compute_equal_split(
    validator_set: &[([u8; 32], u128)],
    reward_amount: u128,
    min_distribution: u128,
) -> Result<Vec<([u8; 32], u128)>, DistributionError> {
    #[allow(clippy::cast_possible_truncation)]
    let count = validator_set.len() as u128;

    let per_validator = reward_amount / count;

    if per_validator < min_distribution {
        return Ok(Vec::new());
    }

    Ok(validator_set.iter().map(|&(vid, _)| (vid, per_validator)).collect())
}

fn compute_stake_weighted(
    validator_set: &[([u8; 32], u128)],
    reward_amount: u128,
    min_distribution: u128,
) -> Result<Vec<([u8; 32], u128)>, DistributionError> {
    let total_stake = validator_set
        .iter()
        .try_fold(0u128, |acc, &(_, stake)| acc.checked_add(stake))
        .ok_or(DistributionError::OverflowError)?;

    if total_stake == 0 {
        return Err(DistributionError::NoActiveValidators);
    }

    let mut result = Vec::with_capacity(validator_set.len());
    for &(vid, stake) in validator_set {
        let share = mul_div_u128(stake, reward_amount, total_stake)?;
        let share = if share < min_distribution { 0 } else { share };
        result.push((vid, share));
    }
    Ok(result)
}

// ════════════════════════════════════════════════════════════════════════════════
// 256-BIT INTEGER ARITHMETIC (no external deps, no floating point)
// ════════════════════════════════════════════════════════════════════════════════

/// Compute `(a * b) / c` without intermediate overflow.
///
/// Uses 256-bit widening multiply + binary long division.
fn mul_div_u128(a: u128, b: u128, c: u128) -> Result<u128, DistributionError> {
    if c == 0 {
        return Err(DistributionError::OverflowError);
    }
    let (hi, lo) = widening_mul_128(a, b);
    div_256_by_128(hi, lo, c)
}

/// 128×128 → 256-bit widening multiply → (hi128, lo128).
fn widening_mul_128(a: u128, b: u128) -> (u128, u128) {
    let a_lo = a & 0xFFFF_FFFF_FFFF_FFFF;
    let a_hi = a >> 64;
    let b_lo = b & 0xFFFF_FFFF_FFFF_FFFF;
    let b_hi = b >> 64;

    let ll = a_lo * b_lo;
    let lh = a_lo * b_hi;
    let hl = a_hi * b_lo;
    let hh = a_hi * b_hi;

    let (mid, mid_carry) = lh.overflowing_add(hl);
    let mid_shifted = mid << 64;
    let (lo, lo_carry) = ll.overflowing_add(mid_shifted);

    let mid_carry_val: u128 = if mid_carry { 1u128 << 64 } else { 0 };
    let lo_carry_val: u128 = u128::from(lo_carry);
    let hi = hh
        .wrapping_add(mid >> 64)
        .wrapping_add(mid_carry_val)
        .wrapping_add(lo_carry_val);

    (hi, lo)
}

/// Divide 256-bit (hi, lo) by 128-bit divisor using binary long division.
///
/// Returns quotient (must fit u128) or [`DistributionError::OverflowError`].
fn div_256_by_128(hi: u128, lo: u128, divisor: u128) -> Result<u128, DistributionError> {
    if divisor == 0 {
        return Err(DistributionError::OverflowError);
    }
    if hi == 0 {
        return Ok(lo / divisor);
    }
    if hi >= divisor {
        return Err(DistributionError::OverflowError);
    }

    // Binary long division over 128 quotient bits.
    // Invariant: rem < divisor at the start of each iteration.
    let mut rem: u128 = hi;
    let mut quotient: u128 = 0;

    for i in (0u32..128).rev() {
        // Shift rem left by 1, capturing the carry (bit that falls off the top)
        let carry = rem >> 127;
        rem <<= 1;
        rem |= (lo >> i) & 1;

        quotient <<= 1;

        // If carry == 1 the real remainder is rem + 2^128 which always >= divisor.
        // If carry == 0 we compare rem directly.
        if carry > 0 || rem >= divisor {
            // Subtract divisor from the (possibly 129-bit) remainder.
            // When carry == 1: rem < divisor (proven), so wrapping_sub
            // yields 2^128 + rem - divisor which is the correct result
            // and fits in u128 (since result < divisor).
            // When carry == 0: rem >= divisor, normal subtraction.
            rem = rem.wrapping_sub(divisor);
            quotient |= 1;
        }
    }

    Ok(quotient)
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn vid(n: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = n;
        id
    }

    fn eq_cfg(min: u128) -> DistributionConfig {
        DistributionConfig {
            strategy: DistributionStrategy::EqualSplit,
            min_distribution: min,
        }
    }

    fn sw_cfg(min: u128) -> DistributionConfig {
        DistributionConfig {
            strategy: DistributionStrategy::StakeWeighted,
            min_distribution: min,
        }
    }

    /// Extract Ok variant after asserting success; returns from the test on Err.
    macro_rules! ok {
        ($e:expr) => {{
            let r = $e;
            assert!(r.is_ok(), "expected Ok, got {:?}", r);
            match r { Ok(v) => v, Err(_) => return }
        }};
    }

    // ── 1. equal_split_basic ─────────────────────────────────────────────
    #[test]
    fn equal_split_basic() {
        let mut t = ValidatorRewardTracker::new();
        let v = [(vid(1), 100u128), (vid(2), 200)];
        let r = ok!(distribute_reward(&mut t, &v, 1000, &eq_cfg(0)));
        assert_eq!(r.total_distributed, 1000);
        assert_eq!(r.remainder, 0);
        assert_eq!(r.distributions.len(), 2);
        for &(_, s) in &r.distributions { assert_eq!(s, 500); }
    }

    // ── 2. equal_split_with_remainder ────────────────────────────────────
    #[test]
    fn equal_split_with_remainder() {
        let mut t = ValidatorRewardTracker::new();
        let v = [(vid(1), 1), (vid(2), 1), (vid(3), 1)];
        let r = ok!(distribute_reward(&mut t, &v, 100, &eq_cfg(0)));
        assert_eq!(r.total_distributed, 99);
        assert_eq!(r.remainder, 1);
        assert_eq!(r.total_distributed + r.remainder, 100);
    }

    // ── 3. equal_split_min_distribution_block ────────────────────────────
    #[test]
    fn equal_split_min_distribution_block() {
        let mut t = ValidatorRewardTracker::new();
        let v = [(vid(1), 1), (vid(2), 1), (vid(3), 1)];
        let r = ok!(distribute_reward(&mut t, &v, 100, &eq_cfg(50)));
        assert!(r.distributions.is_empty());
        assert_eq!(r.total_distributed, 0);
        assert_eq!(r.remainder, 100);
    }

    // ── 4. stake_weighted_basic ──────────────────────────────────────────
    #[test]
    fn stake_weighted_basic() {
        let mut t = ValidatorRewardTracker::new();
        let v = [(vid(1), 500u128), (vid(2), 500)];
        let r = ok!(distribute_reward(&mut t, &v, 1000, &sw_cfg(0)));
        assert_eq!(r.total_distributed, 1000);
        assert_eq!(r.remainder, 0);
        for &(_, s) in &r.distributions { assert_eq!(s, 500); }
    }

    // ── 5. stake_weighted_proportional_correct ───────────────────────────
    #[test]
    fn stake_weighted_proportional_correct() {
        let mut t = ValidatorRewardTracker::new();
        let v = [(vid(1), 300u128), (vid(2), 100)];
        let r = ok!(distribute_reward(&mut t, &v, 1000, &sw_cfg(0)));
        let s1 = r.distributions.iter().find(|(id, _)| *id == vid(1)).map(|x| x.1);
        let s2 = r.distributions.iter().find(|(id, _)| *id == vid(2)).map(|x| x.1);
        assert_eq!(s1, Some(750));
        assert_eq!(s2, Some(250));
        assert_eq!(r.total_distributed + r.remainder, 1000);
    }

    // ── 6. stake_weighted_zero_total_stake ───────────────────────────────
    #[test]
    fn stake_weighted_zero_total_stake() {
        let mut t = ValidatorRewardTracker::new();
        let v = [(vid(1), 0u128), (vid(2), 0)];
        assert_eq!(distribute_reward(&mut t, &v, 1000, &sw_cfg(0)),
                   Err(DistributionError::NoActiveValidators));
    }

    // ── 7. invalid_reward_zero ───────────────────────────────────────────
    #[test]
    fn invalid_reward_zero() {
        let mut t = ValidatorRewardTracker::new();
        let v = [(vid(1), 100u128)];
        assert_eq!(distribute_reward(&mut t, &v, 0, &eq_cfg(0)),
                   Err(DistributionError::InvalidRewardAmount));
    }

    // ── 8. no_active_validators ──────────────────────────────────────────
    #[test]
    fn no_active_validators() {
        let mut t = ValidatorRewardTracker::new();
        let v: &[([u8; 32], u128)] = &[];
        assert_eq!(distribute_reward(&mut t, v, 1000, &eq_cfg(0)),
                   Err(DistributionError::NoActiveValidators));
    }

    // ── 9. deterministic_distribution_order ──────────────────────────────
    #[test]
    fn deterministic_distribution_order() {
        let v = [(vid(30), 100u128), (vid(10), 100), (vid(20), 100)];
        let mut t1 = ValidatorRewardTracker::new();
        let r1 = ok!(distribute_reward(&mut t1, &v, 300, &eq_cfg(0)));
        assert_eq!(r1.distributions[0].0, vid(10));
        assert_eq!(r1.distributions[1].0, vid(20));
        assert_eq!(r1.distributions[2].0, vid(30));

        let mut t2 = ValidatorRewardTracker::new();
        let r2 = ok!(distribute_reward(&mut t2, &v, 300, &eq_cfg(0)));
        assert_eq!(r1.distributions, r2.distributions);
    }

    // ── 10. total_matches_reward ─────────────────────────────────────────
    #[test]
    fn total_matches_reward() {
        let v = [
            (vid(1), 333u128), (vid(2), 222),
            (vid(3), 111),     (vid(4), 444),
        ];
        let reward = 9999u128;
        for strat in [DistributionStrategy::EqualSplit, DistributionStrategy::StakeWeighted] {
            let mut t = ValidatorRewardTracker::new();
            let cfg = DistributionConfig { strategy: strat, min_distribution: 0 };
            let r = ok!(distribute_reward(&mut t, &v, reward, &cfg));
            assert_eq!(r.total_distributed + r.remainder, reward, "broken for {strat:?}");
        }
    }

    // ── 11. large_values_no_overflow ─────────────────────────────────────
    #[test]
    fn large_values_no_overflow() {
        let mut t = ValidatorRewardTracker::new();
        let big = u128::MAX / 4;
        let v = [(vid(1), big), (vid(2), big)];
        let r = ok!(distribute_reward(&mut t, &v, big, &sw_cfg(0)));
        assert_eq!(r.total_distributed + r.remainder, big);
    }

    // ── 12. remainder_correct_calculation ────────────────────────────────
    #[test]
    fn remainder_correct_calculation() {
        let mut t = ValidatorRewardTracker::new();
        let v: Vec<([u8; 32], u128)> = (1u8..=7).map(|i| (vid(i), 100u128)).collect();
        let r = ok!(distribute_reward(&mut t, &v, 100, &eq_cfg(0)));
        assert_eq!(r.distributions.len(), 7);
        for &(_, s) in &r.distributions { assert_eq!(s, 14); }
        assert_eq!(r.total_distributed, 98);
        assert_eq!(r.remainder, 2);
        assert_eq!(r.total_distributed + r.remainder, 100);
    }

    // ── 13. tracker_updated_correctly ────────────────────────────────────
    #[test]
    fn tracker_updated_correctly() {
        let mut t = ValidatorRewardTracker::new();
        let v = [(vid(1), 100u128), (vid(2), 100)];
        let _ = ok!(distribute_reward(&mut t, &v, 1000, &eq_cfg(0)));
        assert_eq!(t.get_pending(&vid(1)), 500);
        assert_eq!(t.get_pending(&vid(2)), 500);
        assert_eq!(t.total_distributed(), 1000);

        let _ = ok!(distribute_reward(&mut t, &v, 600, &eq_cfg(0)));
        assert_eq!(t.get_pending(&vid(1)), 800);
        assert_eq!(t.get_pending(&vid(2)), 800);
        assert_eq!(t.total_distributed(), 1600);
    }

    // ── 14. stake_weighted_min_distribution_filters ──────────────────────
    #[test]
    fn stake_weighted_min_distribution_filters() {
        let mut t = ValidatorRewardTracker::new();
        let v = [(vid(1), 990u128), (vid(2), 10)];
        let r = ok!(distribute_reward(&mut t, &v, 100, &sw_cfg(50)));
        let s1 = r.distributions.iter().find(|(id, _)| *id == vid(1)).map(|x| x.1);
        let s2 = r.distributions.iter().find(|(id, _)| *id == vid(2)).map(|x| x.1);
        assert_eq!(s1, Some(99));
        assert_eq!(s2, Some(0));
        assert_eq!(r.total_distributed, 99);
        assert_eq!(r.remainder, 1);
    }
}