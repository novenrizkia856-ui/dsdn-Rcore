//! # Reward Distribution Execution (CH.4)
//!
//! Layer ekonomi kritikal untuk eksekusi distribusi reward.
//!
//! ## Functions
//!
//! | Function | Mutates | Description |
//! |----------|---------|-------------|
//! | `compute_distribution` | No | Compute RewardDistribution from reward_base |
//! | `execute_reward_distribution` | Yes | Atomic credit: node + validator + treasury |
//! | `credit_balance` | Yes | Credit single address with saturating_add |
//! | `credit_treasury` | Yes | Credit treasury_balance with saturating_add |
//! | `release_challenge_reward` | Yes | Release deferred Compute reward after challenge |
//!
//! ## Atomicity Strategy
//!
//! `execute_reward_distribution` performs 3 credits in order:
//!
//! ```text
//! Step 1: credit node_reward → balances[node] + node_earnings[node]
//! Step 2: credit validator_reward → reward_pool
//! Step 3: credit treasury_reward → treasury_balance
//! ```
//!
//! If any step fails, all previous steps are rolled back via manual
//! subtraction (saturating_sub) to restore exact pre-call state.
//!
//! ## Why saturating_add
//!
//! `saturating_add` is used instead of `checked_add` + error because:
//!
//! 1. With `reward_base` capped at `MAX_REWARD_BASE` (1e12) and `u128::MAX` at ~3.4e38,
//!    overflow requires ~3.4e26 successful claims — physically impossible.
//! 2. Even in the theoretical impossible overflow case, saturating to `u128::MAX`
//!    is safer than panicking or silently losing funds.
//! 3. The overflow is still detectable (return value == input), so we can
//!    return `InvalidBalance` if capping actually occurs.
//!
//! ## Challenge Release Lifecycle
//!
//! ```text
//! ClaimReward (Compute) → PendingChallenge { status: Pending }
//!                              │
//!                 ┌────────────┴────────────┐
//!                 │                          │
//!    (no fraud + expired)           (fraud proof submitted)
//!                 │                          │
//!         mark_cleared()            mark_challenged()
//!                 │                          │
//!    release_challenge_reward()      mark_slashed()
//!         ↓                                  ↓
//!    Credits balances              Node reward slashed
//!    Removes challenge             (handled elsewhere)
//! ```
//!
//! ## Mapping: RewardDistribution ↔ FeeSplit (tokenomics.rs)
//!
//! | RewardDistribution | FeeSplit | Destination |
//! |--------------------|----------|-------------|
//! | `node_reward` | `node_share` (70%) | `balances[node]` + `node_earnings[node]` |
//! | `validator_reward` | `validator_share` (20%) | `reward_pool` |
//! | `treasury_reward` | `treasury_share` (10%) | `treasury_balance` |
//!
//! Both use identical constants from `economic_constants`:
//! `REWARD_NODE_PERCENT=70, REWARD_VALIDATOR_PERCENT=20, REWARD_TREASURY_PERCENT=10`.
//!
//! `RewardDistribution::compute()` produces values identical to
//! `tokenomics::calculate_fee_by_resource_class()` for the same input,
//! because both delegate to the same percentage constants and treasury-absorbs-remainder logic.

use dsdn_common::claim_validation::RewardDistribution;
use dsdn_common::challenge_state::ChallengeStatus;

use crate::state::ChainState;
use crate::types::Address;

// ════════════════════════════════════════════════════════════════════════════════
// ERROR TYPE
// ════════════════════════════════════════════════════════════════════════════════

/// Errors from reward distribution execution.
///
/// Each variant represents an unrecoverable failure.
/// On error, no state has been mutated (atomic rollback).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RewardExecutorError {
    /// Balance credit would saturate at u128::MAX.
    /// This is physically impossible under normal operation but
    /// detected for correctness.
    InvalidBalance,
    /// No pending challenge found for the given receipt hash.
    PendingChallengeNotFound {
        receipt_hash: [u8; 32],
    },
    /// Challenge is not yet eligible for release.
    /// Either status != Cleared or challenge period has not expired.
    ChallengeNotExpired {
        receipt_hash: [u8; 32],
    },
    /// Node operator address not found in service_node_index.
    /// Cannot determine credit destination.
    NodeNotFound {
        node_id: [u8; 32],
    },
}

impl std::fmt::Display for RewardExecutorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBalance => {
                write!(f, "Balance credit failed: would saturate at u128::MAX")
            }
            Self::PendingChallengeNotFound { .. } => {
                write!(f, "Pending challenge not found for receipt hash")
            }
            Self::ChallengeNotExpired { .. } => {
                write!(f, "Challenge not yet eligible for release")
            }
            Self::NodeNotFound { .. } => {
                write!(f, "Node operator address not found in registry")
            }
        }
    }
}

impl std::error::Error for RewardExecutorError {}

// ════════════════════════════════════════════════════════════════════════════════
// 1) compute_distribution
// ════════════════════════════════════════════════════════════════════════════════

/// Computes reward distribution from reward_base.
///
/// Delegates directly to [`RewardDistribution::compute`] or
/// [`RewardDistribution::with_anti_self_dealing`].
///
/// Produces values **identical** to `tokenomics::calculate_fee_by_resource_class()`
/// because both use the same constants from `economic_constants`:
///
/// - Normal: 70% node / 20% validator / 10% treasury
/// - Self-dealing: 0% node / 20% validator / 80% treasury
///
/// Treasury absorbs integer division remainder in both cases.
///
/// ## Invariant
///
/// `result.node_reward + result.validator_reward + result.treasury_reward == reward_base`
///
/// No additional logic. No manual formula reimplementation.
#[must_use]
pub fn compute_distribution(reward_base: u128, anti_self_dealing: bool) -> RewardDistribution {
    if anti_self_dealing {
        RewardDistribution::with_anti_self_dealing(reward_base)
    } else {
        RewardDistribution::compute(reward_base)
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// 2) credit_balance
// ════════════════════════════════════════════════════════════════════════════════

/// Credits `amount` to the balance of `address` using saturating arithmetic.
///
/// If balance was at u128::MAX and amount > 0, the add saturates.
/// This is detected and returns `InvalidBalance`.
///
/// Under normal operation this never fails: `MAX_REWARD_BASE` (1e12) is
/// negligible relative to `u128::MAX` (~3.4e38).
///
/// No unwrap. No panic. Deterministic.
pub fn credit_balance(
    state: &mut ChainState,
    address: &Address,
    amount: u128,
) -> Result<(), RewardExecutorError> {
    if amount == 0 {
        return Ok(());
    }

    let balance = state.balances.entry(*address).or_insert(0);
    let before = *balance;
    *balance = before.saturating_add(amount);

    // Detect saturation: if before + amount > u128::MAX, saturating_add
    // returns u128::MAX, which means we lost precision.
    if *balance != before.wrapping_add(amount) {
        // Rollback: restore original value.
        *balance = before;
        return Err(RewardExecutorError::InvalidBalance);
    }

    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// 3) credit_treasury
// ════════════════════════════════════════════════════════════════════════════════

/// Credits `amount` to `state.treasury_balance` using saturating arithmetic.
///
/// Treasury address is NOT hardcoded — it is the `treasury_balance` field
/// of ChainState, which is the protocol-level treasury accumulator.
///
/// Saturation detection identical to `credit_balance`.
///
/// No unwrap. No panic. Deterministic.
pub fn credit_treasury(
    state: &mut ChainState,
    amount: u128,
) -> Result<(), RewardExecutorError> {
    if amount == 0 {
        return Ok(());
    }

    let before = state.treasury_balance;
    state.treasury_balance = before.saturating_add(amount);

    if state.treasury_balance != before.wrapping_add(amount) {
        state.treasury_balance = before;
        return Err(RewardExecutorError::InvalidBalance);
    }

    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// INTERNAL: credit_reward_pool
// ════════════════════════════════════════════════════════════════════════════════

/// Credits `amount` to `state.reward_pool` (validator/proposer reward accumulator).
///
/// Same saturation detection as `credit_balance`.
fn credit_reward_pool(
    state: &mut ChainState,
    amount: u128,
) -> Result<(), RewardExecutorError> {
    if amount == 0 {
        return Ok(());
    }

    let before = state.reward_pool;
    state.reward_pool = before.saturating_add(amount);

    if state.reward_pool != before.wrapping_add(amount) {
        state.reward_pool = before;
        return Err(RewardExecutorError::InvalidBalance);
    }

    Ok(())
}

/// Credits `amount` to `state.node_earnings[address]`.
///
/// Tracks cumulative earnings per node (separate from liquid balance).
fn credit_node_earnings(
    state: &mut ChainState,
    address: &Address,
    amount: u128,
) -> Result<(), RewardExecutorError> {
    if amount == 0 {
        return Ok(());
    }

    let earnings = state.node_earnings.entry(*address).or_insert(0);
    let before = *earnings;
    *earnings = before.saturating_add(amount);

    if *earnings != before.wrapping_add(amount) {
        *earnings = before;
        return Err(RewardExecutorError::InvalidBalance);
    }

    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// 4) execute_reward_distribution
// ════════════════════════════════════════════════════════════════════════════════

/// Executes a reward distribution atomically.
///
/// ## Credit Order (CONSENSUS-CRITICAL)
///
/// 1. `node_reward` → `balances[node_address]` + `node_earnings[node_address]`
/// 2. `validator_reward` → `reward_pool`
/// 3. `treasury_reward` → `treasury_balance`
///
/// ## Failure Rollback
///
/// If step 2 fails: rollback step 1 (balance + earnings).
/// If step 3 fails: rollback step 1 and 2.
///
/// Partial credit is **impossible** — either all three succeed or
/// the entire operation is rolled back to the exact pre-call state.
///
/// ## Invariant
///
/// `distribution.node_reward + distribution.validator_reward + distribution.treasury_reward`
/// is credited as a unit. No double credit. No partial credit.
pub fn execute_reward_distribution(
    state: &mut ChainState,
    distribution: &RewardDistribution,
    node_address: &Address,
) -> Result<(), RewardExecutorError> {
    // ── STEP 1: Credit node ─────────────────────────────────────────────
    // Credit balance (liquid).
    credit_balance(state, node_address, distribution.node_reward)?;

    // Credit node_earnings (tracking).
    if let Err(e) = credit_node_earnings(state, node_address, distribution.node_reward) {
        // Rollback step 1a: undo balance credit.
        rollback_balance(state, node_address, distribution.node_reward);
        return Err(e);
    }

    // ── STEP 2: Credit validator reward pool ─────────────────────────────
    if let Err(e) = credit_reward_pool(state, distribution.validator_reward) {
        // Rollback step 1: undo balance + earnings.
        rollback_balance(state, node_address, distribution.node_reward);
        rollback_node_earnings(state, node_address, distribution.node_reward);
        return Err(e);
    }

    // ── STEP 3: Credit treasury ─────────────────────────────────────────
    if let Err(e) = credit_treasury(state, distribution.treasury_reward) {
        // Rollback step 1 and 2.
        rollback_balance(state, node_address, distribution.node_reward);
        rollback_node_earnings(state, node_address, distribution.node_reward);
        rollback_reward_pool(state, distribution.validator_reward);
        return Err(e);
    }

    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// ROLLBACK HELPERS
// ════════════════════════════════════════════════════════════════════════════════

/// Rollback: subtract amount from balance using saturating_sub.
///
/// Used only in error paths. If the balance entry doesn't exist
/// (shouldn't happen after credit), this is a no-op.
fn rollback_balance(state: &mut ChainState, address: &Address, amount: u128) {
    if let Some(balance) = state.balances.get_mut(address) {
        *balance = balance.saturating_sub(amount);
    }
}

/// Rollback: subtract amount from node_earnings.
fn rollback_node_earnings(state: &mut ChainState, address: &Address, amount: u128) {
    if let Some(earnings) = state.node_earnings.get_mut(address) {
        *earnings = earnings.saturating_sub(amount);
    }
}

/// Rollback: subtract amount from reward_pool.
fn rollback_reward_pool(state: &mut ChainState, amount: u128) {
    state.reward_pool = state.reward_pool.saturating_sub(amount);
}

// ════════════════════════════════════════════════════════════════════════════════
// 5) release_challenge_reward
// ════════════════════════════════════════════════════════════════════════════════

/// Releases a deferred Compute reward after the challenge period expires
/// without fraud proof.
///
/// ## Preconditions (ALL must be true)
///
/// 1. `receipt_hash` exists in `state.pending_challenges`
/// 2. Challenge `status == Cleared`
/// 3. Challenge `is_expired(now) == true`
///
/// If any precondition fails, returns error with zero state mutation.
///
/// ## Execution Steps
///
/// 1. Validate preconditions (read-only)
/// 2. Lookup node operator address from `service_node_index`
/// 3. Execute reward distribution (atomic)
/// 4. Remove challenge entry from `pending_challenges`
/// 5. Increment `total_rewards_distributed`
///
/// ## Why Step 4 After Step 3
///
/// Distribution (step 3) is the irreversible economic action.
/// If distribution fails, the challenge entry remains for retry.
/// If distribution succeeds, removal (step 4) is safe because the
/// rewards are already credited.
///
/// ## Rollback
///
/// Step 3 has internal rollback (execute_reward_distribution).
/// Steps 4-5 are infallible after step 3 succeeds.
pub fn release_challenge_reward(
    state: &mut ChainState,
    receipt_hash: &[u8; 32],
    now: u64,
) -> Result<RewardDistribution, RewardExecutorError> {
    // ── STEP 1: Validate preconditions (read-only) ──────────────────────

    // 1a. Challenge must exist.
    let challenge = state
        .pending_challenges
        .get(receipt_hash)
        .ok_or(RewardExecutorError::PendingChallengeNotFound {
            receipt_hash: *receipt_hash,
        })?;

    // 1b. Status must be Cleared.
    if challenge.status != ChallengeStatus::Cleared {
        return Err(RewardExecutorError::ChallengeNotExpired {
            receipt_hash: *receipt_hash,
        });
    }

    // 1c. Challenge period must be expired.
    if !challenge.is_expired(now) {
        return Err(RewardExecutorError::ChallengeNotExpired {
            receipt_hash: *receipt_hash,
        });
    }

    // Extract data we need before mutable borrow.
    let distribution = challenge.reward_distribution;
    let node_id = challenge.node_id;

    // ── STEP 2: Lookup node operator address ────────────────────────────

    let node_address = state
        .service_node_index
        .get(&node_id)
        .copied()
        .ok_or(RewardExecutorError::NodeNotFound { node_id })?;

    // ── STEP 3: Execute reward distribution (atomic) ────────────────────

    execute_reward_distribution(state, &distribution, &node_address)?;

    // ── STEP 4: Remove challenge entry (infallible after step 3) ────────

    state.pending_challenges.remove(receipt_hash);

    // ── STEP 5: Increment total_rewards_distributed ─────────────────────
    // Total = node_reward + validator_reward + treasury_reward == reward_base.

    let distribution_total = distribution
        .node_reward
        .saturating_add(distribution.validator_reward)
        .saturating_add(distribution.treasury_reward);

    state.total_rewards_distributed = state
        .total_rewards_distributed
        .saturating_add(distribution_total);

    Ok(distribution)
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use dsdn_common::claim_validation::RewardDistribution;
    use dsdn_common::challenge_state::{ChallengeStatus, PendingChallenge};

    // ── HELPERS ─────────────────────────────────────────────────────────

    fn addr(byte: u8) -> Address {
        Address::from_bytes([byte; 20])
    }

    const HASH_A: [u8; 32] = [0xAA; 32];
    const NODE_ID_A: [u8; 32] = [0x11; 32];

    fn make_cleared_challenge(distribution: RewardDistribution) -> PendingChallenge {
        let mut challenge = PendingChallenge::new(
            HASH_A,
            NODE_ID_A,
            distribution,
            1_000_000, // start time
        );
        challenge.mark_cleared();
        challenge
    }

    // ════════════════════════════════════════════════════════════════════
    // compute_distribution
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn compute_distribution_normal_70_20_10() {
        let d = compute_distribution(1000, false);
        assert_eq!(d.node_reward, 700);
        assert_eq!(d.validator_reward, 200);
        assert_eq!(d.treasury_reward, 100);
    }

    #[test]
    fn compute_distribution_self_dealing_0_20_80() {
        let d = compute_distribution(1000, true);
        assert_eq!(d.node_reward, 0);
        assert_eq!(d.validator_reward, 200);
        assert_eq!(d.treasury_reward, 800);
    }

    #[test]
    fn compute_distribution_sum_invariant() {
        for base in [0, 1, 3, 7, 10, 99, 100, 999, 1_000_000, 1_000_000_000_000] {
            let d = compute_distribution(base, false);
            assert_eq!(
                d.node_reward + d.validator_reward + d.treasury_reward,
                base,
                "normal sum invariant failed for base={}",
                base
            );

            let d2 = compute_distribution(base, true);
            assert_eq!(
                d2.node_reward + d2.validator_reward + d2.treasury_reward,
                base,
                "self-dealing sum invariant failed for base={}",
                base
            );
        }
    }

    #[test]
    fn compute_distribution_identical_to_reward_distribution() {
        // Verify our function produces identical output to the underlying type.
        for base in [0, 1, 100, 1000, 999_999] {
            let ours = compute_distribution(base, false);
            let theirs = RewardDistribution::compute(base);
            assert_eq!(ours, theirs);

            let ours_sd = compute_distribution(base, true);
            let theirs_sd = RewardDistribution::with_anti_self_dealing(base);
            assert_eq!(ours_sd, theirs_sd);
        }
    }

    // ════════════════════════════════════════════════════════════════════
    // credit_balance
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn credit_balance_creates_entry() {
        let mut state = ChainState::new();
        let a = addr(0x01);
        assert!(credit_balance(&mut state, &a, 500).is_ok());
        assert_eq!(*state.balances.get(&a).unwrap_or(&0), 500);
    }

    #[test]
    fn credit_balance_accumulates() {
        let mut state = ChainState::new();
        let a = addr(0x01);
        credit_balance(&mut state, &a, 300).ok();
        credit_balance(&mut state, &a, 200).ok();
        assert_eq!(*state.balances.get(&a).unwrap_or(&0), 500);
    }

    #[test]
    fn credit_balance_zero_is_noop() {
        let mut state = ChainState::new();
        let a = addr(0x01);
        assert!(credit_balance(&mut state, &a, 0).is_ok());
        assert!(state.balances.get(&a).is_none());
    }

    #[test]
    fn credit_balance_detects_saturation() {
        let mut state = ChainState::new();
        let a = addr(0x01);
        state.balances.insert(a, u128::MAX);
        let result = credit_balance(&mut state, &a, 1);
        assert_eq!(result, Err(RewardExecutorError::InvalidBalance));
        // Rollback: balance unchanged.
        assert_eq!(*state.balances.get(&a).unwrap_or(&0), u128::MAX);
    }

    // ════════════════════════════════════════════════════════════════════
    // credit_treasury
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn credit_treasury_increments() {
        let mut state = ChainState::new();
        assert!(credit_treasury(&mut state, 100).is_ok());
        assert_eq!(state.treasury_balance, 100);
        assert!(credit_treasury(&mut state, 50).is_ok());
        assert_eq!(state.treasury_balance, 150);
    }

    #[test]
    fn credit_treasury_zero_is_noop() {
        let mut state = ChainState::new();
        state.treasury_balance = 42;
        assert!(credit_treasury(&mut state, 0).is_ok());
        assert_eq!(state.treasury_balance, 42);
    }

    #[test]
    fn credit_treasury_detects_saturation() {
        let mut state = ChainState::new();
        state.treasury_balance = u128::MAX;
        let result = credit_treasury(&mut state, 1);
        assert_eq!(result, Err(RewardExecutorError::InvalidBalance));
        assert_eq!(state.treasury_balance, u128::MAX);
    }

    // ════════════════════════════════════════════════════════════════════
    // execute_reward_distribution
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn execute_distribution_normal() {
        let mut state = ChainState::new();
        let a = addr(0x01);
        let dist = RewardDistribution::compute(1000);

        assert!(execute_reward_distribution(&mut state, &dist, &a).is_ok());

        assert_eq!(*state.balances.get(&a).unwrap_or(&0), 700);
        assert_eq!(*state.node_earnings.get(&a).unwrap_or(&0), 700);
        assert_eq!(state.reward_pool, 200);
        assert_eq!(state.treasury_balance, 100);
    }

    #[test]
    fn execute_distribution_self_dealing() {
        let mut state = ChainState::new();
        let a = addr(0x01);
        let dist = RewardDistribution::with_anti_self_dealing(1000);

        assert!(execute_reward_distribution(&mut state, &dist, &a).is_ok());

        assert_eq!(*state.balances.get(&a).unwrap_or(&0), 0);
        assert_eq!(*state.node_earnings.get(&a).unwrap_or(&0), 0);
        assert_eq!(state.reward_pool, 200);
        assert_eq!(state.treasury_balance, 800);
    }

    #[test]
    fn execute_distribution_accumulates() {
        let mut state = ChainState::new();
        let a = addr(0x01);
        let dist = RewardDistribution::compute(1000);

        execute_reward_distribution(&mut state, &dist, &a).ok();
        execute_reward_distribution(&mut state, &dist, &a).ok();

        assert_eq!(*state.balances.get(&a).unwrap_or(&0), 1400);
        assert_eq!(*state.node_earnings.get(&a).unwrap_or(&0), 1400);
        assert_eq!(state.reward_pool, 400);
        assert_eq!(state.treasury_balance, 200);
    }

    #[test]
    fn execute_distribution_rollback_on_treasury_saturation() {
        let mut state = ChainState::new();
        let a = addr(0x01);
        state.treasury_balance = u128::MAX;

        let dist = RewardDistribution::compute(1000);
        let result = execute_reward_distribution(&mut state, &dist, &a);
        assert_eq!(result, Err(RewardExecutorError::InvalidBalance));

        // Verify rollback: no partial credits.
        assert_eq!(*state.balances.get(&a).unwrap_or(&0), 0);
        assert_eq!(*state.node_earnings.get(&a).unwrap_or(&0), 0);
        assert_eq!(state.reward_pool, 0);
        assert_eq!(state.treasury_balance, u128::MAX);
    }

    #[test]
    fn execute_distribution_rollback_on_reward_pool_saturation() {
        let mut state = ChainState::new();
        let a = addr(0x01);
        state.reward_pool = u128::MAX;

        let dist = RewardDistribution::compute(1000);
        let result = execute_reward_distribution(&mut state, &dist, &a);
        assert_eq!(result, Err(RewardExecutorError::InvalidBalance));

        // Verify rollback: node credit was undone.
        assert_eq!(*state.balances.get(&a).unwrap_or(&0), 0);
        assert_eq!(*state.node_earnings.get(&a).unwrap_or(&0), 0);
        assert_eq!(state.reward_pool, u128::MAX);
    }

    #[test]
    fn execute_distribution_zero_base() {
        let mut state = ChainState::new();
        let a = addr(0x01);
        let dist = RewardDistribution::compute(0);

        assert!(execute_reward_distribution(&mut state, &dist, &a).is_ok());

        assert!(state.balances.get(&a).is_none());
        assert_eq!(state.reward_pool, 0);
        assert_eq!(state.treasury_balance, 0);
    }

    // ════════════════════════════════════════════════════════════════════
    // release_challenge_reward
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn release_challenge_not_found() {
        let mut state = ChainState::new();
        let result = release_challenge_reward(&mut state, &HASH_A, 9_999_999);
        assert_eq!(
            result,
            Err(RewardExecutorError::PendingChallengeNotFound {
                receipt_hash: HASH_A,
            })
        );
    }

    #[test]
    fn release_challenge_not_cleared() {
        let mut state = ChainState::new();
        let dist = RewardDistribution::compute(1000);
        // Insert as Pending (not Cleared).
        let challenge = PendingChallenge::new(HASH_A, NODE_ID_A, dist, 1_000_000);
        state.pending_challenges.insert(HASH_A, challenge);

        let result = release_challenge_reward(&mut state, &HASH_A, 9_999_999);
        assert_eq!(
            result,
            Err(RewardExecutorError::ChallengeNotExpired {
                receipt_hash: HASH_A,
            })
        );
    }

    #[test]
    fn release_challenge_not_expired() {
        let mut state = ChainState::new();
        let dist = RewardDistribution::compute(1000);
        let mut challenge = PendingChallenge::new(HASH_A, NODE_ID_A, dist, 1_000_000);
        challenge.mark_cleared();
        state.pending_challenges.insert(HASH_A, challenge);

        // now < challenge_end → not expired
        let result = release_challenge_reward(&mut state, &HASH_A, 1_000_001);
        assert_eq!(
            result,
            Err(RewardExecutorError::ChallengeNotExpired {
                receipt_hash: HASH_A,
            })
        );
    }

    #[test]
    fn release_challenge_node_not_found() {
        let mut state = ChainState::new();
        let dist = RewardDistribution::compute(1000);
        let challenge = make_cleared_challenge(dist);
        state.pending_challenges.insert(HASH_A, challenge);
        // No service_node_index entry for NODE_ID_A.

        let result = release_challenge_reward(&mut state, &HASH_A, 9_999_999);
        assert_eq!(
            result,
            Err(RewardExecutorError::NodeNotFound { node_id: NODE_ID_A })
        );
        // Challenge NOT removed (distribution failed).
        assert!(state.pending_challenges.contains_key(&HASH_A));
    }

    #[test]
    fn release_challenge_success() {
        let mut state = ChainState::new();
        let a = addr(0x42);
        let dist = RewardDistribution::compute(1000);

        // Register node in index.
        state.service_node_index.insert(NODE_ID_A, a);

        // Insert cleared challenge.
        let challenge = make_cleared_challenge(dist);
        state.pending_challenges.insert(HASH_A, challenge);

        // Release at time well past expiry.
        let result = release_challenge_reward(&mut state, &HASH_A, 9_999_999);
        assert!(result.is_ok());
        let released = result.unwrap();
        assert_eq!(released, dist);

        // Verify credits.
        assert_eq!(*state.balances.get(&a).unwrap_or(&0), 700);
        assert_eq!(*state.node_earnings.get(&a).unwrap_or(&0), 700);
        assert_eq!(state.reward_pool, 200);
        assert_eq!(state.treasury_balance, 100);

        // Challenge removed.
        assert!(!state.pending_challenges.contains_key(&HASH_A));

        // Counter incremented.
        assert_eq!(state.total_rewards_distributed, 1000);
    }

    #[test]
    fn release_challenge_self_dealing_distribution() {
        let mut state = ChainState::new();
        let a = addr(0x42);
        let dist = RewardDistribution::with_anti_self_dealing(1000);

        state.service_node_index.insert(NODE_ID_A, a);
        let challenge = make_cleared_challenge(dist);
        state.pending_challenges.insert(HASH_A, challenge);

        let result = release_challenge_reward(&mut state, &HASH_A, 9_999_999);
        assert!(result.is_ok());

        assert_eq!(*state.balances.get(&a).unwrap_or(&0), 0);
        assert_eq!(state.reward_pool, 200);
        assert_eq!(state.treasury_balance, 800);
        assert_eq!(state.total_rewards_distributed, 1000);
    }

    #[test]
    fn release_challenge_double_release_fails() {
        let mut state = ChainState::new();
        let a = addr(0x42);
        let dist = RewardDistribution::compute(1000);

        state.service_node_index.insert(NODE_ID_A, a);
        let challenge = make_cleared_challenge(dist);
        state.pending_challenges.insert(HASH_A, challenge);

        // First release: OK.
        assert!(release_challenge_reward(&mut state, &HASH_A, 9_999_999).is_ok());

        // Second release: challenge gone.
        let result = release_challenge_reward(&mut state, &HASH_A, 9_999_999);
        assert_eq!(
            result,
            Err(RewardExecutorError::PendingChallengeNotFound {
                receipt_hash: HASH_A,
            })
        );

        // No double credit.
        assert_eq!(*state.balances.get(&a).unwrap_or(&0), 700);
        assert_eq!(state.total_rewards_distributed, 1000);
    }

    // ════════════════════════════════════════════════════════════════════
    // Determinism
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn deterministic_multiple_calls() {
        let dist = compute_distribution(12345, false);
        let dist2 = compute_distribution(12345, false);
        assert_eq!(dist, dist2);
    }

    // ════════════════════════════════════════════════════════════════════
    // Edge cases
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn distribution_total_equals_base() {
        let dist = RewardDistribution::compute(1000);
        let total = dist
            .node_reward
            .saturating_add(dist.validator_reward)
            .saturating_add(dist.treasury_reward);
        assert_eq!(total, 1000);
    }

    #[test]
    fn rollback_preserves_exact_state() {
        let mut state = ChainState::new();
        let a = addr(0x01);
        state.balances.insert(a, 500);
        state.node_earnings.insert(a, 100);
        state.reward_pool = 200;
        state.treasury_balance = u128::MAX; // Force treasury failure.

        let dist = RewardDistribution::compute(1000);
        let result = execute_reward_distribution(&mut state, &dist, &a);
        assert!(result.is_err());

        // State restored exactly.
        assert_eq!(*state.balances.get(&a).unwrap_or(&0), 500);
        assert_eq!(*state.node_earnings.get(&a).unwrap_or(&0), 100);
        assert_eq!(state.reward_pool, 200);
        assert_eq!(state.treasury_balance, u128::MAX);
    }
}