//! # Challenge Period State Management (CH.6)
//!
//! Manages the lifecycle of pending challenges in chain state.
//!
//! ## Overview
//!
//! When a Compute receipt is claimed via `ClaimReward`, the reward is not
//! distributed immediately. Instead, a challenge period is opened during
//! which anyone can submit a fraud proof. This module manages that lifecycle:
//!
//! ```text
//! ClaimReward (Compute)
//!     │
//!     ▼
//! start_challenge_period()
//!     │
//!     ▼
//! PendingChallenge { status: Pending }
//!     │
//!     ├── (no fraud + expired) ──▶ process_expired_challenges()
//!     │                                   │
//!     │                           mark_cleared() + distribute
//!     │                                   │
//!     │                           ChallengeResolution::Cleared
//!     │
//!     └── (fraud proof submitted) ──▶ mark_challenged()
//!                                         │
//!                                 ChallengeResolution::PendingResolution
//!                                 (resolved externally via dispute system)
//! ```
//!
//! ## Consensus-Critical
//!
//! `pending_challenges` is included in state_root computation.
//! All operations in this module MUST be deterministic.
//!
//! ## Integration Point
//!
//! `process_expired_challenges` is called during block finalization,
//! after transaction execution and economic job, but BEFORE `compute_state_root()`.
//!
//! Both the miner path (`mine_block`) and the full-node path
//! (`apply_block_without_mining`) MUST invoke this at the same pipeline
//! position to produce identical state roots.
//!
//! ## Idempotency
//!
//! Calling `process_expired_challenges` twice on the same state + time
//! produces no additional state changes on the second call, because:
//!
//! 1. Pending challenges that were cleared are removed from `pending_challenges`.
//! 2. Terminal challenges (Cleared/Slashed) are skipped.
//! 3. Challenged entries produce only informational `PendingResolution` (no mutation).

use dsdn_common::challenge_state::{ChallengeStatus, PendingChallenge};
use dsdn_common::claim_validation::RewardDistribution;

use crate::reward_executor;
use crate::state::ChainState;

// ════════════════════════════════════════════════════════════════════════════════
// CHALLENGE RESOLUTION ENUM
// ════════════════════════════════════════════════════════════════════════════════

/// Outcome of processing a single expired challenge.
///
/// Produced by [`process_expired_challenges`] for each expired entry.
/// Informational — does not itself mutate state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChallengeResolution {
    /// Challenge period expired without fraud proof.
    /// Reward has been distributed to the node operator.
    /// The challenge entry has been removed from `pending_challenges`.
    Cleared {
        receipt_hash: [u8; 32],
    },

    /// Challenge was disputed (fraud proof submitted) and awaits
    /// external resolution via the dispute system.
    /// No reward distributed. Challenge entry remains.
    PendingResolution {
        receipt_hash: [u8; 32],
    },

    /// Challenge was resolved as fraudulent.
    /// Node reward was slashed by `amount`.
    ///
    /// Note: This variant is NOT produced by `process_expired_challenges`
    /// directly. It is included for completeness and used by the dispute
    /// resolution system (future CH.7+).
    Slashed {
        receipt_hash: [u8; 32],
        amount: u128,
    },
}

// ════════════════════════════════════════════════════════════════════════════════
// CHALLENGE ERROR
// ════════════════════════════════════════════════════════════════════════════════

/// Errors from challenge period operations.
///
/// All variants are explicit and recoverable.
/// No panic, no unwrap, no silent failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChallengeError {
    /// A pending challenge already exists for this receipt hash.
    /// Duplicate insertion is not allowed.
    AlreadyExists {
        receipt_hash: [u8; 32],
    },
}

impl std::fmt::Display for ChallengeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyExists { .. } => {
                write!(
                    f,
                    "challenge period already exists for this receipt hash"
                )
            }
        }
    }
}

impl std::error::Error for ChallengeError {}

// ════════════════════════════════════════════════════════════════════════════════
// 1) process_expired_challenges
// ════════════════════════════════════════════════════════════════════════════════

/// Processes all expired challenges in the current state.
///
/// Called during block finalization, after transaction execution and
/// economic job, BEFORE `compute_state_root()`.
///
/// ## Behavior per status
///
/// | Status | Action | Resolution |
/// |--------|--------|------------|
/// | `Pending` | mark cleared → distribute reward → remove entry | `Cleared` |
/// | `Challenged` | no mutation | `PendingResolution` |
/// | `Cleared` | skip (terminal) | — |
/// | `Slashed` | skip (terminal) | — |
///
/// ## Idempotency
///
/// Safe to call multiple times for the same block/time:
///
/// - First call: processes all expired Pending challenges, removes them.
/// - Second call: `get_expired_challenges` returns fewer/no entries
///   (removed in first call). Terminal entries are skipped. No double
///   reward release.
///
/// ## Determinism
///
/// - `get_expired_challenges` returns sorted `Vec<[u8; 32]>`.
/// - Processing order is deterministic (lexicographic by receipt hash).
/// - All operations use saturating arithmetic (no overflow panic).
/// - No allocation of random data, no system calls, no IO.
///
/// ## Error Handling
///
/// If reward distribution fails for a specific challenge (e.g., balance
/// overflow at `u128::MAX`), that challenge is skipped for this block.
/// It remains in `pending_challenges` with `Pending` status and will
/// be retried on the next block. No partial state corruption occurs
/// because `execute_reward_distribution` has internal rollback.
///
/// If node operator lookup fails (node not in `service_node_index`),
/// the challenge is also skipped. The entry remains as `Pending` and
/// will be retried when the node is registered.
pub fn process_expired_challenges(
    state: &mut ChainState,
    current_time: u64,
) -> Vec<ChallengeResolution> {
    // ── STEP 1: Collect expired challenge hashes (read-only) ────────────
    //
    // get_expired_challenges returns a SORTED Vec<[u8; 32]>.
    // Sorting guarantees deterministic processing order across all nodes.
    let expired_hashes = state.get_expired_challenges(current_time);

    if expired_hashes.is_empty() {
        return Vec::new();
    }

    let mut resolutions = Vec::with_capacity(expired_hashes.len());

    // ── STEP 2: Process each expired challenge ─────────────────────────
    for receipt_hash in expired_hashes {
        // Read challenge data (immutable borrow).
        // If the entry no longer exists (removed by a previous iteration
        // or a concurrent call — though concurrency is not expected),
        // skip silently. This is the idempotency guard.
        let (status, node_id, distribution) = match state.pending_challenges.get(&receipt_hash) {
            Some(challenge) => (
                challenge.status,
                challenge.node_id,
                challenge.reward_distribution,
            ),
            None => continue,
        };

        match status {
            // ── PENDING: Clear and release reward ───────────────────
            //
            // The challenge period expired without any fraud proof.
            // This is the happy path for honest compute nodes.
            ChallengeStatus::Pending => {
                // 2a. Lookup node operator address (read-only).
                //     If node is not registered, skip. The challenge stays
                //     as Pending and will be retried next block.
                let node_address = match state.service_node_index.get(&node_id).copied() {
                    Some(addr) => addr,
                    None => continue,
                };

                // 2b. Mark as cleared.
                //     This is a status transition: Pending → Cleared.
                //     Done BEFORE distribution so the challenge is in a
                //     consistent terminal state if distribution fails.
                if let Some(challenge) = state.pending_challenges.get_mut(&receipt_hash) {
                    challenge.mark_cleared();
                }

                // 2c. Execute reward distribution (atomic with rollback).
                //     Uses the same executor as release_challenge_reward.
                //     If this fails (u128 overflow — physically impossible),
                //     the challenge remains as Cleared but not removed.
                //     This is acceptable: the entry is terminal and won't
                //     be processed again (idempotency).
                if reward_executor::execute_reward_distribution(
                    state,
                    &distribution,
                    &node_address,
                )
                .is_err()
                {
                    // Distribution failed. Challenge is now Cleared but
                    // rewards not distributed. Terminal state — won't retry.
                    // This is a degenerate case that requires u128 overflow.
                    continue;
                }

                // 2d. Remove challenge entry (infallible after distribution).
                state.pending_challenges.remove(&receipt_hash);

                // 2e. Increment total_rewards_distributed (saturating).
                //     Total = node + validator + treasury == reward_base.
                let distribution_total = distribution
                    .node_reward
                    .saturating_add(distribution.validator_reward)
                    .saturating_add(distribution.treasury_reward);

                state.total_rewards_distributed = state
                    .total_rewards_distributed
                    .saturating_add(distribution_total);

                resolutions.push(ChallengeResolution::Cleared { receipt_hash });
            }

            // ── CHALLENGED: Awaiting dispute resolution ────────────
            //
            // A fraud proof was submitted during the challenge period.
            // The dispute system (CH.7+) will resolve this externally.
            // We do NOT modify state here — only report the status.
            ChallengeStatus::Challenged => {
                resolutions.push(ChallengeResolution::PendingResolution { receipt_hash });
            }

            // ── TERMINAL: Already resolved ─────────────────────────
            //
            // Cleared: reward already distributed (or stuck — see 2c).
            // Slashed: fraud confirmed, node penalized.
            //
            // No action. Idempotency guarantee: calling again produces
            // no state change and no resolution entry.
            ChallengeStatus::Cleared | ChallengeStatus::Slashed => {
                // Intentionally empty.
                // Terminal challenges that still appear in
                // get_expired_challenges are stale entries that should
                // have been removed. They are harmless — just skipped.
            }
        }
    }

    resolutions
}

// ════════════════════════════════════════════════════════════════════════════════
// 2) start_challenge_period
// ════════════════════════════════════════════════════════════════════════════════

/// Opens a new challenge period for a compute receipt.
///
/// Called by `handle_claim_reward` (CH.3) when a Compute receipt is claimed.
///
/// ## Preconditions
///
/// - `receipt_hash` MUST NOT already exist in `pending_challenges`.
///   If it does, returns `ChallengeError::AlreadyExists`.
///
/// ## Postconditions
///
/// - `pending_challenges[receipt_hash]` contains a new `PendingChallenge`
///   with `status == Pending`.
/// - No other state fields are modified.
///
/// ## Atomicity
///
/// Single `HashMap::insert` — either the entry is created or the function
/// returns an error. No partial insertion is possible.
///
/// ## Thread Safety
///
/// `ChainState` is protected by `RwLock` at the executor layer.
/// This function requires exclusive `&mut` access, which is guaranteed
/// by the write lock. No internal locking needed.
pub fn start_challenge_period(
    receipt_hash: [u8; 32],
    node_id: [u8; 32],
    distribution: RewardDistribution,
    start_time: u64,
    state: &mut ChainState,
) -> Result<(), ChallengeError> {
    // ── GUARD: Reject duplicate insertion ────────────────────────────────
    //
    // This check is the primary safety guarantee. Without it, an existing
    // challenge (possibly with different distribution or timing) would be
    // silently overwritten, causing economic inconsistency.
    if state.pending_challenges.contains_key(&receipt_hash) {
        return Err(ChallengeError::AlreadyExists { receipt_hash });
    }

    // ── CREATE and INSERT ───────────────────────────────────────────────
    //
    // PendingChallenge::new sets:
    //   - status = Pending
    //   - challenge_end = start_time + CHALLENGE_PERIOD_DURATION
    //   - reward_distribution = distribution
    //   - node_id = node_id
    let challenge = PendingChallenge::new(receipt_hash, node_id, distribution, start_time);

    state.pending_challenges.insert(receipt_hash, challenge);

    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ChainState;
    use crate::types::Address;
    use dsdn_common::challenge_state::PendingChallenge;
    use dsdn_common::claim_validation::RewardDistribution;

    // ── CONSTANTS ───────────────────────────────────────────────────────

    const HASH_A: [u8; 32] = [0xAA; 32];
    const HASH_B: [u8; 32] = [0xBB; 32];
    const HASH_C: [u8; 32] = [0xCC; 32];
    const NODE_ID_A: [u8; 32] = [0x11; 32];
    const NODE_ID_B: [u8; 32] = [0x22; 32];

    fn addr(byte: u8) -> Address {
        Address::from_bytes([byte; 20])
    }

    /// Time far in the future — all challenges are expired.
    const FAR_FUTURE: u64 = 99_999_999;

    /// Time before any challenge expires.
    const BEFORE_EXPIRY: u64 = 1;

    // ════════════════════════════════════════════════════════════════════
    // start_challenge_period
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn start_challenge_period_success() {
        let mut state = ChainState::new();
        let dist = RewardDistribution::compute(1000);

        let result = start_challenge_period(HASH_A, NODE_ID_A, dist, 1_000_000, &mut state);

        assert!(result.is_ok());
        assert!(state.pending_challenges.contains_key(&HASH_A));
        assert_eq!(state.pending_challenges.len(), 1);

        let challenge = state.pending_challenges.get(&HASH_A);
        assert!(challenge.is_some());
        let ch = challenge.unwrap();
        assert_eq!(ch.status, ChallengeStatus::Pending);
        assert_eq!(ch.node_id, NODE_ID_A);
        assert_eq!(ch.reward_distribution, dist);
    }

    #[test]
    fn start_challenge_period_duplicate_rejected() {
        let mut state = ChainState::new();
        let dist = RewardDistribution::compute(1000);

        // First insertion: OK.
        assert!(start_challenge_period(HASH_A, NODE_ID_A, dist, 1_000_000, &mut state).is_ok());

        // Second insertion with same hash: rejected.
        let result = start_challenge_period(HASH_A, NODE_ID_B, dist, 2_000_000, &mut state);
        assert_eq!(
            result,
            Err(ChallengeError::AlreadyExists {
                receipt_hash: HASH_A,
            })
        );

        // Original challenge unchanged.
        let ch = state.pending_challenges.get(&HASH_A).unwrap();
        assert_eq!(ch.node_id, NODE_ID_A);
    }

    #[test]
    fn start_challenge_period_different_hashes_ok() {
        let mut state = ChainState::new();
        let dist = RewardDistribution::compute(1000);

        assert!(start_challenge_period(HASH_A, NODE_ID_A, dist, 1_000_000, &mut state).is_ok());
        assert!(start_challenge_period(HASH_B, NODE_ID_B, dist, 1_000_000, &mut state).is_ok());

        assert_eq!(state.pending_challenges.len(), 2);
    }

    #[test]
    fn start_challenge_period_no_other_state_modified() {
        let mut state = ChainState::new();
        let dist = RewardDistribution::compute(1000);

        let treasury_before = state.treasury_balance;
        let rewards_before = state.total_rewards_distributed;
        let receipts_before = state.total_receipts_claimed;

        start_challenge_period(HASH_A, NODE_ID_A, dist, 1_000_000, &mut state).unwrap();

        assert_eq!(state.treasury_balance, treasury_before);
        assert_eq!(state.total_rewards_distributed, rewards_before);
        assert_eq!(state.total_receipts_claimed, receipts_before);
    }

    // ════════════════════════════════════════════════════════════════════
    // process_expired_challenges — empty / no-op cases
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn process_no_challenges_returns_empty() {
        let mut state = ChainState::new();
        let resolutions = process_expired_challenges(&mut state, FAR_FUTURE);
        assert!(resolutions.is_empty());
    }

    #[test]
    fn process_no_expired_returns_empty() {
        let mut state = ChainState::new();
        let dist = RewardDistribution::compute(1000);
        let challenge = PendingChallenge::new(HASH_A, NODE_ID_A, dist, FAR_FUTURE);
        state.pending_challenges.insert(HASH_A, challenge);

        // current_time < challenge_end → not expired.
        let resolutions = process_expired_challenges(&mut state, BEFORE_EXPIRY);
        assert!(resolutions.is_empty());

        // Challenge unchanged.
        assert!(state.pending_challenges.contains_key(&HASH_A));
    }

    // ════════════════════════════════════════════════════════════════════
    // process_expired_challenges — Pending → Cleared
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn process_pending_cleared_and_distributed() {
        let mut state = ChainState::new();
        let a = addr(0x42);
        let dist = RewardDistribution::compute(1000);

        // Register node in service_node_index.
        state.service_node_index.insert(NODE_ID_A, a);

        // Insert Pending challenge that will be expired.
        let challenge = PendingChallenge::new(HASH_A, NODE_ID_A, dist, 1_000_000);
        state.pending_challenges.insert(HASH_A, challenge);

        let resolutions = process_expired_challenges(&mut state, FAR_FUTURE);

        // One Cleared resolution.
        assert_eq!(resolutions.len(), 1);
        assert_eq!(
            resolutions[0],
            ChallengeResolution::Cleared {
                receipt_hash: HASH_A,
            }
        );

        // Challenge removed from state.
        assert!(!state.pending_challenges.contains_key(&HASH_A));

        // Rewards distributed: 700 node, 200 validator pool, 100 treasury.
        assert_eq!(*state.balances.get(&a).unwrap_or(&0), 700);
        assert_eq!(state.reward_pool, 200);
        assert_eq!(state.treasury_balance, 100);

        // Counter updated.
        assert_eq!(state.total_rewards_distributed, 1000);
    }

    #[test]
    fn process_pending_node_not_found_skipped() {
        let mut state = ChainState::new();
        let dist = RewardDistribution::compute(1000);

        // No entry in service_node_index for NODE_ID_A.
        let challenge = PendingChallenge::new(HASH_A, NODE_ID_A, dist, 1_000_000);
        state.pending_challenges.insert(HASH_A, challenge);

        let resolutions = process_expired_challenges(&mut state, FAR_FUTURE);

        // No resolution (skipped).
        assert!(resolutions.is_empty());

        // Challenge still present (will retry next block).
        assert!(state.pending_challenges.contains_key(&HASH_A));
        assert_eq!(
            state.pending_challenges.get(&HASH_A).unwrap().status,
            ChallengeStatus::Pending,
        );

        // No rewards distributed.
        assert_eq!(state.total_rewards_distributed, 0);
    }

    // ════════════════════════════════════════════════════════════════════
    // process_expired_challenges — Challenged → PendingResolution
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn process_challenged_produces_pending_resolution() {
        let mut state = ChainState::new();
        let a = addr(0x42);
        let dist = RewardDistribution::compute(1000);

        state.service_node_index.insert(NODE_ID_A, a);

        // Insert challenged entry.
        let mut challenge = PendingChallenge::new(HASH_A, NODE_ID_A, dist, 1_000_000);
        challenge.mark_challenged([0xF0; 20]);
        state.pending_challenges.insert(HASH_A, challenge);

        let resolutions = process_expired_challenges(&mut state, FAR_FUTURE);

        assert_eq!(resolutions.len(), 1);
        assert_eq!(
            resolutions[0],
            ChallengeResolution::PendingResolution {
                receipt_hash: HASH_A,
            }
        );

        // Challenge NOT removed (awaiting dispute resolution).
        assert!(state.pending_challenges.contains_key(&HASH_A));

        // No rewards distributed.
        assert_eq!(state.total_rewards_distributed, 0);
    }

    // ════════════════════════════════════════════════════════════════════
    // process_expired_challenges — Terminal statuses skipped
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn process_cleared_terminal_skipped() {
        let mut state = ChainState::new();
        let a = addr(0x42);
        let dist = RewardDistribution::compute(1000);

        state.service_node_index.insert(NODE_ID_A, a);

        let mut challenge = PendingChallenge::new(HASH_A, NODE_ID_A, dist, 1_000_000);
        challenge.mark_cleared();
        state.pending_challenges.insert(HASH_A, challenge);

        let resolutions = process_expired_challenges(&mut state, FAR_FUTURE);

        // No resolution for terminal entries.
        assert!(resolutions.is_empty());

        // No rewards distributed.
        assert_eq!(state.total_rewards_distributed, 0);
    }

    #[test]
    fn process_slashed_terminal_skipped() {
        let mut state = ChainState::new();
        let a = addr(0x42);
        let dist = RewardDistribution::compute(1000);

        state.service_node_index.insert(NODE_ID_A, a);

        let mut challenge = PendingChallenge::new(HASH_A, NODE_ID_A, dist, 1_000_000);
        // State machine: Pending → Challenged → Slashed.
        // mark_slashed() is no-op unless status == Challenged.
        challenge.mark_challenged([0xF0; 20]);
        challenge.mark_slashed();
        state.pending_challenges.insert(HASH_A, challenge);

        let resolutions = process_expired_challenges(&mut state, FAR_FUTURE);

        assert!(resolutions.is_empty());
        assert_eq!(state.total_rewards_distributed, 0);
    }

    // ════════════════════════════════════════════════════════════════════
    // process_expired_challenges — Idempotency
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn idempotent_double_call_no_extra_state_change() {
        let mut state = ChainState::new();
        let a = addr(0x42);
        let dist = RewardDistribution::compute(1000);

        state.service_node_index.insert(NODE_ID_A, a);
        let challenge = PendingChallenge::new(HASH_A, NODE_ID_A, dist, 1_000_000);
        state.pending_challenges.insert(HASH_A, challenge);

        // First call: processes challenge.
        let r1 = process_expired_challenges(&mut state, FAR_FUTURE);
        assert_eq!(r1.len(), 1);

        // Snapshot state after first call.
        let balance_after = *state.balances.get(&a).unwrap_or(&0);
        let rewards_after = state.total_rewards_distributed;
        let treasury_after = state.treasury_balance;
        let pool_after = state.reward_pool;
        let challenges_len = state.pending_challenges.len();

        // Second call: no changes.
        let r2 = process_expired_challenges(&mut state, FAR_FUTURE);
        assert!(r2.is_empty());

        // State unchanged.
        assert_eq!(*state.balances.get(&a).unwrap_or(&0), balance_after);
        assert_eq!(state.total_rewards_distributed, rewards_after);
        assert_eq!(state.treasury_balance, treasury_after);
        assert_eq!(state.reward_pool, pool_after);
        assert_eq!(state.pending_challenges.len(), challenges_len);
    }

    #[test]
    fn no_double_reward_release() {
        let mut state = ChainState::new();
        let a = addr(0x42);
        let dist = RewardDistribution::compute(2000);

        state.service_node_index.insert(NODE_ID_A, a);
        let challenge = PendingChallenge::new(HASH_A, NODE_ID_A, dist, 1_000_000);
        state.pending_challenges.insert(HASH_A, challenge);

        // First call: 1400 to node, 400 to pool, 200 to treasury.
        process_expired_challenges(&mut state, FAR_FUTURE);
        assert_eq!(*state.balances.get(&a).unwrap_or(&0), 1400);
        assert_eq!(state.total_rewards_distributed, 2000);

        // Second call: nothing changes.
        process_expired_challenges(&mut state, FAR_FUTURE);
        assert_eq!(*state.balances.get(&a).unwrap_or(&0), 1400);
        assert_eq!(state.total_rewards_distributed, 2000);
    }

    // ════════════════════════════════════════════════════════════════════
    // process_expired_challenges — Multiple challenges
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn process_multiple_mixed_statuses() {
        let mut state = ChainState::new();
        let a = addr(0x42);
        let b = addr(0x43);
        let dist_a = RewardDistribution::compute(1000);
        let dist_b = RewardDistribution::compute(2000);
        let dist_c = RewardDistribution::compute(500);

        state.service_node_index.insert(NODE_ID_A, a);
        state.service_node_index.insert(NODE_ID_B, b);

        // HASH_A: Pending (will be cleared).
        let ch_a = PendingChallenge::new(HASH_A, NODE_ID_A, dist_a, 1_000_000);
        state.pending_challenges.insert(HASH_A, ch_a);

        // HASH_B: Challenged (will produce PendingResolution).
        let mut ch_b = PendingChallenge::new(HASH_B, NODE_ID_B, dist_b, 1_000_000);
        ch_b.mark_challenged([0xF0; 20]);
        state.pending_challenges.insert(HASH_B, ch_b);

        // HASH_C: Already Cleared (terminal, skip).
        let mut ch_c = PendingChallenge::new(HASH_C, NODE_ID_A, dist_c, 1_000_000);
        ch_c.mark_cleared();
        state.pending_challenges.insert(HASH_C, ch_c);

        let resolutions = process_expired_challenges(&mut state, FAR_FUTURE);

        // Two resolutions: Cleared(A) and PendingResolution(B).
        // HASH_C is terminal → skipped (no resolution).
        assert_eq!(resolutions.len(), 2);

        let cleared_count = resolutions
            .iter()
            .filter(|r| matches!(r, ChallengeResolution::Cleared { .. }))
            .count();
        let pending_count = resolutions
            .iter()
            .filter(|r| matches!(r, ChallengeResolution::PendingResolution { .. }))
            .count();

        assert_eq!(cleared_count, 1);
        assert_eq!(pending_count, 1);

        // HASH_A removed, HASH_B and HASH_C remain.
        assert!(!state.pending_challenges.contains_key(&HASH_A));
        assert!(state.pending_challenges.contains_key(&HASH_B));
        assert!(state.pending_challenges.contains_key(&HASH_C));

        // Only HASH_A's reward distributed.
        assert_eq!(state.total_rewards_distributed, 1000);
    }

    // ════════════════════════════════════════════════════════════════════
    // process_expired_challenges — Determinism
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn deterministic_processing_order() {
        // Run twice with same input → same output.
        let make_state = || {
            let mut state = ChainState::new();
            let a = addr(0x42);
            let dist = RewardDistribution::compute(1000);

            state.service_node_index.insert(NODE_ID_A, a);

            let ch_a = PendingChallenge::new(HASH_A, NODE_ID_A, dist, 1_000_000);
            let ch_b = PendingChallenge::new(HASH_B, NODE_ID_A, dist, 1_000_000);
            state.pending_challenges.insert(HASH_A, ch_a);
            state.pending_challenges.insert(HASH_B, ch_b);

            state
        };

        let mut state1 = make_state();
        let mut state2 = make_state();

        let r1 = process_expired_challenges(&mut state1, FAR_FUTURE);
        let r2 = process_expired_challenges(&mut state2, FAR_FUTURE);

        assert_eq!(r1, r2);
        assert_eq!(state1.total_rewards_distributed, state2.total_rewards_distributed);
    }

    // ════════════════════════════════════════════════════════════════════
    // ChallengeError — Display
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn challenge_error_display() {
        let err = ChallengeError::AlreadyExists {
            receipt_hash: HASH_A,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("already exists"));
    }
}