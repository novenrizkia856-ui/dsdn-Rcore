//! # ClaimReward Transaction Handler (CH.3)
//!
//! Entry point untuk transaksi ClaimReward dari mempool.
//!
//! ## Flow Diagram
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                    handle_claim_reward(claim, state)                │
//! │                                                                     │
//! │  STEP 1 ─ VERIFY (read-only)                                       │
//! │  │  verify_receipt_v1(&receipt, state, time, epoch)?                │
//! │  │  ← checks: reward_base, age, epoch, dedup, commitment,         │
//! │  │            node_sig, threshold_sig                               │
//! │  │  ← Err? → return ClaimValidationError                           │
//! │  │                                                                  │
//! │  STEP 2 ─ ANTI-SELF-DEALING (read-only)                            │
//! │  │  detect_self_dealing(claim, state) → bool                        │
//! │  │  ← lookup service_node_index[node_id] → operator                │
//! │  │  ← if submitter == operator → true (penalty, not rejection)     │
//! │  │                                                                  │
//! │  STEP 3 ─ COMPUTE DISTRIBUTION (pure)                              │
//! │  │  if self_dealing:                                                │
//! │  │      RewardDistribution::with_anti_self_dealing(reward_base)    │
//! │  │  else:                                                           │
//! │  │      RewardDistribution::compute(reward_base)                   │
//! │  │                                                                  │
//! │  ════════════════════ MUTATION BOUNDARY ════════════════════════    │
//! │  │                                                                  │
//! │  STEP 4 ─ MARK CLAIMED (first mutation — atomic gate)              │
//! │  │  receipt_dedup_tracker.mark_claimed(hash)?                      │
//! │  │  ← Err? → return ReceiptAlreadyClaimed (no state changed)      │
//! │  │                                                                  │
//! │  STEP 5 ─ ROUTE BY RECEIPT TYPE                                    │
//! │  │                                                                  │
//! │  ├── Storage ─────────────────────────────────────────────────      │
//! │  │   execute_reward_distribution(state, distribution, addr)         │
//! │  │   total_receipts_claimed += 1                                   │
//! │  │   total_rewards_distributed += reward_base                      │
//! │  │   → Ok(ImmediateReward { distribution })                        │
//! │  │                                                                  │
//! │  └── Compute ─────────────────────────────────────────────────     │
//! │      PendingChallenge::new(hash, node_id, distribution, time)      │
//! │      pending_challenges.insert(hash, challenge)                    │
//! │      total_receipts_claimed += 1                                   │
//! │      → Ok(ChallengePeriodStarted { hash, end, distribution })      │
//! │      (total_rewards_distributed NOT incremented — deferred)        │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Atomicity Guarantee
//!
//! State mutation hanya terjadi setelah semua validasi sukses.
//! `mark_claimed` (Step 4) adalah atomic gate:
//!
//! - Jika Step 1–3 gagal → tidak ada mutation sama sekali.
//! - Jika Step 4 gagal → tidak ada mutation (mark_claimed atomic).
//! - Jika Step 4 sukses → Step 5 adalah infallible (saturating arithmetic).
//!
//! Karena Step 5 tidak dapat gagal setelah mark_claimed berhasil,
//! partial state update TIDAK MUNGKIN terjadi.
//!
//! ## Why mark_claimed Before Routing
//!
//! `mark_claimed` ditempatkan SEBELUM routing (Step 5) karena:
//!
//! 1. Ini adalah "point of no return" — setelah ini receipt dianggap consumed.
//! 2. Jika routing dilakukan dulu dan mark_claimed gagal, rewards sudah
//!    terdistribusi tanpa receipt tercatat → double-claim vulnerability.
//! 3. Sebaliknya, jika mark_claimed duluan dan routing "gagal" (impossible
//!    karena infallible), receipt tercatat tapi rewards belum — recoverable.
//!
//! ## Counter Update Rationale
//!
//! - `total_receipts_claimed`: Incremented for BOTH Storage and Compute.
//!   Counts "processed receipts" regardless of immediate vs deferred.
//! - `total_rewards_distributed`: Incremented ONLY for Storage (immediate).
//!   Compute rewards are deferred until challenge period ends without fraud.
//!   The challenge resolution handler (future) increments this counter.
//!
//! ## Error Propagation
//!
//! All errors propagate via `?` operator as `ClaimValidationError`.
//! No error is silently swallowed. No `unwrap`, `expect`, or `panic!`.

use dsdn_common::challenge_state::PendingChallenge;
use dsdn_common::claim_validation::{ClaimValidationError, ClaimValidationResult, RewardDistribution};
use dsdn_common::receipt_v1::{Address, ReceiptType, ReceiptV1};

use crate::receipt_v1_verify;
use crate::state::ChainState;
use crate::types::Address as ChainAddress;

// ════════════════════════════════════════════════════════════════════════════════
// CLAIM REWARD REQUEST
// ════════════════════════════════════════════════════════════════════════════════

/// Native ClaimReward request.
///
/// Constructed from `TxPayload::ClaimReward` after converting the legacy
/// `ResourceReceipt` to [`ReceiptV1`].
///
/// ## Fields
///
/// - `receipt` — The ReceiptV1 to claim (contains all receipt data).
/// - `submitter_address` — Address of the transaction sender (from TxEnvelope).
///   Used for anti-self-dealing detection against the node operator.
#[derive(Debug, Clone)]
pub struct ClaimReward {
    /// The receipt being claimed.
    pub receipt: ReceiptV1,
    /// Address of the entity submitting this ClaimReward transaction.
    /// Derived from the TxEnvelope pubkey (not from the receipt itself).
    pub submitter_address: Address,
}

// ════════════════════════════════════════════════════════════════════════════════
// MAIN HANDLER
// ════════════════════════════════════════════════════════════════════════════════

/// Processes a ClaimReward transaction through the full validation and
/// execution pipeline.
///
/// This is the single entry point for all ClaimReward processing.
/// Called from `apply_payload` in the transaction router.
///
/// ## Parameters
///
/// - `claim` — The claim request (receipt + submitter context).
/// - `state` — Mutable chain state. Only mutated after all validation passes.
/// - `current_time` — Current block timestamp (unix seconds).
/// - `current_epoch` — Current chain epoch number.
///
/// ## Returns
///
/// - `Ok(ImmediateReward { distribution })` — Storage receipt: rewards distributed.
/// - `Ok(ChallengePeriodStarted { ... })` — Compute receipt: challenge period opened.
/// - `Err(ClaimValidationError)` — Validation failed, no state changed.
///
/// ## Invariants (CONSENSUS-CRITICAL)
///
/// - Storage → no pending challenge created.
/// - Compute → must create pending challenge.
/// - `total_receipts_claimed` incremented exactly once per successful call.
/// - `total_rewards_distributed` incremented only for Storage.
/// - No duplicate challenge insertion (receipt_hash is unique after mark_claimed).
/// - No double increment (each counter updated exactly once).
pub fn handle_claim_reward(
    claim: &ClaimReward,
    state: &mut ChainState,
    current_time: u64,
    current_epoch: u64,
) -> Result<ClaimValidationResult, ClaimValidationError> {
    // ──────────────────────────────────────────────────────────────────────
    // STEP 1 — VERIFY (read-only, no mutation)
    // ──────────────────────────────────────────────────────────────────────
    // Runs 7 independent checks (cheap first, expensive last):
    //   1. reward_base range
    //   2. receipt age
    //   3. epoch consistency
    //   4. anti double-claim
    //   5. execution commitment presence
    //   6. node Ed25519 signature
    //   7. coordinator threshold signature
    //
    // Any failure → early return, zero state mutation.
    receipt_v1_verify::verify_receipt_v1(
        &claim.receipt,
        state,
        current_time,
        current_epoch,
    )?;

    // ──────────────────────────────────────────────────────────────────────
    // STEP 2 — ANTI-SELF-DEALING (read-only, no mutation)
    // ──────────────────────────────────────────────────────────────────────
    // Detects if submitter is economically related to the node.
    // Result is a boolean flag — NOT a rejection.
    // Penalty: node_reward redirected to treasury (applied in Step 3).
    let is_self_dealing = detect_self_dealing(claim, state);

    // ──────────────────────────────────────────────────────────────────────
    // STEP 3 — COMPUTE DISTRIBUTION (pure computation, no mutation)
    // ──────────────────────────────────────────────────────────────────────
    // Normal:          70% node / 20% validator / 10% treasury
    // Self-dealing:     0% node / 20% validator / 80% treasury
    //
    // Invariant: sum == reward_base (guaranteed by RewardDistribution).
    let distribution = if is_self_dealing {
        RewardDistribution::with_anti_self_dealing(claim.receipt.reward_base())
    } else {
        RewardDistribution::compute(claim.receipt.reward_base())
    };

    // ══════════════════════════════════════════════════════════════════════
    //                      MUTATION BOUNDARY
    // ══════════════════════════════════════════════════════════════════════
    // Everything above is read-only. Everything below mutates state.
    // mark_claimed is the atomic gate — if it fails, nothing changed.

    // ──────────────────────────────────────────────────────────────────────
    // STEP 4 — MARK RECEIPT CLAIMED (first and gating mutation)
    // ──────────────────────────────────────────────────────────────────────
    // If this fails (ReceiptAlreadyClaimed), NO state has been modified.
    // This is the atomicity gate: no counter/balance changes before this.
    let receipt_hash = claim.receipt.compute_receipt_hash();
    state.receipt_dedup_tracker.mark_claimed(receipt_hash)?;

    // ──────────────────────────────────────────────────────────────────────
    // STEP 5 — ROUTE BASED ON RECEIPT TYPE
    // ──────────────────────────────────────────────────────────────────────
    // After mark_claimed succeeds, all subsequent operations are infallible
    // (saturating arithmetic). Partial state update is impossible.
    match claim.receipt.receipt_type() {
        ReceiptType::Storage => {
            // Immediate reward distribution.
            execute_reward_distribution(
                state,
                &distribution,
                claim.receipt.submitter_address(),
            );

            // Counter updates (saturating — infallible).
            state.total_receipts_claimed = state.total_receipts_claimed.saturating_add(1);
            state.total_rewards_distributed = state
                .total_rewards_distributed
                .saturating_add(claim.receipt.reward_base());

            Ok(ClaimValidationResult::ImmediateReward { distribution })
        }
        ReceiptType::Compute => {
            // Create challenge period — reward deferred.
            let challenge = PendingChallenge::new(
                receipt_hash,
                *claim.receipt.node_id(),
                distribution,
                current_time,
            );
            let challenge_end = challenge.challenge_end;

            // Insert challenge entry.
            // Duplicate insertion impossible: mark_claimed already ensures
            // receipt_hash uniqueness. If the hash was already claimed,
            // Step 4 would have returned Err.
            state.pending_challenges.insert(receipt_hash, challenge);

            // Counter update (saturating — infallible).
            // total_rewards_distributed NOT incremented here.
            // It will be incremented when challenge period resolves
            // without fraud (in the challenge resolution handler).
            state.total_receipts_claimed = state.total_receipts_claimed.saturating_add(1);

            Ok(ClaimValidationResult::ChallengePeriodStarted {
                receipt_hash,
                challenge_end,
                pending_distribution: distribution,
            })
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// STEP 2 HELPER: ANTI-SELF-DEALING DETECTION
// ════════════════════════════════════════════════════════════════════════════════

/// Detects self-dealing between the claim submitter and the node operator.
///
/// Lookup path:
/// 1. `service_node_index[receipt.node_id()]` → `operator_address`
/// 2. Compare `operator_address` against `claim.submitter_address`
///
/// If the node is not registered in `service_node_index`, detection is
/// skipped (returns `false`). This is a conservative choice — unregistered
/// nodes cannot be checked, but the receipt's signatures were already
/// verified in Step 1.
///
/// ## Levels Checked
///
/// 1. Direct match: `operator == submitter`
/// 2. Owner match: `owner == submitter` (currently owner == operator)
/// 3. Wallet affinity: stub v1, always None
///
/// Read-only. Deterministic. No panic.
fn detect_self_dealing(claim: &ClaimReward, state: &ChainState) -> bool {
    let node_operator = match state.service_node_index.get(claim.receipt.node_id()) {
        Some(operator) => operator,
        None => return false,
    };

    // Compare chain Address (newtype) against submitter ([u8; 20])
    // by converting submitter to ChainAddress for comparison.
    let submitter_chain = ChainAddress::from_bytes(claim.submitter_address);

    // Level 1: Direct match — operator == submitter
    // Level 2: Owner match — in current model, owner == operator (same check)
    // Level 3: Wallet affinity — stub v1, skipped
    *node_operator == submitter_chain
}

// ════════════════════════════════════════════════════════════════════════════════
// STEP 5 HELPER: REWARD DISTRIBUTION EXECUTION
// ════════════════════════════════════════════════════════════════════════════════

/// Executes reward distribution by crediting balances.
///
/// ## Credit Targets
///
/// | Component | Target | Field |
/// |-----------|--------|-------|
/// | `node_reward` | Node operator (submitter) | `balances[addr]` |
/// | `validator_reward` | Block proposer pool | `reward_pool` |
/// | `treasury_reward` | Protocol treasury | `treasury_balance` |
///
/// ## Why `reward_pool` for Validator Reward
///
/// The validator reward goes to `reward_pool` (not directly to a validator)
/// because the block proposer is determined at block production time, not
/// at transaction execution time. The proposer collects from the pool
/// during block finalization.
///
/// ## Infallibility
///
/// All operations use `saturating_add` to prevent overflow.
/// With `reward_base` capped at 1 trillion (1e12) and u128 max at ~3.4e38,
/// overflow requires ~3.4e26 successful claims — physically impossible.
///
/// This function CANNOT fail, ensuring atomicity after `mark_claimed`.
fn execute_reward_distribution(
    state: &mut ChainState,
    distribution: &RewardDistribution,
    node_address: &Address,
) {
    // Convert common crate Address ([u8; 20]) → chain Address (newtype)
    let chain_addr = ChainAddress::from_bytes(*node_address);

    // Credit node reward to submitter's balance.
    if distribution.node_reward > 0 {
        let balance = state.balances.entry(chain_addr).or_insert(0);
        *balance = balance.saturating_add(distribution.node_reward);
    }

    // Credit validator reward to proposer pool.
    if distribution.validator_reward > 0 {
        state.reward_pool = state
            .reward_pool
            .saturating_add(distribution.validator_reward);
    }

    // Credit treasury reward.
    if distribution.treasury_reward > 0 {
        state.treasury_balance = state
            .treasury_balance
            .saturating_add(distribution.treasury_reward);
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use dsdn_common::anti_self_dealing::{AntiSelfDealingCheck, SelfDealingViolation};
    use dsdn_common::claim_validation::RewardDistribution;

    // ── CONSTANTS ───────────────────────────────────────────────────────

    // Common crate Address ([u8; 20]) — used for receipt fields and AntiSelfDealingCheck.
    const ADDR_NODE: Address = [0x01; 20];
    const ADDR_SUBMITTER: Address = [0x02; 20];
    const ADDR_SAME: Address = [0x03; 20];

    /// Convert common crate Address ([u8; 20]) → chain Address (newtype).
    /// Shorthand for state interaction in tests.
    fn ca(addr: Address) -> ChainAddress {
        ChainAddress::from_bytes(addr)
    }

    // ── DETECT SELF-DEALING ─────────────────────────────────────────────

    #[test]
    fn self_dealing_no_node_registered() {
        let state = ChainState::new();
        let claim = make_dummy_claim(ADDR_SUBMITTER);
        assert!(!detect_self_dealing(&claim, &state));
    }

    #[test]
    fn self_dealing_different_addresses() {
        let mut state = ChainState::new();
        let node_id = [0xAA; 32];
        // Register node with operator = ADDR_NODE (as ChainAddress)
        state.service_node_index.insert(node_id, ca(ADDR_NODE));
        let claim = make_claim_with_node_id(ADDR_SUBMITTER, node_id);
        assert!(!detect_self_dealing(&claim, &state));
    }

    #[test]
    fn self_dealing_submitter_is_operator() {
        let mut state = ChainState::new();
        let node_id = [0xAA; 32];
        // Register node with operator = ADDR_SAME (as ChainAddress)
        state.service_node_index.insert(node_id, ca(ADDR_SAME));
        // Submitter is the same as operator
        let claim = make_claim_with_node_id(ADDR_SAME, node_id);
        assert!(detect_self_dealing(&claim, &state));
    }

    // ── EXECUTE REWARD DISTRIBUTION ─────────────────────────────────────

    #[test]
    fn distribution_normal_credits_all_three() {
        let mut state = ChainState::new();
        let dist = RewardDistribution::compute(1000);
        execute_reward_distribution(&mut state, &dist, &ADDR_NODE);

        assert_eq!(*state.balances.get(&ca(ADDR_NODE)).unwrap_or(&0), 700);
        assert_eq!(state.reward_pool, 200);
        assert_eq!(state.treasury_balance, 100);
    }

    #[test]
    fn distribution_self_dealing_no_node_reward() {
        let mut state = ChainState::new();
        let dist = RewardDistribution::with_anti_self_dealing(1000);
        execute_reward_distribution(&mut state, &dist, &ADDR_NODE);

        assert_eq!(*state.balances.get(&ca(ADDR_NODE)).unwrap_or(&0), 0);
        assert_eq!(state.reward_pool, 200);
        assert_eq!(state.treasury_balance, 800);
    }

    #[test]
    fn distribution_zero_reward_base() {
        let mut state = ChainState::new();
        let dist = RewardDistribution::compute(0);
        execute_reward_distribution(&mut state, &dist, &ADDR_NODE);

        assert_eq!(state.balances.get(&ca(ADDR_NODE)), None);
        assert_eq!(state.reward_pool, 0);
        assert_eq!(state.treasury_balance, 0);
    }

    #[test]
    fn distribution_accumulates_across_calls() {
        let mut state = ChainState::new();
        let dist = RewardDistribution::compute(1000);

        execute_reward_distribution(&mut state, &dist, &ADDR_NODE);
        execute_reward_distribution(&mut state, &dist, &ADDR_NODE);

        assert_eq!(*state.balances.get(&ca(ADDR_NODE)).unwrap_or(&0), 1400);
        assert_eq!(state.reward_pool, 400);
        assert_eq!(state.treasury_balance, 200);
    }

    #[test]
    fn distribution_creates_account_if_missing() {
        let mut state = ChainState::new();
        let fresh_addr: Address = [0xFF; 20];
        let dist = RewardDistribution::compute(100);

        assert!(state.balances.get(&ca(fresh_addr)).is_none());
        execute_reward_distribution(&mut state, &dist, &fresh_addr);
        assert_eq!(*state.balances.get(&ca(fresh_addr)).unwrap_or(&0), 70);
    }

    // ── ANTI-SELF-DEALING CHECK INTEGRATION ─────────────────────────────

    #[test]
    fn anti_self_dealing_check_direct_match_produces_correct_violation() {
        let check = AntiSelfDealingCheck::new(ADDR_SAME, ADDR_SAME, Some(ADDR_SAME));
        let result = check.run_all_checks(&[]);
        assert_eq!(result, Some(SelfDealingViolation::DirectMatch));
    }

    #[test]
    fn anti_self_dealing_check_no_match() {
        let check = AntiSelfDealingCheck::new(ADDR_NODE, ADDR_SUBMITTER, Some(ADDR_NODE));
        let result = check.run_all_checks(&[]);
        assert_eq!(result, None);
    }

    // ── MARK CLAIMED ATOMICITY ──────────────────────────────────────────

    #[test]
    fn mark_claimed_rejects_duplicate() {
        let mut state = ChainState::new();
        let hash = [0xBB; 32];
        assert!(state.receipt_dedup_tracker.mark_claimed(hash).is_ok());
        assert!(state.receipt_dedup_tracker.mark_claimed(hash).is_err());
    }

    // ── COUNTER UPDATES ─────────────────────────────────────────────────

    #[test]
    fn counter_saturating_add_does_not_panic() {
        let mut val: u64 = u64::MAX;
        val = val.saturating_add(1);
        assert_eq!(val, u64::MAX);

        let mut val128: u128 = u128::MAX;
        val128 = val128.saturating_add(1);
        assert_eq!(val128, u128::MAX);
    }

    // ── CLAIM REWARD STRUCT ─────────────────────────────────────────────

    #[test]
    fn claim_reward_struct_is_clone() {
        let claim = make_dummy_claim(ADDR_SUBMITTER);
        let claim2 = claim.clone();
        assert_eq!(claim.submitter_address, claim2.submitter_address);
    }

    // ── TEST HELPERS ────────────────────────────────────────────────────

    /// Creates a dummy ClaimReward with a zeroed-out receipt.
    /// Only useful for testing detect_self_dealing and distribution,
    /// NOT for full handle_claim_reward (which requires valid signatures).
    fn make_dummy_claim(submitter: Address) -> ClaimReward {
        make_claim_with_node_id(submitter, [0x00; 32])
    }

    fn make_claim_with_node_id(submitter: Address, node_id: [u8; 32]) -> ClaimReward {
        use dsdn_common::receipt_v1::ReceiptType;
        use dsdn_common::coordinator::ids::WorkloadId;

        // Create a minimal valid ReceiptV1 for testing.
        // Signatures are dummy — these tests don't call verify_receipt_v1.
        let receipt = ReceiptV1::new(
            WorkloadId::new([0x00; 32]),
            node_id,
            ReceiptType::Storage,
            [0x00; 32],             // usage_proof_hash
            None,                   // execution_commitment (None for Storage)
            vec![0x00; 64],         // coordinator_threshold_signature
            vec![],                 // signer_ids
            vec![0x00; 64],         // node_signature
            submitter,              // submitter_address
            1000,                   // reward_base
            1000,                   // timestamp
            1,                      // epoch
        );

        // ReceiptV1::new returns Result — unwrap is OK in test code.
        ClaimReward {
            receipt: receipt.expect("test receipt construction should not fail"),
            submitter_address: submitter,
        }
    }
}