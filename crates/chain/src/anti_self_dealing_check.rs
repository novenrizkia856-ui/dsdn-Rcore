//! # Anti-Self-Dealing Chain Validation (CH.5)
//!
//! Integrates anti-self-dealing detection at the chain validation layer.
//!
//! ## Core Principle: Redirect, Never Reject
//!
//! Self-dealing transactions are **NOT rejected**. Instead, the node's
//! reward share is **redirected to treasury**. This design:
//!
//! 1. **Does not punish the network** — validators still earn their 20%,
//!    treasury still receives its share (plus the penalty).
//! 2. **Penalizes only the node** — a dishonest node that submits claims
//!    for its own work earns 0% instead of 70%.
//! 3. **Maintains incentive alignment** — nodes are incentivized to NOT
//!    submit their own claims, encouraging a healthy division of labor
//!    between service nodes and claim submitters.
//! 4. **Preserves transaction finality** — no valid transaction is ever
//!    dropped, maintaining consensus liveness.
//!
//! ## Economic Rationale
//!
//! The 70/20/10 split (node/validator/treasury) assumes that the claim
//! submitter is independent from the node operator. When self-dealing
//! is detected, the split becomes 0/20/80:
//!
//! | Recipient | Normal | Self-Dealing |
//! |-----------|--------|--------------|
//! | Node | 70% | 0% (redirected) |
//! | Validator | 20% | 20% (unchanged) |
//! | Treasury | 10% | 80% (+node share) |
//!
//! This is **identical** to `tokenomics::calculate_fee_by_resource_class()`
//! and `RewardDistribution::with_anti_self_dealing()`.
//!
//! ## Detection Levels
//!
//! | Level | Check | Status |
//! |-------|-------|--------|
//! | 1 | Direct address match (node == submitter) | Active |
//! | 2 | Owner match (node_owner == submitter) | Active |
//! | 3 | Wallet affinity (transaction graph analysis) | Stub v1 (always None) |
//!
//! Level 3 wallet affinity is intentionally a stub in v1. Future versions
//! will implement lookback-based analysis using `WALLET_AFFINITY_LOOKBACK`
//! from `economic_constants`.
//!
//! ## This Module's Responsibility
//!
//! This module **only returns a boolean**. It does NOT:
//! - Mutate state
//! - Calculate reward amounts
//! - Execute transfers
//!
//! Actual reward calculation with the self-dealing penalty is performed
//! by `reward_executor::compute_distribution(reward_base, anti_self_dealing=true)`
//! which delegates to `RewardDistribution::with_anti_self_dealing()`.

use dsdn_common::anti_self_dealing::AntiSelfDealingCheck;
use dsdn_common::claim_validation::ClaimValidationError;
use dsdn_common::receipt_v1::Address as CommonAddress;

use crate::claim_reward_handler::ClaimReward;
use crate::state::ChainState;
use crate::types::Address as ChainAddress;

/// Node identifier type (32 bytes).
type NodeId = [u8; 32];

// ════════════════════════════════════════════════════════════════════════════════
// CHAIN ADDRESS ↔ COMMON ADDRESS CONVERSION
// ════════════════════════════════════════════════════════════════════════════════

/// Converts chain crate `Address` (newtype wrapper) to common crate `Address` (`[u8; 20]`).
///
/// Chain crate uses `types::Address` (a tuple struct wrapping `[u8; 20]`).
/// Common crate uses `type Address = [u8; 20]` (plain alias).
///
/// This conversion is zero-cost at runtime (identical memory layout).
#[inline]
fn chain_to_common(addr: &ChainAddress) -> CommonAddress {
    addr.0
}

// ════════════════════════════════════════════════════════════════════════════════
// lookup_node_owner
// ════════════════════════════════════════════════════════════════════════════════

/// Looks up the owner (operator) address of a node from the chain registry.
///
/// ## Lookup Path
///
/// `state.service_node_index[node_id]` → `operator_address` (ChainAddress)
/// → convert to `CommonAddress` ([u8; 20]).
///
/// ## Safety
///
/// - Returns `None` if node is not registered (no panic).
/// - Read-only: does not mutate state.
/// - Deterministic: same input always produces same output.
///
/// ## Current Model
///
/// In the current DSDN model, operator == owner. The `service_node_index`
/// maps `node_id → operator_address`. When an ownership model is introduced
/// (operator ≠ owner), this function should be updated to query the
/// ownership registry instead.
fn lookup_node_owner(
    state: &ChainState,
    node_id: &NodeId,
) -> Option<CommonAddress> {
    state
        .service_node_index
        .get(node_id)
        .map(chain_to_common)
}

// ════════════════════════════════════════════════════════════════════════════════
// check_anti_self_dealing
// ════════════════════════════════════════════════════════════════════════════════

/// Checks whether a ClaimReward transaction involves self-dealing.
///
/// ## Return Value
///
/// - `Ok(true)` — self-dealing detected. Caller MUST redirect node_share
///   to treasury (penalty). Transaction is NOT rejected.
/// - `Ok(false)` — no self-dealing. Normal 70/20/10 distribution applies.
///
/// This function never returns `Err` under normal operation. `Err` is
/// reserved for future internal logic errors that should not silently pass.
///
/// ## Flow
///
/// 1. Extract `node_id` from `claim.receipt`
/// 2. Extract `submitter_address` from `claim`
/// 3. Lookup node owner via `lookup_node_owner(state, node_id)`
/// 4. Construct `AntiSelfDealingCheck::new(node_address, submitter, owner)`
/// 5. Call `run_all_checks(&[])` (empty lookback data for v1 stub)
///
/// ## State Mutation
///
/// **NONE.** This function is purely read-only. It inspects the claim
/// and chain state but does not modify anything.
///
/// ## Consistency with tokenomics.rs
///
/// When this returns `Ok(true)`, the caller passes `anti_self_dealing=true`
/// to `reward_executor::compute_distribution()`, which delegates to
/// `RewardDistribution::with_anti_self_dealing()`. This produces the
/// exact same split as `tokenomics::calculate_fee_by_resource_class()`
/// with anti-self-dealing flag active:
///
/// - node_share → 0 (redirected to treasury)
/// - validator_share → 20%
/// - treasury_share → 80%
///
/// ## Deterministic
///
/// Same claim + same state → same result. Always.
pub fn check_anti_self_dealing(
    claim: &ClaimReward,
    state: &ChainState,
) -> Result<bool, ClaimValidationError> {
    // Step 1: Extract node_id from receipt.
    let node_id: &NodeId = claim.receipt.node_id();

    // Step 2: Extract submitter address (already [u8; 20] from common crate).
    let submitter: CommonAddress = claim.submitter_address;

    // Step 3: Lookup node owner from chain registry.
    // Returns None if node is not registered — in that case,
    // only Level 1 (direct match) can detect self-dealing.
    let node_owner: Option<CommonAddress> = lookup_node_owner(state, node_id);

    // Step 4: Construct AntiSelfDealingCheck.
    //
    // node_address parameter: use submitter_address from the receipt itself
    // (the address the receipt was issued TO). This is the node's claimed
    // payout address embedded in the receipt.
    let node_address: CommonAddress = *claim.receipt.submitter_address();

    let check = AntiSelfDealingCheck::new(
        node_address,       // node_address: where node reward would go
        submitter,          // submitter_address: who submitted the ClaimReward tx
        node_owner,         // node_owner_address: operator from registry (if known)
    );

    // Step 5: Run all detection levels.
    //
    // Level 1: Direct match (node_address == submitter_address)
    // Level 2: Owner match (node_owner == submitter_address)
    // Level 3: Wallet affinity (stub v1, always None)
    //
    // Empty lookback data (&[]) because wallet affinity is stub v1.
    let result = check.run_all_checks(&[]);

    // Map any violation to Ok(true).
    // Map None (no violation) to Ok(false).
    //
    // CRITICAL: We NEVER return Err for a detected violation.
    // Self-dealing is a penalty trigger, NOT a rejection reason.
    Ok(result.is_some())
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use dsdn_common::anti_self_dealing::SelfDealingViolation;
    use dsdn_common::receipt_v1::ReceiptType;

    // ── HELPERS ─────────────────────────────────────────────────────────

    const ADDR_NODE: CommonAddress = [0x01; 20];
    const ADDR_SUBMITTER: CommonAddress = [0x02; 20];
    const ADDR_OPERATOR: CommonAddress = [0x03; 20];
    const NODE_ID_A: NodeId = [0xAA; 32];

    fn chain_addr(byte: u8) -> ChainAddress {
        ChainAddress::from_bytes([byte; 20])
    }

    /// Build a ClaimReward where receipt.submitter_address == `receipt_addr`
    /// and claim.submitter_address == `tx_submitter`.
    fn make_claim(receipt_addr: CommonAddress, tx_submitter: CommonAddress, node_id: NodeId) -> ClaimReward {
        use dsdn_common::coordinator::ids::WorkloadId;

        let receipt = dsdn_common::receipt_v1::ReceiptV1::new(
            WorkloadId::new([0x00; 32]),
            node_id,
            ReceiptType::Storage,
            [0x00; 32],             // usage_proof_hash
            None,                   // execution_commitment
            vec![0x00; 64],         // coordinator_threshold_signature
            vec![],                 // signer_ids
            vec![0x00; 64],         // node_signature
            receipt_addr,           // submitter_address in receipt
            1000,                   // reward_base
            1000,                   // timestamp
            1,                      // epoch
        );

        ClaimReward {
            receipt: receipt.expect("test receipt construction should not fail"),
            submitter_address: tx_submitter,
        }
    }

    // ════════════════════════════════════════════════════════════════════
    // lookup_node_owner
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn lookup_owner_not_registered() {
        let state = ChainState::new();
        assert_eq!(lookup_node_owner(&state, &NODE_ID_A), None);
    }

    #[test]
    fn lookup_owner_found() {
        let mut state = ChainState::new();
        state.service_node_index.insert(NODE_ID_A, chain_addr(0x03));
        let owner = lookup_node_owner(&state, &NODE_ID_A);
        assert_eq!(owner, Some(ADDR_OPERATOR));
    }

    // ════════════════════════════════════════════════════════════════════
    // check_anti_self_dealing — no violation
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn no_self_dealing_different_addresses() {
        let state = ChainState::new();
        let claim = make_claim(ADDR_NODE, ADDR_SUBMITTER, NODE_ID_A);
        let result = check_anti_self_dealing(&claim, &state);
        assert_eq!(result, Ok(false));
    }

    #[test]
    fn no_self_dealing_with_registered_node_different_operator() {
        let mut state = ChainState::new();
        // Operator is ADDR_OPERATOR, submitter is ADDR_SUBMITTER — different.
        state.service_node_index.insert(NODE_ID_A, chain_addr(0x03));
        let claim = make_claim(ADDR_NODE, ADDR_SUBMITTER, NODE_ID_A);
        let result = check_anti_self_dealing(&claim, &state);
        assert_eq!(result, Ok(false));
    }

    // ════════════════════════════════════════════════════════════════════
    // check_anti_self_dealing — Level 1: direct match
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn self_dealing_direct_match() {
        let state = ChainState::new();
        // receipt.submitter_address == claim.submitter_address
        let claim = make_claim(ADDR_NODE, ADDR_NODE, NODE_ID_A);
        let result = check_anti_self_dealing(&claim, &state);
        assert_eq!(result, Ok(true));
    }

    // ════════════════════════════════════════════════════════════════════
    // check_anti_self_dealing — Level 2: owner match
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn self_dealing_owner_match() {
        let mut state = ChainState::new();
        // Node operator == ADDR_SUBMITTER → owner match.
        state.service_node_index.insert(NODE_ID_A, chain_addr(0x02));
        let claim = make_claim(ADDR_NODE, ADDR_SUBMITTER, NODE_ID_A);
        let result = check_anti_self_dealing(&claim, &state);
        assert_eq!(result, Ok(true));
    }

    // ════════════════════════════════════════════════════════════════════
    // check_anti_self_dealing — Level 3: wallet affinity (stub)
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn wallet_affinity_stub_always_false() {
        // With different addresses and unregistered node, Level 3 is the
        // only possible detection — but it's a stub, so always None.
        let state = ChainState::new();
        let claim = make_claim(ADDR_NODE, ADDR_SUBMITTER, NODE_ID_A);
        let result = check_anti_self_dealing(&claim, &state);
        assert_eq!(result, Ok(false));
    }

    // ════════════════════════════════════════════════════════════════════
    // CRITICAL: Never rejects transaction
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn never_returns_err_on_self_dealing() {
        let state = ChainState::new();
        let claim = make_claim(ADDR_NODE, ADDR_NODE, NODE_ID_A);
        let result = check_anti_self_dealing(&claim, &state);
        // Must be Ok — self-dealing is NOT an error.
        assert!(result.is_ok());
        assert_eq!(result, Ok(true));
    }

    #[test]
    fn never_returns_err_on_no_self_dealing() {
        let state = ChainState::new();
        let claim = make_claim(ADDR_NODE, ADDR_SUBMITTER, NODE_ID_A);
        let result = check_anti_self_dealing(&claim, &state);
        assert!(result.is_ok());
    }

    // ════════════════════════════════════════════════════════════════════
    // State mutation check (compile-time: &ChainState not &mut)
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn does_not_mutate_state() {
        let state = ChainState::new();
        let claim = make_claim(ADDR_NODE, ADDR_NODE, NODE_ID_A);
        let balances_before = state.balances.len();
        let treasury_before = state.treasury_balance;

        let _ = check_anti_self_dealing(&claim, &state);

        // State unchanged.
        assert_eq!(state.balances.len(), balances_before);
        assert_eq!(state.treasury_balance, treasury_before);
    }

    // ════════════════════════════════════════════════════════════════════
    // Determinism
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn deterministic_same_input_same_output() {
        let state = ChainState::new();
        let claim = make_claim(ADDR_NODE, ADDR_NODE, NODE_ID_A);
        let r1 = check_anti_self_dealing(&claim, &state);
        let r2 = check_anti_self_dealing(&claim, &state);
        assert_eq!(r1, r2);
    }

    // ════════════════════════════════════════════════════════════════════
    // Edge cases
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn all_zero_addresses_is_self_dealing() {
        let state = ChainState::new();
        let claim = make_claim([0u8; 20], [0u8; 20], [0u8; 32]);
        let result = check_anti_self_dealing(&claim, &state);
        assert_eq!(result, Ok(true));
    }

    #[test]
    fn unregistered_node_only_checks_direct() {
        // Node not in service_node_index → owner lookup returns None.
        // Only Level 1 (direct match) can detect.
        let state = ChainState::new();

        // Different addresses → no detection possible without owner.
        let claim = make_claim(ADDR_NODE, ADDR_SUBMITTER, NODE_ID_A);
        assert_eq!(check_anti_self_dealing(&claim, &state), Ok(false));

        // Same addresses → Level 1 catches it.
        let claim2 = make_claim(ADDR_NODE, ADDR_NODE, NODE_ID_A);
        assert_eq!(check_anti_self_dealing(&claim2, &state), Ok(true));
    }

    // ════════════════════════════════════════════════════════════════════
    // AntiSelfDealingCheck integration (sanity)
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn anti_self_dealing_check_direct_produces_direct_match() {
        let check = AntiSelfDealingCheck::new(ADDR_NODE, ADDR_NODE, None);
        assert_eq!(
            check.run_all_checks(&[]),
            Some(SelfDealingViolation::DirectMatch)
        );
    }

    #[test]
    fn anti_self_dealing_check_owner_produces_direct_match() {
        let check = AntiSelfDealingCheck::new(ADDR_NODE, ADDR_SUBMITTER, Some(ADDR_SUBMITTER));
        assert_eq!(
            check.run_all_checks(&[]),
            Some(SelfDealingViolation::DirectMatch)
        );
    }

    #[test]
    fn anti_self_dealing_check_no_match() {
        let check = AntiSelfDealingCheck::new(ADDR_NODE, ADDR_SUBMITTER, Some(ADDR_OPERATOR));
        assert_eq!(check.run_all_checks(&[]), None);
    }

    // ════════════════════════════════════════════════════════════════════
    // chain_to_common conversion
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn chain_to_common_roundtrip() {
        let bytes: CommonAddress = [0x42; 20];
        let chain = ChainAddress::from_bytes(bytes);
        let common = chain_to_common(&chain);
        assert_eq!(common, bytes);
    }
}