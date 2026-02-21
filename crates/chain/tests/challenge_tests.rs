//! # CH.10 — Challenge Period & Fraud Proof Integration Tests
//!
//! Tests for the complete challenge lifecycle including:
//! - Challenge period start/expiry/clear
//! - Fraud proof submission
//! - Slashing
//! - Double resolution prevention
//! - Idempotency
//! - CH.6 ↔ CH.7 interaction

use dsdn_chain::challenge_manager::{
    process_expired_challenges, start_challenge_period, ChallengeError, ChallengeResolution,
};
use dsdn_chain::fraud_proof_handler::{
    handle_fraud_proof_challenge, FraudProofChallenge, FraudProofError, MIN_CHALLENGER_STAKE,
};
use dsdn_chain::state::ChainState;
use dsdn_chain::types::Address;
use dsdn_common::challenge_state::{ChallengeStatus, PendingChallenge};
use dsdn_common::claim_validation::RewardDistribution;

// ════════════════════════════════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════════════════════════════════

const HASH_A: [u8; 32] = [0xAA; 32];
const HASH_B: [u8; 32] = [0xBB; 32];
const HASH_C: [u8; 32] = [0xCC; 32];
const NODE_ID_A: [u8; 32] = [0x11; 32];
const NODE_ID_B: [u8; 32] = [0x22; 32];
const CHALLENGER: [u8; 20] = [0xC1; 20];

/// Time within challenge period (after start, before end).
const ACTIVE_TIME: u64 = 1_000_001;
/// Time far beyond any challenge period end.
const FAR_FUTURE: u64 = 99_999_999;

fn chain_addr(byte: u8) -> Address {
    Address::from_bytes([byte; 20])
}

/// Setup a pending challenge with node registered and challenger staked.
fn setup_basic(state: &mut ChainState, hash: [u8; 32], node_id: [u8; 32]) {
    let dist = RewardDistribution::compute(1000);
    let challenge = PendingChallenge::new(hash, node_id, dist, 1_000_000);
    state.pending_challenges.insert(hash, challenge);
    state
        .service_node_index
        .insert(node_id, chain_addr(0x42));
    state
        .locked
        .insert(chain_addr(0xC1), MIN_CHALLENGER_STAKE + 5000);
}

fn make_fraud_proof(hash: [u8; 32], proven: bool) -> FraudProofChallenge {
    FraudProofChallenge {
        receipt_hash: hash,
        challenger_address: CHALLENGER,
        fraud_proof_data: if proven { vec![0x01] } else { vec![] },
    }
}

// ════════════════════════════════════════════════════════════════════════════
// 1. START CHALLENGE PERIOD
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn start_challenge_period_success() {
    let mut state = ChainState::new();
    let dist = RewardDistribution::compute(1000);

    let result = start_challenge_period(HASH_A, NODE_ID_A, dist, 1_000_000, &mut state);

    assert!(result.is_ok());
    assert!(state.pending_challenges.contains_key(&HASH_A));
    assert_eq!(
        state.pending_challenges.get(&HASH_A).expect("exists").status,
        ChallengeStatus::Pending
    );
}

#[test]
fn start_challenge_period_duplicate_rejected() {
    let mut state = ChainState::new();
    let dist = RewardDistribution::compute(1000);

    let _ = start_challenge_period(HASH_A, NODE_ID_A, dist, 1_000_000, &mut state);
    let result = start_challenge_period(HASH_A, NODE_ID_A, dist, 2_000_000, &mut state);

    assert_eq!(result, Err(ChallengeError::AlreadyExists { receipt_hash: HASH_A }));
}

#[test]
fn start_challenge_different_hashes_ok() {
    let mut state = ChainState::new();
    let dist = RewardDistribution::compute(1000);

    let r1 = start_challenge_period(HASH_A, NODE_ID_A, dist, 1_000_000, &mut state);
    let r2 = start_challenge_period(HASH_B, NODE_ID_B, dist, 1_000_000, &mut state);

    assert!(r1.is_ok());
    assert!(r2.is_ok());
    assert_eq!(state.pending_challenges.len(), 2);
}

// ════════════════════════════════════════════════════════════════════════════
// 2. PROCESS EXPIRED CHALLENGES
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn process_empty_state_returns_empty() {
    let mut state = ChainState::new();
    let resolutions = process_expired_challenges(&mut state, FAR_FUTURE);
    assert!(resolutions.is_empty());
}

#[test]
fn process_not_expired_returns_empty() {
    let mut state = ChainState::new();
    setup_basic(&mut state, HASH_A, NODE_ID_A);

    // Time before challenge_end → not expired.
    let resolutions = process_expired_challenges(&mut state, ACTIVE_TIME);
    assert!(resolutions.is_empty());
}

#[test]
fn process_pending_expired_clears_and_distributes() {
    let mut state = ChainState::new();
    setup_basic(&mut state, HASH_A, NODE_ID_A);

    let resolutions = process_expired_challenges(&mut state, FAR_FUTURE);

    assert_eq!(resolutions.len(), 1);
    assert!(matches!(
        resolutions[0],
        ChallengeResolution::Cleared { .. }
    ));
    // Entry removed after clearing.
    assert!(!state.pending_challenges.contains_key(&HASH_A));
    assert!(state.total_rewards_distributed > 0);
}

#[test]
fn process_challenged_produces_pending_resolution() {
    let mut state = ChainState::new();
    setup_basic(&mut state, HASH_A, NODE_ID_A);

    // Mark as Challenged.
    state
        .pending_challenges
        .get_mut(&HASH_A)
        .expect("exists")
        .mark_challenged([0xF0; 20]);

    let resolutions = process_expired_challenges(&mut state, FAR_FUTURE);

    assert_eq!(resolutions.len(), 1);
    assert!(matches!(
        resolutions[0],
        ChallengeResolution::PendingResolution { .. }
    ));
    // Entry NOT removed (still needs resolution).
    assert!(state.pending_challenges.contains_key(&HASH_A));
}

#[test]
fn process_slashed_terminal_skipped() {
    let mut state = ChainState::new();
    setup_basic(&mut state, HASH_A, NODE_ID_A);

    // Pending → Challenged → Slashed (correct state machine).
    let entry = state.pending_challenges.get_mut(&HASH_A).expect("exists");
    entry.mark_challenged([0xF0; 20]);
    entry.mark_slashed();

    let resolutions = process_expired_challenges(&mut state, FAR_FUTURE);

    assert!(resolutions.is_empty());
}

#[test]
fn process_cleared_terminal_skipped() {
    let mut state = ChainState::new();
    setup_basic(&mut state, HASH_A, NODE_ID_A);

    state
        .pending_challenges
        .get_mut(&HASH_A)
        .expect("exists")
        .mark_cleared();

    let resolutions = process_expired_challenges(&mut state, FAR_FUTURE);

    assert!(resolutions.is_empty());
}

// ════════════════════════════════════════════════════════════════════════════
// 3. IDEMPOTENCY
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn idempotent_double_call_no_extra_state_change() {
    let mut state = ChainState::new();
    setup_basic(&mut state, HASH_A, NODE_ID_A);

    let _ = process_expired_challenges(&mut state, FAR_FUTURE);
    let distributed_after_first = state.total_rewards_distributed;

    let resolutions_second = process_expired_challenges(&mut state, FAR_FUTURE);

    assert!(resolutions_second.is_empty());
    assert_eq!(state.total_rewards_distributed, distributed_after_first);
}

#[test]
fn no_double_reward_on_repeated_processing() {
    let mut state = ChainState::new();
    setup_basic(&mut state, HASH_A, NODE_ID_A);

    let _ = process_expired_challenges(&mut state, FAR_FUTURE);
    let balance_after_first = state.get_balance(&chain_addr(0x42));

    let _ = process_expired_challenges(&mut state, FAR_FUTURE);
    let balance_after_second = state.get_balance(&chain_addr(0x42));

    assert_eq!(balance_after_first, balance_after_second);
}

// ════════════════════════════════════════════════════════════════════════════
// 4. FRAUD PROOF CHALLENGE (CH.7)
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn fraud_proof_proven_slashes() {
    let mut state = ChainState::new();
    setup_basic(&mut state, HASH_A, NODE_ID_A);

    let fp = make_fraud_proof(HASH_A, true);
    let result = handle_fraud_proof_challenge(&fp, &mut state, ACTIVE_TIME);

    assert!(matches!(
        result,
        Ok(ChallengeResolution::Slashed { amount: 1000, .. })
    ));
    assert_eq!(
        state
            .pending_challenges
            .get(&HASH_A)
            .expect("exists")
            .status,
        ChallengeStatus::Slashed
    );
    assert_eq!(state.total_challenges_submitted, 1);
    assert_eq!(state.total_fraud_slashed, 1000);
}

#[test]
fn fraud_proof_not_proven_marks_challenged() {
    let mut state = ChainState::new();
    setup_basic(&mut state, HASH_A, NODE_ID_A);

    let fp = make_fraud_proof(HASH_A, false);
    let result = handle_fraud_proof_challenge(&fp, &mut state, ACTIVE_TIME);

    assert!(matches!(
        result,
        Ok(ChallengeResolution::PendingResolution { .. })
    ));
    assert_eq!(
        state
            .pending_challenges
            .get(&HASH_A)
            .expect("exists")
            .status,
        ChallengeStatus::Challenged
    );
    assert_eq!(state.total_challenges_submitted, 1);
    assert_eq!(state.total_fraud_slashed, 0);
}

#[test]
fn fraud_proof_receipt_not_found() {
    let mut state = ChainState::new();
    let fp = make_fraud_proof(HASH_A, true);

    let result = handle_fraud_proof_challenge(&fp, &mut state, ACTIVE_TIME);

    assert!(matches!(
        result,
        Err(FraudProofError::ReceiptNotPending { .. })
    ));
}

#[test]
fn fraud_proof_period_expired() {
    let mut state = ChainState::new();
    setup_basic(&mut state, HASH_A, NODE_ID_A);

    let fp = make_fraud_proof(HASH_A, true);
    let result = handle_fraud_proof_challenge(&fp, &mut state, FAR_FUTURE);

    assert!(matches!(
        result,
        Err(FraudProofError::ChallengePeriodExpired { .. })
    ));
}

#[test]
fn fraud_proof_insufficient_stake() {
    let mut state = ChainState::new();
    setup_basic(&mut state, HASH_A, NODE_ID_A);

    // Override: zero stake.
    state.locked.insert(chain_addr(0xC1), 0);

    let fp = make_fraud_proof(HASH_A, true);
    let result = handle_fraud_proof_challenge(&fp, &mut state, ACTIVE_TIME);

    assert!(matches!(
        result,
        Err(FraudProofError::InsufficientChallengerStake { .. })
    ));
}

#[test]
fn fraud_proof_double_challenge_rejected() {
    let mut state = ChainState::new();
    setup_basic(&mut state, HASH_A, NODE_ID_A);

    let fp1 = make_fraud_proof(HASH_A, false);
    let r1 = handle_fraud_proof_challenge(&fp1, &mut state, ACTIVE_TIME);
    assert!(r1.is_ok());

    let fp2 = make_fraud_proof(HASH_A, true);
    let r2 = handle_fraud_proof_challenge(&fp2, &mut state, ACTIVE_TIME);

    assert!(matches!(
        r2,
        Err(FraudProofError::ChallengeNotPending { .. })
    ));
    assert_eq!(state.total_challenges_submitted, 1);
}

#[test]
fn fraud_proof_zero_state_mutation_on_failure() {
    let mut state = ChainState::new();
    setup_basic(&mut state, HASH_A, NODE_ID_A);

    let challenges_before = state.total_challenges_submitted;
    let slashed_before = state.total_fraud_slashed;

    // Fail at period expired.
    let fp = make_fraud_proof(HASH_A, true);
    let _ = handle_fraud_proof_challenge(&fp, &mut state, FAR_FUTURE);

    assert_eq!(state.total_challenges_submitted, challenges_before);
    assert_eq!(state.total_fraud_slashed, slashed_before);
}

// ════════════════════════════════════════════════════════════════════════════
// 5. CH.6 + CH.7 INTEGRATION
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn slashed_challenge_skipped_by_ch6_expiry() {
    let mut state = ChainState::new();
    setup_basic(&mut state, HASH_A, NODE_ID_A);

    // CH.7: Slash it.
    let fp = make_fraud_proof(HASH_A, true);
    let _ = handle_fraud_proof_challenge(&fp, &mut state, ACTIVE_TIME);

    // CH.6: process_expired_challenges should skip Slashed.
    let resolutions = process_expired_challenges(&mut state, FAR_FUTURE);

    assert!(resolutions.is_empty());
    assert_eq!(state.total_rewards_distributed, 0);
}

#[test]
fn challenged_entry_produces_pending_resolution_in_ch6() {
    let mut state = ChainState::new();
    setup_basic(&mut state, HASH_A, NODE_ID_A);

    // CH.7: Challenge without proof.
    let fp = make_fraud_proof(HASH_A, false);
    let _ = handle_fraud_proof_challenge(&fp, &mut state, ACTIVE_TIME);

    // CH.6: Should see Challenged → PendingResolution.
    let resolutions = process_expired_challenges(&mut state, FAR_FUTURE);

    assert_eq!(resolutions.len(), 1);
    assert!(matches!(
        resolutions[0],
        ChallengeResolution::PendingResolution { .. }
    ));
    assert_eq!(state.total_rewards_distributed, 0);
}

// ════════════════════════════════════════════════════════════════════════════
// 6. MULTIPLE CHALLENGES MIXED
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn multiple_challenges_mixed_statuses() {
    let mut state = ChainState::new();
    setup_basic(&mut state, HASH_A, NODE_ID_A);
    setup_basic(&mut state, HASH_B, NODE_ID_B);

    // Also register NODE_ID_B.
    state
        .service_node_index
        .insert(NODE_ID_B, chain_addr(0x43));

    // HASH_A: Pending → will clear.
    // HASH_B: Slash via fraud proof.
    let fp = make_fraud_proof(HASH_B, true);
    let _ = handle_fraud_proof_challenge(&fp, &mut state, ACTIVE_TIME);

    let resolutions = process_expired_challenges(&mut state, FAR_FUTURE);

    // Only HASH_A should produce Cleared (HASH_B is Slashed → skip).
    let cleared_count = resolutions
        .iter()
        .filter(|r| matches!(r, ChallengeResolution::Cleared { .. }))
        .count();
    assert_eq!(cleared_count, 1);
}

#[test]
fn deterministic_processing_order() {
    let mut state1 = ChainState::new();
    let mut state2 = ChainState::new();

    // Set up identical state in both.
    for state in [&mut state1, &mut state2] {
        setup_basic(state, HASH_A, NODE_ID_A);
        setup_basic(state, HASH_B, NODE_ID_B);
        state
            .service_node_index
            .insert(NODE_ID_B, chain_addr(0x43));
    }

    let r1 = process_expired_challenges(&mut state1, FAR_FUTURE);
    let r2 = process_expired_challenges(&mut state2, FAR_FUTURE);

    assert_eq!(r1.len(), r2.len());
    for (a, b) in r1.iter().zip(r2.iter()) {
        assert_eq!(a, b);
    }
}