//! # Fraud Proof Challenge Handler (CH.7)
//!
//! Handles submission of fraud proof challenges during the challenge period
//! for Compute receipts.
//!
//! ## Flow Diagram
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │           handle_fraud_proof_challenge(challenge, state, time)      │
//! │                                                                     │
//! │  STEP 1 ─ VALIDATE RECEIPT PENDING (read-only)                     │
//! │  │  pending_challenges[receipt_hash] must exist                     │
//! │  │  ← Not found? → FraudProofError::ReceiptNotPending              │
//! │  │                                                                  │
//! │  STEP 2 ─ VALIDATE STATUS IS PENDING (read-only)                   │
//! │  │  status must be ChallengeStatus::Pending                        │
//! │  │  ← Not Pending? → FraudProofError::ChallengeNotPending          │
//! │  │                                                                  │
//! │  STEP 3 ─ VALIDATE CHALLENGE PERIOD ACTIVE (read-only)             │
//! │  │  can_be_challenged(current_time) must be true                   │
//! │  │  ← Expired? → FraudProofError::ChallengePeriodExpired           │
//! │  │                                                                  │
//! │  STEP 4 ─ VERIFY CHALLENGER STAKE (read-only)                      │
//! │  │  challenger must have >= MIN_CHALLENGER_STAKE locked             │
//! │  │  ← Insufficient? → FraudProofError::InsufficientChallengerStake │
//! │  │                                                                  │
//! │  STEP 5 ─ VERIFY FRAUD PROOF (read-only, deterministic)            │
//! │  │  verify_fraud_proof_stub(proof_data) → bool                     │
//! │  │  V1: non-empty proof data → true                                │
//! │  │                                                                  │
//! │  ════════════════════ MUTATION BOUNDARY ════════════════════════    │
//! │  │                                                                  │
//! │  STEP 6 ─ MARK CHALLENGED (first mutation)                         │
//! │  │  Pending → Challenged (records challenger_address)              │
//! │  │  total_challenges_submitted += 1                                │
//! │  │                                                                  │
//! │  STEP 7 ─ ROUTE BY PROOF RESULT                                    │
//! │  │                                                                  │
//! │  ├── fraud_proven == true ─────────────────────────────────────     │
//! │  │   Challenged → Slashed                                          │
//! │  │   total_fraud_slashed += reward_base                            │
//! │  │   → Ok(ChallengeResolution::Slashed { hash, amount })          │
//! │  │                                                                  │
//! │  └── fraud_proven == false ────────────────────────────────────    │
//! │      Status remains Challenged (dispute pending)                   │
//! │      → Ok(ChallengeResolution::PendingResolution { hash })         │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Atomicity Guarantee
//!
//! State mutation only occurs after ALL validations succeed (Steps 1–5).
//!
//! `mark_challenged` (Step 6) is the first mutation:
//! - If Steps 1–5 fail → zero state mutation.
//! - If Step 6 succeeds → Step 7 is infallible (saturating arithmetic).
//!
//! Partial state update is IMPOSSIBLE because:
//! - `mark_challenged` is a single field write.
//! - `mark_slashed` is a single field write.
//! - Counter increments use `saturating_add`.
//!
//! ## Determinism
//!
//! - All validation checks are deterministic (pure comparisons).
//! - `verify_fraud_proof_stub` is deterministic (byte-length check).
//! - No randomness, no IO, no system calls.
//! - Same input → same output → same state mutation.
//!
//! ## Idempotency
//!
//! NOT idempotent by design: calling twice with the same challenge on the
//! same receipt will fail on the second call with `ChallengeNotPending`
//! (status is no longer Pending after first call). This prevents double
//! challenge submission.
//!
//! ## Relationship to CH.6
//!
//! - CH.6 (`process_expired_challenges`) runs per-block after TX execution.
//! - CH.7 (`handle_fraud_proof_challenge`) runs during TX execution.
//! - If CH.7 marks a challenge as Challenged/Slashed, CH.6 will:
//!   - Challenged → produce PendingResolution (no reward distribution).
//!   - Slashed → skip (terminal, no action).
//! - This prevents reward distribution to fraudulent nodes.

use dsdn_common::challenge_state::ChallengeStatus;
use dsdn_common::receipt_v1::Address as CommonAddress;

use crate::challenge_manager::ChallengeResolution;
use crate::state::ChainState;
use crate::types::Address as ChainAddress;

// ════════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════════

/// Minimum locked stake required to submit a fraud proof challenge.
///
/// Prevents spam challenges from dust accounts. The challenger must have
/// at least this amount locked (staked) in the chain.
///
/// V1 value: 1,000 base units. Subject to governance adjustment.
///
/// CONSENSUS-CRITICAL: changing this value requires hard fork.
pub const MIN_CHALLENGER_STAKE: u128 = 1_000;

// ════════════════════════════════════════════════════════════════════════════════
// FRAUD PROOF CHALLENGE (INPUT)
// ════════════════════════════════════════════════════════════════════════════════

/// A fraud proof challenge submission.
///
/// Constructed from a `TxPayload::FraudProofChallenge` transaction.
/// Contains all data needed to validate and process the challenge.
///
/// ## Fields
///
/// - `receipt_hash` — Identifies which pending challenge to dispute.
/// - `challenger_address` — Address of the entity submitting the fraud proof.
///   Used for stake verification and recorded in PendingChallenge.
/// - `fraud_proof_data` — Opaque proof data. V1 uses a stub verifier
///   that accepts any non-empty data. V2+ will implement cryptographic
///   verification.
#[derive(Debug, Clone)]
pub struct FraudProofChallenge {
    /// Hash of the receipt being challenged.
    /// Must match a key in `state.pending_challenges`.
    pub receipt_hash: [u8; 32],

    /// Address of the challenger (common crate Address = [u8; 20]).
    /// Converted to ChainAddress for stake lookup.
    pub challenger_address: CommonAddress,

    /// Fraud proof data (opaque in V1).
    /// V1 stub: non-empty → fraud proven. Empty → not proven.
    /// V2+: cryptographic proof of incorrect computation.
    pub fraud_proof_data: Vec<u8>,
}

// ════════════════════════════════════════════════════════════════════════════════
// FRAUD PROOF ERROR
// ════════════════════════════════════════════════════════════════════════════════

/// Errors from fraud proof challenge handling.
///
/// Each variant is explicit and actionable. No silent failures.
/// On error, zero state mutation has occurred.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FraudProofError {
    /// No pending challenge found for the given receipt hash.
    /// Either the receipt was never claimed, or the challenge was
    /// already resolved and removed.
    ReceiptNotPending {
        receipt_hash: [u8; 32],
    },

    /// The challenge exists but is not in Pending status.
    /// Already Challenged, Cleared, or Slashed — cannot accept
    /// another fraud proof.
    ChallengeNotPending {
        receipt_hash: [u8; 32],
        current_status: ChallengeStatus,
    },

    /// Challenge period has expired. Fraud proofs can only be
    /// submitted while `can_be_challenged(current_time)` returns true.
    ChallengePeriodExpired {
        receipt_hash: [u8; 32],
    },

    /// Challenger does not have enough locked stake.
    /// Required: `MIN_CHALLENGER_STAKE`. Actual: `actual`.
    InsufficientChallengerStake {
        required: u128,
        actual: u128,
    },
}

impl std::fmt::Display for FraudProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReceiptNotPending { .. } => {
                write!(f, "no pending challenge found for receipt hash")
            }
            Self::ChallengeNotPending {
                current_status, ..
            } => {
                write!(
                    f,
                    "challenge is not in Pending status (current: {:?})",
                    current_status
                )
            }
            Self::ChallengePeriodExpired { .. } => {
                write!(f, "challenge period has expired")
            }
            Self::InsufficientChallengerStake { required, actual } => {
                write!(
                    f,
                    "insufficient challenger stake: required {}, actual {}",
                    required, actual
                )
            }
        }
    }
}

impl std::error::Error for FraudProofError {}

// ════════════════════════════════════════════════════════════════════════════════
// MAIN HANDLER
// ════════════════════════════════════════════════════════════════════════════════

/// Processes a fraud proof challenge submission.
///
/// This is the single entry point for all fraud proof processing.
/// Called from `apply_payload` during transaction execution.
///
/// ## Parameters
///
/// - `challenge` — The fraud proof challenge (receipt hash + challenger + proof).
/// - `state` — Mutable chain state. Only mutated after all validation passes.
/// - `current_time` — Current block timestamp (unix seconds).
///
/// ## Returns
///
/// - `Ok(Slashed { receipt_hash, amount })` — Fraud proven, node slashed.
/// - `Ok(PendingResolution { receipt_hash })` — Challenge submitted, fraud not proven.
/// - `Err(FraudProofError)` — Validation failed, no state changed.
///
/// ## Invariants (CONSENSUS-CRITICAL)
///
/// - Challenge status transitions follow the state machine exactly.
/// - `total_challenges_submitted` incremented exactly once per successful call.
/// - `total_fraud_slashed` incremented only when fraud is proven.
/// - No double challenge on the same receipt (Pending check).
/// - No state mutation on validation failure.
/// - Deterministic: same inputs → same outputs → same state.
pub fn handle_fraud_proof_challenge(
    challenge: &FraudProofChallenge,
    state: &mut ChainState,
    current_time: u64,
) -> Result<ChallengeResolution, FraudProofError> {
    // ──────────────────────────────────────────────────────────────────────
    // STEP 1 — VALIDATE RECEIPT EXISTS IN PENDING CHALLENGES (read-only)
    // ──────────────────────────────────────────────────────────────────────
    // The receipt must have an active challenge entry.
    // If not found: receipt was never claimed as Compute, or challenge
    // was already resolved and removed.
    let pending = state
        .pending_challenges
        .get(&challenge.receipt_hash)
        .ok_or(FraudProofError::ReceiptNotPending {
            receipt_hash: challenge.receipt_hash,
        })?;

    // ──────────────────────────────────────────────────────────────────────
    // STEP 2 — VALIDATE STATUS IS PENDING (read-only)
    // ──────────────────────────────────────────────────────────────────────
    // Only Pending challenges can accept fraud proofs.
    // Challenged/Cleared/Slashed are non-Pending → reject.
    //
    // Checked separately from can_be_challenged() for precise error
    // reporting: "already challenged" vs "period expired" are different.
    if pending.status != ChallengeStatus::Pending {
        return Err(FraudProofError::ChallengeNotPending {
            receipt_hash: challenge.receipt_hash,
            current_status: pending.status,
        });
    }

    // ──────────────────────────────────────────────────────────────────────
    // STEP 3 — VALIDATE CHALLENGE PERIOD STILL ACTIVE (read-only)
    // ──────────────────────────────────────────────────────────────────────
    // Uses the official PendingChallenge::can_be_challenged() API.
    // After Step 2 confirms status == Pending, the only reason
    // can_be_challenged returns false is time expiry.
    if !pending.can_be_challenged(current_time) {
        return Err(FraudProofError::ChallengePeriodExpired {
            receipt_hash: challenge.receipt_hash,
        });
    }

    // ──────────────────────────────────────────────────────────────────────
    // STEP 4 — VERIFY CHALLENGER STAKE (read-only)
    // ──────────────────────────────────────────────────────────────────────
    // Challenger must have minimum locked stake to prevent spam.
    verify_challenger_stake(challenge, state)?;

    // ──────────────────────────────────────────────────────────────────────
    // STEP 5 — VERIFY FRAUD PROOF (read-only, deterministic)
    // ──────────────────────────────────────────────────────────────────────
    // V1 stub: non-empty proof data → fraud proven.
    // V2+: cryptographic verification of incorrect computation.
    //
    // This MUST NOT modify state. This MUST NOT panic.
    let fraud_proven = verify_fraud_proof_stub(&challenge.fraud_proof_data);

    // ══════════════════════════════════════════════════════════════════════
    //                      MUTATION BOUNDARY
    // ══════════════════════════════════════════════════════════════════════
    // Everything above is read-only. Everything below mutates state.
    // All validations passed — safe to proceed.

    // ──────────────────────────────────────────────────────────────────────
    // STEP 6 — MARK CHALLENGED (first mutation)
    // ──────────────────────────────────────────────────────────────────────
    // Transition: Pending → Challenged.
    // Records challenger address for audit and future reward.
    //
    // After Step 2 confirmed status == Pending, this call is guaranteed
    // to succeed (mark_challenged only requires Pending status).
    //
    // Borrow note: we drop the immutable `pending` ref from Step 1
    // before taking a mutable ref here.
    let reward_base = {
        let entry = state
            .pending_challenges
            .get_mut(&challenge.receipt_hash)
            .ok_or(FraudProofError::ReceiptNotPending {
                receipt_hash: challenge.receipt_hash,
            })?;

        entry.mark_challenged(challenge.challenger_address);

        // Extract reward_base while we have the mutable ref.
        entry
            .reward_distribution
            .node_reward
            .saturating_add(entry.reward_distribution.validator_reward)
            .saturating_add(entry.reward_distribution.treasury_reward)
    };

    // Increment total_challenges_submitted (saturating — infallible).
    // Incremented for ALL challenge submissions (proven or not).
    state.total_challenges_submitted = state.total_challenges_submitted.saturating_add(1);

    // ──────────────────────────────────────────────────────────────────────
    // STEP 7 — ROUTE BY PROOF RESULT
    // ──────────────────────────────────────────────────────────────────────
    if fraud_proven {
        // ── FRAUD PROVEN: Slash the challenge ───────────────────────
        //
        // Transition: Challenged → Slashed.
        // After Step 6 set status to Challenged, mark_slashed is
        // guaranteed to succeed (requires Challenged status).
        if let Some(entry) = state.pending_challenges.get_mut(&challenge.receipt_hash) {
            entry.mark_slashed();
        }

        // Increment total_fraud_slashed by the full reward_base.
        // The entire deferred reward is prevented from distribution.
        state.total_fraud_slashed = state
            .total_fraud_slashed
            .saturating_add(reward_base);

        Ok(ChallengeResolution::Slashed {
            receipt_hash: challenge.receipt_hash,
            amount: reward_base,
        })
    } else {
        // ── FRAUD NOT PROVEN: Challenge recorded ────────────────────
        //
        // Status is now Challenged (set in Step 6).
        // The dispute system (future CH.8+) may further resolve this.
        // process_expired_challenges (CH.6) will produce
        // PendingResolution for this entry.
        //
        // No slash. No reward distribution.
        Ok(ChallengeResolution::PendingResolution {
            receipt_hash: challenge.receipt_hash,
        })
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// STEP 4 HELPER: CHALLENGER STAKE VERIFICATION
// ════════════════════════════════════════════════════════════════════════════════

/// Verifies that the challenger has sufficient locked stake.
///
/// Lookup path:
/// 1. Convert `challenger_address` ([u8; 20]) to `ChainAddress` (newtype).
/// 2. Look up `state.locked[chain_addr]` for total locked/staked amount.
/// 3. Compare against `MIN_CHALLENGER_STAKE`.
///
/// ## Why `locked` (not `balances`)
///
/// `locked` represents staked funds (skin in the game). Using liquid
/// `balances` would allow challenge spam from accounts with no commitment.
/// Staked funds demonstrate economic participation in the network.
///
/// Read-only. Deterministic. No panic.
fn verify_challenger_stake(
    challenge: &FraudProofChallenge,
    state: &ChainState,
) -> Result<(), FraudProofError> {
    let chain_addr = ChainAddress::from_bytes(challenge.challenger_address);

    let locked_amount = state.locked.get(&chain_addr).copied().unwrap_or(0);

    if locked_amount < MIN_CHALLENGER_STAKE {
        return Err(FraudProofError::InsufficientChallengerStake {
            required: MIN_CHALLENGER_STAKE,
            actual: locked_amount,
        });
    }

    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// STEP 5 HELPER: FRAUD PROOF VERIFICATION (V1 STUB)
// ════════════════════════════════════════════════════════════════════════════════

/// V1 stub for fraud proof verification.
///
/// ## V1 Behavior
///
/// Returns `true` (fraud proven) if `proof_data` is non-empty.
/// Returns `false` (fraud not proven) if `proof_data` is empty.
///
/// This is a deliberate simplification for V1:
/// - Allows functional testing of the full challenge lifecycle.
/// - Non-empty proof data represents "the challenger provided evidence."
/// - Empty proof data represents "no evidence provided."
///
/// ## V2+ Replacement
///
/// Replace with actual cryptographic verification:
/// - Re-execute computation with receipt inputs.
/// - Compare execution commitment against claimed output.
/// - Verify merkle proof of incorrect state transition.
///
/// ## Guarantees
///
/// - Deterministic: same input → same output.
/// - No state modification.
/// - No panic.
/// - No unwrap.
/// - No IO.
#[must_use]
fn verify_fraud_proof_stub(proof_data: &[u8]) -> bool {
    !proof_data.is_empty()
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ChainState;
    use crate::types::Address as ChainAddress;
    use dsdn_common::challenge_state::{ChallengeStatus, PendingChallenge};
    use dsdn_common::claim_validation::RewardDistribution;

    // ── CONSTANTS ───────────────────────────────────────────────────────

    const HASH_A: [u8; 32] = [0xAA; 32];
    const HASH_B: [u8; 32] = [0xBB; 32];
    const NODE_ID_A: [u8; 32] = [0x11; 32];
    const CHALLENGER_ADDR: CommonAddress = [0xC1; 20];
    const OTHER_ADDR: CommonAddress = [0xC2; 20];

    fn chain_addr(byte: u8) -> ChainAddress {
        ChainAddress::from_bytes([byte; 20])
    }

    /// Time within challenge period (after start, before end).
    /// PendingChallenge::new with start=1_000_000 sets
    /// challenge_end = 1_000_000 + CHALLENGE_PERIOD_SECS.
    /// Any time in (1_000_000, challenge_end) is valid.
    const ACTIVE_TIME: u64 = 1_000_001;

    /// Time far in the future — all challenges are expired.
    const FAR_FUTURE: u64 = 99_999_999;

    /// Creates a Pending challenge and registers node + challenger stake.
    fn setup_pending_challenge(state: &mut ChainState) {
        let dist = RewardDistribution::compute(1000);
        let challenge = PendingChallenge::new(HASH_A, NODE_ID_A, dist, 1_000_000);
        state.pending_challenges.insert(HASH_A, challenge);

        // Register node in service_node_index.
        state
            .service_node_index
            .insert(NODE_ID_A, chain_addr(0x42));

        // Give challenger enough locked stake.
        state
            .locked
            .insert(chain_addr(0xC1), MIN_CHALLENGER_STAKE + 1000);
    }

    /// Creates a FraudProofChallenge with non-empty proof data (fraud proven).
    fn make_challenge_proven(receipt_hash: [u8; 32]) -> FraudProofChallenge {
        FraudProofChallenge {
            receipt_hash,
            challenger_address: CHALLENGER_ADDR,
            fraud_proof_data: vec![0x01, 0x02, 0x03],
        }
    }

    /// Creates a FraudProofChallenge with empty proof data (fraud not proven).
    fn make_challenge_not_proven(receipt_hash: [u8; 32]) -> FraudProofChallenge {
        FraudProofChallenge {
            receipt_hash,
            challenger_address: CHALLENGER_ADDR,
            fraud_proof_data: vec![],
        }
    }

    // ════════════════════════════════════════════════════════════════════
    // Step 1: Receipt not in pending_challenges
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn receipt_not_pending_returns_error() {
        let mut state = ChainState::new();
        let challenge = make_challenge_proven(HASH_A);

        let result = handle_fraud_proof_challenge(&challenge, &mut state, ACTIVE_TIME);

        assert_eq!(
            result,
            Err(FraudProofError::ReceiptNotPending {
                receipt_hash: HASH_A,
            })
        );
    }

    // ════════════════════════════════════════════════════════════════════
    // Step 2: Challenge status is not Pending
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn already_challenged_returns_error() {
        let mut state = ChainState::new();
        setup_pending_challenge(&mut state);

        // Manually transition to Challenged.
        state
            .pending_challenges
            .get_mut(&HASH_A)
            .unwrap()
            .mark_challenged([0xF0; 20]);

        let challenge = make_challenge_proven(HASH_A);
        let result = handle_fraud_proof_challenge(&challenge, &mut state, ACTIVE_TIME);

        assert_eq!(
            result,
            Err(FraudProofError::ChallengeNotPending {
                receipt_hash: HASH_A,
                current_status: ChallengeStatus::Challenged,
            })
        );

        // No counters modified.
        assert_eq!(state.total_challenges_submitted, 0);
    }

    #[test]
    fn already_slashed_returns_error() {
        let mut state = ChainState::new();
        setup_pending_challenge(&mut state);

        // Transition: Pending → Challenged → Slashed.
        let entry = state.pending_challenges.get_mut(&HASH_A).unwrap();
        entry.mark_challenged([0xF0; 20]);
        entry.mark_slashed();

        let challenge = make_challenge_proven(HASH_A);
        let result = handle_fraud_proof_challenge(&challenge, &mut state, ACTIVE_TIME);

        assert_eq!(
            result,
            Err(FraudProofError::ChallengeNotPending {
                receipt_hash: HASH_A,
                current_status: ChallengeStatus::Slashed,
            })
        );
    }

    #[test]
    fn already_cleared_returns_error() {
        let mut state = ChainState::new();
        setup_pending_challenge(&mut state);

        // Transition: Pending → Cleared.
        state
            .pending_challenges
            .get_mut(&HASH_A)
            .unwrap()
            .mark_cleared();

        let challenge = make_challenge_proven(HASH_A);
        let result = handle_fraud_proof_challenge(&challenge, &mut state, ACTIVE_TIME);

        assert_eq!(
            result,
            Err(FraudProofError::ChallengeNotPending {
                receipt_hash: HASH_A,
                current_status: ChallengeStatus::Cleared,
            })
        );
    }

    // ════════════════════════════════════════════════════════════════════
    // Step 3: Challenge period expired
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn challenge_period_expired_returns_error() {
        let mut state = ChainState::new();
        setup_pending_challenge(&mut state);

        let challenge = make_challenge_proven(HASH_A);
        let result = handle_fraud_proof_challenge(&challenge, &mut state, FAR_FUTURE);

        assert_eq!(
            result,
            Err(FraudProofError::ChallengePeriodExpired {
                receipt_hash: HASH_A,
            })
        );

        // State unchanged.
        assert_eq!(
            state.pending_challenges.get(&HASH_A).unwrap().status,
            ChallengeStatus::Pending,
        );
        assert_eq!(state.total_challenges_submitted, 0);
    }

    // ════════════════════════════════════════════════════════════════════
    // Step 4: Insufficient challenger stake
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn insufficient_stake_returns_error() {
        let mut state = ChainState::new();
        setup_pending_challenge(&mut state);

        // Override: set challenger stake to 0.
        state.locked.insert(chain_addr(0xC1), 0);

        let challenge = make_challenge_proven(HASH_A);
        let result = handle_fraud_proof_challenge(&challenge, &mut state, ACTIVE_TIME);

        assert_eq!(
            result,
            Err(FraudProofError::InsufficientChallengerStake {
                required: MIN_CHALLENGER_STAKE,
                actual: 0,
            })
        );

        // State unchanged.
        assert_eq!(
            state.pending_challenges.get(&HASH_A).unwrap().status,
            ChallengeStatus::Pending,
        );
    }

    #[test]
    fn stake_below_minimum_returns_error() {
        let mut state = ChainState::new();
        setup_pending_challenge(&mut state);

        // Set stake to exactly MIN - 1.
        state
            .locked
            .insert(chain_addr(0xC1), MIN_CHALLENGER_STAKE - 1);

        let challenge = make_challenge_proven(HASH_A);
        let result = handle_fraud_proof_challenge(&challenge, &mut state, ACTIVE_TIME);

        assert_eq!(
            result,
            Err(FraudProofError::InsufficientChallengerStake {
                required: MIN_CHALLENGER_STAKE,
                actual: MIN_CHALLENGER_STAKE - 1,
            })
        );
    }

    #[test]
    fn stake_exactly_minimum_passes() {
        let mut state = ChainState::new();
        setup_pending_challenge(&mut state);

        // Set stake to exactly MIN.
        state
            .locked
            .insert(chain_addr(0xC1), MIN_CHALLENGER_STAKE);

        let challenge = make_challenge_proven(HASH_A);
        let result = handle_fraud_proof_challenge(&challenge, &mut state, ACTIVE_TIME);

        assert!(result.is_ok());
    }

    #[test]
    fn no_locked_entry_returns_error() {
        let mut state = ChainState::new();
        setup_pending_challenge(&mut state);

        // Remove challenger from locked map entirely.
        state.locked.remove(&chain_addr(0xC1));

        let challenge = make_challenge_proven(HASH_A);
        let result = handle_fraud_proof_challenge(&challenge, &mut state, ACTIVE_TIME);

        assert_eq!(
            result,
            Err(FraudProofError::InsufficientChallengerStake {
                required: MIN_CHALLENGER_STAKE,
                actual: 0,
            })
        );
    }

    // ════════════════════════════════════════════════════════════════════
    // Step 5 + 6 + 7: Fraud proven → Slashed
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn fraud_proven_slashes_challenge() {
        let mut state = ChainState::new();
        setup_pending_challenge(&mut state);

        let challenge = make_challenge_proven(HASH_A);
        let result = handle_fraud_proof_challenge(&challenge, &mut state, ACTIVE_TIME);

        // Returns Slashed with full reward_base.
        assert_eq!(
            result,
            Ok(ChallengeResolution::Slashed {
                receipt_hash: HASH_A,
                amount: 1000, // node(700) + validator(200) + treasury(100)
            })
        );

        // Status is now Slashed.
        let entry = state.pending_challenges.get(&HASH_A).unwrap();
        assert_eq!(entry.status, ChallengeStatus::Slashed);
        assert_eq!(entry.challenger, Some(CHALLENGER_ADDR));

        // Counters updated.
        assert_eq!(state.total_challenges_submitted, 1);
        assert_eq!(state.total_fraud_slashed, 1000);
    }

    #[test]
    fn fraud_proven_different_distribution_amounts() {
        let mut state = ChainState::new();
        let dist = RewardDistribution::compute(5000);
        let challenge_entry = PendingChallenge::new(HASH_B, NODE_ID_A, dist, 1_000_000);
        state.pending_challenges.insert(HASH_B, challenge_entry);
        state
            .service_node_index
            .insert(NODE_ID_A, chain_addr(0x42));
        state
            .locked
            .insert(chain_addr(0xC1), MIN_CHALLENGER_STAKE);

        let challenge = make_challenge_proven(HASH_B);
        let result = handle_fraud_proof_challenge(&challenge, &mut state, ACTIVE_TIME);

        assert_eq!(
            result,
            Ok(ChallengeResolution::Slashed {
                receipt_hash: HASH_B,
                amount: 5000,
            })
        );

        assert_eq!(state.total_fraud_slashed, 5000);
    }

    // ════════════════════════════════════════════════════════════════════
    // Step 5 + 6 + 7: Fraud not proven → PendingResolution
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn fraud_not_proven_marks_challenged_only() {
        let mut state = ChainState::new();
        setup_pending_challenge(&mut state);

        let challenge = make_challenge_not_proven(HASH_A);
        let result = handle_fraud_proof_challenge(&challenge, &mut state, ACTIVE_TIME);

        // Returns PendingResolution.
        assert_eq!(
            result,
            Ok(ChallengeResolution::PendingResolution {
                receipt_hash: HASH_A,
            })
        );

        // Status is Challenged (NOT Slashed).
        let entry = state.pending_challenges.get(&HASH_A).unwrap();
        assert_eq!(entry.status, ChallengeStatus::Challenged);
        assert_eq!(entry.challenger, Some(CHALLENGER_ADDR));

        // total_challenges_submitted incremented.
        assert_eq!(state.total_challenges_submitted, 1);

        // total_fraud_slashed NOT incremented.
        assert_eq!(state.total_fraud_slashed, 0);
    }

    // ════════════════════════════════════════════════════════════════════
    // No double challenge
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn double_challenge_rejected() {
        let mut state = ChainState::new();
        setup_pending_challenge(&mut state);

        // First challenge: succeeds.
        let c1 = make_challenge_not_proven(HASH_A);
        let r1 = handle_fraud_proof_challenge(&c1, &mut state, ACTIVE_TIME);
        assert!(r1.is_ok());

        // Second challenge on same receipt: rejected (status is Challenged).
        let c2 = FraudProofChallenge {
            receipt_hash: HASH_A,
            challenger_address: OTHER_ADDR,
            fraud_proof_data: vec![0xFF],
        };
        // Give other challenger stake too.
        state
            .locked
            .insert(chain_addr(0xC2), MIN_CHALLENGER_STAKE);

        let r2 = handle_fraud_proof_challenge(&c2, &mut state, ACTIVE_TIME);
        assert_eq!(
            r2,
            Err(FraudProofError::ChallengeNotPending {
                receipt_hash: HASH_A,
                current_status: ChallengeStatus::Challenged,
            })
        );

        // Counter NOT incremented on second attempt.
        assert_eq!(state.total_challenges_submitted, 1);
    }

    // ════════════════════════════════════════════════════════════════════
    // No state mutation on validation failure
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn validation_failure_zero_state_mutation() {
        let mut state = ChainState::new();
        setup_pending_challenge(&mut state);

        // Snapshot state.
        let challenges_before = state.total_challenges_submitted;
        let slashed_before = state.total_fraud_slashed;
        let status_before = state.pending_challenges.get(&HASH_A).unwrap().status;

        // Fail at Step 3 (expired).
        let challenge = make_challenge_proven(HASH_A);
        let _ = handle_fraud_proof_challenge(&challenge, &mut state, FAR_FUTURE);

        // State unchanged.
        assert_eq!(state.total_challenges_submitted, challenges_before);
        assert_eq!(state.total_fraud_slashed, slashed_before);
        assert_eq!(
            state.pending_challenges.get(&HASH_A).unwrap().status,
            status_before,
        );
    }

    // ════════════════════════════════════════════════════════════════════
    // verify_fraud_proof_stub
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn stub_nonempty_returns_true() {
        assert!(verify_fraud_proof_stub(&[0x01]));
        assert!(verify_fraud_proof_stub(&[0x00, 0x00]));
        assert!(verify_fraud_proof_stub(&vec![0xFF; 1024]));
    }

    #[test]
    fn stub_empty_returns_false() {
        assert!(!verify_fraud_proof_stub(&[]));
    }

    #[test]
    fn stub_deterministic() {
        let data = vec![0xAB; 32];
        assert_eq!(
            verify_fraud_proof_stub(&data),
            verify_fraud_proof_stub(&data),
        );
    }

    // ════════════════════════════════════════════════════════════════════
    // verify_challenger_stake
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn stake_verification_passes_with_exact_minimum() {
        let mut state = ChainState::new();
        state
            .locked
            .insert(chain_addr(0xC1), MIN_CHALLENGER_STAKE);

        let challenge = make_challenge_proven(HASH_A);
        assert!(verify_challenger_stake(&challenge, &state).is_ok());
    }

    #[test]
    fn stake_verification_passes_with_excess() {
        let mut state = ChainState::new();
        state
            .locked
            .insert(chain_addr(0xC1), MIN_CHALLENGER_STAKE * 100);

        let challenge = make_challenge_proven(HASH_A);
        assert!(verify_challenger_stake(&challenge, &state).is_ok());
    }

    #[test]
    fn stake_verification_fails_with_zero() {
        let state = ChainState::new();
        let challenge = make_challenge_proven(HASH_A);
        assert!(verify_challenger_stake(&challenge, &state).is_err());
    }

    // ════════════════════════════════════════════════════════════════════
    // Error Display
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn error_display_receipt_not_pending() {
        let err = FraudProofError::ReceiptNotPending {
            receipt_hash: HASH_A,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("no pending challenge"));
    }

    #[test]
    fn error_display_challenge_not_pending() {
        let err = FraudProofError::ChallengeNotPending {
            receipt_hash: HASH_A,
            current_status: ChallengeStatus::Challenged,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("not in Pending status"));
    }

    #[test]
    fn error_display_period_expired() {
        let err = FraudProofError::ChallengePeriodExpired {
            receipt_hash: HASH_A,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("expired"));
    }

    #[test]
    fn error_display_insufficient_stake() {
        let err = FraudProofError::InsufficientChallengerStake {
            required: 1000,
            actual: 500,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("1000"));
        assert!(msg.contains("500"));
    }

    // ════════════════════════════════════════════════════════════════════
    // Integration: CH.6 compatibility
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn slashed_challenge_skipped_by_ch6() {
        let mut state = ChainState::new();
        setup_pending_challenge(&mut state);

        // CH.7: Submit fraud proof → Slashed.
        let challenge = make_challenge_proven(HASH_A);
        let result = handle_fraud_proof_challenge(&challenge, &mut state, ACTIVE_TIME);
        assert!(matches!(result, Ok(ChallengeResolution::Slashed { .. })));

        // CH.6: process_expired_challenges should skip Slashed entry.
        let resolutions =
            crate::challenge_manager::process_expired_challenges(&mut state, FAR_FUTURE);

        // No resolution for Slashed (terminal).
        assert!(resolutions.is_empty());

        // No reward distributed.
        assert_eq!(state.total_rewards_distributed, 0);
    }

    #[test]
    fn challenged_produces_pending_resolution_in_ch6() {
        let mut state = ChainState::new();
        setup_pending_challenge(&mut state);

        // CH.7: Submit unproven fraud proof → Challenged.
        let challenge = make_challenge_not_proven(HASH_A);
        let result = handle_fraud_proof_challenge(&challenge, &mut state, ACTIVE_TIME);
        assert!(matches!(
            result,
            Ok(ChallengeResolution::PendingResolution { .. })
        ));

        // CH.6: process_expired_challenges sees Challenged → PendingResolution.
        let resolutions =
            crate::challenge_manager::process_expired_challenges(&mut state, FAR_FUTURE);

        assert_eq!(resolutions.len(), 1);
        assert!(matches!(
            resolutions[0],
            ChallengeResolution::PendingResolution { .. }
        ));

        // No reward distributed (Challenged, not Cleared).
        assert_eq!(state.total_rewards_distributed, 0);
    }
}