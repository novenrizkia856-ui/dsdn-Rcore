//! # ReceiptV1 Verification Logic
//!
//! Modul ini mengimplementasikan pipeline verifikasi untuk [`ReceiptV1`]
//! sebelum reward distribution.
//!
//! ## Verification Order (CONSENSUS-CRITICAL)
//!
//! Urutan disusun **cheap first, expensive last** untuk gas efficiency:
//!
//! | # | Check | Cost | Rationale |
//! |---|-------|------|-----------|
//! | 1 | `check_reward_base` | O(1) comparison | Range check, trivial |
//! | 2 | `check_receipt_age` | O(1) arithmetic | Safe timestamp math |
//! | 3 | `check_epoch` | O(1) comparison | Equality check |
//! | 4 | `check_not_claimed` | O(1) HashSet lookup | Dedup tracker |
//! | 5 | `check_execution_commitment` | O(1) option check | Type-dependent presence |
//! | 6 | `verify_node_signature` | Expensive (Ed25519) | Crypto verification |
//! | 7 | `verify_threshold_signature` | Expensive (Ed25519/FROST) | Crypto verification |
//!
//! ## Design Principles
//!
//! - **No mutation**: All functions are read-only. State is never modified.
//! - **Deterministic**: Same inputs always produce the same result.
//! - **No panic**: No `unwrap`, `expect`, or `panic!`. All errors explicit.
//! - **Independent checks**: Each function can be tested in isolation.
//! - **Short-circuit**: First failure terminates the pipeline.
//!
//! ## Signature Verification
//!
//! Both `verify_node_signature` and `verify_threshold_signature` verify
//! against `ReceiptV1::compute_signable_hash()`, which excludes signature
//! fields to avoid circular dependency.
//!
//! The threshold signature currently uses Ed25519 verification against the
//! coordinator group public key stored in `ChainState::coordinator_group_pubkey`.
//! This will be upgraded to native FROST aggregate verification in a future
//! release without changing the verification interface.

use dsdn_common::claim_validation::ClaimValidationError;
use dsdn_common::economic_constants::{MAX_RECEIPT_AGE_SECS, MIN_REWARD_BASE, MAX_REWARD_BASE};
use dsdn_common::receipt_v1::ReceiptV1;

use crate::crypto;
use crate::state::ChainState;

// ════════════════════════════════════════════════════════════════════════════════
// MAIN ENTRY POINT
// ════════════════════════════════════════════════════════════════════════════════

/// Verifies a [`ReceiptV1`] through the full validation pipeline.
///
/// Checks are executed in order from cheapest to most expensive.
/// The first failure short-circuits and returns the corresponding
/// [`ClaimValidationError`].
///
/// This function does **NOT** mutate `state`. It is purely a validation
/// gate. The caller is responsible for marking the receipt as claimed
/// and distributing rewards after successful verification.
///
/// ## Parameters
///
/// - `receipt` — The receipt to verify.
/// - `state` — Current chain state (read-only).
/// - `current_time` — Current block timestamp (unix seconds).
/// - `current_epoch` — Current chain epoch number.
///
/// ## Returns
///
/// - `Ok(())` — All 7 checks passed.
/// - `Err(ClaimValidationError)` — First failed check.
pub fn verify_receipt_v1(
    receipt: &ReceiptV1,
    state: &ChainState,
    current_time: u64,
    current_epoch: u64,
) -> Result<(), ClaimValidationError> {
    // 1. Cheap: reward base range check
    check_reward_base(receipt.reward_base())?;

    // 2. Cheap: receipt age (timestamp freshness)
    check_receipt_age(receipt.timestamp(), current_time)?;

    // 3. Cheap: epoch consistency
    check_epoch(receipt.epoch(), current_epoch)?;

    // 4. Cheap: anti double-claim (O(1) HashSet lookup)
    let receipt_hash = receipt.compute_receipt_hash();
    check_not_claimed(&receipt_hash, state)?;

    // 5. Cheap: execution commitment presence (Compute only)
    check_execution_commitment(receipt)?;

    // 6. Expensive: node Ed25519 signature verification
    let signable_hash = receipt.compute_signable_hash();
    verify_node_signature(
        receipt.node_id(),
        &signable_hash,
        receipt.node_signature(),
    )?;

    // 7. Expensive: coordinator threshold signature verification
    verify_threshold_signature(
        state.coordinator_group_pubkey.as_ref(),
        &signable_hash,
        receipt.coordinator_threshold_signature(),
    )?;

    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// CHECK 1: REWARD BASE
// ════════════════════════════════════════════════════════════════════════════════

/// Validates that `reward_base` is within the allowed range.
///
/// ## Range
///
/// `MIN_REWARD_BASE` (1) `..=` `MAX_REWARD_BASE` (1,000,000,000,000)
///
/// ## Errors
///
/// [`ClaimValidationError::InvalidRewardBase`] if out of range.
///
/// ## Complexity
///
/// O(1). Two comparisons.
pub fn check_reward_base(reward_base: u128) -> Result<(), ClaimValidationError> {
    if reward_base < MIN_REWARD_BASE || reward_base > MAX_REWARD_BASE {
        return Err(ClaimValidationError::InvalidRewardBase {
            value: reward_base,
        });
    }
    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// CHECK 2: RECEIPT AGE
// ════════════════════════════════════════════════════════════════════════════════

/// Validates that the receipt has not expired.
///
/// Computes `age = current_time - receipt_timestamp` using saturating
/// arithmetic to prevent underflow when clocks are skewed.
///
/// ## Errors
///
/// [`ClaimValidationError::ReceiptExpired`] if age exceeds
/// `MAX_RECEIPT_AGE_SECS` (86,400 seconds = 24 hours).
///
/// ## Complexity
///
/// O(1). Safe arithmetic + comparison.
pub fn check_receipt_age(
    receipt_timestamp: u64,
    current_time: u64,
) -> Result<(), ClaimValidationError> {
    // Saturating subtraction: if receipt is in the future, age = 0 (not expired).
    let age_secs = current_time.saturating_sub(receipt_timestamp);

    if age_secs > MAX_RECEIPT_AGE_SECS {
        return Err(ClaimValidationError::ReceiptExpired {
            age_secs,
            max_secs: MAX_RECEIPT_AGE_SECS,
        });
    }
    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// CHECK 3: EPOCH CONSISTENCY
// ════════════════════════════════════════════════════════════════════════════════

/// Validates that the receipt epoch matches the current chain epoch.
///
/// ## Errors
///
/// [`ClaimValidationError::EpochMismatch`] if epochs differ.
///
/// ## Complexity
///
/// O(1). Single equality check.
pub fn check_epoch(
    receipt_epoch: u64,
    current_epoch: u64,
) -> Result<(), ClaimValidationError> {
    if receipt_epoch != current_epoch {
        return Err(ClaimValidationError::EpochMismatch {
            receipt_epoch,
            current_epoch,
        });
    }
    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// CHECK 4: ANTI DOUBLE-CLAIM
// ════════════════════════════════════════════════════════════════════════════════

/// Validates that the receipt has not been previously claimed.
///
/// Uses `state.receipt_dedup_tracker` for O(1) lookup.
///
/// ## Errors
///
/// [`ClaimValidationError::ReceiptAlreadyClaimed`] if the receipt hash
/// is found in the dedup tracker.
///
/// ## Complexity
///
/// O(1). HashSet `contains` check.
pub fn check_not_claimed(
    receipt_hash: &[u8; 32],
    state: &ChainState,
) -> Result<(), ClaimValidationError> {
    if state.receipt_dedup_tracker.is_claimed(receipt_hash) {
        return Err(ClaimValidationError::ReceiptAlreadyClaimed {
            receipt_hash: *receipt_hash,
        });
    }
    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// CHECK 5: EXECUTION COMMITMENT
// ════════════════════════════════════════════════════════════════════════════════

/// Validates execution commitment presence for Compute receipts.
///
/// - If `receipt_type == Compute` and `execution_commitment` is `None`
///   → error.
/// - If `receipt_type == Storage` → always passes (commitment not required).
///
/// ## Errors
///
/// [`ClaimValidationError::MissingExecutionCommitment`] if Compute receipt
/// lacks an execution commitment.
///
/// ## Complexity
///
/// O(1). Boolean + Option check.
pub fn check_execution_commitment(receipt: &ReceiptV1) -> Result<(), ClaimValidationError> {
    if receipt.requires_challenge_period() && receipt.execution_commitment().is_none() {
        return Err(ClaimValidationError::MissingExecutionCommitment);
    }
    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// CHECK 6: NODE SIGNATURE (Ed25519)
// ════════════════════════════════════════════════════════════════════════════════

/// Verifies the node's Ed25519 signature over the signable hash.
///
/// The `node_id` field of `ReceiptV1` is the node's 32-byte Ed25519
/// public key. The signature is verified against
/// `ReceiptV1::compute_signable_hash()` (which excludes signature fields).
///
/// ## Errors
///
/// [`ClaimValidationError::InvalidNodeSignature`] if verification fails
/// or if the crypto library returns an error (malformed key/signature).
///
/// ## Complexity
///
/// O(1) but expensive — Ed25519 signature verification.
pub fn verify_node_signature(
    node_pubkey: &[u8; 32],
    signable_hash: &[u8; 32],
    node_signature: &[u8],
) -> Result<(), ClaimValidationError> {
    let valid = crypto::verify_signature(node_pubkey, signable_hash, node_signature)
        .unwrap_or(false);

    if !valid {
        return Err(ClaimValidationError::InvalidNodeSignature);
    }
    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// CHECK 7: THRESHOLD SIGNATURE (FROST / Ed25519 PLACEHOLDER)
// ════════════════════════════════════════════════════════════════════════════════

/// Verifies the coordinator's threshold signature over the signable hash.
///
/// Currently uses Ed25519 verification against the coordinator group
/// public key stored in `ChainState::coordinator_group_pubkey`.
///
/// ## FROST Upgrade Path
///
/// When native FROST aggregate verification is implemented, this function
/// will be updated to use `frost::verify_aggregate(group_key, msg, sig)`
/// instead of Ed25519. The function signature remains the same.
///
/// ## Errors
///
/// [`ClaimValidationError::InvalidThresholdSignature`] if:
/// - `coordinator_group_pubkey` is `None` (not configured).
/// - Signature verification fails or crypto returns an error.
///
/// ## Complexity
///
/// O(1) but expensive — Ed25519 (future: FROST) signature verification.
pub fn verify_threshold_signature(
    coordinator_pubkey: Option<&[u8; 32]>,
    signable_hash: &[u8; 32],
    threshold_signature: &[u8],
) -> Result<(), ClaimValidationError> {
    let pubkey = match coordinator_pubkey {
        Some(pk) => pk,
        None => {
            // Coordinator group key not configured — cannot verify.
            return Err(ClaimValidationError::InvalidThresholdSignature);
        }
    };

    let valid = crypto::verify_signature(pubkey, signable_hash, threshold_signature)
        .unwrap_or(false);

    if !valid {
        return Err(ClaimValidationError::InvalidThresholdSignature);
    }
    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── CHECK 1: REWARD BASE ────────────────────────────────────────────

    #[test]
    fn reward_base_valid_min() {
        assert!(check_reward_base(MIN_REWARD_BASE).is_ok());
    }

    #[test]
    fn reward_base_valid_max() {
        assert!(check_reward_base(MAX_REWARD_BASE).is_ok());
    }

    #[test]
    fn reward_base_valid_mid() {
        assert!(check_reward_base(500_000).is_ok());
    }

    #[test]
    fn reward_base_zero_rejected() {
        let err = check_reward_base(0).unwrap_err();
        assert_eq!(err, ClaimValidationError::InvalidRewardBase { value: 0 });
    }

    #[test]
    fn reward_base_above_max_rejected() {
        let val = MAX_REWARD_BASE + 1;
        let err = check_reward_base(val).unwrap_err();
        assert_eq!(err, ClaimValidationError::InvalidRewardBase { value: val });
    }

    #[test]
    fn reward_base_u128_max_rejected() {
        let err = check_reward_base(u128::MAX).unwrap_err();
        assert_eq!(
            err,
            ClaimValidationError::InvalidRewardBase { value: u128::MAX }
        );
    }

    // ── CHECK 2: RECEIPT AGE ────────────────────────────────────────────

    #[test]
    fn receipt_age_fresh() {
        assert!(check_receipt_age(1000, 1001).is_ok());
    }

    #[test]
    fn receipt_age_at_limit() {
        assert!(check_receipt_age(1000, 1000 + MAX_RECEIPT_AGE_SECS).is_ok());
    }

    #[test]
    fn receipt_age_same_timestamp() {
        assert!(check_receipt_age(1000, 1000).is_ok());
    }

    #[test]
    fn receipt_age_future_timestamp() {
        // Receipt in the future (clock skew): age saturates to 0 → valid.
        assert!(check_receipt_age(2000, 1000).is_ok());
    }

    #[test]
    fn receipt_age_expired() {
        let err = check_receipt_age(1000, 1000 + MAX_RECEIPT_AGE_SECS + 1).unwrap_err();
        match err {
            ClaimValidationError::ReceiptExpired { age_secs, max_secs } => {
                assert_eq!(age_secs, MAX_RECEIPT_AGE_SECS + 1);
                assert_eq!(max_secs, MAX_RECEIPT_AGE_SECS);
            }
            _ => panic!("expected ReceiptExpired"),
        }
    }

    #[test]
    fn receipt_age_zero_timestamps() {
        assert!(check_receipt_age(0, 0).is_ok());
    }

    #[test]
    fn receipt_age_overflow_safe() {
        // current_time = 0, receipt_timestamp = u64::MAX
        // saturating_sub(0, u64::MAX) = 0 → not expired.
        assert!(check_receipt_age(u64::MAX, 0).is_ok());
    }

    // ── CHECK 3: EPOCH ──────────────────────────────────────────────────

    #[test]
    fn epoch_match() {
        assert!(check_epoch(42, 42).is_ok());
    }

    #[test]
    fn epoch_mismatch() {
        let err = check_epoch(41, 42).unwrap_err();
        assert_eq!(
            err,
            ClaimValidationError::EpochMismatch {
                receipt_epoch: 41,
                current_epoch: 42,
            }
        );
    }

    #[test]
    fn epoch_zero() {
        assert!(check_epoch(0, 0).is_ok());
    }

    // ── CHECK 4: NOT CLAIMED ────────────────────────────────────────────

    #[test]
    fn not_claimed_passes_on_empty_state() {
        let state = ChainState::new();
        let hash = [0xAB; 32];
        assert!(check_not_claimed(&hash, &state).is_ok());
    }

    #[test]
    fn not_claimed_fails_on_claimed_receipt() {
        let mut state = ChainState::new();
        let hash = [0xAB; 32];
        let _ = state.receipt_dedup_tracker.mark_claimed(hash);

        let err = check_not_claimed(&hash, &state).unwrap_err();
        assert_eq!(
            err,
            ClaimValidationError::ReceiptAlreadyClaimed {
                receipt_hash: hash,
            }
        );
    }

    // ── CHECK 6 & 7: SIGNATURE VERIFICATION ─────────────────────────────

    #[test]
    fn node_signature_invalid_bytes_rejected() {
        let fake_pubkey = [0x01; 32];
        let fake_hash = [0x02; 32];
        let fake_sig = vec![0x03; 64];

        let err = verify_node_signature(&fake_pubkey, &fake_hash, &fake_sig).unwrap_err();
        assert_eq!(err, ClaimValidationError::InvalidNodeSignature);
    }

    #[test]
    fn node_signature_empty_sig_rejected() {
        let fake_pubkey = [0x01; 32];
        let fake_hash = [0x02; 32];

        let err = verify_node_signature(&fake_pubkey, &fake_hash, &[]).unwrap_err();
        assert_eq!(err, ClaimValidationError::InvalidNodeSignature);
    }

    #[test]
    fn threshold_signature_no_coordinator_key() {
        let fake_hash = [0x02; 32];
        let fake_sig = vec![0x03; 64];

        let err = verify_threshold_signature(None, &fake_hash, &fake_sig).unwrap_err();
        assert_eq!(err, ClaimValidationError::InvalidThresholdSignature);
    }

    #[test]
    fn threshold_signature_invalid_bytes_rejected() {
        let fake_pubkey = [0x01; 32];
        let fake_hash = [0x02; 32];
        let fake_sig = vec![0x03; 64];

        let err =
            verify_threshold_signature(Some(&fake_pubkey), &fake_hash, &fake_sig).unwrap_err();
        assert_eq!(err, ClaimValidationError::InvalidThresholdSignature);
    }
}