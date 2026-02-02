//! # Stake Requirements & Class Gating (14B.3)
//!
//! Defines minimum stake thresholds per [`NodeClass`] and provides
//! deterministic verification and classification mechanisms.
//!
//! ## Overview
//!
//! Every DSDN service node must hold a minimum stake (in smallest on-chain
//! units, 18 decimals) to participate. The required amount depends on the
//! node's class:
//!
//! | Class | Human-Readable | On-Chain (18 decimals) |
//! |-------|----------------|-----------------------|
//! | Storage | 5000 NUSA | 5_000_000_000_000_000_000_000 |
//! | Compute | 500 NUSA | 500_000_000_000_000_000_000 |
//!
//! ## Verification
//!
//! [`StakeRequirement::check`] validates that a given stake amount meets
//! the minimum for a specified class. The check is strict:
//!
//! 1. Zero stake is always rejected (`StakeError::ZeroStake`).
//! 2. Stake below the class minimum is rejected (`StakeError::InsufficientStake`).
//! 3. Only exact-or-above passes.
//!
//! ## Classification
//!
//! [`StakeRequirement::classify_by_stake`] determines the **highest** class
//! a stake amount qualifies for:
//!
//! - `stake >= min_stake_storage` → `Some(NodeClass::Storage)`
//! - `stake >= min_stake_compute` → `Some(NodeClass::Compute)`
//! - otherwise (including zero) → `None`
//!
//! ## Safety Properties
//!
//! - All comparisons use `u128` — no floating point, no runtime exponentiation.
//! - Both methods are pure functions: deterministic, no side effects.
//! - Stake verification does NOT trigger status transitions. It is a check
//!   only — the caller decides how to act on the result.

use serde::{Deserialize, Serialize};
use std::fmt;

use super::identity::NodeClass;

// ════════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════════

/// Minimum stake for Storage nodes in smallest on-chain units (18 decimals).
///
/// 5000 NUSA = 5000 × 10^18 = 5_000_000_000_000_000_000_000
const DEFAULT_MIN_STAKE_STORAGE: u128 = 5_000_000_000_000_000_000_000;

/// Minimum stake for Compute nodes in smallest on-chain units (18 decimals).
///
/// 500 NUSA = 500 × 10^18 = 500_000_000_000_000_000_000
const DEFAULT_MIN_STAKE_COMPUTE: u128 = 500_000_000_000_000_000_000;

// ════════════════════════════════════════════════════════════════════════════════
// STAKE REQUIREMENT
// ════════════════════════════════════════════════════════════════════════════════

/// Per-class minimum stake thresholds in on-chain smallest units (18 decimals).
///
/// `StakeRequirement` holds the minimum stake for each [`NodeClass`].
/// The default values correspond to the DSDN protocol specification:
///
/// - **Storage**: 5000 NUSA = `5_000_000_000_000_000_000_000`
/// - **Compute**: 500 NUSA = `500_000_000_000_000_000_000`
///
/// These values are hardcoded — no runtime conversion or floating-point
/// arithmetic is used.
///
/// ## Methods
///
/// - [`check`](StakeRequirement::check): Validates stake against a class minimum.
/// - [`classify_by_stake`](StakeRequirement::classify_by_stake): Determines the
///   highest class a stake qualifies for.
///
/// ## Usage
///
/// ```rust,ignore
/// use dsdn_common::{StakeRequirement, NodeClass};
///
/// let req = StakeRequirement::default();
///
/// // Check if stake meets Storage requirement
/// req.check(&NodeClass::Storage, 5_000_000_000_000_000_000_000)?; // Ok
///
/// // Classify by stake amount
/// let class = req.classify_by_stake(600_000_000_000_000_000_000);
/// assert_eq!(class, Some(NodeClass::Compute));
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StakeRequirement {
    /// Minimum stake for `NodeClass::Storage` in smallest on-chain units.
    pub min_stake_storage: u128,
    /// Minimum stake for `NodeClass::Compute` in smallest on-chain units.
    pub min_stake_compute: u128,
}

impl Default for StakeRequirement {
    /// Returns the protocol-default stake requirements.
    ///
    /// - Storage: 5000 NUSA = `5_000_000_000_000_000_000_000`
    /// - Compute: 500 NUSA = `500_000_000_000_000_000_000`
    fn default() -> Self {
        Self {
            min_stake_storage: DEFAULT_MIN_STAKE_STORAGE,
            min_stake_compute: DEFAULT_MIN_STAKE_COMPUTE,
        }
    }
}

impl StakeRequirement {
    /// Validates that `actual_stake` meets the minimum requirement for `class`.
    ///
    /// This is a **pure function** — deterministic, no side effects, no
    /// external state. The result depends only on the inputs and the
    /// configured thresholds.
    ///
    /// ## Check Order (Strict)
    ///
    /// 1. If `actual_stake == 0` → `Err(StakeError::ZeroStake)`
    /// 2. Determine `required` based on `class`:
    ///    - `NodeClass::Storage` → `self.min_stake_storage`
    ///    - `NodeClass::Compute` → `self.min_stake_compute`
    /// 3. If `actual_stake < required` → `Err(StakeError::InsufficientStake { .. })`
    /// 4. Otherwise → `Ok(())`
    ///
    /// ## Arguments
    ///
    /// * `class` — The node class to check against.
    /// * `actual_stake` — The node's actual staked amount in smallest units.
    ///
    /// ## Returns
    ///
    /// `Ok(())` if the stake meets the requirement, or an appropriate
    /// `StakeError` if it does not.
    ///
    /// ## Note
    ///
    /// This method does NOT trigger status transitions. It is a verification
    /// check only — the caller decides how to act on the result.
    pub fn check(
        &self,
        class: &NodeClass,
        actual_stake: u128,
    ) -> Result<(), StakeError> {
        // Step 1: Zero stake is always invalid
        if actual_stake == 0 {
            return Err(StakeError::ZeroStake);
        }

        // Step 2: Determine required stake based on class
        let required = match class {
            NodeClass::Storage => self.min_stake_storage,
            NodeClass::Compute => self.min_stake_compute,
        };

        // Step 3: Compare actual against required
        if actual_stake < required {
            return Err(StakeError::InsufficientStake {
                required,
                actual: actual_stake,
                class: *class,
            });
        }

        // Step 4: Stake meets requirement
        Ok(())
    }

    /// Determines the **highest** [`NodeClass`] that `stake` qualifies for.
    ///
    /// This is a **pure function** — deterministic, no side effects, no
    /// external state. Classification follows a strict priority order:
    /// Storage (highest) is checked first, then Compute.
    ///
    /// ## Classification Rules (Strict Order)
    ///
    /// 1. If `stake == 0` → `None`
    /// 2. If `stake >= min_stake_storage` → `Some(NodeClass::Storage)`
    /// 3. If `stake >= min_stake_compute` → `Some(NodeClass::Compute)`
    /// 4. Otherwise → `None`
    ///
    /// ## Arguments
    ///
    /// * `stake` — The stake amount to classify, in smallest on-chain units.
    ///
    /// ## Returns
    ///
    /// `Some(NodeClass)` for the highest qualifying class, or `None` if
    /// the stake is zero or below all class minimums.
    ///
    /// ## Note
    ///
    /// This method does NOT assign a class to a node. It only reports what
    /// class the stake amount would qualify for. Class assignment is handled
    /// by upper layers.
    #[must_use]
    pub fn classify_by_stake(&self, stake: u128) -> Option<NodeClass> {
        // Step 1: Zero stake qualifies for nothing
        if stake == 0 {
            return None;
        }

        // Step 2: Check highest class first (Storage)
        if stake >= self.min_stake_storage {
            return Some(NodeClass::Storage);
        }

        // Step 3: Check next class (Compute)
        if stake >= self.min_stake_compute {
            return Some(NodeClass::Compute);
        }

        // Step 4: Below all minimums
        None
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// STAKE ERROR
// ════════════════════════════════════════════════════════════════════════════════

/// Error type for stake verification failures.
///
/// Returned by [`StakeRequirement::check`] when a node's stake does not
/// meet the minimum requirement for its class.
///
/// ## Variants
///
/// - [`ZeroStake`](StakeError::ZeroStake): The stake amount is exactly zero.
///   Zero stake is never valid for any node class.
///
/// - [`InsufficientStake`](StakeError::InsufficientStake): The stake is
///   non-zero but below the class minimum. Includes the required amount,
///   actual amount, and the class for diagnostic purposes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StakeError {
    /// The stake amount provided is exactly zero.
    /// Zero stake is always rejected regardless of node class.
    ZeroStake,

    /// The stake is non-zero but below the minimum for the specified class.
    InsufficientStake {
        /// Minimum stake required for the class (in smallest on-chain units).
        required: u128,
        /// Actual stake provided (in smallest on-chain units).
        actual: u128,
        /// The node class that was checked against.
        class: NodeClass,
    },
}

impl fmt::Display for StakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StakeError::ZeroStake => {
                write!(f, "stake is zero: minimum stake required for all node classes")
            }
            StakeError::InsufficientStake {
                required,
                actual,
                class,
            } => {
                write!(
                    f,
                    "insufficient stake for {}: required {}, actual {}",
                    class, required, actual
                )
            }
        }
    }
}

impl std::error::Error for StakeError {}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ──────────────────────────────────────────────────────────────────────
    // CONSTANT VERIFICATION
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_default_storage_value() {
        let req = StakeRequirement::default();
        assert_eq!(req.min_stake_storage, 5_000_000_000_000_000_000_000_u128);
    }

    #[test]
    fn test_default_compute_value() {
        let req = StakeRequirement::default();
        assert_eq!(req.min_stake_compute, 500_000_000_000_000_000_000_u128);
    }

    #[test]
    fn test_storage_greater_than_compute() {
        let req = StakeRequirement::default();
        assert!(req.min_stake_storage > req.min_stake_compute);
    }

    #[test]
    fn test_storage_is_10x_compute() {
        let req = StakeRequirement::default();
        assert_eq!(req.min_stake_storage, req.min_stake_compute * 10);
    }

    #[test]
    fn test_default_values_match_nusa_amounts() {
        // 5000 NUSA * 10^18 decimals
        let expected_storage: u128 = 5000 * 1_000_000_000_000_000_000_u128;
        assert_eq!(DEFAULT_MIN_STAKE_STORAGE, expected_storage);

        // 500 NUSA * 10^18 decimals
        let expected_compute: u128 = 500 * 1_000_000_000_000_000_000_u128;
        assert_eq!(DEFAULT_MIN_STAKE_COMPUTE, expected_compute);
    }

    // ──────────────────────────────────────────────────────────────────────
    // StakeRequirement TRAIT TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_stake_requirement_clone() {
        let req = StakeRequirement::default();
        let cloned = req.clone();
        assert_eq!(req, cloned);
    }

    #[test]
    fn test_stake_requirement_debug() {
        let req = StakeRequirement::default();
        let debug = format!("{:?}", req);
        assert!(debug.contains("StakeRequirement"));
        assert!(debug.contains("min_stake_storage"));
        assert!(debug.contains("min_stake_compute"));
    }

    #[test]
    fn test_stake_requirement_eq() {
        let a = StakeRequirement::default();
        let b = StakeRequirement::default();
        assert_eq!(a, b);
    }

    #[test]
    fn test_stake_requirement_ne() {
        let a = StakeRequirement::default();
        let b = StakeRequirement {
            min_stake_storage: 999,
            min_stake_compute: 99,
        };
        assert_ne!(a, b);
    }

    #[test]
    fn test_stake_requirement_serde_roundtrip() {
        let req = StakeRequirement::default();
        let json = serde_json::to_string(&req).expect("serialize");
        let back: StakeRequirement = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(req, back);
    }

    #[test]
    fn test_stake_requirement_serde_preserves_values() {
        let req = StakeRequirement::default();
        let json = serde_json::to_string(&req).expect("serialize");
        let back: StakeRequirement = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.min_stake_storage, 5_000_000_000_000_000_000_000_u128);
        assert_eq!(back.min_stake_compute, 500_000_000_000_000_000_000_u128);
    }

    // ──────────────────────────────────────────────────────────────────────
    // check() — ZERO STAKE
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_check_zero_stake_storage() {
        let req = StakeRequirement::default();
        let result = req.check(&NodeClass::Storage, 0);
        assert_eq!(result, Err(StakeError::ZeroStake));
    }

    #[test]
    fn test_check_zero_stake_compute() {
        let req = StakeRequirement::default();
        let result = req.check(&NodeClass::Compute, 0);
        assert_eq!(result, Err(StakeError::ZeroStake));
    }

    #[test]
    fn test_check_zero_stake_precedes_insufficient() {
        // Zero stake must return ZeroStake, NOT InsufficientStake
        let req = StakeRequirement::default();
        let result = req.check(&NodeClass::Storage, 0);
        assert!(matches!(result, Err(StakeError::ZeroStake)));
    }

    // ──────────────────────────────────────────────────────────────────────
    // check() — INSUFFICIENT STAKE
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_check_insufficient_storage() {
        let req = StakeRequirement::default();
        let result = req.check(&NodeClass::Storage, 1);
        assert_eq!(
            result,
            Err(StakeError::InsufficientStake {
                required: 5_000_000_000_000_000_000_000,
                actual: 1,
                class: NodeClass::Storage,
            })
        );
    }

    #[test]
    fn test_check_insufficient_compute() {
        let req = StakeRequirement::default();
        let result = req.check(&NodeClass::Compute, 1);
        assert_eq!(
            result,
            Err(StakeError::InsufficientStake {
                required: 500_000_000_000_000_000_000,
                actual: 1,
                class: NodeClass::Compute,
            })
        );
    }

    #[test]
    fn test_check_storage_one_below_minimum() {
        let req = StakeRequirement::default();
        let just_below = 5_000_000_000_000_000_000_000_u128 - 1;
        let result = req.check(&NodeClass::Storage, just_below);
        assert!(matches!(
            result,
            Err(StakeError::InsufficientStake {
                class: NodeClass::Storage,
                ..
            })
        ));
    }

    #[test]
    fn test_check_compute_one_below_minimum() {
        let req = StakeRequirement::default();
        let just_below = 500_000_000_000_000_000_000_u128 - 1;
        let result = req.check(&NodeClass::Compute, just_below);
        assert!(matches!(
            result,
            Err(StakeError::InsufficientStake {
                class: NodeClass::Compute,
                ..
            })
        ));
    }

    #[test]
    fn test_check_compute_stake_insufficient_for_storage() {
        // 500 NUSA (Compute min) is insufficient for Storage
        let req = StakeRequirement::default();
        let compute_min = 500_000_000_000_000_000_000_u128;
        let result = req.check(&NodeClass::Storage, compute_min);
        assert!(matches!(
            result,
            Err(StakeError::InsufficientStake {
                class: NodeClass::Storage,
                ..
            })
        ));
    }

    // ──────────────────────────────────────────────────────────────────────
    // check() — PASSING (Ok)
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_check_storage_exact_minimum() {
        let req = StakeRequirement::default();
        let result = req.check(&NodeClass::Storage, 5_000_000_000_000_000_000_000);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_check_compute_exact_minimum() {
        let req = StakeRequirement::default();
        let result = req.check(&NodeClass::Compute, 500_000_000_000_000_000_000);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_check_storage_above_minimum() {
        let req = StakeRequirement::default();
        let above = 5_000_000_000_000_000_000_000_u128 + 1;
        assert_eq!(req.check(&NodeClass::Storage, above), Ok(()));
    }

    #[test]
    fn test_check_compute_above_minimum() {
        let req = StakeRequirement::default();
        let above = 500_000_000_000_000_000_000_u128 + 1;
        assert_eq!(req.check(&NodeClass::Compute, above), Ok(()));
    }

    #[test]
    fn test_check_storage_large_stake() {
        let req = StakeRequirement::default();
        let large = u128::MAX;
        assert_eq!(req.check(&NodeClass::Storage, large), Ok(()));
    }

    #[test]
    fn test_check_compute_large_stake() {
        let req = StakeRequirement::default();
        let large = u128::MAX;
        assert_eq!(req.check(&NodeClass::Compute, large), Ok(()));
    }

    #[test]
    fn test_check_compute_with_storage_level_stake() {
        // Storage-level stake satisfies Compute requirement
        let req = StakeRequirement::default();
        let storage_stake = 5_000_000_000_000_000_000_000_u128;
        assert_eq!(req.check(&NodeClass::Compute, storage_stake), Ok(()));
    }

    // ──────────────────────────────────────────────────────────────────────
    // check() — DETERMINISM
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_check_deterministic() {
        let req = StakeRequirement::default();
        let r1 = req.check(&NodeClass::Storage, 1000);
        let r2 = req.check(&NodeClass::Storage, 1000);
        let r3 = req.check(&NodeClass::Storage, 1000);
        assert_eq!(r1, r2);
        assert_eq!(r2, r3);
    }

    // ──────────────────────────────────────────────────────────────────────
    // classify_by_stake() — ZERO
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_classify_zero_returns_none() {
        let req = StakeRequirement::default();
        assert_eq!(req.classify_by_stake(0), None);
    }

    // ──────────────────────────────────────────────────────────────────────
    // classify_by_stake() — BELOW ALL MINIMUMS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_classify_below_compute_minimum() {
        let req = StakeRequirement::default();
        assert_eq!(req.classify_by_stake(1), None);
    }

    #[test]
    fn test_classify_one_below_compute() {
        let req = StakeRequirement::default();
        let just_below = 500_000_000_000_000_000_000_u128 - 1;
        assert_eq!(req.classify_by_stake(just_below), None);
    }

    // ──────────────────────────────────────────────────────────────────────
    // classify_by_stake() — COMPUTE RANGE
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_classify_exact_compute() {
        let req = StakeRequirement::default();
        assert_eq!(
            req.classify_by_stake(500_000_000_000_000_000_000),
            Some(NodeClass::Compute)
        );
    }

    #[test]
    fn test_classify_above_compute_below_storage() {
        let req = StakeRequirement::default();
        let mid = 2_500_000_000_000_000_000_000_u128;
        assert_eq!(req.classify_by_stake(mid), Some(NodeClass::Compute));
    }

    #[test]
    fn test_classify_one_below_storage() {
        let req = StakeRequirement::default();
        let just_below = 5_000_000_000_000_000_000_000_u128 - 1;
        assert_eq!(req.classify_by_stake(just_below), Some(NodeClass::Compute));
    }

    // ──────────────────────────────────────────────────────────────────────
    // classify_by_stake() — STORAGE RANGE
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_classify_exact_storage() {
        let req = StakeRequirement::default();
        assert_eq!(
            req.classify_by_stake(5_000_000_000_000_000_000_000),
            Some(NodeClass::Storage)
        );
    }

    #[test]
    fn test_classify_above_storage() {
        let req = StakeRequirement::default();
        let above = 5_000_000_000_000_000_000_000_u128 + 1;
        assert_eq!(req.classify_by_stake(above), Some(NodeClass::Storage));
    }

    #[test]
    fn test_classify_large_stake() {
        let req = StakeRequirement::default();
        assert_eq!(req.classify_by_stake(u128::MAX), Some(NodeClass::Storage));
    }

    // ──────────────────────────────────────────────────────────────────────
    // classify_by_stake() — PRIORITY (highest class first)
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_classify_returns_highest_qualifying_class() {
        // A stake that meets both Storage and Compute should return Storage
        let req = StakeRequirement::default();
        let both_qualify = 5_000_000_000_000_000_000_000_u128;
        assert_eq!(
            req.classify_by_stake(both_qualify),
            Some(NodeClass::Storage)
        );
    }

    // ──────────────────────────────────────────────────────────────────────
    // classify_by_stake() — DETERMINISM
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_classify_deterministic() {
        let req = StakeRequirement::default();
        let stake = 1_000_000_000_000_000_000_000_u128;
        let r1 = req.classify_by_stake(stake);
        let r2 = req.classify_by_stake(stake);
        let r3 = req.classify_by_stake(stake);
        assert_eq!(r1, r2);
        assert_eq!(r2, r3);
    }

    // ──────────────────────────────────────────────────────────────────────
    // classify_by_stake() — COMPREHENSIVE BOUNDARY TEST
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_classify_boundary_sweep() {
        let req = StakeRequirement::default();

        let cases: &[(u128, Option<NodeClass>)] = &[
            (0, None),
            (1, None),
            (499_999_999_999_999_999_999, None),
            (500_000_000_000_000_000_000, Some(NodeClass::Compute)),
            (500_000_000_000_000_000_001, Some(NodeClass::Compute)),
            (4_999_999_999_999_999_999_999, Some(NodeClass::Compute)),
            (5_000_000_000_000_000_000_000, Some(NodeClass::Storage)),
            (5_000_000_000_000_000_000_001, Some(NodeClass::Storage)),
            (u128::MAX, Some(NodeClass::Storage)),
        ];

        for &(stake, ref expected) in cases {
            assert_eq!(
                req.classify_by_stake(stake),
                *expected,
                "classify_by_stake({}) should be {:?}",
                stake,
                expected
            );
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // StakeError TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_stake_error_zero_display() {
        let err = StakeError::ZeroStake;
        let msg = format!("{}", err);
        assert_eq!(msg, "stake is zero: minimum stake required for all node classes");
    }

    #[test]
    fn test_stake_error_insufficient_display() {
        let err = StakeError::InsufficientStake {
            required: 5_000_000_000_000_000_000_000,
            actual: 100,
            class: NodeClass::Storage,
        };
        let msg = format!("{}", err);
        assert_eq!(
            msg,
            "insufficient stake for Storage: required 5000000000000000000000, actual 100"
        );
    }

    #[test]
    fn test_stake_error_insufficient_compute_display() {
        let err = StakeError::InsufficientStake {
            required: 500_000_000_000_000_000_000,
            actual: 42,
            class: NodeClass::Compute,
        };
        let msg = format!("{}", err);
        assert_eq!(
            msg,
            "insufficient stake for Compute: required 500000000000000000000, actual 42"
        );
    }

    #[test]
    fn test_stake_error_debug() {
        let err = StakeError::ZeroStake;
        let debug = format!("{:?}", err);
        assert!(debug.contains("ZeroStake"));
    }

    #[test]
    fn test_stake_error_clone() {
        let err = StakeError::InsufficientStake {
            required: 100,
            actual: 50,
            class: NodeClass::Storage,
        };
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn test_stake_error_eq() {
        let a = StakeError::ZeroStake;
        let b = StakeError::ZeroStake;
        assert_eq!(a, b);
    }

    #[test]
    fn test_stake_error_ne() {
        let a = StakeError::ZeroStake;
        let b = StakeError::InsufficientStake {
            required: 100,
            actual: 50,
            class: NodeClass::Compute,
        };
        assert_ne!(a, b);
    }

    #[test]
    fn test_stake_error_serde_roundtrip_zero() {
        let err = StakeError::ZeroStake;
        let json = serde_json::to_string(&err).expect("serialize");
        let back: StakeError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(err, back);
    }

    #[test]
    fn test_stake_error_serde_roundtrip_insufficient() {
        let err = StakeError::InsufficientStake {
            required: 5_000_000_000_000_000_000_000,
            actual: 999,
            class: NodeClass::Storage,
        };
        let json = serde_json::to_string(&err).expect("serialize");
        let back: StakeError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(err, back);
    }

    #[test]
    fn test_stake_error_is_std_error() {
        fn assert_error<T: std::error::Error>() {}
        assert_error::<StakeError>();
    }

    // ──────────────────────────────────────────────────────────────────────
    // SEND + SYNC TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<StakeRequirement>();
        assert_send_sync::<StakeError>();
    }

    // ──────────────────────────────────────────────────────────────────────
    // CUSTOM THRESHOLD TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_custom_thresholds() {
        let req = StakeRequirement {
            min_stake_storage: 1000,
            min_stake_compute: 100,
        };
        assert_eq!(req.check(&NodeClass::Storage, 1000), Ok(()));
        assert_eq!(req.check(&NodeClass::Compute, 100), Ok(()));
        assert!(matches!(
            req.check(&NodeClass::Storage, 999),
            Err(StakeError::InsufficientStake { .. })
        ));
        assert!(matches!(
            req.check(&NodeClass::Compute, 99),
            Err(StakeError::InsufficientStake { .. })
        ));
    }

    #[test]
    fn test_classify_custom_thresholds() {
        let req = StakeRequirement {
            min_stake_storage: 1000,
            min_stake_compute: 100,
        };
        assert_eq!(req.classify_by_stake(0), None);
        assert_eq!(req.classify_by_stake(99), None);
        assert_eq!(req.classify_by_stake(100), Some(NodeClass::Compute));
        assert_eq!(req.classify_by_stake(999), Some(NodeClass::Compute));
        assert_eq!(req.classify_by_stake(1000), Some(NodeClass::Storage));
        assert_eq!(req.classify_by_stake(9999), Some(NodeClass::Storage));
    }

    // ──────────────────────────────────────────────────────────────────────
    // check() + classify_by_stake() CONSISTENCY
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_check_and_classify_consistent() {
        // If classify_by_stake returns Some(class), then check(class, stake)
        // must return Ok(())
        let req = StakeRequirement::default();

        let test_stakes: &[u128] = &[
            500_000_000_000_000_000_000,
            1_000_000_000_000_000_000_000,
            4_999_999_999_999_999_999_999,
            5_000_000_000_000_000_000_000,
            10_000_000_000_000_000_000_000,
            u128::MAX,
        ];

        for &stake in test_stakes {
            if let Some(class) = req.classify_by_stake(stake) {
                assert_eq!(
                    req.check(&class, stake),
                    Ok(()),
                    "classify returned {:?} for stake {} but check failed",
                    class,
                    stake
                );
            }
        }
    }

    #[test]
    fn test_classify_none_implies_check_fails_for_all_classes() {
        // If classify_by_stake returns None (and stake > 0), then check must
        // fail for both classes
        let req = StakeRequirement::default();

        let test_stakes: &[u128] = &[
            1,
            100,
            499_999_999_999_999_999_999,
        ];

        for &stake in test_stakes {
            assert_eq!(req.classify_by_stake(stake), None);
            assert!(req.check(&NodeClass::Storage, stake).is_err());
            assert!(req.check(&NodeClass::Compute, stake).is_err());
        }
    }
}