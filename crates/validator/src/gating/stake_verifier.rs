//! # Stake Verifier (14B.21)
//!
//! Stateless verifier that validates whether a service node's stake
//! meets the minimum requirement for its [`NodeClass`].
//!
//! ## Design
//!
//! `StakeVerifier` wraps a [`StakeRequirement`] from `dsdn_common` and
//! produces a [`CheckResult`] indicating pass or fail. It does NOT
//! access chain state, system clock, or any external resource.
//!
//! ## Verification Logic (Strict Order)
//!
//! 1. `actual_stake == 0` → `Err(GatingError::ZeroStake)`
//! 2. Determine `min_stake` from `requirement` based on `class`
//! 3. `actual_stake >= min_stake` → `Ok(CheckResult { passed: true, .. })`
//! 4. `actual_stake < min_stake` → `Ok(CheckResult { passed: false, .. })`
//!
//! ## Properties
//!
//! - **Stateless**: No mutable state, no side effects.
//! - **Deterministic**: Same inputs always produce the same output.
//! - **No panic**: No `unwrap()`, `expect()`, or index access.
//! - **No external dependency**: Does not read chain state or I/O.

use dsdn_common::gating::{
    NodeClass,
    StakeRequirement,
    CheckResult,
    GatingError,
};

// ════════════════════════════════════════════════════════════════════════════
// STAKE VERIFIER
// ════════════════════════════════════════════════════════════════════════════

/// Stateless verifier for service node stake requirements.
///
/// `StakeVerifier` holds a [`StakeRequirement`] configuration and verifies
/// whether a given stake amount meets the minimum for a specified
/// [`NodeClass`]. The struct is immutable after construction.
///
/// ## Usage
///
/// ```rust,ignore
/// use dsdn_common::gating::{StakeRequirement, NodeClass};
/// use dsdn_validator::gating::StakeVerifier;
///
/// let verifier = StakeVerifier::new(StakeRequirement::default());
/// let result = verifier.verify(&NodeClass::Storage, 5_000_000_000_000_000_000_000);
/// assert!(result.is_ok());
/// assert!(result.unwrap().passed);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StakeVerifier {
    /// The stake requirement configuration. Immutable after construction.
    requirement: StakeRequirement,
}

impl StakeVerifier {
    /// Creates a new `StakeVerifier` with the given stake requirement.
    ///
    /// The requirement is consumed and stored immutably. No validation
    /// is performed on the requirement values — they are trusted as
    /// protocol configuration from `dsdn_common`.
    #[must_use]
    #[inline]
    pub fn new(requirement: StakeRequirement) -> Self {
        Self { requirement }
    }

    /// Returns a reference to the underlying stake requirement.
    #[must_use]
    #[inline]
    pub fn requirement(&self) -> &StakeRequirement {
        &self.requirement
    }

    /// Verify whether `actual_stake` meets the minimum for `class`.
    ///
    /// ## Execution Order (STRICT — DO NOT REORDER)
    ///
    /// 1. If `actual_stake == 0` → `Err(GatingError::ZeroStake)`
    /// 2. Determine `min_stake` from `self.requirement` based on `class`:
    ///    - `NodeClass::Storage` → `requirement.min_stake_storage`
    ///    - `NodeClass::Compute` → `requirement.min_stake_compute`
    /// 3. If `actual_stake >= min_stake` → `Ok(CheckResult { passed: true, .. })`
    /// 4. If `actual_stake < min_stake` → `Ok(CheckResult { passed: false, .. })`
    ///
    /// ## Properties
    ///
    /// - Stateless: does not read or modify any external state.
    /// - Deterministic: same `(class, actual_stake)` always yields same result.
    /// - The comparison is `>=` (greater than or equal), not `>`.
    /// - `detail` is always `Some(...)` with explicit, deterministic content.
    /// - No panic, no unwrap, no side effects.
    ///
    /// ## Errors
    ///
    /// - `GatingError::ZeroStake` if `actual_stake` is exactly zero.
    pub fn verify(
        &self,
        class: &NodeClass,
        actual_stake: u128,
    ) -> Result<CheckResult, GatingError> {
        // Step 1: Zero stake is always an error
        if actual_stake == 0 {
            return Err(GatingError::ZeroStake);
        }

        // Step 2: Determine minimum stake based on class (exhaustive match)
        let min_stake = match class {
            NodeClass::Storage => self.requirement.min_stake_storage,
            NodeClass::Compute => self.requirement.min_stake_compute,
        };

        // Steps 3 & 4: Compare and produce CheckResult
        if actual_stake >= min_stake {
            Ok(CheckResult {
                check_name: "stake_check".to_string(),
                passed: true,
                detail: Some(format!(
                    "stake {} meets minimum {} for {}",
                    actual_stake, min_stake, class,
                )),
            })
        } else {
            Ok(CheckResult {
                check_name: "stake_check".to_string(),
                passed: false,
                detail: Some(format!(
                    "stake {} below minimum {} for {}",
                    actual_stake, min_stake, class,
                )),
            })
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn default_verifier() -> StakeVerifier {
        StakeVerifier::new(StakeRequirement::default())
    }

    fn custom_verifier(storage: u128, compute: u128) -> StakeVerifier {
        StakeVerifier::new(StakeRequirement {
            min_stake_storage: storage,
            min_stake_compute: compute,
        })
    }

    // ────────────────────────────────────────────────────────────
    // ZERO STAKE
    // ────────────────────────────────────────────────────────────

    #[test]
    fn test_zero_stake_storage_returns_error() {
        let v = default_verifier();
        let result = v.verify(&NodeClass::Storage, 0);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), GatingError::ZeroStake);
    }

    #[test]
    fn test_zero_stake_compute_returns_error() {
        let v = default_verifier();
        let result = v.verify(&NodeClass::Compute, 0);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), GatingError::ZeroStake);
    }

    // ────────────────────────────────────────────────────────────
    // EXACT MINIMUM (BOUNDARY)
    // ────────────────────────────────────────────────────────────

    #[test]
    fn test_exact_minimum_storage_passes() {
        let v = default_verifier();
        let result = v.verify(
            &NodeClass::Storage,
            5_000_000_000_000_000_000_000,
        );
        assert!(result.is_ok());
        let cr = result.unwrap();
        assert_eq!(cr.check_name, "stake_check");
        assert!(cr.passed);
        assert!(cr.detail.is_some());
        assert!(cr.detail.unwrap().contains("meets minimum"));
    }

    #[test]
    fn test_exact_minimum_compute_passes() {
        let v = default_verifier();
        let result = v.verify(
            &NodeClass::Compute,
            500_000_000_000_000_000_000,
        );
        assert!(result.is_ok());
        let cr = result.unwrap();
        assert!(cr.passed);
    }

    // ────────────────────────────────────────────────────────────
    // BELOW MINIMUM
    // ────────────────────────────────────────────────────────────

    #[test]
    fn test_below_minimum_storage_fails() {
        let v = default_verifier();
        let result = v.verify(
            &NodeClass::Storage,
            4_999_999_999_999_999_999_999,
        );
        assert!(result.is_ok());
        let cr = result.unwrap();
        assert_eq!(cr.check_name, "stake_check");
        assert!(!cr.passed);
        assert!(cr.detail.is_some());
        assert!(cr.detail.unwrap().contains("below minimum"));
    }

    #[test]
    fn test_below_minimum_compute_fails() {
        let v = default_verifier();
        let result = v.verify(
            &NodeClass::Compute,
            499_999_999_999_999_999_999,
        );
        assert!(result.is_ok());
        let cr = result.unwrap();
        assert!(!cr.passed);
    }

    // ────────────────────────────────────────────────────────────
    // ABOVE MINIMUM
    // ────────────────────────────────────────────────────────────

    #[test]
    fn test_above_minimum_storage_passes() {
        let v = default_verifier();
        let result = v.verify(
            &NodeClass::Storage,
            10_000_000_000_000_000_000_000,
        );
        assert!(result.is_ok());
        assert!(result.unwrap().passed);
    }

    #[test]
    fn test_above_minimum_compute_passes() {
        let v = default_verifier();
        let result = v.verify(
            &NodeClass::Compute,
            1_000_000_000_000_000_000_000,
        );
        assert!(result.is_ok());
        assert!(result.unwrap().passed);
    }

    // ────────────────────────────────────────────────────────────
    // VERY LARGE STAKE (u128 near max)
    // ────────────────────────────────────────────────────────────

    #[test]
    fn test_u128_max_stake_passes() {
        let v = default_verifier();
        let result = v.verify(&NodeClass::Storage, u128::MAX);
        assert!(result.is_ok());
        assert!(result.unwrap().passed);
    }

    // ────────────────────────────────────────────────────────────
    // STAKE == 1 (non-zero but below all minimums)
    // ────────────────────────────────────────────────────────────

    #[test]
    fn test_stake_one_storage_fails() {
        let v = default_verifier();
        let result = v.verify(&NodeClass::Storage, 1);
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[test]
    fn test_stake_one_compute_fails() {
        let v = default_verifier();
        let result = v.verify(&NodeClass::Compute, 1);
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    // ────────────────────────────────────────────────────────────
    // CUSTOM THRESHOLDS
    // ────────────────────────────────────────────────────────────

    #[test]
    fn test_custom_thresholds() {
        let v = custom_verifier(1000, 100);
        assert!(v.verify(&NodeClass::Storage, 1000).unwrap().passed);
        assert!(v.verify(&NodeClass::Compute, 100).unwrap().passed);
        assert!(!v.verify(&NodeClass::Storage, 999).unwrap().passed);
        assert!(!v.verify(&NodeClass::Compute, 99).unwrap().passed);
    }

    // ────────────────────────────────────────────────────────────
    // DETERMINISM
    // ────────────────────────────────────────────────────────────

    #[test]
    fn test_verify_deterministic() {
        let v = default_verifier();
        let r1 = v.verify(&NodeClass::Storage, 5_000_000_000_000_000_000_000);
        let r2 = v.verify(&NodeClass::Storage, 5_000_000_000_000_000_000_000);
        assert_eq!(r1, r2);
    }

    // ────────────────────────────────────────────────────────────
    // CHECK_NAME CONSISTENCY
    // ────────────────────────────────────────────────────────────

    #[test]
    fn test_check_name_always_stake_check() {
        let v = default_verifier();
        // Pass case
        let cr1 = v.verify(
            &NodeClass::Storage,
            5_000_000_000_000_000_000_000,
        ).unwrap();
        assert_eq!(cr1.check_name, "stake_check");
        // Fail case
        let cr2 = v.verify(&NodeClass::Storage, 1).unwrap();
        assert_eq!(cr2.check_name, "stake_check");
    }

    // ────────────────────────────────────────────────────────────
    // DETAIL MESSAGES
    // ────────────────────────────────────────────────────────────

    #[test]
    fn test_detail_always_present() {
        let v = default_verifier();
        // Pass
        let cr1 = v.verify(
            &NodeClass::Storage,
            5_000_000_000_000_000_000_000,
        ).unwrap();
        assert!(cr1.detail.is_some());
        // Fail
        let cr2 = v.verify(&NodeClass::Storage, 1).unwrap();
        assert!(cr2.detail.is_some());
    }

    #[test]
    fn test_detail_contains_actual_and_minimum_values() {
        let v = custom_verifier(1000, 100);
        let cr = v.verify(&NodeClass::Storage, 500).unwrap();
        let detail = cr.detail.unwrap();
        assert!(detail.contains("500"), "detail should contain actual: {}", detail);
        assert!(detail.contains("1000"), "detail should contain minimum: {}", detail);
    }

    #[test]
    fn test_detail_contains_class_name() {
        let v = custom_verifier(1000, 100);
        let cr_s = v.verify(&NodeClass::Storage, 1000).unwrap();
        assert!(cr_s.detail.unwrap().contains("Storage"));
        let cr_c = v.verify(&NodeClass::Compute, 100).unwrap();
        assert!(cr_c.detail.unwrap().contains("Compute"));
    }

    // ────────────────────────────────────────────────────────────
    // STRUCT PROPERTIES
    // ────────────────────────────────────────────────────────────

    #[test]
    fn test_verifier_clone() {
        let v1 = default_verifier();
        let v2 = v1.clone();
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_verifier_debug() {
        let v = default_verifier();
        let debug = format!("{:?}", v);
        assert!(debug.contains("StakeVerifier"));
    }

    #[test]
    fn test_requirement_accessor() {
        let req = StakeRequirement::default();
        let v = StakeVerifier::new(req.clone());
        assert_eq!(v.requirement(), &req);
    }

    // ────────────────────────────────────────────────────────────
    // SEND + SYNC
    // ────────────────────────────────────────────────────────────

    #[test]
    fn test_stake_verifier_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<StakeVerifier>();
    }

    // ────────────────────────────────────────────────────────────
    // BOUNDARY SWEEP
    // ────────────────────────────────────────────────────────────

    #[test]
    fn test_storage_boundary_sweep() {
        let v = custom_verifier(5000, 500);
        let cases: &[(u128, bool)] = &[
            (0, false),     // error, not checked here
            (1, false),
            (4999, false),
            (5000, true),
            (5001, true),
            (u128::MAX, true),
        ];
        for &(stake, expected_pass) in cases {
            if stake == 0 {
                assert!(v.verify(&NodeClass::Storage, stake).is_err());
            } else {
                let cr = v.verify(&NodeClass::Storage, stake).unwrap();
                assert_eq!(
                    cr.passed, expected_pass,
                    "Storage stake {} should be passed={}",
                    stake, expected_pass
                );
            }
        }
    }

    #[test]
    fn test_compute_boundary_sweep() {
        let v = custom_verifier(5000, 500);
        let cases: &[(u128, bool)] = &[
            (0, false),
            (1, false),
            (499, false),
            (500, true),
            (501, true),
            (u128::MAX, true),
        ];
        for &(stake, expected_pass) in cases {
            if stake == 0 {
                assert!(v.verify(&NodeClass::Compute, stake).is_err());
            } else {
                let cr = v.verify(&NodeClass::Compute, stake).unwrap();
                assert_eq!(
                    cr.passed, expected_pass,
                    "Compute stake {} should be passed={}",
                    stake, expected_pass
                );
            }
        }
    }
}