//! # Node Class Verifier (14B.25)
//!
//! Deterministic verifier that checks whether a node's actual stake
//! supports its claimed [`NodeClass`].
//!
//! ## Design
//!
//! `ClassVerifier` holds a [`StakeRequirement`] from `dsdn_common`.
//! It does NOT hardcode minimum stakes — all thresholds come from
//! the requirement configuration.
//!
//! ## Verification Logic (`verify`)
//!
//! 1. Determine `required_stake` from `requirement` based on `claimed_class`.
//! 2. If `actual_stake >= required_stake` → pass.
//! 3. If `actual_stake < required_stake` → `Err(GatingError::InvalidNodeClass)`.
//!
//! There is NO automatic fallback to a lower class. The node must
//! explicitly claim a class it can afford.
//!
//! ## Suggestion Logic (`suggest_class`)
//!
//! Delegates to [`StakeRequirement::classify_by_stake`] which evaluates
//! classes in strict priority order (Storage first, then Compute).
//! Returns the highest class the stake qualifies for, or `None`.
//!
//! ## Properties
//!
//! - **Deterministic**: Same inputs always produce the same output.
//! - **No panic**: No `unwrap()`, `expect()`, or index access.
//! - **No hardcoded thresholds**: All values come from `StakeRequirement`.
//! - **No implicit class downgrade**: Verify either passes or errors.

use dsdn_common::gating::{
    CheckResult,
    GatingError,
    NodeClass,
    StakeRequirement,
};

// ════════════════════════════════════════════════════════════════════════════
// CLASS VERIFIER
// ════════════════════════════════════════════════════════════════════════════

/// Deterministic verifier for node class claims.
///
/// `ClassVerifier` validates that a node's actual stake supports its
/// claimed [`NodeClass`]. The minimum stake thresholds are provided
/// by [`StakeRequirement`] — no values are hardcoded.
///
/// ## Usage
///
/// ```rust,ignore
/// use dsdn_validator::gating::ClassVerifier;
/// use dsdn_common::gating::{StakeRequirement, NodeClass};
///
/// let verifier = ClassVerifier::new(StakeRequirement::default());
///
/// // Node claims Storage with sufficient stake → passes
/// let result = verifier.verify(&NodeClass::Storage, 5_000_000_000_000_000_000_000);
/// assert!(result.unwrap().passed);
///
/// // Suggest highest affordable class
/// let suggestion = verifier.suggest_class(600_000_000_000_000_000_000);
/// assert_eq!(suggestion, Some(NodeClass::Compute));
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClassVerifier {
    /// Stake requirement configuration from dsdn_common.
    /// Contains per-class minimum stakes. Not hardcoded.
    requirement: StakeRequirement,
}

impl ClassVerifier {
    /// Creates a new `ClassVerifier` with the given stake requirement.
    ///
    /// The requirement is stored immutably and used for all subsequent
    /// verification and suggestion calls.
    #[must_use]
    #[inline]
    pub fn new(requirement: StakeRequirement) -> Self {
        Self { requirement }
    }

    /// Returns a reference to the stake requirement used by this verifier.
    #[must_use]
    #[inline]
    pub fn requirement(&self) -> &StakeRequirement {
        &self.requirement
    }

    /// Verify that `actual_stake` supports the `claimed_class`.
    ///
    /// ## Execution Order (STRICT — DO NOT REORDER)
    ///
    /// 1. Determine `required_stake` from `self.requirement` based on
    ///    `claimed_class`:
    ///    - `NodeClass::Storage` → `requirement.min_stake_storage`
    ///    - `NodeClass::Compute` → `requirement.min_stake_compute`
    /// 2. If `actual_stake >= required_stake` → pass.
    ///    → `Ok(CheckResult { check_name: "class_check", passed: true, .. })`
    /// 3. If `actual_stake < required_stake` → error.
    ///    → `Err(GatingError::InvalidNodeClass(...))`
    ///
    /// ## Properties
    ///
    /// - Deterministic for same `(claimed_class, actual_stake, requirement)`.
    /// - No automatic fallback to a lower class.
    /// - No panic, no unwrap, no side effects.
    pub fn verify(
        &self,
        claimed_class: &NodeClass,
        actual_stake: u128,
    ) -> Result<CheckResult, GatingError> {
        // STEP 1: Determine required stake for the claimed class
        let required_stake = match claimed_class {
            NodeClass::Storage => self.requirement.min_stake_storage,
            NodeClass::Compute => self.requirement.min_stake_compute,
        };

        // STEP 2: Check if actual stake meets the requirement
        if actual_stake >= required_stake {
            return Ok(CheckResult {
                check_name: "class_check".to_string(),
                passed: true,
                detail: Some(format!(
                    "stake {} meets {} requirement of {}",
                    actual_stake, claimed_class, required_stake,
                )),
            });
        }

        // STEP 3: Insufficient stake for claimed class
        Err(GatingError::InvalidNodeClass(format!(
            "stake {} insufficient for {}: requires {}",
            actual_stake, claimed_class, required_stake,
        )))
    }

    /// Suggest the highest [`NodeClass`] that `actual_stake` qualifies for.
    ///
    /// Delegates to [`StakeRequirement::classify_by_stake`] which evaluates
    /// classes in strict priority order: Storage (highest) first, then
    /// Compute. Returns `None` if the stake qualifies for no class
    /// (including zero stake).
    ///
    /// ## Properties
    ///
    /// - Deterministic for same `(actual_stake, requirement)`.
    /// - No implicit class upgrade — only reports what the stake affords.
    /// - No panic, no side effects.
    #[must_use]
    pub fn suggest_class(&self, actual_stake: u128) -> Option<NodeClass> {
        self.requirement.classify_by_stake(actual_stake)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ────────────────────────────────────────────────────────────
    // HELPERS
    // ────────────────────────────────────────────────────────────

    fn default_verifier() -> ClassVerifier {
        ClassVerifier::new(StakeRequirement::default())
    }

    // Protocol defaults:
    // Storage: 5_000_000_000_000_000_000_000
    // Compute: 500_000_000_000_000_000_000

    const STORAGE_MIN: u128 = 5_000_000_000_000_000_000_000;
    const COMPUTE_MIN: u128 = 500_000_000_000_000_000_000;

    // ════════════════════════════════════════════════════════════
    // verify — PASS CASES
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_storage_exact_min_passes() {
        let v = default_verifier();
        let result = v.verify(&NodeClass::Storage, STORAGE_MIN);
        assert!(result.is_ok());
        let cr = result.unwrap();
        assert_eq!(cr.check_name, "class_check");
        assert!(cr.passed);
        assert!(cr.detail.is_some());
    }

    #[test]
    fn test_verify_storage_above_min_passes() {
        let v = default_verifier();
        let result = v.verify(&NodeClass::Storage, STORAGE_MIN + 1);
        assert!(result.is_ok());
        assert!(result.unwrap().passed);
    }

    #[test]
    fn test_verify_compute_exact_min_passes() {
        let v = default_verifier();
        let result = v.verify(&NodeClass::Compute, COMPUTE_MIN);
        assert!(result.is_ok());
        assert!(result.unwrap().passed);
    }

    #[test]
    fn test_verify_compute_above_min_passes() {
        let v = default_verifier();
        let result = v.verify(&NodeClass::Compute, COMPUTE_MIN + 1);
        assert!(result.is_ok());
        assert!(result.unwrap().passed);
    }

    #[test]
    fn test_verify_u128_max_passes_both() {
        let v = default_verifier();
        assert!(v.verify(&NodeClass::Storage, u128::MAX).is_ok());
        assert!(v.verify(&NodeClass::Compute, u128::MAX).is_ok());
    }

    // ════════════════════════════════════════════════════════════
    // verify — FAIL CASES
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_storage_below_min_fails() {
        let v = default_verifier();
        let result = v.verify(&NodeClass::Storage, STORAGE_MIN - 1);
        assert!(result.is_err());
        match result.unwrap_err() {
            GatingError::InvalidNodeClass(msg) => {
                assert!(msg.contains("insufficient"));
                assert!(msg.contains("Storage"));
            }
            other => panic!("expected InvalidNodeClass, got: {:?}", other),
        }
    }

    #[test]
    fn test_verify_compute_below_min_fails() {
        let v = default_verifier();
        let result = v.verify(&NodeClass::Compute, COMPUTE_MIN - 1);
        assert!(result.is_err());
        match result.unwrap_err() {
            GatingError::InvalidNodeClass(msg) => {
                assert!(msg.contains("insufficient"));
                assert!(msg.contains("Compute"));
            }
            other => panic!("expected InvalidNodeClass, got: {:?}", other),
        }
    }

    #[test]
    fn test_verify_zero_stake_fails_storage() {
        let v = default_verifier();
        let result = v.verify(&NodeClass::Storage, 0);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GatingError::InvalidNodeClass(_)));
    }

    #[test]
    fn test_verify_zero_stake_fails_compute() {
        let v = default_verifier();
        let result = v.verify(&NodeClass::Compute, 0);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GatingError::InvalidNodeClass(_)));
    }

    // ════════════════════════════════════════════════════════════
    // verify — NO IMPLICIT FALLBACK
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_no_implicit_downgrade() {
        // Node claims Storage but only has Compute-level stake → MUST fail
        // No automatic downgrade to Compute
        let v = default_verifier();
        let result = v.verify(&NodeClass::Storage, COMPUTE_MIN);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GatingError::InvalidNodeClass(_)));
    }

    // ════════════════════════════════════════════════════════════
    // verify — DETERMINISM
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_deterministic() {
        let v = default_verifier();
        let r1 = v.verify(&NodeClass::Storage, STORAGE_MIN);
        let r2 = v.verify(&NodeClass::Storage, STORAGE_MIN);
        assert_eq!(r1, r2);
    }

    // ════════════════════════════════════════════════════════════
    // verify — DETAIL MESSAGE
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_detail_contains_stake_and_class() {
        let v = default_verifier();
        let cr = v.verify(&NodeClass::Compute, COMPUTE_MIN).unwrap();
        let detail = cr.detail.unwrap();
        assert!(detail.contains(&COMPUTE_MIN.to_string()));
        assert!(detail.contains("Compute"));
    }

    // ════════════════════════════════════════════════════════════
    // suggest_class
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_suggest_class_zero_is_none() {
        let v = default_verifier();
        assert_eq!(v.suggest_class(0), None);
    }

    #[test]
    fn test_suggest_class_below_compute_is_none() {
        let v = default_verifier();
        assert_eq!(v.suggest_class(COMPUTE_MIN - 1), None);
    }

    #[test]
    fn test_suggest_class_at_compute_min() {
        let v = default_verifier();
        assert_eq!(v.suggest_class(COMPUTE_MIN), Some(NodeClass::Compute));
    }

    #[test]
    fn test_suggest_class_between_compute_and_storage() {
        let v = default_verifier();
        assert_eq!(v.suggest_class(STORAGE_MIN - 1), Some(NodeClass::Compute));
    }

    #[test]
    fn test_suggest_class_at_storage_min() {
        let v = default_verifier();
        assert_eq!(v.suggest_class(STORAGE_MIN), Some(NodeClass::Storage));
    }

    #[test]
    fn test_suggest_class_above_storage() {
        let v = default_verifier();
        assert_eq!(v.suggest_class(STORAGE_MIN + 1), Some(NodeClass::Storage));
    }

    #[test]
    fn test_suggest_class_u128_max() {
        let v = default_verifier();
        assert_eq!(v.suggest_class(u128::MAX), Some(NodeClass::Storage));
    }

    #[test]
    fn test_suggest_class_deterministic() {
        let v = default_verifier();
        let r1 = v.suggest_class(COMPUTE_MIN);
        let r2 = v.suggest_class(COMPUTE_MIN);
        assert_eq!(r1, r2);
    }

    // ════════════════════════════════════════════════════════════
    // verify + suggest_class CONSISTENCY
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_suggest_and_verify_consistent() {
        // If suggest_class returns Some(class), then verify(class, stake) must pass
        let v = default_verifier();
        let stakes = [
            COMPUTE_MIN,
            COMPUTE_MIN + 1,
            STORAGE_MIN - 1,
            STORAGE_MIN,
            STORAGE_MIN + 1,
            u128::MAX,
        ];

        for &stake in &stakes {
            if let Some(class) = v.suggest_class(stake) {
                let result = v.verify(&class, stake);
                assert!(
                    result.is_ok(),
                    "suggest returned {:?} for stake {} but verify failed",
                    class, stake
                );
            }
        }
    }

    #[test]
    fn test_suggest_none_implies_verify_fails_all() {
        // If suggest returns None (and stake > 0), verify must fail for all classes
        let v = default_verifier();
        let stakes = [1_u128, 100, COMPUTE_MIN - 1];

        for &stake in &stakes {
            assert_eq!(v.suggest_class(stake), None);
            assert!(v.verify(&NodeClass::Storage, stake).is_err());
            assert!(v.verify(&NodeClass::Compute, stake).is_err());
        }
    }

    // ════════════════════════════════════════════════════════════
    // CUSTOM REQUIREMENT
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_custom_requirement() {
        let req = StakeRequirement {
            min_stake_storage: 1000,
            min_stake_compute: 100,
        };
        let v = ClassVerifier::new(req);

        assert!(v.verify(&NodeClass::Storage, 1000).is_ok());
        assert!(v.verify(&NodeClass::Storage, 999).is_err());
        assert!(v.verify(&NodeClass::Compute, 100).is_ok());
        assert!(v.verify(&NodeClass::Compute, 99).is_err());

        assert_eq!(v.suggest_class(0), None);
        assert_eq!(v.suggest_class(99), None);
        assert_eq!(v.suggest_class(100), Some(NodeClass::Compute));
        assert_eq!(v.suggest_class(999), Some(NodeClass::Compute));
        assert_eq!(v.suggest_class(1000), Some(NodeClass::Storage));
    }

    // ════════════════════════════════════════════════════════════
    // STRUCT PROPERTIES
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_class_verifier_clone() {
        let v1 = default_verifier();
        let v2 = v1.clone();
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_class_verifier_debug() {
        let v = default_verifier();
        let debug = format!("{:?}", v);
        assert!(debug.contains("ClassVerifier"));
    }

    #[test]
    fn test_class_verifier_requirement_accessor() {
        let v = default_verifier();
        assert_eq!(v.requirement().min_stake_storage, STORAGE_MIN);
        assert_eq!(v.requirement().min_stake_compute, COMPUTE_MIN);
    }

    // ════════════════════════════════════════════════════════════
    // SEND + SYNC
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_class_verifier_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ClassVerifier>();
    }

    // ════════════════════════════════════════════════════════════
    // BOUNDARY SWEEP
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_boundary_sweep_storage() {
        let v = default_verifier();
        let cases: &[(u128, bool)] = &[
            (0, false),
            (1, false),
            (STORAGE_MIN - 1, false),
            (STORAGE_MIN, true),
            (STORAGE_MIN + 1, true),
            (u128::MAX, true),
        ];

        for &(stake, should_pass) in cases {
            let result = v.verify(&NodeClass::Storage, stake);
            assert_eq!(
                result.is_ok(), should_pass,
                "Storage verify at stake {} should_pass={}, got is_ok={}",
                stake, should_pass, result.is_ok()
            );
        }
    }

    #[test]
    fn test_verify_boundary_sweep_compute() {
        let v = default_verifier();
        let cases: &[(u128, bool)] = &[
            (0, false),
            (1, false),
            (COMPUTE_MIN - 1, false),
            (COMPUTE_MIN, true),
            (COMPUTE_MIN + 1, true),
            (u128::MAX, true),
        ];

        for &(stake, should_pass) in cases {
            let result = v.verify(&NodeClass::Compute, stake);
            assert_eq!(
                result.is_ok(), should_pass,
                "Compute verify at stake {} should_pass={}, got is_ok={}",
                stake, should_pass, result.is_ok()
            );
        }
    }

    #[test]
    fn test_suggest_boundary_sweep() {
        let v = default_verifier();
        let cases: &[(u128, Option<NodeClass>)] = &[
            (0, None),
            (1, None),
            (COMPUTE_MIN - 1, None),
            (COMPUTE_MIN, Some(NodeClass::Compute)),
            (COMPUTE_MIN + 1, Some(NodeClass::Compute)),
            (STORAGE_MIN - 1, Some(NodeClass::Compute)),
            (STORAGE_MIN, Some(NodeClass::Storage)),
            (STORAGE_MIN + 1, Some(NodeClass::Storage)),
            (u128::MAX, Some(NodeClass::Storage)),
        ];

        for &(stake, ref expected) in cases {
            assert_eq!(
                v.suggest_class(stake), *expected,
                "suggest_class({}) should be {:?}",
                stake, expected
            );
        }
    }
}