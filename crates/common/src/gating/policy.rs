//! # Gating Policy Configuration (14B.7)
//!
//! Defines `GatingPolicy` — the single source of truth for all gating
//! configuration. This struct combines stake, cooldown, TLS, identity,
//! and scheduling rules into one validated configuration object.
//!
//! ## Overview
//!
//! `GatingPolicy` is consumed by the admission engine, coordinator, and
//! test harnesses. It determines which checks are active during node
//! registration and lifecycle transitions.
//!
//! ## Presets
//!
//! | Preset | Security | Use Case |
//! |--------|----------|----------|
//! | `default()` | Full | Production — all checks enabled |
//! | `permissive()` | None | Testing — all checks disabled |
//!
//! ## Validation
//!
//! `validate()` detects internal contradictions and illogical
//! configurations before the policy is used. A policy must always be
//! validated before being passed to the admission engine.
//!
//! ## Safety Properties
//!
//! - `GatingPolicy` is a value type: no interior mutability, no global
//!   state, no lazy evaluation.
//! - All behavior is determined by explicit field values.
//! - No environment variables, no external state reads.
//! - `validate()` returns a `Result<(), String>` — no panics.

use serde::{Deserialize, Serialize};

use super::cooldown::CooldownConfig;
use super::stake::StakeRequirement;

// ════════════════════════════════════════════════════════════════════════════════
// GATING POLICY
// ════════════════════════════════════════════════════════════════════════════════

/// Combined gating policy configuration.
///
/// `GatingPolicy` is the single source of truth for all gating rules.
/// It determines which checks are active during node admission and
/// lifecycle transitions.
///
/// ## Fields
///
/// - `stake_requirement`: Per-class minimum stake thresholds.
/// - `cooldown_config`: Default and severe cooldown durations.
/// - `require_tls`: Whether TLS certificate validation is required.
/// - `require_identity_proof`: Whether identity proof (signature
///   verification) is required.
/// - `allow_pending_scheduling`: Whether nodes in `Pending` status
///   may be scheduled for workloads before becoming `Active`.
///
/// ## Presets
///
/// - [`GatingPolicy::default()`]: Production preset — all security
///   checks enabled, pending scheduling disabled.
/// - [`GatingPolicy::permissive()`]: Testing preset — all security
///   checks disabled, pending scheduling allowed.
///
/// ## Validation
///
/// Always call [`validate()`](GatingPolicy::validate) before using a
/// policy in the admission engine. This detects internal contradictions
/// and illogical configurations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatingPolicy {
    /// Per-class minimum stake thresholds for node admission.
    pub stake_requirement: StakeRequirement,
    /// Cooldown durations after slashing events.
    pub cooldown_config: CooldownConfig,
    /// Whether TLS certificate validation is required for admission.
    pub require_tls: bool,
    /// Whether identity proof (signature verification) is required.
    pub require_identity_proof: bool,
    /// Whether nodes in Pending status may be scheduled for workloads.
    pub allow_pending_scheduling: bool,
}

impl Default for GatingPolicy {
    /// Returns the **production default** gating policy.
    ///
    /// All security checks are enabled. Pending scheduling is disabled.
    ///
    /// | Field | Value |
    /// |-------|-------|
    /// | `stake_requirement` | `StakeRequirement::default()` (Storage: 5000 NUSA, Compute: 500 NUSA) |
    /// | `cooldown_config` | `CooldownConfig::default()` (24h default, 7d severe) |
    /// | `require_tls` | `true` |
    /// | `require_identity_proof` | `true` |
    /// | `allow_pending_scheduling` | `false` |
    fn default() -> Self {
        Self {
            stake_requirement: StakeRequirement::default(),
            cooldown_config: CooldownConfig::default(),
            require_tls: true,
            require_identity_proof: true,
            allow_pending_scheduling: false,
        }
    }
}

impl GatingPolicy {
    /// Returns a **permissive** gating policy for testing.
    ///
    /// All security checks are disabled. Zero-stake nodes are accepted.
    /// Pending scheduling is allowed.
    ///
    /// **WARNING**: This preset must NEVER be used in production. It
    /// disables all gating protections.
    ///
    /// | Field | Value |
    /// |-------|-------|
    /// | `stake_requirement` | Both minimums = 0 |
    /// | `cooldown_config` | Both durations = 0 |
    /// | `require_tls` | `false` |
    /// | `require_identity_proof` | `false` |
    /// | `allow_pending_scheduling` | `true` |
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            stake_requirement: StakeRequirement {
                min_stake_storage: 0,
                min_stake_compute: 0,
            },
            cooldown_config: CooldownConfig {
                default_cooldown_secs: 0,
                severe_cooldown_secs: 0,
            },
            require_tls: false,
            require_identity_proof: false,
            allow_pending_scheduling: true,
        }
    }

    /// Validates that this policy has no internal contradictions or
    /// illogical configurations.
    ///
    /// ## Checks
    ///
    /// 1. **Inverted stake hierarchy**: `min_stake_compute` must not
    ///    exceed `min_stake_storage`. The Storage class is the higher
    ///    tier and its minimum must be greater than or equal to the
    ///    Compute minimum.
    ///
    /// 2. **Zero stakes with security enabled**: If both stake minimums
    ///    are zero but at least one security check (`require_tls` or
    ///    `require_identity_proof`) is enabled, the configuration is
    ///    contradictory — security checks imply production use, which
    ///    requires non-zero stake thresholds.
    ///
    /// ## Returns
    ///
    /// - `Ok(())` if the policy is internally consistent.
    /// - `Err(String)` with an explicit explanation of the inconsistency.
    ///
    /// ## Notes
    ///
    /// - `require_tls == false` alone is valid (intentionally disabled).
    /// - `require_identity_proof == false` alone is valid.
    /// - `allow_pending_scheduling == true` with `require_identity_proof == true`
    ///   is valid (not conflicting).
    /// - Permissive policy (all checks disabled, zero stakes) is valid.
    pub fn validate(&self) -> Result<(), String> {
        // Check 1: Stake hierarchy inversion
        if self.stake_requirement.min_stake_compute > self.stake_requirement.min_stake_storage {
            return Err(format!(
                "stake hierarchy inverted: min_stake_compute ({}) exceeds min_stake_storage ({}); \
                 Storage class must have a higher or equal minimum than Compute",
                self.stake_requirement.min_stake_compute,
                self.stake_requirement.min_stake_storage,
            ));
        }

        // Check 2: Zero stakes with security checks enabled
        let both_stakes_zero = self.stake_requirement.min_stake_storage == 0
            && self.stake_requirement.min_stake_compute == 0;
        let security_enabled = self.require_tls || self.require_identity_proof;

        if both_stakes_zero && security_enabled {
            return Err(
                "zero stake minimums with security checks enabled: \
                 both min_stake_storage and min_stake_compute are 0, \
                 but require_tls or require_identity_proof is true; \
                 production-like policies require non-zero stake thresholds"
                    .to_string(),
            );
        }

        Ok(())
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ──────────────────────────────────────────────────────────────────────
    // DEFAULT POLICY TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_default_stake_requirement() {
        let policy = GatingPolicy::default();
        let expected_stake = StakeRequirement::default();
        assert_eq!(policy.stake_requirement, expected_stake);
    }

    #[test]
    fn test_default_cooldown_config() {
        let policy = GatingPolicy::default();
        let expected_cooldown = CooldownConfig::default();
        assert_eq!(policy.cooldown_config, expected_cooldown);
    }

    #[test]
    fn test_default_require_tls_is_true() {
        let policy = GatingPolicy::default();
        assert!(policy.require_tls);
    }

    #[test]
    fn test_default_require_identity_proof_is_true() {
        let policy = GatingPolicy::default();
        assert!(policy.require_identity_proof);
    }

    #[test]
    fn test_default_allow_pending_scheduling_is_false() {
        let policy = GatingPolicy::default();
        assert!(!policy.allow_pending_scheduling);
    }

    #[test]
    fn test_default_validates_ok() {
        let policy = GatingPolicy::default();
        assert!(policy.validate().is_ok());
    }

    // ──────────────────────────────────────────────────────────────────────
    // PERMISSIVE POLICY TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_permissive_stake_zero() {
        let policy = GatingPolicy::permissive();
        assert_eq!(policy.stake_requirement.min_stake_storage, 0);
        assert_eq!(policy.stake_requirement.min_stake_compute, 0);
    }

    #[test]
    fn test_permissive_cooldown_zero() {
        let policy = GatingPolicy::permissive();
        assert_eq!(policy.cooldown_config.default_cooldown_secs, 0);
        assert_eq!(policy.cooldown_config.severe_cooldown_secs, 0);
    }

    #[test]
    fn test_permissive_require_tls_is_false() {
        let policy = GatingPolicy::permissive();
        assert!(!policy.require_tls);
    }

    #[test]
    fn test_permissive_require_identity_proof_is_false() {
        let policy = GatingPolicy::permissive();
        assert!(!policy.require_identity_proof);
    }

    #[test]
    fn test_permissive_allow_pending_scheduling_is_true() {
        let policy = GatingPolicy::permissive();
        assert!(policy.allow_pending_scheduling);
    }

    #[test]
    fn test_permissive_validates_ok() {
        let policy = GatingPolicy::permissive();
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn test_permissive_all_checks_disabled() {
        let policy = GatingPolicy::permissive();
        // Verify no security check is active
        assert!(!policy.require_tls);
        assert!(!policy.require_identity_proof);
        assert_eq!(policy.stake_requirement.min_stake_storage, 0);
        assert_eq!(policy.stake_requirement.min_stake_compute, 0);
        assert_eq!(policy.cooldown_config.default_cooldown_secs, 0);
        assert_eq!(policy.cooldown_config.severe_cooldown_secs, 0);
    }

    // ──────────────────────────────────────────────────────────────────────
    // DEFAULT ≠ PERMISSIVE
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_default_ne_permissive() {
        assert_ne!(GatingPolicy::default(), GatingPolicy::permissive());
    }

    // ──────────────────────────────────────────────────────────────────────
    // TRAIT TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_clone() {
        let policy = GatingPolicy::default();
        let cloned = policy.clone();
        assert_eq!(policy, cloned);
    }

    #[test]
    fn test_debug() {
        let policy = GatingPolicy::default();
        let debug = format!("{:?}", policy);
        assert!(debug.contains("GatingPolicy"));
        assert!(debug.contains("require_tls"));
        assert!(debug.contains("require_identity_proof"));
        assert!(debug.contains("allow_pending_scheduling"));
    }

    #[test]
    fn test_eq() {
        let a = GatingPolicy::default();
        let b = GatingPolicy::default();
        assert_eq!(a, b);
    }

    #[test]
    fn test_ne_different_tls() {
        let mut a = GatingPolicy::default();
        let b = GatingPolicy::default();
        a.require_tls = false;
        assert_ne!(a, b);
    }

    #[test]
    fn test_ne_different_identity() {
        let mut a = GatingPolicy::default();
        let b = GatingPolicy::default();
        a.require_identity_proof = false;
        assert_ne!(a, b);
    }

    #[test]
    fn test_ne_different_scheduling() {
        let mut a = GatingPolicy::default();
        let b = GatingPolicy::default();
        a.allow_pending_scheduling = true;
        assert_ne!(a, b);
    }

    #[test]
    fn test_serde_roundtrip_default() {
        let policy = GatingPolicy::default();
        let json = serde_json::to_string(&policy).expect("serialize");
        let back: GatingPolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(policy, back);
    }

    #[test]
    fn test_serde_roundtrip_permissive() {
        let policy = GatingPolicy::permissive();
        let json = serde_json::to_string(&policy).expect("serialize");
        let back: GatingPolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(policy, back);
    }

    #[test]
    fn test_serde_preserves_all_fields() {
        let policy = GatingPolicy::default();
        let json = serde_json::to_string(&policy).expect("serialize");
        let back: GatingPolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.stake_requirement, StakeRequirement::default());
        assert_eq!(back.cooldown_config, CooldownConfig::default());
        assert!(back.require_tls);
        assert!(back.require_identity_proof);
        assert!(!back.allow_pending_scheduling);
    }

    // ──────────────────────────────────────────────────────────────────────
    // validate() — VALID CONFIGURATIONS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_validate_default_ok() {
        assert!(GatingPolicy::default().validate().is_ok());
    }

    #[test]
    fn test_validate_permissive_ok() {
        assert!(GatingPolicy::permissive().validate().is_ok());
    }

    #[test]
    fn test_validate_tls_disabled_alone_ok() {
        let mut policy = GatingPolicy::default();
        policy.require_tls = false;
        // TLS intentionally disabled, but identity proof still on → valid
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn test_validate_identity_disabled_alone_ok() {
        let mut policy = GatingPolicy::default();
        policy.require_identity_proof = false;
        // Identity proof intentionally disabled, TLS still on → valid
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn test_validate_pending_scheduling_with_identity_ok() {
        let mut policy = GatingPolicy::default();
        policy.allow_pending_scheduling = true;
        // allow_pending_scheduling + require_identity_proof → valid
        assert!(policy.require_identity_proof);
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn test_validate_custom_stakes_ok() {
        let mut policy = GatingPolicy::default();
        policy.stake_requirement.min_stake_storage = 10_000;
        policy.stake_requirement.min_stake_compute = 1_000;
        // Storage > Compute, security on → valid
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn test_validate_equal_stakes_ok() {
        let mut policy = GatingPolicy::default();
        policy.stake_requirement.min_stake_storage = 1000;
        policy.stake_requirement.min_stake_compute = 1000;
        // Equal stakes → valid (not inverted)
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn test_validate_zero_compute_nonzero_storage_ok() {
        let mut policy = GatingPolicy::default();
        policy.stake_requirement.min_stake_storage = 5000;
        policy.stake_requirement.min_stake_compute = 0;
        // Compute = 0 < Storage = 5000 → hierarchy not inverted
        // Security enabled, but not BOTH zero → valid
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn test_validate_zero_stakes_all_security_off_ok() {
        // Both stakes zero, no security → permissive variant, valid
        let policy = GatingPolicy {
            stake_requirement: StakeRequirement {
                min_stake_storage: 0,
                min_stake_compute: 0,
            },
            cooldown_config: CooldownConfig::default(),
            require_tls: false,
            require_identity_proof: false,
            allow_pending_scheduling: false,
        };
        assert!(policy.validate().is_ok());
    }

    // ──────────────────────────────────────────────────────────────────────
    // validate() — INVALID CONFIGURATIONS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_validate_inverted_stake_hierarchy() {
        let policy = GatingPolicy {
            stake_requirement: StakeRequirement {
                min_stake_storage: 100,
                min_stake_compute: 200, // compute > storage → inverted
            },
            cooldown_config: CooldownConfig::default(),
            require_tls: true,
            require_identity_proof: true,
            allow_pending_scheduling: false,
        };
        let result = policy.validate();
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(
            msg.contains("stake hierarchy inverted"),
            "expected hierarchy error, got: {}",
            msg
        );
        assert!(msg.contains("200"), "should contain compute value: {}", msg);
        assert!(msg.contains("100"), "should contain storage value: {}", msg);
    }

    #[test]
    fn test_validate_inverted_stake_large_values() {
        let policy = GatingPolicy {
            stake_requirement: StakeRequirement {
                min_stake_storage: 500_000_000_000_000_000_000,  // 500 NUSA
                min_stake_compute: 5_000_000_000_000_000_000_000, // 5000 NUSA → inverted
            },
            cooldown_config: CooldownConfig::default(),
            require_tls: true,
            require_identity_proof: true,
            allow_pending_scheduling: false,
        };
        assert!(policy.validate().is_err());
    }

    #[test]
    fn test_validate_zero_stakes_with_tls_required() {
        let policy = GatingPolicy {
            stake_requirement: StakeRequirement {
                min_stake_storage: 0,
                min_stake_compute: 0,
            },
            cooldown_config: CooldownConfig::default(),
            require_tls: true,
            require_identity_proof: false,
            allow_pending_scheduling: false,
        };
        let result = policy.validate();
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(
            msg.contains("zero stake minimums"),
            "expected zero-stake error, got: {}",
            msg
        );
    }

    #[test]
    fn test_validate_zero_stakes_with_identity_required() {
        let policy = GatingPolicy {
            stake_requirement: StakeRequirement {
                min_stake_storage: 0,
                min_stake_compute: 0,
            },
            cooldown_config: CooldownConfig::default(),
            require_tls: false,
            require_identity_proof: true,
            allow_pending_scheduling: false,
        };
        let result = policy.validate();
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(
            msg.contains("zero stake minimums"),
            "expected zero-stake error, got: {}",
            msg
        );
    }

    #[test]
    fn test_validate_zero_stakes_with_both_security() {
        let policy = GatingPolicy {
            stake_requirement: StakeRequirement {
                min_stake_storage: 0,
                min_stake_compute: 0,
            },
            cooldown_config: CooldownConfig::default(),
            require_tls: true,
            require_identity_proof: true,
            allow_pending_scheduling: false,
        };
        let result = policy.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_error_messages_are_not_generic() {
        // Check 1: hierarchy error is specific
        let inv = GatingPolicy {
            stake_requirement: StakeRequirement {
                min_stake_storage: 10,
                min_stake_compute: 20,
            },
            cooldown_config: CooldownConfig::default(),
            require_tls: true,
            require_identity_proof: true,
            allow_pending_scheduling: false,
        };
        let msg = inv.validate().unwrap_err();
        assert!(!msg.contains("invalid config"), "message too generic: {}", msg);
        assert!(msg.len() > 20, "message too short: {}", msg);

        // Check 2: zero-stake error is specific
        let zero = GatingPolicy {
            stake_requirement: StakeRequirement {
                min_stake_storage: 0,
                min_stake_compute: 0,
            },
            cooldown_config: CooldownConfig::default(),
            require_tls: true,
            require_identity_proof: false,
            allow_pending_scheduling: false,
        };
        let msg = zero.validate().unwrap_err();
        assert!(!msg.contains("invalid config"), "message too generic: {}", msg);
        assert!(msg.len() > 20, "message too short: {}", msg);
    }

    // ──────────────────────────────────────────────────────────────────────
    // validate() — PRIORITY: HIERARCHY CHECKED BEFORE ZERO-STAKE
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_validate_hierarchy_check_takes_priority() {
        // Both inverted AND zero-stake contradiction exist
        let policy = GatingPolicy {
            stake_requirement: StakeRequirement {
                min_stake_storage: 0,
                min_stake_compute: 100, // inverted (compute > storage)
            },
            cooldown_config: CooldownConfig::default(),
            require_tls: true,
            require_identity_proof: true,
            allow_pending_scheduling: false,
        };
        let result = policy.validate();
        assert!(result.is_err());
        let msg = result.unwrap_err();
        // Hierarchy check runs first
        assert!(
            msg.contains("stake hierarchy inverted"),
            "hierarchy should be checked first, got: {}",
            msg
        );
    }

    // ──────────────────────────────────────────────────────────────────────
    // validate() — DETERMINISM
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_validate_deterministic() {
        let policy = GatingPolicy::default();
        let r1 = policy.validate();
        let r2 = policy.validate();
        assert_eq!(r1, r2);

        let bad = GatingPolicy {
            stake_requirement: StakeRequirement {
                min_stake_storage: 10,
                min_stake_compute: 20,
            },
            cooldown_config: CooldownConfig::default(),
            require_tls: true,
            require_identity_proof: true,
            allow_pending_scheduling: false,
        };
        let e1 = bad.validate();
        let e2 = bad.validate();
        assert_eq!(e1, e2);
    }

    // ──────────────────────────────────────────────────────────────────────
    // SEND + SYNC
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<GatingPolicy>();
    }

    // ──────────────────────────────────────────────────────────────────────
    // NO INTERIOR MUTABILITY
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_no_interior_mutability() {
        // GatingPolicy is Clone + Eq, so modifying a clone does not
        // affect the original — this verifies value semantics.
        let original = GatingPolicy::default();
        let mut modified = original.clone();
        modified.require_tls = false;
        assert_ne!(original, modified);
        assert!(original.require_tls); // original unchanged
    }
}