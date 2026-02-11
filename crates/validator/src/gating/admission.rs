//! # Admission Policy Configuration (14B.27)
//!
//! Defines [`AdmissionPolicy`] — the tunable configuration layer for
//! node admission decisions. This struct wraps a [`GatingPolicy`] and
//! adds time-based rules for pending-node rejection and quarantine
//! escalation.
//!
//! ## Overview
//!
//! `AdmissionPolicy` is consumed by the admission coordinator to
//! determine:
//!
//! - Which gating checks to run (via the embedded `GatingPolicy`).
//! - Whether to auto-activate nodes that pass all checks.
//! - Whether a pending node has exceeded its allowed duration.
//! - Whether a quarantined node should be escalated (e.g., banned).
//!
//! ## Time Arithmetic
//!
//! All time-related methods accept caller-provided timestamps as `u64`
//! (Unix seconds). No system clock is ever accessed. Subtraction is
//! guarded: if `current < reference_timestamp`, the method returns
//! `false` (conservative, no-op) to handle clock skew safely.
//!
//! ## Boundary Behavior
//!
//! - `elapsed == max_pending_duration_secs` → NOT rejected (strict `>`).
//! - `elapsed == max_quarantine_duration_secs` → NOT escalated (strict `>`).
//!
//! ## Properties
//!
//! - **Deterministic**: Same inputs always produce the same output.
//! - **Pure**: No system clock, no I/O, no randomness, no side effects.
//! - **Safe**: No panic, no unwrap, no overflow.

use serde::{Deserialize, Serialize};

use dsdn_common::gating::GatingPolicy;

// ════════════════════════════════════════════════════════════════════════════════
// NAMED CONSTANTS
// ════════════════════════════════════════════════════════════════════════════════

/// Default maximum duration (seconds) a node may remain in `Pending`
/// status before being auto-rejected.
///
/// Value: 3600 seconds (1 hour).
const DEFAULT_MAX_PENDING_DURATION_SECS: u64 = 3600;

/// Default maximum duration (seconds) a node may remain in `Quarantined`
/// status before escalation (e.g., ban).
///
/// Value: 86400 seconds (24 hours).
const DEFAULT_MAX_QUARANTINE_DURATION_SECS: u64 = 86400;

// ════════════════════════════════════════════════════════════════════════════════
// ADMISSION POLICY
// ════════════════════════════════════════════════════════════════════════════════

/// Tunable admission policy configuration.
///
/// `AdmissionPolicy` wraps a [`GatingPolicy`] and adds time-based
/// rules for pending-node auto-rejection and quarantine escalation.
///
/// ## Fields
///
/// - `gating_policy`: The embedded gating policy controlling which
///   checks are active during node evaluation.
/// - `max_pending_duration_secs`: Maximum seconds a node may stay in
///   `Pending` status before auto-rejection. Boundary: `elapsed ==
///   max` is NOT rejected (strict `>`).
/// - `max_quarantine_duration_secs`: Maximum seconds a node may stay
///   in `Quarantined` status before escalation. Boundary: `elapsed ==
///   max` is NOT escalated (strict `>`).
/// - `auto_activate_on_pass`: If `true`, nodes that pass all gating
///   checks are automatically transitioned to `Active` status.
/// - `require_all_checks`: If `true`, all configured checks must pass
///   for admission. If `false`, the admission coordinator may apply
///   partial-pass logic (behavior defined by the coordinator, not here).
///
/// ## Presets
///
/// - [`Default::default()`]: Production preset with all checks required,
///   auto-activation enabled, 1-hour pending timeout, 24-hour quarantine
///   timeout.
/// - [`AdmissionPolicy::permissive()`]: Testing preset with permissive
///   gating, auto-activation enabled, maximum timeouts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionPolicy {
    /// The gating policy controlling which checks are active.
    pub gating_policy: GatingPolicy,
    /// Maximum seconds a node may remain in Pending before auto-rejection.
    pub max_pending_duration_secs: u64,
    /// Maximum seconds a node may remain in Quarantined before escalation.
    pub max_quarantine_duration_secs: u64,
    /// Whether to auto-activate nodes that pass all gating checks.
    pub auto_activate_on_pass: bool,
    /// Whether all configured checks must pass for admission.
    pub require_all_checks: bool,
}

impl Default for AdmissionPolicy {
    /// Returns the **production default** admission policy.
    ///
    /// | Field | Value |
    /// |-------|-------|
    /// | `gating_policy` | `GatingPolicy::default()` (all security checks enabled) |
    /// | `max_pending_duration_secs` | 3600 (1 hour) |
    /// | `max_quarantine_duration_secs` | 86400 (24 hours) |
    /// | `auto_activate_on_pass` | `true` |
    /// | `require_all_checks` | `true` |
    fn default() -> Self {
        Self {
            gating_policy: GatingPolicy::default(),
            max_pending_duration_secs: DEFAULT_MAX_PENDING_DURATION_SECS,
            max_quarantine_duration_secs: DEFAULT_MAX_QUARANTINE_DURATION_SECS,
            auto_activate_on_pass: true,
            require_all_checks: true,
        }
    }
}

impl AdmissionPolicy {
    /// Returns a **permissive** admission policy for testing.
    ///
    /// Uses `GatingPolicy::permissive()` (all security checks disabled),
    /// auto-activation enabled, and maximum timeouts (`u64::MAX`) so
    /// neither pending auto-rejection nor quarantine escalation triggers.
    ///
    /// **WARNING**: Must NEVER be used in production.
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            gating_policy: GatingPolicy::permissive(),
            max_pending_duration_secs: u64::MAX,
            max_quarantine_duration_secs: u64::MAX,
            auto_activate_on_pass: true,
            require_all_checks: false,
        }
    }

    /// Determine whether a pending node should be auto-rejected due to
    /// exceeding the maximum pending duration.
    ///
    /// ## Logic
    ///
    /// 1. If `current < registered_at` → `false` (clock skew guard).
    /// 2. `elapsed = current - registered_at`.
    /// 3. If `elapsed > max_pending_duration_secs` → `true` (reject).
    /// 4. Otherwise → `false` (do not reject).
    ///
    /// ## Boundary Behavior
    ///
    /// - `elapsed == max_pending_duration_secs` → `false` (NOT rejected).
    ///   The comparison is strict `>`, not `>=`.
    ///
    /// ## Properties
    ///
    /// - No overflow: subtraction is guarded by the `current < registered_at` check.
    /// - No panic, no unwrap, no system clock access.
    /// - Deterministic for same `(registered_at, current, max_pending_duration_secs)`.
    #[must_use]
    #[inline]
    pub fn should_auto_reject_pending(
        &self,
        registered_at: u64,
        current: u64,
    ) -> bool {
        if current < registered_at {
            return false;
        }
        let elapsed = current - registered_at;
        elapsed > self.max_pending_duration_secs
    }

    /// Determine whether a quarantined node should be escalated (e.g.,
    /// banned) due to exceeding the maximum quarantine duration.
    ///
    /// ## Logic
    ///
    /// 1. If `current < quarantined_at` → `false` (clock skew guard).
    /// 2. `elapsed = current - quarantined_at`.
    /// 3. If `elapsed > max_quarantine_duration_secs` → `true` (escalate).
    /// 4. Otherwise → `false` (do not escalate).
    ///
    /// ## Boundary Behavior
    ///
    /// - `elapsed == max_quarantine_duration_secs` → `false` (NOT escalated).
    ///   The comparison is strict `>`, not `>=`.
    ///
    /// ## Properties
    ///
    /// - No overflow: subtraction is guarded by the `current < quarantined_at` check.
    /// - No panic, no unwrap, no system clock access.
    /// - Deterministic for same `(quarantined_at, current, max_quarantine_duration_secs)`.
    #[must_use]
    #[inline]
    pub fn should_escalate_quarantine(
        &self,
        quarantined_at: u64,
        current: u64,
    ) -> bool {
        if current < quarantined_at {
            return false;
        }
        let elapsed = current - quarantined_at;
        elapsed > self.max_quarantine_duration_secs
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ────────────────────────────────────────────────────────────────────
    // DEFAULT VALUES
    // ────────────────────────────────────────────────────────────────────

    #[test]
    fn test_default_gating_policy_is_default() {
        let ap = AdmissionPolicy::default();
        assert_eq!(ap.gating_policy, GatingPolicy::default());
    }

    #[test]
    fn test_default_max_pending_duration() {
        let ap = AdmissionPolicy::default();
        assert_eq!(ap.max_pending_duration_secs, 3600);
    }

    #[test]
    fn test_default_max_quarantine_duration() {
        let ap = AdmissionPolicy::default();
        assert_eq!(ap.max_quarantine_duration_secs, 86400);
    }

    #[test]
    fn test_default_auto_activate_on_pass() {
        let ap = AdmissionPolicy::default();
        assert!(ap.auto_activate_on_pass);
    }

    #[test]
    fn test_default_require_all_checks() {
        let ap = AdmissionPolicy::default();
        assert!(ap.require_all_checks);
    }

    // ────────────────────────────────────────────────────────────────────
    // PERMISSIVE PRESET
    // ────────────────────────────────────────────────────────────────────

    #[test]
    fn test_permissive_gating_policy() {
        let ap = AdmissionPolicy::permissive();
        assert_eq!(ap.gating_policy, GatingPolicy::permissive());
    }

    #[test]
    fn test_permissive_max_pending_is_u64_max() {
        let ap = AdmissionPolicy::permissive();
        assert_eq!(ap.max_pending_duration_secs, u64::MAX);
    }

    #[test]
    fn test_permissive_max_quarantine_is_u64_max() {
        let ap = AdmissionPolicy::permissive();
        assert_eq!(ap.max_quarantine_duration_secs, u64::MAX);
    }

    #[test]
    fn test_permissive_auto_activate() {
        let ap = AdmissionPolicy::permissive();
        assert!(ap.auto_activate_on_pass);
    }

    #[test]
    fn test_permissive_require_all_checks_false() {
        let ap = AdmissionPolicy::permissive();
        assert!(!ap.require_all_checks);
    }

    // ════════════════════════════════════════════════════════════════════
    // should_auto_reject_pending — BASIC CASES
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn test_pending_not_expired() {
        let ap = AdmissionPolicy::default();
        // registered at 1000, current 2000, elapsed=1000 < 3600
        assert!(!ap.should_auto_reject_pending(1000, 2000));
    }

    #[test]
    fn test_pending_expired() {
        let ap = AdmissionPolicy::default();
        // registered at 1000, current 5000, elapsed=4000 > 3600
        assert!(ap.should_auto_reject_pending(1000, 5000));
    }

    #[test]
    fn test_pending_exact_boundary_not_rejected() {
        let ap = AdmissionPolicy::default();
        // elapsed == 3600 → NOT rejected (strict >)
        assert!(!ap.should_auto_reject_pending(1000, 4600));
    }

    #[test]
    fn test_pending_one_past_boundary_rejected() {
        let ap = AdmissionPolicy::default();
        // elapsed == 3601 > 3600 → rejected
        assert!(ap.should_auto_reject_pending(1000, 4601));
    }

    // ════════════════════════════════════════════════════════════════════
    // should_auto_reject_pending — CLOCK SKEW
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn test_pending_current_before_registered_returns_false() {
        let ap = AdmissionPolicy::default();
        assert!(!ap.should_auto_reject_pending(5000, 1000));
    }

    #[test]
    fn test_pending_current_equals_registered() {
        let ap = AdmissionPolicy::default();
        // elapsed = 0 ≤ 3600 → false
        assert!(!ap.should_auto_reject_pending(1000, 1000));
    }

    // ════════════════════════════════════════════════════════════════════
    // should_auto_reject_pending — EDGE CASES
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn test_pending_registered_at_zero_current_zero() {
        let ap = AdmissionPolicy::default();
        assert!(!ap.should_auto_reject_pending(0, 0));
    }

    #[test]
    fn test_pending_registered_at_zero_large_current() {
        let ap = AdmissionPolicy::default();
        assert!(ap.should_auto_reject_pending(0, u64::MAX));
    }

    #[test]
    fn test_pending_registered_at_zero_current_3601() {
        let ap = AdmissionPolicy::default();
        assert!(ap.should_auto_reject_pending(0, 3601));
    }

    #[test]
    fn test_pending_registered_at_zero_current_3600() {
        let ap = AdmissionPolicy::default();
        // elapsed = 3600 == 3600 → false (strict >)
        assert!(!ap.should_auto_reject_pending(0, 3600));
    }

    #[test]
    fn test_pending_u64_max_timestamps() {
        let ap = AdmissionPolicy::default();
        assert!(!ap.should_auto_reject_pending(u64::MAX, u64::MAX));
    }

    #[test]
    fn test_pending_current_zero_registered_nonzero() {
        let ap = AdmissionPolicy::default();
        assert!(!ap.should_auto_reject_pending(100, 0));
    }

    // ════════════════════════════════════════════════════════════════════
    // should_escalate_quarantine — BASIC CASES
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn test_quarantine_not_expired() {
        let ap = AdmissionPolicy::default();
        assert!(!ap.should_escalate_quarantine(1000, 50000));
    }

    #[test]
    fn test_quarantine_expired() {
        let ap = AdmissionPolicy::default();
        assert!(ap.should_escalate_quarantine(1000, 100000));
    }

    #[test]
    fn test_quarantine_exact_boundary_not_escalated() {
        let ap = AdmissionPolicy::default();
        // elapsed == 86400 → NOT escalated (strict >)
        assert!(!ap.should_escalate_quarantine(1000, 87400));
    }

    #[test]
    fn test_quarantine_one_past_boundary_escalated() {
        let ap = AdmissionPolicy::default();
        // elapsed == 86401 > 86400 → escalated
        assert!(ap.should_escalate_quarantine(1000, 87401));
    }

    // ════════════════════════════════════════════════════════════════════
    // should_escalate_quarantine — CLOCK SKEW
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn test_quarantine_current_before_quarantined_returns_false() {
        let ap = AdmissionPolicy::default();
        assert!(!ap.should_escalate_quarantine(5000, 1000));
    }

    #[test]
    fn test_quarantine_current_equals_quarantined() {
        let ap = AdmissionPolicy::default();
        assert!(!ap.should_escalate_quarantine(1000, 1000));
    }

    // ════════════════════════════════════════════════════════════════════
    // should_escalate_quarantine — EDGE CASES
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn test_quarantine_at_zero_current_zero() {
        let ap = AdmissionPolicy::default();
        assert!(!ap.should_escalate_quarantine(0, 0));
    }

    #[test]
    fn test_quarantine_at_zero_large_current() {
        let ap = AdmissionPolicy::default();
        assert!(ap.should_escalate_quarantine(0, u64::MAX));
    }

    #[test]
    fn test_quarantine_u64_max_timestamps() {
        let ap = AdmissionPolicy::default();
        assert!(!ap.should_escalate_quarantine(u64::MAX, u64::MAX));
    }

    #[test]
    fn test_quarantine_current_zero_quarantined_nonzero() {
        let ap = AdmissionPolicy::default();
        assert!(!ap.should_escalate_quarantine(100, 0));
    }

    // ════════════════════════════════════════════════════════════════════
    // PERMISSIVE — NEVER TRIGGERS
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn test_permissive_never_auto_rejects_pending() {
        let ap = AdmissionPolicy::permissive();
        // max_pending = u64::MAX, elapsed at most u64::MAX → not > u64::MAX
        assert!(!ap.should_auto_reject_pending(0, u64::MAX));
    }

    #[test]
    fn test_permissive_never_escalates_quarantine() {
        let ap = AdmissionPolicy::permissive();
        assert!(!ap.should_escalate_quarantine(0, u64::MAX));
    }

    // ════════════════════════════════════════════════════════════════════
    // CUSTOM POLICY
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn test_custom_pending_duration() {
        let ap = AdmissionPolicy {
            max_pending_duration_secs: 10,
            ..AdmissionPolicy::default()
        };
        assert!(!ap.should_auto_reject_pending(100, 110)); // elapsed=10, not >10
        assert!(ap.should_auto_reject_pending(100, 111));  // elapsed=11 > 10
    }

    #[test]
    fn test_custom_quarantine_duration() {
        let ap = AdmissionPolicy {
            max_quarantine_duration_secs: 60,
            ..AdmissionPolicy::default()
        };
        assert!(!ap.should_escalate_quarantine(100, 160)); // elapsed=60, not >60
        assert!(ap.should_escalate_quarantine(100, 161));  // elapsed=61 > 60
    }

    #[test]
    fn test_zero_duration_pending() {
        let ap = AdmissionPolicy {
            max_pending_duration_secs: 0,
            ..AdmissionPolicy::default()
        };
        assert!(!ap.should_auto_reject_pending(100, 100)); // elapsed=0, not >0
        assert!(ap.should_auto_reject_pending(100, 101));  // elapsed=1 > 0
    }

    #[test]
    fn test_zero_duration_quarantine() {
        let ap = AdmissionPolicy {
            max_quarantine_duration_secs: 0,
            ..AdmissionPolicy::default()
        };
        assert!(!ap.should_escalate_quarantine(100, 100)); // elapsed=0, not >0
        assert!(ap.should_escalate_quarantine(100, 101));  // elapsed=1 > 0
    }

    // ════════════════════════════════════════════════════════════════════
    // DETERMINISM
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn test_pending_deterministic() {
        let ap = AdmissionPolicy::default();
        let r1 = ap.should_auto_reject_pending(1000, 5000);
        let r2 = ap.should_auto_reject_pending(1000, 5000);
        let r3 = ap.should_auto_reject_pending(1000, 5000);
        assert_eq!(r1, r2);
        assert_eq!(r2, r3);
    }

    #[test]
    fn test_quarantine_deterministic() {
        let ap = AdmissionPolicy::default();
        let r1 = ap.should_escalate_quarantine(1000, 100000);
        let r2 = ap.should_escalate_quarantine(1000, 100000);
        let r3 = ap.should_escalate_quarantine(1000, 100000);
        assert_eq!(r1, r2);
        assert_eq!(r2, r3);
    }

    // ════════════════════════════════════════════════════════════════════
    // STRUCT PROPERTIES
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn test_clone() {
        let ap1 = AdmissionPolicy::default();
        let ap2 = ap1.clone();
        assert_eq!(ap1, ap2);
    }

    #[test]
    fn test_debug() {
        let ap = AdmissionPolicy::default();
        let debug = format!("{:?}", ap);
        assert!(debug.contains("AdmissionPolicy"));
    }

    #[test]
    fn test_eq_default_equals_default() {
        let a = AdmissionPolicy::default();
        let b = AdmissionPolicy::default();
        assert_eq!(a, b);
    }

    #[test]
    fn test_ne_different_pending_duration() {
        let a = AdmissionPolicy::default();
        let mut b = AdmissionPolicy::default();
        b.max_pending_duration_secs = 999;
        assert_ne!(a, b);
    }

    #[test]
    fn test_ne_default_vs_permissive() {
        let a = AdmissionPolicy::default();
        let b = AdmissionPolicy::permissive();
        assert_ne!(a, b);
    }

    // ════════════════════════════════════════════════════════════════════
    // SERDE ROUNDTRIP
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn test_serde_roundtrip_default() {
        let ap = AdmissionPolicy::default();
        let json = serde_json::to_string(&ap).expect("serialize");
        let back: AdmissionPolicy =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ap, back);
    }

    #[test]
    fn test_serde_roundtrip_permissive() {
        let ap = AdmissionPolicy::permissive();
        let json = serde_json::to_string(&ap).expect("serialize");
        let back: AdmissionPolicy =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ap, back);
    }

    // ════════════════════════════════════════════════════════════════════
    // SEND + SYNC
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn test_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AdmissionPolicy>();
    }

    // ════════════════════════════════════════════════════════════════════
    // NO INTERIOR MUTABILITY
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn test_value_semantics() {
        let original = AdmissionPolicy::default();
        let mut modified = original.clone();
        modified.auto_activate_on_pass = false;
        assert_ne!(original, modified);
        assert!(original.auto_activate_on_pass);
    }

    // ════════════════════════════════════════════════════════════════════
    // BOUNDARY SWEEP — PENDING
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn test_pending_boundary_sweep() {
        let ap = AdmissionPolicy {
            max_pending_duration_secs: 100,
            ..AdmissionPolicy::default()
        };
        let base: u64 = 1000;

        let cases: &[(u64, bool)] = &[
            (base, false),        // elapsed=0, not >100
            (base + 50, false),   // elapsed=50, not >100
            (base + 99, false),   // elapsed=99, not >100
            (base + 100, false),  // elapsed=100, not >100 (boundary)
            (base + 101, true),   // elapsed=101, >100
            (base + 200, true),   // elapsed=200, >100
        ];

        for &(current, expected) in cases {
            assert_eq!(
                ap.should_auto_reject_pending(base, current),
                expected,
                "pending: registered_at={}, current={}, expected={}",
                base, current, expected,
            );
        }
    }

    // ════════════════════════════════════════════════════════════════════
    // BOUNDARY SWEEP — QUARANTINE
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn test_quarantine_boundary_sweep() {
        let ap = AdmissionPolicy {
            max_quarantine_duration_secs: 100,
            ..AdmissionPolicy::default()
        };
        let base: u64 = 1000;

        let cases: &[(u64, bool)] = &[
            (base, false),        // elapsed=0, not >100
            (base + 50, false),   // elapsed=50, not >100
            (base + 99, false),   // elapsed=99, not >100
            (base + 100, false),  // elapsed=100, not >100 (boundary)
            (base + 101, true),   // elapsed=101, >100
            (base + 200, true),   // elapsed=200, >100
        ];

        for &(current, expected) in cases {
            assert_eq!(
                ap.should_escalate_quarantine(base, current),
                expected,
                "quarantine: quarantined_at={}, current={}, expected={}",
                base, current, expected,
            );
        }
    }
}