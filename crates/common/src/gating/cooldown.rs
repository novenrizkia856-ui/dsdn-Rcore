//! # Slashing Cooldown Types (14B.4)
//!
//! Defines types and deterministic logic for tracking cooldown periods
//! after slashing events. Cooldowns prevent instant re-entry of misbehaving
//! nodes into the network.
//!
//! ## Overview
//!
//! When a node is banned (via slashing or identity spoofing), a cooldown
//! period is imposed before the node can re-register. The cooldown duration
//! depends on the severity of the offense:
//!
//! | Severity | Duration | Use Case |
//! |----------|----------|----------|
//! | Default | 24 hours (86,400 seconds) | Standard violations |
//! | Severe | 7 days (604,800 seconds) | Severe slashing events |
//!
//! ## Determinism
//!
//! All time calculations are based on **input parameters** (timestamps
//! passed by the caller). There is no access to system clocks, wall time,
//! or any non-deterministic time source. Every method is a pure function.
//!
//! ## Safety Properties
//!
//! - All timestamp arithmetic uses `saturating_add` / `saturating_sub`
//!   to prevent overflow and underflow.
//! - If `start_timestamp + duration_secs` would overflow `u64`, it
//!   saturates to `u64::MAX`, meaning the cooldown effectively never
//!   expires — this is the safe/conservative behavior.
//! - Cooldown expiry does NOT automatically change `NodeStatus`. The
//!   caller must explicitly transition `Banned → Pending` after verifying
//!   that the cooldown has expired.
//! - There is no automatic re-activation or appeal mechanism.

use serde::{Deserialize, Serialize};

// ════════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════════

/// Default cooldown duration: 24 hours in seconds.
const DEFAULT_COOLDOWN_SECS: u64 = 86_400;

/// Severe cooldown duration: 7 days in seconds.
const SEVERE_COOLDOWN_SECS: u64 = 604_800;

// ════════════════════════════════════════════════════════════════════════════════
// COOLDOWN PERIOD
// ════════════════════════════════════════════════════════════════════════════════

/// A cooldown period imposed on a node after a slashing event.
///
/// `CooldownPeriod` records when the cooldown started, how long it lasts,
/// and why it was imposed. All time queries are pure functions that take
/// a `current_timestamp` parameter — no system clock access.
///
/// ## Fields
///
/// - `start_timestamp`: Unix timestamp (seconds) when the cooldown began.
/// - `duration_secs`: Duration of the cooldown in seconds.
/// - `reason`: Human-readable explanation for the cooldown.
///
/// ## Overflow Safety
///
/// `expires_at()` uses `saturating_add` — if `start_timestamp + duration_secs`
/// would overflow `u64`, the result is `u64::MAX`. This means the cooldown
/// effectively never expires, which is the conservative/safe behavior.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CooldownPeriod {
    /// Unix timestamp (seconds) when the cooldown started.
    pub start_timestamp: u64,
    /// Duration of the cooldown in seconds.
    pub duration_secs: u64,
    /// Human-readable reason for the cooldown.
    pub reason: String,
}

impl CooldownPeriod {
    /// Returns the Unix timestamp at which this cooldown expires.
    ///
    /// Uses `saturating_add` to prevent overflow. If the sum of
    /// `start_timestamp` and `duration_secs` exceeds `u64::MAX`,
    /// the result is `u64::MAX` (cooldown effectively never expires).
    ///
    /// This is a **pure function** — deterministic, no side effects.
    #[must_use]
    #[inline]
    pub fn expires_at(&self) -> u64 {
        self.start_timestamp.saturating_add(self.duration_secs)
    }

    /// Returns whether this cooldown is still active at `current_timestamp`.
    ///
    /// ## Rules
    ///
    /// 1. If `current_timestamp < start_timestamp` → `true`
    ///    (timestamp is before cooldown start; conservative/safe)
    /// 2. If `current_timestamp < expires_at()` → `true`
    /// 3. Otherwise → `false` (cooldown has expired)
    ///
    /// This is a **pure function** — no system clock access, no side
    /// effects, fully deterministic based on input.
    ///
    /// ## Arguments
    ///
    /// * `current_timestamp` — The current Unix timestamp (seconds),
    ///   provided by the caller. Not read from any clock.
    #[must_use]
    #[inline]
    pub fn is_active(&self, current_timestamp: u64) -> bool {
        // Rule 1: timestamp before cooldown start → conservatively active
        if current_timestamp < self.start_timestamp {
            return true;
        }
        // Rules 2 & 3: check against expiry
        current_timestamp < self.expires_at()
    }

    /// Returns the number of seconds remaining until this cooldown expires.
    ///
    /// ## Rules
    ///
    /// - If the cooldown has expired (`current_timestamp >= expires_at()`) → `0`
    /// - Otherwise → `expires_at() - current_timestamp`
    ///
    /// Uses `saturating_sub` to prevent underflow. This is a **pure function**.
    ///
    /// ## Arguments
    ///
    /// * `current_timestamp` — The current Unix timestamp (seconds),
    ///   provided by the caller.
    #[must_use]
    #[inline]
    pub fn remaining_secs(&self, current_timestamp: u64) -> u64 {
        let expires = self.expires_at();
        if current_timestamp >= expires {
            return 0;
        }
        // Safe: we verified current_timestamp < expires above,
        // so expires - current_timestamp cannot underflow.
        // Using saturating_sub as explicit safety guarantee.
        expires.saturating_sub(current_timestamp)
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// COOLDOWN CONFIG
// ════════════════════════════════════════════════════════════════════════════════

/// Configuration for cooldown durations after slashing events.
///
/// `CooldownConfig` holds the durations for two severity levels:
///
/// - **Default** (24 hours / 86,400 seconds): Standard violations such
///   as minor protocol breaches or temporary stake drops.
/// - **Severe** (7 days / 604,800 seconds): Severe violations such as
///   identity spoofing or repeated misbehavior.
///
/// ## Usage
///
/// ```rust,ignore
/// use dsdn_common::{CooldownConfig, CooldownPeriod};
///
/// let config = CooldownConfig::default();
///
/// // Create a default-severity cooldown
/// let cooldown = config.create_cooldown(false, 1700000000, "stake drop".into());
/// assert_eq!(cooldown.duration_secs, 86_400);
///
/// // Create a severe cooldown
/// let severe = config.create_cooldown(true, 1700000000, "identity spoofing".into());
/// assert_eq!(severe.duration_secs, 604_800);
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CooldownConfig {
    /// Cooldown duration for standard/default violations (in seconds).
    pub default_cooldown_secs: u64,
    /// Cooldown duration for severe violations (in seconds).
    pub severe_cooldown_secs: u64,
}

impl Default for CooldownConfig {
    /// Returns the protocol-default cooldown configuration.
    ///
    /// - Default: 86,400 seconds (24 hours)
    /// - Severe: 604,800 seconds (7 days)
    fn default() -> Self {
        Self {
            default_cooldown_secs: DEFAULT_COOLDOWN_SECS,
            severe_cooldown_secs: SEVERE_COOLDOWN_SECS,
        }
    }
}

impl CooldownConfig {
    /// Creates a new [`CooldownPeriod`] based on severity.
    ///
    /// ## Arguments
    ///
    /// * `severe` — If `true`, uses `severe_cooldown_secs`; otherwise
    ///   uses `default_cooldown_secs`.
    /// * `timestamp` — The Unix timestamp (seconds) when the cooldown begins.
    ///   Passed through unchanged — no normalization or adjustment.
    /// * `reason` — Human-readable explanation for the cooldown.
    ///   Passed through unchanged — no normalization or truncation.
    ///
    /// ## Returns
    ///
    /// A `CooldownPeriod` with the selected duration, the given start
    /// timestamp, and the given reason.
    #[must_use]
    pub fn create_cooldown(
        &self,
        severe: bool,
        timestamp: u64,
        reason: String,
    ) -> CooldownPeriod {
        let duration_secs = if severe {
            self.severe_cooldown_secs
        } else {
            self.default_cooldown_secs
        };

        CooldownPeriod {
            start_timestamp: timestamp,
            duration_secs,
            reason,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// COOLDOWN STATUS
// ════════════════════════════════════════════════════════════════════════════════

/// The cooldown status of a node.
///
/// Used to represent the current cooldown state when evaluating whether
/// a banned node may re-register.
///
/// ## Variants
///
/// - **`NoCooldown`**: No cooldown is in effect. The node either was never
///   banned or has no recorded cooldown period.
///
/// - **`InCooldown(CooldownPeriod)`**: A cooldown is currently active.
///   The node must wait until the cooldown expires before re-registering.
///
/// - **`Expired(CooldownPeriod)`**: The cooldown has expired. The node
///   may proceed with re-registration (subject to other gating checks).
///   The original `CooldownPeriod` is preserved for audit purposes.
///
/// ## Note
///
/// `CooldownStatus` is a **data type only**. It does not trigger any
/// status transitions. The caller is responsible for evaluating the
/// cooldown status and deciding whether to allow re-registration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CooldownStatus {
    /// No cooldown is in effect.
    NoCooldown,
    /// A cooldown is currently active.
    InCooldown(CooldownPeriod),
    /// The cooldown has expired (preserved for audit).
    Expired(CooldownPeriod),
}

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
    fn test_default_cooldown_is_24_hours() {
        assert_eq!(DEFAULT_COOLDOWN_SECS, 86_400);
        assert_eq!(DEFAULT_COOLDOWN_SECS, 24 * 60 * 60);
    }

    #[test]
    fn test_severe_cooldown_is_7_days() {
        assert_eq!(SEVERE_COOLDOWN_SECS, 604_800);
        assert_eq!(SEVERE_COOLDOWN_SECS, 7 * 24 * 60 * 60);
    }

    #[test]
    fn test_severe_greater_than_default() {
        assert!(SEVERE_COOLDOWN_SECS > DEFAULT_COOLDOWN_SECS);
    }

    // ──────────────────────────────────────────────────────────────────────
    // CooldownPeriod TRAIT TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_cooldown_period_clone() {
        let cp = CooldownPeriod {
            start_timestamp: 1000,
            duration_secs: 86_400,
            reason: "test".to_string(),
        };
        let cloned = cp.clone();
        assert_eq!(cp, cloned);
    }

    #[test]
    fn test_cooldown_period_debug() {
        let cp = CooldownPeriod {
            start_timestamp: 1000,
            duration_secs: 86_400,
            reason: "minor violation".to_string(),
        };
        let debug = format!("{:?}", cp);
        assert!(debug.contains("CooldownPeriod"));
        assert!(debug.contains("1000"));
        assert!(debug.contains("86400"));
        assert!(debug.contains("minor violation"));
    }

    #[test]
    fn test_cooldown_period_eq() {
        let a = CooldownPeriod {
            start_timestamp: 1000,
            duration_secs: 100,
            reason: "r".to_string(),
        };
        let b = CooldownPeriod {
            start_timestamp: 1000,
            duration_secs: 100,
            reason: "r".to_string(),
        };
        assert_eq!(a, b);
    }

    #[test]
    fn test_cooldown_period_ne_timestamp() {
        let a = CooldownPeriod {
            start_timestamp: 1000,
            duration_secs: 100,
            reason: "r".to_string(),
        };
        let b = CooldownPeriod {
            start_timestamp: 2000,
            duration_secs: 100,
            reason: "r".to_string(),
        };
        assert_ne!(a, b);
    }

    #[test]
    fn test_cooldown_period_ne_duration() {
        let a = CooldownPeriod {
            start_timestamp: 1000,
            duration_secs: 100,
            reason: "r".to_string(),
        };
        let b = CooldownPeriod {
            start_timestamp: 1000,
            duration_secs: 200,
            reason: "r".to_string(),
        };
        assert_ne!(a, b);
    }

    #[test]
    fn test_cooldown_period_ne_reason() {
        let a = CooldownPeriod {
            start_timestamp: 1000,
            duration_secs: 100,
            reason: "reason A".to_string(),
        };
        let b = CooldownPeriod {
            start_timestamp: 1000,
            duration_secs: 100,
            reason: "reason B".to_string(),
        };
        assert_ne!(a, b);
    }

    #[test]
    fn test_cooldown_period_serde_roundtrip() {
        let cp = CooldownPeriod {
            start_timestamp: 1_700_000_000,
            duration_secs: 604_800,
            reason: "severe slashing".to_string(),
        };
        let json = serde_json::to_string(&cp).expect("serialize");
        let back: CooldownPeriod = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cp, back);
    }

    #[test]
    fn test_cooldown_period_serde_preserves_fields() {
        let cp = CooldownPeriod {
            start_timestamp: 42,
            duration_secs: 99,
            reason: "test reason".to_string(),
        };
        let json = serde_json::to_string(&cp).expect("serialize");
        let back: CooldownPeriod = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.start_timestamp, 42);
        assert_eq!(back.duration_secs, 99);
        assert_eq!(back.reason, "test reason");
    }

    // ──────────────────────────────────────────────────────────────────────
    // expires_at() TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_expires_at_normal() {
        let cp = CooldownPeriod {
            start_timestamp: 1000,
            duration_secs: 500,
            reason: "test".to_string(),
        };
        assert_eq!(cp.expires_at(), 1500);
    }

    #[test]
    fn test_expires_at_zero_duration() {
        let cp = CooldownPeriod {
            start_timestamp: 1000,
            duration_secs: 0,
            reason: "test".to_string(),
        };
        assert_eq!(cp.expires_at(), 1000);
    }

    #[test]
    fn test_expires_at_zero_start() {
        let cp = CooldownPeriod {
            start_timestamp: 0,
            duration_secs: 86_400,
            reason: "test".to_string(),
        };
        assert_eq!(cp.expires_at(), 86_400);
    }

    #[test]
    fn test_expires_at_saturates_on_overflow() {
        let cp = CooldownPeriod {
            start_timestamp: u64::MAX,
            duration_secs: 1,
            reason: "overflow test".to_string(),
        };
        assert_eq!(cp.expires_at(), u64::MAX);
    }

    #[test]
    fn test_expires_at_saturates_both_max() {
        let cp = CooldownPeriod {
            start_timestamp: u64::MAX,
            duration_secs: u64::MAX,
            reason: "overflow test".to_string(),
        };
        assert_eq!(cp.expires_at(), u64::MAX);
    }

    #[test]
    fn test_expires_at_near_overflow_boundary() {
        let cp = CooldownPeriod {
            start_timestamp: u64::MAX - 10,
            duration_secs: 10,
            reason: "boundary".to_string(),
        };
        // u64::MAX - 10 + 10 = u64::MAX, no overflow
        assert_eq!(cp.expires_at(), u64::MAX);
    }

    #[test]
    fn test_expires_at_just_below_overflow() {
        let cp = CooldownPeriod {
            start_timestamp: u64::MAX - 100,
            duration_secs: 99,
            reason: "boundary".to_string(),
        };
        // u64::MAX - 100 + 99 = u64::MAX - 1
        assert_eq!(cp.expires_at(), u64::MAX - 1);
    }

    #[test]
    fn test_expires_at_just_over_overflow() {
        let cp = CooldownPeriod {
            start_timestamp: u64::MAX - 100,
            duration_secs: 101,
            reason: "boundary".to_string(),
        };
        // Would be u64::MAX + 1 → saturates to u64::MAX
        assert_eq!(cp.expires_at(), u64::MAX);
    }

    // ──────────────────────────────────────────────────────────────────────
    // is_active() TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_is_active_before_start() {
        let cp = CooldownPeriod {
            start_timestamp: 1000,
            duration_secs: 500,
            reason: "test".to_string(),
        };
        // current < start → true (conservative)
        assert!(cp.is_active(999));
        assert!(cp.is_active(0));
    }

    #[test]
    fn test_is_active_at_start() {
        let cp = CooldownPeriod {
            start_timestamp: 1000,
            duration_secs: 500,
            reason: "test".to_string(),
        };
        // current == start, still within cooldown
        assert!(cp.is_active(1000));
    }

    #[test]
    fn test_is_active_during_cooldown() {
        let cp = CooldownPeriod {
            start_timestamp: 1000,
            duration_secs: 500,
            reason: "test".to_string(),
        };
        assert!(cp.is_active(1001));
        assert!(cp.is_active(1250));
        assert!(cp.is_active(1499));
    }

    #[test]
    fn test_is_active_at_expiry() {
        let cp = CooldownPeriod {
            start_timestamp: 1000,
            duration_secs: 500,
            reason: "test".to_string(),
        };
        // expires_at = 1500, current == 1500 → NOT active (expired)
        assert!(!cp.is_active(1500));
    }

    #[test]
    fn test_is_active_after_expiry() {
        let cp = CooldownPeriod {
            start_timestamp: 1000,
            duration_secs: 500,
            reason: "test".to_string(),
        };
        assert!(!cp.is_active(1501));
        assert!(!cp.is_active(2000));
        assert!(!cp.is_active(u64::MAX));
    }

    #[test]
    fn test_is_active_zero_duration() {
        let cp = CooldownPeriod {
            start_timestamp: 1000,
            duration_secs: 0,
            reason: "instant".to_string(),
        };
        // expires_at = 1000, so at timestamp 1000: 1000 < 1000 is false → not active
        assert!(cp.is_active(999)); // before start → active
        assert!(!cp.is_active(1000)); // at start = at expiry → not active
        assert!(!cp.is_active(1001));
    }

    #[test]
    fn test_is_active_overflow_saturated() {
        let cp = CooldownPeriod {
            start_timestamp: u64::MAX - 10,
            duration_secs: 100, // would overflow → saturates to u64::MAX
            reason: "overflow".to_string(),
        };
        assert_eq!(cp.expires_at(), u64::MAX);
        // Any timestamp < u64::MAX is still active
        assert!(cp.is_active(0));
        assert!(cp.is_active(u64::MAX - 11));
        assert!(cp.is_active(u64::MAX - 1));
        // u64::MAX == u64::MAX → NOT active (not less than)
        assert!(!cp.is_active(u64::MAX));
    }

    #[test]
    fn test_is_active_deterministic() {
        let cp = CooldownPeriod {
            start_timestamp: 1000,
            duration_secs: 500,
            reason: "test".to_string(),
        };
        let r1 = cp.is_active(1200);
        let r2 = cp.is_active(1200);
        let r3 = cp.is_active(1200);
        assert_eq!(r1, r2);
        assert_eq!(r2, r3);
    }

    // ──────────────────────────────────────────────────────────────────────
    // remaining_secs() TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_remaining_before_start() {
        let cp = CooldownPeriod {
            start_timestamp: 1000,
            duration_secs: 500,
            reason: "test".to_string(),
        };
        // expires_at = 1500, current = 500 → remaining = 1500 - 500 = 1000
        assert_eq!(cp.remaining_secs(500), 1000);
    }

    #[test]
    fn test_remaining_at_start() {
        let cp = CooldownPeriod {
            start_timestamp: 1000,
            duration_secs: 500,
            reason: "test".to_string(),
        };
        // expires_at = 1500, current = 1000 → remaining = 500
        assert_eq!(cp.remaining_secs(1000), 500);
    }

    #[test]
    fn test_remaining_during_cooldown() {
        let cp = CooldownPeriod {
            start_timestamp: 1000,
            duration_secs: 500,
            reason: "test".to_string(),
        };
        assert_eq!(cp.remaining_secs(1250), 250);
        assert_eq!(cp.remaining_secs(1499), 1);
    }

    #[test]
    fn test_remaining_at_expiry() {
        let cp = CooldownPeriod {
            start_timestamp: 1000,
            duration_secs: 500,
            reason: "test".to_string(),
        };
        assert_eq!(cp.remaining_secs(1500), 0);
    }

    #[test]
    fn test_remaining_after_expiry() {
        let cp = CooldownPeriod {
            start_timestamp: 1000,
            duration_secs: 500,
            reason: "test".to_string(),
        };
        assert_eq!(cp.remaining_secs(1501), 0);
        assert_eq!(cp.remaining_secs(2000), 0);
        assert_eq!(cp.remaining_secs(u64::MAX), 0);
    }

    #[test]
    fn test_remaining_zero_duration() {
        let cp = CooldownPeriod {
            start_timestamp: 1000,
            duration_secs: 0,
            reason: "instant".to_string(),
        };
        assert_eq!(cp.remaining_secs(999), 1); // expires_at(1000) - 999 = 1
        assert_eq!(cp.remaining_secs(1000), 0); // at expiry
        assert_eq!(cp.remaining_secs(1001), 0);
    }

    #[test]
    fn test_remaining_overflow_saturated() {
        let cp = CooldownPeriod {
            start_timestamp: u64::MAX - 10,
            duration_secs: 100,
            reason: "overflow".to_string(),
        };
        assert_eq!(cp.expires_at(), u64::MAX);
        // remaining = u64::MAX - 0 = u64::MAX
        assert_eq!(cp.remaining_secs(0), u64::MAX);
        // remaining = u64::MAX - (u64::MAX - 1) = 1
        assert_eq!(cp.remaining_secs(u64::MAX - 1), 1);
        // remaining = u64::MAX - u64::MAX = 0 (expired)
        assert_eq!(cp.remaining_secs(u64::MAX), 0);
    }

    #[test]
    fn test_remaining_deterministic() {
        let cp = CooldownPeriod {
            start_timestamp: 1000,
            duration_secs: 500,
            reason: "test".to_string(),
        };
        let r1 = cp.remaining_secs(1200);
        let r2 = cp.remaining_secs(1200);
        assert_eq!(r1, r2);
    }

    // ──────────────────────────────────────────────────────────────────────
    // is_active() ↔ remaining_secs() CONSISTENCY
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_active_iff_remaining_nonzero() {
        let cp = CooldownPeriod {
            start_timestamp: 1000,
            duration_secs: 500,
            reason: "test".to_string(),
        };

        let timestamps = [0, 500, 999, 1000, 1001, 1250, 1499, 1500, 1501, 2000];

        for &ts in &timestamps {
            let active = cp.is_active(ts);
            let remaining = cp.remaining_secs(ts);

            assert_eq!(
                active,
                remaining > 0,
                "at timestamp {}: is_active={} but remaining={}",
                ts,
                active,
                remaining
            );
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // CooldownConfig TRAIT TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_cooldown_config_default_values() {
        let cfg = CooldownConfig::default();
        assert_eq!(cfg.default_cooldown_secs, 86_400);
        assert_eq!(cfg.severe_cooldown_secs, 604_800);
    }

    #[test]
    fn test_cooldown_config_clone() {
        let cfg = CooldownConfig::default();
        let cloned = cfg.clone();
        assert_eq!(cfg, cloned);
    }

    #[test]
    fn test_cooldown_config_debug() {
        let cfg = CooldownConfig::default();
        let debug = format!("{:?}", cfg);
        assert!(debug.contains("CooldownConfig"));
        assert!(debug.contains("86400"));
        assert!(debug.contains("604800"));
    }

    #[test]
    fn test_cooldown_config_eq() {
        let a = CooldownConfig::default();
        let b = CooldownConfig::default();
        assert_eq!(a, b);
    }

    #[test]
    fn test_cooldown_config_ne() {
        let a = CooldownConfig::default();
        let b = CooldownConfig {
            default_cooldown_secs: 999,
            severe_cooldown_secs: 9999,
        };
        assert_ne!(a, b);
    }

    #[test]
    fn test_cooldown_config_serde_roundtrip() {
        let cfg = CooldownConfig::default();
        let json = serde_json::to_string(&cfg).expect("serialize");
        let back: CooldownConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cfg, back);
    }

    // ──────────────────────────────────────────────────────────────────────
    // create_cooldown() TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_create_cooldown_default() {
        let cfg = CooldownConfig::default();
        let cp = cfg.create_cooldown(false, 1_700_000_000, "stake drop".to_string());
        assert_eq!(cp.start_timestamp, 1_700_000_000);
        assert_eq!(cp.duration_secs, 86_400);
        assert_eq!(cp.reason, "stake drop");
    }

    #[test]
    fn test_create_cooldown_severe() {
        let cfg = CooldownConfig::default();
        let cp = cfg.create_cooldown(true, 1_700_000_000, "identity spoofing".to_string());
        assert_eq!(cp.start_timestamp, 1_700_000_000);
        assert_eq!(cp.duration_secs, 604_800);
        assert_eq!(cp.reason, "identity spoofing");
    }

    #[test]
    fn test_create_cooldown_preserves_timestamp() {
        let cfg = CooldownConfig::default();
        let cp = cfg.create_cooldown(false, 42, "test".to_string());
        assert_eq!(cp.start_timestamp, 42);
    }

    #[test]
    fn test_create_cooldown_preserves_reason() {
        let cfg = CooldownConfig::default();
        let reason = "   whitespace  reason  with  spaces   ".to_string();
        let cp = cfg.create_cooldown(false, 0, reason.clone());
        assert_eq!(cp.reason, reason);
    }

    #[test]
    fn test_create_cooldown_empty_reason() {
        let cfg = CooldownConfig::default();
        let cp = cfg.create_cooldown(false, 0, String::new());
        assert_eq!(cp.reason, "");
    }

    #[test]
    fn test_create_cooldown_custom_config() {
        let cfg = CooldownConfig {
            default_cooldown_secs: 100,
            severe_cooldown_secs: 1000,
        };
        let default = cfg.create_cooldown(false, 0, "d".to_string());
        let severe = cfg.create_cooldown(true, 0, "s".to_string());
        assert_eq!(default.duration_secs, 100);
        assert_eq!(severe.duration_secs, 1000);
    }

    #[test]
    fn test_create_cooldown_zero_timestamp() {
        let cfg = CooldownConfig::default();
        let cp = cfg.create_cooldown(false, 0, "zero".to_string());
        assert_eq!(cp.start_timestamp, 0);
        assert_eq!(cp.expires_at(), 86_400);
    }

    #[test]
    fn test_create_cooldown_max_timestamp() {
        let cfg = CooldownConfig::default();
        let cp = cfg.create_cooldown(false, u64::MAX, "max".to_string());
        assert_eq!(cp.start_timestamp, u64::MAX);
        // expires_at saturates
        assert_eq!(cp.expires_at(), u64::MAX);
    }

    // ──────────────────────────────────────────────────────────────────────
    // CooldownStatus TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_cooldown_status_no_cooldown() {
        let status = CooldownStatus::NoCooldown;
        assert_eq!(status, CooldownStatus::NoCooldown);
    }

    #[test]
    fn test_cooldown_status_in_cooldown() {
        let cp = CooldownPeriod {
            start_timestamp: 1000,
            duration_secs: 500,
            reason: "test".to_string(),
        };
        let status = CooldownStatus::InCooldown(cp.clone());
        assert_eq!(status, CooldownStatus::InCooldown(cp));
    }

    #[test]
    fn test_cooldown_status_expired() {
        let cp = CooldownPeriod {
            start_timestamp: 1000,
            duration_secs: 500,
            reason: "test".to_string(),
        };
        let status = CooldownStatus::Expired(cp.clone());
        assert_eq!(status, CooldownStatus::Expired(cp));
    }

    #[test]
    fn test_cooldown_status_clone() {
        let cp = CooldownPeriod {
            start_timestamp: 1000,
            duration_secs: 500,
            reason: "test".to_string(),
        };
        let status = CooldownStatus::InCooldown(cp);
        let cloned = status.clone();
        assert_eq!(status, cloned);
    }

    #[test]
    fn test_cooldown_status_debug() {
        let status = CooldownStatus::NoCooldown;
        let debug = format!("{:?}", status);
        assert!(debug.contains("NoCooldown"));
    }

    #[test]
    fn test_cooldown_status_ne() {
        let cp = CooldownPeriod {
            start_timestamp: 1000,
            duration_secs: 500,
            reason: "test".to_string(),
        };
        assert_ne!(
            CooldownStatus::NoCooldown,
            CooldownStatus::InCooldown(cp.clone())
        );
        assert_ne!(
            CooldownStatus::InCooldown(cp.clone()),
            CooldownStatus::Expired(cp)
        );
    }

    #[test]
    fn test_cooldown_status_serde_roundtrip_no_cooldown() {
        let status = CooldownStatus::NoCooldown;
        let json = serde_json::to_string(&status).expect("serialize");
        let back: CooldownStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(status, back);
    }

    #[test]
    fn test_cooldown_status_serde_roundtrip_in_cooldown() {
        let cp = CooldownPeriod {
            start_timestamp: 1000,
            duration_secs: 500,
            reason: "test".to_string(),
        };
        let status = CooldownStatus::InCooldown(cp);
        let json = serde_json::to_string(&status).expect("serialize");
        let back: CooldownStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(status, back);
    }

    #[test]
    fn test_cooldown_status_serde_roundtrip_expired() {
        let cp = CooldownPeriod {
            start_timestamp: 1000,
            duration_secs: 500,
            reason: "expired test".to_string(),
        };
        let status = CooldownStatus::Expired(cp);
        let json = serde_json::to_string(&status).expect("serialize");
        let back: CooldownStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(status, back);
    }

    // ──────────────────────────────────────────────────────────────────────
    // SEND + SYNC TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CooldownPeriod>();
        assert_send_sync::<CooldownConfig>();
        assert_send_sync::<CooldownStatus>();
    }

    // ──────────────────────────────────────────────────────────────────────
    // COMPREHENSIVE BOUNDARY SWEEP
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_is_active_boundary_sweep() {
        let cp = CooldownPeriod {
            start_timestamp: 1000,
            duration_secs: 86_400,
            reason: "sweep".to_string(),
        };

        let cases: &[(u64, bool)] = &[
            (0, true),           // before start
            (999, true),         // just before start
            (1000, true),        // at start
            (1001, true),        // just after start
            (44_200, true),      // midway
            (87_399, true),      // one before expiry
            (87_400, false),     // at expiry (1000 + 86400)
            (87_401, false),     // one after expiry
            (u64::MAX, false),   // far future
        ];

        for &(ts, expected) in cases {
            assert_eq!(
                cp.is_active(ts),
                expected,
                "is_active({}) should be {}",
                ts,
                expected
            );
        }
    }

    #[test]
    fn test_remaining_secs_boundary_sweep() {
        let cp = CooldownPeriod {
            start_timestamp: 1000,
            duration_secs: 86_400,
            reason: "sweep".to_string(),
        };

        let cases: &[(u64, u64)] = &[
            (0, 87_400),         // before start: 1000+86400-0 = 87400
            (999, 86_401),       // just before start
            (1000, 86_400),      // at start
            (1001, 86_399),      // just after start
            (87_399, 1),         // one before expiry
            (87_400, 0),         // at expiry
            (87_401, 0),         // after expiry
            (u64::MAX, 0),       // far future
        ];

        for &(ts, expected) in cases {
            assert_eq!(
                cp.remaining_secs(ts),
                expected,
                "remaining_secs({}) should be {}",
                ts,
                expected
            );
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // REALISTIC SCENARIO TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_realistic_default_cooldown_lifecycle() {
        let cfg = CooldownConfig::default();
        let ban_time = 1_700_000_000_u64; // ~Nov 2023

        let cp = cfg.create_cooldown(false, ban_time, "stake drop".to_string());

        // Right after ban
        assert!(cp.is_active(ban_time));
        assert_eq!(cp.remaining_secs(ban_time), 86_400);

        // 12 hours later
        assert!(cp.is_active(ban_time + 43_200));
        assert_eq!(cp.remaining_secs(ban_time + 43_200), 43_200);

        // 24 hours later (exactly at expiry)
        assert!(!cp.is_active(ban_time + 86_400));
        assert_eq!(cp.remaining_secs(ban_time + 86_400), 0);

        // 25 hours later
        assert!(!cp.is_active(ban_time + 90_000));
        assert_eq!(cp.remaining_secs(ban_time + 90_000), 0);
    }

    #[test]
    fn test_realistic_severe_cooldown_lifecycle() {
        let cfg = CooldownConfig::default();
        let ban_time = 1_700_000_000_u64;

        let cp = cfg.create_cooldown(true, ban_time, "identity spoofing".to_string());

        // Right after ban
        assert!(cp.is_active(ban_time));
        assert_eq!(cp.remaining_secs(ban_time), 604_800);

        // 3.5 days later
        let halfway = ban_time + 302_400;
        assert!(cp.is_active(halfway));
        assert_eq!(cp.remaining_secs(halfway), 302_400);

        // 7 days later (exactly at expiry)
        assert!(!cp.is_active(ban_time + 604_800));
        assert_eq!(cp.remaining_secs(ban_time + 604_800), 0);
    }
}