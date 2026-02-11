//! # Slashing Cooldown Verifier (14B.24)
//!
//! Deterministic verifier that checks whether a node is currently
//! in an active slashing cooldown period.
//!
//! ## Design
//!
//! `CooldownVerifier` holds a single `current_timestamp: u64` field.
//! It does NOT access system clocks — the timestamp is provided at
//! construction. All logic delegates to [`CooldownPeriod::is_active`]
//! and [`CooldownPeriod::remaining_secs`] from `dsdn_common`.
//!
//! ## Verification Logic
//!
//! ### `verify`
//!
//! 1. `None` → no cooldown → pass
//! 2. `Some(period)` where `!period.is_active(ts)` → expired → pass
//! 3. `Some(period)` where `period.is_active(ts)` → active → error
//!
//! ### `verify_from_record`
//!
//! Extracts `record.cooldown.as_ref()` and delegates to `verify()`.
//! No re-implementation of cooldown logic.
//!
//! ## Properties
//!
//! - **Deterministic**: Same inputs always produce the same output.
//! - **No panic**: No `unwrap()`, `expect()`, or index access.
//! - **No system clock**: Timestamp is an explicit field, set at construction.
//! - **No logic duplication**: All cooldown semantics come from `CooldownPeriod`.

use dsdn_common::gating::{
    CheckResult,
    CooldownPeriod,
    GatingError,
};
use dsdn_chain::gating::ServiceNodeRecord;

// ════════════════════════════════════════════════════════════════════════════
// COOLDOWN VERIFIER
// ════════════════════════════════════════════════════════════════════════════

/// Deterministic verifier for slashing cooldown periods.
///
/// `CooldownVerifier` holds a `current_timestamp` used to evaluate
/// whether a cooldown is still active. It does NOT access system
/// clocks — the timestamp is provided at construction.
///
/// ## Usage
///
/// ```rust,ignore
/// use dsdn_validator::gating::CooldownVerifier;
///
/// let verifier = CooldownVerifier::new(1_700_000_000);
///
/// // No cooldown → passes
/// let result = verifier.verify(None);
/// assert!(result.unwrap().passed);
///
/// // Expired cooldown → passes
/// // Active cooldown → GatingError::SlashingCooldownActive
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CooldownVerifier {
    /// Unix timestamp (seconds) for cooldown evaluation.
    /// Provided at construction, never derived from system clock.
    current_timestamp: u64,
}

impl CooldownVerifier {
    /// Creates a new `CooldownVerifier` with the given timestamp.
    ///
    /// The timestamp is stored immutably and used for all subsequent
    /// verification calls. It is NEVER derived from the system clock.
    #[must_use]
    #[inline]
    pub fn new(current_timestamp: u64) -> Self {
        Self { current_timestamp }
    }

    /// Returns the timestamp used by this verifier.
    #[must_use]
    #[inline]
    pub fn current_timestamp(&self) -> u64 {
        self.current_timestamp
    }

    /// Verify whether a node is free from active cooldown.
    ///
    /// ## Execution Order (STRICT — DO NOT REORDER)
    ///
    /// **CASE 1**: `cooldown == None`
    /// → No cooldown exists → pass.
    /// → `Ok(CheckResult { check_name: "cooldown_check", passed: true, detail: "no cooldown" })`
    ///
    /// **CASE 2**: `Some(period)` AND `!period.is_active(self.current_timestamp)`
    /// → Cooldown has expired → pass.
    /// → `Ok(CheckResult { check_name: "cooldown_check", passed: true, detail: "expired" })`
    ///
    /// **CASE 3**: `Some(period)` AND `period.is_active(self.current_timestamp)`
    /// → Cooldown is still active → error.
    /// → `Err(GatingError::SlashingCooldownActive { remaining_secs, reason })`
    ///
    /// ## Properties
    ///
    /// - Deterministic for same `(cooldown, current_timestamp)`.
    /// - Delegates all cooldown semantics to `CooldownPeriod::is_active`.
    /// - No panic, no unwrap, no side effects.
    pub fn verify(
        &self,
        cooldown: Option<&CooldownPeriod>,
    ) -> Result<CheckResult, GatingError> {
        match cooldown {
            // CASE 1: No cooldown → pass
            None => Ok(CheckResult {
                check_name: "cooldown_check".to_string(),
                passed: true,
                detail: Some(
                    "no active cooldown: node has no cooldown period".to_string(),
                ),
            }),

            Some(period) => {
                if period.is_active(self.current_timestamp) {
                    // CASE 3: Active cooldown → error
                    Err(GatingError::SlashingCooldownActive {
                        remaining_secs: period.remaining_secs(self.current_timestamp),
                        reason: period.reason.clone(),
                    })
                } else {
                    // CASE 2: Expired cooldown → pass
                    Ok(CheckResult {
                        check_name: "cooldown_check".to_string(),
                        passed: true,
                        detail: Some(format!(
                            "cooldown expired: started at {}, duration {} secs, expired at {}, current timestamp {}",
                            period.start_timestamp,
                            period.duration_secs,
                            period.expires_at(),
                            self.current_timestamp,
                        )),
                    })
                }
            }
        }
    }

    /// Verify cooldown status from a service node record.
    ///
    /// Extracts `record.cooldown.as_ref()` and delegates to [`verify()`].
    /// Does NOT re-implement any cooldown logic.
    ///
    /// ## Arguments
    ///
    /// * `record` — The on-chain service node record.
    pub fn verify_from_record(
        &self,
        record: &ServiceNodeRecord,
    ) -> Result<CheckResult, GatingError> {
        self.verify(record.cooldown.as_ref())
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

    fn active_cooldown() -> CooldownPeriod {
        CooldownPeriod {
            start_timestamp: 1000,
            duration_secs: 500,
            reason: "test violation".to_string(),
        }
        // expires_at = 1500
    }

    fn expired_cooldown() -> CooldownPeriod {
        CooldownPeriod {
            start_timestamp: 1000,
            duration_secs: 100,
            reason: "old violation".to_string(),
        }
        // expires_at = 1100
    }

    fn make_record(cooldown: Option<CooldownPeriod>) -> ServiceNodeRecord {
        use std::collections::HashMap;
        use dsdn_chain::types::Address;
        ServiceNodeRecord {
            operator_address: Address([0x01; 20]),
            node_id: [0x02; 32],
            class: dsdn_common::gating::NodeClass::Storage,
            status: dsdn_common::gating::NodeStatus::Active,
            staked_amount: 5_000_000_000_000_000_000_000,
            registered_height: 100,
            last_status_change_height: 100,
            cooldown,
            tls_fingerprint: None,
            metadata: HashMap::new(),
        }
    }

    // ════════════════════════════════════════════════════════════
    // verify — CASE 1: NO COOLDOWN
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_none_passes() {
        let v = CooldownVerifier::new(1200);
        let result = v.verify(None);
        assert!(result.is_ok());
        let cr = result.unwrap();
        assert_eq!(cr.check_name, "cooldown_check");
        assert!(cr.passed);
        assert!(cr.detail.is_some());
        assert!(cr.detail.unwrap().contains("no"));
    }

    #[test]
    fn test_verify_none_any_timestamp() {
        // None always passes regardless of timestamp
        for ts in [0, 1, 1000, u64::MAX] {
            let v = CooldownVerifier::new(ts);
            let result = v.verify(None);
            assert!(result.is_ok(), "None should pass at timestamp {}", ts);
            assert!(result.unwrap().passed);
        }
    }

    // ════════════════════════════════════════════════════════════
    // verify — CASE 2: EXPIRED COOLDOWN
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_expired_cooldown_passes() {
        let cd = expired_cooldown(); // expires_at = 1100
        let v = CooldownVerifier::new(1200); // past expiry
        let result = v.verify(Some(&cd));
        assert!(result.is_ok());
        let cr = result.unwrap();
        assert_eq!(cr.check_name, "cooldown_check");
        assert!(cr.passed);
        let detail = cr.detail.unwrap();
        assert!(detail.contains("expired"));
        assert!(detail.contains("1000")); // start_timestamp
        assert!(detail.contains("1100")); // expires_at
    }

    #[test]
    fn test_verify_expired_at_exact_boundary() {
        // CooldownPeriod::is_active returns false when ts >= expires_at
        // is_active: current_timestamp < expires_at() → true
        // So at exactly expires_at (1500), is_active returns false → pass
        let cd = active_cooldown(); // expires_at = 1500
        let v = CooldownVerifier::new(1500);
        let result = v.verify(Some(&cd));
        assert!(result.is_ok(), "at exact expiry boundary should pass");
        assert!(result.unwrap().passed);
    }

    // ════════════════════════════════════════════════════════════
    // verify — CASE 3: ACTIVE COOLDOWN
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_active_cooldown_errors() {
        let cd = active_cooldown(); // start=1000, dur=500, expires=1500
        let v = CooldownVerifier::new(1200); // within cooldown
        let result = v.verify(Some(&cd));
        assert!(result.is_err());
        match result.unwrap_err() {
            GatingError::SlashingCooldownActive {
                remaining_secs,
                reason,
            } => {
                assert_eq!(remaining_secs, 300); // 1500 - 1200
                assert_eq!(reason, "test violation");
            }
            other => panic!("expected SlashingCooldownActive, got: {:?}", other),
        }
    }

    #[test]
    fn test_verify_active_one_second_before_expiry() {
        let cd = active_cooldown(); // expires_at = 1500
        let v = CooldownVerifier::new(1499);
        let result = v.verify(Some(&cd));
        assert!(result.is_err());
        match result.unwrap_err() {
            GatingError::SlashingCooldownActive {
                remaining_secs, ..
            } => {
                assert_eq!(remaining_secs, 1); // 1500 - 1499
            }
            other => panic!("expected SlashingCooldownActive, got: {:?}", other),
        }
    }

    #[test]
    fn test_verify_active_at_start_timestamp() {
        // At start_timestamp (1000), cooldown is active
        // is_active: 1000 < 1500 → true
        let cd = active_cooldown();
        let v = CooldownVerifier::new(1000);
        let result = v.verify(Some(&cd));
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_active_before_start_conservative() {
        // Before start_timestamp → is_active returns true (conservative)
        let cd = active_cooldown(); // start = 1000
        let v = CooldownVerifier::new(500);
        let result = v.verify(Some(&cd));
        assert!(result.is_err(), "before start should be conservatively active");
    }

    // ════════════════════════════════════════════════════════════
    // verify — EDGE CASES
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_zero_duration_cooldown() {
        // duration_secs = 0 → expires_at = start_timestamp
        // At start_timestamp: is_active → current < expires_at → false (equal, not less)
        let cd = CooldownPeriod {
            start_timestamp: 1000,
            duration_secs: 0,
            reason: "zero duration".to_string(),
        };
        // At timestamp 1000: is_active(1000) → 1000 < 1000 is false → not active → pass
        let v = CooldownVerifier::new(1000);
        let result = v.verify(Some(&cd));
        assert!(result.is_ok());
        assert!(result.unwrap().passed);
    }

    #[test]
    fn test_verify_overflow_saturating() {
        // start + duration would overflow u64 → saturates to u64::MAX
        // Cooldown effectively never expires
        let cd = CooldownPeriod {
            start_timestamp: u64::MAX - 10,
            duration_secs: 100,
            reason: "overflow test".to_string(),
        };
        // expires_at = u64::MAX (saturated)
        // At u64::MAX - 5: is_active → (u64::MAX - 5) < u64::MAX → true
        let v = CooldownVerifier::new(u64::MAX - 5);
        let result = v.verify(Some(&cd));
        assert!(result.is_err(), "saturated cooldown should be active");
    }

    #[test]
    fn test_verify_at_u64_max() {
        // Cooldown with very large expiry, checked at u64::MAX
        let cd = CooldownPeriod {
            start_timestamp: u64::MAX - 10,
            duration_secs: 10,
            reason: "max test".to_string(),
        };
        // expires_at = u64::MAX
        // is_active(u64::MAX) → u64::MAX < u64::MAX is false → not active → pass
        let v = CooldownVerifier::new(u64::MAX);
        let result = v.verify(Some(&cd));
        assert!(result.is_ok());
    }

    // ════════════════════════════════════════════════════════════
    // verify — DETERMINISM
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_deterministic() {
        let cd = active_cooldown();
        let v = CooldownVerifier::new(1200);
        let r1 = v.verify(Some(&cd));
        let r2 = v.verify(Some(&cd));
        assert_eq!(r1, r2);
    }

    // ════════════════════════════════════════════════════════════
    // verify_from_record
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_from_record_no_cooldown() {
        let record = make_record(None);
        let v = CooldownVerifier::new(1200);
        let result = v.verify_from_record(&record);
        assert!(result.is_ok());
        assert!(result.unwrap().passed);
    }

    #[test]
    fn test_verify_from_record_expired() {
        let record = make_record(Some(expired_cooldown()));
        let v = CooldownVerifier::new(1200);
        let result = v.verify_from_record(&record);
        assert!(result.is_ok());
        assert!(result.unwrap().passed);
    }

    #[test]
    fn test_verify_from_record_active() {
        let record = make_record(Some(active_cooldown()));
        let v = CooldownVerifier::new(1200);
        let result = v.verify_from_record(&record);
        assert!(result.is_err());
        match result.unwrap_err() {
            GatingError::SlashingCooldownActive { .. } => {}
            other => panic!("expected SlashingCooldownActive, got: {:?}", other),
        }
    }

    #[test]
    fn test_verify_from_record_matches_verify() {
        // verify_from_record should produce identical result to verify
        let cd = active_cooldown();
        let record = make_record(Some(cd.clone()));
        let v = CooldownVerifier::new(1200);
        let r_direct = v.verify(Some(&cd));
        let r_record = v.verify_from_record(&record);
        assert_eq!(r_direct, r_record);
    }

    // ════════════════════════════════════════════════════════════
    // STRUCT PROPERTIES
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_cooldown_verifier_clone() {
        let v1 = CooldownVerifier::new(1000);
        let v2 = v1.clone();
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_cooldown_verifier_debug() {
        let v = CooldownVerifier::new(1000);
        let debug = format!("{:?}", v);
        assert!(debug.contains("CooldownVerifier"));
        assert!(debug.contains("1000"));
    }

    #[test]
    fn test_cooldown_verifier_timestamp_accessor() {
        let v = CooldownVerifier::new(42);
        assert_eq!(v.current_timestamp(), 42);
    }

    // ════════════════════════════════════════════════════════════
    // SEND + SYNC
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_cooldown_verifier_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CooldownVerifier>();
    }

    // ════════════════════════════════════════════════════════════
    // BOUNDARY SWEEP
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_boundary_sweep() {
        // Cooldown: start=1000, dur=500 → expires_at=1500
        // is_active: ts < start → true (conservative)
        //            ts < expires_at → true
        //            ts >= expires_at → false
        let cd = active_cooldown();

        let cases: &[(u64, bool)] = &[
            (0, false),       // before start → active (conservative) → error
            (500, false),     // before start → active → error
            (999, false),     // one before start → active → error
            (1000, false),    // at start → active → error
            (1200, false),    // mid cooldown → active → error
            (1499, false),    // one before expiry → active → error
            (1500, true),     // at expiry → NOT active → pass
            (1501, true),     // one after expiry → pass
            (2000, true),     // far after → pass
            (u64::MAX, true), // max → pass
        ];

        for &(ts, should_pass) in cases {
            let v = CooldownVerifier::new(ts);
            let result = v.verify(Some(&cd));
            assert_eq!(
                result.is_ok(), should_pass,
                "at timestamp {} should_pass={}, got is_ok={}",
                ts, should_pass, result.is_ok()
            );
        }
    }
}