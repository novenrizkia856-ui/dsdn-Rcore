//! # Gating Engine (14B.26)
//!
//! Orchestrator for the DSDN gating evaluation process.
//!
//! `GatingEngine` runs all gating verifiers in a fixed, consensus-critical
//! order, collects all errors (never short-circuits), and produces a
//! deterministic [`GatingDecision`].
//!
//! ## Evaluation Order (Consensus-Critical, Fixed)
//!
//! 1. Stake check ([`StakeVerifier`])
//! 2. Class check ([`ClassVerifier`])
//! 3. Identity proof check ([`IdentityVerifier`]) — skipped if
//!    `policy.require_identity_proof == false`
//! 4. TLS check ([`TLSVerifier`]) — skipped if `policy.require_tls == false`
//! 5. Cooldown check ([`CooldownVerifier`])
//!
//! ## Error Collection
//!
//! All applicable checks are always run — the engine never stops at the
//! first error. Errors are collected in a `Vec<GatingError>` in evaluation
//! order. The final decision is:
//!
//! - No errors → [`GatingDecision::Approved`]
//! - One or more errors → [`GatingDecision::Rejected`] with all errors
//!
//! ## Skip Logic
//!
//! - **Identity proof**: Skipped without error if
//!   `policy.require_identity_proof == false`. If required and
//!   `proof == None`, an explicit
//!   [`GatingError::IdentityVerificationFailed`] is produced.
//! - **TLS**: Skipped without error if `policy.require_tls == false`.
//!   If required and `tls == None`, an explicit
//!   [`GatingError::TLSInvalid(MissingCert)`] is produced.
//!
//! ## Properties
//!
//! - **Deterministic**: Same inputs always produce the same `GatingDecision`.
//! - **Stateless**: No mutable state between evaluations, no I/O.
//! - **Pure**: No system clock, no randomness, no side effects.
//! - **Safe**: No panic, no unwrap, no silent failure.

use dsdn_common::gating::{
    CooldownPeriod,
    GatingDecision,
    GatingError,
    GatingPolicy,
    IdentityProof,
    NodeClass,
    NodeIdentity,
    TLSCertInfo,
    TLSValidationError,
};

use super::stake_verifier::StakeVerifier;
use super::class_verifier::ClassVerifier;
use super::identity_verifier::{IdentityVerifier, DEFAULT_MAX_AGE_SECS};
use super::tls_verifier::TLSVerifier;
use super::cooldown_verifier::CooldownVerifier;

// ════════════════════════════════════════════════════════════════════════════════
// GATING ENGINE
// ════════════════════════════════════════════════════════════════════════════════

/// Orchestrator for the gating evaluation process.
///
/// `GatingEngine` holds a [`GatingPolicy`] and a caller-provided timestamp.
/// It runs all verifiers in a fixed, consensus-critical order, collects
/// all errors, and produces a deterministic [`GatingDecision`].
///
/// ## Invariants
///
/// - `policy` is immutable during evaluation.
/// - `timestamp` is never derived from the system clock.
/// - No state is carried between [`evaluate()`](GatingEngine::evaluate) calls.
/// - The engine does not store intermediate results.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatingEngine {
    /// The gating policy configuration. Immutable during evaluation.
    policy: GatingPolicy,
    /// Unix timestamp (seconds) for time-dependent checks.
    /// Caller-provided, never derived from system clock.
    timestamp: u64,
}

impl GatingEngine {
    /// Creates a new `GatingEngine` with the given policy and timestamp.
    ///
    /// The policy is stored immutably and used for all subsequent
    /// `evaluate()` calls. The timestamp is used by time-dependent
    /// verifiers (TLS, cooldown, identity proof freshness).
    ///
    /// No validation is performed on the policy — call
    /// [`GatingPolicy::validate()`] before constructing the engine
    /// if policy validation is required.
    #[must_use]
    #[inline]
    pub fn new(policy: GatingPolicy, timestamp: u64) -> Self {
        Self { policy, timestamp }
    }

    /// Returns a reference to the policy used by this engine.
    #[must_use]
    #[inline]
    pub fn policy(&self) -> &GatingPolicy {
        &self.policy
    }

    /// Returns the timestamp used by this engine.
    #[must_use]
    #[inline]
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Evaluate a node against all gating checks.
    ///
    /// ## Execution Order (CONSENSUS-CRITICAL — DO NOT REORDER)
    ///
    /// 1. Stake check ([`StakeVerifier`])
    /// 2. Class check ([`ClassVerifier`])
    /// 3. Identity proof check ([`IdentityVerifier`])
    ///    — skipped if `policy.require_identity_proof == false`
    /// 4. TLS check ([`TLSVerifier`])
    ///    — skipped if `policy.require_tls == false`
    /// 5. Cooldown check ([`CooldownVerifier`])
    ///
    /// ## Error Collection
    ///
    /// All applicable checks are always run (no short-circuit on first
    /// error). Errors (`GatingError`) from each verifier's `Err` result
    /// are collected in evaluation order into a `Vec<GatingError>`.
    ///
    /// ## Skip Logic
    ///
    /// - **Identity proof**: If `policy.require_identity_proof == true`
    ///   and `proof == None`, produces
    ///   `GatingError::IdentityVerificationFailed`. If
    ///   `require_identity_proof == false`, the check is skipped entirely
    ///   without producing any error.
    /// - **TLS**: If `policy.require_tls == true` and `tls == None`,
    ///   produces `GatingError::TLSInvalid(MissingCert)`. If
    ///   `require_tls == false`, the check is skipped entirely without
    ///   producing any error.
    ///
    /// ## Decision
    ///
    /// - No errors → [`GatingDecision::Approved`]
    /// - One or more errors → [`GatingDecision::Rejected(errors)`]
    ///
    /// ## Properties
    ///
    /// - Deterministic: same inputs → same `GatingDecision` (bitwise-equal).
    /// - Error vector order matches evaluation order.
    /// - No panic, no unwrap, no side effects.
    pub fn evaluate(
        &self,
        identity: &NodeIdentity,
        class: &NodeClass,
        stake: u128,
        cooldown: Option<&CooldownPeriod>,
        tls: Option<&TLSCertInfo>,
        proof: Option<&IdentityProof>,
    ) -> GatingDecision {
        let mut errors: Vec<GatingError> = Vec::new();

        // ════════════════════════════════════════════════════════════
        // CHECK 1: Stake (StakeVerifier)
        // ════════════════════════════════════════════════════════════
        let stake_verifier = StakeVerifier::new(self.policy.stake_requirement.clone());
        if let Err(e) = stake_verifier.verify(class, stake) {
            errors.push(e);
        }

        // ════════════════════════════════════════════════════════════
        // CHECK 2: Class (ClassVerifier)
        // ════════════════════════════════════════════════════════════
        let class_verifier = ClassVerifier::new(self.policy.stake_requirement.clone());
        if let Err(e) = class_verifier.verify(class, stake) {
            errors.push(e);
        }

        // ════════════════════════════════════════════════════════════
        // CHECK 3: Identity Proof (IdentityVerifier)
        // SKIP if policy.require_identity_proof == false
        // ════════════════════════════════════════════════════════════
        if self.policy.require_identity_proof {
            match proof {
                None => {
                    errors.push(GatingError::IdentityVerificationFailed(
                        "identity proof required by policy but not provided".to_string(),
                    ));
                }
                Some(p) => {
                    if let Err(e) = IdentityVerifier::verify_proof(
                        p,
                        self.timestamp,
                        DEFAULT_MAX_AGE_SECS,
                    ) {
                        errors.push(e);
                    }
                }
            }
        }

        // ════════════════════════════════════════════════════════════
        // CHECK 4: TLS (TLSVerifier)
        // SKIP if policy.require_tls == false
        // ════════════════════════════════════════════════════════════
        if self.policy.require_tls {
            match tls {
                None => {
                    errors.push(GatingError::TLSInvalid(TLSValidationError::MissingCert));
                }
                Some(tls_info) => {
                    let tls_verifier = TLSVerifier::new(self.timestamp);
                    if let Err(e) = tls_verifier.verify(tls_info, identity) {
                        errors.push(e);
                    }
                }
            }
        }

        // ════════════════════════════════════════════════════════════
        // CHECK 5: Cooldown (CooldownVerifier)
        // ════════════════════════════════════════════════════════════
        let cooldown_verifier = CooldownVerifier::new(self.timestamp);
        if let Err(e) = cooldown_verifier.verify(cooldown) {
            errors.push(e);
        }

        // ════════════════════════════════════════════════════════════
        // FINAL DECISION
        // ════════════════════════════════════════════════════════════
        if errors.is_empty() {
            GatingDecision::Approved
        } else {
            GatingDecision::Rejected(errors)
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use dsdn_common::gating::{
        CooldownConfig,
        CooldownPeriod,
        IdentityProof,
        NodeIdentity,
        StakeRequirement,
        TLSCertInfo,
    };

    // ────────────────────────────────────────────────────────────────────
    // HELPERS
    // ────────────────────────────────────────────────────────────────────

    const STORAGE_MIN: u128 = 5_000_000_000_000_000_000_000;
    const COMPUTE_MIN: u128 = 500_000_000_000_000_000_000;

    /// Timestamp used across tests (within TLS cert validity).
    const TEST_TS: u64 = 1500;

    fn default_identity() -> NodeIdentity {
        NodeIdentity {
            node_id: [0x01; 32],
            operator_address: [0x02; 20],
            tls_cert_fingerprint: [0xAA; 32],
        }
    }

    fn matching_tls_cert() -> TLSCertInfo {
        TLSCertInfo {
            fingerprint: [0xAA; 32],
            subject_cn: "node.dsdn.example".to_string(),
            not_before: 1000,
            not_after: 2000,
            issuer: "DSDN Test CA".to_string(),
        }
    }

    fn active_cooldown() -> CooldownPeriod {
        CooldownPeriod {
            start_timestamp: 1000,
            duration_secs: 1000,
            reason: "test violation".to_string(),
        }
        // expires_at = 2000, at TEST_TS=1500 → active
    }

    fn expired_cooldown() -> CooldownPeriod {
        CooldownPeriod {
            start_timestamp: 1000,
            duration_secs: 100,
            reason: "old violation".to_string(),
        }
        // expires_at = 1100, at TEST_TS=1500 → expired
    }

    /// Creates a permissive policy (all checks disabled, zero stakes).
    fn permissive_policy() -> GatingPolicy {
        GatingPolicy::permissive()
    }

    /// Creates a policy with require_tls=false, require_identity_proof=false,
    /// but with default stake requirements.
    fn stake_only_policy() -> GatingPolicy {
        GatingPolicy {
            stake_requirement: StakeRequirement::default(),
            cooldown_config: CooldownConfig::default(),
            require_tls: false,
            require_identity_proof: false,
            allow_pending_scheduling: false,
        }
    }

    // ════════════════════════════════════════════════════════════════════
    // CONSTRUCTION
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn test_new_stores_policy_and_timestamp() {
        let policy = GatingPolicy::default();
        let engine = GatingEngine::new(policy.clone(), 42);
        assert_eq!(engine.policy(), &policy);
        assert_eq!(engine.timestamp(), 42);
    }

    #[test]
    fn test_clone() {
        let engine = GatingEngine::new(GatingPolicy::default(), 100);
        let cloned = engine.clone();
        assert_eq!(engine, cloned);
    }

    #[test]
    fn test_debug() {
        let engine = GatingEngine::new(GatingPolicy::default(), 100);
        let debug = format!("{:?}", engine);
        assert!(debug.contains("GatingEngine"));
    }

    // ════════════════════════════════════════════════════════════════════
    // FULLY PERMISSIVE — ALL PASS
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn test_permissive_policy_zero_stake_approved() {
        // Permissive policy: zero stake minimums, no TLS, no identity proof
        let engine = GatingEngine::new(permissive_policy(), TEST_TS);
        let identity = default_identity();
        let decision = engine.evaluate(
            &identity,
            &NodeClass::Storage,
            0, // zero stake allowed with permissive policy (min=0)
            None,
            None,
            None,
        );
        // Zero stake with min=0: StakeVerifier returns Err(ZeroStake)
        // because it ALWAYS rejects zero stake regardless of requirement.
        // ClassVerifier with min=0: 0 >= 0 → Ok(passed=true)
        // So this should be Rejected with ZeroStake.
        assert!(!decision.is_approved());
    }

    #[test]
    fn test_permissive_policy_nonzero_stake_approved() {
        let engine = GatingEngine::new(permissive_policy(), TEST_TS);
        let identity = default_identity();
        let decision = engine.evaluate(
            &identity,
            &NodeClass::Storage,
            1, // non-zero, meets min=0
            None,
            None,
            None,
        );
        assert!(decision.is_approved());
        assert!(decision.errors().is_empty());
    }

    // ════════════════════════════════════════════════════════════════════
    // STAKE CHECK FAILURES
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn test_zero_stake_produces_error() {
        let engine = GatingEngine::new(stake_only_policy(), TEST_TS);
        let identity = default_identity();
        let decision = engine.evaluate(
            &identity,
            &NodeClass::Storage,
            0,
            None,
            None,
            None,
        );
        assert!(!decision.is_approved());
        let errors = decision.errors();
        assert!(
            errors.iter().any(|e| matches!(e, GatingError::ZeroStake)),
            "expected ZeroStake error, got: {:?}",
            errors,
        );
    }

    #[test]
    fn test_insufficient_stake_storage() {
        let engine = GatingEngine::new(stake_only_policy(), TEST_TS);
        let identity = default_identity();
        let decision = engine.evaluate(
            &identity,
            &NodeClass::Storage,
            STORAGE_MIN - 1,
            None,
            None,
            None,
        );
        assert!(!decision.is_approved());
        // ClassVerifier should produce InvalidNodeClass
        let errors = decision.errors();
        assert!(
            errors.iter().any(|e| matches!(e, GatingError::InvalidNodeClass(_))),
            "expected InvalidNodeClass error, got: {:?}",
            errors,
        );
    }

    #[test]
    fn test_sufficient_stake_storage_approved() {
        let engine = GatingEngine::new(stake_only_policy(), TEST_TS);
        let identity = default_identity();
        let decision = engine.evaluate(
            &identity,
            &NodeClass::Storage,
            STORAGE_MIN,
            None,
            None,
            None,
        );
        assert!(decision.is_approved());
    }

    #[test]
    fn test_sufficient_stake_compute_approved() {
        let engine = GatingEngine::new(stake_only_policy(), TEST_TS);
        let identity = default_identity();
        let decision = engine.evaluate(
            &identity,
            &NodeClass::Compute,
            COMPUTE_MIN,
            None,
            None,
            None,
        );
        assert!(decision.is_approved());
    }

    // ════════════════════════════════════════════════════════════════════
    // IDENTITY PROOF — SKIP LOGIC
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn test_identity_not_required_skip_without_error() {
        // require_identity_proof=false, proof=None → no error
        let engine = GatingEngine::new(stake_only_policy(), TEST_TS);
        let identity = default_identity();
        let decision = engine.evaluate(
            &identity,
            &NodeClass::Storage,
            STORAGE_MIN,
            None,
            None,
            None, // no proof, but not required
        );
        assert!(decision.is_approved());
    }

    #[test]
    fn test_identity_required_but_missing_produces_error() {
        let mut policy = stake_only_policy();
        policy.require_identity_proof = true;
        let engine = GatingEngine::new(policy, TEST_TS);
        let identity = default_identity();
        let decision = engine.evaluate(
            &identity,
            &NodeClass::Storage,
            STORAGE_MIN,
            None,
            None,
            None, // proof required but missing
        );
        assert!(!decision.is_approved());
        let errors = decision.errors();
        assert!(
            errors.iter().any(|e| matches!(e, GatingError::IdentityVerificationFailed(_))),
            "expected IdentityVerificationFailed, got: {:?}",
            errors,
        );
    }

    // ════════════════════════════════════════════════════════════════════
    // TLS — SKIP LOGIC
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn test_tls_not_required_skip_without_error() {
        let engine = GatingEngine::new(stake_only_policy(), TEST_TS);
        let identity = default_identity();
        let decision = engine.evaluate(
            &identity,
            &NodeClass::Storage,
            STORAGE_MIN,
            None,
            None, // no TLS, but not required
            None,
        );
        assert!(decision.is_approved());
    }

    #[test]
    fn test_tls_required_but_missing_produces_error() {
        let mut policy = stake_only_policy();
        policy.require_tls = true;
        let engine = GatingEngine::new(policy, TEST_TS);
        let identity = default_identity();
        let decision = engine.evaluate(
            &identity,
            &NodeClass::Storage,
            STORAGE_MIN,
            None,
            None, // TLS required but missing
            None,
        );
        assert!(!decision.is_approved());
        let errors = decision.errors();
        assert!(
            errors.iter().any(|e| matches!(
                e,
                GatingError::TLSInvalid(TLSValidationError::MissingCert)
            )),
            "expected TLSInvalid(MissingCert), got: {:?}",
            errors,
        );
    }

    #[test]
    fn test_tls_required_and_valid_passes() {
        let mut policy = stake_only_policy();
        policy.require_tls = true;
        let engine = GatingEngine::new(policy, TEST_TS);
        let identity = default_identity();
        let tls = matching_tls_cert();
        let decision = engine.evaluate(
            &identity,
            &NodeClass::Storage,
            STORAGE_MIN,
            None,
            Some(&tls),
            None,
        );
        assert!(decision.is_approved());
    }

    #[test]
    fn test_tls_expired_produces_error() {
        let mut policy = stake_only_policy();
        policy.require_tls = true;
        // Use timestamp after cert expiry
        let engine = GatingEngine::new(policy, 3000);
        let identity = default_identity();
        let tls = matching_tls_cert(); // not_after=2000
        let decision = engine.evaluate(
            &identity,
            &NodeClass::Storage,
            STORAGE_MIN,
            None,
            Some(&tls),
            None,
        );
        assert!(!decision.is_approved());
        let errors = decision.errors();
        assert!(
            errors.iter().any(|e| matches!(
                e,
                GatingError::TLSInvalid(TLSValidationError::Expired)
            )),
            "expected TLSInvalid(Expired), got: {:?}",
            errors,
        );
    }

    // ════════════════════════════════════════════════════════════════════
    // COOLDOWN CHECK
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn test_no_cooldown_passes() {
        let engine = GatingEngine::new(stake_only_policy(), TEST_TS);
        let identity = default_identity();
        let decision = engine.evaluate(
            &identity,
            &NodeClass::Storage,
            STORAGE_MIN,
            None, // no cooldown
            None,
            None,
        );
        assert!(decision.is_approved());
    }

    #[test]
    fn test_expired_cooldown_passes() {
        let engine = GatingEngine::new(stake_only_policy(), TEST_TS);
        let identity = default_identity();
        let cd = expired_cooldown();
        let decision = engine.evaluate(
            &identity,
            &NodeClass::Storage,
            STORAGE_MIN,
            Some(&cd),
            None,
            None,
        );
        assert!(decision.is_approved());
    }

    #[test]
    fn test_active_cooldown_produces_error() {
        let engine = GatingEngine::new(stake_only_policy(), TEST_TS);
        let identity = default_identity();
        let cd = active_cooldown();
        let decision = engine.evaluate(
            &identity,
            &NodeClass::Storage,
            STORAGE_MIN,
            Some(&cd),
            None,
            None,
        );
        assert!(!decision.is_approved());
        let errors = decision.errors();
        assert!(
            errors.iter().any(|e| matches!(
                e,
                GatingError::SlashingCooldownActive { .. }
            )),
            "expected SlashingCooldownActive, got: {:?}",
            errors,
        );
    }

    // ════════════════════════════════════════════════════════════════════
    // MULTIPLE SIMULTANEOUS FAILURES
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn test_multiple_failures_all_collected() {
        // Setup: zero stake + active cooldown + TLS required but missing
        // + identity required but missing
        let policy = GatingPolicy {
            stake_requirement: StakeRequirement::default(),
            cooldown_config: CooldownConfig::default(),
            require_tls: true,
            require_identity_proof: true,
            allow_pending_scheduling: false,
        };
        let engine = GatingEngine::new(policy, TEST_TS);
        let identity = default_identity();
        let cd = active_cooldown();
        let decision = engine.evaluate(
            &identity,
            &NodeClass::Storage,
            0, // zero stake
            Some(&cd),
            None, // TLS missing
            None, // proof missing
        );
        assert!(!decision.is_approved());
        let errors = decision.errors();
        // Expected errors (in order):
        // 1. ZeroStake (from StakeVerifier)
        // 2. InvalidNodeClass (from ClassVerifier — zero stake < minimum)
        // 3. IdentityVerificationFailed (missing proof)
        // 4. TLSInvalid(MissingCert)
        // 5. SlashingCooldownActive
        assert!(
            errors.len() >= 5,
            "expected at least 5 errors, got {}: {:?}",
            errors.len(),
            errors,
        );
        assert!(errors.iter().any(|e| matches!(e, GatingError::ZeroStake)));
        assert!(errors.iter().any(|e| matches!(e, GatingError::InvalidNodeClass(_))));
        assert!(errors.iter().any(|e| matches!(e, GatingError::IdentityVerificationFailed(_))));
        assert!(errors.iter().any(|e| matches!(e, GatingError::TLSInvalid(TLSValidationError::MissingCert))));
        assert!(errors.iter().any(|e| matches!(e, GatingError::SlashingCooldownActive { .. })));
    }

    // ════════════════════════════════════════════════════════════════════
    // ERROR ORDER — CONSENSUS-CRITICAL
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn test_error_order_matches_evaluation_order() {
        let policy = GatingPolicy {
            stake_requirement: StakeRequirement::default(),
            cooldown_config: CooldownConfig::default(),
            require_tls: true,
            require_identity_proof: true,
            allow_pending_scheduling: false,
        };
        let engine = GatingEngine::new(policy, TEST_TS);
        let identity = default_identity();
        let cd = active_cooldown();
        let decision = engine.evaluate(
            &identity,
            &NodeClass::Storage,
            0,
            Some(&cd),
            None,
            None,
        );
        let errors = decision.errors();
        // Check order: Stake(1) → Class(2) → Identity(3) → TLS(4) → Cooldown(5)
        assert!(matches!(errors[0], GatingError::ZeroStake));
        assert!(matches!(errors[1], GatingError::InvalidNodeClass(_)));
        assert!(matches!(errors[2], GatingError::IdentityVerificationFailed(_)));
        assert!(matches!(errors[3], GatingError::TLSInvalid(TLSValidationError::MissingCert)));
        assert!(matches!(errors[4], GatingError::SlashingCooldownActive { .. }));
    }

    // ════════════════════════════════════════════════════════════════════
    // DETERMINISM
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn test_determinism_approved() {
        let engine = GatingEngine::new(stake_only_policy(), TEST_TS);
        let identity = default_identity();
        let d1 = engine.evaluate(
            &identity, &NodeClass::Storage, STORAGE_MIN,
            None, None, None,
        );
        let d2 = engine.evaluate(
            &identity, &NodeClass::Storage, STORAGE_MIN,
            None, None, None,
        );
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_determinism_rejected() {
        let engine = GatingEngine::new(stake_only_policy(), TEST_TS);
        let identity = default_identity();
        let d1 = engine.evaluate(
            &identity, &NodeClass::Storage, 0,
            None, None, None,
        );
        let d2 = engine.evaluate(
            &identity, &NodeClass::Storage, 0,
            None, None, None,
        );
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_determinism_multiple_failures() {
        let policy = GatingPolicy {
            stake_requirement: StakeRequirement::default(),
            cooldown_config: CooldownConfig::default(),
            require_tls: true,
            require_identity_proof: true,
            allow_pending_scheduling: false,
        };
        let engine = GatingEngine::new(policy, TEST_TS);
        let identity = default_identity();
        let cd = active_cooldown();
        let d1 = engine.evaluate(
            &identity, &NodeClass::Storage, 0,
            Some(&cd), None, None,
        );
        let d2 = engine.evaluate(
            &identity, &NodeClass::Storage, 0,
            Some(&cd), None, None,
        );
        assert_eq!(d1, d2);
    }

    // ════════════════════════════════════════════════════════════════════
    // SEND + SYNC
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn test_gating_engine_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<GatingEngine>();
    }

    // ════════════════════════════════════════════════════════════════════
    // EDGE CASES
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn test_stake_one_with_default_policy() {
        // stake=1 is non-zero but below all class minimums
        let engine = GatingEngine::new(stake_only_policy(), TEST_TS);
        let identity = default_identity();
        let decision = engine.evaluate(
            &identity,
            &NodeClass::Storage,
            1,
            None,
            None,
            None,
        );
        assert!(!decision.is_approved());
    }

    #[test]
    fn test_u128_max_stake_approved() {
        let engine = GatingEngine::new(stake_only_policy(), TEST_TS);
        let identity = default_identity();
        let decision = engine.evaluate(
            &identity,
            &NodeClass::Storage,
            u128::MAX,
            None,
            None,
            None,
        );
        assert!(decision.is_approved());
    }

    #[test]
    fn test_tls_fingerprint_mismatch() {
        let mut policy = stake_only_policy();
        policy.require_tls = true;
        let engine = GatingEngine::new(policy, TEST_TS);
        let identity = default_identity(); // fingerprint = [0xAA; 32]
        let mut tls = matching_tls_cert();
        tls.fingerprint = [0xBB; 32]; // mismatch
        let decision = engine.evaluate(
            &identity,
            &NodeClass::Storage,
            STORAGE_MIN,
            None,
            Some(&tls),
            None,
        );
        assert!(!decision.is_approved());
        assert!(decision.errors().iter().any(|e| matches!(
            e,
            GatingError::TLSInvalid(TLSValidationError::FingerprintMismatch)
        )));
    }
}