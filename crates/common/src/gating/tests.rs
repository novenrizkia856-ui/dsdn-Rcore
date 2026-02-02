//! # Gating System Integration Tests (14B.10)
//!
//! Comprehensive cross-module tests for the DSDN gating system.
//! Every test is deterministic — no system clock, no random without seed,
//! no dependence on test execution order.

use super::*;
use ed25519_dalek::{Signer, SigningKey};

// ════════════════════════════════════════════════════════════════════════════════
// DETERMINISTIC TEST HELPERS
// ════════════════════════════════════════════════════════════════════════════════

/// Domain separator for operator binding signatures.
/// Must match the private const in identity.rs exactly:
/// `b"DSDN:operator_binding:v1:"`
const TEST_OPERATOR_BINDING_DOMAIN: &[u8] = b"DSDN:operator_binding:v1:";

/// Deterministic Ed25519 signing key from a fixed seed.
/// Seed 0x01..0x20 produces a stable keypair for reproducible tests.
fn deterministic_signing_key() -> SigningKey {
    let seed: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    ];
    SigningKey::from_bytes(&seed)
}

/// A second deterministic signing key (different seed) for mismatch tests.
fn deterministic_signing_key_alt() -> SigningKey {
    let seed: [u8; 32] = [0xFF; 32];
    SigningKey::from_bytes(&seed)
}

/// Build a NodeIdentity from a deterministic signing key.
fn make_identity_from_key(signing_key: &SigningKey) -> NodeIdentity {
    NodeIdentity {
        node_id: signing_key.verifying_key().to_bytes(),
        operator_address: [0x42; 20],
        tls_cert_fingerprint: [0xAA; 32],
    }
}

/// Sign the operator binding message (domain || node_id || operator_address).
fn sign_operator_binding(identity: &NodeIdentity, signing_key: &SigningKey) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        TEST_OPERATOR_BINDING_DOMAIN.len() + 32 + 20,
    );
    message.extend_from_slice(TEST_OPERATOR_BINDING_DOMAIN);
    message.extend_from_slice(&identity.node_id);
    message.extend_from_slice(&identity.operator_address);
    let sig = signing_key.sign(&message);
    sig.to_bytes().to_vec()
}

/// Create a TLSCertInfo valid from t=1_000_000 to t=2_000_000.
fn make_tls_info(fingerprint: [u8; 32]) -> TLSCertInfo {
    TLSCertInfo {
        fingerprint,
        subject_cn: "node.dsdn.io".to_string(),
        not_before: 1_000_000,
        not_after: 2_000_000,
        issuer: "DSDN CA".to_string(),
    }
}

/// Create an eligible NodeRegistryEntry (Active, sufficient stake, no cooldown).
fn make_eligible_entry(class: NodeClass) -> NodeRegistryEntry {
    let sk = deterministic_signing_key();
    let identity = make_identity_from_key(&sk);
    let stake = match class {
        // NodeClass::min_stake() returns NUSA token units:
        // Storage = 5_000, Compute = 500
        NodeClass::Storage => 5_000,
        NodeClass::Compute => 500,
    };
    NodeRegistryEntry {
        identity,
        class,
        status: NodeStatus::Active,
        stake,
        registered_at: 1_000_000,
        last_status_change: 1_000_000,
        cooldown: None,
        tls_info: Some(make_tls_info([0xAA; 32])),
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// 1. NodeIdentity
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn test_node_identity_creation_valid() {
    let sk = deterministic_signing_key();
    let identity = make_identity_from_key(&sk);
    // node_id must match the verifying key
    assert_eq!(identity.node_id, sk.verifying_key().to_bytes());
    assert_eq!(identity.operator_address, [0x42; 20]);
    assert_eq!(identity.tls_cert_fingerprint, [0xAA; 32]);
}

#[test]
fn test_verify_operator_binding_valid_signature() {
    let sk = deterministic_signing_key();
    let identity = make_identity_from_key(&sk);
    let sig = sign_operator_binding(&identity, &sk);
    let result = identity.verify_operator_binding(&sig);
    assert!(result.is_ok(), "verify should not error: {:?}", result);
    assert!(result.expect("already checked"), "valid signature must return true");
}

#[test]
fn test_verify_operator_binding_invalid_signature() {
    let sk = deterministic_signing_key();
    let identity = make_identity_from_key(&sk);
    // Sign with a different key → signature invalid
    let sk_alt = deterministic_signing_key_alt();
    let sig = sign_operator_binding(&identity, &sk_alt);
    let result = identity.verify_operator_binding(&sig);
    assert!(result.is_ok(), "verify should not error on wrong sig");
    assert!(!result.expect("already checked"), "wrong-key signature must return false");
}

#[test]
fn test_verify_operator_binding_operator_mismatch() {
    let sk = deterministic_signing_key();
    let mut identity = make_identity_from_key(&sk);
    // Sign with correct key and original operator address
    let sig = sign_operator_binding(&identity, &sk);
    // Tamper operator address AFTER signing
    identity.operator_address = [0x99; 20];
    let result = identity.verify_operator_binding(&sig);
    assert!(result.is_ok(), "verify should not error on operator mismatch");
    assert!(!result.expect("already checked"), "operator mismatch must return false");
}

// ════════════════════════════════════════════════════════════════════════════════
// 2. NodeClass
// ════════════════════════════════════════════════════════════════════════════════

/// NodeClass::min_stake() returns NUSA token units (not 18-decimal on-chain units).
///
/// The 18-decimal precision is handled by StakeRequirement::default(), where:
/// - Storage = 5_000_000_000_000_000_000_000 (5000 × 10^18)
/// - Compute = 500_000_000_000_000_000_000 (500 × 10^18)
///
/// NodeClass::min_stake() is a simpler, human-friendly NUSA value:
/// - Storage = 5_000 NUSA
/// - Compute = 500 NUSA
#[test]
fn test_node_class_min_stake_storage() {
    assert_eq!(NodeClass::Storage.min_stake(), 5_000);
}

#[test]
fn test_node_class_min_stake_compute() {
    assert_eq!(NodeClass::Compute.min_stake(), 500);
}

#[test]
fn test_node_class_storage_higher_than_compute() {
    assert!(
        NodeClass::Storage.min_stake() > NodeClass::Compute.min_stake(),
        "Storage class must require higher minimum stake than Compute"
    );
}

/// StakeRequirement::default() uses 18-decimal on-chain units.
#[test]
fn test_stake_requirement_default_18_decimal() {
    let req = StakeRequirement::default();
    // Storage: 5000 × 10^18
    assert_eq!(req.min_stake_storage, 5_000_000_000_000_000_000_000_u128);
    // Compute: 500 × 10^18
    assert_eq!(req.min_stake_compute, 500_000_000_000_000_000_000_u128);
}

// ════════════════════════════════════════════════════════════════════════════════
// 3. NodeStatus — All Transitions
// ════════════════════════════════════════════════════════════════════════════════

// ── VALID transitions ──

#[test]
fn test_transition_pending_to_active() {
    assert!(NodeStatus::Pending.can_transition_to(NodeStatus::Active));
}

#[test]
fn test_transition_pending_to_banned() {
    assert!(NodeStatus::Pending.can_transition_to(NodeStatus::Banned));
}

#[test]
fn test_transition_active_to_quarantined() {
    assert!(NodeStatus::Active.can_transition_to(NodeStatus::Quarantined));
}

#[test]
fn test_transition_active_to_banned() {
    assert!(NodeStatus::Active.can_transition_to(NodeStatus::Banned));
}

#[test]
fn test_transition_quarantined_to_active() {
    assert!(NodeStatus::Quarantined.can_transition_to(NodeStatus::Active));
}

#[test]
fn test_transition_quarantined_to_banned() {
    assert!(NodeStatus::Quarantined.can_transition_to(NodeStatus::Banned));
}

#[test]
fn test_transition_banned_to_pending() {
    assert!(NodeStatus::Banned.can_transition_to(NodeStatus::Pending));
}

// ── INVALID transitions ──

#[test]
fn test_invalid_self_transitions() {
    // Self-transitions are never allowed
    let all = [
        NodeStatus::Pending,
        NodeStatus::Active,
        NodeStatus::Quarantined,
        NodeStatus::Banned,
    ];
    for status in &all {
        assert!(
            !status.can_transition_to(*status),
            "{:?} → {:?} must be invalid (self-transition)",
            status, status
        );
    }
}

#[test]
fn test_invalid_pending_to_quarantined() {
    assert!(!NodeStatus::Pending.can_transition_to(NodeStatus::Quarantined));
}

#[test]
fn test_invalid_active_to_pending() {
    assert!(!NodeStatus::Active.can_transition_to(NodeStatus::Pending));
}

#[test]
fn test_invalid_quarantined_to_pending() {
    assert!(!NodeStatus::Quarantined.can_transition_to(NodeStatus::Pending));
}

#[test]
fn test_invalid_banned_to_active() {
    assert!(!NodeStatus::Banned.can_transition_to(NodeStatus::Active));
}

#[test]
fn test_invalid_banned_to_quarantined() {
    assert!(!NodeStatus::Banned.can_transition_to(NodeStatus::Quarantined));
}

#[test]
fn test_invalid_active_to_active() {
    assert!(!NodeStatus::Active.can_transition_to(NodeStatus::Active));
}

// ── is_schedulable ──

#[test]
fn test_is_schedulable_active_true() {
    assert!(NodeStatus::Active.is_schedulable());
}

#[test]
fn test_is_schedulable_pending_false() {
    assert!(!NodeStatus::Pending.is_schedulable());
}

#[test]
fn test_is_schedulable_quarantined_false() {
    assert!(!NodeStatus::Quarantined.is_schedulable());
}

#[test]
fn test_is_schedulable_banned_false() {
    assert!(!NodeStatus::Banned.is_schedulable());
}

// ════════════════════════════════════════════════════════════════════════════════
// 4. StakeRequirement
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn test_stake_check_sufficient() {
    let req = StakeRequirement {
        min_stake_storage: 5_000,
        min_stake_compute: 500,
    };
    assert!(req.check(&NodeClass::Storage, 5_000).is_ok());
    assert!(req.check(&NodeClass::Storage, 10_000).is_ok());
    assert!(req.check(&NodeClass::Compute, 500).is_ok());
    assert!(req.check(&NodeClass::Compute, 1_000).is_ok());
}

#[test]
fn test_stake_check_insufficient() {
    let req = StakeRequirement {
        min_stake_storage: 5_000,
        min_stake_compute: 500,
    };
    let result = req.check(&NodeClass::Storage, 4_999);
    assert!(result.is_err());
    match result {
        Err(StakeError::InsufficientStake { required, actual, class }) => {
            assert_eq!(required, 5_000);
            assert_eq!(actual, 4_999);
            assert_eq!(class, NodeClass::Storage);
        }
        other => panic!("expected InsufficientStake, got: {:?}", other),
    }
}

#[test]
fn test_stake_check_zero() {
    let req = StakeRequirement {
        min_stake_storage: 5_000,
        min_stake_compute: 500,
    };
    let result = req.check(&NodeClass::Storage, 0);
    assert!(result.is_err());
    match result {
        Err(StakeError::ZeroStake) => {} // expected
        other => panic!("expected ZeroStake, got: {:?}", other),
    }
}

#[test]
fn test_classify_by_stake_none() {
    let req = StakeRequirement {
        min_stake_storage: 5_000,
        min_stake_compute: 500,
    };
    assert_eq!(req.classify_by_stake(0), None);
    assert_eq!(req.classify_by_stake(499), None);
}

#[test]
fn test_classify_by_stake_compute() {
    let req = StakeRequirement {
        min_stake_storage: 5_000,
        min_stake_compute: 500,
    };
    assert_eq!(req.classify_by_stake(500), Some(NodeClass::Compute));
    assert_eq!(req.classify_by_stake(4_999), Some(NodeClass::Compute));
}

#[test]
fn test_classify_by_stake_storage() {
    let req = StakeRequirement {
        min_stake_storage: 5_000,
        min_stake_compute: 500,
    };
    assert_eq!(req.classify_by_stake(5_000), Some(NodeClass::Storage));
    assert_eq!(req.classify_by_stake(999_999), Some(NodeClass::Storage));
}

// ════════════════════════════════════════════════════════════════════════════════
// 5. Slashing Cooldown
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn test_cooldown_active_within_window() {
    let cp = CooldownPeriod {
        start_timestamp: 1_000_000,
        duration_secs: 86_400, // 24h
        reason: "minor violation".to_string(),
    };
    // At start → active
    assert!(cp.is_active(1_000_000));
    // Midway → still active
    assert!(cp.is_active(1_043_200));
    // One second before expiry → still active
    assert!(cp.is_active(1_086_399));
}

#[test]
fn test_cooldown_expired_after_window() {
    let cp = CooldownPeriod {
        start_timestamp: 1_000_000,
        duration_secs: 86_400,
        reason: "minor violation".to_string(),
    };
    // Exactly at expiry → expired (is_active returns false)
    assert!(!cp.is_active(1_086_400));
    // Well past expiry
    assert!(!cp.is_active(2_000_000));
}

#[test]
fn test_cooldown_remaining_secs_monotonic() {
    let cp = CooldownPeriod {
        start_timestamp: 1_000_000,
        duration_secs: 1_000,
        reason: "test".to_string(),
    };
    let r1 = cp.remaining_secs(1_000_000); // 1000
    let r2 = cp.remaining_secs(1_000_500); // 500
    let r3 = cp.remaining_secs(1_000_999); // 1
    let r4 = cp.remaining_secs(1_001_000); // 0
    let r5 = cp.remaining_secs(2_000_000); // 0

    assert!(r1 > r2, "remaining must decrease: {} > {}", r1, r2);
    assert!(r2 > r3, "remaining must decrease: {} > {}", r2, r3);
    assert!(r3 > r4, "remaining must decrease: {} > {}", r3, r4);
    assert_eq!(r4, 0);
    assert_eq!(r5, 0);
}

#[test]
fn test_cooldown_severe_vs_default_duration() {
    let config = CooldownConfig::default();
    // Default: 86_400s (24h), Severe: 604_800s (7d)
    assert_eq!(config.default_cooldown_secs, 86_400);
    assert_eq!(config.severe_cooldown_secs, 604_800);

    let default_cd = config.create_cooldown(false, 1_000_000, "minor".to_string());
    let severe_cd = config.create_cooldown(true, 1_000_000, "severe".to_string());

    assert_eq!(default_cd.duration_secs, 86_400);
    assert_eq!(severe_cd.duration_secs, 604_800);
    assert!(severe_cd.duration_secs > default_cd.duration_secs);
}

#[test]
fn test_cooldown_expires_at() {
    let cp = CooldownPeriod {
        start_timestamp: 1_000,
        duration_secs: 500,
        reason: "test".to_string(),
    };
    assert_eq!(cp.expires_at(), 1_500);
}

// ════════════════════════════════════════════════════════════════════════════════
// 6. TLSCertInfo
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn test_tls_valid_within_window() {
    let tls = make_tls_info([0xAA; 32]);
    // Valid from 1_000_000 to 2_000_000 (inclusive)
    assert!(tls.is_valid_at(1_000_000)); // at start
    assert!(tls.is_valid_at(1_500_000)); // middle
    assert!(tls.is_valid_at(2_000_000)); // at end (inclusive)
}

#[test]
fn test_tls_expired() {
    let tls = make_tls_info([0xAA; 32]);
    assert!(tls.is_expired(2_000_001)); // past end
    assert!(tls.is_expired(3_000_000)); // well past
}

#[test]
fn test_tls_not_expired_at_boundary() {
    let tls = make_tls_info([0xAA; 32]);
    // not_after = 2_000_000, is_expired checks timestamp > not_after
    assert!(!tls.is_expired(2_000_000)); // at boundary → not expired
}

#[test]
fn test_tls_not_yet_valid() {
    let tls = make_tls_info([0xAA; 32]);
    assert!(!tls.is_valid_at(999_999)); // before start
    assert!(!tls.is_valid_at(0));       // far before
}

#[test]
fn test_tls_fingerprint_mismatch() {
    let tls = make_tls_info([0xAA; 32]);
    let identity = NodeIdentity {
        node_id: [0; 32],
        operator_address: [0; 20],
        tls_cert_fingerprint: [0xBB; 32], // different from [0xAA; 32]
    };
    assert!(!tls.matches_identity(&identity));
}

#[test]
fn test_tls_matches_identity_correct() {
    let tls = make_tls_info([0xAA; 32]);
    let identity = NodeIdentity {
        node_id: [0; 32],
        operator_address: [0; 20],
        tls_cert_fingerprint: [0xAA; 32], // matches
    };
    assert!(tls.matches_identity(&identity));
}

#[test]
fn test_tls_compute_fingerprint_deterministic() {
    let data = b"test certificate data";
    let fp1 = TLSCertInfo::compute_fingerprint(data);
    let fp2 = TLSCertInfo::compute_fingerprint(data);
    assert_eq!(fp1, fp2, "fingerprint must be deterministic");
    // Different data → different fingerprint
    let fp3 = TLSCertInfo::compute_fingerprint(b"other data");
    assert_ne!(fp1, fp3);
}

// ════════════════════════════════════════════════════════════════════════════════
// 7. GatingDecision
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn test_gating_decision_approved() {
    let d = GatingDecision::Approved;
    assert!(d.is_approved());
    assert!(d.errors().is_empty());
}

#[test]
fn test_gating_decision_rejected() {
    let errs = vec![GatingError::ZeroStake, GatingError::NodeNotRegistered];
    let d = GatingDecision::Rejected(errs.clone());
    assert!(!d.is_approved());
    assert_eq!(d.errors().len(), 2);
    assert_eq!(d.errors()[0], GatingError::ZeroStake);
    assert_eq!(d.errors()[1], GatingError::NodeNotRegistered);
}

#[test]
fn test_gating_decision_errors_returns_exact_slice() {
    let errs = vec![
        GatingError::NodeBanned { until_timestamp: 100 },
        GatingError::ZeroStake,
    ];
    let d = GatingDecision::Rejected(errs.clone());
    // errors() must return the exact slice, not a copy
    let slice = d.errors();
    assert_eq!(slice, &errs[..]);
    // Calling again returns the same pointer (no allocation)
    let slice2 = d.errors();
    assert_eq!(slice.as_ptr(), slice2.as_ptr());
}

// ════════════════════════════════════════════════════════════════════════════════
// 8. GatingReport
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn test_gating_report_serde_roundtrip() {
    let sk = deterministic_signing_key();
    let identity = make_identity_from_key(&sk);
    let report = GatingReport {
        node_identity: identity.clone(),
        decision: GatingDecision::Approved,
        checks: vec![
            CheckResult {
                check_name: "stake_check".to_string(),
                passed: true,
                detail: None,
            },
            CheckResult {
                check_name: "tls_validation".to_string(),
                passed: true,
                detail: Some("cert valid".to_string()),
            },
        ],
        timestamp: 1_700_000_000,
        evaluated_by: "coordinator".to_string(),
    };

    // Serialize → JSON → Deserialize → must equal original
    let json = report.to_json();
    assert!(json.is_ok(), "to_json failed: {:?}", json);
    let json_str = json.expect("already checked");
    let back: GatingReport = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(report, back);
}

#[test]
fn test_gating_report_serde_roundtrip_rejected() {
    let sk = deterministic_signing_key();
    let identity = make_identity_from_key(&sk);
    let report = GatingReport {
        node_identity: identity,
        decision: GatingDecision::Rejected(vec![GatingError::ZeroStake]),
        checks: vec![CheckResult {
            check_name: "stake_check".to_string(),
            passed: false,
            detail: Some("zero stake".to_string()),
        }],
        timestamp: 1_700_000_000,
        evaluated_by: "scheduler".to_string(),
    };

    let json_str = report.to_json().expect("serialize");
    let back: GatingReport = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(report, back);
}

#[test]
fn test_gating_report_summary_nonempty() {
    let sk = deterministic_signing_key();
    let identity = make_identity_from_key(&sk);
    let report = GatingReport {
        node_identity: identity,
        decision: GatingDecision::Approved,
        checks: vec![],
        timestamp: 0,
        evaluated_by: "test".to_string(),
    };
    let s = report.summary();
    assert!(!s.is_empty(), "summary must not be empty");
    assert!(s.contains("approved"), "summary must show decision: {}", s);
}

#[test]
fn test_gating_report_summary_deterministic() {
    let sk = deterministic_signing_key();
    let identity = make_identity_from_key(&sk);
    let report = GatingReport {
        node_identity: identity,
        decision: GatingDecision::Rejected(vec![GatingError::ZeroStake]),
        checks: vec![CheckResult {
            check_name: "stake".to_string(),
            passed: false,
            detail: None,
        }],
        timestamp: 1_000,
        evaluated_by: "test".to_string(),
    };
    let s1 = report.summary();
    let s2 = report.summary();
    let s3 = report.summary();
    assert_eq!(s1, s2);
    assert_eq!(s2, s3);
}

// ════════════════════════════════════════════════════════════════════════════════
// 9. NodeRegistryEntry
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn test_registry_eligible_active_sufficient_no_cooldown() {
    let entry = make_eligible_entry(NodeClass::Storage);
    assert!(entry.is_eligible_for_scheduling(1_500_000));
}

#[test]
fn test_registry_eligible_compute() {
    let entry = make_eligible_entry(NodeClass::Compute);
    assert!(entry.is_eligible_for_scheduling(1_500_000));
}

#[test]
fn test_registry_ineligible_active_cooldown() {
    let mut entry = make_eligible_entry(NodeClass::Storage);
    entry.cooldown = Some(CooldownPeriod {
        start_timestamp: 1_000_000,
        duration_secs: 86_400,
        reason: "slashing".to_string(),
    });
    // 1_000_100 is within the cooldown window
    assert!(!entry.is_eligible_for_scheduling(1_000_100));
}

#[test]
fn test_registry_ineligible_non_active() {
    for status in &[NodeStatus::Pending, NodeStatus::Quarantined, NodeStatus::Banned] {
        let mut entry = make_eligible_entry(NodeClass::Storage);
        entry.status = *status;
        assert!(
            !entry.is_eligible_for_scheduling(1_500_000),
            "{:?} must not be eligible",
            status
        );
    }
}

#[test]
fn test_registry_ineligible_insufficient_stake() {
    let mut entry = make_eligible_entry(NodeClass::Storage);
    // NodeClass::Storage.min_stake() = 5_000; set below
    entry.stake = 4_999;
    assert!(!entry.is_eligible_for_scheduling(1_500_000));
}

#[test]
fn test_registry_eligible_after_cooldown_expires() {
    let mut entry = make_eligible_entry(NodeClass::Storage);
    entry.cooldown = Some(CooldownPeriod {
        start_timestamp: 1_000_000,
        duration_secs: 100,
        reason: "test".to_string(),
    });
    // At 1_000_099 → still active
    assert!(!entry.is_eligible_for_scheduling(1_000_099));
    // At 1_000_100 → expired
    assert!(entry.is_eligible_for_scheduling(1_000_100));
}

// ════════════════════════════════════════════════════════════════════════════════
// 10. IdentityProof
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn test_identity_proof_verify_valid() {
    let sk = deterministic_signing_key();
    let identity = make_identity_from_key(&sk);
    let nonce = [0x42; 32];
    let sig = sk.sign(&nonce);

    let proof = IdentityProof {
        challenge: IdentityChallenge {
            nonce,
            timestamp: 1_000,
            challenger: "coordinator".to_string(),
        },
        signature: sig.to_bytes(),
        node_identity: identity,
    };
    assert!(proof.verify(), "valid proof must verify");
}

#[test]
fn test_identity_proof_verify_wrong_nonce() {
    let sk = deterministic_signing_key();
    let identity = make_identity_from_key(&sk);
    let nonce_a = [0xAA; 32];
    let nonce_b = [0xBB; 32];
    // Sign nonce_a, present with nonce_b
    let sig = sk.sign(&nonce_a);

    let proof = IdentityProof {
        challenge: IdentityChallenge {
            nonce: nonce_b,
            timestamp: 1_000,
            challenger: "test".to_string(),
        },
        signature: sig.to_bytes(),
        node_identity: identity,
    };
    assert!(!proof.verify(), "signature for different nonce must fail");
}

#[test]
fn test_identity_proof_verify_pubkey_mismatch() {
    let sk = deterministic_signing_key();
    let sk_alt = deterministic_signing_key_alt();
    let nonce = [0x42; 32];
    // Sign with sk but present with sk_alt's public key
    let sig = sk.sign(&nonce);

    let proof = IdentityProof {
        challenge: IdentityChallenge {
            nonce,
            timestamp: 1_000,
            challenger: "test".to_string(),
        },
        signature: sig.to_bytes(),
        node_identity: make_identity_from_key(&sk_alt),
    };
    assert!(!proof.verify(), "pubkey mismatch must fail");
}

// ════════════════════════════════════════════════════════════════════════════════
// 11. End-to-End Flow: Identity → Registry → Decision → Report
// ════════════════════════════════════════════════════════════════════════════════

/// This test exercises the complete gating evaluation flow:
/// 1. Create identity with deterministic key
/// 2. Build a registry entry
/// 3. Check eligibility
/// 4. Verify identity proof
/// 5. Produce a gating decision and report
#[test]
fn test_end_to_end_approved_flow() {
    // Step 1: Identity
    let sk = deterministic_signing_key();
    let identity = make_identity_from_key(&sk);

    // Step 2: Registry entry (Active, sufficient stake, no cooldown)
    let entry = NodeRegistryEntry {
        identity: identity.clone(),
        class: NodeClass::Storage,
        status: NodeStatus::Active,
        stake: 5_000,
        registered_at: 1_000_000,
        last_status_change: 1_000_000,
        cooldown: None,
        tls_info: Some(make_tls_info(identity.tls_cert_fingerprint)),
    };

    // Step 3: Eligibility
    let now = 1_500_000;
    assert!(entry.is_eligible_for_scheduling(now));

    // Step 4: TLS validity
    assert!(entry.tls_info.as_ref().expect("tls present").is_valid_at(now));
    assert!(entry.tls_info.as_ref().expect("tls present").matches_identity(&identity));

    // Step 5: Identity challenge–response
    let nonce = [0x77; 32];
    let sig = sk.sign(&nonce);
    let proof = IdentityProof {
        challenge: IdentityChallenge {
            nonce,
            timestamp: now,
            challenger: "coordinator".to_string(),
        },
        signature: sig.to_bytes(),
        node_identity: identity.clone(),
    };
    assert!(proof.verify());

    // Step 6: Build decision and report
    let decision = GatingDecision::Approved;
    let report = GatingReport {
        node_identity: identity,
        decision: decision.clone(),
        checks: vec![
            CheckResult {
                check_name: "stake_check".to_string(),
                passed: true,
                detail: None,
            },
            CheckResult {
                check_name: "tls_validation".to_string(),
                passed: true,
                detail: None,
            },
            CheckResult {
                check_name: "identity_proof".to_string(),
                passed: true,
                detail: None,
            },
            CheckResult {
                check_name: "cooldown_check".to_string(),
                passed: true,
                detail: None,
            },
        ],
        timestamp: now,
        evaluated_by: "coordinator".to_string(),
    };

    assert!(report.decision.is_approved());
    let summary = report.summary();
    assert!(summary.contains("approved"), "summary: {}", summary);
    assert!(summary.contains("4 checks"), "summary: {}", summary);

    // Roundtrip
    let json = report.to_json().expect("serialize");
    let back: GatingReport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(report, back);
}

/// End-to-end rejected flow: node fails stake check.
#[test]
fn test_end_to_end_rejected_flow() {
    let sk = deterministic_signing_key();
    let identity = make_identity_from_key(&sk);

    let entry = NodeRegistryEntry {
        identity: identity.clone(),
        class: NodeClass::Storage,
        status: NodeStatus::Active,
        stake: 0, // Zero stake → ineligible
        registered_at: 1_000_000,
        last_status_change: 1_000_000,
        cooldown: None,
        tls_info: None,
    };

    let now = 1_500_000;
    assert!(!entry.is_eligible_for_scheduling(now));

    let decision = GatingDecision::Rejected(vec![GatingError::ZeroStake]);
    let report = GatingReport {
        node_identity: identity,
        decision,
        checks: vec![CheckResult {
            check_name: "stake_check".to_string(),
            passed: false,
            detail: Some("zero stake".to_string()),
        }],
        timestamp: now,
        evaluated_by: "coordinator".to_string(),
    };

    assert!(!report.decision.is_approved());
    assert_eq!(report.decision.errors().len(), 1);
    let summary = report.summary();
    assert!(summary.contains("rejected"), "summary: {}", summary);
    assert!(summary.contains("1 error"), "summary: {}", summary);
}