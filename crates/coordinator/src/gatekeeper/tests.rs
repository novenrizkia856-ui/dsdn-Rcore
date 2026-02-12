//! # GateKeeper System Tests (14B.40)
//!
//! Comprehensive test suite for the complete GateKeeper gating subsystem
//! (14B.31–14B.39). All tests are deterministic, explicit-timestamp,
//! and thread-safe.
//!
//! ## Coverage
//!
//! 1. AdmissionFilter — process_admission approval/rejection paths
//! 2. StakeCheckHook — stake validation before scheduling/admission
//! 3. IdentityCheckHook — identity proof, TLS, spoof detection
//! 4. SchedulerGate — status-based scheduling eligibility
//! 5. QuarantineManager — quarantine tracking and escalation
//! 6. BanEnforcer — ban tracking and cooldown expiry
//! 7. NodeLifecycleManager — full lifecycle state machine flows
//! 8. GatingEvent — serialization determinism and roundtrip
//!
//! ## Determinism
//!
//! - No system clock access (`std::time::SystemTime` is never used).
//! - All timestamps are explicit `u64` constants.
//! - No randomness — test data uses fixed byte patterns.
//! - No `HashMap` iteration-order dependence in assertions.
//! - All `Vec` outputs are sorted before comparison where noted.

use std::collections::HashMap;

use dsdn_common::gating::{
    CheckResult, CooldownConfig, CooldownPeriod, GatingDecision,
    GatingError, GatingPolicy, IdentityChallenge, IdentityProof,
    NodeClass, NodeIdentity, NodeRegistryEntry, NodeStatus,
    StakeRequirement, TLSCertInfo, TLSValidationError,
};

use crate::gatekeeper::admission::{AdmissionRequest, AdmissionResponse};
use crate::gatekeeper::ban::{BanEnforcer, BanRecord};
use crate::gatekeeper::events::GatingEvent;
use crate::gatekeeper::identity_check::IdentityCheckHook;
use crate::gatekeeper::lifecycle::{NodeLifecycleManager, StatusTransition};
use crate::gatekeeper::quarantine::{QuarantineManager, QuarantineRecord};
use crate::gatekeeper::stake_check::StakeCheckHook;
use crate::gatekeeper::{GateKeeper, GateKeeperConfig};

// ════════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════════

/// Fixed timestamp for test determinism. Represents a plausible Unix timestamp.
const TS: u64 = 1_700_000_000;

/// Default test stake sufficient for Storage class (5000 NUSA in on-chain units).
const STORAGE_STAKE: u128 = 5_000_000_000_000_000_000_000;

/// Default test stake sufficient for Compute class (500 NUSA in on-chain units).
const COMPUTE_STAKE: u128 = 500_000_000_000_000_000_000;

/// Insufficient stake that is non-zero but below Compute minimum.
const LOW_STAKE: u128 = 100;

// ════════════════════════════════════════════════════════════════════════════════
// TEST HELPERS
// ════════════════════════════════════════════════════════════════════════════════

/// Creates a test `NodeIdentity` with deterministic byte patterns.
///
/// - `node_id`: `[seed; 32]`
/// - `operator_address`: `[seed + 0x10; 20]`
/// - `tls_cert_fingerprint`: `[seed + 0x20; 32]`
fn make_identity(seed: u8) -> NodeIdentity {
    NodeIdentity {
        node_id: [seed; 32],
        operator_address: [seed.wrapping_add(0x10); 20],
        tls_cert_fingerprint: [seed.wrapping_add(0x20); 32],
    }
}

/// Creates a dummy `IdentityProof` with zeroed signature (invalid crypto,
/// but sufficient when identity verification is disabled via permissive policy).
fn make_dummy_proof(identity: &NodeIdentity) -> IdentityProof {
    IdentityProof {
        challenge: IdentityChallenge {
            nonce: [0x42; 32],
            timestamp: TS,
            challenger: "test".to_string(),
        },
        signature: [0u8; 64],
        node_identity: identity.clone(),
    }
}

/// Creates a `TLSCertInfo` whose fingerprint matches `identity.tls_cert_fingerprint`
/// and is valid at timestamp `TS`.
fn make_matching_tls(identity: &NodeIdentity) -> TLSCertInfo {
    TLSCertInfo {
        fingerprint: identity.tls_cert_fingerprint,
        subject_cn: "test.dsdn.network".to_string(),
        not_before: TS - 3600,
        not_after: TS + 86400,
        issuer: "DSDN Test CA".to_string(),
    }
}

/// Creates a `TLSCertInfo` that is expired at timestamp `TS`.
fn make_expired_tls() -> TLSCertInfo {
    TLSCertInfo {
        fingerprint: [0xBB; 32],
        subject_cn: "expired.dsdn.network".to_string(),
        not_before: TS - 7200,
        not_after: TS - 3600, // expired 1 hour ago
        issuer: "DSDN Test CA".to_string(),
    }
}

/// Converts a 32-byte node ID to lowercase hex string (registry key format).
fn node_id_hex(seed: u8) -> String {
    [seed; 32].iter().map(|b| format!("{:02x}", b)).collect()
}

/// Creates a permissive `GateKeeperConfig` (all checks disabled, zero stake).
fn make_permissive_config() -> GateKeeperConfig {
    GateKeeperConfig {
        policy: GatingPolicy::permissive(),
        chain_rpc_endpoint: String::new(),
        check_interval_secs: 60,
        enable_gating: true,
        auto_activate_on_pass: false,
    }
}

/// Creates a `GateKeeperConfig` with configurable stake and security flags.
fn make_config_with_stake(
    min_storage: u128,
    min_compute: u128,
    require_tls: bool,
    require_identity: bool,
) -> GateKeeperConfig {
    GateKeeperConfig {
        policy: GatingPolicy {
            stake_requirement: StakeRequirement {
                min_stake_storage: min_storage,
                min_stake_compute: min_compute,
            },
            cooldown_config: CooldownConfig {
                default_cooldown_secs: 86400,
                severe_cooldown_secs: 604800,
            },
            require_tls,
            require_identity_proof: require_identity,
            allow_pending_scheduling: false,
        },
        chain_rpc_endpoint: String::new(),
        check_interval_secs: 60,
        enable_gating: true,
        auto_activate_on_pass: false,
    }
}

/// Creates an `AdmissionRequest` with deterministic test data.
fn make_admission_request(seed: u8) -> AdmissionRequest {
    let identity = make_identity(seed);
    let proof = make_dummy_proof(&identity);
    let tls = make_matching_tls(&identity);
    AdmissionRequest {
        identity,
        claimed_class: NodeClass::Storage,
        identity_proof: proof,
        tls_cert_info: tls,
    }
}

/// Builds a `NodeRegistryEntry` directly for registry-based tests.
fn make_registry_entry(
    seed: u8,
    class: NodeClass,
    status: NodeStatus,
    stake: u128,
) -> NodeRegistryEntry {
    let identity = make_identity(seed);
    NodeRegistryEntry {
        identity,
        class,
        status,
        stake,
        registered_at: TS,
        last_status_change: TS,
        cooldown: None,
        tls_info: None,
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// 1) TEST: ADMISSION FILTER (14B.32)
// ════════════════════════════════════════════════════════════════════════════════

/// Valid admission with permissive policy → approved, status Pending.
#[test]
fn test_admission_valid_approved() {
    let config = make_permissive_config();
    let mut gk = GateKeeper::new(config);

    let request = make_admission_request(0x01);
    let node_id = request.identity.node_id;

    let response = gk.process_admission(request, STORAGE_STAKE, None, TS);

    assert!(response.approved);
    assert_eq!(response.decision, GatingDecision::Approved);
    assert_eq!(response.assigned_status, NodeStatus::Pending);

    // Verify node was inserted into registry.
    assert!(gk.is_node_registered(&node_id));

    // Verify registry entry correctness.
    let hex = node_id_hex(0x01);
    let entry = gk.registry.get(&hex);
    assert!(entry.is_some());
    if let Some(e) = entry {
        assert_eq!(e.status, NodeStatus::Pending);
        assert_eq!(e.stake, STORAGE_STAKE);
        assert_eq!(e.class, NodeClass::Storage);
        assert_eq!(e.registered_at, TS);
    }
}

/// Auto-activate on pass: approved node gets Active status immediately.
#[test]
fn test_admission_auto_activate() {
    let mut config = make_permissive_config();
    config.auto_activate_on_pass = true;
    let mut gk = GateKeeper::new(config);

    let request = make_admission_request(0x02);
    let response = gk.process_admission(request, STORAGE_STAKE, None, TS);

    assert!(response.approved);
    assert_eq!(response.assigned_status, NodeStatus::Active);

    let hex = node_id_hex(0x02);
    if let Some(e) = gk.registry.get(&hex) {
        assert_eq!(e.status, NodeStatus::Active);
    }
}

/// Reject: insufficient stake (non-zero but below configured minimum).
#[test]
fn test_admission_reject_insufficient_stake() {
    let config = make_config_with_stake(STORAGE_STAKE, COMPUTE_STAKE, false, false);
    let mut gk = GateKeeper::new(config);

    let request = make_admission_request(0x03);
    let response = gk.process_admission(request, LOW_STAKE, None, TS);

    assert!(!response.approved);
    assert!(!response.decision.is_approved());
    // Node should NOT be in registry after rejection.
    assert!(!gk.is_node_registered(&[0x03; 32]));
}

/// Reject: zero stake.
#[test]
fn test_admission_reject_zero_stake() {
    let config = make_config_with_stake(STORAGE_STAKE, COMPUTE_STAKE, false, false);
    let mut gk = GateKeeper::new(config);

    let request = make_admission_request(0x04);
    let response = gk.process_admission(request, 0, None, TS);

    assert!(!response.approved);

    // Verify ZeroStake error is present.
    let errors = response.decision.errors();
    let has_zero_stake = errors.iter().any(|e| matches!(e, GatingError::ZeroStake));
    assert!(has_zero_stake);
}

/// Reject: identity verification failed (dummy signature with identity check enabled).
#[test]
fn test_admission_reject_identity_mismatch() {
    // Enable identity proof requirement; disable TLS.
    let config = make_config_with_stake(0, 0, false, true);
    let mut gk = GateKeeper::new(config);

    // The dummy proof has zeroed signature → will fail Ed25519 verification.
    let request = make_admission_request(0x05);
    let response = gk.process_admission(request, STORAGE_STAKE, None, TS);

    assert!(!response.approved);
    // Identity spoof → assigned_status should be Banned.
    assert_eq!(response.assigned_status, NodeStatus::Banned);
    // Node NOT inserted into registry on rejection.
    assert!(!gk.is_node_registered(&[0x05; 32]));
}

/// Reject: TLS invalid (expired certificate with TLS check enabled).
#[test]
fn test_admission_reject_tls_invalid() {
    // Enable TLS requirement; disable identity proof.
    let config = make_config_with_stake(0, 0, true, false);
    let mut gk = GateKeeper::new(config);

    let identity = make_identity(0x06);
    let proof = make_dummy_proof(&identity);
    let tls = make_expired_tls(); // expired cert

    let request = AdmissionRequest {
        identity,
        claimed_class: NodeClass::Storage,
        identity_proof: proof,
        tls_cert_info: tls,
    };

    let response = gk.process_admission(request, STORAGE_STAKE, None, TS);

    assert!(!response.approved);

    // Verify TLS error is present.
    let errors = response.decision.errors();
    let has_tls_error = errors.iter().any(|e| matches!(e, GatingError::TLSInvalid(_)));
    assert!(has_tls_error);
}

/// Reject: active slashing cooldown.
#[test]
fn test_admission_reject_cooldown_active() {
    // Stake=0 threshold so stake doesn't interfere; disable TLS/identity.
    let config = make_config_with_stake(0, 0, false, false);
    let mut gk = GateKeeper::new(config);

    let request = make_admission_request(0x07);

    // Active cooldown: started at TS-100, lasts 86400 seconds.
    let cooldown = CooldownPeriod {
        start_timestamp: TS - 100,
        duration_secs: 86400,
        reason: "test slashing".to_string(),
    };

    let response = gk.process_admission(request, STORAGE_STAKE, Some(cooldown), TS);

    assert!(!response.approved);

    let errors = response.decision.errors();
    let has_cooldown = errors.iter().any(|e| {
        matches!(e, GatingError::SlashingCooldownActive { .. })
    });
    assert!(has_cooldown);
}

/// Report consistency: approved response has non-empty report.
#[test]
fn test_admission_report_consistency() {
    let config = make_permissive_config();
    let mut gk = GateKeeper::new(config);
    let request = make_admission_request(0x08);

    let response = gk.process_admission(request, STORAGE_STAKE, None, TS);

    assert!(response.approved);
    assert_eq!(response.report.timestamp, TS);
    assert!(!response.report.checks.is_empty());
    assert_eq!(response.report.node_identity.node_id, [0x08; 32]);
}

// ════════════════════════════════════════════════════════════════════════════════
// 2) TEST: STAKE CHECK HOOK (14B.33)
// ════════════════════════════════════════════════════════════════════════════════

/// Stake sufficient → pass.
#[test]
fn test_stake_check_sufficient_pass() {
    let hook = StakeCheckHook::new(StakeRequirement {
        min_stake_storage: STORAGE_STAKE,
        min_stake_compute: COMPUTE_STAKE,
    });

    let result = hook.check_before_admission(&NodeClass::Storage, STORAGE_STAKE);
    assert!(result.is_ok());
}

/// Stake drop below minimum → fail.
#[test]
fn test_stake_check_below_minimum_fail() {
    let hook = StakeCheckHook::new(StakeRequirement {
        min_stake_storage: STORAGE_STAKE,
        min_stake_compute: COMPUTE_STAKE,
    });

    let result = hook.check_before_admission(&NodeClass::Storage, LOW_STAKE);
    assert!(result.is_err());

    if let Err(GatingError::InsufficientStake { required, actual, class }) = &result {
        assert_eq!(*required, STORAGE_STAKE);
        assert_eq!(*actual, LOW_STAKE);
        assert_eq!(*class, NodeClass::Storage);
    }
    // Variant guard: ensure it was actually InsufficientStake.
    assert!(matches!(
        result,
        Err(GatingError::InsufficientStake { .. })
    ));
}

/// Edge case: stake == minimum → pass.
#[test]
fn test_stake_check_edge_equal_minimum_pass() {
    let hook = StakeCheckHook::new(StakeRequirement {
        min_stake_storage: STORAGE_STAKE,
        min_stake_compute: COMPUTE_STAKE,
    });

    let result = hook.check_before_admission(&NodeClass::Compute, COMPUTE_STAKE);
    assert!(result.is_ok());
}

/// Stake == 0 → fail with ZeroStake.
#[test]
fn test_stake_check_zero_fail() {
    let hook = StakeCheckHook::new(StakeRequirement {
        min_stake_storage: STORAGE_STAKE,
        min_stake_compute: COMPUTE_STAKE,
    });

    let result = hook.check_before_admission(&NodeClass::Storage, 0);
    assert!(result.is_err());
    assert!(matches!(result, Err(GatingError::ZeroStake)));
}

/// check_before_schedule: node in registry with sufficient stake → pass.
#[test]
fn test_stake_check_schedule_pass() {
    let hook = StakeCheckHook::new(StakeRequirement::default());

    let mut registry = HashMap::new();
    let hex = node_id_hex(0x10);
    let entry = make_registry_entry(0x10, NodeClass::Compute, NodeStatus::Active, COMPUTE_STAKE);
    registry.insert(hex.clone(), entry);

    let result = hook.check_before_schedule(&hex, &registry);
    assert!(result.is_ok());
}

/// check_before_schedule: node not in registry → NodeNotRegistered.
#[test]
fn test_stake_check_schedule_not_registered() {
    let hook = StakeCheckHook::new(StakeRequirement::default());
    let registry = HashMap::new();

    let result = hook.check_before_schedule("nonexistent", &registry);
    assert!(matches!(result, Err(GatingError::NodeNotRegistered)));
}

// ════════════════════════════════════════════════════════════════════════════════
// 3) TEST: IDENTITY CHECK HOOK (14B.34)
// ════════════════════════════════════════════════════════════════════════════════

/// Expired challenge → fail.
///
/// The challenge timestamp is far in the past. `IdentityVerifier::verify_proof`
/// checks timestamp freshness before Ed25519 verification, so this test
/// does not require a valid signature.
#[test]
fn test_identity_check_expired_challenge_fail() {
    let hook = IdentityCheckHook;
    let identity = make_identity(0x20);

    let proof = IdentityProof {
        challenge: IdentityChallenge {
            nonce: [0x42; 32],
            timestamp: 0, // very old challenge (epoch 0)
            challenger: "test".to_string(),
        },
        signature: [0u8; 64],
        node_identity: identity,
    };

    // current_timestamp = TS (1.7 billion) → challenge is expired.
    let result = hook.check_on_join(&proof, TS);
    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(GatingError::IdentityVerificationFailed(_))
    ));
}

/// Future-dated challenge → fail.
///
/// Challenge timestamp is in the future relative to current_timestamp.
#[test]
fn test_identity_check_future_challenge_fail() {
    let hook = IdentityCheckHook;
    let identity = make_identity(0x21);

    let proof = IdentityProof {
        challenge: IdentityChallenge {
            nonce: [0x42; 32],
            timestamp: TS + 1000, // future-dated
            challenger: "test".to_string(),
        },
        signature: [0u8; 64],
        node_identity: identity,
    };

    // current_timestamp < challenge.timestamp → expired (conservative).
    let result = hook.check_on_join(&proof, TS);
    assert!(result.is_err());
}

/// Spoofed node_id (already in registry) → IdentityMismatch.
#[test]
fn test_identity_check_spoofed_node_id_fail() {
    let hook = IdentityCheckHook;

    let mut registry = HashMap::new();
    let hex = node_id_hex(0x22);
    let entry = make_registry_entry(0x22, NodeClass::Storage, NodeStatus::Active, STORAGE_STAKE);
    registry.insert(hex, entry);

    // Same node_id as existing → spoof detected.
    let claimed_id = [0x22u8; 32];
    let result = hook.check_node_id_not_spoofed(&claimed_id, &registry);
    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(GatingError::IdentityMismatch { .. })
    ));
}

/// Node ID not in registry → Ok.
#[test]
fn test_identity_check_fresh_node_id_pass() {
    let hook = IdentityCheckHook;
    let registry = HashMap::new();

    let claimed_id = [0x23u8; 32];
    let result = hook.check_node_id_not_spoofed(&claimed_id, &registry);
    assert!(result.is_ok());
}

/// TLS match: valid cert + matching fingerprint → Ok.
#[test]
fn test_identity_check_tls_match_pass() {
    let hook = IdentityCheckHook;
    let identity = make_identity(0x24);
    let tls = make_matching_tls(&identity);

    let result = hook.check_tls_match(&identity, &tls, TS);
    assert!(result.is_ok());
}

/// TLS match: expired cert → TLSInvalid(Expired).
#[test]
fn test_identity_check_tls_expired_fail() {
    let hook = IdentityCheckHook;
    let identity = make_identity(0x25);
    let tls = make_expired_tls();

    let result = hook.check_tls_match(&identity, &tls, TS);
    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(GatingError::TLSInvalid(TLSValidationError::Expired))
    ));
}

/// TLS match: fingerprint mismatch → TLSInvalid(FingerprintMismatch).
#[test]
fn test_identity_check_tls_fingerprint_mismatch_fail() {
    let hook = IdentityCheckHook;
    let identity = make_identity(0x26);

    // Create TLS cert with different fingerprint but valid timestamps.
    let tls = TLSCertInfo {
        fingerprint: [0xFF; 32], // does NOT match identity.tls_cert_fingerprint
        subject_cn: "mismatch.dsdn.network".to_string(),
        not_before: TS - 3600,
        not_after: TS + 86400,
        issuer: "DSDN Test CA".to_string(),
    };

    let result = hook.check_tls_match(&identity, &tls, TS);
    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(GatingError::TLSInvalid(TLSValidationError::FingerprintMismatch))
    ));
}

// ════════════════════════════════════════════════════════════════════════════════
// 4) TEST: SCHEDULER GATE (14B.35)
// ════════════════════════════════════════════════════════════════════════════════

/// Only Active nodes are eligible for scheduling.
#[test]
fn test_scheduler_gate_active_eligible() {
    let entry = make_registry_entry(0x30, NodeClass::Storage, NodeStatus::Active, STORAGE_STAKE);
    assert!(entry.is_eligible_for_scheduling(TS));
}

/// Quarantined nodes are NOT eligible.
#[test]
fn test_scheduler_gate_quarantined_skip() {
    let entry = make_registry_entry(
        0x31, NodeClass::Storage, NodeStatus::Quarantined, STORAGE_STAKE,
    );
    assert!(!entry.is_eligible_for_scheduling(TS));
}

/// Banned nodes are NOT eligible.
#[test]
fn test_scheduler_gate_banned_skip() {
    let entry = make_registry_entry(
        0x32, NodeClass::Storage, NodeStatus::Banned, STORAGE_STAKE,
    );
    assert!(!entry.is_eligible_for_scheduling(TS));
}

/// Pending nodes are NOT eligible.
#[test]
fn test_scheduler_gate_pending_skip() {
    let entry = make_registry_entry(
        0x33, NodeClass::Storage, NodeStatus::Pending, STORAGE_STAKE,
    );
    assert!(!entry.is_eligible_for_scheduling(TS));
}

/// Active node with insufficient stake is NOT eligible (protocol-level check).
#[test]
fn test_scheduler_gate_active_insufficient_stake() {
    let entry = make_registry_entry(0x34, NodeClass::Storage, NodeStatus::Active, LOW_STAKE);
    assert!(!entry.is_eligible_for_scheduling(TS));
}

/// Active node with active cooldown is NOT eligible.
#[test]
fn test_scheduler_gate_active_with_cooldown() {
    let identity = make_identity(0x35);
    let entry = NodeRegistryEntry {
        identity,
        class: NodeClass::Storage,
        status: NodeStatus::Active,
        stake: STORAGE_STAKE,
        registered_at: TS,
        last_status_change: TS,
        cooldown: Some(CooldownPeriod {
            start_timestamp: TS - 100,
            duration_secs: 86400,
            reason: "test".to_string(),
        }),
        tls_info: None,
    };
    assert!(!entry.is_eligible_for_scheduling(TS));
}

// ════════════════════════════════════════════════════════════════════════════════
// 5) TEST: QUARANTINE MANAGER (14B.36)
// ════════════════════════════════════════════════════════════════════════════════

/// Quarantine a node → is_quarantined true.
#[test]
fn test_quarantine_node() {
    let mut mgr = QuarantineManager::new();
    let operator = [0x10; 20];

    mgr.quarantine_node("node_a", operator, "stake drop".to_string(), TS, 3600);

    assert!(mgr.is_quarantined("node_a"));
    assert!(!mgr.is_quarantined("node_b"));

    let info = mgr.get_quarantine_info("node_a");
    assert!(info.is_some());
    if let Some(record) = info {
        assert_eq!(record.node_id, "node_a");
        assert_eq!(record.reason, "stake drop");
        assert_eq!(record.quarantined_at, TS);
        assert_eq!(record.max_quarantine_secs, 3600);
    }
}

/// Release node from quarantine → returns record, no longer quarantined.
#[test]
fn test_quarantine_release_node() {
    let mut mgr = QuarantineManager::new();
    mgr.quarantine_node("node_a", [0x10; 20], "test".to_string(), TS, 3600);
    assert!(mgr.is_quarantined("node_a"));

    let released = mgr.release_node("node_a");
    assert!(released.is_some());
    assert!(!mgr.is_quarantined("node_a"));

    // Release again → None.
    let released2 = mgr.release_node("node_a");
    assert!(released2.is_none());
}

/// Escalation: quarantine expired → node in escalation list.
#[test]
fn test_quarantine_escalation_triggered() {
    let mut mgr = QuarantineManager::new();
    let operator = [0x10; 20];

    // node_a: quarantined at TS, max 3600 secs → expires at TS + 3600.
    mgr.quarantine_node("node_a", operator, "test".to_string(), TS, 3600);
    // node_b: quarantined at TS, max 7200 secs → expires at TS + 7200.
    mgr.quarantine_node("node_b", operator, "test".to_string(), TS, 7200);

    // At TS + 3600: node_a expired, node_b still active.
    let escalated = mgr.check_escalations(TS + 3600);
    assert_eq!(escalated, vec!["node_a".to_string()]);

    // At TS + 7200: both expired.
    let escalated = mgr.check_escalations(TS + 7200);
    assert_eq!(escalated.len(), 2);
    // Sorted lexicographically (deterministic).
    assert_eq!(escalated[0], "node_a");
    assert_eq!(escalated[1], "node_b");
}

/// Quarantine not yet expired → is_quarantined true, no escalation.
#[test]
fn test_quarantine_is_quarantined_correct() {
    let mut mgr = QuarantineManager::new();
    mgr.quarantine_node("node_a", [0x10; 20], "test".to_string(), TS, 3600);

    assert!(mgr.is_quarantined("node_a"));
    assert!(!mgr.is_quarantined("nonexistent"));

    // Not yet expired → no escalation.
    let escalated = mgr.check_escalations(TS + 1000);
    assert!(escalated.is_empty());
}

/// Overflow safety: max_quarantine_secs causes u64 overflow → conservative (never escalate).
#[test]
fn test_quarantine_overflow_safety() {
    let mut mgr = QuarantineManager::new();
    mgr.quarantine_node(
        "node_a",
        [0x10; 20],
        "overflow test".to_string(),
        u64::MAX - 10,
        100, // u64::MAX - 10 + 100 overflows
    );

    // checked_add returns None → node is NOT escalated.
    let escalated = mgr.check_escalations(u64::MAX);
    assert!(escalated.is_empty());
}

// ════════════════════════════════════════════════════════════════════════════════
// 6) TEST: BAN ENFORCER (14B.37)
// ════════════════════════════════════════════════════════════════════════════════

/// Ban a node → is_banned true while cooldown active.
#[test]
fn test_ban_node() {
    let mut enforcer = BanEnforcer::new();
    let operator = [0x10; 20];
    let cooldown = CooldownPeriod {
        start_timestamp: TS,
        duration_secs: 86400,
        reason: "severe slashing".to_string(),
    };

    enforcer.ban_node("node_a", operator, "severe slashing".to_string(), cooldown);

    assert!(enforcer.is_banned("node_a", TS));
    assert!(enforcer.is_banned("node_a", TS + 86399));
    assert!(!enforcer.is_banned("node_b", TS));

    let info = enforcer.get_ban_info("node_a");
    assert!(info.is_some());
    if let Some(record) = info {
        assert_eq!(record.node_id, "node_a");
        assert_eq!(record.reason, "severe slashing");
        assert_eq!(record.banned_at, TS);
    }
}

/// Expired ban: is_banned false after cooldown expires.
#[test]
fn test_ban_expired_detection() {
    let mut enforcer = BanEnforcer::new();
    let cooldown = CooldownPeriod {
        start_timestamp: TS,
        duration_secs: 86400,
        reason: "test".to_string(),
    };
    enforcer.ban_node("node_a", [0x10; 20], "test".to_string(), cooldown);

    // At TS + 86400 → cooldown expired.
    assert!(!enforcer.is_banned("node_a", TS + 86400));

    // check_expired_bans confirms.
    let expired = enforcer.check_expired_bans(TS + 86400);
    assert_eq!(expired, vec!["node_a".to_string()]);
}

/// Clear expired ban → entry removed.
#[test]
fn test_ban_clear_expired() {
    let mut enforcer = BanEnforcer::new();
    let cooldown = CooldownPeriod {
        start_timestamp: TS,
        duration_secs: 3600,
        reason: "test".to_string(),
    };
    enforcer.ban_node("node_a", [0x10; 20], "test".to_string(), cooldown);

    // Still active → clear_expired_ban returns false.
    assert!(!enforcer.clear_expired_ban("node_a", TS + 100));
    assert!(enforcer.get_ban_info("node_a").is_some());

    // Expired → clear_expired_ban returns true, entry removed.
    assert!(enforcer.clear_expired_ban("node_a", TS + 3600));
    assert!(enforcer.get_ban_info("node_a").is_none());
}

/// is_banned for non-existent node → false.
#[test]
fn test_ban_nonexistent_not_banned() {
    let enforcer = BanEnforcer::new();
    assert!(!enforcer.is_banned("ghost", TS));
}

/// clear_expired_ban for non-existent node → false.
#[test]
fn test_ban_clear_nonexistent_returns_false() {
    let mut enforcer = BanEnforcer::new();
    assert!(!enforcer.clear_expired_ban("ghost", TS));
}

// ════════════════════════════════════════════════════════════════════════════════
// 7) TEST: NODE LIFECYCLE MANAGER (14B.38)
// ════════════════════════════════════════════════════════════════════════════════

/// Helper: create a NodeLifecycleManager with a pre-populated registry.
fn make_lifecycle_manager_with_node(
    seed: u8,
    status: NodeStatus,
    stake: u128,
) -> (NodeLifecycleManager, String) {
    let config = make_permissive_config();
    let mut gk = GateKeeper::new(config);
    let hex = node_id_hex(seed);
    let entry = make_registry_entry(seed, NodeClass::Storage, status, stake);
    gk.registry.insert(hex.clone(), entry);

    let mgr = NodeLifecycleManager::new(
        gk,
        QuarantineManager::new(),
        BanEnforcer::new(),
    );

    (mgr, hex)
}

/// Flow 1: Pending → Active → Quarantined → Active.
///
/// Simulates: admission → activation → stake drop → stake restore.
#[test]
fn test_lifecycle_flow_pending_active_quarantined_active() {
    let mut config = make_permissive_config();
    // Set non-zero stake requirement so stake drop triggers quarantine.
    config.policy.stake_requirement.min_stake_storage = STORAGE_STAKE;
    config.policy.cooldown_config.default_cooldown_secs = 86400;

    let mut gk = GateKeeper::new(config);

    // Step 1: Insert node as Pending (simulates successful admission).
    let hex = node_id_hex(0x50);
    let entry = make_registry_entry(0x50, NodeClass::Storage, NodeStatus::Pending, STORAGE_STAKE);
    gk.registry.insert(hex.clone(), entry);

    let mut mgr = NodeLifecycleManager::new(
        gk,
        QuarantineManager::new(),
        BanEnforcer::new(),
    );

    // Step 2: Activate the node (Pending → Active).
    // We manually set status to Active (admission with auto_activate would do this).
    if let Some(entry) = mgr.gatekeeper.registry.get_mut(&hex) {
        entry.status = NodeStatus::Active;
        entry.last_status_change = TS + 100;
    }
    let entry = mgr.gatekeeper.registry.get(&hex);
    assert!(entry.is_some());
    if let Some(e) = entry {
        assert_eq!(e.status, NodeStatus::Active);
    }

    // Step 3: Stake drops below minimum → Quarantined.
    let transition = mgr.process_stake_change(&hex, LOW_STAKE, TS + 200);
    assert_eq!(
        transition,
        Some(StatusTransition::Quarantined {
            node_id: hex.clone(),
            reason: "stake below minimum threshold".to_string(),
        })
    );

    // Verify: status is Quarantined, quarantine manager has the node.
    if let Some(e) = mgr.gatekeeper.registry.get(&hex) {
        assert_eq!(e.status, NodeStatus::Quarantined);
    }
    assert!(mgr.quarantine_mgr.is_quarantined(&hex));

    // Step 4: Stake restored → Active.
    let transition = mgr.process_stake_change(&hex, STORAGE_STAKE, TS + 300);
    assert_eq!(
        transition,
        Some(StatusTransition::Activated {
            node_id: hex.clone(),
        })
    );

    // Verify: status is Active, no longer quarantined.
    if let Some(e) = mgr.gatekeeper.registry.get(&hex) {
        assert_eq!(e.status, NodeStatus::Active);
    }
    assert!(!mgr.quarantine_mgr.is_quarantined(&hex));
}

/// Flow 2: Pending → Active → Banned → Pending (via ban expiry).
///
/// Simulates: admission → activation → severe slashing → cooldown expires.
#[test]
fn test_lifecycle_flow_pending_active_banned_pending() {
    let mut config = make_permissive_config();
    config.policy.cooldown_config.severe_cooldown_secs = 3600;
    config.policy.cooldown_config.default_cooldown_secs = 1800;

    let mut gk = GateKeeper::new(config);

    // Step 1: Insert node as Active.
    let hex = node_id_hex(0x60);
    let entry = make_registry_entry(0x60, NodeClass::Storage, NodeStatus::Active, STORAGE_STAKE);
    gk.registry.insert(hex.clone(), entry);

    let mut mgr = NodeLifecycleManager::new(
        gk,
        QuarantineManager::new(),
        BanEnforcer::new(),
    );

    // Step 2: Severe slashing → Banned.
    let transition = mgr.process_slashing(&hex, true, TS);
    assert_eq!(
        transition,
        Some(StatusTransition::Banned {
            node_id: hex.clone(),
            reason: "severe slashing penalty".to_string(),
        })
    );

    // Verify: status is Banned, ban enforcer has the node.
    if let Some(e) = mgr.gatekeeper.registry.get(&hex) {
        assert_eq!(e.status, NodeStatus::Banned);
    }
    assert!(mgr.ban_enforcer.is_banned(&hex, TS));

    // Step 3: Periodic maintenance at TS + 3600 → ban expired → Pending.
    let transitions = mgr.periodic_maintenance(TS + 3600);

    let has_ban_expired = transitions.iter().any(|t| {
        matches!(t, StatusTransition::BanExpired { node_id } if node_id == &hex)
    });
    assert!(has_ban_expired);

    // Verify: status is Pending, ban cleared.
    if let Some(e) = mgr.gatekeeper.registry.get(&hex) {
        assert_eq!(e.status, NodeStatus::Pending);
        assert!(e.cooldown.is_none());
    }
    assert!(!mgr.ban_enforcer.is_banned(&hex, TS + 3600));
}

/// Quarantine escalation: quarantine max duration exceeded → Banned.
#[test]
fn test_lifecycle_quarantine_escalation_to_ban() {
    let mut config = make_permissive_config();
    config.policy.cooldown_config.default_cooldown_secs = 1800;
    config.policy.stake_requirement.min_stake_storage = STORAGE_STAKE;

    let mut gk = GateKeeper::new(config);
    let hex = node_id_hex(0x70);
    let entry = make_registry_entry(0x70, NodeClass::Storage, NodeStatus::Active, STORAGE_STAKE);
    gk.registry.insert(hex.clone(), entry);

    let mut mgr = NodeLifecycleManager::new(
        gk,
        QuarantineManager::new(),
        BanEnforcer::new(),
    );

    // Stake drop → quarantine with 1800 sec max.
    let _ = mgr.process_stake_change(&hex, LOW_STAKE, TS);
    assert!(mgr.quarantine_mgr.is_quarantined(&hex));

    // Periodic maintenance at TS + 1800 → quarantine escalation.
    let transitions = mgr.periodic_maintenance(TS + 1800);
    let has_ban = transitions.iter().any(|t| {
        matches!(t, StatusTransition::Banned { node_id, .. } if node_id == &hex)
    });
    assert!(has_ban);

    // Verify: banned, no longer quarantined.
    if let Some(e) = mgr.gatekeeper.registry.get(&hex) {
        assert_eq!(e.status, NodeStatus::Banned);
    }
    assert!(!mgr.quarantine_mgr.is_quarantined(&hex));
    assert!(mgr.ban_enforcer.is_banned(&hex, TS + 1800));
}

/// Minor slashing: Active → Quarantined.
#[test]
fn test_lifecycle_minor_slashing_quarantine() {
    let mut config = make_permissive_config();
    config.policy.cooldown_config.default_cooldown_secs = 86400;

    let mut gk = GateKeeper::new(config);
    let hex = node_id_hex(0x71);
    let entry = make_registry_entry(0x71, NodeClass::Storage, NodeStatus::Active, STORAGE_STAKE);
    gk.registry.insert(hex.clone(), entry);

    let mut mgr = NodeLifecycleManager::new(
        gk,
        QuarantineManager::new(),
        BanEnforcer::new(),
    );

    let transition = mgr.process_slashing(&hex, false, TS);
    assert_eq!(
        transition,
        Some(StatusTransition::Quarantined {
            node_id: hex.clone(),
            reason: "minor slashing penalty".to_string(),
        })
    );
    assert!(mgr.quarantine_mgr.is_quarantined(&hex));
}

/// Slashing a Banned node → None (no double-ban).
#[test]
fn test_lifecycle_slashing_banned_noop() {
    let (mut mgr, hex) = make_lifecycle_manager_with_node(
        0x72, NodeStatus::Banned, STORAGE_STAKE,
    );

    let transition = mgr.process_slashing(&hex, true, TS);
    assert!(transition.is_none());

    let transition = mgr.process_slashing(&hex, false, TS);
    assert!(transition.is_none());
}

/// process_stake_change on unregistered node → None.
#[test]
fn test_lifecycle_stake_change_unregistered() {
    let config = make_permissive_config();
    let gk = GateKeeper::new(config);
    let mut mgr = NodeLifecycleManager::new(
        gk,
        QuarantineManager::new(),
        BanEnforcer::new(),
    );

    let result = mgr.process_stake_change("nonexistent", STORAGE_STAKE, TS);
    assert!(result.is_none());
}

// ════════════════════════════════════════════════════════════════════════════════
// 8) TEST: GATING EVENT SERIALIZATION (14B.39)
// ════════════════════════════════════════════════════════════════════════════════

/// Serde JSON roundtrip: NodeAdmitted.
#[test]
fn test_event_serde_roundtrip_admitted() {
    let event = GatingEvent::NodeAdmitted {
        node_id: "a1b2c3d4".to_string(),
        operator: "0x1234".to_string(),
        class: "Storage".to_string(),
        timestamp: TS,
    };

    let json = serde_json::to_string(&event);
    assert!(json.is_ok());
    if let Ok(s) = json {
        let back: Result<GatingEvent, _> = serde_json::from_str(&s);
        assert!(back.is_ok());
        if let Ok(e) = back {
            assert_eq!(e, event);
        }
    }
}

/// Serde JSON roundtrip: NodeRejected with multiple reasons.
#[test]
fn test_event_serde_roundtrip_rejected() {
    let event = GatingEvent::NodeRejected {
        node_id: "deadbeef".to_string(),
        operator: "0xabcd".to_string(),
        reasons: vec![
            "insufficient stake".to_string(),
            "TLS expired".to_string(),
        ],
        timestamp: TS,
    };

    let json = serde_json::to_string(&event);
    assert!(json.is_ok());
    if let Ok(s) = json {
        let back: Result<GatingEvent, _> = serde_json::from_str(&s);
        assert!(back.is_ok());
        if let Ok(e) = back {
            assert_eq!(e, event);
        }
    }
}

/// Serde JSON roundtrip: NodeQuarantined.
#[test]
fn test_event_serde_roundtrip_quarantined() {
    let event = GatingEvent::NodeQuarantined {
        node_id: "aabbccdd".to_string(),
        reason: "stake drop".to_string(),
        timestamp: TS,
    };

    let json = serde_json::to_string(&event);
    assert!(json.is_ok());
    if let Ok(s) = json {
        let back: Result<GatingEvent, _> = serde_json::from_str(&s);
        assert!(back.is_ok());
        if let Ok(e) = back {
            assert_eq!(e, event);
        }
    }
}

/// Serde JSON roundtrip: NodeBanned.
#[test]
fn test_event_serde_roundtrip_banned() {
    let event = GatingEvent::NodeBanned {
        node_id: "11223344".to_string(),
        reason: "severe slashing".to_string(),
        cooldown_until: TS + 604800,
        timestamp: TS,
    };

    let json = serde_json::to_string(&event);
    assert!(json.is_ok());
    if let Ok(s) = json {
        let back: Result<GatingEvent, _> = serde_json::from_str(&s);
        assert!(back.is_ok());
        if let Ok(e) = back {
            assert_eq!(e, event);
        }
    }
}

/// Serde JSON roundtrip: NodeActivated.
#[test]
fn test_event_serde_roundtrip_activated() {
    let event = GatingEvent::NodeActivated {
        node_id: "55667788".to_string(),
        timestamp: TS,
    };

    let json = serde_json::to_string(&event);
    assert!(json.is_ok());
    if let Ok(s) = json {
        let back: Result<GatingEvent, _> = serde_json::from_str(&s);
        assert!(back.is_ok());
        if let Ok(e) = back {
            assert_eq!(e, event);
        }
    }
}

/// Serde JSON roundtrip: NodeBanExpired.
#[test]
fn test_event_serde_roundtrip_ban_expired() {
    let event = GatingEvent::NodeBanExpired {
        node_id: "99aabbcc".to_string(),
        timestamp: TS,
    };

    let json = serde_json::to_string(&event);
    assert!(json.is_ok());
    if let Ok(s) = json {
        let back: Result<GatingEvent, _> = serde_json::from_str(&s);
        assert!(back.is_ok());
        if let Ok(e) = back {
            assert_eq!(e, event);
        }
    }
}

/// Deterministic bytes: same event → identical JSON output (stable ordering).
#[test]
fn test_event_json_deterministic() {
    let event = GatingEvent::NodeRejected {
        node_id: "aabb".to_string(),
        operator: "ccdd".to_string(),
        reasons: vec!["reason_a".to_string(), "reason_b".to_string()],
        timestamp: TS,
    };

    let json1 = serde_json::to_string(&event);
    let json2 = serde_json::to_string(&event);
    assert!(json1.is_ok());
    assert!(json2.is_ok());
    if let (Ok(s1), Ok(s2)) = (json1, json2) {
        assert_eq!(s1, s2);
    }
}

/// Rejected with empty reasons: roundtrip preserves empty vec.
#[test]
fn test_event_serde_rejected_empty_reasons() {
    let event = GatingEvent::NodeRejected {
        node_id: "empty".to_string(),
        operator: "op".to_string(),
        reasons: vec![],
        timestamp: TS,
    };

    let json = serde_json::to_string(&event);
    assert!(json.is_ok());
    if let Ok(s) = json {
        let back: Result<GatingEvent, _> = serde_json::from_str(&s);
        assert!(back.is_ok());
        if let Ok(GatingEvent::NodeRejected { reasons, .. }) = back {
            assert!(reasons.is_empty());
        }
    }
}

/// Different event variants produce different JSON.
#[test]
fn test_event_different_variants_different_json() {
    let e1 = GatingEvent::NodeAdmitted {
        node_id: "abc".to_string(),
        operator: "op".to_string(),
        class: "Storage".to_string(),
        timestamp: TS,
    };
    let e2 = GatingEvent::NodeRejected {
        node_id: "abc".to_string(),
        operator: "op".to_string(),
        reasons: vec![],
        timestamp: TS,
    };

    let j1 = serde_json::to_string(&e1);
    let j2 = serde_json::to_string(&e2);
    assert!(j1.is_ok());
    assert!(j2.is_ok());
    if let (Ok(s1), Ok(s2)) = (j1, j2) {
        assert_ne!(s1, s2);
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// ADDITIONAL: StatusTransition correctness
// ════════════════════════════════════════════════════════════════════════════════

/// NodeStatus transition rules: valid transitions.
#[test]
fn test_status_transition_valid() {
    assert!(NodeStatus::Pending.can_transition_to(NodeStatus::Active));
    assert!(NodeStatus::Pending.can_transition_to(NodeStatus::Banned));
    assert!(NodeStatus::Active.can_transition_to(NodeStatus::Quarantined));
    assert!(NodeStatus::Active.can_transition_to(NodeStatus::Banned));
    assert!(NodeStatus::Quarantined.can_transition_to(NodeStatus::Active));
    assert!(NodeStatus::Quarantined.can_transition_to(NodeStatus::Banned));
    assert!(NodeStatus::Banned.can_transition_to(NodeStatus::Pending));
}

/// NodeStatus transition rules: forbidden transitions.
#[test]
fn test_status_transition_forbidden() {
    // Self-transitions forbidden.
    assert!(!NodeStatus::Pending.can_transition_to(NodeStatus::Pending));
    assert!(!NodeStatus::Active.can_transition_to(NodeStatus::Active));
    assert!(!NodeStatus::Quarantined.can_transition_to(NodeStatus::Quarantined));
    assert!(!NodeStatus::Banned.can_transition_to(NodeStatus::Banned));

    // Skip/backward forbidden.
    assert!(!NodeStatus::Pending.can_transition_to(NodeStatus::Quarantined));
    assert!(!NodeStatus::Banned.can_transition_to(NodeStatus::Active));
    assert!(!NodeStatus::Banned.can_transition_to(NodeStatus::Quarantined));
    assert!(!NodeStatus::Active.can_transition_to(NodeStatus::Pending));
    assert!(!NodeStatus::Quarantined.can_transition_to(NodeStatus::Pending));
}