//! # Node Registry Entry (14B.9)
//!
//! Defines `NodeRegistryEntry` — the single source of truth for a
//! node's current state within the gating system. This type is used
//! by the scheduler, coordinator, and admission engine to determine
//! a node's eligibility for workload assignment.
//!
//! ## Overview
//!
//! Each registered node has exactly one `NodeRegistryEntry`. The entry
//! combines the node's cryptographic identity, classification, lifecycle
//! status, stake amount, timestamps, and optional cooldown/TLS metadata
//! into a single serializable record.
//!
//! ## Eligibility
//!
//! `is_eligible_for_scheduling(now)` performs a deterministic eligibility
//! check using only the entry's fields and a caller-provided timestamp.
//! A node is eligible if and only if:
//!
//! 1. `status == NodeStatus::Active`
//! 2. `stake >= class.min_stake()`
//! 3. No active cooldown (either `cooldown` is `None`, or the cooldown
//!    has expired at the given timestamp)
//!
//! TLS and identity proof checks are NOT performed here — those are
//! separate gating steps handled by the admission engine.
//!
//! ## Safety Properties
//!
//! - Value type: `Clone`, `Debug`, `PartialEq`, `Eq`.
//! - No system clock access — all time checks use caller-provided timestamps.
//! - No side effects, no logging, no global state.

use serde::{Deserialize, Serialize};

use super::cooldown::CooldownPeriod;
use super::identity::{NodeClass, NodeIdentity};
use super::node_status::NodeStatus;
use super::tls::TLSCertInfo;

// ════════════════════════════════════════════════════════════════════════════════
// NODE REGISTRY ENTRY
// ════════════════════════════════════════════════════════════════════════════════

/// A node's complete registry record in the gating system.
///
/// This struct is the single source of truth for a node's current state.
/// It is used by the scheduler, coordinator, and admission engine for
/// eligibility decisions.
///
/// ## Fields
///
/// - `identity`: The node's cryptographic identity (Ed25519 key, operator
///   wallet, TLS fingerprint).
/// - `class`: The node's classification (Storage or Compute).
/// - `status`: The node's lifecycle status (Pending, Active, Quarantined,
///   Banned).
/// - `stake`: The node's current stake in NUSA token units.
/// - `registered_at`: Unix timestamp (seconds) when the node was registered.
/// - `last_status_change`: Unix timestamp (seconds) of the most recent
///   status transition.
/// - `cooldown`: Optional active cooldown period after a slashing event.
/// - `tls_info`: Optional TLS certificate metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRegistryEntry {
    /// The node's cryptographic identity.
    pub identity: NodeIdentity,
    /// The node's classification (Storage or Compute).
    pub class: NodeClass,
    /// The node's current lifecycle status.
    pub status: NodeStatus,
    /// The node's current stake in NUSA token units.
    pub stake: u128,
    /// Unix timestamp (seconds) when the node was registered.
    pub registered_at: u64,
    /// Unix timestamp (seconds) of the most recent status transition.
    pub last_status_change: u64,
    /// Optional active cooldown period (present after slashing events).
    pub cooldown: Option<CooldownPeriod>,
    /// Optional TLS certificate metadata.
    pub tls_info: Option<TLSCertInfo>,
}

impl NodeRegistryEntry {
    /// Determines whether this node is eligible for workload scheduling.
    ///
    /// A node is eligible if and only if ALL of the following are true:
    ///
    /// 1. `status == NodeStatus::Active`
    /// 2. `stake >= class.min_stake()` (NUSA token units)
    /// 3. No active cooldown at the given timestamp:
    ///    - `cooldown` is `None`, OR
    ///    - `cooldown.is_active(now) == false` (cooldown has expired)
    ///
    /// This method does NOT check TLS certificate validity or identity
    /// proof — those are separate gating steps.
    ///
    /// ## Parameters
    ///
    /// - `now`: Current timestamp in Unix seconds (caller-provided).
    ///   No system clock is accessed internally.
    ///
    /// ## Returns
    ///
    /// `true` if all eligibility conditions are met, `false` otherwise.
    ///
    /// This is a **pure function** — deterministic, no side effects,
    /// no logging.
    #[must_use]
    pub fn is_eligible_for_scheduling(&self, now: u64) -> bool {
        // Condition 1: Status must be Active
        if self.status != NodeStatus::Active {
            return false;
        }

        // Condition 2: Stake must meet class minimum
        if self.stake < self.class.min_stake() {
            return false;
        }

        // Condition 3: No active cooldown
        if let Some(ref cooldown) = self.cooldown {
            if cooldown.is_active(now) {
                return false;
            }
        }

        true
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ──────────────────────────────────────────────────────────────────────
    // HELPERS
    // ──────────────────────────────────────────────────────────────────────

    fn make_identity() -> NodeIdentity {
        NodeIdentity {
            node_id: [0xAA; 32],
            operator_address: [0xBB; 20],
            tls_cert_fingerprint: [0xCC; 32],
        }
    }

    fn make_tls_info() -> TLSCertInfo {
        TLSCertInfo {
            fingerprint: [0xCC; 32],
            subject_cn: "test.dsdn.io".to_string(),
            not_before: 1_000_000,
            not_after: 2_000_000,
            issuer: "DSDN CA".to_string(),
        }
    }

    fn make_eligible_storage_entry() -> NodeRegistryEntry {
        NodeRegistryEntry {
            identity: make_identity(),
            class: NodeClass::Storage,
            status: NodeStatus::Active,
            stake: 5_000, // Exactly min_stake for Storage
            registered_at: 1_000_000,
            last_status_change: 1_000_000,
            cooldown: None,
            tls_info: Some(make_tls_info()),
        }
    }

    fn make_eligible_compute_entry() -> NodeRegistryEntry {
        NodeRegistryEntry {
            identity: make_identity(),
            class: NodeClass::Compute,
            status: NodeStatus::Active,
            stake: 500, // Exactly min_stake for Compute
            registered_at: 1_000_000,
            last_status_change: 1_000_000,
            cooldown: None,
            tls_info: None,
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // ELIGIBILITY — HAPPY PATH
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_eligible_storage_node() {
        let entry = make_eligible_storage_entry();
        assert!(entry.is_eligible_for_scheduling(1_500_000));
    }

    #[test]
    fn test_eligible_compute_node() {
        let entry = make_eligible_compute_entry();
        assert!(entry.is_eligible_for_scheduling(1_500_000));
    }

    #[test]
    fn test_eligible_with_above_minimum_stake() {
        let mut entry = make_eligible_storage_entry();
        entry.stake = 999_999; // Well above 5000
        assert!(entry.is_eligible_for_scheduling(1_500_000));
    }

    #[test]
    fn test_eligible_with_expired_cooldown() {
        let mut entry = make_eligible_storage_entry();
        entry.cooldown = Some(CooldownPeriod {
            start_timestamp: 1_000_000,
            duration_secs: 86_400, // 24h cooldown
            reason: "minor violation".to_string(),
        });
        // now = 1_000_000 + 86_400 + 1 → cooldown expired
        let now = 1_000_000 + 86_400 + 1;
        assert!(entry.is_eligible_for_scheduling(now));
    }

    // ──────────────────────────────────────────────────────────────────────
    // ELIGIBILITY — CONDITION 1: STATUS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_ineligible_pending_status() {
        let mut entry = make_eligible_storage_entry();
        entry.status = NodeStatus::Pending;
        assert!(!entry.is_eligible_for_scheduling(1_500_000));
    }

    #[test]
    fn test_ineligible_quarantined_status() {
        let mut entry = make_eligible_storage_entry();
        entry.status = NodeStatus::Quarantined;
        assert!(!entry.is_eligible_for_scheduling(1_500_000));
    }

    #[test]
    fn test_ineligible_banned_status() {
        let mut entry = make_eligible_storage_entry();
        entry.status = NodeStatus::Banned;
        assert!(!entry.is_eligible_for_scheduling(1_500_000));
    }

    // ──────────────────────────────────────────────────────────────────────
    // ELIGIBILITY — CONDITION 2: STAKE
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_ineligible_zero_stake() {
        let mut entry = make_eligible_storage_entry();
        entry.stake = 0;
        assert!(!entry.is_eligible_for_scheduling(1_500_000));
    }

    #[test]
    fn test_ineligible_below_minimum_stake_storage() {
        let mut entry = make_eligible_storage_entry();
        entry.stake = 4_999; // Below 5000
        assert!(!entry.is_eligible_for_scheduling(1_500_000));
    }

    #[test]
    fn test_ineligible_below_minimum_stake_compute() {
        let mut entry = make_eligible_compute_entry();
        entry.stake = 499; // Below 500
        assert!(!entry.is_eligible_for_scheduling(1_500_000));
    }

    #[test]
    fn test_eligible_at_exact_minimum_stake_storage() {
        let mut entry = make_eligible_storage_entry();
        entry.stake = 5_000; // Exactly min_stake
        assert!(entry.is_eligible_for_scheduling(1_500_000));
    }

    #[test]
    fn test_eligible_at_exact_minimum_stake_compute() {
        let mut entry = make_eligible_compute_entry();
        entry.stake = 500; // Exactly min_stake
        assert!(entry.is_eligible_for_scheduling(1_500_000));
    }

    // ──────────────────────────────────────────────────────────────────────
    // ELIGIBILITY — CONDITION 3: COOLDOWN
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_ineligible_active_cooldown() {
        let mut entry = make_eligible_storage_entry();
        entry.cooldown = Some(CooldownPeriod {
            start_timestamp: 1_000_000,
            duration_secs: 86_400,
            reason: "slashing".to_string(),
        });
        // now = 1_000_000 + 100 → still in cooldown
        let now = 1_000_100;
        assert!(!entry.is_eligible_for_scheduling(now));
    }

    #[test]
    fn test_eligible_no_cooldown() {
        let entry = make_eligible_storage_entry();
        assert!(entry.cooldown.is_none());
        assert!(entry.is_eligible_for_scheduling(1_500_000));
    }

    #[test]
    fn test_cooldown_boundary_still_active() {
        let mut entry = make_eligible_storage_entry();
        entry.cooldown = Some(CooldownPeriod {
            start_timestamp: 1_000_000,
            duration_secs: 100,
            reason: "test".to_string(),
        });
        // Cooldown expires at 1_000_100
        // At exactly 1_000_099 → still active (per is_active: now < expires_at)
        assert!(!entry.is_eligible_for_scheduling(1_000_099));
    }

    #[test]
    fn test_cooldown_boundary_just_expired() {
        let mut entry = make_eligible_storage_entry();
        entry.cooldown = Some(CooldownPeriod {
            start_timestamp: 1_000_000,
            duration_secs: 100,
            reason: "test".to_string(),
        });
        // At 1_000_100 → expired (now >= expires_at → is_active returns false)
        assert!(entry.is_eligible_for_scheduling(1_000_100));
    }

    // ──────────────────────────────────────────────────────────────────────
    // ELIGIBILITY — COMBINED FAILURES
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_multiple_failures_still_false() {
        let mut entry = make_eligible_storage_entry();
        entry.status = NodeStatus::Banned;
        entry.stake = 0;
        entry.cooldown = Some(CooldownPeriod {
            start_timestamp: 1_000_000,
            duration_secs: 86_400,
            reason: "all bad".to_string(),
        });
        assert!(!entry.is_eligible_for_scheduling(1_000_100));
    }

    // ──────────────────────────────────────────────────────────────────────
    // ELIGIBILITY — DETERMINISM
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_eligible_deterministic() {
        let entry = make_eligible_storage_entry();
        let now = 1_500_000;
        let r1 = entry.is_eligible_for_scheduling(now);
        let r2 = entry.is_eligible_for_scheduling(now);
        let r3 = entry.is_eligible_for_scheduling(now);
        assert_eq!(r1, r2);
        assert_eq!(r2, r3);
    }

    // ──────────────────────────────────────────────────────────────────────
    // ELIGIBILITY — TLS NOT CHECKED
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_eligible_without_tls_info() {
        let mut entry = make_eligible_storage_entry();
        entry.tls_info = None;
        // tls_info is not checked in is_eligible_for_scheduling
        assert!(entry.is_eligible_for_scheduling(1_500_000));
    }

    #[test]
    fn test_eligible_with_expired_tls_still_eligible() {
        let mut entry = make_eligible_storage_entry();
        entry.tls_info = Some(TLSCertInfo {
            fingerprint: [0; 32],
            subject_cn: "expired".to_string(),
            not_before: 100,
            not_after: 200, // expired long ago
            issuer: "test".to_string(),
        });
        // TLS expiry is NOT checked here → still eligible
        assert!(entry.is_eligible_for_scheduling(1_500_000));
    }

    // ──────────────────────────────────────────────────────────────────────
    // TRAIT TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_clone() {
        let entry = make_eligible_storage_entry();
        let cloned = entry.clone();
        assert_eq!(entry, cloned);
    }

    #[test]
    fn test_debug() {
        let entry = make_eligible_storage_entry();
        let debug = format!("{:?}", entry);
        assert!(debug.contains("NodeRegistryEntry"));
        assert!(debug.contains("Active"));
        assert!(debug.contains("Storage"));
    }

    #[test]
    fn test_eq() {
        let a = make_eligible_storage_entry();
        let b = make_eligible_storage_entry();
        assert_eq!(a, b);
    }

    #[test]
    fn test_ne_different_status() {
        let a = make_eligible_storage_entry();
        let mut b = make_eligible_storage_entry();
        b.status = NodeStatus::Pending;
        assert_ne!(a, b);
    }

    #[test]
    fn test_ne_different_stake() {
        let a = make_eligible_storage_entry();
        let mut b = make_eligible_storage_entry();
        b.stake = 999_999;
        assert_ne!(a, b);
    }

    #[test]
    fn test_ne_different_class() {
        let a = make_eligible_storage_entry();
        let mut b = make_eligible_storage_entry();
        b.class = NodeClass::Compute;
        assert_ne!(a, b);
    }

    #[test]
    fn test_serde_roundtrip() {
        let entry = make_eligible_storage_entry();
        let json = serde_json::to_string(&entry).expect("serialize");
        let back: NodeRegistryEntry =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(entry, back);
    }

    #[test]
    fn test_serde_roundtrip_with_cooldown() {
        let mut entry = make_eligible_storage_entry();
        entry.cooldown = Some(CooldownPeriod {
            start_timestamp: 100,
            duration_secs: 200,
            reason: "test".to_string(),
        });
        let json = serde_json::to_string(&entry).expect("serialize");
        let back: NodeRegistryEntry =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(entry, back);
    }

    #[test]
    fn test_serde_roundtrip_no_tls() {
        let mut entry = make_eligible_storage_entry();
        entry.tls_info = None;
        let json = serde_json::to_string(&entry).expect("serialize");
        let back: NodeRegistryEntry =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(entry, back);
    }

    #[test]
    fn test_serde_preserves_all_fields() {
        let entry = make_eligible_storage_entry();
        let json = serde_json::to_string(&entry).expect("serialize");
        let back: NodeRegistryEntry =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.identity, entry.identity);
        assert_eq!(back.class, entry.class);
        assert_eq!(back.status, entry.status);
        assert_eq!(back.stake, entry.stake);
        assert_eq!(back.registered_at, entry.registered_at);
        assert_eq!(back.last_status_change, entry.last_status_change);
        assert_eq!(back.cooldown, entry.cooldown);
        assert_eq!(back.tls_info, entry.tls_info);
    }

    // ──────────────────────────────────────────────────────────────────────
    // SEND + SYNC
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NodeRegistryEntry>();
    }
}