//! # Audit Log Event Schema (Tahap 15)
//!
//! Schema contract untuk audit log system DSDN.
//!
//! ## Stability Contract
//!
//! **VARIANT ORDER IS FROZEN AFTER THIS MODULE IS DEPLOYED.**
//!
//! Enum variants MUST NOT be reordered, renamed, or removed.
//! New variants may only be appended at the end.
//! Field additions within variants are handled via the `version` field.
//!
//! ## Variant Overview
//!
//! | # | Variant                     | Producer      | Tahap |
//! |---|-----------------------------|---------------|-------|
//! | 1 | `SlashingExecuted`          | chain         | 15.1  |
//! | 2 | `StakeUpdated`              | chain         | 15.1  |
//! | 3 | `AntiSelfDealingViolation`  | chain         | 15.1  |
//! | 4 | `UserControlledDelete`      | ingress       | 15.1  |
//! | 5 | `DaSyncSequenceUpdate`      | coordinator   | 15.1  |
//! | 6 | `GovernanceProposalEvent`   | chain         | 15.1  |
//! | 7 | `CommitteeRotationEvent`    | coordinator   | 20    |
//! | 8 | `DaFallbackEvent`           | coordinator   | 15.1  |
//! | 9 | `ComputeChallengeEvent`     | node          | 18.1  |
//!
//! ## Serialization
//!
//! Uses `serde` with `bincode` for deterministic binary encoding.
//! Same pipeline as `DAEvent` and `FallbackEvent`:
//!
//! ```text
//! AuditLogEvent → bincode::serialize → SHA3-256 → [u8; 32]
//! ```
//!
//! ## Field Rules
//!
//! Every variant carries:
//! - `version: u32` — schema version for forward compatibility
//! - `timestamp_ms: u64` — Unix timestamp in milliseconds (caller-provided)
//!
//! No auto-generated timestamps. No default values in production.

use serde::{Deserialize, Serialize};

// ════════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════════

/// Current schema version for `AuditLogEvent`.
///
/// Incremented when fields are added to existing variants.
/// Used by decoders to detect and handle schema evolution.
pub const AUDIT_EVENT_SCHEMA_VERSION: u32 = 1;

// ════════════════════════════════════════════════════════════════════════════════
// AUDIT LOG EVENT ENUM
// ════════════════════════════════════════════════════════════════════════════════

/// Core audit log event enum for the DSDN audit trail.
///
/// **STABILITY: Variant order is frozen. Do not reorder or remove variants.**
///
/// Each variant is a placeholder with `version` + `timestamp_ms` only.
/// Full field definitions will be added in subsequent sub-stages (15.2–15.5)
/// via the `version` field for backward compatibility.
///
/// # Thread Safety
///
/// `AuditLogEvent` is `Send + Sync` (all fields are owned, no interior mutability).
///
/// # Serialization
///
/// Deterministic via `serde` + `bincode`. Identical input always produces
/// identical output bytes regardless of platform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditLogEvent {
    // ── Variant 1 ────────────────────────────────────────────────────────────
    /// Validator or node was slashed.
    ///
    /// Produced by: chain crate (DPoS consensus slashing logic).
    SlashingExecuted {
        /// Schema version for forward compatibility.
        version: u32,
        /// Unix timestamp in milliseconds (caller-provided).
        timestamp_ms: u64,
    },

    // ── Variant 2 ────────────────────────────────────────────────────────────
    /// Stake was delegated, undelegated, or redelegated.
    ///
    /// Produced by: chain crate (staking state transitions).
    StakeUpdated {
        /// Schema version for forward compatibility.
        version: u32,
        /// Unix timestamp in milliseconds (caller-provided).
        timestamp_ms: u64,
    },

    // ── Variant 3 ────────────────────────────────────────────────────────────
    /// Anti-self-dealing violation detected during claim validation.
    ///
    /// Produced by: chain crate (claim validation pipeline).
    AntiSelfDealingViolation {
        /// Schema version for forward compatibility.
        version: u32,
        /// Unix timestamp in milliseconds (caller-provided).
        timestamp_ms: u64,
    },

    // ── Variant 4 ────────────────────────────────────────────────────────────
    /// User-initiated data deletion request.
    ///
    /// Produced by: ingress crate (user-facing API).
    UserControlledDelete {
        /// Schema version for forward compatibility.
        version: u32,
        /// Unix timestamp in milliseconds (caller-provided).
        timestamp_ms: u64,
    },

    // ── Variant 5 ────────────────────────────────────────────────────────────
    /// DA sync sequence number advanced.
    ///
    /// Produced by: coordinator crate (DA sync loop).
    DaSyncSequenceUpdate {
        /// Schema version for forward compatibility.
        version: u32,
        /// Unix timestamp in milliseconds (caller-provided).
        timestamp_ms: u64,
    },

    // ── Variant 6 ────────────────────────────────────────────────────────────
    /// Governance proposal lifecycle event (submit, approve, reject, execute).
    ///
    /// Produced by: chain crate (governance module).
    GovernanceProposalEvent {
        /// Schema version for forward compatibility.
        version: u32,
        /// Unix timestamp in milliseconds (caller-provided).
        timestamp_ms: u64,
    },

    // ── Variant 7 ────────────────────────────────────────────────────────────
    /// Coordinator committee rotation event.
    ///
    /// Producer: Tahap 20 (committee rotation mechanism).
    /// Hook is defined now; producer will call it when rotation is active.
    CommitteeRotationEvent {
        /// Schema version for forward compatibility.
        version: u32,
        /// Unix timestamp in milliseconds (caller-provided).
        timestamp_ms: u64,
    },

    // ── Variant 8 ────────────────────────────────────────────────────────────
    /// DA fallback activation or deactivation event.
    ///
    /// Producer: Tahap 15.1 integration (coordinator crate).
    /// Emitted when DA source changes (primary ↔ secondary ↔ emergency).
    DaFallbackEvent {
        /// Schema version for forward compatibility.
        version: u32,
        /// Unix timestamp in milliseconds (caller-provided).
        timestamp_ms: u64,
    },

    // ── Variant 9 ────────────────────────────────────────────────────────────
    /// Compute challenge event (challenge issued, cleared, or fraud detected).
    ///
    /// Producer: Tahap 18.1 (fraud proof system).
    /// Hook is defined now; producer will call it when challenge system is active.
    ComputeChallengeEvent {
        /// Schema version for forward compatibility.
        version: u32,
        /// Unix timestamp in milliseconds (caller-provided).
        timestamp_ms: u64,
    },
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ────────────────────────────────────────────────────────────────────────
    // Helpers
    // ────────────────────────────────────────────────────────────────────────

    /// Build all 9 variants in contract order for testing.
    fn all_variants() -> Vec<AuditLogEvent> {
        vec![
            AuditLogEvent::SlashingExecuted {
                version: AUDIT_EVENT_SCHEMA_VERSION,
                timestamp_ms: 1700000001,
            },
            AuditLogEvent::StakeUpdated {
                version: AUDIT_EVENT_SCHEMA_VERSION,
                timestamp_ms: 1700000002,
            },
            AuditLogEvent::AntiSelfDealingViolation {
                version: AUDIT_EVENT_SCHEMA_VERSION,
                timestamp_ms: 1700000003,
            },
            AuditLogEvent::UserControlledDelete {
                version: AUDIT_EVENT_SCHEMA_VERSION,
                timestamp_ms: 1700000004,
            },
            AuditLogEvent::DaSyncSequenceUpdate {
                version: AUDIT_EVENT_SCHEMA_VERSION,
                timestamp_ms: 1700000005,
            },
            AuditLogEvent::GovernanceProposalEvent {
                version: AUDIT_EVENT_SCHEMA_VERSION,
                timestamp_ms: 1700000006,
            },
            AuditLogEvent::CommitteeRotationEvent {
                version: AUDIT_EVENT_SCHEMA_VERSION,
                timestamp_ms: 1700000007,
            },
            AuditLogEvent::DaFallbackEvent {
                version: AUDIT_EVENT_SCHEMA_VERSION,
                timestamp_ms: 1700000008,
            },
            AuditLogEvent::ComputeChallengeEvent {
                version: AUDIT_EVENT_SCHEMA_VERSION,
                timestamp_ms: 1700000009,
            },
        ]
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 1: audit_event_enum_variant_count
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_event_enum_variant_count() {
        let variants = all_variants();
        assert_eq!(variants.len(), 9, "AuditLogEvent must have exactly 9 variants");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 2: audit_event_enum_variant_order
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_event_enum_variant_order() {
        let variants = all_variants();

        // Verify variant identity by matching. Order must be exactly:
        // 0=Slashing, 1=Stake, 2=AntiSelfDealing, 3=UserDelete,
        // 4=DaSync, 5=Governance, 6=Committee, 7=DaFallback, 8=Compute
        match &variants[0] {
            AuditLogEvent::SlashingExecuted { .. } => {}
            other => assert!(false, "variant 0 must be SlashingExecuted, got {:?}", other),
        }
        match &variants[1] {
            AuditLogEvent::StakeUpdated { .. } => {}
            other => assert!(false, "variant 1 must be StakeUpdated, got {:?}", other),
        }
        match &variants[2] {
            AuditLogEvent::AntiSelfDealingViolation { .. } => {}
            other => assert!(false, "variant 2 must be AntiSelfDealingViolation, got {:?}", other),
        }
        match &variants[3] {
            AuditLogEvent::UserControlledDelete { .. } => {}
            other => assert!(false, "variant 3 must be UserControlledDelete, got {:?}", other),
        }
        match &variants[4] {
            AuditLogEvent::DaSyncSequenceUpdate { .. } => {}
            other => assert!(false, "variant 4 must be DaSyncSequenceUpdate, got {:?}", other),
        }
        match &variants[5] {
            AuditLogEvent::GovernanceProposalEvent { .. } => {}
            other => assert!(false, "variant 5 must be GovernanceProposalEvent, got {:?}", other),
        }
        match &variants[6] {
            AuditLogEvent::CommitteeRotationEvent { .. } => {}
            other => assert!(false, "variant 6 must be CommitteeRotationEvent, got {:?}", other),
        }
        match &variants[7] {
            AuditLogEvent::DaFallbackEvent { .. } => {}
            other => assert!(false, "variant 7 must be DaFallbackEvent, got {:?}", other),
        }
        match &variants[8] {
            AuditLogEvent::ComputeChallengeEvent { .. } => {}
            other => assert!(false, "variant 8 must be ComputeChallengeEvent, got {:?}", other),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 3: audit_event_serialization_roundtrip
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_event_serialization_roundtrip() {
        let variants = all_variants();

        for (i, event) in variants.iter().enumerate() {
            let encoded = bincode::serialize(event);
            match encoded {
                Ok(bytes) => {
                    assert!(!bytes.is_empty(), "variant {} must encode to non-empty bytes", i);

                    let decoded: Result<AuditLogEvent, _> = bincode::deserialize(&bytes);
                    match decoded {
                        Ok(roundtripped) => {
                            assert_eq!(
                                event, &roundtripped,
                                "variant {} roundtrip must preserve data",
                                i
                            );
                        }
                        Err(e) => {
                            assert!(false, "variant {} decode failed: {}", i, e);
                        }
                    }
                }
                Err(e) => {
                    assert!(false, "variant {} encode failed: {}", i, e);
                }
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 4: audit_event_schema_version_constant
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_event_schema_version_constant() {
        assert_eq!(AUDIT_EVENT_SCHEMA_VERSION, 1, "schema version must be 1");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 5: audit_event_fields_exist
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_event_fields_exist() {
        // Verify every variant has version + timestamp_ms fields accessible.
        let variants = all_variants();

        for (i, event) in variants.iter().enumerate() {
            let (v, ts) = match event {
                AuditLogEvent::SlashingExecuted { version, timestamp_ms } => (*version, *timestamp_ms),
                AuditLogEvent::StakeUpdated { version, timestamp_ms } => (*version, *timestamp_ms),
                AuditLogEvent::AntiSelfDealingViolation { version, timestamp_ms } => (*version, *timestamp_ms),
                AuditLogEvent::UserControlledDelete { version, timestamp_ms } => (*version, *timestamp_ms),
                AuditLogEvent::DaSyncSequenceUpdate { version, timestamp_ms } => (*version, *timestamp_ms),
                AuditLogEvent::GovernanceProposalEvent { version, timestamp_ms } => (*version, *timestamp_ms),
                AuditLogEvent::CommitteeRotationEvent { version, timestamp_ms } => (*version, *timestamp_ms),
                AuditLogEvent::DaFallbackEvent { version, timestamp_ms } => (*version, *timestamp_ms),
                AuditLogEvent::ComputeChallengeEvent { version, timestamp_ms } => (*version, *timestamp_ms),
            };

            assert_eq!(v, AUDIT_EVENT_SCHEMA_VERSION, "variant {} version must match constant", i);
            assert!(ts > 0, "variant {} timestamp_ms must be > 0", i);
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 6: audit_event_no_extra_fields
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_event_no_extra_fields() {
        // Verify that constructing with ONLY version + timestamp_ms compiles
        // and produces the exact same struct as all_variants().
        // If a variant had extra required fields, this would fail to compile.

        let event = AuditLogEvent::SlashingExecuted {
            version: 1,
            timestamp_ms: 100,
        };
        match &event {
            AuditLogEvent::SlashingExecuted { version, timestamp_ms } => {
                assert_eq!(*version, 1);
                assert_eq!(*timestamp_ms, 100);
            }
            _ => assert!(false, "pattern match failed"),
        }

        let event2 = AuditLogEvent::ComputeChallengeEvent {
            version: 1,
            timestamp_ms: 200,
        };
        match &event2 {
            AuditLogEvent::ComputeChallengeEvent { version, timestamp_ms } => {
                assert_eq!(*version, 1);
                assert_eq!(*timestamp_ms, 200);
            }
            _ => assert!(false, "pattern match failed"),
        }

        // All 9 variants constructable with only 2 fields
        let _v1 = AuditLogEvent::SlashingExecuted { version: 1, timestamp_ms: 0 };
        let _v2 = AuditLogEvent::StakeUpdated { version: 1, timestamp_ms: 0 };
        let _v3 = AuditLogEvent::AntiSelfDealingViolation { version: 1, timestamp_ms: 0 };
        let _v4 = AuditLogEvent::UserControlledDelete { version: 1, timestamp_ms: 0 };
        let _v5 = AuditLogEvent::DaSyncSequenceUpdate { version: 1, timestamp_ms: 0 };
        let _v6 = AuditLogEvent::GovernanceProposalEvent { version: 1, timestamp_ms: 0 };
        let _v7 = AuditLogEvent::CommitteeRotationEvent { version: 1, timestamp_ms: 0 };
        let _v8 = AuditLogEvent::DaFallbackEvent { version: 1, timestamp_ms: 0 };
        let _v9 = AuditLogEvent::ComputeChallengeEvent { version: 1, timestamp_ms: 0 };
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 7: audit_event_send_sync
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_event_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AuditLogEvent>();
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 8: audit_event_clone_eq
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_event_clone_eq() {
        let event = AuditLogEvent::SlashingExecuted {
            version: 1,
            timestamp_ms: 1700000000,
        };
        let cloned = event.clone();
        assert_eq!(event, cloned, "Clone + PartialEq must work");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 9: audit_event_deterministic_encoding
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_event_deterministic_encoding() {
        let event = AuditLogEvent::GovernanceProposalEvent {
            version: 1,
            timestamp_ms: 1700000006,
        };

        let enc1 = bincode::serialize(&event);
        let enc2 = bincode::serialize(&event);

        match (enc1, enc2) {
            (Ok(a), Ok(b)) => {
                assert_eq!(a, b, "encoding must be deterministic");
            }
            _ => assert!(false, "serialization should not fail"),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 10: audit_event_different_variants_different_encoding
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_event_different_variants_different_encoding() {
        let e1 = AuditLogEvent::SlashingExecuted {
            version: 1,
            timestamp_ms: 1700000000,
        };
        let e2 = AuditLogEvent::StakeUpdated {
            version: 1,
            timestamp_ms: 1700000000,
        };

        let enc1 = bincode::serialize(&e1);
        let enc2 = bincode::serialize(&e2);

        match (enc1, enc2) {
            (Ok(a), Ok(b)) => {
                assert_ne!(a, b, "different variants must produce different encoding");
            }
            _ => assert!(false, "serialization should not fail"),
        }
    }
}