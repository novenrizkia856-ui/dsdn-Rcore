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
// SUPPORTING ENUMS
// ════════════════════════════════════════════════════════════════════════════════

/// Type of stake operation recorded in [`AuditLogEvent::StakeUpdated`].
///
/// # Thread Safety
///
/// `Send + Sync` — all variants are fieldless.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StakeOperation {
    /// Tokens delegated to a validator.
    Delegate,
    /// Tokens undelegated from a validator.
    Undelegate,
    /// Tokens redelegated from one validator to another.
    Redelegate,
}

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
    ///
    /// Fields expanded in Tahap 15.2.
    SlashingExecuted {
        /// Schema version for forward compatibility.
        version: u8,
        /// Unix timestamp in milliseconds (caller-provided).
        timestamp_ms: u64,
        /// Validator that executed or was subject to slashing.
        validator_id: String,
        /// Node that was slashed.
        node_id: String,
        /// Amount slashed in smallest unit (18 decimals).
        slash_amount: u128,
        /// Human-readable reason for slashing.
        reason: String,
        /// Epoch in which slashing occurred.
        epoch: u64,
        /// SHA3-256 hash of the slashing evidence.
        evidence_hash: [u8; 32],
    },

    // ── Variant 2 ────────────────────────────────────────────────────────────
    /// Stake was delegated, undelegated, or redelegated.
    ///
    /// Produced by: chain crate (staking state transitions).
    ///
    /// Fields expanded in Tahap 15.2.
    StakeUpdated {
        /// Schema version for forward compatibility.
        version: u8,
        /// Unix timestamp in milliseconds (caller-provided).
        timestamp_ms: u64,
        /// Address of the staker performing the operation.
        staker_address: String,
        /// Type of stake operation.
        operation: StakeOperation,
        /// Amount staked/unstaked in smallest unit (18 decimals).
        amount: u128,
        /// Target validator for the operation.
        validator_id: String,
        /// Epoch in which the operation occurred.
        epoch: u64,
    },

    // ── Variant 3 ────────────────────────────────────────────────────────────
    /// Anti-self-dealing violation detected during claim validation.
    ///
    /// Produced by: chain crate (claim validation pipeline).
    ///
    /// Fields expanded in Tahap 15.3.
    AntiSelfDealingViolation {
        /// Schema version for forward compatibility.
        version: u8,
        /// Unix timestamp in milliseconds (caller-provided).
        timestamp_ms: u64,
        /// Node that committed the violation.
        node_id: String,
        /// Submitter address that matched the node's operator.
        submitter_address: String,
        /// SHA3-256 hash of the receipt involved.
        receipt_hash: [u8; 32],
        /// Detection method (e.g. `"direct_match"`, `"owner_match"`).
        detection_type: String,
        /// Whether a penalty was applied as a result.
        penalty_applied: bool,
    },

    // ── Variant 4 ────────────────────────────────────────────────────────────
    /// User-initiated data deletion request.
    ///
    /// Produced by: ingress crate (user-facing API).
    ///
    /// Fields expanded in Tahap 15.3.
    UserControlledDelete {
        /// Schema version for forward compatibility.
        version: u8,
        /// Unix timestamp in milliseconds (caller-provided).
        timestamp_ms: u64,
        /// Hash of the chunk requested for deletion.
        chunk_hash: String,
        /// ID of the user requesting deletion.
        requester_id: String,
        /// Human-readable reason for deletion.
        reason: String,
        /// Whether the deletion was authorized by the system.
        authorized: bool,
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
                version: 1,
                timestamp_ms: 1700000001,
                validator_id: "val-001".to_string(),
                node_id: "node-001".to_string(),
                slash_amount: 5000_000_000_000_000_000_000,
                reason: "double_sign".to_string(),
                epoch: 42,
                evidence_hash: [0xAB; 32],
            },
            AuditLogEvent::StakeUpdated {
                version: 1,
                timestamp_ms: 1700000002,
                staker_address: "staker-001".to_string(),
                operation: StakeOperation::Delegate,
                amount: 1000_000_000_000_000_000_000,
                validator_id: "val-002".to_string(),
                epoch: 42,
            },
            AuditLogEvent::AntiSelfDealingViolation {
                version: 1,
                timestamp_ms: 1700000003,
                node_id: "node-asd".to_string(),
                submitter_address: "submitter-asd".to_string(),
                receipt_hash: [0xCC; 32],
                detection_type: "direct_match".to_string(),
                penalty_applied: true,
            },
            AuditLogEvent::UserControlledDelete {
                version: 1,
                timestamp_ms: 1700000004,
                chunk_hash: "chunk-hash-del".to_string(),
                requester_id: "user-001".to_string(),
                reason: "user_request".to_string(),
                authorized: true,
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
    // TEST 5: audit_event_send_sync
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_event_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AuditLogEvent>();
        assert_send_sync::<StakeOperation>();
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 6: audit_event_deterministic_encoding
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
    // 15.2 TESTS
    // ════════════════════════════════════════════════════════════════════════

    // ════════════════════════════════════════════════════════════════════════
    // TEST 7: slashing_executed_fields_exist
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn slashing_executed_fields_exist() {
        let event = AuditLogEvent::SlashingExecuted {
            version: 1,
            timestamp_ms: 1700000000,
            validator_id: "val-abc".to_string(),
            node_id: "node-xyz".to_string(),
            slash_amount: 9999,
            reason: "offline".to_string(),
            epoch: 100,
            evidence_hash: [0xFF; 32],
        };

        match &event {
            AuditLogEvent::SlashingExecuted {
                version,
                timestamp_ms,
                validator_id,
                node_id,
                slash_amount,
                reason,
                epoch,
                evidence_hash,
            } => {
                assert_eq!(*version, 1u8);
                assert_eq!(*timestamp_ms, 1700000000u64);
                assert_eq!(validator_id, "val-abc");
                assert_eq!(node_id, "node-xyz");
                assert_eq!(*slash_amount, 9999u128);
                assert_eq!(reason, "offline");
                assert_eq!(*epoch, 100u64);
                assert_eq!(evidence_hash.len(), 32);
                assert_eq!(evidence_hash[0], 0xFF);
            }
            _ => assert!(false, "pattern match failed"),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 8: slashing_executed_serialization_roundtrip
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn slashing_executed_serialization_roundtrip() {
        let event = AuditLogEvent::SlashingExecuted {
            version: 1,
            timestamp_ms: 1700000000,
            validator_id: "val-roundtrip".to_string(),
            node_id: "node-roundtrip".to_string(),
            slash_amount: u128::MAX,
            reason: "test_reason".to_string(),
            epoch: u64::MAX,
            evidence_hash: [0xDE; 32],
        };

        let encoded = bincode::serialize(&event);
        match encoded {
            Ok(bytes) => {
                assert!(!bytes.is_empty());
                let decoded: Result<AuditLogEvent, _> = bincode::deserialize(&bytes);
                match decoded {
                    Ok(rt) => assert_eq!(event, rt),
                    Err(e) => assert!(false, "decode failed: {}", e),
                }
            }
            Err(e) => assert!(false, "encode failed: {}", e),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 9: stake_updated_fields_exist
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn stake_updated_fields_exist() {
        let event = AuditLogEvent::StakeUpdated {
            version: 1,
            timestamp_ms: 1700000000,
            staker_address: "staker-abc".to_string(),
            operation: StakeOperation::Undelegate,
            amount: 500_000_000_000_000_000_000,
            validator_id: "val-def".to_string(),
            epoch: 50,
        };

        match &event {
            AuditLogEvent::StakeUpdated {
                version,
                timestamp_ms,
                staker_address,
                operation,
                amount,
                validator_id,
                epoch,
            } => {
                assert_eq!(*version, 1u8);
                assert_eq!(*timestamp_ms, 1700000000u64);
                assert_eq!(staker_address, "staker-abc");
                assert_eq!(*operation, StakeOperation::Undelegate);
                assert_eq!(*amount, 500_000_000_000_000_000_000u128);
                assert_eq!(validator_id, "val-def");
                assert_eq!(*epoch, 50u64);
            }
            _ => assert!(false, "pattern match failed"),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 10: stake_updated_serialization_roundtrip
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn stake_updated_serialization_roundtrip() {
        let ops = [
            StakeOperation::Delegate,
            StakeOperation::Undelegate,
            StakeOperation::Redelegate,
        ];

        for op in &ops {
            let event = AuditLogEvent::StakeUpdated {
                version: 1,
                timestamp_ms: 1700000000,
                staker_address: "staker-rt".to_string(),
                operation: op.clone(),
                amount: 42,
                validator_id: "val-rt".to_string(),
                epoch: 1,
            };

            let encoded = bincode::serialize(&event);
            match encoded {
                Ok(bytes) => {
                    assert!(!bytes.is_empty());
                    let decoded: Result<AuditLogEvent, _> = bincode::deserialize(&bytes);
                    match decoded {
                        Ok(rt) => assert_eq!(event, rt),
                        Err(e) => assert!(false, "decode failed for {:?}: {}", op, e),
                    }
                }
                Err(e) => assert!(false, "encode failed for {:?}: {}", op, e),
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 11: stake_operation_enum_variants
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn stake_operation_enum_variants() {
        // All 3 variants constructable
        let d = StakeOperation::Delegate;
        let u = StakeOperation::Undelegate;
        let r = StakeOperation::Redelegate;

        // They are distinct
        assert_ne!(d, u);
        assert_ne!(u, r);
        assert_ne!(d, r);

        // Clone + Eq
        assert_eq!(d.clone(), StakeOperation::Delegate);
        assert_eq!(u.clone(), StakeOperation::Undelegate);
        assert_eq!(r.clone(), StakeOperation::Redelegate);

        // Serialization roundtrip for each
        for op in &[d, u, r] {
            let encoded = bincode::serialize(op);
            match encoded {
                Ok(bytes) => {
                    let decoded: Result<StakeOperation, _> = bincode::deserialize(&bytes);
                    match decoded {
                        Ok(rt) => assert_eq!(op, &rt),
                        Err(e) => assert!(false, "StakeOperation decode failed: {}", e),
                    }
                }
                Err(e) => assert!(false, "StakeOperation encode failed: {}", e),
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 12: audit_event_variant_order_preserved
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_event_variant_order_preserved() {
        // Bincode encodes enum variants as u32 discriminant.
        // Variant 0 = SlashingExecuted, Variant 1 = StakeUpdated.
        // After field expansion, discriminant must NOT change.
        let v0 = AuditLogEvent::SlashingExecuted {
            version: 1,
            timestamp_ms: 0,
            validator_id: String::new(),
            node_id: String::new(),
            slash_amount: 0,
            reason: String::new(),
            epoch: 0,
            evidence_hash: [0u8; 32],
        };
        let v1 = AuditLogEvent::StakeUpdated {
            version: 1,
            timestamp_ms: 0,
            staker_address: String::new(),
            operation: StakeOperation::Delegate,
            amount: 0,
            validator_id: String::new(),
            epoch: 0,
        };

        let enc0 = bincode::serialize(&v0);
        let enc1 = bincode::serialize(&v1);

        match (enc0, enc1) {
            (Ok(b0), Ok(b1)) => {
                // First 4 bytes = u32 discriminant (bincode default)
                assert!(b0.len() >= 4);
                assert!(b1.len() >= 4);

                let disc0 = u32::from_le_bytes([b0[0], b0[1], b0[2], b0[3]]);
                let disc1 = u32::from_le_bytes([b1[0], b1[1], b1[2], b1[3]]);

                assert_eq!(disc0, 0, "SlashingExecuted must be discriminant 0");
                assert_eq!(disc1, 1, "StakeUpdated must be discriminant 1");
            }
            _ => assert!(false, "serialization should not fail"),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 13: evidence_hash_length_validation
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn evidence_hash_length_validation() {
        let event = AuditLogEvent::SlashingExecuted {
            version: 1,
            timestamp_ms: 1700000000,
            validator_id: "val".to_string(),
            node_id: "node".to_string(),
            slash_amount: 0,
            reason: "test".to_string(),
            epoch: 0,
            evidence_hash: [0u8; 32],
        };

        match &event {
            AuditLogEvent::SlashingExecuted { evidence_hash, .. } => {
                assert_eq!(evidence_hash.len(), 32, "evidence_hash must be exactly 32 bytes");
            }
            _ => assert!(false, "wrong variant"),
        }

        // All-zeros hash
        let zero_event = AuditLogEvent::SlashingExecuted {
            version: 1,
            timestamp_ms: 0,
            validator_id: String::new(),
            node_id: String::new(),
            slash_amount: 0,
            reason: String::new(),
            epoch: 0,
            evidence_hash: [0u8; 32],
        };
        let all_ff_event = AuditLogEvent::SlashingExecuted {
            version: 1,
            timestamp_ms: 0,
            validator_id: String::new(),
            node_id: String::new(),
            slash_amount: 0,
            reason: String::new(),
            epoch: 0,
            evidence_hash: [0xFF; 32],
        };

        // Different hashes must produce different events
        assert_ne!(zero_event, all_ff_event);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14: no_extra_fields_present
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn no_extra_fields_present() {
        // SlashingExecuted: exactly 8 fields compile
        let _s = AuditLogEvent::SlashingExecuted {
            version: 1,
            timestamp_ms: 0,
            validator_id: String::new(),
            node_id: String::new(),
            slash_amount: 0,
            reason: String::new(),
            epoch: 0,
            evidence_hash: [0u8; 32],
        };

        // StakeUpdated: exactly 7 fields compile
        let _u = AuditLogEvent::StakeUpdated {
            version: 1,
            timestamp_ms: 0,
            staker_address: String::new(),
            operation: StakeOperation::Delegate,
            amount: 0,
            validator_id: String::new(),
            epoch: 0,
        };

        // Other variants: still only 2 fields (unchanged)
        let _v3 = AuditLogEvent::AntiSelfDealingViolation {
            version: 1, timestamp_ms: 0,
            node_id: String::new(), submitter_address: String::new(),
            receipt_hash: [0u8; 32], detection_type: String::new(),
            penalty_applied: false,
        };
        let _v4 = AuditLogEvent::UserControlledDelete {
            version: 1, timestamp_ms: 0,
            chunk_hash: String::new(), requester_id: String::new(),
            reason: String::new(), authorized: false,
        };
        let _v5 = AuditLogEvent::DaSyncSequenceUpdate { version: 1, timestamp_ms: 0 };
        let _v6 = AuditLogEvent::GovernanceProposalEvent { version: 1, timestamp_ms: 0 };
        let _v7 = AuditLogEvent::CommitteeRotationEvent { version: 1, timestamp_ms: 0 };
        let _v8 = AuditLogEvent::DaFallbackEvent { version: 1, timestamp_ms: 0 };
        let _v9 = AuditLogEvent::ComputeChallengeEvent { version: 1, timestamp_ms: 0 };
    }

    // ════════════════════════════════════════════════════════════════════════
    // 15.3 TESTS
    // ════════════════════════════════════════════════════════════════════════

    // ════════════════════════════════════════════════════════════════════════
    // TEST 15: anti_self_dealing_fields_exist
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn anti_self_dealing_fields_exist() {
        let event = AuditLogEvent::AntiSelfDealingViolation {
            version: 1,
            timestamp_ms: 1700000000,
            node_id: "node-bad".to_string(),
            submitter_address: "addr-bad".to_string(),
            receipt_hash: [0xAB; 32],
            detection_type: "direct_match".to_string(),
            penalty_applied: true,
        };

        match &event {
            AuditLogEvent::AntiSelfDealingViolation {
                version,
                timestamp_ms,
                node_id,
                submitter_address,
                receipt_hash,
                detection_type,
                penalty_applied,
            } => {
                assert_eq!(*version, 1u8);
                assert_eq!(*timestamp_ms, 1700000000u64);
                assert_eq!(node_id, "node-bad");
                assert_eq!(submitter_address, "addr-bad");
                assert_eq!(receipt_hash.len(), 32);
                assert_eq!(receipt_hash[0], 0xAB);
                assert_eq!(detection_type, "direct_match");
                assert!(*penalty_applied);
            }
            _ => assert!(false, "pattern match failed"),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 16: anti_self_dealing_serialization_roundtrip
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn anti_self_dealing_serialization_roundtrip() {
        let event = AuditLogEvent::AntiSelfDealingViolation {
            version: 1,
            timestamp_ms: 1700000000,
            node_id: "node-rt".to_string(),
            submitter_address: "addr-rt".to_string(),
            receipt_hash: [0xDE; 32],
            detection_type: "owner_match".to_string(),
            penalty_applied: false,
        };

        let encoded = bincode::serialize(&event);
        match encoded {
            Ok(bytes) => {
                assert!(!bytes.is_empty());
                let decoded: Result<AuditLogEvent, _> = bincode::deserialize(&bytes);
                match decoded {
                    Ok(rt) => assert_eq!(event, rt),
                    Err(e) => assert!(false, "decode failed: {}", e),
                }
            }
            Err(e) => assert!(false, "encode failed: {}", e),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 17: anti_self_dealing_receipt_hash_length
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn anti_self_dealing_receipt_hash_length() {
        let event = AuditLogEvent::AntiSelfDealingViolation {
            version: 1,
            timestamp_ms: 0,
            node_id: String::new(),
            submitter_address: String::new(),
            receipt_hash: [0u8; 32],
            detection_type: String::new(),
            penalty_applied: false,
        };

        match &event {
            AuditLogEvent::AntiSelfDealingViolation { receipt_hash, .. } => {
                assert_eq!(receipt_hash.len(), 32, "receipt_hash must be exactly 32 bytes");
            }
            _ => assert!(false, "wrong variant"),
        }

        // Different hashes produce different events
        let e_zero = AuditLogEvent::AntiSelfDealingViolation {
            version: 1, timestamp_ms: 0,
            node_id: String::new(), submitter_address: String::new(),
            receipt_hash: [0u8; 32], detection_type: String::new(),
            penalty_applied: false,
        };
        let e_ff = AuditLogEvent::AntiSelfDealingViolation {
            version: 1, timestamp_ms: 0,
            node_id: String::new(), submitter_address: String::new(),
            receipt_hash: [0xFF; 32], detection_type: String::new(),
            penalty_applied: false,
        };
        assert_ne!(e_zero, e_ff);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 18: user_delete_fields_exist
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn user_delete_fields_exist() {
        let event = AuditLogEvent::UserControlledDelete {
            version: 1,
            timestamp_ms: 1700000000,
            chunk_hash: "chunk-abc".to_string(),
            requester_id: "user-xyz".to_string(),
            reason: "gdpr_request".to_string(),
            authorized: true,
        };

        match &event {
            AuditLogEvent::UserControlledDelete {
                version,
                timestamp_ms,
                chunk_hash,
                requester_id,
                reason,
                authorized,
            } => {
                assert_eq!(*version, 1u8);
                assert_eq!(*timestamp_ms, 1700000000u64);
                assert_eq!(chunk_hash, "chunk-abc");
                assert_eq!(requester_id, "user-xyz");
                assert_eq!(reason, "gdpr_request");
                assert!(*authorized);
            }
            _ => assert!(false, "pattern match failed"),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 19: user_delete_serialization_roundtrip
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn user_delete_serialization_roundtrip() {
        let event = AuditLogEvent::UserControlledDelete {
            version: 1,
            timestamp_ms: u64::MAX,
            chunk_hash: "chunk-roundtrip".to_string(),
            requester_id: "user-roundtrip".to_string(),
            reason: "test".to_string(),
            authorized: false,
        };

        let encoded = bincode::serialize(&event);
        match encoded {
            Ok(bytes) => {
                assert!(!bytes.is_empty());
                let decoded: Result<AuditLogEvent, _> = bincode::deserialize(&bytes);
                match decoded {
                    Ok(rt) => assert_eq!(event, rt),
                    Err(e) => assert!(false, "decode failed: {}", e),
                }
            }
            Err(e) => assert!(false, "encode failed: {}", e),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 20: user_delete_authorized_flag
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn user_delete_authorized_flag() {
        let auth = AuditLogEvent::UserControlledDelete {
            version: 1, timestamp_ms: 0,
            chunk_hash: "c".to_string(), requester_id: "u".to_string(),
            reason: "r".to_string(), authorized: true,
        };
        let unauth = AuditLogEvent::UserControlledDelete {
            version: 1, timestamp_ms: 0,
            chunk_hash: "c".to_string(), requester_id: "u".to_string(),
            reason: "r".to_string(), authorized: false,
        };

        // Different authorized flags produce different events
        assert_ne!(auth, unauth);

        // Both serialize correctly
        for event in &[auth, unauth] {
            let encoded = bincode::serialize(event);
            match encoded {
                Ok(bytes) => {
                    let decoded: Result<AuditLogEvent, _> = bincode::deserialize(&bytes);
                    match decoded {
                        Ok(rt) => assert_eq!(event, &rt),
                        Err(e) => assert!(false, "decode failed: {}", e),
                    }
                }
                Err(e) => assert!(false, "encode failed: {}", e),
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 21: variant_order_preserved_15_3
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn variant_order_preserved_15_3() {
        // Verify bincode discriminants for variants 2 and 3.
        let v2 = AuditLogEvent::AntiSelfDealingViolation {
            version: 1, timestamp_ms: 0,
            node_id: String::new(), submitter_address: String::new(),
            receipt_hash: [0u8; 32], detection_type: String::new(),
            penalty_applied: false,
        };
        let v3 = AuditLogEvent::UserControlledDelete {
            version: 1, timestamp_ms: 0,
            chunk_hash: String::new(), requester_id: String::new(),
            reason: String::new(), authorized: false,
        };

        let enc2 = bincode::serialize(&v2);
        let enc3 = bincode::serialize(&v3);

        match (enc2, enc3) {
            (Ok(b2), Ok(b3)) => {
                assert!(b2.len() >= 4);
                assert!(b3.len() >= 4);

                let disc2 = u32::from_le_bytes([b2[0], b2[1], b2[2], b2[3]]);
                let disc3 = u32::from_le_bytes([b3[0], b3[1], b3[2], b3[3]]);

                assert_eq!(disc2, 2, "AntiSelfDealingViolation must be discriminant 2");
                assert_eq!(disc3, 3, "UserControlledDelete must be discriminant 3");
            }
            _ => assert!(false, "serialization should not fail"),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 22: no_extra_fields_15_3
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn no_extra_fields_15_3() {
        // AntiSelfDealingViolation: exactly 7 fields
        let _asd = AuditLogEvent::AntiSelfDealingViolation {
            version: 1,
            timestamp_ms: 0,
            node_id: String::new(),
            submitter_address: String::new(),
            receipt_hash: [0u8; 32],
            detection_type: String::new(),
            penalty_applied: false,
        };

        // UserControlledDelete: exactly 6 fields
        let _ucd = AuditLogEvent::UserControlledDelete {
            version: 1,
            timestamp_ms: 0,
            chunk_hash: String::new(),
            requester_id: String::new(),
            reason: String::new(),
            authorized: false,
        };
    }
}