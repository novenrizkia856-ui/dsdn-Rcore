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
use sha3::{Sha3_256, Digest};

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

/// Governance proposal lifecycle status for [`AuditLogEvent::GovernanceProposalEvent`].
///
/// # Thread Safety
///
/// `Send + Sync` — all variants are fieldless.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovernanceStatus {
    /// Proposal submitted, awaiting review.
    Submitted,
    /// Proposal approved by governance.
    Approved,
    /// Proposal rejected by governance.
    Rejected,
    /// Proposal executed on-chain.
    Executed,
    /// Proposal expired without action.
    Expired,
}

/// DA fallback action type for [`AuditLogEvent::DaFallbackEvent`].
///
/// # Thread Safety
///
/// `Send + Sync` — all variants are fieldless.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DaFallbackAction {
    /// DA fallback layer was activated (primary unavailable).
    Activated,
    /// DA fallback layer was deactivated (primary restored).
    Deactivated,
}

/// Compute challenge outcome for [`AuditLogEvent::ComputeChallengeEvent`].
///
/// # Thread Safety
///
/// `Send + Sync` — all variants are fieldless.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChallengeOutcome {
    /// Challenge issued, awaiting resolution.
    Pending,
    /// Challenge resolved — no fraud detected.
    Cleared,
    /// Challenge resolved — fraud confirmed.
    Fraud,
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
    ///
    /// Fields expanded in Tahap 15.4.
    DaSyncSequenceUpdate {
        /// Schema version for forward compatibility.
        version: u8,
        /// Unix timestamp in milliseconds (caller-provided).
        timestamp_ms: u64,
        /// DA source identifier (e.g. `"celestia"`, `"validator_quorum"`, `"emergency"`).
        da_source: String,
        /// New sequence number after sync.
        sequence_number: u64,
        /// Previous sequence number before sync.
        previous_sequence: u64,
        /// Number of blobs processed in this sync batch.
        blob_count: u64,
    },

    // ── Variant 6 ────────────────────────────────────────────────────────────
    /// Governance proposal lifecycle event (submit, approve, reject, execute).
    ///
    /// Produced by: chain crate (governance module).
    ///
    /// Fields expanded in Tahap 15.4.
    GovernanceProposalEvent {
        /// Schema version for forward compatibility.
        version: u8,
        /// Unix timestamp in milliseconds (caller-provided).
        timestamp_ms: u64,
        /// Unique proposal identifier.
        proposal_id: String,
        /// Address of the proposer.
        proposer_address: String,
        /// Type of proposal (e.g. `"parameter_change"`, `"treasury_spend"`).
        proposal_type: String,
        /// Delay window in seconds before execution.
        delay_window_secs: u64,
        /// Current lifecycle status of the proposal.
        status: GovernanceStatus,
    },

    // ── Variant 7 ────────────────────────────────────────────────────────────
    /// Coordinator committee rotation event.
    ///
    /// Producer: Tahap 20 (committee rotation mechanism).
    /// Hook is defined now; producer will call it when rotation is active.
    ///
    /// Fields expanded in Tahap 15.5.
    CommitteeRotationEvent {
        /// Schema version for forward compatibility.
        version: u8,
        /// Unix timestamp in milliseconds (caller-provided).
        timestamp_ms: u64,
        /// Epoch before rotation.
        old_epoch: u64,
        /// Epoch after rotation.
        new_epoch: u64,
        /// SHA3-256 hash of the old committee.
        old_committee_hash: [u8; 32],
        /// SHA3-256 hash of the new committee.
        new_committee_hash: [u8; 32],
        /// Number of members in the new committee.
        member_count: u32,
        /// Signing threshold of the new committee.
        threshold: u32,
    },

    // ── Variant 8 ────────────────────────────────────────────────────────────
    /// DA fallback activation or deactivation event.
    ///
    /// Producer: Tahap 15.1 integration (coordinator crate).
    /// Emitted when DA source changes (primary ↔ secondary ↔ emergency).
    ///
    /// Fields expanded in Tahap 15.5.
    DaFallbackEvent {
        /// Schema version for forward compatibility.
        version: u8,
        /// Unix timestamp in milliseconds (caller-provided).
        timestamp_ms: u64,
        /// Whether fallback was activated or deactivated.
        action: DaFallbackAction,
        /// DA source before the transition.
        previous_source: String,
        /// DA source after the transition.
        new_source: String,
        /// Human-readable reason for the transition.
        reason: String,
        /// Last known Celestia block height before transition.
        celestia_last_height: u64,
    },

    // ── Variant 9 ────────────────────────────────────────────────────────────
    /// Compute challenge event (challenge issued, cleared, or fraud detected).
    ///
    /// Producer: Tahap 18.1 (fraud proof system).
    /// Hook is defined now; producer will call it when challenge system is active.
    ///
    /// Fields expanded in Tahap 15.5.
    ComputeChallengeEvent {
        /// Schema version for forward compatibility.
        version: u8,
        /// Unix timestamp in milliseconds (caller-provided).
        timestamp_ms: u64,
        /// SHA3-256 hash of the receipt being challenged.
        receipt_hash: [u8; 32],
        /// ID of the entity issuing the challenge.
        challenger_id: String,
        /// ID of the node being challenged.
        challenged_node_id: String,
        /// Type of challenge (e.g. `"execution_mismatch"`, `"resource_inflation"`).
        challenge_type: String,
        /// Current outcome of the challenge.
        outcome: ChallengeOutcome,
    },
}

// ════════════════════════════════════════════════════════════════════════════════
// AUDIT LOG ENTRY (Tahap 15.6)
// ════════════════════════════════════════════════════════════════════════════════

/// Hash-chained audit log entry wrapping an [`AuditLogEvent`].
///
/// Forms a tamper-evident linked list: each entry's `prev_hash` points to the
/// preceding entry's `entry_hash`, and `sequence` increments monotonically.
///
/// ## Hash Chain
///
/// ```text
/// Entry 1          Entry 2          Entry 3
/// ┌──────────┐     ┌──────────┐     ┌──────────┐
/// │ seq=1    │     │ seq=2    │     │ seq=3    │
/// │ prev=[0] │────▶│ prev=H1  │────▶│ prev=H2  │
/// │ event=E1 │     │ event=E2 │     │ event=E3 │
/// │ hash=H1  │     │ hash=H2  │     │ hash=H3  │
/// └──────────┘     └──────────┘     └──────────┘
/// ```
///
/// ## Hash Formula
///
/// `entry_hash = SHA3-256(bincode(sequence, timestamp_ms, prev_hash, event))`
///
/// The `entry_hash` field itself is **excluded** from the hash input.
///
/// ## Thread Safety
///
/// `Send + Sync` — all fields are owned, no interior mutability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditLogEntry {
    /// Global monotonic sequence number (1-based).
    pub sequence: u64,
    /// Entry creation timestamp in Unix milliseconds (caller-provided).
    pub timestamp_ms: u64,
    /// SHA3-256 hash of the previous entry. Zero ([0u8; 32]) for the first entry.
    pub prev_hash: [u8; 32],
    /// The audit event payload.
    pub event: AuditLogEvent,
    /// SHA3-256 hash of (sequence, timestamp_ms, prev_hash, event).
    pub entry_hash: [u8; 32],
}

/// Internal struct for computing entry hash.
/// Contains all fields EXCEPT entry_hash.
#[derive(Serialize)]
struct AuditLogEntryHashInput<'a> {
    sequence: u64,
    timestamp_ms: u64,
    prev_hash: &'a [u8; 32],
    event: &'a AuditLogEvent,
}

impl AuditLogEntry {
    /// Compute the entry hash from (sequence, timestamp_ms, prev_hash, event).
    ///
    /// The `entry_hash` field is **excluded** from the hash input.
    ///
    /// ## Hash Pipeline
    ///
    /// 1. Build `(sequence, timestamp_ms, prev_hash, event)` tuple
    /// 2. Serialize via `bincode` (deterministic, little-endian)
    /// 3. Hash via SHA3-256
    ///
    /// Returns `[u8; 32]`. If serialization fails (should not happen for
    /// valid `AuditLogEvent`), returns hash of empty bytes.
    pub fn compute_entry_hash(&self) -> [u8; 32] {
        let input = AuditLogEntryHashInput {
            sequence: self.sequence,
            timestamp_ms: self.timestamp_ms,
            prev_hash: &self.prev_hash,
            event: &self.event,
        };
        let encoded = bincode::serialize(&input).unwrap_or_default();
        let mut hasher = Sha3_256::new();
        hasher.update(&encoded);
        hasher.finalize().into()
    }

    /// Verify this entry's chain link to the previous entry.
    ///
    /// Returns `true` if and only if:
    /// 1. `self.prev_hash == prev.entry_hash`
    /// 2. `self.sequence == prev.sequence + 1` (overflow-safe)
    ///
    /// Deterministic, no panic, no side effects.
    pub fn verify_chain(&self, prev: &AuditLogEntry) -> bool {
        let hash_matches = self.prev_hash == prev.entry_hash;
        let seq_matches = prev.sequence.checked_add(1).map_or(false, |expected| {
            self.sequence == expected
        });
        hash_matches && seq_matches
    }
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
                version: 1,
                timestamp_ms: 1700000005,
                da_source: "celestia".to_string(),
                sequence_number: 100,
                previous_sequence: 99,
                blob_count: 5,
            },
            AuditLogEvent::GovernanceProposalEvent {
                version: 1,
                timestamp_ms: 1700000006,
                proposal_id: "prop-001".to_string(),
                proposer_address: "proposer-001".to_string(),
                proposal_type: "parameter_change".to_string(),
                delay_window_secs: 86400,
                status: GovernanceStatus::Submitted,
            },
            AuditLogEvent::CommitteeRotationEvent {
                version: 1,
                timestamp_ms: 1700000007,
                old_epoch: 10,
                new_epoch: 11,
                old_committee_hash: [0xAA; 32],
                new_committee_hash: [0xBB; 32],
                member_count: 5,
                threshold: 3,
            },
            AuditLogEvent::DaFallbackEvent {
                version: 1,
                timestamp_ms: 1700000008,
                action: DaFallbackAction::Activated,
                previous_source: "celestia".to_string(),
                new_source: "validator_quorum".to_string(),
                reason: "primary_timeout".to_string(),
                celestia_last_height: 999,
            },
            AuditLogEvent::ComputeChallengeEvent {
                version: 1,
                timestamp_ms: 1700000009,
                receipt_hash: [0xDD; 32],
                challenger_id: "challenger-001".to_string(),
                challenged_node_id: "node-challenged".to_string(),
                challenge_type: "execution_mismatch".to_string(),
                outcome: ChallengeOutcome::Pending,
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
            proposal_id: "prop-det".to_string(),
            proposer_address: "addr-det".to_string(),
            proposal_type: "test".to_string(),
            delay_window_secs: 3600,
            status: GovernanceStatus::Approved,
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
        let _v5 = AuditLogEvent::DaSyncSequenceUpdate {
            version: 1, timestamp_ms: 0,
            da_source: String::new(), sequence_number: 0,
            previous_sequence: 0, blob_count: 0,
        };
        let _v6 = AuditLogEvent::GovernanceProposalEvent {
            version: 1, timestamp_ms: 0,
            proposal_id: String::new(), proposer_address: String::new(),
            proposal_type: String::new(), delay_window_secs: 0,
            status: GovernanceStatus::Submitted,
        };
        let _v7 = AuditLogEvent::CommitteeRotationEvent {
            version: 1, timestamp_ms: 0,
            old_epoch: 0, new_epoch: 0,
            old_committee_hash: [0u8; 32], new_committee_hash: [0u8; 32],
            member_count: 0, threshold: 0,
        };
        let _v8 = AuditLogEvent::DaFallbackEvent {
            version: 1, timestamp_ms: 0,
            action: DaFallbackAction::Activated,
            previous_source: String::new(), new_source: String::new(),
            reason: String::new(), celestia_last_height: 0,
        };
        let _v9 = AuditLogEvent::ComputeChallengeEvent {
            version: 1, timestamp_ms: 0,
            receipt_hash: [0u8; 32],
            challenger_id: String::new(), challenged_node_id: String::new(),
            challenge_type: String::new(), outcome: ChallengeOutcome::Pending,
        };
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

    // ════════════════════════════════════════════════════════════════════════
    // 15.4 TESTS
    // ════════════════════════════════════════════════════════════════════════

    // ════════════════════════════════════════════════════════════════════════
    // TEST 23: da_sync_sequence_fields_exist
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn da_sync_sequence_fields_exist() {
        let event = AuditLogEvent::DaSyncSequenceUpdate {
            version: 1,
            timestamp_ms: 1700000000,
            da_source: "celestia".to_string(),
            sequence_number: 500,
            previous_sequence: 499,
            blob_count: 12,
        };

        match &event {
            AuditLogEvent::DaSyncSequenceUpdate {
                version,
                timestamp_ms,
                da_source,
                sequence_number,
                previous_sequence,
                blob_count,
            } => {
                assert_eq!(*version, 1u8);
                assert_eq!(*timestamp_ms, 1700000000u64);
                assert_eq!(da_source, "celestia");
                assert_eq!(*sequence_number, 500u64);
                assert_eq!(*previous_sequence, 499u64);
                assert_eq!(*blob_count, 12u64);
            }
            _ => assert!(false, "pattern match failed"),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 24: da_sync_sequence_serialization_roundtrip
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn da_sync_sequence_serialization_roundtrip() {
        let sources = ["celestia", "validator_quorum", "emergency"];

        for src in &sources {
            let event = AuditLogEvent::DaSyncSequenceUpdate {
                version: 1,
                timestamp_ms: u64::MAX,
                da_source: src.to_string(),
                sequence_number: u64::MAX,
                previous_sequence: u64::MAX - 1,
                blob_count: 0,
            };

            let encoded = bincode::serialize(&event);
            match encoded {
                Ok(bytes) => {
                    assert!(!bytes.is_empty());
                    let decoded: Result<AuditLogEvent, _> = bincode::deserialize(&bytes);
                    match decoded {
                        Ok(rt) => assert_eq!(event, rt),
                        Err(e) => assert!(false, "decode failed for {}: {}", src, e),
                    }
                }
                Err(e) => assert!(false, "encode failed for {}: {}", src, e),
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 25: governance_proposal_fields_exist
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn governance_proposal_fields_exist() {
        let event = AuditLogEvent::GovernanceProposalEvent {
            version: 1,
            timestamp_ms: 1700000000,
            proposal_id: "prop-123".to_string(),
            proposer_address: "addr-proposer".to_string(),
            proposal_type: "parameter_change".to_string(),
            delay_window_secs: 86400,
            status: GovernanceStatus::Executed,
        };

        match &event {
            AuditLogEvent::GovernanceProposalEvent {
                version,
                timestamp_ms,
                proposal_id,
                proposer_address,
                proposal_type,
                delay_window_secs,
                status,
            } => {
                assert_eq!(*version, 1u8);
                assert_eq!(*timestamp_ms, 1700000000u64);
                assert_eq!(proposal_id, "prop-123");
                assert_eq!(proposer_address, "addr-proposer");
                assert_eq!(proposal_type, "parameter_change");
                assert_eq!(*delay_window_secs, 86400u64);
                assert_eq!(*status, GovernanceStatus::Executed);
            }
            _ => assert!(false, "pattern match failed"),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 26: governance_proposal_serialization_roundtrip
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn governance_proposal_serialization_roundtrip() {
        let statuses = [
            GovernanceStatus::Submitted,
            GovernanceStatus::Approved,
            GovernanceStatus::Rejected,
            GovernanceStatus::Executed,
            GovernanceStatus::Expired,
        ];

        for st in &statuses {
            let event = AuditLogEvent::GovernanceProposalEvent {
                version: 1,
                timestamp_ms: 1700000000,
                proposal_id: "prop-rt".to_string(),
                proposer_address: "addr-rt".to_string(),
                proposal_type: "treasury_spend".to_string(),
                delay_window_secs: 3600,
                status: st.clone(),
            };

            let encoded = bincode::serialize(&event);
            match encoded {
                Ok(bytes) => {
                    assert!(!bytes.is_empty());
                    let decoded: Result<AuditLogEvent, _> = bincode::deserialize(&bytes);
                    match decoded {
                        Ok(rt) => assert_eq!(event, rt),
                        Err(e) => assert!(false, "decode failed for {:?}: {}", st, e),
                    }
                }
                Err(e) => assert!(false, "encode failed for {:?}: {}", st, e),
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 27: governance_status_enum_variants
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn governance_status_enum_variants() {
        let s = GovernanceStatus::Submitted;
        let a = GovernanceStatus::Approved;
        let r = GovernanceStatus::Rejected;
        let e = GovernanceStatus::Executed;
        let x = GovernanceStatus::Expired;

        // All distinct
        let all = [&s, &a, &r, &e, &x];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "variants {} and {} must differ", i, j);
            }
        }

        // Clone + Eq
        assert_eq!(s.clone(), GovernanceStatus::Submitted);
        assert_eq!(x.clone(), GovernanceStatus::Expired);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 28: governance_status_serialization
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn governance_status_serialization() {
        let statuses = [
            GovernanceStatus::Submitted,
            GovernanceStatus::Approved,
            GovernanceStatus::Rejected,
            GovernanceStatus::Executed,
            GovernanceStatus::Expired,
        ];

        for st in &statuses {
            let encoded = bincode::serialize(st);
            match encoded {
                Ok(bytes) => {
                    let decoded: Result<GovernanceStatus, _> = bincode::deserialize(&bytes);
                    match decoded {
                        Ok(rt) => assert_eq!(st, &rt),
                        Err(e) => assert!(false, "GovernanceStatus decode failed: {}", e),
                    }
                }
                Err(e) => assert!(false, "GovernanceStatus encode failed: {}", e),
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 29: variant_order_preserved_15_4
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn variant_order_preserved_15_4() {
        let v4 = AuditLogEvent::DaSyncSequenceUpdate {
            version: 1, timestamp_ms: 0,
            da_source: String::new(), sequence_number: 0,
            previous_sequence: 0, blob_count: 0,
        };
        let v5 = AuditLogEvent::GovernanceProposalEvent {
            version: 1, timestamp_ms: 0,
            proposal_id: String::new(), proposer_address: String::new(),
            proposal_type: String::new(), delay_window_secs: 0,
            status: GovernanceStatus::Submitted,
        };

        let enc4 = bincode::serialize(&v4);
        let enc5 = bincode::serialize(&v5);

        match (enc4, enc5) {
            (Ok(b4), Ok(b5)) => {
                assert!(b4.len() >= 4);
                assert!(b5.len() >= 4);

                let disc4 = u32::from_le_bytes([b4[0], b4[1], b4[2], b4[3]]);
                let disc5 = u32::from_le_bytes([b5[0], b5[1], b5[2], b5[3]]);

                assert_eq!(disc4, 4, "DaSyncSequenceUpdate must be discriminant 4");
                assert_eq!(disc5, 5, "GovernanceProposalEvent must be discriminant 5");
            }
            _ => assert!(false, "serialization should not fail"),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 30: no_extra_fields_15_4
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn no_extra_fields_15_4() {
        // DaSyncSequenceUpdate: exactly 6 fields
        let _ds = AuditLogEvent::DaSyncSequenceUpdate {
            version: 1,
            timestamp_ms: 0,
            da_source: String::new(),
            sequence_number: 0,
            previous_sequence: 0,
            blob_count: 0,
        };

        // GovernanceProposalEvent: exactly 7 fields
        let _gp = AuditLogEvent::GovernanceProposalEvent {
            version: 1,
            timestamp_ms: 0,
            proposal_id: String::new(),
            proposer_address: String::new(),
            proposal_type: String::new(),
            delay_window_secs: 0,
            status: GovernanceStatus::Submitted,
        };
    }

    // ════════════════════════════════════════════════════════════════════════
    // 15.5 TESTS
    // ════════════════════════════════════════════════════════════════════════

    // ════════════════════════════════════════════════════════════════════════
    // TEST 31: committee_rotation_event_fields_exist
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn committee_rotation_event_fields_exist() {
        let event = AuditLogEvent::CommitteeRotationEvent {
            version: 1,
            timestamp_ms: 1700000000,
            old_epoch: 10,
            new_epoch: 11,
            old_committee_hash: [0xAA; 32],
            new_committee_hash: [0xBB; 32],
            member_count: 7,
            threshold: 5,
        };

        match &event {
            AuditLogEvent::CommitteeRotationEvent {
                version, timestamp_ms, old_epoch, new_epoch,
                old_committee_hash, new_committee_hash,
                member_count, threshold,
            } => {
                assert_eq!(*version, 1u8);
                assert_eq!(*timestamp_ms, 1700000000u64);
                assert_eq!(*old_epoch, 10u64);
                assert_eq!(*new_epoch, 11u64);
                assert_eq!(old_committee_hash.len(), 32);
                assert_eq!(old_committee_hash[0], 0xAA);
                assert_eq!(new_committee_hash.len(), 32);
                assert_eq!(new_committee_hash[0], 0xBB);
                assert_eq!(*member_count, 7u32);
                assert_eq!(*threshold, 5u32);
            }
            _ => assert!(false, "pattern match failed"),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 32: committee_rotation_event_serialization
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn committee_rotation_event_serialization() {
        let event = AuditLogEvent::CommitteeRotationEvent {
            version: 1,
            timestamp_ms: u64::MAX,
            old_epoch: u64::MAX,
            new_epoch: 0,
            old_committee_hash: [0xFF; 32],
            new_committee_hash: [0x00; 32],
            member_count: u32::MAX,
            threshold: 0,
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
    // TEST 33: da_fallback_event_fields_exist
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn da_fallback_event_fields_exist() {
        let event = AuditLogEvent::DaFallbackEvent {
            version: 1,
            timestamp_ms: 1700000000,
            action: DaFallbackAction::Activated,
            previous_source: "celestia".to_string(),
            new_source: "validator_quorum".to_string(),
            reason: "timeout".to_string(),
            celestia_last_height: 12345,
        };

        match &event {
            AuditLogEvent::DaFallbackEvent {
                version, timestamp_ms, action,
                previous_source, new_source, reason,
                celestia_last_height,
            } => {
                assert_eq!(*version, 1u8);
                assert_eq!(*timestamp_ms, 1700000000u64);
                assert_eq!(*action, DaFallbackAction::Activated);
                assert_eq!(previous_source, "celestia");
                assert_eq!(new_source, "validator_quorum");
                assert_eq!(reason, "timeout");
                assert_eq!(*celestia_last_height, 12345u64);
            }
            _ => assert!(false, "pattern match failed"),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 34: da_fallback_action_enum_variants
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn da_fallback_action_enum_variants() {
        let a = DaFallbackAction::Activated;
        let d = DaFallbackAction::Deactivated;

        assert_ne!(a, d);
        assert_eq!(a.clone(), DaFallbackAction::Activated);
        assert_eq!(d.clone(), DaFallbackAction::Deactivated);

        // Serialization roundtrip
        for action in &[a, d] {
            let encoded = bincode::serialize(action);
            match encoded {
                Ok(bytes) => {
                    let decoded: Result<DaFallbackAction, _> = bincode::deserialize(&bytes);
                    match decoded {
                        Ok(rt) => assert_eq!(action, &rt),
                        Err(e) => assert!(false, "decode failed: {}", e),
                    }
                }
                Err(e) => assert!(false, "encode failed: {}", e),
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 35: da_fallback_serialization_roundtrip
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn da_fallback_serialization_roundtrip() {
        for action in &[DaFallbackAction::Activated, DaFallbackAction::Deactivated] {
            let event = AuditLogEvent::DaFallbackEvent {
                version: 1,
                timestamp_ms: 1700000000,
                action: action.clone(),
                previous_source: "src_a".to_string(),
                new_source: "src_b".to_string(),
                reason: "test".to_string(),
                celestia_last_height: u64::MAX,
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
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 36: compute_challenge_event_fields_exist
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn compute_challenge_event_fields_exist() {
        let event = AuditLogEvent::ComputeChallengeEvent {
            version: 1,
            timestamp_ms: 1700000000,
            receipt_hash: [0xEE; 32],
            challenger_id: "chal-001".to_string(),
            challenged_node_id: "node-bad".to_string(),
            challenge_type: "execution_mismatch".to_string(),
            outcome: ChallengeOutcome::Fraud,
        };

        match &event {
            AuditLogEvent::ComputeChallengeEvent {
                version, timestamp_ms, receipt_hash,
                challenger_id, challenged_node_id,
                challenge_type, outcome,
            } => {
                assert_eq!(*version, 1u8);
                assert_eq!(*timestamp_ms, 1700000000u64);
                assert_eq!(receipt_hash.len(), 32);
                assert_eq!(receipt_hash[0], 0xEE);
                assert_eq!(challenger_id, "chal-001");
                assert_eq!(challenged_node_id, "node-bad");
                assert_eq!(challenge_type, "execution_mismatch");
                assert_eq!(*outcome, ChallengeOutcome::Fraud);
            }
            _ => assert!(false, "pattern match failed"),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 37: challenge_outcome_enum_variants
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn challenge_outcome_enum_variants() {
        let p = ChallengeOutcome::Pending;
        let c = ChallengeOutcome::Cleared;
        let f = ChallengeOutcome::Fraud;

        assert_ne!(p, c);
        assert_ne!(c, f);
        assert_ne!(p, f);

        assert_eq!(p.clone(), ChallengeOutcome::Pending);
        assert_eq!(c.clone(), ChallengeOutcome::Cleared);
        assert_eq!(f.clone(), ChallengeOutcome::Fraud);

        // Serialization roundtrip
        for outcome in &[p, c, f] {
            let encoded = bincode::serialize(outcome);
            match encoded {
                Ok(bytes) => {
                    let decoded: Result<ChallengeOutcome, _> = bincode::deserialize(&bytes);
                    match decoded {
                        Ok(rt) => assert_eq!(outcome, &rt),
                        Err(e) => assert!(false, "decode failed: {}", e),
                    }
                }
                Err(e) => assert!(false, "encode failed: {}", e),
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 38: compute_challenge_serialization_roundtrip
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn compute_challenge_serialization_roundtrip() {
        for outcome in &[ChallengeOutcome::Pending, ChallengeOutcome::Cleared, ChallengeOutcome::Fraud] {
            let event = AuditLogEvent::ComputeChallengeEvent {
                version: 1,
                timestamp_ms: 1700000000,
                receipt_hash: [0xFF; 32],
                challenger_id: "ch".to_string(),
                challenged_node_id: "nd".to_string(),
                challenge_type: "resource_inflation".to_string(),
                outcome: outcome.clone(),
            };

            let encoded = bincode::serialize(&event);
            match encoded {
                Ok(bytes) => {
                    assert!(!bytes.is_empty());
                    let decoded: Result<AuditLogEvent, _> = bincode::deserialize(&bytes);
                    match decoded {
                        Ok(rt) => assert_eq!(event, rt),
                        Err(e) => assert!(false, "decode failed for {:?}: {}", outcome, e),
                    }
                }
                Err(e) => assert!(false, "encode failed for {:?}: {}", outcome, e),
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 39: audit_event_variant_count_is_9
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_event_variant_count_is_9() {
        let variants = all_variants();
        assert_eq!(variants.len(), 9, "must have exactly 9 variants after 15.5");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 40: audit_event_variant_order_preserved_15_5
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_event_variant_order_preserved_15_5() {
        // Verify discriminants 6, 7, 8 for the three expanded variants.
        let v6 = AuditLogEvent::CommitteeRotationEvent {
            version: 1, timestamp_ms: 0,
            old_epoch: 0, new_epoch: 0,
            old_committee_hash: [0u8; 32], new_committee_hash: [0u8; 32],
            member_count: 0, threshold: 0,
        };
        let v7 = AuditLogEvent::DaFallbackEvent {
            version: 1, timestamp_ms: 0,
            action: DaFallbackAction::Activated,
            previous_source: String::new(), new_source: String::new(),
            reason: String::new(), celestia_last_height: 0,
        };
        let v8 = AuditLogEvent::ComputeChallengeEvent {
            version: 1, timestamp_ms: 0,
            receipt_hash: [0u8; 32],
            challenger_id: String::new(), challenged_node_id: String::new(),
            challenge_type: String::new(), outcome: ChallengeOutcome::Pending,
        };

        let enc6 = bincode::serialize(&v6);
        let enc7 = bincode::serialize(&v7);
        let enc8 = bincode::serialize(&v8);

        match (enc6, enc7, enc8) {
            (Ok(b6), Ok(b7), Ok(b8)) => {
                assert!(b6.len() >= 4);
                assert!(b7.len() >= 4);
                assert!(b8.len() >= 4);

                let d6 = u32::from_le_bytes([b6[0], b6[1], b6[2], b6[3]]);
                let d7 = u32::from_le_bytes([b7[0], b7[1], b7[2], b7[3]]);
                let d8 = u32::from_le_bytes([b8[0], b8[1], b8[2], b8[3]]);

                assert_eq!(d6, 6, "CommitteeRotationEvent must be discriminant 6");
                assert_eq!(d7, 7, "DaFallbackEvent must be discriminant 7");
                assert_eq!(d8, 8, "ComputeChallengeEvent must be discriminant 8");
            }
            _ => assert!(false, "serialization should not fail"),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 41: all_supporting_enums_exist
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn all_supporting_enums_exist() {
        // Verify all 4 supporting enums are constructable + Send + Sync
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<StakeOperation>();
        assert_send_sync::<GovernanceStatus>();
        assert_send_sync::<DaFallbackAction>();
        assert_send_sync::<ChallengeOutcome>();

        // All constructable
        let _so = StakeOperation::Delegate;
        let _gs = GovernanceStatus::Submitted;
        let _da = DaFallbackAction::Activated;
        let _co = ChallengeOutcome::Pending;
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 42: all_variants_version_u8_after_15_5
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn all_variants_version_u8_after_15_5() {
        // After 15.5, all 9 variants use version: u8
        let variants = all_variants();
        for (i, event) in variants.iter().enumerate() {
            let v: u8 = match event {
                AuditLogEvent::SlashingExecuted { version, .. } => *version,
                AuditLogEvent::StakeUpdated { version, .. } => *version,
                AuditLogEvent::AntiSelfDealingViolation { version, .. } => *version,
                AuditLogEvent::UserControlledDelete { version, .. } => *version,
                AuditLogEvent::DaSyncSequenceUpdate { version, .. } => *version,
                AuditLogEvent::GovernanceProposalEvent { version, .. } => *version,
                AuditLogEvent::CommitteeRotationEvent { version, .. } => *version,
                AuditLogEvent::DaFallbackEvent { version, .. } => *version,
                AuditLogEvent::ComputeChallengeEvent { version, .. } => *version,
            };
            assert_eq!(v, 1u8, "variant {} version must be u8 value 1", i);
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // 15.6 TESTS — AuditLogEntry
    // ════════════════════════════════════════════════════════════════════════

    fn make_entry(seq: u64, ts: u64, prev: [u8; 32], event: AuditLogEvent) -> AuditLogEntry {
        let mut entry = AuditLogEntry {
            sequence: seq,
            timestamp_ms: ts,
            prev_hash: prev,
            event,
            entry_hash: [0u8; 32],
        };
        entry.entry_hash = entry.compute_entry_hash();
        entry
    }

    fn sample_event_1() -> AuditLogEvent {
        AuditLogEvent::SlashingExecuted {
            version: 1,
            timestamp_ms: 1700000000,
            validator_id: "val-001".to_string(),
            node_id: "node-001".to_string(),
            slash_amount: 1000,
            reason: "test".to_string(),
            epoch: 1,
            evidence_hash: [0xAA; 32],
        }
    }

    fn sample_event_2() -> AuditLogEvent {
        AuditLogEvent::StakeUpdated {
            version: 1,
            timestamp_ms: 1700000001,
            staker_address: "staker".to_string(),
            operation: StakeOperation::Delegate,
            amount: 500,
            validator_id: "val".to_string(),
            epoch: 2,
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 43: audit_log_entry_hash_deterministic
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_log_entry_hash_deterministic() {
        let entry = make_entry(1, 1700000000, [0u8; 32], sample_event_1());

        let h1 = entry.compute_entry_hash();
        let h2 = entry.compute_entry_hash();
        let h3 = entry.compute_entry_hash();

        assert_eq!(h1, h2, "hash must be deterministic (1 vs 2)");
        assert_eq!(h2, h3, "hash must be deterministic (2 vs 3)");
        assert_eq!(h1.len(), 32);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 44: audit_log_entry_hash_changes_on_event_change
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_log_entry_hash_changes_on_event_change() {
        let e1 = make_entry(1, 1700000000, [0u8; 32], sample_event_1());
        let e2 = make_entry(1, 1700000000, [0u8; 32], sample_event_2());

        assert_ne!(e1.entry_hash, e2.entry_hash, "different events must produce different hashes");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 45: audit_log_entry_hash_changes_on_sequence_change
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_log_entry_hash_changes_on_sequence_change() {
        let e1 = make_entry(1, 1700000000, [0u8; 32], sample_event_1());
        let e2 = make_entry(2, 1700000000, [0u8; 32], sample_event_1());

        assert_ne!(e1.entry_hash, e2.entry_hash, "different sequence must produce different hashes");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 46: audit_log_entry_hash_changes_on_prev_hash_change
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_log_entry_hash_changes_on_prev_hash_change() {
        let e1 = make_entry(1, 1700000000, [0u8; 32], sample_event_1());
        let e2 = make_entry(1, 1700000000, [0xFF; 32], sample_event_1());

        assert_ne!(e1.entry_hash, e2.entry_hash, "different prev_hash must produce different hashes");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 47: audit_log_entry_chain_valid
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_log_entry_chain_valid() {
        let entry1 = make_entry(1, 1700000000, [0u8; 32], sample_event_1());
        let entry2 = make_entry(2, 1700000001, entry1.entry_hash, sample_event_2());

        assert!(entry2.verify_chain(&entry1), "valid chain link must return true");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 48: audit_log_entry_chain_invalid_sequence
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_log_entry_chain_invalid_sequence() {
        let entry1 = make_entry(1, 1700000000, [0u8; 32], sample_event_1());
        // Sequence gap: 1 → 3 (should be 2)
        let entry3 = make_entry(3, 1700000002, entry1.entry_hash, sample_event_2());

        assert!(!entry3.verify_chain(&entry1), "sequence gap must return false");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 49: audit_log_entry_chain_invalid_prev_hash
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_log_entry_chain_invalid_prev_hash() {
        let entry1 = make_entry(1, 1700000000, [0u8; 32], sample_event_1());
        // Wrong prev_hash
        let entry2 = make_entry(2, 1700000001, [0xFF; 32], sample_event_2());

        assert!(!entry2.verify_chain(&entry1), "wrong prev_hash must return false");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 50: audit_log_entry_serialization_roundtrip
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_log_entry_serialization_roundtrip() {
        let entry = make_entry(42, 1700000000, [0xDE; 32], sample_event_1());

        let encoded = bincode::serialize(&entry);
        match encoded {
            Ok(bytes) => {
                assert!(!bytes.is_empty());
                let decoded: Result<AuditLogEntry, _> = bincode::deserialize(&bytes);
                match decoded {
                    Ok(rt) => assert_eq!(entry, rt, "roundtrip must preserve entry"),
                    Err(e) => assert!(false, "decode failed: {}", e),
                }
            }
            Err(e) => assert!(false, "encode failed: {}", e),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 51: audit_log_entry_first_entry_zero_prev_hash
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_log_entry_first_entry_zero_prev_hash() {
        let first = make_entry(1, 1700000000, [0u8; 32], sample_event_1());

        // First entry has zero prev_hash
        assert_eq!(first.prev_hash, [0u8; 32], "first entry must have zero prev_hash");
        // Hash is still computed (not zero)
        assert_ne!(first.entry_hash, [0u8; 32], "entry_hash must not be zero");
        // Sequence is 1
        assert_eq!(first.sequence, 1);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 52: audit_log_entry_hash_matches_compute_method
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_log_entry_hash_matches_compute_method() {
        let entry = make_entry(10, 1700000000, [0xAB; 32], sample_event_2());

        // entry_hash set by make_entry should match compute_entry_hash
        let recomputed = entry.compute_entry_hash();
        assert_eq!(entry.entry_hash, recomputed, "stored hash must match recomputed hash");

        // Tamper with entry_hash — recompute should still produce original
        let mut tampered = entry.clone();
        tampered.entry_hash = [0xFF; 32];
        let recomputed2 = tampered.compute_entry_hash();
        assert_eq!(entry.entry_hash, recomputed2, "entry_hash field must not affect hash computation");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 53: audit_log_entry_send_sync
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_log_entry_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AuditLogEntry>();
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 54: audit_log_entry_three_link_chain
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_log_entry_three_link_chain() {
        let e1 = make_entry(1, 100, [0u8; 32], sample_event_1());
        let e2 = make_entry(2, 200, e1.entry_hash, sample_event_2());
        let e3 = make_entry(3, 300, e2.entry_hash, sample_event_1());

        assert!(e2.verify_chain(&e1), "e2 → e1 chain valid");
        assert!(e3.verify_chain(&e2), "e3 → e2 chain valid");
        assert!(!e3.verify_chain(&e1), "e3 → e1 chain must be invalid (skips e2)");
    }
}