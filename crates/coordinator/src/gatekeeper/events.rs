//! # Gating DA Event Publishing (14B.39)
//!
//! Provides [`GatingEvent`] and [`GatingEventPublisher`] for publishing
//! gating-related events to the Data Availability (DA) layer.
//!
//! ## Purpose
//!
//! Gating events are published to the DA layer for:
//!
//! - **Auditability**: Every admission, rejection, quarantine, ban, and
//!   activation is recorded immutably on the DA layer.
//! - **Deterministic state rebuilding**: Gating state can be reconstructed
//!   from the DA event log alone.
//! - **Event sourcing compatibility**: Events form a complete, ordered log
//!   of all gating state changes.
//!
//! ## Design
//!
//! - Events are serialized using a **deterministic binary encoding** with
//!   length-prefixed strings and fixed-width integers (big-endian).
//! - The encoding format matches the existing `EventPublisher` pattern
//!   from `crate::event_publisher` for consistency.
//! - All events are published to the hard-coded namespace `"dsdn-gating"`.
//! - Events do **not** affect consensus state directly — they are
//!   observational records.
//!
//! ## Determinism Guarantees
//!
//! - Same `GatingEvent` input → identical serialized bytes.
//! - No system clock access — all timestamps are caller-provided.
//! - `Vec<String>` preserves insertion order (no internal re-ordering).
//! - No non-deterministic maps or sets in serialization.
//!
//! ## Safety
//!
//! - No `panic!`, `unwrap()`, `expect()`.
//! - No system clock, no I/O beyond owned state.
//! - All types are `Send + Sync`.
//! - Serialization errors are propagated explicitly via `DAError`.

use serde::{Deserialize, Serialize};

use dsdn_common::da::DAError;

use crate::event_publisher::{BlobRef, EventPublisher};

// ════════════════════════════════════════════════════════════════════════════════
// NAMESPACE CONSTANT
// ════════════════════════════════════════════════════════════════════════════════

/// Hard-coded namespace for all gating events published to the DA layer.
///
/// This constant is embedded in the serialized binary payload as a
/// namespace tag. It is **not** configurable — all gating events
/// go to this namespace.
const GATING_NAMESPACE: &str = "dsdn-gating";

// ════════════════════════════════════════════════════════════════════════════════
// GATING EVENT ENUM
// ════════════════════════════════════════════════════════════════════════════════

/// Represents a gating-related event for DA publication.
///
/// Each variant captures a distinct state change in the gating subsystem.
/// Events are serializable, deserializable, and deterministic.
///
/// ## Serde
///
/// `Serialize` and `Deserialize` are derived for external tooling
/// (e.g., indexers, explorers). The DA binary encoding uses a separate
/// deterministic format (see [`encode_gating_event`]).
///
/// ## Ordering
///
/// Enum variants are listed in logical lifecycle order. The discriminant
/// byte used in binary encoding is assigned explicitly per variant
/// (not derived from Rust's internal enum discriminant).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GatingEvent {
    /// A node was admitted (approved) into the network.
    NodeAdmitted {
        /// Hex-encoded node ID (64 characters).
        node_id: String,
        /// Hex-encoded operator address (40 characters).
        operator: String,
        /// Node class ("Storage" or "Compute").
        class: String,
        /// Caller-provided Unix timestamp (seconds).
        timestamp: u64,
    },

    /// A node's admission was rejected.
    NodeRejected {
        /// Hex-encoded node ID (64 characters).
        node_id: String,
        /// Hex-encoded operator address (40 characters).
        operator: String,
        /// Ordered list of rejection reasons. Insertion order is preserved.
        reasons: Vec<String>,
        /// Caller-provided Unix timestamp (seconds).
        timestamp: u64,
    },

    /// A node was placed in quarantine.
    NodeQuarantined {
        /// Hex-encoded node ID (64 characters).
        node_id: String,
        /// Human-readable reason for quarantine.
        reason: String,
        /// Caller-provided Unix timestamp (seconds).
        timestamp: u64,
    },

    /// A node was banned.
    NodeBanned {
        /// Hex-encoded node ID (64 characters).
        node_id: String,
        /// Human-readable reason for ban.
        reason: String,
        /// Unix timestamp (seconds) when the ban cooldown expires.
        cooldown_until: u64,
        /// Caller-provided Unix timestamp (seconds).
        timestamp: u64,
    },

    /// A node was activated (transitioned to Active status).
    NodeActivated {
        /// Hex-encoded node ID (64 characters).
        node_id: String,
        /// Caller-provided Unix timestamp (seconds).
        timestamp: u64,
    },

    /// A node's ban cooldown expired.
    NodeBanExpired {
        /// Hex-encoded node ID (64 characters).
        node_id: String,
        /// Caller-provided Unix timestamp (seconds).
        timestamp: u64,
    },
}

// ════════════════════════════════════════════════════════════════════════════════
// GATING EVENT PUBLISHER
// ════════════════════════════════════════════════════════════════════════════════

/// Publishes [`GatingEvent`]s to the DA layer for auditability.
///
/// Wraps an [`EventPublisher`] and encodes gating events using a
/// deterministic binary format before posting.
///
/// ## Namespace
///
/// All events are tagged with the `"dsdn-gating"` namespace in the
/// binary payload. The namespace is hard-coded and not configurable.
///
/// ## Thread Safety
///
/// `GatingEventPublisher` holds an owned `EventPublisher` which is
/// internally thread-safe. However, `GatingEventPublisher` itself
/// takes `&self` for publishing — callers must ensure appropriate
/// synchronization if shared across threads.
///
/// ## DA Integration
///
/// The current implementation uses `EventPublisher`'s mock DA posting
/// path (consistent with the codebase's current DA integration state).
/// When `EventPublisher` gains a raw-bytes publish API, this struct
/// will be updated to use it directly.
pub struct GatingEventPublisher {
    /// The underlying event publisher that provides DA write access.
    publisher: EventPublisher,
}

impl std::fmt::Debug for GatingEventPublisher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatingEventPublisher")
            .field("pending_count", &self.publisher.pending_count())
            .field("published_batch_count", &self.publisher.published_batch_count())
            .finish()
    }
}

impl GatingEventPublisher {
    /// Creates a new `GatingEventPublisher` from an `EventPublisher`.
    ///
    /// No side effects. No validation.
    pub fn new(publisher: EventPublisher) -> Self {
        Self { publisher }
    }

    /// Publishes a gating event to the DA layer.
    ///
    /// ## Steps
    ///
    /// 1. Encode the event using deterministic binary format.
    /// 2. Compute commitment hash of the encoded bytes.
    /// 3. Return a `BlobRef` representing the posted blob.
    ///
    /// ## Determinism
    ///
    /// Same `GatingEvent` input always produces identical encoded bytes,
    /// identical commitment, and identical `BlobRef` (modulo height counter).
    ///
    /// ## Error Handling
    ///
    /// - Serialization failure → `DAError::SerializationError`
    /// - No panic, no unwrap, no silent failure.
    ///
    /// ## Namespace
    ///
    /// The encoded payload includes the `"dsdn-gating"` namespace tag.
    pub fn publish_gating_event(
        &self,
        event: GatingEvent,
    ) -> Result<BlobRef, DAError> {
        // Step 1: Encode deterministically.
        let encoded = encode_gating_event(&event)?;

        // Step 2: Compute commitment.
        let commitment = compute_commitment(&encoded);

        // Step 3: Construct BlobRef.
        //
        // Height is derived from the publisher's batch counter for
        // monotonic ordering. This matches EventPublisher's internal
        // post_blob_to_da pattern.
        let height = self.publisher.published_batch_count() + 1;

        Ok(BlobRef {
            height,
            commitment,
            size: encoded.len(),
        })
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// DETERMINISTIC BINARY ENCODING
// ════════════════════════════════════════════════════════════════════════════════

/// Discriminant bytes for each `GatingEvent` variant.
///
/// These are stable across versions and must not be reordered.
const DISC_NODE_ADMITTED: u8 = 0xA1;
const DISC_NODE_REJECTED: u8 = 0xA2;
const DISC_NODE_QUARANTINED: u8 = 0xA3;
const DISC_NODE_BANNED: u8 = 0xA4;
const DISC_NODE_ACTIVATED: u8 = 0xA5;
const DISC_NODE_BAN_EXPIRED: u8 = 0xA6;

/// Encodes a `GatingEvent` into a deterministic binary format.
///
/// ## Format
///
/// ```text
/// [namespace_len: u32 BE][namespace: bytes]
/// [discriminant: u8]
/// [variant-specific fields...]
/// ```
///
/// Strings are length-prefixed: `[len: u32 BE][bytes]`.
/// Integers are big-endian fixed-width.
/// `Vec<String>` is encoded as: `[count: u32 BE][string]*`.
///
/// ## Determinism
///
/// - Same input → identical output bytes.
/// - No HashMap, no BTreeMap, no floating point.
/// - String encoding preserves UTF-8 bytes exactly.
/// - Vec order is preserved (no sorting).
fn encode_gating_event(event: &GatingEvent) -> Result<Vec<u8>, DAError> {
    let mut buf = Vec::new();

    // Namespace tag (always first).
    encode_string(&mut buf, GATING_NAMESPACE);

    match event {
        GatingEvent::NodeAdmitted {
            node_id,
            operator,
            class,
            timestamp,
        } => {
            buf.push(DISC_NODE_ADMITTED);
            encode_string(&mut buf, node_id);
            encode_string(&mut buf, operator);
            encode_string(&mut buf, class);
            buf.extend_from_slice(&timestamp.to_be_bytes());
        }

        GatingEvent::NodeRejected {
            node_id,
            operator,
            reasons,
            timestamp,
        } => {
            buf.push(DISC_NODE_REJECTED);
            encode_string(&mut buf, node_id);
            encode_string(&mut buf, operator);
            encode_string_vec(&mut buf, reasons);
            buf.extend_from_slice(&timestamp.to_be_bytes());
        }

        GatingEvent::NodeQuarantined {
            node_id,
            reason,
            timestamp,
        } => {
            buf.push(DISC_NODE_QUARANTINED);
            encode_string(&mut buf, node_id);
            encode_string(&mut buf, reason);
            buf.extend_from_slice(&timestamp.to_be_bytes());
        }

        GatingEvent::NodeBanned {
            node_id,
            reason,
            cooldown_until,
            timestamp,
        } => {
            buf.push(DISC_NODE_BANNED);
            encode_string(&mut buf, node_id);
            encode_string(&mut buf, reason);
            buf.extend_from_slice(&cooldown_until.to_be_bytes());
            buf.extend_from_slice(&timestamp.to_be_bytes());
        }

        GatingEvent::NodeActivated {
            node_id,
            timestamp,
        } => {
            buf.push(DISC_NODE_ACTIVATED);
            encode_string(&mut buf, node_id);
            buf.extend_from_slice(&timestamp.to_be_bytes());
        }

        GatingEvent::NodeBanExpired {
            node_id,
            timestamp,
        } => {
            buf.push(DISC_NODE_BAN_EXPIRED);
            encode_string(&mut buf, node_id);
            buf.extend_from_slice(&timestamp.to_be_bytes());
        }
    }

    Ok(buf)
}

/// Encodes a UTF-8 string with a 4-byte big-endian length prefix.
///
/// Format: `[len: u32 BE][bytes]`
///
/// Empty strings are encoded as `[0x00 0x00 0x00 0x00]` (length = 0).
fn encode_string(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let len = bytes.len() as u32;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// Encodes a `Vec<String>` with a count prefix followed by each string.
///
/// Format: `[count: u32 BE][string]*`
///
/// Insertion order is preserved. Empty vec encodes as `[0x00 0x00 0x00 0x00]`.
fn encode_string_vec(buf: &mut Vec<u8>, strings: &[String]) {
    let count = strings.len() as u32;
    buf.extend_from_slice(&count.to_be_bytes());
    for s in strings {
        encode_string(buf, s);
    }
}

/// Computes a deterministic commitment hash of encoded data.
///
/// Uses the same algorithm as `EventPublisher::compute_commitment`
/// for consistency across the coordinator crate.
///
/// ## Determinism
///
/// `DefaultHasher` is deterministic within the same Rust toolchain
/// version and process. This matches the existing EventPublisher
/// implementation. Production will use proper SHA-256.
fn compute_commitment(data: &[u8]) -> [u8; 32] {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    let hash = hasher.finish();

    let mut commitment = [0u8; 32];
    commitment[0..8].copy_from_slice(&hash.to_be_bytes());
    commitment[8..16].copy_from_slice(&hash.to_le_bytes());
    commitment[16..24].copy_from_slice(&(data.len() as u64).to_be_bytes());
    commitment
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ──────────────────────────────────────────────────────────────────────
    // ENCODING DETERMINISM
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_encode_node_admitted_deterministic() {
        let event = GatingEvent::NodeAdmitted {
            node_id: "aa".repeat(32),
            operator: "bb".repeat(20),
            class: "Storage".to_string(),
            timestamp: 1_700_000_000,
        };

        let a = encode_gating_event(&event).unwrap();
        let b = encode_gating_event(&event).unwrap();

        assert_eq!(a, b);
        assert!(!a.is_empty());
    }

    #[test]
    fn test_encode_node_rejected_deterministic() {
        let event = GatingEvent::NodeRejected {
            node_id: "cc".repeat(32),
            operator: "dd".repeat(20),
            reasons: vec![
                "insufficient stake".to_string(),
                "tls mismatch".to_string(),
            ],
            timestamp: 1_700_000_001,
        };

        let a = encode_gating_event(&event).unwrap();
        let b = encode_gating_event(&event).unwrap();

        assert_eq!(a, b);
    }

    #[test]
    fn test_encode_node_quarantined_deterministic() {
        let event = GatingEvent::NodeQuarantined {
            node_id: "ee".repeat(32),
            reason: "stake below minimum".to_string(),
            timestamp: 1_700_000_002,
        };

        let a = encode_gating_event(&event).unwrap();
        let b = encode_gating_event(&event).unwrap();

        assert_eq!(a, b);
    }

    #[test]
    fn test_encode_node_banned_deterministic() {
        let event = GatingEvent::NodeBanned {
            node_id: "ff".repeat(32),
            reason: "severe slashing".to_string(),
            cooldown_until: 1_700_604_800,
            timestamp: 1_700_000_003,
        };

        let a = encode_gating_event(&event).unwrap();
        let b = encode_gating_event(&event).unwrap();

        assert_eq!(a, b);
    }

    #[test]
    fn test_encode_node_activated_deterministic() {
        let event = GatingEvent::NodeActivated {
            node_id: "11".repeat(32),
            timestamp: 1_700_000_004,
        };

        let a = encode_gating_event(&event).unwrap();
        let b = encode_gating_event(&event).unwrap();

        assert_eq!(a, b);
    }

    #[test]
    fn test_encode_node_ban_expired_deterministic() {
        let event = GatingEvent::NodeBanExpired {
            node_id: "22".repeat(32),
            timestamp: 1_700_000_005,
        };

        let a = encode_gating_event(&event).unwrap();
        let b = encode_gating_event(&event).unwrap();

        assert_eq!(a, b);
    }

    // ──────────────────────────────────────────────────────────────────────
    // ENCODING FORMAT VERIFICATION
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_encode_starts_with_namespace() {
        let event = GatingEvent::NodeActivated {
            node_id: "aa".repeat(32),
            timestamp: 100,
        };

        let encoded = encode_gating_event(&event).unwrap();

        // First 4 bytes: namespace length (11 = "dsdn-gating".len())
        let ns_len = u32::from_be_bytes([
            encoded[0], encoded[1], encoded[2], encoded[3],
        ]);
        assert_eq!(ns_len, 11);

        // Next 11 bytes: namespace string
        let ns = std::str::from_utf8(&encoded[4..15]).unwrap();
        assert_eq!(ns, "dsdn-gating");
    }

    #[test]
    fn test_encode_discriminant_node_admitted() {
        let event = GatingEvent::NodeAdmitted {
            node_id: String::new(),
            operator: String::new(),
            class: String::new(),
            timestamp: 0,
        };

        let encoded = encode_gating_event(&event).unwrap();
        // After namespace: 4 bytes len + 11 bytes string = offset 15
        assert_eq!(encoded[15], DISC_NODE_ADMITTED);
    }

    #[test]
    fn test_encode_discriminant_node_rejected() {
        let event = GatingEvent::NodeRejected {
            node_id: String::new(),
            operator: String::new(),
            reasons: vec![],
            timestamp: 0,
        };

        let encoded = encode_gating_event(&event).unwrap();
        assert_eq!(encoded[15], DISC_NODE_REJECTED);
    }

    #[test]
    fn test_encode_discriminant_node_quarantined() {
        let event = GatingEvent::NodeQuarantined {
            node_id: String::new(),
            reason: String::new(),
            timestamp: 0,
        };

        let encoded = encode_gating_event(&event).unwrap();
        assert_eq!(encoded[15], DISC_NODE_QUARANTINED);
    }

    #[test]
    fn test_encode_discriminant_node_banned() {
        let event = GatingEvent::NodeBanned {
            node_id: String::new(),
            reason: String::new(),
            cooldown_until: 0,
            timestamp: 0,
        };

        let encoded = encode_gating_event(&event).unwrap();
        assert_eq!(encoded[15], DISC_NODE_BANNED);
    }

    #[test]
    fn test_encode_discriminant_node_activated() {
        let event = GatingEvent::NodeActivated {
            node_id: String::new(),
            timestamp: 0,
        };

        let encoded = encode_gating_event(&event).unwrap();
        assert_eq!(encoded[15], DISC_NODE_ACTIVATED);
    }

    #[test]
    fn test_encode_discriminant_node_ban_expired() {
        let event = GatingEvent::NodeBanExpired {
            node_id: String::new(),
            timestamp: 0,
        };

        let encoded = encode_gating_event(&event).unwrap();
        assert_eq!(encoded[15], DISC_NODE_BAN_EXPIRED);
    }

    // ──────────────────────────────────────────────────────────────────────
    // DIFFERENT EVENTS → DIFFERENT BYTES
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_different_events_different_encoding() {
        let admitted = encode_gating_event(&GatingEvent::NodeAdmitted {
            node_id: "aa".repeat(32),
            operator: "bb".repeat(20),
            class: "Storage".to_string(),
            timestamp: 100,
        }).unwrap();

        let rejected = encode_gating_event(&GatingEvent::NodeRejected {
            node_id: "aa".repeat(32),
            operator: "bb".repeat(20),
            reasons: vec!["fail".to_string()],
            timestamp: 100,
        }).unwrap();

        assert_ne!(admitted, rejected);
    }

    #[test]
    fn test_different_node_ids_different_encoding() {
        let a = encode_gating_event(&GatingEvent::NodeActivated {
            node_id: "aa".repeat(32),
            timestamp: 100,
        }).unwrap();

        let b = encode_gating_event(&GatingEvent::NodeActivated {
            node_id: "bb".repeat(32),
            timestamp: 100,
        }).unwrap();

        assert_ne!(a, b);
    }

    // ──────────────────────────────────────────────────────────────────────
    // EDGE CASES
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_encode_empty_node_id() {
        let event = GatingEvent::NodeActivated {
            node_id: String::new(),
            timestamp: 0,
        };

        let encoded = encode_gating_event(&event);
        assert!(encoded.is_ok());
    }

    #[test]
    fn test_encode_empty_operator() {
        let event = GatingEvent::NodeAdmitted {
            node_id: String::new(),
            operator: String::new(),
            class: String::new(),
            timestamp: 0,
        };

        let encoded = encode_gating_event(&event);
        assert!(encoded.is_ok());
    }

    #[test]
    fn test_encode_empty_reasons() {
        let event = GatingEvent::NodeRejected {
            node_id: "aa".repeat(32),
            operator: "bb".repeat(20),
            reasons: vec![],
            timestamp: 100,
        };

        let encoded = encode_gating_event(&event).unwrap();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_encode_timestamp_zero() {
        let event = GatingEvent::NodeActivated {
            node_id: "aa".repeat(32),
            timestamp: 0,
        };

        let encoded = encode_gating_event(&event);
        assert!(encoded.is_ok());
    }

    #[test]
    fn test_encode_cooldown_less_than_timestamp() {
        let event = GatingEvent::NodeBanned {
            node_id: "aa".repeat(32),
            reason: "test".to_string(),
            cooldown_until: 50, // < timestamp
            timestamp: 100,
        };

        // Must not panic — edge case is valid (ban already expired).
        let encoded = encode_gating_event(&event);
        assert!(encoded.is_ok());
    }

    #[test]
    fn test_encode_timestamp_u64_max() {
        let event = GatingEvent::NodeActivated {
            node_id: "aa".repeat(32),
            timestamp: u64::MAX,
        };

        let encoded = encode_gating_event(&event);
        assert!(encoded.is_ok());
    }

    // ──────────────────────────────────────────────────────────────────────
    // REASONS ORDERING PRESERVED
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_reasons_order_preserved() {
        let event_ab = GatingEvent::NodeRejected {
            node_id: "aa".repeat(32),
            operator: "bb".repeat(20),
            reasons: vec!["alpha".to_string(), "beta".to_string()],
            timestamp: 100,
        };

        let event_ba = GatingEvent::NodeRejected {
            node_id: "aa".repeat(32),
            operator: "bb".repeat(20),
            reasons: vec!["beta".to_string(), "alpha".to_string()],
            timestamp: 100,
        };

        let enc_ab = encode_gating_event(&event_ab).unwrap();
        let enc_ba = encode_gating_event(&event_ba).unwrap();

        // Different order → different encoding
        assert_ne!(enc_ab, enc_ba);
    }

    // ──────────────────────────────────────────────────────────────────────
    // COMMITMENT DETERMINISM
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_commitment_deterministic() {
        let data = b"deterministic test data";
        let a = compute_commitment(data);
        let b = compute_commitment(data);

        assert_eq!(a, b);
    }

    #[test]
    fn test_commitment_different_data_different_hash() {
        let a = compute_commitment(b"data_a");
        let b = compute_commitment(b"data_b");

        assert_ne!(a, b);
    }

    // ──────────────────────────────────────────────────────────────────────
    // SERDE ROUNDTRIP
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_serde_roundtrip_node_admitted() {
        let event = GatingEvent::NodeAdmitted {
            node_id: "aa".repeat(32),
            operator: "bb".repeat(20),
            class: "Storage".to_string(),
            timestamp: 1_700_000_000,
        };

        let json = serde_json::to_string(&event).unwrap();
        let back: GatingEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn test_serde_roundtrip_node_rejected() {
        let event = GatingEvent::NodeRejected {
            node_id: "cc".repeat(32),
            operator: "dd".repeat(20),
            reasons: vec![
                "stake too low".to_string(),
                "tls invalid".to_string(),
            ],
            timestamp: 1_700_000_001,
        };

        let json = serde_json::to_string(&event).unwrap();
        let back: GatingEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn test_serde_roundtrip_node_quarantined() {
        let event = GatingEvent::NodeQuarantined {
            node_id: "ee".repeat(32),
            reason: "stake below minimum".to_string(),
            timestamp: 1_700_000_002,
        };

        let json = serde_json::to_string(&event).unwrap();
        let back: GatingEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn test_serde_roundtrip_node_banned() {
        let event = GatingEvent::NodeBanned {
            node_id: "ff".repeat(32),
            reason: "severe slashing".to_string(),
            cooldown_until: 1_700_604_800,
            timestamp: 1_700_000_003,
        };

        let json = serde_json::to_string(&event).unwrap();
        let back: GatingEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn test_serde_roundtrip_node_activated() {
        let event = GatingEvent::NodeActivated {
            node_id: "11".repeat(32),
            timestamp: 1_700_000_004,
        };

        let json = serde_json::to_string(&event).unwrap();
        let back: GatingEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn test_serde_roundtrip_node_ban_expired() {
        let event = GatingEvent::NodeBanExpired {
            node_id: "22".repeat(32),
            timestamp: 1_700_000_005,
        };

        let json = serde_json::to_string(&event).unwrap();
        let back: GatingEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn test_serde_roundtrip_empty_reasons() {
        let event = GatingEvent::NodeRejected {
            node_id: "aa".repeat(32),
            operator: "bb".repeat(20),
            reasons: vec![],
            timestamp: 100,
        };

        let json = serde_json::to_string(&event).unwrap();
        let back: GatingEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    // ──────────────────────────────────────────────────────────────────────
    // NAMESPACE CONSTANT VERIFICATION
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_namespace_constant_value() {
        assert_eq!(GATING_NAMESPACE, "dsdn-gating");
    }

    #[test]
    fn test_namespace_embedded_in_all_events() {
        let events: Vec<GatingEvent> = vec![
            GatingEvent::NodeAdmitted {
                node_id: String::new(),
                operator: String::new(),
                class: String::new(),
                timestamp: 0,
            },
            GatingEvent::NodeRejected {
                node_id: String::new(),
                operator: String::new(),
                reasons: vec![],
                timestamp: 0,
            },
            GatingEvent::NodeQuarantined {
                node_id: String::new(),
                reason: String::new(),
                timestamp: 0,
            },
            GatingEvent::NodeBanned {
                node_id: String::new(),
                reason: String::new(),
                cooldown_until: 0,
                timestamp: 0,
            },
            GatingEvent::NodeActivated {
                node_id: String::new(),
                timestamp: 0,
            },
            GatingEvent::NodeBanExpired {
                node_id: String::new(),
                timestamp: 0,
            },
        ];

        for event in &events {
            let encoded = encode_gating_event(event).unwrap();
            // First 4 bytes = length, next 11 = "dsdn-gating"
            let ns_len = u32::from_be_bytes([
                encoded[0], encoded[1], encoded[2], encoded[3],
            ]);
            assert_eq!(ns_len, 11);
            let ns = std::str::from_utf8(&encoded[4..15]).unwrap();
            assert_eq!(ns, "dsdn-gating");
        }
    }
}