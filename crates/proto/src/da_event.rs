//! DA Event Schema for DSDN Data Availability Layer
//!
//! Schema ini adalah kontrak data yang TIDAK BOLEH DIUBAH setelah deploy.
//! Penambahan variant baru harus backward-compatible.

use serde::{Serialize, Deserialize};
use sha3::{Sha3_256, Digest};
use std::collections::HashMap;

/// Core DA Event enum untuk semua event yang di-post ke Celestia DA.
///
/// INVARIANTS:
/// - Setiap variant WAJIB memiliki `version` dan `timestamp_ms`
/// - Encoding: bincode (deterministic binary)
/// - Tidak ada default values
/// - Tidak ada auto-generated timestamps
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DAEvent {
    /// Node baru bergabung ke network
    NodeRegistered {
        /// Schema version untuk forward compatibility
        version: u8,
        /// Unix timestamp dalam milliseconds (disediakan caller)
        timestamp_ms: u64,
        /// Unique node identifier
        node_id: String,
        /// Geographic/logical zone
        zone: String,
        /// Network address (host:port)
        addr: String,
        /// Storage capacity dalam GB
        capacity_gb: u64,
    },

    /// Chunk baru dideklarasikan ke network
    ChunkDeclared {
        /// Schema version untuk forward compatibility
        version: u8,
        /// Unix timestamp dalam milliseconds (disediakan caller)
        timestamp_ms: u64,
        /// SHA256 hex hash of chunk data
        chunk_hash: String,
        /// Chunk size dalam bytes
        size_bytes: u64,
        /// Node ID yang meng-upload
        uploader_id: String,
        /// Target replication factor
        replication_factor: u8,
    },

    /// Replica ditambahkan ke node
    ReplicaAdded {
        /// Schema version untuk forward compatibility
        version: u8,
        /// Unix timestamp dalam milliseconds (disediakan caller)
        timestamp_ms: u64,
        /// Chunk hash yang di-replicate
        chunk_hash: String,
        /// Node ID yang menyimpan replica
        node_id: String,
        /// Index replica (0, 1, 2 untuk RF=3)
        replica_index: u8,
    },

    /// Replica dihapus dari node
    ReplicaRemoved {
        /// Schema version untuk forward compatibility
        version: u8,
        /// Unix timestamp dalam milliseconds (disediakan caller)
        timestamp_ms: u64,
        /// Chunk hash yang replica-nya dihapus
        chunk_hash: String,
        /// Node ID yang kehilangan replica
        node_id: String,
        /// Alasan penghapusan
        reason: ReplicaRemovalReason,
    },

    /// Request penghapusan chunk (pointer removal)
    DeleteRequested {
        /// Schema version untuk forward compatibility
        version: u8,
        /// Unix timestamp dalam milliseconds (disediakan caller)
        timestamp_ms: u64,
        /// Chunk hash yang diminta untuk dihapus
        chunk_hash: String,
        /// ID peminta penghapusan
        requester_id: String,
        /// Alasan penghapusan
        reason: DeleteReason,
    },
}

/// Alasan penghapusan replica dari node
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplicaRemovalReason {
    /// Node offline / tidak responsif
    NodeOffline,
    /// Rebalancing untuk distribusi merata
    Rebalance,
    /// Data corruption terdeteksi
    Corruption,
    /// Penghapusan manual oleh operator
    Manual,
}

/// Alasan request penghapusan chunk
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeleteReason {
    /// User meminta penghapusan
    UserRequest,
    /// Data expired (TTL habis)
    Expired,
    /// Keputusan governance
    Governance,
    /// Compliance requirement
    Compliance,
}

/// Tipe node dalam network
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeType {
    /// Node regular / individual
    Regular,
    /// Node data center dengan kapasitas besar
    DataCenter,
}

/// Event untuk registrasi node baru dalam sistem DA
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRegisteredEvent {
    /// Unique identifier node
    pub node_id: String,
    /// Geographic / logical zone
    pub zone: String,
    /// Network address dalam format host:port
    pub addr: String,
    /// Storage capacity dalam gigabyte
    pub capacity_gb: u64,
    /// Tipe node
    pub node_type: NodeType,
    /// Ed25519 public key (fixed 32 bytes)
    pub public_key: [u8; 32],
    /// Metadata tambahan
    pub metadata: HashMap<String, String>,
}

impl From<NodeRegisteredEvent> for DAEvent {
    fn from(event: NodeRegisteredEvent) -> Self {
        DAEvent::NodeRegistered {
            version: 1,
            timestamp_ms: 0,
            node_id: event.node_id,
            zone: event.zone,
            addr: event.addr,
            capacity_gb: event.capacity_gb,
        }
    }
}

// ============================================================================
// DAEventEnvelope System (Specification 14A.2)
// ============================================================================

/// Lightweight discriminant enum for DA event routing and indexing.
///
/// This enum carries NO payload data - it exists solely to identify
/// event types without deserializing the full payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DAEventType {
    NodeRegistered,
    ChunkDeclared,
    ReplicaAdded,
    ReplicaRemoved,
    DeleteRequested,
}

/// Error types for DAEventEnvelope decoding operations.
///
/// Explicit error variants prevent hidden failure modes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DAEventDecodeError {
    /// Input bytes are empty or structurally invalid
    InvalidFormat,
    /// Bincode deserialization failed
    DeserializationFailed,
}

/// Universal envelope wrapper for all DA events posted to Celestia.
///
/// This is the CANONICAL container format. Field order is fixed and
/// MUST NOT be changed to preserve binary compatibility.
///
/// # Wire Format (bincode)
/// ```text
/// [version:1][timestamp_ms:8][sequence:8][event_type:1][payload_len:8][payload:N][checksum:32]
/// ```
///
/// # Verification Flow
/// 1. `decode()` - deserialize from bytes
/// 2. `verify_checksum()` - validate payload integrity
/// 3. Deserialize `payload` to concrete `DAEvent` variant
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DAEventEnvelope {
    /// Envelope schema version (current = 1)
    pub version: u8,
    /// Unix timestamp in milliseconds (caller-provided)
    pub timestamp_ms: u64,
    /// Monotonic sequence number (caller-managed for ordering)
    pub sequence: u64,
    /// Event type discriminant for routing without payload inspection
    pub event_type: DAEventType,
    /// Serialized event payload (bincode-encoded DAEvent)
    pub payload: Vec<u8>,
    /// SHA3-256 checksum of payload for integrity verification
    pub checksum: [u8; 32],
}

impl DAEventEnvelope {
    /// Serialize envelope to deterministic binary format using bincode.
    ///
    /// # Returns
    /// Binary representation suitable for DA layer storage.
    /// Returns empty Vec only on catastrophic serialization failure
    /// (should not occur with well-formed envelope).
    pub fn encode(&self) -> Vec<u8> {
        // bincode serialization of fixed-structure data cannot fail
        // under normal conditions; empty fallback is defensive only
        bincode::serialize(self).unwrap_or_else(|_| Vec::new())
    }

    /// Deserialize envelope from binary format.
    ///
    /// # Arguments
    /// * `bytes` - Raw bytes from DA layer
    ///
    /// # Returns
    /// * `Ok(Self)` - Successfully decoded envelope
    /// * `Err(InvalidFormat)` - Empty or malformed input
    /// * `Err(DeserializationFailed)` - Bincode decode failure
    ///
    /// # Note
    /// This method does NOT verify checksum. Call `verify_checksum()`
    /// separately after decoding to validate payload integrity.
    pub fn decode(bytes: &[u8]) -> Result<Self, DAEventDecodeError> {
        if bytes.is_empty() {
            return Err(DAEventDecodeError::InvalidFormat);
        }
        bincode::deserialize(bytes).map_err(|_| DAEventDecodeError::DeserializationFailed)
    }

    /// Verify payload integrity by comparing stored checksum with computed SHA3-256.
    ///
    /// # Returns
    /// * `true` - Checksum matches, payload is intact
    /// * `false` - Checksum mismatch, payload may be corrupted
    ///
    /// # Security
    /// MUST be called after `decode()` before trusting payload contents.
    /// Detects both accidental corruption and malicious tampering.
    pub fn verify_checksum(&self) -> bool {
        let mut hasher = Sha3_256::new();
        hasher.update(&self.payload);
        let computed: [u8; 32] = hasher.finalize().into();
        computed == self.checksum
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_registered_event_serialization_roundtrip() {
        // Setup: create NodeRegisteredEvent with all fields populated
        let mut metadata = HashMap::new();
        metadata.insert("operator".to_string(), "DSDN-Labs".to_string());
        metadata.insert("region".to_string(), "asia-southeast".to_string());

        let original = NodeRegisteredEvent {
            node_id: "node-abc-123".to_string(),
            zone: "id-jakarta-1".to_string(),
            addr: "192.168.1.100:9000".to_string(),
            capacity_gb: 1000,
            node_type: NodeType::DataCenter,
            public_key: [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
            ],
            metadata: metadata,
        };

        // Step 1: Serialize to bytes
        let serialized = bincode::serialize(&original).expect("serialization must succeed");

        // Step 2: Deserialize back
        let deserialized: NodeRegisteredEvent =
            bincode::deserialize(&serialized).expect("deserialization must succeed");

        // Step 3: Verify ALL fields are identical
        assert_eq!(original.node_id, deserialized.node_id, "node_id mismatch");
        assert_eq!(original.zone, deserialized.zone, "zone mismatch");
        assert_eq!(original.addr, deserialized.addr, "addr mismatch");
        assert_eq!(original.capacity_gb, deserialized.capacity_gb, "capacity_gb mismatch");
        assert_eq!(original.node_type, deserialized.node_type, "node_type mismatch");
        assert_eq!(original.public_key, deserialized.public_key, "public_key mismatch");
        assert_eq!(original.public_key.len(), 32, "public_key must be exactly 32 bytes");
        assert_eq!(original.metadata, deserialized.metadata, "metadata mismatch");

        // Step 4: Full struct equality
        assert_eq!(original, deserialized, "full struct equality failed");
    }

    #[test]
    fn test_node_registered_event_to_da_event_conversion() {
        let mut metadata = HashMap::new();
        metadata.insert("key".to_string(), "value".to_string());

        let event = NodeRegisteredEvent {
            node_id: "node-xyz".to_string(),
            zone: "us-west-1".to_string(),
            addr: "10.0.0.1:8080".to_string(),
            capacity_gb: 500,
            node_type: NodeType::Regular,
            public_key: [0u8; 32],
            metadata: metadata,
        };

        // Convert to DAEvent
        let da_event: DAEvent = event.clone().into();

        // Verify mapping
        match da_event {
            DAEvent::NodeRegistered {
                version,
                timestamp_ms,
                node_id,
                zone,
                addr,
                capacity_gb,
            } => {
                assert_eq!(version, 1, "version must be 1");
                assert_eq!(timestamp_ms, 0, "timestamp_ms must be 0");
                assert_eq!(node_id, event.node_id, "node_id mapping failed");
                assert_eq!(zone, event.zone, "zone mapping failed");
                assert_eq!(addr, event.addr, "addr mapping failed");
                assert_eq!(capacity_gb, event.capacity_gb, "capacity_gb mapping failed");
            }
            _ => panic!("conversion must produce DAEvent::NodeRegistered"),
        }
    }

    #[test]
    fn test_node_registered_event_empty_metadata() {
        let original = NodeRegisteredEvent {
            node_id: "node-empty".to_string(),
            zone: "zone-1".to_string(),
            addr: "127.0.0.1:3000".to_string(),
            capacity_gb: 100,
            node_type: NodeType::Regular,
            public_key: [0xffu8; 32],
            metadata: HashMap::new(),
        };

        let serialized = bincode::serialize(&original).expect("serialization must succeed");
        let deserialized: NodeRegisteredEvent =
            bincode::deserialize(&serialized).expect("deserialization must succeed");

        assert!(deserialized.metadata.is_empty(), "metadata must be empty");
        assert_eq!(original, deserialized, "roundtrip with empty metadata failed");
    }

    #[test]
    fn test_node_type_variants() {
        // Test Regular variant
        let regular = NodeType::Regular;
        let serialized = bincode::serialize(&regular).expect("serialize Regular");
        let deserialized: NodeType = bincode::deserialize(&serialized).expect("deserialize Regular");
        assert_eq!(regular, deserialized);

        // Test DataCenter variant
        let datacenter = NodeType::DataCenter;
        let serialized = bincode::serialize(&datacenter).expect("serialize DataCenter");
        let deserialized: NodeType = bincode::deserialize(&serialized).expect("deserialize DataCenter");
        assert_eq!(datacenter, deserialized);
    }
}