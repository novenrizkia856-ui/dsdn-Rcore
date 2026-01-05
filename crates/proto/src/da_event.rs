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

/// Event untuk deklarasi chunk baru dalam sistem DA
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkDeclaredEvent {
    /// SHA256 hex hash dari data chunk
    pub chunk_hash: String,
    /// Ukuran chunk dalam bytes
    pub size_bytes: u64,
    /// Identifier pihak yang meng-upload chunk
    pub uploader_id: String,
    /// Replication factor yang dibutuhkan
    pub replication_factor: u8,
    /// Hash encryption key jika chunk terenkripsi (None jika tidak)
    pub encryption_key_hash: Option<[u8; 32]>,
    /// Celestia blob commitment (fixed 32 bytes)
    pub da_commitment: [u8; 32],
    /// Timestamp deklarasi dalam milliseconds
    pub declared_at: u64,
}

impl From<ChunkDeclaredEvent> for DAEvent {
    fn from(event: ChunkDeclaredEvent) -> Self {
        DAEvent::ChunkDeclared {
            version: 1,
            timestamp_ms: event.declared_at,
            chunk_hash: event.chunk_hash,
            size_bytes: event.size_bytes,
            uploader_id: event.uploader_id,
            replication_factor: event.replication_factor,
        }
    }
}

/// Event untuk penambahan replica ke node
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicaAddedEvent {
    /// Identifier chunk
    pub chunk_hash: String,
    /// Identifier node yang menyimpan replica
    pub node_id: String,
    /// Index replica (contoh: 0, 1, 2 untuk RF=3)
    pub replica_index: u8,
    /// Timestamp replica ditambahkan
    pub added_at: u64,
    /// True jika replica sudah diverifikasi tersimpan
    pub verified: bool,
}

impl From<ReplicaAddedEvent> for DAEvent {
    fn from(event: ReplicaAddedEvent) -> Self {
        DAEvent::ReplicaAdded {
            version: 1,
            timestamp_ms: event.added_at,
            chunk_hash: event.chunk_hash,
            node_id: event.node_id,
            replica_index: event.replica_index,
        }
    }
}

/// Event untuk penghapusan replica dari node
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicaRemovedEvent {
    /// Identifier chunk
    pub chunk_hash: String,
    /// Identifier node yang kehilangan replica
    pub node_id: String,
    /// Alasan penghapusan replica
    pub reason: ReplicaRemovalReason,
    /// Timestamp replica dihapus
    pub removed_at: u64,
}

impl From<ReplicaRemovedEvent> for DAEvent {
    fn from(event: ReplicaRemovedEvent) -> Self {
        DAEvent::ReplicaRemoved {
            version: 1,
            timestamp_ms: event.removed_at,
            chunk_hash: event.chunk_hash,
            node_id: event.node_id,
            reason: event.reason,
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

    #[test]
    fn test_chunk_declared_event_with_encryption_key_hash() {
        let encryption_key: [u8; 32] = [
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
            0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
            0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        ];

        let da_commitment: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ];

        let original = ChunkDeclaredEvent {
            chunk_hash: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
            size_bytes: 1048576,
            uploader_id: "uploader-001".to_string(),
            replication_factor: 3,
            encryption_key_hash: Some(encryption_key),
            da_commitment: da_commitment,
            declared_at: 1704067200000,
        };

        // Serialize
        let serialized = bincode::serialize(&original).expect("serialization must succeed");

        // Deserialize
        let deserialized: ChunkDeclaredEvent =
            bincode::deserialize(&serialized).expect("deserialization must succeed");

        // Verify ALL fields
        assert_eq!(original.chunk_hash, deserialized.chunk_hash, "chunk_hash mismatch");
        assert_eq!(original.size_bytes, deserialized.size_bytes, "size_bytes mismatch");
        assert_eq!(original.uploader_id, deserialized.uploader_id, "uploader_id mismatch");
        assert_eq!(original.replication_factor, deserialized.replication_factor, "replication_factor mismatch");
        assert_eq!(original.encryption_key_hash, deserialized.encryption_key_hash, "encryption_key_hash mismatch");
        assert!(deserialized.encryption_key_hash.is_some(), "encryption_key_hash must be Some");
        assert_eq!(deserialized.encryption_key_hash.unwrap().len(), 32, "encryption_key_hash must be 32 bytes");
        assert_eq!(original.da_commitment, deserialized.da_commitment, "da_commitment mismatch");
        assert_eq!(original.da_commitment.len(), 32, "da_commitment must be 32 bytes");
        assert_eq!(original.declared_at, deserialized.declared_at, "declared_at mismatch");

        // Full equality
        assert_eq!(original, deserialized, "full struct equality failed");
    }

    #[test]
    fn test_chunk_declared_event_without_encryption_key_hash() {
        let da_commitment: [u8; 32] = [
            0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
            0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
            0xef, 0xee, 0xed, 0xec, 0xeb, 0xea, 0xe9, 0xe8,
            0xe7, 0xe6, 0xe5, 0xe4, 0xe3, 0xe2, 0xe1, 0xe0,
        ];

        let original = ChunkDeclaredEvent {
            chunk_hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            size_bytes: 524288,
            uploader_id: "uploader-002".to_string(),
            replication_factor: 5,
            encryption_key_hash: None,
            da_commitment: da_commitment,
            declared_at: 1704153600000,
        };

        // Serialize
        let serialized = bincode::serialize(&original).expect("serialization must succeed");

        // Deserialize
        let deserialized: ChunkDeclaredEvent =
            bincode::deserialize(&serialized).expect("deserialization must succeed");

        // Verify ALL fields
        assert_eq!(original.chunk_hash, deserialized.chunk_hash, "chunk_hash mismatch");
        assert_eq!(original.size_bytes, deserialized.size_bytes, "size_bytes mismatch");
        assert_eq!(original.uploader_id, deserialized.uploader_id, "uploader_id mismatch");
        assert_eq!(original.replication_factor, deserialized.replication_factor, "replication_factor mismatch");
        assert_eq!(original.encryption_key_hash, deserialized.encryption_key_hash, "encryption_key_hash mismatch");
        assert!(deserialized.encryption_key_hash.is_none(), "encryption_key_hash must be None");
        assert_eq!(original.da_commitment, deserialized.da_commitment, "da_commitment mismatch");
        assert_eq!(original.da_commitment.len(), 32, "da_commitment must be 32 bytes");
        assert_eq!(original.declared_at, deserialized.declared_at, "declared_at mismatch");

        // Full equality
        assert_eq!(original, deserialized, "full struct equality failed");
    }

    #[test]
    fn test_chunk_declared_event_to_da_event_conversion() {
        let da_commitment: [u8; 32] = [0x42u8; 32];
        let encryption_key: [u8; 32] = [0x13u8; 32];

        let event = ChunkDeclaredEvent {
            chunk_hash: "deadbeef".to_string(),
            size_bytes: 2048,
            uploader_id: "test-uploader".to_string(),
            replication_factor: 2,
            encryption_key_hash: Some(encryption_key),
            da_commitment: da_commitment,
            declared_at: 1700000000000,
        };

        // Convert to DAEvent
        let da_event: DAEvent = event.clone().into();

        // Verify mapping
        match da_event {
            DAEvent::ChunkDeclared {
                version,
                timestamp_ms,
                chunk_hash,
                size_bytes,
                uploader_id,
                replication_factor,
            } => {
                assert_eq!(version, 1, "version must be 1");
                assert_eq!(timestamp_ms, event.declared_at, "timestamp_ms must equal declared_at");
                assert_eq!(chunk_hash, event.chunk_hash, "chunk_hash mapping failed");
                assert_eq!(size_bytes, event.size_bytes, "size_bytes mapping failed");
                assert_eq!(uploader_id, event.uploader_id, "uploader_id mapping failed");
                assert_eq!(replication_factor, event.replication_factor, "replication_factor mapping failed");
            }
            _ => panic!("conversion must produce DAEvent::ChunkDeclared"),
        }
    }

    #[test]
    fn test_replica_added_event_verified_true() {
        let original = ReplicaAddedEvent {
            chunk_hash: "abc123def456".to_string(),
            node_id: "node-001".to_string(),
            replica_index: 0,
            added_at: 1704067200000,
            verified: true,
        };

        // Serialize
        let serialized = bincode::serialize(&original).expect("serialization must succeed");

        // Deserialize
        let deserialized: ReplicaAddedEvent =
            bincode::deserialize(&serialized).expect("deserialization must succeed");

        // Verify ALL fields
        assert_eq!(original.chunk_hash, deserialized.chunk_hash, "chunk_hash mismatch");
        assert_eq!(original.node_id, deserialized.node_id, "node_id mismatch");
        assert_eq!(original.replica_index, deserialized.replica_index, "replica_index mismatch");
        assert_eq!(original.added_at, deserialized.added_at, "added_at mismatch");
        assert_eq!(original.verified, deserialized.verified, "verified mismatch");
        assert!(deserialized.verified, "verified must be true");

        // Full equality
        assert_eq!(original, deserialized, "full struct equality failed");
    }

    #[test]
    fn test_replica_added_event_verified_false() {
        let original = ReplicaAddedEvent {
            chunk_hash: "xyz789".to_string(),
            node_id: "node-002".to_string(),
            replica_index: 2,
            added_at: 1704153600000,
            verified: false,
        };

        // Serialize
        let serialized = bincode::serialize(&original).expect("serialization must succeed");

        // Deserialize
        let deserialized: ReplicaAddedEvent =
            bincode::deserialize(&serialized).expect("deserialization must succeed");

        // Verify ALL fields
        assert_eq!(original.chunk_hash, deserialized.chunk_hash, "chunk_hash mismatch");
        assert_eq!(original.node_id, deserialized.node_id, "node_id mismatch");
        assert_eq!(original.replica_index, deserialized.replica_index, "replica_index mismatch");
        assert_eq!(original.added_at, deserialized.added_at, "added_at mismatch");
        assert_eq!(original.verified, deserialized.verified, "verified mismatch");
        assert!(!deserialized.verified, "verified must be false");

        // Full equality
        assert_eq!(original, deserialized, "full struct equality failed");
    }

    #[test]
    fn test_replica_added_event_to_da_event_conversion() {
        let event = ReplicaAddedEvent {
            chunk_hash: "test-chunk".to_string(),
            node_id: "test-node".to_string(),
            replica_index: 1,
            added_at: 1700000000000,
            verified: true,
        };

        // Convert to DAEvent
        let da_event: DAEvent = event.clone().into();

        // Verify mapping
        match da_event {
            DAEvent::ReplicaAdded {
                version,
                timestamp_ms,
                chunk_hash,
                node_id,
                replica_index,
            } => {
                assert_eq!(version, 1, "version must be 1");
                assert_eq!(timestamp_ms, event.added_at, "timestamp_ms must equal added_at");
                assert_eq!(chunk_hash, event.chunk_hash, "chunk_hash mapping failed");
                assert_eq!(node_id, event.node_id, "node_id mapping failed");
                assert_eq!(replica_index, event.replica_index, "replica_index mapping failed");
            }
            _ => panic!("conversion must produce DAEvent::ReplicaAdded"),
        }
    }

    #[test]
    fn test_replica_removed_event_reason_node_offline() {
        let original = ReplicaRemovedEvent {
            chunk_hash: "chunk-offline".to_string(),
            node_id: "node-offline".to_string(),
            reason: ReplicaRemovalReason::NodeOffline,
            removed_at: 1704067200000,
        };

        let serialized = bincode::serialize(&original).expect("serialization must succeed");
        let deserialized: ReplicaRemovedEvent =
            bincode::deserialize(&serialized).expect("deserialization must succeed");

        assert_eq!(original.chunk_hash, deserialized.chunk_hash, "chunk_hash mismatch");
        assert_eq!(original.node_id, deserialized.node_id, "node_id mismatch");
        assert_eq!(original.reason, deserialized.reason, "reason mismatch");
        assert_eq!(original.reason, ReplicaRemovalReason::NodeOffline, "reason must be NodeOffline");
        assert_eq!(original.removed_at, deserialized.removed_at, "removed_at mismatch");
        assert_eq!(original, deserialized, "full struct equality failed");
    }

    #[test]
    fn test_replica_removed_event_reason_rebalance() {
        let original = ReplicaRemovedEvent {
            chunk_hash: "chunk-rebalance".to_string(),
            node_id: "node-rebalance".to_string(),
            reason: ReplicaRemovalReason::Rebalance,
            removed_at: 1704153600000,
        };

        let serialized = bincode::serialize(&original).expect("serialization must succeed");
        let deserialized: ReplicaRemovedEvent =
            bincode::deserialize(&serialized).expect("deserialization must succeed");

        assert_eq!(original.chunk_hash, deserialized.chunk_hash, "chunk_hash mismatch");
        assert_eq!(original.node_id, deserialized.node_id, "node_id mismatch");
        assert_eq!(original.reason, deserialized.reason, "reason mismatch");
        assert_eq!(original.reason, ReplicaRemovalReason::Rebalance, "reason must be Rebalance");
        assert_eq!(original.removed_at, deserialized.removed_at, "removed_at mismatch");
        assert_eq!(original, deserialized, "full struct equality failed");
    }

    #[test]
    fn test_replica_removed_event_reason_corruption() {
        let original = ReplicaRemovedEvent {
            chunk_hash: "chunk-corrupt".to_string(),
            node_id: "node-corrupt".to_string(),
            reason: ReplicaRemovalReason::Corruption,
            removed_at: 1704240000000,
        };

        let serialized = bincode::serialize(&original).expect("serialization must succeed");
        let deserialized: ReplicaRemovedEvent =
            bincode::deserialize(&serialized).expect("deserialization must succeed");

        assert_eq!(original.chunk_hash, deserialized.chunk_hash, "chunk_hash mismatch");
        assert_eq!(original.node_id, deserialized.node_id, "node_id mismatch");
        assert_eq!(original.reason, deserialized.reason, "reason mismatch");
        assert_eq!(original.reason, ReplicaRemovalReason::Corruption, "reason must be Corruption");
        assert_eq!(original.removed_at, deserialized.removed_at, "removed_at mismatch");
        assert_eq!(original, deserialized, "full struct equality failed");
    }

    #[test]
    fn test_replica_removed_event_reason_manual() {
        let original = ReplicaRemovedEvent {
            chunk_hash: "chunk-manual".to_string(),
            node_id: "node-manual".to_string(),
            reason: ReplicaRemovalReason::Manual,
            removed_at: 1704326400000,
        };

        let serialized = bincode::serialize(&original).expect("serialization must succeed");
        let deserialized: ReplicaRemovedEvent =
            bincode::deserialize(&serialized).expect("deserialization must succeed");

        assert_eq!(original.chunk_hash, deserialized.chunk_hash, "chunk_hash mismatch");
        assert_eq!(original.node_id, deserialized.node_id, "node_id mismatch");
        assert_eq!(original.reason, deserialized.reason, "reason mismatch");
        assert_eq!(original.reason, ReplicaRemovalReason::Manual, "reason must be Manual");
        assert_eq!(original.removed_at, deserialized.removed_at, "removed_at mismatch");
        assert_eq!(original, deserialized, "full struct equality failed");
    }

    #[test]
    fn test_replica_removed_event_to_da_event_conversion() {
        let event = ReplicaRemovedEvent {
            chunk_hash: "test-chunk-removed".to_string(),
            node_id: "test-node-removed".to_string(),
            reason: ReplicaRemovalReason::Rebalance,
            removed_at: 1700000000000,
        };

        // Convert to DAEvent
        let da_event: DAEvent = event.clone().into();

        // Verify mapping
        match da_event {
            DAEvent::ReplicaRemoved {
                version,
                timestamp_ms,
                chunk_hash,
                node_id,
                reason,
            } => {
                assert_eq!(version, 1, "version must be 1");
                assert_eq!(timestamp_ms, event.removed_at, "timestamp_ms must equal removed_at");
                assert_eq!(chunk_hash, event.chunk_hash, "chunk_hash mapping failed");
                assert_eq!(node_id, event.node_id, "node_id mapping failed");
                assert_eq!(reason, event.reason, "reason mapping failed");
            }
            _ => panic!("conversion must produce DAEvent::ReplicaRemoved"),
        }
    }
}