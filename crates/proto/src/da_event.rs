//! DA Event Schema for DSDN Data Availability Layer
//!
//! Schema ini adalah kontrak data yang TIDAK BOLEH DIUBAH setelah deploy.
//! Penambahan variant baru harus backward-compatible.

use serde::{Serialize, Deserialize};
use sha3::{Sha3_256, Digest};

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