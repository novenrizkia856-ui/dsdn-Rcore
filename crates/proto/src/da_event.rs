//! DA Event Schema for DSDN Data Availability Layer
//!
//! Schema ini adalah kontrak data yang TIDAK BOLEH DIUBAH setelah deploy.
//! Penambahan variant baru harus backward-compatible.

use serde::{Serialize, Deserialize};

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