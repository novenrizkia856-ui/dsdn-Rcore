//! # Snapshot Types & Configuration (13.18.1)
//!
//! Module ini mendefinisikan tipe data dan konfigurasi untuk state snapshot system.
//!
//! ## Tujuan
//!
//! Snapshot system memungkinkan:
//! - Fast sync: Node baru download snapshot, replay blocks setelahnya
//! - Recovery: Rollback ke checkpoint saat terjadi corruption
//! - Audit: Verifikasi state historis
//!
//! ## Apa yang Disimpan di Snapshot
//!
//! ```text
//! snapshots/
//! └── checkpoint_{height}/
//!     ├── data.mdb          — LMDB database copy
//!     └── metadata.json     — SnapshotMetadata (height, state_root, timestamp, block_hash)
//! ```
//!
//! ## Status Tahap
//!
//! ```text
//! 13.18.1 — Snapshot Types & Configuration  ← CURRENT (types only, NO logic)
//! 13.18.2 — Snapshot Creation (LMDB copy)   — NEXT
//! 13.18.3 — Snapshot Loading & Validation   — PENDING
//! ```
//!
//! ## PERINGATAN
//!
//! Module ini HANYA berisi definisi tipe.
//! TIDAK ADA logic pembuatan, loading, atau validasi snapshot.
//! Logic akan ditambahkan di sub-tahap berikutnya.

use crate::types::Hash;
use serde::{Deserialize, Serialize};

// ════════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════════

/// Default interval untuk automatic snapshot creation.
///
/// Snapshot dibuat setiap N blocks untuk menyediakan checkpoint recovery.
/// Nilai 1000 blocks dipilih untuk balance antara:
/// - Storage overhead (tidak terlalu sering)
/// - Recovery time (tidak terlalu jarang)
///
/// Dapat di-override via SnapshotConfig.interval_blocks.
pub const DEFAULT_SNAPSHOT_INTERVAL: u64 = 1_000;

// ════════════════════════════════════════════════════════════════════════════════
// SNAPSHOT CONFIGURATION
// ════════════════════════════════════════════════════════════════════════════════

/// Konfigurasi untuk snapshot system.
///
/// Menentukan kapan dan di mana snapshot dibuat, serta berapa banyak yang disimpan.
///
/// ## Fields
///
/// - `interval_blocks`: Interval pembuatan snapshot (setiap N blocks)
/// - `path`: Direktori penyimpanan snapshot
/// - `max_snapshots`: Maksimum snapshot yang disimpan (FIFO cleanup)
///
/// ## Contoh
///
/// ```text
/// SnapshotConfig {
///     interval_blocks: 1000,      // Snapshot setiap 1000 blocks
///     path: "./snapshots",        // Simpan di ./snapshots/
///     max_snapshots: 5,           // Simpan maksimum 5 snapshot terbaru
/// }
/// ```
///
/// ## Lifecycle
///
/// 1. Config dibaca saat node startup
/// 2. Setiap block, check: height % interval_blocks == 0
/// 3. Jika true, create snapshot di path/checkpoint_{height}/
/// 4. Jika jumlah snapshot > max_snapshots, hapus yang tertua
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotConfig {
    /// Interval pembuatan snapshot dalam blocks.
    ///
    /// Snapshot dibuat ketika: block_height % interval_blocks == 0
    /// Default: DEFAULT_SNAPSHOT_INTERVAL (1000)
    pub interval_blocks: u64,

    /// Path direktori untuk menyimpan snapshots.
    ///
    /// Format: {path}/checkpoint_{height}/
    /// Contoh: "./snapshots/checkpoint_1000/"
    pub path: String,

    /// Maksimum jumlah snapshot yang disimpan.
    ///
    /// Ketika jumlah snapshot melebihi nilai ini,
    /// snapshot tertua akan dihapus (FIFO).
    /// Minimum: 1 (selalu simpan minimal 1 snapshot)
    pub max_snapshots: u32,
}

impl Default for SnapshotConfig {
    /// Default configuration untuk snapshot system.
    ///
    /// - interval_blocks: 1000 (setiap 1000 blocks)
    /// - path: "./snapshots" (direktori lokal)
    /// - max_snapshots: 5 (simpan 5 snapshot terbaru)
    fn default() -> Self {
        Self {
            interval_blocks: DEFAULT_SNAPSHOT_INTERVAL,
            path: String::from("./snapshots"),
            max_snapshots: 5,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// SNAPSHOT METADATA
// ════════════════════════════════════════════════════════════════════════════════

/// Metadata untuk setiap snapshot.
///
/// Disimpan sebagai metadata.json di folder snapshot untuk:
/// - Identifikasi snapshot (height, block_hash)
/// - Verifikasi integritas (state_root)
/// - Audit trail (timestamp)
///
/// ## Fields
///
/// - `height`: Block height saat snapshot dibuat
/// - `state_root`: State root dari block tersebut (untuk verifikasi)
/// - `timestamp`: Unix timestamp saat snapshot dibuat
/// - `block_hash`: Hash dari block tersebut
///
/// ## Verifikasi
///
/// Saat loading snapshot:
/// 1. Load LMDB dari data.mdb
/// 2. Compute state_root dari loaded state
/// 3. Compare dengan metadata.state_root
/// 4. Jika berbeda → SnapshotStatus::Corrupted
///
/// ## Format JSON
///
/// ```json
/// {
///     "height": 1000,
///     "state_root": "0x...",
///     "timestamp": 1700000000,
///     "block_hash": "0x..."
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotMetadata {
    /// Block height saat snapshot dibuat.
    ///
    /// Digunakan untuk:
    /// - Identifikasi snapshot
    /// - Menentukan dari mana replay blocks dimulai
    pub height: u64,

    /// State root dari block pada height ini.
    ///
    /// CONSENSUS-CRITICAL untuk verifikasi:
    /// - Setelah load snapshot, compute state_root
    /// - Harus IDENTIK dengan nilai ini
    /// - Jika berbeda, snapshot corrupted
    pub state_root: Hash,

    /// Unix timestamp saat snapshot dibuat.
    ///
    /// Untuk audit dan tracking.
    /// Bukan timestamp block, tapi timestamp pembuatan snapshot.
    pub timestamp: u64,

    /// Hash dari block pada height ini.
    ///
    /// Untuk cross-reference dengan block database.
    /// Memastikan snapshot dibuat dari block yang benar.
    pub block_hash: Hash,
}

// ════════════════════════════════════════════════════════════════════════════════
// SNAPSHOT STATUS
// ════════════════════════════════════════════════════════════════════════════════

/// Status snapshot untuk tracking lifecycle.
///
/// ## Status Flow
///
/// ```text
/// [Creating] ──success──► [Ready]
///     │                      │
///     │                      ▼
///     └──failure──► [Corrupted] ◄── validation failed
/// ```
///
/// ## Makna Status
///
/// - `Creating`: Snapshot sedang dibuat (LMDB copy in progress)
/// - `Ready`: Snapshot valid dan siap digunakan
/// - `Corrupted`: Snapshot rusak atau gagal verifikasi
///
/// ## Usage
///
/// ```text
/// 1. Mulai create snapshot → status = Creating
/// 2. LMDB copy selesai → status = Ready
/// 3. Saat load, verifikasi gagal → status = Corrupted
/// ```
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SnapshotStatus {
    /// Snapshot sedang dibuat.
    ///
    /// Status ini aktif selama:
    /// - LMDB copy in progress
    /// - Metadata belum ditulis
    ///
    /// Node TIDAK boleh menggunakan snapshot dengan status ini.
    Creating,

    /// Snapshot valid dan siap digunakan.
    ///
    /// Status ini berarti:
    /// - LMDB copy complete
    /// - Metadata tersimpan
    /// - Siap untuk fast sync atau recovery
    Ready,

    /// Snapshot rusak atau gagal verifikasi.
    ///
    /// Penyebab:
    /// - LMDB copy interrupted
    /// - state_root mismatch setelah load
    /// - File corruption
    ///
    /// Snapshot dengan status ini HARUS dihapus.
    Corrupted,
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_snapshot_config() {
        let config = SnapshotConfig::default();
        assert_eq!(config.interval_blocks, DEFAULT_SNAPSHOT_INTERVAL);
        assert_eq!(config.path, "./snapshots");
        assert_eq!(config.max_snapshots, 5);
    }

    #[test]
    fn test_snapshot_config_serialization() {
        let config = SnapshotConfig {
            interval_blocks: 500,
            path: String::from("/data/snapshots"),
            max_snapshots: 10,
        };

        let serialized = serde_json::to_string(&config);
        assert!(serialized.is_ok());

        let deserialized: Result<SnapshotConfig, _> =
            serde_json::from_str(&serialized.unwrap());
        assert!(deserialized.is_ok());
        assert_eq!(deserialized.unwrap(), config);
    }

    #[test]
    fn test_snapshot_metadata_serialization() {
        let metadata = SnapshotMetadata {
            height: 1000,
            state_root: Hash::from_bytes([0xAB; 64]),
            timestamp: 1700000000,
            block_hash: Hash::from_bytes([0xCD; 64]),
        };

        let serialized = serde_json::to_string(&metadata);
        assert!(serialized.is_ok());

        let deserialized: Result<SnapshotMetadata, _> =
            serde_json::from_str(&serialized.unwrap());
        assert!(deserialized.is_ok());
        assert_eq!(deserialized.unwrap(), metadata);
    }

    #[test]
    fn test_snapshot_status_values() {
        assert_ne!(SnapshotStatus::Creating, SnapshotStatus::Ready);
        assert_ne!(SnapshotStatus::Ready, SnapshotStatus::Corrupted);
        assert_ne!(SnapshotStatus::Creating, SnapshotStatus::Corrupted);
    }

    #[test]
    fn test_snapshot_status_serialization() {
        let statuses = [
            SnapshotStatus::Creating,
            SnapshotStatus::Ready,
            SnapshotStatus::Corrupted,
        ];

        for status in statuses {
            let serialized = serde_json::to_string(&status);
            assert!(serialized.is_ok());

            let deserialized: Result<SnapshotStatus, _> =
                serde_json::from_str(&serialized.unwrap());
            assert!(deserialized.is_ok());
            assert_eq!(deserialized.unwrap(), status);
        }
    }

    #[test]
    fn test_default_snapshot_interval_value() {
        assert_eq!(DEFAULT_SNAPSHOT_INTERVAL, 1_000);
    }
}