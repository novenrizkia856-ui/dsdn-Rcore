//! # DA-Aware Storage Module
//!
//! Modul ini menyediakan lapisan storage yang sadar Data Availability (DA).
//!
//! ## Arsitektur
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                        DAStorage                                 │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  ┌─────────────┐  ┌──────────────────┐  ┌───────────────────┐  │
//! │  │    inner    │  │  chunk_metadata  │  │  declared_chunks  │  │
//! │  │  (Storage)  │  │   (DA metadata)  │  │   (DA events)     │  │
//! │  └─────────────┘  └──────────────────┘  └───────────────────┘  │
//! │         │                  │                     │              │
//! │         ▼                  ▼                     ▼              │
//! │  ┌─────────────┐  ┌──────────────────┐  ┌───────────────────┐  │
//! │  │  Actual     │  │   Derived from   │  │  Received from    │  │
//! │  │  Data       │  │   DA events      │  │  DA layer         │  │
//! │  └─────────────┘  └──────────────────┘  └───────────────────┘  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Prinsip Kunci
//!
//! - `inner` adalah storage asli yang menyimpan data chunk
//! - `chunk_metadata` adalah STATE TURUNAN dari DA events
//! - `declared_chunks` menyimpan ChunkDeclared events dari DA
//! - Data di `inner` adalah sumber kebenaran untuk keberadaan chunk
//! - Metadata hanya untuk tracking hubungan dengan DA
//!
//! ## DA Metadata Sync Flow
//!
//! ```text
//! DA Layer → receive_chunk_declared() → declared_chunks
//!                                            │
//!                                            ▼
//!                    sync_metadata_from_da() → chunk_metadata
//! ```
//!
//! ## Invariant
//!
//! - Metadata BUKAN pengganti data
//! - has_chunk() HARUS cek inner, bukan metadata
//! - Error dari inner HARUS propagate, tidak boleh disembunyikan
//! - Metadata derived dari DA events, tidak boleh fiktif
//! - verified TIDAK BOLEH otomatis berubah ke true saat sync

use std::collections::HashMap;
use std::fmt::{self, Debug, Display};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::error::Error;

use parking_lot::{RwLock, MappedRwLockReadGuard, RwLockReadGuard};
use sha3::{Sha3_256, Digest};
use tracing::{debug, error, info, warn};

use dsdn_common::{BlobRef, DALayer, DAError};

use crate::store::Storage;

// ════════════════════════════════════════════════════════════════════════════
// STORAGE ERROR
// ════════════════════════════════════════════════════════════════════════════

/// Error type untuk operasi storage.
///
/// Digunakan untuk error spesifik storage yang tidak tercakup
/// oleh error types lainnya.
#[derive(Debug)]
pub enum StorageError {
    /// Chunk tidak ditemukan di storage.
    ChunkNotFound(String),
    /// Metadata tidak ditemukan.
    MetadataNotFound(String),
    /// IO error saat akses storage.
    IoError(String),
    /// Commitment mismatch antara data dan metadata.
    CommitmentMismatch {
        hash: String,
        expected: [u8; 32],
        actual: [u8; 32],
    },
    /// Error lainnya.
    Other(String),
}

impl Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageError::ChunkNotFound(hash) => write!(f, "Chunk not found: {}", hash),
            StorageError::MetadataNotFound(hash) => write!(f, "Metadata not found: {}", hash),
            StorageError::IoError(msg) => write!(f, "IO error: {}", msg),
            StorageError::CommitmentMismatch { hash, expected, actual } => {
                write!(
                    f,
                    "Commitment mismatch for {}: expected {:02x?}, got {:02x?}",
                    hash,
                    &expected[..4],
                    &actual[..4]
                )
            }
            StorageError::Other(msg) => write!(f, "Storage error: {}", msg),
        }
    }
}

impl Error for StorageError {}

impl From<Box<dyn Error + Send + Sync>> for StorageError {
    fn from(err: Box<dyn Error + Send + Sync>) -> Self {
        StorageError::IoError(err.to_string())
    }
}

// ════════════════════════════════════════════════════════════════════════════
// COMMITMENT REPORT
// ════════════════════════════════════════════════════════════════════════════

/// Laporan hasil verifikasi commitment untuk semua chunks.
///
/// Struct ini berisi ringkasan hasil verifikasi commitment
/// untuk semua chunks yang memiliki metadata.
///
/// # Fields
///
/// - `verified_count`: Jumlah chunks yang terverifikasi (data cocok dengan commitment)
/// - `failed_count`: Jumlah chunks yang gagal verifikasi (data tidak cocok)
/// - `missing_count`: Jumlah chunks yang metadata ada tapi data tidak ada
/// - `failed_chunks`: List hash chunks yang gagal verifikasi
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CommitmentReport {
    /// Jumlah chunks yang terverifikasi (data cocok dengan commitment).
    pub verified_count: usize,
    /// Jumlah chunks yang gagal verifikasi (data tidak cocok).
    pub failed_count: usize,
    /// Jumlah chunks yang metadata ada tapi data tidak ada.
    pub missing_count: usize,
    /// List hash chunks yang gagal verifikasi.
    pub failed_chunks: Vec<String>,
}

impl CommitmentReport {
    /// Membuat CommitmentReport baru (kosong).
    pub fn new() -> Self {
        Self::default()
    }

    /// Total chunks yang diproses.
    pub fn total_processed(&self) -> usize {
        self.verified_count + self.failed_count + self.missing_count
    }

    /// Apakah semua verifikasi berhasil.
    pub fn all_verified(&self) -> bool {
        self.failed_count == 0 && self.missing_count == 0
    }

    /// Apakah ada yang gagal.
    pub fn has_failures(&self) -> bool {
        self.failed_count > 0
    }

    /// Apakah ada yang missing.
    pub fn has_missing(&self) -> bool {
        self.missing_count > 0
    }
}

impl Display for CommitmentReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CommitmentReport {{ verified: {}, failed: {}, missing: {} }}",
            self.verified_count, self.failed_count, self.missing_count
        )
    }
}

// ════════════════════════════════════════════════════════════════════════════
// REPLICA INFO
// ════════════════════════════════════════════════════════════════════════════

/// Informasi tentang satu replica chunk.
///
/// Struct ini merepresentasikan satu node yang menyimpan replica
/// dari chunk tertentu. Derived dari DA events.
///
/// # Fields
///
/// - `node_id`: ID unik node yang menyimpan replica
/// - `added_at`: Timestamp saat replica ditambahkan (Unix ms)
/// - `blob_ref`: Referensi blob DA dari ReplicaAdded event
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicaInfo {
    /// ID unik node yang menyimpan replica.
    pub node_id: String,
    /// Timestamp saat replica ditambahkan (Unix milliseconds).
    pub added_at: u64,
    /// Referensi blob DA dari ReplicaAdded event.
    pub blob_ref: Option<BlobRef>,
}

impl ReplicaInfo {
    /// Membuat ReplicaInfo baru.
    pub fn new(node_id: String, added_at: u64, blob_ref: Option<BlobRef>) -> Self {
        Self {
            node_id,
            added_at,
            blob_ref,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// REPLICA EVENTS
// ════════════════════════════════════════════════════════════════════════════

/// Event yang menandakan replica ditambahkan.
///
/// Diterima dari DA layer ketika node mendeklarasikan
/// bahwa ia menyimpan replica chunk tertentu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicaAddedEvent {
    /// Hash chunk yang di-replica.
    pub chunk_hash: String,
    /// ID node yang menyimpan replica.
    pub node_id: String,
    /// Timestamp event (Unix milliseconds).
    pub timestamp: u64,
    /// Referensi blob DA.
    pub blob_ref: Option<BlobRef>,
}

impl ReplicaAddedEvent {
    /// Membuat ReplicaAddedEvent baru.
    pub fn new(
        chunk_hash: String,
        node_id: String,
        timestamp: u64,
        blob_ref: Option<BlobRef>,
    ) -> Self {
        Self {
            chunk_hash,
            node_id,
            timestamp,
            blob_ref,
        }
    }
}

/// Event yang menandakan replica dihapus.
///
/// Diterima dari DA layer ketika node tidak lagi
/// menyimpan replica chunk tertentu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicaRemovedEvent {
    /// Hash chunk yang replica-nya dihapus.
    pub chunk_hash: String,
    /// ID node yang menghapus replica.
    pub node_id: String,
    /// Timestamp event (Unix milliseconds).
    pub timestamp: u64,
    /// Referensi blob DA.
    pub blob_ref: Option<BlobRef>,
}

impl ReplicaRemovedEvent {
    /// Membuat ReplicaRemovedEvent baru.
    pub fn new(
        chunk_hash: String,
        node_id: String,
        timestamp: u64,
        blob_ref: Option<BlobRef>,
    ) -> Self {
        Self {
            chunk_hash,
            node_id,
            timestamp,
            blob_ref,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// CHUNK DECLARED EVENT
// ════════════════════════════════════════════════════════════════════════════

/// Event yang mendeklarasikan chunk di DA layer.
///
/// Struct ini merepresentasikan ChunkDeclared event yang diterima
/// dari DA layer. Setiap event mendeklarasikan keberadaan chunk
/// dengan metadata terkait.
///
/// # Fields
///
/// - `chunk_hash`: Hash unik chunk (canonical string)
/// - `size_bytes`: Ukuran chunk dalam bytes
/// - `da_commitment`: Commitment 32-byte dari DA
/// - `blob_ref`: Referensi ke blob DA tempat event dipublish
/// - `declared_at`: Timestamp (Unix ms) saat event dideklarasikan
/// - `target_rf`: Target replication factor untuk chunk ini
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkDeclaredEvent {
    /// Hash unik chunk.
    pub chunk_hash: String,
    /// Ukuran chunk dalam bytes.
    pub size_bytes: u64,
    /// Commitment 32-byte dari DA.
    pub da_commitment: [u8; 32],
    /// Referensi ke blob DA.
    pub blob_ref: Option<BlobRef>,
    /// Timestamp deklarasi (Unix milliseconds).
    pub declared_at: u64,
    /// Target replication factor.
    pub target_rf: u8,
}

impl ChunkDeclaredEvent {
    /// Membuat ChunkDeclaredEvent baru.
    pub fn new(
        chunk_hash: String,
        size_bytes: u64,
        da_commitment: [u8; 32],
        blob_ref: Option<BlobRef>,
        declared_at: u64,
    ) -> Self {
        Self {
            chunk_hash,
            size_bytes,
            da_commitment,
            blob_ref,
            declared_at,
            target_rf: 3, // Default RF
        }
    }

    /// Membuat ChunkDeclaredEvent dengan target_rf spesifik.
    pub fn with_target_rf(
        chunk_hash: String,
        size_bytes: u64,
        da_commitment: [u8; 32],
        blob_ref: Option<BlobRef>,
        declared_at: u64,
        target_rf: u8,
    ) -> Self {
        Self {
            chunk_hash,
            size_bytes,
            da_commitment,
            blob_ref,
            declared_at,
            target_rf,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// DA CHUNK METADATA
// ════════════════════════════════════════════════════════════════════════════

/// Metadata chunk yang terkait dengan Data Availability layer.
///
/// Struct ini menyimpan informasi hubungan antara chunk di storage
/// dengan blob di DA layer. Ini adalah STATE TURUNAN, bukan authoritative.
///
/// # Fields
///
/// - `hash`: Chunk hash (string canonical)
/// - `size_bytes`: Ukuran chunk dalam bytes
/// - `da_commitment`: Commitment 32-byte dari DA
/// - `blob_ref`: Referensi blob DA (jika sudah dipublish)
/// - `verified`: Hasil verifikasi terhadap DA
/// - `replicas`: Daftar replica berdasarkan DA events (DERIVED ONLY)
/// - `target_rf`: Target replication factor dari ChunkDeclared event
/// - `current_rf`: Jumlah replica aktif saat ini (konsisten dengan replicas.len())
///
/// # Invariant
///
/// - `verified` TIDAK BOLEH default `true`. Chunk harus diverifikasi
///   secara eksplisit sebelum dianggap verified.
/// - `replicas` HANYA diisi dari DA events, TIDAK BOLEH dari asumsi lokal
/// - `current_rf` HARUS selalu sama dengan `replicas.len()`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DAChunkMeta {
    /// Chunk hash (string canonical).
    pub hash: String,
    /// Ukuran chunk dalam bytes.
    pub size_bytes: u64,
    /// Commitment 32-byte dari DA.
    pub da_commitment: [u8; 32],
    /// Referensi blob DA (jika sudah dipublish).
    pub blob_ref: Option<BlobRef>,
    /// Hasil verifikasi terhadap DA. Default: false.
    pub verified: bool,
    /// Daftar replica berdasarkan DA events. DERIVED ONLY.
    pub replicas: Vec<ReplicaInfo>,
    /// Target replication factor dari ChunkDeclared event.
    pub target_rf: u8,
    /// Jumlah replica aktif saat ini. MUST equal replicas.len().
    pub current_rf: u8,
}

impl DAChunkMeta {
    /// Membuat DAChunkMeta baru.
    ///
    /// # Arguments
    ///
    /// * `hash` - Chunk hash
    /// * `size_bytes` - Ukuran chunk
    /// * `da_commitment` - Commitment dari DA
    ///
    /// # Returns
    ///
    /// DAChunkMeta dengan `verified = false`, `blob_ref = None`,
    /// `replicas = []`, `target_rf = 3`, `current_rf = 0`.
    pub fn new(hash: String, size_bytes: u64, da_commitment: [u8; 32]) -> Self {
        Self {
            hash,
            size_bytes,
            da_commitment,
            blob_ref: None,
            verified: false, // WAJIB default false
            replicas: Vec::new(), // WAJIB kosong, derived only
            target_rf: 3, // Default RF
            current_rf: 0, // WAJIB 0, no replicas yet
        }
    }

    /// Membuat DAChunkMeta dengan target_rf spesifik.
    pub fn with_target_rf(
        hash: String,
        size_bytes: u64,
        da_commitment: [u8; 32],
        target_rf: u8,
    ) -> Self {
        Self {
            hash,
            size_bytes,
            da_commitment,
            blob_ref: None,
            verified: false,
            replicas: Vec::new(),
            target_rf,
            current_rf: 0,
        }
    }

    /// Membuat DAChunkMeta dengan BlobRef.
    ///
    /// Digunakan ketika chunk berasal dari DA blob.
    pub fn with_blob_ref(
        hash: String,
        size_bytes: u64,
        da_commitment: [u8; 32],
        blob_ref: BlobRef,
    ) -> Self {
        Self {
            hash,
            size_bytes,
            da_commitment,
            blob_ref: Some(blob_ref),
            verified: false, // WAJIB default false
            replicas: Vec::new(),
            target_rf: 3,
            current_rf: 0,
        }
    }

    /// Set verified status.
    ///
    /// # Arguments
    ///
    /// * `verified` - Status verifikasi
    pub fn set_verified(&mut self, verified: bool) {
        self.verified = verified;
    }

    /// Set blob reference.
    ///
    /// # Arguments
    ///
    /// * `blob_ref` - Referensi blob DA
    pub fn set_blob_ref(&mut self, blob_ref: BlobRef) {
        self.blob_ref = Some(blob_ref);
    }

    /// Add replica from ReplicaAdded event.
    ///
    /// # Arguments
    ///
    /// * `replica` - ReplicaInfo to add
    ///
    /// # Returns
    ///
    /// `true` if replica was added, `false` if already exists (no duplicate).
    pub fn add_replica(&mut self, replica: ReplicaInfo) -> bool {
        // Check for duplicate
        if self.replicas.iter().any(|r| r.node_id == replica.node_id) {
            return false;
        }
        self.replicas.push(replica);
        self.current_rf = self.replicas.len() as u8;
        true
    }

    /// Remove replica by node_id.
    ///
    /// # Arguments
    ///
    /// * `node_id` - ID node yang replicanya dihapus
    ///
    /// # Returns
    ///
    /// `true` if replica was removed, `false` if not found.
    pub fn remove_replica(&mut self, node_id: &str) -> bool {
        let initial_len = self.replicas.len();
        self.replicas.retain(|r| r.node_id != node_id);
        let removed = self.replicas.len() < initial_len;
        self.current_rf = self.replicas.len() as u8;
        removed
    }

    /// Get list of node IDs that hold replicas.
    ///
    /// # Returns
    ///
    /// Vector of node_id strings, sorted for determinism.
    pub fn replica_node_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.replicas.iter().map(|r| r.node_id.clone()).collect();
        ids.sort();
        ids
    }

    /// Check if a node is a replica holder.
    ///
    /// # Arguments
    ///
    /// * `node_id` - Node ID to check
    ///
    /// # Returns
    ///
    /// `true` if node holds a replica.
    pub fn is_replica(&self, node_id: &str) -> bool {
        self.replicas.iter().any(|r| r.node_id == node_id)
    }

    /// Update from ChunkDeclaredEvent.
    ///
    /// Updates only DA-derived fields. Does NOT change:
    /// - verified (MUST NOT auto-change to true)
    /// - replicas (only changed by ReplicaAdded/Removed events)
    /// - current_rf (derived from replicas)
    ///
    /// DOES update:
    /// - target_rf from event
    ///
    /// # Arguments
    ///
    /// * `event` - ChunkDeclaredEvent to update from
    fn update_from_event(&mut self, event: &ChunkDeclaredEvent) {
        // Update DA-derived fields only
        self.size_bytes = event.size_bytes;
        self.da_commitment = event.da_commitment;
        self.target_rf = event.target_rf;
        if event.blob_ref.is_some() {
            self.blob_ref = event.blob_ref.clone();
        }
        // CRITICAL: verified TIDAK BOLEH diubah ke true secara otomatis
        // CRITICAL: replicas TIDAK BOLEH diubah dari ChunkDeclared event
    }
}

// ════════════════════════════════════════════════════════════════════════════
// DA STORAGE
// ════════════════════════════════════════════════════════════════════════════

/// Storage wrapper yang sadar Data Availability.
///
/// `DAStorage` membungkus storage asli dan menambahkan tracking
/// metadata untuk hubungan dengan DA layer.
///
/// # Arsitektur
///
/// - `inner`: Storage asli (filesystem / memory / dll)
/// - `da`: Sumber kebenaran Data Availability
/// - `chunk_metadata`: STATE TURUNAN, bukan authoritative
/// - `declared_chunks`: ChunkDeclared events dari DA
/// - `replica_added_events`: ReplicaAdded events dari DA
/// - `replica_removed_events`: ReplicaRemoved events dari DA
///
/// # Prinsip
///
/// - Semua operasi data didelegasikan ke `inner`
/// - Metadata di-sync dari DA events
/// - `inner` adalah sumber kebenaran untuk keberadaan data
/// - Metadata hanya untuk tracking, bukan pengganti data
/// - Replica info HANYA dari DA events, TIDAK dari asumsi lokal
///
/// # Invariant
///
/// - `has_chunk()` HARUS cek `inner`, bukan metadata
/// - Error dari `inner` HARUS propagate
/// - Metadata tidak boleh menggantikan data asli
/// - Metadata derived dari DA events
/// - Replica list derived dari ReplicaAdded/Removed events
pub struct DAStorage {
    /// Storage asli yang menyimpan data chunk.
    inner: Arc<dyn Storage>,
    /// DA layer untuk verifikasi dan referensi.
    da: Arc<dyn DALayer>,
    /// Metadata chunk terkait DA. STATE TURUNAN, bukan authoritative.
    chunk_metadata: RwLock<HashMap<String, DAChunkMeta>>,
    /// ChunkDeclared events yang diterima dari DA.
    declared_chunks: RwLock<HashMap<String, ChunkDeclaredEvent>>,
    /// ReplicaAdded events yang diterima dari DA. Key: (chunk_hash, node_id).
    replica_added_events: RwLock<HashMap<(String, String), ReplicaAddedEvent>>,
    /// ReplicaRemoved events yang diterima dari DA. Key: (chunk_hash, node_id).
    replica_removed_events: RwLock<HashMap<(String, String), ReplicaRemovedEvent>>,
    /// Flag untuk menghentikan background sync.
    sync_running: AtomicBool,
}

impl Debug for DAStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DAStorage")
            .field("inner", &self.inner)
            .field("da", &"<DALayer>")
            .field("chunk_metadata_count", &self.chunk_metadata.read().len())
            .field("declared_chunks_count", &self.declared_chunks.read().len())
            .field("replica_added_events_count", &self.replica_added_events.read().len())
            .field("replica_removed_events_count", &self.replica_removed_events.read().len())
            .finish()
    }
}

impl DAStorage {
    /// Membuat DAStorage baru.
    ///
    /// # Arguments
    ///
    /// * `inner` - Storage asli untuk penyimpanan data
    /// * `da` - DA layer untuk tracking dan verifikasi
    ///
    /// # Returns
    ///
    /// DAStorage baru dengan metadata kosong.
    pub fn new(inner: Arc<dyn Storage>, da: Arc<dyn DALayer>) -> Self {
        Self {
            inner,
            da,
            chunk_metadata: RwLock::new(HashMap::new()),
            declared_chunks: RwLock::new(HashMap::new()),
            replica_added_events: RwLock::new(HashMap::new()),
            replica_removed_events: RwLock::new(HashMap::new()),
            sync_running: AtomicBool::new(false),
        }
    }

    /// Get reference to inner storage.
    ///
    /// # Returns
    ///
    /// Reference to the underlying storage.
    pub fn inner(&self) -> &Arc<dyn Storage> {
        &self.inner
    }

    /// Get reference to DA layer.
    ///
    /// # Returns
    ///
    /// Reference to the DA layer.
    pub fn da(&self) -> &Arc<dyn DALayer> {
        &self.da
    }

    // ════════════════════════════════════════════════════════════════════════
    // DA EVENT RECEIVING
    // ════════════════════════════════════════════════════════════════════════

    /// Menerima ChunkDeclared event dari DA.
    ///
    /// Method ini dipanggil oleh DA consumer ketika menerima
    /// ChunkDeclared event dari DA layer.
    ///
    /// # Arguments
    ///
    /// * `event` - ChunkDeclaredEvent yang diterima
    ///
    /// # Behavior
    ///
    /// - Menyimpan event ke declared_chunks
    /// - Tidak langsung update metadata (gunakan sync_metadata_from_da)
    /// - Idempotent: event yang sama akan di-overwrite
    pub fn receive_chunk_declared(&self, event: ChunkDeclaredEvent) {
        debug!("Received ChunkDeclared event for chunk: {}", event.chunk_hash);
        self.declared_chunks
            .write()
            .insert(event.chunk_hash.clone(), event);
    }

    /// Menerima multiple ChunkDeclared events dari DA.
    ///
    /// # Arguments
    ///
    /// * `events` - Iterator of ChunkDeclaredEvent
    ///
    /// # Returns
    ///
    /// Jumlah events yang diterima.
    pub fn receive_chunk_declared_batch<I>(&self, events: I) -> usize
    where
        I: IntoIterator<Item = ChunkDeclaredEvent>,
    {
        let mut declared = self.declared_chunks.write();
        let mut count = 0;
        for event in events {
            declared.insert(event.chunk_hash.clone(), event);
            count += 1;
        }
        debug!("Received {} ChunkDeclared events", count);
        count
    }

    // ════════════════════════════════════════════════════════════════════════
    // REPLICA EVENT RECEIVING (14A.45)
    // ════════════════════════════════════════════════════════════════════════

    /// Menerima ReplicaAdded event dari DA.
    ///
    /// # Arguments
    ///
    /// * `event` - ReplicaAddedEvent yang diterima
    ///
    /// # Behavior
    ///
    /// - Menyimpan event ke replica_added_events
    /// - Idempotent: event yang sama akan di-overwrite
    pub fn receive_replica_added(&self, event: ReplicaAddedEvent) {
        debug!(
            "Received ReplicaAdded event: chunk={}, node={}",
            event.chunk_hash, event.node_id
        );
        let key = (event.chunk_hash.clone(), event.node_id.clone());
        self.replica_added_events.write().insert(key, event);
    }

    /// Menerima ReplicaRemoved event dari DA.
    ///
    /// # Arguments
    ///
    /// * `event` - ReplicaRemovedEvent yang diterima
    ///
    /// # Behavior
    ///
    /// - Menyimpan event ke replica_removed_events
    /// - Idempotent: event yang sama akan di-overwrite
    pub fn receive_replica_removed(&self, event: ReplicaRemovedEvent) {
        debug!(
            "Received ReplicaRemoved event: chunk={}, node={}",
            event.chunk_hash, event.node_id
        );
        let key = (event.chunk_hash.clone(), event.node_id.clone());
        self.replica_removed_events.write().insert(key, event);
    }

    /// Menerima batch ReplicaAdded events.
    ///
    /// # Returns
    ///
    /// Jumlah events yang diterima.
    pub fn receive_replica_added_batch<I>(&self, events: I) -> usize
    where
        I: IntoIterator<Item = ReplicaAddedEvent>,
    {
        let mut added = self.replica_added_events.write();
        let mut count = 0;
        for event in events {
            let key = (event.chunk_hash.clone(), event.node_id.clone());
            added.insert(key, event);
            count += 1;
        }
        debug!("Received {} ReplicaAdded events", count);
        count
    }

    /// Menerima batch ReplicaRemoved events.
    ///
    /// # Returns
    ///
    /// Jumlah events yang diterima.
    pub fn receive_replica_removed_batch<I>(&self, events: I) -> usize
    where
        I: IntoIterator<Item = ReplicaRemovedEvent>,
    {
        let mut removed = self.replica_removed_events.write();
        let mut count = 0;
        for event in events {
            let key = (event.chunk_hash.clone(), event.node_id.clone());
            removed.insert(key, event);
            count += 1;
        }
        debug!("Received {} ReplicaRemoved events", count);
        count
    }

    // ════════════════════════════════════════════════════════════════════════
    // DA METADATA SYNC (14A.42)
    // ════════════════════════════════════════════════════════════════════════

    /// Sinkronisasi metadata chunk dari DA events.
    ///
    /// Method ini mengupdate chunk_metadata berdasarkan ChunkDeclared
    /// events yang telah diterima via receive_chunk_declared().
    ///
    /// # Returns
    ///
    /// - `Ok(usize)`: Jumlah metadata chunk yang berhasil disinkronkan
    /// - `Err(DAError)`: Jika terjadi error
    ///
    /// # Behavior
    ///
    /// - Untuk setiap ChunkDeclared event:
    ///   - Jika chunk belum ada di metadata → insert
    ///   - Jika chunk sudah ada → update hanya field DA-derived
    /// - `verified` TIDAK BOLEH otomatis berubah ke true
    /// - Tidak menyentuh data chunk fisik
    /// - Tidak menghapus metadata tanpa event eksplisit
    ///
    /// # Invariant
    ///
    /// - Return value = jumlah metadata yang di-sync
    /// - Idempotent: sync berkali-kali tidak membuat duplikat
    pub fn sync_metadata_from_da(&self) -> Result<usize, DAError> {
        let declared = self.declared_chunks.read();
        let mut metadata = self.chunk_metadata.write();

        let mut synced_count = 0;

        for (hash, event) in declared.iter() {
            if let Some(existing) = metadata.get_mut(hash) {
                // Update existing metadata dengan DA-derived fields
                // CRITICAL: verified TIDAK BOLEH auto-true
                existing.update_from_event(event);
                synced_count += 1;
            } else {
                // Insert new metadata dari event dengan target_rf
                let mut meta = DAChunkMeta::with_target_rf(
                    event.chunk_hash.clone(),
                    event.size_bytes,
                    event.da_commitment,
                    event.target_rf,
                );
                if let Some(ref blob_ref) = event.blob_ref {
                    meta.blob_ref = Some(blob_ref.clone());
                }
                // CRITICAL: verified = false (already default)
                // CRITICAL: replicas = [] (must be synced separately)
                metadata.insert(hash.clone(), meta);
                synced_count += 1;
            }
        }

        debug!("Synced {} metadata entries from DA events", synced_count);
        Ok(synced_count)
    }

    /// Get metadata reference for a chunk.
    ///
    /// # Arguments
    ///
    /// * `hash` - Chunk hash
    ///
    /// # Returns
    ///
    /// - `Some(guard)`: Guard yang dapat di-deref ke &DAChunkMeta
    /// - `None`: Jika metadata tidak ada
    ///
    /// # Note
    ///
    /// Return type adalah MappedRwLockReadGuard yang implement Deref<Target=DAChunkMeta>.
    /// Gunakan `&*guard` atau deref langsung untuk mendapatkan &DAChunkMeta.
    ///
    /// TIDAK melakukan fetch DA.
    /// TIDAK ada side-effect.
    pub fn get_chunk_meta(&self, hash: &str) -> Option<MappedRwLockReadGuard<'_, DAChunkMeta>> {
        let guard = self.chunk_metadata.read();
        if guard.contains_key(hash) {
            Some(RwLockReadGuard::map(guard, |m| m.get(hash).unwrap()))
        } else {
            None
        }
    }

    /// List semua chunk hash yang pernah dideklarasikan di DA.
    ///
    /// # Returns
    ///
    /// Vector of chunk hashes yang dideklarasikan, sorted untuk determinism.
    ///
    /// # Note
    ///
    /// - TIDAK query DA langsung
    /// - Urutan deterministik dan konsisten
    pub fn list_declared_chunks(&self) -> Vec<String> {
        let declared = self.declared_chunks.read();
        let mut hashes: Vec<String> = declared.keys().cloned().collect();
        hashes.sort(); // Deterministic ordering
        hashes
    }

    /// Get count of declared chunks.
    pub fn declared_chunks_count(&self) -> usize {
        self.declared_chunks.read().len()
    }

    /// Check if chunk is declared in DA.
    pub fn is_chunk_declared(&self, hash: &str) -> bool {
        self.declared_chunks.read().contains_key(hash)
    }

    /// Get declared event for a chunk.
    pub fn get_declared_event(&self, hash: &str) -> Option<ChunkDeclaredEvent> {
        self.declared_chunks.read().get(hash).cloned()
    }

    // ════════════════════════════════════════════════════════════════════════
    // REPLICA TRACKING (14A.45)
    // ════════════════════════════════════════════════════════════════════════

    /// Sinkronisasi replica info dari DA events untuk satu chunk.
    ///
    /// # Arguments
    ///
    /// * `chunk_hash` - Hash chunk yang akan di-sync
    ///
    /// # Returns
    ///
    /// - `Ok(())`: Sync berhasil
    /// - `Err(DAError)`: Jika metadata chunk tidak ada
    ///
    /// # Behavior
    ///
    /// - Fetch ReplicaAdded dan ReplicaRemoved events untuk chunk_hash
    /// - Proses events secara urut berdasarkan timestamp
    /// - ReplicaAdded → tambahkan ke replicas (jika belum ada)
    /// - ReplicaRemoved → hapus dari replicas
    /// - Update current_rf sesuai replicas.len()
    /// - target_rf TIDAK DIUBAH (hanya dari ChunkDeclared event)
    ///
    /// # Invariant
    ///
    /// - Idempotent: sync berkali-kali menghasilkan state yang sama
    /// - current_rf selalu konsisten dengan replicas.len()
    /// - Tidak menghapus metadata chunk
    /// - Tidak panic
    pub fn sync_replica_info(&self, chunk_hash: &str) -> Result<(), DAError> {
        // Check metadata exists
        if !self.chunk_metadata.read().contains_key(chunk_hash) {
            return Err(DAError::Other(format!(
                "Metadata not found for chunk: {}",
                chunk_hash
            )));
        }

        // Collect all replica events for this chunk
        let added_events: Vec<ReplicaAddedEvent> = {
            let added = self.replica_added_events.read();
            added
                .iter()
                .filter(|((hash, _), _)| hash == chunk_hash)
                .map(|(_, event)| event.clone())
                .collect()
        };

        let removed_events: Vec<ReplicaRemovedEvent> = {
            let removed = self.replica_removed_events.read();
            removed
                .iter()
                .filter(|((hash, _), _)| hash == chunk_hash)
                .map(|(_, event)| event.clone())
                .collect()
        };

        // Combine and sort by timestamp
        #[derive(Debug)]
        enum ReplicaEvent {
            Added(ReplicaAddedEvent),
            Removed(ReplicaRemovedEvent),
        }

        let mut events: Vec<(u64, ReplicaEvent)> = Vec::new();
        for e in added_events {
            events.push((e.timestamp, ReplicaEvent::Added(e)));
        }
        for e in removed_events {
            events.push((e.timestamp, ReplicaEvent::Removed(e)));
        }
        events.sort_by_key(|(ts, _)| *ts);

        // Apply events to metadata
        let mut metadata = self.chunk_metadata.write();
        if let Some(meta) = metadata.get_mut(chunk_hash) {
            // Clear and rebuild replicas from events
            meta.replicas.clear();

            for (_, event) in events {
                match event {
                    ReplicaEvent::Added(e) => {
                        let replica = ReplicaInfo::new(
                            e.node_id.clone(),
                            e.timestamp,
                            e.blob_ref.clone(),
                        );
                        // Add if not duplicate
                        if !meta.replicas.iter().any(|r| r.node_id == e.node_id) {
                            meta.replicas.push(replica);
                        }
                    }
                    ReplicaEvent::Removed(e) => {
                        meta.replicas.retain(|r| r.node_id != e.node_id);
                    }
                }
            }

            // Update current_rf
            meta.current_rf = meta.replicas.len() as u8;

            debug!(
                "Synced replica info for {}: current_rf={}, target_rf={}",
                chunk_hash, meta.current_rf, meta.target_rf
            );
        }

        Ok(())
    }

    /// Sinkronisasi replica info untuk semua chunks.
    ///
    /// # Returns
    ///
    /// Jumlah chunks yang di-sync.
    pub fn sync_all_replica_info(&self) -> Result<usize, DAError> {
        let hashes: Vec<String> = {
            let metadata = self.chunk_metadata.read();
            metadata.keys().cloned().collect()
        };

        let mut synced = 0;
        for hash in hashes {
            if self.sync_replica_info(&hash).is_ok() {
                synced += 1;
            }
        }

        debug!("Synced replica info for {} chunks", synced);
        Ok(synced)
    }

    /// Get list of node IDs yang menyimpan replica chunk.
    ///
    /// # Arguments
    ///
    /// * `chunk_hash` - Hash chunk
    ///
    /// # Returns
    ///
    /// Vector of node_id strings, sorted untuk determinism.
    /// Empty vec jika chunk tidak ada.
    ///
    /// # Note
    ///
    /// - TIDAK query DA
    /// - PURE READ, tanpa side-effect
    pub fn get_replica_nodes(&self, chunk_hash: &str) -> Vec<String> {
        let metadata = self.chunk_metadata.read();
        match metadata.get(chunk_hash) {
            Some(meta) => meta.replica_node_ids(),
            None => Vec::new(),
        }
    }

    /// Check apakah node ini adalah replica holder.
    ///
    /// # Arguments
    ///
    /// * `chunk_hash` - Hash chunk
    /// * `my_node_id` - ID node untuk dicek
    ///
    /// # Returns
    ///
    /// - `true`: Node adalah replica holder
    /// - `false`: Bukan replica atau chunk tidak ada
    ///
    /// # Note
    ///
    /// PURE FUNCTION, tanpa side-effect.
    pub fn am_i_replica(&self, chunk_hash: &str, my_node_id: &str) -> bool {
        let metadata = self.chunk_metadata.read();
        match metadata.get(chunk_hash) {
            Some(meta) => meta.is_replica(my_node_id),
            None => false,
        }
    }

    /// Get replication factor info untuk chunk.
    ///
    /// # Arguments
    ///
    /// * `chunk_hash` - Hash chunk
    ///
    /// # Returns
    ///
    /// `Some((current_rf, target_rf))` jika chunk ada, `None` jika tidak.
    pub fn get_rf_info(&self, chunk_hash: &str) -> Option<(u8, u8)> {
        let metadata = self.chunk_metadata.read();
        metadata.get(chunk_hash).map(|meta| (meta.current_rf, meta.target_rf))
    }

    /// Get all chunks that are under-replicated.
    ///
    /// # Returns
    ///
    /// Vector of chunk hashes where current_rf < target_rf.
    pub fn under_replicated_chunks(&self) -> Vec<String> {
        let metadata = self.chunk_metadata.read();
        metadata
            .iter()
            .filter(|(_, meta)| meta.current_rf < meta.target_rf)
            .map(|(hash, _)| hash.clone())
            .collect()
    }

    /// Get all chunks that meet replication factor.
    ///
    /// # Returns
    ///
    /// Vector of chunk hashes where current_rf >= target_rf.
    pub fn fully_replicated_chunks(&self) -> Vec<String> {
        let metadata = self.chunk_metadata.read();
        metadata
            .iter()
            .filter(|(_, meta)| meta.current_rf >= meta.target_rf)
            .map(|(hash, _)| hash.clone())
            .collect()
    }

    // ════════════════════════════════════════════════════════════════════════
    // BACKGROUND SYNC TASK
    // ════════════════════════════════════════════════════════════════════════

    /// Start background metadata sync task.
    ///
    /// # Arguments
    ///
    /// * `interval` - Interval antara sync (Duration)
    ///
    /// # Returns
    ///
    /// JoinHandle untuk task. Task berhenti ketika stop_background_sync() dipanggil.
    ///
    /// # Behavior
    ///
    /// - Memanggil sync_metadata_from_da() secara periodik
    /// - Handle error dengan logging (tidak panic)
    /// - Berhenti ketika sync_running = false
    pub fn start_background_sync(
        self: &Arc<Self>,
        interval: Duration,
    ) -> tokio::task::JoinHandle<()> {
        let storage = Arc::clone(self);
        storage.sync_running.store(true, Ordering::SeqCst);

        tokio::spawn(async move {
            info!("Background metadata sync started with interval {:?}", interval);
            let mut interval_timer = tokio::time::interval(interval);

            while storage.sync_running.load(Ordering::SeqCst) {
                interval_timer.tick().await;

                if !storage.sync_running.load(Ordering::SeqCst) {
                    break;
                }

                match storage.sync_metadata_from_da() {
                    Ok(count) => {
                        if count > 0 {
                            debug!("Background sync: synced {} metadata entries", count);
                        }
                    }
                    Err(e) => {
                        error!("Background sync error: {}", e);
                    }
                }
            }

            info!("Background metadata sync stopped");
        })
    }

    /// Stop background sync task.
    ///
    /// Sets sync_running to false. Task akan berhenti pada iterasi berikutnya.
    pub fn stop_background_sync(&self) {
        self.sync_running.store(false, Ordering::SeqCst);
        info!("Background sync stop requested");
    }

    /// Check if background sync is running.
    pub fn is_sync_running(&self) -> bool {
        self.sync_running.load(Ordering::SeqCst)
    }

    // ════════════════════════════════════════════════════════════════════════
    // EXISTING METHODS (from 14A.41)
    // ════════════════════════════════════════════════════════════════════════

    /// Get metadata for a chunk (clone).
    ///
    /// # Arguments
    ///
    /// * `hash` - Chunk hash
    ///
    /// # Returns
    ///
    /// Clone of metadata if exists, None otherwise.
    pub fn get_metadata(&self, hash: &str) -> Option<DAChunkMeta> {
        self.chunk_metadata.read().get(hash).cloned()
    }

    /// Set metadata for a chunk.
    ///
    /// # Arguments
    ///
    /// * `hash` - Chunk hash
    /// * `meta` - Metadata to set
    pub fn set_metadata(&self, hash: &str, meta: DAChunkMeta) {
        self.chunk_metadata.write().insert(hash.to_string(), meta);
    }

    /// Remove metadata for a chunk.
    ///
    /// # Arguments
    ///
    /// * `hash` - Chunk hash
    ///
    /// # Returns
    ///
    /// Removed metadata if existed.
    pub fn remove_metadata(&self, hash: &str) -> Option<DAChunkMeta> {
        self.chunk_metadata.write().remove(hash)
    }

    /// Check if metadata exists for a chunk.
    ///
    /// # Note
    ///
    /// Ini HANYA cek metadata, bukan keberadaan data.
    /// Untuk cek keberadaan data, gunakan `has_chunk()`.
    pub fn has_metadata(&self, hash: &str) -> bool {
        self.chunk_metadata.read().contains_key(hash)
    }

    /// Get count of tracked metadata entries.
    pub fn metadata_count(&self) -> usize {
        self.chunk_metadata.read().len()
    }

    /// Get all metadata entries.
    ///
    /// # Returns
    ///
    /// Clone of all metadata.
    pub fn all_metadata(&self) -> HashMap<String, DAChunkMeta> {
        self.chunk_metadata.read().clone()
    }

    /// Clear all metadata.
    ///
    /// # Warning
    ///
    /// Ini TIDAK menghapus data dari storage.
    /// Hanya menghapus metadata tracking.
    pub fn clear_metadata(&self) {
        self.chunk_metadata.write().clear();
    }

    /// Put chunk with DA metadata.
    ///
    /// # Arguments
    ///
    /// * `hash` - Chunk hash
    /// * `data` - Chunk data
    /// * `da_commitment` - DA commitment
    ///
    /// # Returns
    ///
    /// Result dari operasi storage.
    pub fn put_chunk_with_meta(
        &self,
        hash: &str,
        data: &[u8],
        da_commitment: [u8; 32],
    ) -> dsdn_common::Result<()> {
        // 1. Simpan ke inner storage
        self.inner.put_chunk(hash, data)?;

        // 2. Update metadata
        let meta = DAChunkMeta::new(hash.to_string(), data.len() as u64, da_commitment);
        self.chunk_metadata.write().insert(hash.to_string(), meta);

        Ok(())
    }

    /// Put chunk with DA metadata and BlobRef.
    ///
    /// Digunakan ketika chunk berasal dari DA blob.
    ///
    /// # Arguments
    ///
    /// * `hash` - Chunk hash
    /// * `data` - Chunk data
    /// * `da_commitment` - DA commitment
    /// * `blob_ref` - Reference to DA blob
    ///
    /// # Returns
    ///
    /// Result dari operasi storage.
    pub fn put_chunk_with_blob_ref(
        &self,
        hash: &str,
        data: &[u8],
        da_commitment: [u8; 32],
        blob_ref: BlobRef,
    ) -> dsdn_common::Result<()> {
        // 1. Simpan ke inner storage
        self.inner.put_chunk(hash, data)?;

        // 2. Update metadata dengan blob_ref
        let meta = DAChunkMeta::with_blob_ref(
            hash.to_string(),
            data.len() as u64,
            da_commitment,
            blob_ref,
        );
        self.chunk_metadata.write().insert(hash.to_string(), meta);

        Ok(())
    }

    /// Delete chunk data and metadata.
    ///
    /// # Note
    ///
    /// Karena Storage trait tidak memiliki delete_chunk,
    /// method ini mencoba menghapus metadata dan menandai
    /// slot untuk penghapusan. Data fisik mungkin perlu
    /// dibersihkan oleh storage backend secara terpisah.
    ///
    /// Untuk LocalFsStorage, gunakan delete_chunk_file().
    ///
    /// # Arguments
    ///
    /// * `hash` - Chunk hash
    ///
    /// # Returns
    ///
    /// - `Ok(true)` jika berhasil dihapus
    /// - `Ok(false)` jika chunk tidak ada
    /// - `Err` jika terjadi error
    pub fn delete_chunk(&self, hash: &str) -> dsdn_common::Result<bool> {
        // Check if chunk exists
        let has_data = self.inner.has_chunk(hash)?;
        let has_meta = self.has_metadata(hash);

        if !has_data && !has_meta {
            return Ok(false);
        }

        // Delete metadata first
        self.delete_metadata(hash);

        // For data deletion, we need to work with what's available.
        // Since Storage trait doesn't have delete, we mark it as removed
        // by clearing metadata. The actual data cleanup depends on
        // the storage implementation.
        //
        // For file-based storage, the data will be orphaned until
        // the storage backend's own cleanup runs, or manual deletion.

        // Also remove from declared_chunks and replica events
        self.declared_chunks.write().remove(hash);
        
        // Clear replica events for this chunk
        {
            let mut added = self.replica_added_events.write();
            added.retain(|(h, _), _| h != hash);
        }
        {
            let mut removed = self.replica_removed_events.write();
            removed.retain(|(h, _), _| h != hash);
        }

        debug!("Deleted chunk: {} (had_data={}, had_meta={})", hash, has_data, has_meta);
        Ok(true)
    }

    /// Delete chunk metadata.
    ///
    /// # Note
    ///
    /// Karena Storage trait tidak memiliki delete_chunk,
    /// method ini hanya menghapus metadata.
    ///
    /// # Arguments
    ///
    /// * `hash` - Chunk hash
    ///
    /// # Returns
    ///
    /// Removed metadata if existed.
    pub fn delete_metadata(&self, hash: &str) -> Option<DAChunkMeta> {
        self.chunk_metadata.write().remove(hash)
    }

    /// Mark chunk as verified.
    ///
    /// # Arguments
    ///
    /// * `hash` - Chunk hash
    /// * `verified` - Verification status
    ///
    /// # Returns
    ///
    /// `true` if metadata existed and was updated, `false` otherwise.
    pub fn set_verified(&self, hash: &str, verified: bool) -> bool {
        let mut metadata = self.chunk_metadata.write();
        if let Some(meta) = metadata.get_mut(hash) {
            meta.verified = verified;
            true
        } else {
            false
        }
    }

    /// Update blob_ref for a chunk.
    ///
    /// # Arguments
    ///
    /// * `hash` - Chunk hash
    /// * `blob_ref` - BlobRef to set
    ///
    /// # Returns
    ///
    /// `true` if metadata existed and was updated, `false` otherwise.
    pub fn set_blob_ref(&self, hash: &str, blob_ref: BlobRef) -> bool {
        let mut metadata = self.chunk_metadata.write();
        if let Some(meta) = metadata.get_mut(hash) {
            meta.blob_ref = Some(blob_ref);
            true
        } else {
            false
        }
    }

    /// Get all unverified chunks.
    ///
    /// # Returns
    ///
    /// Vector of chunk hashes that are not verified.
    pub fn unverified_chunks(&self) -> Vec<String> {
        self.chunk_metadata
            .read()
            .iter()
            .filter(|(_, meta)| !meta.verified)
            .map(|(hash, _)| hash.clone())
            .collect()
    }

    /// Get all verified chunks.
    ///
    /// # Returns
    ///
    /// Vector of chunk hashes that are verified.
    pub fn verified_chunks(&self) -> Vec<String> {
        self.chunk_metadata
            .read()
            .iter()
            .filter(|(_, meta)| meta.verified)
            .map(|(hash, _)| hash.clone())
            .collect()
    }

    /// Get chunks with blob_ref.
    ///
    /// # Returns
    ///
    /// Vector of chunk hashes that have blob_ref.
    pub fn chunks_with_blob_ref(&self) -> Vec<String> {
        self.chunk_metadata
            .read()
            .iter()
            .filter(|(_, meta)| meta.blob_ref.is_some())
            .map(|(hash, _)| hash.clone())
            .collect()
    }

    // ════════════════════════════════════════════════════════════════════════
    // DA COMMITMENT VERIFICATION (14A.44)
    // ════════════════════════════════════════════════════════════════════════

    /// Compute SHA3-256 hash of data.
    fn compute_commitment(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Verify commitment untuk satu chunk.
    ///
    /// # Arguments
    ///
    /// * `hash` - Chunk hash
    ///
    /// # Returns
    ///
    /// - `Ok(true)`: Data cocok dengan da_commitment
    /// - `Ok(false)`: Data tidak cocok atau chunk tidak ada
    /// - `Err(StorageError)`: Error saat akses storage/metadata
    ///
    /// # Verification Process
    ///
    /// 1. Load chunk data dari inner storage
    /// 2. Load metadata dari chunk_metadata
    /// 3. Compute commitment: SHA3-256(chunk_data)
    /// 4. Compare dengan da_commitment di metadata
    ///
    /// # Invariant
    ///
    /// - TIDAK mengubah data atau metadata
    /// - TIDAK auto-repair
    /// - TIDAK panic
    pub fn verify_chunk_commitment(&self, hash: &str) -> Result<bool, StorageError> {
        // 1. Load metadata
        let metadata = self.chunk_metadata.read();
        let meta = match metadata.get(hash) {
            Some(m) => m,
            None => {
                debug!("Verify commitment: metadata not found for {}", hash);
                return Err(StorageError::MetadataNotFound(hash.to_string()));
            }
        };
        let expected_commitment = meta.da_commitment;
        drop(metadata); // Release lock before IO

        // 2. Load chunk data dari inner storage
        let data = match self.inner.get_chunk(hash) {
            Ok(Some(d)) => d,
            Ok(None) => {
                debug!("Verify commitment: chunk not found for {}", hash);
                return Ok(false); // Chunk tidak ada = tidak terverifikasi
            }
            Err(e) => {
                return Err(StorageError::IoError(e.to_string()));
            }
        };

        // 3. Compute commitment: SHA3-256(chunk_data)
        let actual_commitment = Self::compute_commitment(&data);

        // 4. Compare dengan da_commitment
        if actual_commitment == expected_commitment {
            debug!("Verify commitment: {} passed", hash);
            Ok(true)
        } else {
            debug!(
                "Verify commitment: {} FAILED - expected {:02x?}..., got {:02x?}...",
                hash,
                &expected_commitment[..4],
                &actual_commitment[..4]
            );
            Ok(false)
        }
    }

    /// Verify commitment untuk SEMUA chunks yang memiliki metadata.
    ///
    /// # Returns
    ///
    /// - `Ok(CommitmentReport)`: Laporan lengkap hasil verifikasi
    /// - `Err(StorageError)`: Error fatal saat verifikasi
    ///
    /// # Verification Process
    ///
    /// Untuk setiap chunk dengan metadata:
    /// - Jika data tidak ada → missing_count += 1
    /// - Jika commitment cocok → verified_count += 1
    /// - Jika tidak cocok → failed_count += 1, hash ditambahkan ke failed_chunks
    ///
    /// # Invariant
    ///
    /// - Iterasi SEMUA metadata, tidak ada early exit
    /// - TIDAK mengubah data atau metadata
    /// - TIDAK auto-repair atau auto-delete
    /// - TIDAK panic
    pub fn verify_all_commitments(&self) -> Result<CommitmentReport, StorageError> {
        let mut report = CommitmentReport::new();

        // Get all chunk hashes from metadata
        let hashes: Vec<String> = {
            let metadata = self.chunk_metadata.read();
            metadata.keys().cloned().collect()
        };

        debug!("Verify all commitments: checking {} chunks", hashes.len());

        for hash in hashes {
            // Get expected commitment from metadata
            let expected_commitment = {
                let metadata = self.chunk_metadata.read();
                match metadata.get(&hash) {
                    Some(m) => m.da_commitment,
                    None => {
                        // Metadata removed between iteration - skip
                        continue;
                    }
                }
            };

            // Load chunk data
            let data = match self.inner.get_chunk(&hash) {
                Ok(Some(d)) => d,
                Ok(None) => {
                    // Data missing
                    report.missing_count += 1;
                    debug!("Verify all: {} - MISSING", hash);
                    continue;
                }
                Err(e) => {
                    // IO error - treat as missing
                    warn!("Verify all: {} - IO error: {}", hash, e);
                    report.missing_count += 1;
                    continue;
                }
            };

            // Compute and compare commitment
            let actual_commitment = Self::compute_commitment(&data);

            if actual_commitment == expected_commitment {
                report.verified_count += 1;
            } else {
                report.failed_count += 1;
                report.failed_chunks.push(hash.clone());
                debug!(
                    "Verify all: {} - FAILED (expected {:02x?}..., got {:02x?}...)",
                    hash,
                    &expected_commitment[..4],
                    &actual_commitment[..4]
                );
            }
        }

        info!(
            "Verify all commitments complete: {}",
            report
        );

        Ok(report)
    }

    // ════════════════════════════════════════════════════════════════════════
    // BACKGROUND VERIFICATION TASK
    // ════════════════════════════════════════════════════════════════════════

    /// Start background commitment verification task.
    ///
    /// # Arguments
    ///
    /// * `interval` - Interval antara verifikasi (Duration)
    ///
    /// # Returns
    ///
    /// JoinHandle untuk task. Task berhenti ketika stop_background_verification() dipanggil.
    ///
    /// # Behavior
    ///
    /// - Memanggil verify_all_commitments() secara periodik
    /// - Logging hasil (jumlah verified/failed/missing)
    /// - HANYA DETEKSI, tidak melakukan perbaikan
    /// - Handle error dengan logging (tidak panic)
    pub fn start_background_verification(
        self: &Arc<Self>,
        interval: Duration,
    ) -> tokio::task::JoinHandle<()> {
        let storage = Arc::clone(self);
        // Use separate flag for verification
        // Note: Reusing sync_running for simplicity, but in production
        // you might want a separate flag

        tokio::spawn(async move {
            info!("Background commitment verification started with interval {:?}", interval);
            let mut interval_timer = tokio::time::interval(interval);

            loop {
                interval_timer.tick().await;

                // Check if we should stop (using sync_running as general stop flag)
                if !storage.sync_running.load(Ordering::SeqCst) {
                    break;
                }

                match storage.verify_all_commitments() {
                    Ok(report) => {
                        if report.has_failures() {
                            warn!(
                                "Background verification: {} failures detected! Failed: {:?}",
                                report.failed_count,
                                report.failed_chunks
                            );
                        } else if report.has_missing() {
                            warn!(
                                "Background verification: {} missing chunks",
                                report.missing_count
                            );
                        } else if report.verified_count > 0 {
                            debug!(
                                "Background verification: all {} chunks verified",
                                report.verified_count
                            );
                        }
                    }
                    Err(e) => {
                        error!("Background verification error: {}", e);
                    }
                }
            }

            info!("Background commitment verification stopped");
        })
    }

    /// Stop background verification task.
    ///
    /// Note: This uses the same flag as stop_background_sync().
    /// In production, you might want separate flags.
    pub fn stop_background_verification(&self) {
        self.sync_running.store(false, Ordering::SeqCst);
        info!("Background verification stop requested");
    }
}

// ════════════════════════════════════════════════════════════════════════════
// STORAGE TRAIT IMPLEMENTATION
// ════════════════════════════════════════════════════════════════════════════

impl Storage for DAStorage {
    /// Put chunk ke storage.
    ///
    /// # Behavior
    ///
    /// 1. Delegasikan ke inner storage
    /// 2. Update metadata dengan default commitment (zeros)
    ///
    /// # Note
    ///
    /// Untuk put dengan DA metadata, gunakan `put_chunk_with_meta()`.
    fn put_chunk(&self, hash: &str, data: &[u8]) -> dsdn_common::Result<()> {
        // 1. Delegasikan ke inner - error HARUS propagate
        self.inner.put_chunk(hash, data)?;

        // 2. Update metadata dengan default commitment
        let meta = DAChunkMeta::new(hash.to_string(), data.len() as u64, [0u8; 32]);
        self.chunk_metadata.write().insert(hash.to_string(), meta);

        Ok(())
    }

    /// Get chunk dari storage.
    ///
    /// # Behavior
    ///
    /// Delegasikan langsung ke inner storage.
    /// Metadata TIDAK digunakan untuk mengambil data.
    fn get_chunk(&self, hash: &str) -> dsdn_common::Result<Option<Vec<u8>>> {
        // Delegasikan langsung ke inner - metadata tidak relevan untuk get
        self.inner.get_chunk(hash)
    }

    /// Check apakah chunk ada di storage.
    ///
    /// # Behavior
    ///
    /// Cek inner storage, BUKAN metadata.
    /// Metadata bukan sumber kebenaran untuk keberadaan data.
    fn has_chunk(&self, hash: &str) -> dsdn_common::Result<bool> {
        // WAJIB cek inner, BUKAN metadata
        self.inner.has_chunk(hash)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use dsdn_common::MockDA;
    use std::collections::HashMap as StdHashMap;
    use parking_lot::RwLock as ParkingRwLock;

    // ════════════════════════════════════════════════════════════════════════
    // MOCK STORAGE
    // ════════════════════════════════════════════════════════════════════════

    /// Mock storage untuk testing.
    #[derive(Debug)]
    struct MockStorage {
        chunks: ParkingRwLock<StdHashMap<String, Vec<u8>>>,
    }

    impl MockStorage {
        fn new() -> Self {
            Self {
                chunks: ParkingRwLock::new(StdHashMap::new()),
            }
        }
    }

    impl Storage for MockStorage {
        fn put_chunk(&self, hash: &str, data: &[u8]) -> dsdn_common::Result<()> {
            self.chunks.write().insert(hash.to_string(), data.to_vec());
            Ok(())
        }

        fn get_chunk(&self, hash: &str) -> dsdn_common::Result<Option<Vec<u8>>> {
            Ok(self.chunks.read().get(hash).cloned())
        }

        fn has_chunk(&self, hash: &str) -> dsdn_common::Result<bool> {
            Ok(self.chunks.read().contains_key(hash))
        }
    }

    /// Mock storage yang selalu error.
    #[derive(Debug)]
    struct ErrorStorage;

    impl Storage for ErrorStorage {
        fn put_chunk(&self, _hash: &str, _data: &[u8]) -> dsdn_common::Result<()> {
            Err("mock storage error".into())
        }

        fn get_chunk(&self, _hash: &str) -> dsdn_common::Result<Option<Vec<u8>>> {
            Err("mock storage error".into())
        }

        fn has_chunk(&self, _hash: &str) -> dsdn_common::Result<bool> {
            Err("mock storage error".into())
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // HELPER FUNCTIONS
    // ════════════════════════════════════════════════════════════════════════

    fn create_da_storage() -> DAStorage {
        let inner = Arc::new(MockStorage::new());
        let da = Arc::new(MockDA::new());
        DAStorage::new(inner, da)
    }

    fn create_arc_da_storage() -> Arc<DAStorage> {
        let inner = Arc::new(MockStorage::new());
        let da = Arc::new(MockDA::new());
        Arc::new(DAStorage::new(inner, da))
    }

    fn create_error_da_storage() -> DAStorage {
        let inner = Arc::new(ErrorStorage);
        let da = Arc::new(MockDA::new());
        DAStorage::new(inner, da)
    }

    fn create_test_event(hash: &str, size: u64) -> ChunkDeclaredEvent {
        ChunkDeclaredEvent::new(
            hash.to_string(),
            size,
            [0xAB; 32],
            None,
            1000,
        )
    }

    fn create_test_event_with_blob_ref(hash: &str, size: u64) -> ChunkDeclaredEvent {
        let blob_ref = BlobRef {
            height: 100,
            commitment: [0xCD; 32],
            namespace: [0xEF; 29],
        };
        ChunkDeclaredEvent::new(
            hash.to_string(),
            size,
            [0xAB; 32],
            Some(blob_ref),
            1000,
        )
    }

    // ════════════════════════════════════════════════════════════════════════
    // A. EMPTY DA TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_sync_empty_da_returns_zero() {
        let storage = create_da_storage();

        // No events received
        let result = storage.sync_metadata_from_da();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_sync_empty_da_metadata_empty() {
        let storage = create_da_storage();

        storage.sync_metadata_from_da().unwrap();

        assert!(storage.all_metadata().is_empty());
        assert_eq!(storage.metadata_count(), 0);
    }

    #[test]
    fn test_list_declared_chunks_empty() {
        let storage = create_da_storage();

        let declared = storage.list_declared_chunks();
        assert!(declared.is_empty());
    }

    // ════════════════════════════════════════════════════════════════════════
    // B. SINGLE CHUNK DECLARED TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_sync_single_chunk_returns_one() {
        let storage = create_da_storage();

        // Receive single event
        storage.receive_chunk_declared(create_test_event("chunk-1", 1024));

        let result = storage.sync_metadata_from_da();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1);
    }

    #[test]
    fn test_sync_single_chunk_metadata_correct() {
        let storage = create_da_storage();

        let event = create_test_event("chunk-1", 2048);
        storage.receive_chunk_declared(event.clone());
        storage.sync_metadata_from_da().unwrap();

        let meta = storage.get_metadata("chunk-1").unwrap();
        assert_eq!(meta.hash, "chunk-1");
        assert_eq!(meta.size_bytes, 2048);
        assert_eq!(meta.da_commitment, [0xAB; 32]);
        assert!(!meta.verified); // MUST NOT be auto-true
    }

    #[test]
    fn test_sync_chunk_with_blob_ref() {
        let storage = create_da_storage();

        let event = create_test_event_with_blob_ref("chunk-1", 1024);
        storage.receive_chunk_declared(event);
        storage.sync_metadata_from_da().unwrap();

        let meta = storage.get_metadata("chunk-1").unwrap();
        assert!(meta.blob_ref.is_some());
        let blob_ref = meta.blob_ref.unwrap();
        assert_eq!(blob_ref.height, 100);
    }

    #[test]
    fn test_list_declared_chunks_single() {
        let storage = create_da_storage();

        storage.receive_chunk_declared(create_test_event("chunk-1", 1024));

        let declared = storage.list_declared_chunks();
        assert_eq!(declared.len(), 1);
        assert!(declared.contains(&"chunk-1".to_string()));
    }

    // ════════════════════════════════════════════════════════════════════════
    // C. IDEMPOTENCY TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_sync_idempotent_no_duplicate() {
        let storage = create_da_storage();

        storage.receive_chunk_declared(create_test_event("chunk-1", 1024));
        storage.receive_chunk_declared(create_test_event("chunk-2", 2048));

        // Sync twice
        storage.sync_metadata_from_da().unwrap();
        let count1 = storage.metadata_count();

        storage.sync_metadata_from_da().unwrap();
        let count2 = storage.metadata_count();

        // Count should be same
        assert_eq!(count1, count2);
        assert_eq!(count1, 2);
    }

    #[test]
    fn test_sync_twice_returns_same_count() {
        let storage = create_da_storage();

        storage.receive_chunk_declared(create_test_event("chunk-1", 1024));

        let result1 = storage.sync_metadata_from_da().unwrap();
        let result2 = storage.sync_metadata_from_da().unwrap();

        // Both should return 1 (same event synced)
        assert_eq!(result1, 1);
        assert_eq!(result2, 1);
    }

    #[test]
    fn test_receive_same_event_overwrites() {
        let storage = create_da_storage();

        // Receive same chunk twice with different size
        storage.receive_chunk_declared(create_test_event("chunk-1", 1024));
        storage.receive_chunk_declared(create_test_event("chunk-1", 2048));

        // Should only have one declared chunk
        assert_eq!(storage.declared_chunks_count(), 1);

        storage.sync_metadata_from_da().unwrap();

        // Metadata should have updated size
        let meta = storage.get_metadata("chunk-1").unwrap();
        assert_eq!(meta.size_bytes, 2048);
    }

    // ════════════════════════════════════════════════════════════════════════
    // D. PARTIAL UPDATE TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_sync_preserves_local_verified() {
        let storage = create_da_storage();

        // First, create metadata manually and set verified
        let meta = DAChunkMeta::new("chunk-1".to_string(), 1024, [0x11; 32]);
        storage.set_metadata("chunk-1", meta);
        storage.set_verified("chunk-1", true);

        // Now receive DA event (different commitment)
        storage.receive_chunk_declared(create_test_event("chunk-1", 2048));
        storage.sync_metadata_from_da().unwrap();

        // verified should STILL be true (not overwritten)
        let meta = storage.get_metadata("chunk-1").unwrap();
        assert!(meta.verified); // PRESERVED
        // But size should be updated from DA
        assert_eq!(meta.size_bytes, 2048);
    }

    #[test]
    fn test_sync_updates_da_fields_only() {
        let storage = create_da_storage();

        // Create metadata with blob_ref
        let old_blob_ref = BlobRef {
            height: 50,
            commitment: [0x99; 32],
            namespace: [0x88; 29],
        };
        let mut meta = DAChunkMeta::new("chunk-1".to_string(), 1024, [0x11; 32]);
        meta.blob_ref = Some(old_blob_ref.clone());
        meta.verified = true;
        storage.set_metadata("chunk-1", meta);

        // Receive event WITHOUT blob_ref
        storage.receive_chunk_declared(create_test_event("chunk-1", 2048));
        storage.sync_metadata_from_da().unwrap();

        let meta = storage.get_metadata("chunk-1").unwrap();
        // blob_ref should be preserved (event had None)
        assert!(meta.blob_ref.is_some());
        assert_eq!(meta.blob_ref.as_ref().unwrap().height, 50);
        // verified preserved
        assert!(meta.verified);
    }

    #[test]
    fn test_sync_does_not_delete_metadata() {
        let storage = create_da_storage();

        // Add metadata manually (not from DA)
        let meta = DAChunkMeta::new("local-chunk".to_string(), 500, [0x22; 32]);
        storage.set_metadata("local-chunk", meta);

        // Receive different DA event
        storage.receive_chunk_declared(create_test_event("da-chunk", 1024));
        storage.sync_metadata_from_da().unwrap();

        // Local metadata should still exist
        assert!(storage.has_metadata("local-chunk"));
        assert!(storage.has_metadata("da-chunk"));
        assert_eq!(storage.metadata_count(), 2);
    }

    // ════════════════════════════════════════════════════════════════════════
    // E. GET_CHUNK_META TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_get_chunk_meta_returns_reference() {
        let storage = create_da_storage();

        storage.receive_chunk_declared(create_test_event("chunk-1", 1024));
        storage.sync_metadata_from_da().unwrap();

        let guard = storage.get_chunk_meta("chunk-1");
        assert!(guard.is_some());

        // Can deref to &DAChunkMeta
        let meta: &DAChunkMeta = &*guard.unwrap();
        assert_eq!(meta.hash, "chunk-1");
    }

    #[test]
    fn test_get_chunk_meta_none_if_not_exists() {
        let storage = create_da_storage();

        let guard = storage.get_chunk_meta("nonexistent");
        assert!(guard.is_none());
    }

    #[test]
    fn test_get_chunk_meta_no_side_effect() {
        let storage = create_da_storage();

        // Call multiple times
        let _ = storage.get_chunk_meta("chunk-1");
        let _ = storage.get_chunk_meta("chunk-1");
        let _ = storage.get_chunk_meta("chunk-1");

        // No metadata created
        assert_eq!(storage.metadata_count(), 0);
    }

    // ════════════════════════════════════════════════════════════════════════
    // F. LIST_DECLARED_CHUNKS TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_list_declared_chunks_deterministic() {
        let storage = create_da_storage();

        // Add in random order
        storage.receive_chunk_declared(create_test_event("zebra", 100));
        storage.receive_chunk_declared(create_test_event("apple", 200));
        storage.receive_chunk_declared(create_test_event("mango", 300));

        let list1 = storage.list_declared_chunks();
        let list2 = storage.list_declared_chunks();

        // Same order every time
        assert_eq!(list1, list2);
        // Sorted order
        assert_eq!(list1, vec!["apple", "mango", "zebra"]);
    }

    #[test]
    fn test_list_declared_chunks_multiple() {
        let storage = create_da_storage();

        for i in 0..10 {
            storage.receive_chunk_declared(create_test_event(&format!("chunk-{}", i), 1024));
        }

        let declared = storage.list_declared_chunks();
        assert_eq!(declared.len(), 10);
    }

    // ════════════════════════════════════════════════════════════════════════
    // G. VERIFIED NOT AUTO TRUE TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_sync_verified_not_auto_true() {
        let storage = create_da_storage();

        storage.receive_chunk_declared(create_test_event("chunk-1", 1024));
        storage.sync_metadata_from_da().unwrap();

        let meta = storage.get_metadata("chunk-1").unwrap();
        assert!(!meta.verified); // MUST be false
    }

    #[test]
    fn test_sync_multiple_all_unverified() {
        let storage = create_da_storage();

        for i in 0..5 {
            storage.receive_chunk_declared(create_test_event(&format!("chunk-{}", i), 1024));
        }
        storage.sync_metadata_from_da().unwrap();

        // All should be unverified
        let unverified = storage.unverified_chunks();
        assert_eq!(unverified.len(), 5);

        let verified = storage.verified_chunks();
        assert!(verified.is_empty());
    }

    // ════════════════════════════════════════════════════════════════════════
    // H. BACKGROUND SYNC TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_background_sync_starts() {
        let storage = create_arc_da_storage();

        let handle = storage.start_background_sync(Duration::from_millis(100));

        assert!(storage.is_sync_running());

        // Stop and wait
        storage.stop_background_sync();
        tokio::time::sleep(Duration::from_millis(150)).await;

        assert!(!storage.is_sync_running());
        handle.abort();
    }

    #[tokio::test]
    async fn test_background_sync_processes_events() {
        let storage = create_arc_da_storage();

        // Add event before starting sync
        storage.receive_chunk_declared(create_test_event("chunk-1", 1024));

        let handle = storage.start_background_sync(Duration::from_millis(50));

        // Wait for sync to process
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Metadata should be synced
        assert!(storage.has_metadata("chunk-1"));

        storage.stop_background_sync();
        handle.abort();
    }

    #[tokio::test]
    async fn test_background_sync_stops_gracefully() {
        let storage = create_arc_da_storage();

        let _handle = storage.start_background_sync(Duration::from_millis(50));

        assert!(storage.is_sync_running());

        storage.stop_background_sync();
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(!storage.is_sync_running());
    }

    // ════════════════════════════════════════════════════════════════════════
    // I. WRAPPER CORRECTNESS TESTS (from 14A.41)
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_put_get_through_da_storage() {
        let storage = create_da_storage();

        let result = storage.put_chunk("chunk-1", b"test data");
        assert!(result.is_ok());

        let data = storage.get_chunk("chunk-1").unwrap();
        assert_eq!(data, Some(b"test data".to_vec()));
    }

    #[test]
    fn test_has_chunk_checks_inner() {
        let storage = create_da_storage();

        assert!(!storage.has_chunk("chunk-1").unwrap());

        storage.put_chunk("chunk-1", b"data").unwrap();
        assert!(storage.has_chunk("chunk-1").unwrap());
    }

    #[test]
    fn test_metadata_not_authoritative() {
        let storage = create_da_storage();

        storage.put_chunk("chunk-1", b"data").unwrap();
        assert!(storage.has_metadata("chunk-1"));

        storage.delete_metadata("chunk-1");

        assert!(!storage.has_metadata("chunk-1"));
        assert!(storage.has_chunk("chunk-1").unwrap()); // Data still exists
    }

    #[test]
    fn test_has_chunk_ignores_metadata() {
        let storage = create_da_storage();

        // Add metadata without data
        let meta = DAChunkMeta::new("fake-chunk".to_string(), 100, [0u8; 32]);
        storage.set_metadata("fake-chunk", meta);

        assert!(storage.has_metadata("fake-chunk"));
        assert!(!storage.has_chunk("fake-chunk").unwrap());
    }

    // ════════════════════════════════════════════════════════════════════════
    // J. ERROR PROPAGATION TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_put_error_propagates() {
        let storage = create_error_da_storage();

        let result = storage.put_chunk("chunk-1", b"data");
        assert!(result.is_err());
    }

    #[test]
    fn test_get_error_propagates() {
        let storage = create_error_da_storage();

        let result = storage.get_chunk("chunk-1");
        assert!(result.is_err());
    }

    #[test]
    fn test_has_error_propagates() {
        let storage = create_error_da_storage();

        let result = storage.has_chunk("chunk-1");
        assert!(result.is_err());
    }

    // ════════════════════════════════════════════════════════════════════════
    // K. CHUNK DECLARED EVENT TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_chunk_declared_event_creation() {
        let event = ChunkDeclaredEvent::new(
            "chunk-1".to_string(),
            1024,
            [0xAA; 32],
            None,
            12345,
        );

        assert_eq!(event.chunk_hash, "chunk-1");
        assert_eq!(event.size_bytes, 1024);
        assert_eq!(event.da_commitment, [0xAA; 32]);
        assert!(event.blob_ref.is_none());
        assert_eq!(event.declared_at, 12345);
    }

    #[test]
    fn test_receive_chunk_declared_batch() {
        let storage = create_da_storage();

        let events = vec![
            create_test_event("chunk-1", 100),
            create_test_event("chunk-2", 200),
            create_test_event("chunk-3", 300),
        ];

        let count = storage.receive_chunk_declared_batch(events);
        assert_eq!(count, 3);
        assert_eq!(storage.declared_chunks_count(), 3);
    }

    #[test]
    fn test_is_chunk_declared() {
        let storage = create_da_storage();

        assert!(!storage.is_chunk_declared("chunk-1"));

        storage.receive_chunk_declared(create_test_event("chunk-1", 1024));

        assert!(storage.is_chunk_declared("chunk-1"));
        assert!(!storage.is_chunk_declared("chunk-2"));
    }

    #[test]
    fn test_get_declared_event() {
        let storage = create_da_storage();

        storage.receive_chunk_declared(create_test_event("chunk-1", 1024));

        let event = storage.get_declared_event("chunk-1");
        assert!(event.is_some());
        assert_eq!(event.unwrap().size_bytes, 1024);

        let none = storage.get_declared_event("nonexistent");
        assert!(none.is_none());
    }

    // ════════════════════════════════════════════════════════════════════════
    // L. COMMITMENT VERIFICATION TESTS (14A.44)
    // ════════════════════════════════════════════════════════════════════════

    /// Helper to compute SHA3-256 for tests
    fn compute_test_commitment(data: &[u8]) -> [u8; 32] {
        use sha3::{Sha3_256, Digest};
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    #[test]
    fn test_verify_chunk_commitment_valid() {
        let storage = create_da_storage();
        let data = b"test data for commitment";
        let commitment = compute_test_commitment(data);

        // Put chunk with correct commitment
        storage.put_chunk_with_meta("chunk-1", data, commitment).unwrap();

        // Verify should pass
        let result = storage.verify_chunk_commitment("chunk-1");
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_chunk_commitment_invalid() {
        let storage = create_da_storage();
        let data = b"test data";
        let wrong_commitment = [0xFFu8; 32]; // Wrong commitment

        // Put chunk with wrong commitment
        storage.put_chunk_with_meta("chunk-1", data, wrong_commitment).unwrap();

        // Verify should fail (return false)
        let result = storage.verify_chunk_commitment("chunk-1");
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_verify_chunk_commitment_data_modified() {
        let storage = create_da_storage();
        let original_data = b"original data";
        let commitment = compute_test_commitment(original_data);

        // Put chunk with correct commitment
        storage.put_chunk_with_meta("chunk-1", original_data, commitment).unwrap();

        // Modify data in storage (simulated by putting different data)
        let modified_data = b"modified data";
        storage.inner().put_chunk("chunk-1", modified_data).unwrap();

        // Verify should fail (data changed)
        let result = storage.verify_chunk_commitment("chunk-1");
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_verify_chunk_commitment_missing_data() {
        let storage = create_da_storage();

        // Create metadata without data
        let commitment = [0xABu8; 32];
        let meta = DAChunkMeta::new("chunk-1".to_string(), 100, commitment);
        storage.set_metadata("chunk-1", meta);

        // Verify should return false (data missing)
        let result = storage.verify_chunk_commitment("chunk-1");
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_verify_chunk_commitment_missing_metadata() {
        let storage = create_da_storage();

        // Put data without metadata
        storage.inner().put_chunk("chunk-1", b"data").unwrap();

        // Clear metadata
        storage.clear_metadata();

        // Verify should return error (metadata not found)
        let result = storage.verify_chunk_commitment("chunk-1");
        assert!(result.is_err());
        match result.unwrap_err() {
            StorageError::MetadataNotFound(hash) => assert_eq!(hash, "chunk-1"),
            _ => panic!("Expected MetadataNotFound error"),
        }
    }

    #[test]
    fn test_verify_all_commitments_all_valid() {
        let storage = create_da_storage();

        // Add multiple valid chunks
        for i in 0..5 {
            let data = format!("data-{}", i);
            let commitment = compute_test_commitment(data.as_bytes());
            storage.put_chunk_with_meta(&format!("chunk-{}", i), data.as_bytes(), commitment).unwrap();
        }

        // Verify all
        let report = storage.verify_all_commitments().unwrap();

        assert_eq!(report.verified_count, 5);
        assert_eq!(report.failed_count, 0);
        assert_eq!(report.missing_count, 0);
        assert!(report.failed_chunks.is_empty());
        assert!(report.all_verified());
    }

    #[test]
    fn test_verify_all_commitments_some_invalid() {
        let storage = create_da_storage();

        // Add 3 valid chunks
        for i in 0..3 {
            let data = format!("valid-data-{}", i);
            let commitment = compute_test_commitment(data.as_bytes());
            storage.put_chunk_with_meta(&format!("valid-{}", i), data.as_bytes(), commitment).unwrap();
        }

        // Add 2 invalid chunks (wrong commitment)
        for i in 0..2 {
            let data = format!("invalid-data-{}", i);
            let wrong_commitment = [0xFFu8; 32];
            storage.put_chunk_with_meta(&format!("invalid-{}", i), data.as_bytes(), wrong_commitment).unwrap();
        }

        // Verify all
        let report = storage.verify_all_commitments().unwrap();

        assert_eq!(report.verified_count, 3);
        assert_eq!(report.failed_count, 2);
        assert_eq!(report.missing_count, 0);
        assert_eq!(report.failed_chunks.len(), 2);
        assert!(report.has_failures());
    }

    #[test]
    fn test_verify_all_commitments_some_missing() {
        let storage = create_da_storage();

        // Add 2 valid chunks with data
        for i in 0..2 {
            let data = format!("data-{}", i);
            let commitment = compute_test_commitment(data.as_bytes());
            storage.put_chunk_with_meta(&format!("chunk-{}", i), data.as_bytes(), commitment).unwrap();
        }

        // Add 2 metadata-only entries (no data)
        for i in 2..4 {
            let meta = DAChunkMeta::new(format!("chunk-{}", i), 100, [0xABu8; 32]);
            storage.set_metadata(&format!("chunk-{}", i), meta);
        }

        // Verify all
        let report = storage.verify_all_commitments().unwrap();

        assert_eq!(report.verified_count, 2);
        assert_eq!(report.failed_count, 0);
        assert_eq!(report.missing_count, 2);
        assert!(report.has_missing());
    }

    #[test]
    fn test_verify_all_commitments_mixed() {
        let storage = create_da_storage();

        // 2 valid
        let data1 = b"valid data 1";
        storage.put_chunk_with_meta("valid-1", data1, compute_test_commitment(data1)).unwrap();
        let data2 = b"valid data 2";
        storage.put_chunk_with_meta("valid-2", data2, compute_test_commitment(data2)).unwrap();

        // 1 invalid (wrong commitment)
        storage.put_chunk_with_meta("invalid-1", b"some data", [0xFFu8; 32]).unwrap();

        // 1 missing (metadata only)
        let meta = DAChunkMeta::new("missing-1".to_string(), 50, [0xABu8; 32]);
        storage.set_metadata("missing-1", meta);

        // Verify all
        let report = storage.verify_all_commitments().unwrap();

        assert_eq!(report.verified_count, 2);
        assert_eq!(report.failed_count, 1);
        assert_eq!(report.missing_count, 1);
        assert_eq!(report.total_processed(), 4);
        assert!(!report.all_verified());
    }

    #[test]
    fn test_verify_commitment_deterministic() {
        let storage = create_da_storage();
        let data = b"deterministic test data";
        let commitment = compute_test_commitment(data);

        storage.put_chunk_with_meta("chunk-1", data, commitment).unwrap();

        // Verify multiple times - should be same result
        let result1 = storage.verify_chunk_commitment("chunk-1").unwrap();
        let result2 = storage.verify_chunk_commitment("chunk-1").unwrap();
        let result3 = storage.verify_chunk_commitment("chunk-1").unwrap();

        assert!(result1);
        assert_eq!(result1, result2);
        assert_eq!(result2, result3);
    }

    #[test]
    fn test_verify_all_commitments_empty() {
        let storage = create_da_storage();

        // No chunks
        let report = storage.verify_all_commitments().unwrap();

        assert_eq!(report.verified_count, 0);
        assert_eq!(report.failed_count, 0);
        assert_eq!(report.missing_count, 0);
        assert!(report.all_verified()); // Vacuously true
    }

    #[test]
    fn test_commitment_report_display() {
        let mut report = CommitmentReport::new();
        report.verified_count = 10;
        report.failed_count = 2;
        report.missing_count = 1;

        let display = format!("{}", report);
        assert!(display.contains("verified: 10"));
        assert!(display.contains("failed: 2"));
        assert!(display.contains("missing: 1"));
    }

    #[test]
    fn test_storage_error_display() {
        let err = StorageError::ChunkNotFound("chunk-abc".to_string());
        assert!(format!("{}", err).contains("chunk-abc"));

        let err = StorageError::CommitmentMismatch {
            hash: "chunk-1".to_string(),
            expected: [0xAAu8; 32],
            actual: [0xBBu8; 32],
        };
        assert!(format!("{}", err).contains("mismatch"));
    }

    #[tokio::test]
    async fn test_background_verification_starts() {
        let storage = create_arc_da_storage();

        // Add a chunk
        let data = b"background test";
        storage.put_chunk_with_meta("chunk-1", data, compute_test_commitment(data)).unwrap();

        // Start background verification
        storage.sync_running.store(true, Ordering::SeqCst);
        let handle = storage.start_background_verification(Duration::from_millis(50));

        // Wait a bit
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Stop
        storage.stop_background_verification();
        tokio::time::sleep(Duration::from_millis(100)).await;

        handle.abort();
    }

    // ════════════════════════════════════════════════════════════════════════
    // M. REPLICA TRACKING TESTS (14A.45)
    // ════════════════════════════════════════════════════════════════════════

    fn create_test_event_with_rf(hash: &str, size: u64, target_rf: u8) -> ChunkDeclaredEvent {
        ChunkDeclaredEvent::with_target_rf(
            hash.to_string(),
            size,
            [0xAB; 32],
            None,
            1000,
            target_rf,
        )
    }

    #[test]
    fn test_chunk_declared_initial_state() {
        let storage = create_da_storage();

        // Receive ChunkDeclared with target_rf = 3
        let event = create_test_event_with_rf("chunk-1", 1024, 3);
        storage.receive_chunk_declared(event);
        storage.sync_metadata_from_da().unwrap();

        // Check initial state
        let meta = storage.get_metadata("chunk-1").unwrap();
        assert!(meta.replicas.is_empty()); // replicas kosong
        assert_eq!(meta.target_rf, 3); // target_rf benar
        assert_eq!(meta.current_rf, 0); // current_rf = 0
    }

    #[test]
    fn test_replica_added_single() {
        let storage = create_da_storage();

        // Setup: create chunk metadata
        let event = create_test_event_with_rf("chunk-1", 1024, 3);
        storage.receive_chunk_declared(event);
        storage.sync_metadata_from_da().unwrap();

        // Add replica
        let replica_event = ReplicaAddedEvent::new(
            "chunk-1".to_string(),
            "node-A".to_string(),
            2000,
            None,
        );
        storage.receive_replica_added(replica_event);
        storage.sync_replica_info("chunk-1").unwrap();

        // Check replica added
        let meta = storage.get_metadata("chunk-1").unwrap();
        assert_eq!(meta.replicas.len(), 1);
        assert_eq!(meta.current_rf, 1);
        assert_eq!(meta.replicas[0].node_id, "node-A");
    }

    #[test]
    fn test_replica_added_multiple() {
        let storage = create_da_storage();

        // Setup
        let event = create_test_event_with_rf("chunk-1", 1024, 3);
        storage.receive_chunk_declared(event);
        storage.sync_metadata_from_da().unwrap();

        // Add 3 replicas
        for (i, node_id) in ["node-A", "node-B", "node-C"].iter().enumerate() {
            let replica_event = ReplicaAddedEvent::new(
                "chunk-1".to_string(),
                node_id.to_string(),
                2000 + i as u64,
                None,
            );
            storage.receive_replica_added(replica_event);
        }
        storage.sync_replica_info("chunk-1").unwrap();

        // Check
        let meta = storage.get_metadata("chunk-1").unwrap();
        assert_eq!(meta.replicas.len(), 3);
        assert_eq!(meta.current_rf, 3);
    }

    #[test]
    fn test_replica_removed() {
        let storage = create_da_storage();

        // Setup with 2 replicas
        let event = create_test_event_with_rf("chunk-1", 1024, 3);
        storage.receive_chunk_declared(event);
        storage.sync_metadata_from_da().unwrap();

        storage.receive_replica_added(ReplicaAddedEvent::new(
            "chunk-1".to_string(), "node-A".to_string(), 2000, None,
        ));
        storage.receive_replica_added(ReplicaAddedEvent::new(
            "chunk-1".to_string(), "node-B".to_string(), 2001, None,
        ));
        storage.sync_replica_info("chunk-1").unwrap();

        // Remove one replica
        storage.receive_replica_removed(ReplicaRemovedEvent::new(
            "chunk-1".to_string(), "node-A".to_string(), 3000, None,
        ));
        storage.sync_replica_info("chunk-1").unwrap();

        // Check
        let meta = storage.get_metadata("chunk-1").unwrap();
        assert_eq!(meta.replicas.len(), 1);
        assert_eq!(meta.current_rf, 1);
        assert_eq!(meta.replicas[0].node_id, "node-B");
    }

    #[test]
    fn test_replica_sync_idempotent() {
        let storage = create_da_storage();

        // Setup
        let event = create_test_event_with_rf("chunk-1", 1024, 3);
        storage.receive_chunk_declared(event);
        storage.sync_metadata_from_da().unwrap();

        // Add replica
        storage.receive_replica_added(ReplicaAddedEvent::new(
            "chunk-1".to_string(), "node-A".to_string(), 2000, None,
        ));

        // Sync multiple times
        storage.sync_replica_info("chunk-1").unwrap();
        storage.sync_replica_info("chunk-1").unwrap();
        storage.sync_replica_info("chunk-1").unwrap();

        // Check - should still be 1 replica
        let meta = storage.get_metadata("chunk-1").unwrap();
        assert_eq!(meta.replicas.len(), 1);
        assert_eq!(meta.current_rf, 1);
    }

    #[test]
    fn test_replica_no_duplicate() {
        let storage = create_da_storage();

        // Setup
        let event = create_test_event_with_rf("chunk-1", 1024, 3);
        storage.receive_chunk_declared(event);
        storage.sync_metadata_from_da().unwrap();

        // Add same replica twice (same node_id)
        storage.receive_replica_added(ReplicaAddedEvent::new(
            "chunk-1".to_string(), "node-A".to_string(), 2000, None,
        ));
        storage.receive_replica_added(ReplicaAddedEvent::new(
            "chunk-1".to_string(), "node-A".to_string(), 2001, None,
        ));
        storage.sync_replica_info("chunk-1").unwrap();

        // Should only have 1 replica
        let meta = storage.get_metadata("chunk-1").unwrap();
        assert_eq!(meta.replicas.len(), 1);
    }

    #[test]
    fn test_am_i_replica_true() {
        let storage = create_da_storage();

        // Setup
        let event = create_test_event_with_rf("chunk-1", 1024, 3);
        storage.receive_chunk_declared(event);
        storage.sync_metadata_from_da().unwrap();

        storage.receive_replica_added(ReplicaAddedEvent::new(
            "chunk-1".to_string(), "my-node".to_string(), 2000, None,
        ));
        storage.sync_replica_info("chunk-1").unwrap();

        // Check
        assert!(storage.am_i_replica("chunk-1", "my-node"));
    }

    #[test]
    fn test_am_i_replica_false() {
        let storage = create_da_storage();

        // Setup with different node
        let event = create_test_event_with_rf("chunk-1", 1024, 3);
        storage.receive_chunk_declared(event);
        storage.sync_metadata_from_da().unwrap();

        storage.receive_replica_added(ReplicaAddedEvent::new(
            "chunk-1".to_string(), "other-node".to_string(), 2000, None,
        ));
        storage.sync_replica_info("chunk-1").unwrap();

        // Check
        assert!(!storage.am_i_replica("chunk-1", "my-node"));
    }

    #[test]
    fn test_am_i_replica_chunk_not_exist() {
        let storage = create_da_storage();

        // Chunk doesn't exist
        assert!(!storage.am_i_replica("nonexistent", "my-node"));
    }

    #[test]
    fn test_get_replica_nodes_deterministic() {
        let storage = create_da_storage();

        // Setup
        let event = create_test_event_with_rf("chunk-1", 1024, 3);
        storage.receive_chunk_declared(event);
        storage.sync_metadata_from_da().unwrap();

        // Add replicas in random order
        for node_id in ["node-C", "node-A", "node-B"] {
            storage.receive_replica_added(ReplicaAddedEvent::new(
                "chunk-1".to_string(), node_id.to_string(), 2000, None,
            ));
        }
        storage.sync_replica_info("chunk-1").unwrap();

        // Check - should be sorted
        let nodes = storage.get_replica_nodes("chunk-1");
        assert_eq!(nodes, vec!["node-A", "node-B", "node-C"]);

        // Call again - should be same
        let nodes2 = storage.get_replica_nodes("chunk-1");
        assert_eq!(nodes, nodes2);
    }

    #[test]
    fn test_get_replica_nodes_empty() {
        let storage = create_da_storage();

        // Chunk doesn't exist
        let nodes = storage.get_replica_nodes("nonexistent");
        assert!(nodes.is_empty());
    }

    #[test]
    fn test_under_replicated_chunks() {
        let storage = create_da_storage();

        // Chunk-1: target=3, current=1 (under)
        let event1 = create_test_event_with_rf("chunk-1", 1024, 3);
        storage.receive_chunk_declared(event1);

        // Chunk-2: target=3, current=3 (ok)
        let event2 = create_test_event_with_rf("chunk-2", 1024, 3);
        storage.receive_chunk_declared(event2);

        storage.sync_metadata_from_da().unwrap();

        // Add replicas
        storage.receive_replica_added(ReplicaAddedEvent::new(
            "chunk-1".to_string(), "node-A".to_string(), 2000, None,
        ));
        for node_id in ["node-A", "node-B", "node-C"] {
            storage.receive_replica_added(ReplicaAddedEvent::new(
                "chunk-2".to_string(), node_id.to_string(), 2000, None,
            ));
        }
        storage.sync_all_replica_info().unwrap();

        // Check
        let under = storage.under_replicated_chunks();
        assert_eq!(under.len(), 1);
        assert!(under.contains(&"chunk-1".to_string()));

        let full = storage.fully_replicated_chunks();
        assert_eq!(full.len(), 1);
        assert!(full.contains(&"chunk-2".to_string()));
    }

    #[test]
    fn test_replica_info_struct() {
        let replica = ReplicaInfo::new("node-1".to_string(), 12345, None);
        assert_eq!(replica.node_id, "node-1");
        assert_eq!(replica.added_at, 12345);
        assert!(replica.blob_ref.is_none());
    }

    #[test]
    fn test_replica_added_event_struct() {
        let event = ReplicaAddedEvent::new(
            "chunk-1".to_string(),
            "node-A".to_string(),
            5000,
            None,
        );
        assert_eq!(event.chunk_hash, "chunk-1");
        assert_eq!(event.node_id, "node-A");
        assert_eq!(event.timestamp, 5000);
    }

    #[test]
    fn test_replica_removed_event_struct() {
        let event = ReplicaRemovedEvent::new(
            "chunk-1".to_string(),
            "node-A".to_string(),
            6000,
            None,
        );
        assert_eq!(event.chunk_hash, "chunk-1");
        assert_eq!(event.node_id, "node-A");
        assert_eq!(event.timestamp, 6000);
    }

    #[test]
    fn test_sync_replica_info_no_metadata() {
        let storage = create_da_storage();

        // Try to sync without metadata
        let result = storage.sync_replica_info("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_da_chunk_meta_new_fields() {
        let meta = DAChunkMeta::new("hash-1".to_string(), 1024, [0xAB; 32]);

        // Check new fields default values
        assert!(meta.replicas.is_empty());
        assert_eq!(meta.target_rf, 3); // default
        assert_eq!(meta.current_rf, 0);
    }

    #[test]
    fn test_da_chunk_meta_with_target_rf() {
        let meta = DAChunkMeta::with_target_rf(
            "hash-1".to_string(),
            1024,
            [0xAB; 32],
            5,
        );

        assert_eq!(meta.target_rf, 5);
        assert_eq!(meta.current_rf, 0);
        assert!(meta.replicas.is_empty());
    }

    #[test]
    fn test_da_chunk_meta_add_replica() {
        let mut meta = DAChunkMeta::new("hash-1".to_string(), 1024, [0xAB; 32]);

        // Add replica
        let added = meta.add_replica(ReplicaInfo::new("node-1".to_string(), 1000, None));
        assert!(added);
        assert_eq!(meta.current_rf, 1);
        assert_eq!(meta.replicas.len(), 1);

        // Try to add duplicate
        let added2 = meta.add_replica(ReplicaInfo::new("node-1".to_string(), 2000, None));
        assert!(!added2);
        assert_eq!(meta.current_rf, 1);
    }

    #[test]
    fn test_da_chunk_meta_remove_replica() {
        let mut meta = DAChunkMeta::new("hash-1".to_string(), 1024, [0xAB; 32]);
        meta.add_replica(ReplicaInfo::new("node-1".to_string(), 1000, None));
        meta.add_replica(ReplicaInfo::new("node-2".to_string(), 1000, None));

        // Remove
        let removed = meta.remove_replica("node-1");
        assert!(removed);
        assert_eq!(meta.current_rf, 1);

        // Try to remove nonexistent
        let removed2 = meta.remove_replica("node-3");
        assert!(!removed2);
        assert_eq!(meta.current_rf, 1);
    }

    #[test]
    fn test_receive_replica_batch() {
        let storage = create_da_storage();

        let events = vec![
            ReplicaAddedEvent::new("chunk-1".to_string(), "node-A".to_string(), 1000, None),
            ReplicaAddedEvent::new("chunk-1".to_string(), "node-B".to_string(), 1001, None),
            ReplicaAddedEvent::new("chunk-2".to_string(), "node-A".to_string(), 1002, None),
        ];

        let count = storage.receive_replica_added_batch(events);
        assert_eq!(count, 3);
    }
}