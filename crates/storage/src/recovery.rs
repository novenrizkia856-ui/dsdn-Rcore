//! # Storage Recovery Module
//!
//! Modul ini menyediakan mekanisme recovery storage berbasis DA state.
//!
//! ## Prinsip Kunci
//!
//! - Recovery HANYA untuk chunk yang sah (assigned ke node ini via DA)
//! - Data WAJIB diverifikasi sebelum disimpan
//! - Tidak ada overwrite chunk yang sudah ada
//! - Self-healing tanpa melanggar protokol
//!
//! ## Recovery Flow
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                    Recovery Process                           │
//! ├──────────────────────────────────────────────────────────────┤
//! │  1. Identify missing chunks (assigned but not in storage)    │
//! │  2. For each missing chunk:                                  │
//! │     a. Fetch from peer node                                  │
//! │     b. Verify commitment                                     │
//! │     c. Store if valid                                        │
//! │  3. Generate recovery report                                 │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Invariant
//!
//! - Recovery TIDAK overwrite existing chunks
//! - Recovery TIDAK menyimpan tanpa verifikasi
//! - Recovery TIDAK untuk chunk yang bukan milik node ini
//! - Recovery TIDAK panic

use std::collections::HashMap;
use std::fmt::{self, Debug, Display};
use std::sync::Arc;

use sha3::{Sha3_256, Digest};
use tracing::{debug, error, info, warn};

use dsdn_common::{DALayer, BlobRef};

use crate::da_storage::DAStorage;
use crate::store::Storage;

// ════════════════════════════════════════════════════════════════════════════
// RECOVERY ERROR
// ════════════════════════════════════════════════════════════════════════════

/// Error yang dapat terjadi pada operasi recovery.
#[derive(Debug)]
pub enum RecoveryError {
    /// Chunk tidak ditemukan di peer.
    ChunkNotFound(String),
    /// Commitment mismatch setelah fetch.
    CommitmentMismatch {
        hash: String,
        expected: [u8; 32],
        actual: [u8; 32],
    },
    /// Error saat fetch dari peer.
    FetchError(String),
    /// Error storage.
    StorageError(String),
    /// Error lainnya.
    Other(String),
}

impl Display for RecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecoveryError::ChunkNotFound(hash) => {
                write!(f, "Chunk not found: {}", hash)
            }
            RecoveryError::CommitmentMismatch { hash, expected, actual } => {
                write!(
                    f,
                    "Commitment mismatch for {}: expected {:02x?}, got {:02x?}",
                    hash,
                    &expected[..4],
                    &actual[..4]
                )
            }
            RecoveryError::FetchError(msg) => write!(f, "Fetch error: {}", msg),
            RecoveryError::StorageError(msg) => write!(f, "Storage error: {}", msg),
            RecoveryError::Other(msg) => write!(f, "Recovery error: {}", msg),
        }
    }
}

impl std::error::Error for RecoveryError {}

// ════════════════════════════════════════════════════════════════════════════
// RECOVERY DETAIL
// ════════════════════════════════════════════════════════════════════════════

/// Detail recovery untuk satu chunk.
#[derive(Debug, Clone)]
pub struct RecoveryDetail {
    /// Hash chunk.
    pub chunk_hash: String,
    /// Apakah recovery berhasil.
    pub success: bool,
    /// Ukuran bytes (jika sukses).
    pub bytes: u64,
    /// Peer node yang digunakan (jika ada).
    pub peer_node: Option<String>,
    /// Pesan error (jika gagal).
    pub error: Option<String>,
}

impl RecoveryDetail {
    /// Membuat detail sukses.
    pub fn success(chunk_hash: String, bytes: u64, peer_node: String) -> Self {
        Self {
            chunk_hash,
            success: true,
            bytes,
            peer_node: Some(peer_node),
            error: None,
        }
    }

    /// Membuat detail gagal.
    pub fn failure(chunk_hash: String, error: String) -> Self {
        Self {
            chunk_hash,
            success: false,
            bytes: 0,
            peer_node: None,
            error: Some(error),
        }
    }

    /// Membuat detail gagal dengan peer info.
    pub fn failure_with_peer(chunk_hash: String, peer_node: String, error: String) -> Self {
        Self {
            chunk_hash,
            success: false,
            bytes: 0,
            peer_node: Some(peer_node),
            error: Some(error),
        }
    }
}

impl Display for RecoveryDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.success {
            write!(
                f,
                "RECOVERED {} ({} bytes from {})",
                self.chunk_hash,
                self.bytes,
                self.peer_node.as_deref().unwrap_or("unknown")
            )
        } else {
            write!(
                f,
                "FAILED {} ({})",
                self.chunk_hash,
                self.error.as_deref().unwrap_or("unknown error")
            )
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// RECOVERY REPORT
// ════════════════════════════════════════════════════════════════════════════

/// Laporan hasil recovery.
#[derive(Debug, Clone, Default)]
pub struct RecoveryReport {
    /// Jumlah chunk berhasil direcover.
    pub recovered_count: usize,
    /// Jumlah chunk gagal direcover.
    pub failed_count: usize,
    /// Total bytes yang berhasil direcover.
    pub total_bytes: u64,
    /// Detail per-chunk.
    pub details: Vec<RecoveryDetail>,
}

impl RecoveryReport {
    /// Membuat report baru (kosong).
    pub fn new() -> Self {
        Self::default()
    }

    /// Tambah detail sukses.
    pub fn add_success(&mut self, detail: RecoveryDetail) {
        self.recovered_count += 1;
        self.total_bytes += detail.bytes;
        self.details.push(detail);
    }

    /// Tambah detail gagal.
    pub fn add_failure(&mut self, detail: RecoveryDetail) {
        self.failed_count += 1;
        self.details.push(detail);
    }

    /// Total chunks yang diproses.
    pub fn total_processed(&self) -> usize {
        self.recovered_count + self.failed_count
    }

    /// Apakah semua recovery sukses.
    pub fn all_succeeded(&self) -> bool {
        self.failed_count == 0
    }

    /// Get hanya detail sukses.
    pub fn successes(&self) -> Vec<&RecoveryDetail> {
        self.details.iter().filter(|d| d.success).collect()
    }

    /// Get hanya detail gagal.
    pub fn failures(&self) -> Vec<&RecoveryDetail> {
        self.details.iter().filter(|d| !d.success).collect()
    }
}

impl Display for RecoveryReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RecoveryReport {{ recovered: {}, failed: {}, bytes: {} }}",
            self.recovered_count, self.failed_count, self.total_bytes
        )
    }
}

// ════════════════════════════════════════════════════════════════════════════
// PEER FETCHER TRAIT
// ════════════════════════════════════════════════════════════════════════════

/// Trait untuk fetch chunk dari peer node.
///
/// Implementasi konkret bisa menggunakan RPC, HTTP, atau mekanisme lain.
pub trait PeerFetcher: Send + Sync {
    /// Fetch chunk dari peer node.
    ///
    /// # Arguments
    ///
    /// * `peer_id` - ID peer node
    /// * `chunk_hash` - Hash chunk yang diminta
    ///
    /// # Returns
    ///
    /// - `Ok(Some(data))` jika chunk ditemukan
    /// - `Ok(None)` jika chunk tidak ada di peer
    /// - `Err` jika terjadi error
    fn fetch_chunk(&self, peer_id: &str, chunk_hash: &str) -> Result<Option<Vec<u8>>, RecoveryError>;
}

// ════════════════════════════════════════════════════════════════════════════
// STORAGE RECOVERY
// ════════════════════════════════════════════════════════════════════════════

/// Recovery manager untuk storage.
///
/// Memulihkan chunk yang seharusnya ada di node ini berdasarkan DA state.
///
/// # Fields
///
/// - `storage`: DA-aware storage lokal
/// - `da`: Sumber kebenaran assignment & metadata
/// - `my_node_id`: Identitas node ini
/// - `peer_nodes`: Daftar node peer yang mungkin menyimpan replica sah
///
/// # Prinsip
///
/// - Recovery berdasarkan DA assignment
/// - Verifikasi sebelum store
/// - Tidak overwrite existing
pub struct StorageRecovery<F: PeerFetcher> {
    /// DA-aware storage lokal.
    storage: Arc<DAStorage>,
    /// DA layer untuk assignment info.
    da: Arc<dyn DALayer>,
    /// ID node ini.
    my_node_id: String,
    /// Daftar peer nodes.
    peer_nodes: Vec<String>,
    /// Peer fetcher implementation.
    fetcher: F,
}

impl<F: PeerFetcher> Debug for StorageRecovery<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StorageRecovery")
            .field("storage", &"<DAStorage>")
            .field("da", &"<DALayer>")
            .field("my_node_id", &self.my_node_id)
            .field("peer_nodes", &self.peer_nodes)
            .finish()
    }
}

impl<F: PeerFetcher> StorageRecovery<F> {
    /// Membuat StorageRecovery baru.
    ///
    /// # Arguments
    ///
    /// * `storage` - DA-aware storage lokal
    /// * `da` - DA layer
    /// * `my_node_id` - ID node ini
    /// * `peer_nodes` - Daftar peer nodes
    /// * `fetcher` - Peer fetcher implementation
    pub fn new(
        storage: Arc<DAStorage>,
        da: Arc<dyn DALayer>,
        my_node_id: String,
        peer_nodes: Vec<String>,
        fetcher: F,
    ) -> Self {
        Self {
            storage,
            da,
            my_node_id,
            peer_nodes,
            fetcher,
        }
    }

    /// Get storage reference.
    pub fn storage(&self) -> &Arc<DAStorage> {
        &self.storage
    }

    /// Get node ID.
    pub fn my_node_id(&self) -> &str {
        &self.my_node_id
    }

    /// Get peer nodes.
    pub fn peer_nodes(&self) -> &[String] {
        &self.peer_nodes
    }

    // ════════════════════════════════════════════════════════════════════════
    // MISSING CHUNK IDENTIFICATION
    // ════════════════════════════════════════════════════════════════════════

    /// Identify chunks yang assigned ke node ini tapi tidak ada di storage.
    ///
    /// # Returns
    ///
    /// List of (chunk_hash, expected_commitment) tuples.
    pub fn identify_missing(&self) -> Vec<(String, [u8; 32])> {
        let mut missing = Vec::new();

        // Get all metadata (which contains replica info)
        let all_metadata = self.storage.all_metadata();

        for (hash, meta) in all_metadata.iter() {
            // Check if this node is supposed to have this chunk
            if self.storage.am_i_replica(hash, &self.my_node_id) {
                // Check if chunk actually exists in storage
                match self.storage.has_chunk(hash) {
                    Ok(false) => {
                        // Assigned to us but missing
                        missing.push((hash.clone(), meta.da_commitment));
                    }
                    Ok(true) => {
                        // Already have it, skip
                    }
                    Err(e) => {
                        warn!("Error checking chunk {}: {}", hash, e);
                    }
                }
            }
        }

        debug!("Identified {} missing chunks", missing.len());
        missing
    }

    // ════════════════════════════════════════════════════════════════════════
    // COMMITMENT VERIFICATION
    // ════════════════════════════════════════════════════════════════════════

    /// Verify commitment of data.
    ///
    /// # Arguments
    ///
    /// * `data` - Chunk data
    /// * `expected` - Expected commitment
    ///
    /// # Returns
    ///
    /// `true` if commitment matches.
    fn verify_commitment(&self, data: &[u8], expected: &[u8; 32]) -> bool {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let actual: [u8; 32] = result.into();
        actual == *expected
    }

    /// Compute commitment of data.
    fn compute_commitment(&self, data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let result = hasher.finalize();
        result.into()
    }

    // ════════════════════════════════════════════════════════════════════════
    // CHUNK RECOVERY
    // ════════════════════════════════════════════════════════════════════════

    /// Recover satu chunk dari peers.
    ///
    /// # Arguments
    ///
    /// * `chunk_hash` - Hash chunk
    /// * `expected_commitment` - Expected commitment
    ///
    /// # Returns
    ///
    /// RecoveryDetail dengan hasil recovery.
    fn recover_chunk(
        &self,
        chunk_hash: &str,
        expected_commitment: &[u8; 32],
    ) -> RecoveryDetail {
        // Check if already exists (safety: no overwrite)
        match self.storage.has_chunk(chunk_hash) {
            Ok(true) => {
                debug!("Chunk {} already exists, skipping recovery", chunk_hash);
                return RecoveryDetail::failure(
                    chunk_hash.to_string(),
                    "Chunk already exists".to_string(),
                );
            }
            Ok(false) => {}
            Err(e) => {
                return RecoveryDetail::failure(
                    chunk_hash.to_string(),
                    format!("Error checking chunk: {}", e),
                );
            }
        }

        // Try each peer until success
        for peer_id in &self.peer_nodes {
            debug!("Trying to fetch {} from peer {}", chunk_hash, peer_id);

            match self.fetcher.fetch_chunk(peer_id, chunk_hash) {
                Ok(Some(data)) => {
                    // Verify commitment before storing
                    if self.verify_commitment(&data, expected_commitment) {
                        // Store the chunk
                        match self.storage.put_chunk_with_meta(
                            chunk_hash,
                            &data,
                            *expected_commitment,
                        ) {
                            Ok(()) => {
                                info!(
                                    "Recovered chunk {} ({} bytes) from {}",
                                    chunk_hash,
                                    data.len(),
                                    peer_id
                                );
                                return RecoveryDetail::success(
                                    chunk_hash.to_string(),
                                    data.len() as u64,
                                    peer_id.clone(),
                                );
                            }
                            Err(e) => {
                                warn!(
                                    "Failed to store recovered chunk {}: {}",
                                    chunk_hash, e
                                );
                                return RecoveryDetail::failure_with_peer(
                                    chunk_hash.to_string(),
                                    peer_id.clone(),
                                    format!("Store error: {}", e),
                                );
                            }
                        }
                    } else {
                        // Commitment mismatch - try next peer
                        let actual = self.compute_commitment(&data);
                        warn!(
                            "Commitment mismatch for {} from {}: expected {:02x?}, got {:02x?}",
                            chunk_hash,
                            peer_id,
                            &expected_commitment[..4],
                            &actual[..4]
                        );
                        continue;
                    }
                }
                Ok(None) => {
                    debug!("Chunk {} not found at peer {}", chunk_hash, peer_id);
                    continue;
                }
                Err(e) => {
                    debug!("Error fetching {} from {}: {}", chunk_hash, peer_id, e);
                    continue;
                }
            }
        }

        // All peers failed
        RecoveryDetail::failure(
            chunk_hash.to_string(),
            "No peer could provide valid data".to_string(),
        )
    }

    // ════════════════════════════════════════════════════════════════════════
    // RECOVER MISSING
    // ════════════════════════════════════════════════════════════════════════

    /// Recover semua chunk yang missing.
    ///
    /// # Returns
    ///
    /// - `Ok(RecoveryReport)`: Laporan hasil recovery
    /// - `Err(RecoveryError)`: Jika terjadi error fatal
    ///
    /// # Behavior
    ///
    /// 1. Identify chunks assigned ke node ini tapi tidak ada di storage
    /// 2. Untuk setiap chunk missing:
    ///    - Fetch dari peer nodes
    ///    - Verify commitment
    ///    - Store jika valid
    /// 3. Return report lengkap
    ///
    /// # Invariant
    ///
    /// - Tidak overwrite chunk yang sudah ada
    /// - Tidak menyimpan tanpa verifikasi
    /// - Tidak recovery chunk yang tidak assigned
    /// - Tidak panic
    pub fn recover_missing(&self) -> Result<RecoveryReport, RecoveryError> {
        let mut report = RecoveryReport::new();

        // Identify missing chunks
        let missing = self.identify_missing();

        if missing.is_empty() {
            info!("No missing chunks to recover");
            return Ok(report);
        }

        info!("Starting recovery of {} missing chunks", missing.len());

        // Recover each missing chunk
        for (chunk_hash, expected_commitment) in missing {
            let detail = self.recover_chunk(&chunk_hash, &expected_commitment);

            if detail.success {
                report.add_success(detail);
            } else {
                report.add_failure(detail);
            }
        }

        info!(
            "Recovery complete: {} recovered, {} failed, {} bytes",
            report.recovered_count, report.failed_count, report.total_bytes
        );

        Ok(report)
    }

    /// Recover specific chunks.
    ///
    /// # Arguments
    ///
    /// * `chunk_hashes` - List of chunk hashes to recover
    ///
    /// # Returns
    ///
    /// RecoveryReport dengan hasil recovery.
    pub fn recover_specific(
        &self,
        chunk_hashes: &[String],
    ) -> Result<RecoveryReport, RecoveryError> {
        let mut report = RecoveryReport::new();

        for chunk_hash in chunk_hashes {
            // Check if chunk is assigned to this node
            if !self.storage.am_i_replica(chunk_hash, &self.my_node_id) {
                report.add_failure(RecoveryDetail::failure(
                    chunk_hash.clone(),
                    "Chunk not assigned to this node".to_string(),
                ));
                continue;
            }

            // Get expected commitment from metadata
            let expected_commitment = match self.storage.get_metadata(chunk_hash) {
                Some(meta) => meta.da_commitment,
                None => {
                    report.add_failure(RecoveryDetail::failure(
                        chunk_hash.clone(),
                        "Metadata not found".to_string(),
                    ));
                    continue;
                }
            };

            let detail = self.recover_chunk(chunk_hash, &expected_commitment);

            if detail.success {
                report.add_success(detail);
            } else {
                report.add_failure(detail);
            }
        }

        Ok(report)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// SIMPLE STORAGE RECOVERY (WITHOUT GENERIC)
// ════════════════════════════════════════════════════════════════════════════

/// Simple recovery manager dengan mock peer fetcher built-in.
///
/// Untuk production, gunakan `StorageRecovery<F>` dengan custom fetcher.
pub struct SimpleStorageRecovery {
    /// DA-aware storage lokal.
    storage: Arc<DAStorage>,
    /// DA layer untuk assignment info.
    da: Arc<dyn DALayer>,
    /// ID node ini.
    my_node_id: String,
    /// Daftar peer nodes.
    peer_nodes: Vec<String>,
    /// Mock peer data untuk testing.
    mock_peer_data: parking_lot::RwLock<HashMap<(String, String), Vec<u8>>>,
}

impl Debug for SimpleStorageRecovery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SimpleStorageRecovery")
            .field("storage", &"<DAStorage>")
            .field("da", &"<DALayer>")
            .field("my_node_id", &self.my_node_id)
            .field("peer_nodes", &self.peer_nodes)
            .finish()
    }
}

impl SimpleStorageRecovery {
    /// Membuat SimpleStorageRecovery baru.
    pub fn new(
        storage: Arc<DAStorage>,
        da: Arc<dyn DALayer>,
        my_node_id: String,
        peer_nodes: Vec<String>,
    ) -> Self {
        Self {
            storage,
            da,
            my_node_id,
            peer_nodes,
            mock_peer_data: parking_lot::RwLock::new(HashMap::new()),
        }
    }

    /// Set mock peer data untuk testing.
    pub fn set_mock_peer_data(&self, peer_id: &str, chunk_hash: &str, data: Vec<u8>) {
        self.mock_peer_data
            .write()
            .insert((peer_id.to_string(), chunk_hash.to_string()), data);
    }

    /// Get storage reference.
    pub fn storage(&self) -> &Arc<DAStorage> {
        &self.storage
    }

    /// Get node ID.
    pub fn my_node_id(&self) -> &str {
        &self.my_node_id
    }

    /// Get peer nodes.
    pub fn peer_nodes(&self) -> &[String] {
        &self.peer_nodes
    }

    /// Identify missing chunks.
    pub fn identify_missing(&self) -> Vec<(String, [u8; 32])> {
        let mut missing = Vec::new();
        let all_metadata = self.storage.all_metadata();

        for (hash, meta) in all_metadata.iter() {
            if self.storage.am_i_replica(hash, &self.my_node_id) {
                match self.storage.has_chunk(hash) {
                    Ok(false) => {
                        missing.push((hash.clone(), meta.da_commitment));
                    }
                    _ => {}
                }
            }
        }
        missing
    }

    /// Verify commitment.
    fn verify_commitment(&self, data: &[u8], expected: &[u8; 32]) -> bool {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let actual: [u8; 32] = result.into();
        actual == *expected
    }

    /// Compute commitment.
    fn compute_commitment(&self, data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let result = hasher.finalize();
        result.into()
    }

    /// Fetch from mock peer.
    fn fetch_from_peer(&self, peer_id: &str, chunk_hash: &str) -> Option<Vec<u8>> {
        self.mock_peer_data
            .read()
            .get(&(peer_id.to_string(), chunk_hash.to_string()))
            .cloned()
    }

    /// Recover one chunk.
    fn recover_chunk(&self, chunk_hash: &str, expected_commitment: &[u8; 32]) -> RecoveryDetail {
        // Safety: no overwrite
        match self.storage.has_chunk(chunk_hash) {
            Ok(true) => {
                return RecoveryDetail::failure(
                    chunk_hash.to_string(),
                    "Chunk already exists".to_string(),
                );
            }
            Ok(false) => {}
            Err(e) => {
                return RecoveryDetail::failure(
                    chunk_hash.to_string(),
                    format!("Error checking chunk: {}", e),
                );
            }
        }

        // Try each peer
        for peer_id in &self.peer_nodes {
            if let Some(data) = self.fetch_from_peer(peer_id, chunk_hash) {
                // Verify commitment
                if self.verify_commitment(&data, expected_commitment) {
                    // Store
                    match self.storage.put_chunk_with_meta(chunk_hash, &data, *expected_commitment) {
                        Ok(()) => {
                            return RecoveryDetail::success(
                                chunk_hash.to_string(),
                                data.len() as u64,
                                peer_id.clone(),
                            );
                        }
                        Err(e) => {
                            return RecoveryDetail::failure_with_peer(
                                chunk_hash.to_string(),
                                peer_id.clone(),
                                format!("Store error: {}", e),
                            );
                        }
                    }
                }
                // Commitment mismatch, try next peer
            }
        }

        RecoveryDetail::failure(
            chunk_hash.to_string(),
            "No peer could provide valid data".to_string(),
        )
    }

    /// Recover missing chunks.
    pub fn recover_missing(&self) -> Result<RecoveryReport, RecoveryError> {
        let mut report = RecoveryReport::new();
        let missing = self.identify_missing();

        if missing.is_empty() {
            return Ok(report);
        }

        for (chunk_hash, expected_commitment) in missing {
            let detail = self.recover_chunk(&chunk_hash, &expected_commitment);
            if detail.success {
                report.add_success(detail);
            } else {
                report.add_failure(detail);
            }
        }

        Ok(report)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::da_storage::{DAChunkMeta, ChunkDeclaredEvent, ReplicaAddedEvent};
    use dsdn_common::MockDA;
    use parking_lot::RwLock;
    use std::collections::HashMap as StdHashMap;

    // ════════════════════════════════════════════════════════════════════════
    // MOCK STORAGE
    // ════════════════════════════════════════════════════════════════════════

    #[derive(Debug)]
    struct MockStorage {
        chunks: RwLock<StdHashMap<String, Vec<u8>>>,
    }

    impl MockStorage {
        fn new() -> Self {
            Self {
                chunks: RwLock::new(StdHashMap::new()),
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

    // ════════════════════════════════════════════════════════════════════════
    // HELPER FUNCTIONS
    // ════════════════════════════════════════════════════════════════════════

    fn create_test_recovery() -> SimpleStorageRecovery {
        let inner = Arc::new(MockStorage::new());
        let da = Arc::new(MockDA::new());
        let storage = Arc::new(DAStorage::new(inner, da.clone()));
        SimpleStorageRecovery::new(
            storage,
            da,
            "my-node".to_string(),
            vec!["peer-1".to_string(), "peer-2".to_string()],
        )
    }

    fn compute_test_commitment(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let result = hasher.finalize();
        result.into()
    }

    fn setup_chunk_metadata(
        storage: &DAStorage,
        hash: &str,
        commitment: [u8; 32],
        size: u64,
        assigned_node: &str,
    ) {
        // Declare chunk
        let event = ChunkDeclaredEvent::with_target_rf(
            hash.to_string(),
            size,
            commitment,
            None,
            1000,
            3,
        );
        storage.receive_chunk_declared(event);
        storage.sync_metadata_from_da().unwrap();

        // Add replica assignment
        storage.receive_replica_added(ReplicaAddedEvent::new(
            hash.to_string(),
            assigned_node.to_string(),
            1000,
            None,
        ));
        storage.sync_replica_info(hash).unwrap();
    }

    // ════════════════════════════════════════════════════════════════════════
    // A. MISSING CHUNK RECOVERY TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_missing_chunk_recovery_success() {
        let recovery = create_test_recovery();
        let data = b"test data for recovery";
        let commitment = compute_test_commitment(data);

        // Setup: chunk assigned to this node but not in storage
        setup_chunk_metadata(recovery.storage(), "chunk-1", commitment, data.len() as u64, "my-node");

        // Set mock peer data
        recovery.set_mock_peer_data("peer-1", "chunk-1", data.to_vec());

        // Verify chunk is missing
        assert!(!recovery.storage().has_chunk("chunk-1").unwrap());

        // Recover
        let report = recovery.recover_missing().unwrap();

        // Verify recovery
        assert_eq!(report.recovered_count, 1);
        assert_eq!(report.failed_count, 0);
        assert_eq!(report.total_bytes, data.len() as u64);

        // Verify chunk now exists
        assert!(recovery.storage().has_chunk("chunk-1").unwrap());
        let stored = recovery.storage().get_chunk("chunk-1").unwrap().unwrap();
        assert_eq!(stored, data);
    }

    #[test]
    fn test_missing_chunk_multiple_recovery() {
        let recovery = create_test_recovery();

        // Setup 3 missing chunks
        for i in 0..3 {
            let data = format!("data-{}", i);
            let commitment = compute_test_commitment(data.as_bytes());
            setup_chunk_metadata(
                recovery.storage(),
                &format!("chunk-{}", i),
                commitment,
                data.len() as u64,
                "my-node",
            );
            recovery.set_mock_peer_data("peer-1", &format!("chunk-{}", i), data.into_bytes());
        }

        // Recover
        let report = recovery.recover_missing().unwrap();

        assert_eq!(report.recovered_count, 3);
        assert_eq!(report.failed_count, 0);

        // Verify all exist
        for i in 0..3 {
            assert!(recovery.storage().has_chunk(&format!("chunk-{}", i)).unwrap());
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // B. INVALID DATA FROM PEER TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_invalid_data_commitment_mismatch() {
        let recovery = create_test_recovery();
        let original_data = b"original data";
        let commitment = compute_test_commitment(original_data);

        // Setup chunk with correct commitment
        setup_chunk_metadata(recovery.storage(), "chunk-1", commitment, original_data.len() as u64, "my-node");

        // Set mock peer data with WRONG data (different from commitment)
        let wrong_data = b"corrupted data";
        recovery.set_mock_peer_data("peer-1", "chunk-1", wrong_data.to_vec());
        recovery.set_mock_peer_data("peer-2", "chunk-1", wrong_data.to_vec());

        // Recover
        let report = recovery.recover_missing().unwrap();

        // Should fail because commitment mismatch
        assert_eq!(report.recovered_count, 0);
        assert_eq!(report.failed_count, 1);

        // Chunk should NOT be stored
        assert!(!recovery.storage().has_chunk("chunk-1").unwrap());
    }

    #[test]
    fn test_first_peer_invalid_second_valid() {
        let recovery = create_test_recovery();
        let original_data = b"original data";
        let commitment = compute_test_commitment(original_data);

        setup_chunk_metadata(recovery.storage(), "chunk-1", commitment, original_data.len() as u64, "my-node");

        // First peer has wrong data
        recovery.set_mock_peer_data("peer-1", "chunk-1", b"wrong data".to_vec());
        // Second peer has correct data
        recovery.set_mock_peer_data("peer-2", "chunk-1", original_data.to_vec());

        let report = recovery.recover_missing().unwrap();

        // Should succeed from second peer
        assert_eq!(report.recovered_count, 1);
        assert_eq!(report.failed_count, 0);

        // Check peer used
        let detail = &report.details[0];
        assert_eq!(detail.peer_node.as_deref(), Some("peer-2"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // C. CHUNK NOT ASSIGNED TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_chunk_not_assigned_not_recovered() {
        let recovery = create_test_recovery();
        let data = b"not my data";
        let commitment = compute_test_commitment(data);

        // Setup chunk assigned to OTHER node, not this one
        setup_chunk_metadata(recovery.storage(), "chunk-1", commitment, data.len() as u64, "other-node");

        // Set mock peer data
        recovery.set_mock_peer_data("peer-1", "chunk-1", data.to_vec());

        // Recover - should find nothing to recover
        let report = recovery.recover_missing().unwrap();

        assert_eq!(report.recovered_count, 0);
        assert_eq!(report.failed_count, 0);

        // Chunk should NOT exist locally
        assert!(!recovery.storage().has_chunk("chunk-1").unwrap());
    }

    // ════════════════════════════════════════════════════════════════════════
    // D. PARTIAL RECOVERY TESTS
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn test_partial_recovery_mixed_results() {
        let recovery = create_test_recovery();

        // Chunk 1: will succeed
        let data1 = b"data-1";
        let commitment1 = compute_test_commitment(data1);
        setup_chunk_metadata(recovery.storage(), "chunk-1", commitment1, data1.len() as u64, "my-node");
        recovery.set_mock_peer_data("peer-1", "chunk-1", data1.to_vec());

        // Chunk 2: will fail (no peer has it)
        let data2 = b"data-2";
        let commitment2 = compute_test_commitment(data2);
        setup_chunk_metadata(recovery.storage(), "chunk-2", commitment2, data2.len() as u64, "my-node");
        // No mock data for chunk-2

        // Chunk 3: will fail (commitment mismatch)
        let data3 = b"data-3";
        let commitment3 = compute_test_commitment(data3);
        setup_chunk_metadata(recovery.storage(), "chunk-3", commitment3, data3.len() as u64, "my-node");
        recovery.set_mock_peer_data("peer-1", "chunk-3", b"wrong".to_vec());

        // Recover
        let report = recovery.recover_missing().unwrap();

        assert_eq!(report.recovered_count, 1);
        assert_eq!(report.failed_count, 2);
        assert_eq!(report.total_bytes, data1.len() as u64);

        // Only chunk-1 should exist
        assert!(recovery.storage().has_chunk("chunk-1").unwrap());
        assert!(!recovery.storage().has_chunk("chunk-2").unwrap());
        assert!(!recovery.storage().has_chunk("chunk-3").unwrap());
    }

    #[test]
    fn test_report_details_accurate() {
        let recovery = create_test_recovery();

        // One success, one failure
        let data1 = b"success-data";
        let commitment1 = compute_test_commitment(data1);
        setup_chunk_metadata(recovery.storage(), "success", commitment1, data1.len() as u64, "my-node");
        recovery.set_mock_peer_data("peer-1", "success", data1.to_vec());

        let data2 = b"failure-data";
        let commitment2 = compute_test_commitment(data2);
        setup_chunk_metadata(recovery.storage(), "failure", commitment2, data2.len() as u64, "my-node");
        // No mock data

        let report = recovery.recover_missing().unwrap();

        let successes = report.successes();
        let failures = report.failures();

        assert_eq!(successes.len(), 1);
        assert_eq!(failures.len(), 1);

        assert!(successes[0].success);
        assert!(!failures[0].success);
        assert!(failures[0].error.is_some());
    }

    // ════════════════════════════════════════════════════════════════════════
    // E. SAFETY TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_no_overwrite_existing_chunk() {
        let recovery = create_test_recovery();
        let original_data = b"original";
        let commitment = compute_test_commitment(original_data);

        // Setup chunk AND store it locally
        setup_chunk_metadata(recovery.storage(), "chunk-1", commitment, original_data.len() as u64, "my-node");
        recovery.storage().put_chunk_with_meta("chunk-1", original_data, commitment).unwrap();

        // Set mock peer data with DIFFERENT data
        let different_data = b"different";
        recovery.set_mock_peer_data("peer-1", "chunk-1", different_data.to_vec());

        // Recover - should NOT find anything missing
        let report = recovery.recover_missing().unwrap();

        assert_eq!(report.recovered_count, 0);
        assert_eq!(report.failed_count, 0);

        // Original data should be preserved
        let stored = recovery.storage().get_chunk("chunk-1").unwrap().unwrap();
        assert_eq!(stored, original_data);
    }

    #[test]
    fn test_recovery_no_panic_empty_storage() {
        let recovery = create_test_recovery();

        // Empty storage, no chunks
        let report = recovery.recover_missing().unwrap();

        assert_eq!(report.recovered_count, 0);
        assert_eq!(report.failed_count, 0);
    }

    #[test]
    fn test_recovery_no_panic_no_peers() {
        let inner = Arc::new(MockStorage::new());
        let da = Arc::new(MockDA::new());
        let storage = Arc::new(DAStorage::new(inner, da.clone()));
        let recovery = SimpleStorageRecovery::new(
            storage.clone(),
            da,
            "my-node".to_string(),
            vec![], // No peers
        );

        let data = b"test";
        let commitment = compute_test_commitment(data);
        setup_chunk_metadata(recovery.storage(), "chunk-1", commitment, data.len() as u64, "my-node");

        // Should not panic, just fail recovery
        let report = recovery.recover_missing().unwrap();

        assert_eq!(report.recovered_count, 0);
        assert_eq!(report.failed_count, 1);
    }

    // ════════════════════════════════════════════════════════════════════════
    // F. RECOVERY ERROR TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_recovery_error_display() {
        let err = RecoveryError::ChunkNotFound("test-chunk".to_string());
        assert!(format!("{}", err).contains("test-chunk"));

        let err = RecoveryError::CommitmentMismatch {
            hash: "test".to_string(),
            expected: [0xAB; 32],
            actual: [0xCD; 32],
        };
        assert!(format!("{}", err).contains("Commitment mismatch"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // G. RECOVERY REPORT TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_recovery_report_methods() {
        let mut report = RecoveryReport::new();

        assert_eq!(report.total_processed(), 0);
        assert!(report.all_succeeded());

        report.add_success(RecoveryDetail::success("c1".to_string(), 100, "peer".to_string()));
        report.add_failure(RecoveryDetail::failure("c2".to_string(), "error".to_string()));

        assert_eq!(report.total_processed(), 2);
        assert!(!report.all_succeeded());
        assert_eq!(report.recovered_count, 1);
        assert_eq!(report.failed_count, 1);
        assert_eq!(report.total_bytes, 100);
    }

    #[test]
    fn test_recovery_detail_display() {
        let success = RecoveryDetail::success("c1".to_string(), 100, "peer-1".to_string());
        let display = format!("{}", success);
        assert!(display.contains("RECOVERED"));
        assert!(display.contains("c1"));
        assert!(display.contains("100 bytes"));

        let failure = RecoveryDetail::failure("c2".to_string(), "test error".to_string());
        let display = format!("{}", failure);
        assert!(display.contains("FAILED"));
        assert!(display.contains("c2"));
        assert!(display.contains("test error"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // H. IDENTIFY MISSING TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_identify_missing_accurate() {
        let recovery = create_test_recovery();

        // Setup 2 assigned chunks
        for i in 0..2 {
            let data = format!("data-{}", i);
            let commitment = compute_test_commitment(data.as_bytes());
            setup_chunk_metadata(
                recovery.storage(),
                &format!("chunk-{}", i),
                commitment,
                data.len() as u64,
                "my-node",
            );
        }

        // Setup 1 chunk assigned to other node
        let other_data = b"other";
        let other_commitment = compute_test_commitment(other_data);
        setup_chunk_metadata(recovery.storage(), "other-chunk", other_commitment, other_data.len() as u64, "other-node");

        // Identify missing - should find 2 (not the other-node one)
        let missing = recovery.identify_missing();
        assert_eq!(missing.len(), 2);
    }
}