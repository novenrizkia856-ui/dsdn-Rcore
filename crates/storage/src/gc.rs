//! # Garbage Collection Module
//!
//! Modul ini menyediakan mekanisme garbage collection (GC) yang sepenuhnya
//! berdasarkan event DA (Data Availability).
//!
//! ## Prinsip Kunci
//!
//! - Data HANYA dihapus jika sah secara protokol
//! - Tidak ada premature deletion
//! - Semua GC auditable & deterministik
//! - `scan()` menemukan data yang boleh dihapus
//! - `collect()` menghapus data berdasarkan hasil scan
//!
//! ## Kategori GC
//!
//! ```text
//! ┌─────────────┐   ┌───────────────┐   ┌────────────────┐
//! │   Deleted   │   │   Orphaned    │   │   Corrupted    │
//! ├─────────────┤   ├───────────────┤   ├────────────────┤
//! │ DeleteReq   │   │ Not assigned  │   │ Commitment     │
//! │ + grace     │   │ to this node  │   │ mismatch       │
//! │   expired   │   │               │   │                │
//! └─────────────┘   └───────────────┘   └────────────────┘
//! ```
//!
//! ## Invariant
//!
//! - scan() TIDAK menghapus data, hanya mendeteksi
//! - collect() HANYA menghapus hasil scan
//! - Tidak ada auto-delete tanpa scan

use std::collections::HashSet;
use std::fmt::{self, Debug, Display};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::{debug, info, warn, error};

use dsdn_common::{DALayer, BlobRef};

use crate::da_storage::{DAStorage, StorageError};
use crate::store::Storage;

// ════════════════════════════════════════════════════════════════════════════
// GC ERROR
// ════════════════════════════════════════════════════════════════════════════

/// Error yang dapat terjadi pada operasi garbage collection.
#[derive(Debug)]
pub enum GCError {
    /// Error saat mengakses storage.
    StorageError(StorageError),
    /// Error saat mengakses DA layer.
    DAError(String),
    /// Chunk tidak ditemukan untuk dihapus.
    ChunkNotFound(String),
    /// Error lainnya.
    Other(String),
}

impl Display for GCError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GCError::StorageError(e) => write!(f, "Storage error: {}", e),
            GCError::DAError(msg) => write!(f, "DA error: {}", msg),
            GCError::ChunkNotFound(hash) => write!(f, "Chunk not found: {}", hash),
            GCError::Other(msg) => write!(f, "GC error: {}", msg),
        }
    }
}

impl std::error::Error for GCError {}

impl From<StorageError> for GCError {
    fn from(err: StorageError) -> Self {
        GCError::StorageError(err)
    }
}

impl From<Box<dyn std::error::Error + Send + Sync>> for GCError {
    fn from(err: Box<dyn std::error::Error + Send + Sync>) -> Self {
        GCError::Other(err.to_string())
    }
}

// ════════════════════════════════════════════════════════════════════════════
// DELETE REQUESTED EVENT
// ════════════════════════════════════════════════════════════════════════════

/// Event yang menandakan request penghapusan chunk.
///
/// Diterima dari DA layer ketika ada permintaan penghapusan chunk.
/// Grace period harus habis sebelum chunk boleh dihapus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteRequestedEvent {
    /// Hash chunk yang diminta untuk dihapus.
    pub chunk_hash: String,
    /// Timestamp request (Unix milliseconds).
    pub requested_at: u64,
    /// Grace period dalam milliseconds.
    pub grace_period_ms: u64,
    /// Referensi blob DA.
    pub blob_ref: Option<BlobRef>,
}

impl DeleteRequestedEvent {
    /// Membuat DeleteRequestedEvent baru.
    pub fn new(
        chunk_hash: String,
        requested_at: u64,
        grace_period_ms: u64,
        blob_ref: Option<BlobRef>,
    ) -> Self {
        Self {
            chunk_hash,
            requested_at,
            grace_period_ms,
            blob_ref,
        }
    }

    /// Check apakah grace period sudah habis.
    ///
    /// # Arguments
    ///
    /// * `now_ms` - Current timestamp in Unix milliseconds
    ///
    /// # Returns
    ///
    /// `true` jika grace period sudah habis.
    pub fn is_grace_period_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.requested_at.saturating_add(self.grace_period_ms)
    }

    /// Get expiry timestamp.
    pub fn expires_at(&self) -> u64 {
        self.requested_at.saturating_add(self.grace_period_ms)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// GC SCAN RESULT
// ════════════════════════════════════════════════════════════════════════════

/// Hasil scan garbage collection.
///
/// Berisi daftar chunk yang boleh dihapus beserta alasannya.
///
/// # Fields
///
/// - `deleted`: Chunks dengan DeleteRequested event dan grace period habis
/// - `orphaned`: Chunks yang tidak assigned ke node ini
/// - `corrupted`: Chunks dengan commitment mismatch
/// - `total_reclaimable_bytes`: Total bytes yang bisa di-reclaim
///
/// # Invariant
///
/// Tidak ada duplikasi hash antar kategori.
#[derive(Debug, Clone, Default)]
pub struct GCScanResult {
    /// Chunk hashes yang sudah di-delete request dan grace period habis.
    pub deleted: Vec<String>,
    /// Chunk hashes yang tidak assigned ke node ini (orphaned).
    pub orphaned: Vec<String>,
    /// Chunk hashes dengan data corruption (commitment mismatch).
    pub corrupted: Vec<String>,
    /// Total bytes yang bisa di-reclaim.
    pub total_reclaimable_bytes: u64,
}

impl GCScanResult {
    /// Membuat GCScanResult baru (kosong).
    pub fn new() -> Self {
        Self::default()
    }

    /// Total chunks yang bisa di-collect.
    pub fn total_collectible(&self) -> usize {
        self.deleted.len() + self.orphaned.len() + self.corrupted.len()
    }

    /// Apakah ada yang perlu di-collect.
    pub fn has_collectible(&self) -> bool {
        self.total_collectible() > 0
    }

    /// Get semua chunk hashes yang bisa di-collect.
    pub fn all_collectible(&self) -> Vec<String> {
        let mut all = Vec::with_capacity(self.total_collectible());
        all.extend(self.deleted.clone());
        all.extend(self.orphaned.clone());
        all.extend(self.corrupted.clone());
        all
    }

    /// Check apakah hash termasuk dalam hasil scan.
    pub fn contains(&self, hash: &str) -> bool {
        self.deleted.contains(&hash.to_string())
            || self.orphaned.contains(&hash.to_string())
            || self.corrupted.contains(&hash.to_string())
    }
}

impl Display for GCScanResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GCScanResult {{ deleted: {}, orphaned: {}, corrupted: {}, reclaimable: {} bytes }}",
            self.deleted.len(),
            self.orphaned.len(),
            self.corrupted.len(),
            self.total_reclaimable_bytes
        )
    }
}

// ════════════════════════════════════════════════════════════════════════════
// GARBAGE COLLECTOR
// ════════════════════════════════════════════════════════════════════════════

/// Garbage collector untuk storage.
///
/// GC beroperasi berdasarkan event DA dan hanya menghapus data yang
/// sah untuk dihapus secara protokol.
///
/// # Fields
///
/// - `storage`: DA-aware storage (bukan storage mentah)
/// - `da`: Sumber kebenaran lifecycle data
/// - `my_node_id`: Identitas node untuk menentukan orphan
///
/// # Prinsip
///
/// - scan() menemukan data yang boleh dihapus
/// - collect() menghapus berdasarkan hasil scan
/// - Tidak ada auto-delete tanpa scan
pub struct GarbageCollector {
    /// DA-aware storage.
    storage: Arc<DAStorage>,
    /// DA layer untuk verifikasi lifecycle.
    da: Arc<dyn DALayer>,
    /// ID node ini.
    my_node_id: String,
    /// Delete requested events.
    delete_events: parking_lot::RwLock<std::collections::HashMap<String, DeleteRequestedEvent>>,
}

impl Debug for GarbageCollector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GarbageCollector")
            .field("storage", &"<DAStorage>")
            .field("da", &"<DALayer>")
            .field("my_node_id", &self.my_node_id)
            .finish()
    }
}

impl GarbageCollector {
    /// Membuat GarbageCollector baru.
    ///
    /// # Arguments
    ///
    /// * `storage` - DA-aware storage
    /// * `da` - DA layer
    /// * `my_node_id` - ID node ini
    pub fn new(
        storage: Arc<DAStorage>,
        da: Arc<dyn DALayer>,
        my_node_id: String,
    ) -> Self {
        Self {
            storage,
            da,
            my_node_id,
            delete_events: parking_lot::RwLock::new(std::collections::HashMap::new()),
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

    // ════════════════════════════════════════════════════════════════════════
    // DELETE EVENT MANAGEMENT
    // ════════════════════════════════════════════════════════════════════════

    /// Receive DeleteRequested event.
    ///
    /// # Arguments
    ///
    /// * `event` - DeleteRequestedEvent
    pub fn receive_delete_requested(&self, event: DeleteRequestedEvent) {
        debug!(
            "Received DeleteRequested for chunk: {}, grace_period: {}ms",
            event.chunk_hash, event.grace_period_ms
        );
        self.delete_events
            .write()
            .insert(event.chunk_hash.clone(), event);
    }

    /// Check if chunk has delete request.
    pub fn has_delete_request(&self, hash: &str) -> bool {
        self.delete_events.read().contains_key(hash)
    }

    /// Get delete request for chunk.
    pub fn get_delete_request(&self, hash: &str) -> Option<DeleteRequestedEvent> {
        self.delete_events.read().get(hash).cloned()
    }

    /// Clear delete request for chunk.
    pub fn clear_delete_request(&self, hash: &str) {
        self.delete_events.write().remove(hash);
    }

    // ════════════════════════════════════════════════════════════════════════
    // SCAN
    // ════════════════════════════════════════════════════════════════════════

    /// Scan storage untuk menemukan chunks yang boleh dihapus.
    ///
    /// # Returns
    ///
    /// - `Ok(GCScanResult)`: Hasil scan dengan kategori chunks
    /// - `Err(GCError)`: Jika terjadi error
    ///
    /// # Behavior
    ///
    /// Scan HANYA menemukan chunks, TIDAK menghapus.
    ///
    /// Kategori yang ditemukan:
    ///
    /// A. Deleted: DeleteRequested event + grace period habis
    /// B. Orphaned: Chunk tidak assigned ke node ini (berdasarkan replica info)
    /// C. Corrupted: Chunk gagal verify_chunk_commitment
    ///
    /// # Invariant
    ///
    /// - Deterministik
    /// - Tidak mengubah state
    /// - Tidak panic
    pub fn scan(&self) -> Result<GCScanResult, GCError> {
        let mut result = GCScanResult::new();
        let now_ms = current_timestamp_ms();

        // Get all chunks from metadata
        let all_metadata = self.storage.all_metadata();
        let mut seen: HashSet<String> = HashSet::new();

        debug!("GC scan starting: {} chunks in metadata", all_metadata.len());

        for (hash, meta) in all_metadata.iter() {
            // Skip if already categorized
            if seen.contains(hash) {
                continue;
            }

            let chunk_size = meta.size_bytes;

            // A. Check if deleted (DeleteRequested + grace period expired)
            if let Some(delete_event) = self.get_delete_request(hash) {
                if delete_event.is_grace_period_expired(now_ms) {
                    debug!("GC scan: {} -> deleted (grace period expired)", hash);
                    result.deleted.push(hash.clone());
                    result.total_reclaimable_bytes += chunk_size;
                    seen.insert(hash.clone());
                    continue;
                }
            }

            // B. Check if orphaned (not assigned to this node)
            // Based on replica info from DA
            if !self.storage.am_i_replica(hash, &self.my_node_id) {
                // Check if chunk data actually exists in storage
                match self.storage.has_chunk(hash) {
                    Ok(true) => {
                        // Data exists but we're not a replica -> orphaned
                        debug!("GC scan: {} -> orphaned (not replica)", hash);
                        result.orphaned.push(hash.clone());
                        result.total_reclaimable_bytes += chunk_size;
                        seen.insert(hash.clone());
                        continue;
                    }
                    Ok(false) => {
                        // No data, skip
                        continue;
                    }
                    Err(e) => {
                        warn!("GC scan: error checking chunk {}: {}", hash, e);
                        continue;
                    }
                }
            }

            // C. Check if corrupted (commitment mismatch)
            match self.storage.verify_chunk_commitment(hash) {
                Ok(true) => {
                    // Valid, skip
                }
                Ok(false) => {
                    // Commitment mismatch -> corrupted
                    debug!("GC scan: {} -> corrupted (commitment mismatch)", hash);
                    result.corrupted.push(hash.clone());
                    result.total_reclaimable_bytes += chunk_size;
                    seen.insert(hash.clone());
                }
                Err(StorageError::MetadataNotFound(_)) => {
                    // No metadata, skip
                }
                Err(e) => {
                    warn!("GC scan: error verifying chunk {}: {}", hash, e);
                }
            }
        }

        // Also scan for chunks with data but no metadata (potential orphans)
        // This requires iterating storage, which depends on implementation

        info!(
            "GC scan complete: {} deleted, {} orphaned, {} corrupted, {} bytes reclaimable",
            result.deleted.len(),
            result.orphaned.len(),
            result.corrupted.len(),
            result.total_reclaimable_bytes
        );

        Ok(result)
    }

    // ════════════════════════════════════════════════════════════════════════
    // COLLECT
    // ════════════════════════════════════════════════════════════════════════

    /// Collect (hapus) chunks berdasarkan hasil scan.
    ///
    /// # Arguments
    ///
    /// * `result` - Hasil scan dari scan()
    ///
    /// # Returns
    ///
    /// - `Ok(usize)`: Jumlah chunks yang berhasil dihapus
    /// - `Err(GCError)`: Jika terjadi error
    ///
    /// # Behavior
    ///
    /// - Hapus HANYA chunks yang ada di result
    /// - Hapus data chunk DAN metadata
    /// - Stop pada error, return Err
    ///
    /// # Invariant
    ///
    /// - Tidak menghapus di luar result
    /// - Tidak menghapus chunk aktif
    /// - Tidak partial silent failure
    pub fn collect(&self, result: &GCScanResult) -> Result<usize, GCError> {
        let mut deleted_count = 0;

        info!(
            "GC collect starting: {} chunks to delete",
            result.total_collectible()
        );

        // Collect all categories
        let all_hashes = result.all_collectible();

        for hash in all_hashes {
            // Double-check: verify chunk is still in scan result
            if !result.contains(&hash) {
                continue;
            }

            // Delete chunk (data + metadata)
            match self.storage.delete_chunk(&hash) {
                Ok(true) => {
                    debug!("GC collect: deleted chunk {}", hash);
                    deleted_count += 1;

                    // Clear delete request if exists
                    self.clear_delete_request(&hash);
                }
                Ok(false) => {
                    debug!("GC collect: chunk {} not found (already deleted?)", hash);
                }
                Err(e) => {
                    error!("GC collect: error deleting chunk {}: {}", hash, e);
                    return Err(GCError::Other(format!(
                        "Failed to delete chunk {}: {}",
                        hash, e
                    )));
                }
            }
        }

        info!("GC collect complete: {} chunks deleted", deleted_count);
        Ok(deleted_count)
    }

    /// Run full GC cycle (scan + collect).
    ///
    /// # Returns
    ///
    /// - `Ok((GCScanResult, usize))`: Scan result and deleted count
    /// - `Err(GCError)`: If error occurs
    pub fn run(&self) -> Result<(GCScanResult, usize), GCError> {
        let scan_result = self.scan()?;
        let deleted_count = self.collect(&scan_result)?;
        Ok((scan_result, deleted_count))
    }
}

// ════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════

/// Get current timestamp in Unix milliseconds.
fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::da_storage::{DAStorage, DAChunkMeta, ChunkDeclaredEvent, ReplicaAddedEvent};
    use crate::store::Storage;
    use dsdn_common::MockDA;
    use parking_lot::RwLock;
    use std::collections::HashMap;

    // ════════════════════════════════════════════════════════════════════════
    // MOCK STORAGE
    // ════════════════════════════════════════════════════════════════════════

    #[derive(Debug)]
    struct MockStorage {
        chunks: RwLock<HashMap<String, Vec<u8>>>,
    }

    impl MockStorage {
        fn new() -> Self {
            Self {
                chunks: RwLock::new(HashMap::new()),
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

    fn create_test_gc() -> GarbageCollector {
        let inner = Arc::new(MockStorage::new());
        let da = Arc::new(MockDA::new());
        let storage = Arc::new(DAStorage::new(inner, da.clone()));
        GarbageCollector::new(storage, da, "my-node-id".to_string())
    }

    fn compute_test_commitment(data: &[u8]) -> [u8; 32] {
        use sha3::{Sha3_256, Digest};
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    fn create_chunk_declared_event(hash: &str, size: u64, target_rf: u8) -> ChunkDeclaredEvent {
        ChunkDeclaredEvent::with_target_rf(
            hash.to_string(),
            size,
            [0xAB; 32],
            None,
            1000,
            target_rf,
        )
    }

    // ════════════════════════════════════════════════════════════════════════
    // A. DELETED CHUNK TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_deleted_chunk_grace_period_expired() {
        let gc = create_test_gc();
        let data = b"test data for delete";
        let commitment = compute_test_commitment(data);

        // Setup chunk
        gc.storage.put_chunk_with_meta("chunk-1", data, commitment).unwrap();
        
        // Add replica so it's not orphaned
        gc.storage.receive_chunk_declared(create_chunk_declared_event("chunk-1", data.len() as u64, 3));
        gc.storage.sync_metadata_from_da().unwrap();
        gc.storage.receive_replica_added(ReplicaAddedEvent::new(
            "chunk-1".to_string(),
            "my-node-id".to_string(),
            1000,
            None,
        ));
        gc.storage.sync_replica_info("chunk-1").unwrap();

        // Add delete request with grace period already expired
        let delete_event = DeleteRequestedEvent::new(
            "chunk-1".to_string(),
            1000, // requested_at
            100,  // grace_period_ms (very short)
            None,
        );
        gc.receive_delete_requested(delete_event);

        // Scan should find it as deleted
        let result = gc.scan().unwrap();
        assert!(result.deleted.contains(&"chunk-1".to_string()));
        assert!(!result.orphaned.contains(&"chunk-1".to_string()));

        // Collect should delete it
        let deleted = gc.collect(&result).unwrap();
        assert_eq!(deleted, 1);

        // Chunk should be gone
        assert!(!gc.storage.has_metadata("chunk-1"));
    }

    #[test]
    fn test_deleted_chunk_grace_period_not_expired() {
        let gc = create_test_gc();
        let data = b"test data";
        let commitment = compute_test_commitment(data);

        // Setup chunk
        gc.storage.put_chunk_with_meta("chunk-1", data, commitment).unwrap();
        gc.storage.receive_chunk_declared(create_chunk_declared_event("chunk-1", data.len() as u64, 3));
        gc.storage.sync_metadata_from_da().unwrap();
        gc.storage.receive_replica_added(ReplicaAddedEvent::new(
            "chunk-1".to_string(),
            "my-node-id".to_string(),
            1000,
            None,
        ));
        gc.storage.sync_replica_info("chunk-1").unwrap();

        // Add delete request with grace period FAR in future
        let now_ms = current_timestamp_ms();
        let delete_event = DeleteRequestedEvent::new(
            "chunk-1".to_string(),
            now_ms,         // requested_at = now
            86400000,       // grace_period = 24 hours
            None,
        );
        gc.receive_delete_requested(delete_event);

        // Scan should NOT find it as deleted (grace period not expired)
        let result = gc.scan().unwrap();
        assert!(!result.deleted.contains(&"chunk-1".to_string()));
    }

    // ════════════════════════════════════════════════════════════════════════
    // B. ORPHANED CHUNK TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_orphaned_chunk_not_replica() {
        let gc = create_test_gc();
        let data = b"orphaned data";
        let commitment = compute_test_commitment(data);

        // Put chunk with metadata but NO replica for this node
        gc.storage.put_chunk_with_meta("chunk-1", data, commitment).unwrap();
        gc.storage.receive_chunk_declared(create_chunk_declared_event("chunk-1", data.len() as u64, 3));
        gc.storage.sync_metadata_from_da().unwrap();
        
        // Add replica for DIFFERENT node
        gc.storage.receive_replica_added(ReplicaAddedEvent::new(
            "chunk-1".to_string(),
            "other-node".to_string(), // Not my-node-id
            1000,
            None,
        ));
        gc.storage.sync_replica_info("chunk-1").unwrap();

        // Scan should find it as orphaned
        let result = gc.scan().unwrap();
        assert!(result.orphaned.contains(&"chunk-1".to_string()));
        assert_eq!(result.total_reclaimable_bytes, data.len() as u64);
    }

    #[test]
    fn test_not_orphaned_if_replica() {
        let gc = create_test_gc();
        let data = b"valid replica data";
        let commitment = compute_test_commitment(data);

        // Put chunk with metadata AND replica for this node
        gc.storage.put_chunk_with_meta("chunk-1", data, commitment).unwrap();
        gc.storage.receive_chunk_declared(create_chunk_declared_event("chunk-1", data.len() as u64, 3));
        gc.storage.sync_metadata_from_da().unwrap();
        
        // Add replica for THIS node
        gc.storage.receive_replica_added(ReplicaAddedEvent::new(
            "chunk-1".to_string(),
            "my-node-id".to_string(), // This node
            1000,
            None,
        ));
        gc.storage.sync_replica_info("chunk-1").unwrap();

        // Scan should NOT find it as orphaned
        let result = gc.scan().unwrap();
        assert!(!result.orphaned.contains(&"chunk-1".to_string()));
    }

    // ════════════════════════════════════════════════════════════════════════
    // C. CORRUPTED CHUNK TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_corrupted_chunk_commitment_mismatch() {
        let gc = create_test_gc();
        let data = b"original data";
        let wrong_commitment = [0xFFu8; 32]; // Wrong commitment

        // Put chunk with WRONG commitment
        gc.storage.put_chunk_with_meta("chunk-1", data, wrong_commitment).unwrap();
        gc.storage.receive_chunk_declared(create_chunk_declared_event("chunk-1", data.len() as u64, 3));
        gc.storage.sync_metadata_from_da().unwrap();
        
        // Add replica for this node (so it's not orphaned)
        gc.storage.receive_replica_added(ReplicaAddedEvent::new(
            "chunk-1".to_string(),
            "my-node-id".to_string(),
            1000,
            None,
        ));
        gc.storage.sync_replica_info("chunk-1").unwrap();

        // Scan should find it as corrupted
        let result = gc.scan().unwrap();
        assert!(result.corrupted.contains(&"chunk-1".to_string()));
    }

    #[test]
    fn test_not_corrupted_if_valid() {
        let gc = create_test_gc();
        let data = b"valid data";
        let commitment = compute_test_commitment(data); // Correct commitment

        // Put chunk with correct commitment
        gc.storage.put_chunk_with_meta("chunk-1", data, commitment).unwrap();
        gc.storage.receive_chunk_declared(create_chunk_declared_event("chunk-1", data.len() as u64, 3));
        gc.storage.sync_metadata_from_da().unwrap();
        
        // Add replica for this node
        gc.storage.receive_replica_added(ReplicaAddedEvent::new(
            "chunk-1".to_string(),
            "my-node-id".to_string(),
            1000,
            None,
        ));
        gc.storage.sync_replica_info("chunk-1").unwrap();

        // Scan should NOT find it as corrupted
        let result = gc.scan().unwrap();
        assert!(!result.corrupted.contains(&"chunk-1".to_string()));
    }

    // ════════════════════════════════════════════════════════════════════════
    // D. SAFETY TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_active_chunk_not_in_scan() {
        let gc = create_test_gc();
        let data = b"active chunk data";
        let commitment = compute_test_commitment(data);

        // Put valid chunk with correct commitment and replica
        gc.storage.put_chunk_with_meta("active-chunk", data, commitment).unwrap();
        gc.storage.receive_chunk_declared(create_chunk_declared_event("active-chunk", data.len() as u64, 3));
        gc.storage.sync_metadata_from_da().unwrap();
        gc.storage.receive_replica_added(ReplicaAddedEvent::new(
            "active-chunk".to_string(),
            "my-node-id".to_string(),
            1000,
            None,
        ));
        gc.storage.sync_replica_info("active-chunk").unwrap();

        // Scan should NOT find active chunk
        let result = gc.scan().unwrap();
        assert!(!result.contains("active-chunk"));
    }

    #[test]
    fn test_collect_only_deletes_scan_result() {
        let gc = create_test_gc();

        // Setup: one orphaned, one active
        let orphan_data = b"orphan";
        let active_data = b"active";
        let active_commitment = compute_test_commitment(active_data);

        // Orphan - no replica for this node
        gc.storage.put_chunk_with_meta("orphan", orphan_data, [0xAB; 32]).unwrap();
        gc.storage.receive_chunk_declared(create_chunk_declared_event("orphan", orphan_data.len() as u64, 3));
        gc.storage.sync_metadata_from_da().unwrap();
        gc.storage.receive_replica_added(ReplicaAddedEvent::new(
            "orphan".to_string(),
            "other-node".to_string(),
            1000,
            None,
        ));
        gc.storage.sync_replica_info("orphan").unwrap();

        // Active - has replica for this node
        gc.storage.put_chunk_with_meta("active", active_data, active_commitment).unwrap();
        gc.storage.receive_chunk_declared(create_chunk_declared_event("active", active_data.len() as u64, 3));
        gc.storage.sync_metadata_from_da().unwrap();
        gc.storage.receive_replica_added(ReplicaAddedEvent::new(
            "active".to_string(),
            "my-node-id".to_string(),
            1000,
            None,
        ));
        gc.storage.sync_replica_info("active").unwrap();

        // Scan
        let result = gc.scan().unwrap();
        assert!(result.orphaned.contains(&"orphan".to_string()));
        assert!(!result.contains("active"));

        // Collect
        let deleted = gc.collect(&result).unwrap();
        assert_eq!(deleted, 1);

        // Active should still exist
        assert!(gc.storage.has_metadata("active"));
        // Orphan should be gone
        assert!(!gc.storage.has_metadata("orphan"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // E. ACCOUNTING TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_total_reclaimable_bytes_accurate() {
        let gc = create_test_gc();

        // Add multiple orphaned chunks of different sizes
        for i in 0..3 {
            let data = vec![0u8; (i + 1) * 100]; // 100, 200, 300 bytes
            gc.storage.put_chunk_with_meta(&format!("chunk-{}", i), &data, [0xAB; 32]).unwrap();
            gc.storage.receive_chunk_declared(create_chunk_declared_event(&format!("chunk-{}", i), data.len() as u64, 3));
        }
        gc.storage.sync_metadata_from_da().unwrap();

        // Add replicas for OTHER node (making them orphans for this node)
        for i in 0..3 {
            gc.storage.receive_replica_added(ReplicaAddedEvent::new(
                format!("chunk-{}", i),
                "other-node".to_string(),
                1000,
                None,
            ));
            gc.storage.sync_replica_info(&format!("chunk-{}", i)).unwrap();
        }

        // Scan
        let result = gc.scan().unwrap();
        
        // Total should be 100 + 200 + 300 = 600 bytes
        assert_eq!(result.total_reclaimable_bytes, 600);
        assert_eq!(result.orphaned.len(), 3);
    }

    // ════════════════════════════════════════════════════════════════════════
    // F. DELETE REQUESTED EVENT TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_delete_requested_event_grace_period() {
        let event = DeleteRequestedEvent::new(
            "chunk-1".to_string(),
            1000,  // requested_at
            500,   // grace_period
            None,
        );

        // Before grace period expires
        assert!(!event.is_grace_period_expired(1000));
        assert!(!event.is_grace_period_expired(1499));

        // After grace period expires
        assert!(event.is_grace_period_expired(1500));
        assert!(event.is_grace_period_expired(2000));

        // Expiry time
        assert_eq!(event.expires_at(), 1500);
    }

    // ════════════════════════════════════════════════════════════════════════
    // G. GC SCAN RESULT TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_gc_scan_result_methods() {
        let mut result = GCScanResult::new();
        
        assert_eq!(result.total_collectible(), 0);
        assert!(!result.has_collectible());

        result.deleted.push("deleted-1".to_string());
        result.orphaned.push("orphan-1".to_string());
        result.corrupted.push("corrupt-1".to_string());

        assert_eq!(result.total_collectible(), 3);
        assert!(result.has_collectible());
        assert!(result.contains("deleted-1"));
        assert!(result.contains("orphan-1"));
        assert!(result.contains("corrupt-1"));
        assert!(!result.contains("nonexistent"));

        let all = result.all_collectible();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_gc_scan_result_display() {
        let mut result = GCScanResult::new();
        result.deleted.push("d1".to_string());
        result.orphaned.push("o1".to_string());
        result.orphaned.push("o2".to_string());
        result.total_reclaimable_bytes = 1024;

        let display = format!("{}", result);
        assert!(display.contains("deleted: 1"));
        assert!(display.contains("orphaned: 2"));
        assert!(display.contains("1024 bytes"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // H. GC ERROR TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_gc_error_display() {
        let err = GCError::ChunkNotFound("chunk-123".to_string());
        assert!(format!("{}", err).contains("chunk-123"));

        let err = GCError::DAError("connection failed".to_string());
        assert!(format!("{}", err).contains("connection failed"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // I. FULL CYCLE TEST
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_full_gc_cycle() {
        let gc = create_test_gc();

        // Setup mix of chunks
        // 1. Active chunk (valid, has replica)
        let active_data = b"active";
        let active_commit = compute_test_commitment(active_data);
        gc.storage.put_chunk_with_meta("active", active_data, active_commit).unwrap();
        gc.storage.receive_chunk_declared(create_chunk_declared_event("active", active_data.len() as u64, 3));
        gc.storage.sync_metadata_from_da().unwrap();
        gc.storage.receive_replica_added(ReplicaAddedEvent::new(
            "active".to_string(), "my-node-id".to_string(), 1000, None,
        ));
        gc.storage.sync_replica_info("active").unwrap();

        // 2. Orphaned chunk
        let orphan_data = b"orphan data here";
        gc.storage.put_chunk_with_meta("orphan", orphan_data, [0xAB; 32]).unwrap();
        gc.storage.receive_chunk_declared(create_chunk_declared_event("orphan", orphan_data.len() as u64, 3));
        gc.storage.sync_metadata_from_da().unwrap();
        gc.storage.receive_replica_added(ReplicaAddedEvent::new(
            "orphan".to_string(), "other-node".to_string(), 1000, None,
        ));
        gc.storage.sync_replica_info("orphan").unwrap();

        // Run full GC cycle
        let (scan_result, deleted_count) = gc.run().unwrap();

        // Verify results
        assert_eq!(scan_result.orphaned.len(), 1);
        assert!(scan_result.orphaned.contains(&"orphan".to_string()));
        assert!(!scan_result.contains("active"));
        assert_eq!(deleted_count, 1);

        // Active still exists
        assert!(gc.storage.has_metadata("active"));
        // Orphan is gone
        assert!(!gc.storage.has_metadata("orphan"));
    }
}