//! # DA-Aware Storage Module
//!
//! Modul ini menyediakan lapisan storage yang sadar Data Availability (DA).
//!
//! ## Arsitektur
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │              DAStorage                       │
//! ├─────────────────────────────────────────────┤
//! │  ┌─────────────┐    ┌──────────────────┐   │
//! │  │    inner    │    │  chunk_metadata  │   │
//! │  │  (Storage)  │    │   (DA metadata)  │   │
//! │  └─────────────┘    └──────────────────┘   │
//! │         │                    │              │
//! │         ▼                    ▼              │
//! │  ┌─────────────┐    ┌──────────────────┐   │
//! │  │  Actual     │    │   DALayer        │   │
//! │  │  Data       │    │   (Celestia)     │   │
//! │  └─────────────┘    └──────────────────┘   │
//! └─────────────────────────────────────────────┘
//! ```
//!
//! ## Prinsip Kunci
//!
//! - `inner` adalah storage asli yang menyimpan data chunk
//! - `chunk_metadata` adalah STATE TURUNAN, bukan authoritative
//! - Data di `inner` adalah sumber kebenaran untuk keberadaan chunk
//! - Metadata hanya untuk tracking hubungan dengan DA
//!
//! ## Invariant
//!
//! - Metadata BUKAN pengganti data
//! - has_chunk() HARUS cek inner, bukan metadata
//! - Error dari inner HARUS propagate, tidak boleh disembunyikan

use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;

use parking_lot::RwLock;

use dsdn_common::{BlobRef, DALayer};

use crate::store::Storage;

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
///
/// # Invariant
///
/// `verified` TIDAK BOLEH default `true`. Chunk harus diverifikasi
/// secara eksplisit sebelum dianggap verified.
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
    /// DAChunkMeta dengan `verified = false` dan `blob_ref = None`.
    pub fn new(hash: String, size_bytes: u64, da_commitment: [u8; 32]) -> Self {
        Self {
            hash,
            size_bytes,
            da_commitment,
            blob_ref: None,
            verified: false, // WAJIB default false
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
///
/// # Prinsip
///
/// - Semua operasi data didelegasikan ke `inner`
/// - Metadata di-sync saat operasi storage
/// - `inner` adalah sumber kebenaran untuk keberadaan data
/// - Metadata hanya untuk tracking, bukan pengganti data
///
/// # Invariant
///
/// - `has_chunk()` HARUS cek `inner`, bukan metadata
/// - Error dari `inner` HARUS propagate
/// - Metadata tidak boleh menggantikan data asli
pub struct DAStorage {
    /// Storage asli yang menyimpan data chunk.
    inner: Arc<dyn Storage>,
    /// DA layer untuk verifikasi dan referensi.
    da: Arc<dyn DALayer>,
    /// Metadata chunk terkait DA. STATE TURUNAN, bukan authoritative.
    chunk_metadata: RwLock<HashMap<String, DAChunkMeta>>,
}

impl Debug for DAStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DAStorage")
            .field("inner", &self.inner)
            .field("da", &"<DALayer>")
            .field("chunk_metadata_count", &self.chunk_metadata.read().len())
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

    /// Get metadata for a chunk.
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

    /// Delete chunk and its metadata.
    ///
    /// # Note
    ///
    /// Karena Storage trait tidak memiliki delete_chunk,
    /// method ini hanya menghapus metadata.
    /// Untuk delete data, gunakan inner storage langsung jika tersedia.
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

    fn create_error_da_storage() -> DAStorage {
        let inner = Arc::new(ErrorStorage);
        let da = Arc::new(MockDA::new());
        DAStorage::new(inner, da)
    }

    // ════════════════════════════════════════════════════════════════════════
    // A. WRAPPER CORRECTNESS TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_put_get_through_da_storage() {
        let storage = create_da_storage();

        // Put chunk
        let result = storage.put_chunk("chunk-1", b"test data");
        assert!(result.is_ok());

        // Get chunk - should return same data
        let data = storage.get_chunk("chunk-1").unwrap();
        assert_eq!(data, Some(b"test data".to_vec()));
    }

    #[test]
    fn test_has_chunk_checks_inner() {
        let storage = create_da_storage();

        // Before put
        assert!(!storage.has_chunk("chunk-1").unwrap());

        // After put
        storage.put_chunk("chunk-1", b"data").unwrap();
        assert!(storage.has_chunk("chunk-1").unwrap());
    }

    #[test]
    fn test_get_nonexistent_chunk() {
        let storage = create_da_storage();

        let data = storage.get_chunk("nonexistent").unwrap();
        assert!(data.is_none());
    }

    #[test]
    fn test_put_overwrites_existing() {
        let storage = create_da_storage();

        storage.put_chunk("chunk-1", b"original").unwrap();
        storage.put_chunk("chunk-1", b"updated").unwrap();

        let data = storage.get_chunk("chunk-1").unwrap();
        assert_eq!(data, Some(b"updated".to_vec()));
    }

    // ════════════════════════════════════════════════════════════════════════
    // B. METADATA SYNC TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_metadata_created_on_put() {
        let storage = create_da_storage();

        assert!(!storage.has_metadata("chunk-1"));

        storage.put_chunk("chunk-1", b"test data").unwrap();

        assert!(storage.has_metadata("chunk-1"));
        let meta = storage.get_metadata("chunk-1").unwrap();
        assert_eq!(meta.hash, "chunk-1");
        assert_eq!(meta.size_bytes, 9); // "test data" = 9 bytes
        assert!(!meta.verified); // WAJIB false
    }

    #[test]
    fn test_metadata_removed_on_delete() {
        let storage = create_da_storage();

        storage.put_chunk("chunk-1", b"data").unwrap();
        assert!(storage.has_metadata("chunk-1"));

        storage.delete_metadata("chunk-1");
        assert!(!storage.has_metadata("chunk-1"));
    }

    #[test]
    fn test_metadata_with_commitment() {
        let storage = create_da_storage();
        let commitment = [0xAB; 32];

        storage
            .put_chunk_with_meta("chunk-1", b"data", commitment)
            .unwrap();

        let meta = storage.get_metadata("chunk-1").unwrap();
        assert_eq!(meta.da_commitment, commitment);
        assert!(!meta.verified);
    }

    #[test]
    fn test_metadata_with_blob_ref() {
        let storage = create_da_storage();
        let commitment = [0xCD; 32];
        let blob_ref = BlobRef {
            height: 100,
            commitment: [0xEF; 32],
            namespace: [0x01; 29],
        };

        storage
            .put_chunk_with_blob_ref("chunk-1", b"data", commitment, blob_ref.clone())
            .unwrap();

        let meta = storage.get_metadata("chunk-1").unwrap();
        assert_eq!(meta.da_commitment, commitment);
        assert_eq!(meta.blob_ref, Some(blob_ref));
        assert!(!meta.verified);
    }

    #[test]
    fn test_set_verified() {
        let storage = create_da_storage();

        storage.put_chunk("chunk-1", b"data").unwrap();

        // Initially not verified
        let meta = storage.get_metadata("chunk-1").unwrap();
        assert!(!meta.verified);

        // Set verified
        assert!(storage.set_verified("chunk-1", true));
        let meta = storage.get_metadata("chunk-1").unwrap();
        assert!(meta.verified);

        // Set not verified again
        assert!(storage.set_verified("chunk-1", false));
        let meta = storage.get_metadata("chunk-1").unwrap();
        assert!(!meta.verified);
    }

    #[test]
    fn test_set_verified_nonexistent() {
        let storage = create_da_storage();

        // Should return false for nonexistent
        assert!(!storage.set_verified("nonexistent", true));
    }

    #[test]
    fn test_set_blob_ref() {
        let storage = create_da_storage();
        let blob_ref = BlobRef {
            height: 200,
            commitment: [0x11; 32],
            namespace: [0x22; 29],
        };

        storage.put_chunk("chunk-1", b"data").unwrap();

        // Initially no blob_ref
        let meta = storage.get_metadata("chunk-1").unwrap();
        assert!(meta.blob_ref.is_none());

        // Set blob_ref
        assert!(storage.set_blob_ref("chunk-1", blob_ref.clone()));
        let meta = storage.get_metadata("chunk-1").unwrap();
        assert_eq!(meta.blob_ref, Some(blob_ref));
    }

    // ════════════════════════════════════════════════════════════════════════
    // C. NO DATA DUPLICATION TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_metadata_not_authoritative() {
        let storage = create_da_storage();

        // Put chunk
        storage.put_chunk("chunk-1", b"data").unwrap();

        // Metadata exists
        assert!(storage.has_metadata("chunk-1"));

        // Remove metadata only
        storage.delete_metadata("chunk-1");

        // Metadata gone but data still exists
        assert!(!storage.has_metadata("chunk-1"));
        assert!(storage.has_chunk("chunk-1").unwrap()); // Data still in inner
    }

    #[test]
    fn test_has_chunk_ignores_metadata() {
        let storage = create_da_storage();

        // Manually add metadata without data
        let meta = DAChunkMeta::new("fake-chunk".to_string(), 100, [0u8; 32]);
        storage.set_metadata("fake-chunk", meta);

        // Metadata exists but has_chunk returns false
        assert!(storage.has_metadata("fake-chunk"));
        assert!(!storage.has_chunk("fake-chunk").unwrap());
    }

    #[test]
    fn test_get_chunk_ignores_metadata() {
        let storage = create_da_storage();

        // Manually add metadata without data
        let meta = DAChunkMeta::new("fake-chunk".to_string(), 100, [0u8; 32]);
        storage.set_metadata("fake-chunk", meta);

        // get_chunk returns None (checks inner, not metadata)
        let data = storage.get_chunk("fake-chunk").unwrap();
        assert!(data.is_none());
    }

    // ════════════════════════════════════════════════════════════════════════
    // D. ERROR PROPAGATION TESTS
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

    #[test]
    fn test_put_with_meta_error_propagates() {
        let storage = create_error_da_storage();

        let result = storage.put_chunk_with_meta("chunk-1", b"data", [0u8; 32]);
        assert!(result.is_err());

        // Metadata should NOT be created on error
        assert!(!storage.has_metadata("chunk-1"));
    }

    #[test]
    fn test_put_with_blob_ref_error_propagates() {
        let storage = create_error_da_storage();
        let blob_ref = BlobRef {
            height: 1,
            commitment: [0u8; 32],
            namespace: [0u8; 29],
        };

        let result = storage.put_chunk_with_blob_ref("chunk-1", b"data", [0u8; 32], blob_ref);
        assert!(result.is_err());

        // Metadata should NOT be created on error
        assert!(!storage.has_metadata("chunk-1"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // E. DETERMINISM TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_operations_deterministic() {
        let storage1 = create_da_storage();
        let storage2 = create_da_storage();

        // Same operations
        storage1.put_chunk("a", b"data-a").unwrap();
        storage1.put_chunk("b", b"data-b").unwrap();
        storage1.put_chunk("c", b"data-c").unwrap();

        storage2.put_chunk("a", b"data-a").unwrap();
        storage2.put_chunk("b", b"data-b").unwrap();
        storage2.put_chunk("c", b"data-c").unwrap();

        // Same results
        assert_eq!(
            storage1.get_chunk("a").unwrap(),
            storage2.get_chunk("a").unwrap()
        );
        assert_eq!(
            storage1.get_chunk("b").unwrap(),
            storage2.get_chunk("b").unwrap()
        );
        assert_eq!(
            storage1.get_chunk("c").unwrap(),
            storage2.get_chunk("c").unwrap()
        );

        // Same metadata count
        assert_eq!(storage1.metadata_count(), storage2.metadata_count());
    }

    #[test]
    fn test_metadata_deterministic() {
        let storage1 = create_da_storage();
        let storage2 = create_da_storage();

        let commitment = [0x55; 32];

        storage1
            .put_chunk_with_meta("chunk", b"data", commitment)
            .unwrap();
        storage2
            .put_chunk_with_meta("chunk", b"data", commitment)
            .unwrap();

        let meta1 = storage1.get_metadata("chunk").unwrap();
        let meta2 = storage2.get_metadata("chunk").unwrap();

        assert_eq!(meta1.hash, meta2.hash);
        assert_eq!(meta1.size_bytes, meta2.size_bytes);
        assert_eq!(meta1.da_commitment, meta2.da_commitment);
        assert_eq!(meta1.verified, meta2.verified);
    }

    // ════════════════════════════════════════════════════════════════════════
    // F. DACHUNKMETA TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_dachunkmeta_new_verified_false() {
        let meta = DAChunkMeta::new("hash".to_string(), 100, [0u8; 32]);
        assert!(!meta.verified); // WAJIB false
        assert!(meta.blob_ref.is_none());
    }

    #[test]
    fn test_dachunkmeta_with_blob_ref_verified_false() {
        let blob_ref = BlobRef {
            height: 1,
            commitment: [0u8; 32],
            namespace: [0u8; 29],
        };
        let meta = DAChunkMeta::with_blob_ref("hash".to_string(), 100, [0u8; 32], blob_ref.clone());
        assert!(!meta.verified); // WAJIB false
        assert_eq!(meta.blob_ref, Some(blob_ref));
    }

    #[test]
    fn test_dachunkmeta_set_methods() {
        let mut meta = DAChunkMeta::new("hash".to_string(), 100, [0u8; 32]);

        meta.set_verified(true);
        assert!(meta.verified);

        let blob_ref = BlobRef {
            height: 5,
            commitment: [0xAA; 32],
            namespace: [0xBB; 29],
        };
        meta.set_blob_ref(blob_ref.clone());
        assert_eq!(meta.blob_ref, Some(blob_ref));
    }

    // ════════════════════════════════════════════════════════════════════════
    // G. QUERY METHODS TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_unverified_chunks() {
        let storage = create_da_storage();

        storage.put_chunk("a", b"data").unwrap();
        storage.put_chunk("b", b"data").unwrap();
        storage.put_chunk("c", b"data").unwrap();

        // All unverified initially
        let unverified = storage.unverified_chunks();
        assert_eq!(unverified.len(), 3);

        // Verify one
        storage.set_verified("b", true);

        let unverified = storage.unverified_chunks();
        assert_eq!(unverified.len(), 2);
        assert!(!unverified.contains(&"b".to_string()));
    }

    #[test]
    fn test_verified_chunks() {
        let storage = create_da_storage();

        storage.put_chunk("a", b"data").unwrap();
        storage.put_chunk("b", b"data").unwrap();

        // None verified initially
        assert!(storage.verified_chunks().is_empty());

        // Verify one
        storage.set_verified("a", true);

        let verified = storage.verified_chunks();
        assert_eq!(verified.len(), 1);
        assert!(verified.contains(&"a".to_string()));
    }

    #[test]
    fn test_chunks_with_blob_ref() {
        let storage = create_da_storage();
        let blob_ref = BlobRef {
            height: 1,
            commitment: [0u8; 32],
            namespace: [0u8; 29],
        };

        storage.put_chunk("a", b"data").unwrap();
        storage
            .put_chunk_with_blob_ref("b", b"data", [0u8; 32], blob_ref)
            .unwrap();

        let with_ref = storage.chunks_with_blob_ref();
        assert_eq!(with_ref.len(), 1);
        assert!(with_ref.contains(&"b".to_string()));
    }

    // ════════════════════════════════════════════════════════════════════════
    // H. UTILITY METHODS TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_metadata_count() {
        let storage = create_da_storage();

        assert_eq!(storage.metadata_count(), 0);

        storage.put_chunk("a", b"data").unwrap();
        assert_eq!(storage.metadata_count(), 1);

        storage.put_chunk("b", b"data").unwrap();
        assert_eq!(storage.metadata_count(), 2);

        storage.delete_metadata("a");
        assert_eq!(storage.metadata_count(), 1);
    }

    #[test]
    fn test_all_metadata() {
        let storage = create_da_storage();

        storage.put_chunk("a", b"data-a").unwrap();
        storage.put_chunk("b", b"data-b").unwrap();

        let all = storage.all_metadata();
        assert_eq!(all.len(), 2);
        assert!(all.contains_key("a"));
        assert!(all.contains_key("b"));
    }

    #[test]
    fn test_clear_metadata() {
        let storage = create_da_storage();

        storage.put_chunk("a", b"data").unwrap();
        storage.put_chunk("b", b"data").unwrap();
        assert_eq!(storage.metadata_count(), 2);

        storage.clear_metadata();
        assert_eq!(storage.metadata_count(), 0);

        // Data still exists
        assert!(storage.has_chunk("a").unwrap());
        assert!(storage.has_chunk("b").unwrap());
    }

    #[test]
    fn test_inner_reference() {
        let storage = create_da_storage();

        storage.put_chunk("test", b"data").unwrap();

        // Access inner directly
        let inner = storage.inner();
        assert!(inner.has_chunk("test").unwrap());
    }

    #[test]
    fn test_debug_impl() {
        let storage = create_da_storage();
        storage.put_chunk("a", b"data").unwrap();

        let debug = format!("{:?}", storage);
        assert!(debug.contains("DAStorage"));
        assert!(debug.contains("chunk_metadata_count"));
    }
}