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
use std::fmt::Debug;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use parking_lot::{RwLock, MappedRwLockReadGuard, RwLockReadGuard};
use tracing::{debug, error, info};

use dsdn_common::{BlobRef, DALayer, DAError};

use crate::store::Storage;

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

    /// Update from ChunkDeclaredEvent.
    ///
    /// Updates only DA-derived fields. Does NOT change:
    /// - verified (MUST NOT auto-change to true)
    ///
    /// # Arguments
    ///
    /// * `event` - ChunkDeclaredEvent to update from
    fn update_from_event(&mut self, event: &ChunkDeclaredEvent) {
        // Update DA-derived fields only
        self.size_bytes = event.size_bytes;
        self.da_commitment = event.da_commitment;
        if event.blob_ref.is_some() {
            self.blob_ref = event.blob_ref.clone();
        }
        // CRITICAL: verified TIDAK BOLEH diubah ke true secara otomatis
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
///
/// # Prinsip
///
/// - Semua operasi data didelegasikan ke `inner`
/// - Metadata di-sync dari DA events
/// - `inner` adalah sumber kebenaran untuk keberadaan data
/// - Metadata hanya untuk tracking, bukan pengganti data
///
/// # Invariant
///
/// - `has_chunk()` HARUS cek `inner`, bukan metadata
/// - Error dari `inner` HARUS propagate
/// - Metadata tidak boleh menggantikan data asli
/// - Metadata derived dari DA events
pub struct DAStorage {
    /// Storage asli yang menyimpan data chunk.
    inner: Arc<dyn Storage>,
    /// DA layer untuk verifikasi dan referensi.
    da: Arc<dyn DALayer>,
    /// Metadata chunk terkait DA. STATE TURUNAN, bukan authoritative.
    chunk_metadata: RwLock<HashMap<String, DAChunkMeta>>,
    /// ChunkDeclared events yang diterima dari DA.
    declared_chunks: RwLock<HashMap<String, ChunkDeclaredEvent>>,
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
                // Insert new metadata dari event
                let mut meta = DAChunkMeta::new(
                    event.chunk_hash.clone(),
                    event.size_bytes,
                    event.da_commitment,
                );
                if let Some(ref blob_ref) = event.blob_ref {
                    meta.blob_ref = Some(blob_ref.clone());
                }
                // CRITICAL: verified = false (already default)
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
}