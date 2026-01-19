//! ReconciliationEngine - Fondasi untuk reconcile fallback blobs ke Celestia (14A.1A.31)
//!
//! Module ini mendefinisikan struktur dasar untuk ReconciliationEngine.
//!
//! ## Tahap Ini (14A.1A.31)
//!
//! Tahap ini HANYA mendefinisikan:
//! - Struktur dasar `ReconciliationEngine`
//! - Struktur `ReconciliationConfig` dengan Default
//! - Struktur `PendingBlob` untuk tracking
//! - Module exports
//!
//! **TIDAK ADA** logic reconcile, async task, loop, atau side-effect.

use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use parking_lot::RwLock;
use dsdn_common::DALayer;

// ════════════════════════════════════════════════════════════════════════════════
// PENDING BLOB
// ════════════════════════════════════════════════════════════════════════════════

/// Blob yang pending untuk di-reconcile ke Celestia.
///
/// Menyimpan informasi yang diperlukan untuk melakukan
/// reconciliation dari QuorumDA ke Celestia.
#[derive(Debug, Clone)]
pub struct PendingBlob {
    /// Referensi ke blob di source DA (commitment hash).
    pub blob_ref: dsdn_common::BlobRef,

    /// Data blob mentah yang akan di-post ke Celestia.
    pub data: Vec<u8>,

    /// Timestamp saat blob ditambahkan ke pending queue (Unix seconds).
    pub added_at: u64,

    /// Jumlah retry yang sudah dilakukan.
    pub retry_count: u32,
}

impl PendingBlob {
    /// Get size of blob data in bytes.
    #[must_use]
    pub fn size_bytes(&self) -> u64 {
        self.data.len() as u64
    }

    /// Get original sequence number (blob_ref.height).
    ///
    /// Digunakan sebagai identifier unik untuk remove_pending.
    #[must_use]
    pub fn original_sequence(&self) -> u64 {
        self.blob_ref.height
    }

    /// Convert to PendingBlobInfo summary.
    ///
    /// Tidak meng-clone data Vec<u8>, hanya informasi summary.
    #[must_use]
    pub fn to_info(&self) -> PendingBlobInfo {
        PendingBlobInfo {
            original_sequence: self.blob_ref.height,
            source_da: "quorum".to_string(),
            received_at: self.added_at,
            retry_count: self.retry_count,
            size_bytes: self.data.len() as u64,
            commitment_present: true, // commitment selalu ada dalam BlobRef
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// PENDING BLOB INFO (14A.1A.32)
// ════════════════════════════════════════════════════════════════════════════════

/// Summary information untuk PendingBlob tanpa data mentah.
///
/// Digunakan untuk list_pending() agar tidak meng-clone data Vec<u8>.
/// Semua field diisi eksplisit dari PendingBlob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingBlobInfo {
    /// Sequence number dari blob di source DA (blob_ref.height).
    pub original_sequence: u64,

    /// Identifier source DA (selalu "quorum" untuk reconciliation).
    pub source_da: String,

    /// Timestamp saat blob diterima (Unix seconds).
    pub received_at: u64,

    /// Jumlah retry yang sudah dilakukan.
    pub retry_count: u32,

    /// Ukuran data blob dalam bytes.
    pub size_bytes: u64,

    /// Apakah commitment hash ada (selalu true karena BlobRef memiliki commitment).
    pub commitment_present: bool,
}

// ════════════════════════════════════════════════════════════════════════════════
// RECONCILIATION CONFIG
// ════════════════════════════════════════════════════════════════════════════════

/// Konfigurasi untuk ReconciliationEngine.
///
/// Semua nilai memiliki default yang deterministik dan eksplisit.
/// Default TIDAK diambil dari environment variables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciliationConfig {
    /// Jumlah blob per batch untuk reconciliation.
    pub batch_size: usize,

    /// Delay antar retry dalam milidetik.
    pub retry_delay_ms: u64,

    /// Maksimum jumlah retry per blob.
    pub max_retries: u32,

    /// Apakah reconciliation dilakukan secara parallel.
    pub parallel_reconcile: bool,
}

impl Default for ReconciliationConfig {
    /// Default configuration dengan nilai deterministik.
    ///
    /// - `batch_size`: 10
    /// - `retry_delay_ms`: 1000 (1 detik)
    /// - `max_retries`: 3
    /// - `parallel_reconcile`: false
    fn default() -> Self {
        Self {
            batch_size: 10,
            retry_delay_ms: 1000,
            max_retries: 3,
            parallel_reconcile: false,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// RECONCILIATION ENGINE
// ════════════════════════════════════════════════════════════════════════════════

/// Engine untuk melakukan reconciliation blob dari QuorumDA ke Celestia.
///
/// ## Thread Safety
///
/// Semua fields menggunakan tipe thread-safe:
/// - `RwLock` untuk mutable state (`pending_blobs`)
/// - `AtomicU64` untuk counters
/// - `Arc` untuk shared ownership (`celestia`)
pub struct ReconciliationEngine {
    /// Daftar blob yang pending untuk di-reconcile.
    pending_blobs: RwLock<Vec<PendingBlob>>,

    /// Counter blob yang berhasil di-reconcile.
    reconciled_count: AtomicU64,

    /// Counter blob yang gagal di-reconcile setelah max_retries.
    failed_count: AtomicU64,

    /// Timestamp terakhir kali reconciliation dilakukan (Unix seconds).
    last_reconcile: AtomicU64,

    /// Konfigurasi engine (immutable setelah konstruksi).
    config: ReconciliationConfig,

    /// Reference ke Celestia DA layer untuk posting blob.
    celestia: Arc<dyn DALayer>,
}

impl ReconciliationEngine {
    /// Membuat ReconciliationEngine baru.
    ///
    /// ## Parameters
    ///
    /// - `config`: Konfigurasi engine
    /// - `celestia`: Reference ke Celestia DA layer
    #[must_use]
    pub fn new(config: ReconciliationConfig, celestia: Arc<dyn DALayer>) -> Self {
        Self {
            pending_blobs: RwLock::new(Vec::new()),
            reconciled_count: AtomicU64::new(0),
            failed_count: AtomicU64::new(0),
            last_reconcile: AtomicU64::new(0),
            config,
            celestia,
        }
    }

    /// Get reference ke pending blobs queue.
    #[must_use]
    pub fn pending_blobs(&self) -> &RwLock<Vec<PendingBlob>> {
        &self.pending_blobs
    }

    /// Get current reconciled count.
    #[must_use]
    pub fn reconciled_count(&self) -> u64 {
        self.reconciled_count.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get current failed count.
    #[must_use]
    pub fn failed_count(&self) -> u64 {
        self.failed_count.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get last reconcile timestamp.
    #[must_use]
    pub fn last_reconcile(&self) -> u64 {
        self.last_reconcile.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get reference ke config.
    #[must_use]
    pub fn config(&self) -> &ReconciliationConfig {
        &self.config
    }

    /// Get reference ke celestia DA layer.
    #[must_use]
    pub fn celestia(&self) -> &Arc<dyn DALayer> {
        &self.celestia
    }

    /// Get current pending count.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending_blobs.read().len()
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Pending Blob Tracking Methods (14A.1A.32)
    // ────────────────────────────────────────────────────────────────────────────

    /// Menambahkan blob ke pending queue.
    ///
    /// Thread-safe: menggunakan write lock pada pending_blobs.
    /// Tidak overwrite blob yang sudah ada.
    pub fn add_pending(&self, blob: PendingBlob) {
        self.pending_blobs.write().push(blob);
    }

    /// Get jumlah pending blobs.
    ///
    /// Alias untuk pending_count() sesuai spec 14A.1A.32.
    #[must_use]
    pub fn get_pending_count(&self) -> usize {
        self.pending_blobs.read().len()
    }

    /// Get total size semua pending blobs dalam bytes.
    ///
    /// Menggunakan saturating_add untuk mencegah overflow.
    /// Deterministik: selalu mengembalikan hasil yang sama untuk state yang sama.
    #[must_use]
    pub fn get_pending_bytes(&self) -> u64 {
        self.pending_blobs
            .read()
            .iter()
            .fold(0u64, |acc, blob| acc.saturating_add(blob.size_bytes()))
    }

    /// List semua pending blobs sebagai summary.
    ///
    /// Mengembalikan Vec<PendingBlobInfo> tanpa data Vec<u8>.
    /// Urutan stabil sesuai urutan penyimpanan (FIFO).
    #[must_use]
    pub fn list_pending(&self) -> Vec<PendingBlobInfo> {
        self.pending_blobs
            .read()
            .iter()
            .map(PendingBlob::to_info)
            .collect()
    }

    /// Menghapus blob berdasarkan original_sequence.
    ///
    /// Returns Some(blob) jika ditemukan dan dihapus, None jika tidak ada.
    /// Hanya menghapus SATU blob (yang pertama ditemukan dengan sequence yang cocok).
    pub fn remove_pending(&self, sequence: u64) -> Option<PendingBlob> {
        let mut pending = self.pending_blobs.write();
        let position = pending
            .iter()
            .position(|blob| blob.original_sequence() == sequence);

        position.map(|idx| pending.remove(idx))
    }

    /// Menghapus semua blob yang expired.
    ///
    /// Blob dianggap expired jika retry_count >= config.max_retries.
    /// Returns jumlah blob yang dihapus.
    ///
    /// Operasi atomic secara logis: semua expired blob dihapus dalam satu write lock.
    pub fn clear_expired(&self) -> usize {
        let max_retries = self.config.max_retries;
        let mut pending = self.pending_blobs.write();
        let initial_len = pending.len();
        pending.retain(|blob| blob.retry_count < max_retries);
        initial_len - pending.len()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// THREAD SAFETY VERIFICATION
// ════════════════════════════════════════════════════════════════════════════════

// Compile-time assertion bahwa ReconciliationEngine adalah Send + Sync
const _: fn() = || {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<ReconciliationEngine>();
    assert_sync::<ReconciliationEngine>();
};

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::future::Future;

    /// Mock DALayer untuk testing
    struct MockDALayer;

    impl DALayer for MockDALayer {
        fn post_blob(
            &self,
            _data: &[u8],
        ) -> Pin<Box<dyn Future<Output = Result<dsdn_common::BlobRef, dsdn_common::DAError>> + Send + '_>> {
            Box::pin(async move {
                Ok(dsdn_common::BlobRef {
                    height: 1,
                    commitment: [0u8; 32],
                    namespace: [0u8; 29],
                })
            })
        }

        fn get_blob(
            &self,
            _ref_: &dsdn_common::BlobRef,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, dsdn_common::DAError>> + Send + '_>> {
            Box::pin(async move { Ok(vec![]) })
        }

        fn subscribe_blobs(
            &self,
            _from_height: Option<u64>,
        ) -> Pin<Box<dyn Future<Output = Result<dsdn_common::BlobStream, dsdn_common::DAError>> + Send + '_>> {
            Box::pin(async move {
                Err(dsdn_common::DAError::Other("not implemented".to_string()))
            })
        }

        fn health_check(
            &self,
        ) -> Pin<Box<dyn Future<Output = Result<dsdn_common::DAHealthStatus, dsdn_common::DAError>> + Send + '_>> {
            Box::pin(async move { Ok(dsdn_common::DAHealthStatus::Healthy) })
        }
    }

    #[test]
    fn test_reconciliation_config_default() {
        let config = ReconciliationConfig::default();

        assert_eq!(config.batch_size, 10);
        assert_eq!(config.retry_delay_ms, 1000);
        assert_eq!(config.max_retries, 3);
        assert!(!config.parallel_reconcile);
    }

    #[test]
    fn test_reconciliation_config_custom() {
        let config = ReconciliationConfig {
            batch_size: 20,
            retry_delay_ms: 2000,
            max_retries: 5,
            parallel_reconcile: true,
        };

        assert_eq!(config.batch_size, 20);
        assert_eq!(config.retry_delay_ms, 2000);
        assert_eq!(config.max_retries, 5);
        assert!(config.parallel_reconcile);
    }

    #[test]
    fn test_reconciliation_engine_new() {
        let config = ReconciliationConfig::default();
        let celestia: Arc<dyn DALayer> = Arc::new(MockDALayer);
        let engine = ReconciliationEngine::new(config.clone(), celestia);

        assert_eq!(engine.reconciled_count(), 0);
        assert_eq!(engine.failed_count(), 0);
        assert_eq!(engine.last_reconcile(), 0);
        assert_eq!(engine.pending_count(), 0);
        assert_eq!(engine.config().batch_size, config.batch_size);
    }

    #[test]
    fn test_pending_blob_construction() {
        let blob = PendingBlob {
            blob_ref: dsdn_common::BlobRef {
                height: 100,
                commitment: [1u8; 32],
                namespace: [2u8; 29],
            },
            data: vec![1, 2, 3, 4],
            added_at: 1700000000,
            retry_count: 0,
        };

        assert_eq!(blob.blob_ref.height, 100);
        assert_eq!(blob.data, vec![1, 2, 3, 4]);
        assert_eq!(blob.added_at, 1700000000);
        assert_eq!(blob.retry_count, 0);
    }

    #[test]
    fn test_engine_pending_blobs_access() {
        let config = ReconciliationConfig::default();
        let celestia: Arc<dyn DALayer> = Arc::new(MockDALayer);
        let engine = ReconciliationEngine::new(config, celestia);

        // Add a pending blob
        {
            let mut pending = engine.pending_blobs().write();
            pending.push(PendingBlob {
                blob_ref: dsdn_common::BlobRef {
                    height: 0,
                    commitment: [1u8; 32],
                    namespace: [0u8; 29],
                },
                data: vec![1, 2, 3],
                added_at: 1700000000,
                retry_count: 0,
            });
        }

        assert_eq!(engine.pending_count(), 1);
    }

    #[test]
    fn test_config_equality() {
        let config1 = ReconciliationConfig::default();
        let config2 = ReconciliationConfig::default();

        assert_eq!(config1, config2);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Tests for 14A.1A.32 - Pending Blob Tracking
    // ────────────────────────────────────────────────────────────────────────────

    fn make_test_blob(height: u64, data: Vec<u8>, retry_count: u32) -> PendingBlob {
        PendingBlob {
            blob_ref: dsdn_common::BlobRef {
                height,
                commitment: [height as u8; 32],
                namespace: [0u8; 29],
            },
            data,
            added_at: 1700000000 + height,
            retry_count,
        }
    }

    #[test]
    fn test_pending_blob_size_bytes() {
        let blob = make_test_blob(1, vec![1, 2, 3, 4, 5], 0);
        assert_eq!(blob.size_bytes(), 5);

        let empty_blob = make_test_blob(2, vec![], 0);
        assert_eq!(empty_blob.size_bytes(), 0);
    }

    #[test]
    fn test_pending_blob_original_sequence() {
        let blob = make_test_blob(42, vec![1], 0);
        assert_eq!(blob.original_sequence(), 42);
    }

    #[test]
    fn test_pending_blob_to_info() {
        let blob = make_test_blob(100, vec![1, 2, 3], 2);
        let info = blob.to_info();

        assert_eq!(info.original_sequence, 100);
        assert_eq!(info.source_da, "quorum");
        assert_eq!(info.received_at, 1700000100);
        assert_eq!(info.retry_count, 2);
        assert_eq!(info.size_bytes, 3);
        assert!(info.commitment_present);
    }

    #[test]
    fn test_add_pending() {
        let config = ReconciliationConfig::default();
        let celestia: Arc<dyn DALayer> = Arc::new(MockDALayer);
        let engine = ReconciliationEngine::new(config, celestia);

        assert_eq!(engine.get_pending_count(), 0);

        engine.add_pending(make_test_blob(1, vec![1, 2], 0));
        assert_eq!(engine.get_pending_count(), 1);

        engine.add_pending(make_test_blob(2, vec![3, 4, 5], 0));
        assert_eq!(engine.get_pending_count(), 2);
    }

    #[test]
    fn test_get_pending_bytes() {
        let config = ReconciliationConfig::default();
        let celestia: Arc<dyn DALayer> = Arc::new(MockDALayer);
        let engine = ReconciliationEngine::new(config, celestia);

        assert_eq!(engine.get_pending_bytes(), 0);

        engine.add_pending(make_test_blob(1, vec![1, 2, 3], 0));
        assert_eq!(engine.get_pending_bytes(), 3);

        engine.add_pending(make_test_blob(2, vec![4, 5, 6, 7, 8], 0));
        assert_eq!(engine.get_pending_bytes(), 8);
    }

    #[test]
    fn test_list_pending_order() {
        let config = ReconciliationConfig::default();
        let celestia: Arc<dyn DALayer> = Arc::new(MockDALayer);
        let engine = ReconciliationEngine::new(config, celestia);

        engine.add_pending(make_test_blob(10, vec![1], 0));
        engine.add_pending(make_test_blob(20, vec![2, 3], 1));
        engine.add_pending(make_test_blob(30, vec![4, 5, 6], 2));

        let list = engine.list_pending();
        assert_eq!(list.len(), 3);

        // Urutan harus stabil (FIFO)
        assert_eq!(list[0].original_sequence, 10);
        assert_eq!(list[1].original_sequence, 20);
        assert_eq!(list[2].original_sequence, 30);

        // Verify info correctness
        assert_eq!(list[0].size_bytes, 1);
        assert_eq!(list[1].size_bytes, 2);
        assert_eq!(list[2].size_bytes, 3);
    }

    #[test]
    fn test_remove_pending_exists() {
        let config = ReconciliationConfig::default();
        let celestia: Arc<dyn DALayer> = Arc::new(MockDALayer);
        let engine = ReconciliationEngine::new(config, celestia);

        engine.add_pending(make_test_blob(10, vec![1, 2], 0));
        engine.add_pending(make_test_blob(20, vec![3, 4], 0));
        engine.add_pending(make_test_blob(30, vec![5, 6], 0));

        assert_eq!(engine.get_pending_count(), 3);

        // Remove middle blob
        let removed = engine.remove_pending(20);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().original_sequence(), 20);
        assert_eq!(engine.get_pending_count(), 2);

        // Verify remaining blobs
        let list = engine.list_pending();
        assert_eq!(list[0].original_sequence, 10);
        assert_eq!(list[1].original_sequence, 30);
    }

    #[test]
    fn test_remove_pending_not_exists() {
        let config = ReconciliationConfig::default();
        let celestia: Arc<dyn DALayer> = Arc::new(MockDALayer);
        let engine = ReconciliationEngine::new(config, celestia);

        engine.add_pending(make_test_blob(10, vec![1], 0));

        let removed = engine.remove_pending(999);
        assert!(removed.is_none());
        assert_eq!(engine.get_pending_count(), 1);
    }

    #[test]
    fn test_remove_pending_only_first() {
        let config = ReconciliationConfig::default();
        let celestia: Arc<dyn DALayer> = Arc::new(MockDALayer);
        let engine = ReconciliationEngine::new(config, celestia);

        // Add two blobs with same sequence (edge case)
        engine.add_pending(make_test_blob(10, vec![1], 0));
        engine.add_pending(make_test_blob(10, vec![2], 0));

        assert_eq!(engine.get_pending_count(), 2);

        // Remove should only remove first occurrence
        let removed = engine.remove_pending(10);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().data, vec![1]);
        assert_eq!(engine.get_pending_count(), 1);
    }

    #[test]
    fn test_clear_expired_none() {
        let config = ReconciliationConfig::default(); // max_retries = 3
        let celestia: Arc<dyn DALayer> = Arc::new(MockDALayer);
        let engine = ReconciliationEngine::new(config, celestia);

        engine.add_pending(make_test_blob(1, vec![1], 0));
        engine.add_pending(make_test_blob(2, vec![2], 1));
        engine.add_pending(make_test_blob(3, vec![3], 2));

        // No blob has retry_count >= 3
        let cleared = engine.clear_expired();
        assert_eq!(cleared, 0);
        assert_eq!(engine.get_pending_count(), 3);
    }

    #[test]
    fn test_clear_expired_some() {
        let config = ReconciliationConfig::default(); // max_retries = 3
        let celestia: Arc<dyn DALayer> = Arc::new(MockDALayer);
        let engine = ReconciliationEngine::new(config, celestia);

        engine.add_pending(make_test_blob(1, vec![1], 0));
        engine.add_pending(make_test_blob(2, vec![2], 3)); // expired
        engine.add_pending(make_test_blob(3, vec![3], 2));
        engine.add_pending(make_test_blob(4, vec![4], 5)); // expired

        let cleared = engine.clear_expired();
        assert_eq!(cleared, 2);
        assert_eq!(engine.get_pending_count(), 2);

        // Verify remaining blobs
        let list = engine.list_pending();
        assert_eq!(list[0].original_sequence, 1);
        assert_eq!(list[1].original_sequence, 3);
    }

    #[test]
    fn test_clear_expired_all() {
        let config = ReconciliationConfig::default(); // max_retries = 3
        let celestia: Arc<dyn DALayer> = Arc::new(MockDALayer);
        let engine = ReconciliationEngine::new(config, celestia);

        engine.add_pending(make_test_blob(1, vec![1], 3)); // expired
        engine.add_pending(make_test_blob(2, vec![2], 4)); // expired
        engine.add_pending(make_test_blob(3, vec![3], 10)); // expired

        let cleared = engine.clear_expired();
        assert_eq!(cleared, 3);
        assert_eq!(engine.get_pending_count(), 0);
    }

    #[test]
    fn test_pending_blob_info_equality() {
        let info1 = PendingBlobInfo {
            original_sequence: 1,
            source_da: "quorum".to_string(),
            received_at: 1000,
            retry_count: 0,
            size_bytes: 100,
            commitment_present: true,
        };
        let info2 = info1.clone();
        assert_eq!(info1, info2);
    }
}