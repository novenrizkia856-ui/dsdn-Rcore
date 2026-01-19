//! ReconciliationEngine - Reconcile fallback blobs ke Celestia (14A.1A.31-33)
//!
//! Module ini menyediakan ReconciliationEngine untuk melakukan reconciliation
//! blob dari QuorumDA (fallback) ke Celestia (primary DA).
//!
//! ## Components
//!
//! - `ReconciliationEngine`: Engine utama untuk reconciliation
//! - `ReconciliationConfig`: Konfigurasi engine (batch_size, retry, parallel)
//! - `PendingBlob`: Blob yang pending untuk di-reconcile
//! - `PendingBlobInfo`: Summary info tanpa data mentah
//! - `ReconcileReport`: Laporan hasil reconciliation
//! - `ReconcileError`: Error types
//!
//! ## Thread Safety
//!
//! Semua komponen thread-safe:
//! - `RwLock` untuk mutable state
//! - `AtomicU64` untuk counters
//! - Lock TIDAK dipegang saat network call

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
// RECONCILE TYPES (14A.1A.33)
// ════════════════════════════════════════════════════════════════════════════════

/// Error yang dapat terjadi saat reconciliation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileError {
    /// Tidak ada pending blobs untuk diproses.
    NoPendingBlobs,

    /// DA layer tidak tersedia.
    DAUnavailable(String),

    /// Internal error.
    Internal(String),
}

impl std::fmt::Display for ReconcileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoPendingBlobs => write!(f, "No pending blobs to reconcile"),
            Self::DAUnavailable(msg) => write!(f, "DA layer unavailable: {}", msg),
            Self::Internal(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for ReconcileError {}

/// Status hasil reconciliation untuk satu blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlobReconcileStatus {
    /// Berhasil di-reconcile ke Celestia.
    Success,

    /// Gagal dengan error yang dapat di-retry.
    Failed(String),

    /// Gagal permanen (sudah melebihi max_retries).
    PermanentlyFailed(String),

    /// Di-skip karena sudah expired sebelum diproses.
    Skipped(String),
}

/// Detail hasil reconciliation untuk satu blob.
#[derive(Debug, Clone)]
pub struct BlobReconcileDetail {
    /// Sequence number dari blob.
    pub original_sequence: u64,

    /// Status hasil reconciliation.
    pub status: BlobReconcileStatus,

    /// Commitment dari Celestia jika sukses.
    pub celestia_commitment: Option<[u8; 32]>,

    /// Height di Celestia jika sukses.
    pub celestia_height: Option<u64>,

    /// Retry count saat ini.
    pub retry_count: u32,
}

/// Laporan hasil reconciliation batch.
#[derive(Debug, Clone)]
pub struct ReconcileReport {
    /// Jumlah total pending blobs sebelum reconciliation.
    pub total_pending: usize,

    /// Jumlah blob yang berhasil di-reconcile.
    pub reconciled: usize,

    /// Jumlah blob yang gagal.
    pub failed: usize,

    /// Jumlah blob yang di-skip.
    pub skipped: usize,

    /// Detail per-blob.
    pub details: Vec<BlobReconcileDetail>,

    /// Timestamp mulai (Unix seconds).
    pub started_at: u64,

    /// Timestamp selesai (Unix seconds).
    pub completed_at: u64,
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

    // ────────────────────────────────────────────────────────────────────────────
    // Reconcile Method (14A.1A.33)
    // ────────────────────────────────────────────────────────────────────────────

    /// Melakukan reconciliation batch dari pending blobs ke Celestia.
    ///
    /// ## Proses
    ///
    /// 1. Mengambil batch PendingBlob (max batch_size, urutan deterministik)
    /// 2. Untuk setiap blob:
    ///    - Validasi (tidak expired, retry_count <= max_retries)
    ///    - Post ke Celestia via post_blob()
    ///    - Verifikasi commitment
    ///    - Update state berdasarkan hasil
    /// 3. Mengembalikan ReconcileReport lengkap
    ///
    /// ## Thread Safety
    ///
    /// - Lock hanya dipegang saat membaca/menulis state
    /// - Lock TIDAK dipegang saat network call
    /// - Atomic updates untuk counters
    ///
    /// ## Errors
    ///
    /// Returns `Err(ReconcileError::NoPendingBlobs)` jika tidak ada blob untuk diproses.
    pub async fn reconcile(&self) -> Result<ReconcileReport, ReconcileError> {
        let started_at = current_unix_timestamp();
        let max_retries = self.config.max_retries;
        let batch_size = self.config.batch_size;

        // Step 1: Extract batch of blobs to process (with lock)
        // Filter out expired blobs and take at most batch_size
        let batch: Vec<(usize, PendingBlob)> = {
            let pending = self.pending_blobs.read();
            pending
                .iter()
                .enumerate()
                .filter(|(_, blob)| blob.retry_count < max_retries)
                .take(batch_size)
                .map(|(idx, blob)| (idx, blob.clone()))
                .collect()
        };

        let total_pending = self.get_pending_count();

        if batch.is_empty() {
            return Err(ReconcileError::NoPendingBlobs);
        }

        // Step 2: Process blobs (without lock)
        let results: Vec<(u64, BlobReconcileDetail, bool)> = if self.config.parallel_reconcile {
            // Parallel processing
            self.process_batch_parallel(&batch, max_retries).await
        } else {
            // Serial processing
            self.process_batch_serial(&batch, max_retries).await
        };

        // Step 3: Apply results to state (with lock)
        let mut reconciled = 0usize;
        let mut failed = 0usize;
        let mut skipped = 0usize;
        let mut details = Vec::with_capacity(results.len());

        // Collect sequences to remove and retry counts to update
        let mut sequences_to_remove: Vec<u64> = Vec::new();
        let mut sequences_to_increment_retry: Vec<u64> = Vec::new();
        let mut sequences_permanently_failed: Vec<u64> = Vec::new();

        for (sequence, detail, success) in results {
            match &detail.status {
                BlobReconcileStatus::Success => {
                    reconciled += 1;
                    sequences_to_remove.push(sequence);
                }
                BlobReconcileStatus::Failed(_) => {
                    failed += 1;
                    sequences_to_increment_retry.push(sequence);
                }
                BlobReconcileStatus::PermanentlyFailed(_) => {
                    failed += 1;
                    sequences_permanently_failed.push(sequence);
                }
                BlobReconcileStatus::Skipped(_) => {
                    skipped += 1;
                }
            }
            details.push(detail);
        }

        // Apply state changes (with lock)
        {
            let mut pending = self.pending_blobs.write();

            // Remove successfully reconciled blobs
            pending.retain(|blob| !sequences_to_remove.contains(&blob.original_sequence()));

            // Remove permanently failed blobs
            pending.retain(|blob| !sequences_permanently_failed.contains(&blob.original_sequence()));

            // Increment retry count for failed blobs
            for blob in pending.iter_mut() {
                if sequences_to_increment_retry.contains(&blob.original_sequence()) {
                    blob.retry_count = blob.retry_count.saturating_add(1);
                }
            }
        }

        // Step 4: Update metrics (atomic)
        if reconciled > 0 {
            self.reconciled_count.fetch_add(
                reconciled as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
        }
        if failed > 0 {
            self.failed_count.fetch_add(
                failed as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
        }

        let completed_at = current_unix_timestamp();
        self.last_reconcile.store(completed_at, std::sync::atomic::Ordering::Relaxed);

        Ok(ReconcileReport {
            total_pending,
            reconciled,
            failed,
            skipped,
            details,
            started_at,
            completed_at,
        })
    }

    /// Process batch serially (one by one).
    async fn process_batch_serial(
        &self,
        batch: &[(usize, PendingBlob)],
        max_retries: u32,
    ) -> Vec<(u64, BlobReconcileDetail, bool)> {
        let mut results = Vec::with_capacity(batch.len());

        for (_, blob) in batch {
            let result = self.process_single_blob(blob, max_retries).await;
            results.push(result);
        }

        results
    }

    /// Process batch in parallel.
    ///
    /// Uses futures::future::join_all for concurrent execution.
    async fn process_batch_parallel(
        &self,
        batch: &[(usize, PendingBlob)],
        max_retries: u32,
    ) -> Vec<(u64, BlobReconcileDetail, bool)> {
        use futures::future::join_all;

        let futs: Vec<_> = batch
            .iter()
            .map(|(_, blob)| self.process_single_blob(blob, max_retries))
            .collect();

        join_all(futs).await
    }

    /// Process a single blob.
    ///
    /// Returns (sequence, detail, success).
    async fn process_single_blob(
        &self,
        blob: &PendingBlob,
        max_retries: u32,
    ) -> (u64, BlobReconcileDetail, bool) {
        let sequence = blob.original_sequence();
        let current_retry = blob.retry_count;

        // Check if already expired (shouldn't happen but be defensive)
        if current_retry >= max_retries {
            return (
                sequence,
                BlobReconcileDetail {
                    original_sequence: sequence,
                    status: BlobReconcileStatus::Skipped("Already expired".to_string()),
                    celestia_commitment: None,
                    celestia_height: None,
                    retry_count: current_retry,
                },
                false,
            );
        }

        // Post blob to Celestia
        let post_result = self.celestia.post_blob(&blob.data).await;

        match post_result {
            Ok(celestia_ref) => {
                // Verify commitment matches (if original has commitment)
                // Note: blob.blob_ref.commitment is the original commitment from QuorumDA
                // celestia_ref.commitment is the new commitment from Celestia
                // In practice, same data should produce same commitment
                // But we compare anyway for integrity check
                
                let commitment_matches = blob.blob_ref.commitment == celestia_ref.commitment;

                if commitment_matches {
                    (
                        sequence,
                        BlobReconcileDetail {
                            original_sequence: sequence,
                            status: BlobReconcileStatus::Success,
                            celestia_commitment: Some(celestia_ref.commitment),
                            celestia_height: Some(celestia_ref.height),
                            retry_count: current_retry,
                        },
                        true,
                    )
                } else {
                    // Commitment mismatch - this is a serious error
                    // Mark as failed, will retry
                    let new_retry = current_retry.saturating_add(1);
                    let status = if new_retry >= max_retries {
                        BlobReconcileStatus::PermanentlyFailed(
                            "Commitment mismatch after max retries".to_string(),
                        )
                    } else {
                        BlobReconcileStatus::Failed("Commitment mismatch".to_string())
                    };

                    (
                        sequence,
                        BlobReconcileDetail {
                            original_sequence: sequence,
                            status,
                            celestia_commitment: Some(celestia_ref.commitment),
                            celestia_height: Some(celestia_ref.height),
                            retry_count: new_retry,
                        },
                        false,
                    )
                }
            }
            Err(e) => {
                // Post failed
                let new_retry = current_retry.saturating_add(1);
                let error_msg = e.to_string();
                let status = if new_retry >= max_retries {
                    BlobReconcileStatus::PermanentlyFailed(format!(
                        "Post failed after max retries: {}",
                        error_msg
                    ))
                } else {
                    BlobReconcileStatus::Failed(format!("Post failed: {}", error_msg))
                };

                (
                    sequence,
                    BlobReconcileDetail {
                        original_sequence: sequence,
                        status,
                        celestia_commitment: None,
                        celestia_height: None,
                        retry_count: new_retry,
                    },
                    false,
                )
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════════

/// Get current Unix timestamp in seconds.
///
/// Returns 0 if system time is before Unix epoch (should never happen).
fn current_unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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

    // ────────────────────────────────────────────────────────────────────────────
    // Tests for 14A.1A.33 - Reconcile Method
    // ────────────────────────────────────────────────────────────────────────────

    /// Mock DA layer that always fails
    struct FailingDALayer;

    impl DALayer for FailingDALayer {
        fn post_blob(
            &self,
            _data: &[u8],
        ) -> Pin<Box<dyn Future<Output = Result<dsdn_common::BlobRef, dsdn_common::DAError>> + Send + '_>> {
            Box::pin(async move {
                Err(dsdn_common::DAError::NetworkError("Connection refused".to_string()))
            })
        }

        fn get_blob(
            &self,
            _ref_: &dsdn_common::BlobRef,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, dsdn_common::DAError>> + Send + '_>> {
            Box::pin(async move {
                Err(dsdn_common::DAError::Other("not implemented".to_string()))
            })
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
            Box::pin(async move { Ok(dsdn_common::DAHealthStatus::Unavailable) })
        }
    }

    /// Mock DA layer that returns matching commitment
    struct MatchingCommitmentDALayer;

    impl DALayer for MatchingCommitmentDALayer {
        fn post_blob(
            &self,
            data: &[u8],
        ) -> Pin<Box<dyn Future<Output = Result<dsdn_common::BlobRef, dsdn_common::DAError>> + Send + '_>> {
            // Return commitment that matches the blob's height (used as commitment in make_test_blob)
            let height = if data.is_empty() { 0 } else { data[0] as u64 };
            let commitment = [height as u8; 32];
            Box::pin(async move {
                Ok(dsdn_common::BlobRef {
                    height: 1000 + height,
                    commitment,
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

    #[tokio::test]
    async fn test_reconcile_no_pending() {
        let config = ReconciliationConfig::default();
        let celestia: Arc<dyn DALayer> = Arc::new(MockDALayer);
        let engine = ReconciliationEngine::new(config, celestia);

        let result = engine.reconcile().await;
        assert!(result.is_err());
        match result {
            Err(ReconcileError::NoPendingBlobs) => {}
            _ => panic!("Expected NoPendingBlobs error"),
        }
    }

    #[tokio::test]
    async fn test_reconcile_all_success() {
        let config = ReconciliationConfig::default();
        let celestia: Arc<dyn DALayer> = Arc::new(MatchingCommitmentDALayer);
        let engine = ReconciliationEngine::new(config, celestia);

        // Add blobs with matching commitments
        // make_test_blob uses [height as u8; 32] as commitment
        // MatchingCommitmentDALayer returns commitment based on first byte of data
        // So we need data[0] == height for commitment match
        engine.add_pending(PendingBlob {
            blob_ref: dsdn_common::BlobRef {
                height: 1,
                commitment: [1u8; 32],
                namespace: [0u8; 29],
            },
            data: vec![1],
            added_at: 1700000000,
            retry_count: 0,
        });
        engine.add_pending(PendingBlob {
            blob_ref: dsdn_common::BlobRef {
                height: 2,
                commitment: [2u8; 32],
                namespace: [0u8; 29],
            },
            data: vec![2],
            added_at: 1700000000,
            retry_count: 0,
        });

        assert_eq!(engine.get_pending_count(), 2);

        let report = engine.reconcile().await.expect("reconcile should succeed");

        assert_eq!(report.total_pending, 2);
        assert_eq!(report.reconciled, 2);
        assert_eq!(report.failed, 0);
        assert_eq!(report.skipped, 0);
        assert_eq!(report.details.len(), 2);

        // Verify blobs removed
        assert_eq!(engine.get_pending_count(), 0);

        // Verify counters
        assert_eq!(engine.reconciled_count(), 2);
        assert_eq!(engine.failed_count(), 0);
        assert!(engine.last_reconcile() > 0);
    }

    #[tokio::test]
    async fn test_reconcile_all_fail() {
        let config = ReconciliationConfig::default(); // max_retries = 3
        let celestia: Arc<dyn DALayer> = Arc::new(FailingDALayer);
        let engine = ReconciliationEngine::new(config, celestia);

        engine.add_pending(make_test_blob(1, vec![1], 0));
        engine.add_pending(make_test_blob(2, vec![2], 0));

        let report = engine.reconcile().await.expect("reconcile should return report");

        assert_eq!(report.total_pending, 2);
        assert_eq!(report.reconciled, 0);
        assert_eq!(report.failed, 2);
        assert_eq!(report.skipped, 0);

        // Blobs should still be pending (retry_count incremented)
        assert_eq!(engine.get_pending_count(), 2);

        // Verify retry counts incremented
        let list = engine.list_pending();
        assert_eq!(list[0].retry_count, 1);
        assert_eq!(list[1].retry_count, 1);

        // Verify counters
        assert_eq!(engine.reconciled_count(), 0);
        assert_eq!(engine.failed_count(), 2);
    }

    #[tokio::test]
    async fn test_reconcile_retry_exhaustion() {
        let config = ReconciliationConfig {
            batch_size: 10,
            retry_delay_ms: 1000,
            max_retries: 2,
            parallel_reconcile: false,
        };
        let celestia: Arc<dyn DALayer> = Arc::new(FailingDALayer);
        let engine = ReconciliationEngine::new(config, celestia);

        // Add blob that's already at retry_count = 1 (one more failure will reach max_retries)
        engine.add_pending(make_test_blob(1, vec![1], 1));

        let report = engine.reconcile().await.expect("reconcile should return report");

        // Should be permanently failed (retry_count would become 2 == max_retries)
        assert_eq!(report.reconciled, 0);
        assert_eq!(report.failed, 1);

        // Verify status
        assert!(matches!(
            report.details[0].status,
            BlobReconcileStatus::PermanentlyFailed(_)
        ));

        // Permanently failed blob should be removed
        assert_eq!(engine.get_pending_count(), 0);
    }

    #[tokio::test]
    async fn test_reconcile_partial_success() {
        // Use MockDALayer which returns [0u8; 32] commitment
        let config = ReconciliationConfig::default();
        let celestia: Arc<dyn DALayer> = Arc::new(MockDALayer);
        let engine = ReconciliationEngine::new(config, celestia);

        // Blob 1: commitment [0u8; 32] will match MockDALayer's return
        engine.add_pending(PendingBlob {
            blob_ref: dsdn_common::BlobRef {
                height: 1,
                commitment: [0u8; 32], // matches MockDALayer
                namespace: [0u8; 29],
            },
            data: vec![1, 2, 3],
            added_at: 1700000000,
            retry_count: 0,
        });

        // Blob 2: commitment [1u8; 32] will NOT match MockDALayer's return
        engine.add_pending(PendingBlob {
            blob_ref: dsdn_common::BlobRef {
                height: 2,
                commitment: [1u8; 32], // does not match MockDALayer
                namespace: [0u8; 29],
            },
            data: vec![4, 5, 6],
            added_at: 1700000000,
            retry_count: 0,
        });

        assert_eq!(engine.get_pending_count(), 2);

        let report = engine.reconcile().await.expect("reconcile should return report");

        // One success, one fail (commitment mismatch)
        assert_eq!(report.reconciled, 1);
        assert_eq!(report.failed, 1);

        // First blob (success) should be removed
        // Second blob (failed) should still be pending with retry_count = 1
        assert_eq!(engine.get_pending_count(), 1);
        let list = engine.list_pending();
        assert_eq!(list[0].original_sequence, 2);
        assert_eq!(list[0].retry_count, 1);
    }

    #[tokio::test]
    async fn test_reconcile_skips_expired() {
        let config = ReconciliationConfig {
            batch_size: 10,
            retry_delay_ms: 1000,
            max_retries: 3,
            parallel_reconcile: false,
        };
        let celestia: Arc<dyn DALayer> = Arc::new(MatchingCommitmentDALayer);
        let engine = ReconciliationEngine::new(config, celestia);

        // Add one valid blob
        engine.add_pending(PendingBlob {
            blob_ref: dsdn_common::BlobRef {
                height: 1,
                commitment: [1u8; 32],
                namespace: [0u8; 29],
            },
            data: vec![1],
            added_at: 1700000000,
            retry_count: 0,
        });

        // Add one expired blob (retry_count >= max_retries)
        engine.add_pending(PendingBlob {
            blob_ref: dsdn_common::BlobRef {
                height: 2,
                commitment: [2u8; 32],
                namespace: [0u8; 29],
            },
            data: vec![2],
            added_at: 1700000000,
            retry_count: 5, // expired
        });

        assert_eq!(engine.get_pending_count(), 2);

        let report = engine.reconcile().await.expect("reconcile should return report");

        // Only non-expired blob should be processed
        assert_eq!(report.reconciled, 1);
        assert_eq!(report.failed, 0);
        assert_eq!(report.skipped, 0); // expired ones are filtered, not skipped
        assert_eq!(report.details.len(), 1);

        // Only expired blob should remain (valid one removed)
        assert_eq!(engine.get_pending_count(), 1);
    }

    #[tokio::test]
    async fn test_reconcile_batch_size() {
        let config = ReconciliationConfig {
            batch_size: 2, // Only process 2 at a time
            retry_delay_ms: 1000,
            max_retries: 3,
            parallel_reconcile: false,
        };
        let celestia: Arc<dyn DALayer> = Arc::new(MatchingCommitmentDALayer);
        let engine = ReconciliationEngine::new(config, celestia);

        // Add 5 blobs
        for i in 1..=5 {
            engine.add_pending(PendingBlob {
                blob_ref: dsdn_common::BlobRef {
                    height: i,
                    commitment: [i as u8; 32],
                    namespace: [0u8; 29],
                },
                data: vec![i as u8],
                added_at: 1700000000,
                retry_count: 0,
            });
        }

        assert_eq!(engine.get_pending_count(), 5);

        let report = engine.reconcile().await.expect("reconcile should return report");

        // Only 2 should be processed (batch_size = 2)
        assert_eq!(report.total_pending, 5);
        assert_eq!(report.reconciled, 2);
        assert_eq!(report.details.len(), 2);

        // 3 blobs should remain
        assert_eq!(engine.get_pending_count(), 3);
    }

    #[tokio::test]
    async fn test_reconcile_parallel() {
        let config = ReconciliationConfig {
            batch_size: 10,
            retry_delay_ms: 1000,
            max_retries: 3,
            parallel_reconcile: true, // Enable parallel
        };
        let celestia: Arc<dyn DALayer> = Arc::new(MatchingCommitmentDALayer);
        let engine = ReconciliationEngine::new(config, celestia);

        // Add multiple blobs
        for i in 1..=3 {
            engine.add_pending(PendingBlob {
                blob_ref: dsdn_common::BlobRef {
                    height: i,
                    commitment: [i as u8; 32],
                    namespace: [0u8; 29],
                },
                data: vec![i as u8],
                added_at: 1700000000,
                retry_count: 0,
            });
        }

        let report = engine.reconcile().await.expect("reconcile should return report");

        // All should succeed
        assert_eq!(report.reconciled, 3);
        assert_eq!(engine.get_pending_count(), 0);
    }

    #[test]
    fn test_reconcile_error_display() {
        let e1 = ReconcileError::NoPendingBlobs;
        assert_eq!(e1.to_string(), "No pending blobs to reconcile");

        let e2 = ReconcileError::DAUnavailable("test".to_string());
        assert!(e2.to_string().contains("DA layer unavailable"));

        let e3 = ReconcileError::Internal("err".to_string());
        assert!(e3.to_string().contains("Internal error"));
    }

    #[test]
    fn test_blob_reconcile_status_variants() {
        let s1 = BlobReconcileStatus::Success;
        let s2 = BlobReconcileStatus::Failed("err".to_string());
        let s3 = BlobReconcileStatus::PermanentlyFailed("max retries".to_string());
        let s4 = BlobReconcileStatus::Skipped("expired".to_string());

        // Just verify they exist and can be matched
        assert!(matches!(s1, BlobReconcileStatus::Success));
        assert!(matches!(s2, BlobReconcileStatus::Failed(_)));
        assert!(matches!(s3, BlobReconcileStatus::PermanentlyFailed(_)));
        assert!(matches!(s4, BlobReconcileStatus::Skipped(_)));
    }
}