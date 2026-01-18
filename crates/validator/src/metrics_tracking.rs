//! QuorumMetrics - Metrics Tracking for QuorumDA (14A.1A.29)
//!
//! Menyediakan metrics tracking yang:
//! - Deterministik
//! - Thread-safe (semua operasi atomic)
//! - Bebas race condition
//! - Bebas panic/unwrap
//! - Dapat diekspor ke Prometheus format
//!
//! ## Metrics Fields
//!
//! | Field | Deskripsi |
//! |-------|-----------|
//! | blobs_stored | Jumlah blob yang berhasil disimpan ke storage |
//! | blobs_retrieved | Jumlah blob yang berhasil diambil dari storage |
//! | signature_collections | Total operasi pengumpulan signature |
//! | signature_failures | Jumlah kegagalan pengumpulan signature |
//! | quorum_successes | Jumlah quorum yang berhasil tercapai |
//! | quorum_failures | Jumlah quorum yang gagal tercapai |
//! | avg_collection_time_ms | Rata-rata waktu pengumpulan signature (EMA) |
//! | validators_healthy | Jumlah validator yang healthy saat ini |
//!
//! ## Algoritma avg_collection_time_ms
//!
//! Menggunakan Exponential Moving Average (EMA) dengan formula:
//! ```text
//! new_avg = (7 * old_avg + new_value) / 8
//! ```
//!
//! Ini setara dengan α = 0.125 (1/8), memberikan:
//! - 87.5% weight ke historical average
//! - 12.5% weight ke nilai baru
//!
//! Rasionale: Menggunakan pembagian power-of-2 untuk efisiensi
//! dan menghindari floating point.
//!
//! ## Thread Safety
//!
//! Semua field menggunakan AtomicU64 dengan Ordering::Relaxed untuk
//! counter sederhana dan compare_exchange untuk operasi kompleks
//! seperti update EMA.
//!
//! ## Hubungan dengan QuorumDA Lifecycle
//!
//! ```text
//! post_blob() ─┬─> signature_collections++
//!              ├─> record_collection(duration, success)
//!              │   ├─> quorum_successes++ (if success)
//!              │   └─> quorum_failures++ (if !success)
//!              └─> blobs_stored++ (if success)
//!
//! get_blob() ──> blobs_retrieved++
//!
//! health_check() ──> validators_healthy = count
//! ```

use std::sync::atomic::{AtomicU64, Ordering};

// ════════════════════════════════════════════════════════════════════════════════
// QUORUM METRICS STRUCT
// ════════════════════════════════════════════════════════════════════════════════

/// Metrics tracking untuk operasi QuorumDA.
///
/// Semua field menggunakan AtomicU64 untuk thread-safety.
/// Update metrics tidak mempengaruhi logic utama QuorumDA.
///
/// ## Prometheus Export
///
/// Gunakan `to_prometheus()` untuk mengekspor metrics dalam format
/// Prometheus text exposition.
#[derive(Debug, Default)]
pub struct QuorumMetrics {
    /// Jumlah blob yang berhasil disimpan ke storage.
    blobs_stored: AtomicU64,

    /// Jumlah blob yang berhasil diambil dari storage.
    blobs_retrieved: AtomicU64,

    /// Total operasi pengumpulan signature yang dilakukan.
    signature_collections: AtomicU64,

    /// Jumlah kegagalan pengumpulan signature.
    signature_failures: AtomicU64,

    /// Jumlah quorum yang berhasil tercapai.
    quorum_successes: AtomicU64,

    /// Jumlah quorum yang gagal tercapai.
    quorum_failures: AtomicU64,

    /// Rata-rata waktu pengumpulan signature dalam milidetik.
    ///
    /// Dihitung menggunakan Exponential Moving Average (EMA):
    /// `new_avg = (7 * old_avg + new_value) / 8`
    avg_collection_time_ms: AtomicU64,

    /// Jumlah validator yang healthy saat ini.
    validators_healthy: AtomicU64,
}

impl QuorumMetrics {
    /// Membuat instance baru dengan semua counter di 0.
    #[must_use]
    pub fn new() -> Self {
        Self {
            blobs_stored: AtomicU64::new(0),
            blobs_retrieved: AtomicU64::new(0),
            signature_collections: AtomicU64::new(0),
            signature_failures: AtomicU64::new(0),
            quorum_successes: AtomicU64::new(0),
            quorum_failures: AtomicU64::new(0),
            avg_collection_time_ms: AtomicU64::new(0),
            validators_healthy: AtomicU64::new(0),
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // RECORD METHODS
    // ════════════════════════════════════════════════════════════════════════════

    /// Record hasil pengumpulan signature.
    ///
    /// ## Parameters
    ///
    /// - `duration_ms`: Waktu yang dibutuhkan untuk collection (milidetik)
    /// - `success`: true jika quorum tercapai, false jika gagal
    ///
    /// ## Behavior
    ///
    /// 1. Increment `signature_collections`
    /// 2. Update `avg_collection_time_ms` menggunakan EMA
    /// 3. Increment `quorum_successes` ATAU `quorum_failures`
    ///
    /// ## Thread Safety
    ///
    /// Semua operasi atomic. Aman dipanggil dari multiple threads.
    ///
    /// ## Overflow Handling
    ///
    /// Menggunakan saturating_add untuk mencegah overflow silent.
    pub fn record_collection(&self, duration_ms: u64, success: bool) {
        // 1. Increment signature_collections (saturating to prevent overflow)
        let _ = self.signature_collections.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |v| Some(v.saturating_add(1)),
        );

        // 2. Update avg_collection_time_ms menggunakan EMA
        // Formula: new_avg = (7 * old_avg + new_value) / 8
        // Ini setara dengan α = 0.125
        loop {
            let old_avg = self.avg_collection_time_ms.load(Ordering::Relaxed);

            // Handle case pertama (avg = 0)
            let new_avg = if old_avg == 0 {
                duration_ms
            } else {
                // EMA: (7 * old + new) / 8
                // Menggunakan saturating operations untuk keamanan
                let weighted_old = old_avg.saturating_mul(7);
                let sum = weighted_old.saturating_add(duration_ms);
                sum / 8
            };

            // Atomic compare-and-swap
            match self.avg_collection_time_ms.compare_exchange_weak(
                old_avg,
                new_avg,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(_) => continue, // Retry jika ada concurrent update
            }
        }

        // 3. Increment quorum_successes atau quorum_failures
        if success {
            let _ = self.quorum_successes.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |v| Some(v.saturating_add(1)),
            );
        } else {
            let _ = self.quorum_failures.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |v| Some(v.saturating_add(1)),
            );
            // Also increment signature_failures for failed collections
            let _ = self.signature_failures.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |v| Some(v.saturating_add(1)),
            );
        }
    }

    /// Record blob stored.
    pub fn record_blob_stored(&self) {
        let _ = self.blobs_stored.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |v| Some(v.saturating_add(1)),
        );
    }

    /// Record blob retrieved.
    pub fn record_blob_retrieved(&self) {
        let _ = self.blobs_retrieved.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |v| Some(v.saturating_add(1)),
        );
    }

    /// Set validators healthy count.
    pub fn set_validators_healthy(&self, count: u64) {
        self.validators_healthy.store(count, Ordering::Relaxed);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // GETTER METHODS
    // ════════════════════════════════════════════════════════════════════════════

    /// Get blobs_stored count.
    #[must_use]
    pub fn get_blobs_stored(&self) -> u64 {
        self.blobs_stored.load(Ordering::Relaxed)
    }

    /// Get blobs_retrieved count.
    #[must_use]
    pub fn get_blobs_retrieved(&self) -> u64 {
        self.blobs_retrieved.load(Ordering::Relaxed)
    }

    /// Get signature_collections count.
    #[must_use]
    pub fn get_signature_collections(&self) -> u64 {
        self.signature_collections.load(Ordering::Relaxed)
    }

    /// Get signature_failures count.
    #[must_use]
    pub fn get_signature_failures(&self) -> u64 {
        self.signature_failures.load(Ordering::Relaxed)
    }

    /// Get quorum_successes count.
    #[must_use]
    pub fn get_quorum_successes(&self) -> u64 {
        self.quorum_successes.load(Ordering::Relaxed)
    }

    /// Get quorum_failures count.
    #[must_use]
    pub fn get_quorum_failures(&self) -> u64 {
        self.quorum_failures.load(Ordering::Relaxed)
    }

    /// Get avg_collection_time_ms.
    #[must_use]
    pub fn get_avg_collection_time_ms(&self) -> u64 {
        self.avg_collection_time_ms.load(Ordering::Relaxed)
    }

    /// Get validators_healthy count.
    #[must_use]
    pub fn get_validators_healthy(&self) -> u64 {
        self.validators_healthy.load(Ordering::Relaxed)
    }

    // ════════════════════════════════════════════════════════════════════════════
    // PROMETHEUS EXPORT
    // ════════════════════════════════════════════════════════════════════════════

    /// Export metrics ke format Prometheus text exposition.
    ///
    /// ## Output Format
    ///
    /// ```text
    /// # HELP dsdn_quorum_avg_collection_time_ms Average signature collection time in milliseconds (EMA)
    /// # TYPE dsdn_quorum_avg_collection_time_ms gauge
    /// dsdn_quorum_avg_collection_time_ms 100
    /// # HELP dsdn_quorum_blobs_retrieved_total Total blobs retrieved from storage
    /// # TYPE dsdn_quorum_blobs_retrieved_total counter
    /// dsdn_quorum_blobs_retrieved_total 50
    /// ...
    /// ```
    ///
    /// ## Guarantees
    ///
    /// - Output deterministik (sorted alphabetically by metric name)
    /// - Satu metric per baris
    /// - Format Prometheus VALID
    /// - Tidak ada state mutation
    #[must_use]
    pub fn to_prometheus(&self) -> String {
        // Read all values atomically (snapshot)
        let avg_collection_time_ms = self.avg_collection_time_ms.load(Ordering::Relaxed);
        let blobs_retrieved = self.blobs_retrieved.load(Ordering::Relaxed);
        let blobs_stored = self.blobs_stored.load(Ordering::Relaxed);
        let quorum_failures = self.quorum_failures.load(Ordering::Relaxed);
        let quorum_successes = self.quorum_successes.load(Ordering::Relaxed);
        let signature_collections = self.signature_collections.load(Ordering::Relaxed);
        let signature_failures = self.signature_failures.load(Ordering::Relaxed);
        let validators_healthy = self.validators_healthy.load(Ordering::Relaxed);

        // Build output in sorted order (alphabetical by metric name)
        // Using format! to avoid allocation complexity
        let mut output = String::with_capacity(2048);

        // 1. avg_collection_time_ms (gauge)
        output.push_str("# HELP dsdn_quorum_avg_collection_time_ms Average signature collection time in milliseconds (EMA alpha=0.125)\n");
        output.push_str("# TYPE dsdn_quorum_avg_collection_time_ms gauge\n");
        output.push_str(&format!("dsdn_quorum_avg_collection_time_ms {}\n", avg_collection_time_ms));

        // 2. blobs_retrieved_total (counter)
        output.push_str("# HELP dsdn_quorum_blobs_retrieved_total Total blobs retrieved from storage\n");
        output.push_str("# TYPE dsdn_quorum_blobs_retrieved_total counter\n");
        output.push_str(&format!("dsdn_quorum_blobs_retrieved_total {}\n", blobs_retrieved));

        // 3. blobs_stored_total (counter)
        output.push_str("# HELP dsdn_quorum_blobs_stored_total Total blobs stored to storage\n");
        output.push_str("# TYPE dsdn_quorum_blobs_stored_total counter\n");
        output.push_str(&format!("dsdn_quorum_blobs_stored_total {}\n", blobs_stored));

        // 4. failures_total (counter)
        output.push_str("# HELP dsdn_quorum_failures_total Total quorum collection failures\n");
        output.push_str("# TYPE dsdn_quorum_failures_total counter\n");
        output.push_str(&format!("dsdn_quorum_failures_total {}\n", quorum_failures));

        // 5. signature_collections_total (counter)
        output.push_str("# HELP dsdn_quorum_signature_collections_total Total signature collection operations\n");
        output.push_str("# TYPE dsdn_quorum_signature_collections_total counter\n");
        output.push_str(&format!("dsdn_quorum_signature_collections_total {}\n", signature_collections));

        // 6. signature_failures_total (counter)
        output.push_str("# HELP dsdn_quorum_signature_failures_total Total signature collection failures\n");
        output.push_str("# TYPE dsdn_quorum_signature_failures_total counter\n");
        output.push_str(&format!("dsdn_quorum_signature_failures_total {}\n", signature_failures));

        // 7. successes_total (counter)
        output.push_str("# HELP dsdn_quorum_successes_total Total successful quorum collections\n");
        output.push_str("# TYPE dsdn_quorum_successes_total counter\n");
        output.push_str(&format!("dsdn_quorum_successes_total {}\n", quorum_successes));

        // 8. validators_healthy (gauge)
        output.push_str("# HELP dsdn_quorum_validators_healthy Number of healthy validators\n");
        output.push_str("# TYPE dsdn_quorum_validators_healthy gauge\n");
        output.push_str(&format!("dsdn_quorum_validators_healthy {}\n", validators_healthy));

        output
    }

    /// Reset semua metrics ke 0.
    ///
    /// Berguna untuk testing atau periodic reset.
    pub fn reset(&self) {
        self.blobs_stored.store(0, Ordering::Relaxed);
        self.blobs_retrieved.store(0, Ordering::Relaxed);
        self.signature_collections.store(0, Ordering::Relaxed);
        self.signature_failures.store(0, Ordering::Relaxed);
        self.quorum_successes.store(0, Ordering::Relaxed);
        self.quorum_failures.store(0, Ordering::Relaxed);
        self.avg_collection_time_ms.store(0, Ordering::Relaxed);
        self.validators_healthy.store(0, Ordering::Relaxed);
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quorum_metrics_new() {
        let metrics = QuorumMetrics::new();
        assert_eq!(metrics.get_blobs_stored(), 0);
        assert_eq!(metrics.get_blobs_retrieved(), 0);
        assert_eq!(metrics.get_signature_collections(), 0);
        assert_eq!(metrics.get_signature_failures(), 0);
        assert_eq!(metrics.get_quorum_successes(), 0);
        assert_eq!(metrics.get_quorum_failures(), 0);
        assert_eq!(metrics.get_avg_collection_time_ms(), 0);
        assert_eq!(metrics.get_validators_healthy(), 0);
    }

    #[test]
    fn test_record_collection_success() {
        let metrics = QuorumMetrics::new();

        // Record successful collection
        metrics.record_collection(100, true);

        assert_eq!(metrics.get_signature_collections(), 1);
        assert_eq!(metrics.get_quorum_successes(), 1);
        assert_eq!(metrics.get_quorum_failures(), 0);
        assert_eq!(metrics.get_signature_failures(), 0);
        assert_eq!(metrics.get_avg_collection_time_ms(), 100);
    }

    #[test]
    fn test_record_collection_failure() {
        let metrics = QuorumMetrics::new();

        // Record failed collection
        metrics.record_collection(200, false);

        assert_eq!(metrics.get_signature_collections(), 1);
        assert_eq!(metrics.get_quorum_successes(), 0);
        assert_eq!(metrics.get_quorum_failures(), 1);
        assert_eq!(metrics.get_signature_failures(), 1);
        assert_eq!(metrics.get_avg_collection_time_ms(), 200);
    }

    #[test]
    fn test_record_collection_multiple() {
        let metrics = QuorumMetrics::new();

        // Record multiple collections
        metrics.record_collection(100, true);
        metrics.record_collection(200, true);
        metrics.record_collection(300, false);

        assert_eq!(metrics.get_signature_collections(), 3);
        assert_eq!(metrics.get_quorum_successes(), 2);
        assert_eq!(metrics.get_quorum_failures(), 1);
        assert_eq!(metrics.get_signature_failures(), 1);
    }

    #[test]
    fn test_avg_collection_time_ema() {
        let metrics = QuorumMetrics::new();

        // First value: avg = 100
        metrics.record_collection(100, true);
        assert_eq!(metrics.get_avg_collection_time_ms(), 100);

        // Second value: avg = (7*100 + 200) / 8 = 900 / 8 = 112
        metrics.record_collection(200, true);
        assert_eq!(metrics.get_avg_collection_time_ms(), 112);

        // Third value: avg = (7*112 + 100) / 8 = 884 / 8 = 110
        metrics.record_collection(100, true);
        assert_eq!(metrics.get_avg_collection_time_ms(), 110);
    }

    #[test]
    fn test_record_blob_stored() {
        let metrics = QuorumMetrics::new();

        metrics.record_blob_stored();
        metrics.record_blob_stored();
        metrics.record_blob_stored();

        assert_eq!(metrics.get_blobs_stored(), 3);
    }

    #[test]
    fn test_record_blob_retrieved() {
        let metrics = QuorumMetrics::new();

        metrics.record_blob_retrieved();
        metrics.record_blob_retrieved();

        assert_eq!(metrics.get_blobs_retrieved(), 2);
    }

    #[test]
    fn test_set_validators_healthy() {
        let metrics = QuorumMetrics::new();

        metrics.set_validators_healthy(5);
        assert_eq!(metrics.get_validators_healthy(), 5);

        metrics.set_validators_healthy(3);
        assert_eq!(metrics.get_validators_healthy(), 3);
    }

    #[test]
    fn test_to_prometheus_format() {
        let metrics = QuorumMetrics::new();

        // Set some values
        metrics.record_collection(100, true);
        metrics.record_blob_stored();
        metrics.record_blob_retrieved();
        metrics.set_validators_healthy(5);

        let output = metrics.to_prometheus();

        // Verify format
        assert!(output.contains("# HELP dsdn_quorum_avg_collection_time_ms"));
        assert!(output.contains("# TYPE dsdn_quorum_avg_collection_time_ms gauge"));
        assert!(output.contains("dsdn_quorum_avg_collection_time_ms 100"));

        assert!(output.contains("# HELP dsdn_quorum_blobs_stored_total"));
        assert!(output.contains("# TYPE dsdn_quorum_blobs_stored_total counter"));
        assert!(output.contains("dsdn_quorum_blobs_stored_total 1"));

        assert!(output.contains("# HELP dsdn_quorum_blobs_retrieved_total"));
        assert!(output.contains("dsdn_quorum_blobs_retrieved_total 1"));

        assert!(output.contains("dsdn_quorum_successes_total 1"));
        assert!(output.contains("dsdn_quorum_validators_healthy 5"));
    }

    #[test]
    fn test_to_prometheus_deterministic() {
        let metrics = QuorumMetrics::new();
        metrics.record_collection(50, true);

        // Call multiple times, output should be identical
        let output1 = metrics.to_prometheus();
        let output2 = metrics.to_prometheus();
        let output3 = metrics.to_prometheus();

        assert_eq!(output1, output2);
        assert_eq!(output2, output3);
    }

    #[test]
    fn test_to_prometheus_sorted_order() {
        let metrics = QuorumMetrics::new();
        let output = metrics.to_prometheus();

        // Verify metrics are in alphabetical order
        let lines: Vec<&str> = output
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .collect();

        // Metric names should be sorted
        let metric_names: Vec<&str> = lines
            .iter()
            .map(|l| l.split_whitespace().next().unwrap_or(""))
            .collect();

        let mut sorted_names = metric_names.clone();
        sorted_names.sort();

        assert_eq!(metric_names, sorted_names, "Metrics should be sorted alphabetically");
    }

    #[test]
    fn test_reset() {
        let metrics = QuorumMetrics::new();

        // Set some values
        metrics.record_collection(100, true);
        metrics.record_blob_stored();
        metrics.set_validators_healthy(5);

        // Verify non-zero
        assert!(metrics.get_signature_collections() > 0);

        // Reset
        metrics.reset();

        // Verify all zero
        assert_eq!(metrics.get_blobs_stored(), 0);
        assert_eq!(metrics.get_blobs_retrieved(), 0);
        assert_eq!(metrics.get_signature_collections(), 0);
        assert_eq!(metrics.get_signature_failures(), 0);
        assert_eq!(metrics.get_quorum_successes(), 0);
        assert_eq!(metrics.get_quorum_failures(), 0);
        assert_eq!(metrics.get_avg_collection_time_ms(), 0);
        assert_eq!(metrics.get_validators_healthy(), 0);
    }

    #[test]
    fn test_thread_safety_basic() {
        use std::sync::Arc;
        use std::thread;

        let metrics = Arc::new(QuorumMetrics::new());

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let m = Arc::clone(&metrics);
                thread::spawn(move || {
                    for _ in 0..100 {
                        m.record_collection(i * 10, i % 2 == 0);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("Thread panicked");
        }

        // 10 threads × 100 iterations = 1000 total collections
        assert_eq!(metrics.get_signature_collections(), 1000);

        // 5 threads with success (even i) × 100 = 500 successes
        assert_eq!(metrics.get_quorum_successes(), 500);

        // 5 threads with failure (odd i) × 100 = 500 failures
        assert_eq!(metrics.get_quorum_failures(), 500);
    }

    #[test]
    fn test_prometheus_all_fields_present() {
        let metrics = QuorumMetrics::new();
        let output = metrics.to_prometheus();

        // All 8 metric fields should be present
        assert!(output.contains("dsdn_quorum_avg_collection_time_ms"));
        assert!(output.contains("dsdn_quorum_blobs_retrieved_total"));
        assert!(output.contains("dsdn_quorum_blobs_stored_total"));
        assert!(output.contains("dsdn_quorum_failures_total"));
        assert!(output.contains("dsdn_quorum_successes_total"));
        assert!(output.contains("dsdn_quorum_signature_collections_total"));
        assert!(output.contains("dsdn_quorum_signature_failures_total"));
        assert!(output.contains("dsdn_quorum_validators_healthy"));
    }
}