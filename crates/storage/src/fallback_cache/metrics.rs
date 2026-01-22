//! Cache Metrics Module (14A.1A.54)
//!
//! Provides thread-safe, lock-free metrics for FallbackCache observability.
//!
//! ## Design Principles
//!
//! - All counters use AtomicU64 for lock-free operations
//! - No Mutex/RwLock - pure atomic operations
//! - Metrics do NOT affect cache behavior
//! - Saturating operations prevent underflow

use std::sync::atomic::{AtomicU64, Ordering};

// ════════════════════════════════════════════════════════════════════════════════
// CACHE METRICS
// ════════════════════════════════════════════════════════════════════════════════

/// Thread-safe metrics for FallbackCache.
///
/// All fields are AtomicU64 for lock-free concurrent access.
/// Operations use Relaxed ordering for counters (eventual consistency acceptable).
#[derive(Debug)]
pub struct CacheMetrics {
    /// Number of cache hits (successful get operations).
    hits: AtomicU64,
    /// Number of cache misses (get operations returning None).
    misses: AtomicU64,
    /// Number of successful store operations.
    stores: AtomicU64,
    /// Number of blobs evicted (due to limits or TTL).
    evictions: AtomicU64,
    /// Current number of entries in cache.
    current_entries: AtomicU64,
    /// Current total bytes in cache.
    current_bytes: AtomicU64,
    /// Number of entries reconciled from DA.
    reconciled_entries: AtomicU64,
}

impl CacheMetrics {
    /// Create new CacheMetrics with all counters at zero.
    ///
    /// Does not panic.
    #[must_use]
    pub fn new() -> Self {
        Self {
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            stores: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
            current_entries: AtomicU64::new(0),
            current_bytes: AtomicU64::new(0),
            reconciled_entries: AtomicU64::new(0),
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // RECORDING METHODS
    // ════════════════════════════════════════════════════════════════════════════

    /// Record a cache hit.
    ///
    /// Increments hits counter only.
    pub fn record_hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a cache miss.
    ///
    /// Increments misses counter only.
    pub fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a successful store operation.
    ///
    /// - Increments stores by 1
    /// - Increments current_entries by 1
    /// - Increments current_bytes by given bytes
    pub fn record_store(&self, bytes: u64) {
        self.stores.fetch_add(1, Ordering::Relaxed);
        self.current_entries.fetch_add(1, Ordering::Relaxed);
        self.current_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record eviction of blobs.
    ///
    /// - Increments evictions by count
    /// - Decrements current_entries by count (saturating to prevent underflow)
    ///
    /// ## Safety
    ///
    /// Uses saturating subtraction via CAS loop - current_entries will never go negative.
    pub fn record_eviction(&self, count: u64) {
        self.evictions.fetch_add(count, Ordering::Relaxed);

        // Saturating decrement for current_entries using CAS loop
        loop {
            let current = self.current_entries.load(Ordering::Relaxed);
            let new_value = current.saturating_sub(count);
            match self.current_entries.compare_exchange_weak(
                current,
                new_value,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(_) => continue,
            }
        }
    }

    /// Record removal of bytes from cache.
    ///
    /// Uses saturating subtraction via CAS loop to prevent underflow.
    pub fn record_bytes_removed(&self, bytes: u64) {
        loop {
            let current = self.current_bytes.load(Ordering::Relaxed);
            let new_value = current.saturating_sub(bytes);
            match self.current_bytes.compare_exchange_weak(
                current,
                new_value,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(_) => continue,
            }
        }
    }

    /// Record reconciliation of entries from DA.
    pub fn record_reconciliation(&self, count: u64) {
        self.reconciled_entries.fetch_add(count, Ordering::Relaxed);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // GETTERS
    // ════════════════════════════════════════════════════════════════════════════

    /// Get the current hits count.
    #[must_use]
    pub fn get_hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    /// Get the current misses count.
    #[must_use]
    pub fn get_misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }

    /// Get the current stores count.
    #[must_use]
    pub fn get_stores(&self) -> u64 {
        self.stores.load(Ordering::Relaxed)
    }

    /// Get the current evictions count.
    #[must_use]
    pub fn get_evictions(&self) -> u64 {
        self.evictions.load(Ordering::Relaxed)
    }

    /// Get the current number of entries.
    #[must_use]
    pub fn get_current_entries(&self) -> u64 {
        self.current_entries.load(Ordering::Relaxed)
    }

    /// Get the current bytes in cache.
    #[must_use]
    pub fn get_current_bytes(&self) -> u64 {
        self.current_bytes.load(Ordering::Relaxed)
    }

    /// Get the reconciled entries count.
    #[must_use]
    pub fn get_reconciled_entries(&self) -> u64 {
        self.reconciled_entries.load(Ordering::Relaxed)
    }

    // ════════════════════════════════════════════════════════════════════════════
    // COMPUTED METRICS
    // ════════════════════════════════════════════════════════════════════════════

    /// Calculate the cache hit rate.
    ///
    /// Returns hits / (hits + misses).
    /// Returns 0.0 if denominator is zero (no requests yet).
    /// Never returns NaN or panics.
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits.saturating_add(misses);

        if total == 0 {
            return 0.0;
        }

        (hits as f64) / (total as f64)
    }

    // ════════════════════════════════════════════════════════════════════════════
    // SNAPSHOT & EXPORT
    // ════════════════════════════════════════════════════════════════════════════

    /// Create a snapshot of current metrics.
    ///
    /// Returns a non-atomic copy of all metric values.
    /// The snapshot is logically consistent at the time of capture.
    #[must_use]
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            stores: self.stores.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            current_entries: self.current_entries.load(Ordering::Relaxed),
            current_bytes: self.current_bytes.load(Ordering::Relaxed),
            reconciled_entries: self.reconciled_entries.load(Ordering::Relaxed),
        }
    }

    /// Export metrics in Prometheus format.
    ///
    /// Each metric is on its own line with snake_case naming.
    /// Format follows Prometheus exposition format.
    ///
    /// Does not panic.
    #[must_use]
    pub fn to_prometheus(&self) -> String {
        let snapshot = self.snapshot();

        // Pre-allocate reasonable capacity
        let mut output = String::with_capacity(1024);

        // Hits
        output.push_str("# HELP fallback_cache_hits Total cache hits\n");
        output.push_str("# TYPE fallback_cache_hits counter\n");
        output.push_str("fallback_cache_hits ");
        output.push_str(&snapshot.hits.to_string());
        output.push('\n');

        // Misses
        output.push_str("# HELP fallback_cache_misses Total cache misses\n");
        output.push_str("# TYPE fallback_cache_misses counter\n");
        output.push_str("fallback_cache_misses ");
        output.push_str(&snapshot.misses.to_string());
        output.push('\n');

        // Stores
        output.push_str("# HELP fallback_cache_stores Total store operations\n");
        output.push_str("# TYPE fallback_cache_stores counter\n");
        output.push_str("fallback_cache_stores ");
        output.push_str(&snapshot.stores.to_string());
        output.push('\n');

        // Evictions
        output.push_str("# HELP fallback_cache_evictions Total evictions\n");
        output.push_str("# TYPE fallback_cache_evictions counter\n");
        output.push_str("fallback_cache_evictions ");
        output.push_str(&snapshot.evictions.to_string());
        output.push('\n');

        // Current entries (gauge)
        output.push_str("# HELP fallback_cache_current_entries Current entry count\n");
        output.push_str("# TYPE fallback_cache_current_entries gauge\n");
        output.push_str("fallback_cache_current_entries ");
        output.push_str(&snapshot.current_entries.to_string());
        output.push('\n');

        // Current bytes (gauge)
        output.push_str("# HELP fallback_cache_current_bytes Current bytes in cache\n");
        output.push_str("# TYPE fallback_cache_current_bytes gauge\n");
        output.push_str("fallback_cache_current_bytes ");
        output.push_str(&snapshot.current_bytes.to_string());
        output.push('\n');

        // Reconciled entries
        output.push_str("# HELP fallback_cache_reconciled_entries Total reconciled entries\n");
        output.push_str("# TYPE fallback_cache_reconciled_entries counter\n");
        output.push_str("fallback_cache_reconciled_entries ");
        output.push_str(&snapshot.reconciled_entries.to_string());
        output.push('\n');

        // Hit rate (gauge, computed)
        let hit_rate = snapshot.hit_rate();
        output.push_str("# HELP fallback_cache_hit_rate Cache hit rate (0.0-1.0)\n");
        output.push_str("# TYPE fallback_cache_hit_rate gauge\n");
        output.push_str("fallback_cache_hit_rate ");
        // Format with 6 decimal places
        let rate_str = format!("{:.6}", hit_rate);
        output.push_str(&rate_str);
        output.push('\n');

        output
    }
}

impl Default for CacheMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// METRICS SNAPSHOT
// ════════════════════════════════════════════════════════════════════════════════

/// Non-atomic snapshot of cache metrics.
///
/// Plain data struct with no references to CacheMetrics.
/// Safe to store, serialize, or pass across threads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricsSnapshot {
    /// Number of cache hits.
    pub hits: u64,
    /// Number of cache misses.
    pub misses: u64,
    /// Number of store operations.
    pub stores: u64,
    /// Number of evictions.
    pub evictions: u64,
    /// Current entry count.
    pub current_entries: u64,
    /// Current bytes in cache.
    pub current_bytes: u64,
    /// Reconciled entries count.
    pub reconciled_entries: u64,
}

impl MetricsSnapshot {
    /// Calculate hit rate from snapshot values.
    ///
    /// Returns 0.0 if no requests have been made.
    /// Never returns NaN.
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits.saturating_add(self.misses);
        if total == 0 {
            return 0.0;
        }
        (self.hits as f64) / (total as f64)
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ════════════════════════════════════════════════════════════════════════════
    // A. CONSTRUCTION TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_new_initializes_all_zeros() {
        let metrics = CacheMetrics::new();

        assert_eq!(metrics.get_hits(), 0);
        assert_eq!(metrics.get_misses(), 0);
        assert_eq!(metrics.get_stores(), 0);
        assert_eq!(metrics.get_evictions(), 0);
        assert_eq!(metrics.get_current_entries(), 0);
        assert_eq!(metrics.get_current_bytes(), 0);
        assert_eq!(metrics.get_reconciled_entries(), 0);
    }

    #[test]
    fn test_default_equals_new() {
        let from_new = CacheMetrics::new();
        let from_default = CacheMetrics::default();

        assert_eq!(from_new.get_hits(), from_default.get_hits());
        assert_eq!(from_new.get_misses(), from_default.get_misses());
        assert_eq!(from_new.get_stores(), from_default.get_stores());
    }

    // ════════════════════════════════════════════════════════════════════════════
    // B. HIT/MISS RECORDING TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_record_hit_increments_only_hits() {
        let metrics = CacheMetrics::new();

        metrics.record_hit();
        metrics.record_hit();
        metrics.record_hit();

        assert_eq!(metrics.get_hits(), 3);
        assert_eq!(metrics.get_misses(), 0);
        assert_eq!(metrics.get_stores(), 0);
        assert_eq!(metrics.get_evictions(), 0);
    }

    #[test]
    fn test_record_miss_increments_only_misses() {
        let metrics = CacheMetrics::new();

        metrics.record_miss();
        metrics.record_miss();

        assert_eq!(metrics.get_hits(), 0);
        assert_eq!(metrics.get_misses(), 2);
        assert_eq!(metrics.get_stores(), 0);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // C. STORE RECORDING TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_record_store_updates_three_counters() {
        let metrics = CacheMetrics::new();

        metrics.record_store(100);

        assert_eq!(metrics.get_stores(), 1);
        assert_eq!(metrics.get_current_entries(), 1);
        assert_eq!(metrics.get_current_bytes(), 100);
    }

    #[test]
    fn test_record_store_accumulates() {
        let metrics = CacheMetrics::new();

        metrics.record_store(50);
        metrics.record_store(75);
        metrics.record_store(25);

        assert_eq!(metrics.get_stores(), 3);
        assert_eq!(metrics.get_current_entries(), 3);
        assert_eq!(metrics.get_current_bytes(), 150);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // D. EVICTION RECORDING TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_record_eviction_updates_counters() {
        let metrics = CacheMetrics::new();

        // Add some entries first
        metrics.record_store(100);
        metrics.record_store(100);
        metrics.record_store(100);

        assert_eq!(metrics.get_current_entries(), 3);

        // Evict 2
        metrics.record_eviction(2);

        assert_eq!(metrics.get_evictions(), 2);
        assert_eq!(metrics.get_current_entries(), 1);
    }

    #[test]
    fn test_record_eviction_saturates_at_zero() {
        let metrics = CacheMetrics::new();

        // Try to evict more than exists
        metrics.record_eviction(10);

        // Should saturate at 0, not underflow
        assert_eq!(metrics.get_current_entries(), 0);
        assert_eq!(metrics.get_evictions(), 10);
    }

    #[test]
    fn test_record_bytes_removed_saturates() {
        let metrics = CacheMetrics::new();

        metrics.record_store(50);
        metrics.record_bytes_removed(100); // More than stored

        assert_eq!(metrics.get_current_bytes(), 0); // Saturated, not underflowed
    }

    // ════════════════════════════════════════════════════════════════════════════
    // E. HIT RATE TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_hit_rate_zero_when_no_requests() {
        let metrics = CacheMetrics::new();

        assert_eq!(metrics.hit_rate(), 0.0);
        assert!(!metrics.hit_rate().is_nan());
    }

    #[test]
    fn test_hit_rate_all_hits() {
        let metrics = CacheMetrics::new();

        metrics.record_hit();
        metrics.record_hit();
        metrics.record_hit();

        assert_eq!(metrics.hit_rate(), 1.0);
    }

    #[test]
    fn test_hit_rate_all_misses() {
        let metrics = CacheMetrics::new();

        metrics.record_miss();
        metrics.record_miss();

        assert_eq!(metrics.hit_rate(), 0.0);
    }

    #[test]
    fn test_hit_rate_mixed() {
        let metrics = CacheMetrics::new();

        // 3 hits, 1 miss = 75% hit rate
        metrics.record_hit();
        metrics.record_hit();
        metrics.record_hit();
        metrics.record_miss();

        let rate = metrics.hit_rate();
        assert!((rate - 0.75).abs() < 0.0001);
    }

    #[test]
    fn test_hit_rate_never_nan() {
        let metrics = CacheMetrics::new();

        // Various scenarios
        assert!(!metrics.hit_rate().is_nan());

        metrics.record_hit();
        assert!(!metrics.hit_rate().is_nan());

        metrics.record_miss();
        assert!(!metrics.hit_rate().is_nan());
    }

    // ════════════════════════════════════════════════════════════════════════════
    // F. SNAPSHOT TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_snapshot_captures_all_values() {
        let metrics = CacheMetrics::new();

        metrics.record_hit();
        metrics.record_hit();
        metrics.record_miss();
        metrics.record_store(500);
        metrics.record_eviction(1);
        metrics.record_reconciliation(5);

        let snapshot = metrics.snapshot();

        assert_eq!(snapshot.hits, 2);
        assert_eq!(snapshot.misses, 1);
        assert_eq!(snapshot.stores, 1);
        assert_eq!(snapshot.current_entries, 0); // 1 stored - 1 evicted
        assert_eq!(snapshot.current_bytes, 500);
        assert_eq!(snapshot.evictions, 1);
        assert_eq!(snapshot.reconciled_entries, 5);
    }

    #[test]
    fn test_snapshot_is_independent() {
        let metrics = CacheMetrics::new();
        metrics.record_hit();

        let snapshot1 = metrics.snapshot();

        metrics.record_hit();
        metrics.record_hit();

        let snapshot2 = metrics.snapshot();

        // snapshot1 should not change
        assert_eq!(snapshot1.hits, 1);
        assert_eq!(snapshot2.hits, 3);
    }

    #[test]
    fn test_snapshot_hit_rate() {
        let snapshot = MetricsSnapshot {
            hits: 8,
            misses: 2,
            stores: 0,
            evictions: 0,
            current_entries: 0,
            current_bytes: 0,
            reconciled_entries: 0,
        };

        let rate = snapshot.hit_rate();
        assert!((rate - 0.8).abs() < 0.0001);
    }

    #[test]
    fn test_snapshot_hit_rate_zero_denominator() {
        let snapshot = MetricsSnapshot {
            hits: 0,
            misses: 0,
            stores: 0,
            evictions: 0,
            current_entries: 0,
            current_bytes: 0,
            reconciled_entries: 0,
        };

        assert_eq!(snapshot.hit_rate(), 0.0);
        assert!(!snapshot.hit_rate().is_nan());
    }

    // ════════════════════════════════════════════════════════════════════════════
    // G. PROMETHEUS FORMAT TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_prometheus_contains_all_metrics() {
        let metrics = CacheMetrics::new();
        metrics.record_hit();
        metrics.record_miss();
        metrics.record_store(100);

        let output = metrics.to_prometheus();

        assert!(output.contains("fallback_cache_hits"));
        assert!(output.contains("fallback_cache_misses"));
        assert!(output.contains("fallback_cache_stores"));
        assert!(output.contains("fallback_cache_evictions"));
        assert!(output.contains("fallback_cache_current_entries"));
        assert!(output.contains("fallback_cache_current_bytes"));
        assert!(output.contains("fallback_cache_reconciled_entries"));
        assert!(output.contains("fallback_cache_hit_rate"));
    }

    #[test]
    fn test_prometheus_format_consistency() {
        let metrics = CacheMetrics::new();

        let output = metrics.to_prometheus();

        // Check HELP and TYPE lines present
        assert!(output.contains("# HELP fallback_cache_hits"));
        assert!(output.contains("# TYPE fallback_cache_hits counter"));

        // Verify snake_case naming
        assert!(!output.contains("fallbackCache"));
        assert!(!output.contains("FallbackCache"));
    }

    #[test]
    fn test_prometheus_values_correct() {
        let metrics = CacheMetrics::new();

        metrics.record_hit();
        metrics.record_hit();
        metrics.record_hit();
        metrics.record_miss();
        metrics.record_store(256);

        let output = metrics.to_prometheus();

        // Check specific values appear
        assert!(output.contains("fallback_cache_hits 3"));
        assert!(output.contains("fallback_cache_misses 1"));
        assert!(output.contains("fallback_cache_stores 1"));
        assert!(output.contains("fallback_cache_current_bytes 256"));
    }

    #[test]
    fn test_prometheus_no_negative_values() {
        let metrics = CacheMetrics::new();

        // Try to force underflow
        metrics.record_eviction(100);
        metrics.record_bytes_removed(1000);

        let output = metrics.to_prometheus();

        // Parse and verify no negative numbers
        for line in output.lines() {
            if !line.starts_with('#') && !line.is_empty() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    // Try to parse as number
                    if let Ok(val) = parts[1].parse::<f64>() {
                        assert!(val >= 0.0, "Found negative value: {}", line);
                    }
                }
            }
        }
    }

    #[test]
    fn test_prometheus_hit_rate_format() {
        let metrics = CacheMetrics::new();
        metrics.record_hit();
        metrics.record_hit();
        metrics.record_hit();
        metrics.record_miss();

        let output = metrics.to_prometheus();

        // Should contain hit rate with decimal format
        assert!(output.contains("fallback_cache_hit_rate 0.7500"));
    }

    // ════════════════════════════════════════════════════════════════════════════
    // H. THREAD SAFETY TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_cache_metrics_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<CacheMetrics>();
    }

    #[test]
    fn test_cache_metrics_is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<CacheMetrics>();
    }

    #[test]
    fn test_metrics_snapshot_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<MetricsSnapshot>();
    }

    #[test]
    fn test_metrics_snapshot_is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<MetricsSnapshot>();
    }

    #[test]
    fn test_concurrent_recording() {
        use std::sync::Arc;
        use std::thread;

        let metrics = Arc::new(CacheMetrics::new());
        let mut handles = vec![];

        // Spawn multiple threads recording various metrics
        for _ in 0..4 {
            let m = Arc::clone(&metrics);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    m.record_hit();
                    m.record_miss();
                    m.record_store(10);
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Each thread: 100 hits, 100 misses, 100 stores
        // 4 threads total
        assert_eq!(metrics.get_hits(), 400);
        assert_eq!(metrics.get_misses(), 400);
        assert_eq!(metrics.get_stores(), 400);
        assert_eq!(metrics.get_current_entries(), 400);
        assert_eq!(metrics.get_current_bytes(), 4000);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // I. RECONCILIATION TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_record_reconciliation() {
        let metrics = CacheMetrics::new();

        metrics.record_reconciliation(5);
        metrics.record_reconciliation(3);

        assert_eq!(metrics.get_reconciled_entries(), 8);
    }
}