//! FallbackCache Module (14A.1A.53)
//!
//! Provides caching for DA blobs during fallback operations.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

// ════════════════════════════════════════════════════════════════════════════════
// MODULE DECLARATIONS
// ════════════════════════════════════════════════════════════════════════════════

pub mod blob;
pub mod eviction;
pub mod persistence;
pub mod reconciliation;
pub mod metrics;
pub mod validation;

// ════════════════════════════════════════════════════════════════════════════════
// PUBLIC EXPORTS
// ════════════════════════════════════════════════════════════════════════════════

pub use blob::{BlobStorage, CachedBlob, CacheError, DASourceType};
pub use eviction::{
    create_evictor, EvictionPolicy, Evictor, FallbackCacheConfig, FIFOEvictor, LFUEvictor,
    LRUEvictor,
};
pub use metrics::CacheMetrics;
pub use validation::ValidationReport;

// ════════════════════════════════════════════════════════════════════════════════
// FALLBACK CACHE
// ════════════════════════════════════════════════════════════════════════════════

/// Fallback cache for DA blobs.
///
/// Stores blobs temporarily during fallback operations.
/// Thread-safe via RwLock for blob storage.
pub struct FallbackCache {
    /// Cached blobs indexed by sequence number.
    blobs: RwLock<HashMap<u64, CachedBlob>>,
    /// Cache configuration.
    config: FallbackCacheConfig,
    /// Cache metrics (shared).
    metrics: Arc<CacheMetrics>,
    /// Total bytes currently cached.
    total_bytes: AtomicU64,
}

impl FallbackCache {
    /// Create a new FallbackCache with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(FallbackCacheConfig::default())
    }

    /// Create a new FallbackCache with the given configuration.
    #[must_use]
    pub fn with_config(config: FallbackCacheConfig) -> Self {
        Self {
            blobs: RwLock::new(HashMap::new()),
            config,
            metrics: Arc::new(CacheMetrics::new()),
            total_bytes: AtomicU64::new(0),
        }
    }

    /// Get a reference to the cache configuration.
    #[must_use]
    pub fn config(&self) -> &FallbackCacheConfig {
        &self.config
    }

    /// Get a reference to the cache metrics.
    #[must_use]
    pub fn metrics(&self) -> &Arc<CacheMetrics> {
        &self.metrics
    }

    /// Get the current total bytes in cache.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes.load(Ordering::SeqCst)
    }

    /// Get the current number of cached blobs.
    #[must_use]
    pub fn len(&self) -> usize {
        match self.blobs.read() {
            Ok(guard) => guard.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        }
    }

    /// Check if the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    // ════════════════════════════════════════════════════════════════════════════
    // EVICTION METHODS
    // ════════════════════════════════════════════════════════════════════════════

    /// Evict blobs if cache exceeds limits.
    ///
    /// Called after store operations to maintain cache limits.
    /// Triggers eviction if:
    /// - total_bytes > max_bytes
    /// - OR entries > max_entries
    ///
    /// ## Returns
    ///
    /// Number of blobs evicted.
    pub fn evict_if_needed(&self) -> usize {
        let current_bytes = self.total_bytes.load(Ordering::SeqCst);
        let current_entries = self.len();

        // Check if eviction is needed
        if current_bytes <= self.config.max_bytes && current_entries <= self.config.max_entries {
            return 0;
        }

        // Get evictor for configured policy
        let evictor = create_evictor(self.config.eviction_policy);

        // Get eviction candidates (requires read lock)
        let candidates = {
            let guard = match self.blobs.read() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            evictor.select_for_eviction(&guard)
        };

        let mut evicted = 0;

        // Evict until under limits
        for seq in candidates {
            // Re-check current state (may have changed)
            let current_bytes = self.total_bytes.load(Ordering::SeqCst);
            let current_entries = self.len();

            if current_bytes <= self.config.max_bytes && current_entries <= self.config.max_entries
            {
                break;
            }

            // Try to remove using BlobStorage trait method
            if self.remove(seq).is_some() {
                evicted += 1;
                // Record eviction in metrics
                self.metrics.evictions.fetch_add(1, Ordering::Relaxed);
            }
        }

        evicted
    }

    /// Evict expired blobs based on TTL.
    ///
    /// If ttl_seconds is 0, this is a NO-OP.
    ///
    /// ## Returns
    ///
    /// Number of blobs evicted due to expiration.
    pub fn evict_expired(&self) -> usize {
        // TTL = 0 means disabled
        if self.config.ttl_seconds == 0 {
            return 0;
        }

        // Get current time in ms
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let ttl_ms = self.config.ttl_seconds.saturating_mul(1000);
        let threshold = now_ms.saturating_sub(ttl_ms);

        // Find expired sequences (requires read lock)
        let expired: Vec<u64> = {
            let guard = match self.blobs.read() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };

            guard
                .iter()
                .filter(|(_, blob)| blob.received_at < threshold)
                .map(|(&seq, _)| seq)
                .collect()
        };

        let mut evicted = 0;

        for seq in expired {
            if self.remove(seq).is_some() {
                evicted += 1;
                // Record eviction in metrics
                self.metrics.evictions.fetch_add(1, Ordering::Relaxed);
            }
        }

        evicted
    }
}

impl Default for FallbackCache {
    fn default() -> Self {
        Self::new()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// BLOB STORAGE IMPLEMENTATION
// ════════════════════════════════════════════════════════════════════════════════

impl BlobStorage for FallbackCache {
    /// Store a blob at the given sequence number.
    fn store(&self, sequence: u64, blob: CachedBlob) -> Result<(), CacheError> {
        let mut guard = self.blobs.write().map_err(|_| CacheError::LockPoisoned)?;

        if guard.contains_key(&sequence) {
            return Err(CacheError::AlreadyExists(sequence));
        }

        let blob_size = blob.data.len() as u64;
        guard.insert(sequence, blob);

        // Update total_bytes after successful insert
        self.total_bytes.fetch_add(blob_size, Ordering::SeqCst);

        // Record insertion in metrics
        self.metrics.insertions.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    /// Get a blob by sequence number.
    fn get(&self, sequence: u64) -> Option<CachedBlob> {
        let guard = match self.blobs.read() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        guard.get(&sequence).map(|blob| {
            // Increment access_count atomically on the stored blob
            blob.access_count.fetch_add(1, Ordering::Relaxed);
            // Record hit in metrics
            self.metrics.hits.fetch_add(1, Ordering::Relaxed);
            // Return a clone
            blob.clone()
        })
    }

    /// Remove and return a blob by sequence number.
    fn remove(&self, sequence: u64) -> Option<CachedBlob> {
        let mut guard = match self.blobs.write() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        guard.remove(&sequence).map(|blob| {
            let blob_size = blob.data.len() as u64;
            // Update total_bytes after successful removal
            self.total_bytes.fetch_sub(blob_size, Ordering::SeqCst);
            blob
        })
    }

    /// Check if a blob exists at the given sequence number.
    fn contains(&self, sequence: u64) -> bool {
        let guard = match self.blobs.read() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        guard.contains_key(&sequence)
    }

    /// List all sequence numbers in the cache.
    fn list_sequences(&self) -> Vec<u64> {
        let guard = match self.blobs.read() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        guard.keys().copied().collect()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_blob(size: usize, received_at: u64) -> CachedBlob {
        CachedBlob::new(vec![0; size], DASourceType::Primary, received_at, [0; 32])
    }

    fn make_blob_with_access(size: usize, received_at: u64, access_count: u32) -> CachedBlob {
        let blob = make_blob(size, received_at);
        blob.access_count.store(access_count, Ordering::SeqCst);
        blob
    }

    // ════════════════════════════════════════════════════════════════════════════
    // A. CONSTRUCTION TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_fallback_cache_new() {
        let cache = FallbackCache::new();

        assert_eq!(cache.total_bytes(), 0);
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());

        // Verify default config
        assert_eq!(cache.config().max_bytes, 100 * 1024 * 1024);
        assert_eq!(cache.config().max_entries, 1000);
        assert_eq!(cache.config().eviction_policy, EvictionPolicy::LRU);
        assert_eq!(cache.config().ttl_seconds, 0);
    }

    #[test]
    fn test_fallback_cache_with_config() {
        let config = FallbackCacheConfig::new(50 * 1024 * 1024, 500)
            .with_eviction_policy(EvictionPolicy::FIFO)
            .with_ttl_seconds(3600);

        let cache = FallbackCache::with_config(config);

        assert_eq!(cache.config().max_bytes, 50 * 1024 * 1024);
        assert_eq!(cache.config().max_entries, 500);
        assert_eq!(cache.config().eviction_policy, EvictionPolicy::FIFO);
        assert_eq!(cache.config().ttl_seconds, 3600);
    }

    #[test]
    fn test_fallback_cache_default() {
        let cache = FallbackCache::default();
        assert_eq!(cache.total_bytes(), 0);
        assert!(cache.is_empty());
    }

    // ════════════════════════════════════════════════════════════════════════════
    // B. BLOB STORAGE TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_store_and_get_blob() {
        let cache = FallbackCache::new();
        let blob = make_blob(100, 1000);

        assert!(cache.store(1, blob).is_ok());
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.total_bytes(), 100);

        let retrieved = cache.get(1).unwrap();
        assert_eq!(retrieved.data.len(), 100);
    }

    #[test]
    fn test_store_duplicate_fails() {
        let cache = FallbackCache::new();

        assert!(cache.store(1, make_blob(10, 1000)).is_ok());
        assert!(cache.store(1, make_blob(20, 2000)).is_err());
        assert_eq!(cache.total_bytes(), 10); // Unchanged
    }

    #[test]
    fn test_remove_blob() {
        let cache = FallbackCache::new();
        cache.store(1, make_blob(100, 1000)).unwrap();

        let removed = cache.remove(1);
        assert!(removed.is_some());
        assert_eq!(cache.total_bytes(), 0);
        assert!(cache.is_empty());
    }

    // ════════════════════════════════════════════════════════════════════════════
    // C. EVICTION BY MAX BYTES TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_evict_if_needed_max_bytes() {
        let config = FallbackCacheConfig::new(100, 1000); // max 100 bytes
        let cache = FallbackCache::with_config(config);

        // Store blobs totaling 150 bytes
        cache
            .store(1, make_blob_with_access(50, 1000, 10))
            .unwrap();
        cache
            .store(2, make_blob_with_access(50, 2000, 5))
            .unwrap(); // lower access
        cache
            .store(3, make_blob_with_access(50, 3000, 15))
            .unwrap();

        assert_eq!(cache.total_bytes(), 150);

        // Evict
        let evicted = cache.evict_if_needed();

        assert!(evicted > 0);
        assert!(cache.total_bytes() <= 100); // Under limit
    }

    #[test]
    fn test_evict_if_needed_no_eviction_under_limit() {
        let config = FallbackCacheConfig::new(1000, 100);
        let cache = FallbackCache::with_config(config);

        cache.store(1, make_blob(50, 1000)).unwrap();
        cache.store(2, make_blob(50, 2000)).unwrap();

        let evicted = cache.evict_if_needed();
        assert_eq!(evicted, 0);
        assert_eq!(cache.len(), 2);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // D. EVICTION BY MAX ENTRIES TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_evict_if_needed_max_entries() {
        let config = FallbackCacheConfig::new(1_000_000, 2); // max 2 entries
        let cache = FallbackCache::with_config(config);

        cache
            .store(1, make_blob_with_access(10, 1000, 10))
            .unwrap();
        cache
            .store(2, make_blob_with_access(10, 2000, 5))
            .unwrap(); // lower access
        cache
            .store(3, make_blob_with_access(10, 3000, 15))
            .unwrap();

        assert_eq!(cache.len(), 3);

        let evicted = cache.evict_if_needed();

        assert!(evicted > 0);
        assert!(cache.len() <= 2); // Under limit
    }

    // ════════════════════════════════════════════════════════════════════════════
    // E. TTL EXPIRATION TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_evict_expired_ttl_zero_noop() {
        let config = FallbackCacheConfig::new(1000, 100).with_ttl_seconds(0);
        let cache = FallbackCache::with_config(config);

        // Store a blob with very old timestamp
        cache.store(1, make_blob(10, 0)).unwrap();

        let evicted = cache.evict_expired();
        assert_eq!(evicted, 0); // TTL disabled, no eviction
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_evict_expired_removes_old_blobs() {
        let config = FallbackCacheConfig::new(1000, 100).with_ttl_seconds(1); // 1 second TTL
        let cache = FallbackCache::with_config(config);

        // Get current time
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        // Store an old blob (clearly expired)
        cache.store(1, make_blob(10, 0)).unwrap(); // received_at = 0

        // Store a fresh blob
        cache.store(2, make_blob(10, now_ms)).unwrap();

        let evicted = cache.evict_expired();

        assert_eq!(evicted, 1);
        assert!(!cache.contains(1)); // Old blob removed
        assert!(cache.contains(2)); // Fresh blob kept
    }

    #[test]
    fn test_evict_expired_keeps_fresh_blobs() {
        let config = FallbackCacheConfig::new(1000, 100).with_ttl_seconds(3600); // 1 hour TTL
        let cache = FallbackCache::with_config(config);

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        // All blobs are fresh
        cache.store(1, make_blob(10, now_ms)).unwrap();
        cache.store(2, make_blob(10, now_ms)).unwrap();

        let evicted = cache.evict_expired();
        assert_eq!(evicted, 0);
        assert_eq!(cache.len(), 2);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // F. POLICY-SPECIFIC EVICTION TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_lru_eviction_evicts_least_accessed_oldest() {
        let config =
            FallbackCacheConfig::new(100, 2).with_eviction_policy(EvictionPolicy::LRU);
        let cache = FallbackCache::with_config(config);

        // Blob 1: access=5, received=1000 ← should be evicted (lowest access)
        cache
            .store(1, make_blob_with_access(50, 1000, 5))
            .unwrap();
        // Blob 2: access=10, received=2000
        cache
            .store(2, make_blob_with_access(50, 2000, 10))
            .unwrap();
        // Blob 3: access=15, received=3000
        cache
            .store(3, make_blob_with_access(50, 3000, 15))
            .unwrap();

        cache.evict_if_needed();

        assert!(!cache.contains(1)); // Evicted (lowest access_count)
        assert!(cache.contains(2) || cache.contains(3));
    }

    #[test]
    fn test_fifo_eviction_evicts_oldest() {
        let config =
            FallbackCacheConfig::new(100, 2).with_eviction_policy(EvictionPolicy::FIFO);
        let cache = FallbackCache::with_config(config);

        // Blob 1: received=1000 ← oldest, should be evicted
        cache
            .store(1, make_blob_with_access(50, 1000, 100))
            .unwrap();
        // Blob 2: received=2000
        cache
            .store(2, make_blob_with_access(50, 2000, 1))
            .unwrap();
        // Blob 3: received=3000
        cache
            .store(3, make_blob_with_access(50, 3000, 50))
            .unwrap();

        cache.evict_if_needed();

        assert!(!cache.contains(1)); // Evicted (oldest received_at)
        assert!(cache.contains(2) || cache.contains(3));
    }

    #[test]
    fn test_lfu_eviction_evicts_least_frequent() {
        let config =
            FallbackCacheConfig::new(100, 2).with_eviction_policy(EvictionPolicy::LFU);
        let cache = FallbackCache::with_config(config);

        // Blob 1: access=10
        cache
            .store(1, make_blob_with_access(50, 3000, 10))
            .unwrap();
        // Blob 2: access=5 ← lowest, should be evicted
        cache
            .store(2, make_blob_with_access(50, 1000, 5))
            .unwrap();
        // Blob 3: access=15
        cache
            .store(3, make_blob_with_access(50, 2000, 15))
            .unwrap();

        cache.evict_if_needed();

        assert!(!cache.contains(2)); // Evicted (lowest access_count)
        assert!(cache.contains(1) || cache.contains(3));
    }

    // ════════════════════════════════════════════════════════════════════════════
    // G. TOTAL BYTES ENFORCEMENT TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_total_bytes_never_exceeds_max_after_eviction() {
        let config = FallbackCacheConfig::new(50, 1000);
        let cache = FallbackCache::with_config(config);

        // Store blobs that exceed limit
        for i in 0..10 {
            let _ = cache.store(i, make_blob(20, i as u64 * 1000));
            cache.evict_if_needed();
        }

        // After all operations, should be under limit
        assert!(cache.total_bytes() <= 50);
    }

    #[test]
    fn test_total_bytes_tracking_with_eviction() {
        let config = FallbackCacheConfig::new(100, 3);
        let cache = FallbackCache::with_config(config);

        cache.store(1, make_blob(40, 1000)).unwrap();
        cache.store(2, make_blob(40, 2000)).unwrap();
        cache.store(3, make_blob(40, 3000)).unwrap();

        assert_eq!(cache.total_bytes(), 120);

        cache.evict_if_needed();

        // Should have evicted to get under 100 bytes
        assert!(cache.total_bytes() <= 100);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // H. THREAD SAFETY TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_fallback_cache_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<FallbackCache>();
    }

    #[test]
    fn test_fallback_cache_is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<FallbackCache>();
    }

    #[test]
    fn test_concurrent_store_and_evict() {
        use std::thread;

        let config = FallbackCacheConfig::new(500, 50);
        let cache = Arc::new(FallbackCache::with_config(config));

        let mut handles = vec![];

        // Spawn writers
        for i in 0..5 {
            let cache_clone = Arc::clone(&cache);
            handles.push(thread::spawn(move || {
                for j in 0..20 {
                    let seq = (i * 100 + j) as u64;
                    let _ = cache_clone.store(seq, make_blob(10, seq * 1000));
                    cache_clone.evict_if_needed();
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Should be under limits
        assert!(cache.total_bytes() <= 500);
        assert!(cache.len() <= 50);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // I. METRICS TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_eviction_updates_metrics() {
        let config = FallbackCacheConfig::new(50, 1);
        let cache = FallbackCache::with_config(config);

        cache.store(1, make_blob(30, 1000)).unwrap();
        cache.store(2, make_blob(30, 2000)).unwrap();

        cache.evict_if_needed();

        assert!(cache.metrics().evictions.load(Ordering::SeqCst) > 0);
    }

    #[test]
    fn test_insertion_updates_metrics() {
        let cache = FallbackCache::new();

        cache.store(1, make_blob(10, 1000)).unwrap();
        cache.store(2, make_blob(10, 2000)).unwrap();

        assert_eq!(cache.metrics().insertions.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_get_updates_hit_metrics() {
        let cache = FallbackCache::new();
        cache.store(1, make_blob(10, 1000)).unwrap();

        cache.get(1);
        cache.get(1);

        assert_eq!(cache.metrics().hits.load(Ordering::SeqCst), 2);
    }
}