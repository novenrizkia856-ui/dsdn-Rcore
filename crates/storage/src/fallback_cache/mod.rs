//! FallbackCache Module (14A.1A.55)
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
pub mod metrics;
pub mod persistence;
pub mod reconciliation;
pub mod validation;

// ════════════════════════════════════════════════════════════════════════════════
// PUBLIC EXPORTS
// ════════════════════════════════════════════════════════════════════════════════

pub use blob::{BlobStorage, CacheError, CachedBlob, DASourceType};
pub use eviction::{
    create_evictor, EvictionPolicy, Evictor, FIFOEvictor, FallbackCacheConfig, LFUEvictor,
    LRUEvictor,
};
pub use metrics::{CacheMetrics, MetricsSnapshot};
pub use validation::{
    compute_blob_hash, CacheValidator, HashValidator, ValidationError, ValidationReport,
};

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
            if let Some(removed_blob) = self.remove(seq) {
                evicted += 1;
                // Record eviction in metrics (count=1, bytes removed)
                self.metrics.record_eviction(1);
                self.metrics.record_bytes_removed(removed_blob.data.len() as u64);
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
            if let Some(removed_blob) = self.remove(seq) {
                evicted += 1;
                // Record eviction in metrics
                self.metrics.record_eviction(1);
                self.metrics.record_bytes_removed(removed_blob.data.len() as u64);
            }
        }

        evicted
    }

    // ════════════════════════════════════════════════════════════════════════════
    // VALIDATION METHODS
    // ════════════════════════════════════════════════════════════════════════════

    /// Validate a single cache entry by sequence number.
    ///
    /// ## Returns
    ///
    /// - `Ok(true)` - Entry is valid
    /// - `Ok(false)` - Entry is invalid
    /// - `Err(CacheError::NotFound)` - Entry does not exist
    ///
    /// ## Guarantees
    ///
    /// - Does not remove the entry
    /// - Does not panic
    pub fn validate(&self, sequence: u64) -> Result<bool, CacheError> {
        let guard = match self.blobs.read() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        let blob = guard.get(&sequence).ok_or(CacheError::NotFound(sequence))?;

        let validator = HashValidator::new(self.config.ttl_seconds);
        let validation_result = validator.validate_blob(blob);

        Ok(validation_result.is_none()) // None = valid
    }

    /// Validate all cache entries and return a detailed report.
    ///
    /// ## Returns
    ///
    /// ValidationReport containing:
    /// - total_checked: number of entries validated
    /// - valid_count: number of valid entries
    /// - invalid_entries: list of (sequence, error) for invalid entries
    ///
    /// ## Guarantees
    ///
    /// - Does not remove any entries
    /// - Does not panic
    pub fn validate_all(&self) -> ValidationReport {
        let guard = match self.blobs.read() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        let mut report = ValidationReport::new();
        let validator = HashValidator::new(self.config.ttl_seconds);

        for (&sequence, blob) in guard.iter() {
            match validator.validate_blob(blob) {
                None => report.add_valid(),
                Some(error) => report.add_invalid(sequence, error),
            }
        }

        report
    }

    /// Validate all entries and remove invalid ones.
    ///
    /// ## Returns
    ///
    /// Number of invalid entries removed.
    ///
    /// ## Guarantees
    ///
    /// - Only removes invalid entries
    /// - Valid entries are never removed
    /// - Removal is atomic per entry
    /// - Updates metrics consistently
    pub fn remove_invalid(&self) -> usize {
        // First, validate all entries to get invalid sequences
        let report = self.validate_all();

        if report.invalid_entries.is_empty() {
            return 0;
        }

        let mut removed = 0;

        // Remove each invalid entry
        for (sequence, _error) in report.invalid_entries {
            if let Some(removed_blob) = self.remove(sequence) {
                removed += 1;
                // Record eviction in metrics
                self.metrics.record_eviction(1);
                self.metrics.record_bytes_removed(removed_blob.data.len() as u64);
            }
        }

        removed
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

        // Record store in metrics (increments stores, current_entries, current_bytes)
        self.metrics.record_store(blob_size);

        Ok(())
    }

    /// Get a blob by sequence number.
    fn get(&self, sequence: u64) -> Option<CachedBlob> {
        let guard = match self.blobs.read() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        match guard.get(&sequence) {
            Some(blob) => {
                // Increment access_count atomically on the stored blob
                blob.access_count.fetch_add(1, Ordering::Relaxed);
                // Record hit in metrics
                self.metrics.record_hit();
                // Return a clone
                Some(blob.clone())
            }
            None => {
                // Record miss in metrics
                self.metrics.record_miss();
                None
            }
        }
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
    use std::sync::atomic::AtomicU32;

    fn make_blob(size: usize, received_at: u64) -> CachedBlob {
        let data = vec![0; size];
        let hash = compute_blob_hash(&data);
        CachedBlob {
            data,
            source: DASourceType::Primary,
            received_at,
            hash,
            access_count: AtomicU32::new(0),
        }
    }

    fn make_blob_with_access(size: usize, received_at: u64, access_count: u32) -> CachedBlob {
        let blob = make_blob(size, received_at);
        blob.access_count.store(access_count, Ordering::SeqCst);
        blob
    }

    fn make_valid_blob(data: Vec<u8>, received_at: u64) -> CachedBlob {
        let hash = compute_blob_hash(&data);
        CachedBlob {
            data,
            source: DASourceType::Primary,
            received_at,
            hash,
            access_count: AtomicU32::new(0),
        }
    }

    fn make_invalid_hash_blob(data: Vec<u8>, received_at: u64) -> CachedBlob {
        CachedBlob {
            data,
            source: DASourceType::Primary,
            received_at,
            hash: [0xFF; 32], // Wrong hash
            access_count: AtomicU32::new(0),
        }
    }

    fn make_corrupted_blob(received_at: u64) -> CachedBlob {
        CachedBlob {
            data: vec![], // Empty = corrupted
            source: DASourceType::Primary,
            received_at,
            hash: [0; 32],
            access_count: AtomicU32::new(0),
        }
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
        let config = FallbackCacheConfig::new(100, 2).with_eviction_policy(EvictionPolicy::LRU);
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
        let config = FallbackCacheConfig::new(100, 2).with_eviction_policy(EvictionPolicy::FIFO);
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
        let config = FallbackCacheConfig::new(100, 2).with_eviction_policy(EvictionPolicy::LFU);
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

        assert!(cache.metrics().get_evictions() > 0);
    }

    #[test]
    fn test_store_updates_metrics() {
        let cache = FallbackCache::new();

        cache.store(1, make_blob(10, 1000)).unwrap();
        cache.store(2, make_blob(10, 2000)).unwrap();

        assert_eq!(cache.metrics().get_stores(), 2);
        assert_eq!(cache.metrics().get_current_entries(), 2);
        assert_eq!(cache.metrics().get_current_bytes(), 20);
    }

    #[test]
    fn test_get_updates_hit_metrics() {
        let cache = FallbackCache::new();
        cache.store(1, make_blob(10, 1000)).unwrap();

        cache.get(1);
        cache.get(1);

        assert_eq!(cache.metrics().get_hits(), 2);
    }

    #[test]
    fn test_metrics_snapshot() {
        let cache = FallbackCache::new();

        cache.store(1, make_blob(100, 1000)).unwrap();
        cache.get(1);
        cache.get(1);
        cache.get(1);

        let snapshot = cache.metrics().snapshot();

        assert_eq!(snapshot.stores, 1);
        assert_eq!(snapshot.hits, 3);
        assert_eq!(snapshot.current_entries, 1);
        assert_eq!(snapshot.current_bytes, 100);
    }

    #[test]
    fn test_metrics_hit_rate() {
        let cache = FallbackCache::new();
        cache.store(1, make_blob(10, 1000)).unwrap();

        // 3 hits
        cache.get(1);
        cache.get(1);
        cache.get(1);

        // 1 miss (get() records miss automatically when blob not found)
        cache.get(999);

        let rate = cache.metrics().hit_rate();
        assert!((rate - 0.75).abs() < 0.01);
    }

    #[test]
    fn test_get_updates_miss_metrics() {
        let cache = FallbackCache::new();

        // Try to get non-existent blobs
        cache.get(1);
        cache.get(2);
        cache.get(3);

        assert_eq!(cache.metrics().get_misses(), 3);
        assert_eq!(cache.metrics().get_hits(), 0);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // J. VALIDATION TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_validate_valid_entry() {
        let cache = FallbackCache::new();
        let blob = make_valid_blob(vec![1, 2, 3, 4, 5], 1000);

        cache.store(1, blob).unwrap();

        let result = cache.validate(1);
        assert!(result.is_ok());
        assert!(result.unwrap()); // Valid
    }

    #[test]
    fn test_validate_invalid_hash_entry() {
        let cache = FallbackCache::new();
        let blob = make_invalid_hash_blob(vec![1, 2, 3, 4, 5], 1000);

        cache.store(1, blob).unwrap();

        let result = cache.validate(1);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Invalid (hash mismatch)
    }

    #[test]
    fn test_validate_corrupted_entry() {
        let cache = FallbackCache::new();
        let blob = make_corrupted_blob(1000);

        cache.store(1, blob).unwrap();

        let result = cache.validate(1);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Invalid (corrupted)
    }

    #[test]
    fn test_validate_nonexistent_entry() {
        let cache = FallbackCache::new();

        let result = cache.validate(999);
        assert!(result.is_err()); // Not found
    }

    #[test]
    fn test_validate_does_not_remove_entry() {
        let cache = FallbackCache::new();
        let blob = make_invalid_hash_blob(vec![1, 2, 3], 1000);

        cache.store(1, blob).unwrap();
        assert_eq!(cache.len(), 1);

        cache.validate(1).unwrap();

        // Entry still exists
        assert_eq!(cache.len(), 1);
        assert!(cache.contains(1));
    }

    #[test]
    fn test_validate_all_all_valid() {
        let cache = FallbackCache::new();

        cache
            .store(1, make_valid_blob(vec![1, 2, 3], 1000))
            .unwrap();
        cache
            .store(2, make_valid_blob(vec![4, 5, 6], 2000))
            .unwrap();
        cache
            .store(3, make_valid_blob(vec![7, 8, 9], 3000))
            .unwrap();

        let report = cache.validate_all();

        assert_eq!(report.total_checked, 3);
        assert_eq!(report.valid_count, 3);
        assert_eq!(report.invalid_count(), 0);
        assert!(report.is_healthy());
    }

    #[test]
    fn test_validate_all_mixed() {
        let cache = FallbackCache::new();

        cache
            .store(1, make_valid_blob(vec![1, 2, 3], 1000))
            .unwrap();
        cache
            .store(2, make_invalid_hash_blob(vec![4, 5, 6], 2000))
            .unwrap();
        cache.store(3, make_corrupted_blob(3000)).unwrap();
        cache
            .store(4, make_valid_blob(vec![10, 11, 12], 4000))
            .unwrap();

        let report = cache.validate_all();

        assert_eq!(report.total_checked, 4);
        assert_eq!(report.valid_count, 2);
        assert_eq!(report.invalid_count(), 2);
        assert!(!report.is_healthy());
    }

    #[test]
    fn test_validate_all_does_not_remove_entries() {
        let cache = FallbackCache::new();

        cache
            .store(1, make_invalid_hash_blob(vec![1, 2, 3], 1000))
            .unwrap();
        cache.store(2, make_corrupted_blob(2000)).unwrap();

        assert_eq!(cache.len(), 2);

        cache.validate_all();

        // Entries still exist
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_remove_invalid_removes_only_invalid() {
        let cache = FallbackCache::new();

        // Valid entries
        cache
            .store(1, make_valid_blob(vec![1, 2, 3], 1000))
            .unwrap();
        cache
            .store(4, make_valid_blob(vec![10, 11, 12], 4000))
            .unwrap();

        // Invalid entries
        cache
            .store(2, make_invalid_hash_blob(vec![4, 5, 6], 2000))
            .unwrap();
        cache.store(3, make_corrupted_blob(3000)).unwrap();

        assert_eq!(cache.len(), 4);

        let removed = cache.remove_invalid();

        assert_eq!(removed, 2);
        assert_eq!(cache.len(), 2);

        // Valid entries still exist
        assert!(cache.contains(1));
        assert!(cache.contains(4));

        // Invalid entries removed
        assert!(!cache.contains(2));
        assert!(!cache.contains(3));
    }

    #[test]
    fn test_remove_invalid_returns_zero_when_all_valid() {
        let cache = FallbackCache::new();

        cache
            .store(1, make_valid_blob(vec![1, 2, 3], 1000))
            .unwrap();
        cache
            .store(2, make_valid_blob(vec![4, 5, 6], 2000))
            .unwrap();

        let removed = cache.remove_invalid();

        assert_eq!(removed, 0);
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_remove_invalid_updates_metrics() {
        let cache = FallbackCache::new();

        cache
            .store(1, make_invalid_hash_blob(vec![1, 2, 3], 1000))
            .unwrap();
        cache.store(2, make_corrupted_blob(2000)).unwrap();

        let initial_evictions = cache.metrics().get_evictions();

        cache.remove_invalid();

        assert_eq!(cache.metrics().get_evictions(), initial_evictions + 2);
    }

    #[test]
    fn test_remove_invalid_empty_cache() {
        let cache = FallbackCache::new();

        let removed = cache.remove_invalid();

        assert_eq!(removed, 0);
    }

    #[test]
    fn test_validate_with_ttl_expired() {
        let config = FallbackCacheConfig::new(1000, 100).with_ttl_seconds(1); // 1 second TTL
        let cache = FallbackCache::with_config(config);

        // Valid hash but very old blob
        cache
            .store(1, make_valid_blob(vec![1, 2, 3], 0))
            .unwrap(); // received_at = 0

        let result = cache.validate(1);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Invalid (expired)
    }

    #[test]
    fn test_validate_all_with_ttl_expired() {
        let config = FallbackCacheConfig::new(1000, 100).with_ttl_seconds(1);
        let cache = FallbackCache::with_config(config);

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        // Old blob (expired)
        cache
            .store(1, make_valid_blob(vec![1, 2, 3], 0))
            .unwrap();
        // Fresh blob
        cache
            .store(2, make_valid_blob(vec![4, 5, 6], now_ms))
            .unwrap();

        let report = cache.validate_all();

        assert_eq!(report.total_checked, 2);
        assert_eq!(report.valid_count, 1);
        assert_eq!(report.invalid_count(), 1);

        // Check that expired blob is in invalid entries
        let expired_entry = report.invalid_entries.iter().find(|(seq, _)| *seq == 1);
        assert!(expired_entry.is_some());
        assert_eq!(expired_entry.unwrap().1, ValidationError::Expired);
    }

    #[test]
    fn test_remove_invalid_with_expired() {
        let config = FallbackCacheConfig::new(1000, 100).with_ttl_seconds(1);
        let cache = FallbackCache::with_config(config);

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        // Old blob (expired)
        cache
            .store(1, make_valid_blob(vec![1, 2, 3], 0))
            .unwrap();
        // Fresh blob
        cache
            .store(2, make_valid_blob(vec![4, 5, 6], now_ms))
            .unwrap();

        let removed = cache.remove_invalid();

        assert_eq!(removed, 1);
        assert!(!cache.contains(1)); // Expired removed
        assert!(cache.contains(2)); // Fresh kept
    }
}