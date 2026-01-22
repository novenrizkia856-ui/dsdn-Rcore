//! FallbackCache Module (14A.1A.52)
//!
//! Provides caching for DA blobs during fallback operations.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

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
pub use eviction::{EvictionPolicy, FallbackCacheConfig};
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
    ///
    /// ## Behavior
    ///
    /// - Acquires write lock on blobs HashMap
    /// - Returns error if sequence already exists (no silent overwrite)
    /// - Updates total_bytes atomically after successful insert
    ///
    /// ## Errors
    ///
    /// - `CacheError::AlreadyExists` - sequence already in cache
    /// - `CacheError::LockPoisoned` - RwLock was poisoned
    fn store(&self, sequence: u64, blob: CachedBlob) -> Result<(), CacheError> {
        let mut guard = self.blobs.write().map_err(|_| CacheError::LockPoisoned)?;

        if guard.contains_key(&sequence) {
            return Err(CacheError::AlreadyExists(sequence));
        }

        let blob_size = blob.data.len() as u64;
        guard.insert(sequence, blob);

        // Update total_bytes after successful insert
        self.total_bytes.fetch_add(blob_size, Ordering::SeqCst);

        Ok(())
    }

    /// Get a blob by sequence number.
    ///
    /// ## Behavior
    ///
    /// - Acquires read lock on blobs HashMap
    /// - Increments access_count atomically on the stored blob
    /// - Returns a clone of the blob
    ///
    /// ## Returns
    ///
    /// - `Some(CachedBlob)` - clone of blob with updated access_count
    /// - `None` - blob not found
    fn get(&self, sequence: u64) -> Option<CachedBlob> {
        let guard = match self.blobs.read() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        guard.get(&sequence).map(|blob| {
            // Increment access_count atomically on the stored blob
            blob.access_count.fetch_add(1, Ordering::Relaxed);
            // Return a clone
            blob.clone()
        })
    }

    /// Remove and return a blob by sequence number.
    ///
    /// ## Behavior
    ///
    /// - Acquires write lock on blobs HashMap
    /// - Removes blob from cache
    /// - Updates total_bytes atomically after successful removal
    ///
    /// ## Returns
    ///
    /// - `Some(CachedBlob)` - removed blob
    /// - `None` - blob not found
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
    ///
    /// ## Behavior
    ///
    /// - Acquires read lock on blobs HashMap
    /// - Read-only, no side effects
    fn contains(&self, sequence: u64) -> bool {
        let guard = match self.blobs.read() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        guard.contains_key(&sequence)
    }

    /// List all sequence numbers in the cache.
    ///
    /// ## Behavior
    ///
    /// - Acquires read lock on blobs HashMap
    /// - Returns snapshot of current sequences
    /// - Order is not guaranteed
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
        assert_eq!(cache.config().max_blobs, 1000);
        assert_eq!(cache.config().eviction_policy, EvictionPolicy::Lru);
    }

    #[test]
    fn test_fallback_cache_with_config() {
        let config = FallbackCacheConfig::new(50 * 1024 * 1024, 500)
            .with_eviction_policy(EvictionPolicy::Fifo);

        let cache = FallbackCache::with_config(config);

        assert_eq!(cache.total_bytes(), 0);
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());

        // Verify custom config
        assert_eq!(cache.config().max_bytes, 50 * 1024 * 1024);
        assert_eq!(cache.config().max_blobs, 500);
        assert_eq!(cache.config().eviction_policy, EvictionPolicy::Fifo);
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
        let data = vec![1, 2, 3, 4, 5];
        let hash = [0xAB; 32];
        let blob = CachedBlob::new(data.clone(), DASourceType::Primary, 1000, hash);

        // Store blob
        let result = cache.store(42, blob);
        assert!(result.is_ok());

        // Verify cache state
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.total_bytes(), 5);
        assert!(!cache.is_empty());

        // Get blob
        let retrieved = cache.get(42);
        assert!(retrieved.is_some());

        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.data, data);
        assert_eq!(retrieved.source, DASourceType::Primary);
        assert_eq!(retrieved.received_at, 1000);
        assert_eq!(retrieved.hash, hash);
        // access_count should be 1 (incremented by get)
        assert_eq!(retrieved.get_access_count(), 1);
    }

    #[test]
    fn test_store_duplicate_fails() {
        let cache = FallbackCache::new();
        let blob1 = CachedBlob::new(vec![1, 2], DASourceType::Primary, 100, [0; 32]);
        let blob2 = CachedBlob::new(vec![3, 4], DASourceType::Secondary, 200, [1; 32]);

        // First store succeeds
        assert!(cache.store(1, blob1).is_ok());
        assert_eq!(cache.total_bytes(), 2);

        // Second store with same sequence fails
        let result = cache.store(1, blob2);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CacheError::AlreadyExists(1));

        // total_bytes unchanged
        assert_eq!(cache.total_bytes(), 2);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_get_increments_access_count() {
        let cache = FallbackCache::new();
        let blob = CachedBlob::new(vec![1], DASourceType::Primary, 0, [0; 32]);

        cache.store(1, blob).unwrap();

        // Multiple gets should increment access_count
        let b1 = cache.get(1).unwrap();
        assert_eq!(b1.get_access_count(), 1);

        let b2 = cache.get(1).unwrap();
        assert_eq!(b2.get_access_count(), 2);

        let b3 = cache.get(1).unwrap();
        assert_eq!(b3.get_access_count(), 3);
    }

    #[test]
    fn test_get_nonexistent_returns_none() {
        let cache = FallbackCache::new();
        assert!(cache.get(999).is_none());
    }

    #[test]
    fn test_remove_blob() {
        let cache = FallbackCache::new();
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let blob = CachedBlob::new(data.clone(), DASourceType::Secondary, 500, [0xFF; 32]);

        cache.store(100, blob).unwrap();
        assert_eq!(cache.total_bytes(), 10);
        assert_eq!(cache.len(), 1);

        // Remove blob
        let removed = cache.remove(100);
        assert!(removed.is_some());

        let removed = removed.unwrap();
        assert_eq!(removed.data, data);
        assert_eq!(removed.source, DASourceType::Secondary);

        // Verify cache state after removal
        assert_eq!(cache.total_bytes(), 0);
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_remove_nonexistent_returns_none() {
        let cache = FallbackCache::new();
        assert!(cache.remove(999).is_none());
        assert_eq!(cache.total_bytes(), 0);
    }

    #[test]
    fn test_contains() {
        let cache = FallbackCache::new();
        let blob = CachedBlob::new(vec![1], DASourceType::Primary, 0, [0; 32]);

        assert!(!cache.contains(1));

        cache.store(1, blob).unwrap();
        assert!(cache.contains(1));
        assert!(!cache.contains(2));
    }

    #[test]
    fn test_list_sequences() {
        let cache = FallbackCache::new();

        // Empty cache
        assert!(cache.list_sequences().is_empty());

        // Add some blobs
        cache.store(10, CachedBlob::new(vec![1], DASourceType::Primary, 0, [0; 32])).unwrap();
        cache.store(20, CachedBlob::new(vec![2], DASourceType::Primary, 0, [0; 32])).unwrap();
        cache.store(30, CachedBlob::new(vec![3], DASourceType::Primary, 0, [0; 32])).unwrap();

        let sequences = cache.list_sequences();
        assert_eq!(sequences.len(), 3);
        assert!(sequences.contains(&10));
        assert!(sequences.contains(&20));
        assert!(sequences.contains(&30));
    }

    #[test]
    fn test_total_bytes_tracking() {
        let cache = FallbackCache::new();

        // Add blobs of different sizes
        cache.store(1, CachedBlob::new(vec![0; 100], DASourceType::Primary, 0, [0; 32])).unwrap();
        assert_eq!(cache.total_bytes(), 100);

        cache.store(2, CachedBlob::new(vec![0; 50], DASourceType::Primary, 0, [0; 32])).unwrap();
        assert_eq!(cache.total_bytes(), 150);

        // Remove one
        cache.remove(1);
        assert_eq!(cache.total_bytes(), 50);

        // Remove another
        cache.remove(2);
        assert_eq!(cache.total_bytes(), 0);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // C. THREAD SAFETY TESTS
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
    fn test_concurrent_access() {
        use std::thread;

        let cache = Arc::new(FallbackCache::new());

        // Store initial blob
        cache.store(1, CachedBlob::new(vec![0; 10], DASourceType::Primary, 0, [0; 32])).unwrap();

        // Spawn multiple reader threads
        let mut handles = vec![];

        for _ in 0..5 {
            let cache_clone = Arc::clone(&cache);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    let _ = cache_clone.get(1);
                    let _ = cache_clone.contains(1);
                    let _ = cache_clone.list_sequences();
                }
            }));
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // Final access count should be 500
        let blob = cache.get(1).unwrap();
        // 500 from threads + 1 from final get = 501
        assert_eq!(blob.get_access_count(), 501);
    }
}