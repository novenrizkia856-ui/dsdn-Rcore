//! FallbackCache Module (14A.1A.51)
//!
//! Provides caching for DA blobs during fallback operations.

use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
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

pub use blob::{CachedBlob, BlobStorage};
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
    /// Cached blobs indexed by height.
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
        use std::sync::atomic::Ordering;
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
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

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
}