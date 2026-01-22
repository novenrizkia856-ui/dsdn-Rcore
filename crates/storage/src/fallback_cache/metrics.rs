//! Metrics types for FallbackCache (14A.1A.51)

use std::sync::atomic::{AtomicU64, Ordering};

/// Metrics for FallbackCache operations.
#[derive(Debug)]
pub struct CacheMetrics {
    /// Number of cache hits.
    pub hits: AtomicU64,
    /// Number of cache misses.
    pub misses: AtomicU64,
    /// Number of blobs evicted.
    pub evictions: AtomicU64,
    /// Number of blobs inserted.
    pub insertions: AtomicU64,
}

impl CacheMetrics {
    /// Create new CacheMetrics with all counters at zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
            insertions: AtomicU64::new(0),
        }
    }

    /// Get the number of hits.
    #[must_use]
    pub fn get_hits(&self) -> u64 {
        self.hits.load(Ordering::SeqCst)
    }

    /// Get the number of misses.
    #[must_use]
    pub fn get_misses(&self) -> u64 {
        self.misses.load(Ordering::SeqCst)
    }

    /// Get the number of evictions.
    #[must_use]
    pub fn get_evictions(&self) -> u64 {
        self.evictions.load(Ordering::SeqCst)
    }

    /// Get the number of insertions.
    #[must_use]
    pub fn get_insertions(&self) -> u64 {
        self.insertions.load(Ordering::SeqCst)
    }
}

impl Default for CacheMetrics {
    fn default() -> Self {
        Self::new()
    }
}