//! Eviction types for FallbackCache (14A.1A.51)

/// Eviction policy for the fallback cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvictionPolicy {
    /// Least Recently Used.
    Lru,
    /// First In First Out.
    Fifo,
    /// Evict largest blobs first.
    Size,
}

impl Default for EvictionPolicy {
    fn default() -> Self {
        Self::Lru
    }
}

/// Configuration for FallbackCache.
#[derive(Debug, Clone)]
pub struct FallbackCacheConfig {
    /// Maximum total size of cached blobs in bytes.
    pub max_bytes: u64,
    /// Maximum number of blobs to cache.
    pub max_blobs: usize,
    /// Policy for evicting blobs when limits are reached.
    pub eviction_policy: EvictionPolicy,
}

impl Default for FallbackCacheConfig {
    fn default() -> Self {
        Self {
            max_bytes: 100 * 1024 * 1024, // 100 MB
            max_blobs: 1000,
            eviction_policy: EvictionPolicy::default(),
        }
    }
}

impl FallbackCacheConfig {
    /// Create a new configuration with specified limits.
    #[must_use]
    pub fn new(max_bytes: u64, max_blobs: usize) -> Self {
        Self {
            max_bytes,
            max_blobs,
            eviction_policy: EvictionPolicy::default(),
        }
    }

    /// Set the eviction policy.
    #[must_use]
    pub fn with_eviction_policy(mut self, policy: EvictionPolicy) -> Self {
        self.eviction_policy = policy;
        self
    }
}