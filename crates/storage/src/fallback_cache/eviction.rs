//! Eviction types for FallbackCache (14A.1A.53)
//!
//! Provides eviction policies and configuration for cache management.

use std::collections::HashMap;
use std::sync::atomic::Ordering;

use super::blob::CachedBlob;

// ════════════════════════════════════════════════════════════════════════════════
// EVICTION POLICY
// ════════════════════════════════════════════════════════════════════════════════

/// Eviction policy for the fallback cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvictionPolicy {
    /// Least Recently Used (approximation using access_count + received_at).
    LRU,
    /// First In First Out - evict oldest received_at first.
    FIFO,
    /// Least Frequently Used - evict lowest access_count first.
    LFU,
}

impl Default for EvictionPolicy {
    fn default() -> Self {
        Self::LRU
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// FALLBACK CACHE CONFIG
// ════════════════════════════════════════════════════════════════════════════════

/// Configuration for FallbackCache.
#[derive(Debug, Clone)]
pub struct FallbackCacheConfig {
    /// Maximum total size of cached blobs in bytes.
    pub max_bytes: u64,
    /// Maximum number of entries (blobs) in cache.
    pub max_entries: usize,
    /// Policy for evicting blobs when limits are reached.
    pub eviction_policy: EvictionPolicy,
    /// Time-to-live in seconds. 0 means TTL DISABLED.
    pub ttl_seconds: u64,
}

impl Default for FallbackCacheConfig {
    fn default() -> Self {
        Self {
            max_bytes: 100 * 1024 * 1024, // 100 MB
            max_entries: 1000,
            eviction_policy: EvictionPolicy::default(),
            ttl_seconds: 0, // TTL disabled by default
        }
    }
}

impl FallbackCacheConfig {
    /// Create a new configuration with specified limits.
    #[must_use]
    pub fn new(max_bytes: u64, max_entries: usize) -> Self {
        Self {
            max_bytes,
            max_entries,
            eviction_policy: EvictionPolicy::default(),
            ttl_seconds: 0,
        }
    }

    /// Set the eviction policy.
    #[must_use]
    pub fn with_eviction_policy(mut self, policy: EvictionPolicy) -> Self {
        self.eviction_policy = policy;
        self
    }

    /// Set the TTL in seconds. 0 means TTL disabled.
    #[must_use]
    pub fn with_ttl_seconds(mut self, ttl: u64) -> Self {
        self.ttl_seconds = ttl;
        self
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// EVICTOR TRAIT
// ════════════════════════════════════════════════════════════════════════════════

/// Trait for eviction policy implementations.
///
/// Implementations must be deterministic and thread-safe.
/// They select candidates for eviction but do NOT perform the eviction.
pub trait Evictor: Send + Sync {
    /// Select blobs for eviction, ordered by eviction priority.
    ///
    /// Returns sequence IDs with most evictable first.
    /// Does NOT modify the cache - read-only operation.
    fn select_for_eviction(&self, blobs: &HashMap<u64, CachedBlob>) -> Vec<u64>;
}

// ════════════════════════════════════════════════════════════════════════════════
// LRU EVICTOR
// ════════════════════════════════════════════════════════════════════════════════

/// LRU evictor implementation.
///
/// Approximation using access_count and received_at since we don't have
/// last_accessed timestamp.
///
/// Sort order: access_count ASC, received_at ASC, sequence ASC
/// (lowest access count first, oldest received first, deterministic by sequence)
pub struct LRUEvictor;

impl Evictor for LRUEvictor {
    fn select_for_eviction(&self, blobs: &HashMap<u64, CachedBlob>) -> Vec<u64> {
        let mut entries: Vec<(u64, u32, u64)> = blobs
            .iter()
            .map(|(&seq, blob)| {
                let access_count = blob.access_count.load(Ordering::SeqCst);
                (seq, access_count, blob.received_at)
            })
            .collect();

        // Sort by: access_count ASC, received_at ASC, sequence ASC
        entries.sort_by(|a, b| {
            a.1.cmp(&b.1) // access_count ASC
                .then_with(|| a.2.cmp(&b.2)) // received_at ASC
                .then_with(|| a.0.cmp(&b.0)) // sequence ASC
        });

        entries.into_iter().map(|(seq, _, _)| seq).collect()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// FIFO EVICTOR
// ════════════════════════════════════════════════════════════════════════════════

/// FIFO evictor implementation.
///
/// Evicts blobs with oldest received_at first.
///
/// Sort order: received_at ASC, sequence ASC
pub struct FIFOEvictor;

impl Evictor for FIFOEvictor {
    fn select_for_eviction(&self, blobs: &HashMap<u64, CachedBlob>) -> Vec<u64> {
        let mut entries: Vec<(u64, u64)> = blobs
            .iter()
            .map(|(&seq, blob)| (seq, blob.received_at))
            .collect();

        // Sort by: received_at ASC, sequence ASC
        entries.sort_by(|a, b| {
            a.1.cmp(&b.1) // received_at ASC
                .then_with(|| a.0.cmp(&b.0)) // sequence ASC
        });

        entries.into_iter().map(|(seq, _)| seq).collect()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// LFU EVICTOR
// ════════════════════════════════════════════════════════════════════════════════

/// LFU evictor implementation.
///
/// Evicts blobs with lowest access_count first.
///
/// Sort order: access_count ASC, sequence ASC
pub struct LFUEvictor;

impl Evictor for LFUEvictor {
    fn select_for_eviction(&self, blobs: &HashMap<u64, CachedBlob>) -> Vec<u64> {
        let mut entries: Vec<(u64, u32)> = blobs
            .iter()
            .map(|(&seq, blob)| {
                let access_count = blob.access_count.load(Ordering::SeqCst);
                (seq, access_count)
            })
            .collect();

        // Sort by: access_count ASC, sequence ASC
        entries.sort_by(|a, b| {
            a.1.cmp(&b.1) // access_count ASC
                .then_with(|| a.0.cmp(&b.0)) // sequence ASC
        });

        entries.into_iter().map(|(seq, _)| seq).collect()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// FACTORY FUNCTION
// ════════════════════════════════════════════════════════════════════════════════

/// Create an evictor based on the policy.
///
/// Match is exhaustive - no default branch.
#[must_use]
pub fn create_evictor(policy: EvictionPolicy) -> Box<dyn Evictor> {
    match policy {
        EvictionPolicy::LRU => Box::new(LRUEvictor),
        EvictionPolicy::FIFO => Box::new(FIFOEvictor),
        EvictionPolicy::LFU => Box::new(LFUEvictor),
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fallback_cache::blob::DASourceType;

    fn make_blob(received_at: u64, access_count: u32) -> CachedBlob {
        let blob = CachedBlob::new(vec![0; 10], DASourceType::Primary, received_at, [0; 32]);
        blob.access_count
            .store(access_count, Ordering::SeqCst);
        blob
    }

    // ════════════════════════════════════════════════════════════════════════════
    // A. LRU EVICTION TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_lru_evicts_lowest_access_count_first() {
        let mut blobs = HashMap::new();
        blobs.insert(1, make_blob(1000, 10)); // access_count=10
        blobs.insert(2, make_blob(1000, 5)); // access_count=5 ← lowest
        blobs.insert(3, make_blob(1000, 15)); // access_count=15

        let evictor = LRUEvictor;
        let candidates = evictor.select_for_eviction(&blobs);

        assert_eq!(candidates[0], 2); // lowest access_count first
    }

    #[test]
    fn test_lru_tiebreak_by_received_at() {
        let mut blobs = HashMap::new();
        blobs.insert(1, make_blob(2000, 5)); // same access_count, newer
        blobs.insert(2, make_blob(1000, 5)); // same access_count, older ← first
        blobs.insert(3, make_blob(3000, 5)); // same access_count, newest

        let evictor = LRUEvictor;
        let candidates = evictor.select_for_eviction(&blobs);

        assert_eq!(candidates[0], 2); // oldest received_at when access_count tie
    }

    #[test]
    fn test_lru_tiebreak_by_sequence() {
        let mut blobs = HashMap::new();
        blobs.insert(3, make_blob(1000, 5)); // same everything, higher seq
        blobs.insert(1, make_blob(1000, 5)); // same everything, lower seq ← first
        blobs.insert(2, make_blob(1000, 5)); // same everything, middle seq

        let evictor = LRUEvictor;
        let candidates = evictor.select_for_eviction(&blobs);

        assert_eq!(candidates[0], 1); // lowest sequence when all else equal
        assert_eq!(candidates[1], 2);
        assert_eq!(candidates[2], 3);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // B. FIFO EVICTION TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_fifo_evicts_oldest_received_first() {
        let mut blobs = HashMap::new();
        blobs.insert(1, make_blob(2000, 10)); // newer
        blobs.insert(2, make_blob(1000, 5)); // oldest ← first
        blobs.insert(3, make_blob(3000, 15)); // newest

        let evictor = FIFOEvictor;
        let candidates = evictor.select_for_eviction(&blobs);

        assert_eq!(candidates[0], 2); // oldest received_at first
    }

    #[test]
    fn test_fifo_tiebreak_by_sequence() {
        let mut blobs = HashMap::new();
        blobs.insert(3, make_blob(1000, 10)); // same received_at, higher seq
        blobs.insert(1, make_blob(1000, 5)); // same received_at, lower seq ← first
        blobs.insert(2, make_blob(1000, 15)); // same received_at, middle seq

        let evictor = FIFOEvictor;
        let candidates = evictor.select_for_eviction(&blobs);

        assert_eq!(candidates[0], 1); // lowest sequence when received_at tie
        assert_eq!(candidates[1], 2);
        assert_eq!(candidates[2], 3);
    }

    #[test]
    fn test_fifo_ignores_access_count() {
        let mut blobs = HashMap::new();
        blobs.insert(1, make_blob(2000, 0)); // newer, no accesses
        blobs.insert(2, make_blob(1000, 100)); // older, many accesses ← still first

        let evictor = FIFOEvictor;
        let candidates = evictor.select_for_eviction(&blobs);

        assert_eq!(candidates[0], 2); // oldest first regardless of access_count
    }

    // ════════════════════════════════════════════════════════════════════════════
    // C. LFU EVICTION TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_lfu_evicts_lowest_access_count_first() {
        let mut blobs = HashMap::new();
        blobs.insert(1, make_blob(1000, 10)); // access_count=10
        blobs.insert(2, make_blob(2000, 5)); // access_count=5 ← lowest
        blobs.insert(3, make_blob(3000, 15)); // access_count=15

        let evictor = LFUEvictor;
        let candidates = evictor.select_for_eviction(&blobs);

        assert_eq!(candidates[0], 2); // lowest access_count first
    }

    #[test]
    fn test_lfu_tiebreak_by_sequence() {
        let mut blobs = HashMap::new();
        blobs.insert(3, make_blob(1000, 5)); // same access_count, higher seq
        blobs.insert(1, make_blob(2000, 5)); // same access_count, lower seq ← first
        blobs.insert(2, make_blob(3000, 5)); // same access_count, middle seq

        let evictor = LFUEvictor;
        let candidates = evictor.select_for_eviction(&blobs);

        assert_eq!(candidates[0], 1); // lowest sequence when access_count tie
        assert_eq!(candidates[1], 2);
        assert_eq!(candidates[2], 3);
    }

    #[test]
    fn test_lfu_ignores_received_at() {
        let mut blobs = HashMap::new();
        blobs.insert(1, make_blob(1000, 10)); // older, higher access
        blobs.insert(2, make_blob(9000, 5)); // newest, lower access ← first

        let evictor = LFUEvictor;
        let candidates = evictor.select_for_eviction(&blobs);

        assert_eq!(candidates[0], 2); // lowest access first regardless of received_at
    }

    // ════════════════════════════════════════════════════════════════════════════
    // D. FACTORY TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_create_evictor_lru() {
        let evictor = create_evictor(EvictionPolicy::LRU);
        let mut blobs = HashMap::new();
        blobs.insert(1, make_blob(1000, 5));
        blobs.insert(2, make_blob(1000, 10));

        let candidates = evictor.select_for_eviction(&blobs);
        assert_eq!(candidates[0], 1); // LRU: lowest access_count
    }

    #[test]
    fn test_create_evictor_fifo() {
        let evictor = create_evictor(EvictionPolicy::FIFO);
        let mut blobs = HashMap::new();
        blobs.insert(1, make_blob(2000, 5));
        blobs.insert(2, make_blob(1000, 10));

        let candidates = evictor.select_for_eviction(&blobs);
        assert_eq!(candidates[0], 2); // FIFO: oldest received_at
    }

    #[test]
    fn test_create_evictor_lfu() {
        let evictor = create_evictor(EvictionPolicy::LFU);
        let mut blobs = HashMap::new();
        blobs.insert(1, make_blob(1000, 10));
        blobs.insert(2, make_blob(2000, 5));

        let candidates = evictor.select_for_eviction(&blobs);
        assert_eq!(candidates[0], 2); // LFU: lowest access_count
    }

    // ════════════════════════════════════════════════════════════════════════════
    // E. CONFIG TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_config_default() {
        let config = FallbackCacheConfig::default();

        assert_eq!(config.max_bytes, 100 * 1024 * 1024);
        assert_eq!(config.max_entries, 1000);
        assert_eq!(config.eviction_policy, EvictionPolicy::LRU);
        assert_eq!(config.ttl_seconds, 0); // TTL disabled
    }

    #[test]
    fn test_config_new() {
        let config = FallbackCacheConfig::new(1024, 10);

        assert_eq!(config.max_bytes, 1024);
        assert_eq!(config.max_entries, 10);
        assert_eq!(config.eviction_policy, EvictionPolicy::LRU);
        assert_eq!(config.ttl_seconds, 0);
    }

    #[test]
    fn test_config_with_eviction_policy() {
        let config = FallbackCacheConfig::default().with_eviction_policy(EvictionPolicy::FIFO);

        assert_eq!(config.eviction_policy, EvictionPolicy::FIFO);
    }

    #[test]
    fn test_config_with_ttl() {
        let config = FallbackCacheConfig::default().with_ttl_seconds(3600);

        assert_eq!(config.ttl_seconds, 3600);
    }

    #[test]
    fn test_config_ttl_zero_means_disabled() {
        let config = FallbackCacheConfig::default();
        assert_eq!(config.ttl_seconds, 0); // Confirms TTL disabled by default
    }

    // ════════════════════════════════════════════════════════════════════════════
    // F. DETERMINISM TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_eviction_is_deterministic() {
        let mut blobs = HashMap::new();
        blobs.insert(5, make_blob(1000, 5));
        blobs.insert(3, make_blob(1000, 5));
        blobs.insert(7, make_blob(1000, 5));
        blobs.insert(1, make_blob(1000, 5));

        let evictor = LRUEvictor;

        // Run multiple times - should always produce same order
        let result1 = evictor.select_for_eviction(&blobs);
        let result2 = evictor.select_for_eviction(&blobs);
        let result3 = evictor.select_for_eviction(&blobs);

        assert_eq!(result1, result2);
        assert_eq!(result2, result3);
        assert_eq!(result1, vec![1, 3, 5, 7]); // Sorted by sequence
    }

    #[test]
    fn test_empty_blobs_returns_empty() {
        let blobs = HashMap::new();

        assert!(LRUEvictor.select_for_eviction(&blobs).is_empty());
        assert!(FIFOEvictor.select_for_eviction(&blobs).is_empty());
        assert!(LFUEvictor.select_for_eviction(&blobs).is_empty());
    }
}