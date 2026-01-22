//! Blob types for FallbackCache (14A.1A.52)
//!
//! Provides core types for cached blob data and storage operations.

use std::sync::atomic::{AtomicU32, Ordering};

// ════════════════════════════════════════════════════════════════════════════════
// DA SOURCE TYPE
// ════════════════════════════════════════════════════════════════════════════════

/// Type of DA source that provided the blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DASourceType {
    /// Primary DA source (e.g., Celestia).
    Primary,
    /// Secondary/backup DA source.
    Secondary,
    /// Emergency fallback DA source.
    Emergency,
}

// ════════════════════════════════════════════════════════════════════════════════
// CACHE ERROR
// ════════════════════════════════════════════════════════════════════════════════

/// Error type for cache operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheError {
    /// Blob with this sequence already exists.
    AlreadyExists(u64),
    /// RwLock was poisoned.
    LockPoisoned,
}

impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyExists(seq) => write!(f, "blob with sequence {} already exists", seq),
            Self::LockPoisoned => write!(f, "lock poisoned"),
        }
    }
}

impl std::error::Error for CacheError {}

// ════════════════════════════════════════════════════════════════════════════════
// CACHED BLOB
// ════════════════════════════════════════════════════════════════════════════════

/// A cached blob from the DA layer.
///
/// Contains blob data along with metadata for cache management.
///
/// ## Thread Safety
///
/// - `access_count` is AtomicU32 for lock-free increment during get operations
/// - Other fields are immutable after construction
pub struct CachedBlob {
    /// Raw blob data.
    pub data: Vec<u8>,
    /// Source type that provided this blob.
    pub source: DASourceType,
    /// Timestamp when blob was received (Unix ms).
    pub received_at: u64,
    /// Number of times this blob has been accessed.
    pub access_count: AtomicU32,
    /// SHA3-256 hash of the blob data.
    pub hash: [u8; 32],
}

impl CachedBlob {
    /// Create a new CachedBlob.
    ///
    /// ## Arguments
    ///
    /// * `data` - Raw blob bytes
    /// * `source` - DA source type
    /// * `received_at` - Timestamp (Unix ms)
    /// * `hash` - SHA3-256 hash of data
    #[must_use]
    pub fn new(data: Vec<u8>, source: DASourceType, received_at: u64, hash: [u8; 32]) -> Self {
        Self {
            data,
            source,
            received_at,
            access_count: AtomicU32::new(0),
            hash,
        }
    }

    /// Get the current access count.
    #[must_use]
    pub fn get_access_count(&self) -> u32 {
        self.access_count.load(Ordering::SeqCst)
    }

    /// Get the size of the blob data in bytes.
    #[must_use]
    pub fn size(&self) -> usize {
        self.data.len()
    }
}

impl Clone for CachedBlob {
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
            source: self.source,
            received_at: self.received_at,
            access_count: AtomicU32::new(self.access_count.load(Ordering::SeqCst)),
            hash: self.hash,
        }
    }
}

impl std::fmt::Debug for CachedBlob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedBlob")
            .field("data_len", &self.data.len())
            .field("source", &self.source)
            .field("received_at", &self.received_at)
            .field("access_count", &self.access_count.load(Ordering::SeqCst))
            .field("hash", &self.hash)
            .finish()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// BLOB STORAGE TRAIT
// ════════════════════════════════════════════════════════════════════════════════

/// Trait for blob storage backends.
///
/// Defines the interface for storing and retrieving cached blobs.
/// All methods must be thread-safe.
pub trait BlobStorage: Send + Sync {
    /// Store a blob at the given sequence number.
    ///
    /// ## Errors
    ///
    /// Returns `CacheError::AlreadyExists` if a blob with this sequence already exists.
    fn store(&self, sequence: u64, blob: CachedBlob) -> Result<(), CacheError>;

    /// Get a blob by sequence number.
    ///
    /// Increments the blob's access_count atomically.
    /// Returns None if blob is not found.
    fn get(&self, sequence: u64) -> Option<CachedBlob>;

    /// Remove and return a blob by sequence number.
    ///
    /// Returns None if blob is not found.
    fn remove(&self, sequence: u64) -> Option<CachedBlob>;

    /// Check if a blob exists at the given sequence number.
    ///
    /// Read-only operation with no side effects.
    fn contains(&self, sequence: u64) -> bool;

    /// List all sequence numbers in the cache.
    ///
    /// Returns a snapshot of current sequences.
    /// Order is not guaranteed.
    fn list_sequences(&self) -> Vec<u64>;
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cached_blob_new() {
        let data = vec![1, 2, 3, 4, 5];
        let hash = [0xABu8; 32];
        let blob = CachedBlob::new(data.clone(), DASourceType::Primary, 1234567890, hash);

        assert_eq!(blob.data, data);
        assert_eq!(blob.source, DASourceType::Primary);
        assert_eq!(blob.received_at, 1234567890);
        assert_eq!(blob.get_access_count(), 0);
        assert_eq!(blob.hash, hash);
        assert_eq!(blob.size(), 5);
    }

    #[test]
    fn test_cached_blob_clone() {
        let blob = CachedBlob::new(
            vec![1, 2, 3],
            DASourceType::Secondary,
            999,
            [0x11; 32],
        );

        // Increment access count
        blob.access_count.fetch_add(5, Ordering::SeqCst);

        let cloned = blob.clone();

        assert_eq!(cloned.data, blob.data);
        assert_eq!(cloned.source, blob.source);
        assert_eq!(cloned.received_at, blob.received_at);
        assert_eq!(cloned.get_access_count(), 5);
        assert_eq!(cloned.hash, blob.hash);
    }

    #[test]
    fn test_cached_blob_access_count_atomic() {
        let blob = CachedBlob::new(vec![1], DASourceType::Emergency, 0, [0; 32]);

        assert_eq!(blob.get_access_count(), 0);

        blob.access_count.fetch_add(1, Ordering::SeqCst);
        assert_eq!(blob.get_access_count(), 1);

        blob.access_count.fetch_add(10, Ordering::SeqCst);
        assert_eq!(blob.get_access_count(), 11);
    }

    #[test]
    fn test_da_source_type_copy() {
        let source = DASourceType::Primary;
        let copied = source;
        assert_eq!(source, copied);
    }

    #[test]
    fn test_cache_error_display() {
        let err1 = CacheError::AlreadyExists(42);
        assert_eq!(format!("{}", err1), "blob with sequence 42 already exists");

        let err2 = CacheError::LockPoisoned;
        assert_eq!(format!("{}", err2), "lock poisoned");
    }

    #[test]
    fn test_cached_blob_hash_unchanged() {
        let hash = [0xFFu8; 32];
        let blob = CachedBlob::new(vec![1, 2, 3], DASourceType::Primary, 100, hash);

        // Access blob multiple times
        blob.access_count.fetch_add(1, Ordering::SeqCst);
        blob.access_count.fetch_add(1, Ordering::SeqCst);

        // Hash should remain unchanged
        assert_eq!(blob.hash, hash);
    }

    #[test]
    fn test_cached_blob_source_preserved() {
        let blob_primary = CachedBlob::new(vec![], DASourceType::Primary, 0, [0; 32]);
        let blob_secondary = CachedBlob::new(vec![], DASourceType::Secondary, 0, [0; 32]);
        let blob_emergency = CachedBlob::new(vec![], DASourceType::Emergency, 0, [0; 32]);

        assert_eq!(blob_primary.source, DASourceType::Primary);
        assert_eq!(blob_secondary.source, DASourceType::Secondary);
        assert_eq!(blob_emergency.source, DASourceType::Emergency);
    }

    #[test]
    fn test_cached_blob_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<CachedBlob>();
    }

    #[test]
    fn test_cached_blob_is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<CachedBlob>();
    }
}