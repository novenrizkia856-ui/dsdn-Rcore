//! Blob types for FallbackCache (14A.1A.51)

/// A cached blob from the DA layer.
#[derive(Debug, Clone)]
pub struct CachedBlob {
    /// DA height where this blob was published.
    pub height: u64,
    /// Raw blob data.
    pub data: Vec<u8>,
    /// Timestamp when blob was cached (Unix ms).
    pub cached_at: u64,
    /// Size in bytes.
    pub size_bytes: u64,
}

impl CachedBlob {
    /// Create a new CachedBlob.
    #[must_use]
    pub fn new(height: u64, data: Vec<u8>, cached_at: u64) -> Self {
        let size_bytes = data.len() as u64;
        Self {
            height,
            data,
            cached_at,
            size_bytes,
        }
    }
}

/// Trait for blob storage backends.
pub trait BlobStorage: Send + Sync {
    /// Get a blob by height.
    fn get(&self, height: u64) -> Option<CachedBlob>;
    /// Check if a blob is cached.
    fn contains(&self, height: u64) -> bool;
    /// Get the number of cached blobs.
    fn len(&self) -> usize;
    /// Check if cache is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}