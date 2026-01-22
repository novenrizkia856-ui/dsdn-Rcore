//! Cache Persistence Module (14A.1A.57)
//!
//! Provides optional persistence for FallbackCache.
//!
//! ## Features
//!
//! - Append-only log format for durability
//! - Atomic writes with CRC32 checksums
//! - Graceful crash recovery (corrupted tail skipped)
//! - Optional background sync
//!
//! ## Entry Format (AppendLog)
//!
//! ```text
//! [magic: 4 bytes][version: 1 byte][length: 4 bytes]
//! [sequence: 8 bytes][received_at: 8 bytes][source: 1 byte]
//! [hash: 32 bytes][data: variable][crc32: 4 bytes]
//! ```

use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::fallback_cache::blob::{CachedBlob, DASourceType};

// ════════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════════

/// Magic bytes for append log entries.
const MAGIC: [u8; 4] = [0xDA, 0xFB, 0xCA, 0xCE];

/// Current format version.
const VERSION: u8 = 1;

/// Minimum entry size (header + crc, no data).
const MIN_ENTRY_SIZE: usize = 4 + 1 + 4 + 8 + 8 + 1 + 32 + 4; // 62 bytes

// ════════════════════════════════════════════════════════════════════════════════
// PERSISTENCE ERROR
// ════════════════════════════════════════════════════════════════════════════════

/// Error type for persistence operations.
#[derive(Debug)]
pub enum PersistError {
    /// IO error during read/write.
    Io(std::io::Error),
    /// Data corruption detected.
    Corrupted(String),
    /// Unsupported persistence format.
    UnsupportedFormat(String),
    /// Invalid header in entry.
    InvalidHeader(String),
    /// Serialization error.
    Serialization(String),
}

impl std::fmt::Display for PersistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO error: {}", e),
            Self::Corrupted(msg) => write!(f, "data corrupted: {}", msg),
            Self::UnsupportedFormat(fmt) => write!(f, "unsupported format: {}", fmt),
            Self::InvalidHeader(msg) => write!(f, "invalid header: {}", msg),
            Self::Serialization(msg) => write!(f, "serialization error: {}", msg),
        }
    }
}

impl std::error::Error for PersistError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for PersistError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// PERSISTENCE FORMAT
// ════════════════════════════════════════════════════════════════════════════════

/// Persistence format options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PersistenceFormat {
    /// Append-only log format (implemented).
    #[default]
    AppendLog,
    /// RocksDB format (placeholder, not implemented).
    RocksDB,
}

// ════════════════════════════════════════════════════════════════════════════════
// PERSISTENCE CONFIG
// ════════════════════════════════════════════════════════════════════════════════

/// Configuration for cache persistence.
#[derive(Debug, Clone)]
pub struct PersistenceConfig {
    /// Path to persistence file/directory.
    pub path: PathBuf,
    /// Background sync interval in milliseconds (0 = disabled).
    pub sync_interval_ms: u64,
    /// Persistence format.
    pub format: PersistenceFormat,
}

impl PersistenceConfig {
    /// Create a new PersistenceConfig.
    ///
    /// ## Arguments
    ///
    /// * `path` - Path to persistence file
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            sync_interval_ms: 0,
            format: PersistenceFormat::AppendLog,
        }
    }

    /// Set the sync interval in milliseconds.
    ///
    /// If 0, background sync is disabled.
    #[must_use]
    pub fn with_sync_interval_ms(mut self, interval: u64) -> Self {
        self.sync_interval_ms = interval;
        self
    }

    /// Set the persistence format.
    #[must_use]
    pub fn with_format(mut self, format: PersistenceFormat) -> Self {
        self.format = format;
        self
    }

    /// Check if background sync is enabled.
    #[must_use]
    pub fn is_background_sync_enabled(&self) -> bool {
        self.sync_interval_ms > 0
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// CACHE PERSISTENCE TRAIT
// ════════════════════════════════════════════════════════════════════════════════

/// Trait for cache persistence backends.
///
/// ## Contract
///
/// - persist() must not block cache operations for extended periods
/// - restore() must be idempotent
/// - Implementations must handle corrupted data gracefully
/// - No panic or unwrap allowed
pub trait CachePersistence: Send + Sync {
    /// Persist all blobs from the cache.
    ///
    /// ## Errors
    ///
    /// Returns `PersistError` on failure.
    fn persist(&self, blobs: &[(u64, CachedBlob)]) -> Result<(), PersistError>;

    /// Restore blobs from persistence.
    ///
    /// ## Returns
    ///
    /// Vector of (sequence, blob) pairs.
    /// Corrupted entries are skipped, not treated as fatal errors.
    ///
    /// ## Errors
    ///
    /// Returns `PersistError` only for unrecoverable errors.
    fn restore(&self) -> Result<Vec<(u64, CachedBlob)>, PersistError>;
}

// ════════════════════════════════════════════════════════════════════════════════
// CRC32 COMPUTATION
// ════════════════════════════════════════════════════════════════════════════════

/// Compute CRC32 checksum for data.
fn compute_crc32(data: &[u8]) -> u32 {
    // CRC32 IEEE polynomial
    const POLYNOMIAL: u32 = 0xEDB88320;

    let mut crc: u32 = 0xFFFFFFFF;

    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ POLYNOMIAL;
            } else {
                crc >>= 1;
            }
        }
    }

    !crc
}

// ════════════════════════════════════════════════════════════════════════════════
// APPEND LOG PERSISTENCE
// ════════════════════════════════════════════════════════════════════════════════

/// Append-only log persistence implementation.
///
/// ## Format
///
/// Each entry is written atomically with:
/// - Magic bytes (4 bytes)
/// - Version (1 byte)
/// - Entry length (4 bytes, little-endian)
/// - Sequence number (8 bytes, little-endian)
/// - Received timestamp (8 bytes, little-endian)
/// - Source type (1 byte)
/// - Hash (32 bytes)
/// - Data (variable length)
/// - CRC32 checksum (4 bytes, little-endian)
pub struct AppendLogPersistence {
    /// Persistence configuration.
    config: PersistenceConfig,
}

impl AppendLogPersistence {
    /// Create a new AppendLogPersistence.
    #[must_use]
    pub fn new(config: PersistenceConfig) -> Self {
        Self { config }
    }

    /// Serialize a single entry to bytes.
    fn serialize_entry(sequence: u64, blob: &CachedBlob) -> Vec<u8> {
        // Calculate total entry size
        let data_len = blob.data.len();
        let entry_len = 8 + 8 + 1 + 32 + data_len; // sequence + received_at + source + hash + data

        let mut buffer = Vec::with_capacity(4 + 1 + 4 + entry_len + 4);

        // Magic
        buffer.extend_from_slice(&MAGIC);

        // Version
        buffer.push(VERSION);

        // Entry length (excluding magic, version, length itself, and crc)
        buffer.extend_from_slice(&(entry_len as u32).to_le_bytes());

        // Sequence
        buffer.extend_from_slice(&sequence.to_le_bytes());

        // Received at
        buffer.extend_from_slice(&blob.received_at.to_le_bytes());

        // Source type
        let source_byte = match blob.source {
            DASourceType::Primary => 0u8,
            DASourceType::Secondary => 1u8,
            DASourceType::Emergency => 2u8,
        };
        buffer.push(source_byte);

        // Hash
        buffer.extend_from_slice(&blob.hash);

        // Data
        buffer.extend_from_slice(&blob.data);

        // Compute CRC32 over everything except magic and crc itself
        let crc_data = &buffer[4..]; // Skip magic
        let crc = compute_crc32(crc_data);
        buffer.extend_from_slice(&crc.to_le_bytes());

        buffer
    }

    /// Deserialize a single entry from a reader.
    ///
    /// Returns None if entry is corrupted or incomplete.
    fn deserialize_entry<R: Read>(reader: &mut R) -> Option<(u64, CachedBlob)> {
        // Read magic
        let mut magic = [0u8; 4];
        if reader.read_exact(&mut magic).is_err() {
            return None;
        }

        if magic != MAGIC {
            return None;
        }

        // Read version
        let mut version = [0u8; 1];
        if reader.read_exact(&mut version).is_err() {
            return None;
        }

        if version[0] != VERSION {
            return None; // Skip unknown versions
        }

        // Read entry length
        let mut len_bytes = [0u8; 4];
        if reader.read_exact(&mut len_bytes).is_err() {
            return None;
        }
        let entry_len = u32::from_le_bytes(len_bytes) as usize;

        // Sanity check
        if entry_len < MIN_ENTRY_SIZE - 4 - 1 - 4 - 4 {
            // Minimum: sequence + received_at + source + hash
            return None;
        }

        // Read entry data
        let mut entry_data = vec![0u8; entry_len];
        if reader.read_exact(&mut entry_data).is_err() {
            return None;
        }

        // Read CRC
        let mut crc_bytes = [0u8; 4];
        if reader.read_exact(&mut crc_bytes).is_err() {
            return None;
        }
        let stored_crc = u32::from_le_bytes(crc_bytes);

        // Verify CRC
        let mut crc_data = Vec::with_capacity(1 + 4 + entry_len);
        crc_data.push(VERSION);
        crc_data.extend_from_slice(&len_bytes);
        crc_data.extend_from_slice(&entry_data);

        let computed_crc = compute_crc32(&crc_data);
        if computed_crc != stored_crc {
            return None; // Corrupted entry
        }

        // Parse entry data
        if entry_data.len() < 8 + 8 + 1 + 32 {
            return None;
        }

        let sequence = u64::from_le_bytes(entry_data[0..8].try_into().ok()?);
        let received_at = u64::from_le_bytes(entry_data[8..16].try_into().ok()?);

        let source = match entry_data[16] {
            0 => DASourceType::Primary,
            1 => DASourceType::Secondary,
            2 => DASourceType::Emergency,
            _ => return None,
        };

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&entry_data[17..49]);

        let data = entry_data[49..].to_vec();

        let blob = CachedBlob::new(data, source, received_at, hash);

        Some((sequence, blob))
    }
}

impl CachePersistence for AppendLogPersistence {
    fn persist(&self, blobs: &[(u64, CachedBlob)]) -> Result<(), PersistError> {
        // Create parent directories if needed
        if let Some(parent) = self.config.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        // Write to temp file first for atomicity
        let temp_path = self.config.path.with_extension("tmp");

        {
            let mut file = std::fs::File::create(&temp_path)?;

            for (sequence, blob) in blobs {
                let entry = Self::serialize_entry(*sequence, blob);
                file.write_all(&entry)?;
            }

            // Sync to disk
            file.sync_all()?;
        }

        // Atomic rename
        std::fs::rename(&temp_path, &self.config.path)?;

        Ok(())
    }

    fn restore(&self) -> Result<Vec<(u64, CachedBlob)>, PersistError> {
        // Check if file exists
        if !self.config.path.exists() {
            return Ok(Vec::new());
        }

        let file = std::fs::File::open(&self.config.path)?;
        let mut reader = std::io::BufReader::new(file);

        let mut blobs = Vec::new();

        // Read entries until EOF or corruption
        loop {
            match Self::deserialize_entry(&mut reader) {
                Some((sequence, blob)) => {
                    blobs.push((sequence, blob));
                }
                None => {
                    // EOF or corrupted entry - stop reading
                    break;
                }
            }
        }

        Ok(blobs)
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// PERSISTENCE FACTORY
// ════════════════════════════════════════════════════════════════════════════════

/// Create a persistence backend based on config.
///
/// ## Errors
///
/// Returns `PersistError::UnsupportedFormat` for RocksDB.
pub fn create_persistence(
    config: PersistenceConfig,
) -> Result<Box<dyn CachePersistence>, PersistError> {
    match config.format {
        PersistenceFormat::AppendLog => Ok(Box::new(AppendLogPersistence::new(config))),
        PersistenceFormat::RocksDB => Err(PersistError::UnsupportedFormat(
            "RocksDB is not implemented".to_string(),
        )),
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// BACKGROUND SYNC HANDLE
// ════════════════════════════════════════════════════════════════════════════════

/// Handle for managing background sync task.
pub struct BackgroundSyncHandle {
    /// Shutdown signal.
    shutdown: Arc<AtomicBool>,
    /// Join handle for the background thread.
    handle: Option<std::thread::JoinHandle<()>>,
}

impl BackgroundSyncHandle {
    /// Create a new inactive handle.
    fn new() -> Self {
        Self {
            shutdown: Arc::new(AtomicBool::new(false)),
            handle: None,
        }
    }

    /// Check if background sync is running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.handle.is_some()
    }

    /// Signal shutdown.
    pub fn signal_shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Wait for the background task to complete.
    pub fn join(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// PERSISTENT FALLBACK CACHE (Sync version using std::thread)
// ════════════════════════════════════════════════════════════════════════════════

/// Wrapper providing persistence for FallbackCache.
///
/// ## Design
///
/// - `inner` is the single source of truth
/// - Persistence is optional background operation
/// - Background sync can be started/stopped
pub struct PersistentFallbackCache {
    /// Inner cache (source of truth).
    inner: Arc<crate::fallback_cache::FallbackCache>,
    /// Persistence backend.
    persistence: Arc<dyn CachePersistence>,
    /// Background sync handle.
    background_handle: BackgroundSyncHandle,
    /// Persistence config (for interval).
    config: PersistenceConfig,
}

impl PersistentFallbackCache {
    /// Create a new PersistentFallbackCache.
    ///
    /// ## Errors
    ///
    /// Returns error if persistence format is unsupported.
    pub fn new(
        cache: crate::fallback_cache::FallbackCache,
        config: PersistenceConfig,
    ) -> Result<Self, PersistError> {
        let persistence = create_persistence(config.clone())?;

        Ok(Self {
            inner: Arc::new(cache),
            persistence: Arc::from(persistence),
            background_handle: BackgroundSyncHandle::new(),
            config,
        })
    }

    /// Get a reference to the inner cache.
    #[must_use]
    pub fn cache(&self) -> &crate::fallback_cache::FallbackCache {
        &self.inner
    }

    /// Get an Arc reference to the inner cache.
    #[must_use]
    pub fn cache_arc(&self) -> Arc<crate::fallback_cache::FallbackCache> {
        Arc::clone(&self.inner)
    }

    /// Persist the current cache state.
    ///
    /// ## Errors
    ///
    /// Returns `PersistError` on failure.
    pub fn persist(&self) -> Result<(), PersistError> {
        use crate::fallback_cache::BlobStorage;

        // Get snapshot of blobs
        let sequences = self.inner.list_sequences();
        let mut blobs = Vec::with_capacity(sequences.len());

        for seq in sequences {
            if let Some(blob) = self.inner.get(seq) {
                blobs.push((seq, blob));
            }
        }

        self.persistence.persist(&blobs)
    }

    /// Restore blobs from persistence into the cache.
    ///
    /// ## Errors
    ///
    /// Returns `PersistError` on failure.
    pub fn restore(&self) -> Result<usize, PersistError> {
        use crate::fallback_cache::BlobStorage;

        let blobs = self.persistence.restore()?;
        let mut restored = 0;

        for (sequence, blob) in blobs {
            if self.inner.store(sequence, blob).is_ok() {
                restored += 1;
            }
        }

        Ok(restored)
    }

    /// Start background sync task.
    ///
    /// ## Behavior
    ///
    /// - Spawns a thread that periodically persists the cache
    /// - No-op if background sync is disabled (interval = 0)
    /// - No-op if already running
    pub fn start_background_sync(&mut self) {
        // Check if already running
        if self.background_handle.is_running() {
            return;
        }

        // Check if enabled
        if !self.config.is_background_sync_enabled() {
            return;
        }

        let interval_ms = self.config.sync_interval_ms;
        let shutdown = Arc::clone(&self.background_handle.shutdown);
        let cache = Arc::clone(&self.inner);
        let persistence = Arc::clone(&self.persistence);

        // Reset shutdown flag
        shutdown.store(false, Ordering::SeqCst);

        let handle = std::thread::spawn(move || {
            use crate::fallback_cache::BlobStorage;

            let interval = std::time::Duration::from_millis(interval_ms);

            while !shutdown.load(Ordering::SeqCst) {
                // Sleep in small increments to check shutdown
                let sleep_increment = std::time::Duration::from_millis(100);
                let mut elapsed = std::time::Duration::ZERO;

                while elapsed < interval && !shutdown.load(Ordering::SeqCst) {
                    std::thread::sleep(sleep_increment.min(interval - elapsed));
                    elapsed += sleep_increment;
                }

                if shutdown.load(Ordering::SeqCst) {
                    break;
                }

                // Persist
                let sequences = cache.list_sequences();
                let mut blobs = Vec::with_capacity(sequences.len());

                for seq in sequences {
                    if let Some(blob) = cache.get(seq) {
                        blobs.push((seq, blob));
                    }
                }

                // Ignore errors in background task
                let _ = persistence.persist(&blobs);
            }
        });

        self.background_handle.handle = Some(handle);
    }

    /// Stop background sync task.
    ///
    /// ## Behavior
    ///
    /// - Signals shutdown and waits for task to complete
    /// - No-op if not running
    /// - Idempotent (safe to call multiple times)
    pub fn stop_background_sync(&mut self) {
        self.background_handle.signal_shutdown();
        self.background_handle.join();
    }

    /// Check if background sync is running.
    #[must_use]
    pub fn is_background_sync_running(&self) -> bool {
        self.background_handle.is_running()
    }
}

impl Drop for PersistentFallbackCache {
    fn drop(&mut self) {
        self.stop_background_sync();
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;
    use tempfile::tempdir;

    fn make_blob(data: Vec<u8>, received_at: u64, source: DASourceType) -> CachedBlob {
        let hash = crate::fallback_cache::compute_blob_hash(&data);
        CachedBlob {
            data,
            source,
            received_at,
            hash,
            access_count: AtomicU32::new(0),
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // A. PERSISTENCE CONFIG TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_persistence_config_new() {
        let config = PersistenceConfig::new(PathBuf::from("/tmp/cache.log"));

        assert_eq!(config.path, PathBuf::from("/tmp/cache.log"));
        assert_eq!(config.sync_interval_ms, 0);
        assert_eq!(config.format, PersistenceFormat::AppendLog);
    }

    #[test]
    fn test_persistence_config_builder() {
        let config = PersistenceConfig::new(PathBuf::from("/tmp/cache.log"))
            .with_sync_interval_ms(1000)
            .with_format(PersistenceFormat::AppendLog);

        assert_eq!(config.sync_interval_ms, 1000);
        assert!(config.is_background_sync_enabled());
    }

    #[test]
    fn test_persistence_config_background_sync_disabled() {
        let config = PersistenceConfig::new(PathBuf::from("/tmp/cache.log"));
        assert!(!config.is_background_sync_enabled());
    }

    // ════════════════════════════════════════════════════════════════════════════
    // B. CRC32 TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_crc32_deterministic() {
        let data = b"hello world";

        let crc1 = compute_crc32(data);
        let crc2 = compute_crc32(data);

        assert_eq!(crc1, crc2);
    }

    #[test]
    fn test_crc32_different_data() {
        let data1 = b"hello";
        let data2 = b"world";

        let crc1 = compute_crc32(data1);
        let crc2 = compute_crc32(data2);

        assert_ne!(crc1, crc2);
    }

    #[test]
    fn test_crc32_empty() {
        let data: &[u8] = &[];
        let crc = compute_crc32(data);
        assert_eq!(crc, 0); // Known CRC32 of empty data
    }

    // ════════════════════════════════════════════════════════════════════════════
    // C. SERIALIZE/DESERIALIZE TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_serialize_deserialize_entry() {
        let blob = make_blob(vec![1, 2, 3, 4, 5], 12345, DASourceType::Primary);
        let sequence = 42u64;

        let serialized = AppendLogPersistence::serialize_entry(sequence, &blob);

        let mut reader = std::io::Cursor::new(serialized);
        let result = AppendLogPersistence::deserialize_entry(&mut reader);

        assert!(result.is_some());
        let (seq, restored_blob) = result.unwrap();

        assert_eq!(seq, sequence);
        assert_eq!(restored_blob.data, blob.data);
        assert_eq!(restored_blob.received_at, blob.received_at);
        assert_eq!(restored_blob.source, blob.source);
        assert_eq!(restored_blob.hash, blob.hash);
    }

    #[test]
    fn test_serialize_deserialize_all_source_types() {
        for source in [
            DASourceType::Primary,
            DASourceType::Secondary,
            DASourceType::Emergency,
        ] {
            let blob = make_blob(vec![1, 2, 3], 1000, source);
            let serialized = AppendLogPersistence::serialize_entry(1, &blob);

            let mut reader = std::io::Cursor::new(serialized);
            let result = AppendLogPersistence::deserialize_entry(&mut reader);

            assert!(result.is_some());
            assert_eq!(result.unwrap().1.source, source);
        }
    }

    #[test]
    fn test_deserialize_corrupted_magic() {
        let mut data = AppendLogPersistence::serialize_entry(
            1,
            &make_blob(vec![1], 1000, DASourceType::Primary),
        );

        // Corrupt magic
        data[0] = 0xFF;

        let mut reader = std::io::Cursor::new(data);
        let result = AppendLogPersistence::deserialize_entry(&mut reader);

        assert!(result.is_none());
    }

    #[test]
    fn test_deserialize_corrupted_crc() {
        let mut data = AppendLogPersistence::serialize_entry(
            1,
            &make_blob(vec![1, 2, 3], 1000, DASourceType::Primary),
        );

        // Corrupt CRC (last 4 bytes)
        let len = data.len();
        data[len - 1] ^= 0xFF;

        let mut reader = std::io::Cursor::new(data);
        let result = AppendLogPersistence::deserialize_entry(&mut reader);

        assert!(result.is_none());
    }

    #[test]
    fn test_deserialize_truncated_entry() {
        let data = AppendLogPersistence::serialize_entry(
            1,
            &make_blob(vec![1, 2, 3], 1000, DASourceType::Primary),
        );

        // Truncate data
        let truncated = &data[..data.len() - 10];

        let mut reader = std::io::Cursor::new(truncated);
        let result = AppendLogPersistence::deserialize_entry(&mut reader);

        assert!(result.is_none());
    }

    // ════════════════════════════════════════════════════════════════════════════
    // D. APPEND LOG PERSISTENCE TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_persist_and_restore_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("cache.log");

        let config = PersistenceConfig::new(path);
        let persistence = AppendLogPersistence::new(config);

        let result = persistence.persist(&[]);
        assert!(result.is_ok());

        let restored = persistence.restore().unwrap();
        assert!(restored.is_empty());
    }

    #[test]
    fn test_persist_and_restore_single_blob() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("cache.log");

        let config = PersistenceConfig::new(path);
        let persistence = AppendLogPersistence::new(config);

        let blob = make_blob(vec![1, 2, 3, 4, 5], 12345, DASourceType::Primary);
        let blobs = vec![(42u64, blob.clone())];

        persistence.persist(&blobs).unwrap();

        let restored = persistence.restore().unwrap();

        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].0, 42);
        assert_eq!(restored[0].1.data, blob.data);
        assert_eq!(restored[0].1.hash, blob.hash);
        assert_eq!(restored[0].1.received_at, blob.received_at);
    }

    #[test]
    fn test_persist_and_restore_multiple_blobs() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("cache.log");

        let config = PersistenceConfig::new(path);
        let persistence = AppendLogPersistence::new(config);

        let blobs = vec![
            (1u64, make_blob(vec![1, 2, 3], 1000, DASourceType::Primary)),
            (
                5u64,
                make_blob(vec![4, 5, 6, 7], 2000, DASourceType::Secondary),
            ),
            (
                10u64,
                make_blob(vec![8, 9], 3000, DASourceType::Emergency),
            ),
        ];

        persistence.persist(&blobs).unwrap();

        let restored = persistence.restore().unwrap();

        assert_eq!(restored.len(), 3);

        for (i, (orig_seq, orig_blob)) in blobs.iter().enumerate() {
            assert_eq!(restored[i].0, *orig_seq);
            assert_eq!(restored[i].1.data, orig_blob.data);
            assert_eq!(restored[i].1.hash, orig_blob.hash);
        }
    }

    #[test]
    fn test_restore_nonexistent_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nonexistent.log");

        let config = PersistenceConfig::new(path);
        let persistence = AppendLogPersistence::new(config);

        let restored = persistence.restore().unwrap();
        assert!(restored.is_empty());
    }

    // ════════════════════════════════════════════════════════════════════════════
    // E. CRASH RECOVERY TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_restore_with_corrupted_tail() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("cache.log");

        // Write valid entries first
        let config = PersistenceConfig::new(path.clone());
        let persistence = AppendLogPersistence::new(config);

        let blobs = vec![
            (1u64, make_blob(vec![1, 2, 3], 1000, DASourceType::Primary)),
            (2u64, make_blob(vec![4, 5, 6], 2000, DASourceType::Primary)),
        ];

        persistence.persist(&blobs).unwrap();

        // Append garbage to simulate crash
        {
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            file.write_all(&[0xFF, 0xFE, 0xFD, 0xFC]).unwrap();
        }

        // Restore should succeed with valid entries only
        let restored = persistence.restore().unwrap();

        assert_eq!(restored.len(), 2);
        assert_eq!(restored[0].0, 1);
        assert_eq!(restored[1].0, 2);
    }

    #[test]
    fn test_restore_with_partial_entry() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("cache.log");

        // Write one valid entry
        let config = PersistenceConfig::new(path.clone());
        let persistence = AppendLogPersistence::new(config);

        let blobs = vec![(1u64, make_blob(vec![1, 2, 3], 1000, DASourceType::Primary))];
        persistence.persist(&blobs).unwrap();

        // Append partial valid entry (just magic + version)
        {
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            file.write_all(&MAGIC).unwrap();
            file.write_all(&[VERSION]).unwrap();
        }

        // Restore should succeed with first entry only
        let restored = persistence.restore().unwrap();

        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].0, 1);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // F. PERSISTENCE FACTORY TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_create_persistence_append_log() {
        let config = PersistenceConfig::new(PathBuf::from("/tmp/test.log"));
        let result = create_persistence(config);

        assert!(result.is_ok());
    }

    #[test]
    fn test_create_persistence_rocksdb_unsupported() {
        let config =
            PersistenceConfig::new(PathBuf::from("/tmp/test.db")).with_format(PersistenceFormat::RocksDB);

        let result = create_persistence(config);

        assert!(result.is_err());
        match result {
            Err(PersistError::UnsupportedFormat(_)) => {}
            _ => panic!("Expected UnsupportedFormat error"),
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // G. PERSISTENT FALLBACK CACHE TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_persistent_cache_persist_and_restore() {
        use crate::fallback_cache::{BlobStorage, FallbackCache};

        let dir = tempdir().unwrap();
        let path = dir.path().join("cache.log");

        let cache = FallbackCache::new();
        cache
            .store(1, make_blob(vec![1, 2, 3], 1000, DASourceType::Primary))
            .unwrap();
        cache
            .store(2, make_blob(vec![4, 5, 6], 2000, DASourceType::Secondary))
            .unwrap();

        let config = PersistenceConfig::new(path.clone());
        let persistent_cache = PersistentFallbackCache::new(cache, config).unwrap();

        persistent_cache.persist().unwrap();

        // Create new cache and restore
        let new_cache = FallbackCache::new();
        let new_config = PersistenceConfig::new(path);
        let new_persistent_cache = PersistentFallbackCache::new(new_cache, new_config).unwrap();

        let restored_count = new_persistent_cache.restore().unwrap();

        assert_eq!(restored_count, 2);
        assert_eq!(new_persistent_cache.cache().len(), 2);
        assert!(new_persistent_cache.cache().contains(1));
        assert!(new_persistent_cache.cache().contains(2));
    }

    #[test]
    fn test_persistent_cache_restore_preserves_data() {
        use crate::fallback_cache::{BlobStorage, FallbackCache};

        let dir = tempdir().unwrap();
        let path = dir.path().join("cache.log");

        let original_data = vec![10, 20, 30, 40, 50];
        let original_received_at = 99999u64;

        let cache = FallbackCache::new();
        cache
            .store(
                42,
                make_blob(original_data.clone(), original_received_at, DASourceType::Emergency),
            )
            .unwrap();

        let config = PersistenceConfig::new(path.clone());
        let persistent_cache = PersistentFallbackCache::new(cache, config).unwrap();
        persistent_cache.persist().unwrap();

        // Restore to new cache
        let new_cache = FallbackCache::new();
        let new_config = PersistenceConfig::new(path);
        let new_persistent_cache = PersistentFallbackCache::new(new_cache, new_config).unwrap();
        new_persistent_cache.restore().unwrap();

        let restored_blob = new_persistent_cache.cache().get(42).unwrap();

        assert_eq!(restored_blob.data, original_data);
        assert_eq!(restored_blob.received_at, original_received_at);
        assert_eq!(restored_blob.source, DASourceType::Emergency);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // H. BACKGROUND SYNC TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_background_sync_disabled_by_default() {
        use crate::fallback_cache::FallbackCache;

        let dir = tempdir().unwrap();
        let path = dir.path().join("cache.log");

        let cache = FallbackCache::new();
        let config = PersistenceConfig::new(path);
        let mut persistent_cache = PersistentFallbackCache::new(cache, config).unwrap();

        persistent_cache.start_background_sync();

        // Should not start because interval is 0
        assert!(!persistent_cache.is_background_sync_running());
    }

    #[test]
    fn test_background_sync_start_stop() {
        use crate::fallback_cache::FallbackCache;

        let dir = tempdir().unwrap();
        let path = dir.path().join("cache.log");

        let cache = FallbackCache::new();
        let config = PersistenceConfig::new(path).with_sync_interval_ms(100);
        let mut persistent_cache = PersistentFallbackCache::new(cache, config).unwrap();

        persistent_cache.start_background_sync();
        assert!(persistent_cache.is_background_sync_running());

        persistent_cache.stop_background_sync();
        assert!(!persistent_cache.is_background_sync_running());
    }

    #[test]
    fn test_background_sync_idempotent_stop() {
        use crate::fallback_cache::FallbackCache;

        let dir = tempdir().unwrap();
        let path = dir.path().join("cache.log");

        let cache = FallbackCache::new();
        let config = PersistenceConfig::new(path).with_sync_interval_ms(100);
        let mut persistent_cache = PersistentFallbackCache::new(cache, config).unwrap();

        persistent_cache.start_background_sync();

        // Multiple stops should be safe
        persistent_cache.stop_background_sync();
        persistent_cache.stop_background_sync();
        persistent_cache.stop_background_sync();

        assert!(!persistent_cache.is_background_sync_running());
    }

    #[test]
    fn test_background_sync_actually_persists() {
        use crate::fallback_cache::{BlobStorage, FallbackCache};

        let dir = tempdir().unwrap();
        let path = dir.path().join("cache.log");

        let cache = FallbackCache::new();
        cache
            .store(1, make_blob(vec![1, 2, 3], 1000, DASourceType::Primary))
            .unwrap();

        let config = PersistenceConfig::new(path.clone()).with_sync_interval_ms(50);
        let mut persistent_cache = PersistentFallbackCache::new(cache, config).unwrap();

        persistent_cache.start_background_sync();

        // Wait for at least one sync
        std::thread::sleep(std::time::Duration::from_millis(200));

        persistent_cache.stop_background_sync();

        // Verify file was created and has data
        assert!(path.exists());

        // Restore to verify
        let new_cache = FallbackCache::new();
        let new_config = PersistenceConfig::new(path);
        let new_persistent_cache = PersistentFallbackCache::new(new_cache, new_config).unwrap();
        let restored = new_persistent_cache.restore().unwrap();

        assert_eq!(restored, 1);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // I. ERROR HANDLING TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_persist_error_display() {
        let io_err = PersistError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file not found",
        ));
        assert!(io_err.to_string().contains("IO error"));

        let corrupted = PersistError::Corrupted("bad data".to_string());
        assert!(corrupted.to_string().contains("corrupted"));

        let unsupported = PersistError::UnsupportedFormat("RocksDB".to_string());
        assert!(unsupported.to_string().contains("unsupported"));
    }

    // ════════════════════════════════════════════════════════════════════════════
    // J. THREAD SAFETY TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_append_log_persistence_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<AppendLogPersistence>();
    }

    #[test]
    fn test_append_log_persistence_is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<AppendLogPersistence>();
    }

    #[test]
    fn test_persistent_fallback_cache_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<PersistentFallbackCache>();
    }
}