//! # WORM File Storage (Tahap 15.18)
//!
//! File-based WORM (Write Once Read Many) storage backend for audit log.
//!
//! ## File Naming Convention
//!
//! ```text
//! {base_dir}/{file_prefix}_{sequence_start:016}.worm
//! ```
//!
//! Example: `audit_log_0000000000000001.worm`
//!
//! ## Tahap 15.18 — Config + Struct + Constructor
//!
//! Defines config, struct, constructor with directory creation and file scanning.
//!
//! ## Tahap 15.19 — Append-Only Write
//!
//! Implements core WORM append operation with entry format:
//! `[len:8 LE][data:N][crc32:4 LE]`
//!
//! CRC32 IEEE checksum computed over data bytes only.
//! File rotation triggers when size exceeds `max_file_size_bytes`.

use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use dsdn_common::AuditLogError;

// ════════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════════

/// Default max file size: 100 MB.
const DEFAULT_MAX_FILE_SIZE_BYTES: u64 = 100 * 1024 * 1024;

/// Default file prefix for WORM log files.
const DEFAULT_FILE_PREFIX: &str = "audit_log";

/// WORM file extension.
const WORM_FILE_EXTENSION: &str = "worm";

// ════════════════════════════════════════════════════════════════════════════════
// WORM FILE CONFIG
// ════════════════════════════════════════════════════════════════════════════════

/// Configuration for WORM file storage.
#[derive(Debug, Clone)]
pub struct WormFileConfig {
    /// Base directory for WORM log files.
    pub base_dir: PathBuf,
    /// Maximum file size in bytes before rotation (default: 100 MB).
    pub max_file_size_bytes: u64,
    /// File name prefix (default: `"audit_log"`).
    pub file_prefix: String,
    /// Whether to fsync after each write (default: `true`).
    pub sync_on_write: bool,
}

impl WormFileConfig {
    /// Create config with defaults and specified base directory.
    pub fn new(base_dir: PathBuf) -> Self {
        Self {
            base_dir,
            max_file_size_bytes: DEFAULT_MAX_FILE_SIZE_BYTES,
            file_prefix: DEFAULT_FILE_PREFIX.to_string(),
            sync_on_write: true,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// WORM FILE STORAGE
// ════════════════════════════════════════════════════════════════════════════════

/// File-based WORM storage backend.
///
/// # Thread Safety
///
/// - `current_file`: `Mutex<Option<(PathBuf, File)>>` for safe file access.
/// - `current_sequence`: `AtomicU64` for lock-free sequence reads.
/// - `current_file_size`: `AtomicU64` for lock-free size tracking.
///
/// # WORM Invariant
///
/// Files are append-only. No overwrite, no delete, no truncate.
pub struct WormFileStorage {
    /// Storage configuration.
    config: WormFileConfig,
    /// Currently open file handle for appending. `None` if no file is open.
    current_file: Mutex<Option<(PathBuf, std::fs::File)>>,
    /// Latest sequence number written. 0 if empty.
    current_sequence: AtomicU64,
    /// Current file size in bytes.
    current_file_size: AtomicU64,
}

impl WormFileStorage {
    /// Create a new `WormFileStorage`.
    ///
    /// 1. Creates `base_dir` if it does not exist.
    /// 2. Scans existing `.worm` files to find the latest sequence number.
    /// 3. Does **NOT** open any file (deferred to first append).
    ///
    /// # Errors
    ///
    /// Returns error if directory creation or scanning fails.
    pub fn new(config: WormFileConfig) -> dsdn_common::Result<Self> {
        // Create base directory if missing
        fs::create_dir_all(&config.base_dir)
            .map_err(|e| Box::new(AuditLogError::WriteFailed {
                reason: format!("create base_dir {:?}: {}", config.base_dir, e),
            }) as Box<dyn std::error::Error + Send + Sync>)?;

        // Scan existing files to determine last sequence
        let last_seq = scan_last_sequence(&config.base_dir, &config.file_prefix)?;

        Ok(Self {
            config,
            current_file: Mutex::new(None),
            current_sequence: AtomicU64::new(last_seq),
            current_file_size: AtomicU64::new(0),
        })
    }

    /// Return a reference to the configuration.
    pub fn config(&self) -> &WormFileConfig {
        &self.config
    }

    /// Return the current sequence number. 0 if no entries.
    pub fn current_sequence(&self) -> u64 {
        self.current_sequence.load(Ordering::SeqCst)
    }

    /// Return the current file size in bytes.
    pub fn current_file_size(&self) -> u64 {
        self.current_file_size.load(Ordering::SeqCst)
    }

    /// Check if a file handle is currently open.
    pub fn has_open_file(&self) -> bool {
        match self.current_file.lock() {
            Ok(guard) => guard.is_some(),
            Err(_) => false,
        }
    }

    /// Generate file path for a given start sequence.
    ///
    /// Format: `{base_dir}/{prefix}_{sequence:016}.worm`
    fn file_path_for_sequence(&self, seq_start: u64) -> PathBuf {
        self.config.base_dir.join(format!(
            "{}_{:016}.{}",
            self.config.file_prefix, seq_start, WORM_FILE_EXTENSION
        ))
    }

    /// Open or create a WORM file for appending.
    ///
    /// Uses `OpenOptions::append(true)` — no seek, no truncate, no overwrite.
    fn open_append_file(&self, path: &std::path::Path) -> Result<std::fs::File, AuditLogError> {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| AuditLogError::WriteFailed {
                reason: format!("open {:?}: {}", path, e),
            })
    }

    /// Ensure a file is open for writing. Opens a new file if needed.
    /// Called with `current_file` mutex already locked.
    fn ensure_file_open(
        &self,
        guard: &mut Option<(PathBuf, std::fs::File)>,
    ) -> Result<(), AuditLogError> {
        if guard.is_none() {
            let next_seq = self.current_sequence.load(Ordering::SeqCst).saturating_add(1);
            let path = self.file_path_for_sequence(next_seq);
            let file = self.open_append_file(&path)?;
            *guard = Some((path, file));
            self.current_file_size.store(0, Ordering::SeqCst);
        }
        Ok(())
    }

    /// Rotate to a new file if current file exceeds max size.
    /// Called with `current_file` mutex already locked.
    fn rotate_if_needed(
        &self,
        guard: &mut Option<(PathBuf, std::fs::File)>,
    ) -> Result<(), AuditLogError> {
        if self.current_file_size.load(Ordering::SeqCst) >= self.config.max_file_size_bytes {
            // Flush and close old file
            if let Some((_, ref mut old_file)) = guard {
                let _ = old_file.flush();
                let _ = old_file.sync_all();
            }

            let next_seq = self.current_sequence.load(Ordering::SeqCst).saturating_add(1);
            let path = self.file_path_for_sequence(next_seq);
            let file = self.open_append_file(&path)?;
            *guard = Some((path, file));
            self.current_file_size.store(0, Ordering::SeqCst);
        }
        Ok(())
    }

    /// Core append implementation.
    ///
    /// Entry on-disk format: `[len:8 LE][data:N][crc32:4 LE]`
    ///
    /// Returns the new sequence number.
    pub fn append(&self, entry_bytes: &[u8]) -> Result<u64, AuditLogError> {
        let mut guard = self.current_file.lock().map_err(|e| {
            AuditLogError::LockPoisoned {
                reason: format!("current_file lock: {}", e),
            }
        })?;

        // Step 1: Ensure file is open
        self.ensure_file_open(&mut guard)?;

        // Step 2: Check rotation
        self.rotate_if_needed(&mut guard)?;

        // Step 3: Build entry buffer
        let entry_len = entry_bytes.len() as u64;
        let entry_len_bytes = entry_len.to_le_bytes();

        // Step 4: Compute CRC32
        let checksum = crc32_ieee(entry_bytes);
        let checksum_bytes = checksum.to_le_bytes();

        // Step 5: Write to file
        let (_, ref mut file) = guard.as_mut().ok_or_else(|| {
            AuditLogError::WriteFailed {
                reason: "file handle is None after ensure_file_open".to_string(),
            }
        })?;

        file.write_all(&entry_len_bytes).map_err(|e| AuditLogError::WriteFailed {
            reason: format!("write entry_len: {}", e),
        })?;
        file.write_all(entry_bytes).map_err(|e| AuditLogError::WriteFailed {
            reason: format!("write entry_data: {}", e),
        })?;
        file.write_all(&checksum_bytes).map_err(|e| AuditLogError::WriteFailed {
            reason: format!("write checksum: {}", e),
        })?;

        // Step 6: Sync if configured
        if self.config.sync_on_write {
            file.sync_data().map_err(|e| AuditLogError::WriteFailed {
                reason: format!("sync_data: {}", e),
            })?;
        }

        // Step 7: Update counters
        let total_written: u64 = 8 + entry_len + 4;
        let new_seq = self.current_sequence.fetch_add(1, Ordering::SeqCst) + 1;
        self.current_file_size.fetch_add(total_written, Ordering::SeqCst);

        // Step 8: Return sequence
        Ok(new_seq)
    }
}

impl std::fmt::Debug for WormFileStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WormFileStorage")
            .field("base_dir", &self.config.base_dir)
            .field("current_sequence", &self.current_sequence.load(Ordering::SeqCst))
            .field("current_file_size", &self.current_file_size.load(Ordering::SeqCst))
            .finish()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// CRC32 IEEE
// ════════════════════════════════════════════════════════════════════════════════

/// Compute CRC32 IEEE checksum of the given data.
///
/// Uses the standard IEEE polynomial (0xEDB88320 reflected).
/// Deterministic and platform-independent.
pub fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    crc ^ 0xFFFF_FFFF
}

// ════════════════════════════════════════════════════════════════════════════════
// FILE SCANNING
// ════════════════════════════════════════════════════════════════════════════════

/// Scan `base_dir` for `.worm` files with the given prefix and return
/// the highest sequence number found.
///
/// File naming convention: `{prefix}_{sequence:016}.worm`
///
/// Returns 0 if no files found.
fn scan_last_sequence(base_dir: &std::path::Path, prefix: &str) -> dsdn_common::Result<u64> {
    if !base_dir.exists() {
        return Ok(0);
    }

    let entries = fs::read_dir(base_dir)
        .map_err(|e| Box::new(AuditLogError::WriteFailed {
            reason: format!("read base_dir {:?}: {}", base_dir, e),
        }) as Box<dyn std::error::Error + Send + Sync>)?;

    let mut max_seq: u64 = 0;

    let expected_prefix = format!("{}_", prefix);
    let expected_ext = format!(".{}", WORM_FILE_EXTENSION);

    for entry_result in entries {
        let entry = match entry_result {
            Ok(e) => e,
            Err(_) => continue,
        };

        let file_name = entry.file_name().to_string_lossy().to_string();

        // Check prefix and extension
        if !file_name.starts_with(&expected_prefix) {
            continue;
        }
        if !file_name.ends_with(&expected_ext) {
            continue;
        }

        // Extract sequence number: between prefix_ and .worm
        let start = expected_prefix.len();
        let end = file_name.len().saturating_sub(expected_ext.len());
        if start >= end {
            continue;
        }

        let seq_str = &file_name[start..end];
        if let Ok(seq) = seq_str.parse::<u64>() {
            if seq > max_seq {
                max_seq = seq;
            }
        }
    }

    Ok(max_seq)
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "dsdn_worm_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        // Ensure unique per test invocation
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let count = COUNTER.fetch_add(1, Ordering::SeqCst);
        dir.join(format!("{}", count))
    }

    fn cleanup(dir: &std::path::Path) {
        let _ = fs::remove_dir_all(dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 1: worm_file_config_defaults
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_file_config_defaults() {
        let cfg = WormFileConfig::new(PathBuf::from("/tmp/test_worm"));

        assert_eq!(cfg.base_dir, PathBuf::from("/tmp/test_worm"));
        assert_eq!(cfg.max_file_size_bytes, 100 * 1024 * 1024);
        assert_eq!(cfg.file_prefix, "audit_log");
        assert!(cfg.sync_on_write);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 2: worm_file_storage_new_creates_directory
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_file_storage_new_creates_directory() {
        let dir = temp_dir();
        assert!(!dir.exists(), "dir must not exist before test");

        let cfg = WormFileConfig::new(dir.clone());
        let result = WormFileStorage::new(cfg);

        match result {
            Ok(_storage) => {
                assert!(dir.exists(), "dir must be created");
                assert!(dir.is_dir(), "must be a directory");
            }
            Err(e) => assert!(false, "new failed: {}", e),
        }

        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 3: worm_file_storage_new_with_existing_dir
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_file_storage_new_with_existing_dir() {
        let dir = temp_dir();
        let _ = fs::create_dir_all(&dir);
        assert!(dir.exists());

        let cfg = WormFileConfig::new(dir.clone());
        let result = WormFileStorage::new(cfg);

        match result {
            Ok(storage) => {
                assert_eq!(storage.current_sequence(), 0);
            }
            Err(e) => assert!(false, "new with existing dir: {}", e),
        }

        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 4: worm_file_storage_sequence_initial_zero
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_file_storage_sequence_initial_zero() {
        let dir = temp_dir();
        let cfg = WormFileConfig::new(dir.clone());
        let result = WormFileStorage::new(cfg);

        match result {
            Ok(storage) => {
                assert_eq!(storage.current_sequence(), 0, "empty dir → sequence 0");
                assert_eq!(storage.current_file_size(), 0, "no file → size 0");
            }
            Err(e) => assert!(false, "new: {}", e),
        }

        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 5: worm_file_storage_sequence_detect_existing_files
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_file_storage_sequence_detect_existing_files() {
        let dir = temp_dir();
        let _ = fs::create_dir_all(&dir);

        // Create fake WORM files with known sequence numbers
        let _ = fs::write(dir.join("audit_log_0000000000000001.worm"), b"fake1");
        let _ = fs::write(dir.join("audit_log_0000000000000050.worm"), b"fake50");
        let _ = fs::write(dir.join("audit_log_0000000000000025.worm"), b"fake25");
        // Non-matching files should be ignored
        let _ = fs::write(dir.join("other_file.txt"), b"ignored");
        let _ = fs::write(dir.join("audit_log_notanumber.worm"), b"ignored");

        let cfg = WormFileConfig::new(dir.clone());
        let result = WormFileStorage::new(cfg);

        match result {
            Ok(storage) => {
                assert_eq!(storage.current_sequence(), 50,
                    "must detect highest sequence from existing files");
            }
            Err(e) => assert!(false, "new: {}", e),
        }

        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 6: worm_file_storage_thread_safe_struct
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_file_storage_thread_safe_struct() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<WormFileStorage>();
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 7: worm_file_storage_no_file_open_on_init
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_file_storage_no_file_open_on_init() {
        let dir = temp_dir();
        let cfg = WormFileConfig::new(dir.clone());
        let result = WormFileStorage::new(cfg);

        match result {
            Ok(storage) => {
                assert!(!storage.has_open_file(), "no file should be open after init");
            }
            Err(e) => assert!(false, "new: {}", e),
        }

        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 8: worm_file_config_custom_values
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_file_config_custom_values() {
        let cfg = WormFileConfig {
            base_dir: PathBuf::from("/custom/path"),
            max_file_size_bytes: 50 * 1024 * 1024,
            file_prefix: "custom_prefix".to_string(),
            sync_on_write: false,
        };

        assert_eq!(cfg.base_dir, PathBuf::from("/custom/path"));
        assert_eq!(cfg.max_file_size_bytes, 50 * 1024 * 1024);
        assert_eq!(cfg.file_prefix, "custom_prefix");
        assert!(!cfg.sync_on_write);

        // Clone works
        let cloned = cfg.clone();
        assert_eq!(cloned.file_prefix, "custom_prefix");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 9: worm_file_scan_with_custom_prefix
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_file_scan_with_custom_prefix() {
        let dir = temp_dir();
        let _ = fs::create_dir_all(&dir);

        // Files with custom prefix
        let _ = fs::write(dir.join("mylog_0000000000000010.worm"), b"data");
        let _ = fs::write(dir.join("mylog_0000000000000020.worm"), b"data");
        // Files with default prefix — should be IGNORED
        let _ = fs::write(dir.join("audit_log_0000000000000999.worm"), b"data");

        let cfg = WormFileConfig {
            base_dir: dir.clone(),
            max_file_size_bytes: DEFAULT_MAX_FILE_SIZE_BYTES,
            file_prefix: "mylog".to_string(),
            sync_on_write: true,
        };
        let result = WormFileStorage::new(cfg);

        match result {
            Ok(storage) => {
                assert_eq!(storage.current_sequence(), 20,
                    "must only scan files matching custom prefix");
            }
            Err(e) => assert!(false, "new: {}", e),
        }

        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // 15.19 APPEND TESTS
    // ════════════════════════════════════════════════════════════════════════

    // ════════════════════════════════════════════════════════════════════════
    // TEST 10: worm_append_single_entry
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_append_single_entry() {
        let dir = temp_dir();
        let cfg = WormFileConfig::new(dir.clone());
        let result = WormFileStorage::new(cfg);

        match result {
            Ok(storage) => {
                let seq = storage.append(b"hello_worm");
                match seq {
                    Ok(s) => {
                        assert_eq!(s, 1, "first append must return sequence 1");
                        assert_eq!(storage.current_sequence(), 1);
                        assert!(storage.has_open_file(), "file must be open after append");
                    }
                    Err(e) => assert!(false, "append failed: {}", e),
                }
            }
            Err(e) => assert!(false, "new: {}", e),
        }

        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 11: worm_append_multiple_entries
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_append_multiple_entries() {
        let dir = temp_dir();
        let cfg = WormFileConfig::new(dir.clone());
        let result = WormFileStorage::new(cfg);

        match result {
            Ok(storage) => {
                for i in 1u64..=5 {
                    let data = format!("entry_{}", i);
                    let seq = storage.append(data.as_bytes());
                    match seq {
                        Ok(s) => assert_eq!(s, i, "sequence must match"),
                        Err(e) => assert!(false, "append {} failed: {}", i, e),
                    }
                }
                assert_eq!(storage.current_sequence(), 5);
            }
            Err(e) => assert!(false, "new: {}", e),
        }

        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 12: worm_append_sequence_monotonic
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_append_sequence_monotonic() {
        let dir = temp_dir();
        let cfg = WormFileConfig::new(dir.clone());
        let result = WormFileStorage::new(cfg);

        match result {
            Ok(storage) => {
                let mut prev = 0u64;
                for _ in 0..20 {
                    let seq = storage.append(b"data");
                    match seq {
                        Ok(s) => {
                            assert!(s > prev, "seq must be strictly increasing: {} > {}", s, prev);
                            prev = s;
                        }
                        Err(e) => assert!(false, "append: {}", e),
                    }
                }
            }
            Err(e) => assert!(false, "new: {}", e),
        }

        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 13: worm_entry_format_correct
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_entry_format_correct() {
        let dir = temp_dir();
        let cfg = WormFileConfig::new(dir.clone());
        let result = WormFileStorage::new(cfg);

        match result {
            Ok(storage) => {
                let data = b"test_entry_data";
                let _ = storage.append(data);

                // Read raw file
                let files: Vec<_> = fs::read_dir(&dir)
                    .map(|rd| rd.filter_map(|e| e.ok()).collect())
                    .unwrap_or_default();

                let worm_files: Vec<_> = files.iter()
                    .filter(|f| f.path().extension().map_or(false, |ext| ext == "worm"))
                    .collect();

                assert_eq!(worm_files.len(), 1, "one worm file must exist");

                let raw = fs::read(worm_files[0].path());
                match raw {
                    Ok(bytes) => {
                        // Format: [len:8][data:N][crc:4]
                        let expected_len = 8 + data.len() + 4;
                        assert_eq!(bytes.len(), expected_len, "file size must match entry format");

                        // Verify length header
                        let len_bytes: [u8; 8] = [
                            bytes[0], bytes[1], bytes[2], bytes[3],
                            bytes[4], bytes[5], bytes[6], bytes[7],
                        ];
                        let stored_len = u64::from_le_bytes(len_bytes);
                        assert_eq!(stored_len, data.len() as u64, "stored length must match data length");

                        // Verify data
                        let stored_data = &bytes[8..8 + data.len()];
                        assert_eq!(stored_data, data, "stored data must match");

                        // Verify CRC32
                        let crc_offset = 8 + data.len();
                        let crc_bytes: [u8; 4] = [
                            bytes[crc_offset], bytes[crc_offset + 1],
                            bytes[crc_offset + 2], bytes[crc_offset + 3],
                        ];
                        let stored_crc = u32::from_le_bytes(crc_bytes);
                        let computed_crc = crc32_ieee(data);
                        assert_eq!(stored_crc, computed_crc, "CRC32 must match");
                    }
                    Err(e) => assert!(false, "read file: {}", e),
                }
            }
            Err(e) => assert!(false, "new: {}", e),
        }

        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14: worm_crc32_correct
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_crc32_correct() {
        // Known CRC32 IEEE values
        let crc_empty = crc32_ieee(b"");
        assert_eq!(crc_empty, 0x00000000, "CRC32 of empty must be 0");

        let crc_hello = crc32_ieee(b"hello");
        // CRC32 IEEE of "hello" = 0x3610A686
        assert_eq!(crc_hello, 0x3610A686, "CRC32 of 'hello'");

        // Deterministic
        let crc_a = crc32_ieee(b"test_data_for_crc");
        let crc_b = crc32_ieee(b"test_data_for_crc");
        assert_eq!(crc_a, crc_b, "CRC32 must be deterministic");

        // Different data = different CRC
        let crc_c = crc32_ieee(b"different");
        assert_ne!(crc_a, crc_c, "different data → different CRC");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 15: worm_file_grows_monotonically
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_file_grows_monotonically() {
        let dir = temp_dir();
        let cfg = WormFileConfig::new(dir.clone());
        let result = WormFileStorage::new(cfg);

        match result {
            Ok(storage) => {
                let mut prev_size = 0u64;
                for _ in 0..10 {
                    let _ = storage.append(b"growing_entry");
                    let new_size = storage.current_file_size();
                    assert!(new_size > prev_size, "file must grow: {} > {}", new_size, prev_size);
                    prev_size = new_size;
                }
            }
            Err(e) => assert!(false, "new: {}", e),
        }

        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 16: worm_sync_on_write_enabled
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_sync_on_write_enabled() {
        let dir = temp_dir();
        let mut cfg = WormFileConfig::new(dir.clone());
        cfg.sync_on_write = true;

        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                // Append should succeed with sync enabled (default)
                let seq = storage.append(b"sync_test");
                assert!(seq.is_ok(), "append with sync must succeed");

                // Also test with sync disabled
                let dir2 = temp_dir();
                let mut cfg2 = WormFileConfig::new(dir2.clone());
                cfg2.sync_on_write = false;
                let storage2 = WormFileStorage::new(cfg2);
                match storage2 {
                    Ok(s2) => {
                        let seq2 = s2.append(b"no_sync_test");
                        assert!(seq2.is_ok(), "append without sync must succeed");
                    }
                    Err(e) => assert!(false, "new2: {}", e),
                }
                cleanup(&dir2);
            }
            Err(e) => assert!(false, "new: {}", e),
        }

        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 17: worm_rotation_triggered
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_rotation_triggered() {
        let dir = temp_dir();
        let mut cfg = WormFileConfig::new(dir.clone());
        // Very small max size to trigger rotation quickly
        cfg.max_file_size_bytes = 50;
        cfg.sync_on_write = false;

        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                // Each entry is 8 + 20 + 4 = 32 bytes → after 2 entries (64 bytes) > 50, rotation
                for i in 1u64..=5 {
                    let seq = storage.append(b"twelve_byte_data_pad");
                    match seq {
                        Ok(s) => assert_eq!(s, i),
                        Err(e) => assert!(false, "append {} failed: {}", i, e),
                    }
                }

                // Multiple worm files should exist
                let worm_count = fs::read_dir(&dir)
                    .map(|rd| rd.filter_map(|e| e.ok())
                        .filter(|e| e.path().extension().map_or(false, |ext| ext == "worm"))
                        .count())
                    .unwrap_or(0);

                assert!(worm_count > 1, "rotation must create multiple files, got {}", worm_count);
            }
            Err(e) => assert!(false, "new: {}", e),
        }

        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 18: worm_no_overwrite_behavior
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_no_overwrite_behavior() {
        let dir = temp_dir();
        let cfg = WormFileConfig::new(dir.clone());
        let result = WormFileStorage::new(cfg);

        match result {
            Ok(storage) => {
                let _ = storage.append(b"first_entry");
                let _ = storage.append(b"second_entry");

                // Read file and verify both entries exist sequentially
                let files: Vec<_> = fs::read_dir(&dir)
                    .map(|rd| rd.filter_map(|e| e.ok())
                        .filter(|e| e.path().extension().map_or(false, |ext| ext == "worm"))
                        .collect())
                    .unwrap_or_default();

                assert_eq!(files.len(), 1);
                let raw = fs::read(files[0].path());
                match raw {
                    Ok(bytes) => {
                        // Two entries: (8+11+4) + (8+12+4) = 23 + 24 = 47
                        let expected = (8 + 11 + 4) + (8 + 12 + 4);
                        assert_eq!(bytes.len(), expected, "file must contain both entries");

                        // First entry data starts at offset 8
                        assert_eq!(&bytes[8..8 + 11], b"first_entry");
                        // Second entry data starts at offset 23 + 8 = 31
                        assert_eq!(&bytes[23 + 8..23 + 8 + 12], b"second_entry");
                    }
                    Err(e) => assert!(false, "read: {}", e),
                }
            }
            Err(e) => assert!(false, "new: {}", e),
        }

        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 19: worm_concurrent_append_safe
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_concurrent_append_safe() {
        let dir = temp_dir();
        let mut cfg = WormFileConfig::new(dir.clone());
        cfg.sync_on_write = false; // Faster for test

        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                let storage = std::sync::Arc::new(storage);

                let mut handles = Vec::new();
                for _ in 0..5 {
                    let s = std::sync::Arc::clone(&storage);
                    handles.push(std::thread::spawn(move || {
                        for _ in 0..10 {
                            let r = s.append(b"concurrent_data");
                            assert!(r.is_ok());
                        }
                    }));
                }

                for h in handles {
                    match h.join() {
                        Ok(()) => {}
                        Err(_) => assert!(false, "thread panicked"),
                    }
                }

                assert_eq!(storage.current_sequence(), 50, "50 entries from 5x10 threads");

                // Verify total file size is correct
                // Each entry: 8 + 15 + 4 = 27 bytes × 50 = 1350 total (may span multiple files)
                assert!(storage.current_file_size() > 0);
            }
            Err(e) => assert!(false, "new: {}", e),
        }

        cleanup(&dir);
    }
}