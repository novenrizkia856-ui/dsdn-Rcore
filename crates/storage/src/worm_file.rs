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
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use dsdn_common::AuditLogError;
use dsdn_common::WormLogStorage;

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
// RECOVERY REPORT (Tahap 15.22)
// ════════════════════════════════════════════════════════════════════════════════

/// Report from crash recovery scan of WORM log files.
///
/// Recovery is a **read-only operation** — no files are modified or deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryReport {
    /// Total entries encountered (valid + partial).
    pub total_entries: u64,
    /// Number of fully valid entries (len + data + CRC32 all correct).
    pub valid_entries: u64,
    /// Number of partial/corrupted entries detected.
    pub partial_entries: u64,
    /// Sequence number of the last valid entry. 0 if no valid entries.
    pub last_valid_sequence: u64,
    /// Number of `.worm` files scanned.
    pub files_scanned: usize,
}

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

    /// List all `.worm` files matching prefix, sorted lexicographically.
    ///
    /// Public API per Tahap 15.21 spec.
    ///
    /// Returns sorted `Vec<PathBuf>`. Zero-padded filenames ensure
    /// lexicographic order = sequence order.
    pub fn list_log_files(&self) -> dsdn_common::Result<Vec<PathBuf>> {
        let files = self.list_worm_files().map_err(|e| {
            Box::new(e) as Box<dyn std::error::Error + Send + Sync>
        })?;
        Ok(files)
    }

    /// Internal sorted listing of .worm files.
    fn list_worm_files(&self) -> Result<Vec<PathBuf>, AuditLogError> {
        let expected_prefix = format!("{}_", self.config.file_prefix);
        let expected_ext = format!(".{}", WORM_FILE_EXTENSION);

        let entries = fs::read_dir(&self.config.base_dir).map_err(|e| {
            AuditLogError::WriteFailed {
                reason: format!("read_dir {:?}: {}", self.config.base_dir, e),
            }
        })?;

        let mut files: Vec<PathBuf> = Vec::new();
        for entry_result in entries {
            let entry = match entry_result {
                Ok(e) => e,
                Err(_) => continue,
            };
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with(&expected_prefix) && name.ends_with(&expected_ext) {
                files.push(entry.path());
            }
        }

        files.sort();
        Ok(files)
    }

    /// Scan all `.worm` files and recover the last valid sequence.
    ///
    /// This is a **read-only operation**. No files are modified or deleted.
    ///
    /// - Reads each file sequentially.
    /// - Validates each entry: length header, data, CRC32.
    /// - Stops scanning a file on first partial/corrupted entry.
    /// - Updates `current_sequence` to `last_valid_sequence`.
    ///
    /// Returns a `RecoveryReport` summarizing what was found.
    pub fn recover(&self) -> dsdn_common::Result<RecoveryReport> {
        let files = self.list_worm_files().map_err(|e| {
            Box::new(e) as Box<dyn std::error::Error + Send + Sync>
        })?;

        let mut report = RecoveryReport {
            total_entries: 0,
            valid_entries: 0,
            partial_entries: 0,
            last_valid_sequence: 0,
            files_scanned: files.len(),
        };

        for file_path in &files {
            let scan = scan_file_entries(file_path).map_err(|e| {
                Box::new(e) as Box<dyn std::error::Error + Send + Sync>
            })?;

            report.valid_entries = report.valid_entries.saturating_add(scan.valid);
            report.partial_entries = report.partial_entries.saturating_add(scan.partial);
            report.total_entries = report.total_entries
                .saturating_add(scan.valid)
                .saturating_add(scan.partial);
        }

        report.last_valid_sequence = report.valid_entries;

        // Update internal sequence counter to last valid
        self.current_sequence.store(report.last_valid_sequence, Ordering::SeqCst);

        Ok(report)
    }

    /// Find which `.worm` file contains the given sequence number.
    ///
    /// Uses the sorted file list and binary search on `start_seq` from filenames.
    /// Returns the file path where `start_seq <= target` and the next file's
    /// `start_seq > target` (or it's the last file).
    ///
    /// Returns `None` if no matching file is found.
    fn find_file_for_sequence(&self, target: u64) -> Result<Option<PathBuf>, AuditLogError> {
        if target == 0 {
            return Ok(None);
        }

        let files = self.list_worm_files()?;
        if files.is_empty() {
            return Ok(None);
        }

        // Extract (start_seq, path) pairs
        let mut file_seqs: Vec<(u64, PathBuf)> = Vec::new();
        for path in files {
            if let Some(start) = extract_file_start_seq(&path, &self.config.file_prefix) {
                file_seqs.push((start, path));
            }
        }

        if file_seqs.is_empty() {
            return Ok(None);
        }

        // Already sorted by filename = sorted by start_seq
        // Find the file with largest start_seq <= target
        let mut result_idx = 0;
        for (i, (start_seq, _)) in file_seqs.iter().enumerate() {
            if *start_seq <= target {
                result_idx = i;
            } else {
                break;
            }
        }

        if file_seqs[result_idx].0 <= target {
            Ok(Some(file_seqs[result_idx].1.clone()))
        } else {
            Ok(None)
        }
    }

    /// Build a map of (file_start_seq, path) pairs sorted by start_seq.
    fn build_file_seq_map(&self) -> Result<Vec<(u64, PathBuf)>, AuditLogError> {
        let files = self.list_worm_files()?;
        let mut file_seqs: Vec<(u64, PathBuf)> = Vec::new();
        for path in files {
            if let Some(start) = extract_file_start_seq(&path, &self.config.file_prefix) {
                file_seqs.push((start, path));
            }
        }
        // Already sorted by filename
        Ok(file_seqs)
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// FILE READING HELPERS
// ════════════════════════════════════════════════════════════════════════════════

/// Extract start_sequence from a `.worm` filename.
///
/// Filename format: `{prefix}_{sequence:016}.worm`
///
/// Returns `None` if the filename doesn't match the expected pattern.
fn extract_file_start_seq(path: &std::path::Path, prefix: &str) -> Option<u64> {
    let file_name = path.file_name()?.to_string_lossy().to_string();
    let expected_prefix = format!("{}_", prefix);
    let expected_ext = format!(".{}", WORM_FILE_EXTENSION);

    if !file_name.starts_with(&expected_prefix) || !file_name.ends_with(&expected_ext) {
        return None;
    }

    let start = expected_prefix.len();
    let end = file_name.len().saturating_sub(expected_ext.len());
    if start >= end {
        return None;
    }

    file_name[start..end].parse::<u64>().ok()
}

/// Read a single entry at the given byte offset in a byte slice.
///
/// Entry format: `[len:8 LE][data:N][crc32:4 LE]`
///
/// Returns `(entry_data, bytes_consumed)` or error on CRC mismatch / truncation.
fn read_entry_at_offset(all_bytes: &[u8], offset: usize) -> Result<(Vec<u8>, usize), AuditLogError> {
    // Step 1: Read 8-byte length
    if offset + 8 > all_bytes.len() {
        return Err(AuditLogError::RecoveryFailed {
            reason: format!("incomplete header at offset {}", offset),
        });
    }

    let len_bytes: [u8; 8] = all_bytes[offset..offset + 8]
        .try_into()
        .map_err(|_| AuditLogError::RecoveryFailed {
            reason: format!("failed to read length at offset {}", offset),
        })?;
    let entry_len = u64::from_le_bytes(len_bytes) as usize;

    // Step 3: Read N bytes data
    let data_start = offset + 8;
    if data_start + entry_len > all_bytes.len() {
        return Err(AuditLogError::RecoveryFailed {
            reason: format!("incomplete data at offset {}: need {} have {}", offset, entry_len, all_bytes.len() - data_start),
        });
    }

    let data = all_bytes[data_start..data_start + entry_len].to_vec();

    // Step 4: Read 4-byte CRC
    let crc_start = data_start + entry_len;
    if crc_start + 4 > all_bytes.len() {
        return Err(AuditLogError::RecoveryFailed {
            reason: format!("incomplete CRC at offset {}", crc_start),
        });
    }

    let crc_bytes: [u8; 4] = all_bytes[crc_start..crc_start + 4]
        .try_into()
        .map_err(|_| AuditLogError::RecoveryFailed {
            reason: format!("failed to read CRC at offset {}", crc_start),
        })?;
    let stored_crc = u32::from_le_bytes(crc_bytes);

    // Step 5-6: Verify CRC
    let computed_crc = crc32_ieee(&data);
    if stored_crc != computed_crc {
        return Err(AuditLogError::RecoveryFailed {
            reason: format!("CRC mismatch at offset {}: stored={:#010X} computed={:#010X}", offset, stored_crc, computed_crc),
        });
    }

    // Step 7: Return (data, bytes_consumed)
    let bytes_consumed = 8 + entry_len + 4;
    Ok((data, bytes_consumed))
}

/// Read a file's raw bytes.
fn read_file_bytes(path: &std::path::Path) -> Result<Vec<u8>, AuditLogError> {
    let mut file = fs::File::open(path).map_err(|e| {
        AuditLogError::WriteFailed {
            reason: format!("open {:?} for read: {}", path, e),
        }
    })?;

    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|e| {
        AuditLogError::WriteFailed {
            reason: format!("read {:?}: {}", path, e),
        }
    })?;

    Ok(bytes)
}

/// Result of scanning a single file for valid/partial entries.
struct FileScanResult {
    valid: u64,
    partial: u64,
}

/// Read all entries from a single `.worm` file.
///
/// Entry format: `[len:8 LE][data:N][crc32:4 LE]`
///
/// Returns the data portion of each entry.
/// Stops at EOF or incomplete entry (partial write tolerance).
fn read_all_entries_from_file(path: &std::path::Path) -> Result<Vec<Vec<u8>>, AuditLogError> {
    let all_bytes = read_file_bytes(path)?;
    let mut entries = Vec::new();
    let mut cursor: usize = 0;

    while cursor < all_bytes.len() {
        match read_entry_at_offset(&all_bytes, cursor) {
            Ok((data, consumed)) => {
                entries.push(data);
                cursor += consumed;
            }
            Err(_) => break, // Partial/corrupted entry — stop here
        }
    }

    Ok(entries)
}

/// Scan a single `.worm` file to count valid and partial entries.
///
/// Read-only. Validates each entry's length header, data, and CRC32.
/// Stops at first partial/corrupted entry.
fn scan_file_entries(path: &std::path::Path) -> Result<FileScanResult, AuditLogError> {
    let mut file = fs::File::open(path).map_err(|e| {
        AuditLogError::RecoveryFailed {
            reason: format!("open {:?}: {}", path, e),
        }
    })?;

    let mut all_bytes = Vec::new();
    file.read_to_end(&mut all_bytes).map_err(|e| {
        AuditLogError::RecoveryFailed {
            reason: format!("read {:?}: {}", path, e),
        }
    })?;

    let mut valid: u64 = 0;
    let mut cursor: usize = 0;

    while cursor < all_bytes.len() {
        // Step 1: Read 8-byte length header
        if cursor + 8 > all_bytes.len() {
            return Ok(FileScanResult { valid, partial: 1 });
        }

        let len_bytes: [u8; 8] = match all_bytes[cursor..cursor + 8].try_into() {
            Ok(b) => b,
            Err(_) => return Ok(FileScanResult { valid, partial: 1 }),
        };
        let entry_len = u64::from_le_bytes(len_bytes) as usize;
        cursor += 8;

        // Step 3: Read N bytes data
        if cursor + entry_len > all_bytes.len() {
            return Ok(FileScanResult { valid, partial: 1 });
        }

        let data = &all_bytes[cursor..cursor + entry_len];
        cursor += entry_len;

        // Step 4: Read 4-byte CRC32
        if cursor + 4 > all_bytes.len() {
            return Ok(FileScanResult { valid, partial: 1 });
        }

        let crc_bytes: [u8; 4] = match all_bytes[cursor..cursor + 4].try_into() {
            Ok(b) => b,
            Err(_) => return Ok(FileScanResult { valid, partial: 1 }),
        };
        let stored_crc = u32::from_le_bytes(crc_bytes);
        cursor += 4;

        // Step 5: Verify CRC32
        let computed_crc = crc32_ieee(data);
        if stored_crc != computed_crc {
            return Ok(FileScanResult { valid, partial: 1 });
        }

        // Step 6: Valid entry
        valid += 1;
    }

    Ok(FileScanResult { valid, partial: 0 })
}

// ════════════════════════════════════════════════════════════════════════════════
// WormLogStorage TRAIT IMPLEMENTATION
// ════════════════════════════════════════════════════════════════════════════════

impl WormLogStorage for WormFileStorage {
    fn append(&self, entry_bytes: &[u8]) -> Result<u64, AuditLogError> {
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

    fn read_entry(&self, sequence: u64) -> Result<Option<Vec<u8>>, AuditLogError> {
        if sequence == 0 || sequence > self.current_sequence.load(Ordering::SeqCst) {
            return Ok(None);
        }

        // Use file map to skip files before the target
        let file_map = self.build_file_seq_map()?;
        if file_map.is_empty() {
            return Ok(None);
        }

        // Find which file contains the target sequence
        let mut global_seq: u64 = 0;

        for (_, file_path) in &file_map {
            let all_bytes = read_file_bytes(file_path)?;
            let mut cursor: usize = 0;

            while cursor < all_bytes.len() {
                match read_entry_at_offset(&all_bytes, cursor) {
                    Ok((data, consumed)) => {
                        global_seq += 1;
                        if global_seq == sequence {
                            return Ok(Some(data));
                        }
                        cursor += consumed;
                    }
                    Err(_) => break, // Partial entry
                }
            }
        }

        Ok(None)
    }

    fn read_range(&self, start: u64, end: u64) -> Result<Vec<Vec<u8>>, AuditLogError> {
        if start > end {
            return Err(AuditLogError::SequenceGap {
                expected: start,
                got: end,
            });
        }
        if start == end {
            return Ok(Vec::new());
        }

        let file_map = self.build_file_seq_map()?;
        let mut result = Vec::new();
        let mut global_seq: u64 = 0;

        for (_, file_path) in &file_map {
            let all_bytes = read_file_bytes(file_path)?;
            let mut cursor: usize = 0;

            while cursor < all_bytes.len() {
                match read_entry_at_offset(&all_bytes, cursor) {
                    Ok((data, consumed)) => {
                        global_seq += 1;
                        if global_seq >= start && global_seq < end {
                            result.push(data);
                        }
                        if global_seq >= end {
                            return Ok(result);
                        }
                        cursor += consumed;
                    }
                    Err(_) => break,
                }
            }
        }

        Ok(result)
    }

    fn last_sequence(&self) -> Result<u64, AuditLogError> {
        Ok(self.current_sequence.load(Ordering::SeqCst))
    }

    fn entry_count(&self) -> Result<u64, AuditLogError> {
        Ok(self.current_sequence.load(Ordering::SeqCst))
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
    #[allow(unused_imports)]
    use dsdn_common::WormLogStorage;

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

    // ════════════════════════════════════════════════════════════════════════
    // 15.21 FILE ROTATION TESTS
    // ════════════════════════════════════════════════════════════════════════

    fn count_worm_files(dir: &std::path::Path) -> usize {
        fs::read_dir(dir)
            .map(|rd| rd.filter_map(|e| e.ok())
                .filter(|e| e.path().extension().map_or(false, |ext| ext == "worm"))
                .count())
            .unwrap_or(0)
    }

    fn get_worm_filenames(dir: &std::path::Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .map(|rd| rd.filter_map(|e| e.ok())
                .filter(|e| e.path().extension().map_or(false, |ext| ext == "worm"))
                .map(|e| e.file_name().to_string_lossy().to_string())
                .collect())
            .unwrap_or_default();
        names.sort();
        names
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 20: file_rotation_trigger
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn file_rotation_trigger() {
        let dir = temp_dir();
        let mut cfg = WormFileConfig::new(dir.clone());
        cfg.max_file_size_bytes = 40; // Very small: entry = 8+10+4 = 22 bytes
        cfg.sync_on_write = false;

        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                // Entry 1 (22 bytes): check(0<40)→pass, size=22
                let _ = storage.append(b"0123456789");
                assert_eq!(count_worm_files(&dir), 1);

                // Entry 2 (22 bytes): check(22<40)→pass, size=44
                let _ = storage.append(b"0123456789");
                assert_eq!(count_worm_files(&dir), 1, "not yet rotated");

                // Entry 3: check(44>=40)→ROTATE, new file, size=22
                let _ = storage.append(b"0123456789");
                assert!(count_worm_files(&dir) >= 2, "rotation must create new file");
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 21: file_rotation_creates_new_file
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn file_rotation_creates_new_file() {
        let dir = temp_dir();
        let mut cfg = WormFileConfig::new(dir.clone());
        cfg.max_file_size_bytes = 30;
        cfg.sync_on_write = false;

        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                let _ = storage.append(b"entry_one__"); // 8+11+4=23, check(0<30)→pass, size=23
                let _ = storage.append(b"entry_two__"); // check(23<30)→pass, size=46
                let before = count_worm_files(&dir);

                let _ = storage.append(b"entry_three"); // check(46>=30)→ROTATE
                let after = count_worm_files(&dir);

                assert!(after > before, "new file must be created: before={}, after={}", before, after);
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 22: rotation_filename_format
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn rotation_filename_format() {
        let dir = temp_dir();
        let mut cfg = WormFileConfig::new(dir.clone());
        cfg.max_file_size_bytes = 30;
        cfg.sync_on_write = false;
        cfg.file_prefix = "myaudit".to_string();

        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                let _ = storage.append(b"entry_one__");
                let _ = storage.append(b"entry_two__");

                let names = get_worm_filenames(&dir);
                for name in &names {
                    assert!(name.starts_with("myaudit_"), "must start with prefix: {}", name);
                    assert!(name.ends_with(".worm"), "must end with .worm: {}", name);
                    // Extract sequence part
                    let seq_part = &name["myaudit_".len()..name.len() - ".worm".len()];
                    assert_eq!(seq_part.len(), 16, "sequence must be 16 digits: {}", seq_part);
                    assert!(seq_part.parse::<u64>().is_ok(), "must be valid u64: {}", seq_part);
                }
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 23: rotation_resets_file_size
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn rotation_resets_file_size() {
        let dir = temp_dir();
        let mut cfg = WormFileConfig::new(dir.clone());
        cfg.max_file_size_bytes = 30;
        cfg.sync_on_write = false;

        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                let _ = storage.append(b"entry_one__"); // size=23
                let _ = storage.append(b"entry_two__"); // size=46 (exceeds 30)
                let size_before_rotation = storage.current_file_size();
                assert!(size_before_rotation >= 30, "must exceed max before rotation triggers");

                // Entry 3 triggers rotation at start → reset size → write 23
                let _ = storage.append(b"entry_three");
                let size_after = storage.current_file_size();

                // After rotation, size should be just the new entry (23), not 46+23
                assert!(size_after < size_before_rotation,
                    "file size must reset after rotation: before={}, after={}", size_before_rotation, size_after);
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 24: append_after_rotation_goes_to_new_file
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn append_after_rotation_goes_to_new_file() {
        let dir = temp_dir();
        let mut cfg = WormFileConfig::new(dir.clone());
        cfg.max_file_size_bytes = 30;
        cfg.sync_on_write = false;

        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                let _ = storage.append(b"AAAAAAAAAA"); // size=22
                let _ = storage.append(b"AAAAAAAAAA"); // size=44 (exceeds 30)
                let _ = storage.append(b"BBBBBBBBBB"); // check(44>=30)→ROTATE, B goes to new file

                let names = get_worm_filenames(&dir);
                assert!(names.len() >= 2, "must have at least 2 files");

                // Read last file — should contain B's
                let last_file = dir.join(&names[names.len() - 1]);
                let entries = read_all_entries_from_file(&last_file);
                match entries {
                    Ok(e) => {
                        assert!(!e.is_empty(), "new file must have entries");
                        assert_eq!(e[0], b"BBBBBBBBBB", "new file must contain rotated entry");
                    }
                    Err(e) => assert!(false, "read: {}", e),
                }
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 25: old_file_not_modified
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn old_file_not_modified() {
        let dir = temp_dir();
        let mut cfg = WormFileConfig::new(dir.clone());
        cfg.max_file_size_bytes = 30;
        cfg.sync_on_write = false;

        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                // Fill first file past max (rotation hasn't triggered yet)
                let _ = storage.append(b"first_data");  // size=22
                let _ = storage.append(b"second_dat");  // size=44 (exceeds 30)

                // Snapshot the first file BEFORE rotation
                let names = get_worm_filenames(&dir);
                assert_eq!(names.len(), 1, "still 1 file before rotation triggers");
                let first_file = dir.join(&names[0]);
                let size_before = fs::metadata(&first_file).map(|m| m.len()).unwrap_or(0);
                let content_before = fs::read(&first_file).unwrap_or_default();

                // Trigger rotation with 3rd append
                let _ = storage.append(b"third_data");
                let _ = storage.append(b"fourth_dat");

                // Old file must NOT have changed after rotation
                let size_after = fs::metadata(&first_file).map(|m| m.len()).unwrap_or(0);
                let content_after = fs::read(&first_file).unwrap_or_default();

                assert_eq!(size_before, size_after, "old file size must not change");
                assert_eq!(content_before, content_after, "old file content must not change");
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 26: list_log_files_returns_sorted
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn list_log_files_returns_sorted() {
        let dir = temp_dir();
        let mut cfg = WormFileConfig::new(dir.clone());
        cfg.max_file_size_bytes = 25;
        cfg.sync_on_write = false;

        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                for i in 0..5 {
                    let data = format!("entry_{:04}", i);
                    let _ = storage.append(data.as_bytes());
                }

                let files = storage.list_log_files();
                match files {
                    Ok(paths) => {
                        assert!(paths.len() >= 2, "multiple files expected");
                        // Verify sorted
                        for i in 1..paths.len() {
                            let prev = paths[i - 1].file_name().map(|f| f.to_string_lossy().to_string());
                            let curr = paths[i].file_name().map(|f| f.to_string_lossy().to_string());
                            match (prev, curr) {
                                (Some(p), Some(c)) => {
                                    assert!(p < c, "files must be sorted: {} < {}", p, c);
                                }
                                _ => assert!(false, "filenames must be valid"),
                            }
                        }
                    }
                    Err(e) => assert!(false, "list_log_files: {}", e),
                }
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 27: list_log_files_filters_non_worm
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn list_log_files_filters_non_worm() {
        let dir = temp_dir();
        let _ = fs::create_dir_all(&dir);

        // Create non-worm files
        let _ = fs::write(dir.join("random.txt"), b"noise");
        let _ = fs::write(dir.join("audit_log_not_worm.log"), b"noise");
        let _ = fs::write(dir.join("other_0000000000000001.worm"), b"wrong prefix");

        let cfg = WormFileConfig::new(dir.clone());
        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                // Append one entry to create a real worm file
                let _ = storage.append(b"real_data");

                let files = storage.list_log_files();
                match files {
                    Ok(paths) => {
                        assert_eq!(paths.len(), 1, "only 1 matching worm file");
                        let name = paths[0].file_name().map(|f| f.to_string_lossy().to_string());
                        match name {
                            Some(n) => {
                                assert!(n.starts_with("audit_log_"), "must match prefix");
                                assert!(n.ends_with(".worm"), "must have .worm ext");
                            }
                            None => assert!(false, "filename must be valid"),
                        }
                    }
                    Err(e) => assert!(false, "list: {}", e),
                }
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 28: rotation_multiple_times
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn rotation_multiple_times() {
        let dir = temp_dir();
        let mut cfg = WormFileConfig::new(dir.clone());
        cfg.max_file_size_bytes = 25; // entry = 8+10+4 = 22 → rotation after each entry
        cfg.sync_on_write = false;

        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                for i in 1u64..=10 {
                    let seq = storage.append(b"0123456789");
                    match seq {
                        Ok(s) => assert_eq!(s, i, "sequence must be correct"),
                        Err(e) => assert!(false, "append {}: {}", i, e),
                    }
                }

                let files = count_worm_files(&dir);
                assert!(files >= 5, "many rotations must create many files, got {}", files);

                assert_eq!(storage.current_sequence(), 10);
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 29: rotation_does_not_break_sequence
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn rotation_does_not_break_sequence() {
        let dir = temp_dir();
        let mut cfg = WormFileConfig::new(dir.clone());
        cfg.max_file_size_bytes = 30;
        cfg.sync_on_write = false;

        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                let mut prev_seq = 0u64;
                for _ in 0..20 {
                    let seq = storage.append(b"test_data_");
                    match seq {
                        Ok(s) => {
                            assert_eq!(s, prev_seq + 1, "sequence must be strictly +1");
                            prev_seq = s;
                        }
                        Err(e) => assert!(false, "append: {}", e),
                    }
                }

                // All 20 entries must be readable via read_range
                let all = storage.read_range(1, 21);
                match all {
                    Ok(entries) => {
                        assert_eq!(entries.len(), 20, "all 20 entries must be readable across files");
                        for entry in &entries {
                            assert_eq!(entry.as_slice(), b"test_data_");
                        }
                    }
                    Err(e) => assert!(false, "read_range: {}", e),
                }
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // 15.22 RECOVERY TESTS
    // ════════════════════════════════════════════════════════════════════════

    /// Write a complete valid entry directly to a file (bypassing storage).
    fn write_raw_entry(path: &std::path::Path, data: &[u8]) {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path);
        if let Ok(mut f) = file {
            let len_bytes = (data.len() as u64).to_le_bytes();
            let crc = crc32_ieee(data);
            let crc_bytes = crc.to_le_bytes();
            let _ = f.write_all(&len_bytes);
            let _ = f.write_all(data);
            let _ = f.write_all(&crc_bytes);
        }
    }

    /// Append raw bytes to a file (for simulating partial writes).
    fn append_raw_bytes(path: &std::path::Path, bytes: &[u8]) {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path);
        if let Ok(mut f) = file {
            let _ = f.write_all(bytes);
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 30: recovery_empty_storage
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn recovery_empty_storage() {
        let dir = temp_dir();
        let cfg = WormFileConfig::new(dir.clone());
        let result = WormFileStorage::new(cfg);

        match result {
            Ok(storage) => {
                let report = storage.recover();
                match report {
                    Ok(r) => {
                        assert_eq!(r.total_entries, 0);
                        assert_eq!(r.valid_entries, 0);
                        assert_eq!(r.partial_entries, 0);
                        assert_eq!(r.last_valid_sequence, 0);
                        assert_eq!(r.files_scanned, 0);
                    }
                    Err(e) => assert!(false, "recover: {}", e),
                }
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 31: recovery_single_valid_entry
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn recovery_single_valid_entry() {
        let dir = temp_dir();
        let _ = fs::create_dir_all(&dir);

        let file_path = dir.join("audit_log_0000000000000001.worm");
        write_raw_entry(&file_path, b"valid_entry_data");

        let cfg = WormFileConfig::new(dir.clone());
        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                let report = storage.recover();
                match report {
                    Ok(r) => {
                        assert_eq!(r.valid_entries, 1);
                        assert_eq!(r.partial_entries, 0);
                        assert_eq!(r.total_entries, 1);
                        assert_eq!(r.last_valid_sequence, 1);
                        assert_eq!(r.files_scanned, 1);
                    }
                    Err(e) => assert!(false, "recover: {}", e),
                }
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 32: recovery_multiple_valid_entries
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn recovery_multiple_valid_entries() {
        let dir = temp_dir();
        let _ = fs::create_dir_all(&dir);

        let file_path = dir.join("audit_log_0000000000000001.worm");
        write_raw_entry(&file_path, b"entry_one");
        write_raw_entry(&file_path, b"entry_two");
        write_raw_entry(&file_path, b"entry_three");

        let cfg = WormFileConfig::new(dir.clone());
        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                let report = storage.recover();
                match report {
                    Ok(r) => {
                        assert_eq!(r.valid_entries, 3);
                        assert_eq!(r.partial_entries, 0);
                        assert_eq!(r.total_entries, 3);
                        assert_eq!(r.last_valid_sequence, 3);
                    }
                    Err(e) => assert!(false, "recover: {}", e),
                }
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 33: recovery_partial_header
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn recovery_partial_header() {
        let dir = temp_dir();
        let _ = fs::create_dir_all(&dir);

        let file_path = dir.join("audit_log_0000000000000001.worm");
        write_raw_entry(&file_path, b"valid_entry");
        // Simulate crash: only 3 bytes of next header
        append_raw_bytes(&file_path, &[0x05, 0x00, 0x00]);

        let cfg = WormFileConfig::new(dir.clone());
        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                let report = storage.recover();
                match report {
                    Ok(r) => {
                        assert_eq!(r.valid_entries, 1);
                        assert_eq!(r.partial_entries, 1);
                        assert_eq!(r.last_valid_sequence, 1);
                    }
                    Err(e) => assert!(false, "recover: {}", e),
                }
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 34: recovery_partial_data
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn recovery_partial_data() {
        let dir = temp_dir();
        let _ = fs::create_dir_all(&dir);

        let file_path = dir.join("audit_log_0000000000000001.worm");
        write_raw_entry(&file_path, b"valid_entry");
        // Write header saying 100 bytes, but only write 5
        let len_bytes = (100u64).to_le_bytes();
        append_raw_bytes(&file_path, &len_bytes);
        append_raw_bytes(&file_path, b"short");

        let cfg = WormFileConfig::new(dir.clone());
        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                let report = storage.recover();
                match report {
                    Ok(r) => {
                        assert_eq!(r.valid_entries, 1);
                        assert_eq!(r.partial_entries, 1);
                        assert_eq!(r.last_valid_sequence, 1);
                    }
                    Err(e) => assert!(false, "recover: {}", e),
                }
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 35: recovery_crc_mismatch
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn recovery_crc_mismatch() {
        let dir = temp_dir();
        let _ = fs::create_dir_all(&dir);

        let file_path = dir.join("audit_log_0000000000000001.worm");
        write_raw_entry(&file_path, b"valid_entry");

        // Write entry with wrong CRC
        let data = b"bad_crc_data";
        let len_bytes = (data.len() as u64).to_le_bytes();
        let wrong_crc = 0xDEADBEEFu32.to_le_bytes();
        append_raw_bytes(&file_path, &len_bytes);
        append_raw_bytes(&file_path, data);
        append_raw_bytes(&file_path, &wrong_crc);

        let cfg = WormFileConfig::new(dir.clone());
        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                let report = storage.recover();
                match report {
                    Ok(r) => {
                        assert_eq!(r.valid_entries, 1);
                        assert_eq!(r.partial_entries, 1, "CRC mismatch must count as partial");
                        assert_eq!(r.last_valid_sequence, 1);
                    }
                    Err(e) => assert!(false, "recover: {}", e),
                }
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 36: recovery_sequence_correct
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn recovery_sequence_correct() {
        let dir = temp_dir();
        let mut cfg = WormFileConfig::new(dir.clone());
        cfg.sync_on_write = false;

        let result = WormFileStorage::new(cfg.clone());
        match result {
            Ok(storage) => {
                for _ in 0..7 {
                    let _ = storage.append(b"entry_data_");
                }
                assert_eq!(storage.current_sequence(), 7);

                // Create fresh storage to simulate restart
                let storage2 = WormFileStorage::new(cfg);
                match storage2 {
                    Ok(s2) => {
                        let report = s2.recover();
                        match report {
                            Ok(r) => {
                                assert_eq!(r.valid_entries, 7);
                                assert_eq!(r.last_valid_sequence, 7);
                                // current_sequence must be updated
                                assert_eq!(s2.current_sequence(), 7);
                            }
                            Err(e) => assert!(false, "recover: {}", e),
                        }
                    }
                    Err(e) => assert!(false, "new2: {}", e),
                }
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 37: recovery_multiple_files
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn recovery_multiple_files() {
        let dir = temp_dir();
        let _ = fs::create_dir_all(&dir);

        // Create multiple worm files manually
        let file1 = dir.join("audit_log_0000000000000001.worm");
        write_raw_entry(&file1, b"file1_entry1");
        write_raw_entry(&file1, b"file1_entry2");

        let file2 = dir.join("audit_log_0000000000000003.worm");
        write_raw_entry(&file2, b"file2_entry1");
        write_raw_entry(&file2, b"file2_entry2");
        write_raw_entry(&file2, b"file2_entry3");

        let cfg = WormFileConfig::new(dir.clone());
        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                let report = storage.recover();
                match report {
                    Ok(r) => {
                        assert_eq!(r.files_scanned, 2);
                        assert_eq!(r.valid_entries, 5);
                        assert_eq!(r.partial_entries, 0);
                        assert_eq!(r.last_valid_sequence, 5);
                    }
                    Err(e) => assert!(false, "recover: {}", e),
                }
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 38: recovery_detects_partial_entry
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn recovery_detects_partial_entry() {
        let dir = temp_dir();
        let mut cfg = WormFileConfig::new(dir.clone());
        cfg.sync_on_write = false;

        let result = WormFileStorage::new(cfg.clone());
        match result {
            Ok(storage) => {
                let _ = storage.append(b"entry_one__");
                let _ = storage.append(b"entry_two__");
            }
            Err(e) => {
                assert!(false, "new: {}", e);
                return;
            }
        }

        // Simulate crash: append partial data to the worm file
        let files: Vec<_> = fs::read_dir(&dir)
            .map(|rd| rd.filter_map(|e| e.ok())
                .filter(|e| e.path().extension().map_or(false, |ext| ext == "worm"))
                .map(|e| e.path())
                .collect())
            .unwrap_or_default();

        if let Some(last_file) = files.last() {
            // Append incomplete entry: header only, no data
            let len_bytes = (50u64).to_le_bytes();
            append_raw_bytes(last_file, &len_bytes);
        }

        let cfg2 = WormFileConfig::new(dir.clone());
        let result2 = WormFileStorage::new(cfg2);
        match result2 {
            Ok(storage2) => {
                let report = storage2.recover();
                match report {
                    Ok(r) => {
                        assert_eq!(r.valid_entries, 2, "2 valid entries before crash");
                        assert_eq!(r.partial_entries, 1, "1 partial entry after crash");
                    }
                    Err(e) => assert!(false, "recover: {}", e),
                }
            }
            Err(e) => assert!(false, "new2: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 39: recovery_does_not_modify_files
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn recovery_does_not_modify_files() {
        let dir = temp_dir();
        let _ = fs::create_dir_all(&dir);

        let file_path = dir.join("audit_log_0000000000000001.worm");
        write_raw_entry(&file_path, b"valid_data");
        // Add partial entry
        append_raw_bytes(&file_path, &[0x0A, 0x00, 0x00]);

        let size_before = fs::metadata(&file_path).map(|m| m.len()).unwrap_or(0);
        let content_before = fs::read(&file_path).unwrap_or_default();

        let cfg = WormFileConfig::new(dir.clone());
        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                let _ = storage.recover();

                // File must NOT be modified by recovery
                let size_after = fs::metadata(&file_path).map(|m| m.len()).unwrap_or(0);
                let content_after = fs::read(&file_path).unwrap_or_default();

                assert_eq!(size_before, size_after, "file size must not change");
                assert_eq!(content_before, content_after, "file content must not change");
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // 15.23 READ / QUERY TESTS
    // ════════════════════════════════════════════════════════════════════════

    // ════════════════════════════════════════════════════════════════════════
    // TEST 40: read_single_entry
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn read_single_entry() {
        let dir = temp_dir();
        let mut cfg = WormFileConfig::new(dir.clone());
        cfg.sync_on_write = false;

        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                let _ = storage.append(b"hello_world");
                let entry = storage.read_entry(1);
                match entry {
                    Ok(Some(data)) => assert_eq!(data, b"hello_world"),
                    Ok(None) => assert!(false, "entry 1 must exist"),
                    Err(e) => assert!(false, "read_entry: {}", e),
                }
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 41: read_entry_not_found
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn read_entry_not_found() {
        let dir = temp_dir();
        let mut cfg = WormFileConfig::new(dir.clone());
        cfg.sync_on_write = false;

        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                let _ = storage.append(b"data");

                // seq 0 → None
                let r0 = storage.read_entry(0);
                match r0 {
                    Ok(opt) => assert!(opt.is_none(), "seq 0 must be None"),
                    Err(e) => assert!(false, "read 0: {}", e),
                }

                // seq beyond range → None
                let r99 = storage.read_entry(99);
                match r99 {
                    Ok(opt) => assert!(opt.is_none(), "seq 99 must be None"),
                    Err(e) => assert!(false, "read 99: {}", e),
                }
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 42: read_range_basic
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn read_range_basic() {
        let dir = temp_dir();
        let mut cfg = WormFileConfig::new(dir.clone());
        cfg.sync_on_write = false;

        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                for i in 1u64..=5 {
                    let data = format!("entry_{}", i);
                    let _ = storage.append(data.as_bytes());
                }

                // [2, 4) → entries 2, 3
                let range = storage.read_range(2, 4);
                match range {
                    Ok(entries) => {
                        assert_eq!(entries.len(), 2);
                        assert_eq!(entries[0], b"entry_2");
                        assert_eq!(entries[1], b"entry_3");
                    }
                    Err(e) => assert!(false, "read_range: {}", e),
                }
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 43: read_range_multiple_files
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn read_range_multiple_files() {
        let dir = temp_dir();
        let mut cfg = WormFileConfig::new(dir.clone());
        cfg.max_file_size_bytes = 30; // Force rotation
        cfg.sync_on_write = false;

        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                for i in 1u64..=10 {
                    let data = format!("entry_{:02}", i);
                    let _ = storage.append(data.as_bytes());
                }

                assert!(count_worm_files(&dir) > 1, "must have multiple files");

                // Read all 10 across file boundaries
                let all = storage.read_range(1, 11);
                match all {
                    Ok(entries) => {
                        assert_eq!(entries.len(), 10);
                        for (i, entry) in entries.iter().enumerate() {
                            let expected = format!("entry_{:02}", i + 1);
                            assert_eq!(entry.as_slice(), expected.as_bytes(), "entry {} mismatch", i + 1);
                        }
                    }
                    Err(e) => assert!(false, "read_range: {}", e),
                }
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 44: read_range_empty
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn read_range_empty() {
        let dir = temp_dir();
        let mut cfg = WormFileConfig::new(dir.clone());
        cfg.sync_on_write = false;

        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                let _ = storage.append(b"data");

                // start == end → empty
                let r1 = storage.read_range(1, 1);
                match r1 {
                    Ok(v) => assert!(v.is_empty()),
                    Err(e) => assert!(false, "read_range(1,1): {}", e),
                }

                // start > end → error
                let r2 = storage.read_range(5, 2);
                assert!(r2.is_err(), "start > end must error");
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 45: read_range_single_entry
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn read_range_single_entry() {
        let dir = temp_dir();
        let mut cfg = WormFileConfig::new(dir.clone());
        cfg.sync_on_write = false;

        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                let _ = storage.append(b"only_one");

                let range = storage.read_range(1, 2);
                match range {
                    Ok(entries) => {
                        assert_eq!(entries.len(), 1);
                        assert_eq!(entries[0], b"only_one");
                    }
                    Err(e) => assert!(false, "read_range: {}", e),
                }
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 46: last_sequence_correct
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn last_sequence_correct() {
        let dir = temp_dir();
        let mut cfg = WormFileConfig::new(dir.clone());
        cfg.sync_on_write = false;

        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                let ls0 = storage.last_sequence();
                match ls0 {
                    Ok(s) => assert_eq!(s, 0, "empty → 0"),
                    Err(e) => assert!(false, "last_sequence: {}", e),
                }

                for _ in 0..7 {
                    let _ = storage.append(b"data");
                }

                let ls7 = storage.last_sequence();
                match ls7 {
                    Ok(s) => assert_eq!(s, 7),
                    Err(e) => assert!(false, "last_sequence: {}", e),
                }
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 47: entry_count_correct
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn entry_count_correct() {
        let dir = temp_dir();
        let mut cfg = WormFileConfig::new(dir.clone());
        cfg.sync_on_write = false;

        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                let c0 = storage.entry_count();
                match c0 {
                    Ok(c) => assert_eq!(c, 0),
                    Err(e) => assert!(false, "entry_count: {}", e),
                }

                for _ in 0..5 {
                    let _ = storage.append(b"data");
                }

                let c5 = storage.entry_count();
                match c5 {
                    Ok(c) => assert_eq!(c, 5),
                    Err(e) => assert!(false, "entry_count: {}", e),
                }
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 48: find_file_for_sequence_basic
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn find_file_for_sequence_basic() {
        let dir = temp_dir();
        let mut cfg = WormFileConfig::new(dir.clone());
        cfg.max_file_size_bytes = 30;
        cfg.sync_on_write = false;

        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                for _ in 0..5 {
                    let _ = storage.append(b"test_data_");
                }

                // Find file for sequence 1
                let f1 = storage.find_file_for_sequence(1);
                match f1 {
                    Ok(Some(path)) => {
                        let name = path.file_name().map(|f| f.to_string_lossy().to_string());
                        match name {
                            Some(n) => assert!(n.ends_with(".worm"), "must be worm file"),
                            None => assert!(false, "no filename"),
                        }
                    }
                    Ok(None) => assert!(false, "file for seq 1 must exist"),
                    Err(e) => assert!(false, "find: {}", e),
                }

                // Find file for sequence 0 → None
                let f0 = storage.find_file_for_sequence(0);
                match f0 {
                    Ok(opt) => assert!(opt.is_none(), "seq 0 must be None"),
                    Err(e) => assert!(false, "find 0: {}", e),
                }
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 49: find_file_for_sequence_edge
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn find_file_for_sequence_edge() {
        let dir = temp_dir();
        let cfg = WormFileConfig::new(dir.clone());

        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                // No files → None
                let f = storage.find_file_for_sequence(1);
                match f {
                    Ok(opt) => assert!(opt.is_none(), "empty storage → None"),
                    Err(e) => assert!(false, "find: {}", e),
                }
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 50: read_entry_crc_validation
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn read_entry_crc_validation() {
        let dir = temp_dir();
        let _ = fs::create_dir_all(&dir);

        let file_path = dir.join("audit_log_0000000000000001.worm");

        // Write valid entry
        write_raw_entry(&file_path, b"valid_data");

        // Write entry with bad CRC
        let data = b"bad_crc_data";
        let len_bytes = (data.len() as u64).to_le_bytes();
        let bad_crc = 0xDEADu32.to_le_bytes();
        append_raw_bytes(&file_path, &len_bytes);
        append_raw_bytes(&file_path, data);
        append_raw_bytes(&file_path, &bad_crc);

        let cfg = WormFileConfig::new(dir.clone());
        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                let _ = storage.recover();

                // Entry 1 should be valid
                let e1 = storage.read_entry(1);
                match e1 {
                    Ok(Some(d)) => assert_eq!(d, b"valid_data"),
                    Ok(None) => assert!(false, "entry 1 must exist"),
                    Err(e) => assert!(false, "read 1: {}", e),
                }

                // Entry 2 should NOT be readable (bad CRC stops scan)
                let e2 = storage.read_entry(2);
                match e2 {
                    Ok(opt) => assert!(opt.is_none(), "entry 2 must be None (bad CRC)"),
                    Err(_) => {} // Also acceptable
                }
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 51: read_range_large_dataset
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn read_range_large_dataset() {
        let dir = temp_dir();
        let mut cfg = WormFileConfig::new(dir.clone());
        cfg.max_file_size_bytes = 50;
        cfg.sync_on_write = false;

        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                // Write 50 entries across many files
                for i in 1u64..=50 {
                    let data = format!("entry_{:04}", i);
                    let _ = storage.append(data.as_bytes());
                }

                assert_eq!(storage.current_sequence(), 50);
                assert!(count_worm_files(&dir) > 5, "many files expected");

                // Read subrange [10, 20)
                let range = storage.read_range(10, 20);
                match range {
                    Ok(entries) => {
                        assert_eq!(entries.len(), 10, "range [10,20) must have 10 entries");
                        for (i, entry) in entries.iter().enumerate() {
                            let expected = format!("entry_{:04}", 10 + i);
                            assert_eq!(entry.as_slice(), expected.as_bytes());
                        }
                    }
                    Err(e) => assert!(false, "read_range: {}", e),
                }

                // Read full range [1, 51)
                let all = storage.read_range(1, 51);
                match all {
                    Ok(entries) => assert_eq!(entries.len(), 50, "all 50 entries"),
                    Err(e) => assert!(false, "read_range all: {}", e),
                }

                // Read single entry from middle
                let e25 = storage.read_entry(25);
                match e25 {
                    Ok(Some(data)) => assert_eq!(data, b"entry_0025".to_vec()),
                    Ok(None) => assert!(false, "entry 25 must exist"),
                    Err(e) => assert!(false, "read 25: {}", e),
                }
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // 15.24 COMPREHENSIVE TEST SUITE
    // ════════════════════════════════════════════════════════════════════════

    // ════════════════════════════════════════════════════════════════════════
    // TEST 52: worm_create_base_dir
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_create_base_dir() {
        let dir = temp_dir().join("nested").join("deep");
        assert!(!dir.exists());

        let cfg = WormFileConfig::new(dir.clone());
        let result = WormFileStorage::new(cfg);
        match result {
            Ok(_) => assert!(dir.exists() && dir.is_dir(), "nested dir must be created"),
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 53: worm_append_single_entry_15_24
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_append_single_entry_15_24() {
        let dir = temp_dir();
        let mut cfg = WormFileConfig::new(dir.clone());
        cfg.sync_on_write = false;

        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                let seq = storage.append(b"comprehensive_test_data");
                match seq {
                    Ok(s) => {
                        assert_eq!(s, 1);
                        // Verify it's persisted and readable
                        let read = storage.read_entry(1);
                        match read {
                            Ok(Some(data)) => assert_eq!(data, b"comprehensive_test_data"),
                            Ok(None) => assert!(false, "entry must exist"),
                            Err(e) => assert!(false, "read: {}", e),
                        }
                    }
                    Err(e) => assert!(false, "append: {}", e),
                }
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 54: worm_append_multiple_entries_15_24
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_append_multiple_entries_15_24() {
        let dir = temp_dir();
        let mut cfg = WormFileConfig::new(dir.clone());
        cfg.sync_on_write = false;

        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                for i in 1u64..=20 {
                    let data = format!("multi_entry_{:04}", i);
                    let seq = storage.append(data.as_bytes());
                    match seq {
                        Ok(s) => assert_eq!(s, i),
                        Err(e) => assert!(false, "append {}: {}", i, e),
                    }
                }

                assert_eq!(storage.current_sequence(), 20);

                // Verify all readable
                let all = storage.read_range(1, 21);
                match all {
                    Ok(entries) => {
                        assert_eq!(entries.len(), 20);
                        for (i, entry) in entries.iter().enumerate() {
                            let expected = format!("multi_entry_{:04}", i + 1);
                            assert_eq!(entry.as_slice(), expected.as_bytes());
                        }
                    }
                    Err(e) => assert!(false, "read_range: {}", e),
                }
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 55: worm_read_entry_by_sequence
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_read_entry_by_sequence() {
        let dir = temp_dir();
        let mut cfg = WormFileConfig::new(dir.clone());
        cfg.sync_on_write = false;

        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                let _ = storage.append(b"first");
                let _ = storage.append(b"second");
                let _ = storage.append(b"third");

                // Read each by sequence
                for (seq, expected) in [(1u64, b"first" as &[u8]), (2, b"second"), (3, b"third")] {
                    let entry = storage.read_entry(seq);
                    match entry {
                        Ok(Some(data)) => assert_eq!(data, expected, "seq {} mismatch", seq),
                        Ok(None) => assert!(false, "seq {} must exist", seq),
                        Err(e) => assert!(false, "read seq {}: {}", seq, e),
                    }
                }

                // Non-existent
                let none = storage.read_entry(99);
                match none {
                    Ok(opt) => assert!(opt.is_none()),
                    Err(e) => assert!(false, "read 99: {}", e),
                }
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 56: worm_read_range_15_24
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_read_range_15_24() {
        let dir = temp_dir();
        let mut cfg = WormFileConfig::new(dir.clone());
        cfg.sync_on_write = false;

        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                for i in 1u64..=10 {
                    let _ = storage.append(format!("r_{}", i).as_bytes());
                }

                // [3, 7) → entries 3,4,5,6
                let range = storage.read_range(3, 7);
                match range {
                    Ok(entries) => {
                        assert_eq!(entries.len(), 4);
                        assert_eq!(entries[0], b"r_3");
                        assert_eq!(entries[3], b"r_6");
                    }
                    Err(e) => assert!(false, "read_range: {}", e),
                }

                // Empty range
                let empty = storage.read_range(5, 5);
                match empty {
                    Ok(v) => assert!(v.is_empty()),
                    Err(e) => assert!(false, "empty range: {}", e),
                }
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 57: worm_sequence_monotonic_15_24
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_sequence_monotonic_15_24() {
        let dir = temp_dir();
        let mut cfg = WormFileConfig::new(dir.clone());
        cfg.sync_on_write = false;

        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                let mut prev = 0u64;
                for _ in 0..30 {
                    let seq = storage.append(b"mono");
                    match seq {
                        Ok(s) => {
                            assert!(s > prev, "must be strictly increasing: {} > {}", s, prev);
                            assert_eq!(s, prev + 1, "must increment by exactly 1");
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
    // TEST 58: worm_append_only_no_overwrite
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_append_only_no_overwrite() {
        let dir = temp_dir();
        let mut cfg = WormFileConfig::new(dir.clone());
        cfg.sync_on_write = false;

        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                let _ = storage.append(b"aaa");
                let size1 = storage.current_file_size();

                let _ = storage.append(b"bbb");
                let size2 = storage.current_file_size();

                let _ = storage.append(b"ccc");
                let size3 = storage.current_file_size();

                assert!(size2 > size1, "file must grow");
                assert!(size3 > size2, "file must keep growing");

                // All three entries readable in order
                let all = storage.read_range(1, 4);
                match all {
                    Ok(entries) => {
                        assert_eq!(entries.len(), 3);
                        assert_eq!(entries[0], b"aaa");
                        assert_eq!(entries[1], b"bbb");
                        assert_eq!(entries[2], b"ccc");
                    }
                    Err(e) => assert!(false, "range: {}", e),
                }
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 59: worm_crc32_checksum_valid
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_crc32_checksum_valid() {
        let dir = temp_dir();
        let mut cfg = WormFileConfig::new(dir.clone());
        cfg.sync_on_write = false;

        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                let test_data = b"crc_validation_test_data";
                let _ = storage.append(test_data);

                // Read raw file and verify CRC
                let files = storage.list_log_files();
                match files {
                    Ok(paths) => {
                        if let Some(path) = paths.first() {
                            let raw = fs::read(path).unwrap_or_default();
                            // entry: [8 len][N data][4 crc]
                            let data_start = 8;
                            let data_end = data_start + test_data.len();
                            let crc_start = data_end;

                            if raw.len() >= crc_start + 4 {
                                let stored_data = &raw[data_start..data_end];
                                assert_eq!(stored_data, test_data, "stored data must match");

                                let crc_bytes: [u8; 4] = [
                                    raw[crc_start], raw[crc_start + 1],
                                    raw[crc_start + 2], raw[crc_start + 3],
                                ];
                                let stored_crc = u32::from_le_bytes(crc_bytes);
                                let computed_crc = crc32_ieee(test_data);
                                assert_eq!(stored_crc, computed_crc, "CRC must match");
                            }
                        }
                    }
                    Err(e) => assert!(false, "list: {}", e),
                }
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 60: worm_crc32_detects_corruption
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_crc32_detects_corruption() {
        let dir = temp_dir();
        let _ = fs::create_dir_all(&dir);

        let file_path = dir.join("audit_log_0000000000000001.worm");

        // Write valid entry
        write_raw_entry(&file_path, b"good_data");

        // Write corrupted entry (data + wrong CRC)
        let bad_data = b"corrupted__";
        let len_bytes = (bad_data.len() as u64).to_le_bytes();
        let wrong_crc = 0x12345678u32.to_le_bytes();
        append_raw_bytes(&file_path, &len_bytes);
        append_raw_bytes(&file_path, bad_data);
        append_raw_bytes(&file_path, &wrong_crc);

        let cfg = WormFileConfig::new(dir.clone());
        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                let report = storage.recover();
                match report {
                    Ok(r) => {
                        assert_eq!(r.valid_entries, 1, "only first entry valid");
                        assert_eq!(r.partial_entries, 1, "corrupted entry detected");
                    }
                    Err(e) => assert!(false, "recover: {}", e),
                }
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 61: worm_file_rotation_on_size
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_file_rotation_on_size() {
        let dir = temp_dir();
        let mut cfg = WormFileConfig::new(dir.clone());
        cfg.max_file_size_bytes = 40;
        cfg.sync_on_write = false;

        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                // entry = 8 + 10 + 4 = 22 bytes
                let _ = storage.append(b"0123456789");
                assert_eq!(count_worm_files(&dir), 1);

                // 22+22 = 44 >= 40 → rotation
                let _ = storage.append(b"0123456789");
                let _ = storage.append(b"0123456789");

                let file_count = count_worm_files(&dir);
                assert!(file_count >= 2, "rotation must create multiple files, got {}", file_count);
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 62: worm_rotation_preserves_data
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_rotation_preserves_data() {
        let dir = temp_dir();
        let mut cfg = WormFileConfig::new(dir.clone());
        cfg.max_file_size_bytes = 30;
        cfg.sync_on_write = false;

        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                for i in 1u64..=15 {
                    let data = format!("preserved_{:02}", i);
                    let _ = storage.append(data.as_bytes());
                }

                assert!(count_worm_files(&dir) > 1, "must have rotated");

                // ALL entries must be readable across file boundaries
                let all = storage.read_range(1, 16);
                match all {
                    Ok(entries) => {
                        assert_eq!(entries.len(), 15);
                        for (i, entry) in entries.iter().enumerate() {
                            let expected = format!("preserved_{:02}", i + 1);
                            assert_eq!(entry.as_slice(), expected.as_bytes(),
                                "entry {} must survive rotation", i + 1);
                        }
                    }
                    Err(e) => assert!(false, "read_range: {}", e),
                }
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 63: worm_recovery_partial_write
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_recovery_partial_write() {
        let dir = temp_dir();
        let mut cfg = WormFileConfig::new(dir.clone());
        cfg.sync_on_write = false;

        // Write 3 valid entries via storage
        let result = WormFileStorage::new(cfg.clone());
        match result {
            Ok(storage) => {
                let _ = storage.append(b"entry_1");
                let _ = storage.append(b"entry_2");
                let _ = storage.append(b"entry_3");
            }
            Err(e) => {
                assert!(false, "new: {}", e);
                return;
            }
        }

        // Simulate crash: append partial data
        let files: Vec<_> = fs::read_dir(&dir)
            .map(|rd| rd.filter_map(|e| e.ok())
                .filter(|e| e.path().extension().map_or(false, |ext| ext == "worm"))
                .map(|e| e.path())
                .collect())
            .unwrap_or_default();

        if let Some(last) = files.last() {
            // Partial header only
            append_raw_bytes(last, &42u64.to_le_bytes());
        }

        // Recover
        let storage2 = WormFileStorage::new(cfg);
        match storage2 {
            Ok(s2) => {
                let report = s2.recover();
                match report {
                    Ok(r) => {
                        assert_eq!(r.valid_entries, 3, "3 valid before crash");
                        assert_eq!(r.partial_entries, 1, "1 partial after crash");
                        assert_eq!(r.last_valid_sequence, 3);
                        assert_eq!(s2.current_sequence(), 3);
                    }
                    Err(e) => assert!(false, "recover: {}", e),
                }
            }
            Err(e) => assert!(false, "new2: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 64: worm_recovery_clean_log
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_recovery_clean_log() {
        let dir = temp_dir();
        let mut cfg = WormFileConfig::new(dir.clone());
        cfg.sync_on_write = false;

        let result = WormFileStorage::new(cfg.clone());
        match result {
            Ok(storage) => {
                for _ in 0..5 {
                    let _ = storage.append(b"clean_data");
                }
            }
            Err(e) => {
                assert!(false, "new: {}", e);
                return;
            }
        }

        // Recover on clean log — should find all entries, no partials
        let storage2 = WormFileStorage::new(cfg);
        match storage2 {
            Ok(s2) => {
                let report = s2.recover();
                match report {
                    Ok(r) => {
                        assert_eq!(r.valid_entries, 5);
                        assert_eq!(r.partial_entries, 0);
                        assert_eq!(r.last_valid_sequence, 5);
                    }
                    Err(e) => assert!(false, "recover: {}", e),
                }
            }
            Err(e) => assert!(false, "new2: {}", e),
        }
        cleanup(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 65: worm_verify_integrity_valid_chain
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_verify_integrity_valid_chain() {
        let dir = temp_dir();
        let mut cfg = WormFileConfig::new(dir.clone());
        cfg.max_file_size_bytes = 50;
        cfg.sync_on_write = false;

        let result = WormFileStorage::new(cfg);
        match result {
            Ok(storage) => {
                // Write 30 entries across multiple files
                for i in 1u64..=30 {
                    let data = format!("chain_{:04}", i);
                    let _ = storage.append(data.as_bytes());
                }

                assert!(count_worm_files(&dir) > 3, "many files for chain test");
                assert_eq!(storage.current_sequence(), 30);

                // Read entire chain and verify sequential integrity
                let all = storage.read_range(1, 31);
                match all {
                    Ok(entries) => {
                        assert_eq!(entries.len(), 30, "all 30 entries readable");

                        // Verify each entry has correct content
                        for (i, entry) in entries.iter().enumerate() {
                            let expected = format!("chain_{:04}", i + 1);
                            assert_eq!(entry.as_slice(), expected.as_bytes(),
                                "chain entry {} content correct", i + 1);
                        }

                        // Verify individual reads match range reads
                        for i in 1u64..=30 {
                            let single = storage.read_entry(i);
                            match single {
                                Ok(Some(data)) => {
                                    let idx = (i as usize) - 1;
                                    assert_eq!(data, entries[idx],
                                        "single read {} must match range read", i);
                                }
                                Ok(None) => assert!(false, "entry {} must exist", i),
                                Err(e) => assert!(false, "read {}: {}", i, e),
                            }
                        }
                    }
                    Err(e) => assert!(false, "read_range: {}", e),
                }

                // Recovery should confirm all valid
                let report = storage.recover();
                match report {
                    Ok(r) => {
                        assert_eq!(r.valid_entries, 30);
                        assert_eq!(r.partial_entries, 0);
                    }
                    Err(e) => assert!(false, "recover: {}", e),
                }
            }
            Err(e) => assert!(false, "new: {}", e),
        }
        cleanup(&dir);
    }
}