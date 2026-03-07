//! # WORM Log Storage Trait (Tahap 15.10)
//!
//! Append-only storage abstraction for the DSDN audit log.
//!
//! ## WORM Invariant
//!
//! **Write Once, Read Many.** Implementations MUST enforce:
//!
//! - Entries are **append-only** — new entries are added at the end.
//! - Existing entries **cannot be deleted**.
//! - Existing entries **cannot be modified**.
//! - Existing entries **cannot be overwritten**.
//!
//! Any implementation that violates this invariant compromises the integrity
//! of the audit trail.
//!
//! ## Sequence Numbers
//!
//! - Monotonically increasing, starting at 1.
//! - `last_sequence()` returns 0 when storage is empty.
//! - `append()` returns the assigned sequence number.
//! - No gaps allowed in production (gaps may indicate data loss).
//!
//! ## Thread Safety
//!
//! `WormLogStorage: Debug + Send + Sync + 'static` — safe to share
//! across threads via `Arc<dyn WormLogStorage>`.
//!
//! ## Implementations
//!
//! - `WormFileStorage` (crate `storage`, Tahap 15.18–15.24): disk-backed WORM files.
//! - Mock implementations for testing (in-memory `Vec`).

use std::fmt::Debug;

use crate::audit_log_error::AuditLogError;

// ════════════════════════════════════════════════════════════════════════════════
// WORM LOG STORAGE TRAIT
// ════════════════════════════════════════════════════════════════════════════════

/// Append-only storage backend for audit log entries.
///
/// # WORM Invariant
///
/// Once written, entries **must not** be deleted, modified, or overwritten.
/// This is the foundational guarantee for tamper-evident audit logging.
///
/// # Sequence Contract
///
/// - First `append()` returns sequence ≥ 1.
/// - Each subsequent `append()` returns `previous + 1`.
/// - `last_sequence()` returns 0 when empty, latest sequence otherwise.
/// - `entry_count()` is consistent with `last_sequence()`.
///
/// # Error Handling
///
/// All methods return `Result<_, AuditLogError>`. No method may panic,
/// call `unwrap()`, or silently drop errors.
///
/// # Thread Safety
///
/// `Debug + Send + Sync + 'static` — implementations must be safe for
/// concurrent access (e.g., via `Mutex` or `RwLock` internally).
pub trait WormLogStorage: Debug + Send + Sync + 'static {
    /// Append a serialized audit entry to storage.
    ///
    /// # Arguments
    ///
    /// * `entry_bytes` — Bincode-encoded `AuditLogEntry` bytes.
    ///
    /// # Returns
    ///
    /// The monotonically increasing sequence number assigned to this entry.
    /// First entry gets sequence ≥ 1.
    ///
    /// # Errors
    ///
    /// Returns `AuditLogError::WriteFailed` or `AuditLogError::StorageFull`
    /// if the write cannot be completed.
    fn append(&self, entry_bytes: &[u8]) -> Result<u64, AuditLogError>;

    /// Read a single entry by its sequence number.
    ///
    /// # Arguments
    ///
    /// * `sequence` — The sequence number to look up.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(bytes))` — Entry found.
    /// - `Ok(None)` — Sequence not found (no error, just absent).
    ///
    /// # Errors
    ///
    /// Returns `AuditLogError` on I/O or internal failure.
    fn read_entry(&self, sequence: u64) -> Result<Option<Vec<u8>>, AuditLogError>;

    /// Read a range of entries `[start, end)`.
    ///
    /// # Arguments
    ///
    /// * `start` — First sequence number (inclusive).
    /// * `end` — Last sequence number (exclusive).
    ///
    /// # Returns
    ///
    /// `Vec<Vec<u8>>` of entry bytes in order. Empty if range is empty.
    ///
    /// # Errors
    ///
    /// Returns `AuditLogError` if `start > end` or on I/O failure.
    fn read_range(&self, start: u64, end: u64) -> Result<Vec<Vec<u8>>, AuditLogError>;

    /// Return the last (highest) sequence number in storage.
    ///
    /// Returns `Ok(0)` if storage is empty.
    fn last_sequence(&self) -> Result<u64, AuditLogError>;

    /// Return the total number of entries in storage.
    ///
    /// Must be consistent with sequence numbers.
    fn entry_count(&self) -> Result<u64, AuditLogError>;
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::sync::atomic::{AtomicU64, Ordering};

    // ────────────────────────────────────────────────────────────────────────
    // Mock implementation
    // ────────────────────────────────────────────────────────────────────────

    #[derive(Debug)]
    struct MockWormStorage {
        entries: Mutex<Vec<Vec<u8>>>,
        next_seq: AtomicU64,
    }

    impl MockWormStorage {
        fn new() -> Self {
            Self {
                entries: Mutex::new(Vec::new()),
                next_seq: AtomicU64::new(1),
            }
        }
    }

    impl WormLogStorage for MockWormStorage {
        fn append(&self, entry_bytes: &[u8]) -> Result<u64, AuditLogError> {
            let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
            match self.entries.lock() {
                Ok(mut v) => {
                    v.push(entry_bytes.to_vec());
                    Ok(seq)
                }
                Err(e) => Err(AuditLogError::LockPoisoned {
                    reason: format!("{}", e),
                }),
            }
        }

        fn read_entry(&self, sequence: u64) -> Result<Option<Vec<u8>>, AuditLogError> {
            if sequence == 0 {
                return Ok(None);
            }
            match self.entries.lock() {
                Ok(v) => {
                    let idx = (sequence as usize).saturating_sub(1);
                    Ok(v.get(idx).cloned())
                }
                Err(e) => Err(AuditLogError::LockPoisoned {
                    reason: format!("{}", e),
                }),
            }
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
            match self.entries.lock() {
                Ok(v) => {
                    let s = (start as usize).saturating_sub(1);
                    let e = (end as usize).saturating_sub(1);
                    let actual_end = e.min(v.len());
                    if s >= v.len() {
                        return Ok(Vec::new());
                    }
                    Ok(v[s..actual_end].to_vec())
                }
                Err(e) => Err(AuditLogError::LockPoisoned {
                    reason: format!("{}", e),
                }),
            }
        }

        fn last_sequence(&self) -> Result<u64, AuditLogError> {
            let next = self.next_seq.load(Ordering::SeqCst);
            if next <= 1 {
                Ok(0)
            } else {
                Ok(next - 1)
            }
        }

        fn entry_count(&self) -> Result<u64, AuditLogError> {
            match self.entries.lock() {
                Ok(v) => Ok(v.len() as u64),
                Err(e) => Err(AuditLogError::LockPoisoned {
                    reason: format!("{}", e),
                }),
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 1: worm_log_trait_object_safe
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_log_trait_object_safe() {
        // If this compiles, the trait is object-safe
        let storage: Arc<dyn WormLogStorage> = Arc::new(MockWormStorage::new());
        let result = storage.append(b"test");
        assert!(result.is_ok());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 2: worm_log_send_sync
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_log_send_sync() {
        fn assert_bounds<T: Debug + Send + Sync + 'static>() {}
        assert_bounds::<MockWormStorage>();

        // Arc<dyn WormLogStorage> is Send + Sync
        fn assert_arc_bounds<T: Send + Sync>() {}
        assert_arc_bounds::<Arc<dyn WormLogStorage>>();
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 3: worm_log_append_signature
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_log_append_signature() {
        let storage = MockWormStorage::new();

        // append returns Result<u64, AuditLogError>
        let seq1: Result<u64, AuditLogError> = storage.append(b"entry1");
        match seq1 {
            Ok(s) => assert!(s >= 1, "first sequence must be >= 1"),
            Err(e) => assert!(false, "append failed: {}", e),
        }

        let seq2: Result<u64, AuditLogError> = storage.append(b"entry2");
        match (seq1, seq2) {
            (Ok(s1), Ok(s2)) => {
                assert_eq!(s2, s1 + 1, "sequence must be monotonically increasing");
            }
            _ => assert!(false, "append should not fail"),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 4: worm_log_read_entry_signature
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_log_read_entry_signature() {
        let storage = MockWormStorage::new();

        // Read non-existent → None
        let result: Result<Option<Vec<u8>>, AuditLogError> = storage.read_entry(999);
        match result {
            Ok(opt) => assert!(opt.is_none(), "non-existent entry must return None"),
            Err(e) => assert!(false, "read_entry failed: {}", e),
        }

        // Write then read
        let _ = storage.append(b"hello");
        let result2 = storage.read_entry(1);
        match result2 {
            Ok(Some(data)) => assert_eq!(data, b"hello"),
            Ok(None) => assert!(false, "entry 1 must exist"),
            Err(e) => assert!(false, "read_entry failed: {}", e),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 5: worm_log_read_range_signature
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_log_read_range_signature() {
        let storage = MockWormStorage::new();

        let _ = storage.append(b"a");
        let _ = storage.append(b"b");
        let _ = storage.append(b"c");

        // Range [1, 4) → 3 entries
        let result: Result<Vec<Vec<u8>>, AuditLogError> = storage.read_range(1, 4);
        match result {
            Ok(entries) => {
                assert_eq!(entries.len(), 3);
                assert_eq!(entries[0], b"a");
                assert_eq!(entries[1], b"b");
                assert_eq!(entries[2], b"c");
            }
            Err(e) => assert!(false, "read_range failed: {}", e),
        }

        // Empty range [2, 2) → empty
        let result2 = storage.read_range(2, 2);
        match result2 {
            Ok(entries) => assert!(entries.is_empty(), "equal start/end must be empty"),
            Err(e) => assert!(false, "read_range failed: {}", e),
        }

        // Invalid range start > end → error
        let result3 = storage.read_range(5, 2);
        assert!(result3.is_err(), "start > end must return error");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 6: worm_log_last_sequence_signature
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_log_last_sequence_signature() {
        let storage = MockWormStorage::new();

        // Empty → 0
        let result: Result<u64, AuditLogError> = storage.last_sequence();
        match result {
            Ok(s) => assert_eq!(s, 0, "empty storage must return 0"),
            Err(e) => assert!(false, "last_sequence failed: {}", e),
        }

        // After appends
        let _ = storage.append(b"x");
        let _ = storage.append(b"y");
        let result2 = storage.last_sequence();
        match result2 {
            Ok(s) => assert_eq!(s, 2, "last_sequence must be 2 after 2 appends"),
            Err(e) => assert!(false, "last_sequence failed: {}", e),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 7: worm_log_entry_count_signature
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_log_entry_count_signature() {
        let storage = MockWormStorage::new();

        // Empty → 0
        let result: Result<u64, AuditLogError> = storage.entry_count();
        match result {
            Ok(c) => assert_eq!(c, 0, "empty storage must have 0 entries"),
            Err(e) => assert!(false, "entry_count failed: {}", e),
        }

        // After appends
        let _ = storage.append(b"1");
        let _ = storage.append(b"2");
        let _ = storage.append(b"3");
        let result2 = storage.entry_count();
        match result2 {
            Ok(c) => assert_eq!(c, 3, "entry_count must be 3 after 3 appends"),
            Err(e) => assert!(false, "entry_count failed: {}", e),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 8: worm_log_sequence_starts_at_one
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_log_sequence_starts_at_one() {
        let storage = MockWormStorage::new();

        let seq = storage.append(b"first");
        match seq {
            Ok(s) => assert_eq!(s, 1, "first sequence must be 1"),
            Err(e) => assert!(false, "append failed: {}", e),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 9: worm_log_multi_thread
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_log_multi_thread() {
        let storage: Arc<dyn WormLogStorage> = Arc::new(MockWormStorage::new());

        let mut handles = Vec::new();
        for _ in 0..5 {
            let s = Arc::clone(&storage);
            handles.push(std::thread::spawn(move || {
                for j in 0..10 {
                    let _ = s.append(format!("entry-{}", j).as_bytes());
                }
            }));
        }

        for h in handles {
            match h.join() {
                Ok(()) => {}
                Err(_) => assert!(false, "thread panicked"),
            }
        }

        let count = storage.entry_count();
        match count {
            Ok(c) => assert_eq!(c, 50, "50 entries from 5 threads x 10"),
            Err(e) => assert!(false, "entry_count failed: {}", e),
        }
    }
}