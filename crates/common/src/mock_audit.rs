//! # Mock Audit Implementations (Tahap 15.15)
//!
//! Mock implementations for testing across crates:
//! - `MockWormStorage` — in-memory `WormLogStorage`
//! - `MockDaMirrorPublisher` — in-memory `DaMirrorPublisher`
//! - `MockAuditLogWriter` — in-memory `AuditLogWriter` + `AuditLogHook`

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

use crate::audit_event::AuditLogEvent;

use crate::audit_log_error::AuditLogError;
use crate::audit_hook::AuditLogHook;
use crate::audit_writer::AuditLogWriter;
use crate::da_mirror::DaMirrorPublisher;
use crate::worm_log::WormLogStorage;

// ════════════════════════════════════════════════════════════════════════════════
// MOCK WORM STORAGE
// ════════════════════════════════════════════════════════════════════════════════

/// In-memory WORM storage for testing.
///
/// Entries stored in `Vec<Vec<u8>>`. Sequence numbers are 1-based.
/// Set `force_error` to simulate write failures.
#[derive(Debug)]
pub struct MockWormStorage {
    /// Stored entries (index 0 = sequence 1).
    entries: Mutex<Vec<Vec<u8>>>,
    /// Next sequence to assign.
    next_seq: AtomicU64,
    /// When true, `append` returns `WriteFailed`.
    pub force_error: AtomicBool,
}

impl MockWormStorage {
    /// Create a new empty mock storage.
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            next_seq: AtomicU64::new(1),
            force_error: AtomicBool::new(false),
        }
    }
}

impl Default for MockWormStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl WormLogStorage for MockWormStorage {
    fn append(&self, entry_bytes: &[u8]) -> Result<u64, AuditLogError> {
        if self.force_error.load(Ordering::SeqCst) {
            return Err(AuditLogError::WriteFailed {
                reason: "mock forced error".to_string(),
            });
        }
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
        if next <= 1 { Ok(0) } else { Ok(next - 1) }
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

// ════════════════════════════════════════════════════════════════════════════════
// MOCK DA MIRROR PUBLISHER
// ════════════════════════════════════════════════════════════════════════════════

/// In-memory DA publisher for testing.
///
/// Records all published batches. Set `force_error` to simulate failures.
#[derive(Debug)]
pub struct MockDaMirrorPublisher {
    /// All published batches.
    pub published: Mutex<Vec<Vec<Vec<u8>>>>,
    /// Number of `publish_batch` calls.
    pub call_count: AtomicUsize,
    /// Next DA sequence to return.
    next_seq: AtomicU64,
    /// When true, `publish_batch` returns `DaPublishFailed`.
    pub force_error: AtomicBool,
}

impl MockDaMirrorPublisher {
    /// Create a new mock publisher.
    pub fn new() -> Self {
        Self {
            published: Mutex::new(Vec::new()),
            call_count: AtomicUsize::new(0),
            next_seq: AtomicU64::new(1),
            force_error: AtomicBool::new(false),
        }
    }
}

impl Default for MockDaMirrorPublisher {
    fn default() -> Self {
        Self::new()
    }
}

impl DaMirrorPublisher for MockDaMirrorPublisher {
    fn publish_batch(&self, entries: &[Vec<u8>]) -> Result<u64, AuditLogError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        if self.force_error.load(Ordering::SeqCst) {
            return Err(AuditLogError::DaPublishFailed {
                reason: "mock forced error".to_string(),
            });
        }
        let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
        match self.published.lock() {
            Ok(mut v) => {
                v.push(entries.to_vec());
            }
            Err(_) => {}
        }
        Ok(seq)
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// MOCK AUDIT LOG WRITER
// ════════════════════════════════════════════════════════════════════════════════

/// Lightweight mock writer for testing producers.
///
/// Records events in-memory. No real WORM or DA operations.
#[derive(Debug)]
pub struct MockAuditLogWriter {
    /// All events received via `write_event` / `on_event`.
    events: Mutex<Vec<AuditLogEvent>>,
    /// Sequence counter.
    sequences: AtomicU64,
}

impl MockAuditLogWriter {
    /// Create a new mock writer.
    pub fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            sequences: AtomicU64::new(0),
        }
    }

    /// Return number of events recorded.
    pub fn event_count(&self) -> usize {
        match self.events.lock() {
            Ok(v) => v.len(),
            Err(_) => 0,
        }
    }

    /// Return a clone of all recorded events.
    pub fn recorded_events(&self) -> Vec<AuditLogEvent> {
        match self.events.lock() {
            Ok(v) => v.clone(),
            Err(_) => Vec::new(),
        }
    }
}

impl Default for MockAuditLogWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditLogWriter for MockAuditLogWriter {
    fn write_event(&self, event: AuditLogEvent) -> Result<u64, AuditLogError> {
        let seq = self.sequences.fetch_add(1, Ordering::SeqCst).saturating_add(1);
        match self.events.lock() {
            Ok(mut v) => {
                v.push(event);
                Ok(seq)
            }
            Err(e) => Err(AuditLogError::LockPoisoned {
                reason: format!("{}", e),
            }),
        }
    }

    fn flush_da(&self) -> Result<usize, AuditLogError> {
        Ok(0)
    }

    fn last_sequence(&self) -> u64 {
        self.sequences.load(Ordering::SeqCst)
    }

    fn verify_chain(&self, _start: u64, _end: u64) -> Result<bool, AuditLogError> {
        Ok(true)
    }
}

impl AuditLogHook for MockAuditLogWriter {
    fn on_event(&self, event: AuditLogEvent) -> Result<(), AuditLogError> {
        self.write_event(event)?;
        Ok(())
    }

    fn flush(&self) -> Result<usize, AuditLogError> {
        self.flush_da()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn sample_event() -> AuditLogEvent {
        AuditLogEvent::DaSyncSequenceUpdate {
            version: 1,
            timestamp_ms: 1700000000,
            da_source: "test".to_string(),
            sequence_number: 1,
            previous_sequence: 0,
            blob_count: 1,
        }
    }

    #[test]
    fn mock_worm_append_read() {
        let worm = MockWormStorage::new();
        let seq = worm.append(b"hello");
        match seq {
            Ok(s) => {
                assert_eq!(s, 1);
                let entry = worm.read_entry(1);
                match entry {
                    Ok(Some(data)) => assert_eq!(data, b"hello"),
                    _ => assert!(false, "read failed"),
                }
            }
            Err(e) => assert!(false, "append: {}", e),
        }
    }

    #[test]
    fn mock_worm_force_error() {
        let worm = MockWormStorage::new();
        worm.force_error.store(true, Ordering::SeqCst);
        let result = worm.append(b"fail");
        assert!(result.is_err());
    }

    #[test]
    fn mock_worm_entry_count() {
        let worm = MockWormStorage::new();
        let _ = worm.append(b"a");
        let _ = worm.append(b"b");
        let _ = worm.append(b"c");
        let count = worm.entry_count();
        match count {
            Ok(c) => assert_eq!(c, 3),
            Err(e) => assert!(false, "count: {}", e),
        }
    }

    #[test]
    fn mock_da_publisher_records() {
        let pub_mock = MockDaMirrorPublisher::new();
        let result = pub_mock.publish_batch(&[vec![1], vec![2]]);
        match result {
            Ok(seq) => assert!(seq >= 1),
            Err(e) => assert!(false, "publish: {}", e),
        }
        assert_eq!(pub_mock.call_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn mock_da_publisher_force_error() {
        let pub_mock = MockDaMirrorPublisher::new();
        pub_mock.force_error.store(true, Ordering::SeqCst);
        let result = pub_mock.publish_batch(&[vec![1]]);
        assert!(result.is_err());
    }

    #[test]
    fn mock_writer_records_events() {
        let writer = MockAuditLogWriter::new();
        let _ = writer.write_event(sample_event());
        let _ = writer.write_event(sample_event());
        assert_eq!(writer.event_count(), 2);
        assert_eq!(writer.last_sequence(), 2);
    }

    #[test]
    fn mock_writer_as_hook() {
        let writer = MockAuditLogWriter::new();
        let hook: &dyn AuditLogHook = &writer;
        let r = hook.on_event(sample_event());
        assert!(r.is_ok());
        assert_eq!(writer.event_count(), 1);
    }

    #[test]
    fn mock_writer_as_writer_trait_object() {
        let writer: Arc<dyn AuditLogWriter> = Arc::new(MockAuditLogWriter::new());
        let r = writer.write_event(sample_event());
        assert!(r.is_ok());
    }

    #[test]
    fn mock_worm_read_range() {
        let worm = MockWormStorage::new();
        let _ = worm.append(b"a");
        let _ = worm.append(b"b");
        let _ = worm.append(b"c");
        let range = worm.read_range(1, 4);
        match range {
            Ok(entries) => assert_eq!(entries.len(), 3),
            Err(e) => assert!(false, "range: {}", e),
        }
    }

    #[test]
    fn all_mocks_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<MockWormStorage>();
        assert_send_sync::<MockDaMirrorPublisher>();
        assert_send_sync::<MockAuditLogWriter>();
    }
}