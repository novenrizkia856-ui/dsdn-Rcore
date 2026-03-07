//! # DA Mirror Publisher + Sync (Tahap 15.12)
//!
//! DA layer publish abstraction and sync logic for audit log entries.
//!
//! ## DaMirrorPublisher
//!
//! Trait abstracting DA layer publish. Implementations post batches of
//! encoded audit entries to Celestia / fallback DA.
//!
//! ## DaMirrorSync
//!
//! Buffers encoded entries and flushes to publisher in batches.
//! If no publisher is configured, entries are buffered and cleared on flush
//! without error (offline / test mode).
//!
//! ## Thread Safety
//!
//! `DaMirrorSync` is `Send + Sync` — safe to share via `Arc<DaMirrorSync>`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::audit_log_error::AuditLogError;

// ════════════════════════════════════════════════════════════════════════════════
// DA MIRROR PUBLISHER TRAIT
// ════════════════════════════════════════════════════════════════════════════════

/// Abstraction for publishing audit entries to the DA layer.
///
/// `Send + Sync + 'static` — safe to share via `Arc<dyn DaMirrorPublisher>`.
pub trait DaMirrorPublisher: Send + Sync + 'static {
    /// Publish a batch of encoded audit entries to DA.
    ///
    /// Each element is a bincode-encoded `AuditLogEntry`.
    /// Returns the DA sequence number assigned to this batch.
    ///
    /// # Errors
    ///
    /// Returns `AuditLogError::DaPublishFailed` on failure.
    fn publish_batch(&self, entries: &[Vec<u8>]) -> Result<u64, AuditLogError>;
}

// ════════════════════════════════════════════════════════════════════════════════
// DA MIRROR SYNC
// ════════════════════════════════════════════════════════════════════════════════

/// Buffers encoded audit entries and flushes them to DA in batches.
///
/// If `publisher` is `None`, entries are buffered and cleared on flush
/// without error (offline / test mode).
pub struct DaMirrorSync {
    /// Optional DA publisher. `None` = no DA publishing.
    publisher: Option<Arc<dyn DaMirrorPublisher>>,
    /// Last DA sequence number returned by publisher.
    last_da_sequence: AtomicU64,
    /// Buffered entries awaiting flush.
    pending_buffer: Mutex<Vec<Vec<u8>>>,
}

impl DaMirrorSync {
    /// Create a new `DaMirrorSync`.
    ///
    /// Pass `None` for `publisher` for buffer-only mode (no DA publish).
    pub fn new(publisher: Option<Arc<dyn DaMirrorPublisher>>) -> Self {
        Self {
            publisher,
            last_da_sequence: AtomicU64::new(0),
            pending_buffer: Mutex::new(Vec::new()),
        }
    }

    /// Buffer an encoded entry for later flush.
    ///
    /// # Errors
    ///
    /// Returns `AuditLogError::LockPoisoned` if the mutex is poisoned.
    pub fn buffer_entry(&self, encoded: Vec<u8>) -> Result<(), AuditLogError> {
        match self.pending_buffer.lock() {
            Ok(mut buf) => {
                buf.push(encoded);
                Ok(())
            }
            Err(e) => Err(AuditLogError::LockPoisoned {
                reason: format!("da_mirror buffer lock: {}", e),
            }),
        }
    }

    /// Flush all buffered entries to DA.
    ///
    /// - If publisher is `Some` → call `publish_batch`, update sequence, clear buffer.
    /// - If publisher is `None` → clear buffer, return count.
    /// - If publish fails → buffer is **NOT** cleared (no data loss).
    ///
    /// Returns the number of entries flushed.
    pub fn flush_to_da(&self) -> Result<usize, AuditLogError> {
        let entries: Vec<Vec<u8>> = match self.pending_buffer.lock() {
            Ok(buf) => buf.clone(),
            Err(e) => {
                return Err(AuditLogError::LockPoisoned {
                    reason: format!("da_mirror flush lock: {}", e),
                });
            }
        };

        if entries.is_empty() {
            return Ok(0);
        }

        let count = entries.len();

        if let Some(ref publisher) = self.publisher {
            let da_seq = publisher.publish_batch(&entries)?;
            self.last_da_sequence.store(da_seq, Ordering::SeqCst);
        }

        // Clear buffer after successful publish (or no-publisher mode)
        match self.pending_buffer.lock() {
            Ok(mut buf) => buf.clear(),
            Err(e) => {
                return Err(AuditLogError::LockPoisoned {
                    reason: format!("da_mirror clear lock: {}", e),
                });
            }
        }

        Ok(count)
    }

    /// Last DA sequence number from publisher. Returns 0 if no flush occurred.
    pub fn last_synced_sequence(&self) -> u64 {
        self.last_da_sequence.load(Ordering::SeqCst)
    }

    /// Number of entries currently buffered.
    pub fn pending_count(&self) -> usize {
        match self.pending_buffer.lock() {
            Ok(buf) => buf.len(),
            Err(_) => 0,
        }
    }
}

impl std::fmt::Debug for DaMirrorSync {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaMirrorSync")
            .field("has_publisher", &self.publisher.is_some())
            .field("last_da_sequence", &self.last_da_sequence.load(Ordering::SeqCst))
            .field("pending_count", &self.pending_count())
            .finish()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    struct TestPublisher {
        call_count: AtomicUsize,
        next_seq: AtomicU64,
        force_error: AtomicBool,
    }

    impl TestPublisher {
        fn new() -> Self {
            Self {
                call_count: AtomicUsize::new(0),
                next_seq: AtomicU64::new(1),
                force_error: AtomicBool::new(false),
            }
        }
    }

    impl DaMirrorPublisher for TestPublisher {
        fn publish_batch(&self, _entries: &[Vec<u8>]) -> Result<u64, AuditLogError> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            if self.force_error.load(Ordering::SeqCst) {
                return Err(AuditLogError::DaPublishFailed {
                    reason: "test forced".to_string(),
                });
            }
            Ok(self.next_seq.fetch_add(1, Ordering::SeqCst))
        }
    }

    #[test]
    fn da_mirror_buffer_and_flush() {
        let pub_arc = Arc::new(TestPublisher::new());
        let sync = DaMirrorSync::new(Some(pub_arc.clone()));

        assert_eq!(sync.pending_count(), 0);
        let _ = sync.buffer_entry(vec![1, 2, 3]);
        let _ = sync.buffer_entry(vec![4, 5]);
        assert_eq!(sync.pending_count(), 2);

        let flushed = sync.flush_to_da();
        match flushed {
            Ok(c) => assert_eq!(c, 2),
            Err(e) => assert!(false, "flush failed: {}", e),
        }
        assert_eq!(sync.pending_count(), 0);
        assert!(sync.last_synced_sequence() >= 1);
    }

    #[test]
    fn da_mirror_flush_empty() {
        let sync = DaMirrorSync::new(None);
        let flushed = sync.flush_to_da();
        match flushed {
            Ok(c) => assert_eq!(c, 0),
            Err(e) => assert!(false, "empty flush: {}", e),
        }
    }

    #[test]
    fn da_mirror_no_publisher() {
        let sync = DaMirrorSync::new(None);
        let _ = sync.buffer_entry(vec![1]);
        let _ = sync.buffer_entry(vec![2]);
        assert_eq!(sync.pending_count(), 2);

        let flushed = sync.flush_to_da();
        match flushed {
            Ok(c) => assert_eq!(c, 2),
            Err(e) => assert!(false, "flush: {}", e),
        }
        assert_eq!(sync.pending_count(), 0);
        assert_eq!(sync.last_synced_sequence(), 0);
    }

    #[test]
    fn da_mirror_publish_failure_retains_buffer() {
        let pub_arc = Arc::new(TestPublisher::new());
        pub_arc.force_error.store(true, Ordering::SeqCst);
        let sync = DaMirrorSync::new(Some(pub_arc));

        let _ = sync.buffer_entry(vec![1, 2]);
        assert_eq!(sync.pending_count(), 1);

        let result = sync.flush_to_da();
        assert!(result.is_err());
        assert_eq!(sync.pending_count(), 1);
    }

    #[test]
    fn da_mirror_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<DaMirrorSync>();
        assert_send_sync::<Arc<dyn DaMirrorPublisher>>();
    }

    #[test]
    fn da_mirror_trait_object_safe() {
        let _: Box<dyn DaMirrorPublisher> = Box::new(TestPublisher::new());
    }
}