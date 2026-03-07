//! # Audit Log Hook (Tahap 15.11)
//!
//! Interface trait for audit event producers across DSDN.
//!
//! ## Purpose
//!
//! `AuditLogHook` is the **single entry point** through which all producer
//! modules (slashing, governance, DA sync, committee rotation, etc.) submit
//! audit events to the logging subsystem.
//!
//! ## Usage Pattern
//!
//! ```text
//! Producer Module                 Audit Subsystem
//! ┌─────────────┐                ┌────────────────┐
//! │ slashing    │──on_event()──▶│ AuditLogHook   │
//! │ governance  │──on_event()──▶│  impl          │
//! │ DA sync     │──on_event()──▶│                │
//! └─────────────┘                │  flush()───────▶ DA Mirror
//!                                └────────────────┘
//! ```
//!
//! ## Thread Safety
//!
//! `AuditLogHook: Send + Sync + 'static` — safe to share across threads
//! via `Arc<dyn AuditLogHook>`.
//!
//! ## Synchronous Design
//!
//! Both methods are synchronous. Implementations that need async behavior
//! should buffer internally and flush asynchronously via a background task.

use crate::audit_log_error::AuditLogError;

// ════════════════════════════════════════════════════════════════════════════════
// AUDIT LOG HOOK TRAIT
// ════════════════════════════════════════════════════════════════════════════════

/// Interface for submitting audit events to the logging subsystem.
///
/// Implementations receive events from producer modules and persist them
/// to WORM storage + DA mirror.
///
/// # Contract
///
/// - `on_event`: Accept and persist a single event. Must not lose the event
///   silently — return `Err` if persistence fails.
/// - `flush`: Publish all buffered events to DA mirror. Return the count
///   of events successfully flushed. Return 0 if buffer is empty.
///
/// # Thread Safety
///
/// Implementations must be `Send + Sync + 'static` to support multi-threaded
/// producers sharing the hook via `Arc<dyn AuditLogHook>`.
///
/// # No Default Implementations
///
/// This trait defines interface only — no default method bodies.
pub trait AuditLogHook: Send + Sync + 'static {
    /// Accept an audit event from a producer module.
    ///
    /// The implementation should persist the event (e.g., append to WORM log,
    /// enqueue to buffer) before returning `Ok(())`.
    ///
    /// # Errors
    ///
    /// Returns `AuditLogError` if the event cannot be persisted.
    fn on_event(
        &self,
        event: dsdn_proto::audit_event::AuditLogEvent,
    ) -> Result<(), AuditLogError>;

    /// Flush all buffered events to the DA mirror / storage backend.
    ///
    /// Returns the number of events successfully flushed.
    /// Returns `Ok(0)` if no events are pending.
    ///
    /// # Errors
    ///
    /// Returns `AuditLogError` if flush fails (e.g., DA publish error).
    fn flush(&self) -> Result<usize, AuditLogError>;
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::sync::atomic::{AtomicUsize, Ordering};

    // ────────────────────────────────────────────────────────────────────────
    // Mock implementation for testing
    // ────────────────────────────────────────────────────────────────────────

    struct MockAuditHook {
        events: Mutex<Vec<dsdn_proto::audit_event::AuditLogEvent>>,
        flush_count: AtomicUsize,
        force_error: bool,
    }

    impl MockAuditHook {
        fn new() -> Self {
            Self {
                events: Mutex::new(Vec::new()),
                flush_count: AtomicUsize::new(0),
                force_error: false,
            }
        }

        fn with_error() -> Self {
            Self {
                events: Mutex::new(Vec::new()),
                flush_count: AtomicUsize::new(0),
                force_error: true,
            }
        }

        fn event_count(&self) -> usize {
            match self.events.lock() {
                Ok(v) => v.len(),
                Err(_) => 0,
            }
        }
    }

    impl AuditLogHook for MockAuditHook {
        fn on_event(
            &self,
            event: dsdn_proto::audit_event::AuditLogEvent,
        ) -> Result<(), AuditLogError> {
            if self.force_error {
                return Err(AuditLogError::WriteFailed {
                    reason: "mock forced error".to_string(),
                });
            }
            match self.events.lock() {
                Ok(mut v) => {
                    v.push(event);
                    Ok(())
                }
                Err(e) => Err(AuditLogError::LockPoisoned {
                    reason: format!("{}", e),
                }),
            }
        }

        fn flush(&self) -> Result<usize, AuditLogError> {
            if self.force_error {
                return Err(AuditLogError::DaPublishFailed {
                    reason: "mock forced error".to_string(),
                });
            }
            let count = match self.events.lock() {
                Ok(mut v) => {
                    let c = v.len();
                    v.clear();
                    c
                }
                Err(e) => {
                    return Err(AuditLogError::LockPoisoned {
                        reason: format!("{}", e),
                    });
                }
            };
            self.flush_count.fetch_add(1, Ordering::SeqCst);
            Ok(count)
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // Helper
    // ────────────────────────────────────────────────────────────────────────

    fn sample_event() -> dsdn_proto::audit_event::AuditLogEvent {
        dsdn_proto::audit_event::AuditLogEvent::DaSyncSequenceUpdate {
            version: 1,
            timestamp_ms: 1700000000,
            da_source: "celestia".to_string(),
            sequence_number: 100,
            previous_sequence: 99,
            blob_count: 5,
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 1: audit_hook_trait_object_safe
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_hook_trait_object_safe() {
        // If this compiles, the trait is object-safe
        let hook: Arc<dyn AuditLogHook> = Arc::new(MockAuditHook::new());
        let result = hook.on_event(sample_event());
        assert!(result.is_ok());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 2: audit_hook_send_sync
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_hook_send_sync() {
        fn assert_send_sync<T: Send + Sync + 'static>() {}
        // Trait itself requires Send + Sync + 'static
        assert_send_sync::<MockAuditHook>();

        // Arc<dyn AuditLogHook> is Send + Sync
        fn assert_arc_send_sync<T: Send + Sync>() {}
        assert_arc_send_sync::<Arc<dyn AuditLogHook>>();
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 3: audit_hook_on_event_signature
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_hook_on_event_signature() {
        let hook = MockAuditHook::new();

        // on_event takes AuditLogEvent, returns Result<(), AuditLogError>
        let result: Result<(), AuditLogError> = hook.on_event(sample_event());
        assert!(result.is_ok());
        assert_eq!(hook.event_count(), 1);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 4: audit_hook_flush_signature
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_hook_flush_signature() {
        let hook = MockAuditHook::new();

        // Flush empty → 0
        let result: Result<usize, AuditLogError> = hook.flush();
        match result {
            Ok(count) => assert_eq!(count, 0, "empty flush must return 0"),
            Err(e) => assert!(false, "flush failed: {}", e),
        }

        // Add events then flush
        let _ = hook.on_event(sample_event());
        let _ = hook.on_event(sample_event());

        let result2: Result<usize, AuditLogError> = hook.flush();
        match result2 {
            Ok(count) => assert_eq!(count, 2, "flush must return 2 events"),
            Err(e) => assert!(false, "flush failed: {}", e),
        }

        // After flush, buffer empty
        assert_eq!(hook.event_count(), 0);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 5: audit_hook_mock_implementation
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_hook_mock_implementation() {
        let hook = MockAuditHook::new();

        // Add 3 events
        for _ in 0..3 {
            let result = hook.on_event(sample_event());
            assert!(result.is_ok());
        }
        assert_eq!(hook.event_count(), 3);

        // Flush all
        let flushed = hook.flush();
        match flushed {
            Ok(count) => assert_eq!(count, 3),
            Err(e) => assert!(false, "flush failed: {}", e),
        }
        assert_eq!(hook.event_count(), 0);

        // Error variant
        let hook_err = MockAuditHook::with_error();
        let result = hook_err.on_event(sample_event());
        assert!(result.is_err());

        let flush_result = hook_err.flush();
        assert!(flush_result.is_err());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 6: audit_hook_result_types
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_hook_result_types() {
        // Verify error types are correct AuditLogError variants
        let hook_err = MockAuditHook::with_error();

        let on_event_err = hook_err.on_event(sample_event());
        match on_event_err {
            Err(AuditLogError::WriteFailed { reason }) => {
                assert!(reason.contains("mock forced error"));
            }
            _ => assert!(false, "expected WriteFailed error"),
        }

        let flush_err = hook_err.flush();
        match flush_err {
            Err(AuditLogError::DaPublishFailed { reason }) => {
                assert!(reason.contains("mock forced error"));
            }
            _ => assert!(false, "expected DaPublishFailed error"),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 7: audit_hook_multi_thread
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_hook_multi_thread() {
        let hook: Arc<dyn AuditLogHook> = Arc::new(MockAuditHook::new());

        let mut handles = Vec::new();
        for _ in 0..5 {
            let h = Arc::clone(&hook);
            handles.push(std::thread::spawn(move || {
                for _ in 0..10 {
                    let _ = h.on_event(sample_event());
                }
            }));
        }

        for handle in handles {
            match handle.join() {
                Ok(()) => {}
                Err(_) => assert!(false, "thread panicked"),
            }
        }

        // All 50 events should be buffered
        let flushed = hook.flush();
        match flushed {
            Ok(count) => assert_eq!(count, 50, "50 events from 5 threads x 10"),
            Err(e) => assert!(false, "flush failed: {}", e),
        }
    }
}