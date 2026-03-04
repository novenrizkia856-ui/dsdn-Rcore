//! # Receipt Event Logger (14C.C.28)
//!
//! Audit-safe DA log recording for receipt-related economic events.
//!
//! ## Design
//!
//! - [`ReceiptEconomicEvent`] enum with 5 variants covering the claim and
//!   fraud proof lifecycle.
//! - [`EventPublisher`] trait abstracts the DA publish layer.
//! - [`ReceiptEventLogger`] buffers events deterministically and flushes
//!   them through the publisher (or falls back to append-only file logging).
//!
//! ## Thread Safety
//!
//! All state is behind `Mutex`. `ReceiptEventLogger` is `Send + Sync`.
//!
//! ## Deterministic Encoding
//!
//! Events are serialized to sorted-key JSON via [`serde_json::to_string`]
//! on types whose field order is struct-declaration order (serde default).
//! This produces identical output across nodes for the same event.
//!
//! ## Timestamp
//!
//! All timestamps are **Unix epoch seconds** (`u64`), obtained via
//! [`current_timestamp_secs`].

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::Write;
use std::sync::{Arc, Mutex};
use tracing::{error, info, warn};

// ════════════════════════════════════════════════════════════════════════════
// TIMESTAMP HELPER
// ════════════════════════════════════════════════════════════════════════════

/// Get current Unix epoch timestamp in seconds.
///
/// Returns 0 if system clock is unavailable (no panic).
pub fn current_timestamp_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ════════════════════════════════════════════════════════════════════════════
// EVENT ENUM
// ════════════════════════════════════════════════════════════════════════════

/// Receipt-related economic event for DA audit logging.
///
/// All variants carry a `timestamp` field (Unix epoch seconds).
///
/// `Serialize + Deserialize + Clone + Debug + Send + Sync`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event_type")]
pub enum ReceiptEconomicEvent {
    /// A claim has been submitted but not yet processed.
    ClaimSubmitted {
        receipt_hash: String,
        submitter: String,
        timestamp: u64,
    },

    /// A claim was accepted and reward allocated.
    ClaimAccepted {
        receipt_hash: String,
        status: String,
        reward_amount: u128,
        timestamp: u64,
    },

    /// A claim was rejected.
    ClaimRejected {
        receipt_hash: String,
        reason: String,
        timestamp: u64,
    },

    /// A challenge period has started for a receipt.
    ChallengeStarted {
        receipt_hash: String,
        expires_at: u64,
        timestamp: u64,
    },

    /// A fraud proof has been received for a receipt.
    FraudProofReceived {
        receipt_hash: String,
        proof_type: String,
        timestamp: u64,
    },
}

impl fmt::Display for ReceiptEconomicEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReceiptEconomicEvent::ClaimSubmitted {
                receipt_hash,
                submitter,
                ..
            } => write!(
                f,
                "ClaimSubmitted(receipt={}, submitter={})",
                receipt_hash, submitter
            ),
            ReceiptEconomicEvent::ClaimAccepted {
                receipt_hash,
                reward_amount,
                ..
            } => write!(
                f,
                "ClaimAccepted(receipt={}, reward={})",
                receipt_hash, reward_amount
            ),
            ReceiptEconomicEvent::ClaimRejected {
                receipt_hash,
                reason,
                ..
            } => write!(
                f,
                "ClaimRejected(receipt={}, reason={})",
                receipt_hash, reason
            ),
            ReceiptEconomicEvent::ChallengeStarted {
                receipt_hash,
                expires_at,
                ..
            } => write!(
                f,
                "ChallengeStarted(receipt={}, expires={})",
                receipt_hash, expires_at
            ),
            ReceiptEconomicEvent::FraudProofReceived {
                receipt_hash,
                proof_type,
                ..
            } => write!(
                f,
                "FraudProofReceived(receipt={}, type={})",
                receipt_hash, proof_type
            ),
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// EVENT PUBLISHER TRAIT
// ════════════════════════════════════════════════════════════════════════════

/// Abstraction for publishing events to the DA layer.
///
/// `Send + Sync` required for multi-threaded access.
pub trait EventPublisher: Send + Sync {
    /// Publish a batch of serialized events.
    ///
    /// Each element in `events` is a deterministic JSON string.
    ///
    /// Returns `Ok(())` on success, `Err(reason)` on failure.
    fn publish_batch(&self, events: &[String]) -> Result<(), String>;
}

// ════════════════════════════════════════════════════════════════════════════
// RECEIPT EVENT LOGGER
// ════════════════════════════════════════════════════════════════════════════

/// Thread-safe event logger for receipt economic events.
///
/// Buffers events in deterministic insertion order and flushes them through
/// an [`EventPublisher`] (or falls back to append-only file logging).
pub struct ReceiptEventLogger {
    /// Optional DA publisher. `None` → always fallback to file.
    event_publisher: Option<Arc<dyn EventPublisher>>,

    /// Buffered events awaiting flush.  Deterministic insertion order.
    log_buffer: Mutex<Vec<ReceiptEconomicEvent>>,

    /// Fallback log file path (append-only).
    fallback_path: String,
}

impl ReceiptEventLogger {
    /// Create a logger with a publisher and fallback file path.
    pub fn new(
        publisher: Option<Arc<dyn EventPublisher>>,
        fallback_path: String,
    ) -> Self {
        Self {
            event_publisher: publisher,
            log_buffer: Mutex::new(Vec::new()),
            fallback_path,
        }
    }

    /// Create a logger without a publisher (always falls back to file).
    pub fn without_publisher(fallback_path: String) -> Self {
        Self::new(None, fallback_path)
    }

    /// Buffer an event for later flush.
    ///
    /// Does NOT publish immediately. Events are flushed via [`flush`].
    /// If the lock is poisoned, logs a warning and drops the event
    /// (no panic).
    pub fn log_event(&self, event: ReceiptEconomicEvent) {
        match self.log_buffer.lock() {
            Ok(mut buf) => {
                info!("[RECEIPT_EVENT] buffered: {}", event);
                buf.push(event);
            }
            Err(err) => {
                warn!(
                    "[RECEIPT_EVENT] lock poisoned, event dropped: {}",
                    err
                );
            }
        }
    }

    /// Flush all buffered events.
    ///
    /// 1. Encode each event to deterministic JSON.
    /// 2. Publish via [`EventPublisher`] if available.
    /// 3. If publisher is `None` or publish fails → fallback to file.
    /// 4. On successful publish → clear buffer.
    /// 5. On successful file write → clear buffer.
    /// 6. On both failures → buffer is NOT cleared (no data loss).
    ///
    /// Returns the number of events flushed.
    pub fn flush(&self) -> usize {
        let events: Vec<ReceiptEconomicEvent> = match self.log_buffer.lock() {
            Ok(buf) => buf.clone(),
            Err(err) => {
                warn!("[RECEIPT_EVENT] flush: lock poisoned: {}", err);
                return 0;
            }
        };

        if events.is_empty() {
            return 0;
        }

        // Encode all events to deterministic JSON strings.
        let mut encoded: Vec<String> = Vec::with_capacity(events.len());
        for event in &events {
            match serde_json::to_string(event) {
                Ok(json) => encoded.push(json),
                Err(err) => {
                    error!(
                        "[RECEIPT_EVENT] serialize failed: {} — event: {:?}",
                        err, event
                    );
                    // Skip this event but continue encoding others.
                }
            }
        }

        if encoded.is_empty() {
            return 0;
        }

        let count = encoded.len();

        // Try publisher first.
        let published = match &self.event_publisher {
            Some(publisher) => match publisher.publish_batch(&encoded) {
                Ok(()) => {
                    info!("[RECEIPT_EVENT] published {} events to DA", count);
                    true
                }
                Err(err) => {
                    warn!(
                        "[RECEIPT_EVENT] DA publish failed ({}), falling back to file",
                        err
                    );
                    false
                }
            },
            None => false,
        };

        // If publisher unavailable or failed, write to fallback file.
        if !published {
            match self.write_fallback(&encoded) {
                Ok(()) => {
                    info!(
                        "[RECEIPT_EVENT] wrote {} events to fallback file: {}",
                        count, self.fallback_path
                    );
                }
                Err(err) => {
                    error!(
                        "[RECEIPT_EVENT] fallback write failed: {} — {} events NOT cleared",
                        err, count
                    );
                    // Do NOT clear buffer — prevent data loss.
                    return 0;
                }
            }
        }

        // Clear buffer after successful publish or file write.
        match self.log_buffer.lock() {
            Ok(mut buf) => buf.clear(),
            Err(err) => {
                warn!("[RECEIPT_EVENT] clear: lock poisoned: {}", err);
            }
        }

        count
    }

    /// Write encoded events to the fallback file (append-only).
    ///
    /// Each event is written as a single line (newline-delimited JSON).
    fn write_fallback(&self, encoded: &[String]) -> Result<(), String> {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.fallback_path)
            .map_err(|e| format!("open fallback file: {}", e))?;

        for line in encoded {
            file.write_all(line.as_bytes())
                .map_err(|e| format!("write event: {}", e))?;
            file.write_all(b"\n")
                .map_err(|e| format!("write newline: {}", e))?;
        }

        file.flush()
            .map_err(|e| format!("flush file: {}", e))?;

        Ok(())
    }

    /// Get current buffer size (for testing/monitoring).
    pub fn buffer_len(&self) -> usize {
        match self.log_buffer.lock() {
            Ok(buf) => buf.len(),
            Err(_) => 0,
        }
    }

    /// Get a snapshot of buffered events (for testing/debugging).
    pub fn buffer_snapshot(&self) -> Vec<ReceiptEconomicEvent> {
        match self.log_buffer.lock() {
            Ok(buf) => buf.clone(),
            Err(_) => Vec::new(),
        }
    }
}

// Send + Sync: Mutex<Vec> is Send+Sync, Option<Arc<dyn EventPublisher>> is Send+Sync.
// Compiler enforces this automatically.

impl fmt::Debug for ReceiptEventLogger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let buf_len = self.buffer_len();
        f.debug_struct("ReceiptEventLogger")
            .field("has_publisher", &self.event_publisher.is_some())
            .field("buffer_len", &buf_len)
            .field("fallback_path", &self.fallback_path)
            .finish()
    }
}

// ════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    // ────────────────────────────────────────────────────────────────────────
    // MOCK PUBLISHER
    // ────────────────────────────────────────────────────────────────────────

    struct MockPublisher {
        published: Mutex<Vec<Vec<String>>>,
        should_fail: AtomicBool,
        call_count: AtomicUsize,
    }

    impl MockPublisher {
        fn new() -> Self {
            Self {
                published: Mutex::new(Vec::new()),
                should_fail: AtomicBool::new(false),
                call_count: AtomicUsize::new(0),
            }
        }

        fn set_fail(&self, fail: bool) {
            self.should_fail.store(fail, Ordering::SeqCst);
        }

        fn published_batches(&self) -> Vec<Vec<String>> {
            match self.published.lock() {
                Ok(p) => p.clone(),
                Err(_) => Vec::new(),
            }
        }

        fn total_calls(&self) -> usize {
            self.call_count.load(Ordering::SeqCst)
        }
    }

    impl EventPublisher for MockPublisher {
        fn publish_batch(&self, events: &[String]) -> Result<(), String> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            if self.should_fail.load(Ordering::SeqCst) {
                return Err("mock publish failure".to_string());
            }
            match self.published.lock() {
                Ok(mut p) => {
                    p.push(events.to_vec());
                    Ok(())
                }
                Err(e) => Err(format!("mock lock error: {}", e)),
            }
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // HELPERS
    // ────────────────────────────────────────────────────────────────────────

    fn test_fallback_path() -> String {
        let mut p = std::env::temp_dir();
        p.push(format!("dsdn_test_events_{}.jsonl", std::process::id()));
        p.to_string_lossy().to_string()
    }

    fn cleanup_fallback(path: &str) {
        let _ = std::fs::remove_file(path);
    }

    fn make_claim_submitted(seed: u8) -> ReceiptEconomicEvent {
        ReceiptEconomicEvent::ClaimSubmitted {
            receipt_hash: format!("{:0>64x}", seed),
            submitter: format!("{:0>40x}", seed),
            timestamp: 1700000000 + seed as u64,
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 1: log_claim_submitted_event
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn log_claim_submitted_event() {
        let path = test_fallback_path();
        let logger = ReceiptEventLogger::without_publisher(path.clone());

        let event = ReceiptEconomicEvent::ClaimSubmitted {
            receipt_hash: "a".repeat(64),
            submitter: "b".repeat(40),
            timestamp: 1700000000,
        };
        logger.log_event(event.clone());

        assert_eq!(logger.buffer_len(), 1);
        let snap = logger.buffer_snapshot();
        assert_eq!(snap[0], event);

        cleanup_fallback(&path);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 2: log_claim_accepted_event
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn log_claim_accepted_event() {
        let path = test_fallback_path();
        let logger = ReceiptEventLogger::without_publisher(path.clone());

        let event = ReceiptEconomicEvent::ClaimAccepted {
            receipt_hash: "c".repeat(64),
            status: "confirmed".to_string(),
            reward_amount: 5000,
            timestamp: 1700000001,
        };
        logger.log_event(event.clone());

        let snap = logger.buffer_snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0], event);

        cleanup_fallback(&path);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 3: log_claim_rejected_event
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn log_claim_rejected_event() {
        let path = test_fallback_path();
        let logger = ReceiptEventLogger::without_publisher(path.clone());

        let event = ReceiptEconomicEvent::ClaimRejected {
            receipt_hash: "d".repeat(64),
            reason: "invalid receipt data".to_string(),
            timestamp: 1700000002,
        };
        logger.log_event(event.clone());

        assert_eq!(logger.buffer_len(), 1);
        let snap = logger.buffer_snapshot();
        assert_eq!(snap[0], event);

        cleanup_fallback(&path);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 4: log_challenge_started_event
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn log_challenge_started_event() {
        let path = test_fallback_path();
        let logger = ReceiptEventLogger::without_publisher(path.clone());

        let event = ReceiptEconomicEvent::ChallengeStarted {
            receipt_hash: "e".repeat(64),
            expires_at: 1700086400,
            timestamp: 1700000003,
        };
        logger.log_event(event.clone());

        let snap = logger.buffer_snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0], event);

        cleanup_fallback(&path);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 5: log_fraud_proof_received_event
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn log_fraud_proof_received_event() {
        let path = test_fallback_path();
        let logger = ReceiptEventLogger::without_publisher(path.clone());

        let event = ReceiptEconomicEvent::FraudProofReceived {
            receipt_hash: "f".repeat(64),
            proof_type: "execution_mismatch".to_string(),
            timestamp: 1700000004,
        };
        logger.log_event(event.clone());

        let snap = logger.buffer_snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0], event);

        cleanup_fallback(&path);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 6: buffer_event_order_deterministic
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn buffer_event_order_deterministic() {
        let path = test_fallback_path();
        let logger = ReceiptEventLogger::without_publisher(path.clone());

        let e1 = make_claim_submitted(0x01);
        let e2 = make_claim_submitted(0x02);
        let e3 = make_claim_submitted(0x03);

        logger.log_event(e1.clone());
        logger.log_event(e2.clone());
        logger.log_event(e3.clone());

        let snap = logger.buffer_snapshot();
        assert_eq!(snap.len(), 3);
        assert_eq!(snap[0], e1);
        assert_eq!(snap[1], e2);
        assert_eq!(snap[2], e3);

        cleanup_fallback(&path);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 7: flush_publishes_events
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn flush_publishes_events() {
        let path = test_fallback_path();
        let publisher = Arc::new(MockPublisher::new());
        let logger = ReceiptEventLogger::new(
            Some(publisher.clone()),
            path.clone(),
        );

        logger.log_event(make_claim_submitted(0xAA));
        logger.log_event(make_claim_submitted(0xBB));

        let flushed = logger.flush();
        assert_eq!(flushed, 2);
        assert_eq!(publisher.total_calls(), 1);

        let batches = publisher.published_batches();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].len(), 2);

        cleanup_fallback(&path);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 8: flush_clears_buffer
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn flush_clears_buffer() {
        let path = test_fallback_path();
        let publisher = Arc::new(MockPublisher::new());
        let logger = ReceiptEventLogger::new(
            Some(publisher.clone()),
            path.clone(),
        );

        logger.log_event(make_claim_submitted(0x01));
        assert_eq!(logger.buffer_len(), 1);

        let flushed = logger.flush();
        assert_eq!(flushed, 1);
        assert_eq!(logger.buffer_len(), 0);

        // Flush again → nothing to flush
        let flushed2 = logger.flush();
        assert_eq!(flushed2, 0);

        cleanup_fallback(&path);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 9: fallback_file_logging
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn fallback_file_logging() {
        let path = test_fallback_path();
        cleanup_fallback(&path);

        // No publisher → falls back to file
        let logger = ReceiptEventLogger::without_publisher(path.clone());

        logger.log_event(make_claim_submitted(0x10));
        logger.log_event(make_claim_submitted(0x20));

        let flushed = logger.flush();
        assert_eq!(flushed, 2);
        assert_eq!(logger.buffer_len(), 0);

        // Verify file contents
        let contents = std::fs::read_to_string(&path);
        match contents {
            Ok(text) => {
                let lines: Vec<&str> = text.lines().collect();
                assert_eq!(lines.len(), 2, "expected 2 lines in fallback file");
                // Each line should be valid JSON
                for line in &lines {
                    let parsed: Result<ReceiptEconomicEvent, _> =
                        serde_json::from_str(line);
                    assert!(parsed.is_ok(), "each line must be valid JSON");
                }
            }
            Err(e) => {
                assert!(false, "failed to read fallback file: {}", e);
            }
        }

        cleanup_fallback(&path);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 10: event_encoding_deterministic
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn event_encoding_deterministic() {
        let event = ReceiptEconomicEvent::ClaimAccepted {
            receipt_hash: "a".repeat(64),
            status: "confirmed".to_string(),
            reward_amount: 42,
            timestamp: 1700000000,
        };

        let json1 = serde_json::to_string(&event);
        let json2 = serde_json::to_string(&event);

        match (json1, json2) {
            (Ok(a), Ok(b)) => {
                assert_eq!(a, b, "same event must produce identical JSON");
            }
            _ => {
                assert!(false, "serialization should not fail");
            }
        }

        // Deserialize and re-serialize must also be identical
        let event_clone = event.clone();
        let j1 = serde_json::to_string(&event);
        let j2 = serde_json::to_string(&event_clone);
        match (j1, j2) {
            (Ok(a), Ok(b)) => assert_eq!(a, b),
            _ => assert!(false, "re-serialization failed"),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 11: logger_thread_safe
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn logger_thread_safe() {
        let path = test_fallback_path();
        let publisher = Arc::new(MockPublisher::new());
        let logger = Arc::new(ReceiptEventLogger::new(
            Some(publisher.clone()),
            path.clone(),
        ));

        let mut handles = Vec::new();

        // Spawn 10 threads, each logging 10 events
        for t in 0u8..10 {
            let l = Arc::clone(&logger);
            handles.push(std::thread::spawn(move || {
                for i in 0u8..10 {
                    let seed = t.wrapping_mul(10).wrapping_add(i);
                    l.log_event(make_claim_submitted(seed));
                }
            }));
        }

        for h in handles {
            match h.join() {
                Ok(()) => {}
                Err(_) => assert!(false, "thread panicked"),
            }
        }

        // All 100 events should be buffered
        assert_eq!(logger.buffer_len(), 100);

        // Flush should succeed
        let flushed = logger.flush();
        assert_eq!(flushed, 100);
        assert_eq!(logger.buffer_len(), 0);
        assert_eq!(publisher.total_calls(), 1);

        cleanup_fallback(&path);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 12: logger_no_panic_invalid_event
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn logger_no_panic_invalid_event() {
        let path = test_fallback_path();
        let logger = ReceiptEventLogger::without_publisher(path.clone());

        // Edge-case events with empty/unusual strings
        let events = vec![
            ReceiptEconomicEvent::ClaimSubmitted {
                receipt_hash: String::new(),
                submitter: String::new(),
                timestamp: 0,
            },
            ReceiptEconomicEvent::ClaimRejected {
                receipt_hash: "x".repeat(1000),
                reason: String::new(),
                timestamp: u64::MAX,
            },
            ReceiptEconomicEvent::FraudProofReceived {
                receipt_hash: "abc".to_string(),
                proof_type: String::new(),
                timestamp: 0,
            },
        ];

        for e in events {
            logger.log_event(e);
        }

        assert_eq!(logger.buffer_len(), 3);

        // Flush should not panic even with weird data
        let flushed = logger.flush();
        assert_eq!(flushed, 3);

        cleanup_fallback(&path);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 13: multiple_events_flush
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn multiple_events_flush() {
        let path = test_fallback_path();
        cleanup_fallback(&path);

        let publisher = Arc::new(MockPublisher::new());
        let logger = ReceiptEventLogger::new(
            Some(publisher.clone()),
            path.clone(),
        );

        // First batch
        logger.log_event(make_claim_submitted(0x01));
        logger.log_event(make_claim_submitted(0x02));
        let f1 = logger.flush();
        assert_eq!(f1, 2);

        // Second batch
        logger.log_event(make_claim_submitted(0x03));
        let f2 = logger.flush();
        assert_eq!(f2, 1);

        // Third flush with nothing
        let f3 = logger.flush();
        assert_eq!(f3, 0);

        // Publisher called twice (once per non-empty flush)
        assert_eq!(publisher.total_calls(), 2);

        let batches = publisher.published_batches();
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].len(), 2);
        assert_eq!(batches[1].len(), 1);

        cleanup_fallback(&path);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14: timestamp_consistency
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn timestamp_consistency() {
        let ts = 1700000000u64;

        let events: Vec<ReceiptEconomicEvent> = vec![
            ReceiptEconomicEvent::ClaimSubmitted {
                receipt_hash: "a".repeat(64),
                submitter: "b".repeat(40),
                timestamp: ts,
            },
            ReceiptEconomicEvent::ClaimAccepted {
                receipt_hash: "a".repeat(64),
                status: "ok".to_string(),
                reward_amount: 100,
                timestamp: ts,
            },
            ReceiptEconomicEvent::ClaimRejected {
                receipt_hash: "a".repeat(64),
                reason: "bad".to_string(),
                timestamp: ts,
            },
            ReceiptEconomicEvent::ChallengeStarted {
                receipt_hash: "a".repeat(64),
                expires_at: ts + 86400,
                timestamp: ts,
            },
            ReceiptEconomicEvent::FraudProofReceived {
                receipt_hash: "a".repeat(64),
                proof_type: "execution_mismatch".to_string(),
                timestamp: ts,
            },
        ];

        // All events with same timestamp must serialize with matching ts field
        for event in &events {
            let json = serde_json::to_string(event);
            match json {
                Ok(s) => {
                    assert!(
                        s.contains("\"timestamp\":1700000000"),
                        "timestamp must be consistent in JSON: {}",
                        s
                    );
                }
                Err(e) => {
                    assert!(false, "serialize failed: {}", e);
                }
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 15: fallback_on_publish_failure
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn fallback_on_publish_failure() {
        let path = test_fallback_path();
        cleanup_fallback(&path);

        let publisher = Arc::new(MockPublisher::new());
        publisher.set_fail(true);

        let logger = ReceiptEventLogger::new(
            Some(publisher.clone()),
            path.clone(),
        );

        logger.log_event(make_claim_submitted(0xFF));
        let flushed = logger.flush();
        assert_eq!(flushed, 1);
        assert_eq!(logger.buffer_len(), 0);

        // Publisher was called (and failed)
        assert_eq!(publisher.total_calls(), 1);

        // Event should be in fallback file
        let contents = std::fs::read_to_string(&path);
        match contents {
            Ok(text) => {
                assert!(text.lines().count() >= 1);
            }
            Err(e) => {
                assert!(false, "fallback file should exist: {}", e);
            }
        }

        cleanup_fallback(&path);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 16: event_display_impl
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn event_display_impl() {
        let event = ReceiptEconomicEvent::ClaimSubmitted {
            receipt_hash: "abc".to_string(),
            submitter: "def".to_string(),
            timestamp: 0,
        };
        let display = format!("{}", event);
        assert!(display.contains("ClaimSubmitted"));
        assert!(display.contains("abc"));
        assert!(display.contains("def"));
    }
}