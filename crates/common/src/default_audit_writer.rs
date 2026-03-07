//! # Default Audit Log Writer (Tahap 15.14)
//!
//! Production implementation combining WORM storage + DA mirror + hash chain.
//!
//! ## Write Pipeline
//!
//! ```text
//! AuditLogEvent
//!     │
//!     ▼
//! 1. Lock last_hash (Mutex)
//! 2. Build AuditLogEntry { seq, ts, prev_hash, event }
//! 3. Compute entry_hash (SHA3-256 via proto)
//! 4. Encode entry to bytes (bincode via proto)
//! 5. Append to WORM storage
//! 6. Buffer to DA mirror
//! 7. Update last_hash + sequence
//! 8. Return sequence
//! ```

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::audit_event::{AuditLogEntry, AuditLogEvent};

use crate::audit_log_error::AuditLogError;
use crate::audit_hook::AuditLogHook;
use crate::audit_writer::AuditLogWriter;
use crate::da_mirror::DaMirrorSync;
use crate::worm_log::WormLogStorage;

// ════════════════════════════════════════════════════════════════════════════════
// LOCAL ENCODING HELPERS (avoid circular dependency on proto)
// ════════════════════════════════════════════════════════════════════════════════

/// Encode `AuditLogEntry` to bytes via bincode. Returns empty Vec on failure.
fn encode_audit_entry(entry: &AuditLogEntry) -> Vec<u8> {
    bincode::serialize(entry).unwrap_or_default()
}

/// Decode bytes to `AuditLogEntry` via bincode.
fn decode_audit_entry(bytes: &[u8]) -> Result<AuditLogEntry, AuditLogError> {
    if bytes.is_empty() {
        return Err(AuditLogError::EncodingFailed {
            reason: "empty input".to_string(),
        });
    }
    bincode::deserialize(bytes).map_err(|e| AuditLogError::EncodingFailed {
        reason: format!("bincode decode: {}", e),
    })
}

// ════════════════════════════════════════════════════════════════════════════════
// DEFAULT AUDIT LOG WRITER
// ════════════════════════════════════════════════════════════════════════════════

/// Production audit log writer implementing [`AuditLogWriter`] + [`AuditLogHook`].
///
/// # Thread Safety
///
/// - `last_hash`: `Mutex<[u8; 32]>` protects hash chain state.
/// - `current_sequence`: `AtomicU64` for lock-free sequence reads.
/// - `worm` + `da_mirror`: `Arc` for shared ownership.
pub struct DefaultAuditLogWriter {
    /// WORM append-only storage backend.
    worm: Arc<dyn WormLogStorage>,
    /// DA mirror sync for publishing entries.
    da_mirror: Arc<DaMirrorSync>,
    /// Hash of the last written entry. `[0u8; 32]` for first entry.
    last_hash: Mutex<[u8; 32]>,
    /// Current sequence counter. 0 = no entries written yet.
    current_sequence: AtomicU64,
}

impl DefaultAuditLogWriter {
    /// Create a new writer.
    ///
    /// Use `initial_sequence = 0` and `initial_hash = [0u8; 32]` for a fresh log.
    /// Use non-zero values to resume from an existing log.
    pub fn new(
        worm: Arc<dyn WormLogStorage>,
        da_mirror: Arc<DaMirrorSync>,
        initial_sequence: u64,
        initial_hash: [u8; 32],
    ) -> Self {
        Self {
            worm,
            da_mirror,
            last_hash: Mutex::new(initial_hash),
            current_sequence: AtomicU64::new(initial_sequence),
        }
    }

    /// Get current Unix timestamp in milliseconds. Returns 0 if clock unavailable.
    fn current_timestamp_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

impl AuditLogWriter for DefaultAuditLogWriter {
    fn write_event(&self, event: AuditLogEvent) -> Result<u64, AuditLogError> {
        // 1. Lock last_hash
        let mut prev_hash_guard = self.last_hash.lock().map_err(|e| {
            AuditLogError::LockPoisoned {
                reason: format!("last_hash lock: {}", e),
            }
        })?;

        // 2. Build AuditLogEntry
        let seq = self.current_sequence.load(Ordering::SeqCst).saturating_add(1);
        let ts = Self::current_timestamp_ms();
        let prev_hash = *prev_hash_guard;

        let mut entry = AuditLogEntry {
            sequence: seq,
            timestamp_ms: ts,
            prev_hash,
            event,
            entry_hash: [0u8; 32],
        };

        // 3. Compute entry_hash
        entry.entry_hash = entry.compute_entry_hash();

        // 4. Encode entry to bytes
        let entry_bytes = encode_audit_entry(&entry);
        if entry_bytes.is_empty() {
            return Err(AuditLogError::EncodingFailed {
                reason: "encode_audit_entry returned empty bytes".to_string(),
            });
        }

        // 5. Append to WORM
        self.worm.append(&entry_bytes)?;

        // 6. Buffer to DA mirror
        self.da_mirror.buffer_entry(entry_bytes)?;

        // 7. Update state
        *prev_hash_guard = entry.entry_hash;
        self.current_sequence.store(seq, Ordering::SeqCst);

        // 8. Return sequence
        Ok(seq)
    }

    fn flush_da(&self) -> Result<usize, AuditLogError> {
        self.da_mirror.flush_to_da()
    }

    fn last_sequence(&self) -> u64 {
        self.current_sequence.load(Ordering::SeqCst)
    }

    fn verify_chain(&self, start: u64, end: u64) -> Result<bool, AuditLogError> {
        if start >= end {
            return Ok(true);
        }

        let raw_entries = self.worm.read_range(start, end)?;
        if raw_entries.is_empty() {
            return Ok(true);
        }

        let mut prev_entry: Option<AuditLogEntry> = None;

        for raw in raw_entries.iter() {
            let entry = decode_audit_entry(raw)?;

            // Verify entry_hash matches recomputed hash
            let recomputed = entry.compute_entry_hash();
            if entry.entry_hash != recomputed {
                return Ok(false);
            }

            // Verify chain link to previous
            if let Some(ref prev) = prev_entry {
                if !entry.verify_chain(prev) {
                    return Ok(false);
                }
            }

            prev_entry = Some(entry);
        }

        Ok(true)
    }
}

impl AuditLogHook for DefaultAuditLogWriter {
    fn on_event(&self, event: AuditLogEvent) -> Result<(), AuditLogError> {
        self.write_event(event)?;
        Ok(())
    }

    fn flush(&self) -> Result<usize, AuditLogError> {
        self.flush_da()
    }
}

impl std::fmt::Debug for DefaultAuditLogWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DefaultAuditLogWriter")
            .field("current_sequence", &self.current_sequence.load(Ordering::SeqCst))
            .field("da_mirror", &self.da_mirror)
            .finish()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock_audit::{MockWormStorage, MockDaMirrorPublisher};

    fn make_writer() -> (DefaultAuditLogWriter, Arc<MockWormStorage>, Arc<MockDaMirrorPublisher>) {
        let worm = Arc::new(MockWormStorage::new());
        let pub_mock = Arc::new(MockDaMirrorPublisher::new());
        let da = Arc::new(DaMirrorSync::new(Some(pub_mock.clone())));
        let writer = DefaultAuditLogWriter::new(worm.clone(), da, 0, [0u8; 32]);
        (writer, worm, pub_mock)
    }

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

    // ════════════════════════════════════════════════════════════════════════
    // TEST 1: default_writer_append_single_event
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn default_writer_append_single_event() {
        let (writer, worm, _) = make_writer();
        let result = writer.write_event(sample_event());
        match result {
            Ok(seq) => {
                assert_eq!(seq, 1);
                let count = worm.entry_count();
                match count {
                    Ok(c) => assert_eq!(c, 1),
                    Err(e) => assert!(false, "entry_count: {}", e),
                }
            }
            Err(e) => assert!(false, "write_event: {}", e),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 2: default_writer_sequence_increment
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn default_writer_sequence_increment() {
        let (writer, _, _) = make_writer();
        for expected in 1u64..=5 {
            let result = writer.write_event(sample_event());
            match result {
                Ok(seq) => assert_eq!(seq, expected),
                Err(e) => assert!(false, "write at {}: {}", expected, e),
            }
        }
        assert_eq!(writer.last_sequence(), 5);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 3: default_writer_hash_chain_integrity
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn default_writer_hash_chain_integrity() {
        let (writer, worm, _) = make_writer();
        for _ in 0..5 {
            let r = writer.write_event(sample_event());
            assert!(r.is_ok());
        }

        let raw = worm.read_range(1, 6);
        match raw {
            Ok(entries) => {
                assert_eq!(entries.len(), 5);
                let mut prev: Option<AuditLogEntry> = None;
                for (i, bytes) in entries.iter().enumerate() {
                    let entry = decode_audit_entry(bytes);
                    match entry {
                        Ok(e) => {
                            assert_eq!(e.entry_hash, e.compute_entry_hash(), "hash mismatch at {}", i);
                            if let Some(ref p) = prev {
                                assert!(e.verify_chain(p), "chain broken at {}", i);
                            }
                            prev = Some(e);
                        }
                        Err(e) => assert!(false, "decode {}: {}", i, e),
                    }
                }
            }
            Err(e) => assert!(false, "read_range: {}", e),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 4: default_writer_prev_hash_correct
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn default_writer_prev_hash_correct() {
        let (writer, worm, _) = make_writer();
        let _ = writer.write_event(sample_event());
        let _ = writer.write_event(sample_event());

        let r1 = worm.read_entry(1);
        let r2 = worm.read_entry(2);
        match (r1, r2) {
            (Ok(Some(b1)), Ok(Some(b2))) => {
                match (decode_audit_entry(&b1), decode_audit_entry(&b2)) {
                    (Ok(e1), Ok(e2)) => {
                        assert_eq!(e1.prev_hash, [0u8; 32], "first prev_hash must be zero");
                        assert_eq!(e2.prev_hash, e1.entry_hash, "second prev_hash must match first hash");
                    }
                    _ => assert!(false, "decode failed"),
                }
            }
            _ => assert!(false, "read failed"),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 5: default_writer_concurrent_append_safe
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn default_writer_concurrent_append_safe() {
        let (writer, worm, _) = make_writer();
        let writer = Arc::new(writer);

        let mut handles = Vec::new();
        for _ in 0..5 {
            let w = Arc::clone(&writer);
            handles.push(std::thread::spawn(move || {
                for _ in 0..10 {
                    let _ = w.write_event(sample_event());
                }
            }));
        }
        for h in handles {
            match h.join() {
                Ok(()) => {}
                Err(_) => assert!(false, "thread panicked"),
            }
        }

        let count = worm.entry_count();
        match count {
            Ok(c) => assert_eq!(c, 50),
            Err(e) => assert!(false, "entry_count: {}", e),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 6: default_writer_worm_append_called
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn default_writer_worm_append_called() {
        let (writer, worm, _) = make_writer();
        let _ = writer.write_event(sample_event());
        let _ = writer.write_event(sample_event());
        let _ = writer.write_event(sample_event());
        let count = worm.entry_count();
        match count {
            Ok(c) => assert_eq!(c, 3),
            Err(e) => assert!(false, "count: {}", e),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 7: default_writer_da_buffer_called
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn default_writer_da_buffer_called() {
        let worm = Arc::new(MockWormStorage::new());
        let pub_mock = Arc::new(MockDaMirrorPublisher::new());
        let da = Arc::new(DaMirrorSync::new(Some(pub_mock.clone())));
        let writer = DefaultAuditLogWriter::new(worm, da.clone(), 0, [0u8; 32]);

        let _ = writer.write_event(sample_event());
        let _ = writer.write_event(sample_event());
        assert_eq!(da.pending_count(), 2);

        let flushed = writer.flush_da();
        match flushed {
            Ok(c) => assert_eq!(c, 2),
            Err(e) => assert!(false, "flush: {}", e),
        }
        assert_eq!(da.pending_count(), 0);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 8: default_writer_hash_changes_per_event
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn default_writer_hash_changes_per_event() {
        let (writer, worm, _) = make_writer();
        let _ = writer.write_event(sample_event());
        let _ = writer.write_event(AuditLogEvent::SlashingExecuted {
            version: 1, timestamp_ms: 1700000001,
            validator_id: "v".to_string(), node_id: "n".to_string(),
            slash_amount: 100, reason: "r".to_string(), epoch: 1,
            evidence_hash: [0xAB; 32],
        });

        match (worm.read_entry(1), worm.read_entry(2)) {
            (Ok(Some(b1)), Ok(Some(b2))) => {
                match (decode_audit_entry(&b1), decode_audit_entry(&b2)) {
                    (Ok(e1), Ok(e2)) => {
                        assert_ne!(e1.entry_hash, e2.entry_hash, "different events must produce different hashes");
                    }
                    _ => assert!(false, "decode failed"),
                }
            }
            _ => assert!(false, "read failed"),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 9: default_writer_sequence_monotonic
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn default_writer_sequence_monotonic() {
        let (writer, _, _) = make_writer();
        let mut prev_seq = 0u64;
        for _ in 0..10 {
            let result = writer.write_event(sample_event());
            match result {
                Ok(seq) => {
                    assert!(seq > prev_seq, "monotonic");
                    prev_seq = seq;
                }
                Err(e) => assert!(false, "write: {}", e),
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 10: default_writer_flush_via_hook
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn default_writer_flush_via_hook() {
        let worm = Arc::new(MockWormStorage::new());
        let pub_mock = Arc::new(MockDaMirrorPublisher::new());
        let da = Arc::new(DaMirrorSync::new(Some(pub_mock.clone())));
        let writer = DefaultAuditLogWriter::new(worm, da, 0, [0u8; 32]);

        let hook: &dyn AuditLogHook = &writer;
        let r = hook.on_event(sample_event());
        assert!(r.is_ok());

        let flushed = hook.flush();
        match flushed {
            Ok(c) => assert_eq!(c, 1),
            Err(e) => assert!(false, "flush: {}", e),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 11: default_writer_verify_chain
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn default_writer_verify_chain() {
        let (writer, _, _) = make_writer();
        for _ in 0..5 {
            let _ = writer.write_event(sample_event());
        }

        let valid = writer.verify_chain(1, 6);
        match valid {
            Ok(v) => assert!(v, "chain must be valid"),
            Err(e) => assert!(false, "verify: {}", e),
        }
    }
}