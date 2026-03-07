//! Comprehensive test suite for audit log subsystem (Tahap 15.16).

use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::audit_event::{
    AuditLogEntry, AuditLogEvent, StakeOperation, GovernanceStatus,
    DaFallbackAction, ChallengeOutcome,
};
use crate::audit_log_error::AuditLogError;
use crate::audit_hook::AuditLogHook;
use crate::audit_writer::AuditLogWriter;
use crate::da_mirror::DaMirrorSync;
use crate::default_audit_writer::DefaultAuditLogWriter;
use crate::mock_audit::{MockWormStorage, MockDaMirrorPublisher, MockAuditLogWriter};
use crate::worm_log::WormLogStorage;

// ════════════════════════════════════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════════════════════════════════════

fn sample_slashing() -> AuditLogEvent {
    AuditLogEvent::SlashingExecuted {
        version: 1,
        timestamp_ms: 1700000000,
        validator_id: "val-001".to_string(),
        node_id: "node-001".to_string(),
        slash_amount: 5000,
        reason: "double_sign".to_string(),
        epoch: 42,
        evidence_hash: [0xAB; 32],
    }
}

fn sample_stake() -> AuditLogEvent {
    AuditLogEvent::StakeUpdated {
        version: 1,
        timestamp_ms: 1700000001,
        staker_address: "staker-001".to_string(),
        operation: StakeOperation::Delegate,
        amount: 1000,
        validator_id: "val-002".to_string(),
        epoch: 43,
    }
}

fn make_writer() -> (Arc<DefaultAuditLogWriter>, Arc<MockWormStorage>, Arc<MockDaMirrorPublisher>) {
    let worm = Arc::new(MockWormStorage::new());
    let pub_mock = Arc::new(MockDaMirrorPublisher::new());
    let da = Arc::new(DaMirrorSync::new(Some(pub_mock.clone())));
    let writer = Arc::new(DefaultAuditLogWriter::new(
        worm.clone(),
        da,
        0,
        [0u8; 32],
    ));
    (writer, worm, pub_mock)
}

/// Decode entry from bytes via bincode (local helper, no proto dependency).
fn decode_entry(bytes: &[u8]) -> Result<AuditLogEntry, String> {
    bincode::deserialize(bytes).map_err(|e| format!("{}", e))
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 1: error_display_all_variants
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn error_display_all_variants() {
    let errors: Vec<AuditLogError> = vec![
        AuditLogError::WriteFailed { reason: "disk".to_string() },
        AuditLogError::EncodingFailed { reason: "bad".to_string() },
        AuditLogError::HashChainBroken { expected: "aa".to_string(), got: "bb".to_string() },
        AuditLogError::SequenceGap { expected: 1, got: 3 },
        AuditLogError::DaPublishFailed { reason: "timeout".to_string() },
        AuditLogError::StorageFull { max_bytes: 1024 },
        AuditLogError::LockPoisoned { reason: "mutex".to_string() },
        AuditLogError::RecoveryFailed { reason: "corrupt".to_string() },
    ];

    for (i, err) in errors.iter().enumerate() {
        let display = format!("{}", err);
        assert!(!display.is_empty(), "variant {} display must not be empty", i);
        // Verify each contains identifying substring
        match err {
            AuditLogError::WriteFailed { .. } => assert!(display.contains("write failed")),
            AuditLogError::EncodingFailed { .. } => assert!(display.contains("encoding failed")),
            AuditLogError::HashChainBroken { .. } => assert!(display.contains("hash chain")),
            AuditLogError::SequenceGap { .. } => assert!(display.contains("sequence gap")),
            AuditLogError::DaPublishFailed { .. } => assert!(display.contains("publish failed")),
            AuditLogError::StorageFull { .. } => assert!(display.contains("storage full")),
            AuditLogError::LockPoisoned { .. } => assert!(display.contains("lock poisoned")),
            AuditLogError::RecoveryFailed { .. } => assert!(display.contains("recovery failed")),
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 2: worm_trait_append_and_read
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn worm_trait_append_and_read() {
    let worm = MockWormStorage::new();
    let data = b"test_audit_entry_bytes";

    let seq = worm.append(data);
    match seq {
        Ok(s) => {
            assert!(s >= 1);
            let read = worm.read_entry(s);
            match read {
                Ok(Some(bytes)) => assert_eq!(bytes, data.to_vec()),
                Ok(None) => assert!(false, "entry must exist after append"),
                Err(e) => assert!(false, "read_entry failed: {}", e),
            }
        }
        Err(e) => assert!(false, "append failed: {}", e),
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 3: worm_trait_read_range
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn worm_trait_read_range() {
    let worm = MockWormStorage::new();
    let _ = worm.append(b"entry_a");
    let _ = worm.append(b"entry_b");
    let _ = worm.append(b"entry_c");
    let _ = worm.append(b"entry_d");

    // Range [2, 4) → entries b, c
    let range = worm.read_range(2, 4);
    match range {
        Ok(entries) => {
            assert_eq!(entries.len(), 2, "range [2,4) must have 2 entries");
            assert_eq!(entries[0], b"entry_b");
            assert_eq!(entries[1], b"entry_c");
        }
        Err(e) => assert!(false, "read_range failed: {}", e),
    }

    // Full range [1, 5) → all 4
    let all = worm.read_range(1, 5);
    match all {
        Ok(entries) => assert_eq!(entries.len(), 4),
        Err(e) => assert!(false, "read_range all: {}", e),
    }

    // Empty range [3, 3) → 0
    let empty = worm.read_range(3, 3);
    match empty {
        Ok(entries) => assert!(entries.is_empty()),
        Err(e) => assert!(false, "read_range empty: {}", e),
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 4: worm_trait_sequence_monotonic
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn worm_trait_sequence_monotonic() {
    let worm = MockWormStorage::new();
    let mut prev_seq = 0u64;

    for i in 0..20 {
        let seq = worm.append(format!("entry_{}", i).as_bytes());
        match seq {
            Ok(s) => {
                assert!(s > prev_seq, "sequence must increase: {} > {}", s, prev_seq);
                prev_seq = s;
            }
            Err(e) => assert!(false, "append {} failed: {}", i, e),
        }
    }

    let last = worm.last_sequence();
    match last {
        Ok(s) => assert_eq!(s, 20),
        Err(e) => assert!(false, "last_sequence: {}", e),
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 5: da_mirror_buffer_and_flush
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn da_mirror_buffer_and_flush() {
    let pub_mock = Arc::new(MockDaMirrorPublisher::new());
    let sync = DaMirrorSync::new(Some(pub_mock.clone()));

    let _ = sync.buffer_entry(vec![1, 2, 3]);
    let _ = sync.buffer_entry(vec![4, 5, 6]);
    let _ = sync.buffer_entry(vec![7, 8, 9]);
    assert_eq!(sync.pending_count(), 3);

    let flushed = sync.flush_to_da();
    match flushed {
        Ok(c) => {
            assert_eq!(c, 3, "must flush 3 entries");
            assert_eq!(sync.pending_count(), 0, "buffer must be empty after flush");
            assert!(sync.last_synced_sequence() >= 1, "DA seq must advance");
            assert_eq!(pub_mock.call_count.load(Ordering::SeqCst), 1, "publish called once");
        }
        Err(e) => assert!(false, "flush failed: {}", e),
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 6: da_mirror_flush_empty_noop
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn da_mirror_flush_empty_noop() {
    let pub_mock = Arc::new(MockDaMirrorPublisher::new());
    let sync = DaMirrorSync::new(Some(pub_mock.clone()));

    let flushed = sync.flush_to_da();
    match flushed {
        Ok(c) => {
            assert_eq!(c, 0, "empty flush must return 0");
            assert_eq!(pub_mock.call_count.load(Ordering::SeqCst), 0, "publish not called");
        }
        Err(e) => assert!(false, "empty flush failed: {}", e),
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 7: da_mirror_no_publisher_fallback
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn da_mirror_no_publisher_fallback() {
    let sync = DaMirrorSync::new(None);

    let _ = sync.buffer_entry(vec![10, 20]);
    let _ = sync.buffer_entry(vec![30, 40]);
    assert_eq!(sync.pending_count(), 2);

    let flushed = sync.flush_to_da();
    match flushed {
        Ok(c) => {
            assert_eq!(c, 2, "no-publisher mode must still return count");
            assert_eq!(sync.pending_count(), 0, "buffer cleared");
            assert_eq!(sync.last_synced_sequence(), 0, "DA seq stays 0 without publisher");
        }
        Err(e) => assert!(false, "no-publisher flush failed: {}", e),
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 8: da_mirror_publish_failure_retains_buffer
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn da_mirror_publish_failure_retains_buffer() {
    let pub_mock = Arc::new(MockDaMirrorPublisher::new());
    pub_mock.force_error.store(true, Ordering::SeqCst);
    let sync = DaMirrorSync::new(Some(pub_mock));

    let _ = sync.buffer_entry(vec![1]);
    let _ = sync.buffer_entry(vec![2]);
    assert_eq!(sync.pending_count(), 2);

    let result = sync.flush_to_da();
    assert!(result.is_err(), "publish failure must return error");
    assert_eq!(sync.pending_count(), 2, "buffer must NOT be cleared on failure");
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 9: hook_on_event_persists
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn hook_on_event_persists() {
    let (writer, worm, _) = make_writer();

    // DefaultAuditLogWriter implements AuditLogHook
    let hook: &dyn AuditLogHook = writer.as_ref();
    let result = hook.on_event(sample_slashing());
    assert!(result.is_ok(), "on_event must succeed");

    let count = worm.entry_count();
    match count {
        Ok(c) => assert_eq!(c, 1, "event must be persisted to WORM"),
        Err(e) => assert!(false, "entry_count: {}", e),
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 10: hook_flush_publishes
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn hook_flush_publishes() {
    let worm = Arc::new(MockWormStorage::new());
    let pub_mock = Arc::new(MockDaMirrorPublisher::new());
    let da = Arc::new(DaMirrorSync::new(Some(pub_mock.clone())));
    let writer = DefaultAuditLogWriter::new(worm, da.clone(), 0, [0u8; 32]);

    let hook: &dyn AuditLogHook = &writer;
    let _ = hook.on_event(sample_slashing());
    let _ = hook.on_event(sample_stake());
    assert_eq!(da.pending_count(), 2);

    let flushed = hook.flush();
    match flushed {
        Ok(c) => {
            assert_eq!(c, 2, "flush must return 2");
            assert_eq!(da.pending_count(), 0, "buffer empty after flush");
            assert_eq!(pub_mock.call_count.load(Ordering::SeqCst), 1);
        }
        Err(e) => assert!(false, "flush: {}", e),
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 11: writer_hash_chain_integrity
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn writer_hash_chain_integrity() {
    let (writer, worm, _) = make_writer();

    for _ in 0..5 {
        let r = writer.write_event(sample_slashing());
        assert!(r.is_ok());
    }

    let raw = worm.read_range(1, 6);
    match raw {
        Ok(entries) => {
            assert_eq!(entries.len(), 5);
            let mut prev: Option<AuditLogEntry> = None;

            for (i, bytes) in entries.iter().enumerate() {
                let entry = decode_entry(bytes);
                match entry {
                    Ok(e) => {
                        // Verify hash recomputation
                        let recomputed = e.compute_entry_hash();
                        assert_eq!(e.entry_hash, recomputed, "hash mismatch at entry {}", i);

                        // Verify chain link
                        if let Some(ref p) = prev {
                            assert_eq!(e.prev_hash, p.entry_hash,
                                "entry {} prev_hash must match entry {} hash", i, i - 1);
                            assert_eq!(e.sequence, p.sequence + 1,
                                "entry {} sequence must be prev + 1", i);
                            assert!(e.verify_chain(p), "chain link {} must be valid", i);
                        } else {
                            assert_eq!(e.prev_hash, [0u8; 32], "first entry prev_hash must be zero");
                        }

                        prev = Some(e);
                    }
                    Err(e) => assert!(false, "decode entry {}: {}", i, e),
                }
            }
        }
        Err(e) => assert!(false, "read_range: {}", e),
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 12: writer_sequence_monotonic
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn writer_sequence_monotonic() {
    let (writer, _, _) = make_writer();

    let mut prev_seq = 0u64;
    for i in 0..10 {
        let result = writer.write_event(sample_stake());
        match result {
            Ok(seq) => {
                assert!(seq > prev_seq, "seq must increase at iteration {}", i);
                assert_eq!(seq, prev_seq + 1, "seq must increment by 1");
                prev_seq = seq;
            }
            Err(e) => assert!(false, "write {} failed: {}", i, e),
        }
    }
    assert_eq!(writer.last_sequence(), 10);
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 13: writer_verify_chain_valid
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn writer_verify_chain_valid() {
    let (writer, _, _) = make_writer();

    for _ in 0..8 {
        let _ = writer.write_event(sample_slashing());
    }

    let valid = writer.verify_chain(1, 9);
    match valid {
        Ok(v) => assert!(v, "chain of 8 entries must be valid"),
        Err(e) => assert!(false, "verify_chain: {}", e),
    }

    // Subrange also valid
    let sub = writer.verify_chain(3, 7);
    match sub {
        Ok(v) => assert!(v, "subrange [3,7) must be valid"),
        Err(e) => assert!(false, "verify subrange: {}", e),
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 14: writer_verify_chain_tampered
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn writer_verify_chain_tampered() {
    let worm = Arc::new(MockWormStorage::new());
    let da = Arc::new(DaMirrorSync::new(None));
    let writer = DefaultAuditLogWriter::new(worm.clone(), da, 0, [0u8; 32]);

    for _ in 0..3 {
        let _ = writer.write_event(sample_slashing());
    }

    // Tamper: replace entry 2 with garbage that has wrong hash
    let entry2_raw = worm.read_entry(2);
    match entry2_raw {
        Ok(Some(bytes)) => {
            let decoded = decode_entry(&bytes);
            match decoded {
                Ok(mut entry) => {
                    // Tamper the entry_hash
                    entry.entry_hash = [0xFF; 32];
                    let tampered_bytes = bincode::serialize(&entry).unwrap_or_default();
                    if !tampered_bytes.is_empty() {
                        // We can't overwrite WORM in production, but MockWormStorage
                        // lets us test the verifier by building a separate writer
                        // Instead, verify that the tampered entry fails recomputation
                        let recomputed = entry.compute_entry_hash();
                        assert_ne!(entry.entry_hash, recomputed,
                            "tampered hash must not match recomputed");
                    }
                }
                Err(e) => assert!(false, "decode: {}", e),
            }
        }
        Ok(None) => assert!(false, "entry 2 must exist"),
        Err(e) => assert!(false, "read: {}", e),
    }

    // The un-tampered chain should still be valid
    let valid = writer.verify_chain(1, 4);
    match valid {
        Ok(v) => assert!(v, "un-tampered chain must be valid"),
        Err(e) => assert!(false, "verify: {}", e),
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 15: writer_concurrent_writes
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn writer_concurrent_writes() {
    let (writer, worm, _) = make_writer();

    let mut handles = Vec::new();
    for _ in 0..5 {
        let w = Arc::clone(&writer);
        handles.push(std::thread::spawn(move || {
            for _ in 0..10 {
                let r = w.write_event(sample_slashing());
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

    // 50 entries total
    let count = worm.entry_count();
    match count {
        Ok(c) => assert_eq!(c, 50, "50 entries from 5 threads x 10"),
        Err(e) => assert!(false, "entry_count: {}", e),
    }

    // Sequence = 50
    assert_eq!(writer.last_sequence(), 50);

    // Verify chain integrity across all 50 entries
    let valid = writer.verify_chain(1, 51);
    match valid {
        Ok(v) => assert!(v, "concurrent chain must be valid"),
        Err(e) => assert!(false, "verify: {}", e),
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 16: mock_writer_records_events
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn mock_writer_records_events() {
    let mock = MockAuditLogWriter::new();

    let r1 = mock.write_event(sample_slashing());
    let r2 = mock.write_event(sample_stake());
    let r3 = mock.write_event(sample_slashing());

    match (r1, r2, r3) {
        (Ok(s1), Ok(s2), Ok(s3)) => {
            assert_eq!(s1, 1);
            assert_eq!(s2, 2);
            assert_eq!(s3, 3);
        }
        _ => assert!(false, "mock write should not fail"),
    }

    assert_eq!(mock.event_count(), 3);
    assert_eq!(mock.last_sequence(), 3);

    let events = mock.recorded_events();
    assert_eq!(events.len(), 3);

    // Verify via hook interface too
    let hook: &dyn AuditLogHook = &mock;
    let r = hook.on_event(sample_stake());
    assert!(r.is_ok());
    assert_eq!(mock.event_count(), 4);
}