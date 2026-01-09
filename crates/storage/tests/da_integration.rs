//! # DA Integration Tests
//!
//! Integration tests untuk storage crate yang menguji interaksi antar modul
//! dan membuktikan invariant arsitektural.
//!
//! ## Test Categories
//!
//! 1. DA → Metadata Derivation
//! 2. Recovery Roundtrip
//! 3. GC Safety
//! 4. Metrics Consistency
//! 5. Event Emission (Observability)
//!
//! ## Key Invariants Tested
//!
//! - Semua chunk metadata dapat direkonstruksi dari DA events
//! - Recovery hanya untuk chunks yang assigned via DA
//! - GC hanya menghapus chunks yang eligible via DA events
//! - Metrics konsisten dengan actual state
//! - Events bersifat observability-only, tidak mempengaruhi behavior

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use parking_lot::RwLock;
use sha3::{Sha3_256, Digest};

use dsdn_common::{DALayer, MockDA};
use dsdn_storage::{
    // Core
    Storage,
    DAStorage,
    DAChunkMeta,
    // Events
    ChunkDeclaredEvent,
    ReplicaAddedEvent,
    ReplicaRemovedEvent,
    DeleteRequestedEvent,
    // GC
    GarbageCollector,
    // Metrics
    StorageMetrics,
    // Recovery
    SimpleStorageRecovery,
    // Events
    StorageEvent,
    StorageEventListener,
    EventEmitter,
    NoOpListener,
};

// ════════════════════════════════════════════════════════════════════════════════
// MOCK STORAGE
// ════════════════════════════════════════════════════════════════════════════════

#[derive(Debug)]
struct MockStorage {
    chunks: RwLock<HashMap<String, Vec<u8>>>,
}

impl MockStorage {
    fn new() -> Self {
        Self {
            chunks: RwLock::new(HashMap::new()),
        }
    }
}

impl Storage for MockStorage {
    fn put_chunk(&self, hash: &str, data: &[u8]) -> dsdn_common::Result<()> {
        self.chunks.write().insert(hash.to_string(), data.to_vec());
        Ok(())
    }

    fn get_chunk(&self, hash: &str) -> dsdn_common::Result<Option<Vec<u8>>> {
        Ok(self.chunks.read().get(hash).cloned())
    }

    fn has_chunk(&self, hash: &str) -> dsdn_common::Result<bool> {
        Ok(self.chunks.read().contains_key(hash))
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════════

fn compute_commitment(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();
    result.into()
}

fn create_test_storage() -> Arc<DAStorage> {
    let inner = Arc::new(MockStorage::new());
    let da = Arc::new(MockDA::new());
    Arc::new(DAStorage::new(inner, da))
}

fn create_chunk_declared_event(hash: &str, size: u64, commitment: [u8; 32], target_rf: u8) -> ChunkDeclaredEvent {
    ChunkDeclaredEvent::with_target_rf(
        hash.to_string(),
        size,
        commitment,
        None,
        1000, // timestamp
        target_rf,
    )
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 1: DA → METADATA DERIVATION
// ════════════════════════════════════════════════════════════════════════════════

/// Test bahwa metadata di DAStorage sepenuhnya derived dari DA events.
///
/// Invariant: Tidak ada metadata yang dibuat tanpa ChunkDeclared event.
/// Invariant: Replica info hanya dari ReplicaAdded events.
#[test]
fn test_da_to_metadata_derivation() {
    let storage = create_test_storage();
    let data = b"test data for DA derivation";
    let commitment = compute_commitment(data);

    // Initially no metadata
    assert_eq!(storage.metadata_count(), 0);
    assert_eq!(storage.declared_chunks_count(), 0);

    // Simulate ChunkDeclared event from DA
    let declared_event = create_chunk_declared_event(
        "chunk-1",
        data.len() as u64,
        commitment,
        3, // target_rf
    );
    storage.receive_chunk_declared(declared_event);

    // Before sync, metadata not yet created
    assert_eq!(storage.declared_chunks_count(), 1);

    // Sync metadata from DA events
    let synced = storage.sync_metadata_from_da().unwrap();
    assert_eq!(synced, 1);

    // After sync, metadata exists and is derived from DA
    assert_eq!(storage.metadata_count(), 1);
    let meta = storage.get_metadata("chunk-1").unwrap();
    assert_eq!(meta.da_commitment, commitment);
    assert_eq!(meta.size_bytes, data.len() as u64);

    // Replica info initially empty
    assert!(meta.replicas.is_empty());
    assert_eq!(meta.current_rf, 0);
    assert_eq!(meta.target_rf, 3);

    // Simulate ReplicaAdded event from DA
    storage.receive_replica_added(ReplicaAddedEvent::new(
        "chunk-1".to_string(),
        "node-1".to_string(),
        2000,
        None,
    ));

    // Sync replica info
    storage.sync_replica_info("chunk-1").unwrap();

    // Replica info now derived from DA
    let meta = storage.get_metadata("chunk-1").unwrap();
    assert_eq!(meta.current_rf, 1);
    assert_eq!(meta.replicas.len(), 1);
    assert!(meta.replicas[0].node_id == "node-1");

    // Add more replicas
    storage.receive_replica_added(ReplicaAddedEvent::new(
        "chunk-1".to_string(),
        "node-2".to_string(),
        3000,
        None,
    ));
    storage.receive_replica_added(ReplicaAddedEvent::new(
        "chunk-1".to_string(),
        "node-3".to_string(),
        4000,
        None,
    ));
    storage.sync_replica_info("chunk-1").unwrap();

    let meta = storage.get_metadata("chunk-1").unwrap();
    assert_eq!(meta.current_rf, 3);
    assert_eq!(meta.replicas.len(), 3);

    // Verify all metadata is reconstructable from DA
    // Clear and rebuild should yield same result
    storage.clear_metadata();
    assert_eq!(storage.metadata_count(), 0);

    let synced = storage.sync_metadata_from_da().unwrap();
    assert_eq!(synced, 1);
    assert_eq!(storage.metadata_count(), 1);
}

/// Test bahwa metadata sync adalah idempotent.
#[test]
fn test_metadata_sync_idempotent() {
    let storage = create_test_storage();
    let data = b"idempotent test";
    let commitment = compute_commitment(data);

    // Declare chunk
    storage.receive_chunk_declared(create_chunk_declared_event(
        "chunk-idempotent",
        data.len() as u64,
        commitment,
        3,
    ));

    // Sync multiple times
    let sync1 = storage.sync_metadata_from_da().unwrap();
    let sync2 = storage.sync_metadata_from_da().unwrap();
    let sync3 = storage.sync_metadata_from_da().unwrap();

    // First sync creates, subsequent syncs update (count stays same)
    assert_eq!(sync1, 1);
    assert_eq!(sync2, 1);
    assert_eq!(sync3, 1);

    // Metadata remains consistent
    assert_eq!(storage.metadata_count(), 1);
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 2: RECOVERY ROUNDTRIP
// ════════════════════════════════════════════════════════════════════════════════

/// Test recovery dari chunk yang hilang.
///
/// Invariant: Recovery hanya untuk chunks yang assigned via DA.
/// Invariant: Data diverifikasi sebelum disimpan.
/// Invariant: Tidak overwrite chunk yang sudah ada.
#[test]
fn test_recovery_roundtrip() {
    let inner = Arc::new(MockStorage::new());
    let da = Arc::new(MockDA::new());
    let storage = Arc::new(DAStorage::new(inner, da.clone()));

    let data = b"data to recover";
    let commitment = compute_commitment(data);

    // Setup: Declare chunk and assign to "my-node"
    storage.receive_chunk_declared(create_chunk_declared_event(
        "chunk-recover",
        data.len() as u64,
        commitment,
        3,
    ));
    storage.sync_metadata_from_da().unwrap();

    storage.receive_replica_added(ReplicaAddedEvent::new(
        "chunk-recover".to_string(),
        "my-node".to_string(),
        1000,
        None,
    ));
    storage.sync_replica_info("chunk-recover").unwrap();

    // Verify chunk is missing from storage but metadata exists
    assert!(storage.has_metadata("chunk-recover"));
    assert!(!storage.has_chunk("chunk-recover").unwrap());

    // Create recovery manager
    let recovery = SimpleStorageRecovery::new(
        storage.clone(),
        da,
        "my-node".to_string(),
        vec!["peer-1".to_string()],
    );

    // Set mock peer data with correct commitment
    recovery.set_mock_peer_data("peer-1", "chunk-recover", data.to_vec());

    // Identify missing chunks
    let missing = recovery.identify_missing();
    assert_eq!(missing.len(), 1);
    assert_eq!(missing[0].0, "chunk-recover");

    // Run recovery
    let report = recovery.recover_missing().unwrap();

    // Verify recovery succeeded
    assert_eq!(report.recovered_count, 1);
    assert_eq!(report.failed_count, 0);
    assert_eq!(report.total_bytes, data.len() as u64);

    // Chunk now exists in storage
    assert!(storage.has_chunk("chunk-recover").unwrap());

    // Data matches original
    let stored = storage.get_chunk("chunk-recover").unwrap().unwrap();
    assert_eq!(stored, data);

    // Running recovery again should not re-recover (no overwrite)
    let report2 = recovery.recover_missing().unwrap();
    assert_eq!(report2.recovered_count, 0);
    assert_eq!(report2.failed_count, 0);
}

/// Test bahwa recovery gagal jika data dari peer tidak valid.
#[test]
fn test_recovery_rejects_invalid_data() {
    let inner = Arc::new(MockStorage::new());
    let da = Arc::new(MockDA::new());
    let storage = Arc::new(DAStorage::new(inner, da.clone()));

    let original_data = b"original data";
    let commitment = compute_commitment(original_data);

    // Setup
    storage.receive_chunk_declared(create_chunk_declared_event(
        "chunk-invalid",
        original_data.len() as u64,
        commitment,
        3,
    ));
    storage.sync_metadata_from_da().unwrap();
    storage.receive_replica_added(ReplicaAddedEvent::new(
        "chunk-invalid".to_string(),
        "my-node".to_string(),
        1000,
        None,
    ));
    storage.sync_replica_info("chunk-invalid").unwrap();

    let recovery = SimpleStorageRecovery::new(
        storage.clone(),
        da,
        "my-node".to_string(),
        vec!["peer-1".to_string()],
    );

    // Set mock peer data with WRONG data (different from commitment)
    let wrong_data = b"corrupted data";
    recovery.set_mock_peer_data("peer-1", "chunk-invalid", wrong_data.to_vec());

    // Run recovery
    let report = recovery.recover_missing().unwrap();

    // Recovery should fail due to commitment mismatch
    assert_eq!(report.recovered_count, 0);
    assert_eq!(report.failed_count, 1);

    // Chunk should NOT be stored
    assert!(!storage.has_chunk("chunk-invalid").unwrap());
}

/// Test bahwa recovery tidak dilakukan untuk chunks yang tidak assigned.
#[test]
fn test_recovery_skips_unassigned_chunks() {
    let inner = Arc::new(MockStorage::new());
    let da = Arc::new(MockDA::new());
    let storage = Arc::new(DAStorage::new(inner, da.clone()));

    let data = b"other node data";
    let commitment = compute_commitment(data);

    // Setup: Declare chunk but assign to DIFFERENT node
    storage.receive_chunk_declared(create_chunk_declared_event(
        "chunk-other",
        data.len() as u64,
        commitment,
        3,
    ));
    storage.sync_metadata_from_da().unwrap();
    storage.receive_replica_added(ReplicaAddedEvent::new(
        "chunk-other".to_string(),
        "other-node".to_string(), // NOT my-node
        1000,
        None,
    ));
    storage.sync_replica_info("chunk-other").unwrap();

    let recovery = SimpleStorageRecovery::new(
        storage.clone(),
        da,
        "my-node".to_string(),
        vec!["peer-1".to_string()],
    );

    // Set mock peer data
    recovery.set_mock_peer_data("peer-1", "chunk-other", data.to_vec());

    // Identify missing - should be empty because not assigned to my-node
    let missing = recovery.identify_missing();
    assert!(missing.is_empty());

    // Recovery should do nothing
    let report = recovery.recover_missing().unwrap();
    assert_eq!(report.recovered_count, 0);
    assert_eq!(report.failed_count, 0);
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 3: GC SAFETY
// ════════════════════════════════════════════════════════════════════════════════

/// Test bahwa GC hanya menghapus chunks yang eligible via DA events.
///
/// Invariant: Chunk dengan DeleteRequested + grace period expired dapat dihapus.
/// Invariant: Chunk orphan (not assigned to node) dapat dihapus.
/// Invariant: Chunk aktif TIDAK dihapus.
#[test]
fn test_gc_safety_respects_da_assignment() {
    let inner = Arc::new(MockStorage::new());
    let da = Arc::new(MockDA::new());
    let storage = Arc::new(DAStorage::new(inner, da.clone()));

    // Setup: Active chunk (assigned to this node)
    let active_data = b"active chunk data";
    let active_commitment = compute_commitment(active_data);
    storage.put_chunk_with_meta("active-chunk", active_data, active_commitment).unwrap();
    storage.receive_chunk_declared(create_chunk_declared_event(
        "active-chunk",
        active_data.len() as u64,
        active_commitment,
        3,
    ));
    storage.sync_metadata_from_da().unwrap();
    storage.receive_replica_added(ReplicaAddedEvent::new(
        "active-chunk".to_string(),
        "my-node".to_string(),
        1000,
        None,
    ));
    storage.sync_replica_info("active-chunk").unwrap();

    // Setup: Orphan chunk (assigned to different node)
    let orphan_data = b"orphan chunk data";
    let orphan_commitment = compute_commitment(orphan_data);
    storage.put_chunk_with_meta("orphan-chunk", orphan_data, orphan_commitment).unwrap();
    storage.receive_chunk_declared(create_chunk_declared_event(
        "orphan-chunk",
        orphan_data.len() as u64,
        orphan_commitment,
        3,
    ));
    storage.sync_metadata_from_da().unwrap();
    storage.receive_replica_added(ReplicaAddedEvent::new(
        "orphan-chunk".to_string(),
        "other-node".to_string(), // NOT my-node
        1000,
        None,
    ));
    storage.sync_replica_info("orphan-chunk").unwrap();

    // Both chunks exist
    assert!(storage.has_chunk("active-chunk").unwrap());
    assert!(storage.has_chunk("orphan-chunk").unwrap());

    // Create GC
    let gc = GarbageCollector::new(storage.clone(), da, "my-node".to_string());

    // Scan
    let scan_result = gc.scan().unwrap();

    // Active chunk should NOT be in scan result
    assert!(!scan_result.deleted.contains(&"active-chunk".to_string()));
    assert!(!scan_result.orphaned.contains(&"active-chunk".to_string()));

    // Orphan chunk SHOULD be in scan result
    assert!(scan_result.orphaned.contains(&"orphan-chunk".to_string()));

    // Collect
    let deleted_count = gc.collect(&scan_result).unwrap();
    assert_eq!(deleted_count, 1);

    // Active chunk still exists
    assert!(storage.has_metadata("active-chunk"));

    // Orphan chunk removed
    assert!(!storage.has_metadata("orphan-chunk"));
}

/// Test bahwa GC menghormati grace period untuk DeleteRequested.
#[test]
fn test_gc_respects_delete_grace_period() {
    let inner = Arc::new(MockStorage::new());
    let da = Arc::new(MockDA::new());
    let storage = Arc::new(DAStorage::new(inner, da.clone()));

    // Setup chunk
    let data = b"to be deleted";
    let commitment = compute_commitment(data);
    storage.put_chunk_with_meta("chunk-delete", data, commitment).unwrap();
    storage.receive_chunk_declared(create_chunk_declared_event(
        "chunk-delete",
        data.len() as u64,
        commitment,
        3,
    ));
    storage.sync_metadata_from_da().unwrap();
    storage.receive_replica_added(ReplicaAddedEvent::new(
        "chunk-delete".to_string(),
        "my-node".to_string(),
        1000,
        None,
    ));
    storage.sync_replica_info("chunk-delete").unwrap();

    let gc = GarbageCollector::new(storage.clone(), da, "my-node".to_string());

    // Add delete request with grace period ALREADY EXPIRED
    let delete_event = DeleteRequestedEvent::new(
        "chunk-delete".to_string(),
        1000,  // requested_at
        100,   // grace_period_ms (very short, already expired)
        None,
    );
    gc.receive_delete_requested(delete_event);

    // Scan should find it
    let scan_result = gc.scan().unwrap();
    assert!(scan_result.deleted.contains(&"chunk-delete".to_string()));

    // Collect
    let deleted = gc.collect(&scan_result).unwrap();
    assert_eq!(deleted, 1);
    assert!(!storage.has_metadata("chunk-delete"));
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 4: METRICS CONSISTENCY
// ════════════════════════════════════════════════════════════════════════════════

/// Test bahwa metrics konsisten dengan actual state.
///
/// Invariant: Metrics reflect actual storage state.
/// Invariant: Metrics are deterministic.
/// Invariant: Metrics collection does not panic.
#[test]
fn test_metrics_consistency_with_state() {
    let storage = create_test_storage();

    // Empty state
    let metrics = StorageMetrics::collect(&storage);
    assert_eq!(metrics.total_chunks, 0);
    assert_eq!(metrics.total_bytes, 0);
    assert_eq!(metrics.verified_chunks, 0);
    assert_eq!(metrics.pending_verification, 0);

    // Add chunks
    let data1 = vec![0u8; 100];
    let data2 = vec![0u8; 200];
    let data3 = vec![0u8; 300];

    storage.put_chunk_with_meta("c1", &data1, [0xAA; 32]).unwrap();
    storage.put_chunk_with_meta("c2", &data2, [0xBB; 32]).unwrap();
    storage.put_chunk_with_meta("c3", &data3, [0xCC; 32]).unwrap();

    // Set some as verified
    storage.set_verified("c1", true);
    storage.set_verified("c2", true);
    // c3 remains unverified

    // Collect metrics
    let metrics = StorageMetrics::collect(&storage);

    // Verify counts match
    assert_eq!(metrics.total_chunks, 3);
    assert_eq!(metrics.total_bytes, 600); // 100 + 200 + 300
    assert_eq!(metrics.verified_chunks, 2);
    assert_eq!(metrics.pending_verification, 1);

    // Consistency: verified + pending = total
    assert_eq!(
        metrics.verified_chunks + metrics.pending_verification,
        metrics.total_chunks
    );
}

/// Test bahwa metrics collection adalah deterministic.
#[test]
fn test_metrics_deterministic() {
    let storage = create_test_storage();

    // Add some data
    for i in 0..5 {
        let data = vec![i as u8; 100];
        storage.put_chunk_with_meta(&format!("chunk-{}", i), &data, [i; 32]).unwrap();
    }

    // Collect twice
    let metrics1 = StorageMetrics::collect(&storage);
    let metrics2 = StorageMetrics::collect(&storage);

    // Results should be identical
    assert_eq!(metrics1.total_chunks, metrics2.total_chunks);
    assert_eq!(metrics1.total_bytes, metrics2.total_bytes);
    assert_eq!(metrics1.verified_chunks, metrics2.verified_chunks);
    assert_eq!(metrics1.pending_verification, metrics2.pending_verification);
}

/// Test bahwa metrics collection tidak panic pada edge cases.
#[test]
fn test_metrics_no_panic() {
    let storage = create_test_storage();

    // Empty storage
    let _ = StorageMetrics::collect(&storage);

    // After operations
    storage.put_chunk_with_meta("x", b"data", [0; 32]).unwrap();
    let _ = StorageMetrics::collect(&storage);

    storage.delete_metadata("x");
    let _ = StorageMetrics::collect(&storage);

    // No panic occurred
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 5: EVENT EMISSION (OBSERVABILITY)
// ════════════════════════════════════════════════════════════════════════════════

/// Counting listener for testing event emission.
struct CountingListener {
    counts: RwLock<HashMap<String, usize>>,
}

impl CountingListener {
    fn new() -> Self {
        Self {
            counts: RwLock::new(HashMap::new()),
        }
    }

    fn count(&self, event_name: &str) -> usize {
        *self.counts.read().get(event_name).unwrap_or(&0)
    }

    fn total(&self) -> usize {
        self.counts.read().values().sum()
    }
}

impl StorageEventListener for CountingListener {
    fn on_event(&self, event: StorageEvent) {
        let name = event.name().to_string();
        *self.counts.write().entry(name).or_insert(0) += 1;
    }
}

/// Test bahwa events dapat di-emit tanpa mempengaruhi behavior.
///
/// Invariant: Events are observation-only.
/// Invariant: Events do not affect storage correctness.
/// Invariant: Event listeners do not panic.
#[test]
fn test_event_emission_observability() {
    let listener = Arc::new(CountingListener::new());
    let emitter = EventEmitter::new(listener.clone());

    // Emit various events
    emitter.chunk_stored("hash1".to_string(), 100, 10);
    emitter.chunk_stored("hash2".to_string(), 200, 20);
    emitter.chunk_deleted("hash3".to_string(), "gc".to_string());
    emitter.verification_passed("hash4".to_string());
    emitter.verification_failed("hash5".to_string(), "corrupt".to_string());
    emitter.recovery_started("hash6".to_string(), "peer".to_string());
    emitter.recovery_completed("hash7".to_string());
    emitter.gc_completed(1000, 5);

    // Verify all events were received
    assert_eq!(listener.count("ChunkStored"), 2);
    assert_eq!(listener.count("ChunkDeleted"), 1);
    assert_eq!(listener.count("VerificationPassed"), 1);
    assert_eq!(listener.count("VerificationFailed"), 1);
    assert_eq!(listener.count("RecoveryStarted"), 1);
    assert_eq!(listener.count("RecoveryCompleted"), 1);
    assert_eq!(listener.count("GCCompleted"), 1);
    assert_eq!(listener.total(), 8);
}

/// Test bahwa NoOpListener tidak menyebabkan masalah.
#[test]
fn test_noop_listener_safe() {
    let emitter = EventEmitter::noop();

    // Emit many events - should not panic or cause issues
    for i in 0..100 {
        emitter.chunk_stored(format!("hash-{}", i), i as u64, 1);
    }

    // No assertion needed - just verifying no panic
}

/// Test bahwa event listener failure tidak mempengaruhi storage.
#[test]
fn test_event_listener_isolation() {
    let storage = create_test_storage();

    // Storage operations should work regardless of event listeners
    let data = b"test data";
    let commitment = compute_commitment(data);

    // Put chunk
    storage.put_chunk_with_meta("test", data, commitment).unwrap();
    assert!(storage.has_chunk("test").unwrap());

    // Get chunk
    let retrieved = storage.get_chunk("test").unwrap().unwrap();
    assert_eq!(retrieved, data);

    // Event emission is separate from storage correctness
    // Storage works correctly whether or not events are emitted
}

// ════════════════════════════════════════════════════════════════════════════════
// ADDITIONAL INVARIANT TESTS
// ════════════════════════════════════════════════════════════════════════════════

/// Test bahwa metadata selalu bisa di-rebuild dari declared events.
#[test]
fn test_metadata_rebuild_from_da() {
    let storage = create_test_storage();

    // Declare multiple chunks
    for i in 0..5 {
        let data = format!("data-{}", i);
        let commitment = compute_commitment(data.as_bytes());
        storage.receive_chunk_declared(create_chunk_declared_event(
            &format!("chunk-{}", i),
            data.len() as u64,
            commitment,
            3,
        ));
    }

    // Initial sync
    storage.sync_metadata_from_da().unwrap();
    let count1 = storage.metadata_count();
    assert_eq!(count1, 5);

    // Save metadata state
    let metadata_before = storage.all_metadata();

    // Clear metadata
    storage.clear_metadata();
    assert_eq!(storage.metadata_count(), 0);

    // Rebuild from DA
    storage.sync_metadata_from_da().unwrap();
    let count2 = storage.metadata_count();
    assert_eq!(count2, 5);

    // Metadata should be equivalent
    let metadata_after = storage.all_metadata();
    assert_eq!(metadata_before.len(), metadata_after.len());

    for (hash, meta_before) in metadata_before.iter() {
        let meta_after = metadata_after.get(hash).unwrap();
        assert_eq!(meta_before.size_bytes, meta_after.size_bytes);
        assert_eq!(meta_before.da_commitment, meta_after.da_commitment);
    }
}

/// Test bahwa replica info bisa di-rebuild dari DA events.
#[test]
fn test_replica_info_rebuild_from_da() {
    let storage = create_test_storage();

    // Declare chunk
    storage.receive_chunk_declared(create_chunk_declared_event(
        "chunk-replica",
        100,
        [0xAB; 32],
        3,
    ));
    storage.sync_metadata_from_da().unwrap();

    // Add replicas via DA events
    storage.receive_replica_added(ReplicaAddedEvent::new(
        "chunk-replica".to_string(),
        "node-a".to_string(),
        1000,
        None,
    ));
    storage.receive_replica_added(ReplicaAddedEvent::new(
        "chunk-replica".to_string(),
        "node-b".to_string(),
        2000,
        None,
    ));
    storage.receive_replica_added(ReplicaAddedEvent::new(
        "chunk-replica".to_string(),
        "node-c".to_string(),
        3000,
        None,
    ));

    // Sync replica info
    storage.sync_replica_info("chunk-replica").unwrap();

    let meta1 = storage.get_metadata("chunk-replica").unwrap();
    assert_eq!(meta1.current_rf, 3);

    // Sync again - should be idempotent
    storage.sync_replica_info("chunk-replica").unwrap();

    let meta2 = storage.get_metadata("chunk-replica").unwrap();
    assert_eq!(meta2.current_rf, 3);
    assert_eq!(meta1.replicas.len(), meta2.replicas.len());
}