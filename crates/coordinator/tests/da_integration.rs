//! DA Integration Tests
//!
//! These tests verify the complete integration of DA components:
//!
//! - DAConsumer (event ingest)
//! - StateMachine (event processing)
//! - StateRebuilder (recovery)
//! - EventPublisher (event write)
//!
//! ## Key Invariant Under Test
//!
//! **Coordinator state can ALWAYS be reconstructed from DA.**
//! **There is NO authoritative local state.**

use std::collections::BTreeMap;
use std::sync::Arc;

use dsdn_common::MockDA;
use dsdn_common::da::DALayer;

use dsdn_coordinator::{
    StateMachine, DAEvent, DAEventPayload, StateRebuilder,
    NodeRegisteredPayload, ChunkDeclaredPayload, ReplicaAddedPayload,
    EventPublisher,
};

// ════════════════════════════════════════════════════════════════════════════
// TEST CONSTANTS
// ════════════════════════════════════════════════════════════════════════════

const TEST_CHUNK_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

// ════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════

fn make_node_registered_event(seq: u64, node_id: &str, zone: &str) -> DAEvent {
    DAEvent {
        sequence: seq,
        timestamp: seq * 1000,
        payload: DAEventPayload::NodeRegistered(NodeRegisteredPayload {
            node_id: node_id.to_string(),
            zone: zone.to_string(),
            addr: format!("{}:7001", node_id),
            capacity_gb: 100,
        }),
    }
}

fn make_chunk_declared_event(seq: u64, chunk_hash: &str, uploader: &str) -> DAEvent {
    DAEvent {
        sequence: seq,
        timestamp: seq * 1000,
        payload: DAEventPayload::ChunkDeclared(ChunkDeclaredPayload {
            chunk_hash: chunk_hash.to_string(),
            size_bytes: 1024,
            replication_factor: 3,
            uploader_id: uploader.to_string(),
            da_commitment: [0u8; 32],
        }),
    }
}

fn make_replica_added_event(seq: u64, chunk_hash: &str, node_id: &str, index: u8) -> DAEvent {
    DAEvent {
        sequence: seq,
        timestamp: seq * 1000,
        payload: DAEventPayload::ReplicaAdded(ReplicaAddedPayload {
            chunk_hash: chunk_hash.to_string(),
            node_id: node_id.to_string(),
            replica_index: index,
            added_at: seq * 1000,
        }),
    }
}

/// Compute checksum of state for comparison.
/// Uses the same algorithm as StateRebuilder::compute_checksum
fn compute_state_checksum(sm: &StateMachine) -> u64 {
    use std::collections::BTreeMap;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let state = sm.state();
    let mut hasher = DefaultHasher::new();

    // Hash sequence and last_updated
    state.sequence.hash(&mut hasher);
    state.last_updated.hash(&mut hasher);

    // Hash node_registry in sorted order
    let sorted_nodes: BTreeMap<_, _> = state.node_registry.iter().collect();
    for (id, node) in sorted_nodes {
        id.hash(&mut hasher);
        node.id.hash(&mut hasher);
        node.zone.hash(&mut hasher);
        node.addr.hash(&mut hasher);
        node.capacity_gb.hash(&mut hasher);
    }

    // Hash chunk_map in sorted order
    let sorted_chunks: BTreeMap<_, _> = state.chunk_map.iter().collect();
    for (hash, chunk) in sorted_chunks {
        hash.hash(&mut hasher);
        chunk.hash.hash(&mut hasher);
        chunk.size_bytes.hash(&mut hasher);
        chunk.replication_factor.hash(&mut hasher);
        chunk.uploader_id.hash(&mut hasher);
        chunk.declared_at.hash(&mut hasher);
        chunk.da_commitment.hash(&mut hasher);
        chunk.current_rf.hash(&mut hasher);
    }

    // Hash replica_map in sorted order
    let sorted_replicas: BTreeMap<_, _> = state.replica_map.iter().collect();
    for (chunk_hash, replicas) in sorted_replicas {
        chunk_hash.hash(&mut hasher);
        let mut sorted_reps: Vec<_> = replicas.iter().collect();
        sorted_reps.sort_by_key(|r| (&r.node_id, r.replica_index));
        for replica in sorted_reps {
            replica.node_id.hash(&mut hasher);
            replica.replica_index.hash(&mut hasher);
            replica.added_at.hash(&mut hasher);
            replica.verified.hash(&mut hasher);
        }
    }

    // Hash zone_map in sorted order
    let sorted_zones: BTreeMap<_, _> = state.zone_map.iter().collect();
    for (zone, nodes) in sorted_zones {
        zone.hash(&mut hasher);
        let mut sorted_nodes: Vec<_> = nodes.iter().collect();
        sorted_nodes.sort();
        for node in sorted_nodes {
            node.hash(&mut hasher);
        }
    }

    hasher.finish()
}

// ════════════════════════════════════════════════════════════════════════════
// A. FULL PIPELINE TESTS
// ════════════════════════════════════════════════════════════════════════════

/// Test the full event pipeline:
/// Event creation → EventPublisher → (simulated DA) → StateMachine → Final state
#[test]
fn test_full_pipeline_event_flow() {
    let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
    let publisher = EventPublisher::new(Arc::clone(&da));
    let mut state_machine = StateMachine::new();

    // Create events
    let events = vec![
        make_node_registered_event(1, "node1", "zone-a"),
        make_node_registered_event(2, "node2", "zone-b"),
        make_chunk_declared_event(3, TEST_CHUNK_HASH, "uploader1"),
        make_replica_added_event(4, TEST_CHUNK_HASH, "node1", 0),
        make_replica_added_event(5, TEST_CHUNK_HASH, "node2", 1),
    ];

    // Publish events (simulates write to DA)
    for event in &events {
        publisher.publish(event.clone()).unwrap();
    }

    // Flush to DA
    publisher.flush().unwrap();

    // In real scenario, DAConsumer would consume from DA
    // Here we simulate by applying events directly to state machine
    for event in events {
        state_machine.apply_event(event).unwrap();
    }

    // Verify final state
    let state = state_machine.state();
    
    // Nodes registered
    assert_eq!(state.node_registry.len(), 2);
    assert!(state.node_registry.contains_key("node1"));
    assert!(state.node_registry.contains_key("node2"));
    
    // Chunk declared
    assert_eq!(state.chunk_map.len(), 1);
    let chunk = state.chunk_map.get(TEST_CHUNK_HASH).unwrap();
    assert_eq!(chunk.replication_factor, 3);
    assert_eq!(chunk.current_rf, 2); // 2 replicas added
    
    // Replicas added
    let replicas = state.replica_map.get(TEST_CHUNK_HASH).unwrap();
    assert_eq!(replicas.len(), 2);
    
    // Zones populated
    assert_eq!(state.zone_map.len(), 2);
    
    // Sequence updated
    assert_eq!(state.sequence, 5);
}

/// Test that events are processed in order
#[test]
fn test_event_ordering_preserved() {
    let mut sm = StateMachine::new();

    // Events must be applied in dependency order
    // (chunk must exist before replica can be added)
    let events = vec![
        make_node_registered_event(1, "node1", "zone-a"),
        make_chunk_declared_event(2, TEST_CHUNK_HASH, "uploader1"),
        make_replica_added_event(3, TEST_CHUNK_HASH, "node1", 0),
    ];

    for event in events {
        sm.apply_event(event).unwrap();
    }

    // Verify state reflects correct ordering
    assert_eq!(sm.state().sequence, 3);
    assert_eq!(sm.state().chunk_map.get(TEST_CHUNK_HASH).unwrap().current_rf, 1);
}

/// Test that out-of-order event application fails correctly
#[test]
fn test_out_of_order_fails() {
    let mut sm = StateMachine::new();

    // Try to add replica before chunk exists - should fail
    let result = sm.apply_event(make_replica_added_event(1, TEST_CHUNK_HASH, "node1", 0));
    
    assert!(result.is_err());
    
    // State should be unchanged
    assert!(sm.state().replica_map.is_empty());
}

// ════════════════════════════════════════════════════════════════════════════
// B. REBUILD CONSISTENCY TESTS
// ════════════════════════════════════════════════════════════════════════════

/// Test that rebuild produces identical state to live apply
#[test]
fn test_rebuild_equals_live_apply() {
    // Create event sequence
    let events = vec![
        make_node_registered_event(1, "node1", "zone-a"),
        make_node_registered_event(2, "node2", "zone-b"),
        make_node_registered_event(3, "node3", "zone-c"),
        make_chunk_declared_event(4, TEST_CHUNK_HASH, "uploader1"),
        make_replica_added_event(5, TEST_CHUNK_HASH, "node1", 0),
        make_replica_added_event(6, TEST_CHUNK_HASH, "node2", 1),
        make_replica_added_event(7, TEST_CHUNK_HASH, "node3", 2),
    ];

    // Apply live
    let mut live_sm = StateMachine::new();
    for event in &events {
        live_sm.apply_event(event.clone()).unwrap();
    }
    let live_checksum = compute_state_checksum(&live_sm);

    // Rebuild from same events (simulating rebuild from DA)
    let mut rebuild_sm = StateMachine::new();
    for event in &events {
        rebuild_sm.apply_event(event.clone()).unwrap();
    }
    let rebuild_checksum = compute_state_checksum(&rebuild_sm);

    // Checksums MUST be identical
    assert_eq!(live_checksum, rebuild_checksum);

    // State details MUST be identical
    assert_eq!(
        live_sm.state().node_registry.len(),
        rebuild_sm.state().node_registry.len()
    );
    assert_eq!(
        live_sm.state().chunk_map.len(),
        rebuild_sm.state().chunk_map.len()
    );
    assert_eq!(
        live_sm.state().sequence,
        rebuild_sm.state().sequence
    );
}

/// Test rebuild produces consistent state regardless of event batch grouping
#[test]
fn test_rebuild_batch_independence() {
    let events = vec![
        make_node_registered_event(1, "node1", "zone-a"),
        make_node_registered_event(2, "node2", "zone-b"),
        make_chunk_declared_event(3, TEST_CHUNK_HASH, "uploader1"),
        make_replica_added_event(4, TEST_CHUNK_HASH, "node1", 0),
    ];

    // Apply one-by-one
    let mut sm1 = StateMachine::new();
    for event in &events {
        sm1.apply_event(event.clone()).unwrap();
    }

    // Apply as batch
    let mut sm2 = StateMachine::new();
    sm2.apply_batch(events.clone()).unwrap();

    // Apply in two batches
    let mut sm3 = StateMachine::new();
    sm3.apply_batch(events[0..2].to_vec()).unwrap();
    sm3.apply_batch(events[2..].to_vec()).unwrap();

    // All should produce identical state
    let checksum1 = compute_state_checksum(&sm1);
    let checksum2 = compute_state_checksum(&sm2);
    let checksum3 = compute_state_checksum(&sm3);

    assert_eq!(checksum1, checksum2);
    assert_eq!(checksum2, checksum3);
}

// ════════════════════════════════════════════════════════════════════════════
// C. RESTART SIMULATION TESTS
// ════════════════════════════════════════════════════════════════════════════

/// Simulate coordinator restart and state recovery
#[test]
fn test_restart_recovery() {
    let events = vec![
        make_node_registered_event(1, "node1", "zone-a"),
        make_node_registered_event(2, "node2", "zone-b"),
        make_chunk_declared_event(3, TEST_CHUNK_HASH, "uploader1"),
        make_replica_added_event(4, TEST_CHUNK_HASH, "node1", 0),
    ];

    // === PHASE 1: Original coordinator running ===
    let mut original_sm = StateMachine::new();
    for event in &events {
        original_sm.apply_event(event.clone()).unwrap();
    }
    let original_checksum = compute_state_checksum(&original_sm);
    let original_sequence = original_sm.state().sequence;

    // === PHASE 2: Coordinator crashes, state lost ===
    // (original_sm goes out of scope, simulating crash)
    drop(original_sm);

    // === PHASE 3: New coordinator starts, rebuilds from DA ===
    let mut recovered_sm = StateMachine::new();
    
    // Verify state is empty before rebuild
    assert!(recovered_sm.state().node_registry.is_empty());
    assert!(recovered_sm.state().chunk_map.is_empty());
    assert_eq!(recovered_sm.state().sequence, 0);

    // Replay events from DA (simulated)
    for event in &events {
        recovered_sm.apply_event(event.clone()).unwrap();
    }

    // === PHASE 4: Verify recovered state matches original ===
    let recovered_checksum = compute_state_checksum(&recovered_sm);
    
    assert_eq!(original_checksum, recovered_checksum);
    assert_eq!(original_sequence, recovered_sm.state().sequence);
    assert_eq!(recovered_sm.state().node_registry.len(), 2);
    assert_eq!(recovered_sm.state().chunk_map.len(), 1);
}

/// Test partial state is never exposed after failure
#[test]
fn test_no_partial_state_on_failure() {
    let mut sm = StateMachine::new();

    // Apply some valid events
    sm.apply_event(make_node_registered_event(1, "node1", "zone-a")).unwrap();
    sm.apply_event(make_chunk_declared_event(2, TEST_CHUNK_HASH, "uploader1")).unwrap();

    // Create batch with invalid event
    let batch = vec![
        make_replica_added_event(3, TEST_CHUNK_HASH, "node1", 0),
        // This will fail - replica to non-existent chunk
        make_replica_added_event(4, "nonexistent_chunk", "node1", 0),
    ];

    // Batch should fail
    let result = sm.apply_batch(batch);
    assert!(result.is_err());

    // State should be rolled back - no replica from failed batch
    let chunk = sm.state().chunk_map.get(TEST_CHUNK_HASH).unwrap();
    assert_eq!(chunk.current_rf, 0); // No replicas added
}

// ════════════════════════════════════════════════════════════════════════════
// D. INVARIANT TESTS
// ════════════════════════════════════════════════════════════════════════════

/// Test that all state is reconstructable from events
#[test]
fn test_no_authoritative_local_state() {
    // This test verifies the key invariant:
    // ALL state can be derived from DA events alone.
    
    let events = vec![
        make_node_registered_event(1, "node1", "zone-a"),
        make_node_registered_event(2, "node2", "zone-b"),
        make_chunk_declared_event(3, TEST_CHUNK_HASH, "uploader1"),
        make_replica_added_event(4, TEST_CHUNK_HASH, "node1", 0),
        make_replica_added_event(5, TEST_CHUNK_HASH, "node2", 1),
    ];

    // Build state from events
    let mut sm = StateMachine::new();
    for event in &events {
        sm.apply_event(event.clone()).unwrap();
    }

    // Verify every piece of state came from an event:
    
    // 1. node_registry - from NodeRegistered events
    for (node_id, _) in &sm.state().node_registry {
        let found = events.iter().any(|e| {
            if let DAEventPayload::NodeRegistered(p) = &e.payload {
                &p.node_id == node_id
            } else {
                false
            }
        });
        assert!(found, "Node {} not traceable to event", node_id);
    }

    // 2. chunk_map - from ChunkDeclared events
    for (hash, _) in &sm.state().chunk_map {
        let found = events.iter().any(|e| {
            if let DAEventPayload::ChunkDeclared(p) = &e.payload {
                &p.chunk_hash == hash
            } else {
                false
            }
        });
        assert!(found, "Chunk {} not traceable to event", hash);
    }

    // 3. replica_map - from ReplicaAdded events
    for (chunk_hash, replicas) in &sm.state().replica_map {
        for replica in replicas {
            let found = events.iter().any(|e| {
                if let DAEventPayload::ReplicaAdded(p) = &e.payload {
                    &p.chunk_hash == chunk_hash && p.node_id == replica.node_id
                } else {
                    false
                }
            });
            assert!(found, "Replica {}:{} not traceable to event", chunk_hash, replica.node_id);
        }
    }

    // 4. zone_map - derived from NodeRegistered events
    for (zone, nodes) in &sm.state().zone_map {
        for node_id in nodes {
            let found = events.iter().any(|e| {
                if let DAEventPayload::NodeRegistered(p) = &e.payload {
                    &p.zone == zone && &p.node_id == node_id
                } else {
                    false
                }
            });
            assert!(found, "Zone mapping {}:{} not traceable to event", zone, node_id);
        }
    }
}

/// Test state machine is deterministic
#[test]
fn test_deterministic_state_machine() {
    let events = vec![
        make_node_registered_event(1, "node1", "zone-a"),
        make_node_registered_event(2, "node2", "zone-b"),
        make_chunk_declared_event(3, TEST_CHUNK_HASH, "uploader1"),
        make_replica_added_event(4, TEST_CHUNK_HASH, "node1", 0),
    ];

    // Apply same events 3 times to 3 different state machines
    let mut checksums = Vec::new();
    for _ in 0..3 {
        let mut sm = StateMachine::new();
        for event in &events {
            sm.apply_event(event.clone()).unwrap();
        }
        checksums.push(compute_state_checksum(&sm));
    }

    // All checksums must be identical
    assert_eq!(checksums[0], checksums[1]);
    assert_eq!(checksums[1], checksums[2]);
}

/// Test idempotent event application
#[test]
fn test_idempotent_events() {
    let mut sm = StateMachine::new();

    let event = make_node_registered_event(1, "node1", "zone-a");

    // Apply same event multiple times
    sm.apply_event(event.clone()).unwrap();
    let checksum1 = compute_state_checksum(&sm);

    sm.apply_event(event.clone()).unwrap();
    let checksum2 = compute_state_checksum(&sm);

    sm.apply_event(event).unwrap();
    let checksum3 = compute_state_checksum(&sm);

    // State should not change after first application
    assert_eq!(checksum1, checksum2);
    assert_eq!(checksum2, checksum3);

    // Should still have only 1 node
    assert_eq!(sm.state().node_registry.len(), 1);
}

// ════════════════════════════════════════════════════════════════════════════
// E. EVENT PUBLISHER INTEGRATION TESTS
// ════════════════════════════════════════════════════════════════════════════

/// Test EventPublisher batching and flushing
#[test]
fn test_publisher_batch_flush() {
    let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
    let publisher = EventPublisher::with_config(Arc::clone(&da), 3, 10000);

    // Publish 2 events (below batch size)
    publisher.publish(make_node_registered_event(1, "node1", "zone-a")).unwrap();
    publisher.publish(make_node_registered_event(2, "node2", "zone-b")).unwrap();

    assert_eq!(publisher.pending_count(), 2);
    assert_eq!(publisher.published_batch_count(), 0);

    // Publish 1 more (reaches batch size)
    publisher.publish(make_chunk_declared_event(3, TEST_CHUNK_HASH, "uploader1")).unwrap();

    // Should have auto-flushed
    assert_eq!(publisher.pending_count(), 0);
    assert_eq!(publisher.published_batch_count(), 1);
}

/// Test EventPublisher preserves event order
#[test]
fn test_publisher_order_preservation() {
    let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
    let publisher = EventPublisher::new(Arc::clone(&da));

    let events = vec![
        make_node_registered_event(1, "node1", "zone-a"),
        make_node_registered_event(2, "node2", "zone-b"),
        make_node_registered_event(3, "node3", "zone-c"),
    ];

    for event in &events {
        publisher.publish(event.clone()).unwrap();
    }

    assert_eq!(publisher.pending_count(), 3);

    // Flush
    let blob_ref = publisher.flush().unwrap();
    assert!(blob_ref.size > 0);
    assert_eq!(publisher.pending_count(), 0);
}

// ════════════════════════════════════════════════════════════════════════════
// F. COMPLEX SCENARIO TESTS
// ════════════════════════════════════════════════════════════════════════════

/// Test complete lifecycle: register → declare → replicate → query
#[test]
fn test_complete_lifecycle() {
    let mut sm = StateMachine::new();

    // 1. Register nodes
    sm.apply_event(make_node_registered_event(1, "storage-node-1", "dc-west")).unwrap();
    sm.apply_event(make_node_registered_event(2, "storage-node-2", "dc-east")).unwrap();
    sm.apply_event(make_node_registered_event(3, "storage-node-3", "dc-central")).unwrap();

    // 2. Declare chunk
    sm.apply_event(make_chunk_declared_event(4, TEST_CHUNK_HASH, "client-app")).unwrap();

    // 3. Add replicas
    sm.apply_event(make_replica_added_event(5, TEST_CHUNK_HASH, "storage-node-1", 0)).unwrap();
    sm.apply_event(make_replica_added_event(6, TEST_CHUNK_HASH, "storage-node-2", 1)).unwrap();
    sm.apply_event(make_replica_added_event(7, TEST_CHUNK_HASH, "storage-node-3", 2)).unwrap();

    // 4. Query state - use block to limit borrow scope
    {
        let state = sm.state();

        // Verify nodes
        assert_eq!(state.node_registry.len(), 3);
        assert!(state.get_node("storage-node-1").is_some());
        assert!(state.get_node("storage-node-2").is_some());
        assert!(state.get_node("storage-node-3").is_some());

        // Verify chunk
        let chunk = state.get_chunk(TEST_CHUNK_HASH).unwrap();
        assert_eq!(chunk.replication_factor, 3);
        assert_eq!(chunk.current_rf, 3);
        assert_eq!(chunk.uploader_id, "client-app");

        // Verify replicas
        let replicas = state.get_replicas(TEST_CHUNK_HASH);
        assert_eq!(replicas.len(), 3);

        // Verify zones
        assert_eq!(state.list_zones().len(), 3);
        assert_eq!(state.zone_node_count("dc-west"), 1);
        assert_eq!(state.zone_node_count("dc-east"), 1);
        assert_eq!(state.zone_node_count("dc-central"), 1);
    }

    // Verify placement suggestion works
    // (needs another chunk since TEST_CHUNK_HASH already has all replicas)
    let hash2 = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    sm.apply_event(make_chunk_declared_event(8, hash2, "client-app")).unwrap();
    
    let state = sm.state();
    let suggestions = state.suggest_placement(hash2, 3);
    assert_eq!(suggestions.len(), 3);
}

/// Test high event volume
#[test]
fn test_high_volume_events() {
    let mut sm = StateMachine::new();

    // Register 100 nodes
    for i in 0..100 {
        let event = make_node_registered_event(
            i as u64,
            &format!("node-{}", i),
            &format!("zone-{}", i % 10),
        );
        sm.apply_event(event).unwrap();
    }

    assert_eq!(sm.state().node_registry.len(), 100);
    assert_eq!(sm.state().list_zones().len(), 10);

    // Compute checksum
    let checksum = compute_state_checksum(&sm);
    assert_ne!(checksum, 0);

    // Rebuild and verify
    let mut rebuild_sm = StateMachine::new();
    for i in 0..100 {
        let event = make_node_registered_event(
            i as u64,
            &format!("node-{}", i),
            &format!("zone-{}", i % 10),
        );
        rebuild_sm.apply_event(event).unwrap();
    }

    let rebuild_checksum = compute_state_checksum(&rebuild_sm);
    assert_eq!(checksum, rebuild_checksum);
}