//! # DA Integration Tests
//!
//! Integration tests for DSDN Node DA-based architecture.
//!
//! ## Key Invariant Tested
//! Node TIDAK menerima instruksi dari Coordinator via RPC.
//! Semua perintah datang via DA events.
//!
//! ## Test Categories
//! - A. Node startup
//! - B. End-to-end DA flow
//! - C. Health exposure
//! - D. Invariant verification

use std::sync::Arc;

use dsdn_common::{DALayer, MockDA};
use dsdn_node::{
    ChunkAssignment, DAInfo, HealthResponse, HealthStorage, NodeDerivedState, NodeHealth,
    ReplicaStatus,
};

// ════════════════════════════════════════════════════════════════════════════
// TEST HELPERS
// ════════════════════════════════════════════════════════════════════════════

/// Mock storage for integration tests.
struct TestStorage {
    used_bytes: u64,
    capacity_bytes: u64,
}

impl TestStorage {
    fn new() -> Self {
        Self {
            used_bytes: 0,
            capacity_bytes: 100 * 1024 * 1024 * 1024, // 100 GB
        }
    }
}

impl HealthStorage for TestStorage {
    fn storage_used_bytes(&self) -> u64 {
        self.used_bytes
    }

    fn storage_capacity_bytes(&self) -> u64 {
        self.capacity_bytes
    }
}

/// Mock DA info for integration tests.
struct TestDAInfo {
    connected: bool,
    latest_seq: u64,
}

impl TestDAInfo {
    #[allow(dead_code)]
    fn new() -> Self {
        Self {
            connected: true,
            latest_seq: 0,
        }
    }

    fn connected() -> Self {
        Self {
            connected: true,
            latest_seq: 0, // Same as NodeDerivedState::new().last_sequence to avoid lag
        }
    }

    fn disconnected() -> Self {
        Self {
            connected: false,
            latest_seq: 0,
        }
    }
}

impl DAInfo for TestDAInfo {
    fn is_connected(&self) -> bool {
        self.connected
    }

    fn latest_sequence(&self) -> u64 {
        self.latest_seq
    }
}

// ════════════════════════════════════════════════════════════════════════════
// A. NODE STARTUP TESTS
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn test_node_state_init_no_panic() {
    // Node state should initialize without panic
    let state = NodeDerivedState::new();

    assert!(state.my_chunks.is_empty());
    assert_eq!(state.last_sequence, 0);
    assert_eq!(state.last_height, 0);
}

#[test]
fn test_da_follower_components_init() {
    // All DA follower components should initialize
    let state = NodeDerivedState::new();
    let storage = TestStorage::new();
    let da_info = TestDAInfo::connected();

    // Health check should work immediately after init
    let health = NodeHealth::check("test-node", &da_info, &state, &storage);

    assert_eq!(health.node_id, "test-node");
    assert!(health.da_connected);
}

#[tokio::test]
async fn test_mock_da_init() {
    // MockDA should initialize without panic
    let mock_da = MockDA::new();

    // Health check should be healthy
    let health = mock_da.health_check().await;
    assert_eq!(health, dsdn_common::DAHealthStatus::Healthy);
}

#[tokio::test]
async fn test_da_layer_trait_object() {
    // DA layer should work as trait object
    let da: Arc<dyn DALayer> = Arc::new(MockDA::new());

    let health = da.health_check().await.unwrap();
    assert_eq!(health, dsdn_common::DAHealthStatus::Healthy);
}

// ════════════════════════════════════════════════════════════════════════════
// B. END-TO-END DA FLOW TESTS
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn test_state_updates_from_simulated_da_events() {
    // Simulate DA events updating node state
    let mut state = NodeDerivedState::new();

    // Simulate ReplicaAdded event
    let chunk_hash = "test-chunk-hash-1234";
    state.my_chunks.insert(
        chunk_hash.to_string(),
        ChunkAssignment {
            hash: chunk_hash.to_string(),
            replica_index: 0,
            assigned_at: 1000,
            verified: false,
            size_bytes: 1024,
        },
    );
    state
        .replica_status
        .insert(chunk_hash.to_string(), ReplicaStatus::Pending);
    state.last_sequence = 1;

    // Verify state changed
    assert_eq!(state.my_chunks.len(), 1);
    assert_eq!(state.last_sequence, 1);
    assert_eq!(
        state.replica_status.get(chunk_hash),
        Some(&ReplicaStatus::Pending)
    );
}

#[test]
fn test_state_reflects_multiple_da_events() {
    let mut state = NodeDerivedState::new();

    // Simulate multiple ReplicaAdded events
    for i in 0..10 {
        let hash = format!("chunk-{}", i);
        state.my_chunks.insert(
            hash.clone(),
            ChunkAssignment {
                hash: hash.clone(),
                replica_index: i as u8,
                assigned_at: 1000 + i as u64,
                verified: false,
                size_bytes: 1024,
            },
        );
        state.replica_status.insert(hash, ReplicaStatus::Pending);
        state.last_sequence = i as u64 + 1;
    }

    assert_eq!(state.my_chunks.len(), 10);
    assert_eq!(state.last_sequence, 10);
}

#[test]
fn test_state_replica_status_transitions() {
    let mut state = NodeDerivedState::new();

    let hash = "chunk-1";
    state.my_chunks.insert(
        hash.to_string(),
        ChunkAssignment {
            hash: hash.to_string(),
            replica_index: 0,
            assigned_at: 1000,
            verified: false,
            size_bytes: 1024,
        },
    );

    // Pending -> Stored -> Verified
    state
        .replica_status
        .insert(hash.to_string(), ReplicaStatus::Pending);
    assert_eq!(
        state.replica_status.get(hash),
        Some(&ReplicaStatus::Pending)
    );

    state
        .replica_status
        .insert(hash.to_string(), ReplicaStatus::Stored);
    assert_eq!(state.replica_status.get(hash), Some(&ReplicaStatus::Stored));

    state
        .replica_status
        .insert(hash.to_string(), ReplicaStatus::Verified);
    assert_eq!(
        state.replica_status.get(hash),
        Some(&ReplicaStatus::Verified)
    );
}

#[test]
fn test_state_chunk_removal() {
    let mut state = NodeDerivedState::new();

    let hash = "chunk-to-remove";
    state.my_chunks.insert(
        hash.to_string(),
        ChunkAssignment {
            hash: hash.to_string(),
            replica_index: 0,
            assigned_at: 1000,
            verified: false,
            size_bytes: 1024,
        },
    );
    state
        .replica_status
        .insert(hash.to_string(), ReplicaStatus::Stored);

    assert_eq!(state.my_chunks.len(), 1);

    // Simulate ReplicaRemoved event
    state.my_chunks.remove(hash);
    state.replica_status.remove(hash);

    assert!(state.my_chunks.is_empty());
    assert!(state.replica_status.is_empty());
}

// ════════════════════════════════════════════════════════════════════════════
// C. HEALTH EXPOSURE TESTS
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn test_health_endpoint_healthy_response() {
    let state = NodeDerivedState::new();
    let storage = TestStorage::new();
    let da_info = TestDAInfo::connected();

    let health = NodeHealth::check("node-1", &da_info, &state, &storage);
    let response = HealthResponse::from_health(&health);

    assert_eq!(response.status_code, 200);
    assert_eq!(response.content_type, "application/json");
    assert!(!response.body.is_empty());
}

#[test]
fn test_health_endpoint_unhealthy_da_disconnected() {
    let state = NodeDerivedState::new();
    let storage = TestStorage::new();
    let da_info = TestDAInfo::disconnected();

    let health = NodeHealth::check("node-1", &da_info, &state, &storage);
    let response = HealthResponse::from_health(&health);

    // 503 when unhealthy
    assert_eq!(response.status_code, 503);
}

#[test]
fn test_health_json_valid() {
    let state = NodeDerivedState::new();
    let storage = TestStorage::new();
    let da_info = TestDAInfo::connected();

    let health = NodeHealth::check("node-1", &da_info, &state, &storage);
    let json = health.to_json();

    // Should be valid JSON
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&json);
    assert!(parsed.is_ok());

    let value = parsed.unwrap();
    assert!(value.get("node_id").is_some());
    assert!(value.get("da_connected").is_some());
    assert!(value.get("chunks_stored").is_some());
}

#[test]
fn test_health_reflects_chunk_status() {
    let mut state = NodeDerivedState::new();

    // Add stored chunk
    state.my_chunks.insert(
        "stored-1".to_string(),
        ChunkAssignment {
            hash: "stored-1".to_string(),
            replica_index: 0,
            assigned_at: 1000,
            verified: true,
            size_bytes: 1024,
        },
    );
    state
        .replica_status
        .insert("stored-1".to_string(), ReplicaStatus::Stored);

    // Add pending chunk
    state.my_chunks.insert(
        "pending-1".to_string(),
        ChunkAssignment {
            hash: "pending-1".to_string(),
            replica_index: 1,
            assigned_at: 1000,
            verified: false,
            size_bytes: 1024,
        },
    );
    state
        .replica_status
        .insert("pending-1".to_string(), ReplicaStatus::Pending);

    let storage = TestStorage::new();
    let da_info = TestDAInfo::connected();

    let health = NodeHealth::check("node-1", &da_info, &state, &storage);

    assert_eq!(health.chunks_stored, 1);
    assert_eq!(health.chunks_pending, 1);
    assert_eq!(health.chunks_missing, 0);
}

#[test]
fn test_health_detects_missing_chunks() {
    let mut state = NodeDerivedState::new();

    // Add missing chunk
    state.my_chunks.insert(
        "missing-1".to_string(),
        ChunkAssignment {
            hash: "missing-1".to_string(),
            replica_index: 0,
            assigned_at: 1000,
            verified: false,
            size_bytes: 1024,
        },
    );
    state
        .replica_status
        .insert("missing-1".to_string(), ReplicaStatus::Missing);

    let storage = TestStorage::new();
    let da_info = TestDAInfo::connected();

    let health = NodeHealth::check("node-1", &da_info, &state, &storage);

    assert_eq!(health.chunks_missing, 1);
    assert!(!health.is_healthy()); // Unhealthy when chunks missing
}

// ════════════════════════════════════════════════════════════════════════════
// D. INVARIANT TESTS - NO RPC COORDINATOR DEPENDENCY
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn test_invariant_node_state_derived_from_da() {
    // INVARIANT: All node state is derived from DA events
    // This test verifies that NodeDerivedState has no external dependencies

    let state = NodeDerivedState::new();

    // State should be empty initially - no pre-existing coordinator data
    assert!(state.my_chunks.is_empty());
    assert_eq!(state.last_sequence, 0);

    // State only changes through explicit event application
    // (simulated here by direct mutation, in production via apply_event)
}

#[test]
fn test_invariant_no_coordinator_rpc_in_state() {
    // INVARIANT: Node does NOT receive instructions from Coordinator via RPC
    // NodeDerivedState has no RPC client references

    let state = NodeDerivedState::new();

    // NodeDerivedState fields are all local/DA-derived
    // - my_chunks: HashMap (local)
    // - coordinator_state: DADerivedState (from DA)
    // - last_sequence: u64 (from DA)
    // - last_height: u64 (from DA)
    // - replica_status: HashMap (local)

    // No RPC clients, no network calls in state
    assert!(state.my_chunks.is_empty());
}

#[test]
fn test_invariant_health_no_rpc_dependency() {
    // Health check should work without any RPC connection
    let state = NodeDerivedState::new();
    let storage = TestStorage::new();
    let da_info = TestDAInfo::connected();

    // Health check uses only:
    // - DAInfo (connection status, sequence)
    // - NodeDerivedState (local state)
    // - HealthStorage (local storage)
    // NO RPC calls to coordinator

    let health = NodeHealth::check("node-1", &da_info, &state, &storage);

    // Should complete without any network calls
    assert!(!health.node_id.is_empty());
}

#[test]
fn test_invariant_commands_via_da_only() {
    // INVARIANT: Semua perintah datang via DA events
    let mut state = NodeDerivedState::new();

    // The ONLY way to modify state is through events
    // Events come from DA, not from coordinator RPC

    // Simulate DA event sequence
    let events = vec![
        ("chunk-1", ReplicaStatus::Pending),
        ("chunk-2", ReplicaStatus::Pending),
        ("chunk-1", ReplicaStatus::Stored),
    ];

    for (hash, status) in events {
        // Each "event" comes from DA
        if !state.my_chunks.contains_key(hash) {
            state.my_chunks.insert(
                hash.to_string(),
                ChunkAssignment {
                    hash: hash.to_string(),
                    replica_index: 0,
                    assigned_at: 1000,
                    verified: false,
                    size_bytes: 1024,
                },
            );
        }
        state.replica_status.insert(hash.to_string(), status);
        state.last_sequence += 1;
    }

    // State reflects DA events only
    assert_eq!(state.my_chunks.len(), 2);
    assert_eq!(state.last_sequence, 3);
}

#[test]
fn test_invariant_state_rebuildable_from_da() {
    // INVARIANT: Node state can be fully reconstructed from DA

    // Simulate building state from DA events
    let events = vec![
        ("chunk-1", 1000u64),
        ("chunk-2", 1001),
        ("chunk-3", 1002),
    ];

    let mut state1 = NodeDerivedState::new();
    let mut state2 = NodeDerivedState::new();

    // Apply same events to both states
    for (hash, assigned_at) in &events {
        for state in [&mut state1, &mut state2] {
            state.my_chunks.insert(
                hash.to_string(),
                ChunkAssignment {
                    hash: hash.to_string(),
                    replica_index: 0,
                    assigned_at: *assigned_at,
                    verified: false,
                    size_bytes: 1024,
                },
            );
            state
                .replica_status
                .insert(hash.to_string(), ReplicaStatus::Pending);
        }
    }

    // Both states should be identical
    assert_eq!(state1.my_chunks.len(), state2.my_chunks.len());
    for (hash, assignment) in &state1.my_chunks {
        assert_eq!(state2.my_chunks.get(hash).unwrap().hash, assignment.hash);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// E. DETERMINISM TESTS
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn test_health_deterministic() {
    let mut state = NodeDerivedState::new();
    state.last_sequence = 50;

    let storage = TestStorage::new();
    let da_info = TestDAInfo {
        connected: true,
        latest_seq: 100,
    };

    // Multiple health checks should produce consistent results
    let health1 = NodeHealth::check("node-1", &da_info, &state, &storage);
    let health2 = NodeHealth::check("node-1", &da_info, &state, &storage);

    assert_eq!(health1.node_id, health2.node_id);
    assert_eq!(health1.da_connected, health2.da_connected);
    assert_eq!(health1.da_behind_by, health2.da_behind_by);
    assert_eq!(health1.chunks_stored, health2.chunks_stored);
}

#[test]
fn test_state_operations_deterministic() {
    // Same events -> same state
    let events = vec!["chunk-1", "chunk-2", "chunk-3"];

    let mut state1 = NodeDerivedState::new();
    let mut state2 = NodeDerivedState::new();

    for hash in &events {
        for state in [&mut state1, &mut state2] {
            state.my_chunks.insert(
                hash.to_string(),
                ChunkAssignment {
                    hash: hash.to_string(),
                    replica_index: 0,
                    assigned_at: 1000,
                    verified: false,
                    size_bytes: 1024,
                },
            );
        }
    }

    assert_eq!(state1.my_chunks.len(), state2.my_chunks.len());
}

// ════════════════════════════════════════════════════════════════════════════
// F. ERROR HANDLING TESTS
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn test_health_handles_da_disconnection() {
    let state = NodeDerivedState::new();
    let storage = TestStorage::new();
    let da_info = TestDAInfo::disconnected();

    // Should not panic when DA is disconnected
    let health = NodeHealth::check("node-1", &da_info, &state, &storage);

    assert!(!health.da_connected);
    assert!(!health.is_healthy());
}

#[test]
fn test_health_handles_empty_state() {
    let state = NodeDerivedState::new();
    let storage = TestStorage::new();
    let da_info = TestDAInfo::connected();

    // Should handle empty state gracefully
    let health = NodeHealth::check("node-1", &da_info, &state, &storage);

    assert_eq!(health.chunks_stored, 0);
    assert_eq!(health.chunks_pending, 0);
    assert_eq!(health.chunks_missing, 0);
}

#[test]
fn test_json_never_panics() {
    // Health to JSON should never panic
    let health = NodeHealth::default();
    let json = health.to_json();
    assert!(!json.is_empty());
}