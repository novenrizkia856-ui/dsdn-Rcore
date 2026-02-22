//! Integration tests for DSDN Proto Crate
//!
//! Tests end-to-end event lifecycle, batch encoding, and error handling.

use dsdn_proto::da_event::{DAEvent, ReplicaRemovalReason, DeleteReason};
use dsdn_proto::da_health::DAError;
use dsdn_proto::{encode_event, decode_event, compute_event_hash, batch_encode, batch_decode};
use dsdn_proto::PROTO_VERSION;

// ============================================================================
// Full Event Lifecycle Tests
// ============================================================================

#[test]
fn test_lifecycle_node_registered() {
    // Step 1: Create event
    let original = DAEvent::NodeRegistered {
        version: 1,
        timestamp_ms: 1704067200000,
        node_id: "node-lifecycle-001".to_string(),
        zone: "id-jakarta-1".to_string(),
        addr: "192.168.1.100:9000".to_string(),
        capacity_gb: 1000,
    };

    // Step 2: Encode event
    let encoded = encode_event(&original);
    assert!(!encoded.is_empty(), "encoded bytes must not be empty");

    // Step 3: Compute hash
    let hash = compute_event_hash(&original);
    assert_eq!(hash.len(), 32, "hash must be 32 bytes");

    // Step 4: Decode event
    let decoded = decode_event(&encoded).expect("decode must succeed");

    // Step 5: Verify equality
    assert_eq!(original, decoded, "decoded event must equal original");

    // Step 6: Verify hash stability
    let hash_after_decode = compute_event_hash(&decoded);
    assert_eq!(hash, hash_after_decode, "hash must be stable after decode");
}

#[test]
fn test_lifecycle_chunk_declared() {
    let original = DAEvent::ChunkDeclared {
        version: 1,
        timestamp_ms: 1704067200000,
        chunk_hash: "abcdef1234567890abcdef1234567890".to_string(),
        size_bytes: 1048576,
        uploader_id: "uploader-lifecycle".to_string(),
        replication_factor: 3,
    };

    let encoded = encode_event(&original);
    let hash = compute_event_hash(&original);
    let decoded = decode_event(&encoded).expect("decode must succeed");

    assert_eq!(original, decoded, "decoded event must equal original");
    assert_eq!(hash, compute_event_hash(&decoded), "hash must be stable");
}

#[test]
fn test_lifecycle_replica_added() {
    let original = DAEvent::ReplicaAdded {
        version: 1,
        timestamp_ms: 1704067200000,
        chunk_hash: "chunk-lifecycle-001".to_string(),
        node_id: "node-replica-001".to_string(),
        replica_index: 0,
    };

    let encoded = encode_event(&original);
    let hash = compute_event_hash(&original);
    let decoded = decode_event(&encoded).expect("decode must succeed");

    assert_eq!(original, decoded, "decoded event must equal original");
    assert_eq!(hash, compute_event_hash(&decoded), "hash must be stable");
}

#[test]
fn test_lifecycle_replica_removed() {
    let original = DAEvent::ReplicaRemoved {
        version: 1,
        timestamp_ms: 1704067200000,
        chunk_hash: "chunk-removed-001".to_string(),
        node_id: "node-removed-001".to_string(),
        reason: ReplicaRemovalReason::NodeOffline,
    };

    let encoded = encode_event(&original);
    let hash = compute_event_hash(&original);
    let decoded = decode_event(&encoded).expect("decode must succeed");

    assert_eq!(original, decoded, "decoded event must equal original");
    assert_eq!(hash, compute_event_hash(&decoded), "hash must be stable");
}

#[test]
fn test_lifecycle_delete_requested() {
    let original = DAEvent::DeleteRequested {
        version: 1,
        timestamp_ms: 1704067200000,
        chunk_hash: "chunk-delete-001".to_string(),
        requester_id: "user-delete-001".to_string(),
        reason: DeleteReason::UserRequest,
    };

    let encoded = encode_event(&original);
    let hash = compute_event_hash(&original);
    let decoded = decode_event(&encoded).expect("decode must succeed");

    assert_eq!(original, decoded, "decoded event must equal original");
    assert_eq!(hash, compute_event_hash(&decoded), "hash must be stable");
}

#[test]
fn test_lifecycle_all_replica_removal_reasons() {
    let reasons = vec![
        ReplicaRemovalReason::NodeOffline,
        ReplicaRemovalReason::Rebalance,
        ReplicaRemovalReason::Corruption,
        ReplicaRemovalReason::Manual,
    ];

    for reason in reasons {
        let original = DAEvent::ReplicaRemoved {
            version: 1,
            timestamp_ms: 1704067200000,
            chunk_hash: "chunk-reason-test".to_string(),
            node_id: "node-reason-test".to_string(),
            reason: reason.clone(),
        };

        let encoded = encode_event(&original);
        let decoded = decode_event(&encoded).expect("decode must succeed");

        match &decoded {
            DAEvent::ReplicaRemoved { reason: decoded_reason, .. } => {
                assert_eq!(&reason, decoded_reason, "reason must match");
            }
            _ => panic!("decoded event must be ReplicaRemoved"),
        }
    }
}

#[test]
fn test_lifecycle_all_delete_reasons() {
    let reasons = vec![
        DeleteReason::UserRequest,
        DeleteReason::Expired,
        DeleteReason::Governance,
        DeleteReason::Compliance,
    ];

    for reason in reasons {
        let original = DAEvent::DeleteRequested {
            version: 1,
            timestamp_ms: 1704067200000,
            chunk_hash: "chunk-delete-reason".to_string(),
            requester_id: "requester-reason".to_string(),
            reason: reason.clone(),
        };

        let encoded = encode_event(&original);
        let decoded = decode_event(&encoded).expect("decode must succeed");

        match &decoded {
            DAEvent::DeleteRequested { reason: decoded_reason, .. } => {
                assert_eq!(&reason, decoded_reason, "reason must match");
            }
            _ => panic!("decoded event must be DeleteRequested"),
        }
    }
}

// ============================================================================
// Cross-Version Compatibility Tests
// ============================================================================

#[test]
fn test_version_field_preserved() {
    let event = DAEvent::NodeRegistered {
        version: 1,
        timestamp_ms: 1704067200000,
        node_id: "node-version-test".to_string(),
        zone: "zone-1".to_string(),
        addr: "127.0.0.1:45831".to_string(),
        capacity_gb: 100,
    };

    let encoded = encode_event(&event);
    let decoded = decode_event(&encoded).expect("decode must succeed");

    match decoded {
        DAEvent::NodeRegistered { version, .. } => {
            assert_eq!(version, 1, "version field must be preserved");
        }
        _ => panic!("decoded event must be NodeRegistered"),
    }
}

#[test]
fn test_proto_version_constant() {
    assert_eq!(PROTO_VERSION, "0.1", "PROTO_VERSION must be 0.1");
}

#[test]
fn test_encode_decode_consistency_across_calls() {
    let event = DAEvent::ChunkDeclared {
        version: 1,
        timestamp_ms: 1704067200000,
        chunk_hash: "consistency-test".to_string(),
        size_bytes: 2048,
        uploader_id: "uploader-consistency".to_string(),
        replication_factor: 5,
    };

    // Encode multiple times
    let encoded1 = encode_event(&event);
    let encoded2 = encode_event(&event);

    // Must be identical
    assert_eq!(encoded1, encoded2, "encoding must be consistent");

    // Decode both
    let decoded1 = decode_event(&encoded1).expect("decode 1 must succeed");
    let decoded2 = decode_event(&encoded2).expect("decode 2 must succeed");

    // Must be identical
    assert_eq!(decoded1, decoded2, "decoding must be consistent");
    assert_eq!(event, decoded1, "decoded must equal original");
}

// ============================================================================
// Batch Encoding / Decoding Tests
// ============================================================================

#[test]
fn test_batch_empty() {
    let events: Vec<DAEvent> = vec![];
    let encoded = batch_encode(&events);
    let decoded = batch_decode(&encoded).expect("decode must succeed");

    assert_eq!(events.len(), decoded.len(), "empty batch length must match");
    assert!(decoded.is_empty(), "decoded batch must be empty");
}

#[test]
fn test_batch_single_event() {
    let events = vec![DAEvent::NodeRegistered {
        version: 1,
        timestamp_ms: 1704067200000,
        node_id: "batch-single".to_string(),
        zone: "zone-batch".to_string(),
        addr: "10.0.0.1:9000".to_string(),
        capacity_gb: 500,
    }];

    let encoded = batch_encode(&events);
    let decoded = batch_decode(&encoded).expect("decode must succeed");

    assert_eq!(events.len(), decoded.len(), "batch length must match");
    assert_eq!(events[0], decoded[0], "event must match");
}

#[test]
fn test_batch_multiple_events() {
    let events = vec![
        DAEvent::NodeRegistered {
            version: 1,
            timestamp_ms: 1704067200000,
            node_id: "batch-node-1".to_string(),
            zone: "zone-1".to_string(),
            addr: "10.0.0.1:9000".to_string(),
            capacity_gb: 100,
        },
        DAEvent::ChunkDeclared {
            version: 1,
            timestamp_ms: 1704067200001,
            chunk_hash: "batch-chunk-1".to_string(),
            size_bytes: 1024,
            uploader_id: "batch-uploader".to_string(),
            replication_factor: 3,
        },
        DAEvent::ReplicaAdded {
            version: 1,
            timestamp_ms: 1704067200002,
            chunk_hash: "batch-chunk-1".to_string(),
            node_id: "batch-node-1".to_string(),
            replica_index: 0,
        },
        DAEvent::ReplicaRemoved {
            version: 1,
            timestamp_ms: 1704067200003,
            chunk_hash: "batch-chunk-old".to_string(),
            node_id: "batch-node-old".to_string(),
            reason: ReplicaRemovalReason::Rebalance,
        },
        DAEvent::DeleteRequested {
            version: 1,
            timestamp_ms: 1704067200004,
            chunk_hash: "batch-chunk-delete".to_string(),
            requester_id: "batch-requester".to_string(),
            reason: DeleteReason::Expired,
        },
    ];

    let encoded = batch_encode(&events);
    let decoded = batch_decode(&encoded).expect("decode must succeed");

    // Verify length
    assert_eq!(events.len(), decoded.len(), "batch length must match");

    // Verify each event
    for (i, (original, decoded_event)) in events.iter().zip(decoded.iter()).enumerate() {
        assert_eq!(original, decoded_event, "event {} must match", i);
    }
}

#[test]
fn test_batch_order_preserved() {
    let events = vec![
        DAEvent::DeleteRequested {
            version: 1,
            timestamp_ms: 3,
            chunk_hash: "third".to_string(),
            requester_id: "r3".to_string(),
            reason: DeleteReason::Compliance,
        },
        DAEvent::NodeRegistered {
            version: 1,
            timestamp_ms: 1,
            node_id: "first".to_string(),
            zone: "z1".to_string(),
            addr: "1.1.1.1:1".to_string(),
            capacity_gb: 1,
        },
        DAEvent::ChunkDeclared {
            version: 1,
            timestamp_ms: 2,
            chunk_hash: "second".to_string(),
            size_bytes: 2,
            uploader_id: "u2".to_string(),
            replication_factor: 2,
        },
    ];

    let encoded = batch_encode(&events);
    let decoded = batch_decode(&encoded).expect("decode must succeed");

    // Verify order by checking discriminants in sequence
    match &decoded[0] {
        DAEvent::DeleteRequested { chunk_hash, .. } => {
            assert_eq!(chunk_hash, "third", "first event must be DeleteRequested");
        }
        _ => panic!("first event must be DeleteRequested"),
    }

    match &decoded[1] {
        DAEvent::NodeRegistered { node_id, .. } => {
            assert_eq!(node_id, "first", "second event must be NodeRegistered");
        }
        _ => panic!("second event must be NodeRegistered"),
    }

    match &decoded[2] {
        DAEvent::ChunkDeclared { chunk_hash, .. } => {
            assert_eq!(chunk_hash, "second", "third event must be ChunkDeclared");
        }
        _ => panic!("third event must be ChunkDeclared"),
    }
}

#[test]
fn test_batch_determinism() {
    let events = vec![
        DAEvent::NodeRegistered {
            version: 1,
            timestamp_ms: 1704067200000,
            node_id: "determinism-node".to_string(),
            zone: "determinism-zone".to_string(),
            addr: "192.168.1.1:45831".to_string(),
            capacity_gb: 250,
        },
        DAEvent::ChunkDeclared {
            version: 1,
            timestamp_ms: 1704067200001,
            chunk_hash: "determinism-chunk".to_string(),
            size_bytes: 4096,
            uploader_id: "determinism-uploader".to_string(),
            replication_factor: 3,
        },
    ];

    let encoded1 = batch_encode(&events);
    let encoded2 = batch_encode(&events);
    let encoded3 = batch_encode(&events);

    assert_eq!(encoded1, encoded2, "batch encoding must be deterministic (1 vs 2)");
    assert_eq!(encoded2, encoded3, "batch encoding must be deterministic (2 vs 3)");
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[test]
fn test_decode_empty_bytes() {
    let result = decode_event(&[]);

    assert!(result.is_err(), "decoding empty bytes must fail");

    match result {
        Err(DAError::DecodeFailed(msg)) => {
            assert!(!msg.is_empty(), "error message must not be empty");
        }
        _ => panic!("error must be DAError::DecodeFailed"),
    }
}

#[test]
fn test_decode_corrupted_bytes() {
    let corrupted = vec![0x00, 0x01, 0x02, 0x03, 0xff, 0xfe, 0xfd];
    let result = decode_event(&corrupted);

    assert!(result.is_err(), "decoding corrupted bytes must fail");

    match result {
        Err(DAError::DecodeFailed(_)) => {}
        _ => panic!("error must be DAError::DecodeFailed"),
    }
}

#[test]
fn test_decode_truncated_bytes() {
    // Create valid event, encode, then truncate
    let event = DAEvent::NodeRegistered {
        version: 1,
        timestamp_ms: 1704067200000,
        node_id: "truncate-test".to_string(),
        zone: "zone".to_string(),
        addr: "1.2.3.4:5".to_string(),
        capacity_gb: 100,
    };

    let encoded = encode_event(&event);
    let truncated = &encoded[0..encoded.len() / 2];

    let result = decode_event(truncated);
    assert!(result.is_err(), "decoding truncated bytes must fail");
}

#[test]
fn test_batch_decode_truncated_count() {
    // Less than 8 bytes for count
    let truncated = vec![0x01, 0x02, 0x03];
    let result = batch_decode(&truncated);

    assert!(result.is_err(), "batch decode with truncated count must fail");
}

#[test]
fn test_batch_decode_truncated_event() {
    // Valid count but truncated event data
    let mut bytes = vec![];
    bytes.extend_from_slice(&1u64.to_le_bytes()); // count = 1
    bytes.extend_from_slice(&100u64.to_le_bytes()); // length = 100
    // No actual event data

    let result = batch_decode(&bytes);
    assert!(result.is_err(), "batch decode with truncated event must fail");
}

#[test]
fn test_decode_does_not_panic_on_random_bytes() {
    // Various random byte patterns that should not panic
    let patterns: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x00],
        vec![0xff],
        vec![0x00, 0x00, 0x00, 0x00],
        vec![0xff, 0xff, 0xff, 0xff],
        vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        (0..256).map(|i| i as u8).collect(),
    ];

    for pattern in patterns {
        // This should not panic, only return Ok or Err
        let _ = decode_event(&pattern);
    }
}

#[test]
fn test_batch_decode_does_not_panic_on_random_bytes() {
    let patterns: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x00],
        vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // count = 0
        vec![0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // count = 1, no data
        (0..100).map(|i| i as u8).collect(),
    ];

    for pattern in patterns {
        // This should not panic
        let _ = batch_decode(&pattern);
    }
}

// ============================================================================
// Hash Stability Tests
// ============================================================================

#[test]
fn test_hash_stability_across_encode_decode() {
    let event = DAEvent::ChunkDeclared {
        version: 1,
        timestamp_ms: 1704067200000,
        chunk_hash: "hash-stability-test".to_string(),
        size_bytes: 8192,
        uploader_id: "hash-uploader".to_string(),
        replication_factor: 3,
    };

    let hash_original = compute_event_hash(&event);

    // Encode and decode
    let encoded = encode_event(&event);
    let decoded = decode_event(&encoded).expect("decode must succeed");

    let hash_decoded = compute_event_hash(&decoded);

    assert_eq!(hash_original, hash_decoded, "hash must be stable across encode/decode");
}

#[test]
fn test_hash_different_for_different_events() {
    let event1 = DAEvent::NodeRegistered {
        version: 1,
        timestamp_ms: 1704067200000,
        node_id: "node-1".to_string(),
        zone: "zone-1".to_string(),
        addr: "1.1.1.1:1".to_string(),
        capacity_gb: 100,
    };

    let event2 = DAEvent::NodeRegistered {
        version: 1,
        timestamp_ms: 1704067200000,
        node_id: "node-2".to_string(), // Different
        zone: "zone-1".to_string(),
        addr: "1.1.1.1:1".to_string(),
        capacity_gb: 100,
    };

    let hash1 = compute_event_hash(&event1);
    let hash2 = compute_event_hash(&event2);

    assert_ne!(hash1, hash2, "different events must have different hashes");
}

#[test]
fn test_hash_determinism_100_iterations() {
    let event = DAEvent::ReplicaAdded {
        version: 1,
        timestamp_ms: 1704067200000,
        chunk_hash: "hash-determinism".to_string(),
        node_id: "node-hash".to_string(),
        replica_index: 5,
    };

    let reference_hash = compute_event_hash(&event);

    for i in 0..100 {
        let hash = compute_event_hash(&event);
        assert_eq!(reference_hash, hash, "hash must be deterministic at iteration {}", i);
    }
}