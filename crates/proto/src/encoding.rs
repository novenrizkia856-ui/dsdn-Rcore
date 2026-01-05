//! Serialization Helpers for DSDN DA Events
//!
//! Module ini menyediakan fungsi encoding/decoding deterministik untuk DAEvent.
//! Encoding yang sama HARUS menghasilkan output byte yang identik.

use sha3::{Sha3_256, Digest};
use crate::da_event::DAEvent;
use crate::da_health::DAError;

/// Encode single DAEvent ke bytes dengan format deterministik.
///
/// # Determinism Guarantee
/// Input yang sama SELALU menghasilkan output byte yang identik,
/// tidak bergantung pada platform, compiler, atau runtime state.
///
/// # Arguments
/// * `event` - Reference ke DAEvent yang akan di-encode
///
/// # Returns
/// Vec<u8> berisi binary representation dari event
pub fn encode_event(event: &DAEvent) -> Vec<u8> {
    // bincode menggunakan little-endian dan fixed encoding order
    // yang menjamin deterministic output
    bincode::serialize(event).unwrap_or_else(|_| Vec::new())
}

/// Decode bytes ke DAEvent.
///
/// # Arguments
/// * `bytes` - Slice bytes hasil dari encode_event
///
/// # Returns
/// * `Ok(DAEvent)` - Berhasil decode
/// * `Err(DAError::DecodeFailed)` - Gagal decode
///
/// # Roundtrip Guarantee
/// decode_event(encode_event(event)) == event (untuk semua valid event)
pub fn decode_event(bytes: &[u8]) -> Result<DAEvent, DAError> {
    if bytes.is_empty() {
        return Err(DAError::DecodeFailed("empty input".to_string()));
    }
    bincode::deserialize(bytes)
        .map_err(|e| DAError::DecodeFailed(e.to_string()))
}

/// Compute SHA3-256 hash dari encoded event.
///
/// # Determinism Guarantee
/// Hash dihitung dari HASIL encode_event, bukan struct langsung.
/// Input event yang sama SELALU menghasilkan hash yang identik.
///
/// # Arguments
/// * `event` - Reference ke DAEvent
///
/// # Returns
/// Fixed 32 byte array berisi SHA3-256 hash
pub fn compute_event_hash(event: &DAEvent) -> [u8; 32] {
    let encoded = encode_event(event);
    let mut hasher = Sha3_256::new();
    hasher.update(&encoded);
    hasher.finalize().into()
}

/// Encode batch of DAEvents ke bytes.
///
/// # Format
/// ```text
/// [event_count:8][event_1_len:8][event_1_bytes:N]...[event_N_len:8][event_N_bytes:M]
/// ```
///
/// # Determinism Guarantee
/// Urutan event TIDAK BERUBAH. Output deterministik.
///
/// # Arguments
/// * `events` - Slice of DAEvent references
///
/// # Returns
/// Vec<u8> berisi concatenated length-prefixed events
pub fn batch_encode(events: &[DAEvent]) -> Vec<u8> {
    let mut result = Vec::new();
    
    // Write event count as u64 (8 bytes, little-endian)
    let count = events.len() as u64;
    result.extend_from_slice(&count.to_le_bytes());
    
    // Write each event with length prefix
    for event in events {
        let encoded = encode_event(event);
        let len = encoded.len() as u64;
        result.extend_from_slice(&len.to_le_bytes());
        result.extend_from_slice(&encoded);
    }
    
    result
}

/// Decode bytes ke Vec<DAEvent>.
///
/// # Arguments
/// * `bytes` - Slice bytes hasil dari batch_encode
///
/// # Returns
/// * `Ok(Vec<DAEvent>)` - Berhasil decode semua events
/// * `Err(DAError::DecodeFailed)` - Gagal decode
///
/// # Roundtrip Guarantee
/// batch_decode(batch_encode(events)) == events
/// Urutan dan isi TIDAK BERUBAH.
pub fn batch_decode(bytes: &[u8]) -> Result<Vec<DAEvent>, DAError> {
    if bytes.len() < 8 {
        return Err(DAError::DecodeFailed("batch too short for count".to_string()));
    }
    
    let mut cursor = 0;
    
    // Read event count
    let count_bytes: [u8; 8] = bytes[cursor..cursor + 8]
        .try_into()
        .map_err(|_| DAError::DecodeFailed("failed to read count".to_string()))?;
    let count = u64::from_le_bytes(count_bytes) as usize;
    cursor += 8;
    
    let mut events = Vec::with_capacity(count);
    
    // Read each event
    for i in 0..count {
        // Read length prefix
        if cursor + 8 > bytes.len() {
            return Err(DAError::DecodeFailed(
                format!("batch truncated at event {} length", i)
            ));
        }
        
        let len_bytes: [u8; 8] = bytes[cursor..cursor + 8]
            .try_into()
            .map_err(|_| DAError::DecodeFailed(
                format!("failed to read length for event {}", i)
            ))?;
        let event_len = u64::from_le_bytes(len_bytes) as usize;
        cursor += 8;
        
        // Read event bytes
        if cursor + event_len > bytes.len() {
            return Err(DAError::DecodeFailed(
                format!("batch truncated at event {} data", i)
            ));
        }
        
        let event_bytes = &bytes[cursor..cursor + event_len];
        let event = decode_event(event_bytes)?;
        events.push(event);
        cursor += event_len;
    }
    
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::da_event::{ReplicaRemovalReason, DeleteReason};

    fn make_node_registered_event() -> DAEvent {
        DAEvent::NodeRegistered {
            version: 1,
            timestamp_ms: 1704067200000,
            node_id: "node-test-001".to_string(),
            zone: "id-jakarta-1".to_string(),
            addr: "192.168.1.100:9000".to_string(),
            capacity_gb: 1000,
        }
    }

    fn make_chunk_declared_event() -> DAEvent {
        DAEvent::ChunkDeclared {
            version: 1,
            timestamp_ms: 1704067200000,
            chunk_hash: "abcdef1234567890".to_string(),
            size_bytes: 1048576,
            uploader_id: "uploader-001".to_string(),
            replication_factor: 3,
        }
    }

    fn make_replica_added_event() -> DAEvent {
        DAEvent::ReplicaAdded {
            version: 1,
            timestamp_ms: 1704067200000,
            chunk_hash: "chunk-hash-001".to_string(),
            node_id: "node-001".to_string(),
            replica_index: 0,
        }
    }

    fn make_replica_removed_event() -> DAEvent {
        DAEvent::ReplicaRemoved {
            version: 1,
            timestamp_ms: 1704067200000,
            chunk_hash: "chunk-hash-002".to_string(),
            node_id: "node-002".to_string(),
            reason: ReplicaRemovalReason::NodeOffline,
        }
    }

    fn make_delete_requested_event() -> DAEvent {
        DAEvent::DeleteRequested {
            version: 1,
            timestamp_ms: 1704067200000,
            chunk_hash: "chunk-to-delete".to_string(),
            requester_id: "user-001".to_string(),
            reason: DeleteReason::UserRequest,
        }
    }

    #[test]
    fn test_encode_event_not_empty() {
        let event = make_node_registered_event();
        let encoded = encode_event(&event);
        assert!(!encoded.is_empty(), "encoded event must not be empty");
    }

    #[test]
    fn test_decode_event_roundtrip_node_registered() {
        let original = make_node_registered_event();
        let encoded = encode_event(&original);
        let decoded = decode_event(&encoded).expect("decode must succeed");
        assert_eq!(original, decoded, "roundtrip must preserve event");
    }

    #[test]
    fn test_decode_event_roundtrip_chunk_declared() {
        let original = make_chunk_declared_event();
        let encoded = encode_event(&original);
        let decoded = decode_event(&encoded).expect("decode must succeed");
        assert_eq!(original, decoded, "roundtrip must preserve event");
    }

    #[test]
    fn test_decode_event_roundtrip_replica_added() {
        let original = make_replica_added_event();
        let encoded = encode_event(&original);
        let decoded = decode_event(&encoded).expect("decode must succeed");
        assert_eq!(original, decoded, "roundtrip must preserve event");
    }

    #[test]
    fn test_decode_event_roundtrip_replica_removed() {
        let original = make_replica_removed_event();
        let encoded = encode_event(&original);
        let decoded = decode_event(&encoded).expect("decode must succeed");
        assert_eq!(original, decoded, "roundtrip must preserve event");
    }

    #[test]
    fn test_decode_event_roundtrip_delete_requested() {
        let original = make_delete_requested_event();
        let encoded = encode_event(&original);
        let decoded = decode_event(&encoded).expect("decode must succeed");
        assert_eq!(original, decoded, "roundtrip must preserve event");
    }

    #[test]
    fn test_decode_event_empty_input() {
        let result = decode_event(&[]);
        assert!(result.is_err(), "empty input must fail");
    }

    #[test]
    fn test_decode_event_invalid_input() {
        let result = decode_event(&[0x00, 0x01, 0x02]);
        assert!(result.is_err(), "invalid input must fail");
    }

    #[test]
    fn test_encode_determinism_multiple_calls() {
        let event = make_node_registered_event();
        
        let encoded1 = encode_event(&event);
        let encoded2 = encode_event(&event);
        let encoded3 = encode_event(&event);
        
        assert_eq!(encoded1, encoded2, "encode must be deterministic (1 vs 2)");
        assert_eq!(encoded2, encoded3, "encode must be deterministic (2 vs 3)");
    }

    #[test]
    fn test_encode_determinism_100_iterations() {
        let event = make_chunk_declared_event();
        let reference = encode_event(&event);
        
        for i in 0..100 {
            let encoded = encode_event(&event);
            assert_eq!(
                reference, encoded,
                "encode must be deterministic at iteration {}", i
            );
        }
    }

    #[test]
    fn test_compute_event_hash_fixed_size() {
        let event = make_node_registered_event();
        let hash = compute_event_hash(&event);
        assert_eq!(hash.len(), 32, "hash must be exactly 32 bytes");
    }

    #[test]
    fn test_compute_event_hash_determinism() {
        let event = make_chunk_declared_event();
        
        let hash1 = compute_event_hash(&event);
        let hash2 = compute_event_hash(&event);
        let hash3 = compute_event_hash(&event);
        
        assert_eq!(hash1, hash2, "hash must be deterministic (1 vs 2)");
        assert_eq!(hash2, hash3, "hash must be deterministic (2 vs 3)");
    }

    #[test]
    fn test_compute_event_hash_100_iterations() {
        let event = make_replica_added_event();
        let reference = compute_event_hash(&event);
        
        for i in 0..100 {
            let hash = compute_event_hash(&event);
            assert_eq!(
                reference, hash,
                "hash must be deterministic at iteration {}", i
            );
        }
    }

    #[test]
    fn test_compute_event_hash_different_events() {
        let event1 = make_node_registered_event();
        let event2 = make_chunk_declared_event();
        
        let hash1 = compute_event_hash(&event1);
        let hash2 = compute_event_hash(&event2);
        
        assert_ne!(hash1, hash2, "different events must have different hashes");
    }

    #[test]
    fn test_batch_encode_empty() {
        let events: Vec<DAEvent> = vec![];
        let encoded = batch_encode(&events);
        
        // Should contain at least the count (8 bytes)
        assert_eq!(encoded.len(), 8, "empty batch should have 8 bytes for count");
        
        // Count should be 0
        let count = u64::from_le_bytes(encoded[0..8].try_into().unwrap());
        assert_eq!(count, 0, "empty batch count must be 0");
    }

    #[test]
    fn test_batch_encode_single() {
        let events = vec![make_node_registered_event()];
        let encoded = batch_encode(&events);
        
        assert!(encoded.len() > 8, "single event batch must be > 8 bytes");
        
        let count = u64::from_le_bytes(encoded[0..8].try_into().unwrap());
        assert_eq!(count, 1, "single event batch count must be 1");
    }

    #[test]
    fn test_batch_roundtrip_empty() {
        let original: Vec<DAEvent> = vec![];
        let encoded = batch_encode(&original);
        let decoded = batch_decode(&encoded).expect("decode must succeed");
        assert_eq!(original, decoded, "empty batch roundtrip must work");
    }

    #[test]
    fn test_batch_roundtrip_single() {
        let original = vec![make_node_registered_event()];
        let encoded = batch_encode(&original);
        let decoded = batch_decode(&encoded).expect("decode must succeed");
        assert_eq!(original, decoded, "single event batch roundtrip must work");
    }

    #[test]
    fn test_batch_roundtrip_multiple() {
        let original = vec![
            make_node_registered_event(),
            make_chunk_declared_event(),
            make_replica_added_event(),
            make_replica_removed_event(),
            make_delete_requested_event(),
        ];
        
        let encoded = batch_encode(&original);
        let decoded = batch_decode(&encoded).expect("decode must succeed");
        
        assert_eq!(original.len(), decoded.len(), "batch length must match");
        for (i, (orig, dec)) in original.iter().zip(decoded.iter()).enumerate() {
            assert_eq!(orig, dec, "event {} must match", i);
        }
    }

    #[test]
    fn test_batch_order_preserved() {
        let original = vec![
            make_delete_requested_event(),
            make_node_registered_event(),
            make_chunk_declared_event(),
        ];
        
        let encoded = batch_encode(&original);
        let decoded = batch_decode(&encoded).expect("decode must succeed");
        
        // Verify exact order
        assert_eq!(original[0], decoded[0], "event 0 order must be preserved");
        assert_eq!(original[1], decoded[1], "event 1 order must be preserved");
        assert_eq!(original[2], decoded[2], "event 2 order must be preserved");
    }

    #[test]
    fn test_batch_encode_determinism() {
        let events = vec![
            make_node_registered_event(),
            make_chunk_declared_event(),
        ];
        
        let encoded1 = batch_encode(&events);
        let encoded2 = batch_encode(&events);
        let encoded3 = batch_encode(&events);
        
        assert_eq!(encoded1, encoded2, "batch encode must be deterministic (1 vs 2)");
        assert_eq!(encoded2, encoded3, "batch encode must be deterministic (2 vs 3)");
    }

    #[test]
    fn test_batch_decode_truncated_count() {
        let result = batch_decode(&[0x01, 0x02, 0x03]);
        assert!(result.is_err(), "truncated count must fail");
    }

    #[test]
    fn test_batch_decode_truncated_length() {
        // Valid count of 1, but no length prefix
        let mut bytes = vec![];
        bytes.extend_from_slice(&1u64.to_le_bytes());
        
        let result = batch_decode(&bytes);
        assert!(result.is_err(), "truncated length must fail");
    }

    #[test]
    fn test_batch_decode_truncated_data() {
        // Valid count of 1, valid length of 100, but no data
        let mut bytes = vec![];
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&100u64.to_le_bytes());
        
        let result = batch_decode(&bytes);
        assert!(result.is_err(), "truncated data must fail");
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use crate::da_event::{ReplicaRemovalReason, DeleteReason};
    use proptest::prelude::*;

    fn arb_node_registered() -> impl Strategy<Value = DAEvent> {
        (
            any::<u8>(),
            any::<u64>(),
            "[a-z0-9]{1,20}",
            "[a-z0-9]{1,10}",
            "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}:[0-9]{1,5}",
            any::<u64>(),
        )
            .prop_map(|(version, timestamp_ms, node_id, zone, addr, capacity_gb)| {
                DAEvent::NodeRegistered {
                    version,
                    timestamp_ms,
                    node_id,
                    zone,
                    addr,
                    capacity_gb,
                }
            })
    }

    fn arb_chunk_declared() -> impl Strategy<Value = DAEvent> {
        (
            any::<u8>(),
            any::<u64>(),
            "[a-f0-9]{16,64}",
            any::<u64>(),
            "[a-z0-9]{1,20}",
            any::<u8>(),
        )
            .prop_map(|(version, timestamp_ms, chunk_hash, size_bytes, uploader_id, replication_factor)| {
                DAEvent::ChunkDeclared {
                    version,
                    timestamp_ms,
                    chunk_hash,
                    size_bytes,
                    uploader_id,
                    replication_factor,
                }
            })
    }

    fn arb_replica_added() -> impl Strategy<Value = DAEvent> {
        (
            any::<u8>(),
            any::<u64>(),
            "[a-f0-9]{16,64}",
            "[a-z0-9]{1,20}",
            any::<u8>(),
        )
            .prop_map(|(version, timestamp_ms, chunk_hash, node_id, replica_index)| {
                DAEvent::ReplicaAdded {
                    version,
                    timestamp_ms,
                    chunk_hash,
                    node_id,
                    replica_index,
                }
            })
    }

    fn arb_replica_removal_reason() -> impl Strategy<Value = ReplicaRemovalReason> {
        prop_oneof![
            Just(ReplicaRemovalReason::NodeOffline),
            Just(ReplicaRemovalReason::Rebalance),
            Just(ReplicaRemovalReason::Corruption),
            Just(ReplicaRemovalReason::Manual),
        ]
    }

    fn arb_replica_removed() -> impl Strategy<Value = DAEvent> {
        (
            any::<u8>(),
            any::<u64>(),
            "[a-f0-9]{16,64}",
            "[a-z0-9]{1,20}",
            arb_replica_removal_reason(),
        )
            .prop_map(|(version, timestamp_ms, chunk_hash, node_id, reason)| {
                DAEvent::ReplicaRemoved {
                    version,
                    timestamp_ms,
                    chunk_hash,
                    node_id,
                    reason,
                }
            })
    }

    fn arb_delete_reason() -> impl Strategy<Value = DeleteReason> {
        prop_oneof![
            Just(DeleteReason::UserRequest),
            Just(DeleteReason::Expired),
            Just(DeleteReason::Governance),
            Just(DeleteReason::Compliance),
        ]
    }

    fn arb_delete_requested() -> impl Strategy<Value = DAEvent> {
        (
            any::<u8>(),
            any::<u64>(),
            "[a-f0-9]{16,64}",
            "[a-z0-9]{1,20}",
            arb_delete_reason(),
        )
            .prop_map(|(version, timestamp_ms, chunk_hash, requester_id, reason)| {
                DAEvent::DeleteRequested {
                    version,
                    timestamp_ms,
                    chunk_hash,
                    requester_id,
                    reason,
                }
            })
    }

    fn arb_da_event() -> impl Strategy<Value = DAEvent> {
        prop_oneof![
            arb_node_registered(),
            arb_chunk_declared(),
            arb_replica_added(),
            arb_replica_removed(),
            arb_delete_requested(),
        ]
    }

    proptest! {
        #[test]
        fn proptest_encode_decode_roundtrip(event in arb_da_event()) {
            let encoded = encode_event(&event);
            let decoded = decode_event(&encoded).expect("decode must succeed");
            prop_assert_eq!(event, decoded, "roundtrip must preserve event");
        }

        #[test]
        fn proptest_encode_determinism(event in arb_da_event()) {
            let encoded1 = encode_event(&event);
            let encoded2 = encode_event(&event);
            prop_assert_eq!(encoded1, encoded2, "encode must be deterministic");
        }

        #[test]
        fn proptest_hash_determinism(event in arb_da_event()) {
            let hash1 = compute_event_hash(&event);
            let hash2 = compute_event_hash(&event);
            prop_assert_eq!(hash1, hash2, "hash must be deterministic");
        }

        #[test]
        fn proptest_hash_fixed_size(event in arb_da_event()) {
            let hash = compute_event_hash(&event);
            prop_assert_eq!(hash.len(), 32, "hash must be 32 bytes");
        }

        #[test]
        fn proptest_batch_roundtrip(events in prop::collection::vec(arb_da_event(), 0..10)) {
            let encoded = batch_encode(&events);
            let decoded = batch_decode(&encoded).expect("batch decode must succeed");
            prop_assert_eq!(events.len(), decoded.len(), "batch length must match");
            for (i, (orig, dec)) in events.iter().zip(decoded.iter()).enumerate() {
                prop_assert_eq!(orig, dec, "event {} must match", i);
            }
        }

        #[test]
        fn proptest_batch_encode_determinism(events in prop::collection::vec(arb_da_event(), 0..5)) {
            let encoded1 = batch_encode(&events);
            let encoded2 = batch_encode(&events);
            prop_assert_eq!(encoded1, encoded2, "batch encode must be deterministic");
        }

        #[test]
        fn proptest_batch_order_preserved(events in prop::collection::vec(arb_da_event(), 1..5)) {
            let encoded = batch_encode(&events);
            let decoded = batch_decode(&encoded).expect("batch decode must succeed");
            
            for (i, (orig, dec)) in events.iter().zip(decoded.iter()).enumerate() {
                prop_assert_eq!(orig, dec, "event {} order must be preserved", i);
            }
        }

        #[test]
        fn proptest_encode_100_times_determinism(event in arb_da_event()) {
            let reference = encode_event(&event);
            for i in 0..100 {
                let encoded = encode_event(&event);
                prop_assert_eq!(
                    &reference, &encoded,
                    "encode must be deterministic at iteration {}", i
                );
            }
        }

        #[test]
        fn proptest_hash_stability_across_encode(event in arb_da_event()) {
            // Hash should be stable even if we re-encode
            let hash1 = compute_event_hash(&event);
            
            // Re-encode and decode, then hash again
            let encoded = encode_event(&event);
            let decoded = decode_event(&encoded).expect("decode must succeed");
            let hash2 = compute_event_hash(&decoded);
            
            prop_assert_eq!(hash1, hash2, "hash must be stable across re-encoding");
        }
    }
}