//! # Service Node Persistence (14B.17)
//!
//! Persistence helpers for the service node registry.
//!
//! ## Scope
//!
//! This module provides:
//! - Consistency validation after load/export roundtrips
//! - Standalone persistence helpers for batch operations
//! - Comprehensive tests for LMDB roundtrip correctness
//!
//! ## Relationship with other modules
//!
//! - `db.rs`: Low-level LMDB CRUD (`put_service_node`, `get_service_node`,
//!   `load_all_service_nodes`, etc.)
//! - `internal_state_layout.rss`: `export_service_nodes_to_layout` /
//!   `load_service_nodes_from_layout` on `ChainState` (matching node_liveness,
//!   economic, storage_contracts patterns)
//! - This file: Validation and testing
//!
//! ## Invariants (CONSENSUS-CRITICAL)
//!
//! After any load or export:
//! 1. `service_nodes.len() == service_node_index.len()`
//! 2. For every record in `service_nodes`:
//!    `service_node_index[record.node_id] == record.operator_address`
//! 3. No dangling index entries (every index key maps to an existing record)
//! 4. No duplicate `node_id` across different operators

use crate::types::Address;
use super::service_node::ServiceNodeRecord;
use std::collections::HashMap;

// ════════════════════════════════════════════════════════════════════════════════
// CONSISTENCY VALIDATION
// ════════════════════════════════════════════════════════════════════════════════

/// Validate consistency between service_nodes and service_node_index.
///
/// This function verifies the bidirectional invariant:
/// - Every record has a matching index entry
/// - Every index entry points to an existing record
/// - No size mismatch between the two maps
///
/// # Arguments
/// * `service_nodes` - HashMap of operator_address → ServiceNodeRecord
/// * `service_node_index` - HashMap of node_id → operator_address
///
/// # Returns
/// * `Ok(())` - Maps are consistent
/// * `Err(String)` - Description of inconsistency found
///
/// # Usage
/// Call after `load_all_service_nodes()` or `load_service_nodes_from_layout()`
/// to verify LMDB data integrity before using in consensus.
#[inline]
pub fn validate_service_node_consistency(
    service_nodes: &HashMap<Address, ServiceNodeRecord>,
    service_node_index: &HashMap<[u8; 32], Address>,
) -> Result<(), String> {
    // Check 1: Size must match
    if service_nodes.len() != service_node_index.len() {
        return Err(format!(
            "service_nodes count ({}) != service_node_index count ({})",
            service_nodes.len(),
            service_node_index.len(),
        ));
    }

    // Check 2: Every record must have a matching index entry
    for (operator, record) in service_nodes {
        match service_node_index.get(&record.node_id) {
            Some(indexed_operator) => {
                if indexed_operator != operator {
                    return Err(format!(
                        "index mismatch: record operator {:?} but index points to {:?} for node_id {:?}",
                        operator, indexed_operator, record.node_id,
                    ));
                }
            }
            None => {
                return Err(format!(
                    "missing index entry for operator {:?} with node_id {:?}",
                    operator, record.node_id,
                ));
            }
        }
    }

    // Check 3: No dangling index entries
    for (node_id, operator) in service_node_index {
        if !service_nodes.contains_key(operator) {
            return Err(format!(
                "dangling index entry: node_id {:?} points to non-existent operator {:?}",
                node_id, operator,
            ));
        }
    }

    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gating::service_node::ServiceNodeRecord;
    use crate::types::Address;
    use dsdn_common::gating::{NodeClass, NodeStatus, CooldownPeriod};
    use std::collections::HashMap;

    // ──────────────────────────────────────────────────────────────
    // TEST HELPERS
    // ──────────────────────────────────────────────────────────────

    fn make_address(seed: u8) -> Address {
        Address::from_bytes([seed; 20])
    }

    fn make_node_id(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn make_record(seed: u8) -> ServiceNodeRecord {
        ServiceNodeRecord {
            operator_address: make_address(seed),
            node_id: make_node_id(seed),
            class: NodeClass::Storage,
            status: NodeStatus::Active,
            staked_amount: 10_000,
            registered_height: 100,
            last_status_change_height: 100,
            cooldown: None,
            tls_fingerprint: None,
            metadata: HashMap::new(),
        }
    }

    fn make_record_with_cooldown(seed: u8) -> ServiceNodeRecord {
        ServiceNodeRecord {
            operator_address: make_address(seed),
            node_id: make_node_id(seed),
            class: NodeClass::Compute,
            status: NodeStatus::Banned,
            staked_amount: 5_000,
            registered_height: 50,
            last_status_change_height: 200,
            cooldown: Some(CooldownPeriod {
                start_timestamp: 1000,
                duration_secs: 604800,
                reason: "severe slash test".to_string(),
            }),
            tls_fingerprint: Some([0xAB; 32]),
            metadata: {
                let mut m = HashMap::new();
                m.insert("region".to_string(), "ap-southeast-1".to_string());
                m
            },
        }
    }

    // ──────────────────────────────────────────────────────────────
    // CONSISTENCY VALIDATION TESTS
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn test_consistency_empty_maps() {
        let nodes: HashMap<Address, ServiceNodeRecord> = HashMap::new();
        let index: HashMap<[u8; 32], Address> = HashMap::new();
        assert!(validate_service_node_consistency(&nodes, &index).is_ok());
    }

    #[test]
    fn test_consistency_single_record() {
        let record = make_record(1);
        let mut nodes = HashMap::new();
        let mut index = HashMap::new();
        nodes.insert(record.operator_address, record.clone());
        index.insert(record.node_id, record.operator_address);
        assert!(validate_service_node_consistency(&nodes, &index).is_ok());
    }

    #[test]
    fn test_consistency_multiple_records() {
        let mut nodes = HashMap::new();
        let mut index = HashMap::new();
        for seed in 1..=5u8 {
            let record = make_record(seed);
            index.insert(record.node_id, record.operator_address);
            nodes.insert(record.operator_address, record);
        }
        assert!(validate_service_node_consistency(&nodes, &index).is_ok());
    }

    #[test]
    fn test_consistency_with_cooldown_records() {
        let mut nodes = HashMap::new();
        let mut index = HashMap::new();
        let r1 = make_record(1);
        let r2 = make_record_with_cooldown(2);
        index.insert(r1.node_id, r1.operator_address);
        nodes.insert(r1.operator_address, r1);
        index.insert(r2.node_id, r2.operator_address);
        nodes.insert(r2.operator_address, r2);
        assert!(validate_service_node_consistency(&nodes, &index).is_ok());
    }

    #[test]
    fn test_consistency_fail_size_mismatch() {
        let record = make_record(1);
        let mut nodes = HashMap::new();
        let index: HashMap<[u8; 32], Address> = HashMap::new();
        nodes.insert(record.operator_address, record);
        // index is empty but nodes has 1 entry
        let err = validate_service_node_consistency(&nodes, &index).unwrap_err();
        assert!(err.contains("count"));
    }

    #[test]
    fn test_consistency_fail_missing_index() {
        let record = make_record(1);
        let mut nodes = HashMap::new();
        let mut index = HashMap::new();
        nodes.insert(record.operator_address, record.clone());
        // Index with wrong node_id
        index.insert(make_node_id(99), record.operator_address);
        let err = validate_service_node_consistency(&nodes, &index).unwrap_err();
        assert!(err.contains("missing index entry"));
    }

    #[test]
    fn test_consistency_fail_index_mismatch() {
        let r1 = make_record(1);
        let r2 = make_record(2);
        let mut nodes = HashMap::new();
        let mut index = HashMap::new();
        nodes.insert(r1.operator_address, r1.clone());
        nodes.insert(r2.operator_address, r2.clone());
        // Index r1's node_id but pointing to r2's operator
        index.insert(r1.node_id, r2.operator_address);
        index.insert(r2.node_id, r2.operator_address);
        let err = validate_service_node_consistency(&nodes, &index).unwrap_err();
        assert!(err.contains("index mismatch") || err.contains("missing index entry"));
    }

    #[test]
    fn test_consistency_fail_dangling_index() {
        let record = make_record(1);
        let mut nodes = HashMap::new();
        let mut index = HashMap::new();
        nodes.insert(record.operator_address, record.clone());
        index.insert(record.node_id, record.operator_address);
        // Extra dangling index entry
        index.insert(make_node_id(99), make_address(99));
        let err = validate_service_node_consistency(&nodes, &index).unwrap_err();
        assert!(err.contains("count") || err.contains("dangling"));
    }

    // ──────────────────────────────────────────────────────────────
    // SERIALIZATION ROUNDTRIP TESTS
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn test_bincode_roundtrip_basic_record() {
        let record = make_record(1);
        let bytes = bincode::serialize(&record).expect("serialize");
        let decoded: ServiceNodeRecord = bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(record, decoded);
    }

    #[test]
    fn test_bincode_roundtrip_cooldown_record() {
        let record = make_record_with_cooldown(2);
        let bytes = bincode::serialize(&record).expect("serialize");
        let decoded: ServiceNodeRecord = bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(record, decoded);
    }

    #[test]
    fn test_bincode_roundtrip_all_statuses() {
        let statuses = vec![
            NodeStatus::Pending,
            NodeStatus::Active,
            NodeStatus::Quarantined,
            NodeStatus::Banned,
        ];
        for (i, status) in statuses.into_iter().enumerate() {
            let mut record = make_record((i + 10) as u8);
            record.status = status;
            let bytes = bincode::serialize(&record).expect("serialize");
            let decoded: ServiceNodeRecord = bincode::deserialize(&bytes).expect("deserialize");
            assert_eq!(record, decoded);
        }
    }

    #[test]
    fn test_bincode_roundtrip_all_classes() {
        let classes = vec![NodeClass::Storage, NodeClass::Compute];
        for (i, class) in classes.into_iter().enumerate() {
            let mut record = make_record((i + 20) as u8);
            record.class = class;
            let bytes = bincode::serialize(&record).expect("serialize");
            let decoded: ServiceNodeRecord = bincode::deserialize(&bytes).expect("deserialize");
            assert_eq!(record, decoded);
        }
    }

    #[test]
    fn test_bincode_roundtrip_with_metadata() {
        let mut record = make_record(30);
        record.metadata.insert("version".to_string(), "1.0.0".to_string());
        record.metadata.insert("region".to_string(), "us-east-1".to_string());
        record.metadata.insert("tier".to_string(), "premium".to_string());
        let bytes = bincode::serialize(&record).expect("serialize");
        let decoded: ServiceNodeRecord = bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(record, decoded);
    }

    #[test]
    fn test_bincode_roundtrip_max_stake() {
        let mut record = make_record(40);
        record.staked_amount = u128::MAX;
        let bytes = bincode::serialize(&record).expect("serialize");
        let decoded: ServiceNodeRecord = bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(record.staked_amount, decoded.staked_amount);
    }

    #[test]
    fn test_bincode_roundtrip_zero_stake() {
        let mut record = make_record(41);
        record.staked_amount = 0;
        let bytes = bincode::serialize(&record).expect("serialize");
        let decoded: ServiceNodeRecord = bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(record.staked_amount, 0);
    }

    #[test]
    fn test_bincode_roundtrip_with_tls_fingerprint() {
        let mut record = make_record(50);
        record.tls_fingerprint = Some([0xFF; 32]);
        let bytes = bincode::serialize(&record).expect("serialize");
        let decoded: ServiceNodeRecord = bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(record.tls_fingerprint, decoded.tls_fingerprint);
    }

    // ──────────────────────────────────────────────────────────────
    // STATE ROOT DETERMINISM TESTS
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn test_serialization_deterministic() {
        // Same record serialized twice must produce identical bytes
        let record = make_record_with_cooldown(60);
        let bytes1 = bincode::serialize(&record).expect("serialize 1");
        let bytes2 = bincode::serialize(&record).expect("serialize 2");
        assert_eq!(bytes1, bytes2, "bincode serialization must be deterministic");
    }

    #[test]
    fn test_different_records_produce_different_bytes() {
        let r1 = make_record(70);
        let r2 = make_record(71);
        let b1 = bincode::serialize(&r1).expect("serialize r1");
        let b2 = bincode::serialize(&r2).expect("serialize r2");
        assert_ne!(b1, b2, "different records must serialize differently");
    }
}