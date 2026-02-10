//! # Gating Integration Tests (14B.20)
//!
//! Comprehensive test suite validating all service node gating features:
//! - CRUD lifecycle (register → get → list → unregister)
//! - Query API consistency (stake, class, status, slashing)
//! - Slashing enforcement (stake deduction, status transitions, cooldown)
//! - Cooldown lifecycle (active → expired → cleared → reactivation)
//! - Persistence roundtrip (bincode serialize/deserialize, index consistency)
//! - State root integrity (determinism, mutation sensitivity)
//! - Activation logic (Pending → Active, rejection of other statuses)
//!
//! ## Properties
//!
//! - All tests are deterministic (no randomness, no system clock, no I/O)
//! - All tests are independent (no shared mutable state between tests)
//! - All tests are order-independent (can run in any sequence)
//! - No `unwrap()` in production-path assertions; `unwrap()` only on test
//!   setup helpers where failure indicates a broken test, not broken code.

use crate::state::ChainState;
use crate::types::Address;
use crate::gating::ServiceNodeRecord;
use crate::gating::persistence::validate_service_node_consistency;
use dsdn_common::gating::{NodeClass, NodeStatus, CooldownPeriod};
use std::collections::HashMap;

// ════════════════════════════════════════════════════════════════════════════
// TEST HELPERS
// ════════════════════════════════════════════════════════════════════════════

fn addr(seed: u8) -> Address {
    Address([seed; 20])
}

fn node_id(seed: u8) -> [u8; 32] {
    [seed; 32]
}

fn tls_fp(seed: u8) -> [u8; 32] {
    [seed; 32]
}

fn make_record(seed: u8, class: NodeClass, stake: u128) -> ServiceNodeRecord {
    ServiceNodeRecord {
        operator_address: addr(seed),
        node_id: node_id(seed),
        class,
        status: NodeStatus::Pending,
        staked_amount: stake,
        registered_height: 1,
        last_status_change_height: 1,
        cooldown: None,
        tls_fingerprint: Some(tls_fp(seed)),
        metadata: HashMap::new(),
    }
}

/// Insert a record directly into ChainState with consistent index.
fn insert_record(state: &mut ChainState, record: ServiceNodeRecord) {
    let op = record.operator_address;
    let nid = record.node_id;
    state.service_nodes.insert(op, record);
    state.service_node_index.insert(nid, op);
}

// ════════════════════════════════════════════════════════════════════════════
// 1. CRUD LIFECYCLE TESTS
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn test_crud_register_get_list_unregister() {
    let mut state = ChainState::new();
    let record = make_record(0x01, NodeClass::Storage, 5_000);

    // Register
    let result = state.register_service_node(record.clone());
    assert!(result.is_ok(), "register should succeed");

    // Get by operator
    let got = state.get_service_node(&addr(0x01));
    assert!(got.is_some(), "should find registered node");
    assert_eq!(got.unwrap().node_id, node_id(0x01));
    assert_eq!(got.unwrap().class, NodeClass::Storage);
    assert_eq!(got.unwrap().staked_amount, 5_000);

    // Get by node_id
    let got_by_nid = state.get_service_node_by_node_id(&node_id(0x01));
    assert!(got_by_nid.is_some(), "should find by node_id");
    assert_eq!(got_by_nid.unwrap().operator_address, addr(0x01));

    // List
    let list = state.list_service_nodes();
    assert_eq!(list.len(), 1);

    // Index consistency
    assert!(validate_service_node_consistency(
        &state.service_nodes, &state.service_node_index
    ).is_ok());

    // Unregister
    let removed = state.unregister_service_node(&addr(0x01));
    assert!(removed.is_ok(), "unregister should succeed");
    assert_eq!(removed.unwrap().node_id, node_id(0x01));

    // Verify empty
    assert!(state.get_service_node(&addr(0x01)).is_none());
    assert!(state.get_service_node_by_node_id(&node_id(0x01)).is_none());
    assert_eq!(state.list_service_nodes().len(), 0);

    // Index consistency after removal
    assert!(validate_service_node_consistency(
        &state.service_nodes, &state.service_node_index
    ).is_ok());
}

#[test]
fn test_crud_multiple_nodes() {
    let mut state = ChainState::new();
    let r1 = make_record(0x01, NodeClass::Storage, 5_000);
    let r2 = make_record(0x02, NodeClass::Compute, 500);
    let r3 = make_record(0x03, NodeClass::Storage, 10_000);

    assert!(state.register_service_node(r1).is_ok());
    assert!(state.register_service_node(r2).is_ok());
    assert!(state.register_service_node(r3).is_ok());

    assert_eq!(state.list_service_nodes().len(), 3);
    assert!(validate_service_node_consistency(
        &state.service_nodes, &state.service_node_index
    ).is_ok());

    // Remove middle
    assert!(state.unregister_service_node(&addr(0x02)).is_ok());
    assert_eq!(state.list_service_nodes().len(), 2);
    assert!(state.get_service_node(&addr(0x02)).is_none());
    assert!(validate_service_node_consistency(
        &state.service_nodes, &state.service_node_index
    ).is_ok());
}

#[test]
fn test_crud_no_dangling_state_after_unregister() {
    let mut state = ChainState::new();
    let record = make_record(0x10, NodeClass::Compute, 1_000);
    let nid = record.node_id;

    assert!(state.register_service_node(record).is_ok());
    assert!(state.unregister_service_node(&addr(0x10)).is_ok());

    // Both maps must be empty
    assert!(state.service_nodes.is_empty());
    assert!(state.service_node_index.is_empty());
    // Index must not contain stale entry
    assert!(state.service_node_index.get(&nid).is_none());
}

// ════════════════════════════════════════════════════════════════════════════
// 2. REGISTRATION VALIDATION TESTS
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn test_register_duplicate_operator_rejected() {
    let mut state = ChainState::new();
    let r1 = make_record(0x01, NodeClass::Storage, 5_000);
    assert!(state.register_service_node(r1).is_ok());

    // Same operator, different node_id
    let mut r2 = make_record(0x01, NodeClass::Compute, 1_000);
    r2.node_id = node_id(0x99);
    let result = state.register_service_node(r2);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("already registered"));
}

#[test]
fn test_register_duplicate_node_id_rejected() {
    let mut state = ChainState::new();
    let r1 = make_record(0x01, NodeClass::Storage, 5_000);
    assert!(state.register_service_node(r1).is_ok());

    // Different operator, same node_id
    let mut r2 = make_record(0x02, NodeClass::Compute, 1_000);
    r2.node_id = node_id(0x01); // collision
    let result = state.register_service_node(r2);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("already registered"));
}

#[test]
fn test_register_zero_stake_rejected() {
    let mut state = ChainState::new();
    let record = make_record(0x01, NodeClass::Storage, 0);
    let result = state.register_service_node(record);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("greater than 0"));
}

// ════════════════════════════════════════════════════════════════════════════
// 3. QUERY METHOD CONSISTENCY TESTS
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn test_query_stake_by_operator() {
    let mut state = ChainState::new();
    let record = make_record(0x01, NodeClass::Storage, 7_500);
    insert_record(&mut state, record);

    assert_eq!(state.get_service_node_stake(&addr(0x01)), Some(7_500));
    assert_eq!(state.get_service_node_stake(&addr(0x99)), None);
}

#[test]
fn test_query_stake_by_node_id() {
    let mut state = ChainState::new();
    let record = make_record(0x01, NodeClass::Storage, 7_500);
    insert_record(&mut state, record);

    assert_eq!(state.get_service_node_stake_by_node_id(&node_id(0x01)), Some(7_500));
    assert_eq!(state.get_service_node_stake_by_node_id(&node_id(0x99)), None);
}

#[test]
fn test_query_class() {
    let mut state = ChainState::new();
    insert_record(&mut state, make_record(0x01, NodeClass::Storage, 5_000));
    insert_record(&mut state, make_record(0x02, NodeClass::Compute, 500));

    assert_eq!(state.get_service_node_class(&addr(0x01)), Some(NodeClass::Storage));
    assert_eq!(state.get_service_node_class(&addr(0x02)), Some(NodeClass::Compute));
    assert_eq!(state.get_service_node_class(&addr(0x99)), None);
}

#[test]
fn test_query_status() {
    let mut state = ChainState::new();
    insert_record(&mut state, make_record(0x01, NodeClass::Storage, 5_000));

    assert_eq!(state.get_service_node_status(&addr(0x01)), Some(NodeStatus::Pending));
    assert_eq!(state.get_service_node_status(&addr(0x99)), None);
}

#[test]
fn test_query_stake_info_meets_minimum_storage() {
    let mut state = ChainState::new();
    // Storage min = 5,000
    insert_record(&mut state, make_record(0x01, NodeClass::Storage, 5_000));
    insert_record(&mut state, make_record(0x02, NodeClass::Storage, 4_999));

    let info1 = state.get_stake_info(&addr(0x01));
    assert!(info1.is_some());
    assert!(info1.unwrap().meets_minimum);

    let info2 = state.get_stake_info(&addr(0x02));
    assert!(info2.is_some());
    assert!(!info2.unwrap().meets_minimum);
}

#[test]
fn test_query_stake_info_meets_minimum_compute() {
    let mut state = ChainState::new();
    // Compute min = 500
    insert_record(&mut state, make_record(0x01, NodeClass::Compute, 500));
    insert_record(&mut state, make_record(0x02, NodeClass::Compute, 499));

    assert!(state.get_stake_info(&addr(0x01)).unwrap().meets_minimum);
    assert!(!state.get_stake_info(&addr(0x02)).unwrap().meets_minimum);
}

#[test]
fn test_query_consistency_across_apis() {
    let mut state = ChainState::new();
    let record = make_record(0x01, NodeClass::Storage, 8_000);
    insert_record(&mut state, record);

    // All APIs must agree
    let direct = state.get_service_node(&addr(0x01)).unwrap();
    let stake = state.get_service_node_stake(&addr(0x01)).unwrap();
    let class = state.get_service_node_class(&addr(0x01)).unwrap();
    let status = state.get_service_node_status(&addr(0x01)).unwrap();
    let info = state.get_stake_info(&addr(0x01)).unwrap();

    assert_eq!(direct.staked_amount, stake);
    assert_eq!(direct.class, class);
    assert_eq!(direct.status, status);
    assert_eq!(info.staked_amount, stake);
    assert_eq!(info.class, class);
}

// ════════════════════════════════════════════════════════════════════════════
// 4. SLASHING TESTS
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn test_slash_reduces_stake() {
    let mut state = ChainState::new();
    let mut record = make_record(0x01, NodeClass::Storage, 10_000);
    record.status = NodeStatus::Active;
    insert_record(&mut state, record);
    state.locked.insert(addr(0x01), 10_000);

    let event = state.slash_service_node(
        &addr(0x01), 3_000, "test slash".to_string(), 50, 1000, false,
    );
    assert!(event.is_ok());
    let event = event.unwrap();
    assert_eq!(event.amount_slashed, 3_000);
    assert_eq!(state.get_service_node(&addr(0x01)).unwrap().staked_amount, 7_000);
    // locked must also be reduced
    assert_eq!(state.locked.get(&addr(0x01)).copied().unwrap_or(0), 7_000);
}

#[test]
fn test_slash_below_minimum_quarantines() {
    let mut state = ChainState::new();
    let mut record = make_record(0x01, NodeClass::Storage, 5_000);
    record.status = NodeStatus::Active;
    insert_record(&mut state, record);
    state.locked.insert(addr(0x01), 5_000);

    // Slash below minimum (Storage min = 5,000) → Quarantined
    let event = state.slash_service_node(
        &addr(0x01), 1, "minor offense".to_string(), 50, 1000, false,
    ).unwrap();

    assert_eq!(event.new_status, NodeStatus::Quarantined);
    assert!(event.cooldown_applied.is_none());
    assert_eq!(state.get_service_node(&addr(0x01)).unwrap().status, NodeStatus::Quarantined);
}

#[test]
fn test_slash_severe_bans_with_cooldown() {
    let mut state = ChainState::new();
    let mut record = make_record(0x01, NodeClass::Storage, 10_000);
    record.status = NodeStatus::Active;
    insert_record(&mut state, record);
    state.locked.insert(addr(0x01), 10_000);

    let event = state.slash_service_node(
        &addr(0x01), 1_000, "severe offense".to_string(), 50, 2000, true,
    ).unwrap();

    assert_eq!(event.new_status, NodeStatus::Banned);
    assert!(event.cooldown_applied.is_some());
    let cd = event.cooldown_applied.unwrap();
    assert_eq!(cd.start_timestamp, 2000);
    assert_eq!(cd.duration_secs, 604_800); // 7 days

    let r = state.get_service_node(&addr(0x01)).unwrap();
    assert_eq!(r.status, NodeStatus::Banned);
    assert!(r.cooldown.is_some());
}

#[test]
fn test_slash_event_data_consistent_with_state() {
    let mut state = ChainState::new();
    let mut record = make_record(0x01, NodeClass::Compute, 2_000);
    record.status = NodeStatus::Active;
    insert_record(&mut state, record);
    state.locked.insert(addr(0x01), 2_000);

    let event = state.slash_service_node(
        &addr(0x01), 500, "data corruption".to_string(), 100, 5000, true,
    ).unwrap();

    let r = state.get_service_node(&addr(0x01)).unwrap();
    assert_eq!(event.new_status, r.status);
    assert_eq!(event.operator, r.operator_address);
    assert_eq!(r.staked_amount, 1_500); // 2000 - 500
}

#[test]
fn test_slash_zero_amount_rejected() {
    let mut state = ChainState::new();
    let mut record = make_record(0x01, NodeClass::Storage, 5_000);
    record.status = NodeStatus::Active;
    insert_record(&mut state, record);

    let result = state.slash_service_node(
        &addr(0x01), 0, "reason".to_string(), 1, 1, false,
    );
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("greater than 0"));
}

#[test]
fn test_slash_empty_reason_rejected() {
    let mut state = ChainState::new();
    let mut record = make_record(0x01, NodeClass::Storage, 5_000);
    record.status = NodeStatus::Active;
    insert_record(&mut state, record);

    let result = state.slash_service_node(
        &addr(0x01), 100, String::new(), 1, 1, false,
    );
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("not be empty"));
}

#[test]
fn test_slash_insufficient_stake_rejected() {
    let mut state = ChainState::new();
    let mut record = make_record(0x01, NodeClass::Storage, 100);
    record.status = NodeStatus::Active;
    insert_record(&mut state, record);

    let result = state.slash_service_node(
        &addr(0x01), 200, "too much".to_string(), 1, 1, false,
    );
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("insufficient"));
}

#[test]
fn test_slash_unregistered_rejected() {
    let mut state = ChainState::new();
    let result = state.slash_service_node(
        &addr(0x99), 100, "reason".to_string(), 1, 1, false,
    );
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("not registered"));
}

// ════════════════════════════════════════════════════════════════════════════
// 5. COOLDOWN LIFECYCLE TESTS
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn test_cooldown_active_before_expiry() {
    let mut state = ChainState::new();
    let mut record = make_record(0x01, NodeClass::Storage, 10_000);
    record.status = NodeStatus::Active;
    insert_record(&mut state, record);
    state.locked.insert(addr(0x01), 10_000);

    // Severe slash at timestamp=1000 → cooldown 604800s
    state.slash_service_node(
        &addr(0x01), 1_000, "test".to_string(), 50, 1000, true,
    ).unwrap();

    // Cooldown should be active at timestamp=2000 (1000 + 604800 = 605800)
    assert!(state.is_service_node_in_cooldown(&addr(0x01), 2000));
}

#[test]
fn test_cooldown_expired_at_boundary() {
    let mut state = ChainState::new();
    let mut record = make_record(0x01, NodeClass::Storage, 10_000);
    record.status = NodeStatus::Active;
    insert_record(&mut state, record);
    state.locked.insert(addr(0x01), 10_000);

    state.slash_service_node(
        &addr(0x01), 1_000, "test".to_string(), 50, 1000, true,
    ).unwrap();

    // Exactly at expiry: 1000 + 604800 = 605800
    assert!(!state.is_service_node_in_cooldown(&addr(0x01), 605_800));
}

#[test]
fn test_cooldown_cleared_transitions_banned_to_pending() {
    let mut state = ChainState::new();
    let mut record = make_record(0x01, NodeClass::Storage, 10_000);
    record.status = NodeStatus::Banned;
    record.cooldown = Some(CooldownPeriod {
        start_timestamp: 100,
        duration_secs: 500,
        reason: "test".to_string(),
    });
    insert_record(&mut state, record);

    // Before expiry (100+500=600, timestamp=300 < 600)
    state.check_and_clear_expired_cooldowns(300);
    assert_eq!(state.get_service_node(&addr(0x01)).unwrap().status, NodeStatus::Banned);

    // After expiry (timestamp=600 >= 600)
    state.check_and_clear_expired_cooldowns(600);
    assert_eq!(state.get_service_node(&addr(0x01)).unwrap().status, NodeStatus::Pending);
    assert!(state.get_service_node(&addr(0x01)).unwrap().cooldown.is_none());
}

#[test]
fn test_cooldown_cleared_quarantined_stays_quarantined() {
    let mut state = ChainState::new();
    let mut record = make_record(0x01, NodeClass::Storage, 5_000);
    record.status = NodeStatus::Quarantined;
    record.cooldown = Some(CooldownPeriod {
        start_timestamp: 100,
        duration_secs: 500,
        reason: "test".to_string(),
    });
    insert_record(&mut state, record);

    state.check_and_clear_expired_cooldowns(700);
    // Cooldown cleared but status stays Quarantined (only Banned → Pending)
    assert!(state.get_service_node(&addr(0x01)).unwrap().cooldown.is_none());
    assert_eq!(state.get_service_node(&addr(0x01)).unwrap().status, NodeStatus::Quarantined);
}

// ════════════════════════════════════════════════════════════════════════════
// 6. PERSISTENCE / SERIALIZATION TESTS
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn test_persistence_bincode_roundtrip() {
    let record = make_record(0x01, NodeClass::Storage, 5_000);
    let bytes = bincode::serialize(&record).expect("serialize");
    let decoded: ServiceNodeRecord = bincode::deserialize(&bytes).expect("deserialize");
    assert_eq!(record, decoded);
}

#[test]
fn test_persistence_roundtrip_with_cooldown() {
    let mut record = make_record(0x01, NodeClass::Compute, 1_000);
    record.status = NodeStatus::Banned;
    record.cooldown = Some(CooldownPeriod {
        start_timestamp: 5000,
        duration_secs: 604_800,
        reason: "severe test".to_string(),
    });
    let bytes = bincode::serialize(&record).expect("serialize");
    let decoded: ServiceNodeRecord = bincode::deserialize(&bytes).expect("deserialize");
    assert_eq!(record, decoded);
}

#[test]
fn test_persistence_roundtrip_with_metadata() {
    let mut record = make_record(0x01, NodeClass::Storage, 10_000);
    record.metadata.insert("region".to_string(), "ap-southeast-1".to_string());
    record.metadata.insert("version".to_string(), "1.0.0".to_string());
    let bytes = bincode::serialize(&record).expect("serialize");
    let decoded: ServiceNodeRecord = bincode::deserialize(&bytes).expect("deserialize");
    assert_eq!(record, decoded);
}

#[test]
fn test_persistence_index_consistency_after_multi_ops() {
    let mut state = ChainState::new();

    // Register 3 nodes
    for seed in 1..=3u8 {
        let r = make_record(seed, NodeClass::Storage, 5_000);
        state.register_service_node(r).unwrap();
    }
    assert!(validate_service_node_consistency(
        &state.service_nodes, &state.service_node_index
    ).is_ok());

    // Remove one
    state.unregister_service_node(&addr(2)).unwrap();
    assert!(validate_service_node_consistency(
        &state.service_nodes, &state.service_node_index
    ).is_ok());

    // Register a new one
    let r4 = make_record(0x04, NodeClass::Compute, 500);
    state.register_service_node(r4).unwrap();
    assert!(validate_service_node_consistency(
        &state.service_nodes, &state.service_node_index
    ).is_ok());
}

#[test]
fn test_persistence_serialization_deterministic() {
    let record = make_record(0x01, NodeClass::Storage, 5_000);
    let b1 = bincode::serialize(&record).expect("serialize 1");
    let b2 = bincode::serialize(&record).expect("serialize 2");
    assert_eq!(b1, b2, "bincode serialization must be deterministic");
}

// ════════════════════════════════════════════════════════════════════════════
// 7. STATE ROOT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn test_state_root_changes_on_service_node_mutation() {
    let mut state = ChainState::new();
    let root_empty = state.compute_state_root().expect("compute root empty");

    // Register a node
    let record = make_record(0x01, NodeClass::Storage, 5_000);
    insert_record(&mut state, record);
    let root_with_node = state.compute_state_root().expect("compute root with node");

    assert_ne!(root_empty, root_with_node, "state_root must change when service_nodes changes");
}

#[test]
fn test_state_root_same_for_identical_state() {
    let mut s1 = ChainState::new();
    let mut s2 = ChainState::new();

    let record = make_record(0x01, NodeClass::Storage, 5_000);
    insert_record(&mut s1, record.clone());
    insert_record(&mut s2, record);

    let root1 = s1.compute_state_root().expect("root1");
    let root2 = s2.compute_state_root().expect("root2");

    assert_eq!(root1, root2, "identical states must produce identical state_root");
}

#[test]
fn test_state_root_different_for_different_stake() {
    let mut s1 = ChainState::new();
    let mut s2 = ChainState::new();

    insert_record(&mut s1, make_record(0x01, NodeClass::Storage, 5_000));

    let mut r2 = make_record(0x01, NodeClass::Storage, 5_001);
    insert_record(&mut s2, r2);

    let root1 = s1.compute_state_root().expect("root1");
    let root2 = s2.compute_state_root().expect("root2");

    assert_ne!(root1, root2, "different stake amounts must produce different state_root");
}

#[test]
fn test_state_root_different_for_different_index() {
    let mut s1 = ChainState::new();
    let mut s2 = ChainState::new();

    // Same record in s1
    insert_record(&mut s1, make_record(0x01, NodeClass::Storage, 5_000));

    // Same node record but with a different index mapping in s2
    let record = make_record(0x01, NodeClass::Storage, 5_000);
    s2.service_nodes.insert(addr(0x01), record);
    // Different index key (node_id 0x02 instead of 0x01)
    s2.service_node_index.insert(node_id(0x02), addr(0x01));

    let root1 = s1.compute_state_root().expect("root1");
    let root2 = s2.compute_state_root().expect("root2");

    assert_ne!(root1, root2, "different service_node_index must produce different state_root");
}

// ════════════════════════════════════════════════════════════════════════════
// 8. ACTIVATION TESTS
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn test_activate_pending_succeeds() {
    let mut state = ChainState::new();
    insert_record(&mut state, make_record(0x01, NodeClass::Storage, 5_000));

    // Status is Pending by default from make_record
    let result = state.activate_service_node(&addr(0x01), 100);
    assert!(result.is_ok());
    assert_eq!(state.get_service_node(&addr(0x01)).unwrap().status, NodeStatus::Active);
    assert_eq!(state.get_service_node(&addr(0x01)).unwrap().last_status_change_height, 100);
}

#[test]
fn test_activate_active_rejected() {
    let mut state = ChainState::new();
    let mut record = make_record(0x01, NodeClass::Storage, 5_000);
    record.status = NodeStatus::Active;
    insert_record(&mut state, record);

    let result = state.activate_service_node(&addr(0x01), 200);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("expected Pending"));
}

#[test]
fn test_activate_banned_rejected() {
    let mut state = ChainState::new();
    let mut record = make_record(0x01, NodeClass::Storage, 5_000);
    record.status = NodeStatus::Banned;
    insert_record(&mut state, record);

    let result = state.activate_service_node(&addr(0x01), 200);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("expected Pending"));
}

#[test]
fn test_activate_quarantined_rejected() {
    let mut state = ChainState::new();
    let mut record = make_record(0x01, NodeClass::Storage, 5_000);
    record.status = NodeStatus::Quarantined;
    insert_record(&mut state, record);

    let result = state.activate_service_node(&addr(0x01), 200);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("expected Pending"));
}

#[test]
fn test_activate_unregistered_rejected() {
    let mut state = ChainState::new();
    let result = state.activate_service_node(&addr(0x99), 100);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("not registered"));
}

#[test]
fn test_activate_height_stored_correctly() {
    let mut state = ChainState::new();
    insert_record(&mut state, make_record(0x01, NodeClass::Storage, 5_000));

    state.activate_service_node(&addr(0x01), 42).unwrap();
    assert_eq!(state.get_service_node(&addr(0x01)).unwrap().last_status_change_height, 42);
}

// ════════════════════════════════════════════════════════════════════════════
// INTEGRATION: FULL LIFECYCLE
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn test_full_lifecycle_register_activate_slash_cooldown_reactivate() {
    let mut state = ChainState::new();

    // 1. Register (Pending)
    let record = make_record(0x01, NodeClass::Storage, 10_000);
    state.register_service_node(record).unwrap();
    assert_eq!(state.get_service_node(&addr(0x01)).unwrap().status, NodeStatus::Pending);

    // 2. Activate (Pending → Active)
    state.activate_service_node(&addr(0x01), 10).unwrap();
    assert_eq!(state.get_service_node(&addr(0x01)).unwrap().status, NodeStatus::Active);

    // Need locked balance for slash consistency
    state.locked.insert(addr(0x01), 10_000);

    // 3. Severe slash (Active → Banned + cooldown at timestamp=1000)
    let event = state.slash_service_node(
        &addr(0x01), 2_000, "severe".to_string(), 50, 1000, true,
    ).unwrap();
    assert_eq!(event.new_status, NodeStatus::Banned);
    assert_eq!(state.get_service_node(&addr(0x01)).unwrap().staked_amount, 8_000);

    // 4. Cannot activate while Banned
    let result = state.activate_service_node(&addr(0x01), 60);
    assert!(result.is_err());

    // 5. Cooldown expires at 1000 + 604800 = 605800
    state.check_and_clear_expired_cooldowns(605_800);
    assert_eq!(state.get_service_node(&addr(0x01)).unwrap().status, NodeStatus::Pending);

    // 6. Reactivate
    state.activate_service_node(&addr(0x01), 200).unwrap();
    assert_eq!(state.get_service_node(&addr(0x01)).unwrap().status, NodeStatus::Active);

    // 7. Index still consistent
    assert!(validate_service_node_consistency(
        &state.service_nodes, &state.service_node_index
    ).is_ok());
}

#[test]
fn test_count_active_service_nodes() {
    let mut state = ChainState::new();

    // Register 3, activate 2
    for seed in 1..=3u8 {
        let r = make_record(seed, NodeClass::Storage, 5_000);
        state.register_service_node(r).unwrap();
    }
    state.activate_service_node(&addr(1), 10).unwrap();
    state.activate_service_node(&addr(2), 10).unwrap();
    // addr(3) stays Pending

    assert_eq!(state.count_active_service_nodes(), 2);
}