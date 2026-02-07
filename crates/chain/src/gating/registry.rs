//! # Service Node Registry Management (14B.12)
//!
//! This module implements CRUD, query, and status management functions for
//! the service node registry stored in `ChainState`.
//!
//! ## Design
//!
//! All functions take `&ChainState` or `&mut ChainState` as the first
//! parameter. `ChainState` delegates to these functions via inline methods.
//!
//! ## Invariant Preservation
//!
//! Every mutating function in this module preserves the bidirectional index
//! invariants defined in 14B.11:
//!
//! 1. Every entry in `service_nodes` has a corresponding entry in `service_node_index`.
//! 2. `service_node_index[node_id] == operator_address`.
//! 3. No two operators share the same `node_id`.
//! 4. No dangling index entries.
//!
//! Mutating functions perform all map operations atomically within a single
//! `&mut self` borrow — no intermediate observable state where invariants
//! are violated.

use crate::state::ChainState;
use crate::types::Address;
use super::ServiceNodeRecord;
use dsdn_common::gating::NodeStatus;

// ════════════════════════════════════════════════════════════════════════════════
// REGISTRATION
// ════════════════════════════════════════════════════════════════════════════════

/// Register a new service node in the on-chain registry.
///
/// ## Validations
///
/// 1. `record.operator_address` MUST NOT already exist in `service_nodes`.
/// 2. `record.node_id` MUST NOT already exist in `service_node_index`.
/// 3. `record.staked_amount` MUST be greater than 0.
///
/// ## Atomicity
///
/// Both `service_nodes` and `service_node_index` are updated within the
/// same `&mut ChainState` borrow. All validations are performed BEFORE
/// any mutation — if any validation fails, no state is modified.
///
/// ## Errors
///
/// Returns `Err(String)` describing the specific validation failure.
pub fn register_service_node(
    state: &mut ChainState,
    record: ServiceNodeRecord,
) -> Result<(), String> {
    // Validation 1: operator address not already registered
    if state.service_nodes.contains_key(&record.operator_address) {
        return Err(format!(
            "operator address {} already registered in service_nodes",
            hex::encode(record.operator_address.0)
        ));
    }

    // Validation 2: node_id not already in index
    if state.service_node_index.contains_key(&record.node_id) {
        return Err(format!(
            "node_id {} already registered in service_node_index",
            hex::encode(record.node_id)
        ));
    }

    // Validation 3: stake must be positive
    if record.staked_amount == 0 {
        return Err("staked_amount must be greater than 0".to_string());
    }

    // All validations passed — perform atomic insert into both maps.
    // Copy keys before moving record into the map.
    let operator = record.operator_address;
    let node_id = record.node_id;

    state.service_node_index.insert(node_id, operator);
    state.service_nodes.insert(operator, record);

    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// UNREGISTRATION
// ════════════════════════════════════════════════════════════════════════════════

/// Remove a service node from the on-chain registry.
///
/// ## Behavior
///
/// 1. Removes the record from `service_nodes` by `operator`.
/// 2. Removes the corresponding entry from `service_node_index` using
///    the `node_id` from the removed record.
/// 3. Returns the removed `ServiceNodeRecord`.
///
/// ## No Dangling References
///
/// Both maps are cleaned up atomically. After this function returns `Ok`,
/// neither map contains any reference to this node.
///
/// ## Errors
///
/// Returns `Err(String)` if the operator address is not found.
pub fn unregister_service_node(
    state: &mut ChainState,
    operator: &Address,
) -> Result<ServiceNodeRecord, String> {
    // Remove from primary store first — this gives us the record
    // containing the node_id needed to clean up the index.
    let record = state.service_nodes.remove(operator)
        .ok_or_else(|| format!(
            "operator address {} not found in service_nodes",
            hex::encode(operator.0)
        ))?;

    // Remove from reverse index. Per invariant, this entry MUST exist.
    // HashMap::remove is infallible (returns Option, never panics).
    state.service_node_index.remove(&record.node_id);

    Ok(record)
}

// ════════════════════════════════════════════════════════════════════════════════
// QUERIES
// ════════════════════════════════════════════════════════════════════════════════

/// Look up a service node by operator address.
///
/// Returns `None` if no node is registered for this operator.
#[inline]
pub fn get_service_node<'a>(
    state: &'a ChainState,
    operator: &Address,
) -> Option<&'a ServiceNodeRecord> {
    state.service_nodes.get(operator)
}

/// Look up a service node by its 32-byte node ID.
///
/// Uses the reverse index (`service_node_index`) to find the operator
/// address, then looks up the record in the primary store.
///
/// Returns `None` if no node is registered with this node ID.
#[inline]
pub fn get_service_node_by_node_id<'a>(
    state: &'a ChainState,
    node_id: &[u8; 32],
) -> Option<&'a ServiceNodeRecord> {
    let operator = state.service_node_index.get(node_id)?;
    state.service_nodes.get(operator)
}

/// Return references to all service node records.
///
/// The order of elements is non-deterministic (HashMap iteration order).
/// Callers requiring deterministic ordering must sort the result.
#[inline]
pub fn list_service_nodes(state: &ChainState) -> Vec<&ServiceNodeRecord> {
    state.service_nodes.values().collect()
}

/// Count the number of service nodes with `NodeStatus::Active`.
///
/// Iterates all records and filters by status. Deterministic for a given
/// state snapshot (same records always produce the same count).
#[inline]
pub fn count_active_service_nodes(state: &ChainState) -> usize {
    state.service_nodes.values()
        .filter(|r| r.status == NodeStatus::Active)
        .count()
}

// ════════════════════════════════════════════════════════════════════════════════
// STATUS MANAGEMENT
// ════════════════════════════════════════════════════════════════════════════════

/// Update the status of a service node, enforcing valid state transitions.
///
/// ## Transition Rules
///
/// Uses `NodeStatus::can_transition_to()` from `dsdn_common::gating` to
/// validate that the requested transition is allowed. The allowed transitions
/// are a closed set:
///
/// ```text
/// Pending       → Active          (gating checks passed)
/// Pending       → Banned          (identity spoofing detected)
/// Active        → Quarantined     (stake drop or minor violation)
/// Active        → Banned          (severe slashing)
/// Quarantined   → Active          (stake restored + re-check)
/// Quarantined   → Banned          (further violation)
/// Banned        → Pending         (cooldown expired, re-register)
/// ```
///
/// ## Fields Updated
///
/// On success, two fields are updated atomically:
/// - `record.status` ← `new_status`
/// - `record.last_status_change_height` ← `height`
///
/// No other fields are modified. The index maps are NOT modified because
/// the operator address and node_id do not change during a status update.
///
/// ## Errors
///
/// - Operator not found in registry.
/// - Invalid state transition (current status → new_status not allowed).
pub fn update_service_node_status(
    state: &mut ChainState,
    operator: &Address,
    new_status: NodeStatus,
    height: u64,
) -> Result<(), String> {
    let record = state.service_nodes.get_mut(operator)
        .ok_or_else(|| format!(
            "operator address {} not found in service_nodes",
            hex::encode(operator.0)
        ))?;

    // Enforce valid state transition
    if !record.status.can_transition_to(new_status) {
        return Err(format!(
            "invalid status transition from {} to {} for operator {}",
            record.status, new_status, hex::encode(operator.0)
        ));
    }

    // Atomic update: both fields updated within the same mutable borrow.
    record.status = new_status;
    record.last_status_change_height = height;

    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use dsdn_common::gating::{NodeClass, NodeStatus};
    use std::collections::HashMap;

    /// Helper: create a minimal valid ServiceNodeRecord for testing.
    fn make_record(
        operator: Address,
        node_id: [u8; 32],
        class: NodeClass,
        status: NodeStatus,
        staked_amount: u128,
        height: u64,
    ) -> ServiceNodeRecord {
        ServiceNodeRecord {
            operator_address: operator,
            node_id,
            class,
            status,
            staked_amount,
            registered_height: height,
            last_status_change_height: height,
            cooldown: None,
            tls_fingerprint: None,
            metadata: HashMap::new(),
        }
    }

    fn test_operator() -> Address {
        Address([0x01; 20])
    }

    fn test_node_id() -> [u8; 32] {
        [0xAA; 32]
    }

    // ────────────────────────────────────────────────────────────────
    // register_service_node
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn test_register_success() {
        let mut state = ChainState::new();
        let record = make_record(
            test_operator(), test_node_id(),
            NodeClass::Storage, NodeStatus::Pending, 5000, 1,
        );
        let result = register_service_node(&mut state, record);
        assert!(result.is_ok());
        assert_eq!(state.service_nodes.len(), 1);
        assert_eq!(state.service_node_index.len(), 1);
        assert_eq!(
            state.service_node_index.get(&test_node_id()),
            Some(&test_operator())
        );
    }

    #[test]
    fn test_register_duplicate_operator() {
        let mut state = ChainState::new();
        let r1 = make_record(
            test_operator(), test_node_id(),
            NodeClass::Storage, NodeStatus::Pending, 5000, 1,
        );
        let r2 = make_record(
            test_operator(), [0xBB; 32],
            NodeClass::Compute, NodeStatus::Pending, 1000, 2,
        );
        assert!(register_service_node(&mut state, r1).is_ok());
        let err = register_service_node(&mut state, r2);
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("already registered"));
        // State unchanged after failed registration
        assert_eq!(state.service_nodes.len(), 1);
        assert_eq!(state.service_node_index.len(), 1);
    }

    #[test]
    fn test_register_duplicate_node_id() {
        let mut state = ChainState::new();
        let r1 = make_record(
            Address([0x01; 20]), test_node_id(),
            NodeClass::Storage, NodeStatus::Pending, 5000, 1,
        );
        let r2 = make_record(
            Address([0x02; 20]), test_node_id(),
            NodeClass::Compute, NodeStatus::Pending, 1000, 2,
        );
        assert!(register_service_node(&mut state, r1).is_ok());
        let err = register_service_node(&mut state, r2);
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("already registered"));
        assert_eq!(state.service_nodes.len(), 1);
        assert_eq!(state.service_node_index.len(), 1);
    }

    #[test]
    fn test_register_zero_stake() {
        let mut state = ChainState::new();
        let record = make_record(
            test_operator(), test_node_id(),
            NodeClass::Storage, NodeStatus::Pending, 0, 1,
        );
        let err = register_service_node(&mut state, record);
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("staked_amount"));
        assert_eq!(state.service_nodes.len(), 0);
        assert_eq!(state.service_node_index.len(), 0);
    }

    // ────────────────────────────────────────────────────────────────
    // unregister_service_node
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn test_unregister_success() {
        let mut state = ChainState::new();
        let op = test_operator();
        let nid = test_node_id();
        let record = make_record(
            op, nid, NodeClass::Storage, NodeStatus::Pending, 5000, 1,
        );
        register_service_node(&mut state, record).expect("register ok");

        let removed = unregister_service_node(&mut state, &op);
        assert!(removed.is_ok());
        let removed = removed.expect("unwrap ok");
        assert_eq!(removed.operator_address, op);
        assert_eq!(removed.node_id, nid);
        assert_eq!(state.service_nodes.len(), 0);
        assert_eq!(state.service_node_index.len(), 0);
    }

    #[test]
    fn test_unregister_not_found() {
        let mut state = ChainState::new();
        let err = unregister_service_node(&mut state, &Address([0xFF; 20]));
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("not found"));
    }

    // ────────────────────────────────────────────────────────────────
    // get_service_node
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn test_get_service_node_found() {
        let mut state = ChainState::new();
        let op = test_operator();
        let record = make_record(
            op, test_node_id(),
            NodeClass::Storage, NodeStatus::Pending, 5000, 1,
        );
        register_service_node(&mut state, record).expect("register ok");

        let found = get_service_node(&state, &op);
        assert!(found.is_some());
        assert_eq!(found.expect("some").operator_address, op);
    }

    #[test]
    fn test_get_service_node_not_found() {
        let state = ChainState::new();
        assert!(get_service_node(&state, &Address([0xFF; 20])).is_none());
    }

    // ────────────────────────────────────────────────────────────────
    // get_service_node_by_node_id
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn test_get_by_node_id_found() {
        let mut state = ChainState::new();
        let op = test_operator();
        let nid = test_node_id();
        let record = make_record(
            op, nid, NodeClass::Storage, NodeStatus::Pending, 5000, 1,
        );
        register_service_node(&mut state, record).expect("register ok");

        let found = get_service_node_by_node_id(&state, &nid);
        assert!(found.is_some());
        assert_eq!(found.expect("some").node_id, nid);
    }

    #[test]
    fn test_get_by_node_id_not_found() {
        let state = ChainState::new();
        assert!(get_service_node_by_node_id(&state, &[0xFF; 32]).is_none());
    }

    // ────────────────────────────────────────────────────────────────
    // update_service_node_status
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn test_status_update_pending_to_active() {
        let mut state = ChainState::new();
        let op = test_operator();
        let record = make_record(
            op, test_node_id(),
            NodeClass::Storage, NodeStatus::Pending, 5000, 1,
        );
        register_service_node(&mut state, record).expect("register ok");

        let result = update_service_node_status(
            &mut state, &op, NodeStatus::Active, 10,
        );
        assert!(result.is_ok());

        let node = get_service_node(&state, &op).expect("found");
        assert_eq!(node.status, NodeStatus::Active);
        assert_eq!(node.last_status_change_height, 10);
    }

    #[test]
    fn test_status_update_invalid_transition() {
        let mut state = ChainState::new();
        let op = test_operator();
        let record = make_record(
            op, test_node_id(),
            NodeClass::Storage, NodeStatus::Pending, 5000, 1,
        );
        register_service_node(&mut state, record).expect("register ok");

        // Pending → Quarantined is NOT allowed
        let err = update_service_node_status(
            &mut state, &op, NodeStatus::Quarantined, 10,
        );
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("invalid status transition"));

        // Status must remain Pending (unchanged)
        let node = get_service_node(&state, &op).expect("found");
        assert_eq!(node.status, NodeStatus::Pending);
        assert_eq!(node.last_status_change_height, 1); // unchanged
    }

    #[test]
    fn test_status_update_active_to_quarantined() {
        let mut state = ChainState::new();
        let op = test_operator();
        let record = make_record(
            op, test_node_id(),
            NodeClass::Storage, NodeStatus::Pending, 5000, 1,
        );
        register_service_node(&mut state, record).expect("register ok");

        // Pending → Active
        update_service_node_status(&mut state, &op, NodeStatus::Active, 5)
            .expect("ok");
        // Active → Quarantined
        let result = update_service_node_status(
            &mut state, &op, NodeStatus::Quarantined, 15,
        );
        assert!(result.is_ok());

        let node = get_service_node(&state, &op).expect("found");
        assert_eq!(node.status, NodeStatus::Quarantined);
        assert_eq!(node.last_status_change_height, 15);
    }

    #[test]
    fn test_status_update_not_found() {
        let mut state = ChainState::new();
        let err = update_service_node_status(
            &mut state, &Address([0xFF; 20]), NodeStatus::Active, 10,
        );
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("not found"));
    }

    // ────────────────────────────────────────────────────────────────
    // list_service_nodes
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn test_list_empty() {
        let state = ChainState::new();
        assert!(list_service_nodes(&state).is_empty());
    }

    #[test]
    fn test_list_multiple() {
        let mut state = ChainState::new();
        let r1 = make_record(
            Address([0x01; 20]), [0xAA; 32],
            NodeClass::Storage, NodeStatus::Pending, 5000, 1,
        );
        let r2 = make_record(
            Address([0x02; 20]), [0xBB; 32],
            NodeClass::Compute, NodeStatus::Active, 1000, 2,
        );
        register_service_node(&mut state, r1).expect("ok");
        register_service_node(&mut state, r2).expect("ok");

        let nodes = list_service_nodes(&state);
        assert_eq!(nodes.len(), 2);
    }

    // ────────────────────────────────────────────────────────────────
    // count_active_service_nodes
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn test_count_active_empty() {
        let state = ChainState::new();
        assert_eq!(count_active_service_nodes(&state), 0);
    }

    #[test]
    fn test_count_active_mixed() {
        let mut state = ChainState::new();
        let r1 = make_record(
            Address([0x01; 20]), [0xAA; 32],
            NodeClass::Storage, NodeStatus::Pending, 5000, 1,
        );
        let r2 = make_record(
            Address([0x02; 20]), [0xBB; 32],
            NodeClass::Compute, NodeStatus::Active, 1000, 2,
        );
        let r3 = make_record(
            Address([0x03; 20]), [0xCC; 32],
            NodeClass::Storage, NodeStatus::Active, 8000, 3,
        );
        register_service_node(&mut state, r1).expect("ok");
        register_service_node(&mut state, r2).expect("ok");
        register_service_node(&mut state, r3).expect("ok");

        assert_eq!(count_active_service_nodes(&state), 2);
    }

    // ────────────────────────────────────────────────────────────────
    // invariant preservation
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn test_invariant_register_unregister_cycle() {
        let mut state = ChainState::new();

        // Register 3 nodes
        for i in 0u8..3 {
            let mut op = [0u8; 20];
            op[0] = i + 1;
            let mut nid = [0u8; 32];
            nid[0] = i + 0xA0;
            let record = make_record(
                Address(op), nid,
                NodeClass::Storage, NodeStatus::Pending, 1000 * (i as u128 + 1), 1,
            );
            register_service_node(&mut state, record).expect("register ok");
        }
        assert_eq!(state.service_nodes.len(), 3);
        assert_eq!(state.service_node_index.len(), 3);

        // Unregister middle node
        let mut op_mid = [0u8; 20];
        op_mid[0] = 2;
        unregister_service_node(&mut state, &Address(op_mid)).expect("unregister ok");
        assert_eq!(state.service_nodes.len(), 2);
        assert_eq!(state.service_node_index.len(), 2);

        // Verify invariant: every service_node has an index entry
        for (addr, record) in &state.service_nodes {
            let indexed_addr = state.service_node_index.get(&record.node_id);
            assert_eq!(indexed_addr, Some(addr));
        }

        // Verify invariant: every index entry has a service_node
        for (nid, addr) in &state.service_node_index {
            let record = state.service_nodes.get(addr);
            assert!(record.is_some());
            assert_eq!(&record.expect("some").node_id, nid);
        }
    }

    #[test]
    fn test_failed_register_does_not_mutate_state() {
        let mut state = ChainState::new();
        let record = make_record(
            test_operator(), test_node_id(),
            NodeClass::Storage, NodeStatus::Pending, 5000, 1,
        );
        register_service_node(&mut state, record).expect("ok");

        // Snapshot counts before failed attempts
        let sn_count = state.service_nodes.len();
        let idx_count = state.service_node_index.len();

        // Attempt duplicate operator
        let r2 = make_record(
            test_operator(), [0xBB; 32],
            NodeClass::Compute, NodeStatus::Pending, 1000, 2,
        );
        assert!(register_service_node(&mut state, r2).is_err());

        // Attempt duplicate node_id
        let r3 = make_record(
            Address([0x02; 20]), test_node_id(),
            NodeClass::Compute, NodeStatus::Pending, 1000, 3,
        );
        assert!(register_service_node(&mut state, r3).is_err());

        // Attempt zero stake
        let r4 = make_record(
            Address([0x03; 20]), [0xCC; 32],
            NodeClass::Compute, NodeStatus::Pending, 0, 4,
        );
        assert!(register_service_node(&mut state, r4).is_err());

        // State must be unchanged
        assert_eq!(state.service_nodes.len(), sn_count);
        assert_eq!(state.service_node_index.len(), idx_count);
    }

    #[test]
    fn test_status_transition_full_lifecycle() {
        let mut state = ChainState::new();
        let op = test_operator();
        let record = make_record(
            op, test_node_id(),
            NodeClass::Storage, NodeStatus::Pending, 5000, 1,
        );
        register_service_node(&mut state, record).expect("ok");

        // Pending → Active
        assert!(update_service_node_status(&mut state, &op, NodeStatus::Active, 10).is_ok());
        // Active → Quarantined
        assert!(update_service_node_status(&mut state, &op, NodeStatus::Quarantined, 20).is_ok());
        // Quarantined → Banned
        assert!(update_service_node_status(&mut state, &op, NodeStatus::Banned, 30).is_ok());
        // Banned → Pending (re-register after cooldown)
        assert!(update_service_node_status(&mut state, &op, NodeStatus::Pending, 40).is_ok());

        let node = get_service_node(&state, &op).expect("found");
        assert_eq!(node.status, NodeStatus::Pending);
        assert_eq!(node.last_status_change_height, 40);
    }
}