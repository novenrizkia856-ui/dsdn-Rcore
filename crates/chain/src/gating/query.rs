//! # Service Node Stake Query API (14B.14)
//!
//! Read-only, deterministic query functions for service node stake information.
//!
//! ## Design
//!
//! All functions take `&ChainState` — no mutation, no allocation of new state,
//! no side effects. Safe for concurrent read access.
//!
//! ## Consistency
//!
//! Queries rely on the bidirectional index invariant (14B.11):
//! - `service_nodes[operator].node_id == node_id`
//! - `service_node_index[node_id] == operator`
//!
//! If these invariants hold (enforced by registry module), all queries
//! return consistent results.

use crate::state::ChainState;
use crate::types::Address;
use dsdn_common::gating::NodeClass;
use crate::types;

// ══════════════════════════════════════════════════════════════════════════════
// MINIMUM STAKE CONSTANTS
// ══════════════════════════════════════════════════════════════════════════════
//
// Duplicated from internal_payload.rs intentionally:
// - query.rs is in crate::gating (read-only queries)
// - internal_payload.rs is in crate::state (stateful execution)
// - No circular dependency, no shared mutable state
// - Values MUST be kept in sync with internal_payload.rs
// ══════════════════════════════════════════════════════════════════════════════

/// Minimum stake for Storage nodes (NUSA, smallest unit).
const MIN_SERVICE_NODE_STAKE_STORAGE: u128 = 5_000;

/// Minimum stake for Compute nodes (NUSA, smallest unit).
const MIN_SERVICE_NODE_STAKE_COMPUTE: u128 = 500;

// ══════════════════════════════════════════════════════════════════════════════
// ServiceNodeStakeInfo
// ══════════════════════════════════════════════════════════════════════════════

/// Composite stake information for a registered service node.
///
/// Returned by [`get_stake_info`]. All fields are computed at query time
/// from the on-chain `ServiceNodeRecord`.
///
/// ## Fields
///
/// - `operator`: The operator's wallet address.
/// - `staked_amount`: The actual staked amount (from `ServiceNodeRecord`).
/// - `class`: The node's role classification (`Storage` or `Compute`).
/// - `meets_minimum`: `true` if `staked_amount >= min_stake_for_class(class)`.
#[derive(Clone, Debug, PartialEq)]
pub struct ServiceNodeStakeInfo {
    /// Operator wallet address.
    pub operator: Address,

    /// Actual staked amount (smallest unit).
    pub staked_amount: u128,

    /// Node role classification.
    pub class: NodeClass,

    /// Whether staked_amount meets the minimum for this NodeClass.
    pub meets_minimum: bool,
}

// ══════════════════════════════════════════════════════════════════════════════
// HELPER
// ══════════════════════════════════════════════════════════════════════════════

/// Return the minimum stake required for a given `NodeClass`.
///
/// Exhaustive match — no wildcard — so adding a new `NodeClass` variant
/// will produce a compile error here, forcing an explicit decision.
fn min_stake_for_class(class: &NodeClass) -> u128 {
    match class {
        NodeClass::Storage => MIN_SERVICE_NODE_STAKE_STORAGE,
        NodeClass::Compute => MIN_SERVICE_NODE_STAKE_COMPUTE,
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// QUERY FUNCTIONS
// ══════════════════════════════════════════════════════════════════════════════

/// Look up the staked amount for a service node by operator address.
///
/// ## Returns
///
/// - `Some(staked_amount)` if the operator is registered.
/// - `None` if the operator is not registered.
///
/// ## Properties
///
/// - Read-only: `&self` borrow only.
/// - No allocation: returns a `Copy` type.
/// - No panic: uses `HashMap::get` which returns `Option`.
/// - Deterministic: same state → same result.
pub fn get_service_node_stake(
    state: &ChainState,
    operator: &Address,
) -> Option<u128> {
    state.service_nodes
        .get(operator)
        .map(|record| record.staked_amount)
}

/// Look up the staked amount for a service node by its 32-byte node ID.
///
/// ## Lookup Path
///
/// 1. `service_node_index[node_id]` → `operator_address`
/// 2. `service_nodes[operator_address]` → `ServiceNodeRecord`
/// 3. Return `record.staked_amount`
///
/// ## Returns
///
/// - `Some(staked_amount)` if the node ID is registered and the record exists.
/// - `None` if the node ID is not registered, OR if the index points to a
///   missing record (should never happen if invariants hold).
///
/// ## Properties
///
/// - Read-only: `&self` borrow only.
/// - No allocation: returns a `Copy` type.
/// - No panic: chained `Option` via `and_then`.
/// - Deterministic: same state → same result.
/// - No fallback: does NOT scan service_nodes if index lookup fails.
pub fn get_service_node_stake_by_node_id(
    state: &ChainState,
    node_id: &[u8; 32],
) -> Option<u128> {
    state.service_node_index
        .get(node_id)
        .and_then(|operator| state.service_nodes.get(operator))
        .map(|record| record.staked_amount)
}

/// Build composite stake information for a registered service node.
///
/// ## Returns
///
/// - `Some(ServiceNodeStakeInfo)` if the operator is registered.
///   - `meets_minimum` is computed explicitly via `min_stake_for_class`.
/// - `None` if the operator is not registered.
///
/// ## Properties
///
/// - Read-only: `&self` borrow only.
/// - Deterministic: same state → same result.
/// - No panic: uses `HashMap::get` which returns `Option`.
/// - No side effects: does not modify state, does not allocate new state entries.
/// - `meets_minimum` is evaluated per-call, not cached.
pub fn get_stake_info(
    state: &ChainState,
    operator: &Address,
) -> Option<ServiceNodeStakeInfo> {
    state.service_nodes
        .get(operator)
        .map(|record| {
            let min_required = min_stake_for_class(&record.class);
            ServiceNodeStakeInfo {
                operator: record.operator_address,
                staked_amount: record.staked_amount,
                class: record.class,
                meets_minimum: record.staked_amount >= min_required,
            }
        })
}

// ══════════════════════════════════════════════════════════════════════════════
// TESTS
// ══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gating::ServiceNodeRecord;
    use dsdn_common::gating::{NodeClass, NodeStatus};
    use std::collections::HashMap;

    /// Helper: create a ChainState with one registered service node.
    fn state_with_node(
        operator: Address,
        node_id: [u8; 32],
        class: NodeClass,
        staked_amount: u128,
    ) -> ChainState {
        let mut state = ChainState::new();
        let record = ServiceNodeRecord {
            operator_address: operator,
            node_id,
            class,
            status: NodeStatus::Pending,
            staked_amount,
            registered_height: 1,
            last_status_change_height: 1,
            cooldown: None,
            tls_fingerprint: None,
            metadata: HashMap::new(),
        };
        state.service_nodes.insert(operator, record);
        state.service_node_index.insert(node_id, operator);
        state
    }

    fn test_operator() -> Address {
        types::Address([0x01; 20])
    }

    fn test_node_id() -> [u8; 32] {
        [0xAA; 32]
    }

    // ────────────────────────────────────────────────────────────────
    // get_service_node_stake
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn test_get_stake_registered_operator() {
        let state = state_with_node(
            test_operator(), test_node_id(), NodeClass::Storage, 5000,
        );
        assert_eq!(
            get_service_node_stake(&state, &test_operator()),
            Some(5000),
        );
    }

    #[test]
    fn test_get_stake_unregistered_operator() {
        let state = ChainState::new();
        assert_eq!(
            get_service_node_stake(&state, &test_operator()),
            None,
        );
    }

    // ────────────────────────────────────────────────────────────────
    // get_service_node_stake_by_node_id
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn test_get_stake_by_node_id_registered() {
        let state = state_with_node(
            test_operator(), test_node_id(), NodeClass::Compute, 500,
        );
        assert_eq!(
            get_service_node_stake_by_node_id(&state, &test_node_id()),
            Some(500),
        );
    }

    #[test]
    fn test_get_stake_by_node_id_unregistered() {
        let state = ChainState::new();
        assert_eq!(
            get_service_node_stake_by_node_id(&state, &test_node_id()),
            None,
        );
    }

    #[test]
    fn test_get_stake_by_node_id_dangling_index() {
        // Index points to operator, but no record in service_nodes.
        // This violates invariants but must not panic.
        let mut state = ChainState::new();
        state.service_node_index.insert(test_node_id(), test_operator());
        assert_eq!(
            get_service_node_stake_by_node_id(&state, &test_node_id()),
            None,
        );
    }

    // ────────────────────────────────────────────────────────────────
    // get_stake_info
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn test_get_stake_info_storage_meets_minimum() {
        let state = state_with_node(
            test_operator(), test_node_id(), NodeClass::Storage, 5000,
        );
        let info = get_stake_info(&state, &test_operator()).expect("should be Some");
        assert_eq!(info.operator, test_operator());
        assert_eq!(info.staked_amount, 5000);
        assert_eq!(info.class, NodeClass::Storage);
        assert!(info.meets_minimum);
    }

    #[test]
    fn test_get_stake_info_storage_below_minimum() {
        let state = state_with_node(
            test_operator(), test_node_id(), NodeClass::Storage, 4999,
        );
        let info = get_stake_info(&state, &test_operator()).expect("should be Some");
        assert_eq!(info.staked_amount, 4999);
        assert!(!info.meets_minimum);
    }

    #[test]
    fn test_get_stake_info_compute_meets_minimum() {
        let state = state_with_node(
            test_operator(), test_node_id(), NodeClass::Compute, 500,
        );
        let info = get_stake_info(&state, &test_operator()).expect("should be Some");
        assert_eq!(info.class, NodeClass::Compute);
        assert!(info.meets_minimum);
    }

    #[test]
    fn test_get_stake_info_compute_below_minimum() {
        let state = state_with_node(
            test_operator(), test_node_id(), NodeClass::Compute, 499,
        );
        let info = get_stake_info(&state, &test_operator()).expect("should be Some");
        assert!(!info.meets_minimum);
    }

    #[test]
    fn test_get_stake_info_unregistered() {
        let state = ChainState::new();
        assert_eq!(get_stake_info(&state, &test_operator()), None);
    }

    // ────────────────────────────────────────────────────────────────
    // min_stake_for_class
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn test_min_stake_storage() {
        assert_eq!(min_stake_for_class(&NodeClass::Storage), 5_000);
    }

    #[test]
    fn test_min_stake_compute() {
        assert_eq!(min_stake_for_class(&NodeClass::Compute), 500);
    }
}