//! # Service Node Query API (14B.14, 14B.15)
//!
//! Read-only, deterministic query functions for service node information:
//! - Stake queries: `get_service_node_stake`, `get_stake_info` (14B.14)
//! - Class/status queries: `get_service_node_class`, `get_service_node_status` (14B.15)
//! - Slashing queries: `get_service_node_slashing_status`, `is_service_node_in_cooldown` (14B.15)
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
use dsdn_common::gating::{NodeClass, NodeStatus};
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
// ServiceNodeSlashingInfo (14B.15)
// ══════════════════════════════════════════════════════════════════════════════

/// Composite slashing and cooldown information for a registered service node.
///
/// Returned by [`get_service_node_slashing_status`]. All fields are computed
/// at query time from `ServiceNodeRecord` and `NodeLivenessRecord`.
///
/// ## Timestamp Dependency
///
/// `cooldown_active` and `cooldown_remaining_secs` depend on `current_timestamp`.
/// Same state + same timestamp → same result (deterministic).
#[derive(Clone, Debug, PartialEq)]
pub struct ServiceNodeSlashingInfo {
    /// Operator wallet address.
    pub operator: Address,

    /// Whether the node is currently in slashed state.
    /// Derived from `NodeLivenessRecord.slashed`.
    pub is_slashed: bool,

    /// Whether a cooldown period is currently active.
    /// Computed: `current_timestamp < cooldown.start_timestamp + cooldown.duration_secs`.
    pub cooldown_active: bool,

    /// Seconds remaining in cooldown, if active.
    /// `Some(remaining)` only when `cooldown_active == true`.
    /// `None` when no cooldown or cooldown expired.
    pub cooldown_remaining_secs: Option<u64>,

    /// Block height of last slash event.
    /// Currently `None` — field not tracked in on-chain state.
    pub last_slash_height: Option<u64>,

    /// Total count of slashing-related events.
    /// Sum of `data_corruption_count + malicious_behavior_count` from
    /// `NodeLivenessRecord`.
    pub slash_count: u64,
}

// ══════════════════════════════════════════════════════════════════════════════
// CLASS & STATUS QUERIES (14B.15)
// ══════════════════════════════════════════════════════════════════════════════

/// Look up the `NodeClass` of a service node by operator address.
///
/// ## Returns
///
/// - `Some(NodeClass)` if the operator is registered.
/// - `None` if the operator is not registered.
///
/// ## Properties
///
/// - Read-only, no side effects, deterministic.
/// - `NodeClass` is `Copy` — no allocation.
pub fn get_service_node_class(
    state: &ChainState,
    operator: &Address,
) -> Option<NodeClass> {
    state.service_nodes
        .get(operator)
        .map(|record| record.class)
}

/// Look up the `NodeStatus` of a service node by operator address.
///
/// ## Returns
///
/// - `Some(NodeStatus)` if the operator is registered.
/// - `None` if the operator is not registered.
///
/// ## Properties
///
/// - Read-only, no side effects, deterministic.
pub fn get_service_node_status(
    state: &ChainState,
    operator: &Address,
) -> Option<NodeStatus> {
    state.service_nodes
        .get(operator)
        .map(|record| record.status.clone())
}

// ══════════════════════════════════════════════════════════════════════════════
// SLASHING & COOLDOWN QUERIES (14B.15)
// ══════════════════════════════════════════════════════════════════════════════

/// Build composite slashing and cooldown information for a service node.
///
/// ## Parameters
///
/// - `operator`: The operator address to query.
/// - `current_timestamp`: Current unix timestamp (seconds) for cooldown evaluation.
///
/// ## Returns
///
/// - `Some(ServiceNodeSlashingInfo)` if the operator is registered.
/// - `None` if the operator is not registered.
///
/// ## Cooldown Logic
///
/// ```text
/// end = cooldown.start_timestamp + cooldown.duration_secs  (saturating)
/// cooldown_active = current_timestamp < end
/// cooldown_remaining_secs = end - current_timestamp         (if active)
/// ```
///
/// ## Slashing Logic
///
/// - `is_slashed`: from `NodeLivenessRecord.slashed` (false if no liveness record).
/// - `slash_count`: `data_corruption_count + malicious_behavior_count` (0 if no liveness record).
/// - `last_slash_height`: always `None` (not tracked in current state).
///
/// ## Properties
///
/// - Read-only, no side effects.
/// - Deterministic per (state, timestamp) pair.
/// - No panic: all lookups return `Option`.
/// - Consistent with `is_service_node_in_cooldown`.
pub fn get_service_node_slashing_status(
    state: &ChainState,
    operator: &Address,
    current_timestamp: u64,
) -> Option<ServiceNodeSlashingInfo> {
    // Primary lookup: must be a registered service node
    let record = state.service_nodes.get(operator)?;

    // Cooldown evaluation from ServiceNodeRecord.cooldown
    let (cooldown_active, cooldown_remaining_secs) = match &record.cooldown {
        Some(cd) => {
            let end = cd.start_timestamp.saturating_add(cd.duration_secs);
            if current_timestamp < end {
                (true, Some(end.saturating_sub(current_timestamp)))
            } else {
                (false, None)
            }
        }
        None => (false, None),
    };

    // Slashing info from NodeLivenessRecord (supplementary)
    let (is_slashed, slash_count) = match state.node_liveness_records.get(operator) {
        Some(lr) => (
            lr.slashed,
            lr.data_corruption_count as u64 + lr.malicious_behavior_count as u64,
        ),
        None => (false, 0),
    };

    Some(ServiceNodeSlashingInfo {
        operator: *operator,
        is_slashed,
        cooldown_active,
        cooldown_remaining_secs,
        last_slash_height: None,
        slash_count,
    })
}

/// Check whether a service node is currently in an active cooldown period.
///
/// ## Parameters
///
/// - `operator`: The operator address to query.
/// - `current_timestamp`: Current unix timestamp (seconds).
///
/// ## Returns
///
/// - `true` if: operator is registered AND has a cooldown AND `current_timestamp < end`.
/// - `false` otherwise (including unregistered operators).
///
/// ## Properties
///
/// - Read-only, no side effects.
/// - Deterministic per (state, timestamp) pair.
/// - Consistent with `get_service_node_slashing_status().cooldown_active`.
pub fn is_service_node_in_cooldown(
    state: &ChainState,
    operator: &Address,
    current_timestamp: u64,
) -> bool {
    match state.service_nodes.get(operator) {
        Some(record) => match &record.cooldown {
            Some(cd) => {
                let end = cd.start_timestamp.saturating_add(cd.duration_secs);
                current_timestamp < end
            }
            None => false,
        },
        None => false,
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// TESTS
// ══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gating::ServiceNodeRecord;
    use dsdn_common::gating::{NodeClass, NodeStatus, CooldownPeriod};
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

    /// Helper: create a ChainState with a service node that has a cooldown.
    fn state_with_cooldown(
        operator: Address,
        node_id: [u8; 32],
        start_timestamp: u64,
        duration_secs: u64,
    ) -> ChainState {
        let mut state = ChainState::new();
        let record = ServiceNodeRecord {
            operator_address: operator,
            node_id,
            class: NodeClass::Storage,
            status: NodeStatus::Quarantined,
            staked_amount: 5000,
            registered_height: 1,
            last_status_change_height: 10,
            cooldown: Some(CooldownPeriod {
                start_timestamp,
                duration_secs,
                reason: "test cooldown".to_string(),
            }),
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
    // get_service_node_stake (14B.14)
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
    // get_service_node_stake_by_node_id (14B.14)
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
        let mut state = ChainState::new();
        state.service_node_index.insert(test_node_id(), test_operator());
        assert_eq!(
            get_service_node_stake_by_node_id(&state, &test_node_id()),
            None,
        );
    }

    // ────────────────────────────────────────────────────────────────
    // get_stake_info (14B.14)
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
    // min_stake_for_class (14B.14)
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn test_min_stake_storage() {
        assert_eq!(min_stake_for_class(&NodeClass::Storage), 5_000);
    }

    #[test]
    fn test_min_stake_compute() {
        assert_eq!(min_stake_for_class(&NodeClass::Compute), 500);
    }

    // ────────────────────────────────────────────────────────────────
    // get_service_node_class (14B.15)
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn test_get_class_storage() {
        let state = state_with_node(
            test_operator(), test_node_id(), NodeClass::Storage, 5000,
        );
        assert_eq!(
            get_service_node_class(&state, &test_operator()),
            Some(NodeClass::Storage),
        );
    }

    #[test]
    fn test_get_class_compute() {
        let state = state_with_node(
            test_operator(), test_node_id(), NodeClass::Compute, 500,
        );
        assert_eq!(
            get_service_node_class(&state, &test_operator()),
            Some(NodeClass::Compute),
        );
    }

    #[test]
    fn test_get_class_unregistered() {
        let state = ChainState::new();
        assert_eq!(get_service_node_class(&state, &test_operator()), None);
    }

    // ────────────────────────────────────────────────────────────────
    // get_service_node_status (14B.15)
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn test_get_status_registered() {
        let state = state_with_node(
            test_operator(), test_node_id(), NodeClass::Storage, 5000,
        );
        assert_eq!(
            get_service_node_status(&state, &test_operator()),
            Some(NodeStatus::Pending),
        );
    }

    #[test]
    fn test_get_status_unregistered() {
        let state = ChainState::new();
        assert_eq!(get_service_node_status(&state, &test_operator()), None);
    }

    // ────────────────────────────────────────────────────────────────
    // get_service_node_slashing_status (14B.15)
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn test_slashing_status_unregistered() {
        let state = ChainState::new();
        assert_eq!(
            get_service_node_slashing_status(&state, &test_operator(), 1000),
            None,
        );
    }

    #[test]
    fn test_slashing_status_no_cooldown_no_liveness() {
        let state = state_with_node(
            test_operator(), test_node_id(), NodeClass::Storage, 5000,
        );
        let info = get_service_node_slashing_status(&state, &test_operator(), 1000)
            .expect("should be Some");
        assert_eq!(info.operator, test_operator());
        assert!(!info.is_slashed);
        assert!(!info.cooldown_active);
        assert_eq!(info.cooldown_remaining_secs, None);
        assert_eq!(info.last_slash_height, None);
        assert_eq!(info.slash_count, 0);
    }

    #[test]
    fn test_slashing_status_cooldown_active() {
        // Cooldown: start=100, duration=500 → end=600
        // Query at timestamp=300 → active, remaining=300
        let state = state_with_cooldown(
            test_operator(), test_node_id(), 100, 500,
        );
        let info = get_service_node_slashing_status(&state, &test_operator(), 300)
            .expect("should be Some");
        assert!(info.cooldown_active);
        assert_eq!(info.cooldown_remaining_secs, Some(300));
    }

    #[test]
    fn test_slashing_status_cooldown_expired() {
        // Cooldown: start=100, duration=500 → end=600
        // Query at timestamp=700 → expired
        let state = state_with_cooldown(
            test_operator(), test_node_id(), 100, 500,
        );
        let info = get_service_node_slashing_status(&state, &test_operator(), 700)
            .expect("should be Some");
        assert!(!info.cooldown_active);
        assert_eq!(info.cooldown_remaining_secs, None);
    }

    #[test]
    fn test_slashing_status_cooldown_exact_boundary() {
        // Cooldown: start=100, duration=500 → end=600
        // Query at timestamp=600 → NOT active (current_timestamp < end is false)
        let state = state_with_cooldown(
            test_operator(), test_node_id(), 100, 500,
        );
        let info = get_service_node_slashing_status(&state, &test_operator(), 600)
            .expect("should be Some");
        assert!(!info.cooldown_active);
        assert_eq!(info.cooldown_remaining_secs, None);
    }

    #[test]
    fn test_slashing_status_cooldown_one_sec_before_end() {
        // Cooldown: start=100, duration=500 → end=600
        // Query at timestamp=599 → active, remaining=1
        let state = state_with_cooldown(
            test_operator(), test_node_id(), 100, 500,
        );
        let info = get_service_node_slashing_status(&state, &test_operator(), 599)
            .expect("should be Some");
        assert!(info.cooldown_active);
        assert_eq!(info.cooldown_remaining_secs, Some(1));
    }

    #[test]
    fn test_slashing_status_cooldown_saturating_add() {
        // Edge case: start=u64::MAX-10, duration=100 → saturates to u64::MAX
        let state = state_with_cooldown(
            test_operator(), test_node_id(), u64::MAX - 10, 100,
        );
        let info = get_service_node_slashing_status(&state, &test_operator(), u64::MAX - 5)
            .expect("should be Some");
        // end saturates to u64::MAX, timestamp < u64::MAX → active
        assert!(info.cooldown_active);
        // remaining = u64::MAX - (u64::MAX - 5) = 5
        assert_eq!(info.cooldown_remaining_secs, Some(5));
    }

    // ────────────────────────────────────────────────────────────────
    // is_service_node_in_cooldown (14B.15)
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn test_in_cooldown_unregistered() {
        let state = ChainState::new();
        assert!(!is_service_node_in_cooldown(&state, &test_operator(), 1000));
    }

    #[test]
    fn test_in_cooldown_no_cooldown() {
        let state = state_with_node(
            test_operator(), test_node_id(), NodeClass::Storage, 5000,
        );
        assert!(!is_service_node_in_cooldown(&state, &test_operator(), 1000));
    }

    #[test]
    fn test_in_cooldown_active() {
        let state = state_with_cooldown(
            test_operator(), test_node_id(), 100, 500,
        );
        assert!(is_service_node_in_cooldown(&state, &test_operator(), 300));
    }

    #[test]
    fn test_in_cooldown_expired() {
        let state = state_with_cooldown(
            test_operator(), test_node_id(), 100, 500,
        );
        assert!(!is_service_node_in_cooldown(&state, &test_operator(), 700));
    }

    #[test]
    fn test_in_cooldown_consistency_with_slashing_status() {
        // Verify is_service_node_in_cooldown matches slashing_status.cooldown_active
        let state = state_with_cooldown(
            test_operator(), test_node_id(), 100, 500,
        );

        // Active case (timestamp=300)
        let in_cooldown = is_service_node_in_cooldown(&state, &test_operator(), 300);
        let info = get_service_node_slashing_status(&state, &test_operator(), 300)
            .expect("should be Some");
        assert_eq!(in_cooldown, info.cooldown_active);

        // Expired case (timestamp=700)
        let in_cooldown = is_service_node_in_cooldown(&state, &test_operator(), 700);
        let info = get_service_node_slashing_status(&state, &test_operator(), 700)
            .expect("should be Some");
        assert_eq!(in_cooldown, info.cooldown_active);
    }
}