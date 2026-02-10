//! # Service Node Slashing & Cooldown Enforcement (14B.16)
//!
//! Provides slashing, cooldown expiry, and activation logic for service nodes.
//!
//! ## Design
//!
//! - `slash_service_node`: Atomic slash → deduct stake → evaluate status → apply cooldown.
//! - `check_and_clear_expired_cooldowns`: Batch clear expired cooldowns, Banned → Pending.
//! - `activate_service_node`: Pending → Active transition.
//!
//! ## Atomicity
//!
//! All state mutations within a single function call happen within one `&mut self`
//! borrow. No intermediate observable state where invariants are violated.
//!
//! ## Determinism
//!
//! All functions are deterministic given the same (state, parameters) inputs.

use crate::state::ChainState;
use crate::types::Address;
use dsdn_common::gating::{NodeClass, NodeStatus, CooldownPeriod};

// ══════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ══════════════════════════════════════════════════════════════════════════════

/// Minimum stake for Storage nodes (NUSA, smallest unit).
/// MUST be kept in sync with query.rs and internal_payload.rs.
const MIN_SERVICE_NODE_STAKE_STORAGE: u128 = 5_000;

/// Minimum stake for Compute nodes (NUSA, smallest unit).
/// MUST be kept in sync with query.rs and internal_payload.rs.
const MIN_SERVICE_NODE_STAKE_COMPUTE: u128 = 500;

/// Cooldown duration applied on severe slashing (7 days in seconds).
const SEVERE_SLASH_COOLDOWN_SECS: u64 = 604_800;

// ══════════════════════════════════════════════════════════════════════════════
// ServiceNodeSlashEvent
// ══════════════════════════════════════════════════════════════════════════════

/// Record of a service node slashing event.
///
/// Returned by [`slash_service_node`]. All fields reflect the **final** state
/// after the slash has been applied, not intermediate values.
#[derive(Clone, Debug, PartialEq)]
pub struct ServiceNodeSlashEvent {
    /// Operator wallet address of the slashed node.
    pub operator: Address,

    /// Amount of NUSA slashed from the node's stake.
    pub amount_slashed: u128,

    /// Human-readable reason for the slash.
    pub reason: String,

    /// The node's status AFTER the slash was applied.
    pub new_status: NodeStatus,

    /// Cooldown period applied, if any (only for severe slashes).
    pub cooldown_applied: Option<CooldownPeriod>,
}

// ══════════════════════════════════════════════════════════════════════════════
// HELPER
// ══════════════════════════════════════════════════════════════════════════════

/// Return the minimum stake required for a given `NodeClass`.
///
/// Exhaustive match — no wildcard.
fn min_stake_for_class(class: &NodeClass) -> u128 {
    match class {
        NodeClass::Storage => MIN_SERVICE_NODE_STAKE_STORAGE,
        NodeClass::Compute => MIN_SERVICE_NODE_STAKE_COMPUTE,
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// SLASH SERVICE NODE
// ══════════════════════════════════════════════════════════════════════════════

/// Slash a registered service node.
///
/// ## Execution Order (CONSENSUS-CRITICAL — DO NOT REORDER)
///
/// 1. Validate: operator registered, amount > 0, staked >= amount, reason non-empty.
/// 2. Deduct `amount` from `staked_amount`.
/// 3. Evaluate new status:
///    - If `severe` → `Banned` + cooldown applied.
///    - Else if `staked_amount < min_stake(class)` → `Quarantined`.
///    - Else → status unchanged.
/// 4. Apply status, height, and cooldown atomically.
/// 5. Reduce `locked` balance to maintain consistency.
/// 6. Return `ServiceNodeSlashEvent` with FINAL state.
///
/// ## Errors
///
/// - Operator not registered.
/// - Amount is zero.
/// - Reason is empty.
/// - Insufficient staked amount.
pub fn slash_service_node(
    state: &mut ChainState,
    operator: &Address,
    amount: u128,
    reason: String,
    height: u64,
    timestamp: u64,
    severe: bool,
) -> Result<ServiceNodeSlashEvent, String> {
    // ── 1. Non-state validation ──────────────────────────────────────────
    if amount == 0 {
        return Err("slash amount must be greater than 0".to_string());
    }
    if reason.is_empty() {
        return Err("slash reason must not be empty".to_string());
    }

    // ── 2-5. Atomic record mutations (scoped borrow) ─────────────────────
    let event = {
        let record = state.service_nodes.get_mut(operator)
            .ok_or_else(|| format!(
                "operator {:?} not registered as service node",
                operator
            ))?;

        // Validate sufficient stake
        if record.staked_amount < amount {
            return Err(format!(
                "insufficient staked amount: have {}, slash {}",
                record.staked_amount, amount
            ));
        }

        // 2. Deduct from staked_amount
        record.staked_amount -= amount;

        // 3. Evaluate new status based on severity and remaining stake
        let min_required = min_stake_for_class(&record.class);
        let (new_status, cooldown_applied) = if severe {
            // Severe → Banned + cooldown
            let cd = CooldownPeriod {
                start_timestamp: timestamp,
                duration_secs: SEVERE_SLASH_COOLDOWN_SECS,
                reason: reason.clone(),
            };
            (NodeStatus::Banned, Some(cd))
        } else if record.staked_amount < min_required {
            // Below minimum stake → Quarantined (no cooldown)
            (NodeStatus::Quarantined, None)
        } else {
            // Sufficient stake, not severe → status unchanged
            (record.status.clone(), None)
        };

        // 4. Apply status + cooldown atomically
        //    Only update last_status_change_height when status actually changes
        if record.status != new_status {
            record.status = new_status.clone();
            record.last_status_change_height = height;
        }
        if let Some(ref cd) = cooldown_applied {
            record.cooldown = Some(cd.clone());
        }

        // Build event with FINAL state
        ServiceNodeSlashEvent {
            operator: *operator,
            amount_slashed: amount,
            reason,
            new_status,
            cooldown_applied,
        }
    }; // ← mutable borrow of state.service_nodes ends here

    // 5. Reduce locked balance for consistency
    //    (separate borrow — service_nodes borrow is released)
    if let Some(locked) = state.locked.get_mut(operator) {
        *locked = locked.saturating_sub(amount);
    }

    Ok(event)
}

// ══════════════════════════════════════════════════════════════════════════════
// CHECK AND CLEAR EXPIRED COOLDOWNS
// ══════════════════════════════════════════════════════════════════════════════

/// Iterate all service nodes and clear expired cooldowns.
///
/// For each node with an expired cooldown:
/// - `cooldown` is set to `None`.
/// - If `status == Banned` → transitions to `Pending`.
///
/// Nodes without cooldowns or with active cooldowns are left unchanged.
///
/// ## Properties
///
/// - Deterministic per (state, timestamp) pair.
/// - No partial update per-node: cooldown clear and status transition are atomic.
/// - Does not modify nodes without expired cooldowns.
pub fn check_and_clear_expired_cooldowns(
    state: &mut ChainState,
    current_timestamp: u64,
) {
    for record in state.service_nodes.values_mut() {
        let expired = match &record.cooldown {
            Some(cd) => {
                let end = cd.start_timestamp.saturating_add(cd.duration_secs);
                current_timestamp >= end
            }
            None => false,
        };

        if expired {
            record.cooldown = None;
            if record.status == NodeStatus::Banned {
                record.status = NodeStatus::Pending;
            }
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// ACTIVATE SERVICE NODE
// ══════════════════════════════════════════════════════════════════════════════

/// Activate a service node: transition from `Pending` to `Active`.
///
/// ## Preconditions
///
/// - Operator MUST be registered.
/// - Status MUST be `Pending`.
/// - All gating checks (stake, identity, etc.) are assumed to have already
///   passed — this function does NOT re-validate them.
///
/// ## Errors
///
/// - Operator not registered.
/// - Status is not `Pending`.
pub fn activate_service_node(
    state: &mut ChainState,
    operator: &Address,
    height: u64,
) -> Result<(), String> {
    let record = state.service_nodes.get_mut(operator)
        .ok_or_else(|| format!(
            "operator {:?} not registered as service node",
            operator
        ))?;

    if record.status != NodeStatus::Pending {
        return Err(format!(
            "cannot activate: current status is {:?}, expected Pending",
            record.status
        ));
    }

    record.status = NodeStatus::Active;
    record.last_status_change_height = height;

    Ok(())
}

// ══════════════════════════════════════════════════════════════════════════════
// TESTS
// ══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gating::ServiceNodeRecord;
    use crate::types;
    use std::collections::HashMap;

    fn test_operator() -> Address {
        types::Address([0x01; 20])
    }

    fn other_operator() -> Address {
        types::Address([0x02; 20])
    }

    fn test_node_id() -> [u8; 32] {
        [0xAA; 32]
    }

    fn other_node_id() -> [u8; 32] {
        [0xBB; 32]
    }

    /// Helper: create a ChainState with one registered active service node.
    fn state_with_active_node(
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
            status: NodeStatus::Active,
            staked_amount,
            registered_height: 1,
            last_status_change_height: 5,
            cooldown: None,
            tls_fingerprint: None,
            metadata: HashMap::new(),
        };
        state.service_nodes.insert(operator, record);
        state.service_node_index.insert(node_id, operator);
        state.locked.insert(operator, staked_amount);
        state
    }

    /// Helper: create a ChainState with a pending service node.
    fn state_with_pending_node(
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
        state.locked.insert(operator, staked_amount);
        state
    }

    // ────────────────────────────────────────────────────────────────
    // slash_service_node — validation
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn test_slash_unregistered_operator() {
        let mut state = ChainState::new();
        let result = slash_service_node(
            &mut state, &test_operator(), 100, "test".to_string(), 10, 1000, false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_slash_zero_amount() {
        let mut state = state_with_active_node(
            test_operator(), test_node_id(), NodeClass::Storage, 5000,
        );
        let result = slash_service_node(
            &mut state, &test_operator(), 0, "test".to_string(), 10, 1000, false,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("greater than 0"));
    }

    #[test]
    fn test_slash_empty_reason() {
        let mut state = state_with_active_node(
            test_operator(), test_node_id(), NodeClass::Storage, 5000,
        );
        let result = slash_service_node(
            &mut state, &test_operator(), 100, String::new(), 10, 1000, false,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not be empty"));
    }

    #[test]
    fn test_slash_insufficient_stake() {
        let mut state = state_with_active_node(
            test_operator(), test_node_id(), NodeClass::Storage, 5000,
        );
        let result = slash_service_node(
            &mut state, &test_operator(), 5001, "test".to_string(), 10, 1000, false,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("insufficient"));
    }

    // ────────────────────────────────────────────────────────────────
    // slash_service_node — non-severe, stake above minimum
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn test_slash_nonsevere_above_minimum() {
        let mut state = state_with_active_node(
            test_operator(), test_node_id(), NodeClass::Storage, 6000,
        );
        let event = slash_service_node(
            &mut state, &test_operator(), 500, "minor offense".to_string(), 10, 1000, false,
        ).expect("should succeed");

        // Stake reduced
        assert_eq!(event.amount_slashed, 500);
        assert_eq!(state.service_nodes.get(&test_operator()).unwrap().staked_amount, 5500);
        // Status unchanged (Active)
        assert_eq!(event.new_status, NodeStatus::Active);
        assert_eq!(state.service_nodes.get(&test_operator()).unwrap().status, NodeStatus::Active);
        // No cooldown
        assert_eq!(event.cooldown_applied, None);
        // last_status_change_height NOT updated (status unchanged)
        assert_eq!(state.service_nodes.get(&test_operator()).unwrap().last_status_change_height, 5);
        // Locked reduced
        assert_eq!(*state.locked.get(&test_operator()).unwrap(), 5500);
    }

    // ────────────────────────────────────────────────────────────────
    // slash_service_node — non-severe, stake below minimum → Quarantined
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn test_slash_nonsevere_below_minimum_storage() {
        let mut state = state_with_active_node(
            test_operator(), test_node_id(), NodeClass::Storage, 5000,
        );
        // Slash 100 → 4900 < 5000 minimum
        let event = slash_service_node(
            &mut state, &test_operator(), 100, "data loss".to_string(), 20, 2000, false,
        ).expect("should succeed");

        assert_eq!(event.new_status, NodeStatus::Quarantined);
        assert_eq!(state.service_nodes.get(&test_operator()).unwrap().status, NodeStatus::Quarantined);
        assert_eq!(event.cooldown_applied, None);
        assert_eq!(state.service_nodes.get(&test_operator()).unwrap().last_status_change_height, 20);
        assert_eq!(*state.locked.get(&test_operator()).unwrap(), 4900);
    }

    #[test]
    fn test_slash_nonsevere_below_minimum_compute() {
        let mut state = state_with_active_node(
            test_operator(), test_node_id(), NodeClass::Compute, 500,
        );
        // Slash 1 → 499 < 500 minimum
        let event = slash_service_node(
            &mut state, &test_operator(), 1, "timeout".to_string(), 30, 3000, false,
        ).expect("should succeed");

        assert_eq!(event.new_status, NodeStatus::Quarantined);
        assert_eq!(state.service_nodes.get(&test_operator()).unwrap().staked_amount, 499);
    }

    // ────────────────────────────────────────────────────────────────
    // slash_service_node — severe → Banned + cooldown
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn test_slash_severe_banned_with_cooldown() {
        let mut state = state_with_active_node(
            test_operator(), test_node_id(), NodeClass::Storage, 6000,
        );
        let event = slash_service_node(
            &mut state, &test_operator(), 1000, "malicious behavior".to_string(), 50, 5000, true,
        ).expect("should succeed");

        // Status = Banned
        assert_eq!(event.new_status, NodeStatus::Banned);
        assert_eq!(state.service_nodes.get(&test_operator()).unwrap().status, NodeStatus::Banned);
        // Cooldown applied
        let cd = event.cooldown_applied.as_ref().expect("should have cooldown");
        assert_eq!(cd.start_timestamp, 5000);
        assert_eq!(cd.duration_secs, SEVERE_SLASH_COOLDOWN_SECS);
        assert_eq!(cd.reason, "malicious behavior");
        // Record also has cooldown
        assert!(state.service_nodes.get(&test_operator()).unwrap().cooldown.is_some());
        // Stake reduced
        assert_eq!(state.service_nodes.get(&test_operator()).unwrap().staked_amount, 5000);
        // Height updated
        assert_eq!(state.service_nodes.get(&test_operator()).unwrap().last_status_change_height, 50);
        // Locked reduced
        assert_eq!(*state.locked.get(&test_operator()).unwrap(), 5000);
    }

    #[test]
    fn test_slash_severe_even_with_sufficient_stake() {
        // Severe overrides: even if stake is above minimum, still Banned
        let mut state = state_with_active_node(
            test_operator(), test_node_id(), NodeClass::Storage, 10000,
        );
        let event = slash_service_node(
            &mut state, &test_operator(), 100, "fraud".to_string(), 60, 6000, true,
        ).expect("should succeed");

        assert_eq!(event.new_status, NodeStatus::Banned);
        assert_eq!(state.service_nodes.get(&test_operator()).unwrap().staked_amount, 9900);
    }

    #[test]
    fn test_slash_exact_stake() {
        // Slash entire stake
        let mut state = state_with_active_node(
            test_operator(), test_node_id(), NodeClass::Compute, 500,
        );
        let event = slash_service_node(
            &mut state, &test_operator(), 500, "total loss".to_string(), 70, 7000, false,
        ).expect("should succeed");

        assert_eq!(state.service_nodes.get(&test_operator()).unwrap().staked_amount, 0);
        assert_eq!(event.new_status, NodeStatus::Quarantined);
        assert_eq!(*state.locked.get(&test_operator()).unwrap(), 0);
    }

    // ────────────────────────────────────────────────────────────────
    // check_and_clear_expired_cooldowns
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn test_clear_cooldowns_no_nodes() {
        let mut state = ChainState::new();
        // Should not panic
        check_and_clear_expired_cooldowns(&mut state, 1000);
    }

    #[test]
    fn test_clear_cooldowns_no_cooldown_set() {
        let mut state = state_with_active_node(
            test_operator(), test_node_id(), NodeClass::Storage, 5000,
        );
        check_and_clear_expired_cooldowns(&mut state, 1000);
        // No change
        assert_eq!(state.service_nodes.get(&test_operator()).unwrap().status, NodeStatus::Active);
        assert!(state.service_nodes.get(&test_operator()).unwrap().cooldown.is_none());
    }

    #[test]
    fn test_clear_cooldowns_not_expired() {
        let mut state = state_with_active_node(
            test_operator(), test_node_id(), NodeClass::Storage, 5000,
        );
        // Set cooldown: start=100, duration=500 → end=600
        let record = state.service_nodes.get_mut(&test_operator()).unwrap();
        record.status = NodeStatus::Banned;
        record.cooldown = Some(CooldownPeriod {
            start_timestamp: 100,
            duration_secs: 500,
            reason: "test".to_string(),
        });

        // Timestamp 300 < 600 → not expired
        check_and_clear_expired_cooldowns(&mut state, 300);
        assert_eq!(state.service_nodes.get(&test_operator()).unwrap().status, NodeStatus::Banned);
        assert!(state.service_nodes.get(&test_operator()).unwrap().cooldown.is_some());
    }

    #[test]
    fn test_clear_cooldowns_expired_banned_to_pending() {
        let mut state = state_with_active_node(
            test_operator(), test_node_id(), NodeClass::Storage, 5000,
        );
        let record = state.service_nodes.get_mut(&test_operator()).unwrap();
        record.status = NodeStatus::Banned;
        record.cooldown = Some(CooldownPeriod {
            start_timestamp: 100,
            duration_secs: 500,
            reason: "test".to_string(),
        });

        // Timestamp 600 >= 600 → expired
        check_and_clear_expired_cooldowns(&mut state, 600);
        assert_eq!(state.service_nodes.get(&test_operator()).unwrap().status, NodeStatus::Pending);
        assert!(state.service_nodes.get(&test_operator()).unwrap().cooldown.is_none());
    }

    #[test]
    fn test_clear_cooldowns_expired_quarantined_stays() {
        let mut state = state_with_active_node(
            test_operator(), test_node_id(), NodeClass::Storage, 5000,
        );
        let record = state.service_nodes.get_mut(&test_operator()).unwrap();
        record.status = NodeStatus::Quarantined;
        record.cooldown = Some(CooldownPeriod {
            start_timestamp: 100,
            duration_secs: 500,
            reason: "test".to_string(),
        });

        // Expired but status is Quarantined, not Banned
        check_and_clear_expired_cooldowns(&mut state, 700);
        // Cooldown cleared
        assert!(state.service_nodes.get(&test_operator()).unwrap().cooldown.is_none());
        // Status stays Quarantined (only Banned → Pending)
        assert_eq!(state.service_nodes.get(&test_operator()).unwrap().status, NodeStatus::Quarantined);
    }

    #[test]
    fn test_clear_cooldowns_multiple_nodes() {
        let mut state = ChainState::new();

        // Node 1: Banned, cooldown expired
        let r1 = ServiceNodeRecord {
            operator_address: test_operator(),
            node_id: test_node_id(),
            class: NodeClass::Storage,
            status: NodeStatus::Banned,
            staked_amount: 5000,
            registered_height: 1,
            last_status_change_height: 10,
            cooldown: Some(CooldownPeriod {
                start_timestamp: 100,
                duration_secs: 200,
                reason: "ban1".to_string(),
            }),
            tls_fingerprint: None,
            metadata: HashMap::new(),
        };
        state.service_nodes.insert(test_operator(), r1);

        // Node 2: Banned, cooldown NOT expired
        let r2 = ServiceNodeRecord {
            operator_address: other_operator(),
            node_id: other_node_id(),
            class: NodeClass::Compute,
            status: NodeStatus::Banned,
            staked_amount: 500,
            registered_height: 2,
            last_status_change_height: 20,
            cooldown: Some(CooldownPeriod {
                start_timestamp: 100,
                duration_secs: 1000,
                reason: "ban2".to_string(),
            }),
            tls_fingerprint: None,
            metadata: HashMap::new(),
        };
        state.service_nodes.insert(other_operator(), r2);

        // Timestamp 400: node1 expired (100+200=300 < 400), node2 not (100+1000=1100 > 400)
        check_and_clear_expired_cooldowns(&mut state, 400);

        // Node 1: cleared
        assert_eq!(state.service_nodes.get(&test_operator()).unwrap().status, NodeStatus::Pending);
        assert!(state.service_nodes.get(&test_operator()).unwrap().cooldown.is_none());

        // Node 2: unchanged
        assert_eq!(state.service_nodes.get(&other_operator()).unwrap().status, NodeStatus::Banned);
        assert!(state.service_nodes.get(&other_operator()).unwrap().cooldown.is_some());
    }

    // ────────────────────────────────────────────────────────────────
    // activate_service_node
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn test_activate_pending_node() {
        let mut state = state_with_pending_node(
            test_operator(), test_node_id(), NodeClass::Storage, 5000,
        );
        let result = activate_service_node(&mut state, &test_operator(), 100);
        assert!(result.is_ok());
        assert_eq!(state.service_nodes.get(&test_operator()).unwrap().status, NodeStatus::Active);
        assert_eq!(state.service_nodes.get(&test_operator()).unwrap().last_status_change_height, 100);
    }

    #[test]
    fn test_activate_unregistered() {
        let mut state = ChainState::new();
        let result = activate_service_node(&mut state, &test_operator(), 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_activate_already_active() {
        let mut state = state_with_active_node(
            test_operator(), test_node_id(), NodeClass::Storage, 5000,
        );
        let result = activate_service_node(&mut state, &test_operator(), 100);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expected Pending"));
    }

    #[test]
    fn test_activate_banned_node() {
        let mut state = state_with_active_node(
            test_operator(), test_node_id(), NodeClass::Storage, 5000,
        );
        state.service_nodes.get_mut(&test_operator()).unwrap().status = NodeStatus::Banned;
        let result = activate_service_node(&mut state, &test_operator(), 100);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expected Pending"));
    }

    // ────────────────────────────────────────────────────────────────
    // Integration: slash → cooldown expiry → activate
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn test_full_lifecycle_slash_cooldown_activate() {
        let mut state = state_with_active_node(
            test_operator(), test_node_id(), NodeClass::Storage, 10000,
        );

        // 1. Severe slash → Banned + cooldown
        let event = slash_service_node(
            &mut state, &test_operator(), 2000, "severe offense".to_string(), 50, 1000, true,
        ).expect("slash should succeed");
        assert_eq!(event.new_status, NodeStatus::Banned);
        assert_eq!(state.service_nodes.get(&test_operator()).unwrap().staked_amount, 8000);

        // 2. Before cooldown expires: cannot activate
        let result = activate_service_node(&mut state, &test_operator(), 60);
        assert!(result.is_err());

        // 3. Clear expired cooldowns (cooldown end = 1000 + 604800 = 605800)
        check_and_clear_expired_cooldowns(&mut state, 605800);
        assert_eq!(state.service_nodes.get(&test_operator()).unwrap().status, NodeStatus::Pending);
        assert!(state.service_nodes.get(&test_operator()).unwrap().cooldown.is_none());

        // 4. Now activate
        let result = activate_service_node(&mut state, &test_operator(), 100);
        assert!(result.is_ok());
        assert_eq!(state.service_nodes.get(&test_operator()).unwrap().status, NodeStatus::Active);
    }
}