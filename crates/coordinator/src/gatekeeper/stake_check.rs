//! # Stake Check Hook (14B.33)
//!
//! Provides [`StakeCheckHook`], a pure validation layer that verifies
//! stake requirements before scheduling or admission operations.
//!
//! ## Design
//!
//! This hook is a **read-only validator** — it never modifies the registry,
//! never performs network calls, and has no side effects. It can be called
//! at any point in the admission or scheduling pipeline as a pre-condition
//! check.
//!
//! ## Methods
//!
//! - [`check_before_schedule`](StakeCheckHook::check_before_schedule):
//!   Looks up a node in the registry and verifies its stake meets the
//!   protocol-level minimum for its registered class (`NodeClass::min_stake()`).
//!
//! - [`check_before_admission`](StakeCheckHook::check_before_admission):
//!   Validates a candidate's stake against the configurable
//!   [`StakeRequirement`] thresholds for the claimed class.
//!
//! ## Safety
//!
//! - No `panic!`, `unwrap()`, `expect()`.
//! - No mutation of any input.
//! - Deterministic: same inputs always produce the same result.

use std::collections::HashMap;

use dsdn_common::gating::{
    GatingError, NodeClass, NodeRegistryEntry, StakeRequirement,
};

// ════════════════════════════════════════════════════════════════════════════════
// STAKE CHECK HOOK
// ════════════════════════════════════════════════════════════════════════════════

/// Pure validation hook for stake requirements.
///
/// Holds a [`StakeRequirement`] configuration that defines per-class
/// minimum stake thresholds. Used by the coordinator to gate scheduling
/// and admission operations.
///
/// ## Thread Safety
///
/// `StakeCheckHook` is `Send + Sync` — it contains no interior mutability
/// and all methods take `&self` with immutable borrows.
#[derive(Clone, Debug)]
pub struct StakeCheckHook {
    /// Configurable stake thresholds per node class.
    /// Used by [`check_before_admission`](Self::check_before_admission).
    pub requirement: StakeRequirement,
}

impl StakeCheckHook {
    /// Creates a new [`StakeCheckHook`] with the given stake requirement.
    pub fn new(requirement: StakeRequirement) -> Self {
        Self { requirement }
    }

    /// Verifies that a registered node meets the protocol-level stake
    /// minimum for its class before scheduling a workload.
    ///
    /// ## Lookup
    ///
    /// The node is looked up in `registry` by `node_id` (the HashMap key).
    /// If the node is not found, returns `GatingError::NodeNotRegistered`.
    ///
    /// ## Validation
    ///
    /// Uses `NodeClass::min_stake()` (protocol-level minimum) to determine
    /// the threshold. The check passes if `entry.stake >= class.min_stake()`.
    ///
    /// ## Parameters
    ///
    /// - `node_id`: The registry key (lowercase hex string of 32-byte node ID).
    /// - `registry`: Immutable reference to the node registry. Not modified.
    ///
    /// ## Returns
    ///
    /// - `Ok(())` if the node exists and its stake meets the minimum.
    /// - `Err(GatingError::NodeNotRegistered)` if the node is not in the registry.
    /// - `Err(GatingError::InsufficientStake { .. })` if stake is below minimum.
    pub fn check_before_schedule(
        &self,
        node_id: &str,
        registry: &HashMap<String, NodeRegistryEntry>,
    ) -> Result<(), GatingError> {
        let entry = registry.get(node_id).ok_or(GatingError::NodeNotRegistered)?;

        let min_stake = entry.class.min_stake();
        if entry.stake >= min_stake {
            Ok(())
        } else {
            Err(GatingError::InsufficientStake {
                required: min_stake,
                actual: entry.stake,
                class: entry.class.clone(),
            })
        }
    }

    /// Validates a candidate's stake against the configurable requirement
    /// thresholds before admission.
    ///
    /// ## Validation Order
    ///
    /// 1. If `stake == 0` → `Err(GatingError::ZeroStake)`.
    /// 2. Determine `min_stake` from `self.requirement` based on `class`:
    ///    - `NodeClass::Storage` → `requirement.min_stake_storage`
    ///    - `NodeClass::Compute` → `requirement.min_stake_compute`
    /// 3. If `stake >= min_stake` → `Ok(())`.
    /// 4. If `stake < min_stake` → `Err(GatingError::InsufficientStake { .. })`.
    ///
    /// ## Parameters
    ///
    /// - `class`: The node class the candidate claims to qualify for.
    /// - `stake`: The candidate's current on-chain stake (caller-provided).
    ///
    /// ## Returns
    ///
    /// - `Ok(())` if stake meets the requirement for the given class.
    /// - `Err(GatingError::ZeroStake)` if stake is exactly zero.
    /// - `Err(GatingError::InsufficientStake { .. })` if non-zero but insufficient.
    pub fn check_before_admission(
        &self,
        class: &NodeClass,
        stake: u128,
    ) -> Result<(), GatingError> {
        // Step 1: Zero stake is always an error.
        if stake == 0 {
            return Err(GatingError::ZeroStake);
        }

        // Step 2: Determine minimum from configurable requirement.
        let min_stake = match class {
            NodeClass::Storage => self.requirement.min_stake_storage,
            NodeClass::Compute => self.requirement.min_stake_compute,
        };

        // Steps 3 & 4: Compare.
        if stake >= min_stake {
            Ok(())
        } else {
            Err(GatingError::InsufficientStake {
                required: min_stake,
                actual: stake,
                class: class.clone(),
            })
        }
    }
}