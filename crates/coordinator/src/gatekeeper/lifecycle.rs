//! # Node Lifecycle Manager (14B.38)
//!
//! Provides [`NodeLifecycleManager`] and [`StatusTransition`] for
//! orchestrating node status transitions across the GateKeeper,
//! QuarantineManager, and BanEnforcer subsystems.
//!
//! ## Design
//!
//! The lifecycle manager is an explicit state machine that coordinates
//! all status changes for service nodes. Every transition is:
//!
//! - **Explicit**: represented by a [`StatusTransition`] enum variant.
//! - **Atomic**: no partial updates — either the full transition completes
//!   or nothing changes.
//! - **Deterministic**: same inputs always produce the same transitions.
//!
//! ## Invariants
//!
//! 1. A node is never Active AND Banned simultaneously.
//! 2. A node is never Quarantined AND Banned simultaneously.
//! 3. Ban takes precedence over Quarantine.
//! 4. All transitions are recorded — no silent state mutation.
//!
//! ## Ownership
//!
//! The lifecycle manager **owns** the GateKeeper, QuarantineManager,
//! and BanEnforcer. All three are accessed through `&self` or `&mut self`
//! — no shared references, no interior mutability.
//!
//! ## Safety
//!
//! - No `panic!`, `unwrap()`, `expect()`.
//! - No system clock, no I/O, no side effects beyond owned state.
//! - All timestamp arithmetic delegates to `CooldownPeriod` (uses
//!   `saturating_add` internally).
//! - All types `Send + Sync`.

use dsdn_common::gating::{CooldownPeriod, NodeClass, NodeStatus};

use super::admission::{AdmissionRequest, AdmissionResponse};
use super::ban::BanEnforcer;
use super::quarantine::QuarantineManager;
use super::GateKeeper;

// ════════════════════════════════════════════════════════════════════════════════
// STATUS TRANSITION ENUM
// ════════════════════════════════════════════════════════════════════════════════

/// Represents an explicit, auditable status change for a service node.
///
/// Every state mutation performed by [`NodeLifecycleManager`] produces
/// one or more `StatusTransition` values. No implicit state changes occur.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StatusTransition {
    /// Node transitioned to `Active` status.
    Activated { node_id: String },
    /// Node transitioned to `Quarantined` status.
    Quarantined { node_id: String, reason: String },
    /// Node transitioned to `Banned` status.
    Banned { node_id: String, reason: String },
    /// Node released from quarantine (without activation — intermediate state).
    ReleasedFromQuarantine { node_id: String },
    /// Node's ban cooldown expired; status set to `Pending`.
    BanExpired { node_id: String },
}

// ════════════════════════════════════════════════════════════════════════════════
// NODE LIFECYCLE MANAGER
// ════════════════════════════════════════════════════════════════════════════════

/// Orchestrates node status transitions across gating subsystems.
///
/// Owns the [`GateKeeper`], [`QuarantineManager`], and [`BanEnforcer`],
/// ensuring all state mutations go through a single coordination point.
///
/// ## Thread Safety
///
/// All fields are owned types with no interior mutability. The struct
/// is `Send + Sync`.
#[derive(Debug)]
pub struct NodeLifecycleManager {
    /// The gatekeeper that manages node admission and the registry cache.
    pub gatekeeper: GateKeeper,
    /// Tracks quarantined nodes and detects escalation conditions.
    pub quarantine_mgr: QuarantineManager,
    /// Tracks banned nodes with cooldown-based expiry.
    pub ban_enforcer: BanEnforcer,
}

impl NodeLifecycleManager {
    /// Creates a new lifecycle manager from pre-constructed components.
    ///
    /// No side effects. No validation of component state — the caller
    /// is responsible for providing correctly initialized subsystems.
    pub fn new(
        gatekeeper: GateKeeper,
        quarantine_mgr: QuarantineManager,
        ban_enforcer: BanEnforcer,
    ) -> Self {
        Self {
            gatekeeper,
            quarantine_mgr,
            ban_enforcer,
        }
    }

    // ────────────────────────────────────────────────────────────────────
    // 1. ADMISSION
    // ────────────────────────────────────────────────────────────────────

    /// Processes a node join request by delegating to the GateKeeper.
    ///
    /// If the admission is rejected due to identity spoofing
    /// (`assigned_status == Banned`), the node is recorded in the
    /// [`BanEnforcer`] with a severe cooldown to prevent re-admission.
    ///
    /// ## Parameters
    ///
    /// - `request`: Admission request (consumed by GateKeeper).
    /// - `stake`: Caller-provided on-chain stake.
    /// - `cooldown`: Optional active slashing cooldown.
    /// - `timestamp`: Caller-provided Unix timestamp.
    ///
    /// ## Determinism
    ///
    /// Same inputs always produce the same response and ban state.
    pub fn process_join(
        &mut self,
        request: AdmissionRequest,
        stake: u128,
        cooldown: Option<CooldownPeriod>,
        timestamp: u64,
    ) -> AdmissionResponse {
        let response = self.gatekeeper.process_admission(
            request, stake, cooldown, timestamp,
        );

        // If rejected due to identity spoof → record ban in enforcer.
        // The GateKeeper already set assigned_status = Banned, but it does
        // NOT insert into the registry on rejection. We record the ban in
        // BanEnforcer to prevent future admission attempts.
        if !response.approved && response.assigned_status == NodeStatus::Banned {
            let node_id_hex = bytes_to_hex(&response.report.node_identity.node_id);
            let operator = response.report.node_identity.operator_address;

            let severe_secs = self
                .gatekeeper
                .config
                .policy
                .cooldown_config
                .severe_cooldown_secs;

            let ban_cooldown = CooldownPeriod {
                start_timestamp: timestamp,
                duration_secs: severe_secs,
                reason: "identity spoof detected during admission".to_string(),
            };

            self.ban_enforcer.ban_node(
                &node_id_hex,
                operator,
                "identity spoof detected during admission".to_string(),
                ban_cooldown,
            );
        }

        response
    }

    // ────────────────────────────────────────────────────────────────────
    // 2. STAKE CHANGE
    // ────────────────────────────────────────────────────────────────────

    /// Processes a stake change for a registered node.
    ///
    /// ## Cases
    ///
    /// **A — Stake drops below minimum (Active → Quarantined)**:
    /// Updates registry status, inserts quarantine record, returns
    /// `Quarantined` transition.
    ///
    /// **B — Stake restored above minimum (Quarantined → Active)**:
    /// Updates registry status, releases quarantine, returns
    /// `Activated` transition.
    ///
    /// **C — No status impact**: Updates stake value in registry,
    /// returns `None`.
    ///
    /// ## Returns
    ///
    /// `None` if the node is not in the registry, or if the stake
    /// change does not trigger a status transition.
    pub fn process_stake_change(
        &mut self,
        node_id: &str,
        new_stake: u128,
        timestamp: u64,
    ) -> Option<StatusTransition> {
        // Look up node — return None if not registered.
        let entry = self.gatekeeper.registry.get(node_id)?;

        let current_status = entry.status.clone();
        let operator = entry.identity.operator_address;
        let min_stake = min_stake_for_class(
            &entry.class,
            &self.gatekeeper.config.policy,
        );

        match current_status {
            // Case A: Active node with insufficient stake → quarantine.
            NodeStatus::Active if new_stake < min_stake => {
                let reason = "stake below minimum threshold".to_string();

                // Update registry atomically.
                let entry = self.gatekeeper.registry.get_mut(node_id)?;
                entry.status = NodeStatus::Quarantined;
                entry.stake = new_stake;
                entry.last_status_change = timestamp;

                // Record in quarantine manager.
                let default_secs = self
                    .gatekeeper
                    .config
                    .policy
                    .cooldown_config
                    .default_cooldown_secs;

                self.quarantine_mgr.quarantine_node(
                    node_id,
                    operator,
                    reason.clone(),
                    timestamp,
                    default_secs,
                );

                Some(StatusTransition::Quarantined {
                    node_id: node_id.to_string(),
                    reason,
                })
            }

            // Case B: Quarantined node with restored stake → activate.
            NodeStatus::Quarantined if new_stake >= min_stake => {
                // Update registry atomically.
                let entry = self.gatekeeper.registry.get_mut(node_id)?;
                entry.status = NodeStatus::Active;
                entry.stake = new_stake;
                entry.last_status_change = timestamp;

                // Release from quarantine manager.
                self.quarantine_mgr.release_node(node_id);

                Some(StatusTransition::Activated {
                    node_id: node_id.to_string(),
                })
            }

            // Case C: No status-affecting change — just update stake.
            _ => {
                let entry = self.gatekeeper.registry.get_mut(node_id)?;
                entry.stake = new_stake;
                None
            }
        }
    }

    // ────────────────────────────────────────────────────────────────────
    // 3. SLASHING
    // ────────────────────────────────────────────────────────────────────

    /// Processes a slashing event for a registered node.
    ///
    /// ## Parameters
    ///
    /// - `severity`: `false` = minor (quarantine), `true` = severe (ban).
    /// - `timestamp`: Caller-provided Unix timestamp.
    ///
    /// ## Rules
    ///
    /// - **Minor** (`severity == false`): Quarantine the node. Skipped if
    ///   already Banned (ban > quarantine precedence) or already Quarantined
    ///   (no double-quarantine).
    ///
    /// - **Severe** (`severity == true`): Ban the node. Remove from
    ///   quarantine if present. Skipped if already Banned.
    ///
    /// ## Returns
    ///
    /// `None` if the node is not in the registry, or if the action was
    /// skipped due to precedence rules.
    pub fn process_slashing(
        &mut self,
        node_id: &str,
        severity: bool,
        timestamp: u64,
    ) -> Option<StatusTransition> {
        // Look up node — return None if not registered.
        let entry = self.gatekeeper.registry.get(node_id)?;
        let current_status = entry.status.clone();
        let operator = entry.identity.operator_address;

        if severity {
            // ── Severe slashing → Ban ──

            // Don't re-ban an already banned node.
            if current_status == NodeStatus::Banned {
                return None;
            }

            let reason = "severe slashing penalty".to_string();
            let severe_secs = self
                .gatekeeper
                .config
                .policy
                .cooldown_config
                .severe_cooldown_secs;

            let ban_cooldown = CooldownPeriod {
                start_timestamp: timestamp,
                duration_secs: severe_secs,
                reason: reason.clone(),
            };

            // Update registry atomically.
            let entry = self.gatekeeper.registry.get_mut(node_id)?;
            entry.status = NodeStatus::Banned;
            entry.last_status_change = timestamp;
            entry.cooldown = Some(ban_cooldown.clone());

            // Remove from quarantine if present (ban > quarantine).
            self.quarantine_mgr.release_node(node_id);

            // Record in ban enforcer.
            self.ban_enforcer.ban_node(
                node_id,
                operator,
                reason.clone(),
                ban_cooldown,
            );

            Some(StatusTransition::Banned {
                node_id: node_id.to_string(),
                reason,
            })
        } else {
            // ── Minor slashing → Quarantine ──

            // Ban > Quarantine precedence: don't quarantine a banned node.
            if current_status == NodeStatus::Banned {
                return None;
            }

            // Don't double-quarantine.
            if current_status == NodeStatus::Quarantined {
                return None;
            }

            let reason = "minor slashing penalty".to_string();
            let default_secs = self
                .gatekeeper
                .config
                .policy
                .cooldown_config
                .default_cooldown_secs;

            // Update registry atomically.
            let entry = self.gatekeeper.registry.get_mut(node_id)?;
            entry.status = NodeStatus::Quarantined;
            entry.last_status_change = timestamp;

            // Record in quarantine manager.
            self.quarantine_mgr.quarantine_node(
                node_id,
                operator,
                reason.clone(),
                timestamp,
                default_secs,
            );

            Some(StatusTransition::Quarantined {
                node_id: node_id.to_string(),
                reason,
            })
        }
    }

    // ────────────────────────────────────────────────────────────────────
    // 4. PERIODIC MAINTENANCE
    // ────────────────────────────────────────────────────────────────────

    /// Runs periodic maintenance: escalates expired quarantines and
    /// clears expired bans.
    ///
    /// ## Steps
    ///
    /// 1. **Quarantine escalation**: Nodes whose quarantine max duration
    ///    has been exceeded are escalated to `Banned`. They are removed
    ///    from the quarantine manager and inserted into the ban enforcer
    ///    with a default ban cooldown.
    ///
    /// 2. **Ban expiry**: Nodes whose ban cooldown has expired are cleared
    ///    from the ban enforcer and their registry status is set to `Pending`
    ///    (requiring re-admission to become Active again).
    ///
    /// ## Determinism
    ///
    /// The returned `Vec<StatusTransition>` is sorted by (transition type
    /// ordinal, node_id) to ensure deterministic ordering regardless of
    /// `HashMap` iteration order.
    ///
    /// ## Atomicity
    ///
    /// Each individual node transition is atomic — no partial updates.
    /// Transitions are collected into a Vec before return; no short-circuit
    /// on individual failures.
    pub fn periodic_maintenance(
        &mut self,
        timestamp: u64,
    ) -> Vec<StatusTransition> {
        let mut transitions = Vec::new();

        // ── Step 1: Quarantine escalation ──
        //
        // check_escalations returns node_ids whose quarantine max duration
        // has been exceeded. These are escalated to Ban.
        let escalated = self.quarantine_mgr.check_escalations(timestamp);

        for node_id in &escalated {
            // Get operator address from registry. Skip if node vanished.
            let operator = match self.gatekeeper.registry.get(node_id.as_str()) {
                Some(entry) => entry.identity.operator_address,
                None => continue,
            };

            // Remove from quarantine (release before banning).
            self.quarantine_mgr.release_node(node_id);

            // Construct ban cooldown from policy.
            let default_secs = self
                .gatekeeper
                .config
                .policy
                .cooldown_config
                .default_cooldown_secs;

            let reason =
                "quarantine escalation: max duration exceeded".to_string();

            let ban_cooldown = CooldownPeriod {
                start_timestamp: timestamp,
                duration_secs: default_secs,
                reason: reason.clone(),
            };

            // Record in ban enforcer.
            self.ban_enforcer.ban_node(
                node_id,
                operator,
                reason.clone(),
                ban_cooldown.clone(),
            );

            // Update registry status.
            if let Some(entry) =
                self.gatekeeper.registry.get_mut(node_id.as_str())
            {
                entry.status = NodeStatus::Banned;
                entry.last_status_change = timestamp;
                entry.cooldown = Some(ban_cooldown);
            }

            transitions.push(StatusTransition::Banned {
                node_id: node_id.clone(),
                reason,
            });
        }

        // ── Step 2: Ban expiry ──
        //
        // check_expired_bans returns node_ids whose ban cooldown has expired.
        // Clear each and set registry status to Pending.
        let expired_bans = self.ban_enforcer.check_expired_bans(timestamp);

        for node_id in &expired_bans {
            if self.ban_enforcer.clear_expired_ban(node_id, timestamp) {
                // Update registry: Banned → Pending (requires re-admission).
                if let Some(entry) =
                    self.gatekeeper.registry.get_mut(node_id.as_str())
                {
                    entry.status = NodeStatus::Pending;
                    entry.last_status_change = timestamp;
                    entry.cooldown = None;
                }

                transitions.push(StatusTransition::BanExpired {
                    node_id: node_id.clone(),
                });
            }
        }

        // ── Deterministic sort ──
        transitions.sort_by(|a, b| {
            transition_sort_key(a).cmp(&transition_sort_key(b))
        });

        transitions
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS (module-private)
// ════════════════════════════════════════════════════════════════════════════════

/// Returns the minimum stake for a given node class per the gating policy.
///
/// Uses the policy's `StakeRequirement` rather than `NodeClass::min_stake()`
/// to respect runtime-configurable thresholds.
fn min_stake_for_class(
    class: &NodeClass,
    policy: &dsdn_common::gating::GatingPolicy,
) -> u128 {
    match class {
        NodeClass::Storage => policy.stake_requirement.min_stake_storage,
        NodeClass::Compute => policy.stake_requirement.min_stake_compute,
    }
}

/// Converts a 32-byte node ID to a lowercase hex string (64 characters).
///
/// Deterministic: same bytes always produce the same string.
fn bytes_to_hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Returns a sortable key `(type_ordinal, node_id)` for deterministic
/// ordering of `StatusTransition` values.
///
/// Ordinals:
/// - 0 = Activated
/// - 1 = ReleasedFromQuarantine
/// - 2 = Quarantined
/// - 3 = Banned
/// - 4 = BanExpired
fn transition_sort_key(t: &StatusTransition) -> (u8, &str) {
    match t {
        StatusTransition::Activated { node_id } => (0, node_id),
        StatusTransition::ReleasedFromQuarantine { node_id } => (1, node_id),
        StatusTransition::Quarantined { node_id, .. } => (2, node_id),
        StatusTransition::Banned { node_id, .. } => (3, node_id),
        StatusTransition::BanExpired { node_id } => (4, node_id),
    }
}