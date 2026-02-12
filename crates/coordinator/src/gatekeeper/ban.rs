//! # Ban Enforcer (14B.37)
//!
//! Provides [`BanRecord`] and [`BanEnforcer`] for tracking banned nodes
//! and enforcing cooldown-based ban expiry.
//!
//! ## Design
//!
//! The ban enforcer is a **state-tracking** component. It maintains
//! metadata about banned nodes and determines whether a ban is still
//! active based on the [`CooldownPeriod`] attached to each record.
//! It does NOT directly mutate node status in the registry — that
//! responsibility belongs to the caller.
//!
//! ## Cooldown Integration
//!
//! Each [`BanRecord`] contains a [`CooldownPeriod`] from `dsdn_common`.
//! Ban activity is determined by [`CooldownPeriod::is_active`], which
//! uses `saturating_add` for overflow-safe expiry calculation.
//!
//! ## Deviations from Spec
//!
//! 1. **`operator` field type**: Spec declares `operator: Address` but the
//!    coordinator crate has no dependency on `dsdn_chain::types::Address`.
//!    Uses `[u8; 20]` instead, consistent with
//!    `NodeIdentity::operator_address` from `dsdn_common`.
//!
//! 2. **`is_banned` parameter**: Spec declares `is_banned(&self, node_id)`
//!    but also requires checking cooldown activity, which needs a timestamp.
//!    Added `current_timestamp: u64` parameter — `CooldownPeriod::is_active()`
//!    requires it. Without this parameter, cooldown cannot be evaluated.
//!
//! 3. **`ban_node` parameter**: Spec omits `operator` but `BanRecord`
//!    requires it. Added `operator: [u8; 20]` parameter.
//!
//! ## Safety
//!
//! - No `panic!`, `unwrap()`, `expect()`.
//! - Overflow-safe: delegates to `CooldownPeriod::is_active()` and
//!   `CooldownPeriod::expires_at()`, both of which use `saturating_add`.
//! - Deterministic: same inputs → same outputs.
//! - No network calls, no system clock, no side effects.
//! - All types `Send + Sync`.

use std::collections::HashMap;

use dsdn_common::gating::CooldownPeriod;

// ════════════════════════════════════════════════════════════════════════════════
// BAN RECORD
// ════════════════════════════════════════════════════════════════════════════════

/// Metadata for a single banned node.
///
/// Records when the node was banned, why, and the cooldown period that
/// governs when the ban expires. The `banned_at` field is derived from
/// `cooldown.start_timestamp` for consistency.
#[derive(Clone, Debug)]
pub struct BanRecord {
    /// The node's registry key.
    pub node_id: String,
    /// The 20-byte operator wallet address associated with this node.
    ///
    /// Uses `[u8; 20]` to match `NodeIdentity::operator_address` from `dsdn_common`,
    /// avoiding a dependency on `dsdn_chain::types::Address`.
    pub operator: [u8; 20],
    /// Human-readable reason for the ban.
    pub reason: String,
    /// Unix timestamp (seconds) when the node was banned.
    /// Derived from `cooldown.start_timestamp` for consistency.
    pub banned_at: u64,
    /// Cooldown period governing ban duration and expiry.
    /// Ban is active while `cooldown.is_active(current_timestamp)` returns `true`.
    pub cooldown: CooldownPeriod,
}

// ════════════════════════════════════════════════════════════════════════════════
// BAN ENFORCER
// ════════════════════════════════════════════════════════════════════════════════

/// Tracks banned nodes and enforces cooldown-based ban expiry.
///
/// Maintains a `HashMap<String, BanRecord>` keyed by `node_id`.
/// No duplicate entries are possible — inserting the same `node_id`
/// overwrites the previous record.
///
/// ## Thread Safety
///
/// `BanEnforcer` is `Send + Sync` — it contains no interior
/// mutability, `Rc`, raw pointers, or `Cell` types.
#[derive(Clone, Debug, Default)]
pub struct BanEnforcer {
    /// Map of banned node IDs to their ban records.
    pub banned_nodes: HashMap<String, BanRecord>,
}

impl BanEnforcer {
    /// Creates a new empty [`BanEnforcer`].
    pub fn new() -> Self {
        Self {
            banned_nodes: HashMap::new(),
        }
    }

    /// Records a node as banned, or replaces an existing ban record.
    ///
    /// `banned_at` is set to `cooldown.start_timestamp` for consistency
    /// between the ban record and the cooldown period.
    ///
    /// If `node_id` already exists in the map, the record is overwritten.
    /// No other entries are modified. No panic on duplicate or empty `node_id`.
    ///
    /// ## Parameters
    ///
    /// - `node_id`: Registry key for the node.
    /// - `operator`: 20-byte operator wallet address.
    /// - `reason`: Human-readable ban reason.
    /// - `cooldown`: Cooldown period governing ban duration.
    ///
    /// ## Deviation from Spec
    ///
    /// The `operator` parameter is not in the original spec method signature,
    /// but `BanRecord` requires it. Added here — record cannot be
    /// constructed without the operator address.
    pub fn ban_node(
        &mut self,
        node_id: &str,
        operator: [u8; 20],
        reason: String,
        cooldown: CooldownPeriod,
    ) {
        let record = BanRecord {
            node_id: node_id.to_string(),
            operator,
            reason,
            banned_at: cooldown.start_timestamp,
            cooldown,
        };
        self.banned_nodes.insert(node_id.to_string(), record);
    }

    /// Returns `true` if the given node is banned and the ban is still active.
    ///
    /// A node is considered banned if:
    /// 1. It exists in `banned_nodes`, AND
    /// 2. `cooldown.is_active(current_timestamp)` returns `true`.
    ///
    /// If the entry exists but the cooldown has expired, returns `false`.
    /// If the entry does not exist, returns `false`.
    ///
    /// This method does NOT mutate state.
    ///
    /// ## Deviation from Spec
    ///
    /// The `current_timestamp` parameter is not in the original spec signature,
    /// but `CooldownPeriod::is_active()` requires it. Without a timestamp,
    /// cooldown activity cannot be determined.
    pub fn is_banned(&self, node_id: &str, current_timestamp: u64) -> bool {
        match self.banned_nodes.get(node_id) {
            Some(record) => record.cooldown.is_active(current_timestamp),
            None => false,
        }
    }

    /// Returns a sorted list of node IDs whose ban cooldown has expired.
    ///
    /// A ban is expired when `cooldown.is_active(current_timestamp)` returns
    /// `false`, meaning `current_timestamp >= cooldown.expires_at()`.
    ///
    /// ## Determinism
    ///
    /// The returned `Vec<String>` is sorted lexicographically to ensure
    /// deterministic ordering regardless of `HashMap` iteration order.
    ///
    /// ## Overflow Safety
    ///
    /// Delegates to `CooldownPeriod::is_active()` and `expires_at()`,
    /// which use `saturating_add` internally. No overflow possible.
    ///
    /// ## Edge Cases
    ///
    /// - `cooldown.duration_secs == 0`: ban expires immediately at
    ///   `start_timestamp` (since `is_active` checks `current_timestamp < expires_at`).
    /// - `current_timestamp < cooldown.start_timestamp`: ban is active
    ///   (conservative behavior from `CooldownPeriod::is_active`).
    /// - Empty enforcer: returns empty `Vec`.
    pub fn check_expired_bans(&self, current_timestamp: u64) -> Vec<String> {
        let mut expired: Vec<String> = self
            .banned_nodes
            .iter()
            .filter(|(_, record)| !record.cooldown.is_active(current_timestamp))
            .map(|(node_id, _)| node_id.clone())
            .collect();

        // Deterministic ordering: sort lexicographically.
        expired.sort();
        expired
    }

    /// Clears an expired ban for a node and returns `true` on success.
    ///
    /// ## Returns
    ///
    /// - `false` if the node is not in `banned_nodes`.
    /// - `false` if the cooldown is still active at `current_timestamp`.
    /// - `true` if the ban was expired and the entry was removed.
    ///
    /// ## Atomicity
    ///
    /// The entry is removed only when all conditions are met. No partial
    /// mutation occurs — either the full entry is removed or nothing changes.
    pub fn clear_expired_ban(&mut self, node_id: &str, current_timestamp: u64) -> bool {
        // Check existence and cooldown status before removal.
        let is_expired = match self.banned_nodes.get(node_id) {
            Some(record) => !record.cooldown.is_active(current_timestamp),
            None => return false,
        };

        if is_expired {
            self.banned_nodes.remove(node_id);
            true
        } else {
            false
        }
    }

    /// Returns an immutable reference to the ban record for a node,
    /// or `None` if the node is not banned.
    pub fn get_ban_info(&self, node_id: &str) -> Option<&BanRecord> {
        self.banned_nodes.get(node_id)
    }
}