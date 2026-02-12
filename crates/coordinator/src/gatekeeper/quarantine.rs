//! # Quarantine Manager (14B.36)
//!
//! Provides [`QuarantineRecord`] and [`QuarantineManager`] for tracking
//! nodes that have been placed in quarantine status.
//!
//! ## Design
//!
//! The quarantine manager is a **tracking-only** component. It maintains
//! metadata about quarantined nodes and can determine which nodes should
//! be escalated (quarantine → banned) based on time expiry. It does NOT
//! directly mutate node status — that responsibility belongs to the caller
//! (e.g., GateKeeper or coordinator enforcement logic).
//!
//! ## Escalation
//!
//! [`QuarantineManager::check_escalations`] returns a sorted list of node
//! IDs whose quarantine period has expired. The caller decides whether to
//! transition these nodes to `Banned` status.
//!
//! ## Safety
//!
//! - No `panic!`, `unwrap()`, `expect()`.
//! - Overflow-safe timestamp arithmetic (uses `checked_add`).
//! - Deterministic: same inputs → same outputs.
//! - No network calls, no system clock, no side effects.

use std::collections::HashMap;

// ════════════════════════════════════════════════════════════════════════════════
// QUARANTINE RECORD
// ════════════════════════════════════════════════════════════════════════════════

/// Metadata for a single quarantined node.
///
/// Records when the node was quarantined, why, and for how long.
/// The `operator` field stores the 20-byte operator wallet address
/// (same representation as `NodeIdentity::operator_address` in `dsdn_common`).
#[derive(Clone, Debug)]
pub struct QuarantineRecord {
    /// The node's registry key (hex string of 32-byte node ID, or coordinator node ID).
    pub node_id: String,
    /// The 20-byte operator wallet address associated with this node.
    /// Uses `[u8; 20]` to match `NodeIdentity::operator_address` from `dsdn_common`,
    /// avoiding a dependency on `dsdn_chain::types::Address`.
    pub operator: [u8; 20],
    /// Human-readable reason for the quarantine.
    pub reason: String,
    /// Unix timestamp (seconds) when the node was quarantined.
    pub quarantined_at: u64,
    /// Maximum quarantine duration in seconds. When
    /// `current_timestamp >= quarantined_at + max_quarantine_secs`,
    /// the node is eligible for escalation.
    pub max_quarantine_secs: u64,
}

// ════════════════════════════════════════════════════════════════════════════════
// QUARANTINE MANAGER
// ════════════════════════════════════════════════════════════════════════════════

/// Tracks quarantined nodes and checks for escalation eligibility.
///
/// Maintains a `HashMap<String, QuarantineRecord>` keyed by `node_id`.
/// No duplicate entries are possible — inserting the same `node_id`
/// overwrites the previous record.
///
/// ## Thread Safety
///
/// `QuarantineManager` is `Send + Sync` — it contains no interior
/// mutability, `Rc`, raw pointers, or `Cell` types.
#[derive(Clone, Debug, Default)]
pub struct QuarantineManager {
    /// Map of quarantined node IDs to their quarantine records.
    pub quarantined_nodes: HashMap<String, QuarantineRecord>,
}

impl QuarantineManager {
    /// Creates a new empty [`QuarantineManager`].
    pub fn new() -> Self {
        Self {
            quarantined_nodes: HashMap::new(),
        }
    }

    /// Records a node as quarantined, or replaces an existing quarantine record.
    ///
    /// If `node_id` already exists in the map, the record is overwritten.
    /// No other entries are modified. No panic on duplicate or empty `node_id`.
    ///
    /// ## Parameters
    ///
    /// - `node_id`: Registry key for the node.
    /// - `operator`: 20-byte operator wallet address.
    /// - `reason`: Human-readable quarantine reason.
    /// - `timestamp`: Unix timestamp (seconds) when quarantine starts.
    /// - `max_secs`: Maximum quarantine duration in seconds.
    pub fn quarantine_node(
        &mut self,
        node_id: &str,
        operator: [u8; 20],
        reason: String,
        timestamp: u64,
        max_secs: u64,
    ) {
        let record = QuarantineRecord {
            node_id: node_id.to_string(),
            operator,
            reason,
            quarantined_at: timestamp,
            max_quarantine_secs: max_secs,
        };
        self.quarantined_nodes.insert(node_id.to_string(), record);
    }

    /// Removes a node from quarantine and returns its record.
    ///
    /// Returns `Some(QuarantineRecord)` if the node was quarantined,
    /// `None` if it was not found. No panic.
    pub fn release_node(&mut self, node_id: &str) -> Option<QuarantineRecord> {
        self.quarantined_nodes.remove(node_id)
    }

    /// Returns a sorted list of node IDs whose quarantine period has expired.
    ///
    /// A node is eligible for escalation when:
    /// ```text
    /// current_timestamp >= quarantined_at + max_quarantine_secs
    /// ```
    ///
    /// ## Overflow Safety
    ///
    /// Uses `u64::checked_add` for `quarantined_at + max_quarantine_secs`.
    /// If the addition would overflow `u64::MAX`, the node is treated as
    /// **not eligible** for escalation (conservative: infinite quarantine
    /// rather than premature escalation).
    ///
    /// ## Determinism
    ///
    /// The returned `Vec<String>` is sorted lexicographically to ensure
    /// deterministic ordering regardless of `HashMap` iteration order.
    ///
    /// ## Edge Cases
    ///
    /// - `max_quarantine_secs == 0`: node is immediately eligible for
    ///   escalation if `current_timestamp >= quarantined_at`.
    /// - `current_timestamp < quarantined_at`: not eligible (quarantine
    ///   hasn't started from the perspective of the provided timestamp).
    /// - Empty manager: returns empty `Vec`.
    pub fn check_escalations(&self, current_timestamp: u64) -> Vec<String> {
        let mut escalated: Vec<String> = self
            .quarantined_nodes
            .iter()
            .filter(|(_, record)| {
                // Overflow-safe: if addition overflows, treat as not eligible.
                match record.quarantined_at.checked_add(record.max_quarantine_secs) {
                    Some(expiry) => current_timestamp >= expiry,
                    None => false, // overflow → conservative: never escalate
                }
            })
            .map(|(node_id, _)| node_id.clone())
            .collect();

        // Deterministic ordering: sort lexicographically.
        escalated.sort();
        escalated
    }

    /// Returns `true` if the given node ID is currently quarantined.
    pub fn is_quarantined(&self, node_id: &str) -> bool {
        self.quarantined_nodes.contains_key(node_id)
    }

    /// Returns an immutable reference to the quarantine record for a node,
    /// or `None` if the node is not quarantined.
    pub fn get_quarantine_info(&self, node_id: &str) -> Option<&QuarantineRecord> {
        self.quarantined_nodes.get(node_id)
    }
}