//! # Node Status Tracker (14B.44)
//!
//! Provides [`NodeStatusTracker`] for tracking a service node's lifecycle
//! state from the node's own perspective.
//!
//! ## Purpose
//!
//! After a node joins the network, the coordinator assigns it a
//! [`NodeStatus`] (Pending, Active, Quarantined, Banned). The node
//! receives status updates via DA events or coordinator responses.
//! `NodeStatusTracker` maintains a local view of the node's current
//! status and an ordered history of all transitions for auditing.
//!
//! ## State Machine
//!
//! The tracker enforces the same transition rules as the coordinator's
//! `NodeLifecycleManager` (14B.38), using `NodeStatus::can_transition_to`
//! from `dsdn_common`:
//!
//! ```text
//! ┌─────────┐    Approved     ┌────────┐
//! │ Pending │───────────────▶│ Active │
//! │         │                 │        │◀──────────┐
//! └────┬────┘                 └───┬────┘           │
//!      │                          │                │
//!      │ Identity spoof     Stake │ drop /    Stake│ restored /
//!      │                    minor │ slash     released
//!      │                          ▼                │
//!      │                    ┌──────────────┐       │
//!      │                    │ Quarantined  │───────┘
//!      │                    └──────┬───────┘
//!      │                           │
//!      │         Severe slash      │ Escalation
//!      ▼              ▼            ▼
//! ┌─────────┐◀────────────────────────
//! │ Banned  │
//! └────┬────┘
//!      │ Cooldown expired
//!      │
//!      ▼
//! ┌─────────┐
//! │ Pending │  (re-entry)
//! └─────────┘
//! ```
//!
//! ## Invariants
//!
//! - `current_status` always equals the `to` field of the last
//!   `StatusTransition` in `history` (or `Pending` if history is empty).
//! - Timestamps are strictly monotonic: each transition's timestamp
//!   must be ≥ the previous transition's timestamp.
//! - No duplicate transitions at the same timestamp are accepted.
//! - `registered_at` is set to the timestamp of the first transition
//!   away from `Pending` (i.e., the moment the node is first acknowledged).
//!
//! ## Safety
//!
//! - No `panic!`, `unwrap()`, `expect()`.
//! - No `unsafe` code.
//! - All arithmetic uses `saturating_sub` to prevent overflow.
//! - All types are `Send + Sync`.

use std::fmt;

use dsdn_common::gating::{NodeStatus, StatusTransition};

// ════════════════════════════════════════════════════════════════════════════════
// NODE STATUS TRACKER
// ════════════════════════════════════════════════════════════════════════════════

/// Tracks a service node's lifecycle status and transition history.
///
/// Maintains the node's current [`NodeStatus`], an ordered list of
/// [`StatusTransition`] records, and the registration timestamp.
///
/// ## Thread Safety
///
/// `NodeStatusTracker` is `Send + Sync`. All fields are owned values
/// with no interior mutability. External synchronization (e.g., `Mutex`)
/// is required if shared across threads.
pub struct NodeStatusTracker {
    /// The node's current lifecycle status.
    current_status: NodeStatus,
    /// Ordered list of all status transitions (oldest first).
    history: Vec<StatusTransition>,
    /// Timestamp of the first transition away from `Pending`.
    /// `None` if the node has never left `Pending`.
    registered_at: Option<u64>,
}

impl NodeStatusTracker {
    /// Creates a new tracker with initial status `Pending`.
    ///
    /// - `current_status`: `Pending`
    /// - `history`: empty
    /// - `registered_at`: `None`
    ///
    /// This matches the state of a freshly submitted node before
    /// any coordinator response.
    pub fn new() -> Self {
        Self {
            current_status: NodeStatus::Pending,
            history: Vec::new(),
            registered_at: None,
        }
    }

    /// Attempts to transition the node to a new status.
    ///
    /// ## Validation (strict order)
    ///
    /// 1. **Transition legality**: `current_status.can_transition_to(new_status)`
    ///    must return `true`. Illegal transitions are rejected.
    /// 2. **Timestamp monotonicity**: `timestamp` must be ≥ the last
    ///    transition's timestamp. Backwards timestamps are rejected.
    /// 3. **No duplicate**: If `timestamp` equals the last transition's
    ///    timestamp, the transition is rejected (no two transitions at
    ///    the same instant).
    ///
    /// ## Side Effects (on success)
    ///
    /// - A `StatusTransition` is appended to `history`.
    /// - `current_status` is updated to `new_status`.
    /// - If this is the first transition away from `Pending`,
    ///   `registered_at` is set to `timestamp`.
    ///
    /// ## Errors
    ///
    /// Returns `Err(String)` with a descriptive message if validation fails.
    pub fn update_status(
        &mut self,
        new_status: NodeStatus,
        reason: String,
        timestamp: u64,
    ) -> Result<(), String> {
        // Step 1: Validate transition legality
        if !self.current_status.can_transition_to(new_status) {
            return Err(format!(
                "illegal transition: {} -> {} is not allowed",
                self.current_status, new_status,
            ));
        }

        // Step 2 & 3: Validate timestamp monotonicity + no duplicate
        if let Some(last) = self.history.last() {
            if timestamp < last.timestamp {
                return Err(format!(
                    "timestamp {} is before last transition timestamp {}",
                    timestamp, last.timestamp,
                ));
            }
            if timestamp == last.timestamp {
                return Err(format!(
                    "duplicate timestamp {}: two transitions at the same instant are not allowed",
                    timestamp,
                ));
            }
        }

        // Set registered_at on first transition away from Pending
        if self.current_status == NodeStatus::Pending && self.registered_at.is_none() {
            self.registered_at = Some(timestamp);
        }

        // Record transition
        let transition = StatusTransition {
            from: self.current_status,
            to: new_status,
            reason,
            timestamp,
        };
        self.history.push(transition);
        self.current_status = new_status;

        Ok(())
    }

    /// Returns a reference to the current node status.
    #[inline]
    pub fn current(&self) -> &NodeStatus {
        &self.current_status
    }

    /// Returns `true` if the current status is `Active`.
    #[inline]
    pub fn is_active(&self) -> bool {
        self.current_status == NodeStatus::Active
    }

    /// Returns `true` if the current status allows scheduling.
    ///
    /// Delegates to `NodeStatus::is_schedulable()`. Only `Active`
    /// returns `true`.
    #[inline]
    pub fn is_schedulable(&self) -> bool {
        self.current_status.is_schedulable()
    }

    /// Returns the transition history as an immutable slice.
    ///
    /// Transitions are ordered oldest-first. Zero-allocation: returns
    /// a slice reference.
    #[inline]
    pub fn history(&self) -> &[StatusTransition] {
        &self.history
    }

    /// Returns the time spent in the current status.
    ///
    /// Computed as `now - last_transition_timestamp`. If history is
    /// empty (no transitions yet) or `now` is before the last
    /// transition, returns 0.
    ///
    /// Uses `saturating_sub` to prevent underflow.
    #[inline]
    pub fn time_in_current_status(&self, now: u64) -> u64 {
        match self.history.last() {
            Some(last) => now.saturating_sub(last.timestamp),
            None => 0,
        }
    }

    /// Returns the registration timestamp, if the node has transitioned
    /// away from `Pending` at least once.
    #[inline]
    pub fn registered_at(&self) -> Option<u64> {
        self.registered_at
    }
}

impl Default for NodeStatusTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for NodeStatusTracker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeStatusTracker")
            .field("current_status", &self.current_status)
            .field("history_len", &self.history.len())
            .field("registered_at", &self.registered_at)
            .finish()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// COMPILE-TIME ASSERTIONS
// ════════════════════════════════════════════════════════════════════════════════

const _: () = {
    fn assert_send<T: Send>() {}
    fn check() { assert_send::<NodeStatusTracker>(); }
    let _ = check;
};

const _: () = {
    fn assert_sync<T: Sync>() {}
    fn check() { assert_sync::<NodeStatusTracker>(); }
    let _ = check;
};

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    const TS: u64 = 1_700_000_000;

    // ──────────────────────────────────────────────────────────────────
    // CONSTRUCTION
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_new_starts_pending() {
        let tracker = NodeStatusTracker::new();
        assert_eq!(*tracker.current(), NodeStatus::Pending);
        assert!(tracker.history().is_empty());
        assert!(tracker.registered_at().is_none());
        assert!(!tracker.is_active());
        assert!(!tracker.is_schedulable());
    }

    #[test]
    fn test_default_same_as_new() {
        let tracker = NodeStatusTracker::default();
        assert_eq!(*tracker.current(), NodeStatus::Pending);
        assert!(tracker.history().is_empty());
    }

    // ──────────────────────────────────────────────────────────────────
    // VALID TRANSITIONS
    // ──────────────────────────────────────────────────────────────────

    /// Pending → Active
    #[test]
    fn test_transition_pending_to_active() {
        let mut t = NodeStatusTracker::new();
        let result = t.update_status(NodeStatus::Active, "approved".to_string(), TS);
        assert!(result.is_ok());
        assert_eq!(*t.current(), NodeStatus::Active);
        assert!(t.is_active());
        assert!(t.is_schedulable());
        assert_eq!(t.history().len(), 1);
        assert_eq!(t.registered_at(), Some(TS));

        let tr = &t.history()[0];
        assert_eq!(tr.from, NodeStatus::Pending);
        assert_eq!(tr.to, NodeStatus::Active);
        assert_eq!(tr.reason, "approved");
        assert_eq!(tr.timestamp, TS);
    }

    /// Active → Quarantined
    #[test]
    fn test_transition_active_to_quarantined() {
        let mut t = NodeStatusTracker::new();
        assert!(t.update_status(NodeStatus::Active, "approved".to_string(), TS).is_ok());
        let result = t.update_status(NodeStatus::Quarantined, "stake drop".to_string(), TS + 100);
        assert!(result.is_ok());
        assert_eq!(*t.current(), NodeStatus::Quarantined);
        assert!(!t.is_active());
        assert!(!t.is_schedulable());
        assert_eq!(t.history().len(), 2);
    }

    /// Quarantined → Active (recovery)
    #[test]
    fn test_transition_quarantined_to_active() {
        let mut t = NodeStatusTracker::new();
        assert!(t.update_status(NodeStatus::Active, "approved".to_string(), TS).is_ok());
        assert!(t.update_status(NodeStatus::Quarantined, "stake drop".to_string(), TS + 100).is_ok());
        let result = t.update_status(NodeStatus::Active, "stake restored".to_string(), TS + 200);
        assert!(result.is_ok());
        assert!(t.is_active());
        assert_eq!(t.history().len(), 3);
    }

    /// Active → Banned
    #[test]
    fn test_transition_active_to_banned() {
        let mut t = NodeStatusTracker::new();
        assert!(t.update_status(NodeStatus::Active, "approved".to_string(), TS).is_ok());
        let result = t.update_status(NodeStatus::Banned, "severe slashing".to_string(), TS + 100);
        assert!(result.is_ok());
        assert_eq!(*t.current(), NodeStatus::Banned);
    }

    /// Banned → Pending (re-entry)
    #[test]
    fn test_transition_banned_to_pending() {
        let mut t = NodeStatusTracker::new();
        assert!(t.update_status(NodeStatus::Active, "approved".to_string(), TS).is_ok());
        assert!(t.update_status(NodeStatus::Banned, "slashing".to_string(), TS + 100).is_ok());
        let result = t.update_status(NodeStatus::Pending, "cooldown expired".to_string(), TS + 200);
        assert!(result.is_ok());
        assert_eq!(*t.current(), NodeStatus::Pending);
    }

    /// Pending → Banned (identity spoof)
    #[test]
    fn test_transition_pending_to_banned() {
        let mut t = NodeStatusTracker::new();
        let result = t.update_status(NodeStatus::Banned, "identity spoof".to_string(), TS);
        assert!(result.is_ok());
        assert_eq!(*t.current(), NodeStatus::Banned);
        // registered_at is set on first transition away from Pending
        assert_eq!(t.registered_at(), Some(TS));
    }

    /// Quarantined → Banned (escalation)
    #[test]
    fn test_transition_quarantined_to_banned() {
        let mut t = NodeStatusTracker::new();
        assert!(t.update_status(NodeStatus::Active, "ok".to_string(), TS).is_ok());
        assert!(t.update_status(NodeStatus::Quarantined, "stake drop".to_string(), TS + 100).is_ok());
        let result = t.update_status(NodeStatus::Banned, "escalation".to_string(), TS + 200);
        assert!(result.is_ok());
        assert_eq!(*t.current(), NodeStatus::Banned);
        assert_eq!(t.history().len(), 3);
    }

    /// Full lifecycle: Pending → Active → Quarantined → Active → Banned → Pending
    #[test]
    fn test_full_lifecycle() {
        let mut t = NodeStatusTracker::new();
        assert!(t.update_status(NodeStatus::Active, "approved".to_string(), TS).is_ok());
        assert!(t.update_status(NodeStatus::Quarantined, "stake drop".to_string(), TS + 100).is_ok());
        assert!(t.update_status(NodeStatus::Active, "restored".to_string(), TS + 200).is_ok());
        assert!(t.update_status(NodeStatus::Banned, "severe".to_string(), TS + 300).is_ok());
        assert!(t.update_status(NodeStatus::Pending, "cooldown".to_string(), TS + 400).is_ok());

        assert_eq!(*t.current(), NodeStatus::Pending);
        assert_eq!(t.history().len(), 5);
        assert_eq!(t.registered_at(), Some(TS));
    }

    // ──────────────────────────────────────────────────────────────────
    // ILLEGAL TRANSITIONS
    // ──────────────────────────────────────────────────────────────────

    /// Self-transition: Pending → Pending
    #[test]
    fn test_reject_self_transition() {
        let mut t = NodeStatusTracker::new();
        let result = t.update_status(NodeStatus::Pending, "noop".to_string(), TS);
        assert!(result.is_err());
        assert!(t.history().is_empty());
    }

    /// Skip: Pending → Quarantined
    #[test]
    fn test_reject_pending_to_quarantined() {
        let mut t = NodeStatusTracker::new();
        let result = t.update_status(NodeStatus::Quarantined, "invalid".to_string(), TS);
        assert!(result.is_err());
    }

    /// Backward: Active → Pending
    #[test]
    fn test_reject_active_to_pending() {
        let mut t = NodeStatusTracker::new();
        assert!(t.update_status(NodeStatus::Active, "ok".to_string(), TS).is_ok());
        let result = t.update_status(NodeStatus::Pending, "no".to_string(), TS + 100);
        assert!(result.is_err());
        assert_eq!(*t.current(), NodeStatus::Active);
    }

    /// Banned → Active (must go through Pending first)
    #[test]
    fn test_reject_banned_to_active() {
        let mut t = NodeStatusTracker::new();
        assert!(t.update_status(NodeStatus::Active, "ok".to_string(), TS).is_ok());
        assert!(t.update_status(NodeStatus::Banned, "slash".to_string(), TS + 100).is_ok());
        let result = t.update_status(NodeStatus::Active, "skip pending".to_string(), TS + 200);
        assert!(result.is_err());
        assert_eq!(*t.current(), NodeStatus::Banned);
    }

    // ──────────────────────────────────────────────────────────────────
    // TIMESTAMP VALIDATION
    // ──────────────────────────────────────────────────────────────────

    /// Backwards timestamp rejected.
    #[test]
    fn test_reject_backwards_timestamp() {
        let mut t = NodeStatusTracker::new();
        assert!(t.update_status(NodeStatus::Active, "ok".to_string(), TS).is_ok());
        let result = t.update_status(NodeStatus::Quarantined, "drop".to_string(), TS - 1);
        assert!(result.is_err());
        assert_eq!(*t.current(), NodeStatus::Active);
        assert_eq!(t.history().len(), 1);
    }

    /// Duplicate timestamp rejected.
    #[test]
    fn test_reject_duplicate_timestamp() {
        let mut t = NodeStatusTracker::new();
        assert!(t.update_status(NodeStatus::Active, "ok".to_string(), TS).is_ok());
        let result = t.update_status(NodeStatus::Quarantined, "drop".to_string(), TS);
        assert!(result.is_err());
        assert_eq!(*t.current(), NodeStatus::Active);
    }

    // ──────────────────────────────────────────────────────────────────
    // TIME IN CURRENT STATUS
    // ──────────────────────────────────────────────────────────────────

    /// time_in_current_status with no history returns 0.
    #[test]
    fn test_time_no_history() {
        let t = NodeStatusTracker::new();
        assert_eq!(t.time_in_current_status(TS), 0);
    }

    /// time_in_current_status returns correct elapsed time.
    #[test]
    fn test_time_elapsed() {
        let mut t = NodeStatusTracker::new();
        assert!(t.update_status(NodeStatus::Active, "ok".to_string(), TS).is_ok());
        assert_eq!(t.time_in_current_status(TS + 500), 500);
    }

    /// time_in_current_status returns 0 if now < last transition.
    #[test]
    fn test_time_backwards_returns_zero() {
        let mut t = NodeStatusTracker::new();
        assert!(t.update_status(NodeStatus::Active, "ok".to_string(), TS).is_ok());
        assert_eq!(t.time_in_current_status(TS - 100), 0);
    }

    /// time_in_current_status returns 0 if now == last transition.
    #[test]
    fn test_time_at_transition_returns_zero() {
        let mut t = NodeStatusTracker::new();
        assert!(t.update_status(NodeStatus::Active, "ok".to_string(), TS).is_ok());
        assert_eq!(t.time_in_current_status(TS), 0);
    }

    // ──────────────────────────────────────────────────────────────────
    // REGISTERED_AT
    // ──────────────────────────────────────────────────────────────────

    /// registered_at not set before first transition.
    #[test]
    fn test_registered_at_none_initially() {
        let t = NodeStatusTracker::new();
        assert!(t.registered_at().is_none());
    }

    /// registered_at set on first transition from Pending.
    #[test]
    fn test_registered_at_set_on_first_transition() {
        let mut t = NodeStatusTracker::new();
        assert!(t.update_status(NodeStatus::Active, "ok".to_string(), TS).is_ok());
        assert_eq!(t.registered_at(), Some(TS));
    }

    /// registered_at not overwritten on subsequent transitions.
    #[test]
    fn test_registered_at_immutable() {
        let mut t = NodeStatusTracker::new();
        assert!(t.update_status(NodeStatus::Active, "ok".to_string(), TS).is_ok());
        assert!(t.update_status(NodeStatus::Banned, "slash".to_string(), TS + 100).is_ok());
        assert!(t.update_status(NodeStatus::Pending, "cooldown".to_string(), TS + 200).is_ok());
        // Now in Pending again; transition away again
        assert!(t.update_status(NodeStatus::Active, "re-approved".to_string(), TS + 300).is_ok());
        // registered_at should still be the first time
        assert_eq!(t.registered_at(), Some(TS));
    }

    // ──────────────────────────────────────────────────────────────────
    // INVARIANT CHECKS
    // ──────────────────────────────────────────────────────────────────

    /// current_status always matches last transition's `to` field.
    #[test]
    fn test_invariant_current_matches_last_to() {
        let mut t = NodeStatusTracker::new();
        assert!(t.update_status(NodeStatus::Active, "ok".to_string(), TS).is_ok());
        assert!(t.update_status(NodeStatus::Quarantined, "drop".to_string(), TS + 100).is_ok());
        assert!(t.update_status(NodeStatus::Active, "restored".to_string(), TS + 200).is_ok());

        let last = t.history().last();
        assert!(last.is_some());
        if let Some(last_tr) = last {
            assert_eq!(*t.current(), last_tr.to);
        }
    }

    /// Failed transition does not modify any state.
    #[test]
    fn test_failed_transition_no_side_effects() {
        let mut t = NodeStatusTracker::new();
        assert!(t.update_status(NodeStatus::Active, "ok".to_string(), TS).is_ok());
        let prev_len = t.history().len();
        let prev_status = *t.current();

        // Illegal transition
        let _ = t.update_status(NodeStatus::Pending, "nope".to_string(), TS + 100);
        assert_eq!(t.history().len(), prev_len);
        assert_eq!(*t.current(), prev_status);
    }

    // ──────────────────────────────────────────────────────────────────
    // DEBUG
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_debug_output() {
        let t = NodeStatusTracker::new();
        let debug_str = format!("{:?}", t);
        assert!(debug_str.contains("NodeStatusTracker"));
        assert!(debug_str.contains("Pending"));
    }
}