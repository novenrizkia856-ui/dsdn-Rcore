//! # Quarantine Handler (14B.45)
//!
//! Provides [`QuarantineHandler`] for processing quarantine notifications
//! from the coordinator and managing the node's quarantine lifecycle.
//!
//! ## Purpose
//!
//! When the coordinator quarantines a node (stake drop, minor violation),
//! the node receives a notification via DA events or coordinator response.
//! `QuarantineHandler` processes this notification by:
//!
//! 1. Transitioning the [`NodeStatusTracker`] to `Quarantined`.
//! 2. Recording the quarantine reason and timestamp.
//! 3. Providing quarantine duration tracking.
//! 4. Evaluating stake-based recovery eligibility.
//!
//! ## Workload Rejection
//!
//! Quarantined nodes must not accept new workloads. This is enforced
//! logically: callers check `is_quarantined()` or
//! `NodeStatusTracker::is_schedulable()` before assigning work.
//! The handler does not modify any scheduler or workload module.
//!
//! ## Relation to GateKeeper / NodeLifecycleManager
//!
//! The coordinator's `QuarantineManager` (14B.36) and
//! `NodeLifecycleManager` (14B.38) manage the authoritative quarantine
//! state. `QuarantineHandler` is the **node-side reaction**: it applies
//! the coordinator's decision locally using the same transition rules
//! (`NodeStatus::can_transition_to`).
//!
//! ## Recovery Model
//!
//! Recovery from quarantine requires:
//!
//! 1. The node's current stake ≥ the required minimum stake.
//! 2. The coordinator to explicitly transition the node back to `Active`.
//!
//! `attempt_recovery` is a **pure read-only check** — it does not
//! change any state. The actual recovery transition is performed by
//! the coordinator and applied locally via a separate `update_status`
//! call on the tracker.
//!
//! ## State Consistency Invariant
//!
//! - `quarantine_reason` is `Some` if and only if current status is `Quarantined`.
//! - `quarantined_since` is `Some` if and only if current status is `Quarantined`.
//! - When the tracker transitions away from `Quarantined` (externally),
//!   the handler's metadata must be cleared via `clear_quarantine_metadata`.
//!
//! ## Safety
//!
//! - No `panic!`, `unwrap()`, `expect()`.
//! - No `unsafe` code.
//! - All arithmetic uses `saturating_sub`.
//! - No implicit auto-recovery.
//! - No modification of other modules.

use dsdn_common::gating::NodeStatus;

use crate::status_tracker::NodeStatusTracker;

// ════════════════════════════════════════════════════════════════════════════════
// QUARANTINE HANDLER
// ════════════════════════════════════════════════════════════════════════════════

/// Processes quarantine notifications and tracks quarantine metadata.
///
/// Wraps a [`NodeStatusTracker`] via mutable borrow (`&'a mut`) to
/// apply quarantine transitions and store quarantine-specific metadata
/// (reason, timestamp). The borrow enforces exclusive access at
/// compile time — no concurrent modification is possible.
///
/// ## Ownership Model
///
/// `QuarantineHandler` borrows `&'a mut NodeStatusTracker`. This is
/// the simplest safe ownership model: no `Arc`, no `Mutex`, no
/// interior mutability. The borrow is released when the handler is
/// dropped. If concurrent access is needed in the future, the caller
/// wraps the tracker in `Arc<Mutex<>>` and passes `&mut` after locking.
///
/// ## State Consistency
///
/// The handler maintains a consistency invariant between its own
/// metadata fields and the tracker's status:
///
/// | Tracker Status | `quarantine_reason` | `quarantined_since` |
/// |----------------|---------------------|---------------------|
/// | `Quarantined`  | `Some(...)` | `Some(...)` |
/// | Any other      | `None` | `None` |
///
/// This invariant is enforced by:
/// - `handle_quarantine_notification`: sets metadata on success.
/// - `clear_quarantine_metadata`: clears metadata, rejects if still quarantined.
pub struct QuarantineHandler<'a> {
    /// Mutable reference to the node's status tracker.
    status_tracker: &'a mut NodeStatusTracker,
    /// Reason for the current quarantine, if active.
    quarantine_reason: Option<String>,
    /// Timestamp when quarantine started, if active.
    quarantined_since: Option<u64>,
}

impl<'a> QuarantineHandler<'a> {
    /// Creates a new handler wrapping the given status tracker.
    ///
    /// If the tracker is already in `Quarantined` state, the handler
    /// starts without metadata (reason and timestamp unknown from
    /// this handler's perspective). The caller should invoke
    /// `handle_quarantine_notification` if the quarantine context
    /// is known, or accept that metadata is `None` for pre-existing
    /// quarantines.
    pub fn new(status_tracker: &'a mut NodeStatusTracker) -> Self {
        Self {
            status_tracker,
            quarantine_reason: None,
            quarantined_since: None,
        }
    }

    /// Processes a quarantine notification from the coordinator.
    ///
    /// ## Validation (strict order)
    ///
    /// 1. **Already quarantined**: If the tracker is already `Quarantined`,
    ///    returns `Err` — double quarantine is not allowed without an
    ///    intermediate transition.
    /// 2. **Transition legality + timestamp**: Delegates to
    ///    `NodeStatusTracker::update_status(Quarantined, reason, timestamp)`.
    ///    If the transition is illegal (e.g., from `Pending` or `Banned`)
    ///    or the timestamp violates monotonicity, the tracker returns
    ///    `Err` and no state is changed.
    ///
    /// ## Side Effects (on success)
    ///
    /// - Tracker transitions to `Quarantined` (via `update_status`).
    /// - `quarantine_reason` set to the provided reason.
    /// - `quarantined_since` set to the provided timestamp.
    ///
    /// ## Quarantine event
    ///
    /// On success, a `StatusTransition` is recorded in the tracker's
    /// history. No external logger is invoked — the transition history
    /// serves as the audit trail.
    ///
    /// ## Errors
    ///
    /// Returns `Err(String)` with a descriptive message if:
    /// - The node is already quarantined.
    /// - The status transition is illegal.
    /// - The timestamp violates monotonicity or is a duplicate.
    pub fn handle_quarantine_notification(
        &mut self,
        reason: String,
        timestamp: u64,
    ) -> Result<(), String> {
        // Step 1: Reject if already quarantined
        if *self.status_tracker.current() == NodeStatus::Quarantined {
            return Err("node is already quarantined".to_string());
        }

        // Step 2: Attempt transition via tracker
        // Validates: transition legality, timestamp monotonicity, no duplicate ts.
        self.status_tracker.update_status(
            NodeStatus::Quarantined,
            reason.clone(),
            timestamp,
        )?;

        // Step 3: Record quarantine metadata (only reached on success)
        self.quarantine_reason = Some(reason);
        self.quarantined_since = Some(timestamp);

        Ok(())
    }

    /// Evaluates whether the node is eligible for recovery from quarantine.
    ///
    /// ## Conditions (all must be true)
    ///
    /// 1. Current status is `Quarantined`.
    /// 2. `current_stake >= required_stake`.
    ///
    /// ## Important
    ///
    /// This is a **pure read-only function**. It does NOT change any
    /// state. The actual recovery transition (Quarantined → Active)
    /// is performed by the coordinator and applied locally via a
    /// separate `update_status` call on the tracker.
    ///
    /// ## Determinism
    ///
    /// Same inputs always produce the same output. No side effects,
    /// no overflow risk (u128 comparison only).
    pub fn attempt_recovery(
        &self,
        current_stake: u128,
        required_stake: u128,
    ) -> bool {
        *self.status_tracker.current() == NodeStatus::Quarantined
            && current_stake >= required_stake
    }

    /// Returns `true` if the node is currently quarantined.
    ///
    /// Delegates to `NodeStatusTracker::current()` comparison.
    /// Does not check handler metadata — trusts the tracker as
    /// source of truth.
    #[inline]
    pub fn is_quarantined(&self) -> bool {
        *self.status_tracker.current() == NodeStatus::Quarantined
    }

    /// Returns the time spent in quarantine.
    ///
    /// - `None` if `quarantined_since` is not set (handler was not
    ///   used to enter quarantine, or metadata was cleared).
    /// - `Some(0)` if `now <= quarantined_since` (clock skew protection).
    /// - `Some(duration)` otherwise.
    ///
    /// Uses `saturating_sub` to prevent underflow.
    pub fn quarantine_duration(&self, now: u64) -> Option<u64> {
        self.quarantined_since.map(|since| now.saturating_sub(since))
    }

    /// Returns the quarantine reason, if set.
    #[inline]
    pub fn quarantine_reason(&self) -> Option<&str> {
        self.quarantine_reason.as_deref()
    }

    /// Returns the quarantine start timestamp, if set.
    #[inline]
    pub fn quarantined_since(&self) -> Option<u64> {
        self.quarantined_since
    }

    /// Clears quarantine metadata after the node leaves `Quarantined` state.
    ///
    /// Must be called after the tracker transitions away from
    /// `Quarantined` (e.g., to `Active` via recovery, or to `Banned`
    /// via escalation). Enforces the state consistency invariant:
    /// quarantine metadata is `None` when the node is not quarantined.
    ///
    /// ## Errors
    ///
    /// Returns `Err` if the tracker is still in `Quarantined` state.
    /// Metadata must not be cleared while the quarantine is active.
    pub fn clear_quarantine_metadata(&mut self) -> Result<(), String> {
        if *self.status_tracker.current() == NodeStatus::Quarantined {
            return Err(
                "cannot clear quarantine metadata: node is still quarantined".to_string()
            );
        }
        self.quarantine_reason = None;
        self.quarantined_since = None;
        Ok(())
    }

    /// Returns a reference to the underlying status tracker.
    ///
    /// Allows reading current status, history, or other tracker
    /// state without going through the handler's quarantine-specific
    /// methods.
    #[inline]
    pub fn tracker(&self) -> &NodeStatusTracker {
        self.status_tracker
    }

    /// Returns a mutable reference to the underlying status tracker.
    ///
    /// Allows direct status transitions (e.g., recovery: Quarantined → Active)
    /// that are not quarantine-specific. The caller is responsible for
    /// calling `clear_quarantine_metadata` afterwards to maintain the
    /// state consistency invariant.
    #[inline]
    pub fn tracker_mut(&mut self) -> &mut NodeStatusTracker {
        self.status_tracker
    }
}

impl std::fmt::Debug for QuarantineHandler<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuarantineHandler")
            .field("is_quarantined", &self.is_quarantined())
            .field("quarantine_reason", &self.quarantine_reason)
            .field("quarantined_since", &self.quarantined_since)
            .finish()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    const TS: u64 = 1_700_000_000;

    // ──────────────────────────────────────────────────────────────────
    // HELPERS
    // ──────────────────────────────────────────────────────────────────

    /// Creates a tracker in Active state (ready for quarantine).
    fn make_active_tracker() -> NodeStatusTracker {
        let mut t = NodeStatusTracker::new();
        t.update_status(NodeStatus::Active, "approved".to_string(), TS)
            .expect("test setup: pending → active");
        t
    }

    // ──────────────────────────────────────────────────────────────────
    // CONSTRUCTION
    // ──────────────────────────────────────────────────────────────────

    /// New handler starts with no metadata.
    #[test]
    fn test_new_handler_no_metadata() {
        let mut tracker = make_active_tracker();
        let handler = QuarantineHandler::new(&mut tracker);
        assert!(!handler.is_quarantined());
        assert!(handler.quarantine_reason().is_none());
        assert!(handler.quarantined_since().is_none());
        assert!(handler.quarantine_duration(TS + 100).is_none());
    }

    /// New handler wrapping already-quarantined tracker.
    #[test]
    fn test_new_handler_already_quarantined() {
        let mut tracker = make_active_tracker();
        tracker.update_status(NodeStatus::Quarantined, "pre-existing".to_string(), TS + 50)
            .expect("test setup: active → quarantined");
        let handler = QuarantineHandler::new(&mut tracker);
        // Status is quarantined, but handler metadata is None
        // (handler was not the one that performed the transition)
        assert!(handler.is_quarantined());
        assert!(handler.quarantine_reason().is_none());
        assert!(handler.quarantined_since().is_none());
    }

    // ──────────────────────────────────────────────────────────────────
    // HANDLE QUARANTINE NOTIFICATION — SUCCESS
    // ──────────────────────────────────────────────────────────────────

    /// Successful quarantine from Active state.
    #[test]
    fn test_quarantine_success() {
        let mut tracker = make_active_tracker();
        let mut handler = QuarantineHandler::new(&mut tracker);

        let result = handler.handle_quarantine_notification(
            "stake drop below minimum".to_string(),
            TS + 100,
        );

        assert!(result.is_ok());
        assert!(handler.is_quarantined());
        assert_eq!(handler.quarantine_reason(), Some("stake drop below minimum"));
        assert_eq!(handler.quarantined_since(), Some(TS + 100));
        assert_eq!(*handler.tracker().current(), NodeStatus::Quarantined);
        assert_eq!(handler.tracker().history().len(), 2); // approved + quarantined
    }

    /// Quarantine records correct StatusTransition in history.
    #[test]
    fn test_quarantine_history_record() {
        let mut tracker = make_active_tracker();
        let mut handler = QuarantineHandler::new(&mut tracker);

        assert!(handler.handle_quarantine_notification(
            "minor violation".to_string(), TS + 100,
        ).is_ok());

        let last = handler.tracker().history().last();
        assert!(last.is_some());
        if let Some(tr) = last {
            assert_eq!(tr.from, NodeStatus::Active);
            assert_eq!(tr.to, NodeStatus::Quarantined);
            assert_eq!(tr.reason, "minor violation");
            assert_eq!(tr.timestamp, TS + 100);
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // HANDLE QUARANTINE NOTIFICATION — FAILURES
    // ──────────────────────────────────────────────────────────────────

    /// Double quarantine rejected.
    #[test]
    fn test_quarantine_already_quarantined() {
        let mut tracker = make_active_tracker();
        let mut handler = QuarantineHandler::new(&mut tracker);

        assert!(handler.handle_quarantine_notification(
            "stake drop".to_string(), TS + 100,
        ).is_ok());

        let result = handler.handle_quarantine_notification(
            "another reason".to_string(), TS + 200,
        );
        assert!(result.is_err());
        // Metadata unchanged
        assert_eq!(handler.quarantine_reason(), Some("stake drop"));
        assert_eq!(handler.quarantined_since(), Some(TS + 100));
    }

    /// Quarantine from Pending rejected (illegal transition).
    #[test]
    fn test_quarantine_from_pending() {
        let mut tracker = NodeStatusTracker::new();
        let mut handler = QuarantineHandler::new(&mut tracker);

        let result = handler.handle_quarantine_notification(
            "stake drop".to_string(), TS,
        );
        assert!(result.is_err());
        assert!(!handler.is_quarantined());
        assert!(handler.quarantine_reason().is_none());
        assert!(handler.quarantined_since().is_none());
    }

    /// Quarantine from Banned rejected (illegal transition).
    #[test]
    fn test_quarantine_from_banned() {
        let mut tracker = make_active_tracker();
        tracker.update_status(NodeStatus::Banned, "slashing".to_string(), TS + 100)
            .expect("test setup: active → banned");
        let mut handler = QuarantineHandler::new(&mut tracker);

        let result = handler.handle_quarantine_notification(
            "stake drop".to_string(), TS + 200,
        );
        assert!(result.is_err());
        assert!(!handler.is_quarantined());
    }

    /// Backwards timestamp rejected.
    #[test]
    fn test_quarantine_backwards_timestamp() {
        let mut tracker = make_active_tracker();
        let mut handler = QuarantineHandler::new(&mut tracker);

        let result = handler.handle_quarantine_notification(
            "drop".to_string(), TS - 1,
        );
        assert!(result.is_err());
        assert!(!handler.is_quarantined());
        assert!(handler.quarantine_reason().is_none());
    }

    /// Duplicate timestamp rejected.
    #[test]
    fn test_quarantine_duplicate_timestamp() {
        let mut tracker = make_active_tracker();
        let mut handler = QuarantineHandler::new(&mut tracker);

        // TS is the timestamp of the Pending→Active transition
        let result = handler.handle_quarantine_notification(
            "drop".to_string(), TS,
        );
        assert!(result.is_err());
        assert!(!handler.is_quarantined());
    }

    /// Failed notification leaves no side effects.
    #[test]
    fn test_quarantine_failure_no_side_effects() {
        let mut tracker = make_active_tracker();
        let history_before = tracker.history().len();
        let mut handler = QuarantineHandler::new(&mut tracker);

        // Illegal transition: Pending→Quarantined not allowed, but we're Active.
        // Use backwards timestamp to fail:
        let _ = handler.handle_quarantine_notification("fail".to_string(), TS - 1);

        assert_eq!(handler.tracker().history().len(), history_before);
        assert!(handler.tracker().is_active());
        assert!(handler.quarantine_reason().is_none());
        assert!(handler.quarantined_since().is_none());
    }

    // ──────────────────────────────────────────────────────────────────
    // ATTEMPT RECOVERY
    // ──────────────────────────────────────────────────────────────────

    /// Recovery eligible: quarantined + sufficient stake.
    #[test]
    fn test_recovery_eligible() {
        let mut tracker = make_active_tracker();
        let mut handler = QuarantineHandler::new(&mut tracker);
        assert!(handler.handle_quarantine_notification(
            "drop".to_string(), TS + 100,
        ).is_ok());

        assert!(handler.attempt_recovery(1000, 500));
    }

    /// Recovery eligible: stake exactly equals required.
    #[test]
    fn test_recovery_exact_stake() {
        let mut tracker = make_active_tracker();
        let mut handler = QuarantineHandler::new(&mut tracker);
        assert!(handler.handle_quarantine_notification(
            "drop".to_string(), TS + 100,
        ).is_ok());

        assert!(handler.attempt_recovery(500, 500));
    }

    /// Recovery ineligible: insufficient stake.
    #[test]
    fn test_recovery_insufficient_stake() {
        let mut tracker = make_active_tracker();
        let mut handler = QuarantineHandler::new(&mut tracker);
        assert!(handler.handle_quarantine_notification(
            "drop".to_string(), TS + 100,
        ).is_ok());

        assert!(!handler.attempt_recovery(499, 500));
    }

    /// Recovery ineligible: not quarantined (Active).
    #[test]
    fn test_recovery_not_quarantined() {
        let mut tracker = make_active_tracker();
        let handler = QuarantineHandler::new(&mut tracker);
        assert!(!handler.attempt_recovery(1000, 500));
    }

    /// Recovery is read-only: does not change state.
    #[test]
    fn test_recovery_no_side_effects() {
        let mut tracker = make_active_tracker();
        let mut handler = QuarantineHandler::new(&mut tracker);
        assert!(handler.handle_quarantine_notification(
            "drop".to_string(), TS + 100,
        ).is_ok());

        let history_len = handler.tracker().history().len();
        let status_before = *handler.tracker().current();

        let _ = handler.attempt_recovery(1000, 500);

        assert_eq!(handler.tracker().history().len(), history_len);
        assert_eq!(*handler.tracker().current(), status_before);
        assert!(handler.is_quarantined());
    }

    /// Recovery with zero stake and zero requirement.
    #[test]
    fn test_recovery_zero_stake_zero_required() {
        let mut tracker = make_active_tracker();
        let mut handler = QuarantineHandler::new(&mut tracker);
        assert!(handler.handle_quarantine_notification(
            "drop".to_string(), TS + 100,
        ).is_ok());

        // 0 >= 0 is true
        assert!(handler.attempt_recovery(0, 0));
    }

    // ──────────────────────────────────────────────────────────────────
    // QUARANTINE DURATION
    // ──────────────────────────────────────────────────────────────────

    /// Duration when not quarantined (no metadata).
    #[test]
    fn test_duration_not_quarantined() {
        let mut tracker = make_active_tracker();
        let handler = QuarantineHandler::new(&mut tracker);
        assert_eq!(handler.quarantine_duration(TS + 500), None);
    }

    /// Duration when quarantined.
    #[test]
    fn test_duration_quarantined() {
        let mut tracker = make_active_tracker();
        let mut handler = QuarantineHandler::new(&mut tracker);
        assert!(handler.handle_quarantine_notification(
            "drop".to_string(), TS + 100,
        ).is_ok());

        assert_eq!(handler.quarantine_duration(TS + 600), Some(500));
    }

    /// Duration when now == quarantined_since.
    #[test]
    fn test_duration_at_start() {
        let mut tracker = make_active_tracker();
        let mut handler = QuarantineHandler::new(&mut tracker);
        assert!(handler.handle_quarantine_notification(
            "drop".to_string(), TS + 100,
        ).is_ok());

        assert_eq!(handler.quarantine_duration(TS + 100), Some(0));
    }

    /// Duration when now < quarantined_since (clock skew → 0).
    #[test]
    fn test_duration_clock_skew() {
        let mut tracker = make_active_tracker();
        let mut handler = QuarantineHandler::new(&mut tracker);
        assert!(handler.handle_quarantine_notification(
            "drop".to_string(), TS + 100,
        ).is_ok());

        assert_eq!(handler.quarantine_duration(TS + 50), Some(0));
    }

    // ──────────────────────────────────────────────────────────────────
    // CLEAR QUARANTINE METADATA
    // ──────────────────────────────────────────────────────────────────

    /// Clear metadata after recovery transition.
    #[test]
    fn test_clear_metadata_after_recovery() {
        let mut tracker = make_active_tracker();
        let mut handler = QuarantineHandler::new(&mut tracker);
        assert!(handler.handle_quarantine_notification(
            "stake drop".to_string(), TS + 100,
        ).is_ok());

        // Simulate coordinator recovery: Quarantined → Active
        assert!(handler.tracker_mut().update_status(
            NodeStatus::Active, "stake restored".to_string(), TS + 200,
        ).is_ok());

        let result = handler.clear_quarantine_metadata();
        assert!(result.is_ok());
        assert!(handler.quarantine_reason().is_none());
        assert!(handler.quarantined_since().is_none());
        assert!(handler.quarantine_duration(TS + 300).is_none());
    }

    /// Clear metadata rejected while still quarantined.
    #[test]
    fn test_clear_metadata_while_quarantined() {
        let mut tracker = make_active_tracker();
        let mut handler = QuarantineHandler::new(&mut tracker);
        assert!(handler.handle_quarantine_notification(
            "drop".to_string(), TS + 100,
        ).is_ok());

        let result = handler.clear_quarantine_metadata();
        assert!(result.is_err());
        assert!(handler.quarantine_reason().is_some());
        assert!(handler.quarantined_since().is_some());
    }

    /// Clear metadata after escalation (Quarantined → Banned).
    #[test]
    fn test_clear_metadata_after_escalation() {
        let mut tracker = make_active_tracker();
        let mut handler = QuarantineHandler::new(&mut tracker);
        assert!(handler.handle_quarantine_notification(
            "stake drop".to_string(), TS + 100,
        ).is_ok());

        // Escalate: Quarantined → Banned
        assert!(handler.tracker_mut().update_status(
            NodeStatus::Banned, "escalation".to_string(), TS + 200,
        ).is_ok());

        let result = handler.clear_quarantine_metadata();
        assert!(result.is_ok());
        assert!(handler.quarantine_reason().is_none());
    }

    // ──────────────────────────────────────────────────────────────────
    // FULL FLOW
    // ──────────────────────────────────────────────────────────────────

    /// Full flow: Active → Quarantined → check recovery → Active → clear.
    #[test]
    fn test_full_quarantine_recovery_flow() {
        let mut tracker = make_active_tracker();
        let mut handler = QuarantineHandler::new(&mut tracker);

        // 1. Quarantine notification
        assert!(handler.handle_quarantine_notification(
            "stake drop to 400".to_string(), TS + 100,
        ).is_ok());
        assert!(handler.is_quarantined());
        assert!(!handler.attempt_recovery(400, 500)); // Insufficient
        assert!(handler.attempt_recovery(500, 500));   // Sufficient

        // 2. Coordinator approves recovery
        assert!(handler.tracker_mut().update_status(
            NodeStatus::Active, "stake restored".to_string(), TS + 200,
        ).is_ok());
        assert!(!handler.is_quarantined());

        // 3. Clear metadata
        assert!(handler.clear_quarantine_metadata().is_ok());
        assert!(handler.quarantine_reason().is_none());
        assert!(handler.quarantined_since().is_none());
        assert!(handler.quarantine_duration(TS + 300).is_none());
    }

    // ──────────────────────────────────────────────────────────────────
    // DEBUG
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_debug_output() {
        let mut tracker = make_active_tracker();
        let handler = QuarantineHandler::new(&mut tracker);
        let debug_str = format!("{:?}", handler);
        assert!(debug_str.contains("QuarantineHandler"));
        assert!(debug_str.contains("is_quarantined"));
    }

}