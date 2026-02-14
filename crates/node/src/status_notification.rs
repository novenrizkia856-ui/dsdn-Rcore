//! # Status Notification Handler (14B.49)
//!
//! Processes coordinator-originated status notifications and DA-layer
//! gating events, applying deterministic state transitions to the
//! node's [`NodeStatusTracker`].
//!
//! ## Purpose
//!
//! When the coordinator changes a node's status (via DA events or
//! direct notification), the node must update its local state machine
//! to reflect the authoritative decision. `StatusNotificationHandler`
//! is the single entry point for all status lifecycle updates:
//!
//! 1. **Direct notifications** — via [`handle`](StatusNotificationHandler::handle).
//! 2. **DA gating events** — via [`process_da_gating_events`](StatusNotificationHandler::process_da_gating_events).
//!
//! ## Delegation Model
//!
//! - **Quarantine transitions** are delegated to [`QuarantineHandler`]
//!   to enforce quarantine-specific validation (double-quarantine
//!   rejection, transition legality).
//! - **All other transitions** are applied directly via
//!   [`NodeStatusTracker::update_status`].
//!
//! ## Concurrency Model
//!
//! The handler holds `Arc<Mutex<NodeStatusTracker>>` (the same
//! instance shared with [`RejoinManager`] and other subsystems).
//! The Mutex is locked only for the duration of each state transition,
//! never held across method boundaries.
//!
//! ## Quarantine Metadata
//!
//! Because [`QuarantineHandler`] borrows `&'a mut NodeStatusTracker`
//! (cannot be stored alongside `Arc<Mutex<>>`), the notification
//! handler tracks quarantine metadata (reason, start timestamp)
//! locally. A temporary `QuarantineHandler` is created per quarantine
//! transition by locking the Mutex and borrowing the tracker.
//!
//! ## Determinism
//!
//! Same notifications + same internal state → same transitions.
//! No randomness. No implicit timestamps. All parameters are explicit.
//!
//! ## Event Filtering
//!
//! [`process_da_gating_events`](StatusNotificationHandler::process_da_gating_events)
//! filters events by comparing the event's hex-encoded `node_id` field
//! against this handler's cached `node_id_hex`. Only events targeting
//! this specific node are processed.
//!
//! ## Safety
//!
//! - No `panic!`, `unwrap()`, `expect()`.
//! - No `unsafe` code.
//! - No implicit global state.
//! - All state transitions are explicit and auditable via tracker history.

use std::sync::Arc;

use parking_lot::Mutex;

use dsdn_common::gating::{NodeStatus, StatusTransition};
use dsdn_coordinator::GatingEvent;

use crate::quarantine_handler::QuarantineHandler;
use crate::status_tracker::NodeStatusTracker;

// ════════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════════

/// Hex digit lookup table for lowercase encoding.
const HEX_CHARS: [u8; 16] = *b"0123456789abcdef";

// ════════════════════════════════════════════════════════════════════════════════
// STATUS NOTIFICATION
// ════════════════════════════════════════════════════════════════════════════════

/// A coordinator-originated status change notification.
///
/// Carries the target node, the desired new status, a human-readable
/// reason, and an explicit timestamp. All fields are owned values —
/// no lifetimes, no references.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusNotification {
    /// The target node's 32-byte public key.
    pub target_node_id: [u8; 32],
    /// The new status the coordinator wants to apply.
    pub new_status: NodeStatus,
    /// Human-readable reason for the transition.
    pub reason: String,
    /// Unix timestamp (seconds) when the transition should be recorded.
    pub timestamp: u64,
}

// ════════════════════════════════════════════════════════════════════════════════
// STATUS NOTIFICATION HANDLER
// ════════════════════════════════════════════════════════════════════════════════

/// Processes status notifications and DA gating events.
///
/// ## Ownership Model
///
/// | Field | Type | Purpose |
/// |-------|------|---------|
/// | `node_id` | `[u8; 32]` | Raw public key for notification targeting |
/// | `node_id_hex` | `String` | Cached hex for efficient DA event filtering |
/// | `status_tracker` | `Arc<Mutex<NodeStatusTracker>>` | Shared with RejoinManager |
/// | `quarantine_reason` | `Option<String>` | Quarantine metadata (local) |
/// | `quarantine_since` | `Option<u64>` | Quarantine start timestamp (local) |
///
/// ## Thread Safety
///
/// `StatusNotificationHandler` is `Send` (can be transferred between
/// threads) but its `&mut self` methods prevent concurrent access.
/// The inner `Arc<Mutex<>>` ensures safe shared access to the tracker.
pub struct StatusNotificationHandler {
    /// This node's raw 32-byte Ed25519 public key.
    node_id: [u8; 32],
    /// Hex-encoded node ID (64 lowercase chars, no 0x prefix).
    /// Cached at construction to avoid repeated encoding during
    /// event filtering.
    node_id_hex: String,
    /// Shared, mutex-protected status tracker.
    status_tracker: Arc<Mutex<NodeStatusTracker>>,
    /// Quarantine reason, set when this handler processes a
    /// quarantine transition. Cleared on transition away from
    /// Quarantined.
    quarantine_reason: Option<String>,
    /// Quarantine start timestamp, set when this handler processes
    /// a quarantine transition. Cleared on transition away from
    /// Quarantined.
    quarantine_since: Option<u64>,
}

impl StatusNotificationHandler {
    /// Creates a new handler for the given node.
    ///
    /// ## Parameters
    ///
    /// - `node_id`: This node's 32-byte Ed25519 public key.
    /// - `status_tracker`: The shared status tracker (same `Arc`
    ///   used by `RejoinManager` and other subsystems).
    ///
    /// The hex encoding is computed once at construction and cached.
    pub fn new(
        node_id: [u8; 32],
        status_tracker: Arc<Mutex<NodeStatusTracker>>,
    ) -> Self {
        let node_id_hex = bytes_to_lower_hex(&node_id);
        Self {
            node_id,
            node_id_hex,
            status_tracker,
            quarantine_reason: None,
            quarantine_since: None,
        }
    }

    /// Processes a single status notification.
    ///
    /// ## Target Validation
    ///
    /// The notification's `target_node_id` must match this handler's
    /// `node_id`. Mismatched notifications are rejected with `Err`.
    ///
    /// ## Transition Logic
    ///
    /// | `new_status` | Action |
    /// |--------------|--------|
    /// | `Active` | Update tracker → Active, clear quarantine metadata |
    /// | `Quarantined` | Delegate to `QuarantineHandler`, store metadata |
    /// | `Banned` | Update tracker → Banned, clear quarantine metadata |
    /// | `Pending` | Update tracker → Pending (if valid transition) |
    ///
    /// ## Errors
    ///
    /// Returns `Err(String)` if:
    /// - The notification targets a different node.
    /// - The status transition is illegal per the state machine.
    /// - The timestamp violates monotonicity.
    /// - The node is already quarantined (double quarantine).
    ///
    /// On error, no state is changed (tracker and metadata unmodified).
    ///
    /// ## Determinism
    ///
    /// Same tracker state + same notification → same result.
    pub fn handle(
        &mut self,
        notification: StatusNotification,
    ) -> Result<StatusTransition, String> {
        // Step 1: Validate target
        if notification.target_node_id != self.node_id {
            return Err("notification targets a different node".to_string());
        }

        match notification.new_status {
            NodeStatus::Active => {
                self.handle_active(notification.reason, notification.timestamp)
            }
            NodeStatus::Quarantined => {
                self.handle_quarantined(notification.reason, notification.timestamp)
            }
            NodeStatus::Banned => {
                self.handle_banned(notification.reason, notification.timestamp)
            }
            NodeStatus::Pending => {
                self.handle_pending(notification.reason, notification.timestamp)
            }
        }
    }

    /// Processes a batch of DA gating events.
    ///
    /// ## Processing Order
    ///
    /// Events are processed in the order they appear in the input
    /// vector. This preserves DA event ordering guarantees.
    ///
    /// ## Filtering
    ///
    /// Only events whose `node_id` field matches this handler's
    /// `node_id_hex` are processed. Other events are silently skipped.
    ///
    /// ## Skipped Event Types
    ///
    /// - `NodeRejected`: Admission rejection, not a status transition.
    /// - `NodeBanExpired`: Informational. The node must go through
    ///   the rejoin process (via `RejoinManager`) to change status.
    ///   No automatic transition occurs.
    ///
    /// ## Error Handling
    ///
    /// If a valid event produces an invalid transition (e.g., illegal
    /// state machine path, timestamp violation), the error is recorded
    /// in the returned vector as an absence — only successful
    /// transitions are collected. No panic, no unwrap.
    ///
    /// ## Determinism
    ///
    /// Same tracker state + same events → same transitions.
    pub fn process_da_gating_events(
        &mut self,
        events: Vec<GatingEvent>,
    ) -> Vec<StatusTransition> {
        let mut transitions = Vec::new();

        for event in &events {
            // Step 1: Extract node_id hex from event, skip if not ours
            let event_node_id = extract_event_node_id(event);
            if event_node_id != self.node_id_hex {
                continue;
            }

            // Step 2: Map event to notification, skip unmappable events
            let notification = match self.map_gating_event(event) {
                Some(n) => n,
                None => continue,
            };

            // Step 3: Process via handle()
            match self.handle(notification) {
                Ok(transition) => transitions.push(transition),
                Err(_) => {
                    // Invalid transition for this event. The error
                    // message is descriptive but no external logging
                    // mechanism exists in this module. The transition
                    // is simply not collected.
                }
            }
        }

        transitions
    }

    /// Returns the current quarantine reason, if this handler
    /// processed the quarantine transition.
    #[inline]
    pub fn quarantine_reason(&self) -> Option<&str> {
        self.quarantine_reason.as_deref()
    }

    /// Returns the quarantine start timestamp, if this handler
    /// processed the quarantine transition.
    #[inline]
    pub fn quarantine_since(&self) -> Option<u64> {
        self.quarantine_since
    }

    /// Returns this handler's hex-encoded node ID.
    #[inline]
    pub fn node_id_hex(&self) -> &str {
        &self.node_id_hex
    }

    /// Returns this handler's raw node ID bytes.
    #[inline]
    pub fn node_id(&self) -> &[u8; 32] {
        &self.node_id
    }

    /// Returns the current status by reading the tracker.
    ///
    /// Locks the Mutex briefly. Returns a copy (`NodeStatus` is `Copy`).
    pub fn current_status(&self) -> NodeStatus {
        *self.status_tracker.lock().current()
    }

    // ════════════════════════════════════════════════════════════════════════
    // PRIVATE: STATUS-SPECIFIC HANDLERS
    // ════════════════════════════════════════════════════════════════════════

    /// Active transition: update tracker, clear quarantine metadata.
    fn handle_active(
        &mut self,
        reason: String,
        timestamp: u64,
    ) -> Result<StatusTransition, String> {
        let mut tracker = self.status_tracker.lock();
        let from = *tracker.current();
        tracker.update_status(NodeStatus::Active, reason.clone(), timestamp)?;
        drop(tracker);

        // Clear quarantine metadata (if coming from Quarantined)
        self.quarantine_reason = None;
        self.quarantine_since = None;

        Ok(StatusTransition {
            from,
            to: NodeStatus::Active,
            reason,
            timestamp,
        })
    }

    /// Quarantined transition: delegate to QuarantineHandler.
    ///
    /// Creates a temporary `QuarantineHandler` by locking the Mutex
    /// and borrowing `&mut NodeStatusTracker`. The handler validates
    /// the transition (rejects double quarantine, illegal paths) and
    /// applies it atomically. Quarantine metadata is stored locally.
    fn handle_quarantined(
        &mut self,
        reason: String,
        timestamp: u64,
    ) -> Result<StatusTransition, String> {
        let mut tracker = self.status_tracker.lock();
        let from = *tracker.current();

        // Create ephemeral QuarantineHandler for validation + transition
        let mut qh = QuarantineHandler::new(&mut *tracker);
        qh.handle_quarantine_notification(reason.clone(), timestamp)?;
        // QuarantineHandler is dropped here, releasing the &mut borrow.
        // The MutexGuard is still held but no longer exclusively borrowed.
        drop(qh);
        drop(tracker);

        // Store quarantine metadata locally
        self.quarantine_reason = Some(reason.clone());
        self.quarantine_since = Some(timestamp);

        Ok(StatusTransition {
            from,
            to: NodeStatus::Quarantined,
            reason,
            timestamp,
        })
    }

    /// Banned transition: update tracker, clear quarantine metadata.
    fn handle_banned(
        &mut self,
        reason: String,
        timestamp: u64,
    ) -> Result<StatusTransition, String> {
        let mut tracker = self.status_tracker.lock();
        let from = *tracker.current();
        tracker.update_status(NodeStatus::Banned, reason.clone(), timestamp)?;
        drop(tracker);

        // Clear quarantine metadata (if coming from Quarantined)
        self.quarantine_reason = None;
        self.quarantine_since = None;

        Ok(StatusTransition {
            from,
            to: NodeStatus::Banned,
            reason,
            timestamp,
        })
    }

    /// Pending transition: update tracker.
    ///
    /// Valid path: Banned → Pending (re-admission after ban expiry).
    /// Other paths will be rejected by `NodeStatusTracker::update_status`.
    fn handle_pending(
        &mut self,
        reason: String,
        timestamp: u64,
    ) -> Result<StatusTransition, String> {
        let mut tracker = self.status_tracker.lock();
        let from = *tracker.current();
        tracker.update_status(NodeStatus::Pending, reason.clone(), timestamp)?;
        drop(tracker);

        Ok(StatusTransition {
            from,
            to: NodeStatus::Pending,
            reason,
            timestamp,
        })
    }

    // ════════════════════════════════════════════════════════════════════════
    // PRIVATE: GATING EVENT MAPPING
    // ════════════════════════════════════════════════════════════════════════

    /// Maps a `GatingEvent` to a `StatusNotification`.
    ///
    /// Returns `None` for events that do not map to a status transition:
    /// - `NodeRejected`: Admission rejection, not a status change.
    /// - `NodeBanExpired`: Informational, requires rejoin process.
    fn map_gating_event(&self, event: &GatingEvent) -> Option<StatusNotification> {
        match event {
            GatingEvent::NodeAdmitted { timestamp, .. } => {
                Some(StatusNotification {
                    target_node_id: self.node_id,
                    new_status: NodeStatus::Active,
                    reason: "admitted to network".to_string(),
                    timestamp: *timestamp,
                })
            }
            GatingEvent::NodeActivated { timestamp, .. } => {
                Some(StatusNotification {
                    target_node_id: self.node_id,
                    new_status: NodeStatus::Active,
                    reason: "activated by coordinator".to_string(),
                    timestamp: *timestamp,
                })
            }
            GatingEvent::NodeQuarantined { reason, timestamp, .. } => {
                Some(StatusNotification {
                    target_node_id: self.node_id,
                    new_status: NodeStatus::Quarantined,
                    reason: reason.clone(),
                    timestamp: *timestamp,
                })
            }
            GatingEvent::NodeBanned { reason, timestamp, .. } => {
                Some(StatusNotification {
                    target_node_id: self.node_id,
                    new_status: NodeStatus::Banned,
                    reason: reason.clone(),
                    timestamp: *timestamp,
                })
            }
            GatingEvent::NodeRejected { .. } => None,
            GatingEvent::NodeBanExpired { .. } => None,
        }
    }
}

impl std::fmt::Debug for StatusNotificationHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StatusNotificationHandler")
            .field("node_id_hex", &self.node_id_hex)
            .field("current_status", &self.current_status())
            .field("quarantine_reason", &self.quarantine_reason)
            .field("quarantine_since", &self.quarantine_since)
            .finish()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS (MODULE-PRIVATE)
// ════════════════════════════════════════════════════════════════════════════════

/// Converts a byte slice to a lowercase hex string. No `0x` prefix.
fn bytes_to_lower_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        hex.push(HEX_CHARS[(b >> 4) as usize] as char);
        hex.push(HEX_CHARS[(b & 0x0F) as usize] as char);
    }
    hex
}

/// Extracts the hex-encoded `node_id` string from a `GatingEvent`.
///
/// Every `GatingEvent` variant carries a `node_id` field.
/// This function returns a reference to it for filtering.
fn extract_event_node_id(event: &GatingEvent) -> &str {
    match event {
        GatingEvent::NodeAdmitted { node_id, .. } => node_id,
        GatingEvent::NodeRejected { node_id, .. } => node_id,
        GatingEvent::NodeQuarantined { node_id, .. } => node_id,
        GatingEvent::NodeBanned { node_id, .. } => node_id,
        GatingEvent::NodeActivated { node_id, .. } => node_id,
        GatingEvent::NodeBanExpired { node_id, .. } => node_id,
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    const TS: u64 = 1_700_000_000;

    /// A deterministic 32-byte test node ID.
    const TEST_NODE_ID: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    ];

    /// A different 32-byte node ID (for mismatch tests).
    const OTHER_NODE_ID: [u8; 32] = [
        0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
        0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0,
        0xEF, 0xEE, 0xED, 0xEC, 0xEB, 0xEA, 0xE9, 0xE8,
        0xE7, 0xE6, 0xE5, 0xE4, 0xE3, 0xE2, 0xE1, 0xE0,
    ];

    // ──────────────────────────────────────────────────────────────────────
    // HELPERS
    // ──────────────────────────────────────────────────────────────────────

    /// Creates a handler with a fresh Pending tracker.
    fn make_pending_handler() -> StatusNotificationHandler {
        let tracker = Arc::new(Mutex::new(NodeStatusTracker::new()));
        StatusNotificationHandler::new(TEST_NODE_ID, tracker)
    }

    /// Creates a handler with an Active tracker.
    fn make_active_handler() -> StatusNotificationHandler {
        let tracker = Arc::new(Mutex::new(NodeStatusTracker::new()));
        tracker
            .lock()
            .update_status(NodeStatus::Active, "approved".to_string(), TS)
            .expect("test setup: pending → active");
        StatusNotificationHandler::new(TEST_NODE_ID, tracker)
    }

    /// Creates a handler with a Quarantined tracker.
    fn make_quarantined_handler() -> StatusNotificationHandler {
        let tracker = Arc::new(Mutex::new(NodeStatusTracker::new()));
        {
            let mut t = tracker.lock();
            t.update_status(NodeStatus::Active, "approved".to_string(), TS)
                .expect("test setup: pending → active");
            t.update_status(
                NodeStatus::Quarantined,
                "stake drop".to_string(),
                TS + 100,
            )
            .expect("test setup: active → quarantined");
        }
        StatusNotificationHandler::new(TEST_NODE_ID, tracker)
    }

    /// Creates a handler with a Banned tracker.
    fn make_banned_handler() -> StatusNotificationHandler {
        let tracker = Arc::new(Mutex::new(NodeStatusTracker::new()));
        {
            let mut t = tracker.lock();
            t.update_status(NodeStatus::Active, "approved".to_string(), TS)
                .expect("test setup: pending → active");
            t.update_status(NodeStatus::Banned, "slashing".to_string(), TS + 100)
                .expect("test setup: active → banned");
        }
        StatusNotificationHandler::new(TEST_NODE_ID, tracker)
    }

    /// Builds a notification targeting TEST_NODE_ID.
    fn notif(status: NodeStatus, reason: &str, timestamp: u64) -> StatusNotification {
        StatusNotification {
            target_node_id: TEST_NODE_ID,
            new_status: status,
            reason: reason.to_string(),
            timestamp,
        }
    }

    /// Returns hex encoding of TEST_NODE_ID.
    fn test_node_hex() -> String {
        bytes_to_lower_hex(&TEST_NODE_ID)
    }

    // ──────────────────────────────────────────────────────────────────────
    // A. CONSTRUCTION
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_new_handler_initial_state() {
        let handler = make_pending_handler();
        assert_eq!(handler.current_status(), NodeStatus::Pending);
        assert!(handler.quarantine_reason().is_none());
        assert!(handler.quarantine_since().is_none());
        assert_eq!(handler.node_id(), &TEST_NODE_ID);
        assert_eq!(handler.node_id_hex(), test_node_hex());
    }

    #[test]
    fn test_node_id_hex_format() {
        let handler = make_pending_handler();
        let hex = handler.node_id_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(hex, hex.to_lowercase());
    }

    // ──────────────────────────────────────────────────────────────────────
    // B. HANDLE — ACTIVE TRANSITIONS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_handle_active_from_pending() {
        let mut handler = make_pending_handler();
        let result = handler.handle(notif(NodeStatus::Active, "admitted", TS + 1));

        assert!(result.is_ok());
        if let Ok(tr) = result {
            assert_eq!(tr.from, NodeStatus::Pending);
            assert_eq!(tr.to, NodeStatus::Active);
            assert_eq!(tr.reason, "admitted");
            assert_eq!(tr.timestamp, TS + 1);
        }
        assert_eq!(handler.current_status(), NodeStatus::Active);
    }

    #[test]
    fn test_handle_active_from_quarantined() {
        let mut handler = make_quarantined_handler();
        let result = handler.handle(notif(
            NodeStatus::Active,
            "stake restored",
            TS + 200,
        ));

        assert!(result.is_ok());
        if let Ok(tr) = result {
            assert_eq!(tr.from, NodeStatus::Quarantined);
            assert_eq!(tr.to, NodeStatus::Active);
        }
        assert_eq!(handler.current_status(), NodeStatus::Active);
    }

    #[test]
    fn test_handle_active_clears_quarantine_metadata() {
        let mut handler = make_active_handler();

        // First quarantine
        let q_result = handler.handle(notif(
            NodeStatus::Quarantined,
            "stake drop",
            TS + 100,
        ));
        assert!(q_result.is_ok());
        assert!(handler.quarantine_reason().is_some());
        assert!(handler.quarantine_since().is_some());

        // Then recover to Active
        let a_result = handler.handle(notif(
            NodeStatus::Active,
            "recovered",
            TS + 200,
        ));
        assert!(a_result.is_ok());
        assert!(handler.quarantine_reason().is_none());
        assert!(handler.quarantine_since().is_none());
    }

    #[test]
    fn test_handle_active_from_banned_rejected() {
        // Banned → Active is NOT a valid transition
        let mut handler = make_banned_handler();
        let result = handler.handle(notif(NodeStatus::Active, "recover", TS + 200));
        assert!(result.is_err());
        assert_eq!(handler.current_status(), NodeStatus::Banned);
    }

    // ──────────────────────────────────────────────────────────────────────
    // C. HANDLE — QUARANTINED TRANSITIONS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_handle_quarantined_from_active() {
        let mut handler = make_active_handler();
        let result = handler.handle(notif(
            NodeStatus::Quarantined,
            "stake drop",
            TS + 100,
        ));

        assert!(result.is_ok());
        if let Ok(tr) = result {
            assert_eq!(tr.from, NodeStatus::Active);
            assert_eq!(tr.to, NodeStatus::Quarantined);
            assert_eq!(tr.reason, "stake drop");
        }
        assert_eq!(handler.current_status(), NodeStatus::Quarantined);
        assert_eq!(handler.quarantine_reason(), Some("stake drop"));
        assert_eq!(handler.quarantine_since(), Some(TS + 100));
    }

    #[test]
    fn test_handle_quarantined_double_rejected() {
        let mut handler = make_active_handler();

        // First quarantine succeeds
        assert!(handler
            .handle(notif(NodeStatus::Quarantined, "drop", TS + 100))
            .is_ok());

        // Second quarantine rejected (already quarantined)
        let result = handler.handle(notif(
            NodeStatus::Quarantined,
            "another",
            TS + 200,
        ));
        assert!(result.is_err());

        // Metadata unchanged
        assert_eq!(handler.quarantine_reason(), Some("drop"));
        assert_eq!(handler.quarantine_since(), Some(TS + 100));
    }

    #[test]
    fn test_handle_quarantined_from_pending_rejected() {
        // Pending → Quarantined is NOT a valid transition
        let mut handler = make_pending_handler();
        let result = handler.handle(notif(
            NodeStatus::Quarantined,
            "drop",
            TS + 100,
        ));
        assert!(result.is_err());
        assert_eq!(handler.current_status(), NodeStatus::Pending);
        assert!(handler.quarantine_reason().is_none());
    }

    #[test]
    fn test_handle_quarantined_from_banned_rejected() {
        let mut handler = make_banned_handler();
        let result = handler.handle(notif(
            NodeStatus::Quarantined,
            "drop",
            TS + 200,
        ));
        assert!(result.is_err());
        assert_eq!(handler.current_status(), NodeStatus::Banned);
    }

    // ──────────────────────────────────────────────────────────────────────
    // D. HANDLE — BANNED TRANSITIONS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_handle_banned_from_active() {
        let mut handler = make_active_handler();
        let result = handler.handle(notif(
            NodeStatus::Banned,
            "identity spoofing",
            TS + 100,
        ));

        assert!(result.is_ok());
        if let Ok(tr) = result {
            assert_eq!(tr.from, NodeStatus::Active);
            assert_eq!(tr.to, NodeStatus::Banned);
            assert_eq!(tr.reason, "identity spoofing");
        }
        assert_eq!(handler.current_status(), NodeStatus::Banned);
    }

    #[test]
    fn test_handle_banned_from_quarantined() {
        let mut handler = make_quarantined_handler();
        let result = handler.handle(notif(
            NodeStatus::Banned,
            "escalation",
            TS + 200,
        ));

        assert!(result.is_ok());
        if let Ok(tr) = result {
            assert_eq!(tr.from, NodeStatus::Quarantined);
            assert_eq!(tr.to, NodeStatus::Banned);
        }
        assert_eq!(handler.current_status(), NodeStatus::Banned);
    }

    #[test]
    fn test_handle_banned_clears_quarantine_metadata() {
        let mut handler = make_active_handler();

        // Quarantine first
        assert!(handler
            .handle(notif(NodeStatus::Quarantined, "drop", TS + 100))
            .is_ok());
        assert!(handler.quarantine_since().is_some());

        // Escalate to Banned
        assert!(handler
            .handle(notif(NodeStatus::Banned, "escalation", TS + 200))
            .is_ok());
        assert!(handler.quarantine_reason().is_none());
        assert!(handler.quarantine_since().is_none());
    }

    #[test]
    fn test_handle_banned_from_pending() {
        // Pending → Banned IS a valid transition
        let mut handler = make_pending_handler();
        let result = handler.handle(notif(
            NodeStatus::Banned,
            "identity spoofing at admission",
            TS + 1,
        ));
        assert!(result.is_ok());
        assert_eq!(handler.current_status(), NodeStatus::Banned);
    }

    // ──────────────────────────────────────────────────────────────────────
    // E. HANDLE — PENDING TRANSITIONS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_handle_pending_from_banned() {
        // Banned → Pending IS valid (rejoin after ban expiry)
        let mut handler = make_banned_handler();
        let result = handler.handle(notif(
            NodeStatus::Pending,
            "ban expired, re-admission",
            TS + 200,
        ));

        assert!(result.is_ok());
        if let Ok(tr) = result {
            assert_eq!(tr.from, NodeStatus::Banned);
            assert_eq!(tr.to, NodeStatus::Pending);
        }
        assert_eq!(handler.current_status(), NodeStatus::Pending);
    }

    #[test]
    fn test_handle_pending_from_active_rejected() {
        // Active → Pending is NOT valid
        let mut handler = make_active_handler();
        let result = handler.handle(notif(
            NodeStatus::Pending,
            "re-register",
            TS + 100,
        ));
        assert!(result.is_err());
        assert_eq!(handler.current_status(), NodeStatus::Active);
    }

    // ──────────────────────────────────────────────────────────────────────
    // F. HANDLE — TARGET VALIDATION
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_handle_wrong_target_rejected() {
        let mut handler = make_active_handler();
        let notif = StatusNotification {
            target_node_id: OTHER_NODE_ID,
            new_status: NodeStatus::Quarantined,
            reason: "drop".to_string(),
            timestamp: TS + 100,
        };

        let result = handler.handle(notif);
        assert!(result.is_err());
        // No state change
        assert_eq!(handler.current_status(), NodeStatus::Active);
    }

    // ──────────────────────────────────────────────────────────────────────
    // G. HANDLE — TIMESTAMP VALIDATION
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_handle_backwards_timestamp_rejected() {
        let mut handler = make_active_handler();
        // TS is the last transition timestamp; TS - 1 is backwards
        let result = handler.handle(notif(
            NodeStatus::Quarantined,
            "drop",
            TS - 1,
        ));
        assert!(result.is_err());
        assert_eq!(handler.current_status(), NodeStatus::Active);
    }

    #[test]
    fn test_handle_duplicate_timestamp_rejected() {
        let mut handler = make_active_handler();
        // TS is the exact timestamp of Pending→Active
        let result = handler.handle(notif(
            NodeStatus::Quarantined,
            "drop",
            TS,
        ));
        assert!(result.is_err());
        assert_eq!(handler.current_status(), NodeStatus::Active);
    }

    // ──────────────────────────────────────────────────────────────────────
    // H. HANDLE — NO SIDE EFFECTS ON ERROR
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_handle_error_no_side_effects() {
        let mut handler = make_active_handler();
        let tracker_clone = Arc::clone(&handler.status_tracker);
        let history_before = tracker_clone.lock().history().len();

        // Backwards timestamp → error
        let _ = handler.handle(notif(NodeStatus::Quarantined, "fail", TS - 1));

        // No state change
        assert_eq!(tracker_clone.lock().history().len(), history_before);
        assert_eq!(handler.current_status(), NodeStatus::Active);
        assert!(handler.quarantine_reason().is_none());
    }

    // ──────────────────────────────────────────────────────────────────────
    // I. PROCESS DA GATING EVENTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_process_events_filters_by_node_id() {
        let mut handler = make_pending_handler();
        let hex = test_node_hex();
        let other_hex = bytes_to_lower_hex(&OTHER_NODE_ID);

        let events = vec![
            // Event for OTHER node — should be skipped
            GatingEvent::NodeAdmitted {
                node_id: other_hex,
                operator: "aa".repeat(20),
                class: "Storage".to_string(),
                timestamp: TS + 1,
            },
            // Event for THIS node — should be processed
            GatingEvent::NodeAdmitted {
                node_id: hex,
                operator: "bb".repeat(20),
                class: "Storage".to_string(),
                timestamp: TS + 2,
            },
        ];

        let transitions = handler.process_da_gating_events(events);
        assert_eq!(transitions.len(), 1);
        assert_eq!(transitions[0].to, NodeStatus::Active);
    }

    #[test]
    fn test_process_events_skips_rejected() {
        let mut handler = make_pending_handler();
        let hex = test_node_hex();

        let events = vec![GatingEvent::NodeRejected {
            node_id: hex,
            operator: "aa".repeat(20),
            reasons: vec!["insufficient stake".to_string()],
            timestamp: TS + 1,
        }];

        let transitions = handler.process_da_gating_events(events);
        assert!(transitions.is_empty());
        assert_eq!(handler.current_status(), NodeStatus::Pending);
    }

    #[test]
    fn test_process_events_skips_ban_expired() {
        let mut handler = make_banned_handler();
        let hex = test_node_hex();

        let events = vec![GatingEvent::NodeBanExpired {
            node_id: hex,
            timestamp: TS + 200,
        }];

        let transitions = handler.process_da_gating_events(events);
        assert!(transitions.is_empty());
        // Status unchanged — rejoin is handled separately
        assert_eq!(handler.current_status(), NodeStatus::Banned);
    }

    #[test]
    fn test_process_events_admitted() {
        let mut handler = make_pending_handler();
        let hex = test_node_hex();

        let events = vec![GatingEvent::NodeAdmitted {
            node_id: hex,
            operator: "cc".repeat(20),
            class: "Compute".to_string(),
            timestamp: TS + 1,
        }];

        let transitions = handler.process_da_gating_events(events);
        assert_eq!(transitions.len(), 1);
        assert_eq!(transitions[0].from, NodeStatus::Pending);
        assert_eq!(transitions[0].to, NodeStatus::Active);
        assert_eq!(transitions[0].reason, "admitted to network");
    }

    #[test]
    fn test_process_events_quarantined() {
        let mut handler = make_active_handler();
        let hex = test_node_hex();

        let events = vec![GatingEvent::NodeQuarantined {
            node_id: hex,
            reason: "stake below minimum".to_string(),
            timestamp: TS + 100,
        }];

        let transitions = handler.process_da_gating_events(events);
        assert_eq!(transitions.len(), 1);
        assert_eq!(transitions[0].to, NodeStatus::Quarantined);
        assert_eq!(transitions[0].reason, "stake below minimum");
        assert_eq!(handler.quarantine_reason(), Some("stake below minimum"));
    }

    #[test]
    fn test_process_events_banned() {
        let mut handler = make_active_handler();
        let hex = test_node_hex();

        let events = vec![GatingEvent::NodeBanned {
            node_id: hex,
            reason: "severe slashing".to_string(),
            cooldown_until: TS + 86400,
            timestamp: TS + 100,
        }];

        let transitions = handler.process_da_gating_events(events);
        assert_eq!(transitions.len(), 1);
        assert_eq!(transitions[0].to, NodeStatus::Banned);
        assert_eq!(transitions[0].reason, "severe slashing");
    }

    #[test]
    fn test_process_events_activated() {
        let mut handler = make_quarantined_handler();
        let hex = test_node_hex();

        let events = vec![GatingEvent::NodeActivated {
            node_id: hex,
            timestamp: TS + 200,
        }];

        let transitions = handler.process_da_gating_events(events);
        assert_eq!(transitions.len(), 1);
        assert_eq!(transitions[0].from, NodeStatus::Quarantined);
        assert_eq!(transitions[0].to, NodeStatus::Active);
        assert_eq!(transitions[0].reason, "activated by coordinator");
    }

    #[test]
    fn test_process_events_multiple_sequential() {
        let mut handler = make_pending_handler();
        let hex = test_node_hex();

        // Pending → Active → Quarantined (all valid, sequential timestamps)
        let events = vec![
            GatingEvent::NodeAdmitted {
                node_id: hex.clone(),
                operator: "dd".repeat(20),
                class: "Storage".to_string(),
                timestamp: TS + 1,
            },
            GatingEvent::NodeQuarantined {
                node_id: hex,
                reason: "stake drop".to_string(),
                timestamp: TS + 2,
            },
        ];

        let transitions = handler.process_da_gating_events(events);
        assert_eq!(transitions.len(), 2);
        assert_eq!(transitions[0].from, NodeStatus::Pending);
        assert_eq!(transitions[0].to, NodeStatus::Active);
        assert_eq!(transitions[1].from, NodeStatus::Active);
        assert_eq!(transitions[1].to, NodeStatus::Quarantined);
        assert_eq!(handler.current_status(), NodeStatus::Quarantined);
    }

    #[test]
    fn test_process_events_invalid_transition_skipped() {
        let mut handler = make_pending_handler();
        let hex = test_node_hex();

        // Pending → Quarantined is INVALID — should be skipped
        let events = vec![GatingEvent::NodeQuarantined {
            node_id: hex,
            reason: "stake drop".to_string(),
            timestamp: TS + 1,
        }];

        let transitions = handler.process_da_gating_events(events);
        assert!(transitions.is_empty());
        assert_eq!(handler.current_status(), NodeStatus::Pending);
    }

    #[test]
    fn test_process_events_mixed_valid_invalid() {
        let mut handler = make_active_handler();
        let hex = test_node_hex();

        let events = vec![
            // Valid: Active → Quarantined
            GatingEvent::NodeQuarantined {
                node_id: hex.clone(),
                reason: "drop".to_string(),
                timestamp: TS + 100,
            },
            // Invalid: Quarantined → Quarantined (double)
            GatingEvent::NodeQuarantined {
                node_id: hex,
                reason: "second drop".to_string(),
                timestamp: TS + 200,
            },
        ];

        let transitions = handler.process_da_gating_events(events);
        // Only first transition collected
        assert_eq!(transitions.len(), 1);
        assert_eq!(transitions[0].to, NodeStatus::Quarantined);
        assert_eq!(transitions[0].reason, "drop");
    }

    #[test]
    fn test_process_events_empty_vec() {
        let mut handler = make_active_handler();
        let transitions = handler.process_da_gating_events(Vec::new());
        assert!(transitions.is_empty());
    }

    // ──────────────────────────────────────────────────────────────────────
    // J. DETERMINISM
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_handle_deterministic() {
        // Two handlers with identical state produce identical results
        let mut h1 = make_active_handler();
        let mut h2 = make_active_handler();

        let n1 = notif(NodeStatus::Quarantined, "stake drop", TS + 100);
        let n2 = notif(NodeStatus::Quarantined, "stake drop", TS + 100);

        let r1 = h1.handle(n1);
        let r2 = h2.handle(n2);

        assert_eq!(r1, r2);
        assert_eq!(h1.quarantine_reason(), h2.quarantine_reason());
        assert_eq!(h1.quarantine_since(), h2.quarantine_since());
    }

    #[test]
    fn test_process_events_deterministic() {
        let hex = test_node_hex();

        let events1 = vec![
            GatingEvent::NodeAdmitted {
                node_id: hex.clone(),
                operator: "aa".repeat(20),
                class: "Storage".to_string(),
                timestamp: TS + 1,
            },
            GatingEvent::NodeQuarantined {
                node_id: hex.clone(),
                reason: "drop".to_string(),
                timestamp: TS + 2,
            },
        ];
        let events2 = events1.clone();

        let mut h1 = make_pending_handler();
        let mut h2 = make_pending_handler();

        let t1 = h1.process_da_gating_events(events1);
        let t2 = h2.process_da_gating_events(events2);

        assert_eq!(t1, t2);
    }

    // ──────────────────────────────────────────────────────────────────────
    // K. FULL LIFECYCLE FLOW
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_full_lifecycle() {
        let mut handler = make_pending_handler();
        let hex = test_node_hex();

        let events = vec![
            // 1. Pending → Active (admitted)
            GatingEvent::NodeAdmitted {
                node_id: hex.clone(),
                operator: "ee".repeat(20),
                class: "Storage".to_string(),
                timestamp: TS + 1,
            },
            // 2. Active → Quarantined
            GatingEvent::NodeQuarantined {
                node_id: hex.clone(),
                reason: "stake drop".to_string(),
                timestamp: TS + 2,
            },
            // 3. Quarantined → Active (recovery)
            GatingEvent::NodeActivated {
                node_id: hex.clone(),
                timestamp: TS + 3,
            },
            // 4. Active → Banned
            GatingEvent::NodeBanned {
                node_id: hex.clone(),
                reason: "identity spoofing".to_string(),
                cooldown_until: TS + 86400,
                timestamp: TS + 4,
            },
        ];

        let transitions = handler.process_da_gating_events(events);
        assert_eq!(transitions.len(), 4);

        // Verify full chain
        assert_eq!(transitions[0].from, NodeStatus::Pending);
        assert_eq!(transitions[0].to, NodeStatus::Active);

        assert_eq!(transitions[1].from, NodeStatus::Active);
        assert_eq!(transitions[1].to, NodeStatus::Quarantined);

        assert_eq!(transitions[2].from, NodeStatus::Quarantined);
        assert_eq!(transitions[2].to, NodeStatus::Active);

        assert_eq!(transitions[3].from, NodeStatus::Active);
        assert_eq!(transitions[3].to, NodeStatus::Banned);

        assert_eq!(handler.current_status(), NodeStatus::Banned);
        // Quarantine metadata cleared after recovery then ban
        assert!(handler.quarantine_reason().is_none());
        assert!(handler.quarantine_since().is_none());
    }

    // ──────────────────────────────────────────────────────────────────────
    // L. DEBUG
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_debug_output() {
        let handler = make_active_handler();
        let debug = format!("{:?}", handler);
        assert!(debug.contains("StatusNotificationHandler"));
        assert!(debug.contains("node_id_hex"));
        assert!(debug.contains("current_status"));
    }

    // ──────────────────────────────────────────────────────────────────────
    // M. HELPER FUNCTION TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_bytes_to_lower_hex() {
        let bytes = [0xAB, 0xCD, 0x01, 0x23];
        assert_eq!(bytes_to_lower_hex(&bytes), "abcd0123");
    }

    #[test]
    fn test_bytes_to_lower_hex_empty() {
        assert_eq!(bytes_to_lower_hex(&[]), "");
    }

    #[test]
    fn test_extract_event_node_id_all_variants() {
        let id = "abc123".to_string();

        let admitted = GatingEvent::NodeAdmitted {
            node_id: id.clone(),
            operator: "op".to_string(),
            class: "Storage".to_string(),
            timestamp: 0,
        };
        assert_eq!(extract_event_node_id(&admitted), "abc123");

        let rejected = GatingEvent::NodeRejected {
            node_id: id.clone(),
            operator: "op".to_string(),
            reasons: vec![],
            timestamp: 0,
        };
        assert_eq!(extract_event_node_id(&rejected), "abc123");

        let quarantined = GatingEvent::NodeQuarantined {
            node_id: id.clone(),
            reason: "r".to_string(),
            timestamp: 0,
        };
        assert_eq!(extract_event_node_id(&quarantined), "abc123");

        let banned = GatingEvent::NodeBanned {
            node_id: id.clone(),
            reason: "r".to_string(),
            cooldown_until: 0,
            timestamp: 0,
        };
        assert_eq!(extract_event_node_id(&banned), "abc123");

        let activated = GatingEvent::NodeActivated {
            node_id: id.clone(),
            timestamp: 0,
        };
        assert_eq!(extract_event_node_id(&activated), "abc123");

        let expired = GatingEvent::NodeBanExpired {
            node_id: id,
            timestamp: 0,
        };
        assert_eq!(extract_event_node_id(&expired), "abc123");
    }

    #[test]
    fn test_map_gating_event_all_variants() {
        let handler = make_active_handler();
        let hex = test_node_hex();

        // NodeAdmitted → Some(Active)
        let admitted = GatingEvent::NodeAdmitted {
            node_id: hex.clone(),
            operator: "aa".repeat(20),
            class: "Storage".to_string(),
            timestamp: 100,
        };
        let n = handler.map_gating_event(&admitted);
        assert!(n.is_some());
        if let Some(notif) = n {
            assert_eq!(notif.new_status, NodeStatus::Active);
            assert_eq!(notif.reason, "admitted to network");
        }

        // NodeActivated → Some(Active)
        let activated = GatingEvent::NodeActivated {
            node_id: hex.clone(),
            timestamp: 100,
        };
        let n = handler.map_gating_event(&activated);
        assert!(n.is_some());
        if let Some(notif) = n {
            assert_eq!(notif.new_status, NodeStatus::Active);
            assert_eq!(notif.reason, "activated by coordinator");
        }

        // NodeQuarantined → Some(Quarantined)
        let quarantined = GatingEvent::NodeQuarantined {
            node_id: hex.clone(),
            reason: "stake drop".to_string(),
            timestamp: 100,
        };
        let n = handler.map_gating_event(&quarantined);
        assert!(n.is_some());
        if let Some(notif) = n {
            assert_eq!(notif.new_status, NodeStatus::Quarantined);
            assert_eq!(notif.reason, "stake drop");
        }

        // NodeBanned → Some(Banned)
        let banned = GatingEvent::NodeBanned {
            node_id: hex.clone(),
            reason: "slashing".to_string(),
            cooldown_until: 200,
            timestamp: 100,
        };
        let n = handler.map_gating_event(&banned);
        assert!(n.is_some());
        if let Some(notif) = n {
            assert_eq!(notif.new_status, NodeStatus::Banned);
            assert_eq!(notif.reason, "slashing");
        }

        // NodeRejected → None
        let rejected = GatingEvent::NodeRejected {
            node_id: hex.clone(),
            operator: "aa".repeat(20),
            reasons: vec![],
            timestamp: 100,
        };
        assert!(handler.map_gating_event(&rejected).is_none());

        // NodeBanExpired → None
        let expired = GatingEvent::NodeBanExpired {
            node_id: hex,
            timestamp: 100,
        };
        assert!(handler.map_gating_event(&expired).is_none());
    }

    // ──────────────────────────────────────────────────────────────────────
    // N. STATUS NOTIFICATION STRUCT
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_status_notification_clone() {
        let n = notif(NodeStatus::Active, "test", 100);
        let n2 = n.clone();
        assert_eq!(n, n2);
    }

    #[test]
    fn test_status_notification_debug() {
        let n = notif(NodeStatus::Quarantined, "test", 100);
        let debug = format!("{:?}", n);
        assert!(debug.contains("Quarantined"));
        assert!(debug.contains("test"));
    }
}