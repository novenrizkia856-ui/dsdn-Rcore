//! # Rejoin Manager (14B.46)
//!
//! Provides [`RejoinManager`] for managing the node's re-join lifecycle
//! after a ban expires or quarantine recovery completes.
//!
//! ## Purpose
//!
//! When a node is banned or quarantined, it cannot participate in the
//! network. `RejoinManager` handles the re-admission flow:
//!
//! 1. **Eligibility check**: `can_rejoin` evaluates whether the node
//!    is eligible to attempt re-joining based on its current status
//!    and cooldown state.
//! 2. **Request construction**: `build_rejoin_request` creates a
//!    `JoinRequest` identical in structure to an initial join, using
//!    the existing identity and TLS certificate.
//! 3. **Response handling**: `handle_rejoin_response` applies the
//!    coordinator's decision to the local `NodeStatusTracker`.
//!
//! ## Initial Join vs Re-Join
//!
//! There is no structural difference between an initial join request
//! and a re-join request. Both use the same `JoinRequest` format and
//! `JoinRequestBuilder`. The distinction is semantic:
//!
//! - **Initial join**: Node starts in `Pending` (fresh).
//! - **Re-join after ban**: Node is in `Banned`, cooldown must have
//!   expired. The coordinator transitions `Banned → Pending`.
//! - **Re-join after quarantine**: Node is in `Quarantined`, stake
//!   must be sufficient. The coordinator transitions
//!   `Quarantined → Active`.
//!
//! ## Ban Expiry Logic
//!
//! A banned node can re-join when:
//! - Status is `Banned`.
//! - A `CooldownPeriod` is provided.
//! - `cooldown.is_active(current_timestamp)` returns `false`
//!   (cooldown has expired).
//!
//! `can_rejoin` does NOT modify state. It is a pure read-only check.
//!
//! ## Quarantine Recovery
//!
//! A quarantined node can re-join when:
//! - Status is `Quarantined`.
//! - No active cooldown is blocking the attempt.
//!
//! Stake verification is the coordinator's responsibility — the node
//! side cannot verify on-chain stake autonomously.
//!
//! ## Thread Safety
//!
//! `NodeStatusTracker::update_status` requires `&mut self`.
//! Since the contract requires `Arc<NodeStatusTracker>`, mutation
//! through `Arc` requires interior mutability. `parking_lot::Mutex`
//! (already a crate dependency) provides this with no poisoning
//! semantics. The Mutex is locked only for the duration of each
//! operation (no held-across-await).
//!
//! ## Safety
//!
//! - No `panic!`, `unwrap()`, `expect()`.
//! - No `unsafe` code.
//! - All state transitions delegated to `NodeStatusTracker::update_status`
//!   which enforces `NodeStatus::can_transition_to`.
//! - No implicit state mutation in read-only methods.
//! - No bypass of lifecycle rules.

use std::sync::Arc;

use dsdn_common::gating::{
    CooldownPeriod, IdentityChallenge, NodeClass, NodeStatus,
};
use parking_lot::Mutex;

use crate::identity_manager::NodeIdentityManager;
use crate::join_request::{JoinError, JoinRequest, JoinRequestBuilder, JoinResponse};
use crate::status_tracker::NodeStatusTracker;
use crate::tls_manager::TLSCertManager;

// ════════════════════════════════════════════════════════════════════════════════
// REJOIN MANAGER
// ════════════════════════════════════════════════════════════════════════════════

/// Manages node re-admission after ban expiry or quarantine recovery.
///
/// Holds shared references (`Arc`) to the node's identity manager,
/// TLS manager, and status tracker. The status tracker is wrapped in
/// `Mutex` because `update_status` requires `&mut self`.
///
/// ## Ownership
///
/// | Field | Type | Rationale |
/// |-------|------|-----------|
/// | `identity_manager` | `Arc<NodeIdentityManager>` | Read-only, shared with other subsystems |
/// | `tls_manager` | `Arc<TLSCertManager>` | Read-only, shared with other subsystems |
/// | `status_tracker` | `Arc<Mutex<NodeStatusTracker>>` | Mutable, `update_status` requires `&mut` |
pub struct RejoinManager {
    /// Shared reference to the node's identity manager.
    identity_manager: Arc<NodeIdentityManager>,
    /// Shared reference to the TLS certificate manager.
    tls_manager: Arc<TLSCertManager>,
    /// Shared, mutex-protected status tracker.
    status_tracker: Arc<Mutex<NodeStatusTracker>>,
}

impl RejoinManager {
    /// Creates a new `RejoinManager` with shared references to the
    /// node's identity, TLS, and status subsystems.
    pub fn new(
        identity_manager: Arc<NodeIdentityManager>,
        tls_manager: Arc<TLSCertManager>,
        status_tracker: Arc<Mutex<NodeStatusTracker>>,
    ) -> Self {
        Self {
            identity_manager,
            tls_manager,
            status_tracker,
        }
    }

    /// Evaluates whether the node is eligible to attempt re-joining.
    ///
    /// ## Eligibility Conditions
    ///
    /// Returns `true` if **one** of the following holds:
    ///
    /// **A) Ban expired**:
    /// - Current status is `Banned`.
    /// - `cooldown` is `Some`.
    /// - `cooldown.is_active(current_timestamp)` is `false` (expired).
    ///
    /// **B) Quarantine recovery**:
    /// - Current status is `Quarantined`.
    /// - Either no cooldown is provided, or the cooldown has expired.
    ///
    /// All other statuses return `false` (Pending and Active nodes
    /// have no reason to re-join).
    ///
    /// ## Pure Function
    ///
    /// Does NOT modify any state. Locks the status tracker briefly
    /// to read the current status, then releases the lock.
    ///
    /// ## Determinism
    ///
    /// Same status + same cooldown + same timestamp → same result.
    pub fn can_rejoin(
        &self,
        current_timestamp: u64,
        cooldown: Option<&CooldownPeriod>,
    ) -> bool {
        let tracker = self.status_tracker.lock();
        let status = *tracker.current();
        drop(tracker);

        match status {
            // A) Ban expired: cooldown must be provided and expired
            NodeStatus::Banned => {
                match cooldown {
                    Some(cd) => !cd.is_active(current_timestamp),
                    None => false,
                }
            }
            // B) Quarantine recovery: no active cooldown blocking
            NodeStatus::Quarantined => {
                match cooldown {
                    Some(cd) => !cd.is_active(current_timestamp),
                    None => true,
                }
            }
            // Pending / Active: no re-join needed
            _ => false,
        }
    }

    /// Builds a re-join request using the existing identity and TLS certificate.
    ///
    /// Structurally identical to an initial join request. Uses
    /// `JoinRequestBuilder` to construct the request with identity
    /// proof signed against the provided challenge.
    ///
    /// ## Parameters
    ///
    /// - `class`: The node class to claim.
    /// - `challenge`: The coordinator-issued identity challenge.
    /// - `addr`: The node's network address.
    ///
    /// ## Errors
    ///
    /// Returns `JoinError` if:
    /// - Address is empty (`JoinError::MissingAddr`).
    /// - Identity proof construction fails (`JoinError::IdentityError`).
    pub fn build_rejoin_request(
        &self,
        class: NodeClass,
        challenge: IdentityChallenge,
        addr: String,
    ) -> Result<JoinRequest, JoinError> {
        JoinRequestBuilder::new(&self.identity_manager, class)
            .with_tls(&self.tls_manager)
            .with_addr(addr)
            .build(challenge)
    }

    /// Applies the coordinator's re-join response to the local status tracker.
    ///
    /// ## Approved Response
    ///
    /// If `response.approved == true`:
    /// - Transitions the tracker to `response.assigned_status`.
    /// - The transition is validated by `NodeStatusTracker::update_status`
    ///   which enforces `NodeStatus::can_transition_to`.
    /// - Valid re-join transitions:
    ///   - `Banned → Pending` (ban cooldown expired, re-entering admission)
    ///   - `Quarantined → Active` (stake restored, immediate recovery)
    /// - Invalid transitions are rejected by the tracker.
    ///
    /// ## Rejected Response
    ///
    /// If `response.approved == false`:
    /// - No state change.
    /// - Returns `Err` with the rejection reasons for the caller to handle.
    ///
    /// ## Errors
    ///
    /// Returns `Err(String)` if:
    /// - The response is rejected (includes rejection reasons).
    /// - The approved transition is illegal per the state machine.
    /// - The timestamp violates monotonicity.
    pub fn handle_rejoin_response(
        &self,
        response: &JoinResponse,
        timestamp: u64,
    ) -> Result<(), String> {
        if !response.approved {
            let reasons = if response.rejection_reasons.is_empty() {
                "no reasons provided".to_string()
            } else {
                response.rejection_reasons.join("; ")
            };
            return Err(format!("rejoin request rejected: {}", reasons));
        }

        // Approved: transition to assigned status
        let mut tracker = self.status_tracker.lock();
        tracker.update_status(
            response.assigned_status,
            "rejoin approved by coordinator".to_string(),
            timestamp,
        )
    }

    /// Returns the current status by reading the tracker.
    ///
    /// Locks the Mutex briefly. Returns a copy (NodeStatus is `Copy`).
    pub fn current_status(&self) -> NodeStatus {
        *self.status_tracker.lock().current()
    }
}

impl std::fmt::Debug for RejoinManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let status = self.current_status();
        f.debug_struct("RejoinManager")
            .field("current_status", &status)
            .field("identity_manager", &"[Arc]")
            .field("tls_manager", &"[Arc]")
            .finish()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// COMPILE-TIME ASSERTIONS
// ════════════════════════════════════════════════════════════════════════════════

const _: () = {
    fn assert_send<T: Send>() {}
    fn check() { assert_send::<RejoinManager>(); }
    let _ = check;
};

const _: () = {
    fn assert_sync<T: Sync>() {}
    fn check() { assert_sync::<RejoinManager>(); }
    let _ = check;
};

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    const TS: u64 = 1_700_000_000;

    const TEST_SEED: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    ];

    // ──────────────────────────────────────────────────────────────────
    // HELPERS
    // ──────────────────────────────────────────────────────────────────

    fn make_id_mgr() -> Arc<NodeIdentityManager> {
        Arc::new(
            NodeIdentityManager::from_keypair(TEST_SEED)
                .expect("test setup: from_keypair"),
        )
    }

    fn make_tls_mgr() -> Arc<TLSCertManager> {
        Arc::new(
            TLSCertManager::generate_self_signed("rejoin.dsdn.local", 365)
                .expect("test setup: generate_self_signed"),
        )
    }

    fn make_challenge() -> IdentityChallenge {
        IdentityChallenge {
            nonce: [0x42; 32],
            timestamp: TS,
            challenger: "coordinator".to_string(),
        }
    }

    /// Tracker in Banned state: Pending → Active → Banned.
    fn make_banned_tracker() -> Arc<Mutex<NodeStatusTracker>> {
        let mut t = NodeStatusTracker::new();
        t.update_status(NodeStatus::Active, "approved".to_string(), TS)
            .expect("test setup: pending → active");
        t.update_status(NodeStatus::Banned, "slashing".to_string(), TS + 100)
            .expect("test setup: active → banned");
        Arc::new(Mutex::new(t))
    }

    /// Tracker in Quarantined state: Pending → Active → Quarantined.
    fn make_quarantined_tracker() -> Arc<Mutex<NodeStatusTracker>> {
        let mut t = NodeStatusTracker::new();
        t.update_status(NodeStatus::Active, "approved".to_string(), TS)
            .expect("test setup: pending → active");
        t.update_status(NodeStatus::Quarantined, "stake drop".to_string(), TS + 100)
            .expect("test setup: active → quarantined");
        Arc::new(Mutex::new(t))
    }

    /// Tracker in Active state: Pending → Active.
    fn make_active_tracker() -> Arc<Mutex<NodeStatusTracker>> {
        let mut t = NodeStatusTracker::new();
        t.update_status(NodeStatus::Active, "approved".to_string(), TS)
            .expect("test setup: pending → active");
        Arc::new(Mutex::new(t))
    }

    fn make_cooldown(start: u64, duration: u64) -> CooldownPeriod {
        CooldownPeriod {
            start_timestamp: start,
            duration_secs: duration,
            reason: "ban cooldown".to_string(),
        }
    }

    fn make_rejoin_manager(
        tracker: Arc<Mutex<NodeStatusTracker>>,
    ) -> RejoinManager {
        RejoinManager::new(make_id_mgr(), make_tls_mgr(), tracker)
    }

    // ──────────────────────────────────────────────────────────────────
    // CAN_REJOIN — BANNED
    // ──────────────────────────────────────────────────────────────────

    /// Banned + cooldown expired → can rejoin.
    #[test]
    fn test_can_rejoin_banned_cooldown_expired() {
        let mgr = make_rejoin_manager(make_banned_tracker());
        let cd = make_cooldown(TS + 100, 3600); // Expires at TS+3700
        assert!(mgr.can_rejoin(TS + 3700, Some(&cd)));
    }

    /// Banned + cooldown still active → cannot rejoin.
    #[test]
    fn test_can_rejoin_banned_cooldown_active() {
        let mgr = make_rejoin_manager(make_banned_tracker());
        let cd = make_cooldown(TS + 100, 3600);
        assert!(!mgr.can_rejoin(TS + 3699, Some(&cd)));
    }

    /// Banned + no cooldown provided → cannot rejoin.
    #[test]
    fn test_can_rejoin_banned_no_cooldown() {
        let mgr = make_rejoin_manager(make_banned_tracker());
        assert!(!mgr.can_rejoin(TS + 10_000, None));
    }

    // ──────────────────────────────────────────────────────────────────
    // CAN_REJOIN — QUARANTINED
    // ──────────────────────────────────────────────────────────────────

    /// Quarantined + no cooldown → can rejoin.
    #[test]
    fn test_can_rejoin_quarantined_no_cooldown() {
        let mgr = make_rejoin_manager(make_quarantined_tracker());
        assert!(mgr.can_rejoin(TS + 200, None));
    }

    /// Quarantined + cooldown expired → can rejoin.
    #[test]
    fn test_can_rejoin_quarantined_cooldown_expired() {
        let mgr = make_rejoin_manager(make_quarantined_tracker());
        let cd = make_cooldown(TS + 100, 100);
        assert!(mgr.can_rejoin(TS + 200, Some(&cd)));
    }

    /// Quarantined + cooldown active → cannot rejoin.
    #[test]
    fn test_can_rejoin_quarantined_cooldown_active() {
        let mgr = make_rejoin_manager(make_quarantined_tracker());
        let cd = make_cooldown(TS + 100, 3600);
        assert!(!mgr.can_rejoin(TS + 200, Some(&cd)));
    }

    // ──────────────────────────────────────────────────────────────────
    // CAN_REJOIN — OTHER STATUSES
    // ──────────────────────────────────────────────────────────────────

    /// Active → cannot rejoin.
    #[test]
    fn test_can_rejoin_active() {
        let mgr = make_rejoin_manager(make_active_tracker());
        assert!(!mgr.can_rejoin(TS + 200, None));
    }

    /// Pending → cannot rejoin.
    #[test]
    fn test_can_rejoin_pending() {
        let tracker = Arc::new(Mutex::new(NodeStatusTracker::new()));
        let mgr = make_rejoin_manager(tracker);
        assert!(!mgr.can_rejoin(TS, None));
    }

    /// can_rejoin does not modify state.
    #[test]
    fn test_can_rejoin_no_side_effects() {
        let tracker = make_banned_tracker();
        let mgr = make_rejoin_manager(Arc::clone(&tracker));
        let cd = make_cooldown(TS + 100, 3600);

        let history_len = tracker.lock().history().len();
        let _ = mgr.can_rejoin(TS + 5000, Some(&cd));
        assert_eq!(tracker.lock().history().len(), history_len);
    }

    // ──────────────────────────────────────────────────────────────────
    // BUILD REJOIN REQUEST
    // ──────────────────────────────────────────────────────────────────

    /// Build succeeds with valid parameters.
    #[test]
    fn test_build_rejoin_request_success() {
        let mgr = make_rejoin_manager(make_banned_tracker());
        let result = mgr.build_rejoin_request(
            NodeClass::Storage,
            make_challenge(),
            "https://node.dsdn.io:8443".to_string(),
        );
        assert!(result.is_ok());
        if let Ok(req) = result {
            assert_eq!(req.node_addr, "https://node.dsdn.io:8443");
            assert!(req.identity_proof.verify());
        }
    }

    /// Build fails with empty address.
    #[test]
    fn test_build_rejoin_request_empty_addr() {
        let mgr = make_rejoin_manager(make_banned_tracker());
        let result = mgr.build_rejoin_request(
            NodeClass::Storage,
            make_challenge(),
            String::new(),
        );
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e, JoinError::MissingAddr);
        }
    }

    /// Rejoin request is deterministic.
    #[test]
    fn test_build_rejoin_request_deterministic() {
        let mgr = make_rejoin_manager(make_banned_tracker());
        let req1 = mgr.build_rejoin_request(
            NodeClass::Storage, make_challenge(), "addr".to_string(),
        );
        let req2 = mgr.build_rejoin_request(
            NodeClass::Storage, make_challenge(), "addr".to_string(),
        );
        assert!(req1.is_ok());
        assert!(req2.is_ok());
        if let (Ok(r1), Ok(r2)) = (req1, req2) {
            assert_eq!(r1.identity.node_id, r2.identity.node_id);
            assert_eq!(r1.identity_proof.signature, r2.identity_proof.signature);
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // HANDLE REJOIN RESPONSE — APPROVED
    // ──────────────────────────────────────────────────────────────────

    /// Banned → Pending via approved response.
    #[test]
    fn test_handle_response_banned_to_pending() {
        let tracker = make_banned_tracker();
        let mgr = make_rejoin_manager(Arc::clone(&tracker));
        let resp = JoinResponse {
            approved: true,
            assigned_status: NodeStatus::Pending,
            report: None,
            rejection_reasons: vec![],
        };
        let result = mgr.handle_rejoin_response(&resp, TS + 5000);
        assert!(result.is_ok());
        assert_eq!(*tracker.lock().current(), NodeStatus::Pending);
    }

    /// Quarantined → Active via approved response.
    #[test]
    fn test_handle_response_quarantined_to_active() {
        let tracker = make_quarantined_tracker();
        let mgr = make_rejoin_manager(Arc::clone(&tracker));
        let resp = JoinResponse {
            approved: true,
            assigned_status: NodeStatus::Active,
            report: None,
            rejection_reasons: vec![],
        };
        let result = mgr.handle_rejoin_response(&resp, TS + 5000);
        assert!(result.is_ok());
        assert_eq!(*tracker.lock().current(), NodeStatus::Active);
    }

    /// Approved but illegal transition (Banned → Active) → error.
    #[test]
    fn test_handle_response_illegal_transition() {
        let tracker = make_banned_tracker();
        let mgr = make_rejoin_manager(Arc::clone(&tracker));
        let resp = JoinResponse {
            approved: true,
            assigned_status: NodeStatus::Active,
            report: None,
            rejection_reasons: vec![],
        };
        let result = mgr.handle_rejoin_response(&resp, TS + 5000);
        assert!(result.is_err());
        assert_eq!(*tracker.lock().current(), NodeStatus::Banned);
    }

    /// Approved but backwards timestamp → error.
    #[test]
    fn test_handle_response_backwards_timestamp() {
        let tracker = make_banned_tracker();
        let mgr = make_rejoin_manager(Arc::clone(&tracker));
        let resp = JoinResponse {
            approved: true,
            assigned_status: NodeStatus::Pending,
            report: None,
            rejection_reasons: vec![],
        };
        let result = mgr.handle_rejoin_response(&resp, TS + 50);
        assert!(result.is_err());
        assert_eq!(*tracker.lock().current(), NodeStatus::Banned);
    }

    // ──────────────────────────────────────────────────────────────────
    // HANDLE REJOIN RESPONSE — REJECTED
    // ──────────────────────────────────────────────────────────────────

    /// Rejected response with reasons.
    #[test]
    fn test_handle_response_rejected_with_reasons() {
        let tracker = make_banned_tracker();
        let mgr = make_rejoin_manager(Arc::clone(&tracker));
        let resp = JoinResponse {
            approved: false,
            assigned_status: NodeStatus::Banned,
            report: None,
            rejection_reasons: vec![
                "cooldown not expired".to_string(),
                "insufficient stake".to_string(),
            ],
        };
        let result = mgr.handle_rejoin_response(&resp, TS + 5000);
        assert!(result.is_err());
        if let Err(msg) = result {
            assert!(msg.contains("cooldown not expired"));
            assert!(msg.contains("insufficient stake"));
        }
        assert_eq!(*tracker.lock().current(), NodeStatus::Banned);
    }

    /// Rejected response with empty reasons.
    #[test]
    fn test_handle_response_rejected_empty_reasons() {
        let tracker = make_banned_tracker();
        let mgr = make_rejoin_manager(Arc::clone(&tracker));
        let resp = JoinResponse {
            approved: false,
            assigned_status: NodeStatus::Banned,
            report: None,
            rejection_reasons: vec![],
        };
        let result = mgr.handle_rejoin_response(&resp, TS + 5000);
        assert!(result.is_err());
        if let Err(msg) = result {
            assert!(msg.contains("no reasons provided"));
        }
    }

    /// Rejected response does not change state.
    #[test]
    fn test_handle_response_rejected_no_state_change() {
        let tracker = make_quarantined_tracker();
        let mgr = make_rejoin_manager(Arc::clone(&tracker));
        let history_len = tracker.lock().history().len();
        let resp = JoinResponse {
            approved: false,
            assigned_status: NodeStatus::Quarantined,
            report: None,
            rejection_reasons: vec!["denied".to_string()],
        };
        let _ = mgr.handle_rejoin_response(&resp, TS + 5000);
        assert_eq!(tracker.lock().history().len(), history_len);
        assert_eq!(*tracker.lock().current(), NodeStatus::Quarantined);
    }

    // ──────────────────────────────────────────────────────────────────
    // CURRENT STATUS
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_current_status() {
        let mgr = make_rejoin_manager(make_banned_tracker());
        assert_eq!(mgr.current_status(), NodeStatus::Banned);
    }

    // ──────────────────────────────────────────────────────────────────
    // DEBUG
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_debug_output() {
        let mgr = make_rejoin_manager(make_banned_tracker());
        let debug_str = format!("{:?}", mgr);
        assert!(debug_str.contains("RejoinManager"));
        assert!(debug_str.contains("Banned"));
    }
}