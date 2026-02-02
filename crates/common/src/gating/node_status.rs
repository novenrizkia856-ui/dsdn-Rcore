//! # Node Status & Lifecycle Transitions (14B.2)
//!
//! Defines the lifecycle states of DSDN service nodes and the strict,
//! deterministic rules governing transitions between them.
//!
//! ## Overview
//!
//! Every service node in the DSDN network is in exactly one of four states
//! at any given time. The set of allowed transitions between states is a
//! **closed set** — transitions not explicitly listed are forbidden.
//!
//! ## States
//!
//! | Status | Meaning | Schedulable |
//! |--------|---------|-------------|
//! | `Pending` | Newly registered, awaiting verification | No |
//! | `Active` | Verified and eligible for scheduling | **Yes** |
//! | `Quarantined` | Suspended due to stake drop or minor violation | No |
//! | `Banned` | Permanently removed, subject to cooldown before re-registration | No |
//!
//! ## Transition Rules (Closed Set)
//!
//! ```text
//! From          → To             Trigger
//! ─────────────── ────────────── ──────────────────────────────
//! Pending       → Active         All gating checks pass
//! Pending       → Banned         Identity spoofing detected
//! Active        → Quarantined    Stake drop or minor violation
//! Active        → Banned         Severe slashing event
//! Quarantined   → Active         Stake restored + re-check pass
//! Quarantined   → Banned         Further violation while quarantined
//! Banned        → Pending        Cooldown expired, must re-register
//! ```
//!
//! **All other transitions are forbidden and will be rejected.**
//!
//! There are no implicit transitions, no auto-recovery mechanisms, and no
//! self-transitions (a node cannot transition from a state to itself).
//!
//! ## Security Properties
//!
//! - **No implicit re-activation**: A Banned node cannot become Active
//!   without first transitioning to Pending and passing all gating checks.
//! - **No bypass path**: There is no shortcut from Quarantined to Active
//!   that skips re-verification. The `Quarantined → Active` transition
//!   requires explicit stake restoration AND re-check pass.
//! - **Deterministic**: `can_transition_to` is a pure function with no
//!   external dependencies, no configuration, and no side effects.
//! - **No silent failures**: The function returns a boolean; callers
//!   decide how to handle rejection.

use serde::{Deserialize, Serialize};
use std::fmt;

// ════════════════════════════════════════════════════════════════════════════════
// NODE STATUS
// ════════════════════════════════════════════════════════════════════════════════

/// Lifecycle status of a DSDN service node.
///
/// A node is always in exactly one of these four states. The allowed
/// transitions between states form a **closed set** — any transition
/// not explicitly listed in `can_transition_to` is forbidden.
///
/// Only `Active` nodes are eligible for scheduling by the coordinator.
///
/// ## State Descriptions
///
/// - **`Pending`**: The node has been registered on-chain but has not yet
///   passed all gating checks (stake verification, identity proof, TLS
///   validation). Pending nodes cannot receive workloads.
///
/// - **`Active`**: The node has passed all gating checks and is eligible
///   to be scheduled for workloads. This is the ONLY schedulable state.
///
/// - **`Quarantined`**: The node has been suspended due to a stake drop
///   below the class minimum or a minor protocol violation. Quarantined
///   nodes cannot receive new workloads but retain their registration.
///   Recovery to `Active` requires stake restoration and re-verification.
///
/// - **`Banned`**: The node has been permanently removed from the active
///   set due to identity spoofing or severe slashing. A banned node must
///   wait for its cooldown period to expire, then re-register as `Pending`.
///   There is no direct path from `Banned` to `Active`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeStatus {
    /// Newly registered, awaiting gating verification.
    Pending,
    /// Verified and eligible for scheduling.
    Active,
    /// Suspended due to stake drop or minor violation.
    Quarantined,
    /// Removed due to identity spoofing or severe slashing; subject to cooldown.
    Banned,
}

impl fmt::Display for NodeStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeStatus::Pending => write!(f, "pending"),
            NodeStatus::Active => write!(f, "active"),
            NodeStatus::Quarantined => write!(f, "quarantined"),
            NodeStatus::Banned => write!(f, "banned"),
        }
    }
}

impl NodeStatus {
    /// Returns whether a transition from `self` to `target` is allowed.
    ///
    /// This is a **pure function** — deterministic, no side effects, no
    /// external dependencies, no configuration.
    ///
    /// ## Allowed Transitions
    ///
    /// | From | To | Trigger |
    /// |------|----|---------|
    /// | Pending | Active | All gating checks pass |
    /// | Pending | Banned | Identity spoofing detected |
    /// | Active | Quarantined | Stake drop or minor violation |
    /// | Active | Banned | Severe slashing event |
    /// | Quarantined | Active | Stake restored + re-check pass |
    /// | Quarantined | Banned | Further violation while quarantined |
    /// | Banned | Pending | Cooldown expired, must re-register |
    ///
    /// ## Rejected Transitions
    ///
    /// All transitions not listed above return `false`, including:
    /// - Self-transitions (e.g., `Active → Active`)
    /// - Backward jumps not listed (e.g., `Banned → Active`)
    /// - Skip transitions (e.g., `Pending → Quarantined`)
    ///
    /// ## Arguments
    ///
    /// * `target` — The desired target status.
    ///
    /// ## Returns
    ///
    /// `true` if the transition is allowed, `false` otherwise.
    #[must_use]
    #[inline]
    pub const fn can_transition_to(&self, target: NodeStatus) -> bool {
        matches!(
            (self, &target),
            (NodeStatus::Pending, NodeStatus::Active)
                | (NodeStatus::Pending, NodeStatus::Banned)
                | (NodeStatus::Active, NodeStatus::Quarantined)
                | (NodeStatus::Active, NodeStatus::Banned)
                | (NodeStatus::Quarantined, NodeStatus::Active)
                | (NodeStatus::Quarantined, NodeStatus::Banned)
                | (NodeStatus::Banned, NodeStatus::Pending)
        )
    }

    /// Returns whether this status allows the node to be scheduled for workloads.
    ///
    /// **Only `Active` returns `true`.** All other statuses return `false`.
    ///
    /// This is a pure function with no external dependencies or configuration.
    /// The scheduling eligibility of a node is determined solely by its status.
    ///
    /// ## Returns
    ///
    /// `true` if and only if `self` is `NodeStatus::Active`.
    #[must_use]
    #[inline]
    pub const fn is_schedulable(&self) -> bool {
        matches!(self, NodeStatus::Active)
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// STATUS TRANSITION
// ════════════════════════════════════════════════════════════════════════════════

/// Record of a status transition event.
///
/// `StatusTransition` is a **data-only** struct that records a completed
/// status change. It contains no logic and performs no validation of the
/// transition rules — that responsibility belongs to `NodeStatus::can_transition_to`.
///
/// ## Fields
///
/// - `from`: The status before the transition.
/// - `to`: The status after the transition.
/// - `reason`: Human-readable explanation of why the transition occurred.
///   Must not be empty.
/// - `timestamp`: Unix timestamp (seconds) when the transition occurred.
///
/// ## Usage
///
/// ```rust,ignore
/// use dsdn_common::{NodeStatus, StatusTransition};
///
/// let transition = StatusTransition {
///     from: NodeStatus::Pending,
///     to: NodeStatus::Active,
///     reason: "all gating checks passed".to_string(),
///     timestamp: 1700000000,
/// };
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusTransition {
    /// The status before the transition.
    pub from: NodeStatus,
    /// The status after the transition.
    pub to: NodeStatus,
    /// Human-readable explanation for the transition. Must not be empty.
    pub reason: String,
    /// Unix timestamp (seconds) when the transition occurred.
    pub timestamp: u64,
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ──────────────────────────────────────────────────────────────────────
    // NodeStatus TRAIT TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_node_status_copy() {
        let status = NodeStatus::Active;
        let copy = status;
        assert_eq!(status, copy);
    }

    #[test]
    fn test_node_status_clone() {
        let status = NodeStatus::Quarantined;
        #[allow(clippy::clone_on_copy)]
        let cloned = status.clone();
        assert_eq!(status, cloned);
    }

    #[test]
    fn test_node_status_debug() {
        assert_eq!(format!("{:?}", NodeStatus::Pending), "Pending");
        assert_eq!(format!("{:?}", NodeStatus::Active), "Active");
        assert_eq!(format!("{:?}", NodeStatus::Quarantined), "Quarantined");
        assert_eq!(format!("{:?}", NodeStatus::Banned), "Banned");
    }

    #[test]
    fn test_node_status_eq() {
        assert_eq!(NodeStatus::Pending, NodeStatus::Pending);
        assert_eq!(NodeStatus::Active, NodeStatus::Active);
        assert_eq!(NodeStatus::Quarantined, NodeStatus::Quarantined);
        assert_eq!(NodeStatus::Banned, NodeStatus::Banned);
    }

    #[test]
    fn test_node_status_ne() {
        assert_ne!(NodeStatus::Pending, NodeStatus::Active);
        assert_ne!(NodeStatus::Active, NodeStatus::Quarantined);
        assert_ne!(NodeStatus::Quarantined, NodeStatus::Banned);
        assert_ne!(NodeStatus::Banned, NodeStatus::Pending);
    }

    #[test]
    fn test_node_status_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(NodeStatus::Pending);
        set.insert(NodeStatus::Active);
        set.insert(NodeStatus::Quarantined);
        set.insert(NodeStatus::Banned);
        set.insert(NodeStatus::Pending); // duplicate
        assert_eq!(set.len(), 4);
        assert!(set.contains(&NodeStatus::Pending));
        assert!(set.contains(&NodeStatus::Active));
        assert!(set.contains(&NodeStatus::Quarantined));
        assert!(set.contains(&NodeStatus::Banned));
    }

    #[test]
    fn test_node_status_serde_roundtrip() {
        for status in &[
            NodeStatus::Pending,
            NodeStatus::Active,
            NodeStatus::Quarantined,
            NodeStatus::Banned,
        ] {
            let json = serde_json::to_string(status).expect("serialize");
            let back: NodeStatus = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*status, back);
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // NodeStatus DISPLAY TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_display_pending() {
        assert_eq!(format!("{}", NodeStatus::Pending), "pending");
    }

    #[test]
    fn test_display_active() {
        assert_eq!(format!("{}", NodeStatus::Active), "active");
    }

    #[test]
    fn test_display_quarantined() {
        assert_eq!(format!("{}", NodeStatus::Quarantined), "quarantined");
    }

    #[test]
    fn test_display_banned() {
        assert_eq!(format!("{}", NodeStatus::Banned), "banned");
    }

    #[test]
    fn test_display_deterministic() {
        let status = NodeStatus::Active;
        let d1 = format!("{}", status);
        let d2 = format!("{}", status);
        assert_eq!(d1, d2);
    }

    // ──────────────────────────────────────────────────────────────────────
    // ALLOWED TRANSITIONS (7 total — exhaustive positive tests)
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_transition_pending_to_active() {
        assert!(NodeStatus::Pending.can_transition_to(NodeStatus::Active));
    }

    #[test]
    fn test_transition_pending_to_banned() {
        assert!(NodeStatus::Pending.can_transition_to(NodeStatus::Banned));
    }

    #[test]
    fn test_transition_active_to_quarantined() {
        assert!(NodeStatus::Active.can_transition_to(NodeStatus::Quarantined));
    }

    #[test]
    fn test_transition_active_to_banned() {
        assert!(NodeStatus::Active.can_transition_to(NodeStatus::Banned));
    }

    #[test]
    fn test_transition_quarantined_to_active() {
        assert!(NodeStatus::Quarantined.can_transition_to(NodeStatus::Active));
    }

    #[test]
    fn test_transition_quarantined_to_banned() {
        assert!(NodeStatus::Quarantined.can_transition_to(NodeStatus::Banned));
    }

    #[test]
    fn test_transition_banned_to_pending() {
        assert!(NodeStatus::Banned.can_transition_to(NodeStatus::Pending));
    }

    // ──────────────────────────────────────────────────────────────────────
    // FORBIDDEN TRANSITIONS — exhaustive negative tests
    // Every (from, to) pair NOT in the allowed set must return false.
    // Total pairs = 4×4 = 16; allowed = 7; forbidden = 9.
    // ──────────────────────────────────────────────────────────────────────

    // Self-transitions (4)

    #[test]
    fn test_forbidden_pending_to_pending() {
        assert!(!NodeStatus::Pending.can_transition_to(NodeStatus::Pending));
    }

    #[test]
    fn test_forbidden_active_to_active() {
        assert!(!NodeStatus::Active.can_transition_to(NodeStatus::Active));
    }

    #[test]
    fn test_forbidden_quarantined_to_quarantined() {
        assert!(!NodeStatus::Quarantined.can_transition_to(NodeStatus::Quarantined));
    }

    #[test]
    fn test_forbidden_banned_to_banned() {
        assert!(!NodeStatus::Banned.can_transition_to(NodeStatus::Banned));
    }

    // Other forbidden transitions (5)

    #[test]
    fn test_forbidden_pending_to_quarantined() {
        assert!(!NodeStatus::Pending.can_transition_to(NodeStatus::Quarantined));
    }

    #[test]
    fn test_forbidden_active_to_pending() {
        assert!(!NodeStatus::Active.can_transition_to(NodeStatus::Pending));
    }

    #[test]
    fn test_forbidden_quarantined_to_pending() {
        assert!(!NodeStatus::Quarantined.can_transition_to(NodeStatus::Pending));
    }

    #[test]
    fn test_forbidden_banned_to_active() {
        assert!(!NodeStatus::Banned.can_transition_to(NodeStatus::Active));
    }

    #[test]
    fn test_forbidden_banned_to_quarantined() {
        assert!(!NodeStatus::Banned.can_transition_to(NodeStatus::Quarantined));
    }

    // ──────────────────────────────────────────────────────────────────────
    // EXHAUSTIVE MATRIX TEST
    // Validates ALL 16 pairs in a single test for completeness assurance.
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_transition_matrix_exhaustive() {
        let all = [
            NodeStatus::Pending,
            NodeStatus::Active,
            NodeStatus::Quarantined,
            NodeStatus::Banned,
        ];

        // Expected: (from, to) → bool
        // Encoded as a 4×4 matrix, row = from, col = to
        // Order: Pending=0, Active=1, Quarantined=2, Banned=3
        let expected: [[bool; 4]; 4] = [
            // Pending →     [Pending, Active, Quarantined, Banned]
            [false, true, false, true],
            // Active →      [Pending, Active, Quarantined, Banned]
            [false, false, true, true],
            // Quarantined → [Pending, Active, Quarantined, Banned]
            [false, true, false, true],
            // Banned →      [Pending, Active, Quarantined, Banned]
            [true, false, false, false],
        ];

        for (i, from) in all.iter().enumerate() {
            for (j, to) in all.iter().enumerate() {
                let result = from.can_transition_to(*to);
                assert_eq!(
                    result, expected[i][j],
                    "transition {:?} → {:?}: expected {}, got {}",
                    from, to, expected[i][j], result
                );
            }
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // is_schedulable TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_schedulable_active_only() {
        assert!(NodeStatus::Active.is_schedulable());
    }

    #[test]
    fn test_not_schedulable_pending() {
        assert!(!NodeStatus::Pending.is_schedulable());
    }

    #[test]
    fn test_not_schedulable_quarantined() {
        assert!(!NodeStatus::Quarantined.is_schedulable());
    }

    #[test]
    fn test_not_schedulable_banned() {
        assert!(!NodeStatus::Banned.is_schedulable());
    }

    #[test]
    fn test_schedulable_exhaustive() {
        let all = [
            NodeStatus::Pending,
            NodeStatus::Active,
            NodeStatus::Quarantined,
            NodeStatus::Banned,
        ];
        for status in &all {
            let expected = matches!(status, NodeStatus::Active);
            assert_eq!(
                status.is_schedulable(),
                expected,
                "{:?}.is_schedulable() should be {}",
                status,
                expected
            );
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // StatusTransition TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_status_transition_fields() {
        let t = StatusTransition {
            from: NodeStatus::Pending,
            to: NodeStatus::Active,
            reason: "all gating checks passed".to_string(),
            timestamp: 1700000000,
        };
        assert_eq!(t.from, NodeStatus::Pending);
        assert_eq!(t.to, NodeStatus::Active);
        assert_eq!(t.reason, "all gating checks passed");
        assert_eq!(t.timestamp, 1700000000);
    }

    #[test]
    fn test_status_transition_clone() {
        let t = StatusTransition {
            from: NodeStatus::Active,
            to: NodeStatus::Quarantined,
            reason: "stake dropped below minimum".to_string(),
            timestamp: 1700001000,
        };
        let cloned = t.clone();
        assert_eq!(t, cloned);
    }

    #[test]
    fn test_status_transition_eq() {
        let t1 = StatusTransition {
            from: NodeStatus::Active,
            to: NodeStatus::Banned,
            reason: "severe slashing".to_string(),
            timestamp: 1700002000,
        };
        let t2 = StatusTransition {
            from: NodeStatus::Active,
            to: NodeStatus::Banned,
            reason: "severe slashing".to_string(),
            timestamp: 1700002000,
        };
        assert_eq!(t1, t2);
    }

    #[test]
    fn test_status_transition_ne_different_reason() {
        let t1 = StatusTransition {
            from: NodeStatus::Active,
            to: NodeStatus::Banned,
            reason: "reason A".to_string(),
            timestamp: 1700002000,
        };
        let t2 = StatusTransition {
            from: NodeStatus::Active,
            to: NodeStatus::Banned,
            reason: "reason B".to_string(),
            timestamp: 1700002000,
        };
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_status_transition_ne_different_timestamp() {
        let t1 = StatusTransition {
            from: NodeStatus::Active,
            to: NodeStatus::Banned,
            reason: "severe slashing".to_string(),
            timestamp: 1700002000,
        };
        let t2 = StatusTransition {
            from: NodeStatus::Active,
            to: NodeStatus::Banned,
            reason: "severe slashing".to_string(),
            timestamp: 9999999999,
        };
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_status_transition_debug() {
        let t = StatusTransition {
            from: NodeStatus::Banned,
            to: NodeStatus::Pending,
            reason: "cooldown expired".to_string(),
            timestamp: 1700003000,
        };
        let debug = format!("{:?}", t);
        assert!(debug.contains("Banned"));
        assert!(debug.contains("Pending"));
        assert!(debug.contains("cooldown expired"));
        assert!(debug.contains("1700003000"));
    }

    #[test]
    fn test_status_transition_serde_roundtrip() {
        let t = StatusTransition {
            from: NodeStatus::Quarantined,
            to: NodeStatus::Active,
            reason: "stake restored and re-check passed".to_string(),
            timestamp: 1700004000,
        };
        let json = serde_json::to_string(&t).expect("serialize");
        let back: StatusTransition = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(t, back);
    }

    #[test]
    fn test_status_transition_serde_preserves_all_fields() {
        let t = StatusTransition {
            from: NodeStatus::Pending,
            to: NodeStatus::Banned,
            reason: "identity spoofing detected".to_string(),
            timestamp: 1700005000,
        };
        let json = serde_json::to_string(&t).expect("serialize");
        let back: StatusTransition = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.from, NodeStatus::Pending);
        assert_eq!(back.to, NodeStatus::Banned);
        assert_eq!(back.reason, "identity spoofing detected");
        assert_eq!(back.timestamp, 1700005000);
    }

    // ──────────────────────────────────────────────────────────────────────
    // SEND + SYNC TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NodeStatus>();
        assert_send_sync::<StatusTransition>();
    }

    // ──────────────────────────────────────────────────────────────────────
    // DETERMINISM TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_can_transition_to_deterministic() {
        // Same inputs → same result, called multiple times
        let from = NodeStatus::Active;
        let to = NodeStatus::Quarantined;
        let r1 = from.can_transition_to(to);
        let r2 = from.can_transition_to(to);
        let r3 = from.can_transition_to(to);
        assert_eq!(r1, r2);
        assert_eq!(r2, r3);
    }

    #[test]
    fn test_is_schedulable_deterministic() {
        let status = NodeStatus::Active;
        let r1 = status.is_schedulable();
        let r2 = status.is_schedulable();
        assert_eq!(r1, r2);
    }
}