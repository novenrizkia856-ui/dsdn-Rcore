//! # Anti-Self-Dealing Pre-Check (CO.9)
//!
//! Coordinator-level pre-check that detects potential self-dealing before
//! receipt signing. This is a **defense-in-depth** measure — the chain
//! remains the authoritative enforcer.
//!
//! ## Defense-in-Depth Architecture
//!
//! ```text
//! Layer 1 (this module):  Coordinator pre-check (early warning, monitoring)
//!                         ↓ flags suspicious receipts but NEVER blocks signing
//!
//! Layer 2 (chain):        Authoritative enforcement during ClaimReward
//!                         ↓ rejects self-dealing transactions with on-chain proof
//! ```
//!
//! ## What This Module Does
//!
//! - Checks if the submitter address matches the node owner address.
//! - Returns `PreCheckResult::SuspectedSelfDealing` if they match.
//! - Returns `PreCheckResult::Clean` if they don't match or if data is missing.
//!
//! ## What This Module Does NOT Do
//!
//! - Does NOT block, reject, or prevent receipt signing.
//! - Does NOT modify any state (coordinator, signing, receipt).
//! - Does NOT replace chain-level enforcement.
//! - Does NOT throw errors or panic.
//!
//! The result is purely informational — intended for monitoring, alerting,
//! and observability dashboards. A `SuspectedSelfDealing` result means
//! "the coordinator noticed something suspicious" but signing proceeds
//! normally regardless.
//!
//! ## Why Pre-Check at Coordinator Level
//!
//! Detecting self-dealing early (before DA publication) enables:
//!
//! 1. **Monitoring**: Operators can track suspicious patterns in real time.
//! 2. **Metrics**: Count suspected self-dealing attempts per epoch.
//! 3. **Alerting**: Trigger alerts before the chain has to reject on-chain.
//! 4. **Forensics**: Log suspicious receipts for post-hoc analysis.
//!
//! The chain still performs the definitive check because:
//!
//! - The coordinator may have stale or incomplete owner data.
//! - The coordinator check is based on a hint, not a cryptographic proof.
//! - Only the chain has the canonical, finalized node registry.
//!
//! ## False Positives
//!
//! A false positive (Clean when actually self-dealing) is acceptable
//! because the chain catches it. A false negative (SuspectedSelfDealing
//! when not self-dealing) is also acceptable because the pre-check
//! **never blocks signing**. Both are safe.
//!
//! ## Determinism
//!
//! Same inputs → same output. No randomness, no system time, no side effects.
//!
//! ## Safety
//!
//! - No panic, unwrap, expect, todo, unreachable.
//! - No mutation of any state.
//! - No side effects.
//! - Pure function.

use std::fmt;

// ════════════════════════════════════════════════════════════════════════════════
// TYPES
// ════════════════════════════════════════════════════════════════════════════════

/// Node identifier (Ed25519 public key, 32 bytes).
///
/// Matches the `node_id` field in `UsageProof` and `ReceiptV1Proto`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    /// Creates a new `NodeId` from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Address (20 bytes, Ethereum-style).
///
/// Matches the `submitter_address` field in `ReceiptV1Proto`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address(pub [u8; 20]);

impl Address {
    /// Creates a new `Address` from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// NODE OWNER LOOKUP TRAIT
// ════════════════════════════════════════════════════════════════════════════════

/// Trait for looking up node owner addresses.
///
/// Abstracts the node registry lookup so the pre-check is decoupled from
/// any specific coordinator state implementation. The concrete implementation
/// may query an in-memory registry, a database, or a cache.
///
/// ## Why a Trait
///
/// - **Decoupling**: No dependency on a specific `CoordinatorState` struct.
/// - **Testability**: Mock implementations for unit tests.
/// - **Evolution**: Registry implementation can change without touching pre-check.
///
/// ## Contract
///
/// - `lookup_node_owner` MUST be a pure read operation (no mutation).
/// - `lookup_node_owner` MUST NOT panic.
/// - Returns `None` if the node is not registered or has no owner.
pub trait NodeOwnerLookup {
    /// Looks up the owner address of a node.
    ///
    /// Returns `Some(address)` if the node has a registered owner.
    /// Returns `None` if the node is unknown or has no owner on record.
    fn lookup_node_owner(&self, node_id: &NodeId) -> Option<Address>;
}

// ════════════════════════════════════════════════════════════════════════════════
// PRE-CHECK RESULT
// ════════════════════════════════════════════════════════════════════════════════

/// Result of the anti-self-dealing pre-check.
///
/// This is purely informational. It NEVER blocks signing or any other
/// coordinator operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreCheckResult {
    /// No self-dealing detected (or insufficient data to determine).
    Clean,

    /// Submitter address matches node owner address.
    /// The node appears to be claiming rewards for its own work and
    /// submitting the claim itself — a potential self-dealing pattern.
    ///
    /// **This does NOT block signing.** It is an advisory flag for
    /// monitoring and alerting only. The chain performs the
    /// authoritative enforcement.
    SuspectedSelfDealing,
}

impl PreCheckResult {
    /// Returns `true` if the result indicates suspected self-dealing.
    #[must_use]
    pub const fn is_suspected(&self) -> bool {
        matches!(self, PreCheckResult::SuspectedSelfDealing)
    }

    /// Returns `true` if the result indicates no self-dealing detected.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        matches!(self, PreCheckResult::Clean)
    }
}

impl fmt::Display for PreCheckResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PreCheckResult::Clean => write!(f, "Clean"),
            PreCheckResult::SuspectedSelfDealing => {
                write!(f, "SuspectedSelfDealing")
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// PRE-CHECK FUNCTION
// ════════════════════════════════════════════════════════════════════════════════

/// Performs an anti-self-dealing pre-check.
///
/// ## Logic
///
/// 1. If `submitter_hint` is `None` → return `Clean` (no data to check).
/// 2. Look up the node owner via `registry.lookup_node_owner(node_id)`.
/// 3. If owner is found AND owner == submitter → return `SuspectedSelfDealing`.
/// 4. Otherwise → return `Clean`.
///
/// ## Arguments
///
/// * `node_id` — The node that performed the work.
/// * `submitter_hint` — Optional hint of who will submit the `ClaimReward` tx.
///   May be `None` if not yet known at pre-check time.
/// * `registry` — Node owner lookup implementation.
///
/// ## Returns
///
/// * `PreCheckResult::Clean` — No self-dealing detected.
/// * `PreCheckResult::SuspectedSelfDealing` — Submitter matches node owner.
///
/// ## Invariants
///
/// - **No mutation**: `registry` is `&dyn` (immutable).
/// - **No blocking**: Returns immediately, no async, no I/O.
/// - **No side effects**: Pure function.
/// - **No signing impact**: Result is advisory only.
/// - **Deterministic**: Same inputs → same output.
#[must_use]
pub fn precheck_self_dealing(
    node_id: &NodeId,
    submitter_hint: Option<&Address>,
    registry: &dyn NodeOwnerLookup,
) -> PreCheckResult {
    // Step 1: No submitter hint → nothing to check.
    let submitter = match submitter_hint {
        Some(addr) => addr,
        None => return PreCheckResult::Clean,
    };

    // Step 2: Look up node owner.
    let owner = match registry.lookup_node_owner(node_id) {
        Some(addr) => addr,
        None => return PreCheckResult::Clean,
    };

    // Step 3: Compare.
    if owner == *submitter {
        PreCheckResult::SuspectedSelfDealing
    } else {
        PreCheckResult::Clean
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // ── Mock Registry ───────────────────────────────────────────────────

    /// In-memory mock for testing.
    struct MockRegistry {
        owners: HashMap<NodeId, Address>,
    }

    impl MockRegistry {
        fn new() -> Self {
            Self {
                owners: HashMap::new(),
            }
        }

        fn register(&mut self, node_id: NodeId, owner: Address) {
            self.owners.insert(node_id, owner);
        }
    }

    impl NodeOwnerLookup for MockRegistry {
        fn lookup_node_owner(&self, node_id: &NodeId) -> Option<Address> {
            self.owners.get(node_id).copied()
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    fn node(seed: u8) -> NodeId {
        NodeId::new([seed; 32])
    }

    fn addr(seed: u8) -> Address {
        Address::new([seed; 20])
    }

    // ── precheck_self_dealing ────────────────────────────────────────────

    #[test]
    fn submitter_none_returns_clean() {
        let registry = MockRegistry::new();
        let result = precheck_self_dealing(&node(0x01), None, &registry);
        assert_eq!(result, PreCheckResult::Clean);
    }

    #[test]
    fn node_not_registered_returns_clean() {
        let registry = MockRegistry::new(); // Empty registry.
        let submitter = addr(0x0A);
        let result = precheck_self_dealing(&node(0x01), Some(&submitter), &registry);
        assert_eq!(result, PreCheckResult::Clean);
    }

    #[test]
    fn owner_matches_submitter_returns_suspected() {
        let mut registry = MockRegistry::new();
        let owner_addr = addr(0x0A);
        registry.register(node(0x01), owner_addr);

        let result = precheck_self_dealing(&node(0x01), Some(&owner_addr), &registry);
        assert_eq!(result, PreCheckResult::SuspectedSelfDealing);
    }

    #[test]
    fn owner_differs_from_submitter_returns_clean() {
        let mut registry = MockRegistry::new();
        registry.register(node(0x01), addr(0x0A));

        let submitter = addr(0x0B); // Different from owner.
        let result = precheck_self_dealing(&node(0x01), Some(&submitter), &registry);
        assert_eq!(result, PreCheckResult::Clean);
    }

    #[test]
    fn different_node_same_submitter_returns_clean() {
        let mut registry = MockRegistry::new();
        registry.register(node(0x01), addr(0x0A));

        // Node 0x02 is not registered → Clean.
        let result = precheck_self_dealing(&node(0x02), Some(&addr(0x0A)), &registry);
        assert_eq!(result, PreCheckResult::Clean);
    }

    #[test]
    fn multiple_nodes_different_owners() {
        let mut registry = MockRegistry::new();
        registry.register(node(0x01), addr(0x0A));
        registry.register(node(0x02), addr(0x0B));

        // Node 0x01 owner is 0x0A, submitter is 0x0A → suspected.
        assert_eq!(
            precheck_self_dealing(&node(0x01), Some(&addr(0x0A)), &registry),
            PreCheckResult::SuspectedSelfDealing,
        );

        // Node 0x02 owner is 0x0B, submitter is 0x0A → clean.
        assert_eq!(
            precheck_self_dealing(&node(0x02), Some(&addr(0x0A)), &registry),
            PreCheckResult::Clean,
        );
    }

    // ── Determinism ─────────────────────────────────────────────────────

    #[test]
    fn deterministic_100_iterations() {
        let mut registry = MockRegistry::new();
        registry.register(node(0x01), addr(0x0A));
        let submitter = addr(0x0A);

        for _ in 0..100 {
            assert_eq!(
                precheck_self_dealing(&node(0x01), Some(&submitter), &registry),
                PreCheckResult::SuspectedSelfDealing,
            );
        }
    }

    // ── PreCheckResult methods ──────────────────────────────────────────

    #[test]
    fn is_suspected_and_is_clean() {
        assert!(PreCheckResult::SuspectedSelfDealing.is_suspected());
        assert!(!PreCheckResult::SuspectedSelfDealing.is_clean());
        assert!(PreCheckResult::Clean.is_clean());
        assert!(!PreCheckResult::Clean.is_suspected());
    }

    #[test]
    fn display_impl() {
        assert_eq!(format!("{}", PreCheckResult::Clean), "Clean");
        assert_eq!(
            format!("{}", PreCheckResult::SuspectedSelfDealing),
            "SuspectedSelfDealing"
        );
    }

    // ── NodeId / Address ────────────────────────────────────────────────

    #[test]
    fn node_id_roundtrip() {
        let n = NodeId::new([0x42; 32]);
        assert_eq!(*n.as_bytes(), [0x42; 32]);
    }

    #[test]
    fn address_roundtrip() {
        let a = Address::new([0x42; 20]);
        assert_eq!(*a.as_bytes(), [0x42; 20]);
    }

    #[test]
    fn node_id_equality() {
        assert_eq!(node(0x01), node(0x01));
        assert_ne!(node(0x01), node(0x02));
    }

    #[test]
    fn address_equality() {
        assert_eq!(addr(0x01), addr(0x01));
        assert_ne!(addr(0x01), addr(0x02));
    }

    #[test]
    fn node_id_debug() {
        let n = node(0x01);
        let dbg = format!("{:?}", n);
        assert!(dbg.contains("NodeId"));
    }

    #[test]
    fn address_debug() {
        let a = addr(0x01);
        let dbg = format!("{:?}", a);
        assert!(dbg.contains("Address"));
    }

    // ── Trait object safety ─────────────────────────────────────────────

    #[test]
    fn trait_object_works() {
        let registry = MockRegistry::new();
        let lookup: &dyn NodeOwnerLookup = &registry;
        let result = precheck_self_dealing(&node(0x01), None, lookup);
        assert_eq!(result, PreCheckResult::Clean);
    }
}