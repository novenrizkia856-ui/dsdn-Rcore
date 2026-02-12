//! # GateKeeper Module (14B.31–36)
//!
//! Provides the [`GateKeeper`] struct, [`GateKeeperConfig`], node
//! admission filtering, stake validation hooks, identity validation
//! hooks, and quarantine management for service node gating within
//! the coordinator crate.
//!
//! ## Modules
//!
//! - **admission** (14B.32): [`AdmissionRequest`], [`AdmissionResponse`],
//!   and [`GateKeeper::process_admission`] for evaluating node join requests.
//! - **stake_check** (14B.33): [`StakeCheckHook`] for pure stake validation
//!   before scheduling and admission operations.
//! - **identity_check** (14B.34): [`IdentityCheckHook`] for identity proof
//!   verification, TLS matching, and node ID spoof detection.
//! - **quarantine** (14B.36): [`QuarantineManager`] and [`QuarantineRecord`]
//!   for tracking quarantined nodes and escalation checks.
//!
//! ## Scope
//!
//! This module provides foundational types, construction logic, admission
//! filtering, stake validation hooks, identity validation hooks, and
//! quarantine management. It does **not** contain periodic re-checks,
//! RPC calls, or background tasks. Those will be added in subsequent
//! stages (14B.37+).
//!
//! ## Relationship with Validator Gating Engine
//!
//! [`GateKeeper`] holds a [`GatingEngine`] instance from the `dsdn_validator`
//! crate. The engine is a stateless, deterministic evaluator that checks
//! stake, identity, TLS, cooldown, and class requirements for service nodes.
//! The GateKeeper provides the coordinator-side wrapper that maintains a
//! local registry cache and configuration for driving evaluations.
//!
//! ## Relationship with Chain RPC
//!
//! [`GateKeeperConfig::chain_rpc_endpoint`] stores the endpoint URL for
//! querying on-chain state (stake balances, slashing records, node status).
//! No RPC connections are established at construction time — the endpoint
//! is stored for use by future enforcement logic.
//!
//! ## Safety Properties
//!
//! - All types are `Send + Sync` (no interior mutability, no `Rc`, no raw pointers).
//! - Construction is deterministic and side-effect free.
//! - No `panic!`, `unwrap()`, `expect()`, or silent failure paths.

use std::collections::HashMap;

use dsdn_common::gating::{GatingPolicy, NodeRegistryEntry};
use dsdn_validator::gating::GatingEngine;

// Admission filter (14B.32)
pub mod admission;
pub use admission::{AdmissionRequest, AdmissionResponse};

// Stake check hook (14B.33)
pub mod stake_check;
pub use stake_check::StakeCheckHook;

// Identity check hook (14B.34)
pub mod identity_check;
pub use identity_check::IdentityCheckHook;

// Quarantine manager (14B.36)
pub mod quarantine;
pub use quarantine::{QuarantineManager, QuarantineRecord};

// ════════════════════════════════════════════════════════════════════════════════
// CONFIGURATION
// ════════════════════════════════════════════════════════════════════════════════

/// Configuration for the [`GateKeeper`].
///
/// Controls gating policy, chain RPC connectivity, periodic check interval,
/// and the global enable/disable toggle.
///
/// ## Defaults
///
/// | Field | Default Value |
/// |-------|---------------|
/// | `policy` | `GatingPolicy::default()` (full security) |
/// | `chain_rpc_endpoint` | `""` (empty — must be configured before use) |
/// | `check_interval_secs` | `60` |
/// | `enable_gating` | `true` |
/// | `auto_activate_on_pass` | `false` |
#[derive(Clone, Debug)]
pub struct GateKeeperConfig {
    /// The gating policy that defines stake requirements, security checks,
    /// and scheduling permissions. Passed to the [`GatingEngine`] for
    /// evaluation decisions.
    pub policy: GatingPolicy,

    /// Chain RPC endpoint URL for querying on-chain state (stake, slashing,
    /// node records). No connection is established at construction time.
    pub chain_rpc_endpoint: String,

    /// Interval in seconds between periodic re-checks of registered nodes.
    /// Used by future enforcement logic (14B.37+). Default: 60.
    pub check_interval_secs: u64,

    /// Global toggle for gating enforcement. When `false`, the GateKeeper
    /// is constructed but performs no admission checks. Default: `true`.
    pub enable_gating: bool,

    /// When `true`, nodes that pass admission are assigned `NodeStatus::Active`
    /// immediately instead of `NodeStatus::Pending`. Default: `false`.
    ///
    /// Corresponds to `AdmissionPolicy::auto_activate_on_pass` from
    /// the validator crate's admission module.
    pub auto_activate_on_pass: bool,
}

impl Default for GateKeeperConfig {
    fn default() -> Self {
        Self {
            policy: GatingPolicy::default(),
            chain_rpc_endpoint: String::new(),
            check_interval_secs: 60,
            enable_gating: true,
            auto_activate_on_pass: false,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// GATEKEEPER
// ════════════════════════════════════════════════════════════════════════════════

/// Coordinator-side gatekeeper for service node admission control.
///
/// Wraps a [`GatingEngine`] from the `dsdn_validator` crate and maintains
/// a local cache of [`NodeRegistryEntry`] records keyed by node ID.
///
/// ## Construction
///
/// [`GateKeeper::new`] performs deterministic, side-effect-free initialization.
/// The internal [`GatingEngine`] is constructed with timestamp `0` as a
/// placeholder. [`process_admission`](GateKeeper::process_admission) rebuilds
/// the engine with the caller-provided timestamp before each evaluation.
///
/// ## Admission (14B.32)
///
/// [`GateKeeper::process_admission`] runs the full gating evaluation pipeline
/// and returns an [`AdmissionResponse`] with the decision, assigned status,
/// and audit report. Approved nodes are inserted into the local registry.
///
/// ## Registry
///
/// The `registry` field is an in-memory cache of node records. Keys are
/// lowercase hex strings of the 32-byte `identity.node_id` (64 characters).
#[derive(Debug)]
pub struct GateKeeper {
    /// Configuration for this GateKeeper instance.
    pub config: GateKeeperConfig,

    /// Local cache of node registry entries, keyed by node ID (hex string).
    /// Starts empty; populated by future admission logic (14B.32+).
    pub registry: HashMap<String, NodeRegistryEntry>,

    /// The gating engine from `dsdn_validator` that performs stateless,
    /// deterministic evaluation of service node eligibility.
    pub gating_engine: GatingEngine,
}

impl GateKeeper {
    /// Creates a new [`GateKeeper`] with the given configuration.
    ///
    /// ## Guarantees
    ///
    /// - Deterministic: same config produces identical GateKeeper state.
    /// - No side effects: no RPC calls, no thread spawns, no I/O.
    /// - No system clock access: engine timestamp is set to `0`.
    /// - No panic paths: all construction is infallible.
    ///
    /// ## Engine Timestamp
    ///
    /// The internal [`GatingEngine`] is initialized with timestamp `0`.
    /// [`process_admission`](GateKeeper::process_admission) rebuilds the
    /// engine with the caller-provided `current_timestamp` before each
    /// evaluation, ensuring time-sensitive checks use the correct time.
    pub fn new(config: GateKeeperConfig) -> Self {
        let gating_engine = GatingEngine::new(config.policy.clone(), 0);
        Self {
            config,
            registry: HashMap::new(),
            gating_engine,
        }
    }
}