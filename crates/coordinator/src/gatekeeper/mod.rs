//! # GateKeeper Module (14B.31)
//!
//! Provides the [`GateKeeper`] struct and [`GateKeeperConfig`] for service
//! node admission gating within the coordinator crate.
//!
//! ## Scope — Setup Only
//!
//! This module defines the foundational types and construction logic.
//! It does **not** contain enforcement logic, RPC calls, scheduler hooks,
//! background tasks, or any side effects. Those will be added in subsequent
//! stages (14B.32+).
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
    /// Used by future enforcement logic (14B.32+). Default: 60.
    pub check_interval_secs: u64,

    /// Global toggle for gating enforcement. When `false`, the GateKeeper
    /// is constructed but performs no admission checks. Default: `true`.
    pub enable_gating: bool,
}

impl Default for GateKeeperConfig {
    fn default() -> Self {
        Self {
            policy: GatingPolicy::default(),
            chain_rpc_endpoint: String::new(),
            check_interval_secs: 60,
            enable_gating: true,
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
/// placeholder. Actual evaluations (added in 14B.32+) must supply the
/// current timestamp at call time.
///
/// ## Registry
///
/// The `registry` field is an in-memory cache of node records. It starts
/// empty and will be populated by future admission and sync logic.
/// Keys are node ID strings matching [`NodeRegistryEntry::identity::node_id`]
/// hex representation.
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
    /// This is intentional — no evaluations are performed at construction
    /// time. Future evaluation methods (14B.32+) will supply the actual
    /// current timestamp when invoking the engine.
    pub fn new(config: GateKeeperConfig) -> Self {
        let gating_engine = GatingEngine::new(config.policy.clone(), 0);
        Self {
            config,
            registry: HashMap::new(),
            gating_engine,
        }
    }
}