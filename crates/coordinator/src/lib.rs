//! # DSDN Coordinator Crate (14A)
//!
//! The Coordinator is the central orchestration component of DSDN (Decentralized
//! Storage and Data Network). It manages node registry, placement decisions,
//! workload scheduling, and DA layer integration with fallback support.
//!
//! ## Architecture Overview
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                           COORDINATOR                                   │
//! │                                                                         │
//! │  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐     │
//! │  │   DAConsumer    │───▶│  StateMachine   │───▶│ DADerivedState  │     │
//! │  │ (Event Ingest)  │    │ (Event Apply)   │    │ (Authoritative) │     │
//! │  └────────┬────────┘    └─────────────────┘    └────────┬────────┘     │
//! │           │                                              │              │
//! │           │ subscribe                          read-only │              │
//! │           │                                              ▼              │
//! │  ┌────────┴────────┐                          ┌─────────────────┐      │
//! │  │    DALayer      │◀─────────────────────────│   Scheduler     │      │
//! │  │  (Celestia)     │         publish          │   Placement     │      │
//! │  └────────┬────────┘                          └─────────────────┘      │
//! │           │                                              ▲              │
//! │           │                                              │              │
//! │  ┌────────┴────────┐    ┌─────────────────┐             │              │
//! │  │ EventPublisher  │───▶│  StateRebuilder │─────────────┘              │
//! │  │ (Event Write)   │    │   (Recovery)    │     rebuild                │
//! │  └─────────────────┘    └─────────────────┘                            │
//! │                                                                         │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## DA Fallback Architecture (14A.1A.35-39)
//!
//! The coordinator implements a multi-layer DA fallback system to ensure high
//! availability when primary Celestia DA is unavailable.
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────────────┐
//! │                         DA ROUTING SUBSYSTEM                             │
//! │                                                                          │
//! │  ┌────────────────────────────────────────────────────────────────────┐ │
//! │  │                          DARouter                                  │ │
//! │  │  (Single entry point for ALL DA operations)                       │ │
//! │  │                                                                    │ │
//! │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐               │ │
//! │  │  │   Primary   │  │  Secondary  │  │  Emergency  │               │ │
//! │  │  │  (Celestia) │  │  (QuorumDA) │  │    (Mock)   │               │ │
//! │  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘               │ │
//! │  │         │                │                │                       │ │
//! │  │         └────────────────┴────────────────┘                       │ │
//! │  │                          │                                        │ │
//! │  │                    route by health                                │ │
//! │  └──────────────────────────┼────────────────────────────────────────┘ │
//! │                             │                                          │
//! │                             ▼                                          │
//! │  ┌────────────────────────────────────────────────────────────────────┐ │
//! │  │                     DAHealthMonitor                                │ │
//! │  │  - Periodic health checks (configurable interval)                 │ │
//! │  │  - Tracks: primary_healthy, secondary_healthy, emergency_healthy  │ │
//! │  │  - Detects failover (consecutive failures >= threshold)           │ │
//! │  │  - Detects recovery (consecutive successes >= threshold)          │ │
//! │  │  - Triggers auto-reconciliation on recovery (14A.1A.39)           │ │
//! │  └──────────────────────────┼────────────────────────────────────────┘ │
//! │                             │                                          │
//! │                             │ on recovery transition                   │
//! │                             ▼                                          │
//! │  ┌────────────────────────────────────────────────────────────────────┐ │
//! │  │                   ReconciliationEngine                             │ │
//! │  │  - Tracks pending blobs stored in fallback DA                     │ │
//! │  │  - Batch reconcile to Celestia when primary recovers              │ │
//! │  │  - Configurable: batch_size, max_retries, parallel_reconcile      │ │
//! │  │  - Verifies state consistency between DA layers                   │ │
//! │  └────────────────────────────────────────────────────────────────────┘ │
//! │                                                                          │
//! └──────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ### Component Relationships
//!
//! **DARouter** (defined in `main.rs`):
//! - Single entry point for ALL DA operations (`post_blob`, `get_blob`)
//! - Routes requests to primary, secondary, or emergency DA based on health
//! - Tracks routing metrics (request counts, failover counts, recovery counts)
//! - Holds references to all DA layers and health monitor
//!
//! **DAHealthMonitor** (defined in `main.rs`):
//! - Runs periodic health checks on all DA layers
//! - Tracks consecutive failures/successes for each DA
//! - Determines failover: `primary_failures >= failure_threshold`
//! - Determines recovery: `primary_successes >= recovery_threshold` while primary healthy
//! - Triggers automatic reconciliation on recovery transition (14A.1A.39)
//! - Holds reference to [`ReconciliationEngine`] for auto-recovery
//!
//! **ReconciliationEngine** (defined in `reconciliation` module):
//! - Tracks blobs written to fallback DA that need reconciliation to Celestia
//! - Provides batch reconciliation with configurable `batch_size`
//! - Supports retry logic with `max_retries` and `retry_delay_ms`
//! - Optional parallel reconciliation via `parallel_reconcile` config
//! - Verifies state consistency between primary and fallback DA
//!
//! ## DA Status Flow
//!
//! ```text
//! ┌───────────────────────────────────────────────────────────────────────────┐
//! │                         DA STATUS TRANSITIONS                             │
//! │                                                                           │
//! │   ┌─────────┐                                                             │
//! │   │ Healthy │◀──────────────────────────────────────────────────┐        │
//! │   │(Primary)│                                                    │        │
//! │   └────┬────┘                                                    │        │
//! │        │ health check fails                                      │        │
//! │        ▼                                                         │        │
//! │   ┌─────────┐                                                    │        │
//! │   │ Warning │ (primary_failures < failure_threshold)             │        │
//! │   └────┬────┘                                                    │        │
//! │        │ consecutive failures >= threshold                       │        │
//! │        ▼                                                         │        │
//! │   ┌─────────┐                                                    │        │
//! │   │Degraded │ (using secondary/QuorumDA)                         │        │
//! │   │(Fallback)│                                                   │        │
//! │   └────┬────┘                                                    │        │
//! │        │ secondary also fails                                    │        │
//! │        ▼                                                    Reconcile     │
//! │   ┌─────────┐                                               completes     │
//! │   │Emergency│ (using emergency DA)                               │        │
//! │   └────┬────┘                                                    │        │
//! │        │ primary health checks start succeeding                  │        │
//! │        ▼                                                         │        │
//! │   ┌──────────┐                                                   │        │
//! │   │Recovering│ (primary healthy, reconciling pending blobs)──────┘        │
//! │   └──────────┘                                                            │
//! │                                                                           │
//! │   IMPORTANT: Transition to Healthy ONLY after reconciliation succeeds.   │
//! │   If reconciliation fails, status remains NOT Healthy.                    │
//! └───────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Reconciliation Process
//!
//! Reconciliation ensures data written to fallback DA during outages is
//! eventually persisted to Celestia (primary DA).
//!
//! ### When Reconciliation Runs
//!
//! **Automatic (14A.1A.39)**:
//! - Triggered when DAHealthMonitor detects recovery transition
//! - Trigger conditions (ALL must be true):
//!   - `was_on_fallback = true` (previously using fallback)
//!   - `primary_healthy = true` (primary DA now responds)
//!   - `should_recover() = true` (recovery threshold met)
//!   - `is_recovery_in_progress() = false` (not already reconciling)
//! - Spawned as background task (non-blocking to health monitor loop)
//! - Controlled by `auto_reconcile_on_recovery` config (default: `true`)
//!
//! **Manual**:
//! - `POST /fallback/reconcile` HTTP endpoint
//! - Can be triggered independently of recovery state
//! - Requires primary DA to be healthy
//!
//! ### Reconciliation Steps
//!
//! 1. **Pending Blob Tracking**: When blob is written to fallback DA,
//!    it is added to pending queue with `blob_id`, `source_da`, `target_da`, `data`
//!
//! 2. **Batch Processing**: Engine processes up to `batch_size` blobs per run
//!
//! 3. **Per-Blob Processing**:
//!    - Post blob data to primary DA via DARouter
//!    - On success: remove from pending queue
//!    - On failure: increment `retry_count`, re-queue if under `max_retries`
//!
//! 4. **Report Generation**: Returns [`ReconcileReport`] with:
//!    - `blobs_processed`, `blobs_reconciled`, `blobs_failed`
//!    - `duration_ms`, `errors` list
//!    - `success = true` only if `blobs_failed == 0`
//!
//! ### Consistency Verification
//!
//! [`ReconciliationEngine::verify_state_consistency`] checks:
//! - Blobs with high retry counts (potential persistent issues)
//! - Stale blobs (in pending queue too long)
//! - Returns [`ConsistencyReport`] with `is_consistent`, `details`
//!
//! ## Configuration Options
//!
//! ### DARouter Configuration (`DARouterConfig` in `main.rs`)
//!
//! | Option | Type | Default | Description |
//! |--------|------|---------|-------------|
//! | `health_check_interval_ms` | `u64` | `5000` | Interval between health checks |
//! | `failure_threshold` | `u32` | `3` | Consecutive failures before failover |
//! | `recovery_threshold` | `u32` | `2` | Consecutive successes before recovery |
//! | `auto_reconcile_on_recovery` | `bool` | `true` | Auto-trigger reconcile on recovery |
//!
//! ### Reconciliation Configuration ([`ReconciliationConfig`])
//!
//! | Option | Type | Default | Description |
//! |--------|------|---------|-------------|
//! | `batch_size` | `usize` | `10` | Blobs per reconciliation batch |
//! | `retry_delay_ms` | `u64` | `1000` | Delay between retries |
//! | `max_retries` | `u32` | `3` | Max retry attempts per blob |
//! | `parallel_reconcile` | `bool` | `false` | Enable parallel processing |
//!
//! ### Coordinator Configuration (`CoordinatorConfig` in `main.rs`)
//!
//! | Option | Type | Default | Description |
//! |--------|------|---------|-------------|
//! | `enable_fallback` | `bool` | `false` | Enable DA fallback system |
//! | `fallback_da_type` | enum | `None` | `none`, `quorum`, or `emergency` |
//!
//! ## HTTP API Endpoints (14A.1A.38)
//!
//! | Endpoint | Method | Description |
//! |----------|--------|-------------|
//! | `/fallback/status` | GET | Current DA status, fallback state, pending count |
//! | `/fallback/pending` | GET | List of pending blobs awaiting reconciliation |
//! | `/fallback/reconcile` | POST | Trigger manual reconciliation |
//! | `/fallback/consistency` | GET | Verify state consistency |
//!
//! ## Multi-Coordinator Consensus Architecture (14A.2B.2.11–20)
//!
//! The coordinator supports a multi-coordinator consensus mode where multiple
//! coordinator instances run in parallel to eliminate single points of failure.
//! Receipt signing uses threshold cryptography (t-of-n) so that no single
//! coordinator can unilaterally produce valid receipts.
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────────────┐
//! │                     MULTI-COORDINATOR CONSENSUS                          │
//! │                                                                          │
//! │  ┌────────────────────────────────────────────────────────────────────┐ │
//! │  │                      MultiCoordinator                              │ │
//! │  │           (Single entry point — 14A.2B.2.20)                      │ │
//! │  │                                                                    │ │
//! │  │  ┌──────────┐  ┌───────────────┐  ┌─────────────────────────┐    │ │
//! │  │  │    id    │  │  key_share    │  │      committee          │    │ │
//! │  │  │ (immut.) │  │  (threshold)  │  │  (immut. per epoch)     │    │ │
//! │  │  └──────────┘  └───────────────┘  └─────────────────────────┘    │ │
//! │  │                                                                    │ │
//! │  │  ┌──────────────────────┐  ┌────────────────────────────────┐    │ │
//! │  │  │     PeerManager     │  │   Arc<dyn CoordinatorNetwork>  │    │ │
//! │  │  │  (connection track) │  │    (send/recv messages)        │    │ │
//! │  │  └──────────────────────┘  └────────────────────────────────┘    │ │
//! │  │                                                                    │ │
//! │  │  ┌──────────────────────────────────────────────────────────┐    │ │
//! │  │  │              MultiCoordinatorState                       │    │ │
//! │  │  │  ┌──────────────────┐  ┌───────────────────────────┐   │    │ │
//! │  │  │  │ pending_receipts │  │   signing_sessions        │   │    │ │
//! │  │  │  │ HashMap<WID,     │  │   HashMap<SID,            │   │    │ │
//! │  │  │  │  ReceiptConsensus│  │    SigningSession>         │   │    │ │
//! │  │  │  └──────────────────┘  └───────────────────────────┘   │    │ │
//! │  │  └──────────────────────────────────────────────────────────┘    │ │
//! │  └────────────────────────────────────────────────────────────────────┘ │
//! │                                                                          │
//! │  Message Flow:                                                           │
//! │                                                                          │
//! │  propose_receipt(data)                                                   │
//! │    ├─ validate → create ReceiptConsensus → auto-vote → broadcast        │
//! │    └─ returns WorkloadId                                                │
//! │                                                                          │
//! │  handle_message(from, msg)                                              │
//! │    ├─ Ping/Pong       → peer tracking + direct reply                    │
//! │    ├─ ProposeReceipt  → create consensus + auto-vote                    │
//! │    ├─ VoteReceipt     → add_vote → if threshold: initiate signing      │
//! │    ├─ SigningCommit.  → collect commitments → if quorum: partials       │
//! │    ├─ PartialSig.    → collect partials → if quorum: aggregate         │
//! │    └─ EpochHandoff   → acknowledge                                     │
//! │                                                                          │
//! │  Consensus Lifecycle:                                                    │
//! │                                                                          │
//! │    Proposed → Voting → Signing → Completed                              │
//! │                  │                                                       │
//! │                  └── Rejected ──→ Failed                                │
//! │                                                                          │
//! │  Optimistic Path (optional):                                            │
//! │                                                                          │
//! │    OptimisticReceipt (single-sig, fast) → upgrade to ThresholdReceipt   │
//! │                                                                          │
//! └──────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ### Multi-Coordinator Components
//!
//! | Component | Module | Description |
//! |-----------|--------|-------------|
//! | `CoordinatorId`, `KeyShare`, `SessionId`, `WorkloadId`, `Vote` | `types` (14A.2B.2.11) | Identity and base types |
//! | `PeerManager`, `PeerConnection`, `PeerConfig` | `peer` (14A.2B.2.12) | Connection tracking |
//! | `CoordinatorMessage`, `MessageVote` | `message` (14A.2B.2.13) | Wire protocol messages |
//! | `CoordinatorNetwork`, `MockNetwork` | `network` (14A.2B.2.14) | Async send/recv trait |
//! | `ReceiptConsensus`, `ConsensusState` | `consensus` (14A.2B.2.15–16) | Per-receipt state machine |
//! | `MultiCoordinatorState`, handler functions | `handlers` (14A.2B.2.17) | Message → state mutation |
//! | `SigningSession`, `SigningState` | `signing` (14A.2B.2.18) | Threshold signing protocol |
//! | `OptimisticReceipt` | `optimistic` (14A.2B.2.19) | Low-latency single-sig receipt |
//! | `MultiCoordinator`, `MultiCoordinatorConfig` | `coordinator` (14A.2B.2.20) | Main orchestrator struct |
//!
//! ### MultiCoordinator Configuration ([`multi::MultiCoordinatorConfig`])
//!
//! | Option | Type | Description |
//! |--------|------|-------------|
//! | `proposal_timeout_ms` | `u64` | Timeout for receipt proposal consensus (must be > 0) |
//! | `signing_timeout_ms` | `u64` | Timeout for threshold signing session (must be > 0) |
//! | `enable_optimistic` | `bool` | Enable optimistic (single-sig) receipts |
//! | `challenge_window_secs` | `u64` | Challenge window for optimistic receipts (> 0 if enabled) |
//!
//! ### Multi-Coordinator Invariants
//!
//! - **Deterministic**: Same messages in same order → same state on every node
//! - **Atomic updates**: One message → at most one consensus state transition
//! - **No partial state**: Construction validates all invariants; operations never leave half-done state
//! - **No panic**: Zero `panic!`, `unwrap()`, `expect()` in production paths
//! - **Committee immutability**: Committee is fixed for the entire epoch
//! - **Network tolerance**: Broadcast failure does not cancel local consensus
//!
//! ## GateKeeper System (14B)
//!
//! The coordinator includes a [`gatekeeper::GateKeeper`] module that enforces
//! service node admission gating. The GateKeeper wraps the [`GatingEngine`]
//! from the `dsdn_validator` crate and maintains a local cache of
//! [`NodeRegistryEntry`] records from `dsdn_common`.
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────────────┐
//! │                          GATEKEEPER (14B)                                │
//! │                                                                          │
//! │  ┌────────────────────────────────────────────────────────────────────┐ │
//! │  │                      GateKeeper                                    │ │
//! │  │                                                                    │ │
//! │  │  ┌──────────────────┐  ┌─────────────────────────────────────┐   │ │
//! │  │  │ GateKeeperConfig │  │  GatingEngine (dsdn_validator)      │   │ │
//! │  │  │  - policy        │  │  - Stateless evaluation             │   │ │
//! │  │  │  - chain_rpc     │  │  - Stake/Identity/TLS/Cooldown/     │   │ │
//! │  │  │  - interval      │  │    Class verification               │   │ │
//! │  │  │  - enable_gating │  └─────────────────────────────────────┘   │ │
//! │  │  └──────────────────┘                                            │ │
//! │  │                                                                    │ │
//! │  │  ┌──────────────────────────────────────────────────────────┐    │ │
//! │  │  │  registry: HashMap<String, NodeRegistryEntry>            │    │ │
//! │  │  │  (local cache, populated by future admission logic)      │    │ │
//! │  │  └──────────────────────────────────────────────────────────┘    │ │
//! │  └────────────────────────────────────────────────────────────────────┘ │
//! │                                                                          │
//! │  Chain RPC (future): Query on-chain stake, slashing, node records       │
//! │  Status: Setup only (14B.31) — no enforcement logic yet                 │
//! └──────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ### GateKeeper Components
//!
//! | Component | Source | Role |
//! |-----------|--------|------|
//! | `GateKeeperConfig` | `gatekeeper` | Policy, RPC endpoint, interval, toggle |
//! | `GateKeeper` | `gatekeeper` | Coordinator-side admission control wrapper |
//! | `GatingEngine` | `dsdn_validator` | Stateless service node evaluation |
//! | `GatingPolicy` | `dsdn_common` | Combined gating configuration |
//! | `NodeRegistryEntry` | `dsdn_common` | Per-node registry record |
//!
//! ### Current Status (14B.35)
//!
//! The gatekeeper provides struct definitions, deterministic construction,
//! node admission filtering (14B.32), stake validation hooks (14B.33),
//! identity validation hooks (14B.34), and scheduler gate integration (14B.35).
//! Remaining stages (14B.36–40) will add periodic re-checks, RPC connections,
//! and background enforcement tasks.
//!
//! ## Modules
//!
//! - **scheduler**: Node scoring and workload-aware scheduling
//! - **da_consumer**: Event consumption from DA layer
//! - **state_machine**: Deterministic event processing
//! - **state_rebuild**: State reconstruction from DA history
//! - **event_publisher**: Event batching and publishing to DA
//! - **reconciliation**: Fallback blob reconciliation to Celestia (14A.1A.31-34)
//! - **multi**: Multi-coordinator consensus with threshold signing (14A.2B.2.11–20)
//! - **gatekeeper**: Service node admission gating (14B.31+)
//!
//! ## Key Invariant
//!
//! **Coordinator state can ALWAYS be reconstructed from DA.**
//! **There is NO authoritative local state.**
//!
//! All state is derived from events on the Data Availability layer. On restart,
//! crash recovery, or new node bootstrap, the complete state is rebuilt by
//! replaying events from DA. This ensures:
//!
//! - Byzantine fault tolerance
//! - Deterministic state across all coordinators
//! - Full auditability
//! - No single point of failure
//!
//! ## Data Flow
//!
//! 1. **Ingest**: `DAConsumer` subscribes to DA layer events
//! 2. **Apply**: `StateMachine` processes events deterministically
//! 3. **Query**: Scheduler and Placement read from `DADerivedState`
//! 4. **Publish**: `EventPublisher` writes new events to DA
//! 5. **Recovery**: `StateRebuilder` reconstructs state from DA history
//! 6. **Reconcile**: `ReconciliationEngine` syncs fallback blobs to Celestia

use std::collections::HashMap;
use parking_lot::RwLock;
use std::sync::Arc;
use serde::{Serialize, Deserialize};

use dsdn_common::consistent_hash::NodeDesc;
use dsdn_common::gating::NodeStatus;

pub mod scheduler;
pub mod da_consumer;
pub mod state_machine;
pub mod state_rebuild;
pub mod event_publisher;
pub mod reconciliation;

// Multi-coordinator module (14A.2B.2.11–20)
pub mod multi;

// GateKeeper module (14B.31–35)
pub mod gatekeeper;

pub use scheduler::{NodeStats, Workload, Scheduler};
pub use da_consumer::{DAConsumer, DADerivedState, ChunkMeta, ReplicaInfo};
pub use state_machine::{
    StateMachine, DAEvent, DAEventType, DAEventPayload, StateError, EventHandler,
    NodeRegisteredPayload, NodeUnregisteredPayload, ChunkDeclaredPayload, ChunkRemovedPayload,
    ReplicaAddedPayload, ReplicaRemovedPayload, ZoneAssignedPayload, ZoneUnassignedPayload,
};
pub use state_rebuild::{StateRebuilder, RebuildProgress, RebuildError};
pub use event_publisher::{EventPublisher, BlobRef};

// Reconciliation exports (14A.1A.40)
pub use reconciliation::{
    ReconciliationEngine,
    ReconciliationConfig,
    ReconcileReport,
    ConsistencyReport,
    PendingBlobInfo,
};

// GateKeeper exports (14B.31–35)
pub use gatekeeper::{
    GateKeeperConfig, GateKeeper,
    AdmissionRequest, AdmissionResponse,
    StakeCheckHook, IdentityCheckHook,
};

/// Node info stored in coordinator
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeInfo {
    pub id: String,
    pub zone: String,
    pub addr: String,
    pub capacity_gb: u64,
    pub meta: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObjectMeta {
    pub hash: String,
    pub size: u64,
    pub replicas: Vec<String>,
}

#[derive(Clone)]
pub struct Coordinator {
    nodes: Arc<RwLock<HashMap<String, NodeInfo>>>,
    objects: Arc<RwLock<HashMap<String, ObjectMeta>>>,
    // per-node runtime statistics
    node_stats: Arc<RwLock<HashMap<String, NodeStats>>>,
    // scheduler instance (weights)
    scheduler: Arc<RwLock<Scheduler>>,
}

impl Coordinator {
    pub fn new() -> Self {
        Self {
            nodes: Arc::new(RwLock::new(HashMap::new())),
            objects: Arc::new(RwLock::new(HashMap::new())),
            node_stats: Arc::new(RwLock::new(HashMap::new())),
            scheduler: Arc::new(RwLock::new(Scheduler::default())),
        }
    }

    /// Register or update node info
    pub fn register_node(&self, info: NodeInfo) {
        self.nodes.write().insert(info.id.clone(), info);
    }

    /// Update node runtime stats (replace)
    pub fn update_node_stats(&self, node_id: &str, stats: NodeStats) {
        self.node_stats.write().insert(node_id.to_string(), stats);
    }

    /// Get node stats if any
    pub fn get_node_stats(&self, node_id: &str) -> Option<NodeStats> {
        self.node_stats.read().get(node_id).cloned()
    }

    /// List nodes
    pub fn list_nodes(&self) -> Vec<NodeInfo> {
        self.nodes.read().values().cloned().collect()
    }

    /// Register object metadata (initially no replicas)
    pub fn register_object(&self, hash: String, size: u64) {
        let mut objs = self.objects.write();
        objs.entry(hash.clone()).or_insert(ObjectMeta {
            hash,
            size,
            replicas: vec![],
        });
    }

    pub fn get_object(&self, hash: &str) -> Option<ObjectMeta> {
        self.objects.read().get(hash).cloned()
    }

    /// mark replica missing (remove node id from object's replica list)
    pub fn mark_replica_missing(&self, hash: &str, node_id: &str) {
        let mut objs = self.objects.write();
        if let Some(obj) = objs.get_mut(hash) {
            obj.replicas.retain(|nid| nid != node_id);
        }
    }

    /// mark replica healed (add node id if missing)
    pub fn mark_replica_healed(&self, hash: &str, node_id: &str) {
        let mut objs = self.objects.write();
        if let Some(obj) = objs.get_mut(hash) {
            if !obj.replicas.contains(&node_id.to_string()) {
                obj.replicas.push(node_id.to_string());
            }
        } else {
            // create if not exists
            objs.insert(hash.to_string(), ObjectMeta {
                hash: hash.to_string(),
                size: 0,
                replicas: vec![node_id.to_string()],
            });
        }
    }

    /// Placement: choose up to rf node ids for given object hash, prefer distinct zones, based on consistent hashing.
    pub fn placement_for_hash(&self, hash: &str, rf: usize) -> Vec<String> {
        let nodes = self.list_nodes();
        if nodes.is_empty() {
            return vec![];
        }
        let descs: Vec<NodeDesc> = nodes.into_iter().map(|n| NodeDesc {
            id: n.id,
            zone: n.zone,
            weight: (n.capacity_gb.max(1) as u32),
        }).collect();
        let sel = dsdn_common::consistent_hash::select_nodes(&descs, hash, rf);
        sel
    }

    /// Scheduling: pick best node id for given workload.
    /// Returns None if no node meets soft requirements.
    ///
    /// ## Gating Integration (14B.35)
    ///
    /// When `gatekeeper` is `Some`, delegates to [`schedule_with_gating`](Self::schedule_with_gating)
    /// which filters nodes through the gating registry before scoring.
    /// When `gatekeeper` is `None`, runs the original scoring logic unchanged.
    ///
    /// ## Backward Compatibility
    ///
    /// Passing `None` for `gatekeeper` produces identical behavior to the
    /// pre-14B.35 version. No scoring algorithm, tie-breaking, or requirement
    /// checking logic is modified.
    pub fn schedule(&self, workload: &Workload, gatekeeper: Option<&GateKeeper>) -> Option<String> {
        if let Some(gk) = gatekeeper {
            return self.schedule_with_gating(workload, gk);
        }
        let nodes = self.list_nodes();
        if nodes.is_empty() { return None; }
        let stats_map = self.node_stats.read();
        let scheduler = self.scheduler.read().clone();
        // iterate nodes, compute score only for nodes that meet requirements
        let mut best: Option<(String, f64)> = None;
        for n in nodes {
            let stats = stats_map.get(&n.id).cloned().unwrap_or_default();
            if !scheduler.meets(&stats, workload) {
                continue;
            }
            let score = scheduler.score(&stats);
            match &best {
                None => best = Some((n.id.clone(), score)),
                Some((best_id, best_score)) => {
                    if score > *best_score {
                        best = Some((n.id.clone(), score));
                    } else if (score - *best_score).abs() < 1e-9 {
                        // tie-breaker deterministic: pick lexicographically smaller id
                        if n.id < *best_id {
                            best = Some((n.id.clone(), score));
                        }
                    }
                }
            }
        }
        best.map(|(id, _)| id)
    }

    /// Scheduling with gating: pick best node id for given workload,
    /// filtering through the GateKeeper registry.
    ///
    /// ## Flow
    ///
    /// 1. Retrieve list of registered coordinator nodes.
    /// 2. **Gating filter** (before scoring): For each node, verify:
    ///    - The node exists in `gatekeeper.registry` (by coordinator node ID).
    ///    - The node's `NodeRegistryEntry.status == NodeStatus::Active`.
    ///    Nodes that fail either check are skipped with a warning log.
    /// 3. Run existing scoring logic (requirement check + weighted score)
    ///    **without modification** on the filtered set.
    /// 4. Return the best-scoring node, or `None` if no eligible nodes remain.
    ///
    /// ## Determinism
    ///
    /// Same `(workload, gatekeeper.registry, coordinator nodes, stats)` always
    /// produces the same result. Logging does not affect return value.
    ///
    /// ## Immutability
    ///
    /// This method takes `&self` and `&GateKeeper` — no mutation of
    /// coordinator state, gatekeeper registry, or workload.
    pub fn schedule_with_gating(
        &self,
        workload: &Workload,
        gatekeeper: &GateKeeper,
    ) -> Option<String> {
        let nodes = self.list_nodes();
        if nodes.is_empty() { return None; }
        let stats_map = self.node_stats.read();
        let scheduler = self.scheduler.read().clone();

        let mut best: Option<(String, f64)> = None;
        for n in nodes {
            // Gating filter: node must exist in registry with Active status.
            match gatekeeper.registry.get(&n.id) {
                None => {
                    eprintln!(
                        "[gatekeeper] schedule: skipping node '{}': not found in gating registry",
                        n.id,
                    );
                    continue;
                }
                Some(entry) => {
                    if entry.status != NodeStatus::Active {
                        eprintln!(
                            "[gatekeeper] schedule: skipping node '{}': status {:?} != Active",
                            n.id, entry.status,
                        );
                        continue;
                    }
                }
            }

            // Scoring logic: identical to schedule() — no modification.
            let stats = stats_map.get(&n.id).cloned().unwrap_or_default();
            if !scheduler.meets(&stats, workload) {
                continue;
            }
            let score = scheduler.score(&stats);
            match &best {
                None => best = Some((n.id.clone(), score)),
                Some((best_id, best_score)) => {
                    if score > *best_score {
                        best = Some((n.id.clone(), score));
                    } else if (score - *best_score).abs() < 1e-9 {
                        // tie-breaker deterministic: pick lexicographically smaller id
                        if n.id < *best_id {
                            best = Some((n.id.clone(), score));
                        }
                    }
                }
            }
        }
        best.map(|(id, _)| id)
    }

    /// set scheduler weights (optional)
    pub fn set_scheduler(&self, s: Scheduler) {
        *self.scheduler.write() = s;
    }
}

impl Default for Coordinator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_list() {
        let c = Coordinator::new();
        let n = NodeInfo {
            id: "node1".into(),
            zone: "z1".into(),
            addr: "127.0.0.1:7001".into(),
            capacity_gb: 10,
            meta: serde_json::json!({}),
        };
        c.register_node(n.clone());
        let nodes = c.list_nodes();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].id, "node1");
    }

    #[test]
    fn test_placement_three_zones() {
        let c = Coordinator::new();
        // Register 5 nodes in zones a,b,c
        c.register_node(NodeInfo { id: "n1".into(), zone: "a".into(), addr: "a:1".into(), capacity_gb: 10, meta: serde_json::json!({}) });
        c.register_node(NodeInfo { id: "n2".into(), zone: "b".into(), addr: "b:1".into(), capacity_gb: 10, meta: serde_json::json!({}) });
        c.register_node(NodeInfo { id: "n3".into(), zone: "c".into(), addr: "c:1".into(), capacity_gb: 10, meta: serde_json::json!({}) });
        c.register_node(NodeInfo { id: "n4".into(), zone: "a".into(), addr: "a:2".into(), capacity_gb: 10, meta: serde_json::json!({}) });
        c.register_node(NodeInfo { id: "n5".into(), zone: "b".into(), addr: "b:2".into(), capacity_gb: 10, meta: serde_json::json!({}) });

        let selection = c.placement_for_hash("some-object-hash", 3);
        // expect up to 3 nodes, ideally 3 distinct zones
        assert!(selection.len() <= 3);
        let mut zones = std::collections::HashSet::new();
        for id in &selection {
            let node = c.list_nodes().into_iter().find(|n| &n.id == id).unwrap();
            zones.insert(node.zone);
        }
        assert_eq!(zones.len(), selection.len()); // distinct zones
    }

    #[test]
    fn test_scheduler_simple_choice() {
        let c = Coordinator::new();
        // register nodes
        c.register_node(NodeInfo { id: "a".into(), zone: "z1".into(), addr: "a:1".into(), capacity_gb: 100, meta: serde_json::json!({}) });
        c.register_node(NodeInfo { id: "b".into(), zone: "z1".into(), addr: "b:1".into(), capacity_gb: 100, meta: serde_json::json!({}) });
        c.register_node(NodeInfo { id: "c".into(), zone: "z1".into(), addr: "c:1".into(), capacity_gb: 100, meta: serde_json::json!({}) });

        // set stats so that 'b' is best
        c.update_node_stats("a", NodeStats { cpu_free: 0.2, ram_free_mb: 2000.0, gpu_free: 0.0, latency_ms: 10.0, io_pressure: 0.3 });
        c.update_node_stats("b", NodeStats { cpu_free: 0.9, ram_free_mb: 4000.0, gpu_free: 1.0, latency_ms: 5.0, io_pressure: 0.05 });
        c.update_node_stats("c", NodeStats { cpu_free: 0.5, ram_free_mb: 1000.0, gpu_free: 0.0, latency_ms: 20.0, io_pressure: 0.1 });

        let wl = Workload { cpu_req: Some(0.1), ram_req_mb: Some(512.0), gpu_req: None, max_latency_ms: None, io_tolerance: None };
        let chosen = c.schedule(&wl, None).expect("should pick a node");
        assert_eq!(chosen, "b");
    }

    #[test]
    fn test_scheduler_requirement_filtering() {
        let c = Coordinator::new();
        c.register_node(NodeInfo { id: "n1".into(), zone: "z1".into(), addr: "a:1".into(), capacity_gb: 10, meta: serde_json::json!({}) });
        c.register_node(NodeInfo { id: "n2".into(), zone: "z1".into(), addr: "b:1".into(), capacity_gb: 10, meta: serde_json::json!({}) });

        c.update_node_stats("n1", NodeStats { cpu_free: 0.9, ram_free_mb: 1024.0, gpu_free: 0.0, latency_ms: 2.0, io_pressure: 0.0 });
        c.update_node_stats("n2", NodeStats { cpu_free: 0.9, ram_free_mb: 256.0, gpu_free: 0.0, latency_ms: 2.0, io_pressure: 0.0 });

        // workload requires at least 512 MB - only n1 qualifies
        let wl = Workload { cpu_req: None, ram_req_mb: Some(512.0), gpu_req: None, max_latency_ms: None, io_tolerance: None };
        let chosen = c.schedule(&wl, None).expect("should pick n1");
        assert_eq!(chosen, "n1");
    }

    #[test]
    fn test_coordinator_default() {
        let c = Coordinator::default();
        assert!(c.list_nodes().is_empty());
    }
}