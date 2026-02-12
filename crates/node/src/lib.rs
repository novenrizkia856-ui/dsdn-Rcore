//! # DSDN Node Crate (14A)
//!
//! Storage node for DSDN network with Multi-DA source fallback capability.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                              Node                                        │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                          │
//! │  ┌─────────────────────────────────────────────────────────────────┐   │
//! │  │                      MultiDASource                               │   │
//! │  │  ┌───────────┐   ┌─────────────┐   ┌─────────────────────────┐  │   │
//! │  │  │  Primary  │   │  Secondary  │   │       Emergency         │  │   │
//! │  │  │ (Celestia)│   │  (Backup)   │   │    (Last Resort)        │  │   │
//! │  │  └─────┬─────┘   └──────┬──────┘   └────────────┬────────────┘  │   │
//! │  │        │                │                       │               │   │
//! │  │        └────────────────┼───────────────────────┘               │   │
//! │  │                         │ Fallback with Priority                │   │
//! │  └─────────────────────────┼───────────────────────────────────────┘   │
//! │                            │                                            │
//! │                            ▼                                            │
//! │  ┌─────────────────────────────────────────────────────────────────┐   │
//! │  │                       DAFollower                                 │   │
//! │  │  ┌─────────────────┐         ┌──────────────────────────────┐   │   │
//! │  │  │ Source Transition│────────▶│     NodeDerivedState        │   │   │
//! │  │  │   (14A.1A.48)   │         │  - fallback_active           │   │   │
//! │  │  └─────────────────┘         │  - fallback_since            │   │   │
//! │  │                              │  - current_da_source         │   │   │
//! │  │                              │  - events_from_fallback      │   │   │
//! │  │                              │  - last_reconciliation_seq   │   │   │
//! │  │                              └──────────────────────────────┘   │   │
//! │  └─────────────────────────────────────────────────────────────────┘   │
//! │                            │                                            │
//! │              ┌─────────────┼─────────────┐                              │
//! │              ▼             ▼             ▼                              │
//! │  ┌───────────────┐ ┌─────────────┐ ┌──────────────────────────────┐    │
//! │  │EventProcessor │ │   Health    │ │  NodeFallbackMetrics         │    │
//! │  │               │ │  Reporting  │ │  - source_switches           │    │
//! │  │ - is_fallback │ │  - degraded │ │  - events_from_primary       │    │
//! │  │   _source()   │ │    status   │ │  - events_from_fallback      │    │
//! │  │ - detect_     │ │  - fallback │ │  - fallback_duration_secs    │    │
//! │  │   fallback()  │ │    fields   │ │  - transition_failures       │    │
//! │  └───────────────┘ └─────────────┘ └──────────────────────────────┘    │
//! │                                                                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Multi-DA Source Architecture
//!
//! The node implements a fault-tolerant Multi-DA source system with three tiers:
//!
//! | Source    | Priority | Role                                           |
//! |-----------|----------|------------------------------------------------|
//! | Primary   | 1        | Main DA source (Celestia), always preferred    |
//! | Secondary | 2        | Backup DA source, used when Primary fails      |
//! | Emergency | 3        | Last resort DA source, used when both fail     |
//!
//! ## Design Principles
//!
//! - **Determinism**: All nodes must converge to the same state regardless of
//!   which DA source provided the events. Events are identified by sequence
//!   number, not by source.
//!
//! - **No Event Loss**: During source transitions, the system guarantees that
//!   no events are lost. Events are drained from the old source before
//!   switching to the new source.
//!
//! - **No Duplication**: Events are deduplicated by sequence number. If the
//!   same event is seen from multiple sources, only the first is processed.
//!
//! - **Eventual Consistency**: The node will eventually return to Primary
//!   source when it becomes available (auto-promotion).
//!
//! # Source Prioritization
//!
//! ## Priority Order
//!
//! Sources are tried in strict priority order:
//!
//! 1. **Primary** - Always attempted first
//! 2. **Secondary** - Used only when Primary is unavailable
//! 3. **Emergency** - Used only when both Primary and Secondary fail
//!
//! ## Switching Conditions
//!
//! A source switch occurs when:
//!
//! - **Downgrade** (Primary → Secondary → Emergency):
//!   - Current source fails to respond within timeout
//!   - Current source returns errors repeatedly
//!   - Current source returns invalid/corrupted data
//!
//! - **Upgrade** (Emergency → Secondary → Primary):
//!   - Higher priority source becomes available (auto-promotion)
//!   - Periodic health checks succeed on higher priority source
//!
//! ## Auto-Promotion
//!
//! When operating in fallback mode, the system periodically attempts to
//! reconnect to higher priority sources. Successful reconnection triggers
//! an automatic promotion back to the preferred source.
//!
//! # Transition Handling
//!
//! Source transitions follow a strict protocol to ensure data integrity:
//!
//! ## Transition Protocol
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                  Source Transition Flow                  │
//! ├─────────────────────────────────────────────────────────┤
//! │                                                          │
//! │  1. PAUSE     ──▶  Stop processing new events            │
//! │                    (paused flag = true)                  │
//! │                                                          │
//! │  2. DRAIN     ──▶  Process all pending events from       │
//! │                    current source                        │
//! │                                                          │
//! │  3. UPDATE    ──▶  Update NodeDerivedState:              │
//! │                    - Set current_da_source               │
//! │                    - Set fallback_active/fallback_since  │
//! │                                                          │
//! │  4. VERIFY    ──▶  Verify sequence continuity            │
//! │                    (no gaps, no duplicates)              │
//! │                                                          │
//! │  5. RESUME    ──▶  Resume event processing               │
//! │                    (paused flag = false)                 │
//! │                                                          │
//! └─────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Rollback Semantics
//!
//! If any step in the transition fails:
//!
//! 1. State is restored to pre-transition values
//! 2. Event processing resumes from original source
//! 3. Transition failure is recorded in metrics
//! 4. System continues operating on previous source
//!
//! Rollback is atomic - there is no partial state after a failed transition.
//!
//! ## Timeout Handling
//!
//! Transitions have a configurable timeout (`TRANSITION_TIMEOUT_MS`).
//! If the transition exceeds this timeout, it is considered failed and
//! rollback is triggered automatically.
//!
//! # Metrics Interpretation
//!
//! ## Fallback Metrics
//!
//! The [`NodeFallbackMetrics`] struct tracks fallback operations:
//!
//! | Metric                        | Meaning                                    |
//! |-------------------------------|--------------------------------------------|
//! | `source_switches`             | Total number of DA source transitions      |
//! | `events_from_primary`         | Events successfully processed from Primary |
//! | `events_from_fallback`        | Events processed from Secondary/Emergency  |
//! | `fallback_duration_total_secs`| Cumulative time spent in fallback mode     |
//! | `transition_failures`         | Number of failed transition attempts       |
//!
//! ## Health Degradation
//!
//! A node's health is considered **degraded** when:
//!
//! - `fallback_active == true` AND
//! - Time since `fallback_since` exceeds `FALLBACK_DEGRADATION_THRESHOLD_MS` (5 minutes)
//!
//! Degraded health indicates the node has been operating on a fallback source
//! for an extended period, which may indicate Primary source issues.
//!
//! ## Metrics-Health-State Relationship
//!
//! ```text
//! ┌──────────────────────┐      ┌─────────────────┐      ┌──────────────┐
//! │ NodeFallbackMetrics  │      │ NodeDerivedState│      │  NodeHealth  │
//! │                      │      │                 │      │              │
//! │ source_switches ─────┼──────┼▶ fallback_active│──────┼▶ is_healthy  │
//! │ events_from_fallback │      │  fallback_since │      │  health_     │
//! │ transition_failures  │      │  current_source │      │  issues()    │
//! └──────────────────────┘      └─────────────────┘      └──────────────┘
//!         │                             │                       │
//!         │                             │                       │
//!         ▼                             ▼                       ▼
//!    Prometheus              State Transitions           Health API
//!    /metrics                 & Fallback Logic          /health endpoint
//! ```
//!
//! # Environment File Loading
//!
//! The node uses the same env file loading pattern as the coordinator:
//!
//! 1. `DSDN_ENV_FILE` environment variable (custom path)
//! 2. `.env.mainnet` (production default - DSDN defaults to mainnet)
//! 3. `.env` (fallback for development)
//!
//! # Modules
//!
//! | Module              | Description                                          |
//! |---------------------|------------------------------------------------------|
//! | `da_follower`       | DA subscription, event processing, source transitions|
//! | `event_processor`   | Event handling logic with fallback detection         |
//! | `placement_verifier`| Placement verification                               |
//! | `delete_handler`    | Delete request handling                              |
//! | `state_sync`        | State synchronization                                |
//! | `health`            | Health reporting with fallback awareness             |
//! | `multi_da_source`   | Multi-DA source abstraction (Primary/Secondary/Emergency) |
//! | `metrics`           | Node fallback metrics for Prometheus export          |
//! | `identity_manager`  | Ed25519 keypair management and identity proof construction (14B.41) |
//!
//! # Node Identity & Gating (14B)
//!
//! ## NodeIdentityManager (14B.41)
//!
//! `NodeIdentityManager` encapsulates the node's Ed25519 keypair and provides
//! the cryptographic operations needed for coordinator admission gating.
//!
//! ```text
//! ┌──────────────────────────────────────────────────────┐
//! │              NodeIdentityManager                      │
//! │  ┌──────────────┐    ┌───────────────────────────┐   │
//! │  │  SigningKey   │───▶│      NodeIdentity         │   │
//! │  │  (PRIVATE)    │    │  - node_id  [u8; 32]     │   │
//! │  │  Never exposed│    │  - operator  [u8; 20]    │   │
//! │  └──────────────┘    │  - tls_fp   [u8; 32]     │   │
//! │         │             └───────────────────────────┘   │
//! │         ▼                                             │
//! │  sign_challenge(nonce) ──▶ [u8; 64] signature        │
//! │  create_identity_proof(challenge) ──▶ IdentityProof  │
//! └──────────────────────────────────────────────────────┘
//!                          │
//!                          ▼
//! ┌──────────────────────────────────────────────────────┐
//! │          Coordinator GateKeeper (14B.31–40)           │
//! │  IdentityVerifier::verify_proof(proof, ts, max_age)  │
//! │  IdentityProof::verify() → verify_strict(nonce, sig) │
//! └──────────────────────────────────────────────────────┘
//! ```
//!
//! ### Relation to GateKeeper
//!
//! The coordinator's `GateKeeper` (14B.31–40) evaluates admission requests
//! that include an `IdentityProof`. The node constructs this proof using
//! `NodeIdentityManager::create_identity_proof`, which signs the coordinator-
//! issued challenge nonce. The coordinator verifies the proof via
//! `IdentityVerifier::verify_proof` (14B.22).
//!
//! ### Relation to IdentityVerifier
//!
//! `IdentityVerifier` (14B.22) is a stateless verifier on the coordinator
//! side. It calls `IdentityProof::verify()` which uses
//! `ed25519_dalek::VerifyingKey::verify_strict(&challenge.nonce, &signature)`.
//! The signing convention in `NodeIdentityManager::sign_challenge` matches
//! this exactly: raw nonce bytes, no prefix, no domain separator.
//!
//! ### Security
//!
//! - The Ed25519 `SigningKey` is never exposed via any public method.
//! - `Debug` output redacts the signing key (`[REDACTED]`).
//! - No `Clone` derived on the struct (prevents accidental key duplication).
//! - No `Serialize` derived (prevents key serialization to untrusted sinks).
//! - The struct is `Send + Sync` (no interior mutability).
//!
//! ### Determinism
//!
//! - `from_keypair(secret)`: Fully deterministic — same secret always
//!   produces identical `node_id`, `operator_address`, and signatures.
//! - `sign_challenge(nonce)`: Deterministic per RFC 8032 (Ed25519).
//! - `generate()`: Uses OS entropy (`OsRng`); subsequent operations
//!   are deterministic for the generated key.
//!
//! # Key Invariants
//!
//! 1. **DA-Derived State**: Node does NOT receive instructions from Coordinator
//!    via RPC. All commands arrive via DA events.
//!
//! 2. **Source Independence**: Node state is independent of which DA source
//!    provided the events. Same sequence number = same state.
//!
//! 3. **Atomic Transitions**: Source transitions are atomic - they either
//!    complete fully or roll back completely.
//!
//! 4. **No Silent Failures**: All errors are explicitly handled and propagated.
//!    No panic, unwrap, or expect in production code paths.

pub mod da_follower;
pub mod delete_handler;
pub mod event_processor;
pub mod handlers;
pub mod health;
pub mod identity_manager;
pub mod metrics;
pub mod multi_da_source;
pub mod placement_verifier;
pub mod state_sync;

pub use da_follower::{
    DAFollower, NodeDerivedState, ChunkAssignment, StateError, ReplicaStatus,
    TransitionError, TransitionResult, TRANSITION_TIMEOUT_MS,
};
pub use delete_handler::{DeleteHandler, DeleteError, DeleteRequestedEvent, PendingDelete, Storage};
pub use event_processor::{NodeEventProcessor, NodeAction, ProcessError};
pub use health::{
    NodeHealth, HealthStorage, DAInfo, HealthResponse, health_endpoint,
    DA_LAG_THRESHOLD, FALLBACK_DEGRADATION_THRESHOLD_MS,
};
pub use metrics::NodeFallbackMetrics;
pub use multi_da_source::{MultiDASource, MultiDAConfig, DASourceType};
pub use placement_verifier::{PlacementVerifier, PlacementReport, PlacementDetail, PlacementStatus};
pub use state_sync::{StateSync, ConsistencyReport, SyncError, SyncStorage};

// HTTP API handlers (Axum) - READ-ONLY observability endpoints
pub use handlers::{NodeAppState, build_router};
pub use identity_manager::{NodeIdentityManager, IdentityError};