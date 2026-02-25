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
//! | Module                | Responsibility                                         | Key Dependencies         |
//! |-----------------------|--------------------------------------------------------|--------------------------|
//! | `da_follower`         | DA subscription, event processing, source transitions  | `multi_da_source`        |
//! | `delete_handler`      | Delete request handling with quarantine awareness       | —                        |
//! | `event_processor`     | Event handling logic with fallback detection            | `da_follower`            |
//! | `handlers`            | HTTP API routes and application state                  | `health`, `metrics`      |
//! | `health`              | Health reporting with fallback awareness & identity     | `identity_manager`       |
//! | `identity_manager`    | Ed25519 keypair management and identity proofs (14B.41) | `ed25519-dalek`         |
//! | `identity_persistence`| Secure disk persistence for Ed25519 keys (14B.47)      | `identity_manager`       |
//! | `join_request`        | Join request builder with validation (14B.43)          | `identity_manager`, `tls_manager` |
//! | `metrics`             | Node fallback metrics for Prometheus export             | —                        |
//! | `multi_da_source`     | Multi-DA source abstraction (Primary/Secondary/Emergency) | —                     |
//! | `placement_verifier`  | Placement verification against coordinator instructions | —                        |
//! | `quarantine_handler`  | Quarantine processing and recovery eligibility (14B.45) | `status_tracker`         |
//! | `rejoin_manager`      | Re-join eligibility and request building (14B.46)       | `identity_manager`, `tls_manager` |
//! | `state_sync`          | State synchronization across DA sources                 | —                        |
//! | `status_notification` | Status notification processing and lifecycle events (14B.49) | `status_tracker`    |
//! | `status_tracker`      | Node lifecycle state machine with audit history (14B.44) | —                       |
//! | `tls_manager`         | TLS certificate loading, generation, fingerprints (14B.42) | `rcgen`, `x509-parser` |
//! | `workload_executor`   | Stateless runtime dispatch to WASM/VM (14C.B.13)       | `dsdn_runtime_wasm`      |
//! | `usage_proof_builder` | Ed25519-signed resource usage proofs (14C.B.14)         | `identity_manager`, `sha3` |
//! | `coordinator_client`  | Receipt submission via trait transport (14C.B.15)       | `async-trait`            |
//! | `receipt_handler`     | Receipt storage, validation, lifecycle (14C.B.16)       | `dsdn_common`            |
//! | `chain_submitter`     | On-chain reward claim via trait transport (14C.B.17)    | `async-trait`            |
//! | `reward_orchestrator` | Full pipeline glue: execute→proof→coord→receipt→chain (14C.B.18) | all above        |
//!
//! # Node Identity & Gating (14B)
//!
//! ## Architecture Overview
//!
//! The Node Identity & Gating subsystem implements the node-side
//! counterpart to the coordinator's gating system (14B.29–14B.40).
//! It handles identity management, TLS certificates, admission
//! requests, status tracking, quarantine handling, re-join logic,
//! persistent identity storage, health reporting, and event-driven
//! status notification processing.
//!
//! All components operate under strict determinism: same inputs
//! produce same outputs with no randomness, no implicit timestamps,
//! and no hidden global state. The shared `NodeStatusTracker` is
//! protected by `parking_lot::Mutex` and accessed via `Arc` for
//! safe concurrent use across subsystems.
//!
//! ## Component Catalog
//!
//! | Component | Module | Phase |
//! |-----------|--------|-------|
//! | NodeIdentityManager | `identity_manager` | 14B.41 |
//! | TLSCertManager | `tls_manager` | 14B.42 |
//! | JoinRequestBuilder | `join_request` | 14B.43 |
//! | NodeStatusTracker | `status_tracker` | 14B.44 |
//! | QuarantineHandler | `quarantine_handler` | 14B.45 |
//! | RejoinManager | `rejoin_manager` | 14B.46 |
//! | IdentityStore | `identity_persistence` | 14B.47 |
//! | Health Extension | `health` | 14B.48 |
//! | StatusNotificationHandler | `status_notification` | 14B.49 |
//! | Integration Tests | `gating_tests` | 14B.50 |
//!
//! ## Node Lifecycle (ASCII)
//!
//! ```text
//!                  ┌─────────┐
//!       start ───>│ Pending  │
//!                  └────┬────┘
//!                       │ NodeAdmitted
//!               ┌───────▼───────┐
//!               │    Active     │<──────────────────┐
//!               └──┬─────────┬──┘                   │
//!                  │         │                       │
//!      stake drop  │         │ identity spoofing     │ stake restored
//!                  │         │ severe slashing       │ (coordinator)
//!          ┌───────▼──┐  ┌──▼──────┐          ┌─────┴────┐
//!          │Quarantined│  │ Banned  │──expiry─>│ Pending  │
//!          └───┬───┬───┘  └─────────┘          └──────────┘
//!              │   │
//!   escalation │   │ recovery
//!              │   └──────────────────────────────────┘
//!              │
//!          ┌───▼─────┐
//!          │ Banned  │
//!          └─────────┘
//! ```
//!
//! ## State Transition Rules
//!
//! | From | To | Condition |
//! |------|----|-----------|
//! | Pending | Active | Admitted by coordinator |
//! | Pending | Banned | Identity spoofing at admission |
//! | Active | Quarantined | Stake drop, minor violation |
//! | Active | Banned | Severe slashing, identity spoofing |
//! | Quarantined | Active | Stake restored (coordinator) |
//! | Quarantined | Banned | Escalation |
//! | Banned | Pending | Ban cooldown expired, re-admission |
//!
//! All other transitions are illegal and rejected by
//! `NodeStatusTracker::update_status`. Timestamp monotonicity
//! is enforced — each transition must have a strictly increasing
//! timestamp.
//!
//! ## Determinism & Security Guarantees
//!
//! - Same inputs always produce same outputs. No randomness.
//! - No `panic!`, `unwrap()`, `expect()` in production code.
//! - No `unsafe` code in any gating module.
//! - Secret keys are never exposed via health, logging, or serialization.
//! - Only public identity (node_id, operator_address) is visible.
//! - TLS fingerprint verification uses strict SHA-256 byte comparison.
//! - All arithmetic uses saturating operations to prevent overflow.
//! - Mutex locks are held only for the duration of single operations.
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
//! ## TLSCertManager (14B.42)
//!
//! `TLSCertManager` loads or generates TLS certificates and exposes the
//! pre-computed `TLSCertInfo` needed for coordinator admission gating.
//!
//! ```text
//! ┌──────────────────────────────────────────────────────┐
//! │                TLSCertManager                         │
//! │  ┌──────────────┐    ┌───────────────────────────┐   │
//! │  │  cert_der    │───▶│      TLSCertInfo          │   │
//! │  │  (DER bytes) │    │  - fingerprint [u8; 32]   │   │
//! │  │              │    │  - subject_cn  String      │   │
//! │  └──────────────┘    │  - not_before  u64         │   │
//! │                      │  - not_after   u64         │   │
//! │  No private key      │  - issuer      String      │   │
//! │  stored here!        └───────────────────────────┘   │
//! └──────────────────────────────────────────────────────┘
//!                          │
//!                          ▼
//! ┌──────────────────────────────────────────────────────┐
//! │          Coordinator TLSVerifier (14B.23)             │
//! │  - Validates fingerprint ↔ NodeIdentity binding      │
//! │  - Checks not_before ≤ timestamp ≤ not_after         │
//! │  - Verifies subject CN                               │
//! └──────────────────────────────────────────────────────┘
//! ```
//!
//! ### Relation to TLSVerifier
//!
//! `TLSVerifier` (14B.23) is a stateless verifier on the coordinator side.
//! It compares the certificate's SHA-256 fingerprint against the
//! `tls_cert_fingerprint` in `NodeIdentity`. The node must set
//! `NodeIdentity::tls_cert_fingerprint` to `TLSCertManager::fingerprint()`
//! before submitting an admission request.
//!
//! ### Fingerprint Guarantee
//!
//! `fingerprint = SHA-256(cert_der)` — computed once at construction,
//! stored in `TLSCertInfo::fingerprint`, returned by reference. Same
//! DER bytes always produce the same fingerprint. This matches
//! `TLSCertInfo::compute_fingerprint` in `dsdn_common`.
//!
//! ### Security
//!
//! - `TLSCertManager` stores only the certificate (public) bytes.
//! - No private key is retained after `generate_self_signed`.
//! - The struct is `Send + Sync` (no interior mutability).
//! - No `unsafe` code.
//!
//! ## JoinRequestBuilder (14B.43)
//!
//! `JoinRequestBuilder` constructs a validated [`JoinRequest`] from
//! the node's identity manager, TLS manager, and coordinator-issued
//! challenge. The builder enforces that all required fields are present
//! before construction.
//!
//! ```text
//! ┌──────────────────────────────────────────────────────┐
//! │            JoinRequestBuilder                         │
//! │  ┌────────────────────┐                              │
//! │  │ &NodeIdentityManager│──── create_identity_proof   │
//! │  └────────────────────┘                              │
//! │  ┌────────────────────┐                              │
//! │  │ &TLSCertManager    │──── cert_info().clone()      │
//! │  └────────────────────┘                              │
//! │  with_addr(addr)                                     │
//! │  with_capacity(gb)                                   │
//! │  with_meta(k, v)                                     │
//! │         │                                            │
//! │         ▼                                            │
//! │  build(challenge) ──▶ Result<JoinRequest, JoinError> │
//! └──────────────────────────────────────────────────────┘
//!                          │
//!                          ▼
//! ┌──────────────────────────────────────────────────────┐
//! │        Coordinator GateKeeper (14B.31–40)             │
//! │  Extracts: identity, claimed_class, identity_proof,  │
//! │            tls_cert_info → AdmissionRequest (14B.32)  │
//! └──────────────────────────────────────────────────────┘
//! ```
//!
//! ### Relation to AdmissionRequest (14B.32)
//!
//! `JoinRequest` is the node-side representation. The coordinator
//! extracts the four gating-relevant fields (`identity`, `claimed_class`,
//! `identity_proof`, `tls_cert_info`) to construct an `AdmissionRequest`.
//! The remaining fields (`node_addr`, `capacity_gb`, `meta`) are stored
//! in the node registry for operational use.
//!
//! ### Determinism
//!
//! Same `NodeIdentityManager` + same `TLSCertManager` + same
//! `IdentityChallenge` always produce the same `JoinRequest`.
//! The identity proof signature is deterministic (Ed25519, RFC 8032).
//! No implicit defaults — all required fields must be explicitly set.
//!
//! ### Validation
//!
//! `build()` checks in strict order: (1) TLS info set, (2) addr set
//! and non-empty, (3) identity proof construction. Missing fields
//! produce specific `JoinError` variants. No partial state is returned.
//!
//! ## NodeStatusTracker (14B.44)
//!
//! `NodeStatusTracker` maintains the node's local view of its lifecycle
//! status and an ordered history of all transitions.
//!
//! ```text
//! ┌──────────────────────────────────────────────────────┐
//! │             NodeStatusTracker                         │
//! │  current_status: NodeStatus                          │
//! │  history: Vec<StatusTransition>                      │
//! │  registered_at: Option<u64>                          │
//! │                                                      │
//! │  update_status(new, reason, ts) → Result<(), String> │
//! │  current() → &NodeStatus                             │
//! │  is_active() → bool                                  │
//! │  is_schedulable() → bool                             │
//! │  time_in_current_status(now) → u64                   │
//! └──────────────────────────────────────────────────────┘
//! ```
//!
//! ### Relation to GateKeeper
//!
//! The coordinator's `NodeLifecycleManager` (14B.38) manages the
//! authoritative node status. `NodeStatusTracker` is the node-side
//! mirror: it applies the same transition rules
//! (`NodeStatus::can_transition_to`) to maintain a consistent local
//! view. Status updates arrive via coordinator responses or DA events.
//!
//! ### Determinism
//!
//! All transitions are validated against the same 7-transition state
//! machine defined in `NodeStatus::can_transition_to`. Timestamps are
//! strictly monotonic. Arithmetic uses `saturating_sub`.
//!
//! ### History as Audit Trail
//!
//! Every successful transition appends a `StatusTransition` record
//! (from, to, reason, timestamp). History is append-only, never
//! truncated or reordered. `registered_at` records the first
//! transition away from `Pending`.
//!
//! ### No Implicit Transitions
//!
//! The tracker never changes status on its own. All transitions
//! require an explicit `update_status` call with a reason and
//! timestamp. Failed transitions leave all state unchanged.
//!
//! ## QuarantineHandler (14B.45)
//!
//! `QuarantineHandler` processes quarantine notifications from the
//! coordinator and manages quarantine-specific metadata (reason,
//! start timestamp, duration).
//!
//! ```text
//! ┌──────────────────────────────────────────────────────┐
//! │             QuarantineHandler                         │
//! │  &mut NodeStatusTracker ─── update_status(Quarantined)│
//! │  quarantine_reason: Option<String>                   │
//! │  quarantined_since: Option<u64>                      │
//! │                                                      │
//! │  handle_quarantine_notification(reason, ts)           │
//! │  attempt_recovery(cur_stake, req_stake) → bool        │
//! │  is_quarantined() → bool                             │
//! │  quarantine_duration(now) → Option<u64>               │
//! │  clear_quarantine_metadata() → Result                │
//! └──────────────────────────────────────────────────────┘
//! ```
//!
//! ### Relation to GateKeeper and NodeLifecycleManager
//!
//! The coordinator's `QuarantineManager` (14B.36) decides when to
//! quarantine a node. `NodeLifecycleManager` (14B.38) executes the
//! transition authoritatively. `QuarantineHandler` is the node-side
//! counterpart: it applies the coordinator's decision to the local
//! `NodeStatusTracker` using the same transition rules.
//!
//! ### Stake-Based Recovery
//!
//! `attempt_recovery(current_stake, required_stake)` is a pure
//! read-only check. It returns `true` only if the node is
//! quarantined and stake is sufficient. It does NOT perform any
//! transition — the coordinator must explicitly approve recovery.
//!
//! ### Duration Tracking
//!
//! `quarantine_duration(now)` returns `Some(elapsed)` if the handler
//! recorded a quarantine start time, computed via `saturating_sub`.
//! Returns `None` if no quarantine was processed through this handler.
//!
//! ### No Implicit Auto-Recovery
//!
//! The handler never transitions the node out of quarantine on its
//! own. Recovery requires an explicit `update_status` call on the
//! tracker (via `tracker_mut()`), followed by `clear_quarantine_metadata`
//! to maintain the state consistency invariant.
//!
//! ## RejoinManager (14B.46)
//!
//! `RejoinManager` handles re-admission after ban expiry or quarantine
//! recovery. It evaluates eligibility, builds re-join requests, and
//! applies coordinator responses to the local status tracker.
//!
//! ```text
//! ┌──────────────────────────────────────────────────────┐
//! │               RejoinManager                           │
//! │  Arc<NodeIdentityManager>                            │
//! │  Arc<TLSCertManager>                                 │
//! │  Arc<Mutex<NodeStatusTracker>>                       │
//! │                                                      │
//! │  can_rejoin(ts, cooldown?) → bool                    │
//! │  build_rejoin_request(class, challenge, addr)         │
//! │     → Result<JoinRequest, JoinError>                 │
//! │  handle_rejoin_response(resp, ts) → Result           │
//! └──────────────────────────────────────────────────────┘
//! ```
//!
//! ### Initial Join vs Re-Join
//!
//! Both use the same `JoinRequest` format and `JoinRequestBuilder`.
//! The structural difference is zero. The semantic difference:
//! - Initial: fresh node in `Pending`.
//! - Re-join from ban: `Banned → Pending` (cooldown must have expired).
//! - Re-join from quarantine: `Quarantined → Active` (stake restored).
//!
//! ### Ban Expiry
//!
//! `can_rejoin` checks: status == `Banned` AND `cooldown` is `Some`
//! AND `cooldown.is_active(ts)` returns `false`. If no cooldown is
//! provided, banned nodes cannot rejoin (conservative).
//!
//! ### Quarantine Recovery
//!
//! `can_rejoin` checks: status == `Quarantined` AND no active
//! cooldown blocks the attempt. Stake verification is the
//! coordinator's responsibility — the node cannot verify on-chain
//! stake autonomously.
//!
//! ### Determinism
//!
//! `can_rejoin` is a pure read-only function. `build_rejoin_request`
//! produces deterministic output for the same inputs (Ed25519 RFC 8032).
//! `handle_rejoin_response` delegates to `NodeStatusTracker::update_status`
//! which enforces the state machine rules.
//!
//! ### No Implicit State Mutation
//!
//! `can_rejoin` and `build_rejoin_request` do not modify any state.
//! Only `handle_rejoin_response` mutates the tracker, and only if
//! the response is approved AND the transition is legal.
//!
//! ## IdentityStore (14B.47)
//!
//! `IdentityStore` persists and loads the node's Ed25519 secret key,
//! operator address, and TLS fingerprint to a base directory on disk.
//!
//! ```text
//! {base_path}/
//! ├── node_identity.key   # Raw 32-byte Ed25519 secret (0600)
//! ├── operator.addr       # 40-char lowercase hex
//! └── tls.fp              # 64-char lowercase hex
//! ```
//!
//! ### Security Model
//!
//! - `node_identity.key` is written with permission `0600`.
//! - Secret key bytes are never logged or included in error messages.
//! - Writes use `truncate(true)` + `sync_all()` for atomicity.
//! - No JSON, no metadata, no hidden fields.
//!
//! ### Permission Enforcement
//!
//! On Unix, `set_permissions(0o600)` is called after writing the key
//! file. If permission setting fails, the error is propagated. On
//! non-Unix platforms, permission enforcement is delegated to the
//! OS-specific ACL layer.
//!
//! ### Identity Corruption Handling
//!
//! `load_or_generate` validates that the stored operator address
//! matches the one derived from the loaded keypair. If they diverge,
//! `PersistenceError::Corruption` is returned. No silent regeneration.
//!
//! ### Deterministic Restart
//!
//! Given an intact `node_identity.key`, the same `NodeIdentityManager`
//! is reconstructed on every restart. Same secret → same `node_id`,
//! same `operator_address`, same signing behavior.
//!
//! ## Health Reporting Extension (14B.48)
//!
//! `NodeHealth` is extended with 7 optional identity/gating fields:
//! `node_id_hex`, `operator_address_hex`, `node_class`, `gating_status`,
//! `tls_valid`, `tls_expires_at`, `staked_amount`.
//!
//! ### Backward Compatibility
//!
//! All new fields are `Option<T>` with `#[serde(default, skip_serializing_if)]`.
//! When absent, they are omitted from JSON. Old consumers that parse the
//! response are unaffected. Old JSON without these fields deserializes
//! correctly (fields default to `None`).
//!
//! ### Identity Visibility
//!
//! `health_endpoint_extended` accepts optional `NodeIdentityManager`,
//! `TLSCertManager`, `NodeStatus`, `NodeClass`, and stake amount.
//! Only public identity information is exposed (Ed25519 public key,
//! operator address). Secret key material is never accessed.
//!
//! ### Security Consideration
//!
//! The `node_id_hex` field exposes the Ed25519 public key. This is
//! intentional — the public key is already transmitted during admission
//! and is not sensitive. The secret key is never exposed via any
//! health reporting path.
//!
//! ## Status Notification Handler (14B.49)
//!
//! [`StatusNotificationHandler`] is the single entry point for all
//! coordinator-originated status lifecycle updates on the node.
//!
//! ### Event-Driven Lifecycle
//!
//! Status changes arrive via two channels:
//! - **Direct notifications** (`StatusNotification`) processed by `handle()`.
//! - **DA gating events** (`GatingEvent`) processed by `process_da_gating_events()`.
//!
//! ### DA Integration
//!
//! `process_da_gating_events` filters events by hex-encoded `node_id`,
//! maps relevant events to notifications, and applies them sequentially.
//! Events targeting other nodes are silently skipped. `NodeRejected`
//! and `NodeBanExpired` events are not processed (informational only).
//!
//! ### Deterministic State Transition
//!
//! Same tracker state + same notifications → same transitions.
//! No randomness. No implicit timestamps. Quarantine transitions
//! are delegated to `QuarantineHandler` for validation. All other
//! transitions go through `NodeStatusTracker::update_status`.
//!
//! ### Safety Invariants
//!
//! - No `panic!`, `unwrap()`, `expect()` in production code.
//! - Mutex is locked only for the duration of each transition.
//! - On error, no state is changed (atomic: success or no-op).
//! - Quarantine metadata is cleared on transition away from Quarantined.
//!
//! # Reward Pipeline (14C.B.13–14C.B.19)
//!
//! The node implements a complete reward pipeline from workload execution
//! through on-chain reward claiming. The pipeline is composed of six
//! independent modules coordinated by [`RewardOrchestrator`].
//!
//! ## Pipeline ASCII Diagram
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                    REWARD PIPELINE                       │
//! │                                                          │
//! │  WorkloadAssignment                                      │
//! │       │                                                  │
//! │       ▼                                                  │
//! │  WorkloadExecutor ── runtime_wasm / runtime_vm           │
//! │       │                                                  │
//! │       ▼                                                  │
//! │  ExecutionCommitment (compute only)                      │
//! │  UnifiedResourceUsage                                    │
//! │       │                                                  │
//! │       ▼                                                  │
//! │  UsageProofBuilder ── Ed25519 sign                       │
//! │       │                                                  │
//! │       ▼                                                  │
//! │  CoordinatorSubmitter ── ReceiptRequest                  │
//! │       │                                                  │
//! │       ▼                                                  │
//! │  ReceiptHandler ── validate + store                      │
//! │       │                                                  │
//! │       ▼                                                  │
//! │  ChainSubmitter ── ClaimReward tx                        │
//! │       │                                                  │
//! │       ▼                                                  │
//! │  RewardOrchestrator ── full pipeline glue                │
//! └─────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Cross-Crate Dependency Diagram
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────┐
//! │                    node crate                               │
//! │                                                             │
//! │  WorkloadExecutor ──┬── dsdn_runtime_wasm (internal crate) │
//! │                     └── dsdn_runtime_vm  (internal crate)  │
//! │                                                             │
//! │  UsageProofBuilder ──── dsdn_common::coordinator::WorkloadId│
//! │                         ed25519-dalek, sha3                 │
//! │                                                             │
//! │  CoordinatorSubmitter ── async-trait                        │
//! │       │                  dsdn_common::receipt_v1_convert    │
//! │       │                                                     │
//! │  ReceiptHandler ──────── dsdn_common::receipt_v1_convert   │
//! │                          dsdn_common::ExecutionCommitment  │
//! │                                                             │
//! │  ChainSubmitter ───────── async-trait                       │
//! │                           dsdn_common::receipt_v1_convert  │
//! │                                                             │
//! │  RewardOrchestrator ──── (all above, no external deps)     │
//! └────────────────────────────────────────────────────────────┘
//!          │                              │
//!          ▼                              ▼
//!  ┌──────────────────┐    ┌────────────────────────┐
//!  │ Coordinator       │    │ Chain                   │
//!  │ (external system) │    │ (external system)       │
//!  │                   │    │                          │
//!  │ Receives:         │    │ Receives:                │
//!  │  ReceiptRequest   │    │  ClaimRewardRequest      │
//!  │                   │    │                          │
//!  │ Returns:          │    │ Returns:                 │
//!  │  ReceiptResponse  │    │  ClaimRewardResponse     │
//!  │  {Signed|Rejected │    │  {Success|Rejected       │
//!  │   |Pending}       │    │   |ChallengePeriod}     │
//!  └──────────────────┘    └────────────────────────┘
//! ```
//!
//! **Internal crates**: `dsdn_runtime_wasm`, `dsdn_runtime_vm`, `dsdn_common`
//! are compiled as Cargo workspace members. **External systems**: Coordinator
//! and Chain are accessed only via trait-abstracted transports
//! ([`CoordinatorTransport`], [`ChainTransport`]). The node never makes
//! direct network calls — all I/O is behind trait objects.
//!
//! ## Storage vs Compute Flow Comparison
//!
//! ```text
//! COMPUTE (WASM/VM)                     STORAGE
//! ─────────────────                     ───────
//! WorkloadAssignment                    WorkloadAssignment
//!      │                                     │
//!      ▼                                     ▼
//! WorkloadExecutor                      WorkloadExecutor
//!   ├─ WASM: run_wasm_committed()         └─ No runtime call
//!   └─ VM: RuntimeNotAvailable (V1)         commitment = None
//!      │                                     resource_usage = zeros
//!      ▼                                     │
//! ExecutionCommitment (Some)                 ▼
//! UnifiedResourceUsage (nonzero)        UsageProofBuilder
//!      │                                  (cpu_cycles=0, ram_bytes=0,
//!      ▼                                   chunk_count, bandwidth_bytes
//! UsageProofBuilder                        from parameters)
//!      │                                     │
//!      ▼                                     ▼
//! ReceiptRequest                        ReceiptRequest
//!   execution_commitment: Some(...)       execution_commitment: None
//!   workload_type: ComputeWasm/Vm         workload_type: Storage
//!      │                                     │
//!      └─────────────┬───────────────────────┘
//!                     ▼
//!              (same pipeline)
//!         Coordinator → Receipt → Chain
//! ```
//!
//! Key differences:
//!
//! - **Compute**: Produces `ExecutionCommitment` with state/input/output
//!   hashes for fraud-proof verification. Resource metrics reflect actual
//!   CPU/memory consumption.
//! - **Storage**: No runtime execution. `ExecutionCommitment` is `None`.
//!   Resource metrics are zero except `chunk_count` and `bandwidth_bytes`
//!   which are provided by the caller.
//! - **`process_storage_workload()`**: Dedicated method on
//!   [`RewardOrchestrator`] that skips `WorkloadExecutor` entirely and
//!   constructs `UnifiedResourceUsage` directly from parameters.
//!
//! ## Relationship to Coordinator Pipeline (CO.1–CO.9)
//!
//! The node and coordinator have complementary but separate roles:
//!
//! ```text
//! NODE (this crate)              COORDINATOR (coordinator crate)
//! ─────────────────              ────────────────────────────────
//! Builds UsageProof        ───►  verify_usage_proof()
//!   (Ed25519 sign)                 (Ed25519 verify)
//!                                  (signing message byte-identical)
//!
//! Sends ReceiptRequest     ───►  Validates proof + commitment
//!   (proof + commitment)           Signs ReceiptV1Proto
//!                                  Returns Signed/Rejected/Pending
//!
//! Receives ReceiptV1Proto  ◄───  Coordinator-signed receipt
//!   Stores in ReceiptHandler       (threshold signature)
//!
//! Submits to Chain         ───►  Chain verifies receipt
//!   (ClaimRewardRequest)           Distributes reward
//! ```
//!
//! **Node does NOT**:
//!
//! - Verify its own usage proofs (the coordinator does this).
//! - Validate the coordinator's threshold signature (the chain does this).
//! - Determine reward amounts (the chain calculates from `reward_base`).
//! - Retry failed submissions (the orchestration caller decides).
//!
//! **Signing message byte-identity**: The 148-byte signing message built by
//! `UsageProofBuilder::build_usage_proof()` MUST be byte-identical to
//! `build_signing_message()` in `coordinator/execution/usage_verifier.rs`.
//! Domain: `b"DSDN:usage_proof:v1:"` (20 bytes), followed by workload_id (32),
//! node_id (32), cpu_cycles LE (8), ram_bytes LE (8), chunk_count LE (8),
//! bandwidth_bytes LE (8), SHA3-256(proof_data) (32). Total: 148 bytes.
//!
//! ## Determinism Guarantees
//!
//! The reward pipeline is designed to be fully deterministic:
//!
//! 1. **ExecutionCommitment**: For WASM workloads, `run_wasm_committed()`
//!    produces deterministic state/input/output hashes. Same module + same
//!    input = same commitment. VM committed execution is V2.
//!
//! 2. **UsageProof signing**: Ed25519 signatures are deterministic (RFC 8032).
//!    Same keypair + same 148-byte message = same 64-byte signature.
//!    Verified by integration test `determinism_same_input_same_proof_10x`.
//!
//! 3. **No implicit retry**: Every pipeline method performs exactly one
//!    attempt. `RewardOrchestrator` delegates errors immediately.
//!    Retry policy belongs to the caller.
//!
//! 4. **No randomness**: No random number generation anywhere in the
//!    pipeline. Mock transports return responses in FIFO order.
//!
//! 5. **No timestamp injection**: All timestamps are caller-provided
//!    parameters (`timestamp: u64`). The pipeline never calls
//!    `SystemTime::now()` or any clock source.
//!
//! 6. **Explicit state transitions**: Receipt status changes only via
//!    `ReceiptHandler::update_status()` with a caller-specified new status.
//!    Status is only updated AFTER successful chain response — if chain
//!    submission fails, the receipt remains in `Validated` status.
//!
//! 7. **Deterministic ordering**: `ReceiptHandler::pending_submission()`
//!    sorts results by `received_at` ascending, regardless of HashMap
//!    iteration order.
//!
//! ## Pipeline Module Details
//!
//! ### WorkloadExecutor — Runtime Dispatch (14C.B.13)
//!
//! [`WorkloadExecutor`] is a stateless dispatcher that routes
//! [`WorkloadAssignment`] to the appropriate runtime backend:
//!
//! ```text
//! WorkloadAssignment
//!      │
//!      ├─ Storage ────► No execution, commitment = None
//!      ├─ ComputeWasm ► runtime_wasm::run_wasm_committed() → ExecutionCommitment
//!      └─ ComputeVm ──► runtime_vm::exec_committed() (V2, RuntimeNotAvailable in V1)
//!      │
//!      ▼
//! ExecutionOutput { commitment, resource_usage, stdout }
//! ```
//!
//! `WorkloadExecutor` holds no state. All inputs come from `WorkloadAssignment`.
//! Runtime errors are mapped to `ExecutionError` variants (`WasmError`,
//! `VmError`, `RuntimeNotAvailable`, `InvalidWorkloadType`).
//!
//! ### UsageProofBuilder — Signed Resource Attestation (14C.B.14)
//!
//! [`UsageProofBuilder`] constructs signed [`UsageProof`] instances that
//! the coordinator's `verify_usage_proof` can verify:
//!
//! ```text
//! UnifiedResourceUsage + WorkloadId + proof_data
//!      │
//!      ▼
//! UsageProofBuilder::build_usage_proof()
//!      │
//!      ├─ Map fields (cpu_cycles_estimate → cpu_cycles, etc.)
//!      ├─ Build 148-byte signing message (domain + fields + SHA3-256)
//!      └─ Sign with Ed25519
//!      │
//!      ▼
//! UsageProof { ..., node_signature: [u8; 64] }
//! ```
//!
//! ### CoordinatorSubmitter — Receipt Submission Client (14C.B.15)
//!
//! [`CoordinatorSubmitter`] sends a [`ReceiptRequest`] to the coordinator
//! via a [`CoordinatorTransport`] trait object:
//!
//! ```text
//! ReceiptRequest { usage_proof, execution_commitment, workload_type }
//!      │
//!      ▼
//! dyn CoordinatorTransport
//!      │
//!      ▼
//! ReceiptResponse { Signed(ReceiptV1Proto) | Rejected | Pending }
//! ```
//!
//! [`MockCoordinatorTransport`] provides FIFO response queue for testing.
//!
//! ### ReceiptHandler — Receipt Storage & Lifecycle (14C.B.16)
//!
//! [`ReceiptHandler`] receives coordinator-signed [`ReceiptV1Proto`],
//! performs structural validation, and manages lifecycle:
//!
//! ```text
//! ReceiptV1Proto → handle_receipt() → StoredReceipt { Validated }
//!                                          │
//!                     update_status() ◄─────┘
//!                          │
//!      ┌───────────────────┼───────────────────┐
//!      ▼                   ▼                   ▼
//! SubmittedToChain  InChallengePeriod    Rejected
//!      │                   │
//!      ▼                   ▼
//!              Confirmed { reward_amount }
//! ```
//!
//! ### ChainSubmitter — On-Chain Reward Claim (14C.B.17)
//!
//! [`ChainSubmitter`] submits [`ClaimRewardRequest`] to the blockchain
//! via a [`ChainTransport`] trait object:
//!
//! ```text
//! ReceiptV1Proto + submitter_address → ChainSubmitter::submit_claim()
//!      │
//!      ▼
//! ClaimRewardResponse { Success | Rejected | ChallengePeriod }
//! ```
//!
//! [`MockChainTransport`] provides FIFO response queue for testing.
//!
//! ### RewardOrchestrator — Full Pipeline Glue (14C.B.18)
//!
//! [`RewardOrchestrator`] integrates all subsystems into a single
//! sequential pipeline:
//!
//! ```text
//! execute → proof → coordinator → receipt → chain → status update
//! ```
//!
//! The orchestrator does NOT perform cryptography, retry, or network I/O.
//! State consistency: receipt status is only updated after chain response.
//! If chain submission fails, receipt remains `Validated`.
//!
//! ## Integration Test Coverage (14C.B.19)
//!
//! `tests/reward_pipeline_tests.rs` provides 20 end-to-end tests:
//!
//! | Category | Tests |
//! |----------|-------|
//! | Full pipeline success | Storage (both methods), sequential multi-workload |
//! | Compute errors | WASM empty module, VM not available |
//! | Coordinator handling | Signed, Rejected, Pending (skips chain) |
//! | Chain handling | Success→Confirmed, Rejected→Rejected, ChallengePeriod |
//! | Atomicity | Chain fail → receipt stays Validated |
//! | Crypto verification | Ed25519 verify_strict on usage proof |
//! | Receipt lifecycle | Duplicate rejection, status transitions |
//! | Error propagation | Timeout, network error, all Display variants |
//! | Determinism | 10x identical inputs → identical signatures |
//! | Differentiation | Storage zero compute metrics vs compute |
//!
//! All tests use `MockCoordinatorTransport` and `MockChainTransport`.
//! Zero network, zero sleep, zero randomness.
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
//!
//! 5. **Reward Pipeline Atomicity**: Receipt status is updated only after
//!    successful chain response. Chain failure leaves receipt in `Validated`.
//!    No partial updates, no double-confirm.
//!
//! 6. **Signing Message Byte-Identity**: The 148-byte usage proof signing
//!    message built by the node MUST be byte-identical to the coordinator's
//!    verification message. Any divergence breaks consensus.

pub mod da_follower;
pub mod delete_handler;
pub mod event_processor;
pub mod handlers;
pub mod health;
pub mod identity_manager;
pub mod identity_persistence;
pub mod join_request;
pub mod metrics;
pub mod multi_da_source;
pub mod placement_verifier;
pub mod quarantine_handler;
pub mod rejoin_manager;
pub mod state_sync;
pub mod status_notification;
pub mod status_tracker;
pub mod tls_manager;
pub mod workload_executor;
pub mod usage_proof_builder;
pub mod coordinator_client;
pub mod receipt_handler;
pub mod chain_submitter;
pub mod reward_orchestrator;

// Integration tests for Node Identity & Gating (14B.50)
#[cfg(test)]
mod gating_tests;

pub use da_follower::{
    DAFollower, NodeDerivedState, ChunkAssignment, StateError, ReplicaStatus,
    TransitionError, TransitionResult, TRANSITION_TIMEOUT_MS,
};
pub use delete_handler::{DeleteHandler, DeleteError, DeleteRequestedEvent, PendingDelete, Storage};
pub use event_processor::{NodeEventProcessor, NodeAction, ProcessError};
pub use health::{
    NodeHealth, HealthStorage, DAInfo, HealthResponse, health_endpoint,
    health_endpoint_extended,
    DA_LAG_THRESHOLD, FALLBACK_DEGRADATION_THRESHOLD_MS,
};
pub use metrics::NodeFallbackMetrics;
pub use multi_da_source::{MultiDASource, MultiDAConfig, DASourceType};
pub use placement_verifier::{PlacementVerifier, PlacementReport, PlacementDetail, PlacementStatus};
pub use state_sync::{StateSync, ConsistencyReport, SyncError, SyncStorage};

// HTTP API handlers (Axum) - READ-ONLY observability endpoints
pub use handlers::{NodeAppState, build_router};
pub use identity_manager::{NodeIdentityManager, IdentityError};
pub use identity_persistence::{IdentityStore, PersistenceError};
pub use join_request::{JoinRequest, JoinRequestBuilder, JoinResponse, JoinError};
pub use quarantine_handler::QuarantineHandler;
pub use rejoin_manager::RejoinManager;
pub use status_tracker::NodeStatusTracker;
pub use status_notification::{StatusNotificationHandler, StatusNotification};
pub use tls_manager::{TLSCertManager, TLSError};
pub use workload_executor::{
    WorkloadExecutor, WorkloadType, WorkloadAssignment, ResourceLimits,
    ExecutionOutput, UnifiedResourceUsage, ExecutionError,
};
pub use usage_proof_builder::{UsageProofBuilder, UsageProofError, UsageProof};
pub use coordinator_client::{
    CoordinatorSubmitter, CoordinatorTransport, MockCoordinatorTransport,
    ReceiptRequest, ReceiptResponse, SubmitError,
};
pub use receipt_handler::{
    ReceiptHandler, ReceiptStatus, StoredReceipt, ReceiptHandlerError,
};
pub use chain_submitter::{
    ChainSubmitter, ChainTransport, MockChainTransport,
    ClaimRewardRequest, ClaimRewardResponse, ChainSubmitError,
};
pub use reward_orchestrator::{RewardOrchestrator, OrchestratorError};