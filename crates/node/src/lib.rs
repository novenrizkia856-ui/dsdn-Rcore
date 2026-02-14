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
//! | `health`            | Health reporting with fallback awareness and identity extension (14B.48) |
//! | `multi_da_source`   | Multi-DA source abstraction (Primary/Secondary/Emergency) |
//! | `metrics`           | Node fallback metrics for Prometheus export          |
//! | `identity_manager`  | Ed25519 keypair management and identity proof construction (14B.41) |
//! | `identity_persistence`| Secure disk persistence for Ed25519 keys and operator addresses (14B.47) |
//! | `tls_manager`       | TLS certificate loading, generation, and fingerprint computation (14B.42) |
//! | `join_request`      | Join request builder with validation and deterministic proof construction (14B.43) |
//! | `status_tracker`    | Node-side lifecycle state machine with transition validation and audit history (14B.44) |
//! | `quarantine_handler`| Quarantine notification processing, duration tracking, and recovery eligibility (14B.45) |
//! | `rejoin_manager`    | Re-join eligibility, request building, and coordinator response handling (14B.46) |
//! | `status_notification`| Status notification processing, DA gating event handling, and lifecycle transitions (14B.49) |
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