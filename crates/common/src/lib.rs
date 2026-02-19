//! # DSDN Common Crate
//!
//! Crate ini menyediakan abstraksi Data Availability (DA) Layer dan utilities
//! untuk DSDN (Distributed Storage and Data Network).
//!
//! ## Peran Crate
//!
//! `dsdn-common` adalah foundation crate yang menyediakan:
//! - Abstraksi DA Layer untuk multiple backends (Celestia, Validator Quorum, Foundation)
//! - Health monitoring untuk DA endpoints
//! - Routing deterministik dengan fallback hierarchy
//! - Cryptographic utilities
//! - Content addressing (CID)
//! - Configuration management
//! - Multi-coordinator committee management dengan TSS support
//!
//! ## Arsitektur Fallback & DA Routing
//!
//! DSDN menggunakan multi-tier DA architecture untuk high availability:
//!
//! | Tier | DA Layer | Kondisi Penggunaan |
//! |------|----------|-------------------|
//! | Primary | Celestia | Status Healthy/Warning/Recovering |
//! | Secondary | Validator Quorum | Status Degraded (fallback level-1) |
//! | Emergency | Foundation | Status Emergency (fallback level-2) |
//!
//! ### Routing Diagram
//!
//! ```text
//! ┌─────────────────┐
//! │    DARouter     │  <- Routing abstraction
//! └────────┬────────┘
//!          │
//! ┌─────┴─────┬─────────────┐
//! │           │             │
//! ┌──▼──┐    ┌───▼───┐    ┌────▼────┐
//! │Celestia│ │QuorumDA│   │EmergencyDA│
//! │(Primary)│ │(Secondary)│ │(Foundation)│
//! └────────┘ └─────────┘   └───────────┘
//! ```
//!
//! ## Coordinator Committee System
//!
//! DSDN menggunakan committee of coordinators untuk threshold signing.
//! Committee beroperasi dalam epoch-based rotation dengan handoff mechanism.
//!
//! ### Committee Lifecycle
//!
//! ```text
//! Initializing → Active → InHandoff → Active (new epoch)
//!                  ↓           ↓
//!               Expire      Expire
//!                  ↓           ↓
//!               Expired     Expired
//! ```
//!
//! ### Coordinator Types
//!
//! | Type | Description |
//! |------|-------------|
//! | `CoordinatorId` | 32-byte unique identifier |
//! | `CoordinatorMember` | Member dengan pubkey dan stake |
//! | `CoordinatorCommittee` | Committee dengan threshold signing |
//! | `ThresholdReceipt` | Receipt dengan aggregate signature |
//! | `CommitteeTransition` | Epoch rotation dengan handoff |
//! | `CommitteeStatus` | Lifecycle status tracking |
//!
//! ## Komponen Utama
//!
//! ### DAHealthMonitor
//!
//! Thread-safe health monitor yang melacak status DA endpoint.
//! Menyediakan `DAStatus` yang menentukan routing decision.
//!
//! Status yang di-track:
//! - `Healthy`: Primary DA beroperasi normal
//! - `Warning`: Primary DA mengalami latency tinggi
//! - `Degraded`: Primary DA tidak tersedia, gunakan secondary
//! - `Emergency`: Kondisi kritis, gunakan emergency DA
//! - `Recovering`: Primary DA sedang recovery dari degraded/emergency
//!
//! ### DARouter
//!
//! Routing abstraction yang menentukan DA target berdasarkan status kesehatan.
//! Keputusan routing bersifat deterministik berdasarkan `DAStatus` dari
//! `DAStatusProvider` (biasanya `DAHealthMonitor`).
//!
//! Behavior per status:
//! - `Healthy/Warning/Recovering`: Route ke primary (Celestia)
//! - `Degraded`: Route ke secondary, tag blob sebagai `PendingReconcile`
//! - `Emergency`: Route ke emergency, tag blob sebagai `EmergencyPending`
//!
//! ### DALayer Trait
//!
//! Abstraksi untuk DA backend. Implementasi yang tersedia:
//! - `CelestiaDA`: Production implementation untuk Celestia
//! - `MockDA`: Testing implementation
//!
//! ## Usage Patterns
//!
//! ### Basic DA Operations
//!
//! ```rust,ignore
//! use dsdn_common::{DALayer, CelestiaDA};
//!
//! // Initialize DA layer
//! let da = CelestiaDA::from_env()?;
//!
//! // Post blob
//! let blob_ref = da.post_blob(data).await?;
//!
//! // Get blob
//! let blob = da.get_blob(&blob_ref).await?;
//! ```
//!
//! ### Using DARouter with Health Monitoring
//!
//! ```rust,ignore
//! use dsdn_common::{DARouter, DARouterConfig, DARouterMetrics, DAHealthMonitor};
//! use std::sync::Arc;
//!
//! // Setup health monitor sebagai status provider
//! let health_monitor = Arc::new(DAHealthMonitor::new(config));
//!
//! // Setup router dengan fallback hierarchy
//! let metrics = Arc::new(DARouterMetrics::new());
//! let router = DARouter::new(primary_da, health_monitor, DARouterConfig::new(), metrics)
//!     .with_fallbacks(Some(secondary_da), Some(emergency_da));
//!
//! // Router akan memilih DA target berdasarkan status
//! let blob_ref = router.post_blob(data).await?;
//! ```
//!
//! ### Coordinator Committee Operations
//!
//! ```rust,ignore
//! use dsdn_common::{
//!     CoordinatorCommittee, CoordinatorMember, CoordinatorId,
//!     ThresholdReceipt, CommitteeStatus,
//! };
//!
//! // Create committee
//! let committee = CoordinatorCommittee::new(
//!     members, threshold, epoch, epoch_start, duration, group_pubkey
//! )?;
//!
//! // Verify receipt
//! if receipt.verify(&committee) {
//!     // Receipt valid
//! }
//!
//! // Track status
//! let status = CommitteeStatus::active(committee, timestamp);
//! if status.can_accept_receipts() {
//!     // Process receipts
//! }
//! ```
//!
//! ### Fallback Activation
//!
//! Fallback diaktifkan ketika:
//! 1. `DAHealthMonitor` melaporkan status `Degraded` atau `Emergency`
//! 2. `DARouterConfig.enable_fallback` adalah `true` (default)
//! 3. Fallback DA tersedia (dikonfigurasi via `with_fallbacks`)
//!
//! Blob yang ditulis ke fallback akan di-tag untuk reconciliation ketika
//! primary DA kembali sehat.
//!
//! ## Batasan (Non-Goals)
//!
//! Crate ini TIDAK menyediakan:
//! - Automatic reconciliation (hanya tagging, eksekusi di layer lain)
//! - Network transport atau gRPC endpoints
//! - Consensus atau finality guarantees
//! - Persistent storage (in-memory state only)
//! - Rate limiting atau throttling
//!
//! ## Modules
//!
//! | Module | Deskripsi |
//! |--------|-----------|
//! | `da` | DALayer trait definition dan types |
//! | `celestia_da` | Celestia DA implementation |
//! | `mock_da` | Mock implementation for testing |
//! | `da_health_monitor` | Thread-safe DA health monitoring |
//! | `da_router` | DA routing dengan fallback hierarchy |
//! | `crypto` | Cryptographic utilities |
//! | `cid` | Content addressing utilities |
//! | `config` | Configuration management |
//! | `consistent_hash` | Consistent hashing for placement |
//! | `coordinator` | Multi-coordinator committee management dengan TSS |
//! | `gating` | Stake & identity gating system (14B) |
//!
//! ## Gating System (14B)
//!
//! The gating system ensures that only qualified, staked, and identity-verified
//! nodes can participate in the DSDN network. Stake functions purely as a
//! security gate — not as an economic signal or reward multiplier.
//!
//! ### NodeIdentity
//!
//! `NodeIdentity` is the cryptographic identity of a service node, binding three
//! components:
//!
//! - `node_id` ([u8; 32]): Ed25519 public key uniquely identifying the node.
//! - `operator_address` ([u8; 20]): Wallet address of the operator.
//! - `tls_cert_fingerprint` ([u8; 32]): SHA-256 of the DER-encoded TLS certificate.
//!
//! Operator binding is verified via `verify_operator_binding()`, which checks an
//! Ed25519 signature over a deterministic, domain-separated message:
//!
//! ```text
//! message = b"DSDN:operator_binding:v1:" || node_id (32 bytes) || operator_address (20 bytes)
//! ```
//!
//! Verification uses `verify_strict` which rejects weak keys and small-order point
//! components. This prevents identity spoofing: an attacker cannot bind their
//! operator address to a node they do not control.
//!
//! ### NodeClass
//!
//! `NodeClass` classifies a node's role and determines its minimum stake requirement:
//!
//! ```text
//! Class      Min Stake    Role
//! ────────── ───────────  ───────────────────────────────────────
//! Storage    5000 NUSA    Persistent data storage and retrieval
//! Compute     500 NUSA    Computation and processing tasks
//! ```
//!
//! `NodeClass::min_stake()` returns the human-readable NUSA amount.
//! On-chain smallest-unit conversion is handled by `StakeRequirement` (14B.3).
//!
//! ### Stake ↔ Capability Relationship
//!
//! Higher stake requirements for Storage nodes reflect greater data custody
//! responsibility. A Storage node losing or withholding data causes more damage
//! than a Compute node failing a task, hence the 10x stake difference.
//!
//! Stake at this stage does NOT:
//! - Determine reward amounts (economic layer is separate)
//! - Provide governance weight (governance uses quadratic voting)
//! - Enable any capability beyond class membership
//!
//! ### Security Notes
//!
//! - **Operator binding**: Domain-separated, versioned signature prevents
//!   cross-protocol replay attacks. The binding message is explicit and
//!   deterministic with no implicit assumptions about wallet behavior.
//! - **Spoofing resistance**: Node ID spoofing requires the corresponding
//!   Ed25519 private key. Operator address spoofing requires a valid binding
//!   signature from the node's key. TLS spoofing is detected by fingerprint
//!   mismatch (validated in upper layers, 14B.5/14B.23).
//! - **No silent failures**: All verification errors are structured and
//!   propagated. No `panic!`, `unwrap()`, or `expect()` in production code.
//!
//! ### Node Lifecycle & Status Transitions
//!
//! Every service node is in exactly one of four lifecycle states:
//!
//! - **`Pending`**: Newly registered on-chain, awaiting gating verification
//!   (stake check, identity proof, TLS validation). Not schedulable.
//! - **`Active`**: All gating checks have passed. This is the ONLY state
//!   in which a node can be scheduled for workloads by the coordinator.
//! - **`Quarantined`**: Suspended due to stake dropping below the class
//!   minimum or a minor protocol violation. The node retains its registration
//!   but cannot receive new workloads. Recovery to `Active` requires stake
//!   restoration and re-verification — there is no automatic recovery.
//! - **`Banned`**: Permanently removed from the active set due to identity
//!   spoofing or severe slashing. The node must wait for its cooldown period
//!   to expire, then re-register as `Pending`. There is no direct path from
//!   `Banned` to `Active`.
//!
//! The allowed transitions form a **closed set** — only these 7 transitions
//! are permitted:
//!
//! ```text
//! Pending       → Active          (all gating checks pass)
//! Pending       → Banned          (identity spoofing detected)
//! Active        → Quarantined     (stake drop or minor violation)
//! Active        → Banned          (severe slashing event)
//! Quarantined   → Active          (stake restored + re-check pass)
//! Quarantined   → Banned          (further violation while quarantined)
//! Banned        → Pending         (cooldown expired, must re-register)
//! ```
//!
//! All other transitions are rejected. Self-transitions (e.g., `Active → Active`)
//! are forbidden. There are no implicit re-activation paths — a `Banned` node
//! must always pass through `Pending` before becoming `Active` again.
//!
//! ### Stake Requirements & Class Gating
//!
//! Every service node must hold a minimum stake (in smallest on-chain units,
//! 18 decimals) to participate. The required amount depends on the node's class:
//!
//! ```text
//! Class       Human-Readable    On-Chain (18 decimals)
//! ─────────── ───────────────── ──────────────────────────────
//! Storage     5000 NUSA         5_000_000_000_000_000_000_000
//! Compute      500 NUSA           500_000_000_000_000_000_000
//! ```
//!
//! `StakeRequirement` holds these thresholds and provides two operations:
//!
//! - **`check(class, actual_stake)`**: Validates that a stake amount meets
//!   the minimum for a specific class. Returns `Ok(())` or a structured
//!   `StakeError`. Zero stake is always rejected (`StakeError::ZeroStake`),
//!   even before checking class minimums.
//!
//! - **`classify_by_stake(stake)`**: Determines the highest class a stake
//!   qualifies for. Storage is checked first (highest), then Compute. Zero
//!   stake and amounts below all minimums return `None`.
//!
//! Both methods are pure functions — deterministic, no side effects, no
//! external configuration. Stake verification does NOT automatically trigger
//! status transitions; callers decide how to act on the result.
//!
//! ### Slashing Cooldown
//!
//! After a node is banned, a cooldown period prevents immediate re-registration.
//! The cooldown duration depends on the severity of the offense:
//!
//! ```text
//! Severity    Duration        Seconds
//! ─────────── ─────────────── ────────
//! Default     24 hours        86,400
//! Severe      7 days          604,800
//! ```
//!
//! `CooldownPeriod` tracks the start time, duration, and reason for each
//! cooldown. All time queries (`is_active`, `remaining_secs`, `expires_at`)
//! are pure functions that take a `current_timestamp` parameter — there is
//! no system clock access or non-deterministic time source.
//!
//! `CooldownConfig` holds the default and severe durations, and provides
//! `create_cooldown(severe, timestamp, reason)` to construct a new
//! `CooldownPeriod` with the appropriate duration.
//!
//! `CooldownStatus` is a data enum with three states: `NoCooldown`,
//! `InCooldown(CooldownPeriod)`, and `Expired(CooldownPeriod)`. It does
//! NOT trigger status transitions — the caller must explicitly transition
//! `Banned → Pending` after verifying that the cooldown has expired.
//! Cooldown expiry does NOT mean automatic re-activation; the node must
//! still pass all gating checks to become `Active`.
//!
//! ### TLS Certificate Validation
//!
//! Each node's TLS certificate is bound to its [`NodeIdentity`] via the
//! SHA-256 fingerprint of the DER-encoded certificate. This binding
//! prevents MITM attacks and certificate spoofing — a node cannot
//! impersonate another by presenting a different certificate.
//!
//! `TLSCertInfo` captures pre-extracted certificate metadata: the SHA-256
//! fingerprint, subject Common Name, issuer, and the validity window
//! (`not_before` / `not_after` as Unix timestamps). It provides:
//!
//! - **`is_valid_at(timestamp)`**: Returns `true` when
//!   `not_before <= timestamp <= not_after` (both inclusive).
//! - **`is_expired(timestamp)`**: Returns `true` when
//!   `timestamp > not_after` (strictly past the end).
//! - **`compute_fingerprint(der_bytes)`**: Computes SHA-256 over raw
//!   DER certificate bytes. Pure function, deterministic.
//! - **`matches_identity(identity)`**: Strict 32-byte comparison of
//!   the certificate fingerprint against `NodeIdentity.tls_cert_fingerprint`.
//!   No fallback to subject CN or issuer.
//!
//! This module does NOT perform full X.509 parsing or ASN.1 decoding —
//! that is the transport layer's responsibility. All time checks are
//! based on caller-provided timestamps with no system clock access.
//! A valid TLS certificate does NOT automatically make a node Active;
//! it is one of several gating checks that must all pass.
//!
//! ### Gating Errors
//!
//! `GatingError` is the public error contract for all admission and
//! gating operations. Each variant represents a specific, non-overlapping
//! failure condition. Error messages are deterministic, operator-friendly,
//! and suitable for logging and monitoring dashboards.
//!
//! Error categories:
//!
//! - **Stake errors**: `InsufficientStake` (non-zero but below minimum),
//!   `ZeroStake` (exactly zero, always rejected first).
//! - **Cooldown errors**: `SlashingCooldownActive` (node still in
//!   cooldown after slashing, includes remaining seconds and reason).
//! - **TLS errors**: `TLSInvalid` (wraps a `TLSValidationError` with
//!   the specific certificate failure reason).
//! - **Identity errors**: `IdentityMismatch` (node ID does not match
//!   operator binding), `IdentityVerificationFailed` (signature or
//!   other identity check failure with reason string).
//! - **Status errors**: `NodeBanned` (banned until a specific timestamp),
//!   `NodeQuarantined` (quarantined with reason), `NodeNotRegistered`.
//! - **Class errors**: `InvalidNodeClass` (unrecognized class value).
//!
//! `GatingError` implements `Clone`, `Debug`, `PartialEq`, `Eq`,
//! `Serialize`, `Deserialize`, `Display`, and `std::error::Error`.
//! No `thiserror`, `anyhow`, or implicit error wrapping is used.
//!
//! ### Gating Policy
//!
//! `GatingPolicy` is the single source of truth for all gating
//! configuration. It combines stake thresholds, cooldown durations,
//! TLS requirements, identity proof requirements, and scheduling rules
//! into one validated configuration object.
//!
//! Two presets are provided:
//!
//! - **`default()`** (production): All security checks enabled
//!   (`require_tls = true`, `require_identity_proof = true`),
//!   standard stake thresholds and cooldown durations, pending
//!   scheduling disabled.
//! - **`permissive()`** (testing only): All checks disabled, zero
//!   stake thresholds, zero cooldown durations, pending scheduling
//!   allowed.
//!
//! `validate()` must be called before using a policy in the admission
//! engine. It detects internal contradictions such as inverted stake
//! hierarchies (compute minimum exceeding storage minimum) and zero
//! stake thresholds combined with enabled security checks. The policy
//! affects both admission decisions and scheduling eligibility.
//!
//! ### Gating Decision & Report
//!
//! `GatingDecision` is the final output of a gating evaluation:
//! `Approved` if the node passed all checks, or `Rejected` with a
//! `Vec<GatingError>` containing every failure reason in evaluation
//! order. The `errors()` method returns a borrowed slice — no
//! allocation occurs for `Approved` (returns `&[]`).
//!
//! `CheckResult` records the outcome of a single gating check:
//! a descriptive name (e.g., `"stake_check"`, `"tls_validation"`),
//! a `passed` flag, and an optional `detail` string for diagnostics.
//!
//! `GatingReport` is the full audit trail of an evaluation: the
//! evaluated node's identity, the final decision, an ordered list
//! of check results, the evaluation timestamp (caller-provided,
//! not system clock), and the evaluator identifier (e.g.,
//! `"coordinator"`, `"scheduler"`, `"cli"`). The `summary()` method
//! returns a single-line human-readable string. The `to_json()`
//! method serializes the entire report via `serde_json`.
//!
//! All decision and report types are deterministic, serializable,
//! and implement `Clone`, `Debug`, `PartialEq`, and `Eq`. No errors
//! are filtered, merged, or reordered. Checks are stored in the
//! order provided by the caller.
//!
//! ### Node Registry & Identity Challenge
//!
//! `NodeRegistryEntry` is the single source of truth for a node's
//! current state in the gating system. It combines identity, class,
//! status, stake, timestamps, cooldown, and TLS metadata into one
//! record. The `is_eligible_for_scheduling(now)` method performs a
//! deterministic eligibility check: the node must be `Active`, have
//! stake at or above `NodeClass::min_stake()`, and have no active
//! cooldown at the given timestamp. TLS and identity proof are NOT
//! checked in this method — they are separate gating steps.
//!
//! `IdentityChallenge` represents a challenge nonce issued to a node
//! to prove ownership of its Ed25519 private key. The challenger
//! generates the nonce externally; this module never generates nonces.
//!
//! `IdentityProof` contains the challenge, the Ed25519 signature over
//! the raw nonce bytes (no prefix, no suffix, no domain separator),
//! and the node identity. The `verify()` method uses
//! `ed25519_dalek::VerifyingKey::verify_strict` to perform cofactored
//! verification that rejects weak keys and non-canonical signatures.
//! All crypto failures return `false` — no panics.
//!
//! ### Architecture Overview
//!
//! The gating system is a pipeline of deterministic checks. Each check
//! is independent, stateless, and produces explicit pass/fail results.
//! No check relies on the outcome of another. The evaluation flow is:
//!
//! ```text
//!                ┌─────────────────┐
//!                │  NodeIdentity   │  Ed25519 key + operator wallet + TLS fingerprint
//!                └────────┬────────┘
//!                         │
//!                ┌────────▼────────┐
//!                │NodeRegistryEntry│  class, status, stake, cooldown, tls_info
//!                └────────┬────────┘
//!                         │
//!           ┌─────────────┼─────────────┐
//!           │             │             │
//!    ┌──────▼──────┐ ┌───▼───┐  ┌──────▼──────┐
//!    │StakeRequire.│ │  TLS  │  │  Cooldown   │
//!    │  .check()   │ │ valid │  │ .is_active()│
//!    └──────┬──────┘ └───┬───┘  └──────┬──────┘
//!           │            │             │
//!           └─────────┬──┴─────────────┘
//!                     │
//!              ┌──────▼──────┐
//!              │IdentityProof│  challenge–response (Ed25519 over raw nonce)
//!              │  .verify()  │
//!              └──────┬──────┘
//!                     │
//!              ┌──────▼──────┐
//!              │GatingPolicy │  combined thresholds and feature flags
//!              │ .validate() │
//!              └──────┬──────┘
//!                     │
//!              ┌──────▼──────┐
//!              │GatingDecision│  Approved │ Rejected(Vec<GatingError>)
//!              └──────┬──────┘
//!                     │
//!              ┌──────▼──────┐
//!              │ GatingReport │  audit trail: identity, decision, checks, timestamp
//!              └─────────────┘
//! ```
//!
//! ### Type Catalog (14B.1 — 14B.9)
//!
//! | Type | Module | Primary Invariant |
//! |------|--------|-------------------|
//! | `NodeIdentity` | identity | 32-byte Ed25519 key + 20-byte wallet + 32-byte TLS fingerprint |
//! | `NodeClass` | identity | Storage (5000 NUSA) or Compute (500 NUSA); min_stake() is authoritative |
//! | `IdentityError` | identity | Structured Ed25519 verification errors, no panic |
//! | `NodeStatus` | node_status | Exactly one of: Pending, Active, Quarantined, Banned |
//! | `StatusTransition` | node_status | Records from/to/timestamp; only 7 valid transitions |
//! | `StakeRequirement` | stake | 18-decimal on-chain unit thresholds; check() returns ZeroStake or InsufficientStake |
//! | `StakeError` | stake | ZeroStake always checked first; InsufficientStake includes required/actual/class |
//! | `CooldownPeriod` | cooldown | start + duration → expires_at(); is_active(now) is authoritative |
//! | `CooldownConfig` | cooldown | Default 24h, severe 7d; create_cooldown() is the only constructor |
//! | `CooldownStatus` | cooldown | NoCooldown, InCooldown, Expired — no automatic transition |
//! | `TLSCertInfo` | tls | SHA-256 fingerprint; is_valid_at() checks not_before ≤ t ≤ not_after |
//! | `TLSValidationError` | tls | Structured TLS validation errors, no X.509 parsing |
//! | `GatingError` | error | Non-overlapping error variants covering all gating failures |
//! | `GatingPolicy` | policy | Combined config; validate() detects contradictions before use |
//! | `GatingDecision` | decision | Approved or Rejected(errors); errors() returns &[] for Approved |
//! | `CheckResult` | decision | check_name + passed + optional detail for each individual check |
//! | `GatingReport` | decision | Full audit: identity, decision, ordered checks, timestamp, evaluator |
//! | `NodeRegistryEntry` | registry_entry | Single source of truth; is_eligible checks status + stake + cooldown |
//! | `IdentityChallenge` | challenge | Opaque 32-byte nonce + timestamp + challenger string |
//! | `IdentityProof` | challenge | Ed25519 verify_strict over raw nonce; all failures return false |
//!
//! ### Usage Flow
//!
//! A typical gating evaluation follows these steps:
//!
//! 1. **Identity creation**: A node registers with an Ed25519 key,
//!    operator wallet, and TLS certificate fingerprint, forming a
//!    `NodeIdentity`.
//!
//! 2. **Registry entry**: The coordinator creates a `NodeRegistryEntry`
//!    with the node's identity, class, initial status (`Pending`),
//!    and on-chain stake amount.
//!
//! 3. **Policy evaluation**: A `GatingPolicy` defines the thresholds.
//!    `validate()` is called to detect contradictions before use.
//!
//! 4. **Check execution**: Each check (stake, TLS, cooldown, identity
//!    proof) runs independently and produces a `CheckResult`. Failed
//!    checks produce `GatingError` values.
//!
//! 5. **Decision**: If all checks pass → `GatingDecision::Approved`.
//!    If any fail → `GatingDecision::Rejected(errors)`. Errors are
//!    never filtered or merged.
//!
//! 6. **Report**: A `GatingReport` captures the full evaluation:
//!    identity, decision, ordered checks, caller-provided timestamp,
//!    and evaluator string. `to_json()` serializes for audit.
//!    `summary()` returns a single-line human-readable result.
//!
//! All steps are deterministic. No system clock is accessed internally.
//! No implicit trust is granted. A valid identity proof only confirms
//! private key possession — it does not bypass stake or TLS checks.
//!
//! ## Economic Flow V1 (C.1 — C.9)
//!
//! The economic flow defines how service nodes earn rewards for work performed.
//! Every reward claim follows a strict pipeline that ensures correctness,
//! prevents self-dealing, and enforces single-claim semantics.
//!
//! ### Pipeline
//!
//! ```text
//! Node performs work
//!     │
//!     ▼
//! ReceiptV1 created (Storage or Compute)
//!     │
//!     ├── coordinator_threshold_signature (FROST aggregate)
//!     ├── node_signature (Ed25519)
//!     └── submitter_address (20-byte wallet)
//!     │
//!     ▼
//! ClaimReward transaction submitted
//!     │
//!     ▼
//! Validation pipeline:
//!     ├── receipt_dedup: reject if receipt_hash already claimed
//!     ├── anti_self_dealing: detect node_addr == submitter_addr
//!     ├── signature verification (coordinator + node)
//!     ├── receipt_expired check (MAX_RECEIPT_AGE_SECS = 86400)
//!     └── reward_base range check
//!     │
//!     ▼
//! ┌────────────────────────────────────────────────┐
//! │ Storage path              │ Compute path       │
//! │ ImmediateReward           │ ChallengePeriodStart│
//! │ 70% node / 20% val / 10% │ PendingChallenge    │
//! │ treasury                  │ (3600s window)      │
//! │                           │     │               │
//! │                           │     ├─ no fraud ──▶ Cleared → 70/20/10 │
//! │                           │     └─ fraud ────▶ Challenged → Slashed│
//! └────────────────────────────────────────────────┘
//! ```
//!
//! ### Reward Distribution
//!
//! Normal split: 70% node, 20% validator, 10% treasury.
//! Anti-self-dealing split: 0% node, 20% validator, 80% treasury.
//! Integer division with remainder allocated to treasury.
//!
//! ### Hash Canonicalization
//!
//! Two hash algorithms exist for `ReceiptV1`:
//!
//! - **Native hash** (`ReceiptV1::compute_receipt_hash`): feeds raw
//!   `coordinator_threshold_signature` bytes and concatenated `signer_ids`
//!   directly into SHA3-256. Used for internal dedup and state tracking.
//!
//! - **Proto hash** (`compute_receipt_hash_from_proto`): computes a 32-byte
//!   `aggregate_signature_hash` from the full `AggregateSignatureProto`
//!   (including `message_hash` and `aggregated_at`), then feeds that digest
//!   into the receipt hash. Used for cross-layer (DA ↔ chain) verification.
//!
//! The bridge function `compute_receipt_hash_proto_compatible` computes the
//! proto hash from native data plus the original `AggregateSignatureProto`,
//! enabling: `proto_hash == native_proto_compatible_hash`.
//!
//! ### Proto ↔ Native Boundary
//!
//! Proto types are the wire format transmitted via Celestia DA layer.
//! Native types are validated, typed representations used in chain logic.
//! Conversion is via `from_proto()` / `to_proto()` on each type.
//!
//! Lossy field: `AggregateSignatureProto.message_hash` and `.aggregated_at`
//! are not stored in native `ReceiptV1`. `to_proto()` sets these to zero.
//! Hash consistency is maintained via `compute_receipt_hash_proto_compatible`.
//!
//! ### Dedup Tracking
//!
//! `ReceiptDedupTracker` is a `HashSet<[u8; 32]>` that records claimed
//! receipt hashes. `mark_claimed()` returns `ReceiptAlreadyClaimed` error
//! on duplicate. `prune_before()` removes specified hashes for garbage
//! collection across epoch boundaries.
//!
//! ### Module Catalog (C.1 — C.9)
//!
//! | Module | Task | Description |
//! |--------|------|-------------|
//! | `execution_commitment` | C.1 | 6-field commitment with SHA3-256 hash |
//! | `receipt_v1` | C.2 | ReceiptV1 with Storage/Compute variants |
//! | `economic_constants` | C.3 | Reward percentages, time limits, boundaries |
//! | `anti_self_dealing` | C.4 | Direct match + owner match detection |
//! | `receipt_hash` | C.5 | Standalone hash functions for receipt/EC/claim |
//! | `claim_validation` | C.6 | RewardDistribution + ClaimValidationResult |
//! | `challenge_state` | C.7 | PendingChallenge state machine |
//! | `receipt_dedup` | C.8 | HashSet-based duplicate tracker |
//! | `receipt_v1_convert` | C.9 | Proto ↔ Native conversion + hash bridge |

// ════════════════════════════════════════════════════════════════════════════════
// MODULE DECLARATIONS
// ════════════════════════════════════════════════════════════════════════════════

// Core utilities
pub mod crypto;
pub mod cid;
pub mod config;
pub mod consistent_hash;

// DA Layer abstraction
pub mod da;
pub mod celestia_da;
pub mod mock_da;

// DA Health & Routing (14A.1A.11 - 14A.1A.19)
pub mod da_health_monitor;
pub mod da_router;

// Coordinator types (14A.2B.1.11)
pub mod coordinator;

// Gating system (14B)
pub mod gating;

// Execution commitment native type (C.1)
pub mod execution_commitment;

// Receipt V1 native type (C.2)
pub mod receipt_v1;

// Economic constants & challenge period (C.3)
pub mod economic_constants;

// Anti-self-dealing helper (C.4)
pub mod anti_self_dealing;

// Receipt hashing utilities (C.5)
pub mod receipt_hash;

// ClaimReward validation types (C.6)
pub mod claim_validation;

// Challenge period state types (C.7)
pub mod challenge_state;

// Receipt dedup helper (C.8)
pub mod receipt_dedup;

// Proto ↔ Native conversion layer (C.9)
pub mod receipt_v1_convert;

// ════════════════════════════════════════════════════════════════════════════════
// PUBLIC API EXPORTS
// ════════════════════════════════════════════════════════════════════════════════

// DA Layer types
pub use da::{DALayer, DAError, DAHealthStatus, BlobRef, Blob, BlobStream, DAConfig};

// DA Layer implementations
pub use celestia_da::CelestiaDA;
pub use mock_da::MockDA;

// DA Health Monitor types (14A.1A.11)
pub use da_health_monitor::{DAHealthMonitor, DAStatus, DAHealthConfig};

// DA Router types (14A.1A.15 - 14A.1A.19)
pub use da_router::{
    DARouter,
    DARouterConfig,
    DARouterMetrics,
    DAStatusProvider,
    ReconcileTag,
    MetricsSnapshot,
};

// Coordinator types (14A.2B.1.11)
pub use coordinator::*;

// Gating types (14B.1 — 14B.9, tested by 14B.10)
pub use gating::{NodeIdentity, NodeClass, IdentityError};
pub use gating::{NodeStatus, StatusTransition};
pub use gating::{StakeRequirement, StakeError};
pub use gating::{CooldownPeriod, CooldownConfig, CooldownStatus};
pub use gating::{TLSCertInfo, TLSValidationError};
pub use gating::GatingError;
pub use gating::GatingPolicy;
pub use gating::{GatingDecision, CheckResult, GatingReport};
pub use gating::NodeRegistryEntry;
pub use gating::{IdentityChallenge, IdentityProof};

// Execution commitment native type (C.1)
pub use execution_commitment::ExecutionCommitment;

// Receipt V1 native type (C.2)
pub use receipt_v1::{ReceiptV1, ReceiptType};

// Economic constants & challenge period (C.3)
pub use economic_constants::*;

// Anti-self-dealing helper (C.4)
pub use anti_self_dealing::*;

// Receipt hashing utilities (C.5)
pub use receipt_hash::*;

// ClaimReward validation types (C.6)
pub use claim_validation::*;

// Challenge period state types (C.7)
pub use challenge_state::*;

// Receipt dedup helper (C.8)
pub use receipt_dedup::*;

// Proto ↔ Native conversion layer (C.9)
pub use receipt_v1_convert::{
    ConversionError,
    ClaimReward,
    ExecutionCommitmentProto,
    AggregateSignatureProto,
    ReceiptV1Proto,
    ClaimRewardProto,
    compute_aggregate_signature_hash,
    compute_receipt_hash_proto_compatible,
    compute_receipt_hash_from_proto,
};

// ════════════════════════════════════════════════════════════════════════════════
// COMMON TYPES
// ════════════════════════════════════════════════════════════════════════════════

/// Common Result type untuk crate ini.
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

// ════════════════════════════════════════════════════════════════════════════════
// INTEGRATION TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests;