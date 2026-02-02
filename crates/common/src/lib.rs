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

// Gating types (14B.1 — 14B.7)
pub use gating::{NodeIdentity, NodeClass, IdentityError};
pub use gating::{NodeStatus, StatusTransition};
pub use gating::{StakeRequirement, StakeError};
pub use gating::{CooldownPeriod, CooldownConfig, CooldownStatus};
pub use gating::{TLSCertInfo, TLSValidationError};
pub use gating::GatingError;
pub use gating::GatingPolicy;

// ════════════════════════════════════════════════════════════════════════════════
// COMMON TYPES
// ════════════════════════════════════════════════════════════════════════════════

/// Common Result type untuk crate ini.
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;