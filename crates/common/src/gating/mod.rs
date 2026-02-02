//! # Gating System Module (14B)
//!
//! Foundation module for the DSDN Stake & Identity Gating System.
//!
//! ## Purpose
//!
//! The gating system ensures that only qualified, staked, and identity-verified
//! nodes can participate in the DSDN network. It serves as a security gate —
//! not an economic incentive mechanism.
//!
//! ## Current Components (14B.1 — 14B.9)
//!
//! | Type | Module | Purpose |
//! |------|--------|---------|
//! | `NodeIdentity` | `identity` | Cryptographic identity: Ed25519 key, operator wallet, TLS fingerprint |
//! | `NodeClass` | `identity` | Node classification: Storage (5000 NUSA) or Compute (500 NUSA) |
//! | `IdentityError` | `identity` | Structured errors for identity verification operations |
//! | `NodeStatus` | `node_status` | Lifecycle states: Pending, Active, Quarantined, Banned |
//! | `StatusTransition` | `node_status` | Record of a status change event |
//! | `StakeRequirement` | `stake` | Per-class minimum stake thresholds (18-decimal on-chain units) |
//! | `StakeError` | `stake` | Structured errors for stake verification failures |
//! | `CooldownPeriod` | `cooldown` | Cooldown period after slashing: start, duration, reason |
//! | `CooldownConfig` | `cooldown` | Default (24h) and severe (7d) cooldown durations |
//! | `CooldownStatus` | `cooldown` | Cooldown state: NoCooldown, InCooldown, Expired |
//! | `TLSCertInfo` | `tls` | TLS certificate metadata: fingerprint, validity, subject, issuer |
//! | `TLSValidationError` | `tls` | Structured errors for TLS certificate validation |
//! | `GatingError` | `error` | Comprehensive gating error types for admission control |
//! | `GatingPolicy` | `policy` | Combined gating policy configuration: stake, cooldown, TLS, identity |
//! | `GatingDecision` | `decision` | Final gating output: Approved or Rejected with errors |
//! | `CheckResult` | `decision` | Individual check outcome: name, passed, optional detail |
//! | `GatingReport` | `decision` | Full audit report: identity, decision, checks, timestamp, evaluator |
//! | `NodeRegistryEntry` | `registry_entry` | Single source of truth: identity, class, status, stake, cooldown, TLS |
//! | `IdentityChallenge` | `challenge` | Challenge nonce for identity ownership verification |
//! | `IdentityProof` | `challenge` | Ed25519 signature proof over raw challenge nonce |
//!
//! ## Planned Components
//!
//! Future sub-stages will add:
//! - Integration tests and final documentation (14B.10)

pub mod identity;
pub mod node_status;
pub mod stake;
pub mod cooldown;
pub mod tls;
pub mod error;
pub mod policy;
pub mod decision;
pub mod registry_entry;
pub mod challenge;

// ════════════════════════════════════════════════════════════════════════════════
// RE-EXPORTS
// ════════════════════════════════════════════════════════════════════════════════

pub use identity::{IdentityError, NodeClass, NodeIdentity};
pub use node_status::{NodeStatus, StatusTransition};
pub use stake::{StakeRequirement, StakeError};
pub use cooldown::{CooldownPeriod, CooldownConfig, CooldownStatus};
pub use tls::{TLSCertInfo, TLSValidationError};
pub use error::GatingError;
pub use policy::GatingPolicy;
pub use decision::{GatingDecision, CheckResult, GatingReport};
pub use registry_entry::NodeRegistryEntry;
pub use challenge::{IdentityChallenge, IdentityProof};