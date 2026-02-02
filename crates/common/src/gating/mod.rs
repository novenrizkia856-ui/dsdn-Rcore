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
//! ## Current Components (14B.1 — 14B.3)
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
//!
//! ## Planned Components
//!
//! Future sub-stages will add:
//! - `SlashingCooldown` — Cooldown period tracking after slashing events (14B.4)
//! - `TLSCertInfo` — TLS certificate validation types (14B.5)
//! - `GatingError` — Comprehensive gating error types (14B.6)
//! - `GatingPolicy` — Combined gating policy configuration (14B.7)
//! - `GatingDecision` — Approval/rejection decision with audit report (14B.8)
//! - `NodeRegistryEntry` — Shared registry entry type (14B.9)
//! - Integration tests and final documentation (14B.10)

pub mod identity;
pub mod node_status;
pub mod stake;

// ════════════════════════════════════════════════════════════════════════════════
// RE-EXPORTS
// ════════════════════════════════════════════════════════════════════════════════

pub use identity::{IdentityError, NodeClass, NodeIdentity};
pub use node_status::{NodeStatus, StatusTransition};
pub use stake::{StakeRequirement, StakeError};