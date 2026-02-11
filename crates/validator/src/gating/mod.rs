//! # Gating Verifiers (14B)
//!
//! Stateless verifiers for DSDN service node admission gating.
//!
//! ## Modules
//!
//! - `stake_verifier`: Validates stake meets minimum per [`NodeClass`](dsdn_common::gating::NodeClass) (14B.21)
//! - `identity_verifier`: Verifies Ed25519 identity proofs and operator bindings (14B.22)
//! - `tls_verifier`: Validates TLS certificate time, fingerprint, and subject CN (14B.23)
//! - `cooldown_verifier`: Verifies node is not in active slashing cooldown (14B.24)
//! - `class_verifier`: Validates node class claim is supported by actual stake (14B.25)
//! - `engine`: Orchestrator that runs all verifiers and produces a final `GatingDecision` (14B.26)
//! - `admission`: Tunable admission policy configuration with time-based rules (14B.27)
//! - `report`: Stateless audit report generator with deterministic table and JSON output (14B.28)
//!
//! ## Design Principles
//!
//! All verifiers in this module are:
//! - **Stateless**: No mutable state, no chain access, no I/O.
//! - **Deterministic**: Same inputs always produce the same output.
//! - **Pure**: No side effects, no system clock, no randomness.
//! - **Safe**: No panic, no unwrap, no silent failure.
//!
//! Verifiers consume configuration from `dsdn_common` and produce
//! `CheckResult` or `GatingError` — they do NOT mutate chain state
//! or trigger status transitions.

pub mod stake_verifier;
pub mod identity_verifier;
pub mod tls_verifier;
pub mod cooldown_verifier;
pub mod class_verifier;
pub mod engine;
pub mod admission;
pub mod report;

pub use stake_verifier::StakeVerifier;
pub use identity_verifier::IdentityVerifier;
pub use tls_verifier::TLSVerifier;
pub use cooldown_verifier::CooldownVerifier;
pub use class_verifier::ClassVerifier;
pub use engine::GatingEngine;
pub use admission::AdmissionPolicy;
pub use report::ReportGenerator;

#[cfg(test)]
mod tests;