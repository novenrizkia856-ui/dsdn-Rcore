//! # Gating Verifiers (14B)
//!
//! Stateless verifiers for DSDN service node admission gating.
//!
//! ## Modules
//!
//! - `stake_verifier`: Validates stake meets minimum per [`NodeClass`](dsdn_common::gating::NodeClass) (14B.21)
//! - `identity_verifier`: Verifies Ed25519 identity proofs and operator bindings (14B.22)
//! - `tls_verifier`: Validates TLS certificate time, fingerprint, and subject CN (14B.23)
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

pub use stake_verifier::StakeVerifier;
pub use identity_verifier::IdentityVerifier;
pub use tls_verifier::TLSVerifier;