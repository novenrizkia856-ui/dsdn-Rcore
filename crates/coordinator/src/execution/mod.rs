//! # Execution Module (CO.2, CO.3)
//!
//! Provides deterministic construction of [`ExecutionCommitment`] from
//! workload execution results and usage proof verification.
//!
//! ## Components
//!
//! - [`CommitmentBuilder`] — Builds `ExecutionCommitment` from execution outputs.
//! - [`compute_trace_merkle_root`] — Computes binary Merkle root over execution trace.
//! - [`UsageProof`] — Self-reported resource usage claim from a node.
//! - [`verify_usage_proof`] — Verifies usage proof (V1: signature + range checks).
//! - [`calculate_reward_base`] — Computes reward from resource metrics.
//!
//! ## Usage
//!
//! ```ignore
//! use dsdn_coordinator::execution::{CommitmentBuilder, verify_usage_proof, UsageProof};
//! use dsdn_common::coordinator::WorkloadId;
//!
//! // Build execution commitment
//! let builder = CommitmentBuilder::new(WorkloadId::new([0x01; 32]));
//! let commitment = builder.build(
//!     input_hash, output_hash,
//!     state_root_before, state_root_after,
//!     &execution_trace,
//! );
//!
//! // Verify usage proof
//! let result = verify_usage_proof(&proof);
//! ```

pub mod commitment_builder;
pub mod usage_verifier;

pub use commitment_builder::{compute_trace_merkle_root, CommitmentBuilder};
pub use usage_verifier::{
    build_signing_message, calculate_reward_base, verify_usage_proof,
    UsageProof, UsageVerificationResult,
};