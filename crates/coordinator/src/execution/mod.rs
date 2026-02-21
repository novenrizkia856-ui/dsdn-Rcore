//! # Execution Module (CO.2)
//!
//! Provides deterministic construction of [`ExecutionCommitment`] from
//! workload execution results.
//!
//! ## Components
//!
//! - [`CommitmentBuilder`] — Builds `ExecutionCommitment` from execution outputs.
//! - [`compute_trace_merkle_root`] — Computes binary Merkle root over execution trace.
//!
//! ## Usage
//!
//! ```ignore
//! use dsdn_coordinator::execution::CommitmentBuilder;
//! use dsdn_common::coordinator::WorkloadId;
//!
//! let builder = CommitmentBuilder::new(WorkloadId::new([0x01; 32]));
//! let commitment = builder.build(
//!     input_hash,
//!     output_hash,
//!     state_root_before,
//!     state_root_after,
//!     &execution_trace,
//! );
//! ```

pub mod commitment_builder;

pub use commitment_builder::{compute_trace_merkle_root, CommitmentBuilder};