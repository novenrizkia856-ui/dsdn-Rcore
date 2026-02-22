//! # runtime_vm — VM Runtime with Execution Commitment Support
//!
//! Defines a generic abstraction layer for running isolated execution
//! environments ("micro VMs") with optional execution commitment production
//! for fraud-proof reproducibility.
//!
//! ## VM Execution
//!
//! The [`MicroVM`] trait provides a backend-agnostic interface for VM
//! lifecycle management (start, stop, exec). Implementations include
//! [`MockVMController`] for testing and `FirecrackerVM` for production.
//!
//! ## Execution Commitment Pipeline (14C.B.8)
//!
//! For committed execution, the VM runtime produces [`VmExecutionResult`]
//! containing all data needed to construct an `ExecutionCommitment`:
//!
//! ```text
//! ┌─── VM Committed Execution ──────────────────────────────────────┐
//! │                                                                   │
//! │  input_bytes ──► hash_input()    [DSDN:wasm_input:v1:]          │
//! │  vm_image    ──► hash_memory_snapshot()  → state_root_before    │
//! │                                                                   │
//! │  MicroVM::exec() → stdout, stderr, exit_code                     │
//! │                                                                   │
//! │  stdout      ──► hash_output()   [DSDN:wasm_output:v1:]         │
//! │  stdout      ──► hash_memory_snapshot()  → state_root_after     │
//! │  trace       ──► compute_trace_merkle_root()                     │
//! │                                                                   │
//! │  VmExecutionResult                                                │
//! │       │                                                           │
//! │       ▼                                                           │
//! │  to_execution_commitment() → ExecutionCommitment (dsdn_common)   │
//! │       │                                                           │
//! │       ▼                                                           │
//! │  compute_hash() → commitment_hash [u8; 32]                       │
//! └───────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Cross-Runtime Commitment Compatibility
//!
//! Domain separator prefixes are **identical** to `runtime_wasm`:
//! `DSDN:wasm_input:v1:`, `DSDN:wasm_output:v1:`, `DSDN:wasm_memory:v1:`.
//! The Merkle tree algorithm is byte-identical to both `runtime_wasm`
//! and the coordinator. This ensures that for the same 6 commitment
//! fields, VM and WASM runtimes produce the same `commitment_hash()`.
//!
//! ## Determinism Guarantee
//!
//! All commitment-critical fields are deterministic: same input → same
//! hash. Operational fields (`execution_time_ms`, `stderr`, `exit_code`)
//! do NOT affect the commitment hash.
//!
//! ## Modules
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`execution_result`] | [`VmExecutionResult`], [`VmResourceUsage`] types + commitment bridge |
//! | [`merkle`] | `compute_trace_merkle_root` — byte-identical to WASM/coordinator |
//! | [`state_capture`] | `hash_input`, `hash_output`, `hash_memory_snapshot` — identical domain separators |
//! | [`firecracker_vm`] | Firecracker microVM backend (skeleton) |
//! | [`mock_vm`] | Process-based mock VM for testing |

pub mod firecracker_vm;

// ════════════════════════════════════════════════════════════════════════════════
// EXECUTION COMMITMENT MODULES (14C.B.8)
// ════════════════════════════════════════════════════════════════════════════════

/// VM execution result types and commitment bridge.
///
/// Defines [`VmExecutionResult`] and [`VmResourceUsage`] with bridge methods
/// `to_execution_commitment()` and `commitment_hash()` for coordinator
/// compatibility.
pub mod execution_result;

/// Deterministic binary Merkle tree (SHA3-256).
///
/// Byte-identical algorithm to `runtime_wasm::merkle` and
/// `coordinator::execution::commitment_builder`. Consensus-critical.
pub mod merkle;

/// Domain-separated SHA3-256 hashing with cross-runtime compatible prefixes.
///
/// Uses identical domain prefixes to `runtime_wasm::state_capture`:
/// `DSDN:wasm_input:v1:`, `DSDN:wasm_output:v1:`, `DSDN:wasm_memory:v1:`.
pub mod state_capture;

/// Re-exported from [`execution_result`].
pub use execution_result::{VmExecutionResult, VmResourceUsage};

/// Re-exported from [`merkle`]. Consensus-critical: byte-identical to
/// WASM runtime and coordinator.
pub use merkle::compute_trace_merkle_root;

/// Re-exported from [`state_capture`]. Domain-separated SHA3-256 hashing.
pub use state_capture::{hash_input, hash_output, hash_memory_snapshot};

use async_trait::async_trait;
use thiserror::Error;

/// Output from a VM command execution.
///
/// Captures stdout, stderr, exit code, and timeout status from the VM
/// process. Used by [`MicroVM::exec`] implementations.
#[derive(Debug, Clone)]
pub struct ExecOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
}

/// Errors from VM operations (start, stop, exec).
#[derive(Error, Debug)]
pub enum MicroVmError {
    #[error("process error: {0}")]
    Process(String),

    #[error("not implemented: {0}")]
    NotImplemented(String),

    #[error("other error: {0}")]
    Other(String),
}
/// Result type alias for VM operations.
pub type MicroVmResult<T> = Result<T, MicroVmError>;

/// Backend-agnostic interface for isolated execution environments.
///
/// Implementations manage VM lifecycle (start, stop) and command execution.
/// See [`MockVMController`] for testing and `FirecrackerVM` for production.
#[async_trait]
pub trait MicroVM: Send + Sync {
    /// Start the VM / agent. Mutable because it may set internal state (child handle).
    async fn start(&mut self) -> MicroVmResult<()>;

    /// Stop the VM (kill background process etc).
    async fn stop(&mut self) -> MicroVmResult<()>;

    /// Execute a command inside the VM (or mock). `timeout_ms` optional.
    async fn exec(&self, cmd: Vec<String>, timeout_ms: Option<u64>) -> MicroVmResult<ExecOutput>;
}

// Re-export mock implementation
pub mod mock_vm;
pub use mock_vm::{MockVMConfig, MockVMController};