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
//! ## Execution Commitment Pipeline (14C.B.8–14C.B.9)
//!
//! For committed execution, [`exec_committed`] wraps [`MicroVM::exec`] to
//! produce [`VmExecutionResult`] with all data for `ExecutionCommitment`:
//!
//! ```text
//! ┌─── exec_committed() ────────────────────────────────────────────┐
//! │                                                                   │
//! │  input_bytes ──► hash_input()    [DSDN:wasm_input:v1:]          │
//! │  input_bytes ──► SHA3-256(vm_state:v1:before: || input)         │
//! │                   → state_root_before                            │
//! │                                                                   │
//! │  MicroVM::exec(cmd, timeout) → ExecOutput                        │
//! │                                                                   │
//! │  stdout      ──► hash_output()   [DSDN:wasm_output:v1:]         │
//! │  stdout      ──► SHA3-256(vm_state:v1:after: || stdout)          │
//! │                   → state_root_after                             │
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
//! | [`committed_execution`] | `exec_committed` — async wrapper producing [`VmExecutionResult`] (14C.B.9) |
//! | [`firecracker_vm`] | Firecracker microVM backend (skeleton + committed execution placeholder, 14C.B.10) |
//! | [`mock_vm`] | Process-based mock VM for testing |

/// Firecracker microVM backend (skeleton).
///
/// `FirecrackerVM` implements [`MicroVM`] with `NotImplemented` stubs for
/// start/stop/exec. Also provides `exec_committed()` placeholder (14C.B.10)
/// with matching signature to [`exec_committed`] free function, returning
/// `MicroVmError::NotImplemented`. Full implementation requires kernel image,
/// rootfs, vsock agent, and API socket integration.
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

/// Committed VM execution wrapper (14C.B.9).
///
/// [`exec_committed`] wraps [`MicroVM::exec`] without modifying it. It adds
/// state capture (input/output hashing, VM-specific state root computation),
/// V1 minimal execution trace, Merkle root computation, and resource usage
/// estimation. Returns [`VmExecutionResult`] with all data needed to construct
/// an `ExecutionCommitment`.
///
/// ## State Root Design (V1)
///
/// VM state roots use VM-specific domain prefixes distinct from WASM:
/// - `state_root_before`: `SHA3-256(b"DSDN:vm_state:v1:before:" || input_bytes)`
/// - `state_root_after`: `SHA3-256(b"DSDN:vm_state:v1:after:" || stdout)`
///
/// `hash_input` and `hash_output` still use cross-runtime prefixes
/// (`DSDN:wasm_input:v1:`, `DSDN:wasm_output:v1:`) for commitment format
/// compatibility.
///
/// ## Determinism
///
/// All commitment-critical fields are deterministic. `execution_time_ms`
/// is wall-clock (non-deterministic) but does not affect commitment hash.
pub mod committed_execution;

/// Re-exported from [`execution_result`].
pub use execution_result::{VmExecutionResult, VmResourceUsage};

/// Re-exported from [`merkle`]. Consensus-critical: byte-identical to
/// WASM runtime and coordinator.
pub use merkle::compute_trace_merkle_root;

/// Re-exported from [`state_capture`]. Domain-separated SHA3-256 hashing.
pub use state_capture::{hash_input, hash_output, hash_memory_snapshot};

/// Re-exported from [`committed_execution`]: commitment-producing VM
/// execution wrapper that calls [`MicroVM::exec`] internally.
pub use committed_execution::exec_committed;

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