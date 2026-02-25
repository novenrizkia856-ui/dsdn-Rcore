//! # dsdn-runtime-vm — VM Runtime with Execution Commitment Pipeline
//!
//! Provides a backend-agnostic interface for isolated VM execution environments
//! with deterministic state capture for fraud-proof reproducibility. Supports
//! committed execution that produces `ExecutionCommitment` values identical in
//! format to `runtime_wasm`.
//!
//! ## Architecture
//!
//! Two execution paths:
//!
//! - **[`MicroVM::exec`]** — Low-level VM command execution. Returns
//!   [`ExecOutput`] (stdout, stderr, exit_code). No commitment logic.
//!
//! - **[`exec_committed`]** — Wraps `exec()` without modifying it. Adds
//!   state capture, Merkle root computation, and resource estimation.
//!   Returns [`VmExecutionResult`] for commitment construction.
//!
//! ## Execution Commitment Pipeline
//!
//! ```text
//! ┌─── exec_committed(vm, workload_id, cmd, input, timeout) ────────┐
//! │                                                                   │
//! │  Command + Input Bytes                                            │
//! │       │                                                           │
//! │       ├──► hash_input(input_bytes)                                │
//! │       │    prefix: DSDN:wasm_input:v1:  (cross-runtime)          │
//! │       │     → input_hash [u8; 32]                                │
//! │       │                                                           │
//! │       ├──► SHA3-256(DSDN:vm_state:v1:before: || input_bytes)     │
//! │       │     → state_root_before [u8; 32]  (V1 proxy)            │
//! │       │                                                           │
//! │       ▼  Instant::now() ─────────────► start timer               │
//! │                                                                   │
//! │  ┌─────────────────────┐                                         │
//! │  │  MicroVM::exec()    │  ← vm.exec(cmd, timeout).await         │
//! │  │    (UNCHANGED)      │  ← MockVM: process spawn               │
//! │  └──────────┬──────────┘  ← Firecracker: vsock agent (V2)       │
//! │             │                                                     │
//! │             │  ExecOutput { stdout, stderr, exit_code, timed_out }│
//! │             │                                                     │
//! │             ▼  elapsed ──────────────► stop timer                 │
//! │                                                                   │
//! │       ├──► hash_output(stdout)                                    │
//! │       │    prefix: DSDN:wasm_output:v1:  (cross-runtime)         │
//! │       │     → output_hash [u8; 32]                               │
//! │       │                                                           │
//! │       ├──► SHA3-256(DSDN:vm_state:v1:after: || stdout)           │
//! │       │     → state_root_after [u8; 32]  (V1 proxy)             │
//! │       │                                                           │
//! │       ├──► trace = [input_bytes, stdout]  (V1 minimal)           │
//! │       │     → compute_trace_merkle_root(&trace)                  │
//! │       │     → execution_trace_merkle_root [u8; 32]               │
//! │       │                                                           │
//! │       └──► VmResourceUsage {                                      │
//! │              execution_time_ms: elapsed (wall-clock),             │
//! │              cpu_cycles_estimate: ms * 1_000_000 (checked_mul),   │
//! │              peak_memory_bytes: input_bytes.len() as u64,         │
//! │            }                                                      │
//! │                                                                   │
//! │  ┌───────────────────────────────────────────────────────────┐   │
//! │  │                VmExecutionResult                           │   │
//! │  │  workload_id ──────────────────────────────────────┐      │   │
//! │  │  input_hash ───────────────────────────────────┐   │      │   │
//! │  │  output_hash ──────────────────────────────┐   │   │      │   │
//! │  │  state_root_before ────────────────────┐   │   │   │      │   │
//! │  │  state_root_after ─────────────────┐   │   │   │   │      │   │
//! │  │  execution_trace_merkle_root ──┐   │   │   │   │   │      │   │
//! │  │  execution_trace (operational) │   │   │   │   │   │      │   │
//! │  │  stdout (operational)          │   │   │   │   │   │      │   │
//! │  │  stderr (VM-specific)          │   │   │   │   │   │      │   │
//! │  │  exit_code (VM-specific)       │   │   │   │   │   │      │   │
//! │  │  resource_usage (operational)  │   │   │   │   │   │      │   │
//! │  └────────────────────────────────┼───┼───┼───┼───┼───┼──────┘   │
//! │                                   │   │   │   │   │   │          │
//! │       to_execution_commitment()   ▼   ▼   ▼   ▼   ▼   ▼          │
//! │       (1:1 field mapping, 6 fields only)                         │
//! │                                                                   │
//! │  ┌───────────────────────────────────────────────────────────┐   │
//! │  │         ExecutionCommitment (dsdn_common)                  │   │
//! │  │  6 fields, 192 bytes, Copy                                │   │
//! │  │                                                            │   │
//! │  │  compute_hash() → SHA3-256 of all 6 fields                │   │
//! │  │                   → commitment_hash [u8; 32]              │   │
//! │  └──────────────────────────┬────────────────────────────────┘   │
//! │                              │                                    │
//! │                              ▼                                    │
//! │                   Coordinator receipt signing pipeline            │
//! └───────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Modules
//!
//! | Module | Responsibility | Determinism Role | Compatibility | Error Handling |
//! |--------|---------------|------------------|---------------|----------------|
//! | [`execution_result`] | `VmExecutionResult`, `VmResourceUsage`, commitment bridge | Holds all commitment fields; bridge maps to `ExecutionCommitment` | Same `ExecutionCommitment::new` as WASM | N/A (data types) |
//! | [`merkle`] | `compute_trace_merkle_root` — binary SHA3-256 Merkle | Byte-identical to WASM/coordinator | Consensus-critical cross-crate contract | Pure function, no errors |
//! | [`state_capture`] | `hash_input`, `hash_output`, `hash_memory_snapshot` | Domain prefixes prevent cross-context collisions | `DSDN:wasm_input/output/memory:v1:` = WASM | Pure functions, no errors |
//! | [`committed_execution`] | `exec_committed` — async wrapper producing `VmExecutionResult` | Wraps `exec()` without modification; assembles commitment fields | VM-specific state roots; cross-runtime input/output hashes | Propagates `MicroVmError`; overflow → `Other` |
//! | [`firecracker_vm`] | `FirecrackerVM` — production microVM backend (skeleton) | `exec_committed` placeholder returns `NotImplemented` | Interface parity with `exec_committed` free function | `NotImplemented` for all methods |
//! | [`mock_vm`] | `MockVMController` — process-based mock for testing | Deterministic for fixed inputs | Used in integration tests | `Process` errors from spawn/wait |
//! | (root) | [`MicroVM`] trait, [`ExecOutput`], [`MicroVmError`], [`MicroVmResult`] | `MicroVM::exec` is backend-agnostic | Trait shared by all backends | `MicroVmError` enum |
//!
//! ## Cross-Runtime Commitment Compatibility
//!
//! The following compatibility contracts MUST hold between `runtime_vm`,
//! `runtime_wasm`, and the coordinator:
//!
//! 1. **Domain separator identity for input/output hashing** —
//!    `hash_input` uses prefix `DSDN:wasm_input:v1:` (19 bytes) and
//!    `hash_output` uses prefix `DSDN:wasm_output:v1:` (20 bytes).
//!    These are byte-identical to `runtime_wasm::state_capture`. Same
//!    input → same `input_hash` regardless of runtime.
//!
//! 2. **Merkle algorithm identity** — `compute_trace_merkle_root` uses:
//!    leaf = `SHA3-256(step)`, parent = `SHA3-256(left || right)`,
//!    odd count = duplicate last, empty = `[0u8; 32]`. Byte-identical
//!    to `runtime_wasm::merkle` and `coordinator::execution`. Same
//!    trace → same root.
//!
//! 3. **`ExecutionCommitment` format identity** —
//!    `VmExecutionResult::to_execution_commitment()` calls the same
//!    `ExecutionCommitment::new()` constructor as `WasmExecutionResult`.
//!    The 6-field mapping is 1:1 with no transformation.
//!
//! 4. **Commitment hash reproducibility** — `commitment_hash()` returns
//!    the same 32-byte SHA3-256 digest that the coordinator computes
//!    from the same 6 fields via `ExecutionCommitment::compute_hash()`.
//!
//! 5. **Determinism invariant** — All commitment-critical fields are
//!    pure functions of their inputs. No randomness, no time-based
//!    entropy, no nondeterministic ordering. Same VM + same command +
//!    same input → byte-identical commitment.
//!
//! **Note:** `state_root_before` and `state_root_after` use VM-specific
//! domain prefixes (`DSDN:vm_state:v1:before:`, `DSDN:vm_state:v1:after:`)
//! that differ from WASM's `DSDN:wasm_memory:v1:`. These are V1 proxies
//! and will be unified in V2 when full memory snapshots are available.
//!
//! ## V1 Limitations
//!
//! | Feature | V1 Implementation | V1 Rationale | V2 Plan |
//! |---------|-------------------|--------------|---------|
//! | `state_root_before` | `SHA3-256(DSDN:vm_state:v1:before: \|\| input_bytes)` | Input determines pre-execution state (no VM memory access) | Full VM memory snapshot before execution |
//! | `state_root_after` | `SHA3-256(DSDN:vm_state:v1:after: \|\| stdout)` | Output is primary observable effect | Full VM memory + filesystem diff after execution |
//! | Execution trace | `[input_bytes, stdout]` — 2-element trace | Captures boundary conditions | Instruction-level or syscall-level tracing |
//! | CPU cycles | `execution_time_ms * 1_000_000` via `checked_mul` | Wall-clock proxy; overflow → `MicroVmError::Other` | cgroup CPU accounting or hardware counters |
//! | Peak memory | `input_bytes.len() as u64` | Input size proxy | cgroup memory high-water mark |
//! | TEE attestation | Not available | No hardware integration | TEE attestation with signed measurements |
//! | Firecracker committed | Placeholder returning `NotImplemented` | Requires kernel + rootfs + vsock agent | Full Firecracker integration with vsock |
//! | Memory snapshot | Not available | No VM memory access | Full VM state serialization |
//!
//! These V1 proxies are fully deterministic: same input + same command →
//! same proxy hashes. This satisfies the fraud-proof requirement that
//! commitment consistency can be verified by re-execution.
//!
//! ## Relationship to `ExecutionCommitment` (`dsdn_common`)
//!
//! `VmExecutionResult::to_execution_commitment()` maps 6 fields 1:1:
//!
//! | VmExecutionResult field | ExecutionCommitment parameter |
//! |-------------------------|-------------------------------|
//! | `workload_id` | `workload_id` (WorkloadId, Copy) |
//! | `input_hash` | `input_hash` ([u8; 32], Copy) |
//! | `output_hash` | `output_hash` ([u8; 32], Copy) |
//! | `state_root_before` | `state_root_before` ([u8; 32], Copy) |
//! | `state_root_after` | `state_root_after` ([u8; 32], Copy) |
//! | `execution_trace_merkle_root` | `execution_trace_merkle_root` ([u8; 32], Copy) |
//!
//! Excluded from commitment: `execution_trace`, `stdout`, `stderr`,
//! `exit_code`, `resource_usage` — operational data only.
//!
//! `commitment_hash()` is a shortcut for
//! `to_execution_commitment().compute_hash()`. The construction is
//! deterministic: same `VmExecutionResult` → same `ExecutionCommitment`
//! → same 32-byte hash.
//!
//! ## Relationship to Coordinator Pipeline
//!
//! The coordinator uses `ExecutionCommitment` in its receipt signing
//! pipeline:
//!
//! 1. Node executes workload via `exec_committed()` → `VmExecutionResult`
//! 2. Node extracts `ExecutionCommitment` via `to_execution_commitment()`
//! 3. Node submits commitment to coordinator
//! 4. Coordinator verifies `commitment_hash()` matches expected
//! 5. Coordinator signs receipt including the commitment
//! 6. On fraud challenge: verifier re-executes same workload and
//!    compares `commitment_hash()` — must be byte-identical
//!
//! The coordinator's `CommitmentBuilder` and `compute_trace_merkle_root`
//! use the same algorithms. Merkle root verification is cross-crate:
//! the coordinator can recompute the Merkle root from submitted trace
//! steps and verify it matches `execution_trace_merkle_root`.
//!
//! ## Determinism Verification (14C.B.11)
//!
//! Verified by 12 integration tests in `tests/commitment_tests.rs`:
//!
//! - 10x determinism runs for all commitment fields
//! - Different input → different commitment
//! - Different workload_id → different commitment
//! - Commitment roundtrip (bridge + compute_hash)
//! - Cross-runtime Merkle verification (manual SHA3-256)
//! - Cross-runtime `hash_input`/`hash_output` verification
//! - Error path: no partial commitment
//! - Firecracker placeholder: `NotImplemented`
//! - Empty/large input edge cases
//!
//! ## Test Coverage
//!
//! | Location | Tests | Scope |
//! |----------|-------|-------|
//! | `execution_result.rs` (unit) | 10 | Struct, clone, Send/Sync, commitment bridge |
//! | `merkle.rs` (unit) | 6 | Empty, single, even, odd, determinism 100x, order |
//! | `state_capture.rs` (unit) | 6 | Domain separation, determinism 100x, prefix bytes |
//! | `committed_execution.rs` (unit) | 10 | Full pipeline, hash consistency, error propagation |
//! | `tests/commitment_tests.rs` (integration) | 12 | Determinism 10x, cross-runtime, Firecracker placeholder |
//!
//! Total: 44 tests.

/// Firecracker microVM backend (skeleton, 14C.B.10).
///
/// [`FirecrackerVM`] implements [`MicroVM`] with `NotImplemented` stubs for
/// start/stop/exec. Also provides `exec_committed()` placeholder with
/// matching signature to [`exec_committed`] free function, returning
/// `MicroVmError::NotImplemented`.
///
/// ## V1 Status
///
/// Not implemented. Full Firecracker integration requires kernel image,
/// rootfs, vsock agent, and API socket. When implemented, committed
/// execution will follow the same determinism pattern as
/// [`exec_committed`].
pub mod firecracker_vm;

// ════════════════════════════════════════════════════════════════════════════════
// EXECUTION COMMITMENT MODULES (14C.B.8–14C.B.10)
// ════════════════════════════════════════════════════════════════════════════════

/// VM execution result types and commitment bridge (14C.B.8).
///
/// Defines [`VmExecutionResult`] — the VM-side carrier for all data needed
/// to construct an `ExecutionCommitment` — and [`VmResourceUsage`] for V1
/// resource estimation. Bridge methods `to_execution_commitment()` and
/// `commitment_hash()` provide 1:1 mapping to `dsdn_common::ExecutionCommitment`.
///
/// VM-specific fields (`stderr`, `exit_code`) are operational and do NOT
/// affect commitment hashes.
pub mod execution_result;

/// Deterministic binary Merkle tree (14C.B.8).
///
/// [`compute_trace_merkle_root`] computes a SHA3-256 binary Merkle root
/// over execution trace steps. Algorithm is byte-identical to
/// `runtime_wasm::merkle` and `coordinator::execution::compute_trace_merkle_root`:
/// leaf = `SHA3-256(step)`, parent = `SHA3-256(left || right)`,
/// odd count = duplicate last, empty = `[0u8; 32]`.
///
/// This is consensus-critical. Any divergence between VM, WASM, and
/// coordinator implementations breaks fraud-proof reproducibility.
pub mod merkle;

/// Domain-separated SHA3-256 hashing (14C.B.8).
///
/// Provides three pure hashing functions with domain prefixes **identical**
/// to `runtime_wasm::state_capture`:
/// - [`hash_input`]: prefix `DSDN:wasm_input:v1:` (19 bytes)
/// - [`hash_output`]: prefix `DSDN:wasm_output:v1:` (20 bytes)
/// - [`hash_memory_snapshot`]: prefix `DSDN:wasm_memory:v1:` (20 bytes)
///
/// The `wasm_` prefix is retained for cross-runtime commitment format
/// compatibility. These are commitment format identifiers, not
/// runtime-specific labels.
pub mod state_capture;

/// Committed VM execution wrapper (14C.B.9).
///
/// [`exec_committed`] wraps [`MicroVM::exec`] without modifying it. Adds
/// state capture (input/output hashing, VM-specific state root computation),
/// V1 minimal execution trace, Merkle root computation, and resource usage
/// estimation. Returns [`VmExecutionResult`] with all data needed to
/// construct an `ExecutionCommitment`.
///
/// ## State Root Design (V1)
///
/// VM state roots use VM-specific domain prefixes:
/// - `state_root_before`: `SHA3-256(b"DSDN:vm_state:v1:before:" || input_bytes)`
/// - `state_root_after`: `SHA3-256(b"DSDN:vm_state:v1:after:" || stdout)`
///
/// `hash_input` and `hash_output` use cross-runtime prefixes
/// (`DSDN:wasm_input:v1:`, `DSDN:wasm_output:v1:`) for commitment format
/// compatibility with the WASM runtime.
///
/// ## Error Handling
///
/// If `exec()` fails, the error propagates directly. No partial
/// `VmExecutionResult` is ever constructed. CPU cycles overflow
/// returns `MicroVmError::Other`.
///
/// ## Determinism
///
/// All commitment-critical fields are deterministic. `execution_time_ms`
/// is wall-clock (non-deterministic) but does not affect commitment hash.
pub mod committed_execution;

// ════════════════════════════════════════════════════════════════════════════════
// RE-EXPORTS
// ════════════════════════════════════════════════════════════════════════════════

/// Re-exported from [`execution_result`]: VM execution result carrier,
/// V1 resource usage, commitment bridge.
pub use execution_result::{VmExecutionResult, VmResourceUsage};

/// Re-exported from [`merkle`]. Consensus-critical: byte-identical to
/// WASM runtime and coordinator algorithm.
pub use merkle::compute_trace_merkle_root;

/// Re-exported from [`state_capture`]. Domain-separated SHA3-256 hashing
/// with cross-runtime compatible prefixes.
pub use state_capture::{hash_input, hash_output, hash_memory_snapshot};

/// Re-exported from [`committed_execution`]: commitment-producing async
/// VM execution wrapper that calls [`MicroVM::exec`] internally.
pub use committed_execution::exec_committed;

// ════════════════════════════════════════════════════════════════════════════════
// CORE VM RUNTIME TYPES
// ════════════════════════════════════════════════════════════════════════════════

use async_trait::async_trait;
use thiserror::Error;

/// Output from a VM command execution.
///
/// Captures stdout, stderr, exit code, and timeout status from the VM
/// process. Produced by [`MicroVM::exec`] implementations and consumed
/// internally by [`exec_committed`].
///
/// All fields are operational data. `stdout` feeds into commitment
/// hashing (`hash_output`, `state_root_after`, execution trace).
/// `stderr`, `exit_code`, and `timed_out` do NOT affect commitments.
#[derive(Debug, Clone)]
pub struct ExecOutput {
    /// Bytes captured from the VM process standard output.
    pub stdout: Vec<u8>,
    /// Bytes captured from the VM process standard error.
    pub stderr: Vec<u8>,
    /// Process exit code. `None` if the process was killed or timed out.
    pub exit_code: Option<i32>,
    /// Whether the execution was terminated due to timeout.
    pub timed_out: bool,
}

/// Errors from VM operations (start, stop, exec, committed execution).
///
/// Used as the error type in [`MicroVmResult`]. Covers process failures,
/// unimplemented features, and general errors.
#[derive(Error, Debug)]
pub enum MicroVmError {
    /// VM process failed to start, execute, or return results.
    #[error("process error: {0}")]
    Process(String),

    /// Feature not yet implemented (e.g., Firecracker committed execution).
    #[error("not implemented: {0}")]
    NotImplemented(String),

    /// General error: host failures, resource overflow, unexpected conditions.
    /// Used by [`exec_committed`] for `checked_mul` overflow.
    #[error("other error: {0}")]
    Other(String),
}

/// Result type alias for VM operations.
///
/// Used by [`MicroVM`] trait methods and [`exec_committed`].
pub type MicroVmResult<T> = Result<T, MicroVmError>;

/// Backend-agnostic interface for isolated execution environments.
///
/// Implementations manage VM lifecycle (start, stop) and command execution.
/// See [`MockVMController`] for testing and [`FirecrackerVM`](firecracker_vm::FirecrackerVM)
/// for production.
///
/// ## Implementations
///
/// | Backend | Status | Committed Execution |
/// |---------|--------|---------------------|
/// | [`MockVMController`] | Functional | Via [`exec_committed`] free function |
/// | `FirecrackerVM` | Skeleton | Placeholder returning `NotImplemented` |
///
/// ## Contract
///
/// - `start()` must be called before `exec()`.
/// - `stop()` should be called to release resources.
/// - `exec()` must be safe to call concurrently (requires `&self`).
/// - All methods return [`MicroVmResult`] — no panics.
#[async_trait]
pub trait MicroVM: Send + Sync {
    /// Start the VM / agent.
    ///
    /// Mutable because it may set internal state (child process handle).
    async fn start(&mut self) -> MicroVmResult<()>;

    /// Stop the VM and release resources.
    async fn stop(&mut self) -> MicroVmResult<()>;

    /// Execute a command inside the VM.
    ///
    /// ## Arguments
    ///
    /// * `cmd` — Command and arguments to execute.
    /// * `timeout_ms` — Optional wall-clock timeout in milliseconds.
    ///
    /// ## Returns
    ///
    /// [`ExecOutput`] with captured stdout, stderr, exit code.
    /// `timed_out` is `true` if the timeout was reached.
    async fn exec(&self, cmd: Vec<String>, timeout_ms: Option<u64>) -> MicroVmResult<ExecOutput>;
}

// ════════════════════════════════════════════════════════════════════════════════
// MOCK VM
// ════════════════════════════════════════════════════════════════════════════════

/// Process-based mock VM for testing and development.
///
/// [`MockVMController`] spawns real processes to execute commands,
/// providing a lightweight alternative to Firecracker for environments
/// without hardware virtualization. Used in integration tests for
/// committed execution verification.
pub mod mock_vm;

/// Re-exported from [`mock_vm`].
pub use mock_vm::{MockVMConfig, MockVMController};