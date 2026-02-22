//! # dsdn-runtime-wasm — WASM Runtime with Execution Commitment Pipeline
//!
//! Provides deterministic WASM/WASI module execution under resource limits,
//! with cryptographic state capture for fraud-proof reproducibility.
//!
//! ## Architecture
//!
//! Two execution paths are available:
//!
//! - [`run_wasm`] — Low-level WASM execution with timeout, memory limits,
//!   and host I/O callback. No commitment logic. Pre-existing API.
//!
//! - [`run_wasm_committed`] — Wraps `run_wasm` (without modifying it) to
//!   produce a [`WasmExecutionResult`] containing all data required to
//!   construct an `ExecutionCommitment` for coordinator receipt signing.
//!
//! ## Execution Commitment Pipeline
//!
//! ```text
//! ┌─── run_wasm_committed() ─────────────────────────────────────────────┐
//! │                                                                       │
//! │  Input Bytes ──────► hash_input(input_bytes)                         │
//! │  (workload data)     prefix: DSDN:wasm_input:v1:                     │
//! │       │               → input_hash [u8; 32]                          │
//! │       │                                                               │
//! │  Module Bytes ─────► hash_memory_snapshot(module_bytes)               │
//! │  (WASM bytecode)     prefix: DSDN:wasm_memory:v1:                    │
//! │       │               → state_root_before [u8; 32]  (V1 proxy)      │
//! │       │                                                               │
//! │       ▼                                                               │
//! │  ┌─────────────────┐  Instant::now() ─────► start timer              │
//! │  │                 │                                                  │
//! │  │    run_wasm()   │  wasmtime: compile → instantiate → execute      │
//! │  │   (UNCHANGED)   │  spawned thread + recv_timeout                  │
//! │  │                 │  env::write(ptr,len) → stdout buffer            │
//! │  │                 │                                                  │
//! │  └────────┬────────┘  elapsed ────────────► stop timer               │
//! │           │                                                           │
//! │           │  Output { stdout: Vec<u8> }                              │
//! │           │                                                           │
//! │           ├──► hash_output(stdout)                                    │
//! │           │    prefix: DSDN:wasm_output:v1:                          │
//! │           │     → output_hash [u8; 32]                               │
//! │           │                                                           │
//! │           ├──► hash_memory_snapshot(stdout)                           │
//! │           │    prefix: DSDN:wasm_memory:v1:                          │
//! │           │     → state_root_after [u8; 32]  (V1 proxy)             │
//! │           │                                                           │
//! │           ├──► trace = [input_bytes, stdout]  (V1 minimal)           │
//! │           │     → compute_trace_merkle_root(&trace)                  │
//! │           │     → execution_trace_merkle_root [u8; 32]               │
//! │           │                                                           │
//! │           └──► ResourceUsage {                                        │
//! │                  execution_time_ms: elapsed (wall-clock),             │
//! │                  cpu_cycles_estimate: ms * 1_000_000 (checked_mul),   │
//! │                  peak_memory_bytes: module_bytes.len() as u64,        │
//! │                }                                                      │
//! │                                                                       │
//! │  ┌───────────────────────────────────────────────────────────┐       │
//! │  │                 WasmExecutionResult                        │       │
//! │  │  workload_id ─────────────────────────────────────────┐   │       │
//! │  │  input_hash ──────────────────────────────────────┐   │   │       │
//! │  │  output_hash ─────────────────────────────────┐   │   │   │       │
//! │  │  state_root_before ───────────────────────┐   │   │   │   │       │
//! │  │  state_root_after ────────────────────┐   │   │   │   │   │       │
//! │  │  execution_trace_merkle_root ─────┐   │   │   │   │   │   │       │
//! │  │  execution_trace (operational)    │   │   │   │   │   │   │       │
//! │  │  stdout (operational)             │   │   │   │   │   │   │       │
//! │  │  resource_usage (operational)     │   │   │   │   │   │   │       │
//! │  └───────────────────────────────────┼───┼───┼───┼───┼───┼───┘       │
//! │                                      │   │   │   │   │   │           │
//! │         to_execution_commitment()    │   │   │   │   │   │           │
//! │         (1:1 field mapping)          ▼   ▼   ▼   ▼   ▼   ▼           │
//! │                                                                       │
//! │  ┌───────────────────────────────────────────────────────────┐       │
//! │  │           ExecutionCommitment (dsdn_common)                │       │
//! │  │  6 fields, 192 bytes, Copy                                │       │
//! │  │                                                            │       │
//! │  │  compute_hash() → SHA3-256 of all 6 fields                │       │
//! │  │                   → commitment_hash [u8; 32]              │       │
//! │  └──────────────────────────┬────────────────────────────────┘       │
//! │                              │                                        │
//! │                              ▼                                        │
//! │                   Coordinator receipt signing pipeline                │
//! └───────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Modules
//!
//! | Module | Purpose | Determinism Role | Dependencies |
//! |--------|---------|------------------|--------------|
//! | [`execution_result`] | [`WasmExecutionResult`], [`ResourceUsage`] types + commitment bridge (14C.B.1, 14C.B.5) | Holds all commitment fields; bridge maps to `ExecutionCommitment` | `dsdn_common` |
//! | [`merkle`] | [`compute_trace_merkle_root`] — binary SHA3-256 Merkle tree (14C.B.1) | Byte-identical algorithm to coordinator; consensus-critical | `sha3` |
//! | [`state_capture`] | [`hash_input`], [`hash_output`], [`hash_memory_snapshot`] — domain-separated SHA3-256 (14C.B.2) | Unique domain prefixes prevent cross-context collisions; pure functions | `sha3` |
//! | [`trace_recorder`] | [`ExecutionTraceRecorder`] — step accumulator with finalize-time Merkle (14C.B.3) | Preserves insertion order; defers hashing to finalize | [`merkle`] |
//! | [`committed_execution`] | [`run_wasm_committed`] — wrapper producing [`WasmExecutionResult`] (14C.B.4) | Wraps `run_wasm` without modification; assembles all commitment fields | [`state_capture`], [`merkle`], [`execution_result`] |
//! | (root) | [`run_wasm`] — low-level WASM/WASI execution (pre-existing) | Deterministic WASM execution via wasmtime; no commitment logic | `wasmtime`, `wasmtime_wasi` |
//!
//! Also exports: [`RuntimeLimits`], [`RuntimeError`], [`RuntimeResult`], [`Output`].
//!
//! ## Determinism Guarantees
//!
//! The critical fraud-proof invariant:
//!
//! > **Same WASM module + same input → byte-identical `ExecutionCommitment`**
//!
//! This is guaranteed by the following architectural properties:
//!
//! 1. **Domain-separated hashing** — Each hash function uses a unique ASCII
//!    prefix (`DSDN:wasm_input:v1:`, `DSDN:wasm_output:v1:`,
//!    `DSDN:wasm_memory:v1:`). Identical bytes hashed in different contexts
//!    produce different digests. SHA3-256 (FIPS 202) is the sole hash
//!    function across all commitment-critical paths.
//!
//! 2. **Merkle tree determinism** — `compute_trace_merkle_root` is a pure
//!    function over an ordered slice of steps. Leaf order is preserved (no
//!    sorting). The duplicate-last rule for odd node counts is deterministic.
//!    Empty trace returns `[0u8; 32]` (zero hash sentinel).
//!
//! 3. **Execution trace ordering** — Steps are appended in execution order
//!    and never reordered. `ExecutionTraceRecorder` guarantees insertion
//!    order preservation. `finalize(self)` consumes the recorder to prevent
//!    post-finalize mutation.
//!
//! 4. **No randomness** — Zero use of random number generators, random seeds,
//!    or nondeterministic ordering in any commitment-critical code path.
//!
//! 5. **No time-based entropy in commitments** — `execution_time_ms` is
//!    wall-clock and nondeterministic, but it is NOT part of
//!    `ExecutionCommitment`. It feeds only into `ResourceUsage` for reward
//!    calculation, which is excluded from the commitment hash.
//!
//! 6. **Cross-node reproducibility** — Any node executing the same WASM
//!    module with the same input MUST produce the same `commitment_hash()`.
//!    This enables fraud-proof challenges where a verifier reproduces the
//!    execution and compares commitment hashes.
//!
//! 7. **Fraud-proof compatibility** — `commitment_hash()` returns the same
//!    32-byte SHA3-256 digest that the coordinator would compute from the
//!    same 6 commitment fields via `ExecutionCommitment::compute_hash()`.
//!    A mismatch triggers a challenge period with on-chain arbitration.
//!
//! Verified by 16 integration tests in `tests/determinism_tests.rs` (14C.B.6).
//!
//! ## V1 Limitations
//!
//! The current V1 implementation uses deterministic proxies for state capture.
//! These are sufficient for fraud-proof commitment consistency but do not
//! capture full execution state. V2 will replace proxies with full captures.
//!
//! | Feature | V1 Implementation | V1 Rationale | V2 Plan |
//! |---------|-------------------|--------------|---------|
//! | `state_root_before` | `hash_memory_snapshot(module_bytes)` | Post-instantiation memory is determined by module data segments | Full linear memory page dump via wasmtime `Store` access |
//! | `state_root_after` | `hash_memory_snapshot(stdout)` | Output is the primary observable effect of execution | Full linear memory page dump after execution completes |
//! | Execution trace | `[input_bytes, stdout]` — 2-element trace | Captures boundary conditions (what went in, what came out) | Instruction-level tracing via wasmtime epoch instrumentation |
//! | CPU cycles | `execution_time_ms * 1_000_000` via `checked_mul` | Wall-clock rough proxy; overflow returns `RuntimeError::Host` | wasmtime fuel consumption metering |
//! | Peak memory | `module_bytes.len() as u64` | Module size approximates initial memory allocation | wasmtime linear memory high-water mark tracking |
//! | TEE attestation | Not available | Hardware attestation not yet integrated | Hardware attestation integration (planned) |
//!
//! The proxy values are fully deterministic: same module + same input →
//! same proxy hashes. This is the requirement for fraud-proof challenges
//! in the V1 economic model.
//!
//! ## Relationship to Coordinator
//!
//! The coordinator crate contains `CommitmentBuilder` which also computes
//! Merkle roots and constructs `ExecutionCommitment` values. The following
//! cross-crate compatibility contracts MUST hold:
//!
//! 1. **Merkle algorithm identity** — `merkle::compute_trace_merkle_root` in
//!    this crate and `coordinator::execution::compute_trace_merkle_root` are
//!    byte-identical implementations of the same algorithm:
//!    leaf = `SHA3-256(step)`, parent = `SHA3-256(left || right)`,
//!    odd count = duplicate last, empty = `[0u8; 32]`.
//!    Same trace → same root. Verified by cross-crate determinism tests.
//!
//! 2. **`ExecutionCommitment` compatibility** —
//!    `WasmExecutionResult::to_execution_commitment()` produces values that
//!    the coordinator verifies via `ExecutionCommitment::compute_hash()`.
//!    The 6-field mapping is 1:1 with no transformation:
//!    `workload_id`, `input_hash`, `output_hash`, `state_root_before`,
//!    `state_root_after`, `execution_trace_merkle_root`.
//!
//! 3. **Domain separator consistency** — `hash_input` and `hash_output` use
//!    prefixes `DSDN:wasm_input:v1:` and `DSDN:wasm_output:v1:`. The VM
//!    runtime (`runtime_vm`) uses the same prefixes for cross-runtime
//!    commitment format compatibility.
//!
//! 4. **Commitment hash reproducibility** — Given a `WasmExecutionResult`,
//!    `commitment_hash()` returns the same 32-byte SHA3-256 digest that the
//!    coordinator computes from the same 6 fields via
//!    `ExecutionCommitment::compute_hash()`.
//!
//! ## ExecutionCommitment Bridge (14C.B.5)
//!
//! `WasmExecutionResult` provides two bridge methods:
//!
//! - `to_execution_commitment()` — 1:1 field mapping, no transformation.
//!   Maps 6 commitment fields. Excludes `execution_trace`, `stdout`,
//!   `resource_usage` (operational data, not commitment data).
//!
//! - `commitment_hash()` — shortcut for `to_execution_commitment().compute_hash()`.
//!
//! The runtime does not directly expose `ExecutionCommitment` because
//! `WasmExecutionResult` carries additional operational data needed by the
//! node layer. The bridge provides a clean conversion boundary: runtime
//! produces `WasmExecutionResult`, node extracts `ExecutionCommitment` via
//! bridge, coordinator verifies via `compute_hash()`.
//!
//! ## Test Coverage
//!
//! | Location | Tests | Scope |
//! |----------|-------|-------|
//! | `merkle.rs` (unit) | 10 | Merkle: empty, single, even, odd, determinism 100x, order |
//! | `execution_result.rs` (unit) | 13 | Struct construction, clone, debug, Send/Sync, commitment bridge |
//! | `state_capture.rs` (unit) | 10 | Domain separation, empty input, determinism 100x, no mutation |
//! | `trace_recorder.rs` (unit) | 10 | Empty, single, multi-step, order, finalize determinism 100x |
//! | `committed_execution.rs` (unit) | 11 | Full pipeline, hash consistency, resource usage, error propagation |
//! | `tests/determinism_tests.rs` (integration) | 16 | Cross-module determinism: 10x runs, 100x hashing, large input |
//! | `lib.rs` (unit) | 3 | `run_wasm` hello, timeout, memory limit |
//!
//! Total: 73 tests.

use anyhow::Result as AnyResult;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::thread;
use std::sync::mpsc;
use thiserror::Error;
use wasmtime::{Engine, Module, Store, Linker, Caller, Extern};
use wasmtime_wasi::{WasiCtxBuilder, WasiCtx};
use serde::{Serialize, Deserialize};

// ════════════════════════════════════════════════════════════════════════════════
// EXECUTION COMMITMENT MODULES (14C.B.1–14C.B.5)
// ════════════════════════════════════════════════════════════════════════════════

/// Execution result types and commitment bridge (14C.B.1, 14C.B.5).
///
/// Defines [`WasmExecutionResult`] — the carrier for all data required
/// to construct an `ExecutionCommitment` — and [`ResourceUsage`] for
/// V1 resource estimation. The commitment bridge methods
/// `to_execution_commitment()` and `commitment_hash()` provide 1:1
/// mapping to `dsdn_common::ExecutionCommitment`.
pub mod execution_result;

/// Deterministic binary Merkle tree (14C.B.1).
///
/// [`compute_trace_merkle_root`] computes a SHA3-256 binary Merkle root
/// over execution trace steps. Algorithm is byte-identical to
/// `coordinator::execution::compute_trace_merkle_root`:
/// leaf = `SHA3-256(step)`, parent = `SHA3-256(left || right)`,
/// odd count = duplicate last, empty = `[0u8; 32]`.
///
/// This is consensus-critical. Any divergence between the runtime and
/// coordinator implementations breaks fraud-proof reproducibility.
pub mod merkle;

/// Domain-separated SHA3-256 hashing for WASM execution state (14C.B.2).
///
/// Provides three pure hashing functions with distinct domain prefixes:
/// - [`hash_input`]: prefix `DSDN:wasm_input:v1:` — hash workload input before execution
/// - [`hash_output`]: prefix `DSDN:wasm_output:v1:` — hash captured stdout after execution
/// - [`hash_memory_snapshot`]: prefix `DSDN:wasm_memory:v1:` — hash WASM linear memory
///
/// Domain separation prevents cross-context collisions: identical bytes
/// hashed as "input" vs "output" produce different digests. The `v1`
/// version tag enables future scheme changes without breaking existing
/// commitments.
///
/// These hashes feed directly into [`WasmExecutionResult`] fields
/// (`input_hash`, `output_hash`, `state_root_before`, `state_root_after`)
/// and must be deterministic for fraud-proof reproducibility.
pub mod state_capture;

/// Incremental execution trace recorder (14C.B.3).
///
/// [`ExecutionTraceRecorder`] collects raw execution steps during WASM
/// execution without performing any hashing. At `finalize()` time, it
/// computes the Merkle root via [`compute_trace_merkle_root`] and returns
/// both the raw steps and the root.
///
/// Hashing is deferred to finalize because the binary Merkle tree algorithm
/// requires all leaves to be known upfront (the duplicate-last rule depends
/// on total leaf count). Incremental hashing would require a different
/// algorithm that would diverge from the coordinator's batch algorithm.
///
/// `finalize(self)` consumes the recorder to prevent reuse after
/// finalization — no dangling state, no double-finalize.
pub mod trace_recorder;

/// Committed WASM execution wrapper (14C.B.4).
///
/// [`run_wasm_committed`] wraps [`run_wasm`] without modifying it. It adds
/// state capture (input/output hashing, state root computation), V1 minimal
/// execution trace, Merkle root computation, and resource usage estimation.
/// Returns [`WasmExecutionResult`] with all data needed to construct an
/// `ExecutionCommitment`.
///
/// ## V1 Proxy Rules
///
/// - `state_root_before`: `hash_memory_snapshot(module_bytes)` — proxy for
///   post-instantiation linear memory (determined by module data segments).
/// - `state_root_after`: `hash_memory_snapshot(stdout)` — proxy for
///   post-execution state (V2: full memory page dump via wasmtime Store).
/// - Execution trace: `[input_bytes, stdout_bytes]` — V2: instruction-level
///   tracing via wasmtime epoch instrumentation.
/// - Resource usage: wall-clock time * 1M for CPU cycles estimate.
///   V2: wasmtime fuel consumption metering.
///
/// ## Determinism
///
/// All commitment-critical fields are deterministic. `execution_time_ms`
/// is wall-clock (non-deterministic) but does not affect commitment hash.
pub mod committed_execution;

// ════════════════════════════════════════════════════════════════════════════════
// RE-EXPORTS
// ════════════════════════════════════════════════════════════════════════════════

/// Re-exported from [`execution_result`]: WASM execution result carrier
/// and V1 resource usage estimation.
pub use execution_result::{WasmExecutionResult, ResourceUsage};

/// Re-exported from [`merkle`]. Consensus-critical: byte-identical to
/// coordinator's `compute_trace_merkle_root` algorithm.
pub use merkle::compute_trace_merkle_root;

/// Re-exported from [`state_capture`]: domain-separated SHA3-256 hashing
/// with prefixes `DSDN:wasm_input:v1:`, `DSDN:wasm_output:v1:`,
/// `DSDN:wasm_memory:v1:`.
pub use state_capture::{hash_input, hash_output, hash_memory_snapshot};

/// Re-exported from [`trace_recorder`]: incremental step recorder with
/// finalize-time Merkle root computation.
pub use trace_recorder::ExecutionTraceRecorder;

/// Re-exported from [`committed_execution`]: commitment-producing WASM
/// execution wrapper that calls [`run_wasm`] internally.
pub use committed_execution::run_wasm_committed;

// ════════════════════════════════════════════════════════════════════════════════
// CORE RUNTIME TYPES
// ════════════════════════════════════════════════════════════════════════════════

/// Resource limits for WASM module execution.
///
/// Controls maximum wall-clock execution time and initial linear memory size.
/// Used by both [`run_wasm`] and [`run_wasm_committed`].
///
/// ## Defaults
///
/// - `timeout_ms`: 2000 (2 seconds)
/// - `max_memory_bytes`: 16 MiB (16,777,216 bytes)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeLimits {
    /// Maximum execution time (wall clock) in milliseconds.
    /// Enforced via `recv_timeout` on the execution thread channel.
    pub timeout_ms: u64,
    /// Maximum initial linear memory in bytes.
    /// Enforced after instantiation by checking exported memory page count.
    /// Each WASM page is 65,536 bytes.
    pub max_memory_bytes: usize,
}

impl Default for RuntimeLimits {
    fn default() -> Self {
        RuntimeLimits {
            timeout_ms: 2000,
            max_memory_bytes: 16 * 1024 * 1024, // 16 MiB default
        }
    }
}

/// Output from WASM module execution.
///
/// Contains bytes written by the guest via the `env::write` host function.
/// Produced by [`run_wasm`] and consumed internally by [`run_wasm_committed`].
#[derive(Debug, Clone)]
pub struct Output {
    /// Bytes that the WASM guest wrote via the `env::write(ptr, len)`
    /// host function during execution. Empty if no writes occurred.
    pub stdout: Vec<u8>,
}

/// Errors from WASM runtime execution.
///
/// Covers all failure modes of [`run_wasm`] and [`run_wasm_committed`]:
/// compilation, resource limits, timeouts, guest traps, and host errors.
/// Used as the error type in [`RuntimeResult`].
#[derive(Error, Debug)]
pub enum RuntimeError {
    /// WASM module failed validation or compilation via wasmtime.
    #[error("wasm validation/compile error: {0}")]
    CompileError(String),

    /// Module's initial linear memory exceeds [`RuntimeLimits::max_memory_bytes`].
    /// First value is bytes requested, second is the configured limit.
    #[error("module requested too much memory: {0} bytes (limit {1})")]
    MemoryLimitExceeded(usize, usize),

    /// Execution exceeded the wall-clock timeout ([`RuntimeLimits::timeout_ms`]).
    #[error("execution timeout after {0}ms")]
    Timeout(u64),

    /// WASM guest trapped during execution (unreachable, division by zero, etc).
    #[error("guest runtime error: {0}")]
    Trap(String),

    /// Host-side error: linker setup, callback failure, or resource overflow.
    /// Also used by [`run_wasm_committed`] for CPU cycles `checked_mul` overflow.
    #[error("host error: {0}")]
    Host(String),
}

/// Result type alias for WASM runtime operations.
///
/// Used by [`run_wasm`] and [`run_wasm_committed`].
pub type RuntimeResult<T> = std::result::Result<T, RuntimeError>;

// ════════════════════════════════════════════════════════════════════════════════
// LOW-LEVEL WASM EXECUTION (PRE-EXISTING)
// ════════════════════════════════════════════════════════════════════════════════

/// Runs a WASM/WASI module with resource limits and a host I/O callback.
///
/// This is the low-level execution function used internally by
/// [`run_wasm_committed`]. It does not produce commitment data.
///
/// ## Implementation
///
/// 1. Compile module via wasmtime `Engine` + `Module`.
/// 2. Instantiate with WASI context and `env::write(ptr, len)` host function.
/// 3. After instantiation, check exported memory page count against
///    [`RuntimeLimits::max_memory_bytes`].
/// 4. Call exported `"run"` or `"_start"` function in a spawned thread.
/// 5. Wait with `recv_timeout` for wall-clock timeout enforcement.
/// 6. On success, invoke `host_write` callback with captured stdout.
///
/// ## Arguments
///
/// * `module_bytes` — Raw WASM module bytecode.
/// * `_input` — Workload input (reserved for future use; currently unused).
/// * `limits` — Timeout and memory limits.
/// * `host_write` — Callback invoked with captured stdout bytes on success.
///
/// ## Errors
///
/// Returns [`RuntimeError`] variants for compilation failure,
/// memory limit exceeded, timeout, guest trap, or host callback error.
///
/// ## Determinism
///
/// WASM execution via wasmtime is deterministic for the same module and
/// input. However, this function does not capture state for commitment
/// production — use [`run_wasm_committed`] for that purpose.
pub fn run_wasm<F>(
    module_bytes: &[u8],
    _input: &[u8],
    limits: RuntimeLimits,
    mut host_write: F,
) -> RuntimeResult<Output>
where
    F: FnMut(&[u8]) -> AnyResult<()> + Send + 'static,
{
    // compile module first (syntax/validation)
    let engine = Engine::default();
    let _module = Module::new(&engine, module_bytes)
        .map_err(|e| RuntimeError::CompileError(format!("failed to compile module: {}", e)))?;

    // channel for thread result
    let (tx, rx) = mpsc::sync_channel::<Result<Output, RuntimeError>>(1);

    // Move bytes into thread
    let module_owned = module_bytes.to_vec();

    thread::spawn(move || {
        let res = (|| -> RuntimeResult<Output> {
            // re-create engine/module in thread to avoid sharing store across threads
            let engine = Engine::default();
            let module = Module::new(&engine, &module_owned)
                .map_err(|e| RuntimeError::CompileError(format!("compile error(thread): {}", e)))?;

            // prepare linker + wasi
            let mut linker = Linker::new(&engine);

            // host-captured output buffer (thread-local)
            let out_buf = Arc::new(Mutex::new(Vec::<u8>::new()));
            let out_clone = out_buf.clone();

            // host function env::write(ptr: i32, len: i32)
            // we will panic!() on error so that wasmtime yields a trap (panics inside host func -> trap)
            linker.func_wrap(
                "env",
                "write",
                move |mut caller: Caller<'_, WasiCtx>, ptr: i32, len: i32| {
                    // get memory export
                    let mem = match caller.get_export("memory") {
                        Some(Extern::Memory(m)) => m,
                        _ => panic!("wasm guest expects exported memory"),
                    };

                    let start = ptr as usize;
                    let len = len as usize;
                    let mut tmp = vec![0u8; len];
                    // read using caller as context
                    mem.read(&mut caller, start, &mut tmp)
                        .expect("memory read failed");
                    // append to buffer
                    let mut guard = out_clone.lock().expect("lock poisoned");
                    guard.extend_from_slice(&tmp);
                },
            ).map_err(|e| RuntimeError::Host(format!("failed to add host func: {}", e)))?;

            // wasi ctx
            let wasi = WasiCtxBuilder::new().inherit_stdout().inherit_stderr().build();
            wasmtime_wasi::add_to_linker(&mut linker, |s: &mut WasiCtx| s)
                .map_err(|e| RuntimeError::Host(format!("wasi linker failed: {}", e)))?;

            // create store with wasi ctx
            let mut store = Store::new(&engine, wasi);

            // instantiate
            let instance = linker
                .instantiate(&mut store, &module)
                .map_err(|e| RuntimeError::Trap(format!("instantiate error: {}", e)))?;

            // after instantiation, check memory size (if any)
            if let Some(mem) = instance.get_memory(&mut store, "memory") {
                // memory.size returns pages (u64)
                let pages = mem.size(&mut store);
                // pages * 65536 -> bytes
                let bytes_needed = pages as usize * 65536usize;
                if bytes_needed > limits.max_memory_bytes {
                    return Err(RuntimeError::MemoryLimitExceeded(bytes_needed, limits.max_memory_bytes));
                }
            }

            // call exported function "run" if exists, else call "_start" if exists
            if let Some(func) = instance.get_func(&mut store, "run") {
                // try call run()
                let call_res = func.call(&mut store, &[], &mut []);
                if let Err(e) = call_res {
                    return Err(RuntimeError::Trap(format!("run trap: {}", e)));
                }
            } else if let Some(start) = instance.get_func(&mut store, "_start") {
                let call_res = start.call(&mut store, &[], &mut []);
                if let Err(e) = call_res {
                    return Err(RuntimeError::Trap(format!("_start trap: {}", e)));
                }
            } else {
                // nothing to call — allowed
            }

            // collect output
            let out_vec = match out_buf.lock() {
                Ok(g) => g.clone(),
                Err(_) => vec![],
            };

            Ok(Output { stdout: out_vec })
        })();

        // send back result (ignore send error)
        let _ = tx.send(res);
    });

    // wait with timeout
    let timeout = Duration::from_millis(limits.timeout_ms);
    match rx.recv_timeout(timeout) {
        Ok(Ok(output)) => {
            // call host_write with captured stdout (user callback)
            if !output.stdout.is_empty() {
                if let Err(e) = host_write(&output.stdout) {
                    return Err(RuntimeError::Host(format!("host callback error: {}", e)));
                }
            }
            Ok(output)
        }
        Ok(Err(e)) => Err(e),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(RuntimeError::Timeout(limits.timeout_ms)),
        Err(e) => Err(RuntimeError::Host(format!("recv error: {}", e))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use wat::parse_str;

    #[test]
    fn test_run_hello() {
        let wat = r#"
        (module
            (import "env" "write" (func $write (param i32 i32)))
            (memory (export "memory") 1)
            (data (i32.const 0) "Hello from WASM!")
            (func (export "run")
                i32.const 0
                i32.const 16
                call $write
            )
        )
        "#;
        let wasm = parse_str(wat).expect("wat->wasm");

        let limits = RuntimeLimits {
            timeout_ms: 1500,
            max_memory_bytes: 1 * 65536,
        };

        let captured = Arc::new(Mutex::new(Vec::<u8>::new()));
        let cap_clone = captured.clone();

        let res = run_wasm(&wasm, &[], limits.clone(), move |out: &[u8]| {
            let mut g = cap_clone.lock().map_err(|e| anyhow::anyhow!("lock err: {}", e))?;
            g.extend_from_slice(out);
            Ok(())
        });

        assert!(res.is_ok());

        let got = captured.lock().unwrap();
        let s = String::from_utf8_lossy(&got);

        assert_eq!(&s[..], "Hello from WASM!");
    }


    #[test]
    fn test_timeout() {
        let wat = r#"
        (module
            (func (export "run")
                (loop
                    br 0
                )
            )
        )
        "#;
        let wasm = parse_str(wat).expect("wat->wasm");

        let limits = RuntimeLimits {
            timeout_ms: 50,
            max_memory_bytes: 64 * 1024,
        };

        let res = run_wasm(&wasm, &[], limits, |_out| Ok(()));
        match res {
            Err(RuntimeError::Timeout(_)) => {}
            _ => panic!("expected timeout"),
        }
    }

    #[test]
    fn test_memory_limit_exceeded_rejected() {
        // declare memory 1000 pages (~64MB)
        let wat = r#"
        (module
            (memory (export "memory") 1000)
            (func (export "run") )
        )
        "#;
        let wasm = parse_str(wat).expect("wat->wasm");
        let limits = RuntimeLimits {
            timeout_ms: 1000,
            max_memory_bytes: 16 * 1024 * 1024,
        };
        let res = run_wasm(&wasm, &[], limits, |_out| Ok(()));
        match res {
            Err(RuntimeError::MemoryLimitExceeded(_needed, _limit)) => {}
            _ => panic!("expected memory limit error"),
        }
    }
}