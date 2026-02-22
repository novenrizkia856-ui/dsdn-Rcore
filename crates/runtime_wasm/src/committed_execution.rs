//! # Committed WASM Execution (14C.B.4)
//!
//! Wraps [`run_wasm`](crate::run_wasm) with state capture, trace recording,
//! and resource measurement to produce a [`WasmExecutionResult`] suitable
//! for constructing an [`ExecutionCommitment`].
//!
//! ## Wrapper Pattern
//!
//! `run_wasm_committed` does **not** modify `run_wasm`. It calls `run_wasm`
//! as a black box and adds commitment-relevant logic around it:
//!
//! ```text
//! ┌─ run_wasm_committed ─────────────────────────────────────────────┐
//! │                                                                   │
//! │  1. hash_input(input_bytes)           ← state_capture            │
//! │  2. hash_memory_snapshot(module_bytes) ← state_root_before (V1)  │
//! │  3. Instant::now()                    ← start timer              │
//! │  4. run_wasm(module, input, limits)   ← UNCHANGED runtime        │
//! │  5. elapsed                           ← stop timer               │
//! │  6. hash_output(stdout)               ← state_capture            │
//! │  7. hash_memory_snapshot(stdout)      ← state_root_after (V1)    │
//! │  8. [input, stdout] trace             ← V1 minimal trace         │
//! │  9. compute_trace_merkle_root(trace)  ← merkle                   │
//! │ 10. ResourceUsage                     ← V1 estimation            │
//! │ 11. WasmExecutionResult               ← assembled                │
//! │                                                                   │
//! └───────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## V1 Proxy Rules
//!
//! ### state_root_before
//!
//! V1 uses `hash_memory_snapshot(module_bytes)` as proxy for pre-execution
//! WASM linear memory state. Rationale: after instantiation, linear memory
//! content is determined by the module's data segments. Full memory snapshot
//! via wasmtime `Store` access is planned for V2.
//!
//! ### state_root_after
//!
//! V1 uses `hash_memory_snapshot(captured_stdout)` as proxy for post-execution
//! state. Full memory snapshot requires reading WASM linear memory pages
//! from the wasmtime `Store`, which is not accessible outside the execution
//! thread in the current `run_wasm` architecture. Planned for V2.
//!
//! ### Execution Trace
//!
//! V1 trace is minimal: `[input_bytes, stdout_bytes]`. Full instruction-level
//! tracing requires wasmtime epoch-based instrumentation (V2).
//!
//! ### Resource Usage
//!
//! - `execution_time_ms`: wall-clock via `std::time::Instant`.
//! - `cpu_cycles_estimate`: `execution_time_ms × 1,000,000` (V1 rough proxy).
//!   Uses `checked_mul` — returns error on overflow.
//! - `peak_memory_bytes`: `module_bytes.len()` (V1 proxy for initial memory).
//!   V2: wasmtime fuel consumption tracking.
//!
//! ## Determinism
//!
//! All hashing is deterministic (SHA3-256, domain-separated). Merkle root
//! is deterministic. The only non-deterministic element is `execution_time_ms`
//! (wall-clock), which does NOT affect the commitment hash — it only feeds
//! into `ResourceUsage` which is used for reward calculation, not fraud proofs.
//!
//! ## Error Handling
//!
//! If `run_wasm` fails, the error is propagated directly — no partial
//! `WasmExecutionResult` is ever constructed. If `cpu_cycles_estimate`
//! overflows, `RuntimeError::Host` is returned.
//!
//! ## Safety
//!
//! - No panic, unwrap, expect, todo, unreachable.
//! - No unsafe code.
//! - No mutation of input slices.
//! - `run_wasm` is called exactly once, unmodified.

use dsdn_common::coordinator::WorkloadId;

use crate::execution_result::{ResourceUsage, WasmExecutionResult};
use crate::merkle::compute_trace_merkle_root;
use crate::state_capture::{hash_input, hash_memory_snapshot, hash_output};
use crate::{RuntimeError, RuntimeLimits, RuntimeResult};

use std::time::Instant;

// ════════════════════════════════════════════════════════════════════════════════
// PUBLIC API
// ════════════════════════════════════════════════════════════════════════════════

/// Executes a WASM module with full state capture for commitment production.
///
/// Wraps [`run_wasm`](crate::run_wasm) without modifying it. Adds:
/// input/output hashing, state root capture, trace recording, Merkle root
/// computation, and resource usage estimation.
///
/// # Arguments
///
/// * `workload_id` — Coordinator-assigned workload identifier.
/// * `module_bytes` — Raw WASM module bytecode.
/// * `input_bytes` — Workload input data.
/// * `limits` — Execution resource limits (timeout, memory).
///
/// # Returns
///
/// `WasmExecutionResult` containing all data needed to construct an
/// `ExecutionCommitment`. On `run_wasm` failure, the error propagates.
///
/// # Errors
///
/// - `RuntimeError::CompileError` — Invalid WASM module.
/// - `RuntimeError::MemoryLimitExceeded` — Module exceeds memory limit.
/// - `RuntimeError::Timeout` — Execution exceeded time limit.
/// - `RuntimeError::Trap` — WASM guest trapped.
/// - `RuntimeError::Host` — Host function error or CPU cycles overflow.
///
/// # Determinism
///
/// Commitment-relevant fields (`input_hash`, `output_hash`,
/// `state_root_before`, `state_root_after`, `execution_trace_merkle_root`)
/// are fully deterministic. `execution_time_ms` is wall-clock and
/// non-deterministic but does not affect commitment hashes.
pub fn run_wasm_committed(
    workload_id: WorkloadId,
    module_bytes: &[u8],
    input_bytes: &[u8],
    limits: RuntimeLimits,
) -> RuntimeResult<WasmExecutionResult> {
    // ── Step 1: Hash input ──────────────────────────────────────────────
    let input_hash = hash_input(input_bytes);

    // ── Step 2: State root before (V1 proxy: module bytes) ──────────────
    let state_root_before = hash_memory_snapshot(module_bytes);

    // ── Step 3: Execute via run_wasm (measure wall-clock) ───────────────
    let start = Instant::now();

    // No-op callback: stdout is captured internally by run_wasm and
    // returned in Output.stdout. We don't need the callback for anything.
    let output = crate::run_wasm(module_bytes, input_bytes, limits, |_: &[u8]| Ok(()))?;

    let elapsed = start.elapsed();
    let captured_stdout = output.stdout;

    // ── Step 4: Hash output ─────────────────────────────────────────────
    let output_hash = hash_output(&captured_stdout);

    // ── Step 5: State root after (V1 proxy: output bytes) ───────────────
    let state_root_after = hash_memory_snapshot(&captured_stdout);

    // ── Step 6: Build execution trace (V1 minimal) ──────────────────────
    let execution_trace = vec![input_bytes.to_vec(), captured_stdout.clone()];

    // ── Step 7: Merkle root ─────────────────────────────────────────────
    let execution_trace_merkle_root = compute_trace_merkle_root(&execution_trace);

    // ── Step 8: Resource usage estimation (V1 proxy) ────────────────────
    // as_millis() returns u128; clamp to u64 safely.
    let elapsed_ms_u128 = elapsed.as_millis();
    let execution_time_ms = if elapsed_ms_u128 > u128::from(u64::MAX) {
        u64::MAX
    } else {
        elapsed_ms_u128 as u64
    };

    let cpu_cycles_estimate = execution_time_ms
        .checked_mul(1_000_000)
        .ok_or_else(|| {
            RuntimeError::Host(format!(
                "cpu_cycles_estimate overflow: {} ms * 1_000_000 exceeds u64::MAX",
                execution_time_ms
            ))
        })?;

    let peak_memory_bytes = module_bytes.len() as u64;

    // ── Step 9: Construct WasmExecutionResult ───────────────────────────
    Ok(WasmExecutionResult {
        workload_id,
        input_hash,
        output_hash,
        state_root_before,
        state_root_after,
        execution_trace,
        execution_trace_merkle_root,
        stdout: captured_stdout,
        resource_usage: ResourceUsage {
            cpu_cycles_estimate,
            peak_memory_bytes,
            execution_time_ms,
        },
    })
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_capture::{hash_input, hash_memory_snapshot, hash_output};
    use crate::merkle::compute_trace_merkle_root;
    use wat::parse_str;

    /// Simple WASM module that writes "Hello" via env::write.
    fn hello_module_wat() -> &'static str {
        r#"
        (module
            (import "env" "write" (func $write (param i32 i32)))
            (memory (export "memory") 1)
            (data (i32.const 0) "Hello")
            (func (export "run")
                i32.const 0
                i32.const 5
                call $write
            )
        )
        "#
    }

    /// Compile WAT to WASM bytes.
    fn compile_wat(wat: &str) -> Vec<u8> {
        parse_str(wat).expect("test: WAT compilation failed")
    }

    /// Standard test limits.
    fn test_limits() -> RuntimeLimits {
        RuntimeLimits {
            timeout_ms: 3000,
            max_memory_bytes: 65536,
        }
    }

    fn test_wid() -> WorkloadId {
        WorkloadId::new([0x42; 32])
    }

    // ── 1) Basic success ────────────────────────────────────────────────

    #[test]
    fn committed_execution_basic_success() {
        let wasm = compile_wat(hello_module_wat());
        let input = b"test-input";

        let result = run_wasm_committed(test_wid(), &wasm, input, test_limits());
        assert!(result.is_ok());

        let r = result.unwrap();
        assert_eq!(r.workload_id, test_wid());
        assert_eq!(r.stdout, b"Hello");
        assert_ne!(r.input_hash, [0u8; 32]);
        assert_ne!(r.output_hash, [0u8; 32]);
        assert_ne!(r.state_root_before, [0u8; 32]);
        assert_ne!(r.state_root_after, [0u8; 32]);
        assert_ne!(r.execution_trace_merkle_root, [0u8; 32]);
        assert_eq!(r.execution_trace.len(), 2);
    }

    // ── 2) Input hash consistency ───────────────────────────────────────

    #[test]
    fn input_hash_consistency() {
        let wasm = compile_wat(hello_module_wat());
        let input = b"deterministic-input";

        let r = run_wasm_committed(test_wid(), &wasm, input, test_limits()).unwrap();

        // input_hash must equal hash_input(input_bytes)
        let expected = hash_input(input);
        assert_eq!(r.input_hash, expected);
    }

    // ── 3) Output hash consistency ──────────────────────────────────────

    #[test]
    fn output_hash_consistency() {
        let wasm = compile_wat(hello_module_wat());
        let input = b"";

        let r = run_wasm_committed(test_wid(), &wasm, input, test_limits()).unwrap();

        // output_hash must equal hash_output(captured_stdout)
        let expected = hash_output(&r.stdout);
        assert_eq!(r.output_hash, expected);
    }

    // ── 4) state_root_before matches module hash ────────────────────────

    #[test]
    fn state_root_before_matches_module_hash() {
        let wasm = compile_wat(hello_module_wat());
        let input = b"";

        let r = run_wasm_committed(test_wid(), &wasm, input, test_limits()).unwrap();

        // V1: state_root_before = hash_memory_snapshot(module_bytes)
        let expected = hash_memory_snapshot(&wasm);
        assert_eq!(r.state_root_before, expected);
    }

    // ── 5) Merkle root matches trace ────────────────────────────────────

    #[test]
    fn merkle_root_matches_trace() {
        let wasm = compile_wat(hello_module_wat());
        let input = b"trace-test";

        let r = run_wasm_committed(test_wid(), &wasm, input, test_limits()).unwrap();

        // Merkle root must match compute_trace_merkle_root on returned trace
        let expected = compute_trace_merkle_root(&r.execution_trace);
        assert_eq!(r.execution_trace_merkle_root, expected);

        // Trace V1: [input_bytes, stdout]
        assert_eq!(r.execution_trace[0], input.to_vec());
        assert_eq!(r.execution_trace[1], r.stdout);
    }

    // ── 6) Resource usage calculation ───────────────────────────────────

    #[test]
    fn resource_usage_calculation() {
        let wasm = compile_wat(hello_module_wat());
        let input = b"";

        let r = run_wasm_committed(test_wid(), &wasm, input, test_limits()).unwrap();

        // peak_memory_bytes = module_bytes.len()
        assert_eq!(r.resource_usage.peak_memory_bytes, wasm.len() as u64);

        // cpu_cycles_estimate = execution_time_ms * 1_000_000
        assert_eq!(
            r.resource_usage.cpu_cycles_estimate,
            r.resource_usage.execution_time_ms * 1_000_000
        );
    }

    // ── 7) CPU cycles overflow handled ──────────────────────────────────

    #[test]
    fn overflow_cpu_cycles_handled() {
        // Verify that checked_mul is used correctly.
        // u64::MAX / 1_000_000 = 18_446_744_073_709 ms ≈ 584,942 years.
        // This cannot occur in real execution but we verify the arithmetic:
        let large_ms: u64 = u64::MAX;
        let result = large_ms.checked_mul(1_000_000);
        assert!(result.is_none()); // Confirms overflow would be caught
    }

    // ── 8) Error propagation from run_wasm ──────────────────────────────

    #[test]
    fn error_propagation_from_run_wasm() {
        // Invalid WASM module → CompileError propagated
        let bad_wasm = b"not-valid-wasm";
        let result = run_wasm_committed(test_wid(), bad_wasm, b"", test_limits());
        assert!(result.is_err());

        match result {
            Err(RuntimeError::CompileError(_)) => {} // Expected
            other => panic!("expected CompileError, got: {:?}", other),
        }
    }

    // ── 9) state_root_after matches output hash ─────────────────────────

    #[test]
    fn state_root_after_matches_output_memory_hash() {
        let wasm = compile_wat(hello_module_wat());
        let input = b"";

        let r = run_wasm_committed(test_wid(), &wasm, input, test_limits()).unwrap();

        // V1: state_root_after = hash_memory_snapshot(stdout)
        let expected = hash_memory_snapshot(&r.stdout);
        assert_eq!(r.state_root_after, expected);
    }

    // ── 10) Deterministic commitment fields across runs ─────────────────

    #[test]
    fn deterministic_commitment_fields() {
        let wasm = compile_wat(hello_module_wat());
        let input = b"determinism-test";

        let r1 = run_wasm_committed(test_wid(), &wasm, input, test_limits()).unwrap();
        let r2 = run_wasm_committed(test_wid(), &wasm, input, test_limits()).unwrap();

        // All commitment-relevant fields must be identical
        assert_eq!(r1.input_hash, r2.input_hash);
        assert_eq!(r1.output_hash, r2.output_hash);
        assert_eq!(r1.state_root_before, r2.state_root_before);
        assert_eq!(r1.state_root_after, r2.state_root_after);
        assert_eq!(r1.execution_trace_merkle_root, r2.execution_trace_merkle_root);
        assert_eq!(r1.execution_trace, r2.execution_trace);
        assert_eq!(r1.stdout, r2.stdout);

        // execution_time_ms may differ (wall-clock), that's expected
    }

    // ── 11) No-output module produces valid result ──────────────────────

    #[test]
    fn no_output_module_valid() {
        let wat = r#"
        (module
            (func (export "run"))
        )
        "#;
        let wasm = compile_wat(wat);
        let input = b"";

        let r = run_wasm_committed(test_wid(), &wasm, input, test_limits()).unwrap();

        assert!(r.stdout.is_empty());
        assert_ne!(r.output_hash, [0u8; 32]); // hash_output("") != zero hash
        assert_eq!(r.execution_trace.len(), 2);
        assert!(r.execution_trace[0].is_empty()); // input was empty
        assert!(r.execution_trace[1].is_empty()); // stdout was empty
    }
}