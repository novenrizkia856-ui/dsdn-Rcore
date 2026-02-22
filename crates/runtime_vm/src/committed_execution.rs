//! # Committed VM Execution (14C.B.9)
//!
//! Async wrapper around [`MicroVM::exec`](crate::MicroVM::exec) that produces
//! a [`VmExecutionResult`] with full state capture for commitment construction.
//!
//! ## Wrapper Pattern
//!
//! `exec_committed` does **not** modify `exec()`. It calls `exec()` as a
//! black box and adds commitment-relevant logic around it:
//!
//! ```text
//! ┌─ exec_committed ─────────────────────────────────────────────────┐
//! │                                                                   │
//! │  1. hash_input(input_bytes)            ← state_capture           │
//! │  2. SHA3-256(vm_state:before || input) ← state_root_before (V1) │
//! │  3. Instant::now()                     ← start timer             │
//! │  4. vm.exec(cmd, timeout_ms).await     ← UNCHANGED exec()       │
//! │  5. elapsed                            ← stop timer              │
//! │  6. hash_output(stdout)                ← state_capture           │
//! │  7. SHA3-256(vm_state:after || stdout) ← state_root_after (V1)  │
//! │  8. [input, stdout] trace              ← V1 minimal trace        │
//! │  9. compute_trace_merkle_root(trace)   ← merkle                  │
//! │ 10. VmResourceUsage                    ← V1 estimation           │
//! │ 11. VmExecutionResult                  ← assembled               │
//! │                                                                   │
//! └───────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## State Root Design (V1)
//!
//! VM state roots use VM-specific domain prefixes:
//! - `state_root_before`: `SHA3-256(b"DSDN:vm_state:v1:before:" || input_bytes)`
//! - `state_root_after`: `SHA3-256(b"DSDN:vm_state:v1:after:" || stdout)`
//!
//! These are V1 proxies. Full VM state capture (memory snapshot, filesystem
//! diff) is planned for V2.
//!
//! ## Relationship to WASM Committed Execution
//!
//! - `hash_input` and `hash_output` use the same cross-runtime domain
//!   separators (`DSDN:wasm_input:v1:`, `DSDN:wasm_output:v1:`).
//! - `compute_trace_merkle_root` is byte-identical to WASM/coordinator.
//! - `state_root_before/after` use VM-specific prefixes (different from WASM).
//! - The resulting `ExecutionCommitment` is verified by the same coordinator
//!   logic regardless of runtime origin.
//!
//! ## Determinism
//!
//! Commitment-critical fields (`input_hash`, `output_hash`,
//! `state_root_before`, `state_root_after`, `execution_trace_merkle_root`)
//! are fully deterministic. `execution_time_ms` is wall-clock and
//! non-deterministic but does not affect commitment hashes.
//!
//! ## Error Handling
//!
//! If `exec()` fails, the error is propagated directly. No partial
//! `VmExecutionResult` is ever constructed. If `cpu_cycles_estimate`
//! overflows, `MicroVmError::Other` is returned.

use dsdn_common::coordinator::WorkloadId;
use sha3::{Digest, Sha3_256};

use crate::execution_result::{VmExecutionResult, VmResourceUsage};
use crate::merkle::compute_trace_merkle_root;
use crate::state_capture::{hash_input, hash_output};
use crate::{MicroVM, MicroVmError, MicroVmResult};

use std::time::Instant;

// ════════════════════════════════════════════════════════════════════════════════
// DOMAIN PREFIXES (VM-specific, consensus-critical)
// ════════════════════════════════════════════════════════════════════════════════

/// Domain prefix for VM pre-execution state root. Consensus-critical.
const VM_STATE_BEFORE_PREFIX: &[u8] = b"DSDN:vm_state:v1:before:";

/// Domain prefix for VM post-execution state root. Consensus-critical.
const VM_STATE_AFTER_PREFIX: &[u8] = b"DSDN:vm_state:v1:after:";

/// Domain-separated SHA3-256: `SHA3-256(prefix || data)`.
fn domain_hash(prefix: &[u8], data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(prefix);
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// ════════════════════════════════════════════════════════════════════════════════
// PUBLIC API
// ════════════════════════════════════════════════════════════════════════════════

/// Executes a VM command with full state capture for commitment production.
///
/// Wraps [`MicroVM::exec`] without modifying it. Adds: input/output hashing,
/// state root capture, trace recording, Merkle root computation, and resource
/// usage estimation.
///
/// # Arguments
///
/// * `vm` — Any [`MicroVM`] implementation (e.g., `MockVMController`).
/// * `workload_id` — Coordinator-assigned workload identifier.
/// * `cmd` — Command to execute inside the VM.
/// * `input_bytes` — Workload input data (hashed for commitment).
/// * `timeout_ms` — Optional wall-clock timeout for `exec()`.
///
/// # Returns
///
/// `VmExecutionResult` containing all data needed to construct an
/// `ExecutionCommitment`. On `exec()` failure, the error propagates.
///
/// # Errors
///
/// - `MicroVmError::Process` — VM process error.
/// - `MicroVmError::Other` — CPU cycles overflow or other host error.
///
/// # Determinism
///
/// Commitment-relevant fields are fully deterministic.
/// `execution_time_ms` is wall-clock (non-deterministic) but does not
/// affect commitment hashes.
pub async fn exec_committed(
    vm: &dyn MicroVM,
    workload_id: WorkloadId,
    cmd: Vec<String>,
    input_bytes: &[u8],
    timeout_ms: Option<u64>,
) -> MicroVmResult<VmExecutionResult> {
    // ── Step 1: Hash input ──────────────────────────────────────────────
    let input_hash = hash_input(input_bytes);

    // ── Step 2: State root before (V1 proxy) ────────────────────────────
    let state_root_before = domain_hash(VM_STATE_BEFORE_PREFIX, input_bytes);

    // ── Step 3: Execute via MicroVM::exec (measure wall-clock) ──────────
    let start = Instant::now();

    let exec_output = vm.exec(cmd, timeout_ms).await?;

    let elapsed = start.elapsed();

    // ── Step 4: Hash output ─────────────────────────────────────────────
    let output_hash = hash_output(&exec_output.stdout);

    // ── Step 5: State root after (V1 proxy) ─────────────────────────────
    let state_root_after = domain_hash(VM_STATE_AFTER_PREFIX, &exec_output.stdout);

    // ── Step 6: Build execution trace (V1 minimal) ──────────────────────
    let execution_trace = vec![input_bytes.to_vec(), exec_output.stdout.clone()];

    // ── Step 7: Merkle root ─────────────────────────────────────────────
    let execution_trace_merkle_root = compute_trace_merkle_root(&execution_trace);

    // ── Step 8: Resource usage estimation (V1 proxy) ────────────────────
    let elapsed_ms_u128 = elapsed.as_millis();
    let execution_time_ms = if elapsed_ms_u128 > u128::from(u64::MAX) {
        u64::MAX
    } else {
        elapsed_ms_u128 as u64
    };

    let cpu_cycles_estimate = execution_time_ms
        .checked_mul(1_000_000)
        .ok_or_else(|| {
            MicroVmError::Other(format!(
                "cpu_cycles_estimate overflow: {} ms * 1_000_000 exceeds u64::MAX",
                execution_time_ms
            ))
        })?;

    let peak_memory_bytes = input_bytes.len() as u64;

    // ── Step 9: Construct VmExecutionResult ─────────────────────────────
    Ok(VmExecutionResult {
        workload_id,
        input_hash,
        output_hash,
        state_root_before,
        state_root_after,
        execution_trace,
        execution_trace_merkle_root,
        stdout: exec_output.stdout,
        stderr: exec_output.stderr,
        exit_code: exec_output.exit_code,
        resource_usage: VmResourceUsage {
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
    use crate::{ExecOutput, MicroVM, MicroVmResult};
    use async_trait::async_trait;

    /// Mock VM that returns a fixed stdout.
    struct FixedMockVM {
        stdout: Vec<u8>,
    }

    #[async_trait]
    impl MicroVM for FixedMockVM {
        async fn start(&mut self) -> MicroVmResult<()> {
            Ok(())
        }
        async fn stop(&mut self) -> MicroVmResult<()> {
            Ok(())
        }
        async fn exec(
            &self,
            _cmd: Vec<String>,
            _timeout_ms: Option<u64>,
        ) -> MicroVmResult<ExecOutput> {
            Ok(ExecOutput {
                stdout: self.stdout.clone(),
                stderr: vec![],
                exit_code: Some(0),
                timed_out: false,
            })
        }
    }

    /// Mock VM that always fails.
    struct FailingMockVM;

    #[async_trait]
    impl MicroVM for FailingMockVM {
        async fn start(&mut self) -> MicroVmResult<()> {
            Ok(())
        }
        async fn stop(&mut self) -> MicroVmResult<()> {
            Ok(())
        }
        async fn exec(
            &self,
            _cmd: Vec<String>,
            _timeout_ms: Option<u64>,
        ) -> MicroVmResult<ExecOutput> {
            Err(MicroVmError::Process("mock failure".into()))
        }
    }

    fn wid(seed: u8) -> WorkloadId {
        WorkloadId::new([seed; 32])
    }

    // ── 1) Basic success ────────────────────────────────────────────────

    #[tokio::test]
    async fn exec_committed_success() {
        let vm = FixedMockVM {
            stdout: b"hello-output".to_vec(),
        };
        let input = b"test-input";

        let result = exec_committed(
            &vm,
            wid(0x42),
            vec!["echo".into()],
            input,
            Some(5000),
        )
        .await;

        assert!(result.is_ok());
        let r = result.unwrap();
        assert_eq!(r.workload_id, wid(0x42));
        assert_eq!(r.stdout, b"hello-output");
        assert_eq!(r.exit_code, Some(0));
        assert!(r.stderr.is_empty());
        assert_ne!(r.input_hash, [0u8; 32]);
        assert_ne!(r.output_hash, [0u8; 32]);
        assert_ne!(r.state_root_before, [0u8; 32]);
        assert_ne!(r.state_root_after, [0u8; 32]);
        assert_eq!(r.execution_trace.len(), 2);
    }

    // ── 2) Commitment hash matches manual ───────────────────────────────

    #[tokio::test]
    async fn commitment_hash_matches_manual() {
        let vm = FixedMockVM {
            stdout: b"output".to_vec(),
        };

        let r = exec_committed(
            &vm,
            wid(0x01),
            vec!["cmd".into()],
            b"input",
            None,
        )
        .await
        .unwrap();

        let manual = r.to_execution_commitment().compute_hash();
        let shortcut = r.commitment_hash();
        assert_eq!(manual, shortcut);
    }

    // ── 3) Deterministic same input same output ─────────────────────────

    #[tokio::test]
    async fn deterministic_same_input_same_output() {
        let vm = FixedMockVM {
            stdout: b"fixed-output".to_vec(),
        };
        let input = b"determinism-input";
        let cmd = vec!["run".into()];

        let r1 = exec_committed(&vm, wid(0x10), cmd.clone(), input, None)
            .await
            .unwrap();
        let r2 = exec_committed(&vm, wid(0x10), cmd, input, None)
            .await
            .unwrap();

        // All commitment-critical fields must be identical
        assert_eq!(r1.commitment_hash(), r2.commitment_hash());
        assert_eq!(r1.input_hash, r2.input_hash);
        assert_eq!(r1.output_hash, r2.output_hash);
        assert_eq!(r1.state_root_before, r2.state_root_before);
        assert_eq!(r1.state_root_after, r2.state_root_after);
        assert_eq!(r1.execution_trace_merkle_root, r2.execution_trace_merkle_root);
        assert_eq!(r1.execution_trace, r2.execution_trace);
    }

    // ── 4) state_root_before correct domain ─────────────────────────────

    #[tokio::test]
    async fn state_root_before_correct_domain() {
        let vm = FixedMockVM {
            stdout: b"out".to_vec(),
        };
        let input = b"state-root-test";

        let r = exec_committed(&vm, wid(0x20), vec!["x".into()], input, None)
            .await
            .unwrap();

        // state_root_before = SHA3-256(b"DSDN:vm_state:v1:before:" || input_bytes)
        let expected = domain_hash(b"DSDN:vm_state:v1:before:", input);
        assert_eq!(r.state_root_before, expected);
    }

    // ── 5) state_root_after correct domain ──────────────────────────────

    #[tokio::test]
    async fn state_root_after_correct_domain() {
        let vm = FixedMockVM {
            stdout: b"captured-stdout".to_vec(),
        };

        let r = exec_committed(&vm, wid(0x30), vec!["y".into()], b"", None)
            .await
            .unwrap();

        // state_root_after = SHA3-256(b"DSDN:vm_state:v1:after:" || stdout)
        let expected = domain_hash(b"DSDN:vm_state:v1:after:", b"captured-stdout");
        assert_eq!(r.state_root_after, expected);
    }

    // ── 6) Error propagation from exec ──────────────────────────────────

    #[tokio::test]
    async fn error_propagation_from_exec() {
        let vm = FailingMockVM;

        let result = exec_committed(
            &vm,
            wid(0x40),
            vec!["fail".into()],
            b"input",
            None,
        )
        .await;

        assert!(result.is_err());
        match result {
            Err(MicroVmError::Process(msg)) => {
                assert!(msg.contains("mock failure"));
            }
            other => panic!("expected Process error, got: {:?}", other),
        }
    }

    // ── 7) Merkle root matches trace ────────────────────────────────────

    #[tokio::test]
    async fn merkle_root_matches_trace() {
        let vm = FixedMockVM {
            stdout: b"merkle-test".to_vec(),
        };

        let r = exec_committed(&vm, wid(0x50), vec!["z".into()], b"in", None)
            .await
            .unwrap();

        let expected = compute_trace_merkle_root(&r.execution_trace);
        assert_eq!(r.execution_trace_merkle_root, expected);

        // Trace V1: [input_bytes, stdout]
        assert_eq!(r.execution_trace[0], b"in".to_vec());
        assert_eq!(r.execution_trace[1], b"merkle-test".to_vec());
    }

    // ── 8) Resource usage calculation ───────────────────────────────────

    #[tokio::test]
    async fn resource_usage_calculation() {
        let vm = FixedMockVM {
            stdout: b"res".to_vec(),
        };
        let input = b"resource-input";

        let r = exec_committed(&vm, wid(0x60), vec!["r".into()], input, None)
            .await
            .unwrap();

        // peak_memory_bytes = input_bytes.len()
        assert_eq!(r.resource_usage.peak_memory_bytes, input.len() as u64);

        // cpu_cycles = execution_time_ms * 1_000_000
        assert_eq!(
            r.resource_usage.cpu_cycles_estimate,
            r.resource_usage.execution_time_ms * 1_000_000
        );
    }

    // ── 9) Input/output hash consistency ────────────────────────────────

    #[tokio::test]
    async fn input_output_hash_consistency() {
        let vm = FixedMockVM {
            stdout: b"consistent-out".to_vec(),
        };
        let input = b"consistent-in";

        let r = exec_committed(&vm, wid(0x70), vec!["c".into()], input, None)
            .await
            .unwrap();

        assert_eq!(r.input_hash, hash_input(input));
        assert_eq!(r.output_hash, hash_output(&r.stdout));
    }

    // ── 10) State roots differ from each other ──────────────────────────

    #[tokio::test]
    async fn state_roots_differ() {
        let vm = FixedMockVM {
            stdout: b"data".to_vec(),
        };

        let r = exec_committed(&vm, wid(0x80), vec!["d".into()], b"data", None)
            .await
            .unwrap();

        // Even with same bytes, before and after use different domain prefixes
        assert_ne!(r.state_root_before, r.state_root_after);
    }
}