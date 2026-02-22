//! # VM Execution Result Types (14C.B.8)
//!
//! Defines [`VmExecutionResult`] — the VM-side mirror of
//! `runtime_wasm::WasmExecutionResult` — and [`VmResourceUsage`] for
//! V1 resource estimation.
//!
//! ## Cross-Runtime Commitment Compatibility
//!
//! `VmExecutionResult` produces byte-identical `ExecutionCommitment` values
//! to `WasmExecutionResult` when the same 6 commitment fields match:
//! `workload_id`, `input_hash`, `output_hash`, `state_root_before`,
//! `state_root_after`, `execution_trace_merkle_root`.
//!
//! The bridge methods `to_execution_commitment()` and `commitment_hash()`
//! use the same `ExecutionCommitment::new()` constructor and
//! `ExecutionCommitment::compute_hash()` as the WASM runtime.
//!
//! ## VM-Specific Fields
//!
//! Unlike `WasmExecutionResult`, VM results include:
//! - `stderr` — captured standard error from VM process
//! - `exit_code` — process exit code (None if killed/timed out)
//!
//! These are operational fields that do NOT affect the commitment hash.

use dsdn_common::coordinator::WorkloadId;
use dsdn_common::execution_commitment::ExecutionCommitment;

// ════════════════════════════════════════════════════════════════════════════════
// TYPES
// ════════════════════════════════════════════════════════════════════════════════

/// Resource usage measurements from VM execution (V1 estimation).
///
/// All fields are V1 proxies:
/// - `cpu_cycles_estimate`: derived from wall-clock time (not real CPU counters)
/// - `peak_memory_bytes`: estimated from workload size (not real RSS)
/// - `execution_time_ms`: wall-clock elapsed time
///
/// These values feed into reward calculation but do NOT affect the
/// commitment hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmResourceUsage {
    /// Estimated CPU cycles consumed. V1: `execution_time_ms * 1_000_000`.
    pub cpu_cycles_estimate: u64,
    /// Estimated peak memory in bytes. V1: proxy from input/module size.
    pub peak_memory_bytes: u64,
    /// Wall-clock execution time in milliseconds.
    pub execution_time_ms: u64,
}

/// Result of a committed VM execution.
///
/// Contains all data needed to construct an `ExecutionCommitment` plus
/// operational data (stdout, stderr, exit_code, resource_usage) for the
/// node layer.
///
/// ## Commitment-Critical Fields (deterministic)
///
/// - `workload_id` — Coordinator-assigned identifier
/// - `input_hash` — `hash_input(input_bytes)` (domain-separated SHA3-256)
/// - `output_hash` — `hash_output(stdout)` (domain-separated SHA3-256)
/// - `state_root_before` — Pre-execution state hash
/// - `state_root_after` — Post-execution state hash
/// - `execution_trace_merkle_root` — Binary SHA3-256 Merkle root
///
/// ## Operational Fields (not in commitment)
///
/// - `execution_trace` — Raw trace steps
/// - `stdout` — Captured standard output
/// - `stderr` — Captured standard error (VM-specific)
/// - `exit_code` — Process exit code (VM-specific)
/// - `resource_usage` — V1 estimates
#[derive(Debug, Clone)]
pub struct VmExecutionResult {
    /// Coordinator-assigned workload identifier.
    pub workload_id: WorkloadId,
    /// SHA3-256 hash of input bytes with domain prefix `DSDN:wasm_input:v1:`.
    pub input_hash: [u8; 32],
    /// SHA3-256 hash of output bytes with domain prefix `DSDN:wasm_output:v1:`.
    pub output_hash: [u8; 32],
    /// Pre-execution state root (V1: hash of module/image bytes).
    pub state_root_before: [u8; 32],
    /// Post-execution state root (V1: hash of output bytes).
    pub state_root_after: [u8; 32],
    /// Raw execution trace steps.
    pub execution_trace: Vec<Vec<u8>>,
    /// Binary SHA3-256 Merkle root of `execution_trace`.
    pub execution_trace_merkle_root: [u8; 32],
    /// Captured standard output from VM process.
    pub stdout: Vec<u8>,
    /// Captured standard error from VM process.
    pub stderr: Vec<u8>,
    /// Process exit code. `None` if killed or timed out.
    pub exit_code: Option<i32>,
    /// Resource usage measurements (V1 estimation).
    pub resource_usage: VmResourceUsage,
}

// ════════════════════════════════════════════════════════════════════════════════
// EXECUTION COMMITMENT BRIDGE (14C.B.8)
// ════════════════════════════════════════════════════════════════════════════════

impl VmExecutionResult {
    /// Constructs an [`ExecutionCommitment`] from this VM execution result.
    ///
    /// Maps 6 commitment-critical fields 1:1 with no transformation:
    ///
    /// | VmExecutionResult field | ExecutionCommitment parameter |
    /// |-------------------------|-------------------------------|
    /// | `workload_id` | `workload_id` |
    /// | `input_hash` | `input_hash` |
    /// | `output_hash` | `output_hash` |
    /// | `state_root_before` | `state_root_before` |
    /// | `state_root_after` | `state_root_after` |
    /// | `execution_trace_merkle_root` | `execution_trace_merkle_root` |
    ///
    /// Excluded fields: `execution_trace`, `stdout`, `stderr`,
    /// `exit_code`, `resource_usage` — operational data only.
    ///
    /// # Determinism
    ///
    /// All mapped fields are `Copy`. No allocation, no hashing, no
    /// transformation. Same `VmExecutionResult` → same `ExecutionCommitment`.
    #[must_use]
    pub fn to_execution_commitment(&self) -> ExecutionCommitment {
        ExecutionCommitment::new(
            self.workload_id,
            self.input_hash,
            self.output_hash,
            self.state_root_before,
            self.state_root_after,
            self.execution_trace_merkle_root,
        )
    }

    /// Computes the SHA3-256 commitment hash.
    ///
    /// Shortcut for `self.to_execution_commitment().compute_hash()`.
    ///
    /// Produces the same 32-byte hash as `WasmExecutionResult::commitment_hash()`
    /// when the 6 commitment fields are identical.
    ///
    /// # Determinism
    ///
    /// Same `VmExecutionResult` → same 32-byte hash, always.
    #[must_use]
    pub fn commitment_hash(&self) -> [u8; 32] {
        self.to_execution_commitment().compute_hash()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_result() -> VmExecutionResult {
        VmExecutionResult {
            workload_id: WorkloadId::new([0x01; 32]),
            input_hash: [0x02; 32],
            output_hash: [0x03; 32],
            state_root_before: [0x04; 32],
            state_root_after: [0x05; 32],
            execution_trace: vec![vec![0xAA], vec![0xBB]],
            execution_trace_merkle_root: [0x06; 32],
            stdout: b"hello".to_vec(),
            stderr: b"warning".to_vec(),
            exit_code: Some(0),
            resource_usage: VmResourceUsage {
                cpu_cycles_estimate: 1_000_000,
                peak_memory_bytes: 65536,
                execution_time_ms: 1,
            },
        }
    }

    // ── 1) Commitment construction valid ────────────────────────────────

    #[test]
    fn commitment_construction_valid() {
        let result = make_result();
        let ec = result.to_execution_commitment();
        assert_eq!(*ec.workload_id(), result.workload_id);
        assert_eq!(*ec.input_hash(), result.input_hash);
        assert_eq!(*ec.output_hash(), result.output_hash);
        assert_eq!(*ec.state_root_before(), result.state_root_before);
        assert_eq!(*ec.state_root_after(), result.state_root_after);
        assert_eq!(
            *ec.execution_trace_merkle_root(),
            result.execution_trace_merkle_root
        );
    }

    // ── 2) Commitment hash matches manual ───────────────────────────────

    #[test]
    fn commitment_hash_matches_manual() {
        let result = make_result();
        let manual = result.to_execution_commitment().compute_hash();
        let shortcut = result.commitment_hash();
        assert_eq!(manual, shortcut);
    }

    // ── 3) Determinism 100x ─────────────────────────────────────────────

    #[test]
    fn determinism_repeat_100x() {
        let result = make_result();
        let reference = result.commitment_hash();
        for _ in 0..100 {
            assert_eq!(result.commitment_hash(), reference);
        }
    }

    // ── 4) Field mapping exact ──────────────────────────────────────────

    #[test]
    fn field_mapping_exact() {
        let r = make_result();
        let ec = r.to_execution_commitment();

        // Construct expected directly
        let direct = ExecutionCommitment::new(
            WorkloadId::new([0x01; 32]),
            [0x02; 32],
            [0x03; 32],
            [0x04; 32],
            [0x05; 32],
            [0x06; 32],
        );
        assert_eq!(ec, direct);
        assert_eq!(ec.compute_hash(), direct.compute_hash());
    }

    // ── 5) Resource usage preserved ─────────────────────────────────────

    #[test]
    fn resource_usage_preserved() {
        let result = make_result();
        assert_eq!(result.resource_usage.cpu_cycles_estimate, 1_000_000);
        assert_eq!(result.resource_usage.peak_memory_bytes, 65536);
        assert_eq!(result.resource_usage.execution_time_ms, 1);
    }

    // ── 6) Different fields → different commitment ──────────────────────

    #[test]
    fn different_fields_different_commitment() {
        let r1 = make_result();
        let mut r2 = make_result();
        r2.input_hash = [0xFF; 32];
        assert_ne!(r1.commitment_hash(), r2.commitment_hash());
    }

    // ── 7) commitment_hash not zero ─────────────────────────────────────

    #[test]
    fn commitment_hash_not_zero() {
        let result = make_result();
        assert_ne!(result.commitment_hash(), [0u8; 32]);
    }

    // ── 8) stderr and exit_code do not affect commitment ────────────────

    #[test]
    fn operational_fields_excluded_from_commitment() {
        let r1 = make_result();
        let mut r2 = make_result();
        r2.stderr = b"different-error".to_vec();
        r2.exit_code = Some(1);
        r2.resource_usage.execution_time_ms = 999;
        r2.resource_usage.cpu_cycles_estimate = 999_000_000;

        // Commitment hash depends only on the 6 commitment fields
        assert_eq!(r1.commitment_hash(), r2.commitment_hash());
    }

    // ── 9) Send + Sync ──────────────────────────────────────────────────

    #[test]
    fn send_sync_assertions() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<VmExecutionResult>();
        assert_sync::<VmExecutionResult>();
        assert_send::<VmResourceUsage>();
        assert_sync::<VmResourceUsage>();
    }

    // ── 10) Clone produces identical commitment ─────────────────────────

    #[test]
    fn clone_produces_identical_commitment() {
        let r1 = make_result();
        let r2 = r1.clone();
        assert_eq!(r1.commitment_hash(), r2.commitment_hash());
    }
}