//! # WASM Execution Result (14C.B.1)
//!
//! Defines [`WasmExecutionResult`] as the carrier type for all data
//! required to construct an [`ExecutionCommitment`].
//!
//! ## Relationship to ExecutionCommitment
//!
//! `WasmExecutionResult` contains the raw execution outputs (traces,
//! hashes, resource usage) that are produced by committed WASM execution.
//! The `to_execution_commitment()` method (added in 14C.B.5) converts
//! this into the native `ExecutionCommitment` type from `dsdn_common`.
//!
//! ## Field Semantics
//!
//! | Field | Source | Size |
//! |-------|--------|------|
//! | `workload_id` | Assigned by coordinator | 32 bytes (WorkloadId) |
//! | `input_hash` | SHA3-256 of workload input | 32 bytes |
//! | `output_hash` | SHA3-256 of workload output | 32 bytes |
//! | `state_root_before` | Hash of pre-execution state | 32 bytes |
//! | `state_root_after` | Hash of post-execution state | 32 bytes |
//! | `execution_trace` | Raw trace steps | Variable |
//! | `execution_trace_merkle_root` | Merkle root of trace | 32 bytes |
//! | `stdout` | Captured guest output | Variable |
//! | `resource_usage` | Measured resource consumption | Struct |
//!
//! ## Determinism
//!
//! All hash fields are deterministic: same WASM module + same input →
//! same `WasmExecutionResult`. The `execution_trace_merkle_root` is
//! computed via [`compute_trace_merkle_root`] which uses the same
//! algorithm as the coordinator (SHA3-256 binary Merkle tree).
//!
//! ## Safety
//!
//! - No panic, unwrap, expect, todo, unreachable.
//! - No unsafe code.
//! - All fields are public for direct construction.
//! - Struct is Send + Sync (all fields are owned, no interior mutability).

use dsdn_common::coordinator::WorkloadId;

// ════════════════════════════════════════════════════════════════════════════════
// RESOURCE USAGE
// ════════════════════════════════════════════════════════════════════════════════

/// Resource usage measurements from WASM execution.
///
/// All values are estimates in V1. Exact metering requires
/// wasmtime fuel consumption tracking (V2).
///
/// ## Fields
///
/// - `cpu_cycles_estimate`: Estimated CPU cycles. V1 uses
///   `execution_time_ms × 1_000_000` as rough proxy.
/// - `peak_memory_bytes`: Peak linear memory usage in bytes.
///   V1 uses module initial memory size as proxy.
/// - `execution_time_ms`: Wall-clock execution time in milliseconds.
///   Measured by the committed execution wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceUsage {
    /// Estimated CPU cycles consumed during execution.
    pub cpu_cycles_estimate: u64,
    /// Peak memory usage in bytes.
    pub peak_memory_bytes: u64,
    /// Wall-clock execution time in milliseconds.
    pub execution_time_ms: u64,
}

// ════════════════════════════════════════════════════════════════════════════════
// WASM EXECUTION RESULT
// ════════════════════════════════════════════════════════════════════════════════

/// Complete result of a committed WASM workload execution.
///
/// Contains all data required to construct an [`ExecutionCommitment`]
/// and a [`UsageProof`]. Produced by `run_wasm_committed()` (14C.B.4).
///
/// ## Construction
///
/// All fields are public. No builder pattern is required because
/// construction happens exclusively in the committed execution wrapper,
/// which guarantees all fields are populated correctly.
///
/// ## Thread Safety
///
/// All fields are owned types with no interior mutability.
/// `WasmExecutionResult` is `Send + Sync` automatically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmExecutionResult {
    /// Workload identifier assigned by the coordinator.
    pub workload_id: WorkloadId,

    /// SHA3-256 hash of the workload input data.
    pub input_hash: [u8; 32],

    /// SHA3-256 hash of the workload output data.
    pub output_hash: [u8; 32],

    /// Hash of the WASM execution state before execution.
    /// V1: SHA3-256 of module bytes (proxy for initial memory state).
    pub state_root_before: [u8; 32],

    /// Hash of the WASM execution state after execution.
    /// V1: SHA3-256 of output bytes (proxy for final memory state).
    pub state_root_after: [u8; 32],

    /// Raw execution trace steps (ordered).
    /// Each step is an opaque byte vector.
    /// V1: minimal trace = [input_bytes, output_bytes].
    pub execution_trace: Vec<Vec<u8>>,

    /// Merkle root computed from `execution_trace` via binary SHA3-256 tree.
    /// Algorithm identical to coordinator's `compute_trace_merkle_root`.
    pub execution_trace_merkle_root: [u8; 32],

    /// Captured stdout from the WASM guest.
    pub stdout: Vec<u8>,

    /// Resource usage measurements from execution.
    pub resource_usage: ResourceUsage,
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_result() -> WasmExecutionResult {
        WasmExecutionResult {
            workload_id: WorkloadId::new([0x01; 32]),
            input_hash: [0x02; 32],
            output_hash: [0x03; 32],
            state_root_before: [0x04; 32],
            state_root_after: [0x05; 32],
            execution_trace: vec![vec![0xAA; 16], vec![0xBB; 16]],
            execution_trace_merkle_root: [0x06; 32],
            stdout: vec![0x48, 0x65, 0x6C, 0x6C, 0x6F], // "Hello"
            resource_usage: ResourceUsage {
                cpu_cycles_estimate: 1_000_000,
                peak_memory_bytes: 65536,
                execution_time_ms: 100,
            },
        }
    }

    #[test]
    fn construction_all_fields() {
        let result = make_result();
        assert_eq!(*result.workload_id.as_bytes(), [0x01; 32]);
        assert_eq!(result.input_hash, [0x02; 32]);
        assert_eq!(result.output_hash, [0x03; 32]);
        assert_eq!(result.state_root_before, [0x04; 32]);
        assert_eq!(result.state_root_after, [0x05; 32]);
        assert_eq!(result.execution_trace.len(), 2);
        assert_eq!(result.execution_trace_merkle_root, [0x06; 32]);
        assert_eq!(result.stdout, vec![0x48, 0x65, 0x6C, 0x6C, 0x6F]);
        assert_eq!(result.resource_usage.cpu_cycles_estimate, 1_000_000);
        assert_eq!(result.resource_usage.peak_memory_bytes, 65536);
        assert_eq!(result.resource_usage.execution_time_ms, 100);
    }

    #[test]
    fn clone_produces_equal() {
        let r1 = make_result();
        let r2 = r1.clone();
        assert_eq!(r1, r2);
    }

    #[test]
    fn debug_format_not_empty() {
        let dbg = format!("{:?}", make_result());
        assert!(!dbg.is_empty());
        assert!(dbg.contains("WasmExecutionResult"));
    }

    #[test]
    fn resource_usage_debug() {
        let ru = ResourceUsage {
            cpu_cycles_estimate: 42,
            peak_memory_bytes: 1024,
            execution_time_ms: 10,
        };
        let dbg = format!("{:?}", ru);
        assert!(dbg.contains("ResourceUsage"));
    }

    #[test]
    fn ne_different_input_hash() {
        let mut r2 = make_result();
        r2.input_hash = [0xFF; 32];
        assert_ne!(make_result(), r2);
    }

    #[test]
    fn empty_trace_valid() {
        let result = WasmExecutionResult {
            workload_id: WorkloadId::new([0x01; 32]),
            input_hash: [0; 32],
            output_hash: [0; 32],
            state_root_before: [0; 32],
            state_root_after: [0; 32],
            execution_trace: vec![],
            execution_trace_merkle_root: [0; 32],
            stdout: vec![],
            resource_usage: ResourceUsage {
                cpu_cycles_estimate: 0,
                peak_memory_bytes: 0,
                execution_time_ms: 0,
            },
        };
        assert!(result.execution_trace.is_empty());
        assert_eq!(result.execution_trace_merkle_root, [0u8; 32]);
    }

    #[test]
    fn send_sync_assertions() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<WasmExecutionResult>();
        assert_sync::<WasmExecutionResult>();
        assert_send::<ResourceUsage>();
        assert_sync::<ResourceUsage>();
    }
}