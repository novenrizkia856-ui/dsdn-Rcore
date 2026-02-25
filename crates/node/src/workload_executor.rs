//! # Workload Executor — Runtime Dispatch (14C.B.13)
//!
//! Stateless dispatcher that receives a [`WorkloadAssignment`] and routes it
//! to the appropriate runtime backend:
//!
//! ```text
//! ┌─── WorkloadExecutor::execute_workload() ─────────────────────────────┐
//! │                                                                       │
//! │  WorkloadAssignment                                                   │
//! │       │                                                               │
//! │       ├─ Storage ──────► No execution. commitment = None.             │
//! │       │                  resource_usage zeroed. stdout empty.         │
//! │       │                                                               │
//! │       ├─ ComputeWasm ──► runtime_wasm::run_wasm_committed()          │
//! │       │                  → WasmExecutionResult                        │
//! │       │                  → to_execution_commitment()                  │
//! │       │                  → ExecutionOutput with Some(commitment)      │
//! │       │                                                               │
//! │       └─ ComputeVm ───► runtime_vm::exec_committed() (V2)           │
//! │                          V1: RuntimeNotAvailable (async + MicroVM)   │
//! │                                                                       │
//! │  Result<ExecutionOutput, ExecutionError>                              │
//! └───────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Design Principles
//!
//! - **Stateless**: `WorkloadExecutor` is a unit struct with no fields.
//!   All state comes from the `WorkloadAssignment` argument.
//!
//! - **Deterministic**: For compute workloads, the output commitment is
//!   fully deterministic (same assignment → same commitment hash).
//!   Operational fields (timing, stderr) are non-deterministic but do
//!   not affect the commitment.
//!
//! - **Explicit error mapping**: Each runtime's error type is mapped to
//!   a unified `ExecutionError` with the original message preserved.
//!   No errors are swallowed.
//!
//! ## V1 Limitations
//!
//! - **VM path**: Returns `RuntimeNotAvailable` because `exec_committed`
//!   requires an async runtime and a `&dyn MicroVM` instance, neither of
//!   which is available through the synchronous `execute_workload` API.
//!   V2 will add `execute_workload_async` with VM support.
//!
//! - **Storage path**: Returns zeroed resource usage. V2 will integrate
//!   with the storage layer to report chunk counts and bandwidth.

use dsdn_common::ExecutionCommitment;
use dsdn_common::coordinator::WorkloadId;

// ════════════════════════════════════════════════════════════════════════════════
// TYPES
// ════════════════════════════════════════════════════════════════════════════════

/// Runtime backend for a workload.
///
/// Determines which execution path `WorkloadExecutor` takes.
/// `Storage` workloads skip runtime execution entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkloadType {
    /// Data storage workload — no compute execution, no commitment.
    Storage,
    /// WASM compute workload — dispatched to `runtime_wasm::run_wasm_committed`.
    ComputeWasm,
    /// VM compute workload — dispatched to `runtime_vm::exec_committed` (V2).
    /// V1: returns `RuntimeNotAvailable`.
    ComputeVm,
}

/// A workload assigned to this node for execution.
///
/// Contains all data needed to dispatch to the appropriate runtime.
/// For `ComputeWasm`, `module_bytes` must be valid WASM bytecode.
/// For `ComputeVm`, `vm_command` must be non-empty.
/// For `Storage`, compute-related fields are ignored.
#[derive(Debug, Clone)]
pub struct WorkloadAssignment {
    /// Coordinator-assigned workload identifier. Feeds into commitment.
    pub workload_id: WorkloadId,
    /// Runtime backend selector.
    pub workload_type: WorkloadType,
    /// WASM module bytecode (for `ComputeWasm`) or VM disk image (for `ComputeVm`).
    pub module_bytes: Vec<u8>,
    /// Input data for the workload execution.
    pub input_bytes: Vec<u8>,
    /// Command + arguments for VM execution (for `ComputeVm`).
    pub vm_command: Vec<String>,
    /// Execution resource limits (timeout, memory).
    pub resource_limits: ResourceLimits,
}

/// Resource limits for workload execution.
///
/// Mapped to `runtime_wasm::RuntimeLimits` for WASM dispatch and to
/// `timeout_ms` parameter for VM dispatch.
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// Maximum wall-clock execution time in milliseconds.
    pub timeout_ms: u64,
    /// Maximum memory in bytes (WASM: initial linear memory limit).
    pub max_memory_bytes: usize,
}

/// Unified execution output from any runtime backend.
///
/// Contains the optional `ExecutionCommitment` (present for compute workloads,
/// absent for storage), unified resource usage metrics, and captured stdout.
///
/// ## Determinism
///
/// `commitment` is fully deterministic for compute workloads: same
/// assignment → same commitment. `resource_usage.execution_time_ms`
/// is wall-clock and non-deterministic but does not affect the commitment.
#[derive(Debug, Clone)]
pub struct ExecutionOutput {
    /// Execution commitment for fraud-proof verification.
    /// `Some` for compute workloads, `None` for storage workloads.
    pub commitment: Option<ExecutionCommitment>,
    /// Unified resource usage metrics across all runtime backends.
    pub resource_usage: UnifiedResourceUsage,
    /// Captured standard output from the workload execution.
    /// Empty for storage workloads.
    pub stdout: Vec<u8>,
}

/// Unified resource usage metrics across WASM, VM, and storage backends.
///
/// For compute workloads, `cpu_cycles_estimate`, `peak_memory_bytes`, and
/// `execution_time_ms` are populated from the runtime's `ResourceUsage`.
/// For storage workloads, all fields are zero (V1).
///
/// `chunk_count` and `bandwidth_bytes` are reserved for storage integration (V2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnifiedResourceUsage {
    /// Estimated CPU cycles consumed (V1: `execution_time_ms * 1_000_000`).
    pub cpu_cycles_estimate: u64,
    /// Peak memory usage in bytes (V1: module size for WASM, input size for VM).
    pub peak_memory_bytes: u64,
    /// Wall-clock execution time in milliseconds (non-deterministic).
    pub execution_time_ms: u64,
    /// Number of storage chunks involved (V2, currently 0).
    pub chunk_count: u64,
    /// Total bandwidth consumed in bytes (V2, currently 0).
    pub bandwidth_bytes: u64,
}

/// Errors from workload execution dispatch.
///
/// Each variant preserves the original error message from the underlying
/// runtime. No errors are swallowed or transformed beyond string conversion.
#[derive(Debug)]
pub enum ExecutionError {
    /// WASM runtime error: compilation, timeout, trap, memory limit, or host error.
    WasmError(String),
    /// VM runtime error: process failure, timeout, or resource error.
    VmError(String),
    /// Workload type is not valid for the requested operation.
    InvalidWorkloadType,
    /// Required runtime backend is not available in this build or context.
    RuntimeNotAvailable(String),
}

impl std::fmt::Display for ExecutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WasmError(e) => write!(f, "WASM execution error: {}", e),
            Self::VmError(e) => write!(f, "VM execution error: {}", e),
            Self::InvalidWorkloadType => write!(f, "invalid workload type for operation"),
            Self::RuntimeNotAvailable(e) => write!(f, "runtime not available: {}", e),
        }
    }
}

impl std::error::Error for ExecutionError {}

// ════════════════════════════════════════════════════════════════════════════════
// EXECUTOR
// ════════════════════════════════════════════════════════════════════════════════

/// Stateless workload execution dispatcher (14C.B.13).
///
/// Routes `WorkloadAssignment` to the appropriate runtime backend and
/// returns a unified `ExecutionOutput`. Does not hold any state — all
/// information comes from the assignment.
///
/// ## Dispatch Table
///
/// | WorkloadType | Backend | Commitment | V1 Status |
/// |--------------|---------|------------|-----------|
/// | `Storage` | None | `None` | Active |
/// | `ComputeWasm` | `runtime_wasm::run_wasm_committed` | `Some(...)` | Active |
/// | `ComputeVm` | `runtime_vm::exec_committed` | N/A | `RuntimeNotAvailable` |
pub struct WorkloadExecutor;

impl WorkloadExecutor {
    /// Dispatches a workload assignment to the appropriate runtime backend.
    ///
    /// ## Arguments
    ///
    /// * `assignment` — The workload to execute, including type, module, input,
    ///   and resource limits.
    ///
    /// ## Returns
    ///
    /// `ExecutionOutput` with optional commitment, unified resource usage,
    /// and captured stdout.
    ///
    /// ## Errors
    ///
    /// - `ExecutionError::WasmError` — WASM compilation, execution, or resource error.
    /// - `ExecutionError::VmError` — VM execution error (V2).
    /// - `ExecutionError::InvalidWorkloadType` — Compute workload with empty module/command.
    /// - `ExecutionError::RuntimeNotAvailable` — VM runtime not available in V1.
    ///
    /// ## Determinism
    ///
    /// For compute workloads, the `commitment` field is fully deterministic:
    /// same assignment → same commitment hash. Operational fields
    /// (`execution_time_ms`) vary between runs.
    pub fn execute_workload(
        assignment: &WorkloadAssignment,
    ) -> Result<ExecutionOutput, ExecutionError> {
        match assignment.workload_type {
            WorkloadType::Storage => Self::dispatch_storage(assignment),
            WorkloadType::ComputeWasm => Self::dispatch_wasm(assignment),
            WorkloadType::ComputeVm => Self::dispatch_vm(assignment),
        }
    }

    /// Storage dispatch: no execution, zeroed resource usage, no commitment.
    fn dispatch_storage(_assignment: &WorkloadAssignment) -> Result<ExecutionOutput, ExecutionError> {
        Ok(ExecutionOutput {
            commitment: None,
            resource_usage: UnifiedResourceUsage {
                cpu_cycles_estimate: 0,
                peak_memory_bytes: 0,
                execution_time_ms: 0,
                chunk_count: 0,
                bandwidth_bytes: 0,
            },
            stdout: Vec::new(),
        })
    }

    /// WASM dispatch: validate input, call runtime_wasm::run_wasm_committed,
    /// map result to ExecutionOutput.
    fn dispatch_wasm(assignment: &WorkloadAssignment) -> Result<ExecutionOutput, ExecutionError> {
        if assignment.module_bytes.is_empty() {
            return Err(ExecutionError::InvalidWorkloadType);
        }

        let limits = dsdn_runtime_wasm::RuntimeLimits {
            timeout_ms: assignment.resource_limits.timeout_ms,
            max_memory_bytes: assignment.resource_limits.max_memory_bytes,
        };

        let result = dsdn_runtime_wasm::run_wasm_committed(
            assignment.workload_id,
            &assignment.module_bytes,
            &assignment.input_bytes,
            limits,
        )
        .map_err(|e: dsdn_runtime_wasm::RuntimeError| ExecutionError::WasmError(e.to_string()))?;

        let commitment = result.to_execution_commitment();

        Ok(ExecutionOutput {
            commitment: Some(commitment),
            resource_usage: UnifiedResourceUsage {
                cpu_cycles_estimate: result.resource_usage.cpu_cycles_estimate,
                peak_memory_bytes: result.resource_usage.peak_memory_bytes,
                execution_time_ms: result.resource_usage.execution_time_ms,
                chunk_count: 0,
                bandwidth_bytes: 0,
            },
            stdout: result.stdout,
        })
    }

    /// VM dispatch: V1 returns RuntimeNotAvailable.
    ///
    /// `exec_committed` requires an async runtime and a `&dyn MicroVM`
    /// instance, which are not available through this synchronous API.
    /// V2 will add `execute_workload_async` with full VM support.
    fn dispatch_vm(_assignment: &WorkloadAssignment) -> Result<ExecutionOutput, ExecutionError> {
        Err(ExecutionError::RuntimeNotAvailable(
            "VM committed execution requires async runtime and MicroVM instance; \
             use execute_workload_async (V2) for VM workloads"
                .to_string(),
        ))
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn test_wid() -> WorkloadId {
        WorkloadId::new([0x42; 32])
    }

    fn default_limits() -> ResourceLimits {
        ResourceLimits {
            timeout_ms: 3000,
            max_memory_bytes: 65536,
        }
    }

    fn storage_assignment() -> WorkloadAssignment {
        WorkloadAssignment {
            workload_id: test_wid(),
            workload_type: WorkloadType::Storage,
            module_bytes: Vec::new(),
            input_bytes: Vec::new(),
            vm_command: Vec::new(),
            resource_limits: default_limits(),
        }
    }

    // ── 1) Storage dispatch returns None commitment ──────────────────────

    #[test]
    fn storage_dispatch_returns_none_commitment() {
        let assignment = storage_assignment();
        let result = WorkloadExecutor::execute_workload(&assignment);
        assert!(result.is_ok());

        let output = result.unwrap();
        assert!(output.commitment.is_none());
        assert!(output.stdout.is_empty());
        assert_eq!(output.resource_usage.cpu_cycles_estimate, 0);
        assert_eq!(output.resource_usage.peak_memory_bytes, 0);
        assert_eq!(output.resource_usage.execution_time_ms, 0);
        assert_eq!(output.resource_usage.chunk_count, 0);
        assert_eq!(output.resource_usage.bandwidth_bytes, 0);
    }

    // ── 2) WASM dispatch success ─────────────────────────────────────────

    #[test]
    fn wasm_dispatch_success_mock() {
        // Compile a minimal WAT module that writes "Hi" via env::write
        let wat = r#"
        (module
            (import "env" "write" (func $write (param i32 i32)))
            (memory (export "memory") 1)
            (data (i32.const 0) "Hi")
            (func (export "run")
                i32.const 0
                i32.const 2
                call $write
            )
        )
        "#;
        let wasm = wat::parse_str(wat).expect("test: WAT compilation failed");

        let assignment = WorkloadAssignment {
            workload_id: test_wid(),
            workload_type: WorkloadType::ComputeWasm,
            module_bytes: wasm,
            input_bytes: b"test-input".to_vec(),
            vm_command: Vec::new(),
            resource_limits: default_limits(),
        };

        let result = WorkloadExecutor::execute_workload(&assignment);
        assert!(result.is_ok());

        let output = result.unwrap();
        assert!(output.commitment.is_some());
        assert_eq!(output.stdout, b"Hi");
        assert_eq!(output.resource_usage.chunk_count, 0);
        assert_eq!(output.resource_usage.bandwidth_bytes, 0);
        // CPU and memory should be populated
        assert!(output.resource_usage.peak_memory_bytes > 0);
    }

    // ── 3) VM dispatch returns RuntimeNotAvailable (V1) ──────────────────

    #[test]
    fn vm_dispatch_success_mock() {
        let assignment = WorkloadAssignment {
            workload_id: test_wid(),
            workload_type: WorkloadType::ComputeVm,
            module_bytes: Vec::new(),
            input_bytes: Vec::new(),
            vm_command: vec!["echo".to_string(), "hello".to_string()],
            resource_limits: default_limits(),
        };

        let result = WorkloadExecutor::execute_workload(&assignment);
        assert!(result.is_err());

        match result {
            Err(ExecutionError::RuntimeNotAvailable(msg)) => {
                assert!(msg.contains("async"));
                assert!(msg.contains("MicroVM"));
            }
            other => panic!("expected RuntimeNotAvailable, got: {:?}", other),
        }
    }

    // ── 4) Invalid workload type (empty module for ComputeWasm) ──────────

    #[test]
    fn invalid_workload_type_error() {
        let assignment = WorkloadAssignment {
            workload_id: test_wid(),
            workload_type: WorkloadType::ComputeWasm,
            module_bytes: Vec::new(), // empty → InvalidWorkloadType
            input_bytes: Vec::new(),
            vm_command: Vec::new(),
            resource_limits: default_limits(),
        };

        let result = WorkloadExecutor::execute_workload(&assignment);
        assert!(result.is_err());

        match result {
            Err(ExecutionError::InvalidWorkloadType) => {}
            other => panic!("expected InvalidWorkloadType, got: {:?}", other),
        }
    }

    // ── 5) WASM error maps correctly ─────────────────────────────────────

    #[test]
    fn wasm_error_maps_correctly() {
        let assignment = WorkloadAssignment {
            workload_id: test_wid(),
            workload_type: WorkloadType::ComputeWasm,
            module_bytes: b"not-valid-wasm".to_vec(),
            input_bytes: Vec::new(),
            vm_command: Vec::new(),
            resource_limits: default_limits(),
        };

        let result = WorkloadExecutor::execute_workload(&assignment);
        assert!(result.is_err());

        match result {
            Err(ExecutionError::WasmError(msg)) => {
                // Original RuntimeError::CompileError message preserved
                assert!(msg.contains("compile") || msg.contains("validation"));
            }
            other => panic!("expected WasmError, got: {:?}", other),
        }
    }

    // ── 6) Storage deterministic ─────────────────────────────────────────

    #[test]
    fn storage_dispatch_deterministic() {
        let a = storage_assignment();
        let r1 = WorkloadExecutor::execute_workload(&a).unwrap();
        let r2 = WorkloadExecutor::execute_workload(&a).unwrap();

        assert_eq!(r1.commitment.is_none(), r2.commitment.is_none());
        assert_eq!(r1.resource_usage, r2.resource_usage);
        assert_eq!(r1.stdout, r2.stdout);
    }

    // ── 7) WASM commitment deterministic ─────────────────────────────────

    #[test]
    fn wasm_commitment_deterministic() {
        let wat = r#"
        (module
            (import "env" "write" (func $write (param i32 i32)))
            (memory (export "memory") 1)
            (data (i32.const 0) "OK")
            (func (export "run")
                i32.const 0
                i32.const 2
                call $write
            )
        )
        "#;
        let wasm = wat::parse_str(wat).expect("test: WAT compilation failed");

        let assignment = WorkloadAssignment {
            workload_id: test_wid(),
            workload_type: WorkloadType::ComputeWasm,
            module_bytes: wasm,
            input_bytes: b"determinism".to_vec(),
            vm_command: Vec::new(),
            resource_limits: default_limits(),
        };

        let r1 = WorkloadExecutor::execute_workload(&assignment).unwrap();
        let r2 = WorkloadExecutor::execute_workload(&assignment).unwrap();

        // Commitment must be byte-identical
        let c1 = r1.commitment.unwrap();
        let c2 = r2.commitment.unwrap();
        assert_eq!(c1.compute_hash(), c2.compute_hash());

        // Stdout must be identical
        assert_eq!(r1.stdout, r2.stdout);
    }

    // ── 8) Execution error Display impl ──────────────────────────────────

    #[test]
    fn execution_error_display() {
        let e1 = ExecutionError::WasmError("compile fail".to_string());
        assert!(e1.to_string().contains("WASM"));
        assert!(e1.to_string().contains("compile fail"));

        let e2 = ExecutionError::VmError("process died".to_string());
        assert!(e2.to_string().contains("VM"));

        let e3 = ExecutionError::InvalidWorkloadType;
        assert!(e3.to_string().contains("invalid"));

        let e4 = ExecutionError::RuntimeNotAvailable("no vm".to_string());
        assert!(e4.to_string().contains("not available"));
    }
}