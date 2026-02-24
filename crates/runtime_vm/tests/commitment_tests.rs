//! # VM Commitment Tests (14C.B.11)
//!
//! Integration test suite verifying:
//! - Determinism of committed VM execution
//! - Cross-runtime Merkle and hash_input compatibility
//! - No partial commitment on error paths
//! - FirecrackerVM placeholder returns NotImplemented
//! - Resource usage population
//!
//! ## Determinism Rules
//!
//! - Zero randomness
//! - Zero sleep-based timing
//! - Zero thread races
//! - Assertions only on deterministic fields
//! - `execution_time_ms` excluded from equality checks

// NOTE: If Cargo.toml package name is `dsdn-runtime-vm`, import as `dsdn_runtime_vm`.
// Adjust this line if the package name differs.
use dsdn_runtime_vm::{
    exec_committed, compute_trace_merkle_root, hash_input, hash_output,
    ExecOutput, MicroVM, MicroVmError, MicroVmResult,
    VmExecutionResult,
};
use dsdn_runtime_vm::firecracker_vm::{FirecrackerConfig, FirecrackerVM};
use dsdn_common::coordinator::WorkloadId;
use async_trait::async_trait;
use sha3::{Digest, Sha3_256};
use std::path::PathBuf;

// ════════════════════════════════════════════════════════════════════════════════
// TEST MOCK VMs
// ════════════════════════════════════════════════════════════════════════════════

/// Mock VM that returns a fixed stdout. Deterministic output.
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

/// Mock VM that always fails with Process error. Simulates exec failure.
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
        Err(MicroVmError::Process("simulated exec failure".into()))
    }
}

fn wid(seed: u8) -> WorkloadId {
    WorkloadId::new([seed; 32])
}

// ════════════════════════════════════════════════════════════════════════════════
// 1) HAPPY PATH
// ════════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn mock_vm_exec_committed_happy_path() {
    let vm = FixedMockVM {
        stdout: b"hello-world".to_vec(),
    };

    let result = exec_committed(
        &vm,
        wid(0x01),
        vec!["echo".into(), "hello".into()],
        b"test-input",
        Some(5000),
    )
    .await;

    assert!(result.is_ok(), "exec_committed should succeed");
    let r = result.unwrap();

    // VmExecutionResult fully populated
    assert_eq!(r.workload_id, wid(0x01));
    assert_eq!(r.stdout, b"hello-world");
    assert!(r.stderr.is_empty());
    assert_eq!(r.exit_code, Some(0));

    // Commitment fields non-zero
    assert_ne!(r.input_hash, [0u8; 32]);
    assert_ne!(r.output_hash, [0u8; 32]);
    assert_ne!(r.state_root_before, [0u8; 32]);
    assert_ne!(r.state_root_after, [0u8; 32]);
    assert_ne!(r.execution_trace_merkle_root, [0u8; 32]);
    assert_ne!(r.commitment_hash(), [0u8; 32]);

    // Trace has 2 entries (V1 minimal)
    assert_eq!(r.execution_trace.len(), 2);
    assert_eq!(r.execution_trace[0], b"test-input");
    assert_eq!(r.execution_trace[1], b"hello-world");
}

// ════════════════════════════════════════════════════════════════════════════════
// 2) DETERMINISM: SAME INPUT → SAME COMMITMENT (10 RUNS)
// ════════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn same_command_same_input_same_commitment() {
    let vm = FixedMockVM {
        stdout: b"deterministic-output".to_vec(),
    };
    let input = b"deterministic-input";
    let workload = wid(0x10);
    let cmd = vec!["run".into()];

    // First run: establish reference
    let reference = exec_committed(&vm, workload, cmd.clone(), input, None)
        .await
        .unwrap();

    // 9 more runs: all must match
    for i in 1..10 {
        let r = exec_committed(&vm, workload, cmd.clone(), input, None)
            .await
            .unwrap();

        assert_eq!(
            r.commitment_hash(),
            reference.commitment_hash(),
            "commitment_hash diverged at run {}",
            i
        );
        assert_eq!(r.input_hash, reference.input_hash, "input_hash run {}", i);
        assert_eq!(r.output_hash, reference.output_hash, "output_hash run {}", i);
        assert_eq!(
            r.state_root_before, reference.state_root_before,
            "state_root_before run {}",
            i
        );
        assert_eq!(
            r.state_root_after, reference.state_root_after,
            "state_root_after run {}",
            i
        );
        assert_eq!(
            r.execution_trace_merkle_root, reference.execution_trace_merkle_root,
            "merkle_root run {}",
            i
        );
        assert_eq!(
            r.execution_trace, reference.execution_trace,
            "trace run {}",
            i
        );
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// 3) DIFFERENT INPUT → DIFFERENT COMMITMENT
// ════════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn different_input_different_commitment() {
    let vm = FixedMockVM {
        stdout: b"same-output".to_vec(),
    };

    let r_a = exec_committed(&vm, wid(0x20), vec!["x".into()], b"input-A", None)
        .await
        .unwrap();
    let r_b = exec_committed(&vm, wid(0x20), vec!["x".into()], b"input-B", None)
        .await
        .unwrap();

    // Different input → different input_hash, state_root_before, merkle_root, commitment
    assert_ne!(r_a.input_hash, r_b.input_hash);
    assert_ne!(r_a.state_root_before, r_b.state_root_before);
    assert_ne!(r_a.execution_trace_merkle_root, r_b.execution_trace_merkle_root);
    assert_ne!(r_a.commitment_hash(), r_b.commitment_hash());

    // Same output → same output_hash, state_root_after
    assert_eq!(r_a.output_hash, r_b.output_hash);
    assert_eq!(r_a.state_root_after, r_b.state_root_after);
}

// ════════════════════════════════════════════════════════════════════════════════
// 4) COMMITMENT ROUNDTRIP
// ════════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn vm_execution_result_roundtrip_commitment() {
    let vm = FixedMockVM {
        stdout: b"roundtrip".to_vec(),
    };

    let r = exec_committed(&vm, wid(0x30), vec!["cmd".into()], b"data", None)
        .await
        .unwrap();

    // Method 1: to_execution_commitment().compute_hash()
    let ec = r.to_execution_commitment();
    let manual_hash = ec.compute_hash();

    // Method 2: commitment_hash() shortcut
    let shortcut_hash = r.commitment_hash();

    assert_eq!(manual_hash, shortcut_hash);

    // Verify field mapping
    assert_eq!(*ec.workload_id(), r.workload_id);
    assert_eq!(*ec.input_hash(), r.input_hash);
    assert_eq!(*ec.output_hash(), r.output_hash);
    assert_eq!(*ec.state_root_before(), r.state_root_before);
    assert_eq!(*ec.state_root_after(), r.state_root_after);
    assert_eq!(*ec.execution_trace_merkle_root(), r.execution_trace_merkle_root);
}

// ════════════════════════════════════════════════════════════════════════════════
// 5) MERKLE ROOT CROSS-RUNTIME COMPATIBILITY
// ════════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn merkle_root_matches_wasm_algorithm() {
    // Construct a known trace
    let trace = vec![
        b"step-one".to_vec(),
        b"step-two".to_vec(),
        b"step-three".to_vec(),
    ];

    // VM compute_trace_merkle_root
    let vm_root = compute_trace_merkle_root(&trace);

    // Manual computation (same algorithm as runtime_wasm):
    // 1. Hash each leaf
    let leaf = |data: &[u8]| -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(data);
        let r = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&r);
        out
    };

    let parent = |left: &[u8; 32], right: &[u8; 32]| -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(left);
        h.update(right);
        let r = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&r);
        out
    };

    let l0 = leaf(b"step-one");
    let l1 = leaf(b"step-two");
    let l2 = leaf(b"step-three");
    let l3 = l2; // odd count: duplicate last

    // Level 1: [parent(l0,l1), parent(l2,l3)]
    let p0 = parent(&l0, &l1);
    let p1 = parent(&l2, &l3);

    // Root: parent(p0, p1)
    let expected_root = parent(&p0, &p1);

    assert_eq!(vm_root, expected_root, "VM Merkle root must match manual computation (WASM algorithm)");

    // Also verify edge cases
    assert_eq!(compute_trace_merkle_root(&[]), [0u8; 32], "empty = zero");
    assert_eq!(compute_trace_merkle_root(&[b"only".to_vec()]), leaf(b"only"), "single = leaf hash");
}

// ════════════════════════════════════════════════════════════════════════════════
// 6) RESOURCE USAGE POPULATED
// ════════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn resource_usage_populated() {
    let vm = FixedMockVM {
        stdout: b"res".to_vec(),
    };
    let input = b"resource-test-input-data";

    let r = exec_committed(&vm, wid(0x50), vec!["r".into()], input, None)
        .await
        .unwrap();

    // peak_memory_bytes = input_bytes.len()
    assert_eq!(r.resource_usage.peak_memory_bytes, input.len() as u64);

    // cpu_cycles_estimate = execution_time_ms * 1_000_000
    assert_eq!(
        r.resource_usage.cpu_cycles_estimate,
        r.resource_usage.execution_time_ms * 1_000_000
    );

    // execution_time_ms is wall-clock, should be reasonable (>= 0, < 60s)
    assert!(r.resource_usage.execution_time_ms < 60_000);

    // cpu_cycles_estimate should not overflow for fast execution
    assert!(r.resource_usage.cpu_cycles_estimate < u64::MAX);
}

// ════════════════════════════════════════════════════════════════════════════════
// 7) ERROR PATH: NO PARTIAL COMMITMENT
// ════════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn timeout_produces_error_no_partial_commitment() {
    let vm = FailingMockVM;

    let result = exec_committed(
        &vm,
        wid(0x60),
        vec!["fail".into()],
        b"should-not-commit",
        Some(1000),
    )
    .await;

    // Must be Err — no VmExecutionResult produced
    assert!(result.is_err(), "failing exec must propagate error");

    match result {
        Err(MicroVmError::Process(msg)) => {
            assert!(
                msg.contains("simulated exec failure"),
                "error message should describe failure"
            );
        }
        other => panic!("expected Process error, got: {:?}", other),
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// 8) FIRECRACKER PLACEHOLDER: NOT IMPLEMENTED
// ════════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn firecracker_exec_committed_returns_not_implemented() {
    let cfg = FirecrackerConfig {
        id: "test-fc".into(),
        firecracker_bin: PathBuf::from("/usr/bin/firecracker"),
        kernel_image: PathBuf::from("/tmp/vmlinuz"),
        rootfs: PathBuf::from("/tmp/rootfs.ext4"),
        api_socket: PathBuf::from("/tmp/fc.sock"),
        mem_mib: 128,
        vcpu_count: 1,
    };
    let fc = FirecrackerVM::new(cfg);

    let result = fc
        .exec_committed(wid(0x70), vec!["test".into()], b"input", Some(5000))
        .await;

    assert!(result.is_err(), "Firecracker must return Err");

    match result {
        Err(MicroVmError::NotImplemented(msg)) => {
            assert!(
                msg.contains("not implemented"),
                "error should indicate not implemented"
            );
        }
        other => panic!("expected NotImplemented, got: {:?}", other),
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// 9) CROSS-RUNTIME: hash_input VM = hash_input WASM
// ════════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn hash_input_vm_matches_wasm() {
    let data = b"cross-runtime-test-data";

    // VM hash_input (uses DSDN:wasm_input:v1: prefix)
    let vm_hash = hash_input(data);

    // Manual SHA3-256 with same prefix (what WASM does)
    let mut hasher = Sha3_256::new();
    hasher.update(b"DSDN:wasm_input:v1:");
    hasher.update(data);
    let result = hasher.finalize();
    let mut expected = [0u8; 32];
    expected.copy_from_slice(&result);

    assert_eq!(vm_hash, expected, "VM hash_input must use identical domain separator as WASM");

    // Also verify hash_output uses DSDN:wasm_output:v1:
    let vm_out_hash = hash_output(data);
    let mut hasher2 = Sha3_256::new();
    hasher2.update(b"DSDN:wasm_output:v1:");
    hasher2.update(data);
    let result2 = hasher2.finalize();
    let mut expected2 = [0u8; 32];
    expected2.copy_from_slice(&result2);

    assert_eq!(vm_out_hash, expected2, "VM hash_output must use identical domain separator as WASM");
}

// ════════════════════════════════════════════════════════════════════════════════
// 10) DIFFERENT WORKLOAD ID → DIFFERENT COMMITMENT
// ════════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn different_workload_id_different_commitment() {
    let vm = FixedMockVM {
        stdout: b"same".to_vec(),
    };
    let input = b"same-input";
    let cmd = vec!["x".into()];

    let r1 = exec_committed(&vm, wid(0xAA), cmd.clone(), input, None)
        .await
        .unwrap();
    let r2 = exec_committed(&vm, wid(0xBB), cmd, input, None)
        .await
        .unwrap();

    // Same input + same output but different workload_id → different commitment
    assert_ne!(r1.commitment_hash(), r2.commitment_hash());

    // All other commitment fields identical
    assert_eq!(r1.input_hash, r2.input_hash);
    assert_eq!(r1.output_hash, r2.output_hash);
    assert_eq!(r1.state_root_before, r2.state_root_before);
    assert_eq!(r1.state_root_after, r2.state_root_after);
    assert_eq!(r1.execution_trace_merkle_root, r2.execution_trace_merkle_root);
}

// ════════════════════════════════════════════════════════════════════════════════
// 11) EMPTY INPUT AND OUTPUT VALID
// ════════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn empty_input_and_output_valid() {
    let vm = FixedMockVM {
        stdout: vec![],
    };

    let r = exec_committed(&vm, wid(0xCC), vec!["empty".into()], b"", None)
        .await
        .unwrap();

    // Empty input/output still produce valid non-zero hashes
    assert_ne!(r.input_hash, [0u8; 32]);
    assert_ne!(r.output_hash, [0u8; 32]);
    assert_ne!(r.commitment_hash(), [0u8; 32]);

    // Trace has 2 entries (both empty)
    assert_eq!(r.execution_trace.len(), 2);
    assert!(r.execution_trace[0].is_empty());
    assert!(r.execution_trace[1].is_empty());
    assert_eq!(r.stdout, Vec::<u8>::new());
}

// ════════════════════════════════════════════════════════════════════════════════
// 12) LARGE INPUT DETERMINISTIC
// ════════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn large_input_deterministic() {
    let large_input = vec![0xAB; 1024 * 1024]; // 1 MiB
    let vm = FixedMockVM {
        stdout: b"large-test-output".to_vec(),
    };

    let r1 = exec_committed(&vm, wid(0xDD), vec!["lg".into()], &large_input, None)
        .await
        .unwrap();
    let r2 = exec_committed(&vm, wid(0xDD), vec!["lg".into()], &large_input, None)
        .await
        .unwrap();

    assert_eq!(r1.commitment_hash(), r2.commitment_hash());
    assert_eq!(r1.resource_usage.peak_memory_bytes, 1024 * 1024);
}