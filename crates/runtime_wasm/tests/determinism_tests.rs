//! # Determinism Verification Tests (14C.B.6)
//!
//! Verifies the critical invariant:
//!
//!     Same WASM module + same input → byte-identical ExecutionCommitment
//!
//! This invariant is required for fraud-proof reproducibility.
//! Any nondeterminism in commitment-relevant fields would allow
//! a dishonest node to produce different commitments for the same
//! workload, breaking the verification chain.
//!
//! ## What IS Deterministic (commitment-critical)
//!
//! - `input_hash` (SHA3-256 of input bytes)
//! - `output_hash` (SHA3-256 of stdout bytes)
//! - `state_root_before` (SHA3-256 of module bytes)
//! - `state_root_after` (SHA3-256 of stdout bytes)
//! - `execution_trace_merkle_root` (binary SHA3-256 Merkle tree)
//! - `commitment_hash()` (SHA3-256 of all 6 commitment fields)
//!
//! ## What is NOT Deterministic (operational only)
//!
//! - `execution_time_ms` (wall-clock)
//! - `cpu_cycles_estimate` (derived from wall-clock)
//!
//! These operational fields do NOT affect commitment hashes.
//!
//! ## Test Design
//!
//! - Zero randomness.
//! - Zero system time as test input.
//! - Zero sleep-based timing.
//! - Zero thread races.
//! - All assertions on deterministic values only.

use dsdn_common::coordinator::WorkloadId;
use dsdn_runtime_wasm::{
    compute_trace_merkle_root, hash_input, hash_memory_snapshot, hash_output,
    run_wasm_committed, RuntimeLimits, WasmExecutionResult,
};

// ════════════════════════════════════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════════════════════════════════════

/// Simple WASM module: writes "Hello" to host via env::write.
fn hello_wat() -> &'static str {
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

/// WASM module that produces no output.
fn noop_wat() -> &'static str {
    r#"
    (module
        (func (export "run"))
    )
    "#
}

fn compile_wat(wat: &str) -> Vec<u8> {
    wat::parse_str(wat).expect("test: WAT compilation failed")
}

fn test_limits() -> RuntimeLimits {
    RuntimeLimits {
        timeout_ms: 5000,
        max_memory_bytes: 65536,
    }
}

fn wid(seed: u8) -> WorkloadId {
    WorkloadId::new([seed; 32])
}

/// Run committed execution and return the result, panicking on error.
fn run_committed(
    wasm: &[u8],
    input: &[u8],
    seed: u8,
) -> WasmExecutionResult {
    run_wasm_committed(wid(seed), wasm, input, test_limits())
        .expect("test: run_wasm_committed failed")
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

// ── 1) Same module + same input → same commitment (10 runs) ─────────────

#[test]
fn same_module_same_input_same_commitment_run_10x() {
    let wasm = compile_wat(hello_wat());
    let input = b"determinism-test-input";

    let reference = run_committed(&wasm, input, 0x42);
    let ref_hash = reference.commitment_hash();

    for _ in 0..9 {
        let result = run_committed(&wasm, input, 0x42);
        assert_eq!(result.commitment_hash(), ref_hash);
        assert_eq!(result.input_hash, reference.input_hash);
        assert_eq!(result.output_hash, reference.output_hash);
        assert_eq!(result.state_root_before, reference.state_root_before);
        assert_eq!(result.state_root_after, reference.state_root_after);
        assert_eq!(
            result.execution_trace_merkle_root,
            reference.execution_trace_merkle_root
        );
        assert_eq!(result.execution_trace, reference.execution_trace);
        assert_eq!(result.stdout, reference.stdout);
    }
}

// ── 2) Same module + different input → different commitment ─────────────

#[test]
fn same_module_different_input_different_commitment() {
    let wasm = compile_wat(hello_wat());
    let r_a = run_committed(&wasm, b"input-A", 0x01);
    let r_b = run_committed(&wasm, b"input-B", 0x01);

    // input_hash must differ (different input bytes)
    assert_ne!(r_a.input_hash, r_b.input_hash);

    // commitment_hash must differ (input_hash is part of commitment)
    assert_ne!(r_a.commitment_hash(), r_b.commitment_hash());

    // output should be the same (module always writes "Hello")
    assert_eq!(r_a.stdout, r_b.stdout);
    assert_eq!(r_a.output_hash, r_b.output_hash);
}

// ── 3) Merkle root matches compute_trace_merkle_root ────────────────────

#[test]
fn merkle_root_matches_compute_trace_merkle_root() {
    let wasm = compile_wat(hello_wat());
    let result = run_committed(&wasm, b"merkle-test", 0x10);

    // Cross-check: merkle root in result must equal direct computation
    let expected = compute_trace_merkle_root(&result.execution_trace);
    assert_eq!(result.execution_trace_merkle_root, expected);
}

// ── 4) Empty input produces valid commitment ────────────────────────────

#[test]
fn empty_input_produces_valid_commitment() {
    let wasm = compile_wat(hello_wat());
    let result = run_committed(&wasm, b"", 0x20);

    // Must not be zero hash (domain-separated hash of empty != zero)
    assert_ne!(result.input_hash, [0u8; 32]);
    assert_ne!(result.output_hash, [0u8; 32]);
    assert_ne!(result.state_root_before, [0u8; 32]);
    assert_ne!(result.commitment_hash(), [0u8; 32]);

    // Trace should have 2 elements: [empty_input, stdout]
    assert_eq!(result.execution_trace.len(), 2);
    assert!(result.execution_trace[0].is_empty());
}

// ── 5) Large input produces valid commitment ────────────────────────────

#[test]
fn large_input_produces_valid_commitment() {
    let wasm = compile_wat(hello_wat());
    // 1 MB input
    let large_input: Vec<u8> = (0u8..=255).cycle().take(1_000_000).collect();
    let result = run_committed(&wasm, &large_input, 0x30);

    assert_ne!(result.input_hash, [0u8; 32]);
    assert_ne!(result.commitment_hash(), [0u8; 32]);

    // Determinism: run again with same large input
    let result2 = run_committed(&wasm, &large_input, 0x30);
    assert_eq!(result.commitment_hash(), result2.commitment_hash());
    assert_eq!(result.input_hash, result2.input_hash);
}

// ── 6) Resource usage: deterministic fields consistent ──────────────────

#[test]
fn resource_usage_consistent_across_runs() {
    let wasm = compile_wat(hello_wat());
    let input = b"resource-test";

    let reference = run_committed(&wasm, input, 0x40);

    for _ in 0..5 {
        let result = run_committed(&wasm, input, 0x40);

        // peak_memory_bytes = module_bytes.len() — fully deterministic
        assert_eq!(
            result.resource_usage.peak_memory_bytes,
            reference.resource_usage.peak_memory_bytes
        );
        assert_eq!(
            result.resource_usage.peak_memory_bytes,
            wasm.len() as u64
        );

        // cpu_cycles = execution_time_ms * 1_000_000 — relationship holds
        assert_eq!(
            result.resource_usage.cpu_cycles_estimate,
            result.resource_usage.execution_time_ms * 1_000_000
        );

        // NOTE: execution_time_ms itself may vary (wall-clock).
        // This is expected and does NOT affect commitment hash.
    }
}

// ── 7) hash_input deterministic 100x ────────────────────────────────────

#[test]
fn hash_input_deterministic_100x() {
    let data = b"hash-input-determinism-test-data-1234567890";
    let reference = hash_input(data);
    for _ in 0..100 {
        assert_eq!(hash_input(data), reference);
    }
}

// ── 8) hash_output deterministic 100x ───────────────────────────────────

#[test]
fn hash_output_deterministic_100x() {
    let data = b"hash-output-determinism-test-data-0987654321";
    let reference = hash_output(data);
    for _ in 0..100 {
        assert_eq!(hash_output(data), reference);
    }
}

// ── 9) hash_memory_snapshot deterministic 100x ──────────────────────────

#[test]
fn hash_memory_snapshot_deterministic_100x() {
    let data: Vec<u8> = (0u8..=255).collect();
    let reference = hash_memory_snapshot(&data);
    for _ in 0..100 {
        assert_eq!(hash_memory_snapshot(&data), reference);
    }
}

// ── 10) WasmExecutionResult → commitment_hash stable ────────────────────

#[test]
fn wasm_result_to_commitment_hash_stable() {
    let wasm = compile_wat(hello_wat());
    let result = run_committed(&wasm, b"stability-test", 0x50);

    let reference = result.commitment_hash();
    for _ in 0..100 {
        // commitment_hash on same result instance must be identical
        assert_eq!(result.commitment_hash(), reference);
    }

    // Also verify to_execution_commitment().compute_hash() matches
    let ec = result.to_execution_commitment();
    assert_eq!(ec.compute_hash(), reference);
}

// ── 11) Trace order affects commitment ──────────────────────────────────

#[test]
fn trace_order_affects_commitment() {
    let a = vec![0x01; 16];
    let b = vec![0x02; 16];

    let root_ab = compute_trace_merkle_root(&[a.clone(), b.clone()]);
    let root_ba = compute_trace_merkle_root(&[b, a]);

    assert_ne!(root_ab, root_ba);
}

// ── 12) Merkle empty trace consistency ──────────────────────────────────

#[test]
fn merkle_empty_trace_consistency() {
    let reference = compute_trace_merkle_root(&[]);
    assert_eq!(reference, [0u8; 32]);

    for _ in 0..100 {
        assert_eq!(compute_trace_merkle_root(&[]), [0u8; 32]);
    }
}

// ── 13) state_root_before consistency ───────────────────────────────────

#[test]
fn state_root_before_consistency() {
    let wasm = compile_wat(hello_wat());

    let r1 = run_committed(&wasm, b"a", 0x60);
    let r2 = run_committed(&wasm, b"b", 0x60);

    // state_root_before = hash_memory_snapshot(module_bytes)
    // Same module → same state_root_before, regardless of input
    assert_eq!(r1.state_root_before, r2.state_root_before);

    // Must match direct computation
    let expected = hash_memory_snapshot(&wasm);
    assert_eq!(r1.state_root_before, expected);
}

// ── 14) state_root_after consistency ────────────────────────────────────

#[test]
fn state_root_after_consistency() {
    let wasm = compile_wat(hello_wat());

    // Same module + different inputs → same stdout ("Hello") → same state_root_after
    let r1 = run_committed(&wasm, b"x", 0x70);
    let r2 = run_committed(&wasm, b"y", 0x70);

    assert_eq!(r1.stdout, r2.stdout); // Both produce "Hello"
    assert_eq!(r1.state_root_after, r2.state_root_after);

    // Must match direct computation
    let expected = hash_memory_snapshot(&r1.stdout);
    assert_eq!(r1.state_root_after, expected);
}

// ── 15) No-output module commitment determinism ─────────────────────────

#[test]
fn no_output_module_commitment_determinism() {
    let wasm = compile_wat(noop_wat());
    let input = b"noop-test";

    let r1 = run_committed(&wasm, input, 0x80);
    let r2 = run_committed(&wasm, input, 0x80);

    assert!(r1.stdout.is_empty());
    assert_eq!(r1.commitment_hash(), r2.commitment_hash());
    assert_eq!(r1.input_hash, r2.input_hash);
    assert_eq!(r1.output_hash, r2.output_hash);
    assert_eq!(r1.state_root_before, r2.state_root_before);
    assert_eq!(r1.state_root_after, r2.state_root_after);
}

// ── 16) Different workload_id → different commitment ────────────────────

#[test]
fn different_workload_id_different_commitment() {
    let wasm = compile_wat(hello_wat());
    let input = b"same-input";

    let r1 = run_committed(&wasm, input, 0xAA);
    let r2 = run_committed(&wasm, input, 0xBB);

    // Same input + same module → same field hashes
    assert_eq!(r1.input_hash, r2.input_hash);
    assert_eq!(r1.output_hash, r2.output_hash);

    // But different workload_id → different commitment hash
    assert_ne!(r1.commitment_hash(), r2.commitment_hash());
}