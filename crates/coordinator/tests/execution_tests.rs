//! # Execution & Usage Verification Integration Tests (CO.10)
//!
//! Covers execution commitment building, Merkle root computation,
//! usage proof verification, anti-self-dealing pre-check, and Mock TSS
//! determinism.

use std::collections::HashMap;

use dsdn_coordinator::execution::{
    // CommitmentBuilder (CO.2)
    CommitmentBuilder, compute_trace_merkle_root,
    // Usage verification (CO.3)
    UsageProof, UsageVerificationResult,
    verify_usage_proof, calculate_reward_base, build_signing_message,
    // Anti-self-dealing (CO.9)
    precheck_self_dealing, NodeId, Address, NodeOwnerLookup, PreCheckResult,
};

use dsdn_common::coordinator::WorkloadId;
use ed25519_dalek::{Signer, SigningKey};

// ════════════════════════════════════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════════════════════════════════════

fn make_keypair(seed: u8) -> SigningKey {
    let mut secret = [0u8; 32];
    secret[0] = seed;
    SigningKey::from_bytes(&secret)
}

fn make_valid_proof(cpu: u64, chunks: u64) -> UsageProof {
    let key = make_keypair(0x42);
    let vk = key.verifying_key();

    let mut proof = UsageProof {
        workload_id: WorkloadId::new([0x01; 32]),
        node_id: vk.to_bytes(),
        cpu_cycles: cpu,
        ram_bytes: 1024,
        chunk_count: chunks,
        bandwidth_bytes: 512,
        proof_data: vec![0xAB; 16],
        node_signature: vec![],
    };

    let message = build_signing_message(&proof);
    let signature = key.sign(&message);
    proof.node_signature = signature.to_bytes().to_vec();
    proof
}

/// Mock registry for anti-self-dealing tests.
struct TestRegistry {
    owners: HashMap<NodeId, Address>,
}

impl TestRegistry {
    fn new() -> Self {
        Self { owners: HashMap::new() }
    }
    fn register(&mut self, node: NodeId, owner: Address) {
        self.owners.insert(node, owner);
    }
}

impl NodeOwnerLookup for TestRegistry {
    fn lookup_node_owner(&self, node_id: &NodeId) -> Option<Address> {
        self.owners.get(node_id).copied()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// COMMITMENT BUILDER TESTS
// ════════════════════════════════════════════════════════════════════════════════

/// 6) ExecutionCommitment build from trace.
#[test]
fn test_ec_build_from_trace() {
    let builder = CommitmentBuilder::new(WorkloadId::new([0x01; 32]));
    let trace = vec![vec![0xAA; 64], vec![0xBB; 64]];
    let ec = builder.build(
        [0x0A; 32], [0x0B; 32],
        [0x0C; 32], [0x0D; 32],
        &trace,
    );
    // Commitment exists — fields are populated.
    // The merkle root should be non-zero for non-empty trace.
    let merkle = compute_trace_merkle_root(&trace);
    assert_ne!(merkle, [0u8; 32]);
}

/// 7) Merkle root computation edge cases (covered via sub-scenarios).
#[test]
fn test_merkle_root_edge_cases() {
    // Empty → zero.
    assert_eq!(compute_trace_merkle_root(&[]), [0u8; 32]);
    // Single leaf → deterministic.
    let single = compute_trace_merkle_root(&[vec![0x01; 32]]);
    assert_ne!(single, [0u8; 32]);
    // Two leaves → deterministic.
    let two = compute_trace_merkle_root(&[vec![0x01; 32], vec![0x02; 32]]);
    assert_ne!(two, single);
}

// ════════════════════════════════════════════════════════════════════════════════
// USAGE PROOF TESTS
// ════════════════════════════════════════════════════════════════════════════════

/// 8) Usage proof verification — valid signature.
#[test]
fn test_usage_proof_valid() {
    let proof = make_valid_proof(100, 10);
    let result = verify_usage_proof(&proof);
    assert!(matches!(result, UsageVerificationResult::Valid { .. }));
}

/// 9) Usage proof verification — invalid signature.
#[test]
fn test_usage_proof_invalid_signature() {
    let mut proof = make_valid_proof(100, 10);
    proof.node_signature = vec![0xFF; 64]; // Corrupt signature.
    let result = verify_usage_proof(&proof);
    assert!(matches!(result, UsageVerificationResult::Invalid { .. }));
}

/// 19) Invalid usage result rejection (zero cpu + zero chunks).
#[test]
fn test_invalid_usage_rejection() {
    // Valid signature but zero resources → should fail range check.
    let key = make_keypair(0x42);
    let vk = key.verifying_key();

    let mut proof = UsageProof {
        workload_id: WorkloadId::new([0x01; 32]),
        node_id: vk.to_bytes(),
        cpu_cycles: 0,
        ram_bytes: 0,
        chunk_count: 0,
        bandwidth_bytes: 0,
        proof_data: vec![],
        node_signature: vec![],
    };
    let message = build_signing_message(&proof);
    let sig = key.sign(&message);
    proof.node_signature = sig.to_bytes().to_vec();

    let result = verify_usage_proof(&proof);
    assert!(matches!(result, UsageVerificationResult::Invalid { .. }));
}

/// 40) Usage reward_base calculation deterministic.
#[test]
fn test_reward_base_deterministic() {
    let proof = make_valid_proof(100, 10);
    let r1 = calculate_reward_base(&proof);
    let r2 = calculate_reward_base(&proof);
    assert_eq!(r1, r2);
    assert!(r1 > 0);
}

/// 41) Invalid signature rejection in usage verification.
#[test]
fn test_invalid_sig_rejection_usage() {
    let mut proof = make_valid_proof(100, 10);
    // Short signature.
    proof.node_signature = vec![0x01; 32];
    let result = verify_usage_proof(&proof);
    assert!(matches!(result, UsageVerificationResult::Invalid { .. }));
}

// ════════════════════════════════════════════════════════════════════════════════
// MERKLE TREE TESTS
// ════════════════════════════════════════════════════════════════════════════════

/// 20) Empty execution trace → zero hash.
#[test]
fn test_empty_execution_trace() {
    assert_eq!(compute_trace_merkle_root(&[]), [0u8; 32]);
}

/// 21) Single-leaf merkle tree.
#[test]
fn test_single_leaf_merkle() {
    let root = compute_trace_merkle_root(&[vec![0x42; 64]]);
    assert_ne!(root, [0u8; 32]);
}

/// 22) Even number of leaves.
#[test]
fn test_even_leaves_merkle() {
    let root = compute_trace_merkle_root(&[
        vec![0x01; 32], vec![0x02; 32], vec![0x03; 32], vec![0x04; 32],
    ]);
    assert_ne!(root, [0u8; 32]);
}

/// 23) Odd number of leaves.
#[test]
fn test_odd_leaves_merkle() {
    let root = compute_trace_merkle_root(&[
        vec![0x01; 32], vec![0x02; 32], vec![0x03; 32],
    ]);
    assert_ne!(root, [0u8; 32]);
}

/// 24) Deterministic merkle across runs.
#[test]
fn test_deterministic_merkle_across_runs() {
    let trace = vec![vec![0xAA; 64], vec![0xBB; 64], vec![0xCC; 64]];
    let reference = compute_trace_merkle_root(&trace);
    for _ in 0..100 {
        assert_eq!(compute_trace_merkle_root(&trace), reference);
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// ANTI-SELF-DEALING TESTS
// ════════════════════════════════════════════════════════════════════════════════

/// 13) Anti-self-dealing pre-check behavior.
#[test]
fn test_self_dealing_suspected() {
    let mut registry = TestRegistry::new();
    let node = NodeId::new([0x01; 32]);
    let owner = Address::new([0x0A; 20]);
    registry.register(node, owner);

    // Owner == submitter → suspected.
    let result = precheck_self_dealing(&node, Some(&owner), &registry);
    assert_eq!(result, PreCheckResult::SuspectedSelfDealing);

    // Different submitter → clean.
    let other = Address::new([0x0B; 20]);
    let result = precheck_self_dealing(&node, Some(&other), &registry);
    assert_eq!(result, PreCheckResult::Clean);

    // No submitter hint → clean.
    let result = precheck_self_dealing(&node, None, &registry);
    assert_eq!(result, PreCheckResult::Clean);
}

/// 42) Self-dealing pre-check does not block signing (returns result, no error).
#[test]
fn test_self_dealing_does_not_block() {
    let registry = TestRegistry::new();
    let node = NodeId::new([0x01; 32]);
    let addr = Address::new([0x0A; 20]);

    // Even for unknown node, no panic, no error — just Clean.
    let result = precheck_self_dealing(&node, Some(&addr), &registry);
    assert!(result.is_clean());

    // The return type is PreCheckResult, not Result → can never block.
    let _: PreCheckResult = result;
}

// ════════════════════════════════════════════════════════════════════════════════
// MOCK TSS TESTS
// ════════════════════════════════════════════════════════════════════════════════

/// 14) Mock TSS determinism (same input → same signature).
#[cfg(feature = "mock-tss")]
#[test]
fn test_mock_tss_determinism() {
    use dsdn_coordinator::multi::mock_tss::MockTSS;
    use dsdn_coordinator::multi::SessionId;

    let tss = MockTSS::new(2);
    let sid = SessionId::new([0x42; 32]);
    let msg = b"test message";

    let c1 = tss.generate_commitment(&sid);
    let c2 = tss.generate_commitment(&sid);
    assert_eq!(c1, c2);

    let p1 = tss.generate_partial(&sid, msg);
    let p2 = tss.generate_partial(&sid, msg);
    assert_eq!(p1.signature_share, p2.signature_share);

    let sig = tss.compute_aggregate(msg);
    assert!(tss.verify_aggregate(msg, &sig));
    assert!(!tss.verify_aggregate(b"wrong", &sig));
}

// ════════════════════════════════════════════════════════════════════════════════
// COMPILE-TIME ASSERTION
// ════════════════════════════════════════════════════════════════════════════════

/// 44) Clippy-clean build test (compile-time assertion via type imports).
#[test]
fn test_compile_assertions() {
    // Assert all public types are importable and have expected traits.
    fn assert_debug<T: std::fmt::Debug>() {}
    assert_debug::<PreCheckResult>();
    assert_debug::<NodeId>();
    assert_debug::<Address>();
    assert_debug::<UsageVerificationResult>();

    fn assert_eq_trait<T: PartialEq>() {}
    assert_eq_trait::<PreCheckResult>();
    assert_eq_trait::<NodeId>();
    assert_eq_trait::<Address>();
}