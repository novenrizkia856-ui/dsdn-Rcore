//! # Deterministic Binary Merkle Tree (VM Runtime)
//!
//! Byte-identical implementation of the Merkle tree algorithm used by
//! `runtime_wasm::merkle` and `coordinator::execution::commitment_builder`.
//!
//! ## Algorithm
//!
//! - Empty trace → `[0u8; 32]`
//! - Leaf: `SHA3-256(step_bytes)`
//! - Parent: `SHA3-256(left || right)`
//! - Odd node count: duplicate last node
//!
//! ## Cross-Runtime Invariant
//!
//! This implementation MUST produce byte-identical roots to the WASM runtime
//! and coordinator implementations. Any divergence breaks fraud-proof
//! reproducibility and cross-runtime commitment verification.

use sha3::{Digest, Sha3_256};

/// Computes a binary Merkle root over execution trace steps.
///
/// Algorithm is byte-identical to `runtime_wasm::merkle::compute_trace_merkle_root`
/// and `coordinator::execution::compute_trace_merkle_root`.
///
/// # Arguments
///
/// * `trace` — Ordered slice of execution step byte vectors.
///
/// # Returns
///
/// 32-byte SHA3-256 Merkle root. Returns `[0u8; 32]` for empty trace.
///
/// # Determinism
///
/// Pure function. Same trace → same root, always.
#[must_use]
pub fn compute_trace_merkle_root(trace: &[Vec<u8>]) -> [u8; 32] {
    if trace.is_empty() {
        return [0u8; 32];
    }

    // Hash each step to produce leaves
    let mut nodes: Vec<[u8; 32]> = trace
        .iter()
        .map(|step| {
            let mut hasher = Sha3_256::new();
            hasher.update(step);
            let result = hasher.finalize();
            let mut out = [0u8; 32];
            out.copy_from_slice(&result);
            out
        })
        .collect();

    // Build tree bottom-up
    while nodes.len() > 1 {
        // Odd count: duplicate last
        if nodes.len() % 2 != 0 {
            let last = nodes[nodes.len() - 1];
            nodes.push(last);
        }

        let mut parents = Vec::with_capacity(nodes.len() / 2);
        for pair in nodes.chunks_exact(2) {
            let mut hasher = Sha3_256::new();
            hasher.update(pair[0]);
            hasher.update(pair[1]);
            let result = hasher.finalize();
            let mut out = [0u8; 32];
            out.copy_from_slice(&result);
            parents.push(out);
        }
        nodes = parents;
    }

    nodes[0]
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_trace_returns_zero_hash() {
        assert_eq!(compute_trace_merkle_root(&[]), [0u8; 32]);
    }

    #[test]
    fn single_step_returns_leaf_hash() {
        let step = b"single-step-data".to_vec();
        let root = compute_trace_merkle_root(&[step.clone()]);

        // Leaf hash: SHA3-256(step)
        let mut hasher = Sha3_256::new();
        hasher.update(&step);
        let expected = hasher.finalize();
        let mut expected_arr = [0u8; 32];
        expected_arr.copy_from_slice(&expected);

        assert_eq!(root, expected_arr);
    }

    #[test]
    fn even_leaves_balanced_tree() {
        let a = b"step-a".to_vec();
        let b = b"step-b".to_vec();
        let root = compute_trace_merkle_root(&[a, b]);
        assert_ne!(root, [0u8; 32]);
    }

    #[test]
    fn odd_leaves_duplicate_last() {
        let a = b"alpha".to_vec();
        let b = b"beta".to_vec();
        let c = b"gamma".to_vec();
        let root = compute_trace_merkle_root(&[a, b, c]);
        assert_ne!(root, [0u8; 32]);
    }

    #[test]
    fn determinism_100x() {
        let trace = vec![b"x".to_vec(), b"y".to_vec(), b"z".to_vec()];
        let reference = compute_trace_merkle_root(&trace);
        for _ in 0..100 {
            assert_eq!(compute_trace_merkle_root(&trace), reference);
        }
    }

    #[test]
    fn order_matters() {
        let a = vec![0x01; 16];
        let b = vec![0x02; 16];
        let root_ab = compute_trace_merkle_root(&[a.clone(), b.clone()]);
        let root_ba = compute_trace_merkle_root(&[b, a]);
        assert_ne!(root_ab, root_ba);
    }
}