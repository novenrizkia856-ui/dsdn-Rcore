//! # Deterministic Binary Merkle Tree (14C.B.1)
//!
//! Computes Merkle root over execution trace steps using SHA3-256.
//!
//! ## Algorithm — MUST be byte-identical to coordinator
//!
//! This implementation replicates the exact algorithm from
//! `coordinator/src/execution/commitment_builder.rs::compute_trace_merkle_root`.
//! Any divergence breaks fraud-proof reproducibility.
//!
//! ### Leaf Format
//!
//! ```text
//! leaf_hash = SHA3-256(step_bytes)
//! ```
//!
//! ### Parent Format
//!
//! ```text
//! parent_hash = SHA3-256(left_hash ‖ right_hash)
//! ```
//!
//! ### Odd Node Count — Duplicate-Last Rule
//!
//! ```text
//! [A, B, C] → [hash(A,B), hash(C,C)]
//! ```
//!
//! ### Empty Trace
//!
//! Returns `[0u8; 32]` (zero hash sentinel).
//!
//! ## Determinism
//!
//! - No sorting, no shuffling, no randomness.
//! - No global state, no pointer-dependent ordering.
//! - Input order preserved exactly.
//! - Same input → same output, always.
//!
//! ## Safety
//!
//! - No panic, unwrap, expect, todo, unreachable.
//! - No mutation of input data.
//! - No unsafe code.
//! - Pure function: no I/O, no side effects.

use sha3::{Digest, Sha3_256};

// ════════════════════════════════════════════════════════════════════════════════
// PUBLIC API
// ════════════════════════════════════════════════════════════════════════════════

/// Computes a deterministic binary Merkle root over execution trace steps.
///
/// # Algorithm
///
/// 1. **Empty trace** → `[0u8; 32]` (zero hash sentinel).
/// 2. **Single step** → `SHA3-256(step_bytes)`.
/// 3. **Multiple steps**:
///    - Compute leaf hashes: `leaf_i = SHA3-256(trace[i])`.
///    - Iteratively reduce:
///      - Pair adjacent nodes: `parent = SHA3-256(left ‖ right)`.
///      - If odd count at any level, duplicate the last node.
///    - Continue until one root remains.
///
/// # Determinism
///
/// Same `trace` (same elements, same order) always produces the same
/// 32-byte root. This function is a pure function with no side effects.
///
/// # Cross-Crate Compatibility
///
/// This implementation is algorithmically identical to
/// `coordinator::execution::compute_trace_merkle_root`. Both MUST
/// produce the same output for the same input. Any divergence
/// breaks the fraud-proof verification chain.
#[must_use]
pub fn compute_trace_merkle_root(trace: &[Vec<u8>]) -> [u8; 32] {
    // Empty trace → zero hash.
    if trace.is_empty() {
        return [0u8; 32];
    }

    // Compute leaf hashes.
    let mut current_level: Vec<[u8; 32]> = trace.iter().map(|step| sha3_256(step)).collect();

    // Reduce until single root.
    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);

        let mut i = 0;
        while i < current_level.len() {
            let left = current_level[i];
            // If odd count, duplicate last node.
            let right = if i + 1 < current_level.len() {
                current_level[i + 1]
            } else {
                current_level[i] // Duplicate last.
            };

            next_level.push(sha3_256_pair(&left, &right));
            i += 2;
        }

        current_level = next_level;
    }

    current_level[0]
}

// ════════════════════════════════════════════════════════════════════════════════
// INTERNAL HELPERS
// ════════════════════════════════════════════════════════════════════════════════

/// SHA3-256 hash of arbitrary bytes.
#[inline]
fn sha3_256(data: &[u8]) -> [u8; 32] {
    let result = Sha3_256::digest(data);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// SHA3-256 hash of two 32-byte nodes concatenated: `SHA3-256(left ‖ right)`.
#[inline]
fn sha3_256_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(left);
    hasher.update(right);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── 1) Empty trace returns zero hash ────────────────────────────────

    #[test]
    fn empty_trace_returns_zero_hash() {
        let root = compute_trace_merkle_root(&[]);
        assert_eq!(root, [0u8; 32]);
    }

    // ── 2) Single leaf ──────────────────────────────────────────────────

    #[test]
    fn single_leaf() {
        let step = vec![0x42; 64];
        let root = compute_trace_merkle_root(&[step.clone()]);
        let expected = sha3_256(&step);
        assert_eq!(root, expected);
        assert_ne!(root, [0u8; 32]);
    }

    // ── 3) Even number of leaves ────────────────────────────────────────

    #[test]
    fn even_number_of_leaves() {
        let a = vec![0x01; 16];
        let b = vec![0x02; 16];
        let root = compute_trace_merkle_root(&[a.clone(), b.clone()]);

        let ha = sha3_256(&a);
        let hb = sha3_256(&b);
        let expected = sha3_256_pair(&ha, &hb);
        assert_eq!(root, expected);
    }

    // ── 4) Odd number of leaves — duplicate last ────────────────────────

    #[test]
    fn odd_number_of_leaves_duplicate_last() {
        let a = vec![0x01];
        let b = vec![0x02];
        let c = vec![0x03];
        let root = compute_trace_merkle_root(&[a.clone(), b.clone(), c.clone()]);

        let ha = sha3_256(&a);
        let hb = sha3_256(&b);
        let hc = sha3_256(&c);

        // Level 1: [hash(A,B), hash(C,C)]
        let left = sha3_256_pair(&ha, &hb);
        let right = sha3_256_pair(&hc, &hc); // duplicate last
        let expected = sha3_256_pair(&left, &right);

        assert_eq!(root, expected);
    }

    // ── 5) Deterministic repeat 100x ────────────────────────────────────

    #[test]
    fn deterministic_repeat_100x() {
        let trace = vec![vec![0xAB; 100], vec![0xCD; 200], vec![0xEF; 50]];
        let reference = compute_trace_merkle_root(&trace);
        for _ in 0..100 {
            assert_eq!(compute_trace_merkle_root(&trace), reference);
        }
    }

    // ── 6) Cross-check with manual small tree (4 leaves balanced) ───────

    #[test]
    fn cross_check_manual_four_leaves() {
        let steps: Vec<Vec<u8>> = (0u8..4).map(|i| vec![i]).collect();
        let root = compute_trace_merkle_root(&steps);

        let h: Vec<[u8; 32]> = steps.iter().map(|s| sha3_256(s)).collect();
        let l1_0 = sha3_256_pair(&h[0], &h[1]);
        let l1_1 = sha3_256_pair(&h[2], &h[3]);
        let expected = sha3_256_pair(&l1_0, &l1_1);

        assert_eq!(root, expected);
    }

    // ── 7) No mutation of input ─────────────────────────────────────────

    #[test]
    fn no_mutation_of_input() {
        let trace = vec![vec![0x01; 8], vec![0x02; 8], vec![0x03; 8]];
        let trace_before = trace.clone();
        let _ = compute_trace_merkle_root(&trace);
        assert_eq!(trace, trace_before);
    }

    // ── 8) Five elements unbalanced (matches coordinator test) ──────────

    #[test]
    fn five_elements_unbalanced() {
        let steps: Vec<Vec<u8>> = (0u8..5).map(|i| vec![i]).collect();
        let root = compute_trace_merkle_root(&steps);

        let h: Vec<[u8; 32]> = steps.iter().map(|s| sha3_256(s)).collect();
        // Level 1: [hash(0,1), hash(2,3), hash(4,4)]
        let l1_0 = sha3_256_pair(&h[0], &h[1]);
        let l1_1 = sha3_256_pair(&h[2], &h[3]);
        let l1_2 = sha3_256_pair(&h[4], &h[4]); // duplicate last

        // Level 2: [hash(l1_0, l1_1), hash(l1_2, l1_2)]
        let l2_0 = sha3_256_pair(&l1_0, &l1_1);
        let l2_1 = sha3_256_pair(&l1_2, &l1_2); // duplicate last

        let expected = sha3_256_pair(&l2_0, &l2_1);
        assert_eq!(root, expected);
    }

    // ── 9) Order matters ────────────────────────────────────────────────

    #[test]
    fn order_matters() {
        let a = vec![0x01];
        let b = vec![0x02];
        let root_ab = compute_trace_merkle_root(&[a.clone(), b.clone()]);
        let root_ba = compute_trace_merkle_root(&[b, a]);
        assert_ne!(root_ab, root_ba);
    }

    // ── 10) Large trace no panic ────────────────────────────────────────

    #[test]
    fn large_trace_no_panic() {
        let steps: Vec<Vec<u8>> = (0u16..1000).map(|i| i.to_le_bytes().to_vec()).collect();
        let root = compute_trace_merkle_root(&steps);
        assert_ne!(root, [0u8; 32]);
    }
}