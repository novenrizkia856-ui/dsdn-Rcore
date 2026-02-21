//! # CommitmentBuilder — Deterministic ExecutionCommitment Construction (CO.2)
//!
//! Builds [`ExecutionCommitment`] from workload execution results, including
//! deterministic Merkle root computation over execution traces.
//!
//! ## Merkle Tree Algorithm
//!
//! ### Leaf Format
//!
//! Each execution trace step is hashed individually:
//! ```text
//! leaf_hash = SHA3-256(step_bytes)
//! ```
//!
//! ### Parent Format
//!
//! Internal nodes are computed by hashing the concatenation of children:
//! ```text
//! parent_hash = SHA3-256(left_hash ‖ right_hash)
//! ```
//! Where `‖` denotes byte concatenation (64 bytes input → 32 bytes output).
//!
//! ### Odd Node Count — Duplicate-Last Rule
//!
//! If a tree level has an odd number of nodes, the **last** node is
//! duplicated to form a complete pair:
//! ```text
//! [A, B, C] → [hash(A,B), hash(C,C)]
//! ```
//!
//! ### Empty Trace
//!
//! An empty execution trace produces the **zero hash** `[0u8; 32]`.
//! Rationale: an empty trace carries no cryptographic commitment.
//! This is a sentinel value, not a valid SHA3-256 digest.
//!
//! ### Determinism Guarantee
//!
//! Given identical `execution_trace` input (same elements in same order),
//! `compute_trace_merkle_root` always returns the same `[u8; 32]` root.
//! No randomness, no global state, no pointer-dependent ordering.
//!
//! ## Safety
//!
//! - No panic, unwrap, expect, todo, unreachable in any code path.
//! - No heap allocation beyond what `Vec<[u8; 32]>` requires for tree levels.
//! - No mutation of input data.
//! - Fully deterministic.

use dsdn_common::coordinator::WorkloadId;
use dsdn_common::execution_commitment::ExecutionCommitment;
use sha3::{Digest, Sha3_256};

// ════════════════════════════════════════════════════════════════════════════════
// COMMITMENT BUILDER
// ════════════════════════════════════════════════════════════════════════════════

/// Builder for constructing [`ExecutionCommitment`] from workload execution results.
///
/// Holds the `workload_id` and provides a `build` method that accepts
/// execution outputs and computes the Merkle root over the trace.
///
/// ## Usage
///
/// ```ignore
/// let builder = CommitmentBuilder::new(workload_id);
/// let ec = builder.build(input_hash, output_hash, sr_before, sr_after, &trace);
/// ```
///
/// ## Thread Safety
///
/// Immutable after construction. All methods take `&self`.
/// Safe to share across threads.
pub struct CommitmentBuilder {
    workload_id: WorkloadId,
}

impl CommitmentBuilder {
    /// Creates a new `CommitmentBuilder` for the given workload.
    ///
    /// # Arguments
    ///
    /// * `workload_id` — Unique identifier for the workload being executed.
    #[must_use]
    #[inline]
    pub const fn new(workload_id: WorkloadId) -> Self {
        Self { workload_id }
    }

    /// Builds an [`ExecutionCommitment`] from execution results.
    ///
    /// Computes the Merkle root of `execution_trace` via
    /// [`compute_trace_merkle_root`] and delegates to
    /// [`ExecutionCommitment::new`].
    ///
    /// # Arguments
    ///
    /// * `input_hash` — SHA3-256 hash of workload input data.
    /// * `output_hash` — SHA3-256 hash of workload output data.
    /// * `state_root_before` — State root before execution started.
    /// * `state_root_after` — State root after execution completed.
    /// * `execution_trace` — Ordered list of execution trace step bytes.
    ///
    /// # Returns
    ///
    /// A fully constructed `ExecutionCommitment`. Cannot fail. Cannot panic.
    ///
    /// # Determinism
    ///
    /// Same inputs always produce the same `ExecutionCommitment`.
    /// The `execution_trace_merkle_root` field is derived deterministically
    /// from the trace via binary Merkle tree with SHA3-256.
    #[must_use]
    pub fn build(
        &self,
        input_hash: [u8; 32],
        output_hash: [u8; 32],
        state_root_before: [u8; 32],
        state_root_after: [u8; 32],
        execution_trace: &[Vec<u8>],
    ) -> ExecutionCommitment {
        let merkle_root = compute_trace_merkle_root(execution_trace);

        ExecutionCommitment::new(
            self.workload_id,
            input_hash,
            output_hash,
            state_root_before,
            state_root_after,
            merkle_root,
        )
    }

    /// Returns the workload ID this builder is configured for.
    #[must_use]
    #[inline]
    pub const fn workload_id(&self) -> &WorkloadId {
        &self.workload_id
    }
}

impl std::fmt::Debug for CommitmentBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommitmentBuilder")
            .field("workload_id", &self.workload_id)
            .finish()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// MERKLE ROOT
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
/// - Input order preserved (no sorting, no shuffling).
/// - SHA3-256 is deterministic.
/// - Duplicate-last rule is deterministic.
/// - No global state, no randomness, no pointer-dependent ordering.
///
/// # Arguments
///
/// * `trace` — Ordered execution trace steps as raw byte vectors.
///
/// # Returns
///
/// 32-byte Merkle root. `[0u8; 32]` if trace is empty.
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

    // ── Helper ───────────────────────────────────────────────────────────

    fn wid(byte: u8) -> WorkloadId {
        WorkloadId::new([byte; 32])
    }

    // ── compute_trace_merkle_root ────────────────────────────────────────

    #[test]
    fn merkle_empty_trace_returns_zero_hash() {
        let root = compute_trace_merkle_root(&[]);
        assert_eq!(root, [0u8; 32]);
    }

    #[test]
    fn merkle_single_element_is_leaf_hash() {
        let step = vec![0x01, 0x02, 0x03];
        let root = compute_trace_merkle_root(&[step.clone()]);
        let expected = sha3_256(&step);
        assert_eq!(root, expected);
    }

    #[test]
    fn merkle_two_elements() {
        let a = vec![0x01];
        let b = vec![0x02];
        let root = compute_trace_merkle_root(&[a.clone(), b.clone()]);

        let ha = sha3_256(&a);
        let hb = sha3_256(&b);
        let expected = sha3_256_pair(&ha, &hb);
        assert_eq!(root, expected);
    }

    #[test]
    fn merkle_three_elements_duplicate_last() {
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

    #[test]
    fn merkle_four_elements_balanced() {
        let steps: Vec<Vec<u8>> = (0u8..4).map(|i| vec![i]).collect();
        let root = compute_trace_merkle_root(&steps);

        let h: Vec<[u8; 32]> = steps.iter().map(|s| sha3_256(s)).collect();
        let l1_0 = sha3_256_pair(&h[0], &h[1]);
        let l1_1 = sha3_256_pair(&h[2], &h[3]);
        let expected = sha3_256_pair(&l1_0, &l1_1);

        assert_eq!(root, expected);
    }

    #[test]
    fn merkle_five_elements_unbalanced() {
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

    #[test]
    fn merkle_deterministic_same_input() {
        let steps: Vec<Vec<u8>> = (0u8..7).map(|i| vec![i; 64]).collect();
        let r1 = compute_trace_merkle_root(&steps);
        let r2 = compute_trace_merkle_root(&steps);
        assert_eq!(r1, r2);
    }

    #[test]
    fn merkle_deterministic_100_iterations() {
        let steps = vec![vec![0xAB; 100], vec![0xCD; 200]];
        let reference = compute_trace_merkle_root(&steps);
        for _ in 0..100 {
            assert_eq!(compute_trace_merkle_root(&steps), reference);
        }
    }

    #[test]
    fn merkle_order_matters() {
        let a = vec![0x01];
        let b = vec![0x02];
        let root_ab = compute_trace_merkle_root(&[a.clone(), b.clone()]);
        let root_ba = compute_trace_merkle_root(&[b, a]);
        assert_ne!(root_ab, root_ba);
    }

    #[test]
    fn merkle_content_matters() {
        let root_a = compute_trace_merkle_root(&[vec![0x01]]);
        let root_b = compute_trace_merkle_root(&[vec![0x02]]);
        assert_ne!(root_a, root_b);
    }

    #[test]
    fn merkle_single_not_zero_hash() {
        let root = compute_trace_merkle_root(&[vec![0x00]]);
        // SHA3-256 of [0x00] is NOT zero.
        assert_ne!(root, [0u8; 32]);
    }

    #[test]
    fn merkle_large_trace_no_panic() {
        let steps: Vec<Vec<u8>> = (0u16..1000).map(|i| i.to_le_bytes().to_vec()).collect();
        let root = compute_trace_merkle_root(&steps);
        assert_ne!(root, [0u8; 32]);
    }

    // ── CommitmentBuilder ────────────────────────────────────────────────

    #[test]
    fn builder_new_stores_workload_id() {
        let builder = CommitmentBuilder::new(wid(0x42));
        assert_eq!(*builder.workload_id(), wid(0x42));
    }

    #[test]
    fn builder_build_returns_correct_fields() {
        let builder = CommitmentBuilder::new(wid(0x01));
        let ec = builder.build(
            [0x02; 32],
            [0x03; 32],
            [0x04; 32],
            [0x05; 32],
            &[vec![0xAA; 16]],
        );

        assert_eq!(*ec.workload_id(), wid(0x01));
        assert_eq!(*ec.input_hash(), [0x02; 32]);
        assert_eq!(*ec.output_hash(), [0x03; 32]);
        assert_eq!(*ec.state_root_before(), [0x04; 32]);
        assert_eq!(*ec.state_root_after(), [0x05; 32]);

        // Merkle root should be SHA3-256 of single element.
        let expected_root = sha3_256(&[0xAA; 16]);
        assert_eq!(*ec.execution_trace_merkle_root(), expected_root);
    }

    #[test]
    fn builder_build_empty_trace_zero_root() {
        let builder = CommitmentBuilder::new(wid(0x01));
        let ec = builder.build([0x02; 32], [0x03; 32], [0x04; 32], [0x05; 32], &[]);

        assert_eq!(*ec.execution_trace_merkle_root(), [0u8; 32]);
    }

    #[test]
    fn builder_build_multi_step_trace() {
        let builder = CommitmentBuilder::new(wid(0x01));
        let trace = vec![vec![0x10; 8], vec![0x20; 8], vec![0x30; 8]];
        let ec = builder.build([0x02; 32], [0x03; 32], [0x04; 32], [0x05; 32], &trace);

        let expected_root = compute_trace_merkle_root(&trace);
        assert_eq!(*ec.execution_trace_merkle_root(), expected_root);
    }

    #[test]
    fn builder_build_deterministic() {
        let builder = CommitmentBuilder::new(wid(0x01));
        let trace = vec![vec![0xAA], vec![0xBB]];

        let ec1 = builder.build([0x02; 32], [0x03; 32], [0x04; 32], [0x05; 32], &trace);
        let ec2 = builder.build([0x02; 32], [0x03; 32], [0x04; 32], [0x05; 32], &trace);

        assert_eq!(ec1, ec2);
        assert_eq!(ec1.compute_hash(), ec2.compute_hash());
    }

    #[test]
    fn builder_build_different_inputs_different_hash() {
        let builder = CommitmentBuilder::new(wid(0x01));
        let trace = vec![vec![0xAA]];

        let ec1 = builder.build([0x02; 32], [0x03; 32], [0x04; 32], [0x05; 32], &trace);
        let ec2 = builder.build([0xFF; 32], [0x03; 32], [0x04; 32], [0x05; 32], &trace);

        assert_ne!(ec1.compute_hash(), ec2.compute_hash());
    }

    #[test]
    fn builder_build_different_trace_different_root() {
        let builder = CommitmentBuilder::new(wid(0x01));

        let ec1 = builder.build(
            [0x02; 32], [0x03; 32], [0x04; 32], [0x05; 32],
            &[vec![0x01]],
        );
        let ec2 = builder.build(
            [0x02; 32], [0x03; 32], [0x04; 32], [0x05; 32],
            &[vec![0x02]],
        );

        assert_ne!(
            ec1.execution_trace_merkle_root(),
            ec2.execution_trace_merkle_root()
        );
        assert_ne!(ec1.compute_hash(), ec2.compute_hash());
    }

    #[test]
    fn builder_build_uses_execution_commitment_new() {
        // Verify the output matches direct ExecutionCommitment::new construction.
        let builder = CommitmentBuilder::new(wid(0x01));
        let trace = vec![vec![0xAA; 32]];
        let merkle_root = compute_trace_merkle_root(&trace);

        let via_builder = builder.build(
            [0x02; 32], [0x03; 32], [0x04; 32], [0x05; 32], &trace,
        );
        let via_direct = ExecutionCommitment::new(
            wid(0x01), [0x02; 32], [0x03; 32], [0x04; 32], [0x05; 32], merkle_root,
        );

        assert_eq!(via_builder, via_direct);
        assert_eq!(via_builder.compute_hash(), via_direct.compute_hash());
    }

    #[test]
    fn builder_does_not_mutate_trace() {
        let trace = vec![vec![0x01; 8], vec![0x02; 8]];
        let trace_clone = trace.clone();
        let builder = CommitmentBuilder::new(wid(0x01));

        let _ = builder.build([0; 32], [0; 32], [0; 32], [0; 32], &trace);

        assert_eq!(trace, trace_clone);
    }

    // ── Debug ────────────────────────────────────────────────────────────

    #[test]
    fn builder_debug_format() {
        let builder = CommitmentBuilder::new(wid(0x42));
        let dbg = format!("{:?}", builder);
        assert!(dbg.contains("CommitmentBuilder"));
    }

    // ── Edge cases: SHA3-256 internal helpers ────────────────────────────

    #[test]
    fn sha3_256_empty_input_not_zero() {
        let hash = sha3_256(&[]);
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn sha3_256_pair_deterministic() {
        let a = [0x01; 32];
        let b = [0x02; 32];
        let h1 = sha3_256_pair(&a, &b);
        let h2 = sha3_256_pair(&a, &b);
        assert_eq!(h1, h2);
    }

    #[test]
    fn sha3_256_pair_order_matters() {
        let a = [0x01; 32];
        let b = [0x02; 32];
        let h_ab = sha3_256_pair(&a, &b);
        let h_ba = sha3_256_pair(&b, &a);
        assert_ne!(h_ab, h_ba);
    }
}