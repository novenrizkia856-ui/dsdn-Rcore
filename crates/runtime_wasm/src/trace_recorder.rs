//! # Execution Trace Recorder (14C.B.3)
//!
//! Incremental recorder for WASM execution trace steps.
//!
//! ## Role in Pipeline
//!
//! During WASM execution, each significant execution step is recorded
//! via [`ExecutionTraceRecorder::record_step`]. After execution completes,
//! [`ExecutionTraceRecorder::finalize`] computes the Merkle root over
//! all recorded steps and returns both the raw trace and the root.
//!
//! ```text
//! WASM execution loop:
//!   recorder.record_step(step_1)
//!   recorder.record_step(step_2)
//!   ...
//!   recorder.record_step(step_N)
//!
//! After execution:
//!   let (raw_steps, merkle_root) = recorder.finalize();
//! ```
//!
//! ## Why Hashing at Finalize, Not Incrementally
//!
//! The binary Merkle tree algorithm requires all leaves to be known
//! before computing the root (the tree structure depends on total
//! leaf count for the duplicate-last rule). Incremental hashing would
//! require a different algorithm (e.g., streaming Merkle) that would
//! diverge from the coordinator's batch algorithm. To guarantee
//! byte-identical roots, hashing is deferred to `finalize()`.
//!
//! ## Why `finalize` Consumes `self`
//!
//! `finalize(self)` takes ownership to prevent accidental reuse
//! after finalization. Once finalized, the recorder's steps are moved
//! into the return value. No dangling state, no double-finalize.
//!
//! ## Determinism
//!
//! - Steps are appended in insertion order, never reordered.
//! - `finalize` delegates to `compute_trace_merkle_root` (14C.B.1).
//! - Same step sequence → same Merkle root, always.
//!
//! ## Safety
//!
//! - No panic, unwrap, expect, todo, unreachable.
//! - No unsafe code.
//! - No global state.
//! - `step_count` uses `saturating_add` to prevent overflow.

use crate::merkle::compute_trace_merkle_root;

// ════════════════════════════════════════════════════════════════════════════════
// EXECUTION TRACE RECORDER
// ════════════════════════════════════════════════════════════════════════════════

/// Records execution trace steps incrementally during WASM execution.
///
/// Steps are stored as raw byte vectors in insertion order.
/// The Merkle root is computed only at [`finalize`](Self::finalize) time
/// via [`compute_trace_merkle_root`].
///
/// ## Invariant
///
/// `self.steps.len() as u64 == self.step_count` holds at all times.
/// `step_count` uses `saturating_add` so it never panics on overflow
/// (at `u64::MAX` it stops incrementing, which is a theoretical limit
/// of 18.4 exasteps — unreachable in practice).
#[derive(Debug, Clone)]
pub struct ExecutionTraceRecorder {
    /// Raw execution trace steps in insertion order.
    steps: Vec<Vec<u8>>,
    /// Number of recorded steps. Invariant: `steps.len() as u64 == step_count`.
    step_count: u64,
}

impl ExecutionTraceRecorder {
    /// Creates a new empty recorder.
    ///
    /// `step_count` starts at 0. `is_empty()` returns `true`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            steps: Vec::new(),
            step_count: 0,
        }
    }

    /// Records a single execution trace step.
    ///
    /// Appends a copy of `step_data` to the internal step list.
    /// Does not modify `step_data`. Does not perform any hashing.
    ///
    /// # Overflow Safety
    ///
    /// `step_count` uses `saturating_add(1)`. At `u64::MAX` (18.4 × 10¹⁸)
    /// the counter saturates. In practice, memory exhaustion would occur
    /// long before this limit.
    pub fn record_step(&mut self, step_data: &[u8]) {
        self.steps.push(step_data.to_vec());
        self.step_count = self.step_count.saturating_add(1);
    }

    /// Finalizes the recorder, computing the Merkle root over all steps.
    ///
    /// Consumes `self` to prevent reuse after finalization.
    ///
    /// # Returns
    ///
    /// `(raw_steps, merkle_root)` where:
    /// - `raw_steps`: All recorded steps in insertion order.
    /// - `merkle_root`: Binary SHA3-256 Merkle root via
    ///   [`compute_trace_merkle_root`]. `[0u8; 32]` if no steps.
    ///
    /// # Determinism
    ///
    /// Same step sequence → same `merkle_root`, always.
    #[must_use]
    pub fn finalize(self) -> (Vec<Vec<u8>>, [u8; 32]) {
        let merkle_root = compute_trace_merkle_root(&self.steps);
        (self.steps, merkle_root)
    }

    /// Returns the number of recorded steps.
    #[must_use]
    #[inline]
    pub const fn step_count(&self) -> u64 {
        self.step_count
    }

    /// Returns `true` if no steps have been recorded.
    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }
}

impl Default for ExecutionTraceRecorder {
    fn default() -> Self {
        Self::new()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::compute_trace_merkle_root;

    // ── 1) Empty recorder ───────────────────────────────────────────────

    #[test]
    fn empty_recorder() {
        let recorder = ExecutionTraceRecorder::new();
        assert!(recorder.is_empty());
        assert_eq!(recorder.step_count(), 0);

        let (steps, root) = recorder.finalize();
        assert!(steps.is_empty());
        assert_eq!(root, [0u8; 32]); // empty trace → zero hash
    }

    // ── 2) Single step ──────────────────────────────────────────────────

    #[test]
    fn single_step() {
        let mut recorder = ExecutionTraceRecorder::new();
        recorder.record_step(&[0x42; 64]);

        assert!(!recorder.is_empty());
        assert_eq!(recorder.step_count(), 1);

        let (steps, root) = recorder.finalize();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0], vec![0x42; 64]);

        // Root must match direct merkle computation
        let expected = compute_trace_merkle_root(&[vec![0x42; 64]]);
        assert_eq!(root, expected);
        assert_ne!(root, [0u8; 32]);
    }

    // ── 3) Multi-step order sensitive ───────────────────────────────────

    #[test]
    fn multi_step_order_sensitive() {
        let a = [0x01; 8];
        let b = [0x02; 8];
        let c = [0x03; 8];

        // Record A, B, C
        let mut rec_abc = ExecutionTraceRecorder::new();
        rec_abc.record_step(&a);
        rec_abc.record_step(&b);
        rec_abc.record_step(&c);
        let (_, root_abc) = rec_abc.finalize();

        // Record C, B, A
        let mut rec_cba = ExecutionTraceRecorder::new();
        rec_cba.record_step(&c);
        rec_cba.record_step(&b);
        rec_cba.record_step(&a);
        let (_, root_cba) = rec_cba.finalize();

        assert_ne!(root_abc, root_cba);
    }

    // ── 4) Finalize determinism repeat 100x ─────────────────────────────

    #[test]
    fn finalize_determinism_repeat_100x() {
        let step_a = vec![0xAA; 32];
        let step_b = vec![0xBB; 64];
        let step_c = vec![0xCC; 16];

        let mut reference_root = [0u8; 32];

        for i in 0..100 {
            let mut recorder = ExecutionTraceRecorder::new();
            recorder.record_step(&step_a);
            recorder.record_step(&step_b);
            recorder.record_step(&step_c);
            let (_, root) = recorder.finalize();

            if i == 0 {
                reference_root = root;
            }
            assert_eq!(root, reference_root);
        }
    }

    // ── 5) Step count consistency ───────────────────────────────────────

    #[test]
    fn step_count_consistency() {
        let mut recorder = ExecutionTraceRecorder::new();
        for i in 0u16..50 {
            assert_eq!(recorder.step_count(), u64::from(i));
            recorder.record_step(&i.to_le_bytes());
        }
        assert_eq!(recorder.step_count(), 50);

        let (steps, _) = recorder.finalize();
        assert_eq!(steps.len(), 50);
    }

    // ── 6) No input mutation ────────────────────────────────────────────

    #[test]
    fn no_input_mutation() {
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let data_before = data.clone();

        let mut recorder = ExecutionTraceRecorder::new();
        recorder.record_step(&data);

        assert_eq!(data, data_before);
    }

    // ── 7) Finalize consumes recorder (compile-time check) ──────────────

    #[test]
    fn finalize_consumes_recorder() {
        let mut recorder = ExecutionTraceRecorder::new();
        recorder.record_step(&[0x01]);
        let (_steps, _root) = recorder.finalize();
        // After this line, `recorder` is moved and cannot be used.
        // Uncommenting the next line would cause a compile error:
        // let _ = recorder.step_count(); // ERROR: value used after move
    }

    // ── 8) Root matches direct merkle call ──────────────────────────────

    #[test]
    fn root_matches_direct_merkle() {
        let steps_data: Vec<Vec<u8>> = (0u8..7).map(|i| vec![i; 32]).collect();

        let mut recorder = ExecutionTraceRecorder::new();
        for step in &steps_data {
            recorder.record_step(step);
        }
        let (returned_steps, root) = recorder.finalize();

        // Root must be identical to direct call
        let expected = compute_trace_merkle_root(&steps_data);
        assert_eq!(root, expected);

        // Steps must be identical in content and order
        assert_eq!(returned_steps, steps_data);
    }

    // ── 9) Default trait ────────────────────────────────────────────────

    #[test]
    fn default_creates_empty() {
        let recorder = ExecutionTraceRecorder::default();
        assert!(recorder.is_empty());
        assert_eq!(recorder.step_count(), 0);
    }

    // ── 10) Debug format ────────────────────────────────────────────────

    #[test]
    fn debug_format() {
        let mut recorder = ExecutionTraceRecorder::new();
        recorder.record_step(&[0xAB]);
        let dbg = format!("{:?}", recorder);
        assert!(dbg.contains("ExecutionTraceRecorder"));
    }
}