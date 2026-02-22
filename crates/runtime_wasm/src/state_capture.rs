//! # State Capture — Domain-Separated Hashing (14C.B.2)
//!
//! Deterministic SHA3-256 hashing functions for WASM execution state:
//! input data, output data, and linear memory snapshots.
//!
//! ## Domain Separation
//!
//! Each hash function uses a unique ASCII prefix to ensure that identical
//! byte sequences hashed in different contexts produce different digests.
//! This prevents cross-context hash collisions where, for example,
//! `hash_input(x) == hash_output(x)` would be a security vulnerability.
//!
//! | Function | Domain Prefix (ASCII) |
//! |----------|----------------------|
//! | `hash_input` | `DSDN:wasm_input:v1:` |
//! | `hash_output` | `DSDN:wasm_output:v1:` |
//! | `hash_memory_snapshot` | `DSDN:wasm_memory:v1:` |
//!
//! ## Version Tag (`v1`)
//!
//! The `v1` version tag in each prefix allows future changes to the
//! hashing scheme (e.g., adding length prefixes, changing encoding)
//! without breaking backward compatibility. A new version would use
//! `v2` prefix, producing entirely different hashes.
//!
//! ## Execution Timeline
//!
//! These functions are called at specific points during WASM execution:
//!
//! ```text
//! hash_input(input_bytes)        ← Before execution
//! hash_memory_snapshot(memory)   ← After instantiation (state_root_before)
//!     ... WASM execution ...
//! hash_output(stdout_bytes)      ← After execution
//! hash_memory_snapshot(memory)   ← After execution (state_root_after)
//! ```
//!
//! ## Fraud-Proof Reproducibility
//!
//! All functions are pure, deterministic, and side-effect-free.
//! Same input bytes → same hash, always. This is required for
//! fraud-proof verification where a challenger must reproduce the
//! exact same hashes from the same workload data.
//!
//! ## Safety
//!
//! - No panic, unwrap, expect, todo, unreachable.
//! - No unsafe code.
//! - No mutation of input data.
//! - No global state.
//! - No I/O or side effects.
//! - Empty input is valid and produces SHA3-256(prefix).

use sha3::{Digest, Sha3_256};

// ════════════════════════════════════════════════════════════════════════════════
// DOMAIN PREFIXES — CONSENSUS-CRITICAL, IMMUTABLE
// ════════════════════════════════════════════════════════════════════════════════

/// Domain prefix for input hashing. 20 bytes ASCII.
const INPUT_PREFIX: &[u8] = b"DSDN:wasm_input:v1:";

/// Domain prefix for output hashing. 21 bytes ASCII.
const OUTPUT_PREFIX: &[u8] = b"DSDN:wasm_output:v1:";

/// Domain prefix for memory snapshot hashing. 21 bytes ASCII.
const MEMORY_PREFIX: &[u8] = b"DSDN:wasm_memory:v1:";

// ════════════════════════════════════════════════════════════════════════════════
// PUBLIC API
// ════════════════════════════════════════════════════════════════════════════════

/// Computes domain-separated SHA3-256 hash of workload input data.
///
/// ```text
/// hash = SHA3-256(b"DSDN:wasm_input:v1:" ‖ input_bytes)
/// ```
///
/// # Arguments
///
/// * `input_bytes` — Raw input data for the WASM workload.
///   Empty slice is valid and produces `SHA3-256(prefix)`.
///
/// # Determinism
///
/// Pure function. Same `input_bytes` → same 32-byte hash, always.
#[must_use]
pub fn hash_input(input_bytes: &[u8]) -> [u8; 32] {
    domain_hash(INPUT_PREFIX, input_bytes)
}

/// Computes domain-separated SHA3-256 hash of workload output data.
///
/// ```text
/// hash = SHA3-256(b"DSDN:wasm_output:v1:" ‖ output_bytes)
/// ```
///
/// # Arguments
///
/// * `output_bytes` — Captured stdout from the WASM guest.
///   Empty slice is valid and produces `SHA3-256(prefix)`.
///
/// # Determinism
///
/// Pure function. Same `output_bytes` → same 32-byte hash, always.
#[must_use]
pub fn hash_output(output_bytes: &[u8]) -> [u8; 32] {
    domain_hash(OUTPUT_PREFIX, output_bytes)
}

/// Computes domain-separated SHA3-256 hash of WASM linear memory.
///
/// ```text
/// hash = SHA3-256(b"DSDN:wasm_memory:v1:" ‖ memory_bytes)
/// ```
///
/// # Arguments
///
/// * `memory_bytes` — Raw bytes of WASM linear memory snapshot.
///   Empty slice is valid and produces `SHA3-256(prefix)`.
///
/// # Determinism
///
/// Pure function. Same `memory_bytes` → same 32-byte hash, always.
#[must_use]
pub fn hash_memory_snapshot(memory_bytes: &[u8]) -> [u8; 32] {
    domain_hash(MEMORY_PREFIX, memory_bytes)
}

// ════════════════════════════════════════════════════════════════════════════════
// INTERNAL HELPER
// ════════════════════════════════════════════════════════════════════════════════

/// Domain-separated SHA3-256: `SHA3-256(prefix ‖ data)`.
///
/// Uses incremental hashing (update prefix, then data) to avoid
/// allocating a concatenated buffer.
#[inline]
fn domain_hash(prefix: &[u8], data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(prefix);
    hasher.update(data);
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

    // ── 1) Empty input produces SHA3-256(prefix), not zero hash ─────────

    #[test]
    fn hash_input_empty() {
        let hash = hash_input(&[]);
        // Must be SHA3-256(b"DSDN:wasm_input:v1:"), not [0u8; 32]
        assert_ne!(hash, [0u8; 32]);
        // Verify it equals manual computation
        let expected = domain_hash(b"DSDN:wasm_input:v1:", &[]);
        assert_eq!(hash, expected);
    }

    // ── 2) Empty output produces SHA3-256(prefix), not zero hash ────────

    #[test]
    fn hash_output_empty() {
        let hash = hash_output(&[]);
        assert_ne!(hash, [0u8; 32]);
        let expected = domain_hash(b"DSDN:wasm_output:v1:", &[]);
        assert_eq!(hash, expected);
    }

    // ── 3) Empty memory produces SHA3-256(prefix), not zero hash ────────

    #[test]
    fn hash_memory_empty() {
        let hash = hash_memory_snapshot(&[]);
        assert_ne!(hash, [0u8; 32]);
        let expected = domain_hash(b"DSDN:wasm_memory:v1:", &[]);
        assert_eq!(hash, expected);
    }

    // ── 4) Domain separation: same data → different hashes ──────────────

    #[test]
    fn domain_separation_distinct_outputs() {
        let data = b"identical data for all three functions";
        let h_input = hash_input(data);
        let h_output = hash_output(data);
        let h_memory = hash_memory_snapshot(data);

        // All three must be different due to different domain prefixes
        assert_ne!(h_input, h_output);
        assert_ne!(h_input, h_memory);
        assert_ne!(h_output, h_memory);
    }

    // ── 5) Determinism: 100 iterations produce identical hash ───────────

    #[test]
    fn determinism_repeat_100x() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let ref_input = hash_input(&data);
        let ref_output = hash_output(&data);
        let ref_memory = hash_memory_snapshot(&data);
        for _ in 0..100 {
            assert_eq!(hash_input(&data), ref_input);
            assert_eq!(hash_output(&data), ref_output);
            assert_eq!(hash_memory_snapshot(&data), ref_memory);
        }
    }

    // ── 6) No mutation of input ─────────────────────────────────────────

    #[test]
    fn no_input_mutation() {
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let data_before = data.clone();
        let _ = hash_input(&data);
        let _ = hash_output(&data);
        let _ = hash_memory_snapshot(&data);
        assert_eq!(data, data_before);
    }

    // ── 7) Large input consistency ──────────────────────────────────────

    #[test]
    fn large_input_consistency() {
        let data: Vec<u8> = (0u8..=255).cycle().take(1_000_000).collect();
        let h1 = hash_input(&data);
        let h2 = hash_input(&data);
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 32]);
    }

    // ── 8) Different data → different hash ──────────────────────────────

    #[test]
    fn different_data_different_hash() {
        let h1 = hash_input(&[0x01]);
        let h2 = hash_input(&[0x02]);
        assert_ne!(h1, h2);
    }

    // ── 9) Prefix byte correctness ─────────────────────────────────────

    #[test]
    fn prefix_byte_correctness() {
        // Verify exact prefix strings
        assert_eq!(INPUT_PREFIX, b"DSDN:wasm_input:v1:");
        assert_eq!(OUTPUT_PREFIX, b"DSDN:wasm_output:v1:");
        assert_eq!(MEMORY_PREFIX, b"DSDN:wasm_memory:v1:");

        // Verify lengths
        assert_eq!(INPUT_PREFIX.len(), 19);
        assert_eq!(OUTPUT_PREFIX.len(), 20);
        assert_eq!(MEMORY_PREFIX.len(), 20);
    }

    // ── 10) Empty vs non-empty produces different hash ──────────────────

    #[test]
    fn empty_vs_nonempty_different() {
        let h_empty = hash_input(&[]);
        let h_byte = hash_input(&[0x00]);
        assert_ne!(h_empty, h_byte);
    }
}