//! # Domain-Separated SHA3-256 Hashing (VM Runtime)
//!
//! Provides domain-separated hashing functions with prefixes **identical**
//! to `runtime_wasm::state_capture`. This ensures cross-runtime commitment
//! format compatibility: a VM execution and a WASM execution with the same
//! input/output produce the same `input_hash` and `output_hash`.
//!
//! ## Domain Prefixes (consensus-critical, immutable)
//!
//! | Function | Prefix | Length |
//! |----------|--------|--------|
//! | `hash_input` | `DSDN:wasm_input:v1:` | 19 bytes |
//! | `hash_output` | `DSDN:wasm_output:v1:` | 20 bytes |
//! | `hash_memory_snapshot` | `DSDN:wasm_memory:v1:` | 20 bytes |
//!
//! The `wasm_` prefix is retained for cross-runtime compatibility.
//! These are commitment format identifiers, not runtime-specific labels.

use sha3::{Digest, Sha3_256};

/// Domain prefix for input hashing. Consensus-critical — do not change.
const INPUT_PREFIX: &[u8] = b"DSDN:wasm_input:v1:";

/// Domain prefix for output hashing. Consensus-critical — do not change.
const OUTPUT_PREFIX: &[u8] = b"DSDN:wasm_output:v1:";

/// Domain prefix for memory snapshot hashing. Consensus-critical — do not change.
const MEMORY_PREFIX: &[u8] = b"DSDN:wasm_memory:v1:";

/// Internal helper: SHA3-256(prefix || data) with zero intermediate allocation.
fn domain_hash(prefix: &[u8], data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(prefix);
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Hashes workload input with domain separation.
///
/// Computes `SHA3-256(b"DSDN:wasm_input:v1:" || input_bytes)`.
///
/// Identical to `runtime_wasm::state_capture::hash_input` — same domain
/// prefix, same algorithm, same output for same input.
///
/// # Determinism
///
/// Pure function. Same input → same hash, always.
#[must_use]
pub fn hash_input(input_bytes: &[u8]) -> [u8; 32] {
    domain_hash(INPUT_PREFIX, input_bytes)
}

/// Hashes captured output with domain separation.
///
/// Computes `SHA3-256(b"DSDN:wasm_output:v1:" || output_bytes)`.
///
/// Identical to `runtime_wasm::state_capture::hash_output`.
///
/// # Determinism
///
/// Pure function. Same output → same hash, always.
#[must_use]
pub fn hash_output(output_bytes: &[u8]) -> [u8; 32] {
    domain_hash(OUTPUT_PREFIX, output_bytes)
}

/// Hashes a memory snapshot with domain separation.
///
/// Computes `SHA3-256(b"DSDN:wasm_memory:v1:" || snapshot_bytes)`.
///
/// Used for `state_root_before` and `state_root_after` fields.
/// Identical to `runtime_wasm::state_capture::hash_memory_snapshot`.
///
/// # Determinism
///
/// Pure function. Same snapshot → same hash, always.
#[must_use]
pub fn hash_memory_snapshot(snapshot_bytes: &[u8]) -> [u8; 32] {
    domain_hash(MEMORY_PREFIX, snapshot_bytes)
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn determinism_100x_all_functions() {
        let data = b"determinism-test-data-1234567890";

        let ref_input = hash_input(data);
        let ref_output = hash_output(data);
        let ref_memory = hash_memory_snapshot(data);

        for _ in 0..100 {
            assert_eq!(hash_input(data), ref_input);
            assert_eq!(hash_output(data), ref_output);
            assert_eq!(hash_memory_snapshot(data), ref_memory);
        }
    }

    #[test]
    fn different_input_different_hash() {
        let a = hash_input(b"alpha");
        let b = hash_input(b"beta");
        assert_ne!(a, b);
    }

    #[test]
    fn domain_separation_same_data_different_hashes() {
        let data = b"identical-data";
        let h_input = hash_input(data);
        let h_output = hash_output(data);
        let h_memory = hash_memory_snapshot(data);

        // All three must differ (different domain prefixes)
        assert_ne!(h_input, h_output);
        assert_ne!(h_input, h_memory);
        assert_ne!(h_output, h_memory);
    }

    #[test]
    fn empty_input_not_zero_hash() {
        // hash of empty with domain prefix != [0u8; 32]
        assert_ne!(hash_input(b""), [0u8; 32]);
        assert_ne!(hash_output(b""), [0u8; 32]);
        assert_ne!(hash_memory_snapshot(b""), [0u8; 32]);
    }

    #[test]
    fn cross_runtime_compatibility_prefix_bytes() {
        // Verify exact prefix content
        assert_eq!(INPUT_PREFIX, b"DSDN:wasm_input:v1:");
        assert_eq!(OUTPUT_PREFIX, b"DSDN:wasm_output:v1:");
        assert_eq!(MEMORY_PREFIX, b"DSDN:wasm_memory:v1:");

        assert_eq!(INPUT_PREFIX.len(), 19);
        assert_eq!(OUTPUT_PREFIX.len(), 20);
        assert_eq!(MEMORY_PREFIX.len(), 20);
    }

    #[test]
    fn no_input_mutation() {
        let data = b"immutable-data".to_vec();
        let original = data.clone();
        let _ = hash_input(&data);
        let _ = hash_output(&data);
        let _ = hash_memory_snapshot(&data);
        assert_eq!(data, original);
    }
}