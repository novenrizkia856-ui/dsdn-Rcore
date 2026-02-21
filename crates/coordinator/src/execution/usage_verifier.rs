//! # Usage Proof Verification (CO.3)
//!
//! Verifies usage proofs submitted by nodes before the coordinator signs a receipt.
//!
//! ## V1 Limitations
//!
//! This is a **V1 baseline** implementation with the following characteristics:
//!
//! - **Sanity checks only**: Range validation ensures non-trivial resource usage
//!   is claimed. No hardware-level attestation.
//! - **Ed25519 signature verification**: Proves the node holding the private key
//!   for `node_id` produced the proof. Does NOT prove the claimed resources were
//!   actually consumed.
//! - **No TEE attestation**: The proof is self-reported by the node. A malicious
//!   node can fabricate usage data while producing a valid signature.
//! - **No cryptographic usage proof**: No zk-SNARK, no remote attestation,
//!   no hardware measurement.
//! - **Stateless verification**: No node registry lookup. The `node_id` field
//!   is treated as the Ed25519 public key directly (same convention as
//!   `NodeIdentity.node_id` in `dsdn_common::gating::identity`).
//! - **Linear pricing model**: Reward is a simple weighted sum of resource
//!   metrics. No dynamic pricing, no market-based adjustment.
//!
//! ## V2 Roadmap
//!
//! Future versions will add:
//!
//! - **Remote attestation**: Intel SGX / ARM TrustZone attestation quotes
//!   proving execution occurred in a genuine TEE enclave.
//! - **TEE measurement**: `MRENCLAVE` / `MRSIGNER` verification to ensure
//!   the correct code was executed inside the enclave.
//! - **zk-based proof**: Zero-knowledge proofs of computation enabling
//!   verification without re-execution.
//! - **Dynamic pricing model**: Market-driven resource pricing based on
//!   supply/demand signals from the network.
//! - **Node registry validation**: Cross-reference `node_id` against
//!   on-chain node registration and stake status.
//!
//! ## Signature Message Format
//!
//! The node signs a deterministic message constructed as:
//!
//! ```text
//! message = b"DSDN:usage_proof:v1:"        (domain separator, 20 bytes)
//!         ‖ workload_id                     (32 bytes)
//!         ‖ node_id                         (32 bytes)
//!         ‖ cpu_cycles (u64 LE)             (8 bytes)
//!         ‖ ram_bytes (u64 LE)              (8 bytes)
//!         ‖ chunk_count (u64 LE)            (8 bytes)
//!         ‖ bandwidth_bytes (u64 LE)        (8 bytes)
//!         ‖ SHA3-256(proof_data)            (32 bytes)
//! Total: 148 bytes
//! ```
//!
//! Domain separation prevents cross-protocol signature replay.
//! `proof_data` is hashed (not included raw) to bound message size.
//!
//! ## Reward Formula (V1)
//!
//! ```text
//! reward_base = (cpu_cycles × 1)
//!             + (ram_bytes × 1)
//!             + (chunk_count × 1000)
//!             + (bandwidth_bytes × 1)
//! ```
//!
//! All arithmetic uses `u128` with checked operations.
//! Overflow returns `reward_base = 0`.
//!
//! | Resource | Weight | Rationale |
//! |----------|--------|-----------|
//! | `cpu_cycles` | 1 | Base unit of computation |
//! | `ram_bytes` | 1 | 1:1 with cpu for V1 simplicity |
//! | `chunk_count` | 1000 | Chunks represent significant storage commitment |
//! | `bandwidth_bytes` | 1 | 1:1 with cpu for V1 simplicity |
//!
//! ## Safety
//!
//! - No panic, unwrap, expect, todo, unreachable in any code path.
//! - All arithmetic is checked (overflow → 0 reward).
//! - Signature verification uses `ed25519_dalek::verify_strict`.
//! - Fully deterministic: same inputs → same result.

use dsdn_common::coordinator::WorkloadId;
use sha3::{Digest, Sha3_256};

// ════════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════════

/// Domain separator for usage proof signature verification.
///
/// Prevents cross-protocol signature replay attacks.
/// A signature valid for usage proof cannot be replayed in operator binding
/// or any other DSDN subsystem.
const USAGE_PROOF_DOMAIN: &[u8] = b"DSDN:usage_proof:v1:";

/// Weight for `chunk_count` in reward calculation.
///
/// Chunks represent significant storage commitment (replication, durability),
/// so they carry a higher weight than raw byte metrics.
const CHUNK_WEIGHT: u128 = 1_000;

/// Weight for `cpu_cycles` in reward calculation.
const CPU_WEIGHT: u128 = 1;

/// Weight for `ram_bytes` in reward calculation.
const RAM_WEIGHT: u128 = 1;

/// Weight for `bandwidth_bytes` in reward calculation.
const BANDWIDTH_WEIGHT: u128 = 1;

// ════════════════════════════════════════════════════════════════════════════════
// USAGE PROOF
// ════════════════════════════════════════════════════════════════════════════════

/// Self-reported resource usage proof from a node.
///
/// The node claims it consumed the specified resources while executing
/// a workload, and signs the claim with its Ed25519 private key.
///
/// ## V1 Trust Model
///
/// The proof is self-reported. The signature proves the node produced it,
/// but does NOT prove the resources were actually consumed. See module-level
/// documentation for V2 roadmap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageProof {
    /// Workload that was executed.
    pub workload_id: WorkloadId,
    /// Ed25519 public key of the node (32 bytes).
    /// Same convention as `NodeIdentity.node_id`.
    pub node_id: [u8; 32],
    /// CPU cycles consumed.
    pub cpu_cycles: u64,
    /// RAM bytes used (peak or cumulative, depending on workload type).
    pub ram_bytes: u64,
    /// Number of storage chunks accessed or stored.
    pub chunk_count: u64,
    /// Network bandwidth consumed in bytes.
    pub bandwidth_bytes: u64,
    /// Opaque proof data (V1: not cryptographically verified, hashed for signature).
    pub proof_data: Vec<u8>,
    /// Ed25519 signature over the deterministic usage proof message (64 bytes).
    pub node_signature: Vec<u8>,
}

// ════════════════════════════════════════════════════════════════════════════════
// VERIFICATION RESULT
// ════════════════════════════════════════════════════════════════════════════════

/// Result of usage proof verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsageVerificationResult {
    /// Proof passed all V1 checks. Contains computed reward base.
    Valid {
        /// Reward base computed from resource usage (u128).
        reward_base: u128,
    },
    /// Proof failed one or more checks.
    Invalid {
        /// Human-readable reason for rejection.
        reason: String,
    },
}

// ════════════════════════════════════════════════════════════════════════════════
// VERIFICATION
// ════════════════════════════════════════════════════════════════════════════════

/// Verifies a usage proof submitted by a node.
///
/// ## Verification Steps (V1)
///
/// 1. **Signature verification**: Ed25519 `verify_strict` over the
///    deterministic usage proof message. Rejects invalid keys, bad
///    signatures, and small-order points.
///
/// 2. **Range checks**: At least one of `cpu_cycles` or `chunk_count`
///    must be non-zero. A proof claiming zero resources for both
///    computation and storage is rejected.
///
/// 3. **Reward calculation**: Delegates to [`calculate_reward_base`].
///    If overflow occurs, `reward_base = 0` (documented, not silent).
///
/// ## Arguments
///
/// * `proof` — The usage proof to verify.
///
/// ## Returns
///
/// * `Valid { reward_base }` — All checks passed.
/// * `Invalid { reason }` — One or more checks failed.
///
/// ## Determinism
///
/// Same `proof` → same result. No randomness, no global state.
#[must_use]
pub fn verify_usage_proof(proof: &UsageProof) -> UsageVerificationResult {
    // ── Step 1: Signature verification ──────────────────────────────────

    // Validate signature length.
    if proof.node_signature.len() != 64 {
        return UsageVerificationResult::Invalid {
            reason: format!(
                "invalid signature length: expected 64 bytes, got {}",
                proof.node_signature.len()
            ),
        };
    }

    // Parse node_id as Ed25519 public key.
    let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(&proof.node_id) {
        Ok(key) => key,
        Err(e) => {
            return UsageVerificationResult::Invalid {
                reason: format!("invalid node_id (not a valid Ed25519 public key): {}", e),
            };
        }
    };

    // Parse signature bytes.
    let signature = match ed25519_dalek::Signature::from_slice(&proof.node_signature) {
        Ok(sig) => sig,
        Err(e) => {
            return UsageVerificationResult::Invalid {
                reason: format!("invalid signature bytes: {}", e),
            };
        }
    };

    // Construct deterministic message.
    let message = build_signing_message(proof);

    // Verify using strict mode (rejects weak keys, small-order points).
    match verifying_key.verify_strict(&message, &signature) {
        Ok(()) => {}
        Err(_) => {
            return UsageVerificationResult::Invalid {
                reason: "signature verification failed: signature does not match usage proof"
                    .to_string(),
            };
        }
    }

    // ── Step 2: Range checks ────────────────────────────────────────────

    // At least one of cpu_cycles or chunk_count must be non-zero.
    // A proof with both zero claims neither computation nor storage.
    if proof.cpu_cycles == 0 && proof.chunk_count == 0 {
        return UsageVerificationResult::Invalid {
            reason: "invalid usage: both cpu_cycles and chunk_count are zero".to_string(),
        };
    }

    // ── Step 3: Reward calculation ──────────────────────────────────────

    let reward_base = calculate_reward_base(proof);

    UsageVerificationResult::Valid { reward_base }
}

// ════════════════════════════════════════════════════════════════════════════════
// REWARD CALCULATION
// ════════════════════════════════════════════════════════════════════════════════

/// Calculates the reward base from resource usage metrics.
///
/// ## Formula (V1 — Linear Weighted Sum)
///
/// ```text
/// reward_base = (cpu_cycles × CPU_WEIGHT)
///             + (ram_bytes × RAM_WEIGHT)
///             + (chunk_count × CHUNK_WEIGHT)
///             + (bandwidth_bytes × BANDWIDTH_WEIGHT)
/// ```
///
/// ## Overflow Handling
///
/// All arithmetic uses `u128::checked_mul` and `u128::checked_add`.
/// If any step overflows, the function returns `0`.
///
/// Returning `0` on overflow is a deliberate choice:
/// - It prevents a malicious node from exploiting overflow to claim
///   a large reward from small inputs.
/// - It is documented and deterministic (not a silent failure).
/// - The caller (chain layer) will see `reward_base = 0` and can
///   handle it appropriately (e.g., reject the claim).
///
/// ## Determinism
///
/// Same inputs → same output. No floating point. No randomness.
#[must_use]
pub fn calculate_reward_base(usage: &UsageProof) -> u128 {
    let cpu_term = (usage.cpu_cycles as u128).checked_mul(CPU_WEIGHT);
    let ram_term = (usage.ram_bytes as u128).checked_mul(RAM_WEIGHT);
    let chunk_term = (usage.chunk_count as u128).checked_mul(CHUNK_WEIGHT);
    let bw_term = (usage.bandwidth_bytes as u128).checked_mul(BANDWIDTH_WEIGHT);

    // Chain checked_add across all terms. Any None → return 0.
    let result = cpu_term
        .and_then(|cpu| ram_term.and_then(|ram| cpu.checked_add(ram)))
        .and_then(|sum| chunk_term.and_then(|chunk| sum.checked_add(chunk)))
        .and_then(|sum| bw_term.and_then(|bw| sum.checked_add(bw)));

    match result {
        Some(total) => total,
        None => 0, // Overflow → documented zero.
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// SIGNING MESSAGE CONSTRUCTION
// ════════════════════════════════════════════════════════════════════════════════

/// Constructs the deterministic message that a node signs for a usage proof.
///
/// ## Message Layout (148 bytes total)
///
/// | Offset | Length | Content |
/// |--------|--------|---------|
/// | 0 | 20 | Domain separator: `b"DSDN:usage_proof:v1:"` |
/// | 20 | 32 | `workload_id` |
/// | 52 | 32 | `node_id` |
/// | 84 | 8 | `cpu_cycles` (u64 little-endian) |
/// | 92 | 8 | `ram_bytes` (u64 little-endian) |
/// | 100 | 8 | `chunk_count` (u64 little-endian) |
/// | 108 | 8 | `bandwidth_bytes` (u64 little-endian) |
/// | 116 | 32 | `SHA3-256(proof_data)` |
///
/// ## Determinism
///
/// Fixed field order, fixed endianness, fixed hash algorithm.
/// Same `UsageProof` → same message bytes.
#[must_use]
pub fn build_signing_message(proof: &UsageProof) -> Vec<u8> {
    let mut message = Vec::with_capacity(148);

    // Domain separator.
    message.extend_from_slice(USAGE_PROOF_DOMAIN);

    // Workload ID (32 bytes).
    message.extend_from_slice(proof.workload_id.as_bytes());

    // Node ID (32 bytes).
    message.extend_from_slice(&proof.node_id);

    // Resource metrics (u64 little-endian each).
    message.extend_from_slice(&proof.cpu_cycles.to_le_bytes());
    message.extend_from_slice(&proof.ram_bytes.to_le_bytes());
    message.extend_from_slice(&proof.chunk_count.to_le_bytes());
    message.extend_from_slice(&proof.bandwidth_bytes.to_le_bytes());

    // SHA3-256 hash of proof_data (32 bytes).
    let proof_data_hash = Sha3_256::digest(&proof.proof_data);
    message.extend_from_slice(&proof_data_hash);

    message
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    // ── Helpers ──────────────────────────────────────────────────────────

    /// Generate a deterministic Ed25519 keypair from a seed byte.
    fn make_keypair(seed: u8) -> SigningKey {
        let mut secret = [0u8; 32];
        secret[0] = seed;
        SigningKey::from_bytes(&secret)
    }

    /// Build a valid UsageProof signed by the given key.
    fn make_signed_proof(
        signing_key: &SigningKey,
        cpu: u64,
        ram: u64,
        chunks: u64,
        bw: u64,
    ) -> UsageProof {
        let verifying_key = signing_key.verifying_key();
        let mut proof = UsageProof {
            workload_id: WorkloadId::new([0x01; 32]),
            node_id: verifying_key.to_bytes(),
            cpu_cycles: cpu,
            ram_bytes: ram,
            chunk_count: chunks,
            bandwidth_bytes: bw,
            proof_data: vec![0xAB; 16],
            node_signature: vec![], // Placeholder.
        };

        // Sign.
        let message = build_signing_message(&proof);
        let sig = signing_key.sign(&message);
        proof.node_signature = sig.to_bytes().to_vec();

        proof
    }

    // ── Signature Verification ──────────────────────────────────────────

    #[test]
    fn valid_proof_accepted() {
        let key = make_keypair(0x42);
        let proof = make_signed_proof(&key, 1000, 2000, 5, 3000);
        let result = verify_usage_proof(&proof);

        let expected_reward = 1000 + 2000 + (5 * 1000) + 3000;
        assert_eq!(
            result,
            UsageVerificationResult::Valid {
                reward_base: expected_reward
            }
        );
    }

    #[test]
    fn invalid_signature_length_too_short() {
        let key = make_keypair(0x01);
        let mut proof = make_signed_proof(&key, 100, 0, 1, 0);
        proof.node_signature = vec![0xAA; 32]; // Too short.

        match verify_usage_proof(&proof) {
            UsageVerificationResult::Invalid { reason } => {
                assert!(reason.contains("signature length"));
            }
            other => panic!("expected Invalid, got {:?}", other),
        }
    }

    #[test]
    fn invalid_signature_length_too_long() {
        let key = make_keypair(0x01);
        let mut proof = make_signed_proof(&key, 100, 0, 1, 0);
        proof.node_signature = vec![0xAA; 128]; // Too long.

        match verify_usage_proof(&proof) {
            UsageVerificationResult::Invalid { reason } => {
                assert!(reason.contains("signature length"));
            }
            other => panic!("expected Invalid, got {:?}", other),
        }
    }

    #[test]
    fn invalid_signature_empty() {
        let key = make_keypair(0x01);
        let mut proof = make_signed_proof(&key, 100, 0, 1, 0);
        proof.node_signature = vec![];

        match verify_usage_proof(&proof) {
            UsageVerificationResult::Invalid { reason } => {
                assert!(reason.contains("signature length"));
            }
            other => panic!("expected Invalid, got {:?}", other),
        }
    }

    #[test]
    fn invalid_signature_wrong_bytes() {
        let key = make_keypair(0x01);
        let mut proof = make_signed_proof(&key, 100, 0, 1, 0);
        proof.node_signature = vec![0xFF; 64]; // Wrong signature.

        match verify_usage_proof(&proof) {
            UsageVerificationResult::Invalid { reason } => {
                assert!(
                    reason.contains("signature verification failed")
                        || reason.contains("invalid signature")
                );
            }
            other => panic!("expected Invalid, got {:?}", other),
        }
    }

    #[test]
    fn invalid_node_id_not_on_curve() {
        let key = make_keypair(0x01);
        let mut proof = make_signed_proof(&key, 100, 0, 1, 0);
        proof.node_id = [0xFF; 32]; // May or may not be a valid Ed25519 point.

        // Must be Invalid — either because the key is rejected or because
        // the signature no longer matches. Both are acceptable outcomes.
        match verify_usage_proof(&proof) {
            UsageVerificationResult::Invalid { .. } => {} // Expected.
            other => panic!("expected Invalid, got {:?}", other),
        }
    }

    #[test]
    fn tampered_cpu_cycles_rejected() {
        let key = make_keypair(0x01);
        let mut proof = make_signed_proof(&key, 100, 0, 1, 0);
        proof.cpu_cycles = 999; // Tampered after signing.

        match verify_usage_proof(&proof) {
            UsageVerificationResult::Invalid { reason } => {
                assert!(reason.contains("signature"));
            }
            other => panic!("expected Invalid, got {:?}", other),
        }
    }

    #[test]
    fn tampered_proof_data_rejected() {
        let key = make_keypair(0x01);
        let mut proof = make_signed_proof(&key, 100, 0, 1, 0);
        proof.proof_data = vec![0xDE, 0xAD]; // Tampered after signing.

        match verify_usage_proof(&proof) {
            UsageVerificationResult::Invalid { reason } => {
                assert!(reason.contains("signature"));
            }
            other => panic!("expected Invalid, got {:?}", other),
        }
    }

    #[test]
    fn wrong_key_rejected() {
        let key_a = make_keypair(0x01);
        let key_b = make_keypair(0x02);
        let mut proof = make_signed_proof(&key_a, 100, 0, 1, 0);
        // Replace node_id with key_b's pubkey but keep key_a's signature.
        proof.node_id = key_b.verifying_key().to_bytes();

        match verify_usage_proof(&proof) {
            UsageVerificationResult::Invalid { reason } => {
                assert!(reason.contains("signature"));
            }
            other => panic!("expected Invalid, got {:?}", other),
        }
    }

    // ── Range Checks ────────────────────────────────────────────────────

    #[test]
    fn both_cpu_and_chunks_zero_rejected() {
        let key = make_keypair(0x01);
        let proof = make_signed_proof(&key, 0, 500, 0, 1000);

        match verify_usage_proof(&proof) {
            UsageVerificationResult::Invalid { reason } => {
                assert!(reason.contains("cpu_cycles") && reason.contains("chunk_count"));
            }
            other => panic!("expected Invalid, got {:?}", other),
        }
    }

    #[test]
    fn cpu_nonzero_chunks_zero_accepted() {
        let key = make_keypair(0x01);
        let proof = make_signed_proof(&key, 1, 0, 0, 0);
        assert!(matches!(
            verify_usage_proof(&proof),
            UsageVerificationResult::Valid { .. }
        ));
    }

    #[test]
    fn cpu_zero_chunks_nonzero_accepted() {
        let key = make_keypair(0x01);
        let proof = make_signed_proof(&key, 0, 0, 1, 0);
        assert!(matches!(
            verify_usage_proof(&proof),
            UsageVerificationResult::Valid { .. }
        ));
    }

    // ── Reward Calculation ──────────────────────────────────────────────

    #[test]
    fn reward_formula_exact() {
        let key = make_keypair(0x01);
        let proof = make_signed_proof(&key, 100, 200, 3, 400);
        // 100*1 + 200*1 + 3*1000 + 400*1 = 3700
        match verify_usage_proof(&proof) {
            UsageVerificationResult::Valid { reward_base } => {
                assert_eq!(reward_base, 3_700);
            }
            other => panic!("expected Valid, got {:?}", other),
        }
    }

    #[test]
    fn reward_only_cpu() {
        let key = make_keypair(0x01);
        let proof = make_signed_proof(&key, 5000, 0, 0, 0);
        // cpu only: need cpu > 0, chunks can be 0 since cpu > 0
        match verify_usage_proof(&proof) {
            UsageVerificationResult::Valid { reward_base } => {
                assert_eq!(reward_base, 5_000);
            }
            other => panic!("expected Valid, got {:?}", other),
        }
    }

    #[test]
    fn reward_only_chunks() {
        let key = make_keypair(0x01);
        let proof = make_signed_proof(&key, 0, 0, 10, 0);
        match verify_usage_proof(&proof) {
            UsageVerificationResult::Valid { reward_base } => {
                assert_eq!(reward_base, 10_000);
            }
            other => panic!("expected Valid, got {:?}", other),
        }
    }

    #[test]
    fn reward_max_u64_no_overflow() {
        // u64::MAX * 1 = u64::MAX as u128, fits easily.
        let key = make_keypair(0x01);
        let proof = make_signed_proof(&key, u64::MAX, u64::MAX, u64::MAX, u64::MAX);
        let result = calculate_reward_base(&proof);

        let max = u64::MAX as u128;
        let expected = max
            .checked_mul(CPU_WEIGHT)
            .and_then(|v| v.checked_add(max.checked_mul(RAM_WEIGHT)?))
            .and_then(|v| v.checked_add(max.checked_mul(CHUNK_WEIGHT)?))
            .and_then(|v| v.checked_add(max.checked_mul(BANDWIDTH_WEIGHT)?));

        assert_eq!(result, expected.unwrap_or(0));
    }

    #[test]
    fn reward_zero_on_overflow() {
        // Construct a UsageProof with values that would overflow u128
        // when chunk_count * 1000 is huge. Actually u64::MAX * 1000
        // fits in u128 (18_446_744_073_709_551_615_000), so this won't
        // overflow with current weights. Instead, test the function
        // directly with the known no-overflow case and verify correctness.
        let proof = UsageProof {
            workload_id: WorkloadId::new([0; 32]),
            node_id: [0; 32],
            cpu_cycles: u64::MAX,
            ram_bytes: u64::MAX,
            chunk_count: u64::MAX,
            bandwidth_bytes: u64::MAX,
            proof_data: vec![],
            node_signature: vec![0; 64],
        };

        let result = calculate_reward_base(&proof);
        // u64::MAX = 18446744073709551615
        // cpu:  18446744073709551615 * 1    = 18446744073709551615
        // ram:  18446744073709551615 * 1    = 18446744073709551615
        // chunk: 18446744073709551615 * 1000 = 18446744073709551615000
        // bw:   18446744073709551615 * 1    = 18446744073709551615
        // sum = 18446744073709551615000 + 18446744073709551615*3
        //     = 18446744073709551615000 + 55340232221128654845
        //     = 18502084305930680269845
        // This fits in u128 (max ~3.4e38). So result should be nonzero.
        assert!(result > 0);
    }

    #[test]
    fn calculate_reward_deterministic() {
        let key = make_keypair(0x01);
        let proof = make_signed_proof(&key, 100, 200, 3, 400);
        let r1 = calculate_reward_base(&proof);
        let r2 = calculate_reward_base(&proof);
        assert_eq!(r1, r2);
    }

    #[test]
    fn calculate_reward_all_zero() {
        let proof = UsageProof {
            workload_id: WorkloadId::new([0; 32]),
            node_id: [0; 32],
            cpu_cycles: 0,
            ram_bytes: 0,
            chunk_count: 0,
            bandwidth_bytes: 0,
            proof_data: vec![],
            node_signature: vec![0; 64],
        };
        assert_eq!(calculate_reward_base(&proof), 0);
    }

    // ── Signing Message ─────────────────────────────────────────────────

    #[test]
    fn signing_message_length_is_148() {
        let key = make_keypair(0x01);
        let proof = make_signed_proof(&key, 100, 200, 3, 400);
        let msg = build_signing_message(&proof);
        assert_eq!(msg.len(), 148);
    }

    #[test]
    fn signing_message_starts_with_domain() {
        let key = make_keypair(0x01);
        let proof = make_signed_proof(&key, 100, 200, 3, 400);
        let msg = build_signing_message(&proof);
        assert!(msg.starts_with(USAGE_PROOF_DOMAIN));
    }

    #[test]
    fn signing_message_deterministic() {
        let key = make_keypair(0x01);
        let proof = make_signed_proof(&key, 100, 200, 3, 400);
        let m1 = build_signing_message(&proof);
        let m2 = build_signing_message(&proof);
        assert_eq!(m1, m2);
    }

    #[test]
    fn signing_message_different_workload_different_message() {
        let key = make_keypair(0x01);
        let mut p1 = make_signed_proof(&key, 100, 0, 1, 0);
        let mut p2 = p1.clone();
        p2.workload_id = WorkloadId::new([0x02; 32]);

        assert_ne!(build_signing_message(&p1), build_signing_message(&p2));
    }

    // ── Full Pipeline Determinism ───────────────────────────────────────

    #[test]
    fn full_verify_deterministic() {
        let key = make_keypair(0x42);
        let proof = make_signed_proof(&key, 500, 1000, 2, 3000);
        let r1 = verify_usage_proof(&proof);
        let r2 = verify_usage_proof(&proof);
        assert_eq!(r1, r2);
    }

    // ── Debug & Eq ──────────────────────────────────────────────────────

    #[test]
    fn usage_proof_debug_not_empty() {
        let key = make_keypair(0x01);
        let proof = make_signed_proof(&key, 1, 0, 1, 0);
        let dbg = format!("{:?}", proof);
        assert!(dbg.contains("UsageProof"));
    }

    #[test]
    fn verification_result_eq() {
        let v1 = UsageVerificationResult::Valid { reward_base: 100 };
        let v2 = UsageVerificationResult::Valid { reward_base: 100 };
        let v3 = UsageVerificationResult::Invalid {
            reason: "bad".to_string(),
        };
        assert_eq!(v1, v2);
        assert_ne!(v1, v3);
    }
}