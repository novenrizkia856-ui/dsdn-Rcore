//! # UsageProofBuilder — Self-Reported Resource Usage Proof Construction (14C.B.14)
//!
//! Builds a [`UsageProof`] struct with a valid Ed25519 signature that the
//! coordinator's `verify_usage_proof` (in `execution/usage_verifier.rs`)
//! will accept.
//!
//! ## Signing Message Layout (148 bytes total)
//!
//! ```text
//! ┌──────────┬────────┬──────────────────────────────────────┐
//! │ Offset   │ Length  │ Content                              │
//! ├──────────┼────────┼──────────────────────────────────────┤
//! │   0      │  20    │ Domain: b"DSDN:usage_proof:v1:"      │
//! │  20      │  32    │ workload_id                          │
//! │  52      │  32    │ node_id (Ed25519 public key)         │
//! │  84      │   8    │ cpu_cycles        (u64 LE)           │
//! │  92      │   8    │ ram_bytes          (u64 LE)           │
//! │ 100      │   8    │ chunk_count        (u64 LE)           │
//! │ 108      │   8    │ bandwidth_bytes    (u64 LE)           │
//! │ 116      │  32    │ SHA3-256(proof_data)                 │
//! └──────────┴────────┴──────────────────────────────────────┘
//! ```
//!
//! This layout is **byte-identical** to the coordinator's
//! `build_signing_message()` in `execution/usage_verifier.rs`.
//! Any divergence breaks signature verification and consensus.
//!
//! ## Field Mapping
//!
//! [`UnifiedResourceUsage`] fields map to [`UsageProof`] fields:
//!
//! | UnifiedResourceUsage    | UsageProof.field    |
//! |-------------------------|---------------------|
//! | `cpu_cycles_estimate`   | `cpu_cycles`        |
//! | `peak_memory_bytes`     | `ram_bytes`         |
//! | `chunk_count`           | `chunk_count`       |
//! | `bandwidth_bytes`       | `bandwidth_bytes`   |
//!
//! `execution_time_ms` is **not** included in the proof; it is
//! a wall-clock metric only relevant to the runtime layer.
//!
//! ## Determinism
//!
//! Same `(identity, workload_id, resource_usage, proof_data)` always
//! produces the same `UsageProof` with the same `node_signature`.
//! Ed25519 signing is deterministic per RFC 8032.
//!
//! ## Safety
//!
//! - No `panic!`, `unwrap()`, `expect()`.
//! - No silent error swallowing.
//! - All public items documented.

use std::fmt;
use std::sync::Arc;

use dsdn_common::coordinator::WorkloadId;
use sha3::{Digest, Sha3_256};

use crate::identity_manager::NodeIdentityManager;
use crate::workload_executor::UnifiedResourceUsage;

// ════════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════════

/// Domain separator for usage proof signatures.
///
/// Identical to `USAGE_PROOF_DOMAIN` in coordinator's `usage_verifier.rs`.
/// Prevents cross-protocol signature replay.
const USAGE_PROOF_DOMAIN: &[u8] = b"DSDN:usage_proof:v1:";

/// Total signing message length: 20 + 32 + 32 + 8 + 8 + 8 + 8 + 32 = 148.
const SIGNING_MESSAGE_LEN: usize = 148;

// ════════════════════════════════════════════════════════════════════════════════
// USAGE PROOF
// ════════════════════════════════════════════════════════════════════════════════

/// Self-reported resource usage proof from a node.
///
/// This struct is layout-compatible with the coordinator's `UsageProof`
/// in `execution/usage_verifier.rs`. The coordinator verifies the
/// `node_signature` against the deterministic signing message.
///
/// ## V1 Trust Model
///
/// The proof is self-reported. The signature proves the node produced it,
/// but does NOT prove the resources were actually consumed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageProof {
    /// Workload that was executed.
    pub workload_id: WorkloadId,
    /// Ed25519 public key of the node (32 bytes).
    pub node_id: [u8; 32],
    /// CPU cycles consumed (mapped from `cpu_cycles_estimate`).
    pub cpu_cycles: u64,
    /// RAM bytes used (mapped from `peak_memory_bytes`).
    pub ram_bytes: u64,
    /// Number of storage chunks accessed or stored.
    pub chunk_count: u64,
    /// Network bandwidth consumed in bytes.
    pub bandwidth_bytes: u64,
    /// Opaque proof data (hashed with SHA3-256 for signature).
    pub proof_data: Vec<u8>,
    /// Ed25519 signature over the deterministic usage proof message (64 bytes).
    pub node_signature: Vec<u8>,
}

// ════════════════════════════════════════════════════════════════════════════════
// ERROR
// ════════════════════════════════════════════════════════════════════════════════

/// Errors from usage proof construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsageProofError {
    /// Ed25519 signing failed.
    SigningFailed(String),
}

impl fmt::Display for UsageProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SigningFailed(msg) => write!(f, "usage proof signing failed: {}", msg),
        }
    }
}

impl std::error::Error for UsageProofError {}

// ════════════════════════════════════════════════════════════════════════════════
// BUILDER
// ════════════════════════════════════════════════════════════════════════════════

/// Stateful builder that constructs signed [`UsageProof`] instances.
///
/// Holds a reference to [`NodeIdentityManager`] for access to the node's
/// Ed25519 keypair. The builder itself is cheap to clone (only an `Arc`).
///
/// ## Usage
///
/// ```rust,ignore
/// let builder = UsageProofBuilder::new(Arc::clone(&identity));
/// let proof = builder.build_usage_proof(workload_id, &usage, &proof_data)?;
/// // proof.node_signature is now a valid Ed25519 signature
/// ```
pub struct UsageProofBuilder {
    /// Reference to the node's identity manager (Ed25519 keypair).
    identity: Arc<NodeIdentityManager>,
}

impl UsageProofBuilder {
    /// Creates a new builder bound to the given identity manager.
    ///
    /// The identity manager provides the Ed25519 keypair used to sign
    /// all usage proofs produced by this builder.
    #[must_use]
    pub fn new(identity: Arc<NodeIdentityManager>) -> Self {
        Self { identity }
    }

    /// Builds a signed [`UsageProof`] from resource usage data.
    ///
    /// ## Flow
    ///
    /// 1. Map [`UnifiedResourceUsage`] fields to proof fields.
    /// 2. Construct the unsigned proof.
    /// 3. Build the 148-byte signing message (byte-identical to coordinator).
    /// 4. Sign with Ed25519 via [`NodeIdentityManager::sign_message`].
    /// 5. Attach signature and return.
    ///
    /// ## Arguments
    ///
    /// - `workload_id`: The workload this proof covers.
    /// - `resource_usage`: Resource metrics from [`WorkloadExecutor`].
    /// - `proof_data`: Opaque data hashed into the signature (can be empty).
    ///
    /// ## Errors
    ///
    /// Returns [`UsageProofError::SigningFailed`] if Ed25519 signing fails
    /// (should not happen with a valid `NodeIdentityManager`).
    pub fn build_usage_proof(
        &self,
        workload_id: WorkloadId,
        resource_usage: &UnifiedResourceUsage,
        proof_data: &[u8],
    ) -> Result<UsageProof, UsageProofError> {
        // ── Step 1: Construct unsigned proof ────────────────────────────
        let node_id = *self.identity.node_id();

        let mut proof = UsageProof {
            workload_id,
            node_id,
            cpu_cycles: resource_usage.cpu_cycles_estimate,
            ram_bytes: resource_usage.peak_memory_bytes,
            chunk_count: resource_usage.chunk_count,
            bandwidth_bytes: resource_usage.bandwidth_bytes,
            proof_data: proof_data.to_vec(),
            node_signature: Vec::new(), // Placeholder — filled below.
        };

        // ── Step 2: Build deterministic signing message (148 bytes) ────
        let message = build_signing_message(&proof);
        debug_assert_eq!(message.len(), SIGNING_MESSAGE_LEN);

        // ── Step 3: Sign with Ed25519 ──────────────────────────────────
        let signature = self.identity.sign_message(&message);

        // ── Step 4: Attach signature ───────────────────────────────────
        proof.node_signature = signature.to_vec();

        Ok(proof)
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// SIGNING MESSAGE (private — identical to coordinator)
// ════════════════════════════════════════════════════════════════════════════════

/// Constructs the deterministic 148-byte message that is signed.
///
/// This function is **byte-identical** to the coordinator's
/// `build_signing_message()` in `execution/usage_verifier.rs`:
///
/// 1. Domain separator: `b"DSDN:usage_proof:v1:"` (20 bytes)
/// 2. `workload_id` (32 bytes)
/// 3. `node_id` (32 bytes)
/// 4. `cpu_cycles` (u64 little-endian, 8 bytes)
/// 5. `ram_bytes` (u64 little-endian, 8 bytes)
/// 6. `chunk_count` (u64 little-endian, 8 bytes)
/// 7. `bandwidth_bytes` (u64 little-endian, 8 bytes)
/// 8. `SHA3-256(proof_data)` (32 bytes)
fn build_signing_message(proof: &UsageProof) -> Vec<u8> {
    let mut message = Vec::with_capacity(SIGNING_MESSAGE_LEN);

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
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

    // ── Helpers ──────────────────────────────────────────────────────────

    /// Deterministic seed for test keypair.
    const TEST_SEED: [u8; 32] = [0xAA; 32];

    /// Creates a `NodeIdentityManager` from a deterministic seed.
    fn make_identity(seed: [u8; 32]) -> Arc<NodeIdentityManager> {
        let mgr = NodeIdentityManager::from_keypair(seed);
        // from_keypair with valid 32-byte seed never fails.
        Arc::new(mgr.unwrap_or_else(|_| {
            // This branch is unreachable for valid seeds, but we avoid
            // unwrap() per project rules. Tests that reach here will fail
            // assertions, making the issue visible.
            panic!("test setup: from_keypair failed with valid seed");
        }))
    }

    fn make_usage() -> UnifiedResourceUsage {
        UnifiedResourceUsage {
            cpu_cycles_estimate: 1_000_000,
            peak_memory_bytes: 65_536,
            execution_time_ms: 42,
            chunk_count: 3,
            bandwidth_bytes: 4096,
        }
    }

    fn test_wid() -> WorkloadId {
        WorkloadId::new([0x42; 32])
    }

    // ── Test 1: Build valid usage proof ─────────────────────────────────

    /// Verifies that `build_usage_proof` produces a structurally valid proof
    /// with correct field mapping from UnifiedResourceUsage.
    #[test]
    fn build_valid_usage_proof() {
        let identity = make_identity(TEST_SEED);
        let builder = UsageProofBuilder::new(identity.clone());
        let usage = make_usage();
        let proof_data = b"test-proof-data";

        let result = builder.build_usage_proof(test_wid(), &usage, proof_data);
        assert!(result.is_ok(), "build_usage_proof should succeed");

        let proof = result.unwrap_or_else(|e| panic!("unexpected error: {}", e));

        // Field mapping correctness.
        assert_eq!(proof.workload_id, test_wid());
        assert_eq!(proof.node_id, *identity.node_id());
        assert_eq!(proof.cpu_cycles, usage.cpu_cycles_estimate);
        assert_eq!(proof.ram_bytes, usage.peak_memory_bytes);
        assert_eq!(proof.chunk_count, usage.chunk_count);
        assert_eq!(proof.bandwidth_bytes, usage.bandwidth_bytes);
        assert_eq!(proof.proof_data, proof_data.as_slice());
        assert_eq!(proof.node_signature.len(), 64, "Ed25519 signature must be 64 bytes");
    }

    // ── Test 2: Signature verifiable by public key ──────────────────────

    /// Verifies the proof's Ed25519 signature using `verify_strict`,
    /// the same method the coordinator uses.
    #[test]
    fn signature_verifiable_by_public_key() {
        let identity = make_identity(TEST_SEED);
        let builder = UsageProofBuilder::new(identity.clone());
        let usage = make_usage();

        let proof = builder
            .build_usage_proof(test_wid(), &usage, b"payload")
            .unwrap_or_else(|e| panic!("unexpected error: {}", e));

        // Reconstruct signing message exactly as coordinator would.
        let message = build_signing_message(&proof);
        assert_eq!(message.len(), SIGNING_MESSAGE_LEN);

        // Parse public key from node_id.
        let vk = VerifyingKey::from_bytes(&proof.node_id)
            .unwrap_or_else(|e| panic!("invalid public key: {}", e));

        // Parse signature.
        let sig = ed25519_dalek::Signature::from_slice(&proof.node_signature)
            .unwrap_or_else(|e| panic!("invalid signature: {}", e));

        // verify_strict — same as coordinator's verify_usage_proof.
        let verify_result = vk.verify_strict(&message, &sig);
        assert!(verify_result.is_ok(), "signature verification must pass: {:?}", verify_result);
    }

    // ── Test 3: Deterministic — same input, same signature ──────────────

    /// Ed25519 is deterministic (RFC 8032). Same inputs must produce
    /// byte-identical signatures.
    #[test]
    fn deterministic_same_input_same_signature() {
        let identity = make_identity(TEST_SEED);
        let builder = UsageProofBuilder::new(identity);
        let usage = make_usage();
        let proof_data = b"deterministic-test";

        let proof1 = builder
            .build_usage_proof(test_wid(), &usage, proof_data)
            .unwrap_or_else(|e| panic!("unexpected error: {}", e));
        let proof2 = builder
            .build_usage_proof(test_wid(), &usage, proof_data)
            .unwrap_or_else(|e| panic!("unexpected error: {}", e));

        assert_eq!(proof1.node_signature, proof2.node_signature,
            "same inputs must produce identical signatures");
        assert_eq!(proof1, proof2, "entire proofs must be identical");
    }

    // ── Test 4: Different input → different signature ───────────────────

    /// Different workload_id must produce a different signing message
    /// and therefore a different signature.
    #[test]
    fn different_input_different_signature() {
        let identity = make_identity(TEST_SEED);
        let builder = UsageProofBuilder::new(identity);
        let usage = make_usage();

        let wid1 = WorkloadId::new([0x01; 32]);
        let wid2 = WorkloadId::new([0x02; 32]);

        let proof1 = builder
            .build_usage_proof(wid1, &usage, b"same-data")
            .unwrap_or_else(|e| panic!("unexpected error: {}", e));
        let proof2 = builder
            .build_usage_proof(wid2, &usage, b"same-data")
            .unwrap_or_else(|e| panic!("unexpected error: {}", e));

        assert_ne!(proof1.node_signature, proof2.node_signature,
            "different workload_id must produce different signatures");
    }

    // ── Test 5: proof_data hash changes signature ───────────────────────

    /// Different proof_data → different SHA3-256 hash → different message
    /// → different signature.
    #[test]
    fn proof_data_hash_changes_signature() {
        let identity = make_identity(TEST_SEED);
        let builder = UsageProofBuilder::new(identity);
        let usage = make_usage();

        let proof1 = builder
            .build_usage_proof(test_wid(), &usage, b"data-A")
            .unwrap_or_else(|e| panic!("unexpected error: {}", e));
        let proof2 = builder
            .build_usage_proof(test_wid(), &usage, b"data-B")
            .unwrap_or_else(|e| panic!("unexpected error: {}", e));

        assert_ne!(proof1.node_signature, proof2.node_signature,
            "different proof_data must produce different signatures");

        // Verify both signatures are independently valid.
        let vk = VerifyingKey::from_bytes(&proof1.node_id)
            .unwrap_or_else(|e| panic!("invalid public key: {}", e));

        let msg1 = build_signing_message(&proof1);
        let sig1 = ed25519_dalek::Signature::from_slice(&proof1.node_signature)
            .unwrap_or_else(|e| panic!("invalid signature: {}", e));
        assert!(vk.verify_strict(&msg1, &sig1).is_ok());

        let msg2 = build_signing_message(&proof2);
        let sig2 = ed25519_dalek::Signature::from_slice(&proof2.node_signature)
            .unwrap_or_else(|e| panic!("invalid signature: {}", e));
        assert!(vk.verify_strict(&msg2, &sig2).is_ok());
    }

    // ── Test 6: Signing message length ──────────────────────────────────

    /// The signing message must always be exactly 148 bytes.
    #[test]
    fn signing_message_length_is_148() {
        let proof = UsageProof {
            workload_id: test_wid(),
            node_id: [0xBB; 32],
            cpu_cycles: 100,
            ram_bytes: 200,
            chunk_count: 5,
            bandwidth_bytes: 300,
            proof_data: vec![1, 2, 3],
            node_signature: vec![],
        };

        let message = build_signing_message(&proof);
        assert_eq!(message.len(), SIGNING_MESSAGE_LEN,
            "signing message must be exactly 148 bytes");

        // Verify domain separator at offset 0.
        assert_eq!(&message[0..20], USAGE_PROOF_DOMAIN);

        // Verify workload_id at offset 20.
        assert_eq!(&message[20..52], proof.workload_id.as_bytes());

        // Verify node_id at offset 52.
        assert_eq!(&message[52..84], &proof.node_id);

        // Verify cpu_cycles at offset 84 (u64 LE).
        assert_eq!(&message[84..92], &100u64.to_le_bytes());

        // Verify ram_bytes at offset 92 (u64 LE).
        assert_eq!(&message[92..100], &200u64.to_le_bytes());

        // Verify chunk_count at offset 100 (u64 LE).
        assert_eq!(&message[100..108], &5u64.to_le_bytes());

        // Verify bandwidth_bytes at offset 108 (u64 LE).
        assert_eq!(&message[108..116], &300u64.to_le_bytes());

        // Verify SHA3-256(proof_data) at offset 116.
        let expected_hash = Sha3_256::digest(&[1u8, 2, 3]);
        assert_eq!(&message[116..148], expected_hash.as_slice());
    }

    // ── Test 7: Empty proof_data ────────────────────────────────────────

    /// Empty proof_data should produce a valid proof (SHA3-256 of empty input).
    #[test]
    fn empty_proof_data_produces_valid_proof() {
        let identity = make_identity(TEST_SEED);
        let builder = UsageProofBuilder::new(identity);
        let usage = make_usage();

        let result = builder.build_usage_proof(test_wid(), &usage, b"");
        assert!(result.is_ok());

        let proof = result.unwrap_or_else(|e| panic!("unexpected error: {}", e));
        assert!(proof.proof_data.is_empty());
        assert_eq!(proof.node_signature.len(), 64);

        // SHA3-256 of empty input is a well-known constant.
        let message = build_signing_message(&proof);
        let empty_hash = Sha3_256::digest(b"");
        assert_eq!(&message[116..148], empty_hash.as_slice());
    }

    // ── Test 8: Cross-verify with coordinator's message format ──────────

    /// Verifies that our build_signing_message produces the same bytes
    /// as the coordinator would for an identical UsageProof.
    #[test]
    fn signing_message_matches_coordinator_format() {
        let proof = UsageProof {
            workload_id: WorkloadId::new([0x01; 32]),
            node_id: [0x02; 32],
            cpu_cycles: 0x_DEAD_BEEF_CAFE_BABE,
            ram_bytes: 0x_0102_0304_0506_0708,
            chunk_count: 42,
            bandwidth_bytes: 1024,
            proof_data: vec![0xFF; 100],
            node_signature: vec![],
        };

        let message = build_signing_message(&proof);

        // Manually reconstruct expected bytes field-by-field.
        let mut expected = Vec::with_capacity(SIGNING_MESSAGE_LEN);
        expected.extend_from_slice(b"DSDN:usage_proof:v1:");
        expected.extend_from_slice(&[0x01; 32]); // workload_id
        expected.extend_from_slice(&[0x02; 32]); // node_id
        expected.extend_from_slice(&0x_DEAD_BEEF_CAFE_BABEu64.to_le_bytes());
        expected.extend_from_slice(&0x_0102_0304_0506_0708u64.to_le_bytes());
        expected.extend_from_slice(&42u64.to_le_bytes());
        expected.extend_from_slice(&1024u64.to_le_bytes());
        expected.extend_from_slice(&Sha3_256::digest(&vec![0xFF; 100]));

        assert_eq!(message, expected,
            "signing message must be byte-identical to coordinator format");
    }
}