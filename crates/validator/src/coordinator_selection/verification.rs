//! Epoch Seed Verification (14A.2B.2.6)
//!
//! Module ini menyediakan verifikasi bahwa epoch seed yang diklaim:
//! 1. Benar-benar berasal dari DA blob yang valid
//! 2. Sesuai dengan epoch yang diklaim
//! 3. Diverifikasi menggunakan Merkle proof secara deterministik
//!
//! # Merkle Specification
//!
//! - Hash function: SHA3-512 (truncated to 32 bytes)
//! - Leaf format: `SHA3-512(seed || epoch_be_8)[0..32]`
//! - Sibling order: index bit=0 (left) → `hash(current || sibling)`
//!
//! # Determinism
//!
//! Semua operasi dalam module ini DIJAMIN deterministik.
//! Same input = same output di semua nodes dan arsitektur.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_512};

// ════════════════════════════════════════════════════════════════════════════════
// DAMerkleProof
// ════════════════════════════════════════════════════════════════════════════════

/// Merkle proof untuk Data Availability verification.
///
/// # Fields
///
/// - `root`: Merkle root hash (32 bytes)
/// - `path`: Sibling hashes dari leaf ke root
/// - `index`: Posisi leaf dalam tree (menentukan left/right)
///
/// # Index Interpretation
///
/// Index digunakan untuk menentukan concatenation order:
/// - Bit 0 dari index menentukan posisi di level 0
/// - Bit 1 dari index menentukan posisi di level 1
/// - dst.
///
/// Jika bit = 0: node adalah LEFT child → hash(current || sibling)
/// Jika bit = 1: node adalah RIGHT child → hash(sibling || current)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DAMerkleProof {
    /// Merkle root hash (32 bytes)
    pub root: [u8; 32],

    /// Sibling hashes dari leaf ke root
    pub path: Vec<[u8; 32]>,

    /// Leaf index dalam tree
    pub index: u64,
}

// ════════════════════════════════════════════════════════════════════════════════
// SeedVerificationResult
// ════════════════════════════════════════════════════════════════════════════════

/// Result dari epoch seed verification.
///
/// # Invariants
///
/// - `valid == true` → `error` HARUS `None`
/// - `valid == false` → `error` HARUS `Some(..)`
///
/// Invariant ini dijaga oleh constructor methods.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeedVerificationResult {
    /// Apakah verifikasi berhasil
    pub valid: bool,

    /// Error message jika verification gagal
    pub error: Option<String>,
}

impl SeedVerificationResult {
    /// Create successful verification result.
    ///
    /// Invariant: valid=true, error=None
    #[inline]
    pub fn success() -> Self {
        Self {
            valid: true,
            error: None,
        }
    }

    /// Create failed verification result dengan error message.
    ///
    /// Invariant: valid=false, error=Some(..)
    #[inline]
    pub fn failure(error: String) -> Self {
        Self {
            valid: false,
            error: Some(error),
        }
    }

    /// Check apakah result adalah success.
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.valid
    }

    /// Get error message jika ada.
    #[inline]
    pub fn error_message(&self) -> Option<&str> {
        self.error.as_deref()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// Internal Helper Functions
// ════════════════════════════════════════════════════════════════════════════════

/// Compute SHA3-512 hash dan truncate ke 32 bytes.
///
/// # Determinism
///
/// - Same input = same output
/// - Cross-platform deterministic
///
/// # Arguments
///
/// * `data` - Data to hash
///
/// # Returns
///
/// First 32 bytes of SHA3-512 hash.
fn sha3_512_truncated(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_512::new();
    hasher.update(data);
    let full_hash = hasher.finalize();

    // Truncate ke 32 bytes pertama
    let mut result = [0u8; 32];
    result.copy_from_slice(&full_hash[0..32]);
    result
}

/// Compute Merkle leaf hash dari seed dan epoch.
///
/// # Algorithm
///
/// ```text
/// leaf = SHA3-512(seed || epoch_be_8)[0..32]
/// ```
///
/// # Arguments
///
/// * `seed` - Epoch seed (32 bytes)
/// * `epoch` - Epoch number
///
/// # Returns
///
/// Leaf hash (32 bytes).
fn compute_leaf_hash(seed: &[u8; 32], epoch: u64) -> [u8; 32] {
    // Concatenate: seed (32 bytes) || epoch (8 bytes big-endian)
    let mut preimage = [0u8; 40];
    preimage[0..32].copy_from_slice(seed);
    preimage[32..40].copy_from_slice(&epoch.to_be_bytes());

    sha3_512_truncated(&preimage)
}

/// Compute parent hash dari dua child nodes.
///
/// # Algorithm
///
/// ```text
/// parent = SHA3-512(left || right)[0..32]
/// ```
///
/// # Arguments
///
/// * `left` - Left child hash (32 bytes)
/// * `right` - Right child hash (32 bytes)
///
/// # Returns
///
/// Parent hash (32 bytes).
fn compute_parent_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    // Concatenate: left (32 bytes) || right (32 bytes)
    let mut preimage = [0u8; 64];
    preimage[0..32].copy_from_slice(left);
    preimage[32..64].copy_from_slice(right);

    sha3_512_truncated(&preimage)
}

// ════════════════════════════════════════════════════════════════════════════════
// Public Verification Functions
// ════════════════════════════════════════════════════════════════════════════════

/// Verify Merkle proof untuk sebuah leaf.
///
/// # Algorithm
///
/// 1. Start dengan leaf hash
/// 2. Untuk setiap sibling dalam path:
///    - Jika index bit = 0 (left): `hash(current || sibling)`
///    - Jika index bit = 1 (right): `hash(sibling || current)`
///    - Shift index right by 1
/// 3. Compare computed root dengan expected root
///
/// # Determinism
///
/// - Same inputs = same output
/// - Tidak ada randomness
/// - Cross-platform deterministic
///
/// # Arguments
///
/// * `leaf` - Leaf hash to verify (32 bytes)
/// * `proof` - Merkle proof containing root, path, and index
///
/// # Returns
///
/// `true` jika proof valid, `false` jika tidak.
pub fn verify_merkle_proof(leaf: &[u8; 32], proof: &DAMerkleProof) -> bool {
    // Edge case: empty path means leaf should equal root
    if proof.path.is_empty() {
        return *leaf == proof.root;
    }

    let mut current = *leaf;
    let mut index = proof.index;

    // Traverse dari leaf ke root
    for sibling in &proof.path {
        // Determine position berdasarkan bit terkecil dari index
        // bit = 0: current adalah LEFT child → hash(current || sibling)
        // bit = 1: current adalah RIGHT child → hash(sibling || current)
        if index & 1 == 0 {
            // Current is left child
            current = compute_parent_hash(&current, sibling);
        } else {
            // Current is right child
            current = compute_parent_hash(sibling, &current);
        }

        // Move to next level
        index >>= 1;
    }

    // Compare computed root dengan expected root
    current == proof.root
}

/// Verify epoch seed menggunakan DA Merkle proof.
///
/// # Verification Steps
///
/// 1. Derive leaf hash dari seed + epoch
/// 2. Verify leaf terhadap Merkle root menggunakan proof
/// 3. Return result dengan error detail jika gagal
///
/// # Determinism
///
/// - Same inputs = same output
/// - Tidak ada randomness
/// - Cross-platform deterministic
///
/// # Arguments
///
/// * `seed` - Claimed epoch seed (32 bytes)
/// * `epoch` - Claimed epoch number
/// * `da_proof` - Merkle proof dari DA layer
///
/// # Returns
///
/// `SeedVerificationResult` dengan:
/// - `valid=true, error=None` jika verification berhasil
/// - `valid=false, error=Some(..)` jika verification gagal
///
/// # Example
///
/// ```ignore
/// let result = verify_epoch_seed(&seed, epoch, &proof);
/// if result.is_valid() {
///     // Seed verified successfully
/// } else {
///     // Verification failed
///     println!("Error: {}", result.error_message().unwrap());
/// }
/// ```
pub fn verify_epoch_seed(
    seed: &[u8; 32],
    epoch: u64,
    da_proof: &DAMerkleProof,
) -> SeedVerificationResult {
    // Step 1: Derive leaf hash dari seed + epoch
    let leaf = compute_leaf_hash(seed, epoch);

    // Step 2: Verify Merkle proof
    let proof_valid = verify_merkle_proof(&leaf, da_proof);

    if proof_valid {
        SeedVerificationResult::success()
    } else {
        SeedVerificationResult::failure(
            "merkle proof verification failed: computed root does not match expected root"
                .to_string(),
        )
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ────────────────────────────────────────────────────────────────────────────
    // Helper functions untuk testing
    // ────────────────────────────────────────────────────────────────────────────

    /// Build valid Merkle proof untuk testing.
    ///
    /// Creates a simple 2-level tree:
    /// ```text
    ///        root
    ///       /    \
    ///     h01    h23
    ///    /  \   /  \
    ///   L0  L1 L2  L3
    /// ```
    fn build_test_merkle_tree(leaves: &[[u8; 32]; 4]) -> ([u8; 32], Vec<Vec<[u8; 32]>>) {
        // Level 0 -> Level 1
        let h01 = compute_parent_hash(&leaves[0], &leaves[1]);
        let h23 = compute_parent_hash(&leaves[2], &leaves[3]);

        // Level 1 -> Root
        let root = compute_parent_hash(&h01, &h23);

        // Paths untuk setiap leaf
        let paths = vec![
            vec![leaves[1], h23], // Leaf 0: sibling L1, then h23
            vec![leaves[0], h23], // Leaf 1: sibling L0, then h23
            vec![leaves[3], h01], // Leaf 2: sibling L3, then h01
            vec![leaves[2], h01], // Leaf 3: sibling L2, then h01
        ];

        (root, paths)
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Test: verify_merkle_proof
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_valid_merkle_proof_passes() {
        // Create 4 deterministic leaves
        let leaves: [[u8; 32]; 4] = [
            [0x11u8; 32],
            [0x22u8; 32],
            [0x33u8; 32],
            [0x44u8; 32],
        ];

        let (root, paths) = build_test_merkle_tree(&leaves);

        // Test each leaf position
        for (index, (leaf, path)) in leaves.iter().zip(paths.iter()).enumerate() {
            let proof = DAMerkleProof {
                root,
                path: path.clone(),
                index: index as u64,
            };

            assert!(
                verify_merkle_proof(leaf, &proof),
                "valid proof for leaf {} should pass",
                index
            );
        }
    }

    #[test]
    fn test_invalid_merkle_proof_fails() {
        let leaves: [[u8; 32]; 4] = [
            [0x11u8; 32],
            [0x22u8; 32],
            [0x33u8; 32],
            [0x44u8; 32],
        ];

        let (root, paths) = build_test_merkle_tree(&leaves);

        // Test dengan wrong leaf
        let wrong_leaf = [0xFFu8; 32];
        let proof = DAMerkleProof {
            root,
            path: paths[0].clone(),
            index: 0,
        };

        assert!(
            !verify_merkle_proof(&wrong_leaf, &proof),
            "proof with wrong leaf should fail"
        );
    }

    #[test]
    fn test_merkle_proof_wrong_root_fails() {
        let leaves: [[u8; 32]; 4] = [
            [0x11u8; 32],
            [0x22u8; 32],
            [0x33u8; 32],
            [0x44u8; 32],
        ];

        let (_root, paths) = build_test_merkle_tree(&leaves);

        // Test dengan wrong root
        let wrong_root = [0xFFu8; 32];
        let proof = DAMerkleProof {
            root: wrong_root,
            path: paths[0].clone(),
            index: 0,
        };

        assert!(
            !verify_merkle_proof(&leaves[0], &proof),
            "proof with wrong root should fail"
        );
    }

    #[test]
    fn test_merkle_proof_wrong_index_fails() {
        let leaves: [[u8; 32]; 4] = [
            [0x11u8; 32],
            [0x22u8; 32],
            [0x33u8; 32],
            [0x44u8; 32],
        ];

        let (root, paths) = build_test_merkle_tree(&leaves);

        // Test leaf 0 dengan index 1 (wrong position)
        let proof = DAMerkleProof {
            root,
            path: paths[0].clone(),
            index: 1, // Wrong! Should be 0
        };

        assert!(
            !verify_merkle_proof(&leaves[0], &proof),
            "proof with wrong index should fail"
        );
    }

    #[test]
    fn test_merkle_proof_empty_path() {
        let leaf = [0x42u8; 32];

        // Empty path means leaf == root
        let proof = DAMerkleProof {
            root: leaf, // root equals leaf
            path: vec![],
            index: 0,
        };

        assert!(
            verify_merkle_proof(&leaf, &proof),
            "empty path with leaf==root should pass"
        );

        // Different root should fail
        let proof_fail = DAMerkleProof {
            root: [0xFFu8; 32],
            path: vec![],
            index: 0,
        };

        assert!(
            !verify_merkle_proof(&leaf, &proof_fail),
            "empty path with leaf!=root should fail"
        );
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Test: verify_epoch_seed
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_wrong_epoch_fails() {
        let seed = [0x42u8; 32];
        let correct_epoch = 100u64;
        let wrong_epoch = 999u64;

        // Compute leaf untuk correct epoch
        let correct_leaf = compute_leaf_hash(&seed, correct_epoch);

        // Build simple single-leaf tree (leaf == root)
        let proof = DAMerkleProof {
            root: correct_leaf,
            path: vec![],
            index: 0,
        };

        // Verify dengan wrong epoch should fail
        let result = verify_epoch_seed(&seed, wrong_epoch, &proof);

        assert!(!result.is_valid(), "wrong epoch should fail verification");
        assert!(
            result.error.is_some(),
            "failed result should have error message"
        );
    }

    #[test]
    fn test_tampered_seed_fails() {
        let original_seed = [0x42u8; 32];
        let tampered_seed = [0xFFu8; 32];
        let epoch = 100u64;

        // Compute leaf untuk original seed
        let original_leaf = compute_leaf_hash(&original_seed, epoch);

        // Build proof untuk original seed
        let proof = DAMerkleProof {
            root: original_leaf,
            path: vec![],
            index: 0,
        };

        // Verify dengan tampered seed should fail
        let result = verify_epoch_seed(&tampered_seed, epoch, &proof);

        assert!(!result.is_valid(), "tampered seed should fail verification");
        assert!(
            result.error.is_some(),
            "failed result should have error message"
        );
    }

    #[test]
    fn test_valid_epoch_seed_passes() {
        let seed = [0x42u8; 32];
        let epoch = 100u64;

        // Compute correct leaf
        let leaf = compute_leaf_hash(&seed, epoch);

        // Build simple proof
        let proof = DAMerkleProof {
            root: leaf,
            path: vec![],
            index: 0,
        };

        let result = verify_epoch_seed(&seed, epoch, &proof);

        assert!(result.is_valid(), "valid seed should pass verification");
        assert!(
            result.error.is_none(),
            "success result should have no error"
        );
    }

    #[test]
    fn test_deterministic_verification() {
        let seed = [0xABu8; 32];
        let epoch = 12345u64;

        let leaf = compute_leaf_hash(&seed, epoch);

        let proof = DAMerkleProof {
            root: leaf,
            path: vec![],
            index: 0,
        };

        // Run 100 times - all should produce identical results
        let first_result = verify_epoch_seed(&seed, epoch, &proof);

        for i in 0..100 {
            let result = verify_epoch_seed(&seed, epoch, &proof);
            assert_eq!(
                result.valid, first_result.valid,
                "iteration {} should match first result",
                i
            );
            assert_eq!(
                result.error, first_result.error,
                "iteration {} error should match first result",
                i
            );
        }
    }

    #[test]
    fn test_epoch_seed_with_merkle_tree() {
        // Create multiple seeds for different indices
        let seeds: [[u8; 32]; 4] = [
            [0x11u8; 32],
            [0x22u8; 32],
            [0x33u8; 32],
            [0x44u8; 32],
        ];
        let epoch = 999u64;

        // Compute leaves
        let leaves: [[u8; 32]; 4] = [
            compute_leaf_hash(&seeds[0], epoch),
            compute_leaf_hash(&seeds[1], epoch),
            compute_leaf_hash(&seeds[2], epoch),
            compute_leaf_hash(&seeds[3], epoch),
        ];

        let (root, paths) = build_test_merkle_tree(&leaves);

        // Verify each seed
        for (index, (seed, path)) in seeds.iter().zip(paths.iter()).enumerate() {
            let proof = DAMerkleProof {
                root,
                path: path.clone(),
                index: index as u64,
            };

            let result = verify_epoch_seed(seed, epoch, &proof);
            assert!(
                result.is_valid(),
                "seed at index {} should verify",
                index
            );
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Test: SeedVerificationResult invariants
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_seed_verification_result_success_invariant() {
        let result = SeedVerificationResult::success();

        assert!(result.valid);
        assert!(result.error.is_none());
        assert!(result.is_valid());
        assert!(result.error_message().is_none());
    }

    #[test]
    fn test_seed_verification_result_failure_invariant() {
        let result = SeedVerificationResult::failure("test error".to_string());

        assert!(!result.valid);
        assert!(result.error.is_some());
        assert!(!result.is_valid());
        assert_eq!(result.error_message(), Some("test error"));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Test: Internal hash functions
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_sha3_512_truncated_deterministic() {
        let data = b"test data for hashing";

        let hash1 = sha3_512_truncated(data);
        let hash2 = sha3_512_truncated(data);
        let hash3 = sha3_512_truncated(data);

        assert_eq!(hash1, hash2);
        assert_eq!(hash2, hash3);

        // Should not be all zeros
        assert_ne!(hash1, [0u8; 32]);
    }

    #[test]
    fn test_sha3_512_truncated_different_inputs() {
        let data1 = b"input one";
        let data2 = b"input two";

        let hash1 = sha3_512_truncated(data1);
        let hash2 = sha3_512_truncated(data2);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_compute_leaf_hash_deterministic() {
        let seed = [0x42u8; 32];
        let epoch = 12345u64;

        let hash1 = compute_leaf_hash(&seed, epoch);
        let hash2 = compute_leaf_hash(&seed, epoch);
        let hash3 = compute_leaf_hash(&seed, epoch);

        assert_eq!(hash1, hash2);
        assert_eq!(hash2, hash3);
    }

    #[test]
    fn test_compute_leaf_hash_different_epoch() {
        let seed = [0x42u8; 32];

        let hash1 = compute_leaf_hash(&seed, 1);
        let hash2 = compute_leaf_hash(&seed, 2);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_compute_leaf_hash_different_seed() {
        let epoch = 100u64;

        let hash1 = compute_leaf_hash(&[0x11u8; 32], epoch);
        let hash2 = compute_leaf_hash(&[0x22u8; 32], epoch);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_compute_parent_hash_deterministic() {
        let left = [0x11u8; 32];
        let right = [0x22u8; 32];

        let hash1 = compute_parent_hash(&left, &right);
        let hash2 = compute_parent_hash(&left, &right);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_compute_parent_hash_order_matters() {
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];

        let hash_ab = compute_parent_hash(&a, &b);
        let hash_ba = compute_parent_hash(&b, &a);

        // Order MUST matter
        assert_ne!(hash_ab, hash_ba);
    }
}