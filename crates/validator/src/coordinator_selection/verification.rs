//! Epoch Seed Verification (14A.2B.2.6)
//!
//! Module ini menyediakan verifikasi bahwa epoch seed yang diklaim:
//! 1. Benar-benar berasal dari DA blob yang valid
//! 2. Sesuai dengan epoch yang diklaim
//! 3. Diverifikasi menggunakan Merkle proof secara deterministik
//!
//! # Committee Verification (14A.2B.2.8)
//!
//! Selain seed verification, module ini juga menyediakan:
//! - `verify_committee_selection` - Verifikasi committee hasil selection
//! - `verify_member_eligibility` - Verifikasi member eligibility
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

// Import types dari parent module untuk committee verification
use super::{
    CoordinatorCommittee, CoordinatorMember, CoordinatorSelector,
    SelectionConfig, SelectionError, ValidatorCandidate,
};

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
// Committee Verification (14A.2B.2.8 + 14A.2B.2.9)
// ════════════════════════════════════════════════════════════════════════════════

/// Error type untuk committee verification failures.
///
/// Returned ketika `verify_committee_selection` menemukan ketidakcocokan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerificationError {
    /// Re-selection gagal karena error dari selection algorithm
    SelectionFailed(SelectionError),

    /// Jumlah members tidak cocok
    MemberCountMismatch {
        /// Jumlah members di committee yang diklaim
        claimed: usize,
        /// Jumlah members dari re-selection
        expected: usize,
    },

    /// Threshold tidak cocok dengan config
    ThresholdMismatch {
        /// Threshold di committee yang diklaim
        claimed: u8,
        /// Threshold dari config
        expected: u8,
    },

    /// Epoch tidak cocok
    EpochMismatch {
        /// Epoch di committee yang diklaim
        claimed: u64,
        /// Epoch yang diharapkan
        expected: u64,
    },

    /// Member pada index tertentu tidak cocok
    MemberMismatch {
        /// Index member yang tidak cocok
        index: usize,
        /// Deskripsi field yang berbeda
        field: String,
    },

    /// Member tidak ditemukan di validator set
    MemberNotInValidatorSet {
        /// Validator ID dari member yang tidak ditemukan
        validator_id: [u8; 32],
    },

    /// Stake tidak cocok dengan validator source
    StakeMismatch {
        /// Validator ID
        validator_id: [u8; 32],
        /// Stake di member
        member_stake: u128,
        /// Stake di validator
        validator_stake: u128,
    },

    /// Pubkey tidak cocok dengan validator source
    PubkeyMismatch {
        /// Validator ID
        validator_id: [u8; 32],
    },

    // ────────────────────────────────────────────────────────────────────────────
    // Additional variants (14A.2B.2.9)
    // ────────────────────────────────────────────────────────────────────────────

    /// Committee hasil re-selection tidak cocok dengan claimed committee (14A.2B.2.9)
    CommitteeMismatch {
        /// Deskripsi perbedaan
        reason: String,
    },

    /// Member tidak valid atau tidak ada di validator set (14A.2B.2.9)
    InvalidMember {
        /// Validator ID dari member yang tidak valid
        validator_id: [u8; 32],
        /// Deskripsi masalah
        reason: String,
    },

    /// Threshold tidak valid (14A.2B.2.9)
    InvalidThreshold {
        /// Threshold yang diklaim
        claimed: u8,
        /// Nilai yang diharapkan atau batas
        expected: u8,
        /// Deskripsi masalah
        reason: String,
    },

    /// Seed yang digunakan tidak cocok dengan yang diharapkan (14A.2B.2.9)
    SeedMismatch {
        /// Seed yang diklaim
        claimed: [u8; 32],
        /// Seed yang diharapkan
        expected: [u8; 32],
    },
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerificationError::SelectionFailed(e) => {
                write!(f, "re-selection failed: {}", e)
            }
            VerificationError::MemberCountMismatch { claimed, expected } => {
                write!(
                    f,
                    "member count mismatch: claimed {}, expected {}",
                    claimed, expected
                )
            }
            VerificationError::ThresholdMismatch { claimed, expected } => {
                write!(
                    f,
                    "threshold mismatch: claimed {}, expected {}",
                    claimed, expected
                )
            }
            VerificationError::EpochMismatch { claimed, expected } => {
                write!(
                    f,
                    "epoch mismatch: claimed {}, expected {}",
                    claimed, expected
                )
            }
            VerificationError::MemberMismatch { index, field } => {
                write!(
                    f,
                    "member mismatch at index {}: {} differs",
                    index, field
                )
            }
            VerificationError::MemberNotInValidatorSet { validator_id } => {
                write!(
                    f,
                    "member with validator_id {:02x}{:02x}...{:02x}{:02x} not found in validator set",
                    validator_id[0], validator_id[1],
                    validator_id[30], validator_id[31]
                )
            }
            VerificationError::StakeMismatch {
                validator_id,
                member_stake,
                validator_stake,
            } => {
                write!(
                    f,
                    "stake mismatch for validator {:02x}{:02x}...{:02x}{:02x}: member has {}, validator has {}",
                    validator_id[0], validator_id[1],
                    validator_id[30], validator_id[31],
                    member_stake, validator_stake
                )
            }
            VerificationError::PubkeyMismatch { validator_id } => {
                write!(
                    f,
                    "pubkey mismatch for validator {:02x}{:02x}...{:02x}{:02x}",
                    validator_id[0], validator_id[1],
                    validator_id[30], validator_id[31]
                )
            }
            VerificationError::CommitteeMismatch { reason } => {
                write!(f, "committee mismatch: {}", reason)
            }
            VerificationError::InvalidMember { validator_id, reason } => {
                write!(
                    f,
                    "invalid member {:02x}{:02x}...{:02x}{:02x}: {}",
                    validator_id[0], validator_id[1],
                    validator_id[30], validator_id[31],
                    reason
                )
            }
            VerificationError::InvalidThreshold { claimed, expected, reason } => {
                write!(
                    f,
                    "invalid threshold: claimed {}, expected {}, reason: {}",
                    claimed, expected, reason
                )
            }
            VerificationError::SeedMismatch { claimed, expected } => {
                write!(
                    f,
                    "seed mismatch: claimed {:02x}{:02x}..., expected {:02x}{:02x}...",
                    claimed[0], claimed[1],
                    expected[0], expected[1]
                )
            }
        }
    }
}

impl std::error::Error for VerificationError {}

impl From<SelectionError> for VerificationError {
    fn from(e: SelectionError) -> Self {
        VerificationError::SelectionFailed(e)
    }
}

/// Verify bahwa member berasal dari validator set dengan data yang cocok.
///
/// # Verification Steps
///
/// 1. Cari validator dengan `validator_id` yang cocok
/// 2. Verifikasi `stake` cocok
/// 3. Verifikasi `pubkey` cocok
///
/// # Determinism
///
/// - Same inputs = same output
/// - Tidak ada randomness
/// - Linear search (O(n)) untuk deterministic ordering
///
/// # Arguments
///
/// * `member` - CoordinatorMember yang akan diverifikasi
/// * `validators` - Slice of ValidatorCandidate sebagai reference
///
/// # Returns
///
/// `true` jika member valid dan berasal dari validator set.
/// `false` jika tidak ditemukan atau data tidak cocok.
pub fn verify_member_eligibility(
    member: &CoordinatorMember,
    validators: &[ValidatorCandidate],
) -> bool {
    // Linear search untuk deterministic ordering
    for validator in validators {
        // Check if this is the source validator
        if validator.id == member.validator_id {
            // Verify stake matches
            if validator.stake != member.stake {
                return false;
            }

            // Verify pubkey matches
            if validator.pubkey != member.pubkey {
                return false;
            }

            // All checks passed
            return true;
        }
    }

    // Validator not found
    false
}

/// Verify bahwa committee adalah hasil sah dari selection algorithm.
///
/// # Verification Algorithm (URUTAN WAJIB)
///
/// 1. Jalankan ulang `select_committee` dengan input yang sama
/// 2. Bandingkan hasil:
///    - Jumlah member HARUS sama
///    - Threshold HARUS cocok dengan config
///    - Setiap member HARUS identik (byte-wise)
/// 3. Verifikasi setiap member ada di validator set
/// 4. Verifikasi stake dan pubkey cocok dengan validator source
///
/// # Determinism
///
/// - Same inputs = same output
/// - Tidak ada randomness
/// - Tidak ada HashMap iteration
/// - Exact byte-wise comparison
///
/// # Arguments
///
/// * `committee` - Committee yang diklaim untuk diverifikasi
/// * `validators` - Validator set saat selection
/// * `seed` - Epoch seed yang digunakan untuk selection
/// * `config` - Selection config yang digunakan
///
/// # Returns
///
/// `Ok(true)` jika committee valid dan identik dengan re-selection.
/// `Err(VerificationError)` jika ada ketidakcocokan.
///
/// # Note
///
/// Function ini TIDAK pernah return `Ok(false)`. Semua kegagalan
/// dikembalikan sebagai `Err(VerificationError)` dengan detail penyebab.
pub fn verify_committee_selection(
    committee: &CoordinatorCommittee,
    validators: &[ValidatorCandidate],
    seed: &[u8; 32],
    config: &SelectionConfig,
) -> Result<bool, VerificationError> {
    // Step 1: Verify threshold matches config
    if committee.threshold != config.threshold {
        return Err(VerificationError::ThresholdMismatch {
            claimed: committee.threshold,
            expected: config.threshold,
        });
    }

    // Step 2: Create selector dan re-run selection
    let selector = CoordinatorSelector::new(config.clone()).map_err(|e| {
        VerificationError::SelectionFailed(SelectionError::Internal(format!(
            "invalid config: {}",
            e
        )))
    })?;

    let expected_committee = selector.select_committee(validators, committee.epoch, seed)?;

    // Step 3: Verify member count
    if committee.members.len() != expected_committee.members.len() {
        return Err(VerificationError::MemberCountMismatch {
            claimed: committee.members.len(),
            expected: expected_committee.members.len(),
        });
    }

    // Step 4: Verify each member (byte-wise comparison)
    for (index, (claimed, expected)) in committee
        .members
        .iter()
        .zip(expected_committee.members.iter())
        .enumerate()
    {
        // Check member id
        if claimed.id != expected.id {
            return Err(VerificationError::MemberMismatch {
                index,
                field: "id".to_string(),
            });
        }

        // Check validator_id
        if claimed.validator_id != expected.validator_id {
            return Err(VerificationError::MemberMismatch {
                index,
                field: "validator_id".to_string(),
            });
        }

        // Check pubkey
        if claimed.pubkey != expected.pubkey {
            return Err(VerificationError::MemberMismatch {
                index,
                field: "pubkey".to_string(),
            });
        }

        // Check stake
        if claimed.stake != expected.stake {
            return Err(VerificationError::MemberMismatch {
                index,
                field: "stake".to_string(),
            });
        }
    }

    // Step 5: Verify all members exist in validator set with matching data
    for member in &committee.members {
        // Find validator
        let validator = validators.iter().find(|v| v.id == member.validator_id);

        match validator {
            None => {
                return Err(VerificationError::MemberNotInValidatorSet {
                    validator_id: member.validator_id,
                });
            }
            Some(v) => {
                // Verify stake
                if v.stake != member.stake {
                    return Err(VerificationError::StakeMismatch {
                        validator_id: member.validator_id,
                        member_stake: member.stake,
                        validator_stake: v.stake,
                    });
                }

                // Verify pubkey
                if v.pubkey != member.pubkey {
                    return Err(VerificationError::PubkeyMismatch {
                        validator_id: member.validator_id,
                    });
                }
            }
        }
    }

    // All checks passed
    Ok(true)
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

    // ════════════════════════════════════════════════════════════════════════════
    // Committee Verification Tests (14A.2B.2.8)
    // ════════════════════════════════════════════════════════════════════════════

    fn make_validator_for_verification(seed: u8, zone: &str, stake: u128) -> ValidatorCandidate {
        let mut id = [0u8; 32];
        id[0] = seed;
        id[31] = seed.wrapping_add(1);

        let mut pubkey = [0u8; 32];
        pubkey[0] = seed.wrapping_add(100);
        pubkey[31] = seed.wrapping_add(101);

        ValidatorCandidate {
            id,
            pubkey,
            stake,
            zone: zone.to_string(),
            node_identity: None,
            tls_info: None,
            node_class: None,
            cooldown: None,
            identity_proof: None,
        }
    }

    #[test]
    fn test_verify_member_eligibility_valid() {
        let validators = vec![
            make_validator_for_verification(1, "zone-a", 1000),
            make_validator_for_verification(2, "zone-b", 2000),
            make_validator_for_verification(3, "zone-c", 3000),
        ];

        // Create member from validator 2
        let member = CoordinatorMember {
            id: [0x99u8; 32], // member id can be different
            validator_id: validators[1].id,
            pubkey: validators[1].pubkey,
            stake: validators[1].stake,
        };

        assert!(verify_member_eligibility(&member, &validators));
    }

    #[test]
    fn test_verify_member_eligibility_not_in_set() {
        let validators = vec![
            make_validator_for_verification(1, "zone-a", 1000),
            make_validator_for_verification(2, "zone-b", 2000),
        ];

        // Create member with unknown validator_id
        let member = CoordinatorMember {
            id: [0x99u8; 32],
            validator_id: [0xFFu8; 32], // not in validators
            pubkey: [0xAAu8; 32],
            stake: 1000,
        };

        assert!(!verify_member_eligibility(&member, &validators));
    }

    #[test]
    fn test_verify_member_eligibility_stake_mismatch() {
        let validators = vec![
            make_validator_for_verification(1, "zone-a", 1000),
        ];

        let member = CoordinatorMember {
            id: [0x99u8; 32],
            validator_id: validators[0].id,
            pubkey: validators[0].pubkey,
            stake: 9999, // different stake
        };

        assert!(!verify_member_eligibility(&member, &validators));
    }

    #[test]
    fn test_verify_member_eligibility_pubkey_mismatch() {
        let validators = vec![
            make_validator_for_verification(1, "zone-a", 1000),
        ];

        let member = CoordinatorMember {
            id: [0x99u8; 32],
            validator_id: validators[0].id,
            pubkey: [0xFFu8; 32], // different pubkey
            stake: validators[0].stake,
        };

        assert!(!verify_member_eligibility(&member, &validators));
    }

    #[test]
    fn test_verify_committee_selection_valid() {
        let config = SelectionConfig {
            committee_size: 3,
            threshold: 2,
            min_stake: 100,
        };

        let validators: Vec<ValidatorCandidate> = (0..10)
            .map(|i| make_validator_for_verification(i, &format!("zone-{}", i % 3), 1000 + (i as u128 * 100)))
            .collect();

        let seed = [0x42u8; 32];
        let epoch = 1u64;

        // Create committee using selection algorithm
        let selector = CoordinatorSelector::new(config.clone()).expect("valid config");
        let committee = selector.select_committee(&validators, epoch, &seed).expect("selection");

        // Verify should pass
        let result = verify_committee_selection(&committee, &validators, &seed, &config);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_committee_selection_deterministic() {
        let config = SelectionConfig {
            committee_size: 4,
            threshold: 3,
            min_stake: 100,
        };

        let validators: Vec<ValidatorCandidate> = (0..15)
            .map(|i| make_validator_for_verification(i, &format!("zone-{}", i % 4), 1000))
            .collect();

        let seed = [0x55u8; 32];
        let epoch = 5u64;

        let selector = CoordinatorSelector::new(config.clone()).expect("valid config");
        let committee = selector.select_committee(&validators, epoch, &seed).expect("selection");

        // Verify 100 times - all should pass
        for _ in 0..100 {
            let result = verify_committee_selection(&committee, &validators, &seed, &config);
            assert!(result.is_ok());
            assert!(result.unwrap());
        }
    }

    #[test]
    fn test_verify_committee_selection_wrong_seed() {
        let config = SelectionConfig {
            committee_size: 3,
            threshold: 2,
            min_stake: 100,
        };

        let validators: Vec<ValidatorCandidate> = (0..10)
            .map(|i| make_validator_for_verification(i, &format!("zone-{}", i % 3), 1000))
            .collect();

        let seed1 = [0x11u8; 32];
        let seed2 = [0x22u8; 32]; // different seed

        let selector = CoordinatorSelector::new(config.clone()).expect("valid config");
        let committee = selector.select_committee(&validators, 1, &seed1).expect("selection");

        // Verify with wrong seed should fail
        let result = verify_committee_selection(&committee, &validators, &seed2, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_committee_selection_wrong_threshold() {
        let config1 = SelectionConfig {
            committee_size: 3,
            threshold: 2,
            min_stake: 100,
        };
        let config2 = SelectionConfig {
            committee_size: 3,
            threshold: 3, // different threshold
            min_stake: 100,
        };

        let validators: Vec<ValidatorCandidate> = (0..10)
            .map(|i| make_validator_for_verification(i, "zone-a", 1000))
            .collect();

        let seed = [0x33u8; 32];

        let selector = CoordinatorSelector::new(config1).expect("valid config");
        let committee = selector.select_committee(&validators, 1, &seed).expect("selection");

        // Verify with wrong config should fail
        let result = verify_committee_selection(&committee, &validators, &seed, &config2);
        assert!(result.is_err());
        match result.unwrap_err() {
            VerificationError::ThresholdMismatch { claimed, expected } => {
                assert_eq!(claimed, 2);
                assert_eq!(expected, 3);
            }
            _ => panic!("expected ThresholdMismatch error"),
        }
    }

    #[test]
    fn test_verify_committee_selection_different_validators() {
        let config = SelectionConfig {
            committee_size: 3,
            threshold: 2,
            min_stake: 100,
        };

        let validators1: Vec<ValidatorCandidate> = (0..10)
            .map(|i| make_validator_for_verification(i, "zone-a", 1000))
            .collect();

        let validators2: Vec<ValidatorCandidate> = (10..20) // different validators
            .map(|i| make_validator_for_verification(i, "zone-a", 1000))
            .collect();

        let seed = [0x44u8; 32];

        let selector = CoordinatorSelector::new(config.clone()).expect("valid config");
        let committee = selector.select_committee(&validators1, 1, &seed).expect("selection");

        // Verify with different validator set should fail
        let result = verify_committee_selection(&committee, &validators2, &seed, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_committee_selection_tampered_member() {
        let config = SelectionConfig {
            committee_size: 3,
            threshold: 2,
            min_stake: 100,
        };

        let validators: Vec<ValidatorCandidate> = (0..10)
            .map(|i| make_validator_for_verification(i, "zone-a", 1000))
            .collect();

        let seed = [0x55u8; 32];

        let selector = CoordinatorSelector::new(config.clone()).expect("valid config");
        let mut committee = selector.select_committee(&validators, 1, &seed).expect("selection");

        // Tamper with first member's stake
        committee.members[0].stake = 99999;

        // Verify should fail
        let result = verify_committee_selection(&committee, &validators, &seed, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_verification_error_display() {
        let err1 = VerificationError::MemberCountMismatch {
            claimed: 5,
            expected: 3,
        };
        assert!(err1.to_string().contains("5"));
        assert!(err1.to_string().contains("3"));

        let err2 = VerificationError::ThresholdMismatch {
            claimed: 2,
            expected: 3,
        };
        assert!(err2.to_string().contains("2"));
        assert!(err2.to_string().contains("3"));

        let err3 = VerificationError::MemberMismatch {
            index: 1,
            field: "pubkey".to_string(),
        };
        assert!(err3.to_string().contains("1"));
        assert!(err3.to_string().contains("pubkey"));

        let err4 = VerificationError::MemberNotInValidatorSet {
            validator_id: [0xAB; 32],
        };
        assert!(err4.to_string().contains("ab"));

        let err5 = VerificationError::StakeMismatch {
            validator_id: [0xCD; 32],
            member_stake: 1000,
            validator_stake: 2000,
        };
        assert!(err5.to_string().contains("1000"));
        assert!(err5.to_string().contains("2000"));
    }
}