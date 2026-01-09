//! # Storage Proof Generation Module
//!
//! Modul ini menyediakan mekanisme proof storage untuk challenge-response.
//!
//! ## Purpose
//!
//! Memungkinkan node untuk membuktikan bahwa ia benar-benar menyimpan chunk
//! tertentu, tanpa harus mengirimkan seluruh data chunk.
//!
//! ## Challenge-Response Flow
//!
//! ```text
//! ┌──────────────┐              ┌──────────────┐
//! │   Verifier   │              │    Prover    │
//! └──────┬───────┘              └──────┬───────┘
//!        │                             │
//!        │  1. challenge_seed          │
//!        │ ─────────────────────────►  │
//!        │                             │
//!        │                             │ 2. compute response
//!        │                             │    = SHA3-256(data || challenge)
//!        │                             │
//!        │  3. StorageProof            │
//!        │ ◄─────────────────────────  │
//!        │                             │
//!        │ 4. verify proof             │
//!        │                             │
//! ```
//!
//! ## Proof Scheme
//!
//! - `response = SHA3-256(chunk_data || challenge_seed)`
//! - `chunk_hash = hex(SHA3-256(chunk_data))`
//!
//! ## Usage
//!
//! ```rust,ignore
//! // Generate proof
//! let proof = generate_proof(&chunk_data, &challenge_seed);
//!
//! // Verify proof (structural + commitment check)
//! let valid = verify_proof(&proof, &chunk_hash, &da_commitment);
//!
//! // Full verification with data
//! let full_valid = verify_proof_with_data(&proof, &chunk_data, &da_commitment);
//! ```

use sha3::{Sha3_256, Digest};
use std::time::{SystemTime, UNIX_EPOCH};

// ════════════════════════════════════════════════════════════════════════════
// STORAGE PROOF STRUCT
// ════════════════════════════════════════════════════════════════════════════

/// Proof bahwa node menyimpan chunk tertentu.
///
/// Struct ini berisi bukti kriptografis yang membuktikan kepemilikan
/// chunk data asli, sebagai respons terhadap challenge.
///
/// # Fields
///
/// - `chunk_hash`: Hash canonical chunk (hex string)
/// - `challenge_seed`: Seed challenge dari verifier (32 bytes)
/// - `response`: Hash response = SHA3-256(data || challenge) (32 bytes)
/// - `merkle_proof`: Optional Merkle proof untuk chunk besar (dapat kosong)
/// - `timestamp`: Unix timestamp saat proof dibuat (milliseconds)
///
/// # Invariant
///
/// - `response` HARUS deterministik: input sama → output sama
/// - `merkle_proof` BOLEH kosong jika tidak diperlukan
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageProof {
    /// Hash canonical chunk (hex string dari SHA3-256).
    pub chunk_hash: String,
    /// Seed challenge dari verifier (32 bytes).
    pub challenge_seed: [u8; 32],
    /// Hash response: SHA3-256(chunk_data || challenge_seed).
    pub response: [u8; 32],
    /// Merkle proof untuk chunk besar (optional, dapat kosong).
    pub merkle_proof: Vec<[u8; 32]>,
    /// Unix timestamp saat proof dibuat (milliseconds).
    pub timestamp: u64,
}

impl StorageProof {
    /// Check if merkle proof is present.
    pub fn has_merkle_proof(&self) -> bool {
        !self.merkle_proof.is_empty()
    }

    /// Get proof age in milliseconds since creation.
    pub fn age_ms(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        now.saturating_sub(self.timestamp)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════

/// Compute SHA3-256 hash of data.
fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Compute chunk hash: SHA3-256(chunk_data) as hex string.
fn compute_chunk_hash(chunk_data: &[u8]) -> String {
    let hash = sha3_256(chunk_data);
    hex::encode(hash)
}

/// Compute response: SHA3-256(chunk_data || challenge_seed).
///
/// # CRITICAL
///
/// Urutan concatenation adalah: data FIRST, challenge SECOND.
/// TIDAK BOLEH diubah.
fn compute_response(chunk_data: &[u8], challenge_seed: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(chunk_data);
    hasher.update(challenge_seed);
    let result = hasher.finalize();
    let mut response = [0u8; 32];
    response.copy_from_slice(&result);
    response
}

/// Get current timestamp in milliseconds.
fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ════════════════════════════════════════════════════════════════════════════
// PROOF GENERATION
// ════════════════════════════════════════════════════════════════════════════

/// Generate storage proof untuk chunk data.
///
/// # Arguments
///
/// * `chunk_data` - Data chunk asli
/// * `challenge` - Challenge seed dari verifier (32 bytes)
///
/// # Returns
///
/// `StorageProof` yang berisi bukti kepemilikan chunk.
///
/// # Proof Scheme
///
/// ```text
/// response = SHA3-256(chunk_data || challenge_seed)
/// chunk_hash = hex(SHA3-256(chunk_data))
/// ```
///
/// # Determinism
///
/// Fungsi ini DETERMINISTIK: input sama → output sama
/// (kecuali timestamp yang selalu berbeda).
///
/// # Example
///
/// ```rust,ignore
/// let chunk_data = b"some chunk data";
/// let challenge = [0x42u8; 32];
/// let proof = generate_proof(chunk_data, &challenge);
/// ```
pub fn generate_proof(chunk_data: &[u8], challenge: &[u8; 32]) -> StorageProof {
    // 1. Compute chunk hash: SHA3-256(chunk_data) as hex
    let chunk_hash = compute_chunk_hash(chunk_data);

    // 2. Copy challenge seed
    let challenge_seed = *challenge;

    // 3. Compute response: SHA3-256(chunk_data || challenge_seed)
    let response = compute_response(chunk_data, challenge);

    // 4. Merkle proof: kosong (tidak diperlukan untuk chunk kecil)
    let merkle_proof = Vec::new();

    // 5. Timestamp: waktu saat proof dibuat
    let timestamp = current_timestamp_ms();

    StorageProof {
        chunk_hash,
        challenge_seed,
        response,
        merkle_proof,
        timestamp,
    }
}

// ════════════════════════════════════════════════════════════════════════════
// PROOF VERIFICATION
// ════════════════════════════════════════════════════════════════════════════

/// Verify storage proof (structural validation).
///
/// # Arguments
///
/// * `proof` - StorageProof yang akan diverifikasi
/// * `chunk_hash` - Expected chunk hash (hex string)
/// * `da_commitment` - DA commitment (32 bytes)
///
/// # Returns
///
/// `true` jika proof valid secara struktural dan konsisten,
/// `false` jika ada ketidaksesuaian.
///
/// # Validation Steps
///
/// 1. Validate chunk_hash: proof.chunk_hash == chunk_hash
/// 2. Validate commitment: chunk_hash konsisten dengan da_commitment
/// 3. Validate structural: response non-zero, timestamp reasonable
///
/// # Note
///
/// Fungsi ini TIDAK memverifikasi bahwa response benar-benar
/// dihitung dari data asli. Untuk full verification, gunakan
/// `verify_proof_with_data()`.
///
/// # Invariant
///
/// - TIDAK panic
/// - TIDAK auto-trust proof
/// - Deterministik
pub fn verify_proof(
    proof: &StorageProof,
    chunk_hash: &str,
    da_commitment: &[u8; 32],
) -> bool {
    // 1. Validate chunk_hash match
    if proof.chunk_hash != chunk_hash {
        return false;
    }

    // 2. Validate commitment consistency
    // chunk_hash (hex) should decode to bytes that match da_commitment
    // OR da_commitment is derived from chunk_hash in some way
    if let Ok(decoded) = hex::decode(chunk_hash) {
        if decoded.len() == 32 {
            let mut expected = [0u8; 32];
            expected.copy_from_slice(&decoded);
            if expected != *da_commitment {
                return false;
            }
        } else {
            // Invalid chunk_hash length
            return false;
        }
    } else {
        // chunk_hash is not valid hex - check if da_commitment
        // is SHA3-256 of the chunk_hash string itself (fallback)
        let computed = sha3_256(chunk_hash.as_bytes());
        if computed != *da_commitment {
            return false;
        }
    }

    // 3. Validate structural integrity
    // Response should not be all zeros (extremely unlikely for real proof)
    if proof.response == [0u8; 32] {
        return false;
    }

    // Challenge seed should not be all zeros (weak challenge)
    // But this is technically valid, so we allow it

    // Timestamp should be reasonable (not in far future)
    let now = current_timestamp_ms();
    if proof.timestamp > now + 60_000 {
        // More than 1 minute in future
        return false;
    }

    // All checks passed
    true
}

/// Verify storage proof with full data verification.
///
/// # Arguments
///
/// * `proof` - StorageProof yang akan diverifikasi
/// * `chunk_data` - Data chunk asli untuk recompute
/// * `da_commitment` - DA commitment (32 bytes)
///
/// # Returns
///
/// `true` jika proof benar-benar valid (termasuk response match),
/// `false` jika ada ketidaksesuaian.
///
/// # Full Verification
///
/// 1. Recompute chunk_hash dari chunk_data
/// 2. Validate chunk_hash match
/// 3. Validate commitment match
/// 4. Recompute response: SHA3-256(chunk_data || challenge_seed)
/// 5. Compare dengan proof.response
///
/// # Example
///
/// ```rust,ignore
/// let valid = verify_proof_with_data(&proof, &chunk_data, &da_commitment);
/// ```
pub fn verify_proof_with_data(
    proof: &StorageProof,
    chunk_data: &[u8],
    da_commitment: &[u8; 32],
) -> bool {
    // 1. Recompute chunk_hash dari chunk_data
    let computed_hash = compute_chunk_hash(chunk_data);

    // 2. Validate chunk_hash match
    if proof.chunk_hash != computed_hash {
        return false;
    }

    // 3. Validate commitment: da_commitment should be SHA3-256(chunk_data)
    let computed_commitment = sha3_256(chunk_data);
    if computed_commitment != *da_commitment {
        return false;
    }

    // 4. Recompute response: SHA3-256(chunk_data || challenge_seed)
    let computed_response = compute_response(chunk_data, &proof.challenge_seed);

    // 5. Compare dengan proof.response
    if computed_response != proof.response {
        return false;
    }

    // All checks passed
    true
}

/// Compute DA commitment from chunk data.
///
/// # Arguments
///
/// * `chunk_data` - Data chunk
///
/// # Returns
///
/// DA commitment: SHA3-256(chunk_data) as [u8; 32]
pub fn compute_da_commitment(chunk_data: &[u8]) -> [u8; 32] {
    sha3_256(chunk_data)
}

// ════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ════════════════════════════════════════════════════════════════════════
    // HELPER FUNCTIONS
    // ════════════════════════════════════════════════════════════════════════

    fn create_test_challenge() -> [u8; 32] {
        [0x42u8; 32]
    }

    fn create_test_data() -> Vec<u8> {
        b"test chunk data for storage proof".to_vec()
    }

    fn create_commitment_for_data(data: &[u8]) -> [u8; 32] {
        sha3_256(data)
    }

    // ════════════════════════════════════════════════════════════════════════
    // A. PROOF VALID TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_generate_and_verify_valid_proof() {
        let data = create_test_data();
        let challenge = create_test_challenge();
        let commitment = create_commitment_for_data(&data);

        let proof = generate_proof(&data, &challenge);

        // Verify with structural check
        assert!(verify_proof(&proof, &proof.chunk_hash, &commitment));

        // Verify with full data
        assert!(verify_proof_with_data(&proof, &data, &commitment));
    }

    #[test]
    fn test_proof_has_correct_structure() {
        let data = create_test_data();
        let challenge = create_test_challenge();

        let proof = generate_proof(&data, &challenge);

        // Check fields are populated
        assert!(!proof.chunk_hash.is_empty());
        assert_eq!(proof.challenge_seed, challenge);
        assert_ne!(proof.response, [0u8; 32]);
        assert!(proof.merkle_proof.is_empty()); // No merkle proof for simple case
        assert!(proof.timestamp > 0);
    }

    #[test]
    fn test_proof_chunk_hash_is_hex() {
        let data = create_test_data();
        let challenge = create_test_challenge();

        let proof = generate_proof(&data, &challenge);

        // chunk_hash should be valid hex
        let decoded = hex::decode(&proof.chunk_hash);
        assert!(decoded.is_ok());
        assert_eq!(decoded.unwrap().len(), 32);
    }

    // ════════════════════════════════════════════════════════════════════════
    // B. CHALLENGE MISMATCH TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_different_challenge_produces_different_response() {
        let data = create_test_data();
        let challenge1 = [0x11u8; 32];
        let challenge2 = [0x22u8; 32];

        let proof1 = generate_proof(&data, &challenge1);
        let proof2 = generate_proof(&data, &challenge2);

        // Same data, different challenge → different response
        assert_ne!(proof1.response, proof2.response);
        assert_ne!(proof1.challenge_seed, proof2.challenge_seed);

        // But chunk_hash should be same (same data)
        assert_eq!(proof1.chunk_hash, proof2.chunk_hash);
    }

    #[test]
    fn test_verify_fails_with_wrong_challenge() {
        let data = create_test_data();
        let challenge1 = [0x11u8; 32];
        let challenge2 = [0x22u8; 32];
        let commitment = create_commitment_for_data(&data);

        // Generate with challenge1
        let proof = generate_proof(&data, &challenge1);

        // Create a tampered proof with challenge2
        let tampered_proof = StorageProof {
            chunk_hash: proof.chunk_hash.clone(),
            challenge_seed: challenge2, // Different challenge
            response: proof.response,   // Same response (wrong!)
            merkle_proof: proof.merkle_proof.clone(),
            timestamp: proof.timestamp,
        };

        // Full verification should fail (response doesn't match new challenge)
        assert!(!verify_proof_with_data(&tampered_proof, &data, &commitment));
    }

    // ════════════════════════════════════════════════════════════════════════
    // C. CHUNK DATA MODIFIED TESTS
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_modified_data_produces_different_proof() {
        let original_data = b"original data";
        let modified_data = b"modified data";
        let challenge = create_test_challenge();

        let proof_original = generate_proof(original_data, &challenge);
        let proof_modified = generate_proof(modified_data, &challenge);

        // Different data → different response
        assert_ne!(proof_original.response, proof_modified.response);

        // Different data → different chunk_hash
        assert_ne!(proof_original.chunk_hash, proof_modified.chunk_hash);
    }

    #[test]
    fn test_verify_fails_with_modified_data() {
        let original_data = b"original data";
        let modified_data = b"modified data";
        let challenge = create_test_challenge();
        let original_commitment = create_commitment_for_data(original_data);

        // Generate proof with original data
        let proof = generate_proof(original_data, &challenge);

        // Try to verify with modified data - should fail
        assert!(!verify_proof_with_data(&proof, modified_data, &original_commitment));
    }

    #[test]
    fn test_single_byte_modification_detected() {
        let mut data = create_test_data();
        let challenge = create_test_challenge();
        let original_commitment = create_commitment_for_data(&data);

        // Generate proof with original data
        let proof = generate_proof(&data, &challenge);

        // Modify single byte
        data[0] ^= 0xFF;

        // Verification should fail
        assert!(!verify_proof_with_data(&proof, &data, &original_commitment));
    }

    // ════════════════════════════════════════════════════════════════════════
    // D. CHUNK HASH MISMATCH TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_fails_with_wrong_chunk_hash() {
        let data = create_test_data();
        let challenge = create_test_challenge();
        let commitment = create_commitment_for_data(&data);

        let proof = generate_proof(&data, &challenge);

        // Wrong chunk_hash
        let wrong_hash = "0".repeat(64); // All zeros
        assert!(!verify_proof(&proof, &wrong_hash, &commitment));
    }

    #[test]
    fn test_verify_fails_with_mismatched_commitment() {
        let data = create_test_data();
        let challenge = create_test_challenge();

        let proof = generate_proof(&data, &challenge);

        // Wrong commitment (random bytes)
        let wrong_commitment = [0xFFu8; 32];
        assert!(!verify_proof(&proof, &proof.chunk_hash, &wrong_commitment));
    }

    #[test]
    fn test_verify_fails_with_invalid_hex_hash() {
        let data = create_test_data();
        let challenge = create_test_challenge();
        let commitment = create_commitment_for_data(&data);

        let proof = generate_proof(&data, &challenge);

        // Invalid hex string
        let invalid_hash = "not_valid_hex!@#$";
        assert!(!verify_proof(&proof, invalid_hash, &commitment));
    }

    // ════════════════════════════════════════════════════════════════════════
    // E. DETERMINISM TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_same_input_same_response() {
        let data = create_test_data();
        let challenge = create_test_challenge();

        let proof1 = generate_proof(&data, &challenge);
        let proof2 = generate_proof(&data, &challenge);

        // Same input → same response (deterministic)
        assert_eq!(proof1.response, proof2.response);
        assert_eq!(proof1.chunk_hash, proof2.chunk_hash);
        assert_eq!(proof1.challenge_seed, proof2.challenge_seed);

        // Timestamps may differ
    }

    #[test]
    fn test_response_deterministic_across_calls() {
        let data = b"determinism test data";
        let challenge = [0xABu8; 32];

        // Generate 10 times
        let proofs: Vec<_> = (0..10)
            .map(|_| generate_proof(data, &challenge))
            .collect();

        // All responses should be identical
        let first_response = proofs[0].response;
        for proof in &proofs {
            assert_eq!(proof.response, first_response);
        }
    }

    #[test]
    fn test_compute_response_deterministic() {
        let data = b"test data";
        let challenge = [0x55u8; 32];

        let response1 = compute_response(data, &challenge);
        let response2 = compute_response(data, &challenge);

        assert_eq!(response1, response2);
    }

    // ════════════════════════════════════════════════════════════════════════
    // F. EDGE CASE TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_empty_data() {
        let data = b"";
        let challenge = create_test_challenge();
        let commitment = create_commitment_for_data(data);

        let proof = generate_proof(data, &challenge);

        // Should still produce valid proof
        assert!(verify_proof(&proof, &proof.chunk_hash, &commitment));
        assert!(verify_proof_with_data(&proof, data, &commitment));
    }

    #[test]
    fn test_large_data() {
        let data = vec![0xABu8; 1024 * 1024]; // 1 MB
        let challenge = create_test_challenge();
        let commitment = create_commitment_for_data(&data);

        let proof = generate_proof(&data, &challenge);

        assert!(verify_proof(&proof, &proof.chunk_hash, &commitment));
        assert!(verify_proof_with_data(&proof, &data, &commitment));
    }

    #[test]
    fn test_zero_challenge() {
        let data = create_test_data();
        let challenge = [0u8; 32]; // All zeros
        let commitment = create_commitment_for_data(&data);

        let proof = generate_proof(&data, &challenge);

        // Should still work
        assert!(verify_proof(&proof, &proof.chunk_hash, &commitment));
        assert!(verify_proof_with_data(&proof, &data, &commitment));
    }

    #[test]
    fn test_max_challenge() {
        let data = create_test_data();
        let challenge = [0xFFu8; 32]; // All ones
        let commitment = create_commitment_for_data(&data);

        let proof = generate_proof(&data, &challenge);

        assert!(verify_proof(&proof, &proof.chunk_hash, &commitment));
        assert!(verify_proof_with_data(&proof, &data, &commitment));
    }

    // ════════════════════════════════════════════════════════════════════════
    // G. HELPER FUNCTION TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_compute_da_commitment() {
        let data = b"test data";
        let commitment = compute_da_commitment(data);

        // Should be SHA3-256 of data
        assert_eq!(commitment, sha3_256(data));
    }

    #[test]
    fn test_proof_age() {
        let data = create_test_data();
        let challenge = create_test_challenge();

        let proof = generate_proof(&data, &challenge);

        // Age should be very small (just created)
        assert!(proof.age_ms() < 1000); // Less than 1 second
    }

    #[test]
    fn test_has_merkle_proof() {
        let data = create_test_data();
        let challenge = create_test_challenge();

        let proof = generate_proof(&data, &challenge);

        // Simple proof has no merkle proof
        assert!(!proof.has_merkle_proof());
    }

    // ════════════════════════════════════════════════════════════════════════
    // H. STRUCTURAL VALIDATION TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_fails_with_zero_response() {
        let data = create_test_data();
        let challenge = create_test_challenge();
        let commitment = create_commitment_for_data(&data);

        let mut proof = generate_proof(&data, &challenge);

        // Tamper: set response to zeros
        proof.response = [0u8; 32];

        // Structural validation should fail
        assert!(!verify_proof(&proof, &proof.chunk_hash, &commitment));
    }

    #[test]
    fn test_verify_fails_with_future_timestamp() {
        let data = create_test_data();
        let challenge = create_test_challenge();
        let commitment = create_commitment_for_data(&data);

        let mut proof = generate_proof(&data, &challenge);

        // Tamper: set timestamp far in future (1 hour)
        proof.timestamp = current_timestamp_ms() + 3_600_000;

        // Should fail (more than 1 minute in future)
        assert!(!verify_proof(&proof, &proof.chunk_hash, &commitment));
    }

    // ════════════════════════════════════════════════════════════════════════
    // I. SHA3-256 SPECIFIC TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_sha3_256_known_value() {
        // SHA3-256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
        let empty_hash = sha3_256(b"");
        let expected = hex::decode(
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        ).unwrap();

        assert_eq!(empty_hash.to_vec(), expected);
    }

    #[test]
    fn test_concatenation_order_matters() {
        let data = b"data";
        let challenge = [0x11u8; 32];

        // SHA3-256(data || challenge) ≠ SHA3-256(challenge || data)
        let response_correct = compute_response(data, &challenge);

        // Compute wrong order manually
        let mut hasher = Sha3_256::new();
        hasher.update(&challenge); // Challenge first (wrong!)
        hasher.update(data);
        let result = hasher.finalize();
        let mut response_wrong = [0u8; 32];
        response_wrong.copy_from_slice(&result);

        // Should be different
        assert_ne!(response_correct, response_wrong);
    }
}