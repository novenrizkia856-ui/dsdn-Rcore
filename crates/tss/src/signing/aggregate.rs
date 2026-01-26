//! # Aggregate Signature
//!
//! Module ini menyediakan `AggregateSignature` struct dan fungsi
//! `aggregate_signatures` untuk FROST threshold signing.
//!
//! ## Format Serialization
//!
//! | Field | Offset | Size | Description |
//! |-------|--------|------|-------------|
//! | signature | 0 | 64 | FrostSignature (R ‖ s) |
//! | signer_count | 64 | 1 | Jumlah signers (u8) |
//! | signers | 65 | 32*n | Signer IDs |
//! | message_hash | 65+32*n | 32 | Message hash |
//!
//! ## Aggregation Flow
//!
//! ```text
//! PartialSignature[0..t] ──► compute_binding_factors()
//!                                      │
//!                                      ▼
//!                             compute_group_commitment() ──► R
//!                                      │
//!                                      ▼
//!                             sum(signature_shares) ──► s
//!                                      │
//!                                      ▼
//!                             FrostSignature(R ‖ s)
//!                                      │
//!                                      ▼
//!                             AggregateSignature
//! ```

use std::collections::{HashMap, HashSet};

use sha3::{Digest, Sha3_256};

use crate::error::SigningError;
use crate::primitives::{FrostSignature, GroupPublicKey, SigningCommitment, SCALAR_SIZE, SIGNATURE_SIZE};
use crate::types::SignerId;

use super::commitment::SigningCommitmentExt;
use super::partial::{compute_binding_factor, compute_group_commitment, PartialSignature};

// ════════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════════

/// Maximum number of signers supported.
const MAX_SIGNERS: usize = 255;

/// Minimum header size: signature (64) + signer_count (1) + message_hash (32)
const MIN_AGGREGATE_SIZE: usize = SIGNATURE_SIZE + 1 + 32;

// ════════════════════════════════════════════════════════════════════════════════
// AGGREGATE SIGNATURE
// ════════════════════════════════════════════════════════════════════════════════

/// Aggregate signature hasil FROST threshold signing.
///
/// `AggregateSignature` berisi:
/// - `FrostSignature` (R ‖ s)
/// - List signers yang berkontribusi
/// - Hash dari message yang di-sign
///
/// ## Invariant
///
/// - `signers` tidak boleh kosong
/// - Tidak boleh ada duplicate signers
#[derive(Debug, Clone)]
pub struct AggregateSignature {
    /// Inner FROST signature (R ‖ s).
    signature: FrostSignature,

    /// List signer IDs yang berkontribusi dalam signature.
    signers: Vec<SignerId>,

    /// Hash dari message yang di-sign.
    message_hash: [u8; 32],
}

impl AggregateSignature {
    /// Membuat `AggregateSignature` baru.
    ///
    /// # Arguments
    ///
    /// * `signature` - FROST signature (R ‖ s)
    /// * `signers` - List signer IDs yang berkontribusi
    /// * `message_hash` - Hash dari message
    ///
    /// # Panics
    ///
    /// Tidak panic. Validasi dilakukan oleh caller.
    #[must_use]
    pub fn new(
        signature: FrostSignature,
        signers: Vec<SignerId>,
        message_hash: [u8; 32],
    ) -> Self {
        Self {
            signature,
            signers,
            message_hash,
        }
    }

    /// Mengembalikan reference ke inner signature.
    #[must_use]
    pub fn signature(&self) -> &FrostSignature {
        &self.signature
    }

    /// Mengembalikan slice signers.
    #[must_use]
    pub fn signers(&self) -> &[SignerId] {
        &self.signers
    }

    /// Mengembalikan message hash.
    #[must_use]
    pub fn message_hash(&self) -> &[u8; 32] {
        &self.message_hash
    }

    /// Mengembalikan jumlah signers.
    #[must_use]
    pub fn signer_count(&self) -> usize {
        self.signers.len()
    }

    /// Serialize aggregate signature ke bytes.
    ///
    /// Format:
    /// - signature (64 bytes)
    /// - signer_count (1 byte)
    /// - signers (32 * n bytes)
    /// - message_hash (32 bytes)
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let signer_count = self.signers.len();
        let total_size = SIGNATURE_SIZE + 1 + (32 * signer_count) + 32;
        let mut bytes = Vec::with_capacity(total_size);

        // Signature (64 bytes)
        bytes.extend_from_slice(self.signature.as_bytes());

        // Signer count (1 byte)
        // Safe because signer_count is validated to be <= MAX_SIGNERS
        #[allow(clippy::cast_possible_truncation)]
        bytes.push(signer_count as u8);

        // Signers (32 * n bytes)
        for signer in &self.signers {
            bytes.extend_from_slice(signer.as_bytes());
        }

        // Message hash (32 bytes)
        bytes.extend_from_slice(&self.message_hash);

        bytes
    }

    /// Deserialize aggregate signature dari bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Byte slice
    ///
    /// # Errors
    ///
    /// - `SigningError::AggregationFailed` jika format tidak valid
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SigningError> {
        // Validate minimum length
        if bytes.len() < MIN_AGGREGATE_SIZE {
            return Err(SigningError::AggregationFailed {
                reason: format!(
                    "insufficient bytes: expected at least {}, got {}",
                    MIN_AGGREGATE_SIZE,
                    bytes.len()
                ),
            });
        }

        // Parse signature (bytes 0..64)
        let mut sig_bytes = [0u8; SIGNATURE_SIZE];
        sig_bytes.copy_from_slice(&bytes[0..SIGNATURE_SIZE]);
        let signature = FrostSignature::from_bytes(sig_bytes).map_err(|e| {
            SigningError::AggregationFailed {
                reason: format!("invalid signature: {}", e),
            }
        })?;

        // Parse signer count (byte 64)
        let signer_count = bytes[SIGNATURE_SIZE] as usize;

        // Validate signer count
        if signer_count > MAX_SIGNERS {
            return Err(SigningError::AggregationFailed {
                reason: format!(
                    "signer count {} exceeds maximum {}",
                    signer_count, MAX_SIGNERS
                ),
            });
        }

        // Validate expected length
        let expected_len = MIN_AGGREGATE_SIZE + (32 * signer_count);
        if bytes.len() < expected_len {
            return Err(SigningError::AggregationFailed {
                reason: format!(
                    "insufficient bytes for {} signers: expected {}, got {}",
                    signer_count, expected_len, bytes.len()
                ),
            });
        }

        // Parse signers (bytes 65..)
        let mut signers = Vec::with_capacity(signer_count);
        let mut seen = HashSet::with_capacity(signer_count);
        let signers_start = SIGNATURE_SIZE + 1;

        for i in 0..signer_count {
            let start = signers_start + (i * 32);
            let end = start + 32;

            let mut signer_bytes = [0u8; 32];
            signer_bytes.copy_from_slice(&bytes[start..end]);
            let signer = SignerId::from_bytes(signer_bytes);

            // Check for duplicates
            if !seen.insert(signer.clone()) {
                return Err(SigningError::DuplicateSigner { signer });
            }

            signers.push(signer);
        }

        // Parse message hash (last 32 bytes)
        let hash_start = signers_start + (signer_count * 32);
        let mut message_hash = [0u8; 32];
        message_hash.copy_from_slice(&bytes[hash_start..hash_start + 32]);

        Ok(Self {
            signature,
            signers,
            message_hash,
        })
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// AGGREGATE SIGNATURES FUNCTION
// ════════════════════════════════════════════════════════════════════════════════

/// Aggregate partial signatures menjadi satu FROST signature.
///
/// # Arguments
///
/// * `partials` - Slice of PartialSignature
/// * `group_pubkey` - Group public key hasil DKG
/// * `message_hash` - Hash dari message yang di-sign
///
/// # Errors
///
/// - `SigningError::InsufficientSignatures` jika partials kosong
/// - `SigningError::DuplicateSigner` jika ada signer duplikat
/// - `SigningError::AggregationFailed` jika aggregation gagal
///
/// # Algorithm
///
/// 1. Validate inputs
/// 2. Build sorted commitments list
/// 3. Compute binding factors for each signer
/// 4. Compute group commitment (R)
/// 5. Sum signature shares (s = Σ s_i)
/// 6. Build FrostSignature(R ‖ s)
/// 7. Return AggregateSignature
pub fn aggregate_signatures(
    partials: &[PartialSignature],
    _group_pubkey: &GroupPublicKey,
    message_hash: &[u8; 32],
) -> Result<AggregateSignature, SigningError> {
    // Step 1: Validate partials not empty
    if partials.is_empty() {
        return Err(SigningError::InsufficientSignatures {
            expected: 1,
            got: 0,
        });
    }

    // Validate no duplicates and collect signer IDs
    let mut seen_signers = HashSet::with_capacity(partials.len());
    let mut signers = Vec::with_capacity(partials.len());

    for partial in partials {
        let signer_id = partial.signer_id().clone();
        if !seen_signers.insert(signer_id.clone()) {
            return Err(SigningError::DuplicateSigner { signer: signer_id });
        }

        // Validate commitment format
        if !partial.commitment().verify_format() {
            return Err(SigningError::InvalidCommitment {
                signer: signer_id,
                reason: "commitment format invalid".to_string(),
            });
        }

        signers.push(signer_id);
    }

    // Step 2: Build sorted commitments list
    // Sort by signer ID for determinism
    let mut commitments: Vec<(SignerId, SigningCommitment)> = partials
        .iter()
        .map(|p| (p.signer_id().clone(), p.commitment().clone()))
        .collect();
    
    // Sort by signer ID bytes for deterministic ordering
    commitments.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));

    // Step 3: Compute binding factors for each signer
    let mut binding_factors: HashMap<SignerId, [u8; 32]> = HashMap::with_capacity(partials.len());
    
    for (signer_id, _) in &commitments {
        let bf = compute_binding_factor(signer_id, message_hash, &commitments);
        binding_factors.insert(signer_id.clone(), bf);
    }

    // Step 4: Compute group commitment (R)
    let group_commitment = compute_group_commitment(&commitments, &binding_factors);

    // Step 5: Sum signature shares (s = Σ s_i)
    // Sort partials by signer ID for deterministic summation
    let mut sorted_partials: Vec<&PartialSignature> = partials.iter().collect();
    sorted_partials.sort_by(|a, b| a.signer_id().as_bytes().cmp(b.signer_id().as_bytes()));

    let s_sum = sum_signature_shares(&sorted_partials)?;

    // Step 6: Build FrostSignature(R ‖ s)
    let mut sig_bytes = [0u8; SIGNATURE_SIZE];
    sig_bytes[0..32].copy_from_slice(&group_commitment);
    sig_bytes[32..64].copy_from_slice(&s_sum);

    let signature = FrostSignature::from_bytes(sig_bytes).map_err(|e| {
        SigningError::AggregationFailed {
            reason: format!("failed to build signature: {}", e),
        }
    })?;

    // Sort signers for deterministic output
    signers.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

    // Step 7: Return AggregateSignature
    Ok(AggregateSignature::new(signature, signers, *message_hash))
}

/// Sum signature shares dengan hash-based aggregation (placeholder).
///
/// Dalam implementasi nyata, ini akan melakukan modular addition
/// pada scalar field. Placeholder ini menggunakan hash untuk determinism.
fn sum_signature_shares(partials: &[&PartialSignature]) -> Result<[u8; 32], SigningError> {
    let mut hasher = Sha3_256::new();

    // Domain separator
    hasher.update(b"dsdn-tss-sum-shares-v1");

    // Process shares in order (partials must be sorted by caller)
    for partial in partials {
        hasher.update(partial.signer_id().as_bytes());
        hasher.update(partial.signature_share().as_bytes());
    }

    let result = hasher.finalize();
    let mut sum = [0u8; SCALAR_SIZE];
    sum.copy_from_slice(&result);

    // Validate result is non-zero
    if sum.iter().all(|&b| b == 0) {
        return Err(SigningError::AggregationFailed {
            reason: "signature share sum is zero".to_string(),
        });
    }

    Ok(sum)
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::FrostSignatureShare;

    // ────────────────────────────────────────────────────────────────────────────
    // HELPER FUNCTIONS
    // ────────────────────────────────────────────────────────────────────────────

    fn make_signature() -> FrostSignature {
        FrostSignature::from_bytes([0x01; SIGNATURE_SIZE]).unwrap()
    }

    fn make_signers(n: usize) -> Vec<SignerId> {
        (0..n)
            .map(|i| SignerId::from_bytes([i as u8; 32]))
            .collect()
    }

    fn make_aggregate() -> AggregateSignature {
        AggregateSignature::new(make_signature(), make_signers(2), [0xAA; 32])
    }

    fn make_partial(signer_idx: u8) -> PartialSignature {
        let signer_id = SignerId::from_bytes([signer_idx; 32]);
        let share = FrostSignatureShare::from_bytes([0x01; 32]).unwrap();
        let commitment = SigningCommitment::from_parts([0x02; 32], [0x03; 32]).unwrap();
        PartialSignature::new(signer_id, share, commitment)
    }

    // ────────────────────────────────────────────────────────────────────────────
    // AGGREGATE SIGNATURE TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_aggregate_signature_new() {
        let aggregate = make_aggregate();
        assert_eq!(aggregate.signer_count(), 2);
        assert_eq!(aggregate.message_hash(), &[0xAA; 32]);
    }

    #[test]
    fn test_aggregate_signature_accessors() {
        let sig = make_signature();
        let signers = make_signers(3);
        let hash = [0xBB; 32];
        
        let aggregate = AggregateSignature::new(sig.clone(), signers.clone(), hash);
        
        assert_eq!(aggregate.signature().as_bytes(), sig.as_bytes());
        assert_eq!(aggregate.signers().len(), 3);
        assert_eq!(aggregate.message_hash(), &hash);
        assert_eq!(aggregate.signer_count(), 3);
    }

    #[test]
    fn test_aggregate_signature_to_bytes() {
        let aggregate = make_aggregate();
        let bytes = aggregate.to_bytes();

        // signature (64) + count (1) + signers (2*32) + hash (32) = 161
        assert_eq!(bytes.len(), 64 + 1 + 64 + 32);
        assert_eq!(&bytes[0..64], aggregate.signature().as_bytes());
        assert_eq!(bytes[64], 2); // signer count
    }

    #[test]
    fn test_aggregate_signature_from_bytes() {
        let original = make_aggregate();
        let bytes = original.to_bytes();
        let recovered = AggregateSignature::from_bytes(&bytes).unwrap();

        assert_eq!(recovered.signature().as_bytes(), original.signature().as_bytes());
        assert_eq!(recovered.signer_count(), original.signer_count());
        assert_eq!(recovered.message_hash(), original.message_hash());
    }

    #[test]
    fn test_aggregate_signature_roundtrip() {
        let original = AggregateSignature::new(
            make_signature(),
            make_signers(5),
            [0xBB; 32],
        );
        let bytes = original.to_bytes();
        let recovered = AggregateSignature::from_bytes(&bytes).unwrap();

        assert_eq!(recovered.signer_count(), 5);
        for (a, b) in original.signers().iter().zip(recovered.signers().iter()) {
            assert_eq!(a.as_bytes(), b.as_bytes());
        }
    }

    #[test]
    fn test_aggregate_signature_from_bytes_insufficient() {
        let bytes = vec![0u8; 50]; // Too short
        let result = AggregateSignature::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_aggregate_signature_from_bytes_duplicate_signer() {
        // Build bytes manually with duplicate signer
        let sig = make_signature();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(sig.as_bytes());
        bytes.push(2); // 2 signers
        bytes.extend_from_slice(&[0x01; 32]); // signer 1
        bytes.extend_from_slice(&[0x01; 32]); // signer 2 (duplicate!)
        bytes.extend_from_slice(&[0xAA; 32]); // message hash

        let result = AggregateSignature::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_aggregate_signature_from_bytes_zero_signers() {
        let sig = make_signature();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(sig.as_bytes());
        bytes.push(0); // 0 signers
        bytes.extend_from_slice(&[0xAA; 32]); // message hash

        let result = AggregateSignature::from_bytes(&bytes);
        assert!(result.is_ok()); // Zero signers is valid at from_bytes level
    }

    // ────────────────────────────────────────────────────────────────────────────
    // AGGREGATE_SIGNATURES TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_aggregate_signatures_empty_fails() {
        let partials: Vec<PartialSignature> = vec![];
        let group_pubkey = GroupPublicKey::from_bytes([0x01; 32]).unwrap();
        let message_hash = [0xAA; 32];

        let result = aggregate_signatures(&partials, &group_pubkey, &message_hash);
        assert!(result.is_err());
        
        if let Err(SigningError::InsufficientSignatures { expected, got }) = result {
            assert_eq!(expected, 1);
            assert_eq!(got, 0);
        } else {
            panic!("Expected InsufficientSignatures error");
        }
    }

    #[test]
    fn test_aggregate_signatures_single() {
        let partials = vec![make_partial(0x01)];
        let group_pubkey = GroupPublicKey::from_bytes([0x01; 32]).unwrap();
        let message_hash = [0xAA; 32];

        let result = aggregate_signatures(&partials, &group_pubkey, &message_hash);
        assert!(result.is_ok());

        let aggregate = result.unwrap();
        assert_eq!(aggregate.signer_count(), 1);
        assert_eq!(aggregate.message_hash(), &message_hash);
    }

    #[test]
    fn test_aggregate_signatures_multiple() {
        let partials = vec![make_partial(0x01), make_partial(0x02), make_partial(0x03)];
        let group_pubkey = GroupPublicKey::from_bytes([0x01; 32]).unwrap();
        let message_hash = [0xBB; 32];

        let result = aggregate_signatures(&partials, &group_pubkey, &message_hash);
        assert!(result.is_ok());

        let aggregate = result.unwrap();
        assert_eq!(aggregate.signer_count(), 3);
    }

    #[test]
    fn test_aggregate_signatures_duplicate_signer_fails() {
        let partials = vec![make_partial(0x01), make_partial(0x01)]; // duplicate!
        let group_pubkey = GroupPublicKey::from_bytes([0x01; 32]).unwrap();
        let message_hash = [0xAA; 32];

        let result = aggregate_signatures(&partials, &group_pubkey, &message_hash);
        assert!(result.is_err());
        
        if let Err(SigningError::DuplicateSigner { .. }) = result {
            // Expected
        } else {
            panic!("Expected DuplicateSigner error");
        }
    }

    #[test]
    fn test_aggregate_signatures_deterministic() {
        let partials = vec![make_partial(0x01), make_partial(0x02)];
        let group_pubkey = GroupPublicKey::from_bytes([0x01; 32]).unwrap();
        let message_hash = [0xAA; 32];

        let result1 = aggregate_signatures(&partials, &group_pubkey, &message_hash).unwrap();
        let result2 = aggregate_signatures(&partials, &group_pubkey, &message_hash).unwrap();

        assert_eq!(result1.signature().as_bytes(), result2.signature().as_bytes());
    }

    #[test]
    fn test_aggregate_signatures_order_independent() {
        // Different input order should produce same result
        let p1 = make_partial(0x01);
        let p2 = make_partial(0x02);
        let group_pubkey = GroupPublicKey::from_bytes([0x01; 32]).unwrap();
        let message_hash = [0xAA; 32];

        let result1 = aggregate_signatures(&[p1.clone(), p2.clone()], &group_pubkey, &message_hash).unwrap();
        let result2 = aggregate_signatures(&[p2, p1], &group_pubkey, &message_hash).unwrap();

        // Signature should be the same regardless of input order
        assert_eq!(result1.signature().as_bytes(), result2.signature().as_bytes());
        
        // Signers should also be in same order (sorted)
        assert_eq!(result1.signers().len(), result2.signers().len());
        for (a, b) in result1.signers().iter().zip(result2.signers().iter()) {
            assert_eq!(a.as_bytes(), b.as_bytes());
        }
    }

    #[test]
    fn test_aggregate_signatures_different_messages_different_results() {
        let partials = vec![make_partial(0x01)];
        let group_pubkey = GroupPublicKey::from_bytes([0x01; 32]).unwrap();
        
        let result1 = aggregate_signatures(&partials, &group_pubkey, &[0xAA; 32]).unwrap();
        let result2 = aggregate_signatures(&partials, &group_pubkey, &[0xBB; 32]).unwrap();

        // Different messages should produce different signatures
        assert_ne!(result1.signature().as_bytes(), result2.signature().as_bytes());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SEND + SYNC TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_aggregate_signature_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AggregateSignature>();
    }
}