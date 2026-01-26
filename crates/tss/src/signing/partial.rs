//! # Partial Signature
//!
//! Module ini menyediakan `PartialSignature` struct dan helper functions
//! untuk FROST threshold signing.
//!
//! ## Format Serialization
//!
//! | Field | Offset | Size | Description |
//! |-------|--------|------|-------------|
//! | signer_id | 0 | 32 | Signer identifier |
//! | signature_share | 32 | 32 | Partial signature (scalar) |
//! | commitment.hiding | 64 | 32 | Hiding commitment |
//! | commitment.binding | 96 | 32 | Binding commitment |
//! | **Total** | | 128 | |

use std::collections::HashMap;

use sha3::{Digest, Sha3_256};

use crate::error::SigningError;
use crate::primitives::{FrostSignatureShare, GroupPublicKey, SigningCommitment, SCALAR_SIZE};
use crate::types::SignerId;

use super::commitment::SigningCommitmentExt;

// ════════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════════

/// Size of serialized PartialSignature in bytes.
const PARTIAL_SIGNATURE_SIZE: usize = 128; // 32 + 32 + 32 + 32

// ════════════════════════════════════════════════════════════════════════════════
// PARTIAL SIGNATURE
// ════════════════════════════════════════════════════════════════════════════════

/// Partial signature dari satu signer dalam FROST signing.
///
/// `PartialSignature` mengenkapsulasi signature share, signer identifier,
/// dan commitment yang digunakan dalam signing round.
///
/// ## Format
///
/// - `signer_id`: Identifier signer (32 bytes)
/// - `signature_share`: Partial signature scalar (32 bytes)
/// - `commitment`: SigningCommitment (64 bytes)
///
/// Total: 128 bytes saat serialized.
#[derive(Debug, Clone)]
pub struct PartialSignature {
    /// Identifier signer yang menghasilkan partial signature ini.
    signer_id: SignerId,

    /// Signature share (scalar value).
    signature_share: FrostSignatureShare,

    /// Commitment yang digunakan dalam signing round.
    commitment: SigningCommitment,
}

impl PartialSignature {
    /// Membuat `PartialSignature` baru.
    ///
    /// # Arguments
    ///
    /// * `signer_id` - Identifier dari signer
    /// * `signature_share` - Signature share
    /// * `commitment` - Signing commitment
    #[must_use]
    pub fn new(
        signer_id: SignerId,
        signature_share: FrostSignatureShare,
        commitment: SigningCommitment,
    ) -> Self {
        Self {
            signer_id,
            signature_share,
            commitment,
        }
    }

    /// Mengembalikan reference ke signer ID.
    #[must_use]
    pub fn signer_id(&self) -> &SignerId {
        &self.signer_id
    }

    /// Mengembalikan reference ke signature share.
    #[must_use]
    pub fn signature_share(&self) -> &FrostSignatureShare {
        &self.signature_share
    }

    /// Mengembalikan reference ke commitment.
    #[must_use]
    pub fn commitment(&self) -> &SigningCommitment {
        &self.commitment
    }

    /// Serialize partial signature ke bytes.
    ///
    /// Format: signer_id (32) || signature_share (32) || hiding (32) || binding (32)
    ///
    /// # Returns
    ///
    /// `Vec<u8>` dengan panjang 128 bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(PARTIAL_SIGNATURE_SIZE);

        // Signer ID (32 bytes)
        bytes.extend_from_slice(self.signer_id.as_bytes());

        // Signature share (32 bytes)
        bytes.extend_from_slice(self.signature_share.as_bytes());

        // Commitment (64 bytes)
        bytes.extend_from_slice(&self.commitment.to_bytes());

        bytes
    }

    /// Deserialize partial signature dari bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Byte slice dengan panjang minimal 128 bytes
    ///
    /// # Errors
    ///
    /// Mengembalikan `SigningError::InvalidPartialSignature` jika:
    /// - Panjang bytes kurang dari 128
    /// - Format data tidak valid
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SigningError> {
        // Validate length
        if bytes.len() < PARTIAL_SIGNATURE_SIZE {
            return Err(SigningError::InvalidPartialSignature {
                signer: SignerId::from_bytes([0u8; 32]),
                reason: format!(
                    "insufficient bytes: expected {}, got {}",
                    PARTIAL_SIGNATURE_SIZE,
                    bytes.len()
                ),
            });
        }

        // Parse signer_id (bytes 0..32)
        let mut signer_id_bytes = [0u8; 32];
        signer_id_bytes.copy_from_slice(&bytes[0..32]);
        let signer_id = SignerId::from_bytes(signer_id_bytes);

        // Parse signature_share (bytes 32..64)
        let mut share_bytes = [0u8; SCALAR_SIZE];
        share_bytes.copy_from_slice(&bytes[32..64]);
        let signature_share = FrostSignatureShare::from_bytes(share_bytes).map_err(|e| {
            SigningError::InvalidPartialSignature {
                signer: signer_id.clone(),
                reason: format!("invalid signature share: {}", e),
            }
        })?;

        // Parse commitment (bytes 64..128)
        let mut commitment_bytes = [0u8; 64];
        commitment_bytes.copy_from_slice(&bytes[64..128]);
        let commitment =
            SigningCommitment::from_bytes_ext(&commitment_bytes).map_err(|e| {
                SigningError::InvalidPartialSignature {
                    signer: signer_id.clone(),
                    reason: format!("invalid commitment: {}", e),
                }
            })?;

        Ok(Self {
            signer_id,
            signature_share,
            commitment,
        })
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS (PURE, DETERMINISTIC)
// ════════════════════════════════════════════════════════════════════════════════

/// Compute binding factor untuk signer.
///
/// Binding factor adalah nilai yang digunakan untuk mengikat commitment
/// signer ke message dan commitments lainnya.
///
/// Formula (placeholder):
/// binding_factor = H("binding" || signer_id || message_hash || commitments_hash)
///
/// # Arguments
///
/// * `signer_id` - Signer ID
/// * `message_hash` - Hash dari message yang di-sign
/// * `commitments` - Slice of (SignerId, SigningCommitment) pairs, HARUS sorted by SignerId
///
/// # Returns
///
/// 32-byte binding factor.
///
/// # Panics
///
/// Tidak panic.
#[must_use]
pub fn compute_binding_factor(
    signer_id: &SignerId,
    message_hash: &[u8; 32],
    commitments: &[(SignerId, SigningCommitment)],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();

    // Domain separator
    hasher.update(b"dsdn-tss-binding-factor-v1");

    // Signer ID
    hasher.update(signer_id.as_bytes());

    // Message hash
    hasher.update(message_hash);

    // Commitments - MUST be processed in deterministic order
    // Caller MUST provide sorted commitments
    for (sid, commitment) in commitments {
        hasher.update(sid.as_bytes());
        hasher.update(commitment.hiding());
        hasher.update(commitment.binding());
    }

    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    bytes
}

/// Compute group commitment dari semua commitments dan binding factors.
///
/// Group commitment adalah kombinasi dari semua individual commitments,
/// weighted by binding factors.
///
/// Formula (placeholder):
/// group_commitment = H("group" || sum(hiding_i + binding_i * rho_i))
///
/// # Arguments
///
/// * `commitments` - Slice of (SignerId, SigningCommitment) pairs, HARUS sorted by SignerId
/// * `binding_factors` - Map dari SignerId ke binding factor
///
/// # Returns
///
/// 32-byte group commitment.
///
/// # Note
///
/// Dalam implementasi nyata, ini akan melakukan point addition pada kurva.
/// Placeholder ini menggunakan hash untuk determinism.
#[must_use]
pub fn compute_group_commitment(
    commitments: &[(SignerId, SigningCommitment)],
    binding_factors: &HashMap<SignerId, [u8; 32]>,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();

    // Domain separator
    hasher.update(b"dsdn-tss-group-commitment-v1");

    // Process commitments in deterministic order (caller provides sorted slice)
    for (signer_id, commitment) in commitments {
        hasher.update(signer_id.as_bytes());
        hasher.update(commitment.hiding());
        hasher.update(commitment.binding());

        // Include binding factor if available
        if let Some(bf) = binding_factors.get(signer_id) {
            hasher.update(bf);
        }
    }

    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    bytes
}

/// Compute challenge untuk Schnorr signature.
///
/// Challenge = H(R || P || m) dalam Schnorr signature.
///
/// # Arguments
///
/// * `group_commitment` - Group commitment R (32 bytes)
/// * `group_pubkey` - Group public key P
/// * `message_hash` - Hash dari message m
///
/// # Returns
///
/// 32-byte challenge scalar.
#[must_use]
pub fn compute_challenge(
    group_commitment: &[u8; 32],
    group_pubkey: &GroupPublicKey,
    message_hash: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();

    // Domain separator
    hasher.update(b"dsdn-tss-challenge-v1");

    // R (group commitment)
    hasher.update(group_commitment);

    // P (group public key)
    hasher.update(group_pubkey.as_bytes());

    // m (message hash)
    hasher.update(message_hash);

    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    bytes
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ────────────────────────────────────────────────────────────────────────────
    // HELPER FUNCTIONS
    // ────────────────────────────────────────────────────────────────────────────

    fn make_partial_signature() -> PartialSignature {
        let signer_id = SignerId::from_bytes([0xAA; 32]);
        let signature_share = FrostSignatureShare::from_bytes([0x01; 32]).unwrap();
        let commitment = SigningCommitment::from_parts([0x02; 32], [0x03; 32]).unwrap();
        PartialSignature::new(signer_id, signature_share, commitment)
    }

    // ────────────────────────────────────────────────────────────────────────────
    // PARTIAL SIGNATURE TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_partial_signature_new() {
        let partial = make_partial_signature();

        assert_eq!(partial.signer_id().as_bytes(), &[0xAA; 32]);
        assert_eq!(partial.signature_share().as_bytes(), &[0x01; 32]);
        assert_eq!(partial.commitment().hiding(), &[0x02; 32]);
        assert_eq!(partial.commitment().binding(), &[0x03; 32]);
    }

    #[test]
    fn test_partial_signature_to_bytes() {
        let partial = make_partial_signature();
        let bytes = partial.to_bytes();

        assert_eq!(bytes.len(), PARTIAL_SIGNATURE_SIZE);
        assert_eq!(&bytes[0..32], &[0xAA; 32]); // signer_id
        assert_eq!(&bytes[32..64], &[0x01; 32]); // signature_share
        assert_eq!(&bytes[64..96], &[0x02; 32]); // hiding
        assert_eq!(&bytes[96..128], &[0x03; 32]); // binding
    }

    #[test]
    fn test_partial_signature_from_bytes() {
        let mut bytes = vec![0u8; PARTIAL_SIGNATURE_SIZE];
        bytes[0..32].copy_from_slice(&[0xBB; 32]); // signer_id
        bytes[32..64].copy_from_slice(&[0x01; 32]); // signature_share
        bytes[64..96].copy_from_slice(&[0x04; 32]); // hiding
        bytes[96..128].copy_from_slice(&[0x05; 32]); // binding

        let result = PartialSignature::from_bytes(&bytes);
        assert!(result.is_ok());

        let partial = result.unwrap();
        assert_eq!(partial.signer_id().as_bytes(), &[0xBB; 32]);
        assert_eq!(partial.signature_share().as_bytes(), &[0x01; 32]);
        assert_eq!(partial.commitment().hiding(), &[0x04; 32]);
        assert_eq!(partial.commitment().binding(), &[0x05; 32]);
    }

    #[test]
    fn test_partial_signature_roundtrip() {
        let original = make_partial_signature();
        let bytes = original.to_bytes();
        let recovered = PartialSignature::from_bytes(&bytes).unwrap();

        assert_eq!(original.signer_id(), recovered.signer_id());
        assert_eq!(original.signature_share(), recovered.signature_share());
        assert_eq!(original.commitment().hiding(), recovered.commitment().hiding());
        assert_eq!(original.commitment().binding(), recovered.commitment().binding());
    }

    #[test]
    fn test_partial_signature_from_bytes_insufficient_length() {
        let bytes = vec![0u8; 64]; // Only 64 bytes, need 128
        let result = PartialSignature::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_partial_signature_from_bytes_zero_share_fails() {
        let mut bytes = vec![0u8; PARTIAL_SIGNATURE_SIZE];
        bytes[0..32].copy_from_slice(&[0xAA; 32]); // signer_id
        // signature_share is all zeros (invalid)
        bytes[64..96].copy_from_slice(&[0x01; 32]); // hiding
        bytes[96..128].copy_from_slice(&[0x02; 32]); // binding

        let result = PartialSignature::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_partial_signature_from_bytes_zero_commitment_fails() {
        let mut bytes = vec![0u8; PARTIAL_SIGNATURE_SIZE];
        bytes[0..32].copy_from_slice(&[0xAA; 32]); // signer_id
        bytes[32..64].copy_from_slice(&[0x01; 32]); // signature_share
        // hiding is all zeros (invalid)
        bytes[96..128].copy_from_slice(&[0x02; 32]); // binding

        let result = PartialSignature::from_bytes(&bytes);
        assert!(result.is_err());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // BINDING FACTOR TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_compute_binding_factor_deterministic() {
        let signer_id = SignerId::from_bytes([0x01; 32]);
        let message_hash = [0xAA; 32];
        let commitments = vec![
            (
                SignerId::from_bytes([0x01; 32]),
                SigningCommitment::from_parts([0x11; 32], [0x12; 32]).unwrap(),
            ),
            (
                SignerId::from_bytes([0x02; 32]),
                SigningCommitment::from_parts([0x21; 32], [0x22; 32]).unwrap(),
            ),
        ];

        let bf1 = compute_binding_factor(&signer_id, &message_hash, &commitments);
        let bf2 = compute_binding_factor(&signer_id, &message_hash, &commitments);

        assert_eq!(bf1, bf2);
    }

    #[test]
    fn test_compute_binding_factor_different_signers() {
        let signer1 = SignerId::from_bytes([0x01; 32]);
        let signer2 = SignerId::from_bytes([0x02; 32]);
        let message_hash = [0xAA; 32];
        let commitments = vec![];

        let bf1 = compute_binding_factor(&signer1, &message_hash, &commitments);
        let bf2 = compute_binding_factor(&signer2, &message_hash, &commitments);

        assert_ne!(bf1, bf2);
    }

    #[test]
    fn test_compute_binding_factor_different_messages() {
        let signer_id = SignerId::from_bytes([0x01; 32]);
        let message1 = [0xAA; 32];
        let message2 = [0xBB; 32];
        let commitments = vec![];

        let bf1 = compute_binding_factor(&signer_id, &message1, &commitments);
        let bf2 = compute_binding_factor(&signer_id, &message2, &commitments);

        assert_ne!(bf1, bf2);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // GROUP COMMITMENT TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_compute_group_commitment_deterministic() {
        let commitments = vec![
            (
                SignerId::from_bytes([0x01; 32]),
                SigningCommitment::from_parts([0x11; 32], [0x12; 32]).unwrap(),
            ),
            (
                SignerId::from_bytes([0x02; 32]),
                SigningCommitment::from_parts([0x21; 32], [0x22; 32]).unwrap(),
            ),
        ];

        let mut binding_factors = HashMap::new();
        binding_factors.insert(SignerId::from_bytes([0x01; 32]), [0xF1; 32]);
        binding_factors.insert(SignerId::from_bytes([0x02; 32]), [0xF2; 32]);

        let gc1 = compute_group_commitment(&commitments, &binding_factors);
        let gc2 = compute_group_commitment(&commitments, &binding_factors);

        assert_eq!(gc1, gc2);
    }

    #[test]
    fn test_compute_group_commitment_empty() {
        let commitments: Vec<(SignerId, SigningCommitment)> = vec![];
        let binding_factors = HashMap::new();

        let gc = compute_group_commitment(&commitments, &binding_factors);

        // Should still produce a valid hash
        assert!(!gc.iter().all(|&b| b == 0));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // CHALLENGE TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_compute_challenge_deterministic() {
        let group_commitment = [0xAA; 32];
        let group_pubkey = GroupPublicKey::from_bytes([0xBB; 32]).unwrap();
        let message_hash = [0xCC; 32];

        let c1 = compute_challenge(&group_commitment, &group_pubkey, &message_hash);
        let c2 = compute_challenge(&group_commitment, &group_pubkey, &message_hash);

        assert_eq!(c1, c2);
    }

    #[test]
    fn test_compute_challenge_different_commitment() {
        let gc1 = [0xAA; 32];
        let gc2 = [0xBB; 32];
        let group_pubkey = GroupPublicKey::from_bytes([0xCC; 32]).unwrap();
        let message_hash = [0xDD; 32];

        let c1 = compute_challenge(&gc1, &group_pubkey, &message_hash);
        let c2 = compute_challenge(&gc2, &group_pubkey, &message_hash);

        assert_ne!(c1, c2);
    }

    #[test]
    fn test_compute_challenge_different_pubkey() {
        let group_commitment = [0xAA; 32];
        let pk1 = GroupPublicKey::from_bytes([0xBB; 32]).unwrap();
        let pk2 = GroupPublicKey::from_bytes([0xCC; 32]).unwrap();
        let message_hash = [0xDD; 32];

        let c1 = compute_challenge(&group_commitment, &pk1, &message_hash);
        let c2 = compute_challenge(&group_commitment, &pk2, &message_hash);

        assert_ne!(c1, c2);
    }

    #[test]
    fn test_compute_challenge_different_message() {
        let group_commitment = [0xAA; 32];
        let group_pubkey = GroupPublicKey::from_bytes([0xBB; 32]).unwrap();
        let m1 = [0xCC; 32];
        let m2 = [0xDD; 32];

        let c1 = compute_challenge(&group_commitment, &group_pubkey, &m1);
        let c2 = compute_challenge(&group_commitment, &group_pubkey, &m2);

        assert_ne!(c1, c2);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SEND + SYNC TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_partial_signature_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PartialSignature>();
    }
}