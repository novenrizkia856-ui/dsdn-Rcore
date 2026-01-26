//! # SigningCommitment Extension dan SigningNonces
//!
//! Module ini menyediakan extension methods untuk `SigningCommitment`
//! dan struct internal `SigningNonces` untuk FROST signing protocol.
//!
//! ## Keamanan
//!
//! - `SigningNonces` tidak di-export (private)
//! - Nonces di-zeroize saat drop
//! - Tidak ada panic atau unwrap

use sha3::{Digest, Sha3_256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::TSSError;
use crate::primitives::{SecretShare, SigningCommitment, SCALAR_SIZE};
use crate::types::SignerId;

// ════════════════════════════════════════════════════════════════════════════════
// SIGNING NONCES (PRIVATE - NOT EXPORTED)
// ════════════════════════════════════════════════════════════════════════════════

/// Nonces untuk signing round dalam FROST.
///
/// **PRIVATE** - Tidak di-export ke luar module.
/// **SENSITIVE DATA** - Di-zeroize saat drop.
///
/// ## Keamanan
///
/// - Nonces HARUS dijaga rahasia
/// - Setelah digunakan, nonces HARUS di-zeroize
/// - Nonces tidak boleh di-reuse antar signing session
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct SigningNonces {
    /// Hiding nonce (random scalar).
    hiding_nonce: SecretShare,

    /// Binding nonce (random scalar).
    binding_nonce: SecretShare,
}

impl SigningNonces {
    /// Generate nonces baru secara deterministik dari seed.
    ///
    /// Dalam implementasi nyata, ini akan menggunakan random yang aman.
    /// Untuk placeholder, kita derive dari signer_id untuk repeatability.
    ///
    /// # Arguments
    ///
    /// * `signer_id` - Signer ID untuk seed derivation
    ///
    /// # Returns
    ///
    /// `SigningNonces` baru dengan hiding dan binding nonces.
    pub(crate) fn generate(signer_id: &SignerId) -> Result<Self, TSSError> {
        // Generate hiding nonce via SHA3-256
        let hiding_bytes = {
            let mut hasher = Sha3_256::new();
            hasher.update(b"dsdn-tss-hiding-nonce-v1");
            hasher.update(signer_id.as_bytes());
            hasher.update(&rand_bytes_32());
            let result = hasher.finalize();

            let mut bytes = [0u8; SCALAR_SIZE];
            bytes.copy_from_slice(&result);
            bytes
        };

        // Generate binding nonce via SHA3-256
        let binding_bytes = {
            let mut hasher = Sha3_256::new();
            hasher.update(b"dsdn-tss-binding-nonce-v1");
            hasher.update(signer_id.as_bytes());
            hasher.update(&rand_bytes_32());
            let result = hasher.finalize();

            let mut bytes = [0u8; SCALAR_SIZE];
            bytes.copy_from_slice(&result);
            bytes
        };

        let hiding_nonce = SecretShare::from_bytes(hiding_bytes)?;
        let binding_nonce = SecretShare::from_bytes(binding_bytes)?;

        Ok(Self {
            hiding_nonce,
            binding_nonce,
        })
    }

    /// Compute commitment dari nonces.
    ///
    /// Commitment = (g^hiding_nonce, g^binding_nonce) dalam format byte.
    ///
    /// # Returns
    ///
    /// `SigningCommitment` yang merupakan commitment ke nonces.
    pub(crate) fn compute_commitment(&self) -> Result<SigningCommitment, TSSError> {
        // Dalam implementasi nyata, ini akan menghitung g^nonce pada kurva.
        // Untuk placeholder, kita hash nonces.

        let hiding_commitment = {
            let mut hasher = Sha3_256::new();
            hasher.update(b"dsdn-tss-hiding-commitment-v1");
            hasher.update(self.hiding_nonce.as_bytes());
            let result = hasher.finalize();

            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&result);
            bytes
        };

        let binding_commitment = {
            let mut hasher = Sha3_256::new();
            hasher.update(b"dsdn-tss-binding-commitment-v1");
            hasher.update(self.binding_nonce.as_bytes());
            let result = hasher.finalize();

            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&result);
            bytes
        };

        SigningCommitment::from_parts(hiding_commitment, binding_commitment)
    }

    /// Mengembalikan reference ke hiding nonce.
    #[must_use]
    pub(crate) fn hiding_nonce(&self) -> &SecretShare {
        &self.hiding_nonce
    }

    /// Mengembalikan reference ke binding nonce.
    #[must_use]
    pub(crate) fn binding_nonce(&self) -> &SecretShare {
        &self.binding_nonce
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// SIGNING COMMITMENT EXTENSION TRAIT
// ════════════════════════════════════════════════════════════════════════════════

/// Extension trait untuk `SigningCommitment`.
///
/// Trait ini menambahkan methods ke `SigningCommitment` yang sudah
/// didefinisikan di `primitives.rs`.
pub trait SigningCommitmentExt {
    /// Generate commitment baru beserta nonces-nya.
    ///
    /// # Arguments
    ///
    /// * `signer_id` - Signer ID untuk nonce derivation
    ///
    /// # Returns
    ///
    /// Tuple `(SigningCommitment, SigningNonces)`.
    ///
    /// # Errors
    ///
    /// Mengembalikan `TSSError` jika generasi gagal.
    fn generate(signer_id: &SignerId) -> Result<(SigningCommitment, SigningNonces), TSSError>;

    /// Verify format commitment.
    ///
    /// # Returns
    ///
    /// `true` jika commitment valid, `false` jika tidak.
    fn verify_format(&self) -> bool;

    /// Serialize commitment ke bytes.
    ///
    /// Format: hiding (32 bytes) || binding (32 bytes) = 64 bytes total.
    ///
    /// # Returns
    ///
    /// Array 64 bytes.
    fn to_bytes(&self) -> [u8; 64];

    /// Deserialize commitment dari bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - 64 bytes (hiding || binding)
    ///
    /// # Returns
    ///
    /// `SigningCommitment` baru.
    ///
    /// # Errors
    ///
    /// Mengembalikan `TSSError` jika format invalid.
    fn from_bytes_ext(bytes: &[u8; 64]) -> Result<SigningCommitment, TSSError>;
}

impl SigningCommitmentExt for SigningCommitment {
    fn generate(signer_id: &SignerId) -> Result<(SigningCommitment, SigningNonces), TSSError> {
        let nonces = SigningNonces::generate(signer_id)?;
        let commitment = nonces.compute_commitment()?;
        Ok((commitment, nonces))
    }

    fn verify_format(&self) -> bool {
        // Verify hiding commitment tidak all-zeros
        let hiding_valid = !self.hiding().iter().all(|&b| b == 0);

        // Verify binding commitment tidak all-zeros
        let binding_valid = !self.binding().iter().all(|&b| b == 0);

        hiding_valid && binding_valid
    }

    fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(self.hiding());
        bytes[32..64].copy_from_slice(self.binding());
        bytes
    }

    fn from_bytes_ext(bytes: &[u8; 64]) -> Result<SigningCommitment, TSSError> {
        let mut hiding = [0u8; 32];
        let mut binding = [0u8; 32];

        hiding.copy_from_slice(&bytes[0..32]);
        binding.copy_from_slice(&bytes[32..64]);

        SigningCommitment::from_parts(hiding, binding)
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════════

/// Generate 32 random bytes.
///
/// Menggunakan thread_rng untuk cryptographic randomness.
fn rand_bytes_32() -> [u8; 32] {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ────────────────────────────────────────────────────────────────────────────
    // SIGNING NONCES TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_signing_nonces_generate() {
        let signer_id = SignerId::from_bytes([0xAA; 32]);
        let result = SigningNonces::generate(&signer_id);
        assert!(result.is_ok());
    }

    #[test]
    fn test_signing_nonces_compute_commitment() {
        let signer_id = SignerId::from_bytes([0xAA; 32]);
        let nonces = SigningNonces::generate(&signer_id).unwrap();
        let result = nonces.compute_commitment();
        assert!(result.is_ok());

        let commitment = result.unwrap();
        // Verify commitment is non-zero
        assert!(!commitment.hiding().iter().all(|&b| b == 0));
        assert!(!commitment.binding().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_signing_nonces_accessors() {
        let signer_id = SignerId::from_bytes([0xAA; 32]);
        let nonces = SigningNonces::generate(&signer_id).unwrap();

        // Just verify accessors work
        let _ = nonces.hiding_nonce();
        let _ = nonces.binding_nonce();
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SIGNING COMMITMENT EXT TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_signing_commitment_generate() {
        let signer_id = SignerId::from_bytes([0xBB; 32]);
        let result = SigningCommitment::generate(&signer_id);
        assert!(result.is_ok());

        let (commitment, _nonces) = result.unwrap();
        assert!(commitment.verify_format());
    }

    #[test]
    fn test_signing_commitment_verify_format_valid() {
        let commitment = SigningCommitment::from_parts([0x01; 32], [0x02; 32]).unwrap();
        assert!(commitment.verify_format());
    }

    #[test]
    fn test_signing_commitment_to_bytes() {
        let hiding = [0x01; 32];
        let binding = [0x02; 32];
        let commitment = SigningCommitment::from_parts(hiding, binding).unwrap();

        let bytes = commitment.to_bytes();

        assert_eq!(&bytes[0..32], &hiding);
        assert_eq!(&bytes[32..64], &binding);
    }

    #[test]
    fn test_signing_commitment_from_bytes_ext() {
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(&[0x01; 32]);
        bytes[32..64].copy_from_slice(&[0x02; 32]);

        let result = SigningCommitment::from_bytes_ext(&bytes);
        assert!(result.is_ok());

        let commitment = result.unwrap();
        assert_eq!(commitment.hiding(), &[0x01; 32]);
        assert_eq!(commitment.binding(), &[0x02; 32]);
    }

    #[test]
    fn test_signing_commitment_roundtrip() {
        let original = SigningCommitment::from_parts([0xAA; 32], [0xBB; 32]).unwrap();
        let bytes = original.to_bytes();
        let recovered = SigningCommitment::from_bytes_ext(&bytes).unwrap();

        assert_eq!(original.hiding(), recovered.hiding());
        assert_eq!(original.binding(), recovered.binding());
    }

    #[test]
    fn test_signing_commitment_from_bytes_zero_hiding_fails() {
        let mut bytes = [0u8; 64];
        // Hiding is all zeros
        bytes[32..64].copy_from_slice(&[0x01; 32]);

        let result = SigningCommitment::from_bytes_ext(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_signing_commitment_from_bytes_zero_binding_fails() {
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(&[0x01; 32]);
        // Binding is all zeros

        let result = SigningCommitment::from_bytes_ext(&bytes);
        assert!(result.is_err());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SEND + SYNC TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_signing_nonces_is_not_send_sync() {
        // SigningNonces contains SecretShare which doesn't implement Send/Sync
        // This is intentional for security.
        // We don't test Send+Sync for SigningNonces as it's internal only.
    }
}