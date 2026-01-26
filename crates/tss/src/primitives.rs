//! # TSS Cryptographic Primitives
//!
//! Module ini menyediakan cryptographic primitive types untuk FROST TSS:
//! - `GroupPublicKey`: Public key hasil DKG (shared by all participants)
//! - `ParticipantPublicKey`: Public key individual participant
//! - `SecretShare`: Secret share dari DKG (SENSITIVE - akan di-zeroize)
//! - `FrostSignature`: Aggregate signature (R || s format)
//! - `FrostSignatureShare`: Partial signature dari signer
//! - `SigningCommitment`: Commitment untuk signing round
//! - `EncryptionKey`: Key untuk enkripsi share (SENSITIVE - akan di-zeroize)
//!
//! ## Keamanan
//!
//! Types yang mengandung secret data (`SecretShare`, `EncryptionKey`):
//! - Menggunakan `zeroize` untuk membersihkan memory saat drop
//! - TIDAK implement `Debug`, `Serialize`, atau `Deserialize`
//! - TIDAK implement `Copy` untuk mencegah accidental duplication
//!
//! ## Format
//!
//! | Type | Format | Ukuran |
//! |------|--------|--------|
//! | `GroupPublicKey` | Compressed point | 32 bytes |
//! | `ParticipantPublicKey` | Compressed point | 32 bytes |
//! | `SecretShare` | Scalar | 32 bytes |
//! | `FrostSignature` | R ‖ s | 64 bytes |
//! | `FrostSignatureShare` | Partial scalar | 32 bytes |
//! | `SigningCommitment` | hiding ‖ binding | 64 bytes |
//! | `EncryptionKey` | Symmetric key | 32 bytes |

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha3::{Digest, Sha3_256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::TSSError;

// ════════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════════

/// Ukuran public key dalam bytes (compressed point).
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Ukuran scalar dalam bytes.
pub const SCALAR_SIZE: usize = 32;

/// Ukuran signature dalam bytes (R || s).
pub const SIGNATURE_SIZE: usize = 64;

// ════════════════════════════════════════════════════════════════════════════════
// GROUP PUBLIC KEY
// ════════════════════════════════════════════════════════════════════════════════

/// Public key hasil Distributed Key Generation.
///
/// `GroupPublicKey` merepresentasikan shared public key yang dihasilkan
/// oleh DKG ceremony. Semua participants memiliki `GroupPublicKey` yang sama,
/// dan digunakan untuk verifikasi aggregate signatures.
///
/// ## Format
///
/// Compressed elliptic curve point (32 bytes).
/// Byte pertama menentukan parity dari y-coordinate.
///
/// ## Contoh
///
/// ```rust
/// use dsdn_tss::GroupPublicKey;
///
/// let bytes = [0x02; 32]; // Example compressed point
/// let pubkey = GroupPublicKey::from_bytes(bytes).unwrap();
/// assert_eq!(pubkey.as_bytes(), &bytes);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupPublicKey([u8; PUBLIC_KEY_SIZE]);

impl GroupPublicKey {
    /// Membuat `GroupPublicKey` dari bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - 32 bytes representing compressed point
    ///
    /// # Errors
    ///
    /// Mengembalikan `TSSError::Crypto` jika format tidak valid.
    pub fn from_bytes(bytes: [u8; PUBLIC_KEY_SIZE]) -> Result<Self, TSSError> {
        let key = Self(bytes);
        key.verify_format()?;
        Ok(key)
    }

    /// Mengembalikan reference ke inner bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.0
    }

    /// Memverifikasi format public key.
    ///
    /// Compressed point harus memiliki prefix byte yang valid:
    /// - 0x02: y-coordinate genap
    /// - 0x03: y-coordinate ganjil
    /// - 0x00: identity point (special case, ditolak)
    ///
    /// # Errors
    ///
    /// Mengembalikan `TSSError::Crypto` jika format tidak valid.
    pub fn verify_format(&self) -> Result<(), TSSError> {
        // Check for all zeros (identity point - not valid as group key)
        if self.0.iter().all(|&b| b == 0) {
            return Err(TSSError::Crypto(
                "GroupPublicKey: identity point is not valid".to_string(),
            ));
        }

        // In a real implementation, we would verify this is a valid curve point.
        // For now, we just ensure it's not all zeros.
        // The actual curve point validation will happen in the crypto layer.
        Ok(())
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// PARTICIPANT PUBLIC KEY
// ════════════════════════════════════════════════════════════════════════════════

/// Public key individual participant dalam DKG.
///
/// Setiap participant dalam DKG memiliki `ParticipantPublicKey` yang unik,
/// digunakan untuk verifikasi partial signatures dan routing encrypted shares.
///
/// ## Format
///
/// Compressed elliptic curve point (32 bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParticipantPublicKey([u8; PUBLIC_KEY_SIZE]);

impl ParticipantPublicKey {
    /// Membuat `ParticipantPublicKey` dari bytes.
    ///
    /// # Errors
    ///
    /// Mengembalikan `TSSError::Crypto` jika format tidak valid.
    pub fn from_bytes(bytes: [u8; PUBLIC_KEY_SIZE]) -> Result<Self, TSSError> {
        // Check for all zeros (identity point - not valid)
        if bytes.iter().all(|&b| b == 0) {
            return Err(TSSError::Crypto(
                "ParticipantPublicKey: identity point is not valid".to_string(),
            ));
        }

        Ok(Self(bytes))
    }

    /// Mengembalikan reference ke inner bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.0
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// SECRET SHARE
// ════════════════════════════════════════════════════════════════════════════════

/// Secret share dari Distributed Key Generation.
///
/// **SENSITIVE DATA** - Di-zeroize saat drop.
///
/// `SecretShare` merepresentasikan bagian dari secret key yang dimiliki
/// oleh satu participant. Kombinasi t shares (threshold) dapat merekonstruksi
/// signing capability, tetapi tidak mengungkap full secret key.
///
/// ## Keamanan
///
/// - TIDAK implement `Debug` untuk mencegah logging
/// - TIDAK implement `Serialize`/`Deserialize` untuk mencegah persistence
/// - TIDAK implement `Copy` untuk mencegah duplication
/// - Implement `Zeroize` dan `ZeroizeOnDrop` untuk secure cleanup
///
/// ## Format
///
/// Scalar field element (32 bytes, little-endian).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretShare([u8; SCALAR_SIZE]);

impl SecretShare {
    /// Membuat `SecretShare` dari bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - 32 bytes representing scalar
    ///
    /// # Errors
    ///
    /// Mengembalikan `TSSError::Crypto` jika scalar tidak valid.
    pub fn from_bytes(bytes: [u8; SCALAR_SIZE]) -> Result<Self, TSSError> {
        // Check for all zeros (invalid scalar)
        if bytes.iter().all(|&b| b == 0) {
            return Err(TSSError::Crypto(
                "SecretShare: zero scalar is not valid".to_string(),
            ));
        }

        Ok(Self(bytes))
    }

    /// Mengembalikan reference ke inner bytes.
    ///
    /// **WARNING**: Handle dengan hati-hati untuk mencegah kebocoran.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SCALAR_SIZE] {
        &self.0
    }
}

// SecretShare TIDAK implement Debug, Copy, Serialize, Deserialize
// untuk keamanan

// ════════════════════════════════════════════════════════════════════════════════
// FROST SIGNATURE
// ════════════════════════════════════════════════════════════════════════════════

/// Aggregate signature hasil threshold signing.
///
/// `FrostSignature` adalah Schnorr signature dalam format (R, s)
/// dimana R adalah commitment point dan s adalah scalar response.
///
/// ## Format
///
/// | Offset | Size | Field |
/// |--------|------|-------|
/// | 0 | 32 | R (compressed point) |
/// | 32 | 32 | s (scalar) |
///
/// Total: 64 bytes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrostSignature([u8; SIGNATURE_SIZE]);

impl Serialize for FrostSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for FrostSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FrostSignatureVisitor;

        impl<'de> Visitor<'de> for FrostSignatureVisitor {
            type Value = FrostSignature;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("64 bytes for FrostSignature")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if v.len() != SIGNATURE_SIZE {
                    return Err(E::invalid_length(v.len(), &self));
                }
                let mut bytes = [0u8; SIGNATURE_SIZE];
                bytes.copy_from_slice(v);
                Ok(FrostSignature(bytes))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let mut bytes = [0u8; SIGNATURE_SIZE];
                for (i, byte) in bytes.iter_mut().enumerate() {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(i, &self))?;
                }
                Ok(FrostSignature(bytes))
            }
        }

        deserializer.deserialize_bytes(FrostSignatureVisitor)
    }
}

impl FrostSignature {
    /// Membuat `FrostSignature` dari bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - 64 bytes (R || s)
    ///
    /// # Errors
    ///
    /// Mengembalikan `TSSError::Crypto` jika format tidak valid.
    pub fn from_bytes(bytes: [u8; SIGNATURE_SIZE]) -> Result<Self, TSSError> {
        // Basic validation: R component shouldn't be all zeros
        let r = &bytes[0..32];
        if r.iter().all(|&b| b == 0) {
            return Err(TSSError::Crypto(
                "FrostSignature: R component cannot be zero".to_string(),
            ));
        }

        Ok(Self(bytes))
    }

    /// Mengembalikan reference ke inner bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SIGNATURE_SIZE] {
        &self.0
    }

    /// Mengembalikan R component (commitment point).
    #[must_use]
    pub fn r_component(&self) -> &[u8; 32] {
        // SAFETY: self.0[0..32] is always 32 bytes
        self.0[0..32].try_into().expect("slice is exactly 32 bytes")
    }

    /// Mengembalikan s component (scalar response).
    #[must_use]
    pub fn s_component(&self) -> &[u8; 32] {
        // SAFETY: self.0[32..64] is always 32 bytes
        self.0[32..64].try_into().expect("slice is exactly 32 bytes")
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// FROST SIGNATURE SHARE
// ════════════════════════════════════════════════════════════════════════════════

/// Partial signature dari signer dalam threshold signing.
///
/// `FrostSignatureShare` adalah kontribusi signature dari satu signer.
/// Setelah threshold shares dikumpulkan, mereka di-aggregate menjadi
/// `FrostSignature`.
///
/// ## Format
///
/// Scalar field element (32 bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrostSignatureShare([u8; SCALAR_SIZE]);

impl FrostSignatureShare {
    /// Membuat `FrostSignatureShare` dari bytes.
    ///
    /// # Errors
    ///
    /// Mengembalikan `TSSError::Crypto` jika scalar tidak valid.
    pub fn from_bytes(bytes: [u8; SCALAR_SIZE]) -> Result<Self, TSSError> {
        // Signature share of zero is technically valid in some edge cases,
        // but we reject it for safety
        if bytes.iter().all(|&b| b == 0) {
            return Err(TSSError::Crypto(
                "FrostSignatureShare: zero share is not valid".to_string(),
            ));
        }

        Ok(Self(bytes))
    }

    /// Mengembalikan reference ke inner bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SCALAR_SIZE] {
        &self.0
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// SIGNING COMMITMENT
// ════════════════════════════════════════════════════════════════════════════════

/// Commitment untuk signing round dalam FROST.
///
/// Setiap signer menghasilkan `SigningCommitment` yang terdiri dari
/// dua nonce commitments: hiding dan binding.
///
/// ## Format
///
/// | Field | Size | Description |
/// |-------|------|-------------|
/// | hiding | 32 | Hiding nonce commitment |
/// | binding | 32 | Binding nonce commitment |
///
/// Total: 64 bytes logically, stored as two separate 32-byte arrays.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningCommitment {
    hiding: [u8; 32],
    binding: [u8; 32],
}

impl SigningCommitment {
    /// Membuat `SigningCommitment` dari hiding dan binding components.
    ///
    /// # Arguments
    ///
    /// * `hiding` - 32 bytes hiding nonce commitment
    /// * `binding` - 32 bytes binding nonce commitment
    ///
    /// # Errors
    ///
    /// Mengembalikan `TSSError::Crypto` jika salah satu component tidak valid.
    pub fn from_parts(hiding: [u8; 32], binding: [u8; 32]) -> Result<Self, TSSError> {
        // Commitments shouldn't be zero (would indicate degenerate nonces)
        if hiding.iter().all(|&b| b == 0) {
            return Err(TSSError::Crypto(
                "SigningCommitment: hiding commitment cannot be zero".to_string(),
            ));
        }

        if binding.iter().all(|&b| b == 0) {
            return Err(TSSError::Crypto(
                "SigningCommitment: binding commitment cannot be zero".to_string(),
            ));
        }

        Ok(Self { hiding, binding })
    }

    /// Mengembalikan hiding commitment.
    #[must_use]
    pub const fn hiding(&self) -> &[u8; 32] {
        &self.hiding
    }

    /// Mengembalikan binding commitment.
    #[must_use]
    pub const fn binding(&self) -> &[u8; 32] {
        &self.binding
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// ENCRYPTION KEY
// ════════════════════════════════════════════════════════════════════════════════

/// Key untuk enkripsi secret shares.
///
/// **SENSITIVE DATA** - Di-zeroize saat drop.
///
/// `EncryptionKey` digunakan untuk mengenkripsi `SecretShare` saat
/// dikirim antar participants dalam DKG round 2.
///
/// ## Keamanan
///
/// - TIDAK implement `Debug` untuk mencegah logging
/// - TIDAK implement `Serialize`/`Deserialize`
/// - Implement `Zeroize` dan `ZeroizeOnDrop`
///
/// ## Derivasi
///
/// Key dapat diderivasi dari shared secret (ECDH) menggunakan SHA3-256.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EncryptionKey([u8; 32]);

impl EncryptionKey {
    /// Membuat `EncryptionKey` dari bytes.
    ///
    /// # Errors
    ///
    /// Mengembalikan `TSSError::Crypto` jika key tidak valid.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, TSSError> {
        // Zero key is not valid
        if bytes.iter().all(|&b| b == 0) {
            return Err(TSSError::Crypto(
                "EncryptionKey: zero key is not valid".to_string(),
            ));
        }

        Ok(Self(bytes))
    }

    /// Derive encryption key dari shared secret.
    ///
    /// Menggunakan SHA3-256 untuk key derivation.
    ///
    /// # Arguments
    ///
    /// * `secret` - Shared secret bytes (e.g., from ECDH)
    ///
    /// # Errors
    ///
    /// Mengembalikan `TSSError::Crypto` jika secret kosong atau hasil derivasi tidak valid.
    pub fn derive_from_shared_secret(secret: &[u8]) -> Result<Self, TSSError> {
        if secret.is_empty() {
            return Err(TSSError::Crypto(
                "EncryptionKey: cannot derive from empty secret".to_string(),
            ));
        }

        let mut hasher = Sha3_256::new();
        hasher.update(b"dsdn-tss-encryption-key-v1");
        hasher.update(secret);
        let result = hasher.finalize();

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&result);

        // SHA3-256 output will never be all zeros for non-empty input
        Ok(Self(key_bytes))
    }

    /// Mengembalikan reference ke inner bytes.
    ///
    /// **WARNING**: Handle dengan hati-hati untuk mencegah kebocoran.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// EncryptionKey TIDAK implement Debug, Serialize, Deserialize
// untuk keamanan

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ────────────────────────────────────────────────────────────────────────────
    // GROUP PUBLIC KEY TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_group_public_key_from_bytes_valid() {
        let bytes = [0x02; 32];
        let result = GroupPublicKey::from_bytes(bytes);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_bytes(), &bytes);
    }

    #[test]
    fn test_group_public_key_from_bytes_zero_rejected() {
        let bytes = [0x00; 32];
        let result = GroupPublicKey::from_bytes(bytes);
        assert!(result.is_err());
        match result {
            Err(TSSError::Crypto(msg)) => {
                assert!(msg.contains("identity point"));
            }
            _ => panic!("expected TSSError::Crypto"),
        }
    }

    #[test]
    fn test_group_public_key_verify_format() {
        let bytes = [0x03; 32];
        let key = GroupPublicKey::from_bytes(bytes).unwrap();
        assert!(key.verify_format().is_ok());
    }

    #[test]
    fn test_group_public_key_serialize_deserialize() {
        let bytes = [0xAB; 32];
        let key = GroupPublicKey::from_bytes(bytes).unwrap();
        let serialized = serde_json::to_string(&key).unwrap();
        let deserialized: GroupPublicKey = serde_json::from_str(&serialized).unwrap();
        assert_eq!(key, deserialized);
    }

    #[test]
    fn test_group_public_key_debug() {
        let bytes = [0x42; 32];
        let key = GroupPublicKey::from_bytes(bytes).unwrap();
        let debug = format!("{:?}", key);
        assert!(debug.contains("GroupPublicKey"));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // PARTICIPANT PUBLIC KEY TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_participant_public_key_from_bytes_valid() {
        let bytes = [0x02; 32];
        let result = ParticipantPublicKey::from_bytes(bytes);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_bytes(), &bytes);
    }

    #[test]
    fn test_participant_public_key_from_bytes_zero_rejected() {
        let bytes = [0x00; 32];
        let result = ParticipantPublicKey::from_bytes(bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_participant_public_key_serialize_deserialize() {
        let bytes = [0xCD; 32];
        let key = ParticipantPublicKey::from_bytes(bytes).unwrap();
        let serialized = serde_json::to_string(&key).unwrap();
        let deserialized: ParticipantPublicKey = serde_json::from_str(&serialized).unwrap();
        assert_eq!(key, deserialized);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SECRET SHARE TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_secret_share_from_bytes_valid() {
        let bytes = [0x42; 32];
        let result = SecretShare::from_bytes(bytes);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_bytes(), &bytes);
    }

    #[test]
    fn test_secret_share_from_bytes_zero_rejected() {
        let bytes = [0x00; 32];
        let result = SecretShare::from_bytes(bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_secret_share_clone() {
        let bytes = [0xAA; 32];
        let share = SecretShare::from_bytes(bytes).unwrap();
        let cloned = share.clone();
        assert_eq!(share.as_bytes(), cloned.as_bytes());
    }

    #[test]
    fn test_secret_share_zeroize_on_drop() {
        // This test verifies that SecretShare implements ZeroizeOnDrop
        // by checking it compiles with the trait bound
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<SecretShare>();
    }

    // ────────────────────────────────────────────────────────────────────────────
    // FROST SIGNATURE TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_frost_signature_from_bytes_valid() {
        let mut bytes = [0x42; 64];
        bytes[0] = 0x02; // Non-zero R component
        let result = FrostSignature::from_bytes(bytes);
        assert!(result.is_ok());
    }

    #[test]
    fn test_frost_signature_from_bytes_zero_r_rejected() {
        let mut bytes = [0x00; 64];
        bytes[32..].copy_from_slice(&[0x42; 32]); // Non-zero s, zero R
        let result = FrostSignature::from_bytes(bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_frost_signature_components() {
        let mut bytes = [0x00; 64];
        bytes[0..32].copy_from_slice(&[0xAA; 32]);
        bytes[32..64].copy_from_slice(&[0xBB; 32]);
        let sig = FrostSignature::from_bytes(bytes).unwrap();

        assert_eq!(sig.r_component(), &[0xAA; 32]);
        assert_eq!(sig.s_component(), &[0xBB; 32]);
    }

    #[test]
    fn test_frost_signature_serialize_deserialize() {
        let mut bytes = [0x42; 64];
        bytes[0] = 0x02;
        let sig = FrostSignature::from_bytes(bytes).unwrap();
        let serialized = serde_json::to_string(&sig).unwrap();
        let deserialized: FrostSignature = serde_json::from_str(&serialized).unwrap();
        assert_eq!(sig, deserialized);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // FROST SIGNATURE SHARE TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_frost_signature_share_from_bytes_valid() {
        let bytes = [0x42; 32];
        let result = FrostSignatureShare::from_bytes(bytes);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_bytes(), &bytes);
    }

    #[test]
    fn test_frost_signature_share_from_bytes_zero_rejected() {
        let bytes = [0x00; 32];
        let result = FrostSignatureShare::from_bytes(bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_frost_signature_share_serialize_deserialize() {
        let bytes = [0xEF; 32];
        let share = FrostSignatureShare::from_bytes(bytes).unwrap();
        let serialized = serde_json::to_string(&share).unwrap();
        let deserialized: FrostSignatureShare = serde_json::from_str(&serialized).unwrap();
        assert_eq!(share, deserialized);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SIGNING COMMITMENT TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_signing_commitment_from_parts_valid() {
        let hiding = [0xAA; 32];
        let binding = [0xBB; 32];
        let result = SigningCommitment::from_parts(hiding, binding);
        assert!(result.is_ok());
        let commitment = result.unwrap();
        assert_eq!(commitment.hiding(), &hiding);
        assert_eq!(commitment.binding(), &binding);
    }

    #[test]
    fn test_signing_commitment_from_parts_zero_hiding_rejected() {
        let hiding = [0x00; 32];
        let binding = [0xBB; 32];
        let result = SigningCommitment::from_parts(hiding, binding);
        assert!(result.is_err());
    }

    #[test]
    fn test_signing_commitment_from_parts_zero_binding_rejected() {
        let hiding = [0xAA; 32];
        let binding = [0x00; 32];
        let result = SigningCommitment::from_parts(hiding, binding);
        assert!(result.is_err());
    }

    #[test]
    fn test_signing_commitment_serialize_deserialize() {
        let hiding = [0x11; 32];
        let binding = [0x22; 32];
        let commitment = SigningCommitment::from_parts(hiding, binding).unwrap();
        let serialized = serde_json::to_string(&commitment).unwrap();
        let deserialized: SigningCommitment = serde_json::from_str(&serialized).unwrap();
        assert_eq!(commitment, deserialized);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // ENCRYPTION KEY TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_encryption_key_from_bytes_valid() {
        let bytes = [0x42; 32];
        let result = EncryptionKey::from_bytes(bytes);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_bytes(), &bytes);
    }

    #[test]
    fn test_encryption_key_from_bytes_zero_rejected() {
        let bytes = [0x00; 32];
        let result = EncryptionKey::from_bytes(bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_encryption_key_derive_from_shared_secret() {
        let secret = b"shared-secret-from-ecdh";
        let result = EncryptionKey::derive_from_shared_secret(secret);
        assert!(result.is_ok());
        let key = result.unwrap();
        // Key should not be all zeros
        assert!(!key.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_encryption_key_derive_from_empty_secret_rejected() {
        let result = EncryptionKey::derive_from_shared_secret(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_encryption_key_derive_deterministic() {
        let secret = b"test-secret";
        let key1 = EncryptionKey::derive_from_shared_secret(secret).unwrap();
        let key2 = EncryptionKey::derive_from_shared_secret(secret).unwrap();
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_encryption_key_derive_different_secrets_different_keys() {
        let key1 = EncryptionKey::derive_from_shared_secret(b"secret1").unwrap();
        let key2 = EncryptionKey::derive_from_shared_secret(b"secret2").unwrap();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_encryption_key_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<EncryptionKey>();
    }

    #[test]
    fn test_encryption_key_clone() {
        let bytes = [0xAA; 32];
        let key = EncryptionKey::from_bytes(bytes).unwrap();
        let cloned = key.clone();
        assert_eq!(key.as_bytes(), cloned.as_bytes());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SEND + SYNC TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_primitives_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<GroupPublicKey>();
        assert_send_sync::<ParticipantPublicKey>();
        assert_send_sync::<SecretShare>();
        assert_send_sync::<FrostSignature>();
        assert_send_sync::<FrostSignatureShare>();
        assert_send_sync::<SigningCommitment>();
        assert_send_sync::<EncryptionKey>();
    }

    // ────────────────────────────────────────────────────────────────────────────
    // CONSTANTS TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_constants() {
        assert_eq!(PUBLIC_KEY_SIZE, 32);
        assert_eq!(SCALAR_SIZE, 32);
        assert_eq!(SIGNATURE_SIZE, 64);
    }
}