//! # KeyShare Serialization
//!
//! Module ini menyediakan extension trait untuk serialization dan
//! deserialization `KeyShare` struct.
//!
//! ## Security Considerations
//!
//! KeyShare berisi `SecretShare` yang merupakan data sensitif.
//! Module ini menyediakan dua mode serialization:
//!
//! 1. **Encrypted**: Untuk production use - secret share dienkripsi
//! 2. **Plaintext**: HANYA untuk testing - secret share tidak dienkripsi
//!
//! ## Serialization Format
//!
//! ### Encrypted Format
//!
//! | Field | Offset | Size | Description |
//! |-------|--------|------|-------------|
//! | version | 0 | 1 | Format version (0x01) |
//! | participant_id | 1 | 32 | Participant identifier |
//! | group_pubkey | 33 | 32 | Group public key |
//! | participant_pubkey | 65 | 32 | Participant public key |
//! | threshold | 97 | 1 | Threshold (t) |
//! | total | 98 | 1 | Total participants (n) |
//! | nonce | 99 | 12 | Encryption nonce |
//! | encrypted_share | 111 | 32 | Encrypted secret share |
//! | tag | 143 | 16 | Authentication tag |
//! | **Total** | | **159** | |
//!
//! ### Plaintext Format (Testing Only)
//!
//! | Field | Offset | Size | Description |
//! |-------|--------|------|-------------|
//! | version | 0 | 1 | Format version (0x00) |
//! | participant_id | 1 | 32 | Participant identifier |
//! | group_pubkey | 33 | 32 | Group public key |
//! | participant_pubkey | 65 | 32 | Participant public key |
//! | threshold | 97 | 1 | Threshold (t) |
//! | total | 98 | 1 | Total participants (n) |
//! | secret_share | 99 | 32 | Secret share (UNENCRYPTED!) |
//! | **Total** | | **131** | |
//!
//! ## Encryption
//!
//! Encrypted mode menggunakan:
//! - Algorithm: ChaCha20-Poly1305 (placeholder: XOR with derived key)
//! - Key: Derived from EncryptionKey via SHA3-256
//! - Nonce: Random 12 bytes per encryption

use sha3::{Digest, Sha3_256};

use crate::dkg::KeyShare;
use crate::error::TSSError;
use crate::primitives::{
    EncryptionKey, GroupPublicKey, ParticipantPublicKey, SecretShare, SCALAR_SIZE,
};
use crate::types::ParticipantId;

// ════════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════════

/// Version byte for encrypted format.
const VERSION_ENCRYPTED: u8 = 0x01;

/// Version byte for plaintext format.
const VERSION_PLAINTEXT: u8 = 0x00;

/// Size of encryption nonce in bytes.
const NONCE_SIZE: usize = 12;

/// Size of authentication tag in bytes.
const TAG_SIZE: usize = 16;

/// Total size of encrypted KeyShare serialization.
const ENCRYPTED_SIZE: usize = 1 + 32 + 32 + 32 + 1 + 1 + NONCE_SIZE + SCALAR_SIZE + TAG_SIZE;

/// Total size of plaintext KeyShare serialization.
const PLAINTEXT_SIZE: usize = 1 + 32 + 32 + 32 + 1 + 1 + SCALAR_SIZE;

// ════════════════════════════════════════════════════════════════════════════════
// KEYSHARE SERIALIZATION TRAIT
// ════════════════════════════════════════════════════════════════════════════════

/// Extension trait untuk KeyShare serialization.
///
/// Trait ini menambahkan kemampuan serialization ke `KeyShare`
/// yang didefinisikan di `dkg::participant`.
pub trait KeyShareSerialization {
    /// Serialize KeyShare dengan encryption.
    ///
    /// # Arguments
    ///
    /// * `encryption_key` - Key untuk enkripsi secret share
    ///
    /// # Returns
    ///
    /// Encrypted bytes dalam format yang aman untuk storage.
    ///
    /// # Errors
    ///
    /// Mengembalikan `TSSError` jika encryption gagal.
    fn serialize_encrypted(&self, encryption_key: &EncryptionKey) -> Result<Vec<u8>, TSSError>;

    /// Deserialize KeyShare dari encrypted bytes.
    ///
    /// # Arguments
    ///
    /// * `data` - Encrypted bytes
    /// * `encryption_key` - Key untuk dekripsi
    ///
    /// # Returns
    ///
    /// `KeyShare` yang sudah di-deserialize.
    ///
    /// # Errors
    ///
    /// - `TSSError::Crypto` jika decryption gagal
    /// - `TSSError::Crypto` jika format tidak valid
    fn deserialize_encrypted(data: &[u8], encryption_key: &EncryptionKey)
        -> Result<Self, TSSError>
    where
        Self: Sized;

    /// Serialize KeyShare tanpa encryption (TESTING ONLY).
    ///
    /// **WARNING**: Method ini mengekspos secret share dalam plaintext!
    /// Hanya gunakan untuk testing atau debugging.
    ///
    /// # Returns
    ///
    /// Plaintext bytes (TIDAK AMAN untuk production).
    fn serialize_plaintext(&self) -> Vec<u8>;

    /// Deserialize KeyShare dari plaintext bytes (TESTING ONLY).
    ///
    /// **WARNING**: Method ini expects unencrypted secret share!
    /// Hanya gunakan untuk testing atau debugging.
    ///
    /// # Arguments
    ///
    /// * `data` - Plaintext bytes
    ///
    /// # Returns
    ///
    /// `KeyShare` yang sudah di-deserialize.
    ///
    /// # Errors
    ///
    /// - `TSSError::Crypto` jika format tidak valid
    fn deserialize_plaintext(data: &[u8]) -> Result<Self, TSSError>
    where
        Self: Sized;
}

impl KeyShareSerialization for KeyShare {
    fn serialize_encrypted(&self, encryption_key: &EncryptionKey) -> Result<Vec<u8>, TSSError> {
        let mut bytes = Vec::with_capacity(ENCRYPTED_SIZE);

        // Version byte
        bytes.push(VERSION_ENCRYPTED);

        // Participant ID (32 bytes)
        bytes.extend_from_slice(self.participant_id().as_bytes());

        // Group public key (32 bytes)
        bytes.extend_from_slice(self.group_pubkey().as_bytes());

        // Participant public key (32 bytes)
        bytes.extend_from_slice(self.participant_pubkey().as_bytes());

        // Threshold (1 byte)
        bytes.push(self.threshold());

        // Total (1 byte)
        bytes.push(self.total());

        // Generate random nonce (12 bytes)
        let nonce = generate_nonce();
        bytes.extend_from_slice(&nonce);

        // Encrypt secret share
        let (encrypted_share, tag) =
            encrypt_share(self.secret_share().as_bytes(), encryption_key, &nonce)?;

        // Encrypted share (32 bytes)
        bytes.extend_from_slice(&encrypted_share);

        // Authentication tag (16 bytes)
        bytes.extend_from_slice(&tag);

        debug_assert_eq!(bytes.len(), ENCRYPTED_SIZE);
        Ok(bytes)
    }

    fn deserialize_encrypted(
        data: &[u8],
        encryption_key: &EncryptionKey,
    ) -> Result<Self, TSSError> {
        // Validate length
        if data.len() < ENCRYPTED_SIZE {
            return Err(TSSError::Crypto(format!(
                "KeyShare: insufficient bytes for encrypted format, expected {}, got {}",
                ENCRYPTED_SIZE,
                data.len()
            )));
        }

        // Check version
        if data[0] != VERSION_ENCRYPTED {
            return Err(TSSError::Crypto(format!(
                "KeyShare: invalid version for encrypted format, expected {}, got {}",
                VERSION_ENCRYPTED, data[0]
            )));
        }

        // Parse participant_id (bytes 1..33)
        let mut participant_id_bytes = [0u8; 32];
        participant_id_bytes.copy_from_slice(&data[1..33]);
        let participant_id = ParticipantId::from_bytes(participant_id_bytes);

        // Parse group_pubkey (bytes 33..65)
        let mut group_pubkey_bytes = [0u8; 32];
        group_pubkey_bytes.copy_from_slice(&data[33..65]);
        let group_pubkey = GroupPublicKey::from_bytes(group_pubkey_bytes)?;

        // Parse participant_pubkey (bytes 65..97)
        let mut participant_pubkey_bytes = [0u8; 32];
        participant_pubkey_bytes.copy_from_slice(&data[65..97]);
        let participant_pubkey = ParticipantPublicKey::from_bytes(participant_pubkey_bytes)?;

        // Parse threshold (byte 97)
        let threshold = data[97];

        // Parse total (byte 98)
        let total = data[98];

        // Parse nonce (bytes 99..111)
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&data[99..111]);

        // Parse encrypted_share (bytes 111..143)
        let mut encrypted_share = [0u8; SCALAR_SIZE];
        encrypted_share.copy_from_slice(&data[111..143]);

        // Parse tag (bytes 143..159)
        let mut tag = [0u8; TAG_SIZE];
        tag.copy_from_slice(&data[143..159]);

        // Decrypt secret share
        let secret_share_bytes = decrypt_share(&encrypted_share, encryption_key, &nonce, &tag)?;
        let secret_share = SecretShare::from_bytes(secret_share_bytes)?;

        Ok(KeyShare::new(
            secret_share,
            group_pubkey,
            participant_pubkey,
            participant_id,
            threshold,
            total,
        ))
    }

    fn serialize_plaintext(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(PLAINTEXT_SIZE);

        // Version byte
        bytes.push(VERSION_PLAINTEXT);

        // Participant ID (32 bytes)
        bytes.extend_from_slice(self.participant_id().as_bytes());

        // Group public key (32 bytes)
        bytes.extend_from_slice(self.group_pubkey().as_bytes());

        // Participant public key (32 bytes)
        bytes.extend_from_slice(self.participant_pubkey().as_bytes());

        // Threshold (1 byte)
        bytes.push(self.threshold());

        // Total (1 byte)
        bytes.push(self.total());

        // Secret share (32 bytes) - UNENCRYPTED!
        bytes.extend_from_slice(self.secret_share().as_bytes());

        debug_assert_eq!(bytes.len(), PLAINTEXT_SIZE);
        bytes
    }

    fn deserialize_plaintext(data: &[u8]) -> Result<Self, TSSError> {
        // Validate length
        if data.len() < PLAINTEXT_SIZE {
            return Err(TSSError::Crypto(format!(
                "KeyShare: insufficient bytes for plaintext format, expected {}, got {}",
                PLAINTEXT_SIZE,
                data.len()
            )));
        }

        // Check version
        if data[0] != VERSION_PLAINTEXT {
            return Err(TSSError::Crypto(format!(
                "KeyShare: invalid version for plaintext format, expected {}, got {}",
                VERSION_PLAINTEXT, data[0]
            )));
        }

        // Parse participant_id (bytes 1..33)
        let mut participant_id_bytes = [0u8; 32];
        participant_id_bytes.copy_from_slice(&data[1..33]);
        let participant_id = ParticipantId::from_bytes(participant_id_bytes);

        // Parse group_pubkey (bytes 33..65)
        let mut group_pubkey_bytes = [0u8; 32];
        group_pubkey_bytes.copy_from_slice(&data[33..65]);
        let group_pubkey = GroupPublicKey::from_bytes(group_pubkey_bytes)?;

        // Parse participant_pubkey (bytes 65..97)
        let mut participant_pubkey_bytes = [0u8; 32];
        participant_pubkey_bytes.copy_from_slice(&data[65..97]);
        let participant_pubkey = ParticipantPublicKey::from_bytes(participant_pubkey_bytes)?;

        // Parse threshold (byte 97)
        let threshold = data[97];

        // Parse total (byte 98)
        let total = data[98];

        // Parse secret_share (bytes 99..131)
        let mut secret_share_bytes = [0u8; SCALAR_SIZE];
        secret_share_bytes.copy_from_slice(&data[99..131]);
        let secret_share = SecretShare::from_bytes(secret_share_bytes)?;

        Ok(KeyShare::new(
            secret_share,
            group_pubkey,
            participant_pubkey,
            participant_id,
            threshold,
            total,
        ))
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// ENCRYPTION HELPERS
// ════════════════════════════════════════════════════════════════════════════════

/// Generate random nonce for encryption.
fn generate_nonce() -> [u8; NONCE_SIZE] {
    use rand::RngCore;
    let mut nonce = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Derive encryption subkey from main key and nonce.
fn derive_subkey(key: &EncryptionKey, nonce: &[u8; NONCE_SIZE]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"dsdn-tss-keyshare-subkey-v1");
    hasher.update(key.as_bytes());
    hasher.update(nonce);

    let result = hasher.finalize();
    let mut subkey = [0u8; 32];
    subkey.copy_from_slice(&result);
    subkey
}

/// Compute authentication tag.
fn compute_tag(
    encrypted: &[u8; SCALAR_SIZE],
    key: &EncryptionKey,
    nonce: &[u8; NONCE_SIZE],
) -> [u8; TAG_SIZE] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"dsdn-tss-keyshare-tag-v1");
    hasher.update(key.as_bytes());
    hasher.update(nonce);
    hasher.update(encrypted);

    let result = hasher.finalize();
    let mut tag = [0u8; TAG_SIZE];
    tag.copy_from_slice(&result[0..TAG_SIZE]);
    tag
}

/// Encrypt secret share (placeholder: XOR with derived key).
///
/// In production, this should use ChaCha20-Poly1305 or similar AEAD.
fn encrypt_share(
    plaintext: &[u8; SCALAR_SIZE],
    key: &EncryptionKey,
    nonce: &[u8; NONCE_SIZE],
) -> Result<([u8; SCALAR_SIZE], [u8; TAG_SIZE]), TSSError> {
    // Derive subkey
    let subkey = derive_subkey(key, nonce);

    // XOR encryption (placeholder for real AEAD)
    let mut ciphertext = [0u8; SCALAR_SIZE];
    for i in 0..SCALAR_SIZE {
        ciphertext[i] = plaintext[i] ^ subkey[i];
    }

    // Compute authentication tag
    let tag = compute_tag(&ciphertext, key, nonce);

    Ok((ciphertext, tag))
}

/// Decrypt secret share (placeholder: XOR with derived key).
fn decrypt_share(
    ciphertext: &[u8; SCALAR_SIZE],
    key: &EncryptionKey,
    nonce: &[u8; NONCE_SIZE],
    expected_tag: &[u8; TAG_SIZE],
) -> Result<[u8; SCALAR_SIZE], TSSError> {
    // Verify tag first
    let computed_tag = compute_tag(ciphertext, key, nonce);
    if !constant_time_eq(&computed_tag, expected_tag) {
        return Err(TSSError::Crypto(
            "KeyShare: authentication tag mismatch".to_string(),
        ));
    }

    // Derive subkey
    let subkey = derive_subkey(key, nonce);

    // XOR decryption (placeholder for real AEAD)
    let mut plaintext = [0u8; SCALAR_SIZE];
    for i in 0..SCALAR_SIZE {
        plaintext[i] = ciphertext[i] ^ subkey[i];
    }

    Ok(plaintext)
}

/// Constant-time comparison for security.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }

    diff == 0
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

    fn make_key_share() -> KeyShare {
        let secret_share = SecretShare::from_bytes([0x42; 32]).unwrap();
        let group_pubkey = GroupPublicKey::from_bytes([0x01; 32]).unwrap();
        let participant_pubkey = ParticipantPublicKey::from_bytes([0x02; 32]).unwrap();
        let participant_id = ParticipantId::from_bytes([0xAA; 32]);

        KeyShare::new(
            secret_share,
            group_pubkey,
            participant_pubkey,
            participant_id,
            2, // threshold
            3, // total
        )
    }

    fn make_encryption_key() -> EncryptionKey {
        EncryptionKey::from_bytes([0x55; 32]).unwrap()
    }

    // ────────────────────────────────────────────────────────────────────────────
    // PLAINTEXT SERIALIZATION TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_serialize_plaintext() {
        let key_share = make_key_share();
        let bytes = key_share.serialize_plaintext();

        assert_eq!(bytes.len(), PLAINTEXT_SIZE);
        assert_eq!(bytes[0], VERSION_PLAINTEXT);
    }

    #[test]
    fn test_deserialize_plaintext() {
        let key_share = make_key_share();
        let bytes = key_share.serialize_plaintext();

        let recovered = KeyShare::deserialize_plaintext(&bytes).unwrap();

        assert_eq!(recovered.participant_id().as_bytes(), key_share.participant_id().as_bytes());
        assert_eq!(recovered.group_pubkey().as_bytes(), key_share.group_pubkey().as_bytes());
        assert_eq!(recovered.participant_pubkey().as_bytes(), key_share.participant_pubkey().as_bytes());
        assert_eq!(recovered.threshold(), key_share.threshold());
        assert_eq!(recovered.total(), key_share.total());
        assert_eq!(recovered.secret_share().as_bytes(), key_share.secret_share().as_bytes());
    }

    #[test]
    fn test_plaintext_roundtrip() {
        let original = make_key_share();
        let bytes = original.serialize_plaintext();
        let recovered = KeyShare::deserialize_plaintext(&bytes).unwrap();

        assert_eq!(recovered.secret_share().as_bytes(), original.secret_share().as_bytes());
    }

    #[test]
    fn test_deserialize_plaintext_insufficient_bytes() {
        let bytes = vec![0u8; 50]; // Too short
        let result = KeyShare::deserialize_plaintext(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_plaintext_wrong_version() {
        let key_share = make_key_share();
        let mut bytes = key_share.serialize_plaintext();
        bytes[0] = 0xFF; // Wrong version

        let result = KeyShare::deserialize_plaintext(&bytes);
        assert!(result.is_err());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // ENCRYPTED SERIALIZATION TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_serialize_encrypted() {
        let key_share = make_key_share();
        let encryption_key = make_encryption_key();
        let bytes = key_share.serialize_encrypted(&encryption_key).unwrap();

        assert_eq!(bytes.len(), ENCRYPTED_SIZE);
        assert_eq!(bytes[0], VERSION_ENCRYPTED);
    }

    #[test]
    fn test_deserialize_encrypted() {
        let key_share = make_key_share();
        let encryption_key = make_encryption_key();
        let bytes = key_share.serialize_encrypted(&encryption_key).unwrap();

        let recovered = KeyShare::deserialize_encrypted(&bytes, &encryption_key).unwrap();

        assert_eq!(recovered.participant_id().as_bytes(), key_share.participant_id().as_bytes());
        assert_eq!(recovered.group_pubkey().as_bytes(), key_share.group_pubkey().as_bytes());
        assert_eq!(recovered.participant_pubkey().as_bytes(), key_share.participant_pubkey().as_bytes());
        assert_eq!(recovered.threshold(), key_share.threshold());
        assert_eq!(recovered.total(), key_share.total());
        assert_eq!(recovered.secret_share().as_bytes(), key_share.secret_share().as_bytes());
    }

    #[test]
    fn test_encrypted_roundtrip() {
        let original = make_key_share();
        let encryption_key = make_encryption_key();
        
        let bytes = original.serialize_encrypted(&encryption_key).unwrap();
        let recovered = KeyShare::deserialize_encrypted(&bytes, &encryption_key).unwrap();

        assert_eq!(recovered.secret_share().as_bytes(), original.secret_share().as_bytes());
    }

    #[test]
    fn test_deserialize_encrypted_wrong_key() {
        let key_share = make_key_share();
        let encryption_key = make_encryption_key();
        let bytes = key_share.serialize_encrypted(&encryption_key).unwrap();

        // Try to decrypt with different key
        let wrong_key = EncryptionKey::from_bytes([0x99; 32]).unwrap();
        let result = KeyShare::deserialize_encrypted(&bytes, &wrong_key);
        
        assert!(result.is_err()); // Should fail authentication
    }

    #[test]
    fn test_deserialize_encrypted_tampered_ciphertext() {
        let key_share = make_key_share();
        let encryption_key = make_encryption_key();
        let mut bytes = key_share.serialize_encrypted(&encryption_key).unwrap();

        // Tamper with encrypted share
        bytes[120] ^= 0xFF;

        let result = KeyShare::deserialize_encrypted(&bytes, &encryption_key);
        assert!(result.is_err()); // Should fail authentication
    }

    #[test]
    fn test_deserialize_encrypted_insufficient_bytes() {
        let bytes = vec![0u8; 50]; // Too short
        let encryption_key = make_encryption_key();
        let result = KeyShare::deserialize_encrypted(&bytes, &encryption_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_encrypted_wrong_version() {
        let key_share = make_key_share();
        let encryption_key = make_encryption_key();
        let mut bytes = key_share.serialize_encrypted(&encryption_key).unwrap();
        bytes[0] = 0xFF; // Wrong version

        let result = KeyShare::deserialize_encrypted(&bytes, &encryption_key);
        assert!(result.is_err());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // ENCRYPTION UNIQUENESS TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_encrypted_output_unique_per_call() {
        // Each encryption should produce different output (different nonce)
        let key_share = make_key_share();
        let encryption_key = make_encryption_key();

        let bytes1 = key_share.serialize_encrypted(&encryption_key).unwrap();
        let bytes2 = key_share.serialize_encrypted(&encryption_key).unwrap();

        // Nonces should be different
        assert_ne!(&bytes1[99..111], &bytes2[99..111]);
        
        // But both should decrypt to same value
        let recovered1 = KeyShare::deserialize_encrypted(&bytes1, &encryption_key).unwrap();
        let recovered2 = KeyShare::deserialize_encrypted(&bytes2, &encryption_key).unwrap();
        
        assert_eq!(
            recovered1.secret_share().as_bytes(),
            recovered2.secret_share().as_bytes()
        );
    }

    // ────────────────────────────────────────────────────────────────────────────
    // CONSTANT TIME COMPARISON TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_constant_time_eq_equal() {
        let a = [1, 2, 3, 4];
        let b = [1, 2, 3, 4];
        assert!(constant_time_eq(&a, &b));
    }

    #[test]
    fn test_constant_time_eq_not_equal() {
        let a = [1, 2, 3, 4];
        let b = [1, 2, 3, 5];
        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn test_constant_time_eq_different_length() {
        let a = [1, 2, 3, 4];
        let b = [1, 2, 3];
        assert!(!constant_time_eq(&a, &b));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SIZE CONSTANT TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_encrypted_size_constant() {
        assert_eq!(ENCRYPTED_SIZE, 159);
    }

    #[test]
    fn test_plaintext_size_constant() {
        assert_eq!(PLAINTEXT_SIZE, 131);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // REAL DKG INTEGRATION TESTS
    // ────────────────────────────────────────────────────────────────────────────

    /// Run a minimal 2-of-3 DKG and return key shares.
    fn run_dkg_for_serialization_test() -> Vec<KeyShare> {
        use crate::dkg::participant::{DKGParticipant, LocalDKGParticipant};
        use crate::dkg::packages::Round2Package;
        use crate::types::SessionId;
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        let mut rng = ChaCha20Rng::seed_from_u64(77777);
        let session_id = SessionId::from_bytes([0xBB; 32]);

        let pids: Vec<ParticipantId> = (1..=3u8)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[0] = i;
                ParticipantId::from_bytes(bytes)
            })
            .collect();

        let mut participants: Vec<LocalDKGParticipant> = pids
            .iter()
            .map(|pid| {
                LocalDKGParticipant::new(pid.clone(), session_id.clone(), 2, 3)
                    .expect("valid params")
            })
            .collect();

        // Round 1
        let mut r1_pkgs = Vec::new();
        for p in &mut participants {
            r1_pkgs.push(
                p.generate_round1_with_rng(&mut rng)
                    .expect("round1 ok"),
            );
        }

        // Process round 1
        let mut all_r2: Vec<Vec<Round2Package>> = Vec::new();
        for p in &mut participants {
            all_r2.push(p.process_round1(&r1_pkgs).expect("process_round1 ok"));
        }

        // Process round 2
        let mut key_shares = Vec::new();
        for p in &mut participants {
            let my_pkgs: Vec<Round2Package> = all_r2
                .iter()
                .flat_map(|pkgs| pkgs.iter())
                .filter(|pkg| pkg.to_participant() == p.participant_id())
                .cloned()
                .collect();
            key_shares.push(p.process_round2(&my_pkgs).expect("process_round2 ok"));
        }

        key_shares
    }

    #[test]
    fn test_real_dkg_keyshare_plaintext_roundtrip() {
        let key_shares = run_dkg_for_serialization_test();

        for ks in &key_shares {
            let bytes = ks.serialize_plaintext();
            let recovered = KeyShare::deserialize_plaintext(&bytes)
                .expect("plaintext deserialization must succeed");

            assert_eq!(recovered.signing_share(), ks.signing_share());
            assert_eq!(recovered.group_public_key(), ks.group_public_key());
            assert_eq!(recovered.participant_pubkey().as_bytes(), ks.participant_pubkey().as_bytes());
            assert_eq!(recovered.threshold(), ks.threshold());
            assert_eq!(recovered.total(), ks.total());
        }
    }

    #[test]
    fn test_real_dkg_keyshare_encrypted_roundtrip() {
        let key_shares = run_dkg_for_serialization_test();
        let encryption_key = make_encryption_key();

        for ks in &key_shares {
            let bytes = ks
                .serialize_encrypted(&encryption_key)
                .expect("encryption must succeed");
            let recovered = KeyShare::deserialize_encrypted(&bytes, &encryption_key)
                .expect("decryption must succeed");

            assert_eq!(recovered.signing_share(), ks.signing_share());
            assert_eq!(recovered.group_public_key(), ks.group_public_key());
            assert_eq!(recovered.participant_pubkey().as_bytes(), ks.participant_pubkey().as_bytes());
            assert_eq!(recovered.threshold(), ks.threshold());
            assert_eq!(recovered.total(), ks.total());
        }
    }

    #[test]
    fn test_real_dkg_keyshare_encrypted_wrong_key_rejected() {
        let key_shares = run_dkg_for_serialization_test();
        let encryption_key = make_encryption_key();
        let wrong_key = EncryptionKey::from_bytes([0x99; 32]).expect("valid key");

        let bytes = key_shares[0]
            .serialize_encrypted(&encryption_key)
            .expect("encryption must succeed");

        let result = KeyShare::deserialize_encrypted(&bytes, &wrong_key);
        assert!(
            result.is_err(),
            "decryption with wrong key must fail"
        );
    }
}