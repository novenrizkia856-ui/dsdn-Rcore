//! # DKG Round Packages
//!
//! Module ini mendefinisikan struktur data untuk package yang dikirim
//! dalam setiap round DKG protocol.
//!
//! ## Round 1: Commitment Broadcast
//!
//! `Round1Package` berisi:
//! - Pedersen commitment ke polynomial coefficients
//! - Schnorr proof of knowledge
//!
//! ## Round 2: Encrypted Share Distribution
//!
//! `Round2Package` berisi:
//! - Encrypted secret share untuk recipient tertentu
//! - Routing information (from, to)
//!
//! ## Catatan Implementasi
//!
//! Saat ini, fungsi kriptografi adalah **stubs**:
//! - `verify_proof()` selalu return `true`
//! - `decrypt()` menggunakan simple XOR sebagai placeholder
//!
//! Implementasi kriptografi sebenarnya akan ditambahkan di tahap selanjutnya.

use sha3::{Digest, Sha3_256};

use crate::error::DKGError;
use crate::primitives::{EncryptionKey, SecretShare, SCALAR_SIZE};
use crate::types::{ParticipantId, SessionId};

// ════════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════════

/// Ukuran commitment dalam bytes (Pedersen commitment).
pub const COMMITMENT_SIZE: usize = 32;

/// Ukuran proof dalam bytes (Schnorr proof).
pub const PROOF_SIZE: usize = 64;

// ════════════════════════════════════════════════════════════════════════════════
// ROUND 1 PACKAGE
// ════════════════════════════════════════════════════════════════════════════════

/// Package yang dikirim oleh participant dalam Round 1 DKG.
///
/// `Round1Package` berisi commitment dan proof of knowledge yang di-broadcast
/// ke semua participants. Package ini memungkinkan participants lain untuk
/// memverifikasi bahwa sender mengetahui secret yang di-commit.
///
/// ## Fields
///
/// - `participant_id`: Identifier dari sender
/// - `commitment`: Pedersen commitment ke polynomial constant term (32 bytes)
/// - `proof`: Schnorr proof of knowledge (64 bytes)
///
/// ## Verifikasi
///
/// Recipient harus memverifikasi `proof` terhadap `commitment` menggunakan
/// `verify_proof()`. Saat ini ini adalah stub yang selalu return `true`.
///
/// ## Contoh
///
/// ```rust
/// use dsdn_tss::dkg::Round1Package;
/// use dsdn_tss::ParticipantId;
///
/// let participant = ParticipantId::new();
/// let commitment = [0x42u8; 32];
/// let proof = [0xABu8; 64];
///
/// let package = Round1Package::new(participant, commitment, proof);
///
/// // Verify proof (stub - currently always true)
/// assert!(package.verify_proof());
///
/// // Get commitment hash for deterministic identification
/// let hash = package.commitment_hash();
/// assert_eq!(hash.len(), 32);
/// ```
#[derive(Debug, Clone)]
pub struct Round1Package {
    /// Identifier dari participant yang mengirim package ini.
    participant_id: ParticipantId,

    /// Pedersen commitment ke polynomial constant term.
    ///
    /// Format: compressed elliptic curve point (32 bytes).
    commitment: [u8; COMMITMENT_SIZE],

    /// Schnorr proof of knowledge.
    ///
    /// Membuktikan bahwa sender mengetahui discrete log dari commitment.
    /// Format: (challenge || response) = 64 bytes.
    proof: [u8; PROOF_SIZE],
}

impl Round1Package {
    /// Membuat `Round1Package` baru.
    ///
    /// # Arguments
    ///
    /// * `participant_id` - Identifier dari sender
    /// * `commitment` - Pedersen commitment (32 bytes)
    /// * `proof` - Schnorr proof of knowledge (64 bytes)
    #[must_use]
    pub const fn new(
        participant_id: ParticipantId,
        commitment: [u8; COMMITMENT_SIZE],
        proof: [u8; PROOF_SIZE],
    ) -> Self {
        Self {
            participant_id,
            commitment,
            proof,
        }
    }

    /// Mengembalikan participant ID dari sender.
    #[must_use]
    pub const fn participant_id(&self) -> &ParticipantId {
        &self.participant_id
    }

    /// Mengembalikan commitment bytes.
    #[must_use]
    pub const fn commitment(&self) -> &[u8; COMMITMENT_SIZE] {
        &self.commitment
    }

    /// Mengembalikan proof bytes.
    #[must_use]
    pub const fn proof(&self) -> &[u8; PROOF_SIZE] {
        &self.proof
    }

    /// Memverifikasi Schnorr proof of knowledge.
    ///
    /// **STUB**: Saat ini selalu return `true`.
    ///
    /// Implementasi sebenarnya akan:
    /// 1. Parse proof sebagai (challenge, response)
    /// 2. Recompute challenge dari commitment dan public data
    /// 3. Verify bahwa response konsisten dengan challenge dan commitment
    ///
    /// # Returns
    ///
    /// `true` jika proof valid, `false` sebaliknya.
    ///
    /// # Note
    ///
    /// Ini adalah **placeholder deterministik**. Kriptografi sebenarnya
    /// akan diimplementasikan di tahap selanjutnya.
    #[must_use]
    pub fn verify_proof(&self) -> bool {
        // STUB: Placeholder untuk verifikasi Schnorr proof
        //
        // Dalam implementasi sebenarnya:
        // 1. Deserialize commitment sebagai curve point
        // 2. Parse proof sebagai (challenge: [u8; 32], response: [u8; 32])
        // 3. Compute: R = response * G - challenge * commitment
        // 4. Recompute challenge: challenge' = H(commitment || R)
        // 5. Verify: challenge == challenge'
        //
        // Untuk saat ini, kita return true untuk semua input
        // karena implementasi crypto belum ada.
        true
    }

    /// Menghitung hash deterministik dari commitment.
    ///
    /// Hash ini dapat digunakan untuk:
    /// - Mengidentifikasi commitment secara unik
    /// - Mendeteksi duplikat
    /// - Ordering deterministik
    ///
    /// # Returns
    ///
    /// SHA3-256 hash dari commitment (32 bytes).
    ///
    /// # Algorithm
    ///
    /// ```text
    /// hash = SHA3-256(domain_separator || participant_id || commitment)
    /// ```
    #[must_use]
    pub fn commitment_hash(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();

        // Domain separator untuk commitment hash
        hasher.update(b"dsdn-tss-commitment-hash-v1");

        // Include participant_id untuk uniqueness per participant
        hasher.update(self.participant_id.as_bytes());

        // Include commitment data
        hasher.update(&self.commitment);

        let result = hasher.finalize();

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// ROUND 2 PACKAGE
// ════════════════════════════════════════════════════════════════════════════════

/// Package yang dikirim dari satu participant ke participant lain dalam Round 2 DKG.
///
/// `Round2Package` berisi encrypted secret share yang dikirim secara private
/// ke recipient tertentu. Share dienkripsi menggunakan key yang diderivasi
/// dari ECDH antara sender dan recipient.
///
/// ## Fields
///
/// - `session_id`: Identifier untuk DKG session
/// - `from_participant`: Sender participant ID
/// - `to_participant`: Recipient participant ID
/// - `encrypted_share`: Ciphertext dari secret share
///
/// ## Dekripsi
///
/// Recipient harus mendekripsi `encrypted_share` menggunakan `EncryptionKey`
/// yang diderivasi dari shared secret (ECDH).
///
/// ## Contoh
///
/// ```rust
/// use dsdn_tss::dkg::Round2Package;
/// use dsdn_tss::{ParticipantId, SessionId, EncryptionKey};
///
/// let session = SessionId::new();
/// let from = ParticipantId::new();
/// let to = ParticipantId::new();
/// let encrypted_share = vec![0x42u8; 32];
///
/// let package = Round2Package::new(session, from, to, encrypted_share);
/// ```
#[derive(Debug, Clone)]
pub struct Round2Package {
    /// Session ID untuk DKG session.
    session_id: SessionId,

    /// Participant ID dari sender.
    from_participant: ParticipantId,

    /// Participant ID dari recipient.
    to_participant: ParticipantId,

    /// Encrypted secret share.
    ///
    /// Ciphertext yang berisi share yang dienkripsi untuk recipient.
    /// Format bergantung pada encryption scheme yang digunakan.
    encrypted_share: Vec<u8>,
}

impl Round2Package {
    /// Membuat `Round2Package` baru.
    ///
    /// # Arguments
    ///
    /// * `session_id` - DKG session identifier
    /// * `from_participant` - Sender participant ID
    /// * `to_participant` - Recipient participant ID
    /// * `encrypted_share` - Encrypted secret share bytes
    #[must_use]
    pub fn new(
        session_id: SessionId,
        from_participant: ParticipantId,
        to_participant: ParticipantId,
        encrypted_share: Vec<u8>,
    ) -> Self {
        Self {
            session_id,
            from_participant,
            to_participant,
            encrypted_share,
        }
    }

    /// Mengembalikan session ID.
    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Mengembalikan sender participant ID.
    #[must_use]
    pub const fn from_participant(&self) -> &ParticipantId {
        &self.from_participant
    }

    /// Mengembalikan recipient participant ID.
    #[must_use]
    pub const fn to_participant(&self) -> &ParticipantId {
        &self.to_participant
    }

    /// Mengembalikan encrypted share bytes.
    #[must_use]
    pub fn encrypted_share(&self) -> &[u8] {
        &self.encrypted_share
    }

    /// Mendekripsi encrypted share menggunakan encryption key.
    ///
    /// **STUB**: Saat ini menggunakan simple XOR sebagai placeholder.
    ///
    /// Implementasi sebenarnya akan:
    /// 1. Derive encryption key dari ECDH shared secret
    /// 2. Decrypt menggunakan authenticated encryption (e.g., ChaCha20-Poly1305)
    /// 3. Verify authentication tag
    /// 4. Parse decrypted bytes sebagai SecretShare
    ///
    /// # Arguments
    ///
    /// * `key` - Encryption key (derived from ECDH shared secret)
    ///
    /// # Returns
    ///
    /// `Ok(SecretShare)` jika dekripsi berhasil.
    /// `Err(DKGError::InvalidRound2Package)` jika dekripsi gagal.
    ///
    /// # Errors
    ///
    /// - Ciphertext length tidak sesuai (bukan 32 bytes)
    /// - Decrypted share tidak valid (semua zero)
    ///
    /// # Security
    ///
    /// - Tidak ada informasi secret yang bocor dalam error message
    /// - Key tidak di-log atau di-display
    pub fn decrypt(&self, key: &EncryptionKey) -> Result<SecretShare, DKGError> {
        // Validate ciphertext length
        if self.encrypted_share.len() != SCALAR_SIZE {
            return Err(DKGError::InvalidRound2Package {
                from: self.from_participant.clone(),
                to: self.to_participant.clone(),
                reason: "invalid ciphertext length".to_string(),
            });
        }

        // STUB: Simple XOR "decryption" as placeholder
        //
        // Dalam implementasi sebenarnya:
        // 1. Parse ciphertext sebagai (nonce || ciphertext || tag)
        // 2. Decrypt menggunakan ChaCha20-Poly1305 atau AES-GCM
        // 3. Verify authentication tag
        // 4. Handle padding jika ada
        //
        // Untuk saat ini, kita gunakan simple XOR dengan key
        // sebagai simulasi minimal.

        let key_bytes = key.as_bytes();
        let mut decrypted = [0u8; SCALAR_SIZE];

        for (i, (ct_byte, key_byte)) in self
            .encrypted_share
            .iter()
            .zip(key_bytes.iter())
            .enumerate()
        {
            decrypted[i] = ct_byte ^ key_byte;
        }

        // Validate decrypted share
        SecretShare::from_bytes(decrypted).map_err(|_| DKGError::InvalidRound2Package {
            from: self.from_participant.clone(),
            to: self.to_participant.clone(),
            reason: "decryption produced invalid share".to_string(),
        })
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::EncryptionKey;

    // ────────────────────────────────────────────────────────────────────────────
    // ROUND1PACKAGE TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_round1_package_new() {
        let participant = ParticipantId::from_bytes([0xAA; 32]);
        let commitment = [0xBB; 32];
        let proof = [0xCC; 64];

        let package = Round1Package::new(participant.clone(), commitment, proof);

        assert_eq!(package.participant_id(), &participant);
        assert_eq!(package.commitment(), &commitment);
        assert_eq!(package.proof(), &proof);
    }

    #[test]
    fn test_round1_package_verify_proof_stub() {
        let participant = ParticipantId::from_bytes([0xAA; 32]);
        let commitment = [0xBB; 32];
        let proof = [0xCC; 64];

        let package = Round1Package::new(participant, commitment, proof);

        // Stub always returns true
        assert!(package.verify_proof());
    }

    #[test]
    fn test_round1_package_verify_proof_with_zero_inputs() {
        let participant = ParticipantId::from_bytes([0x00; 32]);
        let commitment = [0x00; 32];
        let proof = [0x00; 64];

        let package = Round1Package::new(participant, commitment, proof);

        // Stub still returns true
        assert!(package.verify_proof());
    }

    #[test]
    fn test_round1_package_commitment_hash() {
        let participant = ParticipantId::from_bytes([0xAA; 32]);
        let commitment = [0xBB; 32];
        let proof = [0xCC; 64];

        let package = Round1Package::new(participant, commitment, proof);
        let hash = package.commitment_hash();

        assert_eq!(hash.len(), 32);
        // Hash should not be all zeros for non-zero input
        assert!(!hash.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_round1_package_commitment_hash_deterministic() {
        let participant = ParticipantId::from_bytes([0xAA; 32]);
        let commitment = [0xBB; 32];
        let proof = [0xCC; 64];

        let package1 = Round1Package::new(participant.clone(), commitment, proof);
        let package2 = Round1Package::new(participant, commitment, proof);

        assert_eq!(package1.commitment_hash(), package2.commitment_hash());
    }

    #[test]
    fn test_round1_package_commitment_hash_different_for_different_commitments() {
        let participant = ParticipantId::from_bytes([0xAA; 32]);
        let commitment1 = [0xBB; 32];
        let commitment2 = [0xCC; 32];
        let proof = [0xDD; 64];

        let package1 = Round1Package::new(participant.clone(), commitment1, proof);
        let package2 = Round1Package::new(participant, commitment2, proof);

        assert_ne!(package1.commitment_hash(), package2.commitment_hash());
    }

    #[test]
    fn test_round1_package_commitment_hash_different_for_different_participants() {
        let participant1 = ParticipantId::from_bytes([0xAA; 32]);
        let participant2 = ParticipantId::from_bytes([0xBB; 32]);
        let commitment = [0xCC; 32];
        let proof = [0xDD; 64];

        let package1 = Round1Package::new(participant1, commitment, proof);
        let package2 = Round1Package::new(participant2, commitment, proof);

        assert_ne!(package1.commitment_hash(), package2.commitment_hash());
    }

    #[test]
    fn test_round1_package_clone() {
        let participant = ParticipantId::from_bytes([0xAA; 32]);
        let commitment = [0xBB; 32];
        let proof = [0xCC; 64];

        let package = Round1Package::new(participant.clone(), commitment, proof);
        let cloned = package.clone();

        assert_eq!(cloned.participant_id(), &participant);
        assert_eq!(cloned.commitment(), &commitment);
        assert_eq!(cloned.proof(), &proof);
    }

    #[test]
    fn test_round1_package_debug() {
        let participant = ParticipantId::from_bytes([0xAA; 32]);
        let commitment = [0xBB; 32];
        let proof = [0xCC; 64];

        let package = Round1Package::new(participant, commitment, proof);
        let debug = format!("{:?}", package);

        assert!(debug.contains("Round1Package"));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // ROUND2PACKAGE TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_round2_package_new() {
        let session = SessionId::from_bytes([0x11; 32]);
        let from = ParticipantId::from_bytes([0x22; 32]);
        let to = ParticipantId::from_bytes([0x33; 32]);
        let encrypted_share = vec![0x44u8; 32];

        let package = Round2Package::new(session.clone(), from.clone(), to.clone(), encrypted_share.clone());

        assert_eq!(package.session_id(), &session);
        assert_eq!(package.from_participant(), &from);
        assert_eq!(package.to_participant(), &to);
        assert_eq!(package.encrypted_share(), &encrypted_share[..]);
    }

    #[test]
    fn test_round2_package_decrypt_success() {
        let session = SessionId::from_bytes([0x11; 32]);
        let from = ParticipantId::from_bytes([0x22; 32]);
        let to = ParticipantId::from_bytes([0x33; 32]);

        // Create a key
        let key = EncryptionKey::from_bytes([0xAA; 32]).unwrap();

        // Create "encrypted" share: plaintext XOR key
        // Plaintext should be non-zero to pass SecretShare validation
        let plaintext = [0x42u8; 32];
        let mut encrypted = vec![0u8; 32];
        for (i, (p, k)) in plaintext.iter().zip(key.as_bytes().iter()).enumerate() {
            encrypted[i] = p ^ k;
        }

        let package = Round2Package::new(session, from, to, encrypted);

        let decrypted = package.decrypt(&key);
        assert!(decrypted.is_ok());

        let share = decrypted.unwrap();
        assert_eq!(share.as_bytes(), &plaintext);
    }

    #[test]
    fn test_round2_package_decrypt_invalid_length() {
        let session = SessionId::from_bytes([0x11; 32]);
        let from = ParticipantId::from_bytes([0x22; 32]);
        let to = ParticipantId::from_bytes([0x33; 32]);

        // Invalid length - too short
        let encrypted_share = vec![0x44u8; 16];
        let package = Round2Package::new(session, from, to, encrypted_share);

        let key = EncryptionKey::from_bytes([0xAA; 32]).unwrap();
        let result = package.decrypt(&key);

        assert!(result.is_err());
        match result {
            Err(DKGError::InvalidRound2Package { reason, .. }) => {
                assert!(reason.contains("ciphertext length"));
            }
            _ => panic!("expected InvalidRound2Package"),
        }
    }

    #[test]
    fn test_round2_package_decrypt_produces_zero_share() {
        let session = SessionId::from_bytes([0x11; 32]);
        let from = ParticipantId::from_bytes([0x22; 32]);
        let to = ParticipantId::from_bytes([0x33; 32]);

        // Create a key
        let key = EncryptionKey::from_bytes([0xAA; 32]).unwrap();

        // Create encrypted share that decrypts to all zeros
        // encrypted = 0 XOR key = key
        let encrypted = key.as_bytes().to_vec();

        let package = Round2Package::new(session, from, to, encrypted);

        let result = package.decrypt(&key);
        assert!(result.is_err());
        match result {
            Err(DKGError::InvalidRound2Package { reason, .. }) => {
                assert!(reason.contains("invalid share"));
            }
            _ => panic!("expected InvalidRound2Package"),
        }
    }

    #[test]
    fn test_round2_package_decrypt_error_does_not_leak_data() {
        let session = SessionId::from_bytes([0x11; 32]);
        let from = ParticipantId::from_bytes([0x22; 32]);
        let to = ParticipantId::from_bytes([0x33; 32]);
        let encrypted_share = vec![0x44u8; 16]; // Invalid length

        let package = Round2Package::new(session, from, to, encrypted_share);

        let key = EncryptionKey::from_bytes([0xAA; 32]).unwrap();
        let result = package.decrypt(&key);

        // Error message should not contain key bytes or ciphertext
        match result {
            Err(DKGError::InvalidRound2Package { reason, .. }) => {
                // Reason should not contain hex representation of key
                assert!(!reason.contains("aaaa"));
                assert!(!reason.contains("AAAA"));
            }
            _ => panic!("expected error"),
        }
    }

    #[test]
    fn test_round2_package_clone() {
        let session = SessionId::from_bytes([0x11; 32]);
        let from = ParticipantId::from_bytes([0x22; 32]);
        let to = ParticipantId::from_bytes([0x33; 32]);
        let encrypted_share = vec![0x44u8; 32];

        let package = Round2Package::new(session.clone(), from.clone(), to.clone(), encrypted_share.clone());
        let cloned = package.clone();

        assert_eq!(cloned.session_id(), &session);
        assert_eq!(cloned.from_participant(), &from);
        assert_eq!(cloned.to_participant(), &to);
        assert_eq!(cloned.encrypted_share(), &encrypted_share[..]);
    }

    #[test]
    fn test_round2_package_debug() {
        let session = SessionId::from_bytes([0x11; 32]);
        let from = ParticipantId::from_bytes([0x22; 32]);
        let to = ParticipantId::from_bytes([0x33; 32]);
        let encrypted_share = vec![0x44u8; 32];

        let package = Round2Package::new(session, from, to, encrypted_share);
        let debug = format!("{:?}", package);

        assert!(debug.contains("Round2Package"));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SEND + SYNC TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_packages_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Round1Package>();
        assert_send_sync::<Round2Package>();
    }

    // ────────────────────────────────────────────────────────────────────────────
    // CONSTANTS TESTS
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn test_constants() {
        assert_eq!(COMMITMENT_SIZE, 32);
        assert_eq!(PROOF_SIZE, 64);
    }
}