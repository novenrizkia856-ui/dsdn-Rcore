//! # Threshold Signer
//!
//! Module ini menyediakan `ThresholdSigner` trait dan `LocalThresholdSigner`
//! implementation untuk FROST threshold signing.
//!
//! ## Lifecycle
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                     LocalThresholdSigner Lifecycle                           │
//! └─────────────────────────────────────────────────────────────────────────────┘
//!
//!   new() ──► Ready (current_nonces = None)
//!                 │
//!                 │ create_commitment()
//!                 ▼
//!            HasCommitment (current_nonces = Some)
//!                 │
//!                 │ sign()
//!                 ▼
//!            Ready (current_nonces = None, nonces zeroized)
//! ```
//!
//! ## Keamanan
//!
//! - `SigningNonces` di-zeroize setelah digunakan
//! - Nonces tidak boleh di-reuse
//! - Error eksplisit untuk semua failure modes

use sha3::{Digest, Sha3_256};

use crate::dkg::KeyShare;
use crate::error::SigningError;
use crate::primitives::{FrostSignatureShare, ParticipantPublicKey, SigningCommitment, SCALAR_SIZE};
use crate::types::SignerId;

use super::commitment::{SigningCommitmentExt, SigningNonces};
use super::partial::{compute_binding_factor, compute_challenge, compute_group_commitment, PartialSignature};

// ════════════════════════════════════════════════════════════════════════════════
// THRESHOLD SIGNER TRAIT
// ════════════════════════════════════════════════════════════════════════════════

/// Trait untuk threshold signer dalam FROST protocol.
///
/// `ThresholdSigner` mendefinisikan interface untuk participant yang
/// berpartisipasi dalam threshold signing.
///
/// ## Methods
///
/// - `signer_id()`: Mengembalikan signer identifier
/// - `public_share()`: Mengembalikan participant public key
/// - `create_commitment()`: Generate signing commitment (MUTATES STATE)
/// - `sign()`: Create partial signature menggunakan stored nonces
pub trait ThresholdSigner {
    /// Mengembalikan reference ke signer ID.
    fn signer_id(&self) -> &SignerId;

    /// Mengembalikan reference ke participant public key.
    fn public_share(&self) -> &ParticipantPublicKey;

    /// Generate commitment untuk signing round.
    ///
    /// Method ini:
    /// 1. Generate new SigningNonces
    /// 2. Store nonces secara internal
    /// 3. Return SigningCommitment
    ///
    /// # Errors
    ///
    /// - `SigningError::InvalidCommitment` jika nonces sudah ada (belum di-consume)
    fn create_commitment(&mut self) -> Result<SigningCommitment, SigningError>;

    /// Create partial signature menggunakan stored nonces.
    ///
    /// Method ini:
    /// 1. Validate message consistency
    /// 2. Compute binding factor dan challenge
    /// 3. Compute signature share
    /// 4. CLEAR stored nonces (zeroize)
    /// 5. Return PartialSignature
    ///
    /// # Arguments
    ///
    /// * `message` - Message bytes yang akan di-sign
    /// * `own_commitment` - Commitment yang sudah di-broadcast
    /// * `all_commitments` - Semua commitments dari signers (HARUS sorted by SignerId)
    /// * `key_share` - KeyShare untuk signing
    ///
    /// # Errors
    ///
    /// - `SigningError::InvalidCommitment` jika nonces belum di-generate
    /// - `SigningError::InvalidCommitment` jika own_commitment tidak match
    fn sign(
        &mut self,
        message: &[u8],
        own_commitment: &SigningCommitment,
        all_commitments: &[(SignerId, SigningCommitment)],
        key_share: &KeyShare,
    ) -> Result<PartialSignature, SigningError>;
}

// ════════════════════════════════════════════════════════════════════════════════
// LOCAL THRESHOLD SIGNER
// ════════════════════════════════════════════════════════════════════════════════

/// Local implementation of `ThresholdSigner`.
///
/// `LocalThresholdSigner` manages the nonce lifecycle for signing:
/// - Generate nonces via `create_commitment()`
/// - Consume nonces via `sign()`
/// - Nonces are automatically zeroized after use
///
/// ## Keamanan
///
/// - Nonces stored in `Option<SigningNonces>` (None when consumed)
/// - SigningNonces derives ZeroizeOnDrop
/// - Nonces cannot be reused (checked at runtime)
pub struct LocalThresholdSigner {
    /// Signer identifier.
    signer_id: SignerId,

    /// Participant's public key.
    public_share: ParticipantPublicKey,

    /// Current signing nonces (None if not generated or already consumed).
    ///
    /// This field is:
    /// - `None` initially
    /// - `Some(nonces)` after `create_commitment()`
    /// - `None` after `sign()` (nonces consumed and zeroized)
    current_nonces: Option<SigningNonces>,
}

impl LocalThresholdSigner {
    /// Membuat `LocalThresholdSigner` baru.
    ///
    /// # Arguments
    ///
    /// * `signer_id` - Signer identifier
    /// * `public_share` - Participant's public key
    ///
    /// # Returns
    ///
    /// `LocalThresholdSigner` dengan nonces belum di-generate.
    #[must_use]
    pub fn new(signer_id: SignerId, public_share: ParticipantPublicKey) -> Self {
        Self {
            signer_id,
            public_share,
            current_nonces: None,
        }
    }

    /// Check apakah signer memiliki nonces yang pending.
    ///
    /// # Returns
    ///
    /// `true` jika ada nonces yang belum di-consume.
    #[must_use]
    pub fn has_pending_nonces(&self) -> bool {
        self.current_nonces.is_some()
    }

    /// Clear pending nonces (untuk abort/cleanup).
    ///
    /// Nonces akan di-zeroize karena `SigningNonces` implements `ZeroizeOnDrop`.
    pub fn clear_nonces(&mut self) {
        // Setting to None will drop the old value, triggering ZeroizeOnDrop
        self.current_nonces = None;
    }
}

impl ThresholdSigner for LocalThresholdSigner {
    fn signer_id(&self) -> &SignerId {
        &self.signer_id
    }

    fn public_share(&self) -> &ParticipantPublicKey {
        &self.public_share
    }

    fn create_commitment(&mut self) -> Result<SigningCommitment, SigningError> {
        // Check if nonces already exist (not yet consumed)
        if self.current_nonces.is_some() {
            return Err(SigningError::InvalidCommitment {
                signer: self.signer_id.clone(),
                reason: "nonces already generated, must sign or clear before creating new commitment".to_string(),
            });
        }

        // Generate new commitment and nonces
        let (commitment, nonces) = SigningCommitment::generate(&self.signer_id)
            .map_err(|e| SigningError::InvalidCommitment {
                signer: self.signer_id.clone(),
                reason: format!("failed to generate commitment: {}", e),
            })?;

        // Store nonces for later use in sign()
        self.current_nonces = Some(nonces);

        Ok(commitment)
    }

    fn sign(
        &mut self,
        message: &[u8],
        own_commitment: &SigningCommitment,
        all_commitments: &[(SignerId, SigningCommitment)],
        key_share: &KeyShare,
    ) -> Result<PartialSignature, SigningError> {
        // Step 1: Take nonces (this will clear current_nonces to None)
        // Nonces will be zeroized when dropped at end of function
        let nonces = self.current_nonces.take().ok_or_else(|| {
            SigningError::InvalidCommitment {
                signer: self.signer_id.clone(),
                reason: "no nonces available, must call create_commitment first".to_string(),
            }
        })?;

        // Step 2: Verify own commitment matches stored nonces
        let computed_commitment = nonces.compute_commitment().map_err(|e| {
            SigningError::InvalidCommitment {
                signer: self.signer_id.clone(),
                reason: format!("failed to compute commitment from nonces: {}", e),
            }
        })?;

        if computed_commitment.hiding() != own_commitment.hiding()
            || computed_commitment.binding() != own_commitment.binding()
        {
            return Err(SigningError::InvalidCommitment {
                signer: self.signer_id.clone(),
                reason: "own_commitment does not match stored nonces".to_string(),
            });
        }

        // Step 3: Verify our signer_id is in all_commitments
        let our_commitment_found = all_commitments
            .iter()
            .any(|(sid, _)| sid == &self.signer_id);
        
        if !our_commitment_found {
            return Err(SigningError::InvalidCommitment {
                signer: self.signer_id.clone(),
                reason: "signer not found in all_commitments".to_string(),
            });
        }

        // Step 4: Compute message hash
        let message_hash = compute_message_hash(message);

        // Step 5: Compute binding factor
        let binding_factor = compute_binding_factor(&self.signer_id, &message_hash, all_commitments);

        // Step 6: Build binding_factors map for group commitment
        let mut binding_factors = std::collections::HashMap::with_capacity(all_commitments.len());
        for (sid, _) in all_commitments {
            let bf = compute_binding_factor(sid, &message_hash, all_commitments);
            binding_factors.insert(sid.clone(), bf);
        }

        // Step 7: Compute group commitment (R)
        let group_commitment = compute_group_commitment(all_commitments, &binding_factors);

        // Step 8: Compute challenge
        let challenge = compute_challenge(&group_commitment, key_share.group_pubkey(), &message_hash);

        // Step 9: Compute signature share
        // In FROST: s_i = d_i + e_i * rho_i + lambda_i * s_i * c
        // Where:
        //   d_i = hiding_nonce
        //   e_i = binding_nonce  
        //   rho_i = binding_factor
        //   lambda_i = Lagrange coefficient (placeholder: use signer_id derived)
        //   s_i = secret_share
        //   c = challenge
        //
        // Placeholder implementation using hash for determinism:
        let signature_share_bytes = compute_signature_share(
            nonces.hiding_nonce().as_bytes(),
            nonces.binding_nonce().as_bytes(),
            &binding_factor,
            key_share.secret_share().as_bytes(),
            &challenge,
            &self.signer_id,
        )?;

        let signature_share = FrostSignatureShare::from_bytes(signature_share_bytes)
            .map_err(|e| SigningError::InvalidPartialSignature {
                signer: self.signer_id.clone(),
                reason: format!("invalid signature share: {}", e),
            })?;

        // Step 10: Build PartialSignature
        // Note: nonces will be dropped here, triggering ZeroizeOnDrop
        Ok(PartialSignature::new(
            self.signer_id.clone(),
            signature_share,
            own_commitment.clone(),
        ))
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════════

/// Compute hash of message.
///
/// Uses SHA3-256 with domain separation.
fn compute_message_hash(message: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"dsdn-tss-message-hash-v1");
    hasher.update(message);
    
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Compute signature share (placeholder implementation).
///
/// In real FROST:
/// s_i = d_i + e_i * rho_i + lambda_i * x_i * c
///
/// This placeholder uses hash-based computation for determinism.
fn compute_signature_share(
    hiding_nonce: &[u8; 32],
    binding_nonce: &[u8; 32],
    binding_factor: &[u8; 32],
    secret_share: &[u8; 32],
    challenge: &[u8; 32],
    signer_id: &SignerId,
) -> Result<[u8; 32], SigningError> {
    let mut hasher = Sha3_256::new();

    // Domain separator
    hasher.update(b"dsdn-tss-signature-share-v1");

    // d_i (hiding nonce)
    hasher.update(hiding_nonce);

    // e_i (binding nonce)
    hasher.update(binding_nonce);

    // rho_i (binding factor)
    hasher.update(binding_factor);

    // x_i (secret share)
    hasher.update(secret_share);

    // c (challenge)
    hasher.update(challenge);

    // signer_id (for uniqueness)
    hasher.update(signer_id.as_bytes());

    let result = hasher.finalize();
    let mut share = [0u8; SCALAR_SIZE];
    share.copy_from_slice(&result);

    // Validate non-zero
    if share.iter().all(|&b| b == 0) {
        return Err(SigningError::InvalidPartialSignature {
            signer: signer_id.clone(),
            reason: "computed signature share is zero".to_string(),
        });
    }

    Ok(share)
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{GroupPublicKey, SecretShare};
    use crate::types::ParticipantId;

    // ────────────────────────────────────────────────────────────────────────────
    // HELPER FUNCTIONS
    // ────────────────────────────────────────────────────────────────────────────

    fn make_signer_id(idx: u8) -> SignerId {
        SignerId::from_bytes([idx; 32])
    }

    fn make_public_share(idx: u8) -> ParticipantPublicKey {
        ParticipantPublicKey::from_bytes([idx; 32]).unwrap()
    }

    fn make_key_share(idx: u8) -> KeyShare {
        let secret_share = SecretShare::from_bytes([idx; 32]).unwrap();
        let group_pubkey = GroupPublicKey::from_bytes([0x01; 32]).unwrap();
        let participant_pubkey = ParticipantPublicKey::from_bytes([idx; 32]).unwrap();
        let participant_id = ParticipantId::from_bytes([idx; 32]);

        KeyShare::new(
            secret_share,
            group_pubkey,
            participant_pubkey,
            participant_id,
            2, // threshold
            3, // total
        )
    }

    fn make_signer(idx: u8) -> LocalThresholdSigner {
        LocalThresholdSigner::new(make_signer_id(idx), make_public_share(idx))
    }

    // ────────────────────────────────────────────────────────────────────────────
    // CONSTRUCTOR TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_local_threshold_signer_new() {
        let signer = make_signer(0x01);
        
        assert_eq!(signer.signer_id().as_bytes(), &[0x01; 32]);
        assert!(!signer.has_pending_nonces());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // CREATE COMMITMENT TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_create_commitment_success() {
        let mut signer = make_signer(0x01);
        
        let result = signer.create_commitment();
        assert!(result.is_ok());
        
        let commitment = result.unwrap();
        assert!(commitment.verify_format());
        assert!(signer.has_pending_nonces());
    }

    #[test]
    fn test_create_commitment_fails_if_nonces_exist() {
        let mut signer = make_signer(0x01);
        
        // First call succeeds
        let _ = signer.create_commitment().unwrap();
        
        // Second call should fail
        let result = signer.create_commitment();
        assert!(result.is_err());
        
        if let Err(SigningError::InvalidCommitment { signer: s, reason }) = result {
            assert_eq!(s.as_bytes(), &[0x01; 32]);
            assert!(reason.contains("already generated"));
        } else {
            panic!("Expected InvalidCommitment error");
        }
    }

    #[test]
    fn test_clear_nonces() {
        let mut signer = make_signer(0x01);
        
        let _ = signer.create_commitment().unwrap();
        assert!(signer.has_pending_nonces());
        
        signer.clear_nonces();
        assert!(!signer.has_pending_nonces());
        
        // Can create new commitment after clearing
        let result = signer.create_commitment();
        assert!(result.is_ok());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SIGN TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_sign_fails_without_commitment() {
        let mut signer = make_signer(0x01);
        let key_share = make_key_share(0x01);
        let commitment = SigningCommitment::from_parts([0x01; 32], [0x02; 32]).unwrap();
        let all_commitments = vec![(make_signer_id(0x01), commitment.clone())];
        
        let result = signer.sign(b"message", &commitment, &all_commitments, &key_share);
        assert!(result.is_err());
        
        if let Err(SigningError::InvalidCommitment { reason, .. }) = result {
            assert!(reason.contains("no nonces available"));
        } else {
            panic!("Expected InvalidCommitment error");
        }
    }

    #[test]
    fn test_sign_success() {
        let mut signer = make_signer(0x01);
        let key_share = make_key_share(0x01);
        
        // Create commitment
        let commitment = signer.create_commitment().unwrap();
        
        // All commitments includes our own
        let all_commitments = vec![(make_signer_id(0x01), commitment.clone())];
        
        // Sign
        let result = signer.sign(b"test message", &commitment, &all_commitments, &key_share);
        assert!(result.is_ok());
        
        let partial = result.unwrap();
        assert_eq!(partial.signer_id().as_bytes(), &[0x01; 32]);
        
        // Nonces should be cleared
        assert!(!signer.has_pending_nonces());
    }

    #[test]
    fn test_sign_clears_nonces() {
        let mut signer = make_signer(0x01);
        let key_share = make_key_share(0x01);
        
        let commitment = signer.create_commitment().unwrap();
        let all_commitments = vec![(make_signer_id(0x01), commitment.clone())];
        
        assert!(signer.has_pending_nonces());
        
        let _ = signer.sign(b"test", &commitment, &all_commitments, &key_share).unwrap();
        
        // Nonces should be cleared after sign
        assert!(!signer.has_pending_nonces());
        
        // Can create new commitment
        let result = signer.create_commitment();
        assert!(result.is_ok());
    }

    #[test]
    fn test_sign_fails_with_wrong_commitment() {
        let mut signer = make_signer(0x01);
        let key_share = make_key_share(0x01);
        
        let commitment = signer.create_commitment().unwrap();
        
        // Use different commitment
        let wrong_commitment = SigningCommitment::from_parts([0xAA; 32], [0xBB; 32]).unwrap();
        let all_commitments = vec![(make_signer_id(0x01), wrong_commitment.clone())];
        
        let result = signer.sign(b"test", &wrong_commitment, &all_commitments, &key_share);
        assert!(result.is_err());
        
        if let Err(SigningError::InvalidCommitment { reason, .. }) = result {
            assert!(reason.contains("does not match"));
        } else {
            panic!("Expected InvalidCommitment error");
        }
    }

    #[test]
    fn test_sign_fails_if_signer_not_in_commitments() {
        let mut signer = make_signer(0x01);
        let key_share = make_key_share(0x01);
        
        let commitment = signer.create_commitment().unwrap();
        
        // All commitments does NOT include our signer_id
        let other_commitment = SigningCommitment::from_parts([0xCC; 32], [0xDD; 32]).unwrap();
        let all_commitments = vec![(make_signer_id(0x02), other_commitment)];
        
        let result = signer.sign(b"test", &commitment, &all_commitments, &key_share);
        assert!(result.is_err());
        
        if let Err(SigningError::InvalidCommitment { reason, .. }) = result {
            assert!(reason.contains("not found"));
        } else {
            panic!("Expected InvalidCommitment error");
        }
    }

    #[test]
    fn test_sign_deterministic() {
        // Create two signers with same signer_id
        let mut signer1 = make_signer(0x01);
        let mut signer2 = make_signer(0x01);
        let key_share = make_key_share(0x01);
        
        // Note: Because nonce generation uses random, we can't test determinism
        // of the full sign flow. But we CAN test that compute_signature_share is deterministic.
        
        let hiding = [0x11; 32];
        let binding = [0x22; 32];
        let bf = [0x33; 32];
        let secret = [0x44; 32];
        let challenge = [0x55; 32];
        let signer_id = make_signer_id(0x01);
        
        let share1 = compute_signature_share(&hiding, &binding, &bf, &secret, &challenge, &signer_id).unwrap();
        let share2 = compute_signature_share(&hiding, &binding, &bf, &secret, &challenge, &signer_id).unwrap();
        
        assert_eq!(share1, share2);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // MULTIPLE SIGNERS TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_multiple_signers_sign() {
        let mut signer1 = make_signer(0x01);
        let mut signer2 = make_signer(0x02);
        
        let key_share1 = make_key_share(0x01);
        let key_share2 = make_key_share(0x02);
        
        // Both create commitments
        let commitment1 = signer1.create_commitment().unwrap();
        let commitment2 = signer2.create_commitment().unwrap();
        
        // Sorted all commitments
        let mut all_commitments = vec![
            (make_signer_id(0x01), commitment1.clone()),
            (make_signer_id(0x02), commitment2.clone()),
        ];
        all_commitments.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        
        // Both sign
        let partial1 = signer1.sign(b"shared message", &commitment1, &all_commitments, &key_share1).unwrap();
        let partial2 = signer2.sign(b"shared message", &commitment2, &all_commitments, &key_share2).unwrap();
        
        // Verify different signers produce different shares
        assert_ne!(
            partial1.signature_share().as_bytes(),
            partial2.signature_share().as_bytes()
        );
    }

    // ────────────────────────────────────────────────────────────────────────────
    // MESSAGE HASH TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_compute_message_hash_deterministic() {
        let hash1 = compute_message_hash(b"test message");
        let hash2 = compute_message_hash(b"test message");
        
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_compute_message_hash_different_messages() {
        let hash1 = compute_message_hash(b"message 1");
        let hash2 = compute_message_hash(b"message 2");
        
        assert_ne!(hash1, hash2);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SEND + SYNC TESTS
    // ────────────────────────────────────────────────────────────────────────────

    // Note: LocalThresholdSigner contains SigningNonces which may not be Send+Sync
    // This is intentional for security - nonces should not be shared across threads.
}