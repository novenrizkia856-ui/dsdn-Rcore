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
//!                 │ set_key_package()
//!                 ▼
//!            Ready (key_package = Some, current_nonces = None)
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
//! - `frost::round1::SigningNonces` di-zeroize saat di-drop
//! - Nonces tidak boleh di-reuse
//! - Error eksplisit untuk semua failure modes
//! - Real FROST round1::commit() dan round2::sign() digunakan
//! - Tidak ada placeholder nonce atau dummy signature share

use std::collections::BTreeMap;

use frost_ed25519 as frost;
use rand_core::{CryptoRng, RngCore};

use crate::dkg::KeyShare;
use crate::error::SigningError;
use crate::frost_adapter;
use crate::primitives::{FrostSignatureShare, ParticipantPublicKey, SigningCommitment};
use crate::types::SignerId;

use super::partial::PartialSignature;

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
    /// 1. Generate new SigningNonces via `frost::round1::commit()`
    /// 2. Store nonces secara internal
    /// 3. Return SigningCommitment (hiding + binding nonce commitments)
    ///
    /// # Errors
    ///
    /// - `SigningError::InvalidCommitment` jika nonces sudah ada (belum di-consume)
    /// - `SigningError::InvalidCommitment` jika key package belum di-set
    fn create_commitment(&mut self) -> Result<SigningCommitment, SigningError>;

    /// Create partial signature menggunakan stored nonces.
    ///
    /// Method ini:
    /// 1. Validate commitment matches stored nonces
    /// 2. Build frost `SigningPackage` dari message + all commitments
    /// 3. Call `frost::round2::sign()` untuk compute real signature share
    /// 4. CLEAR stored nonces (zeroized on drop)
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
/// - Set key package via `set_key_package()` (required before commitment)
/// - Generate nonces via `create_commitment()`
/// - Consume nonces via `sign()`
/// - Nonces are automatically zeroized when dropped
///
/// ## Keamanan
///
/// - Nonces stored in `Option<frost::round1::SigningNonces>` (None when consumed)
/// - `frost::round1::SigningNonces` derives `Zeroize` — cleared on drop
/// - Nonces cannot be reused (checked at runtime)
/// - Real FROST `round1::commit()` generates cryptographically secure nonces
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
    /// - `None` after `sign()` (nonces consumed and zeroized on drop)
    current_nonces: Option<frost::round1::SigningNonces>,

    /// Frost key package, needed for `round1::commit()`.
    ///
    /// Must be set via `set_key_package()` or `from_key_share()` before
    /// calling `create_commitment()`.
    key_package: Option<frost::keys::KeyPackage>,
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
    /// `LocalThresholdSigner` dengan nonces belum di-generate
    /// dan key package belum di-set.
    ///
    /// **PENTING**: Caller harus memanggil `set_key_package()` sebelum
    /// `create_commitment()`.
    #[must_use]
    pub fn new(signer_id: SignerId, public_share: ParticipantPublicKey) -> Self {
        Self {
            signer_id,
            public_share,
            current_nonces: None,
            key_package: None,
        }
    }

    /// Membuat `LocalThresholdSigner` dari `KeyShare`.
    ///
    /// Convenience constructor yang juga meng-set key package
    /// dari `KeyShare`, sehingga signer langsung siap untuk
    /// `create_commitment()`.
    ///
    /// `signer_id` diderivasi dari `key_share.participant_id()` bytes.
    ///
    /// # Errors
    ///
    /// Mengembalikan `SigningError::InvalidCommitment` jika konversi
    /// `KeyShare → frost KeyPackage` gagal.
    pub fn from_key_share(key_share: &KeyShare) -> Result<Self, SigningError> {
        let signer_id = SignerId::from_bytes(*key_share.participant_id().as_bytes());

        let public_share = key_share.participant_pubkey().clone();

        let key_package = frost_adapter::key_share_to_key_package(key_share)
            .map_err(|e| SigningError::InvalidCommitment {
                signer: signer_id.clone(),
                reason: format!("failed to convert KeyShare to frost KeyPackage: {}", e),
            })?;

        Ok(Self {
            signer_id,
            public_share,
            current_nonces: None,
            key_package: Some(key_package),
        })
    }

    /// Set frost key package dari `KeyShare`.
    ///
    /// WAJIB dipanggil sebelum `create_commitment()` jika signer
    /// dibuat via `new()`.
    ///
    /// # Errors
    ///
    /// Mengembalikan `SigningError::InvalidCommitment` jika konversi gagal.
    pub fn set_key_package(&mut self, key_share: &KeyShare) -> Result<(), SigningError> {
        let key_package = frost_adapter::key_share_to_key_package(key_share)
            .map_err(|e| SigningError::InvalidCommitment {
                signer: self.signer_id.clone(),
                reason: format!("failed to convert KeyShare to frost KeyPackage: {}", e),
            })?;
        self.key_package = Some(key_package);
        Ok(())
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

    /// Check apakah key package sudah di-set.
    #[must_use]
    pub fn has_key_package(&self) -> bool {
        self.key_package.is_some()
    }

    /// Clear pending nonces (untuk abort/cleanup).
    ///
    /// Nonces akan di-zeroize karena `frost::round1::SigningNonces`
    /// implements `Zeroize` — drop triggers zeroization.
    pub fn clear_nonces(&mut self) {
        // Setting to None will drop the old value, triggering Zeroize
        self.current_nonces = None;
    }

    /// Generate commitment dengan explicit RNG.
    ///
    /// Identical dengan `create_commitment()` tetapi menerima RNG
    /// sebagai parameter. Berguna untuk deterministic testing.
    ///
    /// # Arguments
    ///
    /// * `rng` - Cryptographically secure RNG
    ///
    /// # Errors
    ///
    /// - `SigningError::InvalidCommitment` jika nonces sudah ada
    /// - `SigningError::InvalidCommitment` jika key package belum di-set
    pub fn create_commitment_with_rng<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<SigningCommitment, SigningError> {
        // Check if nonces already exist (not yet consumed)
        if self.current_nonces.is_some() {
            return Err(SigningError::InvalidCommitment {
                signer: self.signer_id.clone(),
                reason: "nonces already generated, must sign or clear before creating new commitment".to_string(),
            });
        }

        // Get signing share from stored key package
        let kp = self.key_package.as_ref().ok_or_else(|| {
            SigningError::InvalidCommitment {
                signer: self.signer_id.clone(),
                reason: "no key package set, call set_key_package() or use from_key_share() before creating commitment".to_string(),
            }
        })?;

        // Generate real FROST nonces and commitments
        let (nonces, commitments) = frost::round1::commit(kp.signing_share(), rng);

        // Convert frost SigningCommitments to our SigningCommitment
        let commitment = frost_adapter::signing_commitments_to_commitment(&commitments)
            .map_err(|e| SigningError::InvalidCommitment {
                signer: self.signer_id.clone(),
                reason: format!("failed to convert frost commitments: {}", e),
            })?;

        // Store nonces for later use in sign()
        self.current_nonces = Some(nonces);

        Ok(commitment)
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
        self.create_commitment_with_rng(&mut rand_core::OsRng)
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
        let computed_frost_commitments = frost::round1::SigningCommitments::from(&nonces);
        let computed_commitment =
            frost_adapter::signing_commitments_to_commitment(&computed_frost_commitments)
                .map_err(|e| SigningError::InvalidCommitment {
                    signer: self.signer_id.clone(),
                    reason: format!("failed to compute commitment from nonces: {}", e),
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

        // Step 4: Build frost commitments map (Identifier → SigningCommitments)
        let mut frost_commitments_map = BTreeMap::new();
        for (sid, commitment) in all_commitments {
            let frost_id = frost_adapter::signer_id_to_frost_identifier(sid)
                .map_err(|e| SigningError::InvalidCommitment {
                    signer: sid.clone(),
                    reason: format!("failed to convert SignerId to frost Identifier: {}", e),
                })?;
            let frost_commitment =
                frost_adapter::commitment_to_signing_commitments(commitment)
                    .map_err(|e| SigningError::InvalidCommitment {
                        signer: sid.clone(),
                        reason: format!("failed to convert commitment to frost format: {}", e),
                    })?;
            frost_commitments_map.insert(frost_id, frost_commitment);
        }

        // Step 5: Build frost SigningPackage
        let signing_package = frost::SigningPackage::new(frost_commitments_map, message);

        // Step 6: Convert KeyShare to frost KeyPackage
        let key_package = frost_adapter::key_share_to_key_package(key_share)
            .map_err(|e| SigningError::InvalidPartialSignature {
                signer: self.signer_id.clone(),
                reason: format!("failed to convert KeyShare to frost KeyPackage: {}", e),
            })?;

        // Step 7: Compute real FROST partial signature
        let frost_share = frost::round2::sign(&signing_package, &nonces, &key_package)
            .map_err(|e| SigningError::InvalidPartialSignature {
                signer: self.signer_id.clone(),
                reason: format!("frost round2 sign failed: {}", e),
            })?;

        // Step 8: Convert frost SignatureShare to our FrostSignatureShare
        let signature_share = frost_adapter::signature_share_to_sig_share(&frost_share)
            .map_err(|e| SigningError::InvalidPartialSignature {
                signer: self.signer_id.clone(),
                reason: format!("failed to convert frost signature share: {}", e),
            })?;

        // Step 9: Build PartialSignature
        // Note: nonces will be dropped here, triggering Zeroize
        Ok(PartialSignature::new(
            self.signer_id.clone(),
            signature_share,
            own_commitment.clone(),
        ))
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost_adapter::{
        key_package_to_key_share, signature_share_to_sig_share,
        signing_commitments_to_commitment, commitment_to_signing_commitments,
        sig_share_to_signature_share, signer_id_to_frost_identifier,
    };
    use crate::signing::commitment::SigningCommitmentExt;
    use frost_ed25519 as frost;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::collections::BTreeMap;

    // ────────────────────────────────────────────────────────────────────────────
    // HELPER FUNCTIONS
    // ────────────────────────────────────────────────────────────────────────────

    /// Generate deterministic frost key material (t-of-n).
    fn generate_frost_keys(
        n: u16,
        t: u16,
        seed: u64,
    ) -> (
        BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
        frost::keys::PublicKeyPackage,
    ) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let (shares, pubkey_package) = frost::keys::generate_with_dealer(
            n,
            t,
            frost::keys::IdentifierList::Default,
            &mut rng,
        )
        .expect("dealer keygen must succeed with valid params");

        let mut key_packages = BTreeMap::new();
        for (identifier, secret_share) in shares {
            let key_package = frost::keys::KeyPackage::try_from(secret_share)
                .expect("KeyPackage from SecretShare must succeed");
            key_packages.insert(identifier, key_package);
        }
        (key_packages, pubkey_package)
    }

    /// Convert frost Identifier to SignerId.
    fn frost_id_to_signer_id(id: &frost::Identifier) -> SignerId {
        let bytes = id.serialize();
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .expect("frost Identifier is 32 bytes");
        SignerId::from_bytes(arr)
    }

    /// Create a LocalThresholdSigner from frost KeyPackage.
    fn make_signer_from_kp(kp: &frost::keys::KeyPackage, total: u8) -> LocalThresholdSigner {
        let key_share = key_package_to_key_share(kp, total)
            .expect("key_package_to_key_share must succeed");
        LocalThresholdSigner::from_key_share(&key_share)
            .expect("from_key_share must succeed")
    }

    /// Create KeyShare from frost KeyPackage.
    fn kp_to_key_share(kp: &frost::keys::KeyPackage, total: u8) -> KeyShare {
        key_package_to_key_share(kp, total).expect("conversion must succeed")
    }

    // ────────────────────────────────────────────────────────────────────────────
    // CONSTRUCTOR TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_local_threshold_signer_new() {
        let (key_packages, _) = generate_frost_keys(3, 2, 42);
        let kp = key_packages.values().next().expect("must have key package");
        let signer = make_signer_from_kp(kp, 3);

        assert!(!signer.has_pending_nonces());
        assert!(signer.has_key_package());
    }

    #[test]
    fn test_new_without_key_package() {
        let signer_id = SignerId::from_bytes([0x01; 32]);
        let (key_packages, _) = generate_frost_keys(3, 2, 42);
        let kp = key_packages.values().next().expect("must have key package");
        let ks = kp_to_key_share(kp, 3);
        let public_share = ks.participant_pubkey().clone();

        let signer = LocalThresholdSigner::new(signer_id, public_share);
        assert!(!signer.has_pending_nonces());
        assert!(!signer.has_key_package());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // CREATE COMMITMENT TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_create_commitment_success() {
        let (key_packages, _) = generate_frost_keys(3, 2, 42);
        let kp = key_packages.values().next().expect("must have key package");
        let mut signer = make_signer_from_kp(kp, 3);

        let result = signer.create_commitment();
        assert!(result.is_ok());

        let commitment = result.expect("just checked is_ok");
        assert!(commitment.verify_format());
        assert!(signer.has_pending_nonces());
    }

    #[test]
    fn test_create_commitment_fails_if_nonces_exist() {
        let (key_packages, _) = generate_frost_keys(3, 2, 42);
        let kp = key_packages.values().next().expect("must have key package");
        let mut signer = make_signer_from_kp(kp, 3);

        // First call succeeds
        let _ = signer.create_commitment().expect("first commitment ok");

        // Second call should fail
        let result = signer.create_commitment();
        assert!(result.is_err());

        if let Err(SigningError::InvalidCommitment { reason, .. }) = result {
            assert!(reason.contains("already generated"));
        } else {
            unreachable!("Expected InvalidCommitment error");
        }
    }

    #[test]
    fn test_create_commitment_fails_without_key_package() {
        let signer_id = SignerId::from_bytes([0x01; 32]);
        let (key_packages, _) = generate_frost_keys(3, 2, 42);
        let kp = key_packages.values().next().expect("must have key package");
        let ks = kp_to_key_share(kp, 3);
        let public_share = ks.participant_pubkey().clone();

        let mut signer = LocalThresholdSigner::new(signer_id, public_share);
        let result = signer.create_commitment();
        assert!(result.is_err());

        if let Err(SigningError::InvalidCommitment { reason, .. }) = result {
            assert!(reason.contains("no key package set"));
        } else {
            unreachable!("Expected InvalidCommitment error");
        }
    }

    #[test]
    fn test_clear_nonces() {
        let (key_packages, _) = generate_frost_keys(3, 2, 42);
        let kp = key_packages.values().next().expect("must have key package");
        let mut signer = make_signer_from_kp(kp, 3);

        let _ = signer.create_commitment().expect("first commitment ok");
        assert!(signer.has_pending_nonces());

        signer.clear_nonces();
        assert!(!signer.has_pending_nonces());

        // Can create new commitment after clearing
        let result = signer.create_commitment();
        assert!(result.is_ok());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 7: SIGNING BEFORE COMMITMENT → ERROR
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_sign_fails_without_commitment() {
        let (key_packages, _) = generate_frost_keys(3, 2, 42);
        let (frost_id, kp) = key_packages.iter().next().expect("must have key package");
        let mut signer = make_signer_from_kp(kp, 3);
        let key_share = kp_to_key_share(kp, 3);
        let signer_id = frost_id_to_signer_id(frost_id);

        // Create a dummy commitment for the API call
        // (signer hasn't called create_commitment yet)
        let (_, dummy_commitments) = {
            let mut rng = ChaCha20Rng::seed_from_u64(999);
            frost::round1::commit(kp.signing_share(), &mut rng)
        };
        let dummy_our = signing_commitments_to_commitment(&dummy_commitments)
            .expect("conversion ok");

        let all_commitments = vec![(signer_id, dummy_our.clone())];

        let result = signer.sign(b"message", &dummy_our, &all_commitments, &key_share);
        assert!(result.is_err());

        if let Err(SigningError::InvalidCommitment { reason, .. }) = result {
            assert!(reason.contains("no nonces available"));
        } else {
            unreachable!("Expected InvalidCommitment error");
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 4: INVALID STATE TRANSITION REJECTION
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_invalid_state_transition_double_commitment_rejected() {
        let (key_packages, _) = generate_frost_keys(3, 2, 42);
        let kp = key_packages.values().next().expect("must have key package");
        let mut signer = make_signer_from_kp(kp, 3);

        // First commitment succeeds
        let _ = signer.create_commitment().expect("first ok");

        // Second commitment REJECTED — nonces already pending
        let result = signer.create_commitment();
        assert!(result.is_err());
        if let Err(SigningError::InvalidCommitment { reason, .. }) = &result {
            assert!(reason.contains("already generated"));
        } else {
            unreachable!("Expected InvalidCommitment");
        }
    }

    #[test]
    fn test_sign_fails_with_wrong_commitment() {
        let (key_packages, _) = generate_frost_keys(3, 2, 42);
        let (frost_id, kp) = key_packages.iter().next().expect("must have key package");
        let mut signer = make_signer_from_kp(kp, 3);
        let key_share = kp_to_key_share(kp, 3);
        let signer_id = frost_id_to_signer_id(frost_id);

        // Create real commitment
        let _real_commitment = signer.create_commitment().expect("commitment ok");

        // Use a different commitment as own_commitment
        let (_, wrong_frost_commitments) = {
            let mut rng = ChaCha20Rng::seed_from_u64(12345);
            frost::round1::commit(kp.signing_share(), &mut rng)
        };
        let wrong_commitment = signing_commitments_to_commitment(&wrong_frost_commitments)
            .expect("conversion ok");

        let all_commitments = vec![(signer_id, wrong_commitment.clone())];

        let result = signer.sign(b"test", &wrong_commitment, &all_commitments, &key_share);
        assert!(result.is_err());

        if let Err(SigningError::InvalidCommitment { reason, .. }) = result {
            assert!(reason.contains("does not match"));
        } else {
            unreachable!("Expected InvalidCommitment error");
        }
    }

    #[test]
    fn test_sign_fails_if_signer_not_in_commitments() {
        let (key_packages, _) = generate_frost_keys(3, 2, 42);
        let mut iter = key_packages.iter();
        let (_, kp1) = iter.next().expect("must have kp");
        let (frost_id2, kp2) = iter.next().expect("must have kp2");
        let mut signer = make_signer_from_kp(kp1, 3);
        let key_share = kp_to_key_share(kp1, 3);

        // Create commitment
        let commitment = signer.create_commitment().expect("commitment ok");

        // All commitments uses a DIFFERENT signer id
        let other_signer_id = frost_id_to_signer_id(frost_id2);
        let (_, other_frost_comm) = {
            let mut rng = ChaCha20Rng::seed_from_u64(777);
            frost::round1::commit(kp2.signing_share(), &mut rng)
        };
        let other_commitment = signing_commitments_to_commitment(&other_frost_comm)
            .expect("conversion ok");

        let all_commitments = vec![(other_signer_id, other_commitment)];

        let result = signer.sign(b"test", &commitment, &all_commitments, &key_share);
        assert!(result.is_err());

        if let Err(SigningError::InvalidCommitment { reason, .. }) = result {
            assert!(reason.contains("not found"));
        } else {
            unreachable!("Expected InvalidCommitment error");
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 3: NONCE REUSE REJECTION
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_nonce_reuse_rejection() {
        let (key_packages, _) = generate_frost_keys(5, 3, 42);
        let signers_vec: Vec<_> = key_packages.iter().take(3).collect();
        let (frost_id0, kp0) = signers_vec[0];

        let mut signer = make_signer_from_kp(kp0, 5);
        let key_share = kp_to_key_share(kp0, 5);
        let signer_id0 = frost_id_to_signer_id(frost_id0);

        // Generate commitment + collect other commitments
        let mut rng = ChaCha20Rng::seed_from_u64(200);
        let commitment0 = signer
            .create_commitment_with_rng(&mut rng)
            .expect("commitment ok");

        let mut all_commitments = vec![(signer_id0.clone(), commitment0.clone())];

        for &(fid, kp) in &signers_vec[1..] {
            let sid = frost_id_to_signer_id(fid);
            let (_, fc) = frost::round1::commit(kp.signing_share(), &mut rng);
            let c = signing_commitments_to_commitment(&fc).expect("ok");
            all_commitments.push((sid, c));
        }
        all_commitments.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));

        // First sign succeeds
        let result = signer.sign(b"message", &commitment0, &all_commitments, &key_share);
        assert!(result.is_ok());

        // Nonces consumed — second sign MUST fail
        assert!(!signer.has_pending_nonces());
        let result2 = signer.sign(b"message", &commitment0, &all_commitments, &key_share);
        assert!(result2.is_err());
        if let Err(SigningError::InvalidCommitment { reason, .. }) = result2 {
            assert!(reason.contains("no nonces available"));
        } else {
            unreachable!("Expected InvalidCommitment for nonce reuse");
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 1: 3-of-5 THRESHOLD SIGNING SUCCESS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_3_of_5_threshold_signing_success() {
        let (key_packages, pubkey_package) = generate_frost_keys(5, 3, 42);

        // Select first 3 signers
        let selected: Vec<_> = key_packages.iter().take(3).collect();

        let mut signers: Vec<LocalThresholdSigner> = Vec::new();
        let mut key_shares: Vec<KeyShare> = Vec::new();
        let mut signer_ids: Vec<SignerId> = Vec::new();

        for &(frost_id, kp) in &selected {
            let s = make_signer_from_kp(kp, 5);
            let ks = kp_to_key_share(kp, 5);
            let sid = frost_id_to_signer_id(frost_id);
            signers.push(s);
            key_shares.push(ks);
            signer_ids.push(sid);
        }

        // Round 1: Generate commitments
        let mut all_commitments: Vec<(SignerId, SigningCommitment)> = Vec::new();
        let mut own_commitments: Vec<SigningCommitment> = Vec::new();
        for signer in &mut signers {
            let c = signer.create_commitment().expect("commitment ok");
            all_commitments.push((signer.signer_id().clone(), c.clone()));
            own_commitments.push(c);
        }
        all_commitments.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));

        // Round 2: Generate partial signatures
        let message = b"DSDN threshold signing test message";
        let mut partial_sigs = Vec::new();
        for (i, signer) in signers.iter_mut().enumerate() {
            let partial = signer
                .sign(message, &own_commitments[i], &all_commitments, &key_shares[i])
                .expect("sign ok");
            partial_sigs.push(partial);
        }

        // Verify: Reconstruct frost types and aggregate
        let mut frost_signature_shares = BTreeMap::new();
        let mut frost_commitments_map = BTreeMap::new();
        for (i, partial) in partial_sigs.iter().enumerate() {
            let frost_id = signer_id_to_frost_identifier(&signer_ids[i])
                .expect("conversion ok");
            let frost_share = sig_share_to_signature_share(partial.signature_share())
                .expect("conversion ok");
            frost_signature_shares.insert(frost_id, frost_share);

            let frost_comm = commitment_to_signing_commitments(&own_commitments[i])
                .expect("conversion ok");
            frost_commitments_map.insert(frost_id, frost_comm);
        }

        let signing_package = frost::SigningPackage::new(frost_commitments_map, &message[..]);
        let group_sig = frost::aggregate(&signing_package, &frost_signature_shares, &pubkey_package);
        assert!(group_sig.is_ok(), "FROST aggregation must succeed");

        // Verify the aggregate signature
        let sig = group_sig.expect("just checked is_ok");
        let vk = pubkey_package.verifying_key();
        let verify_result = vk.verify(message, &sig);
        assert!(verify_result.is_ok(), "Aggregate signature must verify");
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 5: PARTIAL SIGNATURE VALID FOR AGGREGATION
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_partial_signature_valid_for_aggregation() {
        // Full 3-of-5 flow with verification
        let (key_packages, pubkey_package) = generate_frost_keys(5, 3, 100);

        let selected: Vec<_> = key_packages.iter().take(3).collect();
        let mut rng = ChaCha20Rng::seed_from_u64(101);
        let message = b"aggregation verification test";

        let mut signers: Vec<LocalThresholdSigner> = Vec::new();
        let mut key_shares: Vec<KeyShare> = Vec::new();
        let mut signer_ids: Vec<SignerId> = Vec::new();

        for &(fid, kp) in &selected {
            signers.push(make_signer_from_kp(kp, 5));
            key_shares.push(kp_to_key_share(kp, 5));
            signer_ids.push(frost_id_to_signer_id(fid));
        }

        // Commitments
        let mut all_commitments: Vec<(SignerId, SigningCommitment)> = Vec::new();
        let mut own_commitments: Vec<SigningCommitment> = Vec::new();
        for signer in &mut signers {
            let c = signer.create_commitment_with_rng(&mut rng).expect("ok");
            all_commitments.push((signer.signer_id().clone(), c.clone()));
            own_commitments.push(c);
        }
        all_commitments.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));

        // Sign
        let mut partial_sigs = Vec::new();
        for (i, signer) in signers.iter_mut().enumerate() {
            let p = signer
                .sign(message, &own_commitments[i], &all_commitments, &key_shares[i])
                .expect("sign ok");
            partial_sigs.push(p);
        }

        // Aggregate and verify
        let mut frost_shares = BTreeMap::new();
        let mut frost_comms = BTreeMap::new();
        for (i, partial) in partial_sigs.iter().enumerate() {
            let fid = signer_id_to_frost_identifier(&signer_ids[i]).expect("ok");
            frost_shares.insert(
                fid,
                sig_share_to_signature_share(partial.signature_share()).expect("ok"),
            );
            frost_comms.insert(
                fid,
                commitment_to_signing_commitments(&own_commitments[i]).expect("ok"),
            );
        }

        let sp = frost::SigningPackage::new(frost_comms, &message[..]);
        let agg = frost::aggregate(&sp, &frost_shares, &pubkey_package);
        assert!(agg.is_ok(), "aggregation must succeed");

        let sig = agg.expect("just checked");
        assert!(
            pubkey_package.verifying_key().verify(message, &sig).is_ok(),
            "aggregate signature must verify"
        );
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 2: COMMITMENT DETERMINISTIC PER NONCE SEED
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_commitment_deterministic_per_nonce_seed() {
        let (key_packages, _) = generate_frost_keys(3, 2, 42);
        let kp = key_packages.values().next().expect("must have key package");

        // Same seed → same commitment
        let mut signer1 = make_signer_from_kp(kp, 3);
        let mut signer2 = make_signer_from_kp(kp, 3);

        let mut rng1 = ChaCha20Rng::seed_from_u64(999);
        let mut rng2 = ChaCha20Rng::seed_from_u64(999);

        let c1 = signer1
            .create_commitment_with_rng(&mut rng1)
            .expect("ok");
        let c2 = signer2
            .create_commitment_with_rng(&mut rng2)
            .expect("ok");

        assert_eq!(c1.hiding(), c2.hiding(), "same seed must produce same hiding");
        assert_eq!(
            c1.binding(),
            c2.binding(),
            "same seed must produce same binding"
        );

        // Different seed → different commitment
        let mut signer3 = make_signer_from_kp(kp, 3);
        let mut rng3 = ChaCha20Rng::seed_from_u64(1000);
        let c3 = signer3
            .create_commitment_with_rng(&mut rng3)
            .expect("ok");

        assert_ne!(
            c1.hiding(),
            c3.hiding(),
            "different seed should produce different commitment"
        );
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 6: DIFFERENT MESSAGE → DIFFERENT SIGNATURE SHARE
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_different_message_different_signature_share() {
        let (key_packages, _) = generate_frost_keys(5, 3, 42);

        let selected: Vec<_> = key_packages.iter().take(3).collect();

        // Helper to run signing with a specific message
        let do_sign = |msg: &[u8], rng_seed: u64| -> FrostSignatureShare {
            let mut rng = ChaCha20Rng::seed_from_u64(rng_seed);
            let mut signers: Vec<LocalThresholdSigner> = Vec::new();
            let mut key_shares: Vec<KeyShare> = Vec::new();

            for &(_, kp) in &selected {
                signers.push(make_signer_from_kp(kp, 5));
                key_shares.push(kp_to_key_share(kp, 5));
            }

            let mut all_c: Vec<(SignerId, SigningCommitment)> = Vec::new();
            let mut own_c: Vec<SigningCommitment> = Vec::new();
            for signer in &mut signers {
                let c = signer.create_commitment_with_rng(&mut rng).expect("ok");
                all_c.push((signer.signer_id().clone(), c.clone()));
                own_c.push(c);
            }
            all_c.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));

            // Only get the first signer's partial
            let p = signers[0]
                .sign(msg, &own_c[0], &all_c, &key_shares[0])
                .expect("sign ok");
            p.signature_share().clone()
        };

        let share_a = do_sign(b"message A", 200);
        let share_b = do_sign(b"message B", 200);

        assert_ne!(
            share_a.as_bytes(),
            share_b.as_bytes(),
            "different messages must produce different signature shares"
        );
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SIGN LIFECYCLE TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_sign_clears_nonces() {
        let (key_packages, _) = generate_frost_keys(5, 3, 42);
        let selected: Vec<_> = key_packages.iter().take(3).collect();

        let (fid0, kp0) = selected[0];
        let mut signer = make_signer_from_kp(kp0, 5);
        let key_share = kp_to_key_share(kp0, 5);

        let commitment0 = signer.create_commitment().expect("ok");
        assert!(signer.has_pending_nonces());

        // Build all_commitments
        let mut rng = ChaCha20Rng::seed_from_u64(300);
        let sid0 = frost_id_to_signer_id(fid0);
        let mut all_c = vec![(sid0, commitment0.clone())];
        for &(fid, kp) in &selected[1..] {
            let (_, fc) = frost::round1::commit(kp.signing_share(), &mut rng);
            let c = signing_commitments_to_commitment(&fc).expect("ok");
            all_c.push((frost_id_to_signer_id(fid), c));
        }
        all_c.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));

        let _ = signer
            .sign(b"test", &commitment0, &all_c, &key_share)
            .expect("sign ok");

        // Nonces cleared after sign
        assert!(!signer.has_pending_nonces());

        // Can create new commitment
        let result = signer.create_commitment();
        assert!(result.is_ok());
    }

    #[test]
    fn test_multiple_signers_produce_different_shares() {
        let (key_packages, _) = generate_frost_keys(5, 3, 42);
        let selected: Vec<_> = key_packages.iter().take(3).collect();

        let mut signers: Vec<LocalThresholdSigner> = Vec::new();
        let mut key_shares: Vec<KeyShare> = Vec::new();

        for &(_, kp) in &selected {
            signers.push(make_signer_from_kp(kp, 5));
            key_shares.push(kp_to_key_share(kp, 5));
        }

        let mut all_c: Vec<(SignerId, SigningCommitment)> = Vec::new();
        let mut own_c: Vec<SigningCommitment> = Vec::new();
        for signer in &mut signers {
            let c = signer.create_commitment().expect("ok");
            all_c.push((signer.signer_id().clone(), c.clone()));
            own_c.push(c);
        }
        all_c.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));

        let message = b"shared message";
        let p0 = signers[0]
            .sign(message, &own_c[0], &all_c, &key_shares[0])
            .expect("ok");
        let p1 = signers[1]
            .sign(message, &own_c[1], &all_c, &key_shares[1])
            .expect("ok");

        assert_ne!(
            p0.signature_share().as_bytes(),
            p1.signature_share().as_bytes(),
            "different signers must produce different shares"
        );
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SET KEY PACKAGE TEST
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_set_key_package_enables_commitment() {
        let (key_packages, _) = generate_frost_keys(3, 2, 42);
        let (frost_id, kp) = key_packages.iter().next().expect("must have kp");
        let key_share = kp_to_key_share(kp, 3);
        let signer_id = frost_id_to_signer_id(frost_id);
        let public_share = key_share.participant_pubkey().clone();

        let mut signer = LocalThresholdSigner::new(signer_id, public_share);
        assert!(!signer.has_key_package());

        // Fails before key package set
        assert!(signer.create_commitment().is_err());

        // Set key package
        signer.set_key_package(&key_share).expect("set ok");
        assert!(signer.has_key_package());

        // Now succeeds
        assert!(signer.create_commitment().is_ok());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SEND + SYNC TESTS
    // ────────────────────────────────────────────────────────────────────────────

    // Note: LocalThresholdSigner contains frost::round1::SigningNonces
    // which may not be Send+Sync. This is intentional for security
    // — nonces should not be shared across threads.
}