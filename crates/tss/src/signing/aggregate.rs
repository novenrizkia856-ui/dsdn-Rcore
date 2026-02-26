//! # Aggregate Signature
//!
//! Module ini menyediakan `AggregateSignature` struct dan fungsi
//! `aggregate_signatures` untuk FROST threshold signing.
//!
//! ## Aggregation Flow (Real FROST)
//!
//! ```text
//! message + commitments ──► frost::SigningPackage
//!                                    │
//!                                    ▼
//! signature_shares + pubkey_package ──► frost::aggregate()
//!                                    │
//!                                    ▼
//!                           frost::Signature (64 bytes, R ‖ s)
//!                                    │
//!                                    ▼
//!                           AggregateSignature
//! ```
//!
//! ## Format Serialization
//!
//! | Field | Offset | Size | Description |
//! |-------|--------|------|-------------|
//! | signature | 0 | 64 | FrostSignature (R ‖ s) |
//! | signer_count | 64 | 1 | Jumlah signers (u8) |
//! | signers | 65 | 32*n | Signer IDs |
//! | message_hash | 65+32*n | 32 | Message hash |

use std::collections::{BTreeMap, HashSet};

use frost_ed25519 as frost;

use crate::error::SigningError;
use crate::frost_adapter;
use crate::primitives::{
    FrostSignature, GroupPublicKey, ParticipantPublicKey, SigningCommitment, SIGNATURE_SIZE,
};
use crate::types::SignerId;

use super::partial::PartialSignature;

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
/// - `FrostSignature` (R ‖ s) — real Ed25519 signature (64 bytes)
/// - List signers yang berkontribusi
/// - Hash dari message yang di-sign
///
/// ## Invariant
///
/// - `signature` adalah valid 64-byte Ed25519 signature
/// - `signers` tidak boleh kosong
/// - Tidak boleh ada duplicate signers
#[derive(Debug, Clone)]
pub struct AggregateSignature {
    /// Inner FROST signature (R ‖ s), 64 bytes.
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
    /// * `signature` - FROST signature (R ‖ s), 64 bytes
    /// * `signers` - List signer IDs yang berkontribusi
    /// * `message_hash` - Hash dari message
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
// REAL FROST AGGREGATION
// ════════════════════════════════════════════════════════════════════════════════

/// Aggregate partial signatures menggunakan real `frost_ed25519::aggregate()`.
///
/// Fungsi ini membangun semua frost types yang diperlukan dari internal types,
/// kemudian memanggil `frost::aggregate()` untuk menghasilkan valid Ed25519
/// aggregate signature (64 bytes).
///
/// # Arguments
///
/// * `message` - Raw message bytes yang di-sign (frost hashes internally)
/// * `partials` - Slice of PartialSignature (mengandung SignerId, SignatureShare, Commitment)
/// * `group_pubkey` - Group public key hasil DKG
/// * `verifying_shares` - Per-participant verifying shares untuk signature share verification
/// * `message_hash` - Pre-computed hash of message (untuk AggregateSignature metadata)
///
/// # Errors
///
/// - `SigningError::InsufficientSignatures` jika partials kosong
/// - `SigningError::DuplicateSigner` jika ada signer duplikat
/// - `SigningError::AggregationFailed` jika frost aggregation gagal
///
/// # Kriptografi
///
/// Internally calls:
/// 1. Build `frost::SigningPackage` dari message + commitments
/// 2. Build `BTreeMap<Identifier, SignatureShare>` dari partials
/// 3. Build `frost::keys::PublicKeyPackage` dari group_pubkey + verifying_shares
/// 4. Call `frost::aggregate(signing_package, signature_shares, pubkey_package)`
/// 5. Convert 64-byte `frost::Signature` ke `AggregateSignature`
pub fn aggregate_signatures(
    message: &[u8],
    partials: &[PartialSignature],
    group_pubkey: &GroupPublicKey,
    verifying_shares: &[(SignerId, ParticipantPublicKey)],
    message_hash: &[u8; 32],
) -> Result<AggregateSignature, SigningError> {
    // Step 1: Validate partials not empty
    if partials.is_empty() {
        return Err(SigningError::InsufficientSignatures {
            expected: 1,
            got: 0,
        });
    }

    // Step 2: Validate no duplicate signers and collect signer IDs
    let mut seen_signers = HashSet::with_capacity(partials.len());
    let mut signers = Vec::with_capacity(partials.len());

    for partial in partials {
        let signer_id = partial.signer_id().clone();
        if !seen_signers.insert(signer_id.clone()) {
            return Err(SigningError::DuplicateSigner { signer: signer_id });
        }
        signers.push(signer_id);
    }

    // Step 3: Build frost commitments map (Identifier → SigningCommitments)
    let mut frost_commitments_map = BTreeMap::new();
    for partial in partials {
        let frost_id = frost_adapter::signer_id_to_frost_identifier(partial.signer_id())
            .map_err(|e| SigningError::AggregationFailed {
                reason: format!(
                    "failed to convert SignerId to frost Identifier: {}",
                    e
                ),
            })?;
        let frost_commitment =
            frost_adapter::commitment_to_signing_commitments(partial.commitment())
                .map_err(|e| SigningError::AggregationFailed {
                    reason: format!(
                        "failed to convert commitment to frost format: {}",
                        e
                    ),
                })?;
        frost_commitments_map.insert(frost_id, frost_commitment);
    }

    // Step 4: Build frost SigningPackage
    let signing_package = frost::SigningPackage::new(frost_commitments_map, message);

    // Step 5: Build frost signature shares map (Identifier → SignatureShare)
    let mut frost_shares_map = BTreeMap::new();
    for partial in partials {
        let frost_id = frost_adapter::signer_id_to_frost_identifier(partial.signer_id())
            .map_err(|e| SigningError::AggregationFailed {
                reason: format!(
                    "failed to convert SignerId to frost Identifier: {}",
                    e
                ),
            })?;
        let frost_share =
            frost_adapter::sig_share_to_signature_share(partial.signature_share())
                .map_err(|e| SigningError::AggregationFailed {
                    reason: format!(
                        "failed to convert signature share to frost format: {}",
                        e
                    ),
                })?;
        frost_shares_map.insert(frost_id, frost_share);
    }

    // Step 6: Build frost PublicKeyPackage
    let frost_verifying_key = frost_adapter::group_pubkey_to_verifying_key(group_pubkey)
        .map_err(|e| SigningError::AggregationFailed {
            reason: format!("failed to convert group pubkey to frost VerifyingKey: {}", e),
        })?;

    let mut frost_verifying_shares = BTreeMap::new();
    for (sid, ppk) in verifying_shares {
        let frost_id = frost_adapter::signer_id_to_frost_identifier(sid)
            .map_err(|e| SigningError::AggregationFailed {
                reason: format!(
                    "failed to convert verifying share SignerId to frost Identifier: {}",
                    e
                ),
            })?;
        let frost_vs = frost::keys::VerifyingShare::deserialize(ppk.as_bytes())
            .map_err(|e| SigningError::AggregationFailed {
                reason: format!("failed to deserialize verifying share: {}", e),
            })?;
        frost_verifying_shares.insert(frost_id, frost_vs);
    }

    let pubkey_package =
        frost::keys::PublicKeyPackage::new(frost_verifying_shares, frost_verifying_key);

    // Step 7: Call real frost::aggregate()
    let frost_signature =
        frost::aggregate(&signing_package, &frost_shares_map, &pubkey_package)
            .map_err(|e| SigningError::AggregationFailed {
                reason: format!("frost aggregation failed: {}", e),
            })?;

    // Step 8: Convert frost::Signature (64 bytes) to FrostSignature
    let our_signature = frost_adapter::signature_to_frost_sig(&frost_signature)
        .map_err(|e| SigningError::AggregationFailed {
            reason: format!("failed to convert frost signature: {}", e),
        })?;

    // Sort signers for deterministic output
    signers.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

    // Step 9: Return AggregateSignature with 64-byte real Ed25519 signature
    Ok(AggregateSignature::new(our_signature, signers, *message_hash))
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost_adapter::{
        key_package_to_key_share, signature_share_to_sig_share,
        signing_commitments_to_commitment, signer_id_to_frost_identifier,
    };
    use crate::primitives::FrostSignatureShare;
    use frost_ed25519 as frost;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use sha3::{Digest, Sha3_256};

    // ────────────────────────────────────────────────────────────────────────────
    // HELPER FUNCTIONS
    // ────────────────────────────────────────────────────────────────────────────

    fn make_signature() -> FrostSignature {
        FrostSignature::from_bytes([0x01; SIGNATURE_SIZE]).expect("valid signature bytes")
    }

    fn make_signers(n: usize) -> Vec<SignerId> {
        (0..n)
            .map(|i| SignerId::from_bytes([i as u8; 32]))
            .collect()
    }

    fn make_aggregate() -> AggregateSignature {
        AggregateSignature::new(make_signature(), make_signers(2), [0xAA; 32])
    }

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

    /// Compute message hash for AggregateSignature metadata.
    fn compute_message_hash(message: &[u8]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"dsdn-tss-message-hash-v1");
        hasher.update(message);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Run full frost signing ceremony and return all data needed for aggregation tests.
    struct SigningFixture {
        message: Vec<u8>,
        message_hash: [u8; 32],
        partials: Vec<PartialSignature>,
        group_pubkey: GroupPublicKey,
        verifying_shares: Vec<(SignerId, ParticipantPublicKey)>,
        pubkey_package: frost::keys::PublicKeyPackage,
    }

    fn create_signing_fixture(n: u16, t: u16, seed: u64, message: &[u8]) -> SigningFixture {
        let (key_packages, pubkey_package) = generate_frost_keys(n, t, seed);
        let mut rng = ChaCha20Rng::seed_from_u64(seed + 1000);

        // Select first t signers
        let selected: Vec<_> = key_packages.iter().take(t as usize).collect();

        // Round 1: commitments
        let mut nonces_map = BTreeMap::new();
        let mut frost_commitments_map = BTreeMap::new();

        for &(id, kp) in &selected {
            let (nonces, commitments) = frost::round1::commit(kp.signing_share(), &mut rng);
            nonces_map.insert(*id, nonces);
            frost_commitments_map.insert(*id, commitments);
        }

        // Round 2: signing
        let signing_package =
            frost::SigningPackage::new(frost_commitments_map.clone(), message);

        let mut partials = Vec::new();
        for &(id, kp) in &selected {
            let nonces = &nonces_map[id];
            let frost_share = frost::round2::sign(&signing_package, nonces, kp)
                .expect("signing must succeed");

            let sid = frost_id_to_signer_id(id);
            let our_share = signature_share_to_sig_share(&frost_share)
                .expect("conversion ok");
            let our_commitment =
                signing_commitments_to_commitment(&frost_commitments_map[id])
                    .expect("conversion ok");

            partials.push(PartialSignature::new(sid, our_share, our_commitment));
        }

        // Build verifying_shares
        let mut verifying_shares = Vec::new();
        for &(id, kp) in &selected {
            let sid = frost_id_to_signer_id(id);
            let vs_bytes = kp
                .verifying_share()
                .serialize()
                .expect("serialize verifying share");
            let arr: [u8; 32] = vs_bytes
                .as_slice()
                .try_into()
                .expect("32 bytes");
            let ppk = ParticipantPublicKey::from_bytes(arr).expect("valid pubkey");
            verifying_shares.push((sid, ppk));
        }

        // Group pubkey
        let vk = pubkey_package.verifying_key();
        let group_pubkey = frost_adapter::verifying_key_to_group_pubkey(vk)
            .expect("conversion ok");

        let message_hash = compute_message_hash(message);

        SigningFixture {
            message: message.to_vec(),
            message_hash,
            partials,
            group_pubkey,
            verifying_shares,
            pubkey_package,
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // AGGREGATE SIGNATURE STRUCT TESTS
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

        let aggregate = AggregateSignature::new(sig.clone(), signers, hash);

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
        let recovered = AggregateSignature::from_bytes(&bytes).expect("from_bytes ok");

        assert_eq!(
            recovered.signature().as_bytes(),
            original.signature().as_bytes()
        );
        assert_eq!(recovered.signer_count(), original.signer_count());
        assert_eq!(recovered.message_hash(), original.message_hash());
    }

    #[test]
    fn test_aggregate_signature_roundtrip() {
        let original = AggregateSignature::new(make_signature(), make_signers(5), [0xBB; 32]);
        let bytes = original.to_bytes();
        let recovered = AggregateSignature::from_bytes(&bytes).expect("from_bytes ok");

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
    fn test_aggregate_signature_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AggregateSignature>();
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 1: 3-of-5 THRESHOLD AGGREGATION SUCCESS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_3_of_5_threshold_aggregation_success() {
        let fixture = create_signing_fixture(5, 3, 42, b"DSDN aggregation test");

        let result = aggregate_signatures(
            &fixture.message,
            &fixture.partials,
            &fixture.group_pubkey,
            &fixture.verifying_shares,
            &fixture.message_hash,
        );

        assert!(result.is_ok(), "aggregation must succeed");
        let aggregate = result.expect("just checked");

        // Signature must be 64 bytes
        assert_eq!(aggregate.signature().as_bytes().len(), 64);
        assert_eq!(aggregate.signer_count(), 3);
        assert_eq!(aggregate.message_hash(), &fixture.message_hash);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 6: AGGREGATE SIGNATURE VERIFIABLE VIA ED25519 VERIFY
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_aggregate_signature_verifiable() {
        let fixture = create_signing_fixture(5, 3, 42, b"verification test");

        let aggregate = aggregate_signatures(
            &fixture.message,
            &fixture.partials,
            &fixture.group_pubkey,
            &fixture.verifying_shares,
            &fixture.message_hash,
        )
        .expect("aggregation ok");

        // Verify using frost verification
        let frost_sig = frost_adapter::frost_sig_to_signature(aggregate.signature())
            .expect("conversion ok");
        let vk = fixture.pubkey_package.verifying_key();

        let verify_result = vk.verify(&fixture.message, &frost_sig);
        assert!(
            verify_result.is_ok(),
            "aggregate signature must be verifiable with group public key"
        );
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 2: BELOW THRESHOLD → ERROR
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_aggregate_signatures_empty_fails() {
        let fixture = create_signing_fixture(5, 3, 42, b"test");

        let result = aggregate_signatures(
            &fixture.message,
            &[],
            &fixture.group_pubkey,
            &fixture.verifying_shares,
            &fixture.message_hash,
        );
        assert!(result.is_err());

        if let Err(SigningError::InsufficientSignatures { expected, got }) = result {
            assert_eq!(expected, 1);
            assert_eq!(got, 0);
        } else {
            unreachable!("Expected InsufficientSignatures error");
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 3: DUPLICATE SHARE → ERROR
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_aggregate_signatures_duplicate_signer_fails() {
        let fixture = create_signing_fixture(5, 3, 42, b"test");

        // Create duplicates
        let mut partials_with_dup = fixture.partials.clone();
        partials_with_dup.push(fixture.partials[0].clone());

        let result = aggregate_signatures(
            &fixture.message,
            &partials_with_dup,
            &fixture.group_pubkey,
            &fixture.verifying_shares,
            &fixture.message_hash,
        );
        assert!(result.is_err());

        if let Err(SigningError::DuplicateSigner { .. }) = result {
            // Expected
        } else {
            unreachable!("Expected DuplicateSigner error");
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 4: WRONG IDENTIFIER → ERROR
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_aggregate_signatures_wrong_verifying_share_fails() {
        let fixture = create_signing_fixture(5, 3, 42, b"test");

        // Use empty verifying_shares — frost will reject because it can't verify shares
        let result = aggregate_signatures(
            &fixture.message,
            &fixture.partials,
            &fixture.group_pubkey,
            &[],
            &fixture.message_hash,
        );

        assert!(result.is_err(), "aggregation with missing verifying shares must fail");
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 5: DIFFERENT MESSAGE → DIFFERENT AGGREGATE SIGNATURE
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_different_message_different_aggregate_signature() {
        let fixture_a = create_signing_fixture(5, 3, 42, b"message A");
        let fixture_b = create_signing_fixture(5, 3, 42, b"message B");

        let agg_a = aggregate_signatures(
            &fixture_a.message,
            &fixture_a.partials,
            &fixture_a.group_pubkey,
            &fixture_a.verifying_shares,
            &fixture_a.message_hash,
        )
        .expect("aggregation ok");

        let agg_b = aggregate_signatures(
            &fixture_b.message,
            &fixture_b.partials,
            &fixture_b.group_pubkey,
            &fixture_b.verifying_shares,
            &fixture_b.message_hash,
        )
        .expect("aggregation ok");

        assert_ne!(
            agg_a.signature().as_bytes(),
            agg_b.signature().as_bytes(),
            "different messages must produce different aggregate signatures"
        );
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 7: DETERMINISTIC FOR SAME SHARES
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_aggregate_signatures_deterministic() {
        let fixture = create_signing_fixture(5, 3, 100, b"determinism test");

        let result1 = aggregate_signatures(
            &fixture.message,
            &fixture.partials,
            &fixture.group_pubkey,
            &fixture.verifying_shares,
            &fixture.message_hash,
        )
        .expect("ok");

        let result2 = aggregate_signatures(
            &fixture.message,
            &fixture.partials,
            &fixture.group_pubkey,
            &fixture.verifying_shares,
            &fixture.message_hash,
        )
        .expect("ok");

        assert_eq!(
            result1.signature().as_bytes(),
            result2.signature().as_bytes(),
            "same inputs must produce same aggregate signature"
        );
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 8: ORDER INDEPENDENT
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_aggregate_signatures_order_independent() {
        let fixture = create_signing_fixture(5, 3, 42, b"order test");

        let mut reversed_partials = fixture.partials.clone();
        reversed_partials.reverse();

        let result1 = aggregate_signatures(
            &fixture.message,
            &fixture.partials,
            &fixture.group_pubkey,
            &fixture.verifying_shares,
            &fixture.message_hash,
        )
        .expect("ok");

        let result2 = aggregate_signatures(
            &fixture.message,
            &reversed_partials,
            &fixture.group_pubkey,
            &fixture.verifying_shares,
            &fixture.message_hash,
        )
        .expect("ok");

        assert_eq!(
            result1.signature().as_bytes(),
            result2.signature().as_bytes(),
            "input order must not affect aggregate signature"
        );
    }
}