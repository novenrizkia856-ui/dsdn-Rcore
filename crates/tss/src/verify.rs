//! # Signature Verification
//!
//! Module ini menyediakan fungsi-fungsi untuk verifikasi FROST signatures
//! menggunakan real `frost_ed25519` verification.
//!
//! ## Verification Types
//!
//! 1. **Aggregate Verification**: Verifikasi final aggregate signature via
//!    `frost_ed25519::VerifyingKey::verify()` — standard Ed25519 verification
//!    menggunakan group public key dari DKG.
//! 2. **Partial Verification**: Verifikasi structural individual partial signature
//!    (commitment match, type validation, non-zero checks). Cryptographic
//!    partial verification terjadi secara implicit saat `frost::aggregate()`.
//!
//! ## Cryptographic Background
//!
//! FROST aggregate signatures adalah standard Ed25519 Schnorr signatures (R ‖ s)
//! yang diverifikasi dengan group public key. Verification equation:
//! `s*G == R + H(R || PK || message)*PK`
//!
//! ## Security Notes
//!
//! - Verification functions adalah pure dan deterministic
//! - Tidak ada side effects atau state mutations
//! - `frost::VerifyingKey::verify()` melakukan constant-time verification
//! - Invalid signatures ditolak secara eksplisit

use sha3::{Digest, Sha3_256};

use frost_ed25519 as frost;

use crate::frost_adapter;
use crate::primitives::{GroupPublicKey, ParticipantPublicKey, SigningCommitment};
use crate::signing::{AggregateSignature, PartialSignature};
use crate::types::SignerId;

// ════════════════════════════════════════════════════════════════════════════════
// AGGREGATE SIGNATURE VERIFICATION
// ════════════════════════════════════════════════════════════════════════════════

/// Verifikasi aggregate signature menggunakan real FROST verification.
///
/// Fungsi ini memverifikasi bahwa aggregate signature valid untuk
/// message dan group public key menggunakan `frost::VerifyingKey::verify()`.
///
/// # Arguments
///
/// * `signature` - Aggregate signature (64-byte Ed25519 R ‖ s)
/// * `message` - Raw message bytes yang di-sign
/// * `group_pubkey` - Group public key hasil DKG
///
/// # Returns
///
/// `true` jika signature valid, `false` jika tidak.
///
/// # Algorithm
///
/// 1. Compute DSDN message hash for metadata validation
/// 2. Verify metadata message_hash matches
/// 3. Validate at least one signer
/// 4. Convert GroupPublicKey → frost::VerifyingKey
/// 5. Convert FrostSignature → frost::Signature
/// 6. Call `vk.verify(message, &frost_sig)`
#[must_use]
pub fn verify_aggregate(
    signature: &AggregateSignature,
    message: &[u8],
    group_pubkey: &GroupPublicKey,
) -> bool {
    // Step 1: Compute message hash for metadata check
    let computed_hash = compute_message_hash(message);

    // Step 2: Verify message_hash metadata matches
    if computed_hash != *signature.message_hash() {
        return false;
    }

    // Step 3: Verify at least one signer
    if signature.signer_count() == 0 {
        return false;
    }

    // Step 4: Validate signature length (must be 64 bytes)
    if signature.signature().as_bytes().len() != 64 {
        return false;
    }

    // Step 5: Convert GroupPublicKey → frost::VerifyingKey
    let vk = match frost_adapter::group_pubkey_to_verifying_key(group_pubkey) {
        Ok(vk) => vk,
        Err(_) => return false,
    };

    // Step 6: Convert FrostSignature → frost::Signature
    let frost_sig = match frost_adapter::frost_sig_to_signature(signature.signature()) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    // Step 7: Real FROST verification via Ed25519
    vk.verify(message, &frost_sig).is_ok()
}

/// Verifikasi aggregate signature dengan explicit message hash.
///
/// Variant ini memungkinkan caller menyediakan pre-computed message hash
/// untuk skip recomputation saat metadata check. Crypto verification
/// tetap menggunakan raw message bytes (karena FROST signs raw message).
///
/// # Arguments
///
/// * `signature` - Aggregate signature
/// * `message` - Raw message bytes (untuk crypto verification)
/// * `message_hash` - Pre-computed message hash (untuk metadata check, skip recompute)
/// * `group_pubkey` - Group public key
///
/// # Returns
///
/// `true` jika signature valid.
#[must_use]
pub fn verify_aggregate_with_hash(
    signature: &AggregateSignature,
    message: &[u8],
    message_hash: &[u8; 32],
    group_pubkey: &GroupPublicKey,
) -> bool {
    // Verify message_hash metadata matches (skip recomputing hash)
    if message_hash != signature.message_hash() {
        return false;
    }

    // Validate signer count
    if signature.signer_count() == 0 {
        return false;
    }

    // Validate signature length
    if signature.signature().as_bytes().len() != 64 {
        return false;
    }

    // Convert GroupPublicKey → frost::VerifyingKey
    let vk = match frost_adapter::group_pubkey_to_verifying_key(group_pubkey) {
        Ok(vk) => vk,
        Err(_) => return false,
    };

    // Convert FrostSignature → frost::Signature
    let frost_sig = match frost_adapter::frost_sig_to_signature(signature.signature()) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    // Crypto verify over raw message (FROST signs raw bytes, not hash)
    vk.verify(message, &frost_sig).is_ok()
}

/// Verifikasi FROST signature dari raw bytes.
///
/// Fungsi utilitas untuk memverifikasi 64-byte FROST aggregate signature
/// langsung dari raw bytes tanpa memerlukan `AggregateSignature` struct.
/// Digunakan oleh chain layer untuk verifikasi threshold receipt.
///
/// # Arguments
///
/// * `pubkey_bytes` - 32-byte group public key
/// * `message` - Message bytes yang di-sign
/// * `signature_bytes` - 64-byte FROST signature (R ‖ s)
///
/// # Returns
///
/// `true` jika signature valid, `false` jika tidak.
#[must_use]
pub fn verify_frost_signature_bytes(
    pubkey_bytes: &[u8; 32],
    message: &[u8],
    signature_bytes: &[u8],
) -> bool {
    // Validate signature length = 64 bytes
    if signature_bytes.len() != 64 {
        return false;
    }

    // Convert pubkey bytes → frost::VerifyingKey
    let vk = match frost::VerifyingKey::deserialize(pubkey_bytes) {
        Ok(vk) => vk,
        Err(_) => return false,
    };

    // Convert signature bytes → frost::Signature
    let frost_sig = match frost::Signature::deserialize(signature_bytes) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    // Real Ed25519 verification
    vk.verify(message, &frost_sig).is_ok()
}

// ════════════════════════════════════════════════════════════════════════════════
// PARTIAL SIGNATURE VERIFICATION
// ════════════════════════════════════════════════════════════════════════════════

/// Verifikasi partial signature dari satu signer.
///
/// Melakukan structural verification pada partial signature:
/// - Commitment match terhadap session commitments
/// - Signature share non-zero
/// - Frost type conversion validity (bytes represent valid curve points/scalars)
///
/// Cryptographic partial verification (EC math: `s_i*G == D_i + rho_i*E_i + c*lambda_i*PK_i`)
/// dilakukan secara implicit oleh `frost::aggregate()` saat aggregation.
///
/// # Arguments
///
/// * `partial` - Partial signature yang akan diverifikasi
/// * `message` - Message bytes yang di-sign
/// * `participant_pubkey` - Public key dari participant
/// * `all_commitments` - Semua commitments dari signing session (HARUS sorted by SignerId)
///
/// # Returns
///
/// `true` jika partial signature structurally valid, `false` jika tidak.
#[must_use]
pub fn verify_partial(
    partial: &PartialSignature,
    _message: &[u8],
    _participant_pubkey: &ParticipantPublicKey,
    all_commitments: &[(SignerId, SigningCommitment)],
) -> bool {
    // Step 1: Find this signer's commitment in all_commitments
    let signer_id = partial.signer_id();
    let expected_commitment = all_commitments
        .iter()
        .find(|(sid, _)| sid == signer_id)
        .map(|(_, c)| c);

    let expected_commitment = match expected_commitment {
        Some(c) => c,
        None => return false, // Signer not found in commitments
    };

    // Step 2: Verify partial's commitment matches expected
    let partial_commitment = partial.commitment();
    if partial_commitment.hiding() != expected_commitment.hiding()
        || partial_commitment.binding() != expected_commitment.binding()
    {
        return false;
    }

    // Step 3: Validate signature share is non-zero
    if partial.signature_share().as_bytes().iter().all(|&b| b == 0) {
        return false;
    }

    // Step 4: Validate frost type conversions succeed
    // This checks that bytes represent valid curve points/scalars
    if frost_adapter::signer_id_to_frost_identifier(signer_id).is_err() {
        return false;
    }

    if frost_adapter::commitment_to_signing_commitments(partial_commitment).is_err() {
        return false;
    }

    if frost_adapter::sig_share_to_signature_share(partial.signature_share()).is_err() {
        return false;
    }

    true
}

/// Verifikasi partial signature dengan explicit message hash.
///
/// # Arguments
///
/// * `partial` - Partial signature
/// * `message_hash` - Pre-computed message hash
/// * `participant_pubkey` - Participant's public key
/// * `all_commitments` - All commitments (sorted by SignerId)
///
/// # Returns
///
/// `true` jika valid.
#[must_use]
pub fn verify_partial_with_hash(
    partial: &PartialSignature,
    _message_hash: &[u8; 32],
    participant_pubkey: &ParticipantPublicKey,
    all_commitments: &[(SignerId, SigningCommitment)],
) -> bool {
    // Delegate to verify_partial — structural checks are message-independent
    // The message/hash is not used for structural verification;
    // cryptographic verification happens in frost::aggregate()
    verify_partial(partial, &[], participant_pubkey, all_commitments)
}

// ════════════════════════════════════════════════════════════════════════════════
// BATCH VERIFICATION
// ════════════════════════════════════════════════════════════════════════════════

/// Batch verify multiple partial signatures.
///
/// # Arguments
///
/// * `partials` - Slice of (PartialSignature, ParticipantPublicKey) pairs
/// * `message` - Message yang di-sign
/// * `all_commitments` - All commitments (sorted by SignerId)
///
/// # Returns
///
/// `true` jika SEMUA partial signatures valid.
#[must_use]
pub fn verify_partials_batch(
    partials: &[(&PartialSignature, &ParticipantPublicKey)],
    message: &[u8],
    all_commitments: &[(SignerId, SigningCommitment)],
) -> bool {
    for (partial, pubkey) in partials {
        if !verify_partial(partial, message, pubkey, all_commitments) {
            return false;
        }
    }

    true
}

// ════════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════════

/// Compute hash of message using SHA3-256 with domain separation.
fn compute_message_hash(message: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"dsdn-tss-message-hash-v1");
    hasher.update(message);

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost_adapter::{
        signature_share_to_sig_share, signing_commitments_to_commitment,
        signature_to_frost_sig, verifying_key_to_group_pubkey,
    };
    use crate::primitives::{FrostSignature, FrostSignatureShare};
    use frost_ed25519 as frost;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::collections::BTreeMap;

    // ────────────────────────────────────────────────────────────────────────────
    // HELPER: Generate real frost key material + signing ceremony
    // ────────────────────────────────────────────────────────────────────────────

    struct VerifyFixture {
        message: Vec<u8>,
        message_hash: [u8; 32],
        aggregate: AggregateSignature,
        group_pubkey: GroupPublicKey,
        /// Partials with their matching commitments
        partials: Vec<PartialSignature>,
        all_commitments: Vec<(SignerId, SigningCommitment)>,
        participant_pubkeys: Vec<(SignerId, ParticipantPublicKey)>,
    }

    fn frost_id_to_signer_id(id: &frost::Identifier) -> SignerId {
        let bytes = id.serialize();
        let arr: [u8; 32] = bytes.as_slice().try_into().expect("32 bytes");
        SignerId::from_bytes(arr)
    }

    fn create_verify_fixture(message: &[u8], seed: u64) -> VerifyFixture {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let (shares, pubkey_package) = frost::keys::generate_with_dealer(
            5, 3,
            frost::keys::IdentifierList::Default,
            &mut rng,
        ).expect("keygen ok");

        let mut key_packages = BTreeMap::new();
        for (id, ss) in shares {
            let kp = frost::keys::KeyPackage::try_from(ss).expect("kp ok");
            key_packages.insert(id, kp);
        }

        // Select first 3 signers
        let selected: Vec<_> = key_packages.iter().take(3).collect();

        // Round 1: commitments
        let mut nonces_map = BTreeMap::new();
        let mut frost_commitments_map = BTreeMap::new();

        for &(id, kp) in &selected {
            let (nonces, commitments) = frost::round1::commit(kp.signing_share(), &mut rng);
            nonces_map.insert(*id, nonces);
            frost_commitments_map.insert(*id, commitments);
        }

        // Round 2: signing
        let signing_package = frost::SigningPackage::new(frost_commitments_map.clone(), message);

        let mut frost_shares_map = BTreeMap::new();
        let mut partials = Vec::new();
        let mut all_commitments = Vec::new();

        for &(id, kp) in &selected {
            let nonces = &nonces_map[id];
            let frost_share = frost::round2::sign(&signing_package, nonces, kp)
                .expect("sign ok");
            frost_shares_map.insert(*id, frost_share.clone());

            let sid = frost_id_to_signer_id(id);
            let our_share = signature_share_to_sig_share(&frost_share).expect("ok");
            let our_commitment = signing_commitments_to_commitment(&frost_commitments_map[id])
                .expect("ok");

            partials.push(PartialSignature::new(
                sid.clone(),
                our_share,
                our_commitment.clone(),
            ));
            all_commitments.push((sid, our_commitment));
        }

        // Aggregate
        let frost_sig = frost::aggregate(&signing_package, &frost_shares_map, &pubkey_package)
            .expect("aggregate ok");

        // Convert to our types
        let our_sig = signature_to_frost_sig(&frost_sig).expect("ok");
        let vk = pubkey_package.verifying_key();
        let group_pubkey = verifying_key_to_group_pubkey(vk).expect("ok");

        let message_hash = compute_message_hash(message);
        let signers: Vec<_> = selected.iter().map(|&(id, _)| frost_id_to_signer_id(id)).collect();

        let aggregate = AggregateSignature::new(our_sig, signers, message_hash);

        // Build participant pubkeys
        let mut participant_pubkeys = Vec::new();
        for &(id, kp) in &selected {
            let sid = frost_id_to_signer_id(id);
            let vs_bytes = kp.verifying_share().serialize().expect("ok");
            let arr: [u8; 32] = vs_bytes.as_slice().try_into().expect("32 bytes");
            let ppk = ParticipantPublicKey::from_bytes(arr).expect("ok");
            participant_pubkeys.push((sid, ppk));
        }

        VerifyFixture {
            message: message.to_vec(),
            message_hash,
            aggregate,
            group_pubkey,
            partials,
            all_commitments,
            participant_pubkeys,
        }
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

    #[test]
    fn test_compute_message_hash_empty() {
        let hash = compute_message_hash(b"");
        assert!(!hash.iter().all(|&b| b == 0));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 1: VALID AGGREGATE SIGNATURE → VERIFY TRUE
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_verify_aggregate_valid() {
        let fixture = create_verify_fixture(b"test message", 42);

        let result = verify_aggregate(&fixture.aggregate, &fixture.message, &fixture.group_pubkey);
        assert!(result, "valid aggregate signature must verify true");
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 2: TAMPERED MESSAGE → VERIFY FALSE
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_verify_aggregate_tampered_message() {
        let fixture = create_verify_fixture(b"original message", 42);

        let result = verify_aggregate(&fixture.aggregate, b"tampered message", &fixture.group_pubkey);
        assert!(!result, "tampered message must verify false");
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 3: TAMPERED SIGNATURE → VERIFY FALSE
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_verify_aggregate_tampered_signature() {
        let fixture = create_verify_fixture(b"test message", 42);

        // Create aggregate with tampered signature bytes
        let mut tampered_bytes = [0u8; 64];
        tampered_bytes.copy_from_slice(fixture.aggregate.signature().as_bytes());
        // Flip a byte in the signature
        tampered_bytes[10] ^= 0xFF;

        // Try to create a FrostSignature from tampered bytes
        // This may or may not succeed depending on whether the bytes are still valid format
        if let Ok(tampered_sig) = FrostSignature::from_bytes(tampered_bytes) {
            let tampered_aggregate = AggregateSignature::new(
                tampered_sig,
                fixture.aggregate.signers().to_vec(),
                fixture.message_hash,
            );

            let result = verify_aggregate(&tampered_aggregate, &fixture.message, &fixture.group_pubkey);
            assert!(!result, "tampered signature must verify false");
        }
        // If FrostSignature::from_bytes rejects tampered bytes, that's also correct
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 4: TAMPERED PUBLIC KEY → VERIFY FALSE
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_verify_aggregate_tampered_pubkey() {
        let fixture = create_verify_fixture(b"test message", 42);

        // Use a different group pubkey (from different keygen)
        let fixture2 = create_verify_fixture(b"test message", 999);

        let result = verify_aggregate(&fixture.aggregate, &fixture.message, &fixture2.group_pubkey);
        assert!(!result, "wrong public key must verify false");
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 5: WRONG SIGNATURE LENGTH → REJECT
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_verify_frost_signature_bytes_wrong_length() {
        let fixture = create_verify_fixture(b"test message", 42);

        // Too short signature
        let short_sig = vec![0x01; 32];
        let result = verify_frost_signature_bytes(
            fixture.group_pubkey.as_bytes(),
            &fixture.message,
            &short_sig,
        );
        assert!(!result, "short signature must be rejected");

        // Too long signature
        let long_sig = vec![0x01; 128];
        let result = verify_frost_signature_bytes(
            fixture.group_pubkey.as_bytes(),
            &fixture.message,
            &long_sig,
        );
        assert!(!result, "long signature must be rejected");
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 6: PARTIAL SHARE VALID → VERIFY_PARTIAL TRUE
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_verify_partial_valid() {
        let fixture = create_verify_fixture(b"test message", 42);

        let partial = &fixture.partials[0];
        let (_, ppk) = &fixture.participant_pubkeys[0];

        let result = verify_partial(
            partial,
            &fixture.message,
            ppk,
            &fixture.all_commitments,
        );
        assert!(result, "valid partial signature must verify true");
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 7: PARTIAL SHARE TAMPERED → FALSE
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_verify_partial_signer_not_in_commitments() {
        let fixture = create_verify_fixture(b"test message", 42);

        let partial = &fixture.partials[0];
        let (_, ppk) = &fixture.participant_pubkeys[0];

        // Empty commitments — signer won't be found
        let empty_commitments: Vec<(SignerId, SigningCommitment)> = vec![];

        let result = verify_partial(
            partial,
            &fixture.message,
            ppk,
            &empty_commitments,
        );
        assert!(!result, "signer not in commitments must verify false");
    }

    #[test]
    fn test_verify_partial_commitment_mismatch() {
        let fixture = create_verify_fixture(b"test message", 42);

        let partial = &fixture.partials[0];
        let (_, ppk) = &fixture.participant_pubkeys[0];

        // Use different fixture's commitments (different ceremony)
        let fixture2 = create_verify_fixture(b"test message", 999);

        // Build commitments with same signer ID but different commitment values
        let sid = partial.signer_id().clone();
        let wrong_commitments = vec![(sid, fixture2.all_commitments[0].1.clone())];

        let result = verify_partial(
            partial,
            &fixture.message,
            ppk,
            &wrong_commitments,
        );
        assert!(!result, "commitment mismatch must verify false");
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 8: VERIFY_AGGREGATE_WITH_HASH VALID
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_verify_aggregate_with_hash_valid() {
        let fixture = create_verify_fixture(b"test message", 42);

        // Pre-computed hash matches fixture.message_hash
        let result = verify_aggregate_with_hash(
            &fixture.aggregate,
            &fixture.message,
            &fixture.message_hash,
            &fixture.group_pubkey,
        );
        assert!(result, "verify_aggregate_with_hash must succeed");
    }

    #[test]
    fn test_verify_aggregate_with_hash_wrong_hash() {
        let fixture = create_verify_fixture(b"test message", 42);
        let wrong_hash = [0xFF; 32];

        let result = verify_aggregate_with_hash(
            &fixture.aggregate,
            &fixture.message,
            &wrong_hash,
            &fixture.group_pubkey,
        );
        assert!(!result, "wrong hash metadata must verify false");
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 9: CHAIN RECEIPT VERIFICATION END-TO-END (via verify_frost_signature_bytes)
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_verify_frost_signature_bytes_end_to_end() {
        let fixture = create_verify_fixture(b"receipt signable hash", 42);

        // Extract raw bytes (simulating chain layer)
        let pubkey_bytes = fixture.group_pubkey.as_bytes();
        let sig_bytes = fixture.aggregate.signature().as_bytes();

        let result = verify_frost_signature_bytes(
            pubkey_bytes,
            &fixture.message,
            sig_bytes,
        );
        assert!(result, "end-to-end raw bytes verification must succeed");
    }

    #[test]
    fn test_verify_frost_signature_bytes_invalid_pubkey() {
        let fixture = create_verify_fixture(b"test message", 42);

        let wrong_pubkey = [0x00; 32]; // Identity point — invalid
        let sig_bytes = fixture.aggregate.signature().as_bytes();

        let result = verify_frost_signature_bytes(
            &wrong_pubkey,
            &fixture.message,
            sig_bytes,
        );
        assert!(!result, "invalid pubkey must verify false");
    }

    // ────────────────────────────────────────────────────────────────────────────
    // ADDITIONAL: DETERMINISM
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_verify_aggregate_deterministic() {
        let fixture = create_verify_fixture(b"test message", 42);

        let result1 = verify_aggregate(&fixture.aggregate, &fixture.message, &fixture.group_pubkey);
        let result2 = verify_aggregate(&fixture.aggregate, &fixture.message, &fixture.group_pubkey);

        assert_eq!(result1, result2);
        assert!(result1);
    }

    #[test]
    fn test_verify_partial_deterministic() {
        let fixture = create_verify_fixture(b"test message", 42);

        let partial = &fixture.partials[0];
        let (_, ppk) = &fixture.participant_pubkeys[0];

        let result1 = verify_partial(partial, &fixture.message, ppk, &fixture.all_commitments);
        let result2 = verify_partial(partial, &fixture.message, ppk, &fixture.all_commitments);

        assert_eq!(result1, result2);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // EDGE CASES
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_verify_aggregate_empty_signers() {
        let fixture = create_verify_fixture(b"test", 42);

        // Create aggregate with empty signers list
        let empty_aggregate = AggregateSignature::new(
            fixture.aggregate.signature().clone(),
            vec![], // Empty signers!
            fixture.message_hash,
        );

        let result = verify_aggregate(&empty_aggregate, b"test", &fixture.group_pubkey);
        assert!(!result, "empty signers must verify false");
    }

    #[test]
    fn test_verify_partials_batch_all_valid() {
        let fixture = create_verify_fixture(b"test message", 42);

        let pairs: Vec<_> = fixture.partials.iter()
            .zip(fixture.participant_pubkeys.iter())
            .map(|(p, (_, ppk))| (p, ppk))
            .collect();

        let result = verify_partials_batch(&pairs, &fixture.message, &fixture.all_commitments);
        assert!(result, "all valid partials must batch-verify true");
    }

    #[test]
    fn test_verify_partials_batch_empty() {
        let partials: Vec<(&PartialSignature, &ParticipantPublicKey)> = vec![];
        let all_commitments: Vec<(SignerId, SigningCommitment)> = vec![];

        let result = verify_partials_batch(&partials, b"message", &all_commitments);
        assert!(result); // Empty batch is trivially valid
    }
}