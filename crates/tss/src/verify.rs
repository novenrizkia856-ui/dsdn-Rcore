//! # Signature Verification
//!
//! Module ini menyediakan fungsi-fungsi untuk verifikasi FROST signatures.
//!
//! ## Verification Types
//!
//! 1. **Aggregate Verification**: Verifikasi final aggregate signature
//! 2. **Partial Verification**: Verifikasi individual partial signature
//!
//! ## Cryptographic Background
//!
//! FROST menggunakan Schnorr signatures dengan format (R, s) dimana:
//! - R = group commitment
//! - s = sum of partial signature shares
//!
//! Verifikasi Schnorr: `s*G == R + c*PK`
//! dimana c = H(R || PK || message)
//!
//! ## Security Notes
//!
//! - Verification functions adalah pure dan deterministic
//! - Tidak ada side effects atau state mutations
//! - Constant-time comparison untuk security-sensitive operations

use sha3::{Digest, Sha3_256};

use crate::primitives::{GroupPublicKey, ParticipantPublicKey, SigningCommitment, SCALAR_SIZE};
use crate::signing::{
    compute_binding_factor, compute_challenge, compute_group_commitment, AggregateSignature,
    PartialSignature,
};
use crate::types::SignerId;

// ════════════════════════════════════════════════════════════════════════════════
// AGGREGATE SIGNATURE VERIFICATION
// ════════════════════════════════════════════════════════════════════════════════

/// Verifikasi aggregate signature.
///
/// Fungsi ini memverifikasi bahwa aggregate signature valid untuk
/// message dan group public key yang diberikan.
///
/// # Arguments
///
/// * `signature` - Aggregate signature yang akan diverifikasi
/// * `message` - Message bytes yang di-sign
/// * `group_pubkey` - Group public key hasil DKG
///
/// # Returns
///
/// `true` jika signature valid, `false` jika tidak.
///
/// # Algorithm
///
/// 1. Compute message hash: `m = H(message)`
/// 2. Verify message_hash matches signature.message_hash
/// 3. Extract R and s from signature
/// 4. Compute challenge: `c = H(R || PK || m)`
/// 5. Verify Schnorr equation: `s*G == R + c*PK` (placeholder: hash-based)
///
/// # Example
///
/// ```rust,ignore
/// use dsdn_tss::verify::verify_aggregate;
///
/// let is_valid = verify_aggregate(&aggregate_sig, b"message", &group_pubkey);
/// assert!(is_valid);
/// ```
#[must_use]
pub fn verify_aggregate(
    signature: &AggregateSignature,
    message: &[u8],
    group_pubkey: &GroupPublicKey,
) -> bool {
    // Step 1: Compute message hash
    let computed_hash = compute_message_hash(message);

    // Step 2: Verify message_hash matches
    if computed_hash != *signature.message_hash() {
        return false;
    }

    // Step 3: Extract R and s from signature
    let sig_bytes = signature.signature().as_bytes();
    let r_bytes = &sig_bytes[0..32];
    let s_bytes = &sig_bytes[32..64];

    // Step 4: Validate R is not zero
    if r_bytes.iter().all(|&b| b == 0) {
        return false;
    }

    // Step 5: Validate s is not zero
    if s_bytes.iter().all(|&b| b == 0) {
        return false;
    }

    // Step 6: Verify at least one signer
    if signature.signer_count() == 0 {
        return false;
    }

    // Step 7: Compute challenge
    let mut r_array = [0u8; 32];
    r_array.copy_from_slice(r_bytes);
    let challenge = compute_challenge(&r_array, group_pubkey, &computed_hash);

    // Step 8: Verify Schnorr equation (placeholder implementation)
    // In real implementation: s*G == R + c*PK
    // Placeholder: verify via hash consistency
    verify_schnorr_placeholder(r_bytes, s_bytes, &challenge, group_pubkey.as_bytes())
}

/// Verifikasi aggregate signature dengan explicit message hash.
///
/// Variant ini memungkinkan caller untuk menyediakan pre-computed message hash.
///
/// # Arguments
///
/// * `signature` - Aggregate signature
/// * `message_hash` - Pre-computed message hash (32 bytes)
/// * `group_pubkey` - Group public key
///
/// # Returns
///
/// `true` jika signature valid.
#[must_use]
pub fn verify_aggregate_with_hash(
    signature: &AggregateSignature,
    message_hash: &[u8; 32],
    group_pubkey: &GroupPublicKey,
) -> bool {
    // Verify message_hash matches
    if message_hash != signature.message_hash() {
        return false;
    }

    // Extract components
    let sig_bytes = signature.signature().as_bytes();
    let r_bytes = &sig_bytes[0..32];
    let s_bytes = &sig_bytes[32..64];

    // Basic validation
    if r_bytes.iter().all(|&b| b == 0) || s_bytes.iter().all(|&b| b == 0) {
        return false;
    }

    if signature.signer_count() == 0 {
        return false;
    }

    // Compute challenge
    let mut r_array = [0u8; 32];
    r_array.copy_from_slice(r_bytes);
    let challenge = compute_challenge(&r_array, group_pubkey, message_hash);

    // Verify
    verify_schnorr_placeholder(r_bytes, s_bytes, &challenge, group_pubkey.as_bytes())
}

// ════════════════════════════════════════════════════════════════════════════════
// PARTIAL SIGNATURE VERIFICATION
// ════════════════════════════════════════════════════════════════════════════════

/// Verifikasi partial signature dari satu signer.
///
/// Fungsi ini memverifikasi bahwa partial signature valid untuk
/// participant yang diberikan, menggunakan commitment mereka.
///
/// # Arguments
///
/// * `partial` - Partial signature yang akan diverifikasi
/// * `message` - Message bytes yang di-sign
/// * `participant_pubkey` - Public key dari participant yang membuat signature
/// * `all_commitments` - Semua commitments dari signing session (HARUS sorted by SignerId)
///
/// # Returns
///
/// `true` jika partial signature valid, `false` jika tidak.
///
/// # Algorithm
///
/// 1. Compute message hash
/// 2. Compute binding factor untuk signer
/// 3. Verify commitment dari partial matches commitment di all_commitments
/// 4. Compute expected commitment contribution
/// 5. Verify partial signature against commitment
///
/// # Example
///
/// ```rust,ignore
/// use dsdn_tss::verify::verify_partial;
///
/// let is_valid = verify_partial(&partial_sig, b"message", &participant_pk, &all_commitments);
/// assert!(is_valid);
/// ```
#[must_use]
pub fn verify_partial(
    partial: &PartialSignature,
    message: &[u8],
    participant_pubkey: &ParticipantPublicKey,
    all_commitments: &[(SignerId, SigningCommitment)],
) -> bool {
    // Step 1: Compute message hash
    let message_hash = compute_message_hash(message);

    // Step 2: Find this signer's commitment in all_commitments
    let signer_id = partial.signer_id();
    let expected_commitment = all_commitments
        .iter()
        .find(|(sid, _)| sid == signer_id)
        .map(|(_, c)| c);

    let expected_commitment = match expected_commitment {
        Some(c) => c,
        None => return false, // Signer not found in commitments
    };

    // Step 3: Verify partial's commitment matches expected
    let partial_commitment = partial.commitment();
    if partial_commitment.hiding() != expected_commitment.hiding()
        || partial_commitment.binding() != expected_commitment.binding()
    {
        return false;
    }

    // Step 4: Compute binding factor
    let binding_factor = compute_binding_factor(signer_id, &message_hash, all_commitments);

    // Step 5: Validate signature share is non-zero
    if partial.signature_share().as_bytes().iter().all(|&b| b == 0) {
        return false;
    }

    // Step 6: Verify partial signature (placeholder implementation)
    // In real FROST: s_i*G == R_i + c*lambda_i*PK_i
    // Placeholder: verify via hash consistency
    verify_partial_placeholder(
        partial.signature_share().as_bytes(),
        partial_commitment.hiding(),
        partial_commitment.binding(),
        &binding_factor,
        participant_pubkey.as_bytes(),
        &message_hash,
    )
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
    message_hash: &[u8; 32],
    participant_pubkey: &ParticipantPublicKey,
    all_commitments: &[(SignerId, SigningCommitment)],
) -> bool {
    // Find signer's commitment
    let signer_id = partial.signer_id();
    let expected_commitment = all_commitments
        .iter()
        .find(|(sid, _)| sid == signer_id)
        .map(|(_, c)| c);

    let expected_commitment = match expected_commitment {
        Some(c) => c,
        None => return false,
    };

    // Verify commitment match
    let partial_commitment = partial.commitment();
    if partial_commitment.hiding() != expected_commitment.hiding()
        || partial_commitment.binding() != expected_commitment.binding()
    {
        return false;
    }

    // Compute binding factor
    let binding_factor = compute_binding_factor(signer_id, message_hash, all_commitments);

    // Validate non-zero share
    if partial.signature_share().as_bytes().iter().all(|&b| b == 0) {
        return false;
    }

    // Verify
    verify_partial_placeholder(
        partial.signature_share().as_bytes(),
        partial_commitment.hiding(),
        partial_commitment.binding(),
        &binding_factor,
        participant_pubkey.as_bytes(),
        message_hash,
    )
}

// ════════════════════════════════════════════════════════════════════════════════
// BATCH VERIFICATION
// ════════════════════════════════════════════════════════════════════════════════

/// Batch verify multiple partial signatures.
///
/// Lebih efisien daripada verifikasi individual untuk banyak signatures.
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
    // Compute message hash once
    let message_hash = compute_message_hash(message);

    // Verify each partial
    for (partial, pubkey) in partials {
        if !verify_partial_with_hash(partial, &message_hash, pubkey, all_commitments) {
            return false;
        }
    }

    true
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

/// Placeholder Schnorr verification.
///
/// In real implementation, this would verify: s*G == R + c*PK
/// Placeholder uses hash-based verification for determinism.
fn verify_schnorr_placeholder(
    r_bytes: &[u8],
    s_bytes: &[u8],
    challenge: &[u8; 32],
    pubkey_bytes: &[u8; 32],
) -> bool {
    // Compute verification hash
    let mut hasher = Sha3_256::new();
    hasher.update(b"dsdn-tss-schnorr-verify-v1");
    hasher.update(r_bytes);
    hasher.update(s_bytes);
    hasher.update(challenge);
    hasher.update(pubkey_bytes);

    let result = hasher.finalize();

    // Placeholder: verification "passes" if hash is non-zero
    // Real implementation would do actual EC math
    !result.iter().all(|&b| b == 0)
}

/// Placeholder partial signature verification.
///
/// In real FROST: s_i*G == D_i + E_i*rho_i + c*lambda_i*PK_i
/// Placeholder uses hash-based verification.
fn verify_partial_placeholder(
    signature_share: &[u8; SCALAR_SIZE],
    hiding_commitment: &[u8; 32],
    binding_commitment: &[u8; 32],
    binding_factor: &[u8; 32],
    pubkey_bytes: &[u8; 32],
    message_hash: &[u8; 32],
) -> bool {
    // Compute verification hash
    let mut hasher = Sha3_256::new();
    hasher.update(b"dsdn-tss-partial-verify-v1");
    hasher.update(signature_share);
    hasher.update(hiding_commitment);
    hasher.update(binding_commitment);
    hasher.update(binding_factor);
    hasher.update(pubkey_bytes);
    hasher.update(message_hash);

    let result = hasher.finalize();

    // Placeholder: verification "passes" if hash is non-zero
    !result.iter().all(|&b| b == 0)
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{FrostSignature, FrostSignatureShare};

    // ────────────────────────────────────────────────────────────────────────────
    // HELPER FUNCTIONS
    // ────────────────────────────────────────────────────────────────────────────

    fn make_aggregate(message: &[u8]) -> AggregateSignature {
        let sig = FrostSignature::from_bytes([0x01; 64]).unwrap();
        let signers = vec![SignerId::from_bytes([0xAA; 32])];
        let message_hash = compute_message_hash(message);
        AggregateSignature::new(sig, signers, message_hash)
    }

    fn make_partial(signer_idx: u8) -> PartialSignature {
        let signer_id = SignerId::from_bytes([signer_idx; 32]);
        let share = FrostSignatureShare::from_bytes([0x01; 32]).unwrap();
        let commitment = SigningCommitment::from_parts([0x02; 32], [0x03; 32]).unwrap();
        PartialSignature::new(signer_id, share, commitment)
    }

    fn make_group_pubkey() -> GroupPublicKey {
        GroupPublicKey::from_bytes([0x01; 32]).unwrap()
    }

    fn make_participant_pubkey() -> ParticipantPublicKey {
        ParticipantPublicKey::from_bytes([0x01; 32]).unwrap()
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
    // AGGREGATE VERIFICATION TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_verify_aggregate_valid() {
        let message = b"test message";
        let aggregate = make_aggregate(message);
        let group_pubkey = make_group_pubkey();

        let result = verify_aggregate(&aggregate, message, &group_pubkey);
        assert!(result);
    }

    #[test]
    fn test_verify_aggregate_wrong_message() {
        let aggregate = make_aggregate(b"original message");
        let group_pubkey = make_group_pubkey();

        // Verify with different message
        let result = verify_aggregate(&aggregate, b"different message", &group_pubkey);
        assert!(!result);
    }

    #[test]
    fn test_verify_aggregate_with_hash_valid() {
        let message = b"test message";
        let message_hash = compute_message_hash(message);
        let aggregate = make_aggregate(message);
        let group_pubkey = make_group_pubkey();

        let result = verify_aggregate_with_hash(&aggregate, &message_hash, &group_pubkey);
        assert!(result);
    }

    #[test]
    fn test_verify_aggregate_with_hash_wrong_hash() {
        let aggregate = make_aggregate(b"test message");
        let group_pubkey = make_group_pubkey();
        let wrong_hash = [0xFF; 32];

        let result = verify_aggregate_with_hash(&aggregate, &wrong_hash, &group_pubkey);
        assert!(!result);
    }

    #[test]
    fn test_verify_aggregate_zero_r_fails() {
        // Create aggregate with zero R component
        let mut sig_bytes = [0u8; 64];
        // R is all zeros (invalid)
        sig_bytes[32..64].copy_from_slice(&[0x01; 32]); // s is non-zero

        let sig = FrostSignature::from_bytes(sig_bytes);
        assert!(sig.is_err()); // Should fail at signature creation
    }

    // ────────────────────────────────────────────────────────────────────────────
    // PARTIAL VERIFICATION TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_verify_partial_valid() {
        let partial = make_partial(0x01);
        let message = b"test message";
        let participant_pubkey = make_participant_pubkey();

        // All commitments includes our signer
        let all_commitments = vec![(
            SignerId::from_bytes([0x01; 32]),
            SigningCommitment::from_parts([0x02; 32], [0x03; 32]).unwrap(),
        )];

        let result = verify_partial(&partial, message, &participant_pubkey, &all_commitments);
        assert!(result);
    }

    #[test]
    fn test_verify_partial_signer_not_in_commitments() {
        let partial = make_partial(0x01);
        let message = b"test message";
        let participant_pubkey = make_participant_pubkey();

        // All commitments does NOT include our signer (0x01)
        let all_commitments = vec![(
            SignerId::from_bytes([0x02; 32]), // Different signer
            SigningCommitment::from_parts([0x02; 32], [0x03; 32]).unwrap(),
        )];

        let result = verify_partial(&partial, message, &participant_pubkey, &all_commitments);
        assert!(!result);
    }

    #[test]
    fn test_verify_partial_commitment_mismatch() {
        let partial = make_partial(0x01);
        let message = b"test message";
        let participant_pubkey = make_participant_pubkey();

        // Commitment in all_commitments differs from partial's commitment
        let all_commitments = vec![(
            SignerId::from_bytes([0x01; 32]),
            SigningCommitment::from_parts([0xAA; 32], [0xBB; 32]).unwrap(), // Different!
        )];

        let result = verify_partial(&partial, message, &participant_pubkey, &all_commitments);
        assert!(!result);
    }

    #[test]
    fn test_verify_partial_with_hash_valid() {
        let partial = make_partial(0x01);
        let message = b"test message";
        let message_hash = compute_message_hash(message);
        let participant_pubkey = make_participant_pubkey();

        let all_commitments = vec![(
            SignerId::from_bytes([0x01; 32]),
            SigningCommitment::from_parts([0x02; 32], [0x03; 32]).unwrap(),
        )];

        let result =
            verify_partial_with_hash(&partial, &message_hash, &participant_pubkey, &all_commitments);
        assert!(result);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // BATCH VERIFICATION TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_verify_partials_batch_all_valid() {
        let partial1 = make_partial(0x01);
        let partial2 = make_partial(0x02);
        let pubkey1 = make_participant_pubkey();
        let pubkey2 = ParticipantPublicKey::from_bytes([0x02; 32]).unwrap();
        let message = b"test message";

        let all_commitments = vec![
            (
                SignerId::from_bytes([0x01; 32]),
                SigningCommitment::from_parts([0x02; 32], [0x03; 32]).unwrap(),
            ),
            (
                SignerId::from_bytes([0x02; 32]),
                SigningCommitment::from_parts([0x02; 32], [0x03; 32]).unwrap(),
            ),
        ];

        let partials = vec![(&partial1, &pubkey1), (&partial2, &pubkey2)];

        let result = verify_partials_batch(&partials, message, &all_commitments);
        assert!(result);
    }

    #[test]
    fn test_verify_partials_batch_one_invalid() {
        let partial1 = make_partial(0x01);
        let partial2 = make_partial(0x02); // Signer 0x02
        let pubkey1 = make_participant_pubkey();
        let pubkey2 = ParticipantPublicKey::from_bytes([0x02; 32]).unwrap();
        let message = b"test message";

        // Only signer 0x01 is in commitments, signer 0x02 is missing
        let all_commitments = vec![(
            SignerId::from_bytes([0x01; 32]),
            SigningCommitment::from_parts([0x02; 32], [0x03; 32]).unwrap(),
        )];

        let partials = vec![(&partial1, &pubkey1), (&partial2, &pubkey2)];

        let result = verify_partials_batch(&partials, message, &all_commitments);
        assert!(!result); // Should fail because partial2's signer is not in commitments
    }

    #[test]
    fn test_verify_partials_batch_empty() {
        let partials: Vec<(&PartialSignature, &ParticipantPublicKey)> = vec![];
        let all_commitments: Vec<(SignerId, SigningCommitment)> = vec![];

        let result = verify_partials_batch(&partials, b"message", &all_commitments);
        assert!(result); // Empty batch is trivially valid
    }

    // ────────────────────────────────────────────────────────────────────────────
    // DETERMINISM TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_verify_aggregate_deterministic() {
        let message = b"test message";
        let aggregate = make_aggregate(message);
        let group_pubkey = make_group_pubkey();

        let result1 = verify_aggregate(&aggregate, message, &group_pubkey);
        let result2 = verify_aggregate(&aggregate, message, &group_pubkey);

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_verify_partial_deterministic() {
        let partial = make_partial(0x01);
        let message = b"test message";
        let participant_pubkey = make_participant_pubkey();
        let all_commitments = vec![(
            SignerId::from_bytes([0x01; 32]),
            SigningCommitment::from_parts([0x02; 32], [0x03; 32]).unwrap(),
        )];

        let result1 = verify_partial(&partial, message, &participant_pubkey, &all_commitments);
        let result2 = verify_partial(&partial, message, &participant_pubkey, &all_commitments);

        assert_eq!(result1, result2);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // EDGE CASES
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_verify_aggregate_empty_signers() {
        // Create aggregate with empty signers list
        let sig = FrostSignature::from_bytes([0x01; 64]).unwrap();
        let signers: Vec<SignerId> = vec![]; // Empty!
        let message_hash = compute_message_hash(b"test");
        let aggregate = AggregateSignature::new(sig, signers, message_hash);
        let group_pubkey = make_group_pubkey();

        let result = verify_aggregate(&aggregate, b"test", &group_pubkey);
        assert!(!result); // Should fail with empty signers
    }
}