//! # FROST Integration Tests
//!
//! Comprehensive integration tests for the full DSDN TSS cryptographic pipeline:
//!
//! ```text
//! DKG → KeyShare → Signing → Aggregation → Verification
//! ```
//!
//! All tests use **real FROST cryptography** via `frost-ed25519` (ZCash Foundation).
//! No placeholders, no dummy keys, no mock cryptography.
//!
//! ## Test Categories
//!
//! | # | Test | Category |
//! |---|------|----------|
//! | 1 | full_dkg_3_of_3 | DKG |
//! | 2 | full_dkg_2_of_3 | DKG |
//! | 3 | dkg_round1_deterministic | DKG / Determinism |
//! | 4 | dkg_invalid_threshold | DKG / Error |
//! | 5 | full_signing_2_of_3 | Signing |
//! | 6 | full_signing_3_of_3 | Signing |
//! | 7 | signing_below_threshold | Signing / Error |
//! | 8 | aggregate_signature_verifiable | Aggregation + Verify |
//! | 9 | invalid_signature_rejected | Verification |
//! | 10 | partial_verification | Partial Verify |
//! | 11 | different_message_different_sig | Determinism |
//! | 12 | committee_from_genesis | Committee Logic |
//! | 13 | committee_member_offline | Committee Logic |
//! | 14 | committee_quorum_lost | Committee Logic |
//! | 15 | keyshare_encrypted_roundtrip | Serialization |
//! | 16 | end_to_end_dkg_sign_verify | Full Pipeline |
//! | 17 | committee_threshold_calculation | Committee Math |
//!
//! ## Determinism
//!
//! All tests use `ChaCha20Rng` with explicit u64 seeds.
//! Same seed → same output, guaranteed.

use std::collections::BTreeMap;

use frost_ed25519 as frost;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha3::{Digest, Sha3_256};

use dsdn_tss::dkg::{DKGParticipant, LocalDKGParticipant, Round2Package};
use dsdn_tss::error::DKGError;
use dsdn_tss::frost_adapter;
use dsdn_tss::keyshare::KeyShareSerialization;
use dsdn_tss::primitives::{
    EncryptionKey, GroupPublicKey, ParticipantPublicKey, SigningCommitment, SIGNATURE_SIZE,
};
use dsdn_tss::signing::{
    aggregate_signatures, PartialSignature,
};
use dsdn_tss::types::{ParticipantId, SessionId, SignerId};
use dsdn_tss::verify::{verify_aggregate, verify_frost_signature_bytes, verify_partial};
use dsdn_tss::KeyShare;

// ════════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS — DKG
// ════════════════════════════════════════════════════════════════════════════════

/// Create deterministic participant IDs from small integers.
///
/// Bytes layout: first byte = i (1..=n), rest zeros.
/// This produces valid little-endian nonzero scalars for frost.
fn make_participant_ids(n: usize) -> Vec<ParticipantId> {
    (1..=n)
        .map(|i| {
            let mut bytes = [0u8; 32];
            #[allow(clippy::cast_possible_truncation)]
            {
                bytes[0] = i as u8;
            }
            ParticipantId::from_bytes(bytes)
        })
        .collect()
}

/// Run a complete DKG ceremony with deterministic RNG.
///
/// Returns `Ok(Vec<KeyShare>)` for all participants.
fn run_full_dkg(
    threshold: u8,
    total: u8,
    seed: u64,
) -> Result<Vec<KeyShare>, DKGError> {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let session_id = SessionId::from_bytes([0xAA; 32]);
    let pids = make_participant_ids(total as usize);

    // Create participants
    let mut participants: Vec<LocalDKGParticipant> = Vec::new();
    for pid in &pids {
        participants.push(LocalDKGParticipant::new(
            pid.clone(),
            session_id.clone(),
            threshold,
            total,
        )?);
    }

    // Round 1: Generate packages
    let mut round1_packages = Vec::new();
    for p in &mut participants {
        round1_packages.push(p.generate_round1_with_rng(&mut rng)?);
    }

    // Round 1 → Round 2: Process and generate round 2 packages
    let mut all_round2_packages: Vec<Vec<Round2Package>> = Vec::new();
    for p in &mut participants {
        all_round2_packages.push(p.process_round1(&round1_packages)?);
    }

    // Round 2: Route and process
    let mut key_shares = Vec::new();
    for p in &mut participants {
        let my_packages: Vec<Round2Package> = all_round2_packages
            .iter()
            .flat_map(|pkgs| pkgs.iter())
            .filter(|pkg| pkg.to_participant() == p.participant_id())
            .cloned()
            .collect();
        key_shares.push(p.process_round2(&my_packages)?);
    }

    Ok(key_shares)
}

// ════════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS — SIGNING (via frost dealer keygen)
// ════════════════════════════════════════════════════════════════════════════════

/// Generate deterministic frost key material via trusted dealer.
///
/// This avoids the identifier mismatch between DKG's `derive()` and signing's
/// `deserialize()` by using frost's built-in key generation.
fn generate_frost_keys(
    n: u16,
    t: u16,
    seed: u64,
) -> Result<
    (
        BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
        frost::keys::PublicKeyPackage,
    ),
    String,
> {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let (shares, pubkey_package) = frost::keys::generate_with_dealer(
        n,
        t,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )
    .map_err(|e| format!("dealer keygen failed: {}", e))?;

    let mut key_packages = BTreeMap::new();
    for (identifier, secret_share) in shares {
        let key_package = frost::keys::KeyPackage::try_from(secret_share)
            .map_err(|e| format!("KeyPackage conversion failed: {}", e))?;
        key_packages.insert(identifier, key_package);
    }
    Ok((key_packages, pubkey_package))
}

/// Convert frost Identifier to SignerId.
fn frost_id_to_signer_id(id: &frost::Identifier) -> Result<SignerId, String> {
    let bytes = id.serialize();
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "frost Identifier not 32 bytes".to_string())?;
    Ok(SignerId::from_bytes(arr))
}

/// Compute DSDN message hash with domain separation.
fn compute_message_hash(message: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"dsdn-tss-message-hash-v1");
    hasher.update(message);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Full signing fixture: dealer keygen → commit → sign → partial sigs.
struct SigningFixture {
    message: Vec<u8>,
    message_hash: [u8; 32],
    partials: Vec<PartialSignature>,
    group_pubkey: GroupPublicKey,
    verifying_shares: Vec<(SignerId, ParticipantPublicKey)>,
    all_commitments: Vec<(SignerId, SigningCommitment)>,
    #[allow(dead_code)]
    pubkey_package: frost::keys::PublicKeyPackage,
}

fn create_signing_fixture(
    n: u16,
    t: u16,
    seed: u64,
    message: &[u8],
) -> Result<SigningFixture, String> {
    let (key_packages, pubkey_package) =
        generate_frost_keys(n, t, seed)?;
    let mut rng = ChaCha20Rng::seed_from_u64(seed.wrapping_add(1000));

    // Select first t signers
    let selected: Vec<_> = key_packages.iter().take(t as usize).collect();

    // Round 1: commitments
    let mut nonces_map = BTreeMap::new();
    let mut frost_commitments_map = BTreeMap::new();

    for &(id, ref kp) in &selected {
        let (nonces, commitments) = frost::round1::commit(kp.signing_share(), &mut rng);
        nonces_map.insert(*id, nonces);
        frost_commitments_map.insert(*id, commitments);
    }

    // Round 2: sign
    let signing_package =
        frost::SigningPackage::new(frost_commitments_map.clone(), message);

    let mut partials = Vec::new();
    let mut all_commitments = Vec::new();

    for &(id, ref kp) in &selected {
        let nonces = nonces_map
            .get(id)
            .ok_or_else(|| "missing nonces".to_string())?;
        let frost_share = frost::round2::sign(&signing_package, nonces, kp)
            .map_err(|e| format!("sign failed: {}", e))?;

        let sid = frost_id_to_signer_id(id)?;
        let our_share = frost_adapter::signature_share_to_sig_share(&frost_share)
            .map_err(|e| e.to_string())?;
        let our_commitment =
            frost_adapter::signing_commitments_to_commitment(&frost_commitments_map[id])
                .map_err(|e| e.to_string())?;

        all_commitments.push((sid.clone(), our_commitment.clone()));
        partials.push(PartialSignature::new(sid, our_share, our_commitment));
    }

    // Build verifying_shares
    let mut verifying_shares = Vec::new();
    for &(id, ref kp) in &selected {
        let sid = frost_id_to_signer_id(id)?;
        let vs_bytes = kp
            .verifying_share()
            .serialize()
            .map_err(|e| format!("serialize verifying share: {}", e))?;
        let arr: [u8; 32] = vs_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "verifying share not 32 bytes".to_string())?;
        let ppk =
            ParticipantPublicKey::from_bytes(arr).map_err(|e| e.to_string())?;
        verifying_shares.push((sid, ppk));
    }

    // Group pubkey
    let group_pubkey =
        frost_adapter::verifying_key_to_group_pubkey(pubkey_package.verifying_key())
            .map_err(|e| e.to_string())?;

    let message_hash = compute_message_hash(message);

    Ok(SigningFixture {
        message: message.to_vec(),
        message_hash,
        partials,
        group_pubkey,
        verifying_shares,
        all_commitments,
        pubkey_package,
    })
}

// ════════════════════════════════════════════════════════════════════════════════
// HELPER — Committee threshold calculation
// ════════════════════════════════════════════════════════════════════════════════

/// Byzantine-fault-tolerant committee threshold: t = ceil(2n/3) + 1.
///
/// Guarantees:
/// - Always > 2/3 of committee
/// - Always >= 2 (minimum for threshold signatures)
/// - Always <= n
fn committee_threshold(n: u8) -> u8 {
    if n < 2 {
        return n;
    }
    // ceil(2n/3) = (2n + 2) / 3  (integer division)
    let two_n = u16::from(n) * 2;
    let ceil_2n_3 = ((two_n + 2) / 3) as u8;
    let t = ceil_2n_3.saturating_add(1);
    // Clamp: t <= n
    if t > n { n } else { t }
}

/// Check if a quorum is met: need at least `threshold` active members.
fn has_quorum(active_count: u8, total: u8) -> bool {
    active_count >= committee_threshold(total)
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 1: full_dkg_3_of_3
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn full_dkg_3_of_3() -> Result<(), Box<dyn std::error::Error>> {
    let key_shares = run_full_dkg(3, 3, 1001)?;

    // Must produce exactly 3 shares
    assert_eq!(key_shares.len(), 3);

    // All group public keys must be identical
    let gpk0 = key_shares[0].group_public_key();
    for ks in &key_shares[1..] {
        assert_eq!(
            ks.group_public_key(),
            gpk0,
            "all participants must share identical group public key"
        );
    }

    // All signing shares must be unique
    for i in 0..key_shares.len() {
        for j in (i + 1)..key_shares.len() {
            assert_ne!(
                key_shares[i].signing_share(),
                key_shares[j].signing_share(),
                "signing shares must be unique per participant"
            );
        }
    }

    // Threshold and total stored correctly
    for ks in &key_shares {
        assert_eq!(ks.threshold(), 3);
        assert_eq!(ks.total(), 3);
    }

    // Signing shares must be 32 bytes, nonzero
    for ks in &key_shares {
        assert_eq!(ks.signing_share().len(), 32);
        assert!(
            ks.signing_share().iter().any(|&b| b != 0),
            "signing share must not be all zeros"
        );
    }

    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 2: full_dkg_2_of_3
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn full_dkg_2_of_3() -> Result<(), Box<dyn std::error::Error>> {
    let key_shares = run_full_dkg(2, 3, 2002)?;

    assert_eq!(key_shares.len(), 3);

    // Group public key identical
    let gpk0 = key_shares[0].group_public_key();
    for ks in &key_shares[1..] {
        assert_eq!(ks.group_public_key(), gpk0);
    }

    // Signing shares unique
    for i in 0..key_shares.len() {
        for j in (i + 1)..key_shares.len() {
            assert_ne!(key_shares[i].signing_share(), key_shares[j].signing_share());
        }
    }

    // Participant public keys unique
    for i in 0..key_shares.len() {
        for j in (i + 1)..key_shares.len() {
            assert_ne!(
                key_shares[i].participant_pubkey().as_bytes(),
                key_shares[j].participant_pubkey().as_bytes(),
                "participant public keys must be unique"
            );
        }
    }

    for ks in &key_shares {
        assert_eq!(ks.threshold(), 2);
        assert_eq!(ks.total(), 3);
    }

    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 3: dkg_round1_deterministic
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn dkg_round1_deterministic() -> Result<(), Box<dyn std::error::Error>> {
    // Run same DKG twice with same seed → must produce identical group key
    let shares_a = run_full_dkg(2, 3, 3003)?;
    let shares_b = run_full_dkg(2, 3, 3003)?;

    assert_eq!(
        shares_a[0].group_public_key(),
        shares_b[0].group_public_key(),
        "same seed must produce same group public key"
    );

    for i in 0..shares_a.len() {
        assert_eq!(
            shares_a[i].signing_share(),
            shares_b[i].signing_share(),
            "same seed must produce same signing shares"
        );
        assert_eq!(
            shares_a[i].participant_pubkey().as_bytes(),
            shares_b[i].participant_pubkey().as_bytes(),
            "same seed must produce same participant public keys"
        );
    }

    // Different seed → different group key
    let shares_c = run_full_dkg(2, 3, 3004)?;
    assert_ne!(
        shares_a[0].group_public_key(),
        shares_c[0].group_public_key(),
        "different seed must produce different group public key"
    );

    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 4: dkg_invalid_threshold
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn dkg_invalid_threshold() {
    // threshold > total → error
    let result = LocalDKGParticipant::new(
        ParticipantId::from_bytes([0x01; 32]),
        SessionId::from_bytes([0xBB; 32]),
        5,
        3,
    );
    assert!(result.is_err(), "threshold > total must fail");
    if let Err(DKGError::InvalidThreshold { threshold, total }) = result {
        assert_eq!(threshold, 5);
        assert_eq!(total, 3);
    }

    // threshold < 2 → error
    let result = LocalDKGParticipant::new(
        ParticipantId::from_bytes([0x01; 32]),
        SessionId::from_bytes([0xBB; 32]),
        1,
        3,
    );
    assert!(result.is_err(), "threshold < 2 must fail");

    // total < 2 → error
    let result = LocalDKGParticipant::new(
        ParticipantId::from_bytes([0x01; 32]),
        SessionId::from_bytes([0xBB; 32]),
        2,
        1,
    );
    assert!(result.is_err(), "total < 2 must fail");

    // threshold == 0 → error
    let result = LocalDKGParticipant::new(
        ParticipantId::from_bytes([0x01; 32]),
        SessionId::from_bytes([0xBB; 32]),
        0,
        3,
    );
    assert!(result.is_err(), "threshold == 0 must fail");
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 5: full_signing_2_of_3
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn full_signing_2_of_3() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = create_signing_fixture(3, 2, 5005, b"2-of-3 signing test")
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    // Aggregate
    let aggregate = aggregate_signatures(
        &fixture.message,
        &fixture.partials,
        &fixture.group_pubkey,
        &fixture.verifying_shares,
        &fixture.message_hash,
    )?;

    // Signature must be 64 bytes
    assert_eq!(aggregate.signature().as_bytes().len(), SIGNATURE_SIZE);
    assert_eq!(aggregate.signer_count(), 2);

    // Verify
    assert!(
        verify_aggregate(&aggregate, &fixture.message, &fixture.group_pubkey),
        "2-of-3 aggregate signature must verify"
    );

    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 6: full_signing_3_of_3
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn full_signing_3_of_3() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = create_signing_fixture(3, 3, 6006, b"3-of-3 signing test")
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    let aggregate = aggregate_signatures(
        &fixture.message,
        &fixture.partials,
        &fixture.group_pubkey,
        &fixture.verifying_shares,
        &fixture.message_hash,
    )?;

    assert_eq!(aggregate.signature().as_bytes().len(), SIGNATURE_SIZE);
    assert_eq!(aggregate.signer_count(), 3);

    assert!(
        verify_aggregate(&aggregate, &fixture.message, &fixture.group_pubkey),
        "3-of-3 aggregate signature must verify"
    );

    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 7: signing_below_threshold
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn signing_below_threshold() -> Result<(), Box<dyn std::error::Error>> {
    // Create 3-of-5 fixture (has 3 partials)
    let fixture = create_signing_fixture(5, 3, 7007, b"below threshold test")
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    // Only pass 1 partial (below threshold of 3)
    // frost::aggregate() should fail because Lagrange interpolation needs t shares
    let single_partial = &fixture.partials[0..1];

    let result = aggregate_signatures(
        &fixture.message,
        single_partial,
        &fixture.group_pubkey,
        &fixture.verifying_shares,
        &fixture.message_hash,
    );

    // Aggregation may succeed with fewer shares but produce invalid signature,
    // or frost may reject directly. Either way, the aggregate (if produced)
    // must NOT verify.
    match result {
        Err(_) => {
            // frost rejected below-threshold aggregation — correct behavior
        }
        Ok(aggregate) => {
            // frost produced an aggregate but it must not verify
            assert!(
                !verify_aggregate(&aggregate, &fixture.message, &fixture.group_pubkey),
                "below-threshold aggregate must not verify"
            );
        }
    }

    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 8: aggregate_signature_verifiable
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn aggregate_signature_verifiable() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = create_signing_fixture(5, 3, 8008, b"verifiable aggregate")
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    let aggregate = aggregate_signatures(
        &fixture.message,
        &fixture.partials,
        &fixture.group_pubkey,
        &fixture.verifying_shares,
        &fixture.message_hash,
    )?;

    // Verify via verify_aggregate
    assert!(
        verify_aggregate(&aggregate, &fixture.message, &fixture.group_pubkey),
        "aggregate signature must verify via verify_aggregate"
    );

    // Also verify via raw bytes (chain integration path)
    let pubkey_bytes = fixture.group_pubkey.as_bytes();
    let sig_bytes = aggregate.signature().as_bytes();

    assert!(
        verify_frost_signature_bytes(pubkey_bytes, &fixture.message, sig_bytes),
        "aggregate signature must verify via raw bytes"
    );

    // Signature = 64 bytes
    assert_eq!(sig_bytes.len(), 64, "signature must be 64 bytes");

    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 9: invalid_signature_rejected
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn invalid_signature_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = create_signing_fixture(5, 3, 9009, b"invalid sig test")
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    let aggregate = aggregate_signatures(
        &fixture.message,
        &fixture.partials,
        &fixture.group_pubkey,
        &fixture.verifying_shares,
        &fixture.message_hash,
    )?;

    // Wrong message → verification must fail
    assert!(
        !verify_aggregate(&aggregate, b"wrong message", &fixture.group_pubkey),
        "signature for different message must be rejected"
    );

    // Wrong pubkey → verification must fail
    let wrong_gpk = GroupPublicKey::from_bytes([0x01; 32]);
    if let Ok(wrong_gpk) = wrong_gpk {
        assert!(
            !verify_aggregate(&aggregate, &fixture.message, &wrong_gpk),
            "signature with wrong pubkey must be rejected"
        );
    }

    // Tampered signature bytes → verification must fail
    let mut tampered_sig = aggregate.signature().as_bytes().to_vec();
    tampered_sig[10] ^= 0xFF;
    assert!(
        !verify_frost_signature_bytes(
            fixture.group_pubkey.as_bytes(),
            &fixture.message,
            &tampered_sig,
        ),
        "tampered signature must be rejected"
    );

    // Zero signature → rejected
    let zero_sig = vec![0u8; 64];
    assert!(
        !verify_frost_signature_bytes(
            fixture.group_pubkey.as_bytes(),
            &fixture.message,
            &zero_sig,
        ),
        "zero signature must be rejected"
    );

    // Short signature → rejected
    let short_sig = vec![0x01u8; 32];
    assert!(
        !verify_frost_signature_bytes(
            fixture.group_pubkey.as_bytes(),
            &fixture.message,
            &short_sig,
        ),
        "short signature must be rejected"
    );

    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 10: partial_verification
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn partial_verification() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = create_signing_fixture(5, 3, 10010, b"partial verify test")
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    // Valid partial → verify_partial returns true
    let partial = &fixture.partials[0];
    let (_, ref ppk) = fixture.verifying_shares[0];

    assert!(
        verify_partial(partial, &fixture.message, ppk, &fixture.all_commitments),
        "valid partial signature must verify"
    );

    // Partial with wrong commitments → false
    let empty_commitments: Vec<(SignerId, SigningCommitment)> = vec![];
    assert!(
        !verify_partial(partial, &fixture.message, ppk, &empty_commitments),
        "partial with missing commitments must fail"
    );

    // All partials must individually verify
    for (i, partial) in fixture.partials.iter().enumerate() {
        let (_, ref ppk_i) = fixture.verifying_shares[i];
        assert!(
            verify_partial(partial, &fixture.message, ppk_i, &fixture.all_commitments),
            "partial {} must verify",
            i
        );
    }

    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 11: different_message_different_sig
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn different_message_different_sig() -> Result<(), Box<dyn std::error::Error>> {
    let fixture_a = create_signing_fixture(5, 3, 11011, b"message alpha")
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    let fixture_b = create_signing_fixture(5, 3, 11011, b"message beta")
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    let agg_a = aggregate_signatures(
        &fixture_a.message,
        &fixture_a.partials,
        &fixture_a.group_pubkey,
        &fixture_a.verifying_shares,
        &fixture_a.message_hash,
    )?;

    let agg_b = aggregate_signatures(
        &fixture_b.message,
        &fixture_b.partials,
        &fixture_b.group_pubkey,
        &fixture_b.verifying_shares,
        &fixture_b.message_hash,
    )?;

    // Different messages → different aggregate signatures
    assert_ne!(
        agg_a.signature().as_bytes(),
        agg_b.signature().as_bytes(),
        "different messages must produce different aggregate signatures"
    );

    // Both must verify with their own message
    assert!(verify_aggregate(&agg_a, &fixture_a.message, &fixture_a.group_pubkey));
    assert!(verify_aggregate(&agg_b, &fixture_b.message, &fixture_b.group_pubkey));

    // Cross-verification must fail
    assert!(
        !verify_aggregate(&agg_a, &fixture_b.message, &fixture_a.group_pubkey),
        "signature A must not verify with message B"
    );

    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 12: committee_from_genesis
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn committee_from_genesis() {
    // Genesis committee with 4 validators
    let n: u8 = 4;
    let t = committee_threshold(n);

    // t = ceil(2*4/3) + 1 = ceil(8/3) + 1 = 3 + 1 = 4
    assert_eq!(t, 4, "genesis committee of 4 needs threshold 4");

    // All members present → quorum met
    assert!(has_quorum(4, 4));

    // All members present for n=3
    let t3 = committee_threshold(3);
    // t = ceil(2*3/3) + 1 = ceil(6/3) + 1 = 2 + 1 = 3
    assert_eq!(t3, 3, "genesis committee of 3 needs threshold 3");
    assert!(has_quorum(3, 3));
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 13: committee_member_offline
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn committee_member_offline() {
    // 7-member committee, threshold = ceil(14/3) + 1 = 5 + 1 = 6
    let n: u8 = 7;
    let t = committee_threshold(n);
    assert_eq!(t, 6);

    // 6 active (1 offline) → quorum still met
    assert!(has_quorum(6, n), "6 of 7 must meet quorum");

    // 5 active (2 offline) → quorum lost
    assert!(!has_quorum(5, n), "5 of 7 must NOT meet quorum");

    // 10-member committee, threshold = ceil(20/3) + 1 = 7 + 1 = 8
    let n10: u8 = 10;
    let t10 = committee_threshold(n10);
    assert_eq!(t10, 8);

    // 8 active → quorum met
    assert!(has_quorum(8, n10));
    // 7 active → quorum lost
    assert!(!has_quorum(7, n10));
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 14: committee_quorum_lost
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn committee_quorum_lost() {
    // Verify quorum loss across different committee sizes
    let test_cases: Vec<(u8, u8)> = vec![
        (3, 3),   // t=3, need all 3
        (4, 4),   // t=4, need all 4
        (5, 5),   // t=5, need all 5
        (6, 5),   // t=5, can lose 1
        (7, 6),   // t=6, can lose 1
        (9, 7),   // t=7, can lose 2
        (10, 8),  // t=8, can lose 2
    ];

    for (n, expected_t) in &test_cases {
        let t = committee_threshold(*n);
        assert_eq!(
            t, *expected_t,
            "committee of {} should have threshold {}",
            n, expected_t
        );

        // Exactly at threshold → quorum met
        assert!(
            has_quorum(t, *n),
            "exactly at threshold ({}/{}) must have quorum",
            t,
            n
        );

        // One below threshold → quorum lost
        if t > 0 {
            assert!(
                !has_quorum(t - 1, *n),
                "below threshold ({}/{}) must lose quorum",
                t - 1,
                n
            );
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 15: keyshare_encrypted_roundtrip
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn keyshare_encrypted_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    // Run real DKG
    let key_shares = run_full_dkg(2, 3, 15015)?;
    let encryption_key = EncryptionKey::from_bytes([0x42; 32])?;

    for ks in &key_shares {
        // Encrypted roundtrip
        let encrypted = ks.serialize_encrypted(&encryption_key)?;
        let recovered = KeyShare::deserialize_encrypted(&encrypted, &encryption_key)?;

        assert_eq!(
            recovered.signing_share(),
            ks.signing_share(),
            "signing share must roundtrip identically"
        );
        assert_eq!(
            recovered.group_public_key(),
            ks.group_public_key(),
            "group public key must roundtrip identically"
        );
        assert_eq!(
            recovered.participant_pubkey().as_bytes(),
            ks.participant_pubkey().as_bytes(),
            "participant pubkey must roundtrip identically"
        );
        assert_eq!(recovered.threshold(), ks.threshold());
        assert_eq!(recovered.total(), ks.total());

        // Plaintext roundtrip
        let plaintext = ks.serialize_plaintext();
        let recovered_pt = KeyShare::deserialize_plaintext(&plaintext)?;

        assert_eq!(recovered_pt.signing_share(), ks.signing_share());
        assert_eq!(recovered_pt.group_public_key(), ks.group_public_key());

        // Wrong key must fail
        let wrong_key = EncryptionKey::from_bytes([0x99; 32])?;
        let wrong_result = KeyShare::deserialize_encrypted(&encrypted, &wrong_key);
        assert!(wrong_result.is_err(), "wrong key must fail decryption");

        // Encrypted output must not contain plaintext secret
        let secret_bytes = ks.signing_share();
        let contains_plaintext = encrypted
            .windows(32)
            .any(|window| window == secret_bytes);
        assert!(
            !contains_plaintext,
            "encrypted output must not leak plaintext secret share"
        );
    }

    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 16: end_to_end_dkg_sign_verify
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn end_to_end_dkg_sign_verify() -> Result<(), Box<dyn std::error::Error>> {
    // Phase 1: Real DKG (2-of-3)
    let key_shares = run_full_dkg(2, 3, 16016)?;

    let message = b"DSDN end-to-end integration test";
    let mut rng = ChaCha20Rng::seed_from_u64(16016_5000);

    // Phase 2: Signing — use frost API directly with correct derived identifiers
    // Derive frost Identifiers from ParticipantIds (same as DKG used internally)
    let mut frost_identifiers = Vec::new();
    for ks in &key_shares {
        let fid = frost_adapter::participant_id_to_frost_identifier(ks.participant_id())
            .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;
        frost_identifiers.push(fid);
    }

    // Convert key shares to frost signing shares and build key packages
    // with the CORRECT derived identifiers
    let mut frost_key_packages = Vec::new();
    for (i, ks) in key_shares.iter().enumerate() {
        let signing_share =
            frost_adapter::secret_share_to_signing_share(ks.secret_share())
                .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;
        let verifying_share =
            frost::keys::VerifyingShare::deserialize(ks.participant_pubkey().as_bytes())
                .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;
        let verifying_key =
            frost_adapter::group_pubkey_to_verifying_key(ks.group_pubkey())
                .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;

        let kp = frost::keys::KeyPackage::new(
            frost_identifiers[i],
            signing_share,
            verifying_share,
            verifying_key,
            u16::from(ks.threshold()),
        );
        frost_key_packages.push(kp);
    }

    // Select first 2 (threshold) participants
    let signers: Vec<usize> = vec![0, 1];

    // Round 1: Commit
    let mut nonces_map = BTreeMap::new();
    let mut frost_commitments_map = BTreeMap::new();

    for &idx in &signers {
        let (nonces, commitments) =
            frost::round1::commit(frost_key_packages[idx].signing_share(), &mut rng);
        nonces_map.insert(frost_identifiers[idx], nonces);
        frost_commitments_map.insert(frost_identifiers[idx], commitments);
    }

    // Round 2: Sign
    let signing_package =
        frost::SigningPackage::new(frost_commitments_map.clone(), &message[..]);

    let mut frost_shares = BTreeMap::new();
    for &idx in &signers {
        let fid = frost_identifiers[idx];
        let nonces = nonces_map
            .get(&fid)
            .ok_or("missing nonces")?;
        let share =
            frost::round2::sign(&signing_package, nonces, &frost_key_packages[idx])
                .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;
        frost_shares.insert(fid, share);
    }

    // Build PublicKeyPackage for aggregation
    let mut vs_map = BTreeMap::new();
    for &idx in &signers {
        let vs =
            frost::keys::VerifyingShare::deserialize(key_shares[idx].participant_pubkey().as_bytes())
                .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;
        vs_map.insert(frost_identifiers[idx], vs);
    }
    let vk =
        frost_adapter::group_pubkey_to_verifying_key(key_shares[0].group_pubkey())
            .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;
    let pubkey_package = frost::keys::PublicKeyPackage::new(vs_map, vk.clone());

    // Aggregate
    let frost_signature = frost::aggregate(&signing_package, &frost_shares, &pubkey_package)
        .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;

    // Phase 3: Verify — using our crate's verification function
    let sig_bytes = frost_signature
        .serialize()
        .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;

    assert_eq!(sig_bytes.len(), 64, "aggregate signature must be 64 bytes");

    let gpk_bytes = key_shares[0].group_public_key();
    assert!(
        verify_frost_signature_bytes(gpk_bytes, message, &sig_bytes),
        "end-to-end DKG→Sign→Verify must succeed"
    );

    // Verify via frost native API as well
    assert!(
        vk.verify(message, &frost_signature).is_ok(),
        "frost native verification must also succeed"
    );

    // Wrong message must fail
    assert!(
        !verify_frost_signature_bytes(gpk_bytes, b"wrong message", &sig_bytes),
        "wrong message must fail verification"
    );

    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 17: committee_threshold_calculation
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn committee_threshold_calculation() {
    // Mathematically verify t = ceil(2n/3) + 1 for all committee sizes 2..=20

    for n in 2u8..=20 {
        let t = committee_threshold(n);

        // Verify: t = ceil(2n/3) + 1
        let two_n = f64::from(n) * 2.0;
        let ceil_2n_3 = (two_n / 3.0).ceil() as u8;
        let expected = if ceil_2n_3 + 1 > n { n } else { ceil_2n_3 + 1 };
        assert_eq!(
            t, expected,
            "committee_threshold({}) = {} but expected {}",
            n, t, expected
        );

        // Verify: t >= 2 (minimum for threshold signatures)
        assert!(t >= 2, "threshold for n={} must be >= 2, got {}", n, t);

        // Verify: t <= n
        assert!(t <= n, "threshold for n={} must be <= n, got {}", n, t);

        // Verify: t > 2n/3 (BFT safety: more than 2/3)
        let two_thirds = (f64::from(n) * 2.0) / 3.0;
        assert!(
            f64::from(t) > two_thirds,
            "threshold {} must be > 2*{}/3 = {:.2}",
            t,
            n,
            two_thirds
        );
    }

    // Specific known values from the BFT formula:
    // n=3: t=3, n=4: t=4, n=5: t=4(ceil(10/3)+1=4+1=5, but 5>5 => 5? No)
    // Actually let me recalculate:
    // n=5: ceil(10/3)+1 = ceil(3.33)+1 = 4+1 = 5, 5<=5, so t=5? Hmm.
    // Wait: n=5, ceil(10/3) = 4, 4+1=5, 5<=5 so t=5? That means ALL 5 must sign.
    // n=5: t=5 (need all 5)
    // n=6: ceil(12/3)+1 = 4+1 = 5, 5<=6 so t=5
    // n=7: ceil(14/3)+1 = 5+1 = 6
    // n=9: ceil(18/3)+1 = 6+1 = 7
    let specific_cases = [
        (2u8, 2u8),
        (3, 3),
        (4, 4),
        (5, 5),
        (6, 5),
        (7, 6),
        (8, 7),
        (9, 7),
        (10, 8),
        (15, 11),
        (20, 15),
    ];

    for (n, expected_t) in &specific_cases {
        assert_eq!(
            committee_threshold(*n),
            *expected_t,
            "committee_threshold({}) must be {}",
            n,
            expected_t
        );
    }
}