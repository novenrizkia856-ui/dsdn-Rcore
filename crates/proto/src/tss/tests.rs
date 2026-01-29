//! # TSS Integration Tests
//!
//! Module ini menyediakan integration tests untuk TSS protocol messages.
//!
//! ## Test Categories
//!
//! | Category | Tests |
//! |----------|-------|
//! | Roundtrip | encode → decode untuk semua types |
//! | Hash Determinism | hash sama untuk data sama |
//! | Validation | menolak data invalid |

use super::*;

// ════════════════════════════════════════════════════════════════════════════════
// TEST HELPERS
// ════════════════════════════════════════════════════════════════════════════════

fn make_valid_dkg_round1() -> DKGRound1PackageProto {
    DKGRound1PackageProto {
        session_id: vec![0x01; 32],
        participant_id: vec![0x02; 32],
        commitment: vec![0x03; 32],
        proof: vec![0x04; 64],
    }
}

fn make_valid_dkg_round2() -> DKGRound2PackageProto {
    DKGRound2PackageProto {
        session_id: vec![0x01; 32],
        from_participant: vec![0x02; 32],
        to_participant: vec![0x03; 32],
        encrypted_share: vec![0x04; 48],
    }
}

fn make_valid_dkg_result() -> DKGResultProto {
    DKGResultProto::success(
        vec![0x01; 32],                               // session_id
        vec![0x02; 32],                               // group_pubkey
        vec![vec![0x03; 32], vec![0x04; 32]],         // participant_pubkeys
        2,                                            // threshold
    )
}

fn make_valid_signing_request() -> SigningRequestProto {
    SigningRequestProto {
        session_id: vec![0x01; 32],
        message: b"Hello, World!".to_vec(),
        message_hash: vec![0x02; 32],
        required_signers: vec![vec![0x03; 32], vec![0x04; 32]],
        epoch: 1,
        timeout_secs: 30,
        request_timestamp: 1700000000,
    }
}

fn make_valid_signing_commitment() -> SigningCommitmentProto {
    SigningCommitmentProto {
        session_id: vec![0x01; 32],
        signer_id: vec![0x02; 32],
        hiding: vec![0x03; 32],
        binding: vec![0x04; 32],
        timestamp: 1700000000,
    }
}

fn make_valid_partial_signature() -> PartialSignatureProto {
    PartialSignatureProto {
        session_id: vec![0x01; 32],
        signer_id: vec![0x02; 32],
        signature_share: vec![0x03; 32],
        commitment: make_valid_signing_commitment(),
    }
}

fn make_valid_aggregate_signature() -> AggregateSignatureProto {
    AggregateSignatureProto {
        signature: vec![0xAA; 64],
        signer_ids: vec![vec![0x01; 32], vec![0x02; 32]],
        message_hash: vec![0xBB; 32],
        aggregated_at: 1700000000,
    }
}

fn make_valid_coordinator_member(id_byte: u8, stake: u64) -> CoordinatorMemberProto {
    CoordinatorMemberProto {
        id: vec![id_byte; 32],
        validator_id: vec![id_byte; 32],
        pubkey: vec![id_byte; 32],
        stake,
        joined_at: 1700000000,
    }
}

fn make_valid_coordinator_committee() -> CoordinatorCommitteeProto {
    CoordinatorCommitteeProto {
        members: vec![
            make_valid_coordinator_member(0x01, 1000),
            make_valid_coordinator_member(0x02, 2000),
        ],
        threshold: 2,
        epoch: 1,
        epoch_start: 1700000000,
        epoch_duration_secs: 3600,
        group_pubkey: vec![0xAA; 32],
    }
}

fn make_valid_receipt_data() -> ReceiptDataProto {
    ReceiptDataProto {
        workload_id: vec![0x01; 32],
        blob_hash: vec![0x02; 32],
        placement: vec![vec![0x03; 32], vec![0x04; 32]],
        timestamp: 1700000000,
        sequence: 1,
        epoch: 1,
    }
}

fn make_valid_threshold_receipt() -> ThresholdReceiptProto {
    ThresholdReceiptProto {
        receipt_data: make_valid_receipt_data(),
        signature: make_valid_aggregate_signature(),
        signer_ids: vec![vec![0x01; 32], vec![0x02; 32]], // Must match signature.signer_ids
        epoch: 1, // Must match receipt_data.epoch
        committee_hash: vec![0xCC; 32],
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// DKG ROUNDTRIP TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn test_dkg_round1_roundtrip() {
    let original = make_valid_dkg_round1();

    // Validate
    assert!(original.validate().is_ok(), "valid DKG round 1");

    // Encode
    let encoded = encode_dkg_round1(&original);
    assert!(!encoded.is_empty(), "encoded bytes not empty");

    // Decode
    let decoded = decode_dkg_round1(&encoded);
    assert!(decoded.is_ok(), "decode should succeed");

    // Compare
    assert_eq!(original, decoded.expect("valid"), "roundtrip matches");
}

#[test]
fn test_dkg_round2_roundtrip() {
    let original = make_valid_dkg_round2();

    // Validate
    assert!(original.validate().is_ok(), "valid DKG round 2");

    // Encode
    let encoded = encode_dkg_round2(&original);
    assert!(!encoded.is_empty(), "encoded bytes not empty");

    // Decode
    let decoded = decode_dkg_round2(&encoded);
    assert!(decoded.is_ok(), "decode should succeed");

    // Compare
    assert_eq!(original, decoded.expect("valid"), "roundtrip matches");
}

#[test]
fn test_dkg_result_roundtrip() {
    let original = make_valid_dkg_result();

    // Validate
    assert!(original.validate().is_ok(), "valid DKG result");

    // Encode
    let encoded = encode_dkg_result(&original);
    assert!(!encoded.is_empty(), "encoded bytes not empty");

    // Decode
    let decoded = decode_dkg_result(&encoded);
    assert!(decoded.is_ok(), "decode should succeed");

    // Compare
    assert_eq!(original, decoded.expect("valid"), "roundtrip matches");
}

// ════════════════════════════════════════════════════════════════════════════════
// SIGNING ROUNDTRIP TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn test_signing_request_roundtrip() {
    let original = make_valid_signing_request();

    // Validate
    assert!(original.validate().is_ok(), "valid signing request");

    // Encode
    let encoded = encode_signing_request(&original);
    assert!(!encoded.is_empty(), "encoded bytes not empty");

    // Decode
    let decoded = decode_signing_request(&encoded);
    assert!(decoded.is_ok(), "decode should succeed");

    // Compare
    assert_eq!(original, decoded.expect("valid"), "roundtrip matches");
}

#[test]
fn test_signing_commitment_roundtrip() {
    let original = make_valid_signing_commitment();

    // Validate
    assert!(original.validate().is_ok(), "valid signing commitment");

    // Encode
    let encoded = encode_signing_commitment(&original);
    assert!(!encoded.is_empty(), "encoded bytes not empty");

    // Decode
    let decoded = decode_signing_commitment(&encoded);
    assert!(decoded.is_ok(), "decode should succeed");

    // Compare
    assert_eq!(original, decoded.expect("valid"), "roundtrip matches");
}

#[test]
fn test_partial_signature_roundtrip() {
    let original = make_valid_partial_signature();

    // Validate
    assert!(original.validate().is_ok(), "valid partial signature");

    // Encode
    let encoded = encode_partial_signature(&original);
    assert!(!encoded.is_empty(), "encoded bytes not empty");

    // Decode
    let decoded = decode_partial_signature(&encoded);
    assert!(decoded.is_ok(), "decode should succeed");

    // Compare
    assert_eq!(original, decoded.expect("valid"), "roundtrip matches");
}

#[test]
fn test_aggregate_signature_roundtrip() {
    let original = make_valid_aggregate_signature();

    // Validate
    assert!(original.validate().is_ok(), "valid aggregate signature");

    // Encode
    let encoded = encode_aggregate_signature(&original);
    assert!(!encoded.is_empty(), "encoded bytes not empty");

    // Decode
    let decoded = decode_aggregate_signature(&encoded);
    assert!(decoded.is_ok(), "decode should succeed");

    // Compare
    assert_eq!(original, decoded.expect("valid"), "roundtrip matches");
}

// ════════════════════════════════════════════════════════════════════════════════
// COMMITTEE ROUNDTRIP TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn test_coordinator_member_roundtrip() {
    let member = make_valid_coordinator_member(0x01, 1000);

    // Validate
    assert!(member.validate().is_ok(), "valid coordinator member");

    // Member is nested, test via committee
    let committee = CoordinatorCommitteeProto {
        members: vec![member.clone()],
        threshold: 1,
        epoch: 1,
        epoch_start: 1700000000,
        epoch_duration_secs: 3600,
        group_pubkey: vec![0xAA; 32],
    };

    let encoded = encode_committee(&committee);
    let decoded = decode_committee(&encoded).expect("valid");

    assert_eq!(committee.members[0], decoded.members[0], "member roundtrip matches");
}

#[test]
fn test_coordinator_committee_roundtrip() {
    let original = make_valid_coordinator_committee();

    // Validate
    assert!(original.validate().is_ok(), "valid coordinator committee");

    // Encode
    let encoded = encode_committee(&original);
    assert!(!encoded.is_empty(), "encoded bytes not empty");

    // Decode
    let decoded = decode_committee(&encoded);
    assert!(decoded.is_ok(), "decode should succeed");

    // Compare
    assert_eq!(original, decoded.expect("valid"), "roundtrip matches");
}

// ════════════════════════════════════════════════════════════════════════════════
// RECEIPT ROUNDTRIP TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn test_receipt_data_roundtrip() {
    let original = make_valid_receipt_data();

    // Validate
    assert!(original.validate().is_ok(), "valid receipt data");

    // Receipt data is nested, test via threshold receipt
    let receipt = ThresholdReceiptProto {
        receipt_data: original.clone(),
        signature: make_valid_aggregate_signature(),
        signer_ids: vec![vec![0x01; 32], vec![0x02; 32]],
        epoch: original.epoch,
        committee_hash: vec![0xCC; 32],
    };

    let encoded = encode_receipt(&receipt);
    let decoded = decode_receipt(&encoded).expect("valid");

    assert_eq!(original, decoded.receipt_data, "receipt data roundtrip matches");
}

#[test]
fn test_threshold_receipt_roundtrip() {
    let original = make_valid_threshold_receipt();

    // Validate
    assert!(original.validate().is_ok(), "valid threshold receipt");

    // Encode
    let encoded = encode_receipt(&original);
    assert!(!encoded.is_empty(), "encoded bytes not empty");

    // Decode
    let decoded = decode_receipt(&encoded);
    assert!(decoded.is_ok(), "decode should succeed");

    // Compare
    assert_eq!(original, decoded.expect("valid"), "roundtrip matches");
}

// ════════════════════════════════════════════════════════════════════════════════
// HASH DETERMINISM TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn test_hash_determinism_all_types() {
    // DKG Round 1
    let dkg_round1 = make_valid_dkg_round1();
    let hash1_a = compute_dkg_round1_hash(&dkg_round1);
    let hash1_b = compute_dkg_round1_hash(&dkg_round1);
    assert_eq!(hash1_a, hash1_b, "DKG round 1 hash deterministic");

    // Aggregate Signature
    let agg_sig = make_valid_aggregate_signature();
    let hash2_a = compute_aggregate_signature_hash(&agg_sig);
    let hash2_b = compute_aggregate_signature_hash(&agg_sig);
    assert_eq!(hash2_a, hash2_b, "Aggregate signature hash deterministic");

    // Committee
    let committee = make_valid_coordinator_committee();
    let hash3_a = compute_committee_hash(&committee);
    let hash3_b = compute_committee_hash(&committee);
    assert_eq!(hash3_a, hash3_b, "Committee hash deterministic");

    // Receipt
    let receipt = make_valid_threshold_receipt();
    let hash4_a = compute_receipt_hash(&receipt);
    let hash4_b = compute_receipt_hash(&receipt);
    assert_eq!(hash4_a, hash4_b, "Receipt hash deterministic");

    // Receipt Data
    let receipt_data = make_valid_receipt_data();
    let hash5_a = receipt_data.compute_hash();
    let hash5_b = receipt_data.compute_hash();
    assert_eq!(hash5_a, hash5_b, "Receipt data hash deterministic");
}

#[test]
fn test_hash_changes_on_data_change() {
    // DKG Round 1
    let dkg1 = make_valid_dkg_round1();
    let mut dkg2 = make_valid_dkg_round1();
    dkg2.commitment = vec![0xFF; 32]; // Change commitment
    assert_ne!(
        compute_dkg_round1_hash(&dkg1),
        compute_dkg_round1_hash(&dkg2),
        "DKG hash changes on data change"
    );

    // Committee
    let comm1 = make_valid_coordinator_committee();
    let mut comm2 = make_valid_coordinator_committee();
    comm2.epoch = 999;
    assert_ne!(
        compute_committee_hash(&comm1),
        compute_committee_hash(&comm2),
        "Committee hash changes on data change"
    );

    // Receipt
    let rcpt1 = make_valid_threshold_receipt();
    let mut rcpt2 = make_valid_threshold_receipt();
    rcpt2.committee_hash = vec![0xFF; 32];
    assert_ne!(
        compute_receipt_hash(&rcpt1),
        compute_receipt_hash(&rcpt2),
        "Receipt hash changes on data change"
    );
}

// ════════════════════════════════════════════════════════════════════════════════
// VALIDATION REJECTION TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn test_validation_rejects_invalid() {
    // Invalid DKG Round 1 - wrong session_id length
    let mut dkg = make_valid_dkg_round1();
    dkg.session_id = vec![0x01; 16]; // Wrong length
    assert!(dkg.validate().is_err(), "rejects invalid session_id length");

    // Invalid DKG Round 2 - wrong from_participant length
    let mut dkg2 = make_valid_dkg_round2();
    dkg2.from_participant = vec![0x01; 64]; // Wrong length
    assert!(dkg2.validate().is_err(), "rejects invalid from_participant length");

    // Invalid Signing Request - empty signers
    let mut req = make_valid_signing_request();
    req.required_signers = vec![]; // Empty
    assert!(req.validate().is_err(), "rejects empty signers");

    // Invalid Commitment - wrong hiding length
    let mut commit = make_valid_signing_commitment();
    commit.hiding = vec![0x01; 16]; // Wrong length
    assert!(commit.validate().is_err(), "rejects invalid hiding length");

    // Invalid Aggregate Signature - wrong signature length
    let mut agg = make_valid_aggregate_signature();
    agg.signature = vec![0x01; 32]; // Wrong length
    assert!(agg.validate().is_err(), "rejects invalid signature length");

    // Invalid Committee - empty members
    let mut comm = make_valid_coordinator_committee();
    comm.members = vec![]; // Empty
    assert!(comm.validate().is_err(), "rejects empty members");

    // Invalid Receipt - epoch mismatch
    let mut rcpt = make_valid_threshold_receipt();
    rcpt.epoch = 999; // Doesn't match receipt_data.epoch
    assert!(rcpt.validate().is_err(), "rejects epoch mismatch");

    // Invalid Receipt - signer_ids mismatch
    let mut rcpt2 = make_valid_threshold_receipt();
    rcpt2.signer_ids = vec![vec![0xFF; 32]]; // Different from signature.signer_ids
    assert!(rcpt2.validate().is_err(), "rejects signer_ids mismatch");
}

// ════════════════════════════════════════════════════════════════════════════════
// ENCODING DETERMINISM TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn test_encoding_determinism() {
    // DKG Round 1
    let dkg = make_valid_dkg_round1();
    let enc1 = encode_dkg_round1(&dkg);
    let enc2 = encode_dkg_round1(&dkg);
    assert_eq!(enc1, enc2, "DKG round 1 encoding deterministic");

    // DKG Round 2
    let dkg2 = make_valid_dkg_round2();
    let enc3 = encode_dkg_round2(&dkg2);
    let enc4 = encode_dkg_round2(&dkg2);
    assert_eq!(enc3, enc4, "DKG round 2 encoding deterministic");

    // Signing Request
    let req = make_valid_signing_request();
    let enc5 = encode_signing_request(&req);
    let enc6 = encode_signing_request(&req);
    assert_eq!(enc5, enc6, "Signing request encoding deterministic");

    // Committee
    let comm = make_valid_coordinator_committee();
    let enc7 = encode_committee(&comm);
    let enc8 = encode_committee(&comm);
    assert_eq!(enc7, enc8, "Committee encoding deterministic");

    // Receipt
    let rcpt = make_valid_threshold_receipt();
    let enc9 = encode_receipt(&rcpt);
    let enc10 = encode_receipt(&rcpt);
    assert_eq!(enc9, enc10, "Receipt encoding deterministic");
}

// ════════════════════════════════════════════════════════════════════════════════
// DECODE VALIDATES TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn test_decode_validates_data() {
    // Create invalid proto by bypassing validation
    let invalid_dkg = DKGRound1PackageProto {
        session_id: vec![0x01; 16], // Invalid length
        participant_id: vec![0x02; 32],
        commitment: vec![0x03; 32],
        proof: vec![0x04; 64],
    };

    // Encode without validation
    let bytes = bincode::serialize(&invalid_dkg).expect("serialize");

    // Decode should fail validation
    let result = decode_dkg_round1(&bytes);
    assert!(result.is_err(), "decode validates and rejects invalid data");
}

// ════════════════════════════════════════════════════════════════════════════════
// SEND + SYNC TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn test_types_are_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<DKGRound1PackageProto>();
    assert_send_sync::<DKGRound2PackageProto>();
    assert_send_sync::<DKGResultProto>();
    assert_send_sync::<SigningRequestProto>();
    assert_send_sync::<SigningCommitmentProto>();
    assert_send_sync::<PartialSignatureProto>();
    assert_send_sync::<AggregateSignatureProto>();
    assert_send_sync::<CoordinatorMemberProto>();
    assert_send_sync::<CoordinatorCommitteeProto>();
    assert_send_sync::<ReceiptDataProto>();
    assert_send_sync::<ThresholdReceiptProto>();
}

// ════════════════════════════════════════════════════════════════════════════════
// ERROR TYPE TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn test_error_types_are_error_trait() {
    fn assert_error<T: std::error::Error>() {}

    assert_error::<ValidationError>();
    assert_error::<DecodeError>();
    assert_error::<SigningValidationError>();
    assert_error::<SigningDecodeError>();
    assert_error::<CommitteeValidationError>();
    assert_error::<CommitteeDecodeError>();
}

// ════════════════════════════════════════════════════════════════════════════════
// SIZE CONSTANT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn test_size_constants_are_correct() {
    // DKG constants
    assert_eq!(SESSION_ID_SIZE, 32);
    assert_eq!(PARTICIPANT_ID_SIZE, 32);
    assert_eq!(COMMITMENT_SIZE, 32);
    assert_eq!(PROOF_SIZE, 64);
    assert_eq!(GROUP_PUBKEY_SIZE, 32);

    // Signing constants
    assert_eq!(SIGNER_ID_SIZE, 32);
    assert_eq!(MESSAGE_HASH_SIZE, 32);
    assert_eq!(HIDING_SIZE, 32);
    assert_eq!(BINDING_SIZE, 32);
    assert_eq!(SIGNATURE_SHARE_SIZE, 32);
    assert_eq!(FROST_SIGNATURE_SIZE, 64);

    // Committee constants
    assert_eq!(COORDINATOR_ID_SIZE, 32);
    assert_eq!(VALIDATOR_ID_SIZE, 32);
    assert_eq!(PUBKEY_SIZE, 32);

    // Receipt constants
    assert_eq!(WORKLOAD_ID_SIZE, 32);
    assert_eq!(BLOB_HASH_SIZE, 32);
    assert_eq!(NODE_ID_SIZE, 32);
    assert_eq!(COMMITTEE_HASH_SIZE, 32);

    // Wrapper constants
    assert_eq!(BYTES_WRAPPER_SIZE, 32);
    assert_eq!(SIGNATURE_BYTES_SIZE, 64);
}