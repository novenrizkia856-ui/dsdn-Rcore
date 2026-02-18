//! # Integration Tests — ReceiptV1Proto, ReceiptTypeProto, ChallengePeriodStatusProto (P.2/P.5/P.7)

use dsdn_proto::tss::execution::ExecutionCommitmentProto;
use dsdn_proto::tss::receipt_v1::{
    ChallengeStatusProto, ChallengePeriodError, ChallengePeriodStatusProto,
    ReceiptTypeProto, ReceiptV1Error, ReceiptV1Proto,
    compute_receipt_v1_hash, encode_receipt_v1,
    CHALLENGER_ADDRESS_SIZE, CHALLENGE_RECEIPT_HASH_SIZE, CHALLENGE_WINDOW_SECS,
    RECEIPT_TYPE_COMPUTE, RECEIPT_TYPE_STORAGE,
};
use dsdn_proto::tss::signing::AggregateSignatureProto;

type R = Result<(), Box<dyn std::error::Error>>;

// ── HELPERS ─────────────────────────────────────────────────────────

fn make_agg_sig() -> AggregateSignatureProto {
    AggregateSignatureProto {
        signature: vec![0xAA; 64],
        signer_ids: vec![vec![0x01; 32], vec![0x02; 32]],
        message_hash: vec![0xBB; 32],
        aggregated_at: 1_700_000_000,
    }
}

fn make_ec() -> ExecutionCommitmentProto {
    ExecutionCommitmentProto {
        workload_id: vec![0x10; 32],
        input_hash: vec![0x11; 32],
        output_hash: vec![0x12; 32],
        state_root_before: vec![0x13; 32],
        state_root_after: vec![0x14; 32],
        execution_trace_merkle_root: vec![0x15; 32],
    }
}

fn make_storage() -> ReceiptV1Proto {
    ReceiptV1Proto {
        workload_id: vec![0x01; 32],
        node_id: vec![0x02; 32],
        receipt_type: RECEIPT_TYPE_STORAGE,
        usage_proof_hash: vec![0x03; 32],
        execution_commitment: None,
        coordinator_threshold_signature: make_agg_sig(),
        node_signature: vec![0x04; 64],
        submitter_address: vec![0x05; 20],
        reward_base: 1_000_000,
        timestamp: 1_700_000_000,
        epoch: 42,
    }
}

fn make_compute() -> ReceiptV1Proto {
    ReceiptV1Proto {
        receipt_type: RECEIPT_TYPE_COMPUTE,
        execution_commitment: Some(make_ec()),
        ..make_storage()
    }
}

// ── RECEIPT V1 VALIDATE ─────────────────────────────────────────────

#[test]
fn validate_storage_ok() {
    assert!(make_storage().validate().is_ok());
}

#[test]
fn validate_compute_ok() {
    assert!(make_compute().validate().is_ok());
}

#[test]
fn validate_compute_without_ec_fails() {
    let mut r = make_compute();
    r.execution_commitment = None;
    assert!(matches!(r.validate(), Err(ReceiptV1Error::MissingExecutionCommitment)));
}

#[test]
fn validate_storage_with_ec_fails() {
    let mut r = make_storage();
    r.execution_commitment = Some(make_ec());
    assert!(matches!(r.validate(), Err(ReceiptV1Error::UnexpectedExecutionCommitment)));
}

#[test]
fn validate_invalid_workload_id() {
    let mut r = make_storage();
    r.workload_id = vec![0x01; 16];
    assert!(r.validate().is_err());
}

#[test]
fn validate_invalid_node_id() {
    let mut r = make_storage();
    r.node_id = vec![0x02; 10];
    assert!(r.validate().is_err());
}

#[test]
fn validate_invalid_receipt_type() {
    let mut r = make_storage();
    r.receipt_type = 5;
    assert!(r.validate().is_err());
}

#[test]
fn validate_invalid_usage_proof_hash() {
    let mut r = make_storage();
    r.usage_proof_hash = Vec::new();
    assert!(r.validate().is_err());
}

#[test]
fn validate_invalid_node_signature() {
    let mut r = make_storage();
    r.node_signature = vec![0x04; 32];
    assert!(r.validate().is_err());
}

#[test]
fn validate_invalid_submitter_address() {
    let mut r = make_storage();
    r.submitter_address = vec![0x05; 32];
    assert!(r.validate().is_err());
}

// ── RECEIPT V1 HASH ─────────────────────────────────────────────────

#[test]
fn hash_storage_deterministic() -> R {
    assert_eq!(make_storage().compute_receipt_hash()?, make_storage().compute_receipt_hash()?);
    Ok(())
}

#[test]
fn hash_compute_deterministic() -> R {
    assert_eq!(make_compute().compute_receipt_hash()?, make_compute().compute_receipt_hash()?);
    Ok(())
}

#[test]
fn hash_storage_vs_compute_different() -> R {
    assert_ne!(make_storage().compute_receipt_hash()?, make_compute().compute_receipt_hash()?);
    Ok(())
}

#[test]
fn hash_differs_epoch() -> R {
    let mut r2 = make_storage();
    r2.epoch = 999;
    assert_ne!(make_storage().compute_receipt_hash()?, r2.compute_receipt_hash()?);
    Ok(())
}

#[test]
fn hash_standalone_matches_method() -> R {
    let r = make_storage();
    assert_eq!(r.compute_receipt_hash()?, compute_receipt_v1_hash(&r)?);
    Ok(())
}

#[test]
fn hash_rejects_invalid() {
    let mut r = make_storage();
    r.workload_id = vec![0x01; 5];
    assert!(r.compute_receipt_hash().is_err());
}

// ── RECEIPT V1 ENCODE / DECODE ──────────────────────────────────────

#[test]
fn encode_decode_storage_roundtrip() -> R {
    let r = make_storage();
    let decoded = ReceiptV1Proto::decode(&r.encode()?)?;
    assert_eq!(r, decoded);
    Ok(())
}

#[test]
fn encode_decode_compute_roundtrip() -> R {
    let r = make_compute();
    let decoded = ReceiptV1Proto::decode(&r.encode()?)?;
    assert_eq!(r, decoded);
    Ok(())
}

#[test]
fn encode_decode_preserves_hash() -> R {
    let r = make_compute();
    let hash_before = r.compute_receipt_hash()?;
    let decoded = ReceiptV1Proto::decode(&r.encode()?)?;
    assert_eq!(hash_before, decoded.compute_receipt_hash()?);
    Ok(())
}

#[test]
fn standalone_encode_matches_method() -> R {
    let r = make_storage();
    assert_eq!(r.encode()?, encode_receipt_v1(&r));
    Ok(())
}

#[test]
fn decode_invalid_bytes() {
    assert!(ReceiptV1Proto::decode(&[0xFF, 0x01]).is_err());
}

// ── RECEIPT V1 HELPERS ──────────────────────────────────────────────

#[test]
fn helper_is_storage() {
    let r = make_storage();
    assert!(r.is_storage());
    assert!(!r.is_compute());
    assert!(!r.requires_challenge_period());
    assert!(!r.has_execution_commitment());
}

#[test]
fn helper_is_compute() {
    let r = make_compute();
    assert!(r.is_compute());
    assert!(!r.is_storage());
    assert!(r.requires_challenge_period());
    assert!(r.has_execution_commitment());
}

// ── RECEIPT TYPE PROTO ──────────────────────────────────────────────

#[test]
fn receipt_type_from_u8_valid() {
    assert_eq!(ReceiptTypeProto::from_u8(0), Some(ReceiptTypeProto::Storage));
    assert_eq!(ReceiptTypeProto::from_u8(1), Some(ReceiptTypeProto::Compute));
}

#[test]
fn receipt_type_from_u8_invalid() {
    assert_eq!(ReceiptTypeProto::from_u8(2), None);
    assert_eq!(ReceiptTypeProto::from_u8(255), None);
}

#[test]
fn receipt_type_as_u8_matches_constants() {
    assert_eq!(ReceiptTypeProto::Storage.as_u8(), RECEIPT_TYPE_STORAGE);
    assert_eq!(ReceiptTypeProto::Compute.as_u8(), RECEIPT_TYPE_COMPUTE);
}

#[test]
fn receipt_type_roundtrip_0_and_1() {
    for v in 0..=1u8 {
        let rt = ReceiptTypeProto::from_u8(v);
        assert!(rt.is_some());
        if let Some(r) = rt {
            assert_eq!(r.as_u8(), v);
        }
    }
}

#[test]
fn receipt_type_requires_ec() {
    assert!(!ReceiptTypeProto::Storage.requires_execution_commitment());
    assert!(ReceiptTypeProto::Compute.requires_execution_commitment());
}

#[test]
fn receipt_type_requires_challenge() {
    assert!(!ReceiptTypeProto::Storage.requires_challenge_period());
    assert!(ReceiptTypeProto::Compute.requires_challenge_period());
}

// ── CHALLENGE STATUS PROTO ──────────────────────────────────────────

#[test]
fn challenge_status_from_u8_all_valid() {
    assert_eq!(ChallengeStatusProto::from_u8(0), Some(ChallengeStatusProto::Pending));
    assert_eq!(ChallengeStatusProto::from_u8(1), Some(ChallengeStatusProto::Challenged));
    assert_eq!(ChallengeStatusProto::from_u8(2), Some(ChallengeStatusProto::Cleared));
    assert_eq!(ChallengeStatusProto::from_u8(3), Some(ChallengeStatusProto::Slashed));
}

#[test]
fn challenge_status_invalid() {
    assert_eq!(ChallengeStatusProto::from_u8(4), None);
    assert_eq!(ChallengeStatusProto::from_u8(255), None);
}

#[test]
fn challenge_status_terminal() {
    assert!(!ChallengeStatusProto::Pending.is_terminal());
    assert!(!ChallengeStatusProto::Challenged.is_terminal());
    assert!(ChallengeStatusProto::Cleared.is_terminal());
    assert!(ChallengeStatusProto::Slashed.is_terminal());
}

#[test]
fn challenge_status_active() {
    assert!(ChallengeStatusProto::Pending.is_active());
    assert!(ChallengeStatusProto::Challenged.is_active());
    assert!(!ChallengeStatusProto::Cleared.is_active());
    assert!(!ChallengeStatusProto::Slashed.is_active());
}

// ── CHALLENGE PERIOD STATUS ─────────────────────────────────────────

fn make_pending() -> ChallengePeriodStatusProto {
    ChallengePeriodStatusProto {
        receipt_hash: vec![0x01; 32],
        status: ChallengeStatusProto::Pending.as_u8(),
        challenge_start: 1_700_000_000,
        challenge_end: 1_700_000_000 + CHALLENGE_WINDOW_SECS,
        challenger: None,
    }
}

fn make_challenged() -> ChallengePeriodStatusProto {
    ChallengePeriodStatusProto {
        status: ChallengeStatusProto::Challenged.as_u8(),
        challenger: Some(vec![0x02; 20]),
        ..make_pending()
    }
}

#[test]
fn cp_validate_pending_ok() {
    assert!(make_pending().validate().is_ok());
}

#[test]
fn cp_validate_challenged_ok() {
    assert!(make_challenged().validate().is_ok());
}

#[test]
fn cp_validate_invalid_receipt_hash() {
    let mut s = make_pending();
    s.receipt_hash = vec![0x01; 10];
    assert!(s.validate().is_err());
}

#[test]
fn cp_validate_invalid_status() {
    let mut s = make_pending();
    s.status = 99;
    assert!(s.validate().is_err());
}

#[test]
fn cp_validate_end_before_start() {
    let mut s = make_pending();
    s.challenge_end = s.challenge_start - 1;
    assert!(s.validate().is_err());
}

#[test]
fn cp_challenged_without_challenger() {
    let mut s = make_challenged();
    s.challenger = None;
    assert!(matches!(s.validate(), Err(ChallengePeriodError::ChallengerRequired)));
}

#[test]
fn cp_pending_with_challenger() {
    let mut s = make_pending();
    s.challenger = Some(vec![0x02; 20]);
    assert!(matches!(s.validate(), Err(ChallengePeriodError::ChallengerMustBeNone)));
}

#[test]
fn cp_is_expired() {
    let s = make_pending();
    assert!(!s.is_expired(s.challenge_end - 1));
    assert!(s.is_expired(s.challenge_end));
    assert!(s.is_expired(s.challenge_end + 1));
}

#[test]
fn cp_encode_decode_roundtrip() -> R {
    let s = make_pending();
    let decoded = ChallengePeriodStatusProto::decode(&s.encode()?)?;
    assert_eq!(s, decoded);
    Ok(())
}

#[test]
fn cp_encode_decode_challenged_roundtrip() -> R {
    let s = make_challenged();
    let decoded = ChallengePeriodStatusProto::decode(&s.encode()?)?;
    assert_eq!(s, decoded);
    Ok(())
}

// ── CONSTANTS ───────────────────────────────────────────────────────

#[test]
fn constants_correct() {
    assert_eq!(RECEIPT_TYPE_STORAGE, 0);
    assert_eq!(RECEIPT_TYPE_COMPUTE, 1);
    assert_eq!(CHALLENGE_RECEIPT_HASH_SIZE, 32);
    assert_eq!(CHALLENGER_ADDRESS_SIZE, 20);
    assert_eq!(CHALLENGE_WINDOW_SECS, 3600);
}