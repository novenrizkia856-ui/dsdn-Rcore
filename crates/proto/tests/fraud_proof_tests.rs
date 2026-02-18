//! # Integration Tests — FraudProofChallengeProto (P.4)
//!
//! Challenge window: 3600s from receipt submission.
//! Hash order (consensus-critical, immutable):
//! receipt_hash → challenger_address → challenger_signature →
//! execution_trace_segment → disputed_step_index BE → expected_output_hash → timestamp BE

use dsdn_proto::tx::fraud_proof::{
    compute_fraud_proof_hash, decode_fraud_proof, encode_fraud_proof,
    FraudProofChallengeProto, FraudProofError,
    CHALLENGER_ADDRESS_SIZE, CHALLENGER_SIGNATURE_SIZE,
    EXPECTED_OUTPUT_HASH_SIZE, RECEIPT_HASH_SIZE,
};

type R = Result<(), Box<dyn std::error::Error>>;

fn make_valid() -> FraudProofChallengeProto {
    FraudProofChallengeProto {
        receipt_hash: vec![0x01; 32],
        challenger_address: vec![0x02; 20],
        challenger_signature: vec![0x03; 64],
        execution_trace_segment: vec![0x04; 128],
        disputed_step_index: 10,
        expected_output_hash: vec![0x05; 32],
        timestamp: 1_700_000_000,
    }
}

// ── VALIDATE ────────────────────────────────────────────────────────

#[test]
fn validate_happy_path() {
    assert!(make_valid().validate().is_ok());
}

#[test]
fn validate_fails_receipt_hash_not_32() {
    let mut c = make_valid();
    c.receipt_hash = vec![0x01; 16];
    assert!(matches!(
        c.validate(),
        Err(FraudProofError::InvalidLength { field: "receipt_hash", expected: 32, found: 16 })
    ));
}

#[test]
fn validate_fails_receipt_hash_empty() {
    let mut c = make_valid();
    c.receipt_hash = Vec::new();
    assert!(c.validate().is_err());
}

#[test]
fn validate_fails_challenger_address_not_20() {
    let mut c = make_valid();
    c.challenger_address = vec![0x02; 32];
    assert!(matches!(
        c.validate(),
        Err(FraudProofError::InvalidLength { field: "challenger_address", expected: 20, found: 32 })
    ));
}

#[test]
fn validate_fails_challenger_signature_not_64() {
    let mut c = make_valid();
    c.challenger_signature = vec![0x03; 32];
    assert!(c.validate().is_err());
}

#[test]
fn validate_fails_expected_output_hash_not_32() {
    let mut c = make_valid();
    c.expected_output_hash = vec![0x05; 48];
    assert!(c.validate().is_err());
}

#[test]
fn validate_fails_empty_trace_segment() {
    let mut c = make_valid();
    c.execution_trace_segment = Vec::new();
    assert!(matches!(c.validate(), Err(FraudProofError::EmptyTraceSegment)));
}

#[test]
fn validate_minimal_trace_ok() {
    let mut c = make_valid();
    c.execution_trace_segment = vec![0xFF];
    assert!(c.validate().is_ok());
}

#[test]
fn validate_step_index_zero_ok() {
    let mut c = make_valid();
    c.disputed_step_index = 0;
    assert!(c.validate().is_ok());
}

#[test]
fn validate_step_index_max_ok() {
    let mut c = make_valid();
    c.disputed_step_index = u64::MAX;
    assert!(c.validate().is_ok());
}

#[test]
fn validate_timestamp_zero_ok() {
    let mut c = make_valid();
    c.timestamp = 0;
    assert!(c.validate().is_ok());
}

#[test]
fn validate_timestamp_max_ok() {
    let mut c = make_valid();
    c.timestamp = u64::MAX;
    assert!(c.validate().is_ok());
}

// ── HASH ────────────────────────────────────────────────────────────

#[test]
fn hash_deterministic() -> R {
    assert_eq!(make_valid().compute_challenge_hash()?, make_valid().compute_challenge_hash()?);
    Ok(())
}

#[test]
fn hash_differs_receipt_hash() -> R {
    let mut c2 = make_valid();
    c2.receipt_hash = vec![0xFF; 32];
    assert_ne!(make_valid().compute_challenge_hash()?, c2.compute_challenge_hash()?);
    Ok(())
}

#[test]
fn hash_differs_challenger_address() -> R {
    let mut c2 = make_valid();
    c2.challenger_address = vec![0xFF; 20];
    assert_ne!(make_valid().compute_challenge_hash()?, c2.compute_challenge_hash()?);
    Ok(())
}

#[test]
fn hash_differs_trace_segment() -> R {
    let mut c2 = make_valid();
    c2.execution_trace_segment = vec![0xFF; 128];
    assert_ne!(make_valid().compute_challenge_hash()?, c2.compute_challenge_hash()?);
    Ok(())
}

#[test]
fn hash_differs_step_index() -> R {
    let mut c2 = make_valid();
    c2.disputed_step_index = 999;
    assert_ne!(make_valid().compute_challenge_hash()?, c2.compute_challenge_hash()?);
    Ok(())
}

#[test]
fn hash_differs_expected_output() -> R {
    let mut c2 = make_valid();
    c2.expected_output_hash = vec![0xFF; 32];
    assert_ne!(make_valid().compute_challenge_hash()?, c2.compute_challenge_hash()?);
    Ok(())
}

#[test]
fn hash_differs_timestamp() -> R {
    let mut c2 = make_valid();
    c2.timestamp = 1_700_999_999;
    assert_ne!(make_valid().compute_challenge_hash()?, c2.compute_challenge_hash()?);
    Ok(())
}

#[test]
fn hash_rejects_invalid() {
    let mut c = make_valid();
    c.receipt_hash = vec![0x01; 5];
    assert!(c.compute_challenge_hash().is_err());
}

#[test]
fn hash_32_bytes_not_zero() -> R {
    let h = make_valid().compute_challenge_hash()?;
    assert_eq!(h.len(), 32);
    assert_ne!(h, [0u8; 32]);
    Ok(())
}

#[test]
fn hash_standalone_matches_method() -> R {
    let c = make_valid();
    assert_eq!(c.compute_challenge_hash()?, compute_fraud_proof_hash(&c)?);
    Ok(())
}

// ── ENCODE / DECODE ─────────────────────────────────────────────────

#[test]
fn encode_decode_roundtrip() -> R {
    let c = make_valid();
    let decoded = FraudProofChallengeProto::decode(&c.encode()?)?;
    assert_eq!(c, decoded);
    Ok(())
}

#[test]
fn encode_decode_preserves_hash() -> R {
    let c = make_valid();
    let hash_before = c.compute_challenge_hash()?;
    let decoded = FraudProofChallengeProto::decode(&c.encode()?)?;
    assert_eq!(hash_before, decoded.compute_challenge_hash()?);
    Ok(())
}

#[test]
fn encode_decode_encode_byte_identical() -> R {
    let b1 = make_valid().encode()?;
    let b2 = FraudProofChallengeProto::decode(&b1)?.encode()?;
    assert_eq!(b1, b2);
    Ok(())
}

#[test]
fn standalone_encode_decode() -> R {
    let c = make_valid();
    let decoded = decode_fraud_proof(&encode_fraud_proof(&c))?;
    assert_eq!(c, decoded);
    Ok(())
}

#[test]
fn standalone_encode_matches_method() -> R {
    let c = make_valid();
    assert_eq!(c.encode()?, encode_fraud_proof(&c));
    Ok(())
}

#[test]
fn decode_invalid_bytes() {
    assert!(FraudProofChallengeProto::decode(&[0xFF, 0x01]).is_err());
}

#[test]
fn decode_empty_bytes() {
    assert!(FraudProofChallengeProto::decode(&[]).is_err());
}

// ── CLONE / EQ / CONSTANTS / ERROR ──────────────────────────────────

#[test]
fn clone_equal() {
    assert_eq!(make_valid(), make_valid().clone());
}

#[test]
fn different_not_equal() {
    let mut c2 = make_valid();
    c2.disputed_step_index = 999;
    assert_ne!(make_valid(), c2);
}

#[test]
fn constants_correct() {
    assert_eq!(RECEIPT_HASH_SIZE, 32);
    assert_eq!(CHALLENGER_ADDRESS_SIZE, 20);
    assert_eq!(CHALLENGER_SIGNATURE_SIZE, 64);
    assert_eq!(EXPECTED_OUTPUT_HASH_SIZE, 32);
}

#[test]
fn error_display_invalid_length() {
    let err = FraudProofError::InvalidLength {
        field: "receipt_hash",
        expected: 32,
        found: 16,
    };
    let msg = format!("{}", err);
    assert!(msg.contains("receipt_hash") && msg.contains("32") && msg.contains("16"));
}

#[test]
fn error_display_empty_trace() {
    assert!(!format!("{}", FraudProofError::EmptyTraceSegment).is_empty());
}

#[test]
fn error_display_hashing_failed() {
    assert!(!format!("{}", FraudProofError::HashingFailed).is_empty());
}