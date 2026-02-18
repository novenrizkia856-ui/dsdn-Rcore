//! # Integration Tests — ExecutionCommitmentProto (P.1)
//!
//! Hash order (consensus-critical, immutable):
//! 1. workload_id (32) → 2. input_hash (32) → 3. output_hash (32)
//! → 4. state_root_before (32) → 5. state_root_after (32)
//! → 6. execution_trace_merkle_root (32)
//! Total: 192 bytes → SHA3-256 → 32 bytes.

use dsdn_proto::tss::execution::{
    compute_execution_commitment_hash, decode_execution_commitment, encode_execution_commitment,
    ExecutionCommitmentError, ExecutionCommitmentProto, EXECUTION_FIELD_SIZE,
};

type R = Result<(), Box<dyn std::error::Error>>;

fn make_valid() -> ExecutionCommitmentProto {
    ExecutionCommitmentProto {
        workload_id: vec![0x01; 32],
        input_hash: vec![0x02; 32],
        output_hash: vec![0x03; 32],
        state_root_before: vec![0x04; 32],
        state_root_after: vec![0x05; 32],
        execution_trace_merkle_root: vec![0x06; 32],
    }
}

// ── VALIDATE ────────────────────────────────────────────────────────

#[test]
fn validate_happy_path() {
    assert!(make_valid().validate().is_ok());
}

#[test]
fn validate_fails_workload_id_not_32() {
    let mut c = make_valid();
    c.workload_id = vec![0x01; 16];
    assert!(matches!(
        c.validate(),
        Err(ExecutionCommitmentError::InvalidLength { field: "workload_id", .. })
    ));
}

#[test]
fn validate_fails_input_hash_not_32() {
    let mut c = make_valid();
    c.input_hash = vec![0x02; 48];
    assert!(matches!(
        c.validate(),
        Err(ExecutionCommitmentError::InvalidLength { field: "input_hash", .. })
    ));
}

#[test]
fn validate_fails_output_hash_not_32() {
    let mut c = make_valid();
    c.output_hash = vec![0x03; 10];
    assert!(c.validate().is_err());
}

#[test]
fn validate_fails_state_root_before_not_32() {
    let mut c = make_valid();
    c.state_root_before = vec![0x04; 64];
    assert!(matches!(
        c.validate(),
        Err(ExecutionCommitmentError::InvalidLength { field: "state_root_before", .. })
    ));
}

#[test]
fn validate_fails_state_root_after_not_32() {
    let mut c = make_valid();
    c.state_root_after = Vec::new();
    assert!(matches!(
        c.validate(),
        Err(ExecutionCommitmentError::InvalidLength { field: "state_root_after", found: 0, .. })
    ));
}

#[test]
fn validate_fails_trace_merkle_root_not_32() {
    let mut c = make_valid();
    c.execution_trace_merkle_root = vec![0x06; 5];
    assert!(matches!(
        c.validate(),
        Err(ExecutionCommitmentError::InvalidLength { field: "execution_trace_merkle_root", .. })
    ));
}

#[test]
fn validate_first_invalid_field_reported() {
    let c = ExecutionCommitmentProto {
        workload_id: vec![0x01; 10],       // invalid — reported first
        input_hash: vec![0x02; 5],          // also invalid
        output_hash: vec![0x03; 32],
        state_root_before: vec![0x04; 32],
        state_root_after: vec![0x05; 32],
        execution_trace_merkle_root: vec![0x06; 32],
    };
    assert!(matches!(
        c.validate(),
        Err(ExecutionCommitmentError::InvalidLength { field: "workload_id", .. })
    ));
}

// ── HASH ────────────────────────────────────────────────────────────

#[test]
fn hash_deterministic() -> R {
    assert_eq!(make_valid().compute_hash()?, make_valid().compute_hash()?);
    Ok(())
}

#[test]
fn hash_differs_workload_id() -> R {
    let mut c2 = make_valid();
    c2.workload_id = vec![0xFF; 32];
    assert_ne!(make_valid().compute_hash()?, c2.compute_hash()?);
    Ok(())
}

#[test]
fn hash_differs_input_hash() -> R {
    let mut c2 = make_valid();
    c2.input_hash = vec![0xFF; 32];
    assert_ne!(make_valid().compute_hash()?, c2.compute_hash()?);
    Ok(())
}

#[test]
fn hash_differs_output_hash() -> R {
    let mut c2 = make_valid();
    c2.output_hash = vec![0xFF; 32];
    assert_ne!(make_valid().compute_hash()?, c2.compute_hash()?);
    Ok(())
}

#[test]
fn hash_differs_state_root_before() -> R {
    let mut c2 = make_valid();
    c2.state_root_before = vec![0xFF; 32];
    assert_ne!(make_valid().compute_hash()?, c2.compute_hash()?);
    Ok(())
}

#[test]
fn hash_differs_state_root_after() -> R {
    let mut c2 = make_valid();
    c2.state_root_after = vec![0xFF; 32];
    assert_ne!(make_valid().compute_hash()?, c2.compute_hash()?);
    Ok(())
}

#[test]
fn hash_differs_trace_merkle_root() -> R {
    let mut c2 = make_valid();
    c2.execution_trace_merkle_root = vec![0xFF; 32];
    assert_ne!(make_valid().compute_hash()?, c2.compute_hash()?);
    Ok(())
}

#[test]
fn hash_rejects_invalid() {
    let mut c = make_valid();
    c.workload_id = vec![0x01; 5];
    assert!(c.compute_hash().is_err());
}

#[test]
fn hash_output_32_bytes_not_zero() -> R {
    let h = make_valid().compute_hash()?;
    assert_eq!(h.len(), 32);
    assert_ne!(h, [0u8; 32]);
    Ok(())
}

#[test]
fn hash_standalone_matches_method() -> R {
    let c = make_valid();
    assert_eq!(c.compute_hash()?, compute_execution_commitment_hash(&c)?);
    Ok(())
}

// ── ENCODE / DECODE ─────────────────────────────────────────────────

#[test]
fn encode_decode_roundtrip() -> R {
    let c = make_valid();
    let decoded = ExecutionCommitmentProto::decode(&c.encode()?)?;
    assert_eq!(c, decoded);
    Ok(())
}

#[test]
fn encode_decode_preserves_hash() -> R {
    let c = make_valid();
    let hash_before = c.compute_hash()?;
    let decoded = ExecutionCommitmentProto::decode(&c.encode()?)?;
    assert_eq!(hash_before, decoded.compute_hash()?);
    Ok(())
}

#[test]
fn encode_decode_encode_byte_identical() -> R {
    let b1 = make_valid().encode()?;
    let b2 = ExecutionCommitmentProto::decode(&b1)?.encode()?;
    assert_eq!(b1, b2);
    Ok(())
}

#[test]
fn standalone_encode_matches_method() -> R {
    let c = make_valid();
    assert_eq!(c.encode()?, encode_execution_commitment(&c));
    Ok(())
}

#[test]
fn standalone_decode_roundtrip() -> R {
    let c = make_valid();
    let decoded = decode_execution_commitment(&encode_execution_commitment(&c))?;
    assert_eq!(c, decoded);
    Ok(())
}

#[test]
fn decode_invalid_bytes() {
    assert!(ExecutionCommitmentProto::decode(&[0xFF, 0x01]).is_err());
}

#[test]
fn decode_empty_bytes() {
    assert!(ExecutionCommitmentProto::decode(&[]).is_err());
}

// ── CLONE / EQ / CONSTANTS / ERROR ──────────────────────────────────

#[test]
fn clone_equal() {
    assert_eq!(make_valid(), make_valid().clone());
}

#[test]
fn different_not_equal() {
    let mut c2 = make_valid();
    c2.output_hash = vec![0xFF; 32];
    assert_ne!(make_valid(), c2);
}

#[test]
fn constant_field_size() {
    assert_eq!(EXECUTION_FIELD_SIZE, 32);
}

#[test]
fn error_display_invalid_length() {
    let err = ExecutionCommitmentError::InvalidLength {
        field: "workload_id",
        expected: 32,
        found: 10,
    };
    let msg = format!("{}", err);
    assert!(msg.contains("workload_id"));
    assert!(msg.contains("32"));
    assert!(msg.contains("10"));
}

#[test]
fn error_display_hashing_failed() {
    assert!(!format!("{}", ExecutionCommitmentError::HashingFailed).is_empty());
}