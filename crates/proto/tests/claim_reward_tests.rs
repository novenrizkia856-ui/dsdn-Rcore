//! # Integration Tests — ClaimRewardProto & RewardDistributionProto (P.3/P.6)

use dsdn_proto::tss::execution::ExecutionCommitmentProto;
use dsdn_proto::tss::receipt_v1::{ReceiptV1Proto, RECEIPT_TYPE_COMPUTE, RECEIPT_TYPE_STORAGE};
use dsdn_proto::tss::signing::AggregateSignatureProto;
use dsdn_proto::tx::claim_reward::{
    compute_claim_reward_hash, decode_claim_reward, encode_claim_reward,
    ClaimRewardError, ClaimRewardProto, RewardDistributionError, RewardDistributionProto,
    REWARD_RECEIPT_HASH_SIZE, SUBMITTER_ADDRESS_SIZE, SUBMITTER_SIGNATURE_SIZE,
};

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

fn make_storage_receipt() -> ReceiptV1Proto {
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

fn make_compute_receipt() -> ReceiptV1Proto {
    ReceiptV1Proto {
        receipt_type: RECEIPT_TYPE_COMPUTE,
        execution_commitment: Some(make_ec()),
        ..make_storage_receipt()
    }
}

fn make_storage_claim() -> ClaimRewardProto {
    ClaimRewardProto {
        receipt: make_storage_receipt(),
        submitter_address: vec![0x05; 20],
        submitter_signature: vec![0x06; 64],
        nonce: 1,
        timestamp: 1_700_000_000,
    }
}

fn make_compute_claim() -> ClaimRewardProto {
    ClaimRewardProto {
        receipt: make_compute_receipt(),
        submitter_address: vec![0x05; 20],
        submitter_signature: vec![0x06; 64],
        nonce: 1,
        timestamp: 1_700_000_000,
    }
}

fn make_valid_distribution() -> RewardDistributionProto {
    RewardDistributionProto {
        receipt_hash: vec![0x01; 32],
        node_reward: 700_000,
        validator_reward: 200_000,
        treasury_reward: 100_000,
        total: 1_000_000,
        anti_self_dealing_applied: false,
        challenge_period_active: false,
    }
}

// ── CLAIM REWARD VALIDATE ───────────────────────────────────────────

#[test]
fn claim_validate_storage_ok() {
    assert!(make_storage_claim().validate().is_ok());
}

#[test]
fn claim_validate_compute_ok() {
    assert!(make_compute_claim().validate().is_ok());
}

#[test]
fn claim_validate_invalid_submitter_address() {
    let mut c = make_storage_claim();
    c.submitter_address = vec![0x05; 10];
    assert!(matches!(
        c.validate(),
        Err(ClaimRewardError::InvalidLength { field: "submitter_address", expected: 20, found: 10 })
    ));
}

#[test]
fn claim_validate_invalid_submitter_signature() {
    let mut c = make_storage_claim();
    c.submitter_signature = vec![0x06; 32];
    assert!(c.validate().is_err());
}

#[test]
fn claim_validate_empty_signature() {
    let mut c = make_storage_claim();
    c.submitter_signature = Vec::new();
    assert!(c.validate().is_err());
}

#[test]
fn claim_validate_invalid_receipt_propagates() {
    let mut c = make_storage_claim();
    c.receipt.workload_id = vec![0x01; 5];
    assert!(matches!(c.validate(), Err(ClaimRewardError::ReceiptInvalid)));
}

#[test]
fn claim_validate_nonce_zero_ok() {
    let mut c = make_storage_claim();
    c.nonce = 0;
    assert!(c.validate().is_ok());
}

#[test]
fn claim_validate_nonce_max_ok() {
    let mut c = make_storage_claim();
    c.nonce = u64::MAX;
    assert!(c.validate().is_ok());
}

// ── CLAIM REWARD HASH ───────────────────────────────────────────────

#[test]
fn claim_hash_deterministic() -> R {
    let c = make_storage_claim();
    assert_eq!(c.compute_tx_hash()?, c.compute_tx_hash()?);
    Ok(())
}

#[test]
fn claim_hash_differs_nonce() -> R {
    let c1 = make_storage_claim();
    let mut c2 = make_storage_claim();
    c2.nonce = 999;
    assert_ne!(c1.compute_tx_hash()?, c2.compute_tx_hash()?);
    Ok(())
}

#[test]
fn claim_hash_differs_timestamp() -> R {
    let c1 = make_storage_claim();
    let mut c2 = make_storage_claim();
    c2.timestamp = 1_700_999_999;
    assert_ne!(c1.compute_tx_hash()?, c2.compute_tx_hash()?);
    Ok(())
}

#[test]
fn claim_hash_storage_vs_compute_different() -> R {
    assert_ne!(make_storage_claim().compute_tx_hash()?, make_compute_claim().compute_tx_hash()?);
    Ok(())
}

#[test]
fn claim_hash_standalone_matches_method() -> R {
    let c = make_storage_claim();
    assert_eq!(c.compute_tx_hash()?, compute_claim_reward_hash(&c)?);
    Ok(())
}

#[test]
fn claim_hash_rejects_invalid() {
    let mut c = make_storage_claim();
    c.submitter_address = vec![0x05; 10];
    assert!(c.compute_tx_hash().is_err());
}

#[test]
fn claim_hash_32_bytes_not_zero() -> R {
    let h = make_storage_claim().compute_tx_hash()?;
    assert_eq!(h.len(), 32);
    assert_ne!(h, [0u8; 32]);
    Ok(())
}

// ── CLAIM REWARD ENCODE / DECODE ────────────────────────────────────

#[test]
fn claim_encode_decode_storage_roundtrip() -> R {
    let c = make_storage_claim();
    let decoded = ClaimRewardProto::decode(&c.encode()?)?;
    assert_eq!(c, decoded);
    Ok(())
}

#[test]
fn claim_encode_decode_compute_roundtrip() -> R {
    let c = make_compute_claim();
    let decoded = ClaimRewardProto::decode(&c.encode()?)?;
    assert_eq!(c, decoded);
    Ok(())
}

#[test]
fn claim_encode_decode_preserves_hash() -> R {
    let c = make_compute_claim();
    let hash_before = c.compute_tx_hash()?;
    let decoded = ClaimRewardProto::decode(&c.encode()?)?;
    assert_eq!(hash_before, decoded.compute_tx_hash()?);
    Ok(())
}

#[test]
fn claim_standalone_encode_decode() -> R {
    let c = make_storage_claim();
    let decoded = decode_claim_reward(&encode_claim_reward(&c))?;
    assert_eq!(c, decoded);
    Ok(())
}

#[test]
fn claim_decode_invalid_bytes() {
    assert!(ClaimRewardProto::decode(&[0xFF, 0x01, 0x02]).is_err());
}

#[test]
fn claim_decode_empty_bytes() {
    assert!(ClaimRewardProto::decode(&[]).is_err());
}

// ── REWARD DISTRIBUTION VALIDATE ────────────────────────────────────

#[test]
fn rd_validate_ok() {
    assert!(make_valid_distribution().validate().is_ok());
}

#[test]
fn rd_validate_all_zeros_ok() {
    let d = RewardDistributionProto {
        receipt_hash: vec![0x00; 32],
        node_reward: 0,
        validator_reward: 0,
        treasury_reward: 0,
        total: 0,
        anti_self_dealing_applied: false,
        challenge_period_active: false,
    };
    assert!(d.validate().is_ok());
}

#[test]
fn rd_validate_invalid_receipt_hash() {
    let mut d = make_valid_distribution();
    d.receipt_hash = vec![0x01; 16];
    assert!(matches!(
        d.validate(),
        Err(RewardDistributionError::InvalidLength { field: "receipt_hash", .. })
    ));
}

#[test]
fn rd_validate_total_mismatch() {
    let mut d = make_valid_distribution();
    d.total = 999_999;
    assert!(matches!(
        d.validate(),
        Err(RewardDistributionError::TotalMismatch { expected: 999_999, computed: 1_000_000 })
    ));
}

#[test]
fn rd_validate_overflow_node_plus_validator() {
    let d = RewardDistributionProto {
        receipt_hash: vec![0x01; 32],
        node_reward: u128::MAX,
        validator_reward: 1,
        treasury_reward: 0,
        total: 0,
        anti_self_dealing_applied: false,
        challenge_period_active: false,
    };
    assert!(matches!(d.validate(), Err(RewardDistributionError::ArithmeticOverflow)));
}

#[test]
fn rd_validate_overflow_sum_plus_treasury() {
    let d = RewardDistributionProto {
        receipt_hash: vec![0x01; 32],
        node_reward: u128::MAX - 1,
        validator_reward: 1,
        treasury_reward: 1,
        total: 0,
        anti_self_dealing_applied: false,
        challenge_period_active: false,
    };
    assert!(d.validate().is_err());
}

#[test]
fn rd_validate_max_no_overflow() {
    let third = u128::MAX / 3;
    let remainder = u128::MAX - third * 2;
    let d = RewardDistributionProto {
        receipt_hash: vec![0x01; 32],
        node_reward: third,
        validator_reward: third,
        treasury_reward: remainder,
        total: u128::MAX,
        anti_self_dealing_applied: false,
        challenge_period_active: false,
    };
    assert!(d.validate().is_ok());
}

#[test]
fn rd_validate_with_flags() {
    let mut d = make_valid_distribution();
    d.anti_self_dealing_applied = true;
    d.challenge_period_active = true;
    assert!(d.validate().is_ok());
}

// ── REWARD DISTRIBUTION ENCODE / DECODE ─────────────────────────────

#[test]
fn rd_encode_decode_roundtrip() -> R {
    let d = make_valid_distribution();
    let decoded = RewardDistributionProto::decode(&d.encode()?)?;
    assert_eq!(d, decoded);
    Ok(())
}

#[test]
fn rd_encode_decode_with_flags() -> R {
    let mut d = make_valid_distribution();
    d.anti_self_dealing_applied = true;
    d.challenge_period_active = true;
    let decoded = RewardDistributionProto::decode(&d.encode()?)?;
    assert_eq!(d, decoded);
    Ok(())
}

#[test]
fn rd_decode_invalid_bytes() {
    assert!(RewardDistributionProto::decode(&[0xFF, 0x01]).is_err());
}

#[test]
fn rd_decode_empty_bytes() {
    assert!(RewardDistributionProto::decode(&[]).is_err());
}

// ── CONSTANTS / ERROR DISPLAY ───────────────────────────────────────

#[test]
fn constants_correct() {
    assert_eq!(SUBMITTER_ADDRESS_SIZE, 20);
    assert_eq!(SUBMITTER_SIGNATURE_SIZE, 64);
    assert_eq!(REWARD_RECEIPT_HASH_SIZE, 32);
}

#[test]
fn claim_error_display_invalid_length() {
    let err = ClaimRewardError::InvalidLength {
        field: "submitter_address",
        expected: 20,
        found: 10,
    };
    let msg = format!("{}", err);
    assert!(msg.contains("submitter_address"));
}

#[test]
fn claim_error_display_receipt_invalid() {
    assert!(!format!("{}", ClaimRewardError::ReceiptInvalid).is_empty());
}

#[test]
fn rd_error_display_overflow() {
    assert!(!format!("{}", RewardDistributionError::ArithmeticOverflow).is_empty());
}

#[test]
fn rd_error_display_total_mismatch() {
    let err = RewardDistributionError::TotalMismatch {
        expected: 100,
        computed: 200,
    };
    let msg = format!("{}", err);
    assert!(msg.contains("100") && msg.contains("200"));
}