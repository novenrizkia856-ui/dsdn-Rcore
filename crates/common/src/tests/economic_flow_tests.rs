//! # Economic Flow Integration Tests
//!
//! End-to-end tests yang memverifikasi seluruh economic flow DSDN:
//!
//! ```text
//! Node → ReceiptV1 → ClaimReward → Validation → Distribution
//!
//! Storage path:  immediate 70/20/10
//! Compute path:  challenge period → cleared → 70/20/10
//! Self-dealing:  detected → 0/20/80 redistribution
//! Dedup:         receipt hash tracked → second claim rejected
//! Hash:          native ↔ proto hash consistency
//! ```

use crate::anti_self_dealing::AntiSelfDealingCheck;
use crate::challenge_state::{ChallengeStatus, PendingChallenge};
use crate::claim_validation::{ClaimValidationError, ClaimValidationResult, RewardDistribution};
use crate::coordinator::WorkloadId;
use crate::economic_constants::{
    challenge_end_time, is_challenge_expired, is_receipt_expired, CHALLENGE_PERIOD_SECS,
    MAX_RECEIPT_AGE_SECS, REWARD_NODE_PERCENT, REWARD_TREASURY_PERCENT,
    REWARD_VALIDATOR_PERCENT,
};
use crate::receipt_dedup::ReceiptDedupTracker;
use crate::receipt_v1::{Address, ReceiptType, ReceiptV1};
use crate::receipt_v1_convert::{
    compute_receipt_hash_from_proto, compute_receipt_hash_proto_compatible, AggregateSignatureProto,
    ClaimReward, ClaimRewardProto, ExecutionCommitmentProto, ReceiptV1Proto,
};
use crate::execution_commitment::ExecutionCommitment;

// ════════════════════════════════════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════════════════════════════════════

fn make_storage_receipt() -> ReceiptV1 {
    ReceiptV1::new(
        WorkloadId::new([0x01; 32]),
        [0x02; 32],              // node_id
        ReceiptType::Storage,
        [0x03; 32],              // usage_proof_hash
        None,                    // no execution_commitment
        vec![0x04; 64],          // coordinator_threshold_signature
        vec![[0x05; 32], [0x06; 32]], // signer_ids
        vec![0x07; 64],          // node_signature
        [0x08; 20],              // submitter_address
        1_000_000,               // reward_base (1M NUSA)
        1_700_000_000,           // timestamp
        42,                      // epoch
    )
    .expect("storage receipt must be valid")
}

fn make_compute_receipt() -> ReceiptV1 {
    let ec = ExecutionCommitment::new(
        WorkloadId::new([0xA0; 32]),
        [0xA1; 32],
        [0xA2; 32],
        [0xA3; 32],
        [0xA4; 32],
        [0xA5; 32],
    );

    ReceiptV1::new(
        WorkloadId::new([0x01; 32]),
        [0x02; 32],
        ReceiptType::Compute,
        [0x03; 32],
        Some(ec),
        vec![0x04; 64],
        vec![[0x05; 32], [0x06; 32]],
        vec![0x07; 64],
        [0x08; 20],
        1_000_000,
        1_700_000_000,
        42,
    )
    .expect("compute receipt must be valid")
}

fn make_agg_sig_proto() -> AggregateSignatureProto {
    AggregateSignatureProto {
        signature: vec![0x04; 64],
        signer_ids: vec![vec![0x05; 32], vec![0x06; 32]],
        message_hash: vec![0xCC; 32],
        aggregated_at: 1_700_000_000,
    }
}

fn make_storage_receipt_proto() -> ReceiptV1Proto {
    ReceiptV1Proto {
        workload_id: vec![0x01; 32],
        node_id: vec![0x02; 32],
        receipt_type: 0,
        usage_proof_hash: vec![0x03; 32],
        execution_commitment: None,
        coordinator_threshold_signature: make_agg_sig_proto(),
        node_signature: vec![0x07; 64],
        submitter_address: vec![0x08; 20],
        reward_base: 1_000_000,
        timestamp: 1_700_000_000,
        epoch: 42,
    }
}

fn make_compute_receipt_proto() -> ReceiptV1Proto {
    ReceiptV1Proto {
        workload_id: vec![0x01; 32],
        node_id: vec![0x02; 32],
        receipt_type: 1,
        usage_proof_hash: vec![0x03; 32],
        execution_commitment: Some(ExecutionCommitmentProto {
            workload_id: vec![0xA0; 32],
            input_hash: vec![0xA1; 32],
            output_hash: vec![0xA2; 32],
            state_root_before: vec![0xA3; 32],
            state_root_after: vec![0xA4; 32],
            execution_trace_merkle_root: vec![0xA5; 32],
        }),
        coordinator_threshold_signature: make_agg_sig_proto(),
        node_signature: vec![0x07; 64],
        submitter_address: vec![0x08; 20],
        reward_base: 1_000_000,
        timestamp: 1_700_000_000,
        epoch: 42,
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// FLOW 1 — STORAGE PATH: Receipt → Proto → Back → ClaimReward → Distribution
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn flow_storage_receipt_to_immediate_reward() {
    // 1. Create native storage receipt.
    let receipt = make_storage_receipt();
    assert_eq!(receipt.receipt_type(), ReceiptType::Storage);
    assert!(!receipt.requires_challenge_period());

    // 2. Convert to proto.
    let proto = receipt.to_proto();
    assert_eq!(proto.receipt_type, 0);
    assert!(proto.execution_commitment.is_none());

    // 3. Convert back to native.
    let restored = ReceiptV1::from_proto(&proto).expect("roundtrip must succeed");
    assert_eq!(restored.workload_id(), receipt.workload_id());
    assert_eq!(restored.node_id(), receipt.node_id());
    assert_eq!(restored.reward_base(), receipt.reward_base());
    assert_eq!(restored.epoch(), receipt.epoch());

    // 4. Build ClaimReward.
    let claim_proto = ClaimRewardProto {
        receipt: proto,
        submitter_address: vec![0x08; 20],
        submitter_signature: vec![0xFF; 64],
        nonce: 1,
        timestamp: 1_700_000_001,
    };
    let claim = ClaimReward::from_proto(&claim_proto).expect("claim must be valid");
    assert_eq!(claim.nonce, 1);

    // 5. Storage → ImmediateReward.
    let distribution = RewardDistribution::compute(claim.receipt.reward_base());
    let result = ClaimValidationResult::ImmediateReward { distribution };

    // 6. Verify 70/20/10 split.
    match result {
        ClaimValidationResult::ImmediateReward { distribution: d } => {
            assert_eq!(d.node_reward, 700_000);
            assert_eq!(d.validator_reward, 200_000);
            assert_eq!(d.treasury_reward, 100_000);
            assert_eq!(
                d.node_reward + d.validator_reward + d.treasury_reward,
                claim.receipt.reward_base()
            );
        }
        _ => panic!("expected ImmediateReward for storage receipt"),
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// FLOW 2 — COMPUTE PATH: Receipt → Challenge → Expiry → Cleared → Distribution
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn flow_compute_receipt_challenge_period_to_cleared() {
    // 1. Create compute receipt.
    let receipt = make_compute_receipt();
    assert_eq!(receipt.receipt_type(), ReceiptType::Compute);
    assert!(receipt.requires_challenge_period());
    assert!(receipt.has_execution_commitment());

    // 2. Compute pending distribution.
    let distribution = RewardDistribution::compute(receipt.reward_base());
    let receipt_hash = receipt.compute_receipt_hash();

    // 3. Start challenge period.
    let start_time = receipt.timestamp();
    let mut pending = PendingChallenge::new(
        receipt_hash,
        *receipt.node_id(),
        distribution,
        start_time,
    );
    assert_eq!(pending.status, ChallengeStatus::Pending);
    assert_eq!(pending.challenge_end, start_time + CHALLENGE_PERIOD_SECS);

    // 4. NOT expired during challenge period.
    let mid_challenge = start_time + CHALLENGE_PERIOD_SECS / 2;
    assert!(!pending.is_expired(mid_challenge));
    assert!(pending.can_be_challenged(mid_challenge));

    // 5. Expired after challenge period.
    let after_expiry = pending.challenge_end + 1;
    assert!(pending.is_expired(after_expiry));
    assert!(!pending.can_be_challenged(after_expiry));

    // 6. Mark cleared.
    pending.mark_cleared();
    assert_eq!(pending.status, ChallengeStatus::Cleared);

    // 7. Distribution released — verify 70/20/10.
    assert_eq!(pending.reward_distribution.node_reward, 700_000);
    assert_eq!(pending.reward_distribution.validator_reward, 200_000);
    assert_eq!(pending.reward_distribution.treasury_reward, 100_000);
}

// ════════════════════════════════════════════════════════════════════════════════
// FLOW 3 — ANTI-SELF-DEALING: Detected → 0/20/80 redistribution
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn flow_anti_self_dealing_redistributes_reward() {
    let same_address: Address = [0x08; 20];

    // 1. Direct match detected when node_address == submitter_address.
    let check = AntiSelfDealingCheck::new(same_address, same_address, None);
    let violation = check.run_all_checks(&[]);
    assert!(violation.is_some());

    // 2. Anti-self-dealing distribution: 0/20/80.
    let reward_base: u128 = 1_000_000;
    let distribution = RewardDistribution::with_anti_self_dealing(reward_base);
    assert_eq!(distribution.node_reward, 0);
    assert_eq!(
        distribution.validator_reward,
        reward_base * REWARD_VALIDATOR_PERCENT / 100
    );
    assert_eq!(
        distribution.treasury_reward,
        reward_base - distribution.validator_reward
    );
    assert_eq!(
        distribution.node_reward + distribution.validator_reward + distribution.treasury_reward,
        reward_base,
        "total must equal reward_base even after redistribution"
    );

    // 3. Normal distribution for comparison.
    let normal = RewardDistribution::compute(reward_base);
    assert_eq!(normal.node_reward, 700_000);
    assert!(
        distribution.treasury_reward > normal.treasury_reward,
        "treasury gets more under anti-self-dealing"
    );
}

// ════════════════════════════════════════════════════════════════════════════════
// FLOW 4 — DEDUP: mark_claimed → second attempt rejected
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn flow_dedup_rejects_double_claim() {
    let receipt = make_storage_receipt();
    let receipt_hash = receipt.compute_receipt_hash();

    let mut tracker = ReceiptDedupTracker::new();
    assert!(!tracker.is_claimed(&receipt_hash));
    assert_eq!(tracker.claimed_count(), 0);

    // 1. First claim succeeds.
    tracker
        .mark_claimed(receipt_hash)
        .expect("first claim must succeed");
    assert!(tracker.is_claimed(&receipt_hash));
    assert_eq!(tracker.claimed_count(), 1);

    // 2. Second claim fails.
    let err = tracker.mark_claimed(receipt_hash);
    assert!(err.is_err());
    match err {
        Err(ClaimValidationError::ReceiptAlreadyClaimed { receipt_hash: h }) => {
            assert_eq!(h, receipt_hash);
        }
        _ => panic!("expected ReceiptAlreadyClaimed error"),
    }

    // Count unchanged.
    assert_eq!(tracker.claimed_count(), 1);
}

// ════════════════════════════════════════════════════════════════════════════════
// FLOW 5 — HASH CONSISTENCY: native ↔ proto hash must match
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn flow_hash_consistency_end_to_end_storage() {
    let proto = make_storage_receipt_proto();
    let native = ReceiptV1::from_proto(&proto).expect("from_proto");

    // Proto hash.
    let proto_hash = compute_receipt_hash_from_proto(&proto).expect("proto hash");

    // Native proto-compatible hash.
    let native_compat_hash =
        compute_receipt_hash_proto_compatible(&native, &proto.coordinator_threshold_signature);

    // Must be identical.
    assert_eq!(
        proto_hash, native_compat_hash,
        "proto and native proto-compatible hashes must match for storage receipt"
    );

    // Non-zero.
    assert_ne!(proto_hash, [0u8; 32]);

    // Deterministic over multiple calls.
    for _ in 0..100 {
        let h = compute_receipt_hash_from_proto(&proto).expect("hash");
        assert_eq!(h, proto_hash);
    }
}

#[test]
fn flow_hash_consistency_end_to_end_compute() {
    let proto = make_compute_receipt_proto();
    let native = ReceiptV1::from_proto(&proto).expect("from_proto");

    let proto_hash = compute_receipt_hash_from_proto(&proto).expect("proto hash");
    let native_compat_hash =
        compute_receipt_hash_proto_compatible(&native, &proto.coordinator_threshold_signature);

    assert_eq!(
        proto_hash, native_compat_hash,
        "proto and native proto-compatible hashes must match for compute receipt"
    );

    // Compute and storage hashes must differ.
    let storage_proto = make_storage_receipt_proto();
    let storage_hash = compute_receipt_hash_from_proto(&storage_proto).expect("storage hash");
    assert_ne!(
        proto_hash, storage_hash,
        "compute and storage receipt hashes must differ"
    );
}

// ════════════════════════════════════════════════════════════════════════════════
// FLOW 6 — FULL CHALLENGE LIFECYCLE: Pending → Challenged → Slashed
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn flow_challenge_lifecycle_pending_to_slashed() {
    let receipt = make_compute_receipt();
    let distribution = RewardDistribution::compute(receipt.reward_base());
    let receipt_hash = receipt.compute_receipt_hash();
    let start_time: u64 = 1_700_000_000;

    // 1. Create pending challenge.
    let mut pending = PendingChallenge::new(
        receipt_hash,
        *receipt.node_id(),
        distribution,
        start_time,
    );
    assert_eq!(pending.status, ChallengeStatus::Pending);
    assert!(pending.challenger.is_none());

    // 2. Challenger submits fraud proof during challenge window.
    let during_challenge = start_time + 100;
    assert!(pending.can_be_challenged(during_challenge));
    let challenger_addr: Address = [0xBB; 20];
    pending.mark_challenged(challenger_addr);
    assert_eq!(pending.status, ChallengeStatus::Challenged);
    assert_eq!(pending.challenger, Some(challenger_addr));

    // 3. Cannot mark cleared from Challenged state.
    pending.mark_cleared();
    assert_eq!(
        pending.status,
        ChallengeStatus::Challenged,
        "cleared must not change Challenged state"
    );

    // 4. Fraud proven → slashed.
    pending.mark_slashed();
    assert_eq!(pending.status, ChallengeStatus::Slashed);

    // 5. Slashed is terminal — cannot transition further.
    pending.mark_cleared();
    assert_eq!(pending.status, ChallengeStatus::Slashed);
    pending.mark_challenged([0xDD; 20]);
    assert_eq!(pending.status, ChallengeStatus::Slashed);
    pending.mark_slashed();
    assert_eq!(pending.status, ChallengeStatus::Slashed);
}

// ════════════════════════════════════════════════════════════════════════════════
// FLOW 7 — ECONOMIC CONSTANT BOUNDARIES
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn flow_economic_constants_boundaries() {
    // Challenge end time.
    let start: u64 = 1_700_000_000;
    let end = challenge_end_time(start);
    assert_eq!(end, start + CHALLENGE_PERIOD_SECS);

    // Exact boundary: NOT expired at end-1, expired at end.
    assert!(!is_challenge_expired(start, end - 1));
    assert!(is_challenge_expired(start, end));
    assert!(is_challenge_expired(start, end + 1));

    // Receipt expiry boundary.
    let receipt_ts: u64 = 1_700_000_000;
    let at_max = receipt_ts + MAX_RECEIPT_AGE_SECS;
    assert!(!is_receipt_expired(receipt_ts, at_max - 1));
    assert!(is_receipt_expired(receipt_ts, at_max));

    // Overflow guard: u64::MAX start should not panic.
    let overflow_end = challenge_end_time(u64::MAX);
    assert_eq!(overflow_end, u64::MAX, "overflow returns start unchanged");

    // Reward percentage sanity.
    assert_eq!(
        REWARD_NODE_PERCENT + REWARD_VALIDATOR_PERCENT + REWARD_TREASURY_PERCENT,
        100
    );
}

// ════════════════════════════════════════════════════════════════════════════════
// FLOW 8 — PROTO ROUNDTRIP PRESERVES CLAIM REWARD INTEGRITY
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn flow_claim_reward_proto_roundtrip_integrity() {
    let receipt_proto = make_storage_receipt_proto();

    let claim_proto = ClaimRewardProto {
        receipt: receipt_proto.clone(),
        submitter_address: vec![0x09; 20],
        submitter_signature: vec![0xFF; 64],
        nonce: 42,
        timestamp: 1_700_000_001,
    };

    // Proto → native.
    let native = ClaimReward::from_proto(&claim_proto).expect("from_proto");
    assert_eq!(native.submitter_address, [0x09; 20]);
    assert_eq!(native.nonce, 42);
    assert_eq!(native.receipt.receipt_type(), ReceiptType::Storage);

    // Native → proto.
    let back = native.to_proto();
    assert_eq!(back.submitter_address, claim_proto.submitter_address);
    assert_eq!(back.submitter_signature, claim_proto.submitter_signature);
    assert_eq!(back.nonce, claim_proto.nonce);
    assert_eq!(back.timestamp, claim_proto.timestamp);

    // Receipt core fields preserved.
    assert_eq!(back.receipt.workload_id, receipt_proto.workload_id);
    assert_eq!(back.receipt.node_id, receipt_proto.node_id);
    assert_eq!(back.receipt.reward_base, receipt_proto.reward_base);
    assert_eq!(back.receipt.epoch, receipt_proto.epoch);
}