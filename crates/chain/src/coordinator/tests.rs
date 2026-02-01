//! Integration tests for coordinator system (14A.2B.2.30)
//!
//! Tests komprehensif yang menguji interaksi antar sub-module coordinator:
//! EpochManager, EpochDKG, DisputeResolver, CoordinatorAccountability.
//!
//! ## Design Principles
//!
//! - Semua test menggunakan PUBLIC API saja
//! - Deterministic — tidak bergantung waktu nyata atau randomness
//! - Isolated — tidak ada shared mutable global state
//! - Eksplisit — semua assertion dan error handling jelas

use std::collections::HashMap;

use dsdn_common::coordinator::{
    CoordinatorCommittee, CoordinatorId, CoordinatorMember, DAMerkleProof, ReceiptData,
    ThresholdReceipt, WorkloadId,
};
use dsdn_proto::{DKGRound1PackageProto, DKGRound2PackageProto};
use dsdn_tss::{AggregateSignature, FrostSignature, SignerId};
use sha3::{Digest, Sha3_256};

use super::*;
use crate::state::ChainState;
use crate::types::Address;

// ════════════════════════════════════════════════════════════════════════════════
// TEST HELPERS
// ════════════════════════════════════════════════════════════════════════════════

/// Construct CoordinatorCommittee via serde JSON deserialization.
///
/// Same pattern as epoch.rs unit tests. Bypasses constructor
/// validation because chain crate has no access to dsdn-tss
/// construction types directly.
fn test_committee() -> CoordinatorCommittee {
    let json = serde_json::json!({
        "members": [
            { "id": vec![1u8; 32], "validator_id": vec![2u8; 32], "pubkey": vec![3u8; 32], "stake": 1000u64, "joined_at": 0u64 },
            { "id": vec![4u8; 32], "validator_id": vec![5u8; 32], "pubkey": vec![6u8; 32], "stake": 1000u64, "joined_at": 0u64 },
            { "id": vec![7u8; 32], "validator_id": vec![8u8; 32], "pubkey": vec![9u8; 32], "stake": 1000u64, "joined_at": 0u64 }
        ],
        "threshold": 2u8,
        "epoch": 0u64,
        "epoch_start": 0u64,
        "epoch_duration_secs": 3600u64,
        "group_pubkey": vec![1u8; 32]
    });
    serde_json::from_value(json).expect("test committee construction")
}

/// Construct a second committee (different from test_committee) for rotation.
fn test_committee_2() -> CoordinatorCommittee {
    let json = serde_json::json!({
        "members": [
            { "id": vec![0x10u8; 32], "validator_id": vec![0x11u8; 32], "pubkey": vec![0x12u8; 32], "stake": 2000u64, "joined_at": 0u64 },
            { "id": vec![0x13u8; 32], "validator_id": vec![0x14u8; 32], "pubkey": vec![0x15u8; 32], "stake": 2000u64, "joined_at": 0u64 },
            { "id": vec![0x16u8; 32], "validator_id": vec![0x17u8; 32], "pubkey": vec![0x18u8; 32], "stake": 2000u64, "joined_at": 0u64 }
        ],
        "threshold": 2u8,
        "epoch": 1u64,
        "epoch_start": 100u64,
        "epoch_duration_secs": 3600u64,
        "group_pubkey": vec![0x20u8; 32]
    });
    serde_json::from_value(json).expect("test committee 2 construction")
}

/// Valid EpochConfig for tests.
///
/// epoch_duration=100, handoff_duration=10, dkg_timeout=5.
fn valid_config() -> EpochConfig {
    EpochConfig {
        epoch_duration_blocks: 100,
        handoff_duration_blocks: 10,
        dkg_timeout_blocks: 5,
    }
}

/// Non-zero DA seed for rotation trigger.
fn test_da_seed() -> [u8; 32] {
    [0xABu8; 32]
}

/// Construct CoordinatorMember via serde JSON deserialization.
fn test_member(id_byte: u8) -> CoordinatorMember {
    let id: Vec<u8> = vec![id_byte; 32];
    let vid: Vec<u8> = vec![id_byte.wrapping_add(1); 32];
    let pk: Vec<u8> = vec![id_byte.wrapping_add(2); 32];

    let json = serde_json::json!({
        "id": id,
        "validator_id": vid,
        "pubkey": pk,
        "stake": 1000u64,
        "joined_at": 0u64
    });
    serde_json::from_value(json).expect("test member construction")
}

/// Construct 3 test members (id bytes: 1, 4, 7).
fn test_members_3() -> Vec<CoordinatorMember> {
    vec![test_member(1), test_member(4), test_member(7)]
}

/// Compute session_id deterministically using the documented algorithm.
///
/// Formula: SHA3-256(target_epoch_le ‖ member_count_le ‖ sorted_member_ids)
///
/// This replicates the public specification from dkg.rs without
/// accessing private fields.
fn compute_test_session_id(target_epoch: u64, members: &[CoordinatorMember]) -> [u8; 32] {
    let mut sorted = members.to_vec();
    sorted.sort();
    let mut hasher = Sha3_256::new();
    hasher.update(target_epoch.to_le_bytes());
    hasher.update((sorted.len() as u64).to_le_bytes());
    for m in &sorted {
        hasher.update(m.id().as_bytes());
    }
    let result = hasher.finalize();
    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&result);
    session_id
}

/// Construct a valid DKG round 1 package.
fn make_round1_package(session_id: &[u8; 32], id_byte: u8) -> DKGRound1PackageProto {
    DKGRound1PackageProto {
        session_id: session_id.to_vec(),
        participant_id: vec![id_byte; 32],
        commitment: vec![id_byte.wrapping_add(10); 32],
        proof: vec![id_byte.wrapping_add(20); 64],
    }
}

/// Construct a valid DKG round 2 package.
fn make_round2_package(
    session_id: &[u8; 32],
    from_byte: u8,
    to_byte: u8,
) -> DKGRound2PackageProto {
    DKGRound2PackageProto {
        session_id: session_id.to_vec(),
        from_participant: vec![from_byte; 32],
        to_participant: vec![to_byte; 32],
        encrypted_share: vec![0xAA; 16],
    }
}

/// Fill all round 1 packages for 3-member DKG.
fn fill_round1(dkg: &mut EpochDKG, session_id: &[u8; 32]) {
    let r1 = dkg.add_round1_package(make_round1_package(session_id, 1));
    assert!(r1.is_ok(), "round1 member 1 failed: {:?}", r1.err());
    let r2 = dkg.add_round1_package(make_round1_package(session_id, 4));
    assert!(r2.is_ok(), "round1 member 4 failed: {:?}", r2.err());
    let r3 = dkg.add_round1_package(make_round1_package(session_id, 7));
    assert!(r3.is_ok(), "round1 member 7 failed: {:?}", r3.err());
}

/// Fill all round 2 packages for 3-member DKG (3*2=6 packages).
fn fill_round2(dkg: &mut EpochDKG, session_id: &[u8; 32]) {
    let pairs = [(1, 4), (1, 7), (4, 1), (4, 7), (7, 1), (7, 4)];
    for (from, to) in pairs {
        let r = dkg.add_round2_package(make_round2_package(session_id, from, to));
        assert!(r.is_ok(), "round2 ({},{}) failed: {:?}", from, to, r.err());
    }
}

/// Construct a test AggregateSignature.
fn test_aggregate_signature() -> AggregateSignature {
    let sig = FrostSignature::from_bytes([0x42; 64]).expect("test signature construction");
    let signers = vec![
        SignerId::from_bytes([0x01; 32]),
        SignerId::from_bytes([0x02; 32]),
    ];
    let message_hash = [0xAA; 32];
    AggregateSignature::new(sig, signers, message_hash)
}

/// Construct a test ReceiptData.
fn test_receipt_data(workload_byte: u8, epoch: u64) -> ReceiptData {
    ReceiptData::new(
        WorkloadId::new([workload_byte; 32]),
        [0x02; 32],          // blob_hash
        vec![[0x03; 32]],    // placement
        1_700_000_000,       // timestamp
        1,                   // sequence
        epoch,
    )
}

/// Construct a test ThresholdReceipt.
fn test_threshold_receipt(
    workload_byte: u8,
    epoch: u64,
    signers: Vec<CoordinatorId>,
    committee_hash: [u8; 32],
) -> ThresholdReceipt {
    let receipt_data = test_receipt_data(workload_byte, epoch);
    ThresholdReceipt::new(receipt_data, test_aggregate_signature(), signers, committee_hash)
}

/// Construct a test DAMerkleProof.
fn test_da_proof() -> DAMerkleProof {
    DAMerkleProof {
        root: [0xFFu8; 32],
        path: vec![],
        index: 0,
    }
}

/// Construct a DisputeConfig for tests.
fn test_dispute_config() -> DisputeConfig {
    DisputeConfig {
        slash_amount_inconsistent: 5000,
        slash_amount_invalid_sig: 3000,
        slash_amount_missing: 1000,
        slash_amount_unauthorized: 4000,
        min_timeout_witnesses: 2,
    }
}

/// Construct a test CoordinatorId.
fn test_coordinator_id(byte: u8) -> CoordinatorId {
    CoordinatorId::new([byte; 32])
}

/// Construct a test WorkloadId.
fn test_workload_id(byte: u8) -> WorkloadId {
    WorkloadId::new([byte; 32])
}

/// Construct a test AccountableDecision.
fn test_accountable_decision(
    workload_byte: u8,
    block_height: u64,
    merkle_root: [u8; 32],
) -> AccountableDecision {
    let receipt_data = test_receipt_data(workload_byte, 0);
    let merkle_proof = DAMerkleProof {
        root: merkle_root,
        path: vec![],
        index: 0,
    };
    AccountableDecision::new(
        test_workload_id(workload_byte),
        receipt_data,
        merkle_proof,
        1_700_000_000,
        block_height,
    )
}

/// Construct test Address (20 bytes).
fn test_address(byte: u8) -> Address {
    Address::from_str(&format!(
        "0x{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}\
         {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        byte, byte, byte, byte, byte, byte, byte, byte, byte, byte,
        byte, byte, byte, byte, byte, byte, byte, byte, byte, byte,
    ))
    .expect("test address construction")
}

use std::str::FromStr;

// ════════════════════════════════════════════════════════════════════════════════
// 1. test_epoch_rotation_trigger
// ════════════════════════════════════════════════════════════════════════════════

/// Verifikasi bahwa EpochManager mendeteksi dan men-trigger rotation
/// pada epoch boundary yang tepat.
#[test]
fn test_epoch_rotation_trigger() {
    let committee = test_committee();
    let mut em = EpochManager::new(valid_config(), committee);

    // Status awal harus Active
    assert_eq!(em.current_status(), CommitteeStatus::Active);
    assert_eq!(em.current_epoch(), 0);

    // Sebelum boundary: should_rotate = false
    assert!(!em.should_rotate(0));
    assert!(!em.should_rotate(50));
    assert!(!em.should_rotate(99));

    // Pada boundary (epoch_start=0 + duration=100 = 100): should_rotate = true
    assert!(em.should_rotate(100));

    // Trigger rotation
    let result = em.trigger_rotation(100, test_da_seed());
    assert!(result.is_ok());

    // Status berubah ke PendingRotation
    assert_eq!(em.current_status(), CommitteeStatus::PendingRotation);

    // Epoch belum bertambah (baru pending)
    assert_eq!(em.current_epoch(), 0);

    // should_rotate returns false karena status bukan Active lagi
    assert!(!em.should_rotate(100));
}

// ════════════════════════════════════════════════════════════════════════════════
// 2. test_epoch_rotation_at_boundary
// ════════════════════════════════════════════════════════════════════════════════

/// Verifikasi boundary conditions untuk epoch rotation.
#[test]
fn test_epoch_rotation_at_boundary() {
    let committee = test_committee();
    let em = EpochManager::new(valid_config(), committee);

    // epoch_start=0, duration=100 → boundary=100

    // One block before boundary → false
    assert!(!em.should_rotate(99));

    // Exact boundary → true
    assert!(em.should_rotate(100));

    // Past boundary → true
    assert!(em.should_rotate(101));
    assert!(em.should_rotate(200));

    // Trigger at boundary-1 should fail
    let mut em2 = EpochManager::new(valid_config(), test_committee());
    let err = em2.trigger_rotation(99, test_da_seed());
    assert!(err.is_err());

    // Trigger with zero DA seed should fail (SelectionFailed)
    let mut em3 = EpochManager::new(valid_config(), test_committee());
    let err = em3.trigger_rotation(100, [0u8; 32]);
    assert!(err.is_err());

    // Trigger at exact boundary with valid seed succeeds
    let mut em4 = EpochManager::new(valid_config(), test_committee());
    let result = em4.trigger_rotation(100, test_da_seed());
    assert!(result.is_ok());

    // Verify transition data
    let transition = result.ok();
    assert!(transition.is_some());
    let t = transition.as_ref();
    assert!(t.is_some());
    let tr = t.as_ref().map(|t| t.transition_height);
    assert_eq!(tr, Some(100));
}

// ════════════════════════════════════════════════════════════════════════════════
// 3. test_handoff_period_both_committees_valid
// ════════════════════════════════════════════════════════════════════════════════

/// Verifikasi bahwa selama handoff period, kedua committee
/// (current dan next) diakui valid.
#[test]
fn test_handoff_period_both_committees_valid() {
    let committee = test_committee();
    let mut em = EpochManager::new(valid_config(), committee.clone());

    // handoff_window: epoch_end=100, handoff_start = 100 - 10 = 90

    // Before handoff window: only current committee valid
    let committees_before = em.valid_committees_for_height(50);
    assert_eq!(committees_before.len(), 1);

    // In handoff window (height=95): still only current if no next
    let committees_in_handoff_no_next = em.valid_committees_for_height(95);
    assert_eq!(committees_in_handoff_no_next.len(), 1);

    // Trigger rotation dan prepare next committee
    let rotation_result = em.trigger_rotation(100, test_da_seed());
    assert!(rotation_result.is_ok());

    let new_committee = test_committee_2();
    let prepare_result = em.prepare_next_epoch(new_committee);
    assert!(prepare_result.is_ok());

    // During handoff period: both committees valid
    let committees_during = em.valid_committees_for_height(95);
    assert_eq!(committees_during.len(), 2);

    // Before handoff start: only current
    let committees_early = em.valid_committees_for_height(50);
    assert_eq!(committees_early.len(), 1);
}

// ════════════════════════════════════════════════════════════════════════════════
// 4. test_handoff_completion
// ════════════════════════════════════════════════════════════════════════════════

/// Verifikasi complete handoff: epoch increments, committee switches,
/// status returns to Active.
#[test]
fn test_handoff_completion() {
    let original_committee = test_committee();
    let mut em = EpochManager::new(valid_config(), original_committee.clone());

    // Phase 1: trigger rotation
    let rotation = em.trigger_rotation(100, test_da_seed());
    assert!(rotation.is_ok());
    assert_eq!(em.current_status(), CommitteeStatus::PendingRotation);

    // Phase 2: prepare next epoch
    let new_committee = test_committee_2();
    let prepare = em.prepare_next_epoch(new_committee.clone());
    assert!(prepare.is_ok());

    // Phase 3: complete handoff
    let handoff = em.complete_handoff(100);
    assert!(handoff.is_ok());

    // Verify state setelah handoff
    assert_eq!(em.current_epoch(), 1);
    assert_eq!(em.current_status(), CommitteeStatus::Active);

    // Current committee sekarang = new committee
    assert_eq!(*em.current_committee(), new_committee);

    // Epoch progress dari height baru: elapsed=0 dari epoch_start=100
    let (elapsed, remaining) = em.epoch_progress(100);
    assert_eq!(elapsed, 0);
    assert_eq!(remaining, 100);
}

// ════════════════════════════════════════════════════════════════════════════════
// 5. test_dkg_round1_collection
// ════════════════════════════════════════════════════════════════════════════════

/// Verifikasi proses pengumpulan paket DKG round 1.
#[test]
fn test_dkg_round1_collection() {
    let members = test_members_3();
    let session_id = compute_test_session_id(1, &members);
    let mut dkg = EpochDKG::new(1, members, 100);

    // Initial state: Pending
    assert_eq!(*dkg.state(), EpochDKGState::Pending);
    assert!(!dkg.check_round1_complete());

    // Add first round1 package: state → Round1InProgress
    let r1 = dkg.add_round1_package(make_round1_package(&session_id, 1));
    assert!(r1.is_ok());
    let progress = r1.ok();
    assert!(progress.is_some());
    if let Some(p) = progress {
        assert!(!p.round1_complete);
        assert!(!p.round2_complete);
        assert!(matches!(p.state, EpochDKGState::Round1InProgress { received: 1, required: 3 }));
    }

    // Add second package
    let r2 = dkg.add_round1_package(make_round1_package(&session_id, 4));
    assert!(r2.is_ok());
    assert!(!dkg.check_round1_complete());

    // Add third package: round1 complete
    let r3 = dkg.add_round1_package(make_round1_package(&session_id, 7));
    assert!(r3.is_ok());
    assert!(dkg.check_round1_complete());

    // Verify state is Round1InProgress with all received
    assert!(
        matches!(dkg.state(), EpochDKGState::Round1InProgress { received: 3, required: 3 }),
        "expected Round1InProgress {{ received: 3, required: 3 }}, got {:?}",
        dkg.state()
    );

    // Duplicate package should fail
    let dup = dkg.add_round1_package(make_round1_package(&session_id, 1));
    assert!(dup.is_err());
    assert_eq!(dup.err(), Some(DKGError::DuplicatePackage));
}

// ════════════════════════════════════════════════════════════════════════════════
// 6. test_dkg_round2_collection
// ════════════════════════════════════════════════════════════════════════════════

/// Verifikasi proses pengumpulan paket DKG round 2.
#[test]
fn test_dkg_round2_collection() {
    let members = test_members_3();
    let session_id = compute_test_session_id(1, &members);
    let mut dkg = EpochDKG::new(1, members, 100);

    // Fill round 1 first
    fill_round1(&mut dkg, &session_id);
    assert!(dkg.check_round1_complete());

    // Round 2 belum complete
    assert!(!dkg.check_round2_complete());

    // Add round2 packages: 3 members → 3*(3-1) = 6 pairs
    let r1 = dkg.add_round2_package(make_round2_package(&session_id, 1, 4));
    assert!(r1.is_ok());
    if let Some(p) = r1.ok() {
        assert!(p.round1_complete);
        assert!(!p.round2_complete);
    }

    // Add remaining 5 packages
    let pairs = [(1, 7), (4, 1), (4, 7), (7, 1), (7, 4)];
    for (from, to) in pairs {
        let r = dkg.add_round2_package(make_round2_package(&session_id, from, to));
        assert!(r.is_ok(), "round2 ({},{}) failed", from, to);
    }

    // Round 2 now complete
    assert!(dkg.check_round2_complete());

    // State should be Round2InProgress with all received
    assert!(
        matches!(dkg.state(), EpochDKGState::Round2InProgress { received: 6, required: 6 }),
        "expected Round2InProgress {{ received: 6, required: 6 }}, got {:?}",
        dkg.state()
    );

    // Self-send should fail
    let self_send = dkg.add_round2_package(make_round2_package(&session_id, 1, 1));
    assert!(self_send.is_err());
}

// ════════════════════════════════════════════════════════════════════════════════
// 7. test_dkg_finalization
// ════════════════════════════════════════════════════════════════════════════════

/// Verifikasi finalisasi DKG menghasilkan result yang valid.
#[test]
fn test_dkg_finalization() {
    let members = test_members_3();
    let session_id = compute_test_session_id(1, &members);
    let mut dkg = EpochDKG::new(1, members, 100);

    // Fill both rounds
    fill_round1(&mut dkg, &session_id);
    fill_round2(&mut dkg, &session_id);

    // Not yet complete (finalize not called)
    assert!(!dkg.is_complete());
    assert!(dkg.get_result().is_none());

    // Finalize
    let result = dkg.finalize();
    assert!(result.is_ok());

    let dkg_result = result.ok();
    assert!(dkg_result.is_some());
    if let Some(ref r) = dkg_result {
        assert!(r.success);
        assert_eq!(r.threshold, 2); // majority of 3
    }

    // Now is_complete should be true
    assert!(dkg.is_complete());

    // get_result should return Some
    let stored = dkg.get_result();
    assert!(stored.is_some());
    if let (Some(returned), Some(stored_ref)) = (dkg_result.as_ref(), stored) {
        assert_eq!(returned, stored_ref);
    }

    // State should be Completed
    assert!(matches!(dkg.state(), EpochDKGState::Completed { .. }));

    // Double finalize should fail
    let double = dkg.finalize();
    assert!(double.is_err());

    // Adding packages after completion should fail
    let late_pkg = dkg.add_round1_package(make_round1_package(&session_id, 1));
    assert!(late_pkg.is_err());
}

// ════════════════════════════════════════════════════════════════════════════════
// 8. test_dkg_timeout
// ════════════════════════════════════════════════════════════════════════════════

/// Verifikasi DKG timeout behavior: state transitions ke Failed
/// dan menolak operasi selanjutnya.
#[test]
fn test_dkg_timeout() {
    let members = test_members_3();
    let session_id = compute_test_session_id(1, &members);
    let mut dkg = EpochDKG::new(1, members, 100);

    // Add partial round1 (not complete)
    let r = dkg.add_round1_package(make_round1_package(&session_id, 1));
    assert!(r.is_ok());
    assert!(!dkg.check_round1_complete());

    // Before timeout: check_timeout returns false
    assert!(!dkg.check_timeout(50));
    assert!(!dkg.is_complete());

    // At timeout: check_timeout returns true
    assert!(dkg.check_timeout(100));

    // State should be Failed { Timeout }
    assert!(dkg.is_complete());
    assert_eq!(
        *dkg.state(),
        EpochDKGState::Failed {
            error: DKGError::Timeout
        }
    );

    // get_result should return None (not Completed, just Failed)
    assert!(dkg.get_result().is_none());

    // Further packages should be rejected (WrongRound)
    let late = dkg.add_round1_package(make_round1_package(&session_id, 4));
    assert!(late.is_err());

    // check_timeout on already-timed-out DKG returns false (already terminal)
    assert!(!dkg.check_timeout(200));

    // Finalize should fail (terminal state)
    let fin = dkg.finalize();
    assert!(fin.is_err());
}

// ════════════════════════════════════════════════════════════════════════════════
// 9. test_dispute_inconsistent_scheduling
// ════════════════════════════════════════════════════════════════════════════════

/// Verifikasi validasi dan resolusi InconsistentScheduling dispute.
#[test]
fn test_dispute_inconsistent_scheduling() {
    let resolver = DisputeResolver::new(test_dispute_config());

    let signer_a = test_coordinator_id(0x01);
    let signer_b = test_coordinator_id(0x02);
    let committee_hash = [0xCC; 32];

    // Two receipts for same workload but different data
    let receipt_a = test_threshold_receipt(0x01, 0, vec![signer_a, signer_b], committee_hash);

    // Second receipt with different blob_hash (via different ReceiptData)
    let receipt_data_b = ReceiptData::new(
        WorkloadId::new([0x01; 32]),
        [0xFF; 32], // Different blob hash → different receipt_data_hash
        vec![[0x03; 32]],
        1_700_000_000,
        1,
        0,
    );
    let receipt_b = ThresholdReceipt::new(
        receipt_data_b,
        test_aggregate_signature(),
        vec![signer_a, signer_b],
        committee_hash,
    );

    let dispute = CoordinatorDispute::InconsistentScheduling {
        receipt_a,
        receipt_b,
        da_proof: test_da_proof(),
    };

    // Structural validation
    let valid = resolver.validate_dispute(&dispute);
    assert!(valid);

    // Resolution: should be Valid with offenders
    let result = resolver.resolve(&dispute, None);
    assert!(
        matches!(&result, DisputeResult::Valid { .. }),
        "expected DisputeResult::Valid, got {:?}",
        result
    );
    if let DisputeResult::Valid {
        ref offenders,
        slash_amount,
    } = result
    {
        // Both signers should be offenders (union of both receipts' signers)
        assert!(offenders.contains(&signer_a));
        assert!(offenders.contains(&signer_b));
        assert_eq!(slash_amount, 5000); // slash_amount_inconsistent
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// 10. test_dispute_invalid_signature
// ════════════════════════════════════════════════════════════════════════════════

/// Verifikasi validasi dan resolusi InvalidSignature dispute.
///
/// Menggunakan committee dan receipt yang TIDAK cocok sehingga
/// verify() mengembalikan false — membuat dispute valid.
#[test]
fn test_dispute_invalid_signature() {
    let resolver = DisputeResolver::new(test_dispute_config());

    let signer = test_coordinator_id(0x01);
    let committee = test_committee();
    let wrong_committee_hash = [0xFF; 32]; // Doesn't match actual committee hash

    // Receipt dengan committee_hash yang salah → verify() will fail
    let receipt = test_threshold_receipt(0x01, 0, vec![signer], wrong_committee_hash);

    let dispute = CoordinatorDispute::InvalidSignature {
        receipt,
        expected_committee: committee,
    };

    // Structural validation (receipt has signers, committee has members)
    let valid = resolver.validate_dispute(&dispute);
    assert!(valid);

    // Resolution: verify() returns false → dispute Valid
    let result = resolver.resolve(&dispute, None);
    assert!(
        matches!(&result, DisputeResult::Valid { .. }),
        "expected DisputeResult::Valid, got {:?}",
        result
    );
    if let DisputeResult::Valid {
        ref offenders,
        slash_amount,
    } = result
    {
        assert_eq!(offenders.len(), 1);
        assert_eq!(offenders[0], signer);
        assert_eq!(slash_amount, 3000); // slash_amount_invalid_sig
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// 11. test_dispute_resolution_slashing
// ════════════════════════════════════════════════════════════════════════════════

/// Verifikasi bahwa slashing mengurangi stake dan menambah treasury.
#[test]
fn test_dispute_resolution_slashing() {
    let resolver = DisputeResolver::new(test_dispute_config());

    let offender_id = test_coordinator_id(0xAA);
    let offender_addr = test_address(0xAA);

    // Setup ChainState dengan stake
    let mut state = ChainState::default();
    state.locked.insert(offender_addr, 10_000);
    state.validator_stakes.insert(offender_addr, 10_000);
    state.treasury_balance = 0;

    // DisputeResult::Valid
    let dispute_result = DisputeResult::Valid {
        offenders: vec![offender_id],
        slash_amount: 3000,
    };

    // id_to_address mapping
    let mut id_to_address: HashMap<CoordinatorId, Address> = HashMap::new();
    id_to_address.insert(offender_id, offender_addr);

    // Apply slashing
    let slash_result = resolver.apply_slashing(&dispute_result, &mut state, &id_to_address);
    assert!(slash_result.is_ok());

    let summary = slash_result.ok();
    assert!(summary.is_some());
    if let Some(ref s) = summary {
        assert_eq!(s.total_slashed, 3000);
        assert_eq!(s.to_treasury, 3000);
        assert_eq!(s.slashed.len(), 1);
        assert_eq!(s.slashed[0].address, offender_addr);
        assert_eq!(s.slashed[0].amount_deducted, 3000);
    }

    // Verify state mutations
    assert_eq!(*state.locked.get(&offender_addr).unwrap_or(&0), 7000);
    assert_eq!(*state.validator_stakes.get(&offender_addr).unwrap_or(&0), 7000);
    assert_eq!(state.treasury_balance, 3000);

    // Slashing with Invalid result should fail
    let invalid_result = DisputeResult::Invalid {
        reason: "no violation".into(),
    };
    let nothing = resolver.apply_slashing(&invalid_result, &mut state, &id_to_address);
    assert!(nothing.is_err());
}

// ════════════════════════════════════════════════════════════════════════════════
// 12. test_accountability_logging
// ════════════════════════════════════════════════════════════════════════════════

/// Verifikasi accountability logging: append-only, range queries, ordering.
#[test]
fn test_accountability_logging() {
    let coord_id = test_coordinator_id(0x01);
    let mut accountability = CoordinatorAccountability::new(coord_id, 0);

    // Log decisions at different heights
    let d1 = test_accountable_decision(0x01, 10, [0xAA; 32]);
    let d2 = test_accountable_decision(0x02, 20, [0xBB; 32]);
    let d3 = test_accountable_decision(0x03, 30, [0xCC; 32]);
    let d4 = test_accountable_decision(0x04, 15, [0xDD; 32]);

    accountability.log_decision(d1);
    accountability.log_decision(d2);
    accountability.log_decision(d3);
    accountability.log_decision(d4);

    // Range query: 10-20 inclusive should return d1, d2, d4 (insertion order)
    let range_10_20 = accountability.get_decisions_in_range(10, 20);
    assert_eq!(range_10_20.len(), 3);
    assert_eq!(range_10_20[0].block_height(), 10);
    assert_eq!(range_10_20[1].block_height(), 20);
    assert_eq!(range_10_20[2].block_height(), 15);

    // Range query: 25-50 should return only d3
    let range_25_50 = accountability.get_decisions_in_range(25, 50);
    assert_eq!(range_25_50.len(), 1);
    assert_eq!(range_25_50[0].block_height(), 30);

    // Range query with no results
    let range_empty = accountability.get_decisions_in_range(100, 200);
    assert!(range_empty.is_empty());

    // Duplicate workload_id allowed (audit log, not state)
    let d_dup = test_accountable_decision(0x01, 40, [0xEE; 32]);
    accountability.log_decision(d_dup);
    let range_all = accountability.get_decisions_in_range(0, 100);
    assert_eq!(range_all.len(), 5);
}

// ════════════════════════════════════════════════════════════════════════════════
// 13. test_accountability_proof_generation
// ════════════════════════════════════════════════════════════════════════════════

/// Verifikasi accountability proof generation: deterministic,
/// picks earliest match, proof_hash is correct.
#[test]
fn test_accountability_proof_generation() {
    let coord_id = test_coordinator_id(0x01);
    let mut accountability = CoordinatorAccountability::new(coord_id, 0);

    // Log two decisions for the SAME workload_id
    let d1 = test_accountable_decision(0x42, 10, [0xAA; 32]);
    let d2 = test_accountable_decision(0x42, 20, [0xBB; 32]);
    accountability.log_decision(d1);
    accountability.log_decision(d2);

    // Generate proof: should pick FIRST (earliest inserted)
    let proof = accountability.generate_proof(test_workload_id(0x42));
    assert!(proof.is_some());

    let p = proof.as_ref();
    assert!(p.is_some());
    if let Some(ref proof) = p {
        assert_eq!(*proof.coordinator_id(), coord_id);
        assert_eq!(proof.epoch(), 0);
        assert_eq!(proof.decision().block_height(), 10); // First inserted

        // Verify proof_hash is deterministic by generating again
        let proof2 = accountability.generate_proof(test_workload_id(0x42));
        assert!(proof2.is_some());
        if let Some(ref p2) = proof2 {
            assert_eq!(proof.proof_hash(), p2.proof_hash());
        }
    }

    // Non-existent workload_id returns None
    let no_proof = accountability.generate_proof(test_workload_id(0xFF));
    assert!(no_proof.is_none());
}

// ════════════════════════════════════════════════════════════════════════════════
// 14. test_full_epoch_rotation_cycle (END-TO-END)
// ════════════════════════════════════════════════════════════════════════════════

/// Full integration test: simulates complete epoch lifecycle.
///
/// Flow: Epoch 0 Active → should_rotate → trigger_rotation →
///       DKG (round1 + round2 + finalize) → prepare_next_epoch →
///       handoff → complete_handoff → Epoch 1 Active
///
/// No mock shortcuts. No hidden assumptions.
#[test]
fn test_full_epoch_rotation_cycle() {
    // ── Phase 0: Setup ──────────────────────────────────────────
    let genesis_committee = test_committee();
    let mut em = EpochManager::new(valid_config(), genesis_committee.clone());

    // Verify initial state
    assert_eq!(em.current_epoch(), 0);
    assert_eq!(em.current_status(), CommitteeStatus::Active);
    assert_eq!(*em.current_committee(), genesis_committee);

    // ── Phase 1: Epoch boundary detection ───────────────────────
    let (elapsed, remaining) = em.epoch_progress(50);
    assert_eq!(elapsed, 50);
    assert_eq!(remaining, 50);

    // Not yet at boundary
    assert!(!em.should_rotate(99));

    // At boundary
    assert!(em.should_rotate(100));

    // Handoff window check: height 95 is in handoff (90 <= 95 < 100)
    assert!(em.is_in_handoff(95));
    assert!(!em.is_in_handoff(50));
    assert!(!em.is_in_handoff(100)); // at epoch end, not in handoff (half-open)

    // ── Phase 2: Trigger rotation ───────────────────────────────
    let rotation = em.trigger_rotation(100, test_da_seed());
    assert!(rotation.is_ok());
    assert_eq!(em.current_status(), CommitteeStatus::PendingRotation);

    let transition = rotation.ok();
    assert!(transition.is_some());
    if let Some(ref t) = transition {
        assert_eq!(t.transition_height, 100);
        assert_eq!(t.handoff_start, 100);
        // handoff_end = handoff_start + handoff_duration = 100 + 10 = 110
        assert_eq!(t.handoff_end, 110);
    }

    // ── Phase 3: DKG Process ────────────────────────────────────
    let members = test_members_3();
    let session_id = compute_test_session_id(1, &members);
    let mut dkg = EpochDKG::new(1, members, 50); // timeout_blocks=50

    // DKG starts in Pending state
    assert_eq!(*dkg.state(), EpochDKGState::Pending);
    assert!(!dkg.is_complete());

    // Round 1: collect all 3 packages
    fill_round1(&mut dkg, &session_id);
    assert!(dkg.check_round1_complete());

    // Round 2: collect all 6 packages
    fill_round2(&mut dkg, &session_id);
    assert!(dkg.check_round2_complete());

    // Finalize DKG
    let dkg_result = dkg.finalize();
    assert!(dkg_result.is_ok());
    assert!(dkg.is_complete());

    let result = dkg_result.ok();
    assert!(result.is_some());
    if let Some(ref r) = result {
        assert!(r.success);
        assert_eq!(r.threshold, 2);
    }

    // ── Phase 4: Prepare new committee ──────────────────────────
    let new_committee = test_committee_2();
    let prepare = em.prepare_next_epoch(new_committee.clone());
    assert!(prepare.is_ok());

    // During handoff: both committees valid at handoff heights
    let both = em.valid_committees_for_height(95);
    assert_eq!(both.len(), 2);

    // ── Phase 5: Complete handoff ───────────────────────────────
    // handoff_end = epoch_start(0) + epoch_duration(100) = 100
    let complete = em.complete_handoff(100);
    assert!(complete.is_ok());

    // ── Phase 6: Verify new epoch ───────────────────────────────
    assert_eq!(em.current_epoch(), 1);
    assert_eq!(em.current_status(), CommitteeStatus::Active);
    assert_eq!(*em.current_committee(), new_committee);

    // New epoch progress from epoch_start_height = 100
    let (new_elapsed, new_remaining) = em.epoch_progress(150);
    assert_eq!(new_elapsed, 50);
    assert_eq!(new_remaining, 50);

    // Should rotate at new boundary: 100 + 100 = 200
    assert!(!em.should_rotate(199));
    assert!(em.should_rotate(200));

    // ── Phase 7: Accountability logging ─────────────────────────
    // Verify accountability works alongside the rotation cycle
    let coord_id = test_coordinator_id(0x01);
    let mut accountability = CoordinatorAccountability::new(coord_id, 1);

    let decision = test_accountable_decision(0x42, 150, [0xFF; 32]);
    accountability.log_decision(decision);

    let proof = accountability.generate_proof(test_workload_id(0x42));
    assert!(proof.is_some());
    if let Some(ref p) = proof {
        assert_eq!(p.epoch(), 1);
        assert_eq!(p.decision().block_height(), 150);
    }

    let range = accountability.get_decisions_in_range(100, 200);
    assert_eq!(range.len(), 1);
}