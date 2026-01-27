//! # Coordinator Integration Tests
//!
//! Integration tests untuk memverifikasi seluruh lifecycle coordinator module.
//!
//! ## Test Coverage
//!
//! 1. Committee creation & validation
//! 2. Epoch boundaries & progress
//! 3. Receipt data hash determinism
//! 4. Threshold receipt verification
//! 5. Committee transition validation
//! 6. Committee status transitions
//! 7. Handoff dual validity

use super::*;
use dsdn_tss::{AggregateSignature, GroupPublicKey, ParticipantPublicKey};

// ════════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════════

fn make_coordinator_id(byte: u8) -> CoordinatorId {
    CoordinatorId::new([byte; 32])
}

fn make_validator_id(byte: u8) -> ValidatorId {
    ValidatorId::new([byte; 32])
}

fn make_workload_id(byte: u8) -> WorkloadId {
    WorkloadId::new([byte; 32])
}

fn make_participant_pubkey(byte: u8) -> ParticipantPublicKey {
    ParticipantPublicKey::from_bytes([byte; 32]).expect("valid pubkey")
}

fn make_group_pubkey() -> GroupPublicKey {
    GroupPublicKey::from_bytes([0x01; 32]).expect("valid group pubkey")
}

fn make_member(byte: u8, stake: u64) -> CoordinatorMember {
    CoordinatorMember::with_timestamp(
        make_coordinator_id(byte),
        make_validator_id(byte),
        make_participant_pubkey(byte),
        stake,
        1700000000,
    )
}

fn make_committee(epoch: u64, member_bytes: &[u8]) -> CoordinatorCommittee {
    let members: Vec<CoordinatorMember> = member_bytes
        .iter()
        .map(|&b| make_member(b, 1000))
        .collect();
    CoordinatorCommittee::new(
        members,
        2, // threshold
        epoch,
        1700000000, // epoch_start
        3600,       // epoch_duration_secs
        make_group_pubkey(),
    )
    .expect("valid committee")
}

fn make_receipt_data(epoch: u64) -> ReceiptData {
    ReceiptData::new(
        make_workload_id(0x01),
        [0x02; 32],
        vec![[0x03; 32], [0x04; 32]],
        1700000000,
        1,
        epoch,
    )
}

fn make_aggregate_signature() -> AggregateSignature {
    // FrostSignature requires 64 bytes
    let frost_sig = dsdn_tss::FrostSignature::from_bytes([0x01; 64]).expect("valid frost signature");
    // SignerId uses from_bytes with 32-byte array
    let signers = vec![
        dsdn_tss::SignerId::from_bytes([0x01; 32]),
        dsdn_tss::SignerId::from_bytes([0x02; 32]),
    ];
    AggregateSignature::new(frost_sig, signers, [0xAA; 32])
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 1: COMMITTEE CREATION VALIDATION
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn test_committee_creation_validation() {
    // Test 1a: Invalid threshold (< 2)
    let members = vec![make_member(0x01, 1000), make_member(0x02, 2000)];
    let result = CoordinatorCommittee::new(
        members.clone(),
        1, // threshold < 2
        1,
        1700000000,
        3600,
        make_group_pubkey(),
    );
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        CommitteeError::InvalidThreshold { threshold: 1, .. }
    ));

    // Test 1b: Invalid threshold (> member count)
    let result = CoordinatorCommittee::new(
        members.clone(),
        5, // threshold > member_count (2)
        1,
        1700000000,
        3600,
        make_group_pubkey(),
    );
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        CommitteeError::InvalidThreshold { threshold: 5, .. }
    ));

    // Test 1c: Duplicate members
    let duplicate_members = vec![
        make_member(0x01, 1000),
        make_member(0x01, 2000), // Same ID
    ];
    let result = CoordinatorCommittee::new(
        duplicate_members,
        2,
        1,
        1700000000,
        3600,
        make_group_pubkey(),
    );
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        CommitteeError::DuplicateMember { .. }
    ));

    // Test 1d: Valid committee
    let result = CoordinatorCommittee::new(
        members,
        2, // valid threshold
        1,
        1700000000,
        3600,
        make_group_pubkey(),
    );
    assert!(result.is_ok());
    let committee = result.expect("valid");
    assert_eq!(committee.threshold(), 2);
    assert_eq!(committee.member_count(), 2);
    assert_eq!(committee.epoch(), 1);
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 2: COMMITTEE EPOCH BOUNDARIES
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn test_committee_epoch_boundaries() {
    let committee = make_committee(1, &[0x01, 0x02, 0x03]);

    // Test 2a: Epoch start
    assert_eq!(committee.epoch_start(), 1700000000);

    // Test 2b: Epoch end (epoch_start + epoch_duration_secs)
    assert_eq!(committee.epoch_end(), 1700003600);

    // Test 2c: Epoch progress 0.0 at start
    let progress_at_start = committee.epoch_progress(1700000000);
    assert!((progress_at_start - 0.0).abs() < 0.001);

    // Test 2d: Epoch progress 0.5 at midpoint
    let progress_at_mid = committee.epoch_progress(1700001800); // halfway
    assert!((progress_at_mid - 0.5).abs() < 0.001);

    // Test 2e: Epoch progress 1.0 at end
    let progress_at_end = committee.epoch_progress(1700003600);
    assert!((progress_at_end - 1.0).abs() < 0.001);

    // Test 2f: Epoch progress clamped beyond boundaries
    assert_eq!(committee.epoch_progress(1699999999), 0.0);
    assert_eq!(committee.epoch_progress(1700003601), 1.0);

    // Test 2g: is_epoch_valid
    assert!(committee.is_epoch_valid(1700000000)); // at start
    assert!(committee.is_epoch_valid(1700001800)); // during
    assert!(!committee.is_epoch_valid(1700003600)); // at end (exclusive)
    assert!(!committee.is_epoch_valid(1699999999)); // before
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 3: RECEIPT DATA HASH DETERMINISM
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn test_receipt_data_hash_deterministic() {
    // Test 3a: Same data → same hash
    let receipt1 = ReceiptData::new(
        make_workload_id(0x01),
        [0x02; 32],
        vec![[0x03; 32]],
        1700000000,
        1,
        1,
    );
    let receipt2 = ReceiptData::new(
        make_workload_id(0x01),
        [0x02; 32],
        vec![[0x03; 32]],
        1700000000,
        1,
        1,
    );
    assert_eq!(receipt1.receipt_data_hash(), receipt2.receipt_data_hash());

    // Test 3b: Different workload_id → different hash
    let receipt3 = ReceiptData::new(
        make_workload_id(0xFF), // Different
        [0x02; 32],
        vec![[0x03; 32]],
        1700000000,
        1,
        1,
    );
    assert_ne!(receipt1.receipt_data_hash(), receipt3.receipt_data_hash());

    // Test 3c: Different blob_hash → different hash
    let receipt4 = ReceiptData::new(
        make_workload_id(0x01),
        [0xFF; 32], // Different
        vec![[0x03; 32]],
        1700000000,
        1,
        1,
    );
    assert_ne!(receipt1.receipt_data_hash(), receipt4.receipt_data_hash());

    // Test 3d: Different timestamp → different hash
    let receipt5 = ReceiptData::new(
        make_workload_id(0x01),
        [0x02; 32],
        vec![[0x03; 32]],
        1700000001, // Different
        1,
        1,
    );
    assert_ne!(receipt1.receipt_data_hash(), receipt5.receipt_data_hash());

    // Test 3e: Different sequence → different hash
    let receipt6 = ReceiptData::new(
        make_workload_id(0x01),
        [0x02; 32],
        vec![[0x03; 32]],
        1700000000,
        999, // Different
        1,
    );
    assert_ne!(receipt1.receipt_data_hash(), receipt6.receipt_data_hash());

    // Test 3f: Different epoch → different hash
    let receipt7 = ReceiptData::new(
        make_workload_id(0x01),
        [0x02; 32],
        vec![[0x03; 32]],
        1700000000,
        1,
        999, // Different
    );
    assert_ne!(receipt1.receipt_data_hash(), receipt7.receipt_data_hash());
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 4: THRESHOLD RECEIPT VERIFICATION
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn test_threshold_receipt_verification() {
    let committee = make_committee(1, &[0x01, 0x02, 0x03]);

    // Test 4a: Valid signers pass verify_signers
    let receipt_data = make_receipt_data(1);
    let signers = vec![make_coordinator_id(0x01), make_coordinator_id(0x02)];
    let receipt = ThresholdReceipt::new(
        receipt_data.clone(),
        make_aggregate_signature(),
        signers,
        committee.committee_hash(),
    );

    // Sub-verification: signers are valid members
    assert!(receipt.verify_signers(&committee));
    // Sub-verification: threshold met
    assert!(receipt.verify_threshold(&committee));
    // Sub-verification: committee hash matches
    assert!(receipt.verify_committee_hash(&committee));
    // Sub-verification: epoch matches
    assert!(receipt.verify_epoch(&committee));

    // Test 4b: Invalid signer rejected
    let invalid_signers = vec![
        make_coordinator_id(0x01),
        make_coordinator_id(0xFF), // Not a member
    ];
    let invalid_receipt = ThresholdReceipt::new(
        receipt_data.clone(),
        make_aggregate_signature(),
        invalid_signers,
        committee.committee_hash(),
    );
    assert!(!invalid_receipt.verify_signers(&committee));

    // Test 4c: Insufficient signatures rejected
    let insufficient_signers = vec![make_coordinator_id(0x01)]; // Only 1, need 2
    let insufficient_receipt = ThresholdReceipt::new(
        receipt_data.clone(),
        make_aggregate_signature(),
        insufficient_signers,
        committee.committee_hash(),
    );
    assert!(!insufficient_receipt.verify_threshold(&committee));

    // Test 4d: Duplicate signer rejected
    let duplicate_signers = vec![
        make_coordinator_id(0x01),
        make_coordinator_id(0x01), // Duplicate
    ];
    let duplicate_receipt = ThresholdReceipt::new(
        receipt_data.clone(),
        make_aggregate_signature(),
        duplicate_signers,
        committee.committee_hash(),
    );
    assert!(!duplicate_receipt.verify_signers(&committee));

    // Test 4e: Wrong committee hash rejected
    let wrong_hash_receipt = ThresholdReceipt::new(
        receipt_data.clone(),
        make_aggregate_signature(),
        vec![make_coordinator_id(0x01), make_coordinator_id(0x02)],
        [0xFF; 32], // Wrong hash
    );
    assert!(!wrong_hash_receipt.verify_committee_hash(&committee));

    // Test 4f: Wrong epoch rejected
    let wrong_epoch_data = make_receipt_data(999); // Wrong epoch
    let wrong_epoch_receipt = ThresholdReceipt::new(
        wrong_epoch_data,
        make_aggregate_signature(),
        vec![make_coordinator_id(0x01), make_coordinator_id(0x02)],
        committee.committee_hash(),
    );
    assert!(!wrong_epoch_receipt.verify_epoch(&committee));

    // Test 4g: verify_detailed returns specific errors
    let result = invalid_receipt.verify_detailed(&committee);
    assert!(result.is_err());
    // Should be InvalidSigner or DuplicateSigner depending on order
    let err = result.unwrap_err();
    assert!(
        matches!(err, ReceiptVerificationError::InvalidSigner { .. })
            || matches!(err, ReceiptVerificationError::DuplicateSigner { .. })
    );
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 5: COMMITTEE TRANSITION VALIDATION
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn test_committee_transition_validation() {
    let old_committee = make_committee(1, &[0x01, 0x02, 0x03]);
    let new_committee = make_committee(2, &[0x02, 0x03, 0x04]);
    let initiator = make_coordinator_id(0x01);

    // Test 5a: Valid transition (epoch sequence correct)
    let result = CommitteeTransition::new(
        old_committee.clone(),
        new_committee.clone(),
        1700000000,
        3600,
        initiator,
    );
    assert!(result.is_ok());
    let transition = result.expect("valid");
    assert_eq!(transition.from_epoch(), 1);
    assert_eq!(transition.to_epoch(), 2);

    // Test 5b: Invalid epoch sequence (not consecutive)
    let invalid_new_committee = make_committee(5, &[0x01, 0x02]); // Epoch 5 != 1+1
    let result = CommitteeTransition::new(
        old_committee.clone(),
        invalid_new_committee,
        1700000000,
        3600,
        initiator,
    );
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        TransitionError::InvalidEpochSequence { old: 1, new: 5 }
    ));

    // Test 5c: Invalid epoch sequence (same epoch)
    let same_epoch_committee = make_committee(1, &[0x01, 0x02]); // Same epoch
    let result = CommitteeTransition::new(
        old_committee.clone(),
        same_epoch_committee,
        1700000000,
        3600,
        initiator,
    );
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        TransitionError::InvalidEpochSequence { old: 1, new: 1 }
    ));

    // Test 5d: Invalid handoff timing
    let result = CommitteeTransition::new(
        old_committee.clone(),
        new_committee.clone(),
        1699999999, // Before epoch_start
        3600,
        initiator,
    );
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        TransitionError::InvalidHandoffTiming
    ));

    // Test 5e: Invalid handoff duration (zero)
    let result = CommitteeTransition::new(
        old_committee.clone(),
        new_committee,
        1700000000,
        0, // Zero duration
        initiator,
    );
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        TransitionError::InvalidHandoffDuration
    ));
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 6: COMMITTEE STATUS TRANSITIONS
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn test_committee_status_transitions() {
    let committee = make_committee(1, &[0x01, 0x02]);
    let committee2 = make_committee(2, &[0x01, 0x02]);

    // Test 6a: Initializing → Activate → Active
    let status = CommitteeStatus::initializing(1);
    assert!(status.is_initializing());
    assert!(!status.can_accept_receipts());

    let activate = CommitteeStatusTransition::Activate {
        committee: committee.clone(),
        since: 1700000000,
    };
    let result = status.apply_transition(activate);
    assert!(result.is_ok());
    let active_status = result.expect("valid");
    assert!(active_status.is_active());
    assert!(active_status.can_accept_receipts());

    // Test 6b: Active → StartHandoff → InHandoff
    let transition = CommitteeTransition::new(
        committee.clone(),
        committee2.clone(),
        1700000000,
        3600,
        make_coordinator_id(0x01),
    )
    .expect("valid transition");

    let start_handoff = CommitteeStatusTransition::StartHandoff {
        next_committee: committee2.clone(),
        transition: transition.clone(),
    };
    let result = active_status.apply_transition(start_handoff);
    assert!(result.is_ok());
    let handoff_status = result.expect("valid");
    assert!(handoff_status.is_in_handoff());
    assert!(handoff_status.can_accept_receipts());

    // Test 6c: InHandoff → CompleteHandoff → Active
    let complete_handoff = CommitteeStatusTransition::CompleteHandoff {
        completed_at: 1700003600,
    };
    let result = handoff_status.clone().apply_transition(complete_handoff);
    assert!(result.is_ok());
    let new_active = result.expect("valid");
    assert!(new_active.is_active());
    assert_eq!(new_active.current_committee().map(|c| c.epoch()), Some(2));

    // Test 6d: InHandoff → Expire → Expired
    let expire = CommitteeStatusTransition::Expire {
        expired_at: 1700003600,
    };
    let result = handoff_status.apply_transition(expire);
    assert!(result.is_ok());
    let expired_status = result.expect("valid");
    assert!(expired_status.is_expired());
    assert!(!expired_status.can_accept_receipts());

    // Test 6e: Invalid transition (Active → CompleteHandoff)
    let active_status = CommitteeStatus::active(committee.clone(), 1700000000);
    let complete_handoff = CommitteeStatusTransition::CompleteHandoff {
        completed_at: 1700003600,
    };
    let result = active_status.apply_transition(complete_handoff);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        StatusTransitionError::InvalidTransition { .. }
    ));

    // Test 6f: Any → Reset → Initializing
    let expired_status = CommitteeStatus::expired(committee, 1700003600);
    let reset = CommitteeStatusTransition::Reset { expected_epoch: 3 };
    let result = expired_status.apply_transition(reset);
    assert!(result.is_ok());
    let init_status = result.expect("valid");
    assert!(init_status.is_initializing());
}

// ════════════════════════════════════════════════════════════════════════════════
// TEST 7: HANDOFF DUAL VALIDITY
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn test_handoff_both_committees_valid() {
    let old_committee = make_committee(1, &[0x01, 0x02, 0x03]);
    let new_committee = make_committee(2, &[0x02, 0x03, 0x04]);
    let initiator = make_coordinator_id(0x01);

    let transition = CommitteeTransition::new(
        old_committee.clone(),
        new_committee.clone(),
        1700000000, // handoff_start
        3600,       // handoff_duration_secs (handoff_end = 1700003600)
        initiator,
    )
    .expect("valid transition");

    let status = CommitteeStatus::in_handoff(transition.clone());

    // Test 7a: During handoff period, current committee is valid
    let handoff_mid = 1700001800; // Midway through handoff
    assert!(transition.is_in_handoff(handoff_mid));

    let valid_committee = status.valid_committee_for(handoff_mid);
    assert!(valid_committee.is_some());
    assert_eq!(valid_committee.map(|c| c.epoch()), Some(1)); // Current committee

    // Test 7b: Current committee accessible
    assert_eq!(status.current_committee().map(|c| c.epoch()), Some(1));

    // Test 7c: Next committee accessible
    assert_eq!(status.next_committee().map(|c| c.epoch()), Some(2));

    // Test 7d: After handoff_end, next committee is valid
    let after_handoff = 1700003601; // After handoff_end
    assert!(!transition.is_in_handoff(after_handoff));

    let valid_committee = status.valid_committee_for(after_handoff);
    assert!(valid_committee.is_some());
    assert_eq!(valid_committee.map(|c| c.epoch()), Some(2)); // Next committee

    // Test 7e: Before handoff_start, current committee is valid
    let before_handoff = 1699999999;
    assert!(!transition.is_in_handoff(before_handoff));

    // For InHandoff status, valid_committee_for returns current_committee
    // before handoff_start (since handoff hasn't begun)
    let valid_committee = status.valid_committee_for(before_handoff);
    assert!(valid_committee.is_some());
    assert_eq!(valid_committee.map(|c| c.epoch()), Some(1));

    // Test 7f: Handoff progress
    assert_eq!(transition.handoff_progress(1700000000), 0.0); // At start
    let progress_mid = transition.handoff_progress(1700001800);
    assert!((progress_mid - 0.5).abs() < 0.001); // Midway
    assert_eq!(transition.handoff_progress(1700003600), 1.0); // At end

    // Test 7g: Membership queries
    // 0x01 is only in old_committee
    assert!(transition.is_member_of_either(&make_coordinator_id(0x01)));
    assert!(!transition.is_member_of_both(&make_coordinator_id(0x01)));

    // 0x02 is in both committees
    assert!(transition.is_member_of_either(&make_coordinator_id(0x02)));
    assert!(transition.is_member_of_both(&make_coordinator_id(0x02)));

    // 0x04 is only in new_committee
    assert!(transition.is_member_of_either(&make_coordinator_id(0x04)));
    assert!(!transition.is_member_of_both(&make_coordinator_id(0x04)));

    // 0xFF is in neither
    assert!(!transition.is_member_of_either(&make_coordinator_id(0xFF)));

    // Overlapping members
    let overlapping = transition.overlapping_members();
    assert_eq!(overlapping.len(), 2); // 0x02 and 0x03
    assert!(overlapping.contains(&make_coordinator_id(0x02)));
    assert!(overlapping.contains(&make_coordinator_id(0x03)));
}

// ════════════════════════════════════════════════════════════════════════════════
// ADDITIONAL EDGE CASE TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[test]
fn test_receipt_data_serialization_roundtrip() {
    let receipt = make_receipt_data(1);

    // JSON roundtrip
    let json = serde_json::to_string(&receipt).expect("json serialize");
    let deserialized: ReceiptData = serde_json::from_str(&json).expect("json deserialize");
    assert_eq!(receipt, deserialized);
    assert_eq!(receipt.receipt_data_hash(), deserialized.receipt_data_hash());

    // Bincode roundtrip
    let binary = bincode::serialize(&receipt).expect("bincode serialize");
    let deserialized: ReceiptData = bincode::deserialize(&binary).expect("bincode deserialize");
    assert_eq!(receipt, deserialized);
}

#[test]
fn test_committee_hash_deterministic() {
    let committee1 = make_committee(1, &[0x01, 0x02, 0x03]);
    let committee2 = make_committee(1, &[0x01, 0x02, 0x03]);

    // Same committee configuration → same hash
    assert_eq!(committee1.committee_hash(), committee2.committee_hash());

    // Different epoch → different hash
    let committee3 = make_committee(2, &[0x01, 0x02, 0x03]);
    assert_ne!(committee1.committee_hash(), committee3.committee_hash());
}

#[test]
fn test_status_name_mapping() {
    let active = CommitteeStatus::active(make_committee(1, &[0x01, 0x02]), 1700000000);
    assert_eq!(active.status_name(), "active");

    let initializing = CommitteeStatus::initializing(1);
    assert_eq!(initializing.status_name(), "initializing");

    let expired = CommitteeStatus::expired(make_committee(1, &[0x01, 0x02]), 1700000000);
    assert_eq!(expired.status_name(), "expired");

    let transition = CommitteeTransition::new(
        make_committee(1, &[0x01, 0x02]),
        make_committee(2, &[0x01, 0x02]),
        1700000000,
        3600,
        make_coordinator_id(0x01),
    )
    .expect("valid");
    let in_handoff = CommitteeStatus::in_handoff(transition);
    assert_eq!(in_handoff.status_name(), "in_handoff");
}

#[test]
fn test_all_types_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}

    // All identifier types
    assert_send_sync::<CoordinatorId>();
    assert_send_sync::<ValidatorId>();
    assert_send_sync::<WorkloadId>();

    // Member and committee
    assert_send_sync::<CoordinatorMember>();
    assert_send_sync::<CoordinatorCommittee>();

    // Receipt types
    assert_send_sync::<ReceiptData>();
    assert_send_sync::<ThresholdReceipt>();

    // Transition and status
    assert_send_sync::<CommitteeTransition>();
    assert_send_sync::<CommitteeStatus>();
    assert_send_sync::<CommitteeStatusTransition>();

    // Error types
    assert_send_sync::<CommitteeError>();
    assert_send_sync::<TransitionError>();
    assert_send_sync::<StatusTransitionError>();
    assert_send_sync::<ReceiptVerificationError>();
    assert_send_sync::<DecodeError>();
}