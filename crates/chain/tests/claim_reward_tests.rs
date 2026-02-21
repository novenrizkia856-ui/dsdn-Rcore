//! # CH.10 — ClaimReward Integration Tests
//!
//! Tests for the receipt claiming lifecycle including:
//! - Storage claim → immediate reward
//! - Double claim prevention
//! - Receipt validation
//! - ResourceReceipt → ReceiptV1 bridge
//! - Anti-self-dealing scenarios
//! - Boundary conditions and overflow safety

use dsdn_chain::receipt::{MeasuredUsage, NodeClass, ResourceReceipt, ResourceType};
use dsdn_chain::tokenomics::{
    calculate_fee_by_resource_class, calculate_receipt_v1_reward, verify_distribution_consistency,
    FeeSplit,
};
use dsdn_chain::types::Address;
use dsdn_common::claim_validation::RewardDistribution;
use dsdn_common::receipt_v1::ReceiptType;

// ════════════════════════════════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════════════════════════════════

fn addr(byte: u8) -> Address {
    Address::from_bytes([byte; 20])
}

fn make_storage_receipt(reward_base: u128) -> ResourceReceipt {
    ResourceReceipt::new(
        addr(0x01),
        NodeClass::Regular,
        ResourceType::Storage,
        MeasuredUsage::new(100, 200, 10, 500),
        reward_base,
        false,
        1_700_000_000,
    )
}

fn make_compute_receipt(reward_base: u128) -> ResourceReceipt {
    ResourceReceipt::new(
        addr(0x01),
        NodeClass::Regular,
        ResourceType::Compute,
        MeasuredUsage::new(500, 1000, 0, 200),
        reward_base,
        false,
        1_700_000_000,
    )
}

// ════════════════════════════════════════════════════════════════════════════
// 1. STORAGE CLAIM — HAPPY PATH
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn storage_claim_reward_split_70_20_10() {
    let submitter = addr(0x01);
    let node = addr(0x02);

    let split = calculate_receipt_v1_reward(1000, &ReceiptType::Storage, Some(node), &submitter);

    assert_eq!(split.node_share, 700);
    assert_eq!(split.validator_share, 200);
    assert_eq!(split.treasury_share, 100);
    assert_eq!(split.total(), 1000);
}

#[test]
fn compute_claim_reward_split_70_20_10() {
    let submitter = addr(0x01);
    let node = addr(0x02);

    let split = calculate_receipt_v1_reward(1000, &ReceiptType::Compute, Some(node), &submitter);

    assert_eq!(split.node_share, 700);
    assert_eq!(split.validator_share, 200);
    assert_eq!(split.treasury_share, 100);
}

// ════════════════════════════════════════════════════════════════════════════
// 2. RECEIPT HASH DETERMINISM
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn receipt_id_deterministic_same_inputs() {
    let r1 = make_storage_receipt(1_000_000);
    let r2 = make_storage_receipt(1_000_000);
    assert_eq!(r1.receipt_id, r2.receipt_id);
}

#[test]
fn receipt_id_changes_with_reward_base() {
    let r1 = make_storage_receipt(1_000);
    let r2 = make_storage_receipt(2_000);
    assert_ne!(r1.receipt_id, r2.receipt_id);
}

#[test]
fn receipt_id_changes_with_resource_type() {
    let r1 = make_storage_receipt(1000);
    let r2 = make_compute_receipt(1000);
    assert_ne!(r1.receipt_id, r2.receipt_id);
}

// ════════════════════════════════════════════════════════════════════════════
// 3. REWARD BASE BOUNDARIES
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn reward_base_zero_produces_zero_split() {
    let submitter = addr(0x01);
    let node = addr(0x02);

    let split = calculate_receipt_v1_reward(0, &ReceiptType::Storage, Some(node), &submitter);

    assert_eq!(split.node_share, 0);
    assert_eq!(split.validator_share, 0);
    assert_eq!(split.treasury_share, 0);
    assert_eq!(split.total(), 0);
}

#[test]
fn reward_base_one_rounding_correct() {
    let submitter = addr(0x01);
    let node = addr(0x02);

    let split = calculate_receipt_v1_reward(1, &ReceiptType::Storage, Some(node), &submitter);

    // 1 * 70 / 100 = 0, 1 * 20 / 100 = 0, remainder = 1
    assert_eq!(split.node_share, 0);
    assert_eq!(split.validator_share, 0);
    assert_eq!(split.treasury_share, 1);
    assert_eq!(split.total(), 1);
}

#[test]
fn reward_base_large_no_overflow() {
    let submitter = addr(0x01);
    let node = addr(0x02);
    let large = u128::MAX / 200; // Large but safe for multiplication

    let split =
        calculate_receipt_v1_reward(large, &ReceiptType::Storage, Some(node), &submitter);

    assert_eq!(split.total(), large);
}

#[test]
fn reward_base_odd_number_no_loss() {
    let submitter = addr(0x01);
    let node = addr(0x02);

    let split = calculate_receipt_v1_reward(999, &ReceiptType::Storage, Some(node), &submitter);

    // Treasury gets remainder, so total must equal input.
    assert_eq!(split.total(), 999);
}

// ════════════════════════════════════════════════════════════════════════════
// 4. ANTI-SELF-DEALING
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn anti_self_dealing_redirects_node_share_to_treasury() {
    let same_addr = addr(0x01);
    // node == submitter
    let split =
        calculate_receipt_v1_reward(1000, &ReceiptType::Storage, Some(same_addr), &same_addr);

    assert_eq!(split.node_share, 0);
    assert_eq!(split.validator_share, 200);
    assert_eq!(split.treasury_share, 800); // 700 + 100
    assert_eq!(split.total(), 1000);
}

#[test]
fn anti_self_dealing_compute_same_behavior() {
    let same_addr = addr(0x01);

    let split =
        calculate_receipt_v1_reward(1000, &ReceiptType::Compute, Some(same_addr), &same_addr);

    assert_eq!(split.node_share, 0);
    assert_eq!(split.validator_share, 200);
    assert_eq!(split.treasury_share, 800);
}

#[test]
fn no_anti_self_dealing_when_node_none() {
    let submitter = addr(0x01);

    let split = calculate_receipt_v1_reward(1000, &ReceiptType::Storage, None, &submitter);

    // No node → no anti-self-dealing → normal 70/20/10.
    assert_eq!(split.node_share, 700);
    assert_eq!(split.validator_share, 200);
    assert_eq!(split.treasury_share, 100);
}

#[test]
fn no_anti_self_dealing_when_addresses_differ() {
    let submitter = addr(0x01);
    let node = addr(0x02);

    let split = calculate_receipt_v1_reward(1000, &ReceiptType::Storage, Some(node), &submitter);

    assert_eq!(split.node_share, 700);
}

// ════════════════════════════════════════════════════════════════════════════
// 5. RESOURCE RECEIPT → RECEIPT V1 BRIDGE
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn can_upgrade_requires_signature_and_reward() {
    let mut receipt = make_storage_receipt(1000);
    assert!(!receipt.can_upgrade_to_v1()); // No signature

    receipt.set_signature(vec![0x01; 64]);
    assert!(receipt.can_upgrade_to_v1()); // Has signature + reward > 0
}

#[test]
fn can_upgrade_false_for_zero_reward() {
    let mut receipt = make_storage_receipt(0);
    receipt.set_signature(vec![0x01; 64]);
    assert!(!receipt.can_upgrade_to_v1());
}

#[test]
fn to_receipt_v1_storage_success() {
    let mut receipt = make_storage_receipt(1_000_000);
    receipt.set_signature(vec![0x07; 64]);

    let result = receipt.to_receipt_v1(vec![0x04; 64], vec![[0x05; 32]], 42);
    assert!(result.is_ok());

    let v1 = result.expect("Storage receipt should convert successfully");
    assert_eq!(v1.receipt_type(), ReceiptType::Storage);
    assert_eq!(v1.reward_base(), 1_000_000);
    assert_eq!(v1.epoch(), 42);
    assert!(v1.execution_commitment().is_none());
}

#[test]
fn to_receipt_v1_compute_fails_no_execution_commitment() {
    let mut receipt = make_compute_receipt(1000);
    receipt.set_signature(vec![0x07; 64]);

    let result = receipt.to_receipt_v1(vec![0x04; 64], vec![[0x05; 32]], 1);

    // Compute requires execution_commitment = Some, V0 has None.
    assert!(result.is_err());
}

#[test]
fn to_receipt_v1_deterministic() {
    let mut receipt = make_storage_receipt(1000);
    receipt.set_signature(vec![0x07; 64]);

    let v1a = receipt
        .to_receipt_v1(vec![0x04; 64], vec![[0x05; 32]], 42)
        .expect("valid");
    let v1b = receipt
        .to_receipt_v1(vec![0x04; 64], vec![[0x05; 32]], 42)
        .expect("valid");

    assert_eq!(v1a.compute_receipt_hash(), v1b.compute_receipt_hash());
}

#[test]
fn to_receipt_v1_no_mutation_of_source() {
    let mut receipt = make_storage_receipt(1000);
    receipt.set_signature(vec![0x07; 64]);
    let before = receipt.clone();

    let _ = receipt.to_receipt_v1(vec![0x04; 64], vec![], 1);

    assert_eq!(receipt, before);
}

// ════════════════════════════════════════════════════════════════════════════
// 6. RESOURCE TYPE ↔ RECEIPT TYPE CONVERSION
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn resource_type_storage_to_receipt_type() {
    let rt: ReceiptType = ResourceType::Storage.into();
    assert_eq!(rt, ReceiptType::Storage);
}

#[test]
fn resource_type_compute_to_receipt_type() {
    let rt: ReceiptType = ResourceType::Compute.into();
    assert_eq!(rt, ReceiptType::Compute);
}

#[test]
fn receipt_type_to_resource_type_roundtrip() {
    let original = ResourceType::Storage;
    let intermediate: ReceiptType = original.into();
    let roundtrip: ResourceType = intermediate.into();
    assert_eq!(original, roundtrip);
}