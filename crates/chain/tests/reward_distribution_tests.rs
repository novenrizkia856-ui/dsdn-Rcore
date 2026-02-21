//! # CH.10 — Reward Distribution Integration Tests
//!
//! Tests for reward math correctness, consistency, and edge cases:
//! - 70/20/10 exact arithmetic
//! - Anti-self-dealing 0/20/80
//! - Rounding behavior
//! - FeeSplit ↔ RewardDistribution consistency
//! - Cross-path delegation verification
//! - Boundary conditions

use dsdn_chain::tokenomics::{
    calculate_fee_by_resource_class, calculate_receipt_v1_reward, verify_distribution_consistency,
    FeeSplit,
};
use dsdn_chain::tx::ResourceClass;
use dsdn_chain::types::Address;
use dsdn_common::claim_validation::RewardDistribution;
use dsdn_common::receipt_v1::ReceiptType;

// ════════════════════════════════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════════════════════════════════

fn addr(byte: u8) -> Address {
    Address::from_bytes([byte; 20])
}

// ════════════════════════════════════════════════════════════════════════════
// 1. EXACT REWARD MATH 70/20/10
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn exact_split_1000() {
    let split = calculate_fee_by_resource_class(1000, &ResourceClass::Storage, Some(addr(0x02)), &addr(0x01));
    assert_eq!(split.node_share, 700);
    assert_eq!(split.validator_share, 200);
    assert_eq!(split.treasury_share, 100);
    assert_eq!(split.total(), 1000);
}

#[test]
fn exact_split_10000() {
    let split = calculate_fee_by_resource_class(10000, &ResourceClass::Compute, Some(addr(0x02)), &addr(0x01));
    assert_eq!(split.node_share, 7000);
    assert_eq!(split.validator_share, 2000);
    assert_eq!(split.treasury_share, 1000);
    assert_eq!(split.total(), 10000);
}

#[test]
fn exact_split_100() {
    let split = calculate_fee_by_resource_class(100, &ResourceClass::Storage, Some(addr(0x02)), &addr(0x01));
    assert_eq!(split.node_share, 70);
    assert_eq!(split.validator_share, 20);
    assert_eq!(split.treasury_share, 10);
}

// ════════════════════════════════════════════════════════════════════════════
// 2. ANTI-SELF-DEALING 0/20/80
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn anti_self_dealing_storage() {
    let a = addr(0x01);
    let split = calculate_fee_by_resource_class(1000, &ResourceClass::Storage, Some(a), &a);
    assert_eq!(split.node_share, 0);
    assert_eq!(split.validator_share, 200);
    assert_eq!(split.treasury_share, 800);
    assert_eq!(split.total(), 1000);
}

#[test]
fn anti_self_dealing_compute() {
    let a = addr(0x01);
    let split = calculate_fee_by_resource_class(1000, &ResourceClass::Compute, Some(a), &a);
    assert_eq!(split.node_share, 0);
    assert_eq!(split.validator_share, 200);
    assert_eq!(split.treasury_share, 800);
}

// ════════════════════════════════════════════════════════════════════════════
// 3. ROUNDING BEHAVIOR
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn rounding_odd_number_999() {
    let split = calculate_fee_by_resource_class(999, &ResourceClass::Storage, Some(addr(0x02)), &addr(0x01));
    // 999 * 70 / 100 = 699, 999 * 20 / 100 = 199, remainder = 101
    assert_eq!(split.node_share, 699);
    assert_eq!(split.validator_share, 199);
    assert_eq!(split.treasury_share, 101);
    assert_eq!(split.total(), 999);
}

#[test]
fn rounding_small_value_3() {
    let split = calculate_fee_by_resource_class(3, &ResourceClass::Storage, Some(addr(0x02)), &addr(0x01));
    // 3 * 70 / 100 = 2, 3 * 20 / 100 = 0, remainder = 1
    assert_eq!(split.node_share, 2);
    assert_eq!(split.validator_share, 0);
    assert_eq!(split.treasury_share, 1);
    assert_eq!(split.total(), 3);
}

#[test]
fn rounding_value_1_all_to_treasury() {
    let split = calculate_fee_by_resource_class(1, &ResourceClass::Storage, Some(addr(0x02)), &addr(0x01));
    assert_eq!(split.node_share, 0);
    assert_eq!(split.validator_share, 0);
    assert_eq!(split.treasury_share, 1);
    assert_eq!(split.total(), 1);
}

#[test]
fn rounding_value_7() {
    let split = calculate_fee_by_resource_class(7, &ResourceClass::Storage, Some(addr(0x02)), &addr(0x01));
    // 7 * 70 / 100 = 4, 7 * 20 / 100 = 1, remainder = 2
    assert_eq!(split.node_share, 4);
    assert_eq!(split.validator_share, 1);
    assert_eq!(split.treasury_share, 2);
    assert_eq!(split.total(), 7);
}

// ════════════════════════════════════════════════════════════════════════════
// 4. TRANSFER AND GOVERNANCE — 100% VALIDATOR
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn transfer_100_percent_validator() {
    let split = calculate_fee_by_resource_class(1000, &ResourceClass::Transfer, None, &addr(0x01));
    assert_eq!(split.node_share, 0);
    assert_eq!(split.validator_share, 1000);
    assert_eq!(split.treasury_share, 0);
}

#[test]
fn governance_100_percent_validator() {
    let split = calculate_fee_by_resource_class(1000, &ResourceClass::Governance, None, &addr(0x01));
    assert_eq!(split.node_share, 0);
    assert_eq!(split.validator_share, 1000);
    assert_eq!(split.treasury_share, 0);
}

// ════════════════════════════════════════════════════════════════════════════
// 5. LARGE u128 BOUNDARY
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn large_u128_no_overflow() {
    let large = u128::MAX / 200;
    let split = calculate_fee_by_resource_class(large, &ResourceClass::Storage, Some(addr(0x02)), &addr(0x01));
    assert_eq!(split.total(), large);
}

#[test]
fn zero_fee_all_zero() {
    let split = calculate_fee_by_resource_class(0, &ResourceClass::Storage, Some(addr(0x02)), &addr(0x01));
    assert_eq!(split.node_share, 0);
    assert_eq!(split.validator_share, 0);
    assert_eq!(split.treasury_share, 0);
}

// ════════════════════════════════════════════════════════════════════════════
// 6. FEESPLIT ↔ REWARD DISTRIBUTION CONSISTENCY
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn consistency_match_1000() {
    let split = FeeSplit {
        node_share: 700,
        validator_share: 200,
        treasury_share: 100,
    };
    let dist = RewardDistribution::compute(1000);
    assert!(verify_distribution_consistency(&split, &dist));
}

#[test]
fn consistency_mismatch_node() {
    let split = FeeSplit {
        node_share: 699,
        validator_share: 200,
        treasury_share: 100,
    };
    let dist = RewardDistribution::compute(1000);
    assert!(!verify_distribution_consistency(&split, &dist));
}

#[test]
fn consistency_mismatch_validator() {
    let split = FeeSplit {
        node_share: 700,
        validator_share: 199,
        treasury_share: 100,
    };
    let dist = RewardDistribution::compute(1000);
    assert!(!verify_distribution_consistency(&split, &dist));
}

#[test]
fn consistency_mismatch_treasury() {
    let split = FeeSplit {
        node_share: 700,
        validator_share: 200,
        treasury_share: 99,
    };
    let dist = RewardDistribution::compute(1000);
    assert!(!verify_distribution_consistency(&split, &dist));
}

#[test]
fn consistency_zero() {
    let split = FeeSplit {
        node_share: 0,
        validator_share: 0,
        treasury_share: 0,
    };
    let dist = RewardDistribution::compute(0);
    assert!(verify_distribution_consistency(&split, &dist));
}

// ════════════════════════════════════════════════════════════════════════════
// 7. DELEGATION CONSISTENCY — ReceiptV1 vs ResourceClass
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn receipt_v1_delegates_to_resource_class_storage() {
    let submitter = addr(0x01);
    let node = addr(0x02);

    let via_receipt =
        calculate_receipt_v1_reward(5555, &ReceiptType::Storage, Some(node), &submitter);
    let via_resource =
        calculate_fee_by_resource_class(5555, &ResourceClass::Storage, Some(node), &submitter);

    assert_eq!(via_receipt.node_share, via_resource.node_share);
    assert_eq!(via_receipt.validator_share, via_resource.validator_share);
    assert_eq!(via_receipt.treasury_share, via_resource.treasury_share);
}

#[test]
fn receipt_v1_delegates_to_resource_class_compute() {
    let submitter = addr(0x01);
    let node = addr(0x02);

    let via_receipt =
        calculate_receipt_v1_reward(12345, &ReceiptType::Compute, Some(node), &submitter);
    let via_resource =
        calculate_fee_by_resource_class(12345, &ResourceClass::Compute, Some(node), &submitter);

    assert_eq!(via_receipt.node_share, via_resource.node_share);
    assert_eq!(via_receipt.validator_share, via_resource.validator_share);
    assert_eq!(via_receipt.treasury_share, via_resource.treasury_share);
}

// ════════════════════════════════════════════════════════════════════════════
// 8. FULL ROUND-TRIP: tokenomics + dsdn_common agree
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn full_round_trip_tokenomics_and_common_agree() {
    let submitter = addr(0x01);
    let node = addr(0x02);

    let split =
        calculate_receipt_v1_reward(1000, &ReceiptType::Storage, Some(node), &submitter);
    let dist = RewardDistribution::compute(1000);

    assert!(verify_distribution_consistency(&split, &dist));
}

#[test]
fn full_round_trip_anti_self_dealing() {
    let same = addr(0x01);

    let split = calculate_receipt_v1_reward(1000, &ReceiptType::Compute, Some(same), &same);
    let dist = RewardDistribution::with_anti_self_dealing(1000);

    assert!(verify_distribution_consistency(&split, &dist));
}

// ════════════════════════════════════════════════════════════════════════════
// 9. DETERMINISM
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn deterministic_repeated_calculation() {
    let submitter = addr(0x01);
    let node = addr(0x02);

    let s1 = calculate_receipt_v1_reward(999, &ReceiptType::Storage, Some(node), &submitter);
    let s2 = calculate_receipt_v1_reward(999, &ReceiptType::Storage, Some(node), &submitter);

    assert_eq!(s1.node_share, s2.node_share);
    assert_eq!(s1.validator_share, s2.validator_share);
    assert_eq!(s1.treasury_share, s2.treasury_share);
}

// ════════════════════════════════════════════════════════════════════════════
// 10. NO MUTATION SIDE-EFFECT
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn fee_split_is_pure_function() {
    let submitter = addr(0x01);
    let node = addr(0x02);

    // Calling twice does not accumulate or change anything.
    let _ = calculate_receipt_v1_reward(1000, &ReceiptType::Storage, Some(node), &submitter);
    let s2 = calculate_receipt_v1_reward(1000, &ReceiptType::Storage, Some(node), &submitter);

    assert_eq!(s2.node_share, 700);
    assert_eq!(s2.validator_share, 200);
    assert_eq!(s2.treasury_share, 100);
}

#[test]
fn verify_distribution_is_pure_function() {
    let split = FeeSplit {
        node_share: 700,
        validator_share: 200,
        treasury_share: 100,
    };
    let dist = RewardDistribution::compute(1000);

    // Multiple calls return same result.
    assert_eq!(
        verify_distribution_consistency(&split, &dist),
        verify_distribution_consistency(&split, &dist)
    );
}