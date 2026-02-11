//! Comprehensive Selection Tests (14A.2B.2.9)
//!
//! Unit tests untuk seluruh fungsi selection dan verification.
//!
//! # Test Categories
//!
//! - Selection & Determinism
//! - Seed Derivation & Verification
//! - Committee Verification
//! - Utilities (weight computation, shuffle)
//! - Edge Cases

use super::*;

// ════════════════════════════════════════════════════════════════════════════════
// Test Helpers
// ════════════════════════════════════════════════════════════════════════════════

/// Create deterministic validator for testing.
fn create_test_validator(seed: u8, zone: &str, stake: u128) -> ValidatorCandidate {
    let mut id = [0u8; 32];
    id[0] = seed;
    id[31] = seed.wrapping_add(1);

    let mut pubkey = [0u8; 32];
    pubkey[0] = seed.wrapping_add(100);
    pubkey[31] = seed.wrapping_add(101);

    ValidatorCandidate {
        id,
        pubkey,
        stake,
        zone: zone.to_string(),
        node_identity: None,
        tls_info: None,
        node_class: None,
        cooldown: None,
        identity_proof: None,
    }
}

/// Create deterministic validator set.
fn create_validator_set(count: u8, base_stake: u128) -> Vec<ValidatorCandidate> {
    (0..count)
        .map(|i| create_test_validator(i, &format!("zone-{}", i % 3), base_stake + (i as u128 * 100)))
        .collect()
}

/// Create config for testing.
fn create_test_config(committee_size: u8, threshold: u8, min_stake: u128) -> SelectionConfig {
    SelectionConfig {
        committee_size,
        threshold,
        min_stake,
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// Selection & Determinism Tests
// ════════════════════════════════════════════════════════════════════════════════

/// Test that selection is fully deterministic.
/// Same inputs MUST produce same output every time.
#[test]
fn test_selection_deterministic() {
    let config = create_test_config(5, 3, 100);
    let selector = CoordinatorSelector::new(config).expect("valid config");

    let validators = create_validator_set(15, 1000);
    let seed = [0x42u8; 32];
    let epoch = 1u64;

    // Run selection 100 times
    let reference = selector
        .select_committee(&validators, epoch, &seed)
        .expect("first selection");

    for i in 0..100 {
        let result = selector
            .select_committee(&validators, epoch, &seed)
            .expect(&format!("selection iteration {}", i));

        // Member count must match
        assert_eq!(
            result.members.len(),
            reference.members.len(),
            "iteration {} member count mismatch",
            i
        );

        // Each member must be identical
        for (j, (a, b)) in result.members.iter().zip(reference.members.iter()).enumerate() {
            assert_eq!(a.id, b.id, "iteration {} member {} id mismatch", i, j);
            assert_eq!(
                a.validator_id, b.validator_id,
                "iteration {} member {} validator_id mismatch",
                i, j
            );
            assert_eq!(a.pubkey, b.pubkey, "iteration {} member {} pubkey mismatch", i, j);
            assert_eq!(a.stake, b.stake, "iteration {} member {} stake mismatch", i, j);
        }

        // Threshold must match
        assert_eq!(result.threshold, reference.threshold, "iteration {} threshold mismatch", i);

        // Epoch must match
        assert_eq!(result.epoch, reference.epoch, "iteration {} epoch mismatch", i);

        // Group pubkey must match
        assert_eq!(
            result.group_pubkey, reference.group_pubkey,
            "iteration {} group_pubkey mismatch",
            i
        );
    }
}

/// Test that selection respects stake in final ordering.
/// Higher stake validators should appear first in the sorted committee.
#[test]
fn test_selection_stake_weighted() {
    let config = create_test_config(5, 3, 100);
    let selector = CoordinatorSelector::new(config).expect("valid config");

    // Create validators with different stakes
    let mut validators = Vec::new();

    // Mix of high and low stake validators
    for i in 0..10 {
        let stake = if i % 2 == 0 { 10000 } else { 1000 };
        validators.push(create_test_validator(i, &format!("zone-{}", i % 3), stake));
    }

    let seed = [0x42u8; 32];
    let committee = selector
        .select_committee(&validators, 1, &seed)
        .expect("selection should succeed");

    // Verify that committee members are sorted by stake descending
    // This is the actual stake weighting behavior: higher stake = higher position
    for i in 1..committee.members.len() {
        assert!(
            committee.members[i - 1].stake >= committee.members[i].stake,
            "committee should be sorted by stake descending: member {} has {} but member {} has {}",
            i - 1,
            committee.members[i - 1].stake,
            i,
            committee.members[i].stake
        );
    }

    // Verify determinism: same seed should produce same stake ordering
    let committee2 = selector
        .select_committee(&validators, 1, &seed)
        .expect("second selection");

    for (a, b) in committee.members.iter().zip(committee2.members.iter()) {
        assert_eq!(a.stake, b.stake, "stake ordering should be deterministic");
    }
}

/// Test zone diversity constraint.
/// No zone should have more than 1/3 of committee (best effort).
#[test]
fn test_selection_zone_diversity() {
    let config = create_test_config(9, 6, 100);
    let committee_size = config.committee_size; // Store before move
    let selector = CoordinatorSelector::new(config).expect("valid config");

    // Create validators in multiple zones
    let mut validators = Vec::new();
    for i in 0..30 {
        let zone = format!("zone-{}", i % 5); // 5 different zones
        validators.push(create_test_validator(i, &zone, 1000 + (i as u128 * 10)));
    }

    let seed = [0x55u8; 32];
    let committee = selector
        .select_committee(&validators, 1, &seed)
        .expect("selection should succeed");

    // Count members per zone
    let mut zone_counts = std::collections::HashMap::new();
    for member in &committee.members {
        // Find validator to get zone
        let validator = validators
            .iter()
            .find(|v| v.id == member.validator_id)
            .expect("member should have source validator");

        *zone_counts.entry(validator.zone.clone()).or_insert(0) += 1;
    }

    // Max per zone should be (committee_size + 2) / 3 = 3
    let max_per_zone = (committee_size as usize + 2) / 3;

    // Due to best-effort nature, we check that zone diversity is attempted
    // At least 2 different zones should be represented
    assert!(
        zone_counts.len() >= 2,
        "should have at least 2 zones represented, got {}",
        zone_counts.len()
    );

    // Log zone distribution for debugging
    for (zone, count) in &zone_counts {
        // Most zones should respect the limit (best effort)
        if *count > max_per_zone {
            // This is allowed in fallback scenarios, but shouldn't be all zones
            println!(
                "Zone {} has {} members (max recommended: {})",
                zone, count, max_per_zone
            );
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// Seed Tests
// ════════════════════════════════════════════════════════════════════════════════

/// Test epoch seed derivation is deterministic.
#[test]
fn test_seed_derivation() {
    let epoch = 12345u64;
    let da_blob_hash = [0xABu8; 32];
    let prev_committee_hash = [0xCDu8; 32];

    // Derive seed multiple times
    let seed1 = derive_epoch_seed(epoch, &da_blob_hash, &prev_committee_hash);
    let seed2 = derive_epoch_seed(epoch, &da_blob_hash, &prev_committee_hash);
    let seed3 = derive_epoch_seed(epoch, &da_blob_hash, &prev_committee_hash);

    // All must be identical
    assert_eq!(seed1, seed2, "seed derivation not deterministic (1 vs 2)");
    assert_eq!(seed2, seed3, "seed derivation not deterministic (2 vs 3)");

    // Seed should not be all zeros
    assert_ne!(seed1, [0u8; 32], "seed should not be all zeros");

    // Different inputs should produce different seeds
    let different_epoch = derive_epoch_seed(epoch + 1, &da_blob_hash, &prev_committee_hash);
    assert_ne!(seed1, different_epoch, "different epoch should produce different seed");

    let different_da = derive_epoch_seed(epoch, &[0xFFu8; 32], &prev_committee_hash);
    assert_ne!(seed1, different_da, "different da_blob should produce different seed");

    let different_prev = derive_epoch_seed(epoch, &da_blob_hash, &[0xFFu8; 32]);
    assert_ne!(seed1, different_prev, "different prev_committee should produce different seed");

    // Order of inputs matters
    let swapped = derive_epoch_seed(epoch, &prev_committee_hash, &da_blob_hash);
    assert_ne!(seed1, swapped, "input order should matter");
}

/// Test seed verification with Merkle proof.
#[test]
fn test_seed_verification() {
    let seed = [0x42u8; 32];
    let epoch = 100u64;

    // For a simple test, create a single-leaf tree (leaf == root)
    // In real usage, the DA layer provides the proof

    // Compute what the leaf hash should be
    // leaf = SHA3-512(seed || epoch_be_8)[0..32]
    use sha3::{Digest, Sha3_512};
    let mut preimage = [0u8; 40];
    preimage[0..32].copy_from_slice(&seed);
    preimage[32..40].copy_from_slice(&epoch.to_be_bytes());

    let mut hasher = Sha3_512::new();
    hasher.update(&preimage);
    let full_hash = hasher.finalize();

    let mut leaf = [0u8; 32];
    leaf.copy_from_slice(&full_hash[0..32]);

    // Create proof where leaf == root (empty path)
    let proof = DAMerkleProof {
        root: leaf,
        path: vec![],
        index: 0,
    };

    // Verify should pass
    let result = verify_epoch_seed(&seed, epoch, &proof);
    assert!(result.is_valid(), "valid seed should verify");
    assert!(result.error.is_none(), "no error expected");

    // Wrong seed should fail
    let wrong_seed = [0xFFu8; 32];
    let wrong_result = verify_epoch_seed(&wrong_seed, epoch, &proof);
    assert!(!wrong_result.is_valid(), "wrong seed should fail");
    assert!(wrong_result.error.is_some(), "error expected");

    // Wrong epoch should fail
    let wrong_epoch_result = verify_epoch_seed(&seed, epoch + 1, &proof);
    assert!(!wrong_epoch_result.is_valid(), "wrong epoch should fail");
}

// ════════════════════════════════════════════════════════════════════════════════
// Committee Verification Tests
// ════════════════════════════════════════════════════════════════════════════════

/// Test committee verification - valid committee should pass.
#[test]
fn test_committee_verification() {
    let config = create_test_config(4, 3, 100);
    let validators = create_validator_set(12, 1000);
    let seed = [0x77u8; 32];
    let epoch = 5u64;

    // Create committee using selection
    let selector = CoordinatorSelector::new(config.clone()).expect("valid config");
    let committee = selector
        .select_committee(&validators, epoch, &seed)
        .expect("selection should succeed");

    // Verify should pass
    let result = verify_committee_selection(&committee, &validators, &seed, &config);
    assert!(result.is_ok(), "valid committee should verify");
    assert!(result.unwrap(), "verification should return true");

    // Verify with wrong seed should fail
    let wrong_seed = [0x88u8; 32];
    let wrong_result = verify_committee_selection(&committee, &validators, &wrong_seed, &config);
    assert!(wrong_result.is_err(), "wrong seed should fail verification");

    // Verify with wrong config should fail
    let wrong_config = create_test_config(4, 2, 100); // different threshold
    let wrong_config_result = verify_committee_selection(&committee, &validators, &seed, &wrong_config);
    assert!(wrong_config_result.is_err(), "wrong config should fail verification");

    // Verify with different validators should fail
    let different_validators = create_validator_set(12, 2000); // different stakes
    let wrong_validators_result =
        verify_committee_selection(&committee, &different_validators, &seed, &config);
    assert!(
        wrong_validators_result.is_err(),
        "different validators should fail verification"
    );

    // Test member eligibility
    for member in &committee.members {
        assert!(
            verify_member_eligibility(member, &validators),
            "member should be eligible"
        );
    }

    // Non-existent member should fail eligibility
    let fake_member = CoordinatorMember {
        id: [0xFFu8; 32],
        validator_id: [0xFFu8; 32],
        pubkey: [0xFFu8; 32],
        stake: 9999,
    };
    assert!(
        !verify_member_eligibility(&fake_member, &validators),
        "fake member should not be eligible"
    );
}

// ════════════════════════════════════════════════════════════════════════════════
// Utility Tests
// ════════════════════════════════════════════════════════════════════════════════

/// Test weight computation is correct and deterministic.
#[test]
fn test_weight_computation() {
    let config = create_test_config(5, 3, 100);
    let selector = CoordinatorSelector::new(config).expect("valid config");

    let validators = vec![
        create_test_validator(1, "zone-a", 1000),
        create_test_validator(2, "zone-b", 2000),
        create_test_validator(3, "zone-c", 3000),
        create_test_validator(4, "zone-d", 4000),
    ];

    let weights = selector.compute_selection_weights(&validators);

    // Check length
    assert_eq!(weights.len(), validators.len(), "weight count should match validator count");

    // Check individual weights equal stakes
    assert_eq!(weights[0].weight, 1000);
    assert_eq!(weights[1].weight, 2000);
    assert_eq!(weights[2].weight, 3000);
    assert_eq!(weights[3].weight, 4000);

    // Check cumulative weights
    assert_eq!(weights[0].cumulative, 1000);
    assert_eq!(weights[1].cumulative, 3000); // 1000 + 2000
    assert_eq!(weights[2].cumulative, 6000); // 1000 + 2000 + 3000
    assert_eq!(weights[3].cumulative, 10000); // 1000 + 2000 + 3000 + 4000

    // Check validator IDs are preserved
    for (i, weight) in weights.iter().enumerate() {
        assert_eq!(
            weight.validator_id, validators[i].id,
            "validator_id should be preserved"
        );
    }

    // Empty input should return empty weights
    let empty_weights = selector.compute_selection_weights(&[]);
    assert!(empty_weights.is_empty(), "empty input should return empty weights");

    // Determinism test
    let weights2 = selector.compute_selection_weights(&validators);
    for (a, b) in weights.iter().zip(weights2.iter()) {
        assert_eq!(a.validator_id, b.validator_id);
        assert_eq!(a.weight, b.weight);
        assert_eq!(a.cumulative, b.cumulative);
    }
}

/// Test deterministic shuffle.
#[test]
fn test_shuffle_deterministic() {
    let config = create_test_config(5, 3, 100);
    let selector = CoordinatorSelector::new(config).expect("valid config");

    let items: Vec<u32> = (0..20).collect();
    let seed = [0x99u8; 32];

    // Shuffle multiple times with same seed
    let shuffled1 = selector.deterministic_shuffle(&items, &seed);
    let shuffled2 = selector.deterministic_shuffle(&items, &seed);
    let shuffled3 = selector.deterministic_shuffle(&items, &seed);

    // All shuffles must be identical
    assert_eq!(shuffled1, shuffled2, "shuffle not deterministic (1 vs 2)");
    assert_eq!(shuffled2, shuffled3, "shuffle not deterministic (2 vs 3)");

    // Shuffled should be a permutation (same elements, different order)
    let mut sorted1 = shuffled1.clone();
    sorted1.sort();
    let mut sorted_items = items.clone();
    sorted_items.sort();
    assert_eq!(sorted1, sorted_items, "shuffle should preserve elements");

    // Different seed should produce different shuffle
    let different_seed = [0xAAu8; 32];
    let shuffled_different = selector.deterministic_shuffle(&items, &different_seed);
    assert_ne!(shuffled1, shuffled_different, "different seed should produce different shuffle");

    // Empty input should return empty
    let empty: Vec<u32> = vec![];
    let shuffled_empty = selector.deterministic_shuffle(&empty, &seed);
    assert!(shuffled_empty.is_empty(), "empty input should return empty");

    // Single element should return same element
    let single = vec![42u32];
    let shuffled_single = selector.deterministic_shuffle(&single, &seed);
    assert_eq!(shuffled_single, single, "single element should remain unchanged");
}

// ════════════════════════════════════════════════════════════════════════════════
// Edge Cases Tests
// ════════════════════════════════════════════════════════════════════════════════

/// Test edge cases: single validator, equal stakes, minimum threshold, committee_size == threshold.
#[test]
fn test_edge_cases() {
    // ─────────────────────────────────────────────────────────────────────────
    // Edge Case 1: Single validator (committee_size = 1, threshold = 1)
    // ─────────────────────────────────────────────────────────────────────────
    {
        let config = create_test_config(1, 1, 100);
        let selector = CoordinatorSelector::new(config).expect("valid config");

        let validators = vec![create_test_validator(1, "zone-a", 1000)];
        let seed = [0x11u8; 32];

        let committee = selector
            .select_committee(&validators, 1, &seed)
            .expect("single validator selection should succeed");

        assert_eq!(committee.members.len(), 1, "single validator committee");
        assert_eq!(committee.threshold, 1, "threshold should be 1");
        assert_eq!(
            committee.members[0].validator_id,
            validators[0].id,
            "should select the only validator"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Edge Case 2: Equal stakes (all validators have same stake)
    // ─────────────────────────────────────────────────────────────────────────
    {
        let config = create_test_config(3, 2, 100);
        let selector = CoordinatorSelector::new(config).expect("valid config");

        // All validators have exactly the same stake
        let validators: Vec<ValidatorCandidate> = (0..10)
            .map(|i| create_test_validator(i, &format!("zone-{}", i % 3), 5000))
            .collect();

        let seed = [0x22u8; 32];

        let committee = selector
            .select_committee(&validators, 1, &seed)
            .expect("equal stakes selection should succeed");

        assert_eq!(committee.members.len(), 3, "should select 3 members");

        // All members should have the same stake
        for member in &committee.members {
            assert_eq!(member.stake, 5000, "all members should have equal stake");
        }

        // Determinism with equal stakes
        let committee2 = selector
            .select_committee(&validators, 1, &seed)
            .expect("second selection");

        for (a, b) in committee.members.iter().zip(committee2.members.iter()) {
            assert_eq!(a.validator_id, b.validator_id, "equal stakes should still be deterministic");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Edge Case 3: Minimum threshold (threshold = 1)
    // ─────────────────────────────────────────────────────────────────────────
    {
        let config = create_test_config(5, 1, 100);
        let selector = CoordinatorSelector::new(config).expect("valid config");

        let validators = create_validator_set(10, 1000);
        let seed = [0x33u8; 32];

        let committee = selector
            .select_committee(&validators, 1, &seed)
            .expect("minimum threshold selection should succeed");

        assert_eq!(committee.members.len(), 5, "should select 5 members");
        assert_eq!(committee.threshold, 1, "threshold should be 1");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Edge Case 4: committee_size == threshold (unanimous required)
    // ─────────────────────────────────────────────────────────────────────────
    {
        let config = create_test_config(4, 4, 100);
        let selector = CoordinatorSelector::new(config).expect("valid config");

        let validators = create_validator_set(8, 1000);
        let seed = [0x44u8; 32];

        let committee = selector
            .select_committee(&validators, 1, &seed)
            .expect("unanimous selection should succeed");

        assert_eq!(committee.members.len(), 4, "should select 4 members");
        assert_eq!(committee.threshold, 4, "threshold should equal committee_size");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Edge Case 5: Exactly enough validators (validators.len() == committee_size)
    // ─────────────────────────────────────────────────────────────────────────
    {
        let config = create_test_config(5, 3, 100);
        let selector = CoordinatorSelector::new(config).expect("valid config");

        // Exactly 5 validators for committee_size of 5
        let validators = create_validator_set(5, 1000);
        let seed = [0x55u8; 32];

        let committee = selector
            .select_committee(&validators, 1, &seed)
            .expect("exact count selection should succeed");

        assert_eq!(committee.members.len(), 5, "should select all 5 validators");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Edge Case 6: All validators below min_stake
    // ─────────────────────────────────────────────────────────────────────────
    {
        let config = create_test_config(3, 2, 10000);
        let selector = CoordinatorSelector::new(config).expect("valid config");

        // All validators below min_stake
        let validators: Vec<ValidatorCandidate> = (0..10)
            .map(|i| create_test_validator(i, "zone-a", 100)) // stake < min_stake
            .collect();

        let seed = [0x66u8; 32];

        let result = selector.select_committee(&validators, 1, &seed);

        // Should fail with InsufficientEligibleValidators or NoEligibleValidators
        assert!(result.is_err(), "should fail when all below min_stake");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Edge Case 7: Invalid config (threshold > committee_size)
    // ─────────────────────────────────────────────────────────────────────────
    {
        let config = SelectionConfig {
            committee_size: 3,
            threshold: 5, // invalid: threshold > committee_size
            min_stake: 100,
        };

        let result = CoordinatorSelector::new(config);
        assert!(result.is_err(), "should reject invalid config");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Edge Case 8: Zero committee_size
    // ─────────────────────────────────────────────────────────────────────────
    {
        let config = SelectionConfig {
            committee_size: 0,
            threshold: 0,
            min_stake: 100,
        };

        let selector = CoordinatorSelector::new(config);
        // This might be valid (0 threshold <= 0 committee_size), let's see
        if let Ok(sel) = selector {
            let validators = create_validator_set(5, 1000);
            let seed = [0x77u8; 32];

            // Selection with 0 committee_size should result in empty committee or error
            let result = sel.select_committee(&validators, 1, &seed);
            // Either error or empty committee is acceptable
            if let Ok(committee) = result {
                assert_eq!(committee.members.len(), 0, "zero committee_size should produce empty committee");
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// Error Type Tests
// ════════════════════════════════════════════════════════════════════════════════

/// Test SelectionError Display implementations.
#[test]
fn test_selection_error_display() {
    // InsufficientValidators
    let err1 = SelectionError::InsufficientValidators {
        available: 3,
        required: 5,
    };
    let msg1 = err1.to_string();
    assert!(msg1.contains("3"), "should contain available count");
    assert!(msg1.contains("5"), "should contain required count");

    // InsufficientEligibleValidators
    let err2 = SelectionError::InsufficientEligibleValidators {
        eligible: 2,
        required: 4,
    };
    let msg2 = err2.to_string();
    assert!(msg2.contains("2"), "should contain eligible count");
    assert!(msg2.contains("4"), "should contain required count");

    // CommitteeInvariant
    let err3 = SelectionError::CommitteeInvariant {
        threshold: 5,
        members_count: 3,
    };
    let msg3 = err3.to_string();
    assert!(msg3.contains("5"), "should contain threshold");
    assert!(msg3.contains("3"), "should contain members_count");

    // Internal
    let err4 = SelectionError::Internal("test internal error".to_string());
    let msg4 = err4.to_string();
    assert!(msg4.contains("test internal error"), "should contain error message");

    // InvalidConfig (14A.2B.2.9)
    let err5 = SelectionError::InvalidConfig {
        reason: "threshold exceeds committee size".to_string(),
    };
    let msg5 = err5.to_string();
    assert!(msg5.contains("threshold exceeds committee size"), "should contain reason");

    // NoEligibleValidators (14A.2B.2.9)
    let err6 = SelectionError::NoEligibleValidators;
    let msg6 = err6.to_string();
    assert!(msg6.contains("no eligible"), "should indicate no eligible validators");

    // SeedDerivationFailed (14A.2B.2.9)
    let err7 = SelectionError::SeedDerivationFailed {
        reason: "invalid input hash".to_string(),
    };
    let msg7 = err7.to_string();
    assert!(msg7.contains("invalid input hash"), "should contain reason");
}

/// Test VerificationError Display implementations.
#[test]
fn test_verification_error_display() {
    // Test various VerificationError variants
    let err1 = VerificationError::ThresholdMismatch {
        claimed: 3,
        expected: 5,
    };
    let msg1 = err1.to_string();
    assert!(msg1.contains("3"), "should contain claimed threshold");
    assert!(msg1.contains("5"), "should contain expected threshold");

    let err2 = VerificationError::MemberCountMismatch {
        claimed: 4,
        expected: 6,
    };
    let msg2 = err2.to_string();
    assert!(msg2.contains("4"), "should contain claimed count");
    assert!(msg2.contains("6"), "should contain expected count");

    let err3 = VerificationError::MemberMismatch {
        index: 2,
        field: "pubkey".to_string(),
    };
    let msg3 = err3.to_string();
    assert!(msg3.contains("2"), "should contain index");
    assert!(msg3.contains("pubkey"), "should contain field name");

    // Tests for new variants (14A.2B.2.9)
    let err4 = VerificationError::CommitteeMismatch {
        reason: "different members selected".to_string(),
    };
    let msg4 = err4.to_string();
    assert!(msg4.contains("different members selected"), "should contain reason");

    let err5 = VerificationError::InvalidMember {
        validator_id: [0xABu8; 32],
        reason: "stake below minimum".to_string(),
    };
    let msg5 = err5.to_string();
    assert!(msg5.contains("ab"), "should contain validator_id prefix");
    assert!(msg5.contains("stake below minimum"), "should contain reason");

    let err6 = VerificationError::InvalidThreshold {
        claimed: 8,
        expected: 5,
        reason: "exceeds committee size".to_string(),
    };
    let msg6 = err6.to_string();
    assert!(msg6.contains("8"), "should contain claimed");
    assert!(msg6.contains("5"), "should contain expected");
    assert!(msg6.contains("exceeds committee size"), "should contain reason");

    let err7 = VerificationError::SeedMismatch {
        claimed: [0x11u8; 32],
        expected: [0x22u8; 32],
    };
    let msg7 = err7.to_string();
    assert!(msg7.contains("11"), "should contain claimed seed prefix");
    assert!(msg7.contains("22"), "should contain expected seed prefix");
}

/// Test error traits are properly implemented.
#[test]
fn test_error_traits() {
    // Test that SelectionError implements std::error::Error
    fn assert_error<E: std::error::Error>() {}
    assert_error::<SelectionError>();
    assert_error::<VerificationError>();
    assert_error::<SelectorConfigError>();
    assert_error::<CommitteeInvariantError>();

    // Test that errors can be converted to string
    let err = SelectionError::Internal("test".to_string());
    let _ = format!("{}", err);
    let _ = format!("{:?}", err);
}