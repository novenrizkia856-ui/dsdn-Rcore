//! Fee Split Unit Tests (13.9)
//!
//! Tests untuk memverifikasi fee split calculation sesuai blueprint:
//! - Storage/Compute: Node 70%, Validator 20%, Treasury 10%
//! - Transfer/Governance: Validator 100%
//! - Anti-self-dealing node: node_share → treasury

#[cfg(test)]
mod fee_split_tests {
    use crate::tokenomics::{calculate_fee_by_resource_class, FeeSplit};
    use crate::tx::ResourceClass;
    use crate::types::Address;

    // ════════════════════════════════════════════════════════════════════════════
    // TEST: Fee Split Storage/Compute Basic (Blueprint 70/20/10)
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_fee_split_storage_compute_basic() {
        let sender = Address::from_bytes([0x01u8; 20]);
        let service_node = Address::from_bytes([0x02u8; 20]); // Different from sender

        // Test case 1: total_fee = 100
        {
            let split = calculate_fee_by_resource_class(
                100,
                &ResourceClass::Storage,
                Some(service_node),
                &sender,
            );
            assert_eq!(split.node_share, 70, "node_share must be 70% of 100");
            assert_eq!(split.validator_share, 20, "validator_share must be 20% of 100");
            assert_eq!(split.treasury_share, 10, "treasury_share must be 10% of 100");
            assert_eq!(split.total(), 100, "total must equal input fee");
        }

        // Test case 2: total_fee = 12345
        {
            let split = calculate_fee_by_resource_class(
                12345,
                &ResourceClass::Compute,
                Some(service_node),
                &sender,
            );
            let expected_node = 12345 * 70 / 100;      // 8641
            let expected_val = 12345 * 20 / 100;       // 2469
            let expected_tre = 12345 - expected_node - expected_val; // 1235
            
            assert_eq!(split.node_share, expected_node);
            assert_eq!(split.validator_share, expected_val);
            assert_eq!(split.treasury_share, expected_tre);
            assert_eq!(split.total(), 12345);
        }

        // Test case 3: total_fee = 1_000_000_000 (10^9)
        {
            let split = calculate_fee_by_resource_class(
                1_000_000_000,
                &ResourceClass::Storage,
                Some(service_node),
                &sender,
            );
            let expected_node = 1_000_000_000 * 70 / 100;  // 700_000_000
            let expected_val = 1_000_000_000 * 20 / 100;   // 200_000_000
            let expected_tre = 1_000_000_000 - expected_node - expected_val; // 100_000_000
            
            assert_eq!(split.node_share, expected_node);
            assert_eq!(split.validator_share, expected_val);
            assert_eq!(split.treasury_share, expected_tre);
            assert_eq!(split.total(), 1_000_000_000);
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // TEST: Fee Split Transfer/Governance (100% Validator)
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_fee_split_transfer_stake_governance() {
        let sender = Address::from_bytes([0x01u8; 20]);

        // Test Transfer: 100% to validator
        {
            let split = calculate_fee_by_resource_class(
                1000,
                &ResourceClass::Transfer,
                None,
                &sender,
            );
            assert_eq!(split.node_share, 0, "Transfer: node_share must be 0");
            assert_eq!(split.validator_share, 1000, "Transfer: validator_share must be 100%");
            assert_eq!(split.treasury_share, 0, "Transfer: treasury_share must be 0");
            assert_eq!(split.total(), 1000);
        }

        // Test Governance: 100% to validator (per blueprint)
        {
            let split = calculate_fee_by_resource_class(
                5000,
                &ResourceClass::Governance,
                None,
                &sender,
            );
            assert_eq!(split.node_share, 0, "Governance: node_share must be 0");
            assert_eq!(split.validator_share, 5000, "Governance: validator_share must be 100%");
            assert_eq!(split.treasury_share, 0, "Governance: treasury_share must be 0");
            assert_eq!(split.total(), 5000);
        }

        // Test dengan berbagai nilai
        for total_fee in [100u128, 999, 10000, 123456789] {
            let split_transfer = calculate_fee_by_resource_class(
                total_fee,
                &ResourceClass::Transfer,
                None,
                &sender,
            );
            assert_eq!(split_transfer.validator_share, total_fee);
            assert_eq!(split_transfer.node_share, 0);
            assert_eq!(split_transfer.treasury_share, 0);
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // TEST: Anti-Self-Dealing Node Rule
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_fee_split_anti_self_dealing_node() {
        // service_node == sender → node_share redirected to treasury
        let sender = Address::from_bytes([0x01u8; 20]);
        let service_node = Address::from_bytes([0x01u8; 20]); // Same as sender!

        // Test Storage with self-dealing
        {
            let split = calculate_fee_by_resource_class(
                1000,
                &ResourceClass::Storage,
                Some(service_node),
                &sender,
            );
            
            // Anti-self-dealing: node_share (70%) goes to treasury
            assert_eq!(split.node_share, 0, "Self-dealing: node_share must be 0");
            assert_eq!(split.validator_share, 200, "Self-dealing: validator_share unchanged at 20%");
            assert_eq!(split.treasury_share, 800, "Self-dealing: treasury gets 70% + 10% = 80%");
            assert_eq!(split.total(), 1000);
        }

        // Test Compute with self-dealing
        {
            let split = calculate_fee_by_resource_class(
                10000,
                &ResourceClass::Compute,
                Some(service_node),
                &sender,
            );
            
            // Expected: node=0, validator=2000 (20%), treasury=8000 (70%+10%)
            assert_eq!(split.node_share, 0);
            assert_eq!(split.validator_share, 2000);
            assert_eq!(split.treasury_share, 8000);
            assert_eq!(split.total(), 10000);
        }

        // Compare with normal case (different sender)
        {
            let different_sender = Address::from_bytes([0x99u8; 20]);
            let split_normal = calculate_fee_by_resource_class(
                1000,
                &ResourceClass::Storage,
                Some(service_node),
                &different_sender,
            );
            
            // Normal case: 70/20/10
            assert_eq!(split_normal.node_share, 700);
            assert_eq!(split_normal.validator_share, 200);
            assert_eq!(split_normal.treasury_share, 100);
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // TEST: Edge Cases
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_fee_split_edge_cases() {
        let sender = Address::from_bytes([0x01u8; 20]);
        let service_node = Address::from_bytes([0x02u8; 20]);

        // Zero fee
        {
            let split = calculate_fee_by_resource_class(
                0,
                &ResourceClass::Storage,
                Some(service_node),
                &sender,
            );
            assert_eq!(split.node_share, 0);
            assert_eq!(split.validator_share, 0);
            assert_eq!(split.treasury_share, 0);
            assert_eq!(split.total(), 0);
        }

        // Very small fee (rounding test)
        {
            let split = calculate_fee_by_resource_class(
                1,
                &ResourceClass::Storage,
                Some(service_node),
                &sender,
            );
            // 1 * 70 / 100 = 0, 1 * 20 / 100 = 0, treasury = 1 - 0 - 0 = 1
            assert_eq!(split.total(), 1);
        }

        // Fee = 3 (test rounding)
        {
            let split = calculate_fee_by_resource_class(
                3,
                &ResourceClass::Storage,
                Some(service_node),
                &sender,
            );
            // 3 * 70 / 100 = 2, 3 * 20 / 100 = 0, treasury = 3 - 2 - 0 = 1
            assert_eq!(split.node_share, 2);
            assert_eq!(split.validator_share, 0);
            assert_eq!(split.treasury_share, 1);
            assert_eq!(split.total(), 3);
        }
    }
}