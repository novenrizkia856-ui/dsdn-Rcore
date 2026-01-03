
//! Gas Calculation Unit Tests (13.9)
//!
//! Tests untuk memverifikasi gas calculation:
//! - Base op cost per transaction type
//! - Byte cost calculation
//! - Compute cycles cost
//! - Node multiplier effect

#[cfg(test)]
mod gas_tests {
    use crate::state::ChainState;
    use crate::state::internal_gas::{
        compute_gas_for_payload, GasBreakdown,
        BASE_OP_TRANSFER, BASE_OP_STORAGE_OP, BASE_OP_COMPUTE_OP,
        PER_BYTE_COST, PER_COMPUTE_CYCLE_COST, DEFAULT_NODE_COST_INDEX,
    };
    use crate::tx::{TxEnvelope, TxPayload, ResourceClass};
    use crate::types::Address;

    // Helper to create minimal TxEnvelope for testing
    fn create_test_envelope(payload: TxPayload) -> TxEnvelope {
        TxEnvelope {
            pubkey: vec![0u8; 32],
            signature: vec![0u8; 64],
            payload,
            cached_id: None,
            is_private: false,
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // TEST: Gas Calculation Components
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_gas_calculation_components() {
        let state = ChainState::new();
        let sender = Address::from_bytes([0x01u8; 20]);
        let recipient = Address::from_bytes([0x02u8; 20]);

        // Test Transfer payload
        let transfer_payload = TxPayload::Transfer {
            from: sender,
            to: recipient,
            amount: 1000,
            fee: 10,
            nonce: 1,
            gas_limit: 21000,
            resource_class: ResourceClass::Transfer,
            metadata_flagged: false,
        };
        let env = create_test_envelope(transfer_payload);
        let breakdown = compute_gas_for_payload(&env, None, &state);

        // Verify base_op_cost
        assert_eq!(breakdown.base_op_cost, BASE_OP_TRANSFER, 
                   "Transfer base_op_cost must be {}", BASE_OP_TRANSFER);

        // Verify data_cost is calculated (bytes * PER_BYTE_COST)
        assert!(breakdown.data_cost > 0, "data_cost must be > 0");

        // Verify compute_cost is 0 for non-compute tx
        assert_eq!(breakdown.compute_cost, 0, "Transfer compute_cost must be 0");

        // Verify default multiplier is applied
        assert_eq!(breakdown.node_multiplier, DEFAULT_NODE_COST_INDEX,
                   "Default multiplier must be {}", DEFAULT_NODE_COST_INDEX);

        // Verify total_gas_used calculation
        let expected_sum = breakdown.base_op_cost + breakdown.data_cost + breakdown.compute_cost;
        // With default multiplier 100, total = sum * 100 / 100 = sum
        // But ceiling division: (sum * 100 + 99) / 100
        let expected_total = ((expected_sum as u128 * 100 + 99) / 100) as u64;
        assert_eq!(breakdown.total_gas_used, expected_total);

        // Verify total_fee_cost
        assert_eq!(breakdown.total_fee_cost, breakdown.total_gas_used as u128);
    }

    #[test]
    fn test_gas_storage_op_base_cost() {
        let state = ChainState::new();
        let sender = Address::from_bytes([0x01u8; 20]);
        let storage_node = Address::from_bytes([0x02u8; 20]);

        let storage_payload = TxPayload::StorageOperationPayment {
            from: sender,
            to_node: storage_node,
            amount: 500,
            fee: 10,
            nonce: 1,
            operation_id: vec![0u8; 32],
            gas_limit: 50000,
            resource_class: ResourceClass::Storage,
            metadata_flagged: false,
        };
        let env = create_test_envelope(storage_payload);
        let breakdown = compute_gas_for_payload(&env, Some(storage_node), &state);

        assert_eq!(breakdown.base_op_cost, BASE_OP_STORAGE_OP,
                   "Storage base_op_cost must be {}", BASE_OP_STORAGE_OP);
    }

    #[test]
    fn test_gas_compute_op_base_cost() {
        let state = ChainState::new();
        let sender = Address::from_bytes([0x01u8; 20]);
        let compute_node = Address::from_bytes([0x02u8; 20]);

        let compute_payload = TxPayload::ComputeExecutionPayment {
            from: sender,
            to_node: compute_node,
            amount: 500,
            fee: 10,
            nonce: 1,
            execution_id: vec![0u8; 64], // 64 bytes for compute cycles
            gas_limit: 100000,
            resource_class: ResourceClass::Compute,
            metadata_flagged: false,
        };
        let env = create_test_envelope(compute_payload);
        let breakdown = compute_gas_for_payload(&env, Some(compute_node), &state);

        assert_eq!(breakdown.base_op_cost, BASE_OP_COMPUTE_OP,
                   "Compute base_op_cost must be {}", BASE_OP_COMPUTE_OP);

        // Compute cost = execution_id.len() * PER_COMPUTE_CYCLE_COST
        assert_eq!(breakdown.compute_cost, 64 * PER_COMPUTE_CYCLE_COST,
                   "Compute cost must equal execution_id.len() * PER_COMPUTE_CYCLE_COST");
    }

    // ════════════════════════════════════════════════════════════════════════════
    // TEST: Node Multiplier Effect
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_gas_node_multiplier_effect() {
        let mut state = ChainState::new();
        let sender = Address::from_bytes([0x01u8; 20]);
        let storage_node = Address::from_bytes([0x02u8; 20]);

        let storage_payload = TxPayload::StorageOperationPayment {
            from: sender,
            to_node: storage_node,
            amount: 500,
            fee: 10,
            nonce: 1,
            operation_id: vec![0u8; 16],
            gas_limit: 50000,
            resource_class: ResourceClass::Storage,
            metadata_flagged: false,
        };
        let env = create_test_envelope(storage_payload);

        // Test with default multiplier (100 = 1.0x)
        let breakdown_default = compute_gas_for_payload(&env, Some(storage_node), &state);
        let gas_default = breakdown_default.total_gas_used;

        // Set multiplier to 200 (2.0x)
        state.set_node_cost_index(storage_node, 200);
        let breakdown_2x = compute_gas_for_payload(&env, Some(storage_node), &state);
        let gas_2x = breakdown_2x.total_gas_used;

        // Gas with 2x multiplier must be approximately 2x the default
        // Allow for ceiling division variance
        assert!(gas_2x >= gas_default * 2 - 1 && gas_2x <= gas_default * 2 + 1,
                "Gas with 2x multiplier ({}) must be ~2x default ({})", gas_2x, gas_default);

        // Verify the multiplier is stored
        assert_eq!(breakdown_2x.node_multiplier, 200);

        // Set multiplier to 50 (0.5x)
        state.set_node_cost_index(storage_node, 50);
        let breakdown_half = compute_gas_for_payload(&env, Some(storage_node), &state);
        let gas_half = breakdown_half.total_gas_used;

        // Gas with 0.5x multiplier must be approximately half
        assert!(gas_half >= gas_default / 2 - 1 && gas_half <= gas_default / 2 + 1,
                "Gas with 0.5x multiplier ({}) must be ~0.5x default ({})", gas_half, gas_default);
    }

    #[test]
    fn test_gas_multiplier_with_no_service_node() {
        let mut state = ChainState::new();
        let sender = Address::from_bytes([0x01u8; 20]);
        let recipient = Address::from_bytes([0x02u8; 20]);

        // Transfer has no service node
        let transfer_payload = TxPayload::Transfer {
            from: sender,
            to: recipient,
            amount: 1000,
            fee: 10,
            nonce: 1,
            gas_limit: 21000,
            resource_class: ResourceClass::Transfer,
            metadata_flagged: false,
        };
        let env = create_test_envelope(transfer_payload);

        // Even if we set a multiplier for some address, Transfer doesn't use it
        state.set_node_cost_index(recipient, 300);
        
        let breakdown = compute_gas_for_payload(&env, None, &state);
        
        // Default multiplier must be used when service_node is None
        assert_eq!(breakdown.node_multiplier, DEFAULT_NODE_COST_INDEX);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // TEST: Byte Cost Calculation
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_gas_byte_cost_calculation() {
        let state = ChainState::new();
        let sender = Address::from_bytes([0x01u8; 20]);
        let storage_node = Address::from_bytes([0x02u8; 20]);

        // Create payloads with different operation_id sizes
        let create_payload = |op_id_size: usize| {
            TxPayload::StorageOperationPayment {
                from: sender,
                to_node: storage_node,
                amount: 500,
                fee: 10,
                nonce: 1,
                operation_id: vec![0u8; op_id_size],
                gas_limit: 50000,
                resource_class: ResourceClass::Storage,
                metadata_flagged: false,
            }
        };

        let env_small = create_test_envelope(create_payload(16));
        let env_large = create_test_envelope(create_payload(256));

        let breakdown_small = compute_gas_for_payload(&env_small, Some(storage_node), &state);
        let breakdown_large = compute_gas_for_payload(&env_large, Some(storage_node), &state);

        // Larger payload must have higher data_cost
        assert!(breakdown_large.data_cost > breakdown_small.data_cost,
                "Larger payload must have higher data_cost");

        // Difference must be approximately (256-16) * PER_BYTE_COST
        let data_diff = breakdown_large.data_cost - breakdown_small.data_cost;
        let expected_diff = (256 - 16) as u64 * PER_BYTE_COST;
        // Allow some variance due to bincode serialization overhead
        assert!(data_diff >= expected_diff - 100 && data_diff <= expected_diff + 100,
                "Data cost difference {} must be close to expected {}", data_diff, expected_diff);
    }
}