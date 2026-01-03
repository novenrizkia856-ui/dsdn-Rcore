//! Integration Tests for Fee Allocation (13.9)
//!
//! Tests untuk memverifikasi alokasi fee end-to-end:
//! - apply_payload dengan Storage/Compute tx
//! - Anti-self-dealing node
//! - State root deterministik dengan node_cost_index

#[cfg(test)]
mod fee_allocation_tests {
    use crate::state::ChainState;
    use crate::tx::{TxEnvelope, TxPayload, ResourceClass};
    use crate::types::Address;
    use crate::crypto::{sign_ed25519, Ed25519PrivateKey};

    // Helper to create signed TxEnvelope
    fn create_signed_envelope(payload: TxPayload, priv_key: &Ed25519PrivateKey) -> TxEnvelope {
        let payload_bytes = bincode::serialize(&payload).unwrap();
        let signature = sign_ed25519(priv_key, &payload_bytes).unwrap();
        
        TxEnvelope {
            pubkey: priv_key.public_key().as_bytes().to_vec(),
            signature,
            payload,
            cached_id: None,
            is_private: false,
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // TEST: apply_payload Storage Allocates Fees (70/20/10)
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_apply_payload_storage_allocates_fees() {
        let mut state = ChainState::new();

        // Setup addresses
        let sender = Address::from_bytes([0x01u8; 20]);
        let service_node = Address::from_bytes([0x02u8; 20]);
        let proposer = Address::from_bytes([0x03u8; 20]);

        // Fund sender
        state.create_account(sender);
        state.create_account(service_node);
        state.create_account(proposer);
        *state.balances.get_mut(&sender).unwrap() = 1_000_000;

        // Create Storage payment payload
        let fee: u128 = 1000;
        let amount: u128 = 500;
        let payload = TxPayload::StorageOperationPayment {
            from: sender,
            to_node: service_node,
            amount,
            fee,
            nonce: 1,
            operation_id: b"test_op_123".to_vec(),
            gas_limit: 50000,
            resource_class: ResourceClass::Storage,
            metadata_flagged: false,
        };

        // Create unsigned envelope for apply_payload
        let env = TxEnvelope {
            pubkey: vec![0u8; 32],
            signature: vec![0u8; 64],
            payload,
            cached_id: None,
            is_private: false,
        };

        // Record balances before
        let sender_before = state.get_balance(&sender);
        let node_before = state.get_balance(&service_node);
        let proposer_before = state.get_balance(&proposer);
        let treasury_before = state.treasury_balance;

        // Execute apply_payload
        let result = state.apply_payload(&env, &proposer);
        assert!(result.is_ok(), "apply_payload must succeed");

        let (gas_used, events) = result.unwrap();
        let gas_cost = gas_used as u128;
        let total_fee = fee + gas_cost;

        // Calculate expected split (70/20/10)
        let expected_node = total_fee * 70 / 100;
        let expected_validator = total_fee * 20 / 100;
        let expected_treasury = total_fee - expected_node - expected_validator;

        // Assert sender deducted total_fee + gas + amount
        let sender_after = state.get_balance(&sender);
        let total_deduct = amount + fee + gas_cost;
        assert_eq!(sender_before - sender_after, total_deduct,
                   "Sender must be deducted amount + fee + gas_cost");

        // Assert service_node receives 70% + amount
        let node_after = state.get_balance(&service_node);
        assert_eq!(node_after - node_before, expected_node + amount,
                   "Service node must receive 70% fee + payment amount");

        // Assert proposer receives 20%
        let proposer_after = state.get_balance(&proposer);
        assert_eq!(proposer_after - proposer_before, expected_validator,
                   "Proposer must receive 20% of total fee");

        // Assert treasury receives 10%
        let treasury_after = state.treasury_balance;
        assert_eq!(treasury_after - treasury_before, expected_treasury,
                   "Treasury must receive 10% of total fee");

        // Verify total fee distribution equals total_fee
        let total_distributed = (node_after - node_before - amount) + 
                                (proposer_after - proposer_before) + 
                                (treasury_after - treasury_before);
        assert_eq!(total_distributed, total_fee,
                   "Total distributed must equal total_fee");
    }

    // ════════════════════════════════════════════════════════════════════════════
    // TEST: apply_payload Compute Anti-Self-Dealing
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_apply_payload_compute_anti_self_dealing() {
        let mut state = ChainState::new();

        // Setup: service_node == sender (self-dealing)
        let sender = Address::from_bytes([0x01u8; 20]);
        let service_node = sender; // Same as sender!
        let proposer = Address::from_bytes([0x03u8; 20]);

        // Fund sender
        state.create_account(sender);
        state.create_account(proposer);
        *state.balances.get_mut(&sender).unwrap() = 1_000_000;

        // Create Compute payment payload
        let fee: u128 = 1000;
        let amount: u128 = 500;
        let payload = TxPayload::ComputeExecutionPayment {
            from: sender,
            to_node: service_node,
            amount,
            fee,
            nonce: 1,
            execution_id: b"exec_456".to_vec(),
            gas_limit: 100000,
            resource_class: ResourceClass::Compute,
            metadata_flagged: false,
        };

        let env = TxEnvelope {
            pubkey: vec![0u8; 32],
            signature: vec![0u8; 64],
            payload,
            cached_id: None,
            is_private: false,
        };

        // Record balances before
        let sender_before = state.get_balance(&sender);
        let proposer_before = state.get_balance(&proposer);
        let treasury_before = state.treasury_balance;

        // Execute apply_payload
        let result = state.apply_payload(&env, &proposer);
        assert!(result.is_ok(), "apply_payload must succeed");

        let (gas_used, _events) = result.unwrap();
        let gas_cost = gas_used as u128;
        let total_fee = fee + gas_cost;

        // Anti-self-dealing: node_share (70%) → treasury
        // Expected split: node=0, validator=20%, treasury=80%
        let expected_validator = total_fee * 20 / 100;
        let expected_treasury = total_fee - expected_validator; // 80%

        // Assert sender deducted correctly
        let sender_after = state.get_balance(&sender);
        let total_deduct = amount + fee + gas_cost;
        // sender also receives the payment amount (to themselves)
        assert_eq!(sender_before - sender_after, total_deduct - amount,
                   "Sender deduction must account for self-payment");

        // Assert proposer receives 20%
        let proposer_after = state.get_balance(&proposer);
        assert_eq!(proposer_after - proposer_before, expected_validator,
                   "Proposer must receive 20% (anti-self-dealing doesn't affect validator)");

        // Assert treasury receives 70% + 10% = 80%
        let treasury_after = state.treasury_balance;
        assert_eq!(treasury_after - treasury_before, expected_treasury,
                   "Treasury must receive 80% (70% redirected from node + 10% base)");
    }

    // ════════════════════════════════════════════════════════════════════════════
    // TEST: State Root Changes with node_cost_index
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_state_root_includes_node_cost_index() {
        let mut state = ChainState::new();
        let node_addr = Address::from_bytes([0x01u8; 20]);

        // Compute initial state root
        let hash1 = state.compute_state_root().unwrap();

        // Set node_cost_index[addr] = 150
        state.set_node_cost_index(node_addr, 150);

        // Compute state root after change
        let hash2 = state.compute_state_root().unwrap();

        // Hash must be different
        assert_ne!(hash1, hash2, 
                   "State root must change when node_cost_index changes");

        // Change multiplier to different value
        state.set_node_cost_index(node_addr, 200);
        let hash3 = state.compute_state_root().unwrap();

        assert_ne!(hash2, hash3,
                   "State root must change when multiplier value changes");

        // Remove node_cost_index
        state.remove_node_cost_index(&node_addr);
        let hash4 = state.compute_state_root().unwrap();

        assert_ne!(hash3, hash4,
                   "State root must change when node_cost_index is removed");

        // Hash should return to original (empty state)
        assert_eq!(hash1, hash4,
                   "State root must return to original when node_cost_index is removed");
    }

    #[test]
    fn test_state_root_includes_node_earnings() {
        let mut state = ChainState::new();
        let node_addr = Address::from_bytes([0x01u8; 20]);

        // Compute initial state root
        let hash1 = state.compute_state_root().unwrap();

        // Credit earnings to node
        state.credit_node_earning(node_addr, 1000);

        // Compute state root after change
        let hash2 = state.compute_state_root().unwrap();

        // Hash must be different
        assert_ne!(hash1, hash2,
                   "State root must change when node_earnings changes");

        // Credit more earnings
        state.credit_node_earning(node_addr, 500);
        let hash3 = state.compute_state_root().unwrap();

        assert_ne!(hash2, hash3,
                   "State root must change when earnings increase");

        // Claim all earnings
        let claimed = state.claim_node_earning(node_addr);
        assert_eq!(claimed, 1500);
        
        let hash4 = state.compute_state_root().unwrap();
        assert_ne!(hash3, hash4,
                   "State root must change when earnings are claimed");

        // Hash should return to original (empty earnings)
        assert_eq!(hash1, hash4,
                   "State root must return to original when earnings are fully claimed");
    }

    #[test]
    fn test_state_root_deterministic_ordering() {
        // Test that state root is deterministic regardless of insertion order
        let mut state1 = ChainState::new();
        let mut state2 = ChainState::new();

        let addr_a = Address::from_bytes([0x01u8; 20]);
        let addr_b = Address::from_bytes([0x02u8; 20]);
        let addr_c = Address::from_bytes([0x03u8; 20]);

        // State 1: Insert in order A, B, C
        state1.set_node_cost_index(addr_a, 100);
        state1.set_node_cost_index(addr_b, 150);
        state1.set_node_cost_index(addr_c, 200);

        // State 2: Insert in reverse order C, B, A
        state2.set_node_cost_index(addr_c, 200);
        state2.set_node_cost_index(addr_b, 150);
        state2.set_node_cost_index(addr_a, 100);

        let hash1 = state1.compute_state_root().unwrap();
        let hash2 = state2.compute_state_root().unwrap();

        assert_eq!(hash1, hash2,
                   "State root must be deterministic regardless of insertion order");
    }
}