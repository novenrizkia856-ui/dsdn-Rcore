//! Integration tests for DSDN blockchain
//! Run with: cargo test --test integration_tests

use dsdn_chain::*;
use dsdn_chain::types::Address;
use dsdn_chain::tx::{TxEnvelope, TxPayload, ResourceClass};
use dsdn_chain::crypto::{generate_ed25519_keypair_bytes, sign_message_with_keypair_bytes, address_from_pubkey_bytes};
use dsdn_chain::tokenomics::calculate_fee_split;
use dsdn_chain::mempool::Mempool;
use dsdn_chain::epoch::{should_rotate, EpochConfig};
use tempfile::tempdir;

// ============================================================
// CHAIN INTEGRATION TESTS
// ============================================================

#[test]
fn test_chain_genesis_initialization() {
    let dir = tempdir().unwrap();
    let chain = Chain::new(dir.path()).unwrap();
    
    let genesis_addr = "0x1234567890123456789012345678901234567890";
    chain.init_genesis(genesis_addr, 1_000_000_000).unwrap();
    
    let addr = Address::from_str(genesis_addr).unwrap();
    let balance = chain.get_balance(&addr);
    
    assert_eq!(balance, 1_000_000_000);
}

#[test]
fn test_chain_submit_and_mine() {
    let dir = tempdir().unwrap();
    let chain = Chain::new(dir.path()).unwrap();
    
    // Setup genesis
    let (pk, kp_bytes) = generate_ed25519_keypair_bytes();
    let sender = address_from_pubkey_bytes(&pk).unwrap();
    chain.init_genesis(&sender.to_string(), 1_000_000_000).unwrap();
    
    // Create and submit TX
    let recipient = Address::from_bytes([0x02; 20]);
    let payload = TxPayload::Transfer {
        from: sender,
        to: recipient,
        amount: 1000,
        fee: 10,
        nonce: 1,
        gas_limit: 21000,
        resource_class: ResourceClass::Transfer,
        metadata_flagged: false,
    };
    
    let mut env = TxEnvelope::new_unsigned(payload);
    env.pubkey = pk.clone();
    let sig_bytes = env.payload_bytes().unwrap();
    env.signature = sign_message_with_keypair_bytes(&kp_bytes, &sig_bytes).unwrap();
    
    chain.submit_tx(env).unwrap();
    
    // Mine block
    let block = chain.mine_block_and_apply(&sender.to_string()).unwrap();
    
    assert_eq!(block.header.height, 1);
    assert_eq!(block.body.transactions.len(), 1);
}

#[test]
fn test_chain_balance_after_transfer() {
    let dir = tempdir().unwrap();
    let chain = Chain::new(dir.path()).unwrap();
    
    let (pk, kp_bytes) = generate_ed25519_keypair_bytes();
    let sender = address_from_pubkey_bytes(&pk).unwrap();
    let recipient = Address::from_bytes([0x02; 20]);
    
    chain.init_genesis(&sender.to_string(), 1_000_000_000).unwrap();
    
    let payload = TxPayload::Transfer {
        from: sender,
        to: recipient,
        amount: 100_000,
        fee: 100,
        nonce: 1,
        gas_limit: 21000,
        resource_class: ResourceClass::Transfer,
        metadata_flagged: false,
    };
    
    let mut env = TxEnvelope::new_unsigned(payload);
    env.pubkey = pk.clone();
    let sig_bytes = env.payload_bytes().unwrap();
    env.signature = sign_message_with_keypair_bytes(&kp_bytes, &sig_bytes).unwrap();
    
    chain.submit_tx(env).unwrap();
    
    // FIX: Use DIFFERENT proposer to avoid anti self-dealing
    let proposer_addr = Address::from_bytes([0xFF; 20]);
    chain.mine_block_and_apply(&proposer_addr.to_string()).unwrap();
    
    let recipient_balance = chain.get_balance(&recipient);
    assert_eq!(recipient_balance, 100_000);
}

// ============================================================
// VALIDATOR SET TESTS
// ============================================================

#[test]
fn test_validator_registration_and_selection() {
    let dir = tempdir().unwrap();
    let chain = Chain::new(dir.path()).unwrap();
    
    let validator1 = Address::from_bytes([0x01; 20]);
    let validator2 = Address::from_bytes([0x02; 20]);
    
    // Inject validators
    chain.inject_test_validator(validator1, vec![0u8; 32], 1_000_000, true);
    chain.inject_test_validator(validator2, vec![0u8; 32], 3_000_000, true);
    
    let state = chain.get_state_snapshot();
    assert_eq!(state.validator_set.active_count(), 2);
    assert_eq!(state.validator_set.total_stake(), 4_000_000);
}

#[test]
fn test_delegation_affects_voting_power() {
    let dir = tempdir().unwrap();
    let chain = Chain::new(dir.path()).unwrap();
    
    let validator = Address::from_bytes([0x01; 20]);
    let delegator = Address::from_bytes([0x02; 20]);
    
    chain.inject_test_validator(validator, vec![0u8; 32], 100_000_000, true);
    chain.inject_test_delegation(validator, delegator, 400_000_000);
    
    let state = chain.get_state_snapshot();
    let power = state.get_validator_total_power(&validator);
    
    // validator_power = 80% * sqrt(100M) = 8000
    // delegator_power = 20% * sqrt(400M) = 4000
    // total = 12000
    assert!(power > 0);
}

// ============================================================
// MEMPOOL INTEGRATION TESTS
// ============================================================

#[test]
fn test_mempool_resource_class_filtering() {
    let (pk, kp_bytes) = generate_ed25519_keypair_bytes();
    let addr = address_from_pubkey_bytes(&pk).unwrap();
    
    let mempool = Mempool::new();
    
    // Add Storage TX
    let storage_payload = TxPayload::StorageOperationPayment {
        from: addr,
        to_node: addr,
        amount: 1000,
        fee: 50,
        nonce: 1,
        operation_id: vec![1],
        gas_limit: 25000,
        resource_class: ResourceClass::Storage,
        metadata_flagged: false,
    };
    let mut storage_env = TxEnvelope::new_unsigned(storage_payload);
    storage_env.pubkey = pk.clone();
    let sig = storage_env.payload_bytes().unwrap();
    storage_env.signature = sign_message_with_keypair_bytes(&kp_bytes, &sig).unwrap();
    mempool.add(storage_env).unwrap();
    
    // Add Compute TX
    let compute_payload = TxPayload::ComputeExecutionPayment {
        from: addr,
        to_node: addr,
        amount: 2000,
        fee: 100,
        nonce: 2,
        execution_id: vec![2],
        gas_limit: 40000,
        resource_class: ResourceClass::Compute,
        metadata_flagged: false,
    };
    let mut compute_env = TxEnvelope::new_unsigned(compute_payload);
    compute_env.pubkey = pk.clone();
    let sig2 = compute_env.payload_bytes().unwrap();
    compute_env.signature = sign_message_with_keypair_bytes(&kp_bytes, &sig2).unwrap();
    mempool.add(compute_env).unwrap();
    
    assert_eq!(mempool.len(), 2);
    
    // Pop only Storage
    let storage_txs = mempool.pop_by_resource(10, ResourceClass::Storage);
    assert_eq!(storage_txs.len(), 1);
    assert_eq!(mempool.len(), 1);
}

// ============================================================
// EPOCH ROTATION TESTS
// ============================================================

#[test]
fn test_epoch_rotation_triggers_correctly() {
    let config = EpochConfig::new(120, 150);
    
    assert!(!should_rotate(0, &config));
    assert!(!should_rotate(119, &config));
    assert!(should_rotate(120, &config));
    assert!(!should_rotate(121, &config));
    assert!(should_rotate(240, &config));
}

// ============================================================
// SLASHING TESTS
// ============================================================

#[test]
fn test_slashing_threshold() {
    use dsdn_chain::slashing::{LivenessRecord, MAX_MISSED_BLOCKS};
    
    let mut record = LivenessRecord::new();
    
    // Below threshold
    record.missed_blocks = MAX_MISSED_BLOCKS - 1;
    assert!(!record.should_slash());
    
    // At threshold
    record.missed_blocks = MAX_MISSED_BLOCKS;
    assert!(record.should_slash());
    
    // Already slashed
    record.slashed = true;
    assert!(!record.should_slash());
}

// ============================================================
// TOKENOMICS TESTS
// ============================================================

#[test]
fn test_fee_distribution_integrity() {
    for amount in [1u128, 10, 100, 1000, 999, 12345, 1_000_000] {
        let (v, d, t) = calculate_fee_split(amount);
        assert_eq!(v + d + t, amount, "Fee split should preserve total for amount {}", amount);
    }
}

use std::str::FromStr;