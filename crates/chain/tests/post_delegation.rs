//! PoS Delegation Integration Tests (13.8.K)
//!
//! Focused test suite for:
//! - Validator staking with minimum requirements
//! - Delegator staking rules
//! - QV weight calculations
//! - Reward cap enforcement
//! - Unstake delay mechanism
//! - State persistence across restarts

#[cfg(test)]
use dsdn_chain::types::Address;
use dsdn_chain::state::{
    ChainState,
    ValidatorInfo,
    UNSTAKE_DELAY_SECONDS,
};


    // ════════════════════════════════════════════════════════════
    // HELPER FUNCTIONS
    // ════════════════════════════════════════════════════════════

    /// Create a new test chain state
    fn new_test_chain() -> ChainState {
        ChainState::new()
    }

    /// Create and register a validator with given stake
    fn setup_validator(state: &mut ChainState, seed: u8, stake: u128) -> Address {
        let addr = Address::from_bytes([seed; 20]);
        state.create_account(addr);
        state.mint(&addr, stake * 2).unwrap(); // Double for flexibility
        
        let info = ValidatorInfo::new(addr, vec![seed; 32], stake, Some(format!("Validator{}", seed)));
        state.validator_set.add_validator(info);
        state.validator_stakes.insert(addr, stake);
        state.locked.insert(addr, stake);
        
        addr
    }

    /// Create and register a delegator with given stake to validator
    #[allow(dead_code)]
    fn setup_delegator(
        state: &mut ChainState, 
        seed: u8, 
        validator: &Address, 
        stake: u128
    ) -> Result<Address, String> {
        let addr = Address::from_bytes([seed; 20]);
        state.create_account(addr);
        state.mint(&addr, stake * 2).unwrap();
        
        match state.register_delegator_stake(&addr, validator, stake) {
            Ok(_) => Ok(addr),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Simulate block production by advancing timestamps
    #[allow(dead_code)]
    fn advance_blocks(current_ts: u64, blocks: u64) -> u64 {
        // 1 block = 6 hours = 21600 seconds
        const BLOCK_TIME: u64 = 21600;
        current_ts + (blocks * BLOCK_TIME)
    }

    /// Get QV weight for an address
    fn get_qv_weight(state: &ChainState, addr: &Address) -> u128 {
        state.get_qv_weight(addr)
    }

    /// Get validator combined weight
    fn get_validator_weight(state: &ChainState, validator: &Address) -> u128 {
        state.get_validator_qv_weight(validator)
    }

    // ════════════════════════════════════════════════════════════
    // VALIDATOR STAKING TESTS
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_validator_minimum_stake_50k() {
        let mut state = new_test_chain();
        let addr = Address::from_bytes([0x01; 20]);
        
        state.create_account(addr);
        state.mint(&addr, 100_000).unwrap();
        
        let info = ValidatorInfo::new(addr, vec![0u8; 32], 0, None);
        state.validator_set.add_validator(info);
        
        // Below minimum should fail
        let result_low = state.deposit_validator_stake(&addr, 49_999);
        assert!(result_low.is_err(), "Should reject stake < 50,000");
        
        // At minimum should succeed
        let result_ok = state.deposit_validator_stake(&addr, 50_000);
        assert!(result_ok.is_ok(), "Should accept stake >= 50,000");
        assert_eq!(state.get_validator_stake(&addr), 50_000);
    }

    #[test]
    fn test_validator_active_after_stake() {
        let mut state = new_test_chain();
        let validator = setup_validator(&mut state, 0x01, 50_000);
        
        let is_active = state.validator_set.get(&validator)
            .map(|v| v.active)
            .unwrap_or(false);
        
        assert!(is_active, "Validator should be active after staking");
    }

    // ════════════════════════════════════════════════════════════
    // DELEGATOR STAKING TESTS
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_delegator_minimum_stake_100k() {
        let mut state = new_test_chain();
        let validator = setup_validator(&mut state, 0x01, 50_000);
        
        let delegator = Address::from_bytes([0x02; 20]);
        state.create_account(delegator);
        state.mint(&delegator, 200_000).unwrap();
        
        // Below minimum should fail
        let result_low = state.register_delegator_stake(&delegator, &validator, 99_999);
        assert!(result_low.is_err(), "Should reject delegation < 100,000");
        
        // At minimum should succeed
        let result_ok = state.register_delegator_stake(&delegator, &validator, 100_000);
        assert!(result_ok.is_ok(), "Should accept delegation >= 100,000");
    }

    #[test]
    fn test_delegator_cannot_be_validator() {
        let mut state = new_test_chain();
        let validator1 = setup_validator(&mut state, 0x01, 50_000);
        let validator2 = setup_validator(&mut state, 0x02, 50_000);
        
        // Validator1 tries to delegate to Validator2
        let result = state.register_delegator_stake(&validator1, &validator2, 100_000);
        assert!(result.is_err(), "Validator should not be able to delegate");
    }

    #[test]
    fn test_delegator_single_validator_only() {
        let mut state = new_test_chain();
        let validator1 = setup_validator(&mut state, 0x01, 50_000);
        let validator2 = setup_validator(&mut state, 0x02, 50_000);
        
        let delegator = Address::from_bytes([0x03; 20]);
        state.create_account(delegator);
        state.mint(&delegator, 300_000).unwrap();
        
        // First delegation succeeds
        let result1 = state.register_delegator_stake(&delegator, &validator1, 100_000);
        assert!(result1.is_ok(), "First delegation should succeed");
        
        // Second delegation to different validator fails
        let result2 = state.register_delegator_stake(&delegator, &validator2, 100_000);
        assert!(result2.is_err(), "Second delegation should fail");
    }

    // ════════════════════════════════════════════════════════════
    // QUADRATIC VOTING TESTS
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_qv_weight_is_sqrt() {
        let mut state = new_test_chain();
        let addr = Address::from_bytes([0x01; 20]);
        state.create_account(addr);
        
        // Test various stakes
        let test_cases = vec![
            (10_000u128, 100u128),    // sqrt(10000) = 100
            (40_000, 200),            // sqrt(40000) = 200
            (90_000, 300),            // sqrt(90000) = 300 (approx)
            (1_000_000, 1000),        // sqrt(1000000) = 1000
        ];
        
        for (stake, expected_qv) in test_cases {
            state.locked.insert(addr, stake);
            state.update_qv_weight(&addr);
            let qv = get_qv_weight(&state, &addr);
            assert_eq!(qv, expected_qv, "QV for stake {} should be {}", stake, expected_qv);
        }
    }

    #[test]
    fn test_validator_qv_80_20_formula() {
        let mut state = new_test_chain();
        
        // Setup validator with 100,000 stake
        let validator = setup_validator(&mut state, 0x01, 100_000);
        
        // Setup delegators
        let del1 = Address::from_bytes([0x02; 20]);
        let del2 = Address::from_bytes([0x03; 20]);
        state.create_account(del1);
        state.create_account(del2);
        
        // Add delegations manually for test
        state.delegations.entry(validator).or_default().insert(del1, 100_000);
        state.delegations.entry(validator).or_default().insert(del2, 400_000);
        
        state.update_validator_qv_weight(&validator);
        let combined = get_validator_weight(&state, &validator);
        
        // Manual calculation:
        // validator_qv = sqrt(100,000) ≈ 316
        // 80% of 316 ≈ 252
        // del1_qv = sqrt(100,000) ≈ 316
        // del2_qv = sqrt(400,000) ≈ 632
        // sum = 948, 20% ≈ 189
        // total ≈ 441
        
        assert!(combined > 400 && combined < 500, 
               "Combined QV {} should be around 441", combined);
    }

    #[test]
    fn test_qv_updates_on_stake_change() {
        let mut state = new_test_chain();
        let addr = Address::from_bytes([0x01; 20]);
        state.create_account(addr);
        
        // Initial stake
        state.locked.insert(addr, 10_000);
        state.update_qv_weight(&addr);
        let qv1 = get_qv_weight(&state, &addr);
        
        // Increase stake
        state.locked.insert(addr, 40_000);
        state.update_qv_weight(&addr);
        let qv2 = get_qv_weight(&state, &addr);
        
        assert_eq!(qv1, 100, "Initial QV should be 100");
        assert_eq!(qv2, 200, "Updated QV should be 200");
    }

    // ════════════════════════════════════════════════════════════
    // DELEGATOR REWARD CAP TESTS
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_delegator_reward_cap_1_percent() {
        let mut state = new_test_chain();
        let delegator = Address::from_bytes([0x01; 20]);
        state.create_account(delegator);
        
        // Delegator with 100,000 stake
        let stake: u128 = 100_000;
        state.delegator_stakes.insert(delegator, stake);
        
        // Annual cap = 1% = 1,000
        let annual_cap = stake / 100;
        
        // Before any rewards
        let reward1 = state.calculate_capped_reward(&delegator, 500);
        assert_eq!(reward1, 500, "Should get full reward when under cap");
        
        // Accrue to cap
        state.delegator_reward_accrued.insert(delegator, annual_cap);
        let reward2 = state.calculate_capped_reward(&delegator, 500);
        assert_eq!(reward2, 0, "Should get 0 when at cap");
    }

    // ════════════════════════════════════════════════════════════
    // UNSTAKE DELAY TESTS
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_unstake_delay_7_days() {
        assert_eq!(UNSTAKE_DELAY_SECONDS, 604_800, "Unstake delay should be 7 days");
    }

    #[test]
    fn test_unstake_creates_pending_entry() {
        let mut state = new_test_chain();
        let validator = setup_validator(&mut state, 0x01, 50_000);
        
        let delegator = Address::from_bytes([0x02; 20]);
        state.create_account(delegator);
        state.mint(&delegator, 200_000).unwrap();
        state.register_delegator_stake(&delegator, &validator, 100_000).unwrap();
        
        let _ts: u64 = 1_700_000_000;
        state.unbond(&delegator, &validator, 50_000).unwrap();
        
        assert!(state.has_pending_unstake(&delegator), "Should have pending unstake");
        assert_eq!(state.get_total_pending_unstake(&delegator), 50_000);
    }

    #[test]
    fn test_unstake_not_claimable_before_delay() {
        let mut state = new_test_chain();
        let validator = setup_validator(&mut state, 0x01, 50_000);
        
        let delegator = Address::from_bytes([0x02; 20]);
        state.create_account(delegator);
        state.mint(&delegator, 200_000).unwrap();
        state.register_delegator_stake(&delegator, &validator, 100_000).unwrap();
        
        let ts: u64 = 1_700_000_000;
        state.unbond(&delegator, &validator, 50_000).unwrap();
        
        // Try to process before delay
        let process_ts = ts + (6 * 24 * 60 * 60); // 6 days
        let (processed, _) = state.process_unstake_unlocks(process_ts);
        
        assert_eq!(processed, 0, "Should not process before 7 days");
    }

       #[test]
    fn test_unstake_claimable_after_delay() {
        let mut state = new_test_chain();
        let validator = setup_validator(&mut state, 0x01, 50_000);
        
        let delegator = Address::from_bytes([0x02; 20]);
        state.create_account(delegator);
        state.mint(&delegator, 200_000).unwrap();
        state.register_delegator_stake(&delegator, &validator, 100_000).unwrap();
        
        let balance_before = state.get_balance(&delegator);
        
        // unbond() uses SystemTime::now() internally to set unlock_ts
        state.unbond(&delegator, &validator, 50_000).unwrap();
        
        // Get the actual unlock_ts from pending_unstakes
        let unlock_ts = state.pending_unstakes
            .get(&delegator)
            .and_then(|entries| entries.first())
            .map(|e| e.unlock_ts)
            .expect("Should have pending unstake entry");
        
        // Process after delay (use actual unlock_ts + 1)
        let process_ts = unlock_ts + 1;
        let (processed, released) = state.process_unstake_unlocks(process_ts);
        
        assert_eq!(processed, 1, "Should process 1 entry");
        assert_eq!(released, 50_000, "Should release 50,000");
        assert_eq!(state.get_balance(&delegator), balance_before + 50_000);
    }

    #[test]
    fn test_unstake_cancel_works() {
        let mut state = new_test_chain();
        let validator = setup_validator(&mut state, 0x01, 50_000);
        
        let delegator = Address::from_bytes([0x02; 20]);
        state.create_account(delegator);
        state.mint(&delegator, 200_000).unwrap();
        state.register_delegator_stake(&delegator, &validator, 100_000).unwrap();
        
        let ts: u64 = 1_700_000_000;
        state.unbond(&delegator, &validator, 50_000).unwrap();
        
        // Cancel
        let cancel_ts = ts + (3 * 24 * 60 * 60);
        let result = state.cancel_pending_unstake(&delegator, &validator, 50_000, cancel_ts);
        
        assert!(result.is_ok(), "Cancel should succeed");
        assert!(!state.has_pending_unstake(&delegator), "Should have no pending");
    }

    // ════════════════════════════════════════════════════════════
    // STATE PERSISTENCE TESTS  
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_state_export_import() {
        let mut state = new_test_chain();
        
        // Setup complex state
        let validator = setup_validator(&mut state, 0x01, 50_000);
        
        let delegator = Address::from_bytes([0x02; 20]);
        state.create_account(delegator);
        state.mint(&delegator, 200_000).unwrap();
        state.register_delegator_stake(&delegator, &validator, 100_000).unwrap();
        
        state.update_qv_weight(&validator);
        state.update_qv_weight(&delegator);
        state.update_validator_qv_weight(&validator);
        
        // Export
        // Export (includes node_costs as 5th element per 13.9, claimed_receipts as 6th per 13.10)
        let (
            validators,
            stakes,
            delegators,
            qv_weights,
            node_costs,
            claimed_receipts,
            proposals,
            proposal_votes,
            governance_config,
            proposal_count,
        ) = state.export_to_state_layout();
        // Create new state and import
        let mut new_state = new_test_chain();
        new_state.load_from_state_layout(
            validators,
            stakes,
            delegators,
            qv_weights,
            node_costs,
            claimed_receipts,
            proposals,
            proposal_votes,
            Some(governance_config),
            proposal_count,
        );
                
        // Verify consistency
        assert!(new_state.validator_set.is_validator(&validator));
        assert_eq!(new_state.delegator_to_validator.get(&delegator), Some(&validator));
    }