//! Internal state layout helpers (13.8.H)
//! For LMDB bucket layout integration
//! Dipindahkan dari state.rs untuk modularisasi

use crate::types::{Address, Hash};
use std::collections::{HashMap, HashSet};
use super::{ChainState, Validator, ValidatorInfo};
use anyhow::Result;

impl ChainState {
    // ============================================================
    // STATE LAYOUT HELPERS (13.8.H)
    // ============================================================
    // These functions provide structured access to state data
    // matching the new LMDB bucket layout
    // ============================================================

    /// Get StakeData for an address
    /// Combines validator_stakes, delegator_stakes, and locked
    pub fn get_stake_data(&self, addr: &Address) -> crate::db::StakeData {
        crate::db::StakeData {
            address: *addr,
            validator_stake: self.validator_stakes.get(addr).copied().unwrap_or(0),
            delegator_stake: self.delegator_stakes.get(addr).copied().unwrap_or(0),
            locked: self.locked.get(addr).copied().unwrap_or(0),
        }
    }

    /// Set StakeData for an address (updates multiple maps)
    pub fn set_stake_data(&mut self, data: &crate::db::StakeData) {
        if data.validator_stake > 0 {
            self.validator_stakes.insert(data.address, data.validator_stake);
        } else {
            self.validator_stakes.remove(&data.address);
        }
        
        if data.delegator_stake > 0 {
            self.delegator_stakes.insert(data.address, data.delegator_stake);
        } else {
            self.delegator_stakes.remove(&data.address);
        }
        
        if data.locked > 0 {
            self.locked.insert(data.address, data.locked);
        } else {
            self.locked.remove(&data.address);
        }
    }

    /// Get DelegatorData for an address
    pub fn get_delegator_data(&self, addr: &Address) -> crate::db::DelegatorData {
        crate::db::DelegatorData {
            address: *addr,
            validator: self.delegator_to_validator.get(addr).copied(),
            delegated_amount: self.delegator_stakes.get(addr).copied().unwrap_or(0),
            last_reward_epoch: self.delegator_last_epoch.get(addr).copied().unwrap_or(0),
            reward_accrued: self.delegator_reward_accrued.get(addr).copied().unwrap_or(0),
        }
    }

    /// Set DelegatorData for an address (updates multiple maps)
    pub fn set_delegator_data(&mut self, data: &crate::db::DelegatorData) {
        if let Some(validator) = data.validator {
            self.delegator_to_validator.insert(data.address, validator);
        } else {
            self.delegator_to_validator.remove(&data.address);
        }
        
        if data.delegated_amount > 0 {
            self.delegator_stakes.insert(data.address, data.delegated_amount);
        } else {
            self.delegator_stakes.remove(&data.address);
        }
        
        if data.last_reward_epoch > 0 {
            self.delegator_last_epoch.insert(data.address, data.last_reward_epoch);
        }
        
        if data.reward_accrued > 0 {
            self.delegator_reward_accrued.insert(data.address, data.reward_accrued);
        }
    }

    /// Get QvWeightData for an address
    pub fn get_qv_weight_data(&self, addr: &Address) -> crate::db::QvWeightData {
        crate::db::QvWeightData {
            address: *addr,
            individual_weight: self.qv_weights.get(addr).copied().unwrap_or(0),
            validator_combined_weight: self.validator_qv_weights.get(addr).copied().unwrap_or(0),
        }
    }

    /// Set QvWeightData for an address (updates QV maps)
    pub fn set_qv_weight_data(&mut self, data: &crate::db::QvWeightData) {
        if data.individual_weight > 0 {
            self.qv_weights.insert(data.address, data.individual_weight);
        } else {
            self.qv_weights.remove(&data.address);
        }
        
        if data.validator_combined_weight > 0 {
            self.validator_qv_weights.insert(data.address, data.validator_combined_weight);
        } else {
            self.validator_qv_weights.remove(&data.address);
        }
    }

    // ============================================================
    // NODE COST DATA (13.9)
    // ============================================================

    /// Get NodeCostData for an address
    pub fn get_node_cost_data(&self, addr: &Address) -> crate::db::NodeCostData {
        crate::db::NodeCostData {
            address: *addr,
            cost_index: self.node_cost_index.get(addr).copied().unwrap_or(0),
            earnings: self.node_earnings.get(addr).copied().unwrap_or(0),
        }
    }

    /// Set NodeCostData for an address (updates node_cost_index and node_earnings)
    pub fn set_node_cost_data(&mut self, data: &crate::db::NodeCostData) {
        if data.cost_index > 0 {
            self.node_cost_index.insert(data.address, data.cost_index);
        } else {
            self.node_cost_index.remove(&data.address);
        }
        
        if data.earnings > 0 {
            self.node_earnings.insert(data.address, data.earnings);
        } else {
            self.node_earnings.remove(&data.address);
        }
    }

    /// Load state from new layout data (for DB migration)
    pub fn load_from_state_layout(
        &mut self,
        validators: HashMap<Address, crate::db::ValidatorInfo>,
        stakes: HashMap<Address, crate::db::StakeData>,
        delegators: HashMap<Address, crate::db::DelegatorData>,
        qv_weights: HashMap<Address, crate::db::QvWeightData>,
        node_costs: HashMap<Address, crate::db::NodeCostData>,
        claimed_receipts: HashSet<Hash>,
        // Governance data (13.12.7)
        proposals: HashMap<u64, super::Proposal>,
        proposal_votes: HashMap<u64, HashMap<Address, super::Vote>>,
        governance_config: Option<super::GovernanceConfig>,
        proposal_count: u64,
    ) {
        // ✅ RESET STATE YANG TERKAIT VALIDATOR
        self.validator_set.validators.clear();
        self.validators.clear();

        // ✅ LOAD VALIDATORS KE DUA REGISTRY
        for (_, vinfo) in validators {
            // 1. ValidatorSet (DPoS hybrid)
            let state_vinfo = ValidatorInfo {
                address: vinfo.address,
                pubkey: vinfo.pubkey.clone(),
                stake: vinfo.stake,
                active: vinfo.active,
                moniker: vinfo.moniker.clone(),
            };
            self.validator_set.add_validator(state_vinfo);

            // 2. Legacy validators map (WAJIB untuk unbond/slash)
            self.validators.insert(
                vinfo.address,
                Validator {
                    address: vinfo.address,
                    stake: vinfo.stake,
                    pubkey: vinfo.pubkey,
                    active: vinfo.active,
                },
            );
        }

        // ✅ LOAD STAKES
        self.validator_stakes.clear();
        self.delegator_stakes.clear();
        self.locked.clear();
        for data in stakes.values() {
            self.set_stake_data(data);
        }

        // ✅ LOAD DELEGATORS
        self.delegator_to_validator.clear();
        self.delegations.clear();
        for data in delegators.values() {
            self.set_delegator_data(data);
            if let Some(validator) = data.validator {
                self.delegations
                    .entry(validator)
                    .or_insert_with(HashMap::new)
                    .insert(data.address, data.delegated_amount);
            }
        }

        // ✅ LOAD QV DATA
        self.qv_weights.clear();
        self.validator_qv_weights.clear();
        for data in qv_weights.values() {
            self.set_qv_weight_data(data);
        }

        // ✅ LOAD NODE COST DATA (13.9)
        self.node_cost_index.clear();
        self.node_earnings.clear();
        for data in node_costs.values() {
            self.set_node_cost_data(data);
        }

        // ✅ RECOMPUTE DERIVED STATE (KRUSIAL)
        self.recalculate_all_qv_weights();
        // ✅ LOAD CLAIMED RECEIPTS (13.10)
        self.claimed_receipts = claimed_receipts;

        // ✅ LOAD GOVERNANCE STATE (13.12.7)
        self.proposals = proposals;
        self.proposal_votes = proposal_votes;
        self.proposal_count = proposal_count;
        if let Some(config) = governance_config {
            self.governance_config = config;
        }

        println!("📦 State loaded from new layout — VALIDATORS & GOVERNANCE SYNCED ✅");
    }

    /// Export state to new layout format (for snapshot/debugging)
    pub fn export_to_state_layout(&self) -> (
        HashMap<Address, crate::db::ValidatorInfo>, // ✅ DB TYPE
        HashMap<Address, crate::db::StakeData>,
        HashMap<Address, crate::db::DelegatorData>,
        HashMap<Address, crate::db::QvWeightData>,
        HashMap<Address, crate::db::NodeCostData>,
        HashSet<Hash>, // claimed_receipts (13.10)
        // Governance data (13.12.7)
        HashMap<u64, super::Proposal>,
        HashMap<u64, HashMap<Address, super::Vote>>,
        super::GovernanceConfig,
        u64, // proposal_count
    ) {
        // ✅ convert state::ValidatorInfo → db::ValidatorInfo
        let validators = self
            .validator_set
            .validators
            .iter()
            .map(|(addr, v)| {
                (
                    *addr,
                    crate::db::ValidatorInfo {
                        address: v.address,
                        pubkey: v.pubkey.clone(),
                        stake: v.stake,
                        active: v.active,
                        moniker: v.moniker.clone(),
                    },
                )
            })
            .collect();

        // Export stakes
        let mut stakes = HashMap::new();
        let mut all_addrs: std::collections::HashSet<Address> =
            self.validator_stakes.keys().cloned().collect();
        all_addrs.extend(self.delegator_stakes.keys().cloned());

        for addr in all_addrs {
            stakes.insert(addr, self.get_stake_data(&addr));
        }

        // Export delegators
        let mut delegators = HashMap::new();
        for addr in self.delegator_to_validator.keys() {
            delegators.insert(*addr, self.get_delegator_data(addr));
        }

        // Export QV weights
        let mut qv_data = HashMap::new();
        let mut qv_addrs: std::collections::HashSet<Address> =
            self.qv_weights.keys().cloned().collect();
        qv_addrs.extend(self.validator_qv_weights.keys().cloned());

        for addr in qv_addrs {
            qv_data.insert(addr, self.get_qv_weight_data(&addr));
        }

        // Export Node Cost data (13.9)
        let mut node_cost_data = HashMap::new();
        let mut node_addrs: std::collections::HashSet<Address> =
            self.node_cost_index.keys().cloned().collect();
        node_addrs.extend(self.node_earnings.keys().cloned());

        for addr in node_addrs {
            node_cost_data.insert(addr, self.get_node_cost_data(&addr));
        }

        // Export claimed receipts (13.10)
        let claimed_receipts = self.claimed_receipts.clone();

// Export governance state (13.12.7)
        let proposals = self.proposals.clone();
        let proposal_votes = self.proposal_votes.clone();
        let governance_config = self.governance_config.clone();
        let proposal_count = self.proposal_count;

        (validators, stakes, delegators, qv_data, node_cost_data, claimed_receipts,
         proposals, proposal_votes, governance_config, proposal_count)
    }

    // ════════════════════════════════════════════════════════════════════════════
    // NODE LIVENESS PERSISTENCE (13.14.7)
    // ════════════════════════════════════════════════════════════════════════════

    /// Export node liveness records to LMDB
    ///
    /// Iterates all node_liveness_records and persists each to LMDB.
    /// Only consensus-critical data is persisted (NOT slashing_events).
    ///
    /// # Arguments
    /// * `db` - Reference to ChainDb
    ///
    /// # Returns
    /// * `Ok(())` - All records exported successfully
    /// * `Err` - LMDB or serialization error
    ///
    /// # Note
    /// slashing_events is runtime-only and NOT persisted.
    pub fn export_node_liveness_to_layout(&self, db: &crate::db::ChainDb) -> Result<()> {
        let mut count = 0;
        
        for (node_addr, record) in &self.node_liveness_records {
            db.put_node_liveness(node_addr, record)?;
            count += 1;
        }
        
        if count > 0 {
            println!("📦 Exported {} node liveness record(s) to LMDB", count);
        }
        
        Ok(())
    }

    /// Load node liveness records from LMDB
    ///
    /// Clears existing node_liveness_records and loads all records from LMDB.
    /// Guarantees roundtrip validity: export → restart → load → state identik.
    ///
    /// # Arguments
    /// * `db` - Reference to ChainDb
    ///
    /// # Returns
    /// * `Ok(())` - All records loaded successfully
    /// * `Err` - LMDB or deserialization error
    ///
    /// # Note
    /// slashing_events is NOT loaded (runtime-only, starts empty).
    pub fn load_node_liveness_from_layout(&mut self, db: &crate::db::ChainDb) -> Result<()> {
        // Clear existing state before loading
        self.node_liveness_records.clear();
        
        // Load all records from LMDB
        let records = db.load_all_node_liveness()?;
        let count = records.len();
        
        // Populate state
        self.node_liveness_records = records;
        
        // slashing_events is runtime-only, starts empty
        // self.slashing_events remains empty (not loaded from LMDB)
        
        if count > 0 {
            println!("📦 Loaded {} node liveness record(s) from LMDB", count);
        }
        
        Ok(())
    }

    // ════════════════════════════════════════════════════════════════════════════
    // ECONOMIC STATE PERSISTENCE (13.15.7)
    // ════════════════════════════════════════════════════════════════════════════
    //
    // Persistence for:
    // - deflation_config
    // - economic_metrics
    // - last_burn_epoch
    // - cumulative_burned
    //
    // CONSENSUS-CRITICAL:
    // - Format tidak boleh berubah tanpa hard fork
    // - Roundtrip harus valid: export → load → state identik
    // - economic_events adalah runtime-only, TIDAK dipersist
    //
    // ════════════════════════════════════════════════════════════════════════════

    /// Export economic state to LMDB
    ///
    /// Persists all consensus-critical economic data to LMDB:
    /// - deflation_config
    /// - economic_metrics  
    /// - last_burn_epoch
    /// - cumulative_burned
    ///
    /// # Arguments
    /// * `db` - Reference to ChainDb
    ///
    /// # Returns
    /// * `Ok(())` - All data exported successfully
    /// * `Err` - LMDB or serialization error
    ///
    /// # Note
    /// economic_events is runtime-only and NOT persisted.
    pub fn export_economic_state_to_layout(&self, db: &crate::db::ChainDb) -> Result<()> {
        // Export deflation_config
        db.put_deflation_config(&self.deflation_config)?;
        
        // Export economic_metrics
        db.put_economic_metrics(&self.economic_metrics)?;
        
        // Export last_burn_epoch
        db.put_last_burn_epoch(self.last_burn_epoch)?;
        
        // Export cumulative_burned
        db.put_cumulative_burned(self.cumulative_burned)?;
        
        println!("📦 Exported economic state to LMDB");
        
        Ok(())
    }

    /// Load economic state from LMDB
    ///
    /// Loads all consensus-critical economic data from LMDB:
    /// - deflation_config
    /// - economic_metrics
    /// - last_burn_epoch
    /// - cumulative_burned
    ///
    /// If data doesn't exist in DB (first boot), uses default values.
    ///
    /// # Arguments
    /// * `db` - Reference to ChainDb
    ///
    /// # Returns
    /// * `Ok(())` - All data loaded successfully
    /// * `Err` - LMDB or deserialization error
    ///
    /// # Note
    /// economic_events is runtime-only and starts empty.
    pub fn load_economic_state_from_layout(&mut self, db: &crate::db::ChainDb) -> Result<()> {
        // Load deflation_config (use default if not found)
        if let Some(config) = db.get_deflation_config()? {
            self.deflation_config = config;
        }
        // else: keep default from ChainState::new()
        
        // Load economic_metrics (use default if not found)
        if let Some(metrics) = db.get_economic_metrics()? {
            self.economic_metrics = metrics;
        }
        // else: keep default from ChainState::new()
        
        // Load last_burn_epoch (use 0 if not found)
        if let Some(epoch) = db.get_last_burn_epoch()? {
            self.last_burn_epoch = epoch;
        }
        // else: keep default 0
        
        // Load cumulative_burned (use 0 if not found)
        if let Some(burned) = db.get_cumulative_burned()? {
            self.cumulative_burned = burned;
        }
        // else: keep default 0
        
        // economic_events is runtime-only, starts empty
        // self.economic_events remains empty (not loaded from LMDB)
        
        println!("📦 Loaded economic state from LMDB");
        
        Ok(())
    }

    // ════════════════════════════════════════════════════════════════════════════
    // STORAGE CONTRACT PERSISTENCE (13.17.7)
    // ════════════════════════════════════════════════════════════════════════════
    //
    // Persistence for:
    // - storage_contracts (HashMap<Hash, StorageContract>)
    // - user_contracts (HashMap<Address, Vec<Hash>>)
    //
    // CONSENSUS-CRITICAL:
    // - Format tidak boleh berubah tanpa hard fork
    // - Roundtrip harus valid: export → load → state identik
    // - Ordering deterministik untuk state_root
    //
    // ════════════════════════════════════════════════════════════════════════════

    /// Export storage contracts to LMDB
    ///
    /// Persists all storage contracts and user contract mappings:
    /// - storage_contracts: contract_id → StorageContract
    /// - user_contracts: address → Vec<contract_id>
    ///
    /// # Arguments
    /// * `db` - Reference to ChainDb
    ///
    /// # Returns
    /// * `Ok(())` - All data exported successfully
    /// * `Err` - LMDB or serialization error
    pub fn export_storage_contracts_to_layout(&self, db: &crate::db::ChainDb) -> Result<()> {
        let mut contract_count = 0;
        let mut user_count = 0;
        
        // Export all storage contracts
        for (contract_id, contract) in &self.storage_contracts {
            db.put_storage_contract(contract_id, contract)?;
            contract_count += 1;
        }
        
        // Export all user contract mappings
        for (user_addr, contract_ids) in &self.user_contracts {
            db.put_user_contracts(user_addr, contract_ids)?;
            user_count += 1;
        }
        
        if contract_count > 0 || user_count > 0 {
            println!(
                "📦 Exported {} storage contract(s) and {} user mapping(s) to LMDB",
                contract_count, user_count
            );
        }
        
        Ok(())
    }

    /// Load storage contracts from LMDB
    ///
    /// Loads all storage contracts and user contract mappings from LMDB.
    /// Clears existing state before loading.
    ///
    /// # Arguments
    /// * `db` - Reference to ChainDb
    ///
    /// # Returns
    /// * `Ok(())` - All data loaded successfully
    /// * `Err` - LMDB or deserialization error
    pub fn load_storage_contracts_from_layout(&mut self, db: &crate::db::ChainDb) -> Result<()> {
        // Clear existing state before loading
        self.storage_contracts.clear();
        self.user_contracts.clear();
        
        // Load all storage contracts from LMDB
        let contracts = db.load_all_storage_contracts()?;
        let contract_count = contracts.len();
        self.storage_contracts = contracts;
        
        // Load all user contract mappings from LMDB
        let user_mappings = db.load_all_user_contracts()?;
        let user_count = user_mappings.len();
        self.user_contracts = user_mappings;
        
        if contract_count > 0 || user_count > 0 {
            println!(
                "📦 Loaded {} storage contract(s) and {} user mapping(s) from LMDB",
                contract_count, user_count
            );
        }
        
        Ok(())
    }
}
// ════════════════════════════════════════════════════════════════════════════
// CHECKPOINT FUNCTIONS (13.11.4)
// ════════════════════════════════════════════════════════════════════════════

/// Create checkpoint dari ChainState.
///
/// Serialisasi full state ke bytes menggunakan bincode.
/// Checkpoint bersifat deterministik — state yang sama menghasilkan bytes yang sama.
///
/// # Arguments
/// * `state` - ChainState yang akan di-checkpoint
///
/// # Returns
/// * Vec<u8> — serialized state bytes
pub fn create_checkpoint(state: &ChainState) -> Result<Vec<u8>> {
    let bytes = bincode::serialize(state)
        .map_err(|e| anyhow::anyhow!("checkpoint serialization failed: {}", e))?;
    Ok(bytes)
}

/// Restore ChainState dari checkpoint.
///
/// Deserialisasi bytes ke ChainState menggunakan bincode.
///
/// # Arguments
/// * `data` - checkpoint bytes dari create_checkpoint
///
/// # Returns
/// * ChainState — restored state
///
/// # Errors
/// * Deserialization gagal — format invalid atau corrupted
pub fn restore_from_checkpoint(data: &[u8]) -> Result<ChainState> {
    let state: ChainState = bincode::deserialize(data)
        .map_err(|e| anyhow::anyhow!("checkpoint deserialization failed: {}", e))?;
    Ok(state)
}

#[cfg(test)]
mod checkpoint_tests {
    use super::*;

    #[test]
    fn test_checkpoint_roundtrip() {
        let state = ChainState::new();
        
        // Create checkpoint
        let bytes = create_checkpoint(&state).unwrap();
        assert!(!bytes.is_empty());
        
        // Restore
        let restored = restore_from_checkpoint(&bytes).unwrap();
        
        // Verify state roots match
        let original_root = state.compute_state_root().unwrap();
        let restored_root = restored.compute_state_root().unwrap();
        assert_eq!(original_root, restored_root);
    }

    #[test]
    fn test_checkpoint_with_data() {
        let mut state = ChainState::new();
        
        // Add some data
        let addr = crate::types::Address::from_bytes([0x11u8; 20]);
        state.create_account(addr);
        state.mint(&addr, 1_000_000).unwrap();
        
        // Create checkpoint
        let bytes = create_checkpoint(&state).unwrap();
        
        // Restore
        let restored = restore_from_checkpoint(&bytes).unwrap();
        
        // Verify balance preserved
        assert_eq!(restored.get_balance(&addr), 1_000_000);
    }
}