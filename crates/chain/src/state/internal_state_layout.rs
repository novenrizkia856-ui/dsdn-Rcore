


use crate::types::{Address, Hash};
use std::collections::{HashMap, HashSet};
use super::{ChainState, Validator, ValidatorInfo};
use anyhow::Result;

impl ChainState {









pub fn get_stake_data(&self, addr: &Address) -> crate::db::StakeData {
crate::db::StakeData {
address: *addr,
validator_stake: self.validator_stakes.get(addr).copied().unwrap_or(0),
delegator_stake: self.delegator_stakes.get(addr).copied().unwrap_or(0),
locked: self.locked.get(addr).copied().unwrap_or(0),
}
}


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


pub fn get_delegator_data(&self, addr: &Address) -> crate::db::DelegatorData {
crate::db::DelegatorData {
address: *addr,
validator: self.delegator_to_validator.get(addr).copied(),
delegated_amount: self.delegator_stakes.get(addr).copied().unwrap_or(0),
last_reward_epoch: self.delegator_last_epoch.get(addr).copied().unwrap_or(0),
reward_accrued: self.delegator_reward_accrued.get(addr).copied().unwrap_or(0),
}
}


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


pub fn get_qv_weight_data(&self, addr: &Address) -> crate::db::QvWeightData {
crate::db::QvWeightData {
address: *addr,
individual_weight: self.qv_weights.get(addr).copied().unwrap_or(0),
validator_combined_weight: self.validator_qv_weights.get(addr).copied().unwrap_or(0),
}
}


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






pub fn get_node_cost_data(&self, addr: &Address) -> crate::db::NodeCostData {
crate::db::NodeCostData {
address: *addr,
cost_index: self.node_cost_index.get(addr).copied().unwrap_or(0),
earnings: self.node_earnings.get(addr).copied().unwrap_or(0),
}
}


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


pub fn load_from_state_layout(&mut self, validators: HashMap<Address, crate::db::ValidatorInfo>, stakes: HashMap<Address, crate::db::StakeData>, delegators: HashMap<Address, crate::db::DelegatorData>, qv_weights: HashMap<Address, crate::db::QvWeightData>, node_costs: HashMap<Address, crate::db::NodeCostData>, claimed_receipts: HashSet<Hash>, proposals: HashMap<u64, super::Proposal>, proposal_votes: HashMap<u64, HashMap<Address, super::Vote>>, governance_config: Option<super::GovernanceConfig>, proposal_count: u64) {

self.validator_set.validators.clear();
self.validators.clear();


for (_, vinfo) in validators {

let state_vinfo = ValidatorInfo {
address: vinfo.address.clone(),
pubkey: vinfo.pubkey.clone(),
stake: vinfo.stake.clone(),
active: vinfo.active.clone(),
moniker: vinfo.moniker.clone(),
};
self.validator_set.add_validator(state_vinfo);


self.validators.insert(
vinfo.address,
Validator {
address: vinfo.address.clone(),
stake: vinfo.stake.clone(),
pubkey: vinfo.pubkey.clone(),
active: vinfo.active.clone(),
}
);
}


self.validator_stakes.clear();
self.delegator_stakes.clear();
self.locked.clear();
for data in stakes.values() {
self.set_stake_data(data);
}


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


self.qv_weights.clear();
self.validator_qv_weights.clear();
for data in qv_weights.values() {
self.set_qv_weight_data(data);
}


self.node_cost_index.clear();
self.node_earnings.clear();
for data in node_costs.values() {
self.set_node_cost_data(data);
}


self.recalculate_all_qv_weights();

self.claimed_receipts = claimed_receipts;


self.proposals = proposals;
self.proposal_votes = proposal_votes;
self.proposal_count = proposal_count;
if let Some(config) = governance_config {
self.governance_config = config;
}

println!("📦 State loaded from new layout — VALIDATORS & GOVERNANCE SYNCED ✅");
}


pub fn export_to_state_layout(&self) -> ( HashMap<Address, crate::db::ValidatorInfo>, HashMap<Address, crate::db::StakeData>, HashMap<Address, crate::db::DelegatorData>, HashMap<Address, crate::db::QvWeightData>, HashMap<Address, crate::db::NodeCostData>, HashSet<Hash>,  HashMap<u64, super::Proposal>, HashMap<u64, HashMap<Address, super::Vote>>, super::GovernanceConfig, u64, ) {

let validators = self
.validator_set
.validators
.iter()
.map(|(addr, v)| {
(
*addr,
crate::db::ValidatorInfo {
address: v.address.clone(),
pubkey: v.pubkey.clone(),
stake: v.stake.clone(),
active: v.active.clone(),
moniker: v.moniker.clone(),
}
)
})
.collect();


let mut stakes = HashMap::new();
let mut all_addrs: std::collections::HashSet<Address> = self.validator_stakes.keys().cloned().collect();
all_addrs.extend(self.delegator_stakes.keys().cloned());

for addr in all_addrs {
stakes.insert(addr, self.get_stake_data(&addr));
}


let mut delegators = HashMap::new();
for addr in self.delegator_to_validator.keys() {
delegators.insert(*addr, self.get_delegator_data(addr));
}


let mut qv_data = HashMap::new();
let mut qv_addrs: std::collections::HashSet<Address> = self.qv_weights.keys().cloned().collect();
qv_addrs.extend(self.validator_qv_weights.keys().cloned());

for addr in qv_addrs {
qv_data.insert(addr, self.get_qv_weight_data(&addr));
}


let mut node_cost_data = HashMap::new();
let mut node_addrs: std::collections::HashSet<Address> = self.node_cost_index.keys().cloned().collect();
node_addrs.extend(self.node_earnings.keys().cloned());

for addr in node_addrs {
node_cost_data.insert(addr, self.get_node_cost_data(&addr));
}


let claimed_receipts = self.claimed_receipts.clone();


let proposals = self.proposals.clone();
let proposal_votes = self.proposal_votes.clone();
let governance_config = self.governance_config.clone();
let proposal_count = self.proposal_count;

(validators, stakes, delegators, qv_data, node_cost_data, claimed_receipts,
proposals, proposal_votes, governance_config, proposal_count)
}



















pub fn export_node_liveness_to_layout(&self, db: &crate::db::ChainDb) -> Result<()> {
let mut count = 0;

for (node_addr, record) in &self.node_liveness_records {
db.put_node_liveness(node_addr, record)?;
count += 1
}

if count > 0 {
println!("📦 Exported {} node liveness record(s) to LMDB", count)
}

Ok(())
}















pub fn load_node_liveness_from_layout(&mut self, db: &crate::db::ChainDb) -> Result<()> {

self.node_liveness_records.clear();


let records = db.load_all_node_liveness()?;
let mut count = records.len();


self.node_liveness_records = records;




if count > 0 {
println!("📦 Loaded {} node liveness record(s) from LMDB", count)
}

Ok(())
}



































pub fn export_economic_state_to_layout(&self, db: &crate::db::ChainDb) -> Result<()> {

db.put_deflation_config(&self.deflation_config)?;


db.put_economic_metrics(&self.economic_metrics)?;


db.put_last_burn_epoch(self.last_burn_epoch)?;


db.put_cumulative_burned(self.cumulative_burned)?;

println!("📦 Exported economic state to LMDB");

Ok(())
}




















pub fn load_economic_state_from_layout(&mut self, db: &crate::db::ChainDb) -> Result<()> {

if let Some(config) = db.get_deflation_config()? {
self.deflation_config = config
}



if let Some(metrics) = db.get_economic_metrics()? {
self.economic_metrics = metrics
}



if let Some(epoch) = db.get_last_burn_epoch()? {
self.last_burn_epoch = epoch
}



if let Some(burned) = db.get_cumulative_burned()? {
self.cumulative_burned = burned
}





println!("📦 Loaded economic state from LMDB");

Ok(())
}




























pub fn export_storage_contracts_to_layout(&self, db: &crate::db::ChainDb) -> Result<()> {
let mut contract_count = 0;
let mut user_count = 0;


for (contract_id, contract) in &self.storage_contracts {
db.put_storage_contract(contract_id, contract)?;
contract_count += 1
}


for (user_addr, contract_ids) in &self.user_contracts {
db.put_user_contracts(user_addr, contract_ids)?;
user_count += 1
}

if contract_count > 0 || user_count > 0 {
println!(
"📦 Exported {} storage contract(s) and {} user mapping(s) to LMDB",
contract_count, user_count
)
}

Ok(())
}












pub fn load_storage_contracts_from_layout(&mut self, db: &crate::db::ChainDb) -> Result<()> {

self.storage_contracts.clear();
self.user_contracts.clear();


let contracts = db.load_all_storage_contracts()?;
let mut contract_count = contracts.len();
self.storage_contracts = contracts;


let user_mappings = db.load_all_user_contracts()?;
let mut user_count = user_mappings.len();
self.user_contracts = user_mappings;

if contract_count > 0 || user_count > 0 {
println!(
"📦 Loaded {} storage contract(s) and {} user mapping(s) from LMDB",
contract_count, user_count
)
}

Ok(())
}
}















pub fn create_checkpoint(state: &ChainState) -> Result<Vec<u8>> {
let bytes = bincode::serialize(state)
.map_err(|e| anyhow::anyhow!("checkpoint serialization failed: {}", e))?;
Ok(bytes)
}













pub fn restore_from_checkpoint(data: &[u8]) -> Result<ChainState> {
let mut state: ChainState = bincode::deserialize(data)
.map_err(|e| anyhow::anyhow!("checkpoint deserialization failed: {}", e))?;
Ok(state)
}

#[cfg(test)]
mod checkpoint_tests {
use super::*;

#[test]
fn test_checkpoint_roundtrip() {
let mut state = ChainState::new();


let bytes = create_checkpoint(&state).unwrap();
assert!(!bytes.is_empty());


let restored = restore_from_checkpoint(&bytes).unwrap();


let original_root = state.compute_state_root().unwrap();
let restored_root = restored.compute_state_root().unwrap();
assert_eq!(original_root, restored_root);
}

#[test]
fn test_checkpoint_with_data() {
let mut state = ChainState::new();


let addr = crate::types::Address::from_bytes([0x11u8; 20]);
state.create_account(addr);
state.mint(&addr, 1_000_000).unwrap();


let bytes = create_checkpoint(&state).unwrap();


let restored = restore_from_checkpoint(&bytes).unwrap();


assert_eq!(restored.get_balance(&addr), 1_000_000);
}
}