

















use crate::types::Address;
use crate::state::ChainState;
use serde::{Serialize, Deserialize};






pub const MAX_MISSED_BLOCKS: u64 = 50;


pub const SLASH_PERCENTAGE: u64 = 5;










pub const NODE_LIVENESS_SLASH_PERCENT: u16 = 50;



pub const NODE_DATA_CORRUPTION_SLASH_PERCENT: u16 = 500;



pub const VALIDATOR_DOUBLE_SIGN_SLASH_PERCENT: u16 = 1000;



pub const VALIDATOR_OFFLINE_SLASH_PERCENT: u16 = 100;



pub const VALIDATOR_MALICIOUS_BLOCK_SLASH_PERCENT: u16 = 2000;



pub const NODE_LIVENESS_THRESHOLD_SECONDS: u64 = 43_200;



pub const FORCE_UNBOND_DELAY_SECONDS: u64 = 2_592_000;



pub const SLASHING_TREASURY_RATIO: u8 = 50;



pub const SLASHING_BURN_RATIO: u8 = 50;








#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlashingReason {

NodeLivenessFailure,

NodeDataCorruption,

NodeMaliciousBehavior,

ValidatorDoubleSign,

ValidatorProlongedOffline,

ValidatorMaliciousBlock,
}














#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeLivenessRecord {

pub node_address: Address,

pub last_seen_timestamp: u64,

pub consecutive_failures: u32,

pub data_corruption_count: u32,

pub malicious_behavior_count: u32,

pub force_unbond_until: Option<u64>,

pub slashed: bool,




pub double_sign_detected: bool,

pub malicious_block_detected: bool,

pub offline_since: Option<u64>,
}









#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingEvent {

pub target: Address,

pub reason: SlashingReason,

pub amount_slashed: u128,

pub amount_to_treasury: u128,

pub amount_burned: u128,

pub timestamp: u64,
}






#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LivenessRecord {

pub missed_blocks: u64,

pub slashed: bool,

pub slash_count: u64,

pub last_active_height: u64,
}

impl LivenessRecord {
pub fn new() -> Self {
Self {
missed_blocks: 0,
slashed: false,
slash_count: 0,
last_active_height: 0,
}
}


pub fn reset_missed(&mut self, current_height: u64) {
self.missed_blocks = 0;
self.last_active_height = current_height;
}


pub fn increment_missed(&mut self) {
self.missed_blocks = self.missed_blocks.saturating_add(1);
}


pub fn should_slash(&self) -> bool {
!self.slashed && self.missed_blocks >= MAX_MISSED_BLOCKS
}
}











pub fn update_liveness(validator: &Address, produced_block: bool, current_height: u64, mut state: &mut ChainState) -> Option<String> {

let mut record = state.liveness_records
.entry(*validator)
.or_insert_with(LivenessRecord::new);

if produced_block {

record.reset_missed(current_height);
println!("✅ Validator {} produced block at height {}", validator, current_height);
None
} else {

record.increment_missed();
println!("⚠️  Validator {} missed block (consecutive: {})",
validator, record.missed_blocks);


if record.should_slash() {
Some(apply_slashing(validator, state))
} else {
None
}
}
}













pub fn apply_slashing(validator: &Address, mut state: &mut ChainState) -> String {
println!("🔪 SLASHING VALIDATOR: {}", validator);
println!("   Reason: Exceeded {} consecutive missed blocks", MAX_MISSED_BLOCKS);
println!("   Slash percentage: {}%", SLASH_PERCENTAGE);


if let Some(record) = state.liveness_records.get_mut(validator) {
record.slashed = true;
record.slash_count = record.slash_count.saturating_add(1)
}


state.validator_set.set_active(validator, false);


if let Some(v) = state.validators.get_mut(validator) {
v.active = false
}












let (validator_slashed, delegators_slashed, total_slashed) = state.apply_full_slash(validator, SLASH_PERCENTAGE);

let slash_count = state.liveness_records
.get(validator)
.map(|r| r.slash_count)
.unwrap_or(0);

let event = format!(
"ValidatorSlashed:addr={},missed={},slash_count={},validator_slash={},delegator_slash={},total_slash={},to_treasury={}",
validator,
MAX_MISSED_BLOCKS,
slash_count,
validator_slashed,
delegators_slashed,
total_slashed,
total_slashed
);

println!("   Event: {}", event);
event
}














pub fn update_all_validators_liveness(proposer: &Address, current_height: u64, mut state: &mut ChainState) -> Vec<String> {
let mut events = Vec::new();


let active_validators: Vec<Address> = state.validator_set.validators
.iter()
.filter(|(_, v)| v.active)
.map(|(addr, _)| *addr)
.collect();

if active_validators.is_empty() {
return events;
}

println!("📊 Updating liveness for {} active validator(s) at height {}",
active_validators.len(), current_height);


for validator in active_validators {
let produced_block = &validator == proposer;
if let Some(event) = update_liveness(&validator, produced_block, current_height, state) {
events.push(event);
}
}

events
}


pub fn is_slashed(validator: &Address, state: &ChainState) -> bool {
state.liveness_records
.get(validator)
.map(|r| r.slashed)
.unwrap_or(false)
}


pub fn get_liveness_status(validator: &Address, state: &ChainState) -> Option<LivenessRecord> {
state.liveness_records.get(validator).cloned()
}



#[allow(dead_code)]
pub fn reset_slashing(validator: &Address, mut state: &mut ChainState) -> bool {
if let Some(record) = state.liveness_records.get_mut(validator) {
record.slashed = false;
record.missed_blocks = 0;


state.validator_set.set_active(validator, true);
if let Some(v) = state.validators.get_mut(validator) {
v.active = true
}

println!("🔓 Validator {} slashing status reset", validator);
true
} else {
false
}
}

#[cfg(test)]
mod tests {
use super::*;

#[test]
fn test_liveness_record_new() {
let mut record = LivenessRecord::new();
assert_eq!(record.missed_blocks, 0);
assert!(!record.slashed);
assert_eq!(record.slash_count, 0);
}

#[test]
fn test_should_slash() {
let mut record = LivenessRecord::new();


record.missed_blocks = MAX_MISSED_BLOCKS - 1;
assert!(!record.should_slash());


record.missed_blocks = MAX_MISSED_BLOCKS;
assert!(record.should_slash());


record.slashed = true;
assert!(!record.should_slash());
}

#[test]
fn test_reset_missed() {
let mut record = LivenessRecord::new();
record.missed_blocks = 25;
record.reset_missed(100);

assert_eq!(record.missed_blocks, 0);
assert_eq!(record.last_active_height, 100);
}







#[test]
fn test_slashing_constants() {

assert_eq!(NODE_LIVENESS_SLASH_PERCENT, 50,
"Node liveness slash should be 0.5% (50 bp)");
assert_eq!(NODE_DATA_CORRUPTION_SLASH_PERCENT, 500,
"Node data corruption slash should be 5% (500 bp)");


assert_eq!(VALIDATOR_DOUBLE_SIGN_SLASH_PERCENT, 1000,
"Validator double-sign slash should be 10% (1000 bp)");
assert_eq!(VALIDATOR_OFFLINE_SLASH_PERCENT, 100,
"Validator offline slash should be 1% (100 bp)");
assert_eq!(VALIDATOR_MALICIOUS_BLOCK_SLASH_PERCENT, 2000,
"Validator malicious block slash should be 20% (2000 bp)");


assert_eq!(NODE_LIVENESS_THRESHOLD_SECONDS, 43_200,
"Node liveness threshold should be 12 hours (43200 seconds)");
assert_eq!(FORCE_UNBOND_DELAY_SECONDS, 2_592_000,
"Force unbond delay should be 30 days (2592000 seconds)");


assert_eq!(SLASHING_TREASURY_RATIO, 50, "Treasury ratio should be 50%");
assert_eq!(SLASHING_BURN_RATIO, 50, "Burn ratio should be 50%");
assert_eq!(
SLASHING_TREASURY_RATIO + SLASHING_BURN_RATIO,
100,
"Treasury + Burn must equal 100%"
);
}



#[test]
fn test_node_liveness_record_default() {
let addr = Address::from_bytes([0x01; 20]);
let mut record = NodeLivenessRecord {
node_address: addr,
last_seen_timestamp: 0,
consecutive_failures: 0,
data_corruption_count: 0,
malicious_behavior_count: 0,
force_unbond_until: None,
slashed: false,
double_sign_detected: false,
malicious_block_detected: false,
offline_since: None,
};


assert_eq!(record.last_seen_timestamp, 0, "last_seen_timestamp should be 0");
assert_eq!(record.consecutive_failures, 0, "consecutive_failures should be 0");
assert_eq!(record.data_corruption_count, 0, "data_corruption_count should be 0");
assert_eq!(record.malicious_behavior_count, 0, "malicious_behavior_count should be 0");


assert!(!record.slashed, "slashed should be false");
assert!(!record.double_sign_detected, "double_sign_detected should be false");
assert!(!record.malicious_block_detected, "malicious_block_detected should be false");


assert!(record.force_unbond_until.is_none(), "force_unbond_until should be None");
assert!(record.offline_since.is_none(), "offline_since should be None");


assert_eq!(record.node_address, addr, "node_address should match");
}



#[test]
fn test_slashing_reason_variants() {

let reason1 = SlashingReason::NodeLivenessFailure;
let reason2 = SlashingReason::NodeDataCorruption;
let reason3 = SlashingReason::NodeMaliciousBehavior;
let reason4 = SlashingReason::ValidatorDoubleSign;
let reason5 = SlashingReason::ValidatorProlongedOffline;
let reason6 = SlashingReason::ValidatorMaliciousBlock;


assert_ne!(reason1, reason2, "NodeLivenessFailure != NodeDataCorruption");
assert_ne!(reason2, reason3, "NodeDataCorruption != NodeMaliciousBehavior");
assert_ne!(reason3, reason4, "NodeMaliciousBehavior != ValidatorDoubleSign");
assert_ne!(reason4, reason5, "ValidatorDoubleSign != ValidatorProlongedOffline");
assert_ne!(reason5, reason6, "ValidatorProlongedOffline != ValidatorMaliciousBlock");


assert_eq!(reason1, SlashingReason::NodeLivenessFailure);
assert_eq!(reason4, SlashingReason::ValidatorDoubleSign);


let _debug1 = format!("{:?}", reason1);
let _debug6 = format!("{:?}", reason6);


let cloned = reason1.clone();
assert_eq!(cloned, reason1);


let copied: SlashingReason = reason4;
assert_eq!(copied, reason4);
}



#[test]
fn test_slashing_event_creation() {
let target = Address::from_bytes([0xAA; 20]);
let event = SlashingEvent {
target: target,
reason: SlashingReason::ValidatorDoubleSign,
amount_slashed: 1_000_000,
amount_to_treasury: 500_000,
amount_burned: 500_000,
timestamp: 1700000000,
};

assert_eq!(event.target, target);
assert_eq!(event.reason, SlashingReason::ValidatorDoubleSign);
assert_eq!(event.amount_slashed, 1_000_000);
assert_eq!(event.amount_to_treasury, 500_000);
assert_eq!(event.amount_burned, 500_000);
assert_eq!(event.timestamp, 1700000000);


assert_eq!(
event.amount_to_treasury + event.amount_burned,
event.amount_slashed,
"Treasury + Burned should equal total slashed"
);
}



#[test]
fn test_slashing_basis_points_calculation() {
let stake: u128 = 10_000_000;


let node_liveness_slash = (stake * NODE_LIVENESS_SLASH_PERCENT as u128) / 10_000;
assert_eq!(node_liveness_slash, 50_000, "0.5% of 10M should be 50K");


let data_corruption_slash = (stake * NODE_DATA_CORRUPTION_SLASH_PERCENT as u128) / 10_000;
assert_eq!(data_corruption_slash, 500_000, "5% of 10M should be 500K");


let double_sign_slash = (stake * VALIDATOR_DOUBLE_SIGN_SLASH_PERCENT as u128) / 10_000;
assert_eq!(double_sign_slash, 1_000_000, "10% of 10M should be 1M");


let offline_slash = (stake * VALIDATOR_OFFLINE_SLASH_PERCENT as u128) / 10_000;
assert_eq!(offline_slash, 100_000, "1% of 10M should be 100K");


let malicious_slash = (stake * VALIDATOR_MALICIOUS_BLOCK_SLASH_PERCENT as u128) / 10_000;
assert_eq!(malicious_slash, 2_000_000, "20% of 10M should be 2M");
}



#[test]
fn test_slashing_severity_ordering() {
assert!(
VALIDATOR_MALICIOUS_BLOCK_SLASH_PERCENT > VALIDATOR_DOUBLE_SIGN_SLASH_PERCENT,
"Malicious block should be more severe than double-sign"
);
assert!(
VALIDATOR_DOUBLE_SIGN_SLASH_PERCENT > NODE_DATA_CORRUPTION_SLASH_PERCENT,
"Double-sign should be more severe than data corruption"
);
assert!(
NODE_DATA_CORRUPTION_SLASH_PERCENT > VALIDATOR_OFFLINE_SLASH_PERCENT,
"Data corruption should be more severe than offline"
);
assert!(
VALIDATOR_OFFLINE_SLASH_PERCENT > NODE_LIVENESS_SLASH_PERCENT,
"Validator offline should be more severe than node liveness"
);
}
}