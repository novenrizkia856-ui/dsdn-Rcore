
































































use crate::types::{Address, Hash};
use serde::{Serialize, Deserialize};











#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoragePaymentError {

InsufficientBalance,


ContractNotFound,


NotOwner,


ContractExpired,


AlreadyPaid,
}

impl std::fmt::Display for StoragePaymentError {
fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
match self {
StoragePaymentError::InsufficientBalance => {
write!(f, "insufficient balance")
},
StoragePaymentError::ContractNotFound => {
write!(f, "contract not found")
},
StoragePaymentError::NotOwner => {
write!(f, "not contract owner")
},
StoragePaymentError::ContractExpired => {
write!(f, "contract expired or cancelled")
},
StoragePaymentError::AlreadyPaid => {
write!(f, "already paid for this period")
},
}
}
}

impl std::error::Error for StoragePaymentError {}










pub const GRACE_PERIOD_SECONDS: u64 = 604_800;



pub const PAYMENT_INTERVAL_SECONDS: u64 = 2_592_000;










#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StorageContractStatus {


Active,




GracePeriod,




Expired,




Cancelled,
}

impl Default for StorageContractStatus {
fn default() -> Self {
StorageContractStatus::Active
}
}
































#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageContract {


pub contract_id: Hash,



pub owner: Address,



pub node_address: Address,



pub storage_bytes: u64,



pub monthly_cost: u128,



pub start_timestamp: u64,



pub end_timestamp: u64,



pub last_payment_timestamp: u64,



pub status: StorageContractStatus,
}



























#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentSchedule {


pub next_due_timestamp: u64,




pub grace_period_seconds: u64,



pub payments_made: u64,



pub total_paid: u128,
}

impl Default for PaymentSchedule {
fn default() -> Self {
Self {
next_due_timestamp: 0,
grace_period_seconds: GRACE_PERIOD_SECONDS,
payments_made: 0,
total_paid: 0,
}
}
}


















use super::ChainState;






fn generate_contract_id(owner: &Address, node: &Address, timestamp: u64, nonce: u64) -> Hash {


let mut data = [0u8; 64];


data[0..20].copy_from_slice(owner.as_bytes());


data[20..40].copy_from_slice(node.as_bytes());


data[40..48].copy_from_slice(&timestamp.to_be_bytes());


data[48..56].copy_from_slice(&nonce.to_be_bytes());


let mut i = 56;
while i < 64 {
data[i] = data[i % 56] ^ (i as u8);
i = i + 1;
}

Hash::from_bytes(data)
}










fn distribute_payment(mut state: &mut ChainState, node_address: &Address, amount: u128) {




let node_share = amount * 70 / 100;
let validator_share = amount * 20 / 100;
let treasury_share = amount - node_share - validator_share;


let current_earnings = state.node_earnings.get(node_address).copied().unwrap_or(0);
state.node_earnings.insert(*node_address, current_earnings + node_share);


state.validator_fee_pool = state.validator_fee_pool + validator_share;


state.treasury_balance = state.treasury_balance + treasury_share;
}






















pub fn create_storage_contract(mut state: &mut ChainState, owner: Address, node: Address, bytes: u64, monthly_cost: u128, duration_months: u64, current_timestamp: u64) -> Result<Hash, StoragePaymentError> {

let owner_balance = state.balances.get(&owner).copied().unwrap_or(0);
if owner_balance < monthly_cost {
return Err(StoragePaymentError::InsufficientBalance);
}


state.balances.insert(owner, owner_balance - monthly_cost);


distribute_payment(state, &node, monthly_cost);


let user_contracts_count = state.user_contracts
.get(&owner)
.map(|v| v.len() as u64)
.unwrap_or(0);
let contract_id = generate_contract_id(&owner, &node, current_timestamp, user_contracts_count);


let start_timestamp = current_timestamp;
let end_timestamp = start_timestamp + (duration_months * PAYMENT_INTERVAL_SECONDS);


let contract = StorageContract {
contract_id: contract_id.clone(),
owner: owner,
node_address: node,
storage_bytes: bytes,
monthly_cost: monthly_cost,
start_timestamp: start_timestamp,
end_timestamp: end_timestamp,
last_payment_timestamp: start_timestamp,
status: StorageContractStatus::Active,
};


state.storage_contracts.insert(contract_id.clone(), contract);


state.user_contracts
.entry(owner)
.or_insert_with(Vec::new)
.push(contract_id.clone());


Ok(contract_id)
}

















pub fn process_monthly_payment(mut state: &mut ChainState, contract_id: Hash, current_timestamp: u64) -> Result<(), StoragePaymentError> {

let contract = state.storage_contracts.get(&contract_id)
.ok_or(StoragePaymentError::ContractNotFound)?
.clone();


if contract.status == StorageContractStatus::Expired
|| contract.status == StorageContractStatus::Cancelled {
return Err(StoragePaymentError::ContractExpired);
}


let next_due = contract.last_payment_timestamp + &PAYMENT_INTERVAL_SECONDS;
if current_timestamp < next_due {
return Err(StoragePaymentError::AlreadyPaid);
}


let owner_balance = state.balances.get(&contract.owner).copied().unwrap_or(0);

if owner_balance < contract.monthly_cost {

if let Some(c) = state.storage_contracts.get_mut(&contract_id) {
c.status = StorageContractStatus::GracePeriod
}
return Err(StoragePaymentError::InsufficientBalance);
}


state.balances.insert(contract.owner, owner_balance - contract.monthly_cost);


distribute_payment(state, &contract.node_address, contract.monthly_cost);


if let Some(c) = state.storage_contracts.get_mut(&contract_id) {
c.last_payment_timestamp = current_timestamp;
c.status = StorageContractStatus::Active
}

Ok(())
}

















pub fn check_contract_status(mut state: &mut ChainState, contract_id: Hash, current_timestamp: u64) -> Result<StorageContractStatus, StoragePaymentError> {

let contract = state.storage_contracts.get(&contract_id)
.ok_or(StoragePaymentError::ContractNotFound)?
.clone();

let mut new_status = contract.status;


if current_timestamp >= contract.end_timestamp {
new_status = StorageContractStatus::Expired;
}

else if contract.status == StorageContractStatus::GracePeriod {
let grace_end = contract.last_payment_timestamp + &PAYMENT_INTERVAL_SECONDS + &GRACE_PERIOD_SECONDS;
if current_timestamp > grace_end {
new_status = StorageContractStatus::Expired;
}
}


if new_status != contract.status {
if let Some(c) = state.storage_contracts.get_mut(&contract_id) {
c.status = new_status
}
}

Ok(new_status)
}














pub fn cancel_contract(mut state: &mut ChainState, contract_id: Hash, caller: Address) -> Result<(), StoragePaymentError> {

let contract = state.storage_contracts.get(&contract_id)
.ok_or(StoragePaymentError::ContractNotFound)?;


if contract.owner != caller {
return Err(StoragePaymentError::NotOwner);
}


if contract.status == StorageContractStatus::Expired
|| contract.status == StorageContractStatus::Cancelled {
return Err(StoragePaymentError::ContractExpired);
}


if let Some(c) = state.storage_contracts.get_mut(&contract_id) {
c.status = StorageContractStatus::Cancelled
}

Ok(())
}



















pub fn process_storage_payments(mut state: &mut ChainState, current_timestamp: u64) {

let contract_ids: Vec<Hash> = state.storage_contracts.keys().cloned().collect();

for contract_id in contract_ids {

let contract_opt = state.storage_contracts.get(&contract_id).cloned();

if let Some(contract) = contract_opt {
match contract.status {
StorageContractStatus::Active => {

let next_due = contract.last_payment_timestamp + &PAYMENT_INTERVAL_SECONDS;
if current_timestamp >= next_due {

let _ = process_monthly_payment(state, contract_id.clone(), current_timestamp);
}
},
StorageContractStatus::GracePeriod => {

let _ = check_contract_status(state, contract_id.clone(), current_timestamp);
},
StorageContractStatus::Expired | StorageContractStatus::Cancelled => {

},
}
}
}
}





#[cfg(test)]
mod tests {
use super::*;

#[test]
fn test_constants() {

assert_eq!(GRACE_PERIOD_SECONDS, 7 * 24 * 60 * 60);
assert_eq!(GRACE_PERIOD_SECONDS, 604_800);


assert_eq!(PAYMENT_INTERVAL_SECONDS, 30 * 24 * 60 * 60);
assert_eq!(PAYMENT_INTERVAL_SECONDS, 2_592_000);

println!("✅ test_constants PASSED");
}

#[test]
fn test_storage_contract_status_default() {
let status = StorageContractStatus::default();
assert_eq!(status, StorageContractStatus::Active);

println!("✅ test_storage_contract_status_default PASSED");
}

#[test]
fn test_storage_contract_status_variants() {

let active = StorageContractStatus::Active;
let grace = StorageContractStatus::GracePeriod;
let expired = StorageContractStatus::Expired;
let cancelled = StorageContractStatus::Cancelled;

assert_ne!(active, grace);
assert_ne!(active, expired);
assert_ne!(active, cancelled);
assert_ne!(grace, expired);
assert_ne!(grace, cancelled);
assert_ne!(expired, cancelled);

println!("✅ test_storage_contract_status_variants PASSED");
}

#[test]
fn test_payment_schedule_default() {
let schedule = PaymentSchedule::default();

assert_eq!(schedule.next_due_timestamp, 0);
assert_eq!(schedule.grace_period_seconds, GRACE_PERIOD_SECONDS);
assert_eq!(schedule.payments_made, 0);
assert_eq!(schedule.total_paid, 0);

println!("✅ test_payment_schedule_default PASSED");
}

#[test]
fn test_storage_contract_struct_fields() {

let contract = StorageContract {
contract_id: Hash::from_bytes([0x01u8; 64]),
owner: Address::from_bytes([0x02u8; 20]),
node_address: Address::from_bytes([0x03u8; 20]),
storage_bytes: 1024 * 1024,
monthly_cost: 100_000,
start_timestamp: 1000,
end_timestamp: 4000,
last_payment_timestamp: 1000,
status: StorageContractStatus::Active,
};

assert_eq!(contract.storage_bytes, 1024 * 1024);
assert_eq!(contract.monthly_cost, 100_000);
assert_eq!(contract.status, StorageContractStatus::Active);

println!("✅ test_storage_contract_struct_fields PASSED");
}

#[test]
fn test_payment_schedule_struct_fields() {

let schedule = PaymentSchedule {
next_due_timestamp: 2_592_000,
grace_period_seconds: 604_800,
payments_made: 3,
total_paid: 300_000,
};

assert_eq!(schedule.next_due_timestamp, PAYMENT_INTERVAL_SECONDS);
assert_eq!(schedule.grace_period_seconds, GRACE_PERIOD_SECONDS);
assert_eq!(schedule.payments_made, 3);
assert_eq!(schedule.total_paid, 300_000);

println!("✅ test_payment_schedule_struct_fields PASSED");
}





#[test]
fn test_storage_payment_error_variants() {

let e1 = StoragePaymentError::InsufficientBalance;
let e2 = StoragePaymentError::ContractNotFound;
let e3 = StoragePaymentError::NotOwner;
let e4 = StoragePaymentError::ContractExpired;
let e5 = StoragePaymentError::AlreadyPaid;

assert_ne!(e1, e2);
assert_ne!(e1, e3);
assert_ne!(e1, e4);
assert_ne!(e1, e5);
assert_ne!(e2, e3);
assert_ne!(e2, e4);
assert_ne!(e2, e5);
assert_ne!(e3, e4);
assert_ne!(e3, e5);
assert_ne!(e4, e5);

println!("✅ test_storage_payment_error_variants PASSED");
}

#[test]
fn test_storage_payment_error_display() {
assert!(format!("{}", StoragePaymentError::InsufficientBalance).contains("insufficient"));
assert!(format!("{}", StoragePaymentError::ContractNotFound).contains("not found"));
assert!(format!("{}", StoragePaymentError::NotOwner).contains("not"));
assert!(format!("{}", StoragePaymentError::ContractExpired).contains("expired"));
assert!(format!("{}", StoragePaymentError::AlreadyPaid).contains("already"));

println!("✅ test_storage_payment_error_display PASSED");
}

#[test]
fn test_generate_contract_id_determinism() {
let owner = Address::from_bytes([0x01u8; 20]);
let node = Address::from_bytes([0x02u8; 20]);
let timestamp: u64 = 1000;
let nonce: u64 = 0;


let id1 = generate_contract_id(&owner, &node, timestamp, nonce);
let id2 = generate_contract_id(&owner, &node, timestamp, nonce);

assert_eq!(id1, id2);


let id3 = generate_contract_id(&owner, &node, timestamp, 1);
assert_ne!(id1, id3);

println!("✅ test_generate_contract_id_determinism PASSED");
}

#[test]
fn test_fee_split_70_20_10() {

let amount: u128 = 100_000;

let node_share = amount * 70 / 100;
let validator_share = amount * 20 / 100;
let treasury_share = amount - node_share - validator_share;

assert_eq!(node_share, 70_000);
assert_eq!(validator_share, 20_000);
assert_eq!(treasury_share, 10_000);
assert_eq!(node_share + validator_share + treasury_share, amount);

println!("✅ test_fee_split_70_20_10 PASSED");
}

#[test]
fn test_fee_split_no_rounding_loss() {

for amount in [100, 1000, 10_000, 100_000, 1_000_000, 7_777_777u128] {
let node_share = amount * 70 / 100;
let validator_share = amount * 20 / 100;
let treasury_share = amount - node_share - validator_share;


assert_eq!(node_share + validator_share + treasury_share, amount,
"Fee split failed for amount {}", amount);
}

println!("✅ test_fee_split_no_rounding_loss PASSED");
}
}