
use serde::{Serialize, Deserialize};
use crate::types::{Address, Hash};
use crate::crypto::{sha3_512_bytes, address_from_pubkey_bytes, verify_signature};
use crate::receipt::{ResourceReceipt, ResourceType};
use crate::state::{ProposalType, ProposalStatus, VoteOption};
use anyhow::{Result, anyhow};

const MIN_GAS_LIMIT: u64 = 21000;
pub const GAS_PRICE: u128 = 1;


pub use crate::tokenomics::{VALIDATOR_MIN_STAKE, DELEGATOR_MIN_STAKE};

pub const MIN_VALIDATOR_STAKE: u128 = 50_000;
pub const MIN_DELEGATOR_STAKE: u128 = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResourceClass {
Transfer,
Storage,
Compute,
Governance,
}


#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GovernanceActionType {

CreateProposal {
proposal_type: ProposalType,
title: String,
description: String,
},

CastVote {
proposal_id: u64,
vote: VoteOption,
},

FinalizeProposal {
proposal_id: u64,
},

FoundationVeto {
proposal_id: u64,
},

FoundationOverride {
proposal_id: u64,
new_status: ProposalStatus,
},
}


#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum TxPayload {

Transfer {
from: Address,
to: Address,
amount: u128,
fee: u128,
nonce: u64,
gas_limit: u64,
resource_class: ResourceClass,
metadata_flagged: bool,
},


Stake {
delegator: Address,
validator: Address,
amount: u128,
fee: u128,
nonce: u64,
bond: bool,
gas_limit: u64,
resource_class: ResourceClass,
metadata_flagged: bool,
},


Unstake {
delegator: Address,
validator: Address,
amount: u128,
fee: u128,
nonce: u64,
gas_limit: u64,
resource_class: ResourceClass,
metadata_flagged: bool,
},


ClaimReward {
receipt: ResourceReceipt,
fee: u128,
nonce: u64,
gas_limit: u64,
},


StorageOperationPayment {
from: Address,
to_node: Address,
amount: u128,
fee: u128,
nonce: u64,
operation_id: Vec<u8>,
gas_limit: u64,
resource_class: ResourceClass,
metadata_flagged: bool,
},


ComputeExecutionPayment {
from: Address,
to_node: Address,
amount: u128,
fee: u128,
nonce: u64,
execution_id: Vec<u8>,
gas_limit: u64,
resource_class: ResourceClass,
metadata_flagged: bool,
},


ValidatorRegistration {
from: Address,
pubkey: Vec<u8>,
min_stake: u128,
fee: u128,
nonce: u64,
gas_limit: u64,
resource_class: ResourceClass,
metadata_flagged: bool,
},


GovernanceAction {
from: Address,
action: GovernanceActionType,
fee: u128,
nonce: u64,
gas_limit: u64,
},


Custom {
call_type: String,
payload: Vec<u8>,
fee: u128,
nonce: u64,
gas_limit: u64,
resource_class: ResourceClass,
metadata_flagged: bool,
},
}

#[derive(Debug, Clone)]
pub struct PrivateTxInfo {
pub sender: Address,
pub fee: u128,
pub gas_limit: u64,
pub nonce: u64,
pub resource_class: ResourceClass,
}


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TxEnvelope {
pub payload: TxPayload,
pub pubkey: Vec<u8>,
pub signature: Vec<u8>,
pub is_private: bool,
#[serde(skip)]
pub cached_id: Option<Hash>,
}

impl TxEnvelope {
pub fn new_unsigned(payload: TxPayload) -> Self {
Self {
payload: payload,
pubkey: Vec::new(),
signature: Vec::new(),
is_private: false,
cached_id: None,
}
}

pub fn payload_bytes(&self) -> Result<Vec<u8>> {
bincode::serialize(&self.payload).map_err(Into::into)
}

pub fn sign_input_bytes(&self) -> Result<Vec<u8>> {
let mut out = Vec::new();
out.extend_from_slice(&bincode::serialize(&self.payload)?);
out.extend_from_slice(&self.pubkey);
Ok(out)
}

pub fn compute_txid(&self) -> Result<Hash> {
let mut buf = Vec::new();
buf.extend_from_slice(&bincode::serialize(&self.payload)?);
buf.extend_from_slice(&self.pubkey);
buf.extend_from_slice(&self.signature);
Ok(Hash::from_bytes(sha3_512_bytes(&buf)))
}

pub fn txid_hex(&self) -> Result<String> {
Ok(self.compute_txid()?.to_hex())
}

pub fn verify_signature(&self) -> Result<bool> {
if self.pubkey.is_empty() || self.signature.is_empty() {
return Ok(false);
}
let payload_bytes = self.payload_bytes()?;
verify_signature(&self.pubkey, &payload_bytes, &self.signature)
}

pub fn sender_address(&self) -> Result<Option<Address>> {
if self.pubkey.is_empty() {
return Ok(None);
}
address_from_pubkey_bytes(&self.pubkey).map(Some)
}


pub fn is_private(&self) -> bool {
self.is_private
}


pub fn set_private(&mut self, private: bool) {
self.is_private = private;
}


pub fn new_private(payload: TxPayload) -> Self {
Self {
payload: payload,
pubkey: Vec::new(),
signature: Vec::new(),
is_private: true,
cached_id: None,
}
}




pub fn get_private_validation_info(&self) -> Option<PrivateTxInfo> {
if !self.is_private {
return None;
}

let (fee, gas_limit, nonce) = self.payload.get_blind_info();
let sender = self.sender_address().ok().flatten()?;

Some(PrivateTxInfo {
sender: sender,
fee: fee,
gas_limit: gas_limit,
nonce: nonce,
resource_class: self.payload.resource_class(),
})
}

pub fn validate_stateless(&self) -> Result<()> {
if self.signature.is_empty() || self.pubkey.is_empty() {
return Err(anyhow!("missing pubkey or signature"));
}
if !self.verify_signature()? {
return Err(anyhow!("invalid signature"));
}



self.payload.validate_stake_requirements()?;


if self.is_private {
return Ok(());
}

if let Some(sender) = self.sender_address()? {
match &self.payload {
TxPayload::Transfer { from, .. } => {
if &sender != from {
Err(anyhow!("from mismatch"))?
}
},
TxPayload::Stake { delegator, .. } => {
if &sender != delegator {
Err(anyhow!("delegator mismatch"))?
}
},
TxPayload::Unstake { delegator, .. } => {
if &sender != delegator {
Err(anyhow!("delegator mismatch"))?
}
},
TxPayload::ClaimReward { receipt, .. } => {

if sender != receipt.node_address {
return Err(anyhow!("sender does not match receipt.node_address"));
}

if receipt.reward_base == 0 {
return Err(anyhow!("receipt.reward_base must be greater than 0"));
}
if receipt.timestamp == 0 {
return Err(anyhow!("receipt.timestamp must be greater than 0"));
}
},
TxPayload::StorageOperationPayment { from, .. } => {
if &sender != from {
Err(anyhow!("from mismatch"))?
}
},
TxPayload::ComputeExecutionPayment { from, .. } => {
if &sender != from {
Err(anyhow!("from mismatch"))?
}
},
TxPayload::ValidatorRegistration { from, .. } => {
if &sender != from {
Err(anyhow!("from mismatch"))?
}
},
TxPayload::GovernanceAction { from, .. } => {
if &sender != from {
Err(anyhow!("from mismatch"))?
}
},
TxPayload::Custom { .. } => {  },
}
}
Ok(())
}

pub fn validate_stateful<F1, F2>(&self, mut get_balance: F1, mut get_nonce: F2) -> Result<()>
where
F1: FnMut(&Address) -> u128,
F2: FnMut(&Address) -> u64,
{

if self.is_private {
return self.validate_private_tx(get_balance, get_nonce);
}


let sender: &Address = match &self.payload {
TxPayload::Transfer { from, .. }
| TxPayload::Stake { delegator: from, .. }
| TxPayload::Unstake { delegator: from, .. }
| TxPayload::StorageOperationPayment { from, .. }
| TxPayload::ComputeExecutionPayment { from, .. }
| TxPayload::ValidatorRegistration { from, .. }
| TxPayload::GovernanceAction { from, .. } => { from },

TxPayload::ClaimReward { receipt, .. } => { &receipt.node_address },

TxPayload::Custom { .. } => {
return self.validate_stateful_custom(get_balance, get_nonce);
},
};

let (gas_limit, fee, nonce, extra_amount) = match &self.payload {
TxPayload::Transfer { gas_limit, fee, nonce, amount, .. } => { (*gas_limit, *fee, *nonce, *amount) },
TxPayload::Stake { gas_limit, fee, nonce, amount, .. } => { (*gas_limit, *fee, *nonce, *amount) },
TxPayload::Unstake { gas_limit, fee, nonce, amount, .. } => { (*gas_limit, *fee, *nonce, *amount) },
TxPayload::ClaimReward { gas_limit, fee, nonce, .. } => { (*gas_limit, *fee, *nonce, 0u128) },
TxPayload::StorageOperationPayment { gas_limit, fee, nonce, amount, .. } => { (*gas_limit, *fee, *nonce, *amount) },
TxPayload::ComputeExecutionPayment { gas_limit, fee, nonce, amount, .. } => { (*gas_limit, *fee, *nonce, *amount) },
TxPayload::ValidatorRegistration { gas_limit, fee, nonce, min_stake, .. } => { (*gas_limit, *fee, *nonce, *min_stake) },
TxPayload::GovernanceAction { gas_limit, fee, nonce, .. } => { (*gas_limit, *fee, *nonce, 0) },
_ => { unreachable!() },
};


if gas_limit < MIN_GAS_LIMIT {
return Err(anyhow!("gas_limit too low"));
}


let expected_nonce = get_nonce(sender) + 1;
if nonce != expected_nonce {
return Err(anyhow!("invalid nonce: expected {}, got {}", expected_nonce, nonce));
}


let gas_cost = (gas_limit as u128) * crate::tx::GAS_PRICE;
let total_required = fee + &extra_amount + &gas_cost;
let balance = get_balance(sender);

if balance < total_required {
return Err(anyhow!(
"insufficient balance: have {}, need {} (amount: {} + fee: {} + gas_cost: {})",
balance,
total_required,
extra_amount,
fee,
gas_cost
))
}

Ok(())
}


fn validate_stateful_custom<F1, F2>(&self, mut get_balance: F1, mut get_nonce: F2) -> Result<()>
where
F1: FnMut(&Address) -> u128,
F2: FnMut(&Address) -> u64,
{
let sender = self.sender_address()?.ok_or_else(|| anyhow!("custom tx requires sender"))?;

let (gas_limit, fee, nonce) = match &self.payload {
TxPayload::Custom { gas_limit, fee, nonce, .. } => { (*gas_limit, *fee, *nonce) },
_ => { unreachable!() },
};

if gas_limit < MIN_GAS_LIMIT {
return Err(anyhow!("gas_limit too low"));
}

let expected_nonce = get_nonce(&sender) + 1;
if nonce != expected_nonce {
return Err(anyhow!("invalid nonce: expected {}, got {}", expected_nonce, nonce));
}

let gas_cost = (gas_limit as u128) * crate::tx::GAS_PRICE;
let total_required = fee + &gas_cost;
let balance = get_balance(&sender);

if balance < total_required {
return Err(anyhow!("insufficient balance for custom tx"));
}

Ok(())
}

fn validate_private_tx<F1, F2>(&self, mut get_balance: F1, mut get_nonce: F2) -> Result<()>
where
F1: FnMut(&Address) -> u128,
F2: FnMut(&Address) -> u64,
{
let sender = self.sender_address()?.ok_or_else(|| anyhow!("private tx requires sender"))?;



let (gas_limit, fee, nonce) = match &self.payload {
TxPayload::Transfer { gas_limit, fee, nonce, .. }
| TxPayload::Stake { gas_limit, fee, nonce, .. }
| TxPayload::Unstake { gas_limit, fee, nonce, .. }
| TxPayload::ClaimReward { gas_limit, fee, nonce, .. }
| TxPayload::StorageOperationPayment { gas_limit, fee, nonce, .. }
| TxPayload::ComputeExecutionPayment { gas_limit, fee, nonce, .. }
| TxPayload::ValidatorRegistration { gas_limit, fee, nonce, .. }
| TxPayload::GovernanceAction { gas_limit, fee, nonce, .. }
| TxPayload::Custom { gas_limit, fee, nonce, .. } => { (*gas_limit, *fee, *nonce) },
};


if gas_limit < MIN_GAS_LIMIT {
return Err(anyhow!("gas_limit too low"));
}

let expected_nonce = get_nonce(&sender) + 1;
if nonce != expected_nonce {
return Err(anyhow!("invalid nonce: expected {}, got {}", expected_nonce, nonce));
}


let gas_cost = (gas_limit as u128) * crate::tx::GAS_PRICE;
let total_required = fee + &gas_cost;
let balance = get_balance(&sender);

if balance < total_required {
return Err(anyhow!("insufficient balance for private tx (fee + gas)"));
}

Ok(())
}
}

impl TxPayload {
pub fn with_resource_class(mut self, class: ResourceClass) -> Self {
match &mut self {
TxPayload::Transfer { resource_class, .. }
| TxPayload::Stake { resource_class, .. }
| TxPayload::Unstake { resource_class, .. }
| TxPayload::StorageOperationPayment { resource_class, .. }
| TxPayload::ComputeExecutionPayment { resource_class, .. }
| TxPayload::ValidatorRegistration { resource_class, .. }
| TxPayload::Custom { resource_class, .. } => {
*resource_class = class
}
TxPayload::ClaimReward { .. } => {

},
TxPayload::GovernanceAction { .. } => {

},
}
self
}

pub fn resource_class(&self) -> ResourceClass {
match self {
TxPayload::Transfer { .. } => { ResourceClass::Transfer },

TxPayload::Stake { .. }
| TxPayload::Unstake { .. }
| TxPayload::ValidatorRegistration { .. }
| TxPayload::GovernanceAction { .. }
| TxPayload::Custom { .. } => { ResourceClass::Governance },

TxPayload::StorageOperationPayment { .. } => { ResourceClass::Storage },

TxPayload::ComputeExecutionPayment { .. } => { ResourceClass::Compute },

TxPayload::ClaimReward { receipt, .. } => {
match receipt.resource_type {
ResourceType::Storage => { ResourceClass::Storage },
ResourceType::Compute => { ResourceClass::Compute },
}
},
}
}


pub fn is_flagged_illegal(&self) -> bool {
match self {
TxPayload::Transfer { metadata_flagged, .. }
| TxPayload::Stake { metadata_flagged, .. }
| TxPayload::Unstake { metadata_flagged, .. }
| TxPayload::StorageOperationPayment { metadata_flagged, .. }
| TxPayload::ComputeExecutionPayment { metadata_flagged, .. }
| TxPayload::ValidatorRegistration { metadata_flagged, .. }
| TxPayload::Custom { metadata_flagged, .. } => { *metadata_flagged },
TxPayload::GovernanceAction { .. } => { false },
TxPayload::ClaimReward { .. } => { false },
}
}


pub fn get_nonce(&self) -> Option<u64> {
match self {
TxPayload::Transfer { nonce, .. }
| TxPayload::Stake { nonce, .. }
| TxPayload::Unstake { nonce, .. }
| TxPayload::ClaimReward { nonce, .. }
| TxPayload::StorageOperationPayment { nonce, .. }
| TxPayload::ComputeExecutionPayment { nonce, .. }
| TxPayload::ValidatorRegistration { nonce, .. }
| TxPayload::GovernanceAction { nonce, .. }
| TxPayload::Custom { nonce, .. } => { Some(*nonce) },
}
}


pub fn get_sender(&self) -> Option<Address> {
match self {
TxPayload::Transfer { from, .. } => { Some(*from) },
TxPayload::Stake { delegator, .. } => { Some(*delegator) },
TxPayload::Unstake { delegator, .. } => { Some(*delegator) },
TxPayload::ClaimReward { receipt, .. } => { Some(receipt.node_address) },
TxPayload::StorageOperationPayment { from, .. } => { Some(*from) },
TxPayload::ComputeExecutionPayment { from, .. } => { Some(*from) },
TxPayload::ValidatorRegistration { from, .. } => { Some(*from) },
TxPayload::GovernanceAction { from, .. } => { Some(*from) },
TxPayload::Custom { .. } => { None },
}
}



pub fn validate_stake_requirements(&self) -> Result<()> {
match self {
TxPayload::Stake { delegator, validator, amount, bond, .. } => {

if *bond {

if *amount < crate::tokenomics::DELEGATOR_MIN_STAKE {
return Err(anyhow!(
"stake below minimum: {} < {}",
amount,
crate::tokenomics::DELEGATOR_MIN_STAKE
))
}




if delegator != validator {


println!("📋 External delegation request: {} → {}", delegator, validator)
}
}
Ok(())
},
TxPayload::ValidatorRegistration { min_stake, .. } => {

if *min_stake < crate::tokenomics::VALIDATOR_MIN_STAKE {
return Err(anyhow!(
"validator stake below minimum: {} < {}",
min_stake,
crate::tokenomics::VALIDATOR_MIN_STAKE
))
}
Ok(())
},

_ => { Ok(()) },
}
}



pub fn is_validator_fee_eligible(&self) -> bool {
crate::tokenomics::is_validator_fee_eligible(&self.resource_class())
}







pub fn is_self_delegation(&self) -> bool {
match self {
TxPayload::Stake { delegator, validator, .. } => { delegator == validator },
_ => { false },
}
}


pub fn is_external_delegation(&self) -> bool {
match self {
TxPayload::Stake { delegator, validator, bond, .. } => {
*bond && delegator != validator
},
_ => { false },
}
}


pub fn get_delegation_info(&self) -> Option<(Address, Address)> {
match self {
TxPayload::Stake { delegator, validator, .. } => { Some((*delegator, *validator)) },
TxPayload::Unstake { delegator, validator, .. } => { Some((*delegator, *validator)) },
_ => { None },
}
}






pub fn get_stake_amount(&self) -> Option<u128> {
match self {
TxPayload::Stake { amount, .. } => { Some(*amount) },
TxPayload::Unstake { amount, .. } => { Some(*amount) },
TxPayload::ValidatorRegistration { min_stake, .. } => { Some(*min_stake) },
_ => { None },
}
}



pub fn affects_qv_weight(&self) -> bool {
matches!(
self,
TxPayload::Stake { .. }
| TxPayload::Unstake { .. }
| TxPayload::ValidatorRegistration { .. }
)
}



pub fn get_qv_update_addresses(&self) -> Option<(Address, Option<Address>)> {
match self {
TxPayload::Stake { delegator, validator, .. } => {
Some((*delegator, Some(*validator)))
},
TxPayload::Unstake { delegator, validator, .. } => {
Some((*delegator, Some(*validator)))
},
TxPayload::ValidatorRegistration { from, .. } => {
Some((*from, Some(*from)))
},
_ => { None },
}
}







pub fn get_blind_info(&self) -> (u128, u64, u64) {
match self {
TxPayload::Transfer { fee, gas_limit, nonce, .. }
| TxPayload::Stake { fee, gas_limit, nonce, .. }
| TxPayload::Unstake { fee, gas_limit, nonce, .. }
| TxPayload::ClaimReward { fee, gas_limit, nonce, .. }
| TxPayload::StorageOperationPayment { fee, gas_limit, nonce, .. }
| TxPayload::ComputeExecutionPayment { fee, gas_limit, nonce, .. }
| TxPayload::ValidatorRegistration { fee, gas_limit, nonce, .. }
| TxPayload::GovernanceAction { fee, gas_limit, nonce, .. }
| TxPayload::Custom { fee, gas_limit, nonce, .. } => { (*fee, *gas_limit, *nonce) },
}
}


pub fn get_fee(&self) -> u128 {
self.get_blind_info().0
}


pub fn get_gas_limit(&self) -> u64 {
self.get_blind_info().1
}
}

#[cfg(test)]
mod tests {
use super::*;
use crate::crypto::{generate_ed25519_keypair_bytes, address_from_pubkey_bytes};
use crate::state::ChainState;

#[test]
fn test_transfer_sign_verify_and_stateful_validate() {
let (pk, kp_bytes) = generate_ed25519_keypair_bytes();
let from_addr = address_from_pubkey_bytes(&pk).expect("addr");
let to_addr = Address::from_bytes([0x22u8; 20]);
let payload = TxPayload::Transfer {
from: from_addr,
to: to_addr,
amount: 1_000,
fee: 10,
nonce: 1,
gas_limit: 21000,
resource_class: ResourceClass::Transfer,
metadata_flagged: false,
};
let mut env = TxEnvelope::new_unsigned(payload.clone());
env.pubkey = pk.clone();
env.is_private = false;
let payload_bytes = env.payload_bytes().expect("payload bytes");
let sig = crate::crypto::sign_message_with_keypair_bytes(&kp_bytes, &payload_bytes).expect("sign");
env.signature = sig;
env.validate_stateless().expect("stateless ok");
let mut st = ChainState::new();
st.create_account(from_addr);
st.create_account(to_addr);
st.mint(&from_addr, 50_000).expect("mint");
let get_balance = |a: &Address| st.get_balance(a);
let get_nonce = |_a: &Address| -> u64 { 0u64 };
env.validate_stateful(get_balance, get_nonce).expect("stateful ok");
}
}