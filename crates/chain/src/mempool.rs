


use crate::tx::{TxEnvelope, TxPayload};
use crate::types::Hash;
use parking_lot::RwLock;
use std::sync::Arc;
use std::collections::{BinaryHeap, HashMap};
use std::cmp::Ordering;
use anyhow::Result;
use std::time::{SystemTime, UNIX_EPOCH};


#[derive(Clone)]
struct Entry {
txid: Hash,
fee: u128,
ts: u128,
tx: TxEnvelope,
resource_class: crate::tx::ResourceClass,
is_private: bool,
}

impl Entry {
fn new(txid: Hash, fee: u128, tx: TxEnvelope) -> Self {
let ts = SystemTime::now()
.duration_since(UNIX_EPOCH)
.unwrap_or_default()
.as_millis() as u128;
let mut resource_class = tx.payload.resource_class();
let is_private = tx.is_private();
Self { txid: txid, fee: fee, ts: ts, tx: tx, resource_class: resource_class, is_private: is_private }
}


fn weight(&self) -> u128 {
match self.resource_class {
crate::tx::ResourceClass::Transfer => { 1 },
crate::tx::ResourceClass::Storage => { 10 },
crate::tx::ResourceClass::Compute => { 100 },
crate::tx::ResourceClass::Governance => { 10 },
}
}



fn age_bonus(&self) -> u128 {
let now = SystemTime::now()
.duration_since(UNIX_EPOCH)
.unwrap_or_default()
.as_millis() as u128;
let age_ms = now.saturating_sub(self.ts);
let age_seconds = age_ms / 1000;
age_seconds.min(86_400)
}
}


impl PartialEq for Entry {
fn eq(&self, other: &Self) -> bool {
self.fee == other.fee && self.ts == other.ts && self.txid == other.txid
}
}

impl Eq for Entry {}

impl PartialOrd for Entry {

fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
Some(self.cmp(other))
}
}

impl Ord for Entry {
fn cmp(&self, other: &Self) -> Ordering {

let score_self = self.fee
.saturating_mul(self.weight())
.saturating_add(self.age_bonus());

let score_other = other.fee
.saturating_mul(other.weight())
.saturating_add(other.age_bonus());


match score_self.cmp(&score_other) {
Ordering::Equal => {

other.ts.cmp(&self.ts)
},
ord => { ord },
}
}
}


#[derive(Clone)]
pub struct Mempool {
map: Arc<RwLock<HashMap<String, Entry>>>,
heap: Arc<RwLock<BinaryHeap<Entry>>>,
nonce_map: Arc<RwLock<HashMap<String, String>>>,


transfer_count: Arc<RwLock<usize>>,
storage_count: Arc<RwLock<usize>>,
compute_count: Arc<RwLock<usize>>,
governance_count: Arc<RwLock<usize>>,


rejected_count: Arc<RwLock<usize>>,


private_count: Arc<RwLock<usize>>,
}

impl Mempool {
pub fn new() -> Self {
Self {
map: Arc::new(RwLock::new(HashMap::new())),
heap: Arc::new(RwLock::new(BinaryHeap::new())),
nonce_map: Arc::new(RwLock::new(HashMap::new())),
transfer_count: Arc::new(RwLock::new(0)),
storage_count: Arc::new(RwLock::new(0)),
compute_count: Arc::new(RwLock::new(0)),
governance_count: Arc::new(RwLock::new(0)),
rejected_count: Arc::new(RwLock::new(0)),
private_count: Arc::new(RwLock::new(0)),
}
}


pub fn add(&self, tx: TxEnvelope) -> Result<String> {
let txid = tx.compute_txid()?;
let txid_hex = txid.to_hex();


{
if self.map.read().contains_key(&txid_hex) {
*self.rejected_count.write() += 1;
anyhow::bail!("tx already in mempool (duplicate txid)")
}
}


let sender_opt = tx.payload.get_sender().or_else(|| tx.sender_address().ok().flatten());
let nonce_opt = tx.payload.get_nonce();

if let (Some(sender), Some(nonce)) = (sender_opt, nonce_opt) {
let nonce_key = format!("{}|{}", sender, nonce);

if self.nonce_map.read().contains_key(&nonce_key) {
*self.rejected_count.write() += 1;
println!("❌ Rejected: duplicate (sender, nonce) = ({}, {})", sender, nonce);
anyhow::bail!("tx with same sender and nonce already exists")
}


self.nonce_map.write().insert(nonce_key.clone(), txid_hex.clone());
}


let fee = match &tx.payload {
TxPayload::Transfer { fee, .. }
| TxPayload::Stake { fee, .. }
| TxPayload::Unstake { fee, .. }
| TxPayload::ClaimReward { fee, .. }
| TxPayload::StorageOperationPayment { fee, .. }
| TxPayload::ComputeExecutionPayment { fee, .. }
| TxPayload::ValidatorRegistration { fee, .. }
| TxPayload::GovernanceAction { fee, .. }
| TxPayload::Custom { fee, .. } => { *fee },
};
let mut resource_class = tx.payload.resource_class();



const MAX_TOTAL_TX: usize = 30_000;
const MAX_STORAGE_TX: usize = 10_000;
const MAX_COMPUTE_TX: usize = 10_000;

let total_count = self.len();
if total_count >= MAX_TOTAL_TX {
*self.rejected_count.write() += 1;
println!("❌ Rejected: mempool full (total = {})", total_count);
anyhow::bail!("mempool full: total tx limit reached ({})", MAX_TOTAL_TX)
}

match resource_class {
crate::tx::ResourceClass::Storage => {
let mut count = *self.storage_count.read();
if count >= MAX_STORAGE_TX {
*self.rejected_count.write() += 1;
println!("❌ Rejected: storage mempool full (count = {})", count);
anyhow::bail!("storage mempool full (limit: {})", MAX_STORAGE_TX)
}
},
crate::tx::ResourceClass::Compute => {
let mut count = *self.compute_count.read();
if count >= MAX_COMPUTE_TX {
*self.rejected_count.write() += 1;
println!("❌ Rejected: compute mempool full (count = {})", count);
anyhow::bail!("compute mempool full (limit: {})", MAX_COMPUTE_TX)
}
},
_ => {  },
}

println!("Mempool: added tx with resource_class {:?}", resource_class);

let entry = Entry::new(txid, fee, tx.clone());

{
self.map.write().insert(txid_hex.clone(), entry.clone());
}
{
self.heap.write().push(entry);
}


match resource_class {
crate::tx::ResourceClass::Transfer => { *self.transfer_count.write() += 1 },
crate::tx::ResourceClass::Storage => { *self.storage_count.write() += 1 },
crate::tx::ResourceClass::Compute => { *self.compute_count.write() += 1 },
crate::tx::ResourceClass::Governance => { *self.governance_count.write() += 1 },
}

if tx.is_private() {
*self.private_count.write() += 1;
println!("🔒 Private transaction added to mempool (will be relayed only)");
println!("   ⚠️  Validator will NOT read payload details")
}


self.print_metrics();

Ok(txid_hex)
}


pub fn add_from_db(&self, tx: TxEnvelope) -> Result<()> {
let txid = tx.compute_txid()?;
let txid_hex = txid.to_hex();


{
if self.map.read().contains_key(&txid_hex) {
return Ok(());
}
}


let sender_opt = tx.payload.get_sender().or_else(|| tx.sender_address().ok().flatten());
let nonce_opt = tx.payload.get_nonce();

if let (Some(sender), Some(nonce)) = (sender_opt, nonce_opt) {
let nonce_key = format!("{}|{}", sender, nonce);

if self.nonce_map.read().contains_key(&nonce_key) {
return Ok(());
}

self.nonce_map.write().insert(nonce_key, txid_hex.clone());
}


let fee = match &tx.payload {
TxPayload::Transfer { fee, .. }
| TxPayload::Stake { fee, .. }
| TxPayload::Unstake { fee, .. }
| TxPayload::ClaimReward { fee, .. }
| TxPayload::StorageOperationPayment { fee, .. }
| TxPayload::ComputeExecutionPayment { fee, .. }
| TxPayload::ValidatorRegistration { fee, .. }
| TxPayload::GovernanceAction { fee, .. }
| TxPayload::Custom { fee, .. } => { *fee },
};

let entry = Entry::new(txid, fee, tx.clone());

let mut resource_class = entry.resource_class;

{
self.map.write().insert(txid_hex.clone(), entry.clone());
}
{
self.heap.write().push(entry);
}


match resource_class {
crate::tx::ResourceClass::Transfer => { *self.transfer_count.write() += 1 },
crate::tx::ResourceClass::Storage => { *self.storage_count.write() += 1 },
crate::tx::ResourceClass::Compute => { *self.compute_count.write() += 1 },
crate::tx::ResourceClass::Governance => { *self.governance_count.write() += 1 },
}

println!("Mempool: restored tx {} from DB (resource_class: {:?})", txid_hex, resource_class);

if tx.is_private() {
*self.private_count.write() += 1;
println!("🔒 Private transaction restored from DB (blind relay mode)")
}

Ok(())
}



pub fn pop_by_resource(&self, limit: usize, rclass: crate::tx::ResourceClass) -> Vec<TxEnvelope> {
let mut out = Vec::with_capacity(limit);
let mut temp_storage: Vec<Entry> = Vec::new();


while out.len() < limit {
let mut entry_opt = self.heap.write().pop();

match entry_opt {
Some(entry) => {

if entry.resource_class == rclass {

let txid_hex = entry.txid.to_hex();
self.map.write().remove(&txid_hex);


let sender_opt = entry.tx.payload.get_sender()
.or_else(|| entry.tx.sender_address().ok().flatten());
let nonce_opt = entry.tx.payload.get_nonce();

if let (Some(sender), Some(nonce)) = (sender_opt, nonce_opt) {
let nonce_key = format!("{}|{}", sender, nonce);
self.nonce_map.write().remove(&nonce_key);
}


match entry.resource_class {
crate::tx::ResourceClass::Transfer => {
let mut count = self.transfer_count.write();
*count = count.saturating_sub(1)
},
crate::tx::ResourceClass::Storage => {
let mut count = self.storage_count.write();
*count = count.saturating_sub(1)
},
crate::tx::ResourceClass::Compute => {
let mut count = self.compute_count.write();
*count = count.saturating_sub(1)
},
crate::tx::ResourceClass::Governance => {
let mut count = self.governance_count.write();
*count = count.saturating_sub(1)
},
}


if entry.is_private {
let mut count = self.private_count.write();
*count = count.saturating_sub(1)
}

out.push(entry.tx);
} else {

temp_storage.push(entry);
}
},
None => { break },
}
}


{
let mut heap = self.heap.write();
for entry in temp_storage {
heap.push(entry);
}
}

println!("📦 Popped {} tx(s) for resource_class {:?}", out.len(), rclass);
out
}



pub fn pop_mixed(&self, total_limit: usize) -> Vec<TxEnvelope> {
let mut out = Vec::with_capacity(total_limit.min(self.len()));

for _ in 0..total_limit {
let mut entry_opt = self.heap.write().pop();
if let Some(entry) = entry_opt {
let txid_hex = entry.txid.to_hex();
self.map.write().remove(&txid_hex);


let sender_opt = entry.tx.payload.get_sender()
.or_else(|| entry.tx.sender_address().ok().flatten());
let nonce_opt = entry.tx.payload.get_nonce();

if let (Some(sender), Some(nonce)) = (sender_opt, nonce_opt) {
let nonce_key = format!("{}|{}", sender, nonce);
self.nonce_map.write().remove(&nonce_key);
}


match entry.resource_class {
crate::tx::ResourceClass::Transfer => {
let mut count = self.transfer_count.write();
*count = count.saturating_sub(1)
},
crate::tx::ResourceClass::Storage => {
let mut count = self.storage_count.write();
*count = count.saturating_sub(1)
},
crate::tx::ResourceClass::Compute => {
let mut count = self.compute_count.write();
*count = count.saturating_sub(1)
},
crate::tx::ResourceClass::Governance => {
let mut count = self.governance_count.write();
*count = count.saturating_sub(1)
},
}

out.push(entry.tx);
} else {
break
}
}

println!("📦 Popped {} tx(s) in mixed mode (all resource classes)", out.len());
out
}


pub fn pop_for_block(&self, limit: usize) -> Vec<TxEnvelope> {
let result = self.pop_mixed(limit);


if !result.is_empty() {
self.print_metrics()
}

result
}



pub fn snapshot(&self) -> Vec<TxEnvelope> {
self.map.read().values().map(|e| e.tx.clone()).collect()
}


pub fn len(&self) -> usize {
self.map.read().len()
}



pub fn private_count(&self) -> usize {
*self.private_count.read()
}



pub fn is_tx_private(&self, txid_hex: &str) -> Option<bool> {
self.map.read().get(txid_hex).map(|e| e.is_private)
}



pub fn remove(&self, txid_hex: &str) -> bool {
if let Some(entry) = self.map.write().remove(txid_hex) {

let sender_opt = entry.tx.payload.get_sender()
.or_else(|| entry.tx.sender_address().ok().flatten());
let nonce_opt = entry.tx.payload.get_nonce();

if let (Some(sender), Some(nonce)) = (sender_opt, nonce_opt) {
let nonce_key = format!("{}|{}", sender, nonce);
self.nonce_map.write().remove(&nonce_key);
}


match entry.resource_class {
crate::tx::ResourceClass::Transfer => {
*self.transfer_count.write() = self.transfer_count.read().saturating_sub(1)
},
crate::tx::ResourceClass::Storage => {
*self.storage_count.write() = self.storage_count.read().saturating_sub(1)
},
crate::tx::ResourceClass::Compute => {
*self.compute_count.write() = self.compute_count.read().saturating_sub(1)
},
crate::tx::ResourceClass::Governance => {
*self.governance_count.write() = self.governance_count.read().saturating_sub(1)
},
}


let mut heap = self.heap.write();
heap.clear();
for e in self.map.read().values() {
heap.push(e.clone());
}
true
} else {
false
}
}

pub fn print_metrics(&self) {
let total = self.len();
let transfer = *self.transfer_count.read();
let storage = *self.storage_count.read();
let compute = *self.compute_count.read();
let governance = *self.governance_count.read();
let rejected = *self.rejected_count.read();
let private = *self.private_count.read();


let oldest_age_ms = self.map.read()
.values()
.map(|e| {
let now = SystemTime::now()
.duration_since(UNIX_EPOCH)
.unwrap_or_default()
.as_millis() as u128;
now.saturating_sub(e.ts)
})
.max()
.unwrap_or(0);

let oldest_age_sec = oldest_age_ms / 1000;

println!("📊 === MEMPOOL METRICS ===");
println!("   Total TX: {}", total);
println!("   Transfer: {}", transfer);
println!("   Storage: {} / 10000", storage);
println!("   Compute: {} / 10000", compute);
println!("   Governance: {}", governance);
println!("   🔒 Private: {} (blind relay)", private);
println!("   Rejected: {}", rejected);
println!("   Oldest TX age: {}s", oldest_age_sec);
println!("========================");
}
}


#[cfg(test)]
mod tests {
use super::*;
use crate::tx::{TxPayload, TxEnvelope, ResourceClass};
use crate::crypto::{generate_ed25519_keypair_bytes, sign_message_with_keypair_bytes, address_from_pubkey_bytes};

#[test]
fn mempool_add_pop_new_payloads() {
let (pk, kp_bytes) = generate_ed25519_keypair_bytes();
let addr = address_from_pubkey_bytes(&pk).unwrap();

let payload = TxPayload::StorageOperationPayment {
from: addr,
to_node: addr,
amount: 1000,
fee: 50,
nonce: 0,
operation_id: vec!(1, 2, 3),
gas_limit: 25000,
resource_class: ResourceClass::Storage,
metadata_flagged: false,
};

let mut env = TxEnvelope::new_unsigned(payload);
env.pubkey = pk.clone();
env.is_private = false;
let sig_bytes = env.payload_bytes().unwrap();
env.signature = sign_message_with_keypair_bytes(&kp_bytes, &sig_bytes).unwrap();

let mem = Mempool::new();
mem.add(env.clone()).unwrap();
assert_eq!(mem.len(), 1);

let txs = mem.pop_for_block(10);
assert_eq!(txs.len(), 1);
assert_eq!(mem.len(), 0);
}

#[test]
fn mempool_pop_by_resource_filter() {
let (pk, kp_bytes) = generate_ed25519_keypair_bytes();
let addr = address_from_pubkey_bytes(&pk).unwrap();

let mem = Mempool::new();


let storage_payload = TxPayload::StorageOperationPayment {
from: addr,
to_node: addr,
amount: 1000,
fee: 50,
nonce: 0,
operation_id: vec!(1, 2, 3),
gas_limit: 25000,
resource_class: ResourceClass::Storage,
metadata_flagged: false,
};
let mut storage_env = TxEnvelope::new_unsigned(storage_payload);
storage_env.pubkey = pk.clone();
storage_env.is_private = false;
let sig_bytes = storage_env.payload_bytes().unwrap();
storage_env.signature = sign_message_with_keypair_bytes(&kp_bytes, &sig_bytes).unwrap();
mem.add(storage_env).unwrap();


let compute_payload = TxPayload::ComputeExecutionPayment {
from: addr,
to_node: addr,
amount: 2000,
fee: 100,
nonce: 1,
execution_id: vec!(4, 5, 6),
gas_limit: 40000,
resource_class: ResourceClass::Compute,
metadata_flagged: false,
};
let mut compute_env = TxEnvelope::new_unsigned(compute_payload);
compute_env.pubkey = pk.clone();
compute_env.is_private = false;
let sig_bytes2 = compute_env.payload_bytes().unwrap();
compute_env.signature = sign_message_with_keypair_bytes(&kp_bytes, &sig_bytes2).unwrap();
mem.add(compute_env).unwrap();

assert_eq!(mem.len(), 2);


let storage_txs = mem.pop_by_resource(10, ResourceClass::Storage);
assert_eq!(storage_txs.len(), 1);
assert_eq!(mem.len(), 1);


let compute_txs = mem.pop_by_resource(10, ResourceClass::Compute);
assert_eq!(compute_txs.len(), 1);
assert_eq!(mem.len(), 0);
}
}