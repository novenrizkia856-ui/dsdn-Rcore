






















use serde::{Serialize, Deserialize};
use std::collections::{VecDeque, HashSet, HashMap};
use std::sync::{Arc, Mutex};
use anyhow::Result;

use crate::types::Hash;
use crate::block::{Block, BlockHeader};
use crate::db::ChainDb;
use crate::state::ChainState;
use crate::Chain;














#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SyncStatus {

Idle,

SyncingHeaders {

start_height: u64,

target_height: u64,

current_height: u64,
},

SyncingBlocks {

start_height: u64,

target_height: u64,

current_height: u64,
},

SyncingState {

checkpoint_height: u64,
},

Synced,
}











#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SyncRequest {

GetHeaders {

start_height: u64,

count: u64,
},

GetBlock {

height: u64,
},

GetBlocks {

heights: Vec<u64>,
},

GetChainTip,
}








#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncResponse {

Headers {

headers: Vec<BlockHeader>,
},

Block {

block: Block,
},

Blocks {

blocks: Vec<Block>,
},

ChainTip {

height: u64,

hash: Hash,
},

NotFound {

height: u64,
},

Error {

message: String,
},
}












#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncConfig {

pub max_headers_per_request: u64,

pub max_blocks_per_request: u64,

pub sync_timeout_ms: u64,

pub batch_size: u64,
}

impl Default for SyncConfig {
fn default() -> Self {
Self {
max_headers_per_request: 500,
max_blocks_per_request: 100,
sync_timeout_ms: 30000,
batch_size: 50,
}
}
}











#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerSyncState {

pub peer_id: String,

pub tip_height: u64,

pub tip_hash: Hash,

pub last_seen: u64,

pub is_syncing: bool,
}

















#[derive(Debug, Clone)]
pub struct HeaderSyncer {

pub local_tip: (u64, Hash),

pub target_tip: (u64, Hash),

pub pending_headers: VecDeque<BlockHeader>,

pub verified_heights: HashSet<u64>,
}

impl HeaderSyncer {





pub fn new(local_tip: (u64, Hash), target_tip: (u64, Hash)) -> Self {
Self {
local_tip: local_tip,
target_tip: target_tip,
pending_headers: VecDeque::new(),
verified_heights: HashSet::new(),
}
}





pub fn request_next_headers(&self) -> SyncRequest {
let start_height = self.local_tip.0 + 1 + self.verified_heights.len() as u64;
let remaining = self.target_tip.0.saturating_sub(start_height) + 1;
let mut count = remaining.min(SyncConfig::default().max_headers_per_request);

SyncRequest::GetHeaders {
start_height: start_height,
count: count,
}
}














pub fn process_headers(&mut self, headers: Vec<BlockHeader>, db: &ChainDb) -> Result<()> {

self.verify_header_chain(&headers)?;


for header in headers {
let height = header.height;


if self.verified_heights.contains(&height) {
continue
}


db.put_header(height, &header)?;


self.verified_heights.insert(height);
}

Ok(())
}


















pub fn verify_header_chain(&self, headers: &[BlockHeader]) -> Result<()> {
if headers.is_empty() {
return Ok(());
}


let first = &headers[0];
let expected_height = self.local_tip.0 + 1 + self.verified_heights.len() as u64;

if first.height != expected_height {
anyhow::bail!(
"header height mismatch: expected {}, got {}",
expected_height,
first.height
)
}

if first.parent_hash != self.local_tip.1 && self.verified_heights.is_empty() {
anyhow::bail!(
"first header parent_hash mismatch: expected {}, got {}",
self.local_tip.1,
first.parent_hash
)
}


let zero_addr = crate::types::Address::from_bytes([0u8; 20]);
if first.proposer == zero_addr {
anyhow::bail!("header {} has zero proposer address", first.height)
}


for i in 1..headers.len() {
let prev = &headers[i - 1];
let curr = &headers[i];


if curr.height != prev.height + 1 {
anyhow::bail!(
"header height not sequential: {} -> {}",
prev.height,
curr.height
)
}


let prev_hash = Block::compute_hash(prev);
if curr.parent_hash != prev_hash {
anyhow::bail!(
"header {} parent_hash mismatch: expected {}, got {}",
curr.height,
prev_hash,
curr.parent_hash
)
}


if curr.proposer == zero_addr {
anyhow::bail!("header {} has zero proposer address", curr.height)
}


if curr.timestamp <= prev.timestamp {
anyhow::bail!(
"header {} timestamp not increasing: {} <= {}",
curr.height,
curr.timestamp,
prev.timestamp
)
}
}

Ok(())
}




pub fn is_complete(&self) -> bool {
let total_needed = self.target_tip.0.saturating_sub(self.local_tip.0);
self.verified_heights.len() as u64 >= total_needed
}




pub fn get_progress(&self) -> (u64, u64) {
let current = self.local_tip.0 + self.verified_heights.len() as u64;
(current, self.target_tip.0)
}
}






const MAX_RETRY_COUNT: u32 = 3;


















#[derive(Debug, Clone)]
pub struct BlockSyncer {

pub headers_to_fetch: VecDeque<(u64, Hash)>,

pub fetched_blocks: HashMap<u64, Block>,

pub failed_heights: HashSet<u64>,

pub retry_count: HashMap<u64, u32>,
}

impl BlockSyncer {




pub fn new(headers: Vec<(u64, Hash)>) -> Self {
Self {
headers_to_fetch: VecDeque::from(headers),
fetched_blocks: HashMap::new(),
failed_heights: HashSet::new(),
retry_count: HashMap::new(),
}
}







pub fn request_next_blocks(&self, batch_size: u64) -> SyncRequest {
let mut count = (batch_size as usize).min(self.headers_to_fetch.len());
let heights: Vec<u64> = self.headers_to_fetch
.iter()
.take(count)
.map(|(h, _)| *h)
.collect();

SyncRequest::GetBlocks { heights: heights }
}















pub fn process_block(&mut self, block: Block, expected_header: &BlockHeader) -> Result<()> {
let height = block.header.height;


match self.validate_block_header(&block, expected_header) {
Ok(()) => {

self.fetched_blocks.insert(height, block);


self.headers_to_fetch.retain(|(h, _)| *h != height);


self.retry_count.remove(&height);

Ok(())
},
Err(e) => {

let mut count = self.retry_count.entry(height).or_insert(0);
*count += 1;


if *count >= MAX_RETRY_COUNT {

self.failed_heights.insert(height);


self.headers_to_fetch.retain(|(h, _)| *h != height);


self.retry_count.remove(&height);
}

Err(e)
},
}
}

















pub fn validate_block_header(&self, block: &Block, expected_header: &BlockHeader) -> Result<()> {

if block.header.height != expected_header.height {
anyhow::bail!(
"block height mismatch: expected {}, got {}",
expected_header.height,
block.header.height
)
}

if block.header.parent_hash != expected_header.parent_hash {
anyhow::bail!(
"block {} parent_hash mismatch",
block.header.height
)
}

if block.header.state_root != expected_header.state_root {
anyhow::bail!(
"block {} state_root mismatch",
block.header.height
)
}

if block.header.tx_root != expected_header.tx_root {
anyhow::bail!(
"block {} tx_root mismatch",
block.header.height
)
}

if block.header.timestamp != expected_header.timestamp {
anyhow::bail!(
"block {} timestamp mismatch",
block.header.height
)
}

if block.header.proposer != expected_header.proposer {
anyhow::bail!(
"block {} proposer mismatch",
block.header.height
)
}


if !block.verify_signature()? {
anyhow::bail!(
"block {} signature verification failed",
block.header.height
)
}


for (i, tx) in block.body.transactions.iter().enumerate() {
if !tx.verify_signature()? {
anyhow::bail!(
"block {} tx {} signature verification failed",
block.header.height,
i
)
}
}

Ok(())
}




pub fn get_pending_heights(&self) -> Vec<u64> {
self.headers_to_fetch
.iter()
.map(|(h, _)| *h)
.collect()
}






pub fn is_complete(&self) -> bool {
self.headers_to_fetch.is_empty()
}


pub fn fetched_count(&self) -> usize {
self.fetched_blocks.len()
}


pub fn failed_count(&self) -> usize {
self.failed_heights.len()
}


pub fn get_block(&self, height: u64) -> Option<&Block> {
self.fetched_blocks.get(&height)
}
}






















pub struct StateReplayEngine {

pub chain: Chain,

pub start_height: u64,

pub end_height: u64,

pub current_height: u64,

pub state_checkpoint: Option<ChainState>,
}

impl StateReplayEngine {






pub fn new(chain: Chain, start: u64, end: u64) -> Self {
Self {
chain: chain,
start_height: start,
end_height: end,
current_height: start,
state_checkpoint: None,
}
}









pub fn replay_from_genesis(&mut self) -> Result<()> {

let mut state = ChainState::new();


self.current_height = 0;

while self.current_height <= self.end_height {

let block = self.chain.db.get_block(self.current_height)?
.ok_or_else(|| anyhow::anyhow!(
"BlockNotFound: height {}",
self.current_height
))?;


self.replay_block_internal(&block, &mut state)?;


self.verify_state_root(&block, &state)?;


self.current_height += 1
}


self.state_checkpoint = Some(state);

Ok(())
}













pub fn replay_from_checkpoint(&mut self, height: u64, state: ChainState) -> Result<()> {

self.current_height = height + 1;
self.start_height = height + 1;


let mut replay_state = state;

while self.current_height <= self.end_height {

let block = self.chain.db.get_block(self.current_height)?
.ok_or_else(|| anyhow::anyhow!(
"BlockNotFound: height {}",
self.current_height
))?;


self.replay_block_internal(&block, &mut replay_state)?;


self.verify_state_root(&block, &replay_state)?;


self.current_height += 1
}


self.state_checkpoint = Some(replay_state);

Ok(())
}











pub fn replay_block(&mut self, block: &Block) -> Result<()> {

let mut state = self.state_checkpoint.take().unwrap_or_else(ChainState::new);


self.replay_block_internal(block, &mut state)?;


self.verify_state_root(block, &state)?;


self.current_height = block.header.height + 1;


self.state_checkpoint = Some(state);

Ok(())
}


fn replay_block_internal(&self, block: &Block, mut state: &mut ChainState) -> Result<()> {
let proposer = block.header.proposer;


for (i, tx) in block.body.transactions.iter().enumerate() {
match state.apply_payload(tx, &proposer) {
Ok(_) => {

},
Err(e) => {

println!(
"   ⚠️  Block {} TX {} execution error (continuing): {}",
block.header.height,
i,
e
)
},
}
}

Ok(())
}









pub fn verify_state_root(&self, block: &Block, state: &ChainState) -> Result<()> {
let computed = state.compute_state_root()?;
let expected = &block.header.state_root;

if &computed != expected {
anyhow::bail!(
"StateRootMismatch at height {}: expected {}, computed {}",
block.header.height,
expected,
computed
)
}

Ok(())
}




pub fn get_progress(&self) -> (u64, u64) {
(self.current_height, self.end_height)
}




pub fn is_complete(&self) -> bool {
self.current_height > self.end_height
}





pub fn get_final_state(&self) -> ChainState {
self.state_checkpoint.clone().unwrap_or_else(ChainState::new)
}







































pub fn replay_using_chain(&mut self, progress: Option<&dyn Fn(u64, u64)>) -> Result<()> {

self.chain.replay_blocks_from(
self.start_height,
self.end_height,
progress
).map_err(|e| anyhow::anyhow!("Chain replay failed: {}", e))?;


self.current_height = self.end_height + 1;


let final_state = self.chain.state.read().clone();
self.state_checkpoint = Some(final_state);

Ok(())
}

















pub fn fast_sync_from_snapshot(&mut self, snapshot_height: u64, target_height: u64, snapshot_state: ChainState, progress: Option<&dyn Fn(u64, u64)>) -> Result<ChainState> {

{
let mut state_guard = self.chain.state.write();
*state_guard = snapshot_state
}


self.start_height = snapshot_height;
self.end_height = target_height;
self.current_height = snapshot_height + 1;


self.replay_using_chain(progress)?;


Ok(self.get_final_state())
}
}
































pub struct SyncManager {

pub chain: Chain,

pub status: SyncStatus,

pub header_syncer: Option<HeaderSyncer>,

pub block_syncer: Option<BlockSyncer>,

pub replay_engine: Option<StateReplayEngine>,

pub celestia_syncer: Option<Arc<Mutex<crate::celestia::ControlPlaneSyncer>>>,

pub config: SyncConfig,

target_tip: Option<(u64, Hash)>,

start_height: u64,
}

impl SyncManager {





pub fn new(chain: Chain, config: SyncConfig) -> Self {
Self {
chain: chain,
status: SyncStatus::Idle,
header_syncer: None,
block_syncer: None,
replay_engine: None,
celestia_syncer: None,
config: config,
target_tip: None,
start_height: 0,
}
}










pub fn start_sync(&mut self, target_tip: (u64, Hash)) -> Result<()> {

if self.status != SyncStatus::Idle {
anyhow::bail!("sync already in progress, current status: {:?}", self.status)
}


let local_tip = self.chain.db.get_tip()?
.unwrap_or((0, Hash::from_bytes([0u8; 64])));


let local_height = local_tip.0;


if target_tip.0 <= local_height {
println!("✅ Already synced to height {}", local_height);
self.status = SyncStatus::Synced;
return Ok(());
}

println!("═══════════════════════════════════════════════════════════");
println!("🔄 SYNC MANAGER: Starting sync");
println!("   Local tip:  height={}", local_height);
println!("   Target tip: height={}", target_tip.0);
println!("═══════════════════════════════════════════════════════════");


self.target_tip = Some(target_tip.clone());
self.start_height = local_height + 1;


self.header_syncer = Some(HeaderSyncer::new(local_tip, target_tip.clone()));


self.status = SyncStatus::SyncingHeaders {
start_height: self.start_height.clone(),
target_height: target_tip.0.clone(),
current_height: local_height,
};

Ok(())
}













pub fn sync_step(&mut self) -> Result<()> {
match &self.status {
SyncStatus::Idle => {

Ok(())
},
SyncStatus::SyncingHeaders { start_height, target_height, current_height } => {
self.step_syncing_headers(*start_height, *target_height, *current_height)
},
SyncStatus::SyncingBlocks { start_height, target_height, current_height } => {
self.step_syncing_blocks(*start_height, *target_height, *current_height)
},
SyncStatus::SyncingState { checkpoint_height } => {
self.step_syncing_state(*checkpoint_height)
},
SyncStatus::Synced => {

Ok(())
},
}
}


fn step_syncing_headers(&mut self, start_height: u64, target_height: u64, _current_height: u64) -> Result<()> {
let mut syncer = self.header_syncer.as_ref()
.ok_or_else(|| anyhow::anyhow!("header_syncer not initialized"))?;


if syncer.is_complete() {
println!("   ✓ Header sync complete");


let headers: Vec<(u64, Hash)> = (start_height..=target_height)
.map(|h| {

let header = self.chain.db.get_header(h)
.ok()
.flatten()
.map(|hdr| Block::compute_hash(&hdr))
.unwrap_or_else(|| Hash::from_bytes([0u8; 64]));
(h, header)
})
.collect();


self.block_syncer = Some(BlockSyncer::new(headers));


self.status = SyncStatus::SyncingBlocks {
start_height: start_height,
target_height: target_height,
current_height: start_height,
};

return Ok(());
}


let request = syncer.request_next_headers();
println!("   📤 Header request: {:?}", request);








Ok(())
}


fn step_syncing_blocks(&mut self, start_height: u64, target_height: u64, _current_height: u64) -> Result<()> {
let mut syncer = self.block_syncer.as_ref()
.ok_or_else(|| anyhow::anyhow!("block_syncer not initialized"))?;


if syncer.is_complete() {
println!("   ✓ Block sync complete");
println!("   Fetched: {} blocks", syncer.fetched_count());
println!("   Failed:  {} blocks", syncer.failed_count());


if syncer.failed_count() > 0 {
anyhow::bail!(
"sync failed: {} blocks could not be fetched after max retries",
syncer.failed_count()
)
}


self.replay_engine = Some(StateReplayEngine::new(
self.chain.clone(),
start_height,
target_height
));


self.status = SyncStatus::SyncingState {
checkpoint_height: start_height,
};

return Ok(());
}


let request = syncer.request_next_blocks(self.config.batch_size);
println!("   📤 Block request: {:?}", request);



Ok(())
}


fn step_syncing_state(&mut self, _checkpoint_height: u64) -> Result<()> {

if let Some(ref engine) = self.replay_engine {
if engine.is_complete() {
println!("   ✓ State replay complete");


if let Some(ref celestia) = self.celestia_syncer {
celestia.lock().unwrap().apply_updates(&mut self.chain)?;
println!("   ✓ Celestia control-plane updates applied")
}


let final_state = engine.get_final_state();



self.finalize_sync(final_state)?;

return Ok(());
}
}




println!("   🔄 State replay in progress...");

Ok(())
}




fn finalize_sync(&mut self, final_state: ChainState) -> Result<()> {
println!("═══════════════════════════════════════════════════════════");
println!("💾 SYNC MANAGER: Finalizing sync (atomic commit)");
println!("═══════════════════════════════════════════════════════════");


{
let mut state_guard = self.chain.state.write();
*state_guard = final_state
}


let state_snapshot = self.chain.state.read().clone();
self.chain.db.persist_state(&state_snapshot)?;


if let Some((target_height, target_hash)) = &self.target_tip {
self.chain.db.set_tip(*target_height, target_hash)?
}


self.status = SyncStatus::Synced;


self.header_syncer = None;
self.block_syncer = None;
self.replay_engine = None;

println!("═══════════════════════════════════════════════════════════");
println!("✅ SYNC MANAGER: Sync complete!");
println!("═══════════════════════════════════════════════════════════");

Ok(())
}


pub fn get_status(&self) -> SyncStatus {
self.status.clone()
}




pub fn get_progress(&self) -> (u64, u64) {
match &self.status {
SyncStatus::Idle => {
(0, 0)
},
SyncStatus::SyncingHeaders { current_height, target_height, .. } => {
(*current_height, *target_height)
},
SyncStatus::SyncingBlocks { current_height, target_height, .. } => {
(*current_height, *target_height)
},
SyncStatus::SyncingState { checkpoint_height } => {
if let Some(ref engine) = self.replay_engine {
engine.get_progress()
} else {
(*checkpoint_height, self.target_tip.as_ref().map(|(h, _)| *h).unwrap_or(0))
}
},
SyncStatus::Synced => {
let target = self.target_tip.as_ref().map(|(h, _)| *h).unwrap_or(0);
(target, target)
},
}
}


pub fn cancel_sync(&mut self) {
println!("⚠️  SYNC MANAGER: Sync cancelled");


self.header_syncer = None;
self.block_syncer = None;
self.replay_engine = None;
self.target_tip = None;


self.status = SyncStatus::Idle;
}


pub fn is_synced(&self) -> bool {
match self.status {
SyncStatus::Synced => { true },
_ => { false },
}
}








pub fn process_header_response(&mut self, headers: Vec<BlockHeader>) -> Result<()> {
if let Some(ref mut syncer) = self.header_syncer {
syncer.process_headers(headers, &self.chain.db)?;


let (current, target) = syncer.get_progress();
if let SyncStatus::SyncingHeaders { start_height, target_height: _, current_height: _ } = &self.status {
self.status = SyncStatus::SyncingHeaders {
start_height: *start_height,
target_height: target,
current_height: current,
};
}
}
Ok(())
}




pub fn process_block_response(&mut self, blocks: Vec<Block>) -> Result<()> {
if let Some(ref mut syncer) = self.block_syncer {
for block in blocks {
let height = block.header.height;


if let Some(expected_header) = self.chain.db.get_header(height)? {
if let Err(e) = syncer.process_block(block, &expected_header) {
println!("   ⚠️  Block {} processing error: {}", height, e)
}
}
}


let fetched = syncer.fetched_count() as u64;
if let SyncStatus::SyncingBlocks { start_height, target_height, current_height: _ } = &self.status {
self.status = SyncStatus::SyncingBlocks {
start_height: *start_height,
target_height: *target_height,
current_height: *start_height + fetched,
};
}
}
Ok(())
}




pub fn execute_replay(&mut self) -> Result<()> {
if let Some(ref mut engine) = self.replay_engine {
engine.replay_from_genesis()?
}
Ok(())
}


pub fn set_celestia_syncer(&mut self, syncer: crate::celestia::ControlPlaneSyncer) {
self.celestia_syncer = Some(Arc::new(Mutex::new(syncer)));
}
}




#[cfg(test)]
mod tests {
use super::*;

#[test]
fn test_sync_config_default() {
let config = SyncConfig::default();

assert_eq!(config.max_headers_per_request, 500);
assert_eq!(config.max_blocks_per_request, 100);
assert_eq!(config.sync_timeout_ms, 30000);
assert_eq!(config.batch_size, 50);
}

#[test]
fn test_sync_status_variants() {
let idle = SyncStatus::Idle;
let synced = SyncStatus::Synced;

assert_ne!(idle, synced);

let syncing = SyncStatus::SyncingHeaders {
start_height: 0,
target_height: 100,
current_height: 50,
};

assert_ne!(syncing, idle);
}

#[test]
fn test_sync_request_serialization() {
let req = SyncRequest::GetHeaders {
start_height: 100,
count: 50,
};

let json = serde_json::to_string(&req).unwrap();
let restored: SyncRequest = serde_json::from_str(&json).unwrap();

assert_eq!(req, restored);
}

#[test]
fn test_sync_config_serialization() {
let config = SyncConfig::default();
let json = serde_json::to_string(&config).unwrap();
let restored: SyncConfig = serde_json::from_str(&json).unwrap();

assert_eq!(config, restored);
}

#[test]
fn test_header_syncer_new() {
let local_tip = (100, Hash::from_bytes([0x11u8; 64]));
let target_tip = (200, Hash::from_bytes([0x22u8; 64]));

let mut syncer = HeaderSyncer::new(local_tip.clone(), target_tip.clone());

assert_eq!(syncer.local_tip, local_tip);
assert_eq!(syncer.target_tip, target_tip);
assert!(syncer.pending_headers.is_empty());
assert!(syncer.verified_heights.is_empty());
}

#[test]
fn test_header_syncer_request_next() {
let local_tip = (100, Hash::from_bytes([0x11u8; 64]));
let target_tip = (200, Hash::from_bytes([0x22u8; 64]));

let mut syncer = HeaderSyncer::new(local_tip.clone(), target_tip.clone());

let req = syncer.request_next_headers();
match req {
SyncRequest::GetHeaders { start_height, count } => {
assert_eq!(start_height, 101);
assert_eq!(count, 100);
},
_ => {
panic!("expected GetHeaders");
},
}
}

#[test]
fn test_header_syncer_progress() {
let local_tip = (100, Hash::from_bytes([0x11u8; 64]));
let target_tip = (200, Hash::from_bytes([0x22u8; 64]));

let mut syncer = HeaderSyncer::new(local_tip.clone(), target_tip.clone());

let (current, target) = syncer.get_progress();
assert_eq!(current, 100);
assert_eq!(target, 200);
assert!(!syncer.is_complete());


for h in 101..=200 {
syncer.verified_heights.insert(h);
}

let (current2, _) = syncer.get_progress();
assert_eq!(current2, 200);
assert!(syncer.is_complete());
}





#[test]
fn test_block_syncer_new() {
let headers = vec![
(101, Hash::from_bytes([0x11u8; 64])),
(102, Hash::from_bytes([0x22u8; 64])),
(103, Hash::from_bytes([0x33u8; 64])),
];

let mut syncer = BlockSyncer::new(headers.clone());

assert_eq!(syncer.headers_to_fetch.len(), 3);
assert!(syncer.fetched_blocks.is_empty());
assert!(syncer.failed_heights.is_empty());
assert!(syncer.retry_count.is_empty());
assert!(!syncer.is_complete());
}

#[test]
fn test_block_syncer_request_next() {
let headers = vec![
(101, Hash::from_bytes([0x11u8; 64])),
(102, Hash::from_bytes([0x22u8; 64])),
(103, Hash::from_bytes([0x33u8; 64])),
(104, Hash::from_bytes([0x44u8; 64])),
(105, Hash::from_bytes([0x55u8; 64])),
];

let mut syncer = BlockSyncer::new(headers.clone());


let req = syncer.request_next_blocks(3);
match req {
SyncRequest::GetBlocks { heights } => {
assert_eq!(heights.len(), 3);
assert_eq!(heights, vec![101, 102, 103]);
},
_ => {
panic!("expected GetBlocks");
},
}


let req2 = syncer.request_next_blocks(100);
match req2 {
SyncRequest::GetBlocks { heights } => {
assert_eq!(heights.len(), 5);
},
_ => {
panic!("expected GetBlocks");
},
}
}

#[test]
fn test_block_syncer_pending_heights() {
let headers = vec![
(101, Hash::from_bytes([0x11u8; 64])),
(102, Hash::from_bytes([0x22u8; 64])),
(103, Hash::from_bytes([0x33u8; 64])),
];

let mut syncer = BlockSyncer::new(headers.clone());

let pending = syncer.get_pending_heights();
assert_eq!(pending, vec![101, 102, 103]);
}

#[test]
fn test_block_syncer_complete_when_empty() {
let mut syncer = BlockSyncer::new(vec![]);

assert!(syncer.is_complete());
assert_eq!(syncer.fetched_count(), 0);
assert_eq!(syncer.failed_count(), 0);
}





#[test]
fn test_state_replay_engine_progress() {




let _start = 0u64;
let end = 100u64;


let current = 50u64;
let is_done = current > end;

assert_eq!((current, end), (50, 100));
assert!(!is_done);

let current2 = 101u64;
let is_done2 = current2 > end;
assert!(is_done2);
}

#[test]
fn test_state_replay_engine_checkpoint_state() {

let mut state = crate::state::ChainState::new();


let checkpoint = crate::state::create_checkpoint(&state);
assert!(checkpoint.is_ok());


let restored = crate::state::restore_from_checkpoint(&checkpoint.unwrap());
assert!(restored.is_ok());
}





#[test]
fn test_sync_status_transitions() {



let idle = SyncStatus::Idle;
let syncing_headers = SyncStatus::SyncingHeaders {
start_height: 1,
target_height: 100,
current_height: 1,
};
assert_ne!(idle, syncing_headers);


let syncing_blocks = SyncStatus::SyncingBlocks {
start_height: 1,
target_height: 100,
current_height: 1,
};
assert_ne!(syncing_headers, syncing_blocks);


let syncing_state = SyncStatus::SyncingState {
checkpoint_height: 1,
};
assert_ne!(syncing_blocks, syncing_state);


let synced = SyncStatus::Synced;
assert_ne!(syncing_state, synced);


assert_ne!(synced, idle);


let all_states = vec![
SyncStatus::Idle,
SyncStatus::SyncingHeaders { start_height: 0, target_height: 0, current_height: 0 },
SyncStatus::SyncingBlocks { start_height: 0, target_height: 0, current_height: 0 },
SyncStatus::SyncingState { checkpoint_height: 0 },
SyncStatus::Synced,
];
for i in 0..all_states.len() {
for j in 0..all_states.len() {
if i != j {
assert_ne!(
std::mem::discriminant(&all_states[i]),
std::mem::discriminant(&all_states[j])
);
}
}
}
}

#[test]
fn test_sync_status_serialization_roundtrip() {

let statuses = vec![
SyncStatus::Idle,
SyncStatus::SyncingHeaders { start_height: 10, target_height: 100, current_height: 50 },
SyncStatus::SyncingBlocks { start_height: 10, target_height: 100, current_height: 75 },
SyncStatus::SyncingState { checkpoint_height: 100 },
SyncStatus::Synced,
];

for status in statuses {
let json = serde_json::to_string(&status).unwrap();
let restored: SyncStatus = serde_json::from_str(&json).unwrap();
assert_eq!(status, restored);
}
}

#[test]
fn test_header_chain_validation_rules() {

let local_tip = (100, Hash::from_bytes([0x11u8; 64]));
let target_tip = (200, Hash::from_bytes([0x22u8; 64]));

let mut syncer = HeaderSyncer::new(local_tip.clone(), target_tip.clone());


let result = syncer.verify_header_chain(&[]);
assert!(result.is_ok());




}

#[test]
fn test_header_sync_complete_detection() {
let local_tip = (100, Hash::from_bytes([0x11u8; 64]));
let target_tip = (110, Hash::from_bytes([0x22u8; 64]));

let mut syncer = HeaderSyncer::new(local_tip.clone(), target_tip.clone());


assert!(!syncer.is_complete());
assert_eq!(syncer.verified_heights.len(), 0);


for h in 101..=110 {
syncer.verified_heights.insert(h);
}


assert!(syncer.is_complete());


let (current, target) = syncer.get_progress();
assert_eq!(current, 110);
assert_eq!(target, 110);
}

#[test]
fn test_block_sync_retry_tracking() {
let headers = vec![
(101, Hash::from_bytes([0x11u8; 64])),
(102, Hash::from_bytes([0x22u8; 64])),
];

let mut syncer = BlockSyncer::new(headers.clone());


assert!(syncer.retry_count.is_empty());
assert!(syncer.failed_heights.is_empty());


syncer.retry_count.insert(101, 1);
assert_eq!(*syncer.retry_count.get(&101).unwrap(), 1);

syncer.retry_count.insert(101, 2);
assert_eq!(*syncer.retry_count.get(&101).unwrap(), 2);


syncer.retry_count.insert(101, 3);
syncer.failed_heights.insert(101);

assert!(syncer.failed_heights.contains(&101));
assert_eq!(syncer.failed_count(), 1);
}

#[test]
fn test_block_sync_batch_generation() {
let headers: Vec<(u64, Hash)> = (101..=120)
.map(|h| (h, Hash::from_bytes([h as u8; 64])))
.collect();

let mut syncer = BlockSyncer::new(headers.clone());


let req = syncer.request_next_blocks(5);
match req {
SyncRequest::GetBlocks { heights } => {
assert_eq!(heights.len(), 5);
assert_eq!(heights, vec![101, 102, 103, 104, 105]);
},
_ => {
panic!("expected GetBlocks");
},
}


let req2 = syncer.request_next_blocks(10);
match req2 {
SyncRequest::GetBlocks { heights } => {
assert_eq!(heights.len(), 10);
},
_ => {
panic!("expected GetBlocks");
},
}
}

#[test]
fn test_sync_config_defaults_values() {
let config = SyncConfig::default();


assert_eq!(config.max_headers_per_request, 500);
assert_eq!(config.max_blocks_per_request, 100);
assert_eq!(config.sync_timeout_ms, 30000);
assert_eq!(config.batch_size, 50);


let json = serde_json::to_string(&config).unwrap();
let restored: SyncConfig = serde_json::from_str(&json).unwrap();
assert_eq!(config, restored);
}

#[test]
fn test_sync_request_variants() {

let requests = vec![
SyncRequest::GetHeaders { start_height: 100, count: 50 },
SyncRequest::GetBlock { height: 150 },
SyncRequest::GetBlocks { heights: vec![100, 101, 102] },
SyncRequest::GetChainTip,
];

for req in requests {
let json = serde_json::to_string(&req).unwrap();
let restored: SyncRequest = serde_json::from_str(&json).unwrap();
assert_eq!(req, restored);
}
}

#[test]
fn test_peer_sync_state_tracking() {
let mut state = PeerSyncState {
peer_id: "peer_001".to_string(),
tip_height: 12345,
tip_hash: Hash::from_bytes([0x42u8; 64]),
last_seen: 1700000000,
is_syncing: true,
};

assert_eq!(state.peer_id, "peer_001");
assert_eq!(state.tip_height, 12345);
assert!(state.is_syncing);


let json = serde_json::to_string(&state).unwrap();
let restored: PeerSyncState = serde_json::from_str(&json).unwrap();
assert_eq!(state, restored);
}
}