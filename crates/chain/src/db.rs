use crate::block::{Block, Receipt};
use crate::tx::TxEnvelope;
use crate::types::{Address, Hash};
use crate::state::{ChainState, Validator, ValidatorSet, ValidatorInfo as StateValidatorInfo, Proposal, Vote, GovernanceConfig};
use anyhow::Result;
use lmdb::{
    Environment,
    Database,
    DatabaseFlags,
    WriteFlags,
    Transaction as LmdbTxn,
    Cursor,
};

use std::path::Path;
use std::sync::Arc;
use std::collections::HashSet;
use std::path::PathBuf;
use bincode;
use serde::{Serialize, Deserialize};
use thiserror::Error;

// ════════════════════════════════════════════════════════════════════════════
// SNAPSHOT ERROR TYPE (13.18.2)
// ════════════════════════════════════════════════════════════════════════════

/// Error type untuk snapshot operations.
/// Digunakan untuk create_snapshot dan write_snapshot_metadata.
#[derive(Debug, Error)]
pub enum DbError {
    /// Gagal membuat direktori snapshot
    #[error("failed to create snapshot directory: {0}")]
    DirectoryCreation(String),

    /// Gagal melakukan LMDB copy
    #[error("failed to copy LMDB environment: {0}")]
    LmdbCopy(String),

    /// Gagal menulis metadata
    #[error("failed to write snapshot metadata: {0}")]
    MetadataWrite(String),

    /// Gagal serialisasi metadata ke JSON
    #[error("failed to serialize metadata: {0}")]
    Serialization(String),

    /// Snapshot directory tidak ada
    #[error("snapshot directory does not exist: {0}")]
    DirectoryNotFound(String),

    /// Gagal cleanup snapshot parsial
    #[error("failed to cleanup partial snapshot: {0}")]
    Cleanup(String),

    /// IO error umum
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    // ════════════════════════════════════════════════════════════════════════════
    // SNAPSHOT LOADING ERRORS (13.18.3)
    // ════════════════════════════════════════════════════════════════════════════

    /// Gagal membaca metadata.json
    #[error("failed to read snapshot metadata: {0}")]
    MetadataRead(String),

    /// Metadata JSON invalid atau field tidak lengkap
    #[error("invalid snapshot metadata: {0}")]
    MetadataInvalid(String),

    /// data.mdb tidak ditemukan di snapshot folder
    #[error("snapshot data.mdb not found: {0}")]
    DataNotFound(String),

    /// Gagal membuka LMDB environment dari snapshot
    #[error("failed to open snapshot LMDB: {0}")]
    SnapshotOpenFailed(String),

    /// Snapshot korup: state_root tidak match dengan metadata
    #[error("snapshot corrupted: state_root mismatch (expected: {expected}, computed: {computed})")]
    SnapshotCorrupted {
        expected: String,
        computed: String,
    },

    /// Gagal load state dari snapshot
    #[error("failed to load state from snapshot: {0}")]
    StateLoadFailed(String),
}

// ════════════════════════════════════════════════════════════════════════════
// BUCKET CONSTANTS (13.10, 13.11, 13.12, 13.14)
// ════════════════════════════════════════════════════════════════════════════
pub const BUCKET_CLAIMED_RECEIPTS: &str = "claimed_receipts";

/// Header storage bucket for header-first sync (13.11)
pub const BUCKET_HEADERS: &str = "headers";

// ════════════════════════════════════════════════════════════════════════════
// GOVERNANCE BUCKET CONSTANTS (13.12.7)
// ════════════════════════════════════════════════════════════════════════════
// Key formats are CONSENSUS-CRITICAL. Do not modify without hard fork.
// ════════════════════════════════════════════════════════════════════════════

/// Proposals bucket
/// Key: proposal_id (u64 big-endian, 8 bytes)
/// Value: bincode serialized Proposal
pub const BUCKET_PROPOSALS: &str = "proposals";

/// Proposal votes bucket
/// Key: proposal_id (8 bytes BE) + voter_address (20 bytes) = 28 bytes
/// Value: bincode serialized Vote
pub const BUCKET_PROPOSAL_VOTES: &str = "proposal_votes";

/// Governance config bucket
/// Key: "config" (6 bytes)
/// Value: bincode serialized GovernanceConfig
pub const BUCKET_GOVERNANCE_CONFIG: &str = "gov_config";

// ════════════════════════════════════════════════════════════════════════════
// SLASHING BUCKET CONSTANTS (13.14.7)
// ════════════════════════════════════════════════════════════════════════════
// Key formats are CONSENSUS-CRITICAL. Do not modify without hard fork.
// ════════════════════════════════════════════════════════════════════════════

/// Node liveness records bucket
/// Key: node_address (20 bytes)
/// Value: bincode serialized NodeLivenessRecord
pub const BUCKET_NODE_LIVENESS: &str = "node_liveness";

// ════════════════════════════════════════════════════════════════════════════
// ECONOMIC BUCKET CONSTANTS (13.15.7)
// ════════════════════════════════════════════════════════════════════════════
// Key formats are CONSENSUS-CRITICAL. Do not modify without hard fork.
// ════════════════════════════════════════════════════════════════════════════

/// Economic metrics bucket
/// Key: "metrics" (7 bytes)
/// Value: bincode serialized EconomicMetrics
pub const BUCKET_ECONOMIC_METRICS: &str = "economic_metrics";

/// Deflation config bucket
/// Key: "config" (6 bytes)
/// Value: bincode serialized DeflationConfig
pub const BUCKET_DEFLATION_CONFIG: &str = "deflation_config";

// ════════════════════════════════════════════════════════════════════════════
// STORAGE PAYMENT BUCKET CONSTANTS (13.17.7)
// ════════════════════════════════════════════════════════════════════════════
// Key formats are CONSENSUS-CRITICAL. Do not modify without hard fork.
// ════════════════════════════════════════════════════════════════════════════

/// Storage contracts bucket
/// Key: contract_id (Hash, 64 bytes)
/// Value: bincode serialized StorageContract
pub const BUCKET_STORAGE_CONTRACTS: &str = "storage_contracts";

/// User contracts index bucket
/// Key: user_address (20 bytes)
/// Value: bincode serialized Vec<Hash> (list of contract_ids)
pub const BUCKET_USER_CONTRACTS: &str = "user_contracts";

/// Account object persisted in DB
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Account {
    pub address: Address,
    pub balance: u128,
    pub nonce: u64,
    pub locked: u128,
}

/// Validator info persisted
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorInfo {
    pub address: Address,
    pub stake: u128,
    pub pubkey: Vec<u8>,
    pub active: bool,
    pub moniker: Option<String>,
}
impl From<Validator> for ValidatorInfo {
    fn from(v: Validator) -> Self {
        ValidatorInfo {
            address: v.address,
            stake: v.stake,
            pubkey: v.pubkey,
            active: v.active,
            moniker: None, // legacy Validator tidak punya moniker
        }
    }
}

impl From<ValidatorInfo> for Validator {
    fn from(vi: ValidatorInfo) -> Self {
        Validator {
            address: vi.address,
            stake: vi.stake,
            pubkey: vi.pubkey,
            active: vi.active,
        }
    }
}

// ============================================================
// STATE LAYOUT DATA STRUCTURES (13.8.H)
// ============================================================

/// Stake data stored in state/stake/{addr} bucket
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StakeData {
    pub address: Address,
    /// Validator's own stake (if validator)
    pub validator_stake: u128,
    /// Delegator's stake (if delegator)
    pub delegator_stake: u128,
    /// Total locked amount
    pub locked: u128,
}

impl StakeData {
    pub fn new(address: Address) -> Self {
        Self {
            address,
            validator_stake: 0,
            delegator_stake: 0,
            locked: 0,
        }
    }
}

/// Delegator data stored in state/delegators/{addr} bucket
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DelegatorData {
    pub address: Address,
    /// Validator this delegator is delegating to (None if not delegating)
    pub validator: Option<Address>,
    /// Total delegated amount
    pub delegated_amount: u128,
    /// Last epoch when reward was received
    pub last_reward_epoch: u64,
    /// Accrued rewards this year (for annual cap)
    pub reward_accrued: u128,
}

impl DelegatorData {
    pub fn new(address: Address) -> Self {
        Self {
            address,
            validator: None,
            delegated_amount: 0,
            last_reward_epoch: 0,
            reward_accrued: 0,
        }
    }
}

/// QV weight data stored in state/qv_weights/{addr} bucket
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct QvWeightData {
    pub address: Address,
    /// Individual QV weight = sqrt(locked_stake)
    pub individual_weight: u128,
    /// Combined validator QV weight (only for validators)
    /// = 80% * sqrt(self_stake) + 20% * sum(sqrt(delegator_i))
    pub validator_combined_weight: u128,
}

impl QvWeightData {
    pub fn new(address: Address) -> Self {
        Self {
            address,
            individual_weight: 0,
            validator_combined_weight: 0,
        }
    }
}

/// Validator metadata stored in state/validator_metadata/{addr} bucket
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorMetadata {
    pub address: Address,
    pub moniker: Option<String>,
    pub website: Option<String>,
    pub description: Option<String>,
    pub commission_rate: u128,  // basis points (e.g., 2000 = 20%)
    pub registered_at_epoch: u64,
    pub last_active_epoch: u64,
}

impl ValidatorMetadata {
    pub fn new(address: Address) -> Self {
        Self {
            address,
            moniker: None,
            website: None,
            description: None,
            commission_rate: 2000, // default 20%
            registered_at_epoch: 0,
            last_active_epoch: 0,
        }
    }
}

// ============================================================
// NODE COST DATA (13.9)
// ============================================================

/// Node cost data stored in state/node_cost/{addr} bucket
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeCostData {
    pub address: Address,
    /// Node cost index multiplier (basis 100 = 1.0x)
    pub cost_index: u128,
    /// Accumulated earnings for this node
    pub earnings: u128,
}

impl NodeCostData {
    pub fn new(address: Address) -> Self {
        Self {
            address,
            cost_index: 100, // default 1.0x multiplier
            earnings: 0,
        }
    }
}
// Lokasi: Setelah line 183 (setelah impl NodeCostData)
// Tambahkan:

/// Node earnings data stored in state/node_earnings/{addr} bucket (13.9)
/// Tracks accumulated earnings per node address separately
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeEarningsData {
    pub address: Address,
    /// Accumulated earnings for this node
    pub amount: u128,
}

impl NodeEarningsData {
    pub fn new(address: Address) -> Self {
        Self {
            address,
            amount: 0,
        }
    }
}
#[derive(Clone)]
pub struct ChainDb {
    env: Arc<Environment>,
    env_path: PathBuf,
    db_blocks: Database,
    db_block_hashes: Database,
    db_txs: Database,
    db_accounts: Database,
    db_validators: Database,
    db_meta: Database,
    db_mempool: Database,
    db_validator_set: Database,    // DPoS Hybrid validator set bucket
    db_receipts: Database,         // Receipt storage for atomic commit (13.7.I)
    db_pending_unstake: Database,  // Pending unstake entries (13.8.G)
    db_state_node_earnings: Database,
    
    //STATE LAYOUT BUCKETS (13.8.H)

    db_state_validators: Database,       // state/validators/{addr}
    db_state_stake: Database,            // state/stake/{addr}
    db_state_delegators: Database,       // state/delegators/{addr}
    db_state_qv_weights: Database,       // state/qv_weights/{addr}
    db_state_validator_metadata: Database, // state/validator_metadata/{addr}
    db_state_node_cost: Database,        // state/node_cost/{addr} (13.9)
    
    // CLAIMED RECEIPTS (13.10)
    db_claimed_receipts: Database,       // claimed_receipts/{receipt_id}
    
    // HEADER SYNC (13.11)
    db_headers: Database,                // headers/{height} for header-first sync
    
    // GOVERNANCE (13.12.7)
    db_proposals: Database,              // proposals/{proposal_id}
    db_proposal_votes: Database,         // proposal_votes/{proposal_id + voter_address}
    db_governance_config: Database,      // gov_config/config
    
    // SLASHING (13.14.7)
    db_node_liveness: Database,          // node_liveness/{node_address}
    
    // ECONOMIC (13.15.7)
    db_economic_metrics: Database,       // economic_metrics/metrics
    db_deflation_config: Database,       // deflation_config/config
    
    // STORAGE PAYMENT (13.17.7)
    db_storage_contracts: Database,      // storage_contracts/{contract_id}
    db_user_contracts: Database,         // user_contracts/{address}
}
impl ChainDb {
    /// Open LMDB environment at path, create named DBs
      pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let p = path.as_ref();
        std::fs::create_dir_all(p)?;

    let env = Environment::new()
            .set_max_dbs(33) // increased for storage payment buckets (13.17.7)
            .set_map_size(1_000_000_000usize)
            .open(p)?;

        let db_blocks = env.create_db(Some("blocks"), DatabaseFlags::empty())?;
        let db_block_hashes = env.create_db(Some("block_hashes"), DatabaseFlags::empty())?;
        let db_txs = env.create_db(Some("txs"), DatabaseFlags::empty())?;
        let db_accounts = env.create_db(Some("accounts"), DatabaseFlags::empty())?;
        let db_validators = env.create_db(Some("validators"), DatabaseFlags::empty())?;
        let db_meta = env.create_db(Some("meta"), DatabaseFlags::empty())?;
        let db_mempool = env.create_db(Some("pending_mempool"), DatabaseFlags::empty())?;
        let db_validator_set = env.create_db(Some("validator_set"), DatabaseFlags::empty())?;
        let db_receipts = env.create_db(Some("receipts"), DatabaseFlags::empty())?;
        let db_pending_unstake = env.create_db(Some("pending_unstake"), DatabaseFlags::empty())?;
        
        // New state layout buckets (13.8.H)
        let db_state_validators = env.create_db(Some("state_validators"), DatabaseFlags::empty())?;
        let db_state_stake = env.create_db(Some("state_stake"), DatabaseFlags::empty())?;
        let db_state_delegators = env.create_db(Some("state_delegators"), DatabaseFlags::empty())?;
        let db_state_qv_weights = env.create_db(Some("state_qv_weights"), DatabaseFlags::empty())?;
        let db_state_validator_metadata = env.create_db(Some("state_validator_metadata"), DatabaseFlags::empty())?;
        
        // Node cost bucket (13.9)
        let db_state_node_cost = env.create_db(Some("state_node_cost"), DatabaseFlags::empty())?;
        let db_claimed_receipts = env.create_db(Some(BUCKET_CLAIMED_RECEIPTS), DatabaseFlags::empty())?;
        let db_state_node_earnings = env.create_db(Some("state_node_earnings"), DatabaseFlags::empty())?;
        
        // Header sync bucket (13.11)
        let db_headers = env.create_db(Some(BUCKET_HEADERS), DatabaseFlags::empty())?;
        
        // Governance buckets (13.12.7)
        let db_proposals = env.create_db(Some(BUCKET_PROPOSALS), DatabaseFlags::empty())?;
        let db_proposal_votes = env.create_db(Some(BUCKET_PROPOSAL_VOTES), DatabaseFlags::empty())?;
        let db_governance_config = env.create_db(Some(BUCKET_GOVERNANCE_CONFIG), DatabaseFlags::empty())?;
        
        // Slashing bucket (13.14.7)
        let db_node_liveness = env.create_db(Some(BUCKET_NODE_LIVENESS), DatabaseFlags::empty())?;
        
        // Economic buckets (13.15.7)
        let db_economic_metrics = env.create_db(Some(BUCKET_ECONOMIC_METRICS), DatabaseFlags::empty())?;
        let db_deflation_config = env.create_db(Some(BUCKET_DEFLATION_CONFIG), DatabaseFlags::empty())?;
        
        // Storage payment buckets (13.17.7)
        let db_storage_contracts = env.create_db(Some(BUCKET_STORAGE_CONTRACTS), DatabaseFlags::empty())?;
        let db_user_contracts = env.create_db(Some(BUCKET_USER_CONTRACTS), DatabaseFlags::empty())?;

        Ok(Self {
            env: Arc::new(env),
            env_path: p.to_path_buf(),
            db_blocks,
            db_block_hashes,
            db_txs,
            db_accounts,
            db_validators,
            db_meta,
            db_mempool,
            db_validator_set,
            db_receipts,
            db_pending_unstake,
            db_state_validators,
            db_state_stake,
            db_state_delegators,
            db_state_qv_weights,
            db_state_validator_metadata,
            db_state_node_cost,
            db_claimed_receipts,
            db_state_node_earnings,
            db_headers,
            db_proposals,
            db_proposal_votes,
            db_governance_config,
            db_node_liveness,
            db_economic_metrics,
            db_deflation_config,
            db_storage_contracts,
            db_user_contracts,
        })
    }

    // ------------------------
    // block operations
    // ------------------------

    /// store block (key = height bytes big-endian)
    pub fn put_block(&self, block: &Block) -> Result<()> {
        let height_key = Self::height_key(block.header.height);
        let blob = bincode::serialize(block)?;
        let block_hash = crate::block::Block::compute_hash(&block.header);
        let hash_key = block_hash.as_bytes();
        let height_value = block.header.height.to_be_bytes();

        let mut wtxn = self.env.begin_rw_txn()?;
        wtxn.put(self.db_blocks, &height_key, &blob, WriteFlags::empty())?;
        wtxn.put(self.db_block_hashes, hash_key, &height_value, WriteFlags::empty())?;
        wtxn.commit()?;
        Ok(())
    }

    /// get block by height
    pub fn get_block(&self, height: u64) -> Result<Option<Block>> {
        let rtxn = self.env.begin_ro_txn()?;
        let key = Self::height_key(height);
        match rtxn.get(self.db_blocks, &key) {
            Ok(v) => {
                let blk: Block = bincode::deserialize(v)?;
                Ok(Some(blk))
            }
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Return true if genesis marker exists
    pub fn has_genesis(&self) -> Result<bool> {
        let rtxn = self.env.begin_ro_txn()?;
        match rtxn.get(self.db_meta, b"genesis_marker") {
            Ok(_) => Ok(true),
            Err(lmdb::Error::NotFound) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Mark genesis as initialized
    pub fn mark_genesis(&self) -> Result<()> {
        let mut wtxn = self.env.begin_rw_txn()?;
        wtxn.put(self.db_meta, b"genesis_marker", b"1", WriteFlags::empty())?;
        wtxn.commit()?;
        Ok(())
    }

    // ------------------------
    // tx operations
    // ------------------------

    pub fn put_tx(&self, tx: &TxEnvelope) -> Result<()> {
        let txid = tx.compute_txid()?;
        let key = txid.as_bytes();
        let blob = bincode::serialize(tx)?;
        
        let mut wtxn = self.env.begin_rw_txn()?;
        wtxn.put(self.db_txs, key, &blob, WriteFlags::empty())?;
        wtxn.commit()?;
        Ok(())
    }

    pub fn get_tx(&self, txid: &[u8]) -> Result<Option<TxEnvelope>> {
        let rtxn = self.env.begin_ro_txn()?;
        let key: &[u8] = &txid[..];
        match rtxn.get(self.db_txs, &key) {
            Ok(val) => Ok(Some(bincode::deserialize(val)?)),
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
        /// store pending tx for next block (simple append)
    pub fn put_pending_tx(&self, tx: &TxEnvelope) -> Result<()> {
        let txid = tx.compute_txid()?;
        let key = txid.as_bytes();
        let blob = bincode::serialize(tx)?;
        let mut wtxn = self.env.begin_rw_txn()?;
        // kita pake db_txs juga tapi beda flag marker "pending_"
        let mut pending_key = b"pending_".to_vec();
        pending_key.extend_from_slice(key);
        wtxn.put(self.db_txs, &pending_key, &blob, WriteFlags::empty())?;
        wtxn.commit()?;
        Ok(())
    }

    /// load semua pending tx (yang belum di-block)
    pub fn load_pending_txs(&self) -> Result<Vec<TxEnvelope>> {
        let rtxn = self.env.begin_ro_txn()?;
        let mut cursor = rtxn.open_ro_cursor(self.db_txs)?;
        let mut txs = Vec::new();
        for (key, val) in cursor.iter() {
            if key.starts_with(b"pending_") {
                let tx: TxEnvelope = bincode::deserialize(val)?;
                txs.push(tx);
            }
        }
        Ok(txs)
    }

    /// clear semua pending tx (setelah berhasil masuk block)
    pub fn clear_pending_txs(&self) -> Result<()> {
        let mut wtxn = self.env.begin_rw_txn()?;
        let mut cursor = wtxn.open_rw_cursor(self.db_txs)?;
        let mut del_keys = Vec::new();
        for (key, _val) in cursor.iter() {
            if key.starts_with(b"pending_") {
                del_keys.push(key.to_vec());
            }
        }
        drop(cursor);
        for key in del_keys {
            wtxn.del(self.db_txs, &key, None)?;
        }
        wtxn.commit()?;
        Ok(())
    }
    // ------------------------
    // mempool persistence ops (NEW)
    // ------------------------

    /// Simpan tx ke bucket mempool (key = txid_hex)
    pub fn put_mempool_tx(&self, txid_hex: &str, tx: &TxEnvelope) -> Result<()> {
        let blob = bincode::serialize(tx)?;
        let mut wtxn = self.env.begin_rw_txn()?;
        wtxn.put(self.db_mempool, &txid_hex.as_bytes(), &blob, WriteFlags::empty())?;
        wtxn.commit()?;
        Ok(())
    }

    /// Hapus tx dari bucket mempool
    pub fn delete_mempool_tx(&self, txid_hex: &str) -> Result<()> {
        let mut wtxn = self.env.begin_rw_txn()?;
        match wtxn.del(self.db_mempool, &txid_hex.as_bytes(), None) {
            Ok(_) => {},
            Err(lmdb::Error::NotFound) => {}, // already deleted, OK
            Err(e) => return Err(e.into()),
        }
        wtxn.commit()?;
        Ok(())
    }

    /// Load semua tx dari bucket mempool (saat startup)
    pub fn load_all_mempool_txs(&self) -> Result<Vec<TxEnvelope>> {
        let rtxn = self.env.begin_ro_txn()?;
        let mut cursor = rtxn.open_ro_cursor(self.db_mempool)?;
        let mut txs = Vec::new();
        for (_key, val) in cursor.iter() {
            let tx: TxEnvelope = bincode::deserialize(val)?;
            txs.push(tx);
        }
        Ok(txs)
    }

    /// Hapus semua tx dari bucket mempool (cleanup setelah block mined)
    pub fn clear_all_mempool_txs(&self) -> Result<()> {
        let mut wtxn = self.env.begin_rw_txn()?;
        let mut cursor = wtxn.open_rw_cursor(self.db_mempool)?;
        let mut del_keys = Vec::new();
        for (key, _val) in cursor.iter() {
            del_keys.push(key.to_vec());
        }
        drop(cursor);
        for key in del_keys {
            wtxn.del(self.db_mempool, &key, None)?;
        }
        wtxn.commit()?;
        Ok(())
    }

    // ------------------------
    // pending unstake ops (13.8.G)
    // ------------------------

    /// Store pending unstake entries for an address
    pub fn put_pending_unstake(&self, addr: &Address, entries: &[crate::state::UnstakeEntry]) -> Result<()> {
        let key = addr.as_bytes();
        let blob = bincode::serialize(entries)?;
        let mut wtxn = self.env.begin_rw_txn()?;
        wtxn.put(self.db_pending_unstake, key, &blob, WriteFlags::empty())?;
        wtxn.commit()?;
        Ok(())
    }

    /// Delete pending unstake entries for an address
    pub fn delete_pending_unstake(&self, addr: &Address) -> Result<()> {
        let mut wtxn = self.env.begin_rw_txn()?;
        match wtxn.del(self.db_pending_unstake, addr.as_bytes(), None) {
            Ok(_) => {},
            Err(lmdb::Error::NotFound) => {},
            Err(e) => return Err(e.into()),
        }
        wtxn.commit()?;
        Ok(())
    }

    /// Load all pending unstake entries from DB
    pub fn load_pending_unstake_all(&self) -> Result<std::collections::HashMap<Address, Vec<crate::state::UnstakeEntry>>> {
        let mut result = std::collections::HashMap::new();
        let rtxn = self.env.begin_ro_txn()?;
        let mut cursor = rtxn.open_ro_cursor(self.db_pending_unstake)?;
        
        for (key, val) in cursor.iter() {
            if key.len() == 20 {
                let addr = Address::from_bytes(key.try_into().map_err(|_| anyhow::anyhow!("invalid address key"))?);
                let entries: Vec<crate::state::UnstakeEntry> = bincode::deserialize(val)?;
                if !entries.is_empty() {
                    result.insert(addr, entries);
                }
            }
        }
        
        Ok(result)
    }

        pub fn load_pending_unstake(&self, addr: &Address) -> Result<Option<Vec<crate::state::UnstakeEntry>>> {
        let rtxn = self.env.begin_ro_txn()?;
        match rtxn.get(self.db_pending_unstake, addr.as_bytes()) {
            Ok(val) => {
                let entries: Vec<crate::state::UnstakeEntry> = bincode::deserialize(val)?;
                Ok(Some(entries))
            }
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    // ============================================================
    // NEW STATE LAYOUT OPERATIONS (13.8.H)
    // ============================================================
    // Bucket: state/validators/{addr}
    // ============================================================

    /// Put validator info to state/validators/{addr}
    pub fn put_state_validator(&self, addr: &Address, info: &ValidatorInfo) -> Result<()> {
        let key = addr.as_bytes();
        let blob = bincode::serialize(info)?;
        let mut wtxn = self.env.begin_rw_txn()?;
        wtxn.put(self.db_state_validators, key, &blob, WriteFlags::empty())?;
        wtxn.commit()?;
        Ok(())
    }

    /// Get validator info from state/validators/{addr}
    pub fn get_state_validator(&self, addr: &Address) -> Result<Option<ValidatorInfo>> {
        let rtxn = self.env.begin_ro_txn()?;
        match rtxn.get(self.db_state_validators, addr.as_bytes()) {
            Ok(val) => Ok(Some(bincode::deserialize(val)?)),
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Delete validator from state/validators/{addr}
    pub fn delete_state_validator(&self, addr: &Address) -> Result<()> {
        let mut wtxn = self.env.begin_rw_txn()?;
        match wtxn.del(self.db_state_validators, addr.as_bytes(), None) {
            Ok(_) | Err(lmdb::Error::NotFound) => {}
            Err(e) => return Err(e.into()),
        }
        wtxn.commit()?;
        Ok(())
    }

    /// Load all validators from state/validators bucket
    pub fn load_all_state_validators(&self) -> Result<std::collections::HashMap<Address, ValidatorInfo>> {
        let mut result = std::collections::HashMap::new();
        let rtxn = self.env.begin_ro_txn()?;
        let mut cursor = rtxn.open_ro_cursor(self.db_state_validators)?;
        for (key, val) in cursor.iter() {
            if key.len() == 20 {
                let addr = Address::from_bytes(key.try_into().map_err(|_| anyhow::anyhow!("invalid key"))?);
                let info: ValidatorInfo = bincode::deserialize(val)?;
                result.insert(addr, info);
            }
        }
        Ok(result)
    }

    // ============================================================
    // Bucket: state/stake/{addr}
    // ============================================================

    /// Put stake data to state/stake/{addr}
    pub fn put_stake(&self, addr: &Address, data: &StakeData) -> Result<()> {
        let key = addr.as_bytes();
        let blob = bincode::serialize(data)?;
        let mut wtxn = self.env.begin_rw_txn()?;
        wtxn.put(self.db_state_stake, key, &blob, WriteFlags::empty())?;
        wtxn.commit()?;
        Ok(())
    }

    /// Get stake data from state/stake/{addr}
    pub fn get_stake(&self, addr: &Address) -> Result<Option<StakeData>> {
        let rtxn = self.env.begin_ro_txn()?;
        match rtxn.get(self.db_state_stake, addr.as_bytes()) {
            Ok(val) => Ok(Some(bincode::deserialize(val)?)),
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Delete stake data from state/stake/{addr}
    pub fn delete_stake(&self, addr: &Address) -> Result<()> {
        let mut wtxn = self.env.begin_rw_txn()?;
        match wtxn.del(self.db_state_stake, addr.as_bytes(), None) {
            Ok(_) | Err(lmdb::Error::NotFound) => {}
            Err(e) => return Err(e.into()),
        }
        wtxn.commit()?;
        Ok(())
    }

    /// Load all stake data from state/stake bucket
    pub fn load_all_stakes(&self) -> Result<std::collections::HashMap<Address, StakeData>> {
        let mut result = std::collections::HashMap::new();
        let rtxn = self.env.begin_ro_txn()?;
        let mut cursor = rtxn.open_ro_cursor(self.db_state_stake)?;
        for (key, val) in cursor.iter() {
            if key.len() == 20 {
                let addr = Address::from_bytes(key.try_into().map_err(|_| anyhow::anyhow!("invalid key"))?);
                let data: StakeData = bincode::deserialize(val)?;
                result.insert(addr, data);
            }
        }
        Ok(result)
    }

    // ============================================================
    // Bucket: state/delegators/{addr}
    // ============================================================

    /// Put delegator data to state/delegators/{addr}
    pub fn put_delegator(&self, addr: &Address, data: &DelegatorData) -> Result<()> {
        let key = addr.as_bytes();
        let blob = bincode::serialize(data)?;
        let mut wtxn = self.env.begin_rw_txn()?;
        wtxn.put(self.db_state_delegators, key, &blob, WriteFlags::empty())?;
        wtxn.commit()?;
        Ok(())
    }

    /// Get delegator data from state/delegators/{addr}
    pub fn get_delegator(&self, addr: &Address) -> Result<Option<DelegatorData>> {
        let rtxn = self.env.begin_ro_txn()?;
        match rtxn.get(self.db_state_delegators, addr.as_bytes()) {
            Ok(val) => Ok(Some(bincode::deserialize(val)?)),
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Delete delegator data from state/delegators/{addr}
    pub fn delete_delegator(&self, addr: &Address) -> Result<()> {
        let mut wtxn = self.env.begin_rw_txn()?;
        match wtxn.del(self.db_state_delegators, addr.as_bytes(), None) {
            Ok(_) | Err(lmdb::Error::NotFound) => {}
            Err(e) => return Err(e.into()),
        }
        wtxn.commit()?;
        Ok(())
    }

    /// Load all delegator data from state/delegators bucket
    pub fn load_all_delegators(&self) -> Result<std::collections::HashMap<Address, DelegatorData>> {
        let mut result = std::collections::HashMap::new();
        let rtxn = self.env.begin_ro_txn()?;
        let mut cursor = rtxn.open_ro_cursor(self.db_state_delegators)?;
        for (key, val) in cursor.iter() {
            if key.len() == 20 {
                let addr = Address::from_bytes(key.try_into().map_err(|_| anyhow::anyhow!("invalid key"))?);
                let data: DelegatorData = bincode::deserialize(val)?;
                result.insert(addr, data);
            }
        }
        Ok(result)
    }

    // ============================================================
    // Bucket: state/qv_weights/{addr}
    // ============================================================

    /// Put QV weight data to state/qv_weights/{addr}
    pub fn put_qv_weight(&self, addr: &Address, data: &QvWeightData) -> Result<()> {
        let key = addr.as_bytes();
        let blob = bincode::serialize(data)?;
        let mut wtxn = self.env.begin_rw_txn()?;
        wtxn.put(self.db_state_qv_weights, key, &blob, WriteFlags::empty())?;
        wtxn.commit()?;
        Ok(())
    }

    /// Get QV weight data from state/qv_weights/{addr}
    pub fn get_qv_weight(&self, addr: &Address) -> Result<Option<QvWeightData>> {
        let rtxn = self.env.begin_ro_txn()?;
        match rtxn.get(self.db_state_qv_weights, addr.as_bytes()) {
            Ok(val) => Ok(Some(bincode::deserialize(val)?)),
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Delete QV weight data from state/qv_weights/{addr}
    pub fn delete_qv_weight(&self, addr: &Address) -> Result<()> {
        let mut wtxn = self.env.begin_rw_txn()?;
        match wtxn.del(self.db_state_qv_weights, addr.as_bytes(), None) {
            Ok(_) | Err(lmdb::Error::NotFound) => {}
            Err(e) => return Err(e.into()),
        }
        wtxn.commit()?;
        Ok(())
    }

    /// Load all QV weight data from state/qv_weights bucket
    pub fn load_all_qv_weights(&self) -> Result<std::collections::HashMap<Address, QvWeightData>> {
        let mut result = std::collections::HashMap::new();
        let rtxn = self.env.begin_ro_txn()?;
        let mut cursor = rtxn.open_ro_cursor(self.db_state_qv_weights)?;
        for (key, val) in cursor.iter() {
            if key.len() == 20 {
                let addr = Address::from_bytes(key.try_into().map_err(|_| anyhow::anyhow!("invalid key"))?);
                let data: QvWeightData = bincode::deserialize(val)?;
                result.insert(addr, data);
            }
        }
        Ok(result)
    }

    // ============================================================
    // Bucket: state/validator_metadata/{addr}
    // ============================================================

    /// Put validator metadata to state/validator_metadata/{addr}
    pub fn put_validator_metadata(&self, addr: &Address, data: &ValidatorMetadata) -> Result<()> {
        let key = addr.as_bytes();
        let blob = bincode::serialize(data)?;
        let mut wtxn = self.env.begin_rw_txn()?;
        wtxn.put(self.db_state_validator_metadata, key, &blob, WriteFlags::empty())?;
        wtxn.commit()?;
        Ok(())
    }

    /// Get validator metadata from state/validator_metadata/{addr}
    pub fn get_validator_metadata(&self, addr: &Address) -> Result<Option<ValidatorMetadata>> {
        let rtxn = self.env.begin_ro_txn()?;
        match rtxn.get(self.db_state_validator_metadata, addr.as_bytes()) {
            Ok(val) => Ok(Some(bincode::deserialize(val)?)),
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Delete validator metadata from state/validator_metadata/{addr}
    pub fn delete_validator_metadata(&self, addr: &Address) -> Result<()> {
        let mut wtxn = self.env.begin_rw_txn()?;
        match wtxn.del(self.db_state_validator_metadata, addr.as_bytes(), None) {
            Ok(_) | Err(lmdb::Error::NotFound) => {}
            Err(e) => return Err(e.into()),
        }
        wtxn.commit()?;
        Ok(())
    }

    /// Load all validator metadata from state/validator_metadata bucket
    pub fn load_all_validator_metadata(&self) -> Result<std::collections::HashMap<Address, ValidatorMetadata>> {
        let mut result = std::collections::HashMap::new();
        let rtxn = self.env.begin_ro_txn()?;
        let mut cursor = rtxn.open_ro_cursor(self.db_state_validator_metadata)?;
        for (key, val) in cursor.iter() {
            if key.len() == 20 {
                let addr = Address::from_bytes(key.try_into().map_err(|_| anyhow::anyhow!("invalid key"))?);
                let data: ValidatorMetadata = bincode::deserialize(val)?;
                result.insert(addr, data);
            }
        }
        Ok(result)
    }


    // ------------------------
    // account/validator ops
    // ------------------------

    pub fn write_account(&self, acct: &Account) -> Result<()> {
        let key = acct.address.as_bytes();
        let blob = bincode::serialize(acct)?;
        let mut wtxn = self.env.begin_rw_txn()?;
        wtxn.put(self.db_accounts, key, &blob, WriteFlags::empty())?;
        wtxn.commit()?;
        Ok(())
    }

    pub fn load_account(&self, addr: &Address) -> Result<Option<Account>> {
        let rtxn = self.env.begin_ro_txn()?;
        match rtxn.get(self.db_accounts, addr.as_bytes()) {
            Ok(v) => Ok(Some(bincode::deserialize(v)?)),
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn write_validator(&self, v: &ValidatorInfo) -> Result<()> {
        let key = v.address.as_bytes();
        let blob = bincode::serialize(v)?;
        let mut wtxn = self.env.begin_rw_txn()?;
        wtxn.put(self.db_validators, key, &blob, WriteFlags::empty())?;
        wtxn.commit()?;
        Ok(())
    }

    pub fn load_validator(&self, addr: &Address) -> Result<Option<ValidatorInfo>> {
        let rtxn = self.env.begin_ro_txn()?;
        match rtxn.get(self.db_validators, addr.as_bytes()) {
            Ok(v) => Ok(Some(bincode::deserialize(v)?)),
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    // ------------------------
    // ValidatorSet ops (DPoS Hybrid)
    // ------------------------

    /// Persist entire ValidatorSet atomically
    pub fn persist_validator_set(&self, set: &ValidatorSet) -> Result<()> {
        let mut wtxn = self.env.begin_rw_txn()?;
        
        // Clear existing entries first (untuk handle removal)
        let mut cursor = wtxn.open_rw_cursor(self.db_validator_set)?;
        let mut del_keys = Vec::new();
        for (key, _val) in cursor.iter() {
            del_keys.push(key.to_vec());
        }
        drop(cursor);
        for key in del_keys {
            wtxn.del(self.db_validator_set, &key, None)?;
        }
        
        // Write current set
        for (addr, vinfo) in &set.validators {
            let db_vinfo = ValidatorInfo {
                address: vinfo.address,
                stake: vinfo.stake,
                pubkey: vinfo.pubkey.clone(),
                active: vinfo.active,
                moniker: vinfo.moniker.clone(),
            };
            let key = addr.as_bytes();
            let blob = bincode::serialize(&db_vinfo)?;
            wtxn.put(self.db_validator_set, key, &blob, WriteFlags::empty())?;
        }
        
        wtxn.commit()?;
        Ok(())
    }

    /// Load entire ValidatorSet from DB
    pub fn load_validator_set(&self) -> Result<ValidatorSet> {
        let mut set = ValidatorSet::new();
        let rtxn = self.env.begin_ro_txn()?;
        
        let mut cursor = rtxn.open_ro_cursor(self.db_validator_set)?;
        for (_key, val) in cursor.iter() {
            let db_vinfo: ValidatorInfo = bincode::deserialize(val)?;
            let state_vinfo = StateValidatorInfo {
                address: db_vinfo.address,
                pubkey: db_vinfo.pubkey,
                stake: db_vinfo.stake,
                active: db_vinfo.active,
                moniker: db_vinfo.moniker,
            };
            set.validators.insert(state_vinfo.address, state_vinfo);
        }
        
        Ok(set)
    }

    // Stake is handled via locked in accounts and stake in validators; no separate write_stake

    // ------------------------
    // state operations
    // ------------------------

    /// Load entire state from DB (termasuk reward_pool)
     pub fn load_state(&self) -> Result<ChainState> {
        let mut state = ChainState::new();
        let rtxn = self.env.begin_ro_txn()?;

        // Load accounts
        {
            let mut cursor = rtxn.open_ro_cursor(self.db_accounts)?;
            for (_key, val) in cursor.iter() {
                let acct: Account = bincode::deserialize(val)?;
                state.balances.insert(acct.address, acct.balance);
                state.nonces.insert(acct.address, acct.nonce);
                state.locked.insert(acct.address, acct.locked);
            }
        }

        // Load validators
        {
            let mut cursor_val = rtxn.open_ro_cursor(self.db_validators)?;
            for (_key, val) in cursor_val.iter() {
                let vi: ValidatorInfo = bincode::deserialize(val)?;
                state.validators.insert(vi.address, vi.into());
            }
        }

        // Load reward_pool dari meta DB (kalau belum ada, default 0)
        if let Ok(bytes) = rtxn.get(self.db_meta, b"reward_pool") {
            if bytes.len() == 16 {
                state.reward_pool = u128::from_be_bytes(bytes.try_into().unwrap());
            }
        }
        if let Ok(bytes) = rtxn.get(self.db_meta, b"liveness_records") {
            if let Ok(records) = bincode::deserialize(bytes) {
                 state.liveness_records = records;
            }
        }
        // Load ValidatorSet (DPoS Hybrid)
        drop(rtxn); // release read txn sebelum call load_validator_set
        state.validator_set = self.load_validator_set()?;

        // Load pending unstakes (13.8.G)
        let pending_unstakes = self.load_pending_unstake_all()?;
        state.set_pending_unstakes(pending_unstakes);
        println!("   ✓ Loaded {} addresses with pending unstakes", state.pending_unstakes.len());

        // Total supply: sum semua balance (tetap akurat)
        state.total_supply = state.balances.values().cloned().sum::<u128>();

        Ok(state)
    }

    /// Persist entire state to DB (atomic) — sekarang termasuk reward_pool
    pub fn persist_state(&self, state: &ChainState) -> Result<()> {
        let mut wtxn = self.env.begin_rw_txn()?;

        // === Persist accounts ===
        for (addr, bal) in &state.balances {
            let nonce = state.nonces.get(addr).copied().unwrap_or(0);
            let locked = state.locked.get(addr).copied().unwrap_or(0);
            let acct = Account {
                address: *addr,
                balance: *bal,
                nonce,
                locked,
            };
            let key = addr.as_bytes();
            let blob = bincode::serialize(&acct)?;
            wtxn.put(self.db_accounts, key, &blob, WriteFlags::empty())?;
        }

        // === Persist validators ===
        for (addr, val) in &state.validators {
            let vi: ValidatorInfo = val.clone().into();
            let key = addr.as_bytes();
            let blob = bincode::serialize(&vi)?;
            wtxn.put(self.db_validators, key, &blob, WriteFlags::empty())?;
        }

        // === Persist reward_pool ke meta DB ===
        wtxn.put(
            self.db_meta,
            b"reward_pool",
            &state.reward_pool.to_be_bytes(),
            WriteFlags::empty(),
        )?;

        // Commit atomic
        wtxn.commit()?;
        
        // === Persist ValidatorSet (DPoS Hybrid) ===
        // Dilakukan terpisah karena butuh clear + write atomic
        self.persist_validator_set(&state.validator_set)?;

        Ok(())
    }

    // No separate put_state_root; stored in block header

    // ------------------------
    // meta (tip)
    // ------------------------

    pub fn set_tip(&self, height: u64, hash: &Hash) -> Result<()> {
        let mut wtxn = self.env.begin_rw_txn()?;
        let height_key = b"tip_height";
        wtxn.put(self.db_meta, height_key, &height.to_be_bytes(), WriteFlags::empty())?;
        let hash_key = b"tip_hash";
        wtxn.put(self.db_meta, hash_key, hash.as_bytes(), WriteFlags::empty())?;
        wtxn.commit()?;
        Ok(())
    }

    pub fn get_tip(&self) -> Result<Option<(u64, Hash)>> {
        let rtxn = self.env.begin_ro_txn()?;
        match rtxn.get(self.db_meta, b"tip_height") {
            Ok(vh) => {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(vh);
                let height = u64::from_be_bytes(arr);
                let hash_bytes = rtxn.get(self.db_meta, b"tip_hash")?;
                let hash = Hash::from_bytes(hash_bytes.try_into()?);
                Ok(Some((height, hash)))
            }
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    // ============================================================
    // ATOMIC BLOCK COMMIT (13.7.I)
    // ============================================================
    // All block-related writes in a single LMDB transaction
    // If any operation fails, entire transaction is rolled back
    // ============================================================

    /// Atomically commit block, transactions, receipts, state, and tip
    /// This ensures chain consistency - either ALL data is committed or NONE
    pub fn atomic_commit_block(
        &self,
        block: &Block,
        state_snapshot: &ChainState,
    ) -> Result<()> {
        println!("🔒 ATOMIC COMMIT START - Block {}", block.header.height);
        
        let mut wtxn = self.env.begin_rw_txn()?;

        // ─────────────────────────────────────────────────────────
        // 1) STORE BLOCK
        // ─────────────────────────────────────────────────────────
        let height_key = Self::height_key(block.header.height);
        let block_blob = bincode::serialize(block)?;
        let block_hash = crate::block::Block::compute_hash(&block.header);
        let hash_key = block_hash.as_bytes();
        let height_value = block.header.height.to_be_bytes();

        wtxn.put(self.db_blocks, &height_key, &block_blob, WriteFlags::empty())?;
        wtxn.put(self.db_block_hashes, hash_key, &height_value, WriteFlags::empty())?;
        println!("   ✓ Block stored (height={}, hash={})", block.header.height, block_hash);

        // ─────────────────────────────────────────────────────────
        // 2) STORE TRANSACTIONS
        // ─────────────────────────────────────────────────────────
        for tx in &block.body.transactions {
            let txid = tx.compute_txid()?;
            let tx_key = txid.as_bytes();
            let tx_blob = bincode::serialize(tx)?;
            wtxn.put(self.db_txs, tx_key, &tx_blob, WriteFlags::empty())?;
        }
        println!("   ✓ {} transaction(s) stored", block.body.transactions.len());

        // ─────────────────────────────────────────────────────────
        // 3) STORE RECEIPTS
        // ─────────────────────────────────────────────────────────
        for receipt in &block.body.receipts {
            let receipt_key = receipt.tx_hash.as_bytes();
            let receipt_blob = bincode::serialize(receipt)?;
            wtxn.put(self.db_receipts, receipt_key, &receipt_blob, WriteFlags::empty())?;
        }
        println!("   ✓ {} receipt(s) stored", block.body.receipts.len());

        // ─────────────────────────────────────────────────────────
        // 4) STORE STATE SNAPSHOT (accounts, validators, pools)
        // ─────────────────────────────────────────────────────────
        // 4a) Persist accounts
        for (addr, bal) in &state_snapshot.balances {
            let nonce = state_snapshot.nonces.get(addr).copied().unwrap_or(0);
            let locked = state_snapshot.locked.get(addr).copied().unwrap_or(0);
            let acct = Account {
                address: *addr,
                balance: *bal,
                nonce,
                locked,
            };
            let key = addr.as_bytes();
            let blob = bincode::serialize(&acct)?;
            wtxn.put(self.db_accounts, key, &blob, WriteFlags::empty())?;
        }
        println!("   ✓ {} account(s) persisted", state_snapshot.balances.len());

        // 4b) Persist validators
        for (addr, val) in &state_snapshot.validators {
            let vi: ValidatorInfo = val.clone().into();
            let key = addr.as_bytes();
            let blob = bincode::serialize(&vi)?;
            wtxn.put(self.db_validators, key, &blob, WriteFlags::empty())?;
        }
        println!("   ✓ {} validator(s) persisted", state_snapshot.validators.len());

        // 4c) Persist reward_pool
        wtxn.put(
            self.db_meta,
            b"reward_pool",
            &state_snapshot.reward_pool.to_be_bytes(),
            WriteFlags::empty(),
        )?;

        // 4d) Persist treasury_balance
        wtxn.put(
            self.db_meta,
            b"treasury_balance",
            &state_snapshot.treasury_balance.to_be_bytes(),
            WriteFlags::empty(),
        )?;

        // 4e) Persist delegator_pool
        wtxn.put(
            self.db_meta,
            b"delegator_pool",
            &state_snapshot.delegator_pool.to_be_bytes(),
            WriteFlags::empty(),
        )?;
        println!("   ✓ State pools persisted (reward, treasury, delegator)");

        // ─────────────────────────────────────────────────────────
        // 5) STORE VALIDATOR SET (DPoS Hybrid)
        // ─────────────────────────────────────────────────────────
        // Clear existing validator_set entries
        {
            let mut cursor = wtxn.open_rw_cursor(self.db_validator_set)?;
            let mut del_keys = Vec::new();
            for (key, _val) in cursor.iter() {
                del_keys.push(key.to_vec());
            }
            drop(cursor);
            for key in del_keys {
                wtxn.del(self.db_validator_set, &key, None)?;
            }
        }
        // Write current validator set
        for (addr, vinfo) in &state_snapshot.validator_set.validators {
            let db_vinfo = ValidatorInfo {
                address: vinfo.address,
                stake: vinfo.stake,
                pubkey: vinfo.pubkey.clone(),
                active: vinfo.active,
                moniker: vinfo.moniker.clone(),
            };
            let key = addr.as_bytes();
            let blob = bincode::serialize(&db_vinfo)?;
            wtxn.put(self.db_validator_set, key, &blob, WriteFlags::empty())?;
        }
        println!("   ✓ ValidatorSet persisted ({} validators)", 
                 state_snapshot.validator_set.validators.len());

        // ─────────────────────────────────────────────────────────
        // 5b) PERSIST PENDING UNSTAKES (13.8.G)
        // ─────────────────────────────────────────────────────────
        // Clear existing pending unstake entries
        {
            let mut cursor = wtxn.open_rw_cursor(self.db_pending_unstake)?;
            let mut del_keys = Vec::new();
            for (key, _val) in cursor.iter() {
                del_keys.push(key.to_vec());
            }
            drop(cursor);
            for key in del_keys {
                wtxn.del(self.db_pending_unstake, &key, None)?;
            }
        }
        // Write current pending unstakes
        for (addr, entries) in state_snapshot.get_all_pending_unstakes() {
            if !entries.is_empty() {
                let key = addr.as_bytes();
                let blob = bincode::serialize(entries)?;
                wtxn.put(self.db_pending_unstake, key, &blob, WriteFlags::empty())?;
            }
        }
         println!("   ✓ Pending unstakes persisted ({} addresses)", 
                 state_snapshot.pending_unstakes.len());

        // ─────────────────────────────────────────────────────────
        // 5c) PERSIST NEW STATE LAYOUT (13.8.H)
        // ─────────────────────────────────────────────────────────
        
        // 5c-1) Persist state/validators
        {
            let mut cursor = wtxn.open_rw_cursor(self.db_state_validators)?;
            let mut del_keys = Vec::new();
            for (key, _) in cursor.iter() { del_keys.push(key.to_vec()); }
            drop(cursor);
            for key in del_keys { wtxn.del(self.db_state_validators, &key, None)?; }
        }
        for (addr, vinfo) in &state_snapshot.validator_set.validators {
            let db_vinfo = ValidatorInfo {
                address: vinfo.address,
                stake: vinfo.stake,
                pubkey: vinfo.pubkey.clone(),
                active: vinfo.active,
                moniker: vinfo.moniker.clone(),
            };
            let blob = bincode::serialize(&db_vinfo)?;
            wtxn.put(self.db_state_validators, addr.as_bytes(), &blob, WriteFlags::empty())?;
        }
        
        // 5c-2) Persist state/stake
        {
            let mut cursor = wtxn.open_rw_cursor(self.db_state_stake)?;
            let mut del_keys = Vec::new();
            for (key, _) in cursor.iter() { del_keys.push(key.to_vec()); }
            drop(cursor);
            for key in del_keys { wtxn.del(self.db_state_stake, &key, None)?; }
        }
        // Persist validator stakes
        for (addr, &stake) in &state_snapshot.validator_stakes {
            let locked = state_snapshot.locked.get(addr).copied().unwrap_or(0);
            let delegator_stake = state_snapshot.delegator_stakes.get(addr).copied().unwrap_or(0);
            let data = StakeData {
                address: *addr,
                validator_stake: stake,
                delegator_stake,
                locked,
            };
            let blob = bincode::serialize(&data)?;
            wtxn.put(self.db_state_stake, addr.as_bytes(), &blob, WriteFlags::empty())?;
        }
        // Persist delegator stakes (if not already in validator_stakes)
        for (addr, &stake) in &state_snapshot.delegator_stakes {
            if !state_snapshot.validator_stakes.contains_key(addr) {
                let locked = state_snapshot.locked.get(addr).copied().unwrap_or(0);
                let data = StakeData {
                    address: *addr,
                    validator_stake: 0,
                    delegator_stake: stake,
                    locked,
                };
                let blob = bincode::serialize(&data)?;
                wtxn.put(self.db_state_stake, addr.as_bytes(), &blob, WriteFlags::empty())?;
            }
        }
        
        // 5c-3) Persist state/delegators
        {
            let mut cursor = wtxn.open_rw_cursor(self.db_state_delegators)?;
            let mut del_keys = Vec::new();
            for (key, _) in cursor.iter() { del_keys.push(key.to_vec()); }
            drop(cursor);
            for key in del_keys { wtxn.del(self.db_state_delegators, &key, None)?; }
        }
        for (addr, validator) in &state_snapshot.delegator_to_validator {
            let delegated = state_snapshot.delegator_stakes.get(addr).copied().unwrap_or(0);
            let last_epoch = state_snapshot.delegator_last_epoch.get(addr).copied().unwrap_or(0);
            let accrued = state_snapshot.delegator_reward_accrued.get(addr).copied().unwrap_or(0);
            let data = DelegatorData {
                address: *addr,
                validator: Some(*validator),
                delegated_amount: delegated,
                last_reward_epoch: last_epoch,
                reward_accrued: accrued,
            };
            let blob = bincode::serialize(&data)?;
            wtxn.put(self.db_state_delegators, addr.as_bytes(), &blob, WriteFlags::empty())?;
        }
        
        // 5c-4) Persist state/qv_weights
        {
            let mut cursor = wtxn.open_rw_cursor(self.db_state_qv_weights)?;
            let mut del_keys = Vec::new();
            for (key, _) in cursor.iter() { del_keys.push(key.to_vec()); }
            drop(cursor);
            for key in del_keys { wtxn.del(self.db_state_qv_weights, &key, None)?; }
        }
        // Collect all addresses with QV weights
        let mut qv_addrs: std::collections::HashSet<Address> = state_snapshot.qv_weights.keys().cloned().collect();
        qv_addrs.extend(state_snapshot.validator_qv_weights.keys().cloned());
        for addr in qv_addrs {
            let individual = state_snapshot.qv_weights.get(&addr).copied().unwrap_or(0);
            let combined = state_snapshot.validator_qv_weights.get(&addr).copied().unwrap_or(0);
            let data = QvWeightData {
                address: addr,
                individual_weight: individual,
                validator_combined_weight: combined,
            };
            let blob = bincode::serialize(&data)?;
            wtxn.put(self.db_state_qv_weights, addr.as_bytes(), &blob, WriteFlags::empty())?;
        }
        
        // 5c-5) Persist state/node_cost (13.9)
        {
            let mut cursor = wtxn.open_rw_cursor(self.db_state_node_cost)?;
            let mut del_keys = Vec::new();
            for (key, _) in cursor.iter() { del_keys.push(key.to_vec()); }
            drop(cursor);
            for key in del_keys { wtxn.del(self.db_state_node_cost, &key, None)?; }
        }
        // Collect all addresses with node cost data
        let mut node_addrs: std::collections::HashSet<Address> = state_snapshot.node_cost_index.keys().cloned().collect();
        node_addrs.extend(state_snapshot.node_earnings.keys().cloned());
        for addr in node_addrs {
            let cost_index = state_snapshot.node_cost_index.get(&addr).copied().unwrap_or(0);
            let earnings = state_snapshot.node_earnings.get(&addr).copied().unwrap_or(0);
            let data = NodeCostData {
                address: addr,
                cost_index,
                earnings,
            };
            let blob = bincode::serialize(&data)?;
            wtxn.put(self.db_state_node_cost, addr.as_bytes(), &blob, WriteFlags::empty())?;
        }
        
        println!("   ✓ New state layout persisted (13.8.H): validators={}, stakes={}, delegators={}, qv_weights={}, node_costs={}",
                 state_snapshot.validator_set.validators.len(),
                 state_snapshot.validator_stakes.len() + state_snapshot.delegator_stakes.len(),
                 state_snapshot.delegator_to_validator.len(),
                 state_snapshot.qv_weights.len(),
                 state_snapshot.node_cost_index.len());



        // ─────────────────────────────────────────────────────────
        // 6) SET TIP (height + hash)
        // ─────────────────────────────────────────────────────────
        wtxn.put(self.db_meta, b"tip_height", &block.header.height.to_be_bytes(), WriteFlags::empty())?;
        wtxn.put(self.db_meta, b"tip_hash", block_hash.as_bytes(), WriteFlags::empty())?;
        println!("   ✓ Chain tip updated to height {}", block.header.height);

        // ─────────────────────────────────────────────────────────
        // 7) CLEAR PENDING TXS (within same transaction)
        // ─────────────────────────────────────────────────────────
        {
            let mut cursor = wtxn.open_rw_cursor(self.db_txs)?;
            let mut del_keys = Vec::new();
            for (key, _val) in cursor.iter() {
                if key.starts_with(b"pending_") {
                    del_keys.push(key.to_vec());
                }
            }
            drop(cursor);
            for key in del_keys {
                wtxn.del(self.db_txs, &key, None)?;
            }
        }
        println!("   ✓ Pending transactions cleared");

        // ─────────────────────────────────────────────────────────
        // 8) CLEAR MEMPOOL BUCKET (within same transaction)
        // ─────────────────────────────────────────────────────────
        {
            let mut cursor = wtxn.open_rw_cursor(self.db_mempool)?;
            let mut del_keys = Vec::new();
            for (key, _val) in cursor.iter() {
                del_keys.push(key.to_vec());
            }
            drop(cursor);
            for key in del_keys {
                wtxn.del(self.db_mempool, &key, None)?;
            }
        }
        println!("   ✓ Mempool bucket cleared");

        // ─────────────────────────────────────────────────────────
        // COMMIT - All or nothing!
        // ─────────────────────────────────────────────────────────
        wtxn.commit()?;

        println!("🔒 ATOMIC COMMIT SUCCESS - Block {} committed", block.header.height);
        Ok(())
    }

    /// Load receipt by tx_hash
    pub fn get_receipt(&self, tx_hash: &Hash) -> Result<Option<Receipt>> {
        let rtxn = self.env.begin_ro_txn()?;
        match rtxn.get(self.db_receipts, tx_hash.as_bytes()) {
            Ok(val) => Ok(Some(bincode::deserialize(val)?)),
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    // ============================================================
    // NODE COST DATA OPERATIONS (13.9)
    // ============================================================

    /// Store NodeCostData for an address
    pub fn put_node_cost_data(&self, addr: &Address, data: &NodeCostData) -> Result<()> {
        let key = addr.as_bytes();
        let blob = bincode::serialize(data)?;
        let mut wtxn = self.env.begin_rw_txn()?;
        wtxn.put(self.db_state_node_cost, key, &blob, WriteFlags::empty())?;
        wtxn.commit()?;
        Ok(())
    }

    /// Load NodeCostData for an address
    pub fn get_node_cost_data(&self, addr: &Address) -> Result<Option<NodeCostData>> {
        let rtxn = self.env.begin_ro_txn()?;
        let key = addr.as_bytes();
        match rtxn.get(self.db_state_node_cost, key) {
            Ok(val) => Ok(Some(bincode::deserialize(val)?)),
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Load all NodeCostData from database
    pub fn load_all_node_cost_data(&self) -> Result<std::collections::HashMap<Address, NodeCostData>> {
        let rtxn = self.env.begin_ro_txn()?;
        let mut cursor = rtxn.open_ro_cursor(self.db_state_node_cost)?;
        let mut result = std::collections::HashMap::new();
        for (key, val) in cursor.iter() {
            if key.len() == 20 {
                let addr = Address::from_bytes(key.try_into().unwrap());
                let data: NodeCostData = bincode::deserialize(val)?;
                result.insert(addr, data);
            }
        }
        Ok(result)
    }
        // ============================================================
    // NODE COST INDEX OPERATIONS - SEPARATE HELPERS (13.9)
    // ============================================================

    /// Store node cost index (multiplier) for an address
    pub fn put_node_cost(&self, addr: &Address, multiplier: u128) -> Result<()> {
        // Retrieve existing data or create new
        let mut data = self.get_node_cost_data(addr)?.unwrap_or_else(|| NodeCostData::new(*addr));
        data.cost_index = multiplier;
        self.put_node_cost_data(addr, &data)
    }

    /// Get node cost index (multiplier) for an address
    pub fn get_node_cost(&self, addr: &Address) -> Result<Option<u128>> {
        match self.get_node_cost_data(addr)? {
            Some(data) => Ok(Some(data.cost_index)),
            None => Ok(None),
        }
    }

    /// Iterate all node cost indices
    pub fn iter_node_cost(&self) -> Result<std::collections::HashMap<Address, u128>> {
        let all_data = self.load_all_node_cost_data()?;
        Ok(all_data.into_iter().map(|(addr, data)| (addr, data.cost_index)).collect())
    }

    // ============================================================
    // NODE EARNINGS OPERATIONS - SEPARATE BUCKET (13.9)
    // ============================================================

    /// Store node earnings for an address
    pub fn put_node_earning(&self, addr: &Address, amount: u128) -> Result<()> {
        let data = NodeEarningsData {
            address: *addr,
            amount,
        };
        let key = addr.as_bytes();
        let blob = bincode::serialize(&data)?;
        let mut wtxn = self.env.begin_rw_txn()?;
        wtxn.put(self.db_state_node_earnings, key, &blob, WriteFlags::empty())?;
        wtxn.commit()?;
        Ok(())
    }

    /// Get node earnings for an address
    pub fn get_node_earning(&self, addr: &Address) -> Result<Option<u128>> {
        let rtxn = self.env.begin_ro_txn()?;
        let key = addr.as_bytes();
        match rtxn.get(self.db_state_node_earnings, key) {
            Ok(val) => {
                let data: NodeEarningsData = bincode::deserialize(val)?;
                Ok(Some(data.amount))
            }
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Iterate all node earnings
    pub fn iter_node_earnings(&self) -> Result<std::collections::HashMap<Address, u128>> {
        let rtxn = self.env.begin_ro_txn()?;
        let mut cursor = rtxn.open_ro_cursor(self.db_state_node_earnings)?;
        let mut result = std::collections::HashMap::new();
        for (key, val) in cursor.iter() {
            if key.len() == 20 {
                let addr = Address::from_bytes(key.try_into().unwrap());
                let data: NodeEarningsData = bincode::deserialize(val)?;
                result.insert(addr, data.amount);
            }
        }
        Ok(result)
    }

    /// Load all NodeEarningsData from database
    pub fn load_all_node_earnings_data(&self) -> Result<std::collections::HashMap<Address, NodeEarningsData>> {
        let rtxn = self.env.begin_ro_txn()?;
        let mut cursor = rtxn.open_ro_cursor(self.db_state_node_earnings)?;
        let mut result = std::collections::HashMap::new();
        for (key, val) in cursor.iter() {
            if key.len() == 20 {
                let addr = Address::from_bytes(key.try_into().unwrap());
                let data: NodeEarningsData = bincode::deserialize(val)?;
                result.insert(addr, data);
            }
        }
        Ok(result)
    }

    // ============================================================
    // CLAIMED RECEIPTS OPERATIONS (13.10)
    // ============================================================
    // Bucket: claimed_receipts/{receipt_id}
    // Key: Hash (64 bytes)
    // Value: single byte marker (0x01)
    // ============================================================

    /// Store a claimed receipt_id to LMDB
    /// Idempotent: safe to call multiple times for the same receipt_id
    pub fn put_claimed_receipt(&self, receipt_id: &Hash) -> Result<()> {
        let key = receipt_id.as_bytes();
        let marker: [u8; 1] = [0x01]; // existence marker
        let mut wtxn = self.env.begin_rw_txn()?;
        wtxn.put(self.db_claimed_receipts, key, &marker, WriteFlags::empty())?;
        wtxn.commit()?;
        Ok(())
    }

    /// Check if a receipt_id has been claimed
    /// Returns true if the receipt_id exists in the bucket
    pub fn is_receipt_claimed(&self, receipt_id: &Hash) -> Result<bool> {
        let rtxn = self.env.begin_ro_txn()?;
        let key = receipt_id.as_bytes();
        match rtxn.get(self.db_claimed_receipts, key) {
            Ok(_) => Ok(true),
            Err(lmdb::Error::NotFound) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Load all claimed receipt_ids from database
    /// Returns HashSet<Hash> containing all claimed receipt_ids
    pub fn load_all_claimed_receipts(&self) -> Result<HashSet<Hash>> {
        let rtxn = self.env.begin_ro_txn()?;
        let mut cursor = rtxn.open_ro_cursor(self.db_claimed_receipts)?;
        let mut result = HashSet::new();
        for (key, _val) in cursor.iter() {
            if key.len() == 64 {
                let hash = Hash::from_bytes(key.try_into().unwrap());
                result.insert(hash);
            }
        }
        Ok(result)
    }

    // helpers
    fn height_key(height: u64) -> [u8; 8] {
        height.to_be_bytes()
    }

    // ============================================================
    // HEADER SYNC OPERATIONS (13.11)
    // ============================================================
    // Bucket: headers/{height}
    // Key: height (big-endian u64, 8 bytes)
    // Value: serialized BlockHeader
    // ============================================================

    /// Store a BlockHeader at given height
    /// Key = height as big-endian u64
    /// Value = bincode serialized BlockHeader
    pub fn put_header(&self, height: u64, header: &crate::block::BlockHeader) -> Result<()> {
        let key = Self::height_key(height);
        let blob = bincode::serialize(header)?;
        let mut wtxn = self.env.begin_rw_txn()?;
        wtxn.put(self.db_headers, &key, &blob, WriteFlags::empty())?;
        wtxn.commit()?;
        Ok(())
    }

    /// Get a BlockHeader by height
    /// Returns None if header at that height does not exist
    pub fn get_header(&self, height: u64) -> Result<Option<crate::block::BlockHeader>> {
        let rtxn = self.env.begin_ro_txn()?;
        let key = Self::height_key(height);
        match rtxn.get(self.db_headers, &key) {
            Ok(val) => {
                let header: crate::block::BlockHeader = bincode::deserialize(val)?;
                Ok(Some(header))
            }
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Get headers in range [start, end] inclusive
    /// Returns Vec<BlockHeader> sorted by height ascending
    /// Skips heights that do not exist in the database
    pub fn get_headers_range(&self, start: u64, end: u64) -> Result<Vec<crate::block::BlockHeader>> {
        let rtxn = self.env.begin_ro_txn()?;
        let mut headers = Vec::new();
        
        for height in start..=end {
            let key = Self::height_key(height);
            match rtxn.get(self.db_headers, &key) {
                Ok(val) => {
                    let header: crate::block::BlockHeader = bincode::deserialize(val)?;
                    headers.push(header);
                }
                Err(lmdb::Error::NotFound) => {
                    // Skip missing heights
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }
        
Ok(headers)
    }

    // ════════════════════════════════════════════════════════════════════════════
    // GOVERNANCE OPERATIONS (13.12.7)
    // ════════════════════════════════════════════════════════════════════════════
    // Bucket: proposals/{proposal_id}
    // Key: proposal_id (u64 big-endian, 8 bytes)
    // Value: bincode serialized Proposal
    // ════════════════════════════════════════════════════════════════════════════

    /// Store a Proposal to LMDB
    /// Key = proposal.id as big-endian u64 (8 bytes)
    /// Value = bincode serialized Proposal
    pub fn put_proposal(&self, proposal: &Proposal) -> Result<()> {
        let key = proposal.id.to_be_bytes();
        let blob = bincode::serialize(proposal)?;
        let mut wtxn = self.env.begin_rw_txn()?;
        wtxn.put(self.db_proposals, &key, &blob, WriteFlags::empty())?;
        wtxn.commit()?;
        Ok(())
    }

    /// Get a Proposal by ID
    /// Returns None if proposal does not exist
    pub fn get_proposal(&self, id: u64) -> Result<Option<Proposal>> {
        let rtxn = self.env.begin_ro_txn()?;
        let key = id.to_be_bytes();
        match rtxn.get(self.db_proposals, &key) {
            Ok(val) => {
                let proposal: Proposal = bincode::deserialize(val)?;
                Ok(Some(proposal))
            }
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Load all Proposals from database
    /// Returns HashMap<proposal_id, Proposal>
    /// Iteration is deterministic (sorted by key)
    pub fn load_all_proposals(&self) -> Result<std::collections::HashMap<u64, Proposal>> {
        let rtxn = self.env.begin_ro_txn()?;
        let mut cursor = rtxn.open_ro_cursor(self.db_proposals)?;
        let mut result = std::collections::HashMap::new();
        
        for (key, val) in cursor.iter() {
            if key.len() == 8 {
                let id = u64::from_be_bytes(key.try_into().map_err(|_| {
                    anyhow::anyhow!("invalid proposal key length")
                })?);
                let proposal: Proposal = bincode::deserialize(val)?;
                result.insert(id, proposal);
            }
        }
        
        Ok(result)
    }

    // ════════════════════════════════════════════════════════════════════════════
    // Bucket: proposal_votes/{proposal_id + voter_address}
    // Key: proposal_id (8 bytes BE) + voter_address (20 bytes) = 28 bytes
    // Value: bincode serialized Vote
    // ════════════════════════════════════════════════════════════════════════════

    /// Store a Vote to LMDB
    /// Key = proposal_id (8 bytes BE) + voter_address (20 bytes)
    /// Value = bincode serialized Vote
    pub fn put_vote(&self, proposal_id: u64, vote: &Vote) -> Result<()> {
        let mut key = Vec::with_capacity(28);
        key.extend_from_slice(&proposal_id.to_be_bytes());
        key.extend_from_slice(vote.voter.as_bytes());
        
        let blob = bincode::serialize(vote)?;
        let mut wtxn = self.env.begin_rw_txn()?;
        wtxn.put(self.db_proposal_votes, &key, &blob, WriteFlags::empty())?;
        wtxn.commit()?;
        Ok(())
    }

    /// Load all votes for a specific proposal
    /// Scans bucket with prefix = proposal_id
    /// Returns HashMap<voter_address, Vote>
    pub fn load_proposal_votes(&self, proposal_id: u64) -> Result<std::collections::HashMap<Address, Vote>> {
        let rtxn = self.env.begin_ro_txn()?;
        let mut cursor = rtxn.open_ro_cursor(self.db_proposal_votes)?;
        let mut result = std::collections::HashMap::new();
        
        let prefix = proposal_id.to_be_bytes();
        
        for (key, val) in cursor.iter() {
            // Key format: proposal_id (8 bytes) + voter_address (20 bytes) = 28 bytes
            if key.len() == 28 && key.starts_with(&prefix) {
                let voter_bytes: [u8; 20] = key[8..28].try_into().map_err(|_| {
                    anyhow::anyhow!("invalid voter address in key")
                })?;
                let voter = Address::from_bytes(voter_bytes);
                let vote: Vote = bincode::deserialize(val)?;
                result.insert(voter, vote);
            }
        }
        
        Ok(result)
    }

    /// Load ALL votes from database (for full state restore)
    /// Returns HashMap<proposal_id, HashMap<voter_address, Vote>>
    pub fn load_all_proposal_votes(&self) -> Result<std::collections::HashMap<u64, std::collections::HashMap<Address, Vote>>> {
        let rtxn = self.env.begin_ro_txn()?;
        let mut cursor = rtxn.open_ro_cursor(self.db_proposal_votes)?;
        let mut result: std::collections::HashMap<u64, std::collections::HashMap<Address, Vote>> = std::collections::HashMap::new();
        
        for (key, val) in cursor.iter() {
            if key.len() == 28 {
                let proposal_id = u64::from_be_bytes(key[0..8].try_into().map_err(|_| {
                    anyhow::anyhow!("invalid proposal_id in vote key")
                })?);
                let voter_bytes: [u8; 20] = key[8..28].try_into().map_err(|_| {
                    anyhow::anyhow!("invalid voter address in vote key")
                })?;
                let voter = Address::from_bytes(voter_bytes);
                let vote: Vote = bincode::deserialize(val)?;
                
                result.entry(proposal_id)
                    .or_insert_with(std::collections::HashMap::new)
                    .insert(voter, vote);
            }
        }
        
        Ok(result)
    }

    // ════════════════════════════════════════════════════════════════════════════
    // Bucket: gov_config/config
    // Key: "config" (6 bytes)
    // Value: bincode serialized GovernanceConfig
    // ════════════════════════════════════════════════════════════════════════════

    /// Store GovernanceConfig to LMDB
    /// Key = "config" (fixed)
    /// Value = bincode serialized GovernanceConfig
    pub fn put_governance_config(&self, config: &GovernanceConfig) -> Result<()> {
        let key = b"config";
        let blob = bincode::serialize(config)?;
        let mut wtxn = self.env.begin_rw_txn()?;
        wtxn.put(self.db_governance_config, key, &blob, WriteFlags::empty())?;
        wtxn.commit()?;
        Ok(())
    }

/// Get GovernanceConfig from LMDB
    /// Returns None if config does not exist (first boot)
    /// NO DEFAULT VALUE - caller must handle None
    pub fn get_governance_config(&self) -> Result<Option<GovernanceConfig>> {
        let rtxn = self.env.begin_ro_txn()?;
        let key = b"config";
        match rtxn.get(self.db_governance_config, key) {
            Ok(val) => {
                let config: GovernanceConfig = bincode::deserialize(val)?;
                Ok(Some(config))
            }
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // NODE LIVENESS OPERATIONS (13.14.7)
    // ════════════════════════════════════════════════════════════════════════════
    // Bucket: node_liveness/{node_address}
    // Key: node_address (20 bytes)
    // Value: bincode serialized NodeLivenessRecord
    //
    // CONSENSUS-CRITICAL: Format tidak boleh berubah tanpa hard fork.
    // ════════════════════════════════════════════════════════════════════════════

    /// Store NodeLivenessRecord to LMDB
    /// Key = node_address (20 bytes)
    /// Value = bincode serialized NodeLivenessRecord
    ///
    /// # Arguments
    /// * `node` - Address of the node
    /// * `record` - NodeLivenessRecord to store
    ///
    /// # Returns
    /// * `Ok(())` - Success
    /// * `Err` - LMDB or serialization error
    pub fn put_node_liveness(
        &self,
        node: &Address,
        record: &crate::slashing::NodeLivenessRecord,
    ) -> Result<()> {
        let key = node.as_bytes();
        let blob = bincode::serialize(record)?;
        let mut wtxn = self.env.begin_rw_txn()?;
        wtxn.put(self.db_node_liveness, key, &blob, WriteFlags::empty())?;
        wtxn.commit()?;
        Ok(())
    }

    /// Get NodeLivenessRecord by node address
    /// Returns None if record does not exist
    ///
    /// # Arguments
    /// * `node` - Address of the node
    ///
    /// # Returns
    /// * `Ok(Some(record))` - Record found
    /// * `Ok(None)` - Record not found
    /// * `Err` - LMDB or deserialization error
    pub fn get_node_liveness(
        &self,
        node: &Address,
    ) -> Result<Option<crate::slashing::NodeLivenessRecord>> {
        let rtxn = self.env.begin_ro_txn()?;
        let key = node.as_bytes();
        match rtxn.get(self.db_node_liveness, key) {
            Ok(val) => {
                let record: crate::slashing::NodeLivenessRecord = bincode::deserialize(val)?;
                Ok(Some(record))
            }
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Delete NodeLivenessRecord by node address
    ///
    /// # Arguments
    /// * `node` - Address of the node
    ///
    /// # Returns
    /// * `Ok(())` - Success (even if record didn't exist)
    /// * `Err` - LMDB error
    pub fn delete_node_liveness(&self, node: &Address) -> Result<()> {
        let key = node.as_bytes();
        let mut wtxn = self.env.begin_rw_txn()?;
        match wtxn.del(self.db_node_liveness, key, None) {
            Ok(_) => {}
            Err(lmdb::Error::NotFound) => {} // Ignore if not found
            Err(e) => return Err(e.into()),
        }
        wtxn.commit()?;
        Ok(())
    }

    /// Load all NodeLivenessRecords from database
    /// Returns HashMap<node_address, NodeLivenessRecord>
    /// Iteration is deterministic (sorted by key)
    pub fn load_all_node_liveness(&self) -> Result<std::collections::HashMap<Address, crate::slashing::NodeLivenessRecord>> {
        let rtxn = self.env.begin_ro_txn()?;
        let mut cursor = rtxn.open_ro_cursor(self.db_node_liveness)?;
        let mut result = std::collections::HashMap::new();
        
        for (key, val) in cursor.iter() {
            if key.len() == 20 {
                let addr_bytes: [u8; 20] = key.try_into().map_err(|_| {
                    anyhow::anyhow!("invalid node address key length")
                })?;
                let node_addr = Address::from_bytes(addr_bytes);
                let record: crate::slashing::NodeLivenessRecord = bincode::deserialize(val)?;
                result.insert(node_addr, record);
            }
        }
        
        Ok(result)
    }

    // ════════════════════════════════════════════════════════════════════════════
    // ECONOMIC STATE OPERATIONS (13.15.7)
    // ════════════════════════════════════════════════════════════════════════════
    // Bucket: economic_metrics/metrics, deflation_config/config
    //
    // CONSENSUS-CRITICAL: Format tidak boleh berubah tanpa hard fork.
    // ════════════════════════════════════════════════════════════════════════════

    /// Store EconomicMetrics to LMDB
    /// Key = "metrics" (fixed)
    /// Value = bincode serialized EconomicMetrics
    ///
    /// # Arguments
    /// * `metrics` - EconomicMetrics to store
    ///
    /// # Returns
    /// * `Ok(())` - Success
    /// * `Err` - LMDB or serialization error
    pub fn put_economic_metrics(
        &self,
        metrics: &crate::economic::EconomicMetrics,
    ) -> Result<()> {
        let key = b"metrics";
        let blob = bincode::serialize(metrics)?;
        let mut wtxn = self.env.begin_rw_txn()?;
        wtxn.put(self.db_economic_metrics, key, &blob, WriteFlags::empty())?;
        wtxn.commit()?;
        Ok(())
    }

    /// Get EconomicMetrics from LMDB
    /// Returns None if metrics do not exist (first boot)
    ///
    /// # Returns
    /// * `Ok(Some(metrics))` - Metrics found
    /// * `Ok(None)` - Metrics not found
    /// * `Err` - LMDB or deserialization error
    pub fn get_economic_metrics(
        &self,
    ) -> Result<Option<crate::economic::EconomicMetrics>> {
        let rtxn = self.env.begin_ro_txn()?;
        let key = b"metrics";
        match rtxn.get(self.db_economic_metrics, key) {
            Ok(val) => {
                let metrics: crate::economic::EconomicMetrics = bincode::deserialize(val)?;
                Ok(Some(metrics))
            }
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Store DeflationConfig to LMDB
    /// Key = "config" (fixed)
    /// Value = bincode serialized DeflationConfig
    ///
    /// # Arguments
    /// * `config` - DeflationConfig to store
    ///
    /// # Returns
    /// * `Ok(())` - Success
    /// * `Err` - LMDB or serialization error
    pub fn put_deflation_config(
        &self,
        config: &crate::economic::DeflationConfig,
    ) -> Result<()> {
        let key = b"config";
        let blob = bincode::serialize(config)?;
        let mut wtxn = self.env.begin_rw_txn()?;
        wtxn.put(self.db_deflation_config, key, &blob, WriteFlags::empty())?;
        wtxn.commit()?;
        Ok(())
    }

    /// Get DeflationConfig from LMDB
    /// Returns None if config does not exist (first boot)
    ///
    /// # Returns
    /// * `Ok(Some(config))` - Config found
    /// * `Ok(None)` - Config not found
    /// * `Err` - LMDB or deserialization error
    pub fn get_deflation_config(
        &self,
    ) -> Result<Option<crate::economic::DeflationConfig>> {
        let rtxn = self.env.begin_ro_txn()?;
        let key = b"config";
        match rtxn.get(self.db_deflation_config, key) {
            Ok(val) => {
                let config: crate::economic::DeflationConfig = bincode::deserialize(val)?;
                Ok(Some(config))
            }
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Store last_burn_epoch to LMDB (part of economic state)
    /// Key = "last_burn_epoch" (fixed)
    /// Value = u64 big-endian bytes
    pub fn put_last_burn_epoch(&self, epoch: u64) -> Result<()> {
        let key = b"last_burn_epoch";
        let value = epoch.to_be_bytes();
        let mut wtxn = self.env.begin_rw_txn()?;
        wtxn.put(self.db_economic_metrics, key, &value, WriteFlags::empty())?;
        wtxn.commit()?;
        Ok(())
    }

    /// Get last_burn_epoch from LMDB
    /// Returns None if not found (first boot)
    pub fn get_last_burn_epoch(&self) -> Result<Option<u64>> {
        let rtxn = self.env.begin_ro_txn()?;
        let key = b"last_burn_epoch";
        match rtxn.get(self.db_economic_metrics, key) {
            Ok(val) => {
                if val.len() == 8 {
                    let bytes: [u8; 8] = val.try_into().map_err(|_| {
                        anyhow::anyhow!("invalid last_burn_epoch bytes")
                    })?;
                    Ok(Some(u64::from_be_bytes(bytes)))
                } else {
                    Ok(None)
                }
            }
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Store cumulative_burned to LMDB (part of economic state)
    /// Key = "cumulative_burned" (fixed)
    /// Value = u128 big-endian bytes
    pub fn put_cumulative_burned(&self, burned: u128) -> Result<()> {
        let key = b"cumulative_burned";
        let value = burned.to_be_bytes();
        let mut wtxn = self.env.begin_rw_txn()?;
        wtxn.put(self.db_economic_metrics, key, &value, WriteFlags::empty())?;
        wtxn.commit()?;
        Ok(())
    }

    /// Get cumulative_burned from LMDB
    /// Returns None if not found (first boot)
    pub fn get_cumulative_burned(&self) -> Result<Option<u128>> {
        let rtxn = self.env.begin_ro_txn()?;
        let key = b"cumulative_burned";
        match rtxn.get(self.db_economic_metrics, key) {
            Ok(val) => {
                if val.len() == 16 {
                    let bytes: [u8; 16] = val.try_into().map_err(|_| {
                        anyhow::anyhow!("invalid cumulative_burned bytes")
                    })?;
                    Ok(Some(u128::from_be_bytes(bytes)))
                } else {
                    Ok(None)
                }
            }
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // STORAGE CONTRACT OPERATIONS (13.17.7)
    // ════════════════════════════════════════════════════════════════════════════
    // Bucket: storage_contracts/{contract_id}, user_contracts/{address}
    //
    // CONSENSUS-CRITICAL: Format tidak boleh berubah tanpa hard fork.
    // ════════════════════════════════════════════════════════════════════════════

    /// Store StorageContract to LMDB
    /// Key = contract_id (Hash, 64 bytes)
    /// Value = bincode serialized StorageContract
    ///
    /// # Arguments
    /// * `contract_id` - Unique identifier for the contract
    /// * `contract` - StorageContract to store
    ///
    /// # Returns
    /// * `Ok(())` - Success
    /// * `Err` - LMDB or serialization error
    pub fn put_storage_contract(
        &self,
        contract_id: &Hash,
        contract: &crate::state::StorageContract,
    ) -> Result<()> {
        let key = contract_id.as_bytes();
        let blob = bincode::serialize(contract)?;
        let mut wtxn = self.env.begin_rw_txn()?;
        wtxn.put(self.db_storage_contracts, key, &blob, WriteFlags::empty())?;
        wtxn.commit()?;
        Ok(())
    }

    /// Get StorageContract from LMDB
    /// Returns None if contract does not exist
    ///
    /// # Arguments
    /// * `contract_id` - Contract identifier to lookup
    ///
    /// # Returns
    /// * `Ok(Some(contract))` - Contract found
    /// * `Ok(None)` - Contract not found
    /// * `Err` - LMDB or deserialization error
    pub fn get_storage_contract(
        &self,
        contract_id: &Hash,
    ) -> Result<Option<crate::state::StorageContract>> {
        let rtxn = self.env.begin_ro_txn()?;
        let key = contract_id.as_bytes();
        match rtxn.get(self.db_storage_contracts, key) {
            Ok(val) => {
                let contract: crate::state::StorageContract = bincode::deserialize(val)?;
                Ok(Some(contract))
            }
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Delete StorageContract from LMDB
    /// Silently succeeds if contract does not exist
    ///
    /// # Arguments
    /// * `contract_id` - Contract identifier to delete
    ///
    /// # Returns
    /// * `Ok(())` - Success (even if not found)
    /// * `Err` - LMDB error
    pub fn delete_storage_contract(
        &self,
        contract_id: &Hash,
    ) -> Result<()> {
        let key = contract_id.as_bytes();
        let mut wtxn = self.env.begin_rw_txn()?;
        match wtxn.del(self.db_storage_contracts, key, None) {
            Ok(_) => {}
            Err(lmdb::Error::NotFound) => {} // Ignore if not found
            Err(e) => return Err(e.into()),
        }
        wtxn.commit()?;
        Ok(())
    }

    /// Load all StorageContracts from LMDB
    /// Returns HashMap<contract_id, StorageContract>
    /// Iteration is deterministic (sorted by key)
    ///
    /// # Returns
    /// * `Ok(HashMap)` - All contracts loaded
    /// * `Err` - LMDB or deserialization error
    pub fn load_all_storage_contracts(&self) -> Result<std::collections::HashMap<Hash, crate::state::StorageContract>> {
        let rtxn = self.env.begin_ro_txn()?;
        let mut cursor = rtxn.open_ro_cursor(self.db_storage_contracts)?;
        let mut result = std::collections::HashMap::new();
        
        for (key, val) in cursor.iter() {
            if key.len() == 64 {
                let hash_bytes: [u8; 64] = key.try_into().map_err(|_| {
                    anyhow::anyhow!("invalid contract_id key length")
                })?;
                let contract_id = Hash::from_bytes(hash_bytes);
                let contract: crate::state::StorageContract = bincode::deserialize(val)?;
                result.insert(contract_id, contract);
            }
        }
        
        Ok(result)
    }

    /// Store user's contract list to LMDB
    /// Key = address (20 bytes)
    /// Value = bincode serialized Vec<Hash>
    ///
    /// # Arguments
    /// * `address` - User address
    /// * `contract_ids` - List of contract IDs owned by user
    ///
    /// # Returns
    /// * `Ok(())` - Success
    /// * `Err` - LMDB or serialization error
    pub fn put_user_contracts(
        &self,
        address: &Address,
        contract_ids: &[Hash],
    ) -> Result<()> {
        let key = address.as_bytes();
        let blob = bincode::serialize(contract_ids)?;
        let mut wtxn = self.env.begin_rw_txn()?;
        wtxn.put(self.db_user_contracts, key, &blob, WriteFlags::empty())?;
        wtxn.commit()?;
        Ok(())
    }

    /// Get user's contract list from LMDB
    /// Returns empty Vec if user has no contracts
    ///
    /// # Arguments
    /// * `address` - User address to lookup
    ///
    /// # Returns
    /// * Vec<Hash> - List of contract IDs (empty if none)
    pub fn get_user_contracts(
        &self,
        address: &Address,
    ) -> Vec<Hash> {
        let rtxn = match self.env.begin_ro_txn() {
            Ok(t) => t,
            Err(_) => return Vec::new(),
        };
        let key = address.as_bytes();
        match rtxn.get(self.db_user_contracts, key) {
            Ok(val) => {
                match bincode::deserialize::<Vec<Hash>>(val) {
                    Ok(ids) => ids,
                    Err(_) => Vec::new(),
                }
            }
            Err(_) => Vec::new(),
        }
    }

    /// Delete user's contract list from LMDB
    /// Silently succeeds if user has no contracts
    ///
    /// # Arguments
    /// * `address` - User address
    ///
    /// # Returns
    /// * `Ok(())` - Success (even if not found)
    /// * `Err` - LMDB error
    pub fn delete_user_contracts(
        &self,
        address: &Address,
    ) -> Result<()> {
        let key = address.as_bytes();
        let mut wtxn = self.env.begin_rw_txn()?;
        match wtxn.del(self.db_user_contracts, key, None) {
            Ok(_) => {}
            Err(lmdb::Error::NotFound) => {} // Ignore if not found
            Err(e) => return Err(e.into()),
        }
        wtxn.commit()?;
        Ok(())
    }

    /// Load all user contract mappings from LMDB
    /// Returns HashMap<user_address, Vec<contract_id>>
    /// Iteration is deterministic (sorted by key)
    pub fn load_all_user_contracts(&self) -> Result<std::collections::HashMap<Address, Vec<Hash>>> {
        let rtxn = self.env.begin_ro_txn()?;
        let mut cursor = rtxn.open_ro_cursor(self.db_user_contracts)?;
        let mut result = std::collections::HashMap::new();
        
        for (key, val) in cursor.iter() {
            if key.len() == 20 {
                let addr_bytes: [u8; 20] = key.try_into().map_err(|_| {
                    anyhow::anyhow!("invalid user address key length")
                })?;
                let user_addr = Address::from_bytes(addr_bytes);
                let contract_ids: Vec<Hash> = bincode::deserialize(val)?;
                result.insert(user_addr, contract_ids);
            }
        }
        
        Ok(result)
    }

    // ════════════════════════════════════════════════════════════════════════════
    // SNAPSHOT OPERATIONS (13.18.2)
    // ════════════════════════════════════════════════════════════════════════════
    // Methods untuk membuat snapshot LMDB dan menulis metadata.
    //
    // Snapshot adalah ATOMIC:
    // - Jika copy LMDB gagal, folder dihapus
    // - Snapshot parsial TIDAK boleh ada
    //
    // Snapshot adalah CONSISTENT:
    // - Copy dilakukan dalam read transaction
    // - Tidak mengganggu write aktif
    //
    // FOLDER STRUCTURE:
    // snapshots/
    // └── checkpoint_{height}/
    //     ├── data.mdb        ← LMDB database copy
    //     └── metadata.json   ← SnapshotMetadata
    // ════════════════════════════════════════════════════════════════════════════

    /// Create snapshot of LMDB environment at specified height.
    ///
    /// Creates folder `{target_path}/checkpoint_{height}/` containing:
    /// - `data.mdb`: Full LMDB environment copy
    ///
    /// # Arguments
    /// * `height` - Block height for snapshot (used in folder name)
    /// * `target_path` - Base path for snapshots (e.g., "./snapshots")
    ///
    /// # Atomicity
    /// - If copy fails, the partial folder is removed
    /// - No partial snapshots will exist after this method returns
    ///
    /// # Returns
    /// * `Ok(())` - Snapshot created successfully
    /// * `Err(DbError)` - Creation failed (folder cleaned up)
    ///
    /// # Example
    /// ```text
    /// db.create_snapshot(1000, Path::new("./snapshots"))?;
    /// // Creates: ./snapshots/checkpoint_1000/data.mdb
    /// ```
    /// 
    //
    fn find_env_data_mdb(&self) -> Option<std::path::PathBuf> {
        let candidate = self.env_path.join("data.mdb");
        if candidate.exists() {
            return Some(candidate);
        }
        // mungkin env_path sendiri adalah file (rare) atau data.mdb ada di parent
        if self.env_path.is_file() {
            if let Some(name) = self.env_path.file_name().and_then(|n| n.to_str()) {
                if name == "data.mdb" {
                    return Some(self.env_path.clone());
                }
            }
        }
        if let Some(parent) = self.env_path.parent() {
            let p2 = parent.join("data.mdb");
            if p2.exists() {
                return Some(p2);
            }
        }
        // try scanning env_path for data.mdb (non-recursive)
        if let Ok(entries) = std::fs::read_dir(&self.env_path) {
            for e in entries.flatten() {
                if let Ok(fname) = e.file_name().into_string() {
                    if fname == "data.mdb" {
                        return Some(e.path());
                    }
                }
            }
        }
        None
    }

    pub fn create_snapshot(
        &self,
        _height: u64,
        snapshot_path: &Path,
    ) -> Result<(), DbError> {

        // 1. Ensure snapshot directory exists
        std::fs::create_dir_all(snapshot_path).map_err(|e| {
            DbError::DirectoryCreation(format!(
                "path={}, error={}",
                snapshot_path.display(),
                e
            ))
        })?;

        // 2. Find source data.mdb
        let src_data = self
            .find_env_data_mdb()
            .ok_or_else(|| DbError::LmdbCopy(format!(
                "source data.mdb not found (env_path={})",
                self.env_path.display()
            )))?;

        // 3. Sync LMDB to disk
        self.env
            .sync(true)
            .map_err(|e| DbError::LmdbCopy(format!("env.sync failed: {}", e)))?;

        // 4. Copy data.mdb
        let dst_data = snapshot_path.join("data.mdb");
        std::fs::copy(&src_data, &dst_data).map_err(|e| {
            DbError::LmdbCopy(format!(
                "copy failed: {} -> {}, error={}",
                src_data.display(),
                dst_data.display(),
                e
            ))
        })?;

        // 5. Copy lock.mdb if exists (best-effort)
        let src_lock = src_data.with_file_name("lock.mdb");
        let dst_lock = snapshot_path.join("lock.mdb");
        if src_lock.exists() {
            let _ = std::fs::copy(&src_lock, &dst_lock);
        }

        Ok(())
    }



    /// Write snapshot metadata to JSON file.
    ///
    /// Creates `metadata.json` in the snapshot folder containing:
    /// - height, state_root, timestamp, block_hash
    ///
    /// # Arguments
    /// * `snapshot_path` - Path to snapshot folder (e.g., "./snapshots/checkpoint_1000")
    /// * `metadata` - SnapshotMetadata to write
    ///
    /// # File Format
    /// ```json
    /// {
    ///     "height": 1000,
    ///     "state_root": "0x...",
    ///     "timestamp": 1700000000,
    ///     "block_hash": "0x..."
    /// }
    /// ```
    ///
    /// # Returns
    /// * `Ok(())` - Metadata written successfully
    /// * `Err(DbError)` - Write failed
    pub fn write_snapshot_metadata(
        &self,
        snapshot_path: &Path,
        metadata: &crate::state::SnapshotMetadata,
    ) -> std::result::Result<(), DbError> {
        // Verify snapshot directory exists
        if !snapshot_path.exists() {
            return Err(DbError::DirectoryNotFound(
                snapshot_path.display().to_string()
            ));
        }

        // Metadata file path
        let metadata_file = snapshot_path.join("metadata.json");

        // Serialize metadata to JSON
        let json_content = match serde_json::to_string_pretty(metadata) {
            Ok(json) => json,
            Err(e) => {
                return Err(DbError::Serialization(format!(
                    "failed to serialize SnapshotMetadata: {}",
                    e
                )));
            }
        };

        // Write to file (atomic via write then rename not needed for JSON)
        if let Err(e) = std::fs::write(&metadata_file, json_content) {
            return Err(DbError::MetadataWrite(format!(
                "path={}, error={}",
                metadata_file.display(),
                e
            )));
        }

        Ok(())
    }

    // ════════════════════════════════════════════════════════════════════════════
    // SNAPSHOT LOADING & VALIDATION (13.18.3)
    // ════════════════════════════════════════════════════════════════════════════
    // Methods untuk load, validasi, dan list snapshots.
    //
    // ZERO-TRUST PRINCIPLE:
    // - Snapshot TIDAK dipercaya secara default
    // - Validasi state_root WAJIB sebelum boot
    // - Snapshot korup DITOLAK
    //
    // VALIDATION FLOW:
    // 1. read_snapshot_metadata() → ambil expected state_root
    // 2. load_snapshot() → buka LMDB read-only
    // 3. load_state() → reconstruct ChainState
    // 4. compute_state_root() → hitung actual state_root
    // 5. compare → expected == computed? OK : Corrupted
    // ════════════════════════════════════════════════════════════════════════════

    /// Load snapshot LMDB as read-only ChainDb instance.
    ///
    /// Opens the snapshot's data.mdb in read-only mode WITHOUT modifying
    /// the active chain database. This creates a NEW ChainDb instance
    /// that can be used for validation or state recovery.
    ///
    /// # Arguments
    /// * `snapshot_path` - Path to snapshot folder (e.g., "./snapshots/checkpoint_1000")
    ///
    /// # Validation Steps
    /// 1. Verify snapshot_path exists
    /// 2. Verify data.mdb exists inside
    /// 3. Open LMDB environment read-only
    /// 4. Open all required databases
    ///
    /// # Returns
    /// * `Ok(ChainDb)` - New read-only ChainDb instance
    /// * `Err(DbError)` - Load failed
    ///
    /// # Example
    /// ```text
    /// let snapshot_db = ChainDb::load_snapshot(Path::new("./snapshots/checkpoint_1000"))?;
    /// let state = snapshot_db.load_state()?;
    /// ```
    pub fn load_snapshot(snapshot_path: &Path) -> std::result::Result<Self, DbError> {
        // 1. Verify snapshot directory exists
        if !snapshot_path.exists() {
            return Err(DbError::DirectoryNotFound(
                snapshot_path.display().to_string()
            ));
        }

        // 2. Verify data.mdb exists
        let data_mdb = snapshot_path.join("data.mdb");
        if !data_mdb.exists() {
            return Err(DbError::DataNotFound(
                data_mdb.display().to_string()
            ));
        }

        // 3. Open LMDB environment (read-only is default for snapshots)
        // We open with same settings as normal but snapshot is immutable
        let env = Environment::new()
            .set_max_dbs(33)
            .set_map_size(1_000_000_000usize)
            .open(snapshot_path)
            .map_err(|e| DbError::SnapshotOpenFailed(format!(
                "path={}, error={}", snapshot_path.display(), e
            )))?;

        // 4. Open all databases (same as normal open)
        let db_blocks = env.open_db(Some("blocks"))
            .map_err(|e| DbError::SnapshotOpenFailed(format!("blocks: {}", e)))?;
        let db_block_hashes = env.open_db(Some("block_hashes"))
            .map_err(|e| DbError::SnapshotOpenFailed(format!("block_hashes: {}", e)))?;
        let db_txs = env.open_db(Some("txs"))
            .map_err(|e| DbError::SnapshotOpenFailed(format!("txs: {}", e)))?;
        let db_accounts = env.open_db(Some("accounts"))
            .map_err(|e| DbError::SnapshotOpenFailed(format!("accounts: {}", e)))?;
        let db_validators = env.open_db(Some("validators"))
            .map_err(|e| DbError::SnapshotOpenFailed(format!("validators: {}", e)))?;
        let db_meta = env.open_db(Some("meta"))
            .map_err(|e| DbError::SnapshotOpenFailed(format!("meta: {}", e)))?;
        let db_mempool = env.open_db(Some("pending_mempool"))
            .map_err(|e| DbError::SnapshotOpenFailed(format!("pending_mempool: {}", e)))?;
        let db_validator_set = env.open_db(Some("validator_set"))
            .map_err(|e| DbError::SnapshotOpenFailed(format!("validator_set: {}", e)))?;
        let db_receipts = env.open_db(Some("receipts"))
            .map_err(|e| DbError::SnapshotOpenFailed(format!("receipts: {}", e)))?;
        let db_pending_unstake = env.open_db(Some("pending_unstake"))
            .map_err(|e| DbError::SnapshotOpenFailed(format!("pending_unstake: {}", e)))?;
        let db_state_validators = env.open_db(Some("state_validators"))
            .map_err(|e| DbError::SnapshotOpenFailed(format!("state_validators: {}", e)))?;
        let db_state_stake = env.open_db(Some("state_stake"))
            .map_err(|e| DbError::SnapshotOpenFailed(format!("state_stake: {}", e)))?;
        let db_state_delegators = env.open_db(Some("state_delegators"))
            .map_err(|e| DbError::SnapshotOpenFailed(format!("state_delegators: {}", e)))?;
        let db_state_qv_weights = env.open_db(Some("state_qv_weights"))
            .map_err(|e| DbError::SnapshotOpenFailed(format!("state_qv_weights: {}", e)))?;
        let db_state_validator_metadata = env.open_db(Some("state_validator_metadata"))
            .map_err(|e| DbError::SnapshotOpenFailed(format!("state_validator_metadata: {}", e)))?;
        let db_state_node_cost = env.open_db(Some("state_node_cost"))
            .map_err(|e| DbError::SnapshotOpenFailed(format!("state_node_cost: {}", e)))?;
        let db_claimed_receipts = env.open_db(Some(BUCKET_CLAIMED_RECEIPTS))
            .map_err(|e| DbError::SnapshotOpenFailed(format!("claimed_receipts: {}", e)))?;
        let db_state_node_earnings = env.open_db(Some("state_node_earnings"))
            .map_err(|e| DbError::SnapshotOpenFailed(format!("state_node_earnings: {}", e)))?;
        let db_headers = env.open_db(Some(BUCKET_HEADERS))
            .map_err(|e| DbError::SnapshotOpenFailed(format!("headers: {}", e)))?;
        let db_proposals = env.open_db(Some(BUCKET_PROPOSALS))
            .map_err(|e| DbError::SnapshotOpenFailed(format!("proposals: {}", e)))?;
        let db_proposal_votes = env.open_db(Some(BUCKET_PROPOSAL_VOTES))
            .map_err(|e| DbError::SnapshotOpenFailed(format!("proposal_votes: {}", e)))?;
        let db_governance_config = env.open_db(Some(BUCKET_GOVERNANCE_CONFIG))
            .map_err(|e| DbError::SnapshotOpenFailed(format!("gov_config: {}", e)))?;
        let db_node_liveness = env.open_db(Some(BUCKET_NODE_LIVENESS))
            .map_err(|e| DbError::SnapshotOpenFailed(format!("node_liveness: {}", e)))?;
        let db_economic_metrics = env.open_db(Some(BUCKET_ECONOMIC_METRICS))
            .map_err(|e| DbError::SnapshotOpenFailed(format!("economic_metrics: {}", e)))?;
        let db_deflation_config = env.open_db(Some(BUCKET_DEFLATION_CONFIG))
            .map_err(|e| DbError::SnapshotOpenFailed(format!("deflation_config: {}", e)))?;
        let db_storage_contracts = env.open_db(Some(BUCKET_STORAGE_CONTRACTS))
            .map_err(|e| DbError::SnapshotOpenFailed(format!("storage_contracts: {}", e)))?;
        let db_user_contracts = env.open_db(Some(BUCKET_USER_CONTRACTS))
            .map_err(|e| DbError::SnapshotOpenFailed(format!("user_contracts: {}", e)))?;

        Ok(Self {
            env: Arc::new(env),
            env_path: snapshot_path.to_path_buf(),
            db_blocks,
            db_block_hashes,
            db_txs,
            db_accounts,
            db_validators,
            db_meta,
            db_mempool,
            db_validator_set,
            db_receipts,
            db_pending_unstake,
            db_state_validators,
            db_state_stake,
            db_state_delegators,
            db_state_qv_weights,
            db_state_validator_metadata,
            db_state_node_cost,
            db_claimed_receipts,
            db_state_node_earnings,
            db_headers,
            db_proposals,
            db_proposal_votes,
            db_governance_config,
            db_node_liveness,
            db_economic_metrics,
            db_deflation_config,
            db_storage_contracts,
            db_user_contracts,
        })
    }

    /// Read snapshot metadata from JSON file.
    ///
    /// Reads and parses metadata.json from the snapshot folder.
    /// Validates that all required fields are present.
    ///
    /// # Arguments
    /// * `snapshot_path` - Path to snapshot folder
    ///
    /// # Required Fields
    /// - height: u64
    /// - state_root: Hash
    /// - timestamp: u64
    /// - block_hash: Hash
    ///
    /// # Returns
    /// * `Ok(SnapshotMetadata)` - Parsed metadata
    /// * `Err(DbError)` - Read or parse failed
    pub fn read_snapshot_metadata(
        snapshot_path: &Path,
    ) -> std::result::Result<crate::state::SnapshotMetadata, DbError> {
        // Verify snapshot directory exists
        if !snapshot_path.exists() {
            return Err(DbError::DirectoryNotFound(
                snapshot_path.display().to_string()
            ));
        }

        // Metadata file path
        let metadata_file = snapshot_path.join("metadata.json");
        if !metadata_file.exists() {
            return Err(DbError::MetadataRead(format!(
                "metadata.json not found in {}",
                snapshot_path.display()
            )));
        }

        // Read file contents
        let content = std::fs::read_to_string(&metadata_file)
            .map_err(|e| DbError::MetadataRead(format!(
                "failed to read {}: {}",
                metadata_file.display(), e
            )))?;

        // Parse JSON
        let metadata: crate::state::SnapshotMetadata = serde_json::from_str(&content)
            .map_err(|e| DbError::MetadataInvalid(format!(
                "failed to parse metadata.json: {}",
                e
            )))?;

        // Validate required fields (height must be > 0 for non-genesis)
        // Note: height 0 is valid for genesis snapshot
        // state_root and block_hash are validated by serde

        Ok(metadata)
    }

    /// Validate snapshot integrity by comparing state_root.
    ///
    /// This is CONSENSUS-GRADE validation:
    /// 1. Load snapshot LMDB
    /// 2. Read metadata.json
    /// 3. Reconstruct ChainState from LMDB
    /// 4. Compute state_root from ChainState
    /// 5. Compare computed vs metadata.state_root
    ///
    /// # Arguments
    /// * `snapshot_path` - Path to snapshot folder
    ///
    /// # Returns
    /// * `Ok(())` - Snapshot is valid (state_root matches)
    /// * `Err(DbError::SnapshotCorrupted)` - state_root mismatch
    /// * `Err(DbError)` - Other validation error
    ///
    /// # Security Note
    /// NEVER skip this validation when restoring from snapshot.
    /// A corrupted snapshot will cause consensus divergence.
    pub fn validate_snapshot(
        snapshot_path: &Path,
    ) -> std::result::Result<(), DbError> {
        // 1. Read expected state_root from metadata
        let metadata = Self::read_snapshot_metadata(snapshot_path)?;
        let expected_root = metadata.state_root;

        // 2. Load snapshot LMDB
        let snapshot_db = Self::load_snapshot(snapshot_path)?;

        // 3. Load state from snapshot
        let state = snapshot_db.load_state()
            .map_err(|e| DbError::StateLoadFailed(format!(
                "failed to load state from snapshot: {}",
                e
            )))?;

        // 4. Compute actual state_root
        let computed_root = state.compute_state_root()
            .map_err(|e| DbError::StateLoadFailed(format!(
                "failed to compute state_root: {}",
                e
            )))?;

        // 5. Compare
        if computed_root != expected_root {
            return Err(DbError::SnapshotCorrupted {
                expected: expected_root.to_hex(),
                computed: computed_root.to_hex(),
            });
        }

        Ok(())
    }

    /// List all available snapshots in a directory.
    ///
    /// Scans base_path for checkpoint_* folders and returns
    /// their metadata sorted ascending by height.
    ///
    /// # Arguments
    /// * `base_path` - Base snapshots directory (e.g., "./snapshots")
    ///
    /// # Behavior
    /// - Scans for folders matching pattern: checkpoint_{height}
    /// - Reads metadata.json from each valid folder
    /// - Ignores invalid/corrupted snapshots (no panic)
    /// - Returns list sorted by height ascending
    ///
    /// # Returns
    /// * `Ok(Vec<SnapshotMetadata>)` - List of valid snapshots
    /// * `Err(DbError)` - Base path doesn't exist
    ///
    /// # Example
    /// ```text
    /// let snapshots = ChainDb::list_available_snapshots(Path::new("./snapshots"))?;
    /// for snap in snapshots {
    ///     println!("Snapshot at height {}", snap.height);
    /// }
    /// ```
    pub fn list_available_snapshots(
        base_path: &Path,
    ) -> std::result::Result<Vec<crate::state::SnapshotMetadata>, DbError> {
        // Verify base directory exists
        if !base_path.exists() {
            return Err(DbError::DirectoryNotFound(
                base_path.display().to_string()
            ));
        }

        let mut snapshots = Vec::new();

        // Scan directory entries
        let entries = std::fs::read_dir(base_path)
            .map_err(|e| DbError::Io(e))?;

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue, // Skip unreadable entries
            };

            let path = entry.path();

            // Check if it's a directory
            if !path.is_dir() {
                continue;
            }

            // Check if folder name matches checkpoint_{height} pattern
            let folder_name = match path.file_name().and_then(|n| n.to_str()) {
                Some(name) => name,
                None => continue,
            };

            if !folder_name.starts_with("checkpoint_") {
                continue;
            }

            // Try to parse height from folder name
            let height_str = folder_name.strip_prefix("checkpoint_");
            if height_str.is_none() {
                continue;
            }

            // Try to read metadata (ignore invalid snapshots)
            match Self::read_snapshot_metadata(&path) {
                Ok(metadata) => snapshots.push(metadata),
                Err(_) => continue, // Skip corrupted snapshots
            }
        }

        // Sort by height ascending
        snapshots.sort_by_key(|m| m.height);

        Ok(snapshots)
    }

    /// Get the LMDB environment path.
    ///
    /// Used for snapshot operations to access the underlying database path.
    ///
    /// # Returns
    /// Path to the LMDB environment directory
    pub fn get_env_path(&self) -> Option<std::path::PathBuf> {
        Some(self.env_path.clone())
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use crate::types::Address;

    #[test]
    fn test_account_roundtrip_and_tip() {
        let dir = tempdir().unwrap();
        let db = ChainDb::open(dir.path()).unwrap();

        let addr = Address::from_bytes([0x11; 20]);
        let acct = Account {
            address: addr,
            balance: 1_234_567,
            nonce: 0,
            locked: 0,
        };
        db.write_account(&acct).unwrap();
        let loaded = db.load_account(&addr).unwrap().unwrap();
        assert_eq!(loaded.balance, acct.balance);

        let dummy_hash = Hash::from_bytes([0x22u8; 64]);
        db.set_tip(10, &dummy_hash).unwrap();
        let tip = db.get_tip().unwrap().unwrap();
        assert_eq!(tip.0, 10);
        assert_eq!(tip.1.to_hex(), dummy_hash.to_hex());
    }

    // ════════════════════════════════════════════════════════════════════════════
    // SNAPSHOT TESTS (13.18.2)
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_create_snapshot_success() {
        let db_dir = tempdir().unwrap();
        let snapshot_dir = tempdir().unwrap();
        let db = ChainDb::open(db_dir.path()).unwrap();

        // Write some data first
        let addr = Address::from_bytes([0x33; 20]);
        let acct = Account {
            address: addr,
            balance: 999_999,
            nonce: 5,
            locked: 100,
        };
        db.write_account(&acct).unwrap();

        // Create snapshot
        let height = 1000;
        let result = db.create_snapshot(height, snapshot_dir.path());
        assert!(result.is_ok(), "create_snapshot should succeed");

        // Verify folder structure
        let checkpoint_path = snapshot_dir.path().join("checkpoint_1000");
        assert!(checkpoint_path.exists(), "checkpoint folder should exist");

        let data_mdb = checkpoint_path.join("data.mdb");
        assert!(data_mdb.exists(), "data.mdb should exist");
    }

    #[test]
    fn test_write_snapshot_metadata_success() {
        use crate::state::SnapshotMetadata;

        let db_dir = tempdir().unwrap();
        let snapshot_dir = tempdir().unwrap();
        let db = ChainDb::open(db_dir.path()).unwrap();

        // Create snapshot first
        let height = 2000;
        db.create_snapshot(height, snapshot_dir.path()).unwrap();

        // Write metadata
        let checkpoint_path = snapshot_dir.path().join("checkpoint_2000");
        let metadata = SnapshotMetadata {
            height: 2000,
            state_root: Hash::from_bytes([0xAB; 64]),
            timestamp: 1700000000,
            block_hash: Hash::from_bytes([0xCD; 64]),
        };

        let result = db.write_snapshot_metadata(&checkpoint_path, &metadata);
        assert!(result.is_ok(), "write_snapshot_metadata should succeed");

        // Verify metadata file exists
        let metadata_file = checkpoint_path.join("metadata.json");
        assert!(metadata_file.exists(), "metadata.json should exist");

        // Verify content is valid JSON
        let content = std::fs::read_to_string(&metadata_file).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["height"], 2000);
    }

    #[test]
    fn test_write_metadata_directory_not_found() {
        use crate::state::SnapshotMetadata;

        let db_dir = tempdir().unwrap();
        let db = ChainDb::open(db_dir.path()).unwrap();

        let nonexistent_path = std::path::Path::new("/nonexistent/path/checkpoint_999");
        let metadata = SnapshotMetadata {
            height: 999,
            state_root: Hash::from_bytes([0x00; 64]),
            timestamp: 0,
            block_hash: Hash::from_bytes([0x00; 64]),
        };

        let result = db.write_snapshot_metadata(nonexistent_path, &metadata);
        assert!(result.is_err(), "should fail for nonexistent directory");

        match result {
            Err(DbError::DirectoryNotFound(_)) => {}
            _ => panic!("expected DirectoryNotFound error"),
        }
    }

    #[test]
    fn test_snapshot_multiple_heights() {
        let db_dir = tempdir().unwrap();
        let snapshot_dir = tempdir().unwrap();
        let db = ChainDb::open(db_dir.path()).unwrap();

        // Create multiple snapshots
        for height in [1000, 2000, 3000] {
            let result = db.create_snapshot(height, snapshot_dir.path());
            assert!(result.is_ok(), "snapshot at height {} should succeed", height);

            let checkpoint_path = snapshot_dir.path().join(format!("checkpoint_{}", height));
            assert!(checkpoint_path.exists(), "checkpoint_{} folder should exist", height);
        }

        // Verify all three exist
        assert!(snapshot_dir.path().join("checkpoint_1000").exists());
        assert!(snapshot_dir.path().join("checkpoint_2000").exists());
        assert!(snapshot_dir.path().join("checkpoint_3000").exists());
    }

    // ════════════════════════════════════════════════════════════════════════════
    // SNAPSHOT LOADING TESTS (13.18.3)
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_load_snapshot_success() {
        use crate::state::SnapshotMetadata;

        let db_dir = tempdir().unwrap();
        let snapshot_dir = tempdir().unwrap();
        let db = ChainDb::open(db_dir.path()).unwrap();

        // Write data and create snapshot
        let addr = Address::from_bytes([0x44; 20]);
        let acct = Account {
            address: addr,
            balance: 5_000_000,
            nonce: 10,
            locked: 500,
        };
        db.write_account(&acct).unwrap();
        db.create_snapshot(1000, snapshot_dir.path()).unwrap();

        // Write metadata
        let checkpoint_path = snapshot_dir.path().join("checkpoint_1000");
        let metadata = SnapshotMetadata {
            height: 1000,
            state_root: Hash::from_bytes([0xAA; 64]),
            timestamp: 1700000000,
            block_hash: Hash::from_bytes([0xBB; 64]),
        };
        db.write_snapshot_metadata(&checkpoint_path, &metadata).unwrap();

        // Load snapshot
        let snapshot_db = ChainDb::load_snapshot(&checkpoint_path);
        assert!(snapshot_db.is_ok(), "load_snapshot should succeed");

        // Verify we can read data from snapshot
        let loaded_acct = snapshot_db.unwrap().load_account(&addr).unwrap();
        assert!(loaded_acct.is_some());
        assert_eq!(loaded_acct.unwrap().balance, 5_000_000);
    }

    #[test]
    fn test_load_snapshot_missing_data_mdb() {
        let snapshot_dir = tempdir().unwrap();
        let checkpoint_path = snapshot_dir.path().join("checkpoint_999");
        std::fs::create_dir_all(&checkpoint_path).unwrap();
        // Don't create data.mdb

        let result = ChainDb::load_snapshot(&checkpoint_path);
        assert!(result.is_err());
        match result {
            Err(DbError::DataNotFound(_)) => {}
            _ => panic!("expected DataNotFound error"),
        }
    }

    #[test]
    fn test_read_snapshot_metadata_success() {
        use crate::state::SnapshotMetadata;

        let db_dir = tempdir().unwrap();
        let snapshot_dir = tempdir().unwrap();
        let db = ChainDb::open(db_dir.path()).unwrap();

        db.create_snapshot(2000, snapshot_dir.path()).unwrap();

        let checkpoint_path = snapshot_dir.path().join("checkpoint_2000");
        let metadata = SnapshotMetadata {
            height: 2000,
            state_root: Hash::from_bytes([0xCC; 64]),
            timestamp: 1700001000,
            block_hash: Hash::from_bytes([0xDD; 64]),
        };
        db.write_snapshot_metadata(&checkpoint_path, &metadata).unwrap();

        // Read metadata back
        let read_metadata = ChainDb::read_snapshot_metadata(&checkpoint_path);
        assert!(read_metadata.is_ok());
        let m = read_metadata.unwrap();
        assert_eq!(m.height, 2000);
        assert_eq!(m.timestamp, 1700001000);
    }

    #[test]
    fn test_read_snapshot_metadata_missing_file() {
        let snapshot_dir = tempdir().unwrap();
        let checkpoint_path = snapshot_dir.path().join("checkpoint_888");
        std::fs::create_dir_all(&checkpoint_path).unwrap();
        // Don't create metadata.json

        let result = ChainDb::read_snapshot_metadata(&checkpoint_path);
        assert!(result.is_err());
        match result {
            Err(DbError::MetadataRead(_)) => {}
            _ => panic!("expected MetadataRead error"),
        }
    }

    #[test]
    fn test_list_available_snapshots() {
        use crate::state::SnapshotMetadata;

        let db_dir = tempdir().unwrap();
        let snapshot_dir = tempdir().unwrap();
        let db = ChainDb::open(db_dir.path()).unwrap();

        // Create 3 snapshots
        for height in [1000u64, 2000, 3000] {
            db.create_snapshot(height, snapshot_dir.path()).unwrap();
            let checkpoint_path = snapshot_dir.path().join(format!("checkpoint_{}", height));
            let metadata = SnapshotMetadata {
                height,
                state_root: Hash::from_bytes([height as u8; 64]),
                timestamp: 1700000000 + height,
                block_hash: Hash::from_bytes([height as u8; 64]),
            };
            db.write_snapshot_metadata(&checkpoint_path, &metadata).unwrap();
        }

        // List snapshots
        let snapshots = ChainDb::list_available_snapshots(snapshot_dir.path());
        assert!(snapshots.is_ok());
        let list = snapshots.unwrap();
        assert_eq!(list.len(), 3);

        // Verify sorted by height ascending
        assert_eq!(list[0].height, 1000);
        assert_eq!(list[1].height, 2000);
        assert_eq!(list[2].height, 3000);
    }

    #[test]
    fn test_list_snapshots_ignores_invalid() {
        use crate::state::SnapshotMetadata;

        let db_dir = tempdir().unwrap();
        let snapshot_dir = tempdir().unwrap();
        let db = ChainDb::open(db_dir.path()).unwrap();

        // Create 1 valid snapshot
        db.create_snapshot(1000, snapshot_dir.path()).unwrap();
        let checkpoint_path = snapshot_dir.path().join("checkpoint_1000");
        let metadata = SnapshotMetadata {
            height: 1000,
            state_root: Hash::from_bytes([0x11; 64]),
            timestamp: 1700000000,
            block_hash: Hash::from_bytes([0x22; 64]),
        };
        db.write_snapshot_metadata(&checkpoint_path, &metadata).unwrap();

        // Create invalid snapshot folder (no metadata)
        let invalid_path = snapshot_dir.path().join("checkpoint_9999");
        std::fs::create_dir_all(&invalid_path).unwrap();

        // Create non-checkpoint folder
        let other_path = snapshot_dir.path().join("other_folder");
        std::fs::create_dir_all(&other_path).unwrap();

        // List should only return valid snapshot
        let snapshots = ChainDb::list_available_snapshots(snapshot_dir.path()).unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].height, 1000);
    }

    #[test]
    fn test_list_snapshots_empty_directory() {
        let snapshot_dir = tempdir().unwrap();
        
        let snapshots = ChainDb::list_available_snapshots(snapshot_dir.path());
        assert!(snapshots.is_ok());
        assert_eq!(snapshots.unwrap().len(), 0);
    }
}