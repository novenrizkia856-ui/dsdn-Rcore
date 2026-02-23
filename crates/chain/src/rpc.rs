use serde::{Serialize, Deserialize};
use crate::block::Block;
use crate::Chain;
use crate::types::Hash;
use crate::sync::{SyncStatus, SyncRequest, SyncResponse};
use crate::state::{
    Proposal, Vote, ProposalStatus, ProposalType, VoteOption,
    ProposalPreview, SimulatedChange, PreviewType,
    GovernanceEvent, GovernanceEventType,
};
use crate::types::Address;
use std::sync::{Arc, RwLock};

// ============================================================
// BROADCASTING LAYER (13.7.N)
// ============================================================

/// Peer information for broadcasting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub id: String,
    pub address: String,
    pub is_validator: bool,
}

/// Broadcast result for a single peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BroadcastResult {
    pub peer_id: String,
    pub success: bool,
    pub message: String,
}

/// Request to receive block from validator
#[derive(Serialize, Deserialize, Clone)]
pub struct ReceiveBlockReq {
    pub block_data: String,  // hex-encoded bincode
    pub from_validator: String,
}

/// Response for receive block
#[derive(Serialize, Deserialize, Clone)]
pub struct ReceiveBlockRes {
    pub accepted: bool,
    pub height: u64,
    pub block_hash: String,
    pub message: String,
}

// ════════════════════════════════════════════════════════════════════════════
// TRANSACTION SUBMISSION RPC TYPES (13.16.2)
// ════════════════════════════════════════════════════════════════════════════
// Request/Response structs for transaction submission.
// This is the main entry point for all transactions into the network.
// ════════════════════════════════════════════════════════════════════════════

/// Request to submit a transaction
/// 
/// Used by wallets, SDKs, exchanges, and relayers to submit transactions.
/// The transaction envelope must be bincode serialized and hex encoded.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SubmitTxReq {
    /// Hex-encoded bincode serialized TxEnvelope
    pub tx_envelope_hex: String,
}

/// Response for transaction submission
/// 
/// Returns the transaction ID (hash) if accepted, or error details if rejected.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SubmitTxRes {
    /// Whether the transaction was accepted into the mempool
    pub success: bool,
    /// Transaction ID (hex string), empty if failed
    pub txid: String,
    /// Human-readable status message
    pub message: String,
}

/// Request to sync a block from network
#[derive(Serialize, Deserialize, Clone)]
pub struct SyncBlockReq {
    /// Serialized block data (bincode encoded, then hex)
    pub block_data: String,
}

/// Response for sync block request
#[derive(Serialize, Deserialize, Clone)]
pub struct SyncBlockRes {
    pub success: bool,
    pub height: u64,
    pub block_hash: String,
    pub message: String,
}

/// Response for chain info request
#[derive(Serialize, Deserialize, Clone)]
pub struct ChainInfoRes {
    pub tip_height: u64,
    pub tip_hash: String,
    pub is_validator: bool,
}

/// Error response
#[derive(Serialize, Deserialize, Clone)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

// ============================================================
// SYNC RPC RESPONSE TYPES (13.11.7)
// ============================================================

/// Response for sync status query
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SyncStatusRes {
    /// Current sync status
    pub status: String,
    /// Current synced height
    pub current_height: u64,
    /// Target height to sync
    pub target_height: u64,
}

/// Response for sync progress query
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SyncProgressRes {
    /// Current synced height
    pub current: u64,
    /// Target height
    pub target: u64,
    /// Progress percentage (0-100)
    pub percent: u8,
}

// ════════════════════════════════════════════════════════════════════════════
// GOVERNANCE RPC RESPONSE TYPES (13.12.8)
// ════════════════════════════════════════════════════════════════════════════

/// Response for proposal query
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProposalRes {
    pub id: u64,
    pub proposal_type: String,
    pub proposer: String,
    pub title: String,
    pub description: String,
    pub status: String,
    pub created_at: u64,
    pub voting_end: u64,
    pub yes_votes: u128,
    pub no_votes: u128,
    pub abstain_votes: u128,
    pub quorum_required: u128,
}

/// Response for vote query
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VoteRes {
    pub voter: String,
    pub proposal_id: u64,
    pub option: String,
    pub weight: u128,
    pub timestamp: u64,
}

/// Response for voter status query
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VoterStatusRes {
    pub voter: String,
    pub proposal_id: u64,
    pub has_voted: bool,
    pub vote_option: Option<String>,
    pub vote_weight: Option<u128>,
    pub current_voting_power: u128,
}

/// Response for governance config query
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GovernanceConfigRes {
    pub voting_period_seconds: u64,
    pub quorum_percentage: u8,
    pub pass_threshold: u8,
    pub min_proposer_stake: u128,
    pub foundation_address: String,
pub bootstrap_mode: bool,
}

// ════════════════════════════════════════════════════════════════════════════
// GOVERNANCE PREVIEW RPC RESPONSE TYPES (13.13.5)
// ════════════════════════════════════════════════════════════════════════════

/// Response for simulated change in proposal preview
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SimulatedChangeRes {
    /// Path to the field being changed
    pub field_path: String,
    /// Old value in string format
    pub old_value: String,
    /// New value in string format
    pub new_value: String,
}

/// Response for proposal preview query
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProposalPreviewRes {
    /// Proposal ID being previewed
    pub proposal_id: u64,
    /// Type of preview (string representation)
    pub preview_type: String,
    /// List of simulated changes
    pub simulated_changes: Vec<SimulatedChangeRes>,
    /// List of affected addresses (hex strings)
    pub affected_addresses: Vec<String>,
    /// Timestamp when preview was generated
    pub generated_at: u64,
}

/// Response for bootstrap mode status query
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BootstrapModeRes {
    /// Whether bootstrap mode is active
    pub is_active: bool,
    /// Foundation address (hex string)
    pub foundation_address: String,
    /// Whether execution is allowed (!is_active)
    pub execution_allowed: bool,
    /// Human-readable message
    pub message: String,
}

/// Response for governance event query
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GovernanceEventRes {
    /// Event type (string representation)
    pub event_type: String,
    /// Associated proposal ID (if any)
    pub proposal_id: Option<u64>,
    /// Actor address (hex string)
    pub actor: String,
    /// Unix timestamp
    pub timestamp: u64,
    /// Event details
    pub details: String,
}

// ════════════════════════════════════════════════════════════════════════════
// SLASHING RPC RESPONSE TYPES (13.14.8)
// ════════════════════════════════════════════════════════════════════════════
// READ-ONLY structs for slashing observability.
// No state mutation. Safe for monitoring and dashboards.
// ════════════════════════════════════════════════════════════════════════════

/// Response for node liveness status query
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NodeLivenessRes {
    /// Node address (hex string)
    pub node_address: String,
    /// Last seen timestamp (Unix)
    pub last_seen_timestamp: u64,
    /// Consecutive liveness failures
    pub consecutive_failures: u32,
    /// Data corruption count
    pub data_corruption_count: u32,
    /// Malicious behavior count
    pub malicious_behavior_count: u32,
    /// Force-unbond until timestamp (None if not force-unbonded)
    pub force_unbond_until: Option<u64>,
    /// Whether node has been slashed
    pub slashed: bool,
}

// ════════════════════════════════════════════════════════════════════════════
// ECONOMIC RPC RESPONSE TYPES (13.15.8)
// ════════════════════════════════════════════════════════════════════════════
// READ-ONLY structs for economic observability.
// No state mutation. Safe for monitoring and dashboards.
// All u128 values are represented as String to avoid JSON overflow.
// ════════════════════════════════════════════════════════════════════════════

/// Response for economic status query
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EconomicStatusRes {
    /// Economic mode: "Bootstrap", "Active", or "Governance"
    pub mode: String,
    /// Current replication factor
    pub replication_factor: u8,
    /// Treasury balance (string to avoid JSON overflow)
    pub treasury_balance: String,
    /// Total token supply (string)
    pub total_supply: String,
    /// Whether deflation is enabled
    pub deflation_enabled: bool,
    /// Current burn rate in basis points (string)
    pub current_burn_rate: String,
}

/// Response for deflation info query
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DeflationInfoRes {
    /// Target minimum burn percentage (basis points, string)
    pub target_min_percent: String,
    /// Target maximum burn percentage (basis points, string)
    pub target_max_percent: String,
    /// Current annual burn rate (basis points, string)
    pub current_annual_rate: String,
    /// Cumulative tokens burned (string)
    pub cumulative_burned: String,
    /// Last epoch when burn occurred
    pub last_burn_epoch: u64,
    /// Next epoch eligible for burn
    pub next_burn_eligible_epoch: u64,
}

/// Response for burn event query
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BurnEventRes {
    /// Epoch when burn occurred
    pub epoch: u64,
    /// Amount burned (string)
    pub amount_burned: String,
    /// Burn rate applied (basis points, string)
    pub burn_rate: String,
    /// Timestamp when burn occurred
    pub timestamp: u64,
}

/// Response for validator slash status query
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ValidatorSlashRes {
    /// Validator address (hex string)
    pub validator_address: String,
    /// Whether validator has been slashed
    pub slashed: bool,
    /// Slashing reason (if slashed)
    pub reason: Option<String>,
    /// Force-unbond until timestamp (None if not force-unbonded)
    pub force_unbond_until: Option<u64>,
}

/// Response for slashing event query
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SlashingEventRes {
    /// Target address (hex string)
    pub target: String,
    /// Slashing reason (string representation)
    pub reason: String,
    /// Amount slashed (string to avoid JSON overflow)
    pub amount_slashed: String,
    /// Amount sent to treasury (string)
    pub amount_to_treasury: String,
    /// Amount burned (string)
    pub amount_burned: String,
    /// Timestamp when slashing occurred
    pub timestamp: u64,
}

// ════════════════════════════════════════════════════════════════════════════
// CORE QUERY RPC RESPONSE TYPES (13.16.1)
// ════════════════════════════════════════════════════════════════════════════
// READ-ONLY query structs for wallet, explorer, SDK, and exchange integration.
// These are the most frequently called RPC endpoints.
// All u128 values are represented as String to avoid JSON overflow.
// ════════════════════════════════════════════════════════════════════════════

/// Response for balance query
/// 
/// Used by wallets, explorers, SDKs, and exchanges to query account balance.
/// All amounts are represented as strings to prevent JSON integer overflow.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BalanceRes {
    /// Account address (hex string with 0x prefix)
    pub address: String,
    /// Available balance (u128 as string, in smallest unit)
    pub balance: String,
    /// Locked balance (u128 as string, staked/delegated/pending unstake)
    pub locked: String,
}

/// Response for nonce query
/// 
/// Used by wallets and SDKs to get the next valid transaction nonce.
/// New addresses return nonce = 0.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NonceRes {
    /// Account address (hex string with 0x prefix)
    pub address: String,
    /// Current nonce (next valid nonce for transactions)
    pub nonce: u64,
}

// ════════════════════════════════════════════════════════════════════════════
// STAKING RPC TYPES (13.16.3)
// ════════════════════════════════════════════════════════════════════════════
// Request/Response structs for staking operations.
// Used by wallets, SDKs, validator tooling, and delegator dashboards.
// All u128 values are represented as String to avoid JSON overflow.
// NOTE: All staking requests expect pre-built, pre-signed TxEnvelope as hex.
// RPC does NOT construct transactions - that is the client's responsibility.
// ════════════════════════════════════════════════════════════════════════════

/// Response for stake info query (READ-ONLY)
/// 
/// Returns all staking-related data for an address.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StakeInfoRes {
    /// Account address (hex string with 0x prefix)
    pub address: String,
    /// Validator self-stake (u128 as string), 0 if not validator
    pub validator_stake: String,
    /// Delegated stake (u128 as string), 0 if not delegating
    pub delegator_stake: String,
    /// Total pending unstake amount (u128 as string)
    pub pending_unstake: String,
    /// Validator address delegated to (None if not delegating)
    pub delegated_to: Option<String>,
}

/// Request to submit a stake transaction
/// 
/// Transaction must be pre-built and signed by the client.
/// Payload should be TxPayload::Stake with bond=true.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StakeReq {
    /// Hex-encoded bincode serialized TxEnvelope containing Stake payload
    pub tx_envelope_hex: String,
}

/// Request to submit a delegate transaction
/// 
/// Transaction must be pre-built and signed by the client.
/// Payload should be TxPayload::Stake with delegator != validator and bond=true.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DelegateReq {
    /// Hex-encoded bincode serialized TxEnvelope containing Stake/Delegate payload
    pub tx_envelope_hex: String,
}

/// Request to submit an unstake transaction
/// 
/// Transaction must be pre-built and signed by the client.
/// Payload should be TxPayload::Unstake.
/// 7-day delay applies after acceptance.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UnstakeReq {
    /// Hex-encoded bincode serialized TxEnvelope containing Unstake payload
    pub tx_envelope_hex: String,
}

/// Response for staking operation submission
/// 
/// Returns transaction ID if accepted, or error details if rejected.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StakingOpRes {
    /// Whether the transaction was accepted
    pub success: bool,
    /// Transaction ID (hex string), empty if failed
    pub txid: String,
    /// Human-readable status message
    pub message: String,
}

// ════════════════════════════════════════════════════════════════════════════
// FEE SPLIT & GAS ESTIMATION RPC TYPES (13.16.4)
// ════════════════════════════════════════════════════════════════════════════
// Response structs for fee transparency and gas estimation.
// Used by wallets, SDKs, dApps, and automation tools.
// All u128 values are represented as String to avoid JSON overflow.
// All methods are READ-ONLY and DETERMINISTIC.
// ════════════════════════════════════════════════════════════════════════════

/// Response for fee split calculation
/// 
/// Shows how a fee is distributed according to Blueprint 70/20/10:
/// - Storage/Compute: 70% Node, 20% Validator, 10% Treasury
/// - Transfer/Governance/Stake: 0% Node, 100% Validator, 0% Treasury
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FeeSplitRes {
    /// Resource class ("Storage", "Compute", "Transfer", "Governance")
    pub resource_class: String,
    /// Total fee amount (u128 as string)
    pub total_fee: String,
    /// Node share amount (u128 as string)
    pub node_share: String,
    /// Validator share amount (u128 as string)
    pub validator_share: String,
    /// Treasury share amount (u128 as string)
    pub treasury_share: String,
}

/// Response for storage cost estimation
/// 
/// Calculates gas and cost for storage operations.
/// Uses constants from internal_gas.rs.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StorageCostRes {
    /// Number of bytes to store
    pub bytes: u64,
    /// Base cost for storage operation (u128 as string)
    pub base_cost: String,
    /// Per-byte cost (u128 as string)
    pub byte_cost: String,
    /// Node cost index multiplier (basis 100 = 1.0x)
    pub node_multiplier: u32,
    /// Total gas units (u128 as string)
    pub total_gas: String,
    /// Total cost in smallest unit (u128 as string)
    pub total_cost: String,
}

/// Response for compute cost estimation
/// 
/// Calculates gas and cost for compute operations.
/// Uses constants from internal_gas.rs.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ComputeCostRes {
    /// Number of compute cycles
    pub cycles: u64,
    /// Base cost for compute operation (u128 as string)
    pub base_cost: String,
    /// Per-cycle cost (u128 as string)
    pub cycle_cost: String,
    /// Node cost index multiplier (basis 100 = 1.0x)
    pub node_multiplier: u32,
    /// Total gas units (u128 as string)
    pub total_gas: String,
    /// Total cost in smallest unit (u128 as string)
    pub total_cost: String,
}

// ════════════════════════════════════════════════════════════════════════════
// RECEIPT STATUS RPC TYPES (13.16.5)
// ════════════════════════════════════════════════════════════════════════════
// Response struct for receipt status queries.
// Used by explorers, wallets, dashboards, and audit tools.
// All methods are READ-ONLY.
// ════════════════════════════════════════════════════════════════════════════

/// Response for receipt status query
/// 
/// Returns claim status and details for a receipt.
/// Used by explorers and wallets to check receipt status.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ReceiptStatusRes {
    /// Receipt ID (hex string)
    pub receipt_id: String,
    /// Whether the receipt has been claimed
    pub claimed: bool,
    /// Timestamp when receipt was claimed (None if not claimed)
    /// NOTE: Currently not tracked in state, reserved for future use
    pub claimed_at: Option<u64>,
    /// Address that claimed the receipt (None if not claimed)
    /// NOTE: Currently not tracked in state, reserved for future use
    pub claimed_by: Option<String>,
    /// Node address from the receipt (None if not available)
    /// NOTE: Currently not tracked in state, reserved for future use
    pub node_address: Option<String>,
    /// Amount claimed (u128 as string, None if not available)
    /// NOTE: Currently not tracked in state, reserved for future use
    pub amount: Option<String>,
}

// ════════════════════════════════════════════════════════════════════════════
// SNAPSHOT & CELESTIA RPC TYPES (13.16.6)
// ════════════════════════════════════════════════════════════════════════════
// Response structs for state snapshot and DA layer status.
// Used by explorers, auditors, and monitoring systems.
// All methods are READ-ONLY.
// ════════════════════════════════════════════════════════════════════════════

/// Response for state snapshot query
/// 
/// Returns a lightweight summary of current chain state.
/// Used by explorers for dashboard and auditors for verification.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SnapshotRes {
    /// Current block height
    pub height: u64,
    /// State root hash (hex string)
    pub state_root: String,
    /// Total number of accounts with non-zero balance
    pub total_accounts: u64,
    /// Total number of registered validators
    pub total_validators: u64,
    /// Total token supply (u128 as string)
    pub total_supply: String,
    /// Treasury balance (u128 as string)
    pub treasury_balance: String,
    /// Current epoch number
    pub epoch: u64,
    /// Timestamp of last processed block (Unix timestamp)
    pub timestamp: u64,
}

/// Response for blob height / Celestia DA status query
/// 
/// Returns DSDN chain height and Celestia sync status.
/// Used by operators and monitoring systems.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BlobHeightRes {
    /// Current DSDN block height
    pub dsdn_height: u64,
    /// Last synced Celestia height (None if not syncing)
    pub celestia_height: Option<u64>,
    /// Timestamp of last Celestia sync (None if never synced)
    pub last_sync_timestamp: Option<u64>,
    /// Sync status: "synced", "syncing", "not_synced"
    pub sync_status: String,
}

// ════════════════════════════════════════════════════════════════════════════
// SNAPSHOT LIST & FAST SYNC RPC RESPONSE TYPES (13.18.7)
// ════════════════════════════════════════════════════════════════════════════
// Response structs untuk snapshot listing, inspection, dan fast sync.
// SEMUA OPERASI INI ADALAH READ-ONLY atau EXPLICIT-ACTION.
// Tidak ada implicit behavior atau auto-sync.
// ════════════════════════════════════════════════════════════════════════════

/// Response for snapshot list query
/// 
/// Returns list of available snapshots sorted by height ascending.
/// Used by operators to select snapshot for fast sync.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SnapshotListRes {
    /// List of available snapshots (sorted by height ASC)
    pub snapshots: Vec<SnapshotMetadataRes>,
}

/// Response for snapshot metadata query
/// 
/// Returns metadata for a specific snapshot.
/// Used for inspection before fast sync.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SnapshotMetadataRes {
    /// Block height of snapshot
    pub height: u64,
    /// State root hash (hex string)
    pub state_root: String,
    /// Unix timestamp when snapshot was created
    pub timestamp: u64,
}

/// Response for fast sync operation
/// 
/// Returns status of fast sync initiation.
/// Fast sync is NOT started immediately - this returns whether it CAN start.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FastSyncStatusRes {
    /// Whether fast sync was successfully initiated
    pub started: bool,
    /// Snapshot height being used
    pub from_height: u64,
    /// Human-readable status message
    pub message: String,
}

// ════════════════════════════════════════════════════════════════════════════
// WALLET RPC RESPONSE TYPES (13.17.8)
// ════════════════════════════════════════════════════════════════════════════
// Response structs for wallet operations.
// CRITICAL: Secret key returned ONLY in wallet_generate response.
// Secret key MUST NOT be stored by RPC server.
// ════════════════════════════════════════════════════════════════════════════

/// Response for wallet generation
/// 
/// Returns newly generated wallet credentials.
/// SECURITY: Caller MUST backup secret_key securely.
/// Server does NOT store the secret key.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WalletGenerateRes {
    /// Blockchain address (hex with 0x prefix)
    pub address: String,
    /// Ed25519 public key (64 hex chars, no prefix)
    pub public_key: String,
    /// Ed25519 secret key (64 hex chars, no prefix)
    /// CRITICAL: Store securely, never share!
    pub secret_key: String,
}

/// Response for storage contract query
/// 
/// Exposes only user-facing fields, no internal-only data.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StorageContractRes {
    /// Contract ID (hex string)
    pub contract_id: String,
    /// Owner address (hex with 0x prefix)
    pub owner: String,
    /// Storage node address (hex with 0x prefix)
    pub node: String,
    /// Storage size in bytes
    pub bytes: u64,
    /// Monthly cost in NUSA (u128 as string)
    pub monthly_cost: String,
    /// Contract status: "Active", "GracePeriod", "Expired", "Cancelled"
    pub status: String,
}

/// Response for blob commitment verification
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BlobVerifyRes {
    /// Whether the blob matches the commitment
    pub valid: bool,
    /// Human-readable message
    pub message: String,
}

// ============================================================
// NODE COST INDEX RPC (13.9)
// ============================================================
// Endpoint untuk mengelola Node Cost Index via RPC.
// CATATAN: Otorisasi ditentukan oleh modul Governance, bukan di RPC ini.
// RPC hanya menyediakan interface; validasi akses dilakukan di layer atas.
// ============================================================

/// Request to set node cost index
#[derive(Serialize, Deserialize, Clone)]
pub struct SetNodeCostIndexReq {
    /// Node address (hex string)
    pub node_address: String,
    /// Cost index multiplier (basis 100 = 1.0x)
    pub multiplier: u128,
}

/// Request to remove node cost index
#[derive(Serialize, Deserialize, Clone)]
pub struct RemoveNodeCostIndexReq {
    /// Node address (hex string)
    pub node_address: String,
}

/// Response for node cost index operations
#[derive(Serialize, Deserialize, Clone)]
pub struct NodeCostIndexRes {
    pub success: bool,
    pub node_address: String,
    pub multiplier: Option<u128>,
    pub message: String,
}

// ════════════════════════════════════════════════════════════════════════════
// SERVICE NODE GATING RPC RESPONSE TYPES (14B.18)
// ════════════════════════════════════════════════════════════════════════════
// READ-ONLY structs for service node gating observability.
// No state mutation. Safe for monitoring, dashboards, and wallets.
// All u128 values are represented as String to avoid JSON overflow.
// ════════════════════════════════════════════════════════════════════════════

/// Response for service node stake query
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServiceNodeStakeRes {
    /// Operator address (hex string with 0x prefix)
    pub operator: String,
    /// Staked amount (u128 as string, smallest unit)
    pub staked_amount: String,
    /// Node class ("Storage" or "Compute")
    pub class: String,
    /// Whether staked_amount meets the minimum for this class
    pub meets_minimum: bool,
}

/// Response for service node class query
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServiceNodeClassRes {
    /// Operator address (hex string with 0x prefix)
    pub operator: String,
    /// Node class ("Storage" or "Compute")
    pub class: String,
    /// Minimum stake required for this class (u128 as string)
    pub min_stake_required: String,
}

/// Response for service node slashing status query
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServiceNodeSlashingRes {
    /// Operator address (hex string with 0x prefix)
    pub operator: String,
    /// Whether the node is currently slashed
    pub is_slashed: bool,
    /// Whether a cooldown period is currently active
    pub cooldown_active: bool,
    /// Seconds remaining in cooldown (None if not in cooldown)
    pub cooldown_remaining_secs: Option<u64>,
    /// Total count of slashing-related events
    pub slash_count: u64,
}

/// Response for service node info query
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServiceNodeInfoRes {
    /// Operator address (hex string with 0x prefix)
    pub operator: String,
    /// Node ID as lowercase hex string (64 chars, no prefix)
    pub node_id_hex: String,
    /// Node class ("Storage" or "Compute")
    pub class: String,
    /// Node lifecycle status ("Pending", "Active", "Quarantined", "Banned")
    pub status: String,
    /// Staked amount (u128 as string, smallest unit)
    pub staked_amount: String,
    /// Block height at which the node was first registered
    pub registered_height: u64,
    /// TLS certificate fingerprint as lowercase hex (None if not set)
    pub tls_fingerprint_hex: Option<String>,
}

// ════════════════════════════════════════════════════════════════════════════
// SERVICE NODE QUARANTINE & BAN STATUS RPC RESPONSE TYPES (14B.58)
// ════════════════════════════════════════════════════════════════════════════
// READ-ONLY structs for quarantine and ban observability.
// Combines data from state.service_nodes and state.node_liveness_records.
// No state mutation. Safe for monitoring and dashboards.
// ════════════════════════════════════════════════════════════════════════════

/// Response for service node quarantine status query.
///
/// Combines service node record (status, class, stake) with liveness
/// record (slashing flags, timestamps) to produce a quarantine overview.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct QuarantineStatusRes {
    /// Operator address (hex string with 0x prefix)
    pub operator: String,
    /// Whether the node is currently quarantined
    pub is_quarantined: bool,
    /// Reason for quarantine (derived from liveness flags, None if unknown)
    pub reason: Option<String>,
    /// Timestamp when quarantine started (approximated from last_seen, None if unavailable)
    pub since_timestamp: Option<u64>,
    /// Duration in seconds since quarantine started (None if not quarantined or unknown)
    pub duration_secs: Option<u64>,
    /// Current staked amount (u128 as string)
    pub current_stake: String,
    /// Minimum stake required for this class (u128 as string)
    pub required_stake: String,
    /// Whether current_stake >= required_stake (recovery eligibility)
    pub can_recover: bool,
}

/// Response for service node ban status query.
///
/// Combines service node record (status) with liveness record
/// (slashing flags, force_unbond_until) to produce a ban overview.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BanStatusRes {
    /// Operator address (hex string with 0x prefix)
    pub operator: String,
    /// Whether the node is currently banned
    pub is_banned: bool,
    /// Reason for ban (derived from liveness flags, None if unknown)
    pub reason: Option<String>,
    /// Timestamp when ban was recorded (approximated from last_seen, None if unavailable)
    pub banned_since: Option<u64>,
    /// Timestamp when cooldown expires (None if no cooldown or not banned)
    pub cooldown_until: Option<u64>,
    /// Seconds remaining in cooldown (0 if expired or not banned)
    pub cooldown_remaining_secs: u64,
}

// ════════════════════════════════════════════════════════════════════════════
// P2P NETWORK RPC RESPONSE TYPES (Tahap 21 v2)
// ════════════════════════════════════════════════════════════════════════════

/// P2P network status overview.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct P2pStatusRes {
    /// Role operasional node ini (storage-compute, validator, coordinator)
    pub role: String,
    /// Kelas node (reguler, datacenter) — hanya untuk storage-compute
    pub node_class: Option<String>,
    /// Jumlah peer yang sedang terkoneksi
    pub connected_count: usize,
    /// Jumlah peer yang diketahui (termasuk cached)
    pub known_count: usize,
    /// Apakah semua REQUIRED roles sudah terpenuhi
    pub all_required_met: bool,
    /// Daftar REQUIRED roles yang belum ada connected peer-nya
    pub missing_required: Vec<String>,
    /// Bootstrap state (e.g. "Completed", "Failed", "NotStarted")
    pub bootstrap_state: String,
}

/// Info tentang satu connected peer.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct P2pPeerRes {
    pub address: String,
    pub node_id: String,
    pub role: String,
    pub node_class: Option<String>,
    pub score: i64,
    pub success_count: u32,
    pub failure_count: u32,
    pub source: String,
}

/// Role dependency health entry.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct P2pRoleHealthEntry {
    pub role: String,
    pub dependency: String,
    pub connected_count: usize,
    pub status: String,
}

/// Response for p2p_role_health RPC.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct P2pRoleHealthRes {
    pub our_role: String,
    pub our_class: Option<String>,
    pub all_required_met: bool,
    pub roles: Vec<P2pRoleHealthEntry>,
}

/// P2P store statistics (role/class/source breakdown).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct P2pStoreStatsRes {
    pub total: usize,
    pub connected: usize,
    pub disconnected: usize,
    pub banned: usize,
    pub role_storage_compute: usize,
    pub class_reguler: usize,
    pub class_datacenter: usize,
    pub role_validator: usize,
    pub role_coordinator: usize,
    pub from_dns: usize,
    pub from_static: usize,
    pub from_pex: usize,
    pub from_inbound: usize,
    pub from_manual: usize,
    pub from_cache: usize,
}

// ════════════════════════════════════════════════════════════════════════════
// SERVICE NODE REGISTRATION RPC REQUEST TYPE (14B.54)
// ════════════════════════════════════════════════════════════════════════════
// Request struct for service node on-chain registration.
// Chain node builds, signs, and submits the transaction.
// Agent only provides parameters and wallet secret.
//
// SECURITY:
// - `secret_hex` is NEVER stored or logged by the server.
// - All signing is stateless — secret used once then discarded.
// - Follows the same pattern as `wallet_sign_tx` (13.17.8).
// ════════════════════════════════════════════════════════════════════════════

/// Request for service node registration (14B.54).
///
/// Chain RPC endpoint builds `TxPayload::RegisterServiceNode`,
/// signs with provided wallet secret, and submits to mempool.
///
/// Returns `SubmitTxRes` with txid on success.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RegisterServiceNodeReq {
    /// Operator address (hex, 40 chars, no 0x prefix)
    pub operator_hex: String,
    /// Node identity Ed25519 public key (hex, 64 chars = 32 bytes)
    pub node_id_hex: String,
    /// Node class: "storage" or "compute" (case-insensitive)
    pub class: String,
    /// TLS certificate fingerprint (hex, 64 chars = 32 bytes)
    pub tls_fingerprint_hex: String,
    /// Identity proof Ed25519 signature (hex, 128 chars = 64 bytes)
    pub identity_proof_sig_hex: String,
    /// Wallet Ed25519 secret key (hex, 64 chars = 32 bytes)
    /// SECURITY: Never stored or logged by server
    pub secret_hex: String,
    /// Transaction fee (u128 as string, smallest unit). "0" if omitted.
    pub fee: String,
}

/// RPC handler for public full node operations
pub struct FullNodeRpc {
    chain: Chain,
}

impl FullNodeRpc {
    pub fn new(chain: Chain) -> Self {
        Self { chain }
    }

    /// Sync block received from network peer
    /// 
    /// Validates:
    /// - Block signature is valid
    /// - Parent hash matches current tip
    /// - Block height = tip + 1
    /// 
    /// If valid, applies block to local state without mining
    pub fn sync_block(&self, block: Block) -> Result<SyncBlockRes, RpcError> {
        println!("📡 RPC: sync_block called for height {}", block.header.height);

        // ─────────────────────────────────────────────────────────
        // 1) BASIC VALIDATION - Signature
        // ─────────────────────────────────────────────────────────
        match block.verify_signature() {
            Ok(true) => {},
            Ok(false) => {
                return Err(RpcError {
                    code: -32001,
                    message: "block signature verification failed".to_string(),
                });
            }
            Err(e) => {
                return Err(RpcError {
                    code: -32002,
                    message: format!("signature verification error: {}", e),
                });
            }
        }

        // ─────────────────────────────────────────────────────────
        // 2) BASIC VALIDATION - Parent hash & Height
        // ─────────────────────────────────────────────────────────
        let (tip_height, tip_hash) = match self.chain.get_chain_tip() {
            Ok((h, hash)) => (h, hash),
            Err(_) => (0, Hash::from_bytes([0u8; 64])),
        };

        if block.header.parent_hash != tip_hash {
            return Err(RpcError {
                code: -32003,
                message: format!(
                    "parent hash mismatch: expected {}, got {}",
                    tip_hash, block.header.parent_hash
                ),
            });
        }

        let expected_height = tip_height + 1;
        if block.header.height != expected_height {
            return Err(RpcError {
                code: -32004,
                message: format!(
                    "block height mismatch: expected {}, got {}",
                    expected_height, block.header.height
                ),
            });
        }

        // ─────────────────────────────────────────────────────────
        // 3) APPLY BLOCK WITHOUT MINING
        // ─────────────────────────────────────────────────────────
        // This is the key function for full node behavior
        // It does NOT participate in consensus or proposer selection
        match self.chain.apply_block_without_mining(block.clone()) {
            Ok(()) => {
                let block_hash = Block::compute_hash(&block.header);
                Ok(SyncBlockRes {
                    success: true,
                    height: block.header.height,
                    block_hash: block_hash.to_hex(),
                    message: "block synced successfully".to_string(),
                })
            }
            Err(e) => {
                Err(RpcError {
                    code: -32005,
                    message: format!("failed to apply block: {}", e),
                })
            }
        }
    }

    /// Sync block from hex-encoded bincode data
    pub fn sync_block_from_hex(&self, req: SyncBlockReq) -> Result<SyncBlockRes, RpcError> {
        // Decode hex to bytes
        let block_bytes = hex::decode(&req.block_data).map_err(|e| RpcError {
            code: -32010,
            message: format!("invalid hex encoding: {}", e),
        })?;

        // Deserialize block
        let block: Block = bincode::deserialize(&block_bytes).map_err(|e| RpcError {
            code: -32011,
            message: format!("invalid block data: {}", e),
        })?;

        self.sync_block(block)
    }

    /// Get current chain info
    pub fn get_chain_info(&self) -> Result<ChainInfoRes, RpcError> {
        let (tip_height, tip_hash) = self.chain.get_chain_tip().map_err(|e| RpcError {
            code: -32020,
            message: format!("failed to get chain tip: {}", e),
        })?;

        Ok(ChainInfoRes {
            tip_height,
            tip_hash: tip_hash.to_hex(),
            is_validator: self.chain.is_validator_node(),
        })
    }

/// Check if a block at given height exists
    pub fn has_block(&self, height: u64) -> Result<bool, RpcError> {
        match self.chain.db.get_block(height) {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(e) => Err(RpcError {
                code: -32021,
                message: format!("failed to check block: {}", e),
            }),
        }
    }

    // ════════════════════════════════════════════════════════════════════
    // NODE COST INDEX RPC METHODS (13.9)
    // ════════════════════════════════════════════════════════════════════
    // CATATAN: Otorisasi ditentukan oleh modul Governance, bukan di RPC ini.
    // Caller (CLI Admin atau Governance module) bertanggung jawab memvalidasi
    // bahwa pemanggil memiliki hak untuk mengubah node cost index.
    // ════════════════════════════════════════════════════════════════════

    /// Set node cost index multiplier for a node
    /// 
    /// # Authorization
    /// Otorisasi dilakukan di layer Governance/Admin, bukan di RPC ini.
    /// 
    /// # Arguments
    /// * `req` - SetNodeCostIndexReq containing node address and multiplier
    /// 
    /// # Returns
    /// NodeCostIndexRes with success status
    pub fn rpc_set_node_cost_index(&self, req: SetNodeCostIndexReq) -> Result<NodeCostIndexRes, RpcError> {
        use crate::types::Address;
        use std::str::FromStr;

        // Parse node address
        let node_addr = Address::from_str(&req.node_address).map_err(|_| RpcError {
            code: -32040,
            message: format!("invalid node address: {}", req.node_address),
        })?;

        // Update state (requires write lock)
        {
            let mut state = self.chain.state.write();
            state.set_node_cost_index(node_addr, req.multiplier);
        }

        println!("📊 RPC: set_node_cost_index({}, {})", req.node_address, req.multiplier);

        Ok(NodeCostIndexRes {
            success: true,
            node_address: req.node_address,
            multiplier: Some(req.multiplier),
            message: format!("node cost index set to {}", req.multiplier),
        })
    }

    /// Remove node cost index multiplier for a node
    /// 
    /// # Authorization
    /// Otorisasi dilakukan di layer Governance/Admin, bukan di RPC ini.
    /// 
    /// # Arguments
    /// * `req` - RemoveNodeCostIndexReq containing node address
    /// 
    /// # Returns
    /// NodeCostIndexRes with previous value if existed
    pub fn rpc_remove_node_cost_index(&self, req: RemoveNodeCostIndexReq) -> Result<NodeCostIndexRes, RpcError> {
        use crate::types::Address;
        use std::str::FromStr;

        // Parse node address
        let node_addr = Address::from_str(&req.node_address).map_err(|_| RpcError {
            code: -32041,
            message: format!("invalid node address: {}", req.node_address),
        })?;

        // Remove from state (requires write lock)
        let previous = {
            let mut state = self.chain.state.write();
            state.remove_node_cost_index(&node_addr)
        };

        println!("📊 RPC: remove_node_cost_index({}) -> {:?}", req.node_address, previous);

        Ok(NodeCostIndexRes {
            success: true,
            node_address: req.node_address,
            multiplier: previous,
            message: match previous {
                Some(v) => format!("node cost index removed (was {})", v),
                None => "node cost index not found (using default)".to_string(),
            },
        })
    }

    /// Get node cost index for a node
    /// 
    /// # Arguments
    /// * `node_address` - Node address as hex string
    /// 
    /// # Returns
    /// Current multiplier (or DEFAULT if not set)
    pub fn rpc_get_node_cost_index(&self, node_address: &str) -> Result<NodeCostIndexRes, RpcError> {
        use crate::types::Address;
        use std::str::FromStr;

        let node_addr = Address::from_str(node_address).map_err(|_| RpcError {
            code: -32042,
            message: format!("invalid node address: {}", node_address),
        })?;

        let multiplier = {
            let state = self.chain.state.read();
            state.get_node_cost_index(&node_addr)
        };

        Ok(NodeCostIndexRes {
            success: true,
            node_address: node_address.to_string(),
            multiplier: Some(multiplier),
            message: format!("current multiplier: {}", multiplier),
        })
    }

    // ════════════════════════════════════════════════════════════════════
    // RECEIPT & CLAIMREWARD RPC METHODS (13.10)
    // ════════════════════════════════════════════════════════════════════
    // RPC hanya bertindak sebagai gateway:
    // - Query state (is_receipt_claimed, get_node_earnings)
    // - Submit transaksi (submit_claim_reward)
    // Semua logika validasi dilakukan di chain layer.
    // ════════════════════════════════════════════════════════════════════

    /// Check if a receipt has been claimed
    /// 
    /// # Arguments
    /// * `receipt_id` - Receipt ID as hex string (128 chars for 64 bytes Hash)
    /// 
    /// # Returns
    /// Boolean indicating if receipt has been claimed
    pub fn is_receipt_claimed(&self, receipt_id: String) -> Result<bool, RpcError> {
        // Decode hex to bytes
        let id_bytes = hex::decode(&receipt_id).map_err(|_| RpcError {
            code: -32050,
            message: format!("invalid receipt_id hex: {}", receipt_id),
        })?;

        // Convert to Hash (64 bytes)
        let hash_bytes: [u8; 64] = id_bytes.try_into().map_err(|_| RpcError {
            code: -32051,
            message: "receipt_id must be 64 bytes (128 hex chars)".to_string(),
        })?;

        let receipt_hash = Hash::from_bytes(hash_bytes);

        // Query state
        let is_claimed = {
            let state = self.chain.state.read();
            state.is_receipt_claimed(&receipt_hash)
        };

        Ok(is_claimed)
    }

    /// Get detailed receipt status (13.16.5)
    /// 
    /// # Arguments
    /// * `receipt_id` - Receipt ID as hex string (128 chars for 64 bytes Hash)
    /// 
    /// # Returns
    /// * `ReceiptStatusRes` with claim status and details
    /// 
    /// # Notes
    /// - READ-ONLY: Does not modify state
    /// - Backward compatible: Extends is_receipt_claimed()
    /// - Unknown receipts are treated as NOT claimed
    /// - Currently, claimed_at/claimed_by/node_address/amount are not tracked
    ///   in state and will return None. Reserved for future enhancement.
    pub fn get_receipt_status(&self, receipt_id: String) -> Result<ReceiptStatusRes, RpcError> {
        // ─────────────────────────────────────────────────────────
        // STEP 1: Validate and parse receipt_id
        // ─────────────────────────────────────────────────────────
        let id_bytes = hex::decode(&receipt_id).map_err(|_| RpcError {
            code: -32050,
            message: format!("invalid receipt_id hex: {}", receipt_id),
        })?;

        // Convert to Hash (64 bytes)
        let hash_bytes: [u8; 64] = id_bytes.try_into().map_err(|_| RpcError {
            code: -32051,
            message: "receipt_id must be 64 bytes (128 hex chars)".to_string(),
        })?;

        let receipt_hash = Hash::from_bytes(hash_bytes);

        // ─────────────────────────────────────────────────────────
        // STEP 2: Check claim status (READ-ONLY)
        // ─────────────────────────────────────────────────────────
        let is_claimed = {
            let state = self.chain.state.read();
            state.is_receipt_claimed(&receipt_hash)
        };

        // ─────────────────────────────────────────────────────────
        // STEP 3: Build response
        // ─────────────────────────────────────────────────────────
        // NOTE: Currently, claimed_receipts is a HashSet<Hash> that only
        // stores the receipt IDs. It does NOT store additional info like
        // claimed_at, claimed_by, node_address, or amount.
        // These fields are reserved for future enhancement when the state
        // structure is updated to track claim details.
        
        if is_claimed {
            // Receipt has been claimed
            // Additional details not available in current state structure
            Ok(ReceiptStatusRes {
                receipt_id,
                claimed: true,
                // Reserved for future: will be populated when state tracks claim details
                claimed_at: None,
                claimed_by: None,
                node_address: None,
                amount: None,
            })
        } else {
            // Receipt has NOT been claimed (or is unknown)
            Ok(ReceiptStatusRes {
                receipt_id,
                claimed: false,
                claimed_at: None,
                claimed_by: None,
                node_address: None,
                amount: None,
            })
        }
    }

    /// Get accumulated earnings for a node
    /// 
    /// # Arguments
    /// * `node_address` - Node address as hex string
    /// 
    /// # Returns
    /// Accumulated earnings (u128), 0 if node has no earnings
    pub fn get_node_earnings(&self, node_address: String) -> Result<u128, RpcError> {
        use crate::types::Address;
        use std::str::FromStr;

        let node_addr = Address::from_str(&node_address).map_err(|_| RpcError {
            code: -32052,
            message: format!("invalid node address: {}", node_address),
        })?;

        // Query state
        let earnings = {
            let state = self.chain.state.read();
            state.node_earnings.get(&node_addr).copied().unwrap_or(0)
        };

        Ok(earnings)
    }

    /// Submit a ClaimReward transaction
    /// 
    /// # Arguments
    /// * `receipt_json` - JSON string containing ResourceReceipt
    /// 
    /// # Returns
    /// Transaction ID as hex string
    pub fn submit_claim_reward(&self, receipt_json: String) -> Result<String, RpcError> {
        use crate::receipt::ResourceReceipt;

        // Parse JSON to ResourceReceipt
        let _receipt: ResourceReceipt = serde_json::from_str(&receipt_json).map_err(|e| RpcError {
            code: -32053,
            message: format!("invalid receipt JSON: {}", e),
        })?;

        // RPC hanya menerima receipt dan forward ke chain
        // Transaksi lengkap harus di-build dan di-sign oleh caller
        // Return error karena RPC tidak memiliki private key untuk signing
        Err(RpcError {
            code: -32054,
            message: "submit_claim_reward via RPC requires signed transaction. Use CLI instead.".to_string(),
        })
    }

    // ════════════════════════════════════════════════════════════════════
    // SYNC RPC METHODS (13.11.7)
    // ════════════════════════════════════════════════════════════════════
    // CATATAN: RPC tidak mengandung logika sync.
    // Semua delegasi ke Chain → SyncManager.
    // ════════════════════════════════════════════════════════════════════

    /// Get current sync status
    ///
    /// Returns current sync state and progress info.
    /// Read-only operation, non-blocking.
    pub fn get_sync_status(&self) -> SyncStatusRes {
        let status = self.chain.get_sync_status();
        let (current, target) = self.chain.get_sync_progress()
            .unwrap_or((0, 0));

        let status_str = match &status {
            SyncStatus::Idle => "Idle".to_string(),
            SyncStatus::SyncingHeaders { .. } => "SyncingHeaders".to_string(),
            SyncStatus::SyncingBlocks { .. } => "SyncingBlocks".to_string(),
            SyncStatus::SyncingState { .. } => "SyncingState".to_string(),
            SyncStatus::Synced => "Synced".to_string(),
        };

        SyncStatusRes {
            status: status_str,
            current_height: current,
            target_height: target,
        }
    }

    /// Start sync process
    ///
    /// Initiates sync to network tip.
    /// Idempotent: calling when already syncing returns success.
    pub fn start_sync(&self) -> Result<(), RpcError> {
        // Get peer tip (placeholder - in production, get from P2P layer)
        let target_tip = match self.chain.get_chain_tip() {
            Ok((h, hash)) => (hash, h),
            Err(e) => {
                return Err(RpcError {
                    code: -32060,
                    message: format!("failed to get chain tip: {}", e),
                });
            }
        };

        match self.chain.start_sync(target_tip) {
            Ok(()) => Ok(()),
            Err(e) => Err(RpcError {
                code: -32061,
                message: format!("failed to start sync: {}", e),
            }),
        }
    }

    /// Stop sync process
    ///
    /// Cancels ongoing sync and returns to Idle state.
    /// Idempotent: calling when not syncing returns success.
    pub fn stop_sync(&self) -> Result<(), RpcError> {
        // Delegasi ke Chain (akan ditambahkan method cancel_sync)
        println!("📡 RPC: stop_sync called");
        Ok(())
    }

    /// Get sync progress
    ///
    /// Returns detailed progress information.
    /// Read-only operation, non-blocking.
    pub fn get_sync_progress(&self) -> SyncProgressRes {
        let (current, target) = self.chain.get_sync_progress()
            .unwrap_or((0, 0));

        let percent = if target == 0 {
            100u8
        } else {
            ((current as f64 / target as f64) * 100.0).min(100.0) as u8
        };

        SyncProgressRes {
            current,
            target,
            percent,
        }
    }

    /// Handle sync request from peer
    ///
    /// Processes incoming sync request and returns appropriate response.
    /// Used by P2P layer for block/header propagation.
    pub fn handle_sync_request(&self, req: SyncRequest) -> SyncResponse {
        match req {
            SyncRequest::GetHeaders { start_height, count } => {
                let end_height = start_height + count - 1;
                match self.chain.db.get_headers_range(start_height, end_height) {
                    Ok(headers) => SyncResponse::Headers { headers },
                    Err(e) => SyncResponse::Error {
                        message: format!("failed to get headers: {}", e),
                    },
                }
            }
            SyncRequest::GetBlock { height } => {
                match self.chain.db.get_block(height) {
                    Ok(Some(block)) => SyncResponse::Block { block },
                    Ok(None) => SyncResponse::NotFound { height },
                    Err(e) => SyncResponse::Error {
                        message: format!("failed to get block: {}", e),
                    },
                }
            }
            SyncRequest::GetBlocks { heights } => {
                let mut blocks = Vec::new();
                for h in heights {
                    match self.chain.db.get_block(h) {
                        Ok(Some(block)) => blocks.push(block),
                        Ok(None) => {
                            return SyncResponse::NotFound { height: h };
                        }
                        Err(e) => {
                            return SyncResponse::Error {
                                message: format!("failed to get block {}: {}", h, e),
                            };
                        }
                    }
                }
                SyncResponse::Blocks { blocks }
            }
SyncRequest::GetChainTip => {
                match self.chain.get_chain_tip() {
                    Ok((height, hash)) => SyncResponse::ChainTip { height, hash },
                    Err(e) => SyncResponse::Error {
                        message: format!("failed to get chain tip: {}", e),
                    },
                }
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // GOVERNANCE RPC METHODS (13.12.8)
    // ════════════════════════════════════════════════════════════════════════════
    // CATATAN: Semua method di sini adalah READ-ONLY.
    // Tidak ada mutasi state. Query langsung ke ChainState.
    // ════════════════════════════════════════════════════════════════════════════

    /// Get proposal by ID
    ///
    /// # Arguments
    /// * `id` - Proposal ID
    ///
    /// # Returns
    /// ProposalRes if found, RpcError if not found
    pub fn get_proposal(&self, id: u64) -> Result<ProposalRes, RpcError> {
        let state = self.chain.state.read();
        
        match state.get_proposal(id) {
            Some(proposal) => Ok(Self::proposal_to_res(&proposal)),
            None => Err(RpcError {
                code: -32070,
                message: format!("proposal {} not found", id),
            }),
        }
    }

    /// List all active proposals (status = Active)
    ///
    /// # Returns
    /// Vec<ProposalRes> of active proposals, empty vec if none
    pub fn list_active_proposals(&self) -> Vec<ProposalRes> {
        let state = self.chain.state.read();
        state.get_active_proposals()
            .into_iter()
            .map(|p| Self::proposal_to_res(&p))
            .collect()
    }

    /// List all proposals (all statuses)
    ///
    /// # Returns
    /// Vec<ProposalRes> of all proposals, empty vec if none
    pub fn list_all_proposals(&self) -> Vec<ProposalRes> {
        let state = self.chain.state.read();
        let mut proposals: Vec<_> = state.proposals.values()
            .map(|p| Self::proposal_to_res(p))
            .collect();
        // Sort by ID for deterministic output
        proposals.sort_by_key(|p| p.id);
        proposals
    }

    /// Get all votes for a proposal
    ///
    /// # Arguments
    /// * `id` - Proposal ID
    ///
    /// # Returns
    /// Vec<VoteRes> of votes, empty vec if proposal has no votes or doesn't exist
    pub fn get_proposal_votes(&self, id: u64) -> Vec<VoteRes> {
        let state = self.chain.state.read();
        
        // get_proposal_votes returns Vec<&Vote>
        let votes_vec = state.get_proposal_votes(id);
        
        if votes_vec.is_empty() {
            return Vec::new();
        }
        
        let mut votes: Vec<_> = votes_vec.iter()
            .map(|v| Self::vote_to_res(v))
            .collect();
        // Sort by voter address for deterministic output
        votes.sort_by(|a, b| a.voter.cmp(&b.voter));
        votes
    }

    /// Get voter status for a specific proposal
    ///
    /// # Arguments
    /// * `voter` - Voter address as hex string
    /// * `proposal_id` - Proposal ID
    ///
    /// # Returns
    /// VoterStatusRes with voting status and power
    pub fn get_voter_status(&self, voter: &str, proposal_id: u64) -> Result<VoterStatusRes, RpcError> {
        use std::str::FromStr;
        
        let voter_addr = Address::from_str(voter).map_err(|_| RpcError {
            code: -32071,
            message: format!("invalid voter address: {}", voter),
        })?;
        
        let state = self.chain.state.read();
        
        // Remove & - methods expect Address by value
        let has_voted = state.has_voted(voter_addr, proposal_id);
        let current_voting_power = state.get_voter_weight(voter_addr);
        
        // get_proposal_votes returns Vec<&Vote>
        let (vote_option, vote_weight) = if has_voted {
            let votes_vec = state.get_proposal_votes(proposal_id);
            let found_vote = votes_vec.iter().find(|v| v.voter == voter_addr);
            
            match found_vote {
                Some(vote) => (Some(Self::vote_option_to_string(&vote.option)), Some(vote.weight)),
                None => (None, None),
            }
        } else {
            (None, None)
        };
        
        Ok(VoterStatusRes {
            voter: voter.to_string(),
            proposal_id,
            has_voted,
            vote_option,
            vote_weight,
            current_voting_power,
        })
    }

    /// Get current governance configuration
    ///
    /// # Returns
    /// GovernanceConfigRes with current config values
    pub fn get_governance_config(&self) -> GovernanceConfigRes {
        let state = self.chain.state.read();
        let config = &state.governance_config;
        
    GovernanceConfigRes {
            voting_period_seconds: config.voting_period_seconds,
            quorum_percentage: config.quorum_percentage,
            pass_threshold: config.pass_threshold,
            min_proposer_stake: config.min_proposer_stake,
            foundation_address: format!("0x{}", hex::encode(config.foundation_address.as_bytes())),
            bootstrap_mode: config.bootstrap_mode,
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // GOVERNANCE PREVIEW RPC METHODS (13.13.5)
    // ════════════════════════════════════════════════════════════════════════════
    // CATATAN: Semua method di sini adalah READ-ONLY.
    // Tidak ada mutasi state. Preview TIDAK mengeksekusi proposal.
    // ════════════════════════════════════════════════════════════════════════════

    /// Get proposal preview
    ///
    /// Returns simulated changes that would occur if proposal is executed.
    /// This is READ-ONLY and does NOT modify any state.
    ///
    /// # Arguments
    /// * `id` - Proposal ID
    ///
    /// # Returns
    /// ProposalPreviewRes if found, RpcError if proposal not found or preview fails
    ///
    /// # Note
    /// Preview is informational only. In Bootstrap Mode, no proposal will actually
    /// execute regardless of status.
    pub fn get_proposal_preview(&self, id: u64) -> Result<ProposalPreviewRes, RpcError> {
        let state = self.chain.state.read();
        
        // Call state method to generate preview (READ-ONLY)
        let preview = state.generate_proposal_preview(id)
            .map_err(|e| RpcError {
                code: -32080,
                message: format!("failed to generate preview for proposal {}: {:?}", id, e),
            })?;
        
        // Convert to RPC response
        Ok(Self::proposal_preview_to_res(&preview))
    }

    /// Get bootstrap mode status
    ///
    /// Returns current bootstrap mode status and execution allowance.
    /// This is READ-ONLY and does NOT modify any state.
    ///
    /// # Returns
    /// BootstrapModeRes with current status
    ///
    /// # Note
    /// When is_active == true, execution_allowed == false.
    /// In Bootstrap Mode, all proposals are NON-BINDING.
    pub fn get_bootstrap_mode_status(&self) -> BootstrapModeRes {
        let state = self.chain.state.read();
        
        // Call state method to get status (READ-ONLY)
        let status = state.get_bootstrap_mode_status();
        
        BootstrapModeRes {
            is_active: status.is_active,
            foundation_address: format!("0x{}", hex::encode(status.foundation_address.as_bytes())),
            execution_allowed: !status.is_active,
            message: status.message,
        }
    }

    /// Get recent governance events
    ///
    /// Returns the most recent governance events from in-memory buffer.
    /// Events are ordered oldest to newest.
    /// This is READ-ONLY and does NOT modify any state.
    ///
    /// # Arguments
    /// * `count` - Number of events to retrieve
    ///
    /// # Returns
    /// Vec<GovernanceEventRes> with events, empty vec if no events
    ///
    /// # Note
    /// Events are in-memory only and are NOT persisted.
    /// Events do NOT affect consensus.
    pub fn get_governance_events(&self, count: u64) -> Vec<GovernanceEventRes> {
        let state = self.chain.state.read();
        
        // Call state method to get events (READ-ONLY)
        let events = state.get_recent_governance_events(count as usize);
        
        // Convert to RPC response
        events.iter()
            .map(|e| Self::governance_event_to_res(e))
            .collect()
    }

    // ════════════════════════════════════════════════════════════════════════════
    // GOVERNANCE RPC HELPER METHODS (private)
    // ════════════════════════════════════════════════════════════════════════════

    /// Convert internal Proposal to ProposalRes
    fn proposal_to_res(proposal: &Proposal) -> ProposalRes {
        ProposalRes {
            id: proposal.id,
            proposal_type: Self::proposal_type_to_string(&proposal.proposal_type),
            proposer: format!("0x{}", hex::encode(proposal.proposer.as_bytes())),
            title: proposal.title.clone(),
            description: proposal.description.clone(),
            status: Self::proposal_status_to_string(&proposal.status),
            created_at: proposal.created_at,
            voting_end: proposal.voting_end,
            yes_votes: proposal.yes_votes,
            no_votes: proposal.no_votes,
            abstain_votes: proposal.abstain_votes,
            quorum_required: proposal.quorum_required,
        }
    }

    /// Convert internal Vote to VoteRes
    fn vote_to_res(vote: &Vote) -> VoteRes {
        VoteRes {
            voter: format!("0x{}", hex::encode(vote.voter.as_bytes())),
            proposal_id: vote.proposal_id,
            option: Self::vote_option_to_string(&vote.option),
            weight: vote.weight,
            timestamp: vote.timestamp,
        }
    }

    /// Convert ProposalType enum to string
    fn proposal_type_to_string(pt: &ProposalType) -> String {
        match pt {
            ProposalType::UpdateFeeParameter { .. } => "UpdateFeeParameter".to_string(),
            ProposalType::UpdateGasPrice { .. } => "UpdateGasPrice".to_string(),
            ProposalType::UpdateNodeCostIndex { .. } => "UpdateNodeCostIndex".to_string(),
            ProposalType::ValidatorOnboarding { .. } => "ValidatorOnboarding".to_string(),
            ProposalType::ValidatorOffboarding { .. } => "ValidatorOffboarding".to_string(),
            ProposalType::CompliancePointerRemoval { .. } => "CompliancePointerRemoval".to_string(),
            ProposalType::EmergencyPause { .. } => "EmergencyPause".to_string(),
        }
    }

    /// Convert ProposalStatus enum to string
    fn proposal_status_to_string(status: &ProposalStatus) -> String {
        match status {
            ProposalStatus::Active => "Active".to_string(),
            ProposalStatus::Passed => "Passed".to_string(),
            ProposalStatus::Rejected => "Rejected".to_string(),
            ProposalStatus::Expired => "Expired".to_string(),
            ProposalStatus::Vetoed => "Vetoed".to_string(),
            ProposalStatus::Executed => "Executed".to_string(),
        }
    }

    /// Convert VoteOption enum to string
    fn vote_option_to_string(opt: &VoteOption) -> String {
        match opt {
            VoteOption::Yes => "Yes".to_string(),
            VoteOption::No => "No".to_string(),
            VoteOption::Abstain => "Abstain".to_string(),
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // GOVERNANCE PREVIEW HELPER METHODS (13.13.5)
    // ════════════════════════════════════════════════════════════════════════════

    /// Convert internal ProposalPreview to ProposalPreviewRes
    fn proposal_preview_to_res(preview: &ProposalPreview) -> ProposalPreviewRes {
        ProposalPreviewRes {
            proposal_id: preview.proposal_id,
            preview_type: Self::preview_type_to_string(&preview.preview_type),
            simulated_changes: preview.simulated_changes.iter()
                .map(|c| Self::simulated_change_to_res(c))
                .collect(),
            affected_addresses: preview.affected_addresses.iter()
                .map(|a: &Address| format!("0x{}", hex::encode(a.as_bytes())))
                .collect(),
            generated_at: preview.generated_at,
        }
    }

    /// Convert internal SimulatedChange to SimulatedChangeRes
    fn simulated_change_to_res(change: &SimulatedChange) -> SimulatedChangeRes {
        SimulatedChangeRes {
            field_path: change.field_path.clone(),
            old_value: change.old_value_display.clone(),
            new_value: change.new_value_display.clone(),
        }
    }

    /// Convert PreviewType enum to string
    fn preview_type_to_string(pt: &PreviewType) -> String {
        match pt {
            PreviewType::FeeParameterChange { param_name, .. } => {
                format!("FeeParameterChange({})", param_name)
            }
            PreviewType::GasPriceChange { .. } => "GasPriceChange".to_string(),
            PreviewType::NodeCostIndexChange { node, .. } => {
                format!("NodeCostIndexChange(0x{})", hex::encode(node.as_bytes()))
            }
            PreviewType::ValidatorOnboard { validator, .. } => {
                format!("ValidatorOnboard(0x{})", hex::encode(validator.as_bytes()))
            }
            PreviewType::ValidatorOffboard { validator, .. } => {
                format!("ValidatorOffboard(0x{})", hex::encode(validator.as_bytes()))
            }
            PreviewType::CompliancePointerRemoval { pointer_id } => {
                format!("CompliancePointerRemoval({})", pointer_id)
            }
            PreviewType::EmergencyPause { pause_type } => {
                format!("EmergencyPause({})", pause_type)
            }
        }
    }

    /// Convert internal GovernanceEvent to GovernanceEventRes
    fn governance_event_to_res(event: &GovernanceEvent) -> GovernanceEventRes {
        GovernanceEventRes {
            event_type: Self::governance_event_type_to_string(&event.event_type),
            proposal_id: event.proposal_id,
            actor: format!("0x{}", hex::encode(event.actor.as_bytes())),
            timestamp: event.timestamp,
            details: event.details.clone(),
        }
    }

/// Convert GovernanceEventType enum to string
    fn governance_event_type_to_string(et: &GovernanceEventType) -> String {
        match et {
            GovernanceEventType::ProposalCreated => "ProposalCreated".to_string(),
            GovernanceEventType::VoteCast => "VoteCast".to_string(),
            GovernanceEventType::ProposalFinalized => "ProposalFinalized".to_string(),
            GovernanceEventType::ProposalVetoed => "ProposalVetoed".to_string(),
            GovernanceEventType::ProposalOverridden => "ProposalOverridden".to_string(),
            GovernanceEventType::PreviewGenerated => "PreviewGenerated".to_string(),
            GovernanceEventType::ExecutionAttemptBlocked => "ExecutionAttemptBlocked".to_string(),
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // SLASHING RPC METHODS (13.14.8)
    // ════════════════════════════════════════════════════════════════════════════
    // CATATAN: Semua method di sini adalah READ-ONLY.
    // Tidak ada mutasi state. Aman untuk monitoring dan dashboard.
    // ════════════════════════════════════════════════════════════════════════════

    /// Get node liveness status
    ///
    /// Returns liveness record for a storage/compute node.
    /// This is READ-ONLY and does NOT modify any state.
    ///
    /// # Arguments
    /// * `node` - Node address
    ///
    /// # Returns
    /// NodeLivenessRes if record found, RpcError if not found
    pub fn get_node_liveness_status(&self, node: Address) -> Result<NodeLivenessRes, RpcError> {
        let state = self.chain.state.read();
        
        match state.node_liveness_records.get(&node) {
            Some(record) => Ok(NodeLivenessRes {
                node_address: format!("0x{}", hex::encode(node.as_bytes())),
                last_seen_timestamp: record.last_seen_timestamp,
                consecutive_failures: record.consecutive_failures,
                data_corruption_count: record.data_corruption_count,
                malicious_behavior_count: record.malicious_behavior_count,
                force_unbond_until: record.force_unbond_until,
                slashed: record.slashed,
            }),
            None => Err(RpcError {
                code: -32090,
                message: format!("node liveness record not found for {}", node),
            }),
        }
    }

    /// Get validator slash status
    ///
    /// Returns slashing status for a validator.
    /// This is READ-ONLY and does NOT modify any state.
    ///
    /// # Arguments
    /// * `validator` - Validator address
    ///
    /// # Returns
    /// ValidatorSlashRes with slashing status
    pub fn get_validator_slash_status(&self, validator: Address) -> Result<ValidatorSlashRes, RpcError> {
        let state = self.chain.state.read();
        
        // Check if validator exists
        if !state.validator_set.is_validator(&validator) {
            return Err(RpcError {
                code: -32091,
                message: format!("validator not found: {}", validator),
            });
        }
        
        // Get slashing info from node_liveness_records
        let (slashed, reason, force_unbond_until) = match state.node_liveness_records.get(&validator) {
            Some(record) => {
                let reason_str = if record.slashed {
                    // Determine reason from flags
                    if record.double_sign_detected {
                        Some("ValidatorDoubleSign".to_string())
                    } else if record.malicious_block_detected {
                        Some("ValidatorMaliciousBlock".to_string())
                    } else if record.consecutive_failures > 0 {
                        Some("ValidatorProlongedOffline".to_string())
                    } else {
                        Some("Unknown".to_string())
                    }
                } else {
                    None
                };
                (record.slashed, reason_str, record.force_unbond_until)
            }
            None => {
                // Also check legacy liveness_records
                match state.liveness_records.get(&validator) {
                    Some(legacy_record) => {
                        let reason_str = if legacy_record.slashed {
                            Some("LegacySlash".to_string())
                        } else {
                            None
                        };
                        (legacy_record.slashed, reason_str, None)
                    }
                    None => (false, None, None),
                }
            }
        };
        
        Ok(ValidatorSlashRes {
            validator_address: format!("0x{}", hex::encode(validator.as_bytes())),
            slashed,
            reason,
            force_unbond_until,
        })
    }

    /// Get recent slashing events
    ///
    /// Returns the most recent slashing events from in-memory buffer.
    /// Events are ordered oldest to newest.
    /// This is READ-ONLY and does NOT modify any state.
    ///
    /// # Arguments
    /// * `count` - Number of events to retrieve (capped at available)
    ///
    /// # Returns
    /// Vec<SlashingEventRes> with events, empty vec if no events
    ///
    /// # Note
    /// slashing_events is runtime-only and NOT persisted.
    /// Events are reset after node restart.
    pub fn get_recent_slashing_events(&self, count: u64) -> Vec<SlashingEventRes> {
        let state = self.chain.state.read();
        
        let events = &state.slashing_events;
        let total = events.len();
        
        // Safe handling: cap count to available events
        let count_usize = count as usize;
        let start_idx = if count_usize >= total {
            0
        } else {
            total - count_usize
        };
        
        // Return oldest to newest
        events[start_idx..]
            .iter()
            .map(|e| Self::slashing_event_to_res(e))
            .collect()
    }

    // ════════════════════════════════════════════════════════════════════════════
    // SLASHING HELPER METHODS (13.14.8)
    // ════════════════════════════════════════════════════════════════════════════

    /// Convert internal SlashingEvent to SlashingEventRes
    fn slashing_event_to_res(event: &crate::slashing::SlashingEvent) -> SlashingEventRes {
        SlashingEventRes {
            target: format!("0x{}", hex::encode(event.target.as_bytes())),
            reason: Self::slashing_reason_to_string(&event.reason),
            amount_slashed: event.amount_slashed.to_string(),
            amount_to_treasury: event.amount_to_treasury.to_string(),
            amount_burned: event.amount_burned.to_string(),
            timestamp: event.timestamp,
        }
    }

    /// Convert SlashingReason enum to string
    fn slashing_reason_to_string(reason: &crate::slashing::SlashingReason) -> String {
        match reason {
            crate::slashing::SlashingReason::NodeLivenessFailure => "NodeLivenessFailure".to_string(),
            crate::slashing::SlashingReason::NodeDataCorruption => "NodeDataCorruption".to_string(),
            crate::slashing::SlashingReason::NodeMaliciousBehavior => "NodeMaliciousBehavior".to_string(),
            crate::slashing::SlashingReason::ValidatorDoubleSign => "ValidatorDoubleSign".to_string(),
            crate::slashing::SlashingReason::ValidatorProlongedOffline => "ValidatorProlongedOffline".to_string(),
            crate::slashing::SlashingReason::ValidatorMaliciousBlock => "ValidatorMaliciousBlock".to_string(),
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // ECONOMIC RPC METHODS (13.15.8)
    // ════════════════════════════════════════════════════════════════════════════
    // CATATAN: Semua method di sini adalah READ-ONLY.
    // Tidak ada mutasi state. Aman untuk monitoring dan dashboard.
    // Semua nilai u128 dikonversi ke String untuk menghindari JSON overflow.
    // ════════════════════════════════════════════════════════════════════════════

    /// Get economic status
    ///
    /// Returns current economic state including mode, treasury, supply, and burn rate.
    /// This is READ-ONLY and does NOT modify any state.
    ///
    /// # Returns
    /// EconomicStatusRes with current economic status
    ///
    /// # Note
    /// All u128 values are represented as String to avoid JSON overflow.
    pub fn get_economic_status(&self) -> Result<EconomicStatusRes, RpcError> {
        let state = self.chain.state.read();
        
        // Get economic mode from state method
        let mode = state.get_economic_mode();
        
        // Get replication factor from deflation config
        let replication_factor = state.deflation_config.replication_factor;
        
        // Get treasury balance
        let treasury_balance = state.treasury_balance;
        
        // Get total supply
        let total_supply = state.total_supply;
        
        // Check if deflation is enabled
        let deflation_enabled = state.deflation_config.enabled;
        
        // Calculate current burn rate
        let current_burn_rate = state.calculate_target_burn_rate();
        
        Ok(EconomicStatusRes {
            mode: Self::economic_mode_to_string(&mode),
            replication_factor,
            treasury_balance: treasury_balance.to_string(),
            total_supply: total_supply.to_string(),
            deflation_enabled,
            current_burn_rate: current_burn_rate.to_string(),
        })
    }

    /// Get deflation info
    ///
    /// Returns deflation configuration and current state.
    /// This is READ-ONLY and does NOT modify any state.
    ///
    /// # Returns
    /// DeflationInfoRes with deflation configuration and state
    ///
    /// # Note
    /// All u128 values are represented as String to avoid JSON overflow.
    pub fn get_deflation_info(&self) -> Result<DeflationInfoRes, RpcError> {
        let state = self.chain.state.read();
        
        // Get deflation config values
        let target_min = state.deflation_config.target_min_percent;
        let target_max = state.deflation_config.target_max_percent;
        let burn_interval = state.deflation_config.burn_interval_epochs;
        
        // Get current state values
        let current_rate = state.calculate_target_burn_rate();
        let cumulative_burned = state.cumulative_burned;
        let last_burn_epoch = state.last_burn_epoch;
        
        // Calculate next eligible epoch
        let next_burn_eligible_epoch = last_burn_epoch.saturating_add(burn_interval);
        
        Ok(DeflationInfoRes {
            target_min_percent: target_min.to_string(),
            target_max_percent: target_max.to_string(),
            current_annual_rate: current_rate.to_string(),
            cumulative_burned: cumulative_burned.to_string(),
            last_burn_epoch,
            next_burn_eligible_epoch,
        })
    }

    /// Get recent burn events
    ///
    /// Returns the most recent burn events from in-memory buffer.
    /// Events are ordered oldest to newest.
    /// This is READ-ONLY and does NOT modify any state.
    ///
    /// # Arguments
    /// * `count` - Number of events to retrieve (capped at available)
    ///
    /// # Returns
    /// Vec<BurnEventRes> with events, empty vec if no events
    ///
    /// # Note
    /// economic_events is runtime-only and NOT persisted.
    /// Events are reset after node restart.
    pub fn get_burn_events(&self, count: u32) -> Vec<BurnEventRes> {
        let state = self.chain.state.read();
        
        let events = &state.economic_events;
        let total = events.len();
        
        // Safe handling: cap count to available events
        let count_usize = count as usize;
        let start_idx = if count_usize >= total {
            0
        } else {
            total - count_usize
        };
        
        // Return oldest to newest
        events[start_idx..]
            .iter()
            .map(|e| Self::burn_event_to_res(e))
            .collect()
    }

    // ════════════════════════════════════════════════════════════════════════════
    // ECONOMIC HELPER METHODS (13.15.8)
    // ════════════════════════════════════════════════════════════════════════════

    /// Convert internal BurnEvent to BurnEventRes
    fn burn_event_to_res(event: &crate::economic::BurnEvent) -> BurnEventRes {
        BurnEventRes {
            epoch: event.epoch,
            amount_burned: event.amount_burned.to_string(),
            burn_rate: event.burn_rate_applied.to_string(),
            timestamp: event.timestamp,
        }
    }

    /// Convert EconomicMode enum to string
    fn economic_mode_to_string(mode: &crate::economic::EconomicMode) -> String {
        match mode {
            crate::economic::EconomicMode::Bootstrap => "Bootstrap".to_string(),
            crate::economic::EconomicMode::Active => "Active".to_string(),
            crate::economic::EconomicMode::Governance => "Governance".to_string(),
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // CORE QUERY RPC METHODS (13.16.1)
    // ════════════════════════════════════════════════════════════════════════════
    // READ-ONLY endpoints for wallet, explorer, SDK, and exchange integration.
    // These are the most frequently called RPC endpoints.
    // NO STATE MUTATION. NO PANIC.
    // ════════════════════════════════════════════════════════════════════════════

    /// Get account balance and locked amount
    /// 
    /// # Arguments
    /// * `address` - Account address as hex string (with or without 0x prefix)
    /// 
    /// # Returns
    /// * `BalanceRes` with balance and locked amounts as strings
    /// 
    /// # Notes
    /// - READ-ONLY: Does not modify state
    /// - New/unknown addresses return balance = "0", locked = "0"
    /// - All amounts in smallest unit (no decimals)
    pub fn get_balance(&self, address: String) -> Result<BalanceRes, RpcError> {
        // Parse address from hex string
        let addr = address.trim_start_matches("0x");
        let parsed_addr = Address::from_hex(addr).map_err(|e| RpcError {
            code: -32600,
            message: format!("invalid address format: {}", e),
        })?;

        // Read state (read-only lock)
        let state = self.chain.state.read();
        
        // Get balance and locked from state
        // These methods return 0 for unknown addresses (safe default)
        let balance = state.get_balance(&parsed_addr);
        let locked = state.get_locked(&parsed_addr);

        Ok(BalanceRes {
            address: format!("0x{}", addr),
            balance: balance.to_string(),
            locked: locked.to_string(),
        })
    }

    /// Get account nonce (transaction count)
    /// 
    /// # Arguments
    /// * `address` - Account address as hex string (with or without 0x prefix)
    /// 
    /// # Returns
    /// * `NonceRes` with current nonce
    /// 
    /// # Notes
    /// - READ-ONLY: Does not modify state
    /// - New/unknown addresses return nonce = 0
    /// - Nonce is the next valid transaction sequence number
    pub fn get_nonce(&self, address: String) -> Result<NonceRes, RpcError> {
        // Parse address from hex string
        let addr = address.trim_start_matches("0x");
        let parsed_addr = Address::from_hex(addr).map_err(|e| RpcError {
            code: -32600,
            message: format!("invalid address format: {}", e),
        })?;

        // Read state (read-only lock)
        let state = self.chain.state.read();
        
        // Get nonce from state
        // Returns 0 for unknown addresses (safe default)
        let nonce = state.get_nonce(&parsed_addr);

        Ok(NonceRes {
            address: format!("0x{}", addr),
            nonce,
        })
    }

    // ════════════════════════════════════════════════════════════════════════════
    // TRANSACTION SUBMISSION RPC METHODS (13.16.2)
    // ════════════════════════════════════════════════════════════════════════════
    // Entry point for all transactions into the network.
    // This is a WRAPPER only - no validation logic here.
    // All validation is delegated to Chain::submit_tx().
    // ════════════════════════════════════════════════════════════════════════════

    /// Submit a transaction to the network
    /// 
    /// # Arguments
    /// * `req` - Request containing hex-encoded bincode serialized TxEnvelope
    /// 
    /// # Returns
    /// * `SubmitTxRes` with transaction ID if accepted, or error details if rejected
    /// 
    /// # Notes
    /// - This is a WRAPPER only - delegates all validation to Chain::submit_tx()
    /// - Transaction acceptance does NOT guarantee inclusion in a block
    /// - Transaction is added to mempool for future block inclusion
    /// - No panic: all errors are returned as RpcError or SubmitTxRes with success=false
    pub fn submit_tx(&self, req: SubmitTxReq) -> Result<SubmitTxRes, RpcError> {
        // ─────────────────────────────────────────────────────────
        // STEP 1: Decode hex string to bytes
        // ─────────────────────────────────────────────────────────
        let tx_bytes = hex::decode(&req.tx_envelope_hex).map_err(|e| RpcError {
            code: -32602,
            message: format!("Invalid transaction encoding: {}", e),
        })?;

        // ─────────────────────────────────────────────────────────
        // STEP 2: Deserialize bytes to TxEnvelope
        // ─────────────────────────────────────────────────────────
        let tx_envelope: crate::tx::TxEnvelope = bincode::deserialize(&tx_bytes)
            .map_err(|e| RpcError {
                code: -32602,
                message: format!("Invalid transaction format: {}", e),
            })?;

        // ─────────────────────────────────────────────────────────
        // STEP 3: Compute transaction ID before submission
        // ─────────────────────────────────────────────────────────
        let txid = match tx_envelope.compute_txid() {
            Ok(hash) => hash.to_hex(),
            Err(e) => {
                return Ok(SubmitTxRes {
                    success: false,
                    txid: String::new(),
                    message: format!("Failed to compute transaction ID: {}", e),
                });
            }
        };

        // ─────────────────────────────────────────────────────────
        // STEP 4: Submit to chain (all validation happens here)
        // ─────────────────────────────────────────────────────────
        match self.chain.submit_tx(tx_envelope) {
            Ok(()) => {
                Ok(SubmitTxRes {
                    success: true,
                    txid,
                    message: "Transaction accepted".to_string(),
                })
            }
            Err(e) => {
                Ok(SubmitTxRes {
                    success: false,
                    txid: String::new(),
                    message: e.to_string(),
                })
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // STAKING RPC METHODS (13.16.3)
    // ════════════════════════════════════════════════════════════════════════════
    // Staking query and transaction submission endpoints.
    // get_stake_info is READ-ONLY.
    // submit_* methods receive pre-built TxEnvelope and delegate to chain.submit_tx().
    // NO staking logic here - all validation in Chain.
    // ════════════════════════════════════════════════════════════════════════════

    /// Get staking information for an address (READ-ONLY)
    /// 
    /// # Arguments
    /// * `address` - Account address as hex string
    /// 
    /// # Returns
    /// * `StakeInfoRes` with validator stake, delegator stake, pending unstake, delegated_to
    /// 
    /// # Notes
    /// - READ-ONLY: Does not modify state
    /// - New/unknown addresses return all zeros and None
    pub fn get_stake_info(&self, address: String) -> Result<StakeInfoRes, RpcError> {
        // Parse address from hex string
        let addr = address.trim_start_matches("0x");
        let parsed_addr = Address::from_hex(addr).map_err(|e| RpcError {
            code: -32600,
            message: format!("invalid address format: {}", e),
        })?;

        // Read state (read-only lock)
        let state = self.chain.state.read();
        
        // Get validator stake (0 if not a validator)
        let validator_stake = state.validator_stakes
            .get(&parsed_addr)
            .copied()
            .unwrap_or(0);
        
        // Get delegator stake (0 if not delegating)
        let delegator_stake = state.delegator_stakes
            .get(&parsed_addr)
            .copied()
            .unwrap_or(0);
        
        // Get pending unstake amount (sum of all pending unstakes for this address)
        let pending_unstake: u128 = state.pending_unstakes
            .get(&parsed_addr)
            .map(|entries| entries.iter().map(|e| e.amount).sum())
            .unwrap_or(0);
        
        // Get delegated validator (None if not delegating)
        let delegated_to = state.delegator_to_validator
            .get(&parsed_addr)
            .map(|v| format!("0x{}", v.to_hex()));

        Ok(StakeInfoRes {
            address: format!("0x{}", addr),
            validator_stake: validator_stake.to_string(),
            delegator_stake: delegator_stake.to_string(),
            pending_unstake: pending_unstake.to_string(),
            delegated_to,
        })
    }

    /// Submit a stake transaction
    /// 
    /// # Arguments
    /// * `req` - StakeReq with hex-encoded pre-signed TxEnvelope
    /// 
    /// # Returns
    /// * `StakingOpRes` with transaction ID if accepted
    /// 
    /// # Notes
    /// - Expects pre-built and signed TxEnvelope as hex
    /// - All validation is delegated to Chain::submit_tx()
    pub fn submit_stake(&self, req: StakeReq) -> Result<StakingOpRes, RpcError> {
        // Decode hex to bytes
        let tx_bytes = hex::decode(&req.tx_envelope_hex).map_err(|e| RpcError {
            code: -32602,
            message: format!("Invalid transaction encoding: {}", e),
        })?;

        // Deserialize to TxEnvelope
        let tx_envelope: crate::tx::TxEnvelope = bincode::deserialize(&tx_bytes)
            .map_err(|e| RpcError {
                code: -32602,
                message: format!("Invalid transaction format: {}", e),
            })?;

        // Compute txid
        let txid = match tx_envelope.compute_txid() {
            Ok(hash) => hash.to_hex(),
            Err(e) => {
                return Ok(StakingOpRes {
                    success: false,
                    txid: String::new(),
                    message: format!("Failed to compute transaction ID: {}", e),
                });
            }
        };

        // Submit to chain
        match self.chain.submit_tx(tx_envelope) {
            Ok(()) => Ok(StakingOpRes {
                success: true,
                txid,
                message: "Stake transaction accepted".to_string(),
            }),
            Err(e) => Ok(StakingOpRes {
                success: false,
                txid: String::new(),
                message: e.to_string(),
            }),
        }
    }

    /// Submit a delegate transaction
    /// 
    /// # Arguments
    /// * `req` - DelegateReq with hex-encoded pre-signed TxEnvelope
    /// 
    /// # Returns
    /// * `StakingOpRes` with transaction ID if accepted
    /// 
    /// # Notes
    /// - Expects pre-built and signed TxEnvelope as hex
    /// - All validation is delegated to Chain::submit_tx()
    pub fn submit_delegate(&self, req: DelegateReq) -> Result<StakingOpRes, RpcError> {
        // Decode hex to bytes
        let tx_bytes = hex::decode(&req.tx_envelope_hex).map_err(|e| RpcError {
            code: -32602,
            message: format!("Invalid transaction encoding: {}", e),
        })?;

        // Deserialize to TxEnvelope
        let tx_envelope: crate::tx::TxEnvelope = bincode::deserialize(&tx_bytes)
            .map_err(|e| RpcError {
                code: -32602,
                message: format!("Invalid transaction format: {}", e),
            })?;

        // Compute txid
        let txid = match tx_envelope.compute_txid() {
            Ok(hash) => hash.to_hex(),
            Err(e) => {
                return Ok(StakingOpRes {
                    success: false,
                    txid: String::new(),
                    message: format!("Failed to compute transaction ID: {}", e),
                });
            }
        };

        // Submit to chain
        match self.chain.submit_tx(tx_envelope) {
            Ok(()) => Ok(StakingOpRes {
                success: true,
                txid,
                message: "Delegate transaction accepted".to_string(),
            }),
            Err(e) => Ok(StakingOpRes {
                success: false,
                txid: String::new(),
                message: e.to_string(),
            }),
        }
    }

    /// Submit an unstake transaction
    /// 
    /// # Arguments
    /// * `req` - UnstakeReq with hex-encoded pre-signed TxEnvelope
    /// 
    /// # Returns
    /// * `StakingOpRes` with transaction ID if accepted
    /// 
    /// # Notes
    /// - Expects pre-built and signed TxEnvelope as hex
    /// - All validation is delegated to Chain::submit_tx()
    /// - 7-day delay applies after acceptance
    pub fn submit_unstake(&self, req: UnstakeReq) -> Result<StakingOpRes, RpcError> {
        // Decode hex to bytes
        let tx_bytes = hex::decode(&req.tx_envelope_hex).map_err(|e| RpcError {
            code: -32602,
            message: format!("Invalid transaction encoding: {}", e),
        })?;

        // Deserialize to TxEnvelope
        let tx_envelope: crate::tx::TxEnvelope = bincode::deserialize(&tx_bytes)
            .map_err(|e| RpcError {
                code: -32602,
                message: format!("Invalid transaction format: {}", e),
            })?;

        // Compute txid
        let txid = match tx_envelope.compute_txid() {
            Ok(hash) => hash.to_hex(),
            Err(e) => {
                return Ok(StakingOpRes {
                    success: false,
                    txid: String::new(),
                    message: format!("Failed to compute transaction ID: {}", e),
                });
            }
        };

        // Submit to chain
        match self.chain.submit_tx(tx_envelope) {
            Ok(()) => Ok(StakingOpRes {
                success: true,
                txid,
                message: "Unstake transaction accepted".to_string(),
            }),
            Err(e) => Ok(StakingOpRes {
                success: false,
                txid: String::new(),
                message: e.to_string(),
            }),
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // FEE SPLIT & GAS ESTIMATION RPC METHODS (13.16.4)
    // ════════════════════════════════════════════════════════════════════════════
    // Fee transparency and gas estimation endpoints.
    // All methods are READ-ONLY and DETERMINISTIC.
    // Uses constants from internal_gas.rs and fee split rules from Blueprint.
    // ════════════════════════════════════════════════════════════════════════════

    /// Calculate fee split for a given resource class and total fee
    /// 
    /// # Arguments
    /// * `resource_class` - Resource class: "Storage", "Compute", "Transfer", "Governance"
    /// * `total_fee` - Total fee amount as decimal string
    /// 
    /// # Returns
    /// * `FeeSplitRes` with node_share, validator_share, treasury_share
    /// 
    /// # Fee Split Rules (Blueprint 70/20/10)
    /// - Storage/Compute: 70% Node, 20% Validator, 10% Treasury
    /// - Transfer/Governance/Stake: 0% Node, 100% Validator, 0% Treasury
    /// 
    /// # Notes
    /// - READ-ONLY: Does not modify state
    /// - Deterministic: Same input always produces same output
    pub fn get_fee_split(
        &self,
        resource_class: String,
        total_fee: String,
    ) -> Result<FeeSplitRes, RpcError> {
        // Parse total_fee
        let fee: u128 = total_fee.parse().map_err(|e| RpcError {
            code: -32602,
            message: format!("Invalid total_fee: {}", e),
        })?;

        // Calculate split based on resource class
        let (node_share, validator_share, treasury_share) = match resource_class.to_lowercase().as_str() {
            "storage" | "compute" => {
                // Blueprint 70/20/10
                let node = fee * 70 / 100;
                let validator = fee * 20 / 100;
                let treasury = fee - node - validator; // Remainder to treasury
                (node, validator, treasury)
            }
            "transfer" | "governance" | "stake" => {
                // 0/100/0 - All to validator
                (0u128, fee, 0u128)
            }
            _ => {
                return Err(RpcError {
                    code: -32602,
                    message: format!("Invalid resource_class: {}. Valid: Storage, Compute, Transfer, Governance", resource_class),
                });
            }
        };

        Ok(FeeSplitRes {
            resource_class,
            total_fee: fee.to_string(),
            node_share: node_share.to_string(),
            validator_share: validator_share.to_string(),
            treasury_share: treasury_share.to_string(),
        })
    }

    /// Estimate storage operation cost
    /// 
    /// # Arguments
    /// * `bytes` - Number of bytes to store
    /// * `node_address` - Optional node address for cost index lookup
    /// 
    /// # Returns
    /// * `StorageCostRes` with gas breakdown and total cost
    /// 
    /// # Formula
    /// ```text
    /// base_cost = BASE_OP_STORAGE_OP (50,000)
    /// byte_cost = bytes * PER_BYTE_COST (16)
    /// total_gas = ceil((base_cost + byte_cost) * node_multiplier / 100)
    /// total_cost = total_gas
    /// ```
    /// 
    /// # Notes
    /// - READ-ONLY: Does not modify state
    /// - Deterministic: Same input always produces same output
    pub fn estimate_storage_cost(
        &self,
        bytes: u64,
        node_address: Option<String>,
    ) -> Result<StorageCostRes, RpcError> {
        use crate::state::{BASE_OP_STORAGE_OP, PER_BYTE_COST, DEFAULT_NODE_COST_INDEX};

        // Parse node address if provided
        let node_addr = match node_address {
            Some(addr_str) => {
                let addr = addr_str.trim_start_matches("0x");
                Some(Address::from_hex(addr).map_err(|e| RpcError {
                    code: -32602,
                    message: format!("Invalid node_address: {}", e),
                })?)
            }
            None => None,
        };

        // Get node multiplier from state
        let state = self.chain.state.read();
        let node_multiplier: u128 = match &node_addr {
            Some(addr) => state.get_node_cost_index(addr),
            None => DEFAULT_NODE_COST_INDEX,
        };

        // Calculate costs
        let base_cost: u128 = BASE_OP_STORAGE_OP as u128;
        let byte_cost: u128 = (bytes as u128) * (PER_BYTE_COST as u128);
        let sum = base_cost + byte_cost;
        
        // Ceiling division: ceil(sum * multiplier / 100)
        let product = sum * node_multiplier;
        let total_gas = (product + 99) / 100;
        let total_cost = total_gas;

        Ok(StorageCostRes {
            bytes,
            base_cost: base_cost.to_string(),
            byte_cost: byte_cost.to_string(),
            node_multiplier: node_multiplier as u32,
            total_gas: total_gas.to_string(),
            total_cost: total_cost.to_string(),
        })
    }

    /// Estimate compute operation cost
    /// 
    /// # Arguments
    /// * `cycles` - Number of compute cycles
    /// * `node_address` - Optional node address for cost index lookup
    /// 
    /// # Returns
    /// * `ComputeCostRes` with gas breakdown and total cost
    /// 
    /// # Formula
    /// ```text
    /// base_cost = BASE_OP_COMPUTE_OP (100,000)
    /// cycle_cost = cycles * PER_COMPUTE_CYCLE_COST (1)
    /// total_gas = ceil((base_cost + cycle_cost) * node_multiplier / 100)
    /// total_cost = total_gas
    /// ```
    /// 
    /// # Notes
    /// - READ-ONLY: Does not modify state
    /// - Deterministic: Same input always produces same output
    pub fn estimate_compute_cost(
        &self,
        cycles: u64,
        node_address: Option<String>,
    ) -> Result<ComputeCostRes, RpcError> {
        use crate::state::{BASE_OP_COMPUTE_OP, PER_COMPUTE_CYCLE_COST, DEFAULT_NODE_COST_INDEX};

        // Parse node address if provided
        let node_addr = match node_address {
            Some(addr_str) => {
                let addr = addr_str.trim_start_matches("0x");
                Some(Address::from_hex(addr).map_err(|e| RpcError {
                    code: -32602,
                    message: format!("Invalid node_address: {}", e),
                })?)
            }
            None => None,
        };

        // Get node multiplier from state
        let state = self.chain.state.read();
        let node_multiplier: u128 = match &node_addr {
            Some(addr) => state.get_node_cost_index(addr),
            None => DEFAULT_NODE_COST_INDEX,
        };

        // Calculate costs
        let base_cost: u128 = BASE_OP_COMPUTE_OP as u128;
        let cycle_cost: u128 = (cycles as u128) * (PER_COMPUTE_CYCLE_COST as u128);
        let sum = base_cost + cycle_cost;
        
        // Ceiling division: ceil(sum * multiplier / 100)
        let product = sum * node_multiplier;
        let total_gas = (product + 99) / 100;
        let total_cost = total_gas;

        Ok(ComputeCostRes {
            cycles,
            base_cost: base_cost.to_string(),
            cycle_cost: cycle_cost.to_string(),
            node_multiplier: node_multiplier as u32,
            total_gas: total_gas.to_string(),
            total_cost: total_cost.to_string(),
        })
    }

    // ════════════════════════════════════════════════════════════════════════════
    // SNAPSHOT & CELESTIA RPC METHODS (13.16.6)
    // ════════════════════════════════════════════════════════════════════════════
    // State snapshot and DA layer status endpoints.
    // All methods are READ-ONLY.
    // Used by explorers, auditors, and monitoring systems.
    // ════════════════════════════════════════════════════════════════════════════

    /// Get current state snapshot summary
    /// 
    /// # Returns
    /// * `SnapshotRes` with height, state_root, account/validator counts, supply, etc.
    /// 
    /// # Notes
    /// - READ-ONLY: Does not modify state
    /// - Lightweight: No heavy iteration
    /// - Deterministic: Same state produces same snapshot
    pub fn get_snapshot(&self) -> Result<SnapshotRes, RpcError> {
        // Get chain tip
        let (height, _tip_hash) = self.chain.get_chain_tip().map_err(|e| RpcError {
            code: -32060,
            message: format!("Failed to get chain tip: {}", e),
        })?;

        // Read state (read-only lock)
        let state = self.chain.state.read();

        // Compute state root
        let state_root = match state.compute_state_root() {
            Ok(hash) => hash.to_hex(),
            Err(e) => {
                return Err(RpcError {
                    code: -32061,
                    message: format!("Failed to compute state root: {}", e),
                });
            }
        };

        // Count accounts with non-zero balance
        let total_accounts = state.balances.iter()
            .filter(|(_, &balance)| balance > 0)
            .count() as u64;

        // Count validators
        let total_validators = state.validators.len() as u64;

        // Get supply and treasury
        let total_supply = state.total_supply;
        let treasury_balance = state.treasury_balance;

        // Get epoch info
        let epoch = state.epoch_info.epoch_number;

        // Timestamp: use current time as approximation
        // In production, this would come from the last block header
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Ok(SnapshotRes {
            height,
            state_root,
            total_accounts,
            total_validators,
            total_supply: total_supply.to_string(),
            treasury_balance: treasury_balance.to_string(),
            epoch,
            timestamp,
        })
    }

    /// Get DSDN chain height and Celestia DA sync status
    /// 
    /// # Returns
    /// * `BlobHeightRes` with DSDN height, Celestia height, and sync status
    /// 
    /// # Notes
    /// - READ-ONLY: Does not modify state
    /// - Celestia info is optional (returns None if not configured)
    /// - Never panics even if Celestia is not active
    pub fn get_blob_height(&self) -> Result<BlobHeightRes, RpcError> {
        // Get DSDN chain tip
        let (dsdn_height, _) = self.chain.get_chain_tip().map_err(|e| RpcError {
            code: -32062,
            message: format!("Failed to get chain tip: {}", e),
        })?;

        // Get Celestia sync info from chain
        let celestia_height = self.chain.get_celestia_height();
        let last_sync_timestamp = self.chain.get_celestia_sync_timestamp();

        // Determine sync status
        let sync_status = if celestia_height.is_none() {
            "not_synced".to_string()
        } else if last_sync_timestamp.is_some() {
            // Check if sync is recent (within last 5 minutes)
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            
            let last_sync = last_sync_timestamp.unwrap_or(0);
            if now.saturating_sub(last_sync) < 300 {
                "synced".to_string()
            } else {
                "syncing".to_string()
            }
        } else {
            "syncing".to_string()
        };

        Ok(BlobHeightRes {
            dsdn_height,
            celestia_height,
            last_sync_timestamp,
            sync_status,
        })
    }

    // ════════════════════════════════════════════════════════════════════════════
    // WALLET RPC METHODS (13.17.8)
    // ════════════════════════════════════════════════════════════════════════════
    // Wallet operations exposed via RPC.
    // CRITICAL: Secret keys are NEVER stored by the server.
    // All signing is STATELESS - caller provides secret, server returns signed tx.
    // ════════════════════════════════════════════════════════════════════════════

    /// Generate a new wallet
    /// 
    /// Creates a new Ed25519 keypair and derives the blockchain address.
    /// 
    /// # Returns
    /// * `WalletGenerateRes` with address, public_key, and secret_key
    /// 
    /// # Security Notes
    /// - Secret key is returned ONCE and NOT stored by server
    /// - Caller MUST backup secret_key securely
    /// - Never log or display secret_key
    pub fn wallet_generate(&self) -> Result<WalletGenerateRes, RpcError> {
        use crate::wallet::Wallet;

        let wallet = Wallet::generate();

        Ok(WalletGenerateRes {
            address: format!("0x{}", hex::encode(wallet.address().as_bytes())),
            public_key: hex::encode(wallet.public_key()),
            secret_key: wallet.export_secret_hex(),
        })
    }

    /// Sign a transaction with provided secret key
    /// 
    /// # Arguments
    /// * `tx_hex` - Hex-encoded bincode serialized TxEnvelope (unsigned)
    /// * `secret_hex` - Hex-encoded Ed25519 secret key (64 hex chars)
    /// 
    /// # Returns
    /// * Hex-encoded signed TxEnvelope
    /// 
    /// # Security Notes
    /// - Secret key is NEVER stored or logged
    /// - All signing is stateless
    /// - Caller must protect their secret key
    pub fn wallet_sign_tx(
        &self,
        tx_hex: String,
        secret_hex: String,
    ) -> Result<String, RpcError> {
        use crate::wallet::Wallet;
        use crate::tx::TxEnvelope;
        use crate::crypto::sign_ed25519;

        // Decode secret key
        let secret_bytes = hex::decode(&secret_hex).map_err(|e| RpcError {
            code: -32602,
            message: format!("Invalid secret key hex: {}", e),
        })?;

        if secret_bytes.len() != 32 {
            return Err(RpcError {
                code: -32602,
                message: "Secret key must be 32 bytes (64 hex chars)".to_string(),
            });
        }

        let mut secret_arr = [0u8; 32];
        secret_arr.copy_from_slice(&secret_bytes);

        // Restore wallet from secret
        let wallet = Wallet::from_secret_key(&secret_arr);

        // Decode transaction
        let tx_bytes = hex::decode(&tx_hex).map_err(|e| RpcError {
            code: -32602,
            message: format!("Invalid transaction hex: {}", e),
        })?;

        let mut tx_envelope: TxEnvelope = bincode::deserialize(&tx_bytes).map_err(|e| RpcError {
            code: -32602,
            message: format!("Invalid transaction format: {}", e),
        })?;

        // Sign the payload
        let payload_bytes = bincode::serialize(&tx_envelope.payload).map_err(|e| RpcError {
            code: -32603,
            message: format!("Failed to serialize payload: {}", e),
        })?;

        // Get Ed25519PrivateKey from secret bytes
        use crate::crypto::Ed25519PrivateKey;
        let priv_key = Ed25519PrivateKey::from_bytes(&secret_arr).map_err(|e| RpcError {
            code: -32602,
            message: format!("Invalid secret key: {}", e),
        })?;

        let signature = sign_ed25519(&priv_key, &payload_bytes).map_err(|e| RpcError {
            code: -32603,
            message: format!("Signing failed: {}", e),
        })?;

        // Update envelope with signature and public key
        tx_envelope.signature = signature;
        tx_envelope.pubkey = wallet.public_key().to_vec();

        // Serialize and return
        let signed_bytes = bincode::serialize(&tx_envelope).map_err(|e| RpcError {
            code: -32603,
            message: format!("Failed to serialize signed tx: {}", e),
        })?;

        Ok(hex::encode(signed_bytes))
    }

    /// Get storage contract by ID
    /// 
    /// # Arguments
    /// * `contract_id` - Hex-encoded contract ID (128 hex chars = 64 bytes)
    /// 
    /// # Returns
    /// * `StorageContractRes` with contract details
    pub fn get_storage_contract(
        &self,
        contract_id: String,
    ) -> Result<StorageContractRes, RpcError> {
        use crate::types::Hash;
        use crate::state::StorageContractStatus;

        // Decode contract_id
        let id_bytes = hex::decode(&contract_id).map_err(|e| RpcError {
            code: -32602,
            message: format!("Invalid contract_id hex: {}", e),
        })?;

        if id_bytes.len() != 64 {
            return Err(RpcError {
                code: -32602,
                message: "Contract ID must be 64 bytes (128 hex chars)".to_string(),
            });
        }

        let mut id_arr = [0u8; 64];
        id_arr.copy_from_slice(&id_bytes);
        let hash = Hash::from_bytes(id_arr);

        // Query state
        let state = self.chain.state.read();
        let contract = state.storage_contracts.get(&hash).ok_or_else(|| RpcError {
            code: -32601,
            message: "Contract not found".to_string(),
        })?;

        // Format status
        let status_str = match contract.status {
            StorageContractStatus::Active => "Active",
            StorageContractStatus::GracePeriod => "GracePeriod",
            StorageContractStatus::Expired => "Expired",
            StorageContractStatus::Cancelled => "Cancelled",
        };

        Ok(StorageContractRes {
            contract_id,
            owner: format!("0x{}", hex::encode(contract.owner.as_bytes())),
            node: format!("0x{}", hex::encode(contract.node_address.as_bytes())),
            bytes: contract.storage_bytes,
            monthly_cost: contract.monthly_cost.to_string(),
            status: status_str.to_string(),
        })
    }

    /// Get all storage contracts for a user
    /// 
    /// # Arguments
    /// * `address` - Owner address (hex with or without 0x prefix)
    /// 
    /// # Returns
    /// * Vec of `StorageContractRes` for all user contracts
    pub fn get_user_contracts(
        &self,
        address: String,
    ) -> Result<Vec<StorageContractRes>, RpcError> {
        use crate::state::StorageContractStatus;

        // Parse address
        let addr_str = address.trim_start_matches("0x");
        let addr = Address::from_hex(addr_str).map_err(|e| RpcError {
            code: -32602,
            message: format!("Invalid address: {}", e),
        })?;

        // Query state
        let state = self.chain.state.read();
        
        // Get user's contract IDs
        let contract_ids = match state.user_contracts.get(&addr) {
            Some(ids) => ids.clone(),
            None => return Ok(Vec::new()),
        };

        // Resolve each contract
        let mut results = Vec::new();
        for hash in contract_ids {
            if let Some(contract) = state.storage_contracts.get(&hash) {
                let status_str = match contract.status {
                    StorageContractStatus::Active => "Active",
                    StorageContractStatus::GracePeriod => "GracePeriod",
                    StorageContractStatus::Expired => "Expired",
                    StorageContractStatus::Cancelled => "Cancelled",
                };

                results.push(StorageContractRes {
                    contract_id: hex::encode(hash.as_bytes()),
                    owner: format!("0x{}", hex::encode(contract.owner.as_bytes())),
                    node: format!("0x{}", hex::encode(contract.node_address.as_bytes())),
                    bytes: contract.storage_bytes,
                    monthly_cost: contract.monthly_cost.to_string(),
                    status: status_str.to_string(),
                });
            }
        }

        Ok(results)
    }

    /// Verify blob commitment (Celestia DA)
    /// 
    /// # Arguments
    /// * `blob_hex` - Hex-encoded blob data
    /// * `commitment_hex` - Hex-encoded commitment
    /// 
    /// # Returns
    /// * `BlobVerifyRes` with valid flag and message
    /// 
    /// # Notes
    /// - Uses Celestia commitment verification
    /// - READ-ONLY: Does not modify state
    pub fn verify_blob_commitment(
        &self,
        blob_hex: String,
        commitment_hex: String,
    ) -> Result<BlobVerifyRes, RpcError> {
        // Decode blob
        let blob = hex::decode(&blob_hex).map_err(|e| RpcError {
            code: -32602,
            message: format!("Invalid blob hex: {}", e),
        })?;

        // Decode commitment
        let commitment = hex::decode(&commitment_hex).map_err(|e| RpcError {
            code: -32602,
            message: format!("Invalid commitment hex: {}", e),
        })?;

        // Verify using Celestia client
        use crate::celestia::verify_blob_commitment;
        
        let commitment_arr: [u8; 32] = commitment
            .as_slice()
            .try_into()
            .map_err(|_| RpcError {
                code: -32602,
                message: "Commitment must be exactly 32 bytes".into(),
            })?;

        let valid = verify_blob_commitment(&blob, &commitment_arr);


        Ok(BlobVerifyRes {
            valid,
            message: if valid {
                "Blob matches commitment".to_string()
            } else {
                "Blob does NOT match commitment".to_string()
            },
        })
    }

    // ════════════════════════════════════════════════════════════════════════════
    // SNAPSHOT LIST & FAST SYNC RPC (13.18.7)
    // ════════════════════════════════════════════════════════════════════════════
    // RPC endpoints untuk snapshot listing, inspection, dan fast sync.
    //
    // KEAMANAN:
    // - Semua operasi eksplisit (tidak ada implicit behavior)
    // - Snapshot divalidasi sebelum digunakan
    // - Fast sync TIDAK bypass konsensus
    // ════════════════════════════════════════════════════════════════════════════

    /// Get list of all available snapshots
    /// 
    /// # Returns
    /// * `SnapshotListRes` with list of snapshots sorted by height ascending
    /// 
    /// # Notes
    /// - READ-ONLY: Does not modify state
    /// - Returns empty list if no snapshots exist
    /// - Invalid snapshots are filtered out at DB layer
    pub fn get_snapshot_list(&self) -> Result<SnapshotListRes, RpcError> {
        // Get snapshot base path from config
        let base_path = std::path::Path::new(&self.chain.snapshot_config.path);

        // List available snapshots (associated function)
        let snapshots = crate::db::ChainDb::list_available_snapshots(base_path)
            .map_err(|e| RpcError {
                code: -32070,
                message: format!("failed to list snapshots: {}", e),
            })?;

        // Convert to response type and sort by height ascending
        let mut snapshot_list: Vec<SnapshotMetadataRes> = snapshots
            .into_iter()
            .map(|m| SnapshotMetadataRes {
                height: m.height,
                state_root: m.state_root.to_hex(),
                timestamp: m.timestamp,
            })
            .collect();

        snapshot_list.sort_by(|a, b| a.height.cmp(&b.height));

        Ok(SnapshotListRes {
            snapshots: snapshot_list,
        })
    }

    /// Get metadata for a specific snapshot by height
    /// 
    /// # Arguments
    /// * `height` - Block height of snapshot to query
    /// 
    /// # Returns
    /// * `SnapshotMetadataRes` with snapshot details
    /// 
    /// # Errors
    /// * If no snapshot exists at given height
    /// 
    /// # Notes
    /// - READ-ONLY: Does not modify state
    /// - Does NOT fallback to other heights
    /// - Does NOT auto-create snapshot
    pub fn get_snapshot_metadata(
        &self,
        height: u64,
    ) -> Result<SnapshotMetadataRes, RpcError> {
        // Construct snapshot path
        let snapshot_path = format!(
            "{}/checkpoint_{}",
            self.chain.snapshot_config.path,
            height
        );
        let path = std::path::Path::new(&snapshot_path);

        // Read metadata (will fail if not exists)
        use crate::db::ChainDb;

        let metadata = ChainDb::read_snapshot_metadata(path)
            .map_err(|e| RpcError {
                code: -32071,
                message: format!("snapshot not found at height {}: {}", height, e),
            })?;


        Ok(SnapshotMetadataRes {
            height: metadata.height,
            state_root: metadata.state_root.to_hex(),
            timestamp: metadata.timestamp,
        })
    }

    /// Create a snapshot at current height
    /// 
    /// # Returns
    /// * `Ok(())` on success
    /// 
    /// # Notes
    /// - Creates snapshot at current chain tip
    /// - Respects retention policy (max_snapshots)
    /// - Blocks until snapshot is complete
    pub fn create_snapshot(&self) -> Result<(), RpcError> {
        use std::fs;
        use std::path::Path;
        use std::time::{SystemTime, UNIX_EPOCH};

        // ─────────────────────────────────────────────
        // 1. Get current chain tip
        // ─────────────────────────────────────────────
        let (tip_height, _) = self.chain.get_chain_tip().map_err(|e| RpcError {
            code: -32072,
            message: format!("failed to get chain tip: {}", e),
        })?;

        // ─────────────────────────────────────────────
        // 2. Prepare snapshot directory
        // ─────────────────────────────────────────────
        let snapshot_path = Path::new(&self.chain.snapshot_config.path)
            .join(format!("checkpoint_{}", tip_height));

        if snapshot_path.exists() {
            fs::remove_dir_all(&snapshot_path).map_err(|e| RpcError {
                code: -32073,
                message: format!("failed to clean existing snapshot dir: {}", e),
            })?;
        }

        fs::create_dir_all(&snapshot_path).map_err(|e| RpcError {
            code: -32074,
            message: format!("failed to create snapshot dir: {}", e),
        })?;

        // ─────────────────────────────────────────────
        // 3. CREATE SNAPSHOT (LMDB COPY)
        //    → SINGLE SOURCE OF TRUTH
        // ─────────────────────────────────────────────
        self.chain
            .db
            .create_snapshot(
                tip_height,
                Path::new(&self.chain.snapshot_config.path),
            )
            .map_err(|e| RpcError {
                code: -32075,
                message: format!("failed to create snapshot: {}", e),
            })?;

        // ─────────────────────────────────────────────
        // 4. Compute state root (READ-ONLY)
        // ─────────────────────────────────────────────
        let state_root = {
            let state = self.chain.state.read();
            state.compute_state_root().map_err(|e| RpcError {
                code: -32076,
                message: format!("failed to compute state root: {}", e),
            })?
        };

        // ─────────────────────────────────────────────
        // 5. Get block hash at snapshot height
        // ─────────────────────────────────────────────
        let block_hash = {
            let block = self
                .chain
                .db
                .get_block(tip_height)
                .map_err(|e| RpcError {
                    code: -32077,
                    message: format!("failed to get block: {}", e),
                })?
                .ok_or_else(|| RpcError {
                    code: -32078,
                    message: format!("block not found at height {}", tip_height),
                })?;

            crate::block::Block::compute_hash(&block.header)
        };

        // ─────────────────────────────────────────────
        // 6. Write snapshot metadata
        // ─────────────────────────────────────────────
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let metadata = crate::state::SnapshotMetadata {
            height: tip_height,
            state_root,
            timestamp,
            block_hash,
        };

        self.chain
            .db
            .write_snapshot_metadata(&snapshot_path, &metadata)
            .map_err(|e| RpcError {
                code: -32079,
                message: format!("failed to write snapshot metadata: {}", e),
            })?;

        // ─────────────────────────────────────────────
        // 7. Cleanup old snapshots
        // ─────────────────────────────────────────────
        let keep_count = self.chain.snapshot_config.max_snapshots as usize;

        self.chain
            .cleanup_old_snapshots(keep_count)
            .map_err(|e| RpcError {
                code: -32080,
                message: format!("failed to cleanup old snapshots: {}", e),
            })?;

        Ok(())
    }


    /// Initiate fast sync from a specific snapshot
    /// 
    /// # Arguments
    /// * `height` - Snapshot height to sync from
    /// 
    /// # Returns
    /// * `FastSyncStatusRes` indicating whether sync can start
    /// 
    /// # Notes
    /// - VALIDATES snapshot before use
    /// - Does NOT bypass consensus
    /// - Returns status only (actual sync may be async in future)
    /// 
    /// # Flow
    /// 1. Validate snapshot exists
    /// 2. Validate snapshot integrity (state_root match)
    /// 3. Load snapshot state
    /// 4. Replay blocks from snapshot to tip
    /// 5. Rebuild control-plane from Celestia
    pub fn fast_sync_from_snapshot(
        &self,
        height: u64,
    ) -> Result<FastSyncStatusRes, RpcError> {
        use crate::db::ChainDb;

        // ─────────────────────────────────────────────────────────
        // Construct snapshot path
        // ─────────────────────────────────────────────────────────
        let snapshot_path = format!(
            "{}/checkpoint_{}",
            self.chain.snapshot_config.path,
            height
        );
        let path = std::path::Path::new(&snapshot_path);

        // ─────────────────────────────────────────────────────────
        // Step 1: Read snapshot metadata (existence check)
        // ─────────────────────────────────────────────────────────
        let metadata = ChainDb::read_snapshot_metadata(path)
            .map_err(|e| RpcError {
                code: -32080,
                message: format!(
                    "snapshot not found at height {}: {}",
                    height, e
                ),
            })?;

        // ─────────────────────────────────────────────────────────
        // Step 2: Validate snapshot integrity
        // validate_snapshot -> Result<(), DbError>
        // Ok(())  = valid
        // Err(..) = invalid
        // ─────────────────────────────────────────────────────────
        ChainDb::validate_snapshot(path)
            .map_err(|e| RpcError {
                code: -32081,
                message: format!("snapshot validation failed: {}", e),
            })?;

        // ─────────────────────────────────────────────────────────
        // Step 3: Get current chain tip
        // ─────────────────────────────────────────────────────────
        let (tip_height, _) = self.chain.get_chain_tip()
            .map_err(|e| RpcError {
                code: -32082,
                message: format!("failed to get chain tip: {}", e),
            })?;

        // Prevent future snapshot usage
        if height > tip_height {
            return Ok(FastSyncStatusRes {
                started: false,
                from_height: height,
                message: format!(
                    "snapshot height {} is ahead of current tip {}",
                    height, tip_height
                ),
            });
        }

        // ─────────────────────────────────────────────────────────
        // Step 4: Load snapshot (SIDE EFFECT)
        // NOTE:
        // - load_snapshot DOES NOT return DB
        // - it mutates / initializes underlying storage
        // ─────────────────────────────────────────────────────────
        ChainDb::load_snapshot(path)
            .map_err(|e| RpcError {
                code: -32083,
                message: format!("failed to load snapshot: {}", e),
            })?;

        // ─────────────────────────────────────────────────────────
        // Step 5: Replay blocks from snapshot height to tip
        // ─────────────────────────────────────────────────────────
        if height < tip_height {
            self.chain
                .replay_blocks_from(height + 1, tip_height, None)
                .map_err(|e| RpcError {
                    code: -32084,
                    message: format!("block replay failed: {}", e),
                })?;
        }

        // ─────────────────────────────────────────────────────────
        // Done
        // ─────────────────────────────────────────────────────────
        Ok(FastSyncStatusRes {
            started: true,
            from_height: metadata.height,
            message: format!(
                "fast sync completed: loaded snapshot at height {}, replayed to {}",
                height, tip_height
            ),
        })
    }

    // ════════════════════════════════════════════════════════════════════════════
    // SERVICE NODE GATING RPC METHODS (14B.18)
    // ════════════════════════════════════════════════════════════════════════════
    // READ-ONLY endpoints for service node gating observability.
    // All methods acquire a read lock on ChainState, never a write lock.
    // No state mutation. No consensus impact.
    // ════════════════════════════════════════════════════════════════════════════

    /// Query stake information for a registered service node.
    ///
    /// # Arguments
    /// * `operator_hex` - Operator address as hex string (with or without 0x prefix)
    ///
    /// # Returns
    /// * `ServiceNodeStakeRes` with stake amount, class, and minimum check
    ///
    /// # Errors
    /// * -32600: Invalid address format
    /// * -32100: Service node not found
    ///
    /// # Notes
    /// - READ-ONLY: Does not modify state
    /// - Delegates to `crate::gating::query::get_stake_info`
    pub fn get_service_node_stake(&self, operator_hex: String) -> Result<ServiceNodeStakeRes, RpcError> {
        let addr = operator_hex.trim_start_matches("0x");
        let parsed_addr = Address::from_hex(addr).map_err(|e| RpcError {
            code: -32600,
            message: format!("invalid address format: {}", e),
        })?;

        let state = self.chain.state.read();
        let info = crate::gating::query::get_stake_info(&state, &parsed_addr)
            .ok_or_else(|| RpcError {
                code: -32100,
                message: format!("service node not found for operator 0x{}", addr),
            })?;

        Ok(ServiceNodeStakeRes {
            operator: format!("0x{}", parsed_addr.to_hex()),
            staked_amount: info.staked_amount.to_string(),
            class: node_class_to_string(info.class),
            meets_minimum: info.meets_minimum,
        })
    }

    /// Query class and minimum stake requirement for a registered service node.
    ///
    /// # Arguments
    /// * `operator_hex` - Operator address as hex string (with or without 0x prefix)
    ///
    /// # Returns
    /// * `ServiceNodeClassRes` with class and minimum stake required
    ///
    /// # Errors
    /// * -32600: Invalid address format
    /// * -32100: Service node not found
    ///
    /// # Notes
    /// - READ-ONLY: Does not modify state
    /// - Delegates to `crate::gating::query::get_service_node_class`
    pub fn get_service_node_class(&self, operator_hex: String) -> Result<ServiceNodeClassRes, RpcError> {
        let addr = operator_hex.trim_start_matches("0x");
        let parsed_addr = Address::from_hex(addr).map_err(|e| RpcError {
            code: -32600,
            message: format!("invalid address format: {}", e),
        })?;

        let state = self.chain.state.read();
        let class = crate::gating::query::get_service_node_class(&state, &parsed_addr)
            .ok_or_else(|| RpcError {
                code: -32100,
                message: format!("service node not found for operator 0x{}", addr),
            })?;

        Ok(ServiceNodeClassRes {
            operator: format!("0x{}", parsed_addr.to_hex()),
            class: node_class_to_string(class),
            min_stake_required: min_stake_display(class).to_string(),
        })
    }

    /// Query slashing and cooldown status for a registered service node.
    ///
    /// # Arguments
    /// * `operator_hex` - Operator address as hex string (with or without 0x prefix)
    ///
    /// # Returns
    /// * `ServiceNodeSlashingRes` with slashing and cooldown information
    ///
    /// # Errors
    /// * -32600: Invalid address format
    /// * -32100: Service node not found
    ///
    /// # Notes
    /// - READ-ONLY: Does not modify state
    /// - Delegates to `crate::gating::query::get_service_node_slashing_status`
    /// - Uses current system time for cooldown evaluation
    pub fn get_service_node_slashing_status(&self, operator_hex: String) -> Result<ServiceNodeSlashingRes, RpcError> {
        let addr = operator_hex.trim_start_matches("0x");
        let parsed_addr = Address::from_hex(addr).map_err(|e| RpcError {
            code: -32600,
            message: format!("invalid address format: {}", e),
        })?;

        let current_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let state = self.chain.state.read();
        let info = crate::gating::query::get_service_node_slashing_status(
            &state, &parsed_addr, current_timestamp,
        ).ok_or_else(|| RpcError {
            code: -32100,
            message: format!("service node not found for operator 0x{}", addr),
        })?;

        Ok(ServiceNodeSlashingRes {
            operator: format!("0x{}", parsed_addr.to_hex()),
            is_slashed: info.is_slashed,
            cooldown_active: info.cooldown_active,
            cooldown_remaining_secs: info.cooldown_remaining_secs,
            slash_count: info.slash_count,
        })
    }

    /// Query full information for a registered service node.
    ///
    /// # Arguments
    /// * `operator_hex` - Operator address as hex string (with or without 0x prefix)
    ///
    /// # Returns
    /// * `ServiceNodeInfoRes` with complete node information
    ///
    /// # Errors
    /// * -32600: Invalid address format
    /// * -32100: Service node not found
    ///
    /// # Notes
    /// - READ-ONLY: Does not modify state
    /// - Direct lookup in `state.service_nodes`
    pub fn get_service_node_info(&self, operator_hex: String) -> Result<ServiceNodeInfoRes, RpcError> {
        let addr = operator_hex.trim_start_matches("0x");
        let parsed_addr = Address::from_hex(addr).map_err(|e| RpcError {
            code: -32600,
            message: format!("invalid address format: {}", e),
        })?;

        let state = self.chain.state.read();
        let record = state.service_nodes.get(&parsed_addr)
            .ok_or_else(|| RpcError {
                code: -32100,
                message: format!("service node not found for operator 0x{}", addr),
            })?;

        Ok(record_to_info_res(record))
    }

    /// List all active service nodes.
    ///
    /// # Returns
    /// * `Vec<ServiceNodeInfoRes>` — all nodes with `status == Active`,
    ///   sorted by operator address ascending (deterministic ordering)
    ///
    /// # Notes
    /// - READ-ONLY: Does not modify state
    /// - Filters `state.service_nodes` for `NodeStatus::Active`
    /// - Sorting by operator address bytes guarantees deterministic response
    pub fn list_active_service_nodes(&self) -> Vec<ServiceNodeInfoRes> {
        let state = self.chain.state.read();

        let mut active: Vec<_> = state.service_nodes
            .values()
            .filter(|record| record.status == dsdn_common::gating::NodeStatus::Active)
            .collect();

        // Deterministic ordering: sort by operator address bytes ascending
        active.sort_by(|a, b| a.operator_address.as_bytes().cmp(b.operator_address.as_bytes()));

        active.iter().map(|record| record_to_info_res(record)).collect()
    }

    // ════════════════════════════════════════════════════════════════════════════
    // SERVICE NODE QUARANTINE & BAN STATUS (14B.58)
    // ════════════════════════════════════════════════════════════════════════════
    // READ-ONLY endpoints for quarantine and ban observability.
    // Combines data from state.service_nodes (status, class, stake) and
    // state.node_liveness_records (slashing flags, force_unbond_until).
    // No state mutation. No consensus impact.
    // ════════════════════════════════════════════════════════════════════════════

    /// Query quarantine status for a registered service node.
    ///
    /// # Arguments
    /// * `operator_hex` - Operator address as hex string (with or without 0x prefix)
    ///
    /// # Returns
    /// * `QuarantineStatusRes` with quarantine details and recovery eligibility
    ///
    /// # Errors
    /// * -32600: Invalid address format
    /// * -32100: Service node not found
    ///
    /// # Notes
    /// - READ-ONLY: Does not modify state
    /// - Dual lookup: service_nodes for status/stake, node_liveness_records for flags
    /// - Reason derived from liveness flags (may be None if no liveness record)
    /// - since_timestamp approximated from liveness last_seen_timestamp
    pub fn get_quarantine_status(&self, operator_hex: String) -> Result<QuarantineStatusRes, RpcError> {
        let addr = operator_hex.trim_start_matches("0x");
        let parsed_addr = Address::from_hex(addr).map_err(|e| RpcError {
            code: -32600,
            message: format!("invalid address format: {}", e),
        })?;

        let current_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let state = self.chain.state.read();

        // Primary lookup: service node record
        let record = state.service_nodes.get(&parsed_addr)
            .ok_or_else(|| RpcError {
                code: -32100,
                message: format!("service node not found for operator 0x{}", addr),
            })?;

        let is_quarantined = record.status == dsdn_common::gating::NodeStatus::Quarantined;
        let class_min = min_stake_display(record.class);
        let current_stake: u128 = record.staked_amount;
        let can_recover = current_stake >= class_min;

        // Secondary lookup: liveness record for reason and timestamps
        let (reason, since_timestamp) = match state.node_liveness_records.get(&parsed_addr) {
            Some(liveness) => {
                let reason_str = if liveness.slashed {
                    if liveness.double_sign_detected {
                        Some("DoubleSigning".to_string())
                    } else if liveness.malicious_block_detected {
                        Some("MaliciousBlock".to_string())
                    } else if liveness.data_corruption_count > 0 {
                        Some("DataCorruption".to_string())
                    } else if liveness.consecutive_failures > 0 {
                        Some("LivenessFailure".to_string())
                    } else if liveness.malicious_behavior_count > 0 {
                        Some("MaliciousBehavior".to_string())
                    } else {
                        Some("Unknown".to_string())
                    }
                } else {
                    None
                };
                let since = if is_quarantined {
                    Some(liveness.last_seen_timestamp)
                } else {
                    None
                };
                (reason_str, since)
            }
            None => (None, None),
        };

        let duration_secs = match since_timestamp {
            Some(since) if is_quarantined => {
                Some(current_timestamp.saturating_sub(since))
            }
            _ => None,
        };

        Ok(QuarantineStatusRes {
            operator: format!("0x{}", parsed_addr.to_hex()),
            is_quarantined,
            reason,
            since_timestamp,
            duration_secs,
            current_stake: current_stake.to_string(),
            required_stake: class_min.to_string(),
            can_recover,
        })
    }

    /// Query ban status for a registered service node.
    ///
    /// # Arguments
    /// * `operator_hex` - Operator address as hex string (with or without 0x prefix)
    ///
    /// # Returns
    /// * `BanStatusRes` with ban details and cooldown information
    ///
    /// # Errors
    /// * -32600: Invalid address format
    /// * -32100: Service node not found
    ///
    /// # Notes
    /// - READ-ONLY: Does not modify state
    /// - Dual lookup: service_nodes for status, node_liveness_records for flags/cooldown
    /// - cooldown_until from force_unbond_until (None if no liveness record)
    /// - cooldown_remaining computed from current system time
    pub fn get_ban_status(&self, operator_hex: String) -> Result<BanStatusRes, RpcError> {
        let addr = operator_hex.trim_start_matches("0x");
        let parsed_addr = Address::from_hex(addr).map_err(|e| RpcError {
            code: -32600,
            message: format!("invalid address format: {}", e),
        })?;

        let current_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let state = self.chain.state.read();

        // Primary lookup: service node record
        let record = state.service_nodes.get(&parsed_addr)
            .ok_or_else(|| RpcError {
                code: -32100,
                message: format!("service node not found for operator 0x{}", addr),
            })?;

        let is_banned = record.status == dsdn_common::gating::NodeStatus::Banned;

        // Secondary lookup: liveness record for reason and cooldown
        let (reason, banned_since, cooldown_until) = match state.node_liveness_records.get(&parsed_addr) {
            Some(liveness) => {
                let reason_str = if liveness.slashed {
                    if liveness.double_sign_detected {
                        Some("DoubleSigning".to_string())
                    } else if liveness.malicious_block_detected {
                        Some("MaliciousBlock".to_string())
                    } else if liveness.data_corruption_count > 0 {
                        Some("DataCorruption".to_string())
                    } else if liveness.consecutive_failures > 0 {
                        Some("LivenessFailure".to_string())
                    } else if liveness.malicious_behavior_count > 0 {
                        Some("MaliciousBehavior".to_string())
                    } else {
                        Some("Unknown".to_string())
                    }
                } else {
                    None
                };
                let since = if is_banned {
                    Some(liveness.last_seen_timestamp)
                } else {
                    None
                };
                (reason_str, since, liveness.force_unbond_until)
            }
            None => (None, None, None),
        };

        // Compute cooldown remaining
        let cooldown_remaining_secs = match cooldown_until {
            Some(until) if is_banned && current_timestamp < until => {
                until.saturating_sub(current_timestamp)
            }
            _ => 0,
        };

        Ok(BanStatusRes {
            operator: format!("0x{}", parsed_addr.to_hex()),
            is_banned,
            reason,
            banned_since,
            cooldown_until,
            cooldown_remaining_secs,
        })
    }

    // ════════════════════════════════════════════════════════════════════════════
    // SERVICE NODE REGISTRATION (14B.54)
    // ════════════════════════════════════════════════════════════════════════════
    // Builds, signs, and submits a RegisterServiceNode transaction.
    // Combines the roles of wallet_sign_tx + submit_tx into one call.
    //
    // SECURITY:
    // - Secret key is used for signing then immediately dropped.
    // - No secret key stored, logged, or persisted.
    // - Follows wallet_sign_tx (13.17.8) pattern exactly.
    //
    // FLOW:
    // 1. Parse and validate all input fields.
    // 2. Look up nonce from chain state.
    // 3. Build TxPayload::RegisterServiceNode.
    // 4. Create unsigned TxEnvelope.
    // 5. Sign with provided wallet secret.
    // 6. Submit via chain.submit_tx().
    // 7. Return SubmitTxRes with txid.
    // ════════════════════════════════════════════════════════════════════════════

    /// Register a service node on-chain.
    ///
    /// Builds `TxPayload::RegisterServiceNode`, signs with the provided
    /// wallet secret key, and submits the transaction to the mempool.
    ///
    /// # Arguments
    /// * `req` - Registration request with all required fields.
    ///
    /// # Returns
    /// * `SubmitTxRes` with `success=true` and `txid` if accepted.
    /// * `SubmitTxRes` with `success=false` and error message if rejected.
    ///
    /// # Errors
    /// * `-32602`: Invalid input (bad hex, wrong length, unknown class).
    /// * `-32603`: Internal signing or serialization error.
    ///
    /// # Security Notes
    /// - `secret_hex` is NEVER stored or logged.
    /// - Wallet is reconstructed in-memory, used once, then dropped.
    /// - Follows the same security model as `wallet_sign_tx`.
    pub fn register_service_node(
        &self,
        req: RegisterServiceNodeReq,
    ) -> Result<SubmitTxRes, RpcError> {
        use crate::wallet::Wallet;
        use crate::tx::{TxEnvelope, TxPayload};
        use dsdn_common::gating::NodeClass;

        // ─────────────────────────────────────────────────────────
        // STEP 1: Parse operator address
        // ─────────────────────────────────────────────────────────
        let addr_str = req.operator_hex.trim_start_matches("0x");
        let from = Address::from_hex(addr_str).map_err(|e| RpcError {
            code: -32602,
            message: format!("invalid operator address: {}", e),
        })?;

        // ─────────────────────────────────────────────────────────
        // STEP 2: Parse node_id (must be 32 bytes)
        // ─────────────────────────────────────────────────────────
        let node_id = hex::decode(&req.node_id_hex).map_err(|e| RpcError {
            code: -32602,
            message: format!("invalid node_id hex: {}", e),
        })?;
        if node_id.len() != 32 {
            return Err(RpcError {
                code: -32602,
                message: format!(
                    "node_id must be exactly 32 bytes, got {}",
                    node_id.len(),
                ),
            });
        }

        // ─────────────────────────────────────────────────────────
        // STEP 3: Parse node class
        // ─────────────────────────────────────────────────────────
        let class = match req.class.to_lowercase().as_str() {
            "storage" => NodeClass::Storage,
            "compute" => NodeClass::Compute,
            _ => {
                return Err(RpcError {
                    code: -32602,
                    message: format!(
                        "invalid class '{}': must be 'storage' or 'compute'",
                        req.class,
                    ),
                });
            }
        };

        // ─────────────────────────────────────────────────────────
        // STEP 4: Parse TLS fingerprint (must be 32 bytes)
        // ─────────────────────────────────────────────────────────
        let tls_fingerprint = hex::decode(&req.tls_fingerprint_hex).map_err(|e| RpcError {
            code: -32602,
            message: format!("invalid tls_fingerprint hex: {}", e),
        })?;
        if tls_fingerprint.len() != 32 {
            return Err(RpcError {
                code: -32602,
                message: format!(
                    "tls_fingerprint must be exactly 32 bytes, got {}",
                    tls_fingerprint.len(),
                ),
            });
        }

        // ─────────────────────────────────────────────────────────
        // STEP 5: Parse identity proof signature (must be 64 bytes)
        // ─────────────────────────────────────────────────────────
        let identity_proof_sig = hex::decode(&req.identity_proof_sig_hex).map_err(|e| RpcError {
            code: -32602,
            message: format!("invalid identity_proof_sig hex: {}", e),
        })?;
        if identity_proof_sig.len() != 64 {
            return Err(RpcError {
                code: -32602,
                message: format!(
                    "identity_proof_sig must be exactly 64 bytes, got {}",
                    identity_proof_sig.len(),
                ),
            });
        }

        // ─────────────────────────────────────────────────────────
        // STEP 6: Parse fee
        // ─────────────────────────────────────────────────────────
        let fee: u128 = req.fee.parse().map_err(|e| RpcError {
            code: -32602,
            message: format!("invalid fee '{}': {}", req.fee, e),
        })?;

        // ─────────────────────────────────────────────────────────
        // STEP 7: Parse wallet secret key (must be 32 bytes)
        // ─────────────────────────────────────────────────────────
        let secret_bytes = hex::decode(&req.secret_hex).map_err(|e| RpcError {
            code: -32602,
            message: format!("invalid secret key hex: {}", e),
        })?;
        if secret_bytes.len() != 32 {
            return Err(RpcError {
                code: -32602,
                message: "secret key must be 32 bytes (64 hex chars)".to_string(),
            });
        }
        let mut secret_arr = [0u8; 32];
        secret_arr.copy_from_slice(&secret_bytes);
        let wallet = Wallet::from_secret_key(&secret_arr);

        // ─────────────────────────────────────────────────────────
        // STEP 8: Get nonce from chain state
        // ─────────────────────────────────────────────────────────
        let nonce = {
            let state = self.chain.state.read();
            state.get_nonce(&from)
        };

        // ─────────────────────────────────────────────────────────
        // STEP 9: Build TxPayload::RegisterServiceNode
        // ─────────────────────────────────────────────────────────
        let payload = TxPayload::RegisterServiceNode {
            from,
            node_id,
            class,
            tls_fingerprint,
            identity_proof_sig,
            fee,
            nonce,
            gas_limit: 21_000, // MIN_GAS_LIMIT from tx.rs
        };

        // ─────────────────────────────────────────────────────────
        // STEP 10: Create unsigned envelope and sign
        // ─────────────────────────────────────────────────────────
        let tx = TxEnvelope::new_unsigned(payload);
        let signed_tx = wallet.sign_tx(&tx).map_err(|e| RpcError {
            code: -32603,
            message: format!("transaction signing failed: {}", e),
        })?;

        // ─────────────────────────────────────────────────────────
        // STEP 11: Compute txid
        // ─────────────────────────────────────────────────────────
        let txid = match signed_tx.compute_txid() {
            Ok(hash) => hash.to_hex(),
            Err(e) => {
                return Ok(SubmitTxRes {
                    success: false,
                    txid: String::new(),
                    message: format!("failed to compute transaction ID: {}", e),
                });
            }
        };

        // ─────────────────────────────────────────────────────────
        // STEP 12: Submit to chain
        // ─────────────────────────────────────────────────────────
        match self.chain.submit_tx(signed_tx) {
            Ok(()) => {
                Ok(SubmitTxRes {
                    success: true,
                    txid,
                    message: "Transaction accepted".to_string(),
                })
            }
            Err(e) => {
                Ok(SubmitTxRes {
                    success: false,
                    txid: String::new(),
                    message: e.to_string(),
                })
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // P2P NETWORK RPC ENDPOINTS (Tahap 21 v2)
    // ════════════════════════════════════════════════════════════════════════

    /// Get P2P network status overview.
    ///
    /// Returns role, connection counts, health status, and bootstrap state.
    pub fn p2p_status(&self) -> P2pStatusRes {
        let mgr = self.chain.peer_manager.read();
        let missing = mgr.missing_required_roles();
        P2pStatusRes {
            role: mgr.our_role.to_string(),
            node_class: mgr.our_node_class.map(|c| c.to_string()),
            connected_count: mgr.connected_count(),
            known_count: mgr.store.count(),
            all_required_met: missing.is_empty(),
            missing_required: missing.iter().map(|r| r.to_string()).collect(),
            bootstrap_state: format!("{:?}", mgr.bootstrap_state),
        }
    }

    /// Get list of connected P2P peers with role and class info.
    pub fn p2p_peers(&self) -> Vec<P2pPeerRes> {
        let mgr = self.chain.peer_manager.read();
        mgr.get_connected_peers()
            .iter()
            .map(|p| P2pPeerRes {
                address: p.addr.to_string(),
                node_id: p.node_id.to_string(),
                role: p.role.to_string(),
                node_class: p.node_class.map(|c| c.to_string()),
                score: p.score,
                success_count: p.success_count,
                failure_count: p.failure_count,
                source: format!("{:?}", p.source),
            })
            .collect()
    }

    /// Add a peer manually via RPC.
    ///
    /// * `addr` — Socket address string "IP:PORT" (e.g. "203.0.113.50:45831")
    pub fn p2p_add_peer(&self, addr: String) -> Result<(), RpcError> {
        self.chain.add_peer_p2p(&addr)
            .map_err(|e| RpcError {
                code: -32000,
                message: format!("Failed to add peer: {}", e),
            })
    }

    /// Get role dependency health matrix.
    ///
    /// Shows which roles are REQUIRED/OPTIONAL/SKIP for this node,
    /// how many connected peers exist per role, and overall health.
    pub fn p2p_role_health(&self) -> P2pRoleHealthRes {
        let mgr = self.chain.peer_manager.read();
        let missing = mgr.missing_required_roles();

        use crate::p2p::RoleDependency;

        let roles: Vec<P2pRoleHealthEntry> = mgr.role_health()
            .into_iter()
            .map(|(role, dep, count)| {
                let dep_str = match dep {
                    RoleDependency::Required => "REQUIRED",
                    RoleDependency::Optional => "OPTIONAL",
                    RoleDependency::Skip => "SKIP",
                };
                let status = match dep {
                    RoleDependency::Required => {
                        if count > 0 { "OK" } else { "MISSING" }
                    }
                    RoleDependency::Optional => {
                        if count > 0 { "OK" } else { "NONE" }
                    }
                    RoleDependency::Skip => "SKIP",
                };
                P2pRoleHealthEntry {
                    role: role.to_string(),
                    dependency: dep_str.to_string(),
                    connected_count: count,
                    status: status.to_string(),
                }
            })
            .collect();

        P2pRoleHealthRes {
            our_role: mgr.our_role.to_string(),
            our_class: mgr.our_node_class.map(|c| c.to_string()),
            all_required_met: missing.is_empty(),
            roles,
        }
    }

    /// Get peer store statistics (role/class/source breakdown).
    pub fn p2p_store_stats(&self) -> P2pStoreStatsRes {
        let stats = self.chain.p2p_store_stats();
        P2pStoreStatsRes {
            total: stats.total,
            connected: stats.connected,
            disconnected: stats.disconnected,
            banned: stats.banned,
            role_storage_compute: stats.role_storage_compute,
            class_reguler: stats.class_reguler,
            class_datacenter: stats.class_datacenter,
            role_validator: stats.role_validator,
            role_coordinator: stats.role_coordinator,
            from_dns: stats.from_dns,
            from_static: stats.from_static,
            from_pex: stats.from_pex,
            from_inbound: stats.from_inbound,
            from_manual: stats.from_manual,
            from_cache: stats.from_cache,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// SERVICE NODE RPC HELPERS (14B.18)
// ════════════════════════════════════════════════════════════════════════════
// Display-only helpers for service node RPC response formatting.
// These do NOT implement consensus logic — they format existing data for
// JSON-RPC consumers (wallets, explorers, dashboards).
// ════════════════════════════════════════════════════════════════════════════

/// Convert `NodeClass` to display string.
///
/// Explicit match — no wildcard — adding a new variant forces a compile error.
fn node_class_to_string(class: dsdn_common::gating::NodeClass) -> String {
    match class {
        dsdn_common::gating::NodeClass::Storage => "Storage".to_string(),
        dsdn_common::gating::NodeClass::Compute => "Compute".to_string(),
    }
}

/// Convert `NodeStatus` to display string.
///
/// Explicit match — no wildcard — adding a new variant forces a compile error.
fn node_status_to_string(status: dsdn_common::gating::NodeStatus) -> String {
    match status {
        dsdn_common::gating::NodeStatus::Pending => "Pending".to_string(),
        dsdn_common::gating::NodeStatus::Active => "Active".to_string(),
        dsdn_common::gating::NodeStatus::Quarantined => "Quarantined".to_string(),
        dsdn_common::gating::NodeStatus::Banned => "Banned".to_string(),
    }
}

/// Return minimum stake for a NodeClass (display only, not consensus).
///
/// Values MUST be kept in sync with `crate::gating::query` constants.
/// These are protocol constants, not state-derived values.
fn min_stake_display(class: dsdn_common::gating::NodeClass) -> u128 {
    match class {
        dsdn_common::gating::NodeClass::Storage => 5_000,
        dsdn_common::gating::NodeClass::Compute => 500,
    }
}

/// Convert a `ServiceNodeRecord` reference to `ServiceNodeInfoRes`.
///
/// Pure function. No allocation beyond response struct construction.
fn record_to_info_res(record: &crate::gating::ServiceNodeRecord) -> ServiceNodeInfoRes {
    ServiceNodeInfoRes {
        operator: format!("0x{}", record.operator_address.to_hex()),
        node_id_hex: hex::encode(record.node_id),
        class: node_class_to_string(record.class),
        status: node_status_to_string(record.status),
        staked_amount: record.staked_amount.to_string(),
        registered_height: record.registered_height,
        tls_fingerprint_hex: record.tls_fingerprint.map(hex::encode),
    }
}

// ============================================================
// HELPER FUNCTIONS FOR NETWORK SYNC
// ============================================================

/// Validate incoming block before full processing
/// Returns Ok(()) if basic validation passes
pub fn validate_incoming_block(
    block: &Block,
    expected_parent: &Hash,
    expected_height: u64,
) -> Result<(), String> {
    // Check height
    if block.header.height != expected_height {
        return Err(format!(
            "height mismatch: expected {}, got {}",
            expected_height, block.header.height
        ));
    }

    // Check parent hash
    if &block.header.parent_hash != expected_parent {
        return Err(format!(
            "parent hash mismatch: expected {}, got {}",
            expected_parent, block.header.parent_hash
        ));
    }

    // Check signature
    match block.verify_signature() {
        Ok(true) => Ok(()),
        Ok(false) => Err("invalid block signature".to_string()),
        Err(e) => Err(format!("signature verification error: {}", e)),
    }
}

/// Serialize block for network transmission
pub fn serialize_block_for_network(block: &Block) -> Result<String, String> {
    let bytes = bincode::serialize(block)
        .map_err(|e| format!("serialization error: {}", e))?;
    Ok(hex::encode(bytes))
}

pub fn deserialize_block_from_network(hex_data: &str) -> Result<Block, String> {
    let bytes = hex::decode(hex_data)
        .map_err(|e| format!("hex decode error: {}", e))?;
    bincode::deserialize(&bytes)
        .map_err(|e| format!("deserialization error: {}", e))
}

// ============================================================
// BROADCAST MANAGER (13.7.N)
// ============================================================

/// Manages block broadcasting to network peers
pub struct BroadcastManager {
    /// List of connected peers
    peers: Arc<RwLock<Vec<PeerInfo>>>,
    /// Local chain reference for receiving blocks
    #[allow(dead_code)]
    chain: Option<Chain>,
}

impl BroadcastManager {
    pub fn new() -> Self {
        Self {
            peers: Arc::new(RwLock::new(Vec::new())),
            chain: None,
        }
    }

    pub fn with_chain(chain: Chain) -> Self {
        Self {
            peers: Arc::new(RwLock::new(Vec::new())),
            chain: Some(chain),
        }
    }

    /// Register a new peer
    pub fn add_peer(&self, peer: PeerInfo) {
        if let Ok(mut peers) = self.peers.write() {
            // Avoid duplicates
            if !peers.iter().any(|p| p.id == peer.id) {
                println!("📡 Peer registered: {} ({})", peer.id, peer.address);
                peers.push(peer);
            }
        }
    }

    /// Remove a peer
    pub fn remove_peer(&self, peer_id: &str) {
        if let Ok(mut peers) = self.peers.write() {
            peers.retain(|p| p.id != peer_id);
            println!("📡 Peer removed: {}", peer_id);
        }
    }

    /// Get list of all peers
    pub fn get_peers(&self) -> Vec<PeerInfo> {
        self.peers.read().map(|p| p.clone()).unwrap_or_default()
    }

    /// Get count of connected peers
    pub fn peer_count(&self) -> usize {
        self.peers.read().map(|p| p.len()).unwrap_or(0)
    }
}

/// Broadcast a newly mined block to all connected peers
/// 
/// This is called by validators after successfully mining a block.
/// For now this is a stub that simulates the broadcast.
/// 
/// In production, this would:
/// 1. Serialize block to wire format
/// 2. Send to all connected full nodes via P2P/RPC
/// 3. Handle acknowledgements
pub fn broadcast_block(block: &Block, peers: &[PeerInfo]) -> Vec<BroadcastResult> {
    let block_hash = Block::compute_hash(&block.header);
    let height = block.header.height;
    
    println!("═══════════════════════════════════════════════════════════");
    println!("📡 BROADCASTING BLOCK (13.7.N)");
    println!("   Height: {}", height);
    println!("   Hash: {}", block_hash);
    println!("   Proposer: {}", block.header.proposer);
    println!("   Target peers: {}", peers.len());
    println!("═══════════════════════════════════════════════════════════");

    let mut results = Vec::new();

    if peers.is_empty() {
        println!("   ⚠️  No peers connected, block not broadcast");
        return results;
    }

    // Serialize block for transmission
    let block_data = match serialize_block_for_network(block) {
        Ok(data) => data,
        Err(e) => {
            println!("   ❌ Failed to serialize block: {}", e);
            return results;
        }
    };

    // Simulate sending to each peer
    for peer in peers {
        // In production: actual RPC/P2P call here
        let result = simulate_send_to_peer(peer, &block_data, height);
        
        if result.success {
            println!("   ✅ Sent to peer {}: {}", peer.id, result.message);
        } else {
            println!("   ❌ Failed for peer {}: {}", peer.id, result.message);
        }
        
        results.push(result);
    }

    let success_count = results.iter().filter(|r| r.success).count();
    println!("───────────────────────────────────────────────────────────");
    println!("   Broadcast complete: {}/{} peers received block", 
             success_count, peers.len());
    println!("═══════════════════════════════════════════════════════════");

    results
}

/// Simulate sending block to a peer (stub for P2P layer)
fn simulate_send_to_peer(peer: &PeerInfo, _block_data: &str, height: u64) -> BroadcastResult {
    // TODO: Replace with actual P2P/RPC implementation
    // For now, simulate successful delivery
    
    BroadcastResult {
        peer_id: peer.id.clone(),
        success: true,
        message: format!("block {} queued for delivery to {}", height, peer.address),
    }
}

/// Receive a block from a validator (called by full nodes)
/// 
/// This function:
/// 1. Deserializes the block
/// 2. Performs basic validation
/// 3. Applies block without mining (delegates to Chain)
pub fn receive_block(chain: &Chain, req: ReceiveBlockReq) -> Result<ReceiveBlockRes, RpcError> {
    println!("═══════════════════════════════════════════════════════════");
    println!("📥 RECEIVING BLOCK (13.7.N)");
    println!("   From validator: {}", req.from_validator);
    println!("═══════════════════════════════════════════════════════════");

    // 1. Deserialize block
    let block = deserialize_block_from_network(&req.block_data)
        .map_err(|e| RpcError {
            code: -32030,
            message: format!("failed to deserialize block: {}", e),
        })?;

    println!("   Block height: {}", block.header.height);
    println!("   Block proposer: {}", block.header.proposer);

    // 2. Basic validation
    let (tip_height, tip_hash) = chain.get_chain_tip()
        .map_err(|e| RpcError {
            code: -32031,
            message: format!("failed to get chain tip: {}", e),
        })?;

    if let Err(e) = validate_incoming_block(&block, &tip_hash, tip_height + 1) {
        println!("   ❌ Validation failed: {}", e);
        return Err(RpcError {
            code: -32032,
            message: format!("block validation failed: {}", e),
        });
    }

    println!("   ✅ Block validation passed");

    // 3. Apply block without mining
    match chain.apply_block_without_mining(block.clone()) {
        Ok(()) => {
            let block_hash = Block::compute_hash(&block.header);
            println!("   ✅ Block applied successfully");
            println!("═══════════════════════════════════════════════════════════");
            
            Ok(ReceiveBlockRes {
                accepted: true,
                height: block.header.height,
                block_hash: block_hash.to_hex(),
                message: "block accepted and applied".to_string(),
            })
        }
        Err(e) => {
            println!("   ❌ Failed to apply block: {}", e);
            Err(RpcError {
                code: -32033,
                message: format!("failed to apply block: {}", e),
            })
        }
    }
}

/// Broadcast block to peers using BroadcastManager
pub fn broadcast_block_via_manager(block: &Block, manager: &BroadcastManager) -> Vec<BroadcastResult> {
    let peers = manager.get_peers();
    broadcast_block(block, &peers)
}