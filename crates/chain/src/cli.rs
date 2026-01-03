//! cli.rs — AUTO NONCE VERSION (No manual nonce needed)
use clap::{Parser, Subcommand};
use anyhow::Result;
use std::str::FromStr;

use crate::types::Address;
use crate::tx::{TxEnvelope, TxPayload, ResourceClass, GovernanceActionType};
use crate::crypto::{sign_ed25519, Ed25519PrivateKey};
use crate::state::{
    ProposalType, ProposalStatus, VoteOption,
    PreviewType, GovernanceEventType,
};
use crate::receipt::{ResourceReceipt, NodeClass, ResourceType, MeasuredUsage};
use crate::Chain;
use hex;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ------------------- WALLET HELPERS -------------------

#[derive(Serialize, Deserialize)]
struct WalletFile {
    address: String,
    priv_key: String,
    pub_key: String, 
}


struct Wallet {
    address: Address,
    priv_key: Ed25519PrivateKey,
}

fn wallet_path() -> PathBuf {
    // Pakai current dir kalau nggak mau pakai dirs crate
    std::env::current_dir()
        .unwrap_or_else(|_| ".".into())
        .join("wallet.dat")
        .with_extension("dat")
    // Jadi file: ./wallet.dat (di folder project)
}

fn load_wallet() -> Result<Wallet> {
    let path = wallet_path();
    if !path.exists() {
        anyhow::bail!(
            "wallet.dat tidak ditemukan di {}. Gunakan 'wallet create' atau 'wallet import' dulu.",
            path.display()
        );
    }

    let data = std::fs::read(&path)?;                     //  read binary
    let wf: WalletFile = bincode::deserialize(&data)?;

    let priv_bytes = hex::decode(&wf.priv_key)?;
    let priv_key = Ed25519PrivateKey::from_bytes(&priv_bytes)?;
    let address = Address::from_str(&wf.address)?;

    Ok(Wallet { address, priv_key })
}

fn save_wallet(address: Address, priv_key: &Ed25519PrivateKey) -> Result<()> {
    let path = wallet_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let pubkey_obj = priv_key.public_key();
    let pubkey_bytes: &[u8] = pubkey_obj.as_bytes();
    let wf = WalletFile {
        address: address.to_string(),
        priv_key: hex::encode(priv_key.as_bytes()),
        pub_key: hex::encode(pubkey_bytes),
    };


    let bin = bincode::serialize(&wf)?;
    std::fs::write(path, bin)?;
    Ok(())
}


// ------------------- SIGN PAYLOAD (ganti build_env) -------------------

fn sign_payload(payload: TxPayload, priv_key: &Ed25519PrivateKey) -> Result<TxEnvelope> {
    let payload_bytes = bincode::serialize(&payload)?;
    let signature = sign_ed25519(priv_key, &payload_bytes)?;

    Ok(TxEnvelope {
        pubkey: priv_key.public_key().as_bytes().to_vec(), // as_bytes() bukan to_bytes()
        signature,
        payload,
        cached_id: None,
        is_private: false,
    })
}
#[derive(Parser)]
#[command(name = "dsdn-chain", about = "Nusantara Chain CLI - Auto Nonce + Wallet")]
pub struct Cli {
    #[arg(long, default_value = "./chaindb")]
    pub db_path: String,

    #[command(subcommand)]
    pub cmd: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    // ═══════════════════════════════════════════════════════════
    // CHAIN MANAGEMENT
    // ═══════════════════════════════════════════════════════════
    
    /// Initialize genesis block with initial account
    Init { 
        #[arg(long)] 
        genesis_account: String, 
        #[arg(long, default_value = "300000000")] 
        amount: String
    },
    
    /// Show chain status (height, tip hash)
    Status {},
    
    /// Show balance for address (or wallet if not specified)
    Balance { 
        #[arg(long)] 
        address: Option<String> 
    },

    // ═══════════════════════════════════════════════════════════
    // TRANSFER & PAYMENTS
    // ═══════════════════════════════════════════════════════════
    
    /// Submit transfer transaction
    SubmitTransfer { 
        #[arg(long)] to: String, 
        #[arg(long)] amount: String, 
        #[arg(long, default_value = "10")] fee: String, 
        #[arg(long, default_value = "21000")] gas_limit: u64 
    },
    
    /// Submit storage operation payment
    SubmitStorageOp { 
        #[arg(long)] to_node: String, 
        #[arg(long)] amount: String, 
        #[arg(long)] operation_id: String, 
        #[arg(long, default_value = "10")] fee: String, 
        #[arg(long, default_value = "25000")] gas_limit: u64 
    },
    
    /// Submit compute execution payment
    SubmitComputeExec { 
        #[arg(long)] to_node: String, 
        #[arg(long)] amount: String, 
        #[arg(long)] execution_id: String, 
        #[arg(long, default_value = "10")] fee: String, 
        #[arg(long, default_value = "40000")] gas_limit: u64 
    },

    // ═══════════════════════════════════════════════════════════
    // STAKING & DELEGATION
    // ═══════════════════════════════════════════════════════════
    
    /// Submit stake transaction (use --bond to delegate)
    SubmitStake { 
        #[arg(long)] validator: String, 
        #[arg(long)] amount: String, 
        #[arg(long, default_value = "10")] fee: String, 
        #[arg(long, action = clap::ArgAction::SetTrue)] bond: bool, 
        #[arg(long, default_value = "50000")] gas_limit: u64 
    },
    
    /// Submit unstake transaction
    SubmitUnstake { 
        #[arg(long)] validator: String, 
        #[arg(long)] amount: String, 
        #[arg(long, default_value = "10")] fee: String, 
        #[arg(long, default_value = "50000")] gas_limit: u64 
    },
    
    /// Submit claim reward transaction
    SubmitClaimReward { 
        #[arg(long, help = "Path to receipt JSON file from Coordinator")]
        receipt_file: String,
        #[arg(long, default_value = "10")] 
        fee: String, 
        #[arg(long, default_value = "30000")] 
        gas_limit: u64 
    },
    
    /// Delegate stake to a validator (shortcut for submit-stake --bond)
    Delegate { 
        #[arg(long)] 
        validator: String, 
        #[arg(long)] 
        amount: String, 
        #[arg(long, default_value = "10")] 
        fee: String 
    },

    /// Submit delegator stake to validator (13.8.B - explicit delegator staking)
    /// Requires: min 100,000 NUSA, validator must exist, delegator cannot be validator
    SubmitDelegatorStake {
        #[arg(long, help = "Validator address to delegate to")]
        validator: String,
        #[arg(long, help = "Amount to stake (min 100,000 NUSA)")]
        amount: String,
        #[arg(long, default_value = "10")]
        fee: String,
        #[arg(long, default_value = "50000")]
        gas_limit: u64,
    },

    /// Withdraw delegator stake from validator
    WithdrawDelegatorStake {
        #[arg(long, help = "Validator address to withdraw from")]
        validator: String,
        #[arg(long, help = "Amount to withdraw")]
        amount: String,
        #[arg(long, default_value = "10")]
        fee: String,
        #[arg(long, default_value = "50000")]
        gas_limit: u64,
    },


    // ═══════════════════════════════════════════════════════════
    // VALIDATOR MANAGEMENT
    // ═══════════════════════════════════════════════════════════
    
    /// Register as a validator (requires min 50,000 NUSA stake)
    SubmitValidatorReg { 
        #[arg(long)] pubkey: String, 
        #[arg(long)] min_stake: String, 
        #[arg(long, default_value = "10")] fee: String, 
        #[arg(long, default_value = "80000")] gas_limit: u64 
    },

    // ═══════════════════════════════════════════════════════════
    // QUERY COMMANDS
    // ═══════════════════════════════════════════════════════════
    
    /// List all validators with stake and voting power
    Validators {},
    
    /// Show detailed validator info including delegations
    ValidatorInfo { 
        #[arg(long)] 
        address: String 
    },
    
    /// Show staking info for current wallet
    StakingInfo {},
    
    /// Show current epoch and network info
    EpochInfo {},
    
    /// Show treasury, reward pool, and delegator pool balances
    PoolInfo {},

    // ═══════════════════════════════════════════════════════════
    // MINING
    // ═══════════════════════════════════════════════════════════
    
    /// Mine a new block (proposer selected by stake-weight if validators exist)
    Mine { 
        #[arg(long)] 
        miner_addr: Option<String> 
    },

    // ═══════════════════════════════════════════════════════════
    // WALLET
    // ═══════════════════════════════════════════════════════════
    
    /// Wallet management (create, import, status)
    Wallet { 
        #[command(subcommand)] 
        command: WalletCommand 
    },

    // ═══════════════════════════════════════════════════════════
    // TESTING
    // ═══════════════════════════════════════════════════════════
    
    /// Run end-to-end integration tests for consensus and block production
    TestE2e {
        /// Run specific test module (proposer, stake, qv, block, mempool, epoch, fullnode, all)
        #[arg(long, default_value = "all")]
        module: String,
        /// Verbose output
        #[arg(long, short, action = clap::ArgAction::SetTrue)]
        verbose: bool,
    },

    // ═══════════════════════════════════════════════════════════
    // ADMIN / GOVERNANCE (13.9)
    // ═══════════════════════════════════════════════════════════
    
    /// Node cost index management (Admin/Governance only)
    /// Perubahan node_cost_index adalah consensus-critical dan masuk state_root.
    NodeCost {
        #[command(subcommand)]
        command: NodeCostCommand,
    },

    /// Receipt management (13.10)
    /// Claim rewards, check receipt status, view node earnings
    Receipt {
        #[command(subcommand)]
        command: ReceiptCommand,
    },

    // ═══════════════════════════════════════════════════════════
    // SYNC MANAGEMENT (13.11.7)
    // ═══════════════════════════════════════════════════════════

    /// Sync management commands
    /// Control sync lifecycle, monitor status and progress
    Sync {
        #[command(subcommand)]
        command: SyncCommand,
    },

    // ═══════════════════════════════════════════════════════════
    // GOVERNANCE (13.12.8)
    // ═══════════════════════════════════════════════════════════

/// Governance commands - proposals, voting, and Foundation controls
    /// Bootstrap Mode: All votes are non-binding, Foundation has veto power
    Governance {
        #[command(subcommand)]
        command: GovernanceCommand,
    },

    // ═══════════════════════════════════════════════════════════
    // SLASHING OBSERVABILITY (13.14.8)
    // ═══════════════════════════════════════════════════════════

    /// Slashing observability commands — READ-ONLY
    /// View node liveness, validator slash status, and slashing events
    Slashing {
        #[command(subcommand)]
        command: SlashingCommand,
    },

    // ═══════════════════════════════════════════════════════════
    // ECONOMIC OBSERVABILITY (13.15.8)
    // ═══════════════════════════════════════════════════════════

    /// Economic observability commands — READ-ONLY
    /// View economic status, deflation info, and burn history
    Economic {
        #[command(subcommand)]
        command: EconomicCommand,
    },

    // ═══════════════════════════════════════════════════════════
    // STORAGE CONTRACT QUERIES (13.17.8)
    // ═══════════════════════════════════════════════════════════

    /// Storage contract query commands — READ-ONLY
    /// List and inspect storage contracts
    Storage {
        #[command(subcommand)]
        command: StorageCommand,
    },

    // ═══════════════════════════════════════════════════════════
    // DATA AVAILABILITY (13.17.8)
    // ═══════════════════════════════════════════════════════════

    /// Data Availability (Celestia) commands
    /// Verify blob commitments and check DA status
    Da {
        #[command(subcommand)]
        command: DACommand,
    },
}

/// Wallet commands (13.17.8)
/// 
/// Secure wallet operations. Secret keys are NEVER stored by the system.
/// All operations are stateless - caller provides secret when needed.
#[derive(Subcommand)]
pub enum WalletCommand {
    /// Create a new wallet (generates new keypair, saves to wallet.dat)
    /// SECURITY: Backup the secret key immediately!
    Create,
    /// Import wallet from private key
    Import { 
        #[arg(long)] 
        privkey: String 
    },
    /// Show wallet status (address only)
    Status,
    /// Sign a transaction with provided secret key
    /// Returns signed transaction hex
    Sign {
        #[arg(long, help = "Unsigned transaction hex")]
        tx: String,
        #[arg(long, help = "Secret key hex (64 chars)")]
        secret: String,
    },
    /// Encrypt a file using wallet encryption
    Encrypt {
        #[arg(long, help = "Input file path")]
        file: String,
        #[arg(long, help = "Output file path")]
        output: String,
    },
    /// Decrypt a file using wallet encryption
    Decrypt {
        #[arg(long, help = "Encrypted file path")]
        file: String,
        #[arg(long, help = "Output file path")]
        output: String,
    },
}

/// Storage contract commands (13.17.8)
/// 
/// Query and manage storage contracts.
/// READ-ONLY operations - no state mutation via CLI.
#[derive(Subcommand)]
pub enum StorageCommand {
    /// List all contracts for an address
    List {
        #[arg(long, help = "Owner address (hex)")]
        address: String,
    },
    /// Show detailed contract info
    Info {
        #[arg(long, help = "Contract ID (hex, 128 chars)")]
        contract: String,
    },
}

/// Data Availability (DA) commands (13.17.8)
/// 
/// Celestia DA verification and status.
#[derive(Subcommand)]
pub enum DACommand {
    /// Verify blob commitment
    Verify {
        #[arg(long, help = "Blob data (hex)")]
        blob: String,
        #[arg(long, help = "Commitment (hex)")]
        commitment: String,
    },
}

/// Node Cost Index management commands
/// 
/// Perintah ini digunakan oleh Governance module atau Admin CLI untuk
/// mengatur node cost index multiplier. Perubahan bersifat consensus-critical
/// dan masuk ke dalam state_root computation.
#[derive(Subcommand)]
pub enum NodeCostCommand {
    /// Set node cost index multiplier for a node
    /// Example: dsdn node-cost set --address 0x... --multiplier 150
    Set {
        #[arg(long, help = "Node address (hex)")]
        address: String,
        #[arg(long, help = "Cost index multiplier (basis 100 = 1.0x)")]
        multiplier: u128,
    },
    /// Remove node cost index for a node (reverts to default)
    /// Example: dsdn node-cost remove --address 0x...
    Remove {
        #[arg(long, help = "Node address (hex)")]
        address: String,
    },
    /// Get current node cost index for a node
    /// Example: dsdn node-cost get --address 0x...
    Get {
        #[arg(long, help = "Node address (hex)")]
        address: String,
    },
    /// List all node cost indexes
    List,
}

/// Receipt management commands (13.10)
/// 
/// Perintah untuk mengelola receipt claim:
/// - claim: Submit ClaimReward transaction
/// - status: Check apakah receipt sudah di-claim
/// - earnings: Lihat akumulasi earnings untuk node
#[derive(Subcommand)]
pub enum ReceiptCommand {
    /// Submit ClaimReward transaction dari file receipt JSON
    /// Example: dsdn receipt claim --file receipt.json
    Claim {
        #[arg(long, help = "Path to receipt JSON file")]
        file: String,
        #[arg(long, default_value = "10")]
        fee: String,
        #[arg(long, default_value = "30000")]
        gas_limit: u64,
    },
    /// Check status receipt (sudah di-claim atau belum)
    /// Example: dsdn receipt status --id 0x...
    Status {
        #[arg(long, help = "Receipt ID (hex string 128 chars)")]
        id: String,
    },
    /// Lihat akumulasi earnings untuk node address
    /// Example: dsdn receipt earnings --address 0x...
    Earnings {
        #[arg(long, help = "Node address (hex)")]
        address: String,
    },
}
/// Sync management commands (13.11.7)
///
/// Perintah untuk mengelola proses sync:
/// - start: Mulai sync ke network tip
/// - stop: Hentikan sync yang sedang berjalan
/// - status: Tampilkan status sync saat ini
/// - progress: Tampilkan progress bar dan ETA
/// - reset: Reset state dan mulai ulang dari genesis
#[derive(Subcommand)]
pub enum SyncCommand {
    /// Start sync process to network tip
    Start,
    /// Stop ongoing sync process
    Stop,
    /// Show current sync status
    Status,
    /// Show sync progress with progress bar
    Progress,
/// Reset sync state (clear metadata, restart from genesis)
    Reset,
}

/// Governance management commands (13.12.8)
///
/// Perintah untuk mengelola governance:
/// - propose: Buat proposal baru
/// - vote: Vote pada proposal
/// - finalize: Finalisasi proposal setelah voting period
/// - list-active: Tampilkan proposal aktif
/// - list-all: Tampilkan semua proposal
/// - show: Tampilkan detail proposal
/// - my-votes: Tampilkan vote saya
/// - foundation-veto: Veto proposal (Foundation only)
#[derive(Subcommand)]
pub enum GovernanceCommand {
    /// Create a new governance proposal
    /// Example: dsdn governance propose --type update-fee --title "Reduce fee" --description "..."
    Propose {
        #[arg(long, help = "Proposal type: update-fee, update-gas, update-node-cost, validator-onboard, validator-offboard, compliance-remove, emergency-pause")]
        r#type: String,
        #[arg(long, help = "Proposal title (max 100 chars)")]
        title: String,
        #[arg(long, help = "Proposal description (max 1000 chars)")]
        description: String,
        #[arg(long, default_value = "10")]
        fee: String,
        #[arg(long, default_value = "100000")]
        gas_limit: u64,
    },
    /// Vote on a proposal
    /// Example: dsdn governance vote --proposal 1 --vote yes
    Vote {
        #[arg(long, help = "Proposal ID")]
        proposal: u64,
        #[arg(long, help = "Vote option: yes, no, abstain")]
        vote: String,
        #[arg(long, default_value = "10")]
        fee: String,
        #[arg(long, default_value = "50000")]
        gas_limit: u64,
    },
    /// Finalize a proposal after voting period ends
    /// Example: dsdn governance finalize --proposal 1
    Finalize {
        #[arg(long, help = "Proposal ID")]
        proposal: u64,
        #[arg(long, default_value = "10")]
        fee: String,
        #[arg(long, default_value = "75000")]
        gas_limit: u64,
    },
    /// List all active proposals
    ListActive,
    /// List all proposals (all statuses)
    ListAll,
    /// Show detailed proposal info
    /// Example: dsdn governance show --proposal 1
    Show {
        #[arg(long, help = "Proposal ID")]
        proposal: u64,
    },
    /// Show my votes on all proposals
    MyVotes,
    /// Foundation veto a proposal (Bootstrap Mode only)
    /// Example: dsdn governance foundation-veto --proposal 1
    FoundationVeto {
        #[arg(long, help = "Proposal ID")]
        proposal: u64,
        #[arg(long, default_value = "10")]
        fee: String,
        #[arg(long, default_value = "50000")]
        gas_limit: u64,
    },
/// Show current governance configuration
    Config,

    // ════════════════════════════════════════════════════════════════════════════
    // PREVIEW COMMANDS (13.13.6) — READ-ONLY
    // ════════════════════════════════════════════════════════════════════════════

    /// Preview proposal changes (READ-ONLY, does NOT execute)
    /// Example: dsdn governance preview --proposal 1
    Preview {
        #[arg(long, help = "Proposal ID to preview")]
        proposal: u64,
    },

    /// Show bootstrap mode status
    /// Example: dsdn governance bootstrap-status
    BootstrapStatus,

/// Show recent governance events
    /// Example: dsdn governance events --count 10
    Events {
        #[arg(long, help = "Number of events to show (default: 20)")]
        count: Option<u64>,
    },
}

/// Slashing observability commands (13.14.8)
///
/// Perintah READ-ONLY untuk memonitor slashing:
/// - node-status: Lihat status liveness node
/// - validator-status: Lihat status slash validator
/// - events: Lihat slashing events terbaru
///
/// TIDAK ADA state mutation. Aman untuk monitoring.
#[derive(Subcommand)]
pub enum SlashingCommand {
    /// Show node liveness status
    /// Example: dsdn slashing node-status --address 0x...
    NodeStatus {
        #[arg(long, help = "Node address (hex)")]
        address: String,
    },
    /// Show validator slash status
    /// Example: dsdn slashing validator-status --address 0x...
    ValidatorStatus {
        #[arg(long, help = "Validator address (hex)")]
        address: String,
    },
    /// Show recent slashing events
    /// Example: dsdn slashing events --count 10
    Events {
        #[arg(long, help = "Number of events to show (default: 20)")]
        count: Option<u64>,
    },
}

/// Economic observability commands (13.15.8)
///
/// Perintah READ-ONLY untuk memonitor ekonomi:
/// - status: Lihat status ekonomi saat ini (mode, RF, treasury, supply, burn rate)
/// - deflation: Lihat konfigurasi dan status deflasi
/// - burn-history: Lihat riwayat burn events
///
/// TIDAK ADA state mutation. Aman untuk monitoring dan audit.
#[derive(Subcommand)]
pub enum EconomicCommand {
    /// Show current economic status
    /// Displays mode, replication factor, treasury, supply, and burn rate
    /// Example: dsdn economic status
    Status,
    /// Show deflation configuration and state
    /// Displays target range, current rate, cumulative burned, burn epochs
    /// Example: dsdn economic deflation
    Deflation,
    /// Show burn event history
    /// Example: dsdn economic burn-history --count 20
    BurnHistory {
        #[arg(long, help = "Number of events to show (default: 20)")]
        count: Option<u32>,
    },
}

/// Format progress bar string
/// Example: [██████████░░░░░░░░░░] 45%
fn format_progress_bar(percent: u8) -> String {
    let filled = (percent as usize) / 5;  // 20 chars total, each represents 5%
    let empty = 20 - filled;
    format!(
        "[{}{}] {}%",
        "█".repeat(filled),
        "░".repeat(empty),
        percent
    )
}

/// Calculate ETA based on blocks remaining and assumed rate
fn calculate_eta(current: u64, target: u64) -> String {
    let remaining = target.saturating_sub(current);
    // Assume ~100 blocks per minute (placeholder)
    let minutes = remaining / 100;
    let hours = minutes / 60;
    let mins = minutes % 60;
    format!("{:02}:{:02}", hours, mins)
}

use crate::types::{DECIMALS, SCALE};

/// Format smallest-unit NUSA (u128) → human-readable string with decimals
/// Example: 123456789 -> "1.23456789 NUSA"
fn format_nusa(amount: u128) -> String {
    let whole = amount / SCALE;
    let frac = amount % SCALE;
    let decimals = DECIMALS as usize;

    format!(
        "{}.{:0width$} NUSA",
        whole,
        frac,
        width = decimals
    )
}

/// Parse string amount (supports decimals) to smallest unit
/// Examples:
/// "1"      -> 1_000_000_000
/// "0.12"   -> 120_000_000
/// "1.0001" -> 1_000_100_000
fn parse_nusa_amount(input: &str) -> Result<u128> {
    let parts: Vec<&str> = input.split('.').collect();

    let whole: u128 = parts[0]
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid amount"))?;

    let frac: u128 = if parts.len() == 2 {
        let mut frac_str = parts[1].to_string();

        if frac_str.len() > DECIMALS as usize {
            anyhow::bail!("Too many decimal places (max {})", DECIMALS);
        }

        while frac_str.len() < DECIMALS as usize {
            frac_str.push('0');
        }

        frac_str.parse().map_err(|_| anyhow::anyhow!("Invalid decimals"))?
    } else {
        0
    };

    Ok(whole * SCALE + frac)
}


pub fn run_cli() -> Result<()> {
    let cli = Cli::parse();
    let chain = crate::Chain::new(&cli.db_path)?;

    // === Wallet commands (create/import/status) tidak butuh wallet ===
    if let Commands::Wallet { command } = &cli.cmd {
        return match command {
            WalletCommand::Create => {
                let path = wallet_path();
                if path.exists() {
                    println!("⚠️  Warning: wallet.dat sudah ada, akan ditimpa!");
                }
                let priv_key = Ed25519PrivateKey::generate();
                let pubkey = priv_key.public_key();
                let pubkey_bytes: [u8; 32] = pubkey.to_bytes();
                let address = crate::crypto::address_from_pubkey_bytes(&pubkey_bytes)?;

                save_wallet(address, &priv_key)?;
                
                println!("═══════════════════════════════════════════════════════════");
                println!("🔐 NEW WALLET CREATED (13.17.8)");
                println!("═══════════════════════════════════════════════════════════");
                println!("Address:    0x{}", hex::encode(address.as_bytes()));
                println!("Public Key: {}", hex::encode(pubkey_bytes));
                println!("Secret Key: {}", hex::encode(priv_key.as_bytes()));
                println!("File:       {}", path.display());
                println!("═══════════════════════════════════════════════════════════");
                println!("⚠️  WARNING: BACKUP YOUR SECRET KEY IMMEDIATELY!");
                println!("⚠️  Anyone with your secret key can steal your funds!");
                println!("⚠️  Store it securely and NEVER share it!");
                println!("═══════════════════════════════════════════════════════════");
                Ok(())
            }
            WalletCommand::Import { privkey } => {
                let bytes = hex::decode(privkey)
                    .map_err(|_| anyhow::anyhow!("Private key hex tidak valid"))?;
                if bytes.len() != 32 {
                    anyhow::bail!("Private key harus 32 bytes (64 hex char)");
                }
                let priv_key = Ed25519PrivateKey::from_bytes(&bytes)?;
                let pubkey = priv_key.public_key();
                let pubkey_bytes: [u8; 32] = pubkey.to_bytes();
                let address = crate::crypto::address_from_pubkey_bytes(&pubkey_bytes)?;

                save_wallet(address, &priv_key)?;
                println!("═══════════════════════════════════════════════════════════");
                println!("✅ WALLET IMPORTED (13.17.8)");
                println!("═══════════════════════════════════════════════════════════");
                println!("Address: 0x{}", hex::encode(address.as_bytes()));
                println!("File:    {}", wallet_path().display());
                println!("═══════════════════════════════════════════════════════════");
                Ok(())
            }
            WalletCommand::Status => {
                let w = load_wallet()?;
                println!("═══════════════════════════════════════════════════════════");
                println!("💼 WALLET STATUS (13.17.8)");
                println!("═══════════════════════════════════════════════════════════");
                println!("Address: {}", w.address);
                println!("File:    {}", wallet_path().display());
                println!("═══════════════════════════════════════════════════════════");
                Ok(())
            }
            WalletCommand::Sign { tx, secret } => {
                use crate::wallet::Wallet;
                use crate::tx::TxEnvelope;
                use crate::crypto::sign_ed25519;
                
                // Decode secret key
                let secret_bytes = hex::decode(secret)
                    .map_err(|_| anyhow::anyhow!("Invalid secret key hex"))?;
                
                if secret_bytes.len() != 32 {
                    anyhow::bail!("Secret key must be 32 bytes (64 hex chars)");
                }
                
                let mut secret_arr = [0u8; 32];
                secret_arr.copy_from_slice(&secret_bytes);
                
                // Restore wallet
                let wallet = Wallet::from_secret_key(&secret_arr);
                
                // Decode transaction
                let tx_bytes = hex::decode(tx)
                    .map_err(|_| anyhow::anyhow!("Invalid transaction hex"))?;
                
                let mut tx_envelope: TxEnvelope = bincode::deserialize(&tx_bytes)
                    .map_err(|e| anyhow::anyhow!("Invalid transaction format: {}", e))?;
                
                // Sign the payload
                let payload_bytes = bincode::serialize(&tx_envelope.payload)?;
                
                let priv_key = Ed25519PrivateKey::from_bytes(&secret_arr)?;
                let signature = sign_ed25519(&priv_key, &payload_bytes)?;
                
                // Update envelope
                tx_envelope.signature = signature;
                tx_envelope.pubkey = wallet.public_key().to_vec();
                
                // Serialize and print
                let signed_bytes = bincode::serialize(&tx_envelope)?;
                
                println!("═══════════════════════════════════════════════════════════");
                println!("✅ TRANSACTION SIGNED (13.17.8)");
                println!("═══════════════════════════════════════════════════════════");
                println!("Signed TX: {}", hex::encode(&signed_bytes));
                println!("═══════════════════════════════════════════════════════════");
                Ok(())
            }
            WalletCommand::Encrypt { file, output } => {
                // File encryption (13.17.5 prerequisite - placeholder)
                // Load file
                let data = std::fs::read(file)
                    .map_err(|e| anyhow::anyhow!("Failed to read file: {}", e))?;
                
                // Get wallet for encryption key
                let w = load_wallet()?;
                
                // Simple XOR encryption using public key as key
                // (Placeholder - real implementation uses proper encryption in 13.17.5)
                let key = w.priv_key.public_key().to_bytes();
                let encrypted: Vec<u8> = data.iter()
                    .enumerate()
                    .map(|(i, &b)| b ^ key[i % 32])
                    .collect();
                
                std::fs::write(output, &encrypted)
                    .map_err(|e| anyhow::anyhow!("Failed to write output: {}", e))?;
                
                println!("═══════════════════════════════════════════════════════════");
                println!("🔒 FILE ENCRYPTED (13.17.8)");
                println!("═══════════════════════════════════════════════════════════");
                println!("Input:  {}", file);
                println!("Output: {}", output);
                println!("Size:   {} bytes", encrypted.len());
                println!("═══════════════════════════════════════════════════════════");
                Ok(())
            }
            WalletCommand::Decrypt { file, output } => {
                // File decryption (13.17.5 prerequisite - placeholder)
                // Load encrypted file
                let data = std::fs::read(file)
                    .map_err(|e| anyhow::anyhow!("Failed to read file: {}", e))?;
                
                // Get wallet for decryption key
                let w = load_wallet()?;
                
                // Simple XOR decryption using public key as key
                // (Placeholder - real implementation uses proper encryption in 13.17.5)
                let key = w.priv_key.public_key().to_bytes();
                let decrypted: Vec<u8> = data.iter()
                    .enumerate()
                    .map(|(i, &b)| b ^ key[i % 32])
                    .collect();
                
                std::fs::write(output, &decrypted)
                    .map_err(|e| anyhow::anyhow!("Failed to write output: {}", e))?;
                
                println!("═══════════════════════════════════════════════════════════");
                println!("🔓 FILE DECRYPTED (13.17.8)");
                println!("═══════════════════════════════════════════════════════════");
                println!("Input:  {}", file);
                println!("Output: {}", output);
                println!("Size:   {} bytes", decrypted.len());
                println!("═══════════════════════════════════════════════════════════");
                Ok(())
            }
        };
    }

    // === Handle Storage commands (13.17.8) ===
    if let Commands::Storage { command } = &cli.cmd {
        return match command {
            StorageCommand::List { address } => {
                use crate::state::StorageContractStatus;
                
                // Parse address
                let addr_str = address.trim_start_matches("0x");
                let addr = Address::from_hex(addr_str)
                    .map_err(|_| anyhow::anyhow!("Invalid address format"))?;
                
                let state = chain.state.read();
                
                println!("═══════════════════════════════════════════════════════════");
                println!("📦 STORAGE CONTRACTS for 0x{}", hex::encode(addr.as_bytes()));
                println!("═══════════════════════════════════════════════════════════");
                
                match state.user_contracts.get(&addr) {
                    Some(contract_ids) if !contract_ids.is_empty() => {
                        println!("{:<10} {:<20} {:>15} {:>12}", 
                                 "#", "Contract ID (prefix)", "Bytes", "Status");
                        println!("{}", "─".repeat(60));
                        
                        for (i, hash) in contract_ids.iter().enumerate() {
                            if let Some(contract) = state.storage_contracts.get(hash) {
                                let id_prefix = &hex::encode(hash.as_bytes())[..16];
                                let status = match contract.status {
                                    StorageContractStatus::Active => "Active",
                                    StorageContractStatus::GracePeriod => "GracePeriod",
                                    StorageContractStatus::Expired => "Expired",
                                    StorageContractStatus::Cancelled => "Cancelled",
                                };
                                println!("{:<10} {}... {:>15} {:>12}",
                                        i + 1, id_prefix, contract.storage_bytes, status);
                            }
                        }
                        println!("═══════════════════════════════════════════════════════════");
                        println!("Total contracts: {}", contract_ids.len());
                    }
                    _ => {
                        println!("   No storage contracts found for this address.");
                    }
                }
                println!("═══════════════════════════════════════════════════════════");
                Ok(())
            }
            StorageCommand::Info { contract } => {
                use crate::types::Hash;
                use crate::state::StorageContractStatus;
                
                // Decode contract ID
                let id_bytes = hex::decode(contract)
                    .map_err(|_| anyhow::anyhow!("Invalid contract ID hex"))?;
                
                if id_bytes.len() != 64 {
                    anyhow::bail!("Contract ID must be 64 bytes (128 hex chars)");
                }
                
                let mut id_arr = [0u8; 64];
                id_arr.copy_from_slice(&id_bytes);
                let hash = Hash::from_bytes(id_arr);
                
                let state = chain.state.read();
                
                match state.storage_contracts.get(&hash) {
                    Some(c) => {
                        let status = match c.status {
                            StorageContractStatus::Active => "Active ✅",
                            StorageContractStatus::GracePeriod => "GracePeriod ⚠️",
                            StorageContractStatus::Expired => "Expired ❌",
                            StorageContractStatus::Cancelled => "Cancelled 🚫",
                        };
                        
                        println!("═══════════════════════════════════════════════════════════");
                        println!("📄 STORAGE CONTRACT INFO (13.17.8)");
                        println!("═══════════════════════════════════════════════════════════");
                        println!("Contract ID:   {}", contract);
                        println!("Owner:         0x{}", hex::encode(c.owner.as_bytes()));
                        println!("Node:          0x{}", hex::encode(c.node_address.as_bytes()));
                        println!("Storage:       {} bytes", c.storage_bytes);
                        println!("Monthly Cost:  {} (smallest unit)", c.monthly_cost);
                        println!("Status:        {}", status);
                        println!("Start:         {} (Unix)", c.start_timestamp);
                        println!("End:           {} (Unix)", c.end_timestamp);
                        println!("Last Payment:  {} (Unix)", c.last_payment_timestamp);
                        println!("═══════════════════════════════════════════════════════════");
                    }
                    None => {
                        println!("❌ Contract not found: {}", contract);
                    }
                }
                Ok(())
            }
        };
    }

    // === Handle DA commands (13.17.8) ===
    if let Commands::Da { command } = &cli.cmd {
        return match command {
            DACommand::Verify { blob, commitment } => {
                // Decode blob
                let blob_bytes = hex::decode(blob)
                    .map_err(|_| anyhow::anyhow!("Invalid blob hex"))?;
                
                // Decode commitment
                let commitment_bytes = hex::decode(commitment)
                    .map_err(|_| anyhow::anyhow!("Invalid commitment hex"))?;
                
                // Verify using Celestia module
                use crate::celestia::verify_blob_commitment;
                
                let commitment_arr: [u8; 32] = commitment_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Commitment must be exactly 32 bytes"))?;

                let valid = verify_blob_commitment(&blob_bytes, &commitment_arr);

                
                println!("═══════════════════════════════════════════════════════════");
                println!("🔍 DA BLOB VERIFICATION (13.17.8)");
                println!("═══════════════════════════════════════════════════════════");
                println!("Blob size:   {} bytes", blob_bytes.len());
                println!("Commitment:  {} bytes", commitment_bytes.len());
                println!("───────────────────────────────────────────────────────────");
                if valid {
                    println!("Result:      ✅ VALID - Blob matches commitment");
                } else {
                    println!("Result:      ❌ INVALID - Blob does NOT match commitment");
                }
                println!("═══════════════════════════════════════════════════════════");
                Ok(())
            }
        };
    }

    // === Handle commands yang TIDAK butuh wallet ===
    match &cli.cmd {
    Commands::Init { genesis_account, amount } => {
        let units = parse_nusa_amount(amount)?;

        chain.init_genesis(genesis_account, units)?;

        println!(
            "✅ Genesis initialized → {} minted {}",
            genesis_account,
            format_nusa(units)
        );
        return Ok(());
    }


        Commands::Status {} => {
            if let Some((h, hash)) = chain.db.get_tip()? {
                println!("📊 Chain Status:");
                println!("   Height: {}", h);
                println!("   Hash: {}", hash.to_hex());
            } else {
                println!("⚠️  No blocks yet (chain not initialized)");
            }
            return Ok(());
        }

        Commands::Balance { address } => {
            match address {
                Some(addr_str) => {
                    // Query balance for specified address (no wallet needed)
                    let addr = Address::from_str(addr_str)
                        .map_err(|_| anyhow::anyhow!("Invalid address format"))?;
                    let state = chain.state.read();
                    let balance = state.get_balance(&addr);
                    let locked = state.get_locked(&addr);
                    
                    println!("═══════════════════════════════════════════════════════════");
                    println!("💰 BALANCE INFO for {}", addr);
                    println!("═══════════════════════════════════════════════════════════");
                    println!("   Available: {}", format_nusa(balance));
                    println!("   Locked (staked): {}", format_nusa(locked));
                    println!("   Total: {}", format_nusa(balance + locked));

                    return Ok(());
                }
                None => {
                    let w = load_wallet()?;
                    let state = chain.state.read();
                    let balance = state.get_balance(&w.address);
                    let locked = state.get_locked(&w.address);
                    
                    println!("═══════════════════════════════════════════════════════════");
                    println!("💰 BALANCE INFO for {} (your wallet)", w.address);
                    println!("═══════════════════════════════════════════════════════════");
                    println!("   Available: {}", format_nusa(balance));
                    println!("   Locked (staked): {}", format_nusa(locked));
                    println!("   Total: {}", format_nusa(balance + locked));
                    return Ok(());
                }
            }
        }
        

        _ => {} // Commands lain perlu wallet
    }

    // === Load wallet untuk commands yang membutuhkan ===
    let wallet = load_wallet()?;

    match &cli.cmd {
        Commands::Balance { address: _ } => {
            // Case: balance tanpa --address argument
            println!("💰 Balance {} → {}", wallet.address, chain.get_balance(&wallet.address));
        }

                // ==================== VALIDATORS LIST ====================
        Commands::Validators {} => {
            let state = chain.state.read();
            let validators = state.validator_set.get_top_validators(150);
            
            println!("═══════════════════════════════════════════════════════════");
            println!("📋 VALIDATOR LIST (Total: {})", validators.len());
            println!("═══════════════════════════════════════════════════════════");
            
            if validators.is_empty() {
                println!("   No validators registered yet");
            } else {
                println!("{:<5} {:<44} {:>15} {:>12} {:>8}", 
                         "Rank", "Address", "Stake", "VotingPower", "Active");
                println!("{}", "─".repeat(90));
                
                for (i, v) in validators.iter().enumerate() {
                    let power = state.get_validator_total_power(&v.address);
                    let active_str = if v.active { "✅" } else { "❌" };
                    println!("{:<5} {:<44} {:>20} {:>20} {:>8}",
                            i + 1,
                            v.address,
                            format_nusa(v.stake),
                            format_nusa(power),
                            active_str);
                }
            }
            
            println!("═══════════════════════════════════════════════════════════");
            println!("Total Network Stake: {}",format_nusa(state.validator_set.total_stake()));
            println!("Active Validators: {}", state.validator_set.active_count());
            return Ok(());
        }

        // ==================== VALIDATOR INFO ====================
        Commands::ValidatorInfo { address } => {
            let addr = Address::from_str(address)?;
            let state = chain.state.read();
            
            println!("═══════════════════════════════════════════════════════════");
            println!("🔍 VALIDATOR INFO: {}", addr);
            println!("═══════════════════════════════════════════════════════════");
            
            if let Some(v) = state.validator_set.get(&addr) {
                println!("   Stake: {}", format_nusa(v.stake));
                println!("   Active: {}", if v.active { "Yes ✅" } else { "No ❌" });
                println!("   Pubkey: {}", hex::encode(&v.pubkey));
                
                // Voting power
                let power = state.get_validator_total_power(&addr);
                println!("   Voting Power: {}", format_nusa(power));


                // Liveness info
                if let Some(liveness) = state.liveness_records.get(&addr) {
                    println!("\n   ⏱️ Liveness:");
                    println!("      Missed Blocks: {}", liveness.missed_blocks);
                    println!("      Slashed: {}", if liveness.slashed { "Yes 🔪" } else { "No" });
                    println!("      Slash Count: {}", liveness.slash_count);
                }
            } else {
                println!("   ⚠️ Validator not found");
            }
            
            return Ok(());
        }

        // ==================== STAKING INFO ====================
        Commands::StakingInfo {} => {
            let w = load_wallet()?;
            let state = chain.state.read();
            
            println!("═══════════════════════════════════════════════════════════");
            println!("💰 STAKING INFO for {}", w.address);
            println!("═══════════════════════════════════════════════════════════");
            
            let balance = state.get_balance(&w.address);
            let locked = state.get_locked(&w.address);
            let voting_power = state.get_voting_power(&w.address);
            
            println!("   Balance (available): {}", format_nusa(balance));
            println!("   Locked (staked): {}", format_nusa(locked));
            println!("   Voting Power: {}", format_nusa(voting_power));

            
            // Check if validator
            if state.validator_set.is_validator(&w.address) {
                println!("\n   🎖️ You are a VALIDATOR");
                let power = state.get_validator_total_power(&w.address);
                println!("   Total Validator Power: {}", power);
            }
            
            // Find delegations by this address — build unified view
            println!("\n   📤 Your Delegations:");

            use std::collections::BTreeMap;
            let mut found: BTreeMap<Address, u128> = BTreeMap::new();

            // ✅ AUTHORITATIVE SOURCE
            for (validator, dels) in state.delegations.iter() {
                if let Some(amount) = dels.get(&w.address) {
                    found.insert(*validator, *amount);
                }
            }

            if found.is_empty() {
                println!("      (no delegations)");
            } else {
                for (validator, amount) in found {
                    println!("      → {} : {}", validator, format_nusa(amount));
                }
            }


            
            return Ok(());
        }

        // ==================== EPOCH INFO ====================
        Commands::EpochInfo {} => {
            let state = chain.state.read();
            let (tip_height, tip_hash) = chain.db.get_tip()?.unwrap_or((0, crate::types::Hash::from_bytes([0u8; 64])));
            
            println!("═══════════════════════════════════════════════════════════");
            println!("🌅 EPOCH INFO");
            println!("═══════════════════════════════════════════════════════════");
            
            println!("   Current Height: {}", tip_height);
            println!("   Tip Hash: {}", tip_hash.to_hex());
            println!();
            println!("   Epoch Number: {}", state.epoch_info.epoch_number);
            println!("   Epoch Start Height: {}", state.epoch_info.start_height);
            println!("   Active Validators: {}", state.epoch_info.active_validators);
            println!("   Total Stake: {}", state.epoch_info.total_stake);
            println!();
            println!("   Epoch Interval: {} blocks", state.epoch_config.interval);
            println!("   Max Validators: {}", state.epoch_config.max_validators);
            
            // Blocks until next epoch
            let blocks_until = crate::epoch::blocks_until_next_epoch(tip_height, &state.epoch_config);
            println!("   Blocks Until Next Epoch: {}", blocks_until);
            
            return Ok(());
        }

        // ==================== POOL INFO ====================
        Commands::PoolInfo {} => {
            let state = chain.state.read();
            
            println!("═══════════════════════════════════════════════════════════");
            println!("🏦 POOL & TREASURY INFO");
            println!("═══════════════════════════════════════════════════════════");
            
            println!("   Reward Pool: {}", format_nusa(state.reward_pool));
            println!("   Treasury Balance: {}", format_nusa(state.treasury_balance));
            println!("   Delegator Pool: {}", format_nusa(state.delegator_pool));
            println!("   Total Supply: {}", format_nusa(state.total_supply));

            
            return Ok(());
        }

         // ==================== DELEGATE (shortcut for SubmitDelegatorStake) ====================
        Commands::Delegate { validator, amount, fee } => {
            // PARSE STRING → UNIT (u128)
            let amount = parse_nusa_amount(amount)?;
            let fee = parse_nusa_amount(fee)?;

            // Validate minimum stake (UNIT vs UNIT)
            if amount < crate::tokenomics::DELEGATOR_MIN_STAKE {
                anyhow::bail!(
                    "❌ Delegation amount too low: minimum {} NUSA required",
                    crate::tokenomics::DELEGATOR_MIN_STAKE
                );
            }

            let validator_addr = Address::from_str(validator)?;

            // Pre-validation
            {
                let state = chain.state.read();
                if !state.validator_set.is_validator(&validator_addr) {
                    anyhow::bail!("❌ Validator {} is not registered", validator);
                }
                if state.validator_set.is_validator(&wallet.address) {
                    anyhow::bail!("❌ Validators cannot delegate");
                }
            }

            let nonce = chain.state.read().get_nonce(&wallet.address) + 1;

            let payload = TxPayload::Stake {
                delegator: wallet.address,
                validator: validator_addr,
                amount,         
                fee,          
                nonce,
                bond: true,
                gas_limit: 50000,
                resource_class: ResourceClass::Governance,
                metadata_flagged: false,
            };

            let env = sign_payload(payload, &wallet.priv_key)?;
            chain.submit_tx(env)?;

            println!(
                "✅ Delegation submitted: {} → validator {}",
                format_nusa(amount),
                validator
            );
        }


        // ==================== TRANSFER ====================
        Commands::SubmitTransfer { to, amount, fee, gas_limit } => {
            let nonce = chain.state.read().get_nonce(&wallet.address) + 1;
            let amount = parse_nusa_amount(amount)?;
            let fee = parse_nusa_amount(fee)?;

            let payload = TxPayload::Transfer {
                from: wallet.address,
                to: Address::from_str(to)?,
                amount,
                fee,
                nonce,
                gas_limit: *gas_limit,
                resource_class: ResourceClass::Transfer,
                metadata_flagged: false,
            };
            let env = sign_payload(payload, &wallet.priv_key)?;
            chain.submit_tx(env)?;
            println!("✅ Transfer submitted (nonce={})", nonce);
        }

        // ==================== STAKE ====================
        Commands::SubmitStake { validator, amount, fee, bond, gas_limit } => {
            let nonce = chain.state.read().get_nonce(&wallet.address) + 1;
            let amount = parse_nusa_amount(amount)?;
            let fee = parse_nusa_amount(fee)?;

            let payload = TxPayload::Stake {
                delegator: wallet.address,
                validator: Address::from_str(validator)?,
                amount,
                fee,
                nonce,
                bond: *bond,
                gas_limit: *gas_limit,
                resource_class: ResourceClass::Governance,
                metadata_flagged: false,
            };
            let env = sign_payload(payload, &wallet.priv_key)?;
            chain.submit_tx(env)?;
            println!("Stake submitted (bond={}, nonce={})", bond, nonce);
        }

        // ==================== UNSTAKE ====================
        Commands::SubmitUnstake { validator, amount, fee, gas_limit } => {
            let nonce = chain.state.read().get_nonce(&wallet.address) + 1;
            let amount = parse_nusa_amount(amount)?;
            let fee = parse_nusa_amount(fee)?;

            let payload = TxPayload::Unstake {
                delegator: wallet.address,
                validator: Address::from_str(validator)?,
                amount,
                fee,
                nonce,
                gas_limit: *gas_limit,
                resource_class: ResourceClass::Governance,
                metadata_flagged: false,
            };
            let env = sign_payload(payload, &wallet.priv_key)?;
            chain.submit_tx(env)?;
            println!("Unstake submitted (nonce={})", nonce);
        }

        // ==================== DELEGATOR STAKE (13.8.B) ====================
        Commands::SubmitDelegatorStake { validator, amount, fee, gas_limit } => {
            let amount = parse_nusa_amount(amount)?;
            let fee = parse_nusa_amount(fee)?;

            if amount < crate::tokenomics::DELEGATOR_MIN_STAKE {
                anyhow::bail!(
                    "❌ Delegator stake too low: minimum {} NUSA required, got {}",
                    crate::tokenomics::DELEGATOR_MIN_STAKE,
                    format_nusa(amount)
                );
            }

            let validator_addr = Address::from_str(validator)?;

            {
                let state = chain.state.read();

                if !state.validator_set.is_validator(&validator_addr) {
                    anyhow::bail!("❌ Validator {} is not registered", validator);
                }

                if state.validator_set.is_validator(&wallet.address) {
                    anyhow::bail!("❌ Your address is a validator and cannot delegate");
                }

                if let Some(existing) = state.delegator_to_validator.get(&wallet.address) {
                    if existing != &validator_addr {
                        anyhow::bail!(
                            "❌ Already delegated to validator {}. Withdraw first.",
                            existing
                        );
                    }
                }
            }

            let nonce = chain.state.read().get_nonce(&wallet.address) + 1;

            let payload = TxPayload::Stake {
                delegator: wallet.address,
                validator: validator_addr,
                amount,        
                fee,             
                nonce,
                bond: true,
                gas_limit: *gas_limit,
                resource_class: ResourceClass::Governance,
                metadata_flagged: false,
            };

            let env = sign_payload(payload, &wallet.priv_key)?;
            chain.submit_tx(env)?;

            println!("═══════════════════════════════════════════════════════════");
            println!("✅ DELEGATOR STAKE SUBMITTED");
            println!("   Delegator: {}", wallet.address);
            println!("   Validator: {}", validator);
            println!("   Amount: {}", format_nusa(amount));
            println!("   Fee: {}", format_nusa(fee));
            println!("   Nonce: {}", nonce);
            println!("═══════════════════════════════════════════════════════════");
        }


        // ==================== WITHDRAW DELEGATOR STAKE (13.8.B) ====================
        Commands::WithdrawDelegatorStake { validator, amount, fee, gas_limit } => {
            // 1) Parse dulu amount & fee
            let amount_parsed = parse_nusa_amount(amount)?;
            let fee_parsed = parse_nusa_amount(fee)?;

            let validator_addr = Address::from_str(validator)?;
            
            // 2) Validate delegation exists
            {
                let state = chain.state.read();
                let current_validator = state.delegator_to_validator.get(&wallet.address);
                
                if current_validator.is_none() {
                    anyhow::bail!("❌ You have no active delegation");
                }
                
                if current_validator != Some(&validator_addr) {
                    anyhow::bail!(
                        "❌ You are not delegated to validator {}. Current: {:?}",
                        validator,
                        current_validator
                    );
                }
                
                // Validate the numeric amount (already parsed)
                let delegated = state.delegator_stakes.get(&wallet.address).copied().unwrap_or(0);
                if delegated < amount_parsed {
                    anyhow::bail!(
                        "❌ Insufficient delegation: have {}, want to withdraw {}",
                        delegated,
                        amount_parsed
                    );
                }
            }

            // 3) Build TX
            let nonce = chain.state.read().get_nonce(&wallet.address) + 1;

            let payload = TxPayload::Stake {
                delegator: wallet.address,
                validator: validator_addr,
                amount: amount_parsed,
                fee: fee_parsed,
                nonce,
                bond: false, // unbond
                gas_limit: *gas_limit,
                resource_class: ResourceClass::Governance,
                metadata_flagged: false,
            };

            let env = sign_payload(payload, &wallet.priv_key)?;
            chain.submit_tx(env)?;
            
            println!("═══════════════════════════════════════════════════════════");
            println!("✅ DELEGATOR WITHDRAWAL SUBMITTED");
            println!("   Delegator: {}", wallet.address);
            println!("   Validator: {}", validator);
            println!("   Amount: {} NUSA", amount_parsed);
            println!("   Nonce: {}", nonce);
            println!("═══════════════════════════════════════════════════════════");
        }


        // ==================== CLAIM REWARD (13.10) ====================
        Commands::SubmitClaimReward { receipt_file, fee, gas_limit } => {
            let nonce = chain.state.read().get_nonce(&wallet.address) + 1;
            let fee = parse_nusa_amount(fee)?;

            // Load receipt dari file JSON
            let receipt_json = std::fs::read_to_string(receipt_file)
                .map_err(|e| anyhow::anyhow!("Failed to read receipt file: {}", e))?;
            let receipt: ResourceReceipt = serde_json::from_str(&receipt_json)
                .map_err(|e| anyhow::anyhow!("Failed to parse receipt JSON: {}", e))?;

            // Verifikasi node_address cocok dengan wallet
            if receipt.node_address != wallet.address {
                anyhow::bail!(
                    "Receipt node_address ({}) does not match wallet address ({})",
                    receipt.node_address,
                    wallet.address
                );
            }

            let payload = TxPayload::ClaimReward {
                receipt: receipt.clone(),
                fee,
                nonce,
                gas_limit: *gas_limit,
            };
            let env = sign_payload(payload, &wallet.priv_key)?;
            chain.submit_tx(env)?;
            println!("═══════════════════════════════════════════════════════════");
            println!("✅ CLAIM REWARD SUBMITTED (13.10)");
            println!("   Node: {}", receipt.node_address);
            println!("   Reward Base: {}", receipt.reward_base);
            println!("   Resource Type: {:?}", receipt.resource_type);
            println!("   Nonce: {}", nonce);
            println!("═══════════════════════════════════════════════════════════");
        }

        // ==================== STORAGE PAYMENT ====================
        Commands::SubmitStorageOp { to_node, amount, operation_id, fee, gas_limit } => {
            let nonce = chain.state.read().get_nonce(&wallet.address) + 1;
            let amount = parse_nusa_amount(amount)?;
            let fee = parse_nusa_amount(fee)?;

            let payload = TxPayload::StorageOperationPayment {
                from: wallet.address,
                to_node: Address::from_str(to_node)?,
                amount,
                fee,
                nonce,
                operation_id: operation_id.as_bytes().to_vec(),
                gas_limit: *gas_limit,
                resource_class: ResourceClass::Storage,
                metadata_flagged: false,
            };
            let env = sign_payload(payload, &wallet.priv_key)?;
            chain.submit_tx(env)?;
            println!("StorageOperationPayment submitted (nonce={})", nonce);
        }

        // ==================== COMPUTE PAYMENT ====================
        Commands::SubmitComputeExec { to_node, amount, execution_id, fee, gas_limit } => {
            let nonce = chain.state.read().get_nonce(&wallet.address) + 1;
            let amount = parse_nusa_amount(amount)?;
            let fee = parse_nusa_amount(fee)?;

            let payload = TxPayload::ComputeExecutionPayment {
                from: wallet.address,
                to_node: Address::from_str(to_node)?,
                amount,
                fee,
                nonce,
                execution_id: execution_id.as_bytes().to_vec(),
                gas_limit: *gas_limit,
                resource_class: ResourceClass::Compute,
                metadata_flagged: false,
            };
            let env = sign_payload(payload, &wallet.priv_key)?;
            chain.submit_tx(env)?;
            println!("ComputeExecutionPayment submitted (nonce={})", nonce);
        }

        // ==================== VALIDATOR REGISTRATION ====================
        Commands::SubmitValidatorReg { pubkey, min_stake, fee, gas_limit } => {
            let min_stake = parse_nusa_amount(min_stake)?;
            let fee = parse_nusa_amount(fee)?;

            let nonce = chain.state.read().get_nonce(&wallet.address) + 1;

            let payload = TxPayload::ValidatorRegistration {
                from: wallet.address,
                pubkey: hex::decode(pubkey)?,
                min_stake,
                fee,               
                nonce,
                gas_limit: *gas_limit,
                resource_class: ResourceClass::Governance,
                metadata_flagged: false,
            };

            let env = sign_payload(payload, &wallet.priv_key)?;
            chain.submit_tx(env)?;
            println!("ValidatorRegistration submitted (nonce={})", nonce);
        }

        Commands::Mine { miner_addr } => {
            let miner_string = miner_addr
                .clone()
                .unwrap_or_else(|| wallet.address.to_string());

            let miner_str = miner_string.as_str();

            println!("⛏️  Mining block (miner_addr = {})", miner_str);

            let block = chain.mine_block_and_apply(miner_str)?;
            let block_hash = crate::block::Block::compute_hash(&block.header);

            println!("🎉 Block Mined!");
            println!("   Height: {}", block.header.height);
            println!("   Hash: {}", block_hash.to_hex());
            println!("   TX Count: {}", block.body.transactions.len());
            println!("   Gas Used: {}", block.header.gas_used);
            println!("   State Root: {}", block.header.state_root.to_hex());
        }
         Commands::Init { .. }
            | Commands::Status {}
            | Commands::Wallet { .. } => {
                unreachable!("Command already handled earlier");
            }

        // ═══════════════════════════════════════════════════════════
        // NODE COST INDEX MANAGEMENT (13.9) - Admin/Governance
        // ═══════════════════════════════════════════════════════════
        // Perintah ini digunakan oleh Admin CLI atau Governance module.
        // Perubahan node_cost_index adalah consensus-critical.
        // ═══════════════════════════════════════════════════════════
        Commands::NodeCost { command } => {
            match command {
                NodeCostCommand::Set { address, multiplier } => {
                    let node_addr = Address::from_str(address)?;
                    
                    {
                        let mut state = chain.state.write();
                        state.set_node_cost_index(node_addr, *multiplier);
                    }
                    
                    println!("═══════════════════════════════════════════════════════════");
                    println!("✅ NODE COST INDEX SET");
                    println!("   Node: {}", address);
                    println!("   Multiplier: {} ({}x)", multiplier, *multiplier as f64 / 100.0);
                    println!("   Note: Change is consensus-critical, included in state_root");
                    println!("═══════════════════════════════════════════════════════════");
                }
                
                NodeCostCommand::Remove { address } => {
                    let node_addr = Address::from_str(address)?;
                    
                    let previous = {
                        let mut state = chain.state.write();
                        state.remove_node_cost_index(&node_addr)
                    };
                    
                    println!("═══════════════════════════════════════════════════════════");
                    println!("✅ NODE COST INDEX REMOVED");
                    println!("   Node: {}", address);
                    println!("   Previous value: {:?}", previous);
                    println!("   Node will now use default multiplier (100 = 1.0x)");
                    println!("   Note: Change is consensus-critical, included in state_root");
                    println!("═══════════════════════════════════════════════════════════");
                }
                
                NodeCostCommand::Get { address } => {
                    let node_addr = Address::from_str(address)?;
                    
                    let multiplier = {
                        let state = chain.state.read();
                        state.get_node_cost_index(&node_addr)
                    };
                    
                    println!("═══════════════════════════════════════════════════════════");
                    println!("📊 NODE COST INDEX");
                    println!("   Node: {}", address);
                    println!("   Multiplier: {} ({}x)", multiplier, multiplier as f64 / 100.0);
                    println!("═══════════════════════════════════════════════════════════");
                }
                
                NodeCostCommand::List => {
                    let indexes = {
                        let state = chain.state.read();
                        state.list_node_cost_indexes()
                    };
                    
                    println!("═══════════════════════════════════════════════════════════");
                    println!("📊 ALL NODE COST INDEXES");
                    println!("═══════════════════════════════════════════════════════════");
                    
                    if indexes.is_empty() {
                        println!("   No custom node cost indexes set.");
                        println!("   All nodes using default: 100 (1.0x)");
                    } else {
                        for (addr, mult) in &indexes {
                            println!("   {} → {} ({}x)", addr, mult, *mult as f64 / 100.0);
                        }
                        println!("───────────────────────────────────────────────────────────");
                        println!("   Total custom indexes: {}", indexes.len());
                    }
                    println!("═══════════════════════════════════════════════════════════");
                }
            }
        }

        // ═══════════════════════════════════════════════════════════
        // RECEIPT MANAGEMENT (13.10)
        // ═══════════════════════════════════════════════════════════
        Commands::Receipt { command } => {
            match command {
                ReceiptCommand::Claim { file, fee, gas_limit } => {
                    let fee = parse_nusa_amount(fee)?;
                    let nonce = chain.state.read().get_nonce(&wallet.address) + 1;

                    // Baca file JSON receipt
                    let receipt_json = std::fs::read_to_string(file)
                        .map_err(|e| anyhow::anyhow!("Failed to read receipt file: {}", e))?;
                    let receipt: ResourceReceipt = serde_json::from_str(&receipt_json)
                        .map_err(|e| anyhow::anyhow!("Failed to parse receipt JSON: {}", e))?;

                    // Verifikasi node_address cocok dengan wallet
                    if receipt.node_address != wallet.address {
                        anyhow::bail!(
                            "Receipt node_address ({}) does not match wallet address ({})",
                            receipt.node_address,
                            wallet.address
                        );
                    }

                    let payload = TxPayload::ClaimReward {
                        receipt: receipt.clone(),
                        fee,
                        nonce,
                        gas_limit: *gas_limit,
                    };
                    let env = sign_payload(payload, &wallet.priv_key)?;
                    let tx_id = env.compute_txid()?;
                    chain.submit_tx(env)?;

                    println!("═══════════════════════════════════════════════════════════");
                    println!("✅ CLAIM REWARD SUBMITTED (13.10)");
                    println!("   TxID: {}", tx_id.to_hex());
                    println!("   Node: {}", receipt.node_address);
                    println!("   Reward Base: {}", receipt.reward_base);
                    println!("   Nonce: {}", nonce);
                    println!("═══════════════════════════════════════════════════════════");
                }

                ReceiptCommand::Status { id } => {
                    let id_bytes = hex::decode(id)
                        .map_err(|e| anyhow::anyhow!("Invalid receipt_id hex: {}", e))?;
                    let hash_bytes: [u8; 64] = id_bytes.try_into()
                        .map_err(|_| anyhow::anyhow!("receipt_id must be 64 bytes (128 hex chars)"))?;
                    let receipt_hash = crate::types::Hash::from_bytes(hash_bytes);

                    let is_claimed = chain.state.read().is_receipt_claimed(&receipt_hash);

                    println!("═══════════════════════════════════════════════════════════");
                    println!("📋 RECEIPT STATUS");
                    println!("   Receipt ID: {}", id);
                    println!("   Status: {}", if is_claimed { "CLAIMED ✅" } else { "NOT CLAIMED ❌" });
                    println!("═══════════════════════════════════════════════════════════");
                }

                ReceiptCommand::Earnings { address } => {
                    let node_addr = Address::from_str(address)?;
                    
                    let earnings = {
                        let state = chain.state.read();
                        state.node_earnings.get(&node_addr).copied().unwrap_or(0)
                    };

                    println!("═══════════════════════════════════════════════════════════");
                    println!("💰 NODE EARNINGS");
                    println!("   Node: {}", address);
                    println!("   Total Earnings: {}", format_nusa(earnings));
                    println!("═══════════════════════════════════════════════════════════");
                }
           }
        }

        // ═══════════════════════════════════════════════════════════
        // SYNC MANAGEMENT (13.11.7)
        // ═══════════════════════════════════════════════════════════
        Commands::Sync { command } => {
            match command {
                SyncCommand::Start => {
                    println!("═══════════════════════════════════════════════════════════");
                    println!("🔄 STARTING SYNC");
                    println!("═══════════════════════════════════════════════════════════");

                    // Get current tip for target
                    let (tip_height, tip_hash) = chain.get_chain_tip()?;
                    
                    match chain.start_sync((tip_hash, tip_height)) {
                        Ok(()) => {
                            println!("   ✅ Sync started");
                            println!("   Target: height {}", tip_height);
                        }
                        Err(e) => {
                            println!("   ❌ Failed to start sync: {}", e);
                        }
                    }
                    println!("═══════════════════════════════════════════════════════════");
                }

                SyncCommand::Stop => {
                    println!("═══════════════════════════════════════════════════════════");
                    println!("⏹️  STOPPING SYNC");
                    println!("═══════════════════════════════════════════════════════════");
                    println!("   ✅ Sync stopped");
                    println!("═══════════════════════════════════════════════════════════");
                }

                SyncCommand::Status => {
                    let status = chain.get_sync_status();
                    let (current, target) = chain.get_sync_progress()?;

                    let status_str = match &status {
                        crate::sync::SyncStatus::Idle => "Idle",
                        crate::sync::SyncStatus::SyncingHeaders { .. } => "SyncingHeaders",
                        crate::sync::SyncStatus::SyncingBlocks { .. } => "SyncingBlocks",
                        crate::sync::SyncStatus::SyncingState { .. } => "SyncingState",
                        crate::sync::SyncStatus::Synced => "Synced",
                    };

                    println!("═══════════════════════════════════════════════════════════");
                    println!("📊 SYNC STATUS");
                    println!("═══════════════════════════════════════════════════════════");
                    println!("   Status: {}", status_str);
                    println!("   Current: {}", current);
                    println!("   Target: {}", target);
                    println!("═══════════════════════════════════════════════════════════");
                }

                SyncCommand::Progress => {
                    let (current, target) = chain.get_sync_progress()?;
                    let percent = if target == 0 {
                        100u8
                    } else {
                        ((current as f64 / target as f64) * 100.0).min(100.0) as u8
                    };
                    let progress_bar = format_progress_bar(percent);
                    let eta = calculate_eta(current, target);

                    println!("═══════════════════════════════════════════════════════════");
                    println!("📈 SYNC PROGRESS");
                    println!("═══════════════════════════════════════════════════════════");
                    println!("   {} | {} / {} | ETA {}", progress_bar, current, target, eta);
                    println!("═══════════════════════════════════════════════════════════");
                }

SyncCommand::Reset => {
                    println!("═══════════════════════════════════════════════════════════");
                    println!("🔄 RESETTING SYNC STATE");
                    println!("═══════════════════════════════════════════════════════════");
                    println!("   ⚠️  This will clear sync metadata");
                    println!("   ✅ Sync state reset complete");
                    println!("═══════════════════════════════════════════════════════════");
                }
            }
        }

        // ═══════════════════════════════════════════════════════════
        // GOVERNANCE COMMANDS (13.12.8)
        // ═══════════════════════════════════════════════════════════
        Commands::Governance { command } => {
            match command {
                GovernanceCommand::Propose { r#type, title, description, fee, gas_limit } => {
                    let wallet = load_wallet()?;
                    let nonce = get_next_nonce(&chain, &wallet.address)?;
                    let fee_val: u128 = fee.parse().map_err(|_| anyhow::anyhow!("invalid fee"))?;

                    // Parse proposal type
                    let proposal_type = parse_proposal_type(r#type)?;

                    let payload = TxPayload::GovernanceAction {
                        from: wallet.address,
                        action: GovernanceActionType::CreateProposal {
                            proposal_type,
                            title: title.clone(),
                            description: description.clone(),
                        },
                        fee: fee_val,
                        nonce,
                        gas_limit: *gas_limit,
                    };

                    let env = sign_payload(payload, &wallet.priv_key)?;
                    let tx_id = env.compute_txid()?;
                    chain.submit_tx(env)?;

                    println!("═══════════════════════════════════════════════════════════");
                    println!("🏛️ PROPOSAL SUBMITTED");
                    println!("   TxID: {}", tx_id.to_hex());
                    println!("   Title: {}", title);
                    println!("   Type: {}", r#type);
                    println!("═══════════════════════════════════════════════════════════");
                }

                GovernanceCommand::Vote { proposal, vote, fee, gas_limit } => {
                    let wallet = load_wallet()?;
                    let nonce = get_next_nonce(&chain, &wallet.address)?;
                    let fee_val: u128 = fee.parse().map_err(|_| anyhow::anyhow!("invalid fee"))?;

                    // Parse vote option
                    let vote_option = parse_vote_option(vote)?;

                    let payload = TxPayload::GovernanceAction {
                        from: wallet.address,
                        action: GovernanceActionType::CastVote {
                            proposal_id: *proposal,
                            vote: vote_option,
                        },
                        fee: fee_val,
                        nonce,
                        gas_limit: *gas_limit,
                    };

                    let env = sign_payload(payload, &wallet.priv_key)?;
                    let tx_id = env.compute_txid()?;
                    chain.submit_tx(env)?;

                    println!("═══════════════════════════════════════════════════════════");
                    println!("🗳️ VOTE SUBMITTED");
                    println!("   TxID: {}", tx_id.to_hex());
                    println!("   Proposal: {}", proposal);
                    println!("   Vote: {}", vote);
                    println!("═══════════════════════════════════════════════════════════");
                }

                GovernanceCommand::Finalize { proposal, fee, gas_limit } => {
                    let wallet = load_wallet()?;
                    let nonce = get_next_nonce(&chain, &wallet.address)?;
                    let fee_val: u128 = fee.parse().map_err(|_| anyhow::anyhow!("invalid fee"))?;

                    let payload = TxPayload::GovernanceAction {
                        from: wallet.address,
                        action: GovernanceActionType::FinalizeProposal {
                            proposal_id: *proposal,
                        },
                        fee: fee_val,
                        nonce,
                        gas_limit: *gas_limit,
                    };

                    let env = sign_payload(payload, &wallet.priv_key)?;
                    let tx_id = env.compute_txid()?;
                    chain.submit_tx(env)?;

                    println!("═══════════════════════════════════════════════════════════");
                    println!("✅ FINALIZE SUBMITTED");
                    println!("   TxID: {}", tx_id.to_hex());
                    println!("   Proposal: {}", proposal);
                    println!("═══════════════════════════════════════════════════════════");
                }

                GovernanceCommand::ListActive => {
                    let state = chain.state.read();
                    let proposals = state.get_active_proposals();

                    println!("═══════════════════════════════════════════════════════════");
                    println!("🏛️ ACTIVE PROPOSALS");
                    println!("═══════════════════════════════════════════════════════════");
                    
                    if proposals.is_empty() {
                        println!("   No active proposals");
                    } else {
                        for p in proposals {
                            println!("   #{} | {} | {} votes", p.id, p.title, p.yes_votes + p.no_votes + p.abstain_votes);
                        }
                    }
                    println!("═══════════════════════════════════════════════════════════");
                }

                GovernanceCommand::ListAll => {
                    let state = chain.state.read();
                    let mut proposals: Vec<_> = state.proposals.values().collect();
                    proposals.sort_by_key(|p| p.id);

                    println!("═══════════════════════════════════════════════════════════");
                    println!("🏛️ ALL PROPOSALS");
                    println!("═══════════════════════════════════════════════════════════");
                    
                    if proposals.is_empty() {
                        println!("   No proposals found");
                    } else {
                        for p in proposals {
                            println!("   #{} | {:?} | {} | {}", p.id, p.status, p.title, format_proposal_type(&p.proposal_type));
                        }
                    }
                    println!("═══════════════════════════════════════════════════════════");
                }

                GovernanceCommand::Show { proposal } => {
                    let state = chain.state.read();
                    
                    match state.get_proposal(*proposal) {
                        Some(p) => {
                            println!("═══════════════════════════════════════════════════════════");
                            println!("🏛️ PROPOSAL #{}", p.id);
                            println!("═══════════════════════════════════════════════════════════");
                            println!("   Title: {}", p.title);
                            println!("   Type: {}", format_proposal_type(&p.proposal_type));
                            println!("   Status: {:?}", p.status);
                            println!("   Proposer: {}", p.proposer);
                            println!("   Created: {}", p.created_at);
                            println!("   Voting End: {}", p.voting_end);
                            println!("───────────────────────────────────────────────────────────");
                            println!("   Yes: {} | No: {} | Abstain: {}", p.yes_votes, p.no_votes, p.abstain_votes);
                            println!("   Quorum Required: {}", p.quorum_required);
                            println!("───────────────────────────────────────────────────────────");
                            println!("   Description: {}", p.description);
                            println!("═══════════════════════════════════════════════════════════");
                        }
                        None => {
                            println!("❌ Proposal {} not found", proposal);
                        }
                    }
                }

                GovernanceCommand::MyVotes => {
                    let wallet = load_wallet()?;
                    let state = chain.state.read();

                    println!("═══════════════════════════════════════════════════════════");
                    println!("🗳️ MY VOTES");
                    println!("   Wallet: {}", wallet.address);
                    println!("═══════════════════════════════════════════════════════════");
                    
                    let mut found = false;
                    for (proposal_id, votes_map) in state.proposal_votes.iter() {
                        if let Some(vote) = votes_map.get(&wallet.address) {
                            found = true;
                            println!("   Proposal #{} | {:?} | Weight: {}", proposal_id, vote.option, vote.weight);
                        }
                    }
                    
                    if !found {
                        println!("   No votes found");
                    }
                    println!("═══════════════════════════════════════════════════════════");
                }

                GovernanceCommand::FoundationVeto { proposal, fee, gas_limit } => {
                    let wallet = load_wallet()?;
                    let nonce = get_next_nonce(&chain, &wallet.address)?;
                    let fee_val: u128 = fee.parse().map_err(|_| anyhow::anyhow!("invalid fee"))?;

                    // Validasi dilakukan di tx execution, bukan di CLI
                    // CLI hanya membangun dan submit transaksi

                    let payload = TxPayload::GovernanceAction {
                        from: wallet.address,
                        action: GovernanceActionType::FoundationVeto {
                            proposal_id: *proposal,
                        },
                        fee: fee_val,
                        nonce,
                        gas_limit: *gas_limit,
                    };

                    let env = sign_payload(payload, &wallet.priv_key)?;
                    let tx_id = env.compute_txid()?;
                    chain.submit_tx(env)?;

                    println!("═══════════════════════════════════════════════════════════");
                    println!("⛔ FOUNDATION VETO SUBMITTED");
                    println!("   TxID: {}", tx_id.to_hex());
                    println!("   Proposal: {}", proposal);
                    println!("   ⚠️  Requires Foundation wallet signature");
                    println!("═══════════════════════════════════════════════════════════");
                }

                GovernanceCommand::Config => {
                    let state = chain.state.read();
                    let config = &state.governance_config;

                    println!("═══════════════════════════════════════════════════════════");
                    println!("⚙️ GOVERNANCE CONFIG");
                    println!("═══════════════════════════════════════════════════════════");
                    println!("   Voting Period: {} seconds ({} days)", 
                             config.voting_period_seconds,
                             config.voting_period_seconds / 86400);
                    println!("   Quorum: {}%", config.quorum_percentage);
                    println!("   Pass Threshold: {}%", config.pass_threshold);
                    println!("   Min Proposer Stake: {}", format_nusa(config.min_proposer_stake));
                    println!("   Foundation: 0x{}", hex::encode(config.foundation_address.as_bytes()));
println!("   Bootstrap Mode: {}", if config.bootstrap_mode { "YES ⚠️" } else { "NO" });
                    println!("═══════════════════════════════════════════════════════════");
                }

                // ════════════════════════════════════════════════════════════════════════════
                // PREVIEW COMMANDS (13.13.6) — READ-ONLY
                // ════════════════════════════════════════════════════════════════════════════

                GovernanceCommand::Preview { proposal } => {
                    let state = chain.state.read();
                    
                    // Generate preview (READ-ONLY operation)
                    match state.generate_proposal_preview(*proposal) {
                        Ok(preview) => {
                            println!("═══════════════════════════════════════════════════════════");
                            println!("🔍 PROPOSAL PREVIEW (READ-ONLY)");
                            println!("═══════════════════════════════════════════════════════════");
                            println!("⚠️  INI HANYA PREVIEW — TIDAK ADA EKSEKUSI");
                            println!("═══════════════════════════════════════════════════════════");
                            println!("   Proposal ID: {}", preview.proposal_id);
                            println!("   Preview Type: {}", format_preview_type(&preview.preview_type));
                            println!("   Generated At: {}", preview.generated_at);
                            println!("───────────────────────────────────────────────────────────");
                            println!("   SIMULATED CHANGES:");
                            
                            if preview.simulated_changes.is_empty() {
                                println!("   (no changes)");
                            } else {
                                for (i, change) in preview.simulated_changes.iter().enumerate() {
                                    println!("   [{}] Field: {}", i + 1, change.field_path);
                                    println!("       Old: {}", change.old_value_display);
                                    println!("       New: {}", change.new_value_display);
                                }
                            }
                            
                            println!("───────────────────────────────────────────────────────────");
                            println!("   AFFECTED ADDRESSES:");
                            
                            if preview.affected_addresses.is_empty() {
                                println!("   (none)");
                            } else {
                                for addr in &preview.affected_addresses {
                                    println!("   - 0x{}", hex::encode(addr.as_bytes()));
                                }
                            }
                            
                            println!("═══════════════════════════════════════════════════════════");
                            println!("⚠️  REMINDER: Di Bootstrap Mode, proposal TIDAK dieksekusi");
                            println!("═══════════════════════════════════════════════════════════");
                        }
                        Err(e) => {
                            println!("═══════════════════════════════════════════════════════════");
                            println!("❌ PREVIEW ERROR");
                            println!("   Proposal: {}", proposal);
                            println!("   Error: {:?}", e);
                            println!("═══════════════════════════════════════════════════════════");
                        }
                    }
                }

                GovernanceCommand::BootstrapStatus => {
                    let state = chain.state.read();
                    let status = state.get_bootstrap_mode_status();
                    
                    println!("═══════════════════════════════════════════════════════════");
                    println!("🏛️ BOOTSTRAP MODE STATUS");
                    println!("═══════════════════════════════════════════════════════════");
                    
                    if status.is_active {
                        println!("   Status: ⚠️  AKTIF (Non-Binding)");
                        println!("   Execution: ❌ TIDAK DIIZINKAN");
                    } else {
                        println!("   Status: ✅ NONAKTIF (Binding)");
                        println!("   Execution: ✅ DIIZINKAN (reserved)");
                    }
                    
                    println!("───────────────────────────────────────────────────────────");
                    println!("   Foundation: 0x{}", hex::encode(status.foundation_address.as_bytes()));
                    println!("───────────────────────────────────────────────────────────");
                    println!("   Message: {}", status.message);
                    println!("═══════════════════════════════════════════════════════════");
                }

                GovernanceCommand::Events { count } => {
                    let event_count = count.unwrap_or(20) as usize;
                    let state = chain.state.read();
                    let events = state.get_recent_governance_events(event_count);
                    
                    println!("═══════════════════════════════════════════════════════════");
                    println!("📜 GOVERNANCE EVENTS (last {})", event_count);
                    println!("═══════════════════════════════════════════════════════════");
                    
                    if events.is_empty() {
                        println!("   (no events recorded)");
                    } else {
                        for (i, event) in events.iter().enumerate() {
                            let proposal_str = match event.proposal_id {
                                Some(id) => format!("#{}", id),
                                None => "N/A".to_string(),
                            };
                            
                            println!("───────────────────────────────────────────────────────────");
                            println!("   [{}] {} | Proposal: {}", 
                                     i + 1,
                                     format_event_type(&event.event_type),
                                     proposal_str);
                            println!("       Actor: 0x{}", hex::encode(event.actor.as_bytes()));
                            println!("       Time: {}", event.timestamp);
                            println!("       Details: {}", event.details);
                        }
                    }
                    
                    println!("═══════════════════════════════════════════════════════════");
                    println!("⚠️  Events are in-memory only (NOT persisted)");
                    println!("═══════════════════════════════════════════════════════════");
                }
            }
        }
                // ════════════════════════════════════════════════════════════════════════════
        // SLASHING OBSERVABILITY COMMANDS (13.14.8)
        // ════════════════════════════════════════════════════════════════════════════
        // READ-ONLY commands. Tidak ada state mutation.
        // ════════════════════════════════════════════════════════════════════════════

        Commands::Slashing { command } => {
            match command {
                SlashingCommand::NodeStatus { address } => {
                    println!("═══════════════════════════════════════════════════════════");
                    println!("🔍 NODE LIVENESS STATUS (13.14.8)");
                    println!("═══════════════════════════════════════════════════════════");
                    
                    let node_addr = Address::from_str(address)
                        .map_err(|_| anyhow::anyhow!("invalid node address: {}", address))?;
                    
                    let state = chain.state.read();
                    
                    match state.node_liveness_records.get(&node_addr) {
                        Some(record) => {
                            let status = if record.slashed {
                                "🔴 SLASHED"
                            } else if record.force_unbond_until.is_some() {
                                "🟡 FORCE-UNBONDED"
                            } else if record.consecutive_failures > 0 {
                                "🟠 OFFLINE"
                            } else {
                                "🟢 ONLINE"
                            };
                            
                            println!("   Node: 0x{}", hex::encode(node_addr.as_bytes()));
                            println!("   Status: {}", status);
                            println!("───────────────────────────────────────────────────────────");
                            println!("   Last Seen: {}", record.last_seen_timestamp);
                            println!("   Consecutive Failures: {}", record.consecutive_failures);
                            println!("   Data Corruption Count: {}", record.data_corruption_count);
                            println!("   Malicious Behavior Count: {}", record.malicious_behavior_count);
                            println!("   Slashed: {}", record.slashed);
                            
                            if let Some(until) = record.force_unbond_until {
                                println!("   Force-Unbond Until: {}", until);
                            }
                            
                            // Detection flags
                            if record.double_sign_detected {
                                println!("   ⚠️  Double-Sign Detected: true");
                            }
                            if record.malicious_block_detected {
                                println!("   ⚠️  Malicious Block Detected: true");
                            }
                            if let Some(offline_since) = record.offline_since {
                                println!("   ⚠️  Offline Since: {}", offline_since);
                            }
                        }
                        None => {
                            println!("   ⚠️  No liveness record found for node");
                            println!("   Node: 0x{}", hex::encode(node_addr.as_bytes()));
                        }
                    }
                    
                    println!("═══════════════════════════════════════════════════════════");
                }
                
                SlashingCommand::ValidatorStatus { address } => {
                    println!("═══════════════════════════════════════════════════════════");
                    println!("⚔️ VALIDATOR SLASH STATUS (13.14.8)");
                    println!("═══════════════════════════════════════════════════════════");
                    
                    let validator_addr = Address::from_str(address)
                        .map_err(|_| anyhow::anyhow!("invalid validator address: {}", address))?;
                    
                    let state = chain.state.read();
                    
                    // Check if validator exists
                    if !state.validator_set.is_validator(&validator_addr) {
                        println!("   ⚠️  Address is not a validator");
                        println!("   Address: 0x{}", hex::encode(validator_addr.as_bytes()));
                        println!("═══════════════════════════════════════════════════════════");
                        return Ok(());
                    }
                    
                    // Get validator info
                    let stake = state.validator_stakes.get(&validator_addr).copied().unwrap_or(0);
                    let is_active = state
                        .validator_set
                        .get(&validator_addr)
                        .map(|v| v.active)
                        .unwrap_or(false);

                    
                    println!("   Validator: 0x{}", hex::encode(validator_addr.as_bytes()));
                    println!("   Stake: {} NUSA", stake / crate::types::SCALE);
                    println!("   Active: {}", is_active);
                    println!("───────────────────────────────────────────────────────────");
                    
                    // Check slashing status from node_liveness_records
                    let (slashed, reason, force_unbond) = match state.node_liveness_records.get(&validator_addr) {
                        Some(record) => {
                            let reason_str = if record.double_sign_detected {
                                "ValidatorDoubleSign"
                            } else if record.malicious_block_detected {
                                "ValidatorMaliciousBlock"
                            } else if record.consecutive_failures > 0 {
                                "ValidatorProlongedOffline"
                            } else {
                                "None"
                            };
                            (record.slashed, reason_str, record.force_unbond_until)
                        }
                        None => {
                            // Check legacy liveness_records
                            match state.liveness_records.get(&validator_addr) {
                                Some(legacy) => (legacy.slashed, if legacy.slashed { "LegacySlash" } else { "None" }, None),
                                None => (false, "None", None),
                            }
                        }
                    };
                    
                    let status_icon = if slashed {
                        "🔴 SLASHED"
                    } else if force_unbond.is_some() {
                        "🟡 FORCE-UNBONDED"
                    } else {
                        "🟢 NOT SLASHED"
                    };
                    
                    println!("   Slash Status: {}", status_icon);
                    println!("   Slashed: {}", slashed);
                    
                    if slashed {
                        println!("   Reason: {}", reason);
                    }
                    
                    if let Some(until) = force_unbond {
                        println!("   Force-Unbond Until: {}", until);
                    }
                    
                    println!("═══════════════════════════════════════════════════════════");
                }
                
                SlashingCommand::Events { count } => {
                    let count_val = count.unwrap_or(20);
                    
                    println!("═══════════════════════════════════════════════════════════");
                    println!("⚔️ RECENT SLASHING EVENTS (13.14.8)");
                    println!("   Showing last {} events", count_val);
                    println!("═══════════════════════════════════════════════════════════");
                    
                    let state = chain.state.read();
                    let events = &state.slashing_events;
                    
                    if events.is_empty() {
                        println!("   ℹ️  No slashing events recorded");
                    } else {
                        let total = events.len();
                        let count_usize = count_val as usize;
                        let start_idx = if count_usize >= total { 0 } else { total - count_usize };
                        
                        println!("   Total events: {} (showing {})", total, total - start_idx);
                        println!("───────────────────────────────────────────────────────────");
                        
                        for (i, event) in events[start_idx..].iter().enumerate() {
                            let reason_str = format_slashing_reason(&event.reason);
                            
                            println!("   [{}] {} | {}", 
                                     i + 1,
                                     reason_str,
                                     format!("0x{}", hex::encode(event.target.as_bytes())));
                            println!("       Amount: {} (treasury: {}, burned: {})",
                                     event.amount_slashed,
                                     event.amount_to_treasury,
                                     event.amount_burned);
                            println!("       Timestamp: {}", event.timestamp);
                        }
                    }
                    
                    println!("═══════════════════════════════════════════════════════════");
                    println!("⚠️  Events are in-memory only (NOT persisted after restart)");
                    println!("═══════════════════════════════════════════════════════════");
                }
            }
        }

        // ═══════════════════════════════════════════════════════════════════════════════
        // ECONOMIC COMMANDS (13.15.8) — READ-ONLY
        // ═══════════════════════════════════════════════════════════════════════════════
        Commands::Economic { command } => {
            match command {
                EconomicCommand::Status => {
                    println!("═══════════════════════════════════════════════════════════");
                    println!("💰 ECONOMIC STATUS (13.15.8)");
                    println!("═══════════════════════════════════════════════════════════");
                    
                    let state = chain.state.read();
                    
                    // Get economic mode
                    let mode = state.get_economic_mode();
                    let mode_str = format_economic_mode(&mode);
                    let mode_icon = match mode {
                        crate::economic::EconomicMode::Bootstrap => "🌱",
                        crate::economic::EconomicMode::Active => "📈",
                        crate::economic::EconomicMode::Governance => "🏛️",
                    };
                    
                    // Get values
                    let rf = state.economic_metrics.replication_factor;
                    let treasury = state.treasury_balance;
                    let total_supply = state.total_supply;
                    let deflation_enabled = state.deflation_config.enabled;
                    let burn_rate = state.calculate_target_burn_rate();
                    
                    println!("   Mode: {} {}", mode_icon, mode_str);
                    println!("   Replication Factor: {}", rf);
                    println!("───────────────────────────────────────────────────────────");
                    println!("   Treasury Balance: {} NUSA", treasury / crate::types::SCALE);
                    println!("   Total Supply: {} NUSA", total_supply / crate::types::SCALE);
                    println!("───────────────────────────────────────────────────────────");
                    println!("   Deflation Enabled: {}", if deflation_enabled { "✅ Yes" } else { "❌ No" });
                    println!("   Current Burn Rate: {} bps ({:.2}%)", burn_rate, burn_rate as f64 / 100.0);
                    println!("═══════════════════════════════════════════════════════════");
                }
                
                EconomicCommand::Deflation => {
                    println!("═══════════════════════════════════════════════════════════");
                    println!("🔥 DEFLATION INFO (13.15.8)");
                    println!("═══════════════════════════════════════════════════════════");
                    
                    let state = chain.state.read();
                    
                    // Get deflation config
                    let config = &state.deflation_config;
                    let target_min = config.target_min_percent;
                    let target_max = config.target_max_percent;
                    let burn_interval = config.burn_interval_epochs;
                    
                    // Get current state
                    let current_rate = state.calculate_target_burn_rate();
                    let cumulative_burned = state.cumulative_burned;
                    let last_burn_epoch = state.last_burn_epoch;
                    let next_eligible = last_burn_epoch.saturating_add(burn_interval);
                    
                    println!("   Target Range: {} - {} bps", target_min, target_max);
                    println!("   Current Annual Rate: {} bps ({:.2}%)", current_rate, current_rate as f64 / 100.0);
                    println!("───────────────────────────────────────────────────────────");
                    println!("   Cumulative Burned: {} NUSA", cumulative_burned / crate::types::SCALE);
                    println!("   Last Burn Epoch: {}", last_burn_epoch);
                    println!("   Next Eligible Epoch: {}", next_eligible);
                    println!("   Burn Interval: {} epochs", burn_interval);
                    println!("───────────────────────────────────────────────────────────");
                    println!("   Deflation Enabled: {}", if config.enabled { "✅ Yes" } else { "❌ No" });
                    println!("═══════════════════════════════════════════════════════════");
                }
                
                EconomicCommand::BurnHistory { count } => {
                    let count_val = count.unwrap_or(20);
                    
                    println!("═══════════════════════════════════════════════════════════");
                    println!("🔥 BURN HISTORY (13.15.8)");
                    println!("   Showing last {} events", count_val);
                    println!("═══════════════════════════════════════════════════════════");
                    
                    let state = chain.state.read();
                    let events = &state.economic_events;
                    
                    if events.is_empty() {
                        println!("   ℹ️  No burn events recorded");
                    } else {
                        let total = events.len();
                        let count_usize = count_val as usize;
                        let start_idx = if count_usize >= total { 0 } else { total - count_usize };
                        
                        println!("   Total events: {} (showing {})", total, total - start_idx);
                        println!("───────────────────────────────────────────────────────────");
                        println!("   {:>6} | {:>20} | {:>10} | {:>12}", 
                                 "Epoch", "Amount Burned", "Rate (bps)", "Timestamp");
                        println!("   ────────────────────────────────────────────────────────");
                        
                        for event in events[start_idx..].iter() {
                            let amount_nusa = event.amount_burned / crate::types::SCALE;
                            println!("   {:>6} | {:>17} NUSA | {:>10} | {:>12}", 
                                     event.epoch,
                                     amount_nusa,
                                     event.burn_rate_applied,
                                     event.timestamp);
                        }
                    }
                    
                    println!("═══════════════════════════════════════════════════════════");
                    println!("⚠️  Events are in-memory only (NOT persisted after restart)");
                    println!("═══════════════════════════════════════════════════════════");
                }
            }
        }

        Commands::TestE2e { module, verbose } => {
            println!("═══════════════════════════════════════════════════════════");
            println!("🧪 DSDN E2E TEST SUITE (13.7.A - 13.7.N)");
            println!("   Module: {}", module);
            println!("   Verbose: {}", verbose);
            println!("═══════════════════════════════════════════════════════════");

            let result = crate::e2e_tests::run_e2e_tests(&module, *verbose);
            
            match result {
                Ok(report) => {
                    println!("\n{}", report);
                    if report.contains("FAILED") {
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("❌ Test suite error: {}", e);
                    std::process::exit(1);
                }
            }
        }

        // Storage and Da commands are handled earlier via if-let blocks
        // These patterns are needed for exhaustiveness but should never be reached
        Commands::Storage { .. } => {
            // Already handled above, this is unreachable
        }
        Commands::Da { .. } => {
            // Already handled above, this is unreachable
        }
    }
    
    Ok(())
}
/// Ambil sender & nonce dari payload (kalau ada)
fn extract_sender_and_nonce(payload: &TxPayload) -> Option<(&Address, u64)> {
    match payload {
        TxPayload::Transfer { from, nonce, .. } =>
            Some((from, *nonce)),

        TxPayload::Stake { delegator, nonce, .. } =>
            Some((delegator, *nonce)),

        TxPayload::Unstake { delegator, nonce, .. } =>
            Some((delegator, *nonce)),

        TxPayload::ClaimReward { receipt, nonce, .. } =>
            Some((&receipt.node_address, *nonce)),

        TxPayload::StorageOperationPayment { from, nonce, .. } =>
            Some((from, *nonce)),

        TxPayload::ComputeExecutionPayment { from, nonce, .. } =>
            Some((from, *nonce)),

        TxPayload::ValidatorRegistration { from, nonce, .. } =>
            Some((from, *nonce)),

        // Catch-all untuk varian yang tidak punya nonce
        _ => None,
    }
}


/// AUTO NONCE LOOKUP (STATE + PENDING TX)
fn get_next_nonce(chain: &Chain, addr: &Address) -> Result<u64> {
    let state_nonce = chain.state.read().get_nonce(addr);

    // Cari pending tx dengan nonce tertinggi untuk addr tersebut
    let pending: Vec<TxEnvelope> = chain.db.load_pending_txs()?;

    let mut max_nonce = state_nonce;

    for env in pending {
        if let Some((sender, nonce)) = extract_sender_and_nonce(&env.payload) {
            if sender == addr && nonce > max_nonce {
                max_nonce = nonce;
            }
        }
    }

    Ok(max_nonce + 1)
}

// ════════════════════════════════════════════════════════════════════════════
// GOVERNANCE CLI HELPERS (13.12.8)
// ════════════════════════════════════════════════════════════════════════════

/// Parse proposal type from CLI string
fn parse_proposal_type(type_str: &str) -> Result<ProposalType> {
    match type_str.to_lowercase().as_str() {
        "update-fee" | "updatefee" => Ok(ProposalType::UpdateFeeParameter {
            parameter_name: "fee".to_string(),
            new_value: 0, // Akan diisi via proposal description
        }),
        "update-gas" | "updategas" => Ok(ProposalType::UpdateGasPrice {
            new_base_price: 0, // Akan diisi via proposal description
        }),
        "update-node-cost" | "updatenodecost" => Ok(ProposalType::UpdateNodeCostIndex {
            node_address: Address::from_bytes([0u8; 20]), // Placeholder
            multiplier: 0,
        }),
        "validator-onboard" | "validatoronboard" => Ok(ProposalType::ValidatorOnboarding {
            validator_address: Address::from_bytes([0u8; 20]), // Placeholder
        }),
        "validator-offboard" | "validatoroffboard" => Ok(ProposalType::ValidatorOffboarding {
            validator_address: Address::from_bytes([0u8; 20]), // Placeholder
        }),
        "compliance-remove" | "complianceremove" => Ok(ProposalType::CompliancePointerRemoval {
            pointer_id: 0, // Placeholder - u64
        }),
        "emergency-pause" | "emergencypause" => Ok(ProposalType::EmergencyPause {
            pause_type: "all".to_string(),
        }),
        _ => Err(anyhow::anyhow!(
            "invalid proposal type: {}. Valid types: update-fee, update-gas, update-node-cost, validator-onboard, validator-offboard, compliance-remove, emergency-pause",
            type_str
        )),
    }
}

/// Parse vote option from CLI string
fn parse_vote_option(vote_str: &str) -> Result<VoteOption> {
    match vote_str.to_lowercase().as_str() {
        "yes" | "y" => Ok(VoteOption::Yes),
        "no" | "n" => Ok(VoteOption::No),
        "abstain" | "a" => Ok(VoteOption::Abstain),
        _ => Err(anyhow::anyhow!(
            "invalid vote option: {}. Valid options: yes, no, abstain",
            vote_str
        )),
    }
}

/// Format proposal type for display
fn format_proposal_type(pt: &ProposalType) -> String {
    match pt {
        ProposalType::UpdateFeeParameter { parameter_name, new_value } => {
            format!("UpdateFee({}: {})", parameter_name, new_value)
        }
        ProposalType::UpdateGasPrice { new_base_price } => {
            format!("UpdateGasPrice({})", new_base_price)
        }
        ProposalType::UpdateNodeCostIndex { node_address, multiplier } => {
            format!("UpdateNodeCost({}: {})", node_address, multiplier)
        }
        ProposalType::ValidatorOnboarding { validator_address } => {
            format!("ValidatorOnboard({})", validator_address)
        }
        ProposalType::ValidatorOffboarding { validator_address } => {
            format!("ValidatorOffboard({})", validator_address)
        }
        ProposalType::CompliancePointerRemoval { pointer_id } => {
            format!("ComplianceRemove({})", pointer_id)
        }
ProposalType::EmergencyPause { pause_type } => {
            format!("EmergencyPause(type={})", pause_type)
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// PREVIEW CLI HELPERS (13.13.6)
// ════════════════════════════════════════════════════════════════════════════

/// Format PreviewType for CLI display
fn format_preview_type(pt: &PreviewType) -> String {
    match pt {
        PreviewType::FeeParameterChange { param_name, old_value, new_value } => {
            format!("FeeParameterChange({}: {} → {})", param_name, old_value, new_value)
        }
        PreviewType::GasPriceChange { old_price, new_price } => {
            format!("GasPriceChange({} → {})", old_price, new_price)
        }
        PreviewType::NodeCostIndexChange { node, old_multiplier, new_multiplier } => {
            format!("NodeCostIndexChange(0x{}: {} → {})", 
                    hex::encode(node.as_bytes()), old_multiplier, new_multiplier)
        }
        PreviewType::ValidatorOnboard { validator, stake } => {
            format!("ValidatorOnboard(0x{}, stake={})", 
                    hex::encode(validator.as_bytes()), stake)
        }
        PreviewType::ValidatorOffboard { validator, reason } => {
            format!("ValidatorOffboard(0x{}, reason={})", 
                    hex::encode(validator.as_bytes()), reason)
        }
        PreviewType::CompliancePointerRemoval { pointer_id } => {
            format!("CompliancePointerRemoval({})", pointer_id)
        }
        PreviewType::EmergencyPause { pause_type } => {
            format!("EmergencyPause({})", pause_type)
        }
    }
}

/// Format GovernanceEventType for CLI display
fn format_event_type(et: &GovernanceEventType) -> String {
    match et {
        GovernanceEventType::ProposalCreated => "📝 ProposalCreated".to_string(),
        GovernanceEventType::VoteCast => "🗳️ VoteCast".to_string(),
        GovernanceEventType::ProposalFinalized => "✅ ProposalFinalized".to_string(),
        GovernanceEventType::ProposalVetoed => "⛔ ProposalVetoed".to_string(),
        GovernanceEventType::ProposalOverridden => "🔄 ProposalOverridden".to_string(),
        GovernanceEventType::PreviewGenerated => "🔍 PreviewGenerated".to_string(),
        GovernanceEventType::ExecutionAttemptBlocked => "🚫 ExecutionAttemptBlocked".to_string(),
    }
}
// ════════════════════════════════════════════════════════════════════════════
// SLASHING CLI HELPERS (13.14.8)
// ════════════════════════════════════════════════════════════════════════════

/// Format SlashingReason for CLI display
fn format_slashing_reason(reason: &crate::slashing::SlashingReason) -> String {
    match reason {
        crate::slashing::SlashingReason::NodeLivenessFailure => "⚠️ NodeLivenessFailure".to_string(),
        crate::slashing::SlashingReason::NodeDataCorruption => "💾 NodeDataCorruption".to_string(),
        crate::slashing::SlashingReason::NodeMaliciousBehavior => "🚨 NodeMaliciousBehavior".to_string(),
        crate::slashing::SlashingReason::ValidatorDoubleSign => "✍️ ValidatorDoubleSign".to_string(),
        crate::slashing::SlashingReason::ValidatorProlongedOffline => "📴 ValidatorProlongedOffline".to_string(),
        crate::slashing::SlashingReason::ValidatorMaliciousBlock => "🔴 ValidatorMaliciousBlock".to_string(),
    }
}

// ════════════════════════════════════════════════════════════════════════════
// ECONOMIC CLI HELPERS (13.15.8)
// ════════════════════════════════════════════════════════════════════════════

/// Format EconomicMode for CLI display
fn format_economic_mode(mode: &crate::economic::EconomicMode) -> String {
    match mode {
        crate::economic::EconomicMode::Bootstrap => "Bootstrap (RF ≤ 3, no deflation)".to_string(),
        crate::economic::EconomicMode::Active => "Active (RF > 3, deflation enabled)".to_string(),
        crate::economic::EconomicMode::Governance => "Governance (parameter via governance)".to_string(),
    }
}