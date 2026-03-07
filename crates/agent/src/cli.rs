use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(author="BITEVA", version, about="DSDN Agent CLI")]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) cmd: Commands,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Generate random key (32 bytes). Optionally split into n shares with threshold k.
    GenKey {
        #[arg(short, long, default_value_t = 0)]
        n: u8,
        #[arg(short, long, default_value_t = 0)]
        k: u8,
        #[arg(short, long)]
        out_dir: Option<PathBuf>,
    },

    /// Recover key from shares (provide file paths as args)
    RecoverKey {
        #[arg(required = true)]
        shares: Vec<PathBuf>,
    },

    /// Upload a file to node (node_addr like 127.0.0.1:50051). If --encrypt, agent encrypts with new key and prints key (base64).
    Upload {
        node_addr: String,
        file: PathBuf,
        #[arg(long)]
        encrypt: bool,
        /// Track upload through DA events (ChunkDeclared + ReplicaAdded)
        #[arg(long)]
        track: bool,
        /// Expected replication factor for tracking (default: 1)
        #[arg(long, default_value_t = 1)]
        rf: usize,
        /// Timeout in seconds for DA tracking (default: 120)
        #[arg(long, default_value_t = 120)]
        timeout: u64,
    },

    /// Download a file by hash from node. Optionally decrypt with provided key (base64)
    Get {
        node_addr: String,
        hash: String,
        #[arg(long)]
        decrypt_key_b64: Option<String>,
        #[arg(long)]
        out: Option<PathBuf>,
        /// Verify chunk against DA placement and commitment (multi-source download)
        #[arg(long)]
        verify: bool,
    },

    /// Decrypt a local encrypted file (nonce || ciphertext) using AES-GCM key (base64)
    DecryptFile {
        /// Encrypted input file (produced by encrypt_aes_gcm)
        enc_file: PathBuf,
        /// Output plaintext file path
        out_file: PathBuf,
        /// AES-GCM key in base64 (32 bytes after decode)
        key_b64: String,
    },

    /// DA (Data Availability) layer commands
    Da {
        #[command(subcommand)]
        da_cmd: DaCommands,
    },

    /// Verify state consistency commands
    Verify {
        #[command(subcommand)]
        verify_cmd: VerifyCommands,
    },

    /// Node commands (ALL data derived from DA events)
    Node {
        #[command(subcommand)]
        node_cmd: NodeCommands,
    },

    /// Chunk commands (ALL data derived from DA events)
    Chunk {
        #[command(subcommand)]
        chunk_cmd: ChunkCommands,
    },

    /// Rebuild state from DA events
    Rebuild {
        /// Target to rebuild: "coordinator" or "node"
        #[arg(long, value_parser = parse_rebuild_target)]
        target: String,
        /// Starting DA height (default: 1)
        #[arg(long)]
        from: Option<u64>,
        /// Ending DA height (default: current)
        #[arg(long)]
        to: Option<u64>,
        /// Output file path for state JSON
        #[arg(long)]
        output: Option<PathBuf>,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },

    /// Health check commands
    Health {
        #[command(subcommand)]
        health_cmd: HealthCommands,
    },

    /// Node identity management (14B.51)
    Identity {
        #[command(subcommand)]
        identity_cmd: IdentityCommands,
    },

    /// Service node gating operations (14B.53)
    Gating {
        #[command(subcommand)]
        gating_cmd: GatingCommands,
    },

    /// Economic flow monitoring (14C.C.16)
    Economic {
        #[command(subcommand)]
        economic_cmd: EconomicCommands,
    },
}

/// DA layer subcommands
#[derive(Subcommand)]
pub(crate) enum DaCommands {
    /// Show DA layer status
    Status {
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
}

/// Verify subcommands
#[derive(Subcommand)]
pub(crate) enum VerifyCommands {
    /// Verify state against DA-derived state
    State {
        /// Target to verify: "coordinator" or "node"
        #[arg(long, value_parser = parse_verify_target)]
        target: String,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// Verify node consistency with DA state
    Consistency {
        /// Node address (host:port)
        #[arg(long)]
        node: String,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
}

/// Node subcommands - ALL data derived from DA events only
#[derive(Subcommand)]
pub(crate) enum NodeCommands {
    /// Show node status (derived from DA events: NodeRegistered, ReplicaAdded, etc.)
    Status {
        /// Node ID to query
        node_id: String,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// List all nodes (derived from NodeRegistered DA events)
    List {
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// Show chunks assigned to node (derived from ReplicaAdded/ReplicaRemoved DA events)
    Chunks {
        /// Node ID to query
        node_id: String,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
}

/// Chunk subcommands - ALL data derived from DA events only
#[derive(Subcommand)]
pub(crate) enum ChunkCommands {
    /// Show chunk info (derived from ChunkDeclared DA events)
    Info {
        /// Chunk hash to query
        hash: String,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// Show chunk replicas (derived from ReplicaAdded/ReplicaRemoved DA events)
    Replicas {
        /// Chunk hash to query
        hash: String,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// Show chunk event history (full timeline from DA events)
    History {
        /// Chunk hash to query
        hash: String,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
}

/// Health check subcommands
#[derive(Subcommand)]
pub(crate) enum HealthCommands {
    /// Check health of all components (DA, coordinator, nodes)
    All {
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// Check DA layer health only
    Da {
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// Check coordinator health only
    Coordinator {
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// Check all nodes health
    Nodes {
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
}

/// Identity management subcommands (14B.51)
#[derive(Subcommand)]
pub(crate) enum IdentityCommands {
    /// Generate a new Ed25519 identity keypair
    Generate {
        /// Persist identity to this directory (creates if missing)
        #[arg(long)]
        out_dir: Option<PathBuf>,
        /// Override operator address (40 hex characters, no 0x prefix)
        #[arg(long)]
        operator: Option<String>,
    },
    /// Show existing identity (node_id, operator, TLS fingerprint)
    Show {
        /// Directory containing identity files
        #[arg(long)]
        dir: PathBuf,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// Export identity including secret key (SECURITY SENSITIVE)
    Export {
        /// Directory containing identity files
        #[arg(long)]
        dir: PathBuf,
        /// Export format: hex, base64, or json
        #[arg(long)]
        format: String,
    },
}

/// Gating subcommands (14B.53–14B.59)
#[derive(Subcommand)]
pub(crate) enum GatingCommands {
    /// Check stake status for a service node operator address
    StakeCheck {
        /// Operator address (40 hex characters, no 0x prefix)
        #[arg(long)]
        address: String,
        /// Chain RPC endpoint URL (overrides DSDN_CHAIN_RPC env and default)
        #[arg(long)]
        chain_rpc: Option<String>,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },

    /// Register a service node on-chain (14B.54)
    Register {
        /// Directory containing identity files (keypair, operator, tls.fp)
        #[arg(long)]
        identity_dir: PathBuf,
        /// Node class: "storage" or "compute"
        #[arg(long)]
        class: String,
        /// Chain RPC endpoint URL (REQUIRED, no default)
        #[arg(long)]
        chain_rpc: String,
        /// Path to wallet secret key file (64 hex chars)
        #[arg(long)]
        keyfile: Option<PathBuf>,
    },

    /// Query full gating status of a service node (14B.55)
    Status {
        /// Operator address (40 hex characters, no 0x prefix)
        #[arg(long)]
        address: String,
        /// Chain RPC endpoint URL (overrides DSDN_CHAIN_RPC env and default)
        #[arg(long)]
        chain_rpc: Option<String>,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },

    /// Query slashing & cooldown status of a service node (14B.56)
    SlashingStatus {
        /// Operator address (40 hex characters, no 0x prefix)
        #[arg(long)]
        address: String,
        /// Chain RPC endpoint URL (overrides DSDN_CHAIN_RPC env and default)
        #[arg(long)]
        chain_rpc: Option<String>,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },

    /// Query node class and stake requirements (14B.57)
    NodeClass {
        /// Operator address (40 hex characters, no 0x prefix)
        #[arg(long)]
        address: String,
        /// Chain RPC endpoint URL (overrides DSDN_CHAIN_RPC env and default)
        #[arg(long)]
        chain_rpc: Option<String>,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },

    /// List all active service nodes sorted by stake (14B.57)
    ListActive {
        /// Chain RPC endpoint URL (overrides DSDN_CHAIN_RPC env and default)
        #[arg(long)]
        chain_rpc: Option<String>,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },

    /// Query quarantine details and recovery eligibility (14B.58)
    QuarantineStatus {
        /// Operator address (40 hex characters, no 0x prefix)
        #[arg(long)]
        address: String,
        /// Chain RPC endpoint URL (overrides DSDN_CHAIN_RPC env and default)
        #[arg(long)]
        chain_rpc: Option<String>,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },

    /// Query ban details and cooldown status (14B.58)
    BanStatus {
        /// Operator address (40 hex characters, no 0x prefix)
        #[arg(long)]
        address: String,
        /// Chain RPC endpoint URL (overrides DSDN_CHAIN_RPC env and default)
        #[arg(long)]
        chain_rpc: Option<String>,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },

    /// Full gating diagnosis report (14B.59)
    Diagnose {
        /// Operator address (40 hex characters, no 0x prefix)
        #[arg(long)]
        address: String,
        /// Path to identity directory (enables identity and TLS checks)
        #[arg(long)]
        identity_dir: Option<PathBuf>,
        /// Chain RPC endpoint URL (overrides DSDN_CHAIN_RPC env and default)
        #[arg(long)]
        chain_rpc: Option<String>,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
}

/// Economic flow monitoring subcommands (14C.C.16 + 14C.C.18 + 14C.C.19 + 14C.C.20 + 14C.C.21)
#[derive(Subcommand)]
pub(crate) enum EconomicCommands {
    /// Show status of a specific receipt
    Status {
        /// Receipt hash to query
        receipt_hash: String,
    },
    /// List all tracked receipts
    List,
    /// Show aggregate summary of all receipts
    Summary,
    /// Dispatch a workload to a service node (14C.C.18)
    Dispatch {
        /// Workload type: "storage" or "compute"
        #[arg(long)]
        r#type: String,
        /// Target node address (host:port)
        #[arg(long)]
        node: String,
        /// File containing workload data
        file: std::path::PathBuf,
    },
    /// Monitor execution status of a dispatched workload (14C.C.18)
    Monitor {
        /// Workload ID to monitor
        workload_id: String,
    },
    /// Submit a receipt claim to the chain (14C.C.19)
    Claim {
        /// Receipt hash to claim
        receipt_hash: String,
    },
    /// Poll claim status on-chain (14C.C.19)
    ClaimStatus {
        /// Receipt hash to query
        receipt_hash: String,
    },
    /// Run the full economic lifecycle: dispatch → monitor → proof → submit → claim (14C.C.20)
    Run {
        /// Workload type: "storage" or "compute"
        #[arg(long)]
        r#type: String,
        /// Automatically submit claim after receipt (default: false)
        #[arg(long, default_value_t = false)]
        auto_claim: bool,
        /// Target node address (host:port)
        #[arg(long, default_value = "127.0.0.1:50051")]
        node: String,
        /// File containing workload data
        file: std::path::PathBuf,
    },
    /// Show economic metrics (14C.C.21)
    Metrics {
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
}

/// Parse and validate verify target.
pub(crate) fn parse_verify_target(s: &str) -> Result<String, String> {
    match s.to_lowercase().as_str() {
        "coordinator" | "node" => Ok(s.to_lowercase()),
        _ => Err(format!(
            "invalid target '{}': must be 'coordinator' or 'node'",
            s
        )),
    }
}

/// Parse and validate rebuild target.
pub(crate) fn parse_rebuild_target(s: &str) -> Result<String, String> {
    match s.to_lowercase().as_str() {
        "coordinator" | "node" => Ok(s.to_lowercase()),
        _ => Err(format!(
            "invalid target '{}': must be 'coordinator' or 'node'",
            s
        )),
    }
}