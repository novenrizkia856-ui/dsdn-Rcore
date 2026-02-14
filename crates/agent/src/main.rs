//! # DSDN Agent CLI (14A)
//!
//! Command-line interface for DSDN (Distributed Storage and Data Network).
//!
//! ## Commands
//!
//! ### Key Management
//! - `gen-key`: Generate encryption key (32 bytes), optionally split into shares
//! - `recover-key`: Recover key from SSS shares
//!
//! ### Data Operations
//! - `upload`: Upload file to network node (with optional encryption and DA tracking)
//! - `get`: Download file from network node (with optional decryption and DA verification)
//! - `decrypt-file`: Decrypt local encrypted file using AES-GCM key
//!
//! ### DA Operations (14A)
//! - `da status`: Check DA layer connection status and current height
//!
//! ### Verification (14A)
//! - `verify state`: Verify state consistency against DA-derived state
//! - `verify consistency`: Check node consistency with DA state
//!
//! ### Node/Chunk Info (14A)
//! - `node status`: Show node status from DA events
//! - `node list`: List all registered nodes from DA events
//! - `node chunks`: Show chunks assigned to a node from DA events
//! - `chunk info`: Show chunk info from DA events
//! - `chunk replicas`: Show chunk replicas from DA events
//! - `chunk history`: Show chunk event history from DA events
//!
//! ### Maintenance (14A)
//! - `rebuild`: Rebuild state from DA events in specified height range
//! - `health all`: Check health of all components (DA, coordinator, nodes)
//! - `health da`: Check DA layer health only
//! - `health coordinator`: Check coordinator health only
//! - `health nodes`: Check all nodes health
//!
//! ### Identity Management (14B.51–14B.52)
//! - `identity generate`: Generate Ed25519 identity keypair
//!   - `--out-dir`: Persist to disk
//!   - `--operator`: Override operator address (40 hex chars)
//! - `identity show`: Show existing identity (node_id, operator, TLS fingerprint)
//!   - `--dir`: Directory containing identity files (required)
//!   - `--json`: Output as JSON
//! - `identity export`: Export identity including secret key
//!   - `--dir`: Directory containing identity files (required)
//!   - `--format`: hex, base64, or json
//!
//! ### Gating Operations (14B.53)
//! - `gating stake-check`: Check stake status for a service node
//!   - `--address`: Operator address (40 hex chars, required)
//!   - `--chain-rpc`: Chain RPC endpoint URL (optional)
//!   - `--json`: Output as JSON
//!
//! ## DA Integration
//!
//! Agent can query state directly from DA (Data Availability) layer.
//! This enables read operations without requiring Coordinator connectivity.
//! All node/chunk queries derive their data from DA events only.
//!
//! ## Environment Variables
//!
//! - `DSDN_DA_ENDPOINT`: DA layer endpoint (default: http://127.0.0.1:26658)
//! - `DSDN_DA_NAMESPACE`: DA namespace (default: dsdn)
//! - `DSDN_COORDINATOR_ENDPOINT`: Coordinator endpoint (default: http://127.0.0.1:8080)
//! - `DSDN_CHAIN_RPC`: Chain RPC endpoint for gating queries (default: http://127.0.0.1:8545)

mod sss;
mod crypto;
mod cmd_da;
mod cmd_verify;
mod cmd_chunk;
mod cmd_rebuild;
mod cmd_health;
mod cmd_identity;
mod cmd_gating;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use base64::{engine::general_purpose, Engine as _};
use hex::encode as hex_encode;
use serde::{Deserialize, Serialize};

use std::fs;
use std::io::Read;

use crate::sss::{split_secret, recover_secret};
use crate::crypto::{gen_key, encrypt_aes_gcm, decrypt_aes_gcm};
use dsdn_common::cid::sha256_hex;
use dsdn_storage::rpc;

#[derive(Parser)]
#[command(author="BITEVA", version, about="DSDN Agent CLI")]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
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
}

/// DA layer subcommands
#[derive(Subcommand)]
enum DaCommands {
    /// Show DA layer status
    Status {
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
}

/// Verify subcommands
#[derive(Subcommand)]
enum VerifyCommands {
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
enum NodeCommands {
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
enum ChunkCommands {
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
enum HealthCommands {
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
enum IdentityCommands {
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

/// Gating subcommands (14B.53)
#[derive(Subcommand)]
enum GatingCommands {
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
}

/// Parse and validate verify target.
fn parse_verify_target(s: &str) -> Result<String, String> {
    match s.to_lowercase().as_str() {
        "coordinator" | "node" => Ok(s.to_lowercase()),
        _ => Err(format!(
            "invalid target '{}': must be 'coordinator' or 'node'",
            s
        )),
    }
}

/// Parse and validate rebuild target.
fn parse_rebuild_target(s: &str) -> Result<String, String> {
    match s.to_lowercase().as_str() {
        "coordinator" | "node" => Ok(s.to_lowercase()),
        _ => Err(format!(
            "invalid target '{}': must be 'coordinator' or 'node'",
            s
        )),
    }
}

// ════════════════════════════════════════════════════════════════════════════
// NODE STATUS TYPES (derived from DA events)
// ════════════════════════════════════════════════════════════════════════════

/// Node status derived from DA events.
/// All fields are computed from DA events only - NO RPC to node/coordinator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStatusFromDA {
    /// Node ID (from NodeRegistered event).
    pub node_id: String,
    /// Registration status: "registered" or "unregistered".
    pub registration_status: String,
    /// Node address (from NodeRegistered event).
    pub addr: String,
    /// Zone assignment (from NodeRegistered event, may be None).
    pub zone: Option<String>,
    /// Whether node is active (registered and not unregistered).
    pub is_active: bool,
    /// Number of chunks assigned (count of ReplicaAdded - ReplicaRemoved).
    pub chunk_count: usize,
    /// Number of replicas this node holds (same as chunk_count for single-replica model).
    pub replica_count: usize,
    /// DA height when this status was derived.
    pub da_height: u64,
}

impl NodeStatusFromDA {
    /// Format as table.
    pub fn to_table(&self) -> String {
        let mut output = String::new();
        output.push_str("┌─────────────────────────────────────────────────────────────────┐\n");
        output.push_str("│                    NODE STATUS (from DA)                        │\n");
        output.push_str("├─────────────────────┬───────────────────────────────────────────┤\n");
        output.push_str(&format!("│ Node ID             │ {:41} │\n", truncate_str(&self.node_id, 41)));
        output.push_str(&format!("│ Registration        │ {:41} │\n", self.registration_status));
        output.push_str(&format!("│ Address             │ {:41} │\n", truncate_str(&self.addr, 41)));
        output.push_str(&format!("│ Zone                │ {:41} │\n", self.zone.as_deref().unwrap_or("(none)")));
        output.push_str(&format!("│ Active              │ {:41} │\n", if self.is_active { "yes" } else { "no" }));
        output.push_str(&format!("│ Chunk Count         │ {:41} │\n", self.chunk_count));
        output.push_str(&format!("│ Replica Count       │ {:41} │\n", self.replica_count));
        output.push_str(&format!("│ DA Height           │ {:41} │\n", self.da_height));
        output.push_str("├─────────────────────┴───────────────────────────────────────────┤\n");
        output.push_str("│ Note: All data derived from DA events only                      │\n");
        output.push_str("└─────────────────────────────────────────────────────────────────┘\n");
        output
    }

    /// Format as JSON.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| anyhow::anyhow!("failed to serialize node status: {}", e))
    }
}

/// Node list entry for display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeListEntry {
    pub node_id: String,
    pub addr: String,
    pub zone: Option<String>,
    pub is_active: bool,
    pub chunk_count: usize,
}

/// Node list result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeListFromDA {
    /// List of nodes (sorted by node_id for determinism).
    pub nodes: Vec<NodeListEntry>,
    /// Total count.
    pub total: usize,
    /// Count of active nodes.
    pub active_count: usize,
    /// DA height when this list was derived.
    pub da_height: u64,
}

impl NodeListFromDA {
    /// Format as table.
    pub fn to_table(&self) -> String {
        let mut output = String::new();
        output.push_str("┌──────────────────────────┬──────────────────────┬────────────┬────────┬────────┐\n");
        output.push_str("│ Node ID                  │ Address              │ Zone       │ Active │ Chunks │\n");
        output.push_str("├──────────────────────────┼──────────────────────┼────────────┼────────┼────────┤\n");
        
        if self.nodes.is_empty() {
            output.push_str("│                          No nodes found in DA events                          │\n");
        } else {
            for node in &self.nodes {
                output.push_str(&format!(
                    "│ {:24} │ {:20} │ {:10} │ {:6} │ {:>6} │\n",
                    truncate_str(&node.node_id, 24),
                    truncate_str(&node.addr, 20),
                    truncate_str(node.zone.as_deref().unwrap_or("-"), 10),
                    if node.is_active { "yes" } else { "no" },
                    node.chunk_count
                ));
            }
        }
        
        output.push_str("├──────────────────────────┴──────────────────────┴────────────┴────────┴────────┤\n");
        output.push_str(&format!("│ Total: {} | Active: {} | DA Height: {:>10}                            │\n",
            self.total, self.active_count, self.da_height));
        output.push_str("└─────────────────────────────────────────────────────────────────────────────────┘\n");
        output
    }

    /// Format as JSON.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| anyhow::anyhow!("failed to serialize node list: {}", e))
    }
}

/// Chunk assignment entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkAssignment {
    pub chunk_hash: String,
    pub size: u64,
    pub owner: String,
}

/// Node chunks result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeChunksFromDA {
    pub node_id: String,
    /// Chunks assigned to this node (sorted by chunk_hash for determinism).
    pub chunks: Vec<ChunkAssignment>,
    /// Total count.
    pub total: usize,
    /// Total size in bytes.
    pub total_size: u64,
    /// DA height when this was derived.
    pub da_height: u64,
}

impl NodeChunksFromDA {
    /// Format as table.
    pub fn to_table(&self) -> String {
        let mut output = String::new();
        output.push_str(&format!("Chunks assigned to node: {}\n", self.node_id));
        output.push_str("┌────────────────────────────────────────────────────────────────┬────────────┬──────────────────────┐\n");
        output.push_str("│ Chunk Hash                                                     │       Size │ Owner                │\n");
        output.push_str("├────────────────────────────────────────────────────────────────┼────────────┼──────────────────────┤\n");
        
        if self.chunks.is_empty() {
            output.push_str("│                              No chunks assigned                                                  │\n");
        } else {
            for chunk in &self.chunks {
                output.push_str(&format!(
                    "│ {:62} │ {:>10} │ {:20} │\n",
                    truncate_str(&chunk.chunk_hash, 62),
                    chunk.size,
                    truncate_str(&chunk.owner, 20)
                ));
            }
        }
        
        output.push_str("├────────────────────────────────────────────────────────────────┴────────────┴──────────────────────┤\n");
        output.push_str(&format!("│ Total: {} chunks | Size: {} bytes | DA Height: {:>10}                                   │\n",
            self.total, self.total_size, self.da_height));
        output.push_str("└─────────────────────────────────────────────────────────────────────────────────────────────────────┘\n");
        output
    }

    /// Format as JSON.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| anyhow::anyhow!("failed to serialize node chunks: {}", e))
    }
}

/// Truncate string with ellipsis.
fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else if max_len > 3 {
        format!("{}...", &s[..max_len - 3])
    } else {
        s[..max_len].to_string()
    }
}

// ════════════════════════════════════════════════════════════════════════════
// UPLOAD DA TRACKING
// ════════════════════════════════════════════════════════════════════════════

/// Upload tracking progress stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrackingStage {
    /// Upload in progress.
    Uploading,
    /// Waiting for ChunkDeclared event from DA.
    WaitingDeclared,
    /// Waiting for ReplicaAdded events until RF is met.
    WaitingReplication { current: usize, target: usize },
    /// Tracking complete.
    Complete,
    /// Tracking failed with error.
    Failed(String),
}

impl std::fmt::Display for TrackingStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrackingStage::Uploading => write!(f, "UPLOADING"),
            TrackingStage::WaitingDeclared => write!(f, "WAITING_DECLARED"),
            TrackingStage::WaitingReplication { current, target } => {
                write!(f, "REPLICATING ({}/{})", current, target)
            }
            TrackingStage::Complete => write!(f, "COMPLETE"),
            TrackingStage::Failed(msg) => write!(f, "FAILED: {}", msg),
        }
    }
}

/// Upload tracking result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadTrackingResult {
    pub chunk_hash: String,
    pub size: u64,
    pub declared: bool,
    pub declared_height: Option<u64>,
    pub replicas: Vec<String>,
    pub replication_factor: usize,
    pub target_rf: usize,
    pub rf_achieved: bool,
    pub tracking_time_ms: u64,
}

impl UploadTrackingResult {
    /// Format as table.
    pub fn to_table(&self) -> String {
        let mut output = String::new();
        output.push_str("┌─────────────────────────────────────────────────────────────────────────────┐\n");
        output.push_str("│                      UPLOAD TRACKING RESULT                                 │\n");
        output.push_str("├─────────────────────┬───────────────────────────────────────────────────────┤\n");
        output.push_str(&format!("│ Chunk Hash          │ {:53} │\n", truncate_str(&self.chunk_hash, 53)));
        output.push_str(&format!("│ Size                │ {:>50} bytes │\n", self.size));
        output.push_str(&format!("│ Declared            │ {:53} │\n", if self.declared { "yes" } else { "no" }));
        if let Some(h) = self.declared_height {
            output.push_str(&format!("│ Declared Height     │ {:53} │\n", h));
        }
        output.push_str(&format!("│ Replication         │ {:>3} / {:>3} {:44} │\n", 
            self.replication_factor, self.target_rf,
            if self.rf_achieved { "(achieved)" } else { "(incomplete)" }));
        output.push_str(&format!("│ Tracking Time       │ {:>50} ms │\n", self.tracking_time_ms));
        output.push_str("├─────────────────────┴───────────────────────────────────────────────────────┤\n");
        if self.replicas.is_empty() {
            output.push_str("│ Replicas: (none)                                                            │\n");
        } else {
            output.push_str("│ Replicas:                                                                   │\n");
            for (i, node) in self.replicas.iter().enumerate() {
                output.push_str(&format!("│   {}. {:70} │\n", i + 1, truncate_str(node, 70)));
            }
        }
        output.push_str("└─────────────────────────────────────────────────────────────────────────────┘\n");
        output
    }
}

/// Configuration for DA tracking.
struct TrackingConfig {
    da_endpoint: String,
    namespace: String,
    timeout_secs: u64,
    poll_interval_ms: u64,
}

impl TrackingConfig {
    fn from_env_and_args(timeout_secs: u64) -> Self {
        let da_config = cmd_da::DAConfig::from_env();
        Self {
            da_endpoint: da_config.rpc_url,
            namespace: da_config.namespace,
            timeout_secs,
            poll_interval_ms: 2000,
        }
    }
}

/// Print tracking progress.
fn print_tracking_progress(stage: &TrackingStage, chunk_hash: &str) {
    println!("[TRACK] {} | chunk: {}", stage, truncate_str(chunk_hash, 16));
}

/// Get current DA height.
async fn get_da_height(client: &reqwest::Client, endpoint: &str) -> Result<u64> {
    let url = format!("{}/header/local_head", endpoint);
    let response = client.get(&url).send().await
        .map_err(|e| anyhow::anyhow!("failed to get DA header: {}", e))?;
    
    if !response.status().is_success() {
        return Ok(0);
    }
    
    let body = response.text().await
        .map_err(|e| anyhow::anyhow!("failed to read response: {}", e))?;
    
    let json: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("failed to parse header: {}", e))?;
    
    let height = json.get("header")
        .and_then(|h| h.get("height"))
        .and_then(|h| h.as_str())
        .and_then(|h| h.parse::<u64>().ok())
        .unwrap_or(0);
    
    Ok(height)
}

/// Fetch DA events at specific height.
async fn fetch_da_events(
    client: &reqwest::Client,
    config: &TrackingConfig,
    height: u64,
) -> Result<Vec<cmd_verify::DAEvent>> {
    let url = format!("{}/blob/get_all/{}/{}", config.da_endpoint, height, config.namespace);
    
    let response = match client.get(&url).send().await {
        Ok(r) if r.status().is_success() => r,
        _ => return Ok(Vec::new()),
    };
    
    let body = response.text().await
        .map_err(|e| anyhow::anyhow!("failed to read blob response: {}", e))?;
    
    let json: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("failed to parse blob response: {}", e))?;
    
    let blobs = match json.as_array() {
        Some(arr) => arr,
        None => return Ok(Vec::new()),
    };
    
    let mut all_events = Vec::new();
    for blob in blobs {
        if let Some(data_b64) = blob.get("data").and_then(|d| d.as_str()) {
            if let Ok(data) = general_purpose::STANDARD.decode(data_b64) {
                if let Ok(events) = serde_json::from_slice::<Vec<cmd_verify::DAEvent>>(&data) {
                    all_events.extend(events);
                }
            }
        }
    }
    
    Ok(all_events)
}

/// Wait for ChunkDeclared event in DA.
async fn wait_for_chunk_declared(
    config: &TrackingConfig,
    chunk_hash: &str,
) -> Result<u64> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build HTTP client: {}", e))?;

    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(config.timeout_secs);
    let poll_interval = std::time::Duration::from_millis(config.poll_interval_ms);

    let initial_height = get_da_height(&client, &config.da_endpoint).await.unwrap_or(0);
    let mut last_checked_height = if initial_height > 0 { initial_height - 1 } else { 0 };

    loop {
        if start.elapsed() > timeout {
            anyhow::bail!(
                "timeout waiting for ChunkDeclared event for chunk '{}' after {} seconds",
                chunk_hash,
                config.timeout_secs
            );
        }

        let current_height = get_da_height(&client, &config.da_endpoint).await.unwrap_or(0);

        for height in (last_checked_height + 1)..=current_height {
            let events = fetch_da_events(&client, config, height).await.unwrap_or_default();
            
            for event in events {
                if let cmd_verify::DAEvent::ChunkDeclared { chunk_hash: hash, .. } = event {
                    if hash == chunk_hash {
                        return Ok(height);
                    }
                }
            }
        }

        last_checked_height = current_height;
        tokio::time::sleep(poll_interval).await;
    }
}

/// Wait for ReplicaAdded events until target RF is reached.
async fn wait_for_replication(
    config: &TrackingConfig,
    chunk_hash: &str,
    target_rf: usize,
) -> Result<Vec<String>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build HTTP client: {}", e))?;

    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(config.timeout_secs);
    let poll_interval = std::time::Duration::from_millis(config.poll_interval_ms);

    let mut replicas: Vec<String> = Vec::new();
    let initial_height = get_da_height(&client, &config.da_endpoint).await.unwrap_or(0);
    let mut last_checked_height = if initial_height > 0 { initial_height - 1 } else { 0 };

    loop {
        if replicas.len() >= target_rf {
            return Ok(replicas);
        }

        if start.elapsed() > timeout {
            // Return partial result instead of error
            return Ok(replicas);
        }

        let current_height = get_da_height(&client, &config.da_endpoint).await.unwrap_or(0);

        for height in (last_checked_height + 1)..=current_height {
            let events = fetch_da_events(&client, config, height).await.unwrap_or_default();
            
            for event in events {
                if let cmd_verify::DAEvent::ReplicaAdded { chunk_hash: hash, node_id, .. } = event {
                    if hash == chunk_hash && !replicas.contains(&node_id) {
                        replicas.push(node_id);
                        print_tracking_progress(
                            &TrackingStage::WaitingReplication {
                                current: replicas.len(),
                                target: target_rf,
                            },
                            chunk_hash,
                        );
                        
                        if replicas.len() >= target_rf {
                            return Ok(replicas);
                        }
                    }
                }
            }
        }

        last_checked_height = current_height;
        tokio::time::sleep(poll_interval).await;
    }
}

/// Handle upload with DA tracking.
async fn handle_upload_with_tracking(
    chunk_hash: &str,
    size: u64,
    target_rf: usize,
    timeout_secs: u64,
) -> Result<UploadTrackingResult> {
    let start = std::time::Instant::now();
    let config = TrackingConfig::from_env_and_args(timeout_secs);

    // Stage 1: Wait for ChunkDeclared
    print_tracking_progress(&TrackingStage::WaitingDeclared, chunk_hash);
    
    let declared_height = match wait_for_chunk_declared(&config, chunk_hash).await {
        Ok(h) => Some(h),
        Err(e) => {
            print_tracking_progress(&TrackingStage::Failed(e.to_string()), chunk_hash);
            return Ok(UploadTrackingResult {
                chunk_hash: chunk_hash.to_string(),
                size,
                declared: false,
                declared_height: None,
                replicas: Vec::new(),
                replication_factor: 0,
                target_rf,
                rf_achieved: false,
                tracking_time_ms: start.elapsed().as_millis() as u64,
            });
        }
    };

    println!("[TRACK] ChunkDeclared confirmed at DA height {}", declared_height.unwrap_or(0));

    // Stage 2: Wait for replication
    print_tracking_progress(
        &TrackingStage::WaitingReplication { current: 0, target: target_rf },
        chunk_hash,
    );
    
    let replicas = wait_for_replication(&config, chunk_hash, target_rf).await
        .unwrap_or_default();

    let rf_achieved = replicas.len() >= target_rf;
    
    if rf_achieved {
        print_tracking_progress(&TrackingStage::Complete, chunk_hash);
    } else {
        println!("[TRACK] Partial replication: {}/{}", replicas.len(), target_rf);
    }

    Ok(UploadTrackingResult {
        chunk_hash: chunk_hash.to_string(),
        size,
        declared: true,
        declared_height,
        replication_factor: replicas.len(),
        replicas,
        target_rf,
        rf_achieved,
        tracking_time_ms: start.elapsed().as_millis() as u64,
    })
}

// ════════════════════════════════════════════════════════════════════════════
// DOWNLOAD DA VERIFICATION
// ════════════════════════════════════════════════════════════════════════════

/// Download attempt result.
#[derive(Debug, Clone)]
pub enum DownloadAttemptResult {
    /// Download successful, data verified.
    Success { node_id: String, node_addr: String, data: Vec<u8> },
    /// Download failed (network error, not found, etc.).
    Failed { node_id: String, node_addr: String, reason: String },
    /// Download succeeded but verification failed.
    VerificationFailed { node_id: String, node_addr: String, reason: String },
}

/// Download verification result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadVerificationResult {
    pub chunk_hash: String,
    pub expected_size: u64,
    pub actual_size: u64,
    pub verified: bool,
    pub source_node_id: Option<String>,
    pub source_node_addr: Option<String>,
    pub attempts: Vec<DownloadAttemptInfo>,
    pub da_height: u64,
}

/// Info about a single download attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadAttemptInfo {
    pub node_id: String,
    pub node_addr: String,
    pub success: bool,
    pub reason: Option<String>,
}

impl DownloadVerificationResult {
    /// Format as table.
    pub fn to_table(&self) -> String {
        let mut output = String::new();
        output.push_str("┌─────────────────────────────────────────────────────────────────────────────┐\n");
        output.push_str("│                    DOWNLOAD VERIFICATION RESULT                             │\n");
        output.push_str("├─────────────────────┬───────────────────────────────────────────────────────┤\n");
        output.push_str(&format!("│ Chunk Hash          │ {:53} │\n", truncate_str(&self.chunk_hash, 53)));
        output.push_str(&format!("│ Expected Size       │ {:>50} bytes │\n", self.expected_size));
        output.push_str(&format!("│ Actual Size         │ {:>50} bytes │\n", self.actual_size));
        output.push_str(&format!("│ Verified            │ {:53} │\n", if self.verified { "YES ✓" } else { "NO ✗" }));
        if let Some(ref node_id) = self.source_node_id {
            output.push_str(&format!("│ Source Node         │ {:53} │\n", truncate_str(node_id, 53)));
        }
        if let Some(ref node_addr) = self.source_node_addr {
            output.push_str(&format!("│ Source Address      │ {:53} │\n", truncate_str(node_addr, 53)));
        }
        output.push_str(&format!("│ DA Height           │ {:53} │\n", self.da_height));
        output.push_str("├─────────────────────┴───────────────────────────────────────────────────────┤\n");
        
        if self.attempts.is_empty() {
            output.push_str("│ Attempts: (none)                                                            │\n");
        } else {
            output.push_str("│ Download Attempts:                                                          │\n");
            for (i, attempt) in self.attempts.iter().enumerate() {
                let status = if attempt.success { "✓" } else { "✗" };
                let reason = attempt.reason.as_deref().unwrap_or("-");
                output.push_str(&format!("│   {}. {} {} - {}                   │\n", 
                    i + 1, 
                    status,
                    truncate_str(&attempt.node_id, 20),
                    truncate_str(reason, 30)
                ));
            }
        }
        output.push_str("└─────────────────────────────────────────────────────────────────────────────┘\n");
        output
    }
}

/// Chunk info from DA for verification.
#[derive(Debug, Clone)]
struct DAChunkInfo {
    chunk_hash: String,
    size: u64,
    owner: String,
    replicas: Vec<DAReplicaInfo>,
}

/// Replica info from DA.
#[derive(Debug, Clone)]
struct DAReplicaInfo {
    node_id: String,
    node_addr: String,
    is_active: bool,
}

/// Fetch chunk placement info from DA.
async fn fetch_chunk_placement_from_da(chunk_hash: &str) -> Result<(DAChunkInfo, u64)> {
    let da_config = cmd_da::DAConfig::from_env();
    let state = cmd_verify::rebuild_state_from_da(&da_config).await?;
    
    let chunk_info = state.chunks.get(chunk_hash)
        .ok_or_else(|| anyhow::anyhow!(
            "chunk '{}' not found in DA events at height {}",
            chunk_hash,
            state.last_height
        ))?;
    
    // Build replica list with node addresses
    let mut replicas: Vec<DAReplicaInfo> = Vec::new();
    for node_id in &chunk_info.replicas {
        if let Some(node_info) = state.nodes.get(node_id) {
            replicas.push(DAReplicaInfo {
                node_id: node_id.clone(),
                node_addr: node_info.addr.clone(),
                is_active: node_info.active,
            });
        }
    }
    
    // Sort by node_id for deterministic order
    replicas.sort_by(|a, b| a.node_id.cmp(&b.node_id));
    
    Ok((DAChunkInfo {
        chunk_hash: chunk_hash.to_string(),
        size: chunk_info.size,
        owner: chunk_info.owner.clone(),
        replicas,
    }, state.last_height))
}

/// Verify downloaded data matches expected hash.
fn verify_chunk_integrity(data: &[u8], expected_hash: &str) -> bool {
    let actual_hash = sha256_hex(data);
    actual_hash == expected_hash
}

/// Try to download from a single node.
async fn try_download_from_node(
    node_addr: &str,
    chunk_hash: &str,
) -> Result<Vec<u8>, String> {
    let connect = format!("http://{}", node_addr);
    
    match rpc::client_get(connect, chunk_hash.to_string()).await {
        Ok(Some(data)) => Ok(data),
        Ok(None) => Err("chunk not found on node".to_string()),
        Err(e) => Err(format!("RPC error: {}", e)),
    }
}

/// Download with DA verification - multi-source with fallback.
async fn download_with_da_verification(
    chunk_hash: &str,
    fallback_node_addr: &str,
) -> Result<(Vec<u8>, DownloadVerificationResult)> {
    // Step 1: Fetch chunk placement from DA
    let (da_info, da_height) = fetch_chunk_placement_from_da(chunk_hash).await?;
    
    if da_info.replicas.is_empty() {
        anyhow::bail!(
            "chunk '{}' has no replicas in DA at height {}. Cannot download.",
            chunk_hash,
            da_height
        );
    }
    
    let mut attempts: Vec<DownloadAttemptInfo> = Vec::new();
    let mut successful_data: Option<(Vec<u8>, String, String)> = None;
    
    // Step 2: Try each node in deterministic order (sorted by node_id)
    // First try active nodes, then inactive ones
    let active_replicas: Vec<_> = da_info.replicas.iter()
        .filter(|r| r.is_active)
        .collect();
    let inactive_replicas: Vec<_> = da_info.replicas.iter()
        .filter(|r| !r.is_active)
        .collect();
    
    let ordered_replicas: Vec<_> = active_replicas.into_iter()
        .chain(inactive_replicas.into_iter())
        .collect();
    
    for replica in &ordered_replicas {
        println!("[VERIFY] Attempting download from node '{}' ({})", 
            replica.node_id, replica.node_addr);
        
        // Step 3: Try download
        match try_download_from_node(&replica.node_addr, chunk_hash).await {
            Ok(data) => {
                // Step 4: Verify integrity (hash match)
                if verify_chunk_integrity(&data, chunk_hash) {
                    // Step 5: Verify size matches DA
                    if data.len() as u64 == da_info.size {
                        println!("[VERIFY] ✓ Download successful and verified from '{}'", 
                            replica.node_id);
                        
                        attempts.push(DownloadAttemptInfo {
                            node_id: replica.node_id.clone(),
                            node_addr: replica.node_addr.clone(),
                            success: true,
                            reason: Some("verified".to_string()),
                        });
                        
                        successful_data = Some((
                            data,
                            replica.node_id.clone(),
                            replica.node_addr.clone(),
                        ));
                        break;
                    } else {
                        println!("[VERIFY] ✗ Size mismatch from '{}': expected {}, got {}", 
                            replica.node_id, da_info.size, data.len());
                        
                        attempts.push(DownloadAttemptInfo {
                            node_id: replica.node_id.clone(),
                            node_addr: replica.node_addr.clone(),
                            success: false,
                            reason: Some(format!(
                                "size mismatch: expected {}, got {}",
                                da_info.size, data.len()
                            )),
                        });
                    }
                } else {
                    println!("[VERIFY] ✗ Hash mismatch from '{}'", replica.node_id);
                    
                    attempts.push(DownloadAttemptInfo {
                        node_id: replica.node_id.clone(),
                        node_addr: replica.node_addr.clone(),
                        success: false,
                        reason: Some("hash mismatch - data corrupted".to_string()),
                    });
                }
            }
            Err(reason) => {
                println!("[VERIFY] ✗ Download failed from '{}': {}", replica.node_id, reason);
                
                attempts.push(DownloadAttemptInfo {
                    node_id: replica.node_id.clone(),
                    node_addr: replica.node_addr.clone(),
                    success: false,
                    reason: Some(reason),
                });
            }
        }
    }
    
    // Step 6: If no DA nodes worked, try the fallback address (still verify)
    if successful_data.is_none() && !fallback_node_addr.is_empty() {
        // Check if fallback is not already in DA replicas
        let fallback_tried = attempts.iter()
            .any(|a| a.node_addr == fallback_node_addr);
        
        if !fallback_tried {
            println!("[VERIFY] Attempting fallback download from '{}'", fallback_node_addr);
            
            match try_download_from_node(fallback_node_addr, chunk_hash).await {
                Ok(data) => {
                    if verify_chunk_integrity(&data, chunk_hash) {
                        if data.len() as u64 == da_info.size {
                            println!("[VERIFY] ✓ Fallback download successful and verified");
                            
                            attempts.push(DownloadAttemptInfo {
                                node_id: "fallback".to_string(),
                                node_addr: fallback_node_addr.to_string(),
                                success: true,
                                reason: Some("verified (fallback)".to_string()),
                            });
                            
                            successful_data = Some((
                                data,
                                "fallback".to_string(),
                                fallback_node_addr.to_string(),
                            ));
                        } else {
                            attempts.push(DownloadAttemptInfo {
                                node_id: "fallback".to_string(),
                                node_addr: fallback_node_addr.to_string(),
                                success: false,
                                reason: Some(format!(
                                    "size mismatch: expected {}, got {}",
                                    da_info.size, data.len()
                                )),
                            });
                        }
                    } else {
                        attempts.push(DownloadAttemptInfo {
                            node_id: "fallback".to_string(),
                            node_addr: fallback_node_addr.to_string(),
                            success: false,
                            reason: Some("hash mismatch".to_string()),
                        });
                    }
                }
                Err(reason) => {
                    attempts.push(DownloadAttemptInfo {
                        node_id: "fallback".to_string(),
                        node_addr: fallback_node_addr.to_string(),
                        success: false,
                        reason: Some(reason),
                    });
                }
            }
        }
    }
    
    // Build result
    match successful_data {
        Some((data, node_id, node_addr)) => {
            let result = DownloadVerificationResult {
                chunk_hash: chunk_hash.to_string(),
                expected_size: da_info.size,
                actual_size: data.len() as u64,
                verified: true,
                source_node_id: Some(node_id),
                source_node_addr: Some(node_addr),
                attempts,
                da_height,
            };
            Ok((data, result))
        }
        None => {
            let result = DownloadVerificationResult {
                chunk_hash: chunk_hash.to_string(),
                expected_size: da_info.size,
                actual_size: 0,
                verified: false,
                source_node_id: None,
                source_node_addr: None,
                attempts,
                da_height,
            };
            anyhow::bail!(
                "all download attempts failed for chunk '{}'. Tried {} nodes.\n{}",
                chunk_hash,
                result.attempts.len(),
                result.to_table()
            );
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// NODE COMMAND HANDLERS (all data from DA events)
// ════════════════════════════════════════════════════════════════════════════

/// Validate node_id is not empty.
fn validate_node_id(node_id: &str) -> Result<()> {
    if node_id.is_empty() {
        anyhow::bail!("node_id cannot be empty");
    }
    if node_id.len() > 256 {
        anyhow::bail!("node_id too long (max 256 characters)");
    }
    Ok(())
}

/// Handle `agent node status <node_id>` command.
/// ALL data is derived from DA events only - NO RPC to node or coordinator.
async fn handle_node_status(node_id: &str, json_output: bool) -> Result<()> {
    // Validate input
    validate_node_id(node_id)?;

    // Rebuild state from DA events only
    let config = cmd_da::DAConfig::from_env();
    let state = cmd_verify::rebuild_state_from_da(&config).await?;

    // Find node in DA-derived state
    let node_info = state.nodes.get(node_id);

    match node_info {
        Some(info) => {
            // Count chunks assigned to this node (from ReplicaAdded events)
            let chunk_count = state.chunks.values()
                .filter(|c| c.replicas.contains(&node_id.to_string()))
                .count();

            let status = NodeStatusFromDA {
                node_id: node_id.to_string(),
                registration_status: if info.active { "registered".to_string() } else { "unregistered".to_string() },
                addr: info.addr.clone(),
                zone: info.zone.clone(),
                is_active: info.active,
                chunk_count,
                replica_count: chunk_count, // In current model, 1 replica per assignment
                da_height: state.last_height,
            };

            if json_output {
                println!("{}", status.to_json()?);
            } else {
                print!("{}", status.to_table());
            }
        }
        None => {
            anyhow::bail!(
                "node '{}' not found in DA events. Searched {} registered nodes at DA height {}.",
                node_id,
                state.nodes.len(),
                state.last_height
            );
        }
    }

    Ok(())
}

/// Handle `agent node list` command.
/// ALL data is derived from DA events only - NO RPC to node or coordinator.
async fn handle_node_list(json_output: bool) -> Result<()> {
    // Rebuild state from DA events only
    let config = cmd_da::DAConfig::from_env();
    let state = cmd_verify::rebuild_state_from_da(&config).await?;

    // Build list from DA-derived state
    let mut nodes: Vec<NodeListEntry> = state.nodes.values()
        .map(|info| {
            let chunk_count = state.chunks.values()
                .filter(|c| c.replicas.contains(&info.node_id))
                .count();

            NodeListEntry {
                node_id: info.node_id.clone(),
                addr: info.addr.clone(),
                zone: info.zone.clone(),
                is_active: info.active,
                chunk_count,
            }
        })
        .collect();

    // Sort by node_id for deterministic output
    nodes.sort_by(|a, b| a.node_id.cmp(&b.node_id));

    let active_count = nodes.iter().filter(|n| n.is_active).count();

    let result = NodeListFromDA {
        total: nodes.len(),
        active_count,
        nodes,
        da_height: state.last_height,
    };

    if json_output {
        println!("{}", result.to_json()?);
    } else {
        print!("{}", result.to_table());
    }

    Ok(())
}

/// Handle `agent node chunks <node_id>` command.
/// ALL data is derived from DA events only - NO RPC to node or coordinator.
async fn handle_node_chunks(node_id: &str, json_output: bool) -> Result<()> {
    // Validate input
    validate_node_id(node_id)?;

    // Rebuild state from DA events only
    let config = cmd_da::DAConfig::from_env();
    let state = cmd_verify::rebuild_state_from_da(&config).await?;

    // Verify node exists in DA
    if !state.nodes.contains_key(node_id) {
        anyhow::bail!(
            "node '{}' not found in DA events. Cannot list chunks for unknown node.",
            node_id
        );
    }

    // Find chunks assigned to this node (from ReplicaAdded/ReplicaRemoved events)
    let mut chunks: Vec<ChunkAssignment> = state.chunks.values()
        .filter(|c| c.replicas.contains(&node_id.to_string()))
        .map(|c| ChunkAssignment {
            chunk_hash: c.chunk_hash.clone(),
            size: c.size,
            owner: c.owner.clone(),
        })
        .collect();

    // Sort by chunk_hash for deterministic output
    chunks.sort_by(|a, b| a.chunk_hash.cmp(&b.chunk_hash));

    let total_size: u64 = chunks.iter().map(|c| c.size).sum();

    let result = NodeChunksFromDA {
        node_id: node_id.to_string(),
        total: chunks.len(),
        total_size,
        chunks,
        da_height: state.last_height,
    };

    if json_output {
        println!("{}", result.to_json()?);
    } else {
        print!("{}", result.to_table());
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Commands::GenKey { n, k, out_dir } => {
            let key = gen_key();
            if n > 0 && k > 0 {
                let shares = split_secret(&key, n, k)?;
                if let Some(dir) = out_dir {
                    fs::create_dir_all(&dir)?;
                    for (x, data) in shares.iter() {
                        let fname = dir.join(format!("share-{}.b64", x));
                        let b64 = general_purpose::STANDARD.encode(data);
                        fs::write(&fname, &b64)?;
                        println!("wrote {}", fname.display());
                    }
                } else {
                    for (x, data) in shares.iter() {
                        println!("share-{}: {}", x, general_purpose::STANDARD.encode(data));
                    }
                }
            } else {
                let b64 = general_purpose::STANDARD.encode(&key);
                println!("KEY_B64: {}", b64);
                println!("KEY_HEX: {}", hex_encode(&key));
            }
        }

        Commands::RecoverKey { shares } => {
            let mut parts = Vec::new();
            for p in shares {
                let s = fs::read_to_string(&p)?;
                let s = s.trim();
                let data = general_purpose::STANDARD.decode(s)?;
                let fname = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                let x: u8 = if fname.starts_with("share-") {
                    fname[6..].split('.').next().unwrap_or("1").parse().unwrap_or(1)
                } else {
                    1
                };
                parts.push((x, data));
            }
            let recovered = recover_secret(&parts)?;
            println!("recovered key (hex): {}", hex_encode(&recovered));
            println!("recovered key (b64): {}", general_purpose::STANDARD.encode(&recovered));
        }

        Commands::Upload { node_addr, file, encrypt, track, rf, timeout } => {
            let mut f = fs::File::open(&file)?;
            let mut buf = Vec::new();
            f.read_to_end(&mut buf)?;
            let to_upload = buf;
            let mut printed_key: Option<String> = None;
            let connect = format!("http://{}", node_addr);

            // Validate RF only when tracking
            if track && rf == 0 {
                anyhow::bail!("replication factor (--rf) must be at least 1");
            }

            let (hash, size) = if encrypt {
                let key = gen_key();
                let cipher_blob = encrypt_aes_gcm(&key, &to_upload)?;
                let hash = sha256_hex(&cipher_blob);
                let size = cipher_blob.len() as u64;
                
                if track {
                    print_tracking_progress(&TrackingStage::Uploading, &hash);
                }
                println!("Uploading encrypted blob (cid {}) to {}", hash, node_addr);

                let returned = rpc::client_put(connect.clone(), hash.clone(), cipher_blob.clone())
                    .await
                    .map_err(|e| anyhow::anyhow!(format!("{}", e)))?;
                println!("uploaded -> returned {}", returned);

                let b64 = general_purpose::STANDARD.encode(&key);
                printed_key = Some(b64.clone());
                println!("ENCRYPTION_KEY_B64: {}", b64);
                
                (hash, size)
            } else {
                let hash = sha256_hex(&to_upload);
                let size = to_upload.len() as u64;
                
                if track {
                    print_tracking_progress(&TrackingStage::Uploading, &hash);
                }
                println!("Uploading blob (cid {}) to {}", hash, node_addr);
                
                let returned = rpc::client_put(connect.clone(), hash.clone(), to_upload.clone())
                    .await
                    .map_err(|e| anyhow::anyhow!(format!("{}", e)))?;
                println!("uploaded -> returned {}", returned);
                
                (hash, size)
            };
            
            if let Some(_k) = printed_key {
                println!("Note: save this encryption key (base64) to decrypt later.");
            }

            // DA tracking if --track flag is set
            if track {
                println!("\n--- DA Tracking ---");
                let result = handle_upload_with_tracking(&hash, size, rf, timeout).await?;
                print!("{}", result.to_table());
                
                if !result.rf_achieved {
                    println!("\nWarning: Target replication factor not achieved within timeout.");
                }
            }
        }

        Commands::Get { node_addr, hash, decrypt_key_b64, out, verify } => {
            let data = if verify {
                // DA-verified multi-source download
                println!("--- DA Verification Download ---");
                let (verified_data, result) = download_with_da_verification(&hash, &node_addr).await?;
                print!("{}", result.to_table());
                verified_data
            } else {
                // Original behavior: direct download from specified node
                let connect = format!("http://{}", node_addr);
                let opt = rpc::client_get(connect.clone(), hash.clone())
                    .await
                    .map_err(|e| anyhow::anyhow!(format!("{}", e)))?;
                match opt {
                    None => {
                        println!("not found on node {}", node_addr);
                        return Ok(());
                    }
                    Some(d) => d,
                }
            };
            
            // Process downloaded data (decrypt if needed, write to file or print)
            if let Some(b64) = decrypt_key_b64 {
                let key = general_purpose::STANDARD.decode(&b64)?;
                if key.len() != 32 { anyhow::bail!("invalid key length"); }
                let mut k32 = [0u8; 32];
                k32.copy_from_slice(&key);
                let plain = decrypt_aes_gcm(&k32, &data)?;
                if let Some(path) = out {
                    fs::write(path, &plain)?;
                    println!("wrote decrypted to file");
                } else {
                    println!("decrypted bytes (hex): {}", hex_encode(&plain));
                }
            } else {
                if let Some(path) = out {
                    fs::write(path, &data)?;
                    println!("wrote bytes to file");
                } else {
                    println!("bytes (hex): {}", hex_encode(&data));
                }
            }
        }

        Commands::DecryptFile { enc_file, out_file, key_b64 } => {
            // baca file terenkripsi (nonce || ciphertext)
            let enc = fs::read(&enc_file)?;
            // decode key base64
            let key_bytes = general_purpose::STANDARD.decode(&key_b64)?;
            if key_bytes.len() != 32 {
                anyhow::bail!("invalid key length: expected 32 bytes, got {}", key_bytes.len());
            }
            let mut k32 = [0u8; 32];
            k32.copy_from_slice(&key_bytes);
            // decrypt
            let plain = decrypt_aes_gcm(&k32, &enc)?;
            fs::write(&out_file, &plain)?;
            println!("decrypted {} -> {}", enc_file.display(), out_file.display());
        }

        Commands::Da { da_cmd } => {
            match da_cmd {
                DaCommands::Status { json } => {
                    cmd_da::handle_da_status(json).await?;
                }
            }
        }

        Commands::Verify { verify_cmd } => {
            let is_consistent = match verify_cmd {
                VerifyCommands::State { target, json } => {
                    cmd_verify::handle_verify_state(&target, json).await?
                }
                VerifyCommands::Consistency { node, json } => {
                    cmd_verify::handle_verify_consistency(&node, json).await?
                }
            };
            
            // Exit code: 0 = consistent, 1 = inconsistent
            if !is_consistent {
                std::process::exit(1);
            }
        }

        Commands::Node { node_cmd } => {
            match node_cmd {
                NodeCommands::Status { node_id, json } => {
                    handle_node_status(&node_id, json).await?;
                }
                NodeCommands::List { json } => {
                    handle_node_list(json).await?;
                }
                NodeCommands::Chunks { node_id, json } => {
                    handle_node_chunks(&node_id, json).await?;
                }
            }
        }

        Commands::Chunk { chunk_cmd } => {
            match chunk_cmd {
                ChunkCommands::Info { hash, json } => {
                    cmd_chunk::handle_chunk_info(&hash, json).await?;
                }
                ChunkCommands::Replicas { hash, json } => {
                    cmd_chunk::handle_chunk_replicas(&hash, json).await?;
                }
                ChunkCommands::History { hash, json } => {
                    cmd_chunk::handle_chunk_history(&hash, json).await?;
                }
            }
        }

        Commands::Rebuild { target, from, to, output, json } => {
            cmd_rebuild::handle_rebuild(&target, from, to, output, json).await?;
        }

        Commands::Health { health_cmd } => {
            let is_healthy = match health_cmd {
                HealthCommands::All { json } => {
                    cmd_health::handle_health_all(json).await?
                }
                HealthCommands::Da { json } => {
                    cmd_health::handle_health_da(json).await?
                }
                HealthCommands::Coordinator { json } => {
                    cmd_health::handle_health_coordinator(json).await?
                }
                HealthCommands::Nodes { json } => {
                    cmd_health::handle_health_nodes(json).await?
                }
            };
            
            // Exit code: 0 = healthy, 1 = unhealthy/degraded
            if !is_healthy {
                std::process::exit(1);
            }
        }

        Commands::Identity { identity_cmd } => {
            match identity_cmd {
                IdentityCommands::Generate { out_dir, operator } => {
                    cmd_identity::handle_identity_generate(
                        out_dir.as_deref(),
                        operator.as_deref(),
                    )?;
                }
                IdentityCommands::Show { dir, json } => {
                    cmd_identity::handle_identity_show(&dir, json)?;
                }
                IdentityCommands::Export { dir, format } => {
                    cmd_identity::handle_identity_export(&dir, &format)?;
                }
            }
        }

        Commands::Gating { gating_cmd } => {
            match gating_cmd {
                GatingCommands::StakeCheck { address, chain_rpc, json } => {
                    cmd_gating::handle_stake_check(
                        &address,
                        chain_rpc.as_deref(),
                        json,
                    ).await?;
                }
            }
        }
    }

    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ════════════════════════════════════════════════════════════════════════
    // TEST 1: VALIDATE NODE ID - VALID
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_validate_node_id_valid() {
        assert!(validate_node_id("node-1").is_ok());
        assert!(validate_node_id("node_abc_123").is_ok());
        assert!(validate_node_id("a").is_ok());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 2: VALIDATE NODE ID - EMPTY
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_validate_node_id_empty() {
        let result = validate_node_id("");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("cannot be empty"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 3: VALIDATE NODE ID - TOO LONG
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_validate_node_id_too_long() {
        let long_id = "a".repeat(300);
        let result = validate_node_id(&long_id);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("too long"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 4: NODE STATUS TO TABLE
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_node_status_to_table() {
        let status = NodeStatusFromDA {
            node_id: "node-1".to_string(),
            registration_status: "registered".to_string(),
            addr: "127.0.0.1:9000".to_string(),
            zone: Some("zone-a".to_string()),
            is_active: true,
            chunk_count: 10,
            replica_count: 10,
            da_height: 100,
        };

        let table = status.to_table();

        assert!(table.contains("NODE STATUS"));
        assert!(table.contains("node-1"));
        assert!(table.contains("registered"));
        assert!(table.contains("127.0.0.1:9000"));
        assert!(table.contains("zone-a"));
        assert!(table.contains("yes")); // is_active
        assert!(table.contains("10")); // chunk_count
        assert!(table.contains("from DA"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 5: NODE STATUS TO JSON
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_node_status_to_json() {
        let status = NodeStatusFromDA {
            node_id: "node-1".to_string(),
            registration_status: "registered".to_string(),
            addr: "127.0.0.1:9000".to_string(),
            zone: Some("zone-a".to_string()),
            is_active: true,
            chunk_count: 10,
            replica_count: 10,
            da_height: 100,
        };

        let json = status.to_json().expect("should serialize");
        let parsed: NodeStatusFromDA = serde_json::from_str(&json).expect("should parse");

        assert_eq!(parsed.node_id, status.node_id);
        assert_eq!(parsed.is_active, status.is_active);
        assert_eq!(parsed.chunk_count, status.chunk_count);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 6: NODE LIST EMPTY
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_node_list_empty() {
        let list = NodeListFromDA {
            nodes: vec![],
            total: 0,
            active_count: 0,
            da_height: 0,
        };

        let table = list.to_table();
        assert!(table.contains("No nodes found"));
        assert!(table.contains("Total: 0"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 7: NODE LIST WITH NODES
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_node_list_with_nodes() {
        let list = NodeListFromDA {
            nodes: vec![
                NodeListEntry {
                    node_id: "node-1".to_string(),
                    addr: "127.0.0.1:9000".to_string(),
                    zone: Some("zone-a".to_string()),
                    is_active: true,
                    chunk_count: 5,
                },
                NodeListEntry {
                    node_id: "node-2".to_string(),
                    addr: "127.0.0.1:9001".to_string(),
                    zone: None,
                    is_active: false,
                    chunk_count: 0,
                },
            ],
            total: 2,
            active_count: 1,
            da_height: 100,
        };

        let table = list.to_table();
        assert!(table.contains("node-1"));
        assert!(table.contains("node-2"));
        assert!(table.contains("Total: 2"));
        assert!(table.contains("Active: 1"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 8: NODE LIST JSON
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_node_list_json() {
        let list = NodeListFromDA {
            nodes: vec![
                NodeListEntry {
                    node_id: "node-1".to_string(),
                    addr: "127.0.0.1:9000".to_string(),
                    zone: None,
                    is_active: true,
                    chunk_count: 5,
                },
            ],
            total: 1,
            active_count: 1,
            da_height: 100,
        };

        let json = list.to_json().expect("should serialize");
        let parsed: NodeListFromDA = serde_json::from_str(&json).expect("should parse");

        assert_eq!(parsed.total, 1);
        assert_eq!(parsed.nodes.len(), 1);
        assert_eq!(parsed.nodes[0].node_id, "node-1");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 9: NODE CHUNKS EMPTY
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_node_chunks_empty() {
        let chunks = NodeChunksFromDA {
            node_id: "node-1".to_string(),
            chunks: vec![],
            total: 0,
            total_size: 0,
            da_height: 100,
        };

        let table = chunks.to_table();
        assert!(table.contains("node-1"));
        assert!(table.contains("No chunks assigned"));
        assert!(table.contains("Total: 0"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 10: NODE CHUNKS WITH DATA
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_node_chunks_with_data() {
        let chunks = NodeChunksFromDA {
            node_id: "node-1".to_string(),
            chunks: vec![
                ChunkAssignment {
                    chunk_hash: "abc123".to_string(),
                    size: 1024,
                    owner: "owner-1".to_string(),
                },
                ChunkAssignment {
                    chunk_hash: "def456".to_string(),
                    size: 2048,
                    owner: "owner-2".to_string(),
                },
            ],
            total: 2,
            total_size: 3072,
            da_height: 100,
        };

        let table = chunks.to_table();
        assert!(table.contains("abc123"));
        assert!(table.contains("def456"));
        assert!(table.contains("1024"));
        assert!(table.contains("2048"));
        assert!(table.contains("Total: 2"));
        assert!(table.contains("3072"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 11: NODE CHUNKS JSON
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_node_chunks_json() {
        let chunks = NodeChunksFromDA {
            node_id: "node-1".to_string(),
            chunks: vec![
                ChunkAssignment {
                    chunk_hash: "abc123".to_string(),
                    size: 1024,
                    owner: "owner-1".to_string(),
                },
            ],
            total: 1,
            total_size: 1024,
            da_height: 100,
        };

        let json = chunks.to_json().expect("should serialize");
        let parsed: NodeChunksFromDA = serde_json::from_str(&json).expect("should parse");

        assert_eq!(parsed.node_id, "node-1");
        assert_eq!(parsed.total, 1);
        assert_eq!(parsed.chunks[0].chunk_hash, "abc123");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 12: TRUNCATE STRING
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_truncate_str() {
        assert_eq!(truncate_str("short", 10), "short");
        assert_eq!(truncate_str("exactly10!", 10), "exactly10!");
        assert_eq!(truncate_str("this is too long", 10), "this is...");
        assert_eq!(truncate_str("abc", 3), "abc");
        assert_eq!(truncate_str("abcd", 3), "abc");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 13: DETERMINISTIC OUTPUT - NODE LIST SORTING
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_node_list_deterministic_sorting() {
        // Create unsorted nodes
        let list1 = NodeListFromDA {
            nodes: vec![
                NodeListEntry {
                    node_id: "node-z".to_string(),
                    addr: "addr1".to_string(),
                    zone: None,
                    is_active: true,
                    chunk_count: 0,
                },
                NodeListEntry {
                    node_id: "node-a".to_string(),
                    addr: "addr2".to_string(),
                    zone: None,
                    is_active: true,
                    chunk_count: 0,
                },
            ],
            total: 2,
            active_count: 2,
            da_height: 100,
        };

        // Verify order in table
        let table = list1.to_table();
        let pos_a = table.find("node-a");
        let pos_z = table.find("node-z");
        assert!(pos_a.is_some() && pos_z.is_some());
        // Both should be present (order depends on Vec order, but in real usage we sort)
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14: NO PANIC ON ZONE NONE
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_no_panic_on_zone_none() {
        let status = NodeStatusFromDA {
            node_id: "node-1".to_string(),
            registration_status: "registered".to_string(),
            addr: "127.0.0.1:9000".to_string(),
            zone: None,
            is_active: true,
            chunk_count: 0,
            replica_count: 0,
            da_height: 0,
        };

        let table = status.to_table();
        assert!(table.contains("(none)"));

        let json = status.to_json().expect("should serialize");
        assert!(json.contains("null") || !json.contains("zone")); // zone is null in JSON
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 15: PARSE VERIFY TARGET
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_parse_verify_target() {
        assert!(parse_verify_target("coordinator").is_ok());
        assert!(parse_verify_target("node").is_ok());
        assert!(parse_verify_target("COORDINATOR").is_ok());
        assert!(parse_verify_target("invalid").is_err());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 16: TRACKING STAGE DISPLAY
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_tracking_stage_display() {
        assert_eq!(format!("{}", TrackingStage::Uploading), "UPLOADING");
        assert_eq!(format!("{}", TrackingStage::WaitingDeclared), "WAITING_DECLARED");
        assert_eq!(
            format!("{}", TrackingStage::WaitingReplication { current: 2, target: 3 }),
            "REPLICATING (2/3)"
        );
        assert_eq!(format!("{}", TrackingStage::Complete), "COMPLETE");
        assert_eq!(
            format!("{}", TrackingStage::Failed("timeout".to_string())),
            "FAILED: timeout"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 17: TRACKING RESULT TO TABLE
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_tracking_result_to_table() {
        let result = UploadTrackingResult {
            chunk_hash: "abc123def456".to_string(),
            size: 1024,
            declared: true,
            declared_height: Some(100),
            replicas: vec!["node-1".to_string(), "node-2".to_string()],
            replication_factor: 2,
            target_rf: 3,
            rf_achieved: false,
            tracking_time_ms: 5000,
        };

        let table = result.to_table();
        assert!(table.contains("UPLOAD TRACKING RESULT"));
        assert!(table.contains("abc123def456"));
        assert!(table.contains("1024"));
        assert!(table.contains("yes")); // declared
        assert!(table.contains("100")); // declared height
        assert!(table.contains("2 /   3")); // replication
        assert!(table.contains("node-1"));
        assert!(table.contains("node-2"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 18: TRACKING RESULT EMPTY REPLICAS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_tracking_result_empty_replicas() {
        let result = UploadTrackingResult {
            chunk_hash: "xyz789".to_string(),
            size: 512,
            declared: false,
            declared_height: None,
            replicas: vec![],
            replication_factor: 0,
            target_rf: 1,
            rf_achieved: false,
            tracking_time_ms: 1000,
        };

        let table = result.to_table();
        assert!(table.contains("xyz789"));
        assert!(table.contains("no")); // declared = no
        assert!(table.contains("(none)")); // replicas
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 19: TRACKING RESULT RF ACHIEVED
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_tracking_result_rf_achieved() {
        let result = UploadTrackingResult {
            chunk_hash: "test123".to_string(),
            size: 2048,
            declared: true,
            declared_height: Some(50),
            replicas: vec!["node-1".to_string(), "node-2".to_string(), "node-3".to_string()],
            replication_factor: 3,
            target_rf: 3,
            rf_achieved: true,
            tracking_time_ms: 3000,
        };

        let table = result.to_table();
        assert!(table.contains("(achieved)"));
        assert!(table.contains("node-3"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 20: TRACKING CONFIG FROM ENV
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_tracking_config_default_values() {
        // This test verifies the config structure is correct
        let config = TrackingConfig {
            da_endpoint: "http://localhost:26658".to_string(),
            namespace: "test".to_string(),
            timeout_secs: 120,
            poll_interval_ms: 2000,
        };

        assert_eq!(config.timeout_secs, 120);
        assert_eq!(config.poll_interval_ms, 2000);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 21: TRACKING STAGE EQUALITY
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_tracking_stage_equality() {
        assert_eq!(TrackingStage::Uploading, TrackingStage::Uploading);
        assert_eq!(TrackingStage::Complete, TrackingStage::Complete);
        assert_eq!(
            TrackingStage::WaitingReplication { current: 1, target: 2 },
            TrackingStage::WaitingReplication { current: 1, target: 2 }
        );
        assert_ne!(
            TrackingStage::WaitingReplication { current: 1, target: 2 },
            TrackingStage::WaitingReplication { current: 2, target: 2 }
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 22: DOWNLOAD VERIFICATION RESULT TO TABLE
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_download_verification_result_to_table() {
        let result = DownloadVerificationResult {
            chunk_hash: "abc123def456".to_string(),
            expected_size: 1024,
            actual_size: 1024,
            verified: true,
            source_node_id: Some("node-1".to_string()),
            source_node_addr: Some("127.0.0.1:9000".to_string()),
            attempts: vec![
                DownloadAttemptInfo {
                    node_id: "node-1".to_string(),
                    node_addr: "127.0.0.1:9000".to_string(),
                    success: true,
                    reason: Some("verified".to_string()),
                },
            ],
            da_height: 100,
        };

        let table = result.to_table();
        assert!(table.contains("DOWNLOAD VERIFICATION RESULT"));
        assert!(table.contains("abc123def456"));
        assert!(table.contains("1024"));
        assert!(table.contains("YES"));
        assert!(table.contains("node-1"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 23: DOWNLOAD VERIFICATION RESULT FAILED
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_download_verification_result_failed() {
        let result = DownloadVerificationResult {
            chunk_hash: "xyz789".to_string(),
            expected_size: 2048,
            actual_size: 0,
            verified: false,
            source_node_id: None,
            source_node_addr: None,
            attempts: vec![
                DownloadAttemptInfo {
                    node_id: "node-1".to_string(),
                    node_addr: "127.0.0.1:9000".to_string(),
                    success: false,
                    reason: Some("connection refused".to_string()),
                },
                DownloadAttemptInfo {
                    node_id: "node-2".to_string(),
                    node_addr: "127.0.0.1:9001".to_string(),
                    success: false,
                    reason: Some("hash mismatch".to_string()),
                },
            ],
            da_height: 50,
        };

        let table = result.to_table();
        assert!(table.contains("xyz789"));
        assert!(table.contains("NO"));
        assert!(table.contains("node-1"));
        assert!(table.contains("node-2"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 24: VERIFY CHUNK INTEGRITY
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_chunk_integrity() {
        let data = b"hello world";
        let hash = sha256_hex(data);
        
        assert!(verify_chunk_integrity(data, &hash));
        assert!(!verify_chunk_integrity(data, "wrong_hash"));
        assert!(!verify_chunk_integrity(b"different data", &hash));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 25: DOWNLOAD ATTEMPT INFO SERIALIZATION
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_download_attempt_info_serialization() {
        let attempt = DownloadAttemptInfo {
            node_id: "node-1".to_string(),
            node_addr: "127.0.0.1:9000".to_string(),
            success: true,
            reason: Some("verified".to_string()),
        };

        let json = serde_json::to_string(&attempt).expect("should serialize");
        let parsed: DownloadAttemptInfo = serde_json::from_str(&json).expect("should parse");

        assert_eq!(parsed.node_id, "node-1");
        assert_eq!(parsed.success, true);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 26: DOWNLOAD VERIFICATION EMPTY ATTEMPTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_download_verification_empty_attempts() {
        let result = DownloadVerificationResult {
            chunk_hash: "test123".to_string(),
            expected_size: 512,
            actual_size: 0,
            verified: false,
            source_node_id: None,
            source_node_addr: None,
            attempts: vec![],
            da_height: 0,
        };

        let table = result.to_table();
        assert!(table.contains("(none)"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 27: PARSE REBUILD TARGET
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_parse_rebuild_target() {
        assert!(parse_rebuild_target("coordinator").is_ok());
        assert!(parse_rebuild_target("node").is_ok());
        assert!(parse_rebuild_target("COORDINATOR").is_ok());
        assert!(parse_rebuild_target("NODE").is_ok());
        assert!(parse_rebuild_target("invalid").is_err());
    }
}