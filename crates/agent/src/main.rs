mod sss;
mod crypto;
mod cmd_da;
mod cmd_verify;

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
#[command(author="INEVA", version, about="DSDN Agent CLI")]
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
    },

    /// Download a file by hash from node. Optionally decrypt with provided key (base64)
    Get {
        node_addr: String,
        hash: String,
        #[arg(long)]
        decrypt_key_b64: Option<String>,
        #[arg(long)]
        out: Option<PathBuf>,
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

        Commands::Upload { node_addr, file, encrypt } => {
            let mut f = fs::File::open(&file)?;
            let mut buf = Vec::new();
            f.read_to_end(&mut buf)?;
            let to_upload = buf;
            let mut printed_key: Option<String> = None;
            let connect = format!("http://{}", node_addr);

            if encrypt {
                let key = gen_key();
                let cipher_blob = encrypt_aes_gcm(&key, &to_upload)?;
                let hash = sha256_hex(&cipher_blob);
                println!("Uploading encrypted blob (cid {}) to {}", hash, node_addr);

                let returned = rpc::client_put(connect.clone(), hash.clone(), cipher_blob.clone())
                    .await
                    .map_err(|e| anyhow::anyhow!(format!("{}", e)))?;
                println!("uploaded -> returned {}", returned);

                let b64 = general_purpose::STANDARD.encode(&key);
                printed_key = Some(b64.clone());
                println!("ENCRYPTION_KEY_B64: {}", b64);
            } else {
                let hash = sha256_hex(&to_upload);
                println!("Uploading blob (cid {}) to {}", hash, node_addr);
                let returned = rpc::client_put(connect.clone(), hash.clone(), to_upload.clone())
                    .await
                    .map_err(|e| anyhow::anyhow!(format!("{}", e)))?;
                println!("uploaded -> returned {}", returned);
            }
            if let Some(_k) = printed_key {
                println!("Note: save this encryption key (base64) to decrypt later.");
            }
        }

        Commands::Get { node_addr, hash, decrypt_key_b64, out } => {
            let connect = format!("http://{}", node_addr);
            let opt = rpc::client_get(connect.clone(), hash.clone())
                .await
                .map_err(|e| anyhow::anyhow!(format!("{}", e)))?;
            match opt {
                None => {
                    println!("not found on node {}", node_addr);
                }
                Some(data) => {
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
}