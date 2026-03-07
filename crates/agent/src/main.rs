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
//! ### Gating Operations (14B.53–14B.59)
//! - `gating stake-check`: Check stake status for a service node
//!   - `--address`: Operator address (40 hex chars, required)
//!   - `--chain-rpc`: Chain RPC endpoint URL (optional)
//!   - `--json`: Output as JSON
//! - `gating register`: Register service node on-chain
//!   - `--identity-dir`: Path to identity directory (required)
//!   - `--class`: "storage" or "compute" (required)
//!   - `--chain-rpc`: Chain RPC endpoint URL (required)
//!   - `--keyfile`: Path to wallet secret key file (optional, errors if missing)
//! - `gating status`: Query full gating status of a service node
//!   - `--address`: Operator address (40 hex chars, required)
//!   - `--chain-rpc`: Chain RPC endpoint URL (optional)
//!   - `--json`: Output as JSON
//! - `gating slashing-status`: Query slashing & cooldown status
//!   - `--address`: Operator address (40 hex chars, required)
//!   - `--chain-rpc`: Chain RPC endpoint URL (optional)
//!   - `--json`: Output as JSON
//! - `gating node-class`: Query node class and stake requirements
//!   - `--address`: Operator address (40 hex chars, required)
//!   - `--chain-rpc`: Chain RPC endpoint URL (optional)
//!   - `--json`: Output as JSON
//! - `gating list-active`: List all active service nodes
//!   - `--chain-rpc`: Chain RPC endpoint URL (optional)
//!   - `--json`: Output as JSON
//! - `gating quarantine-status`: Query quarantine details and recovery
//!   - `--address`: Operator address (40 hex chars, required)
//!   - `--chain-rpc`: Chain RPC endpoint URL (optional)
//!   - `--json`: Output as JSON
//! - `gating ban-status`: Query ban details and cooldown
//!   - `--address`: Operator address (40 hex chars, required)
//!   - `--chain-rpc`: Chain RPC endpoint URL (optional)
//!   - `--json`: Output as JSON
//! - `gating diagnose`: Full gating diagnosis report
//!   - `--address`: Operator address (40 hex chars, required)
//!   - `--identity-dir`: Path to identity directory (optional, enables identity/TLS checks)
//!   - `--chain-rpc`: Chain RPC endpoint URL (optional)
//!   - `--json`: Output as JSON
//!
//! //! ### Economic Flow Monitoring (14C.C.16)
//! - `economic status <receipt_hash>`: Show receipt lifecycle status
//! - `economic list`: List all tracked receipts (sorted by receipt_hash)
//! - `economic summary`: Show aggregate summary by state
//!
//! ### Retry Logic (14C.C.17)
//! - `retry` module: Exponential backoff with deterministic jitter
//! - `RetryConfig`: max_retries, initial_delay_ms, max_delay_ms, backoff_multiplier, jitter
//! - `retry_with_backoff`: Async retry with non-retryable error short-circuit
//! - `is_retryable`: Classifies errors as network (retryable) vs validation (non-retryable)
//!
//! ### Workload Dispatch + Execution Monitoring (14C.C.18)
//! - `economic dispatch --type <storage|compute> --node <addr> <file>`: Dispatch workload
//! - `economic monitor <workload_id>`: Monitor execution status
//! - Retry integration via `retry_with_backoff` for all network calls
//! - Timeout enforcement via `tokio::time::timeout`
//! - Response validation (empty fields, NaN progress, bounds checks)
//!
//! ### Receipt Submission + Chain Claim (14C.C.19)
//! - `economic claim <receipt_hash>`: Submit receipt claim to chain
//! - `economic claim-status <receipt_hash>`: Poll claim status on-chain
//! - Double-claim protection: `AlreadyClaimed` error classification
//! - Response validation: amount>0, non-empty tx_hash/challenge_id/reason
//! - Retry + timeout enforced on all network calls
//!
//! ### Full Lifecycle Orchestration (14C.C.20)
//! - `economic run --type <storage|compute> --auto-claim <file>`: Run full flow
//! - Strict step order: dispatch → monitor → proof → submit_receipt → claim
//! - Polling bounded by MAX_POLL_ITERATIONS (no infinite loops)
//! - State tracker updated at every step; error → Failed state
//! - Saturating duration arithmetic (no overflow)
//!
//! ### Economic Metrics + Logging (14C.C.21)
//! - `economic metrics`: Show economic metrics table (default: table format)
//! - `economic metrics --json`: Show economic metrics as JSON
//! - Structured logging: `[ECONOMIC] DISPATCH/EXECUTE/CLAIM` format
//! - Overflow-safe counters (checked_add on all u64/u128 fields)
//! - Deterministic average flow duration (integer division, zero when no completions)
//! - Prometheus exposition format via `to_prometheus()`
//!
//! # Economic Flow
//!
//! The economic subsystem manages the full lifecycle of paid workloads on DSDN.
//!
//! ## Flow Overview
//!
//! 1. **Dispatch** — Operator submits a workload (storage or compute) to a service
//!    node via the coordinator. The dispatcher validates the workload type, serialises
//!    the payload, and sends it with retry+timeout protection.
//!
//! 2. **Execution** — The service node executes the workload. The agent polls
//!    execution status (`economic monitor`) with bounded iterations to avoid
//!    infinite loops. Progress is validated (NaN/bounds checks).
//!
//! 3. **Receipt Submission** — On successful execution the node produces a receipt
//!    (proof-of-work). The receipt is submitted to the chain ingress endpoint.
//!    The `ReceiptStatusTracker` records every state transition:
//!    `Pending → Dispatched → Executing → ReceiptSubmitted → Claimed | Failed`.
//!
//! 4. **Claim** — The operator claims payment for the receipt via
//!    `economic claim <hash>`. Double-claim attempts are detected and returned as
//!    `AlreadyClaimed` errors. Response fields (amount, tx_hash) are validated.
//!
//! 5. **Monitoring** — `economic status`, `economic list`, and `economic summary`
//!    provide visibility into all tracked receipts and their current state.
//!
//! 6. **Retry Strategy** — All network calls use exponential backoff with
//!    deterministic jitter. `RetryConfig` controls: max_retries,
//!    initial_delay_ms, max_delay_ms, backoff_multiplier, jitter.
//!    Non-retryable errors (validation, AlreadyClaimed) short-circuit immediately.
//!
//! 7. **Metrics Collection** — `EconomicMetrics` records dispatch_count,
//!    claim_count, failure_count, total revenue, and flow durations.
//!    Counters use `checked_add` (overflow-safe). Average duration uses integer
//!    division (zero when no completions). Export via table, JSON, or Prometheus
//!    exposition format.
//!
//! ## Command Table
//!
//! | Command                  | Description                                    |
//! |--------------------------|------------------------------------------------|
//! | `economic dispatch`      | Dispatch workload to service node               |
//! | `economic monitor`       | Monitor execution status of dispatched workload  |
//! | `economic claim`         | Submit receipt claim to chain                    |
//! | `economic claim-status`  | Poll claim status on-chain                       |
//! | `economic run`           | Run full lifecycle (dispatch→claim)              |
//! | `economic metrics`       | Show economic metrics (table/JSON/prometheus)    |
//!
//! ## Architecture Diagram
//!
//! ```text
//! dispatch → execute → receipt → claim → monitor
//!          ↘ retry ↗
//! metrics ← all steps
//! ```
//!
//! ### Economic Flow Monitoring (14C.C.16)
//! - `economic status <receipt_hash>`: Show receipt lifecycle status
//! - `economic list`: List all tracked receipts (sorted by receipt_hash)
//! - `economic summary`: Show aggregate summary by state
//!
//! ### Retry Logic (14C.C.17)
//! - `retry` module: Exponential backoff with deterministic jitter
//! - `RetryConfig`: max_retries, initial_delay_ms, max_delay_ms, backoff_multiplier, jitter
//! - `retry_with_backoff`: Async retry with non-retryable error short-circuit
//! - `is_retryable`: Classifies errors as network (retryable) vs validation (non-retryable)
//!
//! ### Workload Dispatch + Execution Monitoring (14C.C.18)
//! - `economic dispatch --type <storage|compute> --node <addr> <file>`: Dispatch workload
//! - `economic monitor <workload_id>`: Monitor execution status
//! - Retry integration via `retry_with_backoff` for all network calls
//! - Timeout enforcement via `tokio::time::timeout`
//! - Response validation (empty fields, NaN progress, bounds checks)
//!
//! ### Receipt Submission + Chain Claim (14C.C.19)
//! - `economic claim <receipt_hash>`: Submit receipt claim to chain
//! - `economic claim-status <receipt_hash>`: Poll claim status on-chain
//! - Double-claim protection: `AlreadyClaimed` error classification
//! - Response validation: amount>0, non-empty tx_hash/challenge_id/reason
//! - Retry + timeout enforced on all network calls
//!
//! ### Full Lifecycle Orchestration (14C.C.20)
//! - `economic run --type <storage|compute> --auto-claim <file>`: Run full flow
//! - Strict step order: dispatch → monitor → proof → submit_receipt → claim
//! - Polling bounded by MAX_POLL_ITERATIONS (no infinite loops)
//! - State tracker updated at every step; error → Failed state
//! - Saturating duration arithmetic (no overflow)
//!
//! ### Economic Metrics + Logging (14C.C.21)
//! - `economic metrics`: Show economic metrics table (default: table format)
//! - `economic metrics --json`: Show economic metrics as JSON
//! - Structured logging: `[ECONOMIC] DISPATCH/EXECUTE/CLAIM` format
//! - Overflow-safe counters (checked_add on all u64/u128 fields)
//! - Deterministic average flow duration (integer division, zero when no completions)
//! - Prometheus exposition format via `to_prometheus()`
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
//! - `DSDN_COORDINATOR_ENDPOINT`: Coordinator endpoint (default: http://127.0.0.1:45831)
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
mod cmd_economic;
mod economic_metrics;
mod retry;

mod cli;
mod da_types;
mod upload_tracking;
mod download_verify;
mod node_handlers;

use anyhow::Result;
use clap::Parser;
use base64::{engine::general_purpose, Engine as _};
use hex::encode as hex_encode;

use std::fs;
use std::io::Read;

use crate::sss::{split_secret, recover_secret};
use crate::crypto::{gen_key, encrypt_aes_gcm, decrypt_aes_gcm};
use dsdn_common::cid::sha256_hex;
use dsdn_storage::rpc;

// Re-export from new modules so tests (`use super::*`) can access them
pub(crate) use crate::cli::*;
pub(crate) use crate::da_types::*;
pub(crate) use crate::upload_tracking::*;
pub(crate) use crate::download_verify::*;
pub(crate) use crate::node_handlers::*;

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
                GatingCommands::Register {
                    identity_dir,
                    class,
                    chain_rpc,
                    keyfile,
                } => {
                    cmd_gating::handle_register(
                        &identity_dir,
                        &class,
                        &chain_rpc,
                        keyfile.as_deref(),
                    ).await?;
                }
                GatingCommands::Status { address, chain_rpc, json } => {
                    cmd_gating::handle_status(
                        &address,
                        chain_rpc.as_deref(),
                        json,
                    ).await?;
                }
                GatingCommands::SlashingStatus { address, chain_rpc, json } => {
                    cmd_gating::handle_slashing_status(
                        &address,
                        chain_rpc.as_deref(),
                        json,
                    ).await?;
                }
                GatingCommands::NodeClass { address, chain_rpc, json } => {
                    cmd_gating::handle_node_class(
                        &address,
                        chain_rpc.as_deref(),
                        json,
                    ).await?;
                }
                GatingCommands::ListActive { chain_rpc, json } => {
                    cmd_gating::handle_list_active(
                        chain_rpc.as_deref(),
                        json,
                    ).await?;
                }
                GatingCommands::QuarantineStatus { address, chain_rpc, json } => {
                    cmd_gating::handle_quarantine_status(
                        &address,
                        chain_rpc.as_deref(),
                        json,
                    ).await?;
                }
                GatingCommands::BanStatus { address, chain_rpc, json } => {
                    cmd_gating::handle_ban_status(
                        &address,
                        chain_rpc.as_deref(),
                        json,
                    ).await?;
                }
                GatingCommands::Diagnose { address, identity_dir, chain_rpc, json } => {
                    cmd_gating::handle_diagnose(
                        &address,
                        identity_dir.as_deref(),
                        chain_rpc.as_deref(),
                        json,
                    ).await?;
                }
            }
        }

        Commands::Economic { economic_cmd } => {
            // NOTE: In production, the tracker would be loaded from persistent state.
            // This CLI stub creates a fresh tracker for demonstration / integration testing.
            let tracker = cmd_economic::ReceiptStatusTracker::new();
            match economic_cmd {
                EconomicCommands::Status { receipt_hash } => {
                    cmd_economic::handle_economic_status(&tracker, &receipt_hash);
                }
                EconomicCommands::List => {
                    cmd_economic::handle_economic_list(&tracker);
                }
                EconomicCommands::Summary => {
                    cmd_economic::handle_economic_summary(&tracker);
                }
                EconomicCommands::Dispatch { r#type, node, file } => {
                    let data = match std::fs::read(&file) {
                        Ok(d) => d,
                        Err(e) => {
                            eprintln!("Error reading file '{}': {}", file.display(), e);
                            return Ok(());
                        }
                    };
                    let coord = std::env::var("DSDN_COORDINATOR_ENDPOINT")
                        .unwrap_or_else(|_| "http://127.0.0.1:45831".to_string());
                    cmd_economic::handle_economic_dispatch(
                        &r#type, &node, &data, &coord,
                    )
                    .await;
                }
                EconomicCommands::Monitor { workload_id } => {
                    let coord = std::env::var("DSDN_COORDINATOR_ENDPOINT")
                        .unwrap_or_else(|_| "http://127.0.0.1:45831".to_string());
                    cmd_economic::handle_economic_monitor(&coord, &workload_id).await;
                }
                EconomicCommands::Claim { receipt_hash } => {
                    let ingress = std::env::var("DSDN_INGRESS_ENDPOINT")
                        .unwrap_or_else(|_| "http://127.0.0.1:45832".to_string());
                    cmd_economic::handle_economic_claim(&ingress, &receipt_hash).await;
                }
                EconomicCommands::ClaimStatus { receipt_hash } => {
                    let ingress = std::env::var("DSDN_INGRESS_ENDPOINT")
                        .unwrap_or_else(|_| "http://127.0.0.1:45832".to_string());
                    cmd_economic::handle_economic_claim_status(&ingress, &receipt_hash).await;
                }
                EconomicCommands::Run { r#type, auto_claim, node, file } => {
                    let data = match std::fs::read(&file) {
                        Ok(d) => d,
                        Err(e) => {
                            eprintln!("Error reading file '{}': {}", file.display(), e);
                            return Ok(());
                        }
                    };
                    let coord = std::env::var("DSDN_COORDINATOR_ENDPOINT")
                        .unwrap_or_else(|_| "http://127.0.0.1:45831".to_string());
                    let ingress = std::env::var("DSDN_INGRESS_ENDPOINT")
                        .unwrap_or_else(|_| "http://127.0.0.1:45832".to_string());
                    cmd_economic::handle_economic_run(
                        &r#type, auto_claim, &data, &coord, &ingress, &node,
                    )
                    .await;
                }
                EconomicCommands::Metrics { json } => {
                    // NOTE: In production, metrics would be loaded from persistent state
                    // or a shared Arc<Mutex<EconomicMetrics>>. This CLI stub creates a
                    // fresh metrics instance for demonstration / integration testing.
                    let metrics = economic_metrics::EconomicMetrics::new();
                    economic_metrics::handle_economic_metrics(&metrics, json);
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
mod tests;