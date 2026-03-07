use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::cmd_da;
use crate::cmd_verify;
use crate::da_types::truncate_str;
use dsdn_common::cid::sha256_hex;
use dsdn_storage::rpc;

// ════════════════════════════════════════════════════════════════════════════
// DOWNLOAD DA VERIFICATION
// ════════════════════════════════════════════════════════════════════════════

/// Download attempt result.
#[derive(Debug, Clone)]
pub(crate) enum DownloadAttemptResult {
    /// Download successful, data verified.
    Success { node_id: String, node_addr: String, data: Vec<u8> },
    /// Download failed (network error, not found, etc.).
    Failed { node_id: String, node_addr: String, reason: String },
    /// Download succeeded but verification failed.
    VerificationFailed { node_id: String, node_addr: String, reason: String },
}

/// Download verification result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DownloadVerificationResult {
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
pub(crate) struct DownloadAttemptInfo {
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
pub(crate) struct DAChunkInfo {
    chunk_hash: String,
    size: u64,
    owner: String,
    replicas: Vec<DAReplicaInfo>,
}

/// Replica info from DA.
#[derive(Debug, Clone)]
pub(crate) struct DAReplicaInfo {
    node_id: String,
    node_addr: String,
    is_active: bool,
}

/// Fetch chunk placement info from DA.
pub(crate) async fn fetch_chunk_placement_from_da(chunk_hash: &str) -> Result<(DAChunkInfo, u64)> {
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
pub(crate) fn verify_chunk_integrity(data: &[u8], expected_hash: &str) -> bool {
    let actual_hash = sha256_hex(data);
    actual_hash == expected_hash
}

/// Try to download from a single node.
pub(crate) async fn try_download_from_node(
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
pub(crate) async fn download_with_da_verification(
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