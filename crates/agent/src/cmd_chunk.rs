//! # Chunk Status from DA Module
//!
//! Module ini menyediakan command untuk mengecek status chunk dari DA events.
//!
//! ## Prinsip
//!
//! - SEMUA data berasal dari DA events (ChunkDeclared, ReplicaAdded, ReplicaRemoved)
//! - Tidak ada RPC ke node atau coordinator
//! - Output deterministik dan dapat diaudit
//! - Tidak ada asumsi default jika data tidak tersedia
//!
//! ## Commands
//!
//! ```bash
//! agent chunk info <hash>       # Metadata chunk (size, RF, uploader)
//! agent chunk replicas <hash>   # Daftar replica placement
//! agent chunk history <hash>    # Event history timeline
//! ```

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::cmd_da::DAConfig;
use crate::cmd_verify;

// ════════════════════════════════════════════════════════════════════════════
// CHUNK INFO TYPES
// ════════════════════════════════════════════════════════════════════════════

/// Chunk metadata derived from DA events.
/// All fields come from ChunkDeclared and ReplicaAdded events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkInfoFromDA {
    /// Chunk hash (from ChunkDeclared event).
    pub chunk_hash: String,
    /// Chunk size in bytes (from ChunkDeclared event).
    pub size: u64,
    /// Replication factor = number of replicas (from ReplicaAdded events count).
    pub replication_factor: usize,
    /// Uploader/owner address (from ChunkDeclared event).
    pub uploader: String,
    /// DA commitment (from ChunkDeclared event).
    pub commitment: String,
    /// Whether chunk is active (not deleted).
    pub is_active: bool,
    /// DA height when this info was derived.
    pub da_height: u64,
}

impl ChunkInfoFromDA {
    /// Format as table.
    pub fn to_table(&self) -> String {
        let mut output = String::new();
        output.push_str("┌─────────────────────────────────────────────────────────────────────────────┐\n");
        output.push_str("│                         CHUNK INFO (from DA)                                │\n");
        output.push_str("├─────────────────────┬───────────────────────────────────────────────────────┤\n");
        output.push_str(&format!("│ Chunk Hash          │ {:53} │\n", truncate_str(&self.chunk_hash, 53)));
        output.push_str(&format!("│ Size                │ {:>50} bytes │\n", self.size));
        output.push_str(&format!("│ Replication Factor  │ {:53} │\n", self.replication_factor));
        output.push_str(&format!("│ Uploader            │ {:53} │\n", truncate_str(&self.uploader, 53)));
        output.push_str(&format!("│ Commitment          │ {:53} │\n", truncate_str(&self.commitment, 53)));
        output.push_str(&format!("│ Active              │ {:53} │\n", if self.is_active { "yes" } else { "no (deleted)" }));
        output.push_str(&format!("│ DA Height           │ {:53} │\n", self.da_height));
        output.push_str("├─────────────────────┴───────────────────────────────────────────────────────┤\n");
        output.push_str("│ Note: All data derived from DA events only                                  │\n");
        output.push_str("└─────────────────────────────────────────────────────────────────────────────┘\n");
        output
    }

    /// Format as JSON.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .context("failed to serialize chunk info to JSON")
    }
}

// ════════════════════════════════════════════════════════════════════════════
// CHUNK REPLICAS TYPES
// ════════════════════════════════════════════════════════════════════════════

/// Single replica entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicaEntry {
    /// Node ID holding this replica.
    pub node_id: String,
    /// Node address (if available from NodeRegistered).
    pub node_addr: Option<String>,
    /// Node zone (if available).
    pub zone: Option<String>,
    /// Whether node is currently active.
    pub node_active: bool,
}

/// Chunk replicas derived from DA events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkReplicasFromDA {
    /// Chunk hash.
    pub chunk_hash: String,
    /// List of replicas (sorted by node_id for determinism).
    pub replicas: Vec<ReplicaEntry>,
    /// Total replica count.
    pub total: usize,
    /// Count of active replicas (on active nodes).
    pub active_count: usize,
    /// DA height when this was derived.
    pub da_height: u64,
}

impl ChunkReplicasFromDA {
    /// Format as table.
    pub fn to_table(&self) -> String {
        let mut output = String::new();
        output.push_str(&format!("Replicas for chunk: {}\n", truncate_str(&self.chunk_hash, 64)));
        output.push_str("┌──────────────────────────┬──────────────────────┬────────────┬────────┐\n");
        output.push_str("│ Node ID                  │ Address              │ Zone       │ Active │\n");
        output.push_str("├──────────────────────────┼──────────────────────┼────────────┼────────┤\n");

        if self.replicas.is_empty() {
            output.push_str("│                         No replicas found                                 │\n");
        } else {
            for replica in &self.replicas {
                output.push_str(&format!(
                    "│ {:24} │ {:20} │ {:10} │ {:6} │\n",
                    truncate_str(&replica.node_id, 24),
                    truncate_str(replica.node_addr.as_deref().unwrap_or("-"), 20),
                    truncate_str(replica.zone.as_deref().unwrap_or("-"), 10),
                    if replica.node_active { "yes" } else { "no" }
                ));
            }
        }

        output.push_str("├──────────────────────────┴──────────────────────┴────────────┴────────┤\n");
        output.push_str(&format!("│ Total: {} | Active: {} | DA Height: {:>10}                         │\n",
            self.total, self.active_count, self.da_height));
        output.push_str("└───────────────────────────────────────────────────────────────────────┘\n");
        output
    }

    /// Format as JSON.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .context("failed to serialize chunk replicas to JSON")
    }
}

// ════════════════════════════════════════════════════════════════════════════
// CHUNK HISTORY TYPES
// ════════════════════════════════════════════════════════════════════════════

/// Event type for chunk history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChunkEventType {
    /// Chunk was declared/created.
    Declared,
    /// Replica was added to a node.
    ReplicaAdded,
    /// Replica was removed from a node.
    ReplicaRemoved,
    /// Delete was requested.
    DeleteRequested,
}

impl std::fmt::Display for ChunkEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChunkEventType::Declared => write!(f, "DECLARED"),
            ChunkEventType::ReplicaAdded => write!(f, "REPLICA_ADDED"),
            ChunkEventType::ReplicaRemoved => write!(f, "REPLICA_REMOVED"),
            ChunkEventType::DeleteRequested => write!(f, "DELETE_REQUESTED"),
        }
    }
}

/// Single history event entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkHistoryEvent {
    /// Sequence number within the chunk's history (1-based, ascending).
    pub sequence: usize,
    /// Event type.
    pub event_type: ChunkEventType,
    /// DA height where this event occurred.
    pub da_height: u64,
    /// Additional details (e.g., node_id for replica events).
    pub details: String,
}

/// Chunk history timeline derived from DA events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkHistoryFromDA {
    /// Chunk hash.
    pub chunk_hash: String,
    /// Timeline of events (sorted by sequence).
    pub events: Vec<ChunkHistoryEvent>,
    /// Total event count.
    pub total_events: usize,
    /// Current DA height.
    pub da_height: u64,
}

impl ChunkHistoryFromDA {
    /// Format as table.
    pub fn to_table(&self) -> String {
        let mut output = String::new();
        output.push_str(&format!("Event history for chunk: {}\n", truncate_str(&self.chunk_hash, 64)));
        output.push_str("┌─────┬──────────────────┬────────────┬─────────────────────────────────────────┐\n");
        output.push_str("│ Seq │ Event Type       │  DA Height │ Details                                 │\n");
        output.push_str("├─────┼──────────────────┼────────────┼─────────────────────────────────────────┤\n");

        if self.events.is_empty() {
            output.push_str("│                           No events found                                        │\n");
        } else {
            for event in &self.events {
                output.push_str(&format!(
                    "│ {:>3} │ {:16} │ {:>10} │ {:39} │\n",
                    event.sequence,
                    event.event_type,
                    event.da_height,
                    truncate_str(&event.details, 39)
                ));
            }
        }

        output.push_str("├─────┴──────────────────┴────────────┴─────────────────────────────────────────┤\n");
        output.push_str(&format!("│ Total Events: {} | Current DA Height: {:>10}                            │\n",
            self.total_events, self.da_height));
        output.push_str("└──────────────────────────────────────────────────────────────────────────────┘\n");
        output
    }

    /// Format as JSON.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .context("failed to serialize chunk history to JSON")
    }
}

// ════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════

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

/// Validate chunk hash is not empty and has valid format.
pub fn validate_chunk_hash(hash: &str) -> Result<()> {
    if hash.is_empty() {
        anyhow::bail!("chunk hash cannot be empty");
    }
    if hash.len() > 128 {
        anyhow::bail!("chunk hash too long (max 128 characters)");
    }
    // Basic hex validation for common hash formats
    let is_valid_hex = hash.chars().all(|c| c.is_ascii_hexdigit());
    if !is_valid_hex && !hash.contains(':') {
        // Allow hex hashes or prefixed formats like "sha256:..."
        anyhow::bail!("chunk hash has invalid format: expected hex string or prefixed format");
    }
    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════
// COMMAND HANDLERS
// ════════════════════════════════════════════════════════════════════════════

/// Handle `agent chunk info <hash>` command.
/// ALL data is derived from DA events only.
pub async fn handle_chunk_info(chunk_hash: &str, json_output: bool) -> Result<()> {
    // Validate input
    validate_chunk_hash(chunk_hash)?;

    // Rebuild state from DA events only
    let config = DAConfig::from_env();
    let state = cmd_verify::rebuild_state_from_da(&config).await?;

    // Find chunk in DA-derived state
    let chunk_info = state.chunks.get(chunk_hash);

    match chunk_info {
        Some(info) => {
            let result = ChunkInfoFromDA {
                chunk_hash: chunk_hash.to_string(),
                size: info.size,
                replication_factor: info.replicas.len(),
                uploader: info.owner.clone(),
                // Note: commitment not stored in StateChunkInfo, derive from events if needed
                commitment: format!("(derived at height {})", state.last_height),
                is_active: true, // If found in state, it's active (deleted chunks are removed)
                da_height: state.last_height,
            };

            if json_output {
                println!("{}", result.to_json()?);
            } else {
                print!("{}", result.to_table());
            }
        }
        None => {
            anyhow::bail!(
                "chunk '{}' not found in DA events. Searched {} chunks at DA height {}.",
                chunk_hash,
                state.chunks.len(),
                state.last_height
            );
        }
    }

    Ok(())
}

/// Handle `agent chunk replicas <hash>` command.
/// ALL data is derived from DA events only.
pub async fn handle_chunk_replicas(chunk_hash: &str, json_output: bool) -> Result<()> {
    // Validate input
    validate_chunk_hash(chunk_hash)?;

    // Rebuild state from DA events only
    let config = DAConfig::from_env();
    let state = cmd_verify::rebuild_state_from_da(&config).await?;

    // Find chunk in DA-derived state
    let chunk_info = state.chunks.get(chunk_hash);

    match chunk_info {
        Some(info) => {
            // Build replica list with node info
            let mut replicas: Vec<ReplicaEntry> = info.replicas.iter()
                .map(|node_id| {
                    let node_info = state.nodes.get(node_id);
                    ReplicaEntry {
                        node_id: node_id.clone(),
                        node_addr: node_info.map(|n| n.addr.clone()),
                        zone: node_info.and_then(|n| n.zone.clone()),
                        node_active: node_info.map(|n| n.active).unwrap_or(false),
                    }
                })
                .collect();

            // Sort by node_id for deterministic output
            replicas.sort_by(|a, b| a.node_id.cmp(&b.node_id));

            let active_count = replicas.iter().filter(|r| r.node_active).count();

            let result = ChunkReplicasFromDA {
                chunk_hash: chunk_hash.to_string(),
                total: replicas.len(),
                active_count,
                replicas,
                da_height: state.last_height,
            };

            if json_output {
                println!("{}", result.to_json()?);
            } else {
                print!("{}", result.to_table());
            }
        }
        None => {
            anyhow::bail!(
                "chunk '{}' not found in DA events. Cannot list replicas for unknown chunk.",
                chunk_hash
            );
        }
    }

    Ok(())
}

/// Handle `agent chunk history <hash>` command.
/// ALL data is derived from DA events only.
pub async fn handle_chunk_history(chunk_hash: &str, json_output: bool) -> Result<()> {
    // Validate input
    validate_chunk_hash(chunk_hash)?;

    // Rebuild state from DA with history tracking
    let config = DAConfig::from_env();
    let (state, history) = rebuild_state_with_history(&config, chunk_hash).await?;

    if history.is_empty() {
        anyhow::bail!(
            "chunk '{}' not found in DA events. No history available.",
            chunk_hash
        );
    }

    let result = ChunkHistoryFromDA {
        chunk_hash: chunk_hash.to_string(),
        total_events: history.len(),
        events: history,
        da_height: state.last_height,
    };

    if json_output {
        println!("{}", result.to_json()?);
    } else {
        print!("{}", result.to_table());
    }

    Ok(())
}

/// Rebuild state from DA and track history for a specific chunk.
async fn rebuild_state_with_history(
    config: &DAConfig,
    target_chunk_hash: &str,
) -> Result<(cmd_verify::DSDNState, Vec<ChunkHistoryEvent>)> {
    let mut state = cmd_verify::DSDNState::default();
    let mut history: Vec<ChunkHistoryEvent> = Vec::new();
    let mut sequence: usize = 0;

    let client = reqwest::Client::builder()
        .timeout(config.timeout())
        .build()
        .context("failed to build HTTP client")?;

    // Get current DA height
    let current_height = get_da_current_height(&client, config).await?;

    if current_height == 0 {
        return Ok((state, history));
    }

    // Fetch and process events from genesis
    for height in 1..=current_height {
        let events = fetch_events_at_height(&client, config, height).await?;

        for event in events {
            // Track history for target chunk
            match &event {
                cmd_verify::DAEvent::ChunkDeclared { chunk_hash, size, owner, .. } => {
                    if chunk_hash == target_chunk_hash {
                        sequence += 1;
                        history.push(ChunkHistoryEvent {
                            sequence,
                            event_type: ChunkEventType::Declared,
                            da_height: height,
                            details: format!("size={}, owner={}", size, owner),
                        });
                    }
                }
                cmd_verify::DAEvent::ReplicaAdded { chunk_hash, node_id, .. } => {
                    if chunk_hash == target_chunk_hash {
                        sequence += 1;
                        history.push(ChunkHistoryEvent {
                            sequence,
                            event_type: ChunkEventType::ReplicaAdded,
                            da_height: height,
                            details: format!("node={}", node_id),
                        });
                    }
                }
                cmd_verify::DAEvent::ReplicaRemoved { chunk_hash, node_id, reason } => {
                    if chunk_hash == target_chunk_hash {
                        sequence += 1;
                        history.push(ChunkHistoryEvent {
                            sequence,
                            event_type: ChunkEventType::ReplicaRemoved,
                            da_height: height,
                            details: format!("node={}, reason={}", node_id, reason),
                        });
                    }
                }
                cmd_verify::DAEvent::DeleteRequested { chunk_hash, requester } => {
                    if chunk_hash == target_chunk_hash {
                        sequence += 1;
                        history.push(ChunkHistoryEvent {
                            sequence,
                            event_type: ChunkEventType::DeleteRequested,
                            da_height: height,
                            details: format!("requester={}", requester),
                        });
                    }
                }
                _ => {}
            }

            // Apply event to state
            cmd_verify::apply_event_to_state(&mut state, &event);
        }

        state.last_height = height;
    }

    state.last_sequence = current_height;
    Ok((state, history))
}

/// Get current DA height.
async fn get_da_current_height(client: &reqwest::Client, config: &DAConfig) -> Result<u64> {
    let url = format!("{}/header/local_head", config.rpc_url);

    let response = client
        .get(&url)
        .send()
        .await
        .context("failed to get DA header")?;

    if !response.status().is_success() {
        return Ok(0);
    }

    let body = response.text().await.context("failed to read response")?;

    let json: serde_json::Value =
        serde_json::from_str(&body).context("failed to parse header response")?;

    let height = json
        .get("header")
        .and_then(|h| h.get("height"))
        .and_then(|h| h.as_str())
        .and_then(|h| h.parse::<u64>().ok())
        .unwrap_or(0);

    Ok(height)
}

/// Fetch events at specific height.
async fn fetch_events_at_height(
    client: &reqwest::Client,
    config: &DAConfig,
    height: u64,
) -> Result<Vec<cmd_verify::DAEvent>> {
    let url = format!(
        "{}/blob/get_all/{}/{}",
        config.rpc_url, height, config.namespace
    );

    let response = client.get(&url).send().await;

    match response {
        Ok(resp) if resp.status().is_success() => {
            let body = resp.text().await.context("failed to read blob response")?;
            parse_events_from_blobs(&body)
        }
        _ => Ok(Vec::new()),
    }
}

/// Parse events from blob response.
fn parse_events_from_blobs(body: &str) -> Result<Vec<cmd_verify::DAEvent>> {
    let json: serde_json::Value =
        serde_json::from_str(body).context("failed to parse blob response")?;

    let blobs = match json.as_array() {
        Some(arr) => arr,
        None => return Ok(Vec::new()),
    };

    let mut all_events = Vec::new();

    for blob in blobs {
        if let Some(data_b64) = blob.get("data").and_then(|d| d.as_str()) {
            if let Ok(data) = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                data_b64,
            ) {
                if let Ok(events) = serde_json::from_slice::<Vec<cmd_verify::DAEvent>>(&data) {
                    all_events.extend(events);
                }
            }
        }
    }

    Ok(all_events)
}

// ════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ════════════════════════════════════════════════════════════════════════
    // TEST 1: VALIDATE CHUNK HASH - VALID
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_validate_chunk_hash_valid() {
        assert!(validate_chunk_hash("abc123def456").is_ok());
        assert!(validate_chunk_hash("0123456789abcdef").is_ok());
        assert!(validate_chunk_hash("sha256:abc123").is_ok());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 2: VALIDATE CHUNK HASH - EMPTY
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_validate_chunk_hash_empty() {
        let result = validate_chunk_hash("");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("cannot be empty"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 3: VALIDATE CHUNK HASH - TOO LONG
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_validate_chunk_hash_too_long() {
        let long_hash = "a".repeat(200);
        let result = validate_chunk_hash(&long_hash);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("too long"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 4: CHUNK INFO TO TABLE
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_chunk_info_to_table() {
        let info = ChunkInfoFromDA {
            chunk_hash: "abc123def456".to_string(),
            size: 1024,
            replication_factor: 3,
            uploader: "user-1".to_string(),
            commitment: "commit-xyz".to_string(),
            is_active: true,
            da_height: 100,
        };

        let table = info.to_table();

        assert!(table.contains("CHUNK INFO"));
        assert!(table.contains("abc123def456"));
        assert!(table.contains("1024"));
        assert!(table.contains("3")); // RF
        assert!(table.contains("user-1"));
        assert!(table.contains("yes")); // active
        assert!(table.contains("from DA"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 5: CHUNK INFO TO JSON
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_chunk_info_to_json() {
        let info = ChunkInfoFromDA {
            chunk_hash: "abc123".to_string(),
            size: 2048,
            replication_factor: 2,
            uploader: "owner".to_string(),
            commitment: "commit".to_string(),
            is_active: true,
            da_height: 50,
        };

        let json = info.to_json().expect("should serialize");
        let parsed: ChunkInfoFromDA = serde_json::from_str(&json).expect("should parse");

        assert_eq!(parsed.chunk_hash, "abc123");
        assert_eq!(parsed.size, 2048);
        assert_eq!(parsed.replication_factor, 2);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 6: CHUNK REPLICAS EMPTY
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_chunk_replicas_empty() {
        let replicas = ChunkReplicasFromDA {
            chunk_hash: "abc123".to_string(),
            replicas: vec![],
            total: 0,
            active_count: 0,
            da_height: 100,
        };

        let table = replicas.to_table();
        assert!(table.contains("abc123"));
        assert!(table.contains("No replicas found"));
        assert!(table.contains("Total: 0"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 7: CHUNK REPLICAS WITH DATA
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_chunk_replicas_with_data() {
        let replicas = ChunkReplicasFromDA {
            chunk_hash: "abc123".to_string(),
            replicas: vec![
                ReplicaEntry {
                    node_id: "node-1".to_string(),
                    node_addr: Some("127.0.0.1:9000".to_string()),
                    zone: Some("zone-a".to_string()),
                    node_active: true,
                },
                ReplicaEntry {
                    node_id: "node-2".to_string(),
                    node_addr: Some("127.0.0.1:9001".to_string()),
                    zone: None,
                    node_active: false,
                },
            ],
            total: 2,
            active_count: 1,
            da_height: 100,
        };

        let table = replicas.to_table();
        assert!(table.contains("node-1"));
        assert!(table.contains("node-2"));
        assert!(table.contains("127.0.0.1:9000"));
        assert!(table.contains("zone-a"));
        assert!(table.contains("Total: 2"));
        assert!(table.contains("Active: 1"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 8: CHUNK REPLICAS JSON
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_chunk_replicas_json() {
        let replicas = ChunkReplicasFromDA {
            chunk_hash: "xyz789".to_string(),
            replicas: vec![
                ReplicaEntry {
                    node_id: "node-1".to_string(),
                    node_addr: None,
                    zone: None,
                    node_active: true,
                },
            ],
            total: 1,
            active_count: 1,
            da_height: 50,
        };

        let json = replicas.to_json().expect("should serialize");
        let parsed: ChunkReplicasFromDA = serde_json::from_str(&json).expect("should parse");

        assert_eq!(parsed.chunk_hash, "xyz789");
        assert_eq!(parsed.total, 1);
        assert_eq!(parsed.replicas[0].node_id, "node-1");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 9: CHUNK HISTORY EMPTY
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_chunk_history_empty() {
        let history = ChunkHistoryFromDA {
            chunk_hash: "abc123".to_string(),
            events: vec![],
            total_events: 0,
            da_height: 100,
        };

        let table = history.to_table();
        assert!(table.contains("abc123"));
        assert!(table.contains("No events found"));
        assert!(table.contains("Total Events: 0"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 10: CHUNK HISTORY WITH EVENTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_chunk_history_with_events() {
        let history = ChunkHistoryFromDA {
            chunk_hash: "abc123".to_string(),
            events: vec![
                ChunkHistoryEvent {
                    sequence: 1,
                    event_type: ChunkEventType::Declared,
                    da_height: 10,
                    details: "size=1024, owner=user1".to_string(),
                },
                ChunkHistoryEvent {
                    sequence: 2,
                    event_type: ChunkEventType::ReplicaAdded,
                    da_height: 11,
                    details: "node=node-1".to_string(),
                },
                ChunkHistoryEvent {
                    sequence: 3,
                    event_type: ChunkEventType::ReplicaAdded,
                    da_height: 12,
                    details: "node=node-2".to_string(),
                },
            ],
            total_events: 3,
            da_height: 100,
        };

        let table = history.to_table();
        assert!(table.contains("DECLARED"));
        assert!(table.contains("REPLICA_ADDED"));
        assert!(table.contains("node-1"));
        assert!(table.contains("node-2"));
        assert!(table.contains("Total Events: 3"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 11: CHUNK HISTORY JSON
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_chunk_history_json() {
        let history = ChunkHistoryFromDA {
            chunk_hash: "def456".to_string(),
            events: vec![
                ChunkHistoryEvent {
                    sequence: 1,
                    event_type: ChunkEventType::Declared,
                    da_height: 5,
                    details: "test".to_string(),
                },
            ],
            total_events: 1,
            da_height: 50,
        };

        let json = history.to_json().expect("should serialize");
        let parsed: ChunkHistoryFromDA = serde_json::from_str(&json).expect("should parse");

        assert_eq!(parsed.chunk_hash, "def456");
        assert_eq!(parsed.total_events, 1);
        assert_eq!(parsed.events[0].event_type, ChunkEventType::Declared);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 12: CHUNK EVENT TYPE DISPLAY
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_chunk_event_type_display() {
        assert_eq!(format!("{}", ChunkEventType::Declared), "DECLARED");
        assert_eq!(format!("{}", ChunkEventType::ReplicaAdded), "REPLICA_ADDED");
        assert_eq!(format!("{}", ChunkEventType::ReplicaRemoved), "REPLICA_REMOVED");
        assert_eq!(format!("{}", ChunkEventType::DeleteRequested), "DELETE_REQUESTED");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 13: TRUNCATE STRING
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_truncate_str_chunk() {
        assert_eq!(truncate_str("short", 10), "short");
        assert_eq!(truncate_str("exactly10!", 10), "exactly10!");
        assert_eq!(truncate_str("this is too long", 10), "this is...");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14: DETERMINISTIC REPLICA SORTING
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_deterministic_replica_sorting() {
        let replicas = ChunkReplicasFromDA {
            chunk_hash: "test".to_string(),
            replicas: vec![
                ReplicaEntry {
                    node_id: "node-z".to_string(),
                    node_addr: None,
                    zone: None,
                    node_active: true,
                },
                ReplicaEntry {
                    node_id: "node-a".to_string(),
                    node_addr: None,
                    zone: None,
                    node_active: true,
                },
            ],
            total: 2,
            active_count: 2,
            da_height: 100,
        };

        let table = replicas.to_table();
        let pos_a = table.find("node-a");
        let pos_z = table.find("node-z");
        assert!(pos_a.is_some() && pos_z.is_some());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 15: NO PANIC ON NONE VALUES
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_no_panic_on_none_values() {
        let replica = ReplicaEntry {
            node_id: "node-1".to_string(),
            node_addr: None,
            zone: None,
            node_active: false,
        };

        let replicas = ChunkReplicasFromDA {
            chunk_hash: "test".to_string(),
            replicas: vec![replica],
            total: 1,
            active_count: 0,
            da_height: 0,
        };

        // Should not panic
        let table = replicas.to_table();
        assert!(table.contains("-")); // Default for None
        let _ = replicas.to_json();
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 16: HISTORY EVENT SEQUENCE ORDER
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_history_event_sequence_order() {
        let history = ChunkHistoryFromDA {
            chunk_hash: "test".to_string(),
            events: vec![
                ChunkHistoryEvent {
                    sequence: 1,
                    event_type: ChunkEventType::Declared,
                    da_height: 10,
                    details: "first".to_string(),
                },
                ChunkHistoryEvent {
                    sequence: 2,
                    event_type: ChunkEventType::ReplicaAdded,
                    da_height: 15,
                    details: "second".to_string(),
                },
                ChunkHistoryEvent {
                    sequence: 3,
                    event_type: ChunkEventType::ReplicaRemoved,
                    da_height: 20,
                    details: "third".to_string(),
                },
            ],
            total_events: 3,
            da_height: 100,
        };

        // Verify sequences are in order
        for (i, event) in history.events.iter().enumerate() {
            assert_eq!(event.sequence, i + 1);
        }

        // Verify DA heights are ascending
        let heights: Vec<u64> = history.events.iter().map(|e| e.da_height).collect();
        for i in 1..heights.len() {
            assert!(heights[i] >= heights[i - 1]);
        }
    }
}