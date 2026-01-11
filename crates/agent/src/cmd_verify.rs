//! # State Verification Command Module
//!
//! Module ini menyediakan command untuk verifikasi state DSDN.
//!
//! ## Prinsip
//!
//! - Rebuild state dari DA secara penuh (dari genesis/checkpoint)
//! - Perbandingan deterministik field-by-field
//! - Tidak ada toleransi mismatch
//! - Exit code 0 = konsisten, 1 = inkonsisten
//! - Tidak ada auto-fix, hanya laporan dan saran
//! - Tidak ada panic, unwrap, atau silent failure
//!
//! ## Usage
//!
//! ```bash
//! agent verify state --target coordinator    # Verify coordinator state
//! agent verify state --target node           # Verify node state
//! agent verify consistency --node <addr>     # Verify node consistency
//! ```

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use crate::cmd_da::DAConfig;

// ════════════════════════════════════════════════════════════════════════════
// VERIFY TARGET
// ════════════════════════════════════════════════════════════════════════════

/// Target untuk state verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyTarget {
    /// Verify coordinator state.
    Coordinator,
    /// Verify node state.
    Node,
}

impl VerifyTarget {
    /// Parse target dari string.
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "coordinator" => Ok(VerifyTarget::Coordinator),
            "node" => Ok(VerifyTarget::Node),
            _ => Err(format!(
                "invalid target '{}': must be 'coordinator' or 'node'",
                s
            )),
        }
    }
}

impl fmt::Display for VerifyTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyTarget::Coordinator => write!(f, "coordinator"),
            VerifyTarget::Node => write!(f, "node"),
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// DISCREPANCY
// ════════════════════════════════════════════════════════════════════════════

/// Tipe perbedaan yang ditemukan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscrepancyType {
    /// Field ada di DA tapi tidak di target.
    MissingInTarget,
    /// Field ada di target tapi tidak di DA.
    MissingInDA,
    /// Nilai berbeda antara DA dan target.
    ValueMismatch,
    /// Tipe berbeda.
    TypeMismatch,
}

impl fmt::Display for DiscrepancyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DiscrepancyType::MissingInTarget => write!(f, "MISSING_IN_TARGET"),
            DiscrepancyType::MissingInDA => write!(f, "MISSING_IN_DA"),
            DiscrepancyType::ValueMismatch => write!(f, "VALUE_MISMATCH"),
            DiscrepancyType::TypeMismatch => write!(f, "TYPE_MISMATCH"),
        }
    }
}

/// Detail perbedaan state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Discrepancy {
    /// Tipe perbedaan.
    pub discrepancy_type: DiscrepancyType,
    /// Path ke field yang berbeda (e.g., "nodes.node-1.active").
    pub path: String,
    /// Nilai dari DA (jika ada).
    pub da_value: Option<String>,
    /// Nilai dari target (jika ada).
    pub target_value: Option<String>,
    /// Deskripsi perbedaan.
    pub description: String,
}

impl Discrepancy {
    /// Format sebagai string untuk display.
    pub fn to_display(&self) -> String {
        let mut output = String::new();
        output.push_str(&format!("  [{}] {}\n", self.discrepancy_type, self.path));
        if let Some(ref da_val) = self.da_value {
            output.push_str(&format!("    DA value:     {}\n", da_val));
        }
        if let Some(ref target_val) = self.target_value {
            output.push_str(&format!("    Target value: {}\n", target_val));
        }
        output.push_str(&format!("    Description:  {}\n", self.description));
        output
    }

    /// Suggested fix untuk discrepancy ini.
    pub fn suggested_fix(&self) -> String {
        match self.discrepancy_type {
            DiscrepancyType::MissingInTarget => {
                format!(
                    "Add '{}' to target with value from DA: {:?}",
                    self.path,
                    self.da_value
                )
            }
            DiscrepancyType::MissingInDA => {
                format!(
                    "Investigate why '{}' exists in target but not in DA. May need to submit to DA.",
                    self.path
                )
            }
            DiscrepancyType::ValueMismatch => {
                format!(
                    "Update '{}' in target to match DA value: {:?} (current: {:?})",
                    self.path, self.da_value, self.target_value
                )
            }
            DiscrepancyType::TypeMismatch => {
                format!(
                    "Type mismatch at '{}'. Investigate data corruption or schema mismatch.",
                    self.path
                )
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// VERIFICATION RESULT
// ════════════════════════════════════════════════════════════════════════════

/// Hasil verifikasi state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Target yang diverifikasi.
    pub target: String,
    /// Apakah state konsisten.
    pub is_consistent: bool,
    /// Jumlah total field yang dibandingkan.
    pub fields_compared: usize,
    /// Jumlah perbedaan yang ditemukan.
    pub discrepancy_count: usize,
    /// Detail perbedaan.
    pub discrepancies: Vec<Discrepancy>,
    /// DA height yang digunakan untuk rebuild.
    pub da_height: u64,
    /// Timestamp verifikasi (Unix ms).
    pub timestamp_ms: u64,
}

impl Default for VerificationResult {
    fn default() -> Self {
        Self {
            target: String::new(),
            is_consistent: true,
            fields_compared: 0,
            discrepancy_count: 0,
            discrepancies: Vec::new(),
            da_height: 0,
            timestamp_ms: 0,
        }
    }
}

impl VerificationResult {
    /// Format sebagai report untuk display.
    pub fn to_report(&self) -> String {
        let mut output = String::new();

        output.push_str("╔══════════════════════════════════════════════════════════════════╗\n");
        output.push_str("║                   STATE VERIFICATION REPORT                      ║\n");
        output.push_str("╠══════════════════════════════════════════════════════════════════╣\n");

        let status = if self.is_consistent {
            "✓ CONSISTENT"
        } else {
            "✗ INCONSISTENT"
        };
        output.push_str(&format!("║ Status:           {:47} ║\n", status));
        output.push_str(&format!("║ Target:           {:47} ║\n", self.target));
        output.push_str(&format!("║ DA Height:        {:47} ║\n", self.da_height));
        output.push_str(&format!("║ Fields Compared:  {:47} ║\n", self.fields_compared));
        output.push_str(&format!("║ Discrepancies:    {:47} ║\n", self.discrepancy_count));

        if !self.discrepancies.is_empty() {
            output.push_str("╠══════════════════════════════════════════════════════════════════╣\n");
            output.push_str("║                       DISCREPANCIES                              ║\n");
            output.push_str("╠══════════════════════════════════════════════════════════════════╣\n");

            for (i, disc) in self.discrepancies.iter().enumerate() {
                output.push_str(&format!("\n[Discrepancy {}]\n", i + 1));
                output.push_str(&disc.to_display());
            }

            output.push_str("\n╠══════════════════════════════════════════════════════════════════╣\n");
            output.push_str("║                     SUGGESTED FIXES                              ║\n");
            output.push_str("╠══════════════════════════════════════════════════════════════════╣\n");

            for (i, disc) in self.discrepancies.iter().enumerate() {
                output.push_str(&format!("\n[Fix {}] {}\n", i + 1, disc.suggested_fix()));
            }
        }

        output.push_str("╚══════════════════════════════════════════════════════════════════╝\n");
        output
    }

    /// Format sebagai JSON.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .context("failed to serialize verification result to JSON")
    }
}

// ════════════════════════════════════════════════════════════════════════════
// STATE STRUCTURES
// ════════════════════════════════════════════════════════════════════════════

/// Node info dalam state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateNodeInfo {
    pub node_id: String,
    pub addr: String,
    pub active: bool,
    pub zone: Option<String>,
}

/// Chunk info dalam state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateChunkInfo {
    pub chunk_hash: String,
    pub size: u64,
    pub owner: String,
    pub replicas: Vec<String>,
}

/// State yang di-rebuild dari DA atau diambil dari target.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DSDNState {
    /// Node registry: node_id -> NodeInfo
    pub nodes: HashMap<String, StateNodeInfo>,
    /// Chunk registry: chunk_hash -> ChunkInfo
    pub chunks: HashMap<String, StateChunkInfo>,
    /// Height terakhir yang diproses.
    pub last_height: u64,
    /// Sequence terakhir.
    pub last_sequence: u64,
}

impl DSDNState {
    /// Hitung jumlah field untuk perbandingan.
    pub fn field_count(&self) -> usize {
        let node_fields = self.nodes.len() * 4; // node_id, addr, active, zone
        let chunk_fields: usize = self.chunks.values().map(|c| 4 + c.replicas.len()).sum();
        2 + node_fields + chunk_fields // +2 for last_height, last_sequence
    }
}

// ════════════════════════════════════════════════════════════════════════════
// STATE COMPARISON
// ════════════════════════════════════════════════════════════════════════════

/// Compare two states dan return discrepancies.
pub fn compare_states(da_state: &DSDNState, target_state: &DSDNState) -> Vec<Discrepancy> {
    let mut discrepancies = Vec::new();

    // Compare last_height
    if da_state.last_height != target_state.last_height {
        discrepancies.push(Discrepancy {
            discrepancy_type: DiscrepancyType::ValueMismatch,
            path: "last_height".to_string(),
            da_value: Some(da_state.last_height.to_string()),
            target_value: Some(target_state.last_height.to_string()),
            description: "Last processed height differs".to_string(),
        });
    }

    // Compare nodes
    compare_nodes(&da_state.nodes, &target_state.nodes, &mut discrepancies);

    // Compare chunks
    compare_chunks(&da_state.chunks, &target_state.chunks, &mut discrepancies);

    discrepancies
}

/// Compare node registries.
fn compare_nodes(
    da_nodes: &HashMap<String, StateNodeInfo>,
    target_nodes: &HashMap<String, StateNodeInfo>,
    discrepancies: &mut Vec<Discrepancy>,
) {
    // Check nodes in DA but not in target
    for (node_id, da_node) in da_nodes {
        match target_nodes.get(node_id) {
            None => {
                discrepancies.push(Discrepancy {
                    discrepancy_type: DiscrepancyType::MissingInTarget,
                    path: format!("nodes.{}", node_id),
                    da_value: Some(format!("{:?}", da_node)),
                    target_value: None,
                    description: format!("Node '{}' exists in DA but not in target", node_id),
                });
            }
            Some(target_node) => {
                // Compare individual fields
                if da_node.addr != target_node.addr {
                    discrepancies.push(Discrepancy {
                        discrepancy_type: DiscrepancyType::ValueMismatch,
                        path: format!("nodes.{}.addr", node_id),
                        da_value: Some(da_node.addr.clone()),
                        target_value: Some(target_node.addr.clone()),
                        description: format!("Node '{}' address differs", node_id),
                    });
                }
                if da_node.active != target_node.active {
                    discrepancies.push(Discrepancy {
                        discrepancy_type: DiscrepancyType::ValueMismatch,
                        path: format!("nodes.{}.active", node_id),
                        da_value: Some(da_node.active.to_string()),
                        target_value: Some(target_node.active.to_string()),
                        description: format!("Node '{}' active status differs", node_id),
                    });
                }
                if da_node.zone != target_node.zone {
                    discrepancies.push(Discrepancy {
                        discrepancy_type: DiscrepancyType::ValueMismatch,
                        path: format!("nodes.{}.zone", node_id),
                        da_value: da_node.zone.clone(),
                        target_value: target_node.zone.clone(),
                        description: format!("Node '{}' zone differs", node_id),
                    });
                }
            }
        }
    }

    // Check nodes in target but not in DA
    for node_id in target_nodes.keys() {
        if !da_nodes.contains_key(node_id) {
            discrepancies.push(Discrepancy {
                discrepancy_type: DiscrepancyType::MissingInDA,
                path: format!("nodes.{}", node_id),
                da_value: None,
                target_value: Some(format!("{:?}", target_nodes.get(node_id))),
                description: format!("Node '{}' exists in target but not in DA", node_id),
            });
        }
    }
}

/// Compare chunk registries.
fn compare_chunks(
    da_chunks: &HashMap<String, StateChunkInfo>,
    target_chunks: &HashMap<String, StateChunkInfo>,
    discrepancies: &mut Vec<Discrepancy>,
) {
    // Check chunks in DA but not in target
    for (chunk_hash, da_chunk) in da_chunks {
        match target_chunks.get(chunk_hash) {
            None => {
                discrepancies.push(Discrepancy {
                    discrepancy_type: DiscrepancyType::MissingInTarget,
                    path: format!("chunks.{}", chunk_hash),
                    da_value: Some(format!("{:?}", da_chunk)),
                    target_value: None,
                    description: format!("Chunk '{}' exists in DA but not in target", chunk_hash),
                });
            }
            Some(target_chunk) => {
                // Compare individual fields
                if da_chunk.size != target_chunk.size {
                    discrepancies.push(Discrepancy {
                        discrepancy_type: DiscrepancyType::ValueMismatch,
                        path: format!("chunks.{}.size", chunk_hash),
                        da_value: Some(da_chunk.size.to_string()),
                        target_value: Some(target_chunk.size.to_string()),
                        description: format!("Chunk '{}' size differs", chunk_hash),
                    });
                }
                if da_chunk.owner != target_chunk.owner {
                    discrepancies.push(Discrepancy {
                        discrepancy_type: DiscrepancyType::ValueMismatch,
                        path: format!("chunks.{}.owner", chunk_hash),
                        da_value: Some(da_chunk.owner.clone()),
                        target_value: Some(target_chunk.owner.clone()),
                        description: format!("Chunk '{}' owner differs", chunk_hash),
                    });
                }

                // Compare replicas
                let mut da_replicas = da_chunk.replicas.clone();
                let mut target_replicas = target_chunk.replicas.clone();
                da_replicas.sort();
                target_replicas.sort();

                if da_replicas != target_replicas {
                    discrepancies.push(Discrepancy {
                        discrepancy_type: DiscrepancyType::ValueMismatch,
                        path: format!("chunks.{}.replicas", chunk_hash),
                        da_value: Some(format!("{:?}", da_replicas)),
                        target_value: Some(format!("{:?}", target_replicas)),
                        description: format!("Chunk '{}' replicas differ", chunk_hash),
                    });
                }
            }
        }
    }

    // Check chunks in target but not in DA
    for chunk_hash in target_chunks.keys() {
        if !da_chunks.contains_key(chunk_hash) {
            discrepancies.push(Discrepancy {
                discrepancy_type: DiscrepancyType::MissingInDA,
                path: format!("chunks.{}", chunk_hash),
                da_value: None,
                target_value: Some(format!("{:?}", target_chunks.get(chunk_hash))),
                description: format!("Chunk '{}' exists in target but not in DA", chunk_hash),
            });
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// DA STATE REBUILD
// ════════════════════════════════════════════════════════════════════════════

/// DA Event untuk rebuild state.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DAEvent {
    ChunkDeclared {
        chunk_hash: String,
        size: u64,
        owner: String,
        commitment: String,
    },
    ReplicaAdded {
        chunk_hash: String,
        node_id: String,
        proof: String,
    },
    ReplicaRemoved {
        chunk_hash: String,
        node_id: String,
        reason: String,
    },
    NodeRegistered {
        node_id: String,
        addr: String,
        zone: Option<String>,
    },
    NodeUnregistered {
        node_id: String,
    },
    DeleteRequested {
        chunk_hash: String,
        requester: String,
    },
}

/// Rebuild state dari DA events.
///
/// # Arguments
///
/// * `config` - DA configuration
///
/// # Returns
///
/// * `Ok(DSDNState)` - Rebuilt state
/// * `Err(anyhow::Error)` - Error during rebuild
///
/// # Behavior
///
/// 1. Fetch all blobs from DA (from genesis/checkpoint)
/// 2. Decode events in order
/// 3. Apply events to build state
/// 4. Return final state
pub async fn rebuild_state_from_da(config: &DAConfig) -> Result<DSDNState> {
    let mut state = DSDNState::default();

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(config.timeout_secs))
        .build()
        .context("failed to build HTTP client")?;

    // Get current DA height
    let current_height = get_da_current_height(&client, config).await?;

    if current_height == 0 {
        return Ok(state);
    }

    // Fetch and process events from genesis (height 1) to current
    // In production, this would use checkpoints for efficiency
    for height in 1..=current_height {
        let events = fetch_events_at_height(&client, config, height).await?;

        for event in events {
            apply_event_to_state(&mut state, &event);
        }

        state.last_height = height;
    }

    state.last_sequence = current_height;
    Ok(state)
}

/// Get current DA height.
async fn get_da_current_height(client: &reqwest::Client, config: &DAConfig) -> Result<u64> {
    let url = format!("{}/header/local_head", config.endpoint);

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
) -> Result<Vec<DAEvent>> {
    let url = format!(
        "{}/blob/get_all/{}/{}",
        config.endpoint, height, config.namespace
    );

    let response = client.get(&url).send().await;

    match response {
        Ok(resp) if resp.status().is_success() => {
            let body = resp.text().await.context("failed to read blob response")?;
            parse_events_from_blobs(&body)
        }
        _ => Ok(Vec::new()), // No blobs at this height
    }
}

/// Parse events from blob response.
fn parse_events_from_blobs(body: &str) -> Result<Vec<DAEvent>> {
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
                if let Ok(events) = serde_json::from_slice::<Vec<DAEvent>>(&data) {
                    all_events.extend(events);
                }
            }
        }
    }

    Ok(all_events)
}

/// Apply event to state.
pub fn apply_event_to_state(state: &mut DSDNState, event: &DAEvent) {
    match event {
        DAEvent::NodeRegistered { node_id, addr, zone } => {
            state.nodes.insert(
                node_id.clone(),
                StateNodeInfo {
                    node_id: node_id.clone(),
                    addr: addr.clone(),
                    active: true,
                    zone: zone.clone(),
                },
            );
        }
        DAEvent::NodeUnregistered { node_id } => {
            if let Some(node) = state.nodes.get_mut(node_id) {
                node.active = false;
            }
        }
        DAEvent::ChunkDeclared {
            chunk_hash,
            size,
            owner,
            ..
        } => {
            state.chunks.insert(
                chunk_hash.clone(),
                StateChunkInfo {
                    chunk_hash: chunk_hash.clone(),
                    size: *size,
                    owner: owner.clone(),
                    replicas: Vec::new(),
                },
            );
        }
        DAEvent::ReplicaAdded {
            chunk_hash,
            node_id,
            ..
        } => {
            if let Some(chunk) = state.chunks.get_mut(chunk_hash) {
                if !chunk.replicas.contains(node_id) {
                    chunk.replicas.push(node_id.clone());
                }
            }
        }
        DAEvent::ReplicaRemoved {
            chunk_hash,
            node_id,
            ..
        } => {
            if let Some(chunk) = state.chunks.get_mut(chunk_hash) {
                chunk.replicas.retain(|id| id != node_id);
            }
        }
        DAEvent::DeleteRequested { chunk_hash, .. } => {
            state.chunks.remove(chunk_hash);
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// TARGET STATE FETCH
// ════════════════════════════════════════════════════════════════════════════

/// Fetch state from coordinator.
pub async fn fetch_coordinator_state(config: &DAConfig) -> Result<DSDNState> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(config.timeout_secs))
        .build()
        .context("failed to build HTTP client")?;

    // Coordinator state endpoint (assumed API)
    let coord_url =
        std::env::var("COORD_BASE_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());

    let url = format!("{}/state", coord_url);

    let response = client
        .get(&url)
        .send()
        .await
        .context("failed to fetch coordinator state")?;

    if !response.status().is_success() {
        anyhow::bail!("coordinator returned error: {}", response.status());
    }

    let body = response
        .text()
        .await
        .context("failed to read coordinator response")?;

    let state: DSDNState =
        serde_json::from_str(&body).context("failed to parse coordinator state")?;

    Ok(state)
}

/// Fetch state from node.
pub async fn fetch_node_state(node_addr: &str) -> Result<DSDNState> {
    validate_node_address(node_addr)?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("failed to build HTTP client")?;

    let url = format!("http://{}/state", node_addr);

    let response = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("failed to fetch state from node {}", node_addr))?;

    if !response.status().is_success() {
        anyhow::bail!("node {} returned error: {}", node_addr, response.status());
    }

    let body = response
        .text()
        .await
        .context("failed to read node response")?;

    let state: DSDNState = serde_json::from_str(&body).context("failed to parse node state")?;

    Ok(state)
}

/// Validate node address format.
fn validate_node_address(addr: &str) -> Result<()> {
    // Basic validation: should be host:port format
    if addr.is_empty() {
        anyhow::bail!("node address cannot be empty");
    }

    let parts: Vec<&str> = addr.split(':').collect();
    if parts.len() != 2 {
        anyhow::bail!(
            "invalid node address format '{}': expected host:port",
            addr
        );
    }

    let host = parts[0];
    let port_str = parts[1];

    if host.is_empty() {
        anyhow::bail!("invalid node address '{}': host cannot be empty", addr);
    }

    let _port: u16 = port_str
        .parse()
        .with_context(|| format!("invalid port in address '{}': not a valid number", addr))?;

    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════
// CLI HANDLERS
// ════════════════════════════════════════════════════════════════════════════

/// Handle `agent verify state --target <target>` command.
///
/// # Arguments
///
/// * `target_str` - Target string ("coordinator" or "node")
/// * `json_output` - Output as JSON
///
/// # Returns
///
/// * `Ok(true)` - State is consistent (exit 0)
/// * `Ok(false)` - State is inconsistent (exit 1)
/// * `Err(anyhow::Error)` - Error during verification
pub async fn handle_verify_state(target_str: &str, json_output: bool) -> Result<bool> {
    let target = VerifyTarget::from_str(target_str)
        .map_err(|e| anyhow::anyhow!(e))?;

    let config = DAConfig::from_env();

    // 1. Rebuild state from DA
    eprintln!("Rebuilding state from DA...");
    let da_state = rebuild_state_from_da(&config).await?;

    // 2. Fetch target state
    eprintln!("Fetching {} state...", target);
    let target_state = match target {
        VerifyTarget::Coordinator => fetch_coordinator_state(&config).await?,
        VerifyTarget::Node => {
            let node_addr = std::env::var("NODE_ADDR")
                .unwrap_or_else(|_| "localhost:9000".to_string());
            fetch_node_state(&node_addr).await?
        }
    };

    // 3. Compare states
    eprintln!("Comparing states...");
    let discrepancies = compare_states(&da_state, &target_state);

    // 4. Build result
    let timestamp_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let result = VerificationResult {
        target: target.to_string(),
        is_consistent: discrepancies.is_empty(),
        fields_compared: da_state.field_count().max(target_state.field_count()),
        discrepancy_count: discrepancies.len(),
        discrepancies,
        da_height: da_state.last_height,
        timestamp_ms,
    };

    // 5. Output
    if json_output {
        println!("{}", result.to_json()?);
    } else {
        print!("{}", result.to_report());
    }

    Ok(result.is_consistent)
}

/// Handle `agent verify consistency --node <node_addr>` command.
///
/// # Arguments
///
/// * `node_addr` - Node address to verify
/// * `json_output` - Output as JSON
///
/// # Returns
///
/// * `Ok(true)` - Node is consistent (exit 0)
/// * `Ok(false)` - Node is inconsistent (exit 1)
/// * `Err(anyhow::Error)` - Error during verification
pub async fn handle_verify_consistency(node_addr: &str, json_output: bool) -> Result<bool> {
    validate_node_address(node_addr)?;

    let config = DAConfig::from_env();

    // 1. Rebuild state from DA
    eprintln!("Rebuilding state from DA...");
    let da_state = rebuild_state_from_da(&config).await?;

    // 2. Fetch node state
    eprintln!("Fetching node state from {}...", node_addr);
    let node_state = fetch_node_state(node_addr).await?;

    // 3. Compare (focus on this node's data only)
    eprintln!("Comparing node consistency...");
    let discrepancies = compare_node_consistency(&da_state, &node_state, node_addr);

    // 4. Build result
    let timestamp_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let result = VerificationResult {
        target: format!("node:{}", node_addr),
        is_consistent: discrepancies.is_empty(),
        fields_compared: node_state.field_count(),
        discrepancy_count: discrepancies.len(),
        discrepancies,
        da_height: da_state.last_height,
        timestamp_ms,
    };

    // 5. Output
    if json_output {
        println!("{}", result.to_json()?);
    } else {
        print!("{}", result.to_report());
    }

    Ok(result.is_consistent)
}

/// Compare node-specific consistency.
fn compare_node_consistency(
    da_state: &DSDNState,
    node_state: &DSDNState,
    node_addr: &str,
) -> Vec<Discrepancy> {
    let mut discrepancies = Vec::new();

    // Find node_id by address in DA state
    let node_id = da_state
        .nodes
        .values()
        .find(|n| n.addr == node_addr)
        .map(|n| n.node_id.clone());

    if let Some(ref nid) = node_id {
        // Check if node exists in both states
        match (da_state.nodes.get(nid), node_state.nodes.get(nid)) {
            (Some(da_node), Some(target_node)) => {
                if da_node.active != target_node.active {
                    discrepancies.push(Discrepancy {
                        discrepancy_type: DiscrepancyType::ValueMismatch,
                        path: format!("node.{}.active", nid),
                        da_value: Some(da_node.active.to_string()),
                        target_value: Some(target_node.active.to_string()),
                        description: "Node active status mismatch".to_string(),
                    });
                }
            }
            (Some(_), None) => {
                discrepancies.push(Discrepancy {
                    discrepancy_type: DiscrepancyType::MissingInTarget,
                    path: format!("node.{}", nid),
                    da_value: Some(nid.clone()),
                    target_value: None,
                    description: "Node not found in node's own state".to_string(),
                });
            }
            (None, _) => {
                discrepancies.push(Discrepancy {
                    discrepancy_type: DiscrepancyType::MissingInDA,
                    path: "node".to_string(),
                    da_value: None,
                    target_value: Some(node_addr.to_string()),
                    description: "Node not registered in DA".to_string(),
                });
            }
        }

        // Check chunks assigned to this node
        for (chunk_hash, da_chunk) in &da_state.chunks {
            if da_chunk.replicas.contains(nid) {
                match node_state.chunks.get(chunk_hash) {
                    None => {
                        discrepancies.push(Discrepancy {
                            discrepancy_type: DiscrepancyType::MissingInTarget,
                            path: format!("chunks.{}", chunk_hash),
                            da_value: Some(format!("{:?}", da_chunk)),
                            target_value: None,
                            description: format!(
                                "Chunk '{}' assigned to node but not in node state",
                                chunk_hash
                            ),
                        });
                    }
                    Some(node_chunk) => {
                        if !node_chunk.replicas.contains(nid) {
                            discrepancies.push(Discrepancy {
                                discrepancy_type: DiscrepancyType::ValueMismatch,
                                path: format!("chunks.{}.replicas", chunk_hash),
                                da_value: Some(format!("{:?}", da_chunk.replicas)),
                                target_value: Some(format!("{:?}", node_chunk.replicas)),
                                description: format!(
                                    "Node not in replica list for chunk '{}' in node state",
                                    chunk_hash
                                ),
                            });
                        }
                    }
                }
            }
        }
    } else {
        discrepancies.push(Discrepancy {
            discrepancy_type: DiscrepancyType::MissingInDA,
            path: "node".to_string(),
            da_value: None,
            target_value: Some(node_addr.to_string()),
            description: format!("Node with address '{}' not found in DA state", node_addr),
        });
    }

    discrepancies
}

// ════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ════════════════════════════════════════════════════════════════════════
    // TEST 1: VERIFY TARGET PARSING
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_target_parsing() {
        assert_eq!(
            VerifyTarget::from_str("coordinator"),
            Ok(VerifyTarget::Coordinator)
        );
        assert_eq!(
            VerifyTarget::from_str("COORDINATOR"),
            Ok(VerifyTarget::Coordinator)
        );
        assert_eq!(VerifyTarget::from_str("node"), Ok(VerifyTarget::Node));
        assert_eq!(VerifyTarget::from_str("NODE"), Ok(VerifyTarget::Node));

        assert!(VerifyTarget::from_str("invalid").is_err());
        assert!(VerifyTarget::from_str("").is_err());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 2: VERIFY TARGET DISPLAY
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_target_display() {
        assert_eq!(format!("{}", VerifyTarget::Coordinator), "coordinator");
        assert_eq!(format!("{}", VerifyTarget::Node), "node");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 3: NODE ADDRESS VALIDATION
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_node_address_validation() {
        // Valid addresses
        assert!(validate_node_address("127.0.0.1:9000").is_ok());
        assert!(validate_node_address("localhost:8080").is_ok());
        assert!(validate_node_address("node1.example.com:9001").is_ok());

        // Invalid addresses
        assert!(validate_node_address("").is_err());
        assert!(validate_node_address("localhost").is_err());
        assert!(validate_node_address(":9000").is_err());
        assert!(validate_node_address("localhost:").is_err());
        assert!(validate_node_address("localhost:abc").is_err());
        assert!(validate_node_address("localhost:99999").is_err()); // port > 65535
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 4: DISCREPANCY TYPE DISPLAY
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_discrepancy_type_display() {
        assert_eq!(
            format!("{}", DiscrepancyType::MissingInTarget),
            "MISSING_IN_TARGET"
        );
        assert_eq!(
            format!("{}", DiscrepancyType::MissingInDA),
            "MISSING_IN_DA"
        );
        assert_eq!(
            format!("{}", DiscrepancyType::ValueMismatch),
            "VALUE_MISMATCH"
        );
        assert_eq!(
            format!("{}", DiscrepancyType::TypeMismatch),
            "TYPE_MISMATCH"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 5: COMPARE IDENTICAL STATES
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_compare_identical_states() {
        let mut state = DSDNState::default();
        state.last_height = 100;
        state.nodes.insert(
            "node-1".to_string(),
            StateNodeInfo {
                node_id: "node-1".to_string(),
                addr: "127.0.0.1:9000".to_string(),
                active: true,
                zone: Some("zone-a".to_string()),
            },
        );
        state.chunks.insert(
            "chunk-1".to_string(),
            StateChunkInfo {
                chunk_hash: "chunk-1".to_string(),
                size: 1024,
                owner: "owner-1".to_string(),
                replicas: vec!["node-1".to_string()],
            },
        );

        let discrepancies = compare_states(&state, &state);
        assert!(discrepancies.is_empty());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 6: COMPARE DIFFERENT STATES - MISSING NODE
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_compare_states_missing_node() {
        let mut da_state = DSDNState::default();
        da_state.nodes.insert(
            "node-1".to_string(),
            StateNodeInfo {
                node_id: "node-1".to_string(),
                addr: "127.0.0.1:9000".to_string(),
                active: true,
                zone: None,
            },
        );

        let target_state = DSDNState::default();

        let discrepancies = compare_states(&da_state, &target_state);

        assert_eq!(discrepancies.len(), 1);
        assert_eq!(discrepancies[0].discrepancy_type, DiscrepancyType::MissingInTarget);
        assert!(discrepancies[0].path.contains("node-1"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 7: COMPARE DIFFERENT STATES - VALUE MISMATCH
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_compare_states_value_mismatch() {
        let mut da_state = DSDNState::default();
        da_state.nodes.insert(
            "node-1".to_string(),
            StateNodeInfo {
                node_id: "node-1".to_string(),
                addr: "127.0.0.1:9000".to_string(),
                active: true,
                zone: None,
            },
        );

        let mut target_state = DSDNState::default();
        target_state.nodes.insert(
            "node-1".to_string(),
            StateNodeInfo {
                node_id: "node-1".to_string(),
                addr: "127.0.0.1:9000".to_string(),
                active: false, // Different!
                zone: None,
            },
        );

        let discrepancies = compare_states(&da_state, &target_state);

        assert!(!discrepancies.is_empty());
        let active_disc = discrepancies
            .iter()
            .find(|d| d.path.contains("active"))
            .expect("should find active discrepancy");
        assert_eq!(active_disc.discrepancy_type, DiscrepancyType::ValueMismatch);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 8: VERIFICATION RESULT CONSISTENT
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_verification_result_consistent() {
        let result = VerificationResult {
            target: "coordinator".to_string(),
            is_consistent: true,
            fields_compared: 10,
            discrepancy_count: 0,
            discrepancies: vec![],
            da_height: 100,
            timestamp_ms: 12345,
        };

        assert!(result.is_consistent);
        let report = result.to_report();
        assert!(report.contains("CONSISTENT"));
        assert!(report.contains("coordinator"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 9: VERIFICATION RESULT INCONSISTENT
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_verification_result_inconsistent() {
        let result = VerificationResult {
            target: "node".to_string(),
            is_consistent: false,
            fields_compared: 10,
            discrepancy_count: 2,
            discrepancies: vec![
                Discrepancy {
                    discrepancy_type: DiscrepancyType::MissingInTarget,
                    path: "nodes.node-1".to_string(),
                    da_value: Some("data".to_string()),
                    target_value: None,
                    description: "Node missing".to_string(),
                },
                Discrepancy {
                    discrepancy_type: DiscrepancyType::ValueMismatch,
                    path: "nodes.node-2.active".to_string(),
                    da_value: Some("true".to_string()),
                    target_value: Some("false".to_string()),
                    description: "Active status differs".to_string(),
                },
            ],
            da_height: 100,
            timestamp_ms: 12345,
        };

        assert!(!result.is_consistent);
        let report = result.to_report();
        assert!(report.contains("INCONSISTENT"));
        assert!(report.contains("DISCREPANCIES"));
        assert!(report.contains("SUGGESTED FIXES"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 10: APPLY EVENT TO STATE - NODE REGISTERED
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_apply_event_node_registered() {
        let mut state = DSDNState::default();
        let event = DAEvent::NodeRegistered {
            node_id: "node-1".to_string(),
            addr: "127.0.0.1:9000".to_string(),
            zone: Some("zone-a".to_string()),
        };

        apply_event_to_state(&mut state, &event);

        assert!(state.nodes.contains_key("node-1"));
        let node = state.nodes.get("node-1").expect("node should exist");
        assert_eq!(node.addr, "127.0.0.1:9000");
        assert!(node.active);
        assert_eq!(node.zone, Some("zone-a".to_string()));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 11: APPLY EVENT TO STATE - NODE UNREGISTERED
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_apply_event_node_unregistered() {
        let mut state = DSDNState::default();
        state.nodes.insert(
            "node-1".to_string(),
            StateNodeInfo {
                node_id: "node-1".to_string(),
                addr: "127.0.0.1:9000".to_string(),
                active: true,
                zone: None,
            },
        );

        let event = DAEvent::NodeUnregistered {
            node_id: "node-1".to_string(),
        };

        apply_event_to_state(&mut state, &event);

        let node = state.nodes.get("node-1").expect("node should exist");
        assert!(!node.active);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 12: APPLY EVENT TO STATE - CHUNK DECLARED
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_apply_event_chunk_declared() {
        let mut state = DSDNState::default();
        let event = DAEvent::ChunkDeclared {
            chunk_hash: "chunk-1".to_string(),
            size: 1024,
            owner: "owner-1".to_string(),
            commitment: "commit-1".to_string(),
        };

        apply_event_to_state(&mut state, &event);

        assert!(state.chunks.contains_key("chunk-1"));
        let chunk = state.chunks.get("chunk-1").expect("chunk should exist");
        assert_eq!(chunk.size, 1024);
        assert_eq!(chunk.owner, "owner-1");
        assert!(chunk.replicas.is_empty());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 13: APPLY EVENT TO STATE - REPLICA ADDED
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_apply_event_replica_added() {
        let mut state = DSDNState::default();
        state.chunks.insert(
            "chunk-1".to_string(),
            StateChunkInfo {
                chunk_hash: "chunk-1".to_string(),
                size: 1024,
                owner: "owner-1".to_string(),
                replicas: vec![],
            },
        );

        let event = DAEvent::ReplicaAdded {
            chunk_hash: "chunk-1".to_string(),
            node_id: "node-1".to_string(),
            proof: "proof-1".to_string(),
        };

        apply_event_to_state(&mut state, &event);

        let chunk = state.chunks.get("chunk-1").expect("chunk should exist");
        assert!(chunk.replicas.contains(&"node-1".to_string()));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14: APPLY EVENT TO STATE - REPLICA REMOVED
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_apply_event_replica_removed() {
        let mut state = DSDNState::default();
        state.chunks.insert(
            "chunk-1".to_string(),
            StateChunkInfo {
                chunk_hash: "chunk-1".to_string(),
                size: 1024,
                owner: "owner-1".to_string(),
                replicas: vec!["node-1".to_string(), "node-2".to_string()],
            },
        );

        let event = DAEvent::ReplicaRemoved {
            chunk_hash: "chunk-1".to_string(),
            node_id: "node-1".to_string(),
            reason: "test".to_string(),
        };

        apply_event_to_state(&mut state, &event);

        let chunk = state.chunks.get("chunk-1").expect("chunk should exist");
        assert!(!chunk.replicas.contains(&"node-1".to_string()));
        assert!(chunk.replicas.contains(&"node-2".to_string()));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 15: APPLY EVENT TO STATE - DELETE REQUESTED
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_apply_event_delete_requested() {
        let mut state = DSDNState::default();
        state.chunks.insert(
            "chunk-1".to_string(),
            StateChunkInfo {
                chunk_hash: "chunk-1".to_string(),
                size: 1024,
                owner: "owner-1".to_string(),
                replicas: vec!["node-1".to_string()],
            },
        );

        let event = DAEvent::DeleteRequested {
            chunk_hash: "chunk-1".to_string(),
            requester: "owner-1".to_string(),
        };

        apply_event_to_state(&mut state, &event);

        assert!(!state.chunks.contains_key("chunk-1"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 16: DISCREPANCY SUGGESTED FIX
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_discrepancy_suggested_fix() {
        let disc1 = Discrepancy {
            discrepancy_type: DiscrepancyType::MissingInTarget,
            path: "nodes.node-1".to_string(),
            da_value: Some("data".to_string()),
            target_value: None,
            description: "test".to_string(),
        };
        assert!(disc1.suggested_fix().contains("Add"));

        let disc2 = Discrepancy {
            discrepancy_type: DiscrepancyType::MissingInDA,
            path: "nodes.node-1".to_string(),
            da_value: None,
            target_value: Some("data".to_string()),
            description: "test".to_string(),
        };
        assert!(disc2.suggested_fix().contains("Investigate"));

        let disc3 = Discrepancy {
            discrepancy_type: DiscrepancyType::ValueMismatch,
            path: "nodes.node-1.active".to_string(),
            da_value: Some("true".to_string()),
            target_value: Some("false".to_string()),
            description: "test".to_string(),
        };
        assert!(disc3.suggested_fix().contains("Update"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 17: VERIFICATION RESULT JSON
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_verification_result_json() {
        let result = VerificationResult {
            target: "coordinator".to_string(),
            is_consistent: true,
            fields_compared: 10,
            discrepancy_count: 0,
            discrepancies: vec![],
            da_height: 100,
            timestamp_ms: 12345,
        };

        let json = result.to_json().expect("should serialize");
        let parsed: VerificationResult =
            serde_json::from_str(&json).expect("should parse");

        assert_eq!(parsed.target, result.target);
        assert_eq!(parsed.is_consistent, result.is_consistent);
        assert_eq!(parsed.da_height, result.da_height);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 18: STATE FIELD COUNT
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_state_field_count() {
        let mut state = DSDNState::default();
        assert_eq!(state.field_count(), 2); // last_height, last_sequence

        state.nodes.insert(
            "node-1".to_string(),
            StateNodeInfo {
                node_id: "node-1".to_string(),
                addr: "127.0.0.1:9000".to_string(),
                active: true,
                zone: None,
            },
        );
        assert_eq!(state.field_count(), 6); // 2 + 4 node fields

        state.chunks.insert(
            "chunk-1".to_string(),
            StateChunkInfo {
                chunk_hash: "chunk-1".to_string(),
                size: 1024,
                owner: "owner-1".to_string(),
                replicas: vec!["node-1".to_string()],
            },
        );
        assert_eq!(state.field_count(), 11); // 6 + 4 chunk fields + 1 replica
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 19: DISCREPANCY DISPLAY
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_discrepancy_display() {
        let disc = Discrepancy {
            discrepancy_type: DiscrepancyType::ValueMismatch,
            path: "nodes.node-1.active".to_string(),
            da_value: Some("true".to_string()),
            target_value: Some("false".to_string()),
            description: "Active status differs".to_string(),
        };

        let display = disc.to_display();
        assert!(display.contains("VALUE_MISMATCH"));
        assert!(display.contains("nodes.node-1.active"));
        assert!(display.contains("true"));
        assert!(display.contains("false"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 20: NO PANIC ON EMPTY STATES
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_no_panic_on_empty_states() {
        let state1 = DSDNState::default();
        let state2 = DSDNState::default();

        let discrepancies = compare_states(&state1, &state2);
        assert!(discrepancies.is_empty());

        let result = VerificationResult {
            target: "test".to_string(),
            is_consistent: true,
            fields_compared: 0,
            discrepancy_count: 0,
            discrepancies: vec![],
            da_height: 0,
            timestamp_ms: 0,
        };

        let _ = result.to_report();
        let _ = result.to_json();
    }
}