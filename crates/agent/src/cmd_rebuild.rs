//! Rebuild State Command
//!
//! This module implements the `agent rebuild` command for reconstructing
//! DSDN state from Data Availability (DA) events.
//!
//! # Commands
//!
//! - `agent rebuild --target <coordinator|node> --from <height> --to <height>`
//! - `agent rebuild --target node --output <state.json>`
//!
//! # Pipeline
//!
//! 1. Fetch all blobs in the specified range
//! 2. Decode all events from blobs
//! 3. Apply events one by one to state machine (deterministic, ordered)
//! 4. Generate final state
//!
//! # Data Source
//!
//! ALL data is derived from DA events ONLY. No RPC to nodes or coordinator.

use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

use crate::cmd_da::DAConfig;
use crate::cmd_verify::{apply_event_to_state, DAEvent, DSDNState, StateChunkInfo, StateNodeInfo};

// ════════════════════════════════════════════════════════════════════════════
// REBUILD RESULT TYPES
// ════════════════════════════════════════════════════════════════════════════

/// Progress stage during rebuild.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RebuildStage {
    /// Fetching blobs from DA.
    FetchingBlobs { current: u64, total: u64 },
    /// Decoding events from blobs.
    DecodingEvents { blobs_processed: u64 },
    /// Applying events to state machine.
    ApplyingEvents { current: usize, total: usize },
    /// Verifying final state.
    Verifying,
    /// Rebuild complete.
    Complete,
}

impl std::fmt::Display for RebuildStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RebuildStage::FetchingBlobs { current, total } => {
                write!(f, "FETCHING_BLOBS ({}/{})", current, total)
            }
            RebuildStage::DecodingEvents { blobs_processed } => {
                write!(f, "DECODING_EVENTS (blobs: {})", blobs_processed)
            }
            RebuildStage::ApplyingEvents { current, total } => {
                write!(f, "APPLYING_EVENTS ({}/{})", current, total)
            }
            RebuildStage::Verifying => write!(f, "VERIFYING"),
            RebuildStage::Complete => write!(f, "COMPLETE"),
        }
    }
}

/// Rebuild statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebuildStats {
    /// Starting height (inclusive).
    pub from_height: u64,
    /// Ending height (inclusive).
    pub to_height: u64,
    /// Number of blobs fetched.
    pub blobs_fetched: u64,
    /// Number of events decoded.
    pub events_decoded: usize,
    /// Number of events applied.
    pub events_applied: usize,
    /// Number of nodes in final state.
    pub nodes_count: usize,
    /// Number of chunks in final state.
    pub chunks_count: usize,
    /// Rebuild duration in milliseconds.
    pub duration_ms: u64,
    /// Whether verification passed.
    pub verified: bool,
}

/// Rebuild result containing final state and statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebuildResult {
    /// Target type: "coordinator" or "node".
    pub target: String,
    /// Final state after rebuild.
    pub state: RebuildState,
    /// Rebuild statistics.
    pub stats: RebuildStats,
}

/// Serializable state for output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebuildState {
    /// Nodes in the state (keyed by node_id).
    pub nodes: HashMap<String, RebuildNodeInfo>,
    /// Chunks in the state (keyed by chunk_hash).
    pub chunks: HashMap<String, RebuildChunkInfo>,
    /// Last processed DA height.
    pub last_height: u64,
}

/// Node info for rebuild output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebuildNodeInfo {
    pub node_id: String,
    pub addr: String,
    pub zone: Option<String>,
    pub active: bool,
}

/// Chunk info for rebuild output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebuildChunkInfo {
    pub chunk_hash: String,
    pub size: u64,
    pub owner: String,
    pub replicas: Vec<String>,
}

impl RebuildResult {
    /// Format as table.
    pub fn to_table(&self) -> String {
        let mut output = String::new();
        output.push_str("┌─────────────────────────────────────────────────────────────────────────────┐\n");
        output.push_str("│                         REBUILD STATE RESULT                                │\n");
        output.push_str("├─────────────────────┬───────────────────────────────────────────────────────┤\n");
        output.push_str(&format!("│ Target              │ {:53} │\n", self.target));
        output.push_str(&format!("│ Height Range        │ {:>25} - {:>25} │\n", 
            self.stats.from_height, self.stats.to_height));
        output.push_str(&format!("│ Blobs Fetched       │ {:>53} │\n", self.stats.blobs_fetched));
        output.push_str(&format!("│ Events Decoded      │ {:>53} │\n", self.stats.events_decoded));
        output.push_str(&format!("│ Events Applied      │ {:>53} │\n", self.stats.events_applied));
        output.push_str(&format!("│ Nodes Count         │ {:>53} │\n", self.stats.nodes_count));
        output.push_str(&format!("│ Chunks Count        │ {:>53} │\n", self.stats.chunks_count));
        output.push_str(&format!("│ Duration            │ {:>50} ms │\n", self.stats.duration_ms));
        output.push_str(&format!("│ Verified            │ {:53} │\n", 
            if self.stats.verified { "YES ✓" } else { "NO ✗" }));
        output.push_str("└─────────────────────┴───────────────────────────────────────────────────────┘\n");
        output
    }

    /// Format as JSON.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| anyhow::anyhow!("failed to serialize rebuild result: {}", e))
    }
}

// ════════════════════════════════════════════════════════════════════════════
// REBUILD CONFIG
// ════════════════════════════════════════════════════════════════════════════

/// Rebuild configuration.
pub struct RebuildConfig {
    /// DA endpoint URL.
    pub da_endpoint: String,
    /// DA namespace.
    pub namespace: String,
    /// Target: "coordinator" or "node".
    pub target: String,
    /// Starting height (inclusive).
    pub from_height: u64,
    /// Ending height (inclusive).
    pub to_height: u64,
    /// Output file path (optional).
    pub output_path: Option<PathBuf>,
}

// ════════════════════════════════════════════════════════════════════════════
// PROGRESS REPORTING
// ════════════════════════════════════════════════════════════════════════════

/// Print rebuild progress.
fn print_rebuild_progress(stage: &RebuildStage) {
    println!("[REBUILD] {}", stage);
}

/// Calculate ETA based on progress.
fn calculate_eta_ms(start_time: std::time::Instant, current: u64, total: u64) -> Option<u64> {
    if current == 0 || total == 0 {
        return None;
    }
    let elapsed = start_time.elapsed().as_millis() as u64;
    let rate = elapsed as f64 / current as f64;
    let remaining = (total - current) as f64;
    let eta = (rate * remaining) as u64;
    Some(eta)
}

/// Print progress with ETA.
fn print_progress_with_eta(stage: &str, current: u64, total: u64, start: std::time::Instant) {
    let eta = calculate_eta_ms(start, current, total);
    let eta_str = match eta {
        Some(ms) if ms > 1000 => format!("ETA: {}s", ms / 1000),
        Some(ms) => format!("ETA: {}ms", ms),
        None => "ETA: calculating...".to_string(),
    };
    println!("[REBUILD] {} ({}/{}) - {}", stage, current, total, eta_str);
}

// ════════════════════════════════════════════════════════════════════════════
// DA FETCHING
// ════════════════════════════════════════════════════════════════════════════

/// Get current DA height.
async fn get_da_height(client: &reqwest::Client, endpoint: &str) -> Result<u64> {
    let url = format!("{}/header/local_head", endpoint);
    let response = client.get(&url).send().await
        .map_err(|e| anyhow::anyhow!("failed to get DA header: {}", e))?;
    
    if !response.status().is_success() {
        anyhow::bail!("failed to get DA header: status {}", response.status());
    }
    
    let body = response.text().await
        .map_err(|e| anyhow::anyhow!("failed to read response: {}", e))?;
    
    let json: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("failed to parse header: {}", e))?;
    
    let height = json.get("header")
        .and_then(|h| h.get("height"))
        .and_then(|h| h.as_str())
        .and_then(|h| h.parse::<u64>().ok())
        .ok_or_else(|| anyhow::anyhow!("missing or invalid height in DA header"))?;
    
    Ok(height)
}

/// Fetch blobs at a specific height.
async fn fetch_blobs_at_height(
    client: &reqwest::Client,
    endpoint: &str,
    namespace: &str,
    height: u64,
) -> Result<Vec<Vec<u8>>> {
    let url = format!("{}/blob/get_all/{}/{}", endpoint, height, namespace);
    
    let response = match client.get(&url).send().await {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            // Height might not have blobs, return empty
            if r.status().as_u16() == 404 {
                return Ok(Vec::new());
            }
            anyhow::bail!("failed to fetch blobs at height {}: status {}", height, r.status());
        }
        Err(e) => anyhow::bail!("failed to fetch blobs at height {}: {}", height, e),
    };
    
    let body = response.text().await
        .map_err(|e| anyhow::anyhow!("failed to read blob response: {}", e))?;
    
    let json: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("failed to parse blob response: {}", e))?;
    
    let blobs = match json.as_array() {
        Some(arr) => arr,
        None => return Ok(Vec::new()),
    };
    
    let mut raw_blobs = Vec::new();
    for blob in blobs {
        if let Some(data_b64) = blob.get("data").and_then(|d| d.as_str()) {
            if let Ok(data) = general_purpose::STANDARD.decode(data_b64) {
                raw_blobs.push(data);
            }
        }
    }
    
    Ok(raw_blobs)
}

/// Decode events from raw blob data.
fn decode_events_from_blob(data: &[u8]) -> Vec<DAEvent> {
    match serde_json::from_slice::<Vec<DAEvent>>(data) {
        Ok(events) => events,
        Err(_) => Vec::new(),
    }
}

// ════════════════════════════════════════════════════════════════════════════
// STATE MACHINE
// ════════════════════════════════════════════════════════════════════════════

/// Initialize empty state.
fn init_empty_state() -> DSDNState {
    DSDNState {
        nodes: HashMap::new(),
        chunks: HashMap::new(),
        last_height: 0,
        last_sequence: 0,
    }
}


/// Convert internal state to rebuild output state.
fn convert_to_rebuild_state(state: &DSDNState) -> RebuildState {
    let nodes: HashMap<String, RebuildNodeInfo> = state.nodes.iter()
        .map(|(k, v)| {
            (k.clone(), RebuildNodeInfo {
                node_id: v.node_id.clone(),
                addr: v.addr.clone(),
                zone: v.zone.clone(),
                active: v.active,
            })
        })
        .collect();
    
    let chunks: HashMap<String, RebuildChunkInfo> = state.chunks.iter()
        .map(|(k, v)| {
            (k.clone(), RebuildChunkInfo {
                chunk_hash: v.chunk_hash.clone(),
                size: v.size,
                owner: v.owner.clone(),
                replicas: v.replicas.clone(),
            })
        })
        .collect();
    
    RebuildState {
        nodes,
        chunks,
        last_height: state.last_height,
    }
}

// ════════════════════════════════════════════════════════════════════════════
// VERIFICATION
// ════════════════════════════════════════════════════════════════════════════

/// Verify rebuilt state for internal consistency.
fn verify_state(state: &DSDNState) -> Result<bool> {
    // Verify all replica references point to existing nodes
    for (chunk_hash, chunk) in &state.chunks {
        for node_id in &chunk.replicas {
            if !state.nodes.contains_key(node_id) {
                anyhow::bail!(
                    "chunk '{}' references non-existent node '{}'",
                    chunk_hash, node_id
                );
            }
        }
    }
    
    // Verify no duplicate replicas per chunk
    for (chunk_hash, chunk) in &state.chunks {
        let mut seen: std::collections::HashSet<&String> = std::collections::HashSet::new();
        for node_id in &chunk.replicas {
            if !seen.insert(node_id) {
                anyhow::bail!(
                    "chunk '{}' has duplicate replica on node '{}'",
                    chunk_hash, node_id
                );
            }
        }
    }
    
    Ok(true)
}

// ════════════════════════════════════════════════════════════════════════════
// MAIN REBUILD PIPELINE
// ════════════════════════════════════════════════════════════════════════════

/// Execute the rebuild pipeline.
pub async fn rebuild_state_in_range(config: &RebuildConfig) -> Result<RebuildResult> {
    let start_time = std::time::Instant::now();
    
    // Validate range
    if config.from_height > config.to_height {
        anyhow::bail!(
            "invalid range: from_height ({}) > to_height ({})",
            config.from_height, config.to_height
        );
    }
    
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build HTTP client: {}", e))?;
    
    // Get current DA height to validate range
    let current_height = get_da_height(&client, &config.da_endpoint).await?;
    
    // Determine actual range
    let from_height = config.from_height;
    let to_height = if config.to_height > current_height {
        println!("[REBUILD] Warning: to_height ({}) exceeds current DA height ({}), using current",
            config.to_height, current_height);
        current_height
    } else {
        config.to_height
    };
    
    if from_height > current_height {
        anyhow::bail!(
            "from_height ({}) exceeds current DA height ({})",
            from_height, current_height
        );
    }
    
    let total_heights = to_height.saturating_sub(from_height) + 1;
    
    // ═══════════════════════════════════════════════════════════════════════
    // STEP 1: Fetch all blobs in range
    // ═══════════════════════════════════════════════════════════════════════
    
    print_rebuild_progress(&RebuildStage::FetchingBlobs { current: 0, total: total_heights });
    
    let mut all_blobs: Vec<(u64, Vec<Vec<u8>>)> = Vec::new();
    let mut blobs_fetched: u64 = 0;
    
    let fetch_start = std::time::Instant::now();
    
    for height in from_height..=to_height {
        let blobs = fetch_blobs_at_height(&client, &config.da_endpoint, &config.namespace, height).await?;
        let blob_count = blobs.len() as u64;
        blobs_fetched += blob_count;
        
        if !blobs.is_empty() {
            all_blobs.push((height, blobs));
        }
        
        let current_idx = height - from_height + 1;
        if current_idx % 10 == 0 || current_idx == total_heights {
            print_progress_with_eta("FETCHING", current_idx, total_heights, fetch_start);
        }
    }
    
    println!("[REBUILD] Fetched {} blobs from {} heights", blobs_fetched, all_blobs.len());
    
    // ═══════════════════════════════════════════════════════════════════════
    // STEP 2: Decode all events from blobs
    // ═══════════════════════════════════════════════════════════════════════
    
    print_rebuild_progress(&RebuildStage::DecodingEvents { blobs_processed: 0 });
    
    let mut all_events: Vec<(u64, DAEvent)> = Vec::new();
    let mut blobs_processed: u64 = 0;
    
    for (height, blobs) in &all_blobs {
        for blob in blobs {
            let events = decode_events_from_blob(blob);
            for event in events {
                all_events.push((*height, event));
            }
            blobs_processed += 1;
        }
    }
    
    println!("[REBUILD] Decoded {} events from {} blobs", all_events.len(), blobs_processed);
    
    // ═══════════════════════════════════════════════════════════════════════
    // STEP 3: Apply events to state machine (deterministic, ordered)
    // ═══════════════════════════════════════════════════════════════════════
    
    let total_events = all_events.len();
    print_rebuild_progress(&RebuildStage::ApplyingEvents { current: 0, total: total_events });
    
    let mut state = init_empty_state();
    let apply_start = std::time::Instant::now();
    
    for (idx, (height, event)) in all_events.iter().enumerate() {
        apply_event_to_state(&mut state, event);
        state.last_height = *height;
        
        if (idx + 1) % 100 == 0 || idx + 1 == total_events {
            print_progress_with_eta("APPLYING", (idx + 1) as u64, total_events as u64, apply_start);
        }
    }
    
    println!("[REBUILD] Applied {} events, final height: {}", total_events, state.last_height);
    
    // ═══════════════════════════════════════════════════════════════════════
    // STEP 4: Verify final state
    // ═══════════════════════════════════════════════════════════════════════
    
    print_rebuild_progress(&RebuildStage::Verifying);
    
    let verified = match verify_state(&state) {
        Ok(v) => v,
        Err(e) => {
            println!("[REBUILD] Verification failed: {}", e);
            false
        }
    };
    
    if verified {
        println!("[REBUILD] State verification passed ✓");
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // Build result
    // ═══════════════════════════════════════════════════════════════════════
    
    print_rebuild_progress(&RebuildStage::Complete);
    
    let stats = RebuildStats {
        from_height,
        to_height,
        blobs_fetched,
        events_decoded: all_events.len(),
        events_applied: all_events.len(),
        nodes_count: state.nodes.len(),
        chunks_count: state.chunks.len(),
        duration_ms: start_time.elapsed().as_millis() as u64,
        verified,
    };
    
    let result = RebuildResult {
        target: config.target.clone(),
        state: convert_to_rebuild_state(&state),
        stats,
    };
    
    Ok(result)
}

/// Rebuild state up to current height.
pub async fn rebuild_state_to_current(target: &str) -> Result<RebuildResult> {
    let da_config = DAConfig::from_env();
    
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build HTTP client: {}", e))?;
    
    let current_height = get_da_height(&client, &da_config.rpc_url).await?;
    
    let config = RebuildConfig {
        da_endpoint: da_config.rpc_url,
        namespace: da_config.namespace,
        target: target.to_string(),
        from_height: 1,
        to_height: current_height,
        output_path: None,
    };
    
    rebuild_state_in_range(&config).await
}

// ════════════════════════════════════════════════════════════════════════════
// COMMAND HANDLERS
// ════════════════════════════════════════════════════════════════════════════

/// Handle `agent rebuild` command.
pub async fn handle_rebuild(
    target: &str,
    from_height: Option<u64>,
    to_height: Option<u64>,
    output_path: Option<PathBuf>,
    json_output: bool,
) -> Result<()> {
    // Validate target
    let target_lower = target.to_lowercase();
    if target_lower != "coordinator" && target_lower != "node" {
        anyhow::bail!("invalid target '{}': must be 'coordinator' or 'node'", target);
    }
    
    let da_config = DAConfig::from_env();
    
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build HTTP client: {}", e))?;
    
    // Get current height for defaults
    let current_height = get_da_height(&client, &da_config.rpc_url).await?;
    
    let from = from_height.unwrap_or(1);
    let to = to_height.unwrap_or(current_height);
    
    let config = RebuildConfig {
        da_endpoint: da_config.rpc_url,
        namespace: da_config.namespace,
        target: target_lower.clone(),
        from_height: from,
        to_height: to,
        output_path: output_path.clone(),
    };
    
    println!("=== DSDN State Rebuild ===");
    println!("Target: {}", target_lower);
    println!("Range: {} - {}", from, to);
    println!();
    
    let result = rebuild_state_in_range(&config).await?;
    
    // Output result
    if json_output {
        println!("{}", result.to_json()?);
    } else {
        print!("{}", result.to_table());
    }
    
    // Write to file if output path specified
    if let Some(path) = output_path {
        let json = serde_json::to_string_pretty(&result.state)
            .map_err(|e| anyhow::anyhow!("failed to serialize state: {}", e))?;
        
        // Check if file already exists
        if path.exists() {
            anyhow::bail!("output file already exists: {}. Will not overwrite.", path.display());
        }
        
        std::fs::write(&path, json)
            .map_err(|e| anyhow::anyhow!("failed to write output file: {}", e))?;
        
        println!("\nState written to: {}", path.display());
    }
    
    // Return error if verification failed
    if !result.stats.verified {
        anyhow::bail!("state verification failed - rebuild may be incomplete or corrupted");
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
    // TEST 1: REBUILD STAGE DISPLAY
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_rebuild_stage_display() {
        assert_eq!(
            format!("{}", RebuildStage::FetchingBlobs { current: 10, total: 100 }),
            "FETCHING_BLOBS (10/100)"
        );
        assert_eq!(
            format!("{}", RebuildStage::DecodingEvents { blobs_processed: 50 }),
            "DECODING_EVENTS (blobs: 50)"
        );
        assert_eq!(
            format!("{}", RebuildStage::ApplyingEvents { current: 25, total: 100 }),
            "APPLYING_EVENTS (25/100)"
        );
        assert_eq!(format!("{}", RebuildStage::Verifying), "VERIFYING");
        assert_eq!(format!("{}", RebuildStage::Complete), "COMPLETE");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 2: REBUILD RESULT TO TABLE
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_rebuild_result_to_table() {
        let result = RebuildResult {
            target: "node".to_string(),
            state: RebuildState {
                nodes: HashMap::new(),
                chunks: HashMap::new(),
                last_height: 100,
            },
            stats: RebuildStats {
                from_height: 1,
                to_height: 100,
                blobs_fetched: 50,
                events_decoded: 200,
                events_applied: 200,
                nodes_count: 5,
                chunks_count: 10,
                duration_ms: 1500,
                verified: true,
            },
        };

        let table = result.to_table();
        assert!(table.contains("REBUILD STATE RESULT"));
        assert!(table.contains("node"));
        assert!(table.contains("100"));
        assert!(table.contains("YES"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 3: REBUILD RESULT JSON SERIALIZATION
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_rebuild_result_json() {
        let result = RebuildResult {
            target: "coordinator".to_string(),
            state: RebuildState {
                nodes: HashMap::new(),
                chunks: HashMap::new(),
                last_height: 50,
            },
            stats: RebuildStats {
                from_height: 1,
                to_height: 50,
                blobs_fetched: 25,
                events_decoded: 100,
                events_applied: 100,
                nodes_count: 3,
                chunks_count: 7,
                duration_ms: 800,
                verified: true,
            },
        };

        let json = result.to_json().expect("should serialize");
        assert!(json.contains("coordinator"));
        assert!(json.contains("\"verified\": true"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 4: INIT EMPTY STATE
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_init_empty_state() {
        let state = init_empty_state();
        assert!(state.nodes.is_empty());
        assert!(state.chunks.is_empty());
        assert_eq!(state.last_height, 0);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 5: DECODE EVENTS FROM BLOB
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_decode_events_from_blob_valid() {
        let events = vec![
            DAEvent::NodeRegistered {
                node_id: "node-1".to_string(),
                addr: "127.0.0.1:9000".to_string(),
                zone: Some("zone-a".to_string()),
            },
        ];
        let blob = serde_json::to_vec(&events).expect("should serialize");
        
        let decoded = decode_events_from_blob(&blob);
        assert_eq!(decoded.len(), 1);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 6: DECODE EVENTS FROM BLOB INVALID
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_decode_events_from_blob_invalid() {
        let invalid_blob = b"not valid json";
        let decoded = decode_events_from_blob(invalid_blob);
        assert!(decoded.is_empty());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 7: VERIFY STATE VALID
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_state_valid() {
        let mut state = init_empty_state();
        state.nodes.insert("node-1".to_string(), StateNodeInfo {
            node_id: "node-1".to_string(),
            addr: "127.0.0.1:9000".to_string(),
            zone: None,
            active: true,
        });
        state.chunks.insert("chunk-1".to_string(), StateChunkInfo {
            chunk_hash: "chunk-1".to_string(),
            size: 1024,
            owner: "owner".to_string(),
            replicas: vec!["node-1".to_string()],
        });

        let result = verify_state(&state);
        assert!(result.is_ok());
        assert!(result.expect("should verify"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 8: VERIFY STATE INVALID - MISSING NODE
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_state_invalid_missing_node() {
        let mut state = init_empty_state();
        // No nodes, but chunk references a node
        state.chunks.insert("chunk-1".to_string(), StateChunkInfo {
            chunk_hash: "chunk-1".to_string(),
            size: 1024,
            owner: "owner".to_string(),
            replicas: vec!["node-1".to_string()], // Node doesn't exist
        });

        let result = verify_state(&state);
        assert!(result.is_err());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 9: CONVERT TO REBUILD STATE
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_convert_to_rebuild_state() {
        let mut state = init_empty_state();
        state.nodes.insert("node-1".to_string(), StateNodeInfo {
            node_id: "node-1".to_string(),
            addr: "127.0.0.1:9000".to_string(),
            zone: Some("zone-a".to_string()),
            active: true,
        });
        state.chunks.insert("chunk-1".to_string(), StateChunkInfo {
            chunk_hash: "chunk-1".to_string(),
            size: 2048,
            owner: "owner-1".to_string(),
            replicas: vec!["node-1".to_string()],
        });
        state.last_height = 100;

        let rebuild_state = convert_to_rebuild_state(&state);
        
        assert_eq!(rebuild_state.nodes.len(), 1);
        assert_eq!(rebuild_state.chunks.len(), 1);
        assert_eq!(rebuild_state.last_height, 100);
        
        let node = rebuild_state.nodes.get("node-1").expect("should have node");
        assert_eq!(node.addr, "127.0.0.1:9000");
        assert_eq!(node.zone, Some("zone-a".to_string()));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 10: CALCULATE ETA
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_calculate_eta() {
        // Zero current should return None
        let start = std::time::Instant::now();
        assert!(calculate_eta_ms(start, 0, 100).is_none());
        
        // Zero total should return None
        assert!(calculate_eta_ms(start, 50, 0).is_none());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 11: REBUILD STATS SERIALIZATION
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_rebuild_stats_serialization() {
        let stats = RebuildStats {
            from_height: 1,
            to_height: 1000,
            blobs_fetched: 500,
            events_decoded: 2000,
            events_applied: 2000,
            nodes_count: 10,
            chunks_count: 100,
            duration_ms: 5000,
            verified: true,
        };

        let json = serde_json::to_string(&stats).expect("should serialize");
        let parsed: RebuildStats = serde_json::from_str(&json).expect("should parse");

        assert_eq!(parsed.from_height, 1);
        assert_eq!(parsed.to_height, 1000);
        assert_eq!(parsed.blobs_fetched, 500);
        assert!(parsed.verified);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 12: REBUILD NODE INFO SERIALIZATION
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_rebuild_node_info_serialization() {
        let node = RebuildNodeInfo {
            node_id: "node-1".to_string(),
            addr: "127.0.0.1:9000".to_string(),
            zone: Some("zone-a".to_string()),
            active: true,
        };

        let json = serde_json::to_string(&node).expect("should serialize");
        let parsed: RebuildNodeInfo = serde_json::from_str(&json).expect("should parse");

        assert_eq!(parsed.node_id, "node-1");
        assert_eq!(parsed.zone, Some("zone-a".to_string()));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 13: REBUILD CHUNK INFO SERIALIZATION
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_rebuild_chunk_info_serialization() {
        let chunk = RebuildChunkInfo {
            chunk_hash: "abc123".to_string(),
            size: 4096,
            owner: "owner-1".to_string(),
            replicas: vec!["node-1".to_string(), "node-2".to_string()],
        };

        let json = serde_json::to_string(&chunk).expect("should serialize");
        let parsed: RebuildChunkInfo = serde_json::from_str(&json).expect("should parse");

        assert_eq!(parsed.chunk_hash, "abc123");
        assert_eq!(parsed.size, 4096);
        assert_eq!(parsed.replicas.len(), 2);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14: REBUILD STAGE EQUALITY
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_rebuild_stage_equality() {
        assert_eq!(RebuildStage::Complete, RebuildStage::Complete);
        assert_eq!(RebuildStage::Verifying, RebuildStage::Verifying);
        assert_eq!(
            RebuildStage::FetchingBlobs { current: 10, total: 100 },
            RebuildStage::FetchingBlobs { current: 10, total: 100 }
        );
        assert_ne!(
            RebuildStage::FetchingBlobs { current: 10, total: 100 },
            RebuildStage::FetchingBlobs { current: 20, total: 100 }
        );
    }
}