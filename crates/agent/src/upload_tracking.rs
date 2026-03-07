use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};

use crate::cmd_da;
use crate::cmd_verify;
use crate::da_types::truncate_str;

// ════════════════════════════════════════════════════════════════════════════
// UPLOAD DA TRACKING
// ════════════════════════════════════════════════════════════════════════════

/// Upload tracking progress stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TrackingStage {
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
pub(crate) struct UploadTrackingResult {
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
pub(crate) struct TrackingConfig {
    pub(crate) da_endpoint: String,
    pub(crate) namespace: String,
    pub(crate) timeout_secs: u64,
    pub(crate) poll_interval_ms: u64,
}

impl TrackingConfig {
    pub(crate) fn from_env_and_args(timeout_secs: u64) -> Self {
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
pub(crate) fn print_tracking_progress(stage: &TrackingStage, chunk_hash: &str) {
    println!("[TRACK] {} | chunk: {}", stage, truncate_str(chunk_hash, 16));
}

/// Get current DA height.
pub(crate) async fn get_da_height(client: &reqwest::Client, endpoint: &str) -> Result<u64> {
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
pub(crate) async fn fetch_da_events(
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
pub(crate) async fn wait_for_chunk_declared(
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
pub(crate) async fn wait_for_replication(
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
pub(crate) async fn handle_upload_with_tracking(
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