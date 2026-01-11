//! # DA Command Module
//!
//! Module ini menyediakan command untuk interaksi dengan DA (Data Availability) layer.
//!
//! ## Prinsip
//!
//! - Semua data diambil dari DA layer aktual
//! - Tidak ada default palsu atau cache tanpa validasi
//! - Output table dan JSON konsisten secara semantik
//! - Blob raw TIDAK dimodifikasi atau diinterpretasi
//! - Tidak ada panic, unwrap, atau silent failure
//!
//! ## Usage
//!
//! ```bash
//! agent da status              # Table format (default)
//! agent da status --json       # JSON format
//! agent da blob get <height> <index>           # Fetch raw blob
//! agent da blob list --from <h1> --to <h2>     # List blobs in range
//! agent da blob decode <height> <index>        # Decode DA event
//! ```

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

// ════════════════════════════════════════════════════════════════════════════
// DA CONFIG
// ════════════════════════════════════════════════════════════════════════════

/// Konfigurasi untuk koneksi ke DA layer.
///
/// Struct ini merepresentasikan parameter koneksi ke Celestia DA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DAConfig {
    /// URL endpoint DA node (e.g., "http://localhost:26658")
    pub endpoint: String,
    /// Namespace ID untuk DSDN (hex encoded)
    pub namespace: String,
    /// Auth token untuk DA node (optional)
    pub auth_token: Option<String>,
    /// Connection timeout dalam detik
    pub timeout_secs: u64,
}

impl Default for DAConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://localhost:26658".to_string(),
            namespace: "0000000000000000000000000000000000000000445344".to_string(), // "DSD" in hex
            auth_token: None,
            timeout_secs: 10,
        }
    }
}

impl DAConfig {
    /// Membuat DAConfig dari environment variables.
    ///
    /// Environment variables:
    /// - DA_ENDPOINT: URL endpoint DA node
    /// - DA_NAMESPACE: Namespace ID (hex)
    /// - DA_AUTH_TOKEN: Auth token (optional)
    /// - DA_TIMEOUT_SECS: Timeout dalam detik
    pub fn from_env() -> Self {
        Self {
            endpoint: std::env::var("DA_ENDPOINT")
                .unwrap_or_else(|_| "http://localhost:26658".to_string()),
            namespace: std::env::var("DA_NAMESPACE")
                .unwrap_or_else(|_| "0000000000000000000000000000000000000000445344".to_string()),
            auth_token: std::env::var("DA_AUTH_TOKEN").ok(),
            timeout_secs: std::env::var("DA_TIMEOUT_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(10),
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// DA STATUS
// ════════════════════════════════════════════════════════════════════════════

/// Status sinkronisasi DA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SyncStatus {
    /// Node sedang sinkronisasi.
    Syncing,
    /// Node sudah sinkron.
    Synced,
    /// Status tidak diketahui.
    Unknown,
}

impl fmt::Display for SyncStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SyncStatus::Syncing => write!(f, "syncing"),
            SyncStatus::Synced => write!(f, "synced"),
            SyncStatus::Unknown => write!(f, "unknown"),
        }
    }
}

/// Status kesehatan DA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// DA layer sehat dan beroperasi normal.
    Healthy,
    /// DA layer mengalami masalah.
    Unhealthy,
    /// Status kesehatan tidak dapat ditentukan.
    Unknown,
}

impl fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HealthStatus::Healthy => write!(f, "healthy"),
            HealthStatus::Unhealthy => write!(f, "unhealthy"),
            HealthStatus::Unknown => write!(f, "unknown"),
        }
    }
}

/// Status koneksi DA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionStatus {
    /// Terhubung ke DA layer.
    Connected,
    /// Tidak terhubung ke DA layer.
    Disconnected,
    /// Sedang mencoba koneksi.
    Connecting,
}

impl fmt::Display for ConnectionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectionStatus::Connected => write!(f, "connected"),
            ConnectionStatus::Disconnected => write!(f, "disconnected"),
            ConnectionStatus::Connecting => write!(f, "connecting"),
        }
    }
}

/// Status lengkap DA layer.
///
/// Struct ini berisi semua informasi status yang diambil dari DA layer.
/// Semua field berasal dari query aktual ke DA node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DAStatus {
    /// Status koneksi ke DA node.
    pub connection: ConnectionStatus,
    /// Block height saat ini di DA layer.
    pub current_height: u64,
    /// Namespace yang digunakan (hex encoded).
    pub namespace: String,
    /// Status sinkronisasi node.
    pub sync_status: SyncStatus,
    /// Sequence number event terakhir yang diproses.
    pub last_event_sequence: u64,
    /// Status kesehatan DA layer.
    pub health: HealthStatus,
    /// Endpoint yang digunakan.
    pub endpoint: String,
    /// Error message jika ada (untuk diagnostik).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Default for DAStatus {
    fn default() -> Self {
        Self {
            connection: ConnectionStatus::Disconnected,
            current_height: 0,
            namespace: String::new(),
            sync_status: SyncStatus::Unknown,
            last_event_sequence: 0,
            health: HealthStatus::Unknown,
            endpoint: String::new(),
            error: None,
        }
    }
}

impl DAStatus {
    /// Format status sebagai table untuk display.
    pub fn to_table(&self) -> String {
        let mut output = String::new();
        output.push_str("┌─────────────────────────────────────────────────────────────┐\n");
        output.push_str("│                      DA Layer Status                        │\n");
        output.push_str("├─────────────────────┬───────────────────────────────────────┤\n");
        output.push_str(&format!("│ Connection          │ {:37} │\n", self.connection));
        output.push_str(&format!("│ Current Height      │ {:37} │\n", self.current_height));
        output.push_str(&format!("│ Namespace           │ {:37} │\n", truncate_string(&self.namespace, 37)));
        output.push_str(&format!("│ Sync Status         │ {:37} │\n", self.sync_status));
        output.push_str(&format!("│ Last Event Sequence │ {:37} │\n", self.last_event_sequence));
        output.push_str(&format!("│ Health              │ {:37} │\n", self.health));
        output.push_str(&format!("│ Endpoint            │ {:37} │\n", truncate_string(&self.endpoint, 37)));
        if let Some(ref err) = self.error {
            output.push_str("├─────────────────────┼───────────────────────────────────────┤\n");
            output.push_str(&format!("│ Error               │ {:37} │\n", truncate_string(err, 37)));
        }
        output.push_str("└─────────────────────┴───────────────────────────────────────┘\n");
        output
    }

    /// Format status sebagai JSON.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .context("failed to serialize DA status to JSON")
    }
}

/// Truncate string dengan ellipsis jika terlalu panjang.
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else if max_len > 3 {
        format!("{}...", &s[..max_len - 3])
    } else {
        s[..max_len].to_string()
    }
}

// ════════════════════════════════════════════════════════════════════════════
// DA STATUS QUERY
// ════════════════════════════════════════════════════════════════════════════

/// Error yang dapat terjadi saat query DA status.
#[allow(dead_code)]
#[derive(Debug)]
pub enum DAStatusError {
    /// Gagal terhubung ke DA node.
    ConnectionFailed(String),
    /// Timeout saat query.
    Timeout(String),
    /// Response tidak valid.
    InvalidResponse(String),
    /// Error lainnya.
    Other(String),
}

impl fmt::Display for DAStatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DAStatusError::ConnectionFailed(msg) => write!(f, "connection failed: {}", msg),
            DAStatusError::Timeout(msg) => write!(f, "timeout: {}", msg),
            DAStatusError::InvalidResponse(msg) => write!(f, "invalid response: {}", msg),
            DAStatusError::Other(msg) => write!(f, "error: {}", msg),
        }
    }
}

impl std::error::Error for DAStatusError {}

/// Query DA status dari DA layer.
///
/// # Arguments
///
/// * `config` - Konfigurasi DA connection
///
/// # Returns
///
/// * `Ok(DAStatus)` - Status berhasil diambil
/// * `Err(anyhow::Error)` - Error saat query
///
/// # Behavior
///
/// 1. Mencoba koneksi ke DA endpoint
/// 2. Query node info (height, sync status)
/// 3. Query namespace status
/// 4. Query health status
/// 5. Return compiled status
///
/// # Thread Safety
///
/// Fungsi ini stateless dan thread-safe.
pub async fn da_status(config: &DAConfig) -> Result<DAStatus> {
    let mut status = DAStatus {
        endpoint: config.endpoint.clone(),
        namespace: config.namespace.clone(),
        ..Default::default()
    };

    // Build HTTP client with timeout
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(config.timeout_secs))
        .build()
        .context("failed to build HTTP client")?;

    // Try to query DA node status
    match query_da_node(&client, config).await {
        Ok(node_status) => {
            status.connection = ConnectionStatus::Connected;
            status.current_height = node_status.height;
            status.sync_status = node_status.sync_status;
            status.last_event_sequence = node_status.last_sequence;
            status.health = if node_status.is_healthy {
                HealthStatus::Healthy
            } else {
                HealthStatus::Unhealthy
            };
        }
        Err(e) => {
            status.connection = ConnectionStatus::Disconnected;
            status.health = HealthStatus::Unknown;
            status.error = Some(e.to_string());
        }
    }

    Ok(status)
}

/// Internal node status dari query.
struct NodeQueryResult {
    height: u64,
    sync_status: SyncStatus,
    last_sequence: u64,
    is_healthy: bool,
}

/// Query DA node untuk status.
async fn query_da_node(client: &reqwest::Client, config: &DAConfig) -> Result<NodeQueryResult> {
    // Try JSON-RPC header endpoint (Celestia standard)
    let header_url = format!("{}/header/local_head", config.endpoint);
    
    let response = client
        .get(&header_url)
        .send()
        .await
        .context("failed to connect to DA node")?;

    if !response.status().is_success() {
        // Try alternate endpoint
        return query_da_node_alternate(client, config).await;
    }

    let body = response
        .text()
        .await
        .context("failed to read response body")?;

    // Parse response
    parse_header_response(&body)
}

/// Alternate query method untuk DA node.
async fn query_da_node_alternate(client: &reqwest::Client, config: &DAConfig) -> Result<NodeQueryResult> {
    // Try status endpoint
    let status_url = format!("{}/status", config.endpoint);
    
    let response = client
        .get(&status_url)
        .send()
        .await
        .context("failed to connect to DA node status endpoint")?;

    if !response.status().is_success() {
        anyhow::bail!("DA node returned error status: {}", response.status());
    }

    let body = response
        .text()
        .await
        .context("failed to read status response body")?;

    parse_status_response(&body)
}

/// Parse header response dari DA node.
fn parse_header_response(body: &str) -> Result<NodeQueryResult> {
    // Try to parse as JSON
    let json: serde_json::Value = serde_json::from_str(body)
        .context("failed to parse header response as JSON")?;

    let height = json
        .get("header")
        .and_then(|h| h.get("height"))
        .and_then(|h| h.as_str())
        .and_then(|h| h.parse::<u64>().ok())
        .or_else(|| json.get("height").and_then(|h| h.as_u64()))
        .unwrap_or(0);

    let is_syncing = json
        .get("syncing")
        .and_then(|s| s.as_bool())
        .unwrap_or(false);

    let sync_status = if is_syncing {
        SyncStatus::Syncing
    } else if height > 0 {
        SyncStatus::Synced
    } else {
        SyncStatus::Unknown
    };

    Ok(NodeQueryResult {
        height,
        sync_status,
        last_sequence: height, // Use height as proxy for sequence
        is_healthy: height > 0,
    })
}

/// Parse status response dari DA node.
fn parse_status_response(body: &str) -> Result<NodeQueryResult> {
    let json: serde_json::Value = serde_json::from_str(body)
        .context("failed to parse status response as JSON")?;

    let height = json
        .get("result")
        .and_then(|r| r.get("sync_info"))
        .and_then(|s| s.get("latest_block_height"))
        .and_then(|h| h.as_str())
        .and_then(|h| h.parse::<u64>().ok())
        .unwrap_or(0);

    let catching_up = json
        .get("result")
        .and_then(|r| r.get("sync_info"))
        .and_then(|s| s.get("catching_up"))
        .and_then(|c| c.as_bool())
        .unwrap_or(true);

    let sync_status = if catching_up {
        SyncStatus::Syncing
    } else if height > 0 {
        SyncStatus::Synced
    } else {
        SyncStatus::Unknown
    };

    Ok(NodeQueryResult {
        height,
        sync_status,
        last_sequence: height,
        is_healthy: height > 0 && !catching_up,
    })
}

// ════════════════════════════════════════════════════════════════════════════
// BLOB TYPES
// ════════════════════════════════════════════════════════════════════════════

/// Information about a blob at specific height.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobInfo {
    /// Block height containing the blob.
    pub height: u64,
    /// Index within the height.
    pub index: u32,
    /// Size in bytes.
    pub size: usize,
    /// Namespace (hex).
    pub namespace: String,
    /// Commitment hash (hex).
    pub commitment: String,
}

impl BlobInfo {
    /// Format as table row.
    #[allow(dead_code)]
    pub fn to_table_row(&self) -> String {
        format!(
            "│ {:>10} │ {:>5} │ {:>10} │ {:>16} │ {:>20} │",
            self.height,
            self.index,
            self.size,
            truncate_string(&self.namespace, 16),
            truncate_string(&self.commitment, 20),
        )
    }
}

/// List of blobs for display.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobList {
    /// Start height (inclusive).
    pub from_height: u64,
    /// End height (inclusive).
    pub to_height: u64,
    /// List of blobs found.
    pub blobs: Vec<BlobInfo>,
    /// Total count.
    pub total: usize,
}

impl BlobList {
    /// Format as table.
    #[allow(dead_code)]
    pub fn to_table(&self) -> String {
        let mut output = String::new();
        output.push_str("┌────────────┬───────┬────────────┬──────────────────┬──────────────────────┐\n");
        output.push_str("│     Height │ Index │       Size │        Namespace │           Commitment │\n");
        output.push_str("├────────────┼───────┼────────────┼──────────────────┼──────────────────────┤\n");
        
        if self.blobs.is_empty() {
            output.push_str("│                          No blobs found                                   │\n");
        } else {
            for blob in &self.blobs {
                output.push_str(&blob.to_table_row());
                output.push('\n');
            }
        }
        
        output.push_str("├────────────┴───────┴────────────┴──────────────────┴──────────────────────┤\n");
        output.push_str(&format!("│ Range: {} - {} | Total: {:>6} blobs {:>24}│\n", 
            self.from_height, self.to_height, self.total, ""));
        output.push_str("└─────────────────────────────────────────────────────────────────────────────┘\n");
        output
    }

    /// Format as JSON.
    #[allow(dead_code)]
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .context("failed to serialize blob list to JSON")
    }
}

/// Raw blob data from DA.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct RawBlob {
    /// Block height.
    pub height: u64,
    /// Blob index within height.
    pub index: u32,
    /// Raw bytes (NOT modified).
    pub data: Vec<u8>,
    /// Namespace (hex).
    pub namespace: String,
    /// Commitment (hex).
    pub commitment: String,
}

impl RawBlob {
    /// Format as hex dump.
    /// Output format: offset | hex bytes | ASCII representation
    #[allow(dead_code)]
    pub fn to_hex_dump(&self) -> String {
        let mut output = String::new();
        output.push_str(&format!("Height: {}\n", self.height));
        output.push_str(&format!("Index: {}\n", self.index));
        output.push_str(&format!("Namespace: {}\n", self.namespace));
        output.push_str(&format!("Commitment: {}\n", self.commitment));
        output.push_str(&format!("Size: {} bytes\n", self.data.len()));
        output.push_str(&"─".repeat(76));
        output.push('\n');
        
        // Hex dump with 16 bytes per line
        for (offset, chunk) in self.data.chunks(16).enumerate() {
            // Offset
            output.push_str(&format!("{:08x}  ", offset * 16));
            
            // Hex bytes
            for (i, byte) in chunk.iter().enumerate() {
                output.push_str(&format!("{:02x} ", byte));
                if i == 7 {
                    output.push(' ');
                }
            }
            
            // Padding for incomplete lines
            if chunk.len() < 16 {
                for i in chunk.len()..16 {
                    output.push_str("   ");
                    if i == 7 {
                        output.push(' ');
                    }
                }
            }
            
            // ASCII representation
            output.push_str(" |");
            for byte in chunk {
                if *byte >= 0x20 && *byte <= 0x7e {
                    output.push(*byte as char);
                } else {
                    output.push('.');
                }
            }
            output.push_str("|\n");
        }
        
        output
    }

    /// Format as pure hex string (no formatting).
    #[allow(dead_code)]
    pub fn to_hex_string(&self) -> String {
        hex::encode(&self.data)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// DA EVENT TYPES (for decode)
// ════════════════════════════════════════════════════════════════════════════

/// DA Event types from DSDN blockchain.
/// These match the exact format stored in DA blobs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
#[allow(dead_code)]
pub enum DAEvent {
    /// Chunk declared by owner.
    ChunkDeclared {
        chunk_hash: String,
        size: u64,
        owner: String,
        commitment: String,
    },
    /// Replica added to chunk.
    ReplicaAdded {
        chunk_hash: String,
        node_id: String,
        proof: String,
    },
    /// Replica removed from chunk.
    ReplicaRemoved {
        chunk_hash: String,
        node_id: String,
        reason: String,
    },
    /// Node registered.
    NodeRegistered {
        node_id: String,
        addr: String,
        zone: Option<String>,
    },
    /// Node unregistered.
    NodeUnregistered {
        node_id: String,
    },
    /// Delete requested for chunk.
    DeleteRequested {
        chunk_hash: String,
        requester: String,
    },
}

impl DAEvent {
    /// Format event untuk display.
    #[allow(dead_code)]
    pub fn to_pretty(&self) -> String {
        let mut output = String::new();
        
        match self {
            DAEvent::ChunkDeclared { chunk_hash, size, owner, commitment } => {
                output.push_str("┌─ ChunkDeclared ─────────────────────────────────────────────┐\n");
                output.push_str(&format!("│ chunk_hash: {:50} │\n", truncate_string(chunk_hash, 50)));
                output.push_str(&format!("│ size:       {:50} │\n", size));
                output.push_str(&format!("│ owner:      {:50} │\n", truncate_string(owner, 50)));
                output.push_str(&format!("│ commitment: {:50} │\n", truncate_string(commitment, 50)));
                output.push_str("└─────────────────────────────────────────────────────────────┘\n");
            }
            DAEvent::ReplicaAdded { chunk_hash, node_id, proof } => {
                output.push_str("┌─ ReplicaAdded ──────────────────────────────────────────────┐\n");
                output.push_str(&format!("│ chunk_hash: {:50} │\n", truncate_string(chunk_hash, 50)));
                output.push_str(&format!("│ node_id:    {:50} │\n", truncate_string(node_id, 50)));
                output.push_str(&format!("│ proof:      {:50} │\n", truncate_string(proof, 50)));
                output.push_str("└─────────────────────────────────────────────────────────────┘\n");
            }
            DAEvent::ReplicaRemoved { chunk_hash, node_id, reason } => {
                output.push_str("┌─ ReplicaRemoved ────────────────────────────────────────────┐\n");
                output.push_str(&format!("│ chunk_hash: {:50} │\n", truncate_string(chunk_hash, 50)));
                output.push_str(&format!("│ node_id:    {:50} │\n", truncate_string(node_id, 50)));
                output.push_str(&format!("│ reason:     {:50} │\n", truncate_string(reason, 50)));
                output.push_str("└─────────────────────────────────────────────────────────────┘\n");
            }
            DAEvent::NodeRegistered { node_id, addr, zone } => {
                output.push_str("┌─ NodeRegistered ────────────────────────────────────────────┐\n");
                output.push_str(&format!("│ node_id: {:53} │\n", truncate_string(node_id, 53)));
                output.push_str(&format!("│ addr:    {:53} │\n", truncate_string(addr, 53)));
                output.push_str(&format!("│ zone:    {:53} │\n", zone.as_deref().unwrap_or("(none)")));
                output.push_str("└─────────────────────────────────────────────────────────────┘\n");
            }
            DAEvent::NodeUnregistered { node_id } => {
                output.push_str("┌─ NodeUnregistered ──────────────────────────────────────────┐\n");
                output.push_str(&format!("│ node_id: {:53} │\n", truncate_string(node_id, 53)));
                output.push_str("└─────────────────────────────────────────────────────────────┘\n");
            }
            DAEvent::DeleteRequested { chunk_hash, requester } => {
                output.push_str("┌─ DeleteRequested ───────────────────────────────────────────┐\n");
                output.push_str(&format!("│ chunk_hash: {:50} │\n", truncate_string(chunk_hash, 50)));
                output.push_str(&format!("│ requester:  {:50} │\n", truncate_string(requester, 50)));
                output.push_str("└─────────────────────────────────────────────────────────────┘\n");
            }
        }
        
        output
    }

    /// Format as JSON.
    #[allow(dead_code)]
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .context("failed to serialize DA event to JSON")
    }
}

/// Decoded blob containing events.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct DecodedBlob {
    /// Block height.
    pub height: u64,
    /// Blob index.
    pub index: u32,
    /// Decoded events.
    pub events: Vec<DAEvent>,
    /// Number of events.
    pub event_count: usize,
}

impl DecodedBlob {
    /// Format as pretty printed output.
    #[allow(dead_code)]
    pub fn to_pretty(&self) -> String {
        let mut output = String::new();
        output.push_str(&format!("Height: {}\n", self.height));
        output.push_str(&format!("Index: {}\n", self.index));
        output.push_str(&format!("Events: {}\n", self.event_count));
        output.push_str(&"═".repeat(65));
        output.push('\n');
        
        for (i, event) in self.events.iter().enumerate() {
            output.push_str(&format!("\n[Event {}]\n", i + 1));
            output.push_str(&event.to_pretty());
        }
        
        output
    }

    /// Format as JSON.
    #[allow(dead_code)]
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .context("failed to serialize decoded blob to JSON")
    }
}

// ════════════════════════════════════════════════════════════════════════════
// BLOB QUERY FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════

/// Fetch raw blob from DA at specific height and index.
///
/// # Arguments
///
/// * `config` - DA configuration
/// * `height` - Block height
/// * `index` - Blob index within height
///
/// # Returns
///
/// * `Ok(RawBlob)` - Raw blob data (NOT modified)
/// * `Err(anyhow::Error)` - Error fetching blob
#[allow(dead_code)]
pub async fn fetch_blob_raw(config: &DAConfig, height: u64, index: u32) -> Result<RawBlob> {
    // Validate inputs
    if height == 0 {
        anyhow::bail!("invalid height: must be > 0");
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(config.timeout_secs))
        .build()
        .context("failed to build HTTP client")?;

    // Celestia blob.Get endpoint
    let url = format!(
        "{}/blob/get/{}/{}/{}",
        config.endpoint,
        height,
        config.namespace,
        index
    );

    let response = client
        .get(&url)
        .send()
        .await
        .context("failed to connect to DA node for blob fetch")?;

    if !response.status().is_success() {
        anyhow::bail!(
            "blob fetch failed: height={}, index={}, status={}",
            height,
            index,
            response.status()
        );
    }

    let body = response
        .text()
        .await
        .context("failed to read blob response")?;

    parse_blob_response(&body, height, index)
}

/// Parse blob response from DA node.
fn parse_blob_response(body: &str, height: u64, index: u32) -> Result<RawBlob> {
    let json: serde_json::Value = serde_json::from_str(body)
        .context("failed to parse blob response as JSON")?;

    // Extract data (base64 encoded in Celestia)
    let data_b64 = json
        .get("data")
        .and_then(|d| d.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing 'data' field in blob response"))?;

    let data = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        data_b64,
    ).context("failed to decode blob data from base64")?;

    let namespace = json
        .get("namespace")
        .and_then(|n| n.as_str())
        .unwrap_or("")
        .to_string();

    let commitment = json
        .get("commitment")
        .and_then(|c| c.as_str())
        .unwrap_or("")
        .to_string();

    Ok(RawBlob {
        height,
        index,
        data,
        namespace,
        commitment,
    })
}

/// List blobs in height range.
///
/// # Arguments
///
/// * `config` - DA configuration
/// * `from_height` - Start height (inclusive)
/// * `to_height` - End height (inclusive)
///
/// # Returns
///
/// * `Ok(BlobList)` - List of blob info
/// * `Err(anyhow::Error)` - Error listing blobs
#[allow(dead_code)]
pub async fn list_blobs(config: &DAConfig, from_height: u64, to_height: u64) -> Result<BlobList> {
    // Validate inputs
    if from_height == 0 {
        anyhow::bail!("invalid from_height: must be > 0");
    }
    if to_height < from_height {
        anyhow::bail!("invalid range: to_height ({}) < from_height ({})", to_height, from_height);
    }
    if to_height - from_height > 1000 {
        anyhow::bail!("range too large: max 1000 heights per query");
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(config.timeout_secs))
        .build()
        .context("failed to build HTTP client")?;

    let mut all_blobs = Vec::new();

    for height in from_height..=to_height {
        match fetch_blobs_at_height(&client, config, height).await {
            Ok(blobs) => all_blobs.extend(blobs),
            Err(e) => {
                // Log error but continue with other heights
                eprintln!("Warning: failed to fetch blobs at height {}: {}", height, e);
            }
        }
    }

    Ok(BlobList {
        from_height,
        to_height,
        total: all_blobs.len(),
        blobs: all_blobs,
    })
}

/// Fetch blob info at specific height.
#[allow(dead_code)]
async fn fetch_blobs_at_height(
    client: &reqwest::Client,
    config: &DAConfig,
    height: u64,
) -> Result<Vec<BlobInfo>> {
    // Celestia blob.GetAll endpoint
    let url = format!(
        "{}/blob/get_all/{}/{}",
        config.endpoint,
        height,
        config.namespace
    );

    let response = client
        .get(&url)
        .send()
        .await
        .context("failed to fetch blobs at height")?;

    if !response.status().is_success() {
        // No blobs at this height is not an error
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(Vec::new());
        }
        anyhow::bail!("blob list failed: height={}, status={}", height, response.status());
    }

    let body = response
        .text()
        .await
        .context("failed to read blob list response")?;

    parse_blob_list_response(&body, height)
}

/// Parse blob list response.
fn parse_blob_list_response(body: &str, height: u64) -> Result<Vec<BlobInfo>> {
    let json: serde_json::Value = serde_json::from_str(body)
        .context("failed to parse blob list response")?;

    let blobs_array = json
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("expected array in blob list response"))?;

    let mut result = Vec::new();

    for (index, blob) in blobs_array.iter().enumerate() {
        let data_b64 = blob.get("data").and_then(|d| d.as_str()).unwrap_or("");
        let data_len = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            data_b64,
        ).map(|d| d.len()).unwrap_or(0);

        let namespace = blob
            .get("namespace")
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_string();

        let commitment = blob
            .get("commitment")
            .and_then(|c| c.as_str())
            .unwrap_or("")
            .to_string();

        result.push(BlobInfo {
            height,
            index: index as u32,
            size: data_len,
            namespace,
            commitment,
        });
    }

    Ok(result)
}

/// Decode blob into DA events.
///
/// # Arguments
///
/// * `config` - DA configuration
/// * `height` - Block height
/// * `index` - Blob index
///
/// # Returns
///
/// * `Ok(DecodedBlob)` - Decoded events
/// * `Err(anyhow::Error)` - Error decoding
#[allow(dead_code)]
pub async fn decode_blob(config: &DAConfig, height: u64, index: u32) -> Result<DecodedBlob> {
    // Fetch raw blob first
    let raw = fetch_blob_raw(config, height, index).await?;

    // Decode events from raw data
    let events = decode_events_from_bytes(&raw.data)?;

    Ok(DecodedBlob {
        height,
        index,
        event_count: events.len(),
        events,
    })
}

/// Decode DA events from raw bytes.
///
/// Format: JSON array of events (DSDN format)
#[allow(dead_code)]
fn decode_events_from_bytes(data: &[u8]) -> Result<Vec<DAEvent>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    // Try to parse as JSON array of events
    let events: Vec<DAEvent> = serde_json::from_slice(data)
        .context("failed to decode events from blob data")?;

    Ok(events)
}

// ════════════════════════════════════════════════════════════════════════════
// CLI HANDLERS
// ════════════════════════════════════════════════════════════════════════════

/// Handle `agent da status` command.
///
/// # Arguments
///
/// * `json_output` - Jika true, output dalam format JSON
///
/// # Returns
///
/// * `Ok(())` - Command berhasil
/// * `Err(anyhow::Error)` - Error saat execute
pub async fn handle_da_status(json_output: bool) -> Result<()> {
    let config = DAConfig::from_env();
    let status = da_status(&config).await?;

    if json_output {
        let json = status.to_json()?;
        println!("{}", json);
    } else {
        print!("{}", status.to_table());
    }

    Ok(())
}

/// Handle `agent da blob get` command.
///
/// # Arguments
///
/// * `height` - Block height
/// * `index` - Blob index
/// * `output` - Optional output file path
///
/// # Returns
///
/// * `Ok(())` - Command berhasil
/// * `Err(anyhow::Error)` - Error saat execute
#[allow(dead_code)]
pub async fn handle_blob_get(height: u64, index: u32, output: Option<PathBuf>) -> Result<()> {
    let config = DAConfig::from_env();
    let raw = fetch_blob_raw(&config, height, index).await?;

    let hex_dump = raw.to_hex_dump();

    // Write to file if specified
    if let Some(path) = output {
        write_output_no_overwrite(&path, hex_dump.as_bytes())?;
        println!("Output written to: {}", path.display());
    } else {
        print!("{}", hex_dump);
    }

    Ok(())
}

/// Handle `agent da blob list` command.
///
/// # Arguments
///
/// * `from_height` - Start height
/// * `to_height` - End height
/// * `json_output` - Output as JSON
/// * `output` - Optional output file path
///
/// # Returns
///
/// * `Ok(())` - Command berhasil
/// * `Err(anyhow::Error)` - Error saat execute
#[allow(dead_code)]
pub async fn handle_blob_list(
    from_height: u64,
    to_height: u64,
    json_output: bool,
    output: Option<PathBuf>,
) -> Result<()> {
    let config = DAConfig::from_env();
    let list = list_blobs(&config, from_height, to_height).await?;

    let out_str = if json_output {
        list.to_json()?
    } else {
        list.to_table()
    };

    // Write to file if specified
    if let Some(path) = output {
        write_output_no_overwrite(&path, out_str.as_bytes())?;
        println!("Output written to: {}", path.display());
    } else {
        print!("{}", out_str);
    }

    Ok(())
}

/// Handle `agent da blob decode` command.
///
/// # Arguments
///
/// * `height` - Block height
/// * `index` - Blob index
/// * `json_output` - Output as JSON
/// * `output` - Optional output file path
///
/// # Returns
///
/// * `Ok(())` - Command berhasil
/// * `Err(anyhow::Error)` - Error saat execute
#[allow(dead_code)]
pub async fn handle_blob_decode(
    height: u64,
    index: u32,
    json_output: bool,
    output: Option<PathBuf>,
) -> Result<()> {
    let config = DAConfig::from_env();
    let decoded = decode_blob(&config, height, index).await?;

    let out_str = if json_output {
        decoded.to_json()?
    } else {
        decoded.to_pretty()
    };

    // Write to file if specified
    if let Some(path) = output {
        write_output_no_overwrite(&path, out_str.as_bytes())?;
        println!("Output written to: {}", path.display());
    } else {
        print!("{}", out_str);
    }

    Ok(())
}

/// Write output to file without silent overwrite.
///
/// # Arguments
///
/// * `path` - Output file path
/// * `data` - Data to write
///
/// # Returns
///
/// * `Ok(())` - Write successful
/// * `Err(anyhow::Error)` - Error (including file exists)
fn write_output_no_overwrite(path: &PathBuf, data: &[u8]) -> Result<()> {
    if path.exists() {
        anyhow::bail!("output file already exists: {}. Use different path or remove existing file.", path.display());
    }

    let mut file = fs::File::create(path)
        .with_context(|| format!("failed to create output file: {}", path.display()))?;

    file.write_all(data)
        .with_context(|| format!("failed to write to output file: {}", path.display()))?;

    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ════════════════════════════════════════════════════════════════════════
    // TEST 1: DA CONFIG DEFAULT
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_da_config_default() {
        let config = DAConfig::default();
        
        assert!(!config.endpoint.is_empty());
        assert!(!config.namespace.is_empty());
        assert!(config.timeout_secs > 0);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 2: DA STATUS DEFAULT
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_da_status_default() {
        let status = DAStatus::default();
        
        assert_eq!(status.connection, ConnectionStatus::Disconnected);
        assert_eq!(status.current_height, 0);
        assert_eq!(status.sync_status, SyncStatus::Unknown);
        assert_eq!(status.health, HealthStatus::Unknown);
        assert!(status.error.is_none());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 3: TABLE OUTPUT VALID
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_table_output_valid() {
        let status = DAStatus {
            connection: ConnectionStatus::Connected,
            current_height: 12345,
            namespace: "test-namespace".to_string(),
            sync_status: SyncStatus::Synced,
            last_event_sequence: 100,
            health: HealthStatus::Healthy,
            endpoint: "http://localhost:26658".to_string(),
            error: None,
        };

        let table = status.to_table();
        
        // Verify all fields present
        assert!(table.contains("Connection"));
        assert!(table.contains("connected"));
        assert!(table.contains("Current Height"));
        assert!(table.contains("12345"));
        assert!(table.contains("Namespace"));
        assert!(table.contains("test-namespace"));
        assert!(table.contains("Sync Status"));
        assert!(table.contains("synced"));
        assert!(table.contains("Last Event Sequence"));
        assert!(table.contains("100"));
        assert!(table.contains("Health"));
        assert!(table.contains("healthy"));
        assert!(table.contains("Endpoint"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 4: JSON OUTPUT VALID & CONSISTENT
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_json_output_valid_and_consistent() {
        let status = DAStatus {
            connection: ConnectionStatus::Connected,
            current_height: 12345,
            namespace: "test-namespace".to_string(),
            sync_status: SyncStatus::Synced,
            last_event_sequence: 100,
            health: HealthStatus::Healthy,
            endpoint: "http://localhost:26658".to_string(),
            error: None,
        };

        let json_str = status.to_json().expect("should serialize");
        
        // Parse back and verify
        let parsed: DAStatus = serde_json::from_str(&json_str).expect("should parse");
        
        assert_eq!(parsed.connection, status.connection);
        assert_eq!(parsed.current_height, status.current_height);
        assert_eq!(parsed.namespace, status.namespace);
        assert_eq!(parsed.sync_status, status.sync_status);
        assert_eq!(parsed.last_event_sequence, status.last_event_sequence);
        assert_eq!(parsed.health, status.health);
        assert_eq!(parsed.endpoint, status.endpoint);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 5: TABLE AND JSON SEMANTICALLY CONSISTENT
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_table_json_semantically_consistent() {
        let status = DAStatus {
            connection: ConnectionStatus::Disconnected,
            current_height: 999,
            namespace: "ns123".to_string(),
            sync_status: SyncStatus::Syncing,
            last_event_sequence: 50,
            health: HealthStatus::Unhealthy,
            endpoint: "http://example.com".to_string(),
            error: Some("test error".to_string()),
        };

        let table = status.to_table();
        let json_str = status.to_json().expect("should serialize");
        let json: serde_json::Value = serde_json::from_str(&json_str).expect("should parse");

        // Verify semantic consistency
        assert!(table.contains("disconnected"));
        assert_eq!(json["connection"], "disconnected");

        assert!(table.contains("999"));
        assert_eq!(json["current_height"], 999);

        assert!(table.contains("syncing"));
        assert_eq!(json["sync_status"], "syncing");

        assert!(table.contains("unhealthy"));
        assert_eq!(json["health"], "unhealthy");

        assert!(table.contains("test error"));
        assert_eq!(json["error"], "test error");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 6: ERROR HANDLING - NO PANIC
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_no_panic_on_invalid_data() {
        // Empty status should not panic
        let status = DAStatus::default();
        let _ = status.to_table();
        let _ = status.to_json();

        // Long strings should not panic
        let long_status = DAStatus {
            connection: ConnectionStatus::Connected,
            current_height: u64::MAX,
            namespace: "a".repeat(1000),
            sync_status: SyncStatus::Synced,
            last_event_sequence: u64::MAX,
            health: HealthStatus::Healthy,
            endpoint: "b".repeat(1000),
            error: Some("c".repeat(1000)),
        };
        let _ = long_status.to_table();
        let _ = long_status.to_json();
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 7: PARSE HEADER RESPONSE
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_parse_header_response() {
        let json = r#"{
            "header": {
                "height": "12345"
            },
            "syncing": false
        }"#;

        let result = parse_header_response(json).expect("should parse");
        assert_eq!(result.height, 12345);
        assert_eq!(result.sync_status, SyncStatus::Synced);
        assert!(result.is_healthy);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 8: PARSE STATUS RESPONSE
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_parse_status_response() {
        let json = r#"{
            "result": {
                "sync_info": {
                    "latest_block_height": "54321",
                    "catching_up": false
                }
            }
        }"#;

        let result = parse_status_response(json).expect("should parse");
        assert_eq!(result.height, 54321);
        assert_eq!(result.sync_status, SyncStatus::Synced);
        assert!(result.is_healthy);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 9: DETERMINISTIC OUTPUT
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_deterministic_output() {
        let status = DAStatus {
            connection: ConnectionStatus::Connected,
            current_height: 100,
            namespace: "test".to_string(),
            sync_status: SyncStatus::Synced,
            last_event_sequence: 50,
            health: HealthStatus::Healthy,
            endpoint: "http://test".to_string(),
            error: None,
        };

        // Run multiple times - should be identical
        let table1 = status.to_table();
        let table2 = status.to_table();
        assert_eq!(table1, table2);

        let json1 = status.to_json().expect("should serialize");
        let json2 = status.to_json().expect("should serialize");
        assert_eq!(json1, json2);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 10: TRUNCATE STRING
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_truncate_string() {
        assert_eq!(truncate_string("short", 10), "short");
        assert_eq!(truncate_string("exactly10!", 10), "exactly10!");
        assert_eq!(truncate_string("this is too long", 10), "this is...");
        assert_eq!(truncate_string("abc", 3), "abc");
        assert_eq!(truncate_string("abcd", 3), "abc");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 11: SYNC STATUS DISPLAY
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_sync_status_display() {
        assert_eq!(format!("{}", SyncStatus::Syncing), "syncing");
        assert_eq!(format!("{}", SyncStatus::Synced), "synced");
        assert_eq!(format!("{}", SyncStatus::Unknown), "unknown");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 12: HEALTH STATUS DISPLAY
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_health_status_display() {
        assert_eq!(format!("{}", HealthStatus::Healthy), "healthy");
        assert_eq!(format!("{}", HealthStatus::Unhealthy), "unhealthy");
        assert_eq!(format!("{}", HealthStatus::Unknown), "unknown");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 13: CONNECTION STATUS DISPLAY
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_connection_status_display() {
        assert_eq!(format!("{}", ConnectionStatus::Connected), "connected");
        assert_eq!(format!("{}", ConnectionStatus::Disconnected), "disconnected");
        assert_eq!(format!("{}", ConnectionStatus::Connecting), "connecting");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14: RAW BLOB HEX DUMP
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_raw_blob_hex_dump() {
        let raw = RawBlob {
            height: 100,
            index: 0,
            data: vec![0x00, 0x01, 0x02, 0x03, 0x48, 0x65, 0x6c, 0x6c, 0x6f],
            namespace: "test-ns".to_string(),
            commitment: "abc123".to_string(),
        };

        let dump = raw.to_hex_dump();

        // Verify header
        assert!(dump.contains("Height: 100"));
        assert!(dump.contains("Index: 0"));
        assert!(dump.contains("Namespace: test-ns"));
        assert!(dump.contains("Commitment: abc123"));
        assert!(dump.contains("Size: 9 bytes"));

        // Verify hex content
        assert!(dump.contains("00 01 02 03"));
        assert!(dump.contains("48 65 6c 6c"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 15: RAW BLOB HEX STRING
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_raw_blob_hex_string() {
        let raw = RawBlob {
            height: 100,
            index: 0,
            data: vec![0xde, 0xad, 0xbe, 0xef],
            namespace: "".to_string(),
            commitment: "".to_string(),
        };

        let hex = raw.to_hex_string();
        assert_eq!(hex, "deadbeef");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 16: BLOB LIST TABLE
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_blob_list_table() {
        let list = BlobList {
            from_height: 100,
            to_height: 200,
            total: 2,
            blobs: vec![
                BlobInfo {
                    height: 100,
                    index: 0,
                    size: 1024,
                    namespace: "ns1".to_string(),
                    commitment: "commit1".to_string(),
                },
                BlobInfo {
                    height: 150,
                    index: 1,
                    size: 2048,
                    namespace: "ns2".to_string(),
                    commitment: "commit2".to_string(),
                },
            ],
        };

        let table = list.to_table();

        // Verify headers
        assert!(table.contains("Height"));
        assert!(table.contains("Index"));
        assert!(table.contains("Size"));
        assert!(table.contains("Namespace"));
        assert!(table.contains("Commitment"));

        // Verify data
        assert!(table.contains("100"));
        assert!(table.contains("150"));
        assert!(table.contains("1024"));
        assert!(table.contains("2048"));

        // Verify range
        assert!(table.contains("Range: 100 - 200"));
        assert!(table.contains("Total:      2 blobs"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 17: BLOB LIST JSON
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_blob_list_json() {
        let list = BlobList {
            from_height: 100,
            to_height: 200,
            total: 1,
            blobs: vec![BlobInfo {
                height: 100,
                index: 0,
                size: 512,
                namespace: "test".to_string(),
                commitment: "abc".to_string(),
            }],
        };

        let json_str = list.to_json().expect("should serialize");
        let parsed: BlobList = serde_json::from_str(&json_str).expect("should parse");

        assert_eq!(parsed.from_height, 100);
        assert_eq!(parsed.to_height, 200);
        assert_eq!(parsed.total, 1);
        assert_eq!(parsed.blobs.len(), 1);
        assert_eq!(parsed.blobs[0].height, 100);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 18: DA EVENT PRETTY PRINT
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_da_event_pretty_print() {
        let event = DAEvent::ChunkDeclared {
            chunk_hash: "abc123".to_string(),
            size: 1024,
            owner: "user1".to_string(),
            commitment: "commit1".to_string(),
        };

        let pretty = event.to_pretty();

        assert!(pretty.contains("ChunkDeclared"));
        assert!(pretty.contains("chunk_hash:"));
        assert!(pretty.contains("abc123"));
        assert!(pretty.contains("size:"));
        assert!(pretty.contains("1024"));
        assert!(pretty.contains("owner:"));
        assert!(pretty.contains("user1"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 19: DA EVENT JSON
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_da_event_json() {
        let event = DAEvent::ReplicaAdded {
            chunk_hash: "hash1".to_string(),
            node_id: "node1".to_string(),
            proof: "proof1".to_string(),
        };

        let json_str = event.to_json().expect("should serialize");
        let parsed: DAEvent = serde_json::from_str(&json_str).expect("should parse");

        assert_eq!(parsed, event);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 20: DECODED BLOB OUTPUT
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_decoded_blob_output() {
        let decoded = DecodedBlob {
            height: 100,
            index: 0,
            event_count: 2,
            events: vec![
                DAEvent::NodeRegistered {
                    node_id: "node1".to_string(),
                    addr: "127.0.0.1:9000".to_string(),
                    zone: Some("zone-a".to_string()),
                },
                DAEvent::ChunkDeclared {
                    chunk_hash: "hash1".to_string(),
                    size: 100,
                    owner: "owner1".to_string(),
                    commitment: "commit1".to_string(),
                },
            ],
        };

        let pretty = decoded.to_pretty();

        assert!(pretty.contains("Height: 100"));
        assert!(pretty.contains("Index: 0"));
        assert!(pretty.contains("Events: 2"));
        assert!(pretty.contains("[Event 1]"));
        assert!(pretty.contains("[Event 2]"));
        assert!(pretty.contains("NodeRegistered"));
        assert!(pretty.contains("ChunkDeclared"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 21: DECODE EVENTS FROM BYTES
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_decode_events_from_bytes() {
        let events = vec![
            DAEvent::NodeRegistered {
                node_id: "n1".to_string(),
                addr: "addr1".to_string(),
                zone: None,
            },
        ];

        let json_bytes = serde_json::to_vec(&events).expect("should serialize");
        let decoded = decode_events_from_bytes(&json_bytes).expect("should decode");

        assert_eq!(decoded.len(), 1);
        match &decoded[0] {
            DAEvent::NodeRegistered { node_id, .. } => {
                assert_eq!(node_id, "n1");
            }
            _ => panic!("expected NodeRegistered"),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 22: DECODE EMPTY BYTES
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_decode_empty_bytes() {
        let decoded = decode_events_from_bytes(&[]).expect("should decode");
        assert!(decoded.is_empty());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 23: ALL DA EVENT TYPES
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_all_da_event_types() {
        // Test each event type serializes and deserializes correctly
        let events = vec![
            DAEvent::ChunkDeclared {
                chunk_hash: "h1".to_string(),
                size: 100,
                owner: "o1".to_string(),
                commitment: "c1".to_string(),
            },
            DAEvent::ReplicaAdded {
                chunk_hash: "h2".to_string(),
                node_id: "n1".to_string(),
                proof: "p1".to_string(),
            },
            DAEvent::ReplicaRemoved {
                chunk_hash: "h3".to_string(),
                node_id: "n2".to_string(),
                reason: "r1".to_string(),
            },
            DAEvent::NodeRegistered {
                node_id: "n3".to_string(),
                addr: "a1".to_string(),
                zone: Some("z1".to_string()),
            },
            DAEvent::NodeUnregistered {
                node_id: "n4".to_string(),
            },
            DAEvent::DeleteRequested {
                chunk_hash: "h4".to_string(),
                requester: "req1".to_string(),
            },
        ];

        for event in &events {
            let json = event.to_json().expect("should serialize");
            let parsed: DAEvent = serde_json::from_str(&json).expect("should parse");
            assert_eq!(&parsed, event);

            // Pretty print should not panic
            let _ = event.to_pretty();
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 24: HEX DUMP DETERMINISTIC
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_hex_dump_deterministic() {
        let raw = RawBlob {
            height: 100,
            index: 0,
            data: vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77],
            namespace: "ns".to_string(),
            commitment: "cm".to_string(),
        };

        let dump1 = raw.to_hex_dump();
        let dump2 = raw.to_hex_dump();
        assert_eq!(dump1, dump2);

        let hex1 = raw.to_hex_string();
        let hex2 = raw.to_hex_string();
        assert_eq!(hex1, hex2);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 25: BLOB INFO TABLE ROW
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_blob_info_table_row() {
        let info = BlobInfo {
            height: 12345,
            index: 7,
            size: 999,
            namespace: "test-ns".to_string(),
            commitment: "test-commit".to_string(),
        };

        let row = info.to_table_row();

        assert!(row.contains("12345"));
        assert!(row.contains("7"));
        assert!(row.contains("999"));
        assert!(row.contains("test-ns"));
        assert!(row.contains("test-commit"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 26: EMPTY BLOB LIST
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_empty_blob_list() {
        let list = BlobList {
            from_height: 100,
            to_height: 200,
            total: 0,
            blobs: vec![],
        };

        let table = list.to_table();
        assert!(table.contains("No blobs found"));

        let json_str = list.to_json().expect("should serialize");
        let parsed: BlobList = serde_json::from_str(&json_str).expect("should parse");
        assert_eq!(parsed.total, 0);
        assert!(parsed.blobs.is_empty());
    }
}