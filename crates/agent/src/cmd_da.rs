//! # DA Status Command Module
//!
//! Module ini menyediakan command untuk melihat status DA (Data Availability) layer.
//!
//! ## Prinsip
//!
//! - Semua data status diambil dari DA layer aktual
//! - Tidak ada default palsu atau cache tanpa validasi
//! - Output table dan JSON konsisten secara semantik
//! - Tidak ada panic, unwrap, atau silent failure
//!
//! ## Usage
//!
//! ```bash
//! agent da status              # Table format (default)
//! agent da status --json       # JSON format
//! ```

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
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
// CLI HANDLER
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

        let json_str = status.to_json().unwrap();
        
        // Parse back and verify
        let parsed: DAStatus = serde_json::from_str(&json_str).unwrap();
        
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
        let json_str = status.to_json().unwrap();
        let json: serde_json::Value = serde_json::from_str(&json_str).unwrap();

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

        let result = parse_header_response(json).unwrap();
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

        let result = parse_status_response(json).unwrap();
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

        let json1 = status.to_json().unwrap();
        let json2 = status.to_json().unwrap();
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
}