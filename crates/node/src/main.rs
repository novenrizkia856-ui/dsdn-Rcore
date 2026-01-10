//! # DSDN Node Entry Point (14A)
//!
//! Production entry point for DSDN storage node.
//!
//! ## Key Invariant
//! Node TIDAK menerima instruksi dari Coordinator via RPC.
//! Semua perintah datang via DA events.
//!
//! ## Initialization Flow
//! 1. Parse CLI arguments
//! 2. Load configuration
//! 3. Initialize DA layer
//! 4. Initialize storage
//! 5. Initialize DA follower
//! 6. Start follower
//! 7. Start HTTP server (health endpoint)

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use parking_lot::RwLock;
use tokio::sync::Notify;
use tracing::{error, info, warn, Level};
use uuid::Uuid;

use dsdn_common::{CelestiaDA, DAConfig, DALayer, MockDA};
use dsdn_node::{
    DAInfo, HealthResponse, HealthStorage, NodeDerivedState, NodeHealth,
};

// ════════════════════════════════════════════════════════════════════════════
// CLI CONFIGURATION
// ════════════════════════════════════════════════════════════════════════════

/// Node configuration parsed from CLI arguments.
#[derive(Debug, Clone)]
struct NodeConfig {
    /// Unique node identifier.
    node_id: String,
    /// DA endpoint URL.
    da_endpoint: String,
    /// Storage directory path.
    storage_path: String,
    /// HTTP port for health endpoint.
    http_port: u16,
    /// Whether to use mock DA for testing.
    use_mock_da: bool,
}

impl NodeConfig {
    /// Parse configuration from CLI arguments.
    ///
    /// Usage: dsdn-node <node-id|auto> <da-endpoint|mock> <storage-path> <http-port>
    fn from_args() -> Result<Self, String> {
        let args: Vec<String> = env::args().collect();

        if args.len() < 5 {
            return Err(format!(
                "Usage: {} <node-id|auto> <da-endpoint|mock> <storage-path> <http-port>\n\
                 Example: {} auto http://localhost:26658 ./data/node1 8080\n\
                 Example: {} node-1 mock ./data/node1 8080",
                args[0], args[0], args[0]
            ));
        }

        // Parse node_id
        let node_id = if args[1] == "auto" {
            Uuid::new_v4().to_string()
        } else {
            args[1].clone()
        };

        // Parse DA endpoint
        let da_endpoint = args[2].clone();
        let use_mock_da = da_endpoint == "mock";

        // Parse storage path
        let storage_path = args[3].clone();

        // Parse HTTP port
        let http_port: u16 = args[4]
            .parse()
            .map_err(|_| format!("Invalid HTTP port: {}", args[4]))?;

        Ok(Self {
            node_id,
            da_endpoint,
            storage_path,
            http_port,
            use_mock_da,
        })
    }

    /// Validate configuration.
    fn validate(&self) -> Result<(), String> {
        // Validate node_id
        if self.node_id.is_empty() {
            return Err("Node ID cannot be empty".to_string());
        }

        // Validate storage path (basic check)
        if self.storage_path.is_empty() {
            return Err("Storage path cannot be empty".to_string());
        }

        // Validate port range
        if self.http_port == 0 {
            return Err("HTTP port cannot be 0".to_string());
        }

        Ok(())
    }
}

// ════════════════════════════════════════════════════════════════════════════
// NODE STORAGE IMPLEMENTATION
// ════════════════════════════════════════════════════════════════════════════

/// Simple in-memory storage implementation for health reporting.
struct NodeStorage {
    /// Storage directory path.
    #[allow(dead_code)]
    path: String,
    /// Simulated used bytes.
    used_bytes: RwLock<u64>,
    /// Simulated capacity bytes (100 GB default).
    capacity_bytes: u64,
}

impl NodeStorage {
    fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
            used_bytes: RwLock::new(0),
            capacity_bytes: 100 * 1024 * 1024 * 1024, // 100 GB
        }
    }

    #[allow(dead_code)]
    fn add_used(&self, bytes: u64) {
        let mut used = self.used_bytes.write();
        *used = used.saturating_add(bytes);
    }
}

impl HealthStorage for NodeStorage {
    fn storage_used_bytes(&self) -> u64 {
        *self.used_bytes.read()
    }

    fn storage_capacity_bytes(&self) -> u64 {
        self.capacity_bytes
    }
}

// ════════════════════════════════════════════════════════════════════════════
// DA INFO WRAPPER
// ════════════════════════════════════════════════════════════════════════════

/// Wrapper for DA layer to implement DAInfo trait.
struct DAInfoWrapper {
    /// DA layer reference.
    #[allow(dead_code)]
    da: Arc<dyn DALayer>,
    /// Latest sequence (updated by follower).
    latest_sequence: RwLock<u64>,
    /// Connection status.
    connected: RwLock<bool>,
}

impl DAInfoWrapper {
    fn new(da: Arc<dyn DALayer>) -> Self {
        Self {
            da,
            latest_sequence: RwLock::new(0),
            connected: RwLock::new(true),
        }
    }

    fn update_sequence(&self, seq: u64) {
        let mut latest = self.latest_sequence.write();
        if seq > *latest {
            *latest = seq;
        }
    }

    fn set_connected(&self, connected: bool) {
        *self.connected.write() = connected;
    }
}

impl DAInfo for DAInfoWrapper {
    fn is_connected(&self) -> bool {
        *self.connected.read()
    }

    fn latest_sequence(&self) -> u64 {
        *self.latest_sequence.read()
    }
}

// ════════════════════════════════════════════════════════════════════════════
// HTTP SERVER (HEALTH ENDPOINT)
// ════════════════════════════════════════════════════════════════════════════

/// Start a minimal HTTP server for health endpoint.
async fn start_http_server(
    addr: SocketAddr,
    node_id: String,
    da_info: Arc<DAInfoWrapper>,
    state: Arc<RwLock<NodeDerivedState>>,
    storage: Arc<NodeStorage>,
    shutdown: Arc<Notify>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind HTTP server to {}: {}", addr, e);
            return;
        }
    };

    info!("🏥 Health endpoint available at http://{}/health", addr);

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((mut socket, _)) => {
                        let node_id = node_id.clone();
                        let da_info = da_info.clone();
                        let state = state.clone();
                        let storage = storage.clone();

                        tokio::spawn(async move {
                            let mut buf = [0u8; 1024];
                            if socket.read(&mut buf).await.is_err() {
                                return;
                            }

                            let request = String::from_utf8_lossy(&buf);

                            // Simple HTTP request parsing
                            let response = if request.contains("GET /health") {
                                let state_guard = state.read();
                                let health = NodeHealth::check(
                                    &node_id,
                                    da_info.as_ref(),
                                    &state_guard,
                                    storage.as_ref(),
                                );
                                drop(state_guard);

                                let hr = HealthResponse::from_health(&health);
                                format!(
                                    "HTTP/1.1 {} OK\r\n\
                                     Content-Type: {}\r\n\
                                     Content-Length: {}\r\n\
                                     Connection: close\r\n\
                                     \r\n\
                                     {}",
                                    hr.status_code,
                                    hr.content_type,
                                    hr.body.len(),
                                    hr.body
                                )
                            } else if request.contains("GET /") {
                                let body = r#"{"status":"ok","endpoints":["/health"]}"#;
                                format!(
                                    "HTTP/1.1 200 OK\r\n\
                                     Content-Type: application/json\r\n\
                                     Content-Length: {}\r\n\
                                     Connection: close\r\n\
                                     \r\n\
                                     {}",
                                    body.len(),
                                    body
                                )
                            } else {
                                "HTTP/1.1 404 Not Found\r\n\
                                 Content-Length: 0\r\n\
                                 Connection: close\r\n\
                                 \r\n"
                                    .to_string()
                            };

                            let _ = socket.write_all(response.as_bytes()).await;
                        });
                    }
                    Err(e) => {
                        warn!("Failed to accept connection: {}", e);
                    }
                }
            }
            _ = shutdown.notified() => {
                info!("HTTP server shutting down");
                break;
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// MAIN ENTRY POINT
// ════════════════════════════════════════════════════════════════════════════

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_target(false)
        .init();

    // Parse CLI arguments
    let config = match NodeConfig::from_args() {
        Ok(c) => c,
        Err(e) => {
            error!("{}", e);
            std::process::exit(1);
        }
    };

    // Validate configuration
    if let Err(e) = config.validate() {
        error!("Configuration error: {}", e);
        std::process::exit(1);
    }

    info!("═══════════════════════════════════════════════════════════════");
    info!("                    DSDN Node (14A)                            ");
    info!("═══════════════════════════════════════════════════════════════");
    info!("Node ID:      {}", config.node_id);
    info!("DA Endpoint:  {}", config.da_endpoint);
    info!("Storage Path: {}", config.storage_path);
    info!("HTTP Port:    {}", config.http_port);
    info!("═══════════════════════════════════════════════════════════════");

    // Step 1: Initialize DA layer
    let da: Arc<dyn DALayer> = if config.use_mock_da {
        info!("Using MockDA for testing");
        Arc::new(MockDA::new())
    } else {
        info!("Connecting to Celestia DA at {}", config.da_endpoint);
        let mut da_config = DAConfig::default();
        da_config.rpc_url = config.da_endpoint.clone();
        match CelestiaDA::new(da_config) {
            Ok(da) => Arc::new(da),
            Err(e) => {
                error!("Failed to connect to DA: {}", e);
                std::process::exit(1);
            }
        }
    };

    // Step 2: Initialize storage
    info!("Initializing storage at {}", config.storage_path);
    let storage = Arc::new(NodeStorage::new(&config.storage_path));

    // Create storage directory if needed
    if let Err(e) = std::fs::create_dir_all(&config.storage_path) {
        error!("Failed to create storage directory: {}", e);
        std::process::exit(1);
    }

    // Step 3: Initialize node state
    let state = Arc::new(RwLock::new(NodeDerivedState::new()));

    // Step 4: Initialize DA info wrapper
    let da_info = Arc::new(DAInfoWrapper::new(da.clone()));

    // Step 5: Setup shutdown signal
    let shutdown = Arc::new(Notify::new());

    // Step 6: Start HTTP server for health endpoint
    let http_addr: SocketAddr = format!("0.0.0.0:{}", config.http_port)
        .parse()
        .expect("Invalid HTTP address");

    let http_handle = {
        let node_id = config.node_id.clone();
        let da_info = da_info.clone();
        let state = state.clone();
        let storage = storage.clone();
        let shutdown = shutdown.clone();

        tokio::spawn(async move {
            start_http_server(http_addr, node_id, da_info, state, storage, shutdown).await;
        })
    };

    // Step 7: Start DA follower
    info!("🚀 Starting DA follower...");
    info!("");
    info!("╔═══════════════════════════════════════════════════════════════╗");
    info!("║  INVARIANT: Node receives ALL commands via DA events ONLY    ║");
    info!("║  Node does NOT accept instructions from Coordinator via RPC  ║");
    info!("╚═══════════════════════════════════════════════════════════════╝");
    info!("");

    // DA follower loop (simplified - in production this would use DAFollower)
    let follower_handle = {
        let da = da.clone();
        let da_info = da_info.clone();
        let state = state.clone();
        let shutdown = shutdown.clone();
        let node_id = config.node_id.clone();

        tokio::spawn(async move {
            let _namespace = [0x01; 29]; // Default namespace

            info!("DA follower started for node {}", node_id);

            // Get initial health check
            let check_interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
            tokio::pin!(check_interval);

            loop {
                tokio::select! {
                    _ = shutdown.notified() => {
                        info!("DA follower shutting down");
                        break;
                    }
                    _ = check_interval.tick() => {
                        // Periodic health status log
                        let health_result = da.health_check().await;
                        match health_result {
                            Ok(dsdn_common::DAHealthStatus::Healthy) => {
                                da_info.set_connected(true);
                                info!("DA health: Healthy");
                            }
                            Ok(dsdn_common::DAHealthStatus::Degraded) => {
                                da_info.set_connected(true);
                                warn!("DA health: Degraded");
                            }
                            Ok(dsdn_common::DAHealthStatus::Unavailable) => {
                                da_info.set_connected(false);
                                error!("DA health: Unavailable");
                            }
                            Err(e) => {
                                da_info.set_connected(false);
                                error!("DA health check error: {}", e);
                            }
                        }

                        // Update sequence from state
                        let state_guard = state.read();
                        da_info.update_sequence(state_guard.last_sequence);
                        drop(state_guard);
                    }
                }
            }
        })
    };

    // Wait for shutdown signal (Ctrl+C)
    info!("Node running. Press Ctrl+C to shutdown.");
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to listen for Ctrl+C");

    info!("");
    info!("Shutdown requested...");
    shutdown.notify_waiters();

    // Wait for tasks to complete
    let _ = http_handle.await;
    let _ = follower_handle.await;

    info!("═══════════════════════════════════════════════════════════════");
    info!("                    Node stopped cleanly                       ");
    info!("═══════════════════════════════════════════════════════════════");
}

// ════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation_empty_node_id() {
        let config = NodeConfig {
            node_id: String::new(),
            da_endpoint: "mock".to_string(),
            storage_path: "./data".to_string(),
            http_port: 8080,
            use_mock_da: true,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_empty_storage_path() {
        let config = NodeConfig {
            node_id: "node-1".to_string(),
            da_endpoint: "mock".to_string(),
            storage_path: String::new(),
            http_port: 8080,
            use_mock_da: true,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_zero_port() {
        let config = NodeConfig {
            node_id: "node-1".to_string(),
            da_endpoint: "mock".to_string(),
            storage_path: "./data".to_string(),
            http_port: 0,
            use_mock_da: true,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_valid() {
        let config = NodeConfig {
            node_id: "node-1".to_string(),
            da_endpoint: "mock".to_string(),
            storage_path: "./data".to_string(),
            http_port: 8080,
            use_mock_da: true,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_node_storage_health() {
        let storage = NodeStorage::new("./test");
        assert_eq!(storage.storage_used_bytes(), 0);
        assert!(storage.storage_capacity_bytes() > 0);
    }

    #[test]
    fn test_da_info_wrapper() {
        let da: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let wrapper = DAInfoWrapper::new(da);

        assert!(wrapper.is_connected());
        assert_eq!(wrapper.latest_sequence(), 0);

        wrapper.update_sequence(100);
        assert_eq!(wrapper.latest_sequence(), 100);

        wrapper.set_connected(false);
        assert!(!wrapper.is_connected());
    }
}