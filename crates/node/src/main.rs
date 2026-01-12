//! # DSDN Node Entry Point (Mainnet Ready)
//!
//! Production entry point for DSDN storage node.
//!
//! ## Key Invariant
//! Node TIDAK menerima instruksi dari Coordinator via RPC.
//! Semua perintah datang via DA events.
//!
//! ## Configuration Modes
//!
//! ### Mode 1: CLI Arguments (Development)
//! ```
//! dsdn-node <node-id|auto> <da-endpoint|mock> <storage-path> <http-port>
//! ```
//!
//! ### Mode 2: Environment Variables (Production)
//! ```
//! dsdn-node env
//! ```
//!
//! Required environment variables for env mode:
//! - `NODE_ID`: Unique node identifier (or "auto" for UUID)
//! - `NODE_STORAGE_PATH`: Storage directory path
//! - `NODE_HTTP_PORT`: HTTP server port
//! - `DA_RPC_URL`: Celestia light node RPC endpoint
//! - `DA_NAMESPACE`: 58-character hex namespace
//! - `DA_AUTH_TOKEN`: Authentication token (required for mainnet)
//!
//! Optional:
//! - `DA_NETWORK`: Network identifier (mainnet, mocha, local)
//! - `DA_TIMEOUT_MS`: Operation timeout in milliseconds
//! - `USE_MOCK_DA`: Use mock DA for development
//!
//! ## Initialization Flow
//! 1. Parse configuration (CLI or env)
//! 2. Validate configuration
//! 3. Initialize DA layer with startup health check
//! 4. Initialize storage
//! 5. Initialize DA follower
//! 6. Start follower
//! 7. Start HTTP server (health endpoint)

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use tokio::sync::Notify;
use tracing::{error, info, warn, Level};
use uuid::Uuid;

use dsdn_common::{CelestiaDA, DAConfig, DAError, DAHealthStatus, DALayer, MockDA};
use dsdn_node::{
    DAInfo, HealthResponse, HealthStorage, NodeDerivedState, NodeHealth,
};

// ════════════════════════════════════════════════════════════════════════════
// CLI CONFIGURATION
// ════════════════════════════════════════════════════════════════════════════

/// Node configuration parsed from CLI arguments or environment.
#[derive(Debug, Clone)]
struct NodeConfig {
    /// Unique node identifier.
    node_id: String,
    /// DA configuration.
    da_config: DAConfig,
    /// Storage directory path.
    storage_path: String,
    /// HTTP port for health endpoint.
    http_port: u16,
    /// Whether to use mock DA for testing.
    use_mock_da: bool,
    /// Configuration source (cli or env).
    config_source: String,
}

impl NodeConfig {
    /// Parse configuration from CLI arguments.
    ///
    /// Usage: dsdn-node <node-id|auto> <da-endpoint|mock> <storage-path> <http-port>
    ///    OR: dsdn-node env
    fn from_args() -> Result<Self, String> {
        let args: Vec<String> = env::args().collect();

        if args.len() < 2 {
            return Err(Self::usage_message(&args[0]));
        }

        // Check for "env" mode
        if args[1] == "env" {
            return Self::from_env();
        }

        // CLI mode requires exactly 5 arguments
        if args.len() < 5 {
            return Err(Self::usage_message(&args[0]));
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

        // Build DA config for CLI mode
        let da_config = if use_mock_da {
            DAConfig::default()
        } else {
            DAConfig {
                rpc_url: da_endpoint,
                namespace: [0u8; 29], // Default namespace for CLI mode
                auth_token: None,
                timeout_ms: 30000,
                retry_count: 3,
                retry_delay_ms: 1000,
                network: "local".to_string(),
                enable_pooling: true,
                max_connections: 10,
                idle_timeout_ms: 60000,
            }
        };

        // Parse storage path
        let storage_path = args[3].clone();

        // Parse HTTP port
        let http_port: u16 = args[4]
            .parse()
            .map_err(|_| format!("Invalid HTTP port: {}", args[4]))?;

        Ok(Self {
            node_id,
            da_config,
            storage_path,
            http_port,
            use_mock_da,
            config_source: "cli".to_string(),
        })
    }

    /// Parse configuration from environment variables.
    fn from_env() -> Result<Self, String> {
        // Check if using mock DA
        let use_mock_da = env::var("USE_MOCK_DA")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false);

        // Load DA config
        let da_config = if use_mock_da {
            DAConfig::default()
        } else {
            DAConfig::from_env().map_err(|e| format!("DA config error: {}", e))?
        };

        // Required: NODE_ID
        let node_id_raw = env::var("NODE_ID")
            .map_err(|_| "NODE_ID environment variable not set")?;
        let node_id = if node_id_raw == "auto" {
            Uuid::new_v4().to_string()
        } else {
            node_id_raw
        };

        // Required: NODE_STORAGE_PATH
        let storage_path = env::var("NODE_STORAGE_PATH")
            .map_err(|_| "NODE_STORAGE_PATH environment variable not set")?;

        // Required: NODE_HTTP_PORT
        let http_port: u16 = env::var("NODE_HTTP_PORT")
            .map_err(|_| "NODE_HTTP_PORT environment variable not set")?
            .parse()
            .map_err(|_| "NODE_HTTP_PORT must be a valid port number")?;

        Ok(Self {
            node_id,
            da_config,
            storage_path,
            http_port,
            use_mock_da,
            config_source: "env".to_string(),
        })
    }

    /// Generate usage message.
    fn usage_message(prog: &str) -> String {
        format!(
            "Usage:\n\
             \n\
             Mode 1 - CLI Arguments (Development):\n\
             {} <node-id|auto> <da-endpoint|mock> <storage-path> <http-port>\n\
             \n\
             Example:\n\
             {} auto http://localhost:26658 ./data/node1 8080\n\
             {} node-1 mock ./data/node1 8080\n\
             \n\
             Mode 2 - Environment Variables (Production):\n\
             {} env\n\
             \n\
             Required environment variables for env mode:\n\
             NODE_ID           - Unique node identifier (or 'auto')\n\
             NODE_STORAGE_PATH - Storage directory path\n\
             NODE_HTTP_PORT    - HTTP server port\n\
             DA_RPC_URL        - Celestia light node RPC endpoint\n\
             DA_NAMESPACE      - 58-character hex namespace\n\
             DA_AUTH_TOKEN     - Authentication token (required for mainnet)\n\
             \n\
             Optional:\n\
             DA_NETWORK        - Network identifier (mainnet, mocha, local)\n\
             USE_MOCK_DA       - Use mock DA for development",
            prog, prog, prog, prog
        )
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

        // Validate for production if mainnet
        if self.da_config.is_mainnet() {
            self.da_config
                .validate_for_production()
                .map_err(|e| format!("Production validation failed: {}", e))?;
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
// DA STARTUP HEALTH CHECK
// ════════════════════════════════════════════════════════════════════════════

/// Perform startup DA health check with retries.
async fn startup_da_health_check(da: &dyn DALayer) -> Result<(), DAError> {
    let max_attempts = 3;
    let retry_delay = Duration::from_secs(2);

    for attempt in 1..=max_attempts {
        info!("🔍 DA health check (attempt {}/{})", attempt, max_attempts);

        match da.health_check().await {
            Ok(DAHealthStatus::Healthy) => {
                info!("✅ DA layer healthy");
                return Ok(());
            }
            Ok(DAHealthStatus::Degraded) => {
                warn!("⚠️ DA layer degraded but operational");
                return Ok(());
            }
            Ok(DAHealthStatus::Unavailable) => {
                if attempt < max_attempts {
                    warn!("DA unavailable, retrying in {} seconds...", retry_delay.as_secs());
                    tokio::time::sleep(retry_delay).await;
                } else {
                    return Err(DAError::Unavailable);
                }
            }
            Err(e) => {
                if attempt < max_attempts {
                    warn!("DA health check error: {}, retrying...", e);
                    tokio::time::sleep(retry_delay).await;
                } else {
                    return Err(e);
                }
            }
        }
    }

    Err(DAError::Unavailable)
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
                                // Build health response
                                let state_guard = state.read();
                                let health = NodeHealth::check(
                                    &node_id,
                                    da_info.as_ref(),
                                    &state_guard,
                                    storage.as_ref(),
                                );
                                let health_response = HealthResponse::from_health(&health);
                                let json = health_response.body;

                                let status_line = if health_response.status_code == 200 {
                                    "HTTP/1.1 200 OK"
                                } else {
                                    "HTTP/1.1 503 Service Unavailable"
                                };

                                format!(
                                    "{}\r\n\
                                     Content-Type: application/json\r\n\
                                     Content-Length: {}\r\n\
                                     Connection: close\r\n\
                                     \r\n\
                                     {}",
                                    status_line,
                                    json.len(),
                                    json
                                )
                            } else if request.contains("GET /ready") {
                                // Readiness check
                                if da_info.is_connected() {
                                    "HTTP/1.1 200 OK\r\n\
                                     Content-Type: text/plain\r\n\
                                     Content-Length: 2\r\n\
                                     Connection: close\r\n\
                                     \r\n\
                                     OK".to_string()
                                } else {
                                    "HTTP/1.1 503 Service Unavailable\r\n\
                                     Content-Type: text/plain\r\n\
                                     Content-Length: 11\r\n\
                                     Connection: close\r\n\
                                     \r\n\
                                     Unavailable".to_string()
                                }
                            } else {
                                "HTTP/1.1 404 Not Found\r\n\
                                 Content-Type: text/plain\r\n\
                                 Content-Length: 9\r\n\
                                 Connection: close\r\n\
                                 \r\n\
                                 Not Found".to_string()
                            };

                            let _ = socket.write_all(response.as_bytes()).await;
                        });
                    }
                    Err(e) => {
                        warn!("Accept error: {}", e);
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
    info!("               DSDN Node (Mainnet Ready)                        ");
    info!("═══════════════════════════════════════════════════════════════");
    info!("Node ID:      {}", config.node_id);
    info!("Config Mode:  {}", config.config_source);
    info!("DA Network:   {}", config.da_config.network);
    info!("DA Endpoint:  {}", config.da_config.rpc_url);
    info!("Storage Path: {}", config.storage_path);
    info!("HTTP Port:    {}", config.http_port);
    info!("═══════════════════════════════════════════════════════════════");

    // Step 1: Initialize DA layer
    let da: Arc<dyn DALayer> = if config.use_mock_da {
        info!("Using MockDA for testing");
        Arc::new(MockDA::new())
    } else {
        info!("Connecting to Celestia DA...");
        match CelestiaDA::new(config.da_config.clone()) {
            Ok(da) => Arc::new(da),
            Err(e) => {
                error!("❌ Failed to connect to DA: {}", e);
                error!("");
                error!("Troubleshooting:");
                error!("  1. Ensure Celestia light node is running");
                error!("  2. Verify DA_RPC_URL is correct");
                error!("  3. Check DA_AUTH_TOKEN is valid");
                error!("  4. Verify network connectivity");
                std::process::exit(1);
            }
        }
    };

    // Step 2: Startup DA health check
    if let Err(e) = startup_da_health_check(da.as_ref()).await {
        error!("❌ DA health check failed: {}", e);
        if config.da_config.is_mainnet() {
            error!("Cannot start node on mainnet without healthy DA connection");
            std::process::exit(1);
        } else {
            warn!("⚠️ Continuing in degraded mode (DA unhealthy)");
        }
    }

    // Step 3: Initialize storage
    info!("Initializing storage at {}", config.storage_path);
    let storage = Arc::new(NodeStorage::new(&config.storage_path));

    // Create storage directory if needed
    if let Err(e) = std::fs::create_dir_all(&config.storage_path) {
        error!("Failed to create storage directory: {}", e);
        std::process::exit(1);
    }

    // Step 4: Initialize node state
    let state = Arc::new(RwLock::new(NodeDerivedState::new()));

    // Step 5: Initialize DA info wrapper
    let da_info = Arc::new(DAInfoWrapper::new(da.clone()));

    // Step 6: Setup shutdown signal
    let shutdown = Arc::new(Notify::new());

    // Step 7: Start HTTP server for health endpoint
    let http_addr: SocketAddr = format!("0.0.0.0:{}", config.http_port)
        .parse()
        .unwrap_or_else(|_| {
            error!("Invalid HTTP address");
            std::process::exit(1);
        });

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

    // Step 8: Start DA follower
    info!("🚀 Starting DA follower...");
    info!("");
    info!("╔═══════════════════════════════════════════════════════════════╗");
    info!("║  INVARIANT: Node receives ALL commands via DA events ONLY    ║");
    info!("║  Node does NOT accept instructions from Coordinator via RPC  ║");
    info!("╚═══════════════════════════════════════════════════════════════╝");
    info!("");

    // DA follower loop with reconnection logic
    let follower_handle = {
        let da = da.clone();
        let da_info = da_info.clone();
        let state = state.clone();
        let shutdown = shutdown.clone();
        let node_id = config.node_id.clone();

        tokio::spawn(async move {
            let reconnect_delay = Duration::from_secs(5);
            let health_check_interval = Duration::from_secs(30);

            info!("DA follower started for node {}", node_id);

            let mut last_health_check = std::time::Instant::now();

            loop {
                tokio::select! {
                    _ = shutdown.notified() => {
                        info!("DA follower shutting down");
                        break;
                    }
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {
                        // Periodic health check
                        if last_health_check.elapsed() >= health_check_interval {
                            last_health_check = std::time::Instant::now();

                            match da.health_check().await {
                                Ok(DAHealthStatus::Healthy) => {
                                    if !da_info.is_connected() {
                                        info!("✅ DA connection restored");
                                    }
                                    da_info.set_connected(true);
                                }
                                Ok(DAHealthStatus::Degraded) => {
                                    da_info.set_connected(true);
                                    warn!("⚠️ DA health: Degraded");
                                }
                                Ok(DAHealthStatus::Unavailable) => {
                                    if da_info.is_connected() {
                                        error!("❌ DA connection lost, will retry...");
                                    }
                                    da_info.set_connected(false);

                                    // Wait before reconnect attempt
                                    tokio::time::sleep(reconnect_delay).await;
                                }
                                Err(e) => {
                                    if da_info.is_connected() {
                                        error!("❌ DA health check error: {}", e);
                                    }
                                    da_info.set_connected(false);
                                }
                            }

                            // Update sequence from state
                            let state_guard = state.read();
                            da_info.update_sequence(state_guard.last_sequence);
                        }
                    }
                }
            }
        })
    };

    // Wait for shutdown signal (Ctrl+C)
    info!("Node running. Press Ctrl+C to shutdown.");
    match tokio::signal::ctrl_c().await {
        Ok(()) => {
            info!("");
            info!("Shutdown requested...");
        }
        Err(e) => {
            error!("Failed to listen for Ctrl+C: {}", e);
        }
    }

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
            da_config: DAConfig::default(),
            storage_path: "./data".to_string(),
            http_port: 8080,
            use_mock_da: true,
            config_source: "test".to_string(),
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_empty_storage_path() {
        let config = NodeConfig {
            node_id: "node-1".to_string(),
            da_config: DAConfig::default(),
            storage_path: String::new(),
            http_port: 8080,
            use_mock_da: true,
            config_source: "test".to_string(),
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_zero_port() {
        let config = NodeConfig {
            node_id: "node-1".to_string(),
            da_config: DAConfig::default(),
            storage_path: "./data".to_string(),
            http_port: 0,
            use_mock_da: true,
            config_source: "test".to_string(),
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_valid() {
        let config = NodeConfig {
            node_id: "node-1".to_string(),
            da_config: DAConfig::default(),
            storage_path: "./data".to_string(),
            http_port: 8080,
            use_mock_da: true,
            config_source: "test".to_string(),
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

    #[test]
    fn test_config_from_env() {
        std::env::set_var("USE_MOCK_DA", "true");
        std::env::set_var("NODE_ID", "test-node");
        std::env::set_var("NODE_STORAGE_PATH", "./test-data");
        std::env::set_var("NODE_HTTP_PORT", "9090");

        let config = NodeConfig::from_env().unwrap();
        
        assert_eq!(config.node_id, "test-node");
        assert_eq!(config.storage_path, "./test-data");
        assert_eq!(config.http_port, 9090);
        assert!(config.use_mock_da);
        assert_eq!(config.config_source, "env");

        // Cleanup
        std::env::remove_var("USE_MOCK_DA");
        std::env::remove_var("NODE_ID");
        std::env::remove_var("NODE_STORAGE_PATH");
        std::env::remove_var("NODE_HTTP_PORT");
    }

    #[test]
    fn test_config_auto_node_id() {
        std::env::set_var("USE_MOCK_DA", "true");
        std::env::set_var("NODE_ID", "auto");
        std::env::set_var("NODE_STORAGE_PATH", "./test-data");
        std::env::set_var("NODE_HTTP_PORT", "9090");

        let config = NodeConfig::from_env().unwrap();
        
        // Should be a UUID
        assert!(config.node_id.len() >= 32);
        assert_ne!(config.node_id, "auto");

        // Cleanup
        std::env::remove_var("USE_MOCK_DA");
        std::env::remove_var("NODE_ID");
        std::env::remove_var("NODE_STORAGE_PATH");
        std::env::remove_var("NODE_HTTP_PORT");
    }
}