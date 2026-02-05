//! # DSDN Node Entry Point (Mainnet Ready)
//!
//! Production entry point for DSDN storage node.
//!
//! ## Key Invariant
//! Node TIDAK menerima instruksi dari Coordinator via RPC.
//! Semua perintah datang via DA events.
//!
//! ## Environment File Loading
//!
//! The node automatically loads configuration from environment files
//! (same pattern as coordinator):
//!
//! 1. `DSDN_ENV_FILE` environment variable (custom path)
//! 2. `.env.mainnet` (production default - **DSDN defaults to mainnet**)
//! 3. `.env` (fallback for development)
//!
//! ## CLI Subcommands
//!
//! ### `dsdn-node run [env | <node-id> <da-endpoint> <storage-path> <http-port>]`
//! Start the node. Default mode is `env` (reads from .env.mainnet).
//!
//! ### `dsdn-node status [--port PORT]`
//! Query a running node's status via HTTP.
//!
//! ### `dsdn-node health [--port PORT]`
//! Query a running node's health endpoint via HTTP.
//!
//! ### `dsdn-node info`
//! Display node build and configuration info.
//!
//! ### `dsdn-node version`
//! Display version string.
//!
//! ## Initialization Flow (run)
//! 1. Load .env.mainnet (or custom env file)
//! 2. Parse configuration (CLI or env)
//! 3. Validate configuration
//! 4. Initialize DA layer with startup health check
//! 5. Initialize storage
//! 6. Initialize DA follower
//! 7. Start follower
//! 8. Start HTTP server (Axum - observability endpoints)

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use parking_lot::RwLock;
use tokio::sync::Notify;
use tracing::{error, info, warn, Level};
use uuid::Uuid;

use dsdn_common::{CelestiaDA, DAConfig, DAError, DAHealthStatus, DALayer, MockDA};
use dsdn_node::{
    DAInfo, HealthResponse, HealthStorage, NodeDerivedState, NodeHealth,
    NodeAppState, build_router,
};

// ════════════════════════════════════════════════════════════════════════════
// VERSION & BUILD INFO
// ════════════════════════════════════════════════════════════════════════════

const NODE_VERSION: &str = env!("CARGO_PKG_VERSION");
const NODE_NAME: &str = "dsdn-node";

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
    /// Parse configuration from CLI arguments for `run` subcommand.
    ///
    /// Usage: dsdn-node run <node-id|auto> <da-endpoint|mock> <storage-path> <http-port>
    ///    OR: dsdn-node run env   (default if no args after `run`)
    ///    OR: dsdn-node run       (defaults to env mode)
    fn from_run_args(args: &[String]) -> Result<Self, String> {
        // No extra args or "env" → env mode
        if args.is_empty() || (args.len() == 1 && args[0] == "env") {
            return Self::from_env();
        }

        // CLI mode requires exactly 4 arguments after `run`
        if args.len() < 4 {
            return Err(
                "CLI mode requires: dsdn-node run <node-id|auto> <da-endpoint|mock> <storage-path> <http-port>".to_string()
            );
        }

        // Parse node_id
        let node_id = if args[0] == "auto" {
            Uuid::new_v4().to_string()
        } else {
            args[0].clone()
        };

        // Parse DA endpoint
        let da_endpoint = args[1].clone();
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
        let storage_path = args[2].clone();

        // Parse HTTP port
        let http_port: u16 = args[3]
            .parse()
            .map_err(|_| format!("Invalid HTTP port: {}", args[3]))?;

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
        // Set default DA_NETWORK to mainnet if not specified
        // DSDN defaults to mainnet (same as coordinator)
        if env::var("DA_NETWORK").is_err() {
            env::set_var("DA_NETWORK", "mainnet");
        }

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
// ENV FILE LOADING (same pattern as coordinator)
// ════════════════════════════════════════════════════════════════════════════

/// Load environment variables from .env.mainnet or custom env file.
///
/// Priority order:
/// 1. `DSDN_ENV_FILE` environment variable (custom path)
/// 2. `.env.mainnet` (production default - DSDN defaults to mainnet)
/// 3. `.env` (fallback for development)
fn load_env_file() {
    let env_file = env::var("DSDN_ENV_FILE").unwrap_or_else(|_| {
        if std::path::Path::new(".env.mainnet").exists() {
            ".env.mainnet".to_string()
        } else if std::path::Path::new(".env").exists() {
            ".env".to_string()
        } else {
            ".env.mainnet".to_string() // Will fail gracefully if not exists
        }
    });

    match dotenvy::from_filename(&env_file) {
        Ok(path) => {
            // Store which file was loaded for later logging (tracing not initialized yet)
            env::set_var("_DSDN_LOADED_ENV_FILE", path.display().to_string());
        }
        Err(e) => {
            // File not found is acceptable, other errors are warnings
            if !matches!(e, dotenvy::Error::Io(_)) {
                eprintln!("⚠️  Warning: Failed to load {}: {}", env_file, e);
            }
            // Continue without env file - will use environment variables directly
        }
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
// HTTP SERVER (AXUM)
// ════════════════════════════════════════════════════════════════════════════

/// Start HTTP server using Axum with full observability endpoints.
///
/// Endpoints: /health /ready /info /status /state /state/fallback
///            /state/assignments /da/status /metrics /metrics/prometheus
///
/// ALL endpoints are READ-ONLY (observability only).
/// Node receives commands via DA events, NOT via HTTP.
async fn start_axum_server(
    addr: SocketAddr,
    router: Router,
    shutdown: Arc<Notify>,
) {
    info!("🌐 Starting HTTP server on http://{}", addr);
    info!("   Endpoints: /health /ready /info /status /state /da/status /metrics");

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind HTTP server to {}: {}", addr, e);
            return;
        }
    };

    // Serve with graceful shutdown
    axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            shutdown.notified().await;
            info!("HTTP server shutting down");
        })
        .await
        .unwrap_or_else(|e| {
            error!("HTTP server error: {}", e);
        });
}

// ════════════════════════════════════════════════════════════════════════════
// CLI SUBCOMMANDS
// ════════════════════════════════════════════════════════════════════════════

/// Print usage/help message.
fn print_usage(prog: &str) {
    eprintln!("DSDN Node v{}", NODE_VERSION);
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  {} run [env]                                          Start node (env mode, default)", prog);
    eprintln!("  {} run <node-id|auto> <da-endpoint|mock> <storage-path> <http-port>", prog);
    eprintln!("                                                          Start node (CLI mode)");
    eprintln!("  {} status [--port PORT]                               Query running node status", prog);
    eprintln!("  {} health [--port PORT]                               Query running node health", prog);
    eprintln!("  {} info                                               Show build/config info", prog);
    eprintln!("  {} version                                            Show version", prog);
    eprintln!();
    eprintln!("Environment variables (env mode):");
    eprintln!("  NODE_ID             Unique node identifier (or 'auto')");
    eprintln!("  NODE_STORAGE_PATH   Storage directory path");
    eprintln!("  NODE_HTTP_PORT      HTTP server port");
    eprintln!("  DA_RPC_URL          Celestia light node RPC endpoint");
    eprintln!("  DA_NAMESPACE        58-character hex namespace");
    eprintln!("  DA_AUTH_TOKEN       Authentication token (required for mainnet)");
    eprintln!();
    eprintln!("Optional:");
    eprintln!("  DA_NETWORK          Network identifier (default: mainnet)");
    eprintln!("  DA_TIMEOUT_MS       Operation timeout in milliseconds");
    eprintln!("  USE_MOCK_DA         Use mock DA for development");
    eprintln!("  DSDN_ENV_FILE       Custom env file path (default: .env.mainnet)");
    eprintln!();
    eprintln!("Environment file loading (automatic):");
    eprintln!("  Priority: DSDN_ENV_FILE > .env.mainnet > .env");
}

/// Execute `version` subcommand.
fn cmd_version() {
    println!("{} v{}", NODE_NAME, NODE_VERSION);
}

/// Execute `info` subcommand — show build info and current env config.
fn cmd_info() {
    // Load env file so we can display config
    load_env_file();

    println!("═══════════════════════════════════════════════════════════════");
    println!("                    DSDN Node Info                              ");
    println!("═══════════════════════════════════════════════════════════════");
    println!("Version:        {} v{}", NODE_NAME, NODE_VERSION);

    if let Ok(loaded) = env::var("_DSDN_LOADED_ENV_FILE") {
        println!("Env file:       {}", loaded);
    } else {
        println!("Env file:       (none loaded)");
    }

    println!();
    println!("── Current Configuration (from env) ──");
    println!("NODE_ID:            {}", env::var("NODE_ID").unwrap_or_else(|_| "(not set)".into()));
    println!("NODE_STORAGE_PATH:  {}", env::var("NODE_STORAGE_PATH").unwrap_or_else(|_| "(not set)".into()));
    println!("NODE_HTTP_PORT:     {}", env::var("NODE_HTTP_PORT").unwrap_or_else(|_| "(not set)".into()));
    println!("DA_RPC_URL:         {}", env::var("DA_RPC_URL").unwrap_or_else(|_| "(not set)".into()));
    println!("DA_NAMESPACE:       {}", env::var("DA_NAMESPACE").unwrap_or_else(|_| "(not set)".into()));
    println!("DA_NETWORK:         {}", env::var("DA_NETWORK").unwrap_or_else(|_| "mainnet (default)".into()));
    println!("DA_AUTH_TOKEN:      {}", if env::var("DA_AUTH_TOKEN").is_ok() { "(set)" } else { "(not set)" });
    println!("USE_MOCK_DA:        {}", env::var("USE_MOCK_DA").unwrap_or_else(|_| "false".into()));
    println!("═══════════════════════════════════════════════════════════════");
}

/// Parse --port flag from args, default to 8080.
fn parse_port_flag(args: &[String]) -> u16 {
    for i in 0..args.len() {
        if args[i] == "--port" || args[i] == "-p" {
            if let Some(port_str) = args.get(i + 1) {
                return port_str.parse().unwrap_or(8080);
            }
        }
    }
    // Also try from NODE_HTTP_PORT env
    env::var("NODE_HTTP_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8080)
}

/// Execute `status` subcommand — query a running node's /status endpoint.
async fn cmd_status(port: u16) {
    let url = format!("http://127.0.0.1:{}/status", port);
    println!("Querying node status at {}...", url);

    match reqwest::get(&url).await {
        Ok(resp) => {
            let status = resp.status();
            match resp.text().await {
                Ok(body) => {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                        println!();
                        println!("HTTP {}", status);
                        println!("{}", serde_json::to_string_pretty(&json).unwrap_or(body));
                    } else {
                        println!("HTTP {} — {}", status, body);
                    }
                }
                Err(e) => {
                    eprintln!("Failed to read response body: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to connect to node at port {}: {}", port, e);
            eprintln!("Is the node running? Start it with: dsdn-node run");
            std::process::exit(1);
        }
    }
}

/// Execute `health` subcommand — query a running node's /health endpoint.
async fn cmd_health(port: u16) {
    let url = format!("http://127.0.0.1:{}/health", port);
    println!("Querying node health at {}...", url);

    match reqwest::get(&url).await {
        Ok(resp) => {
            let status = resp.status();
            match resp.text().await {
                Ok(body) => {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                        println!();
                        if status.is_success() {
                            println!("✅ Node is healthy (HTTP {})", status);
                        } else {
                            println!("❌ Node is unhealthy (HTTP {})", status);
                        }
                        println!("{}", serde_json::to_string_pretty(&json).unwrap_or(body));
                    } else {
                        println!("HTTP {} — {}", status, body);
                    }
                }
                Err(e) => {
                    eprintln!("Failed to read response body: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to connect to node at port {}: {}", port, e);
            eprintln!("Is the node running? Start it with: dsdn-node run");
            std::process::exit(1);
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// RUN SUBCOMMAND (main node loop)
// ════════════════════════════════════════════════════════════════════════════

/// Execute `run` subcommand — start the node.
async fn cmd_run(run_args: &[String]) {
    // Parse configuration
    let config = match NodeConfig::from_run_args(run_args) {
        Ok(c) => c,
        Err(e) => {
            error!("{}", e);
            error!("");
            error!("Required environment variables:");
            error!("  NODE_ID             - Unique node identifier (or 'auto')");
            error!("  NODE_STORAGE_PATH   - Storage directory path");
            error!("  NODE_HTTP_PORT      - HTTP server port");
            error!("  DA_RPC_URL          - Celestia light node RPC endpoint");
            error!("  DA_NAMESPACE        - 58-character hex namespace");
            error!("  DA_AUTH_TOKEN       - Authentication token (required for mainnet)");
            error!("");
            error!("Optional:");
            error!("  DA_NETWORK          - Network identifier (default: mainnet)");
            error!("  DA_TIMEOUT_MS       - Operation timeout (default: 30000)");
            error!("  USE_MOCK_DA         - Use mock DA for development");
            error!("  DSDN_ENV_FILE       - Custom env file path (default: .env.mainnet)");
            std::process::exit(1);
        }
    };

    // Validate configuration
    if let Err(e) = config.validate() {
        error!("Configuration error: {}", e);
        std::process::exit(1);
    }

    info!("═══════════════════════════════════════════════════════════════");
    info!("               DSDN Node v{} (Mainnet Ready)                   ", NODE_VERSION);
    info!("═══════════════════════════════════════════════════════════════");

    // Log which env file was loaded (if any)
    if let Ok(loaded_file) = env::var("_DSDN_LOADED_ENV_FILE") {
        info!("Env File:     {}", loaded_file);
    }

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

    // Step 7: Get start time for uptime tracking
    let start_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Step 8: Build NodeAppState for Axum handlers
    let app_state = Arc::new(NodeAppState {
        node_id: config.node_id.clone(),
        state: state.clone(),
        da_info: da_info.clone(),
        storage: storage.clone(),
        start_time,
        da_network: config.da_config.network.clone(),
        da_endpoint: config.da_config.rpc_url.clone(),
    });

    // Step 9: Build Axum router
    let router = build_router(app_state);

    // Step 10: Start HTTP server (Axum)
    let http_addr: SocketAddr = format!("0.0.0.0:{}", config.http_port)
        .parse()
        .unwrap_or_else(|_| {
            error!("Invalid HTTP address");
            std::process::exit(1);
        });

    let http_handle = {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            start_axum_server(http_addr, router, shutdown).await;
        })
    };

    // Step 11: Start DA follower
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
// MAIN
// ════════════════════════════════════════════════════════════════════════════

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let prog = &args[0];

    // ─────────────────────────────────────────────────────────────────────
    // Step 0: Load environment from .env.mainnet (or custom env file)
    // This happens BEFORE anything else, same pattern as coordinator.
    // ─────────────────────────────────────────────────────────────────────
    load_env_file();

    // Determine subcommand
    let subcommand = args.get(1).map(|s| s.as_str());

    match subcommand {
        // ── version ──────────────────────────────────────────────────────
        Some("version") | Some("--version") | Some("-V") => {
            cmd_version();
        }

        // ── info ─────────────────────────────────────────────────────────
        Some("info") => {
            cmd_info();
        }

        // ── status ───────────────────────────────────────────────────────
        Some("status") => {
            let port = parse_port_flag(&args[2..]);
            cmd_status(port).await;
        }

        // ── health ───────────────────────────────────────────────────────
        Some("health") => {
            let port = parse_port_flag(&args[2..]);
            cmd_health(port).await;
        }

        // ── run (explicit) ──────────────────────────────────────────────
        Some("run") => {
            // Initialize tracing for run mode
            tracing_subscriber::fmt()
                .with_max_level(Level::INFO)
                .with_target(false)
                .init();

            let run_args = &args[2..];
            cmd_run(run_args.to_vec().as_slice()).await;
        }

        // ── backward compatibility: `dsdn-node env` ─────────────────────
        Some("env") => {
            tracing_subscriber::fmt()
                .with_max_level(Level::INFO)
                .with_target(false)
                .init();

            cmd_run(&[]).await;
        }

        // ── backward compatibility: `dsdn-node <node-id> <da> <path> <port>` ──
        // If first arg is not a known subcommand, treat as legacy CLI mode
        Some(first_arg) if !first_arg.starts_with('-') => {
            tracing_subscriber::fmt()
                .with_max_level(Level::INFO)
                .with_target(false)
                .init();

            // Pass all args after program name as run args (legacy mode)
            cmd_run(&args[1..]).await;
        }

        // ── help ─────────────────────────────────────────────────────────
        Some("--help") | Some("-h") | Some("help") => {
            print_usage(prog);
        }

        // ── no args → default to `run env` ──────────────────────────────
        None => {
            tracing_subscriber::fmt()
                .with_max_level(Level::INFO)
                .with_target(false)
                .init();

            info!("No subcommand specified, defaulting to 'run' (env mode)");
            cmd_run(&[]).await;
        }

        _ => {
            print_usage(prog);
            std::process::exit(1);
        }
    }
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
        env::set_var("USE_MOCK_DA", "true");
        env::set_var("NODE_ID", "test-node");
        env::set_var("NODE_STORAGE_PATH", "./test-data");
        env::set_var("NODE_HTTP_PORT", "9090");

        let config = NodeConfig::from_env().unwrap();

        assert_eq!(config.node_id, "test-node");
        assert_eq!(config.storage_path, "./test-data");
        assert_eq!(config.http_port, 9090);
        assert!(config.use_mock_da);
        assert_eq!(config.config_source, "env");

        // Cleanup
        env::remove_var("USE_MOCK_DA");
        env::remove_var("NODE_ID");
        env::remove_var("NODE_STORAGE_PATH");
        env::remove_var("NODE_HTTP_PORT");
    }

    #[test]
    fn test_config_auto_node_id() {
        env::set_var("USE_MOCK_DA", "true");
        env::set_var("NODE_ID", "auto");
        env::set_var("NODE_STORAGE_PATH", "./test-data");
        env::set_var("NODE_HTTP_PORT", "9090");

        let config = NodeConfig::from_env().unwrap();

        // Should be a UUID
        assert!(config.node_id.len() >= 32);
        assert_ne!(config.node_id, "auto");

        // Cleanup
        env::remove_var("USE_MOCK_DA");
        env::remove_var("NODE_ID");
        env::remove_var("NODE_STORAGE_PATH");
        env::remove_var("NODE_HTTP_PORT");
    }

    #[test]
    fn test_run_args_empty_defaults_to_env() {
        env::set_var("USE_MOCK_DA", "true");
        env::set_var("NODE_ID", "test-run");
        env::set_var("NODE_STORAGE_PATH", "./test-run-data");
        env::set_var("NODE_HTTP_PORT", "9091");

        let config = NodeConfig::from_run_args(&[]).unwrap();
        assert_eq!(config.node_id, "test-run");
        assert_eq!(config.config_source, "env");

        // Cleanup
        env::remove_var("USE_MOCK_DA");
        env::remove_var("NODE_ID");
        env::remove_var("NODE_STORAGE_PATH");
        env::remove_var("NODE_HTTP_PORT");
    }

    #[test]
    fn test_run_args_env_keyword() {
        env::set_var("USE_MOCK_DA", "true");
        env::set_var("NODE_ID", "test-env-kw");
        env::set_var("NODE_STORAGE_PATH", "./test-env");
        env::set_var("NODE_HTTP_PORT", "9092");

        let args = vec!["env".to_string()];
        let config = NodeConfig::from_run_args(&args).unwrap();
        assert_eq!(config.node_id, "test-env-kw");
        assert_eq!(config.config_source, "env");

        // Cleanup
        env::remove_var("USE_MOCK_DA");
        env::remove_var("NODE_ID");
        env::remove_var("NODE_STORAGE_PATH");
        env::remove_var("NODE_HTTP_PORT");
    }

    #[test]
    fn test_run_args_cli_mode() {
        let args = vec![
            "node-1".to_string(),
            "mock".to_string(),
            "./data/node1".to_string(),
            "8080".to_string(),
        ];
        let config = NodeConfig::from_run_args(&args).unwrap();
        assert_eq!(config.node_id, "node-1");
        assert!(config.use_mock_da);
        assert_eq!(config.storage_path, "./data/node1");
        assert_eq!(config.http_port, 8080);
        assert_eq!(config.config_source, "cli");
    }

    #[test]
    fn test_parse_port_flag() {
        let args = vec!["--port".to_string(), "9999".to_string()];
        assert_eq!(parse_port_flag(&args), 9999);

        let args = vec!["-p".to_string(), "7777".to_string()];
        assert_eq!(parse_port_flag(&args), 7777);

        let args: Vec<String> = vec![];
        // Will fall back to NODE_HTTP_PORT env or 8080
        let port = parse_port_flag(&args);
        assert!(port > 0);
    }

    #[test]
    fn test_version_constant() {
        assert!(!NODE_VERSION.is_empty());
        assert_eq!(NODE_NAME, "dsdn-node");
    }
}