//! # DSDN Node CLI Module
//!
//! All CLI configuration, subcommands, HTTP/gRPC server setup,
//! storage backend, and DA helpers extracted from the main entry point.

use std::env;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{Path as AxumPath, State as AxumState};
use axum::http::StatusCode;
use axum::routing::{get, put as axum_put};
use axum::{Json, Router};
use parking_lot::RwLock;
use serde::Serialize;
use tokio::sync::Notify;
use tracing::{error, info, warn};
use uuid::Uuid;

use dsdn_common::cid::sha256_hex;
use dsdn_common::{CelestiaDA, DAConfig, DAError, DAHealthStatus, DALayer, MockDA};
use dsdn_node::{
    DAInfo, HealthResponse, HealthStorage, NodeDerivedState, NodeHealth,
    NodeAppState, build_router,
};
use dsdn_storage::chunker;
use dsdn_storage::localfs::LocalFsStorage;
use dsdn_storage::rpc;
use dsdn_storage::store::Storage as StorageTrait;

use crate::{NODE_VERSION, NODE_NAME, DEFAULT_GRPC_PORT_OFFSET};

// ════════════════════════════════════════════════════════════════════════════
// CLI CONFIGURATION
// ════════════════════════════════════════════════════════════════════════════

/// Node configuration parsed from CLI arguments or environment.
#[derive(Debug, Clone)]
pub(crate) struct NodeConfig {
    /// Unique node identifier.
    pub node_id: String,
    /// DA configuration.
    pub da_config: DAConfig,
    /// Storage directory path.
    pub storage_path: String,
    /// HTTP port for health endpoint.
    pub http_port: u16,
    /// gRPC port for storage server.
    pub grpc_port: u16,
    /// Whether to use mock DA for testing.
    pub use_mock_da: bool,
    /// Configuration source (cli or env).
    pub config_source: String,
}

impl NodeConfig {
    /// Parse configuration from CLI arguments for `run` subcommand.
    ///
    /// Usage: dsdn-node run <node-id|auto> <da-endpoint|mock> <storage-path> <http-port>
    ///    OR: dsdn-node run env   (default if no args after `run`)
    ///    OR: dsdn-node run       (defaults to env mode)
    pub fn from_run_args(args: &[String]) -> Result<Self, String> {
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

        // Build DA config for CLI mode.
        // CLI provides the RPC URL; auth_token, namespace, and other DA
        // settings are picked up from environment (.env.mainnet already
        // loaded by load_env_file() before we get here).
        let da_config = if use_mock_da {
            DAConfig::default()
        } else {
            // --- namespace from env ---
            let namespace = match env::var("DA_NAMESPACE") {
                Ok(hex_str) => {
                    let hex_str = hex_str.trim();
                    if hex_str.len() == 58 {
                        let mut ns = [0u8; 29];
                        let mut valid = true;
                        for i in 0..29 {
                            match u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16) {
                                Ok(b) => ns[i] = b,
                                Err(_) => { valid = false; break; }
                            }
                        }
                        if valid { ns } else {
                            eprintln!("⚠️  Invalid DA_NAMESPACE hex, using zeroed namespace");
                            [0u8; 29]
                        }
                    } else {
                        eprintln!("⚠️  DA_NAMESPACE must be 58 hex chars (got {}), using zeroed namespace", hex_str.len());
                        [0u8; 29]
                    }
                }
                Err(_) => [0u8; 29],
            };

            // --- auth token from env ---
            let auth_token = env::var("DA_AUTH_TOKEN").ok().filter(|s| !s.trim().is_empty());
            if auth_token.is_none() {
                eprintln!("⚠️  DA_AUTH_TOKEN not set — Celestia will reject requests that need 'read' permission");
            }

            // --- other DA settings from env with sane defaults ---
            let network = env::var("DA_NETWORK").unwrap_or_else(|_| "mainnet".to_string());
            let timeout_ms = env::var("DA_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30000u64);
            let retry_count = env::var("DA_RETRY_COUNT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3u8);

            DAConfig {
                rpc_url: da_endpoint,
                namespace,
                auth_token,
                timeout_ms,
                retry_count,
                retry_delay_ms: 1000,
                network,
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

        // gRPC port: from env or http_port + offset
        let grpc_port = Self::resolve_grpc_port(http_port);

        Ok(Self {
            node_id,
            da_config,
            storage_path,
            http_port,
            grpc_port,
            use_mock_da,
            config_source: "cli".to_string(),
        })
    }

    /// Parse configuration from environment variables.
    pub fn from_env() -> Result<Self, String> {
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

        // gRPC port: from env or http_port + offset
        let grpc_port = Self::resolve_grpc_port(http_port);

        Ok(Self {
            node_id,
            da_config,
            storage_path,
            http_port,
            grpc_port,
            use_mock_da,
            config_source: "env".to_string(),
        })
    }

    /// Resolve gRPC port from env or derive from HTTP port.
    fn resolve_grpc_port(http_port: u16) -> u16 {
        env::var("NODE_GRPC_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| http_port.saturating_add(DEFAULT_GRPC_PORT_OFFSET))
    }

    /// Validate configuration.
    pub fn validate(&self) -> Result<(), String> {
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

        if self.grpc_port == 0 {
            return Err("gRPC port cannot be 0".to_string());
        }

        if self.http_port == self.grpc_port {
            return Err(format!(
                "HTTP port ({}) and gRPC port ({}) cannot be the same",
                self.http_port, self.grpc_port
            ));
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
pub fn load_env_file() {
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
// NODE STORAGE BACKEND (wraps LocalFsStorage)
// ════════════════════════════════════════════════════════════════════════════

/// Cache duration for storage metrics (30 seconds).
const STORAGE_METRICS_CACHE_SECS: u64 = 30;

/// Real storage backend that wraps `LocalFsStorage` from dsdn_storage.
///
/// Implements `HealthStorage` for health/metrics reporting and provides
/// access to the underlying `LocalFsStorage` for chunk operations.
pub(crate) struct NodeStorageBackend {
    /// Underlying local filesystem storage.
    local_fs: Arc<LocalFsStorage>,
    /// Objects directory path (for calculating disk usage).
    objects_dir: PathBuf,
    /// Cached used bytes + last calculation time.
    cached_used: RwLock<(u64, Instant)>,
    /// Storage capacity in bytes (configurable or detected).
    capacity_bytes: u64,
}

impl NodeStorageBackend {
    /// Create a new storage backend rooted at `storage_path`.
    ///
    /// This creates the directory structure if needed and performs an
    /// initial scan of existing data to calculate used bytes.
    pub fn new(storage_path: &str) -> Result<Self, String> {
        let local_fs = Arc::new(
            LocalFsStorage::new(storage_path)
                .map_err(|e| format!("Failed to initialize LocalFsStorage: {}", e))?
        );

        let objects_dir = PathBuf::from(storage_path).join("objects");

        // Initial scan for used bytes
        let initial_used = calculate_dir_size(&objects_dir);

        // Capacity from env or default 100 GB
        let capacity_bytes: u64 = env::var("NODE_STORAGE_CAPACITY_GB")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(100)
            * 1024 * 1024 * 1024;

        Ok(Self {
            local_fs,
            objects_dir,
            cached_used: RwLock::new((initial_used, Instant::now())),
            capacity_bytes,
        })
    }

    /// Get reference to underlying LocalFsStorage.
    pub fn local_fs(&self) -> &Arc<LocalFsStorage> {
        &self.local_fs
    }

    /// Invalidate the usage cache (call after writes).
    pub fn invalidate_cache(&self) {
        let mut cache = self.cached_used.write();
        // Set timestamp to epoch so next read recalculates
        cache.1 = Instant::now() - Duration::from_secs(STORAGE_METRICS_CACHE_SECS + 1);
    }

    /// Get current used bytes (with caching).
    fn used_bytes_cached(&self) -> u64 {
        let cache = self.cached_used.read();
        if cache.1.elapsed().as_secs() < STORAGE_METRICS_CACHE_SECS {
            return cache.0;
        }
        drop(cache);

        let size = calculate_dir_size(&self.objects_dir);
        let mut cache = self.cached_used.write();
        *cache = (size, Instant::now());
        size
    }
}

impl HealthStorage for NodeStorageBackend {
    fn storage_used_bytes(&self) -> u64 {
        self.used_bytes_cached()
    }

    fn storage_capacity_bytes(&self) -> u64 {
        self.capacity_bytes
    }
}

/// Recursively calculate total size of all files in a directory.
pub(crate) fn calculate_dir_size(path: &Path) -> u64 {
    let mut total = 0u64;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                total += calculate_dir_size(&p);
            } else {
                total += entry.metadata().map(|m| m.len()).unwrap_or(0);
            }
        }
    }
    total
}

/// Count total number of files (chunks) in a directory recursively.
pub(crate) fn count_files(path: &Path) -> u64 {
    let mut count = 0u64;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                count += count_files(&p);
            } else {
                count += 1;
            }
        }
    }
    count
}

// ════════════════════════════════════════════════════════════════════════════
// DA INFO WRAPPER
// ════════════════════════════════════════════════════════════════════════════

/// Wrapper for DA layer to implement DAInfo trait.
pub(crate) struct DAInfoWrapper {
    /// DA layer reference.
    #[allow(dead_code)]
    da: Arc<dyn DALayer>,
    /// Latest sequence (updated by follower).
    latest_sequence: RwLock<u64>,
    /// Connection status.
    connected: RwLock<bool>,
}

impl DAInfoWrapper {
    pub fn new(da: Arc<dyn DALayer>) -> Self {
        Self {
            da,
            latest_sequence: RwLock::new(0),
            connected: RwLock::new(true),
        }
    }

    pub fn update_sequence(&self, seq: u64) {
        let mut latest = self.latest_sequence.write();
        if seq > *latest {
            *latest = seq;
        }
    }

    pub fn set_connected(&self, connected: bool) {
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
// STORAGE HTTP ENDPOINTS (Data Plane)
// ════════════════════════════════════════════════════════════════════════════
//
// These endpoints handle chunk data transfer via HTTP.
// They are data plane operations — NOT control plane instructions.
// Control plane commands still come exclusively via DA events.

/// Shared state for storage HTTP endpoints.
#[derive(Clone)]
struct StorageHttpState {
    store: Arc<LocalFsStorage>,
    objects_dir: PathBuf,
}

/// Path parameter for hash-based routes.
#[derive(Debug, serde::Deserialize)]
struct HashParam {
    hash: String,
}

/// Response for chunk operations.
#[derive(Debug, Serialize)]
struct ChunkResponse {
    hash: String,
    size: usize,
    status: String,
}

/// Response for storage stats.
#[derive(Debug, Serialize)]
struct StorageStatsResponse {
    total_chunks: u64,
    total_bytes: u64,
    storage_path: String,
}

/// GET /storage/chunk/:hash — Retrieve a chunk by hash.
async fn http_get_chunk(
    AxumPath(params): AxumPath<HashParam>,
    AxumState(st): AxumState<Arc<StorageHttpState>>,
) -> Result<Vec<u8>, StatusCode> {
    match st.store.get_chunk(&params.hash) {
        Ok(Some(data)) => Ok(data),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// GET /storage/has/:hash — Check if a chunk exists.
async fn http_has_chunk(
    AxumPath(params): AxumPath<HashParam>,
    AxumState(st): AxumState<Arc<StorageHttpState>>,
) -> Json<serde_json::Value> {
    let exists = st.store.has_chunk(&params.hash).unwrap_or(false);
    Json(serde_json::json!({ "hash": params.hash, "exists": exists }))
}

/// PUT /storage/chunk — Store a chunk (hash computed from data).
async fn http_put_chunk(
    AxumState(st): AxumState<Arc<StorageHttpState>>,
    body: Bytes,
) -> Result<Json<ChunkResponse>, StatusCode> {
    if body.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let hash = sha256_hex(&body);
    let size = body.len();

    st.store
        .put_chunk(&hash, &body)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ChunkResponse {
        hash,
        size,
        status: "ok".to_string(),
    }))
}

/// GET /storage/stats — Storage statistics.
async fn http_storage_stats(
    AxumState(st): AxumState<Arc<StorageHttpState>>,
) -> Json<StorageStatsResponse> {
    let total_bytes = calculate_dir_size(&st.objects_dir);
    let total_chunks = count_files(&st.objects_dir);

    Json(StorageStatsResponse {
        total_chunks,
        total_bytes,
        storage_path: st.objects_dir.parent()
            .unwrap_or(&st.objects_dir)
            .display()
            .to_string(),
    })
}

/// Build storage HTTP router (data plane endpoints).
fn build_storage_router(state: Arc<StorageHttpState>) -> Router {
    Router::new()
        // Primary routes with /storage prefix
        .route("/storage/chunk/:hash", get(http_get_chunk))
        .route("/storage/has/:hash", get(http_has_chunk))
        .route("/storage/chunk", axum_put(http_put_chunk))
        .route("/storage/stats", get(http_storage_stats))
        // Backward compatibility aliases without prefix
        .route("/chunks/:hash", get(http_get_chunk))
        .route("/has/:hash", get(http_has_chunk))
        .route("/chunks", axum_put(http_put_chunk))
        .with_state(state)
}

// ════════════════════════════════════════════════════════════════════════════
// HTTP SERVER (AXUM)
// ════════════════════════════════════════════════════════════════════════════

/// Start HTTP server using Axum with full observability endpoints.
///
/// Endpoints:
///   Observability: /health /ready /info /status /state /state/fallback
///                  /state/assignments /da/status /metrics /metrics/prometheus
///   Storage:       /storage/chunk/:hash (GET) /storage/chunk (PUT)
///                  /storage/has/:hash (GET) /storage/stats (GET)
///                  /chunks/:hash (GET) /chunks (PUT) /has/:hash (GET)
///                  (aliases for backward compatibility)
///
/// Control plane commands come via DA events, NOT via HTTP.
/// Storage endpoints are data plane operations.
async fn start_axum_server(
    addr: SocketAddr,
    router: Router,
    shutdown: Arc<Notify>,
) {
    info!("🌐 Starting HTTP server on http://{}", addr);
    info!("   Observability: /health /ready /info /status /state /da/status /metrics");
    info!("   Storage:       /storage/chunk/:hash /storage/chunk /storage/has/:hash /storage/stats");
    info!("   Aliases:       /chunks/:hash /chunks /has/:hash (backward compatibility)");

    let listener = match bind_with_reuse(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("❌ Failed to bind HTTP server to {}: {}", addr, e);
            error!("   Hint: kill the previous node process, or use a different --port");
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

/// Bind TCP listener with SO_REUSEADDR and retry.
/// Handles Windows TIME_WAIT issue after rapid restart.
async fn bind_with_reuse(addr: SocketAddr) -> Result<tokio::net::TcpListener, String> {
    let max_attempts = 5;

    for attempt in 1..=max_attempts {
        match try_bind_reuse(addr) {
            Ok(listener) => {
                if attempt > 1 {
                    info!("✅ HTTP port {} bound on attempt {}", addr.port(), attempt);
                }
                return Ok(listener);
            }
            Err(e) => {
                if attempt < max_attempts {
                    warn!(
                        "Port {} busy (attempt {}/{}): {} — retrying in 2s...",
                        addr.port(), attempt, max_attempts, e
                    );
                    tokio::time::sleep(Duration::from_secs(2)).await;
                } else {
                    return Err(format!(
                        "port {} still busy after {} attempts: {}",
                        addr.port(), max_attempts, e
                    ));
                }
            }
        }
    }
    unreachable!()
}

/// Single bind attempt using socket2 for SO_REUSEADDR.
fn try_bind_reuse(addr: SocketAddr) -> Result<tokio::net::TcpListener, String> {
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };

    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))
        .map_err(|e| format!("socket create: {}", e))?;

    socket.set_reuse_address(true).map_err(|e| format!("SO_REUSEADDR: {}", e))?;
    socket.set_nonblocking(true).map_err(|e| format!("nonblocking: {}", e))?;

    let sock_addr: socket2::SockAddr = addr.into();
    socket.bind(&sock_addr).map_err(|e| format!("bind: {}", e))?;
    socket.listen(1024).map_err(|e| format!("listen: {}", e))?;

    let std_listener: std::net::TcpListener = socket.into();
    tokio::net::TcpListener::from_std(std_listener).map_err(|e| format!("tokio wrap: {}", e))
}

// ════════════════════════════════════════════════════════════════════════════
// CLI SUBCOMMANDS
// ════════════════════════════════════════════════════════════════════════════

/// Print usage/help message.
pub fn print_usage(prog: &str) {
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
    eprintln!("Storage commands:");
    eprintln!("  {} store put <file> [chunk_size]                      Chunk file & store locally", prog);
    eprintln!("  {} store get <hash> [output_file]                     Get chunk from local store", prog);
    eprintln!("  {} store has <hash>                                   Check if chunk exists", prog);
    eprintln!("  {} store stats                                        Show storage statistics", prog);
    eprintln!("  {} store send <grpc-addr> <file>                      Send file chunks via gRPC", prog);
    eprintln!("  {} store fetch <grpc-addr> <hash> [output]            Fetch chunk from remote via gRPC", prog);
    eprintln!();
    eprintln!("Environment variables (env mode):");
    eprintln!("  NODE_ID             Unique node identifier (or 'auto')");
    eprintln!("  NODE_STORAGE_PATH   Storage directory path");
    eprintln!("  NODE_HTTP_PORT      HTTP server port");
    eprintln!("  NODE_GRPC_PORT      gRPC storage server port (default: HTTP_PORT + 1000)");
    eprintln!("  DA_RPC_URL          Celestia light node RPC endpoint");
    eprintln!("  DA_NAMESPACE        58-character hex namespace");
    eprintln!("  DA_AUTH_TOKEN       Authentication token (required for mainnet)");
    eprintln!();
    eprintln!("Optional:");
    eprintln!("  DA_NETWORK              Network identifier (default: mainnet)");
    eprintln!("  DA_TIMEOUT_MS           Operation timeout in milliseconds");
    eprintln!("  USE_MOCK_DA             Use mock DA for development");
    eprintln!("  DSDN_ENV_FILE           Custom env file path (default: .env.mainnet)");
    eprintln!("  NODE_STORAGE_CAPACITY_GB  Storage capacity in GB (default: 100)");
    eprintln!();
    eprintln!("Environment file loading (automatic):");
    eprintln!("  Priority: DSDN_ENV_FILE > .env.mainnet > .env");
}

/// Execute `version` subcommand.
pub fn cmd_version() {
    println!("{} v{}", NODE_NAME, NODE_VERSION);
}

/// Execute `info` subcommand — show build info and current env config.
pub fn cmd_info() {
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
    println!("NODE_GRPC_PORT:     {}", env::var("NODE_GRPC_PORT").unwrap_or_else(|_| "(auto)".into()));
    println!("DA_RPC_URL:         {}", env::var("DA_RPC_URL").unwrap_or_else(|_| "(not set)".into()));
    println!("DA_NAMESPACE:       {}", env::var("DA_NAMESPACE").unwrap_or_else(|_| "(not set)".into()));
    println!("DA_NETWORK:         {}", env::var("DA_NETWORK").unwrap_or_else(|_| "mainnet (default)".into()));
    println!("DA_AUTH_TOKEN:      {}", if env::var("DA_AUTH_TOKEN").is_ok() { "(set)" } else { "(not set)" });
    println!("USE_MOCK_DA:        {}", env::var("USE_MOCK_DA").unwrap_or_else(|_| "false".into()));
    println!("═══════════════════════════════════════════════════════════════");
}

/// Parse --port flag from args, default to 45831.
pub fn parse_port_flag(args: &[String]) -> u16 {
    for i in 0..args.len() {
        if args[i] == "--port" || args[i] == "-p" {
            if let Some(port_str) = args.get(i + 1) {
                return port_str.parse().unwrap_or(45831);
            }
        }
    }
    // Also try from NODE_HTTP_PORT env
    env::var("NODE_HTTP_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(45831)
}

/// Execute `status` subcommand — query a running node's /status endpoint.
pub async fn cmd_status(port: u16) {
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
pub async fn cmd_health(port: u16) {
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
// STORE SUBCOMMANDS
// ════════════════════════════════════════════════════════════════════════════

/// Get storage path from env or default.
fn resolve_storage_path() -> String {
    env::var("NODE_STORAGE_PATH").unwrap_or_else(|_| "./data".to_string())
}

/// Execute `store put <file> [chunk_size]`
pub fn cmd_store_put(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: dsdn-node store put <file> [chunk_size]");
        std::process::exit(2);
    }

    let file = Path::new(&args[0]);
    if !file.exists() {
        eprintln!("❌ File not found: {:?}", file);
        std::process::exit(1);
    }

    let chunk_size: usize = if args.len() >= 2 {
        args[1].parse().unwrap_or(chunker::DEFAULT_CHUNK_SIZE)
    } else {
        chunker::DEFAULT_CHUNK_SIZE
    };

    let storage_path = resolve_storage_path();
    let store = match LocalFsStorage::new(&storage_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("❌ Failed to open storage at {}: {}", storage_path, e);
            std::process::exit(1);
        }
    };

    let mut f = match std::fs::File::open(file) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("❌ Failed to open file: {}", e);
            std::process::exit(1);
        }
    };

    let chunks = match chunker::chunk_reader(&mut f, chunk_size) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("❌ Failed to chunk file: {}", e);
            std::process::exit(1);
        }
    };

    println!("📦 Storing {} chunks (chunk_size = {}) from {:?}", chunks.len(), chunk_size, file);
    for (i, chunk) in chunks.into_iter().enumerate() {
        let h = sha256_hex(&chunk);
        if let Err(e) = store.put_chunk(&h, &chunk) {
            eprintln!("❌ Failed to store chunk {}: {}", i, e);
            std::process::exit(1);
        }
        println!("  chunk {:>4}: {} ({} bytes)", i, h, chunk.len());
    }
    println!("✅ Done. Storage path: {}", storage_path);
}

/// Execute `store get <hash> [output_file]`
pub fn cmd_store_get(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: dsdn-node store get <hash> [output_file]");
        std::process::exit(2);
    }

    let hash = &args[0];
    let storage_path = resolve_storage_path();
    let store = match LocalFsStorage::new(&storage_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("❌ Failed to open storage at {}: {}", storage_path, e);
            std::process::exit(1);
        }
    };

    match store.get_chunk(hash) {
        Ok(Some(data)) => {
            if args.len() >= 2 {
                // Write to file
                let output = &args[1];
                if let Err(e) = std::fs::write(output, &data) {
                    eprintln!("❌ Failed to write to {}: {}", output, e);
                    std::process::exit(1);
                }
                println!("✅ Chunk {} ({} bytes) written to {}", hash, data.len(), output);
            } else {
                // Print info
                println!("✅ Chunk found: {} ({} bytes)", hash, data.len());
                // If data is small and looks like text, print it
                if data.len() <= 1024 {
                    if let Ok(text) = std::str::from_utf8(&data) {
                        println!("Content (text): {}", text);
                    } else {
                        println!("Content (hex, first 64 bytes): {}", hex_preview(&data, 64));
                    }
                } else {
                    println!("Content (hex, first 64 bytes): {}", hex_preview(&data, 64));
                }
            }
        }
        Ok(None) => {
            eprintln!("❌ Chunk not found: {}", hash);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("❌ Storage error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Execute `store has <hash>`
pub fn cmd_store_has(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: dsdn-node store has <hash>");
        std::process::exit(2);
    }

    let hash = &args[0];
    let storage_path = resolve_storage_path();
    let store = match LocalFsStorage::new(&storage_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("❌ Failed to open storage at {}: {}", storage_path, e);
            std::process::exit(1);
        }
    };

    match store.has_chunk(hash) {
        Ok(true) => println!("✅ Chunk exists: {}", hash),
        Ok(false) => {
            println!("❌ Chunk not found: {}", hash);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("❌ Storage error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Execute `store stats`
pub fn cmd_store_stats() {
    let storage_path = resolve_storage_path();
    let objects_dir = PathBuf::from(&storage_path).join("objects");

    if !objects_dir.exists() {
        println!("Storage path: {}", storage_path);
        println!("Status: empty (no data yet)");
        return;
    }

    let total_bytes = calculate_dir_size(&objects_dir);
    let total_chunks = count_files(&objects_dir);

    println!("═══════════════════════════════════════════════════════════════");
    println!("                  DSDN Storage Statistics                       ");
    println!("═══════════════════════════════════════════════════════════════");
    println!("Storage path:   {}", storage_path);
    println!("Objects dir:    {}", objects_dir.display());
    println!("Total chunks:   {}", total_chunks);
    println!("Total size:     {} ({} bytes)", human_bytes(total_bytes), total_bytes);
    println!("═══════════════════════════════════════════════════════════════");
}

/// Execute `store send <addr> <file>`
pub async fn cmd_store_send(args: &[String]) {
    if args.len() < 2 {
        eprintln!("Usage: dsdn-node store send <grpc-addr> <file>");
        eprintln!("  e.g. dsdn-node store send 127.0.0.1:9080 myfile.dat");
        std::process::exit(2);
    }

    let addr = &args[0];
    let file = Path::new(&args[1]);
    if !file.exists() {
        eprintln!("❌ File not found: {:?}", file);
        std::process::exit(1);
    }

    let mut f = std::fs::File::open(file).expect("open file");
    let chunks = chunker::chunk_reader(&mut f, chunker::DEFAULT_CHUNK_SIZE).expect("chunk file");

    println!("📤 Sending {} chunks to {}", chunks.len(), addr);
    for (i, chunk) in chunks.into_iter().enumerate() {
        let h = sha256_hex(&chunk);
        match rpc::client_put(format!("http://{}", addr), h.clone(), chunk).await {
            Ok(returned) => println!("  chunk {:>4}: sent → {}", i, returned),
            Err(e) => {
                eprintln!("❌ Failed to send chunk {}: {}", i, e);
                std::process::exit(1);
            }
        }
    }
    println!("✅ File transfer done.");
}

/// Execute `store fetch <addr> <hash> [output]`
pub async fn cmd_store_fetch(args: &[String]) {
    if args.len() < 2 {
        eprintln!("Usage: dsdn-node store fetch <grpc-addr> <hash> [output_file]");
        std::process::exit(2);
    }

    let addr = &args[0];
    let hash = &args[1];

    match rpc::client_get(format!("http://{}", addr), hash.clone()).await {
        Ok(Some(data)) => {
            if args.len() >= 3 {
                let output = &args[2];
                std::fs::write(output, &data).expect("write output");
                println!("✅ Fetched chunk {} ({} bytes) → {}", hash, data.len(), output);
            } else {
                println!("✅ Fetched chunk {} ({} bytes)", hash, data.len());
                if data.len() <= 1024 {
                    if let Ok(text) = std::str::from_utf8(&data) {
                        println!("Content: {}", text);
                    }
                }
            }
        }
        Ok(None) => {
            eprintln!("❌ Chunk not found on remote: {}", hash);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("❌ gRPC error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Helper: hex preview of bytes.
pub(crate) fn hex_preview(data: &[u8], max: usize) -> String {
    let limit = data.len().min(max);
    let hex: String = data[..limit].iter().map(|b| format!("{:02x}", b)).collect();
    if data.len() > max {
        format!("{}...", hex)
    } else {
        hex
    }
}

/// Helper: human-readable byte sizes.
pub(crate) fn human_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;

    if bytes >= GIB {
        format!("{:.2} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.2} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.2} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{} B", bytes)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// RUN SUBCOMMAND (main node loop)
// ════════════════════════════════════════════════════════════════════════════

/// Execute `run` subcommand — start the node.
pub async fn cmd_run(run_args: &[String]) {
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
            error!("  DA_NETWORK              - Network identifier (default: mainnet)");
            error!("  DA_TIMEOUT_MS           - Operation timeout (default: 30000)");
            error!("  USE_MOCK_DA             - Use mock DA for development");
            error!("  DSDN_ENV_FILE           - Custom env file path (default: .env.mainnet)");
            error!("  NODE_GRPC_PORT          - gRPC storage port (default: HTTP_PORT + 1000)");
            error!("  NODE_STORAGE_CAPACITY_GB - Storage capacity in GB (default: 100)");
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
    info!("DA Auth:      {}", if config.da_config.auth_token.is_some() { "present ✅" } else { "MISSING ❌" });
    info!("Storage Path: {}", config.storage_path);
    info!("HTTP Port:    {}", config.http_port);
    info!("gRPC Port:    {}", config.grpc_port);
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

    // Step 3: Initialize REAL storage (LocalFsStorage)
    info!("Initializing storage at {}", config.storage_path);
    let storage_backend = Arc::new(
        match NodeStorageBackend::new(&config.storage_path) {
            Ok(s) => s,
            Err(e) => {
                error!("❌ Failed to initialize storage: {}", e);
                std::process::exit(1);
            }
        }
    );

    let initial_used = storage_backend.storage_used_bytes();
    let capacity = storage_backend.storage_capacity_bytes();
    info!(
        "Storage initialized: {} used / {} capacity ({} chunks)",
        human_bytes(initial_used),
        human_bytes(capacity),
        count_files(&PathBuf::from(&config.storage_path).join("objects")),
    );

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
        storage: storage_backend.clone(),
        start_time,
        da_network: config.da_config.network.clone(),
        da_endpoint: config.da_config.rpc_url.clone(),
    });

    // Step 9: Build combined router (observability + storage data plane)
    let observability_router = build_router(app_state);

    let storage_http_state = Arc::new(StorageHttpState {
        store: storage_backend.local_fs().clone(),
        objects_dir: PathBuf::from(&config.storage_path).join("objects"),
    });
    let storage_router = build_storage_router(storage_http_state);

    // Merge routers directly (both already Router<()> after .with_state())
    let combined_router = observability_router
        .merge(storage_router)
        .fallback(|| async {
            (StatusCode::NOT_FOUND, "Route not found - check route registration")
        });


    // Step 10: Start gRPC storage server
    let grpc_addr: SocketAddr = format!("0.0.0.0:{}", config.grpc_port)
        .parse()
        .unwrap_or_else(|_| {
            error!("Invalid gRPC address");
            std::process::exit(1);
        });

    let grpc_handle = {
        let store = storage_backend.local_fs().clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            info!("📡 Starting gRPC storage server on {}", grpc_addr);
            if let Err(e) = rpc::run_server(grpc_addr, store, shutdown).await {
                error!("gRPC server error: {}", e);
            }
        })
    };

    // Step 11: Start HTTP server (Axum)
    let http_addr: SocketAddr = format!("0.0.0.0:{}", config.http_port)
        .parse()
        .unwrap_or_else(|_| {
            error!("Invalid HTTP address");
            std::process::exit(1);
        });

    let http_handle = {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            start_axum_server(http_addr, combined_router, shutdown).await;
        })
    };

    // Step 12: Start DA follower
    info!("🚀 Starting DA follower...");
    info!("");
    info!("╔═══════════════════════════════════════════════════════════════╗");
    info!("║  INVARIANT: Node receives ALL commands via DA events ONLY    ║");
    info!("║  Node does NOT accept instructions from Coordinator via RPC  ║");
    info!("╠═══════════════════════════════════════════════════════════════╣");
    info!("║  Storage:  gRPC  → 0.0.0.0:{}                            ║", config.grpc_port);
    info!("║            HTTP  → 0.0.0.0:{}/storage/*                  ║", config.http_port);
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
    let _ = grpc_handle.await;
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
    use dsdn_common::MockDA;

    #[test]
    fn test_config_validation_empty_node_id() {
        let config = NodeConfig {
            node_id: String::new(),
            da_config: DAConfig::default(),
            storage_path: "./data".to_string(),
            http_port: 45831,
            grpc_port: 9080,
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
            http_port: 45831,
            grpc_port: 9080,
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
            grpc_port: 9080,
            use_mock_da: true,
            config_source: "test".to_string(),
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_same_ports() {
        let config = NodeConfig {
            node_id: "node-1".to_string(),
            da_config: DAConfig::default(),
            storage_path: "./data".to_string(),
            http_port: 45831,
            grpc_port: 45831,
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
            http_port: 45831,
            grpc_port: 9080,
            use_mock_da: true,
            config_source: "test".to_string(),
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_node_storage_backend() {
        let tmp = tempfile::TempDir::new().expect("tmpdir");
        let backend = NodeStorageBackend::new(
            tmp.path().to_str().unwrap()
        ).expect("create backend");

        // Initially empty
        assert_eq!(backend.storage_used_bytes(), 0);
        assert!(backend.storage_capacity_bytes() > 0);

        // Put a chunk
        let data = b"test chunk data";
        let hash = sha256_hex(data);
        backend.local_fs().put_chunk(&hash, data).expect("put");

        // Invalidate cache and check
        backend.invalidate_cache();
        assert!(backend.storage_used_bytes() > 0);

        // Get chunk back
        let got = backend.local_fs().get_chunk(&hash).expect("get").expect("exists");
        assert_eq!(got.as_slice(), data);
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
        assert_eq!(config.grpc_port, 9090 + DEFAULT_GRPC_PORT_OFFSET);
        assert!(config.use_mock_da);
        assert_eq!(config.config_source, "env");

        // Cleanup
        env::remove_var("USE_MOCK_DA");
        env::remove_var("NODE_ID");
        env::remove_var("NODE_STORAGE_PATH");
        env::remove_var("NODE_HTTP_PORT");
    }

    #[test]
    fn test_config_grpc_port_from_env() {
        env::set_var("USE_MOCK_DA", "true");
        env::set_var("NODE_ID", "test-grpc");
        env::set_var("NODE_STORAGE_PATH", "./test-grpc");
        env::set_var("NODE_HTTP_PORT", "45831");
        env::set_var("NODE_GRPC_PORT", "5555");

        let config = NodeConfig::from_env().unwrap();
        assert_eq!(config.grpc_port, 5555);

        // Cleanup
        env::remove_var("USE_MOCK_DA");
        env::remove_var("NODE_ID");
        env::remove_var("NODE_STORAGE_PATH");
        env::remove_var("NODE_HTTP_PORT");
        env::remove_var("NODE_GRPC_PORT");
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
            "45831".to_string(),
        ];
        let config = NodeConfig::from_run_args(&args).unwrap();
        assert_eq!(config.node_id, "node-1");
        assert!(config.use_mock_da);
        assert_eq!(config.storage_path, "./data/node1");
        assert_eq!(config.http_port, 45831);
        assert_eq!(config.config_source, "cli");
    }

    #[test]
    fn test_parse_port_flag() {
        let args = vec!["--port".to_string(), "9999".to_string()];
        assert_eq!(parse_port_flag(&args), 9999);

        let args = vec!["-p".to_string(), "7777".to_string()];
        assert_eq!(parse_port_flag(&args), 7777);

        let args: Vec<String> = vec![];
        // Will fall back to NODE_HTTP_PORT env or 45831
        let port = parse_port_flag(&args);
        assert!(port > 0);
    }

    #[test]
    fn test_version_constant() {
        assert!(!NODE_VERSION.is_empty());
        assert_eq!(NODE_NAME, "dsdn-node");
    }

    #[test]
    fn test_calculate_dir_size() {
        let tmp = tempfile::TempDir::new().expect("tmpdir");
        let dir = tmp.path();

        // Empty dir = 0
        assert_eq!(calculate_dir_size(dir), 0);

        // Write a file
        std::fs::write(dir.join("test.dat"), b"hello world").unwrap();
        assert_eq!(calculate_dir_size(dir), 11);

        // Nested dir
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub/test2.dat"), b"more data").unwrap();
        assert_eq!(calculate_dir_size(dir), 11 + 9);
    }

    #[test]
    fn test_human_bytes() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1024), "1.00 KiB");
        assert_eq!(human_bytes(1024 * 1024), "1.00 MiB");
        assert_eq!(human_bytes(1024 * 1024 * 1024), "1.00 GiB");
    }

    #[test]
    fn test_hex_preview() {
        assert_eq!(hex_preview(&[0xab, 0xcd, 0xef], 10), "abcdef");
        assert_eq!(hex_preview(&[0xab, 0xcd, 0xef], 2), "abcd...");
    }
}