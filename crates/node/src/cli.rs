//! # DSDN Node CLI Module
//!
//! Full clap-based CLI for the DSDN storage node.
//!
//! All CLI configuration, subcommands, HTTP/gRPC server setup,
//! storage backend, and DA helpers.

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
use clap::{Parser, Subcommand, Args};
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
// CLI DEFINITIONS (clap)
// ════════════════════════════════════════════════════════════════════════════

/// DSDN Node — Distributed Storage and Data Network
///
/// Storage node that receives ALL commands via DA events (Celestia).
/// Provides chunk storage (gRPC + HTTP) and observability endpoints.
///
/// Running without a subcommand defaults to 'run' (starts the node server).
#[derive(Parser)]
#[command(
    name = "dsdn-node",
    version,
    about = "DSDN Node — Distributed Storage and Data Network",
    long_about = "Storage node that receives ALL commands via DA events.\n\
                  Provides chunk storage (gRPC + HTTP) and observability endpoints.\n\n\
                  Running without a subcommand defaults to 'run' (starts the node)."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Start the node server
    Run(RunArgs),

    /// Query a running node's status
    Status(QueryArgs),

    /// Query a running node's health
    Health(QueryArgs),

    /// Show build and configuration info
    Info,

    /// Show version string
    Version,

    /// Storage operations (local and remote)
    #[command(subcommand)]
    Store(StoreCommand),
}

// ────────────────────────────────────────────────────────────────────────────
// `run` subcommand
// ────────────────────────────────────────────────────────────────────────────

/// Arguments for the `run` subcommand — starts the node server.
///
/// All flags have environment variable fallbacks. CLI flags take precedence.
#[derive(Args)]
pub struct RunArgs {
    // ── Node Identity ───────────────────────────────────────────────────

    /// Unique node identifier (use 'auto' to generate a UUID)
    #[arg(long, env = "NODE_ID", default_value = "auto")]
    pub node_id: String,

    // ── Storage ─────────────────────────────────────────────────────────

    /// Storage directory path
    #[arg(long, env = "NODE_STORAGE_PATH", default_value = "./data")]
    pub storage_path: String,

    /// Storage capacity in GB
    #[arg(long, env = "NODE_STORAGE_CAPACITY_GB", default_value_t = 100)]
    pub storage_capacity_gb: u64,

    // ── Network Ports ───────────────────────────────────────────────────

    /// HTTP server port (observability + storage data-plane endpoints)
    #[arg(long, env = "NODE_HTTP_PORT", default_value_t = 45832)]
    pub http_port: u16,

    /// gRPC storage server port (default: http-port + 1000)
    #[arg(long, env = "NODE_GRPC_PORT")]
    pub grpc_port: Option<u16>,

    // ── Primary DA (Celestia) ───────────────────────────────────────────

    /// Celestia light node RPC endpoint
    #[arg(long, env = "DA_RPC_URL", required_unless_present = "mock_da")]
    pub da_rpc_url: Option<String>,

    /// DA namespace (58-character hex string, 29 bytes)
    #[arg(long, env = "DA_NAMESPACE", required_unless_present = "mock_da")]
    pub da_namespace: Option<String>,

    /// DA authentication token (required for mainnet)
    #[arg(long, env = "DA_AUTH_TOKEN")]
    pub da_auth_token: Option<String>,

    /// DA network identifier
    #[arg(long, env = "DA_NETWORK", default_value = "mainnet")]
    pub da_network: String,

    /// DA operation timeout in milliseconds
    #[arg(long, env = "DA_TIMEOUT_MS", default_value_t = 30000)]
    pub da_timeout_ms: u64,

    /// DA retry count for failed operations
    #[arg(long, env = "DA_RETRY_COUNT", default_value_t = 3)]
    pub da_retry_count: u8,

    /// DA retry delay in milliseconds
    #[arg(long, env = "DA_RETRY_DELAY_MS", default_value_t = 1000)]
    pub da_retry_delay_ms: u64,

    /// DA max connections (connection pooling)
    #[arg(long, env = "DA_MAX_CONNECTIONS", default_value_t = 10)]
    pub da_max_connections: u16,

    /// DA idle timeout in milliseconds
    #[arg(long, env = "DA_IDLE_TIMEOUT_MS", default_value_t = 60000)]
    pub da_idle_timeout_ms: u64,

    /// Enable DA connection pooling
    #[arg(long, env = "DA_ENABLE_POOLING", default_value_t = true)]
    pub da_enable_pooling: bool,

    /// Use mock DA layer for development (skips real Celestia connection)
    #[arg(long, env = "USE_MOCK_DA", default_value_t = false)]
    pub mock_da: bool,

    // ── Environment File ────────────────────────────────────────────────

    /// Path to environment file (auto: .env.mainnet → .env)
    #[arg(long, env = "DSDN_ENV_FILE")]
    pub env_file: Option<String>,
}

// ────────────────────────────────────────────────────────────────────────────
// `status` / `health` query args
// ────────────────────────────────────────────────────────────────────────────

/// Arguments for querying a running node (status, health).
#[derive(Args)]
pub struct QueryArgs {
    /// HTTP port of the running node
    #[arg(long, short = 'p', env = "NODE_HTTP_PORT", default_value_t = 45832)]
    pub port: u16,

    /// Host of the running node
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,
}

// ────────────────────────────────────────────────────────────────────────────
// `store` subcommands
// ────────────────────────────────────────────────────────────────────────────

#[derive(Subcommand)]
pub enum StoreCommand {
    /// Chunk a file and store locally
    Put(StorePutArgs),

    /// Retrieve a chunk from local storage
    Get(StoreGetArgs),

    /// Check if a chunk exists in local storage
    Has(StoreHasArgs),

    /// Show local storage statistics
    Stats,

    /// Send file chunks to a remote node via gRPC
    Send(StoreSendArgs),

    /// Fetch a chunk from a remote node via gRPC
    Fetch(StoreFetchArgs),
}

#[derive(Args)]
pub struct StorePutArgs {
    /// File to chunk and store
    pub file: String,

    /// Chunk size in bytes
    #[arg(long, default_value_t = chunker::DEFAULT_CHUNK_SIZE)]
    pub chunk_size: usize,
}

#[derive(Args)]
pub struct StoreGetArgs {
    /// Chunk content hash
    pub hash: String,

    /// Output file path (prints info if omitted)
    #[arg(long, short = 'o')]
    pub output: Option<String>,
}

#[derive(Args)]
pub struct StoreHasArgs {
    /// Chunk content hash
    pub hash: String,
}

#[derive(Args)]
pub struct StoreSendArgs {
    /// Remote node gRPC address (host:port)
    pub grpc_addr: String,

    /// File to send
    pub file: String,
}

#[derive(Args)]
pub struct StoreFetchArgs {
    /// Remote node gRPC address (host:port)
    pub grpc_addr: String,

    /// Chunk content hash to fetch
    pub hash: String,

    /// Output file path (prints info if omitted)
    #[arg(long, short = 'o')]
    pub output: Option<String>,
}

// ════════════════════════════════════════════════════════════════════════════
// INTERNAL NODE CONFIGURATION (built from RunArgs)
// ════════════════════════════════════════════════════════════════════════════

/// Node configuration parsed from clap RunArgs.
#[derive(Debug, Clone)]
pub(crate) struct NodeConfig {
    pub node_id: String,
    pub da_config: DAConfig,
    pub storage_path: String,
    pub storage_capacity_gb: u64,
    pub http_port: u16,
    pub grpc_port: u16,
    pub use_mock_da: bool,
}

impl NodeConfig {
    /// Build configuration from clap RunArgs.
    pub fn from_args(args: &RunArgs) -> Result<Self, String> {
        // Resolve node_id
        let node_id = if args.node_id == "auto" {
            Uuid::new_v4().to_string()
        } else {
            args.node_id.clone()
        };

        // Build DA config
        let da_config = if args.mock_da {
            DAConfig::default()
        } else {
            let rpc_url = args.da_rpc_url.clone().ok_or(
                "Missing --da-rpc-url (or DA_RPC_URL env). Use --mock-da for development."
            )?;
            let namespace_hex = args.da_namespace.clone().ok_or(
                "Missing --da-namespace (or DA_NAMESPACE env). Use --mock-da for development."
            )?;
            let namespace = parse_namespace_hex(&namespace_hex)?;

            DAConfig {
                rpc_url,
                namespace,
                auth_token: args.da_auth_token.clone().filter(|s| !s.trim().is_empty()),
                timeout_ms: args.da_timeout_ms,
                retry_count: args.da_retry_count,
                retry_delay_ms: args.da_retry_delay_ms,
                network: args.da_network.clone(),
                enable_pooling: args.da_enable_pooling,
                max_connections: args.da_max_connections,
                idle_timeout_ms: args.da_idle_timeout_ms,
            }
        };

        // Resolve gRPC port
        let grpc_port = args.grpc_port
            .unwrap_or_else(|| args.http_port.saturating_add(DEFAULT_GRPC_PORT_OFFSET));

        Ok(Self {
            node_id,
            da_config,
            storage_path: args.storage_path.clone(),
            storage_capacity_gb: args.storage_capacity_gb,
            http_port: args.http_port,
            grpc_port,
            use_mock_da: args.mock_da,
        })
    }

    /// Validate configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.node_id.is_empty() {
            return Err("Node ID cannot be empty".to_string());
        }
        if self.storage_path.is_empty() {
            return Err("Storage path cannot be empty".to_string());
        }
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
        if self.da_config.is_mainnet() {
            self.da_config
                .validate_for_production()
                .map_err(|e| format!("Production validation failed: {}", e))?;
        }
        Ok(())
    }
}

/// Parse a 58-character hex namespace string into [u8; 29].
fn parse_namespace_hex(hex_str: &str) -> Result<[u8; 29], String> {
    let hex_str = hex_str.trim();
    if hex_str.len() != 58 {
        return Err(format!(
            "DA namespace must be 58 hex chars (got {}). \
             Example: 0000000000000000000000000000000000000000000064736E6474657374",
            hex_str.len()
        ));
    }
    let mut ns = [0u8; 29];
    for i in 0..29 {
        ns[i] = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16)
            .map_err(|_| format!(
                "Invalid hex at position {}: '{}'",
                i * 2, &hex_str[i * 2..i * 2 + 2]
            ))?;
    }
    Ok(ns)
}

// ════════════════════════════════════════════════════════════════════════════
// ENV FILE LOADING (same pattern as coordinator)
// ════════════════════════════════════════════════════════════════════════════

/// Load environment variables from .env.mainnet or custom env file.
///
/// Priority:
/// 1. `DSDN_ENV_FILE` environment variable (custom path)
/// 2. `.env.mainnet` (production default)
/// 3. `.env` (fallback for development)
pub fn load_env_file() {
    let env_file = env::var("DSDN_ENV_FILE").unwrap_or_else(|_| {
        if Path::new(".env.mainnet").exists() {
            ".env.mainnet".to_string()
        } else if Path::new(".env").exists() {
            ".env".to_string()
        } else {
            ".env.mainnet".to_string()
        }
    });

    match dotenvy::from_filename(&env_file) {
        Ok(path) => {
            env::set_var("_DSDN_LOADED_ENV_FILE", path.display().to_string());
        }
        Err(e) => {
            if !matches!(e, dotenvy::Error::Io(_)) {
                eprintln!("⚠️  Warning: Failed to load {}: {}", env_file, e);
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// NODE STORAGE BACKEND (wraps LocalFsStorage)
// ════════════════════════════════════════════════════════════════════════════

/// Cache duration for storage metrics (30 seconds).
const STORAGE_METRICS_CACHE_SECS: u64 = 30;

/// Real storage backend wrapping `LocalFsStorage` from dsdn_storage.
pub(crate) struct NodeStorageBackend {
    local_fs: Arc<LocalFsStorage>,
    objects_dir: PathBuf,
    cached_used: RwLock<(u64, Instant)>,
    capacity_bytes: u64,
}

impl NodeStorageBackend {
    pub fn new(storage_path: &str, capacity_gb: u64) -> Result<Self, String> {
        let local_fs = Arc::new(
            LocalFsStorage::new(storage_path)
                .map_err(|e| format!("Failed to initialize LocalFsStorage: {}", e))?
        );
        let objects_dir = PathBuf::from(storage_path).join("objects");
        let initial_used = calculate_dir_size(&objects_dir);
        let capacity_bytes = capacity_gb * 1024 * 1024 * 1024;

        Ok(Self {
            local_fs,
            objects_dir,
            cached_used: RwLock::new((initial_used, Instant::now())),
            capacity_bytes,
        })
    }

    pub fn local_fs(&self) -> &Arc<LocalFsStorage> {
        &self.local_fs
    }

    pub fn invalidate_cache(&self) {
        let mut cache = self.cached_used.write();
        cache.1 = Instant::now() - Duration::from_secs(STORAGE_METRICS_CACHE_SECS + 1);
    }

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
    #[allow(dead_code)]
    da: Arc<dyn DALayer>,
    latest_sequence: RwLock<u64>,
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
                    warn!("DA unavailable, retrying in {}s...", retry_delay.as_secs());
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
// These are DATA PLANE operations — NOT control plane instructions.
// Control plane commands come exclusively via DA events.

#[derive(Clone)]
struct StorageHttpState {
    store: Arc<LocalFsStorage>,
    objects_dir: PathBuf,
}

#[derive(Debug, serde::Deserialize)]
struct HashParam {
    hash: String,
}

#[derive(Debug, Serialize)]
struct ChunkResponse {
    hash: String,
    size: usize,
    status: String,
}

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
    st.store.put_chunk(&hash, &body).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(ChunkResponse { hash, size, status: "ok".to_string() }))
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
        // Backward compatibility aliases
        .route("/chunks/:hash", get(http_get_chunk))
        .route("/has/:hash", get(http_has_chunk))
        .route("/chunks", axum_put(http_put_chunk))
        .with_state(state)
}

// ════════════════════════════════════════════════════════════════════════════
// HTTP SERVER (AXUM)
// ════════════════════════════════════════════════════════════════════════════

async fn start_axum_server(addr: SocketAddr, router: Router, shutdown: Arc<Notify>) {
    info!("🌐 Starting HTTP server on http://{}", addr);
    info!("   Observability: /health /ready /info /status /state /da/status /metrics");
    info!("   Storage:       /storage/chunk/:hash /storage/chunk /storage/has/:hash /storage/stats");

    let listener = match bind_with_reuse(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("❌ Failed to bind HTTP server to {}: {}", addr, e);
            error!("   Hint: kill the previous node process, or use a different --http-port");
            return;
        }
    };

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

/// Bind TCP listener with SO_REUSEADDR and retry (handles Windows TIME_WAIT).
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
                    warn!("Port {} busy (attempt {}/{}): {} — retrying in 2s...",
                        addr.port(), attempt, max_attempts, e);
                    tokio::time::sleep(Duration::from_secs(2)).await;
                } else {
                    return Err(format!("port {} still busy after {} attempts: {}",
                        addr.port(), max_attempts, e));
                }
            }
        }
    }
    unreachable!()
}

fn try_bind_reuse(addr: SocketAddr) -> Result<tokio::net::TcpListener, String> {
    let domain = if addr.is_ipv4() { socket2::Domain::IPV4 } else { socket2::Domain::IPV6 };
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
// COMMAND IMPLEMENTATIONS
// ════════════════════════════════════════════════════════════════════════════

/// `version` — print version string.
pub fn cmd_version() {
    println!("{} v{}", NODE_NAME, NODE_VERSION);
}

/// `info` — show build and configuration info.
pub fn cmd_info() {
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

/// `status` — query a running node's /status endpoint.
pub async fn cmd_status(args: &QueryArgs) {
    let url = format!("http://{}:{}/status", args.host, args.port);
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
                    eprintln!("Failed to read response: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to connect to node at {}:{}: {}", args.host, args.port, e);
            eprintln!("Is the node running? Start with: dsdn-node run --mock-da");
            std::process::exit(1);
        }
    }
}

/// `health` — query a running node's /health endpoint.
pub async fn cmd_health(args: &QueryArgs) {
    let url = format!("http://{}:{}/health", args.host, args.port);
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
                    eprintln!("Failed to read response: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to connect to node at {}:{}: {}", args.host, args.port, e);
            eprintln!("Is the node running? Start with: dsdn-node run --mock-da");
            std::process::exit(1);
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// STORE SUBCOMMAND IMPLEMENTATIONS
// ════════════════════════════════════════════════════════════════════════════

/// Resolve storage path from env or default.
fn resolve_storage_path() -> String {
    env::var("NODE_STORAGE_PATH").unwrap_or_else(|_| "./data".to_string())
}

/// Dispatch store subcommands.
pub async fn cmd_store(cmd: StoreCommand) {
    match cmd {
        StoreCommand::Put(args)   => cmd_store_put(&args),
        StoreCommand::Get(args)   => cmd_store_get(&args),
        StoreCommand::Has(args)   => cmd_store_has(&args),
        StoreCommand::Stats       => cmd_store_stats(),
        StoreCommand::Send(args)  => cmd_store_send(&args).await,
        StoreCommand::Fetch(args) => cmd_store_fetch(&args).await,
    }
}

fn cmd_store_put(args: &StorePutArgs) {
    let file = Path::new(&args.file);
    if !file.exists() {
        eprintln!("❌ File not found: {:?}", file);
        std::process::exit(1);
    }

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

    let chunks = match chunker::chunk_reader(&mut f, args.chunk_size) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("❌ Failed to chunk file: {}", e);
            std::process::exit(1);
        }
    };

    println!("📦 Storing {} chunks (chunk_size = {}) from {:?}",
        chunks.len(), args.chunk_size, file);
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

fn cmd_store_get(args: &StoreGetArgs) {
    let storage_path = resolve_storage_path();
    let store = match LocalFsStorage::new(&storage_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("❌ Failed to open storage at {}: {}", storage_path, e);
            std::process::exit(1);
        }
    };

    match store.get_chunk(&args.hash) {
        Ok(Some(data)) => {
            if let Some(ref output) = args.output {
                if let Err(e) = std::fs::write(output, &data) {
                    eprintln!("❌ Failed to write to {}: {}", output, e);
                    std::process::exit(1);
                }
                println!("✅ Chunk {} ({} bytes) written to {}", args.hash, data.len(), output);
            } else {
                println!("✅ Chunk found: {} ({} bytes)", args.hash, data.len());
                if data.len() <= 1024 {
                    if let Ok(text) = std::str::from_utf8(&data) {
                        println!("Content (text): {}", text);
                    } else {
                        println!("Content (hex): {}", hex_preview(&data, 64));
                    }
                } else {
                    println!("Content (hex, first 64 bytes): {}", hex_preview(&data, 64));
                }
            }
        }
        Ok(None) => {
            eprintln!("❌ Chunk not found: {}", args.hash);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("❌ Storage error: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_store_has(args: &StoreHasArgs) {
    let storage_path = resolve_storage_path();
    let store = match LocalFsStorage::new(&storage_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("❌ Failed to open storage at {}: {}", storage_path, e);
            std::process::exit(1);
        }
    };

    match store.has_chunk(&args.hash) {
        Ok(true) => println!("✅ Chunk exists: {}", args.hash),
        Ok(false) => {
            println!("❌ Chunk not found: {}", args.hash);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("❌ Storage error: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_store_stats() {
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

async fn cmd_store_send(args: &StoreSendArgs) {
    let file = Path::new(&args.file);
    if !file.exists() {
        eprintln!("❌ File not found: {:?}", file);
        std::process::exit(1);
    }

    let mut f = std::fs::File::open(file).expect("open file");
    let chunks = chunker::chunk_reader(&mut f, chunker::DEFAULT_CHUNK_SIZE).expect("chunk file");

    println!("📤 Sending {} chunks to {}", chunks.len(), args.grpc_addr);
    for (i, chunk) in chunks.into_iter().enumerate() {
        let h = sha256_hex(&chunk);
        match rpc::client_put(format!("http://{}", args.grpc_addr), h.clone(), chunk).await {
            Ok(returned) => println!("  chunk {:>4}: sent → {}", i, returned),
            Err(e) => {
                eprintln!("❌ Failed to send chunk {}: {}", i, e);
                std::process::exit(1);
            }
        }
    }
    println!("✅ File transfer done.");
}

async fn cmd_store_fetch(args: &StoreFetchArgs) {
    match rpc::client_get(format!("http://{}", args.grpc_addr), args.hash.clone()).await {
        Ok(Some(data)) => {
            if let Some(ref output) = args.output {
                std::fs::write(output, &data).expect("write output");
                println!("✅ Fetched chunk {} ({} bytes) → {}", args.hash, data.len(), output);
            } else {
                println!("✅ Fetched chunk {} ({} bytes)", args.hash, data.len());
                if data.len() <= 1024 {
                    if let Ok(text) = std::str::from_utf8(&data) {
                        println!("Content: {}", text);
                    }
                }
            }
        }
        Ok(None) => {
            eprintln!("❌ Chunk not found on remote: {}", args.hash);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("❌ gRPC error: {}", e);
            std::process::exit(1);
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════════════════════════════════

pub(crate) fn hex_preview(data: &[u8], max: usize) -> String {
    let limit = data.len().min(max);
    let hex: String = data[..limit].iter().map(|b| format!("{:02x}", b)).collect();
    if data.len() > max { format!("{}...", hex) } else { hex }
}

pub(crate) fn human_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;

    if bytes >= GIB { format!("{:.2} GiB", bytes as f64 / GIB as f64) }
    else if bytes >= MIB { format!("{:.2} MiB", bytes as f64 / MIB as f64) }
    else if bytes >= KIB { format!("{:.2} KiB", bytes as f64 / KIB as f64) }
    else { format!("{} B", bytes) }
}

// ════════════════════════════════════════════════════════════════════════════
// RUN SUBCOMMAND (main node loop)
// ════════════════════════════════════════════════════════════════════════════

/// Execute `run` subcommand — start the full node server.
pub async fn cmd_run(args: &RunArgs) {
    // Build config from clap args
    let config = match NodeConfig::from_args(args) {
        Ok(c) => c,
        Err(e) => {
            error!("Configuration error: {}", e);
            error!("");
            error!("Required (or use --mock-da):");
            error!("  --da-rpc-url <URL>        Celestia RPC endpoint");
            error!("  --da-namespace <HEX>      58-character hex namespace");
            error!("  --da-auth-token <TOKEN>   Auth token (mainnet)");
            error!("");
            error!("Run 'dsdn-node run --help' for all options.");
            std::process::exit(1);
        }
    };

    if let Err(e) = config.validate() {
        error!("Configuration error: {}", e);
        std::process::exit(1);
    }

    info!("═══════════════════════════════════════════════════════════════");
    info!("               DSDN Node v{} (Mainnet Ready)                   ", NODE_VERSION);
    info!("═══════════════════════════════════════════════════════════════");

    if let Ok(loaded_file) = env::var("_DSDN_LOADED_ENV_FILE") {
        info!("Env File:     {}", loaded_file);
    }

    info!("Node ID:      {}", config.node_id);
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
                error!("Troubleshooting:");
                error!("  1. Ensure Celestia light node is running");
                error!("  2. Verify --da-rpc-url is correct");
                error!("  3. Check --da-auth-token is valid");
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
        match NodeStorageBackend::new(&config.storage_path, config.storage_capacity_gb) {
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
            storage_capacity_gb: 100,
            http_port: 45832,
            grpc_port: 9080,
            use_mock_da: true,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_empty_storage_path() {
        let config = NodeConfig {
            node_id: "node-1".to_string(),
            da_config: DAConfig::default(),
            storage_path: String::new(),
            storage_capacity_gb: 100,
            http_port: 45832,
            grpc_port: 9080,
            use_mock_da: true,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_zero_port() {
        let config = NodeConfig {
            node_id: "node-1".to_string(),
            da_config: DAConfig::default(),
            storage_path: "./data".to_string(),
            storage_capacity_gb: 100,
            http_port: 0,
            grpc_port: 9080,
            use_mock_da: true,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_same_ports() {
        let config = NodeConfig {
            node_id: "node-1".to_string(),
            da_config: DAConfig::default(),
            storage_path: "./data".to_string(),
            storage_capacity_gb: 100,
            http_port: 45832,
            grpc_port: 45832,
            use_mock_da: true,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_valid() {
        let config = NodeConfig {
            node_id: "node-1".to_string(),
            da_config: DAConfig::default(),
            storage_path: "./data".to_string(),
            storage_capacity_gb: 100,
            http_port: 45832,
            grpc_port: 9080,
            use_mock_da: true,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_node_storage_backend() {
        let tmp = tempfile::TempDir::new().expect("tmpdir");
        let backend = NodeStorageBackend::new(
            tmp.path().to_str().unwrap(), 100,
        ).expect("create backend");

        assert_eq!(backend.storage_used_bytes(), 0);
        assert!(backend.storage_capacity_bytes() > 0);

        let data = b"test chunk data";
        let hash = sha256_hex(data);
        backend.local_fs().put_chunk(&hash, data).expect("put");

        backend.invalidate_cache();
        assert!(backend.storage_used_bytes() > 0);

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
    fn test_parse_namespace_hex_valid() {
        let hex = "0000000000000000000000000000000000000000000064736E6474657374";
        let ns = parse_namespace_hex(hex).unwrap();
        assert_eq!(ns.len(), 29);
        assert_eq!(ns[28], 0x74); // 't' in "dsdntest"
    }

    #[test]
    fn test_parse_namespace_hex_invalid_length() {
        assert!(parse_namespace_hex("abc").is_err());
    }

    #[test]
    fn test_parse_namespace_hex_invalid_chars() {
        let bad = "GGGG000000000000000000000000000000000000000064736E6474657374";
        assert!(parse_namespace_hex(bad).is_err());
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

        assert_eq!(calculate_dir_size(dir), 0);

        std::fs::write(dir.join("test.dat"), b"hello world").unwrap();
        assert_eq!(calculate_dir_size(dir), 11);

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