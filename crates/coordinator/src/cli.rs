//! DSDN Coordinator CLI Entry Point
//!
//! This module contains the CLI argument definitions (via `clap`), HTTP server setup,
//! route handlers, request/response types, DA initialization helpers, and the main()
//! entry point for the coordinator binary.
//!
//! ## Architecture
//!
//! The coordinator exposes two interfaces:
//!
//! 1. **`serve`** subcommand — Starts the HTTP server with all configuration
//!    provided as CLI flags (environment variables serve as fallback).
//!
//! 2. **Management subcommands** (`node`, `object`, `replica`, `fallback`, `health`,
//!    `ready`, `schedule`) — CLI clients that connect to a running coordinator
//!    instance and execute operations via HTTP.
//!
//! ## Usage Examples
//!
//! ```bash
//! # Start coordinator server (CLI flags override env vars)
//! dsdn-coordinator serve \
//!     --da-rpc-url http://localhost:26658 \
//!     --da-namespace 0000000000000000000000000000000000000000000000000000000000 \
//!     --da-auth-token <TOKEN> \
//!     --da-network mocha \
//!     --host 0.0.0.0 \
//!     --port 45831
//!
//! # Start with mock DA for development
//! dsdn-coordinator serve --mock-da
//!
//! # Node management
//! dsdn-coordinator node register --id node-1 --zone us-east --addr 10.0.0.1:9000
//! dsdn-coordinator node list
//!
//! # Object operations
//! dsdn-coordinator object register --hash abc123 --size 1024
//! dsdn-coordinator object get abc123
//! dsdn-coordinator object placement abc123 --rf 3
//!
//! # Replica management
//! dsdn-coordinator replica mark-missing --hash abc123 --node-id node-1
//! dsdn-coordinator replica mark-healed --hash abc123 --node-id node-1
//!
//! # Workload scheduling
//! dsdn-coordinator schedule --id job-1 --cpu 4 --mem 8 --disk 100
//!
//! # Health & readiness
//! dsdn-coordinator health
//! dsdn-coordinator ready
//!
//! # Fallback DA management
//! dsdn-coordinator fallback status
//! dsdn-coordinator fallback pending
//! dsdn-coordinator fallback reconcile
//! dsdn-coordinator fallback consistency
//! ```

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Router,
    Json,
};
use clap::{Parser, Subcommand, Args};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn, Level};
use serde_json::{Value, json};
use tokio::task::JoinHandle;

use dsdn_common::{CelestiaDA, DAError, DAHealthStatus, DALayer, MockDA};
use dsdn_common::da::DAMetricsSnapshot;
use dsdn_coordinator::{Coordinator, NodeInfo, Workload, ReconciliationConfig};

use crate::{
    AppState, CoordinatorConfig, DAHealthMonitor, DARouter, DARouterConfig, DARouterMetrics,
    FallbackDAType, FallbackStatusResponse, PendingBlobInfo, ReconcileReport, ConsistencyReport,
    ReconciliationEngine, RoutingState,
};
use crate::handlers;

// ════════════════════════════════════════════════════════════════════════════
// CLI DEFINITIONS (clap)
// ════════════════════════════════════════════════════════════════════════════

/// DSDN Coordinator — Distributed Storage and Data Network
///
/// Manages node registration, object placement, DA routing, and fallback
/// reconciliation for the DSDN network.
#[derive(Parser)]
#[command(
    name = "dsdn-coordinator",
    version,
    about = "DSDN Coordinator — Distributed Storage and Data Network",
    long_about = "Manages node registration, object placement, DA routing, \
                  and fallback reconciliation for the DSDN network.\n\n\
                  Running without a subcommand defaults to 'serve' (starts the server).\n\
                  Use management subcommands to interact with a running coordinator instance."
)]
pub struct Cli {
    /// Coordinator server URL for management subcommands
    #[arg(
        long,
        global = true,
        default_value = "http://127.0.0.1:45831",
        env = "DSDN_COORDINATOR_URL",
        help = "URL of the running coordinator (for management commands)"
    )]
    pub coordinator_url: String,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Start the coordinator HTTP server
    Serve(ServeArgs),

    /// Node management operations
    #[command(subcommand)]
    Node(NodeCommand),

    /// Object storage operations
    #[command(subcommand)]
    Object(ObjectCommand),

    /// Replica management operations
    #[command(subcommand)]
    Replica(ReplicaCommand),

    /// Schedule a workload on the cluster
    Schedule(ScheduleArgs),

    /// Check coordinator health status
    Health,

    /// Check coordinator readiness
    Ready,

    /// Fallback DA management
    #[command(subcommand)]
    Fallback(FallbackCommand),
}

// ────────────────────────────────────────────────────────────────────────────
// Serve subcommand args
// ────────────────────────────────────────────────────────────────────────────

/// Arguments for the `serve` subcommand — starts the coordinator HTTP server.
///
/// All flags have environment variable fallbacks. CLI flags take precedence.
#[derive(Args)]
pub struct ServeArgs {
    // ── Primary DA ──────────────────────────────────────────────────────
    /// Celestia light node RPC endpoint
    #[arg(long, env = "DA_RPC_URL", required_unless_present = "mock_da")]
    pub da_rpc_url: Option<String>,

    /// DA namespace (58-character hex string)
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

    /// Maximum DA connections (connection pooling)
    #[arg(long, env = "DA_MAX_CONNECTIONS", default_value_t = 5)]
    pub da_max_connections: u16,

    /// DA idle connection timeout in milliseconds
    #[arg(long, env = "DA_IDLE_TIMEOUT_MS", default_value_t = 60000)]
    pub da_idle_timeout_ms: u64,

    /// Enable DA connection pooling
    #[arg(long, env = "DA_ENABLE_POOLING", default_value_t = true)]
    pub da_enable_pooling: bool,

    /// DA max retries per operation
    #[arg(long, env = "DA_RETRY_COUNT", default_value_t = 3)]
    pub da_retry_count: u8,

    /// DA retry delay in milliseconds
    #[arg(long, env = "DA_RETRY_DELAY_MS", default_value_t = 1000)]
    pub da_retry_delay_ms: u64,

    /// Use mock DA layer for development (skips real Celestia connection)
    #[arg(long, env = "USE_MOCK_DA", default_value_t = false)]
    pub mock_da: bool,

    // ── HTTP Server ─────────────────────────────────────────────────────
    /// HTTP server bind host
    #[arg(long, env = "COORDINATOR_HOST", default_value = "127.0.0.1")]
    pub host: String,

    /// HTTP server bind port
    #[arg(long, env = "COORDINATOR_PORT", default_value_t = 45831)]
    pub port: u16,

    // ── Fallback DA ─────────────────────────────────────────────────────
    /// Enable fallback DA layer
    #[arg(long, env = "ENABLE_FALLBACK", default_value_t = false)]
    pub enable_fallback: bool,

    /// Fallback DA type: none, quorum, emergency
    #[arg(long, env = "FALLBACK_DA_TYPE", default_value = "none")]
    pub fallback_da_type: String,

    /// Comma-separated validator addresses for QuorumDA
    #[arg(long, env = "QUORUM_VALIDATORS", value_delimiter = ',')]
    pub quorum_validators: Option<Vec<String>>,

    /// Quorum percentage threshold (1-100)
    #[arg(long, env = "QUORUM_THRESHOLD", default_value_t = 67)]
    pub quorum_threshold: u8,

    /// Quorum signature collection timeout in milliseconds
    #[arg(long, env = "QUORUM_SIGNATURE_TIMEOUT_MS", default_value_t = 5000)]
    pub quorum_signature_timeout_ms: u64,

    /// Emergency DA endpoint URL
    #[arg(long, env = "EMERGENCY_DA_URL")]
    pub emergency_da_url: Option<String>,

    // ── Reconciliation ──────────────────────────────────────────────────
    /// Reconciliation batch size
    #[arg(long, env = "RECONCILE_BATCH_SIZE", default_value_t = 10)]
    pub reconcile_batch_size: usize,

    /// Max reconciliation retries
    #[arg(long, env = "RECONCILE_MAX_RETRIES", default_value_t = 3)]
    pub reconcile_max_retries: u32,

    /// Reconciliation retry delay in milliseconds
    #[arg(long, env = "RECONCILE_RETRY_DELAY_MS", default_value_t = 1000)]
    pub reconcile_retry_delay_ms: u64,

    /// Enable parallel reconciliation
    #[arg(long, env = "RECONCILE_PARALLEL", default_value_t = false)]
    pub reconcile_parallel: bool,

    // ── Environment ─────────────────────────────────────────────────────
    /// Path to environment file (loaded before CLI parsing for fallback values)
    #[arg(long, env = "DSDN_ENV_FILE")]
    pub env_file: Option<String>,
}

// ────────────────────────────────────────────────────────────────────────────
// Node subcommands
// ────────────────────────────────────────────────────────────────────────────

#[derive(Subcommand)]
pub enum NodeCommand {
    /// Register a new storage node
    Register(NodeRegisterArgs),

    /// List all registered nodes
    List,
}

#[derive(Args)]
pub struct NodeRegisterArgs {
    /// Unique node identifier
    #[arg(long)]
    pub id: String,

    /// Geographic zone (e.g. us-east, ap-southeast)
    #[arg(long)]
    pub zone: String,

    /// Node network address (host:port)
    #[arg(long)]
    pub addr: String,

    /// Storage capacity in GB
    #[arg(long, default_value_t = 100)]
    pub capacity_gb: u64,
}

// ────────────────────────────────────────────────────────────────────────────
// Object subcommands
// ────────────────────────────────────────────────────────────────────────────

#[derive(Subcommand)]
pub enum ObjectCommand {
    /// Register a new object
    Register(ObjectRegisterArgs),

    /// Get object metadata by hash
    Get(ObjectGetArgs),

    /// Get placement nodes for an object hash
    Placement(ObjectPlacementArgs),
}

#[derive(Args)]
pub struct ObjectRegisterArgs {
    /// Object content hash
    #[arg(long)]
    pub hash: String,

    /// Object size in bytes
    #[arg(long)]
    pub size: u64,
}

#[derive(Args)]
pub struct ObjectGetArgs {
    /// Object content hash
    pub hash: String,
}

#[derive(Args)]
pub struct ObjectPlacementArgs {
    /// Object content hash
    pub hash: String,

    /// Replication factor
    #[arg(long, default_value_t = 3)]
    pub rf: usize,
}

// ────────────────────────────────────────────────────────────────────────────
// Replica subcommands
// ────────────────────────────────────────────────────────────────────────────

#[derive(Subcommand)]
pub enum ReplicaCommand {
    /// Mark a replica as missing on a node
    MarkMissing(ReplicaArgs),

    /// Mark a replica as healed on a node
    MarkHealed(ReplicaArgs),
}

#[derive(Args)]
pub struct ReplicaArgs {
    /// Object content hash
    #[arg(long)]
    pub hash: String,

    /// Node identifier
    #[arg(long)]
    pub node_id: String,
}

// ────────────────────────────────────────────────────────────────────────────
// Schedule subcommand
// ────────────────────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct ScheduleArgs {
    /// Workload identifier
    #[arg(long)]
    pub id: String,

    /// Required CPU cores
    #[arg(long)]
    pub cpu: u32,

    /// Required memory in GB
    #[arg(long)]
    pub mem: u64,

    /// Required disk in GB
    #[arg(long)]
    pub disk: u64,
}

// ────────────────────────────────────────────────────────────────────────────
// Fallback subcommands
// ────────────────────────────────────────────────────────────────────────────

#[derive(Subcommand)]
pub enum FallbackCommand {
    /// Show current fallback DA status
    Status,

    /// List pending blobs awaiting reconciliation
    Pending,

    /// Trigger manual reconciliation
    Reconcile,

    /// Run state consistency check
    Consistency,
}

// ════════════════════════════════════════════════════════════════════════════
// HTTP REQUEST/RESPONSE TYPES (for server-side handlers)
// ════════════════════════════════════════════════════════════════════════════

/// Request body for registering a node (HTTP API)
#[derive(Deserialize)]
pub(crate) struct RegisterNodeReq {
    id: String,
    zone: String,
    addr: String,
    capacity_gb: Option<u64>,
}

/// Request body for registering an object (HTTP API)
#[derive(Deserialize)]
pub(crate) struct RegisterObjectReq {
    hash: String,
    size: u64,
}

/// Query params for placement endpoint (HTTP API)
#[derive(Deserialize)]
pub(crate) struct PlacementQuery {
    rf: Option<usize>,
}

/// Request body for replica operations (HTTP API)
#[derive(Deserialize)]
pub(crate) struct ReplicaReq {
    hash: String,
    node_id: String,
}

/// Health response with optional metrics
#[derive(Serialize, Deserialize)]
pub(crate) struct HealthResponse {
    status: String,
    da_available: bool,
    da_health: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    metrics: Option<MetricsInfo>,
}

/// Metrics info for health endpoint
#[derive(Serialize, Deserialize)]
pub(crate) struct MetricsInfo {
    post_count: u64,
    get_count: u64,
    health_check_count: u64,
    error_count: u64,
    retry_count: u64,
    avg_post_latency_us: u64,
    avg_get_latency_us: u64,
}

// ════════════════════════════════════════════════════════════════════════════
// HTTP HANDLERS (for serve mode)
// ════════════════════════════════════════════════════════════════════════════

pub(crate) async fn register_node(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterNodeReq>,
) -> Json<Value> {
    let info = NodeInfo {
        id: payload.id,
        zone: payload.zone,
        addr: payload.addr,
        capacity_gb: payload.capacity_gb.unwrap_or(100),
        meta: serde_json::json!({}),
    };
    state.coordinator.register_node(info);
    Json(json!({"ok": true}))
}

pub(crate) async fn list_nodes(State(state): State<Arc<AppState>>) -> Json<Value> {
    let nodes = state.coordinator.list_nodes();
    Json(json!(nodes))
}

pub(crate) async fn placement(
    Path(hash): Path<String>,
    Query(q): Query<PlacementQuery>,
    State(state): State<Arc<AppState>>,
) -> Json<Value> {
    let rf = q.rf.unwrap_or(3);
    let sel = state.coordinator.placement_for_hash(&hash, rf);
    Json(json!(sel))
}

pub(crate) async fn register_object(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterObjectReq>,
) -> Json<Value> {
    state.coordinator.register_object(payload.hash, payload.size);
    Json(json!({"ok": true}))
}

pub(crate) async fn get_object(
    Path(hash): Path<String>,
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<Value>) {
    match state.coordinator.get_object(&hash) {
        Some(o) => {
            let val = serde_json::to_value(o).unwrap_or_else(|_| json!({}));
            (StatusCode::OK, Json(val))
        }
        None => (StatusCode::NOT_FOUND, Json(json!({"error":"not found"}))),
    }
}

pub(crate) async fn mark_missing(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ReplicaReq>,
) -> Json<Value> {
    state.coordinator.mark_replica_missing(&payload.hash, &payload.node_id);
    Json(json!({"ok": true}))
}

pub(crate) async fn mark_healed(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ReplicaReq>,
) -> Json<Value> {
    state.coordinator.mark_replica_healed(&payload.hash, &payload.node_id);
    Json(json!({"ok": true}))
}

pub(crate) async fn schedule_workload(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<Workload>,
) -> (StatusCode, Json<Value>) {
    match state.coordinator.schedule(&payload) {
        Some(node_id) => (StatusCode::OK, Json(json!({ "node_id": node_id }))),
        None => (StatusCode::NOT_FOUND, Json(json!({ "error": "no suitable node" }))),
    }
}

/// Health check endpoint with DA status via DARouter
pub(crate) async fn health_check(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    let da_status = state.da().health_check().await;
    let da_healthy = matches!(da_status, Ok(DAHealthStatus::Healthy));
    let da_available = state.is_da_available();
    let routing_state = state.routing_state();

    let status = if da_healthy && da_available {
        format!("healthy (routing: {})", routing_state)
    } else if da_available {
        format!("degraded (routing: {})", routing_state)
    } else {
        "unavailable".to_string()
    };

    let metrics = state.da().metrics().map(|m| MetricsInfo {
        post_count: m.post_count,
        get_count: m.get_count,
        health_check_count: m.health_check_count,
        error_count: m.error_count,
        retry_count: m.retry_count,
        avg_post_latency_us: m.avg_post_latency_us,
        avg_get_latency_us: m.avg_get_latency_us,
    });

    Json(HealthResponse {
        status,
        da_available,
        da_health: format!("{:?}", da_status),
        metrics,
    })
}

/// Readiness check — returns 200 only if fully operational
pub(crate) async fn ready_check(State(state): State<Arc<AppState>>) -> StatusCode {
    let da_status = state.da().health_check().await;
    if matches!(da_status, Ok(DAHealthStatus::Healthy)) && state.is_da_available() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

// ════════════════════════════════════════════════════════════════════════════
// FALLBACK HTTP HANDLERS (14A.1A.38)
// ════════════════════════════════════════════════════════════════════════════

/// GET /fallback/status — Returns current fallback status.
pub(crate) async fn get_fallback_status(
    State(state): State<Arc<AppState>>,
) -> Json<FallbackStatusResponse> {
    let health = state.health_monitor();
    let reconcile = state.reconciliation_engine();

    let response = FallbackStatusResponse {
        current_status: health.current_da_status(),
        fallback_active: health.is_fallback_active(),
        fallback_reason: health.get_fallback_reason(),
        pending_reconcile_count: reconcile.pending_count(),
        last_fallback_at: health.get_last_fallback_at(),
    };

    Json(response)
}

/// GET /fallback/pending — Returns list of pending blobs awaiting reconciliation.
pub(crate) async fn get_pending_blobs(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<PendingBlobInfo>> {
    let reconcile = state.reconciliation_engine();
    Json(reconcile.get_pending_blobs())
}

/// POST /fallback/reconcile — Triggers manual reconciliation.
pub(crate) async fn trigger_reconcile(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ReconcileReport>, (StatusCode, Json<Value>)> {
    let reconcile = state.reconciliation_engine();

    let report = reconcile.reconcile().await;

    if !report.success && report.blobs_processed == 0 && !report.errors.is_empty() {
        let error_msg = report.errors.first()
            .cloned()
            .unwrap_or_else(|| "Unknown reconciliation error".to_string());
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "reconciliation_failed",
                "message": error_msg,
                "report": report
            })),
        ));
    }

    Ok(Json(report))
}

/// GET /fallback/consistency — Verifies state consistency (read-only).
pub(crate) async fn get_consistency_report(
    State(state): State<Arc<AppState>>,
) -> Json<ConsistencyReport> {
    let reconcile = state.reconciliation_engine();
    Json(reconcile.verify_state_consistency())
}

// ════════════════════════════════════════════════════════════════════════════
// DA CONNECTION TEST
// ════════════════════════════════════════════════════════════════════════════

/// Test DA connection at startup with retry logic.
pub(crate) async fn test_da_connection(da: &dyn DALayer) -> Result<(), DAError> {
    let max_attempts = 3;
    let retry_delay = Duration::from_secs(2);

    for attempt in 1..=max_attempts {
        info!("Testing DA connection (attempt {}/{})", attempt, max_attempts);

        match da.health_check().await {
            Ok(DAHealthStatus::Healthy) => {
                info!("✅ DA connection healthy");
                return Ok(());
            }
            Ok(DAHealthStatus::Degraded) => {
                warn!("⚠️ DA connection degraded but functional");
                return Ok(());
            }
            Ok(DAHealthStatus::Unavailable) => {
                if attempt < max_attempts {
                    warn!(
                        "DA unavailable, retrying in {} seconds...",
                        retry_delay.as_secs()
                    );
                    tokio::time::sleep(retry_delay).await;
                } else {
                    return Err(DAError::Unavailable);
                }
            }
            Err(e) => {
                if attempt < max_attempts {
                    warn!("DA connection error: {}, retrying...", e);
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
// DA INITIALIZATION HELPERS (14A.1A.36)
// ════════════════════════════════════════════════════════════════════════════

/// Initialize secondary DA (QuorumDA) from config.
/// Returns None if not enabled or initialization fails (graceful).
pub(crate) fn initialize_secondary_da(config: &CoordinatorConfig) -> Option<Arc<dyn DALayer>> {
    if !config.is_fallback_ready() {
        return None;
    }

    if config.fallback_da_type != FallbackDAType::Quorum {
        return None;
    }

    let _quorum_config = match &config.quorum_da_config {
        Some(c) => c,
        None => {
            error!("❌ QuorumDA config missing despite type=Quorum");
            return None;
        }
    };

    // TODO: Replace with actual ValidatorQuorumDA when integrated
    info!("  📦 Initializing Secondary DA (QuorumDA placeholder)...");
    info!("  ✅ Secondary DA initialized (MockDA placeholder)");
    Some(Arc::new(MockDA::new()))
}

/// Initialize emergency DA from config.
/// Returns None if not enabled or initialization fails (graceful).
pub(crate) fn initialize_emergency_da(config: &CoordinatorConfig) -> Option<Arc<dyn DALayer>> {
    if !config.is_fallback_ready() {
        return None;
    }

    if config.fallback_da_type != FallbackDAType::Emergency {
        return None;
    }

    let _emergency_url = match &config.emergency_da_url {
        Some(url) => url,
        None => {
            error!("❌ Emergency DA URL missing despite type=Emergency");
            return None;
        }
    };

    // TODO: Replace with actual EmergencyDA when integrated
    info!("  📦 Initializing Emergency DA (placeholder)...");
    info!("  ✅ Emergency DA initialized (MockDA placeholder)");
    Some(Arc::new(MockDA::new()))
}

// ════════════════════════════════════════════════════════════════════════════
// BUILD HTTP ROUTER
// ════════════════════════════════════════════════════════════════════════════

/// Build the complete HTTP router with all routes.
pub(crate) fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/register", post(register_node))
        .route("/nodes", get(list_nodes))
        .route("/placement/:hash", get(placement))
        .route("/object/register", post(register_object))
        .route("/object/:hash", get(get_object))
        .route("/replica/mark_missing", post(mark_missing))
        .route("/replica/mark_healed", post(mark_healed))
        .route("/schedule", post(schedule_workload))
        .route("/health", get(health_check))
        .route("/ready", get(ready_check))
        .merge(handlers::extended_routes())
        // Fallback HTTP endpoints (14A.1A.38)
        .route("/fallback/status", get(get_fallback_status))
        .route("/fallback/pending", get(get_pending_blobs))
        .route("/fallback/reconcile", post(trigger_reconcile))
        .route("/fallback/consistency", get(get_consistency_report))
        .with_state(state)
}

// ════════════════════════════════════════════════════════════════════════════
// CLI CLIENT HELPERS
// ════════════════════════════════════════════════════════════════════════════

/// HTTP client for management subcommands that talk to a running coordinator.
struct CliClient {
    base_url: String,
    client: reqwest::Client,
}

impl CliClient {
    fn new(base_url: &str) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("Failed to build HTTP client");

        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    async fn get_json(&self, path: &str) -> Result<Value, String> {
        let url = self.url(path);
        let resp = self.client.get(&url)
            .send()
            .await
            .map_err(|e| format!("Connection failed: {} (is the coordinator running at {}?)", e, self.base_url))?;

        let status = resp.status();
        let text = resp.text().await
            .map_err(|e| format!("Failed to read response body from {}: {}", url, e))?;

        let body: Value = serde_json::from_str(&text)
            .map_err(|e| format!("Invalid JSON from GET {} (HTTP {}): {}\nBody: {}", url, status, e, text))?;

        if !status.is_success() {
            return Err(format!("HTTP {} — {}", status, serde_json::to_string_pretty(&body).unwrap_or_default()));
        }

        Ok(body)
    }

    async fn post_json(&self, path: &str, body: &Value) -> Result<Value, String> {
        let url = self.url(path);
        let resp = self.client.post(&url)
            .json(body)
            .send()
            .await
            .map_err(|e| format!("Connection failed: {} (is the coordinator running at {}?)", e, self.base_url))?;

        let status = resp.status();
        let text = resp.text().await
            .map_err(|e| format!("Failed to read response body from {}: {}", url, e))?;

        let body: Value = serde_json::from_str(&text)
            .map_err(|e| format!("Invalid JSON from POST {} (HTTP {}): {}\nBody: {}", url, status, e, text))?;

        if !status.is_success() {
            return Err(format!("HTTP {} — {}", status, serde_json::to_string_pretty(&body).unwrap_or_default()));
        }

        Ok(body)
    }

    /// GET with status code return (for ready check)
    async fn get_status(&self, path: &str) -> Result<u16, String> {
        let resp = self.client.get(self.url(path))
            .send()
            .await
            .map_err(|e| format!("Connection failed: {} (is the coordinator running at {}?)", e, self.base_url))?;

        Ok(resp.status().as_u16())
    }
}

/// Pretty-print a JSON value to stdout.
fn print_json(value: &Value) {
    println!("{}", serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string()));
}

// ════════════════════════════════════════════════════════════════════════════
// CLI COMMAND EXECUTION
// ════════════════════════════════════════════════════════════════════════════

/// Execute a management subcommand (talks to running coordinator via HTTP).
async fn exec_management_command(cli: &Cli) -> Result<(), String> {
    let client = CliClient::new(&cli.coordinator_url);

    match &cli.command {
        // ── Node commands ───────────────────────────────────────────────
        Some(Command::Node(NodeCommand::Register(args))) => {
            let body = json!({
                "id": args.id,
                "zone": args.zone,
                "addr": args.addr,
                "capacity_gb": args.capacity_gb,
            });
            let resp = client.post_json("/register", &body).await?;
            print_json(&resp);
        }

        Some(Command::Node(NodeCommand::List)) => {
            let resp = client.get_json("/nodes").await?;
            print_json(&resp);
        }

        // ── Object commands ─────────────────────────────────────────────
        Some(Command::Object(ObjectCommand::Register(args))) => {
            let body = json!({
                "hash": args.hash,
                "size": args.size,
            });
            let resp = client.post_json("/object/register", &body).await?;
            print_json(&resp);
        }

        Some(Command::Object(ObjectCommand::Get(args))) => {
            let resp = client.get_json(&format!("/object/{}", args.hash)).await?;
            print_json(&resp);
        }

        Some(Command::Object(ObjectCommand::Placement(args))) => {
            let resp = client.get_json(&format!("/placement/{}?rf={}", args.hash, args.rf)).await?;
            print_json(&resp);
        }

        // ── Replica commands ────────────────────────────────────────────
        Some(Command::Replica(ReplicaCommand::MarkMissing(args))) => {
            let body = json!({
                "hash": args.hash,
                "node_id": args.node_id,
            });
            let resp = client.post_json("/replica/mark_missing", &body).await?;
            print_json(&resp);
        }

        Some(Command::Replica(ReplicaCommand::MarkHealed(args))) => {
            let body = json!({
                "hash": args.hash,
                "node_id": args.node_id,
            });
            let resp = client.post_json("/replica/mark_healed", &body).await?;
            print_json(&resp);
        }

        // ── Schedule ────────────────────────────────────────────────────
        Some(Command::Schedule(args)) => {
            let body = json!({
                "id": args.id,
                "cpu": args.cpu,
                "mem": args.mem,
                "disk": args.disk,
            });
            let resp = client.post_json("/schedule", &body).await?;
            print_json(&resp);
        }

        // ── Health ──────────────────────────────────────────────────────
        Some(Command::Health) => {
            let resp = client.get_json("/health").await?;
            print_json(&resp);
        }

        // ── Ready ───────────────────────────────────────────────────────
        Some(Command::Ready) => {
            let status = client.get_status("/ready").await?;
            if status == 200 {
                println!("ready (HTTP 200)");
            } else {
                println!("not ready (HTTP {})", status);
                std::process::exit(1);
            }
        }

        // ── Fallback commands ───────────────────────────────────────────
        Some(Command::Fallback(FallbackCommand::Status)) => {
            let resp = client.get_json("/fallback/status").await?;
            print_json(&resp);
        }

        Some(Command::Fallback(FallbackCommand::Pending)) => {
            let resp = client.get_json("/fallback/pending").await?;
            print_json(&resp);
        }

        Some(Command::Fallback(FallbackCommand::Reconcile)) => {
            let resp = client.post_json("/fallback/reconcile", &json!({})).await?;
            print_json(&resp);
        }

        Some(Command::Fallback(FallbackCommand::Consistency)) => {
            let resp = client.get_json("/fallback/consistency").await?;
            print_json(&resp);
        }

        // Serve and None are handled in main() — should never reach here
        Some(Command::Serve(_)) | None => unreachable!(),
    }

    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════
// SERVE COMMAND: Build CoordinatorConfig from CLI args
// ════════════════════════════════════════════════════════════════════════════

/// Build a CoordinatorConfig from ServeArgs (CLI flags with env fallback).
///
/// This replaces the old `CoordinatorConfig::from_env()` approach for the CLI.
/// CLI flags always take precedence; env vars are used as fallback via clap's `env`.
fn build_config_from_args(args: &ServeArgs) -> Result<CoordinatorConfig, String> {
    // Parse fallback DA type
    let fallback_da_type = match args.fallback_da_type.to_lowercase().as_str() {
        "none" => FallbackDAType::None,
        "quorum" => FallbackDAType::Quorum,
        "emergency" => FallbackDAType::Emergency,
        other => return Err(format!(
            "Invalid --fallback-da-type '{}'. Expected: none, quorum, emergency", other
        )),
    };

    // Build the DA config portion
    // Parse namespace hex string into [u8; 29]
    let namespace_str = args.da_namespace.clone().unwrap_or_default();
    let namespace: [u8; 29] = if namespace_str.is_empty() {
        [0u8; 29]
    } else {
        let hex_str = namespace_str.strip_prefix("0x").unwrap_or(&namespace_str);
        let bytes = hex::decode(hex_str).map_err(|e| {
            format!("Invalid --da-namespace hex: {} (expected 58 hex chars / 29 bytes)", e)
        })?;
        if bytes.len() != 29 {
            return Err(format!(
                "Invalid --da-namespace length: got {} bytes, expected 29 (58 hex chars)",
                bytes.len()
            ));
        }
        let mut arr = [0u8; 29];
        arr.copy_from_slice(&bytes);
        arr
    };

    let da_config = dsdn_common::DAConfig {
        rpc_url: args.da_rpc_url.clone().unwrap_or_default(),
        namespace,
        auth_token: args.da_auth_token.clone(),
        network: args.da_network.clone(),
        timeout_ms: args.da_timeout_ms,
        max_connections: args.da_max_connections,
        idle_timeout_ms: args.da_idle_timeout_ms,
        enable_pooling: args.da_enable_pooling,
        retry_count: args.da_retry_count,
        retry_delay_ms: args.da_retry_delay_ms,
    };

    // Build quorum config if validators provided
    let quorum_da_config = args.quorum_validators.as_ref().map(|validators| {
        crate::QuorumDAConfig {
            validators: validators.clone(),
            quorum_threshold: args.quorum_threshold,
            signature_timeout_ms: args.quorum_signature_timeout_ms,
        }
    });

    // Build reconciliation config
    let reconciliation_config = ReconciliationConfig {
        batch_size: args.reconcile_batch_size,
        max_retries: args.reconcile_max_retries,
        retry_delay_ms: args.reconcile_retry_delay_ms,
        parallel_reconcile: args.reconcile_parallel,
    };

    let config = CoordinatorConfig {
        da_config,
        use_mock_da: args.mock_da,
        host: args.host.clone(),
        port: args.port,
        enable_fallback: args.enable_fallback,
        fallback_da_type,
        quorum_da_config,
        emergency_da_url: args.emergency_da_url.clone(),
        reconciliation_config,
    };

    // Validate: if not mock, rpc_url and namespace must be set
    if !config.use_mock_da {
        if config.da_config.rpc_url.is_empty() {
            return Err(
                "Missing --da-rpc-url (or DA_RPC_URL env). Use --mock-da for development.".into()
            );
        }
        if config.da_config.namespace == [0u8; 29] {
            return Err(
                "Missing --da-namespace (or DA_NAMESPACE env). Use --mock-da for development.".into()
            );
        }
    }

    Ok(config)
}

// ════════════════════════════════════════════════════════════════════════════
// SERVE COMMAND: Start coordinator server
// ════════════════════════════════════════════════════════════════════════════

/// Run the coordinator HTTP server (the `serve` subcommand).
async fn run_serve(args: &ServeArgs) {
    // ═══════════════════════════════════════════════════════════════════════
    // Step 0: Optionally load .env file (for env-var fallback)
    // ═══════════════════════════════════════════════════════════════════════

    if let Some(ref env_path) = args.env_file {
        match dotenvy::from_filename(env_path) {
            Ok(_) => info!("📁 Loaded environment from: {}", env_path),
            Err(e) => warn!("⚠️ Failed to load env file '{}': {}", env_path, e),
        }
    } else {
        // Auto-detect env file (legacy compat)
        let auto_env = if std::path::Path::new(".env.mainnet").exists() {
            Some(".env.mainnet")
        } else if std::path::Path::new(".env").exists() {
            Some(".env")
        } else {
            None
        };

        if let Some(env_path) = auto_env {
            if dotenvy::from_filename(env_path).is_ok() {
                info!("📁 Auto-loaded environment from: {}", env_path);
            }
        }
    }

    info!("═══════════════════════════════════════════════════════════════");
    info!("              DSDN Coordinator (Mainnet Ready)                  ");
    info!("           DARouter Integration (14A.1A.36)                     ");
    info!("═══════════════════════════════════════════════════════════════");

    // ═══════════════════════════════════════════════════════════════════════
    // Step 1: Build CoordinatorConfig from CLI args
    // ═══════════════════════════════════════════════════════════════════════

    let config = match build_config_from_args(args) {
        Ok(c) => c,
        Err(e) => {
            error!("Configuration error: {}", e);
            error!("");
            error!("Usage: dsdn-coordinator serve [OPTIONS]");
            error!("");
            error!("Required (or use --mock-da):");
            error!("  --da-rpc-url <URL>        Celestia light node RPC endpoint");
            error!("  --da-namespace <HEX>      58-character hex namespace");
            error!("  --da-auth-token <TOKEN>   Authentication token (mainnet)");
            error!("");
            error!("Run 'dsdn-coordinator serve --help' for all options.");
            std::process::exit(1);
        }
    };

    // Validate configuration for production
    if config.da_config.is_mainnet() {
        info!("🌐 Running in MAINNET mode");
        if let Err(e) = config.validate_for_production() {
            error!("Production validation failed: {}", e);
            std::process::exit(1);
        }
    } else {
        info!("🔧 Running in {} mode", config.da_config.network);
    }

    // Display configuration
    info!("DA Endpoint:  {}", config.da_config.rpc_url);
    info!("DA Network:   {}", config.da_config.network);
    info!("HTTP Server:  {}:{}", config.host, config.port);

    if config.enable_fallback {
        info!("Fallback DA:  ENABLED (type: {})", config.fallback_da_type);
        if let Some(ref quorum) = config.quorum_da_config {
            info!("  Validators: {} configured", quorum.validators.len());
            info!("  Threshold:  {}%", quorum.quorum_threshold);
        }
        if let Some(ref url) = config.emergency_da_url {
            info!("  Emergency:  {}", url);
        }
    } else {
        info!("Fallback DA:  DISABLED");
    }

    info!("Reconcile:    batch={}, retries={}, parallel={}",
        config.reconciliation_config.batch_size,
        config.reconciliation_config.max_retries,
        config.reconciliation_config.parallel_reconcile
    );

    info!("═══════════════════════════════════════════════════════════════");

    // ═══════════════════════════════════════════════════════════════════════
    // Step 2: Initialize PRIMARY DA (Celestia) — REQUIRED
    // ═══════════════════════════════════════════════════════════════════════

    info!("📦 Initializing Primary DA...");
    let primary_da: Arc<dyn DALayer> = if config.use_mock_da {
        info!("  Using MockDA for development");
        Arc::new(MockDA::new())
    } else {
        info!("  Connecting to Celestia DA...");
        match CelestiaDA::new(config.da_config.clone()) {
            Ok(celestia) => {
                info!("  ✅ Primary DA (Celestia) initialized");
                Arc::new(celestia)
            }
            Err(e) => {
                error!("❌ Failed to initialize Primary DA (Celestia): {}", e);
                error!("");
                error!("Troubleshooting:");
                error!("  1. Ensure Celestia light node is running and synced");
                error!("  2. Verify --da-rpc-url is correct");
                error!("  3. Check --da-auth-token is valid");
                error!("  4. Verify network connectivity");
                std::process::exit(1);
            }
        }
    };

    // Test primary DA connection
    if let Err(e) = test_da_connection(primary_da.as_ref()).await {
        error!("❌ Primary DA connection test failed: {}", e);

        if config.da_config.network != "mainnet" {
            warn!("⚠️ Primary DA unavailable — will rely on fallback if configured");
        } else {
            error!("Cannot start coordinator on mainnet without Primary DA connection");
            std::process::exit(1);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Step 3: Initialize SECONDARY DA (QuorumDA) — if enabled
    // ═══════════════════════════════════════════════════════════════════════

    let secondary_da: Option<Arc<dyn DALayer>> = if config.enable_fallback
        && config.fallback_da_type == FallbackDAType::Quorum
    {
        match initialize_secondary_da(&config) {
            Some(da) => Some(da),
            None => {
                error!("❌ Failed to initialize Secondary DA (QuorumDA)");
                warn!("⚠️ Continuing without secondary fallback");
                None
            }
        }
    } else {
        if config.enable_fallback && config.fallback_da_type == FallbackDAType::Quorum {
            warn!("⚠️ QuorumDA fallback configured but not ready");
        }
        None
    };

    // ═══════════════════════════════════════════════════════════════════════
    // Step 4: Initialize EMERGENCY DA — if enabled
    // ═══════════════════════════════════════════════════════════════════════

    let emergency_da: Option<Arc<dyn DALayer>> = if config.enable_fallback
        && config.fallback_da_type == FallbackDAType::Emergency
    {
        match initialize_emergency_da(&config) {
            Some(da) => Some(da),
            None => {
                error!("❌ Failed to initialize Emergency DA");
                warn!("⚠️ Continuing without emergency fallback");
                None
            }
        }
    } else {
        if config.enable_fallback && config.fallback_da_type == FallbackDAType::Emergency {
            warn!("⚠️ Emergency DA fallback configured but not ready");
        }
        None
    };

    // ═══════════════════════════════════════════════════════════════════════
    // Step 5: Create DAHealthMonitor
    // ═══════════════════════════════════════════════════════════════════════

    info!("🏥 Creating DAHealthMonitor...");
    let router_config = DARouterConfig::default();
    let health_monitor = Arc::new(DAHealthMonitor::new(
        router_config.clone(),
        Arc::clone(&primary_da),
        secondary_da.clone(),
        emergency_da.clone(),
    ));
    info!("  ✅ DAHealthMonitor created");

    // ═══════════════════════════════════════════════════════════════════════
    // Step 6: Create DARouter (primary + optional fallback)
    // ═══════════════════════════════════════════════════════════════════════

    info!("🔀 Creating DARouter...");
    let router_metrics = DARouterMetrics::new();
    let da_router = Arc::new(DARouter::new(
        primary_da,
        secondary_da,
        emergency_da,
        Arc::clone(&health_monitor),
        router_config,
        router_metrics,
    ));

    let fallback_status = if health_monitor.is_secondary_healthy() {
        "secondary"
    } else if health_monitor.is_emergency_healthy() {
        "emergency"
    } else {
        "none"
    };
    info!("  ✅ DARouter created (fallback: {})", fallback_status);

    // ═══════════════════════════════════════════════════════════════════════
    // Step 7: Create ReconciliationEngine (14A.1A.38)
    // ═══════════════════════════════════════════════════════════════════════

    info!("🔄 Creating ReconciliationEngine...");
    let reconciliation_engine = Arc::new(ReconciliationEngine::new(
        Arc::clone(&da_router),
        Arc::clone(&health_monitor),
        config.reconciliation_config.clone(),
    ));
    info!("  ✅ ReconciliationEngine created");

    // ═══════════════════════════════════════════════════════════════════════
    // Step 7.5: Link ReconciliationEngine to DAHealthMonitor (14A.1A.39)
    // ═══════════════════════════════════════════════════════════════════════

    health_monitor.set_reconciliation_engine(Arc::clone(&reconciliation_engine));
    info!("  ✅ ReconciliationEngine linked to DAHealthMonitor for auto-recovery");

    // ═══════════════════════════════════════════════════════════════════════
    // Step 7.6: Start health monitoring loop
    // ═══════════════════════════════════════════════════════════════════════

    info!("🏥 Starting health monitoring...");
    let monitor_handle = health_monitor.start_monitoring();
    info!("  ✅ Health monitoring active (auto_reconcile={})",
        health_monitor.is_auto_reconcile_enabled());

    // ═══════════════════════════════════════════════════════════════════════
    // Step 8: Inject DARouter to AppState
    // ═══════════════════════════════════════════════════════════════════════

    let coordinator = Coordinator::new();
    let state = Arc::new(AppState::new(
        coordinator,
        da_router,
        Some(monitor_handle),
        reconciliation_engine,
    ));
    info!("  ✅ AppState initialized with DARouter and ReconciliationEngine");

    // ═══════════════════════════════════════════════════════════════════════
    // Step 9: Run application runtime
    // ═══════════════════════════════════════════════════════════════════════

    let app = build_router(state);

    let addr: SocketAddr = format!("{}:{}", config.host, config.port)
        .parse()
        .unwrap_or_else(|_| {
            error!("Invalid address: {}:{}", config.host, config.port);
            std::process::exit(1);
        });

    info!("");
    info!("═══════════════════════════════════════════════════════════════");
    info!("🚀 Coordinator listening on http://{}", addr);
    info!("   Primary DA:     ready");
    info!("   Health Monitor: active");
    info!("═══════════════════════════════════════════════════════════════");
    info!("");

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind to {}: {}", addr, e);
            std::process::exit(1);
        }
    };

    if let Err(e) = axum::serve(listener, app).await {
        error!("Server error: {}", e);
        std::process::exit(1);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// MAIN ENTRY POINT (14A.1A.36)
// ════════════════════════════════════════════════════════════════════════════

#[tokio::main]
pub async fn main() {
    // Pre-load env file before clap parsing so env fallbacks work.
    // We check DSDN_ENV_FILE first, then auto-detect.
    let env_file_hint = std::env::var("DSDN_ENV_FILE").ok();
    let env_path = env_file_hint
        .as_deref()
        .or_else(|| {
            if std::path::Path::new(".env.mainnet").exists() {
                Some(".env.mainnet")
            } else if std::path::Path::new(".env").exists() {
                Some(".env")
            } else {
                None
            }
        });

    if let Some(path) = env_path {
        let _ = dotenvy::from_filename(path);
    }

    // Parse CLI arguments (env vars serve as fallback via clap `env` attribute)
    let cli = Cli::parse();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_target(false)
        .init();

    // Dispatch to serve or management command
    match &cli.command {
        Some(Command::Serve(args)) => {
            run_serve(args).await;
        }
        None => {
            // No subcommand given — default to serve (backward compatible).
            // Re-parse with "serve" injected so env-var fallbacks still apply.
            info!("No subcommand specified, defaulting to 'serve'...");
            let mut args: Vec<String> = std::env::args().collect();
            args.insert(1, "serve".to_string());
            let cli_serve = Cli::parse_from(args);
            if let Some(Command::Serve(serve_args)) = cli_serve.command {
                run_serve(&serve_args).await;
            }
        }
        _ => {
            // Management subcommands — talk to a running coordinator
            if let Err(e) = exec_management_command(&cli).await {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    }
}