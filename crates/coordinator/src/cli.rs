//! DSDN Coordinator CLI & HTTP Server Entry Point
//!
//! This module contains the HTTP server setup, route handlers, request/response types,
//! DA initialization helpers, and the main() entry point for the coordinator binary.
//!
//! ## Responsibilities
//!
//! - HTTP request/response types (RegisterNodeReq, HealthResponse, etc.)
//! - HTTP route handlers (register_node, health_check, fallback endpoints, etc.)
//! - DA connection testing and initialization helpers
//! - Application startup sequence (main function)
//!
//! ## Architecture
//!
//! All core types (DARouter, DAHealthMonitor, ReconciliationEngine, CoordinatorConfig, etc.)
//! are defined in the main crate root and re-exported for use here.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Router,
    Json,
};
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
// REQUEST/RESPONSE TYPES
// ════════════════════════════════════════════════════════════════════════════

/// Request body for registering a node
#[derive(Deserialize)]
pub(crate) struct RegisterNodeReq {
    id: String,
    zone: String,
    addr: String,
    capacity_gb: Option<u64>,
}

/// Request body for registering an object
#[derive(Deserialize)]
pub(crate) struct RegisterObjectReq {
    hash: String,
    size: u64,
}

/// Query params for placement endpoint
#[derive(Deserialize)]
pub(crate) struct PlacementQuery {
    rf: Option<usize>,
}

/// Request body for replica operations
#[derive(Deserialize)]
pub(crate) struct ReplicaReq {
    hash: String,
    node_id: String,
}

/// Health response with optional metrics
#[derive(Serialize)]
pub(crate) struct HealthResponse {
    status: String,
    da_available: bool,
    da_health: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    metrics: Option<MetricsInfo>,
}

/// Metrics info for health endpoint
#[derive(Serialize)]
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
// HTTP HANDLERS
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

    // Get metrics and convert to serializable struct
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

/// Readiness check - returns 200 only if fully operational
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

/// GET /fallback/status - Returns current fallback status.
///
/// Response includes:
/// - current_status: DAStatus
/// - fallback_active: bool
/// - fallback_reason: Option<String>
/// - pending_reconcile_count: u64
/// - last_fallback_at: Option<u64>
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

/// GET /fallback/pending - Returns list of pending blobs awaiting reconciliation.
///
/// Does NOT return raw blob data, only metadata.
pub(crate) async fn get_pending_blobs(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<PendingBlobInfo>> {
    let reconcile = state.reconciliation_engine();
    Json(reconcile.get_pending_blobs())
}

/// POST /fallback/reconcile - Triggers manual reconciliation.
///
/// This endpoint:
/// - Calls ReconciliationEngine::reconcile()
/// - Does NOT spawn background tasks
/// - Returns ReconcileReport directly
///
/// Returns HTTP 500 if reconciliation fails critically.
pub(crate) async fn trigger_reconcile(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ReconcileReport>, (StatusCode, Json<Value>)> {
    let reconcile = state.reconciliation_engine();

    let report = reconcile.reconcile().await;

    // If reconciliation failed critically (not just individual blobs)
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

/// GET /fallback/consistency - Verifies state consistency.
///
/// This is a READ-ONLY operation that does NOT modify state.
pub(crate) async fn get_consistency_report(
    State(state): State<Arc<AppState>>,
) -> Json<ConsistencyReport> {
    let reconcile = state.reconciliation_engine();
    Json(reconcile.verify_state_consistency())
}

// ════════════════════════════════════════════════════════════════════════════
// DA CONNECTION TEST
// ════════════════════════════════════════════════════════════════════════════

/// Test DA connection at startup.
///
/// Performs a health check with retry logic.
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
///
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
    // For now, use MockDA as placeholder
    info!("  📦 Initializing Secondary DA (QuorumDA placeholder)...");
    info!("  ✅ Secondary DA initialized (MockDA placeholder)");
    Some(Arc::new(MockDA::new()))
}

/// Initialize emergency DA from config.
///
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
    // For now, use MockDA as placeholder
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
        .route("/placement/{hash}", get(placement))
        .route("/object/register", post(register_object))
        .route("/object/{hash}", get(get_object))
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
// MAIN (14A.1A.36)
// ════════════════════════════════════════════════════════════════════════════

#[tokio::main]
pub async fn main() {
    // ═══════════════════════════════════════════════════════════════════════
    // Step 0: Load environment from .env.mainnet (default) or custom env file
    // ═══════════════════════════════════════════════════════════════════════
    
    // Priority order for env file loading:
    // 1. DSDN_ENV_FILE environment variable (custom path)
    // 2. .env.mainnet (production default - DSDN defaults to mainnet)
    // 3. .env (fallback for development)
    let env_file = std::env::var("DSDN_ENV_FILE").unwrap_or_else(|_| {
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
            // Will log after tracing is initialized
            std::env::set_var("_DSDN_LOADED_ENV_FILE", path.display().to_string());
        }
        Err(e) => {
            // Check if it's just file not found (acceptable) vs other errors
            if !matches!(e, dotenvy::Error::Io(_)) {
                eprintln!("⚠️  Warning: Failed to load {}: {}", env_file, e);
            }
            // Continue without env file - will use environment variables directly
        }
    }

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_target(false)
        .init();

    // Log which env file was loaded (if any)
    if let Ok(loaded_file) = std::env::var("_DSDN_LOADED_ENV_FILE") {
        info!("📁 Loaded configuration from: {}", loaded_file);
    }

    info!("═══════════════════════════════════════════════════════════════");
    info!("              DSDN Coordinator (Mainnet Ready)                  ");
    info!("           DARouter Integration (14A.1A.36)                     ");
    info!("═══════════════════════════════════════════════════════════════");

    // ═══════════════════════════════════════════════════════════════════════
    // Step 1: Load CoordinatorConfig (including fallback config)
    // ═══════════════════════════════════════════════════════════════════════

    let config = match CoordinatorConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            error!("Configuration error: {}", e);
            error!("");
            error!("Required environment variables:");
            error!("  DA_RPC_URL       - Celestia light node RPC endpoint");
            error!("  DA_NAMESPACE     - 58-character hex namespace");
            error!("  DA_AUTH_TOKEN    - Authentication token (required for mainnet)");
            error!("");
            error!("Optional (Primary DA):");
            error!("  DA_NETWORK       - Network identifier (default: mainnet, options: mocha, local)");
            error!("  DA_TIMEOUT_MS    - Operation timeout (default: 30000)");
            error!("  USE_MOCK_DA      - Use mock DA for development (default: false)");
            error!("");
            error!("Environment file loading (automatic):");
            error!("  DSDN_ENV_FILE    - Custom env file path (default: .env.mainnet)");
            error!("");
            error!("Optional (Fallback DA):");
            error!("  ENABLE_FALLBACK  - Enable fallback DA (default: false)");
            error!("  FALLBACK_DA_TYPE - Fallback type: none, quorum, emergency");
            error!("  QUORUM_VALIDATORS      - Comma-separated validator addresses");
            error!("  QUORUM_THRESHOLD       - Quorum percentage 1-100 (default: 67)");
            error!("  EMERGENCY_DA_URL       - Emergency DA endpoint URL");
            error!("");
            error!("Optional (Reconciliation):");
            error!("  RECONCILE_BATCH_SIZE    - Batch size (default: 10)");
            error!("  RECONCILE_MAX_RETRIES   - Max retries (default: 3)");
            error!("  RECONCILE_RETRY_DELAY_MS - Retry delay ms (default: 1000)");
            error!("  RECONCILE_PARALLEL      - Parallel mode (default: false)");
            error!("");
            error!("Optional (HTTP Server):");
            error!("  COORDINATOR_HOST - HTTP server host (default: 127.0.0.1)");
            error!("  COORDINATOR_PORT - HTTP server port (default: 45831)");
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

    // Display fallback configuration
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

    // Display reconciliation config
    info!("Reconcile:    batch={}, retries={}, parallel={}",
        config.reconciliation_config.batch_size,
        config.reconciliation_config.max_retries,
        config.reconciliation_config.parallel_reconcile
    );

    info!("═══════════════════════════════════════════════════════════════");

    // ═══════════════════════════════════════════════════════════════════════
    // Step 2: Initialize PRIMARY DA (Celestia) - REQUIRED
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
                error!("  2. Verify DA_RPC_URL is correct");
                error!("  3. Check DA_AUTH_TOKEN is valid");
                error!("  4. Verify network connectivity");
                std::process::exit(1);
            }
        }
    };

    // Test primary DA connection
    if let Err(e) = test_da_connection(primary_da.as_ref()).await {
        error!("❌ Primary DA connection test failed: {}", e);

        if config.da_config.network != "mainnet" {
            warn!("⚠️ Primary DA unavailable - will rely on fallback if configured");
        } else {
            error!("Cannot start coordinator on mainnet without Primary DA connection");
            std::process::exit(1);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Step 3: Initialize SECONDARY DA (QuorumDA) - if enabled
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
    // Step 4: Initialize EMERGENCY DA - if enabled
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
    // Step 7: Create ReconciliationEngine (14A.1A.38) - BEFORE monitoring starts
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

    // Build HTTP router
    let app = build_router(state);

    // Start HTTP server
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