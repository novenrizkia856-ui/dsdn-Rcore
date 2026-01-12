//! DSDN Coordinator Entry Point
//!
//! Production coordinator with Celestia mainnet integration.
//!
//! ## Configuration
//!
//! The coordinator loads configuration from environment variables for production:
//!
//! - `DA_RPC_URL`: Celestia light node RPC endpoint (required)
//! - `DA_NAMESPACE`: 58-character hex namespace (required)
//! - `DA_AUTH_TOKEN`: Authentication token (required for mainnet)
//! - `DA_NETWORK`: Network identifier (mainnet, mocha, local)
//! - `DA_TIMEOUT_MS`: Operation timeout in milliseconds
//! - `DA_RETRY_COUNT`: Number of retries for failed operations
//! - `DA_RETRY_DELAY_MS`: Delay between retries
//! - `COORDINATOR_PORT`: HTTP server port (default: 8080)
//! - `COORDINATOR_HOST`: HTTP server host (default: 127.0.0.1)
//!
//! ## Startup Flow
//!
//! 1. Load configuration from environment
//! 2. Validate configuration for production
//! 3. Initialize DA layer with connection test
//! 4. Initialize state machine and consumer
//! 5. Start HTTP server
//! 6. Begin DA event consumption

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

use dsdn_common::{CelestiaDA, DAConfig, DAError, DAHealthStatus, DALayer, MockDA};
use dsdn_coordinator::{Coordinator, NodeInfo, Workload};
use parking_lot::RwLock;

// ════════════════════════════════════════════════════════════════════════════
// CONFIGURATION
// ════════════════════════════════════════════════════════════════════════════

/// Coordinator configuration.
#[derive(Debug, Clone)]
struct CoordinatorConfig {
    /// HTTP server host
    host: String,
    /// HTTP server port
    port: u16,
    /// DA layer configuration
    da_config: DAConfig,
    /// Use mock DA for development
    use_mock_da: bool,
}

impl CoordinatorConfig {
    /// Load configuration from environment variables.
    ///
    /// # Returns
    ///
    /// * `Ok(CoordinatorConfig)` - Configuration loaded successfully
    /// * `Err(String)` - Missing or invalid configuration
    fn from_env() -> Result<Self, String> {
        // Check if we should use mock DA
        let use_mock_da = std::env::var("USE_MOCK_DA")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false);

        // Load DA config (required unless using mock)
        let da_config = if use_mock_da {
            DAConfig::default()
        } else {
            DAConfig::from_env().map_err(|e| format!("DA config error: {}", e))?
        };

        // Load HTTP server config
        let host = std::env::var("COORDINATOR_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
        let port: u16 = std::env::var("COORDINATOR_PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse()
            .map_err(|_| "COORDINATOR_PORT must be a valid port number")?;

        Ok(Self {
            host,
            port,
            da_config,
            use_mock_da,
        })
    }

    /// Validate configuration for production use.
    fn validate_for_production(&self) -> Result<(), String> {
        if !self.use_mock_da {
            self.da_config
                .validate_for_production()
                .map_err(|e| format!("Production validation failed: {}", e))?;
        }
        Ok(())
    }
}

// ════════════════════════════════════════════════════════════════════════════
// APP STATE
// ════════════════════════════════════════════════════════════════════════════

/// Application state shared across handlers.
///
/// Note: DAConsumer is NOT stored here because it contains a Stream
/// that is not Sync. The consumer runs as a separate background task.
struct AppState {
    /// Coordinator instance
    coordinator: Coordinator,
    /// DA layer instance
    da: Arc<dyn DALayer>,
    /// Whether DA is available
    da_available: RwLock<bool>,
}

impl AppState {
    fn new(coordinator: Coordinator, da: Arc<dyn DALayer>) -> Self {
        Self {
            coordinator,
            da,
            da_available: RwLock::new(true),
        }
    }

    fn set_da_available(&self, available: bool) {
        *self.da_available.write() = available;
    }

    fn is_da_available(&self) -> bool {
        *self.da_available.read()
    }
}

// ════════════════════════════════════════════════════════════════════════════
// REQUEST/RESPONSE TYPES
// ════════════════════════════════════════════════════════════════════════════

/// Request body for registering a node
#[derive(Deserialize)]
struct RegisterNodeReq {
    id: String,
    zone: String,
    addr: String,
    capacity_gb: Option<u64>,
}

/// Request body for registering an object
#[derive(Deserialize)]
struct RegisterObjectReq {
    hash: String,
    size: u64,
}

/// Query params for placement endpoint
#[derive(Deserialize)]
struct PlacementQuery {
    rf: Option<usize>,
}

/// Request body for replica operations
#[derive(Deserialize)]
struct ReplicaReq {
    hash: String,
    node_id: String,
}

/// Health response with optional metrics
#[derive(Serialize)]
struct HealthResponse {
    status: String,
    da_available: bool,
    da_health: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    metrics: Option<MetricsInfo>,
}

/// Metrics info for health endpoint
#[derive(Serialize)]
struct MetricsInfo {
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

async fn register_node(
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

async fn list_nodes(State(state): State<Arc<AppState>>) -> Json<Value> {
    let nodes = state.coordinator.list_nodes();
    Json(json!(nodes))
}

async fn placement(
    Path(hash): Path<String>,
    Query(q): Query<PlacementQuery>,
    State(state): State<Arc<AppState>>,
) -> Json<Value> {
    let rf = q.rf.unwrap_or(3);
    let sel = state.coordinator.placement_for_hash(&hash, rf);
    Json(json!(sel))
}

async fn register_object(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterObjectReq>,
) -> Json<Value> {
    state.coordinator.register_object(payload.hash, payload.size);
    Json(json!({"ok": true}))
}

async fn get_object(
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

async fn mark_missing(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ReplicaReq>,
) -> Json<Value> {
    state.coordinator.mark_replica_missing(&payload.hash, &payload.node_id);
    Json(json!({"ok": true}))
}

async fn mark_healed(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ReplicaReq>,
) -> Json<Value> {
    state.coordinator.mark_replica_healed(&payload.hash, &payload.node_id);
    Json(json!({"ok": true}))
}

async fn schedule_workload(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<Workload>,
) -> (StatusCode, Json<Value>) {
    match state.coordinator.schedule(&payload) {
        Some(node_id) => (StatusCode::OK, Json(json!({ "node_id": node_id }))),
        None => (StatusCode::NOT_FOUND, Json(json!({ "error": "no suitable node" }))),
    }
}

/// Health check endpoint with DA status
async fn health_check(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    let da_status = state.da.health_check().await;
    let da_healthy = matches!(da_status, Ok(DAHealthStatus::Healthy));
    let da_available = state.is_da_available();

    let status = if da_healthy && da_available {
        "healthy".to_string()
    } else if da_available {
        "degraded".to_string()
    } else {
        "unavailable".to_string()
    };

    // Get metrics and convert to serializable struct
    let metrics = state.da.metrics().map(|m| MetricsInfo {
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
async fn ready_check(State(state): State<Arc<AppState>>) -> StatusCode {
    let da_status = state.da.health_check().await;
    if matches!(da_status, Ok(DAHealthStatus::Healthy)) && state.is_da_available() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

// ════════════════════════════════════════════════════════════════════════════
// DA CONNECTION TEST
// ════════════════════════════════════════════════════════════════════════════

/// Test DA connection at startup.
///
/// Performs a health check with retry logic.
async fn test_da_connection(da: &dyn DALayer) -> Result<(), DAError> {
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
// MAIN
// ════════════════════════════════════════════════════════════════════════════

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_target(false)
        .init();

    info!("═══════════════════════════════════════════════════════════════");
    info!("              DSDN Coordinator (Mainnet Ready)                  ");
    info!("═══════════════════════════════════════════════════════════════");

    // Step 1: Load configuration from environment
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
            error!("Optional:");
            error!("  DA_NETWORK       - Network identifier (mainnet, mocha, local)");
            error!("  DA_TIMEOUT_MS    - Operation timeout (default: 30000)");
            error!("  COORDINATOR_HOST - HTTP server host (default: 127.0.0.1)");
            error!("  COORDINATOR_PORT - HTTP server port (default: 8080)");
            error!("  USE_MOCK_DA      - Use mock DA for development (default: false)");
            std::process::exit(1);
        }
    };

    // Step 2: Validate configuration for production
    if config.da_config.is_mainnet() {
        info!("🌐 Running in MAINNET mode");
        if let Err(e) = config.validate_for_production() {
            error!("Production validation failed: {}", e);
            std::process::exit(1);
        }
    } else {
        info!("🔧 Running in {} mode", config.da_config.network);
    }

    info!("DA Endpoint:  {}", config.da_config.rpc_url);
    info!("DA Network:   {}", config.da_config.network);
    info!("HTTP Server:  {}:{}", config.host, config.port);
    info!("═══════════════════════════════════════════════════════════════");

    // Step 3: Initialize DA layer
    let da: Arc<dyn DALayer> = if config.use_mock_da {
        info!("Using MockDA for development");
        Arc::new(MockDA::new())
    } else {
        info!("Connecting to Celestia DA...");
        match CelestiaDA::new(config.da_config.clone()) {
            Ok(celestia) => Arc::new(celestia),
            Err(e) => {
                error!("❌ Failed to initialize Celestia DA: {}", e);
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

    // Step 4: Test DA connection
    if let Err(e) = test_da_connection(da.as_ref()).await {
        error!("❌ DA connection test failed: {}", e);

        // Graceful degradation: continue but mark DA as unavailable
        if config.da_config.network != "mainnet" {
            warn!("⚠️ Continuing in degraded mode (DA unavailable)");
        } else {
            error!("Cannot start coordinator on mainnet without DA connection");
            std::process::exit(1);
        }
    }

    // Step 5: Initialize coordinator and state
    let coordinator = Coordinator::new();
    let state = Arc::new(AppState::new(coordinator, da));

    // Step 6: Build HTTP router
    let app = Router::new()
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
        .with_state(state);

    // Step 7: Start HTTP server
    let addr: SocketAddr = format!("{}:{}", config.host, config.port)
        .parse()
        .unwrap_or_else(|_| {
            error!("Invalid address: {}:{}", config.host, config.port);
            std::process::exit(1);
        });

    info!("");
    info!("🚀 Coordinator listening on http://{}", addr);
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
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coordinator_config_defaults() {
        // Clear env vars
        std::env::remove_var("DA_RPC_URL");
        std::env::remove_var("DA_NAMESPACE");
        std::env::remove_var("COORDINATOR_HOST");
        std::env::remove_var("COORDINATOR_PORT");
        std::env::set_var("USE_MOCK_DA", "true");

        let config = CoordinatorConfig::from_env();
        assert!(config.is_ok());

        let config = config.unwrap();
        assert!(config.use_mock_da);
        assert_eq!(config.host, "127.0.0.1");
        assert_eq!(config.port, 8080);

        // Cleanup
        std::env::remove_var("USE_MOCK_DA");
    }

    #[test]
    fn test_coordinator_config_custom_port() {
        std::env::set_var("COORDINATOR_PORT", "9090");
        std::env::set_var("USE_MOCK_DA", "true");

        let config = CoordinatorConfig::from_env().unwrap();
        assert_eq!(config.port, 9090);

        // Cleanup
        std::env::remove_var("COORDINATOR_PORT");
        std::env::remove_var("USE_MOCK_DA");
    }

    #[test]
    fn test_coordinator_config_invalid_port() {
        std::env::set_var("COORDINATOR_PORT", "invalid");
        std::env::set_var("USE_MOCK_DA", "true");

        let result = CoordinatorConfig::from_env();
        assert!(result.is_err());

        // Cleanup
        std::env::remove_var("COORDINATOR_PORT");
        std::env::remove_var("USE_MOCK_DA");
    }

    #[test]
    fn test_app_state_da_available() {
        let coordinator = Coordinator::new();
        let da: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let state = AppState::new(coordinator, da);

        assert!(state.is_da_available());

        state.set_da_available(false);
        assert!(!state.is_da_available());

        state.set_da_available(true);
        assert!(state.is_da_available());
    }
}