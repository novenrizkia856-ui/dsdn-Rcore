//! handlers.rs — Extended HTTP Handlers for DSDN Coordinator
//!
//! Additional endpoints for full system integration (14A.3).
//! These handlers expose all coordinator functionality via HTTP.
//!
//! ## Endpoints Added
//!
//! | Endpoint | Method | Description |
//! |----------|--------|-------------|
//! | `/node/{id}` | GET | Get single node info |
//! | `/node/{id}/stats` | GET | Get node runtime stats |
//! | `/node/{id}/stats` | POST | Update node runtime stats |
//! | `/scheduler/config` | POST | Set scheduler weights |
//! | `/da/post` | POST | Post blob to DA layer |
//! | `/da/metrics` | GET | Get detailed DA metrics |
//! | `/da/routing` | GET | Get current DA routing state |
//! | `/system/info` | GET | System overview |

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;

use dsdn_common::{DAHealthStatus, DALayer};
use dsdn_coordinator::{NodeStats, Scheduler};

// AppState is defined in main.rs (parent module when included via `mod handlers;`)
use super::AppState;

// ════════════════════════════════════════════════════════════════════════════
// REQUEST/RESPONSE TYPES
// ════════════════════════════════════════════════════════════════════════════

/// Request body for updating node stats
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateNodeStatsReq {
    pub cpu_free: f64,
    pub ram_free_mb: f64,
    #[serde(default)]
    pub gpu_free: f64,
    #[serde(default = "default_latency")]
    pub latency_ms: f64,
    #[serde(default)]
    pub io_pressure: f64,
}

fn default_latency() -> f64 {
    10.0
}

/// Request body for scheduler configuration
#[derive(Debug, Clone, Deserialize)]
pub struct SchedulerConfigReq {
    #[serde(default = "default_weight")]
    pub w_cpu: f64,
    #[serde(default = "default_weight")]
    pub w_ram: f64,
    #[serde(default = "default_gpu_weight")]
    pub w_gpu: f64,
    #[serde(default = "default_latency_weight")]
    pub w_latency: f64,
    #[serde(default = "default_io_weight")]
    pub w_io: f64,
}

fn default_weight() -> f64 { 1.0 }
fn default_gpu_weight() -> f64 { 0.5 }
fn default_latency_weight() -> f64 { 0.8 }
fn default_io_weight() -> f64 { 0.6 }

/// Request body for posting blob to DA
#[derive(Debug, Clone, Deserialize)]
pub struct PostBlobReq {
    /// Blob data as hex string
    pub data_hex: String,
}

/// Response for node stats
#[derive(Debug, Clone, Serialize)]
pub struct NodeStatsResponse {
    pub node_id: String,
    pub found: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats: Option<NodeStatsInfo>,
}

/// Serializable node stats info
#[derive(Debug, Clone, Serialize)]
pub struct NodeStatsInfo {
    pub cpu_free: f64,
    pub ram_free_mb: f64,
    pub gpu_free: f64,
    pub latency_ms: f64,
    pub io_pressure: f64,
}

impl From<NodeStats> for NodeStatsInfo {
    fn from(s: NodeStats) -> Self {
        Self {
            cpu_free: s.cpu_free,
            ram_free_mb: s.ram_free_mb,
            gpu_free: s.gpu_free,
            latency_ms: s.latency_ms,
            io_pressure: s.io_pressure,
        }
    }
}

/// Response for DA routing info
#[derive(Debug, Clone, Serialize)]
pub struct DARoutingResponse {
    pub current_state: String,
    pub primary_healthy: bool,
    pub secondary_healthy: bool,
    pub emergency_healthy: bool,
    pub fallback_active: bool,
    pub pending_reconcile: u64,
}

/// Response for system info
#[derive(Debug, Clone, Serialize)]
pub struct SystemInfoResponse {
    pub version: String,
    pub node_count: usize,
    pub da_status: String,
    pub routing_state: String,
    pub fallback_active: bool,
}

/// Response for post blob
#[derive(Debug, Clone, Serialize)]
pub struct PostBlobResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commitment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Response for DA metrics
#[derive(Debug, Clone, Serialize)]
pub struct DAMetricsResponse {
    pub available: bool,
    pub post_count: u64,
    pub get_count: u64,
    pub error_count: u64,
    pub health_check_count: u64,
    pub retry_count: u64,
    pub avg_post_latency_us: u64,
    pub avg_get_latency_us: u64,
}

// ════════════════════════════════════════════════════════════════════════════
// NODE HANDLERS
// ════════════════════════════════════════════════════════════════════════════

/// GET /node/{id} - Get single node info
pub async fn get_node_handler(
    Path(id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<Value>) {
    let nodes = state.coordinator.list_nodes();
    match nodes.into_iter().find(|n| n.id == id) {
        Some(node) => {
            let val = serde_json::to_value(&node).unwrap_or_else(|_| json!({}));
            (StatusCode::OK, Json(val))
        }
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "node not found", "node_id": id}))),
    }
}

/// GET /node/{id}/stats - Get node runtime stats
pub async fn get_node_stats_handler(
    Path(id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Json<NodeStatsResponse> {
    let stats = state.coordinator.get_node_stats(&id);
    Json(NodeStatsResponse {
        node_id: id,
        found: stats.is_some(),
        stats: stats.map(NodeStatsInfo::from),
    })
}

/// POST /node/{id}/stats - Update node runtime stats
pub async fn update_node_stats_handler(
    Path(id): Path<String>,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<UpdateNodeStatsReq>,
) -> (StatusCode, Json<Value>) {
    // Check if node exists
    let nodes = state.coordinator.list_nodes();
    let exists = nodes.iter().any(|n| n.id == id);
    
    if !exists {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "node not found", "node_id": id})));
    }
    
    let stats = NodeStats {
        cpu_free: payload.cpu_free,
        ram_free_mb: payload.ram_free_mb,
        gpu_free: payload.gpu_free,
        latency_ms: payload.latency_ms,
        io_pressure: payload.io_pressure,
    };
    
    state.coordinator.update_node_stats(&id, stats);
    (StatusCode::OK, Json(json!({"ok": true, "node_id": id})))
}

// ════════════════════════════════════════════════════════════════════════════
// SCHEDULER HANDLERS
// ════════════════════════════════════════════════════════════════════════════

/// POST /scheduler/config - Set scheduler weights
pub async fn set_scheduler_config_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SchedulerConfigReq>,
) -> Json<Value> {
    let scheduler = Scheduler {
        w_cpu: payload.w_cpu,
        w_ram: payload.w_ram,
        w_gpu: payload.w_gpu,
        w_latency: payload.w_latency,
        w_io: payload.w_io,
    };
    
    state.coordinator.set_scheduler(scheduler);
    Json(json!({
        "ok": true,
        "message": "scheduler config updated",
        "config": {
            "w_cpu": payload.w_cpu,
            "w_ram": payload.w_ram,
            "w_gpu": payload.w_gpu,
            "w_latency": payload.w_latency,
            "w_io": payload.w_io,
        }
    }))
}

// ════════════════════════════════════════════════════════════════════════════
// DA HANDLERS
// ════════════════════════════════════════════════════════════════════════════

/// POST /da/post - Post blob to DA layer
pub async fn post_blob_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<PostBlobReq>,
) -> (StatusCode, Json<PostBlobResponse>) {
    // Decode hex data
    let data = match hex::decode(&payload.data_hex) {
        Ok(d) => d,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(PostBlobResponse {
                    success: false,
                    commitment: None,
                    height: None,
                    error: Some(format!("invalid hex data: {}", e)),
                }),
            );
        }
    };
    
    // Post via DARouter (using da() accessor)
    match state.da().post_blob(&data).await {
        Ok(blob_ref) => (
            StatusCode::OK,
            Json(PostBlobResponse {
                success: true,
                commitment: Some(hex::encode(&blob_ref.commitment)),
                height: Some(blob_ref.height),
                error: None,
            }),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(PostBlobResponse {
                success: false,
                commitment: None,
                height: None,
                error: Some(format!("{:?}", e)),
            }),
        ),
    }
}

/// GET /da/metrics - Get detailed DA metrics
pub async fn get_da_metrics_handler(
    State(state): State<Arc<AppState>>,
) -> Json<DAMetricsResponse> {
    match state.da().metrics() {
        Some(m) => Json(DAMetricsResponse {
            available: true,
            post_count: m.post_count,
            get_count: m.get_count,
            error_count: m.error_count,
            health_check_count: m.health_check_count,
            retry_count: m.retry_count,
            avg_post_latency_us: m.avg_post_latency_us,
            avg_get_latency_us: m.avg_get_latency_us,
        }),
        None => Json(DAMetricsResponse {
            available: false,
            post_count: 0,
            get_count: 0,
            error_count: 0,
            health_check_count: 0,
            retry_count: 0,
            avg_post_latency_us: 0,
            avg_get_latency_us: 0,
        }),
    }
}

/// GET /da/routing - Get current DA routing state
pub async fn get_da_routing_handler(
    State(state): State<Arc<AppState>>,
) -> Json<DARoutingResponse> {
    let health = state.health_monitor();
    let reconcile = state.reconciliation_engine();
    
    Json(DARoutingResponse {
        current_state: state.routing_state().to_string(),
        primary_healthy: health.is_primary_healthy(),
        secondary_healthy: health.is_secondary_healthy(),
        emergency_healthy: health.is_emergency_healthy(),
        fallback_active: health.is_fallback_active(),
        pending_reconcile: reconcile.pending_count(),
    })
}

// ════════════════════════════════════════════════════════════════════════════
// SYSTEM HANDLERS
// ════════════════════════════════════════════════════════════════════════════

/// GET /system/info - System overview
pub async fn get_system_info_handler(
    State(state): State<Arc<AppState>>,
) -> Json<SystemInfoResponse> {
    let da_status = state.da().health_check().await;
    let health = state.health_monitor();
    
    Json(SystemInfoResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        node_count: state.coordinator.list_nodes().len(),
        da_status: format!("{:?}", da_status),
        routing_state: state.routing_state().to_string(),
        fallback_active: health.is_fallback_active(),
    })
}

// ════════════════════════════════════════════════════════════════════════════
// ROUTER BUILDER
// ════════════════════════════════════════════════════════════════════════════

/// Build extended routes for coordinator
///
/// Call this and merge with main router in main.rs:
/// ```ignore
/// let app = Router::new()
///     .route("/register", post(register_node))
///     // ... existing routes ...
///     .merge(handlers::extended_routes())
///     .with_state(state);
/// ```
pub fn extended_routes() -> Router<Arc<AppState>> {
    Router::new()
        // Node endpoints
        .route("/node/:id", get(get_node_handler))
        .route("/node/:id/stats", get(get_node_stats_handler))
        .route("/node/:id/stats", post(update_node_stats_handler))
        // Scheduler endpoints
        .route("/scheduler/config", post(set_scheduler_config_handler))
        // DA endpoints
        .route("/da/post", post(post_blob_handler))
        .route("/da/metrics", get(get_da_metrics_handler))
        .route("/da/routing", get(get_da_routing_handler))
        // System endpoints
        .route("/system/info", get(get_system_info_handler))
}