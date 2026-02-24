//! handlers.rs — HTTP Handlers for DSDN Node (Observability Only)
//!
//! # CRITICAL INVARIANT
//!
//! Node does NOT receive instructions via HTTP/RPC.
//! ALL commands arrive via DA events (Celestia).
//!
//! Therefore, this module provides READ-ONLY endpoints for:
//! - Health monitoring
//! - Status observability  
//! - Metrics export (Prometheus)
//! - State inspection (debugging)
//!
//! NO POST/PUT/DELETE endpoints for operations.

use axum::{
    extract::State,
    http::StatusCode,
    routing::get,
    Json, Router,
};
use serde::Serialize;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;

use crate::{
    NodeDerivedState, NodeHealth, HealthStorage, DAInfo,
    FALLBACK_DEGRADATION_THRESHOLD_MS,
};

// ════════════════════════════════════════════════════════════════════════════
// APP STATE (untuk di-share ke handlers)
// ════════════════════════════════════════════════════════════════════════════

/// Shared application state.
/// 
/// Semua field adalah Arc karena di-share across async tasks.
pub struct NodeAppState<S: HealthStorage + Send + Sync + 'static> {
    /// Node identifier.
    pub node_id: String,
    /// Node derived state (from DA events).
    pub state: Arc<RwLock<NodeDerivedState>>,
    /// DA info for connection status.
    pub da_info: Arc<dyn DAInfo + Send + Sync>,
    /// Storage implementation for health checks.
    pub storage: Arc<S>,
    /// Node start time (unix timestamp).
    pub start_time: u64,
    /// DA network identifier.
    pub da_network: String,
    /// DA endpoint URL.
    pub da_endpoint: String,
}

// ════════════════════════════════════════════════════════════════════════════
// RESPONSE TYPES (Serialize only - no Deserialize needed for read-only)
// ════════════════════════════════════════════════════════════════════════════

/// GET /health response
#[derive(Debug, Serialize)]
pub struct HealthResp {
    pub healthy: bool,
    pub node_id: String,
    pub da_connected: bool,
    pub fallback_active: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub issues: Vec<String>,
}

/// GET /info response
#[derive(Debug, Serialize)]
pub struct InfoResp {
    pub node_id: String,
    pub version: String,
    pub uptime_secs: u64,
    pub da_network: String,
    pub da_endpoint: String,
}

/// GET /status response
#[derive(Debug, Serialize)]
pub struct StatusResp {
    pub node_id: String,
    pub healthy: bool,
    pub da_connected: bool,
    pub last_sequence: u64,
    pub fallback_active: bool,
    pub current_da_source: String,
    pub assignments_count: usize,
    pub storage_used_bytes: u64,
    pub storage_capacity_bytes: u64,
    pub uptime_secs: u64,
}

/// GET /state response
#[derive(Debug, Serialize)]
pub struct StateResp {
    pub last_sequence: u64,
    pub fallback_active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_since: Option<u64>,
    pub current_da_source: String,
    pub events_from_fallback: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_reconciliation_sequence: Option<u64>,
    pub assignments_count: usize,
}

/// GET /state/fallback response
#[derive(Debug, Serialize)]
pub struct FallbackResp {
    pub fallback_active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_since: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_duration_secs: Option<u64>,
    pub current_source: String,
    pub events_from_fallback: u64,
    pub is_degraded: bool,
}

/// GET /state/assignments response
#[derive(Debug, Serialize)]
pub struct AssignmentsResp {
    pub count: usize,
    pub assignments: Vec<AssignmentEntry>,
}

/// Single assignment entry
#[derive(Debug, Serialize)]
pub struct AssignmentEntry {
    pub chunk_hash: String,
    pub replica_index: u8,
    pub assigned_at: u64,
    pub verified: bool,
    pub size_bytes: u64,
}

/// GET /da/status response
#[derive(Debug, Serialize)]
pub struct DAStatusResp {
    pub connected: bool,
    pub latest_sequence: u64,
    pub network: String,
    pub endpoint: String,
}

/// GET /metrics response (JSON format)
#[derive(Debug, Serialize)]
pub struct MetricsResp {
    pub node_id: String,
    pub uptime_secs: u64,
    pub da_connected: bool,
    pub da_latest_sequence: u64,
    pub fallback_active: bool,
    pub events_from_fallback: u64,
    pub storage_used_bytes: u64,
    pub storage_capacity_bytes: u64,
    pub assignments_count: usize,
}

// ════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════

/// Get current unix timestamp in seconds.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Get current unix timestamp in milliseconds.
fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ════════════════════════════════════════════════════════════════════════════
// HANDLERS (ALL READ-ONLY)
// ════════════════════════════════════════════════════════════════════════════

/// GET /health
/// 
/// Health check endpoint untuk monitoring dan load balancer.
pub async fn health_handler<S: HealthStorage + Send + Sync + 'static>(
    State(app): State<Arc<NodeAppState<S>>>,
) -> (StatusCode, Json<HealthResp>) {
    let state = app.state.read();
    
    // Build health check using existing NodeHealth
    let health = NodeHealth::check(
        &app.node_id,
        app.da_info.as_ref(),
        &state,
        app.storage.as_ref(),
    );
    
    let status = if health.is_healthy() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    
    (status, Json(HealthResp {
        healthy: health.is_healthy(),
        node_id: app.node_id.clone(),
        da_connected: health.da_connected,
        fallback_active: health.fallback_active,
        issues: health.health_issues(),
    }))
}

/// GET /ready
///
/// Kubernetes readiness probe.
pub async fn ready_handler<S: HealthStorage + Send + Sync + 'static>(
    State(app): State<Arc<NodeAppState<S>>>,
) -> StatusCode {
    if app.da_info.is_connected() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

/// GET /info
///
/// Basic node information.
pub async fn info_handler<S: HealthStorage + Send + Sync + 'static>(
    State(app): State<Arc<NodeAppState<S>>>,
) -> Json<InfoResp> {
    Json(InfoResp {
        node_id: app.node_id.clone(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_secs: now_secs().saturating_sub(app.start_time),
        da_network: app.da_network.clone(),
        da_endpoint: app.da_endpoint.clone(),
    })
}

/// GET /status
///
/// Detailed node status.
pub async fn status_handler<S: HealthStorage + Send + Sync + 'static>(
    State(app): State<Arc<NodeAppState<S>>>,
) -> Json<StatusResp> {
    let state = app.state.read();

    Json(StatusResp {
        node_id: app.node_id.clone(),
        healthy: app.da_info.is_connected() && !state.fallback_active,
        da_connected: app.da_info.is_connected(),
        last_sequence: state.last_sequence,
        fallback_active: state.fallback_active,
        current_da_source: state.current_da_source.to_string(),
        assignments_count: state.my_chunks.len(),
        storage_used_bytes: app.storage.storage_used_bytes(),
        storage_capacity_bytes: app.storage.storage_capacity_bytes(),
        uptime_secs: now_secs().saturating_sub(app.start_time),
    })
}

/// GET /state
///
/// Current node derived state (from DA events).
pub async fn state_handler<S: HealthStorage + Send + Sync + 'static>(
    State(app): State<Arc<NodeAppState<S>>>,
) -> Json<StateResp> {
    let state = app.state.read();
    
    Json(StateResp {
        last_sequence: state.last_sequence,
        fallback_active: state.fallback_active,
        fallback_since: state.fallback_since,
        current_da_source: state.current_da_source.to_string(),
        events_from_fallback: state.events_from_fallback,
        last_reconciliation_sequence: state.last_reconciliation_sequence,
        assignments_count: state.my_chunks.len(),
    })
}

/// GET /state/fallback
///
/// Fallback status detail.
pub async fn fallback_handler<S: HealthStorage + Send + Sync + 'static>(
    State(app): State<Arc<NodeAppState<S>>>,
) -> Json<FallbackResp> {
    let state = app.state.read();
    let now = now_millis();
    
    let fallback_duration = state.fallback_since.map(|since| {
        (now.saturating_sub(since)) / 1000
    });
    
    // Degraded if fallback active > FALLBACK_DEGRADATION_THRESHOLD_MS (5 minutes)
    let threshold_secs = FALLBACK_DEGRADATION_THRESHOLD_MS / 1000;
    let is_degraded = state.fallback_active && 
        fallback_duration.map(|d| d > threshold_secs).unwrap_or(false);
    
    Json(FallbackResp {
        fallback_active: state.fallback_active,
        fallback_since: state.fallback_since,
        fallback_duration_secs: fallback_duration,
        current_source: state.current_da_source.to_string(),
        events_from_fallback: state.events_from_fallback,
        is_degraded,
    })
}

/// GET /state/assignments
///
/// List chunk assignments.
pub async fn assignments_handler<S: HealthStorage + Send + Sync + 'static>(
    State(app): State<Arc<NodeAppState<S>>>,
) -> Json<AssignmentsResp> {
    let state = app.state.read();
    
    let assignments: Vec<AssignmentEntry> = state
        .my_chunks
        .values()
        .map(|assignment| AssignmentEntry {
            chunk_hash: assignment.hash.clone(),
            replica_index: assignment.replica_index,
            assigned_at: assignment.assigned_at,
            verified: assignment.verified,
            size_bytes: assignment.size_bytes,
        })
        .collect();
    
    Json(AssignmentsResp {
        count: assignments.len(),
        assignments,
    })
}

/// GET /da/status
///
/// DA connection status.
pub async fn da_status_handler<S: HealthStorage + Send + Sync + 'static>(
    State(app): State<Arc<NodeAppState<S>>>,
) -> Json<DAStatusResp> {
    Json(DAStatusResp {
        connected: app.da_info.is_connected(),
        latest_sequence: app.da_info.latest_sequence(),
        network: app.da_network.clone(),
        endpoint: app.da_endpoint.clone(),
    })
}

/// GET /metrics
///
/// JSON metrics untuk monitoring.
pub async fn metrics_handler<S: HealthStorage + Send + Sync + 'static>(
    State(app): State<Arc<NodeAppState<S>>>,
) -> Json<MetricsResp> {
    let state = app.state.read();
    
    Json(MetricsResp {
        node_id: app.node_id.clone(),
        uptime_secs: now_secs().saturating_sub(app.start_time),
        da_connected: app.da_info.is_connected(),
        da_latest_sequence: app.da_info.latest_sequence(),
        fallback_active: state.fallback_active,
        events_from_fallback: state.events_from_fallback,
        storage_used_bytes: app.storage.storage_used_bytes(),
        storage_capacity_bytes: app.storage.storage_capacity_bytes(),
        assignments_count: state.my_chunks.len(),
    })
}

/// GET /metrics/prometheus
///
/// Prometheus text format metrics.
pub async fn prometheus_handler<S: HealthStorage + Send + Sync + 'static>(
    State(app): State<Arc<NodeAppState<S>>>,
) -> String {
    let state = app.state.read();
    let uptime = now_secs().saturating_sub(app.start_time);
    let da_connected: u8 = if app.da_info.is_connected() { 1 } else { 0 };
    let fallback_active: u8 = if state.fallback_active { 1 } else { 0 };

    let mut out = format!(
r#"# HELP dsdn_node_uptime_seconds Node uptime in seconds
# TYPE dsdn_node_uptime_seconds gauge
dsdn_node_uptime_seconds{{node_id="{node_id}"}} {uptime}

# HELP dsdn_node_da_connected DA connection status (1=connected, 0=disconnected)
# TYPE dsdn_node_da_connected gauge
dsdn_node_da_connected{{node_id="{node_id}"}} {da_connected}

# HELP dsdn_node_da_sequence Latest DA sequence number
# TYPE dsdn_node_da_sequence gauge
dsdn_node_da_sequence{{node_id="{node_id}"}} {da_sequence}

# HELP dsdn_node_fallback_active Fallback mode status (1=active, 0=inactive)
# TYPE dsdn_node_fallback_active gauge
dsdn_node_fallback_active{{node_id="{node_id}"}} {fallback_active}

# HELP dsdn_node_events_from_fallback Events received from fallback DA sources
# TYPE dsdn_node_events_from_fallback counter
dsdn_node_events_from_fallback{{node_id="{node_id}"}} {events_fallback}

# HELP dsdn_node_storage_used_bytes Storage used in bytes
# TYPE dsdn_node_storage_used_bytes gauge
dsdn_node_storage_used_bytes{{node_id="{node_id}"}} {storage_used}

# HELP dsdn_node_storage_capacity_bytes Storage capacity in bytes
# TYPE dsdn_node_storage_capacity_bytes gauge
dsdn_node_storage_capacity_bytes{{node_id="{node_id}"}} {storage_capacity}

# HELP dsdn_node_assignments_count Number of chunk assignments
# TYPE dsdn_node_assignments_count gauge
dsdn_node_assignments_count{{node_id="{node_id}"}} {assignments}
"#,
        node_id = app.node_id,
        uptime = uptime,
        da_connected = da_connected,
        da_sequence = app.da_info.latest_sequence(),
        fallback_active = fallback_active,
        events_fallback = state.events_from_fallback,
        storage_used = app.storage.storage_used_bytes(),
        storage_capacity = app.storage.storage_capacity_bytes(),
        assignments = state.my_chunks.len(),
    );

    out
}

pub fn build_router<S: HealthStorage + Send + Sync + 'static>(
    app_state: Arc<NodeAppState<S>>,
) -> Router {
    Router::new()
        // Health & Readiness
        .route("/health", get(health_handler::<S>))
        .route("/ready", get(ready_handler::<S>))
        // Info & Status
        .route("/info", get(info_handler::<S>))
        .route("/status", get(status_handler::<S>))
        // State (read-only inspection)
        .route("/state", get(state_handler::<S>))
        .route("/state/fallback", get(fallback_handler::<S>))
        .route("/state/assignments", get(assignments_handler::<S>))
        // DA status
        .route("/da/status", get(da_status_handler::<S>))
        // Metrics
        .route("/metrics", get(metrics_handler::<S>))
        .route("/metrics/prometheus", get(prometheus_handler::<S>))
        .with_state(app_state)
}

// ════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_now_secs() {
        let ts = now_secs();
        assert!(ts > 0);
    }
    
    #[test]
    fn test_now_millis() {
        let ts = now_millis();
        assert!(ts > 0);
    }
}