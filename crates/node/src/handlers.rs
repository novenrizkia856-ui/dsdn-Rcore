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
//! - P2P / Bootstrap status (Tahap 21)
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

use parking_lot::{Mutex, RwLock};

use crate::{
    NodeDerivedState, NodeHealth, HealthStorage, DAInfo,
    FALLBACK_DEGRADATION_THRESHOLD_MS,
    PeerManager, BootstrapSummary, NodeRole,
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
    /// P2P bootstrap peer manager (Tahap 21).
    /// `None` only if P2P is explicitly disabled.
    pub peer_manager: Option<Arc<Mutex<PeerManager>>>,
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
    // ── P2P (Tahap 21) ──────────────────────────────────
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p2p_role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p2p_node_class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p2p_active_peers: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p2p_known_peers: Option<usize>,
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

    // P2P info (if available)
    let (p2p_role, p2p_node_class, p2p_active_peers, p2p_known_peers) =
        if let Some(ref pm) = app.peer_manager {
            let mgr = pm.lock();
            let summary = mgr.summary();
            (
                Some(summary.role),
                summary.node_class,
                Some(summary.active_peers),
                Some(summary.known_peers),
            )
        } else {
            (None, None, None, None)
        };

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
        p2p_role,
        p2p_node_class,
        p2p_active_peers,
        p2p_known_peers,
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

    // Append P2P / bootstrap metrics if PeerManager is active
    if let Some(ref pm) = app.peer_manager {
        let mgr = pm.lock();
        out.push_str(&mgr.metrics().to_prometheus(&app.node_id));
    }

    out
}

// ════════════════════════════════════════════════════════════════════════════
// P2P RESPONSE TYPES (Tahap 21)
// ════════════════════════════════════════════════════════════════════════════

/// GET /p2p/status response — high-level bootstrap subsystem summary.
#[derive(Debug, Serialize)]
pub struct P2PStatusResp {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<BootstrapSummary>,
}

/// Single active peer entry for /p2p/peers.
#[derive(Debug, Serialize)]
pub struct P2PPeerEntry {
    pub address: String,
    pub role: Option<String>,
    pub node_class: Option<String>,
    pub score: i64,
    pub success_count: u32,
    pub failure_count: u32,
    pub last_connected: u64,
}

/// GET /p2p/peers response.
#[derive(Debug, Serialize)]
pub struct P2PPeersResp {
    pub active_count: usize,
    pub known_count: usize,
    pub peers: Vec<P2PPeerEntry>,
}

/// GET /p2p/store/stats response.
#[derive(Debug, Serialize)]
pub struct P2PStoreStatsResp {
    pub total: usize,
    pub suspicious: usize,
    pub expired: usize,
    pub connected_24h: usize,
    pub by_role: std::collections::HashMap<String, usize>,
    pub by_class: std::collections::HashMap<String, usize>,
    pub by_source: std::collections::HashMap<String, usize>,
}

/// GET /p2p/role response — what this node needs.
#[derive(Debug, Serialize)]
pub struct P2PRoleInfoResp {
    pub our_role: String,
    pub our_class: Option<String>,
    pub required_roles: Vec<String>,
}

// ════════════════════════════════════════════════════════════════════════════
// P2P HANDLERS (ALL READ-ONLY)
// ════════════════════════════════════════════════════════════════════════════

/// GET /p2p/status
///
/// Bootstrap subsystem summary: role, class, active peers, metrics.
pub async fn p2p_status_handler<S: HealthStorage + Send + Sync + 'static>(
    State(app): State<Arc<NodeAppState<S>>>,
) -> Json<P2PStatusResp> {
    let summary = app.peer_manager.as_ref().map(|pm| {
        let mgr = pm.lock();
        mgr.summary()
    });

    Json(P2PStatusResp {
        enabled: app.peer_manager.is_some(),
        summary,
    })
}

/// GET /p2p/peers
///
/// List all active peers with scoring info.
pub async fn p2p_peers_handler<S: HealthStorage + Send + Sync + 'static>(
    State(app): State<Arc<NodeAppState<S>>>,
) -> Json<P2PPeersResp> {
    let (active_count, known_count, peers) = if let Some(ref pm) = app.peer_manager {
        let mgr = pm.lock();
        let now = now_secs();
        let our_role = mgr.config().role;
        let active: Vec<P2PPeerEntry> = mgr
            .active_peers()
            .map(|p| P2PPeerEntry {
                address: p.socket_addr().to_string(),
                role: p.role.map(|r| r.to_string()),
                node_class: p.node_class.map(|c| c.to_string()),
                score: p.score_with_role(now, Some(our_role)),
                success_count: p.success_count,
                failure_count: p.failure_count,
                last_connected: p.last_connected,
            })
            .collect();
        let active_count = active.len();
        let known_count = mgr.store().len();
        (active_count, known_count, active)
    } else {
        (0, 0, Vec::new())
    };

    Json(P2PPeersResp {
        active_count,
        known_count,
        peers,
    })
}

/// GET /p2p/store/stats
///
/// Peer store statistics breakdown by role, class, source.
pub async fn p2p_store_stats_handler<S: HealthStorage + Send + Sync + 'static>(
    State(app): State<Arc<NodeAppState<S>>>,
) -> Json<P2PStoreStatsResp> {
    let resp = if let Some(ref pm) = app.peer_manager {
        let mgr = pm.lock();
        let stats = mgr.store().stats();
        P2PStoreStatsResp {
            total: stats.total,
            suspicious: stats.suspicious,
            expired: stats.expired,
            connected_24h: stats.connected_24h,
            by_role: stats.by_role,
            by_class: stats.by_class,
            by_source: stats.by_source,
        }
    } else {
        P2PStoreStatsResp {
            total: 0,
            suspicious: 0,
            expired: 0,
            connected_24h: 0,
            by_role: Default::default(),
            by_class: Default::default(),
            by_source: Default::default(),
        }
    };

    Json(resp)
}

/// GET /p2p/role
///
/// This node's role, class, and which roles it needs from peers.
pub async fn p2p_role_handler<S: HealthStorage + Send + Sync + 'static>(
    State(app): State<Arc<NodeAppState<S>>>,
) -> Json<P2PRoleInfoResp> {
    use crate::RoleDependencyMatrix;

    let (our_role, our_class) = if let Some(ref pm) = app.peer_manager {
        let mgr = pm.lock();
        let cfg = mgr.config();
        (cfg.role, cfg.node_class)
    } else {
        (NodeRole::StorageCompute, None)
    };

    let required_roles: Vec<String> = RoleDependencyMatrix::required_roles(our_role)
        .into_iter()
        .map(|r| r.to_string())
        .collect();

    Json(P2PRoleInfoResp {
        our_role: our_role.to_string(),
        our_class: our_class.map(|c| c.to_string()),
        required_roles,
    })
}

// ════════════════════════════════════════════════════════════════════════════
// ROUTER BUILDER
// ════════════════════════════════════════════════════════════════════════════

/// Build HTTP router for node.
///
/// ALL endpoints are READ-ONLY (GET only).
/// Node receives commands via DA events, NOT via HTTP.
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
        // P2P / Bootstrap (Tahap 21)
        .route("/p2p/status", get(p2p_status_handler::<S>))
        .route("/p2p/peers", get(p2p_peers_handler::<S>))
        .route("/p2p/store/stats", get(p2p_store_stats_handler::<S>))
        .route("/p2p/role", get(p2p_role_handler::<S>))
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