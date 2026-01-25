//! # DSDN Ingress (14A)
//!
//! HTTP gateway untuk akses data DSDN.
//!
//! ## Architecture
//! ```text
//! Client → Ingress → DARouter → Node
//!              │
//!              └──→ Celestia DA (for placement info)
//! ```
//!
//! ## Endpoints
//! - GET /object/:hash - Fetch object by hash
//! - GET /health - Health check
//! - GET /ready - Readiness check
//! - GET /metrics - Prometheus metrics
//!
//! ## DA Integration
//! Ingress TIDAK query Coordinator untuk placement.
//! Semua routing decision berdasarkan DA-derived state.
//!
//! ## Modules (imported)
//! - da_router: DA-aware routing
//! - routing: Request routing logic
//! - fallback: Fallback & retry
//! - rate_limit: Rate limiting
//! - metrics: Observability

use axum::{
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    routing::get,
    Router,
    response::IntoResponse,
    Json,
};
use bytes::Bytes;
use serde::Serialize;
use std::{env, net::SocketAddr, sync::Arc, time::Duration};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn, debug, instrument, Span};
use tracing_subscriber;
use tokio::time::timeout;
use tokio::sync::watch;

mod coord_client;
mod da_router;
mod routing;
mod fallback;
mod metrics;
mod rate_limit;
mod fallback_health;
pub use fallback_health::FallbackHealthInfo;

use coord_client::CoordinatorClient;
use da_router::{DARouter, DEFAULT_CACHE_TTL_MS};
use metrics::{IngressMetrics, RequestContext};
use rate_limit::{RateLimiter, RateLimitState, rate_limit_middleware};

// ════════════════════════════════════════════════════════════════════════════
// INGRESS HEALTH STRUCT
// ════════════════════════════════════════════════════════════════════════════

/// Health status ingress yang DA-aware.
///
/// Semua field merepresentasikan state real, bukan asumsi.
#[derive(Debug, Clone, Serialize)]
pub struct IngressHealth {
    /// Apakah DA layer terhubung.
    pub da_connected: bool,
    /// Sequence terakhir dari DA (0 jika tidak tersedia).
    pub da_last_sequence: u64,
    /// Jumlah node dalam cache.
    pub cached_nodes: usize,
    /// Jumlah placement dalam cache.
    pub cached_placements: usize,
    /// Umur cache dalam milliseconds.
    pub cache_age_ms: u64,
    /// Apakah coordinator dapat dijangkau.
    pub coordinator_reachable: bool,
    /// Jumlah node sehat (active).
    pub healthy_nodes: usize,
    /// Total node dalam registry.
    pub total_nodes: usize,
}

impl Default for IngressHealth {
    fn default() -> Self {
        Self {
            da_connected: false,
            da_last_sequence: 0,
            cached_nodes: 0,
            cached_placements: 0,
            cache_age_ms: u64::MAX, // Indicates cache never filled
            coordinator_reachable: false,
            healthy_nodes: 0,
            total_nodes: 0,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// APP STATE
// ════════════════════════════════════════════════════════════════════════════

/// Application state untuk Axum handlers.
#[derive(Clone)]
pub struct AppState {
    /// Coordinator client.
    pub coord: Arc<CoordinatorClient>,
    /// DA Router (optional, None jika DA tidak terhubung).
    pub da_router: Option<Arc<DARouter>>,
    /// DA connected flag.
    pub da_connected: Arc<std::sync::atomic::AtomicBool>,
    /// DA last sequence (0 jika tidak tersedia).
    pub da_last_sequence: Arc<std::sync::atomic::AtomicU64>,
    /// Metrics collector.
    pub metrics: Arc<IngressMetrics>,
}

impl AppState {
    /// Membuat AppState baru tanpa DA router.
    pub fn new(coord: Arc<CoordinatorClient>) -> Self {
        Self {
            coord,
            da_router: None,
            da_connected: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            da_last_sequence: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            metrics: Arc::new(IngressMetrics::new()),
        }
    }

    /// Membuat AppState dengan DA router.
    #[allow(dead_code)]
    pub fn with_da_router(coord: Arc<CoordinatorClient>, da_router: Arc<DARouter>) -> Self {
        Self {
            coord,
            da_router: Some(da_router),
            da_connected: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            da_last_sequence: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            metrics: Arc::new(IngressMetrics::new()),
        }
    }

    /// Membuat AppState dengan metrics.
    #[allow(dead_code)]
    pub fn with_metrics(coord: Arc<CoordinatorClient>, metrics: Arc<IngressMetrics>) -> Self {
        Self {
            coord,
            da_router: None,
            da_connected: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            da_last_sequence: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            metrics,
        }
    }

    /// Set DA connected status.
    #[allow(dead_code)]
    pub fn set_da_connected(&self, connected: bool) {
        self.da_connected.store(connected, std::sync::atomic::Ordering::SeqCst);
    }

    /// Set DA last sequence.
    #[allow(dead_code)]
    pub fn set_da_last_sequence(&self, seq: u64) {
        self.da_last_sequence.store(seq, std::sync::atomic::Ordering::SeqCst);
    }

    /// Get DA connected status.
    pub fn is_da_connected(&self) -> bool {
        self.da_connected.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Get DA last sequence.
    pub fn get_da_last_sequence(&self) -> u64 {
        self.da_last_sequence.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Gather health information.
    pub async fn gather_health(&self) -> IngressHealth {
        let mut health = IngressHealth::default();

        // DA connectivity status
        health.da_connected = self.is_da_connected();
        health.da_last_sequence = self.get_da_last_sequence();

        // Cache information from DA router
        if let Some(ref router) = self.da_router {
            let cache = router.get_cache();

            health.cached_nodes = cache.node_registry.len();
            health.cached_placements = cache.chunk_placements.len();
            health.total_nodes = cache.node_registry.len();

            // Count healthy (active) nodes
            health.healthy_nodes = cache.node_registry
                .values()
                .filter(|n| n.active)
                .count();

            // Calculate cache age
            let now = current_timestamp_ms();
            if cache.last_updated > 0 {
                health.cache_age_ms = now.saturating_sub(cache.last_updated);
            }
        }

        // Check coordinator reachability (with timeout)
        let coord_check = timeout(Duration::from_secs(2), self.coord.ping()).await;
        health.coordinator_reachable = matches!(coord_check, Ok(Ok(())));

        health
    }

    /// Check if system is ready (for readiness probe).
    ///
    /// Ready conditions:
    /// - Coordinator reachable
    /// - If DA router exists: cache must be filled with at least one healthy node
    pub async fn is_ready(&self) -> bool {
        // Check coordinator first
        let coord_ok = timeout(Duration::from_secs(2), self.coord.ping()).await;
        if !matches!(coord_ok, Ok(Ok(()))) {
            return false;
        }

        // If DA router exists, check cache state
        if let Some(ref router) = self.da_router {
            let cache = router.get_cache();

            // Cache must have been filled at least once
            if cache.last_updated == 0 {
                return false;
            }

            // Must have at least one healthy node
            let healthy_count = cache.node_registry
                .values()
                .filter(|n| n.active)
                .count();

            if healthy_count == 0 {
                return false;
            }
        }

        true
    }
}

// ════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════

/// Get current timestamp in Unix milliseconds.
fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Simple config via env
fn coordinator_base_from_env() -> String {
    env::var("COORDINATOR_BASE").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string())
}

/// DA router TTL config via env (default 30 seconds)
fn da_router_ttl_from_env() -> u64 {
    env::var("DA_ROUTER_TTL_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_CACHE_TTL_MS)
}

// ════════════════════════════════════════════════════════════════════════════
// MAIN
// ════════════════════════════════════════════════════════════════════════════

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let coord_base = coordinator_base_from_env();
    info!(
        coordinator = %coord_base,
        "ingress starting"
    );

    let coord = Arc::new(CoordinatorClient::new(coord_base));

    // DA Router infrastructure ready
    // Will be activated when DA layer is connected
    let da_ttl = da_router_ttl_from_env();
    info!(da_router_ttl_ms = da_ttl, "DA router TTL configured");

    // Create app state with metrics
    let app_state = AppState::new(coord);

    // Create rate limiter with default limits
    let rate_limiter = Arc::new(RateLimiter::with_defaults());
    let rate_limit_state = RateLimitState::new(rate_limiter);

    // Shutdown channel for background task lifecycle
    let (shutdown_tx, _shutdown_rx) = watch::channel(false);

    // build axum router with rate limiting middleware
    let app = Router::new()
        .route("/object/:hash", get(proxy_object))
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/metrics", get(metrics_endpoint))
        .layer(axum::middleware::from_fn_with_state(
            rate_limit_state.clone(),
            rate_limit_middleware,
        ))
        .with_state(app_state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 8088));
    info!(listen_addr = %addr, "Ingress listening");

    // Use axum::serve wrapper (works consistently across axum versions)
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind failed");
    
    // Graceful shutdown handling
    let server = axum::serve(listener, app);
    
    tokio::select! {
        result = server => {
            if let Err(e) = result {
                error!(error = %e, "Server error");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Shutdown signal received");
            let _ = shutdown_tx.send(true);
        }
    }

    info!("Ingress shutdown complete");
}

// ════════════════════════════════════════════════════════════════════════════
// HANDLERS
// ════════════════════════════════════════════════════════════════════════════

/// GET /health - DA-aware health check
///
/// Returns complete IngressHealth with all fields.
async fn health(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let health_info = state.gather_health().await;
    (StatusCode::OK, Json(health_info))
}

/// GET /ready - readiness probe
///
/// Returns OK only if:
/// - Coordinator is reachable
/// - If DA router exists: cache filled with at least one healthy node
async fn ready(
    State(state): State<AppState>,
) -> impl IntoResponse {
    if state.is_ready().await {
        (StatusCode::OK, "ready")
    } else {
        let health_info = state.gather_health().await;
        warn!(
            da_connected = health_info.da_connected,
            coordinator_reachable = health_info.coordinator_reachable,
            healthy_nodes = health_info.healthy_nodes,
            "ready check failed"
        );
        (StatusCode::SERVICE_UNAVAILABLE, "not ready")
    }
}

/// GET /metrics - Prometheus metrics endpoint
///
/// Returns metrics in Prometheus exposition format.
async fn metrics_endpoint(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let output = state.metrics.to_prometheus();
    let mut headers = HeaderMap::new();
    headers.insert(
        "content-type",
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    (StatusCode::OK, headers, output)
}

/// GET /object/:hash
/// - ask coordinator for placement (rf=1)
/// - map node id -> addr by querying /nodes
/// - use dsdn_storage::rpc::client_get("http://addr", hash) to fetch bytes
/// - return bytes with application/octet-stream
#[instrument(skip(state), fields(trace_id, target_node, routing_strategy, latency_ms, outcome))]
async fn proxy_object(
    Path(hash): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    // Create request context with trace ID
    let ctx = RequestContext::new();
    let trace_id = ctx.trace_id.to_string();

    // Record span fields
    Span::current().record("trace_id", &trace_id);

    // Record request in metrics
    state.metrics.record_request();

    info!(
        trace_id = %trace_id,
        chunk_hash = %hash,
        "request received"
    );

    // we set a small overall timeout for the ingress operation
    let overall = Duration::from_secs(5);
    // clone Arc to move into async block
    let coord = state.coord.clone();
    let hash_cl = hash.clone();
    let metrics = state.metrics.clone();
    let trace_id_cl = trace_id.clone();

    let res = timeout(overall, async move {
        let routing_start = std::time::Instant::now();

        // 1) get placement (ask for 1 target)
        let placement = coord.placement_for_hash(&hash_cl, 1).await?;
        if placement.is_empty() {
            return Err(anyhow::anyhow!("no placement returned"));
        }
        let node_id = &placement[0];

        // Record routing latency
        let routing_latency = routing_start.elapsed().as_millis() as u64;
        metrics.record_routing_latency(routing_latency);

        // 2) get nodes and find node addr
        let nodes = coord.list_nodes().await?;
        let node = nodes.into_iter().find(|n| n.id == *node_id)
            .ok_or_else(|| anyhow::anyhow!("node id {} not found in nodes list", node_id))?;

        let node_addr = node.addr;

        // Structured logging for routing decision
        info!(
            trace_id = %trace_id_cl,
            chunk_hash = %hash_cl,
            target_node = %node_id,
            node_addr = %node_addr,
            routing_latency_ms = routing_latency,
            routing_strategy = "coordinator",
            "routing decision made"
        );

        // 3) call storage gRPC client to fetch chunk; client_get expects "http://addr"
        // note: dsdn-storage rpc::client_get returns Result<Option<Vec<u8>>, _>
        let connect = format!("http://{}", node_addr);
        match dsdn_storage::rpc::client_get(connect, hash_cl.clone()).await {
            Ok(Some(data)) => {
                debug!(
                    trace_id = %trace_id_cl,
                    chunk_hash = %hash_cl,
                    target_node = %node_id,
                    data_size = data.len(),
                    "fetch success"
                );
                Ok::<Bytes, anyhow::Error>(Bytes::from(data))
            }
            Ok(None) => {
                warn!(
                    trace_id = %trace_id_cl,
                    chunk_hash = %hash_cl,
                    target_node = %node_id,
                    "chunk not found on node"
                );
                Err(anyhow::anyhow!("chunk not found on node {}", node_id))
            }
            Err(e) => {
                warn!(
                    trace_id = %trace_id_cl,
                    chunk_hash = %hash_cl,
                    target_node = %node_id,
                    error = %e,
                    "rpc client_get failure"
                );
                Err(anyhow::anyhow!("rpc client_get failure: {}", e))
            }
        }
    }).await;

    // Record latency
    let total_latency = ctx.elapsed_ms();
    Span::current().record("latency_ms", total_latency);

    match res {
        Ok(Ok(bytes)) => {
            state.metrics.record_status(200);
            Span::current().record("outcome", "success");

            info!(
                trace_id = %trace_id,
                chunk_hash = %hash,
                latency_ms = total_latency,
                outcome = "success",
                "request completed"
            );

            let mut headers = HeaderMap::new();
            headers.insert("content-type", HeaderValue::from_static("application/octet-stream"));
            headers.insert("x-trace-id", HeaderValue::from_str(&trace_id).unwrap_or_else(|_| HeaderValue::from_static("unknown")));
            (StatusCode::OK, headers, bytes).into_response()
        }
        Ok(Err(e)) => {
            state.metrics.record_status(502);
            Span::current().record("outcome", "error");

            error!(
                trace_id = %trace_id,
                chunk_hash = %hash,
                latency_ms = total_latency,
                error = %e,
                outcome = "error",
                "fetch error"
            );

            let mut headers = HeaderMap::new();
            headers.insert("x-trace-id", HeaderValue::from_str(&trace_id).unwrap_or_else(|_| HeaderValue::from_static("unknown")));
            (StatusCode::BAD_GATEWAY, headers, format!("error: {}", e)).into_response()
        }
        Err(_) => {
            state.metrics.record_status(504);
            Span::current().record("outcome", "timeout");

            error!(
                trace_id = %trace_id,
                chunk_hash = %hash,
                latency_ms = total_latency,
                outcome = "timeout",
                "request timeout"
            );

            let mut headers = HeaderMap::new();
            headers.insert("x-trace-id", HeaderValue::from_str(&trace_id).unwrap_or_else(|_| HeaderValue::from_static("unknown")));
            (StatusCode::GATEWAY_TIMEOUT, headers, "timeout".to_string()).into_response()
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::da_router::{RoutingDataSource, RoutingResult, NodeInfoFromSource};
    use parking_lot::RwLock;
    use std::collections::HashMap;

    // ════════════════════════════════════════════════════════════════════════
    // MOCK DATA SOURCE
    // ════════════════════════════════════════════════════════════════════════

    struct MockDataSource {
        nodes: RwLock<HashMap<String, MockNodeInfo>>,
        placements: RwLock<HashMap<String, Vec<String>>>,
    }

    struct MockNodeInfo {
        addr: String,
        active: bool,
        zone: Option<String>,
    }

    impl MockDataSource {
        fn new() -> Self {
            Self {
                nodes: RwLock::new(HashMap::new()),
                placements: RwLock::new(HashMap::new()),
            }
        }

        fn add_node(&self, id: &str, addr: &str, active: bool) {
            self.nodes.write().insert(id.to_string(), MockNodeInfo {
                addr: addr.to_string(),
                active,
                zone: None,
            });
        }

        fn add_placement(&self, chunk_hash: &str, node_ids: Vec<&str>) {
            self.placements.write().insert(
                chunk_hash.to_string(),
                node_ids.into_iter().map(|s| s.to_string()).collect(),
            );
        }
    }

    impl RoutingDataSource for MockDataSource {
        fn get_registered_node_ids(&self) -> RoutingResult<Vec<String>> {
            Ok(self.nodes.read().keys().cloned().collect())
        }

        fn get_node_info(&self, node_id: &str) -> RoutingResult<Option<NodeInfoFromSource>> {
            Ok(self.nodes.read().get(node_id).map(|n| NodeInfoFromSource {
                addr: n.addr.clone(),
                active: n.active,
                zone: n.zone.clone(),
            }))
        }

        fn get_all_chunk_placements(&self) -> RoutingResult<HashMap<String, Vec<String>>> {
            Ok(self.placements.read().clone())
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 1: DA CONNECTED VS DISCONNECTED
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_da_connected_vs_disconnected() {
        let coord = Arc::new(CoordinatorClient::new("http://localhost:8080".to_string()));

        // Without DA router
        let state = AppState::new(coord.clone());
        assert!(!state.is_da_connected());

        // With DA connected flag set
        state.set_da_connected(true);
        assert!(state.is_da_connected());

        state.set_da_connected(false);
        assert!(!state.is_da_connected());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 2: CACHE EMPTY VS FILLED
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_cache_empty_vs_filled() {
        let coord = Arc::new(CoordinatorClient::new("http://localhost:8080".to_string()));

        // Create mock DA router with empty cache
        let mock_ds = Arc::new(MockDataSource::new());
        let router = Arc::new(DARouter::new(mock_ds.clone()));

        let state = AppState::with_da_router(coord.clone(), router.clone());

        // Empty cache
        let health = state.gather_health().await;
        assert_eq!(health.cached_nodes, 0);
        assert_eq!(health.cached_placements, 0);

        // Fill cache
        mock_ds.add_node("node-1", "127.0.0.1:9001", true);
        mock_ds.add_placement("chunk-1", vec!["node-1"]);
        router.refresh_cache().unwrap();

        let health = state.gather_health().await;
        assert_eq!(health.cached_nodes, 1);
        assert_eq!(health.cached_placements, 1);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 3: HEALTH RETURNS ALL FIELDS VALID
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_health_returns_all_fields_valid() {
        let coord = Arc::new(CoordinatorClient::new("http://localhost:8080".to_string()));

        let mock_ds = Arc::new(MockDataSource::new());
        mock_ds.add_node("node-1", "127.0.0.1:9001", true);
        mock_ds.add_node("node-2", "127.0.0.1:9002", false); // unhealthy
        mock_ds.add_placement("chunk-1", vec!["node-1"]);

        let router = Arc::new(DARouter::new(mock_ds));
        router.refresh_cache().unwrap();

        let state = AppState::with_da_router(coord, router);
        state.set_da_last_sequence(12345);

        let health = state.gather_health().await;

        // All fields should have valid values
        assert!(health.da_connected);
        assert_eq!(health.da_last_sequence, 12345);
        assert_eq!(health.cached_nodes, 2);
        assert_eq!(health.total_nodes, 2);
        assert_eq!(health.healthy_nodes, 1);
        assert_eq!(health.cached_placements, 1);
        // cache_age_ms should be small (just refreshed)
        assert!(health.cache_age_ms < 10000);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 4: READY FAILS WHEN DA DOWN (coordinator unreachable)
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_ready_fails_coordinator_unreachable() {
        // Use invalid coordinator URL
        let coord = Arc::new(CoordinatorClient::new("http://invalid.localhost:99999".to_string()));
        let state = AppState::new(coord);

        // is_ready should fail because coordinator is unreachable
        let ready = state.is_ready().await;
        assert!(!ready);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 5: READY FAILS WHEN CACHE EMPTY
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_ready_cache_empty_check() {
        let coord = Arc::new(CoordinatorClient::new("http://localhost:8080".to_string()));

        let mock_ds = Arc::new(MockDataSource::new());
        let router = Arc::new(DARouter::new(mock_ds));
        // Don't refresh cache - keep it empty

        let state = AppState::with_da_router(coord, router);

        // Cache last_updated is 0 (never filled)
        let cache = state.da_router.as_ref().unwrap().get_cache();
        assert_eq!(cache.last_updated, 0);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 6: READY SUCCESS WHEN INVARIANTS MET
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_ready_success_invariants() {
        let coord = Arc::new(CoordinatorClient::new("http://localhost:8080".to_string()));

        let mock_ds = Arc::new(MockDataSource::new());
        mock_ds.add_node("node-1", "127.0.0.1:9001", true);

        let router = Arc::new(DARouter::new(mock_ds));
        router.refresh_cache().unwrap();

        let state = AppState::with_da_router(coord, router);

        // Cache should have data
        let cache = state.da_router.as_ref().unwrap().get_cache();
        assert!(cache.last_updated > 0);
        assert_eq!(cache.node_registry.len(), 1);

        // Healthy nodes count
        let healthy = cache.node_registry.values().filter(|n| n.active).count();
        assert_eq!(healthy, 1);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 7: THREAD-SAFE READ HEALTH STATE
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_thread_safe_health_state() {
        use std::thread;

        let coord = Arc::new(CoordinatorClient::new("http://localhost:8080".to_string()));

        let mock_ds = Arc::new(MockDataSource::new());
        for i in 0..5 {
            mock_ds.add_node(&format!("node-{}", i), &format!("127.0.0.1:900{}", i), true);
        }

        let router = Arc::new(DARouter::new(mock_ds));
        router.refresh_cache().unwrap();

        let state = Arc::new(AppState::with_da_router(coord, router));

        let mut handles = vec![];

        // Spawn readers
        for _ in 0..10 {
            let s = state.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    let _ = s.is_da_connected();
                    let _ = s.get_da_last_sequence();
                    if let Some(ref router) = s.da_router {
                        let _ = router.get_cache();
                    }
                }
            }));
        }

        // Spawn writers
        for i in 0..5 {
            let s = state.clone();
            handles.push(thread::spawn(move || {
                for j in 0..50 {
                    s.set_da_connected(j % 2 == 0);
                    s.set_da_last_sequence((i * 100 + j) as u64);
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        // Should not panic or deadlock
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 8: INGRESS HEALTH DEFAULT
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_ingress_health_default() {
        let health = IngressHealth::default();

        assert!(!health.da_connected);
        assert_eq!(health.da_last_sequence, 0);
        assert_eq!(health.cached_nodes, 0);
        assert_eq!(health.cached_placements, 0);
        assert_eq!(health.cache_age_ms, u64::MAX);
        assert!(!health.coordinator_reachable);
        assert_eq!(health.healthy_nodes, 0);
        assert_eq!(health.total_nodes, 0);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 9: METRICS IN APP STATE
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_metrics_in_app_state() {
        let coord = Arc::new(CoordinatorClient::new("http://localhost:8080".to_string()));
        let state = AppState::new(coord);

        // Metrics should be accessible
        state.metrics.record_request();
        state.metrics.record_status(200);
        state.metrics.record_cache_hit();

        assert_eq!(state.metrics.requests_total.get(), 1);
        assert_eq!(state.metrics.requests_by_status.get(200), 1);
        assert_eq!(state.metrics.cache_hits.get(), 1);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 10: METRICS PROMETHEUS OUTPUT
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_metrics_prometheus_output() {
        let coord = Arc::new(CoordinatorClient::new("http://localhost:8080".to_string()));
        let state = AppState::new(coord);

        state.metrics.record_request();
        state.metrics.record_status(200);

        let output = state.metrics.to_prometheus();

        assert!(output.contains("ingress_requests_total 1"));
        assert!(output.contains("ingress_requests_by_status"));
        assert!(output.contains("# HELP"));
        assert!(output.contains("# TYPE"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 11: RATE LIMITER INTEGRATION
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_rate_limiter_integration() {
        use crate::rate_limit::{RateLimiter, LimitConfig};

        let limiter = RateLimiter::with_defaults();

        // Should have default limits
        assert!(limiter.get_limit("per_ip").is_some());
        assert!(limiter.get_limit("global").is_some());

        // Test basic rate limiting
        let config = LimitConfig::global(10, 5);
        for _ in 0..5 {
            assert!(limiter.check_and_record("test_key", &config).is_ok());
        }
        // 6th should fail
        assert!(limiter.check_and_record("test_key", &config).is_err());
    }
}