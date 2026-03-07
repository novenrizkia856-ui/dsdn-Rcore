use axum::{
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    Json,
};
use bytes::Bytes;
use std::time::Duration;
use tracing::{info, warn, debug, instrument, Span};
use tokio::time::timeout;

use crate::app_state::AppState;
use crate::types::{FallbackStatusResponse, ReadyStatus};
use crate::helpers::current_timestamp_ms;
use crate::metrics::RequestContext;

// ════════════════════════════════════════════════════════════════════════════
// HANDLERS
// ════════════════════════════════════════════════════════════════════════════

/// GET /health - DA-aware health check
///
/// Returns complete IngressHealth with all fields.
pub async fn health(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let health_info = state.gather_health().await;
    (StatusCode::OK, Json(health_info))
}

/// GET /ready - readiness probe (14A.1A.66)
///
/// Evaluates readiness conditions:
/// 1. Coordinator reachable → jika tidak: HTTP 503
/// 2. DA available (primary OR fallback OR emergency) → jika tidak: HTTP 503
/// 3. Fallback active > 10 menit → DEGRADED (HTTP 200 + X-Warning)
/// 4. Pending reconcile > 1000 → DEGRADED (HTTP 200 + X-Warning)
///
/// ## Response Status
///
/// - **HTTP 200** (Ready): Normal operation
/// - **HTTP 200 + X-Warning** (Degraded): Fallback active dengan threshold terlampaui
/// - **HTTP 503** (Not Ready): Coordinator unreachable atau no DA available
pub async fn ready(
    State(state): State<AppState>,
) -> impl IntoResponse {
    match state.check_ready().await {
        ReadyStatus::Ready => {
            // Normal ready - HTTP 200 tanpa warning
            debug!("ready check: READY (normal)");
            let mut headers = HeaderMap::new();
            (StatusCode::OK, headers, "ready")
        }

        ReadyStatus::ReadyDegraded(warning) => {
            // Degraded but still ready - HTTP 200 dengan X-Warning header
            debug!(warning = %warning, "ready check: READY (degraded)");
            let mut headers = HeaderMap::new();

            // Set X-Warning header dengan warning message
            // HeaderValue::from_str bisa gagal jika string mengandung karakter invalid
            // Menggunakan from_bytes sebagai fallback yang lebih aman
            if let Ok(header_value) = HeaderValue::from_str(&warning) {
                headers.insert("X-Warning", header_value);
            } else {
                // Jika warning mengandung karakter invalid, gunakan sanitized version
                // Ini seharusnya tidak terjadi karena warning dibangun dari string yang valid
                headers.insert(
                    "X-Warning",
                    HeaderValue::from_static("DEGRADED: see /fallback/status for details")
                );
            }

            (StatusCode::OK, headers, "ready")
        }

        ReadyStatus::NotReady(reason) => {
            // Not ready - HTTP 503
            let health_info = state.gather_health().await;
            warn!(
                reason = %reason,
                da_connected = health_info.da_connected,
                coordinator_reachable = health_info.coordinator_reachable,
                healthy_nodes = health_info.healthy_nodes,
                fallback_active = health_info.fallback_active,
                "ready check failed"
            );

            let mut headers = HeaderMap::new();
            (StatusCode::SERVICE_UNAVAILABLE, headers, "not ready")
        }
    }
}

/// GET /metrics - Prometheus metrics endpoint
///
/// Returns metrics in Prometheus exposition format.
///
/// ## Fallback Metrics (14A.1A.67)
///
/// Before generating output, this handler updates fallback metrics
/// from the current AppState:
/// - `ingress_fallback_active`
/// - `ingress_fallback_duration_seconds`
/// - `ingress_fallback_events_total{source=...}`
/// - `ingress_fallback_pending_reconcile`
/// - `ingress_da_primary_healthy`
/// - `ingress_da_secondary_healthy`
pub async fn metrics_endpoint(
    State(state): State<AppState>,
) -> impl IntoResponse {
    // Update fallback metrics from current state (14A.1A.67)
    // Semua data diambil dari sumber aktual, tidak ada fabrication
    if let Some(fallback_info) = state.gather_fallback_status() {
        state.metrics.update_fallback_metrics(
            fallback_info.active,
            fallback_info.duration_secs,
            fallback_info.pending_reconcile,
            !fallback_info.status.requires_fallback(), // primary healthy jika tidak perlu fallback
            None, // secondary health dari DAHealthMonitor (belum tersedia)
        );
    } else {
        // No fallback info available - set defaults (not fabricated, just "no data")
        state.metrics.update_fallback_metrics(
            false, // not active
            None,  // no duration
            0,     // no pending
            true,  // assume primary healthy if no fallback data
            None,  // secondary not configured
        );
    }

    let output = state.metrics.to_prometheus();
    let mut headers = HeaderMap::new();
    headers.insert(
        "content-type",
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    (StatusCode::OK, headers, output)
}

/// GET /fallback/status - Fallback status endpoint (14A.1A.65)
///
/// SOURCE OF TRUTH untuk status fallback.
///
/// ## Behavior
///
/// - Jika DARouter TIDAK dikonfigurasi: HTTP 404
/// - Jika DARouter dikonfigurasi: HTTP 200 dengan FallbackStatusResponse
///
/// ## Guarantees
///
/// - **NO panic**: Tidak pernah panic
/// - **NO unwrap/expect**: Semua error handling eksplisit
/// - **NO fabricated data**: Semua data dari sumber aktual
/// - **Deterministic**: Hasil konsisten untuk state yang sama
pub async fn fallback_status(
    State(state): State<AppState>,
) -> impl IntoResponse {
    // Cek apakah DARouter dikonfigurasi
    // Jika tidak ada → return 404
    if state.da_router.is_none() {
        debug!("fallback_status: da_router not configured, returning 404");
        return (StatusCode::NOT_FOUND, Json(None::<FallbackStatusResponse>));
    }

    // Ambil fallback status dari gather_fallback_status()
    // Jika None → return 404 (DARouter ada tapi health_monitor tidak tersedia)
    let fallback_info = match state.gather_fallback_status() {
        Some(info) => info,
        None => {
            debug!("fallback_status: gather_fallback_status returned None, returning 404");
            return (StatusCode::NOT_FOUND, Json(None::<FallbackStatusResponse>));
        }
    };

    // Hitung time_since_last_primary_contact_secs
    // Menggunakan saturating arithmetic untuk menghindari overflow
    let time_since_last_primary_contact_secs = fallback_info.last_celestia_contact.map(|last_contact| {
        let current_secs = current_timestamp_ms() / 1000;
        current_secs.saturating_sub(last_contact)
    });

    // Bangun response
    let response = FallbackStatusResponse {
        info: fallback_info.clone(),
        time_since_last_primary_contact_secs,
        reconciliation_queue_depth: fallback_info.pending_reconcile,
        // events_processed: None karena data tidak tersedia dari current DARouter implementation
        // Field ini TIDAK di-fabricate atau di-hardcode
        // Akan diisi ketika DARouter menyediakan metrics per-source
        events_processed: None,
    };

    debug!(
        fallback_active = response.info.active,
        time_since_primary = ?time_since_last_primary_contact_secs,
        queue_depth = response.reconciliation_queue_depth,
        "fallback_status: returning 200"
    );

    (StatusCode::OK, Json(Some(response)))
}

/// GET /object/:hash
/// - ask coordinator for placement (rf=1)
/// - map node id -> addr by querying /nodes
/// - use dsdn_storage::rpc::client_get("http://addr", hash) to fetch bytes
/// - return bytes with application/octet-stream
#[instrument(skip(state), fields(trace_id, target_node, routing_strategy, latency_ms, outcome))]
pub async fn proxy_object(
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
            state.metrics.record_status(404);
            Span::current().record("outcome", "not_found");

            warn!(
                trace_id = %trace_id,
                chunk_hash = %hash,
                latency_ms = total_latency,
                outcome = "not_found",
                error = %e,
                "request failed"
            );

            (StatusCode::NOT_FOUND, "chunk not found").into_response()
        }
        Err(_timeout) => {
            state.metrics.record_status(504);
            Span::current().record("outcome", "timeout");

            warn!(
                trace_id = %trace_id,
                chunk_hash = %hash,
                latency_ms = total_latency,
                outcome = "timeout",
                "request timeout"
            );

            (StatusCode::GATEWAY_TIMEOUT, "request timed out").into_response()
        }
    }
}