use axum::{
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    routing::get,
    Router,
    response::IntoResponse,
};
use bytes::Bytes;
use std::{env, net::SocketAddr, sync::Arc, time::Duration};
use tracing::{error, info, warn};
use tracing_subscriber;
use tokio::time::timeout;
use tokio::sync::watch;

mod coord_client;
mod da_router;
mod routing;
mod fallback;

use coord_client::CoordinatorClient;
// DARouter akan digunakan ketika DA layer connected
// For now, only DEFAULT_CACHE_TTL_MS is used for configuration
use da_router::DEFAULT_CACHE_TTL_MS;

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

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let coord_base = coordinator_base_from_env();
    info!("ingress starting; coordinator = {}", coord_base);

    let coord = Arc::new(CoordinatorClient::new(coord_base));

    // DA Router infrastructure ready
    // Will be activated when DA layer is connected
    let da_ttl = da_router_ttl_from_env();
    info!("DA router TTL configured: {}ms", da_ttl);

    // Shutdown channel for background task lifecycle
    let (shutdown_tx, _shutdown_rx) = watch::channel(false);

    // build axum router
    let app = Router::new()
        .route("/object/:hash", get(proxy_object))
        .route("/health", get(health))
        .route("/ready", get(ready))
        .with_state(coord);

    let addr = SocketAddr::from(([127, 0, 0, 1], 8088));
    info!("Ingress listening on {}", addr);

    // Use axum::serve wrapper (works consistently across axum versions)
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind failed");
    
    // Graceful shutdown handling
    let server = axum::serve(listener, app);
    
    tokio::select! {
        result = server => {
            if let Err(e) = result {
                error!("Server error: {}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Shutdown signal received");
            let _ = shutdown_tx.send(true);
        }
    }

    info!("Ingress shutdown complete");
}

/// GET /health
async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

/// GET /ready - check coordinator reachable
async fn ready(
    State(coord): State<Arc<CoordinatorClient>>,
) -> impl IntoResponse {
    match coord.ping().await {
        Ok(()) => (StatusCode::OK, "ready"),
        Err(e) => {
            warn!("ready: coordinator not ready: {}", e);
            (StatusCode::SERVICE_UNAVAILABLE, "not ready")
        }
    }
}

/// GET /object/:hash
/// - ask coordinator for placement (rf=1)
/// - map node id -> addr by querying /nodes
/// - use dsdn_storage::rpc::client_get("http://addr", hash) to fetch bytes
/// - return bytes with application/octet-stream
async fn proxy_object(
    Path(hash): Path<String>,
    State(coord): State<Arc<CoordinatorClient>>,
) -> impl IntoResponse {
    info!("ingress: request for object {}", hash);

    // we set a small overall timeout for the ingress operation
    let overall = Duration::from_secs(5);
    // clone Arc to move into async block
    let coord_cl = coord.clone();
    let hash_cl = hash.clone();

    let res = timeout(overall, async move {
        // 1) get placement (ask for 1 target)
        let placement = coord_cl.placement_for_hash(&hash_cl, 1).await?;
        if placement.is_empty() {
            return Err(anyhow::anyhow!("no placement returned"));
        }
        let node_id = &placement[0];

        // 2) get nodes and find node addr
        let nodes = coord_cl.list_nodes().await?;
        let node = nodes.into_iter().find(|n| n.id == *node_id)
            .ok_or_else(|| anyhow::anyhow!("node id {} not found in nodes list", node_id))?;

        let node_addr = node.addr;
        info!("ingress: routing {} -> node {} (addr {})", hash_cl, node_id, node_addr);

        // 3) call storage gRPC client to fetch chunk; client_get expects "http://addr"
        // note: dsdn-storage rpc::client_get returns Result<Option<Vec<u8>>, _>
        let connect = format!("http://{}", node_addr);
        match dsdn_storage::rpc::client_get(connect, hash_cl.clone()).await {
            Ok(Some(data)) => {
                Ok::<Bytes, anyhow::Error>(Bytes::from(data))
            }
            Ok(None) => Err(anyhow::anyhow!("chunk not found on node {}", node_id)),
            Err(e) => Err(anyhow::anyhow!("rpc client_get failure: {}", e)),
        }
    }).await;

    match res {
        Ok(Ok(bytes)) => {
            let mut headers = HeaderMap::new();
            headers.insert("content-type", HeaderValue::from_static("application/octet-stream"));
            (StatusCode::OK, headers, bytes).into_response()
        }
        Ok(Err(e)) => {
            error!("ingress: fetch error: {}", e);
            (StatusCode::BAD_GATEWAY, format!("error: {}", e)).into_response()
        }
        Err(_) => {
            error!("ingress: timeout fetching {}", hash);
            (StatusCode::GATEWAY_TIMEOUT, "timeout").into_response()
        }
    }
}