use axum::{
    extract::{Path, Query, State},
    routing::{get, post},
    Router,
    Json,
};
use std::net::SocketAddr;
use std::sync::Arc;
use serde::Deserialize;
use tracing_subscriber;
use dsdn_coordinator::{Coordinator, NodeInfo, Workload};
use serde_json::{Value, json};

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

async fn register_node(
    State(coord): State<Arc<Coordinator>>,
    Json(payload): Json<RegisterNodeReq>,
) -> Json<Value> {
    let info = NodeInfo {
        id: payload.id,
        zone: payload.zone,
        addr: payload.addr,
        capacity_gb: payload.capacity_gb.unwrap_or(100),
        meta: serde_json::json!({}),
    };
    coord.register_node(info);
    Json(json!({"ok": true}))
}

async fn list_nodes(
    State(coord): State<Arc<Coordinator>>,
) -> Json<Value> {
    let nodes = coord.list_nodes();
    Json(json!(nodes))
}

async fn placement(
    Path(hash): Path<String>,
    Query(q): Query<PlacementQuery>,
    State(coord): State<Arc<Coordinator>>,
) -> Json<Value> {
    let rf = q.rf.unwrap_or(3);
    let sel = coord.placement_for_hash(&hash, rf);
    Json(json!(sel))
}

async fn register_object(
    State(coord): State<Arc<Coordinator>>,
    Json(payload): Json<RegisterObjectReq>,
) -> Json<Value> {
    coord.register_object(payload.hash, payload.size);
    Json(json!({"ok": true}))
}

async fn mark_missing(
    State(coord): State<Arc<Coordinator>>,
    Json(payload): Json<ReplicaReq>,
) -> Json<Value> {
    coord.mark_replica_missing(&payload.hash, &payload.node_id);
    Json(json!({"ok": true}))
}

async fn mark_healed(
    State(coord): State<Arc<Coordinator>>,
    Json(payload): Json<ReplicaReq>,
) -> Json<Value> {
    coord.mark_replica_healed(&payload.hash, &payload.node_id);
    Json(json!({"ok": true}))
}

async fn get_object(
    Path(hash): Path<String>,
    State(coord): State<Arc<Coordinator>>,
) -> (axum::http::StatusCode, Json<Value>) {
    match coord.get_object(&hash) {
        Some(o) => {
            let val = serde_json::to_value(o).unwrap_or_else(|_| json!({}));
            (axum::http::StatusCode::OK, Json(val))
        }
        None => (axum::http::StatusCode::NOT_FOUND, Json(json!({"error":"not found"}))),
    }
}

/// New: schedule a workload. Accepts Workload JSON and returns node id string if found.
async fn schedule_workload(
    State(coord): State<Arc<Coordinator>>,
    Json(payload): Json<Workload>,
) -> (axum::http::StatusCode, Json<Value>) {
    match coord.schedule(&payload) {
        Some(node_id) => (axum::http::StatusCode::OK, Json(json!({ "node_id": node_id }))),
        None => (axum::http::StatusCode::NOT_FOUND, Json(json!({ "error": "no suitable node" }))),
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let coord = Arc::new(Coordinator::new());

    let app = Router::new()
        .route("/register", post(register_node))
        .route("/nodes", get(list_nodes))
        .route("/placement/:hash", get(placement))
        .route("/object/register", post(register_object))
        .route("/object/:hash", get(get_object))
        .route("/replica/mark_missing", post(mark_missing))
        .route("/replica/mark_healed", post(mark_healed))
        .route("/schedule", post(schedule_workload))
        .with_state(coord);

    let addr = SocketAddr::from(([127,0,0,1], 8080));
    tracing::info!("Coordinator listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
