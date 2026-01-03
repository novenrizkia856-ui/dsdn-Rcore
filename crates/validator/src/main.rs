use axum::{
    extract::State,
    routing::post,
    Router,
    Json,
};
use std::sync::Arc;
use std::net::SocketAddr;
use serde_json::json;
use tracing_subscriber;
use dsdn_validator::{Validator, Manifest};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let validator = Arc::new(Validator::new());

    // optional: ban demo hash
    validator.ban_hash("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");

    let app = Router::new()
        .route("/validate", post(validate_handler))
        .with_state(validator);

    let addr = SocketAddr::from(([127,0,0,1], 9090));
    tracing::info!("Validator listening on {}", addr);

    // AXUM 0.7: gunakan TcpListener + serve()
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn validate_handler(
    State(validator): State<Arc<Validator>>,
    Json(man): Json<Manifest>,
) -> Json<serde_json::Value> {
    match validator.validate_manifest(&man) {
        Ok(v) => Json(json!({
            "ok": v.ok,
            "errors": v.errors,
            "warnings": v.warnings
        })),
        Err(e) => Json(json!({
            "ok": false,
            "errors": [format!("internal error: {}", e)]
        })),
    }
}
