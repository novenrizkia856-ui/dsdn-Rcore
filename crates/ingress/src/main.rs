//! # DSDN Ingress (14A)
//!
//! HTTP gateway untuk akses data DSDN dengan fallback-aware routing.
//!
//! ## Architecture
//!
//! ```text
//!                                    ┌─────────────────────────────────┐
//!                                    │         DSDN Ingress            │
//!                                    │     (HTTP Gateway - 14A)        │
//!                                    └─────────────────────────────────┘
//!                                                   │
//!         ┌─────────────────────────────────────────┼─────────────────────────────────────────┐
//!         │                                         │                                         │
//!         ▼                                         ▼                                         ▼
//!    ┌─────────┐                            ┌──────────────┐                          ┌──────────────┐
//!    │ Client  │ ◀───── HTTP Request ─────▶ │   Router     │ ◀──── State ────────────▶│  AppState    │
//!    └─────────┘                            └──────────────┘                          └──────────────┘
//!                                                   │                                         │
//!                                                   │                                         │
//!                                                   ▼                                         ▼
//!                                          ┌──────────────┐                          ┌──────────────┐
//!                                          │  DARouter    │ ◀─── Fallback Info ─────▶│ AlertDispatch│
//!                                          └──────────────┘                          └──────────────┘
//!                                                   │
//!                     ┌─────────────────────────────┼─────────────────────────────┐
//!                     │                             │                             │
//!                     ▼                             ▼                             ▼
//!             ┌──────────────┐             ┌──────────────┐             ┌──────────────┐
//!             │  Celestia    │             │  QuorumDA    │             │ EmergencyDA  │
//!             │  (Primary)   │             │ (Secondary)  │             │  (Fallback)  │
//!             └──────────────┘             └──────────────┘             └──────────────┘
//!                     │                             │                             │
//!                     └─────────────────────────────┴─────────────────────────────┘
//!                                                   │
//!                                                   ▼
//!                                          ┌──────────────┐
//!                                          │FallbackHealth│
//!                                          │    Info      │
//!                                          └──────────────┘
//! ```
//!
//! ## Endpoints
//!
//! ### Core Endpoints
//!
//! | Endpoint            | Method | Description                              |
//! |---------------------|--------|------------------------------------------|
//! | `/object/:hash`     | GET    | Fetch object by hash                     |
//! | `/health`           | GET    | Health check (DA-aware)                  |
//! | `/ready`            | GET    | Readiness probe (fallback-aware)         |
//! | `/metrics`          | GET    | Prometheus metrics (includes fallback)   |
//!
//! ### Fallback Endpoints
//!
//! | Endpoint            | Method | Description                              |
//! |---------------------|--------|------------------------------------------|
//! | `/fallback/status`  | GET    | Fallback status (source of truth)        |
//!
//! ### Receipt Status Endpoints (14C.C.24)
//!
//! | Endpoint              | Method | Description                              |
//! |-----------------------|--------|------------------------------------------|
//! | `/receipt/:hash`      | GET    | Query single receipt status by hash      |
//! | `/receipts/status`    | POST   | Batch query up to 100 receipt hashes     |
//!
//! #### Receipt Status Values
//!
//! `pending` · `challenge_period` · `finalized` · `challenged` · `rejected` · `not_found`
//!
//! #### Hash Validation
//!
//! Hex-only, exactly 64 chars, no whitespace, no `0x` prefix.
//! Invalid hash → HTTP 400.
//!
//! #### Batch Rules
//!
//! Min 1, max 100 hashes. Response order matches input order.
//!
//! ### Reward Balance Endpoints (14C.C.25)
//!
//! | Endpoint              | Method | Description                              |
//! |-----------------------|--------|------------------------------------------|
//! | `/rewards/:address`   | GET    | Query reward balance by address          |
//! | `/rewards/validators` | GET    | List all validator reward summaries       |
//! | `/rewards/treasury`   | GET    | Query treasury reward statistics          |
//!
//! #### Address Validation
//!
//! Hex-only, exactly 40 chars, no whitespace, no `0x` prefix.
//! Invalid address → HTTP 400.
//!
//! #### Validator List
//!
//! Sorted by `validator_id` (lexicographic). Deterministic order guaranteed.
//!
//! ### Fraud Proof Endpoints (14C.C.26)
//!
//! | Endpoint              | Method | Description                              |
//! |-----------------------|--------|------------------------------------------|
//! | `/fraud-proof`        | POST   | Submit fraud proof (placeholder only)    |
//! | `/fraud-proofs`       | GET    | List all fraud proof submissions         |
//!
//! #### Placeholder Note
//!
//! All submissions are logged but NOT processed. Verification, arbitration,
//! slashing, and challenge resolution deferred to Tahap 18.8.
//!
//! ### Claim Endpoint (14C.C.28)
//!
//! | Endpoint              | Method | Description                              |
//! |-----------------------|--------|------------------------------------------|
//! | `/claim`              | POST   | Submit reward claim                      |
//!
//! ### DA Event Logging (14C.C.28)
//!
//! All receipt economic events (claims, fraud proofs) are logged to
//! [`ReceiptEventLogger`] for DA audit trail. Events are buffered and
//! flushed through an [`EventPublisher`] (or fallback to file).
//!
//! ## Economic Endpoints (14C.C.24–14C.C.29)
//!
//! ### Request Flow
//!
//! ```text
//! dispatch → execute → receipt → claim → reward → DA log
//!
//! Node executes workload
//!        │
//!        ▼
//! Coordinator generates receipt (TSS-signed)
//!        │
//!        ▼
//! Client submits claim via POST /claim
//!        │
//!        ▼
//! Ingress validates request (economic_validation)
//!        │
//!        ▼
//! ChainForwarder forwards to chain (retry + timeout)
//!        │
//!        ▼
//! Chain verifies receipt → distributes reward
//!        │    70% node · 20% validator · 10% treasury
//!        │
//!        ▼
//! ReceiptEventLogger records DA audit events
//! ```
//!
//! ### Endpoint Reference
//!
//! | Endpoint               | Method | Description                          | Rate Limit       |
//! |------------------------|--------|--------------------------------------|------------------|
//! | `POST /claim`          | POST   | Submit reward claim                  | 10 req/min/IP    |
//! | `GET /receipt/:hash`   | GET    | Query single receipt status          | 60 req/min/IP    |
//! | `POST /receipts/status`| POST   | Batch query up to 100 hashes         | 60 req/min/IP    |
//! | `GET /rewards/:address`| GET    | Query reward balance by address      | 60 req/min/IP    |
//! | `GET /rewards/validators`| GET  | List all validator reward summaries   | 60 req/min/IP    |
//! | `GET /rewards/treasury`| GET    | Query treasury reward statistics     | 60 req/min/IP    |
//! | `POST /fraud-proof`    | POST   | Submit fraud proof (placeholder)     | 10 req/min/IP    |
//! | `GET /fraud-proofs`    | GET    | List all fraud proof submissions     | 60 req/min/IP    |
//!
//! ### Rate Limiting
//!
//! Mutation endpoints (`/claim`, `/fraud-proof`): **10 req/min per IP**
//! Query endpoints (all others): **60 req/min per IP**
//!
//! ### Fraud Proof Notice
//!
//! **The `/fraud-proof` endpoint is a placeholder only.** Submissions are
//! logged but NOT processed. Full verification, arbitration, slashing, and
//! challenge resolution will be implemented in **Tahap 18.8**.
//!
//! ### Request/Response Schemas
//!
//! #### POST /claim
//!
//! Request: `{ "receipt_hash": "abc..64hex", "submitter_address": "abc..40hex", "receipt_data": [1,2,3] }`
//! Response: `{ "success": true, "message": "claim accepted (stub)" }`
//!
//! #### GET /receipt/:hash
//!
//! Response: `{ "receipt_hash": "...", "status": "finalized", "reward_amount": 1000, ... }`
//!
//! #### POST /receipts/status
//!
//! Request: `{ "hashes": ["abc..64hex", "def..64hex"] }`
//! Response: `[{ "receipt_hash": "...", "status": "..." }, ...]`
//!
//! #### GET /rewards/:address
//!
//! Response: `{ "address": "...", "balance": 0, "pending_rewards": 0, ... }`
//!
//! #### POST /fraud-proof
//!
//! Request: `{ "receipt_hash": "abc..64hex", "proof_type": "execution_mismatch", "proof_data": [1], "submitter_address": "abc..40hex" }`
//! Response: `{ "accepted": true, "fraud_proof_id": "fp-...", "message": "...", "note": "placeholder..." }`
//!
//! ## Endpoint Details
//!
//! ### GET /health
//!
//! Returns comprehensive health information including:
//! - DA connectivity status
//! - Cache state (nodes, placements, age)
//! - Coordinator reachability
//! - Fallback status (if available)
//! - DA layer health (primary, secondary, emergency)
//!
//! **Response:** `IngressHealth` JSON
//!
//! ### GET /ready
//!
//! Kubernetes-compatible readiness probe dengan fallback awareness.
//!
//! | Condition                          | HTTP Status | Header        |
//! |------------------------------------|-------------|---------------|
//! | Ready (normal)                     | 200         | -             |
//! | Ready (degraded, fallback active)  | 200         | X-Warning     |
//! | Not Ready (coordinator down)       | 503         | -             |
//! | Not Ready (no DA available)        | 503         | -             |
//!
//! **Degraded Thresholds:**
//! - Fallback active > 600 seconds (10 minutes)
//! - Pending reconcile > 1000 items
//!
//! ### GET /metrics
//!
//! Prometheus-format metrics endpoint dengan fallback metrics:
//!
//! **Fallback Metrics:**
//! - `ingress_fallback_active` (gauge): 1 if fallback active, 0 otherwise
//! - `ingress_fallback_duration_seconds` (gauge): Duration of current fallback
//! - `ingress_fallback_events_total` (counter): Total fallback events by source
//! - `ingress_fallback_pending_reconcile` (gauge): Items pending reconciliation
//! - `ingress_da_primary_healthy` (gauge): Primary DA health status
//! - `ingress_da_secondary_healthy` (gauge): Secondary DA health status
//!
//! ### GET /fallback/status
//!
//! Source of truth untuk fallback status.
//!
//! **Response (200):** `FallbackStatusResponse` JSON dengan:
//! - `info`: FallbackHealthInfo lengkap
//! - `time_since_last_primary_contact_secs`: Waktu sejak primary DA terakhir kontak
//! - `reconciliation_queue_depth`: Jumlah item menunggu rekonsiliasi
//!
//! **Response (404):** DARouter tidak dikonfigurasi atau tidak tersedia.
//!
//! ## Configuration
//!
//! ### Environment Variables
//!
//! | Variable            | Default                   | Description                    |
//! |---------------------|---------------------------|--------------------------------|
//! | `COORDINATOR_BASE`  | `http://127.0.0.1:45831`   | Coordinator service URL        |
//! | `DA_ROUTER_TTL_MS`  | `30000`                   | DA router cache TTL (ms)       |
//!
//! ### Fallback Thresholds (Compile-time Constants)
//!
//! | Constant                            | Value  | Description                          |
//! |-------------------------------------|--------|--------------------------------------|
//! | `FALLBACK_DURATION_THRESHOLD_SECS`  | 600    | Degraded if fallback > 10 minutes    |
//! | `PENDING_RECONCILE_THRESHOLD`       | 1000   | Degraded if pending > 1000 items     |
//!
//! ### Alerting Configuration
//!
//! Alerting hooks tersedia via `AlertDispatcher`:
//! - `LoggingAlertHandler`: Default handler (structured logging)
//! - `WebhookAlertHandler`: HTTP POST ke endpoint eksternal (feature-gated)
//!
//! Events yang di-alert:
//! - Fallback activated
//! - Fallback deactivated
//! - Reconciliation complete
//!
//! ## Monitoring Recommendations
//!
//! ### Health Check Integration
//!
//! ```text
//! Kubernetes Probes:
//!   livenessProbe:
//!     httpGet:
//!       path: /health
//!       port: 8088
//!   readinessProbe:
//!     httpGet:
//!       path: /ready
//!       port: 8088
//! ```
//!
//! ### Degraded Detection
//!
//! Untuk mendeteksi kondisi DEGRADED:
//! 1. **Endpoint /ready**: Check header `X-Warning` pada response 200
//! 2. **Endpoint /metrics**: Monitor `ingress_fallback_active` dan `ingress_fallback_duration_seconds`
//! 3. **Endpoint /fallback/status**: Detail lengkap status fallback
//!
//! ### Critical Alerts
//!
//! Set alert pada kondisi berikut:
//!
//! | Metric/Condition                        | Threshold    | Severity |
//! |-----------------------------------------|--------------|----------|
//! | `ingress_fallback_active == 1`          | immediate    | Warning  |
//! | `ingress_fallback_duration_seconds`     | > 600        | Critical |
//! | `ingress_fallback_pending_reconcile`    | > 1000       | Critical |
//! | `ingress_da_primary_healthy == 0`       | immediate    | Warning  |
//! | `/ready` returns 503                    | immediate    | Critical |
//!
//! ## Modules
//!
//! | Module           | Description                                      |
//! |------------------|--------------------------------------------------|
//! | `coord_client`   | Coordinator API client                           |
//! | `da_router`      | DA-aware routing engine                          |
//! | `routing`        | Request routing logic (fallback-aware)           |
//! | `fallback`       | Fallback & retry mechanisms                      |
//! | `fallback_health`| FallbackHealthInfo struct (14A.1A.59)            |
//! | `alerting`       | Alert hooks for fallback events (14A.1A.68)      |
//! | `metrics`        | Observability & Prometheus metrics               |
//! | `rate_limit`     | Rate limiting middleware                         |
//! | `economic_handlers` | Receipt status query endpoints (14C.C.24)     |
//! |                     | Reward balance query endpoints (14C.C.25)     |
//! |                     | Fraud proof submission placeholder (14C.C.26) |
//! |                     | Claim handler + DA event logging (14C.C.28)   |
//! | `receipt_event_logger` | DA audit logging for receipt events (14C.C.28) |
//! | `economic_validation` | Validation layer & chain forwarding (14C.C.27) |
//!
//! ## DA Integration
//!
//! Ingress TIDAK query Coordinator untuk placement decisions.
//! Semua routing berdasarkan DA-derived state via DARouter.
//!
//! ### Fallback Hierarchy
//!
//! 1. **Primary (Celestia)**: Default DA layer
//! 2. **Secondary (QuorumDA)**: Jika primary tidak tersedia
//! 3. **Emergency**: Jika primary dan secondary tidak tersedia
//!
//! ### State Transitions
//!
//! ```text
//! [Healthy] ──primary down──▶ [Degraded] ──all down──▶ [Emergency]
//!     ▲                            │                        │
//!     │                            │                        │
//!     └────primary recovered───────┴────any recovered───────┘
//! ```


use axum::{
    routing::{get, post},
    Router,
};
use std::{net::SocketAddr, sync::Arc};
use tracing::{error, info};
use tracing_subscriber;
use tokio::sync::watch;

mod coord_client;
mod da_router;
mod routing;
mod fallback;
mod metrics;
mod rate_limit;
mod fallback_health;
mod alerting;
pub mod economic_handlers;
pub mod economic_validation;
pub mod receipt_event_logger;

pub mod types;
pub mod app_state;
pub mod handlers;
pub mod stubs;
pub mod helpers;

pub use fallback_health::FallbackHealthInfo;
pub use alerting::{AlertHandler, AlertDispatcher, LoggingAlertHandler, ReconcileReport};
pub use types::*;
pub use app_state::AppState;
pub use handlers::{health, ready, metrics_endpoint, fallback_status, proxy_object};
pub use stubs::*;
pub use helpers::*;

use coord_client::CoordinatorClient;
use rate_limit::{RateLimiter, RateLimitState, rate_limit_middleware};

// Re-import for tests (used by tests via `use super::*`)
#[cfg(test)]
use metrics::IngressMetrics;

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

    // Receipt status query routes (14C.C.24)
    // Uses ChainForwarder (14C.C.27) — all queries go through forwarding layer.
    let chain_forwarder = Arc::new(economic_validation::ChainForwarder::new(
        "http://localhost:26657".to_string(),
        std::time::Duration::from_secs(10),
    ));
    let economic_state = economic_handlers::EconomicState {
        service: Arc::clone(&chain_forwarder),
    };
    let economic_router = axum::Router::new()
        .route(
            "/receipt/:hash",
            get(economic_handlers::handle_receipt_status::<economic_validation::ChainForwarder>),
        )
        .route(
            "/receipts/status",
            post(economic_handlers::handle_batch_receipt_status::<economic_validation::ChainForwarder>),
        )
        .with_state(economic_state);

    // Reward balance query routes (14C.C.25)
    // Uses same ChainForwarder (14C.C.27) — no direct chain access from handlers.
    // NOTE: Static routes (/rewards/validators, /rewards/treasury) registered
    // BEFORE parameterized route (/rewards/:address) for correct matching.
    let reward_state = economic_handlers::EconomicRewardState {
        service: chain_forwarder,
    };
    let reward_router = axum::Router::new()
        .route(
            "/rewards/validators",
            get(economic_handlers::handle_validator_rewards::<economic_validation::ChainForwarder>),
        )
        .route(
            "/rewards/treasury",
            get(economic_handlers::handle_treasury_rewards::<economic_validation::ChainForwarder>),
        )
        .route(
            "/rewards/:address",
            get(economic_handlers::handle_reward_balance::<economic_validation::ChainForwarder>),
        )
        .with_state(reward_state);

    // Fraud proof submission placeholder routes (14C.C.26)
    // Uses fraud_proof_log from AppState, wrapped in FraudProofState.
    let fraud_proof_state = economic_handlers::FraudProofState {
        log: app_state.fraud_proof_log.clone(),
        event_logger: Arc::clone(&app_state.event_logger),
    };
    let fraud_proof_router = axum::Router::new()
        .route(
            "/fraud-proof",
            post(economic_handlers::handle_fraud_proof_submit),
        )
        .route(
            "/fraud-proofs",
            get(economic_handlers::handle_fraud_proofs_list),
        )
        .with_state(fraud_proof_state);

    // Claim reward route (14C.C.28)
    // Uses ChainForwarder + event logger for DA audit logging.
    let claim_state = economic_handlers::ClaimState {
        forwarder: Arc::new(economic_validation::ChainForwarder::new(
            "http://localhost:26657".to_string(),
            std::time::Duration::from_secs(10),
        )),
        event_logger: Arc::clone(&app_state.event_logger),
    };
    let claim_router = axum::Router::new()
        .route(
            "/claim",
            post(economic_handlers::handle_claim_submit),
        )
        .with_state(claim_state);

    // Create rate limiter with default + economic-specific limits (14C.C.27).
    // Mutation endpoints (claim, fraud-proof): 10 req/min per IP.
    // Query endpoints (status, balance, rewards, treasury): 60 req/min per IP.
    let mut rate_limiter_inner = RateLimiter::with_defaults();
    rate_limiter_inner.add_limit(
        "econ_mutation",
        rate_limit::LimitConfig::per_ip_per_minute(10, 10),
    );
    rate_limiter_inner.add_limit(
        "econ_query",
        rate_limit::LimitConfig::per_ip_per_minute(60, 60),
    );
    let rate_limiter = Arc::new(rate_limiter_inner);
    let rate_limit_state = RateLimitState::new(rate_limiter);

    // Shutdown channel for background task lifecycle
    let (shutdown_tx, _shutdown_rx) = watch::channel(false);

    // build axum router with rate limiting middleware
    let app = Router::new()
        .route("/object/:hash", get(proxy_object))
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/metrics", get(metrics_endpoint))
        .route("/fallback/status", get(fallback_status))
        .merge(economic_router)
        .merge(reward_router)
        .merge(fraud_proof_router)
        .merge(claim_router)
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
// TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod economic_endpoint_tests;

#[cfg(test)]
mod tests;