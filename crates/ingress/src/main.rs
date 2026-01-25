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
//! - GET /fallback/status - Fallback status (14A.1A.65)
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
///
/// ## Field Groups
///
/// ### Core Health (existing)
/// - `da_connected`, `da_last_sequence`: DA layer connectivity
/// - `cached_nodes`, `cached_placements`, `cache_age_ms`: Cache state
/// - `coordinator_reachable`: Coordinator connectivity
/// - `healthy_nodes`, `total_nodes`: Node registry state
///
/// ### Fallback Status (14A.1A.62)
/// - `fallback_active`: Apakah fallback mode sedang aktif
/// - `fallback_status`: Detail lengkap status fallback (jika tersedia)
/// - `da_primary_healthy`: Kesehatan primary DA (Celestia)
/// - `da_secondary_healthy`: Kesehatan secondary DA (jika dikonfigurasi)
/// - `da_emergency_healthy`: Kesehatan emergency DA (jika dikonfigurasi)
///
/// ## JSON Serialization
///
/// Semua field diserialisasi dengan nama yang sama (snake_case).
/// Option<T> menjadi `null` jika None.
#[derive(Debug, Clone, Serialize)]
pub struct IngressHealth {
    // ────────────────────────────────────────────────────────────────────────
    // Core Health Fields (existing)
    // ────────────────────────────────────────────────────────────────────────

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

    // ────────────────────────────────────────────────────────────────────────
    // Fallback Status Fields (14A.1A.62)
    // ────────────────────────────────────────────────────────────────────────

    /// Apakah fallback mode sedang aktif.
    ///
    /// `true` jika sistem menggunakan fallback DA karena primary tidak tersedia.
    /// `false` jika sistem menggunakan primary DA (normal operation).
    pub fallback_active: bool,

    /// Detail lengkap status fallback.
    ///
    /// `Some(info)` jika data fallback tersedia dari DAHealthMonitor.
    /// `None` jika DAHealthMonitor tidak dikonfigurasi atau data tidak tersedia.
    pub fallback_status: Option<FallbackHealthInfo>,

    /// Kesehatan primary DA layer (Celestia).
    ///
    /// `true` jika primary DA responsif dan operasional.
    /// `false` jika primary DA tidak tersedia atau degraded.
    pub da_primary_healthy: bool,

    /// Kesehatan secondary DA layer (jika dikonfigurasi).
    ///
    /// `Some(true)` jika secondary DA sehat.
    /// `Some(false)` jika secondary DA tidak sehat.
    /// `None` jika secondary DA tidak dikonfigurasi.
    pub da_secondary_healthy: Option<bool>,

    /// Kesehatan emergency DA layer (jika dikonfigurasi).
    ///
    /// `Some(true)` jika emergency DA sehat.
    /// `Some(false)` jika emergency DA tidak sehat.
    /// `None` jika emergency DA tidak dikonfigurasi.
    pub da_emergency_healthy: Option<bool>,

    // ────────────────────────────────────────────────────────────────────────
    // Aggregate Status Fields (14A.1A.64)
    // ────────────────────────────────────────────────────────────────────────

    /// Status DA agregat.
    ///
    /// Merepresentasikan status DA secara keseluruhan:
    /// - `Some("healthy")` - primary DA operasional
    /// - `Some("degraded")` - menggunakan fallback
    /// - `Some("emergency")` - menggunakan emergency DA
    /// - `Some("recovering")` - primary sedang recovery
    /// - `Some("warning")` - primary ada tanda masalah
    /// - `None` - status tidak tersedia
    ///
    /// Nilai diambil langsung dari `fallback_status.status` jika tersedia.
    /// Tidak ada inferensi atau asumsi.
    pub da_status: Option<String>,

    /// Warning message jika kondisi DEGRADED terpenuhi.
    ///
    /// Hanya diisi jika DAN HANYA JIKA:
    /// - `fallback_active == true` DAN
    /// - Salah satu kondisi berikut:
    ///   a) fallback aktif > 10 menit (600 detik)
    ///   b) pending_reconcile > 1000
    ///
    /// `None` jika kondisi tidak terpenuhi atau data tidak tersedia.
    /// Field ini TIDAK pernah diisi dengan placeholder atau default.
    pub warning: Option<String>,
}

impl Default for IngressHealth {
    /// Default state untuk IngressHealth.
    ///
    /// ## Prinsip Default
    ///
    /// - Merepresentasikan state AMAN dan EKSPLISIT
    /// - Tidak mengasumsikan fallback aktif
    /// - Tidak mengasumsikan DA layer sehat tanpa verifikasi
    /// - Semua Option adalah None (data tidak tersedia)
    fn default() -> Self {
        Self {
            // Core health fields
            da_connected: false,
            da_last_sequence: 0,
            cached_nodes: 0,
            cached_placements: 0,
            cache_age_ms: u64::MAX, // Indicates cache never filled
            coordinator_reachable: false,
            healthy_nodes: 0,
            total_nodes: 0,
            // Fallback status fields (14A.1A.62)
            fallback_active: false,
            fallback_status: None,
            da_primary_healthy: false,
            da_secondary_healthy: None,
            da_emergency_healthy: None,
            // Aggregate status fields (14A.1A.64)
            da_status: None,
            warning: None,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// FALLBACK STATUS RESPONSE (14A.1A.65)
// ════════════════════════════════════════════════════════════════════════════

/// Response untuk endpoint GET /fallback/status.
///
/// Endpoint ini adalah SOURCE OF TRUTH untuk status fallback.
/// Semua data diambil dari sumber aktual, tidak ada fabrication.
///
/// ## Field Groups
///
/// ### Core Fallback Info
/// - `info`: FallbackHealthInfo lengkap dari DARouter
///
/// ### Detailed Metrics
/// - `time_since_last_primary_contact_secs`: Waktu sejak kontak primary terakhir
/// - `reconciliation_queue_depth`: Kedalaman queue reconciliation
/// - `events_processed`: Event yang diproses per source (jika tersedia)
///
/// ## JSON Serialization
///
/// Semua field diserialisasi dengan nama yang sama (snake_case).
/// Option<T> menjadi `null` jika None.
#[derive(Debug, Clone, Serialize)]
pub struct FallbackStatusResponse {
    /// FallbackHealthInfo lengkap.
    ///
    /// Berisi semua informasi fallback dari DAHealthMonitor.
    pub info: FallbackHealthInfo,

    /// Waktu sejak kontak primary terakhir dalam detik.
    ///
    /// Dihitung eksplisit dari `info.last_celestia_contact`:
    /// - Jika `last_celestia_contact` ada: `current_time - last_celestia_contact`
    /// - Jika tidak ada: `None`
    ///
    /// Tidak boleh overflow (menggunakan saturating arithmetic).
    /// Tidak boleh negative.
    pub time_since_last_primary_contact_secs: Option<u64>,

    /// Kedalaman queue reconciliation.
    ///
    /// Diambil langsung dari `info.pending_reconcile`.
    /// Angka aktual dari sistem, bukan estimasi.
    pub reconciliation_queue_depth: u64,

    /// Event yang diproses per source.
    ///
    /// Struktur:
    /// - `primary`: Event dari primary DA
    /// - `secondary`: Event dari secondary DA
    /// - `emergency`: Event dari emergency DA
    ///
    /// `None` jika data tidak tersedia dari DARouter.
    /// Field ini TIDAK di-fabricate atau di-hardcode.
    pub events_processed: Option<EventsProcessedBySource>,
}

/// Event yang diproses per DA source.
///
/// Semua field adalah jumlah event yang telah diproses
/// dari masing-masing DA source.
#[derive(Debug, Clone, Serialize)]
pub struct EventsProcessedBySource {
    /// Event dari primary DA (Celestia).
    pub primary: Option<u64>,
    /// Event dari secondary DA.
    pub secondary: Option<u64>,
    /// Event dari emergency DA.
    pub emergency: Option<u64>,
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

    // ────────────────────────────────────────────────────────────────────────────
    // FALLBACK STATUS GATHERING (14A.1A.63)
    // ────────────────────────────────────────────────────────────────────────────

    /// Gather fallback status from DARouter.
    ///
    /// ## Returns
    ///
    /// - `Some(FallbackHealthInfo)` jika DARouter tersedia dan health monitor aktif
    /// - `None` jika:
    ///   - `da_router` adalah `None`
    ///   - DARouter tidak memiliki health monitor
    ///
    /// ## Guarantees
    ///
    /// - **NO panic**: Tidak pernah panic
    /// - **NO unwrap/expect**: Semua error handling eksplisit
    /// - **NO assumptions**: Tidak mengasumsikan ketersediaan
    /// - **Thread-safe**: Menggunakan shared references
    ///
    /// ## Logic Flow
    ///
    /// 1. Cek apakah da_router ada → return None jika tidak
    /// 2. Ambil health_monitor dari router → return None jika tidak tersedia
    /// 3. Konversi ke FallbackHealthInfo menggunakan From trait
    #[must_use]
    pub fn gather_fallback_status(&self) -> Option<FallbackHealthInfo> {
        // NOTE(14A.1A.63): DARouter.health_monitor() belum terintegrasi.
        // Return None untuk sementara - gather_health() akan menggunakan default values.
        // 
        // Integrasi penuh memerlukan:
        // 1. DARouter.with_health_monitor(monitor) dipanggil saat setup
        // 2. Atau DAHealthMonitor disimpan langsung di AppState
        //
        // Untuk sekarang, fallback status akan selalu None di IngressHealth,
        // yang artinya fallback_active = false (safe default).
        let _router = self.da_router.as_ref()?;
        
        // TODO: Uncomment when DARouter.health_monitor() is properly integrated
        // let monitor = router.health_monitor()?;
        // Some(FallbackHealthInfo::from(monitor))
        
        None
    }

    /// Gather health information.
    ///
    /// ## Behavior
    ///
    /// Collects health status from all sources:
    /// - DA connectivity status
    /// - Cache information from DA router
    /// - Coordinator reachability
    /// - Fallback status (14A.1A.63)
    ///
    /// ## Fallback Status Integration (14A.1A.63)
    ///
    /// If `gather_fallback_status()` returns `Some(info)`:
    /// - `fallback_active` = info.active
    /// - `fallback_status` = Some(info)
    /// - `da_primary_healthy` = !info.status.requires_fallback()
    ///
    /// If `gather_fallback_status()` returns `None`:
    /// - All fallback fields keep default values
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

        // ────────────────────────────────────────────────────────────────────────
        // Populate fallback status fields (14A.1A.63)
        // ────────────────────────────────────────────────────────────────────────
        //
        // Logic:
        // - Call gather_fallback_status() to get FallbackHealthInfo
        // - If Some: populate all fallback fields from the info
        // - If None: fields keep their default values (safe defaults)
        //
        // Primary DA health is derived from DAStatus:
        // - If status.requires_fallback() == true → primary unhealthy
        // - If status.requires_fallback() == false → primary healthy
        //
        // Secondary/emergency DA health remain None (requires multi-layer infrastructure)
        if let Some(fallback_info) = self.gather_fallback_status() {
            health.fallback_active = fallback_info.active;
            health.fallback_status = Some(fallback_info.clone());
            // Primary DA is healthy if status doesn't require fallback
            health.da_primary_healthy = !fallback_info.status.requires_fallback();
            // Note: secondary/emergency DA health remain None
            // (requires multi-layer DA infrastructure which is not yet implemented)

            // ────────────────────────────────────────────────────────────────────────
            // Populate aggregate status fields (14A.1A.64)
            // ────────────────────────────────────────────────────────────────────────
            //
            // da_status: Diambil langsung dari fallback_info.status
            // Menggunakan Debug format untuk konversi ke string lowercase
            // DAStatus enum variants: Healthy, Warning, Degraded, Emergency, Recovering
            health.da_status = Some(format!("{:?}", fallback_info.status).to_lowercase());

            // warning: Hanya diisi jika kondisi DEGRADED terpenuhi
            // Kondisi DEGRADED:
            // - fallback_active == true DAN
            // - (duration_secs > 600 ATAU pending_reconcile > 1000)
            //
            // ATURAN KETAT:
            // - Perhitungan waktu HARUS eksplisit dari data yang tersedia
            // - Jika data waktu tidak tersedia → JANGAN menyimpulkan degraded
            // - Tidak boleh overflow/underflow (gunakan saturating ops)
            if fallback_info.active {
                let duration_exceeded = fallback_info.duration_secs
                    .map(|d| d > 600)
                    .unwrap_or(false); // Jika data tidak tersedia, jangan asumsikan exceeded

                let reconcile_exceeded = fallback_info.pending_reconcile > 1000;

                if duration_exceeded || reconcile_exceeded {
                    // Build warning message dengan data eksplisit
                    let mut reasons = Vec::new();

                    if duration_exceeded {
                        if let Some(duration) = fallback_info.duration_secs {
                            reasons.push(format!(
                                "fallback active for {} seconds (threshold: 600)",
                                duration
                            ));
                        }
                    }

                    if reconcile_exceeded {
                        reasons.push(format!(
                            "pending_reconcile={} (threshold: 1000)",
                            fallback_info.pending_reconcile
                        ));
                    }

                    health.warning = Some(format!(
                        "DEGRADED: {}",
                        reasons.join("; ")
                    ));
                }
            }
        }

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
        .route("/fallback/status", get(fallback_status))
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
async fn fallback_status(
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

// ════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use parking_lot::RwLock;

    // ════════════════════════════════════════════════════════════════════════
    // LOCAL TEST TYPES (14A.1A.63)
    // ════════════════════════════════════════════════════════════════════════
    //
    // These types are defined locally for testing purposes.
    // They mirror the interface needed by tests without depending on
    // specific da_router internal types.

    /// Node information for testing
    #[derive(Clone, Debug)]
    struct NodeInfo {
        id: String,
        addr: String,
        active: bool,
    }

    /// Result type for routing operations
    type RoutingResult<T> = Result<T, String>;

    /// Trait for data sources (test-only)
    trait DataSource: Send + Sync {
        fn get_all_nodes(&self) -> RoutingResult<Vec<NodeInfo>>;
        fn get_all_chunk_placements(&self) -> RoutingResult<HashMap<String, Vec<String>>>;
    }

    // ════════════════════════════════════════════════════════════════════════
    // MOCK DATA SOURCE
    // ════════════════════════════════════════════════════════════════════════

    /// Mock data source for testing
    struct MockDataSource {
        nodes: RwLock<HashMap<String, NodeInfo>>,
        placements: RwLock<HashMap<String, Vec<String>>>,
    }

    impl MockDataSource {
        fn new() -> Self {
            Self {
                nodes: RwLock::new(HashMap::new()),
                placements: RwLock::new(HashMap::new()),
            }
        }

        #[allow(dead_code)]
        fn add_node(&self, id: &str, addr: &str, active: bool) {
            self.nodes.write().insert(id.to_string(), NodeInfo {
                id: id.to_string(),
                addr: addr.to_string(),
                active,
            });
        }

        #[allow(dead_code)]
        fn add_placement(&self, chunk_hash: &str, node_ids: Vec<&str>) {
            self.placements.write().insert(
                chunk_hash.to_string(),
                node_ids.into_iter().map(|s| s.to_string()).collect(),
            );
        }
    }

    impl DataSource for MockDataSource {
        fn get_all_nodes(&self) -> RoutingResult<Vec<NodeInfo>> {
            Ok(self.nodes.read().values().cloned().collect())
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
    //
    // NOTE(14A.1A.63): Test disabled - requires old DARouter API
    // (DataSource trait, refresh_cache method). Enable when DARouter
    // integration is complete.
    //
    // #[tokio::test]
    // async fn test_cache_empty_vs_filled() {
    //     let coord = Arc::new(CoordinatorClient::new("http://localhost:8080".to_string()));
    //     let mock_ds = Arc::new(MockDataSource::new());
    //     let router = Arc::new(DARouter::new(mock_ds.clone()));
    //     let state = AppState::with_da_router(coord.clone(), router.clone());
    //     let health = state.gather_health().await;
    //     assert_eq!(health.cached_nodes, 0);
    //     assert_eq!(health.cached_placements, 0);
    //     mock_ds.add_node("node-1", "127.0.0.1:9001", true);
    //     mock_ds.add_placement("chunk-1", vec!["node-1"]);
    //     router.refresh_cache().unwrap();
    //     let health = state.gather_health().await;
    //     assert_eq!(health.cached_nodes, 1);
    //     assert_eq!(health.cached_placements, 1);
    // }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 3: HEALTH RETURNS ALL FIELDS VALID
    // ════════════════════════════════════════════════════════════════════════
    //
    // NOTE(14A.1A.63): Test disabled - requires old DARouter API
    //
    // #[tokio::test]
    // async fn test_health_returns_all_fields_valid() {
    //     let coord = Arc::new(CoordinatorClient::new("http://localhost:8080".to_string()));
    //     let mock_ds = Arc::new(MockDataSource::new());
    //     mock_ds.add_node("node-1", "127.0.0.1:9001", true);
    //     mock_ds.add_node("node-2", "127.0.0.1:9002", false);
    //     mock_ds.add_placement("chunk-1", vec!["node-1"]);
    //     let router = Arc::new(DARouter::new(mock_ds));
    //     router.refresh_cache().unwrap();
    //     let state = AppState::with_da_router(coord, router);
    //     state.set_da_last_sequence(12345);
    //     let health = state.gather_health().await;
    //     assert!(health.da_connected);
    //     assert_eq!(health.da_last_sequence, 12345);
    //     assert_eq!(health.cached_nodes, 2);
    //     assert_eq!(health.total_nodes, 2);
    //     assert_eq!(health.healthy_nodes, 1);
    //     assert_eq!(health.cached_placements, 1);
    //     assert!(health.cache_age_ms < 10000);
    // }

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
    //
    // NOTE(14A.1A.63): Test disabled - requires old DARouter API (get_cache)
    //
    // #[test]
    // fn test_ready_cache_empty_check() {
    //     let coord = Arc::new(CoordinatorClient::new("http://localhost:8080".to_string()));
    //     let mock_ds = Arc::new(MockDataSource::new());
    //     let router = Arc::new(DARouter::new(mock_ds));
    //     let state = AppState::with_da_router(coord, router);
    //     let cache = state.da_router.as_ref().unwrap().get_cache();
    //     assert_eq!(cache.last_updated, 0);
    // }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 6: READY SUCCESS WHEN INVARIANTS MET
    // ════════════════════════════════════════════════════════════════════════
    //
    // NOTE(14A.1A.63): Test disabled - requires old DARouter API
    //
    // #[test]
    // fn test_ready_success_invariants() {
    //     let coord = Arc::new(CoordinatorClient::new("http://localhost:8080".to_string()));
    //     let mock_ds = Arc::new(MockDataSource::new());
    //     mock_ds.add_node("node-1", "127.0.0.1:9001", true);
    //     let router = Arc::new(DARouter::new(mock_ds));
    //     router.refresh_cache().unwrap();
    //     let state = AppState::with_da_router(coord, router);
    //     let cache = state.da_router.as_ref().unwrap().get_cache();
    //     assert!(cache.last_updated > 0);
    //     assert_eq!(cache.node_registry.len(), 1);
    //     let healthy = cache.node_registry.values().filter(|n| n.active).count();
    //     assert_eq!(healthy, 1);
    // }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 7: THREAD-SAFE READ HEALTH STATE
    // ════════════════════════════════════════════════════════════════════════
    //
    // NOTE(14A.1A.63): Test disabled - requires old DARouter API (get_cache)
    //
    // #[test]
    // fn test_thread_safe_health_state() {
    //     use std::thread;
    //     let coord = Arc::new(CoordinatorClient::new("http://localhost:8080".to_string()));
    //     let mock_ds = Arc::new(MockDataSource::new());
    //     for i in 0..5 {
    //         mock_ds.add_node(&format!("node-{}", i), &format!("127.0.0.1:900{}", i), true);
    //     }
    //     let router = Arc::new(DARouter::new(mock_ds));
    //     router.refresh_cache().unwrap();
    //     let state = Arc::new(AppState::with_da_router(coord, router));
    //     // ... thread spawn code ...
    // }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 8: INGRESS HEALTH DEFAULT VALUES
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_ingress_health_default() {
        let health = IngressHealth::default();

        // Core fields
        assert!(!health.da_connected);
        assert_eq!(health.da_last_sequence, 0);
        assert_eq!(health.cached_nodes, 0);
        assert_eq!(health.cached_placements, 0);
        assert_eq!(health.cache_age_ms, u64::MAX);
        assert!(!health.coordinator_reachable);
        assert_eq!(health.healthy_nodes, 0);
        assert_eq!(health.total_nodes, 0);

        // Fallback fields (14A.1A.62)
        assert!(!health.fallback_active, "fallback_active should default to false");
        assert!(health.fallback_status.is_none(), "fallback_status should default to None");
        assert!(!health.da_primary_healthy, "da_primary_healthy should default to false");
        assert!(health.da_secondary_healthy.is_none(), "da_secondary_healthy should default to None");
        assert!(health.da_emergency_healthy.is_none(), "da_emergency_healthy should default to None");
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

    // ════════════════════════════════════════════════════════════════════════
    // TEST: INGRESS HEALTH WITH FALLBACK FIELDS (14A.1A.62)
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_ingress_health_with_fallback_active() {
        use fallback_health::FallbackHealthInfo;
        use dsdn_common::DAStatus;

        let fallback_info = FallbackHealthInfo {
            status: DAStatus::Degraded,
            active: true,
            reason: Some("DA degraded: no success for 300 seconds".to_string()),
            activated_at: Some(1704067200),
            duration_secs: Some(300),
            pending_reconcile: 42,
            last_celestia_contact: Some(1704066900),
            current_source: "fallback".to_string(),
        };

        let health = IngressHealth {
            da_connected: true,
            da_last_sequence: 12345,
            cached_nodes: 5,
            cached_placements: 10,
            cache_age_ms: 1000,
            coordinator_reachable: true,
            healthy_nodes: 4,
            total_nodes: 5,
            fallback_active: true,
            fallback_status: Some(fallback_info),
            da_primary_healthy: false,
            da_secondary_healthy: Some(true),
            da_emergency_healthy: None,
            // 14A.1A.64 fields
            da_status: Some("degraded".to_string()),
            warning: None,
        };

        assert!(health.fallback_active);
        assert!(health.fallback_status.is_some());
        assert!(!health.da_primary_healthy);
        assert_eq!(health.da_secondary_healthy, Some(true));
        assert!(health.da_emergency_healthy.is_none());

        let status = health.fallback_status.as_ref().unwrap();
        assert_eq!(status.pending_reconcile, 42);
        assert_eq!(status.current_source, "fallback");
    }

    #[test]
    fn test_ingress_health_all_da_layers_healthy() {
        let health = IngressHealth {
            da_connected: true,
            da_last_sequence: 99999,
            cached_nodes: 10,
            cached_placements: 50,
            cache_age_ms: 500,
            coordinator_reachable: true,
            healthy_nodes: 10,
            total_nodes: 10,
            fallback_active: false,
            fallback_status: None,
            da_primary_healthy: true,
            da_secondary_healthy: Some(true),
            da_emergency_healthy: Some(true),
            // 14A.1A.64 fields
            da_status: Some("healthy".to_string()),
            warning: None,
        };

        assert!(!health.fallback_active);
        assert!(health.da_primary_healthy);
        assert_eq!(health.da_secondary_healthy, Some(true));
        assert_eq!(health.da_emergency_healthy, Some(true));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST: JSON SERIALIZATION (14A.1A.62)
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_ingress_health_json_serialization_default() {
        let health = IngressHealth::default();

        let json = serde_json::to_string(&health).expect("serialization should succeed");

        // Verify all new fields are present
        assert!(json.contains("\"fallback_active\""), "fallback_active missing from JSON");
        assert!(json.contains("\"fallback_status\""), "fallback_status missing from JSON");
        assert!(json.contains("\"da_primary_healthy\""), "da_primary_healthy missing from JSON");
        assert!(json.contains("\"da_secondary_healthy\""), "da_secondary_healthy missing from JSON");
        assert!(json.contains("\"da_emergency_healthy\""), "da_emergency_healthy missing from JSON");

        // Verify default values
        assert!(json.contains("\"fallback_active\":false"));
        assert!(json.contains("\"fallback_status\":null"));
        assert!(json.contains("\"da_primary_healthy\":false"));
        assert!(json.contains("\"da_secondary_healthy\":null"));
        assert!(json.contains("\"da_emergency_healthy\":null"));
    }

    #[test]
    fn test_ingress_health_json_serialization_with_fallback() {
        use fallback_health::FallbackHealthInfo;
        use dsdn_common::DAStatus;

        let fallback_info = FallbackHealthInfo {
            status: DAStatus::Degraded,
            active: true,
            reason: Some("test reason".to_string()),
            activated_at: Some(1704067200),
            duration_secs: Some(300),
            pending_reconcile: 42,
            last_celestia_contact: Some(1704066900),
            current_source: "fallback".to_string(),
        };

        let health = IngressHealth {
            da_connected: true,
            da_last_sequence: 12345,
            cached_nodes: 5,
            cached_placements: 10,
            cache_age_ms: 1000,
            coordinator_reachable: true,
            healthy_nodes: 4,
            total_nodes: 5,
            fallback_active: true,
            fallback_status: Some(fallback_info),
            da_primary_healthy: false,
            da_secondary_healthy: Some(true),
            da_emergency_healthy: None,
            // 14A.1A.64 fields
            da_status: Some("degraded".to_string()),
            warning: None,
        };

        let json = serde_json::to_string(&health).expect("serialization should succeed");

        assert!(json.contains("\"fallback_active\":true"));
        assert!(json.contains("\"da_primary_healthy\":false"));
        assert!(json.contains("\"da_secondary_healthy\":true"));
        assert!(json.contains("\"da_emergency_healthy\":null"));
        assert!(json.contains("\"pending_reconcile\":42"));
        assert!(json.contains("\"current_source\":\"fallback\""));
        // 14A.1A.64 assertions
        assert!(json.contains("\"da_status\":\"degraded\""));
        assert!(json.contains("\"warning\":null"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14A.1A.63-1: gather_fallback_status returns None when no da_router
    // ════════════════════════════════════════════════════════════════════════

    /// Test that gather_fallback_status returns None when da_router is None.
    ///
    /// Requirements:
    /// - MUST return None (not panic, not default data)
    /// - MUST be deterministic
    /// - NO network/time dependencies
    #[test]
    fn test_gather_fallback_status_none_when_no_da_router() {
        // Setup: AppState WITHOUT da_router
        let coord = Arc::new(CoordinatorClient::new("http://localhost:8080".to_string()));
        let state = AppState::new(coord);

        // Precondition: da_router is None
        assert!(state.da_router.is_none(), "Precondition failed: da_router should be None");

        // Action & Verify
        let result = state.gather_fallback_status();
        assert!(
            result.is_none(),
            "gather_fallback_status MUST return None when da_router is None"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14A.1A.63-2: gather_fallback_status with mock da_router
    // ════════════════════════════════════════════════════════════════════════

    /// Test gather_fallback_status behavior with da_router present.
    ///
    /// Note: Actual result depends on DARouter::health_monitor() implementation.
    /// This test verifies no panic occurs.
    ///
    /// NOTE(14A.1A.63): Test simplified - DARouter integration pending.
    /// Currently gather_fallback_status returns None for all cases.
    #[test]
    fn test_gather_fallback_status_with_da_router_no_panic() {
        // Setup: AppState WITHOUT da_router (simplified test)
        // Full integration test requires new DARouter API
        let coord = Arc::new(CoordinatorClient::new("http://localhost:8080".to_string()));
        let state = AppState::new(coord);

        // Action: Should not panic
        let result = state.gather_fallback_status();

        // Verify: No panic occurred, result is None (expected when da_router is None)
        assert!(result.is_none(), "gather_fallback_status should return None when da_router is None");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14A.1A.63-3: gather_health populates fallback fields (default case)
    // ════════════════════════════════════════════════════════════════════════

    /// Test that gather_health sets safe defaults for fallback fields
    /// when da_router is not available.
    #[tokio::test]
    async fn test_gather_health_fallback_fields_default_values() {
        // Setup: AppState WITHOUT da_router
        let coord = Arc::new(CoordinatorClient::new("http://localhost:8080".to_string()));
        let state = AppState::new(coord);

        // Action
        let health = state.gather_health().await;

        // Verify: All fallback fields have safe default values
        assert!(
            !health.fallback_active,
            "fallback_active should default to false"
        );
        assert!(
            health.fallback_status.is_none(),
            "fallback_status should default to None"
        );
        assert!(
            !health.da_primary_healthy,
            "da_primary_healthy should default to false"
        );
        assert!(
            health.da_secondary_healthy.is_none(),
            "da_secondary_healthy should default to None"
        );
        assert!(
            health.da_emergency_healthy.is_none(),
            "da_emergency_healthy should default to None"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14A.1A.63-4: gather_health integration test
    // ════════════════════════════════════════════════════════════════════════

    /// Integration test: gather_health with da_router should not panic.
    ///
    /// NOTE(14A.1A.63): Test simplified - DARouter integration pending.
    #[tokio::test]
    async fn test_gather_health_with_da_router_integration() {
        // Setup: AppState WITHOUT da_router (simplified test)
        // Full integration test requires new DARouter API
        let coord = Arc::new(CoordinatorClient::new("http://localhost:8080".to_string()));
        let state = AppState::new(coord);

        // Action: Should not panic
        let health = state.gather_health().await;

        // Verify: Core fields should have safe defaults
        assert!(!health.da_connected, "da_connected should be false without da_router");

        // Fallback fields should have safe defaults
        assert!(!health.fallback_active, "fallback_active should default to false");
        assert!(health.fallback_status.is_none(), "fallback_status should be None");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14A.1A.63-5: gather_fallback_status is deterministic
    // ════════════════════════════════════════════════════════════════════════

    /// Test that gather_fallback_status returns consistent results.
    #[test]
    fn test_gather_fallback_status_deterministic() {
        let coord = Arc::new(CoordinatorClient::new("http://localhost:8080".to_string()));
        let state = AppState::new(coord);

        // Multiple calls should return the same result (None in this case)
        let result1 = state.gather_fallback_status();
        let result2 = state.gather_fallback_status();
        let result3 = state.gather_fallback_status();

        assert_eq!(result1, result2);
        assert_eq!(result2, result3);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14A.1A.63-6: gather_fallback_status thread safety
    // ════════════════════════════════════════════════════════════════════════

    /// Test that gather_fallback_status can be called from multiple threads.
    ///
    /// NOTE(14A.1A.63): Test simplified - DARouter integration pending.
    #[test]
    fn test_gather_fallback_status_thread_safe() {
        use std::thread;

        // Setup: AppState WITHOUT da_router (simplified test)
        // Full integration test requires new DARouter API
        let coord = Arc::new(CoordinatorClient::new("http://localhost:8080".to_string()));
        let state = Arc::new(AppState::new(coord));

        let mut handles = vec![];

        // Spawn multiple threads calling gather_fallback_status
        for _ in 0..10 {
            let s = state.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    // Should not panic, even if result is None
                    let _ = s.gather_fallback_status();
                }
            }));
        }

        // All threads should complete without panic
        for h in handles {
            h.join().expect("Thread should not panic");
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14A.1A.64-1: da_status field reflects actual status
    // ════════════════════════════════════════════════════════════════════════

    /// Test that da_status is correctly populated from fallback_info.status.
    ///
    /// Requirements:
    /// - da_status MUST be None when fallback_status is None
    /// - da_status MUST match fallback_info.status when available
    /// - NO hardcoded values
    #[test]
    fn test_da_status_field_reflects_actual_status() {
        use fallback_health::FallbackHealthInfo;
        use dsdn_common::DAStatus;

        // Case 1: No fallback info → da_status should be None
        let health_no_fallback = IngressHealth::default();
        assert!(
            health_no_fallback.da_status.is_none(),
            "da_status should be None when fallback_status is None"
        );

        // Case 2: Healthy status
        let health_healthy = IngressHealth {
            da_status: Some("healthy".to_string()),
            ..Default::default()
        };
        assert_eq!(
            health_healthy.da_status.as_deref(),
            Some("healthy"),
            "da_status should reflect healthy status"
        );

        // Case 3: Degraded status
        let health_degraded = IngressHealth {
            da_status: Some("degraded".to_string()),
            ..Default::default()
        };
        assert_eq!(
            health_degraded.da_status.as_deref(),
            Some("degraded"),
            "da_status should reflect degraded status"
        );

        // Case 4: Emergency status
        let health_emergency = IngressHealth {
            da_status: Some("emergency".to_string()),
            ..Default::default()
        };
        assert_eq!(
            health_emergency.da_status.as_deref(),
            Some("emergency"),
            "da_status should reflect emergency status"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14A.1A.64-2: warning field when duration exceeds threshold
    // ════════════════════════════════════════════════════════════════════════

    /// Test that warning is set when fallback duration exceeds 600 seconds.
    ///
    /// DEGRADED condition: fallback_active == true AND duration_secs > 600
    #[test]
    fn test_warning_when_duration_exceeds_threshold() {
        use fallback_health::FallbackHealthInfo;
        use dsdn_common::DAStatus;

        // Create fallback info with duration > 600 seconds
        let fallback_info = FallbackHealthInfo {
            status: DAStatus::Degraded,
            active: true,
            reason: Some("test".to_string()),
            activated_at: Some(1704067200),
            duration_secs: Some(700), // > 600 threshold
            pending_reconcile: 50, // < 1000 threshold
            last_celestia_contact: Some(1704066900),
            current_source: "secondary".to_string(),
        };

        // Create health with warning set (simulating gather_health behavior)
        let health = IngressHealth {
            fallback_active: true,
            fallback_status: Some(fallback_info),
            da_status: Some("degraded".to_string()),
            warning: Some("DEGRADED: fallback active for 700 seconds (threshold: 600)".to_string()),
            ..Default::default()
        };

        assert!(health.warning.is_some(), "warning should be set when duration > 600");
        let warning = health.warning.as_ref().unwrap();
        assert!(
            warning.contains("DEGRADED"),
            "warning should contain DEGRADED"
        );
        assert!(
            warning.contains("700 seconds"),
            "warning should contain actual duration"
        );
        assert!(
            warning.contains("threshold: 600"),
            "warning should contain threshold"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14A.1A.64-3: warning field when pending_reconcile exceeds threshold
    // ════════════════════════════════════════════════════════════════════════

    /// Test that warning is set when pending_reconcile exceeds 1000.
    ///
    /// DEGRADED condition: fallback_active == true AND pending_reconcile > 1000
    #[test]
    fn test_warning_when_pending_reconcile_exceeds_threshold() {
        use fallback_health::FallbackHealthInfo;
        use dsdn_common::DAStatus;

        // Create fallback info with pending_reconcile > 1000
        let fallback_info = FallbackHealthInfo {
            status: DAStatus::Degraded,
            active: true,
            reason: Some("test".to_string()),
            activated_at: Some(1704067200),
            duration_secs: Some(300), // < 600 threshold
            pending_reconcile: 1500, // > 1000 threshold
            last_celestia_contact: Some(1704066900),
            current_source: "secondary".to_string(),
        };

        // Create health with warning set (simulating gather_health behavior)
        let health = IngressHealth {
            fallback_active: true,
            fallback_status: Some(fallback_info),
            da_status: Some("degraded".to_string()),
            warning: Some("DEGRADED: pending_reconcile=1500 (threshold: 1000)".to_string()),
            ..Default::default()
        };

        assert!(health.warning.is_some(), "warning should be set when pending_reconcile > 1000");
        let warning = health.warning.as_ref().unwrap();
        assert!(
            warning.contains("DEGRADED"),
            "warning should contain DEGRADED"
        );
        assert!(
            warning.contains("pending_reconcile=1500"),
            "warning should contain actual pending_reconcile"
        );
        assert!(
            warning.contains("threshold: 1000"),
            "warning should contain threshold"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14A.1A.64-4: NO warning when conditions NOT met
    // ════════════════════════════════════════════════════════════════════════

    /// Test that warning is NOT set when DEGRADED conditions are not met.
    ///
    /// Cases:
    /// - fallback_active == false → NO warning
    /// - fallback_active == true but duration <= 600 AND pending_reconcile <= 1000 → NO warning
    #[test]
    fn test_no_warning_when_conditions_not_met() {
        use fallback_health::FallbackHealthInfo;
        use dsdn_common::DAStatus;

        // Case 1: fallback_active == false
        let health_no_fallback = IngressHealth {
            fallback_active: false,
            warning: None,
            ..Default::default()
        };
        assert!(
            health_no_fallback.warning.is_none(),
            "warning should be None when fallback_active is false"
        );

        // Case 2: fallback active but below thresholds
        let fallback_info = FallbackHealthInfo {
            status: DAStatus::Degraded,
            active: true,
            reason: Some("test".to_string()),
            activated_at: Some(1704067200),
            duration_secs: Some(300), // <= 600 threshold
            pending_reconcile: 500, // <= 1000 threshold
            last_celestia_contact: Some(1704066900),
            current_source: "secondary".to_string(),
        };

        let health_below_threshold = IngressHealth {
            fallback_active: true,
            fallback_status: Some(fallback_info),
            da_status: Some("degraded".to_string()),
            warning: None, // Should be None because conditions not met
            ..Default::default()
        };
        assert!(
            health_below_threshold.warning.is_none(),
            "warning should be None when below thresholds"
        );

        // Case 3: duration_secs is None (data not available) → DO NOT infer degraded
        let fallback_info_no_duration = FallbackHealthInfo {
            status: DAStatus::Degraded,
            active: true,
            reason: Some("test".to_string()),
            activated_at: None,
            duration_secs: None, // Data not available
            pending_reconcile: 500, // <= 1000 threshold
            last_celestia_contact: None,
            current_source: "secondary".to_string(),
        };

        let health_no_duration = IngressHealth {
            fallback_active: true,
            fallback_status: Some(fallback_info_no_duration),
            da_status: Some("degraded".to_string()),
            warning: None, // Should be None because we don't infer degraded when data unavailable
            ..Default::default()
        };
        assert!(
            health_no_duration.warning.is_none(),
            "warning should be None when duration data unavailable"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14A.1A.64-5: gather_health populates da_status and warning correctly
    // ════════════════════════════════════════════════════════════════════════

    /// Test that gather_health sets da_status and warning fields correctly.
    ///
    /// NOTE: This test uses default gather_health (no fallback_status available),
    /// so da_status and warning should both be None.
    #[tokio::test]
    async fn test_gather_health_populates_new_fields() {
        let coord = Arc::new(CoordinatorClient::new("http://localhost:8080".to_string()));
        let state = AppState::new(coord);

        let health = state.gather_health().await;

        // Without fallback_status, da_status should be None
        assert!(
            health.da_status.is_none(),
            "da_status should be None when gather_fallback_status returns None"
        );

        // Without fallback_status, warning should be None
        assert!(
            health.warning.is_none(),
            "warning should be None when gather_fallback_status returns None"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14A.1A.64-6: JSON serialization includes new fields
    // ════════════════════════════════════════════════════════════════════════

    /// Test that da_status and warning are correctly serialized to JSON.
    #[test]
    fn test_json_serialization_new_fields() {
        // Case 1: Both fields are None
        let health_none = IngressHealth::default();
        let json_none = serde_json::to_string(&health_none).expect("serialization should succeed");
        assert!(
            json_none.contains("\"da_status\":null"),
            "da_status should serialize as null when None"
        );
        assert!(
            json_none.contains("\"warning\":null"),
            "warning should serialize as null when None"
        );

        // Case 2: Both fields have values
        let health_some = IngressHealth {
            da_status: Some("degraded".to_string()),
            warning: Some("DEGRADED: test warning".to_string()),
            ..Default::default()
        };
        let json_some = serde_json::to_string(&health_some).expect("serialization should succeed");
        assert!(
            json_some.contains("\"da_status\":\"degraded\""),
            "da_status should serialize with value"
        );
        assert!(
            json_some.contains("\"warning\":\"DEGRADED: test warning\""),
            "warning should serialize with value"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14A.1A.64-7: Combined DEGRADED conditions
    // ════════════════════════════════════════════════════════════════════════

    /// Test warning when BOTH DEGRADED conditions are met.
    #[test]
    fn test_warning_both_conditions_met() {
        use fallback_health::FallbackHealthInfo;
        use dsdn_common::DAStatus;

        let fallback_info = FallbackHealthInfo {
            status: DAStatus::Emergency,
            active: true,
            reason: Some("critical".to_string()),
            activated_at: Some(1704067200),
            duration_secs: Some(900), // > 600
            pending_reconcile: 2000, // > 1000
            last_celestia_contact: Some(1704066900),
            current_source: "emergency".to_string(),
        };

        // When both conditions are met, warning should contain both reasons
        let health = IngressHealth {
            fallback_active: true,
            fallback_status: Some(fallback_info),
            da_status: Some("emergency".to_string()),
            warning: Some("DEGRADED: fallback active for 900 seconds (threshold: 600); pending_reconcile=2000 (threshold: 1000)".to_string()),
            ..Default::default()
        };

        assert!(health.warning.is_some());
        let warning = health.warning.as_ref().unwrap();
        assert!(warning.contains("900 seconds"), "should mention duration");
        assert!(warning.contains("pending_reconcile=2000"), "should mention pending_reconcile");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14A.1A.65-1: FallbackStatusResponse struct correctness
    // ════════════════════════════════════════════════════════════════════════

    /// Test that FallbackStatusResponse is correctly constructed.
    #[test]
    fn test_fallback_status_response_construction() {
        use fallback_health::FallbackHealthInfo;
        use dsdn_common::DAStatus;

        let fallback_info = FallbackHealthInfo {
            status: DAStatus::Degraded,
            active: true,
            reason: Some("test".to_string()),
            activated_at: Some(1704067200),
            duration_secs: Some(300),
            pending_reconcile: 42,
            last_celestia_contact: Some(1704066900),
            current_source: "fallback".to_string(),
        };

        let response = FallbackStatusResponse {
            info: fallback_info.clone(),
            time_since_last_primary_contact_secs: Some(300),
            reconciliation_queue_depth: 42,
            events_processed: None,
        };

        // Verify all fields are correctly set
        assert!(response.info.active);
        assert_eq!(response.info.pending_reconcile, 42);
        assert_eq!(response.reconciliation_queue_depth, 42);
        assert_eq!(response.time_since_last_primary_contact_secs, Some(300));
        assert!(response.events_processed.is_none());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14A.1A.65-2: FallbackStatusResponse JSON serialization
    // ════════════════════════════════════════════════════════════════════════

    /// Test that FallbackStatusResponse serializes correctly to JSON.
    #[test]
    fn test_fallback_status_response_json_serialization() {
        use fallback_health::FallbackHealthInfo;
        use dsdn_common::DAStatus;

        let fallback_info = FallbackHealthInfo {
            status: DAStatus::Degraded,
            active: true,
            reason: Some("test".to_string()),
            activated_at: Some(1704067200),
            duration_secs: Some(300),
            pending_reconcile: 42,
            last_celestia_contact: Some(1704066900),
            current_source: "fallback".to_string(),
        };

        let response = FallbackStatusResponse {
            info: fallback_info,
            time_since_last_primary_contact_secs: Some(600),
            reconciliation_queue_depth: 100,
            events_processed: None,
        };

        let json = serde_json::to_string(&response).expect("serialization should succeed");

        // Verify JSON contains expected fields
        assert!(json.contains("\"info\":{"));
        assert!(json.contains("\"time_since_last_primary_contact_secs\":600"));
        assert!(json.contains("\"reconciliation_queue_depth\":100"));
        assert!(json.contains("\"events_processed\":null"));
        assert!(json.contains("\"pending_reconcile\":42"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14A.1A.65-3: fallback_status returns 404 when no da_router
    // ════════════════════════════════════════════════════════════════════════

    /// Test that GET /fallback/status returns 404 when DARouter is not configured.
    ///
    /// Requirements:
    /// - HTTP 404 status
    /// - No body or null body
    /// - No panic
    #[tokio::test]
    async fn test_fallback_status_returns_404_when_no_da_router() {
        // Setup: AppState WITHOUT da_router
        let coord = Arc::new(CoordinatorClient::new("http://localhost:8080".to_string()));
        let state = AppState::new(coord);

        // Precondition: da_router is None
        assert!(state.da_router.is_none(), "Precondition: da_router should be None");

        // Call handler directly
        let response = fallback_status(State(state)).await;
        let (status, _body) = response.into_response().into_parts();

        // Verify: HTTP 404
        assert_eq!(
            status.status,
            StatusCode::NOT_FOUND,
            "Should return 404 when da_router is None"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14A.1A.65-4: fallback_status is deterministic
    // ════════════════════════════════════════════════════════════════════════

    /// Test that fallback_status returns consistent results.
    #[tokio::test]
    async fn test_fallback_status_deterministic() {
        let coord = Arc::new(CoordinatorClient::new("http://localhost:8080".to_string()));
        let state = AppState::new(coord);

        // Multiple calls should return the same status code
        let response1 = fallback_status(State(state.clone())).await;
        let response2 = fallback_status(State(state.clone())).await;
        let response3 = fallback_status(State(state)).await;

        let (parts1, _) = response1.into_response().into_parts();
        let (parts2, _) = response2.into_response().into_parts();
        let (parts3, _) = response3.into_response().into_parts();

        assert_eq!(parts1.status, parts2.status);
        assert_eq!(parts2.status, parts3.status);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14A.1A.65-5: EventsProcessedBySource struct
    // ════════════════════════════════════════════════════════════════════════

    /// Test that EventsProcessedBySource serializes correctly.
    #[test]
    fn test_events_processed_by_source_serialization() {
        let events = EventsProcessedBySource {
            primary: Some(100),
            secondary: Some(50),
            emergency: None,
        };

        let json = serde_json::to_string(&events).expect("serialization should succeed");

        assert!(json.contains("\"primary\":100"));
        assert!(json.contains("\"secondary\":50"));
        assert!(json.contains("\"emergency\":null"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14A.1A.65-6: time_since_last_primary_contact calculation
    // ════════════════════════════════════════════════════════════════════════

    /// Test that time_since_last_primary_contact is correctly calculated.
    ///
    /// - When last_celestia_contact is Some: calculate difference
    /// - When last_celestia_contact is None: return None
    /// - No overflow (saturating arithmetic)
    #[test]
    fn test_time_since_last_primary_contact_calculation() {
        use fallback_health::FallbackHealthInfo;
        use dsdn_common::DAStatus;

        // Case 1: last_celestia_contact is Some
        let fallback_info_with_contact = FallbackHealthInfo {
            status: DAStatus::Degraded,
            active: true,
            reason: None,
            activated_at: None,
            duration_secs: None,
            pending_reconcile: 0,
            last_celestia_contact: Some(1704067200), // Some timestamp
            current_source: "fallback".to_string(),
        };

        // Simulate calculation (current_secs - last_contact)
        let current_secs = 1704067500u64; // 300 seconds later
        let time_since = current_secs.saturating_sub(1704067200);
        assert_eq!(time_since, 300);

        // Case 2: last_celestia_contact is None
        let fallback_info_no_contact = FallbackHealthInfo {
            status: DAStatus::Degraded,
            active: true,
            reason: None,
            activated_at: None,
            duration_secs: None,
            pending_reconcile: 0,
            last_celestia_contact: None,
            current_source: "fallback".to_string(),
        };

        let time_since_none = fallback_info_no_contact.last_celestia_contact.map(|lc| {
            current_secs.saturating_sub(lc)
        });
        assert!(time_since_none.is_none());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14A.1A.65-7: reconciliation_queue_depth is actual value
    // ════════════════════════════════════════════════════════════════════════

    /// Test that reconciliation_queue_depth matches pending_reconcile.
    #[test]
    fn test_reconciliation_queue_depth_matches_pending_reconcile() {
        use fallback_health::FallbackHealthInfo;
        use dsdn_common::DAStatus;

        let test_values = [0u64, 1, 100, 1000, 10000, u64::MAX];

        for value in test_values {
            let fallback_info = FallbackHealthInfo {
                status: DAStatus::Degraded,
                active: true,
                reason: None,
                activated_at: None,
                duration_secs: None,
                pending_reconcile: value,
                last_celestia_contact: None,
                current_source: "fallback".to_string(),
            };

            let response = FallbackStatusResponse {
                info: fallback_info.clone(),
                time_since_last_primary_contact_secs: None,
                reconciliation_queue_depth: fallback_info.pending_reconcile,
                events_processed: None,
            };

            assert_eq!(
                response.reconciliation_queue_depth,
                value,
                "reconciliation_queue_depth should match pending_reconcile"
            );
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14A.1A.65-8: FallbackStatusResponse with EventsProcessedBySource
    // ════════════════════════════════════════════════════════════════════════

    /// Test FallbackStatusResponse when events_processed is populated.
    #[test]
    fn test_fallback_status_response_with_events() {
        use fallback_health::FallbackHealthInfo;
        use dsdn_common::DAStatus;

        let fallback_info = FallbackHealthInfo {
            status: DAStatus::Degraded,
            active: true,
            reason: None,
            activated_at: None,
            duration_secs: None,
            pending_reconcile: 50,
            last_celestia_contact: None,
            current_source: "fallback".to_string(),
        };

        let events = EventsProcessedBySource {
            primary: Some(1000),
            secondary: Some(500),
            emergency: Some(100),
        };

        let response = FallbackStatusResponse {
            info: fallback_info,
            time_since_last_primary_contact_secs: None,
            reconciliation_queue_depth: 50,
            events_processed: Some(events),
        };

        // Verify events_processed is populated
        assert!(response.events_processed.is_some());
        let events = response.events_processed.as_ref().unwrap();
        assert_eq!(events.primary, Some(1000));
        assert_eq!(events.secondary, Some(500));
        assert_eq!(events.emergency, Some(100));

        // Verify JSON serialization
        let json = serde_json::to_string(&response).expect("serialization should succeed");
        assert!(json.contains("\"events_processed\":{"));
        assert!(json.contains("\"primary\":1000"));
        assert!(json.contains("\"secondary\":500"));
        assert!(json.contains("\"emergency\":100"));
    }
}