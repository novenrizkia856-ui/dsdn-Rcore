use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

use crate::coord_client::CoordinatorClient;
use crate::da_router::DARouter;
use crate::metrics::IngressMetrics;
use crate::alerting::AlertDispatcher;
use crate::economic_handlers;
use crate::receipt_event_logger;
use crate::types::{IngressHealth, ReadyStatus, ready_thresholds};
use crate::helpers::current_timestamp_ms;
use crate::FallbackHealthInfo;

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
    /// Alert dispatcher untuk notifikasi fallback events (14A.1A.68).
    pub alert_dispatcher: AlertDispatcher,
    /// Fraud proof submission log (14C.C.26). Thread-safe via `RwLock`.
    pub fraud_proof_log: economic_handlers::FraudProofLog,
    /// Receipt event logger for DA audit logging (14C.C.28).
    pub event_logger: Arc<receipt_event_logger::ReceiptEventLogger>,
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
            alert_dispatcher: AlertDispatcher::with_logging(),
            fraud_proof_log: economic_handlers::new_fraud_proof_log(),
            event_logger: Arc::new(receipt_event_logger::ReceiptEventLogger::without_publisher(
                "receipt_events.jsonl".to_string(),
            )),
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
            alert_dispatcher: AlertDispatcher::with_logging(),
            fraud_proof_log: economic_handlers::new_fraud_proof_log(),
            event_logger: Arc::new(receipt_event_logger::ReceiptEventLogger::without_publisher(
                "receipt_events.jsonl".to_string(),
            )),
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
            alert_dispatcher: AlertDispatcher::with_logging(),
            fraud_proof_log: economic_handlers::new_fraud_proof_log(),
            event_logger: Arc::new(receipt_event_logger::ReceiptEventLogger::without_publisher(
                "receipt_events.jsonl".to_string(),
            )),
        }
    }

    /// Membuat AppState dengan custom AlertDispatcher (14A.1A.68).
    #[allow(dead_code)]
    pub fn with_alert_dispatcher(coord: Arc<CoordinatorClient>, dispatcher: AlertDispatcher) -> Self {
        Self {
            coord,
            da_router: None,
            da_connected: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            da_last_sequence: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            metrics: Arc::new(IngressMetrics::new()),
            alert_dispatcher: dispatcher,
            fraud_proof_log: economic_handlers::new_fraud_proof_log(),
            event_logger: Arc::new(receipt_event_logger::ReceiptEventLogger::without_publisher(
                "receipt_events.jsonl".to_string(),
            )),
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
    #[allow(dead_code)]
    pub async fn is_ready(&self) -> bool {
        matches!(self.check_ready().await, ReadyStatus::Ready | ReadyStatus::ReadyDegraded(_))
    }

    /// Check readiness with detailed status (14A.1A.66).
    ///
    /// ## Ready Conditions (KONTRAK KERAS)
    ///
    /// 1. **Coordinator reachable**
    ///    - Jika TIDAK → NOT READY
    ///
    /// 2. **DA available (MINIMAL SATU SOURCE)**
    ///    - Primary OR Fallback OR Emergency
    ///    - Jika TIDAK ADA satupun → NOT READY
    ///
    /// 3. **Fallback active lebih lama dari threshold**
    ///    - Status: DEGRADED (bukan failure)
    ///    - Threshold: 600 detik
    ///
    /// 4. **Pending reconciliation > threshold**
    ///    - Status: DEGRADED (bukan failure)
    ///    - Threshold: 1000
    ///
    /// ## Return Values
    ///
    /// - `ReadyStatus::Ready` - Sistem siap (HTTP 200)
    /// - `ReadyStatus::ReadyDegraded(warning)` - Sistem degraded (HTTP 200 + X-Warning)
    /// - `ReadyStatus::NotReady(reason)` - Sistem tidak siap (HTTP 503)
    ///
    /// ## Guarantees
    ///
    /// - **NO panic**: Tidak pernah panic
    /// - **NO unwrap/expect**: Semua error handling eksplisit
    /// - **Deterministic**: Hasil konsisten untuk state yang sama
    pub async fn check_ready(&self) -> ReadyStatus {
        // ────────────────────────────────────────────────────────────────────────
        // CONDITION 1: Coordinator reachable
        // ────────────────────────────────────────────────────────────────────────
        let coord_ok = timeout(Duration::from_secs(2), self.coord.ping()).await;
        if !matches!(coord_ok, Ok(Ok(()))) {
            return ReadyStatus::NotReady("coordinator not reachable".to_string());
        }

        // ────────────────────────────────────────────────────────────────────────
        // CONDITION 2: DA available (MINIMAL SATU SOURCE)
        // ────────────────────────────────────────────────────────────────────────
        //
        // Check apakah ada DA source yang tersedia:
        // - Jika da_router ada dan cache valid → DA tersedia
        // - Jika da_router None tapi da_connected true → DA tersedia (connected mode)
        // - Jika tidak ada sama sekali → NOT READY
        //
        // Untuk fallback awareness:
        // - Primary healthy → da_primary_healthy
        // - Secondary healthy → da_secondary_healthy.unwrap_or(false)
        // - Emergency healthy → da_emergency_healthy.unwrap_or(false)

        let da_available = if let Some(ref router) = self.da_router {
            let cache = router.get_cache();

            // Cache must have been filled at least once
            if cache.last_updated == 0 {
                return ReadyStatus::NotReady("DA cache not initialized".to_string());
            }

            // Must have at least one healthy node
            let healthy_count = cache.node_registry
                .values()
                .filter(|n| n.active)
                .count();

            if healthy_count == 0 {
                return ReadyStatus::NotReady("no healthy nodes in DA cache".to_string());
            }

            true
        } else {
            // No da_router configured
            // Check if we're in connected mode (legacy compatibility)
            self.is_da_connected()
        };

        if !da_available {
            return ReadyStatus::NotReady("no DA source available".to_string());
        }

        // ────────────────────────────────────────────────────────────────────────
        // CONDITION 3 & 4: Check for DEGRADED status
        // ────────────────────────────────────────────────────────────────────────
        //
        // DEGRADED jika:
        // - fallback_active == true DAN
        // - (duration_secs > 600 ATAU pending_reconcile > 1000)
        //
        // Ambil data dari gather_fallback_status()
        if let Some(fallback_info) = self.gather_fallback_status() {
            if fallback_info.active {
                let mut degraded_reasons = Vec::new();

                // Check duration threshold
                let duration_exceeded = fallback_info.duration_secs
                    .map(|d| d > ready_thresholds::FALLBACK_DURATION_THRESHOLD_SECS)
                    .unwrap_or(false);

                if duration_exceeded {
                    if let Some(duration) = fallback_info.duration_secs {
                        degraded_reasons.push(format!(
                            "fallback active for {} seconds (threshold: {})",
                            duration,
                            ready_thresholds::FALLBACK_DURATION_THRESHOLD_SECS
                        ));
                    }
                }

                // Check pending_reconcile threshold
                if fallback_info.pending_reconcile > ready_thresholds::PENDING_RECONCILE_THRESHOLD {
                    degraded_reasons.push(format!(
                        "pending_reconcile={} (threshold: {})",
                        fallback_info.pending_reconcile,
                        ready_thresholds::PENDING_RECONCILE_THRESHOLD
                    ));
                }

                // Return DEGRADED if any threshold exceeded
                if !degraded_reasons.is_empty() {
                    return ReadyStatus::ReadyDegraded(format!(
                        "DEGRADED: {}",
                        degraded_reasons.join("; ")
                    ));
                }
            }
        }

        // All conditions met → READY
        ReadyStatus::Ready
    }
}