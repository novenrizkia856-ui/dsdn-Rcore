//! DSDN Coordinator Entry Point
//!
//! Production coordinator with Celestia mainnet integration and DARouter fallback support.
//!
//! ## Environment File Loading
//!
//! The coordinator automatically loads configuration from environment files:
//!
//! 1. `DSDN_ENV_FILE` environment variable (custom path)
//! 2. `.env.mainnet` (production default - **DSDN defaults to mainnet**)
//! 3. `.env` (fallback for development)
//!
//! ## Configuration
//!
//! The coordinator loads configuration from environment variables for production:
//!
//! ### Primary DA Configuration
//! - `DA_RPC_URL`: Celestia light node RPC endpoint (required)
//! - `DA_NAMESPACE`: 58-character hex namespace (required)
//! - `DA_AUTH_TOKEN`: Authentication token (required for mainnet)
//! - `DA_NETWORK`: Network identifier (**default: mainnet**, options: mocha, local)
//! - `DA_TIMEOUT_MS`: Operation timeout in milliseconds
//! - `DA_RETRY_COUNT`: Number of retries for failed operations
//! - `DA_RETRY_DELAY_MS`: Delay between retries
//!
//! ### Fallback DA Configuration (14A.1A.35)
//! - `ENABLE_FALLBACK`: Enable fallback DA (true/false, default: false)
//! - `FALLBACK_DA_TYPE`: Fallback type (none, quorum, emergency)
//! - `QUORUM_VALIDATORS`: Comma-separated validator addresses (required if type=quorum)
//! - `QUORUM_THRESHOLD`: Quorum threshold percentage 1-100 (default: 67)
//! - `QUORUM_SIGNATURE_TIMEOUT_MS`: Signature collection timeout (default: 5000)
//! - `EMERGENCY_DA_URL`: Emergency DA URL (required if type=emergency)
//!
//! ### Reconciliation Configuration
//! - `RECONCILE_BATCH_SIZE`: Batch size for reconciliation (default: 10)
//! - `RECONCILE_RETRY_DELAY_MS`: Retry delay in ms (default: 1000)
//! - `RECONCILE_MAX_RETRIES`: Max retries per blob (default: 3)
//! - `RECONCILE_PARALLEL`: Enable parallel reconciliation (default: false)
//!
//! ### HTTP Server Configuration
//! - `COORDINATOR_PORT`: HTTP server port (default: 8080)
//! - `COORDINATOR_HOST`: HTTP server host (default: 127.0.0.1)
//!
//! ## Startup Flow (14A.1A.36)
//!
//! The coordinator follows this EXACT startup sequence:
//!
//! 1. Load CoordinatorConfig (including fallback config)
//! 2. Initialize PRIMARY DA (Celestia) - REQUIRED
//! 3. Initialize SECONDARY DA (QuorumDA) - if enable_fallback && type=Quorum
//! 4. Initialize EMERGENCY DA - if enable_fallback && type=Emergency
//! 5. Create DAHealthMonitor
//! 6. Create DARouter (primary + optional fallback)
//! 7. Start health monitoring loop
//! 8. Inject DARouter to AppState
//! 9. Run application runtime
//!
//! ## DARouter Architecture
//!
//! DARouter is the SOLE entry point for all DA operations. It:
//! - Routes requests to primary, secondary, or emergency DA
//! - Monitors health via DAHealthMonitor
//! - Handles automatic failover and recovery
//! - Tracks metrics per DA layer

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Router,
    Json,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use std::pin::Pin;
use std::future::Future;
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn, Level};
use serde_json::{Value, json};
use tokio::task::JoinHandle;

use dsdn_common::{CelestiaDA, DAConfig, DAError, DAHealthStatus, DALayer, MockDA, BlobRef, BlobStream};
use dsdn_common::da::DAMetricsSnapshot;
use dsdn_coordinator::{Coordinator, NodeInfo, Workload, ReconciliationConfig};
use parking_lot::RwLock;
mod handlers;

// ════════════════════════════════════════════════════════════════════════════
// FALLBACK DA TYPES (14A.1A.35)
// ════════════════════════════════════════════════════════════════════════════

/// Type of fallback DA to use when primary (Celestia) is unavailable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FallbackDAType {
    /// No fallback - only primary DA
    None,
    /// Quorum-based DA using validator signatures
    Quorum,
    /// Emergency single-node DA
    Emergency,
}

impl FallbackDAType {
    /// Parse from string (case-insensitive).
    ///
    /// Returns error for invalid values.
    fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "none" | "" => Ok(Self::None),
            "quorum" => Ok(Self::Quorum),
            "emergency" => Ok(Self::Emergency),
            other => Err(format!(
                "Invalid FALLBACK_DA_TYPE '{}'. Valid values: none, quorum, emergency",
                other
            )),
        }
    }
}

impl std::fmt::Display for FallbackDAType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Quorum => write!(f, "quorum"),
            Self::Emergency => write!(f, "emergency"),
        }
    }
}

/// Configuration for Quorum-based DA fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumDAConfig {
    /// List of validator addresses (URLs or identifiers).
    pub validators: Vec<String>,
    /// Quorum threshold percentage (1-100).
    pub quorum_threshold: u8,
    /// Timeout for signature collection in milliseconds.
    pub signature_timeout_ms: u64,
}

impl QuorumDAConfig {
    /// Parse from environment variables.
    ///
    /// Required env vars:
    /// - `QUORUM_VALIDATORS`: Comma-separated validator addresses
    ///
    /// Optional env vars:
    /// - `QUORUM_THRESHOLD`: Percentage (default: 67)
    /// - `QUORUM_SIGNATURE_TIMEOUT_MS`: Timeout in ms (default: 5000)
    fn from_env() -> Result<Self, String> {
        let validators_str = std::env::var("QUORUM_VALIDATORS")
            .map_err(|_| "QUORUM_VALIDATORS is required when FALLBACK_DA_TYPE=quorum")?;

        let validators: Vec<String> = validators_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        if validators.is_empty() {
            return Err("QUORUM_VALIDATORS must contain at least one validator address".to_string());
        }

        let quorum_threshold: u8 = std::env::var("QUORUM_THRESHOLD")
            .unwrap_or_else(|_| "67".to_string())
            .parse()
            .map_err(|_| "QUORUM_THRESHOLD must be a number 1-100")?;

        if quorum_threshold == 0 || quorum_threshold > 100 {
            return Err("QUORUM_THRESHOLD must be between 1 and 100".to_string());
        }

        let signature_timeout_ms: u64 = std::env::var("QUORUM_SIGNATURE_TIMEOUT_MS")
            .unwrap_or_else(|_| "5000".to_string())
            .parse()
            .map_err(|_| "QUORUM_SIGNATURE_TIMEOUT_MS must be a valid number")?;

        Ok(Self {
            validators,
            quorum_threshold,
            signature_timeout_ms,
        })
    }
}

// ════════════════════════════════════════════════════════════════════════════
// FALLBACK HTTP ENDPOINT TYPES (14A.1A.38)
// ════════════════════════════════════════════════════════════════════════════

/// DA layer status for HTTP responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DAStatus {
    /// Primary DA is healthy and active.
    PrimaryHealthy,
    /// Primary DA degraded but usable.
    PrimaryDegraded,
    /// Fallback DA is active (secondary).
    FallbackSecondary,
    /// Fallback DA is active (emergency).
    FallbackEmergency,
    /// All DA layers unavailable.
    Unavailable,
}

impl std::fmt::Display for DAStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PrimaryHealthy => write!(f, "primary_healthy"),
            Self::PrimaryDegraded => write!(f, "primary_degraded"),
            Self::FallbackSecondary => write!(f, "fallback_secondary"),
            Self::FallbackEmergency => write!(f, "fallback_emergency"),
            Self::Unavailable => write!(f, "unavailable"),
        }
    }
}

/// Response for GET /fallback/status endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct FallbackStatusResponse {
    /// Current DA status.
    pub current_status: DAStatus,
    /// Whether fallback DA is currently active.
    pub fallback_active: bool,
    /// Reason for fallback activation (if active).
    pub fallback_reason: Option<String>,
    /// Number of pending blobs awaiting reconciliation.
    pub pending_reconcile_count: u64,
    /// Timestamp of last fallback activation (Unix ms).
    pub last_fallback_at: Option<u64>,
}

/// Information about a pending blob awaiting reconciliation.
#[derive(Debug, Clone, Serialize)]
pub struct PendingBlobInfo {
    /// Blob reference ID (commitment hash as hex).
    pub blob_id: String,
    /// Source DA layer.
    pub source_da: String,
    /// Target DA layer for reconciliation.
    pub target_da: String,
    /// Timestamp when blob was stored (Unix ms).
    pub stored_at: u64,
    /// Number of reconciliation attempts.
    pub retry_count: u32,
    /// Last error message (if any).
    pub last_error: Option<String>,
}

/// Report from a reconciliation operation.
#[derive(Debug, Clone, Serialize)]
pub struct ReconcileReport {
    /// Whether reconciliation completed successfully.
    pub success: bool,
    /// Number of blobs processed.
    pub blobs_processed: u64,
    /// Number of blobs successfully reconciled.
    pub blobs_reconciled: u64,
    /// Number of blobs that failed reconciliation.
    pub blobs_failed: u64,
    /// Duration of reconciliation in milliseconds.
    pub duration_ms: u64,
    /// Error messages for failed blobs (if any).
    pub errors: Vec<String>,
}

/// Report from state consistency verification.
#[derive(Debug, Clone, Serialize)]
pub struct ConsistencyReport {
    /// Whether state is consistent.
    pub is_consistent: bool,
    /// Number of items verified.
    pub items_verified: u64,
    /// Number of inconsistencies found.
    pub inconsistencies_found: u64,
    /// Description of inconsistencies (if any).
    pub details: Vec<String>,
    /// Verification timestamp (Unix ms).
    pub verified_at: u64,
}

// ════════════════════════════════════════════════════════════════════════════
// DAROUTER TYPES (14A.1A.36)
// ════════════════════════════════════════════════════════════════════════════

/// Configuration for DARouter.
#[derive(Debug, Clone)]
pub struct DARouterConfig {
    /// Health check interval in milliseconds.
    pub health_check_interval_ms: u64,
    /// Number of consecutive failures before switching to fallback.
    pub failure_threshold: u32,
    /// Number of consecutive successes before switching back to primary.
    pub recovery_threshold: u32,
    /// Automatically trigger reconciliation when recovering from fallback (14A.1A.39).
    /// Default: true
    pub auto_reconcile_on_recovery: bool,
}

impl Default for DARouterConfig {
    fn default() -> Self {
        Self {
            health_check_interval_ms: 5000,
            failure_threshold: 3,
            recovery_threshold: 2,
            auto_reconcile_on_recovery: true,
        }
    }
}

/// Metrics for DARouter operations.
#[derive(Debug)]
pub struct DARouterMetrics {
    /// Total requests routed to primary.
    pub primary_requests: AtomicU64,
    /// Total requests routed to secondary.
    pub secondary_requests: AtomicU64,
    /// Total requests routed to emergency.
    pub emergency_requests: AtomicU64,
    /// Total failover events.
    pub failover_count: AtomicU64,
    /// Total recovery events.
    pub recovery_count: AtomicU64,
}

impl DARouterMetrics {
    /// Create new metrics instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            primary_requests: AtomicU64::new(0),
            secondary_requests: AtomicU64::new(0),
            emergency_requests: AtomicU64::new(0),
            failover_count: AtomicU64::new(0),
            recovery_count: AtomicU64::new(0),
        }
    }
}

impl Default for DARouterMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Current routing state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingState {
    /// Using primary DA.
    Primary,
    /// Using secondary (fallback) DA.
    Secondary,
    /// Using emergency DA.
    Emergency,
}

impl std::fmt::Display for RoutingState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Primary => write!(f, "primary"),
            Self::Secondary => write!(f, "secondary"),
            Self::Emergency => write!(f, "emergency"),
        }
    }
}

/// Health status tracker for DA layers.
///
/// Tracks health of primary, secondary, and emergency DA layers.
/// Used by DARouter to make routing decisions.
pub struct DAHealthMonitor {
    /// Primary DA health status.
    primary_healthy: AtomicBool,
    /// Secondary DA health status.
    secondary_healthy: AtomicBool,
    /// Emergency DA health status.
    emergency_healthy: AtomicBool,
    /// Consecutive primary failures.
    primary_failures: AtomicU64,
    /// Consecutive primary successes (after recovery).
    primary_successes: AtomicU64,
    /// Configuration.
    config: DARouterConfig,
    /// Primary DA reference.
    primary: Arc<dyn DALayer>,
    /// Secondary DA reference (optional).
    secondary: Option<Arc<dyn DALayer>>,
    /// Emergency DA reference (optional).
    emergency: Option<Arc<dyn DALayer>>,
    /// Shutdown signal.
    shutdown: AtomicBool,
    /// Reason for current fallback state (14A.1A.38).
    fallback_reason: RwLock<Option<String>>,
    /// Timestamp of last fallback activation in Unix ms (14A.1A.38).
    last_fallback_at: AtomicU64,
    /// Whether recovery reconciliation is in progress (14A.1A.39).
    recovery_in_progress: AtomicBool,
    /// Reference to reconciliation engine for auto-recovery (14A.1A.39).
    reconciliation_engine: RwLock<Option<Arc<ReconciliationEngine>>>,
    /// Whether currently on fallback (tracks previous state for transition detection) (14A.1A.39).
    was_on_fallback: AtomicBool,
}

impl DAHealthMonitor {
    /// Create new health monitor.
    pub fn new(
        config: DARouterConfig,
        primary: Arc<dyn DALayer>,
        secondary: Option<Arc<dyn DALayer>>,
        emergency: Option<Arc<dyn DALayer>>,
    ) -> Self {
        // Initially NOT on fallback - we start assuming primary is healthy
        Self {
            primary_healthy: AtomicBool::new(true),
            secondary_healthy: AtomicBool::new(secondary.is_some()),
            emergency_healthy: AtomicBool::new(emergency.is_some()),
            primary_failures: AtomicU64::new(0),
            primary_successes: AtomicU64::new(0),
            config,
            primary,
            secondary,
            emergency,
            shutdown: AtomicBool::new(false),
            fallback_reason: RwLock::new(None),
            last_fallback_at: AtomicU64::new(0),
            recovery_in_progress: AtomicBool::new(false),
            reconciliation_engine: RwLock::new(None),
            was_on_fallback: AtomicBool::new(false),
        }
    }

    /// Check if primary is healthy.
    pub fn is_primary_healthy(&self) -> bool {
        self.primary_healthy.load(Ordering::Relaxed)
    }

    /// Check if secondary is healthy.
    pub fn is_secondary_healthy(&self) -> bool {
        self.secondary_healthy.load(Ordering::Relaxed)
    }

    /// Check if emergency is healthy.
    pub fn is_emergency_healthy(&self) -> bool {
        self.emergency_healthy.load(Ordering::Relaxed)
    }

    /// Update primary health status.
    pub fn update_primary_health(&self, healthy: bool) {
        self.primary_healthy.store(healthy, Ordering::Relaxed);
        if healthy {
            self.primary_failures.store(0, Ordering::Relaxed);
            self.primary_successes.fetch_add(1, Ordering::Relaxed);
        } else {
            self.primary_successes.store(0, Ordering::Relaxed);
            self.primary_failures.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Check if should failover based on failure count.
    pub fn should_failover(&self) -> bool {
        self.primary_failures.load(Ordering::Relaxed) >= u64::from(self.config.failure_threshold)
    }

    /// Check if should recover based on success count.
    pub fn should_recover(&self) -> bool {
        self.primary_successes.load(Ordering::Relaxed) >= u64::from(self.config.recovery_threshold)
    }

    /// Signal shutdown.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }

    /// Check if shutdown signaled.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    /// Get current DA status for HTTP API.
    pub fn current_da_status(&self) -> DAStatus {
        if self.is_primary_healthy() {
            DAStatus::PrimaryHealthy
        } else if self.is_secondary_healthy() {
            DAStatus::FallbackSecondary
        } else if self.is_emergency_healthy() {
            DAStatus::FallbackEmergency
        } else {
            DAStatus::Unavailable
        }
    }

    /// Check if any fallback is currently active.
    pub fn is_fallback_active(&self) -> bool {
        !self.is_primary_healthy() && (self.is_secondary_healthy() || self.is_emergency_healthy())
    }

    /// Get current fallback reason.
    pub fn get_fallback_reason(&self) -> Option<String> {
        self.fallback_reason.read().clone()
    }

    /// Set fallback reason and update timestamp.
    pub fn set_fallback_reason(&self, reason: String) {
        *self.fallback_reason.write() = Some(reason);
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        self.last_fallback_at.store(now_ms, Ordering::Relaxed);
    }

    /// Clear fallback reason (when recovered to primary).
    pub fn clear_fallback_reason(&self) {
        *self.fallback_reason.write() = None;
    }

    /// Get last fallback activation timestamp.
    pub fn get_last_fallback_at(&self) -> Option<u64> {
        let ts = self.last_fallback_at.load(Ordering::Relaxed);
        if ts == 0 { None } else { Some(ts) }
    }

    /// Get consecutive failure count.
    pub fn failure_count(&self) -> u64 {
        self.primary_failures.load(Ordering::Relaxed)
    }

    /// Set the reconciliation engine reference (14A.1A.39).
    ///
    /// Must be called after ReconciliationEngine is created to enable auto-recovery.
    pub fn set_reconciliation_engine(&self, engine: Arc<ReconciliationEngine>) {
        *self.reconciliation_engine.write() = Some(engine);
    }

    /// Check if recovery reconciliation is in progress (14A.1A.39).
    pub fn is_recovery_in_progress(&self) -> bool {
        self.recovery_in_progress.load(Ordering::Relaxed)
    }

    /// Check if auto-reconcile on recovery is enabled.
    pub fn is_auto_reconcile_enabled(&self) -> bool {
        self.config.auto_reconcile_on_recovery
    }

    /// Update was_on_fallback state (14A.1A.39).
    pub fn update_fallback_state(&self, currently_on_fallback: bool) {
        self.was_on_fallback.store(currently_on_fallback, Ordering::Relaxed);
    }

    /// Check if was on fallback in previous cycle (14A.1A.39).
    pub fn was_previously_on_fallback(&self) -> bool {
        self.was_on_fallback.load(Ordering::Relaxed)
    }

    /// Start health monitoring loop.
    ///
    /// Returns JoinHandle for the monitoring task.
    ///
    /// ## Recovery Handling (14A.1A.39)
    ///
    /// When transitioning from Degraded/Emergency (fallback) to Recovering:
    /// 1. Log transition event (INFO level, eksplisit)
    /// 2. Clear fallback reason
    /// 3. If auto_reconcile_on_recovery is enabled:
    ///    - Spawn background reconciliation task
    ///    - Wait for completion (async)
    ///    - Log result
    /// 4. If reconcile succeeds → transition to Healthy
    /// 5. If reconcile fails → status NOT Healthy, error logged
    pub fn start_monitoring(self: &Arc<Self>) -> JoinHandle<()> {
        let monitor = Arc::clone(self);
        let interval = Duration::from_millis(monitor.config.health_check_interval_ms);

        tokio::spawn(async move {
            info!("🏥 Health monitor started (interval: {}ms)", interval.as_millis());

            loop {
                if monitor.is_shutdown() {
                    info!("Health monitor shutting down");
                    break;
                }

                // Track previous state BEFORE health checks
                let was_on_fallback = monitor.was_previously_on_fallback();

                // Check primary health
                match monitor.primary.health_check().await {
                    Ok(DAHealthStatus::Healthy) => {
                        monitor.update_primary_health(true);
                    }
                    Ok(DAHealthStatus::Degraded) => {
                        // Degraded is still usable
                        monitor.update_primary_health(true);
                    }
                    _ => {
                        monitor.update_primary_health(false);
                    }
                }

                // Check secondary health if available
                if let Some(ref secondary) = monitor.secondary {
                    let healthy = matches!(
                        secondary.health_check().await,
                        Ok(DAHealthStatus::Healthy) | Ok(DAHealthStatus::Degraded)
                    );
                    monitor.secondary_healthy.store(healthy, Ordering::Relaxed);
                }

                // Check emergency health if available
                if let Some(ref emergency) = monitor.emergency {
                    let healthy = matches!(
                        emergency.health_check().await,
                        Ok(DAHealthStatus::Healthy) | Ok(DAHealthStatus::Degraded)
                    );
                    monitor.emergency_healthy.store(healthy, Ordering::Relaxed);
                }

                // Determine current fallback state AFTER health checks
                let primary_healthy = monitor.is_primary_healthy();
                let currently_on_fallback = !primary_healthy
                    && (monitor.is_secondary_healthy() || monitor.is_emergency_healthy());

                // ═══════════════════════════════════════════════════════════════════
                // Recovery Transition Detection (14A.1A.39)
                // ═══════════════════════════════════════════════════════════════════
                //
                // Trigger ONLY when:
                // - Status BEFORE: Degraded (on fallback) OR Emergency
                // - Status AFTER: Primary recovering (healthy and should_recover)
                //
                // This happens when:
                // 1. Was on fallback (was_on_fallback = true)
                // 2. Primary is now healthy
                // 3. Recovery threshold is met (should_recover)
                // 4. Recovery is not already in progress

                let should_trigger_recovery = was_on_fallback
                    && primary_healthy
                    && monitor.should_recover()
                    && !monitor.is_recovery_in_progress();

                if should_trigger_recovery {
                    // Step 1: Log transition event (INFO level, eksplisit)
                    info!("🔄 Recovery transition detected: Fallback → Recovering");
                    info!("  Previous state: fallback_active={}", was_on_fallback);
                    info!("  Primary healthy: {}", primary_healthy);

                    // Step 2: Clear fallback reason
                    monitor.clear_fallback_reason();

                    // Step 3: Check if auto-reconcile is enabled
                    if monitor.is_auto_reconcile_enabled() {
                        // Get reconciliation engine reference
                        let engine_opt = monitor.reconciliation_engine.read().clone();

                        if let Some(engine) = engine_opt {
                            // Set recovery in progress flag BEFORE spawning
                            monitor.recovery_in_progress.store(true, Ordering::Relaxed);

                            info!("🔄 Starting automatic reconciliation...");

                            // Spawn background task for reconciliation (non-blocking)
                            let monitor_clone = Arc::clone(&monitor);
                            let engine_clone = Arc::clone(&engine);

                            tokio::spawn(async move {
                                // Step 4: Trigger ReconciliationEngine.reconcile()
                                // WAIT until reconcile completes (async await)
                                let report = engine_clone.reconcile().await;

                                // Step 5/6: Handle result
                                if report.success {
                                    info!("✅ Recovery reconciliation completed successfully");
                                    info!("  Blobs processed: {}", report.blobs_processed);
                                    info!("  Blobs reconciled: {}", report.blobs_reconciled);
                                    // Transition to Healthy is implicit (primary is already healthy)
                                } else {
                                    // Reconciliation failed - log error explicitly
                                    error!("❌ Recovery reconciliation failed");
                                    error!("  Blobs failed: {}", report.blobs_failed);
                                    for err in &report.errors {
                                        error!("  Error: {}", err);
                                    }
                                    // Status MUST NOT be Healthy if reconcile fails
                                    // Set fallback reason to indicate failed recovery
                                    monitor_clone.set_fallback_reason(
                                        format!("Recovery reconciliation failed: {} errors", report.errors.len())
                                    );
                                }

                                // Clear recovery in progress flag
                                monitor_clone.recovery_in_progress.store(false, Ordering::Relaxed);
                            });
                        } else {
                            warn!("⚠️ ReconciliationEngine not set, skipping auto-reconcile");
                        }
                    } else {
                        info!("ℹ️ Auto-reconcile disabled, skipping reconciliation");
                    }
                }

                // Update fallback tracking state for next cycle
                monitor.update_fallback_state(currently_on_fallback);

                // Update fallback reason when entering fallback
                if !was_on_fallback && currently_on_fallback {
                    if monitor.is_secondary_healthy() {
                        monitor.set_fallback_reason("Primary DA unhealthy, using secondary".to_string());
                    } else if monitor.is_emergency_healthy() {
                        monitor.set_fallback_reason("Primary DA unhealthy, using emergency".to_string());
                    }
                }

                tokio::time::sleep(interval).await;
            }
        })
    }
}

/// DA Router - Routes DA operations to primary, secondary, or emergency DA.
///
/// Thread-safe: All operations are safe to call from multiple threads.
/// This is the ONLY entry point for DA operations after startup.
pub struct DARouter {
    /// Primary DA layer (Celestia).
    primary: Arc<dyn DALayer>,
    /// Secondary DA layer (QuorumDA) - optional.
    secondary: Option<Arc<dyn DALayer>>,
    /// Emergency DA layer - optional.
    emergency: Option<Arc<dyn DALayer>>,
    /// Health monitor.
    health: Arc<DAHealthMonitor>,
    /// Configuration.
    #[allow(dead_code)]
    config: DARouterConfig,
    /// Metrics.
    metrics: DARouterMetrics,
    /// Current routing state.
    state: RwLock<RoutingState>,
}

impl DARouter {
    /// Create new DARouter.
    ///
    /// # Arguments
    ///
    /// * `primary` - Primary DA layer (required)
    /// * `secondary` - Secondary DA layer (optional)
    /// * `emergency` - Emergency DA layer (optional)
    /// * `health` - Health monitor
    /// * `config` - Router configuration
    /// * `metrics` - Router metrics
    pub fn new(
        primary: Arc<dyn DALayer>,
        secondary: Option<Arc<dyn DALayer>>,
        emergency: Option<Arc<dyn DALayer>>,
        health: Arc<DAHealthMonitor>,
        config: DARouterConfig,
        metrics: DARouterMetrics,
    ) -> Self {
        Self {
            primary,
            secondary,
            emergency,
            health,
            config,
            metrics,
            state: RwLock::new(RoutingState::Primary),
        }
    }

    /// Get current routing state.
    pub fn current_state(&self) -> RoutingState {
        *self.state.read()
    }

    /// Get metrics reference.
    pub fn router_metrics(&self) -> &DARouterMetrics {
        &self.metrics
    }

    /// Get health monitor reference.
    pub fn health_monitor(&self) -> &Arc<DAHealthMonitor> {
        &self.health
    }

    /// Select the appropriate DA layer based on health status.
    fn select_da(&self) -> (Arc<dyn DALayer>, RoutingState) {
        let current_state = *self.state.read();

        // If currently on primary
        if current_state == RoutingState::Primary {
            if self.health.is_primary_healthy() || !self.health.should_failover() {
                return (Arc::clone(&self.primary), RoutingState::Primary);
            }
            // Primary failed, try secondary
            if let Some(ref secondary) = self.secondary {
                if self.health.is_secondary_healthy() {
                    self.metrics.failover_count.fetch_add(1, Ordering::Relaxed);
                    *self.state.write() = RoutingState::Secondary;
                    warn!("⚠️ Failing over to secondary DA");
                    return (Arc::clone(secondary), RoutingState::Secondary);
                }
            }
            // Secondary unavailable, try emergency
            if let Some(ref emergency) = self.emergency {
                if self.health.is_emergency_healthy() {
                    self.metrics.failover_count.fetch_add(1, Ordering::Relaxed);
                    *self.state.write() = RoutingState::Emergency;
                    warn!("🚨 Failing over to emergency DA");
                    return (Arc::clone(emergency), RoutingState::Emergency);
                }
            }
            // No fallback available, still use primary
            return (Arc::clone(&self.primary), RoutingState::Primary);
        }

        // If currently on secondary, check if should recover to primary
        if current_state == RoutingState::Secondary {
            if self.health.is_primary_healthy() && self.health.should_recover() {
                self.metrics.recovery_count.fetch_add(1, Ordering::Relaxed);
                *self.state.write() = RoutingState::Primary;
                info!("✅ Recovered to primary DA");
                return (Arc::clone(&self.primary), RoutingState::Primary);
            }
            if let Some(ref secondary) = self.secondary {
                if self.health.is_secondary_healthy() {
                    return (Arc::clone(secondary), RoutingState::Secondary);
                }
            }
            // Secondary failed, try emergency
            if let Some(ref emergency) = self.emergency {
                if self.health.is_emergency_healthy() {
                    *self.state.write() = RoutingState::Emergency;
                    return (Arc::clone(emergency), RoutingState::Emergency);
                }
            }
            // Fallback to primary
            return (Arc::clone(&self.primary), RoutingState::Primary);
        }

        // If currently on emergency, check if should recover
        if self.health.is_primary_healthy() && self.health.should_recover() {
            self.metrics.recovery_count.fetch_add(1, Ordering::Relaxed);
            *self.state.write() = RoutingState::Primary;
            info!("✅ Recovered to primary DA from emergency");
            return (Arc::clone(&self.primary), RoutingState::Primary);
        }

        if let Some(ref secondary) = self.secondary {
            if self.health.is_secondary_healthy() {
                *self.state.write() = RoutingState::Secondary;
                return (Arc::clone(secondary), RoutingState::Secondary);
            }
        }

        if let Some(ref emergency) = self.emergency {
            return (Arc::clone(emergency), RoutingState::Emergency);
        }

        // No choice, use primary
        (Arc::clone(&self.primary), RoutingState::Primary)
    }

    /// Update metrics based on routing state.
    fn record_request(&self, state: RoutingState) {
        match state {
            RoutingState::Primary => {
                self.metrics.primary_requests.fetch_add(1, Ordering::Relaxed);
            }
            RoutingState::Secondary => {
                self.metrics.secondary_requests.fetch_add(1, Ordering::Relaxed);
            }
            RoutingState::Emergency => {
                self.metrics.emergency_requests.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

impl DALayer for DARouter {
    fn post_blob(
        &self,
        data: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<BlobRef, DAError>> + Send + '_>> {
        let (da, state) = self.select_da();
        self.record_request(state);
        // Copy data to owned Vec to avoid lifetime issues
        // (data's lifetime is different from &self's lifetime)
        let data_owned = data.to_vec();

        Box::pin(async move {
            da.post_blob(&data_owned).await
        })
    }

    fn get_blob(
        &self,
        ref_: &BlobRef,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, DAError>> + Send + '_>> {
        let (da, state) = self.select_da();
        self.record_request(state);
        let ref_clone = ref_.clone();

        Box::pin(async move {
            da.get_blob(&ref_clone).await
        })
    }

    fn subscribe_blobs(
        &self,
        from_height: Option<u64>,
    ) -> Pin<Box<dyn Future<Output = Result<BlobStream, DAError>> + Send + '_>> {
        let (da, state) = self.select_da();
        self.record_request(state);

        Box::pin(async move {
            da.subscribe_blobs(from_height).await
        })
    }

    fn health_check(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<DAHealthStatus, DAError>> + Send + '_>> {
        let current_state = self.current_state();
        let da = match current_state {
            RoutingState::Primary => Arc::clone(&self.primary),
            RoutingState::Secondary => {
                self.secondary.as_ref().map(Arc::clone).unwrap_or_else(|| Arc::clone(&self.primary))
            }
            RoutingState::Emergency => {
                self.emergency.as_ref().map(Arc::clone).unwrap_or_else(|| Arc::clone(&self.primary))
            }
        };

        Box::pin(async move {
            da.health_check().await
        })
    }

    fn metrics(&self) -> Option<DAMetricsSnapshot> {
        // Return metrics from current active DA
        let current_state = self.current_state();
        match current_state {
            RoutingState::Primary => self.primary.metrics(),
            RoutingState::Secondary => {
                self.secondary.as_ref().and_then(|s| s.metrics()).or_else(|| self.primary.metrics())
            }
            RoutingState::Emergency => {
                self.emergency.as_ref().and_then(|e| e.metrics()).or_else(|| self.primary.metrics())
            }
        }
    }
}

// Compile-time assertion that DARouter is Send + Sync
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<DARouter>();
};

// ════════════════════════════════════════════════════════════════════════════
// RECONCILIATION ENGINE (14A.1A.38)
// ════════════════════════════════════════════════════════════════════════════

/// Internal representation of a pending blob for reconciliation.
struct PendingBlobEntry {
    /// Blob reference ID (commitment hash as hex).
    blob_id: String,
    /// Source DA layer.
    source_da: String,
    /// Target DA layer for reconciliation.
    target_da: String,
    /// Timestamp when blob was stored (Unix ms).
    stored_at: u64,
    /// Number of reconciliation attempts.
    retry_count: u32,
    /// Last error message (if any).
    last_error: Option<String>,
    /// Blob data.
    #[allow(dead_code)]
    data: Vec<u8>,
}

/// Engine for reconciling blobs between primary and fallback DA layers.
///
/// Thread-safe: All operations are safe to call from multiple threads.
pub struct ReconciliationEngine {
    /// Pending blobs awaiting reconciliation.
    pending_blobs: RwLock<Vec<PendingBlobEntry>>,
    /// DA Router for posting blobs.
    da_router: Arc<DARouter>,
    /// Health monitor for checking DA status.
    health_monitor: Arc<DAHealthMonitor>,
    /// Configuration.
    config: ReconciliationConfig,
}

impl ReconciliationEngine {
    /// Create new reconciliation engine.
    pub fn new(
        da_router: Arc<DARouter>,
        health_monitor: Arc<DAHealthMonitor>,
        config: ReconciliationConfig,
    ) -> Self {
        Self {
            pending_blobs: RwLock::new(Vec::new()),
            da_router,
            health_monitor,
            config,
        }
    }

    /// Get count of pending blobs.
    pub fn pending_count(&self) -> u64 {
        self.pending_blobs.read().len() as u64
    }

    /// Get list of pending blob info (for HTTP API).
    pub fn get_pending_blobs(&self) -> Vec<PendingBlobInfo> {
        self.pending_blobs
            .read()
            .iter()
            .map(|entry| PendingBlobInfo {
                blob_id: entry.blob_id.clone(),
                source_da: entry.source_da.clone(),
                target_da: entry.target_da.clone(),
                stored_at: entry.stored_at,
                retry_count: entry.retry_count,
                last_error: entry.last_error.clone(),
            })
            .collect()
    }

    /// Add a blob to pending reconciliation queue.
    #[allow(dead_code)]
    pub fn add_pending_blob(
        &self,
        blob_id: String,
        source_da: String,
        target_da: String,
        data: Vec<u8>,
    ) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let entry = PendingBlobEntry {
            blob_id,
            source_da,
            target_da,
            stored_at: now_ms,
            retry_count: 0,
            last_error: None,
            data,
        };

        self.pending_blobs.write().push(entry);
    }

    /// Perform reconciliation of pending blobs.
    ///
    /// This is a synchronous operation that blocks until reconciliation completes.
    /// DOES NOT spawn background tasks.
    pub async fn reconcile(&self) -> ReconcileReport {
        let start = std::time::Instant::now();
        let mut blobs_processed: u64 = 0;
        let mut blobs_reconciled: u64 = 0;
        let mut blobs_failed: u64 = 0;
        let mut errors: Vec<String> = Vec::new();

        // Check if primary DA is healthy before attempting reconciliation
        if !self.health_monitor.is_primary_healthy() {
            return ReconcileReport {
                success: false,
                blobs_processed: 0,
                blobs_reconciled: 0,
                blobs_failed: 0,
                duration_ms: start.elapsed().as_millis() as u64,
                errors: vec!["Primary DA is not healthy, cannot reconcile".to_string()],
            };
        }

        // Take pending blobs for processing
        let pending: Vec<PendingBlobEntry> = {
            let mut guard = self.pending_blobs.write();
            let batch_size = self.config.batch_size.min(guard.len());
            if batch_size == 0 {
                return ReconcileReport {
                    success: true,
                    blobs_processed: 0,
                    blobs_reconciled: 0,
                    blobs_failed: 0,
                    duration_ms: start.elapsed().as_millis() as u64,
                    errors: Vec::new(),
                };
            }
            guard.drain(0..batch_size).collect()
        };

        // Process each pending blob
        for mut entry in pending {
            blobs_processed += 1;

            // Attempt to post blob to primary DA
            match self.da_router.post_blob(&entry.data).await {
                Ok(_blob_ref) => {
                    blobs_reconciled += 1;
                }
                Err(e) => {
                    blobs_failed += 1;
                    entry.retry_count += 1;
                    entry.last_error = Some(e.to_string());
                    errors.push(format!("Blob {}: {}", entry.blob_id, e));

                    // Re-queue if under max retries
                    if entry.retry_count < self.config.max_retries {
                        self.pending_blobs.write().push(entry);
                    } else {
                        errors.push(format!(
                            "Blob {} exceeded max retries ({})",
                            entry.blob_id, self.config.max_retries
                        ));
                    }
                }
            }
        }

        ReconcileReport {
            success: blobs_failed == 0,
            blobs_processed,
            blobs_reconciled,
            blobs_failed,
            duration_ms: start.elapsed().as_millis() as u64,
            errors,
        }
    }

    /// Verify state consistency between primary and fallback DA.
    ///
    /// This is a READ-ONLY operation that does not modify state.
    pub fn verify_state_consistency(&self) -> ConsistencyReport {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let pending = self.pending_blobs.read();
        let pending_count = pending.len() as u64;
        let mut details = Vec::new();

        // Check for blobs with high retry counts
        let high_retry_blobs: Vec<&PendingBlobEntry> = pending
            .iter()
            .filter(|e| e.retry_count >= 2)
            .collect();

        if !high_retry_blobs.is_empty() {
            details.push(format!(
                "{} blob(s) have high retry counts (>=2)",
                high_retry_blobs.len()
            ));
        }

        // Check for stale blobs (older than 5 minutes)
        let stale_threshold_ms = 5 * 60 * 1000; // 5 minutes
        let stale_blobs: Vec<&PendingBlobEntry> = pending
            .iter()
            .filter(|e| now_ms.saturating_sub(e.stored_at) > stale_threshold_ms)
            .collect();

        if !stale_blobs.is_empty() {
            details.push(format!(
                "{} blob(s) are stale (older than 5 minutes)",
                stale_blobs.len()
            ));
        }

        // Check primary/fallback health consistency
        let primary_healthy = self.health_monitor.is_primary_healthy();
        let fallback_active = self.health_monitor.is_fallback_active();

        if fallback_active && pending_count == 0 {
            // Fallback is active but no pending blobs - might have missed some
            details.push("Fallback DA active but no pending blobs - verify blob tracking".to_string());
        }

        if !primary_healthy && !fallback_active {
            details.push("Primary DA unhealthy and no fallback active - system degraded".to_string());
        }

        let inconsistencies_found = details.len() as u64;

        ConsistencyReport {
            is_consistent: inconsistencies_found == 0,
            items_verified: pending_count + 2, // pending blobs + health checks
            inconsistencies_found,
            details,
            verified_at: now_ms,
        }
    }
}

// Compile-time assertion that ReconciliationEngine is Send + Sync
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ReconciliationEngine>();
};

// ════════════════════════════════════════════════════════════════════════════
// CONFIGURATION
// ════════════════════════════════════════════════════════════════════════════

/// Coordinator configuration.
///
/// Includes primary DA, fallback DA, and reconciliation settings.
/// All fields are owned values - no references to environment.
#[derive(Debug, Clone)]
pub struct CoordinatorConfig {
    /// HTTP server host
    pub host: String,
    /// HTTP server port
    pub port: u16,
    /// Primary DA layer configuration (Celestia)
    pub da_config: DAConfig,
    /// Use mock DA for development
    pub use_mock_da: bool,

    // ─────────────────────────────────────────────────────────────────────────
    // Fallback DA Configuration (14A.1A.35)
    // ─────────────────────────────────────────────────────────────────────────

    /// Whether fallback DA is enabled
    pub enable_fallback: bool,
    /// Type of fallback DA
    pub fallback_da_type: FallbackDAType,
    /// Quorum DA configuration (required if fallback_da_type = Quorum)
    pub quorum_da_config: Option<QuorumDAConfig>,
    /// Emergency DA URL (required if fallback_da_type = Emergency)
    pub emergency_da_url: Option<String>,
    /// Reconciliation engine configuration
    pub reconciliation_config: ReconciliationConfig,
}

impl CoordinatorConfig {
    /// Load configuration from environment variables.
    ///
    /// # Environment Variables
    ///
    /// ## Primary DA
    /// - `DA_RPC_URL`, `DA_NAMESPACE`, `DA_AUTH_TOKEN`, etc.
    ///
    /// ## Fallback DA
    /// - `ENABLE_FALLBACK`: true/false (default: false)
    /// - `FALLBACK_DA_TYPE`: none, quorum, emergency
    /// - `QUORUM_VALIDATORS`, `QUORUM_THRESHOLD`, `QUORUM_SIGNATURE_TIMEOUT_MS`
    /// - `EMERGENCY_DA_URL`
    ///
    /// ## Reconciliation
    /// - `RECONCILE_BATCH_SIZE`, `RECONCILE_RETRY_DELAY_MS`, `RECONCILE_MAX_RETRIES`, `RECONCILE_PARALLEL`
    ///
    /// # Returns
    ///
    /// * `Ok(CoordinatorConfig)` - Configuration loaded successfully
    /// * `Err(String)` - Missing or invalid configuration
    pub fn from_env() -> Result<Self, String> {
        // ─────────────────────────────────────────────────────────────────────
        // Set default DA_NETWORK to mainnet if not specified
        // DSDN defaults to mainnet for production-first approach
        // ─────────────────────────────────────────────────────────────────────
        if std::env::var("DA_NETWORK").is_err() {
            std::env::set_var("DA_NETWORK", "mainnet");
        }

        // Check if we should use mock DA
        let use_mock_da = std::env::var("USE_MOCK_DA")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false);

        // Load DA config (required unless using mock)
        let da_config = if use_mock_da {
            DAConfig::default()
        } else {
            DAConfig::from_env().map_err(|e| format!("DA config error: {}", e))?
        };

        // Load HTTP server config
        let host = std::env::var("COORDINATOR_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
        let port: u16 = std::env::var("COORDINATOR_PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse()
            .map_err(|_| "COORDINATOR_PORT must be a valid port number")?;

        // ─────────────────────────────────────────────────────────────────────
        // Parse Fallback DA Configuration
        // ─────────────────────────────────────────────────────────────────────

        let enable_fallback = std::env::var("ENABLE_FALLBACK")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false);

        let fallback_da_type = std::env::var("FALLBACK_DA_TYPE")
            .map(|v| FallbackDAType::from_str(&v))
            .unwrap_or(Ok(FallbackDAType::None))?;

        // ─────────────────────────────────────────────────────────────────────
        // EARLY VALIDATION: Check enable_fallback vs type consistency FIRST
        // This must happen BEFORE parsing nested configs to avoid confusing errors
        // ─────────────────────────────────────────────────────────────────────

        if !enable_fallback && fallback_da_type != FallbackDAType::None {
            return Err(format!(
                "ENABLE_FALLBACK=false but FALLBACK_DA_TYPE={}. \
                 Set ENABLE_FALLBACK=true or FALLBACK_DA_TYPE=none",
                fallback_da_type
            ));
        }

        // Parse quorum config if type is Quorum (only if fallback enabled)
        let quorum_da_config = if fallback_da_type == FallbackDAType::Quorum {
            Some(QuorumDAConfig::from_env()?)
        } else {
            None
        };

        // Parse emergency URL if type is Emergency (only if fallback enabled)
        let emergency_da_url = if fallback_da_type == FallbackDAType::Emergency {
            let url = std::env::var("EMERGENCY_DA_URL")
                .map_err(|_| "EMERGENCY_DA_URL is required when FALLBACK_DA_TYPE=emergency")?;
            if url.is_empty() {
                return Err("EMERGENCY_DA_URL cannot be empty".to_string());
            }
            Some(url)
        } else {
            None
        };

        // ─────────────────────────────────────────────────────────────────────
        // Parse Reconciliation Configuration
        // ─────────────────────────────────────────────────────────────────────

        let reconciliation_config = Self::parse_reconciliation_config()?;

        // ─────────────────────────────────────────────────────────────────────
        // Validate Configuration Consistency
        // ─────────────────────────────────────────────────────────────────────

        Self::validate_fallback_config(
            enable_fallback,
            &fallback_da_type,
            &quorum_da_config,
            &emergency_da_url,
        )?;

        // ─────────────────────────────────────────────────────────────────────
        // Emit Mainnet Warning if Fallback Disabled
        // ─────────────────────────────────────────────────────────────────────

        if da_config.is_mainnet() && !enable_fallback {
            warn!(
                "⚠️ MAINNET WARNING: Fallback DA is disabled. \
                 If Celestia becomes unavailable, data operations will fail. \
                 Consider enabling fallback with ENABLE_FALLBACK=true"
            );
        }

        Ok(Self {
            host,
            port,
            da_config,
            use_mock_da,
            enable_fallback,
            fallback_da_type,
            quorum_da_config,
            emergency_da_url,
            reconciliation_config,
        })
    }

    /// Parse reconciliation configuration from environment.
    fn parse_reconciliation_config() -> Result<ReconciliationConfig, String> {
        let batch_size: usize = std::env::var("RECONCILE_BATCH_SIZE")
            .unwrap_or_else(|_| "10".to_string())
            .parse()
            .map_err(|_| "RECONCILE_BATCH_SIZE must be a valid positive number")?;

        if batch_size == 0 {
            return Err("RECONCILE_BATCH_SIZE must be at least 1".to_string());
        }

        let retry_delay_ms: u64 = std::env::var("RECONCILE_RETRY_DELAY_MS")
            .unwrap_or_else(|_| "1000".to_string())
            .parse()
            .map_err(|_| "RECONCILE_RETRY_DELAY_MS must be a valid number")?;

        let max_retries: u32 = std::env::var("RECONCILE_MAX_RETRIES")
            .unwrap_or_else(|_| "3".to_string())
            .parse()
            .map_err(|_| "RECONCILE_MAX_RETRIES must be a valid number")?;

        let parallel_reconcile = std::env::var("RECONCILE_PARALLEL")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false);

        Ok(ReconciliationConfig {
            batch_size,
            retry_delay_ms,
            max_retries,
            parallel_reconcile,
        })
    }

    /// Validate fallback configuration consistency.
    ///
    /// Rules:
    /// - If enable_fallback = false: type must be None (redundant - checked early in from_env)
    /// - If type = Quorum: quorum_da_config must be Some
    /// - If type = Emergency: emergency_da_url must be Some
    ///
    /// Note: The enable_fallback=false check is redundant here because from_env()
    /// performs early validation before parsing nested configs. Kept as safety net.
    fn validate_fallback_config(
        enable_fallback: bool,
        fallback_da_type: &FallbackDAType,
        quorum_da_config: &Option<QuorumDAConfig>,
        emergency_da_url: &Option<String>,
    ) -> Result<(), String> {
        if !enable_fallback {
            // Safety net: Early validation in from_env() already catches this case
            if *fallback_da_type != FallbackDAType::None {
                return Err(format!(
                    "ENABLE_FALLBACK=false but FALLBACK_DA_TYPE={}. \
                     Set ENABLE_FALLBACK=true or FALLBACK_DA_TYPE=none",
                    fallback_da_type
                ));
            }
            return Ok(());
        }

        // Fallback enabled - validate based on type
        match fallback_da_type {
            FallbackDAType::None => {
                // Type is None but fallback enabled - this is a warning case, not error
                // User might want to enable later
                warn!(
                    "ENABLE_FALLBACK=true but FALLBACK_DA_TYPE=none. \
                     Fallback is enabled but no fallback DA configured."
                );
            }
            FallbackDAType::Quorum => {
                if quorum_da_config.is_none() {
                    return Err(
                        "FALLBACK_DA_TYPE=quorum requires QUORUM_VALIDATORS to be set".to_string()
                    );
                }
            }
            FallbackDAType::Emergency => {
                if emergency_da_url.is_none() {
                    return Err(
                        "FALLBACK_DA_TYPE=emergency requires EMERGENCY_DA_URL to be set".to_string()
                    );
                }
            }
        }

        Ok(())
    }

    /// Validate configuration for production use.
    pub fn validate_for_production(&self) -> Result<(), String> {
        if !self.use_mock_da {
            self.da_config
                .validate_for_production()
                .map_err(|e| format!("Production validation failed: {}", e))?;
        }
        Ok(())
    }

    /// Check if fallback is fully configured and ready to use.
    #[must_use]
    pub fn is_fallback_ready(&self) -> bool {
        if !self.enable_fallback {
            return false;
        }
        match self.fallback_da_type {
            FallbackDAType::None => false,
            FallbackDAType::Quorum => self.quorum_da_config.is_some(),
            FallbackDAType::Emergency => self.emergency_da_url.is_some(),
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// APP STATE (14A.1A.36)
// ════════════════════════════════════════════════════════════════════════════

/// Application state shared across handlers.
///
/// Uses DARouter as the SOLE entry point for DA operations.
/// DAConsumer is NOT stored here because it contains a Stream
/// that is not Sync. The consumer runs as a separate background task.
struct AppState {
    /// Coordinator instance
    coordinator: Coordinator,
    /// DA Router - the ONLY DA entry point
    da_router: Arc<DARouter>,
    /// Health monitor handle (stored to keep it alive)
    #[allow(dead_code)]
    monitor_handle: Option<JoinHandle<()>>,
    /// Reconciliation engine for fallback blob sync (14A.1A.38)
    reconciliation_engine: Arc<ReconciliationEngine>,
}

impl AppState {
    /// Create new AppState with DARouter.
    fn new(
        coordinator: Coordinator,
        da_router: Arc<DARouter>,
        monitor_handle: Option<JoinHandle<()>>,
        reconciliation_engine: Arc<ReconciliationEngine>,
    ) -> Self {
        Self {
            coordinator,
            da_router,
            monitor_handle,
            reconciliation_engine,
        }
    }

    /// Get reference to DA layer via DARouter.
    fn da(&self) -> &DARouter {
        &self.da_router
    }

    /// Check if DA is available based on current routing state.
    fn is_da_available(&self) -> bool {
        self.da_router.health_monitor().is_primary_healthy()
            || self.da_router.health_monitor().is_secondary_healthy()
            || self.da_router.health_monitor().is_emergency_healthy()
    }

    /// Get current routing state.
    fn routing_state(&self) -> RoutingState {
        self.da_router.current_state()
    }

    /// Get reference to health monitor.
    fn health_monitor(&self) -> &Arc<DAHealthMonitor> {
        self.da_router.health_monitor()
    }

    /// Get reference to reconciliation engine.
    fn reconciliation_engine(&self) -> &Arc<ReconciliationEngine> {
        &self.reconciliation_engine
    }
}

// ════════════════════════════════════════════════════════════════════════════
// REQUEST/RESPONSE TYPES
// ════════════════════════════════════════════════════════════════════════════

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

/// Health response with optional metrics
#[derive(Serialize)]
struct HealthResponse {
    status: String,
    da_available: bool,
    da_health: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    metrics: Option<MetricsInfo>,
}

/// Metrics info for health endpoint
#[derive(Serialize)]
struct MetricsInfo {
    post_count: u64,
    get_count: u64,
    health_check_count: u64,
    error_count: u64,
    retry_count: u64,
    avg_post_latency_us: u64,
    avg_get_latency_us: u64,
}

// ════════════════════════════════════════════════════════════════════════════
// HTTP HANDLERS
// ════════════════════════════════════════════════════════════════════════════

async fn register_node(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterNodeReq>,
) -> Json<Value> {
    let info = NodeInfo {
        id: payload.id,
        zone: payload.zone,
        addr: payload.addr,
        capacity_gb: payload.capacity_gb.unwrap_or(100),
        meta: serde_json::json!({}),
    };
    state.coordinator.register_node(info);
    Json(json!({"ok": true}))
}

async fn list_nodes(State(state): State<Arc<AppState>>) -> Json<Value> {
    let nodes = state.coordinator.list_nodes();
    Json(json!(nodes))
}

async fn placement(
    Path(hash): Path<String>,
    Query(q): Query<PlacementQuery>,
    State(state): State<Arc<AppState>>,
) -> Json<Value> {
    let rf = q.rf.unwrap_or(3);
    let sel = state.coordinator.placement_for_hash(&hash, rf);
    Json(json!(sel))
}

async fn register_object(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterObjectReq>,
) -> Json<Value> {
    state.coordinator.register_object(payload.hash, payload.size);
    Json(json!({"ok": true}))
}

async fn get_object(
    Path(hash): Path<String>,
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<Value>) {
    match state.coordinator.get_object(&hash) {
        Some(o) => {
            let val = serde_json::to_value(o).unwrap_or_else(|_| json!({}));
            (StatusCode::OK, Json(val))
        }
        None => (StatusCode::NOT_FOUND, Json(json!({"error":"not found"}))),
    }
}

async fn mark_missing(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ReplicaReq>,
) -> Json<Value> {
    state.coordinator.mark_replica_missing(&payload.hash, &payload.node_id);
    Json(json!({"ok": true}))
}

async fn mark_healed(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ReplicaReq>,
) -> Json<Value> {
    state.coordinator.mark_replica_healed(&payload.hash, &payload.node_id);
    Json(json!({"ok": true}))
}

async fn schedule_workload(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<Workload>,
) -> (StatusCode, Json<Value>) {
    match state.coordinator.schedule(&payload) {
        Some(node_id) => (StatusCode::OK, Json(json!({ "node_id": node_id }))),
        None => (StatusCode::NOT_FOUND, Json(json!({ "error": "no suitable node" }))),
    }
}

/// Health check endpoint with DA status via DARouter
async fn health_check(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    let da_status = state.da().health_check().await;
    let da_healthy = matches!(da_status, Ok(DAHealthStatus::Healthy));
    let da_available = state.is_da_available();
    let routing_state = state.routing_state();

    let status = if da_healthy && da_available {
        format!("healthy (routing: {})", routing_state)
    } else if da_available {
        format!("degraded (routing: {})", routing_state)
    } else {
        "unavailable".to_string()
    };

    // Get metrics and convert to serializable struct
    let metrics = state.da().metrics().map(|m| MetricsInfo {
        post_count: m.post_count,
        get_count: m.get_count,
        health_check_count: m.health_check_count,
        error_count: m.error_count,
        retry_count: m.retry_count,
        avg_post_latency_us: m.avg_post_latency_us,
        avg_get_latency_us: m.avg_get_latency_us,
    });

    Json(HealthResponse {
        status,
        da_available,
        da_health: format!("{:?}", da_status),
        metrics,
    })
}

/// Readiness check - returns 200 only if fully operational
async fn ready_check(State(state): State<Arc<AppState>>) -> StatusCode {
    let da_status = state.da().health_check().await;
    if matches!(da_status, Ok(DAHealthStatus::Healthy)) && state.is_da_available() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

// ════════════════════════════════════════════════════════════════════════════
// FALLBACK HTTP HANDLERS (14A.1A.38)
// ════════════════════════════════════════════════════════════════════════════

/// GET /fallback/status - Returns current fallback status.
///
/// Response includes:
/// - current_status: DAStatus
/// - fallback_active: bool
/// - fallback_reason: Option<String>
/// - pending_reconcile_count: u64
/// - last_fallback_at: Option<u64>
async fn get_fallback_status(
    State(state): State<Arc<AppState>>,
) -> Json<FallbackStatusResponse> {
    let health = state.health_monitor();
    let reconcile = state.reconciliation_engine();

    let response = FallbackStatusResponse {
        current_status: health.current_da_status(),
        fallback_active: health.is_fallback_active(),
        fallback_reason: health.get_fallback_reason(),
        pending_reconcile_count: reconcile.pending_count(),
        last_fallback_at: health.get_last_fallback_at(),
    };

    Json(response)
}

/// GET /fallback/pending - Returns list of pending blobs awaiting reconciliation.
///
/// Does NOT return raw blob data, only metadata.
async fn get_pending_blobs(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<PendingBlobInfo>> {
    let reconcile = state.reconciliation_engine();
    Json(reconcile.get_pending_blobs())
}

/// POST /fallback/reconcile - Triggers manual reconciliation.
///
/// This endpoint:
/// - Calls ReconciliationEngine::reconcile()
/// - Does NOT spawn background tasks
/// - Returns ReconcileReport directly
///
/// Returns HTTP 500 if reconciliation fails critically.
async fn trigger_reconcile(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ReconcileReport>, (StatusCode, Json<Value>)> {
    let reconcile = state.reconciliation_engine();

    let report = reconcile.reconcile().await;

    // If reconciliation failed critically (not just individual blobs)
    if !report.success && report.blobs_processed == 0 && !report.errors.is_empty() {
        let error_msg = report.errors.first()
            .cloned()
            .unwrap_or_else(|| "Unknown reconciliation error".to_string());
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "reconciliation_failed",
                "message": error_msg,
                "report": report
            })),
        ));
    }

    Ok(Json(report))
}

/// GET /fallback/consistency - Verifies state consistency.
///
/// This is a READ-ONLY operation that does NOT modify state.
async fn get_consistency_report(
    State(state): State<Arc<AppState>>,
) -> Json<ConsistencyReport> {
    let reconcile = state.reconciliation_engine();
    Json(reconcile.verify_state_consistency())
}

// ════════════════════════════════════════════════════════════════════════════
// DA CONNECTION TEST
// ════════════════════════════════════════════════════════════════════════════

/// Test DA connection at startup.
///
/// Performs a health check with retry logic.
async fn test_da_connection(da: &dyn DALayer) -> Result<(), DAError> {
    let max_attempts = 3;
    let retry_delay = Duration::from_secs(2);

    for attempt in 1..=max_attempts {
        info!("Testing DA connection (attempt {}/{})", attempt, max_attempts);

        match da.health_check().await {
            Ok(DAHealthStatus::Healthy) => {
                info!("✅ DA connection healthy");
                return Ok(());
            }
            Ok(DAHealthStatus::Degraded) => {
                warn!("⚠️ DA connection degraded but functional");
                return Ok(());
            }
            Ok(DAHealthStatus::Unavailable) => {
                if attempt < max_attempts {
                    warn!(
                        "DA unavailable, retrying in {} seconds...",
                        retry_delay.as_secs()
                    );
                    tokio::time::sleep(retry_delay).await;
                } else {
                    return Err(DAError::Unavailable);
                }
            }
            Err(e) => {
                if attempt < max_attempts {
                    warn!("DA connection error: {}, retrying...", e);
                    tokio::time::sleep(retry_delay).await;
                } else {
                    return Err(e);
                }
            }
        }
    }

    Err(DAError::Unavailable)
}

// ════════════════════════════════════════════════════════════════════════════
// DA INITIALIZATION HELPERS (14A.1A.36)
// ════════════════════════════════════════════════════════════════════════════

/// Initialize secondary DA (QuorumDA) from config.
///
/// Returns None if not enabled or initialization fails (graceful).
fn initialize_secondary_da(config: &CoordinatorConfig) -> Option<Arc<dyn DALayer>> {
    if !config.is_fallback_ready() {
        return None;
    }

    if config.fallback_da_type != FallbackDAType::Quorum {
        return None;
    }

    let _quorum_config = match &config.quorum_da_config {
        Some(c) => c,
        None => {
            error!("❌ QuorumDA config missing despite type=Quorum");
            return None;
        }
    };

    // TODO: Replace with actual ValidatorQuorumDA when integrated
    // For now, use MockDA as placeholder
    info!("  📦 Initializing Secondary DA (QuorumDA placeholder)...");
    info!("  ✅ Secondary DA initialized (MockDA placeholder)");
    Some(Arc::new(MockDA::new()))
}

/// Initialize emergency DA from config.
///
/// Returns None if not enabled or initialization fails (graceful).
fn initialize_emergency_da(config: &CoordinatorConfig) -> Option<Arc<dyn DALayer>> {
    if !config.is_fallback_ready() {
        return None;
    }

    if config.fallback_da_type != FallbackDAType::Emergency {
        return None;
    }

    let _emergency_url = match &config.emergency_da_url {
        Some(url) => url,
        None => {
            error!("❌ Emergency DA URL missing despite type=Emergency");
            return None;
        }
    };

    // TODO: Replace with actual EmergencyDA when integrated
    // For now, use MockDA as placeholder
    info!("  📦 Initializing Emergency DA (placeholder)...");
    info!("  ✅ Emergency DA initialized (MockDA placeholder)");
    Some(Arc::new(MockDA::new()))
}

// ════════════════════════════════════════════════════════════════════════════
// MAIN (14A.1A.36)
// ════════════════════════════════════════════════════════════════════════════

#[tokio::main]
async fn main() {
    // ═══════════════════════════════════════════════════════════════════════
    // Step 0: Load environment from .env.mainnet (default) or custom env file
    // ═══════════════════════════════════════════════════════════════════════
    
    // Priority order for env file loading:
    // 1. DSDN_ENV_FILE environment variable (custom path)
    // 2. .env.mainnet (production default - DSDN defaults to mainnet)
    // 3. .env (fallback for development)
    let env_file = std::env::var("DSDN_ENV_FILE").unwrap_or_else(|_| {
        if std::path::Path::new(".env.mainnet").exists() {
            ".env.mainnet".to_string()
        } else if std::path::Path::new(".env").exists() {
            ".env".to_string()
        } else {
            ".env.mainnet".to_string() // Will fail gracefully if not exists
        }
    });
    
    match dotenvy::from_filename(&env_file) {
        Ok(path) => {
            // Will log after tracing is initialized
            std::env::set_var("_DSDN_LOADED_ENV_FILE", path.display().to_string());
        }
        Err(e) => {
            // Check if it's just file not found (acceptable) vs other errors
            if !matches!(e, dotenvy::Error::Io(_)) {
                eprintln!("⚠️  Warning: Failed to load {}: {}", env_file, e);
            }
            // Continue without env file - will use environment variables directly
        }
    }

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_target(false)
        .init();

    // Log which env file was loaded (if any)
    if let Ok(loaded_file) = std::env::var("_DSDN_LOADED_ENV_FILE") {
        info!("📁 Loaded configuration from: {}", loaded_file);
    }

    info!("═══════════════════════════════════════════════════════════════");
    info!("              DSDN Coordinator (Mainnet Ready)                  ");
    info!("           DARouter Integration (14A.1A.36)                     ");
    info!("═══════════════════════════════════════════════════════════════");

    // ═══════════════════════════════════════════════════════════════════════
    // Step 1: Load CoordinatorConfig (including fallback config)
    // ═══════════════════════════════════════════════════════════════════════

    let config = match CoordinatorConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            error!("Configuration error: {}", e);
            error!("");
            error!("Required environment variables:");
            error!("  DA_RPC_URL       - Celestia light node RPC endpoint");
            error!("  DA_NAMESPACE     - 58-character hex namespace");
            error!("  DA_AUTH_TOKEN    - Authentication token (required for mainnet)");
            error!("");
            error!("Optional (Primary DA):");
            error!("  DA_NETWORK       - Network identifier (default: mainnet, options: mocha, local)");
            error!("  DA_TIMEOUT_MS    - Operation timeout (default: 30000)");
            error!("  USE_MOCK_DA      - Use mock DA for development (default: false)");
            error!("");
            error!("Environment file loading (automatic):");
            error!("  DSDN_ENV_FILE    - Custom env file path (default: .env.mainnet)");
            error!("");
            error!("Optional (Fallback DA):");
            error!("  ENABLE_FALLBACK  - Enable fallback DA (default: false)");
            error!("  FALLBACK_DA_TYPE - Fallback type: none, quorum, emergency");
            error!("  QUORUM_VALIDATORS      - Comma-separated validator addresses");
            error!("  QUORUM_THRESHOLD       - Quorum percentage 1-100 (default: 67)");
            error!("  EMERGENCY_DA_URL       - Emergency DA endpoint URL");
            error!("");
            error!("Optional (Reconciliation):");
            error!("  RECONCILE_BATCH_SIZE    - Batch size (default: 10)");
            error!("  RECONCILE_MAX_RETRIES   - Max retries (default: 3)");
            error!("  RECONCILE_RETRY_DELAY_MS - Retry delay ms (default: 1000)");
            error!("  RECONCILE_PARALLEL      - Parallel mode (default: false)");
            error!("");
            error!("Optional (HTTP Server):");
            error!("  COORDINATOR_HOST - HTTP server host (default: 127.0.0.1)");
            error!("  COORDINATOR_PORT - HTTP server port (default: 8080)");
            std::process::exit(1);
        }
    };

    // Validate configuration for production
    if config.da_config.is_mainnet() {
        info!("🌐 Running in MAINNET mode");
        if let Err(e) = config.validate_for_production() {
            error!("Production validation failed: {}", e);
            std::process::exit(1);
        }
    } else {
        info!("🔧 Running in {} mode", config.da_config.network);
    }

    // Display configuration
    info!("DA Endpoint:  {}", config.da_config.rpc_url);
    info!("DA Network:   {}", config.da_config.network);
    info!("HTTP Server:  {}:{}", config.host, config.port);

    // Display fallback configuration
    if config.enable_fallback {
        info!("Fallback DA:  ENABLED (type: {})", config.fallback_da_type);
        if let Some(ref quorum) = config.quorum_da_config {
            info!("  Validators: {} configured", quorum.validators.len());
            info!("  Threshold:  {}%", quorum.quorum_threshold);
        }
        if let Some(ref url) = config.emergency_da_url {
            info!("  Emergency:  {}", url);
        }
    } else {
        info!("Fallback DA:  DISABLED");
    }

    // Display reconciliation config
    info!("Reconcile:    batch={}, retries={}, parallel={}",
        config.reconciliation_config.batch_size,
        config.reconciliation_config.max_retries,
        config.reconciliation_config.parallel_reconcile
    );

    info!("═══════════════════════════════════════════════════════════════");

    // ═══════════════════════════════════════════════════════════════════════
    // Step 2: Initialize PRIMARY DA (Celestia) - REQUIRED
    // ═══════════════════════════════════════════════════════════════════════

    info!("📦 Initializing Primary DA...");
    let primary_da: Arc<dyn DALayer> = if config.use_mock_da {
        info!("  Using MockDA for development");
        Arc::new(MockDA::new())
    } else {
        info!("  Connecting to Celestia DA...");
        match CelestiaDA::new(config.da_config.clone()) {
            Ok(celestia) => {
                info!("  ✅ Primary DA (Celestia) initialized");
                Arc::new(celestia)
            }
            Err(e) => {
                error!("❌ Failed to initialize Primary DA (Celestia): {}", e);
                error!("");
                error!("Troubleshooting:");
                error!("  1. Ensure Celestia light node is running and synced");
                error!("  2. Verify DA_RPC_URL is correct");
                error!("  3. Check DA_AUTH_TOKEN is valid");
                error!("  4. Verify network connectivity");
                std::process::exit(1);
            }
        }
    };

    // Test primary DA connection
    if let Err(e) = test_da_connection(primary_da.as_ref()).await {
        error!("❌ Primary DA connection test failed: {}", e);

        if config.da_config.network != "mainnet" {
            warn!("⚠️ Primary DA unavailable - will rely on fallback if configured");
        } else {
            error!("Cannot start coordinator on mainnet without Primary DA connection");
            std::process::exit(1);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Step 3: Initialize SECONDARY DA (QuorumDA) - if enabled
    // ═══════════════════════════════════════════════════════════════════════

    let secondary_da: Option<Arc<dyn DALayer>> = if config.enable_fallback
        && config.fallback_da_type == FallbackDAType::Quorum
    {
        match initialize_secondary_da(&config) {
            Some(da) => Some(da),
            None => {
                error!("❌ Failed to initialize Secondary DA (QuorumDA)");
                warn!("⚠️ Continuing without secondary fallback");
                None
            }
        }
    } else {
        if config.enable_fallback && config.fallback_da_type == FallbackDAType::Quorum {
            warn!("⚠️ QuorumDA fallback configured but not ready");
        }
        None
    };

    // ═══════════════════════════════════════════════════════════════════════
    // Step 4: Initialize EMERGENCY DA - if enabled
    // ═══════════════════════════════════════════════════════════════════════

    let emergency_da: Option<Arc<dyn DALayer>> = if config.enable_fallback
        && config.fallback_da_type == FallbackDAType::Emergency
    {
        match initialize_emergency_da(&config) {
            Some(da) => Some(da),
            None => {
                error!("❌ Failed to initialize Emergency DA");
                warn!("⚠️ Continuing without emergency fallback");
                None
            }
        }
    } else {
        if config.enable_fallback && config.fallback_da_type == FallbackDAType::Emergency {
            warn!("⚠️ Emergency DA fallback configured but not ready");
        }
        None
    };

    // ═══════════════════════════════════════════════════════════════════════
    // Step 5: Create DAHealthMonitor
    // ═══════════════════════════════════════════════════════════════════════

    info!("🏥 Creating DAHealthMonitor...");
    let router_config = DARouterConfig::default();
    let health_monitor = Arc::new(DAHealthMonitor::new(
        router_config.clone(),
        Arc::clone(&primary_da),
        secondary_da.clone(),
        emergency_da.clone(),
    ));
    info!("  ✅ DAHealthMonitor created");

    // ═══════════════════════════════════════════════════════════════════════
    // Step 6: Create DARouter (primary + optional fallback)
    // ═══════════════════════════════════════════════════════════════════════

    info!("🔀 Creating DARouter...");
    let router_metrics = DARouterMetrics::new();
    let da_router = Arc::new(DARouter::new(
        primary_da,
        secondary_da,
        emergency_da,
        Arc::clone(&health_monitor),
        router_config,
        router_metrics,
    ));

    let fallback_status = if health_monitor.is_secondary_healthy() {
        "secondary"
    } else if health_monitor.is_emergency_healthy() {
        "emergency"
    } else {
        "none"
    };
    info!("  ✅ DARouter created (fallback: {})", fallback_status);

    // ═══════════════════════════════════════════════════════════════════════
    // Step 7: Create ReconciliationEngine (14A.1A.38) - BEFORE monitoring starts
    // ═══════════════════════════════════════════════════════════════════════

    info!("🔄 Creating ReconciliationEngine...");
    let reconciliation_engine = Arc::new(ReconciliationEngine::new(
        Arc::clone(&da_router),
        Arc::clone(&health_monitor),
        config.reconciliation_config.clone(),
    ));
    info!("  ✅ ReconciliationEngine created");

    // ═══════════════════════════════════════════════════════════════════════
    // Step 7.5: Link ReconciliationEngine to DAHealthMonitor (14A.1A.39)
    // ═══════════════════════════════════════════════════════════════════════

    health_monitor.set_reconciliation_engine(Arc::clone(&reconciliation_engine));
    info!("  ✅ ReconciliationEngine linked to DAHealthMonitor for auto-recovery");

    // ═══════════════════════════════════════════════════════════════════════
    // Step 7.6: Start health monitoring loop
    // ═══════════════════════════════════════════════════════════════════════

    info!("🏥 Starting health monitoring...");
    let monitor_handle = health_monitor.start_monitoring();
    info!("  ✅ Health monitoring active (auto_reconcile={})", 
        health_monitor.is_auto_reconcile_enabled());

    // ═══════════════════════════════════════════════════════════════════════
    // Step 8: Inject DARouter to AppState
    // ═══════════════════════════════════════════════════════════════════════

    let coordinator = Coordinator::new();
    let state = Arc::new(AppState::new(
        coordinator,
        da_router,
        Some(monitor_handle),
        reconciliation_engine,
    ));
    info!("  ✅ AppState initialized with DARouter and ReconciliationEngine");

    // ═══════════════════════════════════════════════════════════════════════
    // Step 9: Run application runtime
    // ═══════════════════════════════════════════════════════════════════════

    // Build HTTP router
    let app = Router::new()
        .route("/register", post(register_node))
        .route("/nodes", get(list_nodes))
        .route("/placement/{hash}", get(placement))
        .route("/object/register", post(register_object))
        .route("/object/{hash}", get(get_object))
        .route("/replica/mark_missing", post(mark_missing))
        .route("/replica/mark_healed", post(mark_healed))
        .route("/schedule", post(schedule_workload))
        .route("/health", get(health_check))
        .route("/ready", get(ready_check))
        .merge(handlers::extended_routes())
        // Fallback HTTP endpoints (14A.1A.38)
        .route("/fallback/status", get(get_fallback_status))
        .route("/fallback/pending", get(get_pending_blobs))
        .route("/fallback/reconcile", post(trigger_reconcile))
        .route("/fallback/consistency", get(get_consistency_report))
        .with_state(state);

    // Start HTTP server
    let addr: SocketAddr = format!("{}:{}", config.host, config.port)
        .parse()
        .unwrap_or_else(|_| {
            error!("Invalid address: {}:{}", config.host, config.port);
            std::process::exit(1);
        });

    info!("");
    info!("═══════════════════════════════════════════════════════════════");
    info!("🚀 Coordinator listening on http://{}", addr);
    info!("   Primary DA:     ready");
    info!("   Health Monitor: active");
    info!("═══════════════════════════════════════════════════════════════");
    info!("");

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind to {}: {}", addr, e);
            std::process::exit(1);
        }
    };

    if let Err(e) = axum::serve(listener, app).await {
        error!("Server error: {}", e);
        std::process::exit(1);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// Mutex to serialize environment variable tests.
    /// Environment variables are process-global state, so concurrent tests
    /// that modify them will race and produce flaky results.
    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Helper to clear all fallback-related env vars
    fn clear_fallback_env_vars() {
        std::env::remove_var("ENABLE_FALLBACK");
        std::env::remove_var("FALLBACK_DA_TYPE");
        std::env::remove_var("QUORUM_VALIDATORS");
        std::env::remove_var("QUORUM_THRESHOLD");
        std::env::remove_var("QUORUM_SIGNATURE_TIMEOUT_MS");
        std::env::remove_var("EMERGENCY_DA_URL");
        std::env::remove_var("RECONCILE_BATCH_SIZE");
        std::env::remove_var("RECONCILE_RETRY_DELAY_MS");
        std::env::remove_var("RECONCILE_MAX_RETRIES");
        std::env::remove_var("RECONCILE_PARALLEL");
    }

    /// Helper to clear all env vars for clean test state
    fn clear_all_env_vars() {
        std::env::remove_var("DA_RPC_URL");
        std::env::remove_var("DA_NAMESPACE");
        std::env::remove_var("DA_AUTH_TOKEN");
        std::env::remove_var("DA_NETWORK");
        std::env::remove_var("COORDINATOR_HOST");
        std::env::remove_var("COORDINATOR_PORT");
        std::env::remove_var("USE_MOCK_DA");
        clear_fallback_env_vars();
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Basic Configuration Tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_config_mock_da() {
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_all_env_vars();

        std::env::set_var("USE_MOCK_DA", "true");

        let config = CoordinatorConfig::from_env().unwrap();

        assert!(config.use_mock_da);
        assert!(!config.enable_fallback);
        assert_eq!(config.fallback_da_type, FallbackDAType::None);

        clear_all_env_vars();
    }

    #[test]
    fn test_config_defaults() {
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_all_env_vars();

        std::env::set_var("USE_MOCK_DA", "true");

        let config = CoordinatorConfig::from_env().unwrap();

        assert_eq!(config.host, "127.0.0.1");
        assert_eq!(config.port, 8080);
        assert_eq!(config.reconciliation_config.batch_size, 10);
        assert_eq!(config.reconciliation_config.retry_delay_ms, 1000);
        assert_eq!(config.reconciliation_config.max_retries, 3);
        assert!(!config.reconciliation_config.parallel_reconcile);

        clear_all_env_vars();
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Fallback Configuration Tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_fallback_quorum() {
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_all_env_vars();

        std::env::set_var("USE_MOCK_DA", "true");
        std::env::set_var("ENABLE_FALLBACK", "true");
        std::env::set_var("FALLBACK_DA_TYPE", "quorum");
        std::env::set_var("QUORUM_VALIDATORS", "http://v1:8080,http://v2:8080");
        std::env::set_var("QUORUM_THRESHOLD", "75");

        let config = CoordinatorConfig::from_env().unwrap();

        assert!(config.enable_fallback);
        assert_eq!(config.fallback_da_type, FallbackDAType::Quorum);
        assert!(config.quorum_da_config.is_some());
        assert!(config.is_fallback_ready());

        let quorum = config.quorum_da_config.unwrap();
        assert_eq!(quorum.validators.len(), 2);
        assert_eq!(quorum.quorum_threshold, 75);

        clear_all_env_vars();
    }

    #[test]
    fn test_fallback_emergency() {
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_all_env_vars();

        std::env::set_var("USE_MOCK_DA", "true");
        std::env::set_var("ENABLE_FALLBACK", "true");
        std::env::set_var("FALLBACK_DA_TYPE", "emergency");
        std::env::set_var("EMERGENCY_DA_URL", "http://emergency-da:8080");

        let config = CoordinatorConfig::from_env().unwrap();

        assert!(config.enable_fallback);
        assert_eq!(config.fallback_da_type, FallbackDAType::Emergency);
        assert!(config.emergency_da_url.is_some());
        assert!(config.is_fallback_ready());
        assert_eq!(config.emergency_da_url.unwrap(), "http://emergency-da:8080");

        clear_all_env_vars();
    }

    #[test]
    fn test_fallback_quorum_missing_validators() {
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_all_env_vars();

        std::env::set_var("USE_MOCK_DA", "true");
        std::env::set_var("ENABLE_FALLBACK", "true");
        std::env::set_var("FALLBACK_DA_TYPE", "quorum");
        // Missing QUORUM_VALIDATORS

        let result = CoordinatorConfig::from_env();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("QUORUM_VALIDATORS"));

        clear_all_env_vars();
    }

    #[test]
    fn test_fallback_emergency_missing_url() {
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_all_env_vars();

        std::env::set_var("USE_MOCK_DA", "true");
        std::env::set_var("ENABLE_FALLBACK", "true");
        std::env::set_var("FALLBACK_DA_TYPE", "emergency");
        // Missing EMERGENCY_DA_URL

        let result = CoordinatorConfig::from_env();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("EMERGENCY_DA_URL"));

        clear_all_env_vars();
    }

    #[test]
    fn test_fallback_disabled_but_type_set() {
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_all_env_vars();

        std::env::set_var("USE_MOCK_DA", "true");
        std::env::set_var("ENABLE_FALLBACK", "false");
        std::env::set_var("FALLBACK_DA_TYPE", "quorum");

        let result = CoordinatorConfig::from_env();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("ENABLE_FALLBACK=false"));

        clear_all_env_vars();
    }

    #[test]
    fn test_fallback_invalid_type() {
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_all_env_vars();

        std::env::set_var("USE_MOCK_DA", "true");
        std::env::set_var("ENABLE_FALLBACK", "true");
        std::env::set_var("FALLBACK_DA_TYPE", "invalid_type");

        let result = CoordinatorConfig::from_env();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid FALLBACK_DA_TYPE"));

        clear_all_env_vars();
    }

    #[test]
    fn test_quorum_threshold_bounds() {
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_all_env_vars();

        std::env::set_var("USE_MOCK_DA", "true");
        std::env::set_var("ENABLE_FALLBACK", "true");
        std::env::set_var("FALLBACK_DA_TYPE", "quorum");
        std::env::set_var("QUORUM_VALIDATORS", "http://v1:8080");
        std::env::set_var("QUORUM_THRESHOLD", "0");

        let result = CoordinatorConfig::from_env();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("between 1 and 100"));

        std::env::set_var("QUORUM_THRESHOLD", "101");
        let result = CoordinatorConfig::from_env();
        assert!(result.is_err());

        clear_all_env_vars();
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Reconciliation Configuration Tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_reconciliation_config_custom() {
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_all_env_vars();

        std::env::set_var("USE_MOCK_DA", "true");
        std::env::set_var("RECONCILE_BATCH_SIZE", "25");
        std::env::set_var("RECONCILE_RETRY_DELAY_MS", "2000");
        std::env::set_var("RECONCILE_MAX_RETRIES", "5");
        std::env::set_var("RECONCILE_PARALLEL", "true");

        let config = CoordinatorConfig::from_env().unwrap();

        assert_eq!(config.reconciliation_config.batch_size, 25);
        assert_eq!(config.reconciliation_config.retry_delay_ms, 2000);
        assert_eq!(config.reconciliation_config.max_retries, 5);
        assert!(config.reconciliation_config.parallel_reconcile);

        clear_all_env_vars();
    }

    #[test]
    fn test_reconciliation_batch_size_zero() {
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_all_env_vars();

        std::env::set_var("USE_MOCK_DA", "true");
        std::env::set_var("RECONCILE_BATCH_SIZE", "0");

        let result = CoordinatorConfig::from_env();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("at least 1"));

        clear_all_env_vars();
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Type Tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_fallback_da_type_from_str() {
        assert_eq!(FallbackDAType::from_str("none").unwrap(), FallbackDAType::None);
        assert_eq!(FallbackDAType::from_str("NONE").unwrap(), FallbackDAType::None);
        assert_eq!(FallbackDAType::from_str("").unwrap(), FallbackDAType::None);
        assert_eq!(FallbackDAType::from_str("quorum").unwrap(), FallbackDAType::Quorum);
        assert_eq!(FallbackDAType::from_str("QUORUM").unwrap(), FallbackDAType::Quorum);
        assert_eq!(FallbackDAType::from_str("emergency").unwrap(), FallbackDAType::Emergency);
        assert_eq!(FallbackDAType::from_str("EMERGENCY").unwrap(), FallbackDAType::Emergency);
        assert!(FallbackDAType::from_str("invalid").is_err());
    }

    #[test]
    fn test_fallback_da_type_display() {
        assert_eq!(FallbackDAType::None.to_string(), "none");
        assert_eq!(FallbackDAType::Quorum.to_string(), "quorum");
        assert_eq!(FallbackDAType::Emergency.to_string(), "emergency");
    }

    #[test]
    fn test_is_fallback_ready() {
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_all_env_vars();

        // Not enabled
        std::env::set_var("USE_MOCK_DA", "true");
        let config = CoordinatorConfig::from_env().unwrap();
        assert!(!config.is_fallback_ready());

        // Enabled but type None
        clear_all_env_vars();
        std::env::set_var("USE_MOCK_DA", "true");
        std::env::set_var("ENABLE_FALLBACK", "true");
        std::env::set_var("FALLBACK_DA_TYPE", "none");
        let config = CoordinatorConfig::from_env().unwrap();
        assert!(!config.is_fallback_ready());

        clear_all_env_vars();
    }

    // ────────────────────────────────────────────────────────────────────────────
    // DARouter Tests (14A.1A.36)
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_da_router_config_default() {
        let config = DARouterConfig::default();
        assert_eq!(config.health_check_interval_ms, 5000);
        assert_eq!(config.failure_threshold, 3);
        assert_eq!(config.recovery_threshold, 2);
    }

    #[test]
    fn test_da_router_metrics_new() {
        let metrics = DARouterMetrics::new();
        assert_eq!(metrics.primary_requests.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.secondary_requests.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.emergency_requests.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.failover_count.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.recovery_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_routing_state_display() {
        assert_eq!(RoutingState::Primary.to_string(), "primary");
        assert_eq!(RoutingState::Secondary.to_string(), "secondary");
        assert_eq!(RoutingState::Emergency.to_string(), "emergency");
    }

    #[test]
    fn test_da_router_primary_only() {
        let primary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let config = DARouterConfig::default();
        let health = Arc::new(DAHealthMonitor::new(
            config.clone(),
            Arc::clone(&primary),
            None,
            None,
        ));
        let metrics = DARouterMetrics::new();

        let router = DARouter::new(
            primary,
            None,
            None,
            health,
            config,
            metrics,
        );

        assert_eq!(router.current_state(), RoutingState::Primary);
        assert!(!router.health_monitor().is_secondary_healthy());
        assert!(!router.health_monitor().is_emergency_healthy());
    }

    #[test]
    fn test_da_router_with_secondary() {
        let primary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let secondary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let config = DARouterConfig::default();
        let health = Arc::new(DAHealthMonitor::new(
            config.clone(),
            Arc::clone(&primary),
            Some(Arc::clone(&secondary)),
            None,
        ));
        let metrics = DARouterMetrics::new();

        let router = DARouter::new(
            primary,
            Some(secondary),
            None,
            health,
            config,
            metrics,
        );

        assert_eq!(router.current_state(), RoutingState::Primary);
        assert!(router.health_monitor().is_secondary_healthy());
        assert!(!router.health_monitor().is_emergency_healthy());
    }

    #[test]
    fn test_da_router_with_emergency() {
        let primary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let emergency: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let config = DARouterConfig::default();
        let health = Arc::new(DAHealthMonitor::new(
            config.clone(),
            Arc::clone(&primary),
            None,
            Some(Arc::clone(&emergency)),
        ));
        let metrics = DARouterMetrics::new();

        let router = DARouter::new(
            primary,
            None,
            Some(emergency),
            health,
            config,
            metrics,
        );

        assert_eq!(router.current_state(), RoutingState::Primary);
        assert!(!router.health_monitor().is_secondary_healthy());
        assert!(router.health_monitor().is_emergency_healthy());
    }

    #[test]
    fn test_da_health_monitor_initial_state() {
        let primary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let config = DARouterConfig::default();
        let health = DAHealthMonitor::new(
            config,
            primary,
            None,
            None,
        );

        assert!(health.is_primary_healthy());
        assert!(!health.is_secondary_healthy());
        assert!(!health.is_emergency_healthy());
        assert!(!health.should_failover());
        assert!(!health.should_recover());
        assert!(!health.is_shutdown());
    }

    #[test]
    fn test_da_health_monitor_update_health() {
        let primary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let config = DARouterConfig {
            health_check_interval_ms: 5000,
            failure_threshold: 3,
            recovery_threshold: 2,
            auto_reconcile_on_recovery: true,
        };
        let health = DAHealthMonitor::new(
            config,
            primary,
            None,
            None,
        );

        // Initially healthy
        assert!(health.is_primary_healthy());
        assert!(!health.should_failover());

        // Mark unhealthy 3 times
        health.update_primary_health(false);
        assert!(!health.is_primary_healthy());
        assert!(!health.should_failover()); // 1 failure

        health.update_primary_health(false);
        assert!(!health.should_failover()); // 2 failures

        health.update_primary_health(false);
        assert!(health.should_failover()); // 3 failures - threshold reached

        // Mark healthy again
        health.update_primary_health(true);
        assert!(health.is_primary_healthy());
        assert!(!health.should_failover()); // Failures reset

        // Need 2 successes to recover
        assert!(!health.should_recover()); // 1 success
        health.update_primary_health(true);
        assert!(health.should_recover()); // 2 successes
    }

    #[test]
    fn test_da_health_monitor_shutdown() {
        let primary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let config = DARouterConfig::default();
        let health = DAHealthMonitor::new(
            config,
            primary,
            None,
            None,
        );

        assert!(!health.is_shutdown());
        health.shutdown();
        assert!(health.is_shutdown());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // AppState Tests (14A.1A.36)
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_app_state_with_da_router() {
        let coordinator = Coordinator::new();
        let primary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let config = DARouterConfig::default();
        let health = Arc::new(DAHealthMonitor::new(
            config.clone(),
            Arc::clone(&primary),
            None,
            None,
        ));
        let metrics = DARouterMetrics::new();
        let da_router = Arc::new(DARouter::new(
            primary,
            None,
            None,
            Arc::clone(&health),
            config,
            metrics,
        ));

        let reconciliation_config = ReconciliationConfig {
            batch_size: 10,
            retry_delay_ms: 1000,
            max_retries: 3,
            parallel_reconcile: false,
        };
        let reconciliation_engine = Arc::new(ReconciliationEngine::new(
            Arc::clone(&da_router),
            Arc::clone(&health),
            reconciliation_config,
        ));

        let state = AppState::new(coordinator, da_router, None, reconciliation_engine);

        assert!(state.is_da_available());
        assert_eq!(state.routing_state(), RoutingState::Primary);
    }

    #[test]
    fn test_app_state_routing_state() {
        let coordinator = Coordinator::new();
        let primary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let secondary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let config = DARouterConfig::default();
        let health = Arc::new(DAHealthMonitor::new(
            config.clone(),
            Arc::clone(&primary),
            Some(Arc::clone(&secondary)),
            None,
        ));
        let metrics = DARouterMetrics::new();
        let da_router = Arc::new(DARouter::new(
            primary,
            Some(secondary),
            None,
            Arc::clone(&health),
            config,
            metrics,
        ));

        let reconciliation_config = ReconciliationConfig {
            batch_size: 10,
            retry_delay_ms: 1000,
            max_retries: 3,
            parallel_reconcile: false,
        };
        let reconciliation_engine = Arc::new(ReconciliationEngine::new(
            Arc::clone(&da_router),
            Arc::clone(&health),
            reconciliation_config,
        ));

        let state = AppState::new(coordinator, da_router, None, reconciliation_engine);

        // Initially on primary
        assert_eq!(state.routing_state(), RoutingState::Primary);
        assert!(state.is_da_available());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Integration Tests - Startup Scenarios (14A.1A.36)
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_startup_fallback_disabled_primary_only() {
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_all_env_vars();

        std::env::set_var("USE_MOCK_DA", "true");

        let config = CoordinatorConfig::from_env().unwrap();

        assert!(!config.enable_fallback);
        assert_eq!(config.fallback_da_type, FallbackDAType::None);
        assert!(!config.is_fallback_ready());

        // Simulate startup: primary only
        let primary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let router_config = DARouterConfig::default();
        let health = Arc::new(DAHealthMonitor::new(
            router_config.clone(),
            Arc::clone(&primary),
            None,
            None,
        ));
        let metrics = DARouterMetrics::new();
        let router = Arc::new(DARouter::new(
            primary,
            None, // No secondary
            None, // No emergency
            health,
            router_config,
            metrics,
        ));

        assert_eq!(router.current_state(), RoutingState::Primary);

        clear_all_env_vars();
    }

    #[test]
    fn test_startup_fallback_enabled_quorum() {
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_all_env_vars();

        std::env::set_var("USE_MOCK_DA", "true");
        std::env::set_var("ENABLE_FALLBACK", "true");
        std::env::set_var("FALLBACK_DA_TYPE", "quorum");
        std::env::set_var("QUORUM_VALIDATORS", "http://v1:8080,http://v2:8080");

        let config = CoordinatorConfig::from_env().unwrap();

        assert!(config.enable_fallback);
        assert_eq!(config.fallback_da_type, FallbackDAType::Quorum);
        assert!(config.is_fallback_ready());

        // Simulate startup: primary + secondary
        let primary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let secondary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let router_config = DARouterConfig::default();
        let health = Arc::new(DAHealthMonitor::new(
            router_config.clone(),
            Arc::clone(&primary),
            Some(Arc::clone(&secondary)),
            None,
        ));
        let metrics = DARouterMetrics::new();
        let router = Arc::new(DARouter::new(
            primary,
            Some(secondary),
            None,
            health,
            router_config,
            metrics,
        ));

        assert_eq!(router.current_state(), RoutingState::Primary);
        assert!(router.health_monitor().is_secondary_healthy());

        clear_all_env_vars();
    }

    #[test]
    fn test_startup_fallback_enabled_emergency() {
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_all_env_vars();

        std::env::set_var("USE_MOCK_DA", "true");
        std::env::set_var("ENABLE_FALLBACK", "true");
        std::env::set_var("FALLBACK_DA_TYPE", "emergency");
        std::env::set_var("EMERGENCY_DA_URL", "http://emergency:8080");

        let config = CoordinatorConfig::from_env().unwrap();

        assert!(config.enable_fallback);
        assert_eq!(config.fallback_da_type, FallbackDAType::Emergency);
        assert!(config.is_fallback_ready());

        // Simulate startup: primary + emergency
        let primary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let emergency: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let router_config = DARouterConfig::default();
        let health = Arc::new(DAHealthMonitor::new(
            router_config.clone(),
            Arc::clone(&primary),
            None,
            Some(Arc::clone(&emergency)),
        ));
        let metrics = DARouterMetrics::new();
        let router = Arc::new(DARouter::new(
            primary,
            None,
            Some(emergency),
            health,
            router_config,
            metrics,
        ));

        assert_eq!(router.current_state(), RoutingState::Primary);
        assert!(router.health_monitor().is_emergency_healthy());

        clear_all_env_vars();
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Fallback HTTP Endpoint Tests (14A.1A.38)
    // ────────────────────────────────────────────────────────────────────────────

    /// Helper to create test infrastructure for fallback endpoint tests.
    fn create_test_infrastructure() -> (
        Arc<DARouter>,
        Arc<DAHealthMonitor>,
        Arc<ReconciliationEngine>,
    ) {
        let primary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let secondary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let router_config = DARouterConfig::default();
        let health = Arc::new(DAHealthMonitor::new(
            router_config.clone(),
            Arc::clone(&primary),
            Some(Arc::clone(&secondary)),
            None,
        ));
        let metrics = DARouterMetrics::new();
        let router = Arc::new(DARouter::new(
            primary,
            Some(secondary),
            None,
            Arc::clone(&health),
            router_config,
            metrics,
        ));

        let reconciliation_config = ReconciliationConfig {
            batch_size: 10,
            retry_delay_ms: 1000,
            max_retries: 3,
            parallel_reconcile: false,
        };
        let reconcile = Arc::new(ReconciliationEngine::new(
            Arc::clone(&router),
            Arc::clone(&health),
            reconciliation_config,
        ));

        (router, health, reconcile)
    }

    #[test]
    fn test_da_status_primary_healthy() {
        let (_router, health, _reconcile) = create_test_infrastructure();
        assert_eq!(health.current_da_status(), DAStatus::PrimaryHealthy);
    }

    #[test]
    fn test_da_status_fallback_secondary() {
        let (_router, health, _reconcile) = create_test_infrastructure();
        
        // Simulate primary unhealthy
        health.update_primary_health(false);
        
        // Secondary should be healthy (from create_test_infrastructure)
        assert!(health.is_secondary_healthy());
        assert_eq!(health.current_da_status(), DAStatus::FallbackSecondary);
    }

    #[test]
    fn test_da_status_unavailable() {
        let primary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let router_config = DARouterConfig::default();
        let health = Arc::new(DAHealthMonitor::new(
            router_config.clone(),
            Arc::clone(&primary),
            None, // No secondary
            None, // No emergency
        ));
        
        // Simulate primary unhealthy
        health.update_primary_health(false);
        
        assert_eq!(health.current_da_status(), DAStatus::Unavailable);
    }

    #[test]
    fn test_fallback_active_detection() {
        let (_router, health, _reconcile) = create_test_infrastructure();
        
        // Initially primary is healthy
        assert!(!health.is_fallback_active());
        
        // Simulate primary unhealthy
        health.update_primary_health(false);
        
        // Now fallback should be active (secondary is healthy)
        assert!(health.is_fallback_active());
    }

    #[test]
    fn test_fallback_reason_tracking() {
        let (_router, health, _reconcile) = create_test_infrastructure();
        
        // Initially no reason
        assert!(health.get_fallback_reason().is_none());
        assert!(health.get_last_fallback_at().is_none());
        
        // Set fallback reason
        health.set_fallback_reason("Primary DA connection timeout".to_string());
        
        // Should have reason and timestamp
        assert_eq!(
            health.get_fallback_reason(),
            Some("Primary DA connection timeout".to_string())
        );
        assert!(health.get_last_fallback_at().is_some());
        
        // Clear reason
        health.clear_fallback_reason();
        assert!(health.get_fallback_reason().is_none());
        // Timestamp should still be present (historical)
        assert!(health.get_last_fallback_at().is_some());
    }

    #[test]
    fn test_reconciliation_engine_pending_count() {
        let (_router, _health, reconcile) = create_test_infrastructure();
        
        assert_eq!(reconcile.pending_count(), 0);
        
        // Add pending blob
        reconcile.add_pending_blob(
            "abc123".to_string(),
            "secondary".to_string(),
            "primary".to_string(),
            vec![1, 2, 3],
        );
        
        assert_eq!(reconcile.pending_count(), 1);
    }

    #[test]
    fn test_reconciliation_engine_get_pending_blobs() {
        let (_router, _health, reconcile) = create_test_infrastructure();
        
        assert!(reconcile.get_pending_blobs().is_empty());
        
        // Add pending blob
        reconcile.add_pending_blob(
            "abc123".to_string(),
            "secondary".to_string(),
            "primary".to_string(),
            vec![1, 2, 3],
        );
        
        let pending = reconcile.get_pending_blobs();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].blob_id, "abc123");
        assert_eq!(pending[0].source_da, "secondary");
        assert_eq!(pending[0].target_da, "primary");
        assert_eq!(pending[0].retry_count, 0);
        assert!(pending[0].last_error.is_none());
    }

    #[tokio::test]
    async fn test_reconciliation_engine_reconcile_empty() {
        let (_router, _health, reconcile) = create_test_infrastructure();
        
        let report = reconcile.reconcile().await;
        
        assert!(report.success);
        assert_eq!(report.blobs_processed, 0);
        assert_eq!(report.blobs_reconciled, 0);
        assert_eq!(report.blobs_failed, 0);
        assert!(report.errors.is_empty());
    }

    #[tokio::test]
    async fn test_reconciliation_engine_reconcile_with_blobs() {
        let (_router, _health, reconcile) = create_test_infrastructure();
        
        // Add pending blob
        reconcile.add_pending_blob(
            "blob1".to_string(),
            "secondary".to_string(),
            "primary".to_string(),
            vec![1, 2, 3, 4],
        );
        
        let report = reconcile.reconcile().await;
        
        // MockDA should succeed
        assert!(report.success);
        assert_eq!(report.blobs_processed, 1);
        assert_eq!(report.blobs_reconciled, 1);
        assert_eq!(report.blobs_failed, 0);
        
        // Pending count should be 0 now
        assert_eq!(reconcile.pending_count(), 0);
    }

    #[tokio::test]
    async fn test_reconciliation_engine_reconcile_primary_unhealthy() {
        let (_router, health, reconcile) = create_test_infrastructure();
        
        // Add pending blob
        reconcile.add_pending_blob(
            "blob1".to_string(),
            "secondary".to_string(),
            "primary".to_string(),
            vec![1, 2, 3, 4],
        );
        
        // Simulate primary unhealthy
        health.update_primary_health(false);
        
        let report = reconcile.reconcile().await;
        
        // Should fail because primary is not healthy
        assert!(!report.success);
        assert_eq!(report.blobs_processed, 0);
        assert!(!report.errors.is_empty());
        assert!(report.errors[0].contains("Primary DA is not healthy"));
        
        // Blob should still be pending
        assert_eq!(reconcile.pending_count(), 1);
    }

    #[test]
    fn test_consistency_report_empty() {
        let (_router, _health, reconcile) = create_test_infrastructure();
        
        let report = reconcile.verify_state_consistency();
        
        assert!(report.is_consistent);
        assert_eq!(report.items_verified, 2); // health checks only
        assert_eq!(report.inconsistencies_found, 0);
        assert!(report.details.is_empty());
        assert!(report.verified_at > 0);
    }

    #[test]
    fn test_consistency_report_with_fallback_active() {
        let (_router, health, reconcile) = create_test_infrastructure();
        
        // Simulate primary unhealthy (fallback active)
        health.update_primary_health(false);
        
        let report = reconcile.verify_state_consistency();
        
        // Should detect fallback active with no pending blobs
        assert!(!report.is_consistent);
        assert!(report.inconsistencies_found > 0);
        assert!(report.details.iter().any(|d| d.contains("Fallback DA active")));
    }

    #[test]
    fn test_fallback_status_response_fields() {
        let (_router, health, reconcile) = create_test_infrastructure();
        
        let response = FallbackStatusResponse {
            current_status: health.current_da_status(),
            fallback_active: health.is_fallback_active(),
            fallback_reason: health.get_fallback_reason(),
            pending_reconcile_count: reconcile.pending_count(),
            last_fallback_at: health.get_last_fallback_at(),
        };
        
        assert_eq!(response.current_status, DAStatus::PrimaryHealthy);
        assert!(!response.fallback_active);
        assert!(response.fallback_reason.is_none());
        assert_eq!(response.pending_reconcile_count, 0);
        assert!(response.last_fallback_at.is_none());
    }

    #[test]
    fn test_pending_blob_info_struct() {
        let info = PendingBlobInfo {
            blob_id: "test123".to_string(),
            source_da: "secondary".to_string(),
            target_da: "primary".to_string(),
            stored_at: 1234567890,
            retry_count: 2,
            last_error: Some("Connection timeout".to_string()),
        };
        
        assert_eq!(info.blob_id, "test123");
        assert_eq!(info.source_da, "secondary");
        assert_eq!(info.target_da, "primary");
        assert_eq!(info.stored_at, 1234567890);
        assert_eq!(info.retry_count, 2);
        assert_eq!(info.last_error, Some("Connection timeout".to_string()));
    }

    #[test]
    fn test_reconcile_report_struct() {
        let report = ReconcileReport {
            success: true,
            blobs_processed: 10,
            blobs_reconciled: 8,
            blobs_failed: 2,
            duration_ms: 1500,
            errors: vec!["Error 1".to_string(), "Error 2".to_string()],
        };
        
        assert!(report.success);
        assert_eq!(report.blobs_processed, 10);
        assert_eq!(report.blobs_reconciled, 8);
        assert_eq!(report.blobs_failed, 2);
        assert_eq!(report.duration_ms, 1500);
        assert_eq!(report.errors.len(), 2);
    }

    #[test]
    fn test_consistency_report_struct() {
        let report = ConsistencyReport {
            is_consistent: false,
            items_verified: 15,
            inconsistencies_found: 3,
            details: vec![
                "Detail 1".to_string(),
                "Detail 2".to_string(),
                "Detail 3".to_string(),
            ],
            verified_at: 1234567890,
        };
        
        assert!(!report.is_consistent);
        assert_eq!(report.items_verified, 15);
        assert_eq!(report.inconsistencies_found, 3);
        assert_eq!(report.details.len(), 3);
        assert_eq!(report.verified_at, 1234567890);
    }

    #[test]
    fn test_da_status_display() {
        assert_eq!(format!("{}", DAStatus::PrimaryHealthy), "primary_healthy");
        assert_eq!(format!("{}", DAStatus::PrimaryDegraded), "primary_degraded");
        assert_eq!(format!("{}", DAStatus::FallbackSecondary), "fallback_secondary");
        assert_eq!(format!("{}", DAStatus::FallbackEmergency), "fallback_emergency");
        assert_eq!(format!("{}", DAStatus::Unavailable), "unavailable");
    }

    #[test]
    fn test_reconciliation_engine_batch_size() {
        let primary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let secondary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let router_config = DARouterConfig::default();
        let health = Arc::new(DAHealthMonitor::new(
            router_config.clone(),
            Arc::clone(&primary),
            Some(Arc::clone(&secondary)),
            None,
        ));
        let metrics = DARouterMetrics::new();
        let router = Arc::new(DARouter::new(
            primary,
            Some(secondary),
            None,
            Arc::clone(&health),
            router_config,
            metrics,
        ));

        // Small batch size
        let reconciliation_config = ReconciliationConfig {
            batch_size: 2,
            retry_delay_ms: 1000,
            max_retries: 3,
            parallel_reconcile: false,
        };
        let reconcile = Arc::new(ReconciliationEngine::new(
            Arc::clone(&router),
            Arc::clone(&health),
            reconciliation_config,
        ));

        // Add 5 blobs
        for i in 0..5 {
            reconcile.add_pending_blob(
                format!("blob{}", i),
                "secondary".to_string(),
                "primary".to_string(),
                vec![i as u8],
            );
        }

        assert_eq!(reconcile.pending_count(), 5);
    }

    #[test]
    fn test_health_monitor_failure_count() {
        let primary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let router_config = DARouterConfig::default();
        let health = Arc::new(DAHealthMonitor::new(
            router_config,
            primary,
            None,
            None,
        ));

        // Initially 0 failures
        assert_eq!(health.failure_count(), 0);

        // Simulate failures
        health.update_primary_health(false);
        assert_eq!(health.failure_count(), 1);
        
        health.update_primary_health(false);
        assert_eq!(health.failure_count(), 2);

        // Recovery resets failures
        health.update_primary_health(true);
        assert_eq!(health.failure_count(), 0);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Auto-Reconciliation Tests (14A.1A.39)
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_auto_reconcile_config_default_enabled() {
        let config = DARouterConfig::default();
        assert!(config.auto_reconcile_on_recovery);
    }

    #[test]
    fn test_auto_reconcile_config_can_be_disabled() {
        let config = DARouterConfig {
            health_check_interval_ms: 5000,
            failure_threshold: 3,
            recovery_threshold: 2,
            auto_reconcile_on_recovery: false,
        };
        assert!(!config.auto_reconcile_on_recovery);
    }

    #[test]
    fn test_health_monitor_auto_reconcile_enabled() {
        let primary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let config = DARouterConfig::default();
        let health = Arc::new(DAHealthMonitor::new(
            config,
            primary,
            None,
            None,
        ));

        assert!(health.is_auto_reconcile_enabled());
    }

    #[test]
    fn test_health_monitor_auto_reconcile_disabled() {
        let primary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let config = DARouterConfig {
            health_check_interval_ms: 5000,
            failure_threshold: 3,
            recovery_threshold: 2,
            auto_reconcile_on_recovery: false,
        };
        let health = Arc::new(DAHealthMonitor::new(
            config,
            primary,
            None,
            None,
        ));

        assert!(!health.is_auto_reconcile_enabled());
    }

    #[test]
    fn test_health_monitor_recovery_in_progress_initially_false() {
        let primary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let config = DARouterConfig::default();
        let health = Arc::new(DAHealthMonitor::new(
            config,
            primary,
            None,
            None,
        ));

        assert!(!health.is_recovery_in_progress());
    }

    #[test]
    fn test_health_monitor_set_reconciliation_engine() {
        let primary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let secondary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let config = DARouterConfig::default();
        let health = Arc::new(DAHealthMonitor::new(
            config.clone(),
            Arc::clone(&primary),
            Some(Arc::clone(&secondary)),
            None,
        ));
        let metrics = DARouterMetrics::new();
        let router = Arc::new(DARouter::new(
            primary,
            Some(secondary),
            None,
            Arc::clone(&health),
            config,
            metrics,
        ));

        let reconciliation_config = ReconciliationConfig {
            batch_size: 10,
            retry_delay_ms: 1000,
            max_retries: 3,
            parallel_reconcile: false,
        };
        let reconcile = Arc::new(ReconciliationEngine::new(
            Arc::clone(&router),
            Arc::clone(&health),
            reconciliation_config,
        ));

        // Set reconciliation engine - should not panic
        health.set_reconciliation_engine(Arc::clone(&reconcile));

        // Verify state is correct after setting
        assert!(!health.is_recovery_in_progress());
        assert!(health.is_auto_reconcile_enabled());
    }

    #[test]
    fn test_health_monitor_was_on_fallback_tracking() {
        let primary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let secondary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let config = DARouterConfig::default();
        let health = Arc::new(DAHealthMonitor::new(
            config,
            primary,
            Some(secondary),
            None,
        ));

        // Initially was_on_fallback should be false (we start assuming primary healthy)
        assert!(!health.was_previously_on_fallback());

        // Update fallback state
        health.update_fallback_state(true);
        assert!(health.was_previously_on_fallback());

        health.update_fallback_state(false);
        assert!(!health.was_previously_on_fallback());
    }

    #[test]
    fn test_health_monitor_was_on_fallback_no_secondary() {
        let primary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let config = DARouterConfig::default();
        let health = Arc::new(DAHealthMonitor::new(
            config,
            primary,
            None,
            None,
        ));

        // Without secondary/emergency, initially was_on_fallback should be false
        assert!(!health.was_previously_on_fallback());
    }

    #[tokio::test]
    async fn test_auto_reconcile_triggered_on_recovery() {
        let primary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let secondary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let config = DARouterConfig {
            health_check_interval_ms: 5000,
            failure_threshold: 1,
            recovery_threshold: 1,
            auto_reconcile_on_recovery: true,
        };
        let health = Arc::new(DAHealthMonitor::new(
            config.clone(),
            Arc::clone(&primary),
            Some(Arc::clone(&secondary)),
            None,
        ));
        let metrics = DARouterMetrics::new();
        let router = Arc::new(DARouter::new(
            primary,
            Some(secondary),
            None,
            Arc::clone(&health),
            config,
            metrics,
        ));

        let reconciliation_config = ReconciliationConfig {
            batch_size: 10,
            retry_delay_ms: 1000,
            max_retries: 3,
            parallel_reconcile: false,
        };
        let reconcile = Arc::new(ReconciliationEngine::new(
            Arc::clone(&router),
            Arc::clone(&health),
            reconciliation_config,
        ));

        // Set reconciliation engine
        health.set_reconciliation_engine(Arc::clone(&reconcile));

        // Simulate being on fallback
        health.update_fallback_state(true);
        health.update_primary_health(false);

        // Now simulate primary recovery
        health.update_primary_health(true);
        health.update_primary_health(true); // Meet recovery threshold

        // Verify should_recover is true
        assert!(health.should_recover());

        // Verify was_on_fallback is still true (before update)
        assert!(health.was_previously_on_fallback());
    }

    #[tokio::test]
    async fn test_auto_reconcile_not_triggered_when_disabled() {
        let primary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let secondary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let config = DARouterConfig {
            health_check_interval_ms: 5000,
            failure_threshold: 1,
            recovery_threshold: 1,
            auto_reconcile_on_recovery: false, // Disabled
        };
        let health = Arc::new(DAHealthMonitor::new(
            config.clone(),
            Arc::clone(&primary),
            Some(Arc::clone(&secondary)),
            None,
        ));

        // Verify auto-reconcile is disabled
        assert!(!health.is_auto_reconcile_enabled());
    }

    #[tokio::test]
    async fn test_manual_reconcile_still_works() {
        let primary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let secondary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let config = DARouterConfig::default();
        let health = Arc::new(DAHealthMonitor::new(
            config.clone(),
            Arc::clone(&primary),
            Some(Arc::clone(&secondary)),
            None,
        ));
        let metrics = DARouterMetrics::new();
        let router = Arc::new(DARouter::new(
            primary,
            Some(secondary),
            None,
            Arc::clone(&health),
            config,
            metrics,
        ));

        let reconciliation_config = ReconciliationConfig {
            batch_size: 10,
            retry_delay_ms: 1000,
            max_retries: 3,
            parallel_reconcile: false,
        };
        let reconcile = Arc::new(ReconciliationEngine::new(
            Arc::clone(&router),
            Arc::clone(&health),
            reconciliation_config,
        ));

        // Manual reconcile should work
        let report = reconcile.reconcile().await;
        
        // Empty reconciliation should succeed
        assert!(report.success);
        assert_eq!(report.blobs_processed, 0);
    }

    #[tokio::test]
    async fn test_reconcile_once_per_transition() {
        let primary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let secondary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let config = DARouterConfig {
            health_check_interval_ms: 5000,
            failure_threshold: 1,
            recovery_threshold: 1,
            auto_reconcile_on_recovery: true,
        };
        let health = Arc::new(DAHealthMonitor::new(
            config,
            Arc::clone(&primary),
            Some(Arc::clone(&secondary)),
            None,
        ));

        // Verify recovery_in_progress blocks duplicate triggers
        health.recovery_in_progress.store(true, Ordering::Relaxed);
        assert!(health.is_recovery_in_progress());

        // Clear it
        health.recovery_in_progress.store(false, Ordering::Relaxed);
        assert!(!health.is_recovery_in_progress());
    }

    #[test]
    fn test_health_monitor_does_not_block_with_reconciliation_engine() {
        let primary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let secondary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let config = DARouterConfig::default();
        let health = Arc::new(DAHealthMonitor::new(
            config.clone(),
            Arc::clone(&primary),
            Some(Arc::clone(&secondary)),
            None,
        ));
        let metrics = DARouterMetrics::new();
        let router = Arc::new(DARouter::new(
            primary,
            Some(secondary),
            None,
            Arc::clone(&health),
            config,
            metrics,
        ));

        let reconciliation_config = ReconciliationConfig {
            batch_size: 10,
            retry_delay_ms: 1000,
            max_retries: 3,
            parallel_reconcile: false,
        };
        let reconcile = Arc::new(ReconciliationEngine::new(
            Arc::clone(&router),
            Arc::clone(&health),
            reconciliation_config,
        ));

        // Set reconciliation engine
        health.set_reconciliation_engine(reconcile);

        // Verify we can call methods without blocking
        assert!(health.is_auto_reconcile_enabled());
        assert!(!health.is_recovery_in_progress());
        assert!(!health.was_previously_on_fallback());
    }

    #[test]
    fn test_recovery_transition_detection_conditions() {
        let primary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let secondary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let config = DARouterConfig {
            health_check_interval_ms: 5000,
            failure_threshold: 2,
            recovery_threshold: 2,
            auto_reconcile_on_recovery: true,
        };
        let health = Arc::new(DAHealthMonitor::new(
            config,
            Arc::clone(&primary),
            Some(Arc::clone(&secondary)),
            None,
        ));

        // Condition 1: Was NOT on fallback - should NOT trigger
        health.update_fallback_state(false);
        health.update_primary_health(true);
        health.update_primary_health(true);
        assert!(!health.was_previously_on_fallback());
        // Recovery would NOT trigger because was_on_fallback = false

        // Condition 2: Was on fallback but primary not healthy - should NOT trigger
        health.update_fallback_state(true);
        health.update_primary_health(false);
        assert!(health.was_previously_on_fallback());
        assert!(!health.is_primary_healthy());
        // Recovery would NOT trigger because primary not healthy

        // Condition 3: Was on fallback, primary healthy, but threshold not met - should NOT trigger
        health.update_fallback_state(true);
        health.update_primary_health(true); // Only 1 success
        assert!(health.was_previously_on_fallback());
        assert!(health.is_primary_healthy());
        assert!(!health.should_recover()); // Need 2 successes
        // Recovery would NOT trigger because threshold not met

        // Condition 4: All conditions met - should trigger
        health.update_fallback_state(true);
        health.update_primary_health(true);
        health.update_primary_health(true); // 2 successes
        assert!(health.was_previously_on_fallback());
        assert!(health.is_primary_healthy());
        assert!(health.should_recover());
        assert!(!health.is_recovery_in_progress());
        // Recovery SHOULD trigger
    }

    #[test]
    fn test_recovery_in_progress_prevents_duplicate_trigger() {
        let primary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let secondary: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let config = DARouterConfig {
            health_check_interval_ms: 5000,
            failure_threshold: 1,
            recovery_threshold: 1,
            auto_reconcile_on_recovery: true,
        };
        let health = Arc::new(DAHealthMonitor::new(
            config,
            Arc::clone(&primary),
            Some(Arc::clone(&secondary)),
            None,
        ));

        // Setup: All conditions met for recovery
        health.update_fallback_state(true);
        health.update_primary_health(true);
        
        // But recovery is already in progress
        health.recovery_in_progress.store(true, Ordering::Relaxed);

        // Verify: should_trigger_recovery would be false
        let should_trigger = health.was_previously_on_fallback()
            && health.is_primary_healthy()
            && health.should_recover()
            && !health.is_recovery_in_progress();

        assert!(!should_trigger); // Blocked by recovery_in_progress
    }
}