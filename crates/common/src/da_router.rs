//! # DA Router (14A.1A.15 + 14A.1A.16)
//!
//! Abstraksi routing deterministik ke multiple Data Availability sources.
//!
//! ## Overview
//!
//! `DARouter` menyediakan mekanisme untuk routing operasi DA ke:
//! - Primary DA (Celestia) - selalu ada
//! - Secondary DA (Validator Quorum) - fallback level-1, opsional
//! - Emergency DA (Foundation) - fallback level-2, opsional
//!
//! ## Thread Safety
//!
//! Semua field menggunakan `Arc` untuk shared ownership yang thread-safe.
//! Struct ini adalah Send + Sync.
//!
//! ## Routing Logic (14A.1A.16)
//!
//! Routing berdasarkan `DAStatus` dari `DAHealthMonitor`:
//!
//! | Status | Route Target | Tag |
//! |--------|--------------|-----|
//! | Healthy | primary | None |
//! | Warning | primary (extended timeout) | None |
//! | Degraded | secondary | PendingReconcile |
//! | Emergency | emergency | EmergencyPending |
//! | Recovering | primary | PendingReconcile |
//!
//! ## Usage
//!
//! ```rust,ignore
//! let router = DARouter::new(primary, health, config, metrics)
//!     .with_fallbacks(Some(secondary), Some(emergency));
//!
//! // Routing berdasarkan health status
//! let blob_ref = router.post_blob(data).await?;
//! ```

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::da::{DALayer, DAError, DAHealthStatus, BlobRef, BlobStream, DAMetricsSnapshot};
use crate::da_health_monitor::{DAHealthMonitor, DAStatus};

// ════════════════════════════════════════════════════════════════════════════════
// DA STATUS PROVIDER TRAIT (14A.1A.16)
// ════════════════════════════════════════════════════════════════════════════════

/// Trait untuk menyediakan `DAStatus` ke `DARouter`.
///
/// Abstraksi ini memungkinkan:
/// - Penggunaan `DAHealthMonitor` di production
/// - Penggunaan mock di tests
///
/// ## Thread Safety
///
/// Trait ini memerlukan `Send + Sync` karena digunakan di multi-threaded context.
pub trait DAStatusProvider: Send + Sync {
    /// Mendapatkan status DA saat ini.
    ///
    /// # Returns
    ///
    /// `DAStatus` yang merepresentasikan kondisi kesehatan DA layer.
    fn get_da_status(&self) -> DAStatus;

    /// Memeriksa apakah fallback mode aktif.
    ///
    /// Fallback mode menentukan apakah read operations boleh
    /// mencoba secondary/emergency DA ketika primary gagal.
    ///
    /// # Returns
    ///
    /// - `true` jika fallback diizinkan
    /// - `false` jika hanya primary yang boleh digunakan
    fn is_fallback_active(&self) -> bool;
}

/// Implementasi `DAStatusProvider` untuk `DAHealthMonitor`.
///
/// Delegasi langsung ke methods yang sudah ada di `DAHealthMonitor`.
impl DAStatusProvider for DAHealthMonitor {
    fn get_da_status(&self) -> DAStatus {
        DAHealthMonitor::get_da_status(self)
    }

    fn is_fallback_active(&self) -> bool {
        DAHealthMonitor::is_fallback_active(self)
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// RECONCILE TAG (14A.1A.16)
// ════════════════════════════════════════════════════════════════════════════════

/// Tag untuk blob yang memerlukan reconciliation.
///
/// Digunakan untuk menandai blob yang ditulis ke fallback DA
/// dan perlu di-reconcile ke primary DA.
///
/// ## Variants
///
/// - `None`: Tidak memerlukan reconciliation (written to primary)
/// - `PendingReconcile`: Ditulis ke secondary, perlu sync ke primary
/// - `EmergencyPending`: Ditulis ke emergency, perlu sync ke primary
///
/// ## Thread Safety
///
/// Enum ini adalah Copy + Clone, thread-safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileTag {
    /// Blob ditulis ke primary, tidak perlu reconciliation.
    None,
    /// Blob ditulis ke secondary (Degraded/Recovering status).
    /// Harus di-reconcile ke primary ketika primary kembali Healthy.
    PendingReconcile,
    /// Blob ditulis ke emergency (Emergency status).
    /// Harus di-reconcile ke primary ketika primary kembali Healthy.
    EmergencyPending,
}

impl Default for ReconcileTag {
    fn default() -> Self {
        Self::None
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// DA ROUTER CONFIG
// ════════════════════════════════════════════════════════════════════════════════

/// Konfigurasi untuk DARouter.
///
/// Placeholder struct untuk tahap ini.
/// Akan diperluas di tahap berikutnya dengan:
/// - Routing policies
/// - Retry configurations
/// - Timeout settings
///
/// ## Thread Safety
///
/// Struct ini adalah plain data, Send + Sync safe.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DARouterConfig {
    /// Placeholder field untuk konfigurasi routing.
    ///
    /// Akan diganti dengan field aktual di tahap berikutnya.
    _placeholder: (),
}

impl DARouterConfig {
    /// Membuat konfigurasi default.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// DA ROUTER METRICS (14A.1A.16 + 14A.1A.17)
// ════════════════════════════════════════════════════════════════════════════════

/// Metrics internal untuk DARouter.
///
/// Melacak operasi per-path dengan atomic counters.
///
/// ## Tracked Metrics
///
/// - Post counts per path (primary, secondary, emergency)
/// - Read counts per path (primary, secondary, emergency)
/// - Error counts per path (post and read)
/// - Pending reconcile blob count
/// - Emergency pending blob count
/// - Fallback read count
///
/// ## Thread Safety
///
/// Semua counters menggunakan AtomicU64 untuk thread-safe updates.
/// Struct ini adalah Send + Sync.
#[derive(Debug)]
pub struct DARouterMetrics {
    // ── Post Metrics ──────────────────────────────────────────────────────────
    /// Jumlah post_blob sukses ke primary.
    primary_post_count: AtomicU64,
    /// Jumlah post_blob sukses ke secondary.
    secondary_post_count: AtomicU64,
    /// Jumlah post_blob sukses ke emergency.
    emergency_post_count: AtomicU64,
    /// Jumlah error post pada primary path.
    primary_error_count: AtomicU64,
    /// Jumlah error post pada secondary path.
    secondary_error_count: AtomicU64,
    /// Jumlah error post pada emergency path.
    emergency_error_count: AtomicU64,
    /// Jumlah blob dengan tag PendingReconcile.
    pending_reconcile_count: AtomicU64,
    /// Jumlah blob dengan tag EmergencyPending.
    emergency_pending_count: AtomicU64,

    // ── Read Metrics (14A.1A.17) ──────────────────────────────────────────────
    /// Jumlah get_blob sukses dari primary.
    primary_read_count: AtomicU64,
    /// Jumlah get_blob sukses dari secondary (fallback).
    secondary_read_count: AtomicU64,
    /// Jumlah get_blob sukses dari emergency (fallback).
    emergency_read_count: AtomicU64,
    /// Jumlah error get_blob dari primary.
    primary_read_error_count: AtomicU64,
    /// Jumlah error get_blob dari secondary.
    secondary_read_error_count: AtomicU64,
    /// Jumlah error get_blob dari emergency.
    emergency_read_error_count: AtomicU64,
    /// Jumlah total fallback reads (secondary + emergency).
    fallback_read_count: AtomicU64,
}

impl DARouterMetrics {
    /// Membuat metrics baru dengan semua counter di nol.
    #[must_use]
    pub fn new() -> Self {
        Self {
            // Post metrics
            primary_post_count: AtomicU64::new(0),
            secondary_post_count: AtomicU64::new(0),
            emergency_post_count: AtomicU64::new(0),
            primary_error_count: AtomicU64::new(0),
            secondary_error_count: AtomicU64::new(0),
            emergency_error_count: AtomicU64::new(0),
            pending_reconcile_count: AtomicU64::new(0),
            emergency_pending_count: AtomicU64::new(0),
            // Read metrics (14A.1A.17)
            primary_read_count: AtomicU64::new(0),
            secondary_read_count: AtomicU64::new(0),
            emergency_read_count: AtomicU64::new(0),
            primary_read_error_count: AtomicU64::new(0),
            secondary_read_error_count: AtomicU64::new(0),
            emergency_read_error_count: AtomicU64::new(0),
            fallback_read_count: AtomicU64::new(0),
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Post Record Methods
    // ────────────────────────────────────────────────────────────────────────────

    /// Record successful post to primary.
    #[inline]
    pub fn record_primary_post(&self) {
        self.primary_post_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Record successful post to secondary.
    #[inline]
    pub fn record_secondary_post(&self) {
        self.secondary_post_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Record successful post to emergency.
    #[inline]
    pub fn record_emergency_post(&self) {
        self.emergency_post_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Record error on primary post path.
    #[inline]
    pub fn record_primary_error(&self) {
        self.primary_error_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Record error on secondary post path.
    #[inline]
    pub fn record_secondary_error(&self) {
        self.secondary_error_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Record error on emergency post path.
    #[inline]
    pub fn record_emergency_error(&self) {
        self.emergency_error_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Record blob tagged as PendingReconcile.
    #[inline]
    pub fn record_pending_reconcile(&self) {
        self.pending_reconcile_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Record blob tagged as EmergencyPending.
    #[inline]
    pub fn record_emergency_pending(&self) {
        self.emergency_pending_count.fetch_add(1, Ordering::Relaxed);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Read Record Methods (14A.1A.17)
    // ────────────────────────────────────────────────────────────────────────────

    /// Record successful read from primary.
    #[inline]
    pub fn record_primary_read(&self) {
        self.primary_read_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Record successful read from secondary (fallback).
    #[inline]
    pub fn record_secondary_read(&self) {
        self.secondary_read_count.fetch_add(1, Ordering::Relaxed);
        self.fallback_read_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Record successful read from emergency (fallback).
    #[inline]
    pub fn record_emergency_read(&self) {
        self.emergency_read_count.fetch_add(1, Ordering::Relaxed);
        self.fallback_read_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Record error on primary read path.
    #[inline]
    pub fn record_primary_read_error(&self) {
        self.primary_read_error_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Record error on secondary read path.
    #[inline]
    pub fn record_secondary_read_error(&self) {
        self.secondary_read_error_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Record error on emergency read path.
    #[inline]
    pub fn record_emergency_read_error(&self) {
        self.emergency_read_error_count.fetch_add(1, Ordering::Relaxed);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Accessor Methods
    // ────────────────────────────────────────────────────────────────────────────

    /// Get primary post count.
    #[inline]
    #[must_use]
    pub fn primary_post_count(&self) -> u64 {
        self.primary_post_count.load(Ordering::Relaxed)
    }

    /// Get secondary post count.
    #[inline]
    #[must_use]
    pub fn secondary_post_count(&self) -> u64 {
        self.secondary_post_count.load(Ordering::Relaxed)
    }

    /// Get emergency post count.
    #[inline]
    #[must_use]
    pub fn emergency_post_count(&self) -> u64 {
        self.emergency_post_count.load(Ordering::Relaxed)
    }

    /// Get primary error count.
    #[inline]
    #[must_use]
    pub fn primary_error_count(&self) -> u64 {
        self.primary_error_count.load(Ordering::Relaxed)
    }

    /// Get secondary error count.
    #[inline]
    #[must_use]
    pub fn secondary_error_count(&self) -> u64 {
        self.secondary_error_count.load(Ordering::Relaxed)
    }

    /// Get emergency error count.
    #[inline]
    #[must_use]
    pub fn emergency_error_count(&self) -> u64 {
        self.emergency_error_count.load(Ordering::Relaxed)
    }

    /// Get pending reconcile count.
    #[inline]
    #[must_use]
    pub fn pending_reconcile_count(&self) -> u64 {
        self.pending_reconcile_count.load(Ordering::Relaxed)
    }

    /// Get emergency pending count.
    #[inline]
    #[must_use]
    pub fn emergency_pending_count(&self) -> u64 {
        self.emergency_pending_count.load(Ordering::Relaxed)
    }

    /// Get total post count across all paths.
    #[inline]
    #[must_use]
    pub fn total_post_count(&self) -> u64 {
        self.primary_post_count()
            + self.secondary_post_count()
            + self.emergency_post_count()
    }

    /// Get total error count across all paths (post errors only).
    #[inline]
    #[must_use]
    pub fn total_error_count(&self) -> u64 {
        self.primary_error_count()
            + self.secondary_error_count()
            + self.emergency_error_count()
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Read Accessor Methods (14A.1A.17)
    // ────────────────────────────────────────────────────────────────────────────

    /// Get primary read count.
    #[inline]
    #[must_use]
    pub fn primary_read_count(&self) -> u64 {
        self.primary_read_count.load(Ordering::Relaxed)
    }

    /// Get secondary read count.
    #[inline]
    #[must_use]
    pub fn secondary_read_count(&self) -> u64 {
        self.secondary_read_count.load(Ordering::Relaxed)
    }

    /// Get emergency read count.
    #[inline]
    #[must_use]
    pub fn emergency_read_count(&self) -> u64 {
        self.emergency_read_count.load(Ordering::Relaxed)
    }

    /// Get primary read error count.
    #[inline]
    #[must_use]
    pub fn primary_read_error_count(&self) -> u64 {
        self.primary_read_error_count.load(Ordering::Relaxed)
    }

    /// Get secondary read error count.
    #[inline]
    #[must_use]
    pub fn secondary_read_error_count(&self) -> u64 {
        self.secondary_read_error_count.load(Ordering::Relaxed)
    }

    /// Get emergency read error count.
    #[inline]
    #[must_use]
    pub fn emergency_read_error_count(&self) -> u64 {
        self.emergency_read_error_count.load(Ordering::Relaxed)
    }

    /// Get fallback read count (secondary + emergency).
    #[inline]
    #[must_use]
    pub fn fallback_read_count(&self) -> u64 {
        self.fallback_read_count.load(Ordering::Relaxed)
    }

    /// Get total read count across all paths.
    #[inline]
    #[must_use]
    pub fn total_read_count(&self) -> u64 {
        self.primary_read_count()
            + self.secondary_read_count()
            + self.emergency_read_count()
    }

    /// Get total read error count across all paths.
    #[inline]
    #[must_use]
    pub fn total_read_error_count(&self) -> u64 {
        self.primary_read_error_count()
            + self.secondary_read_error_count()
            + self.emergency_read_error_count()
    }
}

impl Default for DARouterMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for DARouterMetrics {
    fn clone(&self) -> Self {
        Self {
            // Post metrics
            primary_post_count: AtomicU64::new(self.primary_post_count.load(Ordering::Relaxed)),
            secondary_post_count: AtomicU64::new(self.secondary_post_count.load(Ordering::Relaxed)),
            emergency_post_count: AtomicU64::new(self.emergency_post_count.load(Ordering::Relaxed)),
            primary_error_count: AtomicU64::new(self.primary_error_count.load(Ordering::Relaxed)),
            secondary_error_count: AtomicU64::new(self.secondary_error_count.load(Ordering::Relaxed)),
            emergency_error_count: AtomicU64::new(self.emergency_error_count.load(Ordering::Relaxed)),
            pending_reconcile_count: AtomicU64::new(self.pending_reconcile_count.load(Ordering::Relaxed)),
            emergency_pending_count: AtomicU64::new(self.emergency_pending_count.load(Ordering::Relaxed)),
            // Read metrics (14A.1A.17)
            primary_read_count: AtomicU64::new(self.primary_read_count.load(Ordering::Relaxed)),
            secondary_read_count: AtomicU64::new(self.secondary_read_count.load(Ordering::Relaxed)),
            emergency_read_count: AtomicU64::new(self.emergency_read_count.load(Ordering::Relaxed)),
            primary_read_error_count: AtomicU64::new(self.primary_read_error_count.load(Ordering::Relaxed)),
            secondary_read_error_count: AtomicU64::new(self.secondary_read_error_count.load(Ordering::Relaxed)),
            emergency_read_error_count: AtomicU64::new(self.emergency_read_error_count.load(Ordering::Relaxed)),
            fallback_read_count: AtomicU64::new(self.fallback_read_count.load(Ordering::Relaxed)),
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// DA ROUTER STRUCT
// ════════════════════════════════════════════════════════════════════════════════

/// Router untuk multiple Data Availability sources.
///
/// `DARouter` menyediakan abstraksi routing deterministik ke:
/// - Primary DA (wajib) - Celestia sebagai DA utama
/// - Secondary DA (opsional) - Validator Quorum sebagai fallback level-1
/// - Emergency DA (opsional) - Foundation sebagai fallback level-2
///
/// ## Field Semantics
///
/// | Field | Type | Description |
/// |-------|------|-------------|
/// | `primary` | `Arc<dyn DALayer>` | DA utama, selalu ada |
/// | `secondary` | `Option<Arc<dyn DALayer>>` | Fallback level-1 |
/// | `emergency` | `Option<Arc<dyn DALayer>>` | Fallback level-2 |
/// | `health` | `Arc<dyn DAStatusProvider>` | Provider status kesehatan DA |
/// | `config` | `DARouterConfig` | Konfigurasi routing |
/// | `metrics` | `Arc<DARouterMetrics>` | Metrics internal |
///
/// ## Thread Safety
///
/// Semua field menggunakan `Arc` atau plain data.
/// Struct ini adalah Send + Sync.
///
/// ## Routing Logic (14A.1A.16)
///
/// Routing berdasarkan `DAStatus`:
/// - `Healthy`: Route ke primary
/// - `Warning`: Route ke primary (extended timeout via existing mechanism)
/// - `Degraded`: Route ke secondary, tag as PendingReconcile
/// - `Emergency`: Route ke emergency, tag as EmergencyPending
/// - `Recovering`: Route ke primary, mark for reconciliation
///
/// ## Example
///
/// ```rust,ignore
/// let primary: Arc<dyn DALayer> = Arc::new(CelestiaDA::new(...));
/// let health: Arc<dyn DAStatusProvider> = Arc::new(DAHealthMonitor::new(config));
/// let router_config = DARouterConfig::new();
/// let metrics = Arc::new(DARouterMetrics::new());
///
/// let router = DARouter::new(primary, health, router_config, metrics)
///     .with_fallbacks(Some(secondary_da), Some(emergency_da));
/// ```
pub struct DARouter {
    /// DA utama (Celestia).
    ///
    /// Selalu ada dan digunakan sebagai sumber utama.
    /// Fallback hanya diaktifkan jika primary tidak tersedia.
    primary: Arc<dyn DALayer>,

    /// DA fallback level-1 (Validator Quorum).
    ///
    /// Digunakan ketika primary dalam status Degraded.
    /// None jika tidak dikonfigurasi.
    secondary: Option<Arc<dyn DALayer>>,

    /// DA fallback level-2 (Foundation / Emergency).
    ///
    /// Digunakan ketika primary dalam status Emergency.
    /// None jika tidak dikonfigurasi.
    emergency: Option<Arc<dyn DALayer>>,

    /// Provider status kesehatan DA.
    ///
    /// Menggunakan trait `DAStatusProvider` untuk fleksibilitas:
    /// - Production: `DAHealthMonitor`
    /// - Testing: Mock implementations
    health: Arc<dyn DAStatusProvider>,

    /// Konfigurasi router.
    ///
    /// Menentukan policy routing dan behavior.
    config: DARouterConfig,

    /// Metrics internal router.
    ///
    /// Tracking request counts, errors, dan pending reconcile.
    /// Wrapped in Arc for interior mutability.
    metrics: Arc<DARouterMetrics>,
}

// ════════════════════════════════════════════════════════════════════════════════
// DA ROUTER IMPLEMENTATION
// ════════════════════════════════════════════════════════════════════════════════

impl DARouter {
    /// Membuat instance baru `DARouter`.
    ///
    /// # Arguments
    ///
    /// * `primary` - DA utama (wajib)
    /// * `health` - Provider status kesehatan DA
    /// * `config` - Konfigurasi router
    /// * `metrics` - Metrics internal (Arc wrapped)
    ///
    /// # Returns
    ///
    /// Instance baru dengan:
    /// - `primary` ter-set
    /// - `secondary` = None
    /// - `emergency` = None
    /// - `health`, `config`, `metrics` ter-set
    ///
    /// # Guarantees
    ///
    /// - Tidak panic
    /// - Tidak melakukan validasi kompleks
    /// - Tidak melakukan I/O
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let router = DARouter::new(primary, health, config, Arc::new(DARouterMetrics::new()));
    /// ```
    #[must_use]
    pub fn new(
        primary: Arc<dyn DALayer>,
        health: Arc<dyn DAStatusProvider>,
        config: DARouterConfig,
        metrics: Arc<DARouterMetrics>,
    ) -> Self {
        Self {
            primary,
            secondary: None,
            emergency: None,
            health,
            config,
            metrics,
        }
    }

    /// Meng-set fallback DA sources.
    ///
    /// Builder-style method untuk mengkonfigurasi secondary dan emergency DA.
    ///
    /// # Arguments
    ///
    /// * `secondary` - Fallback level-1 (Validator Quorum), atau None
    /// * `emergency` - Fallback level-2 (Foundation), atau None
    ///
    /// # Returns
    ///
    /// Self dengan fallbacks ter-set.
    ///
    /// # Behavior
    ///
    /// - Hanya mengubah `secondary` dan `emergency`
    /// - Tidak mengubah `primary`, `health`, `config`, atau `metrics`
    /// - Tidak melakukan cloning berlebihan (ownership transfer)
    ///
    /// # Guarantees
    ///
    /// - Tidak panic
    /// - Chainable (builder pattern)
    /// - Tidak melakukan I/O
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // Hanya secondary
    /// let router = router.with_fallbacks(Some(secondary), None);
    ///
    /// // Hanya emergency
    /// let router = router.with_fallbacks(None, Some(emergency));
    ///
    /// // Keduanya
    /// let router = router.with_fallbacks(Some(secondary), Some(emergency));
    /// ```
    #[must_use]
    pub fn with_fallbacks(
        mut self,
        secondary: Option<Arc<dyn DALayer>>,
        emergency: Option<Arc<dyn DALayer>>,
    ) -> Self {
        self.secondary = secondary;
        self.emergency = emergency;
        self
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Accessor Methods
    // ────────────────────────────────────────────────────────────────────────────

    /// Mendapatkan reference ke primary DA.
    #[inline]
    #[must_use]
    pub fn primary(&self) -> &Arc<dyn DALayer> {
        &self.primary
    }

    /// Mendapatkan reference ke secondary DA (jika ada).
    #[inline]
    #[must_use]
    pub fn secondary(&self) -> Option<&Arc<dyn DALayer>> {
        self.secondary.as_ref()
    }

    /// Mendapatkan reference ke emergency DA (jika ada).
    #[inline]
    #[must_use]
    pub fn emergency(&self) -> Option<&Arc<dyn DALayer>> {
        self.emergency.as_ref()
    }

    /// Mendapatkan reference ke health provider.
    #[inline]
    #[must_use]
    pub fn health(&self) -> &Arc<dyn DAStatusProvider> {
        &self.health
    }

    /// Mendapatkan reference ke konfigurasi.
    #[inline]
    #[must_use]
    pub fn config(&self) -> &DARouterConfig {
        &self.config
    }

    /// Mendapatkan reference ke metrics.
    #[inline]
    #[must_use]
    pub fn metrics(&self) -> &Arc<DARouterMetrics> {
        &self.metrics
    }

    /// Memeriksa apakah secondary DA tersedia.
    #[inline]
    #[must_use]
    pub fn has_secondary(&self) -> bool {
        self.secondary.is_some()
    }

    /// Memeriksa apakah emergency DA tersedia.
    #[inline]
    #[must_use]
    pub fn has_emergency(&self) -> bool {
        self.emergency.is_some()
    }

    /// Menghitung jumlah DA sources yang tersedia.
    ///
    /// # Returns
    ///
    /// Jumlah DA sources (1-3):
    /// - 1 = hanya primary
    /// - 2 = primary + secondary ATAU primary + emergency
    /// - 3 = primary + secondary + emergency
    #[must_use]
    pub fn available_sources_count(&self) -> usize {
        let mut count = 1; // primary selalu ada
        if self.secondary.is_some() {
            count += 1;
        }
        if self.emergency.is_some() {
            count += 1;
        }
        count
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Internal Routing Helpers (14A.1A.16)
    // ────────────────────────────────────────────────────────────────────────────

    /// Route post_blob ke primary dan record metrics.
    ///
    /// # Arguments
    ///
    /// * `data` - Blob data
    /// * `tag` - Reconciliation tag untuk tracking
    ///
    /// # Returns
    ///
    /// Result dari primary.post_blob()
    async fn route_to_primary(&self, data: &[u8], tag: ReconcileTag) -> Result<BlobRef, DAError> {
        let result = self.primary.post_blob(data).await;
        match &result {
            Ok(_) => {
                self.metrics.record_primary_post();
                match tag {
                    ReconcileTag::None => {}
                    ReconcileTag::PendingReconcile => {
                        self.metrics.record_pending_reconcile();
                    }
                    ReconcileTag::EmergencyPending => {
                        // Tidak seharusnya terjadi untuk primary path
                    }
                }
            }
            Err(_) => {
                self.metrics.record_primary_error();
            }
        }
        result
    }

    /// Route post_blob ke secondary dan record metrics.
    ///
    /// # Arguments
    ///
    /// * `data` - Blob data
    ///
    /// # Returns
    ///
    /// - `Ok(BlobRef)` jika berhasil, blob ditag PendingReconcile
    /// - `Err(DAError)` jika secondary tidak tersedia atau gagal
    async fn route_to_secondary(&self, data: &[u8]) -> Result<BlobRef, DAError> {
        let secondary = self.secondary.as_ref().ok_or_else(|| {
            self.metrics.record_secondary_error();
            DAError::Other(
                "secondary DA not available: DAStatus is Degraded but no secondary DA configured"
                    .to_string(),
            )
        })?;

        let result = secondary.post_blob(data).await;
        match &result {
            Ok(_) => {
                self.metrics.record_secondary_post();
                self.metrics.record_pending_reconcile();
            }
            Err(_) => {
                self.metrics.record_secondary_error();
            }
        }
        result
    }

    /// Route post_blob ke emergency dan record metrics.
    ///
    /// # Arguments
    ///
    /// * `data` - Blob data
    ///
    /// # Returns
    ///
    /// - `Ok(BlobRef)` jika berhasil, blob ditag EmergencyPending
    /// - `Err(DAError)` jika emergency tidak tersedia atau gagal
    async fn route_to_emergency(&self, data: &[u8]) -> Result<BlobRef, DAError> {
        let emergency = self.emergency.as_ref().ok_or_else(|| {
            self.metrics.record_emergency_error();
            DAError::Other(
                "emergency DA not available: DAStatus is Emergency but no emergency DA configured"
                    .to_string(),
            )
        })?;

        let result = emergency.post_blob(data).await;
        match &result {
            Ok(_) => {
                self.metrics.record_emergency_post();
                self.metrics.record_emergency_pending();
            }
            Err(_) => {
                self.metrics.record_emergency_error();
            }
        }
        result
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// DALAYER TRAIT IMPLEMENTATION (14A.1A.16)
// ════════════════════════════════════════════════════════════════════════════════

impl DALayer for DARouter {
    /// Route post_blob berdasarkan DAStatus dari health provider.
    ///
    /// # Routing Logic
    ///
    /// | DAStatus | Target | Tag |
    /// |----------|--------|-----|
    /// | Healthy | primary | None |
    /// | Warning | primary (extended timeout) | None |
    /// | Degraded | secondary | PendingReconcile |
    /// | Emergency | emergency | EmergencyPending |
    /// | Recovering | primary | PendingReconcile |
    ///
    /// # Arguments
    ///
    /// * `data` - Blob data untuk di-post
    ///
    /// # Returns
    ///
    /// * `Ok(BlobRef)` - Referensi ke blob yang di-post
    /// * `Err(DAError)` - Error dengan konteks path yang gagal
    ///
    /// # Errors
    ///
    /// - `DAError::Other` jika fallback tidak tersedia:
    ///   - Degraded + secondary None
    ///   - Emergency + emergency None
    /// - Error dari underlying DA layer jika operasi gagal
    ///
    /// # Metrics
    ///
    /// Method ini mencatat:
    /// - Post count per path (primary/secondary/emergency)
    /// - Error count per path
    /// - Pending reconcile count
    /// - Emergency pending count
    ///
    /// # Thread Safety
    ///
    /// Thread-safe, menggunakan atomic counters untuk metrics.
    fn post_blob(
        &self,
        data: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<BlobRef, DAError>> + Send + '_>> {
        // Clone data ke owned Vec untuk menghindari lifetime issues
        let data = data.to_vec();
        
        Box::pin(async move {
            // Gunakan get_da_status() yang mengembalikan DAStatus (5 variants)
            let status = self.health.get_da_status();

            match status {
                DAStatus::Healthy => {
                    // Route ke primary, tidak ada tag tambahan
                    self.route_to_primary(&data, ReconcileTag::None).await
                }
                DAStatus::Warning => {
                    // Route ke primary dengan extended timeout (via existing mechanism)
                    // Timeout dikonfigurasi di DAConfig level, bukan di router
                    self.route_to_primary(&data, ReconcileTag::None).await
                }
                DAStatus::Degraded => {
                    // Route ke secondary, tag sebagai PendingReconcile
                    // Error eksplisit jika secondary tidak tersedia
                    self.route_to_secondary(&data).await
                }
                DAStatus::Emergency => {
                    // Route ke emergency, tag sebagai EmergencyPending
                    // Error eksplisit jika emergency tidak tersedia
                    // TIDAK mencoba secondary atau primary
                    self.route_to_emergency(&data).await
                }
                DAStatus::Recovering => {
                    // Route ke primary, menandai untuk reconciliation
                    // Tidak menulis ke secondary/emergency
                    self.route_to_primary(&data, ReconcileTag::PendingReconcile).await
                }
            }
        })
    }

    /// Read blob with deterministic fallback routing (14A.1A.17).
    ///
    /// # Read Routing Logic
    ///
    /// 1. SELALU coba primary terlebih dahulu
    /// 2. Jika primary berhasil → return data, catat metrics
    /// 3. Jika primary gagal DAN fallback_active == true:
    ///    - Coba secondary jika tersedia
    ///    - Jika secondary gagal, coba emergency jika tersedia
    /// 4. Jika semua gagal → return error eksplisit
    ///
    /// # Arguments
    ///
    /// * `ref_` - Referensi ke blob yang akan dibaca
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - Data blob
    /// * `Err(DAError)` - Error dengan konteks semua path yang dicoba
    ///
    /// # Metrics
    ///
    /// Method ini mencatat:
    /// - Read count per path (primary/secondary/emergency)
    /// - Read error count per path
    /// - Fallback read count
    ///
    /// # Caching Hint
    ///
    /// Blob yang berhasil dibaca dicatat di metrics untuk analisis
    /// pola akses. Ini hanya hint, bukan cache aktif.
    ///
    /// # Thread Safety
    ///
    /// Thread-safe, menggunakan atomic counters untuk metrics.
    fn get_blob(
        &self,
        ref_: &BlobRef,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, DAError>> + Send + '_>> {
        // Clone BlobRef untuk ownership di async block
        let blob_ref = ref_.clone();
        
        Box::pin(async move {
            // Step 1: SELALU coba primary terlebih dahulu
            let primary_result = self.primary.get_blob(&blob_ref).await;
            
            match primary_result {
                Ok(data) => {
                    // Primary berhasil - catat metrics dan return
                    self.metrics.record_primary_read();
                    return Ok(data);
                }
                Err(primary_err) => {
                    // Primary gagal - catat error
                    self.metrics.record_primary_read_error();
                    
                    // Step 2: Evaluasi kondisi fallback
                    if !self.health.is_fallback_active() {
                        // Fallback tidak aktif - return error primary
                        return Err(DAError::Other(format!(
                            "get_blob failed: primary error ({}), fallback not active",
                            primary_err
                        )));
                    }
                    
                    // Step 3: Coba secondary jika tersedia
                    if let Some(ref secondary) = self.secondary {
                        let secondary_result = secondary.get_blob(&blob_ref).await;
                        
                        match secondary_result {
                            Ok(data) => {
                                // Secondary berhasil - catat metrics dan return
                                self.metrics.record_secondary_read();
                                return Ok(data);
                            }
                            Err(secondary_err) => {
                                // Secondary gagal - catat error dan lanjut ke emergency
                                self.metrics.record_secondary_read_error();
                                
                                // Step 4: Coba emergency jika tersedia
                                if let Some(ref emergency) = self.emergency {
                                    let emergency_result = emergency.get_blob(&blob_ref).await;
                                    
                                    match emergency_result {
                                        Ok(data) => {
                                            // Emergency berhasil - catat metrics dan return
                                            self.metrics.record_emergency_read();
                                            return Ok(data);
                                        }
                                        Err(emergency_err) => {
                                            // Semua gagal - catat error dan return
                                            self.metrics.record_emergency_read_error();
                                            return Err(DAError::Other(format!(
                                                "get_blob failed: all paths exhausted - \
                                                primary ({}), secondary ({}), emergency ({})",
                                                primary_err, secondary_err, emergency_err
                                            )));
                                        }
                                    }
                                } else {
                                    // Emergency tidak tersedia
                                    return Err(DAError::Other(format!(
                                        "get_blob failed: primary ({}) and secondary ({}) failed, \
                                        emergency not configured",
                                        primary_err, secondary_err
                                    )));
                                }
                            }
                        }
                    } else {
                        // Secondary tidak tersedia, coba emergency langsung
                        if let Some(ref emergency) = self.emergency {
                            let emergency_result = emergency.get_blob(&blob_ref).await;
                            
                            match emergency_result {
                                Ok(data) => {
                                    // Emergency berhasil - catat metrics dan return
                                    self.metrics.record_emergency_read();
                                    return Ok(data);
                                }
                                Err(emergency_err) => {
                                    // Emergency gagal
                                    self.metrics.record_emergency_read_error();
                                    return Err(DAError::Other(format!(
                                        "get_blob failed: primary ({}) failed, \
                                        secondary not configured, emergency ({})",
                                        primary_err, emergency_err
                                    )));
                                }
                            }
                        } else {
                            // Tidak ada fallback tersedia
                            return Err(DAError::Other(format!(
                                "get_blob failed: primary ({}), \
                                no fallback configured (secondary: none, emergency: none)",
                                primary_err
                            )));
                        }
                    }
                }
            }
        })
    }

    /// Delegate subscribe_blobs ke primary DA.
    fn subscribe_blobs(
        &self,
        from_height: Option<u64>,
    ) -> Pin<Box<dyn Future<Output = Result<BlobStream, DAError>> + Send + '_>> {
        self.primary.subscribe_blobs(from_height)
    }

    /// Delegate health_check ke primary DA.
    fn health_check(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<DAHealthStatus, DAError>> + Send + '_>> {
        self.primary.health_check()
    }

    /// Return metrics dari primary DA jika tersedia.
    fn metrics(&self) -> Option<DAMetricsSnapshot> {
        self.primary.metrics()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::da::DAConfig;
    use std::sync::atomic::AtomicUsize;
    use parking_lot::RwLock;

    // ────────────────────────────────────────────────────────────────────────────
    // Mock DAStatusProvider for Testing
    // ────────────────────────────────────────────────────────────────────────────

    /// Mock implementation of DAStatusProvider untuk testing.
    ///
    /// Memungkinkan kontrol langsung atas DAStatus dan fallback_active.
    struct MockStatusProvider {
        status: RwLock<DAStatus>,
        fallback_active: RwLock<bool>,
    }

    impl MockStatusProvider {
        fn new(status: DAStatus) -> Self {
            Self {
                status: RwLock::new(status),
                fallback_active: RwLock::new(false),
            }
        }

        fn with_fallback_active(status: DAStatus, fallback_active: bool) -> Self {
            Self {
                status: RwLock::new(status),
                fallback_active: RwLock::new(fallback_active),
            }
        }

        #[allow(dead_code)]
        fn set_status(&self, status: DAStatus) {
            *self.status.write() = status;
        }

        #[allow(dead_code)]
        fn set_fallback_active(&self, active: bool) {
            *self.fallback_active.write() = active;
        }
    }

    impl DAStatusProvider for MockStatusProvider {
        fn get_da_status(&self) -> DAStatus {
            *self.status.read()
        }

        fn is_fallback_active(&self) -> bool {
            *self.fallback_active.read()
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Test DALayer Mock with Call Tracking
    // ────────────────────────────────────────────────────────────────────────────

    /// Mock DALayer yang melacak panggilan dan dapat dikonfigurasi untuk sukses/gagal.
    struct TrackingMockDA {
        /// Nama untuk identifikasi (primary/secondary/emergency)
        name: String,
        /// Counter untuk post_blob calls
        post_count: AtomicUsize,
        /// Counter untuk get_blob calls
        get_count: AtomicUsize,
        /// Apakah post_blob harus return error
        should_fail: bool,
        /// Apakah get_blob harus return error
        should_fail_get: RwLock<bool>,
        /// Data yang akan dikembalikan oleh get_blob
        get_blob_data: RwLock<Vec<u8>>,
    }

    impl TrackingMockDA {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                post_count: AtomicUsize::new(0),
                get_count: AtomicUsize::new(0),
                should_fail: false,
                should_fail_get: RwLock::new(false),
                get_blob_data: RwLock::new(vec![0xDE, 0xAD, 0xBE, 0xEF]),
            }
        }

        fn failing(name: &str) -> Self {
            Self {
                name: name.to_string(),
                post_count: AtomicUsize::new(0),
                get_count: AtomicUsize::new(0),
                should_fail: true,
                should_fail_get: RwLock::new(true),
                get_blob_data: RwLock::new(Vec::new()),
            }
        }

        fn with_get_behavior(name: &str, should_fail_get: bool, data: Vec<u8>) -> Self {
            Self {
                name: name.to_string(),
                post_count: AtomicUsize::new(0),
                get_count: AtomicUsize::new(0),
                should_fail: false,
                should_fail_get: RwLock::new(should_fail_get),
                get_blob_data: RwLock::new(data),
            }
        }

        fn call_count(&self) -> usize {
            self.post_count.load(Ordering::SeqCst)
        }

        fn get_call_count(&self) -> usize {
            self.get_count.load(Ordering::SeqCst)
        }

        #[allow(dead_code)]
        fn set_should_fail_get(&self, fail: bool) {
            *self.should_fail_get.write() = fail;
        }
    }

    impl DALayer for TrackingMockDA {
        fn post_blob(
            &self,
            _data: &[u8],
        ) -> Pin<Box<dyn Future<Output = Result<BlobRef, DAError>> + Send + '_>> {
            self.post_count.fetch_add(1, Ordering::SeqCst);
            let should_fail = self.should_fail;
            let name = self.name.clone();

            Box::pin(async move {
                if should_fail {
                    Err(DAError::Other(format!("{}: simulated failure", name)))
                } else {
                    Ok(BlobRef {
                        height: 100,
                        commitment: [0xAA; 32],
                        namespace: [0xBB; 29],
                    })
                }
            })
        }

        fn get_blob(
            &self,
            _ref_: &BlobRef,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, DAError>> + Send + '_>> {
            self.get_count.fetch_add(1, Ordering::SeqCst);
            let should_fail = *self.should_fail_get.read();
            let name = self.name.clone();
            let data = self.get_blob_data.read().clone();

            Box::pin(async move {
                if should_fail {
                    Err(DAError::Other(format!("{}: get_blob simulated failure", name)))
                } else {
                    Ok(data)
                }
            })
        }

        fn subscribe_blobs(
            &self,
            _from_height: Option<u64>,
        ) -> Pin<Box<dyn Future<Output = Result<BlobStream, DAError>> + Send + '_>> {
            Box::pin(async { Err(DAError::Other("mock: not implemented".to_string())) })
        }

        fn health_check(
            &self,
        ) -> Pin<Box<dyn Future<Output = Result<DAHealthStatus, DAError>> + Send + '_>> {
            Box::pin(async { Ok(DAHealthStatus::Healthy) })
        }

        fn metrics(&self) -> Option<DAMetricsSnapshot> {
            None
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Simple Mock DALayer for structure tests
    // ────────────────────────────────────────────────────────────────────────────

    struct MockDALayer;

    impl MockDALayer {
        fn new() -> Self {
            Self
        }
    }

    impl DALayer for MockDALayer {
        fn post_blob(
            &self,
            _data: &[u8],
        ) -> Pin<Box<dyn Future<Output = Result<BlobRef, DAError>> + Send + '_>> {
            Box::pin(async { Err(DAError::Other("mock: not implemented".to_string())) })
        }

        fn get_blob(
            &self,
            _ref_: &BlobRef,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, DAError>> + Send + '_>> {
            Box::pin(async { Err(DAError::Other("mock: not implemented".to_string())) })
        }

        fn subscribe_blobs(
            &self,
            _from_height: Option<u64>,
        ) -> Pin<Box<dyn Future<Output = Result<BlobStream, DAError>> + Send + '_>> {
            Box::pin(async { Err(DAError::Other("mock: not implemented".to_string())) })
        }

        fn health_check(
            &self,
        ) -> Pin<Box<dyn Future<Output = Result<DAHealthStatus, DAError>> + Send + '_>> {
            Box::pin(async { Ok(DAHealthStatus::Healthy) })
        }

        fn metrics(&self) -> Option<DAMetricsSnapshot> {
            None
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Helper functions
    // ────────────────────────────────────────────────────────────────────────────

    fn create_mock_da() -> Arc<dyn DALayer> {
        Arc::new(MockDALayer::new())
    }

    fn create_tracking_mock(name: &str) -> Arc<TrackingMockDA> {
        Arc::new(TrackingMockDA::new(name))
    }

    fn create_failing_mock(name: &str) -> Arc<TrackingMockDA> {
        Arc::new(TrackingMockDA::failing(name))
    }

    fn create_mock_with_get_behavior(name: &str, should_fail: bool, data: Vec<u8>) -> Arc<TrackingMockDA> {
        Arc::new(TrackingMockDA::with_get_behavior(name, should_fail, data))
    }

    fn create_health_monitor() -> Arc<dyn DAStatusProvider> {
        let config = DAConfig::default();
        Arc::new(DAHealthMonitor::new(config))
    }

    fn create_mock_status_provider(status: DAStatus) -> Arc<dyn DAStatusProvider> {
        Arc::new(MockStatusProvider::new(status))
    }

    fn create_mock_status_provider_with_fallback(status: DAStatus, fallback_active: bool) -> Arc<dyn DAStatusProvider> {
        Arc::new(MockStatusProvider::with_fallback_active(status, fallback_active))
    }

    fn create_test_blob_ref() -> BlobRef {
        BlobRef {
            height: 100,
            commitment: [0xAA; 32],
            namespace: [0xBB; 29],
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // ReconcileTag tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_reconcile_tag_default() {
        let tag = ReconcileTag::default();
        assert_eq!(tag, ReconcileTag::None);
    }

    #[test]
    fn test_reconcile_tag_variants() {
        let none = ReconcileTag::None;
        let pending = ReconcileTag::PendingReconcile;
        let emergency = ReconcileTag::EmergencyPending;

        assert_ne!(none, pending);
        assert_ne!(pending, emergency);
        assert_ne!(none, emergency);
    }

    #[test]
    fn test_reconcile_tag_clone() {
        let tag = ReconcileTag::PendingReconcile;
        let cloned = tag;
        assert_eq!(tag, cloned);
    }

    #[test]
    fn test_reconcile_tag_debug() {
        let tag = ReconcileTag::EmergencyPending;
        let debug_str = format!("{:?}", tag);
        assert!(debug_str.contains("EmergencyPending"));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // DARouterMetrics tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_router_metrics_new() {
        let metrics = DARouterMetrics::new();
        assert_eq!(metrics.primary_post_count(), 0);
        assert_eq!(metrics.secondary_post_count(), 0);
        assert_eq!(metrics.emergency_post_count(), 0);
        assert_eq!(metrics.primary_error_count(), 0);
        assert_eq!(metrics.secondary_error_count(), 0);
        assert_eq!(metrics.emergency_error_count(), 0);
        assert_eq!(metrics.pending_reconcile_count(), 0);
        assert_eq!(metrics.emergency_pending_count(), 0);
    }

    #[test]
    fn test_router_metrics_record_primary() {
        let metrics = DARouterMetrics::new();
        metrics.record_primary_post();
        metrics.record_primary_post();
        assert_eq!(metrics.primary_post_count(), 2);
    }

    #[test]
    fn test_router_metrics_record_secondary() {
        let metrics = DARouterMetrics::new();
        metrics.record_secondary_post();
        assert_eq!(metrics.secondary_post_count(), 1);
    }

    #[test]
    fn test_router_metrics_record_emergency() {
        let metrics = DARouterMetrics::new();
        metrics.record_emergency_post();
        assert_eq!(metrics.emergency_post_count(), 1);
    }

    #[test]
    fn test_router_metrics_record_errors() {
        let metrics = DARouterMetrics::new();
        metrics.record_primary_error();
        metrics.record_secondary_error();
        metrics.record_emergency_error();
        assert_eq!(metrics.primary_error_count(), 1);
        assert_eq!(metrics.secondary_error_count(), 1);
        assert_eq!(metrics.emergency_error_count(), 1);
        assert_eq!(metrics.total_error_count(), 3);
    }

    #[test]
    fn test_router_metrics_record_pending_reconcile() {
        let metrics = DARouterMetrics::new();
        metrics.record_pending_reconcile();
        metrics.record_pending_reconcile();
        assert_eq!(metrics.pending_reconcile_count(), 2);
    }

    #[test]
    fn test_router_metrics_record_emergency_pending() {
        let metrics = DARouterMetrics::new();
        metrics.record_emergency_pending();
        assert_eq!(metrics.emergency_pending_count(), 1);
    }

    #[test]
    fn test_router_metrics_total_counts() {
        let metrics = DARouterMetrics::new();
        metrics.record_primary_post();
        metrics.record_secondary_post();
        metrics.record_emergency_post();
        assert_eq!(metrics.total_post_count(), 3);
    }

    #[test]
    fn test_router_metrics_clone() {
        let metrics = DARouterMetrics::new();
        metrics.record_primary_post();
        metrics.record_pending_reconcile();

        let cloned = metrics.clone();
        assert_eq!(cloned.primary_post_count(), 1);
        assert_eq!(cloned.pending_reconcile_count(), 1);
    }

    #[test]
    fn test_router_metrics_debug() {
        let metrics = DARouterMetrics::new();
        let debug_str = format!("{:?}", metrics);
        assert!(debug_str.contains("DARouterMetrics"));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // DARouterConfig tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_router_config_new() {
        let config = DARouterConfig::new();
        assert_eq!(config, DARouterConfig::default());
    }

    #[test]
    fn test_router_config_clone() {
        let config = DARouterConfig::new();
        let cloned = config.clone();
        assert_eq!(config, cloned);
    }

    #[test]
    fn test_router_config_debug() {
        let config = DARouterConfig::new();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("DARouterConfig"));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // DARouter::new() tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_darouter_new_creates_instance() {
        let primary = create_mock_da();
        let health = create_health_monitor();
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(primary, health, config, metrics);

        // Router should be created without panic
        let _ = router;
    }

    #[test]
    fn test_darouter_new_secondary_is_none() {
        let primary = create_mock_da();
        let health = create_health_monitor();
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(primary, health, config, metrics);

        assert!(router.secondary().is_none());
        assert!(!router.has_secondary());
    }

    #[test]
    fn test_darouter_new_emergency_is_none() {
        let primary = create_mock_da();
        let health = create_health_monitor();
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(primary, health, config, metrics);

        assert!(router.emergency().is_none());
        assert!(!router.has_emergency());
    }

    #[test]
    fn test_darouter_new_primary_accessible() {
        let primary = create_mock_da();
        let health = create_health_monitor();
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(primary, health, config, metrics);

        // Should be able to access primary
        let _ = router.primary();
    }

    #[test]
    fn test_darouter_new_health_accessible() {
        let primary = create_mock_da();
        let health = create_health_monitor();
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(primary, health, config, metrics);

        // Should be able to access health
        let _ = router.health();
    }

    #[test]
    fn test_darouter_new_config_is_set() {
        let primary = create_mock_da();
        let health = create_health_monitor();
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(primary, health, config.clone(), metrics);

        assert_eq!(router.config(), &config);
    }

    #[test]
    fn test_darouter_new_metrics_accessible() {
        let primary = create_mock_da();
        let health = create_health_monitor();
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(primary, health, config, metrics);

        // Should be able to access metrics
        let _ = router.metrics();
    }

    #[test]
    fn test_darouter_new_sources_count_is_one() {
        let primary = create_mock_da();
        let health = create_health_monitor();
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(primary, health, config, metrics);

        assert_eq!(router.available_sources_count(), 1);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // DARouter::with_fallbacks() tests - only secondary
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_with_fallbacks_only_secondary() {
        let primary = create_mock_da();
        let secondary = create_mock_da();
        let health = create_health_monitor();
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(primary, health, config, metrics)
            .with_fallbacks(Some(secondary), None);

        assert!(router.has_secondary());
        assert!(!router.has_emergency());
        assert!(router.secondary().is_some());
    }

    #[test]
    fn test_with_fallbacks_only_secondary_sources_count() {
        let primary = create_mock_da();
        let secondary = create_mock_da();
        let health = create_health_monitor();
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(primary, health, config, metrics)
            .with_fallbacks(Some(secondary), None);

        assert_eq!(router.available_sources_count(), 2);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // DARouter::with_fallbacks() tests - only emergency
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_with_fallbacks_only_emergency() {
        let primary = create_mock_da();
        let emergency = create_mock_da();
        let health = create_health_monitor();
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(primary, health, config, metrics)
            .with_fallbacks(None, Some(emergency));

        assert!(!router.has_secondary());
        assert!(router.has_emergency());
        assert!(router.emergency().is_some());
    }

    #[test]
    fn test_with_fallbacks_only_emergency_sources_count() {
        let primary = create_mock_da();
        let emergency = create_mock_da();
        let health = create_health_monitor();
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(primary, health, config, metrics)
            .with_fallbacks(None, Some(emergency));

        assert_eq!(router.available_sources_count(), 2);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // DARouter::with_fallbacks() tests - both
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_with_fallbacks_both() {
        let primary = create_mock_da();
        let secondary = create_mock_da();
        let emergency = create_mock_da();
        let health = create_health_monitor();
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(primary, health, config, metrics)
            .with_fallbacks(Some(secondary), Some(emergency));

        assert!(router.has_secondary());
        assert!(router.has_emergency());
        assert!(router.secondary().is_some());
        assert!(router.emergency().is_some());
    }

    #[test]
    fn test_with_fallbacks_both_sources_count() {
        let primary = create_mock_da();
        let secondary = create_mock_da();
        let emergency = create_mock_da();
        let health = create_health_monitor();
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(primary, health, config, metrics)
            .with_fallbacks(Some(secondary), Some(emergency));

        assert_eq!(router.available_sources_count(), 3);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // DARouter::with_fallbacks() tests - none (explicit)
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_with_fallbacks_none() {
        let primary = create_mock_da();
        let health = create_health_monitor();
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(primary, health, config, metrics).with_fallbacks(None, None);

        assert!(!router.has_secondary());
        assert!(!router.has_emergency());
        assert_eq!(router.available_sources_count(), 1);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // DARouter::with_fallbacks() - primary preserved
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_with_fallbacks_primary_still_accessible() {
        let primary = create_mock_da();
        let secondary = create_mock_da();
        let emergency = create_mock_da();
        let health = create_health_monitor();
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(primary, health, config, metrics)
            .with_fallbacks(Some(secondary), Some(emergency));

        // Primary should still be accessible
        let _ = router.primary();
    }

    // ────────────────────────────────────────────────────────────────────────────
    // DARouter - chainable builder
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_builder_chainable() {
        let primary = create_mock_da();
        let secondary = create_mock_da();
        let health = create_health_monitor();
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        // This should compile and work
        let router =
            DARouter::new(primary, health, config, metrics).with_fallbacks(Some(secondary), None);

        assert!(router.has_secondary());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // DARouter - multiple with_fallbacks calls
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_with_fallbacks_overwrites_previous() {
        let primary = create_mock_da();
        let secondary1 = create_mock_da();
        let secondary2 = create_mock_da();
        let emergency = create_mock_da();
        let health = create_health_monitor();
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        // First call sets only secondary1
        // Second call overwrites with secondary2 and adds emergency
        let router = DARouter::new(primary, health, config, metrics)
            .with_fallbacks(Some(secondary1), None)
            .with_fallbacks(Some(secondary2), Some(emergency));

        // Should have both secondary and emergency now
        assert!(router.has_secondary());
        assert!(router.has_emergency());
        assert_eq!(router.available_sources_count(), 3);
    }

    #[test]
    fn test_with_fallbacks_can_clear() {
        let primary = create_mock_da();
        let secondary = create_mock_da();
        let emergency = create_mock_da();
        let health = create_health_monitor();
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        // First set both, then clear both
        let router = DARouter::new(primary, health, config, metrics)
            .with_fallbacks(Some(secondary), Some(emergency))
            .with_fallbacks(None, None);

        assert!(!router.has_secondary());
        assert!(!router.has_emergency());
        assert_eq!(router.available_sources_count(), 1);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // No panic tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_darouter_new_no_panic() {
        let result = std::panic::catch_unwind(|| {
            let primary = create_mock_da();
            let health = create_health_monitor();
            let config = DARouterConfig::new();
            let metrics = Arc::new(DARouterMetrics::new());
            DARouter::new(primary, health, config, metrics)
        });
        assert!(result.is_ok(), "DARouter::new should not panic");
    }

    #[test]
    fn test_with_fallbacks_no_panic() {
        let result = std::panic::catch_unwind(|| {
            let primary = create_mock_da();
            let secondary = create_mock_da();
            let emergency = create_mock_da();
            let health = create_health_monitor();
            let config = DARouterConfig::new();
            let metrics = Arc::new(DARouterMetrics::new());
            DARouter::new(primary, health, config, metrics)
                .with_fallbacks(Some(secondary), Some(emergency))
        });
        assert!(result.is_ok(), "with_fallbacks should not panic");
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Accessor consistency tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_accessor_consistency_no_fallbacks() {
        let primary = create_mock_da();
        let health = create_health_monitor();
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(primary, health, config, metrics);

        // Accessors should be consistent
        assert!(!router.has_secondary());
        assert!(router.secondary().is_none());
        assert!(!router.has_emergency());
        assert!(router.emergency().is_none());
    }

    #[test]
    fn test_accessor_consistency_with_fallbacks() {
        let primary = create_mock_da();
        let secondary = create_mock_da();
        let emergency = create_mock_da();
        let health = create_health_monitor();
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(primary, health, config, metrics)
            .with_fallbacks(Some(secondary), Some(emergency));

        // Accessors should be consistent
        assert!(router.has_secondary());
        assert!(router.secondary().is_some());
        assert!(router.has_emergency());
        assert!(router.emergency().is_some());
    }

    // ════════════════════════════════════════════════════════════════════════════
    // POST_BLOB ROUTING TESTS (14A.1A.16)
    // ════════════════════════════════════════════════════════════════════════════

    // ────────────────────────────────────────────────────────────────────────────
    // DAStatus::Healthy - Routes to Primary
    // ────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_post_blob_healthy_routes_to_primary() {
        let primary = create_tracking_mock("primary");
        let secondary = create_tracking_mock("secondary");
        let emergency = create_tracking_mock("emergency");
        let health = create_mock_status_provider(DAStatus::Healthy);
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(
            primary.clone() as Arc<dyn DALayer>,
            health,
            config,
            metrics.clone(),
        )
        .with_fallbacks(
            Some(secondary.clone() as Arc<dyn DALayer>),
            Some(emergency.clone() as Arc<dyn DALayer>),
        );

        let result = router.post_blob(b"test data").await;

        assert!(result.is_ok());
        assert_eq!(primary.call_count(), 1);
        assert_eq!(secondary.call_count(), 0);
        assert_eq!(emergency.call_count(), 0);
        assert_eq!(metrics.primary_post_count(), 1);
        assert_eq!(metrics.pending_reconcile_count(), 0);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // DAStatus::Warning - Routes to Primary (Extended Timeout)
    // ────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_post_blob_warning_routes_to_primary() {
        let primary = create_tracking_mock("primary");
        let secondary = create_tracking_mock("secondary");
        let health = create_mock_status_provider(DAStatus::Warning);
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(
            primary.clone() as Arc<dyn DALayer>,
            health,
            config,
            metrics.clone(),
        )
        .with_fallbacks(Some(secondary.clone() as Arc<dyn DALayer>), None);

        let result = router.post_blob(b"test data").await;

        assert!(result.is_ok());
        assert_eq!(primary.call_count(), 1);
        assert_eq!(secondary.call_count(), 0);
        assert_eq!(metrics.primary_post_count(), 1);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // DAStatus::Degraded - Routes to Secondary, Tags PendingReconcile
    // ────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_post_blob_degraded_routes_to_secondary() {
        let primary = create_tracking_mock("primary");
        let secondary = create_tracking_mock("secondary");
        let health = create_mock_status_provider(DAStatus::Degraded);
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(
            primary.clone() as Arc<dyn DALayer>,
            health,
            config,
            metrics.clone(),
        )
        .with_fallbacks(Some(secondary.clone() as Arc<dyn DALayer>), None);

        let result = router.post_blob(b"test data").await;

        assert!(result.is_ok());
        assert_eq!(primary.call_count(), 0);
        assert_eq!(secondary.call_count(), 1);
        assert_eq!(metrics.secondary_post_count(), 1);
        assert_eq!(metrics.pending_reconcile_count(), 1);
    }

    #[tokio::test]
    async fn test_post_blob_degraded_no_secondary_returns_error() {
        let primary = create_tracking_mock("primary");
        let health = create_mock_status_provider(DAStatus::Degraded);
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        // No secondary configured
        let router = DARouter::new(
            primary.clone() as Arc<dyn DALayer>,
            health,
            config,
            metrics.clone(),
        );

        let result = router.post_blob(b"test data").await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            DAError::Other(msg) => {
                assert!(msg.contains("secondary DA not available"));
                assert!(msg.contains("Degraded"));
            }
            _ => panic!("Expected DAError::Other"),
        }
        assert_eq!(primary.call_count(), 0);
        assert_eq!(metrics.secondary_error_count(), 1);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // DAStatus::Emergency - Routes to Emergency, Tags EmergencyPending
    // ────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_post_blob_emergency_routes_to_emergency() {
        let primary = create_tracking_mock("primary");
        let secondary = create_tracking_mock("secondary");
        let emergency = create_tracking_mock("emergency");
        let health = create_mock_status_provider(DAStatus::Emergency);
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(
            primary.clone() as Arc<dyn DALayer>,
            health,
            config,
            metrics.clone(),
        )
        .with_fallbacks(
            Some(secondary.clone() as Arc<dyn DALayer>),
            Some(emergency.clone() as Arc<dyn DALayer>),
        );

        let result = router.post_blob(b"test data").await;

        assert!(result.is_ok());
        assert_eq!(primary.call_count(), 0);
        assert_eq!(secondary.call_count(), 0);
        assert_eq!(emergency.call_count(), 1);
        assert_eq!(metrics.emergency_post_count(), 1);
        assert_eq!(metrics.emergency_pending_count(), 1);
    }

    #[tokio::test]
    async fn test_post_blob_emergency_no_emergency_returns_error() {
        let primary = create_tracking_mock("primary");
        let secondary = create_tracking_mock("secondary");
        let health = create_mock_status_provider(DAStatus::Emergency);
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        // No emergency configured (only secondary)
        let router = DARouter::new(
            primary.clone() as Arc<dyn DALayer>,
            health,
            config,
            metrics.clone(),
        )
        .with_fallbacks(Some(secondary.clone() as Arc<dyn DALayer>), None);

        let result = router.post_blob(b"test data").await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            DAError::Other(msg) => {
                assert!(msg.contains("emergency DA not available"));
                assert!(msg.contains("Emergency"));
            }
            _ => panic!("Expected DAError::Other"),
        }
        assert_eq!(primary.call_count(), 0);
        assert_eq!(secondary.call_count(), 0);
        assert_eq!(metrics.emergency_error_count(), 1);
    }

    #[tokio::test]
    async fn test_post_blob_emergency_does_not_fallback_to_secondary() {
        let primary = create_tracking_mock("primary");
        let secondary = create_tracking_mock("secondary");
        let health = create_mock_status_provider(DAStatus::Emergency);
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        // Secondary available but no emergency - should NOT use secondary
        let router = DARouter::new(
            primary.clone() as Arc<dyn DALayer>,
            health,
            config,
            metrics.clone(),
        )
        .with_fallbacks(Some(secondary.clone() as Arc<dyn DALayer>), None);

        let result = router.post_blob(b"test data").await;

        // Should error, not fallback to secondary
        assert!(result.is_err());
        assert_eq!(secondary.call_count(), 0);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // DAStatus::Recovering - Routes to Primary, Marks for Reconciliation
    // ────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_post_blob_recovering_routes_to_primary() {
        let primary = create_tracking_mock("primary");
        let secondary = create_tracking_mock("secondary");
        let health = create_mock_status_provider(DAStatus::Recovering);
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(
            primary.clone() as Arc<dyn DALayer>,
            health,
            config,
            metrics.clone(),
        )
        .with_fallbacks(Some(secondary.clone() as Arc<dyn DALayer>), None);

        let result = router.post_blob(b"test data").await;

        assert!(result.is_ok());
        assert_eq!(primary.call_count(), 1);
        assert_eq!(secondary.call_count(), 0);
        assert_eq!(metrics.primary_post_count(), 1);
        assert_eq!(metrics.pending_reconcile_count(), 1);
    }

    #[tokio::test]
    async fn test_post_blob_recovering_does_not_write_to_secondary() {
        let primary = create_tracking_mock("primary");
        let secondary = create_tracking_mock("secondary");
        let emergency = create_tracking_mock("emergency");
        let health = create_mock_status_provider(DAStatus::Recovering);
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(
            primary.clone() as Arc<dyn DALayer>,
            health,
            config,
            metrics.clone(),
        )
        .with_fallbacks(
            Some(secondary.clone() as Arc<dyn DALayer>),
            Some(emergency.clone() as Arc<dyn DALayer>),
        );

        let _ = router.post_blob(b"test data").await;

        assert_eq!(secondary.call_count(), 0);
        assert_eq!(emergency.call_count(), 0);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Error Handling - Primary Failure
    // ────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_post_blob_healthy_primary_failure_records_error() {
        let primary = create_failing_mock("primary");
        let health = create_mock_status_provider(DAStatus::Healthy);
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(primary.clone() as Arc<dyn DALayer>, health, config, metrics.clone());

        let result = router.post_blob(b"test data").await;

        assert!(result.is_err());
        assert_eq!(primary.call_count(), 1);
        assert_eq!(metrics.primary_error_count(), 1);
        assert_eq!(metrics.primary_post_count(), 0);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Error Handling - Secondary Failure
    // ────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_post_blob_degraded_secondary_failure_records_error() {
        let primary = create_tracking_mock("primary");
        let secondary = create_failing_mock("secondary");
        let health = create_mock_status_provider(DAStatus::Degraded);
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(
            primary.clone() as Arc<dyn DALayer>,
            health,
            config,
            metrics.clone(),
        )
        .with_fallbacks(Some(secondary.clone() as Arc<dyn DALayer>), None);

        let result = router.post_blob(b"test data").await;

        assert!(result.is_err());
        assert_eq!(secondary.call_count(), 1);
        assert_eq!(metrics.secondary_error_count(), 1);
        assert_eq!(metrics.secondary_post_count(), 0);
        assert_eq!(metrics.pending_reconcile_count(), 0);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Error Handling - Emergency Failure
    // ────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_post_blob_emergency_failure_records_error() {
        let primary = create_tracking_mock("primary");
        let emergency = create_failing_mock("emergency");
        let health = create_mock_status_provider(DAStatus::Emergency);
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(
            primary.clone() as Arc<dyn DALayer>,
            health,
            config,
            metrics.clone(),
        )
        .with_fallbacks(None, Some(emergency.clone() as Arc<dyn DALayer>));

        let result = router.post_blob(b"test data").await;

        assert!(result.is_err());
        assert_eq!(emergency.call_count(), 1);
        assert_eq!(metrics.emergency_error_count(), 1);
        assert_eq!(metrics.emergency_post_count(), 0);
        assert_eq!(metrics.emergency_pending_count(), 0);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // No Panic Tests for post_blob
    // ────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_post_blob_no_panic_on_degraded_without_secondary() {
        let primary = create_tracking_mock("primary");
        let health = create_mock_status_provider(DAStatus::Degraded);
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(primary.clone() as Arc<dyn DALayer>, health, config, metrics);

        // Should not panic, should return error
        let result = router.post_blob(b"test data").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_post_blob_no_panic_on_emergency_without_emergency() {
        let primary = create_tracking_mock("primary");
        let health = create_mock_status_provider(DAStatus::Emergency);
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(primary.clone() as Arc<dyn DALayer>, health, config, metrics);

        // Should not panic, should return error
        let result = router.post_blob(b"test data").await;
        assert!(result.is_err());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Metrics Isolation Tests
    // ────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_metrics_not_mixed_between_paths() {
        let primary = create_tracking_mock("primary");
        let secondary = create_tracking_mock("secondary");
        let emergency = create_tracking_mock("emergency");
        let metrics = Arc::new(DARouterMetrics::new());

        // Test with Healthy -> primary
        {
            let health = create_mock_status_provider(DAStatus::Healthy);
            let router = DARouter::new(
                primary.clone() as Arc<dyn DALayer>,
                health,
                DARouterConfig::new(),
                metrics.clone(),
            )
            .with_fallbacks(
                Some(secondary.clone() as Arc<dyn DALayer>),
                Some(emergency.clone() as Arc<dyn DALayer>),
            );
            let _ = router.post_blob(b"data").await;
        }

        assert_eq!(metrics.primary_post_count(), 1);
        assert_eq!(metrics.secondary_post_count(), 0);
        assert_eq!(metrics.emergency_post_count(), 0);

        // Test with Degraded -> secondary
        {
            let health = create_mock_status_provider(DAStatus::Degraded);
            let router = DARouter::new(
                primary.clone() as Arc<dyn DALayer>,
                health,
                DARouterConfig::new(),
                metrics.clone(),
            )
            .with_fallbacks(
                Some(secondary.clone() as Arc<dyn DALayer>),
                Some(emergency.clone() as Arc<dyn DALayer>),
            );
            let _ = router.post_blob(b"data").await;
        }

        assert_eq!(metrics.primary_post_count(), 1);
        assert_eq!(metrics.secondary_post_count(), 1);
        assert_eq!(metrics.emergency_post_count(), 0);

        // Test with Emergency -> emergency
        {
            let health = create_mock_status_provider(DAStatus::Emergency);
            let router = DARouter::new(
                primary.clone() as Arc<dyn DALayer>,
                health,
                DARouterConfig::new(),
                metrics.clone(),
            )
            .with_fallbacks(
                Some(secondary.clone() as Arc<dyn DALayer>),
                Some(emergency.clone() as Arc<dyn DALayer>),
            );
            let _ = router.post_blob(b"data").await;
        }

        assert_eq!(metrics.primary_post_count(), 1);
        assert_eq!(metrics.secondary_post_count(), 1);
        assert_eq!(metrics.emergency_post_count(), 1);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // GET_BLOB ROUTING TESTS (14A.1A.17)
    // ════════════════════════════════════════════════════════════════════════════

    // ────────────────────────────────────────────────────────────────────────────
    // Primary Success - No Fallback Needed
    // ────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_get_blob_primary_success_returns_data() {
        let expected_data = vec![0x01, 0x02, 0x03, 0x04];
        let primary = create_mock_with_get_behavior("primary", false, expected_data.clone());
        let secondary = create_mock_with_get_behavior("secondary", false, vec![0xFF]);
        let health = create_mock_status_provider_with_fallback(DAStatus::Healthy, false);
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(
            primary.clone() as Arc<dyn DALayer>,
            health,
            config,
            metrics.clone(),
        )
        .with_fallbacks(Some(secondary.clone() as Arc<dyn DALayer>), None);

        let blob_ref = create_test_blob_ref();
        let result = router.get_blob(&blob_ref).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_data);
        assert_eq!(primary.get_call_count(), 1);
        assert_eq!(secondary.get_call_count(), 0);
        assert_eq!(metrics.primary_read_count(), 1);
        assert_eq!(metrics.secondary_read_count(), 0);
        assert_eq!(metrics.fallback_read_count(), 0);
    }

    #[tokio::test]
    async fn test_get_blob_primary_success_only_calls_primary() {
        let primary = create_tracking_mock("primary");
        let secondary = create_tracking_mock("secondary");
        let emergency = create_tracking_mock("emergency");
        let health = create_mock_status_provider_with_fallback(DAStatus::Healthy, true);
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(
            primary.clone() as Arc<dyn DALayer>,
            health,
            config,
            metrics.clone(),
        )
        .with_fallbacks(
            Some(secondary.clone() as Arc<dyn DALayer>),
            Some(emergency.clone() as Arc<dyn DALayer>),
        );

        let blob_ref = create_test_blob_ref();
        let _ = router.get_blob(&blob_ref).await;

        // Primary dipanggil, secondary dan emergency tidak
        assert_eq!(primary.get_call_count(), 1);
        assert_eq!(secondary.get_call_count(), 0);
        assert_eq!(emergency.get_call_count(), 0);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Primary Failure, Fallback Not Active
    // ────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_get_blob_primary_fails_fallback_not_active_returns_error() {
        let primary = create_mock_with_get_behavior("primary", true, vec![]);
        let secondary = create_mock_with_get_behavior("secondary", false, vec![0xFF]);
        let health = create_mock_status_provider_with_fallback(DAStatus::Healthy, false);
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(
            primary.clone() as Arc<dyn DALayer>,
            health,
            config,
            metrics.clone(),
        )
        .with_fallbacks(Some(secondary.clone() as Arc<dyn DALayer>), None);

        let blob_ref = create_test_blob_ref();
        let result = router.get_blob(&blob_ref).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            DAError::Other(msg) => {
                assert!(msg.contains("primary error"));
                assert!(msg.contains("fallback not active"));
            }
            _ => panic!("Expected DAError::Other"),
        }
        assert_eq!(primary.get_call_count(), 1);
        assert_eq!(secondary.get_call_count(), 0);
        assert_eq!(metrics.primary_read_error_count(), 1);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Primary Failure, Fallback to Secondary
    // ────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_get_blob_fallback_to_secondary_success() {
        let primary = create_mock_with_get_behavior("primary", true, vec![]);
        let expected_data = vec![0xAA, 0xBB, 0xCC];
        let secondary = create_mock_with_get_behavior("secondary", false, expected_data.clone());
        let health = create_mock_status_provider_with_fallback(DAStatus::Degraded, true);
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(
            primary.clone() as Arc<dyn DALayer>,
            health,
            config,
            metrics.clone(),
        )
        .with_fallbacks(Some(secondary.clone() as Arc<dyn DALayer>), None);

        let blob_ref = create_test_blob_ref();
        let result = router.get_blob(&blob_ref).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_data);
        assert_eq!(primary.get_call_count(), 1);
        assert_eq!(secondary.get_call_count(), 1);
        assert_eq!(metrics.primary_read_error_count(), 1);
        assert_eq!(metrics.secondary_read_count(), 1);
        assert_eq!(metrics.fallback_read_count(), 1);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Cascading Fallback - Primary → Secondary → Emergency
    // ────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_get_blob_cascading_fallback_to_emergency() {
        let primary = create_mock_with_get_behavior("primary", true, vec![]);
        let secondary = create_mock_with_get_behavior("secondary", true, vec![]);
        let expected_data = vec![0x11, 0x22, 0x33];
        let emergency = create_mock_with_get_behavior("emergency", false, expected_data.clone());
        let health = create_mock_status_provider_with_fallback(DAStatus::Emergency, true);
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(
            primary.clone() as Arc<dyn DALayer>,
            health,
            config,
            metrics.clone(),
        )
        .with_fallbacks(
            Some(secondary.clone() as Arc<dyn DALayer>),
            Some(emergency.clone() as Arc<dyn DALayer>),
        );

        let blob_ref = create_test_blob_ref();
        let result = router.get_blob(&blob_ref).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_data);
        assert_eq!(primary.get_call_count(), 1);
        assert_eq!(secondary.get_call_count(), 1);
        assert_eq!(emergency.get_call_count(), 1);
        assert_eq!(metrics.primary_read_error_count(), 1);
        assert_eq!(metrics.secondary_read_error_count(), 1);
        assert_eq!(metrics.emergency_read_count(), 1);
        assert_eq!(metrics.fallback_read_count(), 1);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // All Paths Fail - Error Contains All Context
    // ────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_get_blob_all_paths_fail_returns_comprehensive_error() {
        let primary = create_mock_with_get_behavior("primary", true, vec![]);
        let secondary = create_mock_with_get_behavior("secondary", true, vec![]);
        let emergency = create_mock_with_get_behavior("emergency", true, vec![]);
        let health = create_mock_status_provider_with_fallback(DAStatus::Emergency, true);
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(
            primary.clone() as Arc<dyn DALayer>,
            health,
            config,
            metrics.clone(),
        )
        .with_fallbacks(
            Some(secondary.clone() as Arc<dyn DALayer>),
            Some(emergency.clone() as Arc<dyn DALayer>),
        );

        let blob_ref = create_test_blob_ref();
        let result = router.get_blob(&blob_ref).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            DAError::Other(msg) => {
                assert!(msg.contains("primary"));
                assert!(msg.contains("secondary"));
                assert!(msg.contains("emergency"));
                assert!(msg.contains("all paths exhausted"));
            }
            _ => panic!("Expected DAError::Other"),
        }
        assert_eq!(primary.get_call_count(), 1);
        assert_eq!(secondary.get_call_count(), 1);
        assert_eq!(emergency.get_call_count(), 1);
        assert_eq!(metrics.primary_read_error_count(), 1);
        assert_eq!(metrics.secondary_read_error_count(), 1);
        assert_eq!(metrics.emergency_read_error_count(), 1);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // No Fallback Configured
    // ────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_get_blob_no_fallback_configured_returns_error() {
        let primary = create_mock_with_get_behavior("primary", true, vec![]);
        let health = create_mock_status_provider_with_fallback(DAStatus::Degraded, true);
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(
            primary.clone() as Arc<dyn DALayer>,
            health,
            config,
            metrics.clone(),
        );
        // No fallbacks configured

        let blob_ref = create_test_blob_ref();
        let result = router.get_blob(&blob_ref).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            DAError::Other(msg) => {
                assert!(msg.contains("no fallback configured"));
            }
            _ => panic!("Expected DAError::Other"),
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Emergency Only (No Secondary)
    // ────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_get_blob_fallback_to_emergency_when_no_secondary() {
        let primary = create_mock_with_get_behavior("primary", true, vec![]);
        let expected_data = vec![0xEE, 0xFF];
        let emergency = create_mock_with_get_behavior("emergency", false, expected_data.clone());
        let health = create_mock_status_provider_with_fallback(DAStatus::Emergency, true);
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(
            primary.clone() as Arc<dyn DALayer>,
            health,
            config,
            metrics.clone(),
        )
        .with_fallbacks(None, Some(emergency.clone() as Arc<dyn DALayer>));

        let blob_ref = create_test_blob_ref();
        let result = router.get_blob(&blob_ref).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_data);
        assert_eq!(primary.get_call_count(), 1);
        assert_eq!(emergency.get_call_count(), 1);
        assert_eq!(metrics.emergency_read_count(), 1);
        assert_eq!(metrics.fallback_read_count(), 1);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // No Panic Tests
    // ────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_get_blob_no_panic_when_all_fallbacks_missing() {
        let primary = create_mock_with_get_behavior("primary", true, vec![]);
        let health = create_mock_status_provider_with_fallback(DAStatus::Emergency, true);
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(
            primary.clone() as Arc<dyn DALayer>,
            health,
            config,
            metrics.clone(),
        );

        let blob_ref = create_test_blob_ref();
        let result = router.get_blob(&blob_ref).await;

        // Should return error, not panic
        assert!(result.is_err());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Metrics Isolation Tests
    // ────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_get_blob_metrics_not_mixed_with_post_metrics() {
        let primary = create_tracking_mock("primary");
        let health = create_mock_status_provider(DAStatus::Healthy);
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(
            primary.clone() as Arc<dyn DALayer>,
            health,
            config,
            metrics.clone(),
        );

        // Do a post
        let _ = router.post_blob(b"test").await;
        
        // Do a get
        let blob_ref = create_test_blob_ref();
        let _ = router.get_blob(&blob_ref).await;

        // Post metrics should be separate from read metrics
        assert_eq!(metrics.primary_post_count(), 1);
        assert_eq!(metrics.primary_read_count(), 1);
        assert_eq!(metrics.total_post_count(), 1);
        assert_eq!(metrics.total_read_count(), 1);
    }

    #[tokio::test]
    async fn test_get_blob_read_metrics_accumulate_correctly() {
        let primary = create_mock_with_get_behavior("primary", true, vec![]);
        let secondary = create_mock_with_get_behavior("secondary", false, vec![0xAA]);
        let health = create_mock_status_provider_with_fallback(DAStatus::Degraded, true);
        let config = DARouterConfig::new();
        let metrics = Arc::new(DARouterMetrics::new());

        let router = DARouter::new(
            primary.clone() as Arc<dyn DALayer>,
            health,
            config,
            metrics.clone(),
        )
        .with_fallbacks(Some(secondary.clone() as Arc<dyn DALayer>), None);

        let blob_ref = create_test_blob_ref();
        
        // Multiple reads
        let _ = router.get_blob(&blob_ref).await;
        let _ = router.get_blob(&blob_ref).await;
        let _ = router.get_blob(&blob_ref).await;

        assert_eq!(metrics.primary_read_error_count(), 3);
        assert_eq!(metrics.secondary_read_count(), 3);
        assert_eq!(metrics.fallback_read_count(), 3);
    }
}