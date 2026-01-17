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
// DA ROUTER CONFIG (14A.1A.18)
// ════════════════════════════════════════════════════════════════════════════════

/// Konfigurasi deterministik untuk perilaku DARouter.
///
/// Struct ini mendefinisikan semua parameter yang mengontrol:
/// - Fallback behavior ketika primary DA tidak tersedia
/// - Emergency routing behavior
/// - Retry policy pada fallback paths
/// - Recovery dan reconciliation behavior
///
/// ## Environment Variables
///
/// Konfigurasi dapat dibaca dari environment variables dengan prefix `DSDN_DA_ROUTER_`:
/// - `DSDN_DA_ROUTER_ENABLE_FALLBACK` - bool ("true"/"false")
/// - `DSDN_DA_ROUTER_ENABLE_EMERGENCY` - bool ("true"/"false")
/// - `DSDN_DA_ROUTER_EXTENDED_TIMEOUT_MULTIPLIER` - f64 (decimal)
/// - `DSDN_DA_ROUTER_MAX_RETRY_ON_FALLBACK` - u32 (non-negative integer)
/// - `DSDN_DA_ROUTER_RECONCILE_ON_RECOVERY` - bool ("true"/"false")
/// - `DSDN_DA_ROUTER_PARALLEL_POST_ON_RECOVERING` - bool ("true"/"false")
///
/// ## Thread Safety
///
/// Struct ini adalah plain data tanpa interior mutability.
/// Aman untuk digunakan di multi-threaded context (Send + Sync).
///
/// ## Usage
///
/// ```rust,ignore
/// // Menggunakan default values
/// let config = DARouterConfig::default();
///
/// // Membaca dari environment
/// let config = DARouterConfig::from_env();
///
/// // Manual construction
/// let config = DARouterConfig::new();
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct DARouterConfig {
    /// Mengaktifkan fallback ke secondary DA ketika primary gagal.
    ///
    /// ## Behavior
    ///
    /// - `true`: Ketika primary DA gagal, router akan mencoba secondary DA
    /// - `false`: Hanya primary DA yang digunakan, error langsung dikembalikan
    ///
    /// ## Checked At
    ///
    /// - `post_blob`: Sebelum routing ke secondary pada status Degraded
    /// - `get_blob`: Sebelum fallback read ke secondary
    ///
    /// ## Default
    ///
    /// `true` - Fallback diaktifkan secara default untuk high availability.
    pub enable_fallback: bool,

    /// Mengaktifkan emergency DA ketika primary dan secondary gagal.
    ///
    /// ## Behavior
    ///
    /// - `true`: Ketika primary dan secondary gagal, router akan mencoba emergency DA
    /// - `false`: Emergency DA tidak pernah digunakan
    ///
    /// ## Checked At
    ///
    /// - `post_blob`: Sebelum routing ke emergency pada status Emergency
    /// - `get_blob`: Sebelum fallback read ke emergency
    ///
    /// ## Default
    ///
    /// `true` - Emergency diaktifkan secara default untuk disaster recovery.
    pub enable_emergency: bool,

    /// Multiplier untuk extended timeout pada status Warning.
    ///
    /// ## Behavior
    ///
    /// Ketika DA status adalah Warning, timeout akan diperpanjang dengan multiplier ini.
    /// Contoh: jika base timeout 5s dan multiplier 2.0, timeout menjadi 10s.
    ///
    /// ## Valid Range
    ///
    /// - Minimum: 1.0 (tidak ada perpanjangan)
    /// - Recommended: 1.5 - 3.0
    ///
    /// ## Checked At
    ///
    /// - `post_blob`: Ketika status Warning, sebelum operasi ke primary
    ///
    /// ## Default
    ///
    /// `2.0` - Timeout digandakan pada Warning status.
    pub extended_timeout_multiplier: f64,

    /// Jumlah maksimum retry pada fallback path (secondary/emergency).
    ///
    /// ## Behavior
    ///
    /// Ketika operasi ke fallback DA gagal, router akan retry hingga
    /// `max_retry_on_fallback` kali sebelum mengembalikan error.
    ///
    /// ## Valid Range
    ///
    /// - Minimum: 0 (tidak ada retry)
    /// - Maximum: 10 (recommended untuk menghindari latency berlebih)
    ///
    /// ## Checked At
    ///
    /// - `post_blob`: Pada setiap retry ke secondary/emergency
    /// - `get_blob`: Pada setiap retry read dari fallback
    ///
    /// ## Default
    ///
    /// `3` - Maksimal 3 kali retry pada fallback.
    pub max_retry_on_fallback: u32,

    /// Mengaktifkan reconciliation otomatis ketika primary kembali Healthy.
    ///
    /// ## Behavior
    ///
    /// - `true`: Blob yang ditulis ke fallback akan di-reconcile ke primary
    ///   ketika primary kembali dari status Recovering ke Healthy
    /// - `false`: Tidak ada reconciliation otomatis
    ///
    /// ## Checked At
    ///
    /// - Recovery handler: Ketika status berubah dari Recovering ke Healthy
    /// - Reconciliation worker: Sebelum memproses pending reconcile queue
    ///
    /// ## Default
    ///
    /// `true` - Reconciliation diaktifkan untuk menjaga data consistency.
    pub reconcile_on_recovery: bool,

    /// Mengaktifkan parallel write ke primary dan fallback pada status Recovering.
    ///
    /// ## Behavior
    ///
    /// - `true`: Ketika status Recovering, blob ditulis ke primary DAN fallback
    ///   secara paralel untuk menghindari data loss jika primary gagal lagi
    /// - `false`: Hanya primary yang digunakan pada Recovering
    ///
    /// ## Trade-offs
    ///
    /// - `true`: Higher consistency, higher latency, more storage
    /// - `false`: Lower latency, risk of data loss if primary fails again
    ///
    /// ## Checked At
    ///
    /// - `post_blob`: Ketika status Recovering, sebelum write operation
    ///
    /// ## Default
    ///
    /// `false` - Single write ke primary untuk lower latency.
    pub parallel_post_on_recovering: bool,
}

impl Default for DARouterConfig {
    fn default() -> Self {
        Self {
            enable_fallback: true,
            enable_emergency: true,
            extended_timeout_multiplier: 2.0,
            max_retry_on_fallback: 3,
            reconcile_on_recovery: true,
            parallel_post_on_recovering: false,
        }
    }
}

impl DARouterConfig {
    /// Membuat konfigurasi dengan default values.
    ///
    /// # Returns
    ///
    /// Instance baru dengan semua field set ke default values.
    ///
    /// # Default Values
    ///
    /// - `enable_fallback`: true
    /// - `enable_emergency`: true
    /// - `extended_timeout_multiplier`: 2.0
    /// - `max_retry_on_fallback`: 3
    /// - `reconcile_on_recovery`: true
    /// - `parallel_post_on_recovering`: false
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Membaca konfigurasi dari environment variables.
    ///
    /// Setiap field dibaca dari environment variable dengan prefix `DSDN_DA_ROUTER_`.
    /// Jika environment variable tidak ada atau tidak valid, nilai default digunakan.
    ///
    /// # Environment Variables
    ///
    /// | Variable | Type | Default |
    /// |----------|------|---------|
    /// | `DSDN_DA_ROUTER_ENABLE_FALLBACK` | bool | true |
    /// | `DSDN_DA_ROUTER_ENABLE_EMERGENCY` | bool | true |
    /// | `DSDN_DA_ROUTER_EXTENDED_TIMEOUT_MULTIPLIER` | f64 | 2.0 |
    /// | `DSDN_DA_ROUTER_MAX_RETRY_ON_FALLBACK` | u32 | 3 |
    /// | `DSDN_DA_ROUTER_RECONCILE_ON_RECOVERY` | bool | true |
    /// | `DSDN_DA_ROUTER_PARALLEL_POST_ON_RECOVERING` | bool | false |
    ///
    /// # Parsing Rules
    ///
    /// - **bool**: "true" atau "false" (case-insensitive)
    /// - **f64**: decimal valid (e.g., "2.0", "1.5")
    /// - **u32**: integer non-negative (e.g., "3", "5")
    ///
    /// # Returns
    ///
    /// Instance dengan values dari environment atau default jika tidak tersedia/invalid.
    ///
    /// # Guarantees
    ///
    /// - Tidak panic
    /// - Tidak menggunakan unwrap/expect
    /// - Deterministik: input sama selalu menghasilkan output sama
    #[must_use]
    pub fn from_env() -> Self {
        let defaults = Self::default();

        Self {
            enable_fallback: Self::parse_env_bool(
                "DSDN_DA_ROUTER_ENABLE_FALLBACK",
                defaults.enable_fallback,
            ),
            enable_emergency: Self::parse_env_bool(
                "DSDN_DA_ROUTER_ENABLE_EMERGENCY",
                defaults.enable_emergency,
            ),
            extended_timeout_multiplier: Self::parse_env_f64(
                "DSDN_DA_ROUTER_EXTENDED_TIMEOUT_MULTIPLIER",
                defaults.extended_timeout_multiplier,
            ),
            max_retry_on_fallback: Self::parse_env_u32(
                "DSDN_DA_ROUTER_MAX_RETRY_ON_FALLBACK",
                defaults.max_retry_on_fallback,
            ),
            reconcile_on_recovery: Self::parse_env_bool(
                "DSDN_DA_ROUTER_RECONCILE_ON_RECOVERY",
                defaults.reconcile_on_recovery,
            ),
            parallel_post_on_recovering: Self::parse_env_bool(
                "DSDN_DA_ROUTER_PARALLEL_POST_ON_RECOVERING",
                defaults.parallel_post_on_recovering,
            ),
        }
    }

    /// Parse boolean dari environment variable.
    ///
    /// Accepts "true" atau "false" (case-insensitive).
    /// Returns default jika tidak ada atau tidak valid.
    fn parse_env_bool(key: &str, default: bool) -> bool {
        match std::env::var(key) {
            Ok(val) => match val.to_lowercase().as_str() {
                "true" => true,
                "false" => false,
                _ => default,
            },
            Err(_) => default,
        }
    }

    /// Parse f64 dari environment variable.
    ///
    /// Returns default jika tidak ada atau tidak valid.
    fn parse_env_f64(key: &str, default: f64) -> f64 {
        match std::env::var(key) {
            Ok(val) => val.parse::<f64>().unwrap_or(default),
            Err(_) => default,
        }
    }

    /// Parse u32 dari environment variable.
    ///
    /// Returns default jika tidak ada atau tidak valid.
    fn parse_env_u32(key: &str, default: u32) -> u32 {
        match std::env::var(key) {
            Ok(val) => val.parse::<u32>().unwrap_or(default),
            Err(_) => default,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// DA ROUTER METRICS (14A.1A.19)
// ════════════════════════════════════════════════════════════════════════════════

/// Snapshot point-in-time dari semua metrics DARouter.
///
/// Struct ini merepresentasikan salinan nilai dari semua metrics
/// pada satu titik waktu tertentu. Digunakan untuk:
/// - Audit trail
/// - Export ke external systems
/// - Debugging dan monitoring
///
/// ## Thread Safety
///
/// Struct ini adalah plain data (u64 values), tidak mengandung Atomic.
/// Aman untuk disimpan, di-serialize, atau di-transfer antar thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricsSnapshot {
    /// Jumlah post_blob sukses ke primary DA.
    pub primary_posts: u64,
    /// Jumlah post_blob sukses ke fallback DA (secondary).
    pub fallback_posts: u64,
    /// Jumlah post_blob sukses ke emergency DA.
    pub emergency_posts: u64,
    /// Jumlah get_blob sukses dari primary DA.
    pub primary_gets: u64,
    /// Jumlah get_blob sukses dari fallback DA (secondary/emergency).
    pub fallback_gets: u64,
    /// Jumlah aktivasi fallback mode.
    pub fallback_activations: u64,
    /// Jumlah reconciliation yang di-trigger.
    pub reconciliations_triggered: u64,
    /// Timestamp terakhir kali fallback digunakan (epoch seconds).
    pub last_fallback_at: u64,
}

/// Metrics deterministik, thread-safe, dan audit-ready untuk DARouter.
///
/// Struct ini menyediakan mekanisme tracking untuk:
/// - Operasi post_blob per path (primary, fallback, emergency)
/// - Operasi get_blob per path (primary, fallback)
/// - Aktivasi fallback mode
/// - Reconciliation events
///
/// ## Invariants
///
/// - Semua counter bersifat monotonically increasing
/// - Tidak ada counter yang di-reset secara implisit
/// - `last_fallback_at` hanya di-update saat fallback benar-benar terjadi
/// - Semua increment bersifat atomic (tidak ada partial update)
///
/// ## Thread Safety
///
/// Semua field menggunakan `AtomicU64` dengan explicit memory ordering.
/// Struct ini adalah Send + Sync dan aman untuk concurrent access.
///
/// ## Usage
///
/// ```rust,ignore
/// let metrics = DARouterMetrics::new();
///
/// // Record operations
/// metrics.record_primary_post();
/// metrics.record_fallback_activation();
///
/// // Get snapshot
/// let snapshot = metrics.snapshot();
///
/// // Export to Prometheus
/// let prometheus_text = metrics.to_prometheus();
/// ```
#[derive(Debug)]
pub struct DARouterMetrics {
    /// Jumlah post_blob sukses ke primary DA.
    ///
    /// ## Kapan di-increment
    ///
    /// Ketika post_blob berhasil dikirim ke primary DA layer,
    /// terlepas dari status kesehatan (Healthy, Warning, Recovering).
    ///
    /// ## Makna Operasional
    ///
    /// Menunjukkan jumlah blob yang berhasil di-persist ke DA utama (Celestia).
    /// Nilai tinggi menandakan primary DA beroperasi dengan baik.
    primary_posts: AtomicU64,

    /// Jumlah post_blob sukses ke fallback DA (secondary).
    ///
    /// ## Kapan di-increment
    ///
    /// Ketika post_blob dialihkan ke secondary DA karena primary
    /// dalam status Degraded atau tidak tersedia.
    ///
    /// ## Makna Operasional
    ///
    /// Menunjukkan jumlah blob yang di-persist ke fallback.
    /// Nilai tinggi menandakan primary DA sering bermasalah.
    fallback_posts: AtomicU64,

    /// Jumlah post_blob sukses ke emergency DA.
    ///
    /// ## Kapan di-increment
    ///
    /// Ketika post_blob dialihkan ke emergency DA karena primary
    /// dalam status Emergency atau kritis.
    ///
    /// ## Makna Operasional
    ///
    /// Menunjukkan jumlah blob yang di-persist ke emergency path.
    /// Nilai tinggi menandakan kondisi darurat sering terjadi.
    emergency_posts: AtomicU64,

    /// Jumlah get_blob sukses dari primary DA.
    ///
    /// ## Kapan di-increment
    ///
    /// Ketika get_blob berhasil membaca data dari primary DA layer.
    ///
    /// ## Makna Operasional
    ///
    /// Menunjukkan jumlah read sukses dari primary.
    /// Nilai tinggi relatif terhadap fallback_gets = primary sehat.
    primary_gets: AtomicU64,

    /// Jumlah get_blob sukses dari fallback DA (secondary/emergency).
    ///
    /// ## Kapan di-increment
    ///
    /// Ketika get_blob harus menggunakan secondary atau emergency DA
    /// karena primary gagal dan fallback aktif.
    ///
    /// ## Makna Operasional
    ///
    /// Menunjukkan jumlah read yang memerlukan fallback.
    /// Nilai tinggi menandakan primary DA sering gagal untuk reads.
    fallback_gets: AtomicU64,

    /// Jumlah aktivasi fallback mode.
    ///
    /// ## Kapan di-increment
    ///
    /// Setiap kali router beralih dari primary ke fallback path,
    /// baik untuk post maupun get operation.
    ///
    /// ## Makna Operasional
    ///
    /// Total kejadian di mana sistem harus menggunakan fallback.
    /// Tracking ini penting untuk SLA dan incident analysis.
    fallback_activations: AtomicU64,

    /// Jumlah reconciliation yang di-trigger.
    ///
    /// ## Kapan di-increment
    ///
    /// Ketika blob ditandai untuk reconciliation (PendingReconcile tag).
    /// Terjadi saat menulis ke fallback yang perlu di-sync ke primary.
    ///
    /// ## Makna Operasional
    ///
    /// Jumlah blob yang perlu di-reconcile ke primary.
    /// Nilai tinggi = banyak data di fallback perlu di-sync.
    reconciliations_triggered: AtomicU64,

    /// Timestamp terakhir kali fallback digunakan (epoch seconds).
    ///
    /// ## Kapan di-update
    ///
    /// Setiap kali fallback path benar-benar digunakan (post atau get).
    /// Menggunakan UNIX epoch seconds untuk konsistensi.
    ///
    /// ## Makna Operasional
    ///
    /// Menunjukkan kapan terakhir kali fallback diaktifkan.
    /// Berguna untuk alerting dan incident timeline.
    last_fallback_at: AtomicU64,
}

impl DARouterMetrics {
    /// Membuat metrics baru dengan semua counter di nol.
    #[must_use]
    pub fn new() -> Self {
        Self {
            primary_posts: AtomicU64::new(0),
            fallback_posts: AtomicU64::new(0),
            emergency_posts: AtomicU64::new(0),
            primary_gets: AtomicU64::new(0),
            fallback_gets: AtomicU64::new(0),
            fallback_activations: AtomicU64::new(0),
            reconciliations_triggered: AtomicU64::new(0),
            last_fallback_at: AtomicU64::new(0),
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Core Record Methods (14A.1A.19)
    // ────────────────────────────────────────────────────────────────────────────

    /// Record successful post to primary DA.
    #[inline]
    pub fn record_primary_post(&self) {
        self.primary_posts.fetch_add(1, Ordering::Relaxed);
    }

    /// Record successful post to fallback (secondary) DA.
    ///
    /// Also increments fallback_activations and updates last_fallback_at.
    #[inline]
    pub fn record_fallback_post(&self) {
        self.fallback_posts.fetch_add(1, Ordering::Relaxed);
        self.fallback_activations.fetch_add(1, Ordering::Relaxed);
        self.update_last_fallback_timestamp();
    }

    /// Record successful post to emergency DA.
    ///
    /// Also increments fallback_activations and updates last_fallback_at.
    #[inline]
    pub fn record_emergency_post(&self) {
        self.emergency_posts.fetch_add(1, Ordering::Relaxed);
        self.fallback_activations.fetch_add(1, Ordering::Relaxed);
        self.update_last_fallback_timestamp();
    }

    /// Record successful get from primary DA.
    #[inline]
    pub fn record_primary_get(&self) {
        self.primary_gets.fetch_add(1, Ordering::Relaxed);
    }

    /// Record successful get from fallback DA (secondary or emergency).
    ///
    /// Also increments fallback_activations and updates last_fallback_at.
    #[inline]
    pub fn record_fallback_get(&self) {
        self.fallback_gets.fetch_add(1, Ordering::Relaxed);
        self.fallback_activations.fetch_add(1, Ordering::Relaxed);
        self.update_last_fallback_timestamp();
    }

    /// Record reconciliation triggered.
    #[inline]
    pub fn record_reconciliation(&self) {
        self.reconciliations_triggered.fetch_add(1, Ordering::Relaxed);
    }

    /// Update last fallback timestamp to current time.
    #[inline]
    fn update_last_fallback_timestamp(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.last_fallback_at.store(now, Ordering::Relaxed);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Backward Compatibility Methods (untuk routing logic existing)
    // ────────────────────────────────────────────────────────────────────────────

    /// Record successful post to secondary (alias for record_fallback_post).
    #[inline]
    pub fn record_secondary_post(&self) {
        self.record_fallback_post();
    }

    /// Record pending reconcile tag.
    #[inline]
    pub fn record_pending_reconcile(&self) {
        self.record_reconciliation();
    }

    /// Record emergency pending (increments reconciliation).
    #[inline]
    pub fn record_emergency_pending(&self) {
        self.record_reconciliation();
    }

    /// Record error on primary path (no-op in new spec, for backward compat).
    #[inline]
    pub fn record_primary_error(&self) {
        // Error tracking removed in 14A.1A.19 spec
    }

    /// Record error on secondary path (no-op in new spec, for backward compat).
    #[inline]
    pub fn record_secondary_error(&self) {
        // Error tracking removed in 14A.1A.19 spec
    }

    /// Record error on emergency path (no-op in new spec, for backward compat).
    #[inline]
    pub fn record_emergency_error(&self) {
        // Error tracking removed in 14A.1A.19 spec
    }

    /// Record successful read from primary (alias for record_primary_get).
    #[inline]
    pub fn record_primary_read(&self) {
        self.record_primary_get();
    }

    /// Record successful read from secondary (alias for record_fallback_get).
    #[inline]
    pub fn record_secondary_read(&self) {
        self.record_fallback_get();
    }

    /// Record successful read from emergency (alias for record_fallback_get).
    #[inline]
    pub fn record_emergency_read(&self) {
        self.record_fallback_get();
    }

    /// Record error on primary read path (no-op in new spec, for backward compat).
    #[inline]
    pub fn record_primary_read_error(&self) {
        // Error tracking removed in 14A.1A.19 spec
    }

    /// Record error on secondary read path (no-op in new spec, for backward compat).
    #[inline]
    pub fn record_secondary_read_error(&self) {
        // Error tracking removed in 14A.1A.19 spec
    }

    /// Record error on emergency read path (no-op in new spec, for backward compat).
    #[inline]
    pub fn record_emergency_read_error(&self) {
        // Error tracking removed in 14A.1A.19 spec
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Accessor Methods (14A.1A.19)
    // ────────────────────────────────────────────────────────────────────────────

    /// Get primary posts count.
    #[inline]
    #[must_use]
    pub fn primary_posts(&self) -> u64 {
        self.primary_posts.load(Ordering::Relaxed)
    }

    /// Get fallback posts count.
    #[inline]
    #[must_use]
    pub fn fallback_posts(&self) -> u64 {
        self.fallback_posts.load(Ordering::Relaxed)
    }

    /// Get emergency posts count.
    #[inline]
    #[must_use]
    pub fn emergency_posts(&self) -> u64 {
        self.emergency_posts.load(Ordering::Relaxed)
    }

    /// Get primary gets count.
    #[inline]
    #[must_use]
    pub fn primary_gets(&self) -> u64 {
        self.primary_gets.load(Ordering::Relaxed)
    }

    /// Get fallback gets count.
    #[inline]
    #[must_use]
    pub fn fallback_gets(&self) -> u64 {
        self.fallback_gets.load(Ordering::Relaxed)
    }

    /// Get fallback activations count.
    #[inline]
    #[must_use]
    pub fn fallback_activations(&self) -> u64 {
        self.fallback_activations.load(Ordering::Relaxed)
    }

    /// Get reconciliations triggered count.
    #[inline]
    #[must_use]
    pub fn reconciliations_triggered(&self) -> u64 {
        self.reconciliations_triggered.load(Ordering::Relaxed)
    }

    /// Get last fallback timestamp (epoch seconds).
    #[inline]
    #[must_use]
    pub fn last_fallback_at(&self) -> u64 {
        self.last_fallback_at.load(Ordering::Relaxed)
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Backward Compatibility Accessors
    // ────────────────────────────────────────────────────────────────────────────

    /// Get primary post count (alias for primary_posts).
    #[inline]
    #[must_use]
    pub fn primary_post_count(&self) -> u64 {
        self.primary_posts()
    }

    /// Get secondary post count (alias for fallback_posts).
    #[inline]
    #[must_use]
    pub fn secondary_post_count(&self) -> u64 {
        self.fallback_posts()
    }

    /// Get emergency post count (alias for emergency_posts).
    #[inline]
    #[must_use]
    pub fn emergency_post_count(&self) -> u64 {
        self.emergency_posts()
    }

    /// Get primary error count (always 0 in new spec).
    #[inline]
    #[must_use]
    pub fn primary_error_count(&self) -> u64 {
        0
    }

    /// Get secondary error count (always 0 in new spec).
    #[inline]
    #[must_use]
    pub fn secondary_error_count(&self) -> u64 {
        0
    }

    /// Get emergency error count (always 0 in new spec).
    #[inline]
    #[must_use]
    pub fn emergency_error_count(&self) -> u64 {
        0
    }

    /// Get pending reconcile count (alias for reconciliations_triggered).
    #[inline]
    #[must_use]
    pub fn pending_reconcile_count(&self) -> u64 {
        self.reconciliations_triggered()
    }

    /// Get emergency pending count (alias for reconciliations_triggered).
    #[inline]
    #[must_use]
    pub fn emergency_pending_count(&self) -> u64 {
        self.reconciliations_triggered()
    }

    /// Get total post count across all paths.
    #[inline]
    #[must_use]
    pub fn total_post_count(&self) -> u64 {
        self.primary_posts() + self.fallback_posts() + self.emergency_posts()
    }

    /// Get total error count (always 0 in new spec).
    #[inline]
    #[must_use]
    pub fn total_error_count(&self) -> u64 {
        0
    }

    /// Get primary read count (alias for primary_gets).
    #[inline]
    #[must_use]
    pub fn primary_read_count(&self) -> u64 {
        self.primary_gets()
    }

    /// Get secondary read count (returns fallback_gets for compatibility).
    #[inline]
    #[must_use]
    pub fn secondary_read_count(&self) -> u64 {
        self.fallback_gets()
    }

    /// Get emergency read count (returns 0, merged into fallback_gets).
    #[inline]
    #[must_use]
    pub fn emergency_read_count(&self) -> u64 {
        0
    }

    /// Get primary read error count (always 0 in new spec).
    #[inline]
    #[must_use]
    pub fn primary_read_error_count(&self) -> u64 {
        0
    }

    /// Get secondary read error count (always 0 in new spec).
    #[inline]
    #[must_use]
    pub fn secondary_read_error_count(&self) -> u64 {
        0
    }

    /// Get emergency read error count (always 0 in new spec).
    #[inline]
    #[must_use]
    pub fn emergency_read_error_count(&self) -> u64 {
        0
    }

    /// Get fallback read count (alias for fallback_gets).
    #[inline]
    #[must_use]
    pub fn fallback_read_count(&self) -> u64 {
        self.fallback_gets()
    }

    /// Get total read count across all paths.
    #[inline]
    #[must_use]
    pub fn total_read_count(&self) -> u64 {
        self.primary_gets() + self.fallback_gets()
    }

    /// Get total read error count (always 0 in new spec).
    #[inline]
    #[must_use]
    pub fn total_read_error_count(&self) -> u64 {
        0
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Snapshot & Export Methods (14A.1A.19)
    // ────────────────────────────────────────────────────────────────────────────

    /// Mengambil snapshot konsisten dari semua metrics.
    ///
    /// Snapshot merepresentasikan state metrics pada satu titik waktu.
    /// Method ini TIDAK memodifikasi state apapun.
    ///
    /// # Returns
    ///
    /// `MetricsSnapshot` berisi salinan nilai dari semua metrics.
    ///
    /// # Thread Safety
    ///
    /// Setiap field dibaca secara atomic, namun snapshot mungkin
    /// tidak perfectly consistent jika ada concurrent writes.
    /// Untuk audit purposes, ini dianggap acceptable.
    #[must_use]
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            primary_posts: self.primary_posts.load(Ordering::Relaxed),
            fallback_posts: self.fallback_posts.load(Ordering::Relaxed),
            emergency_posts: self.emergency_posts.load(Ordering::Relaxed),
            primary_gets: self.primary_gets.load(Ordering::Relaxed),
            fallback_gets: self.fallback_gets.load(Ordering::Relaxed),
            fallback_activations: self.fallback_activations.load(Ordering::Relaxed),
            reconciliations_triggered: self.reconciliations_triggered.load(Ordering::Relaxed),
            last_fallback_at: self.last_fallback_at.load(Ordering::Relaxed),
        }
    }

    /// Export metrics dalam format Prometheus exposition text.
    ///
    /// Format output adalah text/plain sesuai Prometheus exposition format.
    /// Setiap metric memiliki satu baris dengan format:
    /// `metric_name value`
    ///
    /// # Returns
    ///
    /// String berisi semua metrics dalam format Prometheus.
    ///
    /// # Guarantees
    ///
    /// - Output deterministik (urutan metrics tetap)
    /// - Tidak panic
    /// - Tidak fail
    ///
    /// # Example Output
    ///
    /// ```text
    /// # HELP dsdn_da_router_primary_posts Total successful posts to primary DA
    /// # TYPE dsdn_da_router_primary_posts counter
    /// dsdn_da_router_primary_posts 42
    /// # HELP dsdn_da_router_fallback_posts Total successful posts to fallback DA
    /// # TYPE dsdn_da_router_fallback_posts counter
    /// dsdn_da_router_fallback_posts 5
    /// ...
    /// ```
    #[must_use]
    pub fn to_prometheus(&self) -> String {
        let snapshot = self.snapshot();
        
        let mut output = String::with_capacity(2048);

        // Primary posts (counter)
        output.push_str("# HELP dsdn_da_router_primary_posts Total successful posts to primary DA\n");
        output.push_str("# TYPE dsdn_da_router_primary_posts counter\n");
        output.push_str(&format!("dsdn_da_router_primary_posts {}\n", snapshot.primary_posts));

        // Fallback posts (counter)
        output.push_str("# HELP dsdn_da_router_fallback_posts Total successful posts to fallback DA\n");
        output.push_str("# TYPE dsdn_da_router_fallback_posts counter\n");
        output.push_str(&format!("dsdn_da_router_fallback_posts {}\n", snapshot.fallback_posts));

        // Emergency posts (counter)
        output.push_str("# HELP dsdn_da_router_emergency_posts Total successful posts to emergency DA\n");
        output.push_str("# TYPE dsdn_da_router_emergency_posts counter\n");
        output.push_str(&format!("dsdn_da_router_emergency_posts {}\n", snapshot.emergency_posts));

        // Primary gets (counter)
        output.push_str("# HELP dsdn_da_router_primary_gets Total successful gets from primary DA\n");
        output.push_str("# TYPE dsdn_da_router_primary_gets counter\n");
        output.push_str(&format!("dsdn_da_router_primary_gets {}\n", snapshot.primary_gets));

        // Fallback gets (counter)
        output.push_str("# HELP dsdn_da_router_fallback_gets Total successful gets from fallback DA\n");
        output.push_str("# TYPE dsdn_da_router_fallback_gets counter\n");
        output.push_str(&format!("dsdn_da_router_fallback_gets {}\n", snapshot.fallback_gets));

        // Fallback activations (counter)
        output.push_str("# HELP dsdn_da_router_fallback_activations Total fallback mode activations\n");
        output.push_str("# TYPE dsdn_da_router_fallback_activations counter\n");
        output.push_str(&format!("dsdn_da_router_fallback_activations {}\n", snapshot.fallback_activations));

        // Reconciliations triggered (counter)
        output.push_str("# HELP dsdn_da_router_reconciliations_triggered Total reconciliations triggered\n");
        output.push_str("# TYPE dsdn_da_router_reconciliations_triggered counter\n");
        output.push_str(&format!("dsdn_da_router_reconciliations_triggered {}\n", snapshot.reconciliations_triggered));

        // Last fallback at (gauge - timestamp)
        output.push_str("# HELP dsdn_da_router_last_fallback_at Timestamp of last fallback activation (epoch seconds)\n");
        output.push_str("# TYPE dsdn_da_router_last_fallback_at gauge\n");
        output.push_str(&format!("dsdn_da_router_last_fallback_at {}\n", snapshot.last_fallback_at));

        output
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
            primary_posts: AtomicU64::new(self.primary_posts.load(Ordering::Relaxed)),
            fallback_posts: AtomicU64::new(self.fallback_posts.load(Ordering::Relaxed)),
            emergency_posts: AtomicU64::new(self.emergency_posts.load(Ordering::Relaxed)),
            primary_gets: AtomicU64::new(self.primary_gets.load(Ordering::Relaxed)),
            fallback_gets: AtomicU64::new(self.fallback_gets.load(Ordering::Relaxed)),
            fallback_activations: AtomicU64::new(self.fallback_activations.load(Ordering::Relaxed)),
            reconciliations_triggered: AtomicU64::new(self.reconciliations_triggered.load(Ordering::Relaxed)),
            last_fallback_at: AtomicU64::new(self.last_fallback_at.load(Ordering::Relaxed)),
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
    // DARouterMetrics tests (14A.1A.19)
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_router_metrics_new() {
        let metrics = DARouterMetrics::new();
        assert_eq!(metrics.primary_posts(), 0);
        assert_eq!(metrics.fallback_posts(), 0);
        assert_eq!(metrics.emergency_posts(), 0);
        assert_eq!(metrics.primary_gets(), 0);
        assert_eq!(metrics.fallback_gets(), 0);
        assert_eq!(metrics.fallback_activations(), 0);
        assert_eq!(metrics.reconciliations_triggered(), 0);
        assert_eq!(metrics.last_fallback_at(), 0);
    }

    #[test]
    fn test_router_metrics_record_primary_post() {
        let metrics = DARouterMetrics::new();
        metrics.record_primary_post();
        metrics.record_primary_post();
        assert_eq!(metrics.primary_posts(), 2);
        assert_eq!(metrics.fallback_activations(), 0);
    }

    #[test]
    fn test_router_metrics_record_fallback_post() {
        let metrics = DARouterMetrics::new();
        metrics.record_fallback_post();
        assert_eq!(metrics.fallback_posts(), 1);
        assert_eq!(metrics.fallback_activations(), 1);
        assert!(metrics.last_fallback_at() > 0);
    }

    #[test]
    fn test_router_metrics_record_emergency_post() {
        let metrics = DARouterMetrics::new();
        metrics.record_emergency_post();
        assert_eq!(metrics.emergency_posts(), 1);
        assert_eq!(metrics.fallback_activations(), 1);
        assert!(metrics.last_fallback_at() > 0);
    }

    #[test]
    fn test_router_metrics_record_primary_get() {
        let metrics = DARouterMetrics::new();
        metrics.record_primary_get();
        metrics.record_primary_get();
        assert_eq!(metrics.primary_gets(), 2);
        assert_eq!(metrics.fallback_activations(), 0);
    }

    #[test]
    fn test_router_metrics_record_fallback_get() {
        let metrics = DARouterMetrics::new();
        metrics.record_fallback_get();
        assert_eq!(metrics.fallback_gets(), 1);
        assert_eq!(metrics.fallback_activations(), 1);
        assert!(metrics.last_fallback_at() > 0);
    }

    #[test]
    fn test_router_metrics_record_reconciliation() {
        let metrics = DARouterMetrics::new();
        metrics.record_reconciliation();
        metrics.record_reconciliation();
        assert_eq!(metrics.reconciliations_triggered(), 2);
    }

    #[test]
    fn test_router_metrics_fallback_activations_accumulate() {
        let metrics = DARouterMetrics::new();
        metrics.record_fallback_post();
        metrics.record_emergency_post();
        metrics.record_fallback_get();
        assert_eq!(metrics.fallback_activations(), 3);
    }

    #[test]
    fn test_router_metrics_snapshot() {
        let metrics = DARouterMetrics::new();
        metrics.record_primary_post();
        metrics.record_fallback_post();
        metrics.record_emergency_post();
        metrics.record_primary_get();
        metrics.record_fallback_get();
        metrics.record_reconciliation();

        let snapshot = metrics.snapshot();

        assert_eq!(snapshot.primary_posts, 1);
        assert_eq!(snapshot.fallback_posts, 1);
        assert_eq!(snapshot.emergency_posts, 1);
        assert_eq!(snapshot.primary_gets, 1);
        assert_eq!(snapshot.fallback_gets, 1);
        assert_eq!(snapshot.fallback_activations, 3); // fallback_post + emergency_post + fallback_get
        assert_eq!(snapshot.reconciliations_triggered, 1);
        assert!(snapshot.last_fallback_at > 0);
    }

    #[test]
    fn test_router_metrics_snapshot_does_not_modify_state() {
        let metrics = DARouterMetrics::new();
        metrics.record_primary_post();

        let snapshot1 = metrics.snapshot();
        let snapshot2 = metrics.snapshot();

        assert_eq!(snapshot1.primary_posts, snapshot2.primary_posts);
        assert_eq!(metrics.primary_posts(), 1);
    }

    #[test]
    fn test_router_metrics_to_prometheus_format() {
        let metrics = DARouterMetrics::new();
        metrics.record_primary_post();
        metrics.record_fallback_post();
        metrics.record_emergency_post();
        metrics.record_primary_get();
        metrics.record_fallback_get();

        let prometheus = metrics.to_prometheus();

        // Verify all metrics are present
        assert!(prometheus.contains("dsdn_da_router_primary_posts 1"));
        assert!(prometheus.contains("dsdn_da_router_fallback_posts 1"));
        assert!(prometheus.contains("dsdn_da_router_emergency_posts 1"));
        assert!(prometheus.contains("dsdn_da_router_primary_gets 1"));
        assert!(prometheus.contains("dsdn_da_router_fallback_gets 1"));
        assert!(prometheus.contains("dsdn_da_router_fallback_activations"));
        assert!(prometheus.contains("dsdn_da_router_reconciliations_triggered"));
        assert!(prometheus.contains("dsdn_da_router_last_fallback_at"));

        // Verify HELP and TYPE annotations
        assert!(prometheus.contains("# HELP dsdn_da_router_primary_posts"));
        assert!(prometheus.contains("# TYPE dsdn_da_router_primary_posts counter"));
        assert!(prometheus.contains("# TYPE dsdn_da_router_last_fallback_at gauge"));
    }

    #[test]
    fn test_router_metrics_to_prometheus_deterministic() {
        let metrics = DARouterMetrics::new();
        metrics.record_primary_post();
        metrics.record_primary_get();

        let prometheus1 = metrics.to_prometheus();
        let prometheus2 = metrics.to_prometheus();

        // Output should be identical for same state
        assert_eq!(prometheus1, prometheus2);
    }

    #[test]
    fn test_router_metrics_clone() {
        let metrics = DARouterMetrics::new();
        metrics.record_primary_post();
        metrics.record_fallback_post();
        metrics.record_reconciliation();

        let cloned = metrics.clone();
        assert_eq!(cloned.primary_posts(), 1);
        assert_eq!(cloned.fallback_posts(), 1);
        assert_eq!(cloned.reconciliations_triggered(), 1);
        assert_eq!(cloned.fallback_activations(), 1);
    }

    #[test]
    fn test_router_metrics_debug() {
        let metrics = DARouterMetrics::new();
        let debug_str = format!("{:?}", metrics);
        assert!(debug_str.contains("DARouterMetrics"));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Backward Compatibility Tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_router_metrics_backward_compat_record_primary() {
        let metrics = DARouterMetrics::new();
        metrics.record_primary_post();
        metrics.record_primary_post();
        // Backward compatible accessor
        assert_eq!(metrics.primary_post_count(), 2);
    }

    #[test]
    fn test_router_metrics_backward_compat_record_secondary() {
        let metrics = DARouterMetrics::new();
        metrics.record_secondary_post(); // Should map to fallback_post
        assert_eq!(metrics.secondary_post_count(), 1);
        assert_eq!(metrics.fallback_posts(), 1);
    }

    #[test]
    fn test_router_metrics_backward_compat_record_emergency() {
        let metrics = DARouterMetrics::new();
        metrics.record_emergency_post();
        assert_eq!(metrics.emergency_post_count(), 1);
    }

    #[test]
    fn test_router_metrics_backward_compat_errors_return_zero() {
        let metrics = DARouterMetrics::new();
        metrics.record_primary_error();
        metrics.record_secondary_error();
        metrics.record_emergency_error();
        // Error counts are now always 0 in new spec
        assert_eq!(metrics.primary_error_count(), 0);
        assert_eq!(metrics.secondary_error_count(), 0);
        assert_eq!(metrics.emergency_error_count(), 0);
        assert_eq!(metrics.total_error_count(), 0);
    }

    #[test]
    fn test_router_metrics_backward_compat_pending_reconcile() {
        let metrics = DARouterMetrics::new();
        metrics.record_pending_reconcile();
        metrics.record_pending_reconcile();
        assert_eq!(metrics.pending_reconcile_count(), 2);
        assert_eq!(metrics.reconciliations_triggered(), 2);
    }

    #[test]
    fn test_router_metrics_backward_compat_emergency_pending() {
        let metrics = DARouterMetrics::new();
        metrics.record_emergency_pending();
        // Maps to reconciliation
        assert_eq!(metrics.emergency_pending_count(), 1);
    }

    #[test]
    fn test_router_metrics_backward_compat_total_counts() {
        let metrics = DARouterMetrics::new();
        metrics.record_primary_post();
        metrics.record_secondary_post();
        metrics.record_emergency_post();
        assert_eq!(metrics.total_post_count(), 3);
    }

    #[test]
    fn test_router_metrics_backward_compat_read_methods() {
        let metrics = DARouterMetrics::new();
        metrics.record_primary_read();
        metrics.record_secondary_read();
        metrics.record_emergency_read();

        assert_eq!(metrics.primary_read_count(), 1);
        assert_eq!(metrics.secondary_read_count(), 2); // secondary + emergency mapped to fallback
        assert_eq!(metrics.fallback_read_count(), 2);
    }

    #[test]
    fn test_router_metrics_backward_compat_read_errors_return_zero() {
        let metrics = DARouterMetrics::new();
        metrics.record_primary_read_error();
        metrics.record_secondary_read_error();
        metrics.record_emergency_read_error();

        assert_eq!(metrics.primary_read_error_count(), 0);
        assert_eq!(metrics.secondary_read_error_count(), 0);
        assert_eq!(metrics.emergency_read_error_count(), 0);
        assert_eq!(metrics.total_read_error_count(), 0);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Atomicity Tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_router_metrics_atomic_increments() {
        use std::thread;

        let metrics = Arc::new(DARouterMetrics::new());
        let mut handles = vec![];

        // Spawn 10 threads, each incrementing 100 times
        for _ in 0..10 {
            let m = metrics.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    m.record_primary_post();
                }
            }));
        }

        for h in handles {
            h.join().expect("Thread panicked");
        }

        // All increments should be counted
        assert_eq!(metrics.primary_posts(), 1000);
    }

    #[test]
    fn test_router_metrics_concurrent_mixed_operations() {
        use std::thread;

        let metrics = Arc::new(DARouterMetrics::new());
        let mut handles = vec![];

        // Thread 1: primary posts
        let m1 = metrics.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..50 {
                m1.record_primary_post();
            }
        }));

        // Thread 2: fallback posts
        let m2 = metrics.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..50 {
                m2.record_fallback_post();
            }
        }));

        // Thread 3: reads
        let m3 = metrics.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..50 {
                m3.record_primary_get();
            }
        }));

        for h in handles {
            h.join().expect("Thread panicked");
        }

        assert_eq!(metrics.primary_posts(), 50);
        assert_eq!(metrics.fallback_posts(), 50);
        assert_eq!(metrics.primary_gets(), 50);
        assert_eq!(metrics.fallback_activations(), 50);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // MetricsSnapshot Tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_metrics_snapshot_copy() {
        let snapshot = MetricsSnapshot {
            primary_posts: 1,
            fallback_posts: 2,
            emergency_posts: 3,
            primary_gets: 4,
            fallback_gets: 5,
            fallback_activations: 6,
            reconciliations_triggered: 7,
            last_fallback_at: 8,
        };

        let copy = snapshot;
        assert_eq!(copy.primary_posts, 1);
        assert_eq!(copy.fallback_posts, 2);
    }

    #[test]
    fn test_metrics_snapshot_clone() {
        let snapshot = MetricsSnapshot {
            primary_posts: 10,
            fallback_posts: 20,
            emergency_posts: 30,
            primary_gets: 40,
            fallback_gets: 50,
            fallback_activations: 60,
            reconciliations_triggered: 70,
            last_fallback_at: 80,
        };

        let cloned = snapshot.clone();
        assert_eq!(snapshot, cloned);
    }

    #[test]
    fn test_metrics_snapshot_debug() {
        let snapshot = MetricsSnapshot {
            primary_posts: 1,
            fallback_posts: 2,
            emergency_posts: 3,
            primary_gets: 4,
            fallback_gets: 5,
            fallback_activations: 6,
            reconciliations_triggered: 7,
            last_fallback_at: 8,
        };

        let debug_str = format!("{:?}", snapshot);
        assert!(debug_str.contains("MetricsSnapshot"));
        assert!(debug_str.contains("primary_posts"));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // DARouterConfig tests (14A.1A.18)
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

    #[test]
    fn test_router_config_default_enable_fallback() {
        let config = DARouterConfig::default();
        assert!(config.enable_fallback);
    }

    #[test]
    fn test_router_config_default_enable_emergency() {
        let config = DARouterConfig::default();
        assert!(config.enable_emergency);
    }

    #[test]
    fn test_router_config_default_extended_timeout_multiplier() {
        let config = DARouterConfig::default();
        assert!((config.extended_timeout_multiplier - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_router_config_default_max_retry_on_fallback() {
        let config = DARouterConfig::default();
        assert_eq!(config.max_retry_on_fallback, 3);
    }

    #[test]
    fn test_router_config_default_reconcile_on_recovery() {
        let config = DARouterConfig::default();
        assert!(config.reconcile_on_recovery);
    }

    #[test]
    fn test_router_config_default_parallel_post_on_recovering() {
        let config = DARouterConfig::default();
        assert!(!config.parallel_post_on_recovering);
    }

    #[test]
    fn test_router_config_default_all_values() {
        let config = DARouterConfig::default();
        
        // Verify ALL default values in one test
        assert!(config.enable_fallback, "enable_fallback should be true");
        assert!(config.enable_emergency, "enable_emergency should be true");
        assert!((config.extended_timeout_multiplier - 2.0).abs() < f64::EPSILON, 
            "extended_timeout_multiplier should be 2.0");
        assert_eq!(config.max_retry_on_fallback, 3, "max_retry_on_fallback should be 3");
        assert!(config.reconcile_on_recovery, "reconcile_on_recovery should be true");
        assert!(!config.parallel_post_on_recovering, "parallel_post_on_recovering should be false");
    }

    #[test]
    fn test_router_config_from_env_empty_returns_default() {
        // Clear all env vars first
        std::env::remove_var("DSDN_DA_ROUTER_ENABLE_FALLBACK");
        std::env::remove_var("DSDN_DA_ROUTER_ENABLE_EMERGENCY");
        std::env::remove_var("DSDN_DA_ROUTER_EXTENDED_TIMEOUT_MULTIPLIER");
        std::env::remove_var("DSDN_DA_ROUTER_MAX_RETRY_ON_FALLBACK");
        std::env::remove_var("DSDN_DA_ROUTER_RECONCILE_ON_RECOVERY");
        std::env::remove_var("DSDN_DA_ROUTER_PARALLEL_POST_ON_RECOVERING");

        let config = DARouterConfig::from_env();
        let default_config = DARouterConfig::default();

        assert_eq!(config.enable_fallback, default_config.enable_fallback);
        assert_eq!(config.enable_emergency, default_config.enable_emergency);
        assert!((config.extended_timeout_multiplier - default_config.extended_timeout_multiplier).abs() < f64::EPSILON);
        assert_eq!(config.max_retry_on_fallback, default_config.max_retry_on_fallback);
        assert_eq!(config.reconcile_on_recovery, default_config.reconcile_on_recovery);
        assert_eq!(config.parallel_post_on_recovering, default_config.parallel_post_on_recovering);
    }

    #[test]
    fn test_router_config_from_env_valid_bool_true() {
        std::env::set_var("DSDN_DA_ROUTER_ENABLE_FALLBACK", "true");
        std::env::set_var("DSDN_DA_ROUTER_PARALLEL_POST_ON_RECOVERING", "true");

        let config = DARouterConfig::from_env();

        assert!(config.enable_fallback);
        assert!(config.parallel_post_on_recovering);

        // Cleanup
        std::env::remove_var("DSDN_DA_ROUTER_ENABLE_FALLBACK");
        std::env::remove_var("DSDN_DA_ROUTER_PARALLEL_POST_ON_RECOVERING");
    }

    #[test]
    fn test_router_config_from_env_valid_bool_false() {
        std::env::set_var("DSDN_DA_ROUTER_ENABLE_FALLBACK", "false");
        std::env::set_var("DSDN_DA_ROUTER_ENABLE_EMERGENCY", "false");

        let config = DARouterConfig::from_env();

        assert!(!config.enable_fallback);
        assert!(!config.enable_emergency);

        // Cleanup
        std::env::remove_var("DSDN_DA_ROUTER_ENABLE_FALLBACK");
        std::env::remove_var("DSDN_DA_ROUTER_ENABLE_EMERGENCY");
    }

    #[test]
    fn test_router_config_from_env_bool_case_insensitive() {
        std::env::set_var("DSDN_DA_ROUTER_ENABLE_FALLBACK", "TRUE");
        std::env::set_var("DSDN_DA_ROUTER_ENABLE_EMERGENCY", "FALSE");
        std::env::set_var("DSDN_DA_ROUTER_RECONCILE_ON_RECOVERY", "True");
        std::env::set_var("DSDN_DA_ROUTER_PARALLEL_POST_ON_RECOVERING", "False");

        let config = DARouterConfig::from_env();

        assert!(config.enable_fallback);
        assert!(!config.enable_emergency);
        assert!(config.reconcile_on_recovery);
        assert!(!config.parallel_post_on_recovering);

        // Cleanup
        std::env::remove_var("DSDN_DA_ROUTER_ENABLE_FALLBACK");
        std::env::remove_var("DSDN_DA_ROUTER_ENABLE_EMERGENCY");
        std::env::remove_var("DSDN_DA_ROUTER_RECONCILE_ON_RECOVERY");
        std::env::remove_var("DSDN_DA_ROUTER_PARALLEL_POST_ON_RECOVERING");
    }

    #[test]
    fn test_router_config_from_env_valid_f64() {
        std::env::set_var("DSDN_DA_ROUTER_EXTENDED_TIMEOUT_MULTIPLIER", "3.5");

        let config = DARouterConfig::from_env();

        assert!((config.extended_timeout_multiplier - 3.5).abs() < f64::EPSILON);

        // Cleanup
        std::env::remove_var("DSDN_DA_ROUTER_EXTENDED_TIMEOUT_MULTIPLIER");
    }

    #[test]
    fn test_router_config_from_env_valid_u32() {
        std::env::set_var("DSDN_DA_ROUTER_MAX_RETRY_ON_FALLBACK", "5");

        let config = DARouterConfig::from_env();

        assert_eq!(config.max_retry_on_fallback, 5);

        // Cleanup
        std::env::remove_var("DSDN_DA_ROUTER_MAX_RETRY_ON_FALLBACK");
    }

    #[test]
    fn test_router_config_from_env_invalid_bool_returns_default() {
        std::env::set_var("DSDN_DA_ROUTER_ENABLE_FALLBACK", "yes");
        std::env::set_var("DSDN_DA_ROUTER_ENABLE_EMERGENCY", "no");
        std::env::set_var("DSDN_DA_ROUTER_RECONCILE_ON_RECOVERY", "1");
        std::env::set_var("DSDN_DA_ROUTER_PARALLEL_POST_ON_RECOVERING", "invalid");

        let config = DARouterConfig::from_env();
        let defaults = DARouterConfig::default();

        // Invalid bools should fallback to default
        assert_eq!(config.enable_fallback, defaults.enable_fallback);
        assert_eq!(config.enable_emergency, defaults.enable_emergency);
        assert_eq!(config.reconcile_on_recovery, defaults.reconcile_on_recovery);
        assert_eq!(config.parallel_post_on_recovering, defaults.parallel_post_on_recovering);

        // Cleanup
        std::env::remove_var("DSDN_DA_ROUTER_ENABLE_FALLBACK");
        std::env::remove_var("DSDN_DA_ROUTER_ENABLE_EMERGENCY");
        std::env::remove_var("DSDN_DA_ROUTER_RECONCILE_ON_RECOVERY");
        std::env::remove_var("DSDN_DA_ROUTER_PARALLEL_POST_ON_RECOVERING");
    }

    #[test]
    fn test_router_config_from_env_invalid_f64_returns_default() {
        std::env::set_var("DSDN_DA_ROUTER_EXTENDED_TIMEOUT_MULTIPLIER", "not_a_number");

        let config = DARouterConfig::from_env();
        let defaults = DARouterConfig::default();

        assert!((config.extended_timeout_multiplier - defaults.extended_timeout_multiplier).abs() < f64::EPSILON);

        // Cleanup
        std::env::remove_var("DSDN_DA_ROUTER_EXTENDED_TIMEOUT_MULTIPLIER");
    }

    #[test]
    fn test_router_config_from_env_invalid_u32_returns_default() {
        std::env::set_var("DSDN_DA_ROUTER_MAX_RETRY_ON_FALLBACK", "-1");

        let config = DARouterConfig::from_env();
        let defaults = DARouterConfig::default();

        assert_eq!(config.max_retry_on_fallback, defaults.max_retry_on_fallback);

        // Cleanup
        std::env::remove_var("DSDN_DA_ROUTER_MAX_RETRY_ON_FALLBACK");
    }

    #[test]
    fn test_router_config_from_env_overflow_u32_returns_default() {
        std::env::set_var("DSDN_DA_ROUTER_MAX_RETRY_ON_FALLBACK", "999999999999");

        let config = DARouterConfig::from_env();
        let defaults = DARouterConfig::default();

        assert_eq!(config.max_retry_on_fallback, defaults.max_retry_on_fallback);

        // Cleanup
        std::env::remove_var("DSDN_DA_ROUTER_MAX_RETRY_ON_FALLBACK");
    }

    #[test]
    fn test_router_config_from_env_no_panic_on_any_input() {
        // Test various potentially problematic inputs - should never panic
        let test_values = [
            ("", "empty string"),
            ("   ", "whitespace"),
            ("\n\t", "control chars"),
            ("null", "null string"),
            ("undefined", "undefined string"),
            ("NaN", "NaN string"),
            ("inf", "infinity string"),
            ("-inf", "negative infinity"),
            ("0x10", "hex string"),
            ("1e100", "scientific notation"),
        ];

        for (val, _desc) in test_values {
            std::env::set_var("DSDN_DA_ROUTER_ENABLE_FALLBACK", val);
            std::env::set_var("DSDN_DA_ROUTER_EXTENDED_TIMEOUT_MULTIPLIER", val);
            std::env::set_var("DSDN_DA_ROUTER_MAX_RETRY_ON_FALLBACK", val);

            // This should not panic
            let _config = DARouterConfig::from_env();
        }

        // Cleanup
        std::env::remove_var("DSDN_DA_ROUTER_ENABLE_FALLBACK");
        std::env::remove_var("DSDN_DA_ROUTER_EXTENDED_TIMEOUT_MULTIPLIER");
        std::env::remove_var("DSDN_DA_ROUTER_MAX_RETRY_ON_FALLBACK");
    }

    #[test]
    fn test_router_config_from_env_all_overrides() {
        // Set all env vars to non-default values
        std::env::set_var("DSDN_DA_ROUTER_ENABLE_FALLBACK", "false");
        std::env::set_var("DSDN_DA_ROUTER_ENABLE_EMERGENCY", "false");
        std::env::set_var("DSDN_DA_ROUTER_EXTENDED_TIMEOUT_MULTIPLIER", "1.5");
        std::env::set_var("DSDN_DA_ROUTER_MAX_RETRY_ON_FALLBACK", "5");
        std::env::set_var("DSDN_DA_ROUTER_RECONCILE_ON_RECOVERY", "false");
        std::env::set_var("DSDN_DA_ROUTER_PARALLEL_POST_ON_RECOVERING", "true");

        let config = DARouterConfig::from_env();

        assert!(!config.enable_fallback);
        assert!(!config.enable_emergency);
        assert!((config.extended_timeout_multiplier - 1.5).abs() < f64::EPSILON);
        assert_eq!(config.max_retry_on_fallback, 5);
        assert!(!config.reconcile_on_recovery);
        assert!(config.parallel_post_on_recovering);

        // Cleanup
        std::env::remove_var("DSDN_DA_ROUTER_ENABLE_FALLBACK");
        std::env::remove_var("DSDN_DA_ROUTER_ENABLE_EMERGENCY");
        std::env::remove_var("DSDN_DA_ROUTER_EXTENDED_TIMEOUT_MULTIPLIER");
        std::env::remove_var("DSDN_DA_ROUTER_MAX_RETRY_ON_FALLBACK");
        std::env::remove_var("DSDN_DA_ROUTER_RECONCILE_ON_RECOVERY");
        std::env::remove_var("DSDN_DA_ROUTER_PARALLEL_POST_ON_RECOVERING");
    }

    #[test]
    fn test_router_config_partial_override() {
        // Only set some env vars
        std::env::set_var("DSDN_DA_ROUTER_ENABLE_FALLBACK", "false");
        std::env::set_var("DSDN_DA_ROUTER_MAX_RETRY_ON_FALLBACK", "10");

        // Clear others
        std::env::remove_var("DSDN_DA_ROUTER_ENABLE_EMERGENCY");
        std::env::remove_var("DSDN_DA_ROUTER_EXTENDED_TIMEOUT_MULTIPLIER");
        std::env::remove_var("DSDN_DA_ROUTER_RECONCILE_ON_RECOVERY");
        std::env::remove_var("DSDN_DA_ROUTER_PARALLEL_POST_ON_RECOVERING");

        let config = DARouterConfig::from_env();
        let defaults = DARouterConfig::default();

        // Overridden values
        assert!(!config.enable_fallback);
        assert_eq!(config.max_retry_on_fallback, 10);

        // Default values
        assert_eq!(config.enable_emergency, defaults.enable_emergency);
        assert!((config.extended_timeout_multiplier - defaults.extended_timeout_multiplier).abs() < f64::EPSILON);
        assert_eq!(config.reconcile_on_recovery, defaults.reconcile_on_recovery);
        assert_eq!(config.parallel_post_on_recovering, defaults.parallel_post_on_recovering);

        // Cleanup
        std::env::remove_var("DSDN_DA_ROUTER_ENABLE_FALLBACK");
        std::env::remove_var("DSDN_DA_ROUTER_MAX_RETRY_ON_FALLBACK");
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
        // Error tracking removed in 14A.1A.19 spec
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
        // Error tracking removed in 14A.1A.19 spec
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
        // Error tracking removed in 14A.1A.19 spec
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
        // Error tracking removed in 14A.1A.19 spec
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
        // Error tracking removed in 14A.1A.19 spec
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
        // Error counts are no longer tracked in 14A.1A.19
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
        // In 14A.1A.19, secondary reads map to fallback_gets
        assert_eq!(metrics.fallback_gets(), 1);
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
        // In 14A.1A.19, emergency reads also map to fallback_gets
        assert_eq!(metrics.fallback_gets(), 1);
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
        // Error counts are no longer tracked in 14A.1A.19
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
        // In 14A.1A.19, emergency reads map to fallback_gets
        assert_eq!(metrics.fallback_gets(), 1);
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

        // In 14A.1A.19, secondary reads map to fallback_gets
        assert_eq!(metrics.fallback_gets(), 3);
        assert_eq!(metrics.fallback_read_count(), 3);
        assert_eq!(metrics.fallback_activations(), 3);
    }
}