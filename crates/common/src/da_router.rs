//! # DA Router (14A.1A.15)
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
//! ## Usage
//!
//! ```rust,ignore
//! let router = DARouter::new(primary, health, config, metrics)
//!     .with_fallbacks(Some(secondary), Some(emergency));
//! ```

use std::sync::Arc;

use crate::da::DALayer;
use crate::da_health_monitor::DAHealthMonitor;

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
// DA ROUTER METRICS
// ════════════════════════════════════════════════════════════════════════════════

/// Metrics internal untuk DARouter.
///
/// Placeholder struct untuk tahap ini.
/// Akan diperluas di tahap berikutnya dengan:
/// - Request counters per DA source
/// - Latency histograms
/// - Error rates
///
/// ## Thread Safety
///
/// Struct ini adalah plain data, Send + Sync safe.
/// Metrics aktual akan menggunakan atomic counters.
#[derive(Debug, Clone, Default)]
pub struct DARouterMetrics {
    /// Placeholder field untuk metrics.
    ///
    /// Akan diganti dengan atomic counters di tahap berikutnya.
    _placeholder: (),
}

impl DARouterMetrics {
    /// Membuat metrics baru dengan nilai awal.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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
/// | `health` | `Arc<DAHealthMonitor>` | Monitor kesehatan DA |
/// | `config` | `DARouterConfig` | Konfigurasi routing |
/// | `metrics` | `DARouterMetrics` | Metrics internal |
///
/// ## Thread Safety
///
/// Semua field menggunakan `Arc` atau plain data.
/// Struct ini adalah Send + Sync.
///
/// ## Routing Logic
///
/// Routing logic belum diimplementasikan di tahap ini.
/// Akan ditambahkan di tahap berikutnya berdasarkan:
/// - Status dari `DAHealthMonitor`
/// - Policy dari `DARouterConfig`
///
/// ## Example
///
/// ```rust,ignore
/// let primary: Arc<dyn DALayer> = Arc::new(CelestiaDA::new(...));
/// let health = Arc::new(DAHealthMonitor::new(config));
/// let router_config = DARouterConfig::new();
/// let metrics = DARouterMetrics::new();
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

    /// Monitor kesehatan DA.
    ///
    /// Referensi tunggal ke DAHealthMonitor.
    /// Digunakan untuk keputusan routing (di tahap berikutnya).
    health: Arc<DAHealthMonitor>,

    /// Konfigurasi router.
    ///
    /// Menentukan policy routing dan behavior.
    config: DARouterConfig,

    /// Metrics internal router.
    ///
    /// Tracking request counts, latencies, dan errors.
    metrics: DARouterMetrics,
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
    /// * `health` - Monitor kesehatan DA
    /// * `config` - Konfigurasi router
    /// * `metrics` - Metrics internal
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
    /// let router = DARouter::new(primary, health, config, metrics);
    /// ```
    #[must_use]
    pub fn new(
        primary: Arc<dyn DALayer>,
        health: Arc<DAHealthMonitor>,
        config: DARouterConfig,
        metrics: DARouterMetrics,
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

    /// Mendapatkan reference ke health monitor.
    #[inline]
    #[must_use]
    pub fn health(&self) -> &Arc<DAHealthMonitor> {
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
    pub fn metrics(&self) -> &DARouterMetrics {
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
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::da::{DAConfig, DAError, DAHealthStatus, BlobRef, BlobStream, DAMetricsSnapshot};
    use std::future::Future;
    use std::pin::Pin;

    // ────────────────────────────────────────────────────────────────────────────
    // Mock DALayer for testing
    // ────────────────────────────────────────────────────────────────────────────

    /// Mock DALayer untuk testing.
    ///
    /// Implementasi minimal yang tidak melakukan operasi nyata.
    /// Semua method async mengembalikan error karena ini hanya untuk testing struktur.
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
            Box::pin(async {
                Err(DAError::Other("mock: not implemented".to_string()))
            })
        }

        fn get_blob(
            &self,
            _ref_: &BlobRef,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, DAError>> + Send + '_>> {
            Box::pin(async {
                Err(DAError::Other("mock: not implemented".to_string()))
            })
        }

        fn subscribe_blobs(
            &self,
            _from_height: Option<u64>,
        ) -> Pin<Box<dyn Future<Output = Result<BlobStream, DAError>> + Send + '_>> {
            Box::pin(async {
                Err(DAError::Other("mock: not implemented".to_string()))
            })
        }

        fn health_check(
            &self,
        ) -> Pin<Box<dyn Future<Output = Result<DAHealthStatus, DAError>> + Send + '_>> {
            Box::pin(async {
                Ok(DAHealthStatus::Healthy)
            })
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

    fn create_health_monitor() -> Arc<DAHealthMonitor> {
        let config = DAConfig::default();
        Arc::new(DAHealthMonitor::new(config))
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
    // DARouterMetrics tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_router_metrics_new() {
        let metrics = DARouterMetrics::new();
        // Metrics should be created without panic
        let _ = metrics;
    }

    #[test]
    fn test_router_metrics_clone() {
        let metrics = DARouterMetrics::new();
        let cloned = metrics.clone();
        // Both should exist without panic
        let _ = (metrics, cloned);
    }

    #[test]
    fn test_router_metrics_debug() {
        let metrics = DARouterMetrics::new();
        let debug_str = format!("{:?}", metrics);
        assert!(debug_str.contains("DARouterMetrics"));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // DARouter::new() tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_darouter_new_creates_instance() {
        let primary = create_mock_da();
        let health = create_health_monitor();
        let config = DARouterConfig::new();
        let metrics = DARouterMetrics::new();

        let router = DARouter::new(primary, health, config, metrics);

        // Router should be created without panic
        let _ = router;
    }

    #[test]
    fn test_darouter_new_secondary_is_none() {
        let primary = create_mock_da();
        let health = create_health_monitor();
        let config = DARouterConfig::new();
        let metrics = DARouterMetrics::new();

        let router = DARouter::new(primary, health, config, metrics);

        assert!(router.secondary().is_none());
        assert!(!router.has_secondary());
    }

    #[test]
    fn test_darouter_new_emergency_is_none() {
        let primary = create_mock_da();
        let health = create_health_monitor();
        let config = DARouterConfig::new();
        let metrics = DARouterMetrics::new();

        let router = DARouter::new(primary, health, config, metrics);

        assert!(router.emergency().is_none());
        assert!(!router.has_emergency());
    }

    #[test]
    fn test_darouter_new_primary_accessible() {
        let primary = create_mock_da();
        let health = create_health_monitor();
        let config = DARouterConfig::new();
        let metrics = DARouterMetrics::new();

        let router = DARouter::new(primary, health, config, metrics);

        // Should be able to access primary
        let _ = router.primary();
    }

    #[test]
    fn test_darouter_new_health_accessible() {
        let primary = create_mock_da();
        let health = create_health_monitor();
        let config = DARouterConfig::new();
        let metrics = DARouterMetrics::new();

        let router = DARouter::new(primary, health, config, metrics);

        // Should be able to access health
        let _ = router.health();
    }

    #[test]
    fn test_darouter_new_config_is_set() {
        let primary = create_mock_da();
        let health = create_health_monitor();
        let config = DARouterConfig::new();
        let metrics = DARouterMetrics::new();

        let router = DARouter::new(primary, health, config.clone(), metrics);

        assert_eq!(router.config(), &config);
    }

    #[test]
    fn test_darouter_new_metrics_accessible() {
        let primary = create_mock_da();
        let health = create_health_monitor();
        let config = DARouterConfig::new();
        let metrics = DARouterMetrics::new();

        let router = DARouter::new(primary, health, config, metrics);

        // Should be able to access metrics
        let _ = router.metrics();
    }

    #[test]
    fn test_darouter_new_sources_count_is_one() {
        let primary = create_mock_da();
        let health = create_health_monitor();
        let config = DARouterConfig::new();
        let metrics = DARouterMetrics::new();

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
        let metrics = DARouterMetrics::new();

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
        let metrics = DARouterMetrics::new();

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
        let metrics = DARouterMetrics::new();

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
        let metrics = DARouterMetrics::new();

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
        let metrics = DARouterMetrics::new();

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
        let metrics = DARouterMetrics::new();

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
        let metrics = DARouterMetrics::new();

        let router = DARouter::new(primary, health, config, metrics)
            .with_fallbacks(None, None);

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
        let metrics = DARouterMetrics::new();

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
        let metrics = DARouterMetrics::new();

        // This should compile and work
        let router = DARouter::new(primary, health, config, metrics)
            .with_fallbacks(Some(secondary), None);

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
        let metrics = DARouterMetrics::new();

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
        let metrics = DARouterMetrics::new();

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
            let metrics = DARouterMetrics::new();
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
            let metrics = DARouterMetrics::new();
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
        let metrics = DARouterMetrics::new();

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
        let metrics = DARouterMetrics::new();

        let router = DARouter::new(primary, health, config, metrics)
            .with_fallbacks(Some(secondary), Some(emergency));

        // Accessors should be consistent
        assert!(router.has_secondary());
        assert!(router.secondary().is_some());
        assert!(router.has_emergency());
        assert!(router.emergency().is_some());
    }
}