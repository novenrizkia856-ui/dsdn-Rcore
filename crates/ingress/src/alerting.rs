//! # Alerting Hooks Module (14A.1A.68)
//!
//! Menyediakan mekanisme hook alerting untuk merespons transisi fallback
//! dan proses rekonsiliasi.
//!
//! ## Prinsip Desain
//!
//! - Hook TIDAK boleh blocking critical path
//! - Error handling HARUS eksplisit
//! - Tidak ada silent failure
//! - Semua hook adalah fire-and-forget (async spawn)
//!
//! ## Implementasi
//!
//! - `LoggingAlertHandler`: Default handler menggunakan tracing
//! - `WebhookAlertHandler`: HTTP notification ke endpoint eksternal
//!
//! ## Thread Safety
//!
//! Semua handler implement Send + Sync untuk penggunaan lintas thread.

use serde::Serialize;
use std::time::Duration;
use tracing::{error, info, warn};

// Re-export FallbackHealthInfo untuk convenience
pub use crate::FallbackHealthInfo;

// ════════════════════════════════════════════════════════════════════════════
// RECONCILE REPORT STRUCT
// ════════════════════════════════════════════════════════════════════════════

/// Laporan hasil rekonsiliasi.
///
/// Merepresentasikan hasil dari proses rekonsiliasi data
/// antara fallback DA dan primary DA.
///
/// ## Field Meanings
///
/// - `items_processed`: Jumlah item yang berhasil diproses
/// - `items_failed`: Jumlah item yang gagal diproses
/// - `duration_ms`: Durasi proses rekonsiliasi dalam milliseconds
/// - `source`: Sumber data yang direkonsiliasi ("primary", "secondary", "emergency")
/// - `error`: Error message jika ada kegagalan
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReconcileReport {
    /// Jumlah item yang berhasil diproses.
    pub items_processed: u64,

    /// Jumlah item yang gagal diproses.
    pub items_failed: u64,

    /// Durasi proses rekonsiliasi dalam milliseconds.
    pub duration_ms: u64,

    /// Sumber data yang direkonsiliasi.
    ///
    /// Values: "primary", "secondary", "emergency"
    pub source: String,

    /// Error message jika ada kegagalan.
    ///
    /// `Some(error)` jika ada error selama rekonsiliasi.
    /// `None` jika tidak ada error.
    pub error: Option<String>,
}

impl ReconcileReport {
    /// Membuat ReconcileReport untuk operasi sukses.
    ///
    /// ## Parameters
    ///
    /// - `items_processed`: Jumlah item yang berhasil diproses
    /// - `duration_ms`: Durasi proses dalam milliseconds
    /// - `source`: Sumber data yang direkonsiliasi
    #[must_use]
    pub fn success(items_processed: u64, duration_ms: u64, source: impl Into<String>) -> Self {
        Self {
            items_processed,
            items_failed: 0,
            duration_ms,
            source: source.into(),
            error: None,
        }
    }

    /// Membuat ReconcileReport untuk operasi dengan kegagalan partial.
    ///
    /// ## Parameters
    ///
    /// - `items_processed`: Jumlah item yang berhasil diproses
    /// - `items_failed`: Jumlah item yang gagal
    /// - `duration_ms`: Durasi proses dalam milliseconds
    /// - `source`: Sumber data yang direkonsiliasi
    /// - `error`: Error message
    #[must_use]
    pub fn partial_failure(
        items_processed: u64,
        items_failed: u64,
        duration_ms: u64,
        source: impl Into<String>,
        error: impl Into<String>,
    ) -> Self {
        Self {
            items_processed,
            items_failed,
            duration_ms,
            source: source.into(),
            error: Some(error.into()),
        }
    }

    /// Check if the reconciliation was fully successful.
    #[inline]
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.items_failed == 0 && self.error.is_none()
    }

    /// Get total items attempted.
    #[inline]
    #[must_use]
    pub fn total_items(&self) -> u64 {
        self.items_processed.saturating_add(self.items_failed)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// ALERT HANDLER TRAIT
// ════════════════════════════════════════════════════════════════════════════

/// Trait untuk handling alert events dari sistem fallback.
///
/// ## Kontrak
///
/// - Method TIDAK BOLEH panic
/// - Method TIDAK BOLEH block sistem utama
/// - Error handling HARUS eksplisit
/// - Tidak ada silent failure
///
/// ## Thread Safety
///
/// Handler HARUS implement Send + Sync untuk penggunaan lintas thread.
///
/// ## Implementasi
///
/// ```rust,ignore
/// struct MyHandler;
///
/// impl AlertHandler for MyHandler {
///     fn on_fallback_activated(&self, info: &FallbackHealthInfo) {
///         // Handle activation
///     }
///
///     fn on_fallback_deactivated(&self, duration_secs: u64) {
///         // Handle deactivation
///     }
///
///     fn on_reconciliation_complete(&self, report: &ReconcileReport) {
///         // Handle reconciliation
///     }
/// }
/// ```
pub trait AlertHandler: Send + Sync {
    /// Dipanggil ketika fallback mode diaktifkan.
    ///
    /// ## Parameters
    ///
    /// - `info`: FallbackHealthInfo pada saat aktivasi
    ///
    /// ## Guarantees
    ///
    /// - TIDAK BOLEH panic
    /// - TIDAK BOLEH block (harus return segera)
    /// - Error harus di-log, bukan propagate
    fn on_fallback_activated(&self, info: &FallbackHealthInfo);

    /// Dipanggil ketika fallback mode dinonaktifkan.
    ///
    /// ## Parameters
    ///
    /// - `duration_secs`: Durasi fallback aktif dalam detik
    ///
    /// ## Guarantees
    ///
    /// - TIDAK BOLEH panic
    /// - TIDAK BOLEH block (harus return segera)
    /// - Error harus di-log, bukan propagate
    fn on_fallback_deactivated(&self, duration_secs: u64);

    /// Dipanggil ketika rekonsiliasi selesai.
    ///
    /// ## Parameters
    ///
    /// - `report`: Laporan hasil rekonsiliasi
    ///
    /// ## Guarantees
    ///
    /// - TIDAK BOLEH panic
    /// - TIDAK BOLEH block (harus return segera)
    /// - Error harus di-log, bukan propagate
    fn on_reconciliation_complete(&self, report: &ReconcileReport);
}

// ════════════════════════════════════════════════════════════════════════════
// LOGGING ALERT HANDLER
// ════════════════════════════════════════════════════════════════════════════

/// Default alert handler yang menggunakan tracing untuk logging.
///
/// ## Behavior
///
/// - `on_fallback_activated`: Log INFO dengan field fallback info
/// - `on_fallback_deactivated`: Log INFO dengan durasi
/// - `on_reconciliation_complete`: Log INFO/WARN berdasarkan hasil
///
/// ## Thread Safety
///
/// LoggingAlertHandler adalah stateless dan thread-safe.
#[derive(Debug, Clone, Default)]
pub struct LoggingAlertHandler;

impl LoggingAlertHandler {
    /// Membuat LoggingAlertHandler baru.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl AlertHandler for LoggingAlertHandler {
    fn on_fallback_activated(&self, info: &FallbackHealthInfo) {
        info!(
            event = "fallback_activated",
            status = ?info.status,
            active = info.active,
            reason = ?info.reason,
            pending_reconcile = info.pending_reconcile,
            current_source = %info.current_source,
            "Fallback mode activated"
        );
    }

    fn on_fallback_deactivated(&self, duration_secs: u64) {
        info!(
            event = "fallback_deactivated",
            duration_secs = duration_secs,
            "Fallback mode deactivated"
        );
    }

    fn on_reconciliation_complete(&self, report: &ReconcileReport) {
        if report.is_success() {
            info!(
                event = "reconciliation_complete",
                items_processed = report.items_processed,
                duration_ms = report.duration_ms,
                source = %report.source,
                "Reconciliation completed successfully"
            );
        } else {
            warn!(
                event = "reconciliation_complete",
                items_processed = report.items_processed,
                items_failed = report.items_failed,
                duration_ms = report.duration_ms,
                source = %report.source,
                error = ?report.error,
                "Reconciliation completed with failures"
            );
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// WEBHOOK ALERT HANDLER
// ════════════════════════════════════════════════════════════════════════════

/// Webhook payload untuk alert events.
#[derive(Debug, Clone, Serialize)]
struct WebhookPayload {
    /// Tipe event.
    event_type: String,
    /// Timestamp dalam Unix seconds.
    timestamp: u64,
    /// Data event (tergantung tipe).
    data: serde_json::Value,
}

/// Alert handler yang mengirim notifikasi ke webhook endpoint.
///
/// ## Behavior
///
/// - Mengirim HTTP POST ke endpoint yang dikonfigurasi
/// - Payload dalam format JSON
/// - Timeout eksplisit untuk mencegah blocking
/// - Kegagalan di-log, tidak menjatuhkan sistem
///
/// ## Thread Safety
///
/// WebhookAlertHandler adalah thread-safe dan non-blocking.
/// Setiap notifikasi di-spawn sebagai task terpisah.
///
/// ## Configuration
///
/// - `endpoint`: URL endpoint webhook
/// - `timeout`: Timeout untuk request (default 5 detik)
#[derive(Debug, Clone)]
pub struct WebhookAlertHandler {
    /// URL endpoint webhook.
    endpoint: String,
    /// Timeout untuk request.
    timeout: Duration,
}

impl WebhookAlertHandler {
    /// Membuat WebhookAlertHandler baru.
    ///
    /// ## Parameters
    ///
    /// - `endpoint`: URL endpoint webhook
    /// - `timeout`: Timeout untuk request (default 5 detik jika None)
    ///
    /// ## Validation
    ///
    /// - `endpoint` tidak boleh kosong
    /// - Tidak ada validasi URL format (akan gagal saat request)
    #[must_use]
    pub fn new(endpoint: impl Into<String>, timeout: Option<Duration>) -> Self {
        Self {
            endpoint: endpoint.into(),
            timeout: timeout.unwrap_or(Duration::from_secs(5)),
        }
    }

    /// Get current timestamp in Unix seconds.
    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Send webhook notification asynchronously.
    ///
    /// Spawns a task to send the notification, does not block.
    /// Errors are logged, not propagated.
    ///
    /// ## Runtime Safety
    ///
    /// This method checks if a Tokio runtime is available before spawning.
    /// If no runtime is available, it logs a warning instead of panicking.
    /// This ensures the method never panics, as required by AlertHandler contract.
    fn send_notification(&self, payload: WebhookPayload) {
        let endpoint = self.endpoint.clone();
        let timeout = self.timeout;

        // Check if Tokio runtime is available
        // This prevents panic when called outside of async context
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                // Runtime available - spawn task
                handle.spawn(async move {
                    match Self::do_send(&endpoint, &payload, timeout).await {
                        Ok(()) => {
                            info!(
                                event = "webhook_sent",
                                endpoint = %endpoint,
                                event_type = %payload.event_type,
                                "Webhook notification sent successfully"
                            );
                        }
                        Err(e) => {
                            error!(
                                event = "webhook_failed",
                                endpoint = %endpoint,
                                event_type = %payload.event_type,
                                error = %e,
                                "Failed to send webhook notification"
                            );
                        }
                    }
                });
            }
            Err(_) => {
                // No runtime available - log warning instead of panicking
                warn!(
                    event = "webhook_no_runtime",
                    endpoint = %endpoint,
                    event_type = %payload.event_type,
                    "Cannot send webhook: no Tokio runtime available"
                );
            }
        }
    }

    /// Actually send the HTTP request.
    ///
    /// This is separated for testability.
    async fn do_send(endpoint: &str, payload: &WebhookPayload, timeout: Duration) -> Result<(), WebhookError> {
        // Validate endpoint tidak kosong
        if endpoint.is_empty() {
            return Err(WebhookError::InvalidEndpoint("endpoint is empty".to_string()));
        }

        // Serialize payload ke JSON
        let body = match serde_json::to_string(payload) {
            Ok(json) => json,
            Err(e) => return Err(WebhookError::SerializationError(e.to_string())),
        };

        // Menggunakan reqwest jika tersedia, atau fallback ke error
        // CATATAN: Jika reqwest tidak tersedia, ini akan mencatat error
        // dan tidak mengirim notifikasi.
        //
        // Untuk production, pastikan reqwest ada di dependencies:
        // reqwest = { version = "0.11", features = ["json"] }
        #[cfg(feature = "webhook")]
        {
            let client = reqwest::Client::builder()
                .timeout(timeout)
                .build()
                .map_err(|e| WebhookError::ClientError(e.to_string()))?;

            let response = client
                .post(endpoint)
                .header("Content-Type", "application/json")
                .body(body)
                .send()
                .await
                .map_err(|e| WebhookError::RequestFailed(e.to_string()))?;

            if !response.status().is_success() {
                return Err(WebhookError::ResponseError(format!(
                    "HTTP {}",
                    response.status()
                )));
            }

            Ok(())
        }

        #[cfg(not(feature = "webhook"))]
        {
            // Tanpa reqwest, log bahwa webhook tidak tersedia
            warn!(
                event = "webhook_not_available",
                endpoint = %endpoint,
                "Webhook feature not enabled, notification not sent. \
                 Enable 'webhook' feature and add reqwest dependency."
            );
            // Return Ok untuk tidak mengganggu sistem
            // Ini adalah expected behavior ketika feature tidak enabled
            let _ = (body, timeout); // Suppress unused warnings
            Ok(())
        }
    }
}

/// Error types untuk webhook operations.
#[derive(Debug)]
enum WebhookError {
    /// Endpoint tidak valid.
    InvalidEndpoint(String),
    /// Gagal serialize payload.
    SerializationError(String),
    /// Gagal membuat HTTP client.
    #[allow(dead_code)]
    ClientError(String),
    /// Request gagal.
    #[allow(dead_code)]
    RequestFailed(String),
    /// Response bukan success.
    #[allow(dead_code)]
    ResponseError(String),
}

impl std::fmt::Display for WebhookError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEndpoint(msg) => write!(f, "invalid endpoint: {}", msg),
            Self::SerializationError(msg) => write!(f, "serialization error: {}", msg),
            Self::ClientError(msg) => write!(f, "client error: {}", msg),
            Self::RequestFailed(msg) => write!(f, "request failed: {}", msg),
            Self::ResponseError(msg) => write!(f, "response error: {}", msg),
        }
    }
}

impl AlertHandler for WebhookAlertHandler {
    fn on_fallback_activated(&self, info: &FallbackHealthInfo) {
        let data = match serde_json::to_value(info) {
            Ok(v) => v,
            Err(e) => {
                error!(
                    event = "webhook_serialization_failed",
                    error = %e,
                    "Failed to serialize FallbackHealthInfo"
                );
                return;
            }
        };

        let payload = WebhookPayload {
            event_type: "fallback_activated".to_string(),
            timestamp: Self::current_timestamp(),
            data,
        };

        self.send_notification(payload);
    }

    fn on_fallback_deactivated(&self, duration_secs: u64) {
        let data = serde_json::json!({
            "duration_secs": duration_secs
        });

        let payload = WebhookPayload {
            event_type: "fallback_deactivated".to_string(),
            timestamp: Self::current_timestamp(),
            data,
        };

        self.send_notification(payload);
    }

    fn on_reconciliation_complete(&self, report: &ReconcileReport) {
        let data = match serde_json::to_value(report) {
            Ok(v) => v,
            Err(e) => {
                error!(
                    event = "webhook_serialization_failed",
                    error = %e,
                    "Failed to serialize ReconcileReport"
                );
                return;
            }
        };

        let payload = WebhookPayload {
            event_type: "reconciliation_complete".to_string(),
            timestamp: Self::current_timestamp(),
            data,
        };

        self.send_notification(payload);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// ALERT DISPATCHER
// ════════════════════════════════════════════════════════════════════════════

/// Dispatcher untuk mengelola multiple alert handlers.
///
/// ## Behavior
///
/// - Menerima multiple handlers
/// - Memanggil semua handler untuk setiap event
/// - Kegagalan satu handler tidak mempengaruhi handler lain
///
/// ## Thread Safety
///
/// AlertDispatcher adalah thread-safe (handlers wrapped in Arc).
#[derive(Clone)]
pub struct AlertDispatcher {
    /// Daftar handler yang terdaftar.
    handlers: Vec<std::sync::Arc<dyn AlertHandler>>,
}

impl Default for AlertDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl AlertDispatcher {
    /// Membuat AlertDispatcher baru tanpa handler.
    #[must_use]
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
        }
    }

    /// Membuat AlertDispatcher dengan default LoggingAlertHandler.
    #[must_use]
    pub fn with_logging() -> Self {
        let mut dispatcher = Self::new();
        dispatcher.add_handler(std::sync::Arc::new(LoggingAlertHandler::new()));
        dispatcher
    }

    /// Tambahkan handler ke dispatcher.
    pub fn add_handler(&mut self, handler: std::sync::Arc<dyn AlertHandler>) {
        self.handlers.push(handler);
    }

    /// Notify semua handlers tentang fallback activation.
    ///
    /// ## Guarantees
    ///
    /// - Memanggil semua handler
    /// - Kegagalan satu handler tidak mempengaruhi yang lain
    /// - Tidak blocking (setiap handler dipanggil synchronously tapi harus return segera)
    pub fn notify_fallback_activated(&self, info: &FallbackHealthInfo) {
        for handler in &self.handlers {
            handler.on_fallback_activated(info);
        }
    }

    /// Notify semua handlers tentang fallback deactivation.
    pub fn notify_fallback_deactivated(&self, duration_secs: u64) {
        for handler in &self.handlers {
            handler.on_fallback_deactivated(duration_secs);
        }
    }

    /// Notify semua handlers tentang reconciliation completion.
    pub fn notify_reconciliation_complete(&self, report: &ReconcileReport) {
        for handler in &self.handlers {
            handler.on_reconciliation_complete(report);
        }
    }

    /// Get number of registered handlers.
    #[must_use]
    pub fn handler_count(&self) -> usize {
        self.handlers.len()
    }
}

impl std::fmt::Debug for AlertDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlertDispatcher")
            .field("handler_count", &self.handlers.len())
            .finish()
    }
}

// ════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use dsdn_common::DAStatus;

    // ════════════════════════════════════════════════════════════════════════
    // TEST HELPER: Mock AlertHandler
    // ════════════════════════════════════════════════════════════════════════

    /// Mock handler untuk testing.
    struct MockAlertHandler {
        activated_count: AtomicU64,
        deactivated_count: AtomicU64,
        reconcile_count: AtomicU64,
    }

    impl MockAlertHandler {
        fn new() -> Self {
            Self {
                activated_count: AtomicU64::new(0),
                deactivated_count: AtomicU64::new(0),
                reconcile_count: AtomicU64::new(0),
            }
        }

        fn activated_count(&self) -> u64 {
            self.activated_count.load(Ordering::SeqCst)
        }

        fn deactivated_count(&self) -> u64 {
            self.deactivated_count.load(Ordering::SeqCst)
        }

        fn reconcile_count(&self) -> u64 {
            self.reconcile_count.load(Ordering::SeqCst)
        }
    }

    impl AlertHandler for MockAlertHandler {
        fn on_fallback_activated(&self, _info: &FallbackHealthInfo) {
            self.activated_count.fetch_add(1, Ordering::SeqCst);
        }

        fn on_fallback_deactivated(&self, _duration_secs: u64) {
            self.deactivated_count.fetch_add(1, Ordering::SeqCst);
        }

        fn on_reconciliation_complete(&self, _report: &ReconcileReport) {
            self.reconcile_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14A.1A.68-1: ReconcileReport construction
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_reconcile_report_success() {
        let report = ReconcileReport::success(100, 500, "primary");

        assert_eq!(report.items_processed, 100);
        assert_eq!(report.items_failed, 0);
        assert_eq!(report.duration_ms, 500);
        assert_eq!(report.source, "primary");
        assert!(report.error.is_none());
        assert!(report.is_success());
        assert_eq!(report.total_items(), 100);
    }

    #[test]
    fn test_reconcile_report_partial_failure() {
        let report = ReconcileReport::partial_failure(
            80,
            20,
            1000,
            "secondary",
            "some items failed",
        );

        assert_eq!(report.items_processed, 80);
        assert_eq!(report.items_failed, 20);
        assert_eq!(report.duration_ms, 1000);
        assert_eq!(report.source, "secondary");
        assert_eq!(report.error, Some("some items failed".to_string()));
        assert!(!report.is_success());
        assert_eq!(report.total_items(), 100);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14A.1A.68-2: ReconcileReport serialization
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_reconcile_report_serialization() {
        let report = ReconcileReport::success(50, 250, "primary");
        let json = serde_json::to_string(&report).expect("serialization should succeed");

        assert!(json.contains("\"items_processed\":50"));
        assert!(json.contains("\"items_failed\":0"));
        assert!(json.contains("\"duration_ms\":250"));
        assert!(json.contains("\"source\":\"primary\""));
        assert!(json.contains("\"error\":null"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14A.1A.68-3: LoggingAlertHandler does not panic
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_logging_handler_no_panic() {
        let handler = LoggingAlertHandler::new();

        // Test with normal info
        let info = FallbackHealthInfo {
            status: DAStatus::Degraded,
            active: true,
            reason: Some("test".to_string()),
            activated_at: Some(1000),
            duration_secs: Some(100),
            pending_reconcile: 50,
            last_celestia_contact: Some(900),
            current_source: "fallback".to_string(),
        };

        // Should not panic
        handler.on_fallback_activated(&info);
        handler.on_fallback_deactivated(100);

        let report = ReconcileReport::success(10, 50, "primary");
        handler.on_reconciliation_complete(&report);
    }

    #[test]
    fn test_logging_handler_extreme_values() {
        let handler = LoggingAlertHandler::new();

        // Test with extreme values
        let info = FallbackHealthInfo {
            status: DAStatus::Emergency,
            active: true,
            reason: Some("x".repeat(10000)), // Very long string
            activated_at: Some(u64::MAX),
            duration_secs: Some(u64::MAX),
            pending_reconcile: u64::MAX,
            last_celestia_contact: None,
            current_source: "fallback".to_string(),
        };

        // Should not panic
        handler.on_fallback_activated(&info);
        handler.on_fallback_deactivated(u64::MAX);

        let report = ReconcileReport::partial_failure(
            u64::MAX,
            u64::MAX,
            u64::MAX,
            "emergency",
            "extreme test",
        );
        handler.on_reconciliation_complete(&report);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14A.1A.68-4: AlertDispatcher registration
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_alert_dispatcher_registration() {
        let mut dispatcher = AlertDispatcher::new();
        assert_eq!(dispatcher.handler_count(), 0);

        dispatcher.add_handler(Arc::new(LoggingAlertHandler::new()));
        assert_eq!(dispatcher.handler_count(), 1);

        dispatcher.add_handler(Arc::new(MockAlertHandler::new()));
        assert_eq!(dispatcher.handler_count(), 2);
    }

    #[test]
    fn test_alert_dispatcher_with_logging() {
        let dispatcher = AlertDispatcher::with_logging();
        assert_eq!(dispatcher.handler_count(), 1);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14A.1A.68-5: AlertDispatcher notification
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_alert_dispatcher_notify() {
        let mock = Arc::new(MockAlertHandler::new());
        let mut dispatcher = AlertDispatcher::new();
        dispatcher.add_handler(mock.clone());

        let info = FallbackHealthInfo {
            status: DAStatus::Degraded,
            active: true,
            reason: None,
            activated_at: Some(1000),
            duration_secs: Some(100),
            pending_reconcile: 0,
            last_celestia_contact: None,
            current_source: "fallback".to_string(),
        };

        // Test notifications
        dispatcher.notify_fallback_activated(&info);
        assert_eq!(mock.activated_count(), 1);

        dispatcher.notify_fallback_deactivated(100);
        assert_eq!(mock.deactivated_count(), 1);

        let report = ReconcileReport::success(10, 50, "primary");
        dispatcher.notify_reconciliation_complete(&report);
        assert_eq!(mock.reconcile_count(), 1);
    }

    #[test]
    fn test_alert_dispatcher_multiple_handlers() {
        let mock1 = Arc::new(MockAlertHandler::new());
        let mock2 = Arc::new(MockAlertHandler::new());

        let mut dispatcher = AlertDispatcher::new();
        dispatcher.add_handler(mock1.clone());
        dispatcher.add_handler(mock2.clone());

        let info = FallbackHealthInfo {
            status: DAStatus::Healthy,
            active: false,
            reason: None,
            activated_at: None,
            duration_secs: None,
            pending_reconcile: 0,
            last_celestia_contact: None,
            current_source: "celestia".to_string(),
        };

        dispatcher.notify_fallback_activated(&info);

        // Both handlers should be called
        assert_eq!(mock1.activated_count(), 1);
        assert_eq!(mock2.activated_count(), 1);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14A.1A.68-6: WebhookAlertHandler construction
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_webhook_handler_construction() {
        let handler = WebhookAlertHandler::new("http://localhost:8080/webhook", None);
        assert_eq!(handler.endpoint, "http://localhost:8080/webhook");
        assert_eq!(handler.timeout, Duration::from_secs(5));

        let handler_custom = WebhookAlertHandler::new(
            "http://example.com",
            Some(Duration::from_secs(10)),
        );
        assert_eq!(handler_custom.endpoint, "http://example.com");
        assert_eq!(handler_custom.timeout, Duration::from_secs(10));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14A.1A.68-7: WebhookAlertHandler does not panic
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_webhook_handler_no_panic() {
        let handler = WebhookAlertHandler::new("http://localhost:9999/nonexistent", None);

        let info = FallbackHealthInfo {
            status: DAStatus::Warning,
            active: false,
            reason: None,
            activated_at: None,
            duration_secs: None,
            pending_reconcile: 0,
            last_celestia_contact: None,
            current_source: "celestia".to_string(),
        };

        // Should not panic even if endpoint is unreachable
        // (notification is async, errors are logged)
        handler.on_fallback_activated(&info);
        handler.on_fallback_deactivated(50);

        let report = ReconcileReport::success(5, 25, "primary");
        handler.on_reconciliation_complete(&report);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14A.1A.68-8: ReconcileReport edge cases
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_reconcile_report_zero_values() {
        let report = ReconcileReport::success(0, 0, "");

        assert_eq!(report.items_processed, 0);
        assert_eq!(report.duration_ms, 0);
        assert_eq!(report.source, "");
        assert!(report.is_success());
        assert_eq!(report.total_items(), 0);
    }

    #[test]
    fn test_reconcile_report_overflow_safety() {
        let report = ReconcileReport {
            items_processed: u64::MAX,
            items_failed: u64::MAX,
            duration_ms: u64::MAX,
            source: "test".to_string(),
            error: None,
        };

        // total_items should use saturating_add
        assert_eq!(report.total_items(), u64::MAX);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14A.1A.68-9: AlertDispatcher Clone
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_alert_dispatcher_clone() {
        let mock = Arc::new(MockAlertHandler::new());
        let mut dispatcher = AlertDispatcher::new();
        dispatcher.add_handler(mock.clone());

        let cloned = dispatcher.clone();

        assert_eq!(dispatcher.handler_count(), cloned.handler_count());

        // Both should notify the same handler
        let info = FallbackHealthInfo {
            status: DAStatus::Healthy,
            active: false,
            reason: None,
            activated_at: None,
            duration_secs: None,
            pending_reconcile: 0,
            last_celestia_contact: None,
            current_source: "celestia".to_string(),
        };

        dispatcher.notify_fallback_activated(&info);
        cloned.notify_fallback_activated(&info);

        // Handler should be called twice (once from each dispatcher)
        assert_eq!(mock.activated_count(), 2);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14A.1A.68-10: Debug implementations
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_debug_implementations() {
        let report = ReconcileReport::success(10, 100, "primary");
        let debug = format!("{:?}", report);
        assert!(debug.contains("ReconcileReport"));
        assert!(debug.contains("items_processed"));

        let dispatcher = AlertDispatcher::with_logging();
        let debug = format!("{:?}", dispatcher);
        assert!(debug.contains("AlertDispatcher"));
        assert!(debug.contains("handler_count"));

        let logging = LoggingAlertHandler::new();
        let debug = format!("{:?}", logging);
        assert!(debug.contains("LoggingAlertHandler"));

        let webhook = WebhookAlertHandler::new("http://test.com", None);
        let debug = format!("{:?}", webhook);
        assert!(debug.contains("WebhookAlertHandler"));
    }
}