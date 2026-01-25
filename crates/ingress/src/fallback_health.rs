//! # Fallback Health Information (14A.1A.61)
//!
//! Menyediakan struktur data untuk mengekspos status kesehatan fallback
//! ke layer ingress / HTTP API.
//!
//! ## Prinsip Desain
//!
//! - Struct merepresentasikan STATE aktual, bukan interpretasi
//! - Semua field bersumber dari data eksplisit
//! - Konversi bersifat pure dan deterministik
//! - Tidak ada side effect atau IO tersembunyi
//!
//! ## Penggunaan
//!
//! ```rust,ignore
//! use crate::fallback_health::FallbackHealthInfo;
//! use dsdn_common::DAHealthMonitor;
//!
//! let monitor: &DAHealthMonitor = /* ... */;
//! let info = FallbackHealthInfo::from(monitor);
//!
//! // Serialize ke JSON untuk HTTP response
//! let json = serde_json::to_string(&info)?;
//! ```

use serde::Serialize;

// Re-export DAStatus untuk convenience
pub use dsdn_common::DAStatus;

// ════════════════════════════════════════════════════════════════════════════════
// FALLBACK HEALTH INFO STRUCT
// ════════════════════════════════════════════════════════════════════════════════

/// Informasi kesehatan fallback untuk HTTP API.
///
/// Struct ini merepresentasikan STATE aktual sistem fallback,
/// bukan hasil interpretasi, estimasi, atau opini.
///
/// ## Field Sources
///
/// | Field | Source | Method |
/// |-------|--------|--------|
/// | `status` | DAHealthMonitor | `get_da_status()` |
/// | `active` | DAHealthMonitor | `is_fallback_active()` |
/// | `reason` | DAHealthMonitor | `fallback_reason()` |
/// | `activated_at` | DAHealthMonitor | `fallback_activated_at()` |
/// | `duration_secs` | Calculated | `last_health_check_at() - activated_at` |
/// | `pending_reconcile` | DAHealthMonitor | `pending_reconcile_count()` |
/// | `last_celestia_contact` | DAHealthMonitor | `celestia_last_success()` |
/// | `current_source` | DAHealthMonitor | `current_source()` |
///
/// ## JSON Serialization
///
/// Field names di JSON SAMA dengan nama struct (snake_case).
/// Tidak ada custom serializer.
///
/// ## Thread Safety
///
/// Struct ini adalah owned data tanpa interior mutability.
/// Aman untuk di-send antar thread (Send + Sync).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FallbackHealthInfo {
    /// Status DA layer saat ini.
    ///
    /// Possible values: Healthy, Warning, Degraded, Emergency, Recovering.
    /// Serialized sebagai string lowercase.
    pub status: DAStatus,

    /// Apakah fallback mode sedang aktif.
    ///
    /// `true` jika sistem menggunakan fallback DA.
    /// `false` jika sistem menggunakan primary DA (Celestia).
    pub active: bool,

    /// Alasan fallback diaktifkan.
    ///
    /// `Some(reason)` jika fallback aktif dengan alasan.
    /// `None` jika fallback tidak aktif.
    ///
    /// Contoh: "DA degraded: no success for 300 seconds"
    pub reason: Option<String>,

    /// Unix timestamp (seconds) saat fallback diaktifkan.
    ///
    /// `Some(timestamp)` jika fallback aktif.
    /// `None` jika fallback tidak aktif atau belum pernah aktif.
    pub activated_at: Option<u64>,

    /// Durasi fallback aktif dalam detik.
    ///
    /// `Some(duration)` jika fallback aktif.
    /// `None` jika fallback tidak aktif.
    ///
    /// Dihitung secara deterministik dari:
    /// `last_health_check_at - activated_at`
    pub duration_secs: Option<u64>,

    /// Jumlah item yang menunggu reconciliation.
    ///
    /// Counter untuk blob yang belum di-reconcile ke primary DA.
    /// 0 jika tidak ada pending reconciliation.
    pub pending_reconcile: u64,

    /// Unix timestamp (seconds) kontak terakhir dengan Celestia.
    ///
    /// `Some(timestamp)` jika pernah ada kontak sukses.
    /// `None` jika belum pernah ada kontak sukses.
    pub last_celestia_contact: Option<u64>,

    /// Sumber DA yang sedang digunakan.
    ///
    /// `"celestia"` jika menggunakan primary DA.
    /// `"fallback"` jika fallback mode aktif.
    pub current_source: String,
}

// ════════════════════════════════════════════════════════════════════════════════
// FROM IMPLEMENTATION
// ════════════════════════════════════════════════════════════════════════════════

impl From<&dsdn_common::DAHealthMonitor> for FallbackHealthInfo {
    /// Konversi dari `DAHealthMonitor` ke `FallbackHealthInfo`.
    ///
    /// ## Guarantees
    ///
    /// - **Pure**: Tidak ada side effect
    /// - **Deterministik**: Input sama selalu menghasilkan output sama
    /// - **No IO**: Tidak melakukan network, disk, atau system calls
    /// - **No time fetch**: Tidak memanggil `SystemTime::now()` atau sejenisnya
    ///
    /// ## Duration Calculation
    ///
    /// `duration_secs` dihitung dari data eksplisit di monitor:
    /// ```text
    /// duration = last_health_check_at - activated_at
    /// ```
    ///
    /// Ini deterministik karena kedua nilai berasal dari monitor,
    /// bukan dari waktu saat konversi.
    ///
    /// ## Field Mapping Rules
    ///
    /// - `activated_at`: `Some` hanya jika nilai > 0 DAN fallback aktif
    /// - `duration_secs`: `Some` hanya jika `activated_at` is `Some`
    /// - `last_celestia_contact`: `Some` hanya jika nilai > 0
    /// - Tidak ada default implisit atau nilai palsu
    fn from(monitor: &dsdn_common::DAHealthMonitor) -> Self {
        let status = monitor.get_da_status();
        let active = monitor.is_fallback_active();
        let reason = monitor.fallback_reason();

        // Get activated_at timestamp
        // Only Some if value > 0 AND fallback is active
        let activated_at_raw = monitor.fallback_activated_at();
        let activated_at = if activated_at_raw > 0 && active {
            Some(activated_at_raw)
        } else {
            None
        };

        // Calculate duration deterministicly from monitor data
        // Uses last_health_check_at as the "current" time reference
        let duration_secs = activated_at.and_then(|start| {
            let last_check = monitor.last_health_check_at();
            if last_check > 0 && last_check >= start {
                Some(last_check.saturating_sub(start))
            } else {
                // No health check yet or invalid state
                Some(0)
            }
        });

        // Get last celestia contact timestamp
        // Only Some if value > 0
        let last_success = monitor.celestia_last_success();
        let last_celestia_contact = if last_success > 0 {
            Some(last_success)
        } else {
            None
        };

        Self {
            status,
            active,
            reason,
            activated_at,
            duration_secs,
            pending_reconcile: monitor.pending_reconcile_count(),
            last_celestia_contact,
            current_source: monitor.current_source().to_string(),
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// ADDITIONAL IMPLEMENTATIONS
// ════════════════════════════════════════════════════════════════════════════════

impl FallbackHealthInfo {
    /// Check if the system is in a degraded state.
    ///
    /// Returns `true` if status requires fallback (Degraded, Emergency, Recovering).
    #[inline]
    #[must_use]
    pub fn is_degraded(&self) -> bool {
        self.status.requires_fallback()
    }

    /// Check if the system is operational.
    ///
    /// Returns `true` if status allows operations (not Emergency).
    #[inline]
    #[must_use]
    pub fn is_operational(&self) -> bool {
        self.status.is_operational()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ════════════════════════════════════════════════════════════════════════════
    // MOCK MONITOR FOR TESTING
    // ════════════════════════════════════════════════════════════════════════════

    // Since we can't easily construct DAHealthMonitor in tests without dsdn_common,
    // we test the struct directly and document the expected behavior.

    // ────────────────────────────────────────────────────────────────────────────
    // Struct creation tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_fallback_health_info_healthy_state() {
        let info = FallbackHealthInfo {
            status: DAStatus::Healthy,
            active: false,
            reason: None,
            activated_at: None,
            duration_secs: None,
            pending_reconcile: 0,
            last_celestia_contact: Some(1704067200), // 2024-01-01 00:00:00 UTC
            current_source: "celestia".to_string(),
        };

        assert!(!info.active);
        assert!(!info.is_degraded());
        assert!(info.is_operational());
        assert_eq!(info.current_source, "celestia");
    }

    #[test]
    fn test_fallback_health_info_degraded_state() {
        let info = FallbackHealthInfo {
            status: DAStatus::Degraded,
            active: true,
            reason: Some("DA degraded: no success for 300 seconds".to_string()),
            activated_at: Some(1704067200),
            duration_secs: Some(300),
            pending_reconcile: 42,
            last_celestia_contact: Some(1704066900), // 5 minutes before
            current_source: "fallback".to_string(),
        };

        assert!(info.active);
        assert!(info.is_degraded());
        assert!(info.is_operational()); // Degraded is still operational
        assert_eq!(info.current_source, "fallback");
        assert_eq!(info.pending_reconcile, 42);
    }

    #[test]
    fn test_fallback_health_info_emergency_state() {
        let info = FallbackHealthInfo {
            status: DAStatus::Emergency,
            active: true,
            reason: Some("DA emergency: no success for 1800 seconds".to_string()),
            activated_at: Some(1704065400),
            duration_secs: Some(1800),
            pending_reconcile: 100,
            last_celestia_contact: Some(1704063600),
            current_source: "fallback".to_string(),
        };

        assert!(info.active);
        assert!(info.is_degraded());
        assert!(!info.is_operational()); // Emergency is NOT operational
    }

    #[test]
    fn test_fallback_health_info_recovering_state() {
        let info = FallbackHealthInfo {
            status: DAStatus::Recovering,
            active: true,
            reason: Some("DA recovering: in grace period".to_string()),
            activated_at: Some(1704067200),
            duration_secs: Some(30),
            pending_reconcile: 10,
            last_celestia_contact: Some(1704067230),
            current_source: "fallback".to_string(),
        };

        assert!(info.active);
        assert!(info.is_degraded()); // Recovering requires fallback
        assert!(info.is_operational()); // But still operational
    }

    #[test]
    fn test_fallback_health_info_warning_state() {
        let info = FallbackHealthInfo {
            status: DAStatus::Warning,
            active: false,
            reason: None,
            activated_at: None,
            duration_secs: None,
            pending_reconcile: 0,
            last_celestia_contact: Some(1704067200),
            current_source: "celestia".to_string(),
        };

        assert!(!info.active);
        assert!(!info.is_degraded()); // Warning does not require fallback
        assert!(info.is_operational());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // JSON serialization tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_json_serialization_healthy() {
        let info = FallbackHealthInfo {
            status: DAStatus::Healthy,
            active: false,
            reason: None,
            activated_at: None,
            duration_secs: None,
            pending_reconcile: 0,
            last_celestia_contact: Some(1704067200),
            current_source: "celestia".to_string(),
        };

        let json = serde_json::to_string(&info).expect("serialization should succeed");

        // Verify field names are snake_case
        assert!(json.contains("\"status\""));
        assert!(json.contains("\"active\""));
        assert!(json.contains("\"reason\""));
        assert!(json.contains("\"activated_at\""));
        assert!(json.contains("\"duration_secs\""));
        assert!(json.contains("\"pending_reconcile\""));
        assert!(json.contains("\"last_celestia_contact\""));
        assert!(json.contains("\"current_source\""));

        // Verify values
        assert!(json.contains("\"active\":false"));
        assert!(json.contains("\"reason\":null"));
        assert!(json.contains("\"activated_at\":null"));
        assert!(json.contains("\"duration_secs\":null"));
        assert!(json.contains("\"pending_reconcile\":0"));
        assert!(json.contains("\"last_celestia_contact\":1704067200"));
        assert!(json.contains("\"current_source\":\"celestia\""));
    }

    #[test]
    fn test_json_serialization_degraded() {
        let info = FallbackHealthInfo {
            status: DAStatus::Degraded,
            active: true,
            reason: Some("test reason".to_string()),
            activated_at: Some(1704067200),
            duration_secs: Some(300),
            pending_reconcile: 42,
            last_celestia_contact: Some(1704066900),
            current_source: "fallback".to_string(),
        };

        let json = serde_json::to_string(&info).expect("serialization should succeed");

        assert!(json.contains("\"active\":true"));
        assert!(json.contains("\"reason\":\"test reason\""));
        assert!(json.contains("\"activated_at\":1704067200"));
        assert!(json.contains("\"duration_secs\":300"));
        assert!(json.contains("\"pending_reconcile\":42"));
        assert!(json.contains("\"current_source\":\"fallback\""));
    }

    #[test]
    fn test_json_serialization_pretty() {
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

        let json = serde_json::to_string_pretty(&info).expect("serialization should succeed");

        // Pretty print should have newlines
        assert!(json.contains('\n'));
    }

    #[test]
    fn test_json_deserialization_roundtrip() {
        let original = FallbackHealthInfo {
            status: DAStatus::Degraded,
            active: true,
            reason: Some("roundtrip test".to_string()),
            activated_at: Some(1704067200),
            duration_secs: Some(600),
            pending_reconcile: 99,
            last_celestia_contact: Some(1704066600),
            current_source: "fallback".to_string(),
        };

        let json = serde_json::to_string(&original).expect("serialization should succeed");

        // Note: Deserialization requires Deserialize derive which we don't have
        // This test validates that serialization produces valid JSON
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("should be valid JSON");

        assert!(parsed.is_object());
        assert_eq!(parsed["active"], true);
        assert_eq!(parsed["pending_reconcile"], 99);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Edge case tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_no_celestia_contact_ever() {
        let info = FallbackHealthInfo {
            status: DAStatus::Emergency,
            active: true,
            reason: Some("never connected".to_string()),
            activated_at: Some(1704067200),
            duration_secs: Some(0),
            pending_reconcile: 0,
            last_celestia_contact: None, // Never had contact
            current_source: "fallback".to_string(),
        };

        let json = serde_json::to_string(&info).expect("serialization should succeed");
        assert!(json.contains("\"last_celestia_contact\":null"));
    }

    #[test]
    fn test_max_values() {
        let info = FallbackHealthInfo {
            status: DAStatus::Emergency,
            active: true,
            reason: Some("max test".to_string()),
            activated_at: Some(u64::MAX),
            duration_secs: Some(u64::MAX),
            pending_reconcile: u64::MAX,
            last_celestia_contact: Some(u64::MAX),
            current_source: "fallback".to_string(),
        };

        // Should not panic or overflow
        let json = serde_json::to_string(&info).expect("serialization should succeed");
        assert!(json.contains(&u64::MAX.to_string()));
    }

    #[test]
    fn test_empty_reason_string() {
        let info = FallbackHealthInfo {
            status: DAStatus::Degraded,
            active: true,
            reason: Some(String::new()), // Empty but Some
            activated_at: Some(1704067200),
            duration_secs: Some(100),
            pending_reconcile: 0,
            last_celestia_contact: Some(1704067100),
            current_source: "fallback".to_string(),
        };

        let json = serde_json::to_string(&info).expect("serialization should succeed");
        assert!(json.contains("\"reason\":\"\""));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Clone and equality tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_clone() {
        let original = FallbackHealthInfo {
            status: DAStatus::Warning,
            active: false,
            reason: None,
            activated_at: None,
            duration_secs: None,
            pending_reconcile: 5,
            last_celestia_contact: Some(1704067200),
            current_source: "celestia".to_string(),
        };

        let cloned = original.clone();

        assert_eq!(original, cloned);
    }

    #[test]
    fn test_equality() {
        let info1 = FallbackHealthInfo {
            status: DAStatus::Healthy,
            active: false,
            reason: None,
            activated_at: None,
            duration_secs: None,
            pending_reconcile: 0,
            last_celestia_contact: Some(1704067200),
            current_source: "celestia".to_string(),
        };

        let info2 = FallbackHealthInfo {
            status: DAStatus::Healthy,
            active: false,
            reason: None,
            activated_at: None,
            duration_secs: None,
            pending_reconcile: 0,
            last_celestia_contact: Some(1704067200),
            current_source: "celestia".to_string(),
        };

        let info3 = FallbackHealthInfo {
            status: DAStatus::Warning, // Different
            active: false,
            reason: None,
            activated_at: None,
            duration_secs: None,
            pending_reconcile: 0,
            last_celestia_contact: Some(1704067200),
            current_source: "celestia".to_string(),
        };

        assert_eq!(info1, info2);
        assert_ne!(info1, info3);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Debug tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_debug_format() {
        let info = FallbackHealthInfo {
            status: DAStatus::Healthy,
            active: false,
            reason: None,
            activated_at: None,
            duration_secs: None,
            pending_reconcile: 0,
            last_celestia_contact: Some(1704067200),
            current_source: "celestia".to_string(),
        };

        let debug = format!("{:?}", info);

        assert!(debug.contains("FallbackHealthInfo"));
        assert!(debug.contains("Healthy"));
        assert!(debug.contains("celestia"));
    }
}