//! # Fallback Event Schema
//!
//! Modul ini mendefinisikan `FallbackEvent` enum sebagai container untuk
//! semua fallback-related events dalam sistem DSDN.
//!
//! ## Desain
//!
//! - Setiap variant memiliki field `version` eksplisit untuk backward compatibility
//! - Variants bersifat placeholder dan akan diperluas di tahap selanjutnya
//! - Serialisasi menggunakan serde dengan format deterministik
//!
//! ## Backward Compatibility
//!
//! Field `version` pada setiap variant memungkinkan:
//! - Deteksi schema version saat deserialization
//! - Migrasi data dari versi lama ke baru
//! - Penolakan eksplisit untuk versi yang tidak didukung
//!
//! ## Serialization Guarantee
//!
//! Enum ini menggunakan derive macros standar serde yang menjamin:
//! - Serialisasi deterministik (input sama → output sama)
//! - Round-trip safety (serialize → deserialize → identical)

use serde::{Deserialize, Serialize};

// ════════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════════

/// Current schema version untuk FallbackEvent.
///
/// Digunakan saat membuat event baru untuk memastikan
/// version field terisi dengan nilai yang benar.
pub const FALLBACK_EVENT_SCHEMA_VERSION: u32 = 1;

// ════════════════════════════════════════════════════════════════════════════════
// FALLBACK EVENT ENUM
// ════════════════════════════════════════════════════════════════════════════════

/// Enum container untuk semua fallback-related events.
///
/// `FallbackEvent` adalah tipe utama untuk merepresentasikan
/// event-event yang terjadi selama fallback DA layer operations.
///
/// ## Variants
///
/// Enum ini memiliki tepat 4 variant placeholder:
///
/// 1. `FallbackActivated` - Fallback layer diaktifkan
/// 2. `FallbackDeactivated` - Fallback layer dinonaktifkan
/// 3. `ReconciliationStarted` - Proses reconciliation dimulai
/// 4. `ReconciliationCompleted` - Proses reconciliation selesai
///
/// ## Version Field
///
/// Setiap variant memiliki field `version: u32` yang:
/// - Eksplisit (tidak implicit atau hardcoded di luar struktur)
/// - Digunakan untuk backward compatibility checking
/// - Harus diisi dengan `FALLBACK_EVENT_SCHEMA_VERSION` saat pembuatan
///
/// ## Serialization
///
/// Enum ini dapat di-serialize dan di-deserialize menggunakan serde.
/// Format serialisasi bersifat deterministik untuk konsistensi
/// di seluruh sistem terdistribusi.
///
/// ## Example
///
/// ```
/// use dsdn_proto::fallback_event::{FallbackEvent, FALLBACK_EVENT_SCHEMA_VERSION};
///
/// let event = FallbackEvent::FallbackActivated {
///     version: FALLBACK_EVENT_SCHEMA_VERSION,
/// };
///
/// // Serialize
/// let bytes = bincode::serialize(&event).unwrap();
///
/// // Deserialize
/// let decoded: FallbackEvent = bincode::deserialize(&bytes).unwrap();
///
/// assert_eq!(event, decoded);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FallbackEvent {
    /// Placeholder variant: Fallback layer telah diaktifkan.
    ///
    /// Event ini di-emit ketika sistem beralih dari primary DA
    /// (Celestia) ke fallback DA (Validator Quorum atau Emergency).
    ///
    /// Field tambahan akan ditambahkan di tahap selanjutnya.
    FallbackActivated {
        /// Schema version untuk backward compatibility.
        version: u32,
    },

    /// Placeholder variant: Fallback layer telah dinonaktifkan.
    ///
    /// Event ini di-emit ketika sistem kembali ke primary DA
    /// setelah recovery dari kondisi fallback.
    ///
    /// Field tambahan akan ditambahkan di tahap selanjutnya.
    FallbackDeactivated {
        /// Schema version untuk backward compatibility.
        version: u32,
    },

    /// Placeholder variant: Proses reconciliation telah dimulai.
    ///
    /// Event ini di-emit ketika sistem mulai melakukan
    /// reconciliation pending blobs dari fallback DA ke primary DA.
    ///
    /// Field tambahan akan ditambahkan di tahap selanjutnya.
    ReconciliationStarted {
        /// Schema version untuk backward compatibility.
        version: u32,
    },

    /// Placeholder variant: Proses reconciliation telah selesai.
    ///
    /// Event ini di-emit ketika proses reconciliation selesai,
    /// baik sukses maupun dengan error partial.
    ///
    /// Field tambahan akan ditambahkan di tahap selanjutnya.
    ReconciliationCompleted {
        /// Schema version untuk backward compatibility.
        version: u32,
    },
}

impl FallbackEvent {
    /// Mendapatkan version dari event apapun.
    ///
    /// Method ini memungkinkan akses uniform ke field version
    /// tanpa perlu match pada setiap variant.
    ///
    /// # Returns
    ///
    /// Version number dari event.
    #[inline]
    #[must_use]
    pub const fn version(&self) -> u32 {
        match self {
            Self::FallbackActivated { version } => *version,
            Self::FallbackDeactivated { version } => *version,
            Self::ReconciliationStarted { version } => *version,
            Self::ReconciliationCompleted { version } => *version,
        }
    }

    /// Memeriksa apakah event memiliki version yang didukung.
    ///
    /// Saat ini hanya version 1 yang didukung.
    ///
    /// # Returns
    ///
    /// `true` jika version didukung, `false` jika tidak.
    #[inline]
    #[must_use]
    pub const fn is_supported_version(&self) -> bool {
        self.version() == FALLBACK_EVENT_SCHEMA_VERSION
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// Test: FallbackActivated dapat di-serialize dan di-deserialize.
    #[test]
    fn test_fallback_activated_serialize_deserialize() {
        let event = FallbackEvent::FallbackActivated {
            version: FALLBACK_EVENT_SCHEMA_VERSION,
        };

        let serialized = bincode::serialize(&event);
        assert!(serialized.is_ok(), "Serialization must succeed");

        let bytes = serialized.unwrap();
        let deserialized: Result<FallbackEvent, _> = bincode::deserialize(&bytes);
        assert!(deserialized.is_ok(), "Deserialization must succeed");

        let decoded = deserialized.unwrap();
        assert_eq!(event, decoded, "Round-trip must produce identical result");
    }

    /// Test: FallbackDeactivated dapat di-serialize dan di-deserialize.
    #[test]
    fn test_fallback_deactivated_serialize_deserialize() {
        let event = FallbackEvent::FallbackDeactivated {
            version: FALLBACK_EVENT_SCHEMA_VERSION,
        };

        let serialized = bincode::serialize(&event);
        assert!(serialized.is_ok(), "Serialization must succeed");

        let bytes = serialized.unwrap();
        let deserialized: Result<FallbackEvent, _> = bincode::deserialize(&bytes);
        assert!(deserialized.is_ok(), "Deserialization must succeed");

        let decoded = deserialized.unwrap();
        assert_eq!(event, decoded, "Round-trip must produce identical result");
    }

    /// Test: ReconciliationStarted dapat di-serialize dan di-deserialize.
    #[test]
    fn test_reconciliation_started_serialize_deserialize() {
        let event = FallbackEvent::ReconciliationStarted {
            version: FALLBACK_EVENT_SCHEMA_VERSION,
        };

        let serialized = bincode::serialize(&event);
        assert!(serialized.is_ok(), "Serialization must succeed");

        let bytes = serialized.unwrap();
        let deserialized: Result<FallbackEvent, _> = bincode::deserialize(&bytes);
        assert!(deserialized.is_ok(), "Deserialization must succeed");

        let decoded = deserialized.unwrap();
        assert_eq!(event, decoded, "Round-trip must produce identical result");
    }

    /// Test: ReconciliationCompleted dapat di-serialize dan di-deserialize.
    #[test]
    fn test_reconciliation_completed_serialize_deserialize() {
        let event = FallbackEvent::ReconciliationCompleted {
            version: FALLBACK_EVENT_SCHEMA_VERSION,
        };

        let serialized = bincode::serialize(&event);
        assert!(serialized.is_ok(), "Serialization must succeed");

        let bytes = serialized.unwrap();
        let deserialized: Result<FallbackEvent, _> = bincode::deserialize(&bytes);
        assert!(deserialized.is_ok(), "Deserialization must succeed");

        let decoded = deserialized.unwrap();
        assert_eq!(event, decoded, "Round-trip must produce identical result");
    }

    /// Test: Serialisasi deterministik (input sama → output sama).
    #[test]
    fn test_serialization_deterministic() {
        let event = FallbackEvent::FallbackActivated {
            version: FALLBACK_EVENT_SCHEMA_VERSION,
        };

        let bytes1 = bincode::serialize(&event);
        let bytes2 = bincode::serialize(&event);

        assert!(bytes1.is_ok(), "First serialization must succeed");
        assert!(bytes2.is_ok(), "Second serialization must succeed");
        assert_eq!(
            bytes1.unwrap(),
            bytes2.unwrap(),
            "Deterministic: same input must produce same output"
        );
    }

    /// Test: Semua variant memiliki version yang dapat diakses.
    #[test]
    fn test_version_accessor() {
        let events = [
            FallbackEvent::FallbackActivated { version: 1 },
            FallbackEvent::FallbackDeactivated { version: 2 },
            FallbackEvent::ReconciliationStarted { version: 3 },
            FallbackEvent::ReconciliationCompleted { version: 4 },
        ];

        assert_eq!(events[0].version(), 1);
        assert_eq!(events[1].version(), 2);
        assert_eq!(events[2].version(), 3);
        assert_eq!(events[3].version(), 4);
    }

    /// Test: is_supported_version bekerja dengan benar.
    #[test]
    fn test_is_supported_version() {
        let supported = FallbackEvent::FallbackActivated {
            version: FALLBACK_EVENT_SCHEMA_VERSION,
        };
        let unsupported = FallbackEvent::FallbackActivated { version: 999 };

        assert!(supported.is_supported_version());
        assert!(!unsupported.is_supported_version());
    }

    /// Test: PartialEq bekerja dengan benar.
    #[test]
    fn test_partial_eq() {
        let event1 = FallbackEvent::FallbackActivated { version: 1 };
        let event2 = FallbackEvent::FallbackActivated { version: 1 };
        let event3 = FallbackEvent::FallbackActivated { version: 2 };
        let event4 = FallbackEvent::FallbackDeactivated { version: 1 };

        assert_eq!(event1, event2, "Same variant and version must be equal");
        assert_ne!(event1, event3, "Different version must not be equal");
        assert_ne!(event1, event4, "Different variant must not be equal");
    }

    /// Test: Clone bekerja dengan benar.
    #[test]
    fn test_clone() {
        let event = FallbackEvent::ReconciliationStarted {
            version: FALLBACK_EVENT_SCHEMA_VERSION,
        };
        let cloned = event.clone();

        assert_eq!(event, cloned, "Clone must produce equal value");
    }

    /// Test: Debug trait tersedia.
    #[test]
    fn test_debug() {
        let event = FallbackEvent::FallbackActivated {
            version: FALLBACK_EVENT_SCHEMA_VERSION,
        };
        let debug_str = format!("{:?}", event);

        assert!(
            debug_str.contains("FallbackActivated"),
            "Debug output must contain variant name"
        );
        assert!(
            debug_str.contains("version"),
            "Debug output must contain field name"
        );
    }

    /// Test: Enum memiliki tepat 4 variant (compile-time check via exhaustive match).
    #[test]
    fn test_exactly_four_variants() {
        let event = FallbackEvent::FallbackActivated { version: 1 };

        // Exhaustive match membuktikan tepat 4 variant
        let _variant_name = match event {
            FallbackEvent::FallbackActivated { .. } => "FallbackActivated",
            FallbackEvent::FallbackDeactivated { .. } => "FallbackDeactivated",
            FallbackEvent::ReconciliationStarted { .. } => "ReconciliationStarted",
            FallbackEvent::ReconciliationCompleted { .. } => "ReconciliationCompleted",
        };
        // Jika ada variant ke-5, match ini akan error saat compile
    }

    /// Test: JSON serialization juga deterministik (serde compatibility).
    #[test]
    fn test_json_serialize_deserialize() {
        let event = FallbackEvent::FallbackActivated {
            version: FALLBACK_EVENT_SCHEMA_VERSION,
        };

        let json = serde_json::to_string(&event);
        assert!(json.is_ok(), "JSON serialization must succeed");

        let json_str = json.unwrap();
        let deserialized: Result<FallbackEvent, _> = serde_json::from_str(&json_str);
        assert!(deserialized.is_ok(), "JSON deserialization must succeed");

        let decoded = deserialized.unwrap();
        assert_eq!(event, decoded, "JSON round-trip must produce identical result");
    }
}