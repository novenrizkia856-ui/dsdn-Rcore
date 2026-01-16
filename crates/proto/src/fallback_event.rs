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

/// Default reason string untuk `FallbackActivated` saat menggunakan `Default` trait.
///
/// Nilai ini bersifat eksplisit dan tidak kosong untuk menghindari ambiguitas.
/// Digunakan hanya untuk inisialisasi default, bukan untuk production events.
const DEFAULT_FALLBACK_REASON: &str = "unspecified";

/// Default timestamp value untuk `FallbackActivated` saat menggunakan `Default` trait.
///
/// Nilai 0 dipilih karena:
/// - Deterministik (tidak bergantung pada waktu sistem)
/// - Mudah diidentifikasi sebagai "belum diisi"
/// - Valid secara tipe (u64)
const DEFAULT_TIMESTAMP: u64 = 0;

/// Default Celestia height untuk `FallbackActivated` saat menggunakan `Default` trait.
///
/// Nilai 0 menandakan "tidak ada height terakhir yang diketahui".
const DEFAULT_CELESTIA_HEIGHT: u64 = 0;

/// Jumlah detik dalam satu menit.
const SECONDS_PER_MINUTE: u64 = 60;

/// Jumlah detik dalam satu jam.
const SECONDS_PER_HOUR: u64 = 3600;

/// Jumlah detik dalam satu hari.
const SECONDS_PER_DAY: u64 = 86400;

// ════════════════════════════════════════════════════════════════════════════════
// FALLBACK TYPE ENUM
// ════════════════════════════════════════════════════════════════════════════════

/// Tipe fallback DA layer yang dapat diaktifkan.
///
/// Enum ini merepresentasikan dua jenis fallback yang tersedia
/// dalam sistem DSDN ketika primary DA (Celestia) tidak tersedia.
///
/// ## Variants
///
/// - `ValidatorQuorum`: Fallback ke validator quorum DA (secondary)
/// - `Emergency`: Fallback ke emergency DA yang dikelola foundation (tertiary)
///
/// ## Serialization
///
/// Enum ini di-serialize sebagai string tag oleh serde untuk readability.
/// Format ini deterministik dan stabil untuk backward compatibility.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FallbackType {
    /// Fallback ke Validator Quorum DA.
    ///
    /// Menggunakan quorum dari validator aktif untuk menyimpan blobs.
    /// Membutuhkan minimal 2/3 validator signatures untuk validity.
    ValidatorQuorum,

    /// Fallback ke Emergency DA.
    ///
    /// Menggunakan self-hosted DA yang dikelola oleh foundation.
    /// Digunakan sebagai last resort ketika Validator Quorum juga tidak tersedia.
    Emergency,
}

impl Default for FallbackType {
    /// Mengembalikan default fallback type.
    ///
    /// Default adalah `ValidatorQuorum` karena:
    /// - Lebih decentralized dibanding Emergency
    /// - Merupakan fallback pertama dalam hierarki
    /// - Eksplisit dipilih (bukan implicit Rust ordering)
    #[inline]
    fn default() -> Self {
        Self::ValidatorQuorum
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// FALLBACK ACTIVATED STRUCT
// ════════════════════════════════════════════════════════════════════════════════

/// Struktur data untuk event aktivasi fallback.
///
/// Struct ini merepresentasikan informasi lengkap ketika sistem
/// beralih dari primary DA (Celestia) ke fallback DA.
///
/// ## Fields
///
/// Semua fields bersifat wajib dan eksplisit:
/// - `reason`: Alasan mengapa fallback diaktifkan
/// - `celestia_last_height`: Height terakhir yang diketahui dari Celestia
/// - `activated_at`: Unix timestamp saat aktivasi
/// - `fallback_type`: Tipe fallback yang diaktifkan
///
/// ## Serialization
///
/// Struct ini dapat di-serialize menggunakan bincode atau JSON.
/// Semua fields ikut dalam serialisasi, tidak ada field tersembunyi.
///
/// ## Example
///
/// ```
/// use dsdn_proto::fallback_event::{FallbackActivated, FallbackType};
///
/// let event = FallbackActivated {
///     reason: String::from("celestia_timeout"),
///     celestia_last_height: 12345,
///     activated_at: 1704067200,
///     fallback_type: FallbackType::ValidatorQuorum,
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FallbackActivated {
    /// Alasan mengapa fallback diaktifkan.
    ///
    /// Berisi deskripsi singkat yang menjelaskan kondisi yang
    /// menyebabkan aktivasi fallback. Contoh nilai:
    /// - "celestia_timeout": Celestia tidak merespon dalam batas waktu
    /// - "celestia_unavailable": Celestia tidak dapat dijangkau
    /// - "manual_override": Aktivasi manual oleh operator
    pub reason: String,

    /// Height terakhir yang diketahui dari Celestia sebelum fallback.
    ///
    /// Nilai ini digunakan untuk:
    /// - Tracking titik terakhir sinkronisasi dengan Celestia
    /// - Menentukan starting point untuk reconciliation saat recovery
    /// - Audit trail untuk debugging
    ///
    /// Nilai 0 menandakan tidak ada height yang diketahui.
    pub celestia_last_height: u64,

    /// Unix timestamp (seconds since epoch) saat fallback diaktifkan.
    ///
    /// Timestamp ini merepresentasikan waktu lokal sistem ketika
    /// keputusan untuk mengaktifkan fallback dibuat.
    ///
    /// Nilai 0 menandakan timestamp belum diisi (hanya untuk Default).
    pub activated_at: u64,

    /// Tipe fallback yang diaktifkan.
    ///
    /// Menentukan DA layer mana yang digunakan sebagai pengganti Celestia.
    /// Lihat dokumentasi `FallbackType` untuk detail setiap tipe.
    pub fallback_type: FallbackType,
}

impl Default for FallbackActivated {
    /// Membuat instance `FallbackActivated` dengan nilai default.
    ///
    /// Nilai default bersifat:
    /// - Deterministik (tidak bergantung pada state eksternal)
    /// - Valid secara tipe
    /// - Dapat diidentifikasi sebagai "belum diisi"
    ///
    /// ## Default Values
    ///
    /// - `reason`: "unspecified" (eksplisit, bukan string kosong)
    /// - `celestia_last_height`: 0 (tidak ada height diketahui)
    /// - `activated_at`: 0 (timestamp belum diisi)
    /// - `fallback_type`: `ValidatorQuorum` (fallback pertama dalam hierarki)
    #[inline]
    fn default() -> Self {
        Self {
            reason: String::from(DEFAULT_FALLBACK_REASON),
            celestia_last_height: DEFAULT_CELESTIA_HEIGHT,
            activated_at: DEFAULT_TIMESTAMP,
            fallback_type: FallbackType::default(),
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// FALLBACK DEACTIVATED STRUCT
// ════════════════════════════════════════════════════════════════════════════════

/// Struktur data untuk event deaktivasi fallback (recovery Celestia).
///
/// Struct ini merepresentasikan informasi lengkap ketika sistem
/// kembali dari fallback DA ke primary DA (Celestia) setelah recovery.
///
/// ## Fields
///
/// Semua fields bersifat wajib dan eksplisit:
/// - `celestia_recovery_height`: Height Celestia saat recovery berhasil
/// - `blobs_reconciled`: Jumlah blobs yang di-reconcile ke Celestia
/// - `deactivated_at`: Unix timestamp saat deaktivasi
/// - `downtime_duration_secs`: Total durasi downtime dalam detik
///
/// ## Serialization
///
/// Struct ini dapat di-serialize menggunakan bincode atau JSON.
/// Semua fields ikut dalam serialisasi, tidak ada field tersembunyi.
///
/// ## Example
///
/// ```
/// use dsdn_proto::fallback_event::FallbackDeactivated;
///
/// let event = FallbackDeactivated {
///     celestia_recovery_height: 12500,
///     blobs_reconciled: 42,
///     deactivated_at: 1704070800,
///     downtime_duration_secs: 3600,
/// };
///
/// assert_eq!(event.duration_human(), "1h 0m 0s");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FallbackDeactivated {
    /// Height Celestia pada saat recovery berhasil dilakukan.
    ///
    /// Nilai ini menandakan block height pertama yang berhasil
    /// di-post ke Celestia setelah periode fallback berakhir.
    ///
    /// Digunakan untuk:
    /// - Verifikasi bahwa Celestia kembali operasional
    /// - Tracking titik awal sinkronisasi ulang
    /// - Audit trail untuk debugging dan monitoring
    pub celestia_recovery_height: u64,

    /// Jumlah blobs yang berhasil di-reconcile ke Celestia.
    ///
    /// Merepresentasikan total blobs yang awalnya disimpan
    /// di fallback DA dan kemudian berhasil dipindahkan ke Celestia
    /// selama proses reconciliation.
    ///
    /// Nilai 0 menandakan tidak ada blobs yang perlu di-reconcile
    /// (fallback period sangat singkat atau tidak ada aktivitas).
    pub blobs_reconciled: u64,

    /// Unix timestamp (seconds since epoch) saat fallback dinonaktifkan.
    ///
    /// Timestamp ini merepresentasikan waktu lokal sistem ketika
    /// sistem kembali menggunakan primary DA (Celestia).
    ///
    /// Nilai 0 menandakan timestamp belum diisi (hanya untuk Default).
    pub deactivated_at: u64,

    /// Total durasi downtime Celestia dalam detik.
    ///
    /// Dihitung sebagai selisih antara `deactivated_at` dan
    /// `activated_at` dari event `FallbackActivated` sebelumnya.
    ///
    /// Nilai ini digunakan untuk:
    /// - Monitoring dan alerting
    /// - SLA tracking
    /// - Analisis performa sistem
    ///
    /// Nilai 0 menandakan durasi tidak diketahui atau sangat singkat.
    pub downtime_duration_secs: u64,
}

impl FallbackDeactivated {
    /// Mengkonversi `downtime_duration_secs` ke format string yang dapat dibaca manusia.
    ///
    /// ## Format Output
    ///
    /// Format output mengikuti pola: `{days}d {hours}h {minutes}m {seconds}s`
    ///
    /// Dengan ketentuan:
    /// - Komponen dengan nilai 0 di awal tidak ditampilkan (kecuali semua 0)
    /// - Jika durasi 0 detik, output adalah "0s"
    /// - Jika durasi < 1 menit, output adalah "{seconds}s"
    /// - Jika durasi < 1 jam, output adalah "{minutes}m {seconds}s"
    /// - Jika durasi < 1 hari, output adalah "{hours}h {minutes}m {seconds}s"
    /// - Jika durasi >= 1 hari, output adalah "{days}d {hours}h {minutes}m {seconds}s"
    ///
    /// ## Determinism
    ///
    /// Fungsi ini bersifat deterministik: input yang sama selalu
    /// menghasilkan output yang sama, tanpa bergantung pada locale,
    /// timezone, atau state global apapun.
    ///
    /// ## Examples
    ///
    /// ```
    /// use dsdn_proto::fallback_event::FallbackDeactivated;
    ///
    /// let event = FallbackDeactivated {
    ///     celestia_recovery_height: 100,
    ///     blobs_reconciled: 0,
    ///     deactivated_at: 0,
    ///     downtime_duration_secs: 3661,
    /// };
    /// assert_eq!(event.duration_human(), "1h 1m 1s");
    ///
    /// let event2 = FallbackDeactivated {
    ///     celestia_recovery_height: 100,
    ///     blobs_reconciled: 0,
    ///     deactivated_at: 0,
    ///     downtime_duration_secs: 0,
    /// };
    /// assert_eq!(event2.duration_human(), "0s");
    /// ```
    #[must_use]
    pub fn duration_human(&self) -> String {
        let total_secs = self.downtime_duration_secs;

        // Handle zero case explicitly
        if total_secs == 0 {
            return String::from("0s");
        }

        let days = total_secs / SECONDS_PER_DAY;
        let remaining_after_days = total_secs % SECONDS_PER_DAY;

        let hours = remaining_after_days / SECONDS_PER_HOUR;
        let remaining_after_hours = remaining_after_days % SECONDS_PER_HOUR;

        let minutes = remaining_after_hours / SECONDS_PER_MINUTE;
        let seconds = remaining_after_hours % SECONDS_PER_MINUTE;

        // Build output string, omitting leading zero components
        let mut parts: Vec<String> = Vec::with_capacity(4);

        if days > 0 {
            parts.push(format!("{}d", days));
        }

        if days > 0 || hours > 0 {
            parts.push(format!("{}h", hours));
        }

        if days > 0 || hours > 0 || minutes > 0 {
            parts.push(format!("{}m", minutes));
        }

        // Seconds always included (we already handled total_secs == 0)
        parts.push(format!("{}s", seconds));

        parts.join(" ")
    }
}

impl Default for FallbackDeactivated {
    /// Membuat instance `FallbackDeactivated` dengan nilai default.
    ///
    /// Nilai default bersifat:
    /// - Deterministik (tidak bergantung pada state eksternal)
    /// - Valid secara tipe
    /// - Dapat diidentifikasi sebagai "belum diisi"
    ///
    /// ## Default Values
    ///
    /// - `celestia_recovery_height`: 0 (tidak ada height diketahui)
    /// - `blobs_reconciled`: 0 (tidak ada blobs di-reconcile)
    /// - `deactivated_at`: 0 (timestamp belum diisi)
    /// - `downtime_duration_secs`: 0 (durasi tidak diketahui)
    #[inline]
    fn default() -> Self {
        Self {
            celestia_recovery_height: DEFAULT_CELESTIA_HEIGHT,
            blobs_reconciled: 0,
            deactivated_at: DEFAULT_TIMESTAMP,
            downtime_duration_secs: 0,
        }
    }
}

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

    // ════════════════════════════════════════════════════════════════════════════
    // FALLBACK EVENT ENUM TESTS (existing)
    // ════════════════════════════════════════════════════════════════════════════

    /// Test: FallbackActivated variant dapat di-serialize dan di-deserialize.
    #[test]
    fn test_fallback_activated_variant_serialize_deserialize() {
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

    /// Test: FallbackDeactivated variant dapat di-serialize dan di-deserialize.
    #[test]
    fn test_fallback_deactivated_variant_serialize_deserialize() {
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

    // ════════════════════════════════════════════════════════════════════════════
    // FALLBACK TYPE ENUM TESTS (14A.1A.2)
    // ════════════════════════════════════════════════════════════════════════════

    /// Test: FallbackType memiliki tepat 2 variant (compile-time check).
    #[test]
    fn test_fallback_type_exactly_two_variants() {
        let ft = FallbackType::ValidatorQuorum;

        // Exhaustive match membuktikan tepat 2 variant
        let _name = match ft {
            FallbackType::ValidatorQuorum => "ValidatorQuorum",
            FallbackType::Emergency => "Emergency",
        };
        // Jika ada variant ke-3, match ini akan error saat compile
    }

    /// Test: FallbackType dapat di-serialize dan di-deserialize (bincode).
    #[test]
    fn test_fallback_type_bincode_roundtrip() {
        let variants = [FallbackType::ValidatorQuorum, FallbackType::Emergency];

        for original in variants {
            let serialized = bincode::serialize(&original);
            assert!(serialized.is_ok(), "FallbackType serialization must succeed");

            let bytes = serialized.unwrap();
            let deserialized: Result<FallbackType, _> = bincode::deserialize(&bytes);
            assert!(deserialized.is_ok(), "FallbackType deserialization must succeed");

            let decoded = deserialized.unwrap();
            assert_eq!(original, decoded, "FallbackType round-trip must be identical");
        }
    }

    /// Test: FallbackType dapat di-serialize dan di-deserialize (JSON).
    #[test]
    fn test_fallback_type_json_roundtrip() {
        let variants = [FallbackType::ValidatorQuorum, FallbackType::Emergency];

        for original in variants {
            let json = serde_json::to_string(&original);
            assert!(json.is_ok(), "FallbackType JSON serialization must succeed");

            let json_str = json.unwrap();
            let deserialized: Result<FallbackType, _> = serde_json::from_str(&json_str);
            assert!(deserialized.is_ok(), "FallbackType JSON deserialization must succeed");

            let decoded = deserialized.unwrap();
            assert_eq!(original, decoded, "FallbackType JSON round-trip must be identical");
        }
    }

    /// Test: FallbackType default adalah ValidatorQuorum.
    #[test]
    fn test_fallback_type_default() {
        let default_type = FallbackType::default();
        assert_eq!(
            default_type,
            FallbackType::ValidatorQuorum,
            "Default FallbackType must be ValidatorQuorum"
        );
    }

    /// Test: FallbackType PartialEq bekerja dengan benar.
    #[test]
    fn test_fallback_type_partial_eq() {
        let vq1 = FallbackType::ValidatorQuorum;
        let vq2 = FallbackType::ValidatorQuorum;
        let em = FallbackType::Emergency;

        assert_eq!(vq1, vq2, "Same variant must be equal");
        assert_ne!(vq1, em, "Different variants must not be equal");
    }

    /// Test: FallbackType Clone bekerja dengan benar.
    #[test]
    fn test_fallback_type_clone() {
        let original = FallbackType::Emergency;
        let cloned = original.clone();
        assert_eq!(original, cloned, "Clone must produce equal value");
    }

    /// Test: FallbackType Copy trait bekerja (karena Copy derive).
    #[test]
    fn test_fallback_type_copy() {
        let original = FallbackType::ValidatorQuorum;
        let copied = original; // Copy, bukan move
        assert_eq!(original, copied, "Copy must produce equal value");
        // original masih bisa digunakan karena Copy
        let _ = original;
    }

    // ════════════════════════════════════════════════════════════════════════════
    // FALLBACK ACTIVATED STRUCT TESTS (14A.1A.2)
    // ════════════════════════════════════════════════════════════════════════════

    /// Test: FallbackActivated struct dapat di-serialize dan di-deserialize (bincode).
    #[test]
    fn test_fallback_activated_struct_bincode_roundtrip() {
        let original = FallbackActivated {
            reason: String::from("celestia_timeout"),
            celestia_last_height: 12345,
            activated_at: 1704067200,
            fallback_type: FallbackType::ValidatorQuorum,
        };

        let serialized = bincode::serialize(&original);
        assert!(serialized.is_ok(), "FallbackActivated serialization must succeed");

        let bytes = serialized.unwrap();
        let deserialized: Result<FallbackActivated, _> = bincode::deserialize(&bytes);
        assert!(deserialized.is_ok(), "FallbackActivated deserialization must succeed");

        let decoded = deserialized.unwrap();
        assert_eq!(original, decoded, "FallbackActivated round-trip must be identical");
    }

    /// Test: FallbackActivated struct dapat di-serialize dan di-deserialize (JSON).
    #[test]
    fn test_fallback_activated_struct_json_roundtrip() {
        let original = FallbackActivated {
            reason: String::from("manual_override"),
            celestia_last_height: 99999,
            activated_at: 1704153600,
            fallback_type: FallbackType::Emergency,
        };

        let json = serde_json::to_string(&original);
        assert!(json.is_ok(), "FallbackActivated JSON serialization must succeed");

        let json_str = json.unwrap();
        let deserialized: Result<FallbackActivated, _> = serde_json::from_str(&json_str);
        assert!(deserialized.is_ok(), "FallbackActivated JSON deserialization must succeed");

        let decoded = deserialized.unwrap();
        assert_eq!(original, decoded, "FallbackActivated JSON round-trip must be identical");
    }

    /// Test: FallbackActivated serialization deterministik.
    #[test]
    fn test_fallback_activated_struct_deterministic_serialization() {
        let event = FallbackActivated {
            reason: String::from("test_reason"),
            celestia_last_height: 1000,
            activated_at: 2000,
            fallback_type: FallbackType::ValidatorQuorum,
        };

        let bytes1 = bincode::serialize(&event);
        let bytes2 = bincode::serialize(&event);

        assert!(bytes1.is_ok(), "First serialization must succeed");
        assert!(bytes2.is_ok(), "Second serialization must succeed");
        assert_eq!(
            bytes1.unwrap(),
            bytes2.unwrap(),
            "Deterministic: same input must produce same bytes"
        );
    }

    /// Test: FallbackActivated Default menghasilkan nilai valid.
    #[test]
    fn test_fallback_activated_default_validity() {
        let default_event = FallbackActivated::default();

        // Verify semua field memiliki nilai yang diharapkan
        assert_eq!(
            default_event.reason, "unspecified",
            "Default reason must be 'unspecified'"
        );
        assert_eq!(
            default_event.celestia_last_height, 0,
            "Default celestia_last_height must be 0"
        );
        assert_eq!(
            default_event.activated_at, 0,
            "Default activated_at must be 0"
        );
        assert_eq!(
            default_event.fallback_type,
            FallbackType::ValidatorQuorum,
            "Default fallback_type must be ValidatorQuorum"
        );
    }

    /// Test: FallbackActivated Default dapat di-serialize dan di-deserialize.
    #[test]
    fn test_fallback_activated_default_serialization() {
        let default_event = FallbackActivated::default();

        let serialized = bincode::serialize(&default_event);
        assert!(serialized.is_ok(), "Default FallbackActivated serialization must succeed");

        let bytes = serialized.unwrap();
        let deserialized: Result<FallbackActivated, _> = bincode::deserialize(&bytes);
        assert!(deserialized.is_ok(), "Default FallbackActivated deserialization must succeed");

        let decoded = deserialized.unwrap();
        assert_eq!(
            default_event, decoded,
            "Default FallbackActivated round-trip must be identical"
        );
    }

    /// Test: FallbackActivated Default deterministik.
    #[test]
    fn test_fallback_activated_default_deterministic() {
        let default1 = FallbackActivated::default();
        let default2 = FallbackActivated::default();

        assert_eq!(
            default1, default2,
            "Default must be deterministic (same value every time)"
        );
    }

    /// Test: FallbackActivated PartialEq bekerja dengan benar.
    #[test]
    fn test_fallback_activated_partial_eq() {
        let event1 = FallbackActivated {
            reason: String::from("test"),
            celestia_last_height: 100,
            activated_at: 200,
            fallback_type: FallbackType::ValidatorQuorum,
        };

        let event2 = FallbackActivated {
            reason: String::from("test"),
            celestia_last_height: 100,
            activated_at: 200,
            fallback_type: FallbackType::ValidatorQuorum,
        };

        let event3 = FallbackActivated {
            reason: String::from("different"),
            celestia_last_height: 100,
            activated_at: 200,
            fallback_type: FallbackType::ValidatorQuorum,
        };

        assert_eq!(event1, event2, "Same values must be equal");
        assert_ne!(event1, event3, "Different reason must not be equal");
    }

    /// Test: FallbackActivated Clone bekerja dengan benar.
    #[test]
    fn test_fallback_activated_clone() {
        let original = FallbackActivated {
            reason: String::from("clone_test"),
            celestia_last_height: 555,
            activated_at: 666,
            fallback_type: FallbackType::Emergency,
        };

        let cloned = original.clone();
        assert_eq!(original, cloned, "Clone must produce equal value");
    }

    /// Test: FallbackActivated Debug output mengandung semua field names.
    #[test]
    fn test_fallback_activated_debug() {
        let event = FallbackActivated {
            reason: String::from("debug_test"),
            celestia_last_height: 777,
            activated_at: 888,
            fallback_type: FallbackType::ValidatorQuorum,
        };

        let debug_str = format!("{:?}", event);

        assert!(debug_str.contains("reason"), "Debug must contain 'reason'");
        assert!(
            debug_str.contains("celestia_last_height"),
            "Debug must contain 'celestia_last_height'"
        );
        assert!(debug_str.contains("activated_at"), "Debug must contain 'activated_at'");
        assert!(debug_str.contains("fallback_type"), "Debug must contain 'fallback_type'");
    }

    /// Test: FallbackActivated dengan berbagai FallbackType values.
    #[test]
    fn test_fallback_activated_with_different_fallback_types() {
        let with_quorum = FallbackActivated {
            reason: String::from("test"),
            celestia_last_height: 1,
            activated_at: 2,
            fallback_type: FallbackType::ValidatorQuorum,
        };

        let with_emergency = FallbackActivated {
            reason: String::from("test"),
            celestia_last_height: 1,
            activated_at: 2,
            fallback_type: FallbackType::Emergency,
        };

        assert_ne!(
            with_quorum, with_emergency,
            "Different fallback_type must produce different events"
        );

        // Verify both can be serialized
        let bytes_quorum = bincode::serialize(&with_quorum);
        let bytes_emergency = bincode::serialize(&with_emergency);

        assert!(bytes_quorum.is_ok(), "ValidatorQuorum variant must serialize");
        assert!(bytes_emergency.is_ok(), "Emergency variant must serialize");
    }

    /// Test: FallbackActivated dengan reason kosong valid secara tipe.
    #[test]
    fn test_fallback_activated_empty_reason_valid() {
        let event = FallbackActivated {
            reason: String::new(), // Empty string is valid
            celestia_last_height: 0,
            activated_at: 0,
            fallback_type: FallbackType::ValidatorQuorum,
        };

        let serialized = bincode::serialize(&event);
        assert!(serialized.is_ok(), "Empty reason must be serializable");

        let bytes = serialized.unwrap();
        let deserialized: Result<FallbackActivated, _> = bincode::deserialize(&bytes);
        assert!(deserialized.is_ok(), "Empty reason must be deserializable");
    }

    /// Test: FallbackActivated dengan nilai maksimum u64.
    #[test]
    fn test_fallback_activated_max_u64_values() {
        let event = FallbackActivated {
            reason: String::from("max_test"),
            celestia_last_height: u64::MAX,
            activated_at: u64::MAX,
            fallback_type: FallbackType::Emergency,
        };

        let serialized = bincode::serialize(&event);
        assert!(serialized.is_ok(), "Max u64 values must serialize");

        let bytes = serialized.unwrap();
        let deserialized: Result<FallbackActivated, _> = bincode::deserialize(&bytes);
        assert!(deserialized.is_ok(), "Max u64 values must deserialize");

        let decoded = deserialized.unwrap();
        assert_eq!(decoded.celestia_last_height, u64::MAX);
        assert_eq!(decoded.activated_at, u64::MAX);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // FALLBACK DEACTIVATED STRUCT TESTS (14A.1A.3)
    // ════════════════════════════════════════════════════════════════════════════

    /// Test: FallbackDeactivated struct dapat di-serialize dan di-deserialize (bincode).
    #[test]
    fn test_fallback_deactivated_struct_bincode_roundtrip() {
        let original = FallbackDeactivated {
            celestia_recovery_height: 12500,
            blobs_reconciled: 42,
            deactivated_at: 1704070800,
            downtime_duration_secs: 3600,
        };

        let serialized = bincode::serialize(&original);
        assert!(serialized.is_ok(), "FallbackDeactivated serialization must succeed");

        let bytes = serialized.unwrap();
        let deserialized: Result<FallbackDeactivated, _> = bincode::deserialize(&bytes);
        assert!(deserialized.is_ok(), "FallbackDeactivated deserialization must succeed");

        let decoded = deserialized.unwrap();
        assert_eq!(original, decoded, "FallbackDeactivated round-trip must be identical");
    }

    /// Test: FallbackDeactivated struct dapat di-serialize dan di-deserialize (JSON).
    #[test]
    fn test_fallback_deactivated_struct_json_roundtrip() {
        let original = FallbackDeactivated {
            celestia_recovery_height: 99999,
            blobs_reconciled: 100,
            deactivated_at: 1704153600,
            downtime_duration_secs: 7200,
        };

        let json = serde_json::to_string(&original);
        assert!(json.is_ok(), "FallbackDeactivated JSON serialization must succeed");

        let json_str = json.unwrap();
        let deserialized: Result<FallbackDeactivated, _> = serde_json::from_str(&json_str);
        assert!(deserialized.is_ok(), "FallbackDeactivated JSON deserialization must succeed");

        let decoded = deserialized.unwrap();
        assert_eq!(original, decoded, "FallbackDeactivated JSON round-trip must be identical");
    }

    /// Test: FallbackDeactivated serialization deterministik.
    #[test]
    fn test_fallback_deactivated_struct_deterministic_serialization() {
        let event = FallbackDeactivated {
            celestia_recovery_height: 1000,
            blobs_reconciled: 50,
            deactivated_at: 2000,
            downtime_duration_secs: 500,
        };

        let bytes1 = bincode::serialize(&event);
        let bytes2 = bincode::serialize(&event);

        assert!(bytes1.is_ok(), "First serialization must succeed");
        assert!(bytes2.is_ok(), "Second serialization must succeed");
        assert_eq!(
            bytes1.unwrap(),
            bytes2.unwrap(),
            "Deterministic: same input must produce same bytes"
        );
    }

    /// Test: FallbackDeactivated Default menghasilkan nilai valid.
    #[test]
    fn test_fallback_deactivated_default_validity() {
        let default_event = FallbackDeactivated::default();

        assert_eq!(
            default_event.celestia_recovery_height, 0,
            "Default celestia_recovery_height must be 0"
        );
        assert_eq!(
            default_event.blobs_reconciled, 0,
            "Default blobs_reconciled must be 0"
        );
        assert_eq!(
            default_event.deactivated_at, 0,
            "Default deactivated_at must be 0"
        );
        assert_eq!(
            default_event.downtime_duration_secs, 0,
            "Default downtime_duration_secs must be 0"
        );
    }

    /// Test: FallbackDeactivated Default dapat di-serialize dan di-deserialize.
    #[test]
    fn test_fallback_deactivated_default_serialization() {
        let default_event = FallbackDeactivated::default();

        let serialized = bincode::serialize(&default_event);
        assert!(serialized.is_ok(), "Default FallbackDeactivated serialization must succeed");

        let bytes = serialized.unwrap();
        let deserialized: Result<FallbackDeactivated, _> = bincode::deserialize(&bytes);
        assert!(deserialized.is_ok(), "Default FallbackDeactivated deserialization must succeed");

        let decoded = deserialized.unwrap();
        assert_eq!(
            default_event, decoded,
            "Default FallbackDeactivated round-trip must be identical"
        );
    }

    /// Test: FallbackDeactivated Default deterministik.
    #[test]
    fn test_fallback_deactivated_default_deterministic() {
        let default1 = FallbackDeactivated::default();
        let default2 = FallbackDeactivated::default();

        assert_eq!(
            default1, default2,
            "Default must be deterministic (same value every time)"
        );
    }

    /// Test: FallbackDeactivated PartialEq bekerja dengan benar.
    #[test]
    fn test_fallback_deactivated_partial_eq() {
        let event1 = FallbackDeactivated {
            celestia_recovery_height: 100,
            blobs_reconciled: 10,
            deactivated_at: 200,
            downtime_duration_secs: 300,
        };

        let event2 = FallbackDeactivated {
            celestia_recovery_height: 100,
            blobs_reconciled: 10,
            deactivated_at: 200,
            downtime_duration_secs: 300,
        };

        let event3 = FallbackDeactivated {
            celestia_recovery_height: 999,
            blobs_reconciled: 10,
            deactivated_at: 200,
            downtime_duration_secs: 300,
        };

        assert_eq!(event1, event2, "Same values must be equal");
        assert_ne!(event1, event3, "Different celestia_recovery_height must not be equal");
    }

    /// Test: FallbackDeactivated Clone bekerja dengan benar.
    #[test]
    fn test_fallback_deactivated_clone() {
        let original = FallbackDeactivated {
            celestia_recovery_height: 555,
            blobs_reconciled: 66,
            deactivated_at: 777,
            downtime_duration_secs: 888,
        };

        let cloned = original.clone();
        assert_eq!(original, cloned, "Clone must produce equal value");
    }

    /// Test: FallbackDeactivated Debug output mengandung semua field names.
    #[test]
    fn test_fallback_deactivated_debug() {
        let event = FallbackDeactivated {
            celestia_recovery_height: 100,
            blobs_reconciled: 20,
            deactivated_at: 300,
            downtime_duration_secs: 400,
        };

        let debug_str = format!("{:?}", event);

        assert!(
            debug_str.contains("celestia_recovery_height"),
            "Debug must contain 'celestia_recovery_height'"
        );
        assert!(
            debug_str.contains("blobs_reconciled"),
            "Debug must contain 'blobs_reconciled'"
        );
        assert!(
            debug_str.contains("deactivated_at"),
            "Debug must contain 'deactivated_at'"
        );
        assert!(
            debug_str.contains("downtime_duration_secs"),
            "Debug must contain 'downtime_duration_secs'"
        );
    }

    /// Test: FallbackDeactivated dengan nilai maksimum u64.
    #[test]
    fn test_fallback_deactivated_max_u64_values() {
        let event = FallbackDeactivated {
            celestia_recovery_height: u64::MAX,
            blobs_reconciled: u64::MAX,
            deactivated_at: u64::MAX,
            downtime_duration_secs: u64::MAX,
        };

        let serialized = bincode::serialize(&event);
        assert!(serialized.is_ok(), "Max u64 values must serialize");

        let bytes = serialized.unwrap();
        let deserialized: Result<FallbackDeactivated, _> = bincode::deserialize(&bytes);
        assert!(deserialized.is_ok(), "Max u64 values must deserialize");

        let decoded = deserialized.unwrap();
        assert_eq!(decoded.celestia_recovery_height, u64::MAX);
        assert_eq!(decoded.blobs_reconciled, u64::MAX);
        assert_eq!(decoded.deactivated_at, u64::MAX);
        assert_eq!(decoded.downtime_duration_secs, u64::MAX);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // DURATION_HUMAN() METHOD TESTS (14A.1A.3)
    // ════════════════════════════════════════════════════════════════════════════

    /// Test: duration_human() returns "0s" for zero duration.
    #[test]
    fn test_duration_human_zero() {
        let event = FallbackDeactivated {
            celestia_recovery_height: 0,
            blobs_reconciled: 0,
            deactivated_at: 0,
            downtime_duration_secs: 0,
        };

        assert_eq!(event.duration_human(), "0s", "Zero duration must return '0s'");
    }

    /// Test: duration_human() returns correct format for seconds only.
    #[test]
    fn test_duration_human_seconds_only() {
        let event = FallbackDeactivated {
            celestia_recovery_height: 0,
            blobs_reconciled: 0,
            deactivated_at: 0,
            downtime_duration_secs: 45,
        };

        assert_eq!(event.duration_human(), "45s", "45 seconds must return '45s'");
    }

    /// Test: duration_human() returns correct format for minutes and seconds.
    #[test]
    fn test_duration_human_minutes_seconds() {
        let event = FallbackDeactivated {
            celestia_recovery_height: 0,
            blobs_reconciled: 0,
            deactivated_at: 0,
            downtime_duration_secs: 125, // 2 minutes 5 seconds
        };

        assert_eq!(event.duration_human(), "2m 5s", "125 seconds must return '2m 5s'");
    }

    /// Test: duration_human() returns correct format for hours, minutes, seconds.
    #[test]
    fn test_duration_human_hours_minutes_seconds() {
        let event = FallbackDeactivated {
            celestia_recovery_height: 0,
            blobs_reconciled: 0,
            deactivated_at: 0,
            downtime_duration_secs: 3661, // 1 hour 1 minute 1 second
        };

        assert_eq!(event.duration_human(), "1h 1m 1s", "3661 seconds must return '1h 1m 1s'");
    }

    /// Test: duration_human() returns correct format for days, hours, minutes, seconds.
    #[test]
    fn test_duration_human_days_hours_minutes_seconds() {
        let event = FallbackDeactivated {
            celestia_recovery_height: 0,
            blobs_reconciled: 0,
            deactivated_at: 0,
            downtime_duration_secs: 90061, // 1 day 1 hour 1 minute 1 second
        };

        assert_eq!(
            event.duration_human(),
            "1d 1h 1m 1s",
            "90061 seconds must return '1d 1h 1m 1s'"
        );
    }

    /// Test: duration_human() returns correct format for exact hours.
    #[test]
    fn test_duration_human_exact_hours() {
        let event = FallbackDeactivated {
            celestia_recovery_height: 0,
            blobs_reconciled: 0,
            deactivated_at: 0,
            downtime_duration_secs: 3600, // exactly 1 hour
        };

        assert_eq!(event.duration_human(), "1h 0m 0s", "3600 seconds must return '1h 0m 0s'");
    }

    /// Test: duration_human() returns correct format for exact days.
    #[test]
    fn test_duration_human_exact_days() {
        let event = FallbackDeactivated {
            celestia_recovery_height: 0,
            blobs_reconciled: 0,
            deactivated_at: 0,
            downtime_duration_secs: 86400, // exactly 1 day
        };

        assert_eq!(
            event.duration_human(),
            "1d 0h 0m 0s",
            "86400 seconds must return '1d 0h 0m 0s'"
        );
    }

    /// Test: duration_human() returns correct format for multiple days.
    #[test]
    fn test_duration_human_multiple_days() {
        let event = FallbackDeactivated {
            celestia_recovery_height: 0,
            blobs_reconciled: 0,
            deactivated_at: 0,
            downtime_duration_secs: 259200, // 3 days
        };

        assert_eq!(
            event.duration_human(),
            "3d 0h 0m 0s",
            "259200 seconds must return '3d 0h 0m 0s'"
        );
    }

    /// Test: duration_human() is deterministic.
    #[test]
    fn test_duration_human_deterministic() {
        let event = FallbackDeactivated {
            celestia_recovery_height: 100,
            blobs_reconciled: 10,
            deactivated_at: 200,
            downtime_duration_secs: 12345,
        };

        let result1 = event.duration_human();
        let result2 = event.duration_human();

        assert_eq!(
            result1, result2,
            "duration_human() must be deterministic (same output for same input)"
        );
    }

    /// Test: duration_human() handles large values correctly.
    #[test]
    fn test_duration_human_large_value() {
        let event = FallbackDeactivated {
            celestia_recovery_height: 0,
            blobs_reconciled: 0,
            deactivated_at: 0,
            downtime_duration_secs: 31536000, // 365 days
        };

        assert_eq!(
            event.duration_human(),
            "365d 0h 0m 0s",
            "31536000 seconds must return '365d 0h 0m 0s'"
        );
    }

    /// Test: duration_human() handles boundary between minutes and hours.
    #[test]
    fn test_duration_human_minute_hour_boundary() {
        let event = FallbackDeactivated {
            celestia_recovery_height: 0,
            blobs_reconciled: 0,
            deactivated_at: 0,
            downtime_duration_secs: 3599, // 59 minutes 59 seconds
        };

        assert_eq!(
            event.duration_human(),
            "59m 59s",
            "3599 seconds must return '59m 59s'"
        );
    }

    /// Test: duration_human() exact one minute.
    #[test]
    fn test_duration_human_exact_one_minute() {
        let event = FallbackDeactivated {
            celestia_recovery_height: 0,
            blobs_reconciled: 0,
            deactivated_at: 0,
            downtime_duration_secs: 60,
        };

        assert_eq!(event.duration_human(), "1m 0s", "60 seconds must return '1m 0s'");
    }

    /// Test: duration_human() with one second.
    #[test]
    fn test_duration_human_one_second() {
        let event = FallbackDeactivated {
            celestia_recovery_height: 0,
            blobs_reconciled: 0,
            deactivated_at: 0,
            downtime_duration_secs: 1,
        };

        assert_eq!(event.duration_human(), "1s", "1 second must return '1s'");
    }
}