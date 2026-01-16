//! # Reconcile Report Schema
//!
//! Modul ini mendefinisikan struktur laporan hasil reconciliation
//! untuk proses pemindahan blobs dari fallback DA ke primary DA (Celestia).
//!
//! ## Desain
//!
//! - `ReconcileReport` adalah container utama untuk hasil reconciliation
//! - `ReconcileDetail` merepresentasikan hasil per-blob
//! - `ReconcileStatus` adalah enum status untuk setiap blob
//!
//! ## Serialization Guarantee
//!
//! Semua struktur menggunakan derive macros standar serde yang menjamin:
//! - Serialisasi deterministik (input sama → output sama)
//! - Round-trip safety (serialize → deserialize → identical)
//!
//! ## Usage
//!
//! ```
//! use dsdn_proto::reconcile_report::{ReconcileReport, ReconcileDetail, ReconcileStatus};
//!
//! let report = ReconcileReport {
//!     total_pending: 100,
//!     reconciled: 95,
//!     failed: 3,
//!     skipped: 2,
//!     details: vec![
//!         ReconcileDetail {
//!             blob_sequence: 1,
//!             original_height: 1000,
//!             celestia_height: Some(5000),
//!             status: ReconcileStatus::Success,
//!             error: None,
//!         },
//!     ],
//!     started_at: 1704067200,
//!     completed_at: 1704070800,
//! };
//! ```

use serde::{Deserialize, Serialize};

// ════════════════════════════════════════════════════════════════════════════════
// RECONCILE STATUS ENUM
// ════════════════════════════════════════════════════════════════════════════════

/// Status hasil reconciliation untuk setiap blob.
///
/// Enum ini merepresentasikan empat kemungkinan status
/// yang dapat dimiliki blob setelah proses reconciliation.
///
/// ## Variants
///
/// - `Success`: Blob berhasil di-reconcile ke Celestia
/// - `Failed`: Blob gagal di-reconcile (lihat error message)
/// - `Skipped`: Blob dilewati karena kondisi tertentu
/// - `Pending`: Blob belum diproses
///
/// ## Serialization
///
/// Enum ini di-serialize sebagai string tag oleh serde untuk readability.
/// Format ini deterministik dan stabil untuk backward compatibility.
///
/// ## Stability
///
/// Urutan dan makna variant bersifat stabil dan tidak akan berubah.
/// Variant baru hanya dapat ditambahkan di akhir jika diperlukan.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReconcileStatus {
    /// Blob berhasil di-reconcile ke Celestia.
    ///
    /// Status ini menandakan blob telah berhasil di-post
    /// ke Celestia dan mendapatkan height konfirmasi.
    Success,

    /// Blob gagal di-reconcile ke Celestia.
    ///
    /// Status ini menandakan proses reconciliation untuk blob
    /// ini mengalami error. Detail error tersedia di field `error`
    /// pada `ReconcileDetail`.
    Failed,

    /// Blob dilewati dan tidak di-reconcile.
    ///
    /// Status ini menandakan blob sengaja tidak di-reconcile
    /// karena kondisi tertentu (misalnya: sudah expired,
    /// duplicate, atau berdasarkan policy).
    Skipped,

    /// Blob belum diproses dalam reconciliation.
    ///
    /// Status ini menandakan blob masih dalam antrian
    /// dan belum diproses oleh reconciliation worker.
    Pending,
}

impl Default for ReconcileStatus {
    /// Mengembalikan default status.
    ///
    /// Default adalah `Pending` karena:
    /// - Merepresentasikan state awal sebelum processing
    /// - Eksplisit dipilih (bukan implicit Rust ordering)
    /// - Safe default yang tidak mengindikasikan success atau failure
    #[inline]
    fn default() -> Self {
        Self::Pending
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// RECONCILE DETAIL STRUCT
// ════════════════════════════════════════════════════════════════════════════════

/// Detail hasil reconciliation untuk satu blob.
///
/// Struct ini merepresentasikan informasi lengkap
/// tentang proses reconciliation untuk satu blob individual.
///
/// ## Fields
///
/// Semua fields bersifat wajib dan eksplisit:
/// - `blob_sequence`: Sequence number blob dalam fallback DA
/// - `original_height`: Height di fallback DA saat blob disimpan
/// - `celestia_height`: Height di Celestia setelah reconciliation (jika sukses)
/// - `status`: Status hasil reconciliation
/// - `error`: Pesan error jika status adalah `Failed`
///
/// ## Error Field Convention
///
/// Field `error` hanya boleh berisi `Some(...)` jika `status` adalah `Failed`.
/// Untuk status lain, field `error` harus `None`.
///
/// ## Serialization
///
/// Struct ini dapat di-serialize menggunakan bincode atau JSON.
/// Semua fields ikut dalam serialisasi, tidak ada field tersembunyi.
///
/// ## Example
///
/// ```
/// use dsdn_proto::reconcile_report::{ReconcileDetail, ReconcileStatus};
///
/// // Success case
/// let success = ReconcileDetail {
///     blob_sequence: 42,
///     original_height: 1000,
///     celestia_height: Some(5000),
///     status: ReconcileStatus::Success,
///     error: None,
/// };
///
/// // Failed case
/// let failed = ReconcileDetail {
///     blob_sequence: 43,
///     original_height: 1001,
///     celestia_height: None,
///     status: ReconcileStatus::Failed,
///     error: Some(String::from("celestia_timeout")),
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReconcileDetail {
    /// Sequence number blob dalam fallback DA.
    ///
    /// Merupakan identifier unik untuk blob dalam konteks
    /// fallback DA layer. Digunakan untuk tracking dan
    /// cross-reference dengan data di fallback storage.
    ///
    /// Nilai ini bersifat monotonically increasing dalam
    /// satu session fallback.
    pub blob_sequence: u64,

    /// Height di fallback DA saat blob awalnya disimpan.
    ///
    /// Merepresentasikan "logical height" atau batch number
    /// di fallback DA tempat blob ini pertama kali disimpan.
    ///
    /// Nilai ini digunakan untuk:
    /// - Ordering dan replay
    /// - Audit trail
    /// - Debugging
    pub original_height: u64,

    /// Height di Celestia setelah blob berhasil di-reconcile.
    ///
    /// Bernilai `Some(height)` jika blob berhasil di-post ke Celestia,
    /// di mana `height` adalah block height Celestia yang mengkonfirmasi blob.
    ///
    /// Bernilai `None` jika:
    /// - Blob gagal di-reconcile (`status == Failed`)
    /// - Blob dilewati (`status == Skipped`)
    /// - Blob belum diproses (`status == Pending`)
    pub celestia_height: Option<u64>,

    /// Status hasil reconciliation untuk blob ini.
    ///
    /// Menentukan apakah blob berhasil, gagal, dilewati,
    /// atau masih pending. Lihat dokumentasi `ReconcileStatus`
    /// untuk detail setiap variant.
    pub status: ReconcileStatus,

    /// Pesan error jika reconciliation gagal.
    ///
    /// Bernilai `Some(message)` jika `status == ReconcileStatus::Failed`,
    /// berisi deskripsi singkat penyebab kegagalan.
    ///
    /// Bernilai `None` untuk status selain `Failed`.
    ///
    /// Contoh nilai:
    /// - "celestia_timeout": Celestia tidak merespon dalam batas waktu
    /// - "invalid_blob_format": Format blob tidak valid
    /// - "network_error": Koneksi ke Celestia gagal
    pub error: Option<String>,
}

impl Default for ReconcileDetail {
    /// Membuat instance `ReconcileDetail` dengan nilai default.
    ///
    /// Nilai default bersifat:
    /// - Deterministik (tidak bergantung pada state eksternal)
    /// - Valid secara tipe
    /// - Dapat diidentifikasi sebagai "belum diisi"
    ///
    /// ## Default Values
    ///
    /// - `blob_sequence`: 0
    /// - `original_height`: 0
    /// - `celestia_height`: None
    /// - `status`: `Pending`
    /// - `error`: None
    #[inline]
    fn default() -> Self {
        Self {
            blob_sequence: 0,
            original_height: 0,
            celestia_height: None,
            status: ReconcileStatus::default(),
            error: None,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// RECONCILE REPORT STRUCT
// ════════════════════════════════════════════════════════════════════════════════

/// Laporan lengkap hasil proses reconciliation.
///
/// Struct ini merepresentasikan summary dan detail lengkap
/// dari proses reconciliation blobs dari fallback DA ke Celestia.
///
/// ## Fields
///
/// Semua fields bersifat wajib dan eksplisit:
/// - `total_pending`: Total blobs yang menunggu reconciliation
/// - `reconciled`: Jumlah blobs yang berhasil di-reconcile
/// - `failed`: Jumlah blobs yang gagal di-reconcile
/// - `skipped`: Jumlah blobs yang dilewati
/// - `details`: Detail per-blob
/// - `started_at`: Timestamp mulai
/// - `completed_at`: Timestamp selesai
///
/// ## Invariants
///
/// Untuk report yang valid:
/// - `total_pending == reconciled + failed + skipped + (pending in details)`
/// - `details.len()` dapat kurang dari `total_pending` jika hanya partial report
///
/// ## Serialization
///
/// Struct ini dapat di-serialize menggunakan bincode atau JSON.
/// Semua fields ikut dalam serialisasi, tidak ada field tersembunyi.
///
/// ## Example
///
/// ```
/// use dsdn_proto::reconcile_report::{ReconcileReport, ReconcileDetail, ReconcileStatus};
///
/// let report = ReconcileReport {
///     total_pending: 100,
///     reconciled: 95,
///     failed: 3,
///     skipped: 2,
///     details: Vec::new(), // Simplified for example
///     started_at: 1704067200,
///     completed_at: 1704070800,
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReconcileReport {
    /// Total jumlah blobs yang menunggu untuk di-reconcile.
    ///
    /// Merepresentasikan jumlah blobs di fallback DA yang
    /// perlu dipindahkan ke Celestia pada saat reconciliation dimulai.
    ///
    /// Nilai ini digunakan untuk:
    /// - Progress calculation
    /// - Completeness verification
    /// - Capacity planning
    pub total_pending: u64,

    /// Jumlah blobs yang berhasil di-reconcile ke Celestia.
    ///
    /// Merepresentasikan blobs yang sukses di-post ke Celestia
    /// dan mendapatkan konfirmasi height.
    ///
    /// Nilai ini harus <= `total_pending`.
    pub reconciled: u64,

    /// Jumlah blobs yang gagal di-reconcile.
    ///
    /// Merepresentasikan blobs yang mengalami error selama
    /// proses reconciliation dan tidak berhasil di-post ke Celestia.
    ///
    /// Detail error untuk setiap blob tersedia di `details`.
    pub failed: u64,

    /// Jumlah blobs yang dilewati dan tidak di-reconcile.
    ///
    /// Merepresentasikan blobs yang sengaja tidak di-reconcile
    /// berdasarkan kondisi tertentu (expired, duplicate, policy).
    pub skipped: u64,

    /// Detail hasil reconciliation per-blob.
    ///
    /// Berisi informasi lengkap untuk setiap blob yang diproses.
    /// Urutan dalam vector sesuai urutan processing.
    ///
    /// Catatan: Vector dapat kosong jika hanya summary yang diperlukan,
    /// atau dapat berisi subset dari `total_pending` untuk partial report.
    pub details: Vec<ReconcileDetail>,

    /// Unix timestamp (seconds since epoch) saat reconciliation dimulai.
    ///
    /// Timestamp ini merepresentasikan waktu lokal sistem ketika
    /// proses reconciliation secara resmi dimulai.
    ///
    /// Nilai 0 menandakan timestamp belum diisi (hanya untuk Default).
    pub started_at: u64,

    /// Unix timestamp (seconds since epoch) saat reconciliation selesai.
    ///
    /// Timestamp ini merepresentasikan waktu lokal sistem ketika
    /// proses reconciliation secara resmi selesai.
    ///
    /// Nilai 0 menandakan timestamp belum diisi (hanya untuk Default).
    pub completed_at: u64,
}

impl ReconcileReport {
    /// Menghitung durasi reconciliation dalam detik.
    ///
    /// ## Returns
    ///
    /// Durasi dalam detik, dihitung sebagai `completed_at - started_at`.
    /// Jika `completed_at < started_at` (invalid state), mengembalikan 0.
    ///
    /// ## Determinism
    ///
    /// Fungsi ini bersifat deterministik: input yang sama selalu
    /// menghasilkan output yang sama.
    #[inline]
    #[must_use]
    pub const fn duration_secs(&self) -> u64 {
        if self.completed_at >= self.started_at {
            self.completed_at - self.started_at
        } else {
            0
        }
    }

    /// Menghitung success rate sebagai persentase.
    ///
    /// ## Returns
    ///
    /// Persentase blobs yang berhasil di-reconcile (0-100).
    /// Mengembalikan 0 jika `total_pending` adalah 0 untuk menghindari division by zero.
    ///
    /// ## Determinism
    ///
    /// Fungsi ini bersifat deterministik: input yang sama selalu
    /// menghasilkan output yang sama.
    #[inline]
    #[must_use]
    pub const fn success_rate_percent(&self) -> u64 {
        if self.total_pending == 0 {
            0
        } else {
            (self.reconciled * 100) / self.total_pending
        }
    }
}

impl Default for ReconcileReport {
    /// Membuat instance `ReconcileReport` dengan nilai default.
    ///
    /// Nilai default bersifat:
    /// - Deterministik (tidak bergantung pada state eksternal)
    /// - Valid secara tipe
    /// - Dapat diidentifikasi sebagai "belum diisi"
    ///
    /// ## Default Values
    ///
    /// - `total_pending`: 0
    /// - `reconciled`: 0
    /// - `failed`: 0
    /// - `skipped`: 0
    /// - `details`: empty Vec
    /// - `started_at`: 0
    /// - `completed_at`: 0
    #[inline]
    fn default() -> Self {
        Self {
            total_pending: 0,
            reconciled: 0,
            failed: 0,
            skipped: 0,
            details: Vec::new(),
            started_at: 0,
            completed_at: 0,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ════════════════════════════════════════════════════════════════════════════
    // RECONCILE STATUS ENUM TESTS
    // ════════════════════════════════════════════════════════════════════════════

    /// Test: ReconcileStatus memiliki tepat 4 variant (compile-time check).
    #[test]
    fn test_reconcile_status_exactly_four_variants() {
        let status = ReconcileStatus::Success;

        // Exhaustive match membuktikan tepat 4 variant
        let _name = match status {
            ReconcileStatus::Success => "Success",
            ReconcileStatus::Failed => "Failed",
            ReconcileStatus::Skipped => "Skipped",
            ReconcileStatus::Pending => "Pending",
        };
        // Jika ada variant ke-5, match ini akan error saat compile
    }

    /// Test: ReconcileStatus dapat di-serialize dan di-deserialize (bincode).
    #[test]
    fn test_reconcile_status_bincode_roundtrip() {
        let variants = [
            ReconcileStatus::Success,
            ReconcileStatus::Failed,
            ReconcileStatus::Skipped,
            ReconcileStatus::Pending,
        ];

        for original in variants {
            let serialized = bincode::serialize(&original);
            assert!(serialized.is_ok(), "ReconcileStatus serialization must succeed");

            let bytes = serialized.unwrap();
            let deserialized: Result<ReconcileStatus, _> = bincode::deserialize(&bytes);
            assert!(deserialized.is_ok(), "ReconcileStatus deserialization must succeed");

            let decoded = deserialized.unwrap();
            assert_eq!(original, decoded, "ReconcileStatus round-trip must be identical");
        }
    }

    /// Test: ReconcileStatus dapat di-serialize dan di-deserialize (JSON).
    #[test]
    fn test_reconcile_status_json_roundtrip() {
        let variants = [
            ReconcileStatus::Success,
            ReconcileStatus::Failed,
            ReconcileStatus::Skipped,
            ReconcileStatus::Pending,
        ];

        for original in variants {
            let json = serde_json::to_string(&original);
            assert!(json.is_ok(), "ReconcileStatus JSON serialization must succeed");

            let json_str = json.unwrap();
            let deserialized: Result<ReconcileStatus, _> = serde_json::from_str(&json_str);
            assert!(deserialized.is_ok(), "ReconcileStatus JSON deserialization must succeed");

            let decoded = deserialized.unwrap();
            assert_eq!(original, decoded, "ReconcileStatus JSON round-trip must be identical");
        }
    }

    /// Test: ReconcileStatus default adalah Pending.
    #[test]
    fn test_reconcile_status_default() {
        let default_status = ReconcileStatus::default();
        assert_eq!(
            default_status,
            ReconcileStatus::Pending,
            "Default ReconcileStatus must be Pending"
        );
    }

    /// Test: ReconcileStatus PartialEq bekerja dengan benar.
    #[test]
    fn test_reconcile_status_partial_eq() {
        let s1 = ReconcileStatus::Success;
        let s2 = ReconcileStatus::Success;
        let f1 = ReconcileStatus::Failed;

        assert_eq!(s1, s2, "Same variant must be equal");
        assert_ne!(s1, f1, "Different variants must not be equal");
    }

    /// Test: ReconcileStatus Clone bekerja dengan benar.
    #[test]
    fn test_reconcile_status_clone() {
        let original = ReconcileStatus::Failed;
        let cloned = original.clone();
        assert_eq!(original, cloned, "Clone must produce equal value");
    }

    /// Test: ReconcileStatus Copy trait bekerja (karena Copy derive).
    #[test]
    fn test_reconcile_status_copy() {
        let original = ReconcileStatus::Success;
        let copied = original; // Copy, bukan move
        assert_eq!(original, copied, "Copy must produce equal value");
        // original masih bisa digunakan karena Copy
        let _ = original;
    }

    // ════════════════════════════════════════════════════════════════════════════
    // RECONCILE DETAIL STRUCT TESTS
    // ════════════════════════════════════════════════════════════════════════════

    /// Test: ReconcileDetail dapat di-serialize dan di-deserialize (bincode).
    #[test]
    fn test_reconcile_detail_bincode_roundtrip() {
        let original = ReconcileDetail {
            blob_sequence: 42,
            original_height: 1000,
            celestia_height: Some(5000),
            status: ReconcileStatus::Success,
            error: None,
        };

        let serialized = bincode::serialize(&original);
        assert!(serialized.is_ok(), "ReconcileDetail serialization must succeed");

        let bytes = serialized.unwrap();
        let deserialized: Result<ReconcileDetail, _> = bincode::deserialize(&bytes);
        assert!(deserialized.is_ok(), "ReconcileDetail deserialization must succeed");

        let decoded = deserialized.unwrap();
        assert_eq!(original, decoded, "ReconcileDetail round-trip must be identical");
    }

    /// Test: ReconcileDetail dapat di-serialize dan di-deserialize (JSON).
    #[test]
    fn test_reconcile_detail_json_roundtrip() {
        let original = ReconcileDetail {
            blob_sequence: 100,
            original_height: 2000,
            celestia_height: None,
            status: ReconcileStatus::Failed,
            error: Some(String::from("celestia_timeout")),
        };

        let json = serde_json::to_string(&original);
        assert!(json.is_ok(), "ReconcileDetail JSON serialization must succeed");

        let json_str = json.unwrap();
        let deserialized: Result<ReconcileDetail, _> = serde_json::from_str(&json_str);
        assert!(deserialized.is_ok(), "ReconcileDetail JSON deserialization must succeed");

        let decoded = deserialized.unwrap();
        assert_eq!(original, decoded, "ReconcileDetail JSON round-trip must be identical");
    }

    /// Test: ReconcileDetail serialization deterministik.
    #[test]
    fn test_reconcile_detail_deterministic_serialization() {
        let detail = ReconcileDetail {
            blob_sequence: 50,
            original_height: 500,
            celestia_height: Some(1500),
            status: ReconcileStatus::Success,
            error: None,
        };

        let bytes1 = bincode::serialize(&detail);
        let bytes2 = bincode::serialize(&detail);

        assert!(bytes1.is_ok(), "First serialization must succeed");
        assert!(bytes2.is_ok(), "Second serialization must succeed");
        assert_eq!(
            bytes1.unwrap(),
            bytes2.unwrap(),
            "Deterministic: same input must produce same bytes"
        );
    }

    /// Test: ReconcileDetail Default menghasilkan nilai valid.
    #[test]
    fn test_reconcile_detail_default_validity() {
        let default_detail = ReconcileDetail::default();

        assert_eq!(default_detail.blob_sequence, 0, "Default blob_sequence must be 0");
        assert_eq!(default_detail.original_height, 0, "Default original_height must be 0");
        assert!(default_detail.celestia_height.is_none(), "Default celestia_height must be None");
        assert_eq!(
            default_detail.status,
            ReconcileStatus::Pending,
            "Default status must be Pending"
        );
        assert!(default_detail.error.is_none(), "Default error must be None");
    }

    /// Test: ReconcileDetail Default dapat di-serialize dan di-deserialize.
    #[test]
    fn test_reconcile_detail_default_serialization() {
        let default_detail = ReconcileDetail::default();

        let serialized = bincode::serialize(&default_detail);
        assert!(serialized.is_ok(), "Default ReconcileDetail serialization must succeed");

        let bytes = serialized.unwrap();
        let deserialized: Result<ReconcileDetail, _> = bincode::deserialize(&bytes);
        assert!(deserialized.is_ok(), "Default ReconcileDetail deserialization must succeed");

        let decoded = deserialized.unwrap();
        assert_eq!(
            default_detail, decoded,
            "Default ReconcileDetail round-trip must be identical"
        );
    }

    /// Test: ReconcileDetail Default deterministik.
    #[test]
    fn test_reconcile_detail_default_deterministic() {
        let default1 = ReconcileDetail::default();
        let default2 = ReconcileDetail::default();

        assert_eq!(
            default1, default2,
            "Default must be deterministic (same value every time)"
        );
    }

    /// Test: ReconcileDetail PartialEq bekerja dengan benar.
    #[test]
    fn test_reconcile_detail_partial_eq() {
        let detail1 = ReconcileDetail {
            blob_sequence: 1,
            original_height: 100,
            celestia_height: Some(500),
            status: ReconcileStatus::Success,
            error: None,
        };

        let detail2 = ReconcileDetail {
            blob_sequence: 1,
            original_height: 100,
            celestia_height: Some(500),
            status: ReconcileStatus::Success,
            error: None,
        };

        let detail3 = ReconcileDetail {
            blob_sequence: 2, // Different
            original_height: 100,
            celestia_height: Some(500),
            status: ReconcileStatus::Success,
            error: None,
        };

        assert_eq!(detail1, detail2, "Same values must be equal");
        assert_ne!(detail1, detail3, "Different blob_sequence must not be equal");
    }

    /// Test: ReconcileDetail Clone bekerja dengan benar.
    #[test]
    fn test_reconcile_detail_clone() {
        let original = ReconcileDetail {
            blob_sequence: 99,
            original_height: 999,
            celestia_height: Some(9999),
            status: ReconcileStatus::Skipped,
            error: None,
        };

        let cloned = original.clone();
        assert_eq!(original, cloned, "Clone must produce equal value");
    }

    /// Test: ReconcileDetail Debug output mengandung semua field names.
    #[test]
    fn test_reconcile_detail_debug() {
        let detail = ReconcileDetail {
            blob_sequence: 1,
            original_height: 2,
            celestia_height: Some(3),
            status: ReconcileStatus::Success,
            error: None,
        };

        let debug_str = format!("{:?}", detail);

        assert!(debug_str.contains("blob_sequence"), "Debug must contain 'blob_sequence'");
        assert!(debug_str.contains("original_height"), "Debug must contain 'original_height'");
        assert!(debug_str.contains("celestia_height"), "Debug must contain 'celestia_height'");
        assert!(debug_str.contains("status"), "Debug must contain 'status'");
        assert!(debug_str.contains("error"), "Debug must contain 'error'");
    }

    /// Test: ReconcileDetail dengan semua status variants.
    #[test]
    fn test_reconcile_detail_all_status_variants() {
        let statuses = [
            ReconcileStatus::Success,
            ReconcileStatus::Failed,
            ReconcileStatus::Skipped,
            ReconcileStatus::Pending,
        ];

        for status in statuses {
            let detail = ReconcileDetail {
                blob_sequence: 1,
                original_height: 2,
                celestia_height: if status == ReconcileStatus::Success {
                    Some(100)
                } else {
                    None
                },
                status,
                error: if status == ReconcileStatus::Failed {
                    Some(String::from("test_error"))
                } else {
                    None
                },
            };

            let serialized = bincode::serialize(&detail);
            assert!(serialized.is_ok(), "Detail with status {:?} must serialize", status);

            let bytes = serialized.unwrap();
            let deserialized: Result<ReconcileDetail, _> = bincode::deserialize(&bytes);
            assert!(deserialized.is_ok(), "Detail with status {:?} must deserialize", status);

            let decoded = deserialized.unwrap();
            assert_eq!(detail, decoded, "Detail with status {:?} round-trip must match", status);
        }
    }

    /// Test: ReconcileDetail dengan u64::MAX values.
    #[test]
    fn test_reconcile_detail_max_u64_values() {
        let detail = ReconcileDetail {
            blob_sequence: u64::MAX,
            original_height: u64::MAX,
            celestia_height: Some(u64::MAX),
            status: ReconcileStatus::Success,
            error: None,
        };

        let serialized = bincode::serialize(&detail);
        assert!(serialized.is_ok(), "Max u64 values must serialize");

        let bytes = serialized.unwrap();
        let deserialized: Result<ReconcileDetail, _> = bincode::deserialize(&bytes);
        assert!(deserialized.is_ok(), "Max u64 values must deserialize");

        let decoded = deserialized.unwrap();
        assert_eq!(decoded.blob_sequence, u64::MAX);
        assert_eq!(decoded.original_height, u64::MAX);
        assert_eq!(decoded.celestia_height, Some(u64::MAX));
    }

    // ════════════════════════════════════════════════════════════════════════════
    // RECONCILE REPORT STRUCT TESTS
    // ════════════════════════════════════════════════════════════════════════════

    /// Test: ReconcileReport dapat di-serialize dan di-deserialize (bincode).
    #[test]
    fn test_reconcile_report_bincode_roundtrip() {
        let original = ReconcileReport {
            total_pending: 100,
            reconciled: 95,
            failed: 3,
            skipped: 2,
            details: vec![
                ReconcileDetail {
                    blob_sequence: 1,
                    original_height: 100,
                    celestia_height: Some(500),
                    status: ReconcileStatus::Success,
                    error: None,
                },
                ReconcileDetail {
                    blob_sequence: 2,
                    original_height: 101,
                    celestia_height: None,
                    status: ReconcileStatus::Failed,
                    error: Some(String::from("timeout")),
                },
            ],
            started_at: 1704067200,
            completed_at: 1704070800,
        };

        let serialized = bincode::serialize(&original);
        assert!(serialized.is_ok(), "ReconcileReport serialization must succeed");

        let bytes = serialized.unwrap();
        let deserialized: Result<ReconcileReport, _> = bincode::deserialize(&bytes);
        assert!(deserialized.is_ok(), "ReconcileReport deserialization must succeed");

        let decoded = deserialized.unwrap();
        assert_eq!(original, decoded, "ReconcileReport round-trip must be identical");
    }

    /// Test: ReconcileReport dapat di-serialize dan di-deserialize (JSON).
    #[test]
    fn test_reconcile_report_json_roundtrip() {
        let original = ReconcileReport {
            total_pending: 50,
            reconciled: 48,
            failed: 1,
            skipped: 1,
            details: vec![ReconcileDetail::default()],
            started_at: 1704000000,
            completed_at: 1704003600,
        };

        let json = serde_json::to_string(&original);
        assert!(json.is_ok(), "ReconcileReport JSON serialization must succeed");

        let json_str = json.unwrap();
        let deserialized: Result<ReconcileReport, _> = serde_json::from_str(&json_str);
        assert!(deserialized.is_ok(), "ReconcileReport JSON deserialization must succeed");

        let decoded = deserialized.unwrap();
        assert_eq!(original, decoded, "ReconcileReport JSON round-trip must be identical");
    }

    /// Test: ReconcileReport serialization deterministik.
    #[test]
    fn test_reconcile_report_deterministic_serialization() {
        let report = ReconcileReport {
            total_pending: 10,
            reconciled: 8,
            failed: 1,
            skipped: 1,
            details: vec![ReconcileDetail::default()],
            started_at: 1000,
            completed_at: 2000,
        };

        let bytes1 = bincode::serialize(&report);
        let bytes2 = bincode::serialize(&report);

        assert!(bytes1.is_ok(), "First serialization must succeed");
        assert!(bytes2.is_ok(), "Second serialization must succeed");
        assert_eq!(
            bytes1.unwrap(),
            bytes2.unwrap(),
            "Deterministic: same input must produce same bytes"
        );
    }

    /// Test: ReconcileReport Default menghasilkan nilai valid.
    #[test]
    fn test_reconcile_report_default_validity() {
        let default_report = ReconcileReport::default();

        assert_eq!(default_report.total_pending, 0, "Default total_pending must be 0");
        assert_eq!(default_report.reconciled, 0, "Default reconciled must be 0");
        assert_eq!(default_report.failed, 0, "Default failed must be 0");
        assert_eq!(default_report.skipped, 0, "Default skipped must be 0");
        assert!(default_report.details.is_empty(), "Default details must be empty");
        assert_eq!(default_report.started_at, 0, "Default started_at must be 0");
        assert_eq!(default_report.completed_at, 0, "Default completed_at must be 0");
    }

    /// Test: ReconcileReport Default dapat di-serialize dan di-deserialize.
    #[test]
    fn test_reconcile_report_default_serialization() {
        let default_report = ReconcileReport::default();

        let serialized = bincode::serialize(&default_report);
        assert!(serialized.is_ok(), "Default ReconcileReport serialization must succeed");

        let bytes = serialized.unwrap();
        let deserialized: Result<ReconcileReport, _> = bincode::deserialize(&bytes);
        assert!(deserialized.is_ok(), "Default ReconcileReport deserialization must succeed");

        let decoded = deserialized.unwrap();
        assert_eq!(
            default_report, decoded,
            "Default ReconcileReport round-trip must be identical"
        );
    }

    /// Test: ReconcileReport Default deterministik.
    #[test]
    fn test_reconcile_report_default_deterministic() {
        let default1 = ReconcileReport::default();
        let default2 = ReconcileReport::default();

        assert_eq!(
            default1, default2,
            "Default must be deterministic (same value every time)"
        );
    }

    /// Test: ReconcileReport PartialEq bekerja dengan benar.
    #[test]
    fn test_reconcile_report_partial_eq() {
        let report1 = ReconcileReport {
            total_pending: 10,
            reconciled: 8,
            failed: 1,
            skipped: 1,
            details: Vec::new(),
            started_at: 100,
            completed_at: 200,
        };

        let report2 = ReconcileReport {
            total_pending: 10,
            reconciled: 8,
            failed: 1,
            skipped: 1,
            details: Vec::new(),
            started_at: 100,
            completed_at: 200,
        };

        let report3 = ReconcileReport {
            total_pending: 20, // Different
            reconciled: 8,
            failed: 1,
            skipped: 1,
            details: Vec::new(),
            started_at: 100,
            completed_at: 200,
        };

        assert_eq!(report1, report2, "Same values must be equal");
        assert_ne!(report1, report3, "Different total_pending must not be equal");
    }

    /// Test: ReconcileReport Clone bekerja dengan benar.
    #[test]
    fn test_reconcile_report_clone() {
        let original = ReconcileReport {
            total_pending: 100,
            reconciled: 90,
            failed: 5,
            skipped: 5,
            details: vec![ReconcileDetail::default()],
            started_at: 1000,
            completed_at: 2000,
        };

        let cloned = original.clone();
        assert_eq!(original, cloned, "Clone must produce equal value");
    }

    /// Test: ReconcileReport Debug output mengandung semua field names.
    #[test]
    fn test_reconcile_report_debug() {
        let report = ReconcileReport::default();

        let debug_str = format!("{:?}", report);

        assert!(debug_str.contains("total_pending"), "Debug must contain 'total_pending'");
        assert!(debug_str.contains("reconciled"), "Debug must contain 'reconciled'");
        assert!(debug_str.contains("failed"), "Debug must contain 'failed'");
        assert!(debug_str.contains("skipped"), "Debug must contain 'skipped'");
        assert!(debug_str.contains("details"), "Debug must contain 'details'");
        assert!(debug_str.contains("started_at"), "Debug must contain 'started_at'");
        assert!(debug_str.contains("completed_at"), "Debug must contain 'completed_at'");
    }

    /// Test: ReconcileReport dengan empty details vector.
    #[test]
    fn test_reconcile_report_empty_details() {
        let report = ReconcileReport {
            total_pending: 0,
            reconciled: 0,
            failed: 0,
            skipped: 0,
            details: Vec::new(),
            started_at: 100,
            completed_at: 200,
        };

        let serialized = bincode::serialize(&report);
        assert!(serialized.is_ok(), "Empty details must serialize");

        let bytes = serialized.unwrap();
        let deserialized: Result<ReconcileReport, _> = bincode::deserialize(&bytes);
        assert!(deserialized.is_ok(), "Empty details must deserialize");

        let decoded = deserialized.unwrap();
        assert!(decoded.details.is_empty(), "Decoded details must be empty");
    }

    /// Test: ReconcileReport dengan large details vector.
    #[test]
    fn test_reconcile_report_large_details() {
        let details: Vec<ReconcileDetail> = (0..100)
            .map(|i| ReconcileDetail {
                blob_sequence: i,
                original_height: i * 10,
                celestia_height: Some(i * 100),
                status: ReconcileStatus::Success,
                error: None,
            })
            .collect();

        let report = ReconcileReport {
            total_pending: 100,
            reconciled: 100,
            failed: 0,
            skipped: 0,
            details,
            started_at: 1000,
            completed_at: 2000,
        };

        let serialized = bincode::serialize(&report);
        assert!(serialized.is_ok(), "Large details must serialize");

        let bytes = serialized.unwrap();
        let deserialized: Result<ReconcileReport, _> = bincode::deserialize(&bytes);
        assert!(deserialized.is_ok(), "Large details must deserialize");

        let decoded = deserialized.unwrap();
        assert_eq!(decoded.details.len(), 100, "Decoded must have 100 details");
    }

    /// Test: ReconcileReport dengan u64::MAX values.
    #[test]
    fn test_reconcile_report_max_u64_values() {
        let report = ReconcileReport {
            total_pending: u64::MAX,
            reconciled: u64::MAX,
            failed: u64::MAX,
            skipped: u64::MAX,
            details: Vec::new(),
            started_at: u64::MAX,
            completed_at: u64::MAX,
        };

        let serialized = bincode::serialize(&report);
        assert!(serialized.is_ok(), "Max u64 values must serialize");

        let bytes = serialized.unwrap();
        let deserialized: Result<ReconcileReport, _> = bincode::deserialize(&bytes);
        assert!(deserialized.is_ok(), "Max u64 values must deserialize");

        let decoded = deserialized.unwrap();
        assert_eq!(decoded.total_pending, u64::MAX);
        assert_eq!(decoded.reconciled, u64::MAX);
        assert_eq!(decoded.failed, u64::MAX);
        assert_eq!(decoded.skipped, u64::MAX);
        assert_eq!(decoded.started_at, u64::MAX);
        assert_eq!(decoded.completed_at, u64::MAX);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // RECONCILE REPORT METHOD TESTS
    // ════════════════════════════════════════════════════════════════════════════

    /// Test: duration_secs() returns correct value.
    #[test]
    fn test_reconcile_report_duration_secs() {
        let report = ReconcileReport {
            total_pending: 0,
            reconciled: 0,
            failed: 0,
            skipped: 0,
            details: Vec::new(),
            started_at: 1000,
            completed_at: 1500,
        };

        assert_eq!(report.duration_secs(), 500, "Duration must be 500 seconds");
    }

    /// Test: duration_secs() returns 0 when timestamps are equal.
    #[test]
    fn test_reconcile_report_duration_secs_zero() {
        let report = ReconcileReport {
            total_pending: 0,
            reconciled: 0,
            failed: 0,
            skipped: 0,
            details: Vec::new(),
            started_at: 1000,
            completed_at: 1000,
        };

        assert_eq!(report.duration_secs(), 0, "Duration must be 0 when equal");
    }

    /// Test: duration_secs() returns 0 when completed_at < started_at (invalid state).
    #[test]
    fn test_reconcile_report_duration_secs_invalid() {
        let report = ReconcileReport {
            total_pending: 0,
            reconciled: 0,
            failed: 0,
            skipped: 0,
            details: Vec::new(),
            started_at: 2000,
            completed_at: 1000, // Invalid: completed before started
        };

        assert_eq!(report.duration_secs(), 0, "Duration must be 0 for invalid state");
    }

    /// Test: success_rate_percent() returns correct value.
    #[test]
    fn test_reconcile_report_success_rate_percent() {
        let report = ReconcileReport {
            total_pending: 100,
            reconciled: 95,
            failed: 3,
            skipped: 2,
            details: Vec::new(),
            started_at: 0,
            completed_at: 0,
        };

        assert_eq!(report.success_rate_percent(), 95, "Success rate must be 95%");
    }

    /// Test: success_rate_percent() returns 0 when total_pending is 0.
    #[test]
    fn test_reconcile_report_success_rate_zero_total() {
        let report = ReconcileReport {
            total_pending: 0,
            reconciled: 0,
            failed: 0,
            skipped: 0,
            details: Vec::new(),
            started_at: 0,
            completed_at: 0,
        };

        assert_eq!(
            report.success_rate_percent(),
            0,
            "Success rate must be 0 when total_pending is 0"
        );
    }

    /// Test: success_rate_percent() returns 100 when all reconciled.
    #[test]
    fn test_reconcile_report_success_rate_full() {
        let report = ReconcileReport {
            total_pending: 50,
            reconciled: 50,
            failed: 0,
            skipped: 0,
            details: Vec::new(),
            started_at: 0,
            completed_at: 0,
        };

        assert_eq!(report.success_rate_percent(), 100, "Success rate must be 100%");
    }

    /// Test: duration_secs() is deterministic.
    #[test]
    fn test_reconcile_report_duration_secs_deterministic() {
        let report = ReconcileReport {
            total_pending: 0,
            reconciled: 0,
            failed: 0,
            skipped: 0,
            details: Vec::new(),
            started_at: 500,
            completed_at: 1500,
        };

        let result1 = report.duration_secs();
        let result2 = report.duration_secs();

        assert_eq!(result1, result2, "duration_secs() must be deterministic");
    }

    /// Test: success_rate_percent() is deterministic.
    #[test]
    fn test_reconcile_report_success_rate_deterministic() {
        let report = ReconcileReport {
            total_pending: 100,
            reconciled: 75,
            failed: 15,
            skipped: 10,
            details: Vec::new(),
            started_at: 0,
            completed_at: 0,
        };

        let result1 = report.success_rate_percent();
        let result2 = report.success_rate_percent();

        assert_eq!(result1, result2, "success_rate_percent() must be deterministic");
    }
}