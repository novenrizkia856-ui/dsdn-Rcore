//! # Consistency Report Schema
//!
//! Modul ini mendefinisikan struktur laporan verifikasi konsistensi state
//! antara fallback DA layer dan primary DA (Celestia).
//!
//! ## Desain
//!
//! - `ConsistencyReport` adalah container utama untuk hasil verifikasi
//! - `ConsistencyMismatch` merepresentasikan setiap ketidakkonsistenan yang ditemukan
//! - `MismatchType` mengkategorikan jenis ketidakkonsistenan
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
//! use dsdn_proto::consistency_report::{
//!     ConsistencyReport, ConsistencyMismatch, MismatchType
//! };
//!
//! let report = ConsistencyReport {
//!     celestia_height: 10000,
//!     fallback_height: 500,
//!     is_consistent: false,
//!     mismatches: vec![
//!         ConsistencyMismatch {
//!             sequence: 42,
//!             celestia_hash: None,
//!             fallback_hash: Some([0xAB; 32]),
//!             mismatch_type: MismatchType::Missing,
//!         },
//!     ],
//!     checked_at: 1704067200,
//!     check_duration_ms: 1500,
//! };
//! ```

use serde::{Deserialize, Serialize};

// ════════════════════════════════════════════════════════════════════════════════
// MISMATCH TYPE ENUM
// ════════════════════════════════════════════════════════════════════════════════

/// Tipe ketidakkonsistenan yang dapat ditemukan saat verifikasi.
///
/// Enum ini mengkategorikan jenis-jenis ketidakkonsistenan
/// yang mungkin terjadi antara fallback DA dan Celestia.
///
/// ## Variants
///
/// - `Missing`: Data ada di satu layer tetapi tidak ada di layer lain
/// - `HashMismatch`: Data ada di kedua layer tetapi hash tidak sama
/// - `SequenceGap`: Ada gap dalam sequence numbers
/// - `Duplicate`: Data dengan sequence yang sama muncul lebih dari sekali
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
pub enum MismatchType {
    /// Data ada di satu layer tetapi tidak ada di layer lain.
    ///
    /// Terjadi ketika:
    /// - Blob ada di fallback tetapi tidak ada di Celestia, atau
    /// - Blob ada di Celestia tetapi tidak ada di fallback
    ///
    /// Untuk menentukan layer mana yang memiliki data, periksa
    /// field `celestia_hash` dan `fallback_hash` pada `ConsistencyMismatch`.
    Missing,

    /// Data ada di kedua layer tetapi hash tidak sama.
    ///
    /// Terjadi ketika blob dengan sequence yang sama
    /// memiliki konten berbeda di fallback dan Celestia.
    /// Ini menandakan data corruption atau inconsistency serius.
    HashMismatch,

    /// Ada gap dalam sequence numbers.
    ///
    /// Terjadi ketika sequence number yang diharapkan
    /// tidak ditemukan di salah satu atau kedua layer.
    /// Menandakan data hilang atau out-of-order.
    SequenceGap,

    /// Data dengan sequence yang sama muncul lebih dari sekali.
    ///
    /// Terjadi ketika blob dengan sequence number yang sama
    /// ditemukan multiple kali dalam satu layer.
    /// Menandakan duplicate entry atau replay.
    Duplicate,
}

impl Default for MismatchType {
    /// Mengembalikan default mismatch type.
    ///
    /// Default adalah `Missing` karena:
    /// - Merupakan tipe mismatch paling umum
    /// - Eksplisit dipilih (bukan implicit Rust ordering)
    #[inline]
    fn default() -> Self {
        Self::Missing
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// CONSISTENCY MISMATCH STRUCT
// ════════════════════════════════════════════════════════════════════════════════

/// Detail ketidakkonsistenan yang ditemukan untuk satu blob.
///
/// Struct ini merepresentasikan informasi lengkap
/// tentang satu instance ketidakkonsistenan antara
/// fallback DA dan Celestia.
///
/// ## Fields
///
/// Semua fields bersifat wajib dan eksplisit:
/// - `sequence`: Sequence number blob yang memiliki masalah
/// - `celestia_hash`: Hash blob di Celestia (jika ada)
/// - `fallback_hash`: Hash blob di fallback (jika ada)
/// - `mismatch_type`: Kategori ketidakkonsistenan
///
/// ## Hash Field Convention
///
/// - `celestia_hash` = `None`: Blob tidak ditemukan di Celestia
/// - `fallback_hash` = `None`: Blob tidak ditemukan di fallback
/// - Keduanya `Some(...)`: Blob ada di kedua layer (untuk HashMismatch)
///
/// ## Serialization
///
/// Struct ini dapat di-serialize menggunakan bincode atau JSON.
/// Semua fields ikut dalam serialisasi, tidak ada field tersembunyi.
///
/// ## Example
///
/// ```
/// use dsdn_proto::consistency_report::{ConsistencyMismatch, MismatchType};
///
/// // Missing di Celestia
/// let missing = ConsistencyMismatch {
///     sequence: 42,
///     celestia_hash: None,
///     fallback_hash: Some([0xAB; 32]),
///     mismatch_type: MismatchType::Missing,
/// };
///
/// // Hash mismatch
/// let hash_mismatch = ConsistencyMismatch {
///     sequence: 43,
///     celestia_hash: Some([0x11; 32]),
///     fallback_hash: Some([0x22; 32]),
///     mismatch_type: MismatchType::HashMismatch,
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsistencyMismatch {
    /// Sequence number blob yang memiliki ketidakkonsistenan.
    ///
    /// Merupakan identifier blob dalam konteks
    /// fallback DA layer atau reconciliation.
    ///
    /// Digunakan untuk:
    /// - Identifikasi blob yang bermasalah
    /// - Cross-reference dengan logs dan storage
    /// - Ordering dalam laporan
    pub sequence: u64,

    /// Hash blob di Celestia, jika tersedia.
    ///
    /// Bernilai `Some([u8; 32])` jika blob ditemukan di Celestia,
    /// `None` jika blob tidak ada di Celestia.
    ///
    /// Format: 32 bytes SHA3-256 hash.
    pub celestia_hash: Option<[u8; 32]>,

    /// Hash blob di fallback DA, jika tersedia.
    ///
    /// Bernilai `Some([u8; 32])` jika blob ditemukan di fallback,
    /// `None` jika blob tidak ada di fallback.
    ///
    /// Format: 32 bytes SHA3-256 hash.
    pub fallback_hash: Option<[u8; 32]>,

    /// Kategori ketidakkonsistenan yang ditemukan.
    ///
    /// Menentukan jenis masalah yang terjadi untuk blob ini.
    /// Lihat dokumentasi `MismatchType` untuk detail setiap kategori.
    pub mismatch_type: MismatchType,
}

impl Default for ConsistencyMismatch {
    /// Membuat instance `ConsistencyMismatch` dengan nilai default.
    ///
    /// Nilai default bersifat:
    /// - Deterministik (tidak bergantung pada state eksternal)
    /// - Valid secara tipe
    /// - Dapat diidentifikasi sebagai "belum diisi"
    ///
    /// ## Default Values
    ///
    /// - `sequence`: 0
    /// - `celestia_hash`: None
    /// - `fallback_hash`: None
    /// - `mismatch_type`: Missing
    #[inline]
    fn default() -> Self {
        Self {
            sequence: 0,
            celestia_hash: None,
            fallback_hash: None,
            mismatch_type: MismatchType::default(),
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// CONSISTENCY REPORT STRUCT
// ════════════════════════════════════════════════════════════════════════════════

/// Laporan lengkap hasil verifikasi konsistensi state.
///
/// Struct ini merepresentasikan hasil lengkap dari proses
/// verifikasi konsistensi antara fallback DA layer dan Celestia.
///
/// ## Fields
///
/// Semua fields bersifat wajib dan eksplisit:
/// - `celestia_height`: Height Celestia yang di-check
/// - `fallback_height`: Height fallback yang di-check
/// - `is_consistent`: Apakah kedua layer konsisten
/// - `mismatches`: Detail ketidakkonsistenan yang ditemukan
/// - `checked_at`: Timestamp saat pengecekan dilakukan
/// - `check_duration_ms`: Durasi pengecekan dalam milidetik
///
/// ## Consistency Determination
///
/// `is_consistent` bernilai `true` jika dan hanya jika:
/// - Tidak ada mismatch yang ditemukan (`mismatches.is_empty()`)
/// - Semua data di fallback berhasil diverifikasi di Celestia
///
/// ## Serialization
///
/// Struct ini dapat di-serialize menggunakan bincode atau JSON.
/// Semua fields ikut dalam serialisasi, tidak ada field tersembunyi.
///
/// ## Example
///
/// ```
/// use dsdn_proto::consistency_report::{
///     ConsistencyReport, ConsistencyMismatch, MismatchType
/// };
///
/// // Consistent report
/// let consistent = ConsistencyReport {
///     celestia_height: 10000,
///     fallback_height: 500,
///     is_consistent: true,
///     mismatches: Vec::new(),
///     checked_at: 1704067200,
///     check_duration_ms: 1500,
/// };
///
/// // Inconsistent report
/// let inconsistent = ConsistencyReport {
///     celestia_height: 10000,
///     fallback_height: 500,
///     is_consistent: false,
///     mismatches: vec![ConsistencyMismatch::default()],
///     checked_at: 1704067200,
///     check_duration_ms: 2000,
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsistencyReport {
    /// Height Celestia yang di-check dalam verifikasi ini.
    ///
    /// Merepresentasikan block height Celestia sampai mana
    /// data di-verifikasi untuk konsistensi.
    ///
    /// Digunakan untuk:
    /// - Menentukan range verifikasi
    /// - Audit trail
    /// - Tracking progress
    pub celestia_height: u64,

    /// Height fallback DA yang di-check dalam verifikasi ini.
    ///
    /// Merepresentasikan "logical height" atau batch number
    /// di fallback DA sampai mana data di-verifikasi.
    ///
    /// Digunakan untuk:
    /// - Menentukan range verifikasi
    /// - Cross-reference dengan fallback storage
    /// - Audit trail
    pub fallback_height: u64,

    /// Apakah state kedua layer konsisten.
    ///
    /// Bernilai `true` jika tidak ada mismatch yang ditemukan,
    /// `false` jika ada satu atau lebih mismatch.
    ///
    /// Invariant: `is_consistent == mismatches.is_empty()`
    pub is_consistent: bool,

    /// Detail semua ketidakkonsistenan yang ditemukan.
    ///
    /// Berisi informasi lengkap untuk setiap mismatch.
    /// Vector kosong menandakan tidak ada mismatch (konsisten).
    ///
    /// Urutan dalam vector sesuai urutan penemuan selama verifikasi.
    pub mismatches: Vec<ConsistencyMismatch>,

    /// Unix timestamp (seconds since epoch) saat verifikasi dilakukan.
    ///
    /// Timestamp ini merepresentasikan waktu lokal sistem ketika
    /// proses verifikasi konsistensi dimulai.
    ///
    /// Nilai 0 menandakan timestamp belum diisi (hanya untuk Default).
    pub checked_at: u64,

    /// Durasi proses verifikasi dalam milidetik.
    ///
    /// Merepresentasikan waktu yang dibutuhkan untuk menyelesaikan
    /// seluruh proses verifikasi konsistensi.
    ///
    /// Digunakan untuk:
    /// - Performance monitoring
    /// - Capacity planning
    /// - Alerting jika verifikasi terlalu lama
    ///
    /// Nilai 0 menandakan durasi tidak diketahui atau sangat singkat.
    pub check_duration_ms: u64,
}

impl ConsistencyReport {
    /// Menghitung jumlah mismatch yang ditemukan.
    ///
    /// ## Returns
    ///
    /// Jumlah mismatch dalam laporan.
    ///
    /// ## Determinism
    ///
    /// Fungsi ini bersifat deterministik: input yang sama selalu
    /// menghasilkan output yang sama.
    #[inline]
    #[must_use]
    pub fn mismatch_count(&self) -> usize {
        self.mismatches.len()
    }

    /// Memeriksa apakah laporan menunjukkan konsistensi.
    ///
    /// Method ini memverifikasi nilai `is_consistent` field.
    /// Catatan: Tidak melakukan validasi invariant secara aktif.
    ///
    /// ## Returns
    ///
    /// - `true` jika `is_consistent` field bernilai true
    /// - `false` jika `is_consistent` field bernilai false
    #[inline]
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.is_consistent
    }
}

impl Default for ConsistencyReport {
    /// Membuat instance `ConsistencyReport` dengan nilai default.
    ///
    /// Nilai default bersifat:
    /// - Deterministik (tidak bergantung pada state eksternal)
    /// - Valid secara tipe
    /// - Dapat diidentifikasi sebagai "belum diisi"
    /// - Menunjukkan state konsisten (default safe)
    ///
    /// ## Default Values
    ///
    /// - `celestia_height`: 0
    /// - `fallback_height`: 0
    /// - `is_consistent`: true (no mismatches by default)
    /// - `mismatches`: empty Vec
    /// - `checked_at`: 0
    /// - `check_duration_ms`: 0
    #[inline]
    fn default() -> Self {
        Self {
            celestia_height: 0,
            fallback_height: 0,
            is_consistent: true,
            mismatches: Vec::new(),
            checked_at: 0,
            check_duration_ms: 0,
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
    // MISMATCH TYPE ENUM TESTS
    // ════════════════════════════════════════════════════════════════════════════

    /// Test: MismatchType memiliki tepat 4 variant (compile-time check).
    #[test]
    fn test_mismatch_type_exactly_four_variants() {
        let mt = MismatchType::Missing;

        // Exhaustive match membuktikan tepat 4 variant
        let _name = match mt {
            MismatchType::Missing => "Missing",
            MismatchType::HashMismatch => "HashMismatch",
            MismatchType::SequenceGap => "SequenceGap",
            MismatchType::Duplicate => "Duplicate",
        };
        // Jika ada variant ke-5, match ini akan error saat compile
    }

    /// Test: MismatchType dapat di-serialize dan di-deserialize (bincode).
    #[test]
    fn test_mismatch_type_bincode_roundtrip() {
        let variants = [
            MismatchType::Missing,
            MismatchType::HashMismatch,
            MismatchType::SequenceGap,
            MismatchType::Duplicate,
        ];

        for original in variants {
            let serialized = bincode::serialize(&original);
            assert!(serialized.is_ok(), "MismatchType serialization must succeed");

            let bytes = serialized.unwrap();
            let deserialized: Result<MismatchType, _> = bincode::deserialize(&bytes);
            assert!(deserialized.is_ok(), "MismatchType deserialization must succeed");

            let decoded = deserialized.unwrap();
            assert_eq!(original, decoded, "MismatchType round-trip must be identical");
        }
    }

    /// Test: MismatchType dapat di-serialize dan di-deserialize (JSON).
    #[test]
    fn test_mismatch_type_json_roundtrip() {
        let variants = [
            MismatchType::Missing,
            MismatchType::HashMismatch,
            MismatchType::SequenceGap,
            MismatchType::Duplicate,
        ];

        for original in variants {
            let json = serde_json::to_string(&original);
            assert!(json.is_ok(), "MismatchType JSON serialization must succeed");

            let json_str = json.unwrap();
            let deserialized: Result<MismatchType, _> = serde_json::from_str(&json_str);
            assert!(deserialized.is_ok(), "MismatchType JSON deserialization must succeed");

            let decoded = deserialized.unwrap();
            assert_eq!(original, decoded, "MismatchType JSON round-trip must be identical");
        }
    }

    /// Test: MismatchType default adalah Missing.
    #[test]
    fn test_mismatch_type_default() {
        let default_type = MismatchType::default();
        assert_eq!(
            default_type,
            MismatchType::Missing,
            "Default MismatchType must be Missing"
        );
    }

    /// Test: MismatchType PartialEq bekerja dengan benar.
    #[test]
    fn test_mismatch_type_partial_eq() {
        let m1 = MismatchType::Missing;
        let m2 = MismatchType::Missing;
        let h1 = MismatchType::HashMismatch;

        assert_eq!(m1, m2, "Same variant must be equal");
        assert_ne!(m1, h1, "Different variants must not be equal");
    }

    /// Test: MismatchType Clone bekerja dengan benar.
    #[test]
    fn test_mismatch_type_clone() {
        let original = MismatchType::SequenceGap;
        let cloned = original.clone();
        assert_eq!(original, cloned, "Clone must produce equal value");
    }

    /// Test: MismatchType Copy trait bekerja (karena Copy derive).
    #[test]
    fn test_mismatch_type_copy() {
        let original = MismatchType::Duplicate;
        let copied = original; // Copy, bukan move
        assert_eq!(original, copied, "Copy must produce equal value");
        // original masih bisa digunakan karena Copy
        let _ = original;
    }

    // ════════════════════════════════════════════════════════════════════════════
    // CONSISTENCY MISMATCH STRUCT TESTS
    // ════════════════════════════════════════════════════════════════════════════

    /// Test: ConsistencyMismatch dapat di-serialize dan di-deserialize (bincode).
    #[test]
    fn test_consistency_mismatch_bincode_roundtrip() {
        let original = ConsistencyMismatch {
            sequence: 42,
            celestia_hash: Some([0xAB; 32]),
            fallback_hash: Some([0xCD; 32]),
            mismatch_type: MismatchType::HashMismatch,
        };

        let serialized = bincode::serialize(&original);
        assert!(serialized.is_ok(), "ConsistencyMismatch serialization must succeed");

        let bytes = serialized.unwrap();
        let deserialized: Result<ConsistencyMismatch, _> = bincode::deserialize(&bytes);
        assert!(deserialized.is_ok(), "ConsistencyMismatch deserialization must succeed");

        let decoded = deserialized.unwrap();
        assert_eq!(original, decoded, "ConsistencyMismatch round-trip must be identical");
    }

    /// Test: ConsistencyMismatch dapat di-serialize dan di-deserialize (JSON).
    #[test]
    fn test_consistency_mismatch_json_roundtrip() {
        let original = ConsistencyMismatch {
            sequence: 100,
            celestia_hash: None,
            fallback_hash: Some([0xFF; 32]),
            mismatch_type: MismatchType::Missing,
        };

        let json = serde_json::to_string(&original);
        assert!(json.is_ok(), "ConsistencyMismatch JSON serialization must succeed");

        let json_str = json.unwrap();
        let deserialized: Result<ConsistencyMismatch, _> = serde_json::from_str(&json_str);
        assert!(deserialized.is_ok(), "ConsistencyMismatch JSON deserialization must succeed");

        let decoded = deserialized.unwrap();
        assert_eq!(original, decoded, "ConsistencyMismatch JSON round-trip must be identical");
    }

    /// Test: ConsistencyMismatch serialization deterministik.
    #[test]
    fn test_consistency_mismatch_deterministic_serialization() {
        let mismatch = ConsistencyMismatch {
            sequence: 50,
            celestia_hash: Some([0x11; 32]),
            fallback_hash: Some([0x22; 32]),
            mismatch_type: MismatchType::HashMismatch,
        };

        let bytes1 = bincode::serialize(&mismatch);
        let bytes2 = bincode::serialize(&mismatch);

        assert!(bytes1.is_ok(), "First serialization must succeed");
        assert!(bytes2.is_ok(), "Second serialization must succeed");
        assert_eq!(
            bytes1.unwrap(),
            bytes2.unwrap(),
            "Deterministic: same input must produce same bytes"
        );
    }

    /// Test: ConsistencyMismatch Default menghasilkan nilai valid.
    #[test]
    fn test_consistency_mismatch_default_validity() {
        let default_mismatch = ConsistencyMismatch::default();

        assert_eq!(default_mismatch.sequence, 0, "Default sequence must be 0");
        assert!(default_mismatch.celestia_hash.is_none(), "Default celestia_hash must be None");
        assert!(default_mismatch.fallback_hash.is_none(), "Default fallback_hash must be None");
        assert_eq!(
            default_mismatch.mismatch_type,
            MismatchType::Missing,
            "Default mismatch_type must be Missing"
        );
    }

    /// Test: ConsistencyMismatch Default dapat di-serialize dan di-deserialize.
    #[test]
    fn test_consistency_mismatch_default_serialization() {
        let default_mismatch = ConsistencyMismatch::default();

        let serialized = bincode::serialize(&default_mismatch);
        assert!(serialized.is_ok(), "Default ConsistencyMismatch serialization must succeed");

        let bytes = serialized.unwrap();
        let deserialized: Result<ConsistencyMismatch, _> = bincode::deserialize(&bytes);
        assert!(deserialized.is_ok(), "Default ConsistencyMismatch deserialization must succeed");

        let decoded = deserialized.unwrap();
        assert_eq!(
            default_mismatch, decoded,
            "Default ConsistencyMismatch round-trip must be identical"
        );
    }

    /// Test: ConsistencyMismatch Default deterministik.
    #[test]
    fn test_consistency_mismatch_default_deterministic() {
        let default1 = ConsistencyMismatch::default();
        let default2 = ConsistencyMismatch::default();

        assert_eq!(
            default1, default2,
            "Default must be deterministic (same value every time)"
        );
    }

    /// Test: ConsistencyMismatch PartialEq bekerja dengan benar.
    #[test]
    fn test_consistency_mismatch_partial_eq() {
        let mismatch1 = ConsistencyMismatch {
            sequence: 1,
            celestia_hash: Some([0xAA; 32]),
            fallback_hash: None,
            mismatch_type: MismatchType::Missing,
        };

        let mismatch2 = ConsistencyMismatch {
            sequence: 1,
            celestia_hash: Some([0xAA; 32]),
            fallback_hash: None,
            mismatch_type: MismatchType::Missing,
        };

        let mismatch3 = ConsistencyMismatch {
            sequence: 2, // Different
            celestia_hash: Some([0xAA; 32]),
            fallback_hash: None,
            mismatch_type: MismatchType::Missing,
        };

        assert_eq!(mismatch1, mismatch2, "Same values must be equal");
        assert_ne!(mismatch1, mismatch3, "Different sequence must not be equal");
    }

    /// Test: ConsistencyMismatch Clone bekerja dengan benar.
    #[test]
    fn test_consistency_mismatch_clone() {
        let original = ConsistencyMismatch {
            sequence: 99,
            celestia_hash: Some([0xBB; 32]),
            fallback_hash: Some([0xCC; 32]),
            mismatch_type: MismatchType::Duplicate,
        };

        let cloned = original.clone();
        assert_eq!(original, cloned, "Clone must produce equal value");
    }

    /// Test: ConsistencyMismatch Debug output mengandung semua field names.
    #[test]
    fn test_consistency_mismatch_debug() {
        let mismatch = ConsistencyMismatch::default();

        let debug_str = format!("{:?}", mismatch);

        assert!(debug_str.contains("sequence"), "Debug must contain 'sequence'");
        assert!(debug_str.contains("celestia_hash"), "Debug must contain 'celestia_hash'");
        assert!(debug_str.contains("fallback_hash"), "Debug must contain 'fallback_hash'");
        assert!(debug_str.contains("mismatch_type"), "Debug must contain 'mismatch_type'");
    }

    /// Test: ConsistencyMismatch dengan semua MismatchType variants.
    #[test]
    fn test_consistency_mismatch_all_mismatch_types() {
        let types = [
            MismatchType::Missing,
            MismatchType::HashMismatch,
            MismatchType::SequenceGap,
            MismatchType::Duplicate,
        ];

        for mismatch_type in types {
            let mismatch = ConsistencyMismatch {
                sequence: 1,
                celestia_hash: Some([0x11; 32]),
                fallback_hash: Some([0x22; 32]),
                mismatch_type,
            };

            let serialized = bincode::serialize(&mismatch);
            assert!(serialized.is_ok(), "Mismatch with type {:?} must serialize", mismatch_type);

            let bytes = serialized.unwrap();
            let deserialized: Result<ConsistencyMismatch, _> = bincode::deserialize(&bytes);
            assert!(deserialized.is_ok(), "Mismatch with type {:?} must deserialize", mismatch_type);

            let decoded = deserialized.unwrap();
            assert_eq!(mismatch, decoded, "Mismatch with type {:?} round-trip must match", mismatch_type);
        }
    }

    /// Test: ConsistencyMismatch dengan u64::MAX sequence.
    #[test]
    fn test_consistency_mismatch_max_sequence() {
        let mismatch = ConsistencyMismatch {
            sequence: u64::MAX,
            celestia_hash: Some([0xFF; 32]),
            fallback_hash: Some([0xFF; 32]),
            mismatch_type: MismatchType::HashMismatch,
        };

        let serialized = bincode::serialize(&mismatch);
        assert!(serialized.is_ok(), "Max sequence must serialize");

        let bytes = serialized.unwrap();
        let deserialized: Result<ConsistencyMismatch, _> = bincode::deserialize(&bytes);
        assert!(deserialized.is_ok(), "Max sequence must deserialize");

        let decoded = deserialized.unwrap();
        assert_eq!(decoded.sequence, u64::MAX);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // CONSISTENCY REPORT STRUCT TESTS
    // ════════════════════════════════════════════════════════════════════════════

    /// Test: ConsistencyReport dapat di-serialize dan di-deserialize (bincode).
    #[test]
    fn test_consistency_report_bincode_roundtrip() {
        let original = ConsistencyReport {
            celestia_height: 10000,
            fallback_height: 500,
            is_consistent: false,
            mismatches: vec![
                ConsistencyMismatch {
                    sequence: 42,
                    celestia_hash: None,
                    fallback_hash: Some([0xAB; 32]),
                    mismatch_type: MismatchType::Missing,
                },
                ConsistencyMismatch {
                    sequence: 43,
                    celestia_hash: Some([0x11; 32]),
                    fallback_hash: Some([0x22; 32]),
                    mismatch_type: MismatchType::HashMismatch,
                },
            ],
            checked_at: 1704067200,
            check_duration_ms: 1500,
        };

        let serialized = bincode::serialize(&original);
        assert!(serialized.is_ok(), "ConsistencyReport serialization must succeed");

        let bytes = serialized.unwrap();
        let deserialized: Result<ConsistencyReport, _> = bincode::deserialize(&bytes);
        assert!(deserialized.is_ok(), "ConsistencyReport deserialization must succeed");

        let decoded = deserialized.unwrap();
        assert_eq!(original, decoded, "ConsistencyReport round-trip must be identical");
    }

    /// Test: ConsistencyReport dapat di-serialize dan di-deserialize (JSON).
    #[test]
    fn test_consistency_report_json_roundtrip() {
        let original = ConsistencyReport {
            celestia_height: 5000,
            fallback_height: 250,
            is_consistent: true,
            mismatches: Vec::new(),
            checked_at: 1704000000,
            check_duration_ms: 500,
        };

        let json = serde_json::to_string(&original);
        assert!(json.is_ok(), "ConsistencyReport JSON serialization must succeed");

        let json_str = json.unwrap();
        let deserialized: Result<ConsistencyReport, _> = serde_json::from_str(&json_str);
        assert!(deserialized.is_ok(), "ConsistencyReport JSON deserialization must succeed");

        let decoded = deserialized.unwrap();
        assert_eq!(original, decoded, "ConsistencyReport JSON round-trip must be identical");
    }

    /// Test: ConsistencyReport serialization deterministik.
    #[test]
    fn test_consistency_report_deterministic_serialization() {
        let report = ConsistencyReport {
            celestia_height: 1000,
            fallback_height: 100,
            is_consistent: true,
            mismatches: Vec::new(),
            checked_at: 12345,
            check_duration_ms: 100,
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

    /// Test: ConsistencyReport Default menghasilkan nilai valid.
    #[test]
    fn test_consistency_report_default_validity() {
        let default_report = ConsistencyReport::default();

        assert_eq!(default_report.celestia_height, 0, "Default celestia_height must be 0");
        assert_eq!(default_report.fallback_height, 0, "Default fallback_height must be 0");
        assert!(default_report.is_consistent, "Default is_consistent must be true");
        assert!(default_report.mismatches.is_empty(), "Default mismatches must be empty");
        assert_eq!(default_report.checked_at, 0, "Default checked_at must be 0");
        assert_eq!(default_report.check_duration_ms, 0, "Default check_duration_ms must be 0");
    }

    /// Test: ConsistencyReport Default dapat di-serialize dan di-deserialize.
    #[test]
    fn test_consistency_report_default_serialization() {
        let default_report = ConsistencyReport::default();

        let serialized = bincode::serialize(&default_report);
        assert!(serialized.is_ok(), "Default ConsistencyReport serialization must succeed");

        let bytes = serialized.unwrap();
        let deserialized: Result<ConsistencyReport, _> = bincode::deserialize(&bytes);
        assert!(deserialized.is_ok(), "Default ConsistencyReport deserialization must succeed");

        let decoded = deserialized.unwrap();
        assert_eq!(
            default_report, decoded,
            "Default ConsistencyReport round-trip must be identical"
        );
    }

    /// Test: ConsistencyReport Default deterministik.
    #[test]
    fn test_consistency_report_default_deterministic() {
        let default1 = ConsistencyReport::default();
        let default2 = ConsistencyReport::default();

        assert_eq!(
            default1, default2,
            "Default must be deterministic (same value every time)"
        );
    }

    /// Test: ConsistencyReport PartialEq bekerja dengan benar.
    #[test]
    fn test_consistency_report_partial_eq() {
        let report1 = ConsistencyReport {
            celestia_height: 100,
            fallback_height: 10,
            is_consistent: true,
            mismatches: Vec::new(),
            checked_at: 1000,
            check_duration_ms: 50,
        };

        let report2 = ConsistencyReport {
            celestia_height: 100,
            fallback_height: 10,
            is_consistent: true,
            mismatches: Vec::new(),
            checked_at: 1000,
            check_duration_ms: 50,
        };

        let report3 = ConsistencyReport {
            celestia_height: 200, // Different
            fallback_height: 10,
            is_consistent: true,
            mismatches: Vec::new(),
            checked_at: 1000,
            check_duration_ms: 50,
        };

        assert_eq!(report1, report2, "Same values must be equal");
        assert_ne!(report1, report3, "Different celestia_height must not be equal");
    }

    /// Test: ConsistencyReport Clone bekerja dengan benar.
    #[test]
    fn test_consistency_report_clone() {
        let original = ConsistencyReport {
            celestia_height: 5000,
            fallback_height: 500,
            is_consistent: false,
            mismatches: vec![ConsistencyMismatch::default()],
            checked_at: 1704067200,
            check_duration_ms: 1000,
        };

        let cloned = original.clone();
        assert_eq!(original, cloned, "Clone must produce equal value");
    }

    /// Test: ConsistencyReport Debug output mengandung semua field names.
    #[test]
    fn test_consistency_report_debug() {
        let report = ConsistencyReport::default();

        let debug_str = format!("{:?}", report);

        assert!(debug_str.contains("celestia_height"), "Debug must contain 'celestia_height'");
        assert!(debug_str.contains("fallback_height"), "Debug must contain 'fallback_height'");
        assert!(debug_str.contains("is_consistent"), "Debug must contain 'is_consistent'");
        assert!(debug_str.contains("mismatches"), "Debug must contain 'mismatches'");
        assert!(debug_str.contains("checked_at"), "Debug must contain 'checked_at'");
        assert!(debug_str.contains("check_duration_ms"), "Debug must contain 'check_duration_ms'");
    }

    /// Test: ConsistencyReport dengan empty mismatches vector.
    #[test]
    fn test_consistency_report_empty_mismatches() {
        let report = ConsistencyReport {
            celestia_height: 100,
            fallback_height: 10,
            is_consistent: true,
            mismatches: Vec::new(),
            checked_at: 1000,
            check_duration_ms: 50,
        };

        let serialized = bincode::serialize(&report);
        assert!(serialized.is_ok(), "Empty mismatches must serialize");

        let bytes = serialized.unwrap();
        let deserialized: Result<ConsistencyReport, _> = bincode::deserialize(&bytes);
        assert!(deserialized.is_ok(), "Empty mismatches must deserialize");

        let decoded = deserialized.unwrap();
        assert!(decoded.mismatches.is_empty(), "Decoded mismatches must be empty");
    }

    /// Test: ConsistencyReport dengan large mismatches vector.
    #[test]
    fn test_consistency_report_large_mismatches() {
        let mismatches: Vec<ConsistencyMismatch> = (0..100)
            .map(|i| ConsistencyMismatch {
                sequence: i,
                celestia_hash: Some([i as u8; 32]),
                fallback_hash: Some([(i + 1) as u8; 32]),
                mismatch_type: MismatchType::HashMismatch,
            })
            .collect();

        let report = ConsistencyReport {
            celestia_height: 10000,
            fallback_height: 1000,
            is_consistent: false,
            mismatches,
            checked_at: 1704067200,
            check_duration_ms: 5000,
        };

        let serialized = bincode::serialize(&report);
        assert!(serialized.is_ok(), "Large mismatches must serialize");

        let bytes = serialized.unwrap();
        let deserialized: Result<ConsistencyReport, _> = bincode::deserialize(&bytes);
        assert!(deserialized.is_ok(), "Large mismatches must deserialize");

        let decoded = deserialized.unwrap();
        assert_eq!(decoded.mismatches.len(), 100, "Decoded must have 100 mismatches");
    }

    /// Test: ConsistencyReport dengan u64::MAX values.
    #[test]
    fn test_consistency_report_max_values() {
        let report = ConsistencyReport {
            celestia_height: u64::MAX,
            fallback_height: u64::MAX,
            is_consistent: true,
            mismatches: Vec::new(),
            checked_at: u64::MAX,
            check_duration_ms: u64::MAX,
        };

        let serialized = bincode::serialize(&report);
        assert!(serialized.is_ok(), "Max values must serialize");

        let bytes = serialized.unwrap();
        let deserialized: Result<ConsistencyReport, _> = bincode::deserialize(&bytes);
        assert!(deserialized.is_ok(), "Max values must deserialize");

        let decoded = deserialized.unwrap();
        assert_eq!(decoded.celestia_height, u64::MAX);
        assert_eq!(decoded.fallback_height, u64::MAX);
        assert_eq!(decoded.checked_at, u64::MAX);
        assert_eq!(decoded.check_duration_ms, u64::MAX);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // CONSISTENCY REPORT METHOD TESTS
    // ════════════════════════════════════════════════════════════════════════════

    /// Test: mismatch_count() returns correct count.
    #[test]
    fn test_consistency_report_mismatch_count() {
        let report = ConsistencyReport {
            celestia_height: 100,
            fallback_height: 10,
            is_consistent: false,
            mismatches: vec![
                ConsistencyMismatch::default(),
                ConsistencyMismatch::default(),
                ConsistencyMismatch::default(),
            ],
            checked_at: 1000,
            check_duration_ms: 50,
        };

        assert_eq!(report.mismatch_count(), 3, "mismatch_count must return 3");
    }

    /// Test: mismatch_count() returns 0 for empty mismatches.
    #[test]
    fn test_consistency_report_mismatch_count_empty() {
        let report = ConsistencyReport::default();

        assert_eq!(report.mismatch_count(), 0, "mismatch_count must return 0 for empty");
    }

    /// Test: is_ok() returns correct value.
    #[test]
    fn test_consistency_report_is_ok() {
        let consistent = ConsistencyReport {
            is_consistent: true,
            ..Default::default()
        };

        let inconsistent = ConsistencyReport {
            is_consistent: false,
            ..Default::default()
        };

        assert!(consistent.is_ok(), "is_ok must return true when consistent");
        assert!(!inconsistent.is_ok(), "is_ok must return false when inconsistent");
    }

    /// Test: mismatch_count() is deterministic.
    #[test]
    fn test_consistency_report_mismatch_count_deterministic() {
        let report = ConsistencyReport {
            mismatches: vec![ConsistencyMismatch::default(); 5],
            ..Default::default()
        };

        let count1 = report.mismatch_count();
        let count2 = report.mismatch_count();

        assert_eq!(count1, count2, "mismatch_count must be deterministic");
    }

    /// Test: is_ok() is deterministic.
    #[test]
    fn test_consistency_report_is_ok_deterministic() {
        let report = ConsistencyReport {
            is_consistent: true,
            ..Default::default()
        };

        let result1 = report.is_ok();
        let result2 = report.is_ok();

        assert_eq!(result1, result2, "is_ok must be deterministic");
    }
}