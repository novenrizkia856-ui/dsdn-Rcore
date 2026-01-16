//! # Pending Blob Schema
//!
//! Modul ini mendefinisikan struktur `PendingBlob` sebagai representasi
//! blob yang sedang menunggu proses reconciliation dari fallback DA ke Celestia.
//!
//! ## Desain
//!
//! - `PendingBlob` menyimpan data blob beserta metadata untuk tracking
//! - Method utilitas bersifat deterministik dan tidak bergantung state eksternal
//! - Semua operasi aman dari panic dan overflow
//!
//! ## Serialization Guarantee
//!
//! Struct menggunakan derive macros standar serde yang menjamin:
//! - Serialisasi deterministik (input sama → output sama)
//! - Round-trip safety (serialize → deserialize → identical)
//!
//! ## Expiry Logic
//!
//! Blob dianggap expired berdasarkan `retry_count` yang melebihi
//! threshold `MAX_RETRY_COUNT`. Logika ini:
//! - Deterministik (tidak bergantung waktu sistem)
//! - Berbasis data internal struct
//! - Threshold didefinisikan sebagai konstanta eksplisit
//!
//! ## Usage
//!
//! ```
//! use dsdn_proto::pending_blob::PendingBlob;
//!
//! let blob = PendingBlob {
//!     data: vec![1, 2, 3, 4],
//!     original_sequence: 42,
//!     source_da: String::from("validator_quorum"),
//!     received_at: 1704067200,
//!     retry_count: 0,
//!     commitment: None,
//! };
//!
//! assert_eq!(blob.size_bytes(), 4);
//! assert!(!blob.is_expired());
//! ```

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

// ════════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════════

/// Maksimum jumlah retry sebelum blob dianggap expired.
///
/// Nilai ini dipilih sebagai threshold eksplisit untuk menentukan
/// kapan blob dianggap tidak dapat di-reconcile lagi.
///
/// Blob dengan `retry_count > MAX_RETRY_COUNT` akan dianggap expired.
///
/// Nilai 3 dipilih karena:
/// - Memberikan kesempatan retry yang cukup untuk transient failures
/// - Tidak terlalu tinggi sehingga blob stuck terlalu lama
/// - Nilai eksplisit (bukan asumsi implisit)
pub const MAX_RETRY_COUNT: u32 = 3;

// ════════════════════════════════════════════════════════════════════════════════
// PENDING BLOB STRUCT
// ════════════════════════════════════════════════════════════════════════════════

/// Representasi blob yang menunggu proses reconciliation.
///
/// Struct ini menyimpan data blob beserta metadata yang diperlukan
/// untuk tracking dan processing selama reconciliation dari fallback DA ke Celestia.
///
/// ## Fields
///
/// Semua fields bersifat wajib dan eksplisit:
/// - `data`: Raw bytes dari blob
/// - `original_sequence`: Sequence number di fallback DA
/// - `source_da`: Identifier fallback DA sumber
/// - `received_at`: Timestamp saat blob diterima
/// - `retry_count`: Jumlah percobaan reconciliation
/// - `commitment`: Optional commitment hash untuk verifikasi
///
/// ## Expiry
///
/// Blob dianggap expired jika `retry_count > MAX_RETRY_COUNT`.
/// Logika ini deterministik dan tidak bergantung waktu sistem.
///
/// ## Serialization
///
/// Struct ini dapat di-serialize menggunakan bincode atau JSON.
/// Semua fields ikut dalam serialisasi, tidak ada field tersembunyi.
///
/// ## Example
///
/// ```
/// use dsdn_proto::pending_blob::{PendingBlob, MAX_RETRY_COUNT};
///
/// let blob = PendingBlob {
///     data: vec![0xDE, 0xAD, 0xBE, 0xEF],
///     original_sequence: 100,
///     source_da: String::from("validator_quorum"),
///     received_at: 1704067200,
///     retry_count: 0,
///     commitment: Some([0u8; 32]),
/// };
///
/// // Check if expired based on retry count
/// assert!(!blob.is_expired()); // retry_count (0) <= MAX_RETRY_COUNT (3)
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingBlob {
    /// Raw bytes data dari blob.
    ///
    /// Berisi payload blob yang perlu di-reconcile ke Celestia.
    /// Ukuran dapat bervariasi tergantung konten asli.
    ///
    /// Digunakan untuk:
    /// - Posting ke Celestia saat reconciliation
    /// - Computing hash untuk verifikasi
    /// - Storage dan transfer
    pub data: Vec<u8>,

    /// Sequence number blob di fallback DA.
    ///
    /// Merupakan identifier unik untuk blob dalam konteks
    /// fallback DA layer. Digunakan untuk:
    /// - Ordering dan replay
    /// - Cross-reference dengan fallback storage
    /// - Audit trail
    ///
    /// Nilai ini bersifat monotonically increasing dalam satu session.
    pub original_sequence: u64,

    /// Identifier fallback DA yang menjadi sumber blob.
    ///
    /// Menandakan dari mana blob ini berasal. Contoh nilai:
    /// - "validator_quorum": Dari Validator Quorum DA
    /// - "emergency": Dari Emergency DA
    ///
    /// Digunakan untuk:
    /// - Routing logic
    /// - Audit trail
    /// - Debugging
    pub source_da: String,

    /// Unix timestamp (seconds since epoch) saat blob diterima.
    ///
    /// Timestamp ini merepresentasikan waktu lokal sistem ketika
    /// blob pertama kali masuk ke antrian reconciliation.
    ///
    /// Digunakan untuk:
    /// - Tracking dan logging
    /// - Ordering berdasarkan waktu
    /// - Audit trail
    ///
    /// Nilai 0 menandakan timestamp belum diisi (hanya untuk Default).
    pub received_at: u64,

    /// Jumlah percobaan reconciliation yang telah dilakukan.
    ///
    /// Counter ini di-increment setiap kali percobaan reconciliation
    /// untuk blob ini gagal dan akan dicoba ulang.
    ///
    /// Digunakan untuk:
    /// - Menentukan apakah blob expired (> MAX_RETRY_COUNT)
    /// - Retry logic dan backoff
    /// - Monitoring dan alerting
    ///
    /// Nilai 0 menandakan belum pernah dicoba atau baru pertama kali.
    pub retry_count: u32,

    /// Optional commitment hash untuk verifikasi integritas.
    ///
    /// Berisi 32-byte hash yang dapat digunakan untuk memverifikasi
    /// bahwa data blob tidak berubah sejak awal.
    ///
    /// Bernilai `Some([u8; 32])` jika commitment tersedia,
    /// `None` jika blob tidak memiliki commitment.
    ///
    /// Format hash: 32 bytes fixed-size array.
    pub commitment: Option<[u8; 32]>,
}

impl PendingBlob {
    /// Menentukan apakah blob sudah kedaluwarsa (expired).
    ///
    /// ## Kontrak
    ///
    /// - Deterministik: input sama → output sama
    /// - Berbasis data internal: hanya menggunakan field `retry_count`
    /// - Tidak mengakses waktu sistem
    /// - Tidak panic
    ///
    /// ## Logic
    ///
    /// Blob dianggap expired jika `retry_count > MAX_RETRY_COUNT`.
    /// Threshold `MAX_RETRY_COUNT` didefinisikan sebagai konstanta eksplisit.
    ///
    /// ## Returns
    ///
    /// - `true` jika blob expired (retry_count > MAX_RETRY_COUNT)
    /// - `false` jika blob masih valid (retry_count <= MAX_RETRY_COUNT)
    ///
    /// ## Example
    ///
    /// ```
    /// use dsdn_proto::pending_blob::{PendingBlob, MAX_RETRY_COUNT};
    ///
    /// let mut blob = PendingBlob::default();
    ///
    /// blob.retry_count = 0;
    /// assert!(!blob.is_expired()); // 0 <= 3
    ///
    /// blob.retry_count = 3;
    /// assert!(!blob.is_expired()); // 3 <= 3
    ///
    /// blob.retry_count = 4;
    /// assert!(blob.is_expired()); // 4 > 3
    /// ```
    #[inline]
    #[must_use]
    pub const fn is_expired(&self) -> bool {
        self.retry_count > MAX_RETRY_COUNT
    }

    /// Mengembalikan ukuran data blob dalam bytes.
    ///
    /// ## Kontrak
    ///
    /// - Tepat: mengembalikan panjang exact dari `data` field
    /// - Bebas side-effect: tidak mengubah state
    /// - Tidak overflow: Vec::len() selalu valid usize
    ///
    /// ## Returns
    ///
    /// Ukuran `data` field dalam bytes.
    ///
    /// ## Example
    ///
    /// ```
    /// use dsdn_proto::pending_blob::PendingBlob;
    ///
    /// let blob = PendingBlob {
    ///     data: vec![1, 2, 3, 4, 5],
    ///     ..Default::default()
    /// };
    ///
    /// assert_eq!(blob.size_bytes(), 5);
    /// ```
    #[inline]
    #[must_use]
    pub fn size_bytes(&self) -> usize {
        self.data.len()
    }

    /// Menghasilkan hash deterministik dari data blob.
    ///
    /// ## Kontrak
    ///
    /// - Deterministik: data sama → hash sama
    /// - Tidak bergantung state eksternal
    /// - Tidak panic
    /// - Tidak mengubah state struct
    ///
    /// ## Algorithm
    ///
    /// Menggunakan SHA3-256 (Keccak) untuk menghasilkan 32-byte hash.
    /// SHA3-256 dipilih karena:
    /// - Konsisten dengan hashing di crate ini
    /// - Cryptographically secure
    /// - Fixed output size (32 bytes)
    ///
    /// ## Returns
    ///
    /// 32-byte array berisi SHA3-256 hash dari `data` field.
    ///
    /// ## Example
    ///
    /// ```
    /// use dsdn_proto::pending_blob::PendingBlob;
    ///
    /// let blob = PendingBlob {
    ///     data: vec![1, 2, 3, 4],
    ///     ..Default::default()
    /// };
    ///
    /// let hash1 = blob.compute_hash();
    /// let hash2 = blob.compute_hash();
    ///
    /// // Deterministic: same data produces same hash
    /// assert_eq!(hash1, hash2);
    /// ```
    #[must_use]
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(&self.data);
        let result = hasher.finalize();

        // Convert GenericArray to [u8; 32]
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

impl Default for PendingBlob {
    /// Membuat instance `PendingBlob` dengan nilai default.
    ///
    /// Nilai default bersifat:
    /// - Deterministik (tidak bergantung pada state eksternal)
    /// - Valid secara tipe
    /// - Dapat diidentifikasi sebagai "belum diisi"
    ///
    /// ## Default Values
    ///
    /// - `data`: empty Vec
    /// - `original_sequence`: 0
    /// - `source_da`: "unspecified"
    /// - `received_at`: 0
    /// - `retry_count`: 0
    /// - `commitment`: None
    #[inline]
    fn default() -> Self {
        Self {
            data: Vec::new(),
            original_sequence: 0,
            source_da: String::from("unspecified"),
            received_at: 0,
            retry_count: 0,
            commitment: None,
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
    // PENDING BLOB STRUCT TESTS
    // ════════════════════════════════════════════════════════════════════════════

    /// Test: PendingBlob creation valid.
    #[test]
    fn test_pending_blob_creation_valid() {
        let blob = PendingBlob {
            data: vec![1, 2, 3, 4],
            original_sequence: 42,
            source_da: String::from("validator_quorum"),
            received_at: 1704067200,
            retry_count: 0,
            commitment: Some([0xAB; 32]),
        };

        assert_eq!(blob.data, vec![1, 2, 3, 4]);
        assert_eq!(blob.original_sequence, 42);
        assert_eq!(blob.source_da, "validator_quorum");
        assert_eq!(blob.received_at, 1704067200);
        assert_eq!(blob.retry_count, 0);
        assert_eq!(blob.commitment, Some([0xAB; 32]));
    }

    /// Test: PendingBlob dapat di-serialize dan di-deserialize (bincode).
    #[test]
    fn test_pending_blob_bincode_roundtrip() {
        let original = PendingBlob {
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            original_sequence: 100,
            source_da: String::from("emergency"),
            received_at: 1704153600,
            retry_count: 2,
            commitment: Some([0x11; 32]),
        };

        let serialized = bincode::serialize(&original);
        assert!(serialized.is_ok(), "PendingBlob serialization must succeed");

        let bytes = serialized.unwrap();
        let deserialized: Result<PendingBlob, _> = bincode::deserialize(&bytes);
        assert!(deserialized.is_ok(), "PendingBlob deserialization must succeed");

        let decoded = deserialized.unwrap();
        assert_eq!(original, decoded, "PendingBlob round-trip must be identical");
    }

    /// Test: PendingBlob dapat di-serialize dan di-deserialize (JSON).
    #[test]
    fn test_pending_blob_json_roundtrip() {
        let original = PendingBlob {
            data: vec![1, 2, 3],
            original_sequence: 50,
            source_da: String::from("validator_quorum"),
            received_at: 1704000000,
            retry_count: 1,
            commitment: None,
        };

        let json = serde_json::to_string(&original);
        assert!(json.is_ok(), "PendingBlob JSON serialization must succeed");

        let json_str = json.unwrap();
        let deserialized: Result<PendingBlob, _> = serde_json::from_str(&json_str);
        assert!(deserialized.is_ok(), "PendingBlob JSON deserialization must succeed");

        let decoded = deserialized.unwrap();
        assert_eq!(original, decoded, "PendingBlob JSON round-trip must be identical");
    }

    /// Test: PendingBlob serialization deterministik.
    #[test]
    fn test_pending_blob_deterministic_serialization() {
        let blob = PendingBlob {
            data: vec![1, 2, 3, 4, 5],
            original_sequence: 999,
            source_da: String::from("test"),
            received_at: 12345,
            retry_count: 0,
            commitment: Some([0xFF; 32]),
        };

        let bytes1 = bincode::serialize(&blob);
        let bytes2 = bincode::serialize(&blob);

        assert!(bytes1.is_ok(), "First serialization must succeed");
        assert!(bytes2.is_ok(), "Second serialization must succeed");
        assert_eq!(
            bytes1.unwrap(),
            bytes2.unwrap(),
            "Deterministic: same input must produce same bytes"
        );
    }

    /// Test: PendingBlob Default menghasilkan nilai valid.
    #[test]
    fn test_pending_blob_default_validity() {
        let default_blob = PendingBlob::default();

        assert!(default_blob.data.is_empty(), "Default data must be empty");
        assert_eq!(default_blob.original_sequence, 0, "Default original_sequence must be 0");
        assert_eq!(default_blob.source_da, "unspecified", "Default source_da must be 'unspecified'");
        assert_eq!(default_blob.received_at, 0, "Default received_at must be 0");
        assert_eq!(default_blob.retry_count, 0, "Default retry_count must be 0");
        assert!(default_blob.commitment.is_none(), "Default commitment must be None");
    }

    /// Test: PendingBlob Default dapat di-serialize dan di-deserialize.
    #[test]
    fn test_pending_blob_default_serialization() {
        let default_blob = PendingBlob::default();

        let serialized = bincode::serialize(&default_blob);
        assert!(serialized.is_ok(), "Default PendingBlob serialization must succeed");

        let bytes = serialized.unwrap();
        let deserialized: Result<PendingBlob, _> = bincode::deserialize(&bytes);
        assert!(deserialized.is_ok(), "Default PendingBlob deserialization must succeed");

        let decoded = deserialized.unwrap();
        assert_eq!(
            default_blob, decoded,
            "Default PendingBlob round-trip must be identical"
        );
    }

    /// Test: PendingBlob Default deterministik.
    #[test]
    fn test_pending_blob_default_deterministic() {
        let default1 = PendingBlob::default();
        let default2 = PendingBlob::default();

        assert_eq!(
            default1, default2,
            "Default must be deterministic (same value every time)"
        );
    }

    /// Test: PendingBlob PartialEq bekerja dengan benar.
    #[test]
    fn test_pending_blob_partial_eq() {
        let blob1 = PendingBlob {
            data: vec![1, 2, 3],
            original_sequence: 10,
            source_da: String::from("test"),
            received_at: 100,
            retry_count: 0,
            commitment: None,
        };

        let blob2 = PendingBlob {
            data: vec![1, 2, 3],
            original_sequence: 10,
            source_da: String::from("test"),
            received_at: 100,
            retry_count: 0,
            commitment: None,
        };

        let blob3 = PendingBlob {
            data: vec![4, 5, 6], // Different data
            original_sequence: 10,
            source_da: String::from("test"),
            received_at: 100,
            retry_count: 0,
            commitment: None,
        };

        assert_eq!(blob1, blob2, "Same values must be equal");
        assert_ne!(blob1, blob3, "Different data must not be equal");
    }

    /// Test: PendingBlob Clone bekerja dengan benar.
    #[test]
    fn test_pending_blob_clone() {
        let original = PendingBlob {
            data: vec![0xAA, 0xBB, 0xCC],
            original_sequence: 555,
            source_da: String::from("clone_test"),
            received_at: 666,
            retry_count: 2,
            commitment: Some([0x99; 32]),
        };

        let cloned = original.clone();
        assert_eq!(original, cloned, "Clone must produce equal value");
    }

    /// Test: PendingBlob Debug output mengandung semua field names.
    #[test]
    fn test_pending_blob_debug() {
        let blob = PendingBlob::default();

        let debug_str = format!("{:?}", blob);

        assert!(debug_str.contains("data"), "Debug must contain 'data'");
        assert!(debug_str.contains("original_sequence"), "Debug must contain 'original_sequence'");
        assert!(debug_str.contains("source_da"), "Debug must contain 'source_da'");
        assert!(debug_str.contains("received_at"), "Debug must contain 'received_at'");
        assert!(debug_str.contains("retry_count"), "Debug must contain 'retry_count'");
        assert!(debug_str.contains("commitment"), "Debug must contain 'commitment'");
    }

    /// Test: PendingBlob dengan large data.
    #[test]
    fn test_pending_blob_large_data() {
        let large_data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();

        let blob = PendingBlob {
            data: large_data.clone(),
            original_sequence: 1,
            source_da: String::from("test"),
            received_at: 1,
            retry_count: 0,
            commitment: None,
        };

        let serialized = bincode::serialize(&blob);
        assert!(serialized.is_ok(), "Large data must serialize");

        let bytes = serialized.unwrap();
        let deserialized: Result<PendingBlob, _> = bincode::deserialize(&bytes);
        assert!(deserialized.is_ok(), "Large data must deserialize");

        let decoded = deserialized.unwrap();
        assert_eq!(decoded.data.len(), 10000, "Large data must be preserved");
    }

    /// Test: PendingBlob dengan u64::MAX values.
    #[test]
    fn test_pending_blob_max_values() {
        let blob = PendingBlob {
            data: vec![0xFF],
            original_sequence: u64::MAX,
            source_da: String::from("max"),
            received_at: u64::MAX,
            retry_count: u32::MAX,
            commitment: Some([0xFF; 32]),
        };

        let serialized = bincode::serialize(&blob);
        assert!(serialized.is_ok(), "Max values must serialize");

        let bytes = serialized.unwrap();
        let deserialized: Result<PendingBlob, _> = bincode::deserialize(&bytes);
        assert!(deserialized.is_ok(), "Max values must deserialize");

        let decoded = deserialized.unwrap();
        assert_eq!(decoded.original_sequence, u64::MAX);
        assert_eq!(decoded.received_at, u64::MAX);
        assert_eq!(decoded.retry_count, u32::MAX);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // SIZE_BYTES() METHOD TESTS
    // ════════════════════════════════════════════════════════════════════════════

    /// Test: size_bytes() returns correct size for non-empty data.
    #[test]
    fn test_size_bytes_non_empty() {
        let blob = PendingBlob {
            data: vec![1, 2, 3, 4, 5],
            ..Default::default()
        };

        assert_eq!(blob.size_bytes(), 5, "size_bytes must return 5 for 5-byte data");
    }

    /// Test: size_bytes() returns 0 for empty data.
    #[test]
    fn test_size_bytes_empty() {
        let blob = PendingBlob {
            data: Vec::new(),
            ..Default::default()
        };

        assert_eq!(blob.size_bytes(), 0, "size_bytes must return 0 for empty data");
    }

    /// Test: size_bytes() returns correct size for large data.
    #[test]
    fn test_size_bytes_large() {
        let blob = PendingBlob {
            data: vec![0u8; 100000],
            ..Default::default()
        };

        assert_eq!(blob.size_bytes(), 100000, "size_bytes must return 100000 for 100KB data");
    }

    /// Test: size_bytes() is deterministic.
    #[test]
    fn test_size_bytes_deterministic() {
        let blob = PendingBlob {
            data: vec![1, 2, 3],
            ..Default::default()
        };

        let size1 = blob.size_bytes();
        let size2 = blob.size_bytes();

        assert_eq!(size1, size2, "size_bytes must be deterministic");
    }

    // ════════════════════════════════════════════════════════════════════════════
    // COMPUTE_HASH() METHOD TESTS
    // ════════════════════════════════════════════════════════════════════════════

    /// Test: compute_hash() is deterministic.
    #[test]
    fn test_compute_hash_deterministic() {
        let blob = PendingBlob {
            data: vec![1, 2, 3, 4],
            ..Default::default()
        };

        let hash1 = blob.compute_hash();
        let hash2 = blob.compute_hash();

        assert_eq!(hash1, hash2, "compute_hash must be deterministic (same output for same input)");
    }

    /// Test: compute_hash() produces consistent results for same data.
    #[test]
    fn test_compute_hash_consistent() {
        let blob1 = PendingBlob {
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            original_sequence: 1,
            source_da: String::from("a"),
            received_at: 100,
            retry_count: 0,
            commitment: None,
        };

        let blob2 = PendingBlob {
            data: vec![0xDE, 0xAD, 0xBE, 0xEF], // Same data
            original_sequence: 999, // Different metadata
            source_da: String::from("b"),
            received_at: 999,
            retry_count: 5,
            commitment: Some([0xFF; 32]),
        };

        let hash1 = blob1.compute_hash();
        let hash2 = blob2.compute_hash();

        assert_eq!(
            hash1, hash2,
            "compute_hash must be consistent: same data produces same hash regardless of other fields"
        );
    }

    /// Test: compute_hash() produces different results for different data.
    #[test]
    fn test_compute_hash_different_data() {
        let blob1 = PendingBlob {
            data: vec![1, 2, 3],
            ..Default::default()
        };

        let blob2 = PendingBlob {
            data: vec![1, 2, 4], // Different data
            ..Default::default()
        };

        let hash1 = blob1.compute_hash();
        let hash2 = blob2.compute_hash();

        assert_ne!(hash1, hash2, "Different data must produce different hash");
    }

    /// Test: compute_hash() returns 32 bytes.
    #[test]
    fn test_compute_hash_length() {
        let blob = PendingBlob {
            data: vec![1, 2, 3],
            ..Default::default()
        };

        let hash = blob.compute_hash();
        assert_eq!(hash.len(), 32, "compute_hash must return 32 bytes");
    }

    /// Test: compute_hash() for empty data.
    #[test]
    fn test_compute_hash_empty_data() {
        let blob = PendingBlob {
            data: Vec::new(),
            ..Default::default()
        };

        let hash = blob.compute_hash();

        // Empty data should produce a valid hash (SHA3-256 of empty input)
        assert_eq!(hash.len(), 32, "Empty data must produce 32-byte hash");

        // Verify it's deterministic
        let hash2 = blob.compute_hash();
        assert_eq!(hash, hash2, "Empty data hash must be deterministic");
    }

    /// Test: compute_hash() does not modify struct.
    #[test]
    fn test_compute_hash_no_mutation() {
        let blob = PendingBlob {
            data: vec![1, 2, 3, 4],
            original_sequence: 42,
            source_da: String::from("test"),
            received_at: 100,
            retry_count: 2,
            commitment: Some([0xAA; 32]),
        };

        let blob_before = blob.clone();
        let _ = blob.compute_hash();

        assert_eq!(blob, blob_before, "compute_hash must not modify struct");
    }

    // ════════════════════════════════════════════════════════════════════════════
    // IS_EXPIRED() METHOD TESTS
    // ════════════════════════════════════════════════════════════════════════════

    /// Test: is_expired() returns false for retry_count = 0.
    #[test]
    fn test_is_expired_zero_retries() {
        let blob = PendingBlob {
            retry_count: 0,
            ..Default::default()
        };

        assert!(
            !blob.is_expired(),
            "retry_count 0 must not be expired (0 <= MAX_RETRY_COUNT)"
        );
    }

    /// Test: is_expired() returns false for retry_count = MAX_RETRY_COUNT.
    #[test]
    fn test_is_expired_at_max() {
        let blob = PendingBlob {
            retry_count: MAX_RETRY_COUNT,
            ..Default::default()
        };

        assert!(
            !blob.is_expired(),
            "retry_count at MAX_RETRY_COUNT must not be expired"
        );
    }

    /// Test: is_expired() returns true for retry_count > MAX_RETRY_COUNT.
    #[test]
    fn test_is_expired_over_max() {
        let blob = PendingBlob {
            retry_count: MAX_RETRY_COUNT + 1,
            ..Default::default()
        };

        assert!(
            blob.is_expired(),
            "retry_count over MAX_RETRY_COUNT must be expired"
        );
    }

    /// Test: is_expired() is deterministic.
    #[test]
    fn test_is_expired_deterministic() {
        let blob = PendingBlob {
            retry_count: 2,
            ..Default::default()
        };

        let result1 = blob.is_expired();
        let result2 = blob.is_expired();

        assert_eq!(result1, result2, "is_expired must be deterministic");
    }

    /// Test: is_expired() based on internal data only.
    #[test]
    fn test_is_expired_internal_data_only() {
        // Two blobs with same retry_count but different other fields
        let blob1 = PendingBlob {
            data: vec![1, 2, 3],
            original_sequence: 100,
            source_da: String::from("a"),
            received_at: 1000,
            retry_count: 5, // > MAX_RETRY_COUNT
            commitment: None,
        };

        let blob2 = PendingBlob {
            data: vec![4, 5, 6],
            original_sequence: 999,
            source_da: String::from("b"),
            received_at: 9999,
            retry_count: 5, // Same retry_count
            commitment: Some([0xFF; 32]),
        };

        assert_eq!(
            blob1.is_expired(),
            blob2.is_expired(),
            "is_expired must depend only on retry_count"
        );
    }

    /// Test: is_expired() boundary conditions.
    #[test]
    fn test_is_expired_boundary() {
        // Test exact boundaries
        let cases = [
            (0, false),
            (1, false),
            (2, false),
            (3, false),           // MAX_RETRY_COUNT = 3, still not expired
            (4, true),            // First expired value
            (5, true),
            (u32::MAX, true),
        ];

        for (retry_count, expected_expired) in cases {
            let blob = PendingBlob {
                retry_count,
                ..Default::default()
            };

            assert_eq!(
                blob.is_expired(),
                expected_expired,
                "retry_count {} should have is_expired = {}",
                retry_count,
                expected_expired
            );
        }
    }

    /// Test: is_expired() does not modify struct.
    #[test]
    fn test_is_expired_no_mutation() {
        let blob = PendingBlob {
            data: vec![1, 2, 3],
            retry_count: 2,
            ..Default::default()
        };

        let blob_before = blob.clone();
        let _ = blob.is_expired();

        assert_eq!(blob, blob_before, "is_expired must not modify struct");
    }

    /// Test: MAX_RETRY_COUNT constant is accessible and has expected value.
    #[test]
    fn test_max_retry_count_constant() {
        assert_eq!(MAX_RETRY_COUNT, 3, "MAX_RETRY_COUNT must be 3");
    }
}