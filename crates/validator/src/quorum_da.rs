//! # QuorumDA Trait Definition
//!
//! Kontrak trait untuk Data Availability berbasis quorum validator.
//!
//! ## Peran dalam Arsitektur
//!
//! `QuorumDA` adalah secondary DA layer dalam DSDN fallback hierarchy:
//! - Primary: Celestia (external DA)
//! - Secondary: QuorumDA (validator-based DA)
//! - Emergency: Foundation DA
//!
//! ## Kontrak
//!
//! Trait ini mendefinisikan kontrak untuk:
//! - Pengumpulan signature dari validator
//! - Submission data dengan quorum signature
//! - Verifikasi quorum untuk blob yang tersimpan
//!
//! ## Non-Goals
//!
//! Trait ini TIDAK mendefinisikan:
//! - Implementasi konkret
//! - Algoritma voting spesifik
//! - Network transport
//! - Signature scheme
//! - Threshold calculation logic

use dsdn_common::{DALayer, BlobRef};
use std::fmt;

// ════════════════════════════════════════════════════════════════════════════════
// ERROR TYPE
// ════════════════════════════════════════════════════════════════════════════════

/// Error type untuk operasi QuorumDA.
///
/// ## Variants
///
/// Setiap variant merepresentasikan kategori kegagalan yang berbeda.
/// Implementor bebas menambahkan detail dalam pesan string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuorumError {
    /// Quorum threshold tidak tercapai.
    ///
    /// Terjadi ketika jumlah signature valid kurang dari threshold.
    InsufficientQuorum(String),

    /// Signature tidak valid atau tidak dapat diverifikasi.
    InvalidSignature(String),

    /// Validator tidak ditemukan atau tidak aktif.
    ValidatorNotFound(String),

    /// Operasi network gagal.
    NetworkError(String),

    /// Error internal atau tidak terkategorikan.
    Internal(String),
}

impl fmt::Display for QuorumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QuorumError::InsufficientQuorum(msg) => write!(f, "insufficient quorum: {}", msg),
            QuorumError::InvalidSignature(msg) => write!(f, "invalid signature: {}", msg),
            QuorumError::ValidatorNotFound(msg) => write!(f, "validator not found: {}", msg),
            QuorumError::NetworkError(msg) => write!(f, "network error: {}", msg),
            QuorumError::Internal(msg) => write!(f, "internal error: {}", msg),
        }
    }
}

impl std::error::Error for QuorumError {}

// ════════════════════════════════════════════════════════════════════════════════
// CONFIG ERROR TYPE
// ════════════════════════════════════════════════════════════════════════════════

/// Error type untuk konfigurasi QuorumDA.
///
/// Digunakan oleh `QuorumDAConfig::from_env()` untuk melaporkan
/// kegagalan parsing environment variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// Environment variable ada tapi tidak dapat di-parse.
    ///
    /// Field: (nama_variabel, nilai_yang_ditemukan, pesan_error)
    InvalidValue {
        /// Nama environment variable.
        var_name: String,
        /// Nilai yang ditemukan.
        value: String,
        /// Pesan error parsing.
        message: String,
    },

    /// Nilai yang di-parse berada di luar range yang valid.
    OutOfRange {
        /// Nama environment variable.
        var_name: String,
        /// Nilai yang di-parse.
        value: String,
        /// Deskripsi constraint yang dilanggar.
        constraint: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::InvalidValue { var_name, value, message } => {
                write!(f, "invalid value for {}: '{}' - {}", var_name, value, message)
            }
            ConfigError::OutOfRange { var_name, value, constraint } => {
                write!(f, "value out of range for {}: '{}' - {}", var_name, value, constraint)
            }
        }
    }
}

impl std::error::Error for ConfigError {}

// ════════════════════════════════════════════════════════════════════════════════
// QUORUM DA CONFIG
// ════════════════════════════════════════════════════════════════════════════════

/// Konfigurasi untuk QuorumDA.
///
/// Struct ini menyimpan parameter konfigurasi untuk operasi QuorumDA.
/// Semua field memiliki default value yang reasonable.
///
/// ## Fields
///
/// | Field | Type | Default | Deskripsi |
/// |-------|------|---------|-----------|
/// | `min_validators` | `usize` | 3 | Jumlah minimum validator untuk quorum valid |
/// | `quorum_fraction` | `f64` | 0.67 | Fraksi validator yang diperlukan (0.0-1.0) |
/// | `signature_timeout_ms` | `u64` | 10000 | Timeout pengumpulan signature dalam ms |
/// | `max_blob_size` | `usize` | 2MB | Ukuran maksimum blob dalam bytes |
/// | `validator_endpoints` | `Vec<String>` | empty | Daftar endpoint validator |
/// | `retry_count` | `u32` | 3 | Jumlah retry untuk operasi yang gagal |
///
/// ## Invariants
///
/// - `quorum_fraction` harus dalam range [0.0, 1.0]
/// - `min_validators` harus > 0 untuk operasi yang meaningful
#[derive(Debug, Clone, PartialEq)]
pub struct QuorumDAConfig {
    /// Jumlah minimum validator yang diperlukan untuk quorum valid.
    ///
    /// Threshold tidak akan pernah lebih kecil dari nilai ini,
    /// kecuali jika `total_validators` adalah 0.
    ///
    /// Default: 3
    pub min_validators: usize,

    /// Fraksi validator yang diperlukan untuk mencapai quorum.
    ///
    /// Nilai adalah fraksi (bukan persentase), range [0.0, 1.0].
    /// Contoh: 0.67 berarti 67% validator.
    ///
    /// Default: 0.67
    pub quorum_fraction: f64,

    /// Timeout untuk pengumpulan signature dalam milliseconds.
    ///
    /// Operasi `collect_signatures` akan timeout setelah durasi ini.
    ///
    /// Default: 10000 (10 detik)
    pub signature_timeout_ms: u64,

    /// Ukuran maksimum blob yang dapat di-submit dalam bytes.
    ///
    /// Blob yang melebihi ukuran ini akan ditolak.
    ///
    /// Default: 2097152 (2 * 1024 * 1024 = 2MB)
    pub max_blob_size: usize,

    /// Daftar endpoint validator untuk koneksi.
    ///
    /// Format endpoint adalah implementasi-specific.
    ///
    /// Default: empty Vec
    pub validator_endpoints: Vec<String>,

    /// Jumlah retry untuk operasi yang gagal.
    ///
    /// Operasi akan di-retry hingga jumlah ini sebelum return error.
    ///
    /// Default: 3
    pub retry_count: u32,
}

impl Default for QuorumDAConfig {
    fn default() -> Self {
        Self {
            min_validators: 3,
            quorum_fraction: 0.67,
            signature_timeout_ms: 10_000,
            max_blob_size: 2 * 1024 * 1024, // 2MB
            validator_endpoints: Vec::new(),
            retry_count: 3,
        }
    }
}

impl QuorumDAConfig {
    /// Membuat konfigurasi baru dengan default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Membuat konfigurasi dari environment variables.
    ///
    /// ## Environment Variables
    ///
    /// Semua environment variables bersifat OPSIONAL.
    /// Jika tidak di-set, default value akan digunakan.
    ///
    /// | Variable | Type | Default |
    /// |----------|------|---------|
    /// | `QUORUM_MIN_VALIDATORS` | usize | 3 |
    /// | `QUORUM_FRACTION` | f64 | 0.67 |
    /// | `QUORUM_SIGNATURE_TIMEOUT_MS` | u64 | 10000 |
    /// | `QUORUM_MAX_BLOB_SIZE` | usize | 2097152 |
    /// | `QUORUM_VALIDATOR_ENDPOINTS` | comma-separated | empty |
    /// | `QUORUM_RETRY_COUNT` | u32 | 3 |
    ///
    /// ## Returns
    ///
    /// - `Ok(QuorumDAConfig)`: Konfigurasi berhasil di-parse
    /// - `Err(ConfigError)`: Jika parsing gagal untuk salah satu variable
    ///
    /// ## Error Handling
    ///
    /// Jika environment variable ada tapi tidak dapat di-parse,
    /// method ini akan return error (BUKAN silent fallback ke default).
    pub fn from_env() -> Result<Self, ConfigError> {
        let mut config = Self::default();

        // QUORUM_MIN_VALIDATORS
        if let Ok(val) = std::env::var("QUORUM_MIN_VALIDATORS") {
            config.min_validators = val.parse::<usize>().map_err(|_| ConfigError::InvalidValue {
                var_name: "QUORUM_MIN_VALIDATORS".to_string(),
                value: val.clone(),
                message: "expected unsigned integer".to_string(),
            })?;
        }

        // QUORUM_FRACTION
        if let Ok(val) = std::env::var("QUORUM_FRACTION") {
            let fraction = val.parse::<f64>().map_err(|_| ConfigError::InvalidValue {
                var_name: "QUORUM_FRACTION".to_string(),
                value: val.clone(),
                message: "expected floating point number".to_string(),
            })?;

            // Validate range [0.0, 1.0]
            if !(0.0..=1.0).contains(&fraction) {
                return Err(ConfigError::OutOfRange {
                    var_name: "QUORUM_FRACTION".to_string(),
                    value: val,
                    constraint: "must be between 0.0 and 1.0".to_string(),
                });
            }

            config.quorum_fraction = fraction;
        }

        // QUORUM_SIGNATURE_TIMEOUT_MS
        if let Ok(val) = std::env::var("QUORUM_SIGNATURE_TIMEOUT_MS") {
            config.signature_timeout_ms = val.parse::<u64>().map_err(|_| ConfigError::InvalidValue {
                var_name: "QUORUM_SIGNATURE_TIMEOUT_MS".to_string(),
                value: val.clone(),
                message: "expected unsigned integer".to_string(),
            })?;
        }

        // QUORUM_MAX_BLOB_SIZE
        if let Ok(val) = std::env::var("QUORUM_MAX_BLOB_SIZE") {
            config.max_blob_size = val.parse::<usize>().map_err(|_| ConfigError::InvalidValue {
                var_name: "QUORUM_MAX_BLOB_SIZE".to_string(),
                value: val.clone(),
                message: "expected unsigned integer".to_string(),
            })?;
        }

        // QUORUM_VALIDATOR_ENDPOINTS (comma-separated)
        if let Ok(val) = std::env::var("QUORUM_VALIDATOR_ENDPOINTS") {
            if !val.is_empty() {
                config.validator_endpoints = val
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
        }

        // QUORUM_RETRY_COUNT
        if let Ok(val) = std::env::var("QUORUM_RETRY_COUNT") {
            config.retry_count = val.parse::<u32>().map_err(|_| ConfigError::InvalidValue {
                var_name: "QUORUM_RETRY_COUNT".to_string(),
                value: val.clone(),
                message: "expected unsigned integer".to_string(),
            })?;
        }

        Ok(config)
    }

    /// Menghitung quorum threshold berdasarkan jumlah validator.
    ///
    /// ## Formula
    ///
    /// ```text
    /// raw_threshold = ceil(total_validators * quorum_fraction)
    /// with_minimum = max(raw_threshold, min_validators)
    /// threshold = min(with_minimum, total_validators)
    /// ```
    ///
    /// ## Edge Cases
    ///
    /// - Jika `total_validators == 0`, hasil adalah 0
    /// - Threshold tidak pernah < `min_validators` (kecuali total_validators < min_validators)
    /// - Threshold tidak pernah > `total_validators`
    ///
    /// ## Guarantees
    ///
    /// - Tidak panic dalam kondisi apapun
    /// - Hasil selalu dalam range [0, total_validators]
    /// - Deterministic untuk input yang sama
    #[must_use]
    pub fn calculate_quorum_threshold(&self, total_validators: usize) -> usize {
        // Edge case: zero validators
        if total_validators == 0 {
            return 0;
        }

        // Calculate raw threshold using ceiling
        let raw_threshold = (total_validators as f64 * self.quorum_fraction).ceil() as usize;

        // Ensure minimum (but not more than total)
        let with_minimum = raw_threshold.max(self.min_validators);

        // Ensure not more than total validators
        with_minimum.min(total_validators)
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// VALIDATOR TYPES
// ════════════════════════════════════════════════════════════════════════════════

/// Informasi tentang validator dalam quorum.
///
/// ## Fields
///
/// - `id`: Identifier unik validator
/// - `public_key`: Public key untuk verifikasi signature (format opaque)
/// - `weight`: Voting weight validator dalam quorum
///
/// ## Invariants
///
/// - `id` harus non-empty
/// - `weight` harus > 0 untuk validator aktif
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorInfo {
    /// Unique identifier untuk validator.
    pub id: String,

    /// Public key dalam format bytes (scheme-agnostic).
    pub public_key: Vec<u8>,

    /// Voting weight dalam quorum calculation.
    pub weight: u64,
}

/// Signature dari satu validator untuk data tertentu.
///
/// ## Fields (WAJIB per spec)
///
/// - `validator_id`: ID validator yang membuat signature
/// - `signature`: Signature bytes (scheme-agnostic)
/// - `timestamp`: Unix timestamp saat signature dibuat
///
/// ## Invariants
///
/// - `validator_id` harus mereferensikan validator yang valid
/// - `signature` harus non-empty
/// - `timestamp` harus > 0 dan dalam range yang reasonable
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorSignature {
    /// ID validator yang membuat signature ini.
    pub validator_id: String,

    /// Signature bytes (format tergantung implementasi).
    pub signature: Vec<u8>,

    /// Unix timestamp (seconds) saat signature dibuat.
    pub timestamp: u64,
}

// ════════════════════════════════════════════════════════════════════════════════
// QUORUM DA TRAIT
// ════════════════════════════════════════════════════════════════════════════════

/// Trait untuk Data Availability berbasis quorum validator.
///
/// `QuorumDA` meng-extend `DALayer` dan menambahkan operasi
/// yang spesifik untuk quorum-based storage.
///
/// ## Kontrak
///
/// Implementor WAJIB menjamin:
/// - Thread-safety (Send + Sync)
/// - Deterministic quorum verification
/// - Consistent threshold semantics
///
/// ## Non-Guarantees
///
/// Trait ini TIDAK menjamin:
/// - Liveness (implementor-specific)
/// - Specific signature scheme
/// - Network reliability
/// - Persistence durability
pub trait QuorumDA: DALayer {
    /// Mengembalikan quorum threshold minimum.
    ///
    /// ## Returns
    ///
    /// Jumlah minimum signature (atau total weight) yang diperlukan
    /// untuk mencapai quorum.
    ///
    /// ## Guarantees
    ///
    /// - Nilai selalu > 0
    /// - Nilai konsisten selama lifetime instance
    ///
    /// ## Non-Guarantees
    ///
    /// - Tidak mendefinisikan bagaimana threshold dihitung
    /// - Tidak mendefinisikan apakah berbasis count atau weight
    fn quorum_threshold(&self) -> usize;

    /// Mengembalikan daftar validator yang aktif.
    ///
    /// ## Returns
    ///
    /// `Vec<ValidatorInfo>` berisi semua validator yang saat ini
    /// dapat berpartisipasi dalam quorum.
    ///
    /// ## Guarantees
    ///
    /// - Hanya validator aktif yang dikembalikan
    /// - Setiap validator memiliki ID unik
    ///
    /// ## Non-Guarantees
    ///
    /// - Ordering tidak dijamin
    /// - List mungkin berubah antar panggilan
    fn active_validators(&self) -> Vec<ValidatorInfo>;

    /// Submit data dengan kumpulan signature validator.
    ///
    /// ## Parameters
    ///
    /// - `data`: Data bytes yang akan disimpan
    /// - `sigs`: Kumpulan signature dari validator
    ///
    /// ## Returns
    ///
    /// - `Ok(BlobRef)`: Referensi ke blob yang tersimpan
    /// - `Err(QuorumError)`: Jika quorum tidak tercapai atau error lain
    ///
    /// ## Guarantees
    ///
    /// - Data hanya disimpan jika quorum tercapai
    /// - BlobRef valid untuk retrieval via DALayer::get_blob
    ///
    /// ## Non-Guarantees
    ///
    /// - Tidak mendefinisikan durability
    /// - Tidak mendefinisikan replication factor
    fn submit_with_signatures(
        &self,
        data: &[u8],
        sigs: Vec<ValidatorSignature>,
    ) -> Result<BlobRef, QuorumError>;

    /// Verifikasi apakah blob memiliki quorum yang valid.
    ///
    /// ## Parameters
    ///
    /// - `blob_ref`: Referensi ke blob yang akan diverifikasi
    ///
    /// ## Returns
    ///
    /// - `Ok(true)`: Blob memiliki quorum valid
    /// - `Ok(false)`: Blob tidak memiliki quorum valid
    /// - `Err(QuorumError)`: Jika verifikasi gagal
    ///
    /// ## Guarantees
    ///
    /// - Verifikasi bersifat deterministic untuk state yang sama
    ///
    /// ## Non-Guarantees
    ///
    /// - Tidak mendefinisikan apa yang terjadi jika blob tidak ada
    fn verify_quorum(&self, blob_ref: &BlobRef) -> Result<bool, QuorumError>;

    /// Mengumpulkan signature dari validator untuk data hash.
    ///
    /// ## Parameters
    ///
    /// - `data_hash`: SHA-256 hash dari data yang akan di-sign
    ///
    /// ## Returns
    ///
    /// - `Ok(Vec<ValidatorSignature>)`: Signature yang berhasil dikumpulkan
    /// - `Err(QuorumError)`: Jika pengumpulan gagal
    ///
    /// ## Guarantees
    ///
    /// - Setiap signature dalam result valid untuk data_hash
    /// - Tidak ada duplikat validator_id dalam result
    ///
    /// ## Non-Guarantees
    ///
    /// - Tidak menjamin jumlah signature >= threshold
    /// - Tidak mendefinisikan timeout behavior
    fn collect_signatures(
        &self,
        data_hash: &[u8; 32],
    ) -> Result<Vec<ValidatorSignature>, QuorumError>;
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quorum_error_display() {
        let err = QuorumError::InsufficientQuorum("need 3, got 2".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("insufficient quorum"));
        assert!(msg.contains("need 3"));
    }

    #[test]
    fn test_quorum_error_variants() {
        let errors = vec![
            QuorumError::InsufficientQuorum("test".to_string()),
            QuorumError::InvalidSignature("test".to_string()),
            QuorumError::ValidatorNotFound("test".to_string()),
            QuorumError::NetworkError("test".to_string()),
            QuorumError::Internal("test".to_string()),
        ];

        for err in errors {
            // All variants should implement Display
            let _ = format!("{}", err);
        }
    }

    #[test]
    fn test_validator_info_construction() {
        let info = ValidatorInfo {
            id: "validator-1".to_string(),
            public_key: vec![1, 2, 3, 4],
            weight: 100,
        };
        assert_eq!(info.id, "validator-1");
        assert_eq!(info.weight, 100);
        assert_eq!(info.public_key.len(), 4);
    }

    #[test]
    fn test_validator_signature_construction() {
        let sig = ValidatorSignature {
            validator_id: "validator-1".to_string(),
            signature: vec![0xDE, 0xAD, 0xBE, 0xEF],
            timestamp: 1700000000,
        };
        assert_eq!(sig.validator_id, "validator-1");
        assert_eq!(sig.timestamp, 1700000000);
        assert!(!sig.signature.is_empty());
    }

    #[test]
    fn test_validator_signature_has_required_fields() {
        // Verify struct has exactly the 3 required fields per spec
        let sig = ValidatorSignature {
            validator_id: "v1".to_string(),
            signature: vec![],
            timestamp: 0,
        };
        // If this compiles, the struct has the correct fields
        let _ = sig.validator_id;
        let _ = sig.signature;
        let _ = sig.timestamp;
    }

    #[test]
    fn test_validator_info_clone() {
        let info = ValidatorInfo {
            id: "v1".to_string(),
            public_key: vec![1, 2, 3],
            weight: 50,
        };
        let cloned = info.clone();
        assert_eq!(info, cloned);
    }

    #[test]
    fn test_validator_signature_clone() {
        let sig = ValidatorSignature {
            validator_id: "v1".to_string(),
            signature: vec![1, 2, 3],
            timestamp: 12345,
        };
        let cloned = sig.clone();
        assert_eq!(sig, cloned);
    }

    #[test]
    fn test_quorum_error_is_error_trait() {
        let err: Box<dyn std::error::Error> =
            Box::new(QuorumError::Internal("test".to_string()));
        assert!(err.to_string().contains("internal error"));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // QuorumDAConfig Tests (14A.1A.22)
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_quorum_da_config_default_values() {
        let config = QuorumDAConfig::default();

        assert_eq!(config.min_validators, 3);
        assert!((config.quorum_fraction - 0.67).abs() < f64::EPSILON);
        assert_eq!(config.signature_timeout_ms, 10_000);
        assert_eq!(config.max_blob_size, 2 * 1024 * 1024); // 2MB
        assert!(config.validator_endpoints.is_empty());
        assert_eq!(config.retry_count, 3);
    }

    #[test]
    fn test_quorum_da_config_new_equals_default() {
        let new_config = QuorumDAConfig::new();
        let default_config = QuorumDAConfig::default();
        assert_eq!(new_config, default_config);
    }

    #[test]
    fn test_quorum_da_config_max_blob_size_is_2mb() {
        let config = QuorumDAConfig::default();
        // Explicit 2MB check
        assert_eq!(config.max_blob_size, 2_097_152);
    }

    #[test]
    fn test_quorum_da_config_clone() {
        let config = QuorumDAConfig {
            min_validators: 5,
            quorum_fraction: 0.8,
            signature_timeout_ms: 5000,
            max_blob_size: 1024,
            validator_endpoints: vec!["http://localhost:8080".to_string()],
            retry_count: 5,
        };
        let cloned = config.clone();
        assert_eq!(config, cloned);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // calculate_quorum_threshold Tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_calculate_quorum_threshold_zero_validators() {
        let config = QuorumDAConfig::default();
        // Spec: 0 validator → quorum = 0
        assert_eq!(config.calculate_quorum_threshold(0), 0);
    }

    #[test]
    fn test_calculate_quorum_threshold_basic_cases() {
        // Using fraction 0.67 (slightly > 2/3)
        let config = QuorumDAConfig {
            min_validators: 1, // Low min to test pure fraction calculation
            quorum_fraction: 0.67,
            ..Default::default()
        };

        // 3 validators: ceil(3 * 0.67) = ceil(2.01) = 3
        assert_eq!(config.calculate_quorum_threshold(3), 3);

        // 4 validators: ceil(4 * 0.67) = ceil(2.68) = 3
        assert_eq!(config.calculate_quorum_threshold(4), 3);

        // 5 validators: ceil(5 * 0.67) = ceil(3.35) = 4
        assert_eq!(config.calculate_quorum_threshold(5), 4);

        // 10 validators: ceil(10 * 0.67) = ceil(6.7) = 7
        assert_eq!(config.calculate_quorum_threshold(10), 7);
    }

    #[test]
    fn test_calculate_quorum_threshold_with_2_3_fraction() {
        // Using exactly 2/3 fraction for clearer math
        let config = QuorumDAConfig {
            min_validators: 1,
            quorum_fraction: 2.0 / 3.0,
            ..Default::default()
        };

        // 3 validators: ceil(3 * 0.666...) = ceil(2.0) = 2
        assert_eq!(config.calculate_quorum_threshold(3), 2);

        // 4 validators: ceil(4 * 0.666...) = ceil(2.666...) = 3
        assert_eq!(config.calculate_quorum_threshold(4), 3);

        // 6 validators: ceil(6 * 0.666...) = ceil(4.0) = 4
        assert_eq!(config.calculate_quorum_threshold(6), 4);
    }

    #[test]
    fn test_calculate_quorum_threshold_min_validators_constraint() {
        let config = QuorumDAConfig {
            min_validators: 3,
            quorum_fraction: 0.5,
            ..Default::default()
        };

        // 2 validators: ceil(2 * 0.5) = 1, but min is 3, but total is 2
        // Result: min(max(1, 3), 2) = min(3, 2) = 2
        assert_eq!(config.calculate_quorum_threshold(2), 2);

        // 4 validators: ceil(4 * 0.5) = 2, but min is 3
        // Result: min(max(2, 3), 4) = min(3, 4) = 3
        assert_eq!(config.calculate_quorum_threshold(4), 3);

        // 10 validators: ceil(10 * 0.5) = 5, already >= min
        // Result: min(max(5, 3), 10) = min(5, 10) = 5
        assert_eq!(config.calculate_quorum_threshold(10), 5);
    }

    #[test]
    fn test_calculate_quorum_threshold_one_validator() {
        let config = QuorumDAConfig {
            min_validators: 3,
            quorum_fraction: 0.67,
            ..Default::default()
        };

        // 1 validator: ceil(1 * 0.67) = 1
        // min(max(1, 3), 1) = min(3, 1) = 1
        // Cannot exceed total validators
        assert_eq!(config.calculate_quorum_threshold(1), 1);
    }

    #[test]
    fn test_calculate_quorum_threshold_never_exceeds_total() {
        let config = QuorumDAConfig {
            min_validators: 10,
            quorum_fraction: 0.99,
            ..Default::default()
        };

        // Even with high min and fraction, cannot exceed total
        assert_eq!(config.calculate_quorum_threshold(3), 3);
        assert_eq!(config.calculate_quorum_threshold(5), 5);
    }

    #[test]
    fn test_calculate_quorum_threshold_full_quorum() {
        let config = QuorumDAConfig {
            min_validators: 1,
            quorum_fraction: 1.0, // 100%
            ..Default::default()
        };

        assert_eq!(config.calculate_quorum_threshold(1), 1);
        assert_eq!(config.calculate_quorum_threshold(5), 5);
        assert_eq!(config.calculate_quorum_threshold(100), 100);
    }

    #[test]
    fn test_calculate_quorum_threshold_zero_fraction() {
        let config = QuorumDAConfig {
            min_validators: 1,
            quorum_fraction: 0.0,
            ..Default::default()
        };

        // ceil(n * 0) = 0, but min is 1
        // Result: min(max(0, 1), n) = min(1, n)
        assert_eq!(config.calculate_quorum_threshold(3), 1);
        assert_eq!(config.calculate_quorum_threshold(10), 1);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // ConfigError Tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_config_error_display_invalid_value() {
        let err = ConfigError::InvalidValue {
            var_name: "QUORUM_MIN_VALIDATORS".to_string(),
            value: "abc".to_string(),
            message: "expected unsigned integer".to_string(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("QUORUM_MIN_VALIDATORS"));
        assert!(msg.contains("abc"));
        assert!(msg.contains("expected unsigned integer"));
    }

    #[test]
    fn test_config_error_display_out_of_range() {
        let err = ConfigError::OutOfRange {
            var_name: "QUORUM_FRACTION".to_string(),
            value: "1.5".to_string(),
            constraint: "must be between 0.0 and 1.0".to_string(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("QUORUM_FRACTION"));
        assert!(msg.contains("1.5"));
        assert!(msg.contains("must be between 0.0 and 1.0"));
    }

    #[test]
    fn test_config_error_is_error_trait() {
        let err: Box<dyn std::error::Error> = Box::new(ConfigError::InvalidValue {
            var_name: "TEST".to_string(),
            value: "bad".to_string(),
            message: "test error".to_string(),
        });
        assert!(err.to_string().contains("TEST"));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // from_env Tests (requires careful env manipulation)
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_from_env_with_no_env_vars_uses_defaults() {
        // Clear any existing env vars that might interfere
        std::env::remove_var("QUORUM_MIN_VALIDATORS");
        std::env::remove_var("QUORUM_FRACTION");
        std::env::remove_var("QUORUM_SIGNATURE_TIMEOUT_MS");
        std::env::remove_var("QUORUM_MAX_BLOB_SIZE");
        std::env::remove_var("QUORUM_VALIDATOR_ENDPOINTS");
        std::env::remove_var("QUORUM_RETRY_COUNT");

        let config = QuorumDAConfig::from_env().expect("from_env should succeed with no env vars");
        let default_config = QuorumDAConfig::default();

        assert_eq!(config.min_validators, default_config.min_validators);
        assert!((config.quorum_fraction - default_config.quorum_fraction).abs() < f64::EPSILON);
        assert_eq!(config.signature_timeout_ms, default_config.signature_timeout_ms);
        assert_eq!(config.max_blob_size, default_config.max_blob_size);
        assert_eq!(config.validator_endpoints, default_config.validator_endpoints);
        assert_eq!(config.retry_count, default_config.retry_count);
    }

    #[test]
    fn test_from_env_parses_valid_values() {
        std::env::set_var("QUORUM_MIN_VALIDATORS", "5");
        std::env::set_var("QUORUM_FRACTION", "0.75");
        std::env::set_var("QUORUM_SIGNATURE_TIMEOUT_MS", "5000");
        std::env::set_var("QUORUM_MAX_BLOB_SIZE", "1048576");
        std::env::set_var("QUORUM_VALIDATOR_ENDPOINTS", "http://a:1,http://b:2");
        std::env::set_var("QUORUM_RETRY_COUNT", "5");

        let config = QuorumDAConfig::from_env().expect("from_env should succeed");

        assert_eq!(config.min_validators, 5);
        assert!((config.quorum_fraction - 0.75).abs() < f64::EPSILON);
        assert_eq!(config.signature_timeout_ms, 5000);
        assert_eq!(config.max_blob_size, 1048576);
        assert_eq!(config.validator_endpoints, vec!["http://a:1", "http://b:2"]);
        assert_eq!(config.retry_count, 5);

        // Cleanup
        std::env::remove_var("QUORUM_MIN_VALIDATORS");
        std::env::remove_var("QUORUM_FRACTION");
        std::env::remove_var("QUORUM_SIGNATURE_TIMEOUT_MS");
        std::env::remove_var("QUORUM_MAX_BLOB_SIZE");
        std::env::remove_var("QUORUM_VALIDATOR_ENDPOINTS");
        std::env::remove_var("QUORUM_RETRY_COUNT");
    }

    #[test]
    fn test_from_env_fails_on_invalid_min_validators() {
        std::env::set_var("QUORUM_MIN_VALIDATORS", "not_a_number");

        let result = QuorumDAConfig::from_env();
        assert!(result.is_err());

        if let Err(ConfigError::InvalidValue { var_name, .. }) = result {
            assert_eq!(var_name, "QUORUM_MIN_VALIDATORS");
        } else {
            panic!("Expected ConfigError::InvalidValue");
        }

        std::env::remove_var("QUORUM_MIN_VALIDATORS");
    }

    #[test]
    fn test_from_env_fails_on_invalid_fraction() {
        std::env::set_var("QUORUM_FRACTION", "abc");

        let result = QuorumDAConfig::from_env();
        assert!(result.is_err());

        std::env::remove_var("QUORUM_FRACTION");
    }

    #[test]
    fn test_from_env_fails_on_fraction_out_of_range() {
        std::env::set_var("QUORUM_FRACTION", "1.5");

        let result = QuorumDAConfig::from_env();
        assert!(result.is_err());

        if let Err(ConfigError::OutOfRange { var_name, .. }) = result {
            assert_eq!(var_name, "QUORUM_FRACTION");
        } else {
            panic!("Expected ConfigError::OutOfRange");
        }

        std::env::remove_var("QUORUM_FRACTION");
    }

    #[test]
    fn test_from_env_handles_empty_endpoints() {
        std::env::set_var("QUORUM_VALIDATOR_ENDPOINTS", "");

        let config = QuorumDAConfig::from_env().expect("should succeed");
        assert!(config.validator_endpoints.is_empty());

        std::env::remove_var("QUORUM_VALIDATOR_ENDPOINTS");
    }

    #[test]
    fn test_from_env_trims_endpoint_whitespace() {
        std::env::set_var("QUORUM_VALIDATOR_ENDPOINTS", " http://a:1 , http://b:2 ");

        let config = QuorumDAConfig::from_env().expect("should succeed");
        assert_eq!(config.validator_endpoints, vec!["http://a:1", "http://b:2"]);

        std::env::remove_var("QUORUM_VALIDATOR_ENDPOINTS");
    }
}