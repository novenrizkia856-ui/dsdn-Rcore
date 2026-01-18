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

    /// Threshold tidak valid (misalnya 0).
    ///
    /// Terjadi ketika threshold yang diberikan tidak dapat digunakan
    /// untuk verifikasi quorum yang meaningful.
    InvalidThreshold(String),
}

impl fmt::Display for QuorumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QuorumError::InsufficientQuorum(msg) => write!(f, "insufficient quorum: {}", msg),
            QuorumError::InvalidSignature(msg) => write!(f, "invalid signature: {}", msg),
            QuorumError::ValidatorNotFound(msg) => write!(f, "validator not found: {}", msg),
            QuorumError::NetworkError(msg) => write!(f, "network error: {}", msg),
            QuorumError::Internal(msg) => write!(f, "internal error: {}", msg),
            QuorumError::InvalidThreshold(msg) => write!(f, "invalid threshold: {}", msg),
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
// QUORUM VERIFICATION (14A.1A.24)
// ════════════════════════════════════════════════════════════════════════════════

/// Hasil verifikasi quorum signatures.
///
/// Struct ini merepresentasikan hasil lengkap dari proses verifikasi
/// quorum signatures, termasuk detail tentang signature yang valid
/// dan tidak valid.
///
/// ## Fields
///
/// - `is_valid`: True jika quorum tercapai (threshold_met == true)
/// - `valid_signatures`: Jumlah signature yang berhasil diverifikasi
/// - `invalid_signatures`: Daftar (validator_id, reason) untuk signature yang gagal
/// - `threshold_met`: True jika valid_signatures >= threshold
///
/// ## Perbedaan is_valid vs threshold_met
///
/// Saat ini keduanya memiliki nilai yang sama (`is_valid = threshold_met`).
/// Pemisahan ini untuk future extensibility jika ada kondisi tambahan
/// yang mempengaruhi validitas keseluruhan selain threshold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumVerification {
    /// Apakah verifikasi keseluruhan berhasil.
    ///
    /// True jika dan hanya jika threshold_met == true.
    pub is_valid: bool,

    /// Jumlah signature yang valid.
    ///
    /// Hanya menghitung signature yang:
    /// - Berasal dari validator yang dikenal
    /// - Berhasil diverifikasi dengan Ed25519
    pub valid_signatures: usize,

    /// Daftar signature yang tidak valid beserta alasannya.
    ///
    /// Format: (validator_id, reason)
    /// Reason harus eksplisit, tidak boleh empty.
    pub invalid_signatures: Vec<(String, String)>,

    /// Apakah threshold tercapai.
    ///
    /// True jika valid_signatures >= threshold.
    pub threshold_met: bool,
}

/// Memverifikasi quorum signatures menggunakan Ed25519.
///
/// ## Proses Verifikasi
///
/// 1. Validasi threshold (harus > 0)
/// 2. Bangun mapping validator_id -> public_key
/// 3. Untuk setiap signature:
///    - Cek apakah validator_id dikenal
///    - Verifikasi signature Ed25519 terhadap data_hash
/// 4. Hitung valid_signatures dan kumpulkan invalid_signatures
/// 5. Tentukan threshold_met dan is_valid
///
/// ## Parameters
///
/// - `data_hash`: SHA-256 hash dari data yang di-sign (32 bytes)
/// - `signatures`: Daftar signature dari validator
/// - `validators`: Daftar validator dengan public key Ed25519
/// - `threshold`: Jumlah minimum signature valid yang diperlukan
///
/// ## Returns
///
/// - `Ok(QuorumVerification)`: Hasil verifikasi lengkap
/// - `Err(QuorumError::InvalidThreshold)`: Jika threshold == 0
///
/// ## Guarantees
///
/// - Semua signature diproses (tidak ada early return sebelum selesai)
/// - Output deterministik untuk input yang sama
/// - Pure function tanpa side effects
///
/// ## Ed25519 Verification
///
/// Signature diverifikasi langsung terhadap data_hash tanpa
/// transformasi atau hashing ulang.
pub fn verify_quorum_signatures(
    data_hash: &[u8; 32],
    signatures: &[ValidatorSignature],
    validators: &[ValidatorInfo],
    threshold: usize,
) -> Result<QuorumVerification, QuorumError> {
    // Step 1: Validate threshold
    if threshold == 0 {
        return Err(QuorumError::InvalidThreshold(
            "threshold must be greater than 0".to_string(),
        ));
    }

    // Step 2: Build validator_id -> public_key mapping
    let validator_map: std::collections::HashMap<&str, &[u8]> = validators
        .iter()
        .map(|v| (v.id.as_str(), v.public_key.as_slice()))
        .collect();

    // Step 3 & 4: Process all signatures
    let mut valid_signatures: usize = 0;
    let mut invalid_signatures: Vec<(String, String)> = Vec::new();

    for sig in signatures {
        // Check if validator is known
        let public_key = match validator_map.get(sig.validator_id.as_str()) {
            Some(pk) => *pk,
            None => {
                invalid_signatures.push((
                    sig.validator_id.clone(),
                    "unknown validator".to_string(),
                ));
                continue;
            }
        };

        // Verify Ed25519 signature
        match verify_ed25519_signature(data_hash, &sig.signature, public_key) {
            Ok(true) => {
                valid_signatures += 1;
            }
            Ok(false) => {
                invalid_signatures.push((
                    sig.validator_id.clone(),
                    "signature verification failed".to_string(),
                ));
            }
            Err(reason) => {
                invalid_signatures.push((sig.validator_id.clone(), reason));
            }
        }
    }

    // Step 5 & 6: Determine threshold_met and is_valid
    let threshold_met = valid_signatures >= threshold;
    let is_valid = threshold_met;

    // Step 7: Return result
    Ok(QuorumVerification {
        is_valid,
        valid_signatures,
        invalid_signatures,
        threshold_met,
    })
}

/// Verifikasi Ed25519 signature.
///
/// ## Parameters
///
/// - `message`: Data yang di-sign (langsung, tanpa hashing ulang)
/// - `signature`: Signature bytes (64 bytes untuk Ed25519)
/// - `public_key`: Public key bytes (32 bytes untuk Ed25519)
///
/// ## Returns
///
/// - `Ok(true)`: Signature valid
/// - `Ok(false)`: Signature invalid
/// - `Err(String)`: Error dengan reason eksplisit
fn verify_ed25519_signature(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<bool, String> {
    use ed25519_dalek::{Signature, VerifyingKey, Verifier};

    // Validate public key length (Ed25519 public key is 32 bytes)
    if public_key.len() != 32 {
        return Err(format!(
            "invalid public key length: expected 32 bytes, got {}",
            public_key.len()
        ));
    }

    // Validate signature length (Ed25519 signature is 64 bytes)
    if signature.len() != 64 {
        return Err(format!(
            "invalid signature length: expected 64 bytes, got {}",
            signature.len()
        ));
    }

    // Convert to fixed-size arrays
    let pk_bytes: [u8; 32] = match public_key.try_into() {
        Ok(b) => b,
        Err(_) => return Err("failed to convert public key to array".to_string()),
    };

    let sig_bytes: [u8; 64] = match signature.try_into() {
        Ok(b) => b,
        Err(_) => return Err("failed to convert signature to array".to_string()),
    };

    // Parse public key (ed25519-dalek 2.x API)
    let vk: VerifyingKey = match VerifyingKey::from_bytes(&pk_bytes) {
        Ok(key) => key,
        Err(e) => {
            return Err(format!("invalid public key format: {}", e));
        }
    };

    // Parse signature (ed25519-dalek 2.x API)
    let sig = Signature::from_bytes(&sig_bytes);

    // Verify signature
    match vk.verify(message, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
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
// QUORUM METRICS (14A.1A.25)
// ════════════════════════════════════════════════════════════════════════════════

/// Metrik untuk monitoring operasi QuorumDA.
///
/// Semua field menggunakan atomic untuk thread-safety.
/// Update metrik tidak mempengaruhi logic utama.
#[derive(Debug, Default)]
pub struct QuorumMetrics {
    /// Jumlah blob yang berhasil di-submit.
    blobs_submitted: std::sync::atomic::AtomicUsize,

    /// Jumlah quorum yang berhasil tercapai.
    quorum_success: std::sync::atomic::AtomicUsize,

    /// Jumlah quorum yang gagal tercapai.
    quorum_failure: std::sync::atomic::AtomicUsize,

    /// Total signature yang berhasil dikumpulkan.
    signatures_collected: std::sync::atomic::AtomicUsize,

    /// Jumlah verifikasi yang gagal.
    verification_failures: std::sync::atomic::AtomicUsize,

    /// Jumlah get_blob yang ditemukan di local storage (hit).
    local_get_hits: std::sync::atomic::AtomicUsize,

    /// Jumlah get_blob yang tidak ditemukan di local storage (miss).
    local_get_miss: std::sync::atomic::AtomicUsize,

    /// Jumlah fallback fetch dari validator.
    fallback_gets: std::sync::atomic::AtomicUsize,

    /// Jumlah signature re-verification yang dilakukan.
    signature_rechecks: std::sync::atomic::AtomicUsize,

    /// Total health checks yang telah dilakukan.
    health_checks_total: std::sync::atomic::AtomicUsize,

    /// Last health status (0=Unavailable, 1=Degraded, 2=Healthy).
    last_health_status: std::sync::atomic::AtomicUsize,
}

impl QuorumMetrics {
    /// Membuat instance baru dengan semua counter di 0.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment blobs_submitted counter.
    pub fn record_blob_submitted(&self) {
        self.blobs_submitted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Increment quorum_success counter.
    pub fn record_quorum_success(&self) {
        self.quorum_success.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Increment quorum_failure counter.
    pub fn record_quorum_failure(&self) {
        self.quorum_failure.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Add to signatures_collected counter.
    pub fn record_signatures_collected(&self, count: usize) {
        self.signatures_collected.fetch_add(count, std::sync::atomic::Ordering::Relaxed);
    }

    /// Increment verification_failures counter.
    pub fn record_verification_failure(&self) {
        self.verification_failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Increment local_get_hits counter.
    pub fn record_local_get_hit(&self) {
        self.local_get_hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Increment local_get_miss counter.
    pub fn record_local_get_miss(&self) {
        self.local_get_miss.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Increment fallback_gets counter.
    pub fn record_fallback_get(&self) {
        self.fallback_gets.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Increment signature_rechecks counter.
    pub fn record_signature_recheck(&self) {
        self.signature_rechecks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Get current blobs_submitted count.
    #[must_use]
    pub fn get_blobs_submitted(&self) -> usize {
        self.blobs_submitted.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get current quorum_success count.
    #[must_use]
    pub fn get_quorum_success(&self) -> usize {
        self.quorum_success.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get current quorum_failure count.
    #[must_use]
    pub fn get_quorum_failure(&self) -> usize {
        self.quorum_failure.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get current signatures_collected count.
    #[must_use]
    pub fn get_signatures_collected(&self) -> usize {
        self.signatures_collected.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get current verification_failures count.
    #[must_use]
    pub fn get_verification_failures(&self) -> usize {
        self.verification_failures.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get current local_get_hits count.
    #[must_use]
    pub fn get_local_get_hits(&self) -> usize {
        self.local_get_hits.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get current local_get_miss count.
    #[must_use]
    pub fn get_local_get_miss(&self) -> usize {
        self.local_get_miss.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get current fallback_gets count.
    #[must_use]
    pub fn get_fallback_gets(&self) -> usize {
        self.fallback_gets.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get current signature_rechecks count.
    #[must_use]
    pub fn get_signature_rechecks(&self) -> usize {
        self.signature_rechecks.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Increment health_checks_total counter.
    pub fn record_health_check(&self) {
        self.health_checks_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Set last_health_status (0=Unavailable, 1=Degraded, 2=Healthy).
    pub fn set_last_health_status(&self, status: usize) {
        self.last_health_status.store(status, std::sync::atomic::Ordering::Relaxed);
    }

    /// Get current health_checks_total count.
    #[must_use]
    pub fn get_health_checks_total(&self) -> usize {
        self.health_checks_total.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get last_health_status (0=Unavailable, 1=Degraded, 2=Healthy).
    #[must_use]
    pub fn get_last_health_status(&self) -> usize {
        self.last_health_status.load(std::sync::atomic::Ordering::Relaxed)
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// QUORUM BLOB STORAGE (14A.1A.25)
// ════════════════════════════════════════════════════════════════════════════════

/// Metadata untuk blob yang tersimpan di QuorumDA.
///
/// Menyimpan informasi lengkap tentang quorum yang digunakan
/// untuk memvalidasi blob, termasuk hash data, signatures,
/// dan status reconciliation.
#[derive(Debug, Clone)]
pub struct QuorumBlobMetadata {
    /// SHA-256 hash dari data blob.
    pub data_hash: [u8; 32],

    /// Jumlah signature valid saat blob di-submit.
    pub valid_signatures: usize,

    /// Timestamp saat blob disimpan (Unix seconds).
    pub stored_at: u64,

    /// Signature yang digunakan untuk quorum.
    pub signatures: Vec<ValidatorSignature>,

    /// Daftar validator_id yang berpartisipasi dalam quorum.
    pub validator_ids: Vec<String>,

    /// Flag untuk menandai blob yang perlu di-reconcile dengan Celestia.
    ///
    /// True = blob belum di-submit ke Celestia
    /// False = blob sudah di-submit/reconcile ke Celestia
    pub pending_reconcile: bool,
}

/// Storage untuk blob yang di-submit via quorum.
///
/// Thread-safe storage menggunakan parking_lot::RwLock.
/// Deterministik dan tidak mengandung side effects.
/// Key adalah hex-encoded commitment dari BlobRef.
#[derive(Debug, Default)]
pub struct QuorumBlobStorage {
    /// Mapping dari commitment (hex) ke (data, metadata).
    blobs: parking_lot::RwLock<std::collections::HashMap<String, (Vec<u8>, QuorumBlobMetadata)>>,
}

impl QuorumBlobStorage {
    /// Membuat storage kosong baru.
    #[must_use]
    pub fn new() -> Self {
        Self {
            blobs: parking_lot::RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// Convert BlobRef to storage key (hex of commitment).
    fn blob_ref_to_key(blob_ref: &dsdn_common::BlobRef) -> String {
        hex::encode(blob_ref.commitment)
    }

    /// Menyimpan blob dengan metadata quorum.
    ///
    /// ## Parameters
    ///
    /// - `blob_ref`: Referensi blob
    /// - `data`: Data blob
    /// - `metadata`: Metadata quorum
    ///
    /// ## Returns
    ///
    /// - `Ok(())`: Berhasil disimpan
    /// - `Err(String)`: Jika blob sudah ada (reject overwrite)
    pub fn store(
        &self,
        blob_ref: &dsdn_common::BlobRef,
        data: Vec<u8>,
        metadata: QuorumBlobMetadata,
    ) -> Result<(), String> {
        let mut guard = self.blobs.write();
        let key = Self::blob_ref_to_key(blob_ref);

        if guard.contains_key(&key) {
            return Err(format!("blob already exists: {}", key));
        }

        guard.insert(key, (data, metadata));
        Ok(())
    }

    /// Mengambil blob beserta metadata.
    ///
    /// ## Returns
    ///
    /// - `Some((data, metadata))`: Jika blob ditemukan
    /// - `None`: Jika blob tidak ada
    #[must_use]
    pub fn get(&self, blob_ref: &dsdn_common::BlobRef) -> Option<(Vec<u8>, QuorumBlobMetadata)> {
        let guard = self.blobs.read();
        guard.get(&Self::blob_ref_to_key(blob_ref)).cloned()
    }

    /// Cek apakah blob ada di storage.
    #[must_use]
    pub fn contains(&self, blob_ref: &dsdn_common::BlobRef) -> bool {
        let guard = self.blobs.read();
        guard.contains_key(&Self::blob_ref_to_key(blob_ref))
    }

    /// Hapus blob dari storage.
    ///
    /// ## Returns
    ///
    /// - `Some((data, metadata))`: Jika blob ditemukan dan dihapus
    /// - `None`: Jika blob tidak ada
    pub fn remove(&self, blob_ref: &dsdn_common::BlobRef) -> Option<(Vec<u8>, QuorumBlobMetadata)> {
        let mut guard = self.blobs.write();
        guard.remove(&Self::blob_ref_to_key(blob_ref))
    }

    /// Jumlah blob yang tersimpan.
    #[must_use]
    pub fn len(&self) -> usize {
        let guard = self.blobs.read();
        guard.len()
    }

    /// Cek apakah storage kosong.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// VALIDATOR QUORUM DA (14A.1A.25)
// ════════════════════════════════════════════════════════════════════════════════

use crate::signature_collector::{SignatureCollector, SignatureCollectionError};

/// Implementasi konkret QuorumDA berbasis validator quorum.
///
/// ValidatorQuorumDA menyediakan Data Availability layer yang
/// menggunakan quorum signature dari validator untuk memastikan
/// data tersimpan dengan valid.
///
/// ## Thread Safety
///
/// Struct ini adalah Send + Sync dan aman untuk concurrent access.
///
/// ## Fields
///
/// - `config`: Konfigurasi quorum (threshold, timeout, dll)
/// - `collector`: Signature collector untuk mengumpulkan signature
/// - `storage`: Storage untuk blob yang berhasil di-submit
/// - `metrics`: Metrik operasi
pub struct ValidatorQuorumDA {
    /// Konfigurasi QuorumDA.
    config: QuorumDAConfig,

    /// Signature collector untuk mengumpulkan signature dari validator.
    collector: SignatureCollector,

    /// Storage untuk blob yang di-submit via quorum.
    storage: QuorumBlobStorage,

    /// Metrik operasi.
    metrics: QuorumMetrics,

    /// Daftar validator aktif (untuk active_validators()).
    validators: Vec<ValidatorInfo>,

    /// Tokio runtime handle untuk menjalankan async operations.
    runtime: tokio::runtime::Handle,
}

impl ValidatorQuorumDA {
    /// Membuat instance baru ValidatorQuorumDA.
    ///
    /// ## Parameters
    ///
    /// - `config`: Konfigurasi QuorumDA
    /// - `collector`: Signature collector yang sudah dikonfigurasi
    /// - `validators`: Daftar validator aktif
    /// - `runtime`: Tokio runtime handle untuk async operations
    #[must_use]
    pub fn new(
        config: QuorumDAConfig,
        collector: SignatureCollector,
        validators: Vec<ValidatorInfo>,
        runtime: tokio::runtime::Handle,
    ) -> Self {
        Self {
            config,
            collector,
            storage: QuorumBlobStorage::new(),
            metrics: QuorumMetrics::new(),
            validators,
            runtime,
        }
    }

    /// Membuat instance dengan storage dan metrics custom.
    ///
    /// Berguna untuk testing atau konfigurasi lanjutan.
    #[must_use]
    pub fn with_storage_and_metrics(
        config: QuorumDAConfig,
        collector: SignatureCollector,
        validators: Vec<ValidatorInfo>,
        runtime: tokio::runtime::Handle,
        storage: QuorumBlobStorage,
        metrics: QuorumMetrics,
    ) -> Self {
        Self {
            config,
            collector,
            storage,
            metrics,
            validators,
            runtime,
        }
    }

    /// Get reference to storage.
    #[must_use]
    pub fn storage(&self) -> &QuorumBlobStorage {
        &self.storage
    }

    /// Get reference to metrics.
    #[must_use]
    pub fn metrics(&self) -> &QuorumMetrics {
        &self.metrics
    }

    /// Get reference to config.
    #[must_use]
    pub fn config(&self) -> &QuorumDAConfig {
        &self.config
    }

    /// Compute deterministic BlobRef from data.
    /// Uses SHA-256 hash as commitment, height 0, default namespace.
    fn compute_blob_ref(data: &[u8], namespace: [u8; 29]) -> dsdn_common::BlobRef {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash: [u8; 32] = hasher.finalize().into();
        dsdn_common::BlobRef {
            height: 0, // QuorumDA doesn't have block height concept
            commitment: hash,
            namespace,
        }
    }

    /// Get default namespace for quorum DA.
    fn default_namespace() -> [u8; 29] {
        // Use "quorum" prefix padded with zeros
        let mut ns = [0u8; 29];
        ns[0..6].copy_from_slice(b"quorum");
        ns
    }
}

impl QuorumDA for ValidatorQuorumDA {
    fn quorum_threshold(&self) -> usize {
        self.config.calculate_quorum_threshold(self.validators.len())
    }

    fn active_validators(&self) -> Vec<ValidatorInfo> {
        self.validators.clone()
    }

    fn submit_with_signatures(
        &self,
        data: &[u8],
        sigs: Vec<ValidatorSignature>,
    ) -> Result<dsdn_common::BlobRef, QuorumError> {
        // Step 1: Compute data hash for verification
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash_result = hasher.finalize();
        let data_hash: [u8; 32] = hash_result.into();

        // Step 2: Verify quorum signatures
        let threshold = self.quorum_threshold();
        let verification = verify_quorum_signatures(
            &data_hash,
            &sigs,
            &self.validators,
            threshold,
        )?;

        // Step 3: Check if quorum is valid
        if !verification.is_valid {
            self.metrics.record_quorum_failure();
            return Err(QuorumError::InsufficientQuorum(format!(
                "only {} valid signatures, need {}",
                verification.valid_signatures,
                threshold
            )));
        }

        // Step 4: Record success metrics
        self.metrics.record_quorum_success();
        self.metrics.record_signatures_collected(verification.valid_signatures);

        // Step 5: Store blob
        let blob_ref = Self::compute_blob_ref(data, Self::default_namespace());

        // Extract validator IDs
        let validator_ids: Vec<String> = sigs
            .iter()
            .map(|s| s.validator_id.clone())
            .collect();

        let metadata = QuorumBlobMetadata {
            data_hash,
            valid_signatures: verification.valid_signatures,
            stored_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            signatures: sigs,
            validator_ids,
            pending_reconcile: true,
        };

        match self.storage.store(&blob_ref, data.to_vec(), metadata) {
            Ok(()) => {
                self.metrics.record_blob_submitted();
                Ok(blob_ref)
            }
            Err(e) => Err(QuorumError::Internal(format!("storage error: {}", e))),
        }
    }

    fn verify_quorum(&self, blob_ref: &dsdn_common::BlobRef) -> Result<bool, QuorumError> {
        // Step 1: Get blob and metadata from storage
        let (data, metadata) = match self.storage.get(blob_ref) {
            Some(entry) => entry,
            None => {
                return Err(QuorumError::Internal(format!(
                    "blob not found: {}",
                    hex::encode(blob_ref.commitment)
                )));
            }
        };

        // Step 2: Re-compute data hash
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let hash_result = hasher.finalize();
        let data_hash: [u8; 32] = hash_result.into();

        // Step 3: Re-verify quorum using stored signatures
        let threshold = self.quorum_threshold();
        let verification = verify_quorum_signatures(
            &data_hash,
            &metadata.signatures,
            &self.validators,
            threshold,
        )?;

        if !verification.is_valid {
            self.metrics.record_verification_failure();
        }

        Ok(verification.is_valid)
    }

    fn collect_signatures(
        &self,
        data_hash: &[u8; 32],
    ) -> Result<Vec<ValidatorSignature>, QuorumError> {
        // Delegate to SignatureCollector (async -> sync bridge)
        let collector = self.collector.clone();
        let hash = *data_hash;

        let result = self.runtime.block_on(async move {
            collector.collect(&hash).await
        });

        match result {
            Ok(sigs) => {
                self.metrics.record_signatures_collected(sigs.len());
                Ok(sigs)
            }
            Err(SignatureCollectionError::QuorumNotReached { collected, required }) => {
                self.metrics.record_quorum_failure();
                Err(QuorumError::InsufficientQuorum(format!(
                    "collected {} signatures, need {}",
                    collected, required
                )))
            }
            Err(SignatureCollectionError::Timeout { validator_id }) => {
                Err(QuorumError::NetworkError(format!(
                    "timeout waiting for validator {}",
                    validator_id
                )))
            }
            Err(SignatureCollectionError::NetworkError { validator_id, message }) => {
                Err(QuorumError::NetworkError(format!(
                    "network error for {:?}: {}",
                    validator_id, message
                )))
            }
            Err(SignatureCollectionError::InvalidResponse { validator_id, message }) => {
                Err(QuorumError::InvalidSignature(format!(
                    "invalid response from {}: {}",
                    validator_id, message
                )))
            }
            Err(SignatureCollectionError::Internal(msg)) => {
                Err(QuorumError::Internal(msg))
            }
        }
    }
}

// DALayer implementation for ValidatorQuorumDA
// All methods return Pin<Box<dyn Future<...>>>
impl dsdn_common::DALayer for ValidatorQuorumDA {
    /// Post blob to QuorumDA with quorum-based validation.
    ///
    /// ## Alur Operasi (14A.1A.26)
    ///
    /// 1. VALIDASI INPUT - Cek data tidak kosong
    /// 2. COMPUTE HASH - SHA-256 hash untuk signature verification
    /// 3. COLLECT SIGNATURES - Kumpulkan signature dari validator
    /// 4. VERIFY QUORUM - Verifikasi quorum tercapai
    /// 5. STORE BLOB - Simpan dengan metadata lengkap
    /// 6. TAGGING - Set pending_reconcile = true
    /// 7. RETURN BlobRef - Deterministik dan verifiable
    ///
    /// ## Error Handling
    ///
    /// - InvalidBlob: Data kosong
    /// - Other("quorum collection failed: ..."): Gagal collect signatures
    /// - Other("quorum not reached: ..."): Quorum tidak tercapai
    /// - Other("storage failure: ..."): Gagal menyimpan blob
    fn post_blob(
        &self,
        data: &[u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<dsdn_common::BlobRef, dsdn_common::DAError>> + Send + '_>> {
        use sha2::{Sha256, Digest};

        // ════════════════════════════════════════════════════════════════════════
        // STEP 1: VALIDASI INPUT
        // ════════════════════════════════════════════════════════════════════════
        
        // Validasi data tidak kosong
        if data.is_empty() {
            return Box::pin(async move {
                Err(dsdn_common::DAError::InvalidBlob)
            });
        }

        // Clone data untuk async block
        let data_owned = data.to_vec();

        // ════════════════════════════════════════════════════════════════════════
        // STEP 2: COMPUTE HASH
        // ════════════════════════════════════════════════════════════════════════
        
        // Hitung SHA-256 hash - konsisten dengan quorum verification
        let mut hasher = Sha256::new();
        hasher.update(&data_owned);
        let data_hash: [u8; 32] = hasher.finalize().into();

        Box::pin(async move {
            // ════════════════════════════════════════════════════════════════════
            // STEP 3: COLLECT SIGNATURES
            // ════════════════════════════════════════════════════════════════════
            //
            // PENTING: Kita langsung await collector.collect() di sini karena:
            // - Kita sudah di dalam async context
            // - Memanggil self.collect_signatures() akan menyebabkan nested block_on
            //   karena collect_signatures() adalah sync function yang internally
            //   menggunakan block_on
            // - Nested block_on akan panic dengan "Cannot start a runtime from within a runtime"
            //
            let signatures = match self.collector.collect(&data_hash).await {
                Ok(sigs) => {
                    self.metrics.record_signatures_collected(sigs.len());
                    sigs
                }
                Err(e) => {
                    self.metrics.record_quorum_failure();
                    return Err(dsdn_common::DAError::Other(format!(
                        "quorum collection failed: {}",
                        e
                    )));
                }
            };

            // ════════════════════════════════════════════════════════════════════
            // STEP 4: VERIFY QUORUM
            // ════════════════════════════════════════════════════════════════════
            
            let threshold = self.quorum_threshold();
            let verification = match verify_quorum_signatures(
                &data_hash,
                &signatures,
                &self.validators,
                threshold,
            ) {
                Ok(v) => v,
                Err(e) => {
                    self.metrics.record_quorum_failure();
                    return Err(dsdn_common::DAError::Other(format!(
                        "quorum verification error: {}",
                        e
                    )));
                }
            };

            // Cek quorum tercapai
            if !verification.is_valid {
                self.metrics.record_quorum_failure();
                return Err(dsdn_common::DAError::Other(format!(
                    "quorum not reached: {} valid signatures, need {}",
                    verification.valid_signatures,
                    threshold
                )));
            }

            // Record success metrics
            self.metrics.record_quorum_success();

            // ════════════════════════════════════════════════════════════════════
            // STEP 5 & 6: STORE BLOB WITH METADATA + TAGGING
            // ════════════════════════════════════════════════════════════════════
            
            // Compute BlobRef
            let blob_ref = Self::compute_blob_ref(&data_owned, Self::default_namespace());

            // Extract validator IDs yang berpartisipasi
            let validator_ids: Vec<String> = signatures
                .iter()
                .map(|s| s.validator_id.clone())
                .collect();

            // Build metadata dengan pending_reconcile = true
            let metadata = QuorumBlobMetadata {
                data_hash,
                valid_signatures: verification.valid_signatures,
                stored_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
                signatures,
                validator_ids,
                pending_reconcile: true, // TAGGING: Blob perlu di-reconcile ke Celestia
            };

            // Store blob
            match self.storage.store(&blob_ref, data_owned, metadata) {
                Ok(()) => {
                    self.metrics.record_blob_submitted();
                }
                Err(e) => {
                    return Err(dsdn_common::DAError::Other(format!(
                        "storage failure: {}",
                        e
                    )));
                }
            }

            // ════════════════════════════════════════════════════════════════════
            // STEP 7: RETURN BlobRef
            // ════════════════════════════════════════════════════════════════════
            
            Ok(blob_ref)
        })
    }

    /// Get blob from QuorumDA with signature re-verification.
    ///
    /// ## Alur Operasi (14A.1A.27)
    ///
    /// 1. LOCAL STORAGE LOOKUP - Cari blob di storage lokal
    /// 2. SIGNATURE RE-VERIFICATION - Verifikasi ulang quorum signatures
    /// 3. FALLBACK (jika tidak ditemukan) - Return BlobNotFound
    /// 4. RETURN DATA - Return data jika valid
    ///
    /// ## Error Handling
    ///
    /// - BlobNotFound: Blob tidak ada di storage lokal
    /// - Other("quorum verification failed: ..."): Signature/quorum invalid
    fn get_blob(
        &self,
        ref_: &dsdn_common::BlobRef,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, dsdn_common::DAError>> + Send + '_>> {
        let blob_ref = ref_.clone();

        Box::pin(async move {
            // ════════════════════════════════════════════════════════════════════
            // STEP 1: LOCAL STORAGE LOOKUP
            // ════════════════════════════════════════════════════════════════════

            let (data, metadata) = match self.storage.get(&blob_ref) {
                Some(entry) => {
                    self.metrics.record_local_get_hit();
                    entry
                }
                None => {
                    // Cache miss - blob tidak ada di storage lokal
                    self.metrics.record_local_get_miss();

                    // Fallback fetch dari validator tidak tersedia
                    // (tidak ada API untuk read-only fetch dari validators)
                    // Return BlobNotFound
                    return Err(dsdn_common::DAError::BlobNotFound(blob_ref));
                }
            };

            // ════════════════════════════════════════════════════════════════════
            // STEP 2: SIGNATURE RE-VERIFICATION
            // ════════════════════════════════════════════════════════════════════
            //
            // Re-verify quorum signatures untuk memastikan data masih valid.
            // Ini penting untuk deteksi data corruption atau tampering.

            self.metrics.record_signature_recheck();

            // Ambil threshold
            let threshold = self.quorum_threshold();

            // Verifikasi ulang signatures
            let verification = match verify_quorum_signatures(
                &metadata.data_hash,
                &metadata.signatures,
                &self.validators,
                threshold,
            ) {
                Ok(v) => v,
                Err(e) => {
                    self.metrics.record_verification_failure();
                    return Err(dsdn_common::DAError::Other(format!(
                        "quorum verification failed: {}",
                        e
                    )));
                }
            };

            // Cek apakah quorum masih valid
            if !verification.is_valid {
                self.metrics.record_verification_failure();
                return Err(dsdn_common::DAError::Other(format!(
                    "quorum verification failed: {} valid signatures, need {}",
                    verification.valid_signatures,
                    threshold
                )));
            }

            // ════════════════════════════════════════════════════════════════════
            // STEP 3: VERIFY DATA HASH INTEGRITY
            // ════════════════════════════════════════════════════════════════════
            //
            // Pastikan data hash dari metadata cocok dengan hash data aktual.
            // Ini mencegah data corruption.

            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(&data);
            let computed_hash: [u8; 32] = hasher.finalize().into();

            if computed_hash != metadata.data_hash {
                self.metrics.record_verification_failure();
                return Err(dsdn_common::DAError::Other(
                    "data integrity check failed: hash mismatch".to_string()
                ));
            }

            // ════════════════════════════════════════════════════════════════════
            // STEP 4: RETURN DATA
            // ════════════════════════════════════════════════════════════════════
            //
            // Data valid, quorum valid, hash valid - return data

            Ok(data)
        })
    }

    fn subscribe_blobs(
        &self,
        _from_height: Option<u64>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<dsdn_common::BlobStream, dsdn_common::DAError>> + Send + '_>> {
        // QuorumDA doesn't support streaming - return error
        Box::pin(async move {
            Err(dsdn_common::DAError::Other(
                "QuorumDA does not support blob streaming".to_string()
            ))
        })
    }

    /// Health check for QuorumDA (14A.1A.28).
    ///
    /// ## Alur Operasi
    ///
    /// 1. Ambil daftar validator endpoints dari config
    /// 2. Parallel connectivity check ke setiap endpoint
    /// 3. Hitung validator yang reachable
    /// 4. Tentukan status berdasarkan threshold:
    ///    - Healthy: reachable >= quorum_threshold
    ///    - Degraded: 0 < reachable < quorum_threshold
    ///    - Unavailable: reachable == 0
    ///
    /// ## Metrics
    ///
    /// - health_checks_total: Increment setiap pemanggilan
    /// - last_health_status: Update dengan status terakhir
    fn health_check(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<dsdn_common::DAHealthStatus, dsdn_common::DAError>> + Send + '_>> {
        Box::pin(async move {
            // Record health check
            self.metrics.record_health_check();

            // ════════════════════════════════════════════════════════════════════
            // STEP 1: AMBIL DAFTAR VALIDATOR
            // ════════════════════════════════════════════════════════════════════

            let endpoints = &self.config.validator_endpoints;
            let total_validators = endpoints.len();

            // Jika tidak ada endpoint, status = Unavailable
            if total_validators == 0 {
                self.metrics.set_last_health_status(0); // Unavailable
                return Ok(dsdn_common::DAHealthStatus::Unavailable);
            }

            // ════════════════════════════════════════════════════════════════════
            // STEP 2: PARALLEL CONNECTIVITY CHECK
            // ════════════════════════════════════════════════════════════════════

            let timeout_duration = std::time::Duration::from_millis(
                self.config.signature_timeout_ms
            );

            // Create HTTP client for health checks
            let client = reqwest::Client::builder()
                .timeout(timeout_duration)
                .build()
                .unwrap_or_else(|_| reqwest::Client::new());

            // Spawn parallel health check requests
            use futures::future::join_all;

            let health_checks: Vec<_> = endpoints
                .iter()
                .map(|endpoint| {
                    let client = client.clone();
                    let url = endpoint.clone();
                    async move {
                        // Try to connect to validator health endpoint
                        // Use HEAD request for minimal overhead
                        let health_url = format!("{}/health", url.trim_end_matches('/'));
                        match client.head(&health_url).send().await {
                            Ok(response) => response.status().is_success(),
                            Err(_) => {
                                // Fallback: try base URL
                                match client.head(&url).send().await {
                                    Ok(response) => response.status().is_success(),
                                    Err(_) => false,
                                }
                            }
                        }
                    }
                })
                .collect();

            let results = join_all(health_checks).await;

            // ════════════════════════════════════════════════════════════════════
            // STEP 3: HITUNG VALIDATOR REACHABLE
            // ════════════════════════════════════════════════════════════════════

            let reachable_count = results.iter().filter(|&&r| r).count();

            // ════════════════════════════════════════════════════════════════════
            // STEP 4: TENTUKAN STATUS
            // ════════════════════════════════════════════════════════════════════

            let quorum_threshold = self.config.calculate_quorum_threshold(total_validators);

            let status = if reachable_count >= quorum_threshold {
                // Healthy: reachable >= quorum_threshold
                self.metrics.set_last_health_status(2); // Healthy
                dsdn_common::DAHealthStatus::Healthy
            } else if reachable_count > 0 {
                // Degraded: 0 < reachable < quorum_threshold
                self.metrics.set_last_health_status(1); // Degraded
                dsdn_common::DAHealthStatus::Degraded
            } else {
                // Unavailable: reachable == 0
                self.metrics.set_last_health_status(0); // Unavailable
                dsdn_common::DAHealthStatus::Unavailable
            };

            Ok(status)
        })
    }
}

// Ensure ValidatorQuorumDA is Send + Sync
// This is a compile-time check
const _: fn() = || {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<ValidatorQuorumDA>();
    assert_sync::<ValidatorQuorumDA>();
};

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// Mutex untuk serialisasi tests yang mengakses environment variables.
    /// Environment variables adalah process-global state, sehingga tests yang
    /// memodifikasi env vars HARUS diserialisasi untuk menghindari race condition.
    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
        // Acquire mutex to prevent race condition with other env var tests
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

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
        // Acquire mutex to prevent race condition with other env var tests
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

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
        // Acquire mutex to prevent race condition with other env var tests
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

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
        // Acquire mutex to prevent race condition with other env var tests
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

        std::env::set_var("QUORUM_FRACTION", "abc");

        let result = QuorumDAConfig::from_env();
        assert!(result.is_err());

        std::env::remove_var("QUORUM_FRACTION");
    }

    #[test]
    fn test_from_env_fails_on_fraction_out_of_range() {
        // Acquire mutex to prevent race condition with other env var tests
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

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
        // Acquire mutex to prevent race condition with other env var tests
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

        std::env::set_var("QUORUM_VALIDATOR_ENDPOINTS", "");

        let config = QuorumDAConfig::from_env().expect("should succeed");
        assert!(config.validator_endpoints.is_empty());

        std::env::remove_var("QUORUM_VALIDATOR_ENDPOINTS");
    }

    #[test]
    fn test_from_env_trims_endpoint_whitespace() {
        // Acquire mutex to prevent race condition with other env var tests
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

        std::env::set_var("QUORUM_VALIDATOR_ENDPOINTS", " http://a:1 , http://b:2 ");

        let config = QuorumDAConfig::from_env().expect("should succeed");
        assert_eq!(config.validator_endpoints, vec!["http://a:1", "http://b:2"]);

        std::env::remove_var("QUORUM_VALIDATOR_ENDPOINTS");
    }

    // ────────────────────────────────────────────────────────────────────────────
    // QuorumVerification Tests (14A.1A.24)
    // ────────────────────────────────────────────────────────────────────────────

    use ed25519_dalek::{SigningKey, Signer};

    /// Helper: Generate Ed25519 keypair
    fn generate_keypair() -> (SigningKey, Vec<u8>) {
        use rand::rngs::OsRng;
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes().to_vec();
        (signing_key, public_key)
    }

    /// Helper: Sign data with Ed25519
    fn sign_data(signing_key: &SigningKey, data: &[u8]) -> Vec<u8> {
        signing_key.sign(data).to_bytes().to_vec()
    }

    #[test]
    fn test_quorum_verification_struct_construction() {
        let verification = QuorumVerification {
            is_valid: true,
            valid_signatures: 2,
            invalid_signatures: vec![],
            threshold_met: true,
        };
        assert!(verification.is_valid);
        assert_eq!(verification.valid_signatures, 2);
        assert!(verification.invalid_signatures.is_empty());
        assert!(verification.threshold_met);
    }

    #[test]
    fn test_verify_quorum_signatures_invalid_threshold_zero() {
        let data_hash = [0u8; 32];
        let signatures: Vec<ValidatorSignature> = vec![];
        let validators: Vec<ValidatorInfo> = vec![];

        let result = verify_quorum_signatures(&data_hash, &signatures, &validators, 0);
        assert!(result.is_err());
        match result {
            Err(QuorumError::InvalidThreshold(msg)) => {
                assert!(msg.contains("greater than 0"));
            }
            _ => panic!("Expected InvalidThreshold error"),
        }
    }

    #[test]
    fn test_verify_quorum_signatures_valid_quorum() {
        // Generate 3 keypairs
        let (sk1, pk1) = generate_keypair();
        let (sk2, pk2) = generate_keypair();
        let (sk3, pk3) = generate_keypair();

        let data_hash = [42u8; 32];

        // Create validators
        let validators = vec![
            ValidatorInfo { id: "v1".to_string(), public_key: pk1, weight: 1 },
            ValidatorInfo { id: "v2".to_string(), public_key: pk2, weight: 1 },
            ValidatorInfo { id: "v3".to_string(), public_key: pk3, weight: 1 },
        ];

        // Sign with 2 out of 3 validators
        let signatures = vec![
            ValidatorSignature {
                validator_id: "v1".to_string(),
                signature: sign_data(&sk1, &data_hash),
                timestamp: 1700000000,
            },
            ValidatorSignature {
                validator_id: "v2".to_string(),
                signature: sign_data(&sk2, &data_hash),
                timestamp: 1700000001,
            },
        ];

        let result = verify_quorum_signatures(&data_hash, &signatures, &validators, 2);
        assert!(result.is_ok());

        let verification = result.unwrap();
        assert!(verification.is_valid, "Should be valid");
        assert_eq!(verification.valid_signatures, 2, "Should have 2 valid signatures");
        assert!(verification.invalid_signatures.is_empty(), "Should have no invalid signatures");
        assert!(verification.threshold_met, "Threshold should be met");
    }

    #[test]
    fn test_verify_quorum_signatures_with_invalid_signature() {
        // Generate 3 keypairs
        let (sk1, pk1) = generate_keypair();
        let (_sk2, pk2) = generate_keypair();
        let (sk3, pk3) = generate_keypair();

        let data_hash = [42u8; 32];

        // Create validators
        let validators = vec![
            ValidatorInfo { id: "v1".to_string(), public_key: pk1, weight: 1 },
            ValidatorInfo { id: "v2".to_string(), public_key: pk2, weight: 1 },
            ValidatorInfo { id: "v3".to_string(), public_key: pk3, weight: 1 },
        ];

        // Create signatures - v2 has corrupted signature
        let signatures = vec![
            ValidatorSignature {
                validator_id: "v1".to_string(),
                signature: sign_data(&sk1, &data_hash),
                timestamp: 1700000000,
            },
            ValidatorSignature {
                validator_id: "v2".to_string(),
                signature: vec![0u8; 64], // Invalid signature (wrong bytes)
                timestamp: 1700000001,
            },
            ValidatorSignature {
                validator_id: "v3".to_string(),
                signature: sign_data(&sk3, &data_hash),
                timestamp: 1700000002,
            },
        ];

        let result = verify_quorum_signatures(&data_hash, &signatures, &validators, 2);
        assert!(result.is_ok());

        let verification = result.unwrap();
        assert!(verification.is_valid, "Should still be valid with 2 good signatures");
        assert_eq!(verification.valid_signatures, 2, "Should have 2 valid signatures");
        assert_eq!(verification.invalid_signatures.len(), 1, "Should have 1 invalid signature");

        // Check invalid signature details
        let (validator_id, reason) = &verification.invalid_signatures[0];
        assert_eq!(validator_id, "v2");
        assert!(!reason.is_empty(), "Reason must not be empty");
        assert!(verification.threshold_met, "Threshold should be met");
    }

    #[test]
    fn test_verify_quorum_signatures_threshold_not_met() {
        // Generate 3 keypairs
        let (sk1, pk1) = generate_keypair();
        let (_sk2, pk2) = generate_keypair();
        let (_sk3, pk3) = generate_keypair();

        let data_hash = [42u8; 32];

        // Create validators
        let validators = vec![
            ValidatorInfo { id: "v1".to_string(), public_key: pk1, weight: 1 },
            ValidatorInfo { id: "v2".to_string(), public_key: pk2, weight: 1 },
            ValidatorInfo { id: "v3".to_string(), public_key: pk3, weight: 1 },
        ];

        // Only 1 valid signature, threshold is 2
        let signatures = vec![
            ValidatorSignature {
                validator_id: "v1".to_string(),
                signature: sign_data(&sk1, &data_hash),
                timestamp: 1700000000,
            },
        ];

        let result = verify_quorum_signatures(&data_hash, &signatures, &validators, 2);
        assert!(result.is_ok());

        let verification = result.unwrap();
        assert!(!verification.is_valid, "Should NOT be valid");
        assert_eq!(verification.valid_signatures, 1, "Should have 1 valid signature");
        assert!(!verification.threshold_met, "Threshold should NOT be met");
    }

    #[test]
    fn test_verify_quorum_signatures_unknown_validator() {
        let (sk1, pk1) = generate_keypair();

        let data_hash = [42u8; 32];

        // Only v1 is known
        let validators = vec![
            ValidatorInfo { id: "v1".to_string(), public_key: pk1, weight: 1 },
        ];

        // Signature from unknown validator
        let signatures = vec![
            ValidatorSignature {
                validator_id: "v1".to_string(),
                signature: sign_data(&sk1, &data_hash),
                timestamp: 1700000000,
            },
            ValidatorSignature {
                validator_id: "unknown".to_string(),
                signature: vec![0u8; 64],
                timestamp: 1700000001,
            },
        ];

        let result = verify_quorum_signatures(&data_hash, &signatures, &validators, 1);
        assert!(result.is_ok());

        let verification = result.unwrap();
        assert!(verification.is_valid, "Should be valid (v1 is valid)");
        assert_eq!(verification.valid_signatures, 1);
        assert_eq!(verification.invalid_signatures.len(), 1);

        let (validator_id, reason) = &verification.invalid_signatures[0];
        assert_eq!(validator_id, "unknown");
        assert!(reason.contains("unknown validator"));
    }

    #[test]
    fn test_verify_quorum_signatures_invalid_signature_length() {
        let (_sk1, pk1) = generate_keypair();

        let data_hash = [42u8; 32];

        let validators = vec![
            ValidatorInfo { id: "v1".to_string(), public_key: pk1, weight: 1 },
        ];

        // Signature with wrong length
        let signatures = vec![
            ValidatorSignature {
                validator_id: "v1".to_string(),
                signature: vec![0u8; 32], // Wrong length (should be 64)
                timestamp: 1700000000,
            },
        ];

        let result = verify_quorum_signatures(&data_hash, &signatures, &validators, 1);
        assert!(result.is_ok());

        let verification = result.unwrap();
        assert!(!verification.is_valid, "Should not be valid");
        assert_eq!(verification.valid_signatures, 0);
        assert_eq!(verification.invalid_signatures.len(), 1);

        let (_, reason) = &verification.invalid_signatures[0];
        assert!(reason.contains("64 bytes"), "Should mention expected length");
    }

    #[test]
    fn test_verify_quorum_signatures_invalid_public_key_length() {
        let data_hash = [42u8; 32];

        // Validator with wrong public key length
        let validators = vec![
            ValidatorInfo {
                id: "v1".to_string(),
                public_key: vec![0u8; 16], // Wrong length (should be 32)
                weight: 1,
            },
        ];

        let signatures = vec![
            ValidatorSignature {
                validator_id: "v1".to_string(),
                signature: vec![0u8; 64],
                timestamp: 1700000000,
            },
        ];

        let result = verify_quorum_signatures(&data_hash, &signatures, &validators, 1);
        assert!(result.is_ok());

        let verification = result.unwrap();
        assert!(!verification.is_valid);
        assert_eq!(verification.invalid_signatures.len(), 1);

        let (_, reason) = &verification.invalid_signatures[0];
        assert!(reason.contains("32 bytes"), "Should mention expected length");
    }

    #[test]
    fn test_verify_quorum_signatures_empty_signatures() {
        let data_hash = [42u8; 32];
        let validators: Vec<ValidatorInfo> = vec![];
        let signatures: Vec<ValidatorSignature> = vec![];

        let result = verify_quorum_signatures(&data_hash, &signatures, &validators, 1);
        assert!(result.is_ok());

        let verification = result.unwrap();
        assert!(!verification.is_valid);
        assert_eq!(verification.valid_signatures, 0);
        assert!(!verification.threshold_met);
    }

    #[test]
    fn test_verify_quorum_signatures_deterministic() {
        let (sk1, pk1) = generate_keypair();
        let (sk2, pk2) = generate_keypair();

        let data_hash = [42u8; 32];

        let validators = vec![
            ValidatorInfo { id: "v1".to_string(), public_key: pk1, weight: 1 },
            ValidatorInfo { id: "v2".to_string(), public_key: pk2, weight: 1 },
        ];

        let signatures = vec![
            ValidatorSignature {
                validator_id: "v1".to_string(),
                signature: sign_data(&sk1, &data_hash),
                timestamp: 1700000000,
            },
            ValidatorSignature {
                validator_id: "v2".to_string(),
                signature: sign_data(&sk2, &data_hash),
                timestamp: 1700000001,
            },
        ];

        // Run verification multiple times
        let result1 = verify_quorum_signatures(&data_hash, &signatures, &validators, 2).unwrap();
        let result2 = verify_quorum_signatures(&data_hash, &signatures, &validators, 2).unwrap();
        let result3 = verify_quorum_signatures(&data_hash, &signatures, &validators, 2).unwrap();

        // All results should be identical
        assert_eq!(result1, result2);
        assert_eq!(result2, result3);
    }

    #[test]
    fn test_quorum_error_invalid_threshold_display() {
        let err = QuorumError::InvalidThreshold("test message".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("invalid threshold"));
        assert!(msg.contains("test message"));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // QuorumMetrics Tests (14A.1A.25)
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_quorum_metrics_new() {
        let metrics = QuorumMetrics::new();
        assert_eq!(metrics.get_blobs_submitted(), 0);
        assert_eq!(metrics.get_quorum_success(), 0);
        assert_eq!(metrics.get_quorum_failure(), 0);
        assert_eq!(metrics.get_signatures_collected(), 0);
        assert_eq!(metrics.get_verification_failures(), 0);
    }

    #[test]
    fn test_quorum_metrics_record_operations() {
        let metrics = QuorumMetrics::new();

        metrics.record_blob_submitted();
        metrics.record_blob_submitted();
        assert_eq!(metrics.get_blobs_submitted(), 2);

        metrics.record_quorum_success();
        assert_eq!(metrics.get_quorum_success(), 1);

        metrics.record_quorum_failure();
        metrics.record_quorum_failure();
        assert_eq!(metrics.get_quorum_failure(), 2);

        metrics.record_signatures_collected(5);
        metrics.record_signatures_collected(3);
        assert_eq!(metrics.get_signatures_collected(), 8);

        metrics.record_verification_failure();
        assert_eq!(metrics.get_verification_failures(), 1);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // QuorumBlobStorage Tests (14A.1A.25)
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_quorum_blob_storage_new() {
        let storage = QuorumBlobStorage::new();
        assert!(storage.is_empty());
        assert_eq!(storage.len(), 0);
    }

    #[test]
    fn test_quorum_blob_storage_store_and_get() {
        let storage = QuorumBlobStorage::new();
        
        let blob_ref = dsdn_common::BlobRef {
            height: 0,
            commitment: [0x11; 32],
            namespace: [0u8; 29],
        };
        
        let data = vec![1, 2, 3, 4];
        let metadata = QuorumBlobMetadata {
            data_hash: [0x11; 32],
            valid_signatures: 2,
            stored_at: 1700000000,
            signatures: vec![],
            validator_ids: vec!["v1".to_string(), "v2".to_string()],
            pending_reconcile: true,
        };

        // Store
        let result = storage.store(&blob_ref, data.clone(), metadata.clone());
        assert!(result.is_ok());
        assert_eq!(storage.len(), 1);
        assert!(!storage.is_empty());

        // Get
        let retrieved = storage.get(&blob_ref);
        assert!(retrieved.is_some());
        let (retrieved_data, retrieved_metadata) = retrieved.unwrap();
        assert_eq!(retrieved_data, data);
        assert_eq!(retrieved_metadata.valid_signatures, 2);
    }

    #[test]
    fn test_quorum_blob_storage_reject_overwrite() {
        let storage = QuorumBlobStorage::new();
        
        let blob_ref = dsdn_common::BlobRef {
            height: 0,
            commitment: [0x11; 32],
            namespace: [0u8; 29],
        };
        
        let metadata = QuorumBlobMetadata {
            data_hash: [0x11; 32],
            valid_signatures: 2,
            stored_at: 1700000000,
            signatures: vec![],
            validator_ids: vec![],
            pending_reconcile: true,
        };

        // First store succeeds
        let result1 = storage.store(&blob_ref, vec![1, 2, 3], metadata.clone());
        assert!(result1.is_ok());

        // Second store fails (reject overwrite)
        let result2 = storage.store(&blob_ref, vec![4, 5, 6], metadata);
        assert!(result2.is_err());
        assert!(result2.unwrap_err().contains("already exists"));
    }

    #[test]
    fn test_quorum_blob_storage_contains() {
        let storage = QuorumBlobStorage::new();
        
        let blob_ref = dsdn_common::BlobRef {
            height: 0,
            commitment: [0x11; 32],
            namespace: [0u8; 29],
        };

        assert!(!storage.contains(&blob_ref));

        let metadata = QuorumBlobMetadata {
            data_hash: [0x11; 32],
            valid_signatures: 2,
            stored_at: 1700000000,
            signatures: vec![],
            validator_ids: vec![],
            pending_reconcile: true,
        };
        let _ = storage.store(&blob_ref, vec![1, 2, 3], metadata);

        assert!(storage.contains(&blob_ref));
    }

    #[test]
    fn test_quorum_blob_storage_remove() {
        let storage = QuorumBlobStorage::new();
        
        let blob_ref = dsdn_common::BlobRef {
            height: 0,
            commitment: [0x11; 32],
            namespace: [0u8; 29],
        };
        
        let metadata = QuorumBlobMetadata {
            data_hash: [0x11; 32],
            valid_signatures: 2,
            stored_at: 1700000000,
            signatures: vec![],
            validator_ids: vec![],
            pending_reconcile: true,
        };
        let _ = storage.store(&blob_ref, vec![1, 2, 3], metadata);
        assert_eq!(storage.len(), 1);

        let removed = storage.remove(&blob_ref);
        assert!(removed.is_some());
        assert_eq!(storage.len(), 0);
        assert!(!storage.contains(&blob_ref));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // ValidatorQuorumDA Tests (14A.1A.25)
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_validator_quorum_da_quorum_threshold() {
        // Create a minimal setup for testing
        let config = QuorumDAConfig {
            min_validators: 1,
            quorum_fraction: 2.0 / 3.0,
            ..Default::default()
        };

        let client = reqwest::Client::new();
        let collector = crate::signature_collector::SignatureCollector::new(
            vec![],
            config.clone(),
            client,
        );

        let validators = vec![
            ValidatorInfo { id: "v1".to_string(), public_key: vec![1; 32], weight: 1 },
            ValidatorInfo { id: "v2".to_string(), public_key: vec![2; 32], weight: 1 },
            ValidatorInfo { id: "v3".to_string(), public_key: vec![3; 32], weight: 1 },
        ];

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let da = ValidatorQuorumDA::new(
            config,
            collector,
            validators,
            runtime.handle().clone(),
        );

        // 3 validators with 2/3 fraction = 2
        assert_eq!(da.quorum_threshold(), 2);
    }

    #[test]
    fn test_validator_quorum_da_active_validators() {
        let config = QuorumDAConfig::default();
        let client = reqwest::Client::new();
        let collector = crate::signature_collector::SignatureCollector::new(
            vec![],
            config.clone(),
            client,
        );

        let validators = vec![
            ValidatorInfo { id: "v1".to_string(), public_key: vec![1; 32], weight: 1 },
            ValidatorInfo { id: "v2".to_string(), public_key: vec![2; 32], weight: 1 },
        ];

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let da = ValidatorQuorumDA::new(
            config,
            collector,
            validators.clone(),
            runtime.handle().clone(),
        );

        let active = da.active_validators();
        assert_eq!(active.len(), 2);
        assert_eq!(active[0].id, "v1");
        assert_eq!(active[1].id, "v2");
    }

    #[test]
    fn test_validator_quorum_da_storage_initially_empty() {
        let config = QuorumDAConfig::default();
        let client = reqwest::Client::new();
        let collector = crate::signature_collector::SignatureCollector::new(
            vec![],
            config.clone(),
            client,
        );

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let da = ValidatorQuorumDA::new(
            config,
            collector,
            vec![],
            runtime.handle().clone(),
        );

        assert!(da.storage().is_empty());
        assert_eq!(da.storage().len(), 0);
    }

    #[test]
    fn test_validator_quorum_da_submit_with_valid_signatures() {
        let (sk1, pk1) = generate_keypair();
        let (sk2, pk2) = generate_keypair();

        let config = QuorumDAConfig {
            min_validators: 1,
            quorum_fraction: 0.5,
            ..Default::default()
        };
        let client = reqwest::Client::new();
        let collector = crate::signature_collector::SignatureCollector::new(
            vec![],
            config.clone(),
            client,
        );

        let validators = vec![
            ValidatorInfo { id: "v1".to_string(), public_key: pk1, weight: 1 },
            ValidatorInfo { id: "v2".to_string(), public_key: pk2, weight: 1 },
        ];

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let da = ValidatorQuorumDA::new(
            config,
            collector,
            validators,
            runtime.handle().clone(),
        );

        // Data to submit
        let data = b"test data for quorum";
        
        // Compute hash manually
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash: [u8; 32] = hasher.finalize().into();

        // Create valid signatures
        let signatures = vec![
            ValidatorSignature {
                validator_id: "v1".to_string(),
                signature: sign_data(&sk1, &hash),
                timestamp: 1700000000,
            },
            ValidatorSignature {
                validator_id: "v2".to_string(),
                signature: sign_data(&sk2, &hash),
                timestamp: 1700000001,
            },
        ];

        // Submit
        let result = da.submit_with_signatures(data, signatures);
        assert!(result.is_ok(), "Should succeed with valid quorum");

        let blob_ref = result.unwrap();
        // Verify commitment is not all zeros (valid hash was computed)
        assert!(blob_ref.commitment != [0u8; 32]);

        // Verify storage
        assert!(!da.storage().is_empty());
        assert!(da.storage().contains(&blob_ref));

        // Verify metrics
        assert_eq!(da.metrics().get_blobs_submitted(), 1);
        assert_eq!(da.metrics().get_quorum_success(), 1);
        assert_eq!(da.metrics().get_quorum_failure(), 0);
    }

    #[test]
    fn test_validator_quorum_da_submit_with_invalid_signatures() {
        let (_sk1, pk1) = generate_keypair();
        let (_sk2, pk2) = generate_keypair();

        let config = QuorumDAConfig {
            min_validators: 1,
            quorum_fraction: 0.5,
            ..Default::default()
        };
        let client = reqwest::Client::new();
        let collector = crate::signature_collector::SignatureCollector::new(
            vec![],
            config.clone(),
            client,
        );

        let validators = vec![
            ValidatorInfo { id: "v1".to_string(), public_key: pk1, weight: 1 },
            ValidatorInfo { id: "v2".to_string(), public_key: pk2, weight: 1 },
        ];

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let da = ValidatorQuorumDA::new(
            config,
            collector,
            validators,
            runtime.handle().clone(),
        );

        // Data to submit
        let data = b"test data for quorum";

        // Create INVALID signatures (wrong bytes)
        let signatures = vec![
            ValidatorSignature {
                validator_id: "v1".to_string(),
                signature: vec![0u8; 64], // Invalid
                timestamp: 1700000000,
            },
        ];

        // Submit should fail
        let result = da.submit_with_signatures(data, signatures);
        assert!(result.is_err(), "Should fail with invalid signatures");

        match result {
            Err(QuorumError::InsufficientQuorum(_)) => {
                // Expected
            }
            other => panic!("Expected InsufficientQuorum, got {:?}", other),
        }

        // Verify storage is still empty
        assert!(da.storage().is_empty());

        // Verify metrics
        assert_eq!(da.metrics().get_blobs_submitted(), 0);
        assert_eq!(da.metrics().get_quorum_failure(), 1);
    }

    #[test]
    fn test_validator_quorum_da_verify_quorum() {
        let (sk1, pk1) = generate_keypair();
        let (sk2, pk2) = generate_keypair();

        let config = QuorumDAConfig {
            min_validators: 1,
            quorum_fraction: 0.5,
            ..Default::default()
        };
        let client = reqwest::Client::new();
        let collector = crate::signature_collector::SignatureCollector::new(
            vec![],
            config.clone(),
            client,
        );

        let validators = vec![
            ValidatorInfo { id: "v1".to_string(), public_key: pk1, weight: 1 },
            ValidatorInfo { id: "v2".to_string(), public_key: pk2, weight: 1 },
        ];

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let da = ValidatorQuorumDA::new(
            config,
            collector,
            validators,
            runtime.handle().clone(),
        );

        // Submit valid data
        let data = b"test data for verification";
        
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash: [u8; 32] = hasher.finalize().into();

        let signatures = vec![
            ValidatorSignature {
                validator_id: "v1".to_string(),
                signature: sign_data(&sk1, &hash),
                timestamp: 1700000000,
            },
            ValidatorSignature {
                validator_id: "v2".to_string(),
                signature: sign_data(&sk2, &hash),
                timestamp: 1700000001,
            },
        ];

        let blob_ref = da.submit_with_signatures(data, signatures).unwrap();

        // Verify quorum
        let is_valid = da.verify_quorum(&blob_ref);
        assert!(is_valid.is_ok());
        assert!(is_valid.unwrap(), "Stored blob should have valid quorum");
    }

    #[test]
    fn test_validator_quorum_da_verify_quorum_not_found() {
        let config = QuorumDAConfig::default();
        let client = reqwest::Client::new();
        let collector = crate::signature_collector::SignatureCollector::new(
            vec![],
            config.clone(),
            client,
        );

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let da = ValidatorQuorumDA::new(
            config,
            collector,
            vec![],
            runtime.handle().clone(),
        );

        let blob_ref = dsdn_common::BlobRef {
            height: 0,
            commitment: [0xFF; 32], // nonexistent
            namespace: [0u8; 29],
        };

        let result = da.verify_quorum(&blob_ref);
        assert!(result.is_err());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // DALayer::post_blob Tests (14A.1A.26)
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_post_blob_empty_data_returns_invalid_blob() {
        let config = QuorumDAConfig::default();
        let client = reqwest::Client::new();
        let collector = crate::signature_collector::SignatureCollector::new(
            vec![],
            config.clone(),
            client,
        );

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let da = ValidatorQuorumDA::new(
            config,
            collector,
            vec![],
            runtime.handle().clone(),
        );

        // Empty data should return InvalidBlob
        // Use block_on from OUTSIDE async context
        let result = runtime.block_on(da.post_blob(&[]));
        assert!(result.is_err());

        match result {
            Err(dsdn_common::DAError::InvalidBlob) => {
                // Expected
            }
            other => panic!("Expected InvalidBlob, got {:?}", other),
        }
    }

    #[test]
    fn test_post_blob_quorum_not_reached() {
        let config = QuorumDAConfig {
            min_validators: 2,
            quorum_fraction: 0.67,
            signature_timeout_ms: 100,
            ..Default::default()
        };
        let client = reqwest::Client::new();

        // Create collector with unreachable endpoints
        let collector = crate::signature_collector::SignatureCollector::new(
            vec![
                crate::signature_collector::ValidatorEndpoint {
                    id: "v1".to_string(),
                    url: "http://127.0.0.1:1".to_string(), // Invalid
                    public_key: vec![1; 32],
                },
            ],
            config.clone(),
            client,
        );

        let validators = vec![
            ValidatorInfo { id: "v1".to_string(), public_key: vec![1; 32], weight: 1 },
        ];

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let da = ValidatorQuorumDA::new(
            config,
            collector,
            validators,
            runtime.handle().clone(),
        );

        // Quorum not reached should return error
        // Use block_on from OUTSIDE async context
        let result = runtime.block_on(da.post_blob(b"test data"));
        assert!(result.is_err());

        match result {
            Err(dsdn_common::DAError::Other(msg)) => {
                assert!(
                    msg.contains("quorum") || msg.contains("collection"),
                    "Error should mention quorum or collection: {}",
                    msg
                );
            }
            other => panic!("Expected Other error, got {:?}", other),
        }

        // Storage should be empty
        assert!(da.storage().is_empty());
    }

    #[test]
    fn test_quorum_blob_metadata_has_required_fields() {
        use sha2::{Sha256, Digest};
        
        let data = b"test data";
        let mut hasher = Sha256::new();
        hasher.update(data);
        let data_hash: [u8; 32] = hasher.finalize().into();

        let metadata = QuorumBlobMetadata {
            data_hash,
            valid_signatures: 2,
            stored_at: 1700000000,
            signatures: vec![],
            validator_ids: vec!["v1".to_string(), "v2".to_string()],
            pending_reconcile: true,
        };

        // Verify all required fields per spec
        assert_eq!(metadata.data_hash, data_hash);
        assert_eq!(metadata.valid_signatures, 2);
        assert!(metadata.stored_at > 0);
        assert!(metadata.pending_reconcile, "pending_reconcile should be true");
        assert_eq!(metadata.validator_ids.len(), 2);
    }

    #[test]
    fn test_quorum_blob_metadata_pending_reconcile_flag() {
        let metadata = QuorumBlobMetadata {
            data_hash: [0u8; 32],
            valid_signatures: 1,
            stored_at: 1700000000,
            signatures: vec![],
            validator_ids: vec!["v1".to_string()],
            pending_reconcile: true,
        };

        // pending_reconcile should be explicitly readable
        assert!(metadata.pending_reconcile);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // DALayer::get_blob Tests (14A.1A.27)
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_get_blob_from_local_storage_valid() {
        // Setup: Create DA with validators and valid signatures
        let (sk1, pk1) = generate_keypair();
        let (sk2, pk2) = generate_keypair();

        let config = QuorumDAConfig {
            min_validators: 1,
            quorum_fraction: 0.5,
            ..Default::default()
        };
        let client = reqwest::Client::new();
        let collector = crate::signature_collector::SignatureCollector::new(
            vec![],
            config.clone(),
            client,
        );

        let validators = vec![
            ValidatorInfo { id: "v1".to_string(), public_key: pk1.clone(), weight: 1 },
            ValidatorInfo { id: "v2".to_string(), public_key: pk2.clone(), weight: 1 },
        ];

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let da = ValidatorQuorumDA::new(
            config,
            collector,
            validators,
            runtime.handle().clone(),
        );

        // Manually store a blob with valid signatures
        let data = b"test data for get_blob";
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let data_hash: [u8; 32] = hasher.finalize().into();

        let signatures = vec![
            ValidatorSignature {
                validator_id: "v1".to_string(),
                signature: sign_data(&sk1, &data_hash),
                timestamp: 1700000000,
            },
            ValidatorSignature {
                validator_id: "v2".to_string(),
                signature: sign_data(&sk2, &data_hash),
                timestamp: 1700000001,
            },
        ];

        let blob_ref = ValidatorQuorumDA::compute_blob_ref(data, ValidatorQuorumDA::default_namespace());
        let metadata = QuorumBlobMetadata {
            data_hash,
            valid_signatures: 2,
            stored_at: 1700000000,
            signatures,
            validator_ids: vec!["v1".to_string(), "v2".to_string()],
            pending_reconcile: true,
        };

        // Store directly
        da.storage().store(&blob_ref, data.to_vec(), metadata).unwrap();

        // Test get_blob
        let result = runtime.block_on(da.get_blob(&blob_ref));
        assert!(result.is_ok(), "get_blob should succeed for valid blob");

        let retrieved_data = result.unwrap();
        assert_eq!(retrieved_data, data.to_vec());

        // Check metrics
        assert_eq!(da.metrics().get_local_get_hits(), 1);
        assert_eq!(da.metrics().get_signature_rechecks(), 1);
    }

    #[test]
    fn test_get_blob_not_found() {
        let config = QuorumDAConfig::default();
        let client = reqwest::Client::new();
        let collector = crate::signature_collector::SignatureCollector::new(
            vec![],
            config.clone(),
            client,
        );

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let da = ValidatorQuorumDA::new(
            config,
            collector,
            vec![],
            runtime.handle().clone(),
        );

        // Try to get non-existent blob
        let blob_ref = dsdn_common::BlobRef {
            height: 0,
            commitment: [0xFF; 32],
            namespace: [0u8; 29],
        };

        let result = runtime.block_on(da.get_blob(&blob_ref));
        assert!(result.is_err(), "get_blob should fail for non-existent blob");

        match result {
            Err(dsdn_common::DAError::BlobNotFound(_)) => {
                // Expected
            }
            other => panic!("Expected BlobNotFound, got {:?}", other),
        }

        // Check metrics
        assert_eq!(da.metrics().get_local_get_miss(), 1);
    }

    #[test]
    fn test_get_blob_signature_verification_failed() {
        // Setup: Create DA with validators but store blob with INVALID signatures
        let (_sk1, pk1) = generate_keypair();
        let (_sk2, pk2) = generate_keypair();

        let config = QuorumDAConfig {
            min_validators: 1,
            quorum_fraction: 0.5,
            ..Default::default()
        };
        let client = reqwest::Client::new();
        let collector = crate::signature_collector::SignatureCollector::new(
            vec![],
            config.clone(),
            client,
        );

        let validators = vec![
            ValidatorInfo { id: "v1".to_string(), public_key: pk1, weight: 1 },
            ValidatorInfo { id: "v2".to_string(), public_key: pk2, weight: 1 },
        ];

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let da = ValidatorQuorumDA::new(
            config,
            collector,
            validators,
            runtime.handle().clone(),
        );

        // Store blob with INVALID signatures (all zeros)
        let data = b"test data with invalid sigs";
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let data_hash: [u8; 32] = hasher.finalize().into();

        let invalid_signatures = vec![
            ValidatorSignature {
                validator_id: "v1".to_string(),
                signature: vec![0u8; 64], // Invalid signature
                timestamp: 1700000000,
            },
        ];

        let blob_ref = ValidatorQuorumDA::compute_blob_ref(data, ValidatorQuorumDA::default_namespace());
        let metadata = QuorumBlobMetadata {
            data_hash,
            valid_signatures: 1, // Claimed 1, but actually 0 valid
            stored_at: 1700000000,
            signatures: invalid_signatures,
            validator_ids: vec!["v1".to_string()],
            pending_reconcile: true,
        };

        // Store directly
        da.storage().store(&blob_ref, data.to_vec(), metadata).unwrap();

        // Test get_blob - should fail due to signature verification
        let result = runtime.block_on(da.get_blob(&blob_ref));
        assert!(result.is_err(), "get_blob should fail with invalid signatures");

        match result {
            Err(dsdn_common::DAError::Other(msg)) => {
                assert!(
                    msg.contains("quorum verification failed"),
                    "Error should mention quorum verification: {}",
                    msg
                );
            }
            other => panic!("Expected Other error with verification message, got {:?}", other),
        }

        // Check metrics
        assert_eq!(da.metrics().get_local_get_hits(), 1);
        assert_eq!(da.metrics().get_verification_failures(), 1);
    }

    #[test]
    fn test_get_blob_data_integrity_check() {
        // Setup: Create DA with validators and valid signatures but corrupted data
        let (sk1, pk1) = generate_keypair();

        let config = QuorumDAConfig {
            min_validators: 1,
            quorum_fraction: 0.5,
            ..Default::default()
        };
        let client = reqwest::Client::new();
        let collector = crate::signature_collector::SignatureCollector::new(
            vec![],
            config.clone(),
            client,
        );

        let validators = vec![
            ValidatorInfo { id: "v1".to_string(), public_key: pk1.clone(), weight: 1 },
        ];

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let da = ValidatorQuorumDA::new(
            config,
            collector,
            validators,
            runtime.handle().clone(),
        );

        // Original data and hash
        let original_data = b"original data";
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(original_data);
        let data_hash: [u8; 32] = hasher.finalize().into();

        // Valid signature for original data
        let signatures = vec![
            ValidatorSignature {
                validator_id: "v1".to_string(),
                signature: sign_data(&sk1, &data_hash),
                timestamp: 1700000000,
            },
        ];

        let blob_ref = ValidatorQuorumDA::compute_blob_ref(original_data, ValidatorQuorumDA::default_namespace());
        let metadata = QuorumBlobMetadata {
            data_hash,
            valid_signatures: 1,
            stored_at: 1700000000,
            signatures,
            validator_ids: vec!["v1".to_string()],
            pending_reconcile: true,
        };

        // Store CORRUPTED data (different from what was hashed)
        let corrupted_data = b"corrupted data!!";
        da.storage().store(&blob_ref, corrupted_data.to_vec(), metadata).unwrap();

        // Test get_blob - should fail due to hash mismatch
        let result = runtime.block_on(da.get_blob(&blob_ref));
        assert!(result.is_err(), "get_blob should fail with corrupted data");

        match result {
            Err(dsdn_common::DAError::Other(msg)) => {
                assert!(
                    msg.contains("hash mismatch") || msg.contains("integrity"),
                    "Error should mention hash/integrity: {}",
                    msg
                );
            }
            other => panic!("Expected Other error with integrity message, got {:?}", other),
        }
    }

    #[test]
    fn test_get_blob_metrics_update() {
        let config = QuorumDAConfig::default();
        let client = reqwest::Client::new();
        let collector = crate::signature_collector::SignatureCollector::new(
            vec![],
            config.clone(),
            client,
        );

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let da = ValidatorQuorumDA::new(
            config,
            collector,
            vec![],
            runtime.handle().clone(),
        );

        // Initial metrics should be 0
        assert_eq!(da.metrics().get_local_get_hits(), 0);
        assert_eq!(da.metrics().get_local_get_miss(), 0);
        assert_eq!(da.metrics().get_signature_rechecks(), 0);

        // Try to get non-existent blob
        let blob_ref = dsdn_common::BlobRef {
            height: 0,
            commitment: [0xFF; 32],
            namespace: [0u8; 29],
        };
        let _ = runtime.block_on(da.get_blob(&blob_ref));

        // Check miss was recorded
        assert_eq!(da.metrics().get_local_get_miss(), 1);
        assert_eq!(da.metrics().get_local_get_hits(), 0);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // DALayer::health_check Tests (14A.1A.28)
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_health_check_unavailable_no_endpoints() {
        // No validator endpoints configured
        let config = QuorumDAConfig {
            validator_endpoints: vec![],
            ..Default::default()
        };
        let client = reqwest::Client::new();
        let collector = crate::signature_collector::SignatureCollector::new(
            vec![],
            config.clone(),
            client,
        );

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let da = ValidatorQuorumDA::new(
            config,
            collector,
            vec![],
            runtime.handle().clone(),
        );

        // Health check should return Unavailable
        let result = runtime.block_on(da.health_check());
        assert!(result.is_ok());
        
        match result.unwrap() {
            dsdn_common::DAHealthStatus::Unavailable => {
                // Expected
            }
            other => panic!("Expected Unavailable, got {:?}", other),
        }

        // Check metrics
        assert_eq!(da.metrics().get_health_checks_total(), 1);
        assert_eq!(da.metrics().get_last_health_status(), 0); // Unavailable
    }

    #[test]
    fn test_health_check_unavailable_all_unreachable() {
        // Configure with unreachable endpoints
        let config = QuorumDAConfig {
            validator_endpoints: vec![
                "http://127.0.0.1:1".to_string(), // Invalid port
                "http://127.0.0.1:2".to_string(), // Invalid port
            ],
            signature_timeout_ms: 100, // Short timeout
            quorum_fraction: 0.67,
            ..Default::default()
        };
        let client = reqwest::Client::new();
        let collector = crate::signature_collector::SignatureCollector::new(
            vec![],
            config.clone(),
            client,
        );

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let da = ValidatorQuorumDA::new(
            config,
            collector,
            vec![],
            runtime.handle().clone(),
        );

        // Health check - all endpoints unreachable = Unavailable
        let result = runtime.block_on(da.health_check());
        assert!(result.is_ok());

        match result.unwrap() {
            dsdn_common::DAHealthStatus::Unavailable => {
                // Expected - all validators unreachable
            }
            other => panic!("Expected Unavailable, got {:?}", other),
        }

        // Check metrics
        assert_eq!(da.metrics().get_health_checks_total(), 1);
        assert_eq!(da.metrics().get_last_health_status(), 0); // Unavailable
    }

    #[test]
    fn test_health_check_metrics_increment() {
        let config = QuorumDAConfig {
            validator_endpoints: vec![],
            ..Default::default()
        };
        let client = reqwest::Client::new();
        let collector = crate::signature_collector::SignatureCollector::new(
            vec![],
            config.clone(),
            client,
        );

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let da = ValidatorQuorumDA::new(
            config,
            collector,
            vec![],
            runtime.handle().clone(),
        );

        // Initial metrics
        assert_eq!(da.metrics().get_health_checks_total(), 0);

        // First health check
        let _ = runtime.block_on(da.health_check());
        assert_eq!(da.metrics().get_health_checks_total(), 1);

        // Second health check
        let _ = runtime.block_on(da.health_check());
        assert_eq!(da.metrics().get_health_checks_total(), 2);

        // Third health check
        let _ = runtime.block_on(da.health_check());
        assert_eq!(da.metrics().get_health_checks_total(), 3);
    }

    #[test]
    fn test_health_check_status_mapping() {
        // Test status codes: 0=Unavailable, 1=Degraded, 2=Healthy
        let metrics = QuorumMetrics::new();

        // Test Unavailable (0)
        metrics.set_last_health_status(0);
        assert_eq!(metrics.get_last_health_status(), 0);

        // Test Degraded (1)
        metrics.set_last_health_status(1);
        assert_eq!(metrics.get_last_health_status(), 1);

        // Test Healthy (2)
        metrics.set_last_health_status(2);
        assert_eq!(metrics.get_last_health_status(), 2);
    }

    #[test]
    fn test_health_check_threshold_calculation() {
        // Verify threshold calculation used in health check
        let config = QuorumDAConfig {
            quorum_fraction: 0.67,
            min_validators: 1,
            ..Default::default()
        };

        // 3 validators: ceil(3 * 0.67) = ceil(2.01) = 3
        let threshold_3 = config.calculate_quorum_threshold(3);
        assert_eq!(threshold_3, 3);

        // 5 validators: ceil(5 * 0.67) = ceil(3.35) = 4
        let threshold_5 = config.calculate_quorum_threshold(5);
        assert_eq!(threshold_5, 4);

        // 10 validators: ceil(10 * 0.67) = ceil(6.7) = 7
        let threshold_10 = config.calculate_quorum_threshold(10);
        assert_eq!(threshold_10, 7);
    }
}