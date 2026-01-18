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
}