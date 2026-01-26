//! # DSDN TSS Crate
//!
//! Crate ini menyediakan foundational types dan cryptographic primitives untuk
//! Threshold Signature Scheme (TSS) dalam sistem DSDN.
//!
//! ## Peran Crate
//!
//! `dsdn-tss` adalah foundation crate yang menyediakan:
//! - Identifier types untuk DKG dan signing sessions
//! - Cryptographic primitive types (akan ditambahkan di tahap selanjutnya)
//! - Error types untuk operasi TSS
//!
//! Crate ini TIDAK mengimplementasikan protocol DKG atau signing.
//! Protocol implementation berada di layer yang lebih tinggi.
//!
//! ## Arsitektur TSS di DSDN
//!
//! TSS digunakan untuk multi-coordinator system dimana:
//! - Committee coordinators menjalankan DKG untuk generate shared key
//! - Threshold signing (t-of-n) digunakan untuk sign receipts
//! - Tidak ada single coordinator yang memiliki full signing key
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    TSS Component Hierarchy                       │
//! └─────────────────────────────────────────────────────────────────┘
//!
//!                        ┌─────────────────┐
//!                        │   dsdn-tss      │  ← Foundation (crate ini)
//!                        │   (types)       │
//!                        └────────┬────────┘
//!                                 │
//!              ┌──────────────────┼──────────────────┐
//!              │                  │                  │
//!              ▼                  ▼                  ▼
//!      ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
//!      │  DKG Types   │  │ Signing Types│  │ Verification │
//!      │  (tahap 4-6) │  │ (tahap 7-9)  │  │ (tahap 10)   │
//!      └──────────────┘  └──────────────┘  └──────────────┘
//! ```
//!
//! ## Types dalam Crate Ini
//!
//! ### Identifier Types (tahap 14A.2B.1.1)
//!
//! | Type | Deskripsi | Ukuran |
//! |------|-----------|--------|
//! | `SessionId` | Identifier untuk DKG/signing session | 32 bytes |
//! | `ParticipantId` | Identifier untuk DKG participant | 32 bytes |
//! | `SignerId` | Identifier untuk threshold signer | 32 bytes |
//!
//! Semua identifier types memiliki:
//! - Random generation via `new()`
//! - Deterministic construction via `from_bytes()`
//! - Hex encoding via `to_hex()`
//! - Serialization via serde
//!
//! ### Error Types (tahap 14A.2B.1.2)
//!
//! | Type | Deskripsi |
//! |------|-----------|
//! | `DKGError` | Error dalam Distributed Key Generation protocol |
//! | `SigningError` | Error dalam threshold signing protocol |
//! | `TSSError` | Wrapper untuk semua TSS errors |
//!
//! ## Keamanan
//!
//! - Random identifier generation menggunakan cryptographically secure RNG
//! - Secret data akan menggunakan `zeroize` untuk secure memory cleanup
//! - Tidak ada logging atau display secret values
//!
//! ## Thread Safety
//!
//! Semua types dalam crate ini adalah `Send` dan `Sync` secara struktural
//! karena hanya berisi data immutable setelah construction.
//!
//! ## Contoh Penggunaan
//!
//! ```rust
//! use dsdn_tss::{SessionId, ParticipantId, SignerId};
//!
//! // Buat identifier baru
//! let session_id = SessionId::new();
//! let participant_id = ParticipantId::new();
//! let signer_id = SignerId::new();
//!
//! // Logging dengan hex representation
//! println!("Session: {}", session_id.to_hex());
//!
//! // Construct dari known bytes
//! let known_bytes = [0x42u8; 32];
//! let session = SessionId::from_bytes(known_bytes);
//! assert_eq!(session.as_bytes(), &known_bytes);
//! ```

// ════════════════════════════════════════════════════════════════════════════════
// MODULE DECLARATIONS
// ════════════════════════════════════════════════════════════════════════════════

/// Basic identifier types untuk TSS operations.
pub mod types;

/// Error types untuk DKG dan signing operations.
pub mod error;

/// Cryptographic primitive types untuk FROST TSS.
pub mod primitives;

/// DKG (Distributed Key Generation) types dan state machine.
pub mod dkg;

// ════════════════════════════════════════════════════════════════════════════════
// PUBLIC API EXPORTS
// ════════════════════════════════════════════════════════════════════════════════

// Identifier types (14A.2B.1.1)
pub use types::{ParticipantId, SessionId, SignerId, IDENTIFIER_SIZE};

// Error types (14A.2B.1.2)
pub use error::{DKGError, SigningError, TSSError};

// Cryptographic primitives (14A.2B.1.3)
pub use primitives::{
    EncryptionKey, FrostSignature, FrostSignatureShare, GroupPublicKey, ParticipantPublicKey,
    SecretShare, SigningCommitment, PUBLIC_KEY_SIZE, SCALAR_SIZE, SIGNATURE_SIZE,
};

// DKG types (14A.2B.1.4 & 14A.2B.1.5)
pub use dkg::{DKGSession, DKGSessionConfig, DKGState, Round1Package, Round2Package};

// ════════════════════════════════════════════════════════════════════════════════
// CRATE-LEVEL CONSTANTS
// ════════════════════════════════════════════════════════════════════════════════

/// Version string untuk crate ini.
pub const TSS_VERSION: &str = "0.1.0";

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_re_exports_available() {
        // Pastikan semua types dapat diakses via crate root
        let _session = SessionId::new();
        let _participant = ParticipantId::new();
        let _signer = SignerId::new();
    }

    #[test]
    fn test_identifier_size_constant() {
        assert_eq!(IDENTIFIER_SIZE, 32);
    }

    #[test]
    fn test_version_string() {
        assert!(!TSS_VERSION.is_empty());
    }

    #[test]
    fn test_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        
        assert_send_sync::<SessionId>();
        assert_send_sync::<ParticipantId>();
        assert_send_sync::<SignerId>();
    }

    #[test]
    fn test_error_re_exports_available() {
        // Pastikan error types dapat diakses via crate root
        let _dkg_err = DKGError::InvalidThreshold {
            threshold: 5,
            total: 3,
        };
        let _signing_err = SigningError::MessageMismatch;
        let _tss_err = TSSError::Crypto("test".to_string());
    }

    #[test]
    fn test_error_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        
        assert_send_sync::<DKGError>();
        assert_send_sync::<SigningError>();
        assert_send_sync::<TSSError>();
    }

    #[test]
    fn test_primitives_re_exports_available() {
        // Pastikan primitive types dapat diakses via crate root
        let _gpk = GroupPublicKey::from_bytes([0x02; 32]);
        let _ppk = ParticipantPublicKey::from_bytes([0x02; 32]);
        let _ss = SecretShare::from_bytes([0x42; 32]);
        let _sig = FrostSignature::from_bytes([0x02; 64]);
        let _share = FrostSignatureShare::from_bytes([0x42; 32]);
        let _commit = SigningCommitment::from_parts([0xAA; 32], [0xBB; 32]);
        let _ek = EncryptionKey::from_bytes([0x42; 32]);
    }

    #[test]
    fn test_primitives_constants_available() {
        assert_eq!(PUBLIC_KEY_SIZE, 32);
        assert_eq!(SCALAR_SIZE, 32);
        assert_eq!(SIGNATURE_SIZE, 64);
    }

    #[test]
    fn test_primitives_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        
        assert_send_sync::<GroupPublicKey>();
        assert_send_sync::<ParticipantPublicKey>();
        assert_send_sync::<SecretShare>();
        assert_send_sync::<FrostSignature>();
        assert_send_sync::<FrostSignatureShare>();
        assert_send_sync::<SigningCommitment>();
        assert_send_sync::<EncryptionKey>();
    }

    #[test]
    fn test_dkg_re_exports_available() {
        // Pastikan DKG types dapat diakses via crate root
        let _state = DKGState::Initialized;
        let participant = ParticipantId::new();
        let _package1 = Round1Package::new(participant.clone(), [0xAA; 32], [0xBB; 64]);
        let session = SessionId::new();
        let _package2 = Round2Package::new(session, participant.clone(), participant, vec![0xCC; 32]);
    }

    #[test]
    fn test_dkg_session_re_export_available() {
        // Pastikan DKGSession dapat diakses via crate root
        let session_id = SessionId::new();
        let participants = vec![
            ParticipantId::new(),
            ParticipantId::new(),
            ParticipantId::new(),
        ];
        let session = DKGSession::new(session_id, participants, 2);
        assert!(session.is_ok());
    }

    #[test]
    fn test_dkg_session_config_re_export_available() {
        // Pastikan DKGSessionConfig dapat diakses via crate root
        let config = DKGSessionConfig::default();
        assert_eq!(config.timeout_secs(), 300);
    }

    #[test]
    fn test_dkg_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        
        assert_send_sync::<DKGState>();
        assert_send_sync::<Round1Package>();
        assert_send_sync::<Round2Package>();
        assert_send_sync::<DKGSession>();
        assert_send_sync::<DKGSessionConfig>();
    }
}