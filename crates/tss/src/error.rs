//! # TSS Error Types
//!
//! Module ini menyediakan error types untuk operasi TSS:
//! - `DKGError`: Error dalam Distributed Key Generation protocol
//! - `SigningError`: Error dalam threshold signing protocol
//! - `TSSError`: Wrapper untuk semua TSS errors
//!
//! ## Karakteristik
//!
//! Semua error types:
//! - Implement `std::error::Error` dan `Display`
//! - Bersifat `Send + Sync` untuk thread safety
//! - Menyediakan pesan error yang informatif tanpa membocorkan data sensitif
//! - Dapat di-propagate lintas crate boundaries
//!
//! ## Error Hierarchy
//!
//! ```text
//! TSSError
//! ├── DKG(DKGError)      ← Error dari DKG protocol
//! ├── Signing(SigningError) ← Error dari signing protocol
//! ├── Serialization(String) ← Error serialization/deserialization
//! └── Crypto(String)     ← Error cryptographic operations
//! ```
//!
//! ## Penggunaan
//!
//! ```rust
//! use dsdn_tss::{DKGError, SigningError, TSSError, ParticipantId, SignerId};
//!
//! fn example_dkg_error() -> Result<(), TSSError> {
//!     let participant = ParticipantId::new();
//!     Err(DKGError::InvalidCommitment { participant })?
//! }
//!
//! fn example_signing_error() -> Result<(), TSSError> {
//!     let signer = SignerId::new();
//!     Err(SigningError::SignerNotInCommittee { signer })?
//! }
//! ```

use std::error::Error;
use std::fmt;

use crate::types::{ParticipantId, SessionId, SignerId};

// ════════════════════════════════════════════════════════════════════════════════
// DKG ERROR
// ════════════════════════════════════════════════════════════════════════════════

/// Error yang terjadi dalam Distributed Key Generation (DKG) protocol.
///
/// DKG adalah proses dimana multiple participants secara bersama-sama
/// menghasilkan shared secret key tanpa ada satu pihak yang mengetahui
/// full secret.
#[derive(Debug, Clone)]
pub enum DKGError {
    /// Round 1 package dari participant tidak valid.
    ///
    /// Terjadi ketika commitment atau proof dalam Round1Package
    /// gagal verifikasi.
    InvalidRound1Package {
        /// Participant yang mengirim package invalid.
        participant: ParticipantId,
        /// Alasan kegagalan validasi.
        reason: String,
    },

    /// Round 2 package tidak valid.
    ///
    /// Terjadi ketika encrypted share tidak dapat didekripsi
    /// atau share tidak konsisten dengan commitment.
    InvalidRound2Package {
        /// Participant pengirim package.
        from: ParticipantId,
        /// Participant penerima package.
        to: ParticipantId,
        /// Alasan kegagalan validasi.
        reason: String,
    },

    /// Jumlah participant tidak mencukupi untuk threshold yang diminta.
    InsufficientParticipants {
        /// Jumlah minimum participant yang diharapkan.
        expected: u8,
        /// Jumlah participant yang tersedia.
        got: u8,
    },

    /// Threshold tidak valid untuk jumlah participant.
    ///
    /// Threshold harus memenuhi: 2 <= threshold <= total_participants
    InvalidThreshold {
        /// Threshold yang diminta.
        threshold: u8,
        /// Total participant.
        total: u8,
    },

    /// Participant dengan ID yang sama sudah terdaftar.
    DuplicateParticipant {
        /// Participant ID yang duplikat.
        participant: ParticipantId,
    },

    /// Commitment dari participant tidak valid atau tidak konsisten.
    InvalidCommitment {
        /// Participant dengan commitment invalid.
        participant: ParticipantId,
    },

    /// Proof of knowledge dari participant tidak valid.
    InvalidProof {
        /// Participant dengan proof invalid.
        participant: ParticipantId,
    },

    /// Verifikasi share gagal - share tidak konsisten dengan commitment.
    ShareVerificationFailed {
        /// Participant yang share-nya gagal verifikasi.
        participant: ParticipantId,
    },

    /// Session dengan ID yang diberikan tidak ditemukan.
    SessionNotFound {
        /// Session ID yang tidak ditemukan.
        session_id: SessionId,
    },

    /// State machine dalam state yang tidak sesuai untuk operasi.
    InvalidState {
        /// State yang diharapkan.
        expected: String,
        /// State aktual.
        got: String,
    },
}

impl fmt::Display for DKGError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DKGError::InvalidRound1Package { participant, reason } => {
                write!(
                    f,
                    "DKG: invalid round 1 package from participant {}: {}",
                    participant.to_hex(),
                    reason
                )
            }
            DKGError::InvalidRound2Package { from, to, reason } => {
                write!(
                    f,
                    "DKG: invalid round 2 package from {} to {}: {}",
                    from.to_hex(),
                    to.to_hex(),
                    reason
                )
            }
            DKGError::InsufficientParticipants { expected, got } => {
                write!(
                    f,
                    "DKG: insufficient participants, expected at least {}, got {}",
                    expected, got
                )
            }
            DKGError::InvalidThreshold { threshold, total } => {
                write!(
                    f,
                    "DKG: invalid threshold {}, must be between 2 and {} (total participants)",
                    threshold, total
                )
            }
            DKGError::DuplicateParticipant { participant } => {
                write!(
                    f,
                    "DKG: duplicate participant {}",
                    participant.to_hex()
                )
            }
            DKGError::InvalidCommitment { participant } => {
                write!(
                    f,
                    "DKG: invalid commitment from participant {}",
                    participant.to_hex()
                )
            }
            DKGError::InvalidProof { participant } => {
                write!(
                    f,
                    "DKG: invalid proof from participant {}",
                    participant.to_hex()
                )
            }
            DKGError::ShareVerificationFailed { participant } => {
                write!(
                    f,
                    "DKG: share verification failed for participant {}",
                    participant.to_hex()
                )
            }
            DKGError::SessionNotFound { session_id } => {
                write!(
                    f,
                    "DKG: session {} not found",
                    session_id.to_hex()
                )
            }
            DKGError::InvalidState { expected, got } => {
                write!(
                    f,
                    "DKG: invalid state, expected '{}', got '{}'",
                    expected, got
                )
            }
        }
    }
}

impl Error for DKGError {}

// ════════════════════════════════════════════════════════════════════════════════
// SIGNING ERROR
// ════════════════════════════════════════════════════════════════════════════════

/// Error yang terjadi dalam threshold signing protocol.
///
/// Threshold signing memungkinkan t-of-n signers untuk menghasilkan
/// valid signature tanpa mengungkap individual secret keys.
#[derive(Debug, Clone)]
pub enum SigningError {
    /// Signing commitment dari signer tidak valid.
    InvalidCommitment {
        /// Signer yang commitment-nya invalid.
        signer: SignerId,
        /// Alasan kegagalan validasi.
        reason: String,
    },

    /// Partial signature dari signer tidak valid.
    InvalidPartialSignature {
        /// Signer yang partial signature-nya invalid.
        signer: SignerId,
        /// Alasan kegagalan validasi.
        reason: String,
    },

    /// Jumlah signature tidak mencukupi threshold.
    InsufficientSignatures {
        /// Jumlah minimum signature yang diharapkan (threshold).
        expected: u8,
        /// Jumlah signature yang diterima.
        got: usize,
    },

    /// Aggregation partial signatures gagal.
    AggregationFailed {
        /// Alasan kegagalan aggregation.
        reason: String,
    },

    /// Signer tidak terdaftar dalam committee.
    SignerNotInCommittee {
        /// Signer yang tidak terdaftar.
        signer: SignerId,
    },

    /// Signer dengan ID yang sama sudah submit signature.
    DuplicateSigner {
        /// Signer ID yang duplikat.
        signer: SignerId,
    },

    /// Message yang di-sign tidak cocok dengan yang diharapkan.
    MessageMismatch,

    /// Signing session sudah expired.
    SessionExpired {
        /// Session ID yang expired.
        session_id: SessionId,
    },
}

impl fmt::Display for SigningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SigningError::InvalidCommitment { signer, reason } => {
                write!(
                    f,
                    "Signing: invalid commitment from signer {}: {}",
                    signer.to_hex(),
                    reason
                )
            }
            SigningError::InvalidPartialSignature { signer, reason } => {
                write!(
                    f,
                    "Signing: invalid partial signature from signer {}: {}",
                    signer.to_hex(),
                    reason
                )
            }
            SigningError::InsufficientSignatures { expected, got } => {
                write!(
                    f,
                    "Signing: insufficient signatures, expected {}, got {}",
                    expected, got
                )
            }
            SigningError::AggregationFailed { reason } => {
                write!(f, "Signing: aggregation failed: {}", reason)
            }
            SigningError::SignerNotInCommittee { signer } => {
                write!(
                    f,
                    "Signing: signer {} not in committee",
                    signer.to_hex()
                )
            }
            SigningError::DuplicateSigner { signer } => {
                write!(
                    f,
                    "Signing: duplicate signer {}",
                    signer.to_hex()
                )
            }
            SigningError::MessageMismatch => {
                write!(f, "Signing: message mismatch")
            }
            SigningError::SessionExpired { session_id } => {
                write!(
                    f,
                    "Signing: session {} expired",
                    session_id.to_hex()
                )
            }
        }
    }
}

impl Error for SigningError {}

// ════════════════════════════════════════════════════════════════════════════════
// TSS ERROR (WRAPPER)
// ════════════════════════════════════════════════════════════════════════════════

/// Wrapper error type untuk semua TSS operations.
///
/// `TSSError` mengenkapsulasi semua error yang dapat terjadi
/// dalam operasi TSS, termasuk DKG, signing, serialization,
/// dan cryptographic errors.
#[derive(Debug, Clone)]
pub enum TSSError {
    /// Error dari DKG protocol.
    DKG(DKGError),

    /// Error dari signing protocol.
    Signing(SigningError),

    /// Error serialization atau deserialization.
    Serialization(String),

    /// Error dari cryptographic operations.
    Crypto(String),
}

impl fmt::Display for TSSError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TSSError::DKG(e) => write!(f, "{}", e),
            TSSError::Signing(e) => write!(f, "{}", e),
            TSSError::Serialization(msg) => write!(f, "TSS serialization error: {}", msg),
            TSSError::Crypto(msg) => write!(f, "TSS crypto error: {}", msg),
        }
    }
}

impl Error for TSSError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            TSSError::DKG(e) => Some(e),
            TSSError::Signing(e) => Some(e),
            TSSError::Serialization(_) => None,
            TSSError::Crypto(_) => None,
        }
    }
}

impl From<DKGError> for TSSError {
    fn from(e: DKGError) -> Self {
        TSSError::DKG(e)
    }
}

impl From<SigningError> for TSSError {
    fn from(e: SigningError) -> Self {
        TSSError::Signing(e)
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ────────────────────────────────────────────────────────────────────────────
    // DKG ERROR TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_dkg_error_invalid_round1_package_display() {
        let participant = ParticipantId::from_bytes([0xAB; 32]);
        let err = DKGError::InvalidRound1Package {
            participant,
            reason: "commitment hash mismatch".to_string(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("DKG"));
        assert!(msg.contains("round 1"));
        assert!(msg.contains("commitment hash mismatch"));
    }

    #[test]
    fn test_dkg_error_invalid_round2_package_display() {
        let from = ParticipantId::from_bytes([0x11; 32]);
        let to = ParticipantId::from_bytes([0x22; 32]);
        let err = DKGError::InvalidRound2Package {
            from,
            to,
            reason: "decryption failed".to_string(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("DKG"));
        assert!(msg.contains("round 2"));
        assert!(msg.contains("decryption failed"));
    }

    #[test]
    fn test_dkg_error_insufficient_participants_display() {
        let err = DKGError::InsufficientParticipants {
            expected: 4,
            got: 2,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("insufficient participants"));
        assert!(msg.contains("4"));
        assert!(msg.contains("2"));
    }

    #[test]
    fn test_dkg_error_invalid_threshold_display() {
        let err = DKGError::InvalidThreshold {
            threshold: 5,
            total: 3,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("invalid threshold"));
        assert!(msg.contains("5"));
        assert!(msg.contains("3"));
    }

    #[test]
    fn test_dkg_error_duplicate_participant_display() {
        let participant = ParticipantId::from_bytes([0xCC; 32]);
        let err = DKGError::DuplicateParticipant { participant };
        let msg = format!("{}", err);
        assert!(msg.contains("duplicate participant"));
    }

    #[test]
    fn test_dkg_error_invalid_commitment_display() {
        let participant = ParticipantId::from_bytes([0xDD; 32]);
        let err = DKGError::InvalidCommitment { participant };
        let msg = format!("{}", err);
        assert!(msg.contains("invalid commitment"));
    }

    #[test]
    fn test_dkg_error_invalid_proof_display() {
        let participant = ParticipantId::from_bytes([0xEE; 32]);
        let err = DKGError::InvalidProof { participant };
        let msg = format!("{}", err);
        assert!(msg.contains("invalid proof"));
    }

    #[test]
    fn test_dkg_error_share_verification_failed_display() {
        let participant = ParticipantId::from_bytes([0xFF; 32]);
        let err = DKGError::ShareVerificationFailed { participant };
        let msg = format!("{}", err);
        assert!(msg.contains("share verification failed"));
    }

    #[test]
    fn test_dkg_error_session_not_found_display() {
        let session_id = SessionId::from_bytes([0x99; 32]);
        let err = DKGError::SessionNotFound { session_id };
        let msg = format!("{}", err);
        assert!(msg.contains("session"));
        assert!(msg.contains("not found"));
    }

    #[test]
    fn test_dkg_error_invalid_state_display() {
        let err = DKGError::InvalidState {
            expected: "Round1Complete".to_string(),
            got: "Initialized".to_string(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("invalid state"));
        assert!(msg.contains("Round1Complete"));
        assert!(msg.contains("Initialized"));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SIGNING ERROR TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_signing_error_invalid_commitment_display() {
        let signer = SignerId::from_bytes([0xAA; 32]);
        let err = SigningError::InvalidCommitment {
            signer,
            reason: "wrong format".to_string(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("Signing"));
        assert!(msg.contains("invalid commitment"));
        assert!(msg.contains("wrong format"));
    }

    #[test]
    fn test_signing_error_invalid_partial_signature_display() {
        let signer = SignerId::from_bytes([0xBB; 32]);
        let err = SigningError::InvalidPartialSignature {
            signer,
            reason: "verification failed".to_string(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("invalid partial signature"));
        assert!(msg.contains("verification failed"));
    }

    #[test]
    fn test_signing_error_insufficient_signatures_display() {
        let err = SigningError::InsufficientSignatures {
            expected: 3,
            got: 2,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("insufficient signatures"));
        assert!(msg.contains("3"));
        assert!(msg.contains("2"));
    }

    #[test]
    fn test_signing_error_aggregation_failed_display() {
        let err = SigningError::AggregationFailed {
            reason: "invalid group element".to_string(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("aggregation failed"));
        assert!(msg.contains("invalid group element"));
    }

    #[test]
    fn test_signing_error_signer_not_in_committee_display() {
        let signer = SignerId::from_bytes([0xCC; 32]);
        let err = SigningError::SignerNotInCommittee { signer };
        let msg = format!("{}", err);
        assert!(msg.contains("not in committee"));
    }

    #[test]
    fn test_signing_error_duplicate_signer_display() {
        let signer = SignerId::from_bytes([0xDD; 32]);
        let err = SigningError::DuplicateSigner { signer };
        let msg = format!("{}", err);
        assert!(msg.contains("duplicate signer"));
    }

    #[test]
    fn test_signing_error_message_mismatch_display() {
        let err = SigningError::MessageMismatch;
        let msg = format!("{}", err);
        assert!(msg.contains("message mismatch"));
    }

    #[test]
    fn test_signing_error_session_expired_display() {
        let session_id = SessionId::from_bytes([0xEE; 32]);
        let err = SigningError::SessionExpired { session_id };
        let msg = format!("{}", err);
        assert!(msg.contains("session"));
        assert!(msg.contains("expired"));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TSS ERROR TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_tss_error_from_dkg_error() {
        let dkg_err = DKGError::InsufficientParticipants {
            expected: 4,
            got: 2,
        };
        let tss_err: TSSError = dkg_err.into();
        
        match tss_err {
            TSSError::DKG(_) => {}
            _ => panic!("expected TSSError::DKG"),
        }
    }

    #[test]
    fn test_tss_error_from_signing_error() {
        let signing_err = SigningError::MessageMismatch;
        let tss_err: TSSError = signing_err.into();
        
        match tss_err {
            TSSError::Signing(_) => {}
            _ => panic!("expected TSSError::Signing"),
        }
    }

    #[test]
    fn test_tss_error_serialization_display() {
        let err = TSSError::Serialization("invalid encoding".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("serialization"));
        assert!(msg.contains("invalid encoding"));
    }

    #[test]
    fn test_tss_error_crypto_display() {
        let err = TSSError::Crypto("invalid curve point".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("crypto"));
        assert!(msg.contains("invalid curve point"));
    }

    #[test]
    fn test_tss_error_dkg_display_delegates() {
        let dkg_err = DKGError::InvalidThreshold {
            threshold: 10,
            total: 5,
        };
        let tss_err = TSSError::DKG(dkg_err);
        let msg = format!("{}", tss_err);
        assert!(msg.contains("DKG"));
        assert!(msg.contains("invalid threshold"));
    }

    #[test]
    fn test_tss_error_signing_display_delegates() {
        let signing_err = SigningError::MessageMismatch;
        let tss_err = TSSError::Signing(signing_err);
        let msg = format!("{}", tss_err);
        assert!(msg.contains("Signing"));
        assert!(msg.contains("message mismatch"));
    }

    #[test]
    fn test_tss_error_source_dkg() {
        let dkg_err = DKGError::InvalidThreshold {
            threshold: 5,
            total: 3,
        };
        let tss_err = TSSError::DKG(dkg_err);
        assert!(tss_err.source().is_some());
    }

    #[test]
    fn test_tss_error_source_signing() {
        let signing_err = SigningError::MessageMismatch;
        let tss_err = TSSError::Signing(signing_err);
        assert!(tss_err.source().is_some());
    }

    #[test]
    fn test_tss_error_source_serialization() {
        let tss_err = TSSError::Serialization("test".to_string());
        assert!(tss_err.source().is_none());
    }

    #[test]
    fn test_tss_error_source_crypto() {
        let tss_err = TSSError::Crypto("test".to_string());
        assert!(tss_err.source().is_none());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // PROPAGATION TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_dkg_error_propagates_to_tss_error() {
        fn inner() -> Result<(), DKGError> {
            Err(DKGError::InvalidThreshold {
                threshold: 5,
                total: 3,
            })
        }

        fn outer() -> Result<(), TSSError> {
            inner()?;
            Ok(())
        }

        let result = outer();
        assert!(result.is_err());
        match result {
            Err(TSSError::DKG(DKGError::InvalidThreshold { .. })) => {}
            _ => panic!("unexpected error type"),
        }
    }

    #[test]
    fn test_signing_error_propagates_to_tss_error() {
        fn inner() -> Result<(), SigningError> {
            Err(SigningError::MessageMismatch)
        }

        fn outer() -> Result<(), TSSError> {
            inner()?;
            Ok(())
        }

        let result = outer();
        assert!(result.is_err());
        match result {
            Err(TSSError::Signing(SigningError::MessageMismatch)) => {}
            _ => panic!("unexpected error type"),
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SEND + SYNC TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_errors_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        
        assert_send_sync::<DKGError>();
        assert_send_sync::<SigningError>();
        assert_send_sync::<TSSError>();
    }

    // ────────────────────────────────────────────────────────────────────────────
    // CLONE TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_dkg_error_clone() {
        let err = DKGError::InvalidThreshold {
            threshold: 5,
            total: 3,
        };
        let cloned = err.clone();
        match cloned {
            DKGError::InvalidThreshold { threshold, total } => {
                assert_eq!(threshold, 5);
                assert_eq!(total, 3);
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn test_signing_error_clone() {
        let signer = SignerId::from_bytes([0xFF; 32]);
        let err = SigningError::SignerNotInCommittee { signer: signer.clone() };
        let cloned = err.clone();
        match cloned {
            SigningError::SignerNotInCommittee { signer: s } => {
                assert_eq!(s, signer);
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn test_tss_error_clone() {
        let err = TSSError::Crypto("test error".to_string());
        let cloned = err.clone();
        match cloned {
            TSSError::Crypto(msg) => {
                assert_eq!(msg, "test error");
            }
            _ => panic!("unexpected variant"),
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // DEBUG TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_dkg_error_debug() {
        let err = DKGError::InvalidThreshold {
            threshold: 5,
            total: 3,
        };
        let debug = format!("{:?}", err);
        assert!(debug.contains("InvalidThreshold"));
    }

    #[test]
    fn test_signing_error_debug() {
        let err = SigningError::MessageMismatch;
        let debug = format!("{:?}", err);
        assert!(debug.contains("MessageMismatch"));
    }

    #[test]
    fn test_tss_error_debug() {
        let err = TSSError::Serialization("test".to_string());
        let debug = format!("{:?}", err);
        assert!(debug.contains("Serialization"));
    }
}