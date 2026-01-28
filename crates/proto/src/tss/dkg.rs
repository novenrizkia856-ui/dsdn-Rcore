//! # DKG Protocol Messages
//!
//! Module ini menyediakan proto message types untuk Distributed Key Generation (DKG).
//!
//! ## Overview
//!
//! DKG proto types adalah representasi serializable dari DKG protocol packages.
//! Types ini digunakan untuk transport dan storage, bukan untuk crypto operations.
//!
//! ## Round 1 Package
//!
//! `DKGRound1PackageProto` merepresentasikan Round 1 broadcast message:
//!
//! | Field | Size | Description |
//! |-------|------|-------------|
//! | `session_id` | 32 bytes | Unique session identifier |
//! | `participant_id` | 32 bytes | Sender participant identifier |
//! | `commitment` | 32 bytes | Pedersen commitment |
//! | `proof` | 64 bytes | Schnorr proof of knowledge |
//!
//! ## Encoding Format
//!
//! | Property | Value |
//! |----------|-------|
//! | Format | bincode |
//! | Byte Order | Little-endian |
//! | Serialization | Deterministic |

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::fmt;

// ════════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════════

/// Expected size for session_id field.
pub const SESSION_ID_SIZE: usize = 32;

/// Expected size for participant_id field.
pub const PARTICIPANT_ID_SIZE: usize = 32;

/// Expected size for commitment field.
pub const COMMITMENT_SIZE: usize = 32;

/// Expected size for proof field.
pub const PROOF_SIZE: usize = 64;

// ════════════════════════════════════════════════════════════════════════════════
// ERROR TYPES
// ════════════════════════════════════════════════════════════════════════════════

/// Error type untuk validasi `DKGRound1PackageProto`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// session_id length tidak valid.
    InvalidSessionIdLength {
        /// Expected length.
        expected: usize,
        /// Actual length.
        got: usize,
    },

    /// participant_id length tidak valid.
    InvalidParticipantIdLength {
        /// Expected length.
        expected: usize,
        /// Actual length.
        got: usize,
    },

    /// commitment length tidak valid.
    InvalidCommitmentLength {
        /// Expected length.
        expected: usize,
        /// Actual length.
        got: usize,
    },

    /// proof length tidak valid.
    InvalidProofLength {
        /// Expected length.
        expected: usize,
        /// Actual length.
        got: usize,
    },

    /// from_participant length tidak valid (Round2).
    InvalidFromParticipantLength {
        /// Expected length.
        expected: usize,
        /// Actual length.
        got: usize,
    },

    /// to_participant length tidak valid (Round2).
    InvalidToParticipantLength {
        /// Expected length.
        expected: usize,
        /// Actual length.
        got: usize,
    },

    /// encrypted_share kosong (Round2).
    EmptyEncryptedShare,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::InvalidSessionIdLength { expected, got } => {
                write!(
                    f,
                    "invalid session_id length: expected {}, got {}",
                    expected, got
                )
            }
            ValidationError::InvalidParticipantIdLength { expected, got } => {
                write!(
                    f,
                    "invalid participant_id length: expected {}, got {}",
                    expected, got
                )
            }
            ValidationError::InvalidCommitmentLength { expected, got } => {
                write!(
                    f,
                    "invalid commitment length: expected {}, got {}",
                    expected, got
                )
            }
            ValidationError::InvalidProofLength { expected, got } => {
                write!(
                    f,
                    "invalid proof length: expected {}, got {}",
                    expected, got
                )
            }
            ValidationError::InvalidFromParticipantLength { expected, got } => {
                write!(
                    f,
                    "invalid from_participant length: expected {}, got {}",
                    expected, got
                )
            }
            ValidationError::InvalidToParticipantLength { expected, got } => {
                write!(
                    f,
                    "invalid to_participant length: expected {}, got {}",
                    expected, got
                )
            }
            ValidationError::EmptyEncryptedShare => {
                write!(f, "encrypted_share must not be empty")
            }
        }
    }
}

impl std::error::Error for ValidationError {}

/// Error type untuk decoding `DKGRound1PackageProto`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Bincode deserialization failed.
    DeserializationFailed {
        /// Error description.
        reason: String,
    },

    /// Validation failed after deserialization.
    ValidationFailed {
        /// Underlying validation error.
        error: ValidationError,
    },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::DeserializationFailed { reason } => {
                write!(f, "deserialization failed: {}", reason)
            }
            DecodeError::ValidationFailed { error } => {
                write!(f, "validation failed: {}", error)
            }
        }
    }
}

impl std::error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DecodeError::ValidationFailed { error } => Some(error),
            _ => None,
        }
    }
}

impl From<ValidationError> for DecodeError {
    fn from(error: ValidationError) -> Self {
        DecodeError::ValidationFailed { error }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// DKG ROUND 1 PACKAGE PROTO
// ════════════════════════════════════════════════════════════════════════════════

/// Proto message untuk DKG Round 1 Package.
///
/// `DKGRound1PackageProto` adalah representasi serializable dari `Round1Package`
/// yang digunakan untuk transport dan storage.
///
/// ## Field Sizes
///
/// | Field | Expected Size |
/// |-------|---------------|
/// | `session_id` | 32 bytes |
/// | `participant_id` | 32 bytes |
/// | `commitment` | 32 bytes |
/// | `proof` | 64 bytes |
///
/// ## Validation
///
/// Gunakan `validate()` untuk memastikan semua field memiliki panjang yang benar
/// sebelum conversion ke native types.
///
/// ## Example
///
/// ```rust,ignore
/// use dsdn_proto::tss::dkg::{DKGRound1PackageProto, encode_dkg_round1, decode_dkg_round1};
///
/// let proto = DKGRound1PackageProto {
///     session_id: vec![0u8; 32],
///     participant_id: vec![0u8; 32],
///     commitment: vec![0u8; 32],
///     proof: vec![0u8; 64],
/// };
///
/// // Validate
/// assert!(proto.validate().is_ok());
///
/// // Encode
/// let bytes = encode_dkg_round1(&proto);
///
/// // Decode (includes validation)
/// let decoded = decode_dkg_round1(&bytes).unwrap();
/// assert_eq!(proto, decoded);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DKGRound1PackageProto {
    /// Session identifier (MUST be 32 bytes).
    pub session_id: Vec<u8>,

    /// Participant identifier (MUST be 32 bytes).
    pub participant_id: Vec<u8>,

    /// Pedersen commitment (MUST be 32 bytes).
    pub commitment: Vec<u8>,

    /// Schnorr proof of knowledge (MUST be 64 bytes).
    pub proof: Vec<u8>,
}

impl DKGRound1PackageProto {
    /// Validates all field lengths.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if all fields have correct lengths
    /// - `Err(ValidationError)` if any field has incorrect length
    ///
    /// # Validation Rules
    ///
    /// - `session_id.len() == 32`
    /// - `participant_id.len() == 32`
    /// - `commitment.len() == 32`
    /// - `proof.len() == 64`
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.session_id.len() != SESSION_ID_SIZE {
            return Err(ValidationError::InvalidSessionIdLength {
                expected: SESSION_ID_SIZE,
                got: self.session_id.len(),
            });
        }

        if self.participant_id.len() != PARTICIPANT_ID_SIZE {
            return Err(ValidationError::InvalidParticipantIdLength {
                expected: PARTICIPANT_ID_SIZE,
                got: self.participant_id.len(),
            });
        }

        if self.commitment.len() != COMMITMENT_SIZE {
            return Err(ValidationError::InvalidCommitmentLength {
                expected: COMMITMENT_SIZE,
                got: self.commitment.len(),
            });
        }

        if self.proof.len() != PROOF_SIZE {
            return Err(ValidationError::InvalidProofLength {
                expected: PROOF_SIZE,
                got: self.proof.len(),
            });
        }

        Ok(())
    }

    /// Creates proto from native types.
    ///
    /// # Arguments
    ///
    /// * `pkg` - Reference to `Round1Package`
    /// * `session_id` - Reference to `SessionId`
    ///
    /// # Returns
    ///
    /// A valid `DKGRound1PackageProto` with all bytes copied.
    ///
    /// # Note
    ///
    /// This function is infallible because native types guarantee correct sizes.
    #[cfg(feature = "tss-conversion")]
    pub fn from_round1_package(
        pkg: &dsdn_tss::dkg::Round1Package,
        session_id: &dsdn_tss::SessionId,
    ) -> Self {
        Self {
            session_id: session_id.as_bytes().to_vec(),
            participant_id: pkg.participant_id().as_bytes().to_vec(),
            commitment: pkg.commitment().to_vec(),
            proof: pkg.proof().to_vec(),
        }
    }

    /// Converts proto back to native types.
    ///
    /// # Returns
    ///
    /// - `Ok((SessionId, Round1Package))` if valid
    /// - `Err(DecodeError)` if validation fails
    ///
    /// # Note
    ///
    /// This method calls `validate()` internally. If validation fails,
    /// the error is returned immediately without attempting conversion.
    #[cfg(feature = "tss-conversion")]
    pub fn to_round1_package(
        &self,
    ) -> Result<(dsdn_tss::SessionId, dsdn_tss::dkg::Round1Package), DecodeError> {
        // Validate first
        self.validate()?;

        // Safe to convert - validation ensures correct lengths

        // Convert session_id
        let mut session_bytes = [0u8; SESSION_ID_SIZE];
        session_bytes.copy_from_slice(&self.session_id);
        let session_id = dsdn_tss::SessionId::from_bytes(session_bytes);

        // Convert participant_id
        let mut participant_bytes = [0u8; PARTICIPANT_ID_SIZE];
        participant_bytes.copy_from_slice(&self.participant_id);
        let participant_id = dsdn_tss::ParticipantId::from_bytes(participant_bytes);

        // Convert commitment
        let mut commitment = [0u8; COMMITMENT_SIZE];
        commitment.copy_from_slice(&self.commitment);

        // Convert proof
        let mut proof = [0u8; PROOF_SIZE];
        proof.copy_from_slice(&self.proof);

        // Build Round1Package
        let package = dsdn_tss::dkg::Round1Package::new(participant_id, commitment, proof);

        Ok((session_id, package))
    }
}

impl Default for DKGRound1PackageProto {
    fn default() -> Self {
        Self {
            session_id: vec![0u8; SESSION_ID_SIZE],
            participant_id: vec![0u8; PARTICIPANT_ID_SIZE],
            commitment: vec![0u8; COMMITMENT_SIZE],
            proof: vec![0u8; PROOF_SIZE],
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// ENCODING FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════════

/// Encodes `DKGRound1PackageProto` to bytes.
///
/// # Arguments
///
/// * `pkg` - Reference to proto message
///
/// # Returns
///
/// Bincode-encoded bytes (little-endian, deterministic).
///
/// # Note
///
/// This function does NOT validate the proto. Call `validate()` first
/// if validation is needed.
#[must_use]
pub fn encode_dkg_round1(pkg: &DKGRound1PackageProto) -> Vec<u8> {
    // Use bincode with standard config (little-endian, fixed int encoding)
    bincode::serialize(pkg).unwrap_or_else(|_| Vec::new())
}

/// Decodes bytes to `DKGRound1PackageProto`.
///
/// # Arguments
///
/// * `bytes` - Bincode-encoded bytes
///
/// # Returns
///
/// - `Ok(DKGRound1PackageProto)` if decoding and validation succeed
/// - `Err(DecodeError)` if decoding or validation fails
///
/// # Note
///
/// This function calls `validate()` after deserialization.
/// Invalid field lengths will result in `DecodeError::ValidationFailed`.
pub fn decode_dkg_round1(bytes: &[u8]) -> Result<DKGRound1PackageProto, DecodeError> {
    let proto: DKGRound1PackageProto =
        bincode::deserialize(bytes).map_err(|e| DecodeError::DeserializationFailed {
            reason: e.to_string(),
        })?;

    // Validate after deserialization
    proto.validate()?;

    Ok(proto)
}

// ════════════════════════════════════════════════════════════════════════════════
// HASH FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════════

/// Computes deterministic hash of `DKGRound1PackageProto`.
///
/// # Arguments
///
/// * `pkg` - Reference to proto message
///
/// # Returns
///
/// SHA3-256 hash of the encoded proto (32 bytes).
///
/// # Algorithm
///
/// ```text
/// hash = SHA3-256(encode_dkg_round1(pkg))
/// ```
///
/// # Note
///
/// Hash is computed from the serialized bytes, not from individual fields.
/// This ensures determinism and consistency with other hash computations.
#[must_use]
pub fn compute_dkg_round1_hash(pkg: &DKGRound1PackageProto) -> [u8; 32] {
    let encoded = encode_dkg_round1(pkg);

    let mut hasher = Sha3_256::new();
    hasher.update(&encoded);
    let result = hasher.finalize();

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

// ════════════════════════════════════════════════════════════════════════════════
// DKG ROUND 2 PACKAGE PROTO
// ════════════════════════════════════════════════════════════════════════════════

/// Proto message untuk DKG Round 2 Package.
///
/// `DKGRound2PackageProto` adalah representasi serializable dari `Round2Package`
/// yang digunakan untuk transport dan storage. Round 2 packages berisi
/// encrypted secret shares yang dikirim dari satu participant ke participant lain.
///
/// ## Field Sizes
///
/// | Field | Expected Size |
/// |-------|---------------|
/// | `session_id` | 32 bytes |
/// | `from_participant` | 32 bytes |
/// | `to_participant` | 32 bytes |
/// | `encrypted_share` | > 0 bytes (opaque) |
///
/// ## Validation
///
/// Gunakan `validate()` untuk memastikan semua field memiliki panjang yang benar.
/// `encrypted_share` diperlakukan sebagai opaque bytes dan hanya divalidasi
/// tidak kosong.
///
/// ## Example
///
/// ```rust,ignore
/// use dsdn_proto::tss::dkg::{DKGRound2PackageProto, encode_dkg_round2, decode_dkg_round2};
///
/// let proto = DKGRound2PackageProto {
///     session_id: vec![0u8; 32],
///     from_participant: vec![0u8; 32],
///     to_participant: vec![0u8; 32],
///     encrypted_share: vec![0x42u8; 48],
/// };
///
/// // Validate
/// assert!(proto.validate().is_ok());
///
/// // Encode
/// let bytes = encode_dkg_round2(&proto);
///
/// // Decode (includes validation)
/// let decoded = decode_dkg_round2(&bytes).unwrap();
/// assert_eq!(proto, decoded);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DKGRound2PackageProto {
    /// Session identifier (MUST be 32 bytes).
    pub session_id: Vec<u8>,

    /// Sender participant identifier (MUST be 32 bytes).
    pub from_participant: Vec<u8>,

    /// Recipient participant identifier (MUST be 32 bytes).
    pub to_participant: Vec<u8>,

    /// Encrypted secret share (MUST be > 0 bytes, opaque).
    ///
    /// Ini adalah ciphertext yang berisi share yang dienkripsi.
    /// Format tidak diasumsikan - diperlakukan sebagai opaque bytes.
    pub encrypted_share: Vec<u8>,
}

impl DKGRound2PackageProto {
    /// Validates all field lengths.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if all fields have correct lengths
    /// - `Err(ValidationError)` if any field has incorrect length
    ///
    /// # Validation Rules
    ///
    /// - `session_id.len() == 32`
    /// - `from_participant.len() == 32`
    /// - `to_participant.len() == 32`
    /// - `encrypted_share.len() > 0`
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.session_id.len() != SESSION_ID_SIZE {
            return Err(ValidationError::InvalidSessionIdLength {
                expected: SESSION_ID_SIZE,
                got: self.session_id.len(),
            });
        }

        if self.from_participant.len() != PARTICIPANT_ID_SIZE {
            return Err(ValidationError::InvalidFromParticipantLength {
                expected: PARTICIPANT_ID_SIZE,
                got: self.from_participant.len(),
            });
        }

        if self.to_participant.len() != PARTICIPANT_ID_SIZE {
            return Err(ValidationError::InvalidToParticipantLength {
                expected: PARTICIPANT_ID_SIZE,
                got: self.to_participant.len(),
            });
        }

        if self.encrypted_share.is_empty() {
            return Err(ValidationError::EmptyEncryptedShare);
        }

        Ok(())
    }

    /// Creates proto from native `Round2Package`.
    ///
    /// # Arguments
    ///
    /// * `pkg` - Reference to `Round2Package`
    ///
    /// # Returns
    ///
    /// A `DKGRound2PackageProto` with all bytes copied.
    ///
    /// # Note
    ///
    /// This function is infallible because native types guarantee correct sizes.
    #[cfg(feature = "tss-conversion")]
    pub fn from_round2_package(pkg: &dsdn_tss::dkg::Round2Package) -> Self {
        Self {
            session_id: pkg.session_id().as_bytes().to_vec(),
            from_participant: pkg.from_participant().as_bytes().to_vec(),
            to_participant: pkg.to_participant().as_bytes().to_vec(),
            encrypted_share: pkg.encrypted_share().to_vec(),
        }
    }

    /// Converts proto back to native `Round2Package`.
    ///
    /// # Returns
    ///
    /// - `Ok(Round2Package)` if valid
    /// - `Err(DecodeError)` if validation fails
    ///
    /// # Note
    ///
    /// This method calls `validate()` internally. If validation fails,
    /// the error is returned immediately without attempting conversion.
    #[cfg(feature = "tss-conversion")]
    pub fn to_round2_package(&self) -> Result<dsdn_tss::dkg::Round2Package, DecodeError> {
        // Validate first
        self.validate()?;

        // Safe to convert - validation ensures correct lengths

        // Convert session_id
        let mut session_bytes = [0u8; SESSION_ID_SIZE];
        session_bytes.copy_from_slice(&self.session_id);
        let session_id = dsdn_tss::SessionId::from_bytes(session_bytes);

        // Convert from_participant
        let mut from_bytes = [0u8; PARTICIPANT_ID_SIZE];
        from_bytes.copy_from_slice(&self.from_participant);
        let from_participant = dsdn_tss::ParticipantId::from_bytes(from_bytes);

        // Convert to_participant
        let mut to_bytes = [0u8; PARTICIPANT_ID_SIZE];
        to_bytes.copy_from_slice(&self.to_participant);
        let to_participant = dsdn_tss::ParticipantId::from_bytes(to_bytes);

        // Build Round2Package
        let package = dsdn_tss::dkg::Round2Package::new(
            session_id,
            from_participant,
            to_participant,
            self.encrypted_share.clone(),
        );

        Ok(package)
    }
}

impl Default for DKGRound2PackageProto {
    fn default() -> Self {
        Self {
            session_id: vec![0u8; SESSION_ID_SIZE],
            from_participant: vec![0u8; PARTICIPANT_ID_SIZE],
            to_participant: vec![0u8; PARTICIPANT_ID_SIZE],
            encrypted_share: vec![0u8; 1], // Minimal non-empty
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// ROUND 2 ENCODING FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════════

/// Encodes `DKGRound2PackageProto` to bytes.
///
/// # Arguments
///
/// * `pkg` - Reference to proto message
///
/// # Returns
///
/// Bincode-encoded bytes (little-endian, deterministic).
///
/// # Note
///
/// This function does NOT validate the proto. Call `validate()` first
/// if validation is needed.
#[must_use]
pub fn encode_dkg_round2(pkg: &DKGRound2PackageProto) -> Vec<u8> {
    bincode::serialize(pkg).unwrap_or_else(|_| Vec::new())
}

/// Decodes bytes to `DKGRound2PackageProto`.
///
/// # Arguments
///
/// * `bytes` - Bincode-encoded bytes
///
/// # Returns
///
/// - `Ok(DKGRound2PackageProto)` if decoding and validation succeed
/// - `Err(DecodeError)` if decoding or validation fails
///
/// # Note
///
/// This function calls `validate()` after deserialization.
/// Invalid field lengths will result in `DecodeError::ValidationFailed`.
pub fn decode_dkg_round2(bytes: &[u8]) -> Result<DKGRound2PackageProto, DecodeError> {
    let proto: DKGRound2PackageProto =
        bincode::deserialize(bytes).map_err(|e| DecodeError::DeserializationFailed {
            reason: e.to_string(),
        })?;

    // Validate after deserialization
    proto.validate()?;

    Ok(proto)
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ────────────────────────────────────────────────────────────────────────────
    // VALIDATION TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_validate_valid_proto() {
        let proto = DKGRound1PackageProto {
            session_id: vec![0xAA; 32],
            participant_id: vec![0xBB; 32],
            commitment: vec![0xCC; 32],
            proof: vec![0xDD; 64],
        };

        assert!(proto.validate().is_ok());
    }

    #[test]
    fn test_validate_invalid_session_id_length() {
        let proto = DKGRound1PackageProto {
            session_id: vec![0xAA; 16], // Wrong length
            participant_id: vec![0xBB; 32],
            commitment: vec![0xCC; 32],
            proof: vec![0xDD; 64],
        };

        let result = proto.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::InvalidSessionIdLength { expected: 32, got: 16 }
        ));
    }

    #[test]
    fn test_validate_invalid_participant_id_length() {
        let proto = DKGRound1PackageProto {
            session_id: vec![0xAA; 32],
            participant_id: vec![0xBB; 64], // Wrong length
            commitment: vec![0xCC; 32],
            proof: vec![0xDD; 64],
        };

        let result = proto.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::InvalidParticipantIdLength { expected: 32, got: 64 }
        ));
    }

    #[test]
    fn test_validate_invalid_commitment_length() {
        let proto = DKGRound1PackageProto {
            session_id: vec![0xAA; 32],
            participant_id: vec![0xBB; 32],
            commitment: vec![0xCC; 48], // Wrong length
            proof: vec![0xDD; 64],
        };

        let result = proto.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::InvalidCommitmentLength { expected: 32, got: 48 }
        ));
    }

    #[test]
    fn test_validate_invalid_proof_length() {
        let proto = DKGRound1PackageProto {
            session_id: vec![0xAA; 32],
            participant_id: vec![0xBB; 32],
            commitment: vec![0xCC; 32],
            proof: vec![0xDD; 32], // Wrong length
        };

        let result = proto.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::InvalidProofLength { expected: 64, got: 32 }
        ));
    }

    #[test]
    fn test_validate_empty_fields() {
        let proto = DKGRound1PackageProto {
            session_id: vec![],
            participant_id: vec![],
            commitment: vec![],
            proof: vec![],
        };

        let result = proto.validate();
        assert!(result.is_err());
        // First validation failure is session_id
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::InvalidSessionIdLength { expected: 32, got: 0 }
        ));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // ENCODING TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_encode_decode_roundtrip() {
        let proto = DKGRound1PackageProto {
            session_id: vec![0x11; 32],
            participant_id: vec![0x22; 32],
            commitment: vec![0x33; 32],
            proof: vec![0x44; 64],
        };

        let encoded = encode_dkg_round1(&proto);
        let decoded = decode_dkg_round1(&encoded);

        assert!(decoded.is_ok());
        assert_eq!(proto, decoded.expect("valid"));
    }

    #[test]
    fn test_encode_deterministic() {
        let proto = DKGRound1PackageProto {
            session_id: vec![0xAA; 32],
            participant_id: vec![0xBB; 32],
            commitment: vec![0xCC; 32],
            proof: vec![0xDD; 64],
        };

        let encoded1 = encode_dkg_round1(&proto);
        let encoded2 = encode_dkg_round1(&proto);

        assert_eq!(encoded1, encoded2);
    }

    #[test]
    fn test_decode_invalid_bytes() {
        let invalid_bytes = vec![0xFF; 10];
        let result = decode_dkg_round1(&invalid_bytes);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DecodeError::DeserializationFailed { .. }
        ));
    }

    #[test]
    fn test_decode_validates_after_deserialization() {
        // Create invalid proto manually and serialize
        let invalid_proto = DKGRound1PackageProto {
            session_id: vec![0xAA; 16], // Invalid length
            participant_id: vec![0xBB; 32],
            commitment: vec![0xCC; 32],
            proof: vec![0xDD; 64],
        };

        // Serialize (bypassing validation)
        let bytes = bincode::serialize(&invalid_proto).expect("serialize");

        // Decode should fail validation
        let result = decode_dkg_round1(&bytes);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DecodeError::ValidationFailed { .. }
        ));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // HASH TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_hash_deterministic() {
        let proto = DKGRound1PackageProto {
            session_id: vec![0x11; 32],
            participant_id: vec![0x22; 32],
            commitment: vec![0x33; 32],
            proof: vec![0x44; 64],
        };

        let hash1 = compute_dkg_round1_hash(&proto);
        let hash2 = compute_dkg_round1_hash(&proto);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_different_for_different_session_id() {
        let proto1 = DKGRound1PackageProto {
            session_id: vec![0x11; 32],
            participant_id: vec![0x22; 32],
            commitment: vec![0x33; 32],
            proof: vec![0x44; 64],
        };

        let proto2 = DKGRound1PackageProto {
            session_id: vec![0xFF; 32], // Different
            participant_id: vec![0x22; 32],
            commitment: vec![0x33; 32],
            proof: vec![0x44; 64],
        };

        let hash1 = compute_dkg_round1_hash(&proto1);
        let hash2 = compute_dkg_round1_hash(&proto2);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_different_for_different_participant_id() {
        let proto1 = DKGRound1PackageProto {
            session_id: vec![0x11; 32],
            participant_id: vec![0x22; 32],
            commitment: vec![0x33; 32],
            proof: vec![0x44; 64],
        };

        let proto2 = DKGRound1PackageProto {
            session_id: vec![0x11; 32],
            participant_id: vec![0xFF; 32], // Different
            commitment: vec![0x33; 32],
            proof: vec![0x44; 64],
        };

        let hash1 = compute_dkg_round1_hash(&proto1);
        let hash2 = compute_dkg_round1_hash(&proto2);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_different_for_different_commitment() {
        let proto1 = DKGRound1PackageProto {
            session_id: vec![0x11; 32],
            participant_id: vec![0x22; 32],
            commitment: vec![0x33; 32],
            proof: vec![0x44; 64],
        };

        let proto2 = DKGRound1PackageProto {
            session_id: vec![0x11; 32],
            participant_id: vec![0x22; 32],
            commitment: vec![0xFF; 32], // Different
            proof: vec![0x44; 64],
        };

        let hash1 = compute_dkg_round1_hash(&proto1);
        let hash2 = compute_dkg_round1_hash(&proto2);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_different_for_different_proof() {
        let proto1 = DKGRound1PackageProto {
            session_id: vec![0x11; 32],
            participant_id: vec![0x22; 32],
            commitment: vec![0x33; 32],
            proof: vec![0x44; 64],
        };

        let proto2 = DKGRound1PackageProto {
            session_id: vec![0x11; 32],
            participant_id: vec![0x22; 32],
            commitment: vec![0x33; 32],
            proof: vec![0xFF; 64], // Different
        };

        let hash1 = compute_dkg_round1_hash(&proto1);
        let hash2 = compute_dkg_round1_hash(&proto2);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_single_byte_change() {
        let mut proto1 = DKGRound1PackageProto {
            session_id: vec![0x11; 32],
            participant_id: vec![0x22; 32],
            commitment: vec![0x33; 32],
            proof: vec![0x44; 64],
        };

        let hash1 = compute_dkg_round1_hash(&proto1);

        // Change single byte
        proto1.commitment[15] = 0xFF;
        let hash2 = compute_dkg_round1_hash(&proto1);

        assert_ne!(hash1, hash2);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // ERROR DISPLAY TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_validation_error_display() {
        let error = ValidationError::InvalidSessionIdLength {
            expected: 32,
            got: 16,
        };
        let display = format!("{}", error);
        assert!(display.contains("session_id"));
        assert!(display.contains("32"));
        assert!(display.contains("16"));
    }

    #[test]
    fn test_decode_error_display() {
        let error = DecodeError::DeserializationFailed {
            reason: "test error".to_string(),
        };
        let display = format!("{}", error);
        assert!(display.contains("deserialization"));
        assert!(display.contains("test error"));
    }

    #[test]
    fn test_decode_error_from_validation_error() {
        let validation_error = ValidationError::InvalidProofLength {
            expected: 64,
            got: 32,
        };
        let decode_error: DecodeError = validation_error.into();

        assert!(matches!(
            decode_error,
            DecodeError::ValidationFailed { .. }
        ));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // DEFAULT TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_default() {
        let proto = DKGRound1PackageProto::default();

        assert_eq!(proto.session_id.len(), 32);
        assert_eq!(proto.participant_id.len(), 32);
        assert_eq!(proto.commitment.len(), 32);
        assert_eq!(proto.proof.len(), 64);
        assert!(proto.validate().is_ok());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // ROUND 2 VALIDATION TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_round2_validate_valid_proto() {
        let proto = DKGRound2PackageProto {
            session_id: vec![0xAA; 32],
            from_participant: vec![0xBB; 32],
            to_participant: vec![0xCC; 32],
            encrypted_share: vec![0xDD; 48],
        };

        assert!(proto.validate().is_ok());
    }

    #[test]
    fn test_round2_validate_invalid_session_id_length() {
        let proto = DKGRound2PackageProto {
            session_id: vec![0xAA; 16], // Wrong length
            from_participant: vec![0xBB; 32],
            to_participant: vec![0xCC; 32],
            encrypted_share: vec![0xDD; 48],
        };

        let result = proto.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::InvalidSessionIdLength { expected: 32, got: 16 }
        ));
    }

    #[test]
    fn test_round2_validate_invalid_from_participant_length() {
        let proto = DKGRound2PackageProto {
            session_id: vec![0xAA; 32],
            from_participant: vec![0xBB; 64], // Wrong length
            to_participant: vec![0xCC; 32],
            encrypted_share: vec![0xDD; 48],
        };

        let result = proto.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::InvalidFromParticipantLength { expected: 32, got: 64 }
        ));
    }

    #[test]
    fn test_round2_validate_invalid_to_participant_length() {
        let proto = DKGRound2PackageProto {
            session_id: vec![0xAA; 32],
            from_participant: vec![0xBB; 32],
            to_participant: vec![0xCC; 16], // Wrong length
            encrypted_share: vec![0xDD; 48],
        };

        let result = proto.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::InvalidToParticipantLength { expected: 32, got: 16 }
        ));
    }

    #[test]
    fn test_round2_validate_empty_encrypted_share() {
        let proto = DKGRound2PackageProto {
            session_id: vec![0xAA; 32],
            from_participant: vec![0xBB; 32],
            to_participant: vec![0xCC; 32],
            encrypted_share: vec![], // Empty
        };

        let result = proto.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::EmptyEncryptedShare
        ));
    }

    #[test]
    fn test_round2_validate_single_byte_encrypted_share() {
        // Single byte should be valid
        let proto = DKGRound2PackageProto {
            session_id: vec![0xAA; 32],
            from_participant: vec![0xBB; 32],
            to_participant: vec![0xCC; 32],
            encrypted_share: vec![0x01], // Single byte is valid
        };

        assert!(proto.validate().is_ok());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // ROUND 2 ENCODING TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_round2_encode_decode_roundtrip() {
        let proto = DKGRound2PackageProto {
            session_id: vec![0x11; 32],
            from_participant: vec![0x22; 32],
            to_participant: vec![0x33; 32],
            encrypted_share: vec![0x44; 64],
        };

        let encoded = encode_dkg_round2(&proto);
        let decoded = decode_dkg_round2(&encoded);

        assert!(decoded.is_ok());
        assert_eq!(proto, decoded.expect("valid"));
    }

    #[test]
    fn test_round2_encode_deterministic() {
        let proto = DKGRound2PackageProto {
            session_id: vec![0xAA; 32],
            from_participant: vec![0xBB; 32],
            to_participant: vec![0xCC; 32],
            encrypted_share: vec![0xDD; 48],
        };

        let encoded1 = encode_dkg_round2(&proto);
        let encoded2 = encode_dkg_round2(&proto);

        assert_eq!(encoded1, encoded2);
    }

    #[test]
    fn test_round2_decode_invalid_bytes() {
        let invalid_bytes = vec![0xFF; 10];
        let result = decode_dkg_round2(&invalid_bytes);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DecodeError::DeserializationFailed { .. }
        ));
    }

    #[test]
    fn test_round2_decode_validates_after_deserialization() {
        // Create invalid proto manually and serialize
        let invalid_proto = DKGRound2PackageProto {
            session_id: vec![0xAA; 16], // Invalid length
            from_participant: vec![0xBB; 32],
            to_participant: vec![0xCC; 32],
            encrypted_share: vec![0xDD; 48],
        };

        // Serialize (bypassing validation)
        let bytes = bincode::serialize(&invalid_proto).expect("serialize");

        // Decode should fail validation
        let result = decode_dkg_round2(&bytes);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DecodeError::ValidationFailed { .. }
        ));
    }

    #[test]
    fn test_round2_decode_validates_empty_share() {
        // Create proto with empty encrypted_share
        let invalid_proto = DKGRound2PackageProto {
            session_id: vec![0xAA; 32],
            from_participant: vec![0xBB; 32],
            to_participant: vec![0xCC; 32],
            encrypted_share: vec![], // Empty
        };

        // Serialize (bypassing validation)
        let bytes = bincode::serialize(&invalid_proto).expect("serialize");

        // Decode should fail validation
        let result = decode_dkg_round2(&bytes);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DecodeError::ValidationFailed {
                error: ValidationError::EmptyEncryptedShare
            }
        ));
    }

    #[test]
    fn test_round2_variable_encrypted_share_lengths() {
        // Test various valid lengths
        for len in [1, 32, 48, 64, 128, 256] {
            let proto = DKGRound2PackageProto {
                session_id: vec![0xAA; 32],
                from_participant: vec![0xBB; 32],
                to_participant: vec![0xCC; 32],
                encrypted_share: vec![0xDD; len],
            };

            assert!(proto.validate().is_ok(), "length {} should be valid", len);

            let encoded = encode_dkg_round2(&proto);
            let decoded = decode_dkg_round2(&encoded).expect("decode should succeed");
            assert_eq!(proto, decoded, "roundtrip should preserve data for length {}", len);
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // ROUND 2 DEFAULT TEST
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_round2_default() {
        let proto = DKGRound2PackageProto::default();

        assert_eq!(proto.session_id.len(), 32);
        assert_eq!(proto.from_participant.len(), 32);
        assert_eq!(proto.to_participant.len(), 32);
        assert!(!proto.encrypted_share.is_empty());
        assert!(proto.validate().is_ok());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // ROUND 2 ERROR DISPLAY TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_round2_validation_error_from_participant_display() {
        let error = ValidationError::InvalidFromParticipantLength {
            expected: 32,
            got: 64,
        };
        let display = format!("{}", error);
        assert!(display.contains("from_participant"));
        assert!(display.contains("32"));
        assert!(display.contains("64"));
    }

    #[test]
    fn test_round2_validation_error_to_participant_display() {
        let error = ValidationError::InvalidToParticipantLength {
            expected: 32,
            got: 16,
        };
        let display = format!("{}", error);
        assert!(display.contains("to_participant"));
        assert!(display.contains("32"));
        assert!(display.contains("16"));
    }

    #[test]
    fn test_round2_validation_error_empty_share_display() {
        let error = ValidationError::EmptyEncryptedShare;
        let display = format!("{}", error);
        assert!(display.contains("encrypted_share"));
        assert!(display.contains("empty"));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SEND + SYNC TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<DKGRound1PackageProto>();
        assert_send_sync::<DKGRound2PackageProto>();
        assert_send_sync::<ValidationError>();
        assert_send_sync::<DecodeError>();
    }
}