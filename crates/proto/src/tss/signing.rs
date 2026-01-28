//! # Signing Protocol Messages
//!
//! Module ini menyediakan proto message types untuk threshold signing.
//!
//! ## Overview
//!
//! Signing proto types adalah representasi serializable dari signing request
//! yang digunakan untuk transport dan storage.
//!
//! ## SigningRequestProto
//!
//! `SigningRequestProto` merepresentasikan permintaan untuk threshold signing:
//!
//! | Field | Size | Description |
//! |-------|------|-------------|
//! | `session_id` | 32 bytes | Unique session identifier |
//! | `message` | Variable | Message to be signed |
//! | `message_hash` | 32 bytes | SHA3-256 hash of message |
//! | `required_signers` | N × 32 bytes | List of signer identifiers |
//! | `epoch` | 8 bytes | Epoch number |
//! | `timeout_secs` | 8 bytes | Timeout in seconds |
//! | `request_timestamp` | 8 bytes | Unix timestamp of request |
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
use std::time::{SystemTime, UNIX_EPOCH};

// ════════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════════

/// Expected size for session_id field.
pub const SESSION_ID_SIZE: usize = 32;

/// Expected size for signer_id field.
pub const SIGNER_ID_SIZE: usize = 32;

/// Expected size for message_hash field.
pub const MESSAGE_HASH_SIZE: usize = 32;

// ════════════════════════════════════════════════════════════════════════════════
// ERROR TYPES
// ════════════════════════════════════════════════════════════════════════════════

/// Error type untuk validasi `SigningRequestProto`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningValidationError {
    /// session_id length tidak valid.
    InvalidSessionIdLength {
        /// Expected length.
        expected: usize,
        /// Actual length.
        got: usize,
    },

    /// message_hash length tidak valid.
    InvalidMessageHashLength {
        /// Expected length.
        expected: usize,
        /// Actual length.
        got: usize,
    },

    /// required_signers kosong.
    EmptyRequiredSigners,

    /// signer_id length tidak valid.
    InvalidSignerIdLength {
        /// Index of invalid signer.
        index: usize,
        /// Expected length.
        expected: usize,
        /// Actual length.
        got: usize,
    },

    /// timeout_secs tidak valid (must be > 0).
    InvalidTimeout {
        /// Actual value.
        timeout_secs: u64,
    },
}

impl fmt::Display for SigningValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SigningValidationError::InvalidSessionIdLength { expected, got } => {
                write!(
                    f,
                    "invalid session_id length: expected {}, got {}",
                    expected, got
                )
            }
            SigningValidationError::InvalidMessageHashLength { expected, got } => {
                write!(
                    f,
                    "invalid message_hash length: expected {}, got {}",
                    expected, got
                )
            }
            SigningValidationError::EmptyRequiredSigners => {
                write!(f, "required_signers must not be empty")
            }
            SigningValidationError::InvalidSignerIdLength { index, expected, got } => {
                write!(
                    f,
                    "invalid required_signers[{}] length: expected {}, got {}",
                    index, expected, got
                )
            }
            SigningValidationError::InvalidTimeout { timeout_secs } => {
                write!(
                    f,
                    "invalid timeout_secs: {} (must be > 0)",
                    timeout_secs
                )
            }
        }
    }
}

impl std::error::Error for SigningValidationError {}

/// Error type untuk decoding `SigningRequestProto`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningDecodeError {
    /// Bincode deserialization failed.
    DeserializationFailed {
        /// Error description.
        reason: String,
    },

    /// Validation failed after deserialization.
    ValidationFailed {
        /// Underlying validation error.
        error: SigningValidationError,
    },
}

impl fmt::Display for SigningDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SigningDecodeError::DeserializationFailed { reason } => {
                write!(f, "deserialization failed: {}", reason)
            }
            SigningDecodeError::ValidationFailed { error } => {
                write!(f, "validation failed: {}", error)
            }
        }
    }
}

impl std::error::Error for SigningDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SigningDecodeError::ValidationFailed { error } => Some(error),
            _ => None,
        }
    }
}

impl From<SigningValidationError> for SigningDecodeError {
    fn from(error: SigningValidationError) -> Self {
        SigningDecodeError::ValidationFailed { error }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// SIGNING REQUEST PROTO
// ════════════════════════════════════════════════════════════════════════════════

/// Proto message untuk Signing Request.
///
/// `SigningRequestProto` adalah representasi serializable dari permintaan
/// threshold signing yang digunakan untuk transport dan storage.
///
/// ## Field Sizes
///
/// | Field | Expected Size |
/// |-------|---------------|
/// | `session_id` | 32 bytes |
/// | `message` | Variable |
/// | `message_hash` | 32 bytes |
/// | `required_signers[i]` | 32 bytes each |
///
/// ## Validation
///
/// Gunakan `validate()` untuk memastikan semua field memiliki panjang yang benar
/// sebelum processing.
///
/// ## Example
///
/// ```rust,ignore
/// use dsdn_proto::tss::signing::{SigningRequestProto, encode_signing_request, decode_signing_request};
///
/// let proto = SigningRequestProto {
///     session_id: vec![0u8; 32],
///     message: b"hello world".to_vec(),
///     message_hash: vec![0u8; 32], // Should be SHA3-256 of message
///     required_signers: vec![vec![0u8; 32], vec![0u8; 32]],
///     epoch: 1,
///     timeout_secs: 60,
///     request_timestamp: 1234567890,
/// };
///
/// // Validate
/// assert!(proto.validate().is_ok());
///
/// // Encode
/// let bytes = encode_signing_request(&proto);
///
/// // Decode (includes validation)
/// let decoded = decode_signing_request(&bytes).unwrap();
/// assert_eq!(proto, decoded);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningRequestProto {
    /// Session identifier (MUST be 32 bytes).
    pub session_id: Vec<u8>,

    /// Message to be signed (variable length).
    pub message: Vec<u8>,

    /// SHA3-256 hash of message (MUST be 32 bytes).
    pub message_hash: Vec<u8>,

    /// Required signer identifiers (EACH MUST be 32 bytes).
    pub required_signers: Vec<Vec<u8>>,

    /// Epoch number.
    pub epoch: u64,

    /// Timeout in seconds (MUST be > 0).
    pub timeout_secs: u64,

    /// Unix timestamp of request creation (seconds since epoch).
    pub request_timestamp: u64,
}

impl SigningRequestProto {
    /// Creates a new `SigningRequestProto`.
    ///
    /// # Arguments
    ///
    /// * `session_id` - Session identifier
    /// * `message` - Message to be signed
    /// * `required_signers` - List of signer identifiers
    /// * `epoch` - Epoch number
    /// * `timeout_secs` - Timeout in seconds
    ///
    /// # Returns
    ///
    /// A `SigningRequestProto` with:
    /// - `message_hash` computed as SHA3-256 of message
    /// - `request_timestamp` set to current Unix time
    ///
    /// # Note
    ///
    /// This constructor is feature-gated. Use direct struct initialization
    /// when not using the tss-conversion feature.
    #[cfg(feature = "tss-conversion")]
    #[must_use]
    pub fn new(
        session_id: dsdn_tss::SessionId,
        message: Vec<u8>,
        required_signers: Vec<dsdn_tss::SignerId>,
        epoch: u64,
        timeout_secs: u64,
    ) -> Self {
        // Compute message hash
        let message_hash = compute_message_hash(&message);

        // Get current timestamp
        let request_timestamp = current_unix_timestamp();

        Self {
            session_id: session_id.as_bytes().to_vec(),
            message,
            message_hash: message_hash.to_vec(),
            required_signers: required_signers
                .iter()
                .map(|s| s.as_bytes().to_vec())
                .collect(),
            epoch,
            timeout_secs,
            request_timestamp,
        }
    }

    /// Creates a `SigningRequestProto` from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `session_id` - Session identifier bytes (32 bytes)
    /// * `message` - Message to be signed
    /// * `required_signers` - List of signer identifier bytes (each 32 bytes)
    /// * `epoch` - Epoch number
    /// * `timeout_secs` - Timeout in seconds
    ///
    /// # Returns
    ///
    /// A `SigningRequestProto` with:
    /// - `message_hash` computed as SHA3-256 of message
    /// - `request_timestamp` set to current Unix time
    #[must_use]
    pub fn from_raw(
        session_id: Vec<u8>,
        message: Vec<u8>,
        required_signers: Vec<Vec<u8>>,
        epoch: u64,
        timeout_secs: u64,
    ) -> Self {
        // Compute message hash
        let message_hash = compute_message_hash(&message);

        // Get current timestamp
        let request_timestamp = current_unix_timestamp();

        Self {
            session_id,
            message,
            message_hash: message_hash.to_vec(),
            required_signers,
            epoch,
            timeout_secs,
            request_timestamp,
        }
    }

    /// Validates all field lengths and constraints.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if all fields are valid
    /// - `Err(SigningValidationError)` if any validation fails
    ///
    /// # Validation Rules
    ///
    /// - `session_id.len() == 32`
    /// - `message_hash.len() == 32`
    /// - `required_signers` is not empty
    /// - Each `required_signers[i].len() == 32`
    /// - `timeout_secs > 0`
    pub fn validate(&self) -> Result<(), SigningValidationError> {
        // Validate session_id
        if self.session_id.len() != SESSION_ID_SIZE {
            return Err(SigningValidationError::InvalidSessionIdLength {
                expected: SESSION_ID_SIZE,
                got: self.session_id.len(),
            });
        }

        // Validate message_hash
        if self.message_hash.len() != MESSAGE_HASH_SIZE {
            return Err(SigningValidationError::InvalidMessageHashLength {
                expected: MESSAGE_HASH_SIZE,
                got: self.message_hash.len(),
            });
        }

        // Validate required_signers not empty
        if self.required_signers.is_empty() {
            return Err(SigningValidationError::EmptyRequiredSigners);
        }

        // Validate each signer_id length
        for (i, signer_id) in self.required_signers.iter().enumerate() {
            if signer_id.len() != SIGNER_ID_SIZE {
                return Err(SigningValidationError::InvalidSignerIdLength {
                    index: i,
                    expected: SIGNER_ID_SIZE,
                    got: signer_id.len(),
                });
            }
        }

        // Validate timeout_secs > 0
        if self.timeout_secs == 0 {
            return Err(SigningValidationError::InvalidTimeout {
                timeout_secs: self.timeout_secs,
            });
        }

        Ok(())
    }

    /// Converts proto to native types.
    ///
    /// # Returns
    ///
    /// - `Ok((SessionId, Vec<u8>, Vec<SignerId>, u64, u64, u64))` containing:
    ///   - session_id
    ///   - message
    ///   - required_signers
    ///   - epoch
    ///   - timeout_secs
    ///   - request_timestamp
    /// - `Err(SigningDecodeError)` if validation fails
    ///
    /// # Note
    ///
    /// This method calls `validate()` internally.
    #[cfg(feature = "tss-conversion")]
    pub fn to_signing_request(
        &self,
    ) -> Result<
        (
            dsdn_tss::SessionId,
            Vec<u8>,
            Vec<dsdn_tss::SignerId>,
            u64,
            u64,
            u64,
        ),
        SigningDecodeError,
    > {
        // Validate first
        self.validate()?;

        // Convert session_id
        let mut session_bytes = [0u8; SESSION_ID_SIZE];
        session_bytes.copy_from_slice(&self.session_id);
        let session_id = dsdn_tss::SessionId::from_bytes(session_bytes);

        // Convert required_signers
        let mut signers = Vec::with_capacity(self.required_signers.len());
        for signer_bytes in &self.required_signers {
            let mut signer_arr = [0u8; SIGNER_ID_SIZE];
            signer_arr.copy_from_slice(signer_bytes);
            signers.push(dsdn_tss::SignerId::from_bytes(signer_arr));
        }

        Ok((
            session_id,
            self.message.clone(),
            signers,
            self.epoch,
            self.timeout_secs,
            self.request_timestamp,
        ))
    }

    /// Verifies that `message_hash` matches the hash of `message`.
    ///
    /// # Returns
    ///
    /// `true` if `message_hash == SHA3-256(message)`, `false` otherwise.
    #[must_use]
    pub fn verify_message_hash(&self) -> bool {
        let computed = compute_message_hash(&self.message);
        self.message_hash == computed
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════════

/// Computes SHA3-256 hash of a message.
///
/// # Arguments
///
/// * `message` - Message bytes to hash
///
/// # Returns
///
/// 32-byte SHA3-256 hash.
#[must_use]
fn compute_message_hash(message: &[u8]) -> [u8; MESSAGE_HASH_SIZE] {
    let mut hasher = Sha3_256::new();
    hasher.update(message);
    let result = hasher.finalize();

    let mut hash = [0u8; MESSAGE_HASH_SIZE];
    hash.copy_from_slice(&result);
    hash
}

/// Gets current Unix timestamp in seconds.
///
/// # Returns
///
/// Current time as seconds since Unix epoch.
/// Returns 0 if system time is before Unix epoch (should never happen).
#[must_use]
fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ════════════════════════════════════════════════════════════════════════════════
// ENCODING FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════════

/// Encodes `SigningRequestProto` to bytes.
///
/// # Arguments
///
/// * `req` - Reference to proto message
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
pub fn encode_signing_request(req: &SigningRequestProto) -> Vec<u8> {
    bincode::serialize(req).unwrap_or_else(|_| Vec::new())
}

/// Decodes bytes to `SigningRequestProto`.
///
/// # Arguments
///
/// * `bytes` - Bincode-encoded bytes
///
/// # Returns
///
/// - `Ok(SigningRequestProto)` if decoding and validation succeed
/// - `Err(SigningDecodeError)` if decoding or validation fails
///
/// # Note
///
/// This function calls `validate()` after deserialization.
pub fn decode_signing_request(bytes: &[u8]) -> Result<SigningRequestProto, SigningDecodeError> {
    let proto: SigningRequestProto =
        bincode::deserialize(bytes).map_err(|e| SigningDecodeError::DeserializationFailed {
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
    // HELPER FUNCTIONS
    // ────────────────────────────────────────────────────────────────────────────

    fn make_valid_proto() -> SigningRequestProto {
        let message = b"test message".to_vec();
        let message_hash = compute_message_hash(&message);

        SigningRequestProto {
            session_id: vec![0xAA; 32],
            message,
            message_hash: message_hash.to_vec(),
            required_signers: vec![vec![0xBB; 32], vec![0xCC; 32]],
            epoch: 1,
            timeout_secs: 60,
            request_timestamp: 1234567890,
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // VALIDATION TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_validate_valid_proto() {
        let proto = make_valid_proto();
        assert!(proto.validate().is_ok());
    }

    #[test]
    fn test_validate_invalid_session_id_length() {
        let mut proto = make_valid_proto();
        proto.session_id = vec![0xAA; 16]; // Wrong length

        let result = proto.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SigningValidationError::InvalidSessionIdLength { expected: 32, got: 16 }
        ));
    }

    #[test]
    fn test_validate_invalid_message_hash_length() {
        let mut proto = make_valid_proto();
        proto.message_hash = vec![0x00; 16]; // Wrong length

        let result = proto.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SigningValidationError::InvalidMessageHashLength { expected: 32, got: 16 }
        ));
    }

    #[test]
    fn test_validate_empty_required_signers() {
        let mut proto = make_valid_proto();
        proto.required_signers = vec![]; // Empty

        let result = proto.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SigningValidationError::EmptyRequiredSigners
        ));
    }

    #[test]
    fn test_validate_invalid_signer_id_length() {
        let mut proto = make_valid_proto();
        proto.required_signers = vec![vec![0xBB; 32], vec![0xCC; 16]]; // Second one wrong

        let result = proto.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SigningValidationError::InvalidSignerIdLength { index: 1, expected: 32, got: 16 }
        ));
    }

    #[test]
    fn test_validate_invalid_timeout() {
        let mut proto = make_valid_proto();
        proto.timeout_secs = 0; // Invalid

        let result = proto.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SigningValidationError::InvalidTimeout { timeout_secs: 0 }
        ));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // MESSAGE HASH TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_compute_message_hash_deterministic() {
        let message = b"test message";
        let hash1 = compute_message_hash(message);
        let hash2 = compute_message_hash(message);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_compute_message_hash_different_for_different_messages() {
        let hash1 = compute_message_hash(b"message 1");
        let hash2 = compute_message_hash(b"message 2");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_compute_message_hash_empty_message() {
        let hash = compute_message_hash(b"");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_verify_message_hash_valid() {
        let proto = make_valid_proto();
        assert!(proto.verify_message_hash());
    }

    #[test]
    fn test_verify_message_hash_invalid() {
        let mut proto = make_valid_proto();
        proto.message_hash = vec![0x00; 32]; // Wrong hash
        assert!(!proto.verify_message_hash());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // ENCODING TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_encode_decode_roundtrip() {
        let proto = make_valid_proto();

        let encoded = encode_signing_request(&proto);
        let decoded = decode_signing_request(&encoded);

        assert!(decoded.is_ok());
        assert_eq!(proto, decoded.expect("valid"));
    }

    #[test]
    fn test_encode_deterministic() {
        let proto = make_valid_proto();

        let encoded1 = encode_signing_request(&proto);
        let encoded2 = encode_signing_request(&proto);

        assert_eq!(encoded1, encoded2);
    }

    #[test]
    fn test_decode_invalid_bytes() {
        let invalid_bytes = vec![0xFF; 10];
        let result = decode_signing_request(&invalid_bytes);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SigningDecodeError::DeserializationFailed { .. }
        ));
    }

    #[test]
    fn test_decode_validates_after_deserialization() {
        // Create invalid proto manually and serialize
        let invalid_proto = SigningRequestProto {
            session_id: vec![0xAA; 16], // Invalid length
            message: b"test".to_vec(),
            message_hash: vec![0x00; 32],
            required_signers: vec![vec![0xBB; 32]],
            epoch: 1,
            timeout_secs: 60,
            request_timestamp: 12345,
        };

        // Serialize (bypassing validation)
        let bytes = bincode::serialize(&invalid_proto).expect("serialize");

        // Decode should fail validation
        let result = decode_signing_request(&bytes);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SigningDecodeError::ValidationFailed { .. }
        ));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // FROM_RAW TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_from_raw_computes_hash() {
        let message = b"hello world".to_vec();
        let proto = SigningRequestProto::from_raw(
            vec![0xAA; 32],
            message.clone(),
            vec![vec![0xBB; 32]],
            1,
            60,
        );

        // message_hash should be computed
        let expected_hash = compute_message_hash(&message);
        assert_eq!(proto.message_hash, expected_hash.to_vec());
    }

    #[test]
    fn test_from_raw_sets_timestamp() {
        let proto = SigningRequestProto::from_raw(
            vec![0xAA; 32],
            b"test".to_vec(),
            vec![vec![0xBB; 32]],
            1,
            60,
        );

        // request_timestamp should be set to current time (approximately)
        let now = current_unix_timestamp();
        assert!(proto.request_timestamp <= now);
        assert!(proto.request_timestamp > now - 10); // Within 10 seconds
    }

    // ────────────────────────────────────────────────────────────────────────────
    // ERROR DISPLAY TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_validation_error_session_id_display() {
        let error = SigningValidationError::InvalidSessionIdLength {
            expected: 32,
            got: 16,
        };
        let display = format!("{}", error);
        assert!(display.contains("session_id"));
        assert!(display.contains("32"));
        assert!(display.contains("16"));
    }

    #[test]
    fn test_validation_error_message_hash_display() {
        let error = SigningValidationError::InvalidMessageHashLength {
            expected: 32,
            got: 64,
        };
        let display = format!("{}", error);
        assert!(display.contains("message_hash"));
        assert!(display.contains("32"));
        assert!(display.contains("64"));
    }

    #[test]
    fn test_validation_error_empty_signers_display() {
        let error = SigningValidationError::EmptyRequiredSigners;
        let display = format!("{}", error);
        assert!(display.contains("required_signers"));
        assert!(display.contains("empty"));
    }

    #[test]
    fn test_validation_error_signer_id_display() {
        let error = SigningValidationError::InvalidSignerIdLength {
            index: 2,
            expected: 32,
            got: 48,
        };
        let display = format!("{}", error);
        assert!(display.contains("required_signers[2]"));
        assert!(display.contains("32"));
        assert!(display.contains("48"));
    }

    #[test]
    fn test_validation_error_timeout_display() {
        let error = SigningValidationError::InvalidTimeout { timeout_secs: 0 };
        let display = format!("{}", error);
        assert!(display.contains("timeout_secs"));
        assert!(display.contains("0"));
    }

    #[test]
    fn test_decode_error_display() {
        let error = SigningDecodeError::DeserializationFailed {
            reason: "test error".to_string(),
        };
        let display = format!("{}", error);
        assert!(display.contains("deserialization"));
        assert!(display.contains("test error"));
    }

    #[test]
    fn test_decode_error_from_validation_error() {
        let validation_error = SigningValidationError::InvalidTimeout { timeout_secs: 0 };
        let decode_error: SigningDecodeError = validation_error.into();

        assert!(matches!(
            decode_error,
            SigningDecodeError::ValidationFailed { .. }
        ));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SEND + SYNC TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SigningRequestProto>();
        assert_send_sync::<SigningValidationError>();
        assert_send_sync::<SigningDecodeError>();
    }

    // ────────────────────────────────────────────────────────────────────────────
    // EDGE CASE TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_large_message() {
        let message = vec![0x42u8; 1024 * 1024]; // 1MB message
        let proto = SigningRequestProto::from_raw(
            vec![0xAA; 32],
            message,
            vec![vec![0xBB; 32]],
            1,
            60,
        );

        assert!(proto.validate().is_ok());
        assert!(proto.verify_message_hash());
    }

    #[test]
    fn test_many_signers() {
        let signers: Vec<Vec<u8>> = (0..100).map(|i| vec![i as u8; 32]).collect();
        let proto = SigningRequestProto::from_raw(
            vec![0xAA; 32],
            b"test".to_vec(),
            signers,
            1,
            60,
        );

        assert!(proto.validate().is_ok());
        assert_eq!(proto.required_signers.len(), 100);
    }

    #[test]
    fn test_single_signer() {
        let proto = SigningRequestProto::from_raw(
            vec![0xAA; 32],
            b"test".to_vec(),
            vec![vec![0xBB; 32]],
            1,
            60,
        );

        assert!(proto.validate().is_ok());
        assert_eq!(proto.required_signers.len(), 1);
    }
}