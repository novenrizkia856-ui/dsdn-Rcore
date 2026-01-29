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

/// Expected size for hiding commitment field.
pub const HIDING_SIZE: usize = 32;

/// Expected size for binding commitment field.
pub const BINDING_SIZE: usize = 32;

/// Expected size for signature_share field.
pub const SIGNATURE_SHARE_SIZE: usize = 32;

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

    // ════════════════════════════════════════════════════════════════════════════════
    // SIGNING COMMITMENT VALIDATION ERRORS
    // ════════════════════════════════════════════════════════════════════════════════

    /// commitment signer_id length tidak valid.
    InvalidCommitmentSignerIdLength {
        /// Expected length.
        expected: usize,
        /// Actual length.
        got: usize,
    },

    /// hiding length tidak valid.
    InvalidHidingLength {
        /// Expected length.
        expected: usize,
        /// Actual length.
        got: usize,
    },

    /// binding length tidak valid.
    InvalidBindingLength {
        /// Expected length.
        expected: usize,
        /// Actual length.
        got: usize,
    },

    // ════════════════════════════════════════════════════════════════════════════════
    // PARTIAL SIGNATURE VALIDATION ERRORS
    // ════════════════════════════════════════════════════════════════════════════════

    /// signature_share length tidak valid.
    InvalidSignatureShareLength {
        /// Expected length.
        expected: usize,
        /// Actual length.
        got: usize,
    },

    /// Nested commitment validation failed.
    InvalidNestedCommitment {
        /// Underlying error message.
        reason: String,
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
            SigningValidationError::InvalidCommitmentSignerIdLength { expected, got } => {
                write!(
                    f,
                    "invalid commitment signer_id length: expected {}, got {}",
                    expected, got
                )
            }
            SigningValidationError::InvalidHidingLength { expected, got } => {
                write!(
                    f,
                    "invalid hiding length: expected {}, got {}",
                    expected, got
                )
            }
            SigningValidationError::InvalidBindingLength { expected, got } => {
                write!(
                    f,
                    "invalid binding length: expected {}, got {}",
                    expected, got
                )
            }
            SigningValidationError::InvalidSignatureShareLength { expected, got } => {
                write!(
                    f,
                    "invalid signature_share length: expected {}, got {}",
                    expected, got
                )
            }
            SigningValidationError::InvalidNestedCommitment { reason } => {
                write!(f, "invalid nested commitment: {}", reason)
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
// SIGNING COMMITMENT PROTO
// ════════════════════════════════════════════════════════════════════════════════

/// Proto message untuk Signing Commitment.
///
/// `SigningCommitmentProto` adalah representasi serializable dari signing commitment
/// yang digunakan dalam FROST threshold signing.
///
/// ## Field Sizes
///
/// | Field | Expected Size |
/// |-------|---------------|
/// | `session_id` | 32 bytes |
/// | `signer_id` | 32 bytes |
/// | `hiding` | 32 bytes |
/// | `binding` | 32 bytes |
///
/// ## Validation
///
/// Gunakan `validate()` untuk memastikan semua field memiliki panjang yang benar.
///
/// ## Example
///
/// ```rust,ignore
/// use dsdn_proto::tss::signing::{SigningCommitmentProto, encode_signing_commitment, decode_signing_commitment};
///
/// let proto = SigningCommitmentProto {
///     session_id: vec![0u8; 32],
///     signer_id: vec![0u8; 32],
///     hiding: vec![0x01; 32],
///     binding: vec![0x02; 32],
///     timestamp: 1234567890,
/// };
///
/// // Validate
/// assert!(proto.validate().is_ok());
///
/// // Encode
/// let bytes = encode_signing_commitment(&proto);
///
/// // Decode (includes validation)
/// let decoded = decode_signing_commitment(&bytes).unwrap();
/// assert_eq!(proto, decoded);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningCommitmentProto {
    /// Session identifier (MUST be 32 bytes).
    pub session_id: Vec<u8>,

    /// Signer identifier (MUST be 32 bytes).
    pub signer_id: Vec<u8>,

    /// Hiding nonce commitment (MUST be 32 bytes).
    pub hiding: Vec<u8>,

    /// Binding nonce commitment (MUST be 32 bytes).
    pub binding: Vec<u8>,

    /// Unix timestamp when commitment was created.
    pub timestamp: u64,
}

impl SigningCommitmentProto {
    /// Validates all field lengths.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if all fields have correct lengths
    /// - `Err(SigningValidationError)` if any validation fails
    ///
    /// # Validation Rules
    ///
    /// - `session_id.len() == 32`
    /// - `signer_id.len() == 32`
    /// - `hiding.len() == 32`
    /// - `binding.len() == 32`
    pub fn validate(&self) -> Result<(), SigningValidationError> {
        // Validate session_id
        if self.session_id.len() != SESSION_ID_SIZE {
            return Err(SigningValidationError::InvalidSessionIdLength {
                expected: SESSION_ID_SIZE,
                got: self.session_id.len(),
            });
        }

        // Validate signer_id
        if self.signer_id.len() != SIGNER_ID_SIZE {
            return Err(SigningValidationError::InvalidCommitmentSignerIdLength {
                expected: SIGNER_ID_SIZE,
                got: self.signer_id.len(),
            });
        }

        // Validate hiding
        if self.hiding.len() != HIDING_SIZE {
            return Err(SigningValidationError::InvalidHidingLength {
                expected: HIDING_SIZE,
                got: self.hiding.len(),
            });
        }

        // Validate binding
        if self.binding.len() != BINDING_SIZE {
            return Err(SigningValidationError::InvalidBindingLength {
                expected: BINDING_SIZE,
                got: self.binding.len(),
            });
        }

        Ok(())
    }

    /// Creates proto from native commitment types.
    ///
    /// # Arguments
    ///
    /// * `session_id` - Reference to `SessionId`
    /// * `signer_id` - Reference to `SignerId`
    /// * `commitment` - Reference to `SigningCommitment`
    ///
    /// # Returns
    ///
    /// A `SigningCommitmentProto` with all bytes copied and timestamp set.
    #[cfg(feature = "tss-conversion")]
    #[must_use]
    pub fn from_commitment(
        session_id: &dsdn_tss::SessionId,
        signer_id: &dsdn_tss::SignerId,
        commitment: &dsdn_tss::SigningCommitment,
    ) -> Self {
        Self {
            session_id: session_id.as_bytes().to_vec(),
            signer_id: signer_id.as_bytes().to_vec(),
            hiding: commitment.hiding().to_vec(),
            binding: commitment.binding().to_vec(),
            timestamp: current_unix_timestamp(),
        }
    }

    /// Converts proto back to native commitment types.
    ///
    /// # Returns
    ///
    /// - `Ok((SessionId, SignerId, SigningCommitment))` if valid
    /// - `Err(SigningDecodeError)` if validation or conversion fails
    ///
    /// # Note
    ///
    /// This method calls `validate()` internally.
    #[cfg(feature = "tss-conversion")]
    pub fn to_commitment(
        &self,
    ) -> Result<
        (
            dsdn_tss::SessionId,
            dsdn_tss::SignerId,
            dsdn_tss::SigningCommitment,
        ),
        SigningDecodeError,
    > {
        // Validate first
        self.validate()?;

        // Convert session_id
        let mut session_bytes = [0u8; SESSION_ID_SIZE];
        session_bytes.copy_from_slice(&self.session_id);
        let session_id = dsdn_tss::SessionId::from_bytes(session_bytes);

        // Convert signer_id
        let mut signer_bytes = [0u8; SIGNER_ID_SIZE];
        signer_bytes.copy_from_slice(&self.signer_id);
        let signer_id = dsdn_tss::SignerId::from_bytes(signer_bytes);

        // Convert commitment
        let mut hiding = [0u8; HIDING_SIZE];
        hiding.copy_from_slice(&self.hiding);

        let mut binding = [0u8; BINDING_SIZE];
        binding.copy_from_slice(&self.binding);

        let commitment = dsdn_tss::SigningCommitment::from_parts(hiding, binding)
            .map_err(|e| SigningDecodeError::DeserializationFailed {
                reason: format!("invalid commitment: {}", e),
            })?;

        Ok((session_id, signer_id, commitment))
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// SIGNING COMMITMENT ENCODING FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════════

/// Encodes `SigningCommitmentProto` to bytes.
///
/// # Arguments
///
/// * `commitment` - Reference to proto message
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
pub fn encode_signing_commitment(commitment: &SigningCommitmentProto) -> Vec<u8> {
    bincode::serialize(commitment).unwrap_or_else(|_| Vec::new())
}

/// Decodes bytes to `SigningCommitmentProto`.
///
/// # Arguments
///
/// * `bytes` - Bincode-encoded bytes
///
/// # Returns
///
/// - `Ok(SigningCommitmentProto)` if decoding and validation succeed
/// - `Err(SigningDecodeError)` if decoding or validation fails
///
/// # Note
///
/// This function calls `validate()` after deserialization.
pub fn decode_signing_commitment(bytes: &[u8]) -> Result<SigningCommitmentProto, SigningDecodeError> {
    let proto: SigningCommitmentProto =
        bincode::deserialize(bytes).map_err(|e| SigningDecodeError::DeserializationFailed {
            reason: e.to_string(),
        })?;

    // Validate after deserialization
    proto.validate()?;

    Ok(proto)
}

// ════════════════════════════════════════════════════════════════════════════════
// PARTIAL SIGNATURE PROTO
// ════════════════════════════════════════════════════════════════════════════════

/// Proto message untuk Partial Signature.
///
/// `PartialSignatureProto` adalah representasi serializable dari partial signature
/// yang digunakan dalam FROST threshold signing.
///
/// ## Field Sizes
///
/// | Field | Expected Size |
/// |-------|---------------|
/// | `session_id` | 32 bytes |
/// | `signer_id` | 32 bytes |
/// | `signature_share` | 32 bytes |
/// | `commitment` | Nested SigningCommitmentProto |
///
/// ## Important
///
/// Partial signature WAJIB menyertakan commitment. Partial signature tanpa
/// commitment adalah INVALID.
///
/// ## Example
///
/// ```rust,ignore
/// use dsdn_proto::tss::signing::{
///     SigningCommitmentProto, PartialSignatureProto,
///     encode_partial_signature, decode_partial_signature,
/// };
///
/// let commitment = SigningCommitmentProto {
///     session_id: vec![0u8; 32],
///     signer_id: vec![0u8; 32],
///     hiding: vec![0x01; 32],
///     binding: vec![0x02; 32],
///     timestamp: 1234567890,
/// };
///
/// let proto = PartialSignatureProto {
///     session_id: vec![0u8; 32],
///     signer_id: vec![0u8; 32],
///     signature_share: vec![0x03; 32],
///     commitment,
/// };
///
/// // Validate
/// assert!(proto.validate().is_ok());
///
/// // Encode
/// let bytes = encode_partial_signature(&proto);
///
/// // Decode (includes validation)
/// let decoded = decode_partial_signature(&bytes).unwrap();
/// assert_eq!(proto, decoded);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartialSignatureProto {
    /// Session identifier (MUST be 32 bytes).
    pub session_id: Vec<u8>,

    /// Signer identifier (MUST be 32 bytes).
    pub signer_id: Vec<u8>,

    /// Signature share scalar (MUST be 32 bytes).
    pub signature_share: Vec<u8>,

    /// Commitment used in signing round (REQUIRED).
    pub commitment: SigningCommitmentProto,
}

impl PartialSignatureProto {
    /// Validates all field lengths and nested commitment.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if all fields are valid
    /// - `Err(SigningValidationError)` if any validation fails
    ///
    /// # Validation Rules
    ///
    /// - `session_id.len() == 32`
    /// - `signer_id.len() == 32`
    /// - `signature_share.len() == 32`
    /// - `commitment.validate()` succeeds
    pub fn validate(&self) -> Result<(), SigningValidationError> {
        // Validate session_id
        if self.session_id.len() != SESSION_ID_SIZE {
            return Err(SigningValidationError::InvalidSessionIdLength {
                expected: SESSION_ID_SIZE,
                got: self.session_id.len(),
            });
        }

        // Validate signer_id
        if self.signer_id.len() != SIGNER_ID_SIZE {
            return Err(SigningValidationError::InvalidCommitmentSignerIdLength {
                expected: SIGNER_ID_SIZE,
                got: self.signer_id.len(),
            });
        }

        // Validate signature_share
        if self.signature_share.len() != SIGNATURE_SHARE_SIZE {
            return Err(SigningValidationError::InvalidSignatureShareLength {
                expected: SIGNATURE_SHARE_SIZE,
                got: self.signature_share.len(),
            });
        }

        // Validate nested commitment
        self.commitment.validate().map_err(|e| {
            SigningValidationError::InvalidNestedCommitment {
                reason: e.to_string(),
            }
        })?;

        Ok(())
    }

    /// Creates proto from native partial signature types.
    ///
    /// # Arguments
    ///
    /// * `session_id` - Reference to `SessionId`
    /// * `partial` - Reference to `PartialSignature`
    ///
    /// # Returns
    ///
    /// A `PartialSignatureProto` with all bytes copied.
    #[cfg(feature = "tss-conversion")]
    #[must_use]
    pub fn from_partial(
        session_id: &dsdn_tss::SessionId,
        partial: &dsdn_tss::signing::PartialSignature,
    ) -> Self {
        let commitment = SigningCommitmentProto {
            session_id: session_id.as_bytes().to_vec(),
            signer_id: partial.signer_id().as_bytes().to_vec(),
            hiding: partial.commitment().hiding().to_vec(),
            binding: partial.commitment().binding().to_vec(),
            timestamp: current_unix_timestamp(),
        };

        Self {
            session_id: session_id.as_bytes().to_vec(),
            signer_id: partial.signer_id().as_bytes().to_vec(),
            signature_share: partial.signature_share().as_bytes().to_vec(),
            commitment,
        }
    }

    /// Converts proto back to native partial signature types.
    ///
    /// # Returns
    ///
    /// - `Ok((SessionId, PartialSignature))` if valid
    /// - `Err(SigningDecodeError)` if validation or conversion fails
    ///
    /// # Note
    ///
    /// This method calls `validate()` internally.
    #[cfg(feature = "tss-conversion")]
    pub fn to_partial(
        &self,
    ) -> Result<(dsdn_tss::SessionId, dsdn_tss::signing::PartialSignature), SigningDecodeError> {
        // Validate first
        self.validate()?;

        // Convert session_id
        let mut session_bytes = [0u8; SESSION_ID_SIZE];
        session_bytes.copy_from_slice(&self.session_id);
        let session_id = dsdn_tss::SessionId::from_bytes(session_bytes);

        // Convert signer_id
        let mut signer_bytes = [0u8; SIGNER_ID_SIZE];
        signer_bytes.copy_from_slice(&self.signer_id);
        let signer_id = dsdn_tss::SignerId::from_bytes(signer_bytes);

        // Convert signature_share
        let mut share_bytes = [0u8; SIGNATURE_SHARE_SIZE];
        share_bytes.copy_from_slice(&self.signature_share);
        let signature_share = dsdn_tss::FrostSignatureShare::from_bytes(share_bytes)
            .map_err(|e| SigningDecodeError::DeserializationFailed {
                reason: format!("invalid signature_share: {}", e),
            })?;

        // Convert commitment
        let mut hiding = [0u8; HIDING_SIZE];
        hiding.copy_from_slice(&self.commitment.hiding);

        let mut binding = [0u8; BINDING_SIZE];
        binding.copy_from_slice(&self.commitment.binding);

        let commitment = dsdn_tss::SigningCommitment::from_parts(hiding, binding)
            .map_err(|e| SigningDecodeError::DeserializationFailed {
                reason: format!("invalid commitment: {}", e),
            })?;

        // Build PartialSignature
        let partial = dsdn_tss::signing::PartialSignature::new(
            signer_id,
            signature_share,
            commitment,
        );

        Ok((session_id, partial))
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// PARTIAL SIGNATURE ENCODING FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════════

/// Encodes `PartialSignatureProto` to bytes.
///
/// # Arguments
///
/// * `partial` - Reference to proto message
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
pub fn encode_partial_signature(partial: &PartialSignatureProto) -> Vec<u8> {
    bincode::serialize(partial).unwrap_or_else(|_| Vec::new())
}

/// Decodes bytes to `PartialSignatureProto`.
///
/// # Arguments
///
/// * `bytes` - Bincode-encoded bytes
///
/// # Returns
///
/// - `Ok(PartialSignatureProto)` if decoding and validation succeed
/// - `Err(SigningDecodeError)` if decoding or validation fails
///
/// # Note
///
/// This function calls `validate()` after deserialization.
pub fn decode_partial_signature(bytes: &[u8]) -> Result<PartialSignatureProto, SigningDecodeError> {
    let proto: PartialSignatureProto =
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

    // ════════════════════════════════════════════════════════════════════════════════
    // SIGNING COMMITMENT PROTO TESTS
    // ════════════════════════════════════════════════════════════════════════════════

    fn make_valid_commitment() -> SigningCommitmentProto {
        SigningCommitmentProto {
            session_id: vec![0xAA; 32],
            signer_id: vec![0xBB; 32],
            hiding: vec![0x01; 32],
            binding: vec![0x02; 32],
            timestamp: 1234567890,
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // COMMITMENT VALIDATION TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_commitment_validate_valid() {
        let proto = make_valid_commitment();
        assert!(proto.validate().is_ok());
    }

    #[test]
    fn test_commitment_validate_invalid_session_id() {
        let mut proto = make_valid_commitment();
        proto.session_id = vec![0xAA; 16]; // Wrong length

        let result = proto.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SigningValidationError::InvalidSessionIdLength { expected: 32, got: 16 }
        ));
    }

    #[test]
    fn test_commitment_validate_invalid_signer_id() {
        let mut proto = make_valid_commitment();
        proto.signer_id = vec![0xBB; 64]; // Wrong length

        let result = proto.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SigningValidationError::InvalidCommitmentSignerIdLength { expected: 32, got: 64 }
        ));
    }

    #[test]
    fn test_commitment_validate_invalid_hiding() {
        let mut proto = make_valid_commitment();
        proto.hiding = vec![0x01; 16]; // Wrong length

        let result = proto.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SigningValidationError::InvalidHidingLength { expected: 32, got: 16 }
        ));
    }

    #[test]
    fn test_commitment_validate_invalid_binding() {
        let mut proto = make_valid_commitment();
        proto.binding = vec![0x02; 48]; // Wrong length

        let result = proto.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SigningValidationError::InvalidBindingLength { expected: 32, got: 48 }
        ));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // COMMITMENT ENCODING TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_commitment_encode_decode_roundtrip() {
        let proto = make_valid_commitment();

        let encoded = encode_signing_commitment(&proto);
        let decoded = decode_signing_commitment(&encoded);

        assert!(decoded.is_ok());
        assert_eq!(proto, decoded.expect("valid"));
    }

    #[test]
    fn test_commitment_encode_deterministic() {
        let proto = make_valid_commitment();

        let encoded1 = encode_signing_commitment(&proto);
        let encoded2 = encode_signing_commitment(&proto);

        assert_eq!(encoded1, encoded2);
    }

    #[test]
    fn test_commitment_decode_invalid_bytes() {
        let invalid_bytes = vec![0xFF; 10];
        let result = decode_signing_commitment(&invalid_bytes);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SigningDecodeError::DeserializationFailed { .. }
        ));
    }

    #[test]
    fn test_commitment_decode_validates_after_deserialization() {
        // Create invalid proto manually and serialize
        let invalid_proto = SigningCommitmentProto {
            session_id: vec![0xAA; 16], // Invalid length
            signer_id: vec![0xBB; 32],
            hiding: vec![0x01; 32],
            binding: vec![0x02; 32],
            timestamp: 12345,
        };

        // Serialize (bypassing validation)
        let bytes = bincode::serialize(&invalid_proto).expect("serialize");

        // Decode should fail validation
        let result = decode_signing_commitment(&bytes);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SigningDecodeError::ValidationFailed { .. }
        ));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // COMMITMENT ERROR DISPLAY TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_commitment_validation_error_signer_id_display() {
        let error = SigningValidationError::InvalidCommitmentSignerIdLength {
            expected: 32,
            got: 64,
        };
        let display = format!("{}", error);
        assert!(display.contains("signer_id"));
        assert!(display.contains("32"));
        assert!(display.contains("64"));
    }

    #[test]
    fn test_commitment_validation_error_hiding_display() {
        let error = SigningValidationError::InvalidHidingLength {
            expected: 32,
            got: 16,
        };
        let display = format!("{}", error);
        assert!(display.contains("hiding"));
        assert!(display.contains("32"));
        assert!(display.contains("16"));
    }

    #[test]
    fn test_commitment_validation_error_binding_display() {
        let error = SigningValidationError::InvalidBindingLength {
            expected: 32,
            got: 48,
        };
        let display = format!("{}", error);
        assert!(display.contains("binding"));
        assert!(display.contains("32"));
        assert!(display.contains("48"));
    }

    // ════════════════════════════════════════════════════════════════════════════════
    // PARTIAL SIGNATURE PROTO TESTS
    // ════════════════════════════════════════════════════════════════════════════════

    fn make_valid_partial_signature() -> PartialSignatureProto {
        PartialSignatureProto {
            session_id: vec![0xAA; 32],
            signer_id: vec![0xBB; 32],
            signature_share: vec![0x03; 32],
            commitment: make_valid_commitment(),
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // PARTIAL SIGNATURE VALIDATION TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_partial_signature_validate_valid() {
        let proto = make_valid_partial_signature();
        assert!(proto.validate().is_ok());
    }

    #[test]
    fn test_partial_signature_validate_invalid_session_id() {
        let mut proto = make_valid_partial_signature();
        proto.session_id = vec![0xAA; 16]; // Wrong length

        let result = proto.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SigningValidationError::InvalidSessionIdLength { expected: 32, got: 16 }
        ));
    }

    #[test]
    fn test_partial_signature_validate_invalid_signer_id() {
        let mut proto = make_valid_partial_signature();
        proto.signer_id = vec![0xBB; 64]; // Wrong length

        let result = proto.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SigningValidationError::InvalidCommitmentSignerIdLength { expected: 32, got: 64 }
        ));
    }

    #[test]
    fn test_partial_signature_validate_invalid_signature_share() {
        let mut proto = make_valid_partial_signature();
        proto.signature_share = vec![0x03; 16]; // Wrong length

        let result = proto.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SigningValidationError::InvalidSignatureShareLength { expected: 32, got: 16 }
        ));
    }

    #[test]
    fn test_partial_signature_validate_invalid_nested_commitment() {
        let mut proto = make_valid_partial_signature();
        proto.commitment.hiding = vec![0x01; 16]; // Invalid hiding in nested commitment

        let result = proto.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SigningValidationError::InvalidNestedCommitment { .. }
        ));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // PARTIAL SIGNATURE ENCODING TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_partial_signature_encode_decode_roundtrip() {
        let proto = make_valid_partial_signature();

        let encoded = encode_partial_signature(&proto);
        let decoded = decode_partial_signature(&encoded);

        assert!(decoded.is_ok());
        assert_eq!(proto, decoded.expect("valid"));
    }

    #[test]
    fn test_partial_signature_encode_deterministic() {
        let proto = make_valid_partial_signature();

        let encoded1 = encode_partial_signature(&proto);
        let encoded2 = encode_partial_signature(&proto);

        assert_eq!(encoded1, encoded2);
    }

    #[test]
    fn test_partial_signature_decode_invalid_bytes() {
        let invalid_bytes = vec![0xFF; 10];
        let result = decode_partial_signature(&invalid_bytes);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SigningDecodeError::DeserializationFailed { .. }
        ));
    }

    #[test]
    fn test_partial_signature_decode_validates_after_deserialization() {
        // Create invalid proto manually
        let invalid_proto = PartialSignatureProto {
            session_id: vec![0xAA; 16], // Invalid length
            signer_id: vec![0xBB; 32],
            signature_share: vec![0x03; 32],
            commitment: make_valid_commitment(),
        };

        // Serialize (bypassing validation)
        let bytes = bincode::serialize(&invalid_proto).expect("serialize");

        // Decode should fail validation
        let result = decode_partial_signature(&bytes);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SigningDecodeError::ValidationFailed { .. }
        ));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // PARTIAL SIGNATURE ERROR DISPLAY TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_partial_signature_validation_error_share_display() {
        let error = SigningValidationError::InvalidSignatureShareLength {
            expected: 32,
            got: 64,
        };
        let display = format!("{}", error);
        assert!(display.contains("signature_share"));
        assert!(display.contains("32"));
        assert!(display.contains("64"));
    }

    #[test]
    fn test_partial_signature_validation_error_nested_display() {
        let error = SigningValidationError::InvalidNestedCommitment {
            reason: "test error".to_string(),
        };
        let display = format!("{}", error);
        assert!(display.contains("nested commitment"));
        assert!(display.contains("test error"));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // COMMITMENT & PARTIAL SIGNATURE SEND + SYNC TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_commitment_and_partial_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SigningCommitmentProto>();
        assert_send_sync::<PartialSignatureProto>();
    }
}