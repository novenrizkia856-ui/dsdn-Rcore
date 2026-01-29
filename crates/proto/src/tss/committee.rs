//! # Committee Protocol Messages
//!
//! Module ini menyediakan proto message types untuk coordinator committee.
//!
//! ## Overview
//!
//! Committee proto types adalah representasi serializable dari coordinator
//! committee yang digunakan untuk transport dan storage.
//!
//! ## CoordinatorMemberProto
//!
//! `CoordinatorMemberProto` merepresentasikan anggota committee:
//!
//! | Field | Size | Description |
//! |-------|------|-------------|
//! | `id` | 32 bytes | Coordinator identifier |
//! | `validator_id` | 32 bytes | Validator identifier |
//! | `pubkey` | 32 bytes | Public key untuk TSS |
//! | `stake` | 8 bytes | Jumlah stake |
//! | `joined_at` | 8 bytes | Unix timestamp |
//!
//! ## CoordinatorCommitteeProto
//!
//! `CoordinatorCommitteeProto` merepresentasikan committee:
//!
//! | Field | Size | Description |
//! |-------|------|-------------|
//! | `members` | Variable | List of members |
//! | `threshold` | 4 bytes | Threshold untuk signing |
//! | `epoch` | 8 bytes | Epoch number |
//! | `epoch_start` | 8 bytes | Unix timestamp |
//! | `epoch_duration_secs` | 8 bytes | Durasi epoch |
//! | `group_pubkey` | 32 bytes | Shared public key |
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
use std::collections::HashSet;
use std::fmt;
use crate::tss::signing;
// ════════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════════

/// Expected size for coordinator_id field.
pub const COORDINATOR_ID_SIZE: usize = 32;

/// Expected size for validator_id field.
pub const VALIDATOR_ID_SIZE: usize = 32;

/// Expected size for pubkey field.
pub const PUBKEY_SIZE: usize = 32;

/// Expected size for group_pubkey field.
pub const GROUP_PUBKEY_SIZE: usize = 32;

/// Expected size for workload_id field.
pub const WORKLOAD_ID_SIZE: usize = 32;

/// Expected size for blob_hash field.
pub const BLOB_HASH_SIZE: usize = 32;

/// Expected size for node_id field.
pub const NODE_ID_SIZE: usize = 32;

/// Expected size for committee_hash field.
pub const COMMITTEE_HASH_SIZE: usize = 32;

// ════════════════════════════════════════════════════════════════════════════════
// ERROR TYPES
// ════════════════════════════════════════════════════════════════════════════════

/// Error type untuk validasi committee proto messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitteeValidationError {
    // ════════════════════════════════════════════════════════════════════════════════
    // MEMBER VALIDATION ERRORS
    // ════════════════════════════════════════════════════════════════════════════════

    /// id length tidak valid.
    InvalidIdLength {
        /// Expected length.
        expected: usize,
        /// Actual length.
        got: usize,
    },

    /// validator_id length tidak valid.
    InvalidValidatorIdLength {
        /// Expected length.
        expected: usize,
        /// Actual length.
        got: usize,
    },

    /// pubkey length tidak valid.
    InvalidPubkeyLength {
        /// Expected length.
        expected: usize,
        /// Actual length.
        got: usize,
    },

    /// stake tidak valid (must be > 0).
    InvalidStake {
        /// Actual stake value.
        stake: u64,
    },

    // ════════════════════════════════════════════════════════════════════════════════
    // COMMITTEE VALIDATION ERRORS
    // ════════════════════════════════════════════════════════════════════════════════

    /// members kosong.
    EmptyMembers,

    /// threshold tidak valid.
    InvalidThreshold {
        /// Threshold value.
        threshold: u32,
        /// Member count.
        member_count: usize,
    },

    /// epoch_duration_secs tidak valid (must be > 0).
    InvalidEpochDuration {
        /// Actual duration.
        epoch_duration_secs: u64,
    },

    /// group_pubkey length tidak valid.
    InvalidGroupPubkeyLength {
        /// Expected length.
        expected: usize,
        /// Actual length.
        got: usize,
    },

    /// Duplicate member id detected.
    DuplicateMemberId {
        /// Index of duplicate member.
        index: usize,
    },

    /// Member validation failed.
    InvalidMember {
        /// Index of invalid member.
        index: usize,
        /// Underlying error.
        reason: String,
    },

    // ════════════════════════════════════════════════════════════════════════════════
    // RECEIPT DATA VALIDATION ERRORS
    // ════════════════════════════════════════════════════════════════════════════════

    /// workload_id length tidak valid.
    InvalidWorkloadIdLength {
        /// Expected length.
        expected: usize,
        /// Actual length.
        got: usize,
    },

    /// blob_hash length tidak valid.
    InvalidBlobHashLength {
        /// Expected length.
        expected: usize,
        /// Actual length.
        got: usize,
    },

    /// placement node_id length tidak valid.
    InvalidPlacementNodeLength {
        /// Index of invalid node.
        index: usize,
        /// Expected length.
        expected: usize,
        /// Actual length.
        got: usize,
    },

    // ════════════════════════════════════════════════════════════════════════════════
    // THRESHOLD RECEIPT VALIDATION ERRORS
    // ════════════════════════════════════════════════════════════════════════════════

    /// committee_hash length tidak valid.
    InvalidCommitteeHashLength {
        /// Expected length.
        expected: usize,
        /// Actual length.
        got: usize,
    },

    /// signer_ids kosong.
    EmptySignerIds,

    /// signer_id length tidak valid.
    InvalidSignerIdLength {
        /// Index of invalid signer.
        index: usize,
        /// Expected length.
        expected: usize,
        /// Actual length.
        got: usize,
    },

    /// Duplicate signer_id detected.
    DuplicateSignerId {
        /// Index of duplicate signer.
        index: usize,
    },

    /// receipt_data validation failed.
    InvalidReceiptData {
        /// Underlying error.
        reason: String,
    },

    /// signature validation failed.
    InvalidSignature {
        /// Underlying error.
        reason: String,
    },

    /// signer_ids tidak cocok dengan signature.signer_ids.
    SignerIdsMismatch,

    /// epoch tidak konsisten dengan receipt_data.epoch.
    EpochMismatch {
        /// Epoch dari receipt.
        receipt_epoch: u64,
        /// Epoch dari receipt_data.
        data_epoch: u64,
    },
}

impl fmt::Display for CommitteeValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommitteeValidationError::InvalidIdLength { expected, got } => {
                write!(
                    f,
                    "invalid id length: expected {}, got {}",
                    expected, got
                )
            }
            CommitteeValidationError::InvalidValidatorIdLength { expected, got } => {
                write!(
                    f,
                    "invalid validator_id length: expected {}, got {}",
                    expected, got
                )
            }
            CommitteeValidationError::InvalidPubkeyLength { expected, got } => {
                write!(
                    f,
                    "invalid pubkey length: expected {}, got {}",
                    expected, got
                )
            }
            CommitteeValidationError::InvalidStake { stake } => {
                write!(f, "invalid stake: {} (must be > 0)", stake)
            }
            CommitteeValidationError::EmptyMembers => {
                write!(f, "members must not be empty")
            }
            CommitteeValidationError::InvalidThreshold { threshold, member_count } => {
                write!(
                    f,
                    "invalid threshold: {} for {} members (must be > 0 and <= member count)",
                    threshold, member_count
                )
            }
            CommitteeValidationError::InvalidEpochDuration { epoch_duration_secs } => {
                write!(
                    f,
                    "invalid epoch_duration_secs: {} (must be > 0)",
                    epoch_duration_secs
                )
            }
            CommitteeValidationError::InvalidGroupPubkeyLength { expected, got } => {
                write!(
                    f,
                    "invalid group_pubkey length: expected {}, got {}",
                    expected, got
                )
            }
            CommitteeValidationError::DuplicateMemberId { index } => {
                write!(f, "duplicate member id at index {}", index)
            }
            CommitteeValidationError::InvalidMember { index, reason } => {
                write!(f, "invalid member at index {}: {}", index, reason)
            }
            CommitteeValidationError::InvalidWorkloadIdLength { expected, got } => {
                write!(
                    f,
                    "invalid workload_id length: expected {}, got {}",
                    expected, got
                )
            }
            CommitteeValidationError::InvalidBlobHashLength { expected, got } => {
                write!(
                    f,
                    "invalid blob_hash length: expected {}, got {}",
                    expected, got
                )
            }
            CommitteeValidationError::InvalidPlacementNodeLength { index, expected, got } => {
                write!(
                    f,
                    "invalid placement node length at index {}: expected {}, got {}",
                    index, expected, got
                )
            }
            CommitteeValidationError::InvalidCommitteeHashLength { expected, got } => {
                write!(
                    f,
                    "invalid committee_hash length: expected {}, got {}",
                    expected, got
                )
            }
            CommitteeValidationError::EmptySignerIds => {
                write!(f, "signer_ids must not be empty")
            }
            CommitteeValidationError::InvalidSignerIdLength { index, expected, got } => {
                write!(
                    f,
                    "invalid signer_id length at index {}: expected {}, got {}",
                    index, expected, got
                )
            }
            CommitteeValidationError::DuplicateSignerId { index } => {
                write!(f, "duplicate signer_id at index {}", index)
            }
            CommitteeValidationError::InvalidReceiptData { reason } => {
                write!(f, "invalid receipt_data: {}", reason)
            }
            CommitteeValidationError::InvalidSignature { reason } => {
                write!(f, "invalid signature: {}", reason)
            }
            CommitteeValidationError::SignerIdsMismatch => {
                write!(f, "signer_ids do not match signature.signer_ids")
            }
            CommitteeValidationError::EpochMismatch { receipt_epoch, data_epoch } => {
                write!(
                    f,
                    "epoch mismatch: receipt epoch {} != receipt_data epoch {}",
                    receipt_epoch, data_epoch
                )
            }
        }
    }
}

impl std::error::Error for CommitteeValidationError {}

/// Error type untuk decoding committee proto messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitteeDecodeError {
    /// Bincode deserialization failed.
    DeserializationFailed {
        /// Error description.
        reason: String,
    },

    /// Validation failed after deserialization.
    ValidationFailed {
        /// Underlying validation error.
        error: CommitteeValidationError,
    },

    /// Native type conversion failed.
    ConversionFailed {
        /// Error description.
        reason: String,
    },
}

impl fmt::Display for CommitteeDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommitteeDecodeError::DeserializationFailed { reason } => {
                write!(f, "deserialization failed: {}", reason)
            }
            CommitteeDecodeError::ValidationFailed { error } => {
                write!(f, "validation failed: {}", error)
            }
            CommitteeDecodeError::ConversionFailed { reason } => {
                write!(f, "conversion failed: {}", reason)
            }
        }
    }
}

impl std::error::Error for CommitteeDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CommitteeDecodeError::ValidationFailed { error } => Some(error),
            _ => None,
        }
    }
}

impl From<CommitteeValidationError> for CommitteeDecodeError {
    fn from(error: CommitteeValidationError) -> Self {
        CommitteeDecodeError::ValidationFailed { error }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// COORDINATOR MEMBER PROTO
// ════════════════════════════════════════════════════════════════════════════════

/// Proto message untuk Coordinator Member.
///
/// `CoordinatorMemberProto` adalah representasi serializable dari coordinator
/// member yang digunakan untuk transport dan storage.
///
/// ## Field Sizes
///
/// | Field | Expected Size |
/// |-------|---------------|
/// | `id` | 32 bytes |
/// | `validator_id` | 32 bytes |
/// | `pubkey` | 32 bytes |
///
/// ## Validation
///
/// Gunakan `validate()` untuk memastikan semua field valid sebelum processing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinatorMemberProto {
    /// Coordinator identifier (MUST be 32 bytes).
    pub id: Vec<u8>,

    /// Validator identifier (MUST be 32 bytes).
    pub validator_id: Vec<u8>,

    /// Public key untuk TSS (MUST be 32 bytes).
    pub pubkey: Vec<u8>,

    /// Jumlah stake (MUST be > 0).
    pub stake: u64,

    /// Unix timestamp saat member bergabung.
    pub joined_at: u64,
}

impl CoordinatorMemberProto {
    /// Validates all field lengths and values.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if all fields are valid
    /// - `Err(CommitteeValidationError)` if any validation fails
    ///
    /// # Validation Rules
    ///
    /// - `id.len() == 32`
    /// - `validator_id.len() == 32`
    /// - `pubkey.len() == 32`
    /// - `stake > 0`
    pub fn validate(&self) -> Result<(), CommitteeValidationError> {
        // Validate id
        if self.id.len() != COORDINATOR_ID_SIZE {
            return Err(CommitteeValidationError::InvalidIdLength {
                expected: COORDINATOR_ID_SIZE,
                got: self.id.len(),
            });
        }

        // Validate validator_id
        if self.validator_id.len() != VALIDATOR_ID_SIZE {
            return Err(CommitteeValidationError::InvalidValidatorIdLength {
                expected: VALIDATOR_ID_SIZE,
                got: self.validator_id.len(),
            });
        }

        // Validate pubkey
        if self.pubkey.len() != PUBKEY_SIZE {
            return Err(CommitteeValidationError::InvalidPubkeyLength {
                expected: PUBKEY_SIZE,
                got: self.pubkey.len(),
            });
        }

        // Validate stake
        if self.stake == 0 {
            return Err(CommitteeValidationError::InvalidStake { stake: self.stake });
        }

        Ok(())
    }

    /// Creates proto from native `CoordinatorMember`.
    ///
    /// # Arguments
    ///
    /// * `member` - Reference to native member
    ///
    /// # Returns
    ///
    /// A proto with all bytes copied.
    #[cfg(feature = "common-conversion")]
    #[must_use]
    pub fn from_member(member: &dsdn_common::CoordinatorMember) -> Self {
        Self {
            id: member.id().as_bytes().to_vec(),
            validator_id: member.validator_id().as_bytes().to_vec(),
            pubkey: member.pubkey().as_bytes().to_vec(),
            stake: member.stake(),
            joined_at: member.joined_at(),
        }
    }

    /// Converts proto back to native `CoordinatorMember`.
    ///
    /// # Returns
    ///
    /// - `Ok(CoordinatorMember)` if valid
    /// - `Err(CommitteeDecodeError)` if validation or conversion fails
    ///
    /// # Note
    ///
    /// This method calls `validate()` internally.
    #[cfg(feature = "common-conversion")]
    pub fn to_member(&self) -> Result<dsdn_common::CoordinatorMember, CommitteeDecodeError> {
        // Validate first
        self.validate()?;

        // Convert id
        let id = dsdn_common::CoordinatorId::from_bytes(&self.id)
            .ok_or_else(|| CommitteeDecodeError::ConversionFailed {
                reason: "invalid coordinator id".to_string(),
            })?;

        // Convert validator_id
        let validator_id = dsdn_common::ValidatorId::from_bytes(&self.validator_id)
            .ok_or_else(|| CommitteeDecodeError::ConversionFailed {
                reason: "invalid validator id".to_string(),
            })?;

        // Convert pubkey
        let mut pubkey_bytes = [0u8; PUBKEY_SIZE];
        pubkey_bytes.copy_from_slice(&self.pubkey);
        let pubkey = dsdn_tss::ParticipantPublicKey::from_bytes(pubkey_bytes)
            .map_err(|e| CommitteeDecodeError::ConversionFailed {
                reason: format!("invalid pubkey: {}", e),
            })?;

        Ok(dsdn_common::CoordinatorMember::with_timestamp(
            id,
            validator_id,
            pubkey,
            self.stake,
            self.joined_at,
        ))
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// COORDINATOR COMMITTEE PROTO
// ════════════════════════════════════════════════════════════════════════════════

/// Proto message untuk Coordinator Committee.
///
/// `CoordinatorCommitteeProto` adalah representasi serializable dari coordinator
/// committee yang digunakan untuk transport dan storage.
///
/// ## Field Sizes
///
/// | Field | Expected Size |
/// |-------|---------------|
/// | `group_pubkey` | 32 bytes |
///
/// ## Validation
///
/// Gunakan `validate()` untuk memastikan semua field valid sebelum processing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinatorCommitteeProto {
    /// Committee members (MUST NOT be empty).
    pub members: Vec<CoordinatorMemberProto>,

    /// Threshold untuk signing (MUST be > 0 and <= members.len()).
    pub threshold: u32,

    /// Epoch number.
    pub epoch: u64,

    /// Epoch start timestamp (Unix seconds).
    pub epoch_start: u64,

    /// Epoch duration in seconds (MUST be > 0).
    pub epoch_duration_secs: u64,

    /// Group public key (MUST be 32 bytes).
    pub group_pubkey: Vec<u8>,
}

impl CoordinatorCommitteeProto {
    /// Validates all fields and nested members.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if all fields are valid
    /// - `Err(CommitteeValidationError)` if any validation fails
    ///
    /// # Validation Rules
    ///
    /// - `members` is not empty
    /// - `threshold > 0`
    /// - `threshold <= members.len()`
    /// - `epoch_duration_secs > 0`
    /// - `group_pubkey.len() == 32`
    /// - No duplicate member IDs
    /// - All members pass validation
    pub fn validate(&self) -> Result<(), CommitteeValidationError> {
        // Validate members not empty
        if self.members.is_empty() {
            return Err(CommitteeValidationError::EmptyMembers);
        }

        // Validate threshold > 0
        if self.threshold == 0 {
            return Err(CommitteeValidationError::InvalidThreshold {
                threshold: self.threshold,
                member_count: self.members.len(),
            });
        }

        // Validate threshold <= members.len()
        if (self.threshold as usize) > self.members.len() {
            return Err(CommitteeValidationError::InvalidThreshold {
                threshold: self.threshold,
                member_count: self.members.len(),
            });
        }

        // Validate epoch_duration_secs > 0
        if self.epoch_duration_secs == 0 {
            return Err(CommitteeValidationError::InvalidEpochDuration {
                epoch_duration_secs: self.epoch_duration_secs,
            });
        }

        // Validate group_pubkey length
        if self.group_pubkey.len() != GROUP_PUBKEY_SIZE {
            return Err(CommitteeValidationError::InvalidGroupPubkeyLength {
                expected: GROUP_PUBKEY_SIZE,
                got: self.group_pubkey.len(),
            });
        }

        // Validate each member and check for duplicates
        let mut seen_ids: HashSet<&[u8]> = HashSet::with_capacity(self.members.len());
        for (i, member) in self.members.iter().enumerate() {
            // Validate member
            member.validate().map_err(|e| {
                CommitteeValidationError::InvalidMember {
                    index: i,
                    reason: e.to_string(),
                }
            })?;

            // Check for duplicate IDs
            if !seen_ids.insert(member.id.as_slice()) {
                return Err(CommitteeValidationError::DuplicateMemberId { index: i });
            }
        }

        Ok(())
    }

    /// Creates proto from native `CoordinatorCommittee`.
    ///
    /// # Arguments
    ///
    /// * `committee` - Reference to native committee
    ///
    /// # Returns
    ///
    /// A proto with all data copied.
    #[cfg(feature = "common-conversion")]
    #[must_use]
    pub fn from_committee(committee: &dsdn_common::CoordinatorCommittee) -> Self {
        Self {
            members: committee
                .members()
                .iter()
                .map(CoordinatorMemberProto::from_member)
                .collect(),
            threshold: committee.threshold() as u32,
            epoch: committee.epoch(),
            epoch_start: committee.epoch_start(),
            epoch_duration_secs: committee.epoch_duration_secs(),
            group_pubkey: committee.group_pubkey().as_bytes().to_vec(),
        }
    }

    /// Converts proto back to native `CoordinatorCommittee`.
    ///
    /// # Returns
    ///
    /// - `Ok(CoordinatorCommittee)` if valid
    /// - `Err(CommitteeDecodeError)` if validation or conversion fails
    ///
    /// # Note
    ///
    /// This method calls `validate()` internally.
    #[cfg(feature = "common-conversion")]
    pub fn to_committee(&self) -> Result<dsdn_common::CoordinatorCommittee, CommitteeDecodeError> {
        // Validate first
        self.validate()?;

        // Convert members
        let mut members = Vec::with_capacity(self.members.len());
        for (i, member_proto) in self.members.iter().enumerate() {
            let member = member_proto.to_member().map_err(|e| {
                CommitteeDecodeError::ConversionFailed {
                    reason: format!("member[{}]: {}", i, e),
                }
            })?;
            members.push(member);
        }

        // Convert group_pubkey
        let mut pubkey_bytes = [0u8; GROUP_PUBKEY_SIZE];
        pubkey_bytes.copy_from_slice(&self.group_pubkey);
        let group_pubkey = dsdn_tss::GroupPublicKey::from_bytes(pubkey_bytes)
            .map_err(|e| CommitteeDecodeError::ConversionFailed {
                reason: format!("invalid group_pubkey: {}", e),
            })?;

        // Threshold must fit in u8
        let threshold = if self.threshold > 255 {
            return Err(CommitteeDecodeError::ConversionFailed {
                reason: format!("threshold {} exceeds u8 max", self.threshold),
            });
        } else {
            self.threshold as u8
        };

        dsdn_common::CoordinatorCommittee::new(
            members,
            threshold,
            self.epoch,
            self.epoch_start,
            self.epoch_duration_secs,
            group_pubkey,
        )
        .map_err(|e| CommitteeDecodeError::ConversionFailed {
            reason: format!("committee construction failed: {}", e),
        })
    }

    /// Returns the number of members.
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// Returns the total stake of all members.
    ///
    /// Uses saturating addition to prevent overflow.
    #[must_use]
    pub fn total_stake(&self) -> u64 {
        self.members
            .iter()
            .fold(0u64, |acc, m| acc.saturating_add(m.stake))
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// ENCODING FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════════

/// Encodes `CoordinatorCommitteeProto` to bytes.
///
/// # Arguments
///
/// * `committee` - Reference to proto message
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
pub fn encode_committee(committee: &CoordinatorCommitteeProto) -> Vec<u8> {
    bincode::serialize(committee).unwrap_or_else(|_| Vec::new())
}

/// Decodes bytes to `CoordinatorCommitteeProto`.
///
/// # Arguments
///
/// * `bytes` - Bincode-encoded bytes
///
/// # Returns
///
/// - `Ok(CoordinatorCommitteeProto)` if decoding and validation succeed
/// - `Err(CommitteeDecodeError)` if decoding or validation fails
///
/// # Note
///
/// This function calls `validate()` after deserialization.
pub fn decode_committee(bytes: &[u8]) -> Result<CoordinatorCommitteeProto, CommitteeDecodeError> {
    let proto: CoordinatorCommitteeProto =
        bincode::deserialize(bytes).map_err(|e| CommitteeDecodeError::DeserializationFailed {
            reason: e.to_string(),
        })?;

    // Validate after deserialization
    proto.validate()?;

    Ok(proto)
}

/// Computes deterministic hash of `CoordinatorCommitteeProto`.
///
/// # Arguments
///
/// * `committee` - Reference to proto message
///
/// # Returns
///
/// 32-byte SHA3-256 hash computed from all fields.
///
/// # Determinism
///
/// The hash is computed in a deterministic order:
/// 1. epoch (8 bytes, LE)
/// 2. epoch_start (8 bytes, LE)
/// 3. epoch_duration_secs (8 bytes, LE)
/// 4. threshold (4 bytes, LE)
/// 5. member_count (8 bytes, LE)
/// 6. for each member (in order):
///    - id, validator_id, pubkey, stake (8 bytes, LE), joined_at (8 bytes, LE)
/// 7. group_pubkey
#[must_use]
pub fn compute_committee_hash(committee: &CoordinatorCommitteeProto) -> [u8; 32] {
    let mut hasher = Sha3_256::new();

    // Domain separator
    hasher.update(b"dsdn-proto-committee-v1");

    // Epoch info
    hasher.update(committee.epoch.to_le_bytes());
    hasher.update(committee.epoch_start.to_le_bytes());
    hasher.update(committee.epoch_duration_secs.to_le_bytes());

    // Threshold
    hasher.update(committee.threshold.to_le_bytes());

    // Member count
    let member_count = committee.members.len() as u64;
    hasher.update(member_count.to_le_bytes());

    // Members in order
    for member in &committee.members {
        hasher.update(&member.id);
        hasher.update(&member.validator_id);
        hasher.update(&member.pubkey);
        hasher.update(member.stake.to_le_bytes());
        hasher.update(member.joined_at.to_le_bytes());
    }

    // Group pubkey
    hasher.update(&committee.group_pubkey);

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

// ════════════════════════════════════════════════════════════════════════════════
// RECEIPT DATA PROTO
// ════════════════════════════════════════════════════════════════════════════════

/// Proto message untuk Receipt Data.
///
/// `ReceiptDataProto` adalah representasi serializable dari receipt data
/// yang digunakan untuk transport dan storage.
///
/// ## Field Sizes
///
/// | Field | Expected Size |
/// |-------|---------------|
/// | `workload_id` | 32 bytes |
/// | `blob_hash` | 32 bytes |
/// | `placement` | N × 32 bytes |
///
/// ## Hash Computation
///
/// `compute_hash()` HARUS IDENTIK dengan `ReceiptData::receipt_data_hash()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptDataProto {
    /// Workload identifier (MUST be 32 bytes).
    pub workload_id: Vec<u8>,

    /// Hash dari blob data (MUST be 32 bytes).
    pub blob_hash: Vec<u8>,

    /// Daftar node placement (EACH MUST be 32 bytes).
    pub placement: Vec<Vec<u8>>,

    /// Timestamp pembuatan receipt (Unix seconds).
    pub timestamp: u64,

    /// Nomor urut receipt.
    pub sequence: u64,

    /// Nomor epoch.
    pub epoch: u64,
}

impl ReceiptDataProto {
    /// Validates all field lengths.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if all fields are valid
    /// - `Err(CommitteeValidationError)` if any validation fails
    ///
    /// # Validation Rules
    ///
    /// - `workload_id.len() == 32`
    /// - `blob_hash.len() == 32`
    /// - Each `placement[i].len() == 32`
    pub fn validate(&self) -> Result<(), CommitteeValidationError> {
        // Validate workload_id
        if self.workload_id.len() != WORKLOAD_ID_SIZE {
            return Err(CommitteeValidationError::InvalidWorkloadIdLength {
                expected: WORKLOAD_ID_SIZE,
                got: self.workload_id.len(),
            });
        }

        // Validate blob_hash
        if self.blob_hash.len() != BLOB_HASH_SIZE {
            return Err(CommitteeValidationError::InvalidBlobHashLength {
                expected: BLOB_HASH_SIZE,
                got: self.blob_hash.len(),
            });
        }

        // Validate each placement node
        for (i, node_id) in self.placement.iter().enumerate() {
            if node_id.len() != NODE_ID_SIZE {
                return Err(CommitteeValidationError::InvalidPlacementNodeLength {
                    index: i,
                    expected: NODE_ID_SIZE,
                    got: node_id.len(),
                });
            }
        }

        Ok(())
    }

    /// Creates proto from native `ReceiptData`.
    ///
    /// # Arguments
    ///
    /// * `data` - Reference to native receipt data
    ///
    /// # Returns
    ///
    /// A proto with all bytes copied.
    #[cfg(feature = "common-conversion")]
    #[must_use]
    pub fn from_receipt_data(data: &dsdn_common::ReceiptData) -> Self {
        Self {
            workload_id: data.workload_id().as_bytes().to_vec(),
            blob_hash: data.blob_hash().to_vec(),
            placement: data.placement().iter().map(|n| n.to_vec()).collect(),
            timestamp: data.timestamp(),
            sequence: data.sequence(),
            epoch: data.epoch(),
        }
    }

    /// Converts proto back to native `ReceiptData`.
    ///
    /// # Returns
    ///
    /// - `Ok(ReceiptData)` if valid
    /// - `Err(CommitteeDecodeError)` if validation or conversion fails
    ///
    /// # Note
    ///
    /// This method calls `validate()` internally.
    #[cfg(feature = "common-conversion")]
    pub fn to_receipt_data(&self) -> Result<dsdn_common::ReceiptData, CommitteeDecodeError> {
        // Validate first
        self.validate()?;

        // Convert workload_id
        let workload_id = dsdn_common::WorkloadId::from_bytes(&self.workload_id)
            .ok_or_else(|| CommitteeDecodeError::ConversionFailed {
                reason: "invalid workload_id".to_string(),
            })?;

        // Convert blob_hash
        let mut blob_hash = [0u8; BLOB_HASH_SIZE];
        blob_hash.copy_from_slice(&self.blob_hash);

        // Convert placement
        let mut placement = Vec::with_capacity(self.placement.len());
        for node_bytes in &self.placement {
            let mut node_id = [0u8; NODE_ID_SIZE];
            node_id.copy_from_slice(node_bytes);
            placement.push(node_id);
        }

        Ok(dsdn_common::ReceiptData::new(
            workload_id,
            blob_hash,
            placement,
            self.timestamp,
            self.sequence,
            self.epoch,
        ))
    }

    /// Computes deterministic hash of receipt data.
    ///
    /// # Returns
    ///
    /// 32-byte SHA3-256 hash.
    ///
    /// # CRITICAL
    ///
    /// This MUST be IDENTICAL to `ReceiptData::receipt_data_hash()`.
    /// Hash order:
    /// 1. workload_id (32 bytes)
    /// 2. blob_hash (32 bytes)
    /// 3. placement_count (8 bytes, LE)
    /// 4. placement nodes (32 bytes each, in order)
    /// 5. timestamp (8 bytes, LE)
    /// 6. sequence (8 bytes, LE)
    /// 7. epoch (8 bytes, LE)
    #[must_use]
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();

        // 1. workload_id (32 bytes)
        hasher.update(&self.workload_id);

        // 2. blob_hash (32 bytes)
        hasher.update(&self.blob_hash);

        // 3. placement_count (8 bytes, little-endian)
        let placement_count = self.placement.len() as u64;
        hasher.update(placement_count.to_le_bytes());

        // 4. placement nodes (32 bytes each, in order)
        for node_id in &self.placement {
            hasher.update(node_id);
        }

        // 5. timestamp (8 bytes, little-endian)
        hasher.update(self.timestamp.to_le_bytes());

        // 6. sequence (8 bytes, little-endian)
        hasher.update(self.sequence.to_le_bytes());

        // 7. epoch (8 bytes, little-endian)
        hasher.update(self.epoch.to_le_bytes());

        // Finalize and return
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// THRESHOLD RECEIPT PROTO
// ════════════════════════════════════════════════════════════════════════════════

/// Proto message untuk Threshold Receipt.
///
/// `ThresholdReceiptProto` adalah representasi serializable dari threshold
/// receipt yang digunakan untuk transport dan storage.
///
/// ## Field Sizes
///
/// | Field | Expected Size |
/// |-------|---------------|
/// | `signer_ids` | N × 32 bytes |
/// | `committee_hash` | 32 bytes |
///
/// ## Validation
///
/// - `signer_ids` HARUS SETARA dengan `signature.signer_ids`
/// - `epoch` HARUS konsisten dengan `receipt_data.epoch`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdReceiptProto {
    /// Receipt data.
    pub receipt_data: ReceiptDataProto,

    /// Aggregate FROST signature.
    pub signature: super::signing::AggregateSignatureProto,

    /// Signer CoordinatorIds (EACH MUST be 32 bytes, MUST match signature.signer_ids).
    pub signer_ids: Vec<Vec<u8>>,

    /// Epoch number (MUST equal receipt_data.epoch).
    pub epoch: u64,

    /// Committee hash saat signing (MUST be 32 bytes).
    pub committee_hash: Vec<u8>,
}

impl ThresholdReceiptProto {
    /// Validates all fields and nested structures.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if all fields are valid
    /// - `Err(CommitteeValidationError)` if any validation fails
    ///
    /// # Validation Rules
    ///
    /// - `receipt_data.validate()` passes
    /// - `signature.validate()` passes
    /// - `signer_ids` is not empty
    /// - Each `signer_ids[i].len() == 32`
    /// - No duplicate `signer_ids`
    /// - `signer_ids` == `signature.signer_ids` (exact match)
    /// - `committee_hash.len() == 32`
    /// - `epoch == receipt_data.epoch`
    pub fn validate(&self) -> Result<(), CommitteeValidationError> {
        // Validate receipt_data
        self.receipt_data.validate().map_err(|e| {
            CommitteeValidationError::InvalidReceiptData {
                reason: e.to_string(),
            }
        })?;

        // Validate signature
        self.signature.validate().map_err(|e| {
            CommitteeValidationError::InvalidSignature {
                reason: e.to_string(),
            }
        })?;

        // Validate signer_ids not empty
        if self.signer_ids.is_empty() {
            return Err(CommitteeValidationError::EmptySignerIds);
        }

        // Validate each signer_id length and check for duplicates
        let mut seen: HashSet<&[u8]> = HashSet::with_capacity(self.signer_ids.len());
        for (i, signer_id) in self.signer_ids.iter().enumerate() {
            if signer_id.len() != COORDINATOR_ID_SIZE {
                return Err(CommitteeValidationError::InvalidSignerIdLength {
                    index: i,
                    expected: COORDINATOR_ID_SIZE,
                    got: signer_id.len(),
                });
            }

            if !seen.insert(signer_id.as_slice()) {
                return Err(CommitteeValidationError::DuplicateSignerId { index: i });
            }
        }

        // Validate signer_ids matches signature.signer_ids
        if self.signer_ids.len() != self.signature.signer_ids.len() {
            return Err(CommitteeValidationError::SignerIdsMismatch);
        }

        for (i, signer_id) in self.signer_ids.iter().enumerate() {
            if signer_id.as_slice() != self.signature.signer_ids[i].as_slice() {
                return Err(CommitteeValidationError::SignerIdsMismatch);
            }
        }

        // Validate committee_hash length
        if self.committee_hash.len() != COMMITTEE_HASH_SIZE {
            return Err(CommitteeValidationError::InvalidCommitteeHashLength {
                expected: COMMITTEE_HASH_SIZE,
                got: self.committee_hash.len(),
            });
        }

        // Validate epoch consistency
        if self.epoch != self.receipt_data.epoch {
            return Err(CommitteeValidationError::EpochMismatch {
                receipt_epoch: self.epoch,
                data_epoch: self.receipt_data.epoch,
            });
        }

        Ok(())
    }

    /// Creates proto from native `ThresholdReceipt`.
    ///
    /// # Arguments
    ///
    /// * `receipt` - Reference to native receipt
    ///
    /// # Returns
    ///
    /// A proto with all data copied.
    #[cfg(feature = "common-conversion")]
    #[must_use]
    pub fn from_receipt(receipt: &dsdn_common::ThresholdReceipt) -> Self {
        Self {
            receipt_data: ReceiptDataProto::from_receipt_data(receipt.receipt_data()),
            signature: super::signing::AggregateSignatureProto::from_aggregate(
                receipt.aggregate_signature(),
            ),
            signer_ids: receipt
                .signers()
                .iter()
                .map(|s| s.as_bytes().to_vec())
                .collect(),
            epoch: receipt.epoch(),
            committee_hash: receipt.committee_hash().to_vec(),
        }
    }

    /// Converts proto back to native `ThresholdReceipt`.
    ///
    /// # Returns
    ///
    /// - `Ok(ThresholdReceipt)` if valid
    /// - `Err(CommitteeDecodeError)` if validation or conversion fails
    ///
    /// # Note
    ///
    /// This method calls `validate()` internally.
    #[cfg(feature = "common-conversion")]
    pub fn to_receipt(&self) -> Result<dsdn_common::ThresholdReceipt, CommitteeDecodeError> {
        // Validate first
        self.validate()?;

        // Convert receipt_data
        let receipt_data = self.receipt_data.to_receipt_data()?;

        // Convert signature
        let aggregate_signature = self.signature.to_aggregate().map_err(|e| {
            CommitteeDecodeError::ConversionFailed {
                reason: format!("signature conversion failed: {}", e),
            }
        })?;

        // Convert signer_ids
        let mut signers = Vec::with_capacity(self.signer_ids.len());
        for signer_bytes in &self.signer_ids {
            let signer = dsdn_common::CoordinatorId::from_bytes(signer_bytes)
                .ok_or_else(|| CommitteeDecodeError::ConversionFailed {
                    reason: "invalid signer_id".to_string(),
                })?;
            signers.push(signer);
        }

        // Convert committee_hash
        let mut committee_hash = [0u8; COMMITTEE_HASH_SIZE];
        committee_hash.copy_from_slice(&self.committee_hash);

        Ok(dsdn_common::ThresholdReceipt::new(
            receipt_data,
            aggregate_signature,
            signers,
            committee_hash,
        ))
    }

    /// Returns the number of signers.
    #[must_use]
    pub fn signer_count(&self) -> usize {
        self.signer_ids.len()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// RECEIPT ENCODING FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════════

/// Encodes `ThresholdReceiptProto` to bytes.
///
/// # Arguments
///
/// * `receipt` - Reference to proto message
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
pub fn encode_receipt(receipt: &ThresholdReceiptProto) -> Vec<u8> {
    bincode::serialize(receipt).unwrap_or_else(|_| Vec::new())
}

/// Decodes bytes to `ThresholdReceiptProto`.
///
/// # Arguments
///
/// * `bytes` - Bincode-encoded bytes
///
/// # Returns
///
/// - `Ok(ThresholdReceiptProto)` if decoding and validation succeed
/// - `Err(CommitteeDecodeError)` if decoding or validation fails
///
/// # Note
///
/// This function calls `validate()` after deserialization.
pub fn decode_receipt(bytes: &[u8]) -> Result<ThresholdReceiptProto, CommitteeDecodeError> {
    let proto: ThresholdReceiptProto =
        bincode::deserialize(bytes).map_err(|e| CommitteeDecodeError::DeserializationFailed {
            reason: e.to_string(),
        })?;

    // Validate after deserialization
    proto.validate()?;

    Ok(proto)
}

/// Computes deterministic hash of `ThresholdReceiptProto`.
///
/// # Arguments
///
/// * `receipt` - Reference to proto message
///
/// # Returns
///
/// 32-byte SHA3-256 hash computed from all fields.
///
/// # Determinism
///
/// The hash is computed in a deterministic order:
/// 1. Domain separator
/// 2. receipt_data hash (via compute_hash())
/// 3. signature bytes (64 bytes)
/// 4. signer_count (8 bytes, LE)
/// 5. for each signer_id (32 bytes each, in order)
/// 6. epoch (8 bytes, LE)
/// 7. committee_hash (32 bytes)
#[must_use]
pub fn compute_receipt_hash(receipt: &ThresholdReceiptProto) -> [u8; 32] {
    let mut hasher = Sha3_256::new();

    // Domain separator
    hasher.update(b"dsdn-proto-receipt-v1");

    // Receipt data hash
    let data_hash = receipt.receipt_data.compute_hash();
    hasher.update(data_hash);

    // Signature bytes
    hasher.update(&receipt.signature.signature);

    // Signer count
    let signer_count = receipt.signer_ids.len() as u64;
    hasher.update(signer_count.to_le_bytes());

    // Signers in order
    for signer_id in &receipt.signer_ids {
        hasher.update(signer_id);
    }

    // Epoch
    hasher.update(receipt.epoch.to_le_bytes());

    // Committee hash
    hasher.update(&receipt.committee_hash);

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
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

    fn make_valid_member(id_byte: u8, stake: u64) -> CoordinatorMemberProto {
        CoordinatorMemberProto {
            id: vec![id_byte; 32],
            validator_id: vec![id_byte + 0x10; 32],
            pubkey: vec![id_byte + 0x20; 32],
            stake,
            joined_at: 1234567890,
        }
    }

    fn make_valid_committee() -> CoordinatorCommitteeProto {
        CoordinatorCommitteeProto {
            members: vec![make_valid_member(0x01, 1000), make_valid_member(0x02, 2000)],
            threshold: 2,
            epoch: 1,
            epoch_start: 1700000000,
            epoch_duration_secs: 3600,
            group_pubkey: vec![0xAA; 32],
        }
    }

    // ════════════════════════════════════════════════════════════════════════════════
    // MEMBER VALIDATION TESTS
    // ════════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_member_validate_valid() {
        let member = make_valid_member(0x01, 1000);
        assert!(member.validate().is_ok());
    }

    #[test]
    fn test_member_validate_invalid_id_length() {
        let mut member = make_valid_member(0x01, 1000);
        member.id = vec![0x01; 16]; // Wrong length

        let result = member.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CommitteeValidationError::InvalidIdLength { expected: 32, got: 16 }
        ));
    }

    #[test]
    fn test_member_validate_invalid_validator_id_length() {
        let mut member = make_valid_member(0x01, 1000);
        member.validator_id = vec![0x01; 64]; // Wrong length

        let result = member.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CommitteeValidationError::InvalidValidatorIdLength { expected: 32, got: 64 }
        ));
    }

    #[test]
    fn test_member_validate_invalid_pubkey_length() {
        let mut member = make_valid_member(0x01, 1000);
        member.pubkey = vec![0x01; 48]; // Wrong length

        let result = member.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CommitteeValidationError::InvalidPubkeyLength { expected: 32, got: 48 }
        ));
    }

    #[test]
    fn test_member_validate_zero_stake() {
        let mut member = make_valid_member(0x01, 1000);
        member.stake = 0; // Invalid

        let result = member.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CommitteeValidationError::InvalidStake { stake: 0 }
        ));
    }

    // ════════════════════════════════════════════════════════════════════════════════
    // COMMITTEE VALIDATION TESTS
    // ════════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_committee_validate_valid() {
        let committee = make_valid_committee();
        assert!(committee.validate().is_ok());
    }

    #[test]
    fn test_committee_validate_empty_members() {
        let mut committee = make_valid_committee();
        committee.members = vec![]; // Empty

        let result = committee.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CommitteeValidationError::EmptyMembers
        ));
    }

    #[test]
    fn test_committee_validate_zero_threshold() {
        let mut committee = make_valid_committee();
        committee.threshold = 0; // Invalid

        let result = committee.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CommitteeValidationError::InvalidThreshold { threshold: 0, .. }
        ));
    }

    #[test]
    fn test_committee_validate_threshold_exceeds_members() {
        let mut committee = make_valid_committee();
        committee.threshold = 5; // > 2 members

        let result = committee.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CommitteeValidationError::InvalidThreshold { threshold: 5, member_count: 2 }
        ));
    }

    #[test]
    fn test_committee_validate_zero_epoch_duration() {
        let mut committee = make_valid_committee();
        committee.epoch_duration_secs = 0; // Invalid

        let result = committee.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CommitteeValidationError::InvalidEpochDuration { epoch_duration_secs: 0 }
        ));
    }

    #[test]
    fn test_committee_validate_invalid_group_pubkey() {
        let mut committee = make_valid_committee();
        committee.group_pubkey = vec![0xAA; 16]; // Wrong length

        let result = committee.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CommitteeValidationError::InvalidGroupPubkeyLength { expected: 32, got: 16 }
        ));
    }

    #[test]
    fn test_committee_validate_duplicate_member_id() {
        let mut committee = make_valid_committee();
        committee.members = vec![
            make_valid_member(0x01, 1000),
            make_valid_member(0x01, 2000), // Duplicate id
        ];

        let result = committee.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CommitteeValidationError::DuplicateMemberId { index: 1 }
        ));
    }

    #[test]
    fn test_committee_validate_invalid_nested_member() {
        let mut committee = make_valid_committee();
        committee.members[1].stake = 0; // Invalid member

        let result = committee.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CommitteeValidationError::InvalidMember { index: 1, .. }
        ));
    }

    // ════════════════════════════════════════════════════════════════════════════════
    // ENCODING TESTS
    // ════════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_committee_encode_decode_roundtrip() {
        let committee = make_valid_committee();

        let encoded = encode_committee(&committee);
        let decoded = decode_committee(&encoded);

        assert!(decoded.is_ok());
        assert_eq!(committee, decoded.expect("valid"));
    }

    #[test]
    fn test_committee_encode_deterministic() {
        let committee = make_valid_committee();

        let encoded1 = encode_committee(&committee);
        let encoded2 = encode_committee(&committee);

        assert_eq!(encoded1, encoded2);
    }

    #[test]
    fn test_committee_decode_invalid_bytes() {
        let invalid_bytes = vec![0xFF; 10];
        let result = decode_committee(&invalid_bytes);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CommitteeDecodeError::DeserializationFailed { .. }
        ));
    }

    #[test]
    fn test_committee_decode_validates_after_deserialization() {
        // Create invalid proto manually
        let invalid_committee = CoordinatorCommitteeProto {
            members: vec![],  // Invalid: empty
            threshold: 2,
            epoch: 1,
            epoch_start: 1700000000,
            epoch_duration_secs: 3600,
            group_pubkey: vec![0xAA; 32],
        };

        // Serialize (bypassing validation)
        let bytes = bincode::serialize(&invalid_committee).expect("serialize");

        // Decode should fail validation
        let result = decode_committee(&bytes);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CommitteeDecodeError::ValidationFailed { .. }
        ));
    }

    // ════════════════════════════════════════════════════════════════════════════════
    // HASH TESTS
    // ════════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_committee_hash_deterministic() {
        let committee = make_valid_committee();

        let hash1 = compute_committee_hash(&committee);
        let hash2 = compute_committee_hash(&committee);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_committee_hash_different_epoch() {
        let committee1 = make_valid_committee();
        let mut committee2 = make_valid_committee();
        committee2.epoch = 2; // Different

        let hash1 = compute_committee_hash(&committee1);
        let hash2 = compute_committee_hash(&committee2);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_committee_hash_different_threshold() {
        let mut committee1 = make_valid_committee();
        committee1.threshold = 1;
        let mut committee2 = make_valid_committee();
        committee2.threshold = 2;

        let hash1 = compute_committee_hash(&committee1);
        let hash2 = compute_committee_hash(&committee2);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_committee_hash_different_members() {
        let committee1 = make_valid_committee();
        let mut committee2 = make_valid_committee();
        committee2.members[0].stake = 9999; // Different stake

        let hash1 = compute_committee_hash(&committee1);
        let hash2 = compute_committee_hash(&committee2);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_committee_hash_different_member_order() {
        let committee1 = CoordinatorCommitteeProto {
            members: vec![make_valid_member(0x01, 1000), make_valid_member(0x02, 2000)],
            threshold: 2,
            epoch: 1,
            epoch_start: 1700000000,
            epoch_duration_secs: 3600,
            group_pubkey: vec![0xAA; 32],
        };
        let committee2 = CoordinatorCommitteeProto {
            members: vec![make_valid_member(0x02, 2000), make_valid_member(0x01, 1000)],
            threshold: 2,
            epoch: 1,
            epoch_start: 1700000000,
            epoch_duration_secs: 3600,
            group_pubkey: vec![0xAA; 32],
        };

        let hash1 = compute_committee_hash(&committee1);
        let hash2 = compute_committee_hash(&committee2);

        // Different order = different hash (order matters)
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_committee_hash_different_group_pubkey() {
        let committee1 = make_valid_committee();
        let mut committee2 = make_valid_committee();
        committee2.group_pubkey = vec![0xBB; 32]; // Different

        let hash1 = compute_committee_hash(&committee1);
        let hash2 = compute_committee_hash(&committee2);

        assert_ne!(hash1, hash2);
    }

    // ════════════════════════════════════════════════════════════════════════════════
    // QUERY TESTS
    // ════════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_committee_member_count() {
        let committee = make_valid_committee();
        assert_eq!(committee.member_count(), 2);
    }

    #[test]
    fn test_committee_total_stake() {
        let committee = make_valid_committee();
        assert_eq!(committee.total_stake(), 3000); // 1000 + 2000
    }

    #[test]
    fn test_committee_total_stake_saturating() {
        let mut committee = make_valid_committee();
        committee.members[0].stake = u64::MAX;
        committee.members[1].stake = u64::MAX;

        // Should saturate, not overflow
        assert_eq!(committee.total_stake(), u64::MAX);
    }

    // ════════════════════════════════════════════════════════════════════════════════
    // ERROR DISPLAY TESTS
    // ════════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_validation_error_id_display() {
        let error = CommitteeValidationError::InvalidIdLength {
            expected: 32,
            got: 16,
        };
        let display = format!("{}", error);
        assert!(display.contains("id"));
        assert!(display.contains("32"));
        assert!(display.contains("16"));
    }

    #[test]
    fn test_validation_error_stake_display() {
        let error = CommitteeValidationError::InvalidStake { stake: 0 };
        let display = format!("{}", error);
        assert!(display.contains("stake"));
        assert!(display.contains("0"));
    }

    #[test]
    fn test_validation_error_empty_members_display() {
        let error = CommitteeValidationError::EmptyMembers;
        let display = format!("{}", error);
        assert!(display.contains("members"));
        assert!(display.contains("empty"));
    }

    #[test]
    fn test_validation_error_threshold_display() {
        let error = CommitteeValidationError::InvalidThreshold {
            threshold: 5,
            member_count: 2,
        };
        let display = format!("{}", error);
        assert!(display.contains("threshold"));
        assert!(display.contains("5"));
        assert!(display.contains("2"));
    }

    #[test]
    fn test_validation_error_duplicate_display() {
        let error = CommitteeValidationError::DuplicateMemberId { index: 3 };
        let display = format!("{}", error);
        assert!(display.contains("duplicate"));
        assert!(display.contains("3"));
    }

    #[test]
    fn test_decode_error_display() {
        let error = CommitteeDecodeError::DeserializationFailed {
            reason: "test error".to_string(),
        };
        let display = format!("{}", error);
        assert!(display.contains("deserialization"));
        assert!(display.contains("test error"));
    }

    // ════════════════════════════════════════════════════════════════════════════════
    // SEND + SYNC TESTS
    // ════════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CoordinatorMemberProto>();
        assert_send_sync::<CoordinatorCommitteeProto>();
        assert_send_sync::<CommitteeValidationError>();
        assert_send_sync::<CommitteeDecodeError>();
    }

    // ════════════════════════════════════════════════════════════════════════════════
    // EDGE CASE TESTS
    // ════════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_committee_single_member() {
        let committee = CoordinatorCommitteeProto {
            members: vec![make_valid_member(0x01, 1000)],
            threshold: 1,
            epoch: 1,
            epoch_start: 1700000000,
            epoch_duration_secs: 3600,
            group_pubkey: vec![0xAA; 32],
        };

        assert!(committee.validate().is_ok());
        assert_eq!(committee.member_count(), 1);
        assert_eq!(committee.total_stake(), 1000);
    }

    #[test]
    fn test_committee_many_members() {
        let members: Vec<_> = (1u8..=50)
            .map(|i| make_valid_member(i, i as u64 * 100))
            .collect();

        let committee = CoordinatorCommitteeProto {
            members,
            threshold: 34, // ~2/3 of 50
            epoch: 1,
            epoch_start: 1700000000,
            epoch_duration_secs: 3600,
            group_pubkey: vec![0xAA; 32],
        };

        assert!(committee.validate().is_ok());
        assert_eq!(committee.member_count(), 50);
    }

    #[test]
    fn test_committee_minimum_stake() {
        let committee = CoordinatorCommitteeProto {
            members: vec![make_valid_member(0x01, 1), make_valid_member(0x02, 1)],
            threshold: 2,
            epoch: 1,
            epoch_start: 1700000000,
            epoch_duration_secs: 3600,
            group_pubkey: vec![0xAA; 32],
        };

        assert!(committee.validate().is_ok());
        assert_eq!(committee.total_stake(), 2);
    }

    // ════════════════════════════════════════════════════════════════════════════════
    // RECEIPT DATA PROTO TESTS
    // ════════════════════════════════════════════════════════════════════════════════

    fn make_valid_receipt_data() -> ReceiptDataProto {
        ReceiptDataProto {
            workload_id: vec![0x01; 32],
            blob_hash: vec![0x02; 32],
            placement: vec![vec![0x03; 32], vec![0x04; 32]],
            timestamp: 1700000000,
            sequence: 1,
            epoch: 1,
        }
    }

    fn make_valid_aggregate_signature() -> super::signing::AggregateSignatureProto {
        super::signing::AggregateSignatureProto {
            signature: vec![0xAA; 64],
            signer_ids: vec![vec![0x01; 32], vec![0x02; 32]],
            message_hash: vec![0xBB; 32],
            aggregated_at: 1700000000,
        }
    }

    fn make_valid_threshold_receipt() -> ThresholdReceiptProto {
        ThresholdReceiptProto {
            receipt_data: make_valid_receipt_data(),
            signature: make_valid_aggregate_signature(),
            signer_ids: vec![vec![0x01; 32], vec![0x02; 32]], // MUST match signature.signer_ids
            epoch: 1, // MUST match receipt_data.epoch
            committee_hash: vec![0xCC; 32],
        }
    }

    #[test]
    fn test_receipt_data_validate_valid() {
        let data = make_valid_receipt_data();
        assert!(data.validate().is_ok());
    }

    #[test]
    fn test_receipt_data_validate_invalid_workload_id() {
        let mut data = make_valid_receipt_data();
        data.workload_id = vec![0x01; 16]; // Wrong length

        let result = data.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CommitteeValidationError::InvalidWorkloadIdLength { expected: 32, got: 16 }
        ));
    }

    #[test]
    fn test_receipt_data_validate_invalid_blob_hash() {
        let mut data = make_valid_receipt_data();
        data.blob_hash = vec![0x02; 64]; // Wrong length

        let result = data.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CommitteeValidationError::InvalidBlobHashLength { expected: 32, got: 64 }
        ));
    }

    #[test]
    fn test_receipt_data_validate_invalid_placement_node() {
        let mut data = make_valid_receipt_data();
        data.placement[1] = vec![0x04; 16]; // Wrong length at index 1

        let result = data.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CommitteeValidationError::InvalidPlacementNodeLength { index: 1, expected: 32, got: 16 }
        ));
    }

    #[test]
    fn test_receipt_data_compute_hash_deterministic() {
        let data = make_valid_receipt_data();

        let hash1 = data.compute_hash();
        let hash2 = data.compute_hash();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_receipt_data_compute_hash_different_workload() {
        let data1 = make_valid_receipt_data();
        let mut data2 = make_valid_receipt_data();
        data2.workload_id = vec![0xFF; 32];

        let hash1 = data1.compute_hash();
        let hash2 = data2.compute_hash();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_receipt_data_compute_hash_different_blob_hash() {
        let data1 = make_valid_receipt_data();
        let mut data2 = make_valid_receipt_data();
        data2.blob_hash = vec![0xFF; 32];

        let hash1 = data1.compute_hash();
        let hash2 = data2.compute_hash();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_receipt_data_compute_hash_different_placement() {
        let data1 = make_valid_receipt_data();
        let mut data2 = make_valid_receipt_data();
        data2.placement = vec![vec![0xFF; 32]]; // Different placement

        let hash1 = data1.compute_hash();
        let hash2 = data2.compute_hash();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_receipt_data_compute_hash_placement_order_matters() {
        let data1 = ReceiptDataProto {
            workload_id: vec![0x01; 32],
            blob_hash: vec![0x02; 32],
            placement: vec![vec![0x03; 32], vec![0x04; 32]],
            timestamp: 1700000000,
            sequence: 1,
            epoch: 1,
        };
        let data2 = ReceiptDataProto {
            workload_id: vec![0x01; 32],
            blob_hash: vec![0x02; 32],
            placement: vec![vec![0x04; 32], vec![0x03; 32]], // Reversed
            timestamp: 1700000000,
            sequence: 1,
            epoch: 1,
        };

        let hash1 = data1.compute_hash();
        let hash2 = data2.compute_hash();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_receipt_data_compute_hash_different_timestamp() {
        let data1 = make_valid_receipt_data();
        let mut data2 = make_valid_receipt_data();
        data2.timestamp = 9999;

        let hash1 = data1.compute_hash();
        let hash2 = data2.compute_hash();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_receipt_data_compute_hash_different_sequence() {
        let data1 = make_valid_receipt_data();
        let mut data2 = make_valid_receipt_data();
        data2.sequence = 9999;

        let hash1 = data1.compute_hash();
        let hash2 = data2.compute_hash();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_receipt_data_compute_hash_different_epoch() {
        let data1 = make_valid_receipt_data();
        let mut data2 = make_valid_receipt_data();
        data2.epoch = 9999;

        let hash1 = data1.compute_hash();
        let hash2 = data2.compute_hash();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_receipt_data_empty_placement() {
        let data = ReceiptDataProto {
            workload_id: vec![0x01; 32],
            blob_hash: vec![0x02; 32],
            placement: vec![], // Empty is valid
            timestamp: 1700000000,
            sequence: 1,
            epoch: 1,
        };

        assert!(data.validate().is_ok());
    }

    // ════════════════════════════════════════════════════════════════════════════════
    // THRESHOLD RECEIPT PROTO TESTS
    // ════════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_threshold_receipt_validate_valid() {
        let receipt = make_valid_threshold_receipt();
        assert!(receipt.validate().is_ok());
    }

    #[test]
    fn test_threshold_receipt_validate_invalid_receipt_data() {
        let mut receipt = make_valid_threshold_receipt();
        receipt.receipt_data.workload_id = vec![0x01; 16]; // Invalid

        let result = receipt.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CommitteeValidationError::InvalidReceiptData { .. }
        ));
    }

    #[test]
    fn test_threshold_receipt_validate_invalid_signature() {
        let mut receipt = make_valid_threshold_receipt();
        receipt.signature.signature = vec![0xAA; 32]; // Wrong length

        let result = receipt.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CommitteeValidationError::InvalidSignature { .. }
        ));
    }

    #[test]
    fn test_threshold_receipt_validate_empty_signer_ids() {
        let mut receipt = make_valid_threshold_receipt();
        receipt.signer_ids = vec![]; // Empty
        // Also clear signature.signer_ids to avoid count mismatch
        receipt.signature.signer_ids = vec![];

        let result = receipt.validate();
        assert!(result.is_err());
        // Could be EmptySignerIds or InvalidSignature depending on validation order
    }

    #[test]
    fn test_threshold_receipt_validate_invalid_signer_id_length() {
        let mut receipt = make_valid_threshold_receipt();
        receipt.signer_ids[0] = vec![0x01; 16]; // Wrong length
        receipt.signature.signer_ids[0] = vec![0x01; 16]; // Keep them matching

        let result = receipt.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_threshold_receipt_validate_duplicate_signer_id() {
        let mut receipt = make_valid_threshold_receipt();
        receipt.signer_ids = vec![vec![0x01; 32], vec![0x01; 32]]; // Duplicate
        receipt.signature.signer_ids = vec![vec![0x01; 32], vec![0x01; 32]];

        let result = receipt.validate();
        assert!(result.is_err());
        // Could fail on duplicate check
    }

    #[test]
    fn test_threshold_receipt_validate_signer_ids_mismatch_count() {
        let mut receipt = make_valid_threshold_receipt();
        receipt.signer_ids = vec![vec![0x01; 32]]; // Only 1
        // signature.signer_ids still has 2

        let result = receipt.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CommitteeValidationError::SignerIdsMismatch
        ));
    }

    #[test]
    fn test_threshold_receipt_validate_signer_ids_mismatch_content() {
        let mut receipt = make_valid_threshold_receipt();
        receipt.signer_ids[0] = vec![0xFF; 32]; // Different from signature.signer_ids[0]

        let result = receipt.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CommitteeValidationError::SignerIdsMismatch
        ));
    }

    #[test]
    fn test_threshold_receipt_validate_invalid_committee_hash() {
        let mut receipt = make_valid_threshold_receipt();
        receipt.committee_hash = vec![0xCC; 16]; // Wrong length

        let result = receipt.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CommitteeValidationError::InvalidCommitteeHashLength { expected: 32, got: 16 }
        ));
    }

    #[test]
    fn test_threshold_receipt_validate_epoch_mismatch() {
        let mut receipt = make_valid_threshold_receipt();
        receipt.epoch = 99; // Different from receipt_data.epoch

        let result = receipt.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CommitteeValidationError::EpochMismatch { receipt_epoch: 99, data_epoch: 1 }
        ));
    }

    #[test]
    fn test_threshold_receipt_encode_decode_roundtrip() {
        let receipt = make_valid_threshold_receipt();

        let encoded = encode_receipt(&receipt);
        let decoded = decode_receipt(&encoded);

        assert!(decoded.is_ok());
        assert_eq!(receipt, decoded.expect("valid"));
    }

    #[test]
    fn test_threshold_receipt_encode_deterministic() {
        let receipt = make_valid_threshold_receipt();

        let encoded1 = encode_receipt(&receipt);
        let encoded2 = encode_receipt(&receipt);

        assert_eq!(encoded1, encoded2);
    }

    #[test]
    fn test_threshold_receipt_decode_invalid_bytes() {
        let invalid_bytes = vec![0xFF; 10];
        let result = decode_receipt(&invalid_bytes);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CommitteeDecodeError::DeserializationFailed { .. }
        ));
    }

    #[test]
    fn test_threshold_receipt_decode_validates() {
        // Create invalid proto manually
        let invalid_receipt = ThresholdReceiptProto {
            receipt_data: ReceiptDataProto {
                workload_id: vec![0x01; 16], // Invalid length
                blob_hash: vec![0x02; 32],
                placement: vec![],
                timestamp: 1,
                sequence: 1,
                epoch: 1,
            },
            signature: make_valid_aggregate_signature(),
            signer_ids: vec![vec![0x01; 32], vec![0x02; 32]],
            epoch: 1,
            committee_hash: vec![0xCC; 32],
        };

        // Serialize (bypassing validation)
        let bytes = bincode::serialize(&invalid_receipt).expect("serialize");

        // Decode should fail validation
        let result = decode_receipt(&bytes);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CommitteeDecodeError::ValidationFailed { .. }
        ));
    }

    #[test]
    fn test_compute_receipt_hash_deterministic() {
        let receipt = make_valid_threshold_receipt();

        let hash1 = compute_receipt_hash(&receipt);
        let hash2 = compute_receipt_hash(&receipt);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_compute_receipt_hash_different_receipt_data() {
        let receipt1 = make_valid_threshold_receipt();
        let mut receipt2 = make_valid_threshold_receipt();
        receipt2.receipt_data.sequence = 999;

        let hash1 = compute_receipt_hash(&receipt1);
        let hash2 = compute_receipt_hash(&receipt2);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_compute_receipt_hash_different_signature() {
        let receipt1 = make_valid_threshold_receipt();
        let mut receipt2 = make_valid_threshold_receipt();
        receipt2.signature.signature = vec![0xFF; 64];

        let hash1 = compute_receipt_hash(&receipt1);
        let hash2 = compute_receipt_hash(&receipt2);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_compute_receipt_hash_different_signer_ids() {
        let receipt1 = make_valid_threshold_receipt();
        let mut receipt2 = make_valid_threshold_receipt();
        receipt2.signer_ids[0] = vec![0xFF; 32];
        receipt2.signature.signer_ids[0] = vec![0xFF; 32];

        let hash1 = compute_receipt_hash(&receipt1);
        let hash2 = compute_receipt_hash(&receipt2);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_compute_receipt_hash_different_committee_hash() {
        let receipt1 = make_valid_threshold_receipt();
        let mut receipt2 = make_valid_threshold_receipt();
        receipt2.committee_hash = vec![0xFF; 32];

        let hash1 = compute_receipt_hash(&receipt1);
        let hash2 = compute_receipt_hash(&receipt2);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_threshold_receipt_signer_count() {
        let receipt = make_valid_threshold_receipt();
        assert_eq!(receipt.signer_count(), 2);
    }

    // ════════════════════════════════════════════════════════════════════════════════
    // RECEIPT ERROR DISPLAY TESTS
    // ════════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_receipt_error_workload_id_display() {
        let error = CommitteeValidationError::InvalidWorkloadIdLength {
            expected: 32,
            got: 16,
        };
        let display = format!("{}", error);
        assert!(display.contains("workload_id"));
        assert!(display.contains("32"));
        assert!(display.contains("16"));
    }

    #[test]
    fn test_receipt_error_signer_ids_mismatch_display() {
        let error = CommitteeValidationError::SignerIdsMismatch;
        let display = format!("{}", error);
        assert!(display.contains("signer_ids"));
        assert!(display.contains("match"));
    }

    #[test]
    fn test_receipt_error_epoch_mismatch_display() {
        let error = CommitteeValidationError::EpochMismatch {
            receipt_epoch: 99,
            data_epoch: 1,
        };
        let display = format!("{}", error);
        assert!(display.contains("epoch"));
        assert!(display.contains("99"));
        assert!(display.contains("1"));
    }
}