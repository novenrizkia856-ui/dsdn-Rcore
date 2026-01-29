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
}