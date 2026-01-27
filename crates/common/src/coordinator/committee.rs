//! # Coordinator Committee
//!
//! Module ini menyediakan `CoordinatorCommittee` struct yang merepresentasikan
//! committee coordinators dalam sistem multi-coordinator DSDN.
//!
//! ## Struktur
//!
//! | Field | Type | Deskripsi |
//! |-------|------|-----------|
//! | `members` | `Vec<CoordinatorMember>` | Anggota committee |
//! | `threshold` | `u8` | Threshold untuk signing (t-of-n) |
//! | `epoch` | `u64` | Nomor epoch |
//! | `epoch_start` | `Timestamp` | Waktu mulai epoch |
//! | `epoch_duration_secs` | `u64` | Durasi epoch dalam detik |
//! | `group_pubkey` | `GroupPublicKey` | Shared public key hasil DKG |
//!
//! ## Validation
//!
//! Committee dianggap valid jika:
//! - Members tidak kosong
//! - Threshold ≥ 2
//! - Threshold ≤ jumlah members
//! - Tidak ada duplicate member ID
//! - Epoch duration > 0
//! - Group pubkey format valid
//!
//! ## Determinism
//!
//! Constructor TIDAK melakukan sorting atau mutasi tersembunyi.
//! Members disimpan dalam urutan yang diberikan.

use std::collections::HashSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::{CoordinatorId, CoordinatorMember, Timestamp};
use dsdn_tss::GroupPublicKey;

// ════════════════════════════════════════════════════════════════════════════════
// COMMITTEE ERROR
// ════════════════════════════════════════════════════════════════════════════════

/// Error type untuk operasi `CoordinatorCommittee`.
///
/// Semua error variants menyimpan informasi diagnostik yang berguna
/// untuk debugging dan logging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitteeError {
    /// Threshold tidak valid.
    ///
    /// Terjadi ketika:
    /// - threshold < 2
    /// - threshold > member_count
    InvalidThreshold {
        /// Threshold yang diberikan.
        threshold: u8,
        /// Jumlah members.
        member_count: usize,
    },

    /// Jumlah members tidak mencukupi.
    ///
    /// Terjadi ketika members kosong.
    InsufficientMembers {
        /// Jumlah minimum yang diperlukan.
        min: usize,
        /// Jumlah yang diberikan.
        got: usize,
    },

    /// Terdapat duplicate member ID.
    DuplicateMember {
        /// ID member yang duplikat.
        id: CoordinatorId,
    },

    /// Epoch duration tidak valid (harus > 0).
    InvalidEpochDuration,

    /// Group pubkey format tidak valid.
    InvalidGroupPubkey,
}

impl fmt::Display for CommitteeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommitteeError::InvalidThreshold {
                threshold,
                member_count,
            } => {
                write!(
                    f,
                    "invalid threshold: {} for {} members (must be >= 2 and <= member count)",
                    threshold, member_count
                )
            }
            CommitteeError::InsufficientMembers { min, got } => {
                write!(
                    f,
                    "insufficient members: got {}, minimum required {}",
                    got, min
                )
            }
            CommitteeError::DuplicateMember { id } => {
                write!(f, "duplicate member ID: {}", id.to_hex())
            }
            CommitteeError::InvalidEpochDuration => {
                write!(f, "invalid epoch duration: must be > 0")
            }
            CommitteeError::InvalidGroupPubkey => {
                write!(f, "invalid group pubkey format")
            }
        }
    }
}

impl std::error::Error for CommitteeError {}

// ════════════════════════════════════════════════════════════════════════════════
// COORDINATOR COMMITTEE
// ════════════════════════════════════════════════════════════════════════════════

/// Committee coordinators untuk threshold signing.
///
/// `CoordinatorCommittee` merepresentasikan grup coordinators yang
/// berpartisipasi dalam threshold signing untuk epoch tertentu.
///
/// ## Immutability
///
/// Setelah construction, semua fields bersifat immutable.
/// Untuk epoch baru, buat committee baru.
///
/// ## Determinism
///
/// - Members disimpan dalam urutan yang diberikan (tidak di-sort)
/// - Tidak ada mutasi tersembunyi
/// - Serialization stabil
///
/// ## Contoh
///
/// ```rust,ignore
/// use dsdn_common::{CoordinatorCommittee, CoordinatorMember, CoordinatorId, ValidatorId};
/// use dsdn_tss::{GroupPublicKey, ParticipantPublicKey};
///
/// let members = vec![member1, member2, member3];
/// let group_pubkey = GroupPublicKey::from_bytes([0x01; 32]).unwrap();
///
/// let committee = CoordinatorCommittee::new(
///     members,
///     2,           // threshold
///     1,           // epoch
///     1700000000,  // epoch_start
///     3600,        // epoch_duration_secs
///     group_pubkey,
/// )?;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinatorCommittee {
    /// Anggota committee.
    members: Vec<CoordinatorMember>,

    /// Threshold untuk signing (t in t-of-n).
    threshold: u8,

    /// Nomor epoch.
    epoch: u64,

    /// Timestamp mulai epoch (Unix seconds).
    epoch_start: Timestamp,

    /// Durasi epoch dalam detik.
    epoch_duration_secs: u64,

    /// Shared public key hasil DKG.
    group_pubkey: GroupPublicKey,
}

impl CoordinatorCommittee {
    /// Membuat `CoordinatorCommittee` baru dengan validasi.
    ///
    /// # Arguments
    ///
    /// * `members` - Anggota committee (tidak boleh kosong)
    /// * `threshold` - Threshold signing (≥ 2, ≤ member count)
    /// * `epoch` - Nomor epoch
    /// * `epoch_start` - Timestamp mulai epoch
    /// * `epoch_duration_secs` - Durasi epoch (> 0)
    /// * `group_pubkey` - Shared public key hasil DKG
    ///
    /// # Errors
    ///
    /// - `InsufficientMembers` jika members kosong
    /// - `InvalidThreshold` jika threshold < 2 atau threshold > members.len()
    /// - `DuplicateMember` jika ada duplicate member ID
    /// - `InvalidEpochDuration` jika epoch_duration_secs = 0
    /// - `InvalidGroupPubkey` jika group_pubkey format tidak valid
    ///
    /// # Note
    ///
    /// Constructor TIDAK melakukan sorting atau normalisasi.
    /// Members disimpan dalam urutan yang diberikan.
    pub fn new(
        members: Vec<CoordinatorMember>,
        threshold: u8,
        epoch: u64,
        epoch_start: Timestamp,
        epoch_duration_secs: u64,
        group_pubkey: GroupPublicKey,
    ) -> Result<Self, CommitteeError> {
        // Validation 1: members tidak boleh kosong
        if members.is_empty() {
            return Err(CommitteeError::InsufficientMembers { min: 1, got: 0 });
        }

        // Validation 2: threshold >= 2
        if threshold < 2 {
            return Err(CommitteeError::InvalidThreshold {
                threshold,
                member_count: members.len(),
            });
        }

        // Validation 3: threshold <= members.len()
        if (threshold as usize) > members.len() {
            return Err(CommitteeError::InvalidThreshold {
                threshold,
                member_count: members.len(),
            });
        }

        // Validation 4: no duplicate member IDs
        let mut seen_ids: HashSet<CoordinatorId> = HashSet::with_capacity(members.len());
        for member in &members {
            let id = *member.id(); // CoordinatorId implements Copy
            if !seen_ids.insert(id) {
                return Err(CommitteeError::DuplicateMember { id });
            }
        }

        // Validation 5: epoch_duration_secs > 0
        if epoch_duration_secs == 0 {
            return Err(CommitteeError::InvalidEpochDuration);
        }

        // Validation 6: group_pubkey format valid
        if group_pubkey.verify_format().is_err() {
            return Err(CommitteeError::InvalidGroupPubkey);
        }

        Ok(Self {
            members,
            threshold,
            epoch,
            epoch_start,
            epoch_duration_secs,
            group_pubkey,
        })
    }

    /// Membuat `CoordinatorCommittee` kosong untuk testing.
    ///
    /// **WARNING**: Hanya untuk testing! Committee ini tidak valid
    /// untuk operasi production.
    ///
    /// # Arguments
    ///
    /// * `epoch` - Nomor epoch
    ///
    /// # Returns
    ///
    /// Committee kosong dengan:
    /// - members = []
    /// - threshold = 0
    /// - epoch_start = 0
    /// - epoch_duration_secs = 0
    /// - group_pubkey = zero bytes (TIDAK VALID untuk production)
    #[must_use]
    pub fn empty(epoch: u64) -> Self {
        // Create zero group pubkey - this is ONLY for testing
        // In production, this would fail verify_format()
        // We bypass validation here intentionally for testing purposes
        Self {
            members: Vec::new(),
            threshold: 0,
            epoch,
            epoch_start: 0,
            epoch_duration_secs: 0,
            // Use a non-zero value to pass serde, but still invalid for real use
            // We use 0x01 repeated to ensure it's not the identity point
            group_pubkey: create_test_group_pubkey(),
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // GETTERS
    // ────────────────────────────────────────────────────────────────────────────

    /// Mengembalikan reference ke members.
    #[must_use]
    #[inline]
    pub fn members(&self) -> &[CoordinatorMember] {
        &self.members
    }

    /// Mengembalikan threshold.
    #[must_use]
    #[inline]
    pub const fn threshold(&self) -> u8 {
        self.threshold
    }

    /// Mengembalikan epoch number.
    #[must_use]
    #[inline]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Mengembalikan epoch start timestamp.
    #[must_use]
    #[inline]
    pub const fn epoch_start(&self) -> Timestamp {
        self.epoch_start
    }

    /// Mengembalikan epoch duration dalam detik.
    #[must_use]
    #[inline]
    pub const fn epoch_duration_secs(&self) -> u64 {
        self.epoch_duration_secs
    }

    /// Mengembalikan reference ke group public key.
    #[must_use]
    #[inline]
    pub const fn group_pubkey(&self) -> &GroupPublicKey {
        &self.group_pubkey
    }

    /// Mengembalikan jumlah members.
    #[must_use]
    #[inline]
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// Menghitung epoch end timestamp.
    ///
    /// Returns `epoch_start + epoch_duration_secs`.
    /// Menggunakan saturating_add untuk menghindari overflow.
    #[must_use]
    #[inline]
    pub fn epoch_end(&self) -> Timestamp {
        self.epoch_start.saturating_add(self.epoch_duration_secs)
    }

    /// Mengecek apakah committee ini valid untuk production.
    ///
    /// Committee valid jika:
    /// - members tidak kosong
    /// - threshold >= 2
    /// - threshold <= member_count
    /// - epoch_duration_secs > 0
    /// - group_pubkey format valid
    ///
    /// # Note
    ///
    /// Committee yang dibuat via `new()` selalu valid.
    /// Committee yang dibuat via `empty()` tidak valid.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        if self.members.is_empty() {
            return false;
        }

        if self.threshold < 2 {
            return false;
        }

        if (self.threshold as usize) > self.members.len() {
            return false;
        }

        if self.epoch_duration_secs == 0 {
            return false;
        }

        if self.group_pubkey.verify_format().is_err() {
            return false;
        }

        true
    }

    /// Mencari member berdasarkan CoordinatorId.
    ///
    /// # Arguments
    ///
    /// * `id` - CoordinatorId yang dicari
    ///
    /// # Returns
    ///
    /// `Some(&CoordinatorMember)` jika ditemukan, `None` jika tidak.
    #[must_use]
    pub fn find_member(&self, id: &CoordinatorId) -> Option<&CoordinatorMember> {
        self.members.iter().find(|m| m.id() == id)
    }

    /// Mengecek apakah CoordinatorId adalah member committee.
    ///
    /// # Arguments
    ///
    /// * `id` - CoordinatorId yang dicek
    #[must_use]
    pub fn contains_member(&self, id: &CoordinatorId) -> bool {
        self.members.iter().any(|m| m.id() == id)
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════════

/// Create a test group pubkey for empty() constructor.
///
/// This uses non-zero bytes to avoid identity point, but the resulting
/// committee is still not valid for production use.
fn create_test_group_pubkey() -> GroupPublicKey {
    // Use 0x01 repeated - this passes from_bytes validation but is not a real key
    // This is safe because empty() is documented as testing-only
    GroupPublicKey::from_bytes([0x01; 32]).unwrap_or_else(|_| {
        // Fallback: if somehow 0x01 fails, use 0x02
        // This should never happen based on current implementation
        GroupPublicKey::from_bytes([0x02; 32]).expect("test pubkey creation failed")
    })
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinator::ValidatorId;
    use dsdn_tss::ParticipantPublicKey;

    // ────────────────────────────────────────────────────────────────────────────
    // HELPER FUNCTIONS
    // ────────────────────────────────────────────────────────────────────────────

    fn make_coordinator_id(byte: u8) -> CoordinatorId {
        CoordinatorId::new([byte; 32])
    }

    fn make_validator_id(byte: u8) -> ValidatorId {
        ValidatorId::new([byte; 32])
    }

    fn make_pubkey(byte: u8) -> ParticipantPublicKey {
        let b = if byte == 0 { 1 } else { byte };
        ParticipantPublicKey::from_bytes([b; 32]).expect("valid pubkey")
    }

    fn make_member(id_byte: u8, stake: u64) -> CoordinatorMember {
        CoordinatorMember::with_timestamp(
            make_coordinator_id(id_byte),
            make_validator_id(id_byte),
            make_pubkey(id_byte),
            stake,
            1700000000,
        )
    }

    fn make_group_pubkey() -> GroupPublicKey {
        GroupPublicKey::from_bytes([0x01; 32]).expect("valid group pubkey")
    }

    fn make_valid_committee() -> CoordinatorCommittee {
        let members = vec![make_member(0x01, 1000), make_member(0x02, 2000)];
        CoordinatorCommittee::new(members, 2, 1, 1700000000, 3600, make_group_pubkey())
            .expect("valid committee")
    }

    // ────────────────────────────────────────────────────────────────────────────
    // COMMITTEE ERROR TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_error_display_invalid_threshold() {
        let err = CommitteeError::InvalidThreshold {
            threshold: 5,
            member_count: 3,
        };
        let msg = err.to_string();
        assert!(msg.contains("5"));
        assert!(msg.contains("3"));
    }

    #[test]
    fn test_error_display_insufficient_members() {
        let err = CommitteeError::InsufficientMembers { min: 1, got: 0 };
        let msg = err.to_string();
        assert!(msg.contains("0"));
        assert!(msg.contains("1"));
    }

    #[test]
    fn test_error_display_duplicate_member() {
        let id = make_coordinator_id(0x42);
        let err = CommitteeError::DuplicateMember { id };
        let msg = err.to_string();
        assert!(msg.contains("duplicate"));
    }

    #[test]
    fn test_error_display_invalid_epoch_duration() {
        let err = CommitteeError::InvalidEpochDuration;
        let msg = err.to_string();
        assert!(msg.contains("epoch duration"));
    }

    #[test]
    fn test_error_display_invalid_group_pubkey() {
        let err = CommitteeError::InvalidGroupPubkey;
        let msg = err.to_string();
        assert!(msg.contains("pubkey"));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // CONSTRUCTOR TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_new_valid_committee() {
        let members = vec![make_member(0x01, 1000), make_member(0x02, 2000)];
        let group_pubkey = make_group_pubkey();

        let result = CoordinatorCommittee::new(members, 2, 1, 1700000000, 3600, group_pubkey);

        assert!(result.is_ok());
        let committee = result.unwrap();
        assert_eq!(committee.member_count(), 2);
        assert_eq!(committee.threshold(), 2);
        assert_eq!(committee.epoch(), 1);
        assert_eq!(committee.epoch_start(), 1700000000);
        assert_eq!(committee.epoch_duration_secs(), 3600);
    }

    #[test]
    fn test_new_empty_members_fails() {
        let members: Vec<CoordinatorMember> = vec![];
        let group_pubkey = make_group_pubkey();

        let result = CoordinatorCommittee::new(members, 2, 1, 1700000000, 3600, group_pubkey);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CommitteeError::InsufficientMembers { min: 1, got: 0 }
        ));
    }

    #[test]
    fn test_new_threshold_less_than_2_fails() {
        let members = vec![make_member(0x01, 1000), make_member(0x02, 2000)];
        let group_pubkey = make_group_pubkey();

        let result = CoordinatorCommittee::new(members, 1, 1, 1700000000, 3600, group_pubkey);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CommitteeError::InvalidThreshold {
                threshold: 1,
                member_count: 2
            }
        ));
    }

    #[test]
    fn test_new_threshold_zero_fails() {
        let members = vec![make_member(0x01, 1000)];
        let group_pubkey = make_group_pubkey();

        let result = CoordinatorCommittee::new(members, 0, 1, 1700000000, 3600, group_pubkey);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CommitteeError::InvalidThreshold { .. }
        ));
    }

    #[test]
    fn test_new_threshold_exceeds_members_fails() {
        let members = vec![make_member(0x01, 1000), make_member(0x02, 2000)];
        let group_pubkey = make_group_pubkey();

        let result = CoordinatorCommittee::new(members, 5, 1, 1700000000, 3600, group_pubkey);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CommitteeError::InvalidThreshold {
                threshold: 5,
                member_count: 2
            }
        ));
    }

    #[test]
    fn test_new_duplicate_member_fails() {
        let members = vec![
            make_member(0x01, 1000),
            make_member(0x01, 2000), // Duplicate ID!
        ];
        let group_pubkey = make_group_pubkey();

        let result = CoordinatorCommittee::new(members, 2, 1, 1700000000, 3600, group_pubkey);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CommitteeError::DuplicateMember { .. }
        ));
    }

    #[test]
    fn test_new_zero_epoch_duration_fails() {
        let members = vec![make_member(0x01, 1000), make_member(0x02, 2000)];
        let group_pubkey = make_group_pubkey();

        let result = CoordinatorCommittee::new(members, 2, 1, 1700000000, 0, group_pubkey);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CommitteeError::InvalidEpochDuration
        ));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // EMPTY CONSTRUCTOR TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_empty_creates_invalid_committee() {
        let committee = CoordinatorCommittee::empty(5);

        assert_eq!(committee.epoch(), 5);
        assert_eq!(committee.threshold(), 0);
        assert!(committee.members().is_empty());
        assert_eq!(committee.epoch_start(), 0);
        assert_eq!(committee.epoch_duration_secs(), 0);
        assert!(!committee.is_valid());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // GETTER TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_getters_return_correct_values() {
        let committee = make_valid_committee();

        assert_eq!(committee.member_count(), 2);
        assert_eq!(committee.threshold(), 2);
        assert_eq!(committee.epoch(), 1);
        assert_eq!(committee.epoch_start(), 1700000000);
        assert_eq!(committee.epoch_duration_secs(), 3600);
    }

    #[test]
    fn test_epoch_end_calculation() {
        let committee = make_valid_committee();
        assert_eq!(committee.epoch_end(), 1700000000 + 3600);
    }

    #[test]
    fn test_epoch_end_no_overflow() {
        let members = vec![make_member(0x01, 1000), make_member(0x02, 2000)];
        let committee = CoordinatorCommittee::new(
            members,
            2,
            1,
            u64::MAX - 100,
            1000,
            make_group_pubkey(),
        )
        .unwrap();

        // Should saturate instead of overflow
        assert_eq!(committee.epoch_end(), u64::MAX);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // IS_VALID TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_is_valid_for_valid_committee() {
        let committee = make_valid_committee();
        assert!(committee.is_valid());
    }

    #[test]
    fn test_is_valid_for_empty_committee() {
        let committee = CoordinatorCommittee::empty(1);
        assert!(!committee.is_valid());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // MEMBER LOOKUP TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_find_member_existing() {
        let committee = make_valid_committee();
        let id = make_coordinator_id(0x01);

        let found = committee.find_member(&id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().id(), &id);
    }

    #[test]
    fn test_find_member_not_existing() {
        let committee = make_valid_committee();
        let id = make_coordinator_id(0xFF);

        let found = committee.find_member(&id);
        assert!(found.is_none());
    }

    #[test]
    fn test_contains_member_existing() {
        let committee = make_valid_committee();
        let id = make_coordinator_id(0x01);

        assert!(committee.contains_member(&id));
    }

    #[test]
    fn test_contains_member_not_existing() {
        let committee = make_valid_committee();
        let id = make_coordinator_id(0xFF);

        assert!(!committee.contains_member(&id));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SERIALIZATION TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_serde_json_roundtrip() {
        let original = make_valid_committee();

        let serialized = serde_json::to_string(&original).expect("serialize");
        let deserialized: CoordinatorCommittee =
            serde_json::from_str(&serialized).expect("deserialize");

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_serde_bincode_roundtrip() {
        let original = make_valid_committee();

        let serialized = bincode::serialize(&original).expect("serialize");
        let deserialized: CoordinatorCommittee =
            bincode::deserialize(&serialized).expect("deserialize");

        assert_eq!(original, deserialized);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // CLONE TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_clone() {
        let original = make_valid_committee();
        let cloned = original.clone();

        assert_eq!(original, cloned);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // DEBUG TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_debug() {
        let committee = make_valid_committee();
        let debug = format!("{:?}", committee);

        assert!(debug.contains("CoordinatorCommittee"));
        assert!(debug.contains("threshold"));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SEND + SYNC TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<CoordinatorCommittee>();
        assert_send_sync::<CommitteeError>();
    }

    // ────────────────────────────────────────────────────────────────────────────
    // EDGE CASE TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_minimum_valid_committee() {
        // Minimum valid: 2 members, threshold 2
        let members = vec![make_member(0x01, 1000), make_member(0x02, 2000)];
        let result =
            CoordinatorCommittee::new(members, 2, 0, 0, 1, make_group_pubkey());

        assert!(result.is_ok());
    }

    #[test]
    fn test_large_committee() {
        // Create 10 members
        let members: Vec<_> = (1u8..=10).map(|i| make_member(i, i as u64 * 100)).collect();

        let result =
            CoordinatorCommittee::new(members, 7, 1, 1700000000, 3600, make_group_pubkey());

        assert!(result.is_ok());
        assert_eq!(result.unwrap().member_count(), 10);
    }

    #[test]
    fn test_members_order_preserved() {
        // Verify members are NOT sorted
        let members = vec![
            make_member(0x03, 100), // Lower stake, higher ID
            make_member(0x01, 300), // Higher stake, lower ID
            make_member(0x02, 200),
        ];

        let committee =
            CoordinatorCommittee::new(members, 2, 1, 1700000000, 3600, make_group_pubkey())
                .unwrap();

        // Order should be preserved (not sorted by stake or ID)
        assert_eq!(committee.members()[0].id().as_bytes(), &[0x03; 32]);
        assert_eq!(committee.members()[1].id().as_bytes(), &[0x01; 32]);
        assert_eq!(committee.members()[2].id().as_bytes(), &[0x02; 32]);
    }
}