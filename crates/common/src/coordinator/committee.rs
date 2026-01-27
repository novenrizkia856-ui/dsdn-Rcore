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
use sha3::{Digest, Sha3_256};

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
        Self {
            members: Vec::new(),
            threshold: 0,
            epoch,
            epoch_start: 0,
            epoch_duration_secs: 0,
            group_pubkey: create_test_group_pubkey(),
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // 1. MEMBERSHIP QUERIES
    // ════════════════════════════════════════════════════════════════════════════

    /// Mengecek apakah CoordinatorId adalah member committee.
    ///
    /// # Arguments
    ///
    /// * `id` - CoordinatorId yang dicek
    ///
    /// # Returns
    ///
    /// `true` jika id adalah member, `false` jika tidak.
    #[must_use]
    #[inline]
    pub fn is_member(&self, id: &CoordinatorId) -> bool {
        self.members.iter().any(|m| m.id() == id)
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
    pub fn get_member(&self, id: &CoordinatorId) -> Option<&CoordinatorMember> {
        self.members.iter().find(|m| m.id() == id)
    }

    /// Mengambil member berdasarkan index.
    ///
    /// # Arguments
    ///
    /// * `index` - Index member (0-based)
    ///
    /// # Returns
    ///
    /// `Some(&CoordinatorMember)` jika index valid, `None` jika out of bounds.
    #[must_use]
    #[inline]
    pub fn get_member_by_index(&self, index: usize) -> Option<&CoordinatorMember> {
        self.members.get(index)
    }

    /// Mengembalikan jumlah members.
    #[must_use]
    #[inline]
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// Mengembalikan reference ke members slice.
    #[must_use]
    #[inline]
    pub fn members(&self) -> &[CoordinatorMember] {
        &self.members
    }

    /// Mengembalikan daftar semua member IDs.
    ///
    /// Urutan SAMA dengan urutan internal members vector.
    ///
    /// # Returns
    ///
    /// `Vec<CoordinatorId>` berisi semua member IDs dalam urutan yang sama.
    #[must_use]
    pub fn member_ids(&self) -> Vec<CoordinatorId> {
        self.members.iter().map(|m| *m.id()).collect()
    }

    // ════════════════════════════════════════════════════════════════════════════
    // 2. EPOCH QUERIES
    // ════════════════════════════════════════════════════════════════════════════

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

    /// Menghitung epoch end timestamp.
    ///
    /// Returns `epoch_start + epoch_duration_secs`.
    /// Menggunakan saturating_add untuk menghindari overflow.
    #[must_use]
    #[inline]
    pub fn epoch_end(&self) -> Timestamp {
        self.epoch_start.saturating_add(self.epoch_duration_secs)
    }

    /// Mengembalikan epoch duration dalam detik.
    #[must_use]
    #[inline]
    pub const fn epoch_duration_secs(&self) -> u64 {
        self.epoch_duration_secs
    }

    /// Mengecek apakah timestamp berada dalam epoch ini.
    ///
    /// Timestamp valid jika: `epoch_start <= timestamp < epoch_end`
    ///
    /// # Arguments
    ///
    /// * `timestamp` - Timestamp untuk dicek
    ///
    /// # Returns
    ///
    /// `true` jika timestamp dalam range epoch [epoch_start, epoch_end).
    #[must_use]
    pub fn is_epoch_valid(&self, timestamp: Timestamp) -> bool {
        let end = self.epoch_end();
        timestamp >= self.epoch_start && timestamp < end
    }

    /// Menghitung sisa waktu epoch dalam detik.
    ///
    /// # Arguments
    ///
    /// * `now` - Timestamp saat ini
    ///
    /// # Returns
    ///
    /// Sisa waktu dalam detik. Returns 0 jika epoch sudah berakhir.
    #[must_use]
    pub fn epoch_remaining_secs(&self, now: Timestamp) -> u64 {
        let end = self.epoch_end();
        if now >= end {
            return 0;
        }
        end.saturating_sub(now)
    }

    /// Menghitung waktu yang sudah berlalu dalam epoch.
    ///
    /// # Arguments
    ///
    /// * `now` - Timestamp saat ini
    ///
    /// # Returns
    ///
    /// - 0 jika `now <= epoch_start`
    /// - `epoch_duration_secs` jika `now >= epoch_end`
    /// - `now - epoch_start` otherwise
    #[must_use]
    pub fn epoch_elapsed_secs(&self, now: Timestamp) -> u64 {
        if now <= self.epoch_start {
            return 0;
        }

        let end = self.epoch_end();
        if now >= end {
            return self.epoch_duration_secs;
        }

        now.saturating_sub(self.epoch_start)
    }

    /// Menghitung progress epoch sebagai fraction [0.0, 1.0].
    ///
    /// # Arguments
    ///
    /// * `now` - Timestamp saat ini
    ///
    /// # Returns
    ///
    /// - 0.0 jika `now <= epoch_start` atau `epoch_duration_secs == 0`
    /// - 1.0 jika `now >= epoch_end`
    /// - Fraction dalam [0.0, 1.0] otherwise
    ///
    /// # Note
    ///
    /// Tidak pernah return NaN atau nilai di luar [0.0, 1.0].
    #[must_use]
    pub fn epoch_progress(&self, now: Timestamp) -> f64 {
        // Guard against division by zero
        if self.epoch_duration_secs == 0 {
            return 0.0;
        }

        if now <= self.epoch_start {
            return 0.0;
        }

        let end = self.epoch_end();
        if now >= end {
            return 1.0;
        }

        let elapsed = now.saturating_sub(self.epoch_start);
        // Safe: epoch_duration_secs > 0 (checked above)
        let progress = elapsed as f64 / self.epoch_duration_secs as f64;

        // Clamp to [0.0, 1.0] for safety (should already be in range)
        progress.clamp(0.0, 1.0)
    }

    // ════════════════════════════════════════════════════════════════════════════
    // 3. THRESHOLD & SIGNING QUERIES
    // ════════════════════════════════════════════════════════════════════════════

    /// Mengembalikan threshold untuk signing.
    #[must_use]
    #[inline]
    pub const fn threshold(&self) -> u8 {
        self.threshold
    }

    /// Mengembalikan reference ke group public key.
    #[must_use]
    #[inline]
    pub const fn group_pubkey(&self) -> &GroupPublicKey {
        &self.group_pubkey
    }

    /// Mengembalikan jumlah signatures yang diperlukan.
    ///
    /// Identik dengan `threshold()`.
    #[must_use]
    #[inline]
    pub const fn requires_signatures(&self) -> u8 {
        self.threshold
    }

    /// Mengecek apakah set signers dapat membuat valid signature.
    ///
    /// # Arguments
    ///
    /// * `signers` - Slice of CoordinatorIds yang akan sign
    ///
    /// # Returns
    ///
    /// `true` jika:
    /// - Semua signers adalah member committee
    /// - Jumlah signer UNIK >= threshold
    ///
    /// # Note
    ///
    /// - Duplicate signers TIDAK dihitung ganda
    /// - Urutan signers tidak berpengaruh
    #[must_use]
    pub fn can_sign_with(&self, signers: &[CoordinatorId]) -> bool {
        // Collect unique signers that are members
        let mut unique_valid_signers: HashSet<CoordinatorId> = HashSet::new();

        for signer in signers {
            // Check if signer is a member
            if self.is_member(signer) {
                unique_valid_signers.insert(*signer);
            } else {
                // Non-member signer → cannot sign
                return false;
            }
        }

        // Check if we have enough unique signers
        unique_valid_signers.len() >= self.threshold as usize
    }

    // ════════════════════════════════════════════════════════════════════════════
    // 4. STAKE QUERIES
    // ════════════════════════════════════════════════════════════════════════════

    /// Menghitung total stake semua members.
    ///
    /// Menggunakan saturating_add untuk menghindari overflow.
    /// Jika overflow terjadi, returns u64::MAX.
    ///
    /// # Returns
    ///
    /// Total stake semua members.
    #[must_use]
    pub fn total_stake(&self) -> u64 {
        self.members
            .iter()
            .fold(0u64, |acc, m| acc.saturating_add(m.stake()))
    }

    /// Mengambil stake member berdasarkan ID.
    ///
    /// # Arguments
    ///
    /// * `id` - CoordinatorId member
    ///
    /// # Returns
    ///
    /// `Some(stake)` jika member ditemukan, `None` jika tidak.
    #[must_use]
    pub fn member_stake(&self, id: &CoordinatorId) -> Option<u64> {
        self.get_member(id).map(|m| m.stake())
    }

    /// Menghitung stake weight member sebagai fraction.
    ///
    /// # Arguments
    ///
    /// * `id` - CoordinatorId member
    ///
    /// # Returns
    ///
    /// - `None` jika member tidak ditemukan atau total_stake == 0
    /// - `Some(weight)` dimana weight = member_stake / total_stake
    ///
    /// # Note
    ///
    /// Tidak pernah return NaN. Returns None jika total_stake == 0.
    #[must_use]
    pub fn stake_weight(&self, id: &CoordinatorId) -> Option<f64> {
        let total = self.total_stake();
        if total == 0 {
            return None;
        }

        let member_stake = self.member_stake(id)?;
        Some(member_stake as f64 / total as f64)
    }

    // ════════════════════════════════════════════════════════════════════════════
    // 5. COMMITTEE HASH
    // ════════════════════════════════════════════════════════════════════════════

    /// Menghitung hash deterministik committee.
    ///
    /// Hash mencakup:
    /// - epoch (8 bytes, little-endian)
    /// - epoch_start (8 bytes, little-endian)
    /// - epoch_duration_secs (8 bytes, little-endian)
    /// - threshold (1 byte)
    /// - group_pubkey (32 bytes)
    /// - Semua members (dalam urutan vector):
    ///   - id (32 bytes)
    ///   - pubkey (32 bytes)
    ///   - stake (8 bytes, little-endian)
    ///
    /// # Returns
    ///
    /// SHA3-256 hash (32 bytes).
    ///
    /// # Determinism
    ///
    /// Hash sama untuk state committee yang sama.
    /// Tidak bergantung pada alamat memori atau random.
    #[must_use]
    pub fn committee_hash(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();

        // Hash epoch fields
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.epoch_start.to_le_bytes());
        hasher.update(self.epoch_duration_secs.to_le_bytes());

        // Hash threshold
        hasher.update([self.threshold]);

        // Hash group pubkey
        hasher.update(self.group_pubkey.as_bytes());

        // Hash all members in order
        for member in &self.members {
            hasher.update(member.id().as_bytes());
            hasher.update(member.pubkey().as_bytes());
            hasher.update(member.stake().to_le_bytes());
        }

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    // ════════════════════════════════════════════════════════════════════════════
    // VALIDATION & COMPATIBILITY METHODS
    // ════════════════════════════════════════════════════════════════════════════

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

    // Legacy aliases for compatibility
    // These delegate to the new canonical names

    /// Alias untuk `get_member()`.
    #[must_use]
    #[inline]
    pub fn find_member(&self, id: &CoordinatorId) -> Option<&CoordinatorMember> {
        self.get_member(id)
    }

    /// Alias untuk `is_member()`.
    #[must_use]
    #[inline]
    pub fn contains_member(&self, id: &CoordinatorId) -> bool {
        self.is_member(id)
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
    // MEMBERSHIP QUERY TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_is_member_existing() {
        let committee = make_valid_committee();
        let id = make_coordinator_id(0x01);
        assert!(committee.is_member(&id));
    }

    #[test]
    fn test_is_member_not_existing() {
        let committee = make_valid_committee();
        let id = make_coordinator_id(0xFF);
        assert!(!committee.is_member(&id));
    }

    #[test]
    fn test_get_member_existing() {
        let committee = make_valid_committee();
        let id = make_coordinator_id(0x01);

        let found = committee.get_member(&id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().id(), &id);
    }

    #[test]
    fn test_get_member_not_existing() {
        let committee = make_valid_committee();
        let id = make_coordinator_id(0xFF);

        let found = committee.get_member(&id);
        assert!(found.is_none());
    }

    #[test]
    fn test_get_member_by_index_valid() {
        let committee = make_valid_committee();

        let m0 = committee.get_member_by_index(0);
        assert!(m0.is_some());
        assert_eq!(m0.unwrap().id().as_bytes(), &[0x01; 32]);

        let m1 = committee.get_member_by_index(1);
        assert!(m1.is_some());
        assert_eq!(m1.unwrap().id().as_bytes(), &[0x02; 32]);
    }

    #[test]
    fn test_get_member_by_index_out_of_bounds() {
        let committee = make_valid_committee();
        assert!(committee.get_member_by_index(10).is_none());
    }

    #[test]
    fn test_member_ids_order_preserved() {
        let members = vec![
            make_member(0x03, 100),
            make_member(0x01, 200),
            make_member(0x02, 300),
        ];
        let committee =
            CoordinatorCommittee::new(members, 2, 1, 1700000000, 3600, make_group_pubkey())
                .unwrap();

        let ids = committee.member_ids();
        assert_eq!(ids.len(), 3);
        assert_eq!(ids[0].as_bytes(), &[0x03; 32]);
        assert_eq!(ids[1].as_bytes(), &[0x01; 32]);
        assert_eq!(ids[2].as_bytes(), &[0x02; 32]);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // EPOCH QUERY TESTS
    // ────────────────────────────────────────────────────────────────────────────

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

        assert_eq!(committee.epoch_end(), u64::MAX);
    }

    #[test]
    fn test_is_epoch_valid_in_range() {
        let committee = make_valid_committee();
        // epoch_start = 1700000000, epoch_end = 1700003600

        assert!(committee.is_epoch_valid(1700000000)); // Start
        assert!(committee.is_epoch_valid(1700001800)); // Middle
        assert!(committee.is_epoch_valid(1700003599)); // Just before end
    }

    #[test]
    fn test_is_epoch_valid_out_of_range() {
        let committee = make_valid_committee();

        assert!(!committee.is_epoch_valid(1699999999)); // Before start
        assert!(!committee.is_epoch_valid(1700003600)); // At end (exclusive)
        assert!(!committee.is_epoch_valid(1700003601)); // After end
    }

    #[test]
    fn test_epoch_remaining_secs() {
        let committee = make_valid_committee();
        // epoch_start = 1700000000, duration = 3600, epoch_end = 1700003600

        assert_eq!(committee.epoch_remaining_secs(1700000000), 3600);
        assert_eq!(committee.epoch_remaining_secs(1700001800), 1800);
        assert_eq!(committee.epoch_remaining_secs(1700003600), 0);
        assert_eq!(committee.epoch_remaining_secs(1700010000), 0);
    }

    #[test]
    fn test_epoch_elapsed_secs() {
        let committee = make_valid_committee();

        assert_eq!(committee.epoch_elapsed_secs(1699999999), 0); // Before start
        assert_eq!(committee.epoch_elapsed_secs(1700000000), 0); // At start
        assert_eq!(committee.epoch_elapsed_secs(1700001800), 1800); // Middle
        assert_eq!(committee.epoch_elapsed_secs(1700003600), 3600); // At end
        assert_eq!(committee.epoch_elapsed_secs(1700010000), 3600); // After end
    }

    #[test]
    fn test_epoch_progress() {
        let committee = make_valid_committee();

        assert_eq!(committee.epoch_progress(1699999999), 0.0); // Before start
        assert_eq!(committee.epoch_progress(1700000000), 0.0); // At start
        assert!((committee.epoch_progress(1700001800) - 0.5).abs() < 0.001); // Middle
        assert_eq!(committee.epoch_progress(1700003600), 1.0); // At end
        assert_eq!(committee.epoch_progress(1700010000), 1.0); // After end
    }

    #[test]
    fn test_epoch_progress_zero_duration() {
        let committee = CoordinatorCommittee::empty(1);
        // epoch_duration_secs = 0

        assert_eq!(committee.epoch_progress(0), 0.0);
        assert_eq!(committee.epoch_progress(1000), 0.0);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // THRESHOLD & SIGNING TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_requires_signatures_equals_threshold() {
        let committee = make_valid_committee();
        assert_eq!(committee.requires_signatures(), committee.threshold());
    }

    #[test]
    fn test_can_sign_with_sufficient_signers() {
        let committee = make_valid_committee();
        let signers = vec![make_coordinator_id(0x01), make_coordinator_id(0x02)];

        assert!(committee.can_sign_with(&signers));
    }

    #[test]
    fn test_can_sign_with_insufficient_signers() {
        let committee = make_valid_committee();
        let signers = vec![make_coordinator_id(0x01)]; // Only 1, need 2

        assert!(!committee.can_sign_with(&signers));
    }

    #[test]
    fn test_can_sign_with_non_member() {
        let committee = make_valid_committee();
        let signers = vec![
            make_coordinator_id(0x01),
            make_coordinator_id(0xFF), // Not a member
        ];

        assert!(!committee.can_sign_with(&signers));
    }

    #[test]
    fn test_can_sign_with_duplicates_not_counted() {
        let committee = make_valid_committee();
        let signers = vec![
            make_coordinator_id(0x01),
            make_coordinator_id(0x01), // Duplicate
        ];

        // Only 1 unique signer, need 2
        assert!(!committee.can_sign_with(&signers));
    }

    #[test]
    fn test_can_sign_with_empty_signers() {
        let committee = make_valid_committee();
        assert!(!committee.can_sign_with(&[]));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // STAKE QUERY TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_total_stake() {
        let committee = make_valid_committee();
        // Members: 0x01 with 1000, 0x02 with 2000
        assert_eq!(committee.total_stake(), 3000);
    }

    #[test]
    fn test_total_stake_overflow_protection() {
        let members = vec![
            make_member(0x01, u64::MAX),
            make_member(0x02, 1000),
        ];
        let committee =
            CoordinatorCommittee::new(members, 2, 1, 1700000000, 3600, make_group_pubkey())
                .unwrap();

        assert_eq!(committee.total_stake(), u64::MAX);
    }

    #[test]
    fn test_member_stake_existing() {
        let committee = make_valid_committee();
        let id = make_coordinator_id(0x01);

        assert_eq!(committee.member_stake(&id), Some(1000));
    }

    #[test]
    fn test_member_stake_not_existing() {
        let committee = make_valid_committee();
        let id = make_coordinator_id(0xFF);

        assert_eq!(committee.member_stake(&id), None);
    }

    #[test]
    fn test_stake_weight() {
        let committee = make_valid_committee();
        // Total stake = 3000

        let id1 = make_coordinator_id(0x01);
        let weight1 = committee.stake_weight(&id1).unwrap();
        assert!((weight1 - (1000.0 / 3000.0)).abs() < 0.001);

        let id2 = make_coordinator_id(0x02);
        let weight2 = committee.stake_weight(&id2).unwrap();
        assert!((weight2 - (2000.0 / 3000.0)).abs() < 0.001);
    }

    #[test]
    fn test_stake_weight_non_member() {
        let committee = make_valid_committee();
        let id = make_coordinator_id(0xFF);

        assert!(committee.stake_weight(&id).is_none());
    }

    #[test]
    fn test_stake_weight_zero_total_stake() {
        let committee = CoordinatorCommittee::empty(1);
        let id = make_coordinator_id(0x01);

        assert!(committee.stake_weight(&id).is_none());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // COMMITTEE HASH TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_committee_hash_deterministic() {
        let committee = make_valid_committee();

        let hash1 = committee.committee_hash();
        let hash2 = committee.committee_hash();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_committee_hash_different_for_different_committees() {
        let committee1 = make_valid_committee();

        let members2 = vec![make_member(0x01, 1000), make_member(0x03, 2000)];
        let committee2 =
            CoordinatorCommittee::new(members2, 2, 1, 1700000000, 3600, make_group_pubkey())
                .unwrap();

        assert_ne!(committee1.committee_hash(), committee2.committee_hash());
    }

    #[test]
    fn test_committee_hash_different_for_different_epochs() {
        let members1 = vec![make_member(0x01, 1000), make_member(0x02, 2000)];
        let committee1 =
            CoordinatorCommittee::new(members1, 2, 1, 1700000000, 3600, make_group_pubkey())
                .unwrap();

        let members2 = vec![make_member(0x01, 1000), make_member(0x02, 2000)];
        let committee2 =
            CoordinatorCommittee::new(members2, 2, 2, 1700000000, 3600, make_group_pubkey())
                .unwrap();

        assert_ne!(committee1.committee_hash(), committee2.committee_hash());
    }

    #[test]
    fn test_committee_hash_different_for_different_stakes() {
        let members1 = vec![make_member(0x01, 1000), make_member(0x02, 2000)];
        let committee1 =
            CoordinatorCommittee::new(members1, 2, 1, 1700000000, 3600, make_group_pubkey())
                .unwrap();

        let members2 = vec![make_member(0x01, 1000), make_member(0x02, 3000)]; // Different stake
        let committee2 =
            CoordinatorCommittee::new(members2, 2, 1, 1700000000, 3600, make_group_pubkey())
                .unwrap();

        assert_ne!(committee1.committee_hash(), committee2.committee_hash());
    }

    #[test]
    fn test_committee_hash_order_matters() {
        let members1 = vec![make_member(0x01, 1000), make_member(0x02, 2000)];
        let committee1 =
            CoordinatorCommittee::new(members1, 2, 1, 1700000000, 3600, make_group_pubkey())
                .unwrap();

        let members2 = vec![make_member(0x02, 2000), make_member(0x01, 1000)]; // Reversed
        let committee2 =
            CoordinatorCommittee::new(members2, 2, 1, 1700000000, 3600, make_group_pubkey())
                .unwrap();

        // Different order = different hash
        assert_ne!(committee1.committee_hash(), committee2.committee_hash());
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
    // LEGACY ALIAS TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_find_member_alias() {
        let committee = make_valid_committee();
        let id = make_coordinator_id(0x01);

        assert_eq!(committee.find_member(&id), committee.get_member(&id));
    }

    #[test]
    fn test_contains_member_alias() {
        let committee = make_valid_committee();
        let id = make_coordinator_id(0x01);

        assert_eq!(committee.contains_member(&id), committee.is_member(&id));
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
    fn test_members_order_preserved() {
        let members = vec![
            make_member(0x03, 100),
            make_member(0x01, 300),
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