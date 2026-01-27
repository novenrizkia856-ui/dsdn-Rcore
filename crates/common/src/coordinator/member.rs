//! # Coordinator Member
//!
//! Module ini menyediakan `CoordinatorMember` struct yang merepresentasikan
//! anggota committee dalam sistem multi-coordinator DSDN.
//!
//! ## Struktur
//!
//! | Field | Type | Deskripsi |
//! |-------|------|-----------|
//! | `id` | `CoordinatorId` | Identifier unik coordinator |
//! | `validator_id` | `ValidatorId` | Identifier validator terkait |
//! | `pubkey` | `ParticipantPublicKey` | Public key untuk TSS |
//! | `stake` | `u64` | Jumlah stake |
//! | `joined_at` | `Timestamp` | Waktu bergabung (Unix seconds) |
//!
//! ## Ordering
//!
//! `CoordinatorMember` diurutkan dengan aturan:
//! 1. Stake MENURUN (descending) - stake lebih tinggi = lebih prioritas
//! 2. Jika stake sama, urutkan berdasarkan `id` (ascending, deterministik)
//!
//! ## Validation
//!
//! Member dianggap valid jika:
//! - `stake > 0`
//! - `pubkey` format valid (bukan identity point / all-zero)

use std::cmp::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::{CoordinatorId, Timestamp, ValidatorId};
use dsdn_tss::ParticipantPublicKey;

// ════════════════════════════════════════════════════════════════════════════════
// COORDINATOR MEMBER
// ════════════════════════════════════════════════════════════════════════════════

/// Anggota committee dalam sistem multi-coordinator.
///
/// `CoordinatorMember` merepresentasikan satu coordinator dalam committee
/// yang berpartisipasi dalam threshold signing dan koordinasi.
///
/// ## Immutability
///
/// Setelah construction, semua fields bersifat immutable.
/// Untuk mengubah member, buat instance baru.
///
/// ## Ordering
///
/// Implements `Ord` dengan aturan:
/// 1. Stake descending (stake tinggi lebih prioritas)
/// 2. ID ascending (untuk determinism saat stake sama)
///
/// ## Contoh
///
/// ```rust,ignore
/// use dsdn_common::{CoordinatorMember, CoordinatorId, ValidatorId};
/// use dsdn_tss::ParticipantPublicKey;
///
/// let id = CoordinatorId::new([0x01; 32]);
/// let validator_id = ValidatorId::new([0x02; 32]);
/// let pubkey = ParticipantPublicKey::from_bytes([0x03; 32]).unwrap();
///
/// let member = CoordinatorMember::new(id, validator_id, pubkey, 1000);
/// assert!(member.is_valid());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinatorMember {
    /// Unique identifier untuk coordinator ini.
    id: CoordinatorId,

    /// Identifier validator terkait.
    validator_id: ValidatorId,

    /// Public key untuk threshold signing.
    pubkey: ParticipantPublicKey,

    /// Jumlah stake yang di-lock.
    stake: u64,

    /// Timestamp saat member bergabung (Unix seconds).
    joined_at: Timestamp,
}

impl CoordinatorMember {
    /// Membuat `CoordinatorMember` baru.
    ///
    /// `joined_at` akan di-set ke waktu saat construction.
    ///
    /// # Arguments
    ///
    /// * `id` - Coordinator identifier
    /// * `validator_id` - Validator identifier terkait
    /// * `pubkey` - Public key untuk TSS
    /// * `stake` - Jumlah stake
    ///
    /// # Returns
    ///
    /// `CoordinatorMember` baru dengan `joined_at` = waktu sekarang.
    ///
    /// # Note
    ///
    /// Constructor TIDAK melakukan validasi implisit.
    /// Gunakan `is_valid()` untuk validasi eksplisit.
    #[must_use]
    pub fn new(
        id: CoordinatorId,
        validator_id: ValidatorId,
        pubkey: ParticipantPublicKey,
        stake: u64,
    ) -> Self {
        let joined_at = current_timestamp();

        Self {
            id,
            validator_id,
            pubkey,
            stake,
            joined_at,
        }
    }

    /// Membuat `CoordinatorMember` dengan timestamp eksplisit.
    ///
    /// Berguna untuk deserialization atau testing.
    ///
    /// # Arguments
    ///
    /// * `id` - Coordinator identifier
    /// * `validator_id` - Validator identifier terkait
    /// * `pubkey` - Public key untuk TSS
    /// * `stake` - Jumlah stake
    /// * `joined_at` - Timestamp eksplisit
    #[must_use]
    pub fn with_timestamp(
        id: CoordinatorId,
        validator_id: ValidatorId,
        pubkey: ParticipantPublicKey,
        stake: u64,
        joined_at: Timestamp,
    ) -> Self {
        Self {
            id,
            validator_id,
            pubkey,
            stake,
            joined_at,
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // GETTERS
    // ────────────────────────────────────────────────────────────────────────────

    /// Mengembalikan reference ke coordinator ID.
    #[must_use]
    #[inline]
    pub const fn id(&self) -> &CoordinatorId {
        &self.id
    }

    /// Mengembalikan reference ke validator ID.
    #[must_use]
    #[inline]
    pub const fn validator_id(&self) -> &ValidatorId {
        &self.validator_id
    }

    /// Mengembalikan reference ke public key.
    #[must_use]
    #[inline]
    pub const fn pubkey(&self) -> &ParticipantPublicKey {
        &self.pubkey
    }

    /// Mengembalikan jumlah stake.
    #[must_use]
    #[inline]
    pub const fn stake(&self) -> u64 {
        self.stake
    }

    /// Mengembalikan timestamp saat member bergabung.
    #[must_use]
    #[inline]
    pub const fn joined_at(&self) -> Timestamp {
        self.joined_at
    }

    // ────────────────────────────────────────────────────────────────────────────
    // VALIDATION
    // ────────────────────────────────────────────────────────────────────────────

    /// Memvalidasi apakah member ini valid.
    ///
    /// # Rules
    ///
    /// 1. `stake > 0` - Member harus memiliki stake
    /// 2. `pubkey` format valid - Tidak boleh identity point (all zeros)
    ///
    /// # Returns
    ///
    /// `true` jika member valid, `false` jika tidak.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        // Rule 1: stake must be positive
        if self.stake == 0 {
            return false;
        }

        // Rule 2: pubkey must not be identity point (all zeros)
        // This is consistent with ParticipantPublicKey::from_bytes() validation
        if self.pubkey.as_bytes().iter().all(|&b| b == 0) {
            return false;
        }

        true
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// ORDERING
// ════════════════════════════════════════════════════════════════════════════════

impl PartialOrd for CoordinatorMember {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CoordinatorMember {
    /// Membandingkan dua `CoordinatorMember` untuk ordering.
    ///
    /// # Aturan Ordering
    ///
    /// 1. Stake DESCENDING (stake tinggi = lebih kecil dalam Ord = lebih prioritas)
    /// 2. Jika stake sama, ID ASCENDING (untuk determinism)
    ///
    /// # Contoh
    ///
    /// ```text
    /// stake=1000, id=0x01 < stake=500, id=0x01  (stake lebih tinggi = prioritas)
    /// stake=500, id=0x01 < stake=500, id=0x02   (stake sama, id lebih kecil = prioritas)
    /// ```
    fn cmp(&self, other: &Self) -> Ordering {
        // Primary: stake DESCENDING (reverse comparison)
        // Higher stake should come first, so we reverse the comparison
        match other.stake.cmp(&self.stake) {
            Ordering::Equal => {
                // Secondary: id ASCENDING (normal comparison on bytes)
                self.id.as_bytes().cmp(other.id.as_bytes())
            }
            ordering => ordering,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════════

/// Mendapatkan current timestamp sebagai Unix seconds.
///
/// Jika gagal mendapatkan waktu sistem (seharusnya tidak terjadi),
/// mengembalikan 0.
fn current_timestamp() -> Timestamp {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

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
        // Ensure non-zero for valid pubkey
        let b = if byte == 0 { 1 } else { byte };
        ParticipantPublicKey::from_bytes([b; 32]).expect("valid pubkey")
    }

    fn make_member(id_byte: u8, stake: u64) -> CoordinatorMember {
        CoordinatorMember::new(
            make_coordinator_id(id_byte),
            make_validator_id(id_byte),
            make_pubkey(id_byte),
            stake,
        )
    }

    // ────────────────────────────────────────────────────────────────────────────
    // CONSTRUCTOR TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_new_creates_member() {
        let id = make_coordinator_id(0x01);
        let validator_id = make_validator_id(0x02);
        let pubkey = make_pubkey(0x03);
        let stake = 1000u64;

        let member = CoordinatorMember::new(id, validator_id, pubkey.clone(), stake);

        assert_eq!(member.id().as_bytes(), &[0x01; 32]);
        assert_eq!(member.validator_id().as_bytes(), &[0x02; 32]);
        assert_eq!(member.pubkey().as_bytes(), pubkey.as_bytes());
        assert_eq!(member.stake(), 1000);
        // joined_at should be set to current time (non-zero in normal circumstances)
        // We just verify it's accessible
        let _ = member.joined_at();
    }

    #[test]
    fn test_with_timestamp_creates_member() {
        let id = make_coordinator_id(0x01);
        let validator_id = make_validator_id(0x02);
        let pubkey = make_pubkey(0x03);
        let stake = 1000u64;
        let joined_at = 1234567890u64;

        let member =
            CoordinatorMember::with_timestamp(id, validator_id, pubkey, stake, joined_at);

        assert_eq!(member.joined_at(), 1234567890);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // GETTER TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_getters_return_correct_values() {
        let member = make_member(0x42, 5000);

        assert_eq!(member.id().as_bytes(), &[0x42; 32]);
        assert_eq!(member.validator_id().as_bytes(), &[0x42; 32]);
        assert_eq!(member.pubkey().as_bytes(), &[0x42; 32]);
        assert_eq!(member.stake(), 5000);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // VALIDATION TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_is_valid_with_positive_stake() {
        let member = make_member(0x01, 1000);
        assert!(member.is_valid());
    }

    #[test]
    fn test_is_valid_with_zero_stake() {
        let member = make_member(0x01, 0);
        assert!(!member.is_valid());
    }

    #[test]
    fn test_is_valid_with_minimum_stake() {
        let member = make_member(0x01, 1);
        assert!(member.is_valid());
    }

    #[test]
    fn test_is_valid_with_max_stake() {
        let member = make_member(0x01, u64::MAX);
        assert!(member.is_valid());
    }

    // Note: Cannot test invalid pubkey directly because ParticipantPublicKey::from_bytes
    // already validates and rejects all-zero bytes

    // ────────────────────────────────────────────────────────────────────────────
    // ORDERING TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_ordering_by_stake_descending() {
        let member_high = make_member(0x01, 1000);
        let member_low = make_member(0x02, 500);

        // Higher stake should come first (be "less than" in sorting)
        assert!(member_high < member_low);
    }

    #[test]
    fn test_ordering_same_stake_by_id() {
        let member_a = make_member(0x01, 1000);
        let member_b = make_member(0x02, 1000);

        // Same stake, lower id comes first
        assert!(member_a < member_b);
    }

    #[test]
    fn test_ordering_deterministic() {
        let m1 = make_member(0x01, 1000);
        let m2 = make_member(0x01, 1000);

        // Same members should be equal
        assert_eq!(m1.cmp(&m2), Ordering::Equal);
    }

    #[test]
    fn test_ordering_in_btreeset() {
        let member_1000_01 = make_member(0x01, 1000);
        let member_1000_02 = make_member(0x02, 1000);
        let member_500_01 = make_member(0x03, 500);
        let member_2000_01 = make_member(0x04, 2000);

        let mut set = BTreeSet::new();
        set.insert(member_500_01.clone());
        set.insert(member_1000_01.clone());
        set.insert(member_2000_01.clone());
        set.insert(member_1000_02.clone());

        let ordered: Vec<_> = set.into_iter().collect();

        // Expected order: 2000 (first), 1000/0x01, 1000/0x02, 500
        assert_eq!(ordered[0].stake(), 2000);
        assert_eq!(ordered[1].stake(), 1000);
        assert_eq!(ordered[1].id().as_bytes(), &[0x01; 32]);
        assert_eq!(ordered[2].stake(), 1000);
        assert_eq!(ordered[2].id().as_bytes(), &[0x02; 32]);
        assert_eq!(ordered[3].stake(), 500);
    }

    #[test]
    fn test_ordering_consistency_with_eq() {
        let m1 = make_member(0x01, 1000);
        let m2 = make_member(0x01, 1000);
        let m3 = make_member(0x02, 1000);

        // Ord must be consistent with Eq
        assert_eq!(m1, m2);
        assert_eq!(m1.cmp(&m2), Ordering::Equal);

        assert_ne!(m1, m3);
        assert_ne!(m1.cmp(&m3), Ordering::Equal);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SERIALIZATION TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_serde_roundtrip() {
        let original = make_member(0x42, 5000);

        let serialized = serde_json::to_string(&original).expect("serialize");
        let deserialized: CoordinatorMember =
            serde_json::from_str(&serialized).expect("deserialize");

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_serde_bincode_roundtrip() {
        let original = make_member(0x42, 5000);

        let serialized = bincode::serialize(&original).expect("serialize");
        let deserialized: CoordinatorMember =
            bincode::deserialize(&serialized).expect("deserialize");

        assert_eq!(original, deserialized);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // CLONE TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_clone() {
        let original = make_member(0x01, 1000);
        let cloned = original.clone();

        assert_eq!(original, cloned);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // DEBUG TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_debug() {
        let member = make_member(0x01, 1000);
        let debug = format!("{:?}", member);

        assert!(debug.contains("CoordinatorMember"));
        assert!(debug.contains("stake"));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SEND + SYNC TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<CoordinatorMember>();
    }

    // ────────────────────────────────────────────────────────────────────────────
    // EDGE CASE TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_ordering_no_overflow() {
        // Test with max values to ensure no overflow
        let m1 = make_member(0x01, u64::MAX);
        let m2 = make_member(0x02, u64::MAX);

        // Should not panic and should be deterministic
        let _ = m1.cmp(&m2);
    }

    #[test]
    fn test_ordering_with_zero_stake() {
        let m0 = make_member(0x01, 0);
        let m1 = make_member(0x02, 1);

        // m1 (stake=1) should come before m0 (stake=0)
        assert!(m1 < m0);
    }
}