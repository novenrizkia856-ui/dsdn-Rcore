//! # Committee Transition
//!
//! Module ini menyediakan `CommitteeTransition` struct untuk epoch rotation
//! antara dua `CoordinatorCommittee`.
//!
//! ## Struktur
//!
//! | Field | Type | Deskripsi |
//! |-------|------|-----------|
//! | `from_epoch` | `u64` | Epoch asal |
//! | `to_epoch` | `u64` | Epoch tujuan |
//! | `old_committee` | `CoordinatorCommittee` | Committee epoch lama |
//! | `new_committee` | `CoordinatorCommittee` | Committee epoch baru |
//! | `handoff_start` | `Timestamp` | Waktu mulai handoff |
//! | `handoff_end` | `Timestamp` | Waktu selesai handoff |
//! | `initiated_by` | `CoordinatorId` | Coordinator yang memulai transisi |
//! | `transition_proof` | `Option<Vec<u8>>` | Bukti transisi opsional |
//!
//! ## Validasi
//!
//! - Epoch sequence: new = old + 1
//! - Handoff timing: handoff_start >= old_committee.epoch_start()
//! - Handoff duration: > 0
//!
//! ## Membership
//!
//! - `is_member_of_either`: member di salah satu committee
//! - `is_member_of_both`: member di kedua committee
//! - `overlapping_members`: member yang ada di kedua committee

use std::collections::HashSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::{CoordinatorCommittee, CoordinatorId, Timestamp};

// ════════════════════════════════════════════════════════════════════════════════
// ERROR TYPE
// ════════════════════════════════════════════════════════════════════════════════

/// Error type untuk pembuatan `CommitteeTransition`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionError {
    /// Epoch sequence tidak valid (new != old + 1).
    InvalidEpochSequence {
        /// Epoch dari old committee.
        old: u64,
        /// Epoch dari new committee.
        new: u64,
    },

    /// Handoff timing tidak valid (handoff_start < old epoch start).
    InvalidHandoffTiming,

    /// Handoff duration tidak valid (duration = 0).
    InvalidHandoffDuration,
}

impl fmt::Display for TransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransitionError::InvalidEpochSequence { old, new } => {
                write!(
                    f,
                    "invalid epoch sequence: expected new epoch = {}, got {}",
                    old.saturating_add(1),
                    new
                )
            }
            TransitionError::InvalidHandoffTiming => {
                write!(f, "invalid handoff timing: handoff_start must be >= old committee epoch_start")
            }
            TransitionError::InvalidHandoffDuration => {
                write!(f, "invalid handoff duration: must be > 0")
            }
        }
    }
}

impl std::error::Error for TransitionError {}

// ════════════════════════════════════════════════════════════════════════════════
// COMMITTEE TRANSITION
// ════════════════════════════════════════════════════════════════════════════════

/// Struktur untuk epoch rotation antara dua committee.
///
/// `CommitteeTransition` merepresentasikan transisi dari old committee
/// ke new committee dengan handoff period yang terdefinisi.
///
/// ## Immutability
///
/// Setelah construction, semua fields bersifat immutable.
/// Untuk mengubah transisi, buat instance baru.
///
/// ## Contoh
///
/// ```rust,ignore
/// use dsdn_common::{CommitteeTransition, CoordinatorCommittee, CoordinatorId};
///
/// let transition = CommitteeTransition::new(
///     old_committee,
///     new_committee,
///     1700000000,      // handoff_start
///     3600,            // handoff_duration_secs
///     initiator_id,
/// )?;
///
/// // Check handoff status
/// let now = 1700001800; // 30 minutes into handoff
/// assert!(transition.is_in_handoff(now));
/// assert_eq!(transition.handoff_progress(now), 0.5);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeTransition {
    /// Epoch asal (dari old_committee).
    from_epoch: u64,

    /// Epoch tujuan (dari new_committee).
    to_epoch: u64,

    /// Committee epoch lama.
    old_committee: CoordinatorCommittee,

    /// Committee epoch baru.
    new_committee: CoordinatorCommittee,

    /// Timestamp mulai handoff.
    handoff_start: Timestamp,

    /// Timestamp selesai handoff.
    handoff_end: Timestamp,

    /// Coordinator yang memulai transisi.
    initiated_by: CoordinatorId,

    /// Bukti transisi opsional.
    transition_proof: Option<Vec<u8>>,
}

impl CommitteeTransition {
    // ════════════════════════════════════════════════════════════════════════════
    // CONSTRUCTOR
    // ════════════════════════════════════════════════════════════════════════════

    /// Membuat `CommitteeTransition` baru dengan validasi.
    ///
    /// # Arguments
    ///
    /// * `old_committee` - Committee epoch lama
    /// * `new_committee` - Committee epoch baru
    /// * `handoff_start` - Timestamp mulai handoff
    /// * `handoff_duration_secs` - Durasi handoff dalam detik (> 0)
    /// * `initiated_by` - CoordinatorId yang memulai transisi
    ///
    /// # Errors
    ///
    /// - `InvalidEpochSequence` jika new_committee.epoch != old_committee.epoch + 1
    /// - `InvalidHandoffTiming` jika handoff_start < old_committee.epoch_start()
    /// - `InvalidHandoffDuration` jika handoff_duration_secs = 0
    ///
    /// # Note
    ///
    /// - `handoff_end` dihitung sebagai `handoff_start + handoff_duration_secs`
    /// - Menggunakan `checked_add` untuk menghindari overflow; jika overflow
    ///   terjadi, `handoff_end` di-set ke `u64::MAX` (saturating behavior)
    /// - `transition_proof` di-set ke `None`
    pub fn new(
        old_committee: CoordinatorCommittee,
        new_committee: CoordinatorCommittee,
        handoff_start: Timestamp,
        handoff_duration_secs: u64,
        initiated_by: CoordinatorId,
    ) -> Result<Self, TransitionError> {
        // Validation 1: new_committee.epoch == old_committee.epoch + 1
        let old_epoch = old_committee.epoch();
        let new_epoch = new_committee.epoch();
        let expected_new_epoch = old_epoch.saturating_add(1);

        if new_epoch != expected_new_epoch {
            return Err(TransitionError::InvalidEpochSequence {
                old: old_epoch,
                new: new_epoch,
            });
        }

        // Validation 2: handoff_start >= old_committee.epoch_start()
        if handoff_start < old_committee.epoch_start() {
            return Err(TransitionError::InvalidHandoffTiming);
        }

        // Validation 3: handoff_duration_secs > 0
        if handoff_duration_secs == 0 {
            return Err(TransitionError::InvalidHandoffDuration);
        }

        // Calculate handoff_end with overflow protection
        // Using checked_add; if overflow, use saturating behavior (u64::MAX)
        let handoff_end = handoff_start
            .checked_add(handoff_duration_secs)
            .unwrap_or(u64::MAX);

        Ok(Self {
            from_epoch: old_epoch,
            to_epoch: new_epoch,
            old_committee,
            new_committee,
            handoff_start,
            handoff_end,
            initiated_by,
            transition_proof: None,
        })
    }

    /// Membuat `CommitteeTransition` dengan transition proof.
    ///
    /// Sama dengan `new()` namun dengan transition proof yang diberikan.
    pub fn with_proof(
        old_committee: CoordinatorCommittee,
        new_committee: CoordinatorCommittee,
        handoff_start: Timestamp,
        handoff_duration_secs: u64,
        initiated_by: CoordinatorId,
        proof: Vec<u8>,
    ) -> Result<Self, TransitionError> {
        let mut transition = Self::new(
            old_committee,
            new_committee,
            handoff_start,
            handoff_duration_secs,
            initiated_by,
        )?;
        transition.transition_proof = Some(proof);
        Ok(transition)
    }

    // ════════════════════════════════════════════════════════════════════════════
    // QUERY METHODS
    // ════════════════════════════════════════════════════════════════════════════

    /// Mengembalikan from_epoch (epoch asal).
    #[must_use]
    #[inline]
    pub const fn from_epoch(&self) -> u64 {
        self.from_epoch
    }

    /// Mengembalikan to_epoch (epoch tujuan).
    #[must_use]
    #[inline]
    pub const fn to_epoch(&self) -> u64 {
        self.to_epoch
    }

    /// Mengembalikan reference ke old committee.
    #[must_use]
    #[inline]
    pub const fn old_committee(&self) -> &CoordinatorCommittee {
        &self.old_committee
    }

    /// Mengembalikan reference ke new committee.
    #[must_use]
    #[inline]
    pub const fn new_committee(&self) -> &CoordinatorCommittee {
        &self.new_committee
    }

    /// Mengembalikan handoff start timestamp.
    #[must_use]
    #[inline]
    pub const fn handoff_start(&self) -> Timestamp {
        self.handoff_start
    }

    /// Mengembalikan handoff end timestamp.
    #[must_use]
    #[inline]
    pub const fn handoff_end(&self) -> Timestamp {
        self.handoff_end
    }

    /// Menghitung handoff duration dalam detik.
    #[must_use]
    #[inline]
    pub fn handoff_duration_secs(&self) -> u64 {
        // Safe: handoff_end >= handoff_start by construction
        self.handoff_end.saturating_sub(self.handoff_start)
    }

    /// Mengembalikan reference ke initiator CoordinatorId.
    #[must_use]
    #[inline]
    pub const fn initiated_by(&self) -> &CoordinatorId {
        &self.initiated_by
    }

    /// Mengembalikan reference ke transition proof.
    #[must_use]
    #[inline]
    pub fn transition_proof(&self) -> Option<&[u8]> {
        self.transition_proof.as_deref()
    }

    // ════════════════════════════════════════════════════════════════════════════
    // HANDOFF STATUS
    // ════════════════════════════════════════════════════════════════════════════

    /// Mengecek apakah timestamp berada dalam handoff period.
    ///
    /// # Arguments
    ///
    /// * `now` - Timestamp yang dicek
    ///
    /// # Returns
    ///
    /// `true` jika `handoff_start <= now <= handoff_end` (inclusive).
    #[must_use]
    #[inline]
    pub fn is_in_handoff(&self, now: Timestamp) -> bool {
        now >= self.handoff_start && now <= self.handoff_end
    }

    /// Menghitung progress handoff sebagai nilai [0.0, 1.0].
    ///
    /// # Arguments
    ///
    /// * `now` - Timestamp saat ini
    ///
    /// # Returns
    ///
    /// - `0.0` jika `now <= handoff_start`
    /// - `1.0` jika `now >= handoff_end`
    /// - Linear interpolation di antara
    ///
    /// # Guarantees
    ///
    /// - TIDAK pernah return NaN
    /// - TIDAK pernah return Infinity
    /// - Hasil selalu dalam [0.0, 1.0]
    #[must_use]
    pub fn handoff_progress(&self, now: Timestamp) -> f64 {
        // Early exit: before handoff
        if now <= self.handoff_start {
            return 0.0;
        }

        // Early exit: after handoff
        if now >= self.handoff_end {
            return 1.0;
        }

        // Calculate duration
        let duration = self.handoff_end.saturating_sub(self.handoff_start);

        // Guard against division by zero (should not happen by construction)
        if duration == 0 {
            return 1.0;
        }

        // Calculate elapsed
        let elapsed = now.saturating_sub(self.handoff_start);

        // Linear interpolation with explicit clamping
        let progress = elapsed as f64 / duration as f64;

        // Explicit clamp to [0.0, 1.0] as safety measure
        if progress < 0.0 {
            0.0
        } else if progress > 1.0 {
            1.0
        } else if progress.is_nan() {
            0.0
        } else {
            progress
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // MEMBERSHIP QUERIES
    // ════════════════════════════════════════════════════════════════════════════

    /// Mengecek apakah CoordinatorId adalah member di salah satu committee.
    ///
    /// # Arguments
    ///
    /// * `id` - CoordinatorId yang dicek
    ///
    /// # Returns
    ///
    /// `true` jika id ∈ old_committee ATAU id ∈ new_committee.
    #[must_use]
    pub fn is_member_of_either(&self, id: &CoordinatorId) -> bool {
        self.old_committee.is_member(id) || self.new_committee.is_member(id)
    }

    /// Mengecek apakah CoordinatorId adalah member di kedua committee.
    ///
    /// # Arguments
    ///
    /// * `id` - CoordinatorId yang dicek
    ///
    /// # Returns
    ///
    /// `true` jika id ∈ old_committee DAN id ∈ new_committee.
    #[must_use]
    pub fn is_member_of_both(&self, id: &CoordinatorId) -> bool {
        self.old_committee.is_member(id) && self.new_committee.is_member(id)
    }

    /// Mengembalikan list CoordinatorId yang ada di kedua committee.
    ///
    /// # Returns
    ///
    /// Vec berisi CoordinatorId yang overlapping.
    ///
    /// # Guarantees
    ///
    /// - Deterministik
    /// - Tidak ada duplicate
    /// - Urutan konsisten (berdasarkan urutan di old_committee)
    #[must_use]
    pub fn overlapping_members(&self) -> Vec<CoordinatorId> {
        // Use HashSet for efficient lookup in new_committee
        let new_member_set: HashSet<CoordinatorId> = self
            .new_committee
            .member_ids()
            .into_iter()
            .collect();

        // Collect overlapping from old_committee (preserves order)
        self.old_committee
            .member_ids()
            .into_iter()
            .filter(|id| new_member_set.contains(id))
            .collect()
    }

    /// Mengembalikan list CoordinatorId yang hanya ada di old_committee.
    ///
    /// # Returns
    ///
    /// Vec berisi CoordinatorId yang keluar dari committee.
    #[must_use]
    pub fn leaving_members(&self) -> Vec<CoordinatorId> {
        self.old_committee
            .member_ids()
            .into_iter()
            .filter(|id| !self.new_committee.is_member(id))
            .collect()
    }

    /// Mengembalikan list CoordinatorId yang hanya ada di new_committee.
    ///
    /// # Returns
    ///
    /// Vec berisi CoordinatorId yang masuk ke committee.
    #[must_use]
    pub fn joining_members(&self) -> Vec<CoordinatorId> {
        self.new_committee
            .member_ids()
            .into_iter()
            .filter(|id| !self.old_committee.is_member(id))
            .collect()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinator::{CoordinatorMember, ValidatorId};
    use dsdn_tss::{GroupPublicKey, ParticipantPublicKey};

    // ────────────────────────────────────────────────────────────────────────────
    // HELPER FUNCTIONS
    // ────────────────────────────────────────────────────────────────────────────

    fn make_coordinator_id(byte: u8) -> CoordinatorId {
        CoordinatorId::new([byte; 32])
    }

    fn make_validator_id(byte: u8) -> ValidatorId {
        ValidatorId::new([byte; 32])
    }

    fn make_member(byte: u8) -> CoordinatorMember {
        let coord_id = make_coordinator_id(byte);
        let val_id = make_validator_id(byte);
        let pubkey = ParticipantPublicKey::from_bytes([byte; 32]).expect("valid pubkey");
        CoordinatorMember::with_timestamp(coord_id, val_id, pubkey, 1000, 1700000000)
    }

    fn make_committee(epoch: u64, member_bytes: &[u8]) -> CoordinatorCommittee {
        let members: Vec<CoordinatorMember> = member_bytes.iter().map(|&b| make_member(b)).collect();
        let group_pubkey = GroupPublicKey::from_bytes([0x01; 32]).expect("valid group pubkey");
        CoordinatorCommittee::new(
            members,
            2, // threshold
            epoch,
            1700000000, // epoch_start
            3600,       // epoch_duration_secs
            group_pubkey,
        )
        .expect("valid committee")
    }

    fn make_transition() -> CommitteeTransition {
        let old_committee = make_committee(1, &[0x01, 0x02, 0x03]);
        let new_committee = make_committee(2, &[0x02, 0x03, 0x04]);
        let initiator = make_coordinator_id(0x01);

        CommitteeTransition::new(
            old_committee,
            new_committee,
            1700000000, // handoff_start
            3600,       // handoff_duration_secs
            initiator,
        )
        .expect("valid transition")
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TRANSITION ERROR TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_error_invalid_epoch_sequence_display() {
        let err = TransitionError::InvalidEpochSequence { old: 5, new: 7 };
        let msg = err.to_string();
        assert!(msg.contains("epoch sequence"));
        assert!(msg.contains("6")); // expected
        assert!(msg.contains("7")); // got
    }

    #[test]
    fn test_error_invalid_handoff_timing_display() {
        let err = TransitionError::InvalidHandoffTiming;
        let msg = err.to_string();
        assert!(msg.contains("handoff timing"));
    }

    #[test]
    fn test_error_invalid_handoff_duration_display() {
        let err = TransitionError::InvalidHandoffDuration;
        let msg = err.to_string();
        assert!(msg.contains("handoff duration"));
    }

    #[test]
    fn test_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(TransitionError::InvalidHandoffDuration);
        assert!(err.to_string().contains("duration"));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // CONSTRUCTOR VALIDATION TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_new_valid_transition() {
        let transition = make_transition();

        assert_eq!(transition.from_epoch(), 1);
        assert_eq!(transition.to_epoch(), 2);
        assert_eq!(transition.handoff_start(), 1700000000);
        assert_eq!(transition.handoff_end(), 1700003600);
        assert_eq!(transition.handoff_duration_secs(), 3600);
    }

    #[test]
    fn test_new_invalid_epoch_sequence_not_consecutive() {
        let old_committee = make_committee(1, &[0x01, 0x02]);
        let new_committee = make_committee(3, &[0x01, 0x02]); // Should be 2
        let initiator = make_coordinator_id(0x01);

        let result = CommitteeTransition::new(
            old_committee,
            new_committee,
            1700000000,
            3600,
            initiator,
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TransitionError::InvalidEpochSequence { old: 1, new: 3 }
        ));
    }

    #[test]
    fn test_new_invalid_epoch_sequence_same_epoch() {
        let old_committee = make_committee(1, &[0x01, 0x02]);
        let new_committee = make_committee(1, &[0x01, 0x02]); // Same epoch
        let initiator = make_coordinator_id(0x01);

        let result = CommitteeTransition::new(
            old_committee,
            new_committee,
            1700000000,
            3600,
            initiator,
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TransitionError::InvalidEpochSequence { old: 1, new: 1 }
        ));
    }

    #[test]
    fn test_new_invalid_handoff_timing() {
        let old_committee = make_committee(1, &[0x01, 0x02]);
        let new_committee = make_committee(2, &[0x01, 0x02]);
        let initiator = make_coordinator_id(0x01);

        // handoff_start < old_committee.epoch_start()
        let result = CommitteeTransition::new(
            old_committee,
            new_committee,
            1699999999, // Before epoch_start (1700000000)
            3600,
            initiator,
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TransitionError::InvalidHandoffTiming
        ));
    }

    #[test]
    fn test_new_invalid_handoff_duration_zero() {
        let old_committee = make_committee(1, &[0x01, 0x02]);
        let new_committee = make_committee(2, &[0x01, 0x02]);
        let initiator = make_coordinator_id(0x01);

        let result = CommitteeTransition::new(
            old_committee,
            new_committee,
            1700000000,
            0, // Zero duration
            initiator,
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TransitionError::InvalidHandoffDuration
        ));
    }

    #[test]
    fn test_new_handoff_start_equals_epoch_start() {
        let old_committee = make_committee(1, &[0x01, 0x02]);
        let new_committee = make_committee(2, &[0x01, 0x02]);
        let initiator = make_coordinator_id(0x01);

        // handoff_start == old_committee.epoch_start() is valid
        let result = CommitteeTransition::new(
            old_committee,
            new_committee,
            1700000000, // Equal to epoch_start
            3600,
            initiator,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_new_with_proof() {
        let old_committee = make_committee(1, &[0x01, 0x02]);
        let new_committee = make_committee(2, &[0x01, 0x02]);
        let initiator = make_coordinator_id(0x01);
        let proof = vec![0xAA, 0xBB, 0xCC];

        let transition = CommitteeTransition::with_proof(
            old_committee,
            new_committee,
            1700000000,
            3600,
            initiator,
            proof.clone(),
        )
        .expect("valid transition");

        assert_eq!(transition.transition_proof(), Some(proof.as_slice()));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // QUERY METHOD TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_query_methods() {
        let transition = make_transition();

        assert_eq!(transition.from_epoch(), 1);
        assert_eq!(transition.to_epoch(), 2);
        assert_eq!(transition.old_committee().epoch(), 1);
        assert_eq!(transition.new_committee().epoch(), 2);
        assert_eq!(transition.handoff_start(), 1700000000);
        assert_eq!(transition.handoff_end(), 1700003600);
        assert_eq!(transition.handoff_duration_secs(), 3600);
        assert_eq!(transition.initiated_by(), &make_coordinator_id(0x01));
        assert!(transition.transition_proof().is_none());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // HANDOFF STATUS TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_is_in_handoff_before() {
        let transition = make_transition();

        // Before handoff_start
        assert!(!transition.is_in_handoff(1699999999));
    }

    #[test]
    fn test_is_in_handoff_at_start() {
        let transition = make_transition();

        // At handoff_start (inclusive)
        assert!(transition.is_in_handoff(1700000000));
    }

    #[test]
    fn test_is_in_handoff_during() {
        let transition = make_transition();

        // During handoff
        assert!(transition.is_in_handoff(1700001800)); // 30 min in
    }

    #[test]
    fn test_is_in_handoff_at_end() {
        let transition = make_transition();

        // At handoff_end (inclusive)
        assert!(transition.is_in_handoff(1700003600));
    }

    #[test]
    fn test_is_in_handoff_after() {
        let transition = make_transition();

        // After handoff_end
        assert!(!transition.is_in_handoff(1700003601));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // HANDOFF PROGRESS TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_handoff_progress_before_start() {
        let transition = make_transition();

        assert_eq!(transition.handoff_progress(1699999999), 0.0);
    }

    #[test]
    fn test_handoff_progress_at_start() {
        let transition = make_transition();

        assert_eq!(transition.handoff_progress(1700000000), 0.0);
    }

    #[test]
    fn test_handoff_progress_midway() {
        let transition = make_transition();

        // 1800 seconds into 3600 second handoff = 50%
        let progress = transition.handoff_progress(1700001800);
        assert!((progress - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_handoff_progress_at_end() {
        let transition = make_transition();

        assert_eq!(transition.handoff_progress(1700003600), 1.0);
    }

    #[test]
    fn test_handoff_progress_after_end() {
        let transition = make_transition();

        assert_eq!(transition.handoff_progress(1700003601), 1.0);
    }

    #[test]
    fn test_handoff_progress_not_nan() {
        let transition = make_transition();

        for ts in [0, 1, 1699999999, 1700000000, 1700001800, 1700003600, u64::MAX] {
            let progress = transition.handoff_progress(ts);
            assert!(!progress.is_nan());
            assert!(!progress.is_infinite());
            assert!((0.0..=1.0).contains(&progress));
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // MEMBERSHIP QUERY TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_is_member_of_either_in_old_only() {
        let transition = make_transition();
        // 0x01 is in old_committee only
        assert!(transition.is_member_of_either(&make_coordinator_id(0x01)));
    }

    #[test]
    fn test_is_member_of_either_in_new_only() {
        let transition = make_transition();
        // 0x04 is in new_committee only
        assert!(transition.is_member_of_either(&make_coordinator_id(0x04)));
    }

    #[test]
    fn test_is_member_of_either_in_both() {
        let transition = make_transition();
        // 0x02 is in both committees
        assert!(transition.is_member_of_either(&make_coordinator_id(0x02)));
    }

    #[test]
    fn test_is_member_of_either_in_neither() {
        let transition = make_transition();
        // 0xFF is in neither committee
        assert!(!transition.is_member_of_either(&make_coordinator_id(0xFF)));
    }

    #[test]
    fn test_is_member_of_both_true() {
        let transition = make_transition();
        // 0x02 and 0x03 are in both committees
        assert!(transition.is_member_of_both(&make_coordinator_id(0x02)));
        assert!(transition.is_member_of_both(&make_coordinator_id(0x03)));
    }

    #[test]
    fn test_is_member_of_both_false_old_only() {
        let transition = make_transition();
        // 0x01 is only in old_committee
        assert!(!transition.is_member_of_both(&make_coordinator_id(0x01)));
    }

    #[test]
    fn test_is_member_of_both_false_new_only() {
        let transition = make_transition();
        // 0x04 is only in new_committee
        assert!(!transition.is_member_of_both(&make_coordinator_id(0x04)));
    }

    #[test]
    fn test_overlapping_members() {
        let transition = make_transition();
        let overlapping = transition.overlapping_members();

        // Old: [0x01, 0x02, 0x03], New: [0x02, 0x03, 0x04]
        // Overlapping: [0x02, 0x03]
        assert_eq!(overlapping.len(), 2);
        assert!(overlapping.contains(&make_coordinator_id(0x02)));
        assert!(overlapping.contains(&make_coordinator_id(0x03)));
    }

    #[test]
    fn test_overlapping_members_no_overlap() {
        let old_committee = make_committee(1, &[0x01, 0x02]);
        let new_committee = make_committee(2, &[0x03, 0x04]);
        let initiator = make_coordinator_id(0x01);

        let transition = CommitteeTransition::new(
            old_committee,
            new_committee,
            1700000000,
            3600,
            initiator,
        )
        .expect("valid");

        assert!(transition.overlapping_members().is_empty());
    }

    #[test]
    fn test_overlapping_members_full_overlap() {
        let old_committee = make_committee(1, &[0x01, 0x02]);
        let new_committee = make_committee(2, &[0x01, 0x02]);
        let initiator = make_coordinator_id(0x01);

        let transition = CommitteeTransition::new(
            old_committee,
            new_committee,
            1700000000,
            3600,
            initiator,
        )
        .expect("valid");

        let overlapping = transition.overlapping_members();
        assert_eq!(overlapping.len(), 2);
    }

    #[test]
    fn test_leaving_members() {
        let transition = make_transition();
        let leaving = transition.leaving_members();

        // Old: [0x01, 0x02, 0x03], New: [0x02, 0x03, 0x04]
        // Leaving: [0x01]
        assert_eq!(leaving.len(), 1);
        assert!(leaving.contains(&make_coordinator_id(0x01)));
    }

    #[test]
    fn test_joining_members() {
        let transition = make_transition();
        let joining = transition.joining_members();

        // Old: [0x01, 0x02, 0x03], New: [0x02, 0x03, 0x04]
        // Joining: [0x04]
        assert_eq!(joining.len(), 1);
        assert!(joining.contains(&make_coordinator_id(0x04)));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SERIALIZATION TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_serde_json_roundtrip() {
        let original = make_transition();

        let serialized = serde_json::to_string(&original).expect("serialize");
        let deserialized: CommitteeTransition =
            serde_json::from_str(&serialized).expect("deserialize");

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_serde_bincode_roundtrip() {
        let original = make_transition();

        let serialized = bincode::serialize(&original).expect("serialize");
        let deserialized: CommitteeTransition =
            bincode::deserialize(&serialized).expect("deserialize");

        assert_eq!(original, deserialized);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // CLONE & DEBUG TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_clone() {
        let original = make_transition();
        let cloned = original.clone();

        assert_eq!(original, cloned);
    }

    #[test]
    fn test_debug() {
        let transition = make_transition();
        let debug = format!("{:?}", transition);

        assert!(debug.contains("CommitteeTransition"));
        assert!(debug.contains("from_epoch"));
        assert!(debug.contains("to_epoch"));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SEND + SYNC TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<CommitteeTransition>();
        assert_send_sync::<TransitionError>();
    }

    // ────────────────────────────────────────────────────────────────────────────
    // OVERFLOW TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_handoff_end_overflow_protection() {
        let old_committee = make_committee(1, &[0x01, 0x02]);
        let new_committee = make_committee(2, &[0x01, 0x02]);
        let initiator = make_coordinator_id(0x01);

        // Use very large values that would overflow
        let transition = CommitteeTransition::new(
            old_committee,
            new_committee,
            u64::MAX - 100, // Very large handoff_start
            u64::MAX,       // Very large duration (would overflow)
            initiator,
        )
        .expect("valid");

        // handoff_end should be u64::MAX (saturating)
        assert_eq!(transition.handoff_end(), u64::MAX);
    }
}