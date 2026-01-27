//! # Committee Status
//!
//! Module ini menyediakan `CommitteeStatus` enum untuk representasi status
//! lifecycle committee dalam sistem multi-coordinator DSDN.
//!
//! ## Variants
//!
//! | Variant | Deskripsi |
//! |---------|-----------|
//! | `Active` | Committee aktif dan dapat memproses receipts |
//! | `InHandoff` | Committee dalam proses handoff ke epoch berikutnya |
//! | `Expired` | Committee sudah kedaluwarsa |
//! | `Initializing` | Committee sedang dalam proses inisialisasi (DKG) |
//!
//! ## State Machine
//!
//! ```text
//! Initializing → Active → StartHandoff → InHandoff → CompleteHandoff → Active
//!                  ↓            ↓              ↓
//!               Expire      Expire         Expire
//!                  ↓            ↓              ↓
//!               Expired     Expired        Expired
//!
//! Any → Reset → Initializing
//! ```
//!
//! ## Receipt Acceptance
//!
//! Receipts dapat diterima HANYA jika status adalah:
//! - `Active`
//! - `InHandoff` (menggunakan current_committee)

use std::fmt;

use serde::{Deserialize, Serialize};

use super::{CoordinatorCommittee, CommitteeTransition, Timestamp};
use dsdn_tss::SessionId;

// ════════════════════════════════════════════════════════════════════════════════
// ERROR TYPE
// ════════════════════════════════════════════════════════════════════════════════

/// Error type untuk transisi status committee yang tidak valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusTransitionError {
    /// Transisi tidak valid dari status saat ini.
    InvalidTransition {
        /// Nama status saat ini.
        from: &'static str,
        /// Nama transisi yang dicoba.
        transition: &'static str,
    },
}

impl fmt::Display for StatusTransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StatusTransitionError::InvalidTransition { from, transition } => {
                write!(
                    f,
                    "invalid status transition: cannot apply '{}' from '{}'",
                    transition, from
                )
            }
        }
    }
}

impl std::error::Error for StatusTransitionError {}

// ════════════════════════════════════════════════════════════════════════════════
// COMMITTEE STATUS TRANSITION (STATE MACHINE)
// ════════════════════════════════════════════════════════════════════════════════

/// Transisi status committee dalam state machine.
///
/// Digunakan dengan `apply_transition` untuk mengubah status committee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitteeStatusTransition {
    /// Mengaktifkan committee (Initializing → Active).
    Activate {
        /// Committee yang diaktifkan.
        committee: CoordinatorCommittee,
        /// Timestamp aktivasi.
        since: Timestamp,
    },

    /// Memulai handoff ke committee baru (Active → InHandoff).
    StartHandoff {
        /// Committee tujuan.
        next_committee: CoordinatorCommittee,
        /// Transisi yang sedang berlangsung.
        transition: CommitteeTransition,
    },

    /// Menyelesaikan handoff (InHandoff → Active).
    CompleteHandoff {
        /// Timestamp selesai handoff.
        completed_at: Timestamp,
    },

    /// Mengexpire committee (Active/InHandoff → Expired).
    Expire {
        /// Timestamp kedaluwarsa.
        expired_at: Timestamp,
    },

    /// Reset ke initializing (Any → Initializing).
    Reset {
        /// Epoch yang diharapkan.
        expected_epoch: u64,
    },
}

impl CommitteeStatusTransition {
    /// Mengembalikan nama transisi.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            CommitteeStatusTransition::Activate { .. } => "activate",
            CommitteeStatusTransition::StartHandoff { .. } => "start_handoff",
            CommitteeStatusTransition::CompleteHandoff { .. } => "complete_handoff",
            CommitteeStatusTransition::Expire { .. } => "expire",
            CommitteeStatusTransition::Reset { .. } => "reset",
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// COMMITTEE STATUS
// ════════════════════════════════════════════════════════════════════════════════

/// Status lifecycle committee.
///
/// `CommitteeStatus` merepresentasikan status committee saat ini dalam
/// sistem multi-coordinator DSDN.
///
/// ## Immutability
///
/// Setiap variant berisi data immutable. Untuk mengubah status,
/// gunakan `apply_transition` yang menghasilkan status baru.
///
/// ## Contoh
///
/// ```rust,ignore
/// use dsdn_common::{CommitteeStatus, CoordinatorCommittee};
///
/// // Create active status
/// let status = CommitteeStatus::active(committee, 1700000000);
///
/// // Check if can accept receipts
/// if status.can_accept_receipts() {
///     // Process receipt
/// }
///
/// // Get valid committee for timestamp
/// if let Some(committee) = status.valid_committee_for(1700001000) {
///     // Use committee for verification
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommitteeStatus {
    /// Committee aktif dan dapat memproses receipts.
    Active {
        /// Committee yang aktif.
        committee: CoordinatorCommittee,
        /// Timestamp sejak kapan committee aktif.
        since: Timestamp,
    },

    /// Committee dalam proses handoff ke epoch berikutnya.
    InHandoff {
        /// Committee saat ini (masih valid untuk receipts).
        current_committee: CoordinatorCommittee,
        /// Committee tujuan.
        next_committee: CoordinatorCommittee,
        /// Detail transisi.
        transition: CommitteeTransition,
    },

    /// Committee sudah kedaluwarsa.
    Expired {
        /// Committee terakhir sebelum expire.
        last_committee: CoordinatorCommittee,
        /// Timestamp kedaluwarsa.
        expired_at: Timestamp,
    },

    /// Committee sedang dalam proses inisialisasi (DKG).
    Initializing {
        /// Epoch yang diharapkan.
        expected_epoch: u64,
        /// Session ID DKG (jika ada).
        dkg_session_id: Option<SessionId>,
    },
}

impl CommitteeStatus {
    // ════════════════════════════════════════════════════════════════════════════
    // CONSTRUCTORS
    // ════════════════════════════════════════════════════════════════════════════

    /// Membuat status Active.
    ///
    /// # Arguments
    ///
    /// * `committee` - Committee yang aktif
    /// * `since` - Timestamp sejak kapan aktif
    #[must_use]
    pub fn active(committee: CoordinatorCommittee, since: Timestamp) -> Self {
        CommitteeStatus::Active { committee, since }
    }

    /// Membuat status InHandoff dari transition.
    ///
    /// # Arguments
    ///
    /// * `transition` - CommitteeTransition yang sedang berlangsung
    #[must_use]
    pub fn in_handoff(transition: CommitteeTransition) -> Self {
        CommitteeStatus::InHandoff {
            current_committee: transition.old_committee().clone(),
            next_committee: transition.new_committee().clone(),
            transition,
        }
    }

    /// Membuat status Expired.
    ///
    /// # Arguments
    ///
    /// * `committee` - Committee terakhir sebelum expire
    /// * `expired_at` - Timestamp kedaluwarsa
    #[must_use]
    pub fn expired(committee: CoordinatorCommittee, expired_at: Timestamp) -> Self {
        CommitteeStatus::Expired {
            last_committee: committee,
            expired_at,
        }
    }

    /// Membuat status Initializing.
    ///
    /// # Arguments
    ///
    /// * `expected_epoch` - Epoch yang diharapkan
    #[must_use]
    pub fn initializing(expected_epoch: u64) -> Self {
        CommitteeStatus::Initializing {
            expected_epoch,
            dkg_session_id: None,
        }
    }

    /// Membuat status Initializing dengan DKG session ID.
    ///
    /// # Arguments
    ///
    /// * `expected_epoch` - Epoch yang diharapkan
    /// * `dkg_session_id` - Session ID DKG
    #[must_use]
    pub fn initializing_with_session(expected_epoch: u64, dkg_session_id: SessionId) -> Self {
        CommitteeStatus::Initializing {
            expected_epoch,
            dkg_session_id: Some(dkg_session_id),
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // STATUS CHECKS
    // ════════════════════════════════════════════════════════════════════════════

    /// Mengecek apakah status Active.
    #[must_use]
    #[inline]
    pub const fn is_active(&self) -> bool {
        matches!(self, CommitteeStatus::Active { .. })
    }

    /// Mengecek apakah status InHandoff.
    #[must_use]
    #[inline]
    pub const fn is_in_handoff(&self) -> bool {
        matches!(self, CommitteeStatus::InHandoff { .. })
    }

    /// Mengecek apakah status Expired.
    #[must_use]
    #[inline]
    pub const fn is_expired(&self) -> bool {
        matches!(self, CommitteeStatus::Expired { .. })
    }

    /// Mengecek apakah status Initializing.
    #[must_use]
    #[inline]
    pub const fn is_initializing(&self) -> bool {
        matches!(self, CommitteeStatus::Initializing { .. })
    }

    // ════════════════════════════════════════════════════════════════════════════
    // COMMITTEE ACCESS
    // ════════════════════════════════════════════════════════════════════════════

    /// Mengembalikan reference ke committee saat ini.
    ///
    /// # Returns
    ///
    /// - `Some(&committee)` jika Active atau InHandoff (current_committee)
    /// - `None` jika Expired atau Initializing
    #[must_use]
    pub fn current_committee(&self) -> Option<&CoordinatorCommittee> {
        match self {
            CommitteeStatus::Active { committee, .. } => Some(committee),
            CommitteeStatus::InHandoff {
                current_committee, ..
            } => Some(current_committee),
            CommitteeStatus::Expired { .. } => None,
            CommitteeStatus::Initializing { .. } => None,
        }
    }

    /// Mengembalikan reference ke committee berikutnya.
    ///
    /// # Returns
    ///
    /// - `Some(&next_committee)` jika InHandoff
    /// - `None` untuk status lainnya
    #[must_use]
    pub fn next_committee(&self) -> Option<&CoordinatorCommittee> {
        match self {
            CommitteeStatus::InHandoff { next_committee, .. } => Some(next_committee),
            _ => None,
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // RECEIPT LOGIC
    // ════════════════════════════════════════════════════════════════════════════

    /// Mengecek apakah dapat menerima receipts.
    ///
    /// # Returns
    ///
    /// - `true` jika Active atau InHandoff
    /// - `false` jika Expired atau Initializing
    #[must_use]
    #[inline]
    pub const fn can_accept_receipts(&self) -> bool {
        matches!(
            self,
            CommitteeStatus::Active { .. } | CommitteeStatus::InHandoff { .. }
        )
    }

    // ════════════════════════════════════════════════════════════════════════════
    // TIME-BASED RESOLUTION
    // ════════════════════════════════════════════════════════════════════════════

    /// Mengembalikan committee yang valid untuk timestamp tertentu.
    ///
    /// # Arguments
    ///
    /// * `timestamp` - Timestamp untuk resolusi
    ///
    /// # Returns
    ///
    /// - Active: `committee` jika timestamp >= since
    /// - InHandoff:
    ///   - `current_committee` jika transition.is_in_handoff(timestamp)
    ///   - `next_committee` jika timestamp > transition.handoff_end()
    /// - Expired: `None`
    /// - Initializing: `None`
    ///
    /// # Note
    ///
    /// Tidak ada ambiguitas. Hasil deterministik untuk setiap input.
    #[must_use]
    pub fn valid_committee_for(&self, timestamp: Timestamp) -> Option<&CoordinatorCommittee> {
        match self {
            CommitteeStatus::Active { committee, since } => {
                if timestamp >= *since {
                    Some(committee)
                } else {
                    None
                }
            }
            CommitteeStatus::InHandoff {
                current_committee,
                next_committee,
                transition,
            } => {
                // During handoff period: use current_committee
                if transition.is_in_handoff(timestamp) {
                    Some(current_committee)
                // After handoff period: use next_committee
                } else if timestamp > transition.handoff_end() {
                    Some(next_committee)
                // Before handoff period: use current_committee
                } else {
                    Some(current_committee)
                }
            }
            CommitteeStatus::Expired { .. } => None,
            CommitteeStatus::Initializing { .. } => None,
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // STATUS NAME
    // ════════════════════════════════════════════════════════════════════════════

    /// Mengembalikan nama status sebagai string.
    ///
    /// # Returns
    ///
    /// - `"active"` untuk Active
    /// - `"in_handoff"` untuk InHandoff
    /// - `"expired"` untuk Expired
    /// - `"initializing"` untuk Initializing
    #[must_use]
    pub const fn status_name(&self) -> &'static str {
        match self {
            CommitteeStatus::Active { .. } => "active",
            CommitteeStatus::InHandoff { .. } => "in_handoff",
            CommitteeStatus::Expired { .. } => "expired",
            CommitteeStatus::Initializing { .. } => "initializing",
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // STATE MACHINE
    // ════════════════════════════════════════════════════════════════════════════

    /// Menerapkan transisi status.
    ///
    /// # Arguments
    ///
    /// * `transition` - Transisi yang akan diterapkan
    ///
    /// # Returns
    ///
    /// `Ok(CommitteeStatus)` jika transisi valid, `Err(StatusTransitionError)` jika tidak.
    ///
    /// # Valid Transitions
    ///
    /// - Initializing → Activate → Active
    /// - Active → StartHandoff → InHandoff
    /// - InHandoff → CompleteHandoff → Active
    /// - Active → Expire → Expired
    /// - InHandoff → Expire → Expired
    /// - Any → Reset → Initializing
    pub fn apply_transition(
        self,
        transition: CommitteeStatusTransition,
    ) -> Result<CommitteeStatus, StatusTransitionError> {
        match (&self, &transition) {
            // Initializing → Activate → Active
            (
                CommitteeStatus::Initializing { .. },
                CommitteeStatusTransition::Activate { committee, since },
            ) => Ok(CommitteeStatus::Active {
                committee: committee.clone(),
                since: *since,
            }),

            // Active → StartHandoff → InHandoff
            (
                CommitteeStatus::Active { .. },
                CommitteeStatusTransition::StartHandoff {
                    next_committee,
                    transition: trans,
                },
            ) => Ok(CommitteeStatus::InHandoff {
                current_committee: trans.old_committee().clone(),
                next_committee: next_committee.clone(),
                transition: trans.clone(),
            }),

            // InHandoff → CompleteHandoff → Active
            (
                CommitteeStatus::InHandoff { next_committee, .. },
                CommitteeStatusTransition::CompleteHandoff { completed_at },
            ) => Ok(CommitteeStatus::Active {
                committee: next_committee.clone(),
                since: *completed_at,
            }),

            // Active → Expire → Expired
            (
                CommitteeStatus::Active { committee, .. },
                CommitteeStatusTransition::Expire { expired_at },
            ) => Ok(CommitteeStatus::Expired {
                last_committee: committee.clone(),
                expired_at: *expired_at,
            }),

            // InHandoff → Expire → Expired
            (
                CommitteeStatus::InHandoff {
                    current_committee, ..
                },
                CommitteeStatusTransition::Expire { expired_at },
            ) => Ok(CommitteeStatus::Expired {
                last_committee: current_committee.clone(),
                expired_at: *expired_at,
            }),

            // Any → Reset → Initializing
            (_, CommitteeStatusTransition::Reset { expected_epoch }) => {
                Ok(CommitteeStatus::Initializing {
                    expected_epoch: *expected_epoch,
                    dkg_session_id: None,
                })
            }

            // Invalid transition
            _ => Err(StatusTransitionError::InvalidTransition {
                from: self.status_name(),
                transition: transition.name(),
            }),
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinator::{CoordinatorId, CoordinatorMember, ValidatorId};
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

    fn make_committee(epoch: u64) -> CoordinatorCommittee {
        let members = vec![make_member(0x01), make_member(0x02)];
        let group_pubkey = GroupPublicKey::from_bytes([0x01; 32]).expect("valid group pubkey");
        CoordinatorCommittee::new(members, 2, epoch, 1700000000, 3600, group_pubkey)
            .expect("valid committee")
    }

    fn make_transition() -> CommitteeTransition {
        let old_committee = make_committee(1);
        let new_committee = make_committee(2);
        let initiator = make_coordinator_id(0x01);
        CommitteeTransition::new(old_committee, new_committee, 1700000000, 3600, initiator)
            .expect("valid transition")
    }

    // ────────────────────────────────────────────────────────────────────────────
    // ERROR TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_status_transition_error_display() {
        let err = StatusTransitionError::InvalidTransition {
            from: "active",
            transition: "complete_handoff",
        };
        let msg = err.to_string();
        assert!(msg.contains("invalid status transition"));
        assert!(msg.contains("complete_handoff"));
        assert!(msg.contains("active"));
    }

    #[test]
    fn test_status_transition_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(StatusTransitionError::InvalidTransition {
            from: "active",
            transition: "complete_handoff",
        });
        assert!(err.to_string().contains("invalid"));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // CONSTRUCTOR TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_active_constructor() {
        let committee = make_committee(1);
        let status = CommitteeStatus::active(committee.clone(), 1700000000);

        assert!(status.is_active());
        assert!(!status.is_in_handoff());
        assert!(!status.is_expired());
        assert!(!status.is_initializing());
        assert_eq!(status.current_committee(), Some(&committee));
    }

    #[test]
    fn test_in_handoff_constructor() {
        let transition = make_transition();
        let status = CommitteeStatus::in_handoff(transition.clone());

        assert!(!status.is_active());
        assert!(status.is_in_handoff());
        assert!(!status.is_expired());
        assert!(!status.is_initializing());
        assert_eq!(
            status.current_committee(),
            Some(transition.old_committee())
        );
        assert_eq!(status.next_committee(), Some(transition.new_committee()));
    }

    #[test]
    fn test_expired_constructor() {
        let committee = make_committee(1);
        let status = CommitteeStatus::expired(committee.clone(), 1700003600);

        assert!(!status.is_active());
        assert!(!status.is_in_handoff());
        assert!(status.is_expired());
        assert!(!status.is_initializing());
        assert!(status.current_committee().is_none());
    }

    #[test]
    fn test_initializing_constructor() {
        let status = CommitteeStatus::initializing(1);

        assert!(!status.is_active());
        assert!(!status.is_in_handoff());
        assert!(!status.is_expired());
        assert!(status.is_initializing());
        assert!(status.current_committee().is_none());
    }

    #[test]
    fn test_initializing_with_session_constructor() {
        let session_id = SessionId::from_bytes([0xAA; 32]);
        let status = CommitteeStatus::initializing_with_session(1, session_id);

        assert!(status.is_initializing());
        if let CommitteeStatus::Initializing {
            expected_epoch,
            dkg_session_id,
        } = status
        {
            assert_eq!(expected_epoch, 1);
            assert!(dkg_session_id.is_some());
        } else {
            panic!("Expected Initializing variant");
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // STATUS NAME TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_status_name_active() {
        let status = CommitteeStatus::active(make_committee(1), 1700000000);
        assert_eq!(status.status_name(), "active");
    }

    #[test]
    fn test_status_name_in_handoff() {
        let status = CommitteeStatus::in_handoff(make_transition());
        assert_eq!(status.status_name(), "in_handoff");
    }

    #[test]
    fn test_status_name_expired() {
        let status = CommitteeStatus::expired(make_committee(1), 1700003600);
        assert_eq!(status.status_name(), "expired");
    }

    #[test]
    fn test_status_name_initializing() {
        let status = CommitteeStatus::initializing(1);
        assert_eq!(status.status_name(), "initializing");
    }

    // ────────────────────────────────────────────────────────────────────────────
    // CAN_ACCEPT_RECEIPTS TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_can_accept_receipts_active() {
        let status = CommitteeStatus::active(make_committee(1), 1700000000);
        assert!(status.can_accept_receipts());
    }

    #[test]
    fn test_can_accept_receipts_in_handoff() {
        let status = CommitteeStatus::in_handoff(make_transition());
        assert!(status.can_accept_receipts());
    }

    #[test]
    fn test_can_accept_receipts_expired() {
        let status = CommitteeStatus::expired(make_committee(1), 1700003600);
        assert!(!status.can_accept_receipts());
    }

    #[test]
    fn test_can_accept_receipts_initializing() {
        let status = CommitteeStatus::initializing(1);
        assert!(!status.can_accept_receipts());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // VALID_COMMITTEE_FOR TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_valid_committee_for_active_after_since() {
        let committee = make_committee(1);
        let status = CommitteeStatus::active(committee.clone(), 1700000000);

        // Timestamp after since
        assert_eq!(
            status.valid_committee_for(1700001000),
            Some(&committee)
        );
    }

    #[test]
    fn test_valid_committee_for_active_at_since() {
        let committee = make_committee(1);
        let status = CommitteeStatus::active(committee.clone(), 1700000000);

        // Timestamp equals since
        assert_eq!(
            status.valid_committee_for(1700000000),
            Some(&committee)
        );
    }

    #[test]
    fn test_valid_committee_for_active_before_since() {
        let committee = make_committee(1);
        let status = CommitteeStatus::active(committee, 1700000000);

        // Timestamp before since
        assert!(status.valid_committee_for(1699999999).is_none());
    }

    #[test]
    fn test_valid_committee_for_in_handoff_during() {
        let transition = make_transition();
        let status = CommitteeStatus::in_handoff(transition.clone());

        // During handoff (handoff_start=1700000000, handoff_end=1700003600)
        let result = status.valid_committee_for(1700001800);
        assert_eq!(result, Some(transition.old_committee()));
    }

    #[test]
    fn test_valid_committee_for_in_handoff_after() {
        let transition = make_transition();
        let status = CommitteeStatus::in_handoff(transition.clone());

        // After handoff_end
        let result = status.valid_committee_for(1700003601);
        assert_eq!(result, Some(transition.new_committee()));
    }

    #[test]
    fn test_valid_committee_for_in_handoff_before() {
        let transition = make_transition();
        let status = CommitteeStatus::in_handoff(transition.clone());

        // Before handoff_start (use current_committee)
        let result = status.valid_committee_for(1699999999);
        assert_eq!(result, Some(transition.old_committee()));
    }

    #[test]
    fn test_valid_committee_for_expired() {
        let status = CommitteeStatus::expired(make_committee(1), 1700003600);
        assert!(status.valid_committee_for(1700000000).is_none());
    }

    #[test]
    fn test_valid_committee_for_initializing() {
        let status = CommitteeStatus::initializing(1);
        assert!(status.valid_committee_for(1700000000).is_none());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // STATE MACHINE TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_transition_initializing_to_active() {
        let status = CommitteeStatus::initializing(1);
        let committee = make_committee(1);

        let result = status.apply_transition(CommitteeStatusTransition::Activate {
            committee: committee.clone(),
            since: 1700000000,
        });

        assert!(result.is_ok());
        let new_status = result.unwrap();
        assert!(new_status.is_active());
        assert_eq!(new_status.current_committee(), Some(&committee));
    }

    #[test]
    fn test_transition_active_to_start_handoff() {
        let committee = make_committee(1);
        let status = CommitteeStatus::active(committee, 1700000000);

        let transition = make_transition();
        let result = status.apply_transition(CommitteeStatusTransition::StartHandoff {
            next_committee: transition.new_committee().clone(),
            transition: transition.clone(),
        });

        assert!(result.is_ok());
        let new_status = result.unwrap();
        assert!(new_status.is_in_handoff());
    }

    #[test]
    fn test_transition_in_handoff_to_complete() {
        let transition = make_transition();
        let status = CommitteeStatus::in_handoff(transition.clone());

        let result = status.apply_transition(CommitteeStatusTransition::CompleteHandoff {
            completed_at: 1700003600,
        });

        assert!(result.is_ok());
        let new_status = result.unwrap();
        assert!(new_status.is_active());
        assert_eq!(
            new_status.current_committee(),
            Some(transition.new_committee())
        );
    }

    #[test]
    fn test_transition_active_to_expire() {
        let committee = make_committee(1);
        let status = CommitteeStatus::active(committee, 1700000000);

        let result = status.apply_transition(CommitteeStatusTransition::Expire {
            expired_at: 1700003600,
        });

        assert!(result.is_ok());
        let new_status = result.unwrap();
        assert!(new_status.is_expired());
    }

    #[test]
    fn test_transition_in_handoff_to_expire() {
        let transition = make_transition();
        let status = CommitteeStatus::in_handoff(transition);

        let result = status.apply_transition(CommitteeStatusTransition::Expire {
            expired_at: 1700003600,
        });

        assert!(result.is_ok());
        let new_status = result.unwrap();
        assert!(new_status.is_expired());
    }

    #[test]
    fn test_transition_any_to_reset() {
        // From Active
        let status1 = CommitteeStatus::active(make_committee(1), 1700000000);
        let result1 = status1.apply_transition(CommitteeStatusTransition::Reset {
            expected_epoch: 5,
        });
        assert!(result1.is_ok());
        assert!(result1.unwrap().is_initializing());

        // From InHandoff
        let status2 = CommitteeStatus::in_handoff(make_transition());
        let result2 = status2.apply_transition(CommitteeStatusTransition::Reset {
            expected_epoch: 5,
        });
        assert!(result2.is_ok());
        assert!(result2.unwrap().is_initializing());

        // From Expired
        let status3 = CommitteeStatus::expired(make_committee(1), 1700003600);
        let result3 = status3.apply_transition(CommitteeStatusTransition::Reset {
            expected_epoch: 5,
        });
        assert!(result3.is_ok());
        assert!(result3.unwrap().is_initializing());

        // From Initializing
        let status4 = CommitteeStatus::initializing(1);
        let result4 = status4.apply_transition(CommitteeStatusTransition::Reset {
            expected_epoch: 5,
        });
        assert!(result4.is_ok());
        assert!(result4.unwrap().is_initializing());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // INVALID TRANSITION TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_invalid_transition_active_to_complete_handoff() {
        let status = CommitteeStatus::active(make_committee(1), 1700000000);

        let result = status.apply_transition(CommitteeStatusTransition::CompleteHandoff {
            completed_at: 1700003600,
        });

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            StatusTransitionError::InvalidTransition { from: "active", .. }
        ));
    }

    #[test]
    fn test_invalid_transition_expired_to_activate() {
        let status = CommitteeStatus::expired(make_committee(1), 1700003600);

        let result = status.apply_transition(CommitteeStatusTransition::Activate {
            committee: make_committee(2),
            since: 1700004000,
        });

        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_transition_initializing_to_expire() {
        let status = CommitteeStatus::initializing(1);

        let result = status.apply_transition(CommitteeStatusTransition::Expire {
            expired_at: 1700003600,
        });

        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_transition_initializing_to_start_handoff() {
        let status = CommitteeStatus::initializing(1);

        let result = status.apply_transition(CommitteeStatusTransition::StartHandoff {
            next_committee: make_committee(2),
            transition: make_transition(),
        });

        assert!(result.is_err());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SERIALIZATION TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_serde_json_active() {
        let original = CommitteeStatus::active(make_committee(1), 1700000000);

        let serialized = serde_json::to_string(&original).expect("serialize");
        let deserialized: CommitteeStatus =
            serde_json::from_str(&serialized).expect("deserialize");

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_serde_json_in_handoff() {
        let original = CommitteeStatus::in_handoff(make_transition());

        let serialized = serde_json::to_string(&original).expect("serialize");
        let deserialized: CommitteeStatus =
            serde_json::from_str(&serialized).expect("deserialize");

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_serde_json_expired() {
        let original = CommitteeStatus::expired(make_committee(1), 1700003600);

        let serialized = serde_json::to_string(&original).expect("serialize");
        let deserialized: CommitteeStatus =
            serde_json::from_str(&serialized).expect("deserialize");

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_serde_json_initializing() {
        let original = CommitteeStatus::initializing(1);

        let serialized = serde_json::to_string(&original).expect("serialize");
        let deserialized: CommitteeStatus =
            serde_json::from_str(&serialized).expect("deserialize");

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_serde_bincode_roundtrip() {
        let original = CommitteeStatus::active(make_committee(1), 1700000000);

        let serialized = bincode::serialize(&original).expect("serialize");
        let deserialized: CommitteeStatus =
            bincode::deserialize(&serialized).expect("deserialize");

        assert_eq!(original, deserialized);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // CLONE & DEBUG TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_clone() {
        let original = CommitteeStatus::active(make_committee(1), 1700000000);
        let cloned = original.clone();

        assert_eq!(original, cloned);
    }

    #[test]
    fn test_debug() {
        let status = CommitteeStatus::active(make_committee(1), 1700000000);
        let debug = format!("{:?}", status);

        assert!(debug.contains("Active"));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SEND + SYNC TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<CommitteeStatus>();
        assert_send_sync::<CommitteeStatusTransition>();
        assert_send_sync::<StatusTransitionError>();
    }
}