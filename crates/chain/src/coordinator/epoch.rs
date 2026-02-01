//! EpochManager base struct (14A.2B.2.22)
//!
//! Stateful component untuk tracking epoch dan committee rotation
//! di chain layer. Hanya state tracking dan queries — tidak ada
//! logic rotasi, persistence, atau side effects.

use dsdn_common::coordinator::CoordinatorCommittee;

use super::{CommitteeStatus, CommitteeTransition, EpochConfig};

// ════════════════════════════════════════════════════════════════════════════════
// ROTATION ERROR (14A.2B.2.23)
// ════════════════════════════════════════════════════════════════════════════════

/// Error type untuk epoch rotation operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotationError {
    /// Current height belum mencapai epoch boundary.
    NotAtBoundary,
    /// Committee rotation sudah dalam proses atau state tidak valid.
    AlreadyRotating,
    /// Committee selection gagal (termasuk invalid DA seed).
    SelectionFailed,
    /// Distributed key generation gagal.
    DKGFailed,
}

impl std::fmt::Display for RotationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAtBoundary => write!(f, "current height is not at epoch boundary"),
            Self::AlreadyRotating => write!(f, "committee rotation already in progress or invalid state"),
            Self::SelectionFailed => write!(f, "committee selection failed"),
            Self::DKGFailed => write!(f, "distributed key generation failed"),
        }
    }
}

impl std::error::Error for RotationError {}

// ════════════════════════════════════════════════════════════════════════════════
// HANDOFF ERROR (14A.2B.2.24)
// ════════════════════════════════════════════════════════════════════════════════

/// Error type untuk handoff period operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandoffError {
    /// Tidak sedang dalam proses handoff.
    NotInHandoff,
    /// Handoff period belum selesai.
    HandoffNotComplete,
    /// New committee belum tersedia.
    NewCommitteeNotReady,
}

impl std::fmt::Display for HandoffError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotInHandoff => write!(f, "not in handoff process"),
            Self::HandoffNotComplete => write!(f, "handoff period not yet complete"),
            Self::NewCommitteeNotReady => write!(f, "new committee not yet available"),
        }
    }
}

impl std::error::Error for HandoffError {}

// ════════════════════════════════════════════════════════════════════════════════
// EPOCH MANAGER
// ════════════════════════════════════════════════════════════════════════════════

/// Manager untuk tracking epoch dan committee rotation.
///
/// Menyimpan state epoch saat ini, referensi committee, dan konfigurasi.
/// Tidak mengandung logic rotasi — hanya state tracking dan queries.
///
/// ## Invariants
///
/// - `current_epoch` dan `epoch_start_height` konsisten
/// - `status` mencerminkan validitas config (Active jika valid, Inactive jika tidak)
/// - `next_committee` dan `pending_transition` dimulai sebagai `None`
#[derive(Debug)]
pub struct EpochManager {
    current_epoch: u64,
    current_committee: CoordinatorCommittee,
    next_committee: Option<CoordinatorCommittee>,
    epoch_start_height: u64,
    config: EpochConfig,
    status: CommitteeStatus,
    pending_transition: Option<CommitteeTransition>,
}

impl EpochManager {
    /// Membuat `EpochManager` baru dengan genesis committee.
    ///
    /// ## Config Validation
    ///
    /// Constructor memvalidasi:
    /// - `epoch_duration_blocks > 0`
    /// - `handoff_duration_blocks < epoch_duration_blocks`
    /// - `dkg_timeout_blocks <= handoff_duration_blocks`
    ///
    /// Jika config valid → `status = Active`.
    /// Jika config TIDAK valid → `status = Inactive`.
    ///
    /// ## Initial State
    ///
    /// - `current_epoch = 0`
    /// - `epoch_start_height = 0`
    /// - `next_committee = None`
    /// - `pending_transition = None`
    pub fn new(
        config: EpochConfig,
        genesis_committee: CoordinatorCommittee,
    ) -> Self {
        let config_valid = config.epoch_duration_blocks > 0
            && config.handoff_duration_blocks < config.epoch_duration_blocks
            && config.dkg_timeout_blocks <= config.handoff_duration_blocks;

        let status = if config_valid {
            CommitteeStatus::Active
        } else {
            CommitteeStatus::Inactive
        };

        Self {
            current_epoch: 0,
            current_committee: genesis_committee,
            next_committee: None,
            epoch_start_height: 0,
            config,
            status,
            pending_transition: None,
        }
    }

    /// Returns current epoch number.
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Returns reference to current committee.
    pub fn current_committee(&self) -> &CoordinatorCommittee {
        &self.current_committee
    }

    /// Returns current committee status.
    pub fn current_status(&self) -> CommitteeStatus {
        self.status.clone()
    }

    /// Menghitung epoch progress berdasarkan block height.
    ///
    /// ## Returns
    ///
    /// `(elapsed, remaining)` dimana:
    /// - `elapsed` = blocks sejak epoch start (saturating, tidak underflow)
    /// - `remaining` = blocks hingga epoch end (saturating, tidak negatif)
    ///
    /// ## Edge Cases
    ///
    /// - `current_height < epoch_start_height` → `(0, epoch_duration_blocks)`
    /// - `current_height` melewati epoch end → `(elapsed, 0)`
    pub fn epoch_progress(&self, current_height: u64) -> (u64, u64) {
        let elapsed = current_height.saturating_sub(self.epoch_start_height);
        let remaining = self.config.epoch_duration_blocks.saturating_sub(elapsed);
        (elapsed, remaining)
    }

    // ════════════════════════════════════════════════════════════════════════════
    // EPOCH ROTATION (14A.2B.2.23)
    // ════════════════════════════════════════════════════════════════════════════

    /// Cek apakah epoch rotation diperlukan pada height tertentu.
    ///
    /// Return `true` jika dan hanya jika:
    /// 1. `current_height >= epoch_start_height + epoch_duration_blocks`
    /// 2. `status == CommitteeStatus::Active`
    ///
    /// Tidak mengubah state. Tidak panic. Tidak wraparound.
    pub fn should_rotate(&self, current_height: u64) -> bool {
        if self.status != CommitteeStatus::Active {
            return false;
        }
        match self.epoch_start_height.checked_add(self.config.epoch_duration_blocks) {
            Some(boundary) => current_height >= boundary,
            None => false,
        }
    }

    /// Trigger epoch rotation.
    ///
    /// Membuat `CommitteeTransition` placeholder dan mengubah status
    /// dari `Active` ke `PendingRotation`.
    ///
    /// ## Errors
    ///
    /// - `AlreadyRotating` — status bukan `Active`
    /// - `NotAtBoundary` — `should_rotate` mengembalikan `false`
    /// - `SelectionFailed` — `da_seed` adalah default/dummy (all zeros)
    ///
    /// ## State Mutations
    ///
    /// - `status` → `PendingRotation`
    /// - `pending_transition` → `Some(transition)`
    /// - `current_committee` TIDAK berubah
    pub fn trigger_rotation(
        &mut self,
        current_height: u64,
        da_seed: [u8; 32],
    ) -> Result<CommitteeTransition, RotationError> {
        // Check 1: status must be Active
        if self.status != CommitteeStatus::Active {
            return Err(RotationError::AlreadyRotating);
        }

        // Check 2: must be at epoch boundary (calls should_rotate)
        if !self.should_rotate(current_height) {
            return Err(RotationError::NotAtBoundary);
        }

        // Check 3: da_seed must not be dummy/default
        if da_seed == [0u8; 32] {
            return Err(RotationError::SelectionFailed);
        }

        // Compute handoff window from config
        let handoff_start = current_height;
        let handoff_end = current_height.saturating_add(self.config.handoff_duration_blocks);

        // Build transition (new_committee = placeholder, belum diganti)
        let transition = CommitteeTransition {
            old_committee: self.current_committee.clone(),
            new_committee: self.current_committee.clone(),
            transition_height: current_height,
            handoff_start,
            handoff_end,
        };

        // Mutate state
        self.status = CommitteeStatus::PendingRotation;
        self.pending_transition = Some(transition.clone());

        Ok(transition)
    }

    /// Prepare next epoch dengan committee baru.
    ///
    /// Hanya boleh dipanggil saat `status == PendingRotation`.
    /// Men-set `next_committee` tanpa mengubah `current_committee`
    /// atau `current_epoch`.
    ///
    /// ## Errors
    ///
    /// - `AlreadyRotating` — status bukan `PendingRotation`
    pub fn prepare_next_epoch(
        &mut self,
        new_committee: CoordinatorCommittee,
    ) -> Result<(), RotationError> {
        if self.status != CommitteeStatus::PendingRotation {
            return Err(RotationError::AlreadyRotating);
        }
        self.next_committee = Some(new_committee);
        Ok(())
    }

    // ════════════════════════════════════════════════════════════════════════════
    // HANDOFF MANAGEMENT (14A.2B.2.24)
    // ════════════════════════════════════════════════════════════════════════════

    /// Compute handoff window boundaries.
    ///
    /// Returns `Some((handoff_start, handoff_end))` where:
    /// - `handoff_end = epoch_start_height + epoch_duration_blocks`
    /// - `handoff_start = handoff_end - handoff_duration_blocks`
    ///
    /// Returns `None` jika overflow terjadi.
    fn handoff_window(&self) -> Option<(u64, u64)> {
        let epoch_end = self.epoch_start_height.checked_add(self.config.epoch_duration_blocks)?;
        let handoff_start = epoch_end.checked_sub(self.config.handoff_duration_blocks)?;
        Some((handoff_start, epoch_end))
    }

    /// Cek apakah height berada dalam handoff period.
    ///
    /// Return `true` jika dan hanya jika:
    /// `current_height >= handoff_start` DAN `current_height < handoff_end`
    ///
    /// Tidak mengubah state. Tidak panic.
    pub fn is_in_handoff(&self, current_height: u64) -> bool {
        match self.handoff_window() {
            Some((start, end)) => current_height >= start && current_height < end,
            None => false,
        }
    }

    /// Return committee yang valid untuk signing pada height tertentu.
    ///
    /// - height < handoff_end → `&current_committee`
    /// - height >= handoff_end → `&next_committee` (fallback ke current jika belum ada)
    ///
    /// Tidak allocate. Tidak clone. Tidak panic.
    pub fn valid_committee_for_height(&self, height: u64) -> &CoordinatorCommittee {
        match self.handoff_window() {
            Some((_, end)) if height >= end => {
                match &self.next_committee {
                    Some(next) => next,
                    None => &self.current_committee,
                }
            }
            _ => &self.current_committee,
        }
    }

    /// Return semua committee yang valid untuk height tertentu.
    ///
    /// - height < handoff_start → `[&current_committee]`
    /// - height >= handoff_start DAN < handoff_end → `[&current_committee, &next_committee]`
    /// - height >= handoff_end → `[&next_committee]`
    ///
    /// Urutan: OLD dulu, NEW setelahnya.
    /// Jika next_committee belum tersedia saat dibutuhkan → fallback ke current saja.
    pub fn valid_committees_for_height(&self, height: u64) -> Vec<&CoordinatorCommittee> {
        match self.handoff_window() {
            Some((start, end)) => {
                if height < start {
                    vec![&self.current_committee]
                } else if height < end {
                    match &self.next_committee {
                        Some(next) => vec![&self.current_committee, next],
                        None => vec![&self.current_committee],
                    }
                } else {
                    match &self.next_committee {
                        Some(next) => vec![next],
                        None => vec![&self.current_committee],
                    }
                }
            }
            None => vec![&self.current_committee],
        }
    }

    /// Complete handoff: finalisasi transisi committee.
    ///
    /// ## Preconditions
    ///
    /// - `current_height >= handoff_end`
    /// - `next_committee` tersedia
    /// - Ada pending transition
    ///
    /// ## State Effects
    ///
    /// - `current_committee = next_committee`
    /// - `next_committee = None`
    /// - `pending_transition = None`
    /// - `epoch_start_height = handoff_end`
    /// - `status = Active`
    /// - `current_epoch += 1`
    pub fn complete_handoff(
        &mut self,
        current_height: u64,
    ) -> Result<(), HandoffError> {
        // Guard: must have pending transition
        if self.pending_transition.is_none() {
            return Err(HandoffError::NotInHandoff);
        }

        // Compute handoff_end
        let (_, handoff_end) = match self.handoff_window() {
            Some(w) => w,
            None => return Err(HandoffError::NotInHandoff),
        };

        // Must be past handoff_end
        if current_height < handoff_end {
            return Err(HandoffError::HandoffNotComplete);
        }

        // next_committee must be ready
        let new_committee = match self.next_committee.take() {
            Some(c) => c,
            None => return Err(HandoffError::NewCommitteeNotReady),
        };

        // Atomic state transition
        self.current_committee = new_committee;
        // next_committee already None from take()
        self.pending_transition = None;
        self.epoch_start_height = handoff_end;
        self.status = CommitteeStatus::Active;
        self.current_epoch = self.current_epoch.saturating_add(1);

        Ok(())
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: construct minimal CoordinatorCommittee via serde deserialization.
    ///
    /// Bypasses constructor validation (test-only).
    /// Chain crate tidak memiliki akses langsung ke dsdn-tss types
    /// (GroupPublicKey, ParticipantPublicKey), sehingga construction
    /// dilakukan via JSON deserialization.
    fn test_committee() -> CoordinatorCommittee {
        let id1: Vec<u8> = vec![1u8; 32];
        let id2: Vec<u8> = vec![4u8; 32];
        let id3: Vec<u8> = vec![7u8; 32];
        let vid1: Vec<u8> = vec![2u8; 32];
        let vid2: Vec<u8> = vec![5u8; 32];
        let vid3: Vec<u8> = vec![8u8; 32];
        let pk1: Vec<u8> = vec![3u8; 32];
        let pk2: Vec<u8> = vec![6u8; 32];
        let pk3: Vec<u8> = vec![9u8; 32];
        let gpk: Vec<u8> = vec![1u8; 32];

        let json = serde_json::json!({
            "members": [
                { "id": id1, "validator_id": vid1, "pubkey": pk1, "stake": 1000u64, "joined_at": 0u64 },
                { "id": id2, "validator_id": vid2, "pubkey": pk2, "stake": 1000u64, "joined_at": 0u64 },
                { "id": id3, "validator_id": vid3, "pubkey": pk3, "stake": 1000u64, "joined_at": 0u64 }
            ],
            "threshold": 2u8,
            "epoch": 0u64,
            "epoch_start": 0u64,
            "epoch_duration_secs": 3600u64,
            "group_pubkey": gpk
        });

        serde_json::from_value(json).expect("test committee construction")
    }

    fn valid_config() -> EpochConfig {
        EpochConfig {
            epoch_duration_blocks: 100,
            handoff_duration_blocks: 10,
            dkg_timeout_blocks: 5,
        }
    }

    fn test_da_seed() -> [u8; 32] {
        [0xABu8; 32]
    }

    // ──────────────────────────────────────────────────────────
    // Constructor tests
    // ──────────────────────────────────────────────────────────

    #[test]
    fn test_new_valid_config_status_active() {
        let em = EpochManager::new(valid_config(), test_committee());
        assert_eq!(em.current_status(), CommitteeStatus::Active);
    }

    #[test]
    fn test_new_valid_config_initial_state() {
        let em = EpochManager::new(valid_config(), test_committee());
        assert_eq!(em.current_epoch(), 0);
        assert_eq!(em.epoch_start_height, 0);
        assert!(em.next_committee.is_none());
        assert!(em.pending_transition.is_none());
    }

    #[test]
    fn test_new_zero_epoch_duration_inactive() {
        let config = EpochConfig {
            epoch_duration_blocks: 0,
            handoff_duration_blocks: 0,
            dkg_timeout_blocks: 0,
        };
        let em = EpochManager::new(config, test_committee());
        assert_eq!(em.current_status(), CommitteeStatus::Inactive);
    }

    #[test]
    fn test_new_handoff_ge_epoch_inactive() {
        let config = EpochConfig {
            epoch_duration_blocks: 10,
            handoff_duration_blocks: 10,
            dkg_timeout_blocks: 5,
        };
        let em = EpochManager::new(config, test_committee());
        assert_eq!(em.current_status(), CommitteeStatus::Inactive);
    }

    #[test]
    fn test_new_handoff_gt_epoch_inactive() {
        let config = EpochConfig {
            epoch_duration_blocks: 10,
            handoff_duration_blocks: 20,
            dkg_timeout_blocks: 5,
        };
        let em = EpochManager::new(config, test_committee());
        assert_eq!(em.current_status(), CommitteeStatus::Inactive);
    }

    #[test]
    fn test_new_dkg_gt_handoff_inactive() {
        let config = EpochConfig {
            epoch_duration_blocks: 100,
            handoff_duration_blocks: 10,
            dkg_timeout_blocks: 11,
        };
        let em = EpochManager::new(config, test_committee());
        assert_eq!(em.current_status(), CommitteeStatus::Inactive);
    }

    #[test]
    fn test_new_dkg_eq_handoff_valid() {
        let config = EpochConfig {
            epoch_duration_blocks: 100,
            handoff_duration_blocks: 10,
            dkg_timeout_blocks: 10,
        };
        let em = EpochManager::new(config, test_committee());
        assert_eq!(em.current_status(), CommitteeStatus::Active);
    }

    #[test]
    fn test_new_minimal_valid_config() {
        let config = EpochConfig {
            epoch_duration_blocks: 1,
            handoff_duration_blocks: 0,
            dkg_timeout_blocks: 0,
        };
        let em = EpochManager::new(config, test_committee());
        assert_eq!(em.current_status(), CommitteeStatus::Active);
    }

    // ──────────────────────────────────────────────────────────
    // Getter tests
    // ──────────────────────────────────────────────────────────

    #[test]
    fn test_current_epoch_getter() {
        let em = EpochManager::new(valid_config(), test_committee());
        assert_eq!(em.current_epoch(), 0);
    }

    #[test]
    fn test_current_committee_getter() {
        let committee = test_committee();
        let em = EpochManager::new(valid_config(), committee.clone());
        assert_eq!(*em.current_committee(), committee);
    }

    #[test]
    fn test_current_status_getter() {
        let em = EpochManager::new(valid_config(), test_committee());
        assert_eq!(em.current_status(), CommitteeStatus::Active);
    }

    // ──────────────────────────────────────────────────────────
    // Epoch progress tests
    // ──────────────────────────────────────────────────────────

    #[test]
    fn test_progress_at_start() {
        let em = EpochManager::new(valid_config(), test_committee());
        let (elapsed, remaining) = em.epoch_progress(0);
        assert_eq!(elapsed, 0);
        assert_eq!(remaining, 100);
    }

    #[test]
    fn test_progress_midway() {
        let em = EpochManager::new(valid_config(), test_committee());
        let (elapsed, remaining) = em.epoch_progress(50);
        assert_eq!(elapsed, 50);
        assert_eq!(remaining, 50);
    }

    #[test]
    fn test_progress_at_end() {
        let em = EpochManager::new(valid_config(), test_committee());
        let (elapsed, remaining) = em.epoch_progress(100);
        assert_eq!(elapsed, 100);
        assert_eq!(remaining, 0);
    }

    #[test]
    fn test_progress_past_end() {
        let em = EpochManager::new(valid_config(), test_committee());
        let (elapsed, remaining) = em.epoch_progress(150);
        assert_eq!(elapsed, 150);
        assert_eq!(remaining, 0);
    }

    #[test]
    fn test_progress_before_start() {
        // epoch_start_height = 0 dan current_height = 0 → elapsed = 0
        // Tidak ada kasus underflow karena epoch_start_height = 0
        let em = EpochManager::new(valid_config(), test_committee());
        let (elapsed, remaining) = em.epoch_progress(0);
        assert_eq!(elapsed, 0);
        assert_eq!(remaining, 100);
    }

    #[test]
    fn test_progress_u64_max_no_panic() {
        let em = EpochManager::new(valid_config(), test_committee());
        let (elapsed, remaining) = em.epoch_progress(u64::MAX);
        assert_eq!(elapsed, u64::MAX);
        assert_eq!(remaining, 0);
    }

    #[test]
    fn test_progress_invalid_config_zero_duration() {
        let config = EpochConfig {
            epoch_duration_blocks: 0,
            handoff_duration_blocks: 0,
            dkg_timeout_blocks: 0,
        };
        let em = EpochManager::new(config, test_committee());
        // epoch_duration_blocks = 0, so remaining always 0
        let (elapsed, remaining) = em.epoch_progress(50);
        assert_eq!(elapsed, 50);
        assert_eq!(remaining, 0);
    }

    // ──────────────────────────────────────────────────────────
    // Debug derive test
    // ──────────────────────────────────────────────────────────

    #[test]
    fn test_debug_impl() {
        let em = EpochManager::new(valid_config(), test_committee());
        let debug = format!("{:?}", em);
        assert!(debug.contains("EpochManager"));
    }

    // ──────────────────────────────────────────────────────────
    // should_rotate tests (14A.2B.2.23)
    // ──────────────────────────────────────────────────────────

    #[test]
    fn test_should_rotate_before_boundary() {
        let em = EpochManager::new(valid_config(), test_committee());
        assert!(!em.should_rotate(99));
    }

    #[test]
    fn test_should_rotate_at_boundary() {
        let em = EpochManager::new(valid_config(), test_committee());
        assert!(em.should_rotate(100));
    }

    #[test]
    fn test_should_rotate_after_boundary() {
        let em = EpochManager::new(valid_config(), test_committee());
        assert!(em.should_rotate(150));
    }

    #[test]
    fn test_should_rotate_at_zero() {
        let em = EpochManager::new(valid_config(), test_committee());
        assert!(!em.should_rotate(0));
    }

    #[test]
    fn test_should_rotate_status_not_active() {
        let config = EpochConfig {
            epoch_duration_blocks: 0,
            handoff_duration_blocks: 0,
            dkg_timeout_blocks: 0,
        };
        let em = EpochManager::new(config, test_committee());
        // status = Inactive, should never rotate
        assert!(!em.should_rotate(1000));
    }

    #[test]
    fn test_should_rotate_after_trigger_returns_false() {
        let mut em = EpochManager::new(valid_config(), test_committee());
        let _ = em.trigger_rotation(100, test_da_seed());
        // status is now PendingRotation, not Active
        assert!(!em.should_rotate(200));
    }

    #[test]
    fn test_should_rotate_overflow_boundary() {
        let config = EpochConfig {
            epoch_duration_blocks: u64::MAX,
            handoff_duration_blocks: 0,
            dkg_timeout_blocks: 0,
        };
        let mut em = EpochManager::new(config, test_committee());
        // Force epoch_start_height > 0 to trigger checked_add overflow
        em.epoch_start_height = 1;
        // 1 + u64::MAX → overflow → checked_add returns None → false
        assert!(!em.should_rotate(u64::MAX));
    }

    // ──────────────────────────────────────────────────────────
    // trigger_rotation tests (14A.2B.2.23)
    // ──────────────────────────────────────────────────────────

    #[test]
    fn test_trigger_rotation_success() {
        let mut em = EpochManager::new(valid_config(), test_committee());
        let result = em.trigger_rotation(100, test_da_seed());
        assert!(result.is_ok());
    }

    #[test]
    fn test_trigger_rotation_transition_fields() {
        let committee = test_committee();
        let mut em = EpochManager::new(valid_config(), committee.clone());
        let transition = em.trigger_rotation(100, test_da_seed()).unwrap();

        assert_eq!(transition.old_committee, committee);
        assert_eq!(transition.new_committee, committee); // placeholder
        assert_eq!(transition.transition_height, 100);
        assert_eq!(transition.handoff_start, 100);
        assert_eq!(transition.handoff_end, 110); // 100 + handoff_duration_blocks(10)
    }

    #[test]
    fn test_trigger_rotation_status_changes() {
        let mut em = EpochManager::new(valid_config(), test_committee());
        let _ = em.trigger_rotation(100, test_da_seed());
        assert_eq!(em.current_status(), CommitteeStatus::PendingRotation);
    }

    #[test]
    fn test_trigger_rotation_pending_transition_set() {
        let mut em = EpochManager::new(valid_config(), test_committee());
        let transition = em.trigger_rotation(100, test_da_seed()).unwrap();
        assert_eq!(em.pending_transition, Some(transition));
    }

    #[test]
    fn test_trigger_rotation_current_committee_unchanged() {
        let committee = test_committee();
        let mut em = EpochManager::new(valid_config(), committee.clone());
        let _ = em.trigger_rotation(100, test_da_seed());
        assert_eq!(*em.current_committee(), committee);
    }

    #[test]
    fn test_trigger_rotation_not_at_boundary() {
        let mut em = EpochManager::new(valid_config(), test_committee());
        let result = em.trigger_rotation(50, test_da_seed());
        assert_eq!(result, Err(RotationError::NotAtBoundary));
    }

    #[test]
    fn test_trigger_rotation_status_not_active() {
        let config = EpochConfig {
            epoch_duration_blocks: 0,
            handoff_duration_blocks: 0,
            dkg_timeout_blocks: 0,
        };
        let mut em = EpochManager::new(config, test_committee());
        // status = Inactive
        let result = em.trigger_rotation(100, test_da_seed());
        assert_eq!(result, Err(RotationError::AlreadyRotating));
    }

    #[test]
    fn test_trigger_rotation_zero_da_seed() {
        let mut em = EpochManager::new(valid_config(), test_committee());
        let result = em.trigger_rotation(100, [0u8; 32]);
        assert_eq!(result, Err(RotationError::SelectionFailed));
    }

    #[test]
    fn test_trigger_rotation_zero_seed_state_untouched() {
        let mut em = EpochManager::new(valid_config(), test_committee());
        let _ = em.trigger_rotation(100, [0u8; 32]);
        // State must NOT have changed on seed error
        assert_eq!(em.current_status(), CommitteeStatus::Active);
        assert!(em.pending_transition.is_none());
    }

    #[test]
    fn test_trigger_rotation_double_trigger() {
        let mut em = EpochManager::new(valid_config(), test_committee());
        let first = em.trigger_rotation(100, test_da_seed());
        assert!(first.is_ok());
        // Second trigger fails — status is PendingRotation
        let second = em.trigger_rotation(100, test_da_seed());
        assert_eq!(second, Err(RotationError::AlreadyRotating));
    }

    #[test]
    fn test_trigger_rotation_not_at_boundary_state_untouched() {
        let mut em = EpochManager::new(valid_config(), test_committee());
        let _ = em.trigger_rotation(50, test_da_seed());
        assert_eq!(em.current_status(), CommitteeStatus::Active);
        assert!(em.pending_transition.is_none());
    }

    #[test]
    fn test_trigger_rotation_handoff_end_saturating() {
        let config = EpochConfig {
            epoch_duration_blocks: 10,
            handoff_duration_blocks: 5,
            dkg_timeout_blocks: 3,
        };
        let mut em = EpochManager::new(config, test_committee());
        // Set epoch_start_height so boundary is reachable near u64::MAX
        em.epoch_start_height = u64::MAX - 12;
        let result = em.trigger_rotation(u64::MAX - 2, test_da_seed());
        assert!(result.is_ok());
        let transition = result.unwrap();
        // (u64::MAX - 2) + 5 would overflow → saturating to u64::MAX
        assert_eq!(transition.handoff_end, u64::MAX);
    }

    // ──────────────────────────────────────────────────────────
    // prepare_next_epoch tests (14A.2B.2.23)
    // ──────────────────────────────────────────────────────────

    #[test]
    fn test_prepare_next_epoch_success() {
        let mut em = EpochManager::new(valid_config(), test_committee());
        let _ = em.trigger_rotation(100, test_da_seed());
        let result = em.prepare_next_epoch(test_committee());
        assert!(result.is_ok());
    }

    #[test]
    fn test_prepare_next_epoch_sets_next_committee() {
        let mut em = EpochManager::new(valid_config(), test_committee());
        let _ = em.trigger_rotation(100, test_da_seed());
        let new_committee = test_committee();
        em.prepare_next_epoch(new_committee.clone()).unwrap();
        assert_eq!(em.next_committee, Some(new_committee));
    }

    #[test]
    fn test_prepare_next_epoch_current_committee_unchanged() {
        let committee = test_committee();
        let mut em = EpochManager::new(valid_config(), committee.clone());
        let _ = em.trigger_rotation(100, test_da_seed());
        em.prepare_next_epoch(test_committee()).unwrap();
        assert_eq!(*em.current_committee(), committee);
    }

    #[test]
    fn test_prepare_next_epoch_current_epoch_unchanged() {
        let mut em = EpochManager::new(valid_config(), test_committee());
        let _ = em.trigger_rotation(100, test_da_seed());
        em.prepare_next_epoch(test_committee()).unwrap();
        assert_eq!(em.current_epoch(), 0);
    }

    #[test]
    fn test_prepare_next_epoch_wrong_status_active() {
        let mut em = EpochManager::new(valid_config(), test_committee());
        // status = Active, not PendingRotation
        let result = em.prepare_next_epoch(test_committee());
        assert_eq!(result, Err(RotationError::AlreadyRotating));
    }

    #[test]
    fn test_prepare_next_epoch_wrong_status_inactive() {
        let config = EpochConfig {
            epoch_duration_blocks: 0,
            handoff_duration_blocks: 0,
            dkg_timeout_blocks: 0,
        };
        let mut em = EpochManager::new(config, test_committee());
        // status = Inactive
        let result = em.prepare_next_epoch(test_committee());
        assert_eq!(result, Err(RotationError::AlreadyRotating));
    }

    // ──────────────────────────────────────────────────────────
    // RotationError tests (14A.2B.2.23)
    // ──────────────────────────────────────────────────────────

    #[test]
    fn test_rotation_error_display() {
        assert!(!format!("{}", RotationError::NotAtBoundary).is_empty());
        assert!(!format!("{}", RotationError::AlreadyRotating).is_empty());
        assert!(!format!("{}", RotationError::SelectionFailed).is_empty());
        assert!(!format!("{}", RotationError::DKGFailed).is_empty());
    }

    #[test]
    fn test_rotation_error_debug() {
        let debug = format!("{:?}", RotationError::NotAtBoundary);
        assert!(debug.contains("NotAtBoundary"));
    }

    #[test]
    fn test_rotation_error_clone_eq() {
        let e1 = RotationError::AlreadyRotating;
        let e2 = e1.clone();
        assert_eq!(e1, e2);
    }

    #[test]
    fn test_rotation_error_is_std_error() {
        let e: &dyn std::error::Error = &RotationError::DKGFailed;
        assert!(!e.to_string().is_empty());
    }

    #[test]
    fn test_rotation_error_variants_distinct() {
        assert_ne!(RotationError::NotAtBoundary, RotationError::AlreadyRotating);
        assert_ne!(RotationError::AlreadyRotating, RotationError::SelectionFailed);
        assert_ne!(RotationError::SelectionFailed, RotationError::DKGFailed);
        assert_ne!(RotationError::DKGFailed, RotationError::NotAtBoundary);
    }

    // ──────────────────────────────────────────────────────────
    // Handoff window helper (14A.2B.2.24)
    // ──────────────────────────────────────────────────────────
    //
    // With valid_config: epoch_duration=100, handoff_duration=10
    // epoch_start_height = 0
    // epoch_end = 0 + 100 = 100
    // handoff_start = 100 - 10 = 90
    // handoff_end = 100

    // ──────────────────────────────────────────────────────────
    // is_in_handoff tests (14A.2B.2.24)
    // ──────────────────────────────────────────────────────────

    #[test]
    fn test_is_in_handoff_before_start() {
        let em = EpochManager::new(valid_config(), test_committee());
        assert!(!em.is_in_handoff(89));
    }

    #[test]
    fn test_is_in_handoff_at_start() {
        let em = EpochManager::new(valid_config(), test_committee());
        assert!(em.is_in_handoff(90));
    }

    #[test]
    fn test_is_in_handoff_during() {
        let em = EpochManager::new(valid_config(), test_committee());
        assert!(em.is_in_handoff(95));
    }

    #[test]
    fn test_is_in_handoff_last_block() {
        let em = EpochManager::new(valid_config(), test_committee());
        assert!(em.is_in_handoff(99));
    }

    #[test]
    fn test_is_in_handoff_at_end() {
        let em = EpochManager::new(valid_config(), test_committee());
        // handoff_end = 100, height 100 is NOT in handoff (>= end)
        assert!(!em.is_in_handoff(100));
    }

    #[test]
    fn test_is_in_handoff_after_end() {
        let em = EpochManager::new(valid_config(), test_committee());
        assert!(!em.is_in_handoff(150));
    }

    #[test]
    fn test_is_in_handoff_at_zero() {
        let em = EpochManager::new(valid_config(), test_committee());
        assert!(!em.is_in_handoff(0));
    }

    #[test]
    fn test_is_in_handoff_zero_handoff_duration() {
        let config = EpochConfig {
            epoch_duration_blocks: 100,
            handoff_duration_blocks: 0,
            dkg_timeout_blocks: 0,
        };
        let em = EpochManager::new(config, test_committee());
        // handoff_start = 100, handoff_end = 100 → empty window
        assert!(!em.is_in_handoff(99));
        assert!(!em.is_in_handoff(100));
    }

    #[test]
    fn test_is_in_handoff_overflow() {
        let config = EpochConfig {
            epoch_duration_blocks: u64::MAX,
            handoff_duration_blocks: 10,
            dkg_timeout_blocks: 5,
        };
        let mut em = EpochManager::new(config, test_committee());
        em.epoch_start_height = 1;
        // 1 + u64::MAX → overflow → handoff_window returns None → false
        assert!(!em.is_in_handoff(u64::MAX));
    }

    // ──────────────────────────────────────────────────────────
    // valid_committee_for_height tests (14A.2B.2.24)
    // ──────────────────────────────────────────────────────────

    #[test]
    fn test_valid_committee_before_handoff() {
        let committee = test_committee();
        let em = EpochManager::new(valid_config(), committee.clone());
        assert_eq!(*em.valid_committee_for_height(50), committee);
    }

    #[test]
    fn test_valid_committee_during_handoff() {
        let committee = test_committee();
        let em = EpochManager::new(valid_config(), committee.clone());
        // During handoff (90-99): default is OLD committee
        assert_eq!(*em.valid_committee_for_height(95), committee);
    }

    #[test]
    fn test_valid_committee_after_handoff_with_next() {
        let committee = test_committee();
        let mut em = EpochManager::new(valid_config(), committee.clone());
        let _ = em.trigger_rotation(100, test_da_seed());
        let new_committee = test_committee();
        em.prepare_next_epoch(new_committee.clone()).unwrap();
        // height >= handoff_end (100) → return next_committee
        assert_eq!(*em.valid_committee_for_height(100), new_committee);
    }

    #[test]
    fn test_valid_committee_after_handoff_without_next() {
        let committee = test_committee();
        let em = EpochManager::new(valid_config(), committee.clone());
        // height >= handoff_end but next_committee is None → fallback to current
        assert_eq!(*em.valid_committee_for_height(100), committee);
    }

    #[test]
    fn test_valid_committee_at_handoff_start() {
        let committee = test_committee();
        let em = EpochManager::new(valid_config(), committee.clone());
        // height 90 (handoff_start): still current_committee
        assert_eq!(*em.valid_committee_for_height(90), committee);
    }

    // ──────────────────────────────────────────────────────────
    // valid_committees_for_height tests (14A.2B.2.24)
    // ──────────────────────────────────────────────────────────

    #[test]
    fn test_valid_committees_before_handoff() {
        let committee = test_committee();
        let em = EpochManager::new(valid_config(), committee.clone());
        let result = em.valid_committees_for_height(50);
        assert_eq!(result.len(), 1);
        assert_eq!(*result[0], committee);
    }

    #[test]
    fn test_valid_committees_during_handoff_with_next() {
        let committee = test_committee();
        let mut em = EpochManager::new(valid_config(), committee.clone());
        let _ = em.trigger_rotation(100, test_da_seed());
        let new_committee = test_committee();
        em.prepare_next_epoch(new_committee.clone()).unwrap();
        let result = em.valid_committees_for_height(95);
        assert_eq!(result.len(), 2);
        assert_eq!(*result[0], committee); // OLD first
        assert_eq!(*result[1], new_committee); // NEW second
    }

    #[test]
    fn test_valid_committees_during_handoff_without_next() {
        let committee = test_committee();
        let em = EpochManager::new(valid_config(), committee.clone());
        // In handoff period but next_committee not set → only current
        let result = em.valid_committees_for_height(95);
        assert_eq!(result.len(), 1);
        assert_eq!(*result[0], committee);
    }

    #[test]
    fn test_valid_committees_after_handoff_with_next() {
        let committee = test_committee();
        let mut em = EpochManager::new(valid_config(), committee.clone());
        let _ = em.trigger_rotation(100, test_da_seed());
        let new_committee = test_committee();
        em.prepare_next_epoch(new_committee.clone()).unwrap();
        let result = em.valid_committees_for_height(100);
        assert_eq!(result.len(), 1);
        assert_eq!(*result[0], new_committee); // only NEW
    }

    #[test]
    fn test_valid_committees_after_handoff_without_next() {
        let committee = test_committee();
        let em = EpochManager::new(valid_config(), committee.clone());
        // height >= handoff_end but no next → fallback to current
        let result = em.valid_committees_for_height(100);
        assert_eq!(result.len(), 1);
        assert_eq!(*result[0], committee);
    }

    #[test]
    fn test_valid_committees_order_old_then_new() {
        let mut em = EpochManager::new(valid_config(), test_committee());
        let _ = em.trigger_rotation(100, test_da_seed());
        em.prepare_next_epoch(test_committee()).unwrap();
        let result = em.valid_committees_for_height(95);
        // Must have exactly 2, OLD first
        assert_eq!(result.len(), 2);
        assert!(std::ptr::eq(result[0], &em.current_committee));
    }

    // ──────────────────────────────────────────────────────────
    // complete_handoff tests (14A.2B.2.24)
    // ──────────────────────────────────────────────────────────

    #[test]
    fn test_complete_handoff_success() {
        let mut em = EpochManager::new(valid_config(), test_committee());
        let _ = em.trigger_rotation(100, test_da_seed());
        em.prepare_next_epoch(test_committee()).unwrap();
        let result = em.complete_handoff(100);
        assert!(result.is_ok());
    }

    #[test]
    fn test_complete_handoff_state_current_committee() {
        let committee = test_committee();
        let mut em = EpochManager::new(valid_config(), committee.clone());
        let _ = em.trigger_rotation(100, test_da_seed());
        let new_committee = test_committee();
        em.prepare_next_epoch(new_committee.clone()).unwrap();
        em.complete_handoff(100).unwrap();
        assert_eq!(*em.current_committee(), new_committee);
    }

    #[test]
    fn test_complete_handoff_state_next_committee_none() {
        let mut em = EpochManager::new(valid_config(), test_committee());
        let _ = em.trigger_rotation(100, test_da_seed());
        em.prepare_next_epoch(test_committee()).unwrap();
        em.complete_handoff(100).unwrap();
        assert!(em.next_committee.is_none());
    }

    #[test]
    fn test_complete_handoff_state_pending_transition_none() {
        let mut em = EpochManager::new(valid_config(), test_committee());
        let _ = em.trigger_rotation(100, test_da_seed());
        em.prepare_next_epoch(test_committee()).unwrap();
        em.complete_handoff(100).unwrap();
        assert!(em.pending_transition.is_none());
    }

    #[test]
    fn test_complete_handoff_state_epoch_start_height() {
        let mut em = EpochManager::new(valid_config(), test_committee());
        let _ = em.trigger_rotation(100, test_da_seed());
        em.prepare_next_epoch(test_committee()).unwrap();
        em.complete_handoff(100).unwrap();
        // epoch_start_height = handoff_end = epoch_end = 0 + 100 = 100
        assert_eq!(em.epoch_start_height, 100);
    }

    #[test]
    fn test_complete_handoff_state_status_active() {
        let mut em = EpochManager::new(valid_config(), test_committee());
        let _ = em.trigger_rotation(100, test_da_seed());
        em.prepare_next_epoch(test_committee()).unwrap();
        em.complete_handoff(100).unwrap();
        assert_eq!(em.current_status(), CommitteeStatus::Active);
    }

    #[test]
    fn test_complete_handoff_state_epoch_incremented() {
        let mut em = EpochManager::new(valid_config(), test_committee());
        let _ = em.trigger_rotation(100, test_da_seed());
        em.prepare_next_epoch(test_committee()).unwrap();
        em.complete_handoff(100).unwrap();
        assert_eq!(em.current_epoch(), 1);
    }

    #[test]
    fn test_complete_handoff_err_not_in_handoff() {
        let mut em = EpochManager::new(valid_config(), test_committee());
        // No trigger_rotation → no pending_transition
        let result = em.complete_handoff(100);
        assert_eq!(result, Err(HandoffError::NotInHandoff));
    }

    #[test]
    fn test_complete_handoff_err_before_handoff_end() {
        let mut em = EpochManager::new(valid_config(), test_committee());
        let _ = em.trigger_rotation(100, test_da_seed());
        em.prepare_next_epoch(test_committee()).unwrap();
        // handoff_end = 100, height 99 is before
        let result = em.complete_handoff(99);
        assert_eq!(result, Err(HandoffError::HandoffNotComplete));
    }

    #[test]
    fn test_complete_handoff_err_new_committee_not_ready() {
        let mut em = EpochManager::new(valid_config(), test_committee());
        let _ = em.trigger_rotation(100, test_da_seed());
        // prepare_next_epoch NOT called → next_committee is None
        let result = em.complete_handoff(100);
        assert_eq!(result, Err(HandoffError::NewCommitteeNotReady));
    }

    #[test]
    fn test_complete_handoff_double_complete() {
        let mut em = EpochManager::new(valid_config(), test_committee());
        let _ = em.trigger_rotation(100, test_da_seed());
        em.prepare_next_epoch(test_committee()).unwrap();
        em.complete_handoff(100).unwrap();
        // Second complete → no pending_transition → NotInHandoff
        let result = em.complete_handoff(200);
        assert_eq!(result, Err(HandoffError::NotInHandoff));
    }

    #[test]
    fn test_complete_handoff_state_untouched_on_error() {
        let mut em = EpochManager::new(valid_config(), test_committee());
        let _ = em.trigger_rotation(100, test_da_seed());
        // Don't set next_committee
        let _ = em.complete_handoff(100);
        // State should be unchanged (status still PendingRotation)
        assert_eq!(em.current_status(), CommitteeStatus::PendingRotation);
        assert_eq!(em.current_epoch(), 0);
        assert_eq!(em.epoch_start_height, 0);
    }

    #[test]
    fn test_complete_handoff_past_end_is_ok() {
        let mut em = EpochManager::new(valid_config(), test_committee());
        let _ = em.trigger_rotation(100, test_da_seed());
        em.prepare_next_epoch(test_committee()).unwrap();
        // height 200 is well past handoff_end(100), should still succeed
        let result = em.complete_handoff(200);
        assert!(result.is_ok());
        assert_eq!(em.epoch_start_height, 100); // handoff_end, not current_height
    }

    // ──────────────────────────────────────────────────────────
    // Full lifecycle test (14A.2B.2.24)
    // ──────────────────────────────────────────────────────────

    #[test]
    fn test_full_epoch_lifecycle() {
        let committee = test_committee();
        let mut em = EpochManager::new(valid_config(), committee.clone());

        // Epoch 0: Active
        assert_eq!(em.current_epoch(), 0);
        assert_eq!(em.current_status(), CommitteeStatus::Active);
        assert!(!em.is_in_handoff(50));
        assert!(em.is_in_handoff(95));

        // Trigger rotation at boundary
        assert!(em.should_rotate(100));
        let _ = em.trigger_rotation(100, test_da_seed());
        assert_eq!(em.current_status(), CommitteeStatus::PendingRotation);

        // Prepare new committee
        let new_committee = test_committee();
        em.prepare_next_epoch(new_committee.clone()).unwrap();

        // Verify both committees valid during handoff
        let committees = em.valid_committees_for_height(95);
        assert_eq!(committees.len(), 2);

        // Complete handoff
        em.complete_handoff(100).unwrap();

        // Epoch 1: Active with new committee
        assert_eq!(em.current_epoch(), 1);
        assert_eq!(em.current_status(), CommitteeStatus::Active);
        assert_eq!(em.epoch_start_height, 100);
        assert!(em.next_committee.is_none());
        assert!(em.pending_transition.is_none());
    }

    #[test]
    fn test_two_epoch_rotations() {
        let mut em = EpochManager::new(valid_config(), test_committee());

        // First rotation: epoch 0 → 1
        let _ = em.trigger_rotation(100, test_da_seed());
        em.prepare_next_epoch(test_committee()).unwrap();
        em.complete_handoff(100).unwrap();
        assert_eq!(em.current_epoch(), 1);
        assert_eq!(em.epoch_start_height, 100);

        // Second rotation: epoch 1 → 2
        // New boundary: 100 + 100 = 200
        assert!(em.should_rotate(200));
        let _ = em.trigger_rotation(200, test_da_seed());
        em.prepare_next_epoch(test_committee()).unwrap();
        em.complete_handoff(200).unwrap();
        assert_eq!(em.current_epoch(), 2);
        assert_eq!(em.epoch_start_height, 200);
    }

    // ──────────────────────────────────────────────────────────
    // HandoffError tests (14A.2B.2.24)
    // ──────────────────────────────────────────────────────────

    #[test]
    fn test_handoff_error_display() {
        assert!(!format!("{}", HandoffError::NotInHandoff).is_empty());
        assert!(!format!("{}", HandoffError::HandoffNotComplete).is_empty());
        assert!(!format!("{}", HandoffError::NewCommitteeNotReady).is_empty());
    }

    #[test]
    fn test_handoff_error_debug() {
        let debug = format!("{:?}", HandoffError::NotInHandoff);
        assert!(debug.contains("NotInHandoff"));
    }

    #[test]
    fn test_handoff_error_clone_eq() {
        let e1 = HandoffError::HandoffNotComplete;
        let e2 = e1.clone();
        assert_eq!(e1, e2);
    }

    #[test]
    fn test_handoff_error_is_std_error() {
        let e: &dyn std::error::Error = &HandoffError::NewCommitteeNotReady;
        assert!(!e.to_string().is_empty());
    }

    #[test]
    fn test_handoff_error_variants_distinct() {
        assert_ne!(HandoffError::NotInHandoff, HandoffError::HandoffNotComplete);
        assert_ne!(HandoffError::HandoffNotComplete, HandoffError::NewCommitteeNotReady);
        assert_ne!(HandoffError::NewCommitteeNotReady, HandoffError::NotInHandoff);
    }
}