//! EpochManager base struct (14A.2B.2.22)
//!
//! Stateful component untuk tracking epoch dan committee rotation
//! di chain layer. Hanya state tracking dan queries — tidak ada
//! logic rotasi, persistence, atau side effects.

use dsdn_common::coordinator::CoordinatorCommittee;

use super::{CommitteeStatus, CommitteeTransition, EpochConfig};

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
}