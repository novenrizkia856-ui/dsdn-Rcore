//! # DKG State Machine
//!
//! Module ini mendefinisikan state machine untuk DKG protocol.
//!
//! ## State Transitions
//!
//! ```text
//! Initialized ──► Round1Commitment ──► Round1Complete ──► Round2Share
//!                                                              │
//!                                                              ▼
//!                                            Round2Complete ──► Completed
//!                                                   │
//!                                                   └──────► Failed
//! ```
//!
//! Transisi hanya valid dalam arah forward. Tidak ada rollback.

use std::collections::HashMap;

use crate::error::DKGError;
use crate::primitives::GroupPublicKey;
use crate::types::ParticipantId;

use super::packages::{Round1Package, Round2Package};

// ════════════════════════════════════════════════════════════════════════════════
// DKG STATE ENUM
// ════════════════════════════════════════════════════════════════════════════════

/// State dalam DKG protocol state machine.
///
/// DKG protocol terdiri dari beberapa fase yang direpresentasikan sebagai
/// discrete states. Setiap state menyimpan data yang relevan untuk fase tersebut.
///
/// ## Terminal States
///
/// - `Completed`: DKG berhasil, `GroupPublicKey` tersedia
/// - `Failed`: DKG gagal dengan error
///
/// ## Transition Rules
///
/// State hanya dapat bertransisi ke state berikutnya dalam urutan:
/// 1. `Initialized` → `Round1Commitment`
/// 2. `Round1Commitment` → `Round1Complete`
/// 3. `Round1Complete` → `Round2Share`
/// 4. `Round2Share` → `Round2Complete`
/// 5. `Round2Complete` → `Completed` atau `Failed`
///
/// Dari state manapun (kecuali terminal), transisi ke `Failed` selalu valid.
#[derive(Debug, Clone)]
pub enum DKGState {
    /// State awal sebelum DKG dimulai.
    ///
    /// Dalam state ini, participant list dan threshold belum ditentukan.
    Initialized,

    /// Round 1 sedang berlangsung - menunggu commitments.
    ///
    /// Participants sedang generate dan broadcast Round1Packages.
    Round1Commitment,

    /// Round 1 selesai - semua commitments telah diterima dan diverifikasi.
    ///
    /// Menyimpan mapping dari ParticipantId ke Round1Package mereka.
    Round1Complete {
        /// Commitments dari semua participants.
        commitments: HashMap<ParticipantId, Round1Package>,
    },

    /// Round 2 sedang berlangsung - menunggu encrypted shares.
    ///
    /// Participants sedang mengirim Round2Packages ke masing-masing recipient.
    Round2Share,

    /// Round 2 selesai - semua shares telah diterima.
    ///
    /// Menyimpan mapping dari ParticipantId ke Vec<Round2Package> yang diterima.
    Round2Complete {
        /// Shares yang diterima oleh setiap participant.
        /// Key adalah recipient, value adalah list packages dari semua senders.
        shares: HashMap<ParticipantId, Vec<Round2Package>>,
    },

    /// DKG berhasil diselesaikan.
    ///
    /// Group public key telah dihasilkan dan siap untuk signing.
    Completed {
        /// Shared public key hasil DKG.
        group_pubkey: GroupPublicKey,
    },

    /// DKG gagal dengan error.
    ///
    /// Protocol harus di-restart dari awal.
    Failed {
        /// Error yang menyebabkan kegagalan.
        error: DKGError,
    },
}

impl DKGState {
    /// Mengecek apakah state adalah terminal state.
    ///
    /// Terminal states adalah `Completed` dan `Failed`.
    /// Tidak ada transisi yang valid dari terminal state.
    ///
    /// # Returns
    ///
    /// `true` jika state adalah `Completed` atau `Failed`, `false` sebaliknya.
    ///
    /// # Example
    ///
    /// ```rust
    /// use dsdn_tss::dkg::DKGState;
    ///
    /// assert!(!DKGState::Initialized.is_terminal());
    /// assert!(!DKGState::Round1Commitment.is_terminal());
    /// ```
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, DKGState::Completed { .. } | DKGState::Failed { .. })
    }

    /// Mengecek apakah transisi dari state saat ini ke `next` adalah valid.
    ///
    /// Transisi valid mengikuti alur:
    /// 1. `Initialized` → `Round1Commitment` atau `Failed`
    /// 2. `Round1Commitment` → `Round1Complete` atau `Failed`
    /// 3. `Round1Complete` → `Round2Share` atau `Failed`
    /// 4. `Round2Share` → `Round2Complete` atau `Failed`
    /// 5. `Round2Complete` → `Completed` atau `Failed`
    /// 6. `Completed` → (tidak ada transisi valid)
    /// 7. `Failed` → (tidak ada transisi valid)
    ///
    /// # Arguments
    ///
    /// * `next` - Target state untuk transisi
    ///
    /// # Returns
    ///
    /// `true` jika transisi valid, `false` sebaliknya.
    ///
    /// # Example
    ///
    /// ```rust
    /// use dsdn_tss::dkg::DKGState;
    ///
    /// let state = DKGState::Initialized;
    /// assert!(state.can_transition_to(&DKGState::Round1Commitment));
    /// assert!(!state.can_transition_to(&DKGState::Round2Share));
    /// ```
    #[must_use]
    pub fn can_transition_to(&self, next: &DKGState) -> bool {
        // Terminal states cannot transition to anything
        if self.is_terminal() {
            return false;
        }

        // Any non-terminal state can transition to Failed
        if matches!(next, DKGState::Failed { .. }) {
            return true;
        }

        // Check specific valid transitions
        match (self, next) {
            // Initialized can only go to Round1Commitment
            (DKGState::Initialized, DKGState::Round1Commitment) => true,

            // Round1Commitment can only go to Round1Complete
            (DKGState::Round1Commitment, DKGState::Round1Complete { .. }) => true,

            // Round1Complete can only go to Round2Share
            (DKGState::Round1Complete { .. }, DKGState::Round2Share) => true,

            // Round2Share can only go to Round2Complete
            (DKGState::Round2Share, DKGState::Round2Complete { .. }) => true,

            // Round2Complete can only go to Completed
            (DKGState::Round2Complete { .. }, DKGState::Completed { .. }) => true,

            // All other transitions are invalid
            _ => false,
        }
    }

    /// Mengembalikan nama state sebagai static string.
    ///
    /// Nama state bersifat stabil dan deterministik untuk logging dan debugging.
    ///
    /// # Returns
    ///
    /// Static string yang merepresentasikan nama state.
    ///
    /// # Example
    ///
    /// ```rust
    /// use dsdn_tss::dkg::DKGState;
    ///
    /// assert_eq!(DKGState::Initialized.state_name(), "Initialized");
    /// assert_eq!(DKGState::Round1Commitment.state_name(), "Round1Commitment");
    /// ```
    #[must_use]
    pub const fn state_name(&self) -> &'static str {
        match self {
            DKGState::Initialized => "Initialized",
            DKGState::Round1Commitment => "Round1Commitment",
            DKGState::Round1Complete { .. } => "Round1Complete",
            DKGState::Round2Share => "Round2Share",
            DKGState::Round2Complete { .. } => "Round2Complete",
            DKGState::Completed { .. } => "Completed",
            DKGState::Failed { .. } => "Failed",
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ParticipantId;
    use frost_ed25519 as frost;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    // ────────────────────────────────────────────────────────────────────────────
    // IS_TERMINAL TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_initialized_not_terminal() {
        let state = DKGState::Initialized;
        assert!(!state.is_terminal());
    }

    #[test]
    fn test_round1_commitment_not_terminal() {
        let state = DKGState::Round1Commitment;
        assert!(!state.is_terminal());
    }

    #[test]
    fn test_round1_complete_not_terminal() {
        let state = DKGState::Round1Complete {
            commitments: HashMap::new(),
        };
        assert!(!state.is_terminal());
    }

    #[test]
    fn test_round2_share_not_terminal() {
        let state = DKGState::Round2Share;
        assert!(!state.is_terminal());
    }

    #[test]
    fn test_round2_complete_not_terminal() {
        let state = DKGState::Round2Complete {
            shares: HashMap::new(),
        };
        assert!(!state.is_terminal());
    }

    #[test]
    fn test_completed_is_terminal() {
        let group_pubkey = GroupPublicKey::from_bytes([0x02; 32]).unwrap();
        let state = DKGState::Completed { group_pubkey };
        assert!(state.is_terminal());
    }

    #[test]
    fn test_failed_is_terminal() {
        let error = DKGError::InvalidThreshold {
            threshold: 5,
            total: 3,
        };
        let state = DKGState::Failed { error };
        assert!(state.is_terminal());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // STATE_NAME TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_state_name_initialized() {
        assert_eq!(DKGState::Initialized.state_name(), "Initialized");
    }

    #[test]
    fn test_state_name_round1_commitment() {
        assert_eq!(DKGState::Round1Commitment.state_name(), "Round1Commitment");
    }

    #[test]
    fn test_state_name_round1_complete() {
        let state = DKGState::Round1Complete {
            commitments: HashMap::new(),
        };
        assert_eq!(state.state_name(), "Round1Complete");
    }

    #[test]
    fn test_state_name_round2_share() {
        assert_eq!(DKGState::Round2Share.state_name(), "Round2Share");
    }

    #[test]
    fn test_state_name_round2_complete() {
        let state = DKGState::Round2Complete {
            shares: HashMap::new(),
        };
        assert_eq!(state.state_name(), "Round2Complete");
    }

    #[test]
    fn test_state_name_completed() {
        let group_pubkey = GroupPublicKey::from_bytes([0x02; 32]).unwrap();
        let state = DKGState::Completed { group_pubkey };
        assert_eq!(state.state_name(), "Completed");
    }

    #[test]
    fn test_state_name_failed() {
        let error = DKGError::InvalidThreshold {
            threshold: 5,
            total: 3,
        };
        let state = DKGState::Failed { error };
        assert_eq!(state.state_name(), "Failed");
    }

    // ────────────────────────────────────────────────────────────────────────────
    // CAN_TRANSITION_TO TESTS - VALID TRANSITIONS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_transition_initialized_to_round1_commitment() {
        let current = DKGState::Initialized;
        let next = DKGState::Round1Commitment;
        assert!(current.can_transition_to(&next));
    }

    #[test]
    fn test_transition_round1_commitment_to_round1_complete() {
        let current = DKGState::Round1Commitment;
        let next = DKGState::Round1Complete {
            commitments: HashMap::new(),
        };
        assert!(current.can_transition_to(&next));
    }

    #[test]
    fn test_transition_round1_complete_to_round2_share() {
        let current = DKGState::Round1Complete {
            commitments: HashMap::new(),
        };
        let next = DKGState::Round2Share;
        assert!(current.can_transition_to(&next));
    }

    #[test]
    fn test_transition_round2_share_to_round2_complete() {
        let current = DKGState::Round2Share;
        let next = DKGState::Round2Complete {
            shares: HashMap::new(),
        };
        assert!(current.can_transition_to(&next));
    }

    #[test]
    fn test_transition_round2_complete_to_completed() {
        let current = DKGState::Round2Complete {
            shares: HashMap::new(),
        };
        let group_pubkey = GroupPublicKey::from_bytes([0x02; 32]).unwrap();
        let next = DKGState::Completed { group_pubkey };
        assert!(current.can_transition_to(&next));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // CAN_TRANSITION_TO TESTS - TRANSITION TO FAILED
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_transition_initialized_to_failed() {
        let current = DKGState::Initialized;
        let error = DKGError::InvalidThreshold {
            threshold: 5,
            total: 3,
        };
        let next = DKGState::Failed { error };
        assert!(current.can_transition_to(&next));
    }

    #[test]
    fn test_transition_round1_commitment_to_failed() {
        let current = DKGState::Round1Commitment;
        let error = DKGError::InvalidThreshold {
            threshold: 5,
            total: 3,
        };
        let next = DKGState::Failed { error };
        assert!(current.can_transition_to(&next));
    }

    #[test]
    fn test_transition_round1_complete_to_failed() {
        let current = DKGState::Round1Complete {
            commitments: HashMap::new(),
        };
        let participant = ParticipantId::from_bytes([0xAA; 32]);
        let error = DKGError::InvalidCommitment { participant };
        let next = DKGState::Failed { error };
        assert!(current.can_transition_to(&next));
    }

    #[test]
    fn test_transition_round2_share_to_failed() {
        let current = DKGState::Round2Share;
        let participant = ParticipantId::from_bytes([0xBB; 32]);
        let error = DKGError::ShareVerificationFailed { participant };
        let next = DKGState::Failed { error };
        assert!(current.can_transition_to(&next));
    }

    #[test]
    fn test_transition_round2_complete_to_failed() {
        let current = DKGState::Round2Complete {
            shares: HashMap::new(),
        };
        let error = DKGError::InsufficientParticipants {
            expected: 4,
            got: 2,
        };
        let next = DKGState::Failed { error };
        assert!(current.can_transition_to(&next));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // CAN_TRANSITION_TO TESTS - INVALID TRANSITIONS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_transition_initialized_to_round2_share_invalid() {
        let current = DKGState::Initialized;
        let next = DKGState::Round2Share;
        assert!(!current.can_transition_to(&next));
    }

    #[test]
    fn test_transition_initialized_to_completed_invalid() {
        let current = DKGState::Initialized;
        let group_pubkey = GroupPublicKey::from_bytes([0x02; 32]).unwrap();
        let next = DKGState::Completed { group_pubkey };
        assert!(!current.can_transition_to(&next));
    }

    #[test]
    fn test_transition_round1_commitment_to_round2_complete_invalid() {
        let current = DKGState::Round1Commitment;
        let next = DKGState::Round2Complete {
            shares: HashMap::new(),
        };
        assert!(!current.can_transition_to(&next));
    }

    #[test]
    fn test_transition_completed_to_anything_invalid() {
        let group_pubkey = GroupPublicKey::from_bytes([0x02; 32]).unwrap();
        let current = DKGState::Completed {
            group_pubkey: group_pubkey.clone(),
        };

        // Cannot transition to any state from Completed
        assert!(!current.can_transition_to(&DKGState::Initialized));
        assert!(!current.can_transition_to(&DKGState::Round1Commitment));
        assert!(!current.can_transition_to(&DKGState::Round1Complete {
            commitments: HashMap::new()
        }));
        assert!(!current.can_transition_to(&DKGState::Round2Share));
        assert!(!current.can_transition_to(&DKGState::Round2Complete {
            shares: HashMap::new()
        }));
        assert!(!current.can_transition_to(&DKGState::Completed { group_pubkey }));
        assert!(!current.can_transition_to(&DKGState::Failed {
            error: DKGError::InvalidThreshold {
                threshold: 5,
                total: 3
            }
        }));
    }

    #[test]
    fn test_transition_failed_to_anything_invalid() {
        let error = DKGError::InvalidThreshold {
            threshold: 5,
            total: 3,
        };
        let current = DKGState::Failed {
            error: error.clone(),
        };

        // Cannot transition to any state from Failed
        assert!(!current.can_transition_to(&DKGState::Initialized));
        assert!(!current.can_transition_to(&DKGState::Round1Commitment));
        assert!(!current.can_transition_to(&DKGState::Round1Complete {
            commitments: HashMap::new()
        }));
        assert!(!current.can_transition_to(&DKGState::Round2Share));
        assert!(!current.can_transition_to(&DKGState::Round2Complete {
            shares: HashMap::new()
        }));
        assert!(!current.can_transition_to(&DKGState::Completed {
            group_pubkey: GroupPublicKey::from_bytes([0x02; 32]).unwrap()
        }));
        assert!(!current.can_transition_to(&DKGState::Failed { error }));
    }

    #[test]
    fn test_transition_backward_invalid() {
        // Round1Complete cannot go back to Round1Commitment
        let current = DKGState::Round1Complete {
            commitments: HashMap::new(),
        };
        assert!(!current.can_transition_to(&DKGState::Round1Commitment));
        assert!(!current.can_transition_to(&DKGState::Initialized));
    }

    #[test]
    fn test_transition_skip_state_invalid() {
        // Round1Commitment cannot skip to Round2Complete
        let current = DKGState::Round1Commitment;
        assert!(!current.can_transition_to(&DKGState::Round2Complete {
            shares: HashMap::new()
        }));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SEND + SYNC TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_dkg_state_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<DKGState>();
    }

    // ────────────────────────────────────────────────────────────────────────────
    // DEBUG / CLONE TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_dkg_state_debug() {
        let state = DKGState::Initialized;
        let debug = format!("{:?}", state);
        assert!(debug.contains("Initialized"));
    }

    #[test]
    fn test_dkg_state_clone() {
        let state = DKGState::Round1Commitment;
        let cloned = state.clone();
        assert_eq!(cloned.state_name(), state.state_name());
    }

    #[test]
    fn test_dkg_state_clone_with_data() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let fid = frost::Identifier::try_from(1u16).expect("valid id");
        let (_secret, frost_pkg) =
            frost::keys::dkg::part1(fid, 3, 2, &mut rng).expect("part1 must succeed");

        let mut commitments = HashMap::new();
        let participant = ParticipantId::from_bytes([0xAA; 32]);
        let package = Round1Package::new(participant.clone(), frost_pkg);
        commitments.insert(participant, package);

        let state = DKGState::Round1Complete { commitments };
        let cloned = state.clone();

        match cloned {
            DKGState::Round1Complete { commitments } => {
                assert_eq!(commitments.len(), 1);
            }
            _ => panic!("expected Round1Complete"),
        }
    }
}