//! # Signing State Machine
//!
//! Module ini menyediakan `SigningState` enum untuk state machine
//! threshold signing berbasis FROST.
//!
//! ## State Flow
//!
//! ```text
//! ┌───────────────────────────────────────────────────────────────────────────┐
//! │                         SigningState Flow                                  │
//! └───────────────────────────────────────────────────────────────────────────┘
//!
//!   Initialized
//!       │
//!       │ add_commitment()
//!       ▼
//!   CommitmentPhase { commitments }
//!       │
//!       │ finalize_commitments()
//!       ▼
//!   SigningPhase { commitments, partial_signatures }
//!       │
//!       │ complete()
//!       ├─────────────────────┐
//!       ▼                     ▼
//!   Completed { aggregate }    Failed { error }
//! ```
//!
//! ## Terminal States
//!
//! - `Completed`: Signing berhasil, aggregate signature tersedia
//! - `Failed`: Signing gagal dengan error

use std::collections::HashMap;

use crate::error::SigningError;
use crate::types::SignerId;

use super::{AggregateSignature, PartialSignature, SigningCommitment};

// ════════════════════════════════════════════════════════════════════════════════
// SIGNING STATE ENUM
// ════════════════════════════════════════════════════════════════════════════════

/// State dalam threshold signing protocol.
///
/// `SigningState` merepresentasikan fase-fase dalam FROST signing protocol.
/// Setiap state menyimpan data yang relevan untuk fase tersebut.
///
/// ## Catatan
///
/// - State transitions harus eksplisit
/// - Terminal states tidak dapat di-transisikan lagi
/// - Data di-clone saat transisi untuk menghindari partial updates
#[derive(Debug, Clone)]
pub enum SigningState {
    /// State awal sebelum signing dimulai.
    Initialized,

    /// Phase pengumpulan commitments dari signers.
    ///
    /// Signers mengirim `SigningCommitment` yang berisi hiding dan binding
    /// nonce commitments.
    CommitmentPhase {
        /// Commitments yang sudah dikumpulkan.
        /// Key: SignerId, Value: SigningCommitment dari signer tersebut.
        commitments: HashMap<SignerId, SigningCommitment>,
    },

    /// Phase pengumpulan partial signatures.
    ///
    /// Setelah commitments terkumpul, signers menghitung dan mengirim
    /// partial signatures.
    SigningPhase {
        /// Commitments dari semua signers (dari CommitmentPhase).
        commitments: HashMap<SignerId, SigningCommitment>,

        /// Partial signatures yang sudah dikumpulkan.
        /// Key: SignerId, Value: PartialSignature dari signer tersebut.
        partial_signatures: HashMap<SignerId, PartialSignature>,
    },

    /// Signing berhasil dengan aggregate signature.
    Completed {
        /// Aggregate signature hasil FROST signing.
        aggregate: AggregateSignature,
    },

    /// Signing gagal dengan error.
    Failed {
        /// Error yang menyebabkan kegagalan.
        error: SigningError,
    },
}

impl SigningState {
    /// Mengecek apakah state adalah terminal state.
    ///
    /// Terminal states adalah `Completed` dan `Failed`.
    /// Tidak ada transisi yang valid dari terminal state.
    ///
    /// # Returns
    ///
    /// `true` jika state adalah `Completed` atau `Failed`.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, SigningState::Completed { .. } | SigningState::Failed { .. })
    }

    /// Mengembalikan nama state sebagai static string.
    ///
    /// # Returns
    ///
    /// Nama state yang deterministik dan stabil.
    #[must_use]
    pub const fn state_name(&self) -> &'static str {
        match self {
            SigningState::Initialized => "Initialized",
            SigningState::CommitmentPhase { .. } => "CommitmentPhase",
            SigningState::SigningPhase { .. } => "SigningPhase",
            SigningState::Completed { .. } => "Completed",
            SigningState::Failed { .. } => "Failed",
        }
    }

    /// Mengecek apakah transisi ke state berikutnya valid.
    ///
    /// # Arguments
    ///
    /// * `next` - Target state untuk transisi
    ///
    /// # Returns
    ///
    /// `true` jika transisi valid.
    #[must_use]
    pub fn can_transition_to(&self, next: &SigningState) -> bool {
        // Terminal states cannot transition
        if self.is_terminal() {
            return false;
        }

        // Any non-terminal state can transition to Failed
        if matches!(next, SigningState::Failed { .. }) {
            return true;
        }

        // Valid forward transitions
        match (self, next) {
            // Initialized can go to CommitmentPhase
            (SigningState::Initialized, SigningState::CommitmentPhase { .. }) => true,

            // CommitmentPhase can go to SigningPhase
            (SigningState::CommitmentPhase { .. }, SigningState::SigningPhase { .. }) => true,

            // SigningPhase can go to Completed
            (SigningState::SigningPhase { .. }, SigningState::Completed { .. }) => true,

            // All other transitions are invalid
            _ => false,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::FrostSignature;
    use crate::types::SignerId;

    // ────────────────────────────────────────────────────────────────────────────
    // HELPER FUNCTIONS
    // ────────────────────────────────────────────────────────────────────────────

    fn make_aggregate() -> AggregateSignature {
        let sig = FrostSignature::from_bytes([0x01; 64]).unwrap();
        let signers = vec![SignerId::from_bytes([0xAA; 32])];
        let message_hash = [0xBB; 32];
        AggregateSignature::new(sig, signers, message_hash)
    }

    // ────────────────────────────────────────────────────────────────────────────
    // IS_TERMINAL TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_is_terminal_initialized() {
        let state = SigningState::Initialized;
        assert!(!state.is_terminal());
    }

    #[test]
    fn test_is_terminal_commitment_phase() {
        let state = SigningState::CommitmentPhase {
            commitments: HashMap::new(),
        };
        assert!(!state.is_terminal());
    }

    #[test]
    fn test_is_terminal_signing_phase() {
        let state = SigningState::SigningPhase {
            commitments: HashMap::new(),
            partial_signatures: HashMap::new(),
        };
        assert!(!state.is_terminal());
    }

    #[test]
    fn test_is_terminal_completed() {
        let state = SigningState::Completed {
            aggregate: make_aggregate(),
        };
        assert!(state.is_terminal());
    }

    #[test]
    fn test_is_terminal_failed() {
        let state = SigningState::Failed {
            error: SigningError::MessageMismatch,
        };
        assert!(state.is_terminal());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // STATE_NAME TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_state_name_initialized() {
        assert_eq!(SigningState::Initialized.state_name(), "Initialized");
    }

    #[test]
    fn test_state_name_commitment_phase() {
        let state = SigningState::CommitmentPhase {
            commitments: HashMap::new(),
        };
        assert_eq!(state.state_name(), "CommitmentPhase");
    }

    #[test]
    fn test_state_name_signing_phase() {
        let state = SigningState::SigningPhase {
            commitments: HashMap::new(),
            partial_signatures: HashMap::new(),
        };
        assert_eq!(state.state_name(), "SigningPhase");
    }

    #[test]
    fn test_state_name_completed() {
        let state = SigningState::Completed {
            aggregate: make_aggregate(),
        };
        assert_eq!(state.state_name(), "Completed");
    }

    #[test]
    fn test_state_name_failed() {
        let state = SigningState::Failed {
            error: SigningError::MessageMismatch,
        };
        assert_eq!(state.state_name(), "Failed");
    }

    // ────────────────────────────────────────────────────────────────────────────
    // CAN_TRANSITION_TO TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_initialized_to_commitment_phase() {
        let current = SigningState::Initialized;
        let next = SigningState::CommitmentPhase {
            commitments: HashMap::new(),
        };
        assert!(current.can_transition_to(&next));
    }

    #[test]
    fn test_commitment_phase_to_signing_phase() {
        let current = SigningState::CommitmentPhase {
            commitments: HashMap::new(),
        };
        let next = SigningState::SigningPhase {
            commitments: HashMap::new(),
            partial_signatures: HashMap::new(),
        };
        assert!(current.can_transition_to(&next));
    }

    #[test]
    fn test_signing_phase_to_completed() {
        let current = SigningState::SigningPhase {
            commitments: HashMap::new(),
            partial_signatures: HashMap::new(),
        };
        let next = SigningState::Completed {
            aggregate: make_aggregate(),
        };
        assert!(current.can_transition_to(&next));
    }

    #[test]
    fn test_any_to_failed() {
        let failed = SigningState::Failed {
            error: SigningError::MessageMismatch,
        };

        assert!(SigningState::Initialized.can_transition_to(&failed));
        assert!(SigningState::CommitmentPhase {
            commitments: HashMap::new()
        }
        .can_transition_to(&failed));
        assert!(SigningState::SigningPhase {
            commitments: HashMap::new(),
            partial_signatures: HashMap::new()
        }
        .can_transition_to(&failed));
    }

    #[test]
    fn test_terminal_cannot_transition() {
        let completed = SigningState::Completed {
            aggregate: make_aggregate(),
        };
        let failed = SigningState::Failed {
            error: SigningError::MessageMismatch,
        };

        // Completed cannot transition to anything
        assert!(!completed.can_transition_to(&SigningState::Initialized));
        assert!(!completed.can_transition_to(&failed));

        // Failed cannot transition to anything
        let failed2 = SigningState::Failed {
            error: SigningError::MessageMismatch,
        };
        assert!(!failed2.can_transition_to(&SigningState::Initialized));
        assert!(!failed2.can_transition_to(&completed));
    }

    #[test]
    fn test_invalid_skip_transition() {
        // Cannot skip from Initialized to SigningPhase
        let next = SigningState::SigningPhase {
            commitments: HashMap::new(),
            partial_signatures: HashMap::new(),
        };
        assert!(!SigningState::Initialized.can_transition_to(&next));
    }

    #[test]
    fn test_invalid_backward_transition() {
        // Cannot go from CommitmentPhase back to Initialized
        let current = SigningState::CommitmentPhase {
            commitments: HashMap::new(),
        };
        assert!(!current.can_transition_to(&SigningState::Initialized));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SEND + SYNC TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_signing_state_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SigningState>();
    }
}