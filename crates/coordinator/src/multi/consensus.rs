//! Receipt Consensus State Machine (14A.2B.2.15)
//!
//! Module ini menyediakan state machine deterministic untuk consensus
//! atas satu receipt (satu workload).
//!
//! # Overview
//!
//! `ReceiptConsensus` melacak lifecycle consensus secara eksplisit:
//! - Tidak ada IO
//! - Tidak bergantung network
//! - Tidak spawn task
//! - Murni state transition + validation
//!
//! # State Machine
//!
//! ```text
//! ┌──────────┐
//! │ Proposed │ (initial state)
//! └────┬─────┘
//!      │ add_vote()
//!      ▼
//! ┌──────────┐
//! │  Voting  │ ◄─── add_vote() (accumulate)
//! └────┬─────┘
//!      │
//!      ├── approve >= threshold ──► Signing ──► Completed (terminal)
//!      │
//!      └── reject >= threshold ───► Failed (terminal)
//!
//! Any state + timeout ──► TimedOut (terminal)
//! ```
//!
//! # Terminal States
//!
//! - `Completed` - Consensus berhasil, receipt tersedia
//! - `Failed` - Consensus gagal
//! - `TimedOut` - Timeout tercapai sebelum consensus
//!
//! # Usage
//!
//! ```ignore
//! use dsdn_coordinator::multi::{ReceiptConsensus, ConsensusState};
//!
//! // Create consensus instance
//! let mut consensus = ReceiptConsensus::new(
//!     workload_id,
//!     receipt_data,
//!     proposer_id,
//!     3,      // threshold
//!     30000,  // timeout_ms
//!     now_ms, // current timestamp
//! );
//!
//! // Add votes
//! let transition = consensus.add_vote(voter_id, vote, now_ms);
//!
//! // Check if ready for signing
//! if consensus.should_proceed_to_signing() {
//!     // Start signing process...
//! }
//! ```

use std::collections::HashMap;
use std::fmt;

use dsdn_common::coordinator::{ReceiptData, ThresholdReceipt};

use super::{CoordinatorId, SessionId, Vote, WorkloadId};

// ════════════════════════════════════════════════════════════════════════════════
// CONSENSUS ERROR
// ════════════════════════════════════════════════════════════════════════════════

/// Error type untuk consensus failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusError {
    /// State transition tidak valid.
    InvalidStateTransition {
        /// State saat ini.
        from: String,
        /// State yang dicoba.
        to: String,
    },

    /// Voter sudah pernah vote.
    DuplicateVote {
        /// CoordinatorId yang duplikat.
        voter: CoordinatorId,
    },

    /// Threshold tidak tercapai.
    ThresholdNotMet {
        /// Threshold yang dibutuhkan.
        required: u8,
        /// Jumlah approval yang didapat.
        got: u8,
    },

    /// Consensus di-reject oleh majority.
    Rejected {
        /// Jumlah rejection votes.
        reject_count: u8,
        /// Threshold untuk rejection.
        threshold: u8,
    },

    /// Timeout tercapai.
    Timeout {
        /// Waktu timeout yang ditetapkan.
        timeout_at: u64,
        /// Waktu saat timeout terdeteksi.
        detected_at: u64,
    },

    /// Internal invariant violation (bug dalam kode).
    InternalInvariantViolation {
        /// Deskripsi violation.
        description: String,
    },

    /// Threshold tidak valid (harus > 0).
    InvalidThreshold,
}

impl fmt::Display for ConsensusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConsensusError::InvalidStateTransition { from, to } => {
                write!(f, "invalid state transition from {} to {}", from, to)
            }
            ConsensusError::DuplicateVote { voter } => {
                write!(f, "duplicate vote from {:?}", voter.as_bytes())
            }
            ConsensusError::ThresholdNotMet { required, got } => {
                write!(
                    f,
                    "threshold not met: required {}, got {}",
                    required, got
                )
            }
            ConsensusError::Rejected { reject_count, threshold } => {
                write!(
                    f,
                    "consensus rejected: {} rejections >= threshold {}",
                    reject_count, threshold
                )
            }
            ConsensusError::Timeout { timeout_at, detected_at } => {
                write!(
                    f,
                    "consensus timed out: timeout_at={}, detected_at={}",
                    timeout_at, detected_at
                )
            }
            ConsensusError::InternalInvariantViolation { description } => {
                write!(f, "internal invariant violation: {}", description)
            }
            ConsensusError::InvalidThreshold => {
                write!(f, "invalid threshold: must be > 0")
            }
        }
    }
}

impl std::error::Error for ConsensusError {}

// ════════════════════════════════════════════════════════════════════════════════
// CONSENSUS STATE
// ════════════════════════════════════════════════════════════════════════════════

/// State dalam consensus lifecycle.
///
/// State machine bersifat linear dengan terminal states.
/// Setelah mencapai terminal state, tidak ada transisi lagi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusState {
    /// Receipt baru diusulkan, belum ada vote.
    Proposed,

    /// Sedang mengumpulkan votes.
    Voting {
        /// Jumlah approval votes.
        approve_count: u8,
        /// Jumlah rejection votes.
        reject_count: u8,
    },

    /// Threshold tercapai, sedang dalam proses signing.
    Signing {
        /// Session ID untuk signing.
        signing_session: SessionId,
    },

    /// Consensus berhasil, receipt tersedia.
    Completed {
        /// Receipt yang sudah di-sign.
        receipt: ThresholdReceipt,
    },

    /// Consensus gagal.
    Failed {
        /// Error yang menyebabkan failure.
        error: ConsensusError,
    },

    /// Timeout tercapai sebelum consensus.
    TimedOut,
}

impl ConsensusState {
    /// Mengembalikan nama state sebagai string.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            ConsensusState::Proposed => "Proposed",
            ConsensusState::Voting { .. } => "Voting",
            ConsensusState::Signing { .. } => "Signing",
            ConsensusState::Completed { .. } => "Completed",
            ConsensusState::Failed { .. } => "Failed",
            ConsensusState::TimedOut => "TimedOut",
        }
    }

    /// Memeriksa apakah state adalah terminal.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self,
            ConsensusState::Completed { .. }
                | ConsensusState::Failed { .. }
                | ConsensusState::TimedOut
        )
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// STATE TRANSITION
// ════════════════════════════════════════════════════════════════════════════════

/// Hasil dari operasi `add_vote()`.
///
/// Enum ini menggambarkan apa yang terjadi setelah vote ditambahkan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateTransition {
    /// Tidak ada perubahan state (vote dicatat tapi threshold belum tercapai).
    NoChange {
        /// Jumlah approval saat ini.
        current_approvals: u8,
        /// Jumlah rejection saat ini.
        current_rejections: u8,
    },

    /// State berubah dari Proposed ke Voting.
    MovedToVoting {
        /// Jumlah approval setelah vote.
        approve_count: u8,
        /// Jumlah rejection setelah vote.
        reject_count: u8,
    },

    /// State berubah ke Signing (approval threshold tercapai).
    MovedToSigning {
        /// Session ID untuk signing.
        signing_session: SessionId,
        /// Jumlah approval votes.
        approve_count: u8,
    },

    /// State berubah ke Failed (rejection threshold tercapai).
    MovedToFailed {
        /// Error yang menyebabkan failure.
        error: ConsensusError,
    },

    /// Vote ditolak (tidak valid).
    RejectedVote {
        /// Alasan penolakan.
        reason: ConsensusError,
    },
}

// ════════════════════════════════════════════════════════════════════════════════
// RECEIPT CONSENSUS
// ════════════════════════════════════════════════════════════════════════════════

/// State machine untuk consensus satu receipt.
///
/// `ReceiptConsensus` melacak lifecycle consensus secara eksplisit:
/// - Tidak menyembunyikan state
/// - Tidak melakukan IO
/// - Tidak bergantung network
/// - Tidak spawn task
/// - Murni state transition + validation
///
/// # Thread Safety
///
/// Struct ini TIDAK thread-safe secara internal.
/// Semua mutasi melalui `&mut self`.
/// Jika perlu thread-safety, bungkus dengan `Arc<Mutex<_>>`.
///
/// # Invariants
///
/// - `threshold > 0` (jika tidak, state langsung Failed)
/// - `timeout_at = created_at + timeout_ms`
/// - Duplicate voter ditolak
/// - Terminal state tidak dapat berubah
pub struct ReceiptConsensus {
    /// Workload ID yang terkait.
    workload_id: WorkloadId,

    /// Data receipt yang diusulkan.
    proposed_data: ReceiptData,

    /// Coordinator yang mengusulkan.
    proposer: CoordinatorId,

    /// Map votes dari setiap coordinator.
    votes: HashMap<CoordinatorId, Vote>,

    /// State saat ini.
    state: ConsensusState,

    /// Threshold approval yang dibutuhkan.
    threshold: u8,

    /// Timestamp saat consensus dibuat (milliseconds).
    created_at: u64,

    /// Timestamp timeout (milliseconds).
    timeout_at: u64,
}

impl ReceiptConsensus {
    // ════════════════════════════════════════════════════════════════════════════
    // CONSTRUCTOR
    // ════════════════════════════════════════════════════════════════════════════

    /// Membuat `ReceiptConsensus` baru.
    ///
    /// # Arguments
    ///
    /// * `workload_id` - Identifier workload
    /// * `data` - Receipt data yang diusulkan
    /// * `proposer` - CoordinatorId yang mengusulkan
    /// * `threshold` - Jumlah approval yang dibutuhkan (HARUS > 0)
    /// * `timeout_ms` - Timeout dalam milliseconds
    /// * `now_ms` - Timestamp saat ini dalam milliseconds
    ///
    /// # State
    ///
    /// - Jika `threshold == 0`: state = `Failed { InvalidThreshold }`
    /// - Jika `threshold > 0`: state = `Proposed`
    ///
    /// # Note
    ///
    /// `timeout_at` dihitung sebagai `now_ms + timeout_ms` dengan saturating add.
    #[must_use]
    pub fn new(
        workload_id: WorkloadId,
        data: ReceiptData,
        proposer: CoordinatorId,
        threshold: u8,
        timeout_ms: u64,
        now_ms: u64,
    ) -> Self {
        let timeout_at = now_ms.saturating_add(timeout_ms);

        let state = if threshold == 0 {
            ConsensusState::Failed {
                error: ConsensusError::InvalidThreshold,
            }
        } else {
            ConsensusState::Proposed
        };

        Self {
            workload_id,
            proposed_data: data,
            proposer,
            votes: HashMap::new(),
            state,
            threshold,
            created_at: now_ms,
            timeout_at,
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // GETTERS
    // ════════════════════════════════════════════════════════════════════════════

    /// Mengembalikan reference ke workload ID.
    #[must_use]
    #[inline]
    pub const fn workload_id(&self) -> &WorkloadId {
        &self.workload_id
    }

    /// Mengembalikan reference ke proposed data.
    #[must_use]
    #[inline]
    pub const fn proposed_data(&self) -> &ReceiptData {
        &self.proposed_data
    }

    /// Mengembalikan reference ke proposer.
    #[must_use]
    #[inline]
    pub const fn proposer(&self) -> &CoordinatorId {
        &self.proposer
    }

    /// Mengembalikan reference ke current state.
    #[must_use]
    #[inline]
    pub const fn state(&self) -> &ConsensusState {
        &self.state
    }

    /// Mengembalikan threshold.
    #[must_use]
    #[inline]
    pub const fn threshold(&self) -> u8 {
        self.threshold
    }

    /// Mengembalikan created_at timestamp.
    #[must_use]
    #[inline]
    pub const fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Mengembalikan timeout_at timestamp.
    #[must_use]
    #[inline]
    pub const fn timeout_at(&self) -> u64 {
        self.timeout_at
    }

    /// Mengembalikan jumlah votes yang sudah diterima.
    #[must_use]
    #[inline]
    pub fn vote_count(&self) -> usize {
        self.votes.len()
    }

    /// Mengembalikan reference ke votes map.
    #[must_use]
    #[inline]
    pub const fn votes(&self) -> &HashMap<CoordinatorId, Vote> {
        &self.votes
    }

    // ════════════════════════════════════════════════════════════════════════════
    // STATE QUERIES
    // ════════════════════════════════════════════════════════════════════════════

    /// Memeriksa apakah state adalah terminal.
    ///
    /// Terminal states: `Completed`, `Failed`, `TimedOut`
    #[must_use]
    #[inline]
    pub const fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }

    /// Memeriksa apakah threshold approval sudah tercapai.
    ///
    /// HANYA true jika:
    /// - State adalah `Voting` atau `Signing` atau `Completed`
    /// - `approve_count >= threshold`
    #[must_use]
    pub fn should_proceed_to_signing(&self) -> bool {
        match &self.state {
            ConsensusState::Voting { approve_count, .. } => *approve_count >= self.threshold,
            ConsensusState::Signing { .. } | ConsensusState::Completed { .. } => true,
            _ => false,
        }
    }

    /// Mendapatkan receipt jika consensus completed.
    ///
    /// # Returns
    ///
    /// - `Some(&ThresholdReceipt)` jika state adalah `Completed`
    /// - `None` untuk state lainnya
    #[must_use]
    pub fn get_result(&self) -> Option<&ThresholdReceipt> {
        match &self.state {
            ConsensusState::Completed { receipt } => Some(receipt),
            _ => None,
        }
    }

    /// Menghitung jumlah approval votes saat ini.
    #[must_use]
    pub fn current_approve_count(&self) -> u8 {
        self.votes
            .values()
            .filter(|v| v.approve)
            .count()
            .min(255) as u8
    }

    /// Menghitung jumlah rejection votes saat ini.
    #[must_use]
    pub fn current_reject_count(&self) -> u8 {
        self.votes
            .values()
            .filter(|v| !v.approve)
            .count()
            .min(255) as u8
    }

    // ════════════════════════════════════════════════════════════════════════════
    // STATE TRANSITIONS
    // ════════════════════════════════════════════════════════════════════════════

    /// Menambahkan vote dari coordinator.
    ///
    /// # Arguments
    ///
    /// * `from` - CoordinatorId yang memberikan vote
    /// * `vote` - Vote yang diberikan
    /// * `now_ms` - Timestamp saat ini untuk timeout check
    ///
    /// # Returns
    ///
    /// `StateTransition` yang menggambarkan hasil operasi.
    ///
    /// # State Transitions
    ///
    /// - `Proposed` + vote → `Voting`
    /// - `Voting` + approve >= threshold → `Signing`
    /// - `Voting` + reject >= threshold → `Failed`
    /// - Terminal state → `RejectedVote`
    /// - Duplicate voter → `RejectedVote`
    ///
    /// # Timeout
    ///
    /// Jika `now_ms >= timeout_at` dan state bukan terminal,
    /// state akan berubah ke `TimedOut` dan vote ditolak.
    pub fn add_vote(
        &mut self,
        from: CoordinatorId,
        vote: Vote,
        now_ms: u64,
    ) -> StateTransition {
        // Check timeout first
        if now_ms >= self.timeout_at && !self.state.is_terminal() {
            self.state = ConsensusState::TimedOut;
            return StateTransition::RejectedVote {
                reason: ConsensusError::Timeout {
                    timeout_at: self.timeout_at,
                    detected_at: now_ms,
                },
            };
        }

        // Reject if terminal state
        if self.state.is_terminal() {
            return StateTransition::RejectedVote {
                reason: ConsensusError::InvalidStateTransition {
                    from: self.state.name().to_string(),
                    to: "Voting".to_string(),
                },
            };
        }

        // Reject if not in Proposed or Voting state
        if !matches!(
            self.state,
            ConsensusState::Proposed | ConsensusState::Voting { .. }
        ) {
            return StateTransition::RejectedVote {
                reason: ConsensusError::InvalidStateTransition {
                    from: self.state.name().to_string(),
                    to: "Voting".to_string(),
                },
            };
        }

        // Reject duplicate voter
        if self.votes.contains_key(&from) {
            return StateTransition::RejectedVote {
                reason: ConsensusError::DuplicateVote { voter: from },
            };
        }

        // Record the vote
        self.votes.insert(from, vote);

        // Calculate counts
        let approve_count = self.current_approve_count();
        let reject_count = self.current_reject_count();

        // Check rejection threshold first
        if reject_count >= self.threshold {
            let error = ConsensusError::Rejected {
                reject_count,
                threshold: self.threshold,
            };
            self.state = ConsensusState::Failed {
                error: error.clone(),
            };
            return StateTransition::MovedToFailed { error };
        }

        // Check approval threshold
        if approve_count >= self.threshold {
            let signing_session = SessionId::generate();
            self.state = ConsensusState::Signing {
                signing_session: signing_session.clone(),
            };
            return StateTransition::MovedToSigning {
                signing_session,
                approve_count,
            };
        }

        // Update state based on current state
        match &self.state {
            ConsensusState::Proposed => {
                self.state = ConsensusState::Voting {
                    approve_count,
                    reject_count,
                };
                StateTransition::MovedToVoting {
                    approve_count,
                    reject_count,
                }
            }
            ConsensusState::Voting { .. } => {
                self.state = ConsensusState::Voting {
                    approve_count,
                    reject_count,
                };
                StateTransition::NoChange {
                    current_approvals: approve_count,
                    current_rejections: reject_count,
                }
            }
            _ => {
                // Should never reach here due to earlier checks
                StateTransition::RejectedVote {
                    reason: ConsensusError::InternalInvariantViolation {
                        description: "unexpected state in add_vote".to_string(),
                    },
                }
            }
        }
    }

    /// Memeriksa dan menerapkan timeout jika tercapai.
    ///
    /// # Arguments
    ///
    /// * `now_ms` - Timestamp saat ini dalam milliseconds
    ///
    /// # Returns
    ///
    /// - `true` jika timeout diterapkan (state berubah ke `TimedOut`)
    /// - `false` jika tidak ada perubahan
    ///
    /// # Note
    ///
    /// Method ini HARUS dipanggil secara eksplisit untuk mengecek timeout.
    /// Tidak ada auto-trigger.
    pub fn check_timeout(&mut self, now_ms: u64) -> bool {
        if now_ms >= self.timeout_at && !self.state.is_terminal() {
            self.state = ConsensusState::TimedOut;
            true
        } else {
            false
        }
    }

    /// Transisi ke state Signing secara eksplisit.
    ///
    /// # Arguments
    ///
    /// * `signing_session` - Session ID untuk signing
    ///
    /// # Returns
    ///
    /// - `Ok(())` jika transisi berhasil
    /// - `Err(ConsensusError)` jika transisi tidak valid
    ///
    /// # Requirements
    ///
    /// - State harus `Voting` dengan `approve_count >= threshold`
    pub fn transition_to_signing(
        &mut self,
        signing_session: SessionId,
    ) -> Result<(), ConsensusError> {
        match &self.state {
            ConsensusState::Voting { approve_count, .. } => {
                if *approve_count < self.threshold {
                    return Err(ConsensusError::ThresholdNotMet {
                        required: self.threshold,
                        got: *approve_count,
                    });
                }
                self.state = ConsensusState::Signing { signing_session };
                Ok(())
            }
            _ => Err(ConsensusError::InvalidStateTransition {
                from: self.state.name().to_string(),
                to: "Signing".to_string(),
            }),
        }
    }

    /// Transisi ke state Completed dengan receipt.
    ///
    /// # Arguments
    ///
    /// * `receipt` - ThresholdReceipt yang sudah di-sign
    ///
    /// # Returns
    ///
    /// - `Ok(())` jika transisi berhasil
    /// - `Err(ConsensusError)` jika transisi tidak valid
    ///
    /// # Requirements
    ///
    /// - State harus `Signing`
    pub fn transition_to_completed(
        &mut self,
        receipt: ThresholdReceipt,
    ) -> Result<(), ConsensusError> {
        match &self.state {
            ConsensusState::Signing { .. } => {
                self.state = ConsensusState::Completed { receipt };
                Ok(())
            }
            _ => Err(ConsensusError::InvalidStateTransition {
                from: self.state.name().to_string(),
                to: "Completed".to_string(),
            }),
        }
    }

    /// Transisi ke state Failed secara eksplisit.
    ///
    /// # Arguments
    ///
    /// * `error` - Error yang menyebabkan failure
    ///
    /// # Returns
    ///
    /// - `Ok(())` jika transisi berhasil
    /// - `Err(ConsensusError)` jika state sudah terminal
    pub fn transition_to_failed(&mut self, error: ConsensusError) -> Result<(), ConsensusError> {
        if self.state.is_terminal() {
            return Err(ConsensusError::InvalidStateTransition {
                from: self.state.name().to_string(),
                to: "Failed".to_string(),
            });
        }
        self.state = ConsensusState::Failed { error };
        Ok(())
    }
}

impl fmt::Debug for ReceiptConsensus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceiptConsensus")
            .field("workload_id", &self.workload_id)
            .field("proposer", &self.proposer)
            .field("state", &self.state)
            .field("threshold", &self.threshold)
            .field("vote_count", &self.votes.len())
            .field("created_at", &self.created_at)
            .field("timeout_at", &self.timeout_at)
            .finish()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use dsdn_common::coordinator::WorkloadId as CommonWorkloadId;
    use dsdn_common::coordinator::CoordinatorId as CommonCoordinatorId;

    fn make_workload_id(seed: u8) -> WorkloadId {
        WorkloadId::new([seed; 32])
    }

    fn make_coord_id(seed: u8) -> CoordinatorId {
        CoordinatorId::new([seed; 32])
    }

    /// Helper untuk membuat dsdn_common::CoordinatorId (untuk ThresholdReceipt)
    fn make_common_coord_id(seed: u8) -> CommonCoordinatorId {
        CommonCoordinatorId::new([seed; 32])
    }

    fn make_vote(approve: bool) -> Vote {
        Vote::new(approve, 1700000000, [0xAA; 64])
    }

    fn make_receipt_data() -> ReceiptData {
        ReceiptData::new(
            CommonWorkloadId::new([0x01; 32]),
            [0x02; 32],
            vec![],
            1700000000,
            1,
            1,
        )
    }

    fn make_consensus() -> ReceiptConsensus {
        ReceiptConsensus::new(
            make_workload_id(0x01),
            make_receipt_data(),
            make_coord_id(0x00),
            2, // threshold
            30000, // timeout_ms
            1700000000, // now_ms
        )
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // ConsensusError Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_consensus_error_display() {
        let err = ConsensusError::DuplicateVote {
            voter: make_coord_id(0x01),
        };
        let display = err.to_string();
        assert!(display.contains("duplicate"));
    }

    #[test]
    fn test_consensus_error_clone() {
        let err1 = ConsensusError::InvalidThreshold;
        let err2 = err1.clone();
        assert_eq!(err1, err2);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // ConsensusState Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_consensus_state_name() {
        assert_eq!(ConsensusState::Proposed.name(), "Proposed");
        assert_eq!(
            ConsensusState::Voting {
                approve_count: 1,
                reject_count: 0
            }
            .name(),
            "Voting"
        );
        assert_eq!(ConsensusState::TimedOut.name(), "TimedOut");
    }

    #[test]
    fn test_consensus_state_is_terminal() {
        assert!(!ConsensusState::Proposed.is_terminal());
        assert!(!ConsensusState::Voting {
            approve_count: 1,
            reject_count: 0
        }
        .is_terminal());
        assert!(!ConsensusState::Signing {
            signing_session: SessionId::new([0x01; 32])
        }
        .is_terminal());
        assert!(ConsensusState::TimedOut.is_terminal());
        assert!(ConsensusState::Failed {
            error: ConsensusError::InvalidThreshold
        }
        .is_terminal());
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // ReceiptConsensus Constructor Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_new_valid_threshold() {
        let consensus = make_consensus();

        assert_eq!(consensus.threshold(), 2);
        assert_eq!(consensus.created_at(), 1700000000);
        assert_eq!(consensus.timeout_at(), 1700030000);
        assert!(!consensus.is_terminal());
        assert_eq!(consensus.state().name(), "Proposed");
    }

    #[test]
    fn test_new_zero_threshold_fails() {
        let consensus = ReceiptConsensus::new(
            make_workload_id(0x01),
            make_receipt_data(),
            make_coord_id(0x00),
            0, // invalid threshold
            30000,
            1700000000,
        );

        assert!(consensus.is_terminal());
        assert_eq!(consensus.state().name(), "Failed");
        match consensus.state() {
            ConsensusState::Failed { error } => {
                assert_eq!(*error, ConsensusError::InvalidThreshold);
            }
            _ => panic!("expected Failed state"),
        }
    }

    #[test]
    fn test_new_timeout_overflow() {
        let consensus = ReceiptConsensus::new(
            make_workload_id(0x01),
            make_receipt_data(),
            make_coord_id(0x00),
            2,
            u64::MAX, // would overflow
            u64::MAX - 100,
        );

        // Should saturate to u64::MAX
        assert_eq!(consensus.timeout_at(), u64::MAX);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // add_vote Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_add_vote_first_vote_moves_to_voting() {
        let mut consensus = make_consensus();

        let transition = consensus.add_vote(
            make_coord_id(0x01),
            make_vote(true),
            1700000000,
        );

        assert!(matches!(
            transition,
            StateTransition::MovedToVoting {
                approve_count: 1,
                reject_count: 0
            }
        ));
        assert_eq!(consensus.state().name(), "Voting");
    }

    #[test]
    fn test_add_vote_duplicate_rejected() {
        let mut consensus = make_consensus();
        let voter = make_coord_id(0x01);

        consensus.add_vote(voter.clone(), make_vote(true), 1700000000);
        let transition = consensus.add_vote(voter.clone(), make_vote(true), 1700000001);

        assert!(matches!(
            transition,
            StateTransition::RejectedVote {
                reason: ConsensusError::DuplicateVote { .. }
            }
        ));
    }

    #[test]
    fn test_add_vote_approval_threshold_reached() {
        let mut consensus = make_consensus();

        consensus.add_vote(make_coord_id(0x01), make_vote(true), 1700000000);
        let transition = consensus.add_vote(make_coord_id(0x02), make_vote(true), 1700000001);

        assert!(matches!(
            transition,
            StateTransition::MovedToSigning { approve_count: 2, .. }
        ));
        assert_eq!(consensus.state().name(), "Signing");
    }

    #[test]
    fn test_add_vote_rejection_threshold_reached() {
        let mut consensus = make_consensus();

        consensus.add_vote(make_coord_id(0x01), make_vote(false), 1700000000);
        let transition = consensus.add_vote(make_coord_id(0x02), make_vote(false), 1700000001);

        assert!(matches!(
            transition,
            StateTransition::MovedToFailed {
                error: ConsensusError::Rejected { .. }
            }
        ));
        assert_eq!(consensus.state().name(), "Failed");
    }

    #[test]
    fn test_add_vote_no_change_below_threshold() {
        let mut consensus = ReceiptConsensus::new(
            make_workload_id(0x01),
            make_receipt_data(),
            make_coord_id(0x00),
            3, // higher threshold
            30000,
            1700000000,
        );

        consensus.add_vote(make_coord_id(0x01), make_vote(true), 1700000000);
        let transition = consensus.add_vote(make_coord_id(0x02), make_vote(true), 1700000001);

        assert!(matches!(
            transition,
            StateTransition::NoChange {
                current_approvals: 2,
                current_rejections: 0
            }
        ));
    }

    #[test]
    fn test_add_vote_rejected_on_terminal_state() {
        let mut consensus = make_consensus();

        // Force to terminal
        consensus.add_vote(make_coord_id(0x01), make_vote(false), 1700000000);
        consensus.add_vote(make_coord_id(0x02), make_vote(false), 1700000001);

        // Try to add another vote
        let transition = consensus.add_vote(make_coord_id(0x03), make_vote(true), 1700000002);

        assert!(matches!(
            transition,
            StateTransition::RejectedVote {
                reason: ConsensusError::InvalidStateTransition { .. }
            }
        ));
    }

    #[test]
    fn test_add_vote_timeout() {
        let mut consensus = make_consensus();

        // Add vote after timeout
        let transition = consensus.add_vote(
            make_coord_id(0x01),
            make_vote(true),
            1700030001, // After timeout
        );

        assert!(matches!(
            transition,
            StateTransition::RejectedVote {
                reason: ConsensusError::Timeout { .. }
            }
        ));
        assert_eq!(consensus.state().name(), "TimedOut");
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // check_timeout Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_check_timeout_before_deadline() {
        let mut consensus = make_consensus();

        let timed_out = consensus.check_timeout(1700000000);
        assert!(!timed_out);
        assert_eq!(consensus.state().name(), "Proposed");
    }

    #[test]
    fn test_check_timeout_at_deadline() {
        let mut consensus = make_consensus();

        let timed_out = consensus.check_timeout(1700030000);
        assert!(timed_out);
        assert_eq!(consensus.state().name(), "TimedOut");
    }

    #[test]
    fn test_check_timeout_after_deadline() {
        let mut consensus = make_consensus();

        let timed_out = consensus.check_timeout(1700030001);
        assert!(timed_out);
        assert_eq!(consensus.state().name(), "TimedOut");
    }

    #[test]
    fn test_check_timeout_idempotent_on_terminal() {
        let mut consensus = make_consensus();

        consensus.check_timeout(1700030001);
        let timed_out_again = consensus.check_timeout(1700030002);

        assert!(!timed_out_again); // Already terminal
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // should_proceed_to_signing Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_should_proceed_to_signing_false_initially() {
        let consensus = make_consensus();
        assert!(!consensus.should_proceed_to_signing());
    }

    #[test]
    fn test_should_proceed_to_signing_false_below_threshold() {
        let mut consensus = make_consensus();
        consensus.add_vote(make_coord_id(0x01), make_vote(true), 1700000000);
        assert!(!consensus.should_proceed_to_signing());
    }

    #[test]
    fn test_should_proceed_to_signing_true_at_threshold() {
        let mut consensus = make_consensus();
        consensus.add_vote(make_coord_id(0x01), make_vote(true), 1700000000);
        consensus.add_vote(make_coord_id(0x02), make_vote(true), 1700000001);
        assert!(consensus.should_proceed_to_signing());
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // get_result Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_get_result_none_initially() {
        let consensus = make_consensus();
        assert!(consensus.get_result().is_none());
    }

    #[test]
    fn test_get_result_none_in_signing() {
        let mut consensus = make_consensus();
        consensus.add_vote(make_coord_id(0x01), make_vote(true), 1700000000);
        consensus.add_vote(make_coord_id(0x02), make_vote(true), 1700000001);
        assert!(consensus.get_result().is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // transition_to_* Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_transition_to_signing_success() {
        let mut consensus = make_consensus();
        consensus.add_vote(make_coord_id(0x01), make_vote(true), 1700000000);
        consensus.add_vote(make_coord_id(0x02), make_vote(true), 1700000001);

        // Note: add_vote already transitioned to Signing
        // This test verifies the transition happened
        assert_eq!(consensus.state().name(), "Signing");
    }

    #[test]
    fn test_transition_to_signing_threshold_not_met() {
        let mut consensus = make_consensus();
        consensus.add_vote(make_coord_id(0x01), make_vote(true), 1700000000);

        // Manually try to transition (should fail since we're still at Voting with 1 approval)
        let result = consensus.transition_to_signing(SessionId::generate());
        assert!(result.is_err());
    }

    #[test]
    fn test_transition_to_completed() {
        use dsdn_tss::AggregateSignature;

        let mut consensus = make_consensus();
        consensus.add_vote(make_coord_id(0x01), make_vote(true), 1700000000);
        consensus.add_vote(make_coord_id(0x02), make_vote(true), 1700000001);

        // Now in Signing state
        // AggregateSignature needs 129 bytes for 1 signer
        let receipt = ThresholdReceipt::new(
            make_receipt_data(),
            AggregateSignature::from_bytes(&[0x01; 129]).expect("valid aggregate signature"),
            vec![make_common_coord_id(0x01), make_common_coord_id(0x02)],
            [0xFF; 32],
        );

        let result = consensus.transition_to_completed(receipt);
        assert!(result.is_ok());
        assert_eq!(consensus.state().name(), "Completed");
        assert!(consensus.get_result().is_some());
    }

    #[test]
    fn test_transition_to_completed_from_wrong_state() {
        use dsdn_tss::AggregateSignature;

        let mut consensus = make_consensus();

        // AggregateSignature needs 129 bytes for 1 signer
        let receipt = ThresholdReceipt::new(
            make_receipt_data(),
            AggregateSignature::from_bytes(&[0x01; 129]).expect("valid aggregate signature"),
            vec![],
            [0xFF; 32],
        );

        let result = consensus.transition_to_completed(receipt);
        assert!(result.is_err());
    }

    #[test]
    fn test_transition_to_failed() {
        let mut consensus = make_consensus();

        let result = consensus.transition_to_failed(ConsensusError::InternalInvariantViolation {
            description: "test".to_string(),
        });

        assert!(result.is_ok());
        assert_eq!(consensus.state().name(), "Failed");
    }

    #[test]
    fn test_transition_to_failed_from_terminal() {
        let mut consensus = make_consensus();
        consensus.check_timeout(1700030001); // Move to TimedOut

        let result = consensus.transition_to_failed(ConsensusError::InvalidThreshold);
        assert!(result.is_err());
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Mixed voting Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_mixed_votes_approval_wins() {
        let mut consensus = ReceiptConsensus::new(
            make_workload_id(0x01),
            make_receipt_data(),
            make_coord_id(0x00),
            2,
            30000,
            1700000000,
        );

        consensus.add_vote(make_coord_id(0x01), make_vote(true), 1700000000);
        consensus.add_vote(make_coord_id(0x02), make_vote(false), 1700000001);
        let transition = consensus.add_vote(make_coord_id(0x03), make_vote(true), 1700000002);

        assert!(matches!(transition, StateTransition::MovedToSigning { .. }));
    }

    #[test]
    fn test_mixed_votes_rejection_wins() {
        let mut consensus = ReceiptConsensus::new(
            make_workload_id(0x01),
            make_receipt_data(),
            make_coord_id(0x00),
            2,
            30000,
            1700000000,
        );

        consensus.add_vote(make_coord_id(0x01), make_vote(false), 1700000000);
        consensus.add_vote(make_coord_id(0x02), make_vote(true), 1700000001);
        let transition = consensus.add_vote(make_coord_id(0x03), make_vote(false), 1700000002);

        assert!(matches!(transition, StateTransition::MovedToFailed { .. }));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Debug and Clone Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_consensus_debug() {
        let consensus = make_consensus();
        let debug = format!("{:?}", consensus);
        assert!(debug.contains("ReceiptConsensus"));
        assert!(debug.contains("threshold"));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Getters Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_getters() {
        let consensus = make_consensus();

        assert_eq!(*consensus.workload_id(), make_workload_id(0x01));
        assert_eq!(*consensus.proposer(), make_coord_id(0x00));
        assert_eq!(consensus.threshold(), 2);
        assert_eq!(consensus.created_at(), 1700000000);
        assert_eq!(consensus.timeout_at(), 1700030000);
        assert_eq!(consensus.vote_count(), 0);
        assert!(consensus.votes().is_empty());
    }

    #[test]
    fn test_current_counts() {
        let mut consensus = make_consensus();

        assert_eq!(consensus.current_approve_count(), 0);
        assert_eq!(consensus.current_reject_count(), 0);

        consensus.add_vote(make_coord_id(0x01), make_vote(true), 1700000000);
        assert_eq!(consensus.current_approve_count(), 1);
        assert_eq!(consensus.current_reject_count(), 0);

        consensus.add_vote(make_coord_id(0x02), make_vote(false), 1700000001);
        assert_eq!(consensus.current_approve_count(), 1);
        assert_eq!(consensus.current_reject_count(), 1);
    }
}