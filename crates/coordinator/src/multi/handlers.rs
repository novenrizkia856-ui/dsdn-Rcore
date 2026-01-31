//! Receipt Proposal & Voting Handlers (14A.2B.2.17)
//!
//! Module ini menyediakan handler eksplisit untuk:
//! - ProposeReceipt
//! - VoteReceipt
//!
//! Handlers ini adalah SATU-SATUNYA pintu masuk message → state mutation.
//!
//! # Invariants
//!
//! - Satu workload_id → maksimal satu ReceiptConsensus
//! - Tidak ada implicit consensus creation
//! - Tidak ada implicit vote
//! - Semua vote lewat add_vote
//! - Tidak ada mutation tanpa validasi
//! - Handler TIDAK melakukan signing langsung
//! - Handler hanya MEMICU transisi, bukan menyelesaikan
//!
//! # Usage
//!
//! ```ignore
//! use dsdn_coordinator::multi::{
//!     MultiCoordinatorState, handle_propose_receipt, handle_vote_receipt,
//! };
//!
//! // Create state
//! let mut state = MultiCoordinatorState::new(
//!     self_id, committee_members, threshold, timeout_ms,
//! );
//!
//! // Handle proposal
//! let response = handle_propose_receipt(&mut state, msg, from, now_ms)?;
//!
//! // Handle vote
//! let response = handle_vote_receipt(&mut state, msg, from, now_ms)?;
//! ```

use std::collections::{HashMap, HashSet};
use std::fmt;

use dsdn_common::coordinator::ReceiptData;

use super::{
    AddVoteResult, CoordinatorId, CoordinatorMessage, ConsensusState,
    MessageVote, ReceiptConsensus, SessionId, Vote, WorkloadId,
};

// ════════════════════════════════════════════════════════════════════════════════
// VALIDATION ERROR
// ════════════════════════════════════════════════════════════════════════════════

/// Error type untuk validation failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// Workload ID tidak valid (zero bytes).
    InvalidWorkloadId,

    /// Blob hash tidak valid (zero bytes).
    InvalidBlobHash,

    /// Epoch tidak valid (zero).
    InvalidEpoch,

    /// Timestamp tidak valid.
    InvalidTimestamp,

    /// Placement kosong tapi seharusnya ada.
    EmptyPlacement,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::InvalidWorkloadId => {
                write!(f, "invalid workload_id: all zero bytes")
            }
            ValidationError::InvalidBlobHash => {
                write!(f, "invalid blob_hash: all zero bytes")
            }
            ValidationError::InvalidEpoch => {
                write!(f, "invalid epoch: must be > 0")
            }
            ValidationError::InvalidTimestamp => {
                write!(f, "invalid timestamp")
            }
            ValidationError::EmptyPlacement => {
                write!(f, "empty placement")
            }
        }
    }
}

impl std::error::Error for ValidationError {}

// ════════════════════════════════════════════════════════════════════════════════
// HANDLER ERROR
// ════════════════════════════════════════════════════════════════════════════════

/// Error type untuk handler failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandlerError {
    /// Proposal sudah ada untuk workload_id ini.
    DuplicateProposal {
        /// Workload ID yang sudah ada.
        workload_id: WorkloadId,
    },

    /// Consensus tidak ditemukan.
    ConsensusNotFound {
        /// Workload ID yang dicari.
        workload_id: WorkloadId,
    },

    /// Proposal tidak valid.
    InvalidProposal {
        /// Validation error.
        validation: ValidationError,
    },

    /// Voter bukan anggota committee.
    InvalidVoter {
        /// CoordinatorId yang tidak valid.
        voter: CoordinatorId,
    },

    /// Vote duplikat dari voter yang sama.
    DuplicateVote {
        /// CoordinatorId yang duplikat.
        voter: CoordinatorId,
    },

    /// State tidak valid untuk operasi.
    InvalidState {
        /// State saat ini.
        current_state: String,
        /// Operasi yang dicoba.
        operation: String,
    },

    /// Consensus sudah terminal.
    ConsensusTerminal {
        /// Workload ID.
        workload_id: WorkloadId,
        /// State terminal.
        state: String,
    },

    /// Session ID mismatch.
    SessionMismatch {
        /// Expected session ID.
        expected: SessionId,
        /// Received session ID.
        received: SessionId,
    },
}

impl fmt::Display for HandlerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandlerError::DuplicateProposal { workload_id } => {
                write!(
                    f,
                    "duplicate proposal for workload {:?}",
                    workload_id.as_bytes()
                )
            }
            HandlerError::ConsensusNotFound { workload_id } => {
                write!(
                    f,
                    "consensus not found for workload {:?}",
                    workload_id.as_bytes()
                )
            }
            HandlerError::InvalidProposal { validation } => {
                write!(f, "invalid proposal: {}", validation)
            }
            HandlerError::InvalidVoter { voter } => {
                write!(f, "invalid voter: {:?}", voter.as_bytes())
            }
            HandlerError::DuplicateVote { voter } => {
                write!(f, "duplicate vote from {:?}", voter.as_bytes())
            }
            HandlerError::InvalidState {
                current_state,
                operation,
            } => {
                write!(
                    f,
                    "invalid state {} for operation {}",
                    current_state, operation
                )
            }
            HandlerError::ConsensusTerminal { workload_id, state } => {
                write!(
                    f,
                    "consensus for {:?} is terminal: {}",
                    workload_id.as_bytes(),
                    state
                )
            }
            HandlerError::SessionMismatch { expected, received } => {
                write!(
                    f,
                    "session mismatch: expected {:?}, received {:?}",
                    expected.as_bytes(),
                    received.as_bytes()
                )
            }
        }
    }
}

impl std::error::Error for HandlerError {}

impl From<ValidationError> for HandlerError {
    fn from(err: ValidationError) -> Self {
        HandlerError::InvalidProposal { validation: err }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// MULTI COORDINATOR STATE
// ════════════════════════════════════════════════════════════════════════════════

/// State untuk multi-coordinator consensus.
///
/// Struct ini menyimpan semua state yang diperlukan untuk:
/// - Tracking consensus per workload
/// - Validasi committee membership
/// - Konfigurasi threshold dan timeout
///
/// # Thread Safety
///
/// Struct ini TIDAK thread-safe secara internal.
/// Semua mutasi melalui `&mut self`.
/// Jika perlu thread-safety, bungkus dengan `Arc<Mutex<_>>`.
///
/// # Invariants
///
/// - Satu workload_id → maksimal satu ReceiptConsensus
/// - committee_members tidak boleh kosong
/// - threshold > 0 dan <= committee_members.len()
pub struct MultiCoordinatorState {
    /// ID coordinator ini.
    self_id: CoordinatorId,

    /// Map dari WorkloadId ke ReceiptConsensus.
    consensus_map: HashMap<WorkloadId, ReceiptConsensus>,

    /// Map dari WorkloadId ke SessionId untuk tracking.
    session_map: HashMap<WorkloadId, SessionId>,

    /// Committee members untuk validasi voter.
    committee_members: HashSet<CoordinatorId>,

    /// Threshold untuk consensus.
    threshold: u8,

    /// Timeout untuk consensus (milliseconds).
    consensus_timeout_ms: u64,
}

impl MultiCoordinatorState {
    /// Membuat MultiCoordinatorState baru.
    ///
    /// # Arguments
    ///
    /// * `self_id` - ID coordinator ini
    /// * `committee_members` - Set of committee member IDs
    /// * `threshold` - Threshold untuk consensus
    /// * `consensus_timeout_ms` - Timeout dalam milliseconds
    ///
    /// # Panics
    ///
    /// Tidak panic. Jika committee_members kosong atau threshold invalid,
    /// consensus akan langsung Failed saat dibuat.
    #[must_use]
    pub fn new(
        self_id: CoordinatorId,
        committee_members: HashSet<CoordinatorId>,
        threshold: u8,
        consensus_timeout_ms: u64,
    ) -> Self {
        Self {
            self_id,
            consensus_map: HashMap::new(),
            session_map: HashMap::new(),
            committee_members,
            threshold,
            consensus_timeout_ms,
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // GETTERS
    // ────────────────────────────────────────────────────────────────────────────

    /// Mengembalikan self_id.
    #[must_use]
    #[inline]
    pub const fn self_id(&self) -> &CoordinatorId {
        &self.self_id
    }

    /// Mengembalikan threshold.
    #[must_use]
    #[inline]
    pub const fn threshold(&self) -> u8 {
        self.threshold
    }

    /// Mengembalikan consensus_timeout_ms.
    #[must_use]
    #[inline]
    pub const fn consensus_timeout_ms(&self) -> u64 {
        self.consensus_timeout_ms
    }

    /// Memeriksa apakah coordinator adalah anggota committee.
    #[must_use]
    pub fn is_committee_member(&self, id: &CoordinatorId) -> bool {
        self.committee_members.contains(id)
    }

    /// Mengembalikan jumlah committee members.
    #[must_use]
    pub fn committee_size(&self) -> usize {
        self.committee_members.len()
    }

    /// Mendapatkan consensus untuk workload_id.
    #[must_use]
    pub fn get_consensus(&self, workload_id: &WorkloadId) -> Option<&ReceiptConsensus> {
        self.consensus_map.get(workload_id)
    }

    /// Mendapatkan mutable consensus untuk workload_id.
    #[must_use]
    pub fn get_consensus_mut(&mut self, workload_id: &WorkloadId) -> Option<&mut ReceiptConsensus> {
        self.consensus_map.get_mut(workload_id)
    }

    /// Memeriksa apakah consensus sudah ada untuk workload_id.
    #[must_use]
    pub fn has_consensus(&self, workload_id: &WorkloadId) -> bool {
        self.consensus_map.contains_key(workload_id)
    }

    /// Mendapatkan session_id untuk workload_id.
    #[must_use]
    pub fn get_session(&self, workload_id: &WorkloadId) -> Option<&SessionId> {
        self.session_map.get(workload_id)
    }

    /// Mengembalikan jumlah consensus yang sedang aktif.
    #[must_use]
    pub fn consensus_count(&self) -> usize {
        self.consensus_map.len()
    }

    // ────────────────────────────────────────────────────────────────────────────
    // INTERNAL MUTATIONS
    // ────────────────────────────────────────────────────────────────────────────

    /// Menambahkan consensus baru.
    ///
    /// # Note
    ///
    /// Internal method - gunakan handler functions untuk public API.
    fn insert_consensus(
        &mut self,
        workload_id: WorkloadId,
        session_id: SessionId,
        consensus: ReceiptConsensus,
    ) {
        self.consensus_map.insert(workload_id.clone(), consensus);
        self.session_map.insert(workload_id, session_id);
    }
}

impl fmt::Debug for MultiCoordinatorState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MultiCoordinatorState")
            .field("self_id", &self.self_id)
            .field("consensus_count", &self.consensus_map.len())
            .field("committee_size", &self.committee_members.len())
            .field("threshold", &self.threshold)
            .field("consensus_timeout_ms", &self.consensus_timeout_ms)
            .finish()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// VALIDATION FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════════

/// Validasi receipt proposal data.
///
/// # Arguments
///
/// * `data` - ReceiptData yang akan divalidasi
///
/// # Returns
///
/// - `Ok(())` jika valid
/// - `Err(ValidationError)` jika tidak valid
///
/// # Rules
///
/// - workload_id tidak boleh all zeros
/// - blob_hash tidak boleh all zeros
/// - epoch harus > 0
///
/// # Note
///
/// Tidak bergantung pada external state.
pub fn validate_receipt_proposal(data: &ReceiptData) -> Result<(), ValidationError> {
    // Validate workload_id is not all zeros
    if data.workload_id().as_bytes().iter().all(|&b| b == 0) {
        return Err(ValidationError::InvalidWorkloadId);
    }

    // Validate blob_hash is not all zeros
    if data.blob_hash().iter().all(|&b| b == 0) {
        return Err(ValidationError::InvalidBlobHash);
    }

    // Validate epoch > 0
    if data.epoch() == 0 {
        return Err(ValidationError::InvalidEpoch);
    }

    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// VOTE RESPONSE CREATION
// ════════════════════════════════════════════════════════════════════════════════

/// Membuat vote response message.
///
/// # Arguments
///
/// * `session_id` - Session ID untuk vote
/// * `workload_id` - Workload ID yang di-vote
/// * `my_id` - CoordinatorId yang memberikan vote
/// * `approve` - true untuk approve, false untuk reject
/// * `reject_reason` - Alasan rejection (jika reject)
///
/// # Returns
///
/// `CoordinatorMessage::VoteReceipt` dengan vote yang sesuai.
///
/// # Note
///
/// Tidak ada side effect.
#[must_use]
pub fn create_vote_response(
    session_id: SessionId,
    workload_id: WorkloadId,
    my_id: CoordinatorId,
    approve: bool,
    reject_reason: Option<String>,
) -> CoordinatorMessage {
    let vote = if approve {
        MessageVote::approve()
    } else {
        MessageVote::reject(reject_reason.unwrap_or_else(|| "rejected".to_string()))
    };

    CoordinatorMessage::VoteReceipt {
        session_id,
        workload_id,
        vote,
        voter: my_id,
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// HANDLER FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════════

/// Handle ProposeReceipt message.
///
/// # Arguments
///
/// * `state` - Mutable reference ke MultiCoordinatorState
/// * `session_id` - Session ID dari proposal
/// * `data` - ReceiptData yang diusulkan
/// * `proposer` - CoordinatorId yang mengusulkan
/// * `now_ms` - Timestamp saat ini dalam milliseconds
///
/// # Returns
///
/// - `Ok(Some(CoordinatorMessage))` - VoteReceipt jika auto-vote berhasil
/// - `Ok(None)` - Jika tidak ada response
/// - `Err(HandlerError)` - Jika validasi gagal
///
/// # Rules
///
/// 1. Validasi proposal data
/// 2. Reject jika workload_id sudah ada consensus
/// 3. Validasi proposer adalah committee member
/// 4. Buat ReceiptConsensus baru
/// 5. Auto-vote approve dari node ini via add_vote
/// 6. Return VoteReceipt message
///
/// # State Mutation
///
/// - Membuat ReceiptConsensus baru di consensus_map
/// - Menambahkan vote via add_vote
pub fn handle_propose_receipt(
    state: &mut MultiCoordinatorState,
    session_id: SessionId,
    data: ReceiptData,
    proposer: CoordinatorId,
    now_ms: u64,
) -> Result<Option<CoordinatorMessage>, HandlerError> {
    // Extract workload_id from data
    let workload_id = WorkloadId::new(*data.workload_id().as_bytes());

    // 1. Validate proposal data BEFORE any state mutation
    validate_receipt_proposal(&data)?;

    // 2. Check if consensus already exists for this workload
    if state.has_consensus(&workload_id) {
        return Err(HandlerError::DuplicateProposal {
            workload_id: workload_id.clone(),
        });
    }

    // 3. Validate proposer is committee member
    if !state.is_committee_member(&proposer) {
        return Err(HandlerError::InvalidVoter { voter: proposer });
    }

    // 4. Create new ReceiptConsensus
    let consensus = ReceiptConsensus::new(
        workload_id.clone(),
        data,
        proposer,
        state.threshold,
        state.consensus_timeout_ms,
        now_ms,
    );

    // 5. Insert consensus into state
    state.insert_consensus(workload_id.clone(), session_id.clone(), consensus);

    // 6. Auto-vote approve from this node via add_vote
    // Clone self_id BEFORE getting mutable reference to avoid borrow conflict
    let self_id = state.self_id.clone();

    // Get mutable reference to consensus we just inserted
    let consensus = state
        .get_consensus_mut(&workload_id)
        .ok_or_else(|| HandlerError::ConsensusNotFound {
            workload_id: workload_id.clone(),
        })?;

    // Create vote
    let vote = Vote::new(true, now_ms, [0u8; 64]); // Signature placeholder

    // Add vote through proper channel
    let vote_result = consensus.add_vote(self_id.clone(), vote, now_ms);

    // Check if vote was accepted
    match vote_result {
        AddVoteResult::MovedToVoting { .. }
        | AddVoteResult::MovedToSigning { .. }
        | AddVoteResult::NoChange { .. } => {
            // Vote accepted, create response
            let response = create_vote_response(
                session_id,
                workload_id,
                self_id,
                true,
                None,
            );
            Ok(Some(response))
        }
        AddVoteResult::MovedToFailed { error } => {
            // Consensus failed, but we still created it
            // Return the error info but don't fail the handler
            Err(HandlerError::InvalidState {
                current_state: format!("{:?}", error),
                operation: "auto_vote".to_string(),
            })
        }
        AddVoteResult::RejectedVote { reason } => {
            // Vote was rejected - this shouldn't happen on first vote
            Err(HandlerError::InvalidState {
                current_state: format!("{:?}", reason),
                operation: "auto_vote".to_string(),
            })
        }
    }
}

/// Handle VoteReceipt message.
///
/// # Arguments
///
/// * `state` - Mutable reference ke MultiCoordinatorState
/// * `session_id` - Session ID dari vote
/// * `workload_id` - Workload ID yang di-vote
/// * `vote` - MessageVote (Approve/Reject)
/// * `voter` - CoordinatorId yang memberikan vote
/// * `now_ms` - Timestamp saat ini dalam milliseconds
///
/// # Returns
///
/// - `Ok(Some(CoordinatorMessage))` - SigningCommitment jika threshold tercapai
/// - `Ok(None)` - Jika belum threshold
/// - `Err(HandlerError)` - Jika validasi gagal
///
/// # Rules
///
/// 1. Consensus HARUS sudah ada
/// 2. Voter HARUS anggota committee
/// 3. Duplicate vote HARUS ditolak (handled by add_vote)
/// 4. add_vote HARUS dipanggil
/// 5. Jika threshold tercapai: Trigger transisi ke Signing
///
/// # State Mutation
///
/// - Menambahkan vote via add_vote
pub fn handle_vote_receipt(
    state: &mut MultiCoordinatorState,
    session_id: SessionId,
    workload_id: WorkloadId,
    vote: MessageVote,
    voter: CoordinatorId,
    now_ms: u64,
) -> Result<Option<CoordinatorMessage>, HandlerError> {
    // 1. Check if consensus exists
    if !state.has_consensus(&workload_id) {
        return Err(HandlerError::ConsensusNotFound {
            workload_id: workload_id.clone(),
        });
    }

    // 2. Validate voter is committee member
    if !state.is_committee_member(&voter) {
        return Err(HandlerError::InvalidVoter {
            voter: voter.clone(),
        });
    }

    // 3. Validate session_id matches
    if let Some(expected_session) = state.get_session(&workload_id) {
        if expected_session != &session_id {
            return Err(HandlerError::SessionMismatch {
                expected: expected_session.clone(),
                received: session_id,
            });
        }
    }

    // 4. Get consensus and check if terminal
    let consensus = state
        .get_consensus_mut(&workload_id)
        .ok_or_else(|| HandlerError::ConsensusNotFound {
            workload_id: workload_id.clone(),
        })?;

    if consensus.is_terminal() {
        return Err(HandlerError::ConsensusTerminal {
            workload_id: workload_id.clone(),
            state: consensus.state().name().to_string(),
        });
    }

    // 5. Convert MessageVote to Vote struct
    let approve = vote.is_approve();
    let internal_vote = Vote::new(approve, now_ms, [0u8; 64]); // Signature placeholder

    // 6. Add vote through proper channel
    let vote_result = consensus.add_vote(voter.clone(), internal_vote, now_ms);

    // 7. Handle result
    match vote_result {
        AddVoteResult::MovedToSigning {
            signing_session, ..
        } => {
            // Threshold reached! Return SigningCommitment trigger
            // Note: We don't actually create the commitment here,
            // just signal that signing should begin
            // The actual commitment creation is handled by signing module
            
            // For now, return None since we don't have SigningCommitmentProto yet
            // The caller should check consensus state and initiate signing
            let _ = signing_session; // Acknowledge we have it
            Ok(None)
        }
        AddVoteResult::MovedToVoting { .. } | AddVoteResult::NoChange { .. } => {
            // Vote accepted but threshold not reached
            Ok(None)
        }
        AddVoteResult::MovedToFailed { error } => {
            // Consensus failed due to rejection threshold
            Err(HandlerError::InvalidState {
                current_state: format!("{:?}", error),
                operation: "vote".to_string(),
            })
        }
        AddVoteResult::RejectedVote { reason } => {
            // Vote was rejected
            match &reason {
                super::ConsensusError::DuplicateVote { .. } => {
                    Err(HandlerError::DuplicateVote { voter })
                }
                _ => Err(HandlerError::InvalidState {
                    current_state: format!("{:?}", reason),
                    operation: "vote".to_string(),
                }),
            }
        }
    }
}

/// Convenience function to handle CoordinatorMessage dispatch.
///
/// # Arguments
///
/// * `state` - Mutable reference ke MultiCoordinatorState
/// * `msg` - CoordinatorMessage to handle
/// * `from` - CoordinatorId pengirim
/// * `now_ms` - Timestamp saat ini
///
/// # Returns
///
/// - `Ok(Some(CoordinatorMessage))` - Response message
/// - `Ok(None)` - No response needed
/// - `Err(HandlerError)` - Handler error
pub fn handle_message(
    state: &mut MultiCoordinatorState,
    msg: CoordinatorMessage,
    from: CoordinatorId,
    now_ms: u64,
) -> Result<Option<CoordinatorMessage>, HandlerError> {
    match msg {
        CoordinatorMessage::ProposeReceipt {
            session_id,
            data,
            proposer,
        } => {
            // Validate from matches proposer
            if from != proposer {
                return Err(HandlerError::InvalidVoter { voter: from });
            }
            handle_propose_receipt(state, session_id, data, proposer, now_ms)
        }
        CoordinatorMessage::VoteReceipt {
            session_id,
            workload_id,
            vote,
            voter,
        } => {
            // Validate from matches voter
            if from != voter {
                return Err(HandlerError::InvalidVoter { voter: from });
            }
            handle_vote_receipt(state, session_id, workload_id, vote, voter, now_ms)
        }
        // Other message types are not handled here
        _ => Ok(None),
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use dsdn_common::coordinator::WorkloadId as CommonWorkloadId;

    fn make_coord_id(seed: u8) -> CoordinatorId {
        CoordinatorId::new([seed; 32])
    }

    fn make_workload_id(seed: u8) -> WorkloadId {
        WorkloadId::new([seed; 32])
    }

    fn make_session_id(seed: u8) -> SessionId {
        SessionId::new([seed; 32])
    }

    fn make_receipt_data(workload_seed: u8) -> ReceiptData {
        ReceiptData::new(
            CommonWorkloadId::new([workload_seed; 32]),
            [0x02; 32], // blob_hash
            vec![],
            1700000000,
            1,
            1,
        )
    }

    fn make_state() -> MultiCoordinatorState {
        let self_id = make_coord_id(0x00);
        let mut committee = HashSet::new();
        committee.insert(make_coord_id(0x00));
        committee.insert(make_coord_id(0x01));
        committee.insert(make_coord_id(0x02));

        MultiCoordinatorState::new(self_id, committee, 2, 30000)
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // ValidationError Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_validation_error_display() {
        let err = ValidationError::InvalidWorkloadId;
        assert!(err.to_string().contains("workload_id"));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // HandlerError Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_handler_error_display() {
        let err = HandlerError::DuplicateProposal {
            workload_id: make_workload_id(0x01),
        };
        assert!(err.to_string().contains("duplicate"));
    }

    #[test]
    fn test_handler_error_from_validation() {
        let val_err = ValidationError::InvalidEpoch;
        let handler_err: HandlerError = val_err.into();
        assert!(matches!(handler_err, HandlerError::InvalidProposal { .. }));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // MultiCoordinatorState Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_state_new() {
        let state = make_state();
        assert_eq!(state.threshold(), 2);
        assert_eq!(state.committee_size(), 3);
        assert_eq!(state.consensus_count(), 0);
    }

    #[test]
    fn test_state_is_committee_member() {
        let state = make_state();
        assert!(state.is_committee_member(&make_coord_id(0x00)));
        assert!(state.is_committee_member(&make_coord_id(0x01)));
        assert!(!state.is_committee_member(&make_coord_id(0xFF)));
    }

    #[test]
    fn test_state_debug() {
        let state = make_state();
        let debug = format!("{:?}", state);
        assert!(debug.contains("MultiCoordinatorState"));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // validate_receipt_proposal Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_validate_proposal_valid() {
        let data = make_receipt_data(0x01);
        let result = validate_receipt_proposal(&data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_proposal_zero_workload_id() {
        let data = ReceiptData::new(
            CommonWorkloadId::new([0x00; 32]), // All zeros
            [0x02; 32],
            vec![],
            1700000000,
            1,
            1,
        );
        let result = validate_receipt_proposal(&data);
        assert!(matches!(result, Err(ValidationError::InvalidWorkloadId)));
    }

    #[test]
    fn test_validate_proposal_zero_blob_hash() {
        let data = ReceiptData::new(
            CommonWorkloadId::new([0x01; 32]),
            [0x00; 32], // All zeros
            vec![],
            1700000000,
            1,
            1,
        );
        let result = validate_receipt_proposal(&data);
        assert!(matches!(result, Err(ValidationError::InvalidBlobHash)));
    }

    #[test]
    fn test_validate_proposal_zero_epoch() {
        let data = ReceiptData::new(
            CommonWorkloadId::new([0x01; 32]),
            [0x02; 32],
            vec![],
            1700000000,
            1,
            0, // Zero epoch
        );
        let result = validate_receipt_proposal(&data);
        assert!(matches!(result, Err(ValidationError::InvalidEpoch)));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // create_vote_response Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_create_vote_response_approve() {
        let session_id = make_session_id(0x01);
        let workload_id = make_workload_id(0x02);
        let my_id = make_coord_id(0x03);

        let msg = create_vote_response(session_id, workload_id, my_id, true, None);

        match msg {
            CoordinatorMessage::VoteReceipt { vote, .. } => {
                assert!(vote.is_approve());
            }
            _ => panic!("expected VoteReceipt"),
        }
    }

    #[test]
    fn test_create_vote_response_reject() {
        let session_id = make_session_id(0x01);
        let workload_id = make_workload_id(0x02);
        let my_id = make_coord_id(0x03);

        let msg = create_vote_response(
            session_id,
            workload_id,
            my_id,
            false,
            Some("test reason".to_string()),
        );

        match msg {
            CoordinatorMessage::VoteReceipt { vote, .. } => {
                assert!(vote.is_reject());
                assert_eq!(vote.rejection_reason(), Some("test reason"));
            }
            _ => panic!("expected VoteReceipt"),
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // handle_propose_receipt Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_handle_propose_receipt_success() {
        let mut state = make_state();
        let session_id = make_session_id(0x01);
        let data = make_receipt_data(0x01);
        let proposer = make_coord_id(0x01);

        let result = handle_propose_receipt(&mut state, session_id, data, proposer, 1700000000);

        assert!(result.is_ok());
        assert!(result.unwrap().is_some()); // Should return VoteReceipt
        assert_eq!(state.consensus_count(), 1);
    }

    #[test]
    fn test_handle_propose_receipt_duplicate() {
        let mut state = make_state();
        let session_id = make_session_id(0x01);
        let data = make_receipt_data(0x01);
        let proposer = make_coord_id(0x01);

        // First proposal
        let _ = handle_propose_receipt(
            &mut state,
            session_id.clone(),
            data.clone(),
            proposer.clone(),
            1700000000,
        );

        // Duplicate proposal
        let result =
            handle_propose_receipt(&mut state, session_id, data, proposer, 1700000001);

        assert!(matches!(
            result,
            Err(HandlerError::DuplicateProposal { .. })
        ));
    }

    #[test]
    fn test_handle_propose_receipt_invalid_proposer() {
        let mut state = make_state();
        let session_id = make_session_id(0x01);
        let data = make_receipt_data(0x01);
        let proposer = make_coord_id(0xFF); // Not in committee

        let result = handle_propose_receipt(&mut state, session_id, data, proposer, 1700000000);

        assert!(matches!(result, Err(HandlerError::InvalidVoter { .. })));
    }

    #[test]
    fn test_handle_propose_receipt_invalid_data() {
        let mut state = make_state();
        let session_id = make_session_id(0x01);
        let data = ReceiptData::new(
            CommonWorkloadId::new([0x00; 32]), // Invalid: all zeros
            [0x02; 32],
            vec![],
            1700000000,
            1,
            1,
        );
        let proposer = make_coord_id(0x01);

        let result = handle_propose_receipt(&mut state, session_id, data, proposer, 1700000000);

        assert!(matches!(result, Err(HandlerError::InvalidProposal { .. })));
        // State should NOT be mutated
        assert_eq!(state.consensus_count(), 0);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // handle_vote_receipt Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_handle_vote_receipt_success() {
        let mut state = make_state();
        let session_id = make_session_id(0x01);
        let workload_id = make_workload_id(0x01);
        let data = make_receipt_data(0x01);
        let proposer = make_coord_id(0x01);

        // First create proposal
        let _ = handle_propose_receipt(
            &mut state,
            session_id.clone(),
            data,
            proposer,
            1700000000,
        );

        // Then vote from another member
        let voter = make_coord_id(0x02);
        let vote = MessageVote::approve();

        let result = handle_vote_receipt(
            &mut state,
            session_id,
            workload_id,
            vote,
            voter,
            1700000001,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_vote_receipt_consensus_not_found() {
        let mut state = make_state();
        let session_id = make_session_id(0x01);
        let workload_id = make_workload_id(0x99); // Non-existent
        let voter = make_coord_id(0x01);
        let vote = MessageVote::approve();

        let result =
            handle_vote_receipt(&mut state, session_id, workload_id, vote, voter, 1700000000);

        assert!(matches!(
            result,
            Err(HandlerError::ConsensusNotFound { .. })
        ));
    }

    #[test]
    fn test_handle_vote_receipt_invalid_voter() {
        let mut state = make_state();
        let session_id = make_session_id(0x01);
        let workload_id = make_workload_id(0x01);
        let data = make_receipt_data(0x01);
        let proposer = make_coord_id(0x01);

        // Create proposal first
        let _ = handle_propose_receipt(
            &mut state,
            session_id.clone(),
            data,
            proposer,
            1700000000,
        );

        // Vote from non-committee member
        let voter = make_coord_id(0xFF);
        let vote = MessageVote::approve();

        let result = handle_vote_receipt(
            &mut state,
            session_id,
            workload_id,
            vote,
            voter,
            1700000001,
        );

        assert!(matches!(result, Err(HandlerError::InvalidVoter { .. })));
    }

    #[test]
    fn test_handle_vote_receipt_duplicate_vote() {
        // Use higher threshold to avoid moving to Signing before duplicate test
        let self_id = make_coord_id(0x00);
        let mut committee = HashSet::new();
        committee.insert(make_coord_id(0x00));
        committee.insert(make_coord_id(0x01));
        committee.insert(make_coord_id(0x02));
        committee.insert(make_coord_id(0x03));

        let mut state = MultiCoordinatorState::new(self_id, committee, 3, 30000); // threshold = 3

        let session_id = make_session_id(0x01);
        let workload_id = make_workload_id(0x01);
        let data = make_receipt_data(0x01);
        let proposer = make_coord_id(0x01);

        // Create proposal (auto-vote from self_id = 0x00, count = 1)
        let _ = handle_propose_receipt(
            &mut state,
            session_id.clone(),
            data,
            proposer,
            1700000000,
        );

        // First vote from 0x02 (count = 2, still < threshold 3)
        let voter = make_coord_id(0x02);
        let vote = MessageVote::approve();

        let _ = handle_vote_receipt(
            &mut state,
            session_id.clone(),
            workload_id.clone(),
            vote.clone(),
            voter.clone(),
            1700000001,
        );

        // Duplicate vote from same voter
        let result = handle_vote_receipt(
            &mut state,
            session_id,
            workload_id,
            vote,
            voter,
            1700000002,
        );

        assert!(matches!(result, Err(HandlerError::DuplicateVote { .. })));
    }

    #[test]
    fn test_handle_vote_receipt_session_mismatch() {
        let mut state = make_state();
        let session_id = make_session_id(0x01);
        let wrong_session = make_session_id(0xFF);
        let workload_id = make_workload_id(0x01);
        let data = make_receipt_data(0x01);
        let proposer = make_coord_id(0x01);

        // Create proposal with session_id
        let _ = handle_propose_receipt(
            &mut state,
            session_id,
            data,
            proposer,
            1700000000,
        );

        // Vote with different session
        let voter = make_coord_id(0x02);
        let vote = MessageVote::approve();

        let result = handle_vote_receipt(
            &mut state,
            wrong_session,
            workload_id,
            vote,
            voter,
            1700000001,
        );

        assert!(matches!(result, Err(HandlerError::SessionMismatch { .. })));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Threshold Detection Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_threshold_reached() {
        let mut state = make_state();
        let session_id = make_session_id(0x01);
        let workload_id = make_workload_id(0x01);
        let data = make_receipt_data(0x01);
        let proposer = make_coord_id(0x01);

        // Create proposal (auto-votes from self_id = 0x00)
        let _ = handle_propose_receipt(
            &mut state,
            session_id.clone(),
            data,
            proposer,
            1700000000,
        );

        // Vote from another member (threshold = 2)
        let voter = make_coord_id(0x02);
        let vote = MessageVote::approve();

        let result = handle_vote_receipt(
            &mut state,
            session_id,
            workload_id.clone(),
            vote,
            voter,
            1700000001,
        );

        assert!(result.is_ok());

        // Check consensus state
        let consensus = state.get_consensus(&workload_id).unwrap();
        assert_eq!(consensus.state().name(), "Signing");
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // No State Leak Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_no_state_mutation_on_validation_failure() {
        let mut state = make_state();
        let initial_count = state.consensus_count();

        let session_id = make_session_id(0x01);
        let invalid_data = ReceiptData::new(
            CommonWorkloadId::new([0x00; 32]), // Invalid
            [0x02; 32],
            vec![],
            1700000000,
            1,
            1,
        );
        let proposer = make_coord_id(0x01);

        let _ = handle_propose_receipt(&mut state, session_id, invalid_data, proposer, 1700000000);

        // State should be unchanged
        assert_eq!(state.consensus_count(), initial_count);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Deterministic Behavior Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_deterministic_vote_response() {
        let session_id = make_session_id(0x01);
        let workload_id = make_workload_id(0x02);
        let my_id = make_coord_id(0x03);

        let msg1 = create_vote_response(
            session_id.clone(),
            workload_id.clone(),
            my_id.clone(),
            true,
            None,
        );
        let msg2 = create_vote_response(session_id, workload_id, my_id, true, None);

        assert_eq!(msg1, msg2);
    }
}