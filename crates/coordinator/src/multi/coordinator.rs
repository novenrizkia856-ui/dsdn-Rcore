//! MultiCoordinator Main Struct & Integration (14A.2B.2.20)
//!
//! Module ini menyediakan `MultiCoordinator` sebagai MAIN ENTRY POINT
//! untuk sistem multi-coordinator consensus dalam DSDN.
//!
//! # Overview
//!
//! `MultiCoordinator` mengintegrasikan semua komponen:
//! - Identity & key management (CoordinatorId, KeyShare)
//! - Committee management (CoordinatorCommittee)
//! - Peer tracking (PeerManager)
//! - Network I/O (CoordinatorNetwork trait)
//! - Consensus state machines (ReceiptConsensus)
//! - Signing sessions (SigningSession)
//! - Message routing (handlers)
//!
//! # Invariants
//!
//! - `id` IMMUTABLE setelah construction
//! - `committee` IMMUTABLE selama epoch
//! - `pending_receipts` dan `signing_sessions` KONSISTEN
//! - Network hanya diakses via trait
//! - TIDAK ADA state "setengah jalan"
//! - TIDAK ADA panic/unwrap/expect
//!
//! # Event Loop Semantics
//!
//! - Message diproses SATU PER SATU
//! - Maksimal satu consensus state mutation per event
//! - Tidak ada lock lintas handler
//! - Re-entrant safe secara logis
//!
//! # Usage
//!
//! ```ignore
//! use dsdn_coordinator::multi::{
//!     MultiCoordinator, MultiCoordinatorConfig,
//!     CoordinatorId, KeyShare, MockNetwork,
//! };
//! use dsdn_common::coordinator::CoordinatorCommittee;
//! use std::sync::Arc;
//!
//! let config = MultiCoordinatorConfig::new(30000, 60000, false, 300)?;
//! let coordinator = MultiCoordinator::new(
//!     id, key_share, committee, Arc::new(network), config,
//! )?;
//! ```

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use dsdn_common::coordinator::{CoordinatorCommittee, ReceiptData, ThresholdReceipt};

use super::{
    CoordinatorId, CoordinatorMessage, CoordinatorNetwork, ConsensusError,
    ConsensusState, HandlerError, KeyShare, MessageVote, MultiCoordinatorState,
    PeerConfig, PeerManager, ReceiptConsensus, SessionId, SigningSession,
    WorkloadId, Vote,
    // Handler functions
    handle_message as handler_handle_message,
    handle_propose_receipt, handle_vote_receipt,
    handle_signing_commitment, handle_partial_signature,
    initiate_signing_session,
    validate_receipt_proposal, create_vote_response,
    derive_session_id,
};

// ════════════════════════════════════════════════════════════════════════════════
// CONFIG ERROR
// ════════════════════════════════════════════════════════════════════════════════

/// Error type untuk konfigurasi yang tidak valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// Proposal timeout tidak valid.
    InvalidProposalTimeout {
        /// Nilai yang diberikan.
        value: u64,
        /// Alasan penolakan.
        reason: String,
    },

    /// Signing timeout tidak valid.
    InvalidSigningTimeout {
        /// Nilai yang diberikan.
        value: u64,
        /// Alasan penolakan.
        reason: String,
    },

    /// Challenge window tidak valid.
    InvalidChallengeWindow {
        /// Nilai yang diberikan.
        value: u64,
        /// Alasan penolakan.
        reason: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::InvalidProposalTimeout { value, reason } => {
                write!(
                    f,
                    "invalid proposal_timeout_ms {}: {}",
                    value, reason
                )
            }
            ConfigError::InvalidSigningTimeout { value, reason } => {
                write!(
                    f,
                    "invalid signing_timeout_ms {}: {}",
                    value, reason
                )
            }
            ConfigError::InvalidChallengeWindow { value, reason } => {
                write!(
                    f,
                    "invalid challenge_window_secs {}: {}",
                    value, reason
                )
            }
        }
    }
}

impl std::error::Error for ConfigError {}

// ════════════════════════════════════════════════════════════════════════════════
// MULTI COORDINATOR CONFIG
// ════════════════════════════════════════════════════════════════════════════════

/// Konfigurasi untuk MultiCoordinator.
///
/// Semua field wajib diisi secara eksplisit.
/// Tidak ada default implisit.
///
/// # Validation
///
/// - `proposal_timeout_ms` > 0
/// - `signing_timeout_ms` > 0
/// - `challenge_window_secs` > 0 (jika enable_optimistic)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiCoordinatorConfig {
    /// Timeout untuk proposal consensus dalam milliseconds.
    proposal_timeout_ms: u64,

    /// Timeout untuk signing session dalam milliseconds.
    signing_timeout_ms: u64,

    /// Apakah optimistic receipt diaktifkan.
    enable_optimistic: bool,

    /// Challenge window dalam detik (untuk optimistic receipt).
    challenge_window_secs: u64,
}

impl MultiCoordinatorConfig {
    /// Membuat konfigurasi baru dengan validasi.
    ///
    /// # Arguments
    ///
    /// * `proposal_timeout_ms` - Timeout proposal (> 0)
    /// * `signing_timeout_ms` - Timeout signing (> 0)
    /// * `enable_optimistic` - Flag optimistic receipt
    /// * `challenge_window_secs` - Challenge window (> 0 jika optimistic)
    ///
    /// # Errors
    ///
    /// - `InvalidProposalTimeout` jika proposal_timeout_ms == 0
    /// - `InvalidSigningTimeout` jika signing_timeout_ms == 0
    /// - `InvalidChallengeWindow` jika enable_optimistic && challenge_window_secs == 0
    pub fn new(
        proposal_timeout_ms: u64,
        signing_timeout_ms: u64,
        enable_optimistic: bool,
        challenge_window_secs: u64,
    ) -> Result<Self, ConfigError> {
        if proposal_timeout_ms == 0 {
            return Err(ConfigError::InvalidProposalTimeout {
                value: 0,
                reason: "must be > 0".to_string(),
            });
        }

        if signing_timeout_ms == 0 {
            return Err(ConfigError::InvalidSigningTimeout {
                value: 0,
                reason: "must be > 0".to_string(),
            });
        }

        if enable_optimistic && challenge_window_secs == 0 {
            return Err(ConfigError::InvalidChallengeWindow {
                value: 0,
                reason: "must be > 0 when optimistic is enabled".to_string(),
            });
        }

        Ok(Self {
            proposal_timeout_ms,
            signing_timeout_ms,
            enable_optimistic,
            challenge_window_secs,
        })
    }

    /// Mengembalikan proposal timeout dalam milliseconds.
    #[must_use]
    #[inline]
    pub const fn proposal_timeout_ms(&self) -> u64 {
        self.proposal_timeout_ms
    }

    /// Mengembalikan signing timeout dalam milliseconds.
    #[must_use]
    #[inline]
    pub const fn signing_timeout_ms(&self) -> u64 {
        self.signing_timeout_ms
    }

    /// Apakah optimistic receipt diaktifkan.
    #[must_use]
    #[inline]
    pub const fn enable_optimistic(&self) -> bool {
        self.enable_optimistic
    }

    /// Mengembalikan challenge window dalam detik.
    #[must_use]
    #[inline]
    pub const fn challenge_window_secs(&self) -> u64 {
        self.challenge_window_secs
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// MULTI COORDINATOR ERROR
// ════════════════════════════════════════════════════════════════════════════════

/// Error type untuk MultiCoordinator operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultiCoordinatorError {
    /// Konfigurasi tidak valid.
    Config(ConfigError),

    /// Self ID bukan anggota committee.
    NotCommitteeMember {
        /// CoordinatorId yang bukan member.
        id: CoordinatorId,
    },

    /// Committee tidak valid untuk production.
    InvalidCommittee {
        /// Alasan.
        reason: String,
    },
}

impl fmt::Display for MultiCoordinatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MultiCoordinatorError::Config(err) => {
                write!(f, "config error: {}", err)
            }
            MultiCoordinatorError::NotCommitteeMember { id } => {
                write!(
                    f,
                    "coordinator {:?} is not a committee member",
                    id.as_bytes()
                )
            }
            MultiCoordinatorError::InvalidCommittee { reason } => {
                write!(f, "invalid committee: {}", reason)
            }
        }
    }
}

impl std::error::Error for MultiCoordinatorError {}

impl From<ConfigError> for MultiCoordinatorError {
    fn from(err: ConfigError) -> Self {
        MultiCoordinatorError::Config(err)
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// MULTI COORDINATOR
// ════════════════════════════════════════════════════════════════════════════════

/// Main entry point untuk multi-coordinator consensus.
///
/// `MultiCoordinator` mengintegrasikan semua sub-komponen dan menyediakan
/// API tunggal untuk:
/// - Proposing receipts
/// - Handling incoming messages
/// - Querying state
///
/// # Thread Safety
///
/// Struct ini TIDAK thread-safe secara internal.
/// Semua mutasi melalui `&mut self`.
/// Jika perlu thread-safety, bungkus dengan `Arc<Mutex<_>>`.
///
/// # Architecture
///
/// ```text
/// ┌─────────────────────────────────────────────────────────────────┐
/// │                       MultiCoordinator                          │
/// │                                                                 │
/// │  ┌──────────┐  ┌───────────────┐  ┌─────────────────────────┐ │
/// │  │    id    │  │  key_share    │  │      committee          │ │
/// │  └──────────┘  └───────────────┘  └─────────────────────────┘ │
/// │                                                                 │
/// │  ┌──────────┐  ┌───────────────┐  ┌─────────────────────────┐ │
/// │  │  peers   │  │   network     │  │       config            │ │
/// │  └──────────┘  └───────────────┘  └─────────────────────────┘ │
/// │                                                                 │
/// │  ┌──────────────────────────┐  ┌────────────────────────────┐ │
/// │  │   pending_receipts      │  │   signing_sessions         │ │
/// │  │  HashMap<WID,Consensus> │  │  HashMap<SID,Session>      │ │
/// │  └──────────────────────────┘  └────────────────────────────┘ │
/// │                                                                 │
/// │  Internal: MultiCoordinatorState (delegation target)           │
/// └─────────────────────────────────────────────────────────────────┘
/// ```
pub struct MultiCoordinator {
    /// Immutable coordinator identity.
    id: CoordinatorId,

    /// Key share untuk threshold signing.
    key_share: KeyShare,

    /// Committee (immutable selama epoch).
    committee: CoordinatorCommittee,

    /// Peer connection manager.
    peers: PeerManager,

    /// Network interface (accessed only via trait).
    network: Arc<dyn CoordinatorNetwork>,

    /// Internal state untuk consensus handlers.
    /// Berisi pending_receipts dan signing_sessions.
    state: MultiCoordinatorState,

    /// Configuration.
    config: MultiCoordinatorConfig,
}

impl MultiCoordinator {
    /// Membuat MultiCoordinator baru.
    ///
    /// # Arguments
    ///
    /// * `id` - CoordinatorId (immutable)
    /// * `key_share` - KeyShare untuk threshold signing
    /// * `committee` - CoordinatorCommittee (immutable selama epoch)
    /// * `network` - Network implementation
    /// * `config` - MultiCoordinatorConfig (sudah validated)
    ///
    /// # Returns
    ///
    /// - `Ok(MultiCoordinator)` jika semua invariant terpenuhi
    /// - `Err(MultiCoordinatorError)` jika validasi gagal
    ///
    /// # Errors
    ///
    /// - `NotCommitteeMember` jika id bukan anggota committee
    /// - `InvalidCommittee` jika committee tidak valid
    ///
    /// # Invariants Checked
    ///
    /// 1. Committee harus valid (`is_valid()`)
    /// 2. Self ID harus anggota committee
    pub fn new(
        id: CoordinatorId,
        key_share: KeyShare,
        committee: CoordinatorCommittee,
        network: Arc<dyn CoordinatorNetwork>,
        config: MultiCoordinatorConfig,
    ) -> Result<Self, MultiCoordinatorError> {
        // 1. Validate committee
        if !committee.is_valid() {
            return Err(MultiCoordinatorError::InvalidCommittee {
                reason: "committee failed is_valid() check".to_string(),
            });
        }

        // 2. Validate self is committee member
        // Convert multi::CoordinatorId to common::CoordinatorId for comparison
        let common_id = dsdn_common::coordinator::CoordinatorId::new(*id.as_bytes());
        if !committee.is_member(&common_id) {
            return Err(MultiCoordinatorError::NotCommitteeMember { id });
        }

        // 3. Build committee member set for internal state
        let mut committee_members = std::collections::HashSet::new();
        for member in committee.members() {
            let member_id = CoordinatorId::new(*member.id().as_bytes());
            committee_members.insert(member_id);
        }

        // 4. Create internal state
        let state = MultiCoordinatorState::new(
            id.clone(),
            committee_members,
            committee.threshold(),
            config.proposal_timeout_ms(),
        );

        // 5. Create PeerManager with reasonable defaults
        // PeerConfig::new validates timeout_ms > 0, max_reconnect > 0, interval > 0
        let peer_config = match PeerConfig::new(5000, 3, 1000) {
            Ok(config) => config,
            Err(_) => {
                // This should be unreachable with these known-good values,
                // but we handle it gracefully instead of panicking
                return Err(MultiCoordinatorError::InvalidCommittee {
                    reason: "failed to create default peer config".to_string(),
                });
            }
        };
        let peers = PeerManager::new(peer_config);

        Ok(Self {
            id,
            key_share,
            committee,
            peers,
            network,
            state,
            config,
        })
    }

    // ────────────────────────────────────────────────────────────────────────────
    // GETTERS (Pure, no side effects)
    // ────────────────────────────────────────────────────────────────────────────

    /// Mengembalikan reference ke coordinator ID.
    #[must_use]
    #[inline]
    pub const fn id(&self) -> &CoordinatorId {
        &self.id
    }

    /// Mengembalikan reference ke key share.
    #[must_use]
    #[inline]
    pub const fn key_share(&self) -> &KeyShare {
        &self.key_share
    }

    /// Mengembalikan reference ke committee (immutable selama epoch).
    #[must_use]
    #[inline]
    pub fn get_committee(&self) -> &CoordinatorCommittee {
        &self.committee
    }

    /// Mengembalikan reference ke peer manager.
    #[must_use]
    #[inline]
    pub const fn peers(&self) -> &PeerManager {
        &self.peers
    }

    /// Mengembalikan mutable reference ke peer manager.
    #[inline]
    pub fn peers_mut(&mut self) -> &mut PeerManager {
        &mut self.peers
    }

    /// Mengembalikan reference ke config.
    #[must_use]
    #[inline]
    pub const fn config(&self) -> &MultiCoordinatorConfig {
        &self.config
    }

    /// Mengembalikan jumlah pending receipts.
    #[must_use]
    #[inline]
    pub fn get_pending_count(&self) -> usize {
        self.state.consensus_count()
    }

    /// Mengembalikan jumlah signing sessions aktif.
    #[must_use]
    #[inline]
    pub fn get_signing_session_count(&self) -> usize {
        self.state.signing_session_count()
    }

    /// Mendapatkan reference ke consensus untuk workload_id.
    #[must_use]
    pub fn get_consensus(&self, workload_id: &WorkloadId) -> Option<&ReceiptConsensus> {
        self.state.get_consensus(workload_id)
    }

    /// Mendapatkan reference ke signing session untuk session_id.
    #[must_use]
    pub fn get_signing_session(&self, session_id: &SessionId) -> Option<&SigningSession> {
        self.state.get_signing_session(session_id)
    }

    /// Mengembalikan reference ke internal state (untuk testing/introspection).
    #[must_use]
    #[inline]
    pub fn internal_state(&self) -> &MultiCoordinatorState {
        &self.state
    }

    // ────────────────────────────────────────────────────────────────────────────
    // PROPOSE RECEIPT (Async)
    // ────────────────────────────────────────────────────────────────────────────

    /// Memulai consensus untuk receipt baru.
    ///
    /// # Arguments
    ///
    /// * `data` - ReceiptData yang akan di-propose
    /// * `now_ms` - Timestamp saat ini dalam milliseconds
    ///
    /// # Returns
    ///
    /// - `Ok(WorkloadId)` - WorkloadId dari consensus yang dimulai
    /// - `Err(HandlerError)` - Jika proposal gagal
    ///
    /// # Flow
    ///
    /// 1. Validate receipt data
    /// 2. Generate deterministic session_id
    /// 3. Create ReceiptConsensus via handle_propose_receipt
    /// 4. Broadcast ProposeReceipt message ke semua peers
    /// 5. Return WorkloadId untuk tracking
    ///
    /// # Network
    ///
    /// Broadcast dilakukan async. Kegagalan broadcast TIDAK
    /// membatalkan consensus creation - peers dapat catch up.
    ///
    /// # State Mutation
    ///
    /// - Membuat ReceiptConsensus baru
    /// - Auto-vote approve dari self
    pub async fn propose_receipt(
        &mut self,
        data: ReceiptData,
        now_ms: u64,
    ) -> Result<WorkloadId, HandlerError> {
        // 1. Extract workload_id
        let workload_id = WorkloadId::new(*data.workload_id().as_bytes());

        // 2. Generate deterministic session_id from workload_id
        let session_id = derive_session_id(&workload_id);

        // 3. Create proposal message
        let propose_msg = CoordinatorMessage::ProposeReceipt {
            session_id: session_id.clone(),
            data: data.clone(),
            proposer: self.id.clone(),
        };

        // 4. Handle locally first (creates consensus + auto-vote)
        let response = handle_propose_receipt(
            &mut self.state,
            session_id,
            data,
            self.id.clone(),
            now_ms,
        )?;

        // 5. Broadcast proposal to peers
        // Network failure does not cancel consensus
        let _ = self.network.broadcast(propose_msg).await;

        // 6. If we got a vote response, broadcast it too
        if let Some(vote_msg) = response {
            let _ = self.network.broadcast(vote_msg).await;
        }

        Ok(workload_id)
    }

    // ────────────────────────────────────────────────────────────────────────────
    // MESSAGE HANDLING
    // ────────────────────────────────────────────────────────────────────────────

    /// Handle incoming message dari peer.
    ///
    /// # Arguments
    ///
    /// * `from` - CoordinatorId pengirim
    /// * `msg` - CoordinatorMessage yang diterima
    /// * `now_ms` - Timestamp saat ini dalam milliseconds
    ///
    /// # Returns
    ///
    /// - `Ok(Option<CoordinatorMessage>)` - Optional response message
    /// - `Err(HandlerError)` - Jika handler gagal
    ///
    /// # Flow
    ///
    /// 1. Update peer last_seen
    /// 2. Route message ke handler yang tepat via handler_handle_message
    /// 3. Check for state transitions (e.g., voting → signing)
    /// 4. Return optional response
    ///
    /// # Determinism
    ///
    /// - Same input → same state mutation
    /// - One message → at most one consensus state change
    pub async fn handle_message(
        &mut self,
        from: CoordinatorId,
        msg: CoordinatorMessage,
        now_ms: u64,
    ) -> Result<Option<CoordinatorMessage>, HandlerError> {
        // 1. Update peer tracking
        self.peers.mark_seen(&from);

        // 2. Check for Ping/Pong (handle directly)
        match &msg {
            CoordinatorMessage::Ping { timestamp } => {
                let pong = CoordinatorMessage::Pong {
                    timestamp: *timestamp,
                    received_at: now_ms,
                };
                return Ok(Some(pong));
            }
            CoordinatorMessage::Pong { .. } => {
                // Pong received, peer tracking already updated
                return Ok(None);
            }
            _ => {}
        }

        // 3. Capture workload_id if this is a vote that might trigger signing
        let maybe_workload_id = match &msg {
            CoordinatorMessage::VoteReceipt { workload_id, .. } => Some(workload_id.clone()),
            _ => None,
        };

        // 4. Route to handler
        let result = handler_handle_message(&mut self.state, msg, from, now_ms)?;

        // 5. Check if voting threshold was reached → initiate signing
        if let Some(workload_id) = maybe_workload_id {
            self.try_initiate_signing(&workload_id, now_ms).await;
        }

        Ok(result)
    }

    /// Try to initiate signing if consensus is in Signing state.
    ///
    /// Called after vote processing to check for threshold transitions.
    async fn try_initiate_signing(&mut self, workload_id: &WorkloadId, _now_ms: u64) {
        // Check if consensus is in Signing state
        let should_initiate = self
            .state
            .get_consensus(workload_id)
            .map(|c| matches!(c.state(), ConsensusState::Signing { .. }))
            .unwrap_or(false);

        if !should_initiate {
            return;
        }

        // Check if signing session already exists
        let session_exists = self
            .state
            .get_session(workload_id)
            .map(|sid| self.state.has_signing_session(sid))
            .unwrap_or(false);

        if session_exists {
            return;
        }

        // Initiate signing session
        if let Ok(session_id) = initiate_signing_session(&mut self.state, workload_id) {
            // Broadcast that signing should begin
            // Peers should create their own commitments
            let _ = session_id; // Session created in state
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // QUERY METHODS
    // ────────────────────────────────────────────────────────────────────────────

    /// Memeriksa apakah consensus untuk workload_id sudah selesai.
    ///
    /// # Returns
    ///
    /// - `Some(true)` jika consensus ada dan terminal (Completed/Failed)
    /// - `Some(false)` jika consensus ada dan belum terminal
    /// - `None` jika consensus tidak ditemukan
    #[must_use]
    pub fn is_consensus_terminal(&self, workload_id: &WorkloadId) -> Option<bool> {
        self.state
            .get_consensus(workload_id)
            .map(|c| c.is_terminal())
    }

    /// Mendapatkan ThresholdReceipt jika consensus sudah Completed.
    ///
    /// # Returns
    ///
    /// - `Some(&ThresholdReceipt)` jika consensus completed
    /// - `None` jika belum completed atau tidak ditemukan
    #[must_use]
    pub fn get_completed_receipt(
        &self,
        workload_id: &WorkloadId,
    ) -> Option<&ThresholdReceipt> {
        self.state
            .get_consensus(workload_id)
            .and_then(|c| c.get_result())
    }

    /// Mengembalikan state consensus untuk workload_id.
    ///
    /// # Returns
    ///
    /// - `Some(state_name)` jika consensus ditemukan
    /// - `None` jika consensus tidak ditemukan
    #[must_use]
    pub fn consensus_state_name(&self, workload_id: &WorkloadId) -> Option<String> {
        self.state
            .get_consensus(workload_id)
            .map(|c| c.state().name().to_string())
    }
}

impl fmt::Debug for MultiCoordinator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MultiCoordinator")
            .field("id", &self.id)
            .field("committee_size", &self.committee.member_count())
            .field("threshold", &self.committee.threshold())
            .field("epoch", &self.committee.epoch())
            .field("pending_count", &self.get_pending_count())
            .field("signing_sessions", &self.get_signing_session_count())
            .field("peer_count", &self.peers.peer_count())
            .field("config", &self.config)
            .finish()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use dsdn_common::coordinator::{
        CoordinatorId as CommonCoordinatorId,
        CoordinatorMember,
        ValidatorId,
        WorkloadId as CommonWorkloadId,
    };
    use dsdn_tss::{GroupPublicKey, ParticipantPublicKey};

    use crate::multi::MockNetwork;

    // ────────────────────────────────────────────────────────────────────────────
    // HELPERS
    // ────────────────────────────────────────────────────────────────────────────

    fn make_coord_id(seed: u8) -> CoordinatorId {
        CoordinatorId::new([seed; 32])
    }

    fn make_common_coord_id(seed: u8) -> CommonCoordinatorId {
        CommonCoordinatorId::new([seed; 32])
    }

    fn make_validator_id(seed: u8) -> ValidatorId {
        ValidatorId::new([seed; 32])
    }

    fn make_pubkey(seed: u8) -> ParticipantPublicKey {
        let b = if seed == 0 { 1 } else { seed };
        ParticipantPublicKey::from_bytes([b; 32]).expect("valid pubkey")
    }

    fn make_group_pubkey() -> GroupPublicKey {
        GroupPublicKey::from_bytes([0x01; 32]).expect("valid group pubkey")
    }

    fn make_member(id_byte: u8, stake: u64) -> CoordinatorMember {
        CoordinatorMember::with_timestamp(
            make_common_coord_id(id_byte),
            make_validator_id(id_byte),
            make_pubkey(id_byte),
            stake,
            1700000000,
        )
    }

    fn make_committee() -> CoordinatorCommittee {
        let members = vec![
            make_member(0x01, 1000),
            make_member(0x02, 2000),
            make_member(0x03, 3000),
        ];
        CoordinatorCommittee::new(members, 2, 1, 1700000000, 3600, make_group_pubkey())
            .expect("valid committee")
    }

    fn make_key_share(seed: u8) -> KeyShare {
        KeyShare::new(1, vec![seed; 32], [seed; 32])
    }

    fn make_config() -> MultiCoordinatorConfig {
        MultiCoordinatorConfig::new(30000, 60000, false, 0)
            .expect("valid config")
    }

    fn make_config_optimistic() -> MultiCoordinatorConfig {
        MultiCoordinatorConfig::new(30000, 60000, true, 300)
            .expect("valid config")
    }

    fn make_network(seed: u8) -> Arc<dyn CoordinatorNetwork> {
        Arc::new(MockNetwork::new(make_coord_id(seed)))
    }

    fn make_receipt_data(seed: u8) -> ReceiptData {
        ReceiptData::new(
            CommonWorkloadId::new([seed; 32]),
            [0x02; 32],
            vec![],
            1700000000,
            1,
            1,
        )
    }

    fn make_coordinator(seed: u8) -> MultiCoordinator {
        MultiCoordinator::new(
            make_coord_id(seed),
            make_key_share(seed),
            make_committee(),
            make_network(seed),
            make_config(),
        )
        .expect("valid coordinator")
    }

    // ────────────────────────────────────────────────────────────────────────────
    // CONFIG TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_config_valid() {
        let config = MultiCoordinatorConfig::new(30000, 60000, false, 0);
        assert!(config.is_ok());
    }

    #[test]
    fn test_config_valid_with_optimistic() {
        let config = MultiCoordinatorConfig::new(30000, 60000, true, 300);
        assert!(config.is_ok());
    }

    #[test]
    fn test_config_zero_proposal_timeout() {
        let config = MultiCoordinatorConfig::new(0, 60000, false, 0);
        assert!(matches!(config, Err(ConfigError::InvalidProposalTimeout { .. })));
    }

    #[test]
    fn test_config_zero_signing_timeout() {
        let config = MultiCoordinatorConfig::new(30000, 0, false, 0);
        assert!(matches!(config, Err(ConfigError::InvalidSigningTimeout { .. })));
    }

    #[test]
    fn test_config_optimistic_zero_challenge() {
        let config = MultiCoordinatorConfig::new(30000, 60000, true, 0);
        assert!(matches!(config, Err(ConfigError::InvalidChallengeWindow { .. })));
    }

    #[test]
    fn test_config_no_optimistic_zero_challenge_ok() {
        // Zero challenge window is OK when optimistic is disabled
        let config = MultiCoordinatorConfig::new(30000, 60000, false, 0);
        assert!(config.is_ok());
    }

    #[test]
    fn test_config_getters() {
        let config = make_config_optimistic();
        assert_eq!(config.proposal_timeout_ms(), 30000);
        assert_eq!(config.signing_timeout_ms(), 60000);
        assert!(config.enable_optimistic());
        assert_eq!(config.challenge_window_secs(), 300);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // CONSTRUCTOR TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_new_success() {
        let coord = make_coordinator(0x01);
        assert_eq!(coord.id().as_bytes(), &[0x01; 32]);
        assert_eq!(coord.get_pending_count(), 0);
        assert_eq!(coord.get_signing_session_count(), 0);
    }

    #[test]
    fn test_new_not_committee_member() {
        let result = MultiCoordinator::new(
            make_coord_id(0xFF), // Not a member
            make_key_share(0xFF),
            make_committee(),
            make_network(0xFF),
            make_config(),
        );

        assert!(matches!(
            result,
            Err(MultiCoordinatorError::NotCommitteeMember { .. })
        ));
    }

    #[test]
    fn test_new_invalid_committee() {
        let committee = CoordinatorCommittee::empty(1);

        let result = MultiCoordinator::new(
            make_coord_id(0x01),
            make_key_share(0x01),
            committee,
            make_network(0x01),
            make_config(),
        );

        assert!(matches!(
            result,
            Err(MultiCoordinatorError::InvalidCommittee { .. })
        ));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // GETTER TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_getters() {
        let coord = make_coordinator(0x01);

        assert_eq!(coord.id().as_bytes(), &[0x01; 32]);
        assert_eq!(coord.key_share().index, 1);
        assert_eq!(coord.get_committee().threshold(), 2);
        assert_eq!(coord.get_committee().epoch(), 1);
        assert_eq!(coord.config().proposal_timeout_ms(), 30000);
        assert_eq!(coord.get_pending_count(), 0);
        assert_eq!(coord.get_signing_session_count(), 0);
    }

    #[test]
    fn test_get_committee_immutable() {
        let coord = make_coordinator(0x01);
        let committee = coord.get_committee();

        // Should return reference, not clone
        assert_eq!(committee.member_count(), 3);
        assert_eq!(committee.threshold(), 2);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // PROPOSE RECEIPT TESTS (Async)
    // ────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_propose_receipt_success() {
        let mut coord = make_coordinator(0x01);
        let data = make_receipt_data(0x01);
        let now_ms = 1700000000u64;

        let result = coord.propose_receipt(data, now_ms).await;

        assert!(result.is_ok());
        let wid = result.unwrap();
        assert_eq!(wid.as_bytes(), &[0x01; 32]);
        assert_eq!(coord.get_pending_count(), 1);
    }

    #[tokio::test]
    async fn test_propose_receipt_duplicate() {
        let mut coord = make_coordinator(0x01);
        let data = make_receipt_data(0x01);
        let now_ms = 1700000000u64;

        // First proposal
        let _ = coord.propose_receipt(data.clone(), now_ms).await;

        // Second proposal with same workload_id should fail
        let result = coord.propose_receipt(data, now_ms).await;
        assert!(matches!(result, Err(HandlerError::DuplicateProposal { .. })));
    }

    #[tokio::test]
    async fn test_propose_receipt_invalid_data() {
        let mut coord = make_coordinator(0x01);
        let now_ms = 1700000000u64;

        // Invalid: zero workload_id
        let data = ReceiptData::new(
            CommonWorkloadId::new([0x00; 32]),
            [0x02; 32],
            vec![],
            1700000000,
            1,
            1,
        );

        let result = coord.propose_receipt(data, now_ms).await;
        assert!(matches!(result, Err(HandlerError::InvalidProposal { .. })));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // HANDLE MESSAGE TESTS (Async)
    // ────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_handle_ping() {
        let mut coord = make_coordinator(0x01);
        let now_ms = 1700000000u64;

        let ping = CoordinatorMessage::Ping { timestamp: 1234 };
        let result = coord.handle_message(make_coord_id(0x02), ping, now_ms).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.is_some());

        match response.unwrap() {
            CoordinatorMessage::Pong { timestamp, received_at } => {
                assert_eq!(timestamp, 1234);
                assert_eq!(received_at, now_ms);
            }
            _ => panic!("expected Pong"),
        }
    }

    #[tokio::test]
    async fn test_handle_pong() {
        let mut coord = make_coordinator(0x01);
        let now_ms = 1700000000u64;

        let pong = CoordinatorMessage::Pong {
            timestamp: 1234,
            received_at: 1235,
        };
        let result = coord.handle_message(make_coord_id(0x02), pong, now_ms).await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_handle_propose_from_peer() {
        let mut coord = make_coordinator(0x01);
        let data = make_receipt_data(0x05);
        let now_ms = 1700000000u64;
        let wid = WorkloadId::new([0x05; 32]);
        let session_id = derive_session_id(&wid);

        let msg = CoordinatorMessage::ProposeReceipt {
            session_id,
            data,
            proposer: make_coord_id(0x02),
        };

        let result = coord
            .handle_message(make_coord_id(0x02), msg, now_ms)
            .await;

        assert!(result.is_ok());
        assert_eq!(coord.get_pending_count(), 1);
    }

    #[tokio::test]
    async fn test_handle_vote_advances_consensus() {
        let mut coord = make_coordinator(0x01);
        let data = make_receipt_data(0x05);
        let now_ms = 1700000000u64;

        // First: propose (creates consensus + auto-vote from self)
        let _ = coord.propose_receipt(data, now_ms).await;

        // Second: vote from another peer
        let wid = WorkloadId::new([0x05; 32]);
        let session_id = derive_session_id(&wid);

        let vote_msg = CoordinatorMessage::VoteReceipt {
            session_id,
            workload_id: wid.clone(),
            vote: MessageVote::approve(),
            voter: make_coord_id(0x02),
        };

        let result = coord
            .handle_message(make_coord_id(0x02), vote_msg, now_ms)
            .await;

        assert!(result.is_ok());

        // With threshold 2, two approvals should move to Signing
        let state_name = coord.consensus_state_name(&wid);
        assert!(state_name.is_some());
        // State should be Signing since threshold was met (2 votes with threshold 2)
        assert_eq!(state_name.unwrap(), "Signing");
    }

    // ────────────────────────────────────────────────────────────────────────────
    // QUERY TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_is_consensus_terminal_none() {
        let coord = make_coordinator(0x01);
        let wid = WorkloadId::new([0xFF; 32]);

        assert!(coord.is_consensus_terminal(&wid).is_none());
    }

    #[tokio::test]
    async fn test_is_consensus_terminal_false() {
        let mut coord = make_coordinator(0x01);
        let data = make_receipt_data(0x05);
        let now_ms = 1700000000u64;

        let _ = coord.propose_receipt(data, now_ms).await;
        let wid = WorkloadId::new([0x05; 32]);

        assert_eq!(coord.is_consensus_terminal(&wid), Some(false));
    }

    #[tokio::test]
    async fn test_consensus_state_name() {
        let mut coord = make_coordinator(0x01);
        let data = make_receipt_data(0x05);
        let now_ms = 1700000000u64;

        let _ = coord.propose_receipt(data, now_ms).await;
        let wid = WorkloadId::new([0x05; 32]);

        let name = coord.consensus_state_name(&wid);
        assert!(name.is_some());
        // After proposal + one auto-vote (threshold 2), state should be Voting
        assert_eq!(name.unwrap(), "Voting");
    }

    #[tokio::test]
    async fn test_get_completed_receipt_none() {
        let coord = make_coordinator(0x01);
        let wid = WorkloadId::new([0xFF; 32]);

        assert!(coord.get_completed_receipt(&wid).is_none());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // DEBUG TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_debug_impl() {
        let coord = make_coordinator(0x01);
        let debug = format!("{:?}", coord);

        assert!(debug.contains("MultiCoordinator"));
        assert!(debug.contains("pending_count"));
        assert!(debug.contains("signing_sessions"));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // ERROR DISPLAY TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_config_error_display() {
        let err = ConfigError::InvalidProposalTimeout {
            value: 0,
            reason: "must be > 0".to_string(),
        };
        assert!(err.to_string().contains("proposal_timeout_ms"));

        let err = ConfigError::InvalidSigningTimeout {
            value: 0,
            reason: "must be > 0".to_string(),
        };
        assert!(err.to_string().contains("signing_timeout_ms"));

        let err = ConfigError::InvalidChallengeWindow {
            value: 0,
            reason: "test".to_string(),
        };
        assert!(err.to_string().contains("challenge_window_secs"));
    }

    #[test]
    fn test_multi_coordinator_error_display() {
        let err = MultiCoordinatorError::NotCommitteeMember {
            id: make_coord_id(0xFF),
        };
        assert!(err.to_string().contains("not a committee member"));

        let err = MultiCoordinatorError::InvalidCommittee {
            reason: "test".to_string(),
        };
        assert!(err.to_string().contains("invalid committee"));
    }

    #[test]
    fn test_error_from_config() {
        let config_err = ConfigError::InvalidProposalTimeout {
            value: 0,
            reason: "test".to_string(),
        };
        let err: MultiCoordinatorError = config_err.into();
        assert!(matches!(err, MultiCoordinatorError::Config(_)));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // NO PANIC VERIFICATION
    // ────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_multiple_proposals_different_workloads() {
        let mut coord = make_coordinator(0x01);
        let now_ms = 1700000000u64;

        for seed in 1u8..=5 {
            let data = make_receipt_data(seed);
            let result = coord.propose_receipt(data, now_ms).await;
            assert!(result.is_ok());
        }

        assert_eq!(coord.get_pending_count(), 5);
    }

    #[tokio::test]
    async fn test_handle_message_invalid_voter() {
        let mut coord = make_coordinator(0x01);
        let now_ms = 1700000000u64;

        let msg = CoordinatorMessage::ProposeReceipt {
            session_id: SessionId::new([0x01; 32]),
            data: make_receipt_data(0x01),
            proposer: make_coord_id(0xFF), // Not a member
        };

        let result = coord
            .handle_message(make_coord_id(0xFF), msg, now_ms)
            .await;

        assert!(result.is_err());
    }
}