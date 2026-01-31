//! Signing Session Integration (14A.2B.2.18)
//!
//! Module ini mengintegrasikan TSS signing session dengan consensus flow.
//! Signing hanya boleh terjadi SETELAH voting threshold tercapai.
//!
//! # Invariants
//!
//! - Signing HANYA boleh terjadi setelah consensus mencapai Signing state
//! - Commitments hanya boleh masuk di CollectingCommitments
//! - Partials hanya boleh masuk di CollectingSignatures  
//! - Aggregating hanya boleh terjadi jika quorum tercapai
//! - Completed dan Failed adalah terminal states
//!
//! # Usage
//!
//! ```ignore
//! use dsdn_coordinator::multi::{SigningSession, SigningState};
//!
//! // Initiate signing after consensus threshold
//! let session = SigningSession::new(session_id, workload_id, threshold);
//!
//! // Add commitments
//! session.add_commitment(coord_id, commitment)?;
//!
//! // After quorum commitments, add partials
//! session.add_partial(coord_id, partial)?;
//!
//! // Aggregate when quorum partials reached
//! let result = session.try_aggregate()?;
//! ```

use std::collections::HashMap;
use std::fmt;

use dsdn_proto::tss::signing::{PartialSignatureProto, SigningCommitmentProto};

use super::{CoordinatorId, SessionId, WorkloadId};

// ════════════════════════════════════════════════════════════════════════════════
// SIGNING ERROR
// ════════════════════════════════════════════════════════════════════════════════

/// Error type untuk signing failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningError {
    /// State tidak valid untuk operasi.
    InvalidState {
        /// State saat ini.
        current: String,
        /// Operasi yang dicoba.
        operation: String,
    },

    /// Duplicate commitment dari coordinator.
    DuplicateCommitment {
        /// CoordinatorId yang duplikat.
        coordinator: CoordinatorId,
    },

    /// Duplicate partial signature dari coordinator.
    DuplicatePartial {
        /// CoordinatorId yang duplikat.
        coordinator: CoordinatorId,
    },

    /// Signatures tidak cukup untuk aggregation.
    InsufficientSignatures {
        /// Threshold yang dibutuhkan.
        required: u8,
        /// Jumlah yang didapat.
        got: u8,
    },

    /// Aggregation gagal.
    AggregationFailed {
        /// Alasan kegagalan.
        reason: String,
    },

    /// Session tidak ditemukan.
    SessionNotFound {
        /// Session ID yang dicari.
        session_id: SessionId,
    },

    /// Coordinator bukan anggota committee.
    InvalidCoordinator {
        /// CoordinatorId yang tidak valid.
        coordinator: CoordinatorId,
    },

    /// Commitment tidak valid.
    InvalidCommitment {
        /// Alasan.
        reason: String,
    },

    /// Partial signature tidak valid.
    InvalidPartial {
        /// Alasan.
        reason: String,
    },
}

impl fmt::Display for SigningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SigningError::InvalidState { current, operation } => {
                write!(
                    f,
                    "invalid state {} for operation {}",
                    current, operation
                )
            }
            SigningError::DuplicateCommitment { coordinator } => {
                write!(
                    f,
                    "duplicate commitment from {:?}",
                    coordinator.as_bytes()
                )
            }
            SigningError::DuplicatePartial { coordinator } => {
                write!(
                    f,
                    "duplicate partial from {:?}",
                    coordinator.as_bytes()
                )
            }
            SigningError::InsufficientSignatures { required, got } => {
                write!(
                    f,
                    "insufficient signatures: required {}, got {}",
                    required, got
                )
            }
            SigningError::AggregationFailed { reason } => {
                write!(f, "aggregation failed: {}", reason)
            }
            SigningError::SessionNotFound { session_id } => {
                write!(f, "session not found: {:?}", session_id.as_bytes())
            }
            SigningError::InvalidCoordinator { coordinator } => {
                write!(
                    f,
                    "invalid coordinator: {:?}",
                    coordinator.as_bytes()
                )
            }
            SigningError::InvalidCommitment { reason } => {
                write!(f, "invalid commitment: {}", reason)
            }
            SigningError::InvalidPartial { reason } => {
                write!(f, "invalid partial: {}", reason)
            }
        }
    }
}

impl std::error::Error for SigningError {}

// ════════════════════════════════════════════════════════════════════════════════
// SIGNING STATE
// ════════════════════════════════════════════════════════════════════════════════

/// State dalam signing session lifecycle.
///
/// State machine bersifat linear dengan terminal states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningState {
    /// Mengumpulkan commitments dari coordinators.
    CollectingCommitments,

    /// Mengumpulkan partial signatures.
    CollectingSignatures,

    /// Melakukan aggregation.
    Aggregating,

    /// Signing selesai dengan sukses.
    Completed,

    /// Signing gagal.
    Failed {
        /// Error yang menyebabkan failure.
        error: SigningError,
    },
}

impl SigningState {
    /// Mengembalikan nama state sebagai string.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            SigningState::CollectingCommitments => "CollectingCommitments",
            SigningState::CollectingSignatures => "CollectingSignatures",
            SigningState::Aggregating => "Aggregating",
            SigningState::Completed => "Completed",
            SigningState::Failed { .. } => "Failed",
        }
    }

    /// Memeriksa apakah state adalah terminal.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, SigningState::Completed | SigningState::Failed { .. })
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// SIGNING SESSION
// ════════════════════════════════════════════════════════════════════════════════

/// Signing session untuk threshold signature.
///
/// Manages the collection of commitments and partial signatures
/// from committee members.
///
/// # Lifecycle
///
/// ```text
/// CollectingCommitments ──(quorum)──► CollectingSignatures ──(quorum)──► Aggregating ──► Completed
///         │                                   │                               │
///         └───────────────────────────────────┴───────────────────────────────┴──► Failed
/// ```
///
/// # Thread Safety
///
/// Struct ini TIDAK thread-safe secara internal.
/// Semua mutasi melalui `&mut self`.
pub struct SigningSession {
    /// Session identifier.
    session_id: SessionId,

    /// Workload identifier.
    workload_id: WorkloadId,

    /// Commitments dari coordinators.
    commitments: HashMap<CoordinatorId, SigningCommitmentProto>,

    /// Partial signatures dari coordinators.
    partials: HashMap<CoordinatorId, PartialSignatureProto>,

    /// Current state.
    state: SigningState,

    /// Threshold untuk quorum.
    threshold: u8,

    /// Aggregated signature bytes (set after successful aggregation).
    aggregated_signature: Option<Vec<u8>>,

    /// Signers yang berpartisipasi (set after aggregation).
    signers: Vec<CoordinatorId>,
}

impl SigningSession {
    /// Membuat SigningSession baru.
    ///
    /// # Arguments
    ///
    /// * `session_id` - Session identifier
    /// * `workload_id` - Workload identifier
    /// * `threshold` - Threshold untuk quorum
    ///
    /// # State
    ///
    /// State awal adalah `CollectingCommitments`.
    #[must_use]
    pub fn new(session_id: SessionId, workload_id: WorkloadId, threshold: u8) -> Self {
        Self {
            session_id,
            workload_id,
            commitments: HashMap::new(),
            partials: HashMap::new(),
            state: SigningState::CollectingCommitments,
            threshold,
            aggregated_signature: None,
            signers: Vec::new(),
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // GETTERS
    // ────────────────────────────────────────────────────────────────────────────

    /// Mengembalikan session_id.
    #[must_use]
    #[inline]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Mengembalikan workload_id.
    #[must_use]
    #[inline]
    pub const fn workload_id(&self) -> &WorkloadId {
        &self.workload_id
    }

    /// Mengembalikan current state.
    #[must_use]
    #[inline]
    pub const fn state(&self) -> &SigningState {
        &self.state
    }

    /// Mengembalikan threshold.
    #[must_use]
    #[inline]
    pub const fn threshold(&self) -> u8 {
        self.threshold
    }

    /// Mengembalikan jumlah commitments.
    #[must_use]
    #[inline]
    pub fn commitment_count(&self) -> usize {
        self.commitments.len()
    }

    /// Mengembalikan jumlah partials.
    #[must_use]
    #[inline]
    pub fn partial_count(&self) -> usize {
        self.partials.len()
    }

    /// Memeriksa apakah state adalah terminal.
    #[must_use]
    #[inline]
    pub const fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }

    /// Mengembalikan aggregated signature jika ada.
    #[must_use]
    pub fn aggregated_signature(&self) -> Option<&[u8]> {
        self.aggregated_signature.as_deref()
    }

    /// Mengembalikan signers.
    #[must_use]
    pub fn signers(&self) -> &[CoordinatorId] {
        &self.signers
    }

    /// Memeriksa apakah sudah mencapai commitment quorum.
    #[must_use]
    pub fn has_commitment_quorum(&self) -> bool {
        self.commitments.len() >= self.threshold as usize
    }

    /// Memeriksa apakah sudah mencapai partial quorum.
    #[must_use]
    pub fn has_partial_quorum(&self) -> bool {
        self.partials.len() >= self.threshold as usize
    }

    /// Memeriksa apakah coordinator sudah submit commitment.
    #[must_use]
    pub fn has_commitment_from(&self, coordinator: &CoordinatorId) -> bool {
        self.commitments.contains_key(coordinator)
    }

    /// Memeriksa apakah coordinator sudah submit partial.
    #[must_use]
    pub fn has_partial_from(&self, coordinator: &CoordinatorId) -> bool {
        self.partials.contains_key(coordinator)
    }

    // ────────────────────────────────────────────────────────────────────────────
    // STATE MUTATIONS
    // ────────────────────────────────────────────────────────────────────────────

    /// Menambahkan commitment dari coordinator.
    ///
    /// # Arguments
    ///
    /// * `coordinator` - CoordinatorId yang mengirim
    /// * `commitment` - SigningCommitmentProto
    ///
    /// # Returns
    ///
    /// - `Ok(true)` jika commitment quorum tercapai
    /// - `Ok(false)` jika belum quorum
    /// - `Err(SigningError)` jika gagal
    ///
    /// # Rules
    ///
    /// - State HARUS CollectingCommitments
    /// - Duplicate ditolak
    pub fn add_commitment(
        &mut self,
        coordinator: CoordinatorId,
        commitment: SigningCommitmentProto,
    ) -> Result<bool, SigningError> {
        // Validate state
        if !matches!(self.state, SigningState::CollectingCommitments) {
            return Err(SigningError::InvalidState {
                current: self.state.name().to_string(),
                operation: "add_commitment".to_string(),
            });
        }

        // Check for duplicate
        if self.commitments.contains_key(&coordinator) {
            return Err(SigningError::DuplicateCommitment { coordinator });
        }

        // Validate commitment (basic validation)
        if commitment.session_id.is_empty() {
            return Err(SigningError::InvalidCommitment {
                reason: "empty session_id".to_string(),
            });
        }

        // Add commitment
        self.commitments.insert(coordinator, commitment);

        // Check quorum
        let quorum_reached = self.has_commitment_quorum();
        if quorum_reached {
            self.state = SigningState::CollectingSignatures;
        }

        Ok(quorum_reached)
    }

    /// Menambahkan partial signature dari coordinator.
    ///
    /// # Arguments
    ///
    /// * `coordinator` - CoordinatorId yang mengirim
    /// * `partial` - PartialSignatureProto
    ///
    /// # Returns
    ///
    /// - `Ok(true)` jika partial quorum tercapai (ready for aggregation)
    /// - `Ok(false)` jika belum quorum
    /// - `Err(SigningError)` jika gagal
    ///
    /// # Rules
    ///
    /// - State HARUS CollectingSignatures
    /// - Coordinator HARUS sudah submit commitment
    /// - Duplicate ditolak
    pub fn add_partial(
        &mut self,
        coordinator: CoordinatorId,
        partial: PartialSignatureProto,
    ) -> Result<bool, SigningError> {
        // Validate state
        if !matches!(self.state, SigningState::CollectingSignatures) {
            return Err(SigningError::InvalidState {
                current: self.state.name().to_string(),
                operation: "add_partial".to_string(),
            });
        }

        // Check coordinator has commitment
        if !self.commitments.contains_key(&coordinator) {
            return Err(SigningError::InvalidCoordinator { coordinator });
        }

        // Check for duplicate
        if self.partials.contains_key(&coordinator) {
            return Err(SigningError::DuplicatePartial { coordinator });
        }

        // Validate partial (basic validation)
        if partial.session_id.is_empty() {
            return Err(SigningError::InvalidPartial {
                reason: "empty session_id".to_string(),
            });
        }

        // Add partial
        self.partials.insert(coordinator, partial);

        // Check quorum
        let quorum_reached = self.has_partial_quorum();
        if quorum_reached {
            self.state = SigningState::Aggregating;
        }

        Ok(quorum_reached)
    }

    /// Mencoba melakukan aggregation.
    ///
    /// # Returns
    ///
    /// - `Ok(Vec<u8>)` - Aggregated signature bytes
    /// - `Err(SigningError)` jika gagal
    ///
    /// # Rules
    ///
    /// - State HARUS Aggregating
    /// - Partials >= threshold
    pub fn try_aggregate(&mut self) -> Result<Vec<u8>, SigningError> {
        // Validate state
        if !matches!(self.state, SigningState::Aggregating) {
            return Err(SigningError::InvalidState {
                current: self.state.name().to_string(),
                operation: "try_aggregate".to_string(),
            });
        }

        // Verify quorum
        let partial_count = self.partials.len() as u8;
        if partial_count < self.threshold {
            self.state = SigningState::Failed {
                error: SigningError::InsufficientSignatures {
                    required: self.threshold,
                    got: partial_count,
                },
            };
            return Err(SigningError::InsufficientSignatures {
                required: self.threshold,
                got: partial_count,
            });
        }

        // Collect signers
        self.signers = self.partials.keys().cloned().collect();
        self.signers.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

        // Perform aggregation
        // Note: This is a placeholder - actual TSS aggregation would use dsdn_tss
        // For now, we create a deterministic "aggregate" from the partials
        let aggregate = self.perform_aggregation()?;

        // Store result
        self.aggregated_signature = Some(aggregate.clone());
        self.state = SigningState::Completed;

        Ok(aggregate)
    }

    /// Mark session as failed.
    pub fn mark_failed(&mut self, error: SigningError) {
        if !self.state.is_terminal() {
            self.state = SigningState::Failed { error };
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // INTERNAL
    // ────────────────────────────────────────────────────────────────────────────

    /// Perform actual aggregation.
    ///
    /// Note: This is a simplified implementation. Real aggregation
    /// would use the TSS library.
    fn perform_aggregation(&self) -> Result<Vec<u8>, SigningError> {
        // Collect signature shares in deterministic order
        let mut shares: Vec<_> = self.partials.iter().collect();
        shares.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));

        // Build aggregate (placeholder - real impl would use FROST)
        // For now, we concatenate and hash to create deterministic output
        let mut aggregate_data = Vec::new();
        aggregate_data.extend_from_slice(self.session_id.as_bytes());
        aggregate_data.extend_from_slice(self.workload_id.as_bytes());

        for (coord_id, partial) in &shares {
            aggregate_data.extend_from_slice(coord_id.as_bytes());
            aggregate_data.extend_from_slice(&partial.signature_share);
        }

        // Create deterministic 129-byte "aggregate" (matches AggregateSignature size)
        // First byte is signer count, rest is pseudo-signature
        let mut result = vec![0u8; 129];
        result[0] = shares.len() as u8;

        // Use SHA3 to derive deterministic bytes
        use sha3::{Digest, Sha3_256};
        let hash = Sha3_256::digest(&aggregate_data);
        
        // Fill result with hash bytes (repeated if needed)
        for (i, byte) in result.iter_mut().skip(1).enumerate() {
            *byte = hash[i % 32];
        }

        Ok(result)
    }
}

impl fmt::Debug for SigningSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningSession")
            .field("session_id", &self.session_id)
            .field("workload_id", &self.workload_id)
            .field("state", &self.state)
            .field("threshold", &self.threshold)
            .field("commitment_count", &self.commitments.len())
            .field("partial_count", &self.partials.len())
            .finish()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════════

/// Generate deterministic session_id from workload_id.
///
/// Ensures same workload always gets same session.
#[must_use]
pub fn derive_session_id(workload_id: &WorkloadId) -> SessionId {
    use sha3::{Digest, Sha3_256};

    let mut hasher = Sha3_256::new();
    hasher.update(b"DSDN_SIGNING_SESSION_V1");
    hasher.update(workload_id.as_bytes());

    let hash = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);

    SessionId::new(bytes)
}

/// Validate a SigningCommitmentProto.
///
/// # Returns
///
/// - `Ok(())` if valid
/// - `Err(SigningError)` if invalid
pub fn validate_commitment(commitment: &SigningCommitmentProto) -> Result<(), SigningError> {
    if commitment.session_id.is_empty() {
        return Err(SigningError::InvalidCommitment {
            reason: "empty session_id".to_string(),
        });
    }

    if commitment.signer_id.is_empty() {
        return Err(SigningError::InvalidCommitment {
            reason: "empty signer_id".to_string(),
        });
    }

    if commitment.hiding.is_empty() {
        return Err(SigningError::InvalidCommitment {
            reason: "empty hiding commitment".to_string(),
        });
    }

    if commitment.binding.is_empty() {
        return Err(SigningError::InvalidCommitment {
            reason: "empty binding commitment".to_string(),
        });
    }

    Ok(())
}

/// Validate a PartialSignatureProto.
///
/// # Returns
///
/// - `Ok(())` if valid
/// - `Err(SigningError)` if invalid
pub fn validate_partial(partial: &PartialSignatureProto) -> Result<(), SigningError> {
    if partial.session_id.is_empty() {
        return Err(SigningError::InvalidPartial {
            reason: "empty session_id".to_string(),
        });
    }

    if partial.signer_id.is_empty() {
        return Err(SigningError::InvalidPartial {
            reason: "empty signer_id".to_string(),
        });
    }

    if partial.signature_share.is_empty() {
        return Err(SigningError::InvalidPartial {
            reason: "empty signature_share".to_string(),
        });
    }

    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session_id(seed: u8) -> SessionId {
        SessionId::new([seed; 32])
    }

    fn make_workload_id(seed: u8) -> WorkloadId {
        WorkloadId::new([seed; 32])
    }

    fn make_coord_id(seed: u8) -> CoordinatorId {
        CoordinatorId::new([seed; 32])
    }

    fn make_commitment(seed: u8) -> SigningCommitmentProto {
        SigningCommitmentProto {
            session_id: vec![seed; 32],
            signer_id: vec![seed; 32],
            hiding: vec![seed; 32],
            binding: vec![seed; 32],
            timestamp: 1700000000,
        }
    }

    fn make_partial(seed: u8) -> PartialSignatureProto {
        PartialSignatureProto {
            session_id: vec![seed; 32],
            signer_id: vec![seed; 32],
            signature_share: vec![seed; 32],
            commitment: make_commitment(seed),
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // SigningError Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_signing_error_display() {
        let err = SigningError::DuplicateCommitment {
            coordinator: make_coord_id(0x01),
        };
        assert!(err.to_string().contains("duplicate"));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // SigningState Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_signing_state_name() {
        assert_eq!(SigningState::CollectingCommitments.name(), "CollectingCommitments");
        assert_eq!(SigningState::CollectingSignatures.name(), "CollectingSignatures");
        assert_eq!(SigningState::Aggregating.name(), "Aggregating");
        assert_eq!(SigningState::Completed.name(), "Completed");
    }

    #[test]
    fn test_signing_state_is_terminal() {
        assert!(!SigningState::CollectingCommitments.is_terminal());
        assert!(!SigningState::CollectingSignatures.is_terminal());
        assert!(!SigningState::Aggregating.is_terminal());
        assert!(SigningState::Completed.is_terminal());
        assert!(SigningState::Failed {
            error: SigningError::AggregationFailed {
                reason: "test".to_string(),
            }
        }
        .is_terminal());
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // SigningSession Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_session_new() {
        let session = SigningSession::new(
            make_session_id(0x01),
            make_workload_id(0x02),
            2,
        );

        assert_eq!(session.threshold(), 2);
        assert_eq!(session.commitment_count(), 0);
        assert_eq!(session.partial_count(), 0);
        assert_eq!(session.state().name(), "CollectingCommitments");
    }

    #[test]
    fn test_add_commitment_success() {
        let mut session = SigningSession::new(
            make_session_id(0x01),
            make_workload_id(0x02),
            2,
        );

        let result = session.add_commitment(
            make_coord_id(0x01),
            make_commitment(0x01),
        );

        assert!(result.is_ok());
        assert!(!result.unwrap()); // Not quorum yet
        assert_eq!(session.commitment_count(), 1);
    }

    #[test]
    fn test_add_commitment_quorum() {
        let mut session = SigningSession::new(
            make_session_id(0x01),
            make_workload_id(0x02),
            2,
        );

        session.add_commitment(make_coord_id(0x01), make_commitment(0x01)).unwrap();
        let result = session.add_commitment(make_coord_id(0x02), make_commitment(0x02));

        assert!(result.is_ok());
        assert!(result.unwrap()); // Quorum reached
        assert_eq!(session.state().name(), "CollectingSignatures");
    }

    #[test]
    fn test_add_commitment_duplicate() {
        let mut session = SigningSession::new(
            make_session_id(0x01),
            make_workload_id(0x02),
            2,
        );

        session.add_commitment(make_coord_id(0x01), make_commitment(0x01)).unwrap();
        let result = session.add_commitment(make_coord_id(0x01), make_commitment(0x01));

        assert!(matches!(result, Err(SigningError::DuplicateCommitment { .. })));
    }

    #[test]
    fn test_add_commitment_wrong_state() {
        let mut session = SigningSession::new(
            make_session_id(0x01),
            make_workload_id(0x02),
            2,
        );

        // Move to CollectingSignatures
        session.add_commitment(make_coord_id(0x01), make_commitment(0x01)).unwrap();
        session.add_commitment(make_coord_id(0x02), make_commitment(0x02)).unwrap();

        // Try to add commitment in wrong state
        let result = session.add_commitment(make_coord_id(0x03), make_commitment(0x03));

        assert!(matches!(result, Err(SigningError::InvalidState { .. })));
    }

    #[test]
    fn test_add_partial_success() {
        let mut session = SigningSession::new(
            make_session_id(0x01),
            make_workload_id(0x02),
            2,
        );

        // Move to CollectingSignatures
        session.add_commitment(make_coord_id(0x01), make_commitment(0x01)).unwrap();
        session.add_commitment(make_coord_id(0x02), make_commitment(0x02)).unwrap();

        // Add partial
        let result = session.add_partial(make_coord_id(0x01), make_partial(0x01));

        assert!(result.is_ok());
        assert!(!result.unwrap()); // Not quorum yet
        assert_eq!(session.partial_count(), 1);
    }

    #[test]
    fn test_add_partial_quorum() {
        let mut session = SigningSession::new(
            make_session_id(0x01),
            make_workload_id(0x02),
            2,
        );

        // Move to CollectingSignatures
        session.add_commitment(make_coord_id(0x01), make_commitment(0x01)).unwrap();
        session.add_commitment(make_coord_id(0x02), make_commitment(0x02)).unwrap();

        // Add partials
        session.add_partial(make_coord_id(0x01), make_partial(0x01)).unwrap();
        let result = session.add_partial(make_coord_id(0x02), make_partial(0x02));

        assert!(result.is_ok());
        assert!(result.unwrap()); // Quorum reached
        assert_eq!(session.state().name(), "Aggregating");
    }

    #[test]
    fn test_add_partial_no_commitment() {
        let mut session = SigningSession::new(
            make_session_id(0x01),
            make_workload_id(0x02),
            2,
        );

        // Move to CollectingSignatures
        session.add_commitment(make_coord_id(0x01), make_commitment(0x01)).unwrap();
        session.add_commitment(make_coord_id(0x02), make_commitment(0x02)).unwrap();

        // Try to add partial from coordinator without commitment
        let result = session.add_partial(make_coord_id(0x03), make_partial(0x03));

        assert!(matches!(result, Err(SigningError::InvalidCoordinator { .. })));
    }

    #[test]
    fn test_add_partial_duplicate() {
        let mut session = SigningSession::new(
            make_session_id(0x01),
            make_workload_id(0x02),
            2,
        );

        // Move to CollectingSignatures
        session.add_commitment(make_coord_id(0x01), make_commitment(0x01)).unwrap();
        session.add_commitment(make_coord_id(0x02), make_commitment(0x02)).unwrap();

        // Add partial
        session.add_partial(make_coord_id(0x01), make_partial(0x01)).unwrap();

        // Try duplicate
        let result = session.add_partial(make_coord_id(0x01), make_partial(0x01));

        assert!(matches!(result, Err(SigningError::DuplicatePartial { .. })));
    }

    #[test]
    fn test_try_aggregate_success() {
        let mut session = SigningSession::new(
            make_session_id(0x01),
            make_workload_id(0x02),
            2,
        );

        // Collect commitments
        session.add_commitment(make_coord_id(0x01), make_commitment(0x01)).unwrap();
        session.add_commitment(make_coord_id(0x02), make_commitment(0x02)).unwrap();

        // Collect partials
        session.add_partial(make_coord_id(0x01), make_partial(0x01)).unwrap();
        session.add_partial(make_coord_id(0x02), make_partial(0x02)).unwrap();

        // Aggregate
        let result = session.try_aggregate();

        assert!(result.is_ok());
        assert_eq!(session.state().name(), "Completed");
        assert!(session.aggregated_signature().is_some());
        assert_eq!(session.signers().len(), 2);
    }

    #[test]
    fn test_try_aggregate_wrong_state() {
        let mut session = SigningSession::new(
            make_session_id(0x01),
            make_workload_id(0x02),
            2,
        );

        let result = session.try_aggregate();

        assert!(matches!(result, Err(SigningError::InvalidState { .. })));
    }

    #[test]
    fn test_aggregation_deterministic() {
        let mut session1 = SigningSession::new(
            make_session_id(0x01),
            make_workload_id(0x02),
            2,
        );

        let mut session2 = SigningSession::new(
            make_session_id(0x01),
            make_workload_id(0x02),
            2,
        );

        // Same inputs for both
        for s in [&mut session1, &mut session2] {
            s.add_commitment(make_coord_id(0x01), make_commitment(0x01)).unwrap();
            s.add_commitment(make_coord_id(0x02), make_commitment(0x02)).unwrap();
            s.add_partial(make_coord_id(0x01), make_partial(0x01)).unwrap();
            s.add_partial(make_coord_id(0x02), make_partial(0x02)).unwrap();
        }

        let sig1 = session1.try_aggregate().unwrap();
        let sig2 = session2.try_aggregate().unwrap();

        assert_eq!(sig1, sig2);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Helper Function Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_derive_session_id_deterministic() {
        let workload = make_workload_id(0x01);

        let session1 = derive_session_id(&workload);
        let session2 = derive_session_id(&workload);

        assert_eq!(session1, session2);
    }

    #[test]
    fn test_derive_session_id_different_workloads() {
        let workload1 = make_workload_id(0x01);
        let workload2 = make_workload_id(0x02);

        let session1 = derive_session_id(&workload1);
        let session2 = derive_session_id(&workload2);

        assert_ne!(session1, session2);
    }

    #[test]
    fn test_validate_commitment_valid() {
        let commitment = make_commitment(0x01);
        assert!(validate_commitment(&commitment).is_ok());
    }

    #[test]
    fn test_validate_commitment_empty_session() {
        let mut commitment = make_commitment(0x01);
        commitment.session_id = vec![];

        assert!(matches!(
            validate_commitment(&commitment),
            Err(SigningError::InvalidCommitment { .. })
        ));
    }

    #[test]
    fn test_validate_partial_valid() {
        let partial = make_partial(0x01);
        assert!(validate_partial(&partial).is_ok());
    }

    #[test]
    fn test_validate_partial_empty_share() {
        let mut partial = make_partial(0x01);
        partial.signature_share = vec![];

        assert!(matches!(
            validate_partial(&partial),
            Err(SigningError::InvalidPartial { .. })
        ));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Debug Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_session_debug() {
        let session = SigningSession::new(
            make_session_id(0x01),
            make_workload_id(0x02),
            2,
        );

        let debug = format!("{:?}", session);
        assert!(debug.contains("SigningSession"));
        assert!(debug.contains("threshold"));
    }
}