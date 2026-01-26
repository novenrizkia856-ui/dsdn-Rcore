//! # Signing Session Controller
//!
//! Module ini menyediakan `SigningSession` sebagai stateful controller
//! untuk mengelola lifecycle FROST threshold signing.
//!
//! ## Lifecycle
//!
//! ```text
//! ┌───────────────────────────────────────────────────────────────────────────┐
//! │                      SigningSession Lifecycle                              │
//! └───────────────────────────────────────────────────────────────────────────┘
//!
//!   new() ──► Initialized
//!                 │
//!                 │ add_commitment() × n
//!                 ▼
//!            CommitmentPhase
//!                 │
//!                 │ finalize_commitments()
//!                 ▼
//!            SigningPhase
//!                 │
//!                 │ add_partial_signature() × n
//!                 │ complete(aggregate)
//!                 ▼
//!            Completed
//! ```
//!
//! ## Error Handling
//!
//! Semua method yang dapat gagal mengembalikan `Result<_, SigningError>`.
//! Tidak ada panic atau unwrap dalam implementasi.

use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use sha3::{Digest, Sha3_256};

use crate::error::SigningError;
use crate::types::{SessionId, SignerId};

use super::state::SigningState;
use super::{AggregateSignature, PartialSignature, SigningCommitment};

// ════════════════════════════════════════════════════════════════════════════════
// SIGNING SESSION
// ════════════════════════════════════════════════════════════════════════════════

/// Controller untuk mengelola signing session lifecycle.
///
/// `SigningSession` adalah stateful controller yang mengelola:
/// - Message to sign
/// - Signer registration
/// - Commitment collection
/// - Partial signature collection
/// - State transitions
///
/// ## Invariant
///
/// - `threshold` selalu >= 2
/// - `threshold` selalu <= `signers.len()`
/// - Tidak ada duplicate signers
///
/// ## Contoh
///
/// ```rust
/// use dsdn_tss::signing::SigningSession;
/// use dsdn_tss::{SessionId, SignerId, SigningCommitment};
///
/// // Create session
/// let session_id = SessionId::new();
/// let signers = vec![SignerId::new(), SignerId::new(), SignerId::new()];
/// let message = b"message to sign".to_vec();
///
/// let mut session = SigningSession::new(session_id, message, signers, 2).unwrap();
///
/// // Add commitments...
/// ```
#[derive(Debug, Clone)]
pub struct SigningSession {
    /// Session identifier.
    session_id: SessionId,

    /// Message to be signed.
    message: Vec<u8>,

    /// SHA3-256 hash of the message.
    message_hash: [u8; 32],

    /// List of authorized signers.
    signers: Vec<SignerId>,

    /// Threshold required for valid signature.
    threshold: u8,

    /// Current state dalam state machine.
    state: SigningState,

    /// Unix timestamp (dalam detik) saat session dibuat.
    created_at: u64,

    /// Commitments yang sudah dikumpulkan.
    commitments: HashMap<SignerId, SigningCommitment>,

    /// Partial signatures yang sudah dikumpulkan.
    partial_signatures: HashMap<SignerId, PartialSignature>,
}

impl SigningSession {
    /// Membuat SigningSession baru.
    ///
    /// # Arguments
    ///
    /// * `session_id` - Identifier unik untuk session
    /// * `message` - Message yang akan di-sign
    /// * `signers` - List signer yang authorized
    /// * `threshold` - Threshold signature yang diperlukan
    ///
    /// # Validasi
    ///
    /// - `signers.len()` >= `threshold`
    /// - `threshold` >= 2
    /// - Tidak boleh ada duplicate signers
    ///
    /// # Errors
    ///
    /// - `SigningError::InsufficientSignatures` jika signers.len() < threshold
    /// - `SigningError::DuplicateSigner` jika ada signer duplikat
    pub fn new(
        session_id: SessionId,
        message: Vec<u8>,
        signers: Vec<SignerId>,
        threshold: u8,
    ) -> Result<Self, SigningError> {
        // Validasi: threshold >= 2
        if threshold < 2 {
            return Err(SigningError::InsufficientSignatures {
                expected: 2,
                got: threshold as usize,
            });
        }

        // Validasi: signers.len() >= threshold
        if signers.len() < threshold as usize {
            return Err(SigningError::InsufficientSignatures {
                expected: threshold,
                got: signers.len(),
            });
        }

        // Validasi: tidak ada duplicate signers
        let mut seen = HashSet::with_capacity(signers.len());
        for signer in &signers {
            if !seen.insert(signer.clone()) {
                return Err(SigningError::DuplicateSigner {
                    signer: signer.clone(),
                });
            }
        }

        // Compute message hash
        let message_hash = compute_message_hash(&message);

        // Get current timestamp
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Ok(Self {
            session_id,
            message,
            message_hash,
            signers,
            threshold,
            state: SigningState::Initialized,
            created_at,
            commitments: HashMap::new(),
            partial_signatures: HashMap::new(),
        })
    }

    // ────────────────────────────────────────────────────────────────────────────
    // STATE QUERIES (no side effects)
    // ────────────────────────────────────────────────────────────────────────────

    /// Mengembalikan session ID.
    #[must_use]
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Mengembalikan message.
    #[must_use]
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// Mengembalikan message hash.
    #[must_use]
    pub fn message_hash(&self) -> &[u8; 32] {
        &self.message_hash
    }

    /// Mengembalikan slice signers.
    #[must_use]
    pub fn signers(&self) -> &[SignerId] {
        &self.signers
    }

    /// Mengembalikan threshold.
    #[must_use]
    pub const fn threshold(&self) -> u8 {
        self.threshold
    }

    /// Mengembalikan current state.
    #[must_use]
    pub fn state(&self) -> &SigningState {
        &self.state
    }

    /// Mengembalikan timestamp pembuatan session.
    #[must_use]
    pub const fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Mengecek apakah signing sudah selesai (Completed state).
    #[must_use]
    pub fn is_complete(&self) -> bool {
        matches!(self.state, SigningState::Completed { .. })
    }

    /// Mengecek apakah signing gagal (Failed state).
    #[must_use]
    pub fn is_failed(&self) -> bool {
        matches!(self.state, SigningState::Failed { .. })
    }

    /// Mengecek apakah signer_id terdaftar dalam session.
    #[must_use]
    pub fn is_signer(&self, signer_id: &SignerId) -> bool {
        self.signers.iter().any(|s| s == signer_id)
    }

    // ────────────────────────────────────────────────────────────────────────────
    // COMMITMENT PHASE
    // ────────────────────────────────────────────────────────────────────────────

    /// Menambahkan commitment dari signer.
    ///
    /// # Arguments
    ///
    /// * `signer` - Signer ID
    /// * `commitment` - Signing commitment dari signer
    ///
    /// # Errors
    ///
    /// - `SigningError::AggregationFailed` jika state bukan Initialized/CommitmentPhase
    /// - `SigningError::SignerNotInCommittee` jika signer tidak terdaftar
    /// - `SigningError::DuplicateSigner` jika commitment sudah ada
    pub fn add_commitment(
        &mut self,
        signer: SignerId,
        commitment: SigningCommitment,
    ) -> Result<(), SigningError> {
        // Validasi state
        match &self.state {
            SigningState::Initialized | SigningState::CommitmentPhase { .. } => {}
            _ => {
                return Err(SigningError::AggregationFailed {
                    reason: format!(
                        "invalid state for adding commitment: expected Initialized or CommitmentPhase, got {}",
                        self.state.state_name()
                    ),
                });
            }
        }

        // Validasi signer terdaftar
        if !self.is_signer(&signer) {
            return Err(SigningError::SignerNotInCommittee { signer });
        }

        // Validasi tidak duplicate
        if self.commitments.contains_key(&signer) {
            return Err(SigningError::DuplicateSigner { signer });
        }

        // Insert commitment
        self.commitments.insert(signer, commitment);

        // Transition ke CommitmentPhase jika masih Initialized
        if matches!(self.state, SigningState::Initialized) {
            self.state = SigningState::CommitmentPhase {
                commitments: self.commitments.clone(),
            };
        } else if let SigningState::CommitmentPhase { .. } = &self.state {
            // Update state dengan commitments terbaru
            self.state = SigningState::CommitmentPhase {
                commitments: self.commitments.clone(),
            };
        }

        Ok(())
    }

    /// Mengecek apakah sudah cukup commitments untuk melanjutkan.
    #[must_use]
    pub fn has_enough_commitments(&self) -> bool {
        self.commitments.len() >= self.threshold as usize
    }

    /// Mengembalikan reference ke commitments HashMap.
    #[must_use]
    pub fn get_commitments(&self) -> &HashMap<SignerId, SigningCommitment> {
        &self.commitments
    }

    /// Menyelesaikan commitment phase dan transisi ke SigningPhase.
    ///
    /// # Errors
    ///
    /// - `SigningError::AggregationFailed` jika state bukan CommitmentPhase
    /// - `SigningError::InsufficientSignatures` jika commitments < threshold
    pub fn finalize_commitments(&mut self) -> Result<(), SigningError> {
        // Validasi state
        if !matches!(self.state, SigningState::CommitmentPhase { .. }) {
            return Err(SigningError::AggregationFailed {
                reason: format!(
                    "invalid state for finalizing commitments: expected CommitmentPhase, got {}",
                    self.state.state_name()
                ),
            });
        }

        // Validasi cukup commitments
        if !self.has_enough_commitments() {
            return Err(SigningError::InsufficientSignatures {
                expected: self.threshold,
                got: self.commitments.len(),
            });
        }

        // Transition ke SigningPhase
        self.state = SigningState::SigningPhase {
            commitments: self.commitments.clone(),
            partial_signatures: HashMap::new(),
        };

        Ok(())
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SIGNING PHASE
    // ────────────────────────────────────────────────────────────────────────────

    /// Menambahkan partial signature dari signer.
    ///
    /// # Arguments
    ///
    /// * `partial` - Partial signature dari signer
    ///
    /// # Errors
    ///
    /// - `SigningError::AggregationFailed` jika state bukan SigningPhase
    /// - `SigningError::SignerNotInCommittee` jika signer tidak terdaftar
    /// - `SigningError::DuplicateSigner` jika partial signature sudah ada
    pub fn add_partial_signature(&mut self, partial: PartialSignature) -> Result<(), SigningError> {
        // Validasi state
        if !matches!(self.state, SigningState::SigningPhase { .. }) {
            return Err(SigningError::AggregationFailed {
                reason: format!(
                    "invalid state for adding partial signature: expected SigningPhase, got {}",
                    self.state.state_name()
                ),
            });
        }

        let signer_id = partial.signer_id().clone();

        // Validasi signer terdaftar
        if !self.is_signer(&signer_id) {
            return Err(SigningError::SignerNotInCommittee { signer: signer_id });
        }

        // Validasi signer memiliki commitment (harus sudah submit commitment)
        if !self.commitments.contains_key(&signer_id) {
            return Err(SigningError::InvalidPartialSignature {
                signer: signer_id,
                reason: "signer has not submitted commitment".to_string(),
            });
        }

        // Validasi tidak duplicate
        if self.partial_signatures.contains_key(&signer_id) {
            return Err(SigningError::DuplicateSigner { signer: signer_id });
        }

        // Insert partial signature
        self.partial_signatures.insert(signer_id, partial);

        // Update state dengan partial_signatures terbaru
        if let SigningState::SigningPhase { commitments, .. } = &self.state {
            self.state = SigningState::SigningPhase {
                commitments: commitments.clone(),
                partial_signatures: self.partial_signatures.clone(),
            };
        }

        Ok(())
    }

    /// Mengecek apakah sudah cukup partial signatures untuk aggregation.
    #[must_use]
    pub fn has_enough_signatures(&self) -> bool {
        self.partial_signatures.len() >= self.threshold as usize
    }

    /// Mengembalikan reference ke partial signatures HashMap.
    #[must_use]
    pub fn get_partial_signatures(&self) -> &HashMap<SignerId, PartialSignature> {
        &self.partial_signatures
    }

    // ────────────────────────────────────────────────────────────────────────────
    // COMPLETION & FAILURE
    // ────────────────────────────────────────────────────────────────────────────

    /// Menyelesaikan signing dengan aggregate signature.
    ///
    /// # Arguments
    ///
    /// * `aggregate` - Aggregate signature hasil aggregation
    ///
    /// # Errors
    ///
    /// - `SigningError::AggregationFailed` jika state bukan SigningPhase
    /// - `SigningError::InsufficientSignatures` jika partial_signatures < threshold
    pub fn complete(&mut self, aggregate: AggregateSignature) -> Result<(), SigningError> {
        // Validasi state
        if !matches!(self.state, SigningState::SigningPhase { .. }) {
            return Err(SigningError::AggregationFailed {
                reason: format!(
                    "invalid state for completing: expected SigningPhase, got {}",
                    self.state.state_name()
                ),
            });
        }

        // Validasi cukup partial signatures
        if !self.has_enough_signatures() {
            return Err(SigningError::InsufficientSignatures {
                expected: self.threshold,
                got: self.partial_signatures.len(),
            });
        }

        // Transition ke Completed
        self.state = SigningState::Completed { aggregate };

        Ok(())
    }

    /// Set session ke Failed state.
    ///
    /// Dapat dipanggil dari state manapun kecuali Completed.
    /// Idempotent - jika sudah Failed, tidak ada efek.
    ///
    /// # Arguments
    ///
    /// * `error` - Error yang menyebabkan kegagalan
    pub fn fail(&mut self, error: SigningError) {
        // Tidak overwrite Completed state
        if self.is_complete() {
            return;
        }

        // Tidak overwrite jika sudah Failed
        if self.is_failed() {
            return;
        }

        self.state = SigningState::Failed { error };
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════════

/// Compute SHA3-256 hash of message.
fn compute_message_hash(message: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"dsdn-tss-message-hash-v1");
    hasher.update(message);

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{FrostSignature, FrostSignatureShare};

    // ────────────────────────────────────────────────────────────────────────────
    // HELPER FUNCTIONS
    // ────────────────────────────────────────────────────────────────────────────

    fn make_signers(n: usize) -> Vec<SignerId> {
        (0..n).map(|i| SignerId::from_bytes([i as u8; 32])).collect()
    }

    fn make_session(n: usize, threshold: u8) -> SigningSession {
        let session_id = SessionId::from_bytes([0xAA; 32]);
        let signers = make_signers(n);
        let message = b"test message".to_vec();
        SigningSession::new(session_id, message, signers, threshold).unwrap()
    }

    fn make_commitment() -> SigningCommitment {
        SigningCommitment::from_parts([0x01; 32], [0x02; 32]).unwrap()
    }

    fn make_partial_signature(signer_id: SignerId) -> PartialSignature {
        let share = FrostSignatureShare::from_bytes([0x01; 32]).unwrap();
        PartialSignature::new(signer_id, share)
    }

    fn make_aggregate() -> AggregateSignature {
        let sig = FrostSignature::from_bytes([0x01; 64]).unwrap();
        AggregateSignature::new(sig)
    }

    // ────────────────────────────────────────────────────────────────────────────
    // CONSTRUCTOR TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_new_valid() {
        let session = make_session(3, 2);
        assert_eq!(session.threshold(), 2);
        assert_eq!(session.signers().len(), 3);
        assert!(!session.is_complete());
        assert!(!session.is_failed());
        assert_eq!(session.state().state_name(), "Initialized");
    }

    #[test]
    fn test_new_threshold_equals_signers() {
        let session = make_session(3, 3);
        assert_eq!(session.threshold(), 3);
    }

    #[test]
    fn test_new_threshold_less_than_2_fails() {
        let session_id = SessionId::from_bytes([0xAA; 32]);
        let signers = make_signers(3);
        let result = SigningSession::new(session_id, vec![], signers, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_new_threshold_greater_than_signers_fails() {
        let session_id = SessionId::from_bytes([0xAA; 32]);
        let signers = make_signers(3);
        let result = SigningSession::new(session_id, vec![], signers, 5);
        assert!(result.is_err());
    }

    #[test]
    fn test_new_duplicate_signers_fails() {
        let session_id = SessionId::from_bytes([0xAA; 32]);
        let s1 = SignerId::from_bytes([0x01; 32]);
        let signers = vec![s1.clone(), s1.clone(), SignerId::from_bytes([0x02; 32])];
        let result = SigningSession::new(session_id, vec![], signers, 2);
        assert!(result.is_err());
    }

    #[test]
    fn test_new_message_hash_computed() {
        let session = make_session(3, 2);
        let hash = session.message_hash();
        // Hash should be non-zero
        assert!(!hash.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_new_message_hash_deterministic() {
        let session_id = SessionId::from_bytes([0xAA; 32]);
        let signers = make_signers(3);
        let message = b"test message".to_vec();

        let session1 = SigningSession::new(session_id.clone(), message.clone(), signers.clone(), 2).unwrap();
        let session2 = SigningSession::new(session_id, message, signers, 2).unwrap();

        assert_eq!(session1.message_hash(), session2.message_hash());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // STATE QUERY TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_is_signer() {
        let session = make_session(3, 2);
        let s0 = SignerId::from_bytes([0; 32]);
        let unknown = SignerId::from_bytes([0xFF; 32]);
        assert!(session.is_signer(&s0));
        assert!(!session.is_signer(&unknown));
    }

    #[test]
    fn test_session_id() {
        let session_id = SessionId::from_bytes([0xBB; 32]);
        let signers = make_signers(3);
        let session = SigningSession::new(session_id.clone(), vec![], signers, 2).unwrap();
        assert_eq!(session.session_id(), &session_id);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // COMMITMENT PHASE TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_add_commitment() {
        let mut session = make_session(3, 2);
        let s0 = SignerId::from_bytes([0; 32]);
        let commitment = make_commitment();

        let result = session.add_commitment(s0, commitment);
        assert!(result.is_ok());
        assert_eq!(session.state().state_name(), "CommitmentPhase");
        assert_eq!(session.get_commitments().len(), 1);
    }

    #[test]
    fn test_add_commitment_unregistered_signer_fails() {
        let mut session = make_session(3, 2);
        let unknown = SignerId::from_bytes([0xFF; 32]);
        let commitment = make_commitment();

        let result = session.add_commitment(unknown, commitment);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_commitment_duplicate_fails() {
        let mut session = make_session(3, 2);
        let s0 = SignerId::from_bytes([0; 32]);
        let commitment = make_commitment();

        session.add_commitment(s0.clone(), commitment.clone()).unwrap();
        let result = session.add_commitment(s0, commitment);
        assert!(result.is_err());
    }

    #[test]
    fn test_has_enough_commitments() {
        let mut session = make_session(3, 2);
        assert!(!session.has_enough_commitments());

        let s0 = SignerId::from_bytes([0; 32]);
        let s1 = SignerId::from_bytes([1; 32]);

        session.add_commitment(s0, make_commitment()).unwrap();
        assert!(!session.has_enough_commitments());

        session.add_commitment(s1, make_commitment()).unwrap();
        assert!(session.has_enough_commitments());
    }

    #[test]
    fn test_finalize_commitments() {
        let mut session = make_session(3, 2);

        // Add enough commitments
        for i in 0..2 {
            let signer = SignerId::from_bytes([i as u8; 32]);
            session.add_commitment(signer, make_commitment()).unwrap();
        }

        let result = session.finalize_commitments();
        assert!(result.is_ok());
        assert_eq!(session.state().state_name(), "SigningPhase");
    }

    #[test]
    fn test_finalize_commitments_insufficient_fails() {
        let mut session = make_session(3, 2);

        // Add only 1 commitment (need 2)
        let s0 = SignerId::from_bytes([0; 32]);
        session.add_commitment(s0, make_commitment()).unwrap();

        let result = session.finalize_commitments();
        assert!(result.is_err());
    }

    #[test]
    fn test_finalize_commitments_wrong_state_fails() {
        let session = make_session(3, 2);
        // State is Initialized, not CommitmentPhase
        let mut session = session;
        let result = session.finalize_commitments();
        assert!(result.is_err());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SIGNING PHASE TESTS
    // ────────────────────────────────────────────────────────────────────────────

    fn setup_signing_phase() -> SigningSession {
        let mut session = make_session(3, 2);

        // Add commitments
        for i in 0..3 {
            let signer = SignerId::from_bytes([i as u8; 32]);
            session.add_commitment(signer, make_commitment()).unwrap();
        }

        session.finalize_commitments().unwrap();
        session
    }

    #[test]
    fn test_add_partial_signature() {
        let mut session = setup_signing_phase();
        let s0 = SignerId::from_bytes([0; 32]);
        let partial = make_partial_signature(s0);

        let result = session.add_partial_signature(partial);
        assert!(result.is_ok());
        assert_eq!(session.get_partial_signatures().len(), 1);
    }

    #[test]
    fn test_add_partial_signature_wrong_state_fails() {
        let mut session = make_session(3, 2);
        // State is Initialized
        let s0 = SignerId::from_bytes([0; 32]);
        let partial = make_partial_signature(s0);

        let result = session.add_partial_signature(partial);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_partial_signature_unregistered_signer_fails() {
        let mut session = setup_signing_phase();
        let unknown = SignerId::from_bytes([0xFF; 32]);
        let partial = make_partial_signature(unknown);

        let result = session.add_partial_signature(partial);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_partial_signature_no_commitment_fails() {
        // Special case: signer is registered but didn't submit commitment
        // This shouldn't happen normally because we add all signers' commitments in setup
        // But let's test the validation
        let session_id = SessionId::from_bytes([0xAA; 32]);
        let signers = make_signers(3);
        let mut session = SigningSession::new(session_id, vec![], signers, 2).unwrap();

        // Add only 2 commitments (not including signer 2)
        for i in 0..2 {
            let signer = SignerId::from_bytes([i as u8; 32]);
            session.add_commitment(signer, make_commitment()).unwrap();
        }
        session.finalize_commitments().unwrap();

        // Try to add partial from signer 2 who didn't submit commitment
        let s2 = SignerId::from_bytes([2; 32]);
        let partial = make_partial_signature(s2);

        let result = session.add_partial_signature(partial);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_partial_signature_duplicate_fails() {
        let mut session = setup_signing_phase();
        let s0 = SignerId::from_bytes([0; 32]);

        session.add_partial_signature(make_partial_signature(s0.clone())).unwrap();
        let result = session.add_partial_signature(make_partial_signature(s0));
        assert!(result.is_err());
    }

    #[test]
    fn test_has_enough_signatures() {
        let mut session = setup_signing_phase();
        assert!(!session.has_enough_signatures());

        let s0 = SignerId::from_bytes([0; 32]);
        session.add_partial_signature(make_partial_signature(s0)).unwrap();
        assert!(!session.has_enough_signatures());

        let s1 = SignerId::from_bytes([1; 32]);
        session.add_partial_signature(make_partial_signature(s1)).unwrap();
        assert!(session.has_enough_signatures());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // COMPLETION TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_complete() {
        let mut session = setup_signing_phase();

        // Add enough partial signatures
        for i in 0..2 {
            let signer = SignerId::from_bytes([i as u8; 32]);
            session.add_partial_signature(make_partial_signature(signer)).unwrap();
        }

        let result = session.complete(make_aggregate());
        assert!(result.is_ok());
        assert!(session.is_complete());
        assert_eq!(session.state().state_name(), "Completed");
    }

    #[test]
    fn test_complete_insufficient_signatures_fails() {
        let mut session = setup_signing_phase();

        // Add only 1 partial signature (need 2)
        let s0 = SignerId::from_bytes([0; 32]);
        session.add_partial_signature(make_partial_signature(s0)).unwrap();

        let result = session.complete(make_aggregate());
        assert!(result.is_err());
    }

    #[test]
    fn test_complete_wrong_state_fails() {
        let mut session = make_session(3, 2);
        // State is Initialized
        let result = session.complete(make_aggregate());
        assert!(result.is_err());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // FAIL TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_fail() {
        let mut session = make_session(3, 2);
        session.fail(SigningError::MessageMismatch);
        assert!(session.is_failed());
        assert_eq!(session.state().state_name(), "Failed");
    }

    #[test]
    fn test_fail_does_not_overwrite_completed() {
        let mut session = setup_signing_phase();

        // Complete the session
        for i in 0..2 {
            let signer = SignerId::from_bytes([i as u8; 32]);
            session.add_partial_signature(make_partial_signature(signer)).unwrap();
        }
        session.complete(make_aggregate()).unwrap();

        // Try to fail
        session.fail(SigningError::MessageMismatch);

        // Should still be completed
        assert!(session.is_complete());
        assert!(!session.is_failed());
    }

    #[test]
    fn test_fail_idempotent() {
        let mut session = make_session(3, 2);
        session.fail(SigningError::MessageMismatch);
        session.fail(SigningError::AggregationFailed {
            reason: "test".to_string(),
        });

        // Should still have first error
        assert!(session.is_failed());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // FULL LIFECYCLE TEST
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_full_signing_lifecycle() {
        // Create session
        let session_id = SessionId::from_bytes([0xAA; 32]);
        let signers = make_signers(3);
        let message = b"test message".to_vec();
        let mut session = SigningSession::new(session_id, message, signers, 2).unwrap();

        assert_eq!(session.state().state_name(), "Initialized");

        // Add commitments
        for i in 0..3 {
            let signer = SignerId::from_bytes([i as u8; 32]);
            session.add_commitment(signer, make_commitment()).unwrap();
        }

        assert_eq!(session.state().state_name(), "CommitmentPhase");

        // Finalize commitments
        session.finalize_commitments().unwrap();
        assert_eq!(session.state().state_name(), "SigningPhase");

        // Add partial signatures
        for i in 0..2 {
            let signer = SignerId::from_bytes([i as u8; 32]);
            session.add_partial_signature(make_partial_signature(signer)).unwrap();
        }

        // Complete
        session.complete(make_aggregate()).unwrap();

        assert!(session.is_complete());
        assert!(!session.is_failed());
        assert_eq!(session.state().state_name(), "Completed");
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SEND + SYNC TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_session_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SigningSession>();
    }
}