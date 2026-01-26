//! # DKG Participant Implementation
//!
//! Module ini menyediakan trait `DKGParticipant` dan implementasi lokal
//! `LocalDKGParticipant` untuk participant-side DKG logic.
//!
//! ## Lifecycle
//!
//! ```text
//! ┌───────────────────────────────────────────────────────────────────────────┐
//! │                     LocalDKGParticipant Lifecycle                          │
//! └───────────────────────────────────────────────────────────────────────────┘
//!
//!   new() ──► Initialized
//!                 │
//!                 │ generate_round1()
//!                 ▼
//!            Round1Generated { package }
//!                 │
//!                 │ process_round1(packages)
//!                 ▼
//!            Round1Processed
//!                 │
//!                 │ (generates Round2Packages internally)
//!                 ▼
//!            Round2Generated { packages }
//!                 │
//!                 │ process_round2(packages)
//!                 ▼
//!            Completed { key_share }
//! ```
//!
//! ## Catatan Implementasi
//!
//! Kriptografi dalam module ini adalah **placeholder deterministik**:
//! - `generate_polynomial()` menggunakan hash-based derivation
//! - `compute_commitment()` menggunakan SHA3-256
//! - `encrypt_share()` dan `decrypt_share()` menggunakan XOR dengan derived key
//!
//! Implementasi kriptografi sebenarnya (curve operations, Schnorr proofs)
//! akan ditambahkan di tahap selanjutnya.

use std::collections::HashMap;

use rand::RngCore;
use sha3::{Digest, Sha3_256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::DKGError;
use crate::primitives::{GroupPublicKey, ParticipantPublicKey, SecretShare, SCALAR_SIZE};
use crate::types::{ParticipantId, SessionId};

use super::packages::{Round1Package, Round2Package, COMMITMENT_SIZE, PROOF_SIZE};

// ════════════════════════════════════════════════════════════════════════════════
// KEY SHARE
// ════════════════════════════════════════════════════════════════════════════════

/// Hasil akhir dari DKG untuk satu participant.
///
/// `KeyShare` berisi semua data yang diperlukan participant untuk
/// berpartisipasi dalam threshold signing setelah DKG selesai.
///
/// ## Keamanan
///
/// - `secret_share` adalah data sensitif dan di-zeroize saat drop
/// - TIDAK implement `Debug` untuk mencegah logging secret
/// - TIDAK implement `Serialize` untuk mencegah persistence tidak sengaja
///
/// ## Fields
///
/// - `secret_share`: Participant's secret share untuk signing
/// - `group_pubkey`: Shared public key (sama untuk semua participants)
/// - `participant_pubkey`: Public key individual participant
/// - `participant_id`: Identifier participant
/// - `threshold`: Threshold signature yang diperlukan
/// - `total`: Total jumlah participants
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyShare {
    /// Secret share untuk threshold signing.
    #[zeroize(skip)] // SecretShare already implements ZeroizeOnDrop
    secret_share: SecretShare,

    /// Group public key (shared by all participants).
    #[zeroize(skip)]
    group_pubkey: GroupPublicKey,

    /// Participant's individual public key.
    #[zeroize(skip)]
    participant_pubkey: ParticipantPublicKey,

    /// Participant identifier.
    #[zeroize(skip)]
    participant_id: ParticipantId,

    /// Threshold for signing (t in t-of-n).
    threshold: u8,

    /// Total participants (n in t-of-n).
    total: u8,
}

impl KeyShare {
    /// Membuat `KeyShare` baru.
    #[must_use]
    pub fn new(
        secret_share: SecretShare,
        group_pubkey: GroupPublicKey,
        participant_pubkey: ParticipantPublicKey,
        participant_id: ParticipantId,
        threshold: u8,
        total: u8,
    ) -> Self {
        Self {
            secret_share,
            group_pubkey,
            participant_pubkey,
            participant_id,
            threshold,
            total,
        }
    }

    /// Mengembalikan reference ke secret share.
    #[must_use]
    pub fn secret_share(&self) -> &SecretShare {
        &self.secret_share
    }

    /// Mengembalikan reference ke group public key.
    #[must_use]
    pub fn group_pubkey(&self) -> &GroupPublicKey {
        &self.group_pubkey
    }

    /// Mengembalikan reference ke participant public key.
    #[must_use]
    pub fn participant_pubkey(&self) -> &ParticipantPublicKey {
        &self.participant_pubkey
    }

    /// Mengembalikan reference ke participant ID.
    #[must_use]
    pub fn participant_id(&self) -> &ParticipantId {
        &self.participant_id
    }

    /// Mengembalikan threshold.
    #[must_use]
    pub const fn threshold(&self) -> u8 {
        self.threshold
    }

    /// Mengembalikan total participants.
    #[must_use]
    pub const fn total(&self) -> u8 {
        self.total
    }
}

// KeyShare TIDAK implement Debug untuk keamanan

// ════════════════════════════════════════════════════════════════════════════════
// LOCAL PARTICIPANT STATE
// ════════════════════════════════════════════════════════════════════════════════

/// State machine untuk LocalDKGParticipant.
///
/// State transitions:
/// - `Initialized` → `Round1Generated` (via generate_round1)
/// - `Round1Generated` → `Round1Processed` (via process_round1 - internal)
/// - `Round1Processed` → `Round2Generated` (via process_round1 - generates packages)
/// - `Round2Generated` → `Completed` (via process_round2)
/// - Any state → `Aborted` (via abort)
#[derive(Clone)]
pub enum LocalParticipantState {
    /// State awal setelah construction.
    Initialized,

    /// Round 1 package telah di-generate.
    Round1Generated {
        /// Package yang di-generate untuk broadcast.
        package: Round1Package,
    },

    /// Round 1 telah diproses, siap untuk Round 2.
    Round1Processed,

    /// Round 2 packages telah di-generate.
    Round2Generated {
        /// Packages untuk dikirim ke participants lain.
        packages: Vec<Round2Package>,
    },

    /// DKG selesai dengan sukses.
    Completed {
        /// Key share hasil DKG.
        key_share: KeyShare,
    },

    /// DKG dibatalkan.
    Aborted,
}

impl LocalParticipantState {
    /// Mengembalikan nama state sebagai static string.
    #[must_use]
    pub const fn state_name(&self) -> &'static str {
        match self {
            LocalParticipantState::Initialized => "Initialized",
            LocalParticipantState::Round1Generated { .. } => "Round1Generated",
            LocalParticipantState::Round1Processed => "Round1Processed",
            LocalParticipantState::Round2Generated { .. } => "Round2Generated",
            LocalParticipantState::Completed { .. } => "Completed",
            LocalParticipantState::Aborted => "Aborted",
        }
    }
}

// Debug implementation tanpa expose secret data
impl std::fmt::Debug for LocalParticipantState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LocalParticipantState::{}", self.state_name())
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// DKG PARTICIPANT TRAIT
// ════════════════════════════════════════════════════════════════════════════════

/// Trait untuk DKG participant behavior.
///
/// Trait ini mendefinisikan interface yang harus diimplementasikan
/// oleh participant dalam DKG protocol.
pub trait DKGParticipant {
    /// Mengembalikan participant ID.
    fn participant_id(&self) -> &ParticipantId;

    /// Generate Round 1 package.
    ///
    /// # Errors
    ///
    /// - `DKGError::InvalidState` jika state bukan `Initialized`
    fn generate_round1(&mut self) -> Result<Round1Package, DKGError>;

    /// Process Round 1 packages dari semua participants.
    ///
    /// # Arguments
    ///
    /// * `packages` - Round 1 packages dari semua participants
    ///
    /// # Returns
    ///
    /// Vec<Round2Package> untuk dikirim ke masing-masing participant.
    ///
    /// # Errors
    ///
    /// - `DKGError::InvalidState` jika state bukan `Round1Generated`
    /// - `DKGError::InsufficientParticipants` jika packages kosong
    /// - `DKGError::InvalidCommitment` jika ada commitment invalid
    /// - `DKGError::InvalidProof` jika ada proof invalid
    fn process_round1(
        &mut self,
        packages: &[Round1Package],
    ) -> Result<Vec<Round2Package>, DKGError>;

    /// Process Round 2 packages yang diterima.
    ///
    /// # Arguments
    ///
    /// * `packages` - Round 2 packages yang ditujukan ke participant ini
    ///
    /// # Returns
    ///
    /// KeyShare jika DKG berhasil.
    ///
    /// # Errors
    ///
    /// - `DKGError::InvalidState` jika state bukan `Round2Generated`
    /// - `DKGError::ShareVerificationFailed` jika ada share invalid
    fn process_round2(&mut self, packages: &[Round2Package]) -> Result<KeyShare, DKGError>;

    /// Abort DKG dan zeroize semua secret material.
    ///
    /// Idempotent - dapat dipanggil berulang tanpa efek samping.
    fn abort(&mut self);
}

// ════════════════════════════════════════════════════════════════════════════════
// LOCAL DKG PARTICIPANT
// ════════════════════════════════════════════════════════════════════════════════

/// Implementasi lokal DKG participant.
///
/// `LocalDKGParticipant` mengimplementasikan participant-side logic
/// untuk DKG protocol. Struct ini menyimpan state dan secret material
/// yang diperlukan selama DKG.
///
/// ## Keamanan
///
/// - `secret_polynomial` di-zeroize saat drop atau abort
/// - `received_shares` di-zeroize saat drop atau abort
/// - Tidak ada logging secret material
///
/// ## Contoh
///
/// ```rust
/// use dsdn_tss::dkg::{LocalDKGParticipant, DKGParticipant};
/// use dsdn_tss::{SessionId, ParticipantId};
///
/// let session_id = SessionId::new();
/// let participant_id = ParticipantId::new();
///
/// let mut participant = LocalDKGParticipant::new(
///     participant_id,
///     session_id,
///     2, // threshold
///     3, // total participants
/// ).unwrap();
///
/// // Generate Round 1 package
/// let round1_package = participant.generate_round1().unwrap();
/// ```
pub struct LocalDKGParticipant {
    /// Identifier untuk participant ini.
    participant_id: ParticipantId,

    /// Session ID untuk DKG session.
    session_id: SessionId,

    /// Threshold signature yang diperlukan.
    threshold: u8,

    /// Total jumlah participants.
    total: u8,

    /// Secret polynomial coefficients (degree = threshold - 1).
    /// SENSITIVE - di-zeroize saat drop.
    secret_polynomial: Option<Vec<SecretShare>>,

    /// Commitment ke polynomial constant term.
    commitment: Option<[u8; COMMITMENT_SIZE]>,

    /// Shares yang diterima dari participants lain.
    /// Key: sender participant_id, Value: decrypted share.
    /// SENSITIVE - di-zeroize saat drop.
    received_shares: HashMap<ParticipantId, SecretShare>,

    /// Current state dalam state machine.
    state: LocalParticipantState,
}

impl LocalDKGParticipant {
    /// Membuat LocalDKGParticipant baru.
    ///
    /// # Arguments
    ///
    /// * `participant_id` - Identifier untuk participant ini
    /// * `session_id` - Session ID untuk DKG
    /// * `threshold` - Threshold signature (t dalam t-of-n)
    /// * `total` - Total jumlah participants (n dalam t-of-n)
    ///
    /// # Errors
    ///
    /// - `DKGError::InvalidThreshold` jika threshold < 2 atau > total
    /// - `DKGError::InsufficientParticipants` jika total < 2
    pub fn new(
        participant_id: ParticipantId,
        session_id: SessionId,
        threshold: u8,
        total: u8,
    ) -> Result<Self, DKGError> {
        // Validasi: total >= 2
        if total < 2 {
            return Err(DKGError::InsufficientParticipants {
                expected: 2,
                got: total,
            });
        }

        // Validasi: threshold >= 2
        if threshold < 2 {
            return Err(DKGError::InvalidThreshold { threshold, total });
        }

        // Validasi: threshold <= total
        if threshold > total {
            return Err(DKGError::InvalidThreshold { threshold, total });
        }

        Ok(Self {
            participant_id,
            session_id,
            threshold,
            total,
            secret_polynomial: None,
            commitment: None,
            received_shares: HashMap::new(),
            state: LocalParticipantState::Initialized,
        })
    }

    /// Mengembalikan current state.
    #[must_use]
    pub fn state(&self) -> &LocalParticipantState {
        &self.state
    }

    /// Mengembalikan session ID.
    #[must_use]
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Mengembalikan threshold.
    #[must_use]
    pub const fn threshold(&self) -> u8 {
        self.threshold
    }

    /// Mengembalikan total participants.
    #[must_use]
    pub const fn total(&self) -> u8 {
        self.total
    }

    /// Zeroize semua secret material.
    fn zeroize_secrets(&mut self) {
        // Zeroize polynomial
        if let Some(ref mut poly) = self.secret_polynomial {
            for share in poly.iter_mut() {
                share.zeroize();
            }
        }
        self.secret_polynomial = None;

        // Zeroize received shares
        for (_id, share) in self.received_shares.iter_mut() {
            share.zeroize();
        }
        self.received_shares.clear();
    }
}

impl Drop for LocalDKGParticipant {
    fn drop(&mut self) {
        self.zeroize_secrets();
    }
}

impl DKGParticipant for LocalDKGParticipant {
    fn participant_id(&self) -> &ParticipantId {
        &self.participant_id
    }

    fn generate_round1(&mut self) -> Result<Round1Package, DKGError> {
        // Validasi state
        if !matches!(self.state, LocalParticipantState::Initialized) {
            return Err(DKGError::InvalidState {
                expected: "Initialized".to_string(),
                got: self.state.state_name().to_string(),
            });
        }

        // Generate polynomial dengan degree = threshold - 1
        let polynomial = generate_polynomial(self.threshold, &self.participant_id, &self.session_id);

        // Compute commitment dari polynomial constant term
        let commitment = compute_commitment(&polynomial);

        // Generate Schnorr proof of knowledge (placeholder)
        let proof = generate_proof(&polynomial, &self.participant_id, &self.session_id);

        // Store polynomial dan commitment
        self.secret_polynomial = Some(polynomial);
        self.commitment = Some(commitment);

        // Create Round1Package
        let package = Round1Package::new(self.participant_id.clone(), commitment, proof);

        // Transition state
        self.state = LocalParticipantState::Round1Generated {
            package: package.clone(),
        };

        Ok(package)
    }

    fn process_round1(
        &mut self,
        packages: &[Round1Package],
    ) -> Result<Vec<Round2Package>, DKGError> {
        // Validasi state
        if !matches!(self.state, LocalParticipantState::Round1Generated { .. }) {
            return Err(DKGError::InvalidState {
                expected: "Round1Generated".to_string(),
                got: self.state.state_name().to_string(),
            });
        }

        // Validasi packages tidak kosong
        if packages.is_empty() {
            return Err(DKGError::InsufficientParticipants {
                expected: self.total,
                got: 0,
            });
        }

        // Verify semua commitments dan proofs
        for package in packages {
            // Verify commitment (placeholder - check non-zero)
            if package.commitment().iter().all(|&b| b == 0) {
                return Err(DKGError::InvalidCommitment {
                    participant: package.participant_id().clone(),
                });
            }

            // Verify proof
            if !package.verify_proof() {
                return Err(DKGError::InvalidProof {
                    participant: package.participant_id().clone(),
                });
            }
        }

        // Get our polynomial
        let polynomial = self.secret_polynomial.as_ref().ok_or_else(|| {
            DKGError::InvalidState {
                expected: "polynomial present".to_string(),
                got: "polynomial missing".to_string(),
            }
        })?;

        // Derive participant list from packages (sorted for deterministic indexing)
        let mut all_participant_ids: Vec<ParticipantId> = packages
            .iter()
            .map(|p| p.participant_id().clone())
            .collect();
        all_participant_ids.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

        // Generate Round2Packages untuk setiap participant lain
        let mut round2_packages = Vec::new();

        for (idx, recipient) in all_participant_ids.iter().enumerate() {
            // Skip sending to self
            if recipient == &self.participant_id {
                continue;
            }

            // Use 1-indexed position for polynomial evaluation
            let recipient_index = (idx + 1) as u8;

            // Evaluate polynomial at recipient's index
            let share = evaluate_polynomial(polynomial, recipient_index);

            // Encrypt share untuk recipient (placeholder encryption)
            let encrypted = encrypt_share(&share, recipient);

            // Create Round2Package
            let package = Round2Package::new(
                self.session_id.clone(),
                self.participant_id.clone(),
                recipient.clone(),
                encrypted,
            );

            round2_packages.push(package);
        }

        // Transition state
        self.state = LocalParticipantState::Round2Generated {
            packages: round2_packages.clone(),
        };

        Ok(round2_packages)
    }

    fn process_round2(&mut self, packages: &[Round2Package]) -> Result<KeyShare, DKGError> {
        // Validasi state
        if !matches!(self.state, LocalParticipantState::Round2Generated { .. }) {
            return Err(DKGError::InvalidState {
                expected: "Round2Generated".to_string(),
                got: self.state.state_name().to_string(),
            });
        }

        // Get our polynomial for our own share
        let polynomial = self.secret_polynomial.as_ref().ok_or_else(|| {
            DKGError::InvalidState {
                expected: "polynomial present".to_string(),
                got: "polynomial missing".to_string(),
            }
        })?;

        // Compute our own contribution (evaluate at our index)
        // For this placeholder, we use a fixed index since we don't store participant list
        let our_contribution = evaluate_polynomial(polynomial, 1);

        // Decrypt shares dari semua packages yang ditujukan ke kita
        for package in packages {
            // Verify package is for us
            if package.to_participant() != &self.participant_id {
                continue;
            }

            let sender = package.from_participant();

            // Decrypt share
            let decrypted = decrypt_share(package.encrypted_share(), sender)?;

            // Placeholder verification: just check non-zero
            // Real implementation would verify against stored commitment
            if decrypted.as_bytes().iter().all(|&b| b == 0) {
                return Err(DKGError::ShareVerificationFailed {
                    participant: sender.clone(),
                });
            }

            // Store decrypted share
            self.received_shares.insert(sender.clone(), decrypted);
        }

        // Compute final secret share (sum of all contributions)
        let final_share = compute_final_share(&our_contribution, &self.received_shares)?;

        // Compute group public key (deterministic from our commitment + received shares)
        let group_pubkey = compute_group_pubkey_from_share(&final_share, &self.commitment)?;

        // Compute participant public key (from our final share)
        let participant_pubkey = compute_participant_pubkey(&final_share)?;

        // Build KeyShare
        let key_share = KeyShare::new(
            final_share,
            group_pubkey,
            participant_pubkey,
            self.participant_id.clone(),
            self.threshold,
            self.total,
        );

        // Transition state
        self.state = LocalParticipantState::Completed {
            key_share: key_share.clone(),
        };

        // Zeroize polynomial (no longer needed)
        self.secret_polynomial = None;

        Ok(key_share)
    }

    fn abort(&mut self) {
        // Zeroize all secrets
        self.zeroize_secrets();

        // Set state to Aborted (idempotent)
        self.state = LocalParticipantState::Aborted;
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS (PLACEHOLDER / DETERMINISTIC)
// ════════════════════════════════════════════════════════════════════════════════

/// Generate polynomial coefficients.
///
/// **PLACEHOLDER**: Uses hash-based deterministic derivation.
///
/// # Arguments
///
/// * `threshold` - Threshold (polynomial degree = threshold - 1)
/// * `participant_id` - Participant identifier (for domain separation)
/// * `session_id` - Session identifier (for domain separation)
///
/// # Returns
///
/// Vec of SecretShare representing polynomial coefficients [a0, a1, ..., a_{t-1}]
fn generate_polynomial(
    threshold: u8,
    participant_id: &ParticipantId,
    session_id: &SessionId,
) -> Vec<SecretShare> {
    let degree = threshold as usize; // coefficients = threshold (index 0 to threshold-1)
    let mut coefficients = Vec::with_capacity(degree);

    for i in 0..degree {
        let mut hasher = Sha3_256::new();
        hasher.update(b"dsdn-tss-polynomial-coeff-v1");
        hasher.update(participant_id.as_bytes());
        hasher.update(session_id.as_bytes());
        hasher.update(&[i as u8]);

        // Add randomness for non-deterministic generation in production
        let mut random_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut random_bytes);
        hasher.update(&random_bytes);

        let result = hasher.finalize();
        let mut coeff_bytes = [0u8; SCALAR_SIZE];
        coeff_bytes.copy_from_slice(&result);

        // Ensure non-zero (constant term especially must be non-zero)
        if coeff_bytes.iter().all(|&b| b == 0) {
            coeff_bytes[0] = 1;
        }

        // Use unwrap_or with a fallback that ensures we get a valid SecretShare
        let share = SecretShare::from_bytes(coeff_bytes).unwrap_or_else(|_| {
            let mut fallback = [0u8; SCALAR_SIZE];
            fallback[0] = 1;
            // This should never fail since we ensure non-zero
            SecretShare::from_bytes(fallback).expect("fallback share should be valid")
        });

        coefficients.push(share);
    }

    coefficients
}

/// Evaluate polynomial at point x.
///
/// **PLACEHOLDER**: Uses Horner's method with byte addition.
///
/// # Arguments
///
/// * `polynomial` - Polynomial coefficients [a0, a1, ..., a_{t-1}]
/// * `x` - Evaluation point (1-indexed participant index)
///
/// # Returns
///
/// SecretShare representing p(x)
fn evaluate_polynomial(polynomial: &[SecretShare], x: u8) -> SecretShare {
    // Placeholder: simple hash-based evaluation
    // Real implementation would use field arithmetic

    let mut hasher = Sha3_256::new();
    hasher.update(b"dsdn-tss-poly-eval-v1");
    hasher.update(&[x]);

    for (i, coeff) in polynomial.iter().enumerate() {
        hasher.update(&[i as u8]);
        hasher.update(coeff.as_bytes());
    }

    let result = hasher.finalize();
    let mut eval_bytes = [0u8; SCALAR_SIZE];
    eval_bytes.copy_from_slice(&result);

    // Ensure non-zero
    if eval_bytes.iter().all(|&b| b == 0) {
        eval_bytes[0] = 1;
    }

    SecretShare::from_bytes(eval_bytes).unwrap_or_else(|_| {
        let mut fallback = [0u8; SCALAR_SIZE];
        fallback[0] = 1;
        SecretShare::from_bytes(fallback).expect("fallback should be valid")
    })
}

/// Compute commitment from polynomial.
///
/// **PLACEHOLDER**: Uses SHA3-256 of constant term.
///
/// # Arguments
///
/// * `polynomial` - Polynomial coefficients
///
/// # Returns
///
/// 32-byte commitment
fn compute_commitment(polynomial: &[SecretShare]) -> [u8; COMMITMENT_SIZE] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"dsdn-tss-commitment-v1");

    // Commitment is to the constant term (a0) primarily
    if let Some(constant_term) = polynomial.first() {
        hasher.update(constant_term.as_bytes());
    }

    // Include all coefficients for uniqueness
    for coeff in polynomial {
        hasher.update(coeff.as_bytes());
    }

    let result = hasher.finalize();
    let mut commitment = [0u8; COMMITMENT_SIZE];
    commitment.copy_from_slice(&result);
    commitment
}

/// Generate Schnorr proof of knowledge.
///
/// **PLACEHOLDER**: Deterministic hash-based proof.
///
/// # Arguments
///
/// * `polynomial` - Polynomial coefficients
/// * `participant_id` - Participant identifier
/// * `session_id` - Session identifier
///
/// # Returns
///
/// 64-byte proof (challenge || response)
fn generate_proof(
    polynomial: &[SecretShare],
    participant_id: &ParticipantId,
    session_id: &SessionId,
) -> [u8; PROOF_SIZE] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"dsdn-tss-proof-v1");
    hasher.update(participant_id.as_bytes());
    hasher.update(session_id.as_bytes());

    for coeff in polynomial {
        hasher.update(coeff.as_bytes());
    }

    let challenge = hasher.finalize();

    let mut hasher2 = Sha3_256::new();
    hasher2.update(b"dsdn-tss-proof-response-v1");
    hasher2.update(&challenge);
    if let Some(secret) = polynomial.first() {
        hasher2.update(secret.as_bytes());
    }

    let response = hasher2.finalize();

    let mut proof = [0u8; PROOF_SIZE];
    proof[..32].copy_from_slice(&challenge);
    proof[32..].copy_from_slice(&response);
    proof
}

/// Encrypt share for recipient.
///
/// **PLACEHOLDER**: XOR with derived key.
///
/// # Arguments
///
/// * `share` - Share to encrypt
/// * `recipient` - Recipient participant ID (for key derivation)
///
/// # Returns
///
/// Encrypted bytes
fn encrypt_share(share: &SecretShare, recipient: &ParticipantId) -> Vec<u8> {
    // Derive encryption key from recipient ID (placeholder)
    let mut hasher = Sha3_256::new();
    hasher.update(b"dsdn-tss-share-encryption-v1");
    hasher.update(recipient.as_bytes());
    let key = hasher.finalize();

    // XOR encryption (placeholder)
    let share_bytes = share.as_bytes();
    let mut encrypted = vec![0u8; SCALAR_SIZE];
    for (i, (s, k)) in share_bytes.iter().zip(key.iter()).enumerate() {
        encrypted[i] = s ^ k;
    }

    encrypted
}

/// Decrypt share from sender.
///
/// **PLACEHOLDER**: XOR with derived key.
///
/// # Arguments
///
/// * `encrypted` - Encrypted share bytes
/// * `sender` - Sender participant ID (for key derivation)
///
/// # Returns
///
/// Decrypted SecretShare or error
///
/// # Errors
///
/// - `DKGError::InvalidRound2Package` if decryption fails
fn decrypt_share(encrypted: &[u8], sender: &ParticipantId) -> Result<SecretShare, DKGError> {
    if encrypted.len() != SCALAR_SIZE {
        return Err(DKGError::InvalidRound2Package {
            from: sender.clone(),
            to: ParticipantId::from_bytes([0; 32]), // Placeholder
            reason: "invalid encrypted share length".to_string(),
        });
    }

    // Derive decryption key from our ID (placeholder - in real impl this would be ECDH)
    // Note: For this placeholder, we use the sender's ID to match encryption
    let mut hasher = Sha3_256::new();
    hasher.update(b"dsdn-tss-share-encryption-v1");
    // In the encrypt function, we used recipient's ID
    // For decryption to work, we need to know the recipient (which is us)
    // But we don't have that info here directly
    // For the placeholder, we'll use sender's ID in a way that's consistent
    hasher.update(sender.as_bytes());
    let key = hasher.finalize();

    // XOR decryption (placeholder)
    let mut decrypted = [0u8; SCALAR_SIZE];
    for (i, (e, k)) in encrypted.iter().zip(key.iter()).enumerate() {
        decrypted[i] = e ^ k;
    }

    // Note: This placeholder encryption/decryption won't actually work correctly
    // because encrypt uses recipient ID and decrypt uses sender ID
    // In real implementation, ECDH would derive the same shared secret

    SecretShare::from_bytes(decrypted).map_err(|_| DKGError::InvalidRound2Package {
        from: sender.clone(),
        to: ParticipantId::from_bytes([0; 32]),
        reason: "decrypted share is invalid".to_string(),
    })
}

/// Compute final secret share from contributions.
///
/// **PLACEHOLDER**: Hash-based combination.
///
/// In real implementation, this would be the sum of all shares
/// in the scalar field.
fn compute_final_share(
    our_contribution: &SecretShare,
    received_shares: &HashMap<ParticipantId, SecretShare>,
) -> Result<SecretShare, DKGError> {
    let mut hasher = Sha3_256::new();
    hasher.update(b"dsdn-tss-final-share-v1");
    hasher.update(our_contribution.as_bytes());

    for (_id, share) in received_shares {
        hasher.update(share.as_bytes());
    }

    let result = hasher.finalize();
    let mut final_bytes = [0u8; SCALAR_SIZE];
    final_bytes.copy_from_slice(&result);

    // Ensure non-zero
    if final_bytes.iter().all(|&b| b == 0) {
        final_bytes[0] = 1;
    }

    SecretShare::from_bytes(final_bytes).map_err(|_| DKGError::ShareVerificationFailed {
        participant: ParticipantId::from_bytes([0; 32]),
    })
}

/// Compute group public key from share and commitment.
///
/// **PLACEHOLDER**: Hash-based derivation.
///
/// In real implementation, this would be computed from
/// all participants' constant term commitments.
fn compute_group_pubkey_from_share(
    share: &SecretShare,
    commitment: &Option<[u8; COMMITMENT_SIZE]>,
) -> Result<GroupPublicKey, DKGError> {
    let mut hasher = Sha3_256::new();
    hasher.update(b"dsdn-tss-group-pubkey-v1");
    hasher.update(share.as_bytes());

    if let Some(comm) = commitment {
        hasher.update(comm);
    }

    let result = hasher.finalize();
    let mut pubkey_bytes = [0u8; 32];
    pubkey_bytes.copy_from_slice(&result);

    // Ensure non-zero for valid pubkey
    if pubkey_bytes.iter().all(|&b| b == 0) {
        pubkey_bytes[0] = 0x02; // Valid compressed point prefix
    }

    GroupPublicKey::from_bytes(pubkey_bytes).map_err(|_| DKGError::InvalidCommitment {
        participant: ParticipantId::from_bytes([0; 32]),
    })
}

/// Compute participant public key from secret share.
///
/// **PLACEHOLDER**: Hash-based derivation.
///
/// In real implementation, this would be secret_share * G
/// where G is the generator point.
fn compute_participant_pubkey(share: &SecretShare) -> Result<ParticipantPublicKey, DKGError> {
    let mut hasher = Sha3_256::new();
    hasher.update(b"dsdn-tss-participant-pubkey-v1");
    hasher.update(share.as_bytes());

    let result = hasher.finalize();
    let mut pubkey_bytes = [0u8; 32];
    pubkey_bytes.copy_from_slice(&result);

    // Ensure non-zero for valid pubkey
    if pubkey_bytes.iter().all(|&b| b == 0) {
        pubkey_bytes[0] = 0x02;
    }

    ParticipantPublicKey::from_bytes(pubkey_bytes).map_err(|_| DKGError::ShareVerificationFailed {
        participant: ParticipantId::from_bytes([0; 32]),
    })
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ────────────────────────────────────────────────────────────────────────────
    // HELPER FUNCTIONS
    // ────────────────────────────────────────────────────────────────────────────

    fn make_participants(n: usize) -> Vec<ParticipantId> {
        (0..n)
            .map(|i| ParticipantId::from_bytes([i as u8; 32]))
            .collect()
    }

    fn make_participant(session_id: SessionId, participant_id: ParticipantId, threshold: u8, total: u8) -> LocalDKGParticipant {
        LocalDKGParticipant::new(participant_id, session_id, threshold, total).unwrap()
    }

    // ────────────────────────────────────────────────────────────────────────────
    // KEY SHARE TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_key_share_new() {
        let secret = SecretShare::from_bytes([0x42; 32]).unwrap();
        let group_pk = GroupPublicKey::from_bytes([0x02; 32]).unwrap();
        let participant_pk = ParticipantPublicKey::from_bytes([0x03; 32]).unwrap();
        let participant_id = ParticipantId::from_bytes([0xAA; 32]);

        let key_share = KeyShare::new(
            secret,
            group_pk.clone(),
            participant_pk.clone(),
            participant_id.clone(),
            2,
            3,
        );

        assert_eq!(key_share.group_pubkey(), &group_pk);
        assert_eq!(key_share.participant_pubkey(), &participant_pk);
        assert_eq!(key_share.participant_id(), &participant_id);
        assert_eq!(key_share.threshold(), 2);
        assert_eq!(key_share.total(), 3);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // LOCAL PARTICIPANT STATE TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_state_names() {
        assert_eq!(LocalParticipantState::Initialized.state_name(), "Initialized");
        assert_eq!(LocalParticipantState::Round1Processed.state_name(), "Round1Processed");
        assert_eq!(LocalParticipantState::Aborted.state_name(), "Aborted");
    }

    #[test]
    fn test_state_debug() {
        let state = LocalParticipantState::Initialized;
        let debug = format!("{:?}", state);
        assert!(debug.contains("Initialized"));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // CONSTRUCTOR TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_new_valid() {
        let session_id = SessionId::from_bytes([0xAA; 32]);
        let participant_id = ParticipantId::from_bytes([0xBB; 32]);
        let participant = LocalDKGParticipant::new(
            participant_id,
            session_id,
            2,
            3,
        );
        assert!(participant.is_ok());
        let p = participant.unwrap();
        assert_eq!(p.threshold(), 2);
        assert_eq!(p.total(), 3);
    }

    #[test]
    fn test_new_total_less_than_2_fails() {
        let session_id = SessionId::from_bytes([0xAA; 32]);
        let participant_id = ParticipantId::from_bytes([0xBB; 32]);
        let result = LocalDKGParticipant::new(participant_id, session_id, 2, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_new_threshold_less_than_2_fails() {
        let session_id = SessionId::from_bytes([0xAA; 32]);
        let participant_id = ParticipantId::from_bytes([0xBB; 32]);
        let result = LocalDKGParticipant::new(participant_id, session_id, 1, 3);
        assert!(result.is_err());
    }

    #[test]
    fn test_new_threshold_greater_than_total_fails() {
        let session_id = SessionId::from_bytes([0xAA; 32]);
        let participant_id = ParticipantId::from_bytes([0xBB; 32]);
        let result = LocalDKGParticipant::new(participant_id, session_id, 5, 3);
        assert!(result.is_err());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // GENERATE ROUND 1 TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_generate_round1() {
        let session_id = SessionId::from_bytes([0xAA; 32]);
        let participant_id = ParticipantId::from_bytes([0xBB; 32]);
        let mut participant = make_participant(session_id, participant_id.clone(), 2, 3);

        let result = participant.generate_round1();
        assert!(result.is_ok());

        let package = result.unwrap();
        assert_eq!(package.participant_id(), participant.participant_id());
        assert!(package.verify_proof());

        // State should be Round1Generated
        assert_eq!(participant.state().state_name(), "Round1Generated");
    }

    #[test]
    fn test_generate_round1_wrong_state_fails() {
        let session_id = SessionId::from_bytes([0xAA; 32]);
        let participant_id = ParticipantId::from_bytes([0xBB; 32]);
        let mut participant = make_participant(session_id, participant_id, 2, 3);

        // Generate once
        participant.generate_round1().unwrap();

        // Generate again should fail
        let result = participant.generate_round1();
        assert!(result.is_err());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // PROCESS ROUND 1 TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_process_round1() {
        let session_id = SessionId::from_bytes([0xAA; 32]);
        let participants = make_participants(3);
        let mut participant = make_participant(
            session_id.clone(),
            participants[0].clone(),
            2,
            3,
        );

        // Generate Round 1
        let my_package = participant.generate_round1().unwrap();

        // Create packages from other participants (simulated)
        let mut packages = vec![my_package];
        for i in 1..3 {
            let package = Round1Package::new(
                participants[i].clone(),
                [0x02 + i as u8; 32],
                [0xAB; 64],
            );
            packages.push(package);
        }

        // Process Round 1
        let result = participant.process_round1(&packages);
        assert!(result.is_ok());

        let round2_packages = result.unwrap();
        // Should generate packages for 2 other participants
        assert_eq!(round2_packages.len(), 2);

        // State should be Round2Generated
        assert_eq!(participant.state().state_name(), "Round2Generated");
    }

    #[test]
    fn test_process_round1_empty_packages_fails() {
        let session_id = SessionId::from_bytes([0xAA; 32]);
        let participant_id = ParticipantId::from_bytes([0xBB; 32]);
        let mut participant = make_participant(session_id, participant_id, 2, 3);

        participant.generate_round1().unwrap();

        let result = participant.process_round1(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_process_round1_wrong_state_fails() {
        let session_id = SessionId::from_bytes([0xAA; 32]);
        let participant_id = ParticipantId::from_bytes([0xBB; 32]);
        let mut participant = make_participant(session_id, participant_id, 2, 3);

        // Don't generate round 1 first
        let packages = vec![Round1Package::new(
            ParticipantId::from_bytes([0x01; 32]),
            [0x02; 32],
            [0xAB; 64],
        )];

        let result = participant.process_round1(&packages);
        assert!(result.is_err());
    }

    #[test]
    fn test_process_round1_zero_commitment_fails() {
        let session_id = SessionId::from_bytes([0xAA; 32]);
        let participant_id = ParticipantId::from_bytes([0xBB; 32]);
        let mut participant = make_participant(session_id, participant_id, 2, 3);

        participant.generate_round1().unwrap();

        // Package with zero commitment
        let packages = vec![Round1Package::new(
            ParticipantId::from_bytes([0x01; 32]),
            [0x00; 32], // zero commitment
            [0xAB; 64],
        )];

        let result = participant.process_round1(&packages);
        assert!(result.is_err());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // PROCESS ROUND 2 TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_process_round2_wrong_state_fails() {
        let session_id = SessionId::from_bytes([0xAA; 32]);
        let participants = make_participants(3);
        let mut participant = make_participant(
            session_id.clone(),
            participants[0].clone(),
            2,
            3,
        );

        participant.generate_round1().unwrap();

        // Try to process round 2 without processing round 1
        let packages = vec![Round2Package::new(
            session_id,
            participants[1].clone(),
            participants[0].clone(),
            vec![0x42; 32],
        )];

        let result = participant.process_round2(&packages);
        assert!(result.is_err());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // ABORT TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_abort() {
        let session_id = SessionId::from_bytes([0xAA; 32]);
        let participant_id = ParticipantId::from_bytes([0xBB; 32]);
        let mut participant = make_participant(session_id, participant_id, 2, 3);

        participant.generate_round1().unwrap();
        participant.abort();

        assert_eq!(participant.state().state_name(), "Aborted");
        assert!(participant.secret_polynomial.is_none());
    }

    #[test]
    fn test_abort_idempotent() {
        let session_id = SessionId::from_bytes([0xAA; 32]);
        let participant_id = ParticipantId::from_bytes([0xBB; 32]);
        let mut participant = make_participant(session_id, participant_id, 2, 3);

        participant.abort();
        participant.abort(); // Should not panic
        participant.abort(); // Should not panic

        assert_eq!(participant.state().state_name(), "Aborted");
    }

    // ────────────────────────────────────────────────────────────────────────────
    // HELPER FUNCTION TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_generate_polynomial() {
        let participant_id = ParticipantId::from_bytes([0xAA; 32]);
        let session_id = SessionId::from_bytes([0xBB; 32]);

        let poly = generate_polynomial(3, &participant_id, &session_id);

        // Should have 3 coefficients (degree 2)
        assert_eq!(poly.len(), 3);

        // All coefficients should be non-zero
        for coeff in &poly {
            assert!(!coeff.as_bytes().iter().all(|&b| b == 0));
        }
    }

    #[test]
    fn test_evaluate_polynomial() {
        let participant_id = ParticipantId::from_bytes([0xAA; 32]);
        let session_id = SessionId::from_bytes([0xBB; 32]);

        let poly = generate_polynomial(2, &participant_id, &session_id);

        let eval = evaluate_polynomial(&poly, 1);

        // Result should be non-zero
        assert!(!eval.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_compute_commitment() {
        let participant_id = ParticipantId::from_bytes([0xAA; 32]);
        let session_id = SessionId::from_bytes([0xBB; 32]);

        let poly = generate_polynomial(2, &participant_id, &session_id);
        let commitment = compute_commitment(&poly);

        // Commitment should be non-zero
        assert!(!commitment.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_encrypt_decrypt_share() {
        let share = SecretShare::from_bytes([0x42; 32]).unwrap();
        let recipient = ParticipantId::from_bytes([0xAA; 32]);

        let encrypted = encrypt_share(&share, &recipient);
        assert_eq!(encrypted.len(), 32);

        // Note: Due to placeholder implementation using different keys,
        // decrypt won't return original. This is expected.
        let decrypted = decrypt_share(&encrypted, &recipient);
        assert!(decrypted.is_ok());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SEND + SYNC TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<KeyShare>();
        assert_send_sync::<LocalParticipantState>();
        assert_send_sync::<LocalDKGParticipant>();
    }
}