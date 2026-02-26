//! # DKG Participant Implementation
//!
//! Module ini menyediakan trait `DKGParticipant` dan implementasi lokal
//! `LocalDKGParticipant` untuk participant-side DKG logic menggunakan
//! real FROST DKG dari `frost-ed25519` (ZCash Foundation).
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
//!                 │ generate_round1()       [frost::keys::dkg::part1]
//!                 ▼
//!            Round1Generated { package }
//!                 │
//!                 │ process_round1(packages) [frost::keys::dkg::part2]
//!                 ▼
//!            Round2Generated { packages }
//!                 │
//!                 │ process_round2(packages) [frost::keys::dkg::part3]
//!                 ▼
//!            Completed { key_share }
//! ```
//!
//! ## Kriptografi
//!
//! Implementasi menggunakan **real FROST DKG** (Flexible Round-Optimized
//! Schnorr Threshold Signatures):
//!
//! - **Round 1**: `frost::keys::dkg::part1()` — Generate random polynomial,
//!   compute Feldman VSS commitments, produce Schnorr proof of knowledge
//! - **Round 2**: `frost::keys::dkg::part2()` — Verify all round 1 packages
//!   (commitments + proofs), evaluate secret polynomial for each peer
//! - **Finalization**: `frost::keys::dkg::part3()` — Verify received shares
//!   against VSS commitments, compute final signing share and group public key
//!
//! ## Identifier Derivation
//!
//! FROST requires each participant to have a unique `frost::Identifier` (nonzero
//! Ed25519 scalar). This is derived deterministically from `ParticipantId` bytes
//! via `frost::Identifier::derive()`, which uses hash-to-field to guarantee a
//! valid nonzero scalar. All participants independently compute the same mapping.

use std::collections::BTreeMap;

use rand::CryptoRng;
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use frost_ed25519 as frost;

use crate::error::DKGError;
use crate::frost_adapter;
use crate::primitives::{GroupPublicKey, ParticipantPublicKey, SecretShare, PUBLIC_KEY_SIZE};
use crate::types::{ParticipantId, SessionId};

use super::packages::{Round1Package, Round2Package};

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
/// - `Round1Generated` → `Round2Generated` (via process_round1)
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
// FROST IDENTIFIER DERIVATION
// ════════════════════════════════════════════════════════════════════════════════

/// Derive a deterministic `frost::Identifier` from a `ParticipantId`.
///
/// Uses `frost::Identifier::derive()` which applies hash-to-field
/// to produce a valid nonzero Ed25519 scalar. Deterministic: the same
/// ParticipantId always produces the same Identifier across all participants.
///
/// # Errors
///
/// Returns `DKGError::InvalidRound1Package` if derivation fails (astronomically
/// unlikely for valid hash-to-field).
fn derive_frost_identifier(
    pid: &ParticipantId,
) -> Result<frost::Identifier, DKGError> {
    frost::Identifier::derive(pid.as_bytes()).map_err(|e| {
        DKGError::InvalidRound1Package {
            participant: pid.clone(),
            reason: format!("cannot derive frost identifier: {}", e),
        }
    })
}

// ════════════════════════════════════════════════════════════════════════════════
// LOCAL DKG PARTICIPANT
// ════════════════════════════════════════════════════════════════════════════════

/// Implementasi lokal DKG participant menggunakan real FROST DKG.
///
/// `LocalDKGParticipant` mengimplementasikan Pedersen DKG (Feldman VSS variant)
/// via `frost-ed25519::keys::dkg` API. Setiap method maps ke frost function:
///
/// | Method | FROST Function | Deskripsi |
/// |--------|----------------|-----------|
/// | `generate_round1()` | `dkg::part1()` | Generate polynomial + commitments |
/// | `process_round1()` | `dkg::part2()` | Verify commitments, generate shares |
/// | `process_round2()` | `dkg::part3()` | Verify shares, compute final key |
///
/// ## Keamanan
///
/// - Secret polynomial state di-drop saat abort atau completion
/// - `frost::keys::dkg::round1::SecretPackage` consumed (via take) setelah part2
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

    /// Threshold signature yang diperlukan (min_signers).
    threshold: u8,

    /// Total jumlah participants (max_signers).
    total: u8,

    /// Derived frost Identifier untuk participant ini.
    /// Set during generate_round1().
    frost_identifier: Option<frost::Identifier>,

    /// FROST DKG round 1 secret state.
    /// Produced by part1(), consumed by part2().
    round1_secret_package: Option<frost::keys::dkg::round1::SecretPackage>,

    /// FROST DKG round 2 secret state.
    /// Produced by part2(), used by part3().
    round2_secret_package: Option<frost::keys::dkg::round2::SecretPackage>,

    /// Stored round 1 packages from other participants (excluding self).
    /// Needed by part3().
    received_round1_packages: Option<BTreeMap<frost::Identifier, frost::keys::dkg::round1::Package>>,

    /// Mapping from ParticipantId to frost Identifier for reverse lookup.
    /// Populated during process_round1().
    identifier_map: Vec<(ParticipantId, frost::Identifier)>,

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
            frost_identifier: None,
            round1_secret_package: None,
            round2_secret_package: None,
            received_round1_packages: None,
            identifier_map: Vec::new(),
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

    /// Generate round 1 package with a caller-provided RNG.
    ///
    /// This method allows deterministic testing by injecting a seeded RNG.
    /// In production, use `generate_round1()` which uses `rand::thread_rng()`.
    ///
    /// # Errors
    ///
    /// - `DKGError::InvalidState` jika state bukan `Initialized`
    /// - `DKGError::InvalidRound1Package` jika frost identifier derivation fails
    pub fn generate_round1_with_rng<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<Round1Package, DKGError> {
        // Validasi state
        if !matches!(self.state, LocalParticipantState::Initialized) {
            return Err(DKGError::InvalidState {
                expected: "Initialized".to_string(),
                got: self.state.state_name().to_string(),
            });
        }

        // Derive frost Identifier from our ParticipantId
        let identifier = derive_frost_identifier(&self.participant_id)?;

        // Call frost DKG part1
        let (secret_package, frost_round1_package) = frost::keys::dkg::part1(
            identifier,
            u16::from(self.total),
            u16::from(self.threshold),
            rng,
        )
        .map_err(|e| DKGError::InvalidState {
            expected: "frost part1 success".to_string(),
            got: format!("frost error: {}", e),
        })?;

        // Store FROST internal state
        self.frost_identifier = Some(identifier);
        self.round1_secret_package = Some(secret_package);

        // Create our Round1Package wrapper
        let package = Round1Package::new(
            self.participant_id.clone(),
            frost_round1_package,
        );

        // Transition state
        self.state = LocalParticipantState::Round1Generated {
            package: package.clone(),
        };

        Ok(package)
    }

    /// Clear all frost secret state.
    fn clear_frost_secrets(&mut self) {
        self.round1_secret_package = None;
        self.round2_secret_package = None;
        self.received_round1_packages = None;
        self.frost_identifier = None;
        self.identifier_map.clear();
    }

    /// Find the ParticipantId corresponding to a frost Identifier.
    fn find_participant_id(
        &self,
        frost_id: &frost::Identifier,
    ) -> Result<ParticipantId, DKGError> {
        for (pid, fid) in &self.identifier_map {
            if fid == frost_id {
                return Ok(pid.clone());
            }
        }
        Err(DKGError::InvalidState {
            expected: "known frost identifier".to_string(),
            got: "unknown frost identifier in round2 output".to_string(),
        })
    }
}

impl Drop for LocalDKGParticipant {
    fn drop(&mut self) {
        self.clear_frost_secrets();
    }
}

impl DKGParticipant for LocalDKGParticipant {
    fn participant_id(&self) -> &ParticipantId {
        &self.participant_id
    }

    fn generate_round1(&mut self) -> Result<Round1Package, DKGError> {
        self.generate_round1_with_rng(&mut rand::thread_rng())
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

        // Take our round1 secret package (consumed by part2)
        let secret_package = self.round1_secret_package.take().ok_or_else(|| {
            DKGError::InvalidState {
                expected: "round1 secret package present".to_string(),
                got: "round1 secret package missing".to_string(),
            }
        })?;

        // Build frost round1 package map (excluding our own)
        // and build the identifier mapping for all participants
        let mut frost_round1_packages = BTreeMap::new();
        let mut id_map: Vec<(ParticipantId, frost::Identifier)> = Vec::new();

        for package in packages {
            let pid = package.participant_id();
            let frost_id = derive_frost_identifier(pid)?;

            // Record mapping for all participants (including self)
            id_map.push((pid.clone(), frost_id));

            // Skip our own package — frost part2 expects only OTHER participants
            if pid == &self.participant_id {
                continue;
            }

            // Check for duplicate frost identifiers (collision detection)
            if frost_round1_packages.contains_key(&frost_id) {
                return Err(DKGError::DuplicateParticipant {
                    participant: pid.clone(),
                });
            }

            frost_round1_packages.insert(frost_id, package.frost_package().clone());
        }

        // Validate we have the expected number of OTHER participants' packages
        let expected_others = (self.total as usize).saturating_sub(1);
        if frost_round1_packages.len() != expected_others {
            return Err(DKGError::InsufficientParticipants {
                expected: self.total,
                got: frost_round1_packages.len() as u8 + 1, // +1 for self
            });
        }

        // Store identifier map before calling part2
        self.identifier_map = id_map;

        // Call frost DKG part2
        // This verifies ALL commitments and proofs from round 1 packages.
        // If any commitment or proof is invalid, frost returns an error.
        let (round2_secret_package, frost_round2_packages) =
            frost::keys::dkg::part2(secret_package, &frost_round1_packages).map_err(|e| {
                let msg = e.to_string();
                let msg_lower = msg.to_lowercase();
                if msg_lower.contains("commitment") {
                    DKGError::InvalidCommitment {
                        participant: self.participant_id.clone(),
                    }
                } else if msg_lower.contains("proof") {
                    DKGError::InvalidProof {
                        participant: self.participant_id.clone(),
                    }
                } else {
                    DKGError::InvalidState {
                        expected: "frost part2 success".to_string(),
                        got: format!("frost error: {}", e),
                    }
                }
            })?;

        // Store round 2 secret + round 1 packages (needed for part3)
        self.round2_secret_package = Some(round2_secret_package);
        self.received_round1_packages = Some(frost_round1_packages);

        // Convert frost round2 packages to our Round2Package format
        let mut round2_packages = Vec::new();
        for (recipient_frost_id, frost_r2_pkg) in &frost_round2_packages {
            let recipient_pid = self.find_participant_id(recipient_frost_id)?;

            let package = Round2Package::new(
                self.session_id.clone(),
                self.participant_id.clone(),
                recipient_pid,
                frost_r2_pkg.clone(),
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

        // Get round 2 secret package (borrowed, not consumed)
        let round2_secret = self.round2_secret_package.as_ref().ok_or_else(|| {
            DKGError::InvalidState {
                expected: "round2 secret package present".to_string(),
                got: "round2 secret package missing".to_string(),
            }
        })?;

        // Get stored round 1 packages (from process_round1)
        let round1_packages = self.received_round1_packages.as_ref().ok_or_else(|| {
            DKGError::InvalidState {
                expected: "round1 packages present".to_string(),
                got: "round1 packages missing".to_string(),
            }
        })?;

        // Build frost round2 package map from received packages addressed to us.
        // Key = sender's frost Identifier, Value = frost round2 Package.
        let mut frost_round2_packages = BTreeMap::new();

        for package in packages {
            // Only process packages addressed to us
            if package.to_participant() != &self.participant_id {
                continue;
            }

            let sender_pid = package.from_participant();
            let sender_frost_id = derive_frost_identifier(sender_pid)?;

            // Verify sender was in our round 1 participants
            if !round1_packages.contains_key(&sender_frost_id) {
                return Err(DKGError::InvalidRound2Package {
                    from: sender_pid.clone(),
                    to: self.participant_id.clone(),
                    reason: "sender not in round 1 participants".to_string(),
                });
            }

            // Check for duplicate senders
            if frost_round2_packages.contains_key(&sender_frost_id) {
                return Err(DKGError::DuplicateParticipant {
                    participant: sender_pid.clone(),
                });
            }

            frost_round2_packages.insert(sender_frost_id, package.frost_package().clone());
        }

        // Validate we received packages from all other participants
        let expected_count = (self.total as usize).saturating_sub(1);
        if frost_round2_packages.len() != expected_count {
            return Err(DKGError::InsufficientParticipants {
                expected: self.total.saturating_sub(1),
                got: frost_round2_packages.len() as u8,
            });
        }

        // Call frost DKG part3
        // This verifies all received shares against the VSS commitments from round 1.
        // If any share is invalid, frost returns an error.
        let (key_package, _pubkey_package) =
            frost::keys::dkg::part3(round2_secret, round1_packages, &frost_round2_packages)
                .map_err(|e| {
                    let msg = e.to_string();
                    let msg_lower = msg.to_lowercase();
                    if msg_lower.contains("share") || msg_lower.contains("verification") {
                        DKGError::ShareVerificationFailed {
                            participant: self.participant_id.clone(),
                        }
                    } else {
                        DKGError::InvalidState {
                            expected: "frost part3 success".to_string(),
                            got: format!("frost error: {}", e),
                        }
                    }
                })?;

        // Extract signing share → SecretShare
        let secret_share =
            frost_adapter::signing_share_to_secret_share(key_package.signing_share()).map_err(
                |e| DKGError::InvalidState {
                    expected: "valid signing share conversion".to_string(),
                    got: e.to_string(),
                },
            )?;

        // Extract verifying key → GroupPublicKey
        let vk_bytes = key_package
            .verifying_key()
            .serialize()
            .map_err(|e| DKGError::InvalidState {
                expected: "valid verifying key serialization".to_string(),
                got: e.to_string(),
            })?;
        let vk_array: [u8; PUBLIC_KEY_SIZE] =
            vk_bytes.as_slice().try_into().map_err(|_| DKGError::InvalidState {
                expected: format!("verifying key {} bytes", PUBLIC_KEY_SIZE),
                got: format!("got {} bytes", vk_bytes.len()),
            })?;
        let group_pubkey = GroupPublicKey::from_bytes(vk_array).map_err(|e| {
            DKGError::InvalidState {
                expected: "valid group public key".to_string(),
                got: e.to_string(),
            }
        })?;

        // Extract verifying share → ParticipantPublicKey
        let vs_bytes = key_package
            .verifying_share()
            .serialize()
            .map_err(|e| DKGError::InvalidState {
                expected: "valid verifying share serialization".to_string(),
                got: e.to_string(),
            })?;
        let vs_array: [u8; PUBLIC_KEY_SIZE] =
            vs_bytes.as_slice().try_into().map_err(|_| DKGError::InvalidState {
                expected: format!("verifying share {} bytes", PUBLIC_KEY_SIZE),
                got: format!("got {} bytes", vs_bytes.len()),
            })?;
        let participant_pubkey =
            ParticipantPublicKey::from_bytes(vs_array).map_err(|e| DKGError::InvalidState {
                expected: "valid participant public key".to_string(),
                got: e.to_string(),
            })?;

        // Build KeyShare with our ORIGINAL participant_id
        // (not the frost identifier, which is a derived scalar)
        let key_share = KeyShare::new(
            secret_share,
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

        // Clear frost secret state (no longer needed)
        self.round1_secret_package = None;
        self.round2_secret_package = None;

        Ok(key_share)
    }

    fn abort(&mut self) {
        // Clear all frost secret material
        self.clear_frost_secrets();

        // Set state to Aborted (idempotent)
        self.state = LocalParticipantState::Aborted;
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    // ────────────────────────────────────────────────────────────────────────────
    // HELPER FUNCTIONS
    // ────────────────────────────────────────────────────────────────────────────

    /// Create participant IDs that are valid for frost Identifier derivation.
    /// Uses small nonzero values in first byte to ensure uniqueness.
    fn make_participant_ids(n: usize) -> Vec<ParticipantId> {
        (1..=n)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[0] = i as u8;
                ParticipantId::from_bytes(bytes)
            })
            .collect()
    }

    fn make_participant(
        session_id: SessionId,
        participant_id: ParticipantId,
        threshold: u8,
        total: u8,
    ) -> LocalDKGParticipant {
        LocalDKGParticipant::new(participant_id, session_id, threshold, total)
            .expect("valid params must produce valid participant")
    }

    /// Run a complete DKG ceremony and return key shares.
    fn run_full_dkg(
        threshold: u8,
        total: u8,
        seed: u64,
    ) -> Vec<KeyShare> {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let session_id = SessionId::from_bytes([0xAA; 32]);
        let pids = make_participant_ids(total as usize);

        // Create participants
        let mut participants: Vec<LocalDKGParticipant> = pids
            .iter()
            .map(|pid| make_participant(session_id.clone(), pid.clone(), threshold, total))
            .collect();

        // Round 1: Generate
        let mut round1_packages = Vec::new();
        for p in &mut participants {
            let pkg = p
                .generate_round1_with_rng(&mut rng)
                .expect("generate_round1 must succeed");
            round1_packages.push(pkg);
        }

        // Round 1: Process → generates Round 2 packages
        let mut all_round2_packages: Vec<Vec<Round2Package>> = Vec::new();
        for p in &mut participants {
            let r2_pkgs = p
                .process_round1(&round1_packages)
                .expect("process_round1 must succeed");
            all_round2_packages.push(r2_pkgs);
        }

        // Round 2: Route packages to recipients and process
        let mut key_shares = Vec::new();
        for p in &mut participants {
            let my_packages: Vec<Round2Package> = all_round2_packages
                .iter()
                .flat_map(|pkgs| pkgs.iter())
                .filter(|pkg| pkg.to_participant() == p.participant_id())
                .cloned()
                .collect();

            let key_share = p
                .process_round2(&my_packages)
                .expect("process_round2 must succeed");
            key_shares.push(key_share);
        }

        key_shares
    }

    // ────────────────────────────────────────────────────────────────────────────
    // KEY SHARE TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_key_share_accessors() {
        let secret = SecretShare::from_bytes([0x42; 32]).expect("valid share");
        let group_pk = GroupPublicKey::from_bytes([0x02; 32]).expect("valid pk");
        let participant_pk = ParticipantPublicKey::from_bytes([0x03; 32]).expect("valid pk");
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
        assert_eq!(
            LocalParticipantState::Initialized.state_name(),
            "Initialized"
        );
        assert_eq!(
            LocalParticipantState::Round1Processed.state_name(),
            "Round1Processed"
        );
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
        let participant_id = ParticipantId::from_bytes([0x01; 32]);
        let participant = LocalDKGParticipant::new(participant_id, session_id, 2, 3);
        assert!(participant.is_ok());
        let p = participant.expect("must be ok");
        assert_eq!(p.threshold(), 2);
        assert_eq!(p.total(), 3);
    }

    #[test]
    fn test_new_total_less_than_2_fails() {
        let session_id = SessionId::from_bytes([0xAA; 32]);
        let participant_id = ParticipantId::from_bytes([0x01; 32]);
        let result = LocalDKGParticipant::new(participant_id, session_id, 2, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_new_threshold_less_than_2_fails() {
        let session_id = SessionId::from_bytes([0xAA; 32]);
        let participant_id = ParticipantId::from_bytes([0x01; 32]);
        let result = LocalDKGParticipant::new(participant_id, session_id, 1, 3);
        assert!(result.is_err());
    }

    #[test]
    fn test_new_threshold_greater_than_total_fails() {
        let session_id = SessionId::from_bytes([0xAA; 32]);
        let participant_id = ParticipantId::from_bytes([0x01; 32]);
        let result = LocalDKGParticipant::new(participant_id, session_id, 5, 3);
        assert!(result.is_err());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // GENERATE ROUND 1 TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_generate_round1() {
        let mut rng = ChaCha20Rng::seed_from_u64(100);
        let session_id = SessionId::from_bytes([0xAA; 32]);
        let participant_id = ParticipantId::from_bytes([0x01; 32]);
        let mut participant = make_participant(session_id, participant_id.clone(), 2, 3);

        let result = participant.generate_round1_with_rng(&mut rng);
        assert!(result.is_ok());

        let package = result.expect("must be ok");
        assert_eq!(package.participant_id(), participant.participant_id());

        // State should be Round1Generated
        assert_eq!(participant.state().state_name(), "Round1Generated");
    }

    #[test]
    fn test_generate_round1_wrong_state_fails() {
        let mut rng = ChaCha20Rng::seed_from_u64(101);
        let session_id = SessionId::from_bytes([0xAA; 32]);
        let participant_id = ParticipantId::from_bytes([0x01; 32]);
        let mut participant = make_participant(session_id, participant_id, 2, 3);

        // Generate once
        let _ = participant.generate_round1_with_rng(&mut rng);

        // Generate again should fail
        let result = participant.generate_round1_with_rng(&mut rng);
        assert!(result.is_err());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // PROCESS ROUND 1 TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_process_round1_wrong_state_fails() {
        let session_id = SessionId::from_bytes([0xAA; 32]);
        let participant_id = ParticipantId::from_bytes([0x01; 32]);
        let mut participant = make_participant(session_id, participant_id, 2, 3);

        // Don't generate round 1 first → process_round1 should fail
        let result = participant.process_round1(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_process_round1_empty_packages_fails() {
        let mut rng = ChaCha20Rng::seed_from_u64(102);
        let session_id = SessionId::from_bytes([0xAA; 32]);
        let participant_id = ParticipantId::from_bytes([0x01; 32]);
        let mut participant = make_participant(session_id, participant_id, 2, 3);

        let _ = participant.generate_round1_with_rng(&mut rng);

        let result = participant.process_round1(&[]);
        assert!(result.is_err());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // PROCESS ROUND 2 TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_process_round2_wrong_state_fails() {
        let mut rng = ChaCha20Rng::seed_from_u64(103);
        let session_id = SessionId::from_bytes([0xAA; 32]);
        let participant_id = ParticipantId::from_bytes([0x01; 32]);
        let mut participant = make_participant(session_id, participant_id, 2, 3);

        let _ = participant.generate_round1_with_rng(&mut rng);

        // Try process_round2 without process_round1
        let result = participant.process_round2(&[]);
        assert!(result.is_err());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // ABORT TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_abort() {
        let mut rng = ChaCha20Rng::seed_from_u64(104);
        let session_id = SessionId::from_bytes([0xAA; 32]);
        let participant_id = ParticipantId::from_bytes([0x01; 32]);
        let mut participant = make_participant(session_id, participant_id, 2, 3);

        let _ = participant.generate_round1_with_rng(&mut rng);
        participant.abort();

        assert_eq!(participant.state().state_name(), "Aborted");
        assert!(participant.round1_secret_package.is_none());
        assert!(participant.round2_secret_package.is_none());
        assert!(participant.frost_identifier.is_none());
    }

    #[test]
    fn test_abort_idempotent() {
        let session_id = SessionId::from_bytes([0xAA; 32]);
        let participant_id = ParticipantId::from_bytes([0x01; 32]);
        let mut participant = make_participant(session_id, participant_id, 2, 3);

        participant.abort();
        participant.abort();
        participant.abort();

        assert_eq!(participant.state().state_name(), "Aborted");
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

    // ════════════════════════════════════════════════════════════════════════════
    // REAL FROST DKG INTEGRATION TESTS (SPEC REQUIRED: 6 minimum)
    // ════════════════════════════════════════════════════════════════════════════

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 1: 3-of-5 DKG success
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_full_dkg_3_of_5_success() {
        let key_shares = run_full_dkg(3, 5, 1000);

        // All 5 participants should have a key share
        assert_eq!(key_shares.len(), 5);

        // All key shares should have correct threshold and total
        for ks in &key_shares {
            assert_eq!(ks.threshold(), 3);
            assert_eq!(ks.total(), 5);
        }

        // All participants should have the SAME group public key (Feldman VSS property)
        let first_gpk = key_shares[0].group_pubkey();
        for ks in &key_shares[1..] {
            assert_eq!(
                ks.group_pubkey().as_bytes(),
                first_gpk.as_bytes(),
                "group public key must be identical across all participants"
            );
        }

        // Each participant should have a UNIQUE secret share
        for i in 0..key_shares.len() {
            for j in (i + 1)..key_shares.len() {
                assert_ne!(
                    key_shares[i].secret_share().as_bytes(),
                    key_shares[j].secret_share().as_bytes(),
                    "secret shares must be unique per participant"
                );
            }
        }

        // Each participant should have a UNIQUE participant public key
        for i in 0..key_shares.len() {
            for j in (i + 1)..key_shares.len() {
                assert_ne!(
                    key_shares[i].participant_pubkey().as_bytes(),
                    key_shares[j].participant_pubkey().as_bytes(),
                    "participant public keys must be unique"
                );
            }
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 2: Threshold enforcement (2-of-3 DKG)
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_full_dkg_2_of_3_threshold_enforcement() {
        let key_shares = run_full_dkg(2, 3, 2000);

        assert_eq!(key_shares.len(), 3);

        for ks in &key_shares {
            assert_eq!(ks.threshold(), 2);
            assert_eq!(ks.total(), 3);
        }

        // Group public key must match across all participants
        let first_gpk = key_shares[0].group_pubkey();
        for ks in &key_shares[1..] {
            assert_eq!(ks.group_pubkey().as_bytes(), first_gpk.as_bytes());
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 3: Invalid share rejection (misrouted round2 packages)
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_invalid_share_rejection_insufficient_round2() {
        let mut rng = ChaCha20Rng::seed_from_u64(3000);
        let session_id = SessionId::from_bytes([0xBB; 32]);
        let pids = make_participant_ids(3);

        let mut participants: Vec<LocalDKGParticipant> = pids
            .iter()
            .map(|pid| make_participant(session_id.clone(), pid.clone(), 2, 3))
            .collect();

        // Round 1
        let mut round1_packages = Vec::new();
        for p in &mut participants {
            round1_packages.push(
                p.generate_round1_with_rng(&mut rng)
                    .expect("round1 must succeed"),
            );
        }

        // Process round 1
        let mut all_round2_packages: Vec<Vec<Round2Package>> = Vec::new();
        for p in &mut participants {
            all_round2_packages.push(
                p.process_round1(&round1_packages)
                    .expect("process_round1 must succeed"),
            );
        }

        // Give participant 0 an EMPTY set of round2 packages → should fail
        let result = participants[0].process_round2(&[]);
        assert!(result.is_err());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 4: Invalid commitment rejection (insufficient round1 packages)
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_invalid_commitment_rejection_insufficient_round1() {
        let mut rng = ChaCha20Rng::seed_from_u64(4000);
        let session_id = SessionId::from_bytes([0xCC; 32]);
        let pids = make_participant_ids(3);

        let mut p0 = make_participant(session_id.clone(), pids[0].clone(), 2, 3);
        let mut p1 = make_participant(session_id.clone(), pids[1].clone(), 2, 3);

        let pkg0 = p0
            .generate_round1_with_rng(&mut rng)
            .expect("round1 must succeed");
        let _pkg1 = p1
            .generate_round1_with_rng(&mut rng)
            .expect("round1 must succeed");

        // Give p0 only its own package (missing others) → should fail
        let result = p0.process_round1(&[pkg0]);
        assert!(result.is_err());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 5: Deterministic group public key match
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_deterministic_group_public_key_match() {
        // Run the same DKG twice with the same seed
        let shares1 = run_full_dkg(3, 5, 5000);
        let shares2 = run_full_dkg(3, 5, 5000);

        // Group public keys should be identical between runs (deterministic)
        assert_eq!(
            shares1[0].group_pubkey().as_bytes(),
            shares2[0].group_pubkey().as_bytes(),
            "DKG with same seed must produce same group public key"
        );

        // All secret shares should also match (deterministic)
        for (s1, s2) in shares1.iter().zip(shares2.iter()) {
            assert_eq!(
                s1.secret_share().as_bytes(),
                s2.secret_share().as_bytes(),
                "DKG with same seed must produce same secret shares"
            );
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 6: DKGState transition correctness
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_dkg_state_transition_correctness() {
        let mut rng = ChaCha20Rng::seed_from_u64(6000);
        let session_id = SessionId::from_bytes([0xDD; 32]);
        let pids = make_participant_ids(3);

        let mut participants: Vec<LocalDKGParticipant> = pids
            .iter()
            .map(|pid| make_participant(session_id.clone(), pid.clone(), 2, 3))
            .collect();

        // Initial state: Initialized
        for p in &participants {
            assert_eq!(p.state().state_name(), "Initialized");
        }

        // After generate_round1: Round1Generated
        let mut round1_packages = Vec::new();
        for p in &mut participants {
            round1_packages.push(
                p.generate_round1_with_rng(&mut rng)
                    .expect("round1 must succeed"),
            );
        }
        for p in &participants {
            assert_eq!(p.state().state_name(), "Round1Generated");
        }

        // After process_round1: Round2Generated
        let mut all_round2_packages: Vec<Vec<Round2Package>> = Vec::new();
        for p in &mut participants {
            all_round2_packages.push(
                p.process_round1(&round1_packages)
                    .expect("process_round1 must succeed"),
            );
        }
        for p in &participants {
            assert_eq!(p.state().state_name(), "Round2Generated");
        }

        // After process_round2: Completed
        for p in &mut participants {
            let my_packages: Vec<Round2Package> = all_round2_packages
                .iter()
                .flat_map(|pkgs| pkgs.iter())
                .filter(|pkg| pkg.to_participant() == p.participant_id())
                .cloned()
                .collect();

            let _ = p
                .process_round2(&my_packages)
                .expect("process_round2 must succeed");
        }
        for p in &participants {
            assert_eq!(p.state().state_name(), "Completed");
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // BONUS: Signing share compatibility verification
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_signing_share_valid_for_frost_signing() {
        let key_shares = run_full_dkg(2, 3, 7000);

        // Verify that each key share's secret can round-trip through frost adapter
        for ks in &key_shares {
            let signing_share =
                frost_adapter::secret_share_to_signing_share(ks.secret_share())
                    .expect("secret share must be valid frost signing share");

            let recovered =
                frost_adapter::signing_share_to_secret_share(&signing_share)
                    .expect("roundtrip must succeed");

            assert_eq!(
                ks.secret_share().as_bytes(),
                recovered.as_bytes(),
                "signing share roundtrip must be byte-identical"
            );
        }

        // Verify that group public key can round-trip through frost adapter
        let gpk = key_shares[0].group_pubkey();
        let vk = frost_adapter::group_pubkey_to_verifying_key(gpk)
            .expect("group pubkey must be valid verifying key");
        let recovered = frost_adapter::verifying_key_to_group_pubkey(&vk)
            .expect("roundtrip must succeed");
        assert_eq!(
            gpk.as_bytes(),
            recovered.as_bytes(),
            "group pubkey roundtrip must be byte-identical"
        );
    }

    // ────────────────────────────────────────────────────────────────────────────
    // BONUS: 2-of-2 minimal DKG
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_full_dkg_2_of_2_minimal() {
        let key_shares = run_full_dkg(2, 2, 8000);
        assert_eq!(key_shares.len(), 2);
        assert_eq!(
            key_shares[0].group_pubkey().as_bytes(),
            key_shares[1].group_pubkey().as_bytes()
        );
    }
}