//! # DKG Session Controller
//!
//! Module ini menyediakan `DKGSession` sebagai stateful controller
//! untuk mengelola lifecycle Distributed Key Generation.
//!
//! ## Lifecycle
//!
//! ```text
//! ┌───────────────────────────────────────────────────────────────────────────┐
//! │                         DKGSession Lifecycle                               │
//! └───────────────────────────────────────────────────────────────────────────┘
//!
//!   new() ──► Initialized
//!                 │
//!                 │ start_round1()
//!                 ▼
//!            Round1Commitment
//!                 │
//!                 │ add_round1_package() × n
//!                 │ complete_round1()
//!                 ▼
//!            Round1Complete
//!                 │
//!                 │ start_round2()
//!                 ▼
//!            Round2Share
//!                 │
//!                 │ add_round2_package() × (n × (n-1))
//!                 ▼
//!            Round2Complete
//!                 │
//!                 │ complete_round2(group_pubkey)
//!                 ▼
//!            Completed
//! ```
//!
//! ## Error Handling
//!
//! Semua method yang dapat gagal mengembalikan `Result<_, DKGError>`.
//! Tidak ada panic atau unwrap dalam implementasi.
//!
//! ## Thread Safety
//!
//! `DKGSession` adalah `Send + Sync` secara struktural karena semua
//! field-nya juga `Send + Sync`.

use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::DKGError;
use crate::primitives::GroupPublicKey;
use crate::types::{ParticipantId, SessionId};

use super::packages::{Round1Package, Round2Package};
use super::state::DKGState;

// ════════════════════════════════════════════════════════════════════════════════
// DKG SESSION CONFIG
// ════════════════════════════════════════════════════════════════════════════════

/// Configuration untuk DKG session.
///
/// Struct ini bersifat **pasif** dan disiapkan untuk tahap selanjutnya.
/// Saat ini tidak mengubah behavior default `DKGSession`.
///
/// ## Fields
///
/// - `timeout_secs`: Timeout dalam detik untuk menunggu packages
/// - `allow_late_packages`: Apakah packages yang datang terlambat diterima
///
/// ## Contoh
///
/// ```rust
/// use dsdn_tss::dkg::DKGSessionConfig;
///
/// let config = DKGSessionConfig::default();
/// assert_eq!(config.timeout_secs(), 300);
/// assert!(!config.allow_late_packages());
/// ```
#[derive(Debug, Clone)]
pub struct DKGSessionConfig {
    /// Timeout dalam detik untuk menunggu packages dari participants.
    timeout_secs: u64,

    /// Apakah packages yang datang setelah round selesai boleh diterima.
    allow_late_packages: bool,
}

impl DKGSessionConfig {
    /// Membuat configuration baru dengan nilai custom.
    #[must_use]
    pub const fn new(timeout_secs: u64, allow_late_packages: bool) -> Self {
        Self {
            timeout_secs,
            allow_late_packages,
        }
    }

    /// Mengembalikan timeout dalam detik.
    #[must_use]
    pub const fn timeout_secs(&self) -> u64 {
        self.timeout_secs
    }

    /// Mengembalikan apakah late packages diizinkan.
    #[must_use]
    pub const fn allow_late_packages(&self) -> bool {
        self.allow_late_packages
    }
}

impl Default for DKGSessionConfig {
    fn default() -> Self {
        Self {
            timeout_secs: 300, // 5 menit
            allow_late_packages: false,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// DKG SESSION
// ════════════════════════════════════════════════════════════════════════════════

/// Controller untuk mengelola DKG session lifecycle.
///
/// `DKGSession` adalah stateful controller yang mengelola:
/// - Participant registration
/// - Round 1 package collection
/// - Round 2 package distribution
/// - State transitions
/// - Error handling
///
/// ## Invariant
///
/// - `threshold` selalu >= 2
/// - `threshold` selalu <= `total`
/// - `total` selalu == `participants.len()`
/// - Tidak ada duplicate participants
///
/// ## Contoh
///
/// ```rust
/// use dsdn_tss::dkg::{DKGSession, DKGState, Round1Package};
/// use dsdn_tss::{SessionId, ParticipantId};
///
/// // Create session dengan 3 participants dan threshold 2
/// let session_id = SessionId::new();
/// let participants = vec![
///     ParticipantId::new(),
///     ParticipantId::new(),
///     ParticipantId::new(),
/// ];
///
/// let mut session = DKGSession::new(session_id, participants, 2).unwrap();
///
/// // Start round 1
/// session.start_round1().unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct DKGSession {
    /// Identifier unik untuk session ini.
    session_id: SessionId,

    /// Daftar participant yang terdaftar dalam session.
    participants: Vec<ParticipantId>,

    /// Threshold signature yang diperlukan (t dalam t-of-n).
    threshold: u8,

    /// Total jumlah participants (n dalam t-of-n).
    total: u8,

    /// State machine DKG saat ini.
    state: DKGState,

    /// Unix timestamp (dalam detik) saat session dibuat.
    created_at: u64,

    /// Round 1 packages yang sudah diterima.
    /// Key: participant_id, Value: Round1Package dari participant tersebut.
    round1_packages: HashMap<ParticipantId, Round1Package>,

    /// Round 2 packages yang sudah diterima.
    /// Key: recipient participant_id, Value: Vec<Round2Package> dari semua senders.
    round2_packages: HashMap<ParticipantId, Vec<Round2Package>>,
}

impl DKGSession {
    /// Membuat DKG session baru.
    ///
    /// # Arguments
    ///
    /// * `session_id` - Identifier unik untuk session
    /// * `participants` - Daftar participant yang akan ikut DKG
    /// * `threshold` - Threshold signature yang diperlukan
    ///
    /// # Validasi
    ///
    /// - `participants` tidak boleh kosong
    /// - `threshold` harus >= 2
    /// - `threshold` harus <= `participants.len()`
    /// - Tidak boleh ada duplicate participants
    ///
    /// # Errors
    ///
    /// - `DKGError::InsufficientParticipants` jika participants kosong
    /// - `DKGError::InvalidThreshold` jika threshold tidak valid
    /// - `DKGError::DuplicateParticipant` jika ada participant duplikat
    ///
    /// # Example
    ///
    /// ```rust
    /// use dsdn_tss::dkg::DKGSession;
    /// use dsdn_tss::{SessionId, ParticipantId};
    ///
    /// let session_id = SessionId::new();
    /// let participants = vec![
    ///     ParticipantId::new(),
    ///     ParticipantId::new(),
    ///     ParticipantId::new(),
    /// ];
    ///
    /// let session = DKGSession::new(session_id, participants, 2).unwrap();
    /// assert_eq!(session.threshold(), 2);
    /// assert_eq!(session.total(), 3);
    /// ```
    pub fn new(
        session_id: SessionId,
        participants: Vec<ParticipantId>,
        threshold: u8,
    ) -> Result<Self, DKGError> {
        // Validasi: participants tidak boleh kosong
        if participants.is_empty() {
            return Err(DKGError::InsufficientParticipants { expected: 1, got: 0 });
        }

        // Validasi: participants.len() harus fit dalam u8
        let total = if participants.len() > u8::MAX as usize {
            return Err(DKGError::InsufficientParticipants {
                expected: 1,
                got: u8::MAX,
            });
        } else {
            participants.len() as u8
        };

        // Validasi: threshold >= 2
        if threshold < 2 {
            return Err(DKGError::InvalidThreshold { threshold, total });
        }

        // Validasi: threshold <= total
        if threshold > total {
            return Err(DKGError::InvalidThreshold { threshold, total });
        }

        // Validasi: tidak ada duplicate participants
        let mut seen = HashSet::with_capacity(participants.len());
        for participant in &participants {
            if !seen.insert(participant.clone()) {
                return Err(DKGError::DuplicateParticipant {
                    participant: participant.clone(),
                });
            }
        }

        // Get current timestamp
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0); // Fallback to 0 jika system time error

        Ok(Self {
            session_id,
            participants,
            threshold,
            total,
            state: DKGState::Initialized,
            created_at,
            round1_packages: HashMap::new(),
            round2_packages: HashMap::new(),
        })
    }

    // ────────────────────────────────────────────────────────────────────────────
    // STATE QUERIES (no side effects)
    // ────────────────────────────────────────────────────────────────────────────

    /// Mengembalikan session ID.
    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
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

    /// Mengembalikan current state.
    #[must_use]
    pub const fn state(&self) -> &DKGState {
        &self.state
    }

    /// Mengembalikan timestamp pembuatan session.
    #[must_use]
    pub const fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Mengecek apakah DKG sudah selesai (Completed state).
    #[must_use]
    pub fn is_complete(&self) -> bool {
        matches!(self.state, DKGState::Completed { .. })
    }

    /// Mengecek apakah DKG gagal (Failed state).
    #[must_use]
    pub fn is_failed(&self) -> bool {
        matches!(self.state, DKGState::Failed { .. })
    }

    /// Mengembalikan slice participants.
    #[must_use]
    pub fn participants(&self) -> &[ParticipantId] {
        &self.participants
    }

    /// Mengecek apakah participant_id terdaftar dalam session.
    #[must_use]
    pub fn is_participant(&self, participant_id: &ParticipantId) -> bool {
        self.participants.iter().any(|p| p == participant_id)
    }

    // ────────────────────────────────────────────────────────────────────────────
    // ROUND 1 LOGIC
    // ────────────────────────────────────────────────────────────────────────────

    /// Memulai Round 1 DKG.
    ///
    /// Transisi state dari `Initialized` ke `Round1Commitment`.
    ///
    /// # Errors
    ///
    /// - `DKGError::InvalidState` jika state bukan `Initialized`
    pub fn start_round1(&mut self) -> Result<(), DKGError> {
        let next = DKGState::Round1Commitment;

        if !self.state.can_transition_to(&next) {
            return Err(DKGError::InvalidState {
                expected: "Initialized".to_string(),
                got: self.state.state_name().to_string(),
            });
        }

        self.state = next;
        Ok(())
    }

    /// Menambahkan Round 1 package dari participant.
    ///
    /// # Validasi
    ///
    /// - State harus `Round1Commitment`
    /// - Participant harus terdaftar
    /// - Tidak boleh ada duplicate package dari participant yang sama
    ///
    /// Commitment dan proof verification dilakukan otomatis oleh frost library
    /// saat `frost::keys::dkg::part2()` di `LocalDKGParticipant::process_round1()`.
    ///
    /// # Errors
    ///
    /// - `DKGError::InvalidState` jika state bukan `Round1Commitment`
    /// - `DKGError::InvalidRound1Package` jika participant tidak terdaftar
    /// - `DKGError::DuplicateParticipant` jika package sudah ada
    pub fn add_round1_package(&mut self, package: Round1Package) -> Result<(), DKGError> {
        // Validasi state
        if !matches!(self.state, DKGState::Round1Commitment) {
            return Err(DKGError::InvalidState {
                expected: "Round1Commitment".to_string(),
                got: self.state.state_name().to_string(),
            });
        }

        let participant_id = package.participant_id().clone();

        // Validasi participant terdaftar
        if !self.is_participant(&participant_id) {
            return Err(DKGError::InvalidRound1Package {
                participant: participant_id,
                reason: "participant not registered in session".to_string(),
            });
        }

        // Validasi tidak duplicate
        if self.round1_packages.contains_key(&participant_id) {
            return Err(DKGError::DuplicateParticipant {
                participant: participant_id,
            });
        }

        // Note: Commitment dan proof verification dilakukan oleh frost library
        // secara otomatis saat frost::keys::dkg::part2() dipanggil.
        // Session controller hanya collect dan route packages.

        // Insert package
        self.round1_packages.insert(participant_id, package);

        Ok(())
    }

    /// Mengecek apakah semua Round 1 packages sudah diterima.
    #[must_use]
    pub fn has_all_round1_packages(&self) -> bool {
        self.round1_packages.len() == self.total as usize
    }

    /// Mengembalikan reference ke round1_packages HashMap.
    #[must_use]
    pub fn get_round1_packages(&self) -> &HashMap<ParticipantId, Round1Package> {
        &self.round1_packages
    }

    /// Menyelesaikan Round 1 dan transisi ke Round1Complete.
    ///
    /// # Validasi
    ///
    /// - State harus `Round1Commitment`
    /// - Semua packages harus sudah diterima
    ///
    /// # Errors
    ///
    /// - `DKGError::InvalidState` jika state bukan `Round1Commitment`
    /// - `DKGError::InsufficientParticipants` jika packages belum lengkap
    pub fn complete_round1(&mut self) -> Result<(), DKGError> {
        // Validasi state
        if !matches!(self.state, DKGState::Round1Commitment) {
            return Err(DKGError::InvalidState {
                expected: "Round1Commitment".to_string(),
                got: self.state.state_name().to_string(),
            });
        }

        // Validasi semua packages sudah diterima
        if !self.has_all_round1_packages() {
            return Err(DKGError::InsufficientParticipants {
                expected: self.total,
                got: self.round1_packages.len() as u8,
            });
        }

        // Transition ke Round1Complete dengan commitments
        let next = DKGState::Round1Complete {
            commitments: self.round1_packages.clone(),
        };

        if !self.state.can_transition_to(&next) {
            return Err(DKGError::InvalidState {
                expected: "Round1Commitment".to_string(),
                got: self.state.state_name().to_string(),
            });
        }

        self.state = next;
        Ok(())
    }

    // ────────────────────────────────────────────────────────────────────────────
    // ROUND 2 LOGIC
    // ────────────────────────────────────────────────────────────────────────────

    /// Memulai Round 2 DKG.
    ///
    /// Transisi state dari `Round1Complete` ke `Round2Share`.
    ///
    /// # Errors
    ///
    /// - `DKGError::InvalidState` jika state bukan `Round1Complete`
    pub fn start_round2(&mut self) -> Result<(), DKGError> {
        let next = DKGState::Round2Share;

        if !self.state.can_transition_to(&next) {
            return Err(DKGError::InvalidState {
                expected: "Round1Complete".to_string(),
                got: self.state.state_name().to_string(),
            });
        }

        // Initialize round2_packages with empty Vec for each participant
        for participant in &self.participants {
            self.round2_packages.insert(participant.clone(), Vec::new());
        }

        self.state = next;
        Ok(())
    }

    /// Menambahkan Round 2 package.
    ///
    /// # Validasi
    ///
    /// - State harus `Round2Share`
    /// - `from_participant` harus terdaftar
    /// - `to_participant` harus terdaftar
    /// - Tidak boleh ada duplicate share dari sender ke recipient yang sama
    ///
    /// # Errors
    ///
    /// - `DKGError::InvalidState` jika state bukan `Round2Share`
    /// - `DKGError::InvalidRound2Package` jika participant tidak valid
    pub fn add_round2_package(&mut self, package: Round2Package) -> Result<(), DKGError> {
        // Validasi state
        if !matches!(self.state, DKGState::Round2Share) {
            return Err(DKGError::InvalidState {
                expected: "Round2Share".to_string(),
                got: self.state.state_name().to_string(),
            });
        }

        let from = package.from_participant().clone();
        let to = package.to_participant().clone();

        // Validasi from_participant terdaftar
        if !self.is_participant(&from) {
            return Err(DKGError::InvalidRound2Package {
                from: from.clone(),
                to: to.clone(),
                reason: "sender not registered in session".to_string(),
            });
        }

        // Validasi to_participant terdaftar
        if !self.is_participant(&to) {
            return Err(DKGError::InvalidRound2Package {
                from: from.clone(),
                to: to.clone(),
                reason: "recipient not registered in session".to_string(),
            });
        }

        // Get packages for recipient
        let packages = self
            .round2_packages
            .entry(to.clone())
            .or_insert_with(Vec::new);

        // Check for duplicate (same sender to same recipient)
        let has_duplicate = packages
            .iter()
            .any(|p| p.from_participant() == &from);

        if has_duplicate {
            return Err(DKGError::InvalidRound2Package {
                from,
                to,
                reason: "duplicate share from same sender".to_string(),
            });
        }

        // Insert package
        packages.push(package);

        Ok(())
    }

    /// Mengecek apakah semua Round 2 packages sudah diterima.
    ///
    /// Setiap participant harus menerima share dari semua participant lain.
    /// Total packages per recipient = total - 1 (tidak termasuk diri sendiri).
    #[must_use]
    pub fn has_all_round2_packages(&self) -> bool {
        let expected_per_recipient = (self.total - 1) as usize;

        for participant in &self.participants {
            let count = self
                .round2_packages
                .get(participant)
                .map(|v| v.len())
                .unwrap_or(0);

            if count < expected_per_recipient {
                return false;
            }
        }

        true
    }

    /// Mengembalikan Round 2 packages untuk participant tertentu.
    #[must_use]
    pub fn get_round2_packages_for(&self, participant: &ParticipantId) -> Vec<&Round2Package> {
        self.round2_packages
            .get(participant)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Menandai Round 2 selesai (internal use).
    ///
    /// Dipanggil ketika semua round2 packages sudah diterima.
    fn try_complete_round2_collection(&mut self) -> Result<(), DKGError> {
        if !matches!(self.state, DKGState::Round2Share) {
            return Ok(()); // Not in correct state, no-op
        }

        if !self.has_all_round2_packages() {
            return Ok(()); // Not all packages received yet
        }

        let next = DKGState::Round2Complete {
            shares: self.round2_packages.clone(),
        };

        if !self.state.can_transition_to(&next) {
            return Err(DKGError::InvalidState {
                expected: "Round2Share".to_string(),
                got: self.state.state_name().to_string(),
            });
        }

        self.state = next;
        Ok(())
    }

    /// Menyelesaikan DKG dan set group public key.
    ///
    /// # Arguments
    ///
    /// * `group_pubkey` - Group public key hasil DKG
    ///
    /// # Validasi
    ///
    /// - State harus `Round2Share` atau `Round2Complete`
    /// - Jika `Round2Share`, harus sudah semua packages diterima
    ///
    /// # Errors
    ///
    /// - `DKGError::InvalidState` jika state tidak valid
    pub fn complete_round2(&mut self, group_pubkey: GroupPublicKey) -> Result<(), DKGError> {
        // Try to transition to Round2Complete if still in Round2Share
        if matches!(self.state, DKGState::Round2Share) {
            self.try_complete_round2_collection()?;
        }

        // Validasi state - harus Round2Complete
        if !matches!(self.state, DKGState::Round2Complete { .. }) {
            return Err(DKGError::InvalidState {
                expected: "Round2Complete".to_string(),
                got: self.state.state_name().to_string(),
            });
        }

        let next = DKGState::Completed { group_pubkey };

        if !self.state.can_transition_to(&next) {
            return Err(DKGError::InvalidState {
                expected: "Round2Complete".to_string(),
                got: self.state.state_name().to_string(),
            });
        }

        self.state = next;
        Ok(())
    }

    // ────────────────────────────────────────────────────────────────────────────
    // ERROR HANDLING
    // ────────────────────────────────────────────────────────────────────────────

    /// Set session ke Failed state.
    ///
    /// Dapat dipanggil dari state manapun kecuali Completed.
    /// Jika sudah Completed, tidak ada efek.
    ///
    /// # Arguments
    ///
    /// * `error` - Error yang menyebabkan kegagalan
    pub fn fail(&mut self, error: DKGError) {
        // Tidak overwrite Completed state
        if self.is_complete() {
            return;
        }

        // Tidak overwrite jika sudah Failed
        if self.is_failed() {
            return;
        }

        self.state = DKGState::Failed { error };
    }
}


// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use frost_ed25519 as frost;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::collections::BTreeMap;

    // ────────────────────────────────────────────────────────────────────────────
    // HELPER FUNCTIONS
    // ────────────────────────────────────────────────────────────────────────────

    fn make_participants(n: usize) -> Vec<ParticipantId> {
        (0..n)
            .map(|i| ParticipantId::from_bytes([i as u8; 32]))
            .collect()
    }

    fn make_session(n: usize, threshold: u8) -> DKGSession {
        let session_id = SessionId::from_bytes([0xAA; 32]);
        let participants = make_participants(n);
        DKGSession::new(session_id, participants, threshold).expect("valid session params")
    }

    /// Create a deterministic frost Identifier from u16.
    fn frost_id(n: u16) -> frost::Identifier {
        frost::Identifier::try_from(n).expect("nonzero u16 → valid Identifier")
    }

    /// Generate real FROST round1 packages for n participants with given threshold.
    /// Participant i gets ParticipantId::from_bytes([i as u8; 32]) and frost_id(i+1).
    fn generate_real_round1_packages(
        n: usize,
        threshold: u16,
        rng: &mut ChaCha20Rng,
    ) -> Vec<Round1Package> {
        let mut packages = Vec::new();
        for i in 0..n {
            let fid = frost_id((i + 1) as u16);
            let (_secret, frost_pkg) =
                frost::keys::dkg::part1(fid, n as u16, threshold, &mut *rng)
                    .expect("part1 must succeed");
            let pid = ParticipantId::from_bytes([i as u8; 32]);
            packages.push(Round1Package::new(pid, frost_pkg));
        }
        packages
    }

    /// Generate a real FROST round2 package (from_idx → to_idx).
    /// Uses independent part1+part2 calls (packages won't be cryptographically
    /// linked to the session's round1, but the types are correct for routing tests).
    fn generate_real_round2_package(
        session_id: SessionId,
        from_idx: u8,
        to_idx: u8,
        rng: &mut ChaCha20Rng,
    ) -> Round2Package {
        let fid_from = frost_id((from_idx + 1) as u16);
        let fid_to = frost_id((to_idx + 1) as u16);

        let (secret_from, _pkg_from) =
            frost::keys::dkg::part1(fid_from, 2, 2, &mut *rng).expect("part1 from");
        let (_secret_to, pkg_to) =
            frost::keys::dkg::part1(fid_to, 2, 2, &mut *rng).expect("part1 to");

        let mut r1_map = BTreeMap::new();
        r1_map.insert(fid_to, pkg_to);

        let (_r2_secret, r2_pkgs) =
            frost::keys::dkg::part2(secret_from, &r1_map).expect("part2 must succeed");

        let frost_r2 = r2_pkgs.get(&fid_to).expect("must have package").clone();

        let p_from = ParticipantId::from_bytes([from_idx; 32]);
        let p_to = ParticipantId::from_bytes([to_idx; 32]);
        Round2Package::new(session_id, p_from, p_to, frost_r2)
    }

    /// Helper: advance session to Round2Share state with real round1 packages.
    fn setup_round2_session() -> DKGSession {
        let mut rng = ChaCha20Rng::seed_from_u64(999);
        let mut session = make_session(3, 2);
        session.start_round1().expect("start_round1");

        let packages = generate_real_round1_packages(3, 2, &mut rng);
        for pkg in packages {
            session.add_round1_package(pkg).expect("add_round1_package");
        }

        session.complete_round1().expect("complete_round1");
        session.start_round2().expect("start_round2");
        session
    }

    /// Helper: fill all round2 packages into a session in Round2Share state.
    fn fill_round2_packages(session: &mut DKGSession, rng: &mut ChaCha20Rng) {
        let session_id = session.session_id().clone();
        for from in 0..3u8 {
            for to in 0..3u8 {
                if from != to {
                    let pkg = generate_real_round2_package(
                        session_id.clone(), from, to, rng,
                    );
                    session.add_round2_package(pkg).expect("add r2");
                }
            }
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // CONSTRUCTOR TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_new_valid() {
        let session = make_session(3, 2);
        assert_eq!(session.threshold(), 2);
        assert_eq!(session.total(), 3);
        assert!(!session.is_complete());
        assert!(!session.is_failed());
        assert_eq!(session.state().state_name(), "Initialized");
    }

    #[test]
    fn test_new_threshold_equals_total() {
        let session = make_session(3, 3);
        assert_eq!(session.threshold(), 3);
        assert_eq!(session.total(), 3);
    }

    #[test]
    fn test_new_empty_participants_fails() {
        let session_id = SessionId::from_bytes([0xAA; 32]);
        let result = DKGSession::new(session_id, vec![], 2);
        assert!(result.is_err());
        match result {
            Err(DKGError::InsufficientParticipants { expected: 1, got: 0 }) => {}
            _ => panic!("expected InsufficientParticipants error"),
        }
    }

    #[test]
    fn test_new_threshold_less_than_2_fails() {
        let session_id = SessionId::from_bytes([0xAA; 32]);
        let participants = make_participants(3);
        let result = DKGSession::new(session_id, participants, 1);
        assert!(result.is_err());
        match result {
            Err(DKGError::InvalidThreshold { threshold: 1, total: 3 }) => {}
            _ => panic!("expected InvalidThreshold error"),
        }
    }

    #[test]
    fn test_new_threshold_greater_than_total_fails() {
        let session_id = SessionId::from_bytes([0xAA; 32]);
        let participants = make_participants(3);
        let result = DKGSession::new(session_id, participants, 5);
        assert!(result.is_err());
        match result {
            Err(DKGError::InvalidThreshold { threshold: 5, total: 3 }) => {}
            _ => panic!("expected InvalidThreshold error"),
        }
    }

    #[test]
    fn test_new_duplicate_participants_fails() {
        let session_id = SessionId::from_bytes([0xAA; 32]);
        let p1 = ParticipantId::from_bytes([0x11; 32]);
        let participants = vec![p1.clone(), p1.clone(), ParticipantId::from_bytes([0x22; 32])];
        let result = DKGSession::new(session_id, participants, 2);
        assert!(result.is_err());
        match result {
            Err(DKGError::DuplicateParticipant { .. }) => {}
            _ => panic!("expected DuplicateParticipant error"),
        }
    }

    #[test]
    fn test_new_created_at_is_set() {
        let session = make_session(3, 2);
        assert!(session.created_at() > 0);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // STATE QUERY TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_session_id() {
        let session_id = SessionId::from_bytes([0xBB; 32]);
        let participants = make_participants(3);
        let session = DKGSession::new(session_id.clone(), participants, 2).expect("ok");
        assert_eq!(session.session_id(), &session_id);
    }

    #[test]
    fn test_participants() {
        let session = make_session(3, 2);
        assert_eq!(session.participants().len(), 3);
    }

    #[test]
    fn test_is_participant() {
        let session = make_session(3, 2);
        let p0 = ParticipantId::from_bytes([0; 32]);
        let unknown = ParticipantId::from_bytes([0xFF; 32]);
        assert!(session.is_participant(&p0));
        assert!(!session.is_participant(&unknown));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // ROUND 1 TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_start_round1() {
        let mut session = make_session(3, 2);
        assert!(session.start_round1().is_ok());
        assert_eq!(session.state().state_name(), "Round1Commitment");
    }

    #[test]
    fn test_start_round1_twice_fails() {
        let mut session = make_session(3, 2);
        session.start_round1().expect("first start");
        let result = session.start_round1();
        assert!(result.is_err());
    }

    #[test]
    fn test_add_round1_package() {
        let mut rng = ChaCha20Rng::seed_from_u64(100);
        let mut session = make_session(3, 2);
        session.start_round1().expect("start");

        let packages = generate_real_round1_packages(3, 2, &mut rng);
        assert!(session.add_round1_package(packages[0].clone()).is_ok());
        assert_eq!(session.get_round1_packages().len(), 1);
    }

    #[test]
    fn test_add_round1_package_wrong_state_fails() {
        let mut rng = ChaCha20Rng::seed_from_u64(101);
        let mut session = make_session(3, 2);
        // Don't start round1

        let packages = generate_real_round1_packages(3, 2, &mut rng);
        let result = session.add_round1_package(packages[0].clone());
        assert!(result.is_err());
    }

    #[test]
    fn test_add_round1_package_unregistered_participant_fails() {
        let mut rng = ChaCha20Rng::seed_from_u64(102);
        let mut session = make_session(3, 2);
        session.start_round1().expect("start");

        let fid = frost_id(1);
        let (_secret, frost_pkg) =
            frost::keys::dkg::part1(fid, 3, 2, &mut rng).expect("part1");
        let unknown = ParticipantId::from_bytes([0xFF; 32]);
        let package = Round1Package::new(unknown, frost_pkg);

        let result = session.add_round1_package(package);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_round1_package_duplicate_fails() {
        let mut rng = ChaCha20Rng::seed_from_u64(103);
        let mut session = make_session(3, 2);
        session.start_round1().expect("start");

        let p0 = ParticipantId::from_bytes([0; 32]);
        let fid = frost_id(1);

        let (_s1, fp1) = frost::keys::dkg::part1(fid, 3, 2, &mut rng).expect("p1a");
        let (_s2, fp2) = frost::keys::dkg::part1(fid, 3, 2, &mut rng).expect("p1b");

        let package1 = Round1Package::new(p0.clone(), fp1);
        let package2 = Round1Package::new(p0, fp2);

        session.add_round1_package(package1).expect("first add");
        let result = session.add_round1_package(package2);
        assert!(result.is_err());
    }

    #[test]
    fn test_has_all_round1_packages() {
        let mut rng = ChaCha20Rng::seed_from_u64(104);
        let mut session = make_session(3, 2);
        session.start_round1().expect("start");

        assert!(!session.has_all_round1_packages());

        let packages = generate_real_round1_packages(3, 2, &mut rng);
        for pkg in packages {
            session.add_round1_package(pkg).expect("add");
        }

        assert!(session.has_all_round1_packages());
    }

    #[test]
    fn test_complete_round1() {
        let mut rng = ChaCha20Rng::seed_from_u64(105);
        let mut session = make_session(3, 2);
        session.start_round1().expect("start");

        let packages = generate_real_round1_packages(3, 2, &mut rng);
        for pkg in packages {
            session.add_round1_package(pkg).expect("add");
        }

        assert!(session.complete_round1().is_ok());
        assert_eq!(session.state().state_name(), "Round1Complete");
    }

    #[test]
    fn test_complete_round1_incomplete_fails() {
        let mut rng = ChaCha20Rng::seed_from_u64(106);
        let mut session = make_session(3, 2);
        session.start_round1().expect("start");

        // Only add 2 of 3 packages
        let packages = generate_real_round1_packages(3, 2, &mut rng);
        for pkg in packages.into_iter().take(2) {
            session.add_round1_package(pkg).expect("add");
        }

        let result = session.complete_round1();
        assert!(result.is_err());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // ROUND 2 TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_start_round2() {
        let mut rng = ChaCha20Rng::seed_from_u64(200);
        let mut session = make_session(3, 2);
        session.start_round1().expect("start r1");

        let packages = generate_real_round1_packages(3, 2, &mut rng);
        for pkg in packages {
            session.add_round1_package(pkg).expect("add r1");
        }

        session.complete_round1().expect("complete r1");
        assert!(session.start_round2().is_ok());
        assert_eq!(session.state().state_name(), "Round2Share");
    }

    #[test]
    fn test_add_round2_package() {
        let mut session = setup_round2_session();
        let mut rng = ChaCha20Rng::seed_from_u64(201);
        let session_id = session.session_id().clone();

        let p1 = ParticipantId::from_bytes([1; 32]);
        let package = generate_real_round2_package(session_id, 0, 1, &mut rng);
        assert!(session.add_round2_package(package).is_ok());

        let packages = session.get_round2_packages_for(&p1);
        assert_eq!(packages.len(), 1);
    }

    #[test]
    fn test_add_round2_package_unregistered_sender_fails() {
        let mut session = setup_round2_session();
        let mut rng = ChaCha20Rng::seed_from_u64(202);

        // Generate real frost r2 package but assign to unknown sender
        let fid1 = frost_id(1);
        let fid2 = frost_id(2);
        let (s1, _) = frost::keys::dkg::part1(fid1, 2, 2, &mut rng).expect("p1a");
        let (_, p2) = frost::keys::dkg::part1(fid2, 2, 2, &mut rng).expect("p1b");
        let mut r1_map = BTreeMap::new();
        r1_map.insert(fid2, p2);
        let (_, r2_pkgs) = frost::keys::dkg::part2(s1, &r1_map).expect("p2");
        let frost_r2 = r2_pkgs.get(&fid2).expect("must have").clone();

        let unknown = ParticipantId::from_bytes([0xFF; 32]);
        let p1 = ParticipantId::from_bytes([1; 32]);
        let package = Round2Package::new(session.session_id().clone(), unknown, p1, frost_r2);

        let result = session.add_round2_package(package);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_round2_package_unregistered_recipient_fails() {
        let mut session = setup_round2_session();
        let mut rng = ChaCha20Rng::seed_from_u64(203);

        let fid1 = frost_id(1);
        let fid2 = frost_id(2);
        let (s1, _) = frost::keys::dkg::part1(fid1, 2, 2, &mut rng).expect("p1a");
        let (_, p2) = frost::keys::dkg::part1(fid2, 2, 2, &mut rng).expect("p1b");
        let mut r1_map = BTreeMap::new();
        r1_map.insert(fid2, p2);
        let (_, r2_pkgs) = frost::keys::dkg::part2(s1, &r1_map).expect("p2");
        let frost_r2 = r2_pkgs.get(&fid2).expect("must have").clone();

        let p0 = ParticipantId::from_bytes([0; 32]);
        let unknown = ParticipantId::from_bytes([0xFF; 32]);
        let package = Round2Package::new(session.session_id().clone(), p0, unknown, frost_r2);

        let result = session.add_round2_package(package);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_round2_package_duplicate_fails() {
        let mut session = setup_round2_session();
        let mut rng = ChaCha20Rng::seed_from_u64(204);
        let session_id = session.session_id().clone();

        let pkg1 = generate_real_round2_package(session_id.clone(), 0, 1, &mut rng);
        let pkg2 = generate_real_round2_package(session_id, 0, 1, &mut rng);

        session.add_round2_package(pkg1).expect("first add");
        let result = session.add_round2_package(pkg2);
        assert!(result.is_err());
    }

    #[test]
    fn test_has_all_round2_packages() {
        let mut session = setup_round2_session();
        let mut rng = ChaCha20Rng::seed_from_u64(205);

        assert!(!session.has_all_round2_packages());
        fill_round2_packages(&mut session, &mut rng);
        assert!(session.has_all_round2_packages());
    }

    #[test]
    fn test_complete_round2() {
        let mut session = setup_round2_session();
        let mut rng = ChaCha20Rng::seed_from_u64(206);

        fill_round2_packages(&mut session, &mut rng);

        let group_pubkey = GroupPublicKey::from_bytes([0x02; 32]).expect("valid pk");
        assert!(session.complete_round2(group_pubkey).is_ok());
        assert!(session.is_complete());
        assert_eq!(session.state().state_name(), "Completed");
    }

    #[test]
    fn test_complete_round2_incomplete_fails() {
        let mut session = setup_round2_session();

        let group_pubkey = GroupPublicKey::from_bytes([0x02; 32]).expect("valid pk");
        let result = session.complete_round2(group_pubkey);
        assert!(result.is_err());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // FAIL TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_fail_from_initialized() {
        let mut session = make_session(3, 2);
        let error = DKGError::InvalidThreshold {
            threshold: 5,
            total: 3,
        };
        session.fail(error);
        assert!(session.is_failed());
    }

    #[test]
    fn test_fail_from_round1() {
        let mut session = make_session(3, 2);
        session.start_round1().expect("start");
        let error = DKGError::InvalidThreshold {
            threshold: 5,
            total: 3,
        };
        session.fail(error);
        assert!(session.is_failed());
    }

    #[test]
    fn test_fail_does_not_overwrite_completed() {
        let mut session = setup_round2_session();
        let mut rng = ChaCha20Rng::seed_from_u64(207);

        fill_round2_packages(&mut session, &mut rng);

        let group_pubkey = GroupPublicKey::from_bytes([0x02; 32]).expect("valid pk");
        session.complete_round2(group_pubkey).expect("complete");
        assert!(session.is_complete());

        let error = DKGError::InvalidThreshold {
            threshold: 5,
            total: 3,
        };
        session.fail(error);
        assert!(session.is_complete());
        assert!(!session.is_failed());
    }

    #[test]
    fn test_fail_does_not_overwrite_failed() {
        let mut session = make_session(3, 2);
        let error1 = DKGError::InvalidThreshold {
            threshold: 5,
            total: 3,
        };
        session.fail(error1);
        assert!(session.is_failed());

        let error2 = DKGError::InsufficientParticipants {
            expected: 10,
            got: 1,
        };
        session.fail(error2);

        match session.state() {
            DKGState::Failed { error } => match error {
                DKGError::InvalidThreshold { threshold: 5, total: 3 } => {}
                _ => panic!("expected original error"),
            },
            _ => panic!("expected Failed state"),
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // CONFIG TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_config_default() {
        let config = DKGSessionConfig::default();
        assert_eq!(config.timeout_secs(), 300);
        assert!(!config.allow_late_packages());
    }

    #[test]
    fn test_config_new() {
        let config = DKGSessionConfig::new(600, true);
        assert_eq!(config.timeout_secs(), 600);
        assert!(config.allow_late_packages());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SEND + SYNC TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_session_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<DKGSession>();
        assert_send_sync::<DKGSessionConfig>();
    }

    // ────────────────────────────────────────────────────────────────────────────
    // FULL LIFECYCLE TEST
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_full_dkg_lifecycle() {
        let mut rng = ChaCha20Rng::seed_from_u64(300);
        let session_id = SessionId::from_bytes([0xAA; 32]);
        let participants = make_participants(3);
        let mut session = DKGSession::new(session_id.clone(), participants, 2).expect("ok");

        assert_eq!(session.state().state_name(), "Initialized");

        // Start Round 1
        session.start_round1().expect("start r1");
        assert_eq!(session.state().state_name(), "Round1Commitment");

        // Add Round 1 packages (real frost)
        let r1_packages = generate_real_round1_packages(3, 2, &mut rng);
        for pkg in r1_packages {
            session.add_round1_package(pkg).expect("add r1");
        }

        // Complete Round 1
        session.complete_round1().expect("complete r1");
        assert_eq!(session.state().state_name(), "Round1Complete");

        // Start Round 2
        session.start_round2().expect("start r2");
        assert_eq!(session.state().state_name(), "Round2Share");

        // Add Round 2 packages (real frost)
        for from in 0..3u8 {
            for to in 0..3u8 {
                if from != to {
                    let pkg = generate_real_round2_package(
                        session_id.clone(), from, to, &mut rng,
                    );
                    session.add_round2_package(pkg).expect("add r2");
                }
            }
        }

        // Complete DKG
        let group_pubkey = GroupPublicKey::from_bytes([0x02; 32]).expect("valid pk");
        session.complete_round2(group_pubkey).expect("complete r2");

        assert!(session.is_complete());
        assert!(!session.is_failed());
        assert_eq!(session.state().state_name(), "Completed");
    }
}