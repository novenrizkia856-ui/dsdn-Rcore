//! EpochDKG — DKG coordination for committee rotation (14A.2B.2.25)
//!
//! Stateful tracking untuk proses Distributed Key Generation (DKG)
//! pada committee epoch baru. HANYA mengelola state dan tracking.
//! TIDAK melakukan kriptografi langsung.

use std::collections::HashMap;

use dsdn_common::coordinator::CoordinatorMember;
use dsdn_proto::{DKGResultProto, DKGRound1PackageProto, DKGRound2PackageProto};
use sha3::{Digest, Sha3_256};

// ════════════════════════════════════════════════════════════════════════════════
// DKG ERROR
// ════════════════════════════════════════════════════════════════════════════════

/// Error type untuk DKG operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DKGError {
    /// State DKG tidak valid untuk operasi ini.
    InvalidState,
    /// Paket DKG duplikat dari participant yang sama.
    DuplicatePackage,
    /// Paket dari member yang tidak dikenal.
    UnknownMember,
    /// Proses DKG melebihi batas waktu.
    Timeout,
    /// Round DKG belum lengkap.
    IncompleteRound,
    /// Paket DKG format tidak valid (field lengths, session_id mismatch, self-send).
    InvalidPackage,
    /// Operasi pada round DKG yang salah.
    WrongRound,
    /// Verifikasi struktural paket gagal.
    VerificationFailed,
    /// Paket tidak cukup untuk finalisasi.
    InsufficientPackages,
}

impl std::fmt::Display for DKGError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidState => write!(f, "invalid DKG state for this operation"),
            Self::DuplicatePackage => write!(f, "duplicate DKG package received"),
            Self::UnknownMember => write!(f, "package from unknown member"),
            Self::Timeout => write!(f, "DKG process timed out"),
            Self::IncompleteRound => write!(f, "DKG round is incomplete"),
            Self::InvalidPackage => write!(f, "invalid DKG package format"),
            Self::WrongRound => write!(f, "wrong DKG round for this operation"),
            Self::VerificationFailed => write!(f, "DKG package verification failed"),
            Self::InsufficientPackages => write!(f, "insufficient DKG packages for finalization"),
        }
    }
}

impl std::error::Error for DKGError {}

// ════════════════════════════════════════════════════════════════════════════════
// EPOCH DKG STATE
// ════════════════════════════════════════════════════════════════════════════════

/// State machine untuk proses DKG.
///
/// Transisi hanya maju (no rollback implisit).
/// `Completed` dan `Failed` adalah terminal states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpochDKGState {
    /// Belum ada paket DKG diterima.
    Pending,
    /// Round 1 sedang berlangsung.
    Round1InProgress {
        /// Jumlah paket yang sudah diterima.
        received: usize,
        /// Jumlah paket yang diperlukan (= member count).
        required: usize,
    },
    /// Round 2 sedang berlangsung.
    Round2InProgress {
        /// Jumlah paket yang sudah diterima.
        received: usize,
        /// Jumlah paket yang diperlukan (= n * (n-1)).
        required: usize,
    },
    /// DKG berhasil diselesaikan. Terminal state.
    Completed {
        /// Hasil DKG final dan immutable.
        result: DKGResultProto,
    },
    /// DKG gagal. Terminal state.
    Failed {
        /// Error penyebab kegagalan.
        error: DKGError,
    },
}

// ════════════════════════════════════════════════════════════════════════════════
// DKG PROGRESS (14A.2B.2.26)
// ════════════════════════════════════════════════════════════════════════════════

/// Snapshot hasil setelah operasi DKG.
///
/// Berisi clone eksplisit dari state saat ini
/// beserta status completion kedua round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DKGProgress {
    /// Clone dari state DKG saat ini.
    pub state: EpochDKGState,
    /// Apakah round 1 sudah lengkap.
    pub round1_complete: bool,
    /// Apakah round 2 sudah lengkap.
    pub round2_complete: bool,
}

// ════════════════════════════════════════════════════════════════════════════════
// EPOCH DKG
// ════════════════════════════════════════════════════════════════════════════════

/// Koordinasi DKG untuk committee epoch baru.
///
/// Mengelola state tracking proses DKG secara deterministik dan stateful.
/// Tidak melakukan kriptografi langsung.
///
/// ## Invariants
///
/// - `session_id` deterministik dari `target_epoch` + `new_members`
/// - `round1_packages.len() <= new_members.len()`
/// - `round2_packages.len() <= new_members.len() * (new_members.len() - 1)`
/// - State transitions hanya maju, `Completed` dan `Failed` terminal
/// - `new_members` disortir secara deterministik
#[derive(Debug)]
pub struct EpochDKG {
    target_epoch: u64,
    new_members: Vec<CoordinatorMember>,
    session_id: [u8; 32],
    round1_packages: HashMap<[u8; 32], DKGRound1PackageProto>,
    round2_packages: HashMap<([u8; 32], [u8; 32]), DKGRound2PackageProto>,
    state: EpochDKGState,
    started_at: u64,
    timeout_at: u64,
}

impl EpochDKG {
    /// Membuat `EpochDKG` baru.
    ///
    /// ## Session ID
    ///
    /// `session_id` dihitung secara deterministik menggunakan SHA3-256:
    /// `SHA3-256(target_epoch ‖ member_count ‖ sorted_member_ids)`
    ///
    /// Members disortir terlebih dahulu untuk memastikan determinism.
    ///
    /// ## Empty Members
    ///
    /// Jika `members` kosong, DKG langsung masuk state `Failed { InvalidState }`.
    ///
    /// ## Timing
    ///
    /// - `started_at = 0`
    /// - `timeout_at = started_at + timeout_blocks`
    pub fn new(
        target_epoch: u64,
        members: Vec<CoordinatorMember>,
        timeout_blocks: u64,
    ) -> Self {
        if members.is_empty() {
            return Self {
                target_epoch,
                new_members: Vec::new(),
                session_id: [0u8; 32],
                round1_packages: HashMap::new(),
                round2_packages: HashMap::new(),
                state: EpochDKGState::Failed {
                    error: DKGError::InvalidState,
                },
                started_at: 0,
                timeout_at: 0,
            };
        }

        let mut sorted_members = members;
        sorted_members.sort();

        let session_id = compute_session_id(target_epoch, &sorted_members);

        let started_at: u64 = 0;
        let timeout_at = started_at.saturating_add(timeout_blocks);

        Self {
            target_epoch,
            new_members: sorted_members,
            session_id,
            round1_packages: HashMap::new(),
            round2_packages: HashMap::new(),
            state: EpochDKGState::Pending,
            started_at,
            timeout_at,
        }
    }

    /// Returns reference to current DKG state.
    pub fn state(&self) -> &EpochDKGState {
        &self.state
    }

    /// Cek apakah DKG sudah selesai (berhasil atau gagal).
    ///
    /// Return `true` jika dan hanya jika state adalah `Completed` atau `Failed`.
    pub fn is_complete(&self) -> bool {
        matches!(
            self.state,
            EpochDKGState::Completed { .. } | EpochDKGState::Failed { .. }
        )
    }

    /// Returns reference to DKG result jika state adalah `Completed`.
    ///
    /// Returns `None` untuk semua state lainnya.
    pub fn get_result(&self) -> Option<&DKGResultProto> {
        match &self.state {
            EpochDKGState::Completed { result } => Some(result),
            _ => None,
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // DKG ROUND PROCESSING (14A.2B.2.26)
    // ════════════════════════════════════════════════════════════════════════════

    /// Tambah paket round 1 dari participant.
    ///
    /// ## Preconditions
    ///
    /// - State harus `Pending` atau `Round1InProgress`
    /// - Package harus valid secara struktural (validate())
    /// - Session ID harus cocok
    /// - Participant harus member yang dikenal
    /// - Tidak boleh duplikat
    ///
    /// ## State Effects
    ///
    /// - `Pending` → `Round1InProgress` pada package pertama
    /// - `Round1InProgress` received counter bertambah
    /// - Package disimpan di `round1_packages`
    pub fn add_round1_package(
        &mut self,
        package: DKGRound1PackageProto,
    ) -> Result<DKGProgress, DKGError> {
        // Check 1: state must be Pending or Round1InProgress
        match &self.state {
            EpochDKGState::Pending | EpochDKGState::Round1InProgress { .. } => {}
            _ => return Err(DKGError::WrongRound),
        }

        // Check 2: structural validation
        if package.validate().is_err() {
            return Err(DKGError::VerificationFailed);
        }

        // Check 3: session_id must match
        if package.session_id.as_slice() != self.session_id.as_slice() {
            return Err(DKGError::InvalidPackage);
        }

        // Check 4: extract participant_id safely
        let participant_id: [u8; 32] = package
            .participant_id
            .as_slice()
            .try_into()
            .map_err(|_| DKGError::InvalidPackage)?;

        // Check 5: participant must be a known member
        if !self.is_known_member(&participant_id) {
            return Err(DKGError::UnknownMember);
        }

        // Check 6: no duplicate
        if self.round1_packages.contains_key(&participant_id) {
            return Err(DKGError::DuplicatePackage);
        }

        // --- All validation passed, mutate state ---
        self.round1_packages.insert(participant_id, package);
        self.state = EpochDKGState::Round1InProgress {
            received: self.round1_packages.len(),
            required: self.new_members.len(),
        };

        Ok(self.make_progress())
    }

    /// Tambah paket round 2 dari participant.
    ///
    /// ## Preconditions
    ///
    /// - State harus `Round1InProgress` (dengan round 1 lengkap) atau `Round2InProgress`
    /// - Package harus valid secara struktural
    /// - Session ID harus cocok
    /// - from dan to harus member yang dikenal
    /// - from != to (self-send dilarang)
    /// - Tidak boleh duplikat
    ///
    /// ## State Effects
    ///
    /// - `Round1InProgress` → `Round2InProgress` pada package pertama
    /// - `Round2InProgress` received counter bertambah
    pub fn add_round2_package(
        &mut self,
        package: DKGRound2PackageProto,
    ) -> Result<DKGProgress, DKGError> {
        // Check 1: state must be Round2InProgress, or Round1InProgress with round1 complete
        match &self.state {
            EpochDKGState::Round2InProgress { .. } => {}
            EpochDKGState::Round1InProgress { .. } if self.check_round1_complete() => {}
            _ => return Err(DKGError::WrongRound),
        }

        // Check 2: structural validation
        if package.validate().is_err() {
            return Err(DKGError::VerificationFailed);
        }

        // Check 3: session_id must match
        if package.session_id.as_slice() != self.session_id.as_slice() {
            return Err(DKGError::InvalidPackage);
        }

        // Check 4: extract from_participant and to_participant safely
        let from_id: [u8; 32] = package
            .from_participant
            .as_slice()
            .try_into()
            .map_err(|_| DKGError::InvalidPackage)?;

        let to_id: [u8; 32] = package
            .to_participant
            .as_slice()
            .try_into()
            .map_err(|_| DKGError::InvalidPackage)?;

        // Check 5: self-send dilarang
        if from_id == to_id {
            return Err(DKGError::InvalidPackage);
        }

        // Check 6: both must be known members
        if !self.is_known_member(&from_id) || !self.is_known_member(&to_id) {
            return Err(DKGError::UnknownMember);
        }

        // Check 7: no duplicate
        let key = (from_id, to_id);
        if self.round2_packages.contains_key(&key) {
            return Err(DKGError::DuplicatePackage);
        }

        // --- All validation passed, mutate state ---
        self.round2_packages.insert(key, package);

        let n = self.new_members.len();
        let required_r2 = n.saturating_mul(n.saturating_sub(1));
        self.state = EpochDKGState::Round2InProgress {
            received: self.round2_packages.len(),
            required: required_r2,
        };

        Ok(self.make_progress())
    }

    /// Cek apakah round 1 sudah lengkap.
    ///
    /// Return `true` jika `round1_packages.len() == new_members.len()`.
    pub fn check_round1_complete(&self) -> bool {
        self.round1_packages.len() == self.new_members.len()
    }

    /// Cek apakah round 2 sudah lengkap.
    ///
    /// Return `true` jika `round2_packages.len() == N * (N - 1)`.
    pub fn check_round2_complete(&self) -> bool {
        let n = self.new_members.len();
        let required = n.saturating_mul(n.saturating_sub(1));
        self.round2_packages.len() == required
    }

    /// Finalisasi DKG dan hasilkan `DKGResultProto`.
    ///
    /// ## Preconditions
    ///
    /// - State bukan terminal
    /// - Round 1 harus lengkap
    /// - Round 2 harus lengkap
    ///
    /// ## State Effects
    ///
    /// - State → `Completed { result }`
    /// - Setelah ini, package tidak lagi diterima
    pub fn finalize(&mut self) -> Result<DKGResultProto, DKGError> {
        // Check 1: must not be terminal
        if self.is_complete() {
            return Err(DKGError::InvalidState);
        }

        // Check 2: round 1 must be complete
        if !self.check_round1_complete() {
            return Err(DKGError::IncompleteRound);
        }

        // Check 3: round 2 must be complete
        if !self.check_round2_complete() {
            return Err(DKGError::InsufficientPackages);
        }

        // Build group_pubkey deterministically from round1 commitments
        let group_pubkey = compute_group_pubkey(&self.session_id, &self.new_members, &self.round1_packages);

        // Build participant pubkeys from sorted members
        let participant_pubkeys: Vec<Vec<u8>> = self
            .new_members
            .iter()
            .map(|m| m.pubkey().as_bytes().to_vec())
            .collect();

        // Compute threshold: majority
        let n = self.new_members.len() as u32;
        let threshold = (n / 2).saturating_add(1);

        let result = DKGResultProto::success(
            self.session_id.to_vec(),
            group_pubkey,
            participant_pubkeys,
            threshold,
        );

        // --- Mutate state ---
        self.state = EpochDKGState::Completed {
            result: result.clone(),
        };

        Ok(result)
    }

    /// Cek dan terapkan timeout.
    ///
    /// Jika `current_height >= timeout_at` dan state belum terminal:
    /// - State → `Failed { Timeout }`
    /// - Return `true`
    ///
    /// Jika tidak, return `false`.
    pub fn check_timeout(&mut self, current_height: u64) -> bool {
        if self.is_complete() {
            return false;
        }
        if current_height >= self.timeout_at {
            self.state = EpochDKGState::Failed {
                error: DKGError::Timeout,
            };
            return true;
        }
        false
    }

    // ════════════════════════════════════════════════════════════════════════════
    // PRIVATE HELPERS
    // ════════════════════════════════════════════════════════════════════════════

    /// Cek apakah participant_id ada di new_members.
    fn is_known_member(&self, participant_id: &[u8; 32]) -> bool {
        self.new_members
            .iter()
            .any(|m| m.id().as_bytes() == participant_id)
    }

    /// Buat snapshot DKGProgress dari state saat ini.
    fn make_progress(&self) -> DKGProgress {
        DKGProgress {
            state: self.state.clone(),
            round1_complete: self.check_round1_complete(),
            round2_complete: self.check_round2_complete(),
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// SESSION ID COMPUTATION
// ════════════════════════════════════════════════════════════════════════════════

/// Compute session_id secara deterministik.
///
/// Formula: `SHA3-256(target_epoch_le ‖ member_count_le ‖ member_id_0 ‖ ... ‖ member_id_n)`
///
/// Members HARUS sudah disortir sebelum pemanggilan fungsi ini.
fn compute_session_id(target_epoch: u64, sorted_members: &[CoordinatorMember]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(target_epoch.to_le_bytes());
    hasher.update((sorted_members.len() as u64).to_le_bytes());
    for member in sorted_members {
        hasher.update(member.id().as_bytes());
    }
    let hash = hasher.finalize();
    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&hash);
    session_id
}

/// Compute group_pubkey secara deterministik dari round1 commitments.
///
/// Formula: `SHA3-256(session_id ‖ commitment_0 ‖ commitment_1 ‖ ... ‖ commitment_n)`
///
/// Commitments diiterasi berdasarkan urutan sorted members untuk determinism.
fn compute_group_pubkey(
    session_id: &[u8; 32],
    sorted_members: &[CoordinatorMember],
    round1_packages: &HashMap<[u8; 32], DKGRound1PackageProto>,
) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(session_id);
    for member in sorted_members {
        if let Some(pkg) = round1_packages.get(member.id().as_bytes()) {
            hasher.update(&pkg.commitment);
        }
    }
    hasher.finalize().to_vec()
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ──────────────────────────────────────────────────────────
    // Test helpers
    // ──────────────────────────────────────────────────────────

    /// Helper: construct CoordinatorMember via serde deserialization.
    ///
    /// Chain crate tidak memiliki akses langsung ke dsdn-tss types,
    /// sehingga construction dilakukan via JSON deserialization.
    fn test_member(id_byte: u8) -> CoordinatorMember {
        let id: Vec<u8> = vec![id_byte; 32];
        let vid: Vec<u8> = vec![id_byte.wrapping_add(1); 32];
        let pk: Vec<u8> = vec![id_byte.wrapping_add(2); 32];

        let json = serde_json::json!({
            "id": id,
            "validator_id": vid,
            "pubkey": pk,
            "stake": 1000u64,
            "joined_at": 0u64
        });

        serde_json::from_value(json).expect("test member construction")
    }

    fn test_members_3() -> Vec<CoordinatorMember> {
        vec![test_member(1), test_member(4), test_member(7)]
    }

    fn test_dkg_result() -> DKGResultProto {
        DKGResultProto {
            session_id: vec![0xAB; 32],
            group_pubkey: vec![0xCD; 32],
            participant_pubkeys: vec![vec![0xEF; 32]],
            threshold: 2,
            success: true,
            error_message: None,
        }
    }

    // ──────────────────────────────────────────────────────────
    // Constructor tests
    // ──────────────────────────────────────────────────────────

    #[test]
    fn test_new_valid_members_state_pending() {
        let dkg = EpochDKG::new(1, test_members_3(), 100);
        assert_eq!(*dkg.state(), EpochDKGState::Pending);
    }

    #[test]
    fn test_new_empty_members_state_failed() {
        let dkg = EpochDKG::new(1, Vec::new(), 100);
        assert_eq!(
            *dkg.state(),
            EpochDKGState::Failed {
                error: DKGError::InvalidState
            }
        );
    }

    #[test]
    fn test_new_empty_members_session_id_zero() {
        let dkg = EpochDKG::new(1, Vec::new(), 100);
        assert_eq!(dkg.session_id, [0u8; 32]);
    }

    #[test]
    fn test_new_session_id_deterministic() {
        let dkg1 = EpochDKG::new(1, test_members_3(), 100);
        let dkg2 = EpochDKG::new(1, test_members_3(), 100);
        assert_eq!(dkg1.session_id, dkg2.session_id);
    }

    #[test]
    fn test_new_session_id_different_epoch() {
        let dkg1 = EpochDKG::new(1, test_members_3(), 100);
        let dkg2 = EpochDKG::new(2, test_members_3(), 100);
        assert_ne!(dkg1.session_id, dkg2.session_id);
    }

    #[test]
    fn test_new_session_id_different_members() {
        let dkg1 = EpochDKG::new(1, vec![test_member(1), test_member(4)], 100);
        let dkg2 = EpochDKG::new(1, vec![test_member(1), test_member(7)], 100);
        assert_ne!(dkg1.session_id, dkg2.session_id);
    }

    #[test]
    fn test_new_session_id_order_independent() {
        let members_a = vec![test_member(1), test_member(4), test_member(7)];
        let members_b = vec![test_member(7), test_member(1), test_member(4)];
        let dkg_a = EpochDKG::new(1, members_a, 100);
        let dkg_b = EpochDKG::new(1, members_b, 100);
        // Same members in different order → same session_id (sorted internally)
        assert_eq!(dkg_a.session_id, dkg_b.session_id);
    }

    #[test]
    fn test_new_session_id_is_32_bytes() {
        let dkg = EpochDKG::new(1, test_members_3(), 100);
        assert_eq!(dkg.session_id.len(), 32);
    }

    #[test]
    fn test_new_session_id_not_zero() {
        let dkg = EpochDKG::new(1, test_members_3(), 100);
        assert_ne!(dkg.session_id, [0u8; 32]);
    }

    #[test]
    fn test_new_started_at_zero() {
        let dkg = EpochDKG::new(1, test_members_3(), 100);
        assert_eq!(dkg.started_at, 0);
    }

    #[test]
    fn test_new_timeout_at() {
        let dkg = EpochDKG::new(1, test_members_3(), 100);
        assert_eq!(dkg.timeout_at, 100);
    }

    #[test]
    fn test_new_timeout_blocks_zero() {
        let dkg = EpochDKG::new(1, test_members_3(), 0);
        assert_eq!(dkg.timeout_at, 0);
    }

    #[test]
    fn test_new_timeout_blocks_max() {
        let dkg = EpochDKG::new(1, test_members_3(), u64::MAX);
        assert_eq!(dkg.timeout_at, u64::MAX);
    }

    #[test]
    fn test_new_round1_packages_empty() {
        let dkg = EpochDKG::new(1, test_members_3(), 100);
        assert!(dkg.round1_packages.is_empty());
    }

    #[test]
    fn test_new_round2_packages_empty() {
        let dkg = EpochDKG::new(1, test_members_3(), 100);
        assert!(dkg.round2_packages.is_empty());
    }

    #[test]
    fn test_new_target_epoch_stored() {
        let dkg = EpochDKG::new(42, test_members_3(), 100);
        assert_eq!(dkg.target_epoch, 42);
    }

    #[test]
    fn test_new_members_stored_sorted() {
        let members = vec![test_member(7), test_member(1), test_member(4)];
        let dkg = EpochDKG::new(1, members, 100);
        // Members should be sorted (CoordinatorMember Ord: stake desc, id asc)
        // All have stake=1000, so sorted by id ascending: 1, 4, 7
        assert_eq!(dkg.new_members.len(), 3);
        assert_eq!(dkg.new_members[0].id().as_bytes(), &[1u8; 32]);
        assert_eq!(dkg.new_members[1].id().as_bytes(), &[4u8; 32]);
        assert_eq!(dkg.new_members[2].id().as_bytes(), &[7u8; 32]);
    }

    #[test]
    fn test_new_single_member() {
        let dkg = EpochDKG::new(1, vec![test_member(1)], 50);
        assert_eq!(*dkg.state(), EpochDKGState::Pending);
        assert_eq!(dkg.new_members.len(), 1);
    }

    // ──────────────────────────────────────────────────────────
    // state() tests
    // ──────────────────────────────────────────────────────────

    #[test]
    fn test_state_returns_pending() {
        let dkg = EpochDKG::new(1, test_members_3(), 100);
        assert_eq!(*dkg.state(), EpochDKGState::Pending);
    }

    #[test]
    fn test_state_returns_failed_for_empty() {
        let dkg = EpochDKG::new(1, Vec::new(), 100);
        match dkg.state() {
            EpochDKGState::Failed { error } => assert_eq!(*error, DKGError::InvalidState),
            other => panic!("expected Failed, got {:?}", other),
        }
    }

    // ──────────────────────────────────────────────────────────
    // is_complete() tests
    // ──────────────────────────────────────────────────────────

    #[test]
    fn test_is_complete_pending_false() {
        let dkg = EpochDKG::new(1, test_members_3(), 100);
        assert!(!dkg.is_complete());
    }

    #[test]
    fn test_is_complete_failed_true() {
        let dkg = EpochDKG::new(1, Vec::new(), 100);
        assert!(dkg.is_complete());
    }

    #[test]
    fn test_is_complete_completed_true() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        dkg.state = EpochDKGState::Completed {
            result: test_dkg_result(),
        };
        assert!(dkg.is_complete());
    }

    #[test]
    fn test_is_complete_round1_false() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        dkg.state = EpochDKGState::Round1InProgress {
            received: 1,
            required: 3,
        };
        assert!(!dkg.is_complete());
    }

    #[test]
    fn test_is_complete_round2_false() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        dkg.state = EpochDKGState::Round2InProgress {
            received: 2,
            required: 6,
        };
        assert!(!dkg.is_complete());
    }

    // ──────────────────────────────────────────────────────────
    // get_result() tests
    // ──────────────────────────────────────────────────────────

    #[test]
    fn test_get_result_pending_none() {
        let dkg = EpochDKG::new(1, test_members_3(), 100);
        assert!(dkg.get_result().is_none());
    }

    #[test]
    fn test_get_result_failed_none() {
        let dkg = EpochDKG::new(1, Vec::new(), 100);
        assert!(dkg.get_result().is_none());
    }

    #[test]
    fn test_get_result_completed_some() {
        let expected_result = test_dkg_result();
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        dkg.state = EpochDKGState::Completed {
            result: expected_result.clone(),
        };
        let result = dkg.get_result();
        assert!(result.is_some());
        assert_eq!(*result.unwrap(), expected_result);
    }

    #[test]
    fn test_get_result_round1_none() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        dkg.state = EpochDKGState::Round1InProgress {
            received: 1,
            required: 3,
        };
        assert!(dkg.get_result().is_none());
    }

    #[test]
    fn test_get_result_round2_none() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        dkg.state = EpochDKGState::Round2InProgress {
            received: 2,
            required: 6,
        };
        assert!(dkg.get_result().is_none());
    }

    // ──────────────────────────────────────────────────────────
    // DKGError tests
    // ──────────────────────────────────────────────────────────

    #[test]
    fn test_dkg_error_display() {
        assert!(!format!("{}", DKGError::InvalidState).is_empty());
        assert!(!format!("{}", DKGError::DuplicatePackage).is_empty());
        assert!(!format!("{}", DKGError::UnknownMember).is_empty());
        assert!(!format!("{}", DKGError::Timeout).is_empty());
        assert!(!format!("{}", DKGError::IncompleteRound).is_empty());
    }

    #[test]
    fn test_dkg_error_debug() {
        let debug = format!("{:?}", DKGError::InvalidState);
        assert!(debug.contains("InvalidState"));
    }

    #[test]
    fn test_dkg_error_clone_eq() {
        let e1 = DKGError::Timeout;
        let e2 = e1.clone();
        assert_eq!(e1, e2);
    }

    #[test]
    fn test_dkg_error_is_std_error() {
        let e: &dyn std::error::Error = &DKGError::IncompleteRound;
        assert!(!e.to_string().is_empty());
    }

    #[test]
    fn test_dkg_error_variants_distinct() {
        assert_ne!(DKGError::InvalidState, DKGError::DuplicatePackage);
        assert_ne!(DKGError::DuplicatePackage, DKGError::UnknownMember);
        assert_ne!(DKGError::UnknownMember, DKGError::Timeout);
        assert_ne!(DKGError::Timeout, DKGError::IncompleteRound);
        assert_ne!(DKGError::IncompleteRound, DKGError::InvalidState);
    }

    // ──────────────────────────────────────────────────────────
    // EpochDKGState tests
    // ──────────────────────────────────────────────────────────

    #[test]
    fn test_epoch_dkg_state_debug() {
        let state = EpochDKGState::Pending;
        let debug = format!("{:?}", state);
        assert!(debug.contains("Pending"));
    }

    #[test]
    fn test_epoch_dkg_state_clone() {
        let state = EpochDKGState::Round1InProgress {
            received: 2,
            required: 3,
        };
        let cloned = state.clone();
        assert_eq!(state, cloned);
    }

    #[test]
    fn test_epoch_dkg_state_eq() {
        let s1 = EpochDKGState::Failed {
            error: DKGError::Timeout,
        };
        let s2 = EpochDKGState::Failed {
            error: DKGError::Timeout,
        };
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_epoch_dkg_state_ne() {
        let s1 = EpochDKGState::Pending;
        let s2 = EpochDKGState::Failed {
            error: DKGError::InvalidState,
        };
        assert_ne!(s1, s2);
    }

    // ──────────────────────────────────────────────────────────
    // EpochDKG Debug test
    // ──────────────────────────────────────────────────────────

    #[test]
    fn test_epoch_dkg_debug() {
        let dkg = EpochDKG::new(1, test_members_3(), 100);
        let debug = format!("{:?}", dkg);
        assert!(debug.contains("EpochDKG"));
    }

    // ──────────────────────────────────────────────────────────
    // compute_session_id tests
    // ──────────────────────────────────────────────────────────

    #[test]
    fn test_compute_session_id_deterministic() {
        let members = test_members_3();
        let mut sorted = members.clone();
        sorted.sort();
        let id1 = compute_session_id(1, &sorted);
        let id2 = compute_session_id(1, &sorted);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_compute_session_id_32_bytes() {
        let members = test_members_3();
        let mut sorted = members.clone();
        sorted.sort();
        let id = compute_session_id(1, &sorted);
        assert_eq!(id.len(), 32);
    }

    #[test]
    fn test_compute_session_id_different_epoch_different_id() {
        let members = test_members_3();
        let mut sorted = members.clone();
        sorted.sort();
        let id1 = compute_session_id(1, &sorted);
        let id2 = compute_session_id(2, &sorted);
        assert_ne!(id1, id2);
    }

    // ──────────────────────────────────────────────────────────
    // Test helpers (14A.2B.2.26)
    // ──────────────────────────────────────────────────────────

    /// Build a valid DKGRound1PackageProto for a given DKG instance and member.
    fn make_round1_package(dkg: &EpochDKG, id_byte: u8) -> DKGRound1PackageProto {
        DKGRound1PackageProto {
            session_id: dkg.session_id.to_vec(),
            participant_id: vec![id_byte; 32],
            commitment: vec![id_byte.wrapping_add(10); 32],
            proof: vec![id_byte.wrapping_add(20); 64],
        }
    }

    /// Build a valid DKGRound2PackageProto for a given DKG instance.
    fn make_round2_package(
        dkg: &EpochDKG,
        from_byte: u8,
        to_byte: u8,
    ) -> DKGRound2PackageProto {
        DKGRound2PackageProto {
            session_id: dkg.session_id.to_vec(),
            from_participant: vec![from_byte; 32],
            to_participant: vec![to_byte; 32],
            encrypted_share: vec![0xAA; 16], // non-empty opaque
        }
    }

    /// Populate all round1 packages for 3-member DKG.
    fn fill_round1(dkg: &mut EpochDKG) {
        dkg.add_round1_package(make_round1_package(dkg, 1)).ok();
        dkg.add_round1_package(make_round1_package(dkg, 4)).ok();
        dkg.add_round1_package(make_round1_package(dkg, 7)).ok();
    }

    /// Populate all round2 packages for 3-member DKG (3*2=6 packages).
    fn fill_round2(dkg: &mut EpochDKG) {
        // All ordered pairs: (1,4), (1,7), (4,1), (4,7), (7,1), (7,4)
        dkg.add_round2_package(make_round2_package(dkg, 1, 4)).ok();
        dkg.add_round2_package(make_round2_package(dkg, 1, 7)).ok();
        dkg.add_round2_package(make_round2_package(dkg, 4, 1)).ok();
        dkg.add_round2_package(make_round2_package(dkg, 4, 7)).ok();
        dkg.add_round2_package(make_round2_package(dkg, 7, 1)).ok();
        dkg.add_round2_package(make_round2_package(dkg, 7, 4)).ok();
    }

    // ──────────────────────────────────────────────────────────
    // add_round1_package tests (14A.2B.2.26)
    // ──────────────────────────────────────────────────────────

    #[test]
    fn test_add_round1_success_from_pending() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        let pkg = make_round1_package(&dkg, 1);
        let result = dkg.add_round1_package(pkg);
        assert!(result.is_ok());
    }

    #[test]
    fn test_add_round1_state_transitions_to_round1() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        let pkg = make_round1_package(&dkg, 1);
        let progress = dkg.add_round1_package(pkg).unwrap();
        assert_eq!(
            progress.state,
            EpochDKGState::Round1InProgress {
                received: 1,
                required: 3
            }
        );
    }

    #[test]
    fn test_add_round1_second_package() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        dkg.add_round1_package(make_round1_package(&dkg, 1)).unwrap();
        let progress = dkg.add_round1_package(make_round1_package(&dkg, 4)).unwrap();
        assert_eq!(
            progress.state,
            EpochDKGState::Round1InProgress {
                received: 2,
                required: 3
            }
        );
    }

    #[test]
    fn test_add_round1_complete_marks_progress() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        dkg.add_round1_package(make_round1_package(&dkg, 1)).unwrap();
        dkg.add_round1_package(make_round1_package(&dkg, 4)).unwrap();
        let progress = dkg.add_round1_package(make_round1_package(&dkg, 7)).unwrap();
        assert!(progress.round1_complete);
        assert!(!progress.round2_complete); // n=3, need 6 r2 packages
    }

    #[test]
    fn test_add_round1_duplicate_rejected() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        dkg.add_round1_package(make_round1_package(&dkg, 1)).unwrap();
        let result = dkg.add_round1_package(make_round1_package(&dkg, 1));
        assert_eq!(result, Err(DKGError::DuplicatePackage));
    }

    #[test]
    fn test_add_round1_unknown_member() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        // id_byte=99 is not a known member
        let pkg = make_round1_package(&dkg, 99);
        let result = dkg.add_round1_package(pkg);
        assert_eq!(result, Err(DKGError::UnknownMember));
    }

    #[test]
    fn test_add_round1_wrong_session_id() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        let mut pkg = make_round1_package(&dkg, 1);
        pkg.session_id = vec![0xFF; 32]; // wrong session
        let result = dkg.add_round1_package(pkg);
        assert_eq!(result, Err(DKGError::InvalidPackage));
    }

    #[test]
    fn test_add_round1_invalid_package_format() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        let pkg = DKGRound1PackageProto {
            session_id: vec![0; 10], // wrong length
            participant_id: vec![1; 32],
            commitment: vec![2; 32],
            proof: vec![3; 64],
        };
        let result = dkg.add_round1_package(pkg);
        assert_eq!(result, Err(DKGError::VerificationFailed));
    }

    #[test]
    fn test_add_round1_wrong_round_completed() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        dkg.state = EpochDKGState::Completed {
            result: test_dkg_result(),
        };
        let pkg = make_round1_package(&dkg, 1);
        assert_eq!(dkg.add_round1_package(pkg), Err(DKGError::WrongRound));
    }

    #[test]
    fn test_add_round1_wrong_round_failed() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        dkg.state = EpochDKGState::Failed {
            error: DKGError::Timeout,
        };
        let pkg = make_round1_package(&dkg, 1);
        assert_eq!(dkg.add_round1_package(pkg), Err(DKGError::WrongRound));
    }

    #[test]
    fn test_add_round1_wrong_round_round2() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        dkg.state = EpochDKGState::Round2InProgress {
            received: 0,
            required: 6,
        };
        let pkg = make_round1_package(&dkg, 1);
        assert_eq!(dkg.add_round1_package(pkg), Err(DKGError::WrongRound));
    }

    #[test]
    fn test_add_round1_state_untouched_on_error() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        // Unknown member
        let _ = dkg.add_round1_package(make_round1_package(&dkg, 99));
        assert_eq!(*dkg.state(), EpochDKGState::Pending);
        assert!(dkg.round1_packages.is_empty());
    }

    // ──────────────────────────────────────────────────────────
    // add_round2_package tests (14A.2B.2.26)
    // ──────────────────────────────────────────────────────────

    #[test]
    fn test_add_round2_success_from_round1_complete() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        fill_round1(&mut dkg);
        let pkg = make_round2_package(&dkg, 1, 4);
        let result = dkg.add_round2_package(pkg);
        assert!(result.is_ok());
    }

    #[test]
    fn test_add_round2_transitions_to_round2() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        fill_round1(&mut dkg);
        let pkg = make_round2_package(&dkg, 1, 4);
        let progress = dkg.add_round2_package(pkg).unwrap();
        assert_eq!(
            progress.state,
            EpochDKGState::Round2InProgress {
                received: 1,
                required: 6
            }
        );
    }

    #[test]
    fn test_add_round2_multiple_packages() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        fill_round1(&mut dkg);
        dkg.add_round2_package(make_round2_package(&dkg, 1, 4)).unwrap();
        let progress = dkg.add_round2_package(make_round2_package(&dkg, 1, 7)).unwrap();
        assert_eq!(
            progress.state,
            EpochDKGState::Round2InProgress {
                received: 2,
                required: 6
            }
        );
    }

    #[test]
    fn test_add_round2_complete_marks_progress() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        fill_round1(&mut dkg);
        fill_round2(&mut dkg);
        assert!(dkg.check_round2_complete());
    }

    #[test]
    fn test_add_round2_wrong_round_pending() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        let pkg = make_round2_package(&dkg, 1, 4);
        assert_eq!(dkg.add_round2_package(pkg), Err(DKGError::WrongRound));
    }

    #[test]
    fn test_add_round2_wrong_round_round1_incomplete() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        dkg.add_round1_package(make_round1_package(&dkg, 1)).unwrap();
        // Round1 not complete (1 of 3)
        let pkg = make_round2_package(&dkg, 1, 4);
        assert_eq!(dkg.add_round2_package(pkg), Err(DKGError::WrongRound));
    }

    #[test]
    fn test_add_round2_wrong_round_completed() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        dkg.state = EpochDKGState::Completed {
            result: test_dkg_result(),
        };
        let pkg = make_round2_package(&dkg, 1, 4);
        assert_eq!(dkg.add_round2_package(pkg), Err(DKGError::WrongRound));
    }

    #[test]
    fn test_add_round2_duplicate_rejected() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        fill_round1(&mut dkg);
        dkg.add_round2_package(make_round2_package(&dkg, 1, 4)).unwrap();
        let result = dkg.add_round2_package(make_round2_package(&dkg, 1, 4));
        assert_eq!(result, Err(DKGError::DuplicatePackage));
    }

    #[test]
    fn test_add_round2_unknown_from() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        fill_round1(&mut dkg);
        let pkg = make_round2_package(&dkg, 99, 4); // from=99 unknown
        assert_eq!(dkg.add_round2_package(pkg), Err(DKGError::UnknownMember));
    }

    #[test]
    fn test_add_round2_unknown_to() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        fill_round1(&mut dkg);
        let pkg = make_round2_package(&dkg, 1, 99); // to=99 unknown
        assert_eq!(dkg.add_round2_package(pkg), Err(DKGError::UnknownMember));
    }

    #[test]
    fn test_add_round2_self_send_rejected() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        fill_round1(&mut dkg);
        let pkg = make_round2_package(&dkg, 1, 1); // from == to
        assert_eq!(dkg.add_round2_package(pkg), Err(DKGError::InvalidPackage));
    }

    #[test]
    fn test_add_round2_wrong_session_id() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        fill_round1(&mut dkg);
        let mut pkg = make_round2_package(&dkg, 1, 4);
        pkg.session_id = vec![0xFF; 32];
        assert_eq!(dkg.add_round2_package(pkg), Err(DKGError::InvalidPackage));
    }

    #[test]
    fn test_add_round2_invalid_format() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        fill_round1(&mut dkg);
        let pkg = DKGRound2PackageProto {
            session_id: vec![0; 10], // wrong length
            from_participant: vec![1; 32],
            to_participant: vec![4; 32],
            encrypted_share: vec![0xAA; 16],
        };
        assert_eq!(dkg.add_round2_package(pkg), Err(DKGError::VerificationFailed));
    }

    #[test]
    fn test_add_round2_state_untouched_on_error() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        fill_round1(&mut dkg);
        // Self-send → error
        let _ = dkg.add_round2_package(make_round2_package(&dkg, 1, 1));
        // State should still be Round1InProgress (no transition to Round2)
        assert!(matches!(*dkg.state(), EpochDKGState::Round1InProgress { .. }));
        assert!(dkg.round2_packages.is_empty());
    }

    // ──────────────────────────────────────────────────────────
    // check_round1_complete tests (14A.2B.2.26)
    // ──────────────────────────────────────────────────────────

    #[test]
    fn test_check_round1_complete_empty() {
        let dkg = EpochDKG::new(1, test_members_3(), 100);
        assert!(!dkg.check_round1_complete());
    }

    #[test]
    fn test_check_round1_complete_partial() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        dkg.add_round1_package(make_round1_package(&dkg, 1)).unwrap();
        assert!(!dkg.check_round1_complete());
    }

    #[test]
    fn test_check_round1_complete_all() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        fill_round1(&mut dkg);
        assert!(dkg.check_round1_complete());
    }

    // ──────────────────────────────────────────────────────────
    // check_round2_complete tests (14A.2B.2.26)
    // ──────────────────────────────────────────────────────────

    #[test]
    fn test_check_round2_complete_empty() {
        let dkg = EpochDKG::new(1, test_members_3(), 100);
        assert!(!dkg.check_round2_complete());
    }

    #[test]
    fn test_check_round2_complete_partial() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        fill_round1(&mut dkg);
        dkg.add_round2_package(make_round2_package(&dkg, 1, 4)).unwrap();
        assert!(!dkg.check_round2_complete());
    }

    #[test]
    fn test_check_round2_complete_all() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        fill_round1(&mut dkg);
        fill_round2(&mut dkg);
        assert!(dkg.check_round2_complete());
    }

    #[test]
    fn test_check_round2_complete_single_member() {
        let dkg = EpochDKG::new(1, vec![test_member(1)], 100);
        // n=1 → required = 1*0 = 0 → trivially complete
        assert!(dkg.check_round2_complete());
    }

    // ──────────────────────────────────────────────────────────
    // finalize tests (14A.2B.2.26)
    // ──────────────────────────────────────────────────────────

    #[test]
    fn test_finalize_success() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        fill_round1(&mut dkg);
        fill_round2(&mut dkg);
        let result = dkg.finalize();
        assert!(result.is_ok());
    }

    #[test]
    fn test_finalize_state_completed() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        fill_round1(&mut dkg);
        fill_round2(&mut dkg);
        dkg.finalize().unwrap();
        assert!(matches!(*dkg.state(), EpochDKGState::Completed { .. }));
    }

    #[test]
    fn test_finalize_result_valid_session_id() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        let expected_sid = dkg.session_id;
        fill_round1(&mut dkg);
        fill_round2(&mut dkg);
        let result = dkg.finalize().unwrap();
        assert_eq!(result.session_id.as_slice(), expected_sid.as_slice());
    }

    #[test]
    fn test_finalize_result_valid_fields() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        fill_round1(&mut dkg);
        fill_round2(&mut dkg);
        let result = dkg.finalize().unwrap();
        assert!(result.success);
        assert!(result.error_message.is_none());
        assert_eq!(result.group_pubkey.len(), 32);
        assert_eq!(result.participant_pubkeys.len(), 3);
        assert_eq!(result.threshold, 2); // (3/2) + 1 = 2
    }

    #[test]
    fn test_finalize_result_participant_pubkeys() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        fill_round1(&mut dkg);
        fill_round2(&mut dkg);
        let result = dkg.finalize().unwrap();
        // Each pubkey should be 32 bytes
        for pk in &result.participant_pubkeys {
            assert_eq!(pk.len(), 32);
        }
    }

    #[test]
    fn test_finalize_err_incomplete_round1() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        dkg.add_round1_package(make_round1_package(&dkg, 1)).unwrap();
        // Only 1 of 3 round1 packages
        assert_eq!(dkg.finalize(), Err(DKGError::IncompleteRound));
    }

    #[test]
    fn test_finalize_err_incomplete_round2() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        fill_round1(&mut dkg);
        dkg.add_round2_package(make_round2_package(&dkg, 1, 4)).unwrap();
        // Only 1 of 6 round2 packages
        assert_eq!(dkg.finalize(), Err(DKGError::InsufficientPackages));
    }

    #[test]
    fn test_finalize_err_already_completed() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        fill_round1(&mut dkg);
        fill_round2(&mut dkg);
        dkg.finalize().unwrap();
        assert_eq!(dkg.finalize(), Err(DKGError::InvalidState));
    }

    #[test]
    fn test_finalize_err_failed_state() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        dkg.state = EpochDKGState::Failed {
            error: DKGError::Timeout,
        };
        assert_eq!(dkg.finalize(), Err(DKGError::InvalidState));
    }

    #[test]
    fn test_finalize_no_packages_added() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        // Pending state, no packages at all
        assert_eq!(dkg.finalize(), Err(DKGError::IncompleteRound));
    }

    #[test]
    fn test_finalize_single_member() {
        let mut dkg = EpochDKG::new(1, vec![test_member(1)], 100);
        // Add round1 for single member
        dkg.add_round1_package(make_round1_package(&dkg, 1)).unwrap();
        // n=1: round2 requires 0 packages → trivially complete
        let result = dkg.finalize();
        assert!(result.is_ok());
        let r = result.unwrap();
        assert!(r.success);
        assert_eq!(r.threshold, 1); // (1/2) + 1 = 1
        assert_eq!(r.participant_pubkeys.len(), 1);
    }

    #[test]
    fn test_finalize_deterministic() {
        let mut dkg1 = EpochDKG::new(1, test_members_3(), 100);
        fill_round1(&mut dkg1);
        fill_round2(&mut dkg1);
        let r1 = dkg1.finalize().unwrap();

        let mut dkg2 = EpochDKG::new(1, test_members_3(), 100);
        fill_round1(&mut dkg2);
        fill_round2(&mut dkg2);
        let r2 = dkg2.finalize().unwrap();

        assert_eq!(r1, r2);
    }

    #[test]
    fn test_finalize_get_result_matches() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        fill_round1(&mut dkg);
        fill_round2(&mut dkg);
        let returned = dkg.finalize().unwrap();
        let stored = dkg.get_result().unwrap();
        assert_eq!(returned, *stored);
    }

    #[test]
    fn test_finalize_rejects_packages_after() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        fill_round1(&mut dkg);
        fill_round2(&mut dkg);
        dkg.finalize().unwrap();
        // After Completed, round1 should be rejected
        let pkg = make_round1_package(&dkg, 1);
        assert_eq!(dkg.add_round1_package(pkg), Err(DKGError::WrongRound));
    }

    // ──────────────────────────────────────────────────────────
    // check_timeout tests (14A.2B.2.26)
    // ──────────────────────────────────────────────────────────

    #[test]
    fn test_check_timeout_before_timeout() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        assert!(!dkg.check_timeout(50));
        assert_eq!(*dkg.state(), EpochDKGState::Pending);
    }

    #[test]
    fn test_check_timeout_at_timeout() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        assert!(dkg.check_timeout(100));
        assert_eq!(
            *dkg.state(),
            EpochDKGState::Failed {
                error: DKGError::Timeout
            }
        );
    }

    #[test]
    fn test_check_timeout_after_timeout() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        assert!(dkg.check_timeout(200));
        assert_eq!(
            *dkg.state(),
            EpochDKGState::Failed {
                error: DKGError::Timeout
            }
        );
    }

    #[test]
    fn test_check_timeout_already_completed() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        dkg.state = EpochDKGState::Completed {
            result: test_dkg_result(),
        };
        // Should not override terminal state
        assert!(!dkg.check_timeout(200));
        assert!(matches!(*dkg.state(), EpochDKGState::Completed { .. }));
    }

    #[test]
    fn test_check_timeout_already_failed() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        dkg.state = EpochDKGState::Failed {
            error: DKGError::InvalidState,
        };
        assert!(!dkg.check_timeout(200));
        // Should remain Failed with original error
        assert_eq!(
            *dkg.state(),
            EpochDKGState::Failed {
                error: DKGError::InvalidState
            }
        );
    }

    #[test]
    fn test_check_timeout_during_round1() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        dkg.add_round1_package(make_round1_package(&dkg, 1)).unwrap();
        assert!(dkg.check_timeout(100));
        assert_eq!(
            *dkg.state(),
            EpochDKGState::Failed {
                error: DKGError::Timeout
            }
        );
    }

    #[test]
    fn test_check_timeout_during_round2() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        fill_round1(&mut dkg);
        dkg.add_round2_package(make_round2_package(&dkg, 1, 4)).unwrap();
        assert!(dkg.check_timeout(100));
        assert_eq!(
            *dkg.state(),
            EpochDKGState::Failed {
                error: DKGError::Timeout
            }
        );
    }

    #[test]
    fn test_check_timeout_rejects_packages_after() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        dkg.check_timeout(100);
        let pkg = make_round1_package(&dkg, 1);
        assert_eq!(dkg.add_round1_package(pkg), Err(DKGError::WrongRound));
    }

    // ──────────────────────────────────────────────────────────
    // DKGProgress tests (14A.2B.2.26)
    // ──────────────────────────────────────────────────────────

    #[test]
    fn test_progress_initial() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        let progress = dkg.add_round1_package(make_round1_package(&dkg, 1)).unwrap();
        assert!(!progress.round1_complete);
        assert!(!progress.round2_complete);
    }

    #[test]
    fn test_progress_round1_complete() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);
        fill_round1(&mut dkg);
        // State is Round1InProgress{3,3}
        let progress = dkg.add_round2_package(make_round2_package(&dkg, 1, 4)).unwrap();
        assert!(progress.round1_complete);
        assert!(!progress.round2_complete);
    }

    #[test]
    fn test_progress_debug_clone_eq() {
        let progress = DKGProgress {
            state: EpochDKGState::Pending,
            round1_complete: false,
            round2_complete: false,
        };
        let cloned = progress.clone();
        assert_eq!(progress, cloned);
        let debug = format!("{:?}", progress);
        assert!(debug.contains("DKGProgress"));
    }

    // ──────────────────────────────────────────────────────────
    // Full lifecycle test (14A.2B.2.26)
    // ──────────────────────────────────────────────────────────

    #[test]
    fn test_full_dkg_lifecycle() {
        let mut dkg = EpochDKG::new(1, test_members_3(), 100);

        // Phase 1: Pending → Round1InProgress
        assert_eq!(*dkg.state(), EpochDKGState::Pending);
        assert!(!dkg.check_round1_complete());

        dkg.add_round1_package(make_round1_package(&dkg, 1)).unwrap();
        dkg.add_round1_package(make_round1_package(&dkg, 4)).unwrap();
        dkg.add_round1_package(make_round1_package(&dkg, 7)).unwrap();
        assert!(dkg.check_round1_complete());

        // Phase 2: Round1InProgress → Round2InProgress
        dkg.add_round2_package(make_round2_package(&dkg, 1, 4)).unwrap();
        dkg.add_round2_package(make_round2_package(&dkg, 1, 7)).unwrap();
        dkg.add_round2_package(make_round2_package(&dkg, 4, 1)).unwrap();
        dkg.add_round2_package(make_round2_package(&dkg, 4, 7)).unwrap();
        dkg.add_round2_package(make_round2_package(&dkg, 7, 1)).unwrap();
        dkg.add_round2_package(make_round2_package(&dkg, 7, 4)).unwrap();
        assert!(dkg.check_round2_complete());

        // Phase 3: Round2InProgress → Completed
        let result = dkg.finalize().unwrap();
        assert!(result.success);
        assert!(dkg.is_complete());
        assert!(dkg.get_result().is_some());

        // Phase 4: Terminal — no more operations
        assert!(!dkg.check_timeout(200));
        assert_eq!(
            dkg.add_round1_package(make_round1_package(&dkg, 1)),
            Err(DKGError::WrongRound)
        );
    }

    // ──────────────────────────────────────────────────────────
    // Extended DKGError tests (14A.2B.2.26)
    // ──────────────────────────────────────────────────────────

    #[test]
    fn test_dkg_error_new_variants_display() {
        assert!(!format!("{}", DKGError::InvalidPackage).is_empty());
        assert!(!format!("{}", DKGError::WrongRound).is_empty());
        assert!(!format!("{}", DKGError::VerificationFailed).is_empty());
        assert!(!format!("{}", DKGError::InsufficientPackages).is_empty());
    }

    #[test]
    fn test_dkg_error_new_variants_distinct() {
        assert_ne!(DKGError::InvalidPackage, DKGError::WrongRound);
        assert_ne!(DKGError::WrongRound, DKGError::VerificationFailed);
        assert_ne!(DKGError::VerificationFailed, DKGError::InsufficientPackages);
        assert_ne!(DKGError::InsufficientPackages, DKGError::InvalidPackage);
    }

    #[test]
    fn test_dkg_error_new_variants_std_error() {
        let e1: &dyn std::error::Error = &DKGError::InvalidPackage;
        let e2: &dyn std::error::Error = &DKGError::WrongRound;
        let e3: &dyn std::error::Error = &DKGError::VerificationFailed;
        let e4: &dyn std::error::Error = &DKGError::InsufficientPackages;
        assert!(!e1.to_string().is_empty());
        assert!(!e2.to_string().is_empty());
        assert!(!e3.to_string().is_empty());
        assert!(!e4.to_string().is_empty());
    }
}