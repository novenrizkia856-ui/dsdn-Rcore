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
}

impl std::fmt::Display for DKGError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidState => write!(f, "invalid DKG state for this operation"),
            Self::DuplicatePackage => write!(f, "duplicate DKG package received"),
            Self::UnknownMember => write!(f, "package from unknown member"),
            Self::Timeout => write!(f, "DKG process timed out"),
            Self::IncompleteRound => write!(f, "DKG round is incomplete"),
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
}