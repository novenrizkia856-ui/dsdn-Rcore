//! Coordinator Selection Base Types
//!
//! Tahap 14A.2B.2.1 — Base types untuk sistem coordinator selection.
//!
//! Module ini HANYA mendefinisikan type dasar.
//! TIDAK ada logic seleksi.
//! TIDAK ada algoritma.
//!
//! # Types
//!
//! - `ValidatorCandidate` - Validator yang eligible untuk selection
//! - `SelectionWeight` - Weight holder untuk weighted selection
//! - `CoordinatorMember` - Member dalam coordinator committee
//! - `CoordinatorCommittee` - Committee dengan threshold requirement
//! - `SelectionConfig` - Konfigurasi selection parameters
//!
//! # Invariants
//!
//! - `CoordinatorCommittee`: threshold <= members.len()

use serde::{Deserialize, Serialize};

// ════════════════════════════════════════════════════════════════════════════════
// ValidatorCandidate
// ════════════════════════════════════════════════════════════════════════════════

/// Validator candidate untuk coordinator selection.
///
/// Merepresentasikan validator yang eligible untuk dipilih
/// sebagai coordinator committee member.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorCandidate {
    /// Unique validator identifier (32 bytes)
    pub id: [u8; 32],

    /// Validator public key untuk signature verification (32 bytes)
    pub pubkey: [u8; 32],

    /// Staked amount dalam smallest unit
    pub stake: u64,

    /// Geographic/logical zone identifier
    pub zone: String,
}

// ════════════════════════════════════════════════════════════════════════════════
// SelectionWeight
// ════════════════════════════════════════════════════════════════════════════════

/// Weight data untuk weighted random selection.
///
/// Digunakan dalam algoritma selection untuk menghitung
/// probabilitas terpilih berdasarkan stake.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SelectionWeight {
    /// Validator identifier yang di-weight
    pub validator_id: [u8; 32],

    /// Individual weight (biasanya = stake)
    pub weight: u64,

    /// Cumulative weight sampai validator ini (inclusive)
    pub cumulative: u64,
}

// ════════════════════════════════════════════════════════════════════════════════
// CoordinatorMember
// ════════════════════════════════════════════════════════════════════════════════

/// Member dalam coordinator committee.
///
/// Merepresentasikan validator yang sudah terpilih
/// sebagai bagian dari coordinator committee.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoordinatorMember {
    /// Unique member identifier dalam committee (32 bytes)
    pub id: [u8; 32],

    /// Validator identifier dari mana member berasal (32 bytes)
    pub validator_id: [u8; 32],

    /// Public key untuk threshold signing (32 bytes)
    pub pubkey: [u8; 32],

    /// Stake yang di-commit oleh member
    pub stake: u64,
}

// ════════════════════════════════════════════════════════════════════════════════
// CoordinatorCommittee
// ════════════════════════════════════════════════════════════════════════════════

/// Coordinator committee untuk epoch tertentu.
///
/// # Invariant
///
/// `threshold <= members.len()` HARUS selalu terpenuhi.
/// Invariant ini dijaga oleh constructor `new()`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoordinatorCommittee {
    /// Committee members
    pub members: Vec<CoordinatorMember>,

    /// Minimum signatures required untuk threshold signing
    pub threshold: u8,

    /// Epoch number dimana committee ini aktif
    pub epoch: u64,

    /// Aggregated group public key untuk committee (32 bytes)
    pub group_pubkey: [u8; 32],
}

/// Error type untuk CoordinatorCommittee construction
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitteeInvariantError {
    /// Threshold yang diminta
    pub threshold: u8,

    /// Jumlah members yang tersedia
    pub members_count: usize,
}

impl std::fmt::Display for CommitteeInvariantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "committee invariant violated: threshold ({}) > members.len() ({})",
            self.threshold, self.members_count
        )
    }
}

impl std::error::Error for CommitteeInvariantError {}

impl CoordinatorCommittee {
    /// Create new CoordinatorCommittee dengan invariant check.
    ///
    /// # Errors
    ///
    /// Returns `CommitteeInvariantError` jika `threshold > members.len()`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let committee = CoordinatorCommittee::new(
    ///     members,
    ///     3,  // threshold
    ///     1,  // epoch
    ///     group_pubkey,
    /// )?;
    /// ```
    pub fn new(
        members: Vec<CoordinatorMember>,
        threshold: u8,
        epoch: u64,
        group_pubkey: [u8; 32],
    ) -> Result<Self, CommitteeInvariantError> {
        // Invariant check: threshold <= members.len()
        if threshold as usize > members.len() {
            return Err(CommitteeInvariantError {
                threshold,
                members_count: members.len(),
            });
        }

        Ok(Self {
            members,
            threshold,
            epoch,
            group_pubkey,
        })
    }

    /// Create CoordinatorCommittee tanpa invariant check.
    ///
    /// # Safety
    ///
    /// Caller HARUS menjamin bahwa `threshold <= members.len()`.
    /// Gunakan method ini HANYA untuk deserialization dari trusted source.
    ///
    /// # Panics
    ///
    /// Method ini TIDAK panic. Invariant violation akan menyebabkan
    /// undefined behavior di signing operations.
    pub fn new_unchecked(
        members: Vec<CoordinatorMember>,
        threshold: u8,
        epoch: u64,
        group_pubkey: [u8; 32],
    ) -> Self {
        Self {
            members,
            threshold,
            epoch,
            group_pubkey,
        }
    }

    /// Check apakah invariant terpenuhi.
    ///
    /// Returns `true` jika `threshold <= members.len()`.
    #[inline]
    pub fn is_valid(&self) -> bool {
        (self.threshold as usize) <= self.members.len()
    }

    /// Get jumlah members dalam committee.
    #[inline]
    pub fn member_count(&self) -> usize {
        self.members.len()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// SelectionConfig
// ════════════════════════════════════════════════════════════════════════════════

/// Configuration untuk coordinator selection.
///
/// Tidak ada default values. Semua fields HARUS di-specify explicitly.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SelectionConfig {
    /// Target committee size
    pub committee_size: u8,

    /// Threshold untuk threshold signing (t-of-n)
    pub threshold: u8,

    /// Minimum stake required untuk eligible sebagai candidate
    pub min_stake: u64,
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: create deterministic test data
    fn make_validator_candidate(seed: u8) -> ValidatorCandidate {
        let mut id = [0u8; 32];
        id[0] = seed;
        id[31] = seed.wrapping_add(1);

        let mut pubkey = [0u8; 32];
        pubkey[0] = seed.wrapping_add(100);
        pubkey[31] = seed.wrapping_add(101);

        ValidatorCandidate {
            id,
            pubkey,
            stake: (seed as u64 + 1) * 1000,
            zone: format!("zone-{}", seed % 3),
        }
    }

    fn make_coordinator_member(seed: u8) -> CoordinatorMember {
        let mut id = [0u8; 32];
        id[0] = seed;
        id[31] = seed.wrapping_add(10);

        let mut validator_id = [0u8; 32];
        validator_id[0] = seed;
        validator_id[31] = seed.wrapping_add(1);

        let mut pubkey = [0u8; 32];
        pubkey[0] = seed.wrapping_add(100);
        pubkey[31] = seed.wrapping_add(101);

        CoordinatorMember {
            id,
            validator_id,
            pubkey,
            stake: (seed as u64 + 1) * 1000,
        }
    }

    fn make_selection_config() -> SelectionConfig {
        SelectionConfig {
            committee_size: 5,
            threshold: 3,
            min_stake: 1000,
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Serialization Roundtrip Tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_validator_candidate_serialization_roundtrip() {
        let original = make_validator_candidate(42);

        // Serialize
        let serialized = match serde_json::to_string(&original) {
            Ok(s) => s,
            Err(e) => panic!("serialization failed: {}", e),
        };

        // Deserialize
        let deserialized: ValidatorCandidate = match serde_json::from_str(&serialized) {
            Ok(v) => v,
            Err(e) => panic!("deserialization failed: {}", e),
        };

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_selection_weight_serialization_roundtrip() {
        let mut validator_id = [0u8; 32];
        validator_id[0] = 99;
        validator_id[31] = 100;

        let original = SelectionWeight {
            validator_id,
            weight: 5000,
            cumulative: 15000,
        };

        let serialized = match serde_json::to_string(&original) {
            Ok(s) => s,
            Err(e) => panic!("serialization failed: {}", e),
        };

        let deserialized: SelectionWeight = match serde_json::from_str(&serialized) {
            Ok(v) => v,
            Err(e) => panic!("deserialization failed: {}", e),
        };

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_coordinator_member_serialization_roundtrip() {
        let original = make_coordinator_member(7);

        let serialized = match serde_json::to_string(&original) {
            Ok(s) => s,
            Err(e) => panic!("serialization failed: {}", e),
        };

        let deserialized: CoordinatorMember = match serde_json::from_str(&serialized) {
            Ok(v) => v,
            Err(e) => panic!("deserialization failed: {}", e),
        };

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_coordinator_committee_serialization_roundtrip() {
        let members = vec![
            make_coordinator_member(1),
            make_coordinator_member(2),
            make_coordinator_member(3),
        ];
        let group_pubkey = [0xABu8; 32];

        let original = match CoordinatorCommittee::new(members, 2, 100, group_pubkey) {
            Ok(c) => c,
            Err(e) => panic!("committee construction failed: {}", e),
        };

        let serialized = match serde_json::to_string(&original) {
            Ok(s) => s,
            Err(e) => panic!("serialization failed: {}", e),
        };

        let deserialized: CoordinatorCommittee = match serde_json::from_str(&serialized) {
            Ok(v) => v,
            Err(e) => panic!("deserialization failed: {}", e),
        };

        assert_eq!(original, deserialized);
        assert!(deserialized.is_valid());
    }

    #[test]
    fn test_selection_config_serialization_roundtrip() {
        let original = make_selection_config();

        let serialized = match serde_json::to_string(&original) {
            Ok(s) => s,
            Err(e) => panic!("serialization failed: {}", e),
        };

        let deserialized: SelectionConfig = match serde_json::from_str(&serialized) {
            Ok(v) => v,
            Err(e) => panic!("deserialization failed: {}", e),
        };

        assert_eq!(original, deserialized);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Invariant Tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_committee_invariant_threshold_equals_members() {
        let members = vec![
            make_coordinator_member(1),
            make_coordinator_member(2),
            make_coordinator_member(3),
        ];
        let group_pubkey = [0xCDu8; 32];

        // threshold == members.len() is valid
        let result = CoordinatorCommittee::new(members, 3, 1, group_pubkey);
        assert!(result.is_ok());

        let committee = result.expect("should be valid");
        assert!(committee.is_valid());
        assert_eq!(committee.member_count(), 3);
    }

    #[test]
    fn test_committee_invariant_threshold_less_than_members() {
        let members = vec![
            make_coordinator_member(1),
            make_coordinator_member(2),
            make_coordinator_member(3),
            make_coordinator_member(4),
            make_coordinator_member(5),
        ];
        let group_pubkey = [0xEFu8; 32];

        // threshold < members.len() is valid
        let result = CoordinatorCommittee::new(members, 3, 2, group_pubkey);
        assert!(result.is_ok());

        let committee = result.expect("should be valid");
        assert!(committee.is_valid());
        assert_eq!(committee.threshold, 3);
        assert_eq!(committee.member_count(), 5);
    }

    #[test]
    fn test_committee_invariant_violation() {
        let members = vec![
            make_coordinator_member(1),
            make_coordinator_member(2),
        ];
        let group_pubkey = [0x11u8; 32];

        // threshold > members.len() is INVALID
        let result = CoordinatorCommittee::new(members, 5, 1, group_pubkey);
        assert!(result.is_err());

        let err = result.expect_err("should fail");
        assert_eq!(err.threshold, 5);
        assert_eq!(err.members_count, 2);
    }

    #[test]
    fn test_committee_empty_members_zero_threshold() {
        let members: Vec<CoordinatorMember> = vec![];
        let group_pubkey = [0x00u8; 32];

        // threshold = 0 dengan empty members is valid (edge case)
        let result = CoordinatorCommittee::new(members, 0, 0, group_pubkey);
        assert!(result.is_ok());

        let committee = result.expect("should be valid");
        assert!(committee.is_valid());
        assert_eq!(committee.member_count(), 0);
    }

    #[test]
    fn test_committee_empty_members_nonzero_threshold() {
        let members: Vec<CoordinatorMember> = vec![];
        let group_pubkey = [0x00u8; 32];

        // threshold > 0 dengan empty members is INVALID
        let result = CoordinatorCommittee::new(members, 1, 0, group_pubkey);
        assert!(result.is_err());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Binary Serialization Tests (bincode)
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_validator_candidate_bincode_roundtrip() {
        let original = make_validator_candidate(123);

        let serialized = match bincode::serialize(&original) {
            Ok(b) => b,
            Err(e) => panic!("bincode serialization failed: {}", e),
        };

        let deserialized: ValidatorCandidate = match bincode::deserialize(&serialized) {
            Ok(v) => v,
            Err(e) => panic!("bincode deserialization failed: {}", e),
        };

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_coordinator_committee_bincode_roundtrip() {
        let members = vec![
            make_coordinator_member(10),
            make_coordinator_member(20),
            make_coordinator_member(30),
        ];
        let group_pubkey = [0x99u8; 32];

        let original = match CoordinatorCommittee::new(members, 2, 50, group_pubkey) {
            Ok(c) => c,
            Err(e) => panic!("committee construction failed: {}", e),
        };

        let serialized = match bincode::serialize(&original) {
            Ok(b) => b,
            Err(e) => panic!("bincode serialization failed: {}", e),
        };

        let deserialized: CoordinatorCommittee = match bincode::deserialize(&serialized) {
            Ok(v) => v,
            Err(e) => panic!("bincode deserialization failed: {}", e),
        };

        assert_eq!(original, deserialized);
        assert!(deserialized.is_valid());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Determinism Tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_serialization_determinism() {
        let candidate = make_validator_candidate(77);

        // Serialize multiple times - hasil harus identik
        let s1 = serde_json::to_string(&candidate).expect("s1");
        let s2 = serde_json::to_string(&candidate).expect("s2");
        let s3 = serde_json::to_string(&candidate).expect("s3");

        assert_eq!(s1, s2);
        assert_eq!(s2, s3);
    }

    #[test]
    fn test_config_no_hidden_state() {
        // Dua config dengan nilai sama harus equal
        let c1 = SelectionConfig {
            committee_size: 7,
            threshold: 5,
            min_stake: 10000,
        };

        let c2 = SelectionConfig {
            committee_size: 7,
            threshold: 5,
            min_stake: 10000,
        };

        assert_eq!(c1, c2);

        // Hash equality via serialization
        let s1 = serde_json::to_string(&c1).expect("s1");
        let s2 = serde_json::to_string(&c2).expect("s2");
        assert_eq!(s1, s2);
    }
}