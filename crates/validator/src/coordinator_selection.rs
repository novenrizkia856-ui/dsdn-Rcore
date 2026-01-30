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
// CoordinatorSelector (14A.2B.2.2)
// ════════════════════════════════════════════════════════════════════════════════

/// Error type untuk CoordinatorSelector construction.
///
/// Returned ketika config violates invariant: threshold <= committee_size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectorConfigError {
    /// Threshold yang diminta
    pub threshold: u8,

    /// Committee size yang dikonfigurasi
    pub committee_size: u8,
}

impl std::fmt::Display for SelectorConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "selector config invalid: threshold ({}) > committee_size ({})",
            self.threshold, self.committee_size
        )
    }
}

impl std::error::Error for SelectorConfigError {}

/// Stateless coordinator selection engine.
///
/// CoordinatorSelector adalah pure computation engine tanpa side effects.
/// Semua methods deterministik dan thread-safe.
///
/// # Invariant
///
/// `config.threshold <= config.committee_size` HARUS selalu terpenuhi.
/// Invariant ini dijaga oleh constructor `new()`.
///
/// # Example
///
/// ```ignore
/// let config = SelectionConfig {
///     committee_size: 5,
///     threshold: 3,
///     min_stake: 1000,
/// };
/// let selector = CoordinatorSelector::new(config)?;
///
/// let eligible = selector.compute_eligible_validators(&candidates, 1000);
/// let total = selector.total_stake(&eligible);
/// ```
#[derive(Clone, Debug)]
pub struct CoordinatorSelector {
    /// Selection configuration
    config: SelectionConfig,
}

impl CoordinatorSelector {
    /// Create new CoordinatorSelector dengan config validation.
    ///
    /// # Errors
    ///
    /// Returns `SelectorConfigError` jika `config.threshold > config.committee_size`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config = SelectionConfig {
    ///     committee_size: 5,
    ///     threshold: 3,
    ///     min_stake: 1000,
    /// };
    /// let selector = CoordinatorSelector::new(config)?;
    /// ```
    pub fn new(config: SelectionConfig) -> Result<Self, SelectorConfigError> {
        // Invariant: threshold <= committee_size
        if config.threshold > config.committee_size {
            return Err(SelectorConfigError {
                threshold: config.threshold,
                committee_size: config.committee_size,
            });
        }

        Ok(Self { config })
    }

    /// Get reference ke internal config.
    #[inline]
    pub fn config(&self) -> &SelectionConfig {
        &self.config
    }

    /// Filter validators berdasarkan minimum stake requirement.
    ///
    /// # Behavior
    ///
    /// - Filter: `validator.stake >= min_stake`
    /// - Urutan input dipertahankan (stable)
    /// - Tidak ada sorting
    /// - Tidak ada dedup
    /// - Return adalah clone dari matching validators
    ///
    /// # Arguments
    ///
    /// * `validators` - Slice of validator candidates
    /// * `min_stake` - Minimum stake threshold untuk eligibility
    ///
    /// # Returns
    ///
    /// Vec of validators yang memenuhi kriteria stake.
    pub fn compute_eligible_validators(
        &self,
        validators: &[ValidatorCandidate],
        min_stake: u64,
    ) -> Vec<ValidatorCandidate> {
        validators
            .iter()
            .filter(|v| v.stake >= min_stake)
            .cloned()
            .collect()
    }

    /// Compute total stake dari slice of validators.
    ///
    /// # Overflow Handling
    ///
    /// Menggunakan saturating addition. Jika total melebihi u64::MAX,
    /// result akan saturate ke u64::MAX tanpa panic atau wrap-around.
    ///
    /// # Arguments
    ///
    /// * `validators` - Slice of validator candidates
    ///
    /// # Returns
    ///
    /// Total stake (saturating sum).
    pub fn total_stake(&self, validators: &[ValidatorCandidate]) -> u64 {
        validators
            .iter()
            .fold(0u64, |acc, v| acc.saturating_add(v.stake))
    }

    // ════════════════════════════════════════════════════════════════════════════
    // Selection Weight Computation (14A.2B.2.3)
    // ════════════════════════════════════════════════════════════════════════════

    /// Compute selection weights dengan cumulative distribution.
    ///
    /// # Formula
    ///
    /// - `weight[i] = stake[i]` (tanpa normalisasi, u64)
    /// - `cumulative[i] = sum(stake[0..=i])` (inclusive)
    ///
    /// # Behavior
    ///
    /// - Jika `validators` kosong → return Vec kosong
    /// - Urutan input dipertahankan
    /// - Cumulative monotonically increasing
    /// - Overflow di-handle dengan saturating addition
    ///
    /// # Arguments
    ///
    /// * `validators` - Slice of validator candidates
    ///
    /// # Returns
    ///
    /// Vec of SelectionWeight dengan cumulative distribution.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // validators: [stake=1000, stake=2000, stake=3000]
    /// // result:
    /// //   [0]: weight=1000, cumulative=1000
    /// //   [1]: weight=2000, cumulative=3000
    /// //   [2]: weight=3000, cumulative=6000
    /// ```
    pub fn compute_selection_weights(
        &self,
        validators: &[ValidatorCandidate],
    ) -> Vec<SelectionWeight> {
        if validators.is_empty() {
            return Vec::new();
        }

        let mut cumulative: u64 = 0;
        let mut weights = Vec::with_capacity(validators.len());

        for validator in validators {
            // Saturating add untuk prevent overflow
            cumulative = cumulative.saturating_add(validator.stake);

            weights.push(SelectionWeight {
                validator_id: validator.id,
                weight: validator.stake,
                cumulative,
            });
        }

        weights
    }

    /// Select validator index berdasarkan random value dan cumulative weights.
    ///
    /// # Algorithm
    ///
    /// Kembalikan index TERKECIL `i` dimana `random_value < weights[i].cumulative`.
    ///
    /// # Behavior
    ///
    /// - Jika `weights` kosong → return None
    /// - Jika tidak ada yang cocok → return None
    /// - `weights` diasumsikan SUDAH cumulative (tidak di-validate)
    ///
    /// # Arguments
    ///
    /// * `weights` - Slice of SelectionWeight (harus sudah cumulative)
    /// * `random_value` - Random value untuk selection
    ///
    /// # Returns
    ///
    /// `Some(index)` jika ditemukan, `None` jika tidak.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // weights: [cum=1000, cum=3000, cum=6000]
    /// // random_value = 0    → returns Some(0)  (0 < 1000)
    /// // random_value = 999  → returns Some(0)  (999 < 1000)
    /// // random_value = 1000 → returns Some(1)  (1000 < 3000)
    /// // random_value = 5999 → returns Some(2)  (5999 < 6000)
    /// // random_value = 6000 → returns None     (6000 >= 6000)
    /// ```
    pub fn select_by_weight(
        &self,
        weights: &[SelectionWeight],
        random_value: u64,
    ) -> Option<usize> {
        if weights.is_empty() {
            return None;
        }

        // Linear search untuk index terkecil dimana random_value < cumulative
        for (index, weight) in weights.iter().enumerate() {
            if random_value < weight.cumulative {
                return Some(index);
            }
        }

        // Tidak ada yang cocok (random_value >= last cumulative)
        None
    }
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

    // ────────────────────────────────────────────────────────────────────────────
    // CoordinatorSelector Tests (14A.2B.2.2)
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_selector_new_valid_config() {
        // threshold < committee_size: valid
        let config = SelectionConfig {
            committee_size: 5,
            threshold: 3,
            min_stake: 1000,
        };

        let result = CoordinatorSelector::new(config.clone());
        assert!(result.is_ok());

        let selector = result.expect("should succeed");
        assert_eq!(selector.config().committee_size, 5);
        assert_eq!(selector.config().threshold, 3);
        assert_eq!(selector.config().min_stake, 1000);
    }

    #[test]
    fn test_selector_new_threshold_equals_committee_size() {
        // threshold == committee_size: valid (edge case)
        let config = SelectionConfig {
            committee_size: 5,
            threshold: 5,
            min_stake: 1000,
        };

        let result = CoordinatorSelector::new(config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_selector_new_invalid_config() {
        // threshold > committee_size: INVALID
        let config = SelectionConfig {
            committee_size: 3,
            threshold: 5,
            min_stake: 1000,
        };

        let result = CoordinatorSelector::new(config);
        assert!(result.is_err());

        let err = result.expect_err("should fail");
        assert_eq!(err.threshold, 5);
        assert_eq!(err.committee_size, 3);

        // Verify Display impl
        let msg = format!("{}", err);
        assert!(msg.contains("threshold"));
        assert!(msg.contains("committee_size"));
    }

    #[test]
    fn test_selector_new_zero_values() {
        // Both zero: valid edge case
        let config = SelectionConfig {
            committee_size: 0,
            threshold: 0,
            min_stake: 0,
        };

        let result = CoordinatorSelector::new(config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_compute_eligible_validators_filters_correctly() {
        let config = SelectionConfig {
            committee_size: 5,
            threshold: 3,
            min_stake: 1000,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        // Create validators with different stakes
        let mut v1 = make_validator_candidate(1); // stake = 2000
        v1.stake = 500; // below threshold

        let mut v2 = make_validator_candidate(2); // stake = 3000
        v2.stake = 1000; // at threshold

        let mut v3 = make_validator_candidate(3);
        v3.stake = 1500; // above threshold

        let mut v4 = make_validator_candidate(4);
        v4.stake = 999; // just below

        let mut v5 = make_validator_candidate(5);
        v5.stake = 5000; // well above

        let validators = vec![v1.clone(), v2.clone(), v3.clone(), v4.clone(), v5.clone()];

        // Filter with min_stake = 1000
        let eligible = selector.compute_eligible_validators(&validators, 1000);

        // Should include v2, v3, v5 (stake >= 1000)
        assert_eq!(eligible.len(), 3);

        // Order preserved
        assert_eq!(eligible[0].stake, 1000); // v2
        assert_eq!(eligible[1].stake, 1500); // v3
        assert_eq!(eligible[2].stake, 5000); // v5
    }

    #[test]
    fn test_compute_eligible_validators_empty_input() {
        let config = SelectionConfig {
            committee_size: 5,
            threshold: 3,
            min_stake: 1000,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        let validators: Vec<ValidatorCandidate> = vec![];
        let eligible = selector.compute_eligible_validators(&validators, 1000);

        assert!(eligible.is_empty());
    }

    #[test]
    fn test_compute_eligible_validators_none_eligible() {
        let config = SelectionConfig {
            committee_size: 5,
            threshold: 3,
            min_stake: 1000,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        // All validators below threshold
        let mut v1 = make_validator_candidate(1);
        v1.stake = 100;
        let mut v2 = make_validator_candidate(2);
        v2.stake = 200;
        let mut v3 = make_validator_candidate(3);
        v3.stake = 300;

        let validators = vec![v1, v2, v3];
        let eligible = selector.compute_eligible_validators(&validators, 1000);

        assert!(eligible.is_empty());
    }

    #[test]
    fn test_compute_eligible_validators_all_eligible() {
        let config = SelectionConfig {
            committee_size: 5,
            threshold: 3,
            min_stake: 100,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        let v1 = make_validator_candidate(1); // stake = 2000
        let v2 = make_validator_candidate(2); // stake = 3000
        let v3 = make_validator_candidate(3); // stake = 4000

        let validators = vec![v1.clone(), v2.clone(), v3.clone()];
        let eligible = selector.compute_eligible_validators(&validators, 100);

        assert_eq!(eligible.len(), 3);
        assert_eq!(eligible, validators);
    }

    #[test]
    fn test_compute_eligible_validators_stake_zero() {
        let config = SelectionConfig {
            committee_size: 5,
            threshold: 3,
            min_stake: 0,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        let mut v1 = make_validator_candidate(1);
        v1.stake = 0;
        let mut v2 = make_validator_candidate(2);
        v2.stake = 0;

        let validators = vec![v1.clone(), v2.clone()];

        // min_stake = 0, so stake >= 0 passes
        let eligible = selector.compute_eligible_validators(&validators, 0);
        assert_eq!(eligible.len(), 2);

        // min_stake = 1, stake = 0 fails
        let eligible = selector.compute_eligible_validators(&validators, 1);
        assert!(eligible.is_empty());
    }

    #[test]
    fn test_compute_eligible_validators_preserves_order() {
        let config = SelectionConfig {
            committee_size: 10,
            threshold: 5,
            min_stake: 100,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        // Create validators with specific order
        let validators: Vec<ValidatorCandidate> = (0..10)
            .map(|i| {
                let mut v = make_validator_candidate(i as u8);
                v.stake = 1000 + (i as u64 * 100);
                v
            })
            .collect();

        let eligible = selector.compute_eligible_validators(&validators, 100);

        // All should be eligible and order preserved
        assert_eq!(eligible.len(), 10);
        for (i, v) in eligible.iter().enumerate() {
            assert_eq!(v.stake, 1000 + (i as u64 * 100));
        }
    }

    #[test]
    fn test_total_stake_correct() {
        let config = SelectionConfig {
            committee_size: 5,
            threshold: 3,
            min_stake: 1000,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        let mut v1 = make_validator_candidate(1);
        v1.stake = 1000;
        let mut v2 = make_validator_candidate(2);
        v2.stake = 2000;
        let mut v3 = make_validator_candidate(3);
        v3.stake = 3000;

        let validators = vec![v1, v2, v3];
        let total = selector.total_stake(&validators);

        assert_eq!(total, 6000);
    }

    #[test]
    fn test_total_stake_empty() {
        let config = SelectionConfig {
            committee_size: 5,
            threshold: 3,
            min_stake: 1000,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        let validators: Vec<ValidatorCandidate> = vec![];
        let total = selector.total_stake(&validators);

        assert_eq!(total, 0);
    }

    #[test]
    fn test_total_stake_zero_stakes() {
        let config = SelectionConfig {
            committee_size: 5,
            threshold: 3,
            min_stake: 0,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        let mut v1 = make_validator_candidate(1);
        v1.stake = 0;
        let mut v2 = make_validator_candidate(2);
        v2.stake = 0;

        let validators = vec![v1, v2];
        let total = selector.total_stake(&validators);

        assert_eq!(total, 0);
    }

    #[test]
    fn test_total_stake_overflow_saturates() {
        let config = SelectionConfig {
            committee_size: 5,
            threshold: 3,
            min_stake: 1000,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        let mut v1 = make_validator_candidate(1);
        v1.stake = u64::MAX;
        let mut v2 = make_validator_candidate(2);
        v2.stake = 1000;

        let validators = vec![v1, v2];
        let total = selector.total_stake(&validators);

        // Should saturate to u64::MAX, not overflow/panic
        assert_eq!(total, u64::MAX);
    }

    #[test]
    fn test_total_stake_large_values() {
        let config = SelectionConfig {
            committee_size: 5,
            threshold: 3,
            min_stake: 1000,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        // Large but not overflowing
        let mut v1 = make_validator_candidate(1);
        v1.stake = u64::MAX / 2;
        let mut v2 = make_validator_candidate(2);
        v2.stake = u64::MAX / 2;

        let validators = vec![v1, v2];
        let total = selector.total_stake(&validators);

        // (MAX/2) + (MAX/2) = MAX - 1 (due to integer division)
        assert_eq!(total, (u64::MAX / 2) + (u64::MAX / 2));
    }

    #[test]
    fn test_selector_is_clone() {
        let config = SelectionConfig {
            committee_size: 5,
            threshold: 3,
            min_stake: 1000,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");
        let cloned = selector.clone();

        assert_eq!(selector.config(), cloned.config());
    }

    #[test]
    fn test_selector_is_debug() {
        let config = SelectionConfig {
            committee_size: 5,
            threshold: 3,
            min_stake: 1000,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        // Should not panic
        let debug_str = format!("{:?}", selector);
        assert!(debug_str.contains("CoordinatorSelector"));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Selection Weight Computation Tests (14A.2B.2.3)
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_compute_weights_single_validator() {
        let config = SelectionConfig {
            committee_size: 5,
            threshold: 3,
            min_stake: 1000,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        let mut v1 = make_validator_candidate(1);
        v1.stake = 5000;

        let validators = vec![v1.clone()];
        let weights = selector.compute_selection_weights(&validators);

        assert_eq!(weights.len(), 1);
        assert_eq!(weights[0].validator_id, v1.id);
        assert_eq!(weights[0].weight, 5000);
        assert_eq!(weights[0].cumulative, 5000);
    }

    #[test]
    fn test_compute_weights_equal_stake() {
        let config = SelectionConfig {
            committee_size: 5,
            threshold: 3,
            min_stake: 1000,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        // 3 validators dengan stake equal
        let mut v1 = make_validator_candidate(1);
        v1.stake = 1000;
        let mut v2 = make_validator_candidate(2);
        v2.stake = 1000;
        let mut v3 = make_validator_candidate(3);
        v3.stake = 1000;

        let validators = vec![v1.clone(), v2.clone(), v3.clone()];
        let weights = selector.compute_selection_weights(&validators);

        assert_eq!(weights.len(), 3);

        // weights harus sama
        assert_eq!(weights[0].weight, 1000);
        assert_eq!(weights[1].weight, 1000);
        assert_eq!(weights[2].weight, 1000);

        // cumulative harus increasing
        assert_eq!(weights[0].cumulative, 1000);
        assert_eq!(weights[1].cumulative, 2000);
        assert_eq!(weights[2].cumulative, 3000);

        // validator_id harus match
        assert_eq!(weights[0].validator_id, v1.id);
        assert_eq!(weights[1].validator_id, v2.id);
        assert_eq!(weights[2].validator_id, v3.id);
    }

    #[test]
    fn test_compute_weights_proportional() {
        let config = SelectionConfig {
            committee_size: 5,
            threshold: 3,
            min_stake: 1000,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        // Different stakes: 1000, 2000, 3000
        let mut v1 = make_validator_candidate(1);
        v1.stake = 1000;
        let mut v2 = make_validator_candidate(2);
        v2.stake = 2000;
        let mut v3 = make_validator_candidate(3);
        v3.stake = 3000;

        let validators = vec![v1, v2, v3];
        let weights = selector.compute_selection_weights(&validators);

        assert_eq!(weights.len(), 3);

        // Individual weights = stake
        assert_eq!(weights[0].weight, 1000);
        assert_eq!(weights[1].weight, 2000);
        assert_eq!(weights[2].weight, 3000);

        // Cumulative: 1000, 3000, 6000
        assert_eq!(weights[0].cumulative, 1000);
        assert_eq!(weights[1].cumulative, 3000);
        assert_eq!(weights[2].cumulative, 6000);
    }

    #[test]
    fn test_cumulative_monotonic() {
        let config = SelectionConfig {
            committee_size: 10,
            threshold: 5,
            min_stake: 100,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        // Various stakes including 0
        let stakes = [0u64, 100, 50, 200, 0, 1000, 500];
        let validators: Vec<ValidatorCandidate> = stakes
            .iter()
            .enumerate()
            .map(|(i, &stake)| {
                let mut v = make_validator_candidate(i as u8);
                v.stake = stake;
                v
            })
            .collect();

        let weights = selector.compute_selection_weights(&validators);

        assert_eq!(weights.len(), 7);

        // Verify monotonically increasing (non-decreasing since some stakes are 0)
        let mut prev_cumulative = 0u64;
        for (i, w) in weights.iter().enumerate() {
            assert!(
                w.cumulative >= prev_cumulative,
                "cumulative not monotonic at index {}: {} < {}",
                i,
                w.cumulative,
                prev_cumulative
            );
            prev_cumulative = w.cumulative;
        }

        // Verify total
        let expected_total: u64 = stakes.iter().sum();
        assert_eq!(weights.last().map(|w| w.cumulative), Some(expected_total));
    }

    #[test]
    fn test_compute_weights_empty() {
        let config = SelectionConfig {
            committee_size: 5,
            threshold: 3,
            min_stake: 1000,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        let validators: Vec<ValidatorCandidate> = vec![];
        let weights = selector.compute_selection_weights(&validators);

        assert!(weights.is_empty());
    }

    #[test]
    fn test_compute_weights_preserves_order() {
        let config = SelectionConfig {
            committee_size: 10,
            threshold: 5,
            min_stake: 100,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        // Create validators in specific order
        let validators: Vec<ValidatorCandidate> = (0..5)
            .map(|i| {
                let mut v = make_validator_candidate(i as u8);
                v.stake = ((5 - i) * 1000) as u64; // 5000, 4000, 3000, 2000, 1000
                v
            })
            .collect();

        let weights = selector.compute_selection_weights(&validators);

        // Verify order preserved
        assert_eq!(weights.len(), 5);
        for (i, (v, w)) in validators.iter().zip(weights.iter()).enumerate() {
            assert_eq!(
                w.validator_id, v.id,
                "order not preserved at index {}",
                i
            );
            assert_eq!(w.weight, v.stake);
        }
    }

    #[test]
    fn test_compute_weights_overflow_saturates() {
        let config = SelectionConfig {
            committee_size: 5,
            threshold: 3,
            min_stake: 0,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        let mut v1 = make_validator_candidate(1);
        v1.stake = u64::MAX;
        let mut v2 = make_validator_candidate(2);
        v2.stake = 1000;

        let validators = vec![v1, v2];
        let weights = selector.compute_selection_weights(&validators);

        assert_eq!(weights.len(), 2);
        assert_eq!(weights[0].cumulative, u64::MAX);
        // Saturating: MAX + 1000 = MAX
        assert_eq!(weights[1].cumulative, u64::MAX);
    }

    #[test]
    fn test_select_by_weight_basic() {
        let config = SelectionConfig {
            committee_size: 5,
            threshold: 3,
            min_stake: 1000,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        // Stakes: 1000, 2000, 3000 → cumulative: 1000, 3000, 6000
        let mut v1 = make_validator_candidate(1);
        v1.stake = 1000;
        let mut v2 = make_validator_candidate(2);
        v2.stake = 2000;
        let mut v3 = make_validator_candidate(3);
        v3.stake = 3000;

        let validators = vec![v1, v2, v3];
        let weights = selector.compute_selection_weights(&validators);

        // Test various random values
        // 0-999 should select index 0
        assert_eq!(selector.select_by_weight(&weights, 0), Some(0));
        assert_eq!(selector.select_by_weight(&weights, 500), Some(0));
        assert_eq!(selector.select_by_weight(&weights, 999), Some(0));

        // 1000-2999 should select index 1
        assert_eq!(selector.select_by_weight(&weights, 1000), Some(1));
        assert_eq!(selector.select_by_weight(&weights, 1500), Some(1));
        assert_eq!(selector.select_by_weight(&weights, 2999), Some(1));

        // 3000-5999 should select index 2
        assert_eq!(selector.select_by_weight(&weights, 3000), Some(2));
        assert_eq!(selector.select_by_weight(&weights, 4500), Some(2));
        assert_eq!(selector.select_by_weight(&weights, 5999), Some(2));
    }

    #[test]
    fn test_select_by_weight_edge_low() {
        let config = SelectionConfig {
            committee_size: 5,
            threshold: 3,
            min_stake: 1000,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        let mut v1 = make_validator_candidate(1);
        v1.stake = 1000;

        let validators = vec![v1];
        let weights = selector.compute_selection_weights(&validators);

        // random_value = 0 should select first
        assert_eq!(selector.select_by_weight(&weights, 0), Some(0));
    }

    #[test]
    fn test_select_by_weight_edge_high() {
        let config = SelectionConfig {
            committee_size: 5,
            threshold: 3,
            min_stake: 1000,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        let mut v1 = make_validator_candidate(1);
        v1.stake = 1000;
        let mut v2 = make_validator_candidate(2);
        v2.stake = 2000;

        let validators = vec![v1, v2];
        let weights = selector.compute_selection_weights(&validators);
        // cumulative: 1000, 3000

        // random_value = cumulative[-1] should return None
        assert_eq!(selector.select_by_weight(&weights, 3000), None);

        // random_value > cumulative[-1] should return None
        assert_eq!(selector.select_by_weight(&weights, 5000), None);
        assert_eq!(selector.select_by_weight(&weights, u64::MAX), None);
    }

    #[test]
    fn test_select_empty() {
        let config = SelectionConfig {
            committee_size: 5,
            threshold: 3,
            min_stake: 1000,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        let weights: Vec<SelectionWeight> = vec![];

        assert_eq!(selector.select_by_weight(&weights, 0), None);
        assert_eq!(selector.select_by_weight(&weights, 1000), None);
        assert_eq!(selector.select_by_weight(&weights, u64::MAX), None);
    }

    #[test]
    fn test_select_by_weight_boundary_exact() {
        let config = SelectionConfig {
            committee_size: 5,
            threshold: 3,
            min_stake: 1000,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        // Stakes: 100, 100, 100 → cumulative: 100, 200, 300
        let mut v1 = make_validator_candidate(1);
        v1.stake = 100;
        let mut v2 = make_validator_candidate(2);
        v2.stake = 100;
        let mut v3 = make_validator_candidate(3);
        v3.stake = 100;

        let validators = vec![v1, v2, v3];
        let weights = selector.compute_selection_weights(&validators);

        // Exact boundary tests
        // random_value < 100 → index 0
        assert_eq!(selector.select_by_weight(&weights, 99), Some(0));
        // random_value = 100 → index 1 (100 < 200)
        assert_eq!(selector.select_by_weight(&weights, 100), Some(1));
        // random_value = 199 → index 1
        assert_eq!(selector.select_by_weight(&weights, 199), Some(1));
        // random_value = 200 → index 2 (200 < 300)
        assert_eq!(selector.select_by_weight(&weights, 200), Some(2));
        // random_value = 299 → index 2
        assert_eq!(selector.select_by_weight(&weights, 299), Some(2));
        // random_value = 300 → None (300 >= 300)
        assert_eq!(selector.select_by_weight(&weights, 300), None);
    }

    #[test]
    fn test_select_by_weight_single_validator() {
        let config = SelectionConfig {
            committee_size: 5,
            threshold: 3,
            min_stake: 1000,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        let mut v1 = make_validator_candidate(1);
        v1.stake = 5000;

        let validators = vec![v1];
        let weights = selector.compute_selection_weights(&validators);

        // Any value < 5000 should return Some(0)
        assert_eq!(selector.select_by_weight(&weights, 0), Some(0));
        assert_eq!(selector.select_by_weight(&weights, 2500), Some(0));
        assert_eq!(selector.select_by_weight(&weights, 4999), Some(0));

        // value >= 5000 should return None
        assert_eq!(selector.select_by_weight(&weights, 5000), None);
    }

    #[test]
    fn test_compute_weights_deterministic() {
        let config = SelectionConfig {
            committee_size: 5,
            threshold: 3,
            min_stake: 1000,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        let mut v1 = make_validator_candidate(1);
        v1.stake = 1000;
        let mut v2 = make_validator_candidate(2);
        v2.stake = 2000;

        let validators = vec![v1, v2];

        // Compute multiple times
        let w1 = selector.compute_selection_weights(&validators);
        let w2 = selector.compute_selection_weights(&validators);
        let w3 = selector.compute_selection_weights(&validators);

        // All should be identical
        assert_eq!(w1, w2);
        assert_eq!(w2, w3);
    }

    #[test]
    fn test_select_by_weight_deterministic() {
        let config = SelectionConfig {
            committee_size: 5,
            threshold: 3,
            min_stake: 1000,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        let mut v1 = make_validator_candidate(1);
        v1.stake = 1000;
        let mut v2 = make_validator_candidate(2);
        v2.stake = 2000;

        let validators = vec![v1, v2];
        let weights = selector.compute_selection_weights(&validators);

        // Same random_value should always return same result
        let r1 = selector.select_by_weight(&weights, 500);
        let r2 = selector.select_by_weight(&weights, 500);
        let r3 = selector.select_by_weight(&weights, 500);

        assert_eq!(r1, r2);
        assert_eq!(r2, r3);
        assert_eq!(r1, Some(0));
    }
}