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
//! # Verification (14A.2B.2.6)
//!
//! - `DAMerkleProof` - Merkle proof untuk DA verification
//! - `SeedVerificationResult` - Result dari epoch seed verification
//! - `verify_epoch_seed` - Verify epoch seed dengan Merkle proof
//! - `verify_merkle_proof` - Verify generic Merkle proof
//!
//! # Committee Verification (14A.2B.2.8)
//!
//! - `VerificationError` - Error type untuk committee verification
//! - `verify_committee_selection` - Verify committee adalah hasil selection yang valid
//! - `verify_member_eligibility` - Verify member berasal dari validator set
//!
//! # Invariants
//!
//! - `CoordinatorCommittee`: threshold <= members.len()

// ════════════════════════════════════════════════════════════════════════════════
// Submodules
// ════════════════════════════════════════════════════════════════════════════════

pub mod verification;

// Comprehensive selection tests (14A.2B.2.9)
#[cfg(test)]
#[path = "tests.rs"]
mod selection_tests;

// Re-export verification types (14A.2B.2.6)
pub use verification::{DAMerkleProof, SeedVerificationResult, verify_epoch_seed, verify_merkle_proof};

// Re-export committee verification types (14A.2B.2.8)
pub use verification::{VerificationError, verify_committee_selection, verify_member_eligibility};

// ════════════════════════════════════════════════════════════════════════════════
// Imports
// ════════════════════════════════════════════════════════════════════════════════

use serde::{Deserialize, Serialize};

// ChaCha20 PRNG untuk deterministic shuffle (14A.2B.2.4)
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

// SHA3-256 untuk epoch seed derivation (14A.2B.2.5)
use sha3::{Digest, Sha3_256};

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

// ════════════════════════════════════════════════════════════════════════════════
// SelectionError (14A.2B.2.7 + 14A.2B.2.9)
// ════════════════════════════════════════════════════════════════════════════════

/// Error type untuk committee selection failures.
///
/// Returned ketika `select_committee` tidak dapat membentuk committee yang valid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SelectionError {
    /// Tidak cukup validators untuk membentuk committee
    InsufficientValidators {
        /// Jumlah validators yang tersedia
        available: usize,
        /// Jumlah minimum yang dibutuhkan (committee_size)
        required: usize,
    },

    /// Tidak cukup eligible validators (setelah filter min_stake)
    InsufficientEligibleValidators {
        /// Jumlah eligible validators
        eligible: usize,
        /// Jumlah minimum yang dibutuhkan
        required: usize,
    },

    /// Committee invariant violation (threshold > members)
    CommitteeInvariant {
        /// Threshold yang dikonfigurasi
        threshold: u8,
        /// Jumlah members yang berhasil dipilih
        members_count: usize,
    },

    /// Internal error (should never happen in correct implementation)
    Internal(String),

    /// Invalid configuration parameters (14A.2B.2.9)
    InvalidConfig {
        /// Deskripsi masalah konfigurasi
        reason: String,
    },

    /// Tidak ada validator yang eligible sama sekali (14A.2B.2.9)
    NoEligibleValidators,

    /// Seed derivation gagal (14A.2B.2.9)
    SeedDerivationFailed {
        /// Deskripsi penyebab kegagalan
        reason: String,
    },
}

impl std::fmt::Display for SelectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SelectionError::InsufficientValidators { available, required } => {
                write!(
                    f,
                    "insufficient validators: {} available, {} required",
                    available, required
                )
            }
            SelectionError::InsufficientEligibleValidators { eligible, required } => {
                write!(
                    f,
                    "insufficient eligible validators: {} eligible, {} required",
                    eligible, required
                )
            }
            SelectionError::CommitteeInvariant { threshold, members_count } => {
                write!(
                    f,
                    "committee invariant violated: threshold ({}) > members ({})",
                    threshold, members_count
                )
            }
            SelectionError::Internal(msg) => {
                write!(f, "internal selection error: {}", msg)
            }
            SelectionError::InvalidConfig { reason } => {
                write!(f, "invalid selection config: {}", reason)
            }
            SelectionError::NoEligibleValidators => {
                write!(f, "no eligible validators: all validators below minimum stake")
            }
            SelectionError::SeedDerivationFailed { reason } => {
                write!(f, "seed derivation failed: {}", reason)
            }
        }
    }
}

impl std::error::Error for SelectionError {}

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

    // ════════════════════════════════════════════════════════════════════════════
    // Deterministic Shuffle (14A.2B.2.4)
    // ════════════════════════════════════════════════════════════════════════════

    /// Create ChaCha20 PRNG dari 32-byte seed.
    ///
    /// # Determinism
    ///
    /// - Seed LANGSUNG digunakan tanpa transformasi
    /// - Tidak ada salt atau entropy tambahan
    /// - Same seed = same PRNG state = same random sequence
    ///
    /// # Thread Safety
    ///
    /// PRNG yang dikembalikan adalah owned value, bukan shared state.
    /// Tidak ada global mutable state.
    ///
    /// # Arguments
    ///
    /// * `seed` - 32-byte seed untuk PRNG
    ///
    /// # Returns
    ///
    /// ChaCha20 PRNG yang di-seed dari input.
    pub fn create_prng(&self, seed: &[u8; 32]) -> ChaCha20Rng {
        // Seed PRNG langsung dari input tanpa transformasi
        ChaCha20Rng::from_seed(*seed)
    }

    /// Shuffle items secara deterministik menggunakan Fisher-Yates algorithm.
    ///
    /// # Algorithm
    ///
    /// Fisher-Yates (Knuth) shuffle:
    /// ```text
    /// for i from (len-1) down to 1:
    ///     j = random integer in range [0, i] (inclusive)
    ///     swap(buffer[i], buffer[j])
    /// ```
    ///
    /// # Determinism
    ///
    /// - Same input + same seed = same output (across all nodes/architectures)
    /// - Menggunakan ChaCha20 PRNG yang deterministik
    /// - `gen_range` handles modulo bias dengan rejection sampling
    ///
    /// # Behavior
    ///
    /// - Input `items` TIDAK dimodifikasi
    /// - Returns Vec baru dengan elemen yang di-shuffle
    /// - Jika items kosong → return Vec kosong
    /// - Jika items.len() == 1 → return Vec dengan elemen yang sama
    ///
    /// # Arguments
    ///
    /// * `items` - Slice of items to shuffle
    /// * `seed` - 32-byte seed untuk deterministic PRNG
    ///
    /// # Returns
    ///
    /// Vec baru dengan elemen yang di-shuffle.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let items = vec![1, 2, 3, 4, 5];
    /// let seed = [0u8; 32];
    /// let shuffled = selector.deterministic_shuffle(&items, &seed);
    /// // shuffled adalah permutasi dari items, deterministik berdasarkan seed
    /// ```
    pub fn deterministic_shuffle<T: Clone>(
        &self,
        items: &[T],
        seed: &[u8; 32],
    ) -> Vec<T> {
        // Edge cases
        if items.is_empty() {
            return Vec::new();
        }
        if items.len() == 1 {
            return vec![items[0].clone()];
        }

        // Clone items ke mutable buffer
        let mut buffer: Vec<T> = items.to_vec();
        let len = buffer.len();

        // Create PRNG dari seed
        let mut rng = self.create_prng(seed);

        // Fisher-Yates shuffle: for i from (len-1) down to 1
        // Iterasi dari index terakhir ke index 1 (inclusive)
        for i in (1..len).rev() {
            // j = random integer in range [0, i] (inclusive)
            // gen_range menggunakan [low, high) jadi kita pakai [0, i+1)
            let j = rng.gen_range(0..=i);

            // swap(buffer[i], buffer[j])
            buffer.swap(i, j);
        }

        buffer
    }

    // ════════════════════════════════════════════════════════════════════════════
    // Committee Selection Algorithm (14A.2B.2.7)
    // ════════════════════════════════════════════════════════════════════════════

    /// Check apakah menambahkan candidate akan melanggar zone diversity.
    ///
    /// # Zone Diversity Rule
    ///
    /// Satu zone maksimal 1/3 dari committee_size.
    /// Dihitung berdasarkan jumlah validator, bukan stake.
    ///
    /// # Arguments
    ///
    /// * `selected` - Validators yang sudah terpilih
    /// * `candidate` - Candidate yang akan ditambahkan
    ///
    /// # Returns
    ///
    /// `true` jika candidate DAPAT ditambahkan tanpa melanggar zone diversity.
    /// `false` jika menambahkan candidate akan melanggar batas 1/3.
    ///
    /// # Determinism
    ///
    /// - Same inputs = same output
    /// - Tidak ada randomness
    /// - Tidak bergantung pada HashMap ordering (menggunakan counting)
    pub fn ensure_zone_diversity(
        &self,
        selected: &[ValidatorCandidate],
        candidate: &ValidatorCandidate,
    ) -> bool {
        // Hitung batas maksimum per zone: 1/3 dari committee_size (rounded up)
        // Menggunakan ceiling division: (a + b - 1) / b
        let max_per_zone = (self.config.committee_size as usize + 2) / 3;

        // Hitung berapa kali zone candidate muncul di selected
        let zone_count = selected
            .iter()
            .filter(|v| v.zone == candidate.zone)
            .count();

        // Jika menambahkan candidate akan melebihi limit, return false
        // zone_count + 1 (untuk candidate) <= max_per_zone
        zone_count < max_per_zone
    }

    /// Select committee secara deterministik dari daftar validators.
    ///
    /// # Algorithm (URUTAN WAJIB)
    ///
    /// 1. Ambil daftar validator input APA ADANYA
    /// 2. Filter berdasarkan min_stake (eligible validators)
    /// 3. Validasi: cukup eligible validators untuk committee_size
    /// 4. Deterministic shuffle menggunakan epoch seed
    /// 5. Iterasi hasil shuffle untuk memilih committee:
    ///    a. Skip validator yang sudah terpilih
    ///    b. Cek zone diversity via ensure_zone_diversity
    ///    c. Jika lolos → masukkan
    ///    d. Jika tidak ada kandidat zone-diverse → fallback ke stake tertinggi
    /// 6. Hentikan seleksi tepat saat committee_size tercapai
    /// 7. Urutkan hasil akhir berdasarkan stake DESCENDING
    /// 8. Bentuk CoordinatorCommittee dengan placeholder group_pubkey
    ///
    /// # Determinism
    ///
    /// - Same input + same seed = same output (across all nodes/architectures)
    /// - Tidak ada randomness non-seeded
    /// - Tidak bergantung pada iteration order non-deterministic
    ///
    /// # Arguments
    ///
    /// * `validators` - Slice of validator candidates
    /// * `epoch` - Epoch number untuk committee ini
    /// * `seed` - 32-byte deterministic seed (dari derive_epoch_seed)
    ///
    /// # Returns
    ///
    /// `Ok(CoordinatorCommittee)` jika selection berhasil.
    /// `Err(SelectionError)` jika selection gagal.
    ///
    /// # Note on group_pubkey
    ///
    /// `group_pubkey` dalam hasil adalah **placeholder deterministik** yang
    /// dihitung dari SHA3-256 concatenation of members' pubkeys.
    /// Nilai ini HARUS di-replace setelah DKG ceremony selesai.
    pub fn select_committee(
        &self,
        validators: &[ValidatorCandidate],
        epoch: u64,
        seed: &[u8; 32],
    ) -> Result<CoordinatorCommittee, SelectionError> {
        let committee_size = self.config.committee_size as usize;
        let threshold = self.config.threshold;

        // Step 1: Validasi input cukup
        if validators.len() < committee_size {
            return Err(SelectionError::InsufficientValidators {
                available: validators.len(),
                required: committee_size,
            });
        }

        // Step 2: Filter eligible validators (stake >= min_stake)
        let eligible = self.compute_eligible_validators(validators, self.config.min_stake);

        // Step 3: Validasi eligible cukup
        if eligible.len() < committee_size {
            return Err(SelectionError::InsufficientEligibleValidators {
                eligible: eligible.len(),
                required: committee_size,
            });
        }

        // Step 4: Deterministic shuffle
        let shuffled = self.deterministic_shuffle(&eligible, seed);

        // Step 5: Select committee dengan zone diversity
        let mut selected: Vec<ValidatorCandidate> = Vec::with_capacity(committee_size);

        // Pass 1: Select dengan zone diversity constraint
        for candidate in &shuffled {
            if selected.len() >= committee_size {
                break;
            }

            // Skip jika sudah terpilih (cek by id)
            if selected.iter().any(|s| s.id == candidate.id) {
                continue;
            }

            // Cek zone diversity
            if self.ensure_zone_diversity(&selected, candidate) {
                selected.push(candidate.clone());
            }
        }

        // Pass 2: Fallback jika belum cukup (relax zone diversity, pilih by stake)
        if selected.len() < committee_size {
            // Collect remaining candidates yang belum terpilih
            let mut remaining: Vec<&ValidatorCandidate> = shuffled
                .iter()
                .filter(|c| !selected.iter().any(|s| s.id == c.id))
                .collect();

            // Sort by stake descending untuk deterministic fallback
            remaining.sort_by(|a, b| b.stake.cmp(&a.stake));

            // Add sampai committee_size tercapai
            for candidate in remaining {
                if selected.len() >= committee_size {
                    break;
                }
                selected.push(candidate.clone());
            }
        }

        // Validasi: harus tepat committee_size
        if selected.len() != committee_size {
            return Err(SelectionError::Internal(format!(
                "failed to select {} members, only got {}",
                committee_size,
                selected.len()
            )));
        }

        // Step 6: Sort hasil akhir by stake DESCENDING
        selected.sort_by(|a, b| b.stake.cmp(&a.stake));

        // Step 7: Convert ValidatorCandidate ke CoordinatorMember
        let members: Vec<CoordinatorMember> = selected
            .iter()
            .enumerate()
            .map(|(idx, v)| {
                // Generate deterministic member ID dari validator ID + epoch + index
                let member_id = compute_member_id(&v.id, epoch, idx);

                CoordinatorMember {
                    id: member_id,
                    validator_id: v.id,
                    pubkey: v.pubkey,
                    stake: v.stake,
                }
            })
            .collect();

        // Step 8: Compute placeholder group_pubkey (akan di-replace setelah DKG)
        let group_pubkey = compute_placeholder_group_pubkey(&members);

        // Step 9: Create CoordinatorCommittee
        CoordinatorCommittee::new(members, threshold, epoch, group_pubkey).map_err(|e| {
            SelectionError::CommitteeInvariant {
                threshold: e.threshold,
                members_count: e.members_count,
            }
        })
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// Helper Functions for Committee Selection (14A.2B.2.7)
// ════════════════════════════════════════════════════════════════════════════════

/// Compute deterministic member ID dari validator ID, epoch, dan index.
///
/// # Algorithm
///
/// ```text
/// member_id = SHA3-256(validator_id_32 || epoch_be_8 || index_be_8)
/// ```
///
/// # Determinism
///
/// Same inputs = same output (cross-platform).
fn compute_member_id(validator_id: &[u8; 32], epoch: u64, index: usize) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(validator_id);
    hasher.update(epoch.to_be_bytes());
    hasher.update((index as u64).to_be_bytes());

    let result = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&result);
    id
}

/// Compute placeholder group_pubkey dari committee members.
///
/// # PENTING
///
/// Ini adalah **PLACEHOLDER** yang HARUS di-replace setelah DKG ceremony.
/// Nilai ini digunakan agar CoordinatorCommittee dapat dibentuk sebelum DKG.
///
/// # Algorithm
///
/// ```text
/// placeholder = SHA3-256(
///     0x01 ||  // domain separator
///     member_count_be_8 ||
///     for each member: member.pubkey_32
/// )
/// ```
///
/// # Determinism
///
/// Same members (same order) = same placeholder.
fn compute_placeholder_group_pubkey(members: &[CoordinatorMember]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();

    // Domain separator untuk menandakan ini placeholder
    hasher.update([0x01]);

    // Member count
    hasher.update((members.len() as u64).to_be_bytes());

    // Each member's pubkey (order matters)
    for member in members {
        hasher.update(member.pubkey);
    }

    let result = hasher.finalize();
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&result);
    pubkey
}

// ════════════════════════════════════════════════════════════════════════════════
// Epoch Seed Derivation (14A.2B.2.5)
// ════════════════════════════════════════════════════════════════════════════════

/// Derive epoch seed deterministik untuk committee selection.
///
/// # Algorithm
///
/// ```text
/// seed = SHA3-256(epoch_be_8 || da_blob_hash_32 || prev_committee_hash_32)
/// ```
///
/// # Input Layout (72 bytes total)
///
/// | Offset | Size | Field |
/// |--------|------|-------|
/// | 0      | 8    | epoch (big-endian) |
/// | 8      | 32   | da_blob_hash |
/// | 40     | 32   | prev_committee_hash |
///
/// # Determinism
///
/// - Same inputs = same output (across all nodes/architectures)
/// - Urutan concatenation TIDAK BERUBAH
/// - Epoch di-encode dalam big-endian (network byte order)
/// - Hash inputs digunakan apa adanya
///
/// # Security
///
/// - Menggunakan SHA3-256 (Keccak)
/// - Output tepat 32 bytes
/// - Tidak ada salt atau entropy tambahan
///
/// # Arguments
///
/// * `epoch` - Epoch number
/// * `da_blob_hash` - Hash dari DA blob untuk epoch ini
/// * `prev_committee_hash` - Hash dari committee epoch sebelumnya
///
/// # Returns
///
/// 32-byte epoch seed.
pub fn derive_epoch_seed(
    epoch: u64,
    da_blob_hash: &[u8; 32],
    prev_committee_hash: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();

    // 1. Epoch dalam big-endian (8 bytes)
    hasher.update(epoch.to_be_bytes());

    // 2. DA blob hash (32 bytes)
    hasher.update(da_blob_hash);

    // 3. Previous committee hash (32 bytes)
    hasher.update(prev_committee_hash);

    // Finalize dan convert ke [u8; 32]
    let result = hasher.finalize();

    // SHA3-256 output is exactly 32 bytes
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&result);
    seed
}

/// Compute deterministic hash dari CoordinatorCommittee.
///
/// # Determinism
///
/// Hash DIJAMIN deterministik karena:
/// - Semua fields di-hash dalam urutan tetap
/// - Semua angka di-encode dalam big-endian
/// - Vec<CoordinatorMember> di-iterate secara sequential (urutan Vec dipertahankan)
/// - Tidak bergantung pada memory layout atau pointer
///
/// # Hash Layout
///
/// ```text
/// SHA3-256(
///     epoch_be_8 ||
///     threshold_1 ||
///     group_pubkey_32 ||
///     member_count_be_8 ||
///     for each member:
///         member.id_32 ||
///         member.validator_id_32 ||
///         member.pubkey_32 ||
///         member.stake_be_8
/// )
/// ```
///
/// # Arguments
///
/// * `committee` - CoordinatorCommittee to hash
///
/// # Returns
///
/// 32-byte deterministic hash.
pub fn compute_committee_hash(committee: &CoordinatorCommittee) -> [u8; 32] {
    let mut hasher = Sha3_256::new();

    // 1. Epoch (8 bytes, big-endian)
    hasher.update(committee.epoch.to_be_bytes());

    // 2. Threshold (1 byte)
    hasher.update([committee.threshold]);

    // 3. Group public key (32 bytes)
    hasher.update(committee.group_pubkey);

    // 4. Member count (8 bytes, big-endian) - untuk disambiguasi
    hasher.update((committee.members.len() as u64).to_be_bytes());

    // 5. Each member in order (deterministic karena Vec maintains order)
    for member in &committee.members {
        // Member ID (32 bytes)
        hasher.update(member.id);

        // Validator ID (32 bytes)
        hasher.update(member.validator_id);

        // Public key (32 bytes)
        hasher.update(member.pubkey);

        // Stake (8 bytes, big-endian)
        hasher.update(member.stake.to_be_bytes());
    }

    // Finalize
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
    use rand::Rng; // Untuk test PRNG

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

    // ────────────────────────────────────────────────────────────────────────────
    // Deterministic Shuffle Tests (14A.2B.2.4)
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_shuffle_same_seed_same_output() {
        let config = SelectionConfig {
            committee_size: 10,
            threshold: 5,
            min_stake: 1000,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        // Create test items
        let items: Vec<u32> = (0..20).collect();

        // Fixed seed
        let seed = [0x42u8; 32];

        // Run 100 iterations - ALL must be identical
        let first_result = selector.deterministic_shuffle(&items, &seed);

        for iteration in 0..100 {
            let result = selector.deterministic_shuffle(&items, &seed);
            assert_eq!(
                result, first_result,
                "iteration {} produced different result",
                iteration
            );
        }
    }

    #[test]
    fn test_shuffle_different_seed_different_output() {
        let config = SelectionConfig {
            committee_size: 10,
            threshold: 5,
            min_stake: 1000,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        let items: Vec<u32> = (0..20).collect();

        let seed1 = [0x00u8; 32];
        let seed2 = [0x01u8; 32];
        let seed3 = [0xFFu8; 32];

        let result1 = selector.deterministic_shuffle(&items, &seed1);
        let result2 = selector.deterministic_shuffle(&items, &seed2);
        let result3 = selector.deterministic_shuffle(&items, &seed3);

        // Different seeds should produce different outputs
        // (With 20 items, probability of collision is negligible: 1/20!)
        assert_ne!(result1, result2, "seed1 vs seed2 should differ");
        assert_ne!(result2, result3, "seed2 vs seed3 should differ");
        assert_ne!(result1, result3, "seed1 vs seed3 should differ");
    }

    #[test]
    fn test_shuffle_preserves_elements() {
        let config = SelectionConfig {
            committee_size: 10,
            threshold: 5,
            min_stake: 1000,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        // Test with various seeds
        let seeds: [[u8; 32]; 5] = [
            [0x00u8; 32],
            [0x11u8; 32],
            [0x22u8; 32],
            [0x33u8; 32],
            [0xFFu8; 32],
        ];

        for seed in &seeds {
            let items: Vec<u32> = (0..50).collect();
            let shuffled = selector.deterministic_shuffle(&items, seed);

            // Same length
            assert_eq!(shuffled.len(), items.len());

            // No elements lost - every original element must be present
            let mut sorted_shuffled = shuffled.clone();
            sorted_shuffled.sort();
            assert_eq!(sorted_shuffled, items);
        }
    }

    #[test]
    fn test_shuffle_empty() {
        let config = SelectionConfig {
            committee_size: 10,
            threshold: 5,
            min_stake: 1000,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        let items: Vec<u32> = vec![];
        let seed = [0x42u8; 32];

        let result = selector.deterministic_shuffle(&items, &seed);

        assert!(result.is_empty());
    }

    #[test]
    fn test_shuffle_single_element() {
        let config = SelectionConfig {
            committee_size: 10,
            threshold: 5,
            min_stake: 1000,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        let items = vec![42u32];
        let seed = [0x42u8; 32];

        let result = selector.deterministic_shuffle(&items, &seed);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0], 42);
    }

    #[test]
    fn test_shuffle_two_elements() {
        let config = SelectionConfig {
            committee_size: 10,
            threshold: 5,
            min_stake: 1000,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        let items = vec![1u32, 2];
        let seed = [0x42u8; 32];

        let result = selector.deterministic_shuffle(&items, &seed);

        // Must contain both elements
        assert_eq!(result.len(), 2);
        assert!(result.contains(&1));
        assert!(result.contains(&2));

        // Same seed = same result
        let result2 = selector.deterministic_shuffle(&items, &seed);
        assert_eq!(result, result2);
    }

    #[test]
    fn test_shuffle_with_validator_candidates() {
        let config = SelectionConfig {
            committee_size: 10,
            threshold: 5,
            min_stake: 1000,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        // Create 10 validators
        let validators: Vec<ValidatorCandidate> = (0..10)
            .map(|i| make_validator_candidate(i as u8))
            .collect();

        let seed = [0x99u8; 32];
        let shuffled = selector.deterministic_shuffle(&validators, &seed);

        // Same length
        assert_eq!(shuffled.len(), 10);

        // All original validators present (by id)
        for v in &validators {
            assert!(
                shuffled.iter().any(|s| s.id == v.id),
                "validator {:?} missing from shuffled result",
                v.id[0]
            );
        }

        // Determinism
        let shuffled2 = selector.deterministic_shuffle(&validators, &seed);
        assert_eq!(shuffled, shuffled2);
    }

    #[test]
    fn test_create_prng_deterministic() {
        let config = SelectionConfig {
            committee_size: 10,
            threshold: 5,
            min_stake: 1000,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        let seed = [0xABu8; 32];

        // Create two PRNGs with same seed
        let mut rng1 = selector.create_prng(&seed);
        let mut rng2 = selector.create_prng(&seed);

        // Generate sequence from both - must be identical
        for i in 0..1000 {
            let v1: u64 = rng1.gen();
            let v2: u64 = rng2.gen();
            assert_eq!(v1, v2, "PRNG diverged at iteration {}", i);
        }
    }

    #[test]
    fn test_create_prng_different_seeds() {
        let config = SelectionConfig {
            committee_size: 10,
            threshold: 5,
            min_stake: 1000,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        let seed1 = [0x00u8; 32];
        let seed2 = [0x01u8; 32];

        let mut rng1 = selector.create_prng(&seed1);
        let mut rng2 = selector.create_prng(&seed2);

        // First value should differ
        let v1: u64 = rng1.gen();
        let v2: u64 = rng2.gen();
        assert_ne!(v1, v2, "different seeds should produce different values");
    }

    #[test]
    fn test_shuffle_does_not_modify_input() {
        let config = SelectionConfig {
            committee_size: 10,
            threshold: 5,
            min_stake: 1000,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        let items: Vec<u32> = (0..20).collect();
        let items_clone = items.clone();
        let seed = [0x42u8; 32];

        let _result = selector.deterministic_shuffle(&items, &seed);

        // Original items unchanged
        assert_eq!(items, items_clone);
    }

    #[test]
    fn test_shuffle_cross_invocation_determinism() {
        // This test verifies determinism across multiple selector instances
        let config = SelectionConfig {
            committee_size: 10,
            threshold: 5,
            min_stake: 1000,
        };

        // Create multiple selector instances
        let selector1 = CoordinatorSelector::new(config.clone()).expect("valid config");
        let selector2 = CoordinatorSelector::new(config.clone()).expect("valid config");
        let selector3 = CoordinatorSelector::new(config).expect("valid config");

        let items: Vec<u32> = (0..100).collect();
        let seed = [0x55u8; 32];

        let result1 = selector1.deterministic_shuffle(&items, &seed);
        let result2 = selector2.deterministic_shuffle(&items, &seed);
        let result3 = selector3.deterministic_shuffle(&items, &seed);

        // All results must be identical
        assert_eq!(result1, result2);
        assert_eq!(result2, result3);
    }

    #[test]
    fn test_shuffle_large_array() {
        let config = SelectionConfig {
            committee_size: 10,
            threshold: 5,
            min_stake: 1000,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        // Large array
        let items: Vec<u32> = (0..1000).collect();
        let seed = [0x77u8; 32];

        let shuffled = selector.deterministic_shuffle(&items, &seed);

        // Verify all elements present
        assert_eq!(shuffled.len(), 1000);
        let mut sorted = shuffled.clone();
        sorted.sort();
        assert_eq!(sorted, items);

        // Verify determinism
        let shuffled2 = selector.deterministic_shuffle(&items, &seed);
        assert_eq!(shuffled, shuffled2);
    }

    #[test]
    fn test_shuffle_known_seed_reproducibility() {
        // Test with a known seed to ensure reproducibility across implementations
        let config = SelectionConfig {
            committee_size: 5,
            threshold: 3,
            min_stake: 1000,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        let items: Vec<u8> = vec![0, 1, 2, 3, 4];
        let seed = [0u8; 32]; // All zeros seed

        let result1 = selector.deterministic_shuffle(&items, &seed);
        let result2 = selector.deterministic_shuffle(&items, &seed);

        // Must be deterministic
        assert_eq!(result1, result2);

        // Must be a valid permutation
        let mut sorted = result1.clone();
        sorted.sort();
        assert_eq!(sorted, items);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Epoch Seed Derivation Tests (14A.2B.2.5)
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_epoch_seed_deterministic() {
        let epoch = 42u64;
        let da_blob_hash = [0xAAu8; 32];
        let prev_committee_hash = [0xBBu8; 32];

        // Call multiple times
        let seed1 = derive_epoch_seed(epoch, &da_blob_hash, &prev_committee_hash);
        let seed2 = derive_epoch_seed(epoch, &da_blob_hash, &prev_committee_hash);
        let seed3 = derive_epoch_seed(epoch, &da_blob_hash, &prev_committee_hash);

        // All must be identical
        assert_eq!(seed1, seed2);
        assert_eq!(seed2, seed3);

        // Seed should not be all zeros (extremely unlikely with SHA3)
        assert_ne!(seed1, [0u8; 32]);
    }

    #[test]
    fn test_epoch_seed_diff_epoch() {
        let da_blob_hash = [0xAAu8; 32];
        let prev_committee_hash = [0xBBu8; 32];

        let seed1 = derive_epoch_seed(1, &da_blob_hash, &prev_committee_hash);
        let seed2 = derive_epoch_seed(2, &da_blob_hash, &prev_committee_hash);
        let seed3 = derive_epoch_seed(u64::MAX, &da_blob_hash, &prev_committee_hash);

        // Different epochs = different seeds
        assert_ne!(seed1, seed2);
        assert_ne!(seed2, seed3);
        assert_ne!(seed1, seed3);
    }

    #[test]
    fn test_epoch_seed_diff_da_blob() {
        let epoch = 100u64;
        let prev_committee_hash = [0xBBu8; 32];

        let da_hash1 = [0x00u8; 32];
        let da_hash2 = [0x01u8; 32];
        let da_hash3 = [0xFFu8; 32];

        let seed1 = derive_epoch_seed(epoch, &da_hash1, &prev_committee_hash);
        let seed2 = derive_epoch_seed(epoch, &da_hash2, &prev_committee_hash);
        let seed3 = derive_epoch_seed(epoch, &da_hash3, &prev_committee_hash);

        // Different DA hashes = different seeds
        assert_ne!(seed1, seed2);
        assert_ne!(seed2, seed3);
        assert_ne!(seed1, seed3);
    }

    #[test]
    fn test_epoch_seed_diff_committee() {
        let epoch = 100u64;
        let da_blob_hash = [0xAAu8; 32];

        let comm_hash1 = [0x00u8; 32];
        let comm_hash2 = [0x01u8; 32];
        let comm_hash3 = [0xFFu8; 32];

        let seed1 = derive_epoch_seed(epoch, &da_blob_hash, &comm_hash1);
        let seed2 = derive_epoch_seed(epoch, &da_blob_hash, &comm_hash2);
        let seed3 = derive_epoch_seed(epoch, &da_blob_hash, &comm_hash3);

        // Different committee hashes = different seeds
        assert_ne!(seed1, seed2);
        assert_ne!(seed2, seed3);
        assert_ne!(seed1, seed3);
    }

    #[test]
    fn test_epoch_seed_edge_cases() {
        // Test with all zeros
        let seed_zeros = derive_epoch_seed(0, &[0u8; 32], &[0u8; 32]);
        assert_ne!(seed_zeros, [0u8; 32]);

        // Test with all 0xFF
        let seed_ones = derive_epoch_seed(u64::MAX, &[0xFFu8; 32], &[0xFFu8; 32]);
        assert_ne!(seed_ones, [0xFFu8; 32]);

        // Different inputs should produce different outputs
        assert_ne!(seed_zeros, seed_ones);
    }

    #[test]
    fn test_epoch_seed_ordering_matters() {
        // Verify that order of inputs matters
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];

        let seed1 = derive_epoch_seed(1, &a, &b);
        let seed2 = derive_epoch_seed(1, &b, &a); // Swapped

        // Order should matter
        assert_ne!(seed1, seed2);
    }

    #[test]
    fn test_committee_hash_deterministic() {
        let members = vec![
            make_coordinator_member(1),
            make_coordinator_member(2),
            make_coordinator_member(3),
        ];
        let group_pubkey = [0xCDu8; 32];

        let committee = CoordinatorCommittee::new(members, 2, 100, group_pubkey)
            .expect("valid committee");

        // Hash multiple times
        let hash1 = compute_committee_hash(&committee);
        let hash2 = compute_committee_hash(&committee);
        let hash3 = compute_committee_hash(&committee);

        // All must be identical
        assert_eq!(hash1, hash2);
        assert_eq!(hash2, hash3);

        // Hash should not be all zeros
        assert_ne!(hash1, [0u8; 32]);
    }

    #[test]
    fn test_committee_hash_diff_epoch() {
        let members = vec![make_coordinator_member(1)];
        let group_pubkey = [0xAAu8; 32];

        let comm1 = CoordinatorCommittee::new(members.clone(), 1, 1, group_pubkey)
            .expect("valid committee");
        let comm2 = CoordinatorCommittee::new(members.clone(), 1, 2, group_pubkey)
            .expect("valid committee");
        let comm3 = CoordinatorCommittee::new(members, 1, u64::MAX, group_pubkey)
            .expect("valid committee");

        let hash1 = compute_committee_hash(&comm1);
        let hash2 = compute_committee_hash(&comm2);
        let hash3 = compute_committee_hash(&comm3);

        // Different epochs = different hashes
        assert_ne!(hash1, hash2);
        assert_ne!(hash2, hash3);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_committee_hash_diff_threshold() {
        let members = vec![
            make_coordinator_member(1),
            make_coordinator_member(2),
            make_coordinator_member(3),
        ];
        let group_pubkey = [0xBBu8; 32];

        let comm1 = CoordinatorCommittee::new(members.clone(), 1, 1, group_pubkey)
            .expect("valid committee");
        let comm2 = CoordinatorCommittee::new(members.clone(), 2, 1, group_pubkey)
            .expect("valid committee");
        let comm3 = CoordinatorCommittee::new(members, 3, 1, group_pubkey)
            .expect("valid committee");

        let hash1 = compute_committee_hash(&comm1);
        let hash2 = compute_committee_hash(&comm2);
        let hash3 = compute_committee_hash(&comm3);

        // Different thresholds = different hashes
        assert_ne!(hash1, hash2);
        assert_ne!(hash2, hash3);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_committee_hash_diff_members() {
        let group_pubkey = [0xCCu8; 32];

        let comm1 = CoordinatorCommittee::new(
            vec![make_coordinator_member(1)],
            1,
            1,
            group_pubkey,
        ).expect("valid committee");

        let comm2 = CoordinatorCommittee::new(
            vec![make_coordinator_member(2)],
            1,
            1,
            group_pubkey,
        ).expect("valid committee");

        let comm3 = CoordinatorCommittee::new(
            vec![make_coordinator_member(1), make_coordinator_member(2)],
            1,
            1,
            group_pubkey,
        ).expect("valid committee");

        let hash1 = compute_committee_hash(&comm1);
        let hash2 = compute_committee_hash(&comm2);
        let hash3 = compute_committee_hash(&comm3);

        // Different members = different hashes
        assert_ne!(hash1, hash2);
        assert_ne!(hash2, hash3);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_committee_hash_member_order_matters() {
        let group_pubkey = [0xDDu8; 32];

        // Same members, different order
        let comm1 = CoordinatorCommittee::new(
            vec![make_coordinator_member(1), make_coordinator_member(2)],
            1,
            1,
            group_pubkey,
        ).expect("valid committee");

        let comm2 = CoordinatorCommittee::new(
            vec![make_coordinator_member(2), make_coordinator_member(1)],
            1,
            1,
            group_pubkey,
        ).expect("valid committee");

        let hash1 = compute_committee_hash(&comm1);
        let hash2 = compute_committee_hash(&comm2);

        // Order matters - different order = different hash
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_committee_hash_diff_group_pubkey() {
        let members = vec![make_coordinator_member(1)];

        let comm1 = CoordinatorCommittee::new(members.clone(), 1, 1, [0x00u8; 32])
            .expect("valid committee");
        let comm2 = CoordinatorCommittee::new(members.clone(), 1, 1, [0x01u8; 32])
            .expect("valid committee");
        let comm3 = CoordinatorCommittee::new(members, 1, 1, [0xFFu8; 32])
            .expect("valid committee");

        let hash1 = compute_committee_hash(&comm1);
        let hash2 = compute_committee_hash(&comm2);
        let hash3 = compute_committee_hash(&comm3);

        // Different group pubkeys = different hashes
        assert_ne!(hash1, hash2);
        assert_ne!(hash2, hash3);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_committee_hash_empty_members() {
        let group_pubkey = [0xEEu8; 32];

        let comm = CoordinatorCommittee::new(vec![], 0, 1, group_pubkey)
            .expect("valid committee");

        let hash = compute_committee_hash(&comm);

        // Should produce valid hash even with empty members
        assert_ne!(hash, [0u8; 32]);

        // Should be deterministic
        let hash2 = compute_committee_hash(&comm);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_epoch_seed_and_committee_hash_integration() {
        // Create a committee
        let members = vec![
            make_coordinator_member(1),
            make_coordinator_member(2),
            make_coordinator_member(3),
        ];
        let group_pubkey = [0xFFu8; 32];

        let committee = CoordinatorCommittee::new(members, 2, 1, group_pubkey)
            .expect("valid committee");

        // Compute committee hash
        let committee_hash = compute_committee_hash(&committee);

        // Use it in epoch seed derivation
        let da_blob_hash = [0x12u8; 32];
        let epoch_seed = derive_epoch_seed(2, &da_blob_hash, &committee_hash);

        // Should be valid
        assert_ne!(epoch_seed, [0u8; 32]);

        // Should be deterministic
        let committee_hash2 = compute_committee_hash(&committee);
        let epoch_seed2 = derive_epoch_seed(2, &da_blob_hash, &committee_hash2);
        assert_eq!(epoch_seed, epoch_seed2);
    }

    #[test]
    fn test_committee_hash_clone_equality() {
        let members = vec![make_coordinator_member(5)];
        let group_pubkey = [0x55u8; 32];

        let committee1 = CoordinatorCommittee::new(members.clone(), 1, 10, group_pubkey)
            .expect("valid committee");
        let committee2 = committee1.clone();

        let hash1 = compute_committee_hash(&committee1);
        let hash2 = compute_committee_hash(&committee2);

        // Cloned committees should have identical hashes
        assert_eq!(hash1, hash2);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // Committee Selection Tests (14A.2B.2.7)
    // ════════════════════════════════════════════════════════════════════════════

    fn make_validator_with_zone(seed: u8, zone: &str, stake: u64) -> ValidatorCandidate {
        let mut id = [0u8; 32];
        id[0] = seed;
        id[31] = seed.wrapping_add(1);

        let mut pubkey = [0u8; 32];
        pubkey[0] = seed.wrapping_add(100);
        pubkey[31] = seed.wrapping_add(101);

        ValidatorCandidate {
            id,
            pubkey,
            stake,
            zone: zone.to_string(),
        }
    }

    #[test]
    fn test_ensure_zone_diversity_allows_within_limit() {
        let config = SelectionConfig {
            committee_size: 9,
            threshold: 6,
            min_stake: 100,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        // Max per zone = (9 + 2) / 3 = 3
        let selected = vec![
            make_validator_with_zone(1, "zone-a", 1000),
            make_validator_with_zone(2, "zone-a", 1000),
        ];

        let candidate = make_validator_with_zone(3, "zone-a", 1000);

        // 2 existing + 1 candidate = 3, which is <= 3 (max)
        assert!(selector.ensure_zone_diversity(&selected, &candidate));
    }

    #[test]
    fn test_ensure_zone_diversity_blocks_over_limit() {
        let config = SelectionConfig {
            committee_size: 9,
            threshold: 6,
            min_stake: 100,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        // Max per zone = (9 + 2) / 3 = 3
        let selected = vec![
            make_validator_with_zone(1, "zone-a", 1000),
            make_validator_with_zone(2, "zone-a", 1000),
            make_validator_with_zone(3, "zone-a", 1000),
        ];

        let candidate = make_validator_with_zone(4, "zone-a", 1000);

        // 3 existing + 1 candidate = 4, which is > 3 (max)
        assert!(!selector.ensure_zone_diversity(&selected, &candidate));
    }

    #[test]
    fn test_ensure_zone_diversity_different_zone_allowed() {
        let config = SelectionConfig {
            committee_size: 9,
            threshold: 6,
            min_stake: 100,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        let selected = vec![
            make_validator_with_zone(1, "zone-a", 1000),
            make_validator_with_zone(2, "zone-a", 1000),
            make_validator_with_zone(3, "zone-a", 1000),
        ];

        // Different zone should be allowed
        let candidate = make_validator_with_zone(4, "zone-b", 1000);
        assert!(selector.ensure_zone_diversity(&selected, &candidate));
    }

    #[test]
    fn test_select_committee_deterministic() {
        let config = SelectionConfig {
            committee_size: 5,
            threshold: 3,
            min_stake: 100,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        let validators: Vec<ValidatorCandidate> = (0..10)
            .map(|i| make_validator_with_zone(i, &format!("zone-{}", i % 3), 1000 + (i as u64 * 100)))
            .collect();

        let seed = [0x42u8; 32];
        let epoch = 1;

        // Run 3 times - must be identical
        let committee1 = selector.select_committee(&validators, epoch, &seed).expect("selection 1");
        let committee2 = selector.select_committee(&validators, epoch, &seed).expect("selection 2");
        let committee3 = selector.select_committee(&validators, epoch, &seed).expect("selection 3");

        assert_eq!(committee1.members.len(), committee2.members.len());
        assert_eq!(committee2.members.len(), committee3.members.len());

        for i in 0..committee1.members.len() {
            assert_eq!(committee1.members[i].validator_id, committee2.members[i].validator_id);
            assert_eq!(committee2.members[i].validator_id, committee3.members[i].validator_id);
        }
    }

    #[test]
    fn test_select_committee_different_seeds_different_results() {
        let config = SelectionConfig {
            committee_size: 5,
            threshold: 3,
            min_stake: 100,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        let validators: Vec<ValidatorCandidate> = (0..10)
            .map(|i| make_validator_with_zone(i, &format!("zone-{}", i % 3), 1000 + (i as u64 * 100)))
            .collect();

        let seed1 = [0x11u8; 32];
        let seed2 = [0x22u8; 32];
        let epoch = 1;

        let committee1 = selector.select_committee(&validators, epoch, &seed1).expect("selection 1");
        let committee2 = selector.select_committee(&validators, epoch, &seed2).expect("selection 2");

        // Different seeds should produce different committees (with high probability)
        let ids1: Vec<[u8; 32]> = committee1.members.iter().map(|m| m.validator_id).collect();
        let ids2: Vec<[u8; 32]> = committee2.members.iter().map(|m| m.validator_id).collect();

        // At least one member should be different
        assert_ne!(ids1, ids2);
    }

    #[test]
    fn test_select_committee_correct_size() {
        let config = SelectionConfig {
            committee_size: 7,
            threshold: 5,
            min_stake: 100,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        let validators: Vec<ValidatorCandidate> = (0..20)
            .map(|i| make_validator_with_zone(i, &format!("zone-{}", i % 4), 1000))
            .collect();

        let seed = [0x33u8; 32];
        let committee = selector.select_committee(&validators, 1, &seed).expect("selection");

        assert_eq!(committee.members.len(), 7);
        assert_eq!(committee.threshold, 5);
    }

    #[test]
    fn test_select_committee_sorted_by_stake_descending() {
        let config = SelectionConfig {
            committee_size: 5,
            threshold: 3,
            min_stake: 100,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        let validators: Vec<ValidatorCandidate> = (0..10)
            .map(|i| make_validator_with_zone(i, &format!("zone-{}", i % 5), 100 + (i as u64 * 500)))
            .collect();

        let seed = [0x44u8; 32];
        let committee = selector.select_committee(&validators, 1, &seed).expect("selection");

        // Verify sorted by stake descending
        for i in 1..committee.members.len() {
            assert!(
                committee.members[i - 1].stake >= committee.members[i].stake,
                "members should be sorted by stake descending"
            );
        }
    }

    #[test]
    fn test_select_committee_no_duplicates() {
        let config = SelectionConfig {
            committee_size: 5,
            threshold: 3,
            min_stake: 100,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        let validators: Vec<ValidatorCandidate> = (0..10)
            .map(|i| make_validator_with_zone(i, &format!("zone-{}", i % 3), 1000))
            .collect();

        let seed = [0x55u8; 32];
        let committee = selector.select_committee(&validators, 1, &seed).expect("selection");

        // Check no duplicate validator_ids
        let mut seen = std::collections::HashSet::new();
        for member in &committee.members {
            assert!(
                seen.insert(member.validator_id),
                "duplicate validator_id found"
            );
        }
    }

    #[test]
    fn test_select_committee_respects_min_stake() {
        let config = SelectionConfig {
            committee_size: 5,
            threshold: 3,
            min_stake: 500,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        // Some validators below min_stake
        let mut validators = Vec::new();
        for i in 0..5 {
            validators.push(make_validator_with_zone(i, "zone-a", 100)); // Below min_stake
        }
        for i in 5..15 {
            validators.push(make_validator_with_zone(i, &format!("zone-{}", i % 3), 1000)); // Above min_stake
        }

        let seed = [0x66u8; 32];
        let committee = selector.select_committee(&validators, 1, &seed).expect("selection");

        // All members should have stake >= min_stake
        for member in &committee.members {
            assert!(member.stake >= 500, "member stake should be >= min_stake");
        }
    }

    #[test]
    fn test_select_committee_insufficient_validators_error() {
        let config = SelectionConfig {
            committee_size: 10,
            threshold: 7,
            min_stake: 100,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        // Only 5 validators, but need 10
        let validators: Vec<ValidatorCandidate> = (0..5)
            .map(|i| make_validator_with_zone(i, "zone-a", 1000))
            .collect();

        let seed = [0x77u8; 32];
        let result = selector.select_committee(&validators, 1, &seed);

        assert!(result.is_err());
        match result.unwrap_err() {
            SelectionError::InsufficientValidators { available, required } => {
                assert_eq!(available, 5);
                assert_eq!(required, 10);
            }
            _ => panic!("expected InsufficientValidators error"),
        }
    }

    #[test]
    fn test_select_committee_insufficient_eligible_error() {
        let config = SelectionConfig {
            committee_size: 5,
            threshold: 3,
            min_stake: 1000,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        // 10 validators but only 3 with sufficient stake
        let mut validators = Vec::new();
        for i in 0..7 {
            validators.push(make_validator_with_zone(i, "zone-a", 100)); // Below min_stake
        }
        for i in 7..10 {
            validators.push(make_validator_with_zone(i, "zone-b", 2000)); // Above min_stake
        }

        let seed = [0x88u8; 32];
        let result = selector.select_committee(&validators, 1, &seed);

        assert!(result.is_err());
        match result.unwrap_err() {
            SelectionError::InsufficientEligibleValidators { eligible, required } => {
                assert_eq!(eligible, 3);
                assert_eq!(required, 5);
            }
            _ => panic!("expected InsufficientEligibleValidators error"),
        }
    }

    #[test]
    fn test_select_committee_zone_diversity_best_effort() {
        let config = SelectionConfig {
            committee_size: 6,
            threshold: 4,
            min_stake: 100,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        // Max per zone = (6 + 2) / 3 = 2
        // Create 10 validators: 7 in zone-a, 3 in other zones
        let mut validators = Vec::new();
        for i in 0..7 {
            validators.push(make_validator_with_zone(i, "zone-a", 1000 + (i as u64 * 100)));
        }
        for i in 7..10 {
            validators.push(make_validator_with_zone(i, &format!("zone-{}", i), 1000));
        }

        let seed = [0x99u8; 32];
        let committee = selector.select_committee(&validators, 1, &seed).expect("selection");

        // Committee should be formed (fallback allows exceeding zone limit)
        assert_eq!(committee.members.len(), 6);
    }

    #[test]
    fn test_select_committee_epoch_affects_member_ids() {
        let config = SelectionConfig {
            committee_size: 3,
            threshold: 2,
            min_stake: 100,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        let validators: Vec<ValidatorCandidate> = (0..5)
            .map(|i| make_validator_with_zone(i, "zone-a", 1000))
            .collect();

        let seed = [0xAAu8; 32];

        let committee1 = selector.select_committee(&validators, 1, &seed).expect("epoch 1");
        let committee2 = selector.select_committee(&validators, 2, &seed).expect("epoch 2");

        // Same validator_ids (same seed)
        for i in 0..committee1.members.len() {
            assert_eq!(committee1.members[i].validator_id, committee2.members[i].validator_id);
        }

        // But different member_ids (different epoch)
        for i in 0..committee1.members.len() {
            assert_ne!(committee1.members[i].id, committee2.members[i].id);
        }
    }

    #[test]
    fn test_select_committee_group_pubkey_deterministic() {
        let config = SelectionConfig {
            committee_size: 4,
            threshold: 3,
            min_stake: 100,
        };
        let selector = CoordinatorSelector::new(config).expect("valid config");

        let validators: Vec<ValidatorCandidate> = (0..10)
            .map(|i| make_validator_with_zone(i, &format!("zone-{}", i % 3), 1000))
            .collect();

        let seed = [0xBBu8; 32];

        let committee1 = selector.select_committee(&validators, 1, &seed).expect("selection 1");
        let committee2 = selector.select_committee(&validators, 1, &seed).expect("selection 2");

        // group_pubkey should be deterministic
        assert_eq!(committee1.group_pubkey, committee2.group_pubkey);

        // group_pubkey should not be all zeros
        assert_ne!(committee1.group_pubkey, [0u8; 32]);
    }

    #[test]
    fn test_selection_error_display() {
        let err1 = SelectionError::InsufficientValidators {
            available: 5,
            required: 10,
        };
        assert!(err1.to_string().contains("5"));
        assert!(err1.to_string().contains("10"));

        let err2 = SelectionError::InsufficientEligibleValidators {
            eligible: 3,
            required: 7,
        };
        assert!(err2.to_string().contains("3"));
        assert!(err2.to_string().contains("7"));

        let err3 = SelectionError::CommitteeInvariant {
            threshold: 5,
            members_count: 3,
        };
        assert!(err3.to_string().contains("5"));
        assert!(err3.to_string().contains("3"));

        let err4 = SelectionError::Internal("test error".to_string());
        assert!(err4.to_string().contains("test error"));
    }
}