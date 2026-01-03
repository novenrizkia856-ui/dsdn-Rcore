//! # Governance Data Structures (13.12)
//!
//! Module ini mendefinisikan SELURUH tipe data untuk governance layer.
//! 
//! ## Karakteristik
//!
//! - **Data-only**: Tidak ada logic eksekusi
//! - **Deterministik**: Semua tipe serializable dan hashable
//! - **Consensus-visible**: Akan masuk ke state_root computation
//! - **Bootstrap Mode**: Hasil voting bersifat NON-BINDING
//!
//! ## Tipe Utama
//!
//! | Type | Fungsi |
//! |------|--------|
//! | `ProposalType` | Jenis proposal yang diizinkan |
//! | `ProposalStatus` | Lifecycle status proposal |
//! | `VoteOption` | Pilihan voting (Yes/No/Abstain) |
//! | `Proposal` | Data lengkap proposal |
//! | `Vote` | Record voting individual |
//! | `GovernanceConfig` | Konfigurasi governance system |
//!
//! ## Bootstrap Mode
//!
//! Pada bootstrap mode (`bootstrap_mode: true`):
//! - Proposal dapat diajukan
//! - Voting dapat dilakukan
//! - Hasil voting TIDAK mengeksekusi perubahan
//! - Foundation memiliki full veto power
//!
//! ## Consensus-Critical
//!
//! Semua tipe di module ini adalah consensus-critical.
//! Perubahan struktur memerlukan hard-fork.
//!
//! ## 13.13.1 — Preview Data Structures
//!
//! Struktur data untuk preview/simulasi proposal governance pada Bootstrap Mode.
//!
//! | Type | Fungsi |
//! |------|--------|
//! | `PreviewType` | Jenis preview berdasarkan proposal type |
//! | `SimulatedChange` | Representasi perubahan yang disimulasikan |
//! | `ProposalPreview` | Container lengkap hasil preview proposal |
//!
//! ### Karakteristik Preview
//!
//! - **Read-only**: Tidak mengubah state chain
//! - **Non-binding**: Tidak memicu eksekusi nyata
//! - **Simulation-only**: Digunakan untuk observasi dan analisis
//! - **Bootstrap Mode**: Aktif hanya saat governance dalam mode bootstrap
//!
//! ### Penggunaan
//!
//! Preview digunakan untuk:
//! - Menampilkan dampak proposal sebelum voting selesai
//! - Memberikan informasi kepada voter tentang perubahan yang akan terjadi
//! - Audit trail untuk governance actions
//! - Testing mekanisme governance tanpa risiko
//!
//! ## 13.13.2 — Preview Generator Methods
//!
//! Method untuk generate preview/simulasi dari setiap jenis proposal.
//!
//! | Method | Fungsi |
//! |--------|--------|
//! | `generate_proposal_preview` | Entry point untuk generate preview proposal |
//! | `preview_fee_parameter_update` | Preview perubahan fee parameter |
//! | `preview_gas_price_update` | Preview perubahan gas price |
//! | `preview_node_cost_index_update` | Preview perubahan node cost index |
//! | `preview_validator_onboarding` | Preview onboarding validator |
//! | `preview_validator_offboarding` | Preview offboarding validator |
//! | `preview_emergency_pause` | Preview emergency pause |
//!
//! ### Karakteristik Method Preview
//!
//! - **Read-only**: Semua method menggunakan `&self`, tidak ada mutasi state
//! - **Non-binding**: Hanya menghasilkan simulasi, tidak ada eksekusi nyata
//! - **Safe**: Tidak ada side-effect, aman untuk dipanggil berkali-kali
//! - **UI-friendly**: Output dalam format human-readable untuk display
//!
//! ### Penggunaan
//!
//! ```text
//! let preview = state.generate_proposal_preview(proposal_id)?;
//! // preview.simulated_changes berisi list perubahan yang akan terjadi
//! // preview.affected_addresses berisi address yang terpengaruh
//! ```
//!
//! ## 13.13.3 — Non-Binding Enforcement
//!
//! Guard eksplisit untuk memastikan governance TIDAK MENGEKSEKUSI perubahan
//! selama Bootstrap Mode aktif.
//!
//! | Method | Fungsi |
//! |--------|--------|
//! | `is_execution_allowed` | Check apakah execution diizinkan |
//! | `try_execute_proposal` | Attempt execution (SELALU GAGAL di bootstrap) |
//! | `get_bootstrap_mode_status` | Get info status bootstrap mode |
//!
//! ### Prinsip Non-Binding
//!
//! ```text
//! ⚠️ PRINSIP MUTLAK:
//!
//! "Proposal boleh PASSED, tetapi TIDAK BOLEH mengeksekusi
//!  apa pun selama bootstrap mode aktif."
//!
//! - Semua proposal PASSED tercatat di state
//! - TIDAK ADA perubahan parameter yang terjadi
//! - TIDAK ADA validator yang ter-onboard/offboard
//! - TIDAK ADA treasury yang berubah
//! - Foundation memiliki full veto power
//! ```
//!
//! ### Error Handling
//!
//! ```text
//! try_execute_proposal() akan SELALU return error:
//! - Bootstrap mode ON  → ExecutionDisabledBootstrapMode
//! - Bootstrap mode OFF → ExecutionNotImplemented (reserved future)
//! ```
//!
//! ## 13.13.4 — Governance Event Logging
//!
//! Audit trail in-memory untuk governance actions.
//!
//! | Type | Fungsi |
//! |------|--------|
//! | `GovernanceEventType` | Jenis event yang dicatat |
//! | `GovernanceEvent` | Struktur data event lengkap |
//!
//! ### Karakteristik Event Logging
//!
//! - **In-memory only**: Event TIDAK di-persist ke LMDB
//! - **Non-consensus**: Event TIDAK masuk state_root computation
//! - **Bounded**: Maksimum 1000 event disimpan (FIFO)
//! - **Read-only safe**: Query event tidak mengubah state
//!
//! ### Event yang Dicatat
//!
//! ```text
//! ProposalCreated       → Setelah proposal berhasil dibuat
//! VoteCast              → Setelah vote berhasil dicatat
//! ProposalFinalized     → Setelah proposal di-finalize
//! ProposalVetoed        → Setelah Foundation veto
//! ProposalOverridden    → Setelah Foundation override
//! PreviewGenerated      → Setelah preview di-generate
//! ExecutionAttemptBlocked → Saat try_execute_proposal gagal karena bootstrap
//! ```
//!
//! ### Penggunaan
//!
//! ```text
//! // Query 10 event terakhir
//! let events = state.get_recent_governance_events(10);
//! ```

use serde::{Serialize, Deserialize};
use crate::types::Address;
use std::collections::HashMap;

// ════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════

/// Default voting period: 7 hari dalam detik
pub const DEFAULT_VOTING_PERIOD: u64 = 604_800;

/// Default quorum percentage: 33% dari total voting power
pub const DEFAULT_QUORUM_PERCENTAGE: u8 = 33;

/// Default pass threshold: 50% YES dari total votes
pub const DEFAULT_PASS_THRESHOLD: u8 = 50;

/// Minimum deposit untuk submit proposal: 1000 NUSA (dalam smallest unit)
pub const MIN_PROPOSAL_DEPOSIT: u128 = 1_000_000_000_000;

/// Foundation address untuk genesis (hardcoded).
/// Digunakan sebagai initial foundation_address di GovernanceConfig.
/// Dapat diubah via governance di future, tapi di bootstrap mode ini adalah
/// satu-satunya address dengan veto power.
pub const FOUNDATION_ADDRESS: [u8; 20] = [
    0x6d, 0xcd, 0x67, 0x0a, 0x91, 0x5c, 0x42, 0x9e, 0xb8, 0x41,
0xf4, 0xdd, 0x10, 0x37, 0x71, 0x56, 0x14, 0x9e, 0x3f, 0xb2,
];

/// Default node cost index multiplier (basis 100 = 1.0x)
/// Digunakan saat node belum memiliki custom multiplier
pub const DEFAULT_NODE_COST_INDEX: u128 = 100;

/// Maximum governance events yang disimpan di memori (FIFO)
/// Digunakan untuk retention policy event logging
pub const MAX_GOVERNANCE_EVENTS: usize = 1000;

// ════════════════════════════════════════════════════════════════════════════
// GOVERNANCE EVENT LOGGING (13.13.4)
// ════════════════════════════════════════════════════════════════════════════

/// Jenis event governance yang dicatat untuk audit trail.
///
/// Enum ini mendefinisikan semua jenis aksi governance yang akan
/// di-log ke event buffer in-memory.
///
/// # Variants
///
/// - `ProposalCreated` - Proposal baru berhasil dibuat
/// - `VoteCast` - Vote berhasil dicatat
/// - `ProposalFinalized` - Proposal berhasil di-finalize
/// - `ProposalVetoed` - Foundation melakukan veto
/// - `ProposalOverridden` - Foundation melakukan override
/// - `PreviewGenerated` - Preview proposal di-generate
/// - `ExecutionAttemptBlocked` - Eksekusi diblokir karena bootstrap mode
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GovernanceEventType {
    /// Proposal baru berhasil dibuat
    ProposalCreated,
    /// Vote berhasil dicatat
    VoteCast,
    /// Proposal berhasil di-finalize (Passed/Rejected/Expired)
    ProposalFinalized,
    /// Foundation melakukan veto pada proposal
    ProposalVetoed,
    /// Foundation melakukan override pada hasil proposal
    ProposalOverridden,
    /// Preview proposal di-generate
    PreviewGenerated,
    /// Eksekusi proposal diblokir karena bootstrap mode aktif
    ExecutionAttemptBlocked,
}

/// Event governance untuk audit trail.
///
/// Struct ini menyimpan informasi lengkap tentang satu event governance.
/// Event disimpan di memori runtime dan TIDAK di-persist ke LMDB.
///
/// # Note
///
/// - Event TIDAK masuk state_root computation
/// - Event TIDAK memengaruhi consensus
/// - Event digunakan untuk monitoring, debugging, dan audit runtime
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GovernanceEvent {
    /// Jenis event yang terjadi
    pub event_type: GovernanceEventType,
    /// ID proposal terkait (None untuk event global)
    pub proposal_id: Option<u64>,
    /// Address yang melakukan aksi
    pub actor: Address,
    /// Unix timestamp saat event terjadi
    pub timestamp: u64,
    /// Detail event dalam format human-readable
    pub details: String,
}

// ════════════════════════════════════════════════════════════════════════════
// PREVIEW DATA STRUCTURES (13.13.1)
// ════════════════════════════════════════════════════════════════════════════

/// Representasi perubahan yang disimulasikan oleh proposal.
///
/// Struct ini menampilkan satu unit perubahan dengan format human-readable.
/// Digunakan untuk menampilkan preview kepada user sebelum voting.
///
/// # Fields
///
/// - `field_path`: Path ke field yang berubah (e.g., "governance_config.base_gas_price")
/// - `old_value_display`: String representasi nilai lama
/// - `new_value_display`: String representasi nilai baru
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SimulatedChange {
    /// Path ke field yang berubah dalam state
    pub field_path: String,
    /// Nilai lama dalam format display string
    pub old_value_display: String,
    /// Nilai baru dalam format display string
    pub new_value_display: String,
}

/// Jenis preview berdasarkan tipe proposal.
///
/// Enum ini menyimpan data spesifik untuk setiap jenis preview,
/// termasuk nilai lama dan baru yang relevan.
///
/// # Variants
///
/// Setiap variant sesuai dengan ProposalType yang ada,
/// dengan tambahan field untuk old_value agar bisa dibandingkan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PreviewType {
    /// Preview perubahan fee parameter
    FeeParameterChange {
        /// Nama parameter yang berubah
        param_name: String,
        /// Nilai parameter saat ini
        old_value: u128,
        /// Nilai parameter yang diusulkan
        new_value: u128,
    },
    /// Preview perubahan gas price
    GasPriceChange {
        /// Gas price saat ini
        old_price: u128,
        /// Gas price yang diusulkan
        new_price: u128,
    },
    /// Preview perubahan node cost index
    NodeCostIndexChange {
        /// Address node yang terpengaruh
        node: Address,
        /// Multiplier saat ini
        old_multiplier: u128,
        /// Multiplier yang diusulkan
        new_multiplier: u128,
    },
    /// Preview onboarding validator baru
    ValidatorOnboard {
        /// Address validator yang akan di-onboard
        validator: Address,
        /// Stake amount validator
        stake: u128,
    },
    /// Preview offboarding validator
    ValidatorOffboard {
        /// Address validator yang akan di-offboard
        validator: Address,
        /// Alasan offboarding
        reason: String,
    },
    /// Preview removal compliance pointer
    CompliancePointerRemoval {
        /// ID pointer yang akan dihapus
        pointer_id: u64,
    },
    /// Preview emergency pause
    EmergencyPause {
        /// Tipe pause yang akan dilakukan
        pause_type: String,
    },
}

/// Container lengkap hasil preview proposal.
///
/// Struct ini menyimpan semua informasi yang diperlukan untuk
/// menampilkan preview proposal kepada user.
///
/// # Bootstrap Mode
///
/// Pada Bootstrap Governance Mode, preview ini HANYA bersifat informatif.
/// Tidak ada eksekusi nyata yang terjadi meskipun proposal PASSED.
///
/// # Fields
///
/// - `proposal_id`: ID proposal yang di-preview
/// - `preview_type`: Jenis preview sesuai tipe proposal
/// - `simulated_changes`: List perubahan yang akan terjadi
/// - `affected_addresses`: Address yang terpengaruh oleh proposal
/// - `generated_at`: Unix timestamp saat preview di-generate
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProposalPreview {
    /// ID proposal yang di-preview
    pub proposal_id: u64,
    /// Jenis preview berdasarkan tipe proposal
    pub preview_type: PreviewType,
    /// List perubahan yang disimulasikan
    pub simulated_changes: Vec<SimulatedChange>,
    /// Address yang terpengaruh oleh proposal ini
    pub affected_addresses: Vec<Address>,
    /// Unix timestamp saat preview di-generate (detik)
    pub generated_at: u64,
}

// ════════════════════════════════════════════════════════════════════════════
// PROPOSAL TYPE
// ════════════════════════════════════════════════════════════════════════════

/// Jenis proposal yang diizinkan dalam governance.
///
/// Pada Bootstrap Mode, semua proposal bersifat preview-only.
/// Tidak ada eksekusi otomatis apapun.
///
/// # Variants
///
/// - `UpdateFeeParameter` — Preview perubahan fee parameter
/// - `UpdateGasPrice` — Preview perubahan gas base price
/// - `UpdateNodeCostIndex` — Preview update node cost multiplier
/// - `ValidatorOnboarding` — Preview onboarding validator baru
/// - `ValidatorOffboarding` — Preview offboarding validator
/// - `CompliancePointerRemoval` — Preview removal compliance pointer
/// - `EmergencyPause` — Preview emergency pause
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProposalType {
    /// Update fee parameter (preview only)
    UpdateFeeParameter {
        /// Nama parameter yang diubah (e.g., "storage_fee_percent")
        parameter_name: String,
        /// Nilai baru yang diusulkan
        new_value: u128,
    },
    /// Update gas base price (preview only)
    UpdateGasPrice {
        /// Base price baru yang diusulkan
        new_base_price: u128,
    },
    /// Update node cost index multiplier (preview only)
    UpdateNodeCostIndex {
        /// Address node yang akan diubah
        node_address: Address,
        /// Multiplier baru (basis 100 = 1.0x)
        multiplier: u128,
    },
    /// Validator onboarding (preview only)
    ValidatorOnboarding {
        /// Address validator yang akan di-onboard
        validator_address: Address,
    },
    /// Validator offboarding (preview only)
    ValidatorOffboarding {
        /// Address validator yang akan di-offboard
        validator_address: Address,
    },
    /// Compliance pointer removal (preview only)
    CompliancePointerRemoval {
        /// ID pointer yang akan dihapus
        pointer_id: u64,
    },
    /// Emergency pause (preview only)
    EmergencyPause {
        /// Tipe pause (e.g., "transfers", "staking", "all")
        pause_type: String,
    },
}

// ════════════════════════════════════════════════════════════════════════════
// PROPOSAL STATUS
// ════════════════════════════════════════════════════════════════════════════

/// Status lifecycle proposal.
///
/// # State Machine
///
/// ```text
/// Active → Passed     (quorum tercapai, majority YES)
/// Active → Rejected   (quorum tercapai, majority NO)
/// Active → Expired    (voting period habis tanpa quorum)
/// Active → Vetoed     (di-veto oleh Foundation)
/// Passed → Executed   (RESERVED - tidak digunakan di Bootstrap Mode)
/// ```
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProposalStatus {
    /// Voting sedang berlangsung
    Active,
    /// Quorum tercapai, majority vote YES
    Passed,
    /// Quorum tercapai, majority vote NO
    Rejected,
    /// Voting period habis tanpa quorum tercapai
    Expired,
    /// Di-veto oleh Foundation
    Vetoed,
    /// RESERVED untuk future: Proposal sudah dieksekusi
    /// Tidak digunakan di Bootstrap Mode
    Executed,
}

// ════════════════════════════════════════════════════════════════════════════
// VOTE OPTION
// ════════════════════════════════════════════════════════════════════════════

/// Pilihan voting untuk proposal.
///
/// Setiap voter hanya dapat memilih SATU option per proposal.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum VoteOption {
    /// Mendukung proposal
    Yes,
    /// Menolak proposal
    No,
    /// Abstain (dihitung untuk quorum, tidak untuk result)
    Abstain,
}

// ════════════════════════════════════════════════════════════════════════════
// PROPOSAL
// ════════════════════════════════════════════════════════════════════════════

/// Data lengkap proposal governance.
///
/// Struct ini menyimpan semua informasi proposal termasuk
/// metadata, voting counts, dan execution payload.
///
/// # Consensus-Critical Fields
///
/// Semua fields termasuk dalam state_root computation.
/// Perubahan struktur memerlukan hard-fork.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Proposal {
    /// Unique proposal ID (auto-increment)
    pub id: u64,
    
    /// Jenis proposal
    pub proposal_type: ProposalType,
    
    /// Address yang mengajukan proposal
    pub proposer: Address,
    
    /// Judul proposal (max 100 chars)
    pub title: String,
    
    /// Deskripsi proposal (max 1000 chars)
    pub description: String,
    
    /// Status saat ini
    pub status: ProposalStatus,
    
    /// Unix timestamp saat proposal dibuat
    pub created_at: u64,
    
    /// Unix timestamp akhir voting period
    pub voting_end: u64,
    
    /// Total QV weight vote YES
    pub yes_votes: u128,
    
    /// Total QV weight vote NO
    pub no_votes: u128,
    
    /// Total QV weight vote ABSTAIN
    pub abstain_votes: u128,
    
    /// Minimum total votes untuk proposal valid (quorum)
    pub quorum_required: u128,
    
    /// Serialized execution payload (untuk preview)
    /// Berisi data yang akan dieksekusi post-bootstrap
    pub execution_payload: Vec<u8>,
}

// ════════════════════════════════════════════════════════════════════════════
// VOTE
// ════════════════════════════════════════════════════════════════════════════

/// Record voting individual.
///
/// Setiap vote di-record dengan QV weight saat voting.
/// Weight di-snapshot saat vote cast, bukan saat finalize.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Vote {
    /// Address voter
    pub voter: Address,
    
    /// ID proposal yang di-vote
    pub proposal_id: u64,
    
    /// Pilihan vote
    pub option: VoteOption,
    
    /// QV weight saat voting (snapshot)
    pub weight: u128,
    
    /// Unix timestamp saat vote cast
    pub timestamp: u64,
}

// ════════════════════════════════════════════════════════════════════════════
// GOVERNANCE CONFIG
// ════════════════════════════════════════════════════════════════════════════

/// Konfigurasi governance system.
///
/// Dapat diubah via governance proposal (post-bootstrap).
/// Pada bootstrap mode, config bersifat fixed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GovernanceConfig {
    /// Durasi voting period dalam detik
    /// Default: 7 hari (604,800 detik)
    pub voting_period_seconds: u64,
    
    /// Percentage minimum total voting power untuk quorum
    /// Default: 33%
    pub quorum_percentage: u8,
    
    /// Percentage YES dari total votes untuk pass
    /// Default: 50%
    pub pass_threshold: u8,
    
    /// Minimum stake untuk submit proposal
    /// Default: 10,000 NUSA
    pub min_proposer_stake: u128,
    
    /// Address Foundation dengan veto power
    pub foundation_address: Address,
    
    /// Bootstrap mode flag
    /// TRUE = hasil voting non-binding, tidak ada eksekusi
    /// FALSE = hasil voting binding, eksekusi otomatis
    pub bootstrap_mode: bool,
}

impl Default for GovernanceConfig {
    fn default() -> Self {
        Self {
            voting_period_seconds: DEFAULT_VOTING_PERIOD,
            quorum_percentage: DEFAULT_QUORUM_PERCENTAGE,
            pass_threshold: DEFAULT_PASS_THRESHOLD,
            min_proposer_stake: 10_000_000_000_000, // 10,000 NUSA
            foundation_address: Address::from_bytes([0u8; 20]), // Placeholder, set di genesis
            bootstrap_mode: true, // Default: bootstrap mode aktif
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// GOVERNANCE ERROR
// ════════════════════════════════════════════════════════════════════════════

/// Error types untuk operasi governance.
///
/// Digunakan oleh logic layer di sub-tahap berikutnya.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GovernanceError {
    /// Proposer tidak memiliki stake minimum
    InsufficientStake,
    /// Proposal dengan ID tersebut tidak ditemukan
    ProposalNotFound,
    /// Proposal tidak dalam status Active
    ProposalNotActive,
    /// Voting period sudah berakhir
    VotingPeriodEnded,
    /// Voting period belum berakhir (untuk finalize)
    VotingPeriodNotEnded,
    /// Voter sudah pernah vote di proposal ini
    AlreadyVoted,
    /// Tipe proposal tidak valid
    InvalidProposalType,
    /// Judul proposal melebihi batas karakter
    TitleTooLong,
    /// Deskripsi proposal melebihi batas karakter
    DescriptionTooLong,
    /// Deposit tidak mencukupi
    InsufficientDeposit,
    /// Bukan Foundation address
    NotFoundation,
    /// Proposal sudah di-finalize
    AlreadyFinalized,
    /// Quorum tidak tercapai
    QuorumNotReached,
/// Proposal sudah di-veto
    AlreadyVetoed,
    /// Status proposal tidak valid untuk override (harus Passed atau Rejected)
    InvalidOverrideStatus,
    /// Eksekusi governance dinonaktifkan pada Bootstrap Mode
    /// Digunakan KHUSUS saat execution dicoba di bootstrap mode
    ExecutionDisabledBootstrapMode,
    /// Eksekusi belum diimplementasikan (reserved untuk future phase)
    /// Digunakan saat bootstrap_mode == false tapi execution belum ready
    ExecutionNotImplemented,
}

// ════════════════════════════════════════════════════════════════════════════
// BOOTSTRAP MODE INFO (13.13.3)
// ════════════════════════════════════════════════════════════════════════════

/// Informasi status Bootstrap Mode governance.
///
/// Struct ini menyediakan informasi lengkap tentang status bootstrap mode
/// untuk keperluan query dan display.
///
/// # Fields
///
/// - `is_active`: Apakah bootstrap mode sedang aktif
/// - `foundation_address`: Address Foundation dengan veto power
/// - `message`: Human-readable message tentang status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapModeInfo {
    /// Apakah bootstrap mode sedang aktif
    /// TRUE = governance non-binding, execution disabled
    /// FALSE = governance binding (reserved future)
    pub is_active: bool,
    /// Address Foundation yang memiliki veto power
    pub foundation_address: Address,
    /// Human-readable message tentang status bootstrap mode
    pub message: String,
}

// ════════════════════════════════════════════════════════════════════════════
// PROPOSAL RESULT (PREVIEW ONLY)
// ════════════════════════════════════════════════════════════════════════════

/// Hasil proposal untuk preview (NON-BINDING di Bootstrap Mode).
///
/// Struct ini digunakan untuk menampilkan hasil voting tanpa
/// mengeksekusi perubahan apapun.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProposalResult {
    /// ID proposal
    pub proposal_id: u64,
    /// Status final
    pub status: ProposalStatus,
    /// Total YES votes
    pub yes_votes: u128,
    /// Total NO votes
    pub no_votes: u128,
    /// Total ABSTAIN votes
    pub abstain_votes: u128,
    /// Quorum tercapai atau tidak
    pub quorum_reached: bool,
    /// Execution payload (untuk preview)
    pub execution_payload: Vec<u8>,
}

// ════════════════════════════════════════════════════════════════════════════
// CHAINSTATE GOVERNANCE METHODS (13.12.2)
// ════════════════════════════════════════════════════════════════════════════

use super::ChainState;

impl ChainState {
    /// Membuat proposal baru.
    ///
    /// # Langkah (URUT - CONSENSUS-CRITICAL)
    ///
    /// 1. Validasi proposer stake >= min_proposer_stake
    /// 2. Validasi title.len() <= 100
    /// 3. Validasi description.len() <= 1000
    /// 4. Validasi proposer balance >= MIN_PROPOSAL_DEPOSIT
    /// 5. Increment proposal_count
    /// 6. Generate proposal_id
    /// 7. Set status = Active
    /// 8. Set created_at = current_timestamp
    /// 9. Set voting_end = created_at + voting_period_seconds
    /// 10. Deduct MIN_PROPOSAL_DEPOSIT dari balance proposer
    /// 11. Simpan proposal ke self.proposals
    /// 12. Return proposal_id
    ///
    /// # Arguments
    ///
    /// * `proposer` - Address yang mengajukan proposal
    /// * `proposal_type` - Jenis proposal
    /// * `title` - Judul proposal (max 100 chars)
    /// * `description` - Deskripsi proposal (max 1000 chars)
    /// * `current_timestamp` - Unix timestamp saat ini
    ///
    /// # Returns
    ///
    /// * `Ok(proposal_id)` - ID proposal yang baru dibuat
    /// * `Err(GovernanceError)` - Error validasi
    pub fn create_proposal(
        &mut self,
        proposer: Address,
        proposal_type: ProposalType,
        title: String,
        description: String,
        current_timestamp: u64,
    ) -> Result<u64, GovernanceError> {
        // 1. Validasi proposer stake >= min_proposer_stake
        let proposer_stake = self.get_total_stake(&proposer);
        if proposer_stake < self.governance_config.min_proposer_stake {
            return Err(GovernanceError::InsufficientStake);
        }

        // 2. Validasi title.len() <= 100
        if title.len() > 100 {
            return Err(GovernanceError::TitleTooLong);
        }

        // 3. Validasi description.len() <= 1000
        if description.len() > 1000 {
            return Err(GovernanceError::DescriptionTooLong);
        }

        // 4. Validasi proposer balance >= MIN_PROPOSAL_DEPOSIT
        let proposer_balance = self.get_balance(&proposer);
        if proposer_balance < MIN_PROPOSAL_DEPOSIT {
            return Err(GovernanceError::InsufficientDeposit);
        }

        // 5. Increment proposal_count
        self.proposal_count += 1;

        // 6. Generate proposal_id
        let proposal_id = self.proposal_count;

        // 7-9. Set status, created_at, voting_end
        let voting_end = current_timestamp + self.governance_config.voting_period_seconds;

        // Calculate quorum_required based on total voting power
        let total_voting_power = self.get_total_voting_power();
        let quorum_required = (total_voting_power * self.governance_config.quorum_percentage as u128) / 100;

        // 10. Deduct MIN_PROPOSAL_DEPOSIT dari balance proposer
        *self.balances.entry(proposer).or_insert(0) -= MIN_PROPOSAL_DEPOSIT;

        // 11. Create and store proposal
        let proposal = Proposal {
            id: proposal_id,
            proposal_type,
            proposer,
            title,
            description,
            status: ProposalStatus::Active,
            created_at: current_timestamp,
            voting_end,
            yes_votes: 0,
            no_votes: 0,
            abstain_votes: 0,
            quorum_required,
            execution_payload: vec![],
        };

    self.proposals.insert(proposal_id, proposal);

        // 12. Log event
        self.log_governance_event(GovernanceEvent {
            event_type: GovernanceEventType::ProposalCreated,
            proposal_id: Some(proposal_id),
            actor: proposer,
            timestamp: current_timestamp,
            details: format!("Proposal {} created", proposal_id),
        });

        // 13. Return proposal_id
        Ok(proposal_id)
    }

    /// Get proposal by ID.
    ///
    /// # Arguments
    ///
    /// * `id` - Proposal ID
    ///
    /// # Returns
    ///
    /// * `Some(&Proposal)` - Reference ke proposal
    /// * `None` - Proposal tidak ditemukan
    pub fn get_proposal(&self, id: u64) -> Option<&Proposal> {
        self.proposals.get(&id)
    }

    /// Get semua proposal dengan status Active.
    ///
    /// # Returns
    ///
    /// * `Vec<&Proposal>` - List proposal aktif
    pub fn get_active_proposals(&self) -> Vec<&Proposal> {
        self.proposals
            .values()
            .filter(|p| p.status == ProposalStatus::Active)
            .collect()
    }

    /// Finalize proposal setelah voting period berakhir.
    ///
    /// # Langkah (URUT - CONSENSUS-CRITICAL)
    ///
    /// 1. Pastikan proposal ada
    /// 2. Pastikan status = Active
    /// 3. Pastikan current_timestamp >= voting_end
    /// 4. Hitung total_votes = yes + no + abstain
    /// 5. Validasi quorum: total_votes >= quorum_required
    /// 6. Tentukan hasil: yes > no → Passed, else → Rejected
    /// 7. Update status
    /// 8. Refund deposit ke proposer
    /// 9. Return status final
    ///
    /// # Arguments
    ///
    /// * `id` - Proposal ID
    /// * `current_timestamp` - Unix timestamp saat ini
    ///
    /// # Returns
    ///
    /// * `Ok(ProposalStatus)` - Status final proposal
    /// * `Err(GovernanceError)` - Error validasi
    pub fn finalize_proposal(
        &mut self,
        id: u64,
        current_timestamp: u64,
    ) -> Result<ProposalStatus, GovernanceError> {
        // 1. Pastikan proposal ada
        let proposal = self.proposals.get(&id)
            .ok_or(GovernanceError::ProposalNotFound)?;

        // 2. Pastikan status = Active
        if proposal.status != ProposalStatus::Active {
            return Err(GovernanceError::ProposalNotActive);
        }

        // 3. Pastikan current_timestamp >= voting_end
        if current_timestamp < proposal.voting_end {
            return Err(GovernanceError::VotingPeriodNotEnded);
        }

        // Get proposer for refund
        let proposer = proposal.proposer;

        // 4. Hitung total_votes
        let total_votes = proposal.yes_votes + proposal.no_votes + proposal.abstain_votes;

        // 5. Validasi quorum
        let quorum_reached = total_votes >= proposal.quorum_required;

        // 6. Tentukan hasil
        let final_status = if !quorum_reached {
            ProposalStatus::Expired
        } else if proposal.yes_votes > proposal.no_votes {
            ProposalStatus::Passed
        } else {
            ProposalStatus::Rejected
        };

    // 7. Update status (re-borrow as mutable)
        if let Some(p) = self.proposals.get_mut(&id) {
            p.status = final_status;
        }

        // 8. Refund deposit ke proposer
        *self.balances.entry(proposer).or_insert(0) += MIN_PROPOSAL_DEPOSIT;

        // 9. Log event
        self.log_governance_event(GovernanceEvent {
            event_type: GovernanceEventType::ProposalFinalized,
            proposal_id: Some(id),
            actor: proposer,
            timestamp: current_timestamp,
            details: format!("Proposal {} finalized with status {:?}", id, final_status),
        });

        // 10. Return status final
        Ok(final_status)
    }

    /// Get hasil proposal untuk preview (NON-BINDING).
    ///
    /// Method ini tidak mengubah state apapun.
    ///
    /// # Arguments
    ///
    /// * `id` - Proposal ID
    ///
    /// # Returns
    ///
    /// * `Some(ProposalResult)` - Hasil preview
    /// * `None` - Proposal tidak ditemukan
    pub fn get_proposal_result(&self, id: u64) -> Option<ProposalResult> {
        let proposal = self.proposals.get(&id)?;

        let total_votes = proposal.yes_votes + proposal.no_votes + proposal.abstain_votes;
        let quorum_reached = total_votes >= proposal.quorum_required;

        Some(ProposalResult {
            proposal_id: proposal.id,
            status: proposal.status,
            yes_votes: proposal.yes_votes,
            no_votes: proposal.no_votes,
            abstain_votes: proposal.abstain_votes,
            quorum_reached,
            execution_payload: proposal.execution_payload.clone(),
        })
    }

    /// Get total stake untuk address (validator stake + delegator stake).
    ///
    /// Helper method untuk validasi proposer stake.
    fn get_total_stake(&self, addr: &Address) -> u128 {
        let validator_stake = self.validator_stakes.get(addr).copied().unwrap_or(0);
        let delegator_stake = self.delegator_stakes.get(addr).copied().unwrap_or(0);
        validator_stake + delegator_stake
    }

    /// Get total voting power dari semua QV weights.
    ///
    /// Helper method untuk calculate quorum_required.
    fn get_total_voting_power(&self) -> u128 {
        self.qv_weights.values().sum()
    }

    // ════════════════════════════════════════════════════════════════════════════
    // VOTING MECHANISM (13.12.3)
    // ════════════════════════════════════════════════════════════════════════════

    /// Cast vote untuk proposal.
    ///
    /// # Langkah (URUT - CONSENSUS-CRITICAL)
    ///
    /// 1. Pastikan proposal ada
    /// 2. Pastikan status proposal = Active
    /// 3. Pastikan current_timestamp < voting_end
    /// 4. Pastikan voter belum pernah vote pada proposal ini
    /// 5. Ambil voting weight dari qv_weights (SNAPSHOT)
    /// 6. Buat struct Vote
    /// 7. Simpan vote ke proposal_votes
    /// 8. Update tally proposal
    /// 9. Return Ok(())
    ///
    /// # Arguments
    ///
    /// * `voter` - Address yang voting
    /// * `proposal_id` - ID proposal
    /// * `option` - Pilihan vote (Yes/No/Abstain)
    /// * `current_timestamp` - Unix timestamp saat ini
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Vote berhasil
    /// * `Err(GovernanceError)` - Error validasi
    pub fn cast_vote(
        &mut self,
        voter: Address,
        proposal_id: u64,
        option: VoteOption,
        current_timestamp: u64,
    ) -> Result<(), GovernanceError> {
        // 1. Pastikan proposal ada
        let proposal = self.proposals.get(&proposal_id)
            .ok_or(GovernanceError::ProposalNotFound)?;

        // 2. Pastikan status proposal = Active
        if proposal.status != ProposalStatus::Active {
            return Err(GovernanceError::ProposalNotActive);
        }

        // 3. Pastikan current_timestamp < voting_end
        if current_timestamp >= proposal.voting_end {
            return Err(GovernanceError::VotingPeriodEnded);
        }

        // 4. Pastikan voter belum pernah vote pada proposal ini
        if self.has_voted(voter, proposal_id) {
            return Err(GovernanceError::AlreadyVoted);
        }

        // 5. Ambil voting weight dari qv_weights (SNAPSHOT)
        let weight = self.qv_weights.get(&voter).copied().unwrap_or(0);

        // 6. Buat struct Vote
        let vote = Vote {
            voter,
            proposal_id,
            option,
            weight,
            timestamp: current_timestamp,
        };

        // 7. Simpan vote ke proposal_votes
        self.proposal_votes
            .entry(proposal_id)
            .or_insert_with(HashMap::new)
            .insert(voter, vote);

        // 8. Update tally proposal
        if let Some(p) = self.proposals.get_mut(&proposal_id) {
            match option {
                VoteOption::Yes => p.yes_votes += weight,
                VoteOption::No => p.no_votes += weight,
                VoteOption::Abstain => p.abstain_votes += weight,
            }
        }

        // 9. Log event
        self.log_governance_event(GovernanceEvent {
            event_type: GovernanceEventType::VoteCast,
            proposal_id: Some(proposal_id),
            actor: voter,
            timestamp: current_timestamp,
            details: format!("Vote {:?} cast on proposal {} with weight {}", option, proposal_id, weight),
        });

        // 10. Return Ok(())
        Ok(())
    }

    /// Get voting weight untuk voter.
    ///
    /// Mengambil QV weight dari qv_weights HashMap.
    /// Returns 0 untuk address tanpa stake.
    ///
    /// # Arguments
    ///
    /// * `voter` - Address voter
    ///
    /// # Returns
    ///
    /// * `u128` - Voting weight (sqrt of stake)
    pub fn get_voter_weight(&self, voter: Address) -> u128 {
        self.qv_weights.get(&voter).copied().unwrap_or(0)
    }

    /// Check apakah voter sudah vote pada proposal.
    ///
    /// # Arguments
    ///
    /// * `voter` - Address voter
    /// * `proposal_id` - ID proposal
    ///
    /// # Returns
    ///
    /// * `true` - Voter sudah vote
    /// * `false` - Voter belum vote
    pub fn has_voted(&self, voter: Address, proposal_id: u64) -> bool {
        self.proposal_votes
            .get(&proposal_id)
            .map(|votes| votes.contains_key(&voter))
            .unwrap_or(false)
    }

    /// Get semua votes untuk proposal.
    ///
    /// # Arguments
    ///
    /// * `proposal_id` - ID proposal
    ///
    /// # Returns
    ///
    /// * `Vec<&Vote>` - List semua votes
    pub fn get_proposal_votes(&self, proposal_id: u64) -> Vec<&Vote> {
        self.proposal_votes
            .get(&proposal_id)
            .map(|votes| votes.values().collect())
            .unwrap_or_default()
    }

    /// Calculate quorum untuk proposal.
    ///
    /// Formula: (total_voting_power * quorum_percentage) / 100
    ///
    /// # Arguments
    ///
    /// * `proposal_id` - ID proposal (untuk consistency check)
    ///
    /// # Returns
    ///
    /// * `u128` - Quorum threshold
pub fn calculate_quorum(&self, _proposal_id: u64) -> u128 {
        let total_voting_power = self.get_total_voting_power();
        (total_voting_power * self.governance_config.quorum_percentage as u128) / 100
    }

    // ════════════════════════════════════════════════════════════════════════════
    // FOUNDATION CONTROLS (13.12.4)
    // ════════════════════════════════════════════════════════════════════════════

    /// Veto proposal oleh Foundation.
    ///
    /// # Validasi (URUT - CONSENSUS-CRITICAL)
    ///
    /// 1. foundation_address == governance_config.foundation_address
    /// 2. Proposal ada
    /// 3. proposal.status != Vetoed
    ///
    /// # Aksi
    ///
    /// * Set proposal.status = ProposalStatus::Vetoed
    /// * Refund deposit ke proposer
    ///
    /// # Arguments
    ///
    /// * `foundation_address` - Address yang melakukan veto
    /// * `proposal_id` - ID proposal yang akan di-veto
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Veto berhasil
    /// * `Err(GovernanceError)` - Error validasi
    pub fn veto_proposal(
        &mut self,
        foundation_address: Address,
        proposal_id: u64,
    ) -> Result<(), GovernanceError> {
        // 1. Validasi foundation_address
        if foundation_address != self.governance_config.foundation_address {
            return Err(GovernanceError::NotFoundation);
        }

        // 2. Pastikan proposal ada
        let proposal = self.proposals.get(&proposal_id)
            .ok_or(GovernanceError::ProposalNotFound)?;

        // 3. Pastikan belum di-veto
        if proposal.status == ProposalStatus::Vetoed {
            return Err(GovernanceError::AlreadyVetoed);
        }

        // Get proposer untuk refund
        let proposer = proposal.proposer;

    // Set status = Vetoed
        if let Some(p) = self.proposals.get_mut(&proposal_id) {
            p.status = ProposalStatus::Vetoed;
        }

        // Refund deposit ke proposer
        *self.balances.entry(proposer).or_insert(0) += MIN_PROPOSAL_DEPOSIT;

        // Log event
        self.log_governance_event(GovernanceEvent {
            event_type: GovernanceEventType::ProposalVetoed,
            proposal_id: Some(proposal_id),
            actor: foundation_address,
            timestamp: 0, // Timestamp not available in this context, will be filled by caller
            details: format!("Proposal {} vetoed by Foundation", proposal_id),
        });

        Ok(())
    }

    /// Override hasil proposal oleh Foundation.
    ///
    /// # Validasi (URUT - CONSENSUS-CRITICAL)
    ///
    /// 1. foundation_address == governance_config.foundation_address
    /// 2. Proposal ada
    /// 3. proposal.status == Passed ATAU Rejected
    ///
    /// # Aksi
    ///
    /// * Override status ke new_status
    /// * Di Bootstrap Mode: Passed → Vetoed diizinkan
    ///
    /// # Arguments
    ///
    /// * `foundation_address` - Address yang melakukan override
    /// * `proposal_id` - ID proposal yang akan di-override
    /// * `new_status` - Status baru
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Override berhasil
    /// * `Err(GovernanceError)` - Error validasi
    pub fn override_proposal_result(
        &mut self,
        foundation_address: Address,
        proposal_id: u64,
        new_status: ProposalStatus,
    ) -> Result<(), GovernanceError> {
        // 1. Validasi foundation_address
        if foundation_address != self.governance_config.foundation_address {
            return Err(GovernanceError::NotFoundation);
        }

        // 2. Pastikan proposal ada
        let proposal = self.proposals.get(&proposal_id)
            .ok_or(GovernanceError::ProposalNotFound)?;

        // 3. Pastikan status == Passed atau Rejected
        let current_status = proposal.status;
        if current_status != ProposalStatus::Passed && current_status != ProposalStatus::Rejected {
            return Err(GovernanceError::InvalidOverrideStatus);
        }

        // Override status
        if let Some(p) = self.proposals.get_mut(&proposal_id) {
            p.status = new_status;
        }

        // Log event
        self.log_governance_event(GovernanceEvent {
            event_type: GovernanceEventType::ProposalOverridden,
            proposal_id: Some(proposal_id),
            actor: foundation_address,
            timestamp: 0, // Timestamp not available in this context
            details: format!("Proposal {} overridden from {:?} to {:?}", proposal_id, current_status, new_status),
        });

        Ok(())
    }

    /// Set foundation address baru.
    ///
    /// # Validasi
    ///
    /// * current_foundation == governance_config.foundation_address
    ///
    /// # Aksi
    ///
    /// * Update governance_config.foundation_address = new_address
    ///
    /// # Arguments
    ///
    /// * `current_foundation` - Address foundation saat ini (untuk validasi)
    /// * `new_address` - Address foundation baru
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Update berhasil
    /// * `Err(GovernanceError)` - Error validasi
    pub fn set_foundation_address(
        &mut self,
        current_foundation: Address,
        new_address: Address,
    ) -> Result<(), GovernanceError> {
        // Validasi current_foundation
        if current_foundation != self.governance_config.foundation_address {
            return Err(GovernanceError::NotFoundation);
        }

        // Update foundation_address
        self.governance_config.foundation_address = new_address;

        Ok(())
    }

    /// Check apakah address adalah Foundation.
    ///
    /// # Arguments
    ///
    /// * `address` - Address yang dicek
    ///
    /// # Returns
    ///
    /// * `true` - Address adalah Foundation
    /// * `false` - Address bukan Foundation
/// Check apakah address adalah Foundation.
    ///
    /// # Arguments
    ///
    /// * `address` - Address yang dicek
    ///
    /// # Returns
    ///
    /// * `true` - Address adalah Foundation
    /// * `false` - Address bukan Foundation
    pub fn is_foundation(&self, address: Address) -> bool {
        address == self.governance_config.foundation_address
    }

    // ════════════════════════════════════════════════════════════════════════════
    // PREVIEW GENERATOR METHODS (13.13.2)
    // ════════════════════════════════════════════════════════════════════════════

    /// Generate preview untuk proposal.
    ///
    /// Method ini membaca proposal dari state dan menghasilkan preview
    /// tanpa mengubah state apapun.
    ///
    /// # Arguments
    ///
    /// * `proposal_id` - ID proposal yang akan di-preview
    ///
    /// # Returns
    ///
    /// * `Ok(ProposalPreview)` - Preview lengkap proposal
    /// * `Err(GovernanceError::ProposalNotFound)` - Proposal tidak ditemukan
    ///
    /// # Note
    ///
    /// Method ini bersifat READ-ONLY dan tidak mengubah state.
    pub fn generate_proposal_preview(
        &self,
        proposal_id: u64,
    ) -> Result<ProposalPreview, GovernanceError> {
        // Ambil proposal dari state
        let proposal = self.proposals.get(&proposal_id)
            .ok_or(GovernanceError::ProposalNotFound)?;

        // Generate preview berdasarkan tipe proposal
        let (preview_type, simulated_changes, affected_addresses) = 
            match &proposal.proposal_type {
                ProposalType::UpdateFeeParameter { parameter_name, new_value } => {
                    let change = self.preview_fee_parameter_update(parameter_name, *new_value);
                    let preview_type = PreviewType::FeeParameterChange {
                        param_name: parameter_name.clone(),
                        old_value: self.get_fee_parameter_value(parameter_name),
                        new_value: *new_value,
                    };
                    (preview_type, vec![change], vec![])
                }
                ProposalType::UpdateGasPrice { new_base_price } => {
                    let change = self.preview_gas_price_update(*new_base_price);
                    let old_price = self.get_current_gas_price();
                    let preview_type = PreviewType::GasPriceChange {
                        old_price,
                        new_price: *new_base_price,
                    };
                    (preview_type, vec![change], vec![])
                }
                ProposalType::UpdateNodeCostIndex { node_address, multiplier } => {
                    let change = self.preview_node_cost_index_update(*node_address, *multiplier);
                    let old_multiplier = self.node_cost_index
                        .get(node_address)
                        .copied()
                        .unwrap_or(DEFAULT_NODE_COST_INDEX);
                    let preview_type = PreviewType::NodeCostIndexChange {
                        node: *node_address,
                        old_multiplier,
                        new_multiplier: *multiplier,
                    };
                    (preview_type, vec![change], vec![*node_address])
                }
                ProposalType::ValidatorOnboarding { validator_address } => {
                    let changes = self.preview_validator_onboarding(*validator_address);
                    let stake = self.validator_stakes
                        .get(validator_address)
                        .copied()
                        .unwrap_or(0);
                    let preview_type = PreviewType::ValidatorOnboard {
                        validator: *validator_address,
                        stake,
                    };
                    (preview_type, changes, vec![*validator_address])
                }
                ProposalType::ValidatorOffboarding { validator_address } => {
                    let changes = self.preview_validator_offboarding(*validator_address);
                    let preview_type = PreviewType::ValidatorOffboard {
                        validator: *validator_address,
                        reason: "Governance proposal offboarding".to_string(),
                    };
                    (preview_type, changes, vec![*validator_address])
                }
                ProposalType::CompliancePointerRemoval { pointer_id } => {
                    let change = SimulatedChange {
                        field_path: format!("compliance_pointers.{}", pointer_id),
                        old_value_display: "exists".to_string(),
                        new_value_display: "removed".to_string(),
                    };
                    let preview_type = PreviewType::CompliancePointerRemoval {
                        pointer_id: *pointer_id,
                    };
                    (preview_type, vec![change], vec![])
                }
                ProposalType::EmergencyPause { pause_type } => {
                    let changes = self.preview_emergency_pause(pause_type);
                    let preview_type = PreviewType::EmergencyPause {
                        pause_type: pause_type.clone(),
                    };
                    (preview_type, changes, vec![])
                }
            };

        // Build ProposalPreview
        Ok(ProposalPreview {
            proposal_id,
            preview_type,
            simulated_changes,
            affected_addresses,
            generated_at: proposal.created_at, // Use proposal creation time as reference
        })
    }

    /// Preview perubahan fee parameter.
    ///
    /// # Arguments
    ///
    /// * `param_name` - Nama parameter yang akan diubah
    /// * `new_value` - Nilai baru yang diusulkan
    ///
    /// # Returns
    ///
    /// * `SimulatedChange` - Representasi perubahan
    ///
    /// # Note
    ///
    /// Method ini READ-ONLY, tidak mengubah governance_config.
    fn preview_fee_parameter_update(
        &self,
        param_name: &str,
        new_value: u128,
    ) -> SimulatedChange {
        let old_value = self.get_fee_parameter_value(param_name);
        
        SimulatedChange {
            field_path: format!("governance_config.{}", param_name),
            old_value_display: old_value.to_string(),
            new_value_display: new_value.to_string(),
        }
    }

    /// Get current fee parameter value by name.
    ///
    /// Helper method untuk membaca nilai parameter dari governance_config.
    fn get_fee_parameter_value(&self, param_name: &str) -> u128 {
        match param_name {
            "voting_period_seconds" => self.governance_config.voting_period_seconds as u128,
            "quorum_percentage" => self.governance_config.quorum_percentage as u128,
            "pass_threshold" => self.governance_config.pass_threshold as u128,
            "min_proposer_stake" => self.governance_config.min_proposer_stake,
            _ => 0, // Unknown parameter
        }
    }

    /// Preview perubahan gas price.
    ///
    /// # Arguments
    ///
    /// * `new_price` - Gas price baru yang diusulkan
    ///
    /// # Returns
    ///
    /// * `SimulatedChange` - Representasi perubahan
    ///
    /// # Note
    ///
    /// Method ini READ-ONLY.
    fn preview_gas_price_update(
        &self,
        new_price: u128,
    ) -> SimulatedChange {
        let old_price = self.get_current_gas_price();
        
        SimulatedChange {
            field_path: "runtime.base_gas_price".to_string(),
            old_value_display: old_price.to_string(),
            new_value_display: new_price.to_string(),
        }
    }

    /// Get current gas price.
    ///
    /// Helper method untuk membaca gas price saat ini.
    /// Jika belum diset, return default value.
    fn get_current_gas_price(&self) -> u128 {
        // Gas price tidak disimpan di ChainState secara eksplisit
        // Default gas price adalah 1 (minimal unit)
        1
    }

    /// Preview perubahan node cost index.
    ///
    /// # Arguments
    ///
    /// * `node` - Address node yang akan diubah
    /// * `new_multiplier` - Multiplier baru yang diusulkan
    ///
    /// # Returns
    ///
    /// * `SimulatedChange` - Representasi perubahan
    ///
    /// # Note
    ///
    /// Method ini READ-ONLY, tidak mengubah node_cost_index.
    fn preview_node_cost_index_update(
        &self,
        node: Address,
        new_multiplier: u128,
    ) -> SimulatedChange {
        let old_multiplier = self.node_cost_index
            .get(&node)
            .copied()
            .unwrap_or(DEFAULT_NODE_COST_INDEX);
        
        SimulatedChange {
            field_path: format!("node_cost_index.{:?}", node),
            old_value_display: old_multiplier.to_string(),
            new_value_display: new_multiplier.to_string(),
        }
    }

    /// Preview validator onboarding.
    ///
    /// Mensimulasikan penambahan validator ke validator_set.
    ///
    /// # Arguments
    ///
    /// * `validator` - Address validator yang akan di-onboard
    ///
    /// # Returns
    ///
    /// * `Vec<SimulatedChange>` - List perubahan yang akan terjadi
    ///
    /// # Note
    ///
    /// Method ini READ-ONLY, tidak menambah validator ke state.
    fn preview_validator_onboarding(
        &self,
        validator: Address,
    ) -> Vec<SimulatedChange> {
        let current_validator_count = self.validator_set.validators.len();
        let current_total_stake = self.validator_set.total_stake();
        
        // Get stake yang akan ditambahkan (jika sudah ada di validator_stakes)
        let new_stake = self.validator_stakes
            .get(&validator)
            .copied()
            .unwrap_or(0);
        
        vec![
            SimulatedChange {
                field_path: "validator_set.total_validators".to_string(),
                old_value_display: current_validator_count.to_string(),
                new_value_display: (current_validator_count + 1).to_string(),
            },
            SimulatedChange {
                field_path: "validator_set.total_stake".to_string(),
                old_value_display: current_total_stake.to_string(),
                new_value_display: (current_total_stake + new_stake).to_string(),
            },
            SimulatedChange {
                field_path: format!("validator_set.validators.{:?}", validator),
                old_value_display: "not_registered".to_string(),
                new_value_display: "active".to_string(),
            },
        ]
    }

    /// Preview validator offboarding.
    ///
    /// Mensimulasikan penghapusan validator dari validator_set.
    ///
    /// # Arguments
    ///
    /// * `validator` - Address validator yang akan di-offboard
    ///
    /// # Returns
    ///
    /// * `Vec<SimulatedChange>` - List perubahan yang akan terjadi
    ///
    /// # Note
    ///
    /// Method ini READ-ONLY, tidak menghapus validator dari state.
    fn preview_validator_offboarding(
        &self,
        validator: Address,
    ) -> Vec<SimulatedChange> {
        let current_validator_count = self.validator_set.validators.len();
        let current_total_stake = self.validator_set.total_stake();
        
        // Get stake validator yang akan dihapus
        let validator_stake = self.validator_stakes
            .get(&validator)
            .copied()
            .unwrap_or(0);
        
        // Check if validator exists
        let validator_exists = self.validator_set.get(&validator).is_some();
        
        let mut changes = vec![
            SimulatedChange {
                field_path: format!("validator_set.validators.{:?}", validator),
                old_value_display: if validator_exists { "active".to_string() } else { "not_found".to_string() },
                new_value_display: "removed".to_string(),
            },
        ];
        
        if validator_exists {
            changes.push(SimulatedChange {
                field_path: "validator_set.total_validators".to_string(),
                old_value_display: current_validator_count.to_string(),
                new_value_display: current_validator_count.saturating_sub(1).to_string(),
            });
            changes.push(SimulatedChange {
                field_path: "validator_set.total_stake".to_string(),
                old_value_display: current_total_stake.to_string(),
                new_value_display: current_total_stake.saturating_sub(validator_stake).to_string(),
            });
        }
        
        changes
    }

    /// Preview emergency pause.
    ///
    /// Mensimulasikan efek dari emergency pause.
    ///
    /// # Arguments
    ///
    /// * `pause_type` - Tipe pause (e.g., "transfers", "staking", "all")
    ///
    /// # Returns
    ///
    /// * `Vec<SimulatedChange>` - List perubahan yang akan terjadi
    ///
    /// # Note
    ///
    /// Method ini READ-ONLY, tidak mengubah flag pause apapun.
    fn preview_emergency_pause(
        &self,
        pause_type: &str,
    ) -> Vec<SimulatedChange> {
        match pause_type {
            "transfers" => vec![
                SimulatedChange {
                    field_path: "runtime.pause.transfers".to_string(),
                    old_value_display: "false".to_string(),
                    new_value_display: "true".to_string(),
                },
            ],
            "staking" => vec![
                SimulatedChange {
                    field_path: "runtime.pause.staking".to_string(),
                    old_value_display: "false".to_string(),
                    new_value_display: "true".to_string(),
                },
            ],
            "compute" => vec![
                SimulatedChange {
                    field_path: "runtime.pause.compute".to_string(),
                    old_value_display: "false".to_string(),
                    new_value_display: "true".to_string(),
                },
            ],
            "storage" => vec![
                SimulatedChange {
                    field_path: "runtime.pause.storage".to_string(),
                    old_value_display: "false".to_string(),
                    new_value_display: "true".to_string(),
                },
            ],
            "all" => vec![
                SimulatedChange {
                    field_path: "runtime.pause.transfers".to_string(),
                    old_value_display: "false".to_string(),
                    new_value_display: "true".to_string(),
                },
                SimulatedChange {
                    field_path: "runtime.pause.staking".to_string(),
                    old_value_display: "false".to_string(),
                    new_value_display: "true".to_string(),
                },
                SimulatedChange {
                    field_path: "runtime.pause.compute".to_string(),
                    old_value_display: "false".to_string(),
                    new_value_display: "true".to_string(),
                },
                SimulatedChange {
                    field_path: "runtime.pause.storage".to_string(),
                    old_value_display: "false".to_string(),
                    new_value_display: "true".to_string(),
                },
            ],
            _ => vec![
                SimulatedChange {
                    field_path: format!("runtime.pause.{}", pause_type),
                    old_value_display: "false".to_string(),
                    new_value_display: "true".to_string(),
                },
            ],
}
    }

    // ════════════════════════════════════════════════════════════════════════════
    // NON-BINDING ENFORCEMENT (13.13.3)
    // ════════════════════════════════════════════════════════════════════════════

    /// Check apakah execution governance diizinkan.
    ///
    /// # Returns
    ///
    /// * `true` - Execution diizinkan (bootstrap_mode == false)
    /// * `false` - Execution TIDAK diizinkan (bootstrap_mode == true)
    ///
    /// # Note
    ///
    /// Pada Bootstrap Mode, method ini SELALU return `false`.
    /// Ini adalah guard eksplisit untuk mencegah execution.
    pub fn is_execution_allowed(&self) -> bool {
        !self.governance_config.bootstrap_mode
    }

    /// Attempt execution proposal.
    ///
    /// # PERINGATAN MUTLAK
    ///
    /// Method ini adalah GUARD, BUKAN executor.
    /// Di versi saat ini, method ini SELALU GAGAL:
    /// - Bootstrap mode ON  → ExecutionDisabledBootstrapMode
    /// - Bootstrap mode OFF → ExecutionNotImplemented
    ///
    /// # Arguments
    ///
    /// * `proposal_id` - ID proposal yang akan dieksekusi
    ///
    /// # Returns
    ///
    /// * `Err(GovernanceError::ExecutionDisabledBootstrapMode)` - Bootstrap mode aktif
    /// * `Err(GovernanceError::ExecutionNotImplemented)` - Execution belum ready
    ///
    /// # Note
    ///
    /// Execution akan diimplementasikan di fase future setelah:
    /// - Bootstrap mode dinonaktifkan
    /// - Smart contract layer ready
    /// - Network sudah mature
   pub fn try_execute_proposal(
        &mut self,
        proposal_id: u64,
    ) -> Result<(), GovernanceError> {
        // GUARD 1: Check bootstrap mode
        if !self.is_execution_allowed() {
            // Log blocked execution attempt
            self.log_governance_event(GovernanceEvent {
                event_type: GovernanceEventType::ExecutionAttemptBlocked,
                proposal_id: Some(proposal_id),
                actor: Address::from_bytes([0u8; 20]), // No specific actor for system guard
                timestamp: 0, // Timestamp not available in this context
                details: format!("Execution attempt for proposal {} blocked: bootstrap mode active", proposal_id),
            });
            
            // Bootstrap mode aktif - execution DILARANG
            return Err(GovernanceError::ExecutionDisabledBootstrapMode);
        }

        // GUARD 2: Verify proposal exists
        let _proposal = self.proposals.get(&proposal_id)
            .ok_or(GovernanceError::ProposalNotFound)?;

        // RESERVED FOR FUTURE PHASE:
        // Execution logic akan diimplementasikan setelah:
        // 1. Bootstrap mode dinonaktifkan
        // 2. Smart contract execution layer ready
        // 3. Network sudah sufficiently decentralized
        //
        // Untuk saat ini, bahkan jika bootstrap_mode == false,
        // execution tetap tidak diimplementasikan.
        Err(GovernanceError::ExecutionNotImplemented)
    }

    /// Get informasi status Bootstrap Mode.
    ///
    /// Method ini menyediakan informasi lengkap tentang status bootstrap mode
    /// untuk keperluan query, display, dan audit.
    ///
    /// # Returns
    ///
    /// * `BootstrapModeInfo` - Struct berisi status lengkap
    ///
    /// # Note
    ///
    /// Method ini READ-ONLY, tidak mengubah state.
    pub fn get_bootstrap_mode_status(&self) -> BootstrapModeInfo {
        let is_active = self.governance_config.bootstrap_mode;
        let foundation_address = self.governance_config.foundation_address;
        
        let message = if is_active {
            "Bootstrap mode aktif: governance bersifat non-binding. Proposal PASSED tidak mengeksekusi perubahan.".to_string()
        } else {
            "Bootstrap mode nonaktif: governance binding (execution reserved for future implementation).".to_string()
        };
BootstrapModeInfo {
            is_active,
            foundation_address,
            message,
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // GOVERNANCE EVENT LOGGING (13.13.4)
    // ════════════════════════════════════════════════════════════════════════════

    /// Log governance event ke buffer in-memory.
    ///
    /// Method ini menambahkan event ke governance_events vector dengan
    /// retention policy: hanya MAX_GOVERNANCE_EVENTS terakhir yang disimpan.
    ///
    /// # Arguments
    ///
    /// * `event` - Event yang akan dicatat
    ///
    /// # Note
    ///
    /// - Event TIDAK di-persist ke LMDB
    /// - Event TIDAK masuk state_root
    /// - Event TIDAK memengaruhi consensus
    /// - Jika buffer penuh, event tertua dihapus (FIFO)
    pub fn log_governance_event(&mut self, event: GovernanceEvent) {
        // Tambah event ke vector
        self.governance_events.push(event);
        
        // Enforce retention policy: hapus event tertua jika melebihi limit
        while self.governance_events.len() > MAX_GOVERNANCE_EVENTS {
            self.governance_events.remove(0);
        }
    }

    /// Get governance events terbaru.
    ///
    /// Method ini mengembalikan sejumlah event governance terbaru
    /// dalam urutan oldest → newest.
    ///
    /// # Arguments
    ///
    /// * `count` - Jumlah event yang diminta
    ///
    /// # Returns
    ///
    /// * `Vec<GovernanceEvent>` - Clone dari event terbaru
    ///
    /// # Note
    ///
    /// - Method ini READ-ONLY, tidak mengubah state
    /// - Return min(count, total_events) event
    /// - Urutan: oldest first, newest last
    pub fn get_recent_governance_events(&self, count: usize) -> Vec<GovernanceEvent> {
        let total = self.governance_events.len();
        let start = if count >= total { 0 } else { total - count };
        
        self.governance_events[start..].to_vec()
    }

    /// Log preview generated event.
    ///
    /// Helper method untuk mencatat event preview generation.
    /// Dipanggil setelah generate_proposal_preview berhasil.
    ///
    /// # Arguments
    ///
    /// * `proposal_id` - ID proposal yang di-preview
    /// * `actor` - Address yang meminta preview
    /// * `timestamp` - Unix timestamp saat preview di-generate
    pub fn log_preview_generated(&mut self, proposal_id: u64, actor: Address, timestamp: u64) {
        self.log_governance_event(GovernanceEvent {
            event_type: GovernanceEventType::PreviewGenerated,
            proposal_id: Some(proposal_id),
            actor,
            timestamp,
            details: format!("Preview generated for proposal {}", proposal_id),
        });
    }
}
// ════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(DEFAULT_VOTING_PERIOD, 604_800);
        assert_eq!(DEFAULT_QUORUM_PERCENTAGE, 33);
        assert_eq!(DEFAULT_PASS_THRESHOLD, 50);
        assert_eq!(MIN_PROPOSAL_DEPOSIT, 1_000_000_000_000);
    }

    #[test]
    fn test_governance_config_default() {
        let config = GovernanceConfig::default();
        
        assert_eq!(config.voting_period_seconds, DEFAULT_VOTING_PERIOD);
        assert_eq!(config.quorum_percentage, DEFAULT_QUORUM_PERCENTAGE);
        assert_eq!(config.pass_threshold, DEFAULT_PASS_THRESHOLD);
        assert!(config.bootstrap_mode);
    }

    #[test]
    fn test_proposal_type_serialization() {
        let proposal_type = ProposalType::UpdateFeeParameter {
            parameter_name: "storage_fee".to_string(),
            new_value: 1000,
        };
        
        let json = serde_json::to_string(&proposal_type).unwrap();
        let restored: ProposalType = serde_json::from_str(&json).unwrap();
        
        assert_eq!(proposal_type, restored);
    }

    #[test]
    fn test_proposal_status_variants() {
        let statuses = vec![
            ProposalStatus::Active,
            ProposalStatus::Passed,
            ProposalStatus::Rejected,
            ProposalStatus::Expired,
            ProposalStatus::Vetoed,
            ProposalStatus::Executed,
        ];
        
        for status in statuses {
            let json = serde_json::to_string(&status).unwrap();
            let restored: ProposalStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, restored);
        }
    }

    #[test]
    fn test_vote_option_variants() {
        let options = vec![
            VoteOption::Yes,
            VoteOption::No,
            VoteOption::Abstain,
        ];
        
        for option in options {
            let json = serde_json::to_string(&option).unwrap();
            let restored: VoteOption = serde_json::from_str(&json).unwrap();
            assert_eq!(option, restored);
        }
    }

    #[test]
    fn test_proposal_serialization() {
        let proposal = Proposal {
            id: 1,
            proposal_type: ProposalType::EmergencyPause {
                pause_type: "transfers".to_string(),
            },
            proposer: Address::from_bytes([0x01; 20]),
            title: "Test Proposal".to_string(),
            description: "Test description".to_string(),
            status: ProposalStatus::Active,
            created_at: 1700000000,
            voting_end: 1700604800,
            yes_votes: 0,
            no_votes: 0,
            abstain_votes: 0,
            quorum_required: 1000,
            execution_payload: vec![],
        };
        
        let json = serde_json::to_string(&proposal).unwrap();
        let restored: Proposal = serde_json::from_str(&json).unwrap();
        
        assert_eq!(proposal, restored);
    }

    #[test]
    fn test_vote_serialization() {
        let vote = Vote {
            voter: Address::from_bytes([0x02; 20]),
            proposal_id: 1,
            option: VoteOption::Yes,
            weight: 1000,
            timestamp: 1700000100,
        };
        
        let json = serde_json::to_string(&vote).unwrap();
        let restored: Vote = serde_json::from_str(&json).unwrap();
        
        assert_eq!(vote, restored);
    }

    #[test]
    fn test_governance_error_variants() {
        let errors = vec![
            GovernanceError::InsufficientStake,
            GovernanceError::ProposalNotFound,
            GovernanceError::ProposalNotActive,
            GovernanceError::VotingPeriodEnded,
            GovernanceError::VotingPeriodNotEnded,
            GovernanceError::AlreadyVoted,
            GovernanceError::InvalidProposalType,
            GovernanceError::TitleTooLong,
            GovernanceError::DescriptionTooLong,
            GovernanceError::InsufficientDeposit,
            GovernanceError::NotFoundation,
            GovernanceError::AlreadyFinalized,
        ];
        
        for error in errors {
            let json = serde_json::to_string(&error).unwrap();
            let restored: GovernanceError = serde_json::from_str(&json).unwrap();
            assert_eq!(error, restored);
        }
    }

    #[test]
    fn test_proposal_result_serialization() {
        let result = ProposalResult {
            proposal_id: 1,
            status: ProposalStatus::Passed,
            yes_votes: 1000,
            no_votes: 500,
            abstain_votes: 100,
            quorum_reached: true,
            execution_payload: vec![1, 2, 3],
        };
        
        let json = serde_json::to_string(&result).unwrap();
        let restored: ProposalResult = serde_json::from_str(&json).unwrap();
        
        assert_eq!(result, restored);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// INTEGRATION TESTS (requires ChainState)
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use crate::state::ChainState;

    fn setup_state_with_proposer() -> (ChainState, Address) {
        let mut state = ChainState::new();
        let proposer = Address::from_bytes([0x01; 20]);
        
        // Create account dan set balance
        state.create_account(proposer);
        *state.balances.entry(proposer).or_insert(0) = 10_000_000_000_000_000; // 10,000,000 NUSA
        
        // Set stake untuk memenuhi min_proposer_stake
        state.validator_stakes.insert(proposer, 2_000_000_000_000_000); // 2,000,000 NUSA
        
        // Set QV weight untuk quorum calculation
        state.qv_weights.insert(proposer, 1_000_000);
        
        (state, proposer)
    }

    #[test]
    fn test_create_proposal_success() {
        let (mut state, proposer) = setup_state_with_proposer();
        let balance_before = state.get_balance(&proposer);
        
        let result = state.create_proposal(
            proposer,
            ProposalType::EmergencyPause { pause_type: "test".to_string() },
            "Test Proposal".to_string(),
            "Test Description".to_string(),
            1700000000,
        );
        
        assert!(result.is_ok());
        let proposal_id = result.unwrap();
        assert_eq!(proposal_id, 1);
        assert_eq!(state.proposal_count, 1);
        
        // Check deposit deducted
        let balance_after = state.get_balance(&proposer);
        assert_eq!(balance_before - balance_after, MIN_PROPOSAL_DEPOSIT);
        
        // Check proposal stored
        let proposal = state.get_proposal(proposal_id).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Active);
        assert_eq!(proposal.proposer, proposer);
    }

    #[test]
    fn test_create_proposal_insufficient_stake() {
        let mut state = ChainState::new();
        let proposer = Address::from_bytes([0x02; 20]);
        
        state.create_account(proposer);
        *state.balances.entry(proposer).or_insert(0) = 10_000_000_000_000_000;
        // No stake set
        
        let result = state.create_proposal(
            proposer,
            ProposalType::EmergencyPause { pause_type: "test".to_string() },
            "Test".to_string(),
            "Desc".to_string(),
            1700000000,
        );
        
        assert_eq!(result, Err(GovernanceError::InsufficientStake));
    }

    #[test]
    fn test_create_proposal_title_too_long() {
        let (mut state, proposer) = setup_state_with_proposer();
        
        let long_title = "x".repeat(101);
        
        let result = state.create_proposal(
            proposer,
            ProposalType::EmergencyPause { pause_type: "test".to_string() },
            long_title,
            "Desc".to_string(),
            1700000000,
        );
        
        assert_eq!(result, Err(GovernanceError::TitleTooLong));
    }

    #[test]
    fn test_finalize_proposal_passed() {
        let (mut state, proposer) = setup_state_with_proposer();
        
        let proposal_id = state.create_proposal(
            proposer,
            ProposalType::EmergencyPause { pause_type: "test".to_string() },
            "Test".to_string(),
            "Desc".to_string(),
            1700000000,
        ).unwrap();
        
        // Add votes (manually for testing)
        if let Some(p) = state.proposals.get_mut(&proposal_id) {
            p.yes_votes = 1000;
            p.no_votes = 100;
            p.quorum_required = 500;
        }
        
        let balance_before = state.get_balance(&proposer);
        
        // Finalize after voting period
        let result = state.finalize_proposal(proposal_id, 1700000000 + 604_801);
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ProposalStatus::Passed);
        
        // Check refund
        let balance_after = state.get_balance(&proposer);
        assert_eq!(balance_after - balance_before, MIN_PROPOSAL_DEPOSIT);
    }

#[test]
    fn test_finalize_proposal_expired_no_quorum() {
        let (mut state, proposer) = setup_state_with_proposer();
        
        let proposal_id = state.create_proposal(
            proposer,
            ProposalType::EmergencyPause { pause_type: "test".to_string() },
            "Test".to_string(),
            "Desc".to_string(),
            1700000000,
        ).unwrap();
        
        // Set high quorum that won't be reached
        if let Some(p) = state.proposals.get_mut(&proposal_id) {
            p.yes_votes = 10;
            p.no_votes = 5;
            p.quorum_required = 1000;
        }
        
        let result = state.finalize_proposal(proposal_id, 1700000000 + 604_801);
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ProposalStatus::Expired);
    }

    #[test]
    fn test_finalize_proposal_rejected() {
        // PURPOSE: Finalize proposal with majority NO → status = Rejected
        let (mut state, proposer) = setup_state_with_proposer();
        
        let proposal_id = state.create_proposal(
            proposer,
            ProposalType::EmergencyPause { pause_type: "test".to_string() },
            "Rejected Proposal".to_string(),
            "This proposal will be rejected".to_string(),
            1700000000,
        ).unwrap();
        
        // Setup: majority NO votes, quorum reached
        if let Some(p) = state.proposals.get_mut(&proposal_id) {
            p.yes_votes = 100;     // YES votes
            p.no_votes = 500;      // NO votes (majority)
            p.abstain_votes = 100; // Abstain
            p.quorum_required = 500; // Quorum = 500, total = 700
        }
        
        let balance_before = state.get_balance(&proposer);
        
        // ACTION: Finalize after voting period ends
        let result = state.finalize_proposal(proposal_id, 1700000000 + 604_801);
        
        // ASSERTIONS:
        assert!(result.is_ok(), "finalize should succeed");
        assert_eq!(result.unwrap(), ProposalStatus::Rejected, "status should be Rejected when NO > YES");
        
        // Verify proposal status persisted
        let proposal = state.get_proposal(proposal_id).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Rejected);
        
        // Verify deposit refunded
        let balance_after = state.get_balance(&proposer);
        assert_eq!(balance_after - balance_before, MIN_PROPOSAL_DEPOSIT, "deposit should be refunded");
    }

    #[test]
    fn test_get_active_proposals() {
        let (mut state, proposer) = setup_state_with_proposer();
        
        // Create 3 proposals
        for i in 0..3 {
            state.create_proposal(
                proposer,
                ProposalType::EmergencyPause { pause_type: format!("test{}", i) },
                format!("Test {}", i),
                "Desc".to_string(),
                1700000000,
            ).unwrap();
        }
        
        let active = state.get_active_proposals();
        assert_eq!(active.len(), 3);
    }

    #[test]
    fn test_get_proposal_result() {
        let (mut state, proposer) = setup_state_with_proposer();
        
        let proposal_id = state.create_proposal(
            proposer,
            ProposalType::EmergencyPause { pause_type: "test".to_string() },
            "Test".to_string(),
            "Desc".to_string(),
            1700000000,
        ).unwrap();
        
        let result = state.get_proposal_result(proposal_id);
        assert!(result.is_some());
        
        let pr = result.unwrap();
        assert_eq!(pr.proposal_id, proposal_id);
        assert_eq!(pr.status, ProposalStatus::Active);
        assert!(!pr.quorum_reached);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // VOTING TESTS (13.12.3)
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_cast_vote_success() {
        let (mut state, proposer) = setup_state_with_proposer();
        let voter = Address::from_bytes([0x02; 20]);
        
        // Setup voter dengan QV weight
        state.create_account(voter);
        state.qv_weights.insert(voter, 500_000);
        
        // Create proposal
        let proposal_id = state.create_proposal(
            proposer,
            ProposalType::EmergencyPause { pause_type: "test".to_string() },
            "Test".to_string(),
            "Desc".to_string(),
            1700000000,
        ).unwrap();
        
        // Cast vote
        let result = state.cast_vote(voter, proposal_id, VoteOption::Yes, 1700000001);
        
        assert!(result.is_ok());
        assert!(state.has_voted(voter, proposal_id));
        
        // Check tally updated
        let proposal = state.get_proposal(proposal_id).unwrap();
        assert_eq!(proposal.yes_votes, 500_000);
    }

    #[test]
    fn test_cast_vote_double_vote_rejected() {
        let (mut state, proposer) = setup_state_with_proposer();
        let voter = Address::from_bytes([0x02; 20]);
        
        state.create_account(voter);
        state.qv_weights.insert(voter, 500_000);
        
        let proposal_id = state.create_proposal(
            proposer,
            ProposalType::EmergencyPause { pause_type: "test".to_string() },
            "Test".to_string(),
            "Desc".to_string(),
            1700000000,
        ).unwrap();
        
        // First vote
        state.cast_vote(voter, proposal_id, VoteOption::Yes, 1700000001).unwrap();
        
        // Second vote should fail
        let result = state.cast_vote(voter, proposal_id, VoteOption::No, 1700000002);
        
        assert_eq!(result, Err(GovernanceError::AlreadyVoted));
    }

    #[test]
    fn test_cast_vote_after_voting_period() {
        let (mut state, proposer) = setup_state_with_proposer();
        let voter = Address::from_bytes([0x02; 20]);
        
        state.create_account(voter);
        state.qv_weights.insert(voter, 500_000);
        
        let proposal_id = state.create_proposal(
            proposer,
            ProposalType::EmergencyPause { pause_type: "test".to_string() },
            "Test".to_string(),
            "Desc".to_string(),
            1700000000,
        ).unwrap();
        
        // Try to vote after voting period
        let result = state.cast_vote(voter, proposal_id, VoteOption::Yes, 1700000000 + 604_801);
        
        assert_eq!(result, Err(GovernanceError::VotingPeriodEnded));
    }

    #[test]
    fn test_cast_vote_weight_snapshot() {
        let (mut state, proposer) = setup_state_with_proposer();
        let voter = Address::from_bytes([0x02; 20]);
        
        state.create_account(voter);
        state.qv_weights.insert(voter, 500_000);
        
        let proposal_id = state.create_proposal(
            proposer,
            ProposalType::EmergencyPause { pause_type: "test".to_string() },
            "Test".to_string(),
            "Desc".to_string(),
            1700000000,
        ).unwrap();
        
        // Cast vote
        state.cast_vote(voter, proposal_id, VoteOption::Yes, 1700000001).unwrap();
        
        // Change QV weight AFTER vote
        state.qv_weights.insert(voter, 1_000_000);
        
        // Verify vote weight was snapshotted
        let votes = state.get_proposal_votes(proposal_id);
        assert_eq!(votes.len(), 1);
        assert_eq!(votes[0].weight, 500_000); // Original weight, not new weight
    }

    #[test]
    fn test_get_voter_weight() {
        let mut state = ChainState::new();
        let voter = Address::from_bytes([0x01; 20]);
        
        // No weight initially
        assert_eq!(state.get_voter_weight(voter), 0);
        
        // Set weight
        state.qv_weights.insert(voter, 123_456);
        assert_eq!(state.get_voter_weight(voter), 123_456);
    }

    #[test]
    fn test_get_proposal_votes_empty() {
        let state = ChainState::new();
        let votes = state.get_proposal_votes(999);
        assert!(votes.is_empty());
    }

    #[test]
    fn test_calculate_quorum() {
        let (mut state, _) = setup_state_with_proposer();
        
        // Total QV weights = 1_000_000 (from setup)
        // Quorum percentage = 33%
        // Expected quorum = 330_000
        let quorum = state.calculate_quorum(1);
        assert_eq!(quorum, 330_000);
    }

    #[test]
    fn test_multiple_voters() {
        let (mut state, proposer) = setup_state_with_proposer();
        
        // Setup multiple voters
        let voter1 = Address::from_bytes([0x02; 20]);
        let voter2 = Address::from_bytes([0x03; 20]);
        let voter3 = Address::from_bytes([0x04; 20]);
        
        state.qv_weights.insert(voter1, 100_000);
        state.qv_weights.insert(voter2, 200_000);
        state.qv_weights.insert(voter3, 300_000);
        
        let proposal_id = state.create_proposal(
            proposer,
            ProposalType::EmergencyPause { pause_type: "test".to_string() },
            "Test".to_string(),
            "Desc".to_string(),
            1700000000,
        ).unwrap();
        
        // All vote
        state.cast_vote(voter1, proposal_id, VoteOption::Yes, 1700000001).unwrap();
        state.cast_vote(voter2, proposal_id, VoteOption::No, 1700000002).unwrap();
        state.cast_vote(voter3, proposal_id, VoteOption::Abstain, 1700000003).unwrap();
        
        // Check tallies
        let proposal = state.get_proposal(proposal_id).unwrap();
        assert_eq!(proposal.yes_votes, 100_000);
        assert_eq!(proposal.no_votes, 200_000);
        assert_eq!(proposal.abstain_votes, 300_000);
        
        // Check vote count
        let votes = state.get_proposal_votes(proposal_id);
        assert_eq!(votes.len(), 3);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// FOUNDATION CONTROL TESTS (13.12.4)
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod foundation_tests {
    use super::*;
    use crate::state::ChainState;

    fn setup_state_with_foundation() -> (ChainState, Address, Address) {
        let mut state = ChainState::new();
        let foundation = Address::from_bytes([0x01; 20]);
        let proposer = Address::from_bytes([0x02; 20]);
        
        // Set foundation address
        state.governance_config.foundation_address = foundation;
        
        // Setup proposer
        state.create_account(proposer);
        *state.balances.entry(proposer).or_insert(0) = 10_000_000_000_000_000;
        state.validator_stakes.insert(proposer, 2_000_000_000_000_000);
        state.qv_weights.insert(proposer, 1_000_000);
        
        (state, foundation, proposer)
    }

    #[test]
    fn test_veto_proposal_success() {
        let (mut state, foundation, proposer) = setup_state_with_foundation();
        
        // Create proposal
        let proposal_id = state.create_proposal(
            proposer,
            ProposalType::EmergencyPause { pause_type: "test".to_string() },
            "Test".to_string(),
            "Desc".to_string(),
            1700000000,
        ).unwrap();
        
        let balance_before = state.get_balance(&proposer);
        
        // Veto
        let result = state.veto_proposal(foundation, proposal_id);
        assert!(result.is_ok());
        
        // Check status
        let proposal = state.get_proposal(proposal_id).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Vetoed);
        
        // Check refund
        let balance_after = state.get_balance(&proposer);
        assert_eq!(balance_after - balance_before, MIN_PROPOSAL_DEPOSIT);
    }

    #[test]
    fn test_veto_proposal_not_foundation() {
        let (mut state, _foundation, proposer) = setup_state_with_foundation();
        let non_foundation = Address::from_bytes([0x99; 20]);
        
        let proposal_id = state.create_proposal(
            proposer,
            ProposalType::EmergencyPause { pause_type: "test".to_string() },
            "Test".to_string(),
            "Desc".to_string(),
            1700000000,
        ).unwrap();
        
        let result = state.veto_proposal(non_foundation, proposal_id);
        assert_eq!(result, Err(GovernanceError::NotFoundation));
    }

    #[test]
    fn test_veto_proposal_already_vetoed() {
        let (mut state, foundation, proposer) = setup_state_with_foundation();
        
        let proposal_id = state.create_proposal(
            proposer,
            ProposalType::EmergencyPause { pause_type: "test".to_string() },
            "Test".to_string(),
            "Desc".to_string(),
            1700000000,
        ).unwrap();
        
        // First veto
        state.veto_proposal(foundation, proposal_id).unwrap();
        
        // Second veto should fail
        let result = state.veto_proposal(foundation, proposal_id);
        assert_eq!(result, Err(GovernanceError::AlreadyVetoed));
    }

    #[test]
    fn test_override_proposal_result_success() {
        let (mut state, foundation, proposer) = setup_state_with_foundation();
        
        let proposal_id = state.create_proposal(
            proposer,
            ProposalType::EmergencyPause { pause_type: "test".to_string() },
            "Test".to_string(),
            "Desc".to_string(),
            1700000000,
        ).unwrap();
        
        // Manually set to Passed for testing
        if let Some(p) = state.proposals.get_mut(&proposal_id) {
            p.status = ProposalStatus::Passed;
        }
        
        // Override to Vetoed
        let result = state.override_proposal_result(foundation, proposal_id, ProposalStatus::Vetoed);
        assert!(result.is_ok());
        
        let proposal = state.get_proposal(proposal_id).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Vetoed);
    }

    #[test]
    fn test_override_proposal_invalid_status() {
        let (mut state, foundation, proposer) = setup_state_with_foundation();
        
        let proposal_id = state.create_proposal(
            proposer,
            ProposalType::EmergencyPause { pause_type: "test".to_string() },
            "Test".to_string(),
            "Desc".to_string(),
            1700000000,
        ).unwrap();
        
        // Status is Active, not Passed or Rejected
        let result = state.override_proposal_result(foundation, proposal_id, ProposalStatus::Vetoed);
        assert_eq!(result, Err(GovernanceError::InvalidOverrideStatus));
    }

    #[test]
    fn test_set_foundation_address_success() {
        let (mut state, foundation, _proposer) = setup_state_with_foundation();
        let new_foundation = Address::from_bytes([0xAA; 20]);
        
        let result = state.set_foundation_address(foundation, new_foundation);
        assert!(result.is_ok());
        
        assert_eq!(state.governance_config.foundation_address, new_foundation);
    }

    #[test]
    fn test_set_foundation_address_not_foundation() {
        let (mut state, _foundation, _proposer) = setup_state_with_foundation();
        let non_foundation = Address::from_bytes([0x99; 20]);
        let new_foundation = Address::from_bytes([0xAA; 20]);
        
        let result = state.set_foundation_address(non_foundation, new_foundation);
        assert_eq!(result, Err(GovernanceError::NotFoundation));
    }

    #[test]
    fn test_is_foundation() {
        let (state, foundation, proposer) = setup_state_with_foundation();
        
        assert!(state.is_foundation(foundation));
        assert!(!state.is_foundation(proposer));
    }
}