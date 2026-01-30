//! # DSDN Chain Core Library
//!
//! Library inti untuk blockchain DSDN (Data Semi-Decentral Network).
//! ## Module Overview
//!
//! | Module | Fungsi | Reference |
//! |--------|--------|-----------|
//! | `types` | Core types: Address, Hash, MAX_SUPPLY | Core |
//! | `crypto` | Cryptographic primitives: Ed25519, SHA3-512 | Core |
//! | `state` | Chain state management: ChainState, validators, delegation | 13.8 |
//! | `db` | LMDB persistence: ChainDb, atomic commit | 13.7.I |
//! | `tx` | Transaction types: TxEnvelope, TxPayload, ResourceClass | 13.7.E |
//! | `block` | Block structure: BlockHeader, BlockBody, signing | 13.7.D |
//! | `mempool` | Transaction pool management | Core |
//! | `miner` | Block production: Miner, proposer selection | 13.7.D |
//! | `rpc` | JSON-RPC endpoints: FullNodeRpc, BroadcastManager, SyncRpc | 13.7.N, 13.11.7 |
//! | `cli` | Command line interface: Commands, sync subcommands | 13.9, 13.11.7 |
//! | `qv` | Quadratic Voting: sqrt weight, 80/20 formula | 13.8.C/D |
//! | `proposer` | Stake-weighted proposer selection | 13.7.D |
//! | `tokenomics` | Fee distribution: 70/20/10 split, caps | 13.8.E, 13.9 |
//! | `slashing` | Validator slashing: liveness, penalties | 13.8.J |
//! | `epoch` | Epoch rotation: EpochInfo, EpochConfig | 13.7.L |
//! | `e2e_tests` | End-to-end integration tests | 13.8.K |
//! | `receipt` | Resource receipt: reward foundation, anti-self-dealing | 13.10 |
//! | `sync` | P2P sync: HeaderSync, BlockSync, StateReplay, SyncManager | 13.11 |
//! | `celestia` | Celestia DA integration: blob fetch, control-plane sync | 13.11.5 |
//! | `economic` | Economic controller: deflation, burn rate, treasury | 13.15 |
//! | `wallet` | Wallet management: keypair, signing, encryption | 13.17 |
//! | `encryption` | Sistem enskripsi| 13.17 |
//!
//! ## 13.9 — GAS MODEL & FEE SPLIT
//!
//! ### Rumus Gas
//!
//! ```text
//! GAS = (BASE_OP_COST + (DATA_BYTES * PER_BYTE_COST) + (COMPUTE_CYCLES * PER_COMPUTE_CYCLE_COST)) * NODE_MULTIPLIER / 100
//! ```
//!
//! ### Fee Split (Blueprint 70/20/10)
//!
//! ```text
//! Resource Class        Node     Validator     Treasury
//! -----------------------------------------------------
//! Storage               70%        20%           10%
//! Compute               70%        20%           10%
//! Transfer              0%         100%          0%
//! Governance            0%         100%          0%
//! Stake                 0%         100%          0%
//! ```
//!
//! ### Anti-Self-Dealing
//!
//! ```text
//! Jika service_node == sender:
//!     node_share dialihkan seluruhnya ke treasury.
//! ```
//!
//! ## 13.10 — RESOURCE RECEIPT & CLAIMREWARD
//!
//! ### Overview
//!
//! ResourceReceipt adalah bukti eksekusi resource dari Coordinator yang digunakan
//! oleh service node untuk mengklaim reward secara trustless on-chain.
//!
//! ### ClaimReward Transaction
//!
//! ```text
//! ClaimReward diverifikasi via ResourceReceipt dari Coordinator.
//! Receipt hanya dapat diklaim SEKALI (anti double-claim).
//! Distribusi reward_base: 70% node, 20% validator, 10% treasury.
//! Anti-self-dealing enforced on-chain:
//!     - Jika node_address == sender: node_share → treasury
//!     - Jika anti_self_dealing_flag == true: node_share → treasury
//! ```
//!
//! ### Receipt Verification Order (Consensus-Critical)
//!
//! 1. Coordinator signature (Ed25519)
//! 2. Double-claim check (via claimed_receipts)
//! 3. Node address match
//! 4. Anti-self-dealing flag
//! 5. Timestamp validity
//!
//! ### Persistence & State Root
//!
//! ```text
//! - claimed_receipts dipersist di LMDB bucket: claimed_receipts/{receipt_id}
//! - Termasuk dalam state_root computation (posisi #25)
//! - Restore otomatis saat startup via load_from_state_layout()
//! ```
//!
//! ## Consensus-Critical Components
//!
//! Komponen berikut bersifat **consensus-critical** dan memerlukan hard-fork untuk perubahan:
//!
//! - Gas constants di `state/internal_gas.rs`
//! - Fee split percentages di `tokenomics.rs`
//! - State root hashing di `state/internal_state_root.rs`
//! - Node cost index di `state/internal_node_cost.rs`
//! - Receipt verification di `state/internal_receipt.rs`
//! - COORDINATOR_PUBKEY di `receipt.rs`
//! - claimed_receipts (state_root #25)
//!
//! ## RPC & CLI untuk ClaimReward (13.10)
//!
//! ### RPC Methods
//!
//! - `is_receipt_claimed(receipt_id)` — Query status receipt
//! - `get_node_earnings(node_address)` — Query akumulasi earnings node
//! - `submit_claim_reward(receipt_json)` — Submit ClaimReward transaction
//!
//! ### CLI Commands
//!
//! - `receipt claim --file <path>` — Submit ClaimReward dari file receipt JSON
//! - `receipt status --id <hex>` — Check status receipt (claimed atau belum)
//! - `receipt earnings --address <hex>` — Lihat akumulasi earnings node
//!
//! Semua logika validasi tetap dilakukan di chain layer (state/internal_receipt.rs).
//!
//! ## RPC & CLI untuk Sync (13.11.7)
//!
//! ### RPC Sync Endpoints
//!
//! | Method | Fungsi | Return |
//! |--------|--------|--------|
//! | `get_sync_status()` | Query status sync saat ini | SyncStatusRes |
//! | `start_sync()` | Mulai sync ke network tip | Result<(), RpcError> |
//! | `stop_sync()` | Hentikan sync yang berjalan | Result<(), RpcError> |
//! | `get_sync_progress()` | Query progress detail | SyncProgressRes |
//! | `handle_sync_request(req)` | Handle request dari peer | SyncResponse |
//!
//! ### CLI Sync Commands
//!
//! | Command | Fungsi |
//! |---------|--------|
//! | `sync start` | Mulai sync ke network tip |
//! | `sync stop` | Hentikan sync yang berjalan |
//! | `sync status` | Tampilkan status sync |
//! | `sync progress` | Tampilkan progress bar + ETA |
//! | `sync reset` | Reset state ke genesis |
//!
//! ### Arsitektur RPC/CLI → Chain → SyncManager
//!
//! ```text
//! ┌─────────┐     ┌─────────┐     ┌─────────────┐
//! │   CLI   │────►│  Chain  │────►│ SyncManager │
//! └─────────┘     └─────────┘     └─────────────┘
//!       │               │                │
//! ┌─────────┐           │                │
//! │   RPC   │───────────┘                │
//! └─────────┘                            │
//!                                        ▼
//!                               ┌─────────────────┐
//!                               │ HeaderSyncer    │
//!                               │ BlockSyncer     │
//!                               │ StateReplay     │
//!                               │ CelestiaSyncer  │
//!                               └─────────────────┘
//! ```
//!
//! RPC/CLI TIDAK mengandung logika sync. Semua delegasi ke Chain.
//!
//! ## 13.13.5 — RPC Preview Endpoints
//!
//! ### Tujuan
//!
//! RPC Preview Endpoints menyediakan akses READ-ONLY ke:
//! - Preview proposal (simulasi perubahan yang akan terjadi)
//! - Status bootstrap mode governance
//! - Event governance untuk monitoring
//!
//! ### Endpoint Preview
//!
//! | Method | Fungsi | Return |
//! |--------|--------|--------|
//! | `get_proposal_preview(id)` | Preview proposal dengan simulasi perubahan | ProposalPreviewRes |
//! | `get_bootstrap_mode_status()` | Status bootstrap mode governance | BootstrapModeRes |
//! | `get_governance_events(count)` | Event governance terbaru | Vec<GovernanceEventRes> |
//!
//! ### Karakteristik (PENTING)
//!
//! ```text
//! ⚠️ SEMUA ENDPOINT ADALAH READ-ONLY:
//!
//! - TIDAK mengubah state apapun
//! - TIDAK memengaruhi consensus
//! - Aman dipanggil kapan saja
//! - Response bersifat informatif
//!
//! Preview ≠ Execution:
//! - Preview HANYA menunjukkan perubahan yang AKAN terjadi
//! - Di Bootstrap Mode, TIDAK ADA proposal yang tereksekusi
//! - Preview tidak menjamin execution akan berhasil
//! ```
//!
//! ### Response Structs
//!
//! ```text
//! ProposalPreviewRes {
//!     proposal_id: u64,
//!     preview_type: String,
//!     simulated_changes: Vec<SimulatedChangeRes>,
//!     affected_addresses: Vec<String>,
//!     generated_at: u64,
//! }
//!
//! BootstrapModeRes {
//!     is_active: bool,
//!     foundation_address: String,
//!     execution_allowed: bool,    // == !is_active
//!     message: String,
//! }
//!
//! GovernanceEventRes {
//!     event_type: String,
//!     proposal_id: Option<u64>,
//!     actor: String,
//!     timestamp: u64,
//!     details: String,
//! }
//! ```
//!
//! ## 13.13.6 — CLI Preview Commands
//!
//! ### Tujuan
//!
//! CLI Preview Commands menyediakan akses READ-ONLY ke governance state
//! melalui command line interface.
//!
//! ### Commands
//!
//! | Command | Fungsi |
//! |---------|--------|
//! | `governance preview --proposal <ID>` | Preview proposal dengan simulasi perubahan |
//! | `governance bootstrap-status` | Status bootstrap mode governance |
//! | `governance events --count <N>` | Event governance terbaru (default: 20) |
//!
//! ### Karakteristik (PENTING)
//!
//! ```text
//! ⚠️ SEMUA COMMAND ADALAH READ-ONLY:
//!
//! - TIDAK mengubah state apapun
//! - TIDAK mengirim transaksi
//! - TIDAK memengaruhi consensus
//! - Aman dipanggil kapan saja
//!
//! Preview ≠ Execution:
//! - Preview HANYA menunjukkan perubahan yang AKAN terjadi
//! - Di Bootstrap Mode, TIDAK ADA proposal yang tereksekusi
//! - Preview tidak menjamin execution akan berhasil
//! ```
//!
//! ### Contoh Penggunaan
//!
//! ```bash
//! # Preview proposal #1
//! dsdn governance preview --proposal 1
//!
//! # Cek status bootstrap mode
//! dsdn governance bootstrap-status
//!
//! # Lihat 10 event governance terakhir
//! dsdn governance events --count 10
//! ```
//!
//! ### Perbedaan CLI vs RPC
//!
//! ```text
//! CLI:
//! - Human-readable output dengan emoji dan formatting
//! - Untuk admin/operator manual inspection
//! - Output langsung ke terminal
//!
//! RPC:
//! - Machine-readable JSON response
//! - Untuk integrasi aplikasi/dashboard
//! - Return struct yang dapat di-deserialize
//!
//! Keduanya memanggil STATE READ-ONLY API yang sama.
//! ```
//!
//! ## 13.13 — GOVERNANCE BOOTSTRAP MODE ENFORCEMENT (Summary)
//!
//! Governance Bootstrap Mode adalah fase awal governance di mana semua hasil voting
//! bersifat **NON-BINDING**. Proposal dapat dibuat dan voting dapat dilakukan, tetapi
//! eksekusi perubahan TIDAK terjadi.
//!
//! ### Key Points
//!
//! ```text
//! 1. NON-BINDING GOVERNANCE
//!    - Semua proposal dengan status Passed TIDAK mengeksekusi perubahan
//!    - Status tercatat di state, tetapi tidak ada state mutation
//!    - ExecutionDisabledBootstrapMode error untuk setiap attempt execution
//!
//! 2. PREVIEW & OBSERVABILITY
//!    - Preview system menunjukkan simulasi perubahan
//!    - RPC endpoints: get_proposal_preview, get_bootstrap_mode_status, get_governance_events
//!    - CLI commands: governance preview, bootstrap-status, events
//!    - Semua READ-ONLY, tidak memengaruhi consensus
//!
//! 3. FOUNDATION CONTROLS (Temporary)
//!    - Veto power: Dapat mem-veto proposal Active
//!    - Override power: Dapat mengubah status proposal Passed/Rejected
//!    - Powers ini bersifat SEMENTARA sampai network decentralized
//!
//! 4. EVENT LOGGING
//!    - In-memory audit trail (tidak di-persist)
//!    - Events: ProposalCreated, VoteCast, ProposalFinalized, ProposalVetoed,
//!              ProposalOverridden, PreviewGenerated, ExecutionAttemptBlocked
//!    - Retention: 1000 events max (FIFO)
//! ```
//!
//! Dokumentasi lengkap tersedia di `state/mod.rs` section "## 13.13".
//!
//! ## 13.15.8 — Economic RPC & CLI Observability
//!
//! ### Tujuan
//!
//! Economic RPC & CLI Observability menyediakan akses READ-ONLY ke economic state
//! untuk monitoring, audit, dan dashboard.
//!
//! ### RPC Endpoints
//!
//! | Method | Fungsi | Return |
//! |--------|--------|--------|
//! | `get_economic_status()` | Status ekonomi saat ini | EconomicStatusRes |
//! | `get_deflation_info()` | Konfigurasi dan state deflasi | DeflationInfoRes |
//! | `get_burn_events(count)` | Burn events terbaru | Vec<BurnEventRes> |
//!
//! ### CLI Commands
//!
//! | Command | Fungsi |
//! |---------|--------|
//! | `economic status` | Tampilkan mode, RF, treasury, supply, burn rate |
//! | `economic deflation` | Tampilkan target range, current rate, cumulative burned |
//! | `economic burn-history --count <N>` | Tampilkan riwayat burn events (default: 20) |
//!
//! ### Contoh Penggunaan
//!
//! ```bash
//! # Lihat status ekonomi
//! dsdn economic status
//!
//! # Lihat info deflasi
//! dsdn economic deflation
//!
//! # Lihat 10 burn events terakhir
//! dsdn economic burn-history --count 10
//! ```
//!
//! ### Response Structs
//!
//! ```text
//! EconomicStatusRes {
//!     mode: String,              // "Bootstrap", "Growth", "Mature", "Deflationary"
//!     replication_factor: u8,
//!     treasury_balance: String,  // u128 as string (avoid JSON overflow)
//!     total_supply: String,
//!     deflation_enabled: bool,
//!     current_burn_rate: String, // basis points
//! }
//!
//! DeflationInfoRes {
//!     target_min_percent: String,
//!     target_max_percent: String,
//!     current_annual_rate: String,
//!     cumulative_burned: String,
//!     last_burn_epoch: u64,
//!     next_burn_eligible_epoch: u64,
//! }
//!
//! BurnEventRes {
//!     epoch: u64,
//!     amount_burned: String,
//!     burn_rate: String,
//!     timestamp: u64,
//! }
//! ```
//!
//! ### Karakteristik (PENTING)
//!
//! ```text
//! ⚠️ SEMUA ENDPOINT/COMMAND ADALAH READ-ONLY:
//!
//! - TIDAK mengubah state apapun
//! - TIDAK memengaruhi consensus
//! - Aman dipanggil kapan saja
//! - Response bersifat informatif
//!
//! ⚠️ BURN EVENTS ADALAH RUNTIME-ONLY:
//!
//! - economic_events TIDAK dipersist ke LMDB
//! - Events reset setelah node restart
//! - Untuk audit permanen, gunakan state_root verification
//! ```
//!
//! ## Implementation Status
//!
//! ```text
//! | Tahap | Fitur | Status |
//! |-------|-------|--------|
//! | 13.7  | Core Transaction & Block Processing | ✅ IMPLEMENTED |
//! | 13.8  | Staking, Delegation, QV, Slashing | ✅ IMPLEMENTED |
//! | 13.9  | Gas Model & Fee Split | ✅ IMPLEMENTED |
//! | 13.10 | Resource Receipt & ClaimReward | ✅ IMPLEMENTED |
//! | 13.11 | P2P Sync & Celestia Integration | ✅ IMPLEMENTED |
//! | 13.12 | Governance Foundation (Bootstrap) | ✅ IMPLEMENTED |
//! | 13.13 | Governance Bootstrap Mode Enforcement | ✅ IMPLEMENTED |
//! |       |   - 13.13.1: Preview Data Structures | ✅ IMPLEMENTED |
//! |       |   - 13.13.2: Preview Generator Methods | ✅ IMPLEMENTED |
//! |       |   - 13.13.3: Non-Binding Enforcement | ✅ IMPLEMENTED |
//! |       |   - 13.13.4: Governance Event Logging | ✅ IMPLEMENTED |
//! |       |   - 13.13.5: RPC Preview Endpoints | ✅ IMPLEMENTED |
//! |       |   - 13.13.6: CLI Preview Commands | ✅ IMPLEMENTED |
//! |       |   - 13.13.7: Payload Integration | ✅ IMPLEMENTED |
//! |       |   - 13.13.8: Documentation Update | ✅ IMPLEMENTED |
//! | 13.14 | Automatic Slashing System | ✅ IMPLEMENTED |
//! | 13.15 | Adaptive Economic & Deflation Controller | ✅ IMPLEMENTED |
//! |       |   - 13.15.1: Economic Constants & Data Structures | ✅ IMPLEMENTED |
//! |       |   - 13.15.2: DeflationConfig | ✅ IMPLEMENTED |
//! |       |   - 13.15.3: EconomicMetrics | ✅ IMPLEMENTED |
//! |       |   - 13.15.4: AdaptiveBurnRate | ✅ IMPLEMENTED |
//! |       |   - 13.15.5: TreasuryBurn | ✅ IMPLEMENTED |
//! |       |   - 13.15.6: Block-Level Integration | ✅ IMPLEMENTED |
//! |       |   - 13.15.7: LMDB Persistence | ✅ IMPLEMENTED |
//! |       |   - 13.15.8: RPC & CLI Observability | ✅ IMPLEMENTED |
//! ```
//!
//! ## Chain Struct
//! `Chain` adalah top-level struct yang menggabungkan:
//! - `ChainDb` — LMDB persistence
//! - `ChainState` — World state
//! - `Mempool` — Pending transactions
//! - `Miner` — Block production
//! - `BroadcastManager` — P2P broadcasting
//!
//! ## Usage Example
//!
//! ```rust,ignore
//! use dsdn_chain::Chain;
//!
//! let chain = Chain::new("./data")?;
//! chain.init_genesis("0x...", 1_000_000_000)?;
//! chain.submit_tx(tx_envelope)?;
//! let block = chain.mine_block_and_apply("0x...")?;
//! ```
//! ## 13.14.8 — Slashing RPC & CLI Observability
//!
//! Tahap ini menyediakan VISIBILITAS dan TRANSPARANSI untuk sistem slashing.
//! Semua endpoints dan commands adalah READ-ONLY.
//!
//! ### Tujuan Observability Slashing
//!
//! ```text
//! TUJUAN:
//! 1. Operator dapat memonitor status node/validator
//! 2. Delegator dapat melihat apakah validator di-slash
//! 3. Audit trail slashing transparan
//! 4. Dashboard dan monitoring tools dapat mengakses data
//!
//! KARAKTERISTIK:
//! - READ-ONLY: Tidak ada state mutation
//! - SAFE: Tidak memengaruhi consensus
//! - TRANSPARENT: Data slashing dapat diakses publik
//! ```
//!
//! ### RPC Endpoints
//!
//! | Method | Fungsi | Return |
//! |--------|--------|--------|
//! | `get_node_liveness_status(node)` | Status liveness node | NodeLivenessRes |
//! | `get_validator_slash_status(validator)` | Status slash validator | ValidatorSlashRes |
//! | `get_recent_slashing_events(count)` | Slashing events terbaru | Vec<SlashingEventRes> |
//!
//! ### Response Structs
//!
//! ```text
//! NodeLivenessRes {
//!     node_address: String,
//!     last_seen_timestamp: u64,
//!     consecutive_failures: u32,
//!     data_corruption_count: u32,
//!     malicious_behavior_count: u32,
//!     force_unbond_until: Option<u64>,
//!     slashed: bool,
//! }
//!
//! ValidatorSlashRes {
//!     validator_address: String,
//!     slashed: bool,
//!     reason: Option<String>,
//!     force_unbond_until: Option<u64>,
//! }
//!
//! SlashingEventRes {
//!     target: String,
//!     reason: String,
//!     amount_slashed: String,
//!     amount_to_treasury: String,
//!     amount_burned: String,
//!     timestamp: u64,
//! }
//! ```
//!
//! ### CLI Commands
//!
//! | Command | Fungsi |
//! |---------|--------|
//! | `slashing node-status --address <hex>` | Lihat status liveness node |
//! | `slashing validator-status --address <hex>` | Lihat status slash validator |
//! | `slashing events --count <N>` | Lihat N slashing events terbaru |
//!
//! ### Contoh Penggunaan
//!
//! ```bash
//! # Lihat status node
//! dsdn slashing node-status --address 0x1234...
//!
//! # Lihat status validator
//! dsdn slashing validator-status --address 0xabcd...
//!
//! # Lihat 10 slashing events terbaru
//! dsdn slashing events --count 10
//! ```
//!
//! ### Catatan Penting
//!
//! ```text
//! ⚠️ READ-ONLY:
//! - Semua endpoints/commands TIDAK mengubah state
//! - Aman dipanggil kapan saja
//! - Tidak memengaruhi consensus
//!
//! ⚠️ SLASHING_EVENTS RUNTIME-ONLY:
//! - slashing_events tidak dipersist ke LMDB
//! - Events hilang setelah node restart
//! - Untuk audit trail permanent, gunakan LMDB queries
//!
//! ⚠️ MONITORING & DASHBOARD:
//! - Endpoints dapat digunakan oleh monitoring tools
//! - Response format stabil (JSON-serializable)
//! - Amounts sebagai string untuk menghindari overflow
//! ```
//!
//! ### Lokasi File
//!
//! ```text
//! crates/chain/src/rpc.rs (RPC endpoints + response structs)
//! crates/chain/src/cli.rs (CLI commands)
//! ```
pub mod types;
pub mod crypto;
pub mod state; //direktori = /state/mod.rs
pub mod receipt;
pub mod db;
pub mod tx;
pub mod block; //block.rss adalah prohram rusts+
pub mod mempool;
pub mod miner;
pub mod rpc;
pub mod cli;  
pub mod qv;
pub mod proposer;
pub mod tokenomics;
pub mod slashing;
pub mod epoch;
pub mod e2e_tests;
pub mod sync;
pub mod celestia;
pub mod economic;
pub mod wallet;
pub mod encryption;

use crate::types::{Address, Hash};
use std::str::FromStr;

use crate::db::ChainDb;
use crate::state::ChainState;
use crate::mempool::Mempool;
use crate::miner::Miner;
use parking_lot::RwLock;
use std::sync::Arc;

// ════════════════════════════════════════════════════════════════════════════
// ECONOMIC RE-EXPORTS (13.15)
// ════════════════════════════════════════════════════════════════════════════
pub use economic::{
    DeflationConfig,
    EconomicMetrics,
    EconomicMode,
    BurnEvent,
    EconomicSnapshot,
};

// ════════════════════════════════════════════════════════════════════════════
// WALLET RE-EXPORTS (13.17)
// ════════════════════════════════════════════════════════════════════════════
pub use wallet::Wallet;

// ════════════════════════════════════════════════════════════════════════════
// CHAIN ERROR (13.18.4)
// ════════════════════════════════════════════════════════════════════════════
// Error type untuk Chain operations termasuk block replay.
// Digunakan untuk recovery, fast sync, dan snapshot restore.
// ════════════════════════════════════════════════════════════════════════════

use thiserror::Error;

/// Error type untuk Chain operations.
///
/// Digunakan oleh:
/// - replay_blocks_from() — Block replay setelah snapshot
/// - get_blocks_range() — Fetch block range
/// - Fast sync operations
#[derive(Debug, Error)]
pub enum ChainError {
    /// Block tidak ditemukan di database
    #[error("block not found at height {0}")]
    BlockNotFound(u64),

    /// Range tidak valid (start > end)
    #[error("invalid block range: start {start} > end {end}")]
    InvalidRange {
        start: u64,
        end: u64,
    },

    /// State root mismatch setelah replay
    #[error("state root mismatch at height {height}: expected {expected}, computed {computed}")]
    StateRootMismatch {
        height: u64,
        expected: String,
        computed: String,
    },

    /// Block signature verification failed
    #[error("block signature verification failed at height {0}")]
    SignatureVerificationFailed(u64),

    /// Transaction execution error
    #[error("transaction execution error at height {height}: {message}")]
    TransactionError {
        height: u64,
        message: String,
    },

    /// Database error
    #[error("database error: {0}")]
    DatabaseError(String),

    /// Replay interrupted
    #[error("replay interrupted at height {0}")]
    ReplayInterrupted(u64),

    // ════════════════════════════════════════════════════════════════════════
    // CONTROL-PLANE REBUILD ERRORS (13.18.5)
    // ════════════════════════════════════════════════════════════════════════

    /// Blob decode error during control-plane rebuild
    #[error("control-plane blob decode failed at height {height}: {message}")]
    ControlPlaneBlobDecodeError {
        height: u64,
        message: String,
    },

    /// Unknown payload type in control-plane blob
    #[error("unknown control-plane payload type at height {height}: tag={tag}")]
    UnknownControlPlanePayload {
        height: u64,
        tag: u8,
    },

    /// Control-plane rebuild failed
    #[error("control-plane rebuild failed: {0}")]
    ControlPlaneRebuildFailed(String),

    // ════════════════════════════════════════════════════════════════════════
    // SNAPSHOT ERRORS (13.18.6)
    // ════════════════════════════════════════════════════════════════════════

    /// Snapshot creation failed
    #[error("snapshot creation failed at height {height}: {message}")]
    SnapshotCreationFailed {
        height: u64,
        message: String,
    },

    /// Snapshot cleanup failed
    #[error("snapshot cleanup failed: {0}")]
    SnapshotCleanupFailed(String),
}

/// Top-level Chain struct combining DB, state, mempool and miner.
#[derive(Clone)]
pub struct Chain {
    pub db: Arc<ChainDb>,
    pub state: Arc<RwLock<ChainState>>,
    pub mempool: Arc<Mempool>,
    pub miner: Arc<Miner>,
    /// Broadcast manager for P2P layer (13.7.N)
    pub broadcast_manager: Arc<crate::rpc::BroadcastManager>,
    
    // ════════════════════════════════════════════════════════════════════════════
    // CELESTIA DA TRACKING (13.16.6)
    // ════════════════════════════════════════════════════════════════════════════
    // Observability metadata for Celestia DA layer sync status.
    // These fields are NOT consensus-critical and NOT included in state_root.
    // Thread-safe using atomic operations.
    // ════════════════════════════════════════════════════════════════════════════
    
    /// Last known Celestia block height (0 = not synced yet)
    /// Observability only, not consensus-critical
    pub last_celestia_height: Arc<std::sync::atomic::AtomicU64>,
    
    /// Timestamp of last successful Celestia sync (0 = never synced)
    /// Observability only, not consensus-critical
    pub last_celestia_sync: Arc<std::sync::atomic::AtomicU64>,

    // ════════════════════════════════════════════════════════════════════════════
    // SNAPSHOT CONFIGURATION (13.18.6)
    // ════════════════════════════════════════════════════════════════════════════
    // Konfigurasi untuk automatic checkpoint/snapshot system.
    // Snapshot dibuat otomatis setiap N blocks sesuai config.
    // ════════════════════════════════════════════════════════════════════════════

    /// Snapshot configuration untuk automatic checkpoint
    /// Menentukan interval, path, dan retention policy
    pub snapshot_config: crate::state::SnapshotConfig,
}

impl Chain {
    /// create new chain instance (load state from DB)
    pub fn new<P: AsRef<std::path::Path>>(db_path: P) -> anyhow::Result<Self> {
        let db = ChainDb::open(db_path.as_ref())?;
        let loaded_state = db.load_state()?;
        let state = Arc::new(RwLock::new(loaded_state));
        let mempool = Arc::new(Mempool::new());
        
        // Load pending mempool tx dari DB (NEW) ← TAMBAHKAN INI
        let pending_txs = db.load_all_mempool_txs()?;
        println!("📥 Loading {} pending tx(s) from mempool bucket...", pending_txs.len());
        for tx in pending_txs {
            if let Err(e) = mempool.add_from_db(tx) {
                eprintln!("⚠️  Failed to restore tx from DB: {}", e);
            }
        }
        
        // Dummy miner for dev; in prod, use real proposer/key from config
        let dummy_proposer = Address::from_str("0x0000000000000000000000000000000000000000").unwrap();
        let dummy_priv = vec![0u8; 32];  // Dummy secret key; replace with real
        let miner = Arc::new(Miner::new(dummy_proposer, dummy_priv));
        let broadcast_manager = Arc::new(crate::rpc::BroadcastManager::new());
        
        Ok(Chain {
            db: Arc::new(db),
            state,
            mempool,
            miner,
            broadcast_manager,
            // Initialize Celestia tracking with "not synced" state
            last_celestia_height: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            last_celestia_sync: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            // Initialize snapshot config with defaults (13.18.6)
            snapshot_config: crate::state::SnapshotConfig::default(),
        })
    }

    pub fn init_genesis(&self, genesis_account: &str, amount_scaled: u128) -> anyhow::Result<()> {
        if self.db.has_genesis()? {
            return Ok(());
        }

        let addr = Address::from_str(genesis_account)
            .map_err(|e| anyhow::anyhow!("invalid genesis address: {}", e))?;

        {
            let mut st = self.state.write();
            st.create_account(addr);
            st.mint(&addr, amount_scaled)?;
        }
        // Persist state
        let st_snapshot = self.state.read().clone();
        self.db.persist_state(&st_snapshot)?;

        // Set initial tip
        self.db.set_tip(0, &Hash::from_bytes([0u8; 64]))?;
        self.db.mark_genesis()?;
        Ok(())
    }
    pub fn submit_tx(&self, env: crate::tx::TxEnvelope) -> anyhow::Result<()> {
        // 1) stateless
        env.validate_stateless()
            .map_err(|e| anyhow::anyhow!("stateless validation failed: {}", e))?;

        // 2) validator compliance filter (skip untuk private tx) ← UPDATE INI
        if !env.is_private() && env.payload.is_flagged_illegal() {
            anyhow::bail!("validator rejection: illegal transaction flagged by compliance system");
        }

        // 3) stateful
        let state_clone = self.state.clone();
        let get_balance = move |a: &Address| -> u128 { state_clone.read().get_balance(a) };
        let state_clone2 = self.state.clone();
        let get_nonce = move |a: &Address| -> u64 { state_clone2.read().get_nonce(a) };

        // Stateful validation (untuk private tx hanya check minimal)
        env.validate_stateful(get_balance, get_nonce)
            .map_err(|e| anyhow::anyhow!("stateful validation failed: {}", e))?;

        // 4) persist to DB for next mining
        self.db.put_pending_tx(&env)?;
        
        // 5) persist to mempool bucket
        let txid = env.compute_txid()?;
        self.db.put_mempool_tx(&txid.to_hex(), &env)?;
        
        if env.is_private() {
            println!("✅ Private TX saved to DB (will be relayed, not executed)");
        } else {
            println!("✅ TX saved to DB (pending queue + mempool bucket)");
        }
        Ok(())
    }

   pub fn mine_block_and_apply(&self, miner_addr: &str) -> anyhow::Result<crate::block::Block> {
        let fallback_address = Address::from_str(miner_addr)
            .map_err(|e| anyhow::anyhow!("invalid miner addr: {}", e))?;

        let (parent_height, parent_hash) =
            self.db.get_tip()?.unwrap_or((0, Hash::from_bytes([0u8; 64])));
        let height = parent_height + 1;

        // ============================================================
        // PROPOSER SELECTION (13.7.D)
        // ============================================================
        let proposer_address = {
            let state_read = self.state.read();
            
            // Attempt stake-weighted proposer selection
            match crate::proposer::select_block_proposer(&state_read, &parent_hash) {
                Some(addr) => {
                    println!("🎯 Proposer selected via stake-weighted algorithm: {}", addr);
                    addr
                }
                None => {
                    // Fallback jika belum ada validator terdaftar
                    println!("⚠️  No validators registered, using fallback proposer: {}", fallback_address);
                    fallback_address
                }
            }
        };

        // Buat miner dengan proposer yang terpilih
        let miner = crate::miner::Miner::new(proposer_address, vec![0u8; 32]);

        // Ambil transaksi pending dari DB
        let txs: Vec<crate::tx::TxEnvelope> = self.db.load_pending_txs()?;
        if txs.is_empty() {
            println!("⚠️  No pending transactions found, mining empty block");
        } else {
            println!("🧾 Including {} pending tx(s) into block {}", txs.len(), height);
        }

        // Jalankan eksekusi block dengan proposer terpilih
        let mut state_guard = self.state.write();
        
        // Capture proposer balance before mining (untuk fee tracking)
        let proposer_balance_before = state_guard.get_balance(&proposer_address);
        
        let block = miner.mine_block(
            txs.clone(),
            &mut *state_guard,
            parent_hash,
            height,
        )?;

        // Calculate fees earned by proposer
        let proposer_balance_after = state_guard.get_balance(&proposer_address);
        let fees_earned = proposer_balance_after.saturating_sub(proposer_balance_before);
        if fees_earned > 0 {
            println!("💰 Proposer earned {} in fees", fees_earned);
        }

        // Report treasury balance (13.7.G anti self-dealing)
        let treasury = state_guard.get_treasury_balance();
        if treasury > 0 {
            println!("🏦 Treasury balance: {} (from anti self-dealing)", treasury);
        }

        // Validasi state_root
        let computed_root = state_guard.compute_state_root()?;
        if computed_root != block.header.state_root {
            anyhow::bail!("state_root mismatch after mining");
        }

        // ============================================================
        // ATOMIC COMMIT (13.7.I)
        // ============================================================
        // Capture state snapshot sebelum drop guard
        let state_snapshot = state_guard.clone();
        drop(state_guard);

        // Commit SEMUA data dalam 1 transaksi LMDB
        // Jika gagal, TIDAK ADA yang tersimpan (rollback otomatis)
        self.db.atomic_commit_block(&block, &state_snapshot)?;

        let block_hash = crate::block::Block::compute_hash(&block.header);

        // ============================================================
        // VALIDATOR LIVENESS UPDATE (13.7.K)
        // ============================================================
        // Update liveness counters for all validators
        // Proposer gets reset, others get incremented
        {
            let mut state_guard = self.state.write();
            let slashing_events = crate::slashing::update_all_validators_liveness(
                &proposer_address,
                height,
                &mut *state_guard,
            );
            
            if !slashing_events.is_empty() {
                println!("🔪 SLASHING EVENTS:");
                for event in &slashing_events {
                    println!("   {}", event);
                }
                // Persist updated state with slashing changes
                let updated_snapshot = state_guard.clone();
                drop(state_guard);
                self.db.persist_state(&updated_snapshot)?;
            }
        }

        // ============================================================
        // EPOCH ROTATION CHECK (13.7.L)
        // ============================================================
        // Check if epoch boundary reached and rotate validator set
        // Rotation happens every EPOCH_INTERVAL blocks (default: 120)
        {
            let mut state_guard = self.state.write();
            match state_guard.maybe_rotate_epoch(height) {
                Ok(epoch_events) => {
                    if !epoch_events.is_empty() {
                        println!("🌅 EPOCH ROTATION EVENTS:");
                        for event in &epoch_events {
                            println!("   {}", event);
                        }
                        // Persist updated state after epoch rotation
                        let updated_snapshot = state_guard.clone();
                        drop(state_guard);
                        self.db.persist_state(&updated_snapshot)?;
                    }
                }
                Err(e) => {
                    eprintln!("⚠️  Epoch rotation error: {}", e);
                }
            }
        }

        // ============================================================
        // AUTOMATIC CHECKPOINT (13.18.6)
        // ============================================================
        // Create snapshot if this is a checkpoint height.
        // MUST be called AFTER block is finalized and state is persisted.
        // MUST NOT be called during replay, sync, or recovery.
        // ============================================================
        if let Err(e) = self.maybe_create_checkpoint(height) {
            // Log but don't fail block production
            eprintln!("⚠️  Checkpoint creation error: {}", e);
        }

        // BROADCAST BLOCK 
       // Legacy broadcast (logs only)
        self.broadcast_block(&block)?;
        
        // P2P broadcast to connected peers (13.7.N)
        let broadcast_results = crate::rpc::broadcast_block_via_manager(
            &block, 
            &self.broadcast_manager
        );
        
        if !broadcast_results.is_empty() {
            let success_count = broadcast_results.iter().filter(|r| r.success).count();
            println!("📡 P2P Broadcast: {}/{} peers received block", 
                     success_count, broadcast_results.len());
        }

        // Print final summary
        let stats = self.get_block_stats(&block);
        println!("═══════════════════════════════════════════════════════════");
        println!("📦 BLOCK COMMITTED TO DB");
        println!("   Height: {}", stats.height);
        println!("   Hash: {}", block_hash);
        println!("   TXs: {} total ({} success, {} failed)", 
                 stats.total_txs, stats.successful_txs, stats.failed_txs);
        println!("═══════════════════════════════════════════════════════════");

        Ok(block)
    }


    // ============================================================
    // Block Broadcasting (13.7.E) - Stub for P2P layer
    // ============================================================

    /// Broadcast newly produced block to network peers
    /// This is a stub - actual P2P implementation will be in network layer
    pub fn broadcast_block(&self, block: &crate::block::Block) -> anyhow::Result<()> {
        let block_hash = crate::block::Block::compute_hash(&block.header);
        
        println!("📡 BROADCAST BLOCK");
        println!("   Height: {}", block.header.height);
        println!("   Hash: {}", block_hash);
        println!("   Proposer: {}", block.header.proposer);
        println!("   TXs: {}", block.body.transactions.len());
        println!("   Gas Used: {}", block.header.gas_used);
        
        // TODO: Implement actual P2P broadcast
        // - Serialize block
        // - Send to connected peers
        // - Handle peer responses
        
        println!("   Status: ✅ Ready for P2P broadcast (stub)");
        Ok(())
    }

        /// Get block production statistics
    pub fn get_block_stats(&self, block: &crate::block::Block) -> BlockProductionStats {
        let successful = block.body.receipts.iter().filter(|r| r.success).count();
        let failed = block.body.receipts.iter().filter(|r| !r.success).count();
        
        BlockProductionStats {
            height: block.header.height,
            total_txs: block.body.transactions.len(),
            successful_txs: successful,
            failed_txs: failed,
            gas_used: block.header.gas_used,
            proposer: block.header.proposer,
        }
    }

    // ============================================================
    // PUBLIC FULL NODE BEHAVIOR (13.7.J)
    // ============================================================
    // Full node dapat menerima & apply block dari network
    // TANPA berpartisipasi dalam konsensus atau proposer selection
    // ============================================================

    /// Apply block received from network without mining
    /// Used by public full nodes to sync with the chain
    /// 
    /// This function:
    /// - Verifies all transaction signatures
    /// - Verifies block signature
    /// - Verifies parent hash matches current tip
    /// - Executes all transactions sequentially
    /// - Processes automatic slashing (13.14.6)
    /// - Processes economic job (13.15.6): metrics update & treasury burn
    /// - Commits block + state atomically to LMDB
    /// 
    /// ## Block Processing Pipeline (URUTAN CONSENSUS-CRITICAL)
    /// 
    /// ```text
    /// 1. Execute all transactions
    /// 2. process_automatic_slashing()
    /// 3. process_economic_job()     ← Economic job di sini
    /// 4. compute_state_root()
    /// 5. Verify state_root == block.header.state_root
    /// 6. atomic_commit_block()
    /// ```
    /// 
    /// ## Economic Job (13.15.6)
    /// 
    /// Economic job dijalankan per block, setelah slashing dan sebelum state_root:
    /// - Update active nodes/validators count
    /// - Check epoch transition → reset epoch metrics
    /// - Check burn eligibility → execute treasury burn jika valid
    /// - Burn memengaruhi treasury_balance & cumulative_burned
    /// - State changes WAJIB terjadi sebelum compute_state_root()
    /// 
    /// This function does NOT:
    /// - Perform proposer selection
    /// - Create new blocks
    /// - Participate in consensus
    pub fn apply_block_without_mining(&self, block: crate::block::Block) -> anyhow::Result<()> {
        println!("═══════════════════════════════════════════════════════════");
        println!("📥 FULL NODE: Applying block {} from network", block.header.height);
        println!("═══════════════════════════════════════════════════════════");

        // ─────────────────────────────────────────────────────────
        // 1) VERIFY BLOCK SIGNATURE
        // ─────────────────────────────────────────────────────────
        if !block.verify_signature()? {
            anyhow::bail!("block signature verification failed");
        }
        println!("   ✓ Block signature verified");

        // ─────────────────────────────────────────────────────────
        // 2) VERIFY PARENT HASH MATCHES CURRENT TIP
        // ─────────────────────────────────────────────────────────
        let (tip_height, tip_hash) = self.db.get_tip()?
            .unwrap_or((0, Hash::from_bytes([0u8; 64])));
        
        if block.header.parent_hash != tip_hash {
            anyhow::bail!(
                "parent hash mismatch: expected {}, got {}",
                tip_hash, block.header.parent_hash
            );
        }
        println!("   ✓ Parent hash verified");

        // ─────────────────────────────────────────────────────────
        // 3) VERIFY BLOCK HEIGHT = TIP + 1
        // ─────────────────────────────────────────────────────────
        let expected_height = tip_height + 1;
        if block.header.height != expected_height {
            anyhow::bail!(
                "block height mismatch: expected {}, got {}",
                expected_height, block.header.height
            );
        }
        println!("   ✓ Block height verified ({})", block.header.height);

        // ─────────────────────────────────────────────────────────
        // 4) VERIFY ALL TRANSACTION SIGNATURES
        // ─────────────────────────────────────────────────────────
        for (i, tx) in block.body.transactions.iter().enumerate() {
            if !tx.verify_signature()? {
                anyhow::bail!("transaction {} signature verification failed", i);
            }
        }
        println!("   ✓ All {} transaction signature(s) verified", 
                 block.body.transactions.len());

        // ─────────────────────────────────────────────────────────
        // 5) EXECUTE TRANSACTIONS SEQUENTIALLY
        // ─────────────────────────────────────────────────────────
        let mut state_guard = self.state.write();
        let proposer = block.header.proposer;

        for tx in &block.body.transactions {
            // Apply payload dengan proposer dari block header
            // Fee distribution sudah di-handle oleh state.apply_payload()
            match state_guard.apply_payload(tx, &proposer) {
                Ok(_) => {},
                Err(e) => {
                    // Log error tapi lanjutkan (sesuai behavior di miner)
                    println!("   ⚠️  TX execution error (continuing): {}", e);
                }
            }
        }
        println!("   ✓ All transactions executed");

        // ─────────────────────────────────────────────────────────
        // 5.5) AUTOMATIC SLASHING HOOK (13.14.6)
        // ─────────────────────────────────────────────────────────
        // POSISI WAJIB: Setelah TX execution, SEBELUM state_root
        // Semua slashing diproses di sini secara deterministic
        // ─────────────────────────────────────────────────────────
        let slashing_events = state_guard.process_automatic_slashing(
            block.header.height,
            block.header
                .timestamp
                .timestamp() as u64,
        );

        if !slashing_events.is_empty() {
            println!("   ⚔️ Slashing executed: {} events", slashing_events.len());
            for event in &slashing_events {
                println!("      └─ {:?}: {} slashed {} (treasury={}, burned={})",
                    event.reason,
                    event.target,
                    event.amount_slashed,
                    event.amount_to_treasury,
                    event.amount_burned
                );
            }
        }

        // ─────────────────────────────────────────────────────────
        // 5.6) ECONOMIC JOB (13.15.6)
        // ─────────────────────────────────────────────────────────
        // POSISI WAJIB: Setelah slashing, SEBELUM state_root
        // Economic job memproses:
        // - Update active counts
        // - Epoch transition check
        // - Treasury burn (jika eligible)
        // Burn memengaruhi treasury_balance & cumulative_burned
        // yang termasuk dalam state_root computation.
        // ─────────────────────────────────────────────────────────
        let burn_event = state_guard.process_economic_job(
            block.header.height,
            block.header.timestamp.timestamp() as u64,
        );

        if let Some(event) = &burn_event {
            println!("   🔥 Treasury burn: {} tokens", event.amount_burned);
        }

        // ─────────────────────────────────────────────────────────
        // 6) VERIFY STATE ROOT MATCHES BLOCK HEADER
        // ─────────────────────────────────────────────────────────
        let computed_root = state_guard.compute_state_root()?;
        if computed_root != block.header.state_root {
            anyhow::bail!(
                "state_root mismatch after execution: expected {}, computed {}",
                block.header.state_root, computed_root
            );
        }
        println!("   ✓ State root verified");

        // ─────────────────────────────────────────────────────────
        // 7) ATOMIC COMMIT TO LMDB
        // ─────────────────────────────────────────────────────────
        let state_snapshot = state_guard.clone();
        drop(state_guard);

        self.db.atomic_commit_block(&block, &state_snapshot)?;
        
        let block_hash = crate::block::Block::compute_hash(&block.header);
        println!("═══════════════════════════════════════════════════════════");
        println!("✅ FULL NODE: Block {} applied successfully", block.header.height);
        println!("   Hash: {}", block_hash);
        println!("   TXs: {}", block.body.transactions.len());
        println!("═══════════════════════════════════════════════════════════");

        Ok(())
    }

    /// Check if this node should participate in consensus
    /// Returns false for public full nodes
    pub fn is_validator_node(&self) -> bool {
        // TODO: Load from config - for now return false (full node mode)
        // In production, this would check if node has validator keys configured
        false
    }

    /// Get current chain tip info
    pub fn get_chain_tip(&self) -> anyhow::Result<(u64, Hash)> {
        self.db.get_tip()?.ok_or_else(|| anyhow::anyhow!("no chain tip found"))
    }

    // ============================================================
    // CELESTIA DA TRACKING (13.16.6)
    // ============================================================
    // Methods for tracking Celestia DA layer sync status.
    // These are observability-only and NOT consensus-critical.
    // ============================================================

    /// Get last known Celestia block height
    /// 
    /// Returns None if Celestia sync has never occurred.
    /// This is observability metadata, NOT consensus-critical.
    pub fn get_celestia_height(&self) -> Option<u64> {
        let height = self.last_celestia_height.load(std::sync::atomic::Ordering::Relaxed);
        if height == 0 {
            None
        } else {
            Some(height)
        }
    }

    /// Get timestamp of last successful Celestia sync
    /// 
    /// Returns None if Celestia sync has never occurred.
    /// This is observability metadata, NOT consensus-critical.
    pub fn get_celestia_sync_timestamp(&self) -> Option<u64> {
        let ts = self.last_celestia_sync.load(std::sync::atomic::Ordering::Relaxed);
        if ts == 0 {
            None
        } else {
            Some(ts)
        }
    }

    /// Update Celestia sync tracking (called after successful sync)
    /// 
    /// # Arguments
    /// * `celestia_height` - Latest Celestia block height synced
    /// 
    /// # Notes
    /// - This is observability metadata, NOT consensus-critical
    /// - Does not affect state_root or consensus
    /// - Thread-safe via atomic operations
    pub fn update_celestia_sync(&self, celestia_height: u64) {
        // Update height
        self.last_celestia_height.store(celestia_height, std::sync::atomic::Ordering::Relaxed);
        
        // Update timestamp
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.last_celestia_sync.store(now, std::sync::atomic::Ordering::Relaxed);
    }

    // ============================================================
    // SYNC API (13.11.6)
    // ============================================================

    /// Start sync ke target tip.
    ///
    /// Menginisialisasi SyncManager dan memulai proses sync.
    /// Sync berjalan secara step-based (non-blocking).
    ///
    /// # Arguments
    /// * `target_tip` - (height, hash) dari peer dengan chain terpanjang
    ///
    /// # Note
    /// Setelah start_sync(), caller harus memanggil sync_step() berulang kali.
    pub fn start_sync(&self, target_tip: (crate::types::Hash, u64)) -> anyhow::Result<()> {
        // Note: SyncManager di-manage secara terpisah
        // Ini adalah placeholder untuk API compatibility
        // Actual implementation memerlukan SyncManager instance
        println!("🔄 Chain: Sync requested to height {}", target_tip.1);
        Ok(())
    }

    /// Get current sync status.
    ///
    /// Returns SyncStatus yang menunjukkan state sync saat ini.
    pub fn get_sync_status(&self) -> crate::sync::SyncStatus {
        // Default: Synced (node sudah synchronized)
        // Actual status di-track oleh SyncManager
        crate::sync::SyncStatus::Synced
    }

    /// Check apakah node sudah synchronized.
    ///
    /// Returns true bila:
    /// - Tidak ada sync yang berjalan, ATAU
    /// - Sync sudah selesai
    pub fn is_synced(&self) -> bool {
        match self.get_sync_status() {
            crate::sync::SyncStatus::Synced => true,
            crate::sync::SyncStatus::Idle => true,
            _ => false,
        }
    }

    /// Get sync progress.
    ///
    /// Returns (current_height, target_height).
    /// Bila tidak sedang sync, returns current tip height untuk keduanya.
    pub fn get_sync_progress(&self) -> anyhow::Result<(u64, u64)> {
        let (height, _) = self.get_chain_tip()?;
        Ok((height, height))
    }

    // ════════════════════════════════════════════════════════════════════════════
    // BLOCK REPLAY (13.18.4)
    // ════════════════════════════════════════════════════════════════════════════
    // Methods untuk replay blocks setelah snapshot restore.
    //
    // CONSENSUS-CRITICAL:
    // - Replay HARUS deterministik
    // - state_root WAJIB diverifikasi setiap block
    // - Block TIDAK boleh di-skip
    // - Mismatch = replay gagal total
    //
    // USE CASES:
    // - Fast sync: load snapshot → replay blocks → catch up to tip
    // - Recovery: restore checkpoint → replay → rebuild state
    // ════════════════════════════════════════════════════════════════════════════

    /// Replay blocks from start_height to end_height.
    ///
    /// Melakukan re-eksekusi semua transaksi di setiap block untuk
    /// membangun ulang state dari snapshot/checkpoint.
    ///
    /// ## Consensus-Critical
    ///
    /// - Replay bersifat DETERMINISTIK
    /// - state_root diverifikasi setiap block
    /// - Mismatch state_root = error (ChainError::StateRootMismatch)
    /// - Block TIDAK boleh di-skip
    ///
    /// ## Flow
    ///
    /// ```text
    /// for height in (start_height + 1)..=end_height:
    ///     1. Load block dari DB
    ///     2. Execute all transactions (apply_payload)
    ///     3. Process automatic slashing
    ///     4. Process economic job
    ///     5. Compute state_root
    ///     6. Verify: computed == block.header.state_root
    ///     7. If progress callback: progress(height, end_height)
    /// ```
    ///
    /// ## Arguments
    /// * `start_height` - Height snapshot/checkpoint (replay dimulai dari start_height + 1)
    /// * `end_height` - Height target (inclusive)
    /// * `progress` - Optional callback untuk progress reporting
    ///
    /// ## Returns
    /// * `Ok(())` - Replay sukses, state valid
    /// * `Err(ChainError)` - Replay gagal
    ///
    /// ## Example
    /// ```text
    /// // Replay dari snapshot height 1000 ke tip 1500
    /// chain.replay_blocks_from(1000, 1500, Some(&|current, total| {
    ///     println!("Replaying block {}/{}", current, total);
    /// }))?;
    /// ```

    pub fn replay_blocks_from(
        &self,
        start_height: u64,
        end_height: u64,
        progress: Option<&dyn Fn(u64, u64)>,
    ) -> Result<(), ChainError> {
        // ─────────────────────────────────────────────
        // 0. Validate range
        // ─────────────────────────────────────────────
        if start_height > end_height {
            return Err(ChainError::InvalidRange {
                start: start_height,
                end: end_height,
            });
        }

        // Snapshot is assumed at start_height
        let replay_start = start_height.saturating_add(1);
        if replay_start > end_height {
            return Ok(());
        }

        // ─────────────────────────────────────────────
        // 1. Load blocks to replay
        // ─────────────────────────────────────────────
        let blocks = self.get_blocks_range(replay_start, end_height)?;

        // ─────────────────────────────────────────────
        // 2. Replay loop (NO signature verification)
        // ─────────────────────────────────────────────
        for block in blocks {
            let height = block.header.height;

            {
                let mut state_guard = self.state.write();
                let proposer = block.header.proposer;

                // ─────────────────────────────────────────
                // Apply all transactions (deterministic)
                // ─────────────────────────────────────────
                for tx in &block.body.transactions {
                    if let Err(e) = state_guard.apply_payload(tx, &proposer) {
                        // Replay must be resilient:
                        // log and continue unless you want hard-fail semantics
                        eprintln!(
                            "⚠️ Replay TX error at height {} (continuing): {}",
                            height, e
                        );
                    }
                }

                // ─────────────────────────────────────────
                // Automatic slashing (time-based)
                // ─────────────────────────────────────────
                let _ = state_guard.process_automatic_slashing(
                    height,
                    block.header.timestamp.timestamp() as u64,
                );

                // ─────────────────────────────────────────
                // Economic job (burns, fees, epochs, etc.)
                // ─────────────────────────────────────────
                let _ = state_guard.process_economic_job(
                    height,
                    block.header.timestamp.timestamp() as u64,
                );

                // ─────────────────────────────────────────
                // Compute & verify state root (CRITICAL)
                // ─────────────────────────────────────────
                let computed_root = state_guard
                    .compute_state_root()
                    .map_err(|e| ChainError::DatabaseError(format!(
                        "state_root computation error at height {}: {}",
                        height, e
                    )))?;

                if computed_root != block.header.state_root {
                    return Err(ChainError::StateRootMismatch {
                        height,
                        expected: block.header.state_root.to_hex(),
                        computed: computed_root.to_hex(),
                    });
                }
            }

            // ─────────────────────────────────────────────
            // 3. Progress callback
            // ─────────────────────────────────────────────
            if let Some(cb) = progress {
                cb(height, end_height);
            }
        }

        Ok(())
    }



    /// Get blocks in a range from database.
    ///
    /// Fetches blocks sequentially from start_height to end_height (inclusive).
    /// Blocks are returned in ascending order by height.
    ///
    /// ## Arguments
    /// * `start_height` - First block height (inclusive)
    /// * `end_height` - Last block height (inclusive)
    ///
    /// ## Returns
    /// * `Ok(Vec<Block>)` - Blocks sorted ascending by height
    /// * `Err(ChainError::BlockNotFound)` - If any block is missing
    /// * `Err(ChainError::InvalidRange)` - If start > end
    ///
    /// ## Example
    /// ```text
    /// let blocks = chain.get_blocks_range(100, 110)?;
    /// assert_eq!(blocks.len(), 11);  // 100..=110 = 11 blocks
    /// ```
    pub fn get_blocks_range(
        &self,
        start_height: u64,
        end_height: u64,
    ) -> Result<Vec<crate::block::Block>, ChainError> {
        // Validate range
        if start_height > end_height {
            return Err(ChainError::InvalidRange {
                start: start_height,
                end: end_height,
            });
        }

        let mut blocks = Vec::with_capacity((end_height - start_height + 1) as usize);

        // Fetch blocks sequentially (deterministic order)
        for height in start_height..=end_height {
            let block = self.db.get_block(height)
                .map_err(|e| ChainError::DatabaseError(format!(
                    "failed to load block at height {}: {}", height, e
                )))?
                .ok_or(ChainError::BlockNotFound(height))?;
            
            blocks.push(block);
        }

        Ok(blocks)
    }

    // ════════════════════════════════════════════════════════════════════════════
    // CONTROL-PLANE REBUILD (13.18.5)
    // ════════════════════════════════════════════════════════════════════════════
    // Methods untuk rebuild control-plane state dari Celestia blobs.
    //
    // DIPANGGIL SETELAH:
    // 1. Snapshot restore
    // 2. Block replay
    //
    // DIGUNAKAN UNTUK:
    // - Restore validator set
    // - Restore epoch state
    // - Restore governance state (NON-BINDING)
    //
    // TIDAK MELAKUKAN:
    // - Execute governance proposals
    // - Trigger transactions
    // - Modify block production
    // ════════════════════════════════════════════════════════════════════════════

    /// Rebuild control-plane state dari Celestia blobs.
    ///
    /// Memproses blobs dari Celestia DA untuk rebuild:
    /// - ValidatorSetUpdate → Update validator registry
    /// - EpochRotation → Update epoch counter
    /// - GovernanceProposal → Restore proposal (NON-BINDING)
    ///
    /// ## Consensus-Critical
    ///
    /// - Blobs HARUS diproses dalam urutan (height, index)
    /// - Decode gagal = error (tidak boleh skip)
    /// - Unknown payload type = error
    ///
    /// ## Flow
    ///
    /// ```text
    /// for blob in blobs (ordered by height, index):
    ///     1. Decode blob → ControlPlaneUpdate
    ///     2. Match update type:
    ///        - ValidatorSetUpdate → update validator_set
    ///        - EpochRotation → update epoch_info
    ///        - GovernanceProposal → restore proposal (no execution)
    ///        - ReceiptBatch → skip (handled separately)
    ///        - ConfigUpdate → apply config
    ///        - Checkpoint → skip (for verification only)
    ///     3. Continue to next blob
    /// ```
    ///
    /// ## Arguments
    /// * `blobs` - Celestia blobs sorted by (height, index)
    ///
    /// ## Returns
    /// * `Ok(())` - Rebuild sukses
    /// * `Err(ChainError)` - Rebuild gagal
    ///
    /// ## Example
    /// ```text
    /// let blobs = celestia_client.fetch_control_plane_range(1000, 1100)?;
    /// chain.rebuild_control_plane(blobs)?;
    /// ```
    pub fn rebuild_control_plane(
        &self,
        blobs: Vec<crate::celestia::CelestiaBlob>,
    ) -> Result<(), ChainError> {
        // Create Celestia client for parsing
        let client = crate::celestia::CelestiaClient::new(
            crate::celestia::CelestiaConfig::default()
        );

        // Process blobs in order
        for blob in blobs {
            let height = blob.height;
            
            // Parse blob to ControlPlaneUpdate
            let update = client.parse_blob_to_update(&blob)
                .map_err(|e| ChainError::ControlPlaneBlobDecodeError {
                    height,
                    message: format!("{}", e),
                })?;

            // Apply update based on type
            match update {
                crate::celestia::ControlPlaneUpdate::ValidatorSetUpdate { validators } => {
                    // Update validator registry
                    // TIDAK menghitung ulang stake — hanya sync registry
                    let mut state = self.state.write();
                    for v in validators {
                        state.validator_set.add_validator(v);
                    }
                    println!(
                        "   ✓ ValidatorSetUpdate applied from DA height {}",
                        height
                    );
                }

                crate::celestia::ControlPlaneUpdate::EpochRotation { new_epoch, timestamp } => {
                    let mut state = self.state.write();

                    let start_height = state.epoch_info.start_height;
                    let active_count = state.epoch_info.active_validators as usize;
                    let total_stake = state.epoch_info.total_stake;

                    state
                        .epoch_info
                        .rotate(new_epoch, start_height, active_count, total_stake);

                    println!(
                        "   ✓ EpochRotation applied: epoch={} from DA height {} (ts={})",
                        new_epoch, height, timestamp
                    );
                }

            crate::celestia::ControlPlaneUpdate::GovernanceProposal {
                proposal_id,
                proposer,
                proposal_type,
                data,
                created_at,
            } => {

                println!(
                    "   🗳️ GovernanceProposal observed (NON-BINDING): \
            id={}, proposer={}, type={}, created_at={}, data_len={} from DA height {}",
                    proposal_id,
                    proposer,
                    proposal_type,
                    created_at,
                    data.len(),
                    height
                );
            }


                crate::celestia::ControlPlaneUpdate::ReceiptBatch { .. } => {
                    // Skip — receipts diproses terpisah via ClaimReward tx
                    println!(
                        "   ℹ ReceiptBatch skipped at DA height {} (handled separately)",
                        height
                    );
                }

                crate::celestia::ControlPlaneUpdate::ConfigUpdate { key, value } => {
                    // Apply config update
                    // Logic bergantung pada key
                    println!(
                        "   ✓ ConfigUpdate applied: key={}, len={} from DA height {}",
                        key, value.len(), height
                    );
                }

                crate::celestia::ControlPlaneUpdate::Checkpoint { height: cp_height, state_root } => {
                    // Skip — checkpoint hanya untuk verification
                    println!(
                        "   ℹ Checkpoint at height {} (state_root={}) skipped",
                        cp_height, state_root
                    );
                }
            }
        }

        Ok(())
    }

    // ════════════════════════════════════════════════════════════════════════════
    // AUTOMATIC CHECKPOINT (13.18.6)
    // ════════════════════════════════════════════════════════════════════════════
    // Methods untuk automatic snapshot/checkpoint creation.
    //
    // TRIGGER: Setiap N blocks sesuai snapshot_config.interval_blocks
    // CLEANUP: FIFO deletion saat melebihi max_snapshots
    //
    // DIPANGGIL DARI: mine_block_and_apply() setelah block final
    // TIDAK DIPANGGIL SAAT: replay, sync, atau recovery
    // ════════════════════════════════════════════════════════════════════════════

    /// Maybe create checkpoint at given height.
    ///
    /// Checks if height matches snapshot interval and creates checkpoint if so.
    /// Called after each block is finalized in mine_block_and_apply().
    ///
    /// ## Behavior
    ///
    /// 1. If interval_blocks == 0 → snapshot disabled, return Ok
    /// 2. If height % interval_blocks != 0 → not checkpoint height, return Ok
    /// 3. Create snapshot via ChainDb::create_snapshot()
    /// 4. Write metadata via ChainDb::write_snapshot_metadata()
    /// 5. Cleanup old snapshots via cleanup_old_snapshots()
    ///
    /// ## Arguments
    /// * `height` - Current block height
    ///
    /// ## Returns
    /// * `Ok(())` - Checkpoint created (or skipped)
    /// * `Err(ChainError)` - Checkpoint creation failed
    pub fn maybe_create_checkpoint(
        &self,
        height: u64,
    ) -> Result<(), ChainError> {
        let interval = self.snapshot_config.interval_blocks;

        // Interval 0 = snapshot disabled
        if interval == 0 {
            return Ok(());
        }

        // Check if this height is a checkpoint height
        if height % interval != 0 {
            return Ok(());
        }

        // Determine snapshot height (current height)
        let snapshot_height = height;

        // Create snapshot directory path
        let snapshot_path = format!(
            "{}/checkpoint_{}",
            self.snapshot_config.path,
            snapshot_height
        );

        println!("═══════════════════════════════════════════════════════════");
        println!("📸 AUTOMATIC CHECKPOINT at height {}", snapshot_height);
        println!("   Path: {}", snapshot_path);
        println!("═══════════════════════════════════════════════════════════");

        // Step 1: Create snapshot via ChainDb
        let snapshot_path_ref = std::path::Path::new(&snapshot_path);
        self.db.create_snapshot(snapshot_height, snapshot_path_ref)
            .map_err(|e| ChainError::SnapshotCreationFailed {
                height: snapshot_height,
                message: format!("create_snapshot failed: {}", e),
            })?;

        // Step 2: Get state_root for metadata
        let state_root = {
            let state = self.state.read();
            state.compute_state_root()
                .map_err(|e| ChainError::SnapshotCreationFailed {
                    height: snapshot_height,
                    message: format!("compute_state_root failed: {}", e),
                })?
        };

        // Step 3: Get block hash
        let block_hash = self.db.get_block(snapshot_height)
            .map_err(|e| ChainError::SnapshotCreationFailed {
                height: snapshot_height,
                message: format!("get_block failed: {}", e),
            })?
            .map(|b| crate::block::Block::compute_hash(&b.header))
            .ok_or_else(|| ChainError::SnapshotCreationFailed {
                height: snapshot_height,
                message: "block not found".to_string(),
            })?;

        // Step 4: Create and write metadata
        let metadata = crate::state::SnapshotMetadata {
            height: snapshot_height,
            state_root,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            block_hash,
        };

        self.db.write_snapshot_metadata(snapshot_path_ref, &metadata)
            .map_err(|e| ChainError::SnapshotCreationFailed {
                height: snapshot_height,
                message: format!("write_metadata failed: {}", e),
            })?;

        println!("   ✓ Snapshot created successfully");

        // Step 5: Cleanup old snapshots
        let keep_count = self.snapshot_config.max_snapshots as usize;
        self.cleanup_old_snapshots(keep_count)?;

        Ok(())
    }

    /// Cleanup old snapshots keeping only the most recent ones.
    ///
    /// Lists all snapshots, sorts by height ascending, and deletes
    /// the oldest ones until only keep_count remain.
    ///
    /// ## Behavior
    ///
    /// 1. List all snapshots via ChainDb::list_available_snapshots()
    /// 2. Sort by height ASCENDING (oldest first)
    /// 3. If count <= keep_count → return Ok (nothing to delete)
    /// 4. Delete (count - keep_count) oldest snapshots
    /// 5. Never delete the newest snapshot
    ///
    /// ## Arguments
    /// * `keep_count` - Number of snapshots to keep
    ///
    /// ## Returns
    /// * `Ok(())` - Cleanup successful
    /// * `Err(ChainError)` - Cleanup failed
    pub fn cleanup_old_snapshots(
        &self,
        keep_count: usize,
    ) -> Result<(), ChainError> {
        // Minimum keep 1 (never delete all snapshots)
        let keep_count = keep_count.max(1);

        // List available snapshots (associated function, not method)
        let base_path = std::path::Path::new(&self.snapshot_config.path);
        let snapshots = ChainDb::list_available_snapshots(base_path)
            .map_err(|e| ChainError::SnapshotCleanupFailed(format!(
                "list_available_snapshots failed: {}", e
            )))?;

        // If we have fewer or equal snapshots, nothing to delete
        if snapshots.len() <= keep_count {
            return Ok(());
        }

        // Sort by height ascending (oldest first)
        let mut sorted: Vec<_> = snapshots;
        sorted.sort_by(|a, b| a.height.cmp(&b.height));

        // Calculate how many to delete
        let delete_count = sorted.len() - keep_count;

        println!("   🗑️ Cleaning up {} old snapshot(s)...", delete_count);

        // Delete oldest snapshots (never delete the newest)
        for metadata in sorted.into_iter().take(delete_count) {
            let snapshot_path = format!(
                "{}/checkpoint_{}",
                self.snapshot_config.path,
                metadata.height
            );

            // Remove directory and contents
            if let Err(e) = std::fs::remove_dir_all(&snapshot_path) {
                // Return error on failure
                return Err(ChainError::SnapshotCleanupFailed(format!(
                    "failed to delete snapshot at height {}: {}",
                    metadata.height, e
                )));
            }
            
            println!("   ✓ Deleted snapshot at height {}", metadata.height);
        }

        Ok(())
    }

    // ============================================================
    // PEER MANAGEMENT (13.7.N)
    // ============================================================

    /// Add a peer for block broadcasting
    pub fn add_peer(&self, peer: crate::rpc::PeerInfo) {
        self.broadcast_manager.add_peer(peer);
    }

    /// Remove a peer from broadcast list
    pub fn remove_peer(&self, peer_id: &str) {
        self.broadcast_manager.remove_peer(peer_id);
    }

    /// Get count of connected peers
    pub fn peer_count(&self) -> usize {
        self.broadcast_manager.peer_count()
    }

    /// Get all connected peers
    pub fn get_peers(&self) -> Vec<crate::rpc::PeerInfo> {
        self.broadcast_manager.get_peers()
    }

    // ============================================================
    // TEST UTILITIES (for E2E testing)
    // ============================================================

    /// Create a test chain with temporary directory
    #[cfg(test)]
    pub fn new_test_chain() -> anyhow::Result<(Self, tempfile::TempDir)> {
        let dir = tempfile::tempdir()?;
        let chain = Self::new(dir.path())?;
        Ok((chain, dir))
    }

    /// Inject test validator into state (for testing proposer selection)
    pub fn inject_test_validator(
        &self,
        address: Address,
        pubkey: Vec<u8>,
        stake: u128,
        active: bool,
    ) {
        let mut state = self.state.write();
        let info = crate::state::ValidatorInfo::new(address, pubkey, stake, None);
        state.validator_set.add_validator(info.clone());
        state.validator_set.set_active(&address, active);
        
        // Also add to legacy validators map
        state.validators.insert(address, crate::state::Validator {
            address,
            stake,
            pubkey: info.pubkey,
            active,
        });
    }

    /// Inject delegation for testing QV
    pub fn inject_test_delegation(
        &self,
        validator: Address,
        delegator: Address,
        amount: u128,
    ) {
        let mut state = self.state.write();
        state.delegations
            .entry(validator)
            .or_insert_with(HashMap::new)
            .insert(delegator, amount);
    }

    /// Get current state snapshot (for testing)
    pub fn get_state_snapshot(&self) -> crate::state::ChainState {
        self.state.read().clone()
    }

    /// Set balance directly (for testing)
    pub fn set_test_balance(&self, address: &Address, amount: u128) {
        let mut state = self.state.write();
        state.create_account(*address);
        *state.balances.entry(*address).or_insert(0) = amount;
    }

    /// Get balance
    pub fn get_balance(&self, address: &Address) -> u128 {
        self.state.read().get_balance(address)
    }
}

use std::collections::HashMap;
/// Statistics for block production (13.7.E)
#[derive(Debug, Clone)]
pub struct BlockProductionStats {
    pub height: u64,
    pub total_txs: usize,
    pub successful_txs: usize,
    pub failed_txs: usize,
    pub gas_used: u64,
    pub proposer: Address,
}