//! # Chain State Management Module
//! 
//! Module ini adalah **ENTRY POINT** dan **FACADE** untuk seluruh state management
//! blockchain DSDN (Data Semi-Decentral Network).
//! 
//! ## Arsitektur
//! 
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                         mod.rs (FACADE)                         │
//! │  - ChainState struct definition                                 │
//! │  - Constructor new()                                            │
//! │  - Public re-exports                                            │
//! └─────────────────────────────────────────────────────────────────┘
//!                                    │
//!          ┌─────────────────────────┼─────────────────────────┐
//!          ▼                         ▼                         ▼
//!  ┌──────────────┐         ┌──────────────┐         ┌──────────────┐
//!  │   Account    │         │   Staking    │         │   QV Cache   │
//!  │  Management  │         │  Management  │         │  Management  │
//!  └──────────────┘         └──────────────┘         └──────────────┘
//!          │                         │                         │
//!          ▼                         ▼                         ▼
//!  ┌──────────────┐         ┌──────────────┐         ┌──────────────┐
//!  │     Fees     │         │   Rewards    │         │   Unstake    │
//!  │  Management  │         │ Distribution │         │    Queue     │
//!  └──────────────┘         └──────────────┘         └──────────────┘
//!          │                         │                         │
//!          ▼                         ▼                         ▼
//!  ┌──────────────┐         ┌──────────────┐         ┌──────────────┐
//!  │   Slashing   │         │    State     │         │   Payload    │
//!  │   Adapter    │         │    Layout    │         │  Execution   │
//!  └──────────────┘         └──────────────┘         └──────────────┘
//!                                    │
//!                                    ▼
//!                           ┌──────────────┐
//!                           │  State Root  │
//!                           │ Computation  │
//!                           └──────────────┘
//! ```
//! 
//! ## Module Structure
//! 
//! | Module | Fungsi | Reference |
//! |--------|--------|-----------|
//! | `internal_model` | Data structures: UnstakeEntry, Validator, ValidatorInfo, ValidatorSet | 13.8.G |
//! | `internal_account` | Account CRUD: create, balance, nonce, mint | Core |
//! | `internal_staking` | Staking lifecycle: bond, unbond, delegation | 13.8.A/B |
//! | `internal_qv_cache` | Quadratic Voting weights & caching | 13.8.C/D |
//! | `internal_fees` | Fee pool management per ResourceClass | 13.8.E |
//! | `internal_rewards` | Delegator reward distribution with annual cap | 13.8.F |
//! | `internal_unstake_queue` | 7-day unstake delay processing | 13.8.G |
//! | `internal_slash_adapter` | Slashing logic for validators & delegators | 13.8.J |
//! | `internal_state_layout` | LMDB persistence helpers | 13.8.H |
//! | `internal_payload` | Transaction execution (apply_payload) | 13.7.E/F/G |
//! | `internal_state_root` | Merkle state root computation | Core |
//! | `internal_misc` | Treasury, epoch, liveness helpers | 13.7.K/L |
//! | `internal_receipt` | Receipt verification & claim tracking | 13.10 |
//!  `internal_governance` | Governance data structures: Proposal, Vote, Config | 13.12 |
//! 
//! ## Dependency Rules (PENTING!)
//! 
//! Module ini **TIDAK** menduplikasi module crate-level yang sudah ada:
//! - `crate::qv` → Quadratic Voting formula (sqrt calculation)
//! - `crate::slashing` → Slashing rules & LivenessRecord
//! - `crate::epoch` → Epoch rotation logic
//! - `crate::db` → LMDB persistence types
//! - `crate::tokenomics` → Economic constants & fee calculations
//! 
//! ## Consensus Constants
//! 
//! Gas rules & stake minimum didefinisikan di:
//! - `internal_payload.rs` → FIXED_GAS_* constants
//! - `crate::tokenomics` → VALIDATOR_MIN_STAKE, DELEGATOR_MIN_STAKE
//! 
//! Nilai-nilai ini adalah **consensus-critical** dan tidak boleh diubah
//! tanpa hard fork.
//!
//! ## 13.9 — GAS MODEL & FEE SPLIT (CONSENSUS-CRITICAL)
//!
//! ### Rumus Gas Model
//!
//! ```text
//! GAS = (BASE_OP_COST + (DATA_BYTES * PER_BYTE_COST) + (COMPUTE_CYCLES * PER_COMPUTE_CYCLE_COST)) * NODE_MULTIPLIER / 100
//! ```
//!
//! Konstanta (defined in `internal_gas.rs`):
//! - `BASE_OP_TRANSFER` = 21,000
//! - `BASE_OP_STORAGE_OP` = 50,000
//! - `BASE_OP_COMPUTE_OP` = 100,000
//! - `PER_BYTE_COST` = 16
//! - `PER_COMPUTE_CYCLE_COST` = 1
//! - `DEFAULT_NODE_COST_INDEX` = 100 (basis 100 = 1.0x multiplier)
//!
//! ### Fee Split Table
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
//! ### Anti-Self-Dealing Rule
//!
//! ```text
//! Jika service_node == sender:
//!     node_share dialihkan seluruhnya ke treasury.
//! ```
//!
//! ### Lokasi File Logika
//!
//! - `state/internal_gas.rs`
//! - `state/internal_node_cost.rs`
//! - `state/internal_fees.rs`
//! - `state/internal_payload.rs`
//! - `tokenomics.rs`
//! - `state/internal_state_root.rs`
//! - `state/internal_state_layout.rs`
//! - `db.rs`
//!
//! ### Catatan Konsensus
//!
//! ```text
//! PERINGATAN: Semua konstanta dan aturan di bagian 13.9 bersifat consensus-critical.
//! Perubahan apa pun terhadap nilai konstanta, rumus gas, fee split, atau aturan anti-self-dealing memerlukan hard-fork.
//! ```
//!
//! ### Testing Checklist
//!
//! ```text
//! - Fee split numeric tests (70/20/10)
//! - Transfer/governance/stake → 100% validator
//! - Anti-self-dealing node case
//! ```
//!
//! ## 13.10 — RESOURCE RECEIPT & CLAIMREWARD (CONSENSUS-CRITICAL)
//!
//! ### Receipt Structure
//!
//! `ResourceReceipt` adalah bukti eksekusi resource dari Coordinator:
//!
//! ```text
//! ResourceReceipt {
//!     receipt_id: Hash,              // Unique ID (SHA3-512)
//!     node_address: Address,         // Service node yang melayani
//!     node_class: NodeClass,         // Storage / Compute
//!     resource_type: ResourceType,   // Tipe resource (StorageUpload, etc)
//!     measured_usage: MeasuredUsage, // Usage metrics
//!     reward_base: u128,             // Nominal reward dari Coordinator
//!     anti_self_dealing_flag: bool,  // Anti-self-dealing enforcement
//!     timestamp: u64,                // Unix timestamp saat eksekusi
//!     coordinator_signature: Vec<u8>, // Ed25519 signature dari Coordinator
//! }
//! ```
//!
//! ### Verification Flow
//!
//! Receipt diverifikasi SEBELUM reward diproses dengan urutan WAJIB:
//!
//! 1. **Coordinator Signature** — Ed25519 verification dengan COORDINATOR_PUBKEY
//! 2. **Double-Claim Check** — Receipt belum pernah di-claim (via claimed_receipts)
//! 3. **Node Address Match** — Sender harus sama dengan receipt.node_address
//! 4. **Anti-Self-Dealing Flag** — Flag harus true
//! 5. **Timestamp Validity** — Timestamp harus lebih dari 0
//!
//! ### Reward Distribution
//!
//! ClaimReward mendistribusikan reward_base dengan split FIXED:
//!
//! ```text
//! node_share      = reward_base * 70 / 100
//! validator_share = reward_base * 20 / 100
//! treasury_share  = reward_base - node_share - validator_share
//! ```
//!
//! Alokasi:
//! - `node_share` → `balances[node_address]` + `node_earnings[node_address]`
//! - `validator_share` → `balances[proposer]`
//! - `treasury_share` → `treasury_balance`
//!
//! ### Anti-Self-Dealing Rule
//!
//! ```text
//! Kondisi anti-self-dealing (node_share dialihkan ke treasury):
//! - anti_self_dealing_flag == true, ATAU
//! - node_address == sender
//!
//! Ketika triggered:
//!     treasury_share += node_share
//!     node_share = 0
//! ```
//! ## 13.11 — P2P NETWORK & SYNC
//!
//! ### Overview
//!
//! Dokumentasi ini mendefinisikan arsitektur sinkronisasi P2P DSDN.
//! Semua node melakukan sinkronisasi chain, state, dan control-plane
//! secara deterministik dan dapat diverifikasi.
//!
//! Module sync menyediakan protokol sinkronisasi untuk full node DSDN.
//! Tujuan utama:
//! - Sinkronisasi headers untuk validasi chain structure
//! - Download blocks setelah headers terverifikasi
//! - Replay state dari LMDB untuk rekonstruksi ChainState
//! - Integrasi dengan Celestia DA untuk control-plane state
//!
//! ### Sync Flow (High-Level)
//!
//! ```text
//! 1. Header Sync: [local_tip → target_tip]
//!    - Download headers dari peer
//!    - Verify chain linkage (CONSENSUS-CRITICAL)
//!    - Persist ke LMDB
//!
//! 2. Block Sync: download full blocks
//!    - Validate block vs expected header
//!    - Retry mechanism (max 3)
//!
//! 3. State Replay: execute transactions & verify state_root
//!    - Deterministic execution via apply_payload
//!    - state_root verification mandatory (CONSENSUS-CRITICAL)
//!
//! 4. Celestia Sync: apply control-plane updates
//!    - ReceiptBatch, ValidatorSetUpdate, ConfigUpdate, Checkpoint
//!
//! 5. Atomic Commit: persist final state to LMDB
//!    - Single commit point (CONSENSUS-CRITICAL)
//!    - Error before commit = no data saved
//! ```
//!
//!
//! ### Sync Types (Definisi di `sync.rs`)
//!
//! ```text
//! SyncStatus      — Status mesin sync saat ini
//! SyncRequest     — Request dari peer untuk data
//! SyncResponse    — Response berisi data yang diminta
//! SyncConfig      — Konfigurasi sync protocol
//! PeerSyncState   — Status sync dari peer tertentu
//! ```
//!
//! ### SyncStatus States
//!
//! ```text
//! Idle            — Tidak sedang sync, node idle
//! SyncingHeaders  — Sedang download & verify headers
//! SyncingBlocks   — Sedang download full blocks
//! SyncingState    — Sedang replay state dari checkpoint
//! Synced          — Sync selesai, node synchronized
//! ```
//!
//! ### State Transitions
//!
//! ```text
//! Idle → SyncingHeaders    : sync dimulai
//! SyncingHeaders → SyncingBlocks : semua headers diterima & verified
//! SyncingBlocks → SyncingState   : semua blocks downloaded
//! SyncingState → Synced          : state replay selesai
//! Synced → Idle                  : sync di-reset
//! Any → Idle                     : sync dibatalkan
//! ```
//!
//! ### SyncConfig Defaults
//!
//! ```text
//! max_headers_per_request = 500
//! max_blocks_per_request  = 100
//! sync_timeout_ms         = 30000 (30 detik)
//! batch_size              = 50
//! ```
//!
//! ### Header-First Sync Flow (13.11.2)
//!
//! HeaderSyncer melakukan validasi chain structure sebelum block body di-download.
//!
//! ```text
//! Alur Sync:
//! 1. Tentukan local_tip (height, hash) dari LMDB
//! 2. Terima target_tip dari peer
//! 3. Request headers: GetHeaders { start: local_tip + 1, count: 500 }
//! 4. Verifikasi header chain (CONSENSUS-CRITICAL)
//! 5. Persist headers ke LMDB: headers/{height}
//! 6. Ulangi sampai semua headers terverifikasi
//! 7. Lanjut ke Block Sync (sub-tahap 11.3)
//! ```
//!
//! ### Header Validation Rules (CONSENSUS-CRITICAL)
//!
//! ```text
//! Semua rules berikut WAJIB dipatuhi. Pelanggaran = abort sync.
//!
//! 1. height == previous.height + 1
//!    Header harus sequential, tidak boleh skip height.
//!
//! 2. parent_hash == compute_hash(previous)
//!    Parent hash harus match dengan hash header sebelumnya.
//!
//! 3. proposer != zero_address
//!    Proposer harus address valid (bukan 0x00...00).
//!
//! 4. timestamp > previous.timestamp
//!    Timestamp harus strictly increasing.
//! ```
//!
//! ### Header Storage (LMDB)
//!
//! ```text
//! Bucket: headers
//! Key:    height (big-endian u64, 8 bytes)
//! Value:  bincode serialized BlockHeader
//!
//! Methods:
//! - put_header(height, header) → Result<()>
//! - get_header(height) → Result<Option<BlockHeader>>
//! - get_headers_range(start, end) → Result<Vec<BlockHeader>>
//! ```
//!
//! ### Block Sync Flow (13.11.3)
//!
//! BlockSyncer mengambil full blocks berdasarkan headers yang sudah terverifikasi.
//!
//! ```text
//! Alur Block Sync:
//! 1. HeaderSyncer selesai → headers tersimpan di LMDB
//! 2. Buat BlockSyncer dari list (height, hash) headers
//! 3. Request blocks: GetBlocks { heights: [101, 102, ...] }
//! 4. Validasi block terhadap expected header (CONSENSUS-CRITICAL)
//! 5. Simpan block ke fetched_blocks
//! 6. Ulangi sampai semua blocks tervalidasi
//! 7. Lanjut ke State Replay (sub-tahap 11.4)
//! ```
//!
//! ### Block Validation Rules (CONSENSUS-CRITICAL)
//!
//! ```text
//! Semua rules berikut WAJIB dipatuhi. Pelanggaran = block ditolak.
//!
//! 1. block.header == expected_header (exact match)
//!    Semua fields harus identik: height, parent_hash, state_root,
//!    tx_root, timestamp, proposer.
//!
//! 2. block.verify_signature() sukses
//!    Signature proposer atas block header harus valid.
//!
//! 3. Semua tx.verify_signature() sukses
//!    Setiap transaksi dalam block harus memiliki signature valid.
//! ```
//!
//! ### Retry Mechanism
//!
//! ```text
//! - Maksimum retry per height: 3
//! - Retry count disimpan di retry_count HashMap
//! - Setelah 3 kali gagal:
//!   - Height masuk ke failed_heights
//!   - Dihapus dari headers_to_fetch
//! - Block yang gagal validasi TIDAK BOLEH dieksekusi
//! ```
//!
//! ### BlockSyncer Fields
//!
//! ```text
//! headers_to_fetch: VecDeque<(u64, Hash)>  — headers yang belum di-fetch
//! fetched_blocks:   HashMap<u64, Block>    — blocks yang sudah valid
//! failed_heights:   HashSet<u64>           — heights yang gagal >3x
//! retry_count:      HashMap<u64, u32>      — counter retry per height
//! ```
//!
//! ### State Replay Engine (13.11.4)
//!
//! StateReplayEngine melakukan rebuild ChainState dari blocks secara deterministik.
//!
//! ```text
//! Alur Replay:
//! 1. Buat StateReplayEngine dengan range [start, end]
//! 2. Pilih mode: replay_from_genesis() atau replay_from_checkpoint()
//! 3. Untuk setiap block dalam range:
//!    a. Load block dari DB
//!    b. Execute semua TX via apply_payload (CONSENSUS-CRITICAL)
//!    c. Compute state_root
//!    d. Verify state_root == block.header.state_root
//!    e. Lanjut ke block berikutnya
//! 4. Ambil final state via get_final_state()
//! ```
//!
//! ### Replay Modes
//!
//! ```text
//! 1. replay_from_genesis()
//!    - Mulai dari ChainState kosong
//!    - Replay height 0 sampai end_height
//!    - Untuk initial sync atau disaster recovery
//!
//! 2. replay_from_checkpoint(height, state)
//!    - Mulai dari checkpoint state
//!    - Replay height+1 sampai end_height
//!    - Untuk fast sync atau partial recovery
//! ```
//!
//! ### Checkpoint Format
//!
//! ```text
//! Serialization: bincode
//! Content: Full ChainState snapshot
//! Deterministic: Yes (same state = same bytes)
//!
//! Functions:
//! - create_checkpoint(state) → Vec<u8>
//! - restore_from_checkpoint(bytes) → ChainState
//! ```
//!
//! ### Error Handling
//!
//! ```text
//! FATAL (replay stops):
//! - BlockNotFound: block tidak ada di DB
//! - StateRootMismatch: computed != expected
//!
//! NON-FATAL (logged, continue):
//! - TxExecutionError: TX gagal tapi replay lanjut
//! ```
//!
//! ### Consensus-Critical Notes
//!
//! ```text
//! PERINGATAN: Komponen berikut adalah CONSENSUS-CRITICAL:
//!
//! 1. Urutan replay HARUS sequential (N → N+1 → N+2 → ...)
//! 2. apply_payload HARUS identik dengan mining node
//! 3. state_root verification WAJIB setelah setiap block
//! 4. TX error TIDAK menghentikan replay (sesuai perilaku miner)
//!
//! Replay yang tidak deterministik akan menghasilkan state_root berbeda
//! dan menyebabkan StateRootMismatch.
//! ```
//!
//! ### StateReplayEngine Fields
//!
//! ```text
//! chain:            Chain         — akses DB untuk load blocks
//! start_height:     u64           — height awal replay
//! end_height:       u64           — height akhir replay (inclusive)
//! current_height:   u64           — height saat ini
//! state_checkpoint: Option<ChainState> — state hasil replay
//! ```
//! ### Celestia DA Integration (13.11.5)
//!
//! CelestiaClient dan ControlPlaneSyncer untuk sinkronisasi control-plane state.
//!
//! ```text
//! Peran Celestia:
//! - Data Availability layer untuk control-plane state
//! - BUKAN untuk block data atau transactions
//! - Read-only access dari DSDN chain
//! ```
//!
//! ### ControlPlaneUpdate Types
//!
//! ```text
//! ReceiptBatch        — Batch ResourceReceipt dari Coordinator
//! ValidatorSetUpdate  — Perubahan validator set
//! ConfigUpdate        — Parameter konfigurasi chain
//! Checkpoint          — State snapshot reference (height + state_root)
//! ```
//!
//! ### Namespace Format
//!
//! ```text
//! Namespace ID: 8 bytes
//! Default: "dsdn_ctl" (0x6473646E5F63746C)
//! 
//! Blob format:
//! - Byte 0: type tag (0=Receipt, 1=Validator, 2=Config, 3=Checkpoint)
//! - Byte 1..N: bincode serialized data
//! ```
//!
//! ### Consensus-Critical Notes
//!
//! ```text
//! PERINGATAN: Control-plane updates adalah CONSENSUS-CRITICAL:
//!
//! 1. ReceiptBatch
//!    - Receipts harus diverifikasi sebelum ClaimReward
//!    - Double-claim protection tetap di chain layer
//!
//! 2. ValidatorSetUpdate
//!    - Mempengaruhi proposer selection
//!    - Mempengaruhi stake weights
//!
//! 3. Checkpoint
//!    - Untuk fast sync verification
//!    - state_root harus match saat replay
//!
//! 4. ConfigUpdate
//!    - Parameter changes require coordination
//!    - Affecting fee/gas = hard fork
//! ```
//!
//! ### CelestiaClient Methods
//!
//! ```text
//! fetch_blobs(height, namespace)      — Fetch blobs dari DA height
//! fetch_blobs_range(start, end, ns)   — Fetch range of heights
//! parse_control_plane_blob(blob)      — Parse blob ke ControlPlaneUpdate
//! verify_blob_commitment(blob, comm)  — Verify blob authenticity
//! ```
//!
//! ### ControlPlaneSyncer Methods
//!
//! ```text
//! sync_from_height(height)  — Fetch dan queue updates dari height
//! apply_updates(chain)      — Apply pending updates ke Chain
//! get_pending_receipts()    — Extract receipts dari queue
//! ```
//!
//! ### Sync Manager & Orchestration (13.11.6)
//!
//! SyncManager adalah orchestrator tunggal untuk seluruh sync lifecycle.
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                        SYNC FLOW DIAGRAM                            │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │                                                                     │
//! │  ┌──────┐    ┌────────────────┐    ┌──────────────┐    ┌─────────┐ │
//! │  │ Idle │───►│ SyncingHeaders │───►│ SyncingBlocks│───►│Syncing  │ │
//! │  └──────┘    └────────────────┘    └──────────────┘    │  State  │ │
//! │                     │                     │            └────┬────┘ │
//! │                     ▼                     ▼                 │      │
//! │              ┌──────────────┐      ┌──────────────┐         │      │
//! │              │ HeaderSyncer │      │ BlockSyncer  │         │      │
//! │              └──────────────┘      └──────────────┘         │      │
//! │                                                             ▼      │
//! │                                    ┌───────────────────────────┐   │
//! │                                    │ StateReplayEngine         │   │
//! │                                    │ + ControlPlaneSyncer      │   │
//! │                                    └─────────────┬─────────────┘   │
//! │                                                  │                 │
//! │                                                  ▼                 │
//! │                                           ┌──────────┐            │
//! │                                           │  Synced  │            │
//! │                                           └──────────┘            │
//! │                                                  │                 │
//! │                                                  ▼                 │
//! │                                    ┌───────────────────────────┐   │
//! │                                    │ ATOMIC COMMIT (LMDB)      │   │
//! │                                    │ - State snapshot          │   │
//! │                                    │ - Update tip              │   │
//! │                                    └───────────────────────────┘   │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ### State Transitions
//!
//! ```text
//! Idle → SyncingHeaders
//!     Trigger: start_sync(target_tip)
//!     Action:  Initialize HeaderSyncer
//!
//! SyncingHeaders → SyncingBlocks
//!     Trigger: HeaderSyncer.is_complete()
//!     Action:  Initialize BlockSyncer dari verified headers
//!
//! SyncingBlocks → SyncingState
//!     Trigger: BlockSyncer.is_complete()
//!     Action:  Initialize StateReplayEngine
//!
//! SyncingState → Synced
//!     Trigger: StateReplayEngine.is_complete()
//!     Action:  Apply Celestia updates, atomic commit
//!
//! Any → Idle
//!     Trigger: cancel_sync()
//!     Action:  Reset semua syncers
//! ```
//!
//! ### Peran Masing-Masing Syncer
//!
//! ```text
//! HeaderSyncer (13.11.2)
//!     - Download headers via GetHeaders request
//!     - Verify chain linkage (CONSENSUS-CRITICAL)
//!     - Persist headers ke LMDB
//!
//! BlockSyncer (13.11.3)
//!     - Download full blocks via GetBlocks request
//!     - Validate block vs expected header
//!     - Retry mechanism (max 3)
//!
//! StateReplayEngine (13.11.4)
//!     - Rebuild ChainState dari blocks
//!     - Execute TX via apply_payload
//!     - Verify state_root (CONSENSUS-CRITICAL)
//!
//! ControlPlaneSyncer (13.11.5)
//!     - Sync control-plane dari Celestia DA
//!     - Apply validator updates
//!     - Extract receipt batches
//! ```
//!
//! ### Error Recovery Strategy
//!
//! ```text
//! Header validation failed → Abort sync, stay Idle
//! Block fetch failed (>3x) → Abort sync dengan error
//! State root mismatch     → Abort sync dengan error
//! Celestia sync failed    → Log warning, continue
//!
//! Error sebelum atomic commit = TIDAK ADA DATA TERSIMPAN
//! ```
//!
//! ### Consensus-Critical Notes
//!
//! ```text
//! PERINGATAN: Komponen berikut adalah CONSENSUS-CRITICAL:
//!
//! 1. Replay Order
//!    - Block HARUS diproses sequential (N → N+1 → N+2)
//!    - Skip block = state_root mismatch
//!
//! 2. State Root Verification
//!    - computed_root HARUS == block.header.state_root
//!    - Mismatch = sync abort
//!
//! 3. Atomic Commit
//!    - State di-commit SATU KALI setelah semua tahap selesai
//!    - Error sebelum commit = rollback
//!    - Partial commit DILARANG
//!
//! 4. Transaction Execution
//!    - TX error TIDAK menghentikan replay
//!    - Sesuai behavior mining node
//! ```
//!
//! ### 13.11.7 — RPC & CLI Sync Interface
//!
//! Interface layer untuk mengontrol dan memonitor sync process.
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                     RPC & CLI SYNC INTERFACE                        │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │                                                                     │
//! │  CLI Commands              RPC Methods                              │
//! │  ────────────              ───────────                              │
//! │  sync start     ──────►    start_sync()                            │
//! │  sync stop      ──────►    stop_sync()                             │
//! │  sync status    ──────►    get_sync_status()                       │
//! │  sync progress  ──────►    get_sync_progress()                     │
//! │  sync reset                                                         │
//! │                            handle_sync_request()                    │
//! │                                   │                                 │
//! │                                   ▼                                 │
//! │                             ┌───────────┐                           │
//! │                             │   Chain   │                           │
//! │                             └─────┬─────┘                           │
//! │                                   │                                 │
//! │                                   ▼                                 │
//! │                          ┌──────────────┐                           │
//! │                          │ SyncManager  │                           │
//! │                          └──────────────┘                           │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ### RPC Methods (13.11.7)
//!
//! ```text
//! get_sync_status()           → SyncStatusRes { status, current, target }
//! start_sync()                → Result<(), RpcError>
//! stop_sync()                 → Result<(), RpcError>
//! get_sync_progress()         → SyncProgressRes { current, target, percent }
//! handle_sync_request(req)    → SyncResponse
//! ```
//!
//! ### CLI Commands (13.11.7)
//!
//! ```text
//! sync start      Mulai sync ke network tip
//! sync stop       Hentikan sync yang berjalan
//! sync status     Tampilkan: Status, Current, Target
//! sync progress   Tampilkan: [██████░░░░] 60% | 600/1000 | ETA 04:00
//! sync reset      Reset state ke genesis
//! ```
//!
//! ### Prinsip Desain
//!
//! ```text
//! 1. RPC/CLI TIDAK mengandung logika sync
//! 2. Semua delegasi ke Chain → SyncManager
//! 3. Read-only untuk status/progress queries
//! 4. Non-blocking operations
//! 5. Idempotent commands (start saat Synced = no-op)
//! ```
//! ### Error Handling & Recovery
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                     ERROR HANDLING MATRIX                           │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │                                                                     │
//! │  Error Type              Action            Recovery                 │
//! │  ──────────────────────────────────────────────────────────────     │
//! │  Header invalid          Drop peer         Request from other peer │
//! │  Block invalid           Retry (max 3)     Mark as failed          │
//! │  Block fetch timeout     Retry with exp    Switch peer             │
//! │  State root mismatch     HALT SYNC         Manual investigation    │
//! │  Celestia fetch fail     Retry + backoff   Continue without DA     │
//! │  Commit failure          HALT SYNC         Rollback + retry        │
//! │                                                                     │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ### Files
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                     FILE REFERENCE (13.11)                          │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │                                                                     │
//! │  File           Contents                                            │
//! │  ─────────────────────────────────────────────────────────────      │
//! │  sync.rs        SyncStatus, SyncRequest, SyncResponse               │
//! │                 SyncConfig, PeerSyncState                           │
//! │                 HeaderSyncer (13.11.2)                              │
//! │                 BlockSyncer (13.11.3)                               │
//! │                 StateReplayEngine (13.11.4)                         │
//! │                 SyncManager (13.11.6)                               │
//! │                                                                     │
//! │  celestia.rs    CelestiaConfig, CelestiaClient                      │
//! │                 ControlPlaneUpdate enum                             │
//! │                 ControlPlaneSyncer (13.11.5)                        │
//! │                                                                     │
//! │  rpc.rs         SyncStatusRes, SyncProgressRes                      │
//! │                 get_sync_status(), start_sync(), stop_sync()        │
//! │                 get_sync_progress(), handle_sync_request()          │
//! │                                                                     │
//! │  cli.rs         SyncCommand enum                                    │
//! │                 sync start/stop/status/progress/reset               │
//! │                                                                     │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ### Catatan Implementasi
//!
//! Sub-tahap yang sudah diimplementasi:
//! - 11.1: Sync Types (SyncStatus, SyncRequest, SyncResponse, SyncConfig, PeerSyncState)
//! - 11.2: Header Sync (HeaderSyncer, header validation, LMDB persistence)
//! - 11.3: Block Sync (BlockSyncer, block validation, retry mechanism)
//! - 11.4: State Replay Engine (StateReplayEngine, checkpoint, deterministic replay)
//! - 11.5: Celestia DA Integration (CelestiaClient, ControlPlaneSyncer)
//! - 11.6: Sync Manager & Orchestration (SyncManager, atomic commit)
//! - 11.7: RPC & CLI Sync Interface (RPC methods, CLI commands)
//! - 11.8: Documentation Update (this section)
//!
//! TAHAP 13.11 — P2P NETWORK & SYNC: COMPLETE ✅
//!
//! ### ClaimReward Execution (internal_payload.rs)
//!
//! ```text
//! 1. verify_receipt(&receipt, &sender) → ReceiptError jika gagal
//! 2. Hitung distribusi 70/20/10
//! 3. Apply anti-self-dealing rule
//! 4. Credit balances: node, validator, treasury
//! 5. Update node_earnings[node_address]
//! 6. mark_receipt_claimed(receipt.receipt_id)
//! 7. Deduct fee dari sender
//! 8. Return gas_used
//! ```
//!
//! ### Anti-Replay via claimed_receipts
//!
//! ```text
//! - claimed_receipts: HashSet<Hash> di ChainState
//! - Dipersist di LMDB bucket: claimed_receipts/{receipt_id}
//! - Key: receipt_id (64 bytes)
//! - Value: marker byte (0x01)
//! - Restore saat startup via load_from_state_layout()
//! - Termasuk dalam state_root (posisi #25)
//! ```
//!
//! ### Lokasi File Logika
//!
//! | File | Fungsi |
//! |------|--------|
//! | `receipt.rs` | ResourceReceipt struct, COORDINATOR_PUBKEY, verify_coordinator_signature |
//! | `state/internal_receipt.rs` | ReceiptError, verify_receipt, is_receipt_claimed, mark_receipt_claimed |
//! | `state/internal_payload.rs` | ClaimReward handler di apply_payload |
//! | `state/internal_state_root.rs` | claimed_receipts hashing (posisi #25) |
//! | `state/internal_state_layout.rs` | export/load claimed_receipts |
//! | `db.rs` | BUCKET_CLAIMED_RECEIPTS, put_claimed_receipt, load_all_claimed_receipts |
//!
//! ### Consensus-Critical Notes
//!
//! ```text
//! PERINGATAN: Komponen berikut adalah CONSENSUS-CRITICAL:
//!
//! - COORDINATOR_PUBKEY di receipt.rs (hardcoded, ganti sebelum mainnet)
//! - Verification order (5 langkah, tidak boleh diubah)
//! - Reward distribution formula (70/20/10)
//! - Anti-self-dealing rule
//! - claimed_receipts dalam state_root (posisi #25)
//! - ReceiptError enum variants
//!
//! Perubahan pada komponen di atas memerlukan HARD-FORK.
//! ```
//!
//! ### Testing Checklist
//!
//! ```text
//! - [ ] Receipt signature verification (valid/invalid)
//! - [ ] Double-claim rejection
//! - [ ] Node address mismatch rejection
//! - [ ] Anti-self-dealing flag enforcement
//! - [ ] Timestamp 0 rejection
//! - [ ] Reward distribution 70/20/10 accuracy
//! - [ ] node_earnings update
//! - [ ] claimed_receipts persistence (LMDB)
//! - [ ] State root changes when claimed_receipts changes
//! ```
//!
//! ## 13.12 — GOVERNANCE LAYER (BOOTSTRAP MODE)
//!
//! ### Overview & Tujuan
//!
//! Governance Layer adalah sistem on-chain untuk proposal dan voting atas perubahan protokol,
//! parameter ekonomi, validator set management, dan keputusan strategis lainnya.
//!
//! Pada **Bootstrap Mode** (fase awal Chain Nusantara), governance berfungsi sebagai:
//! - **Preview System**: Proposal dapat diajukan dan divoting, tetapi hasil TIDAK BINDING
//! - **Community Signaling**: Untuk mengukur sentimen komunitas sebelum full governance aktif
//! - **Foundation Authority**: Foundation memiliki veto power dan kontrol eksekusi penuh
//! - **Testing Ground**: Untuk validasi mekanisme governance sebelum produksi penuh
//!
//! #### Mengapa Bootstrap Mode?
//!
//! ```text
//! Bootstrap Mode diperlukan karena:
//! 1. Protocol masih dalam tahap early development
//! 2. Parameter ekonomi belum stabil dan memerlukan adjustment cepat
//! 3. Validator set masih terbatas dan perlu onboarding bertahap
//! 4. Smart contract governance (untuk eksekusi otomatis) belum diimplementasikan
//! 5. Risk mitigation: proposal berbahaya dapat di-veto sebelum eksekusi
//! ```
//!
//! #### Transisi ke Full Governance
//!
//! ```text
//! Bootstrap Mode → Transition Phase → Full Governance
//!
//! Trigger conditions untuk transisi:
//! - Validator count > 50 (decentralization threshold)
//! - Total stake > 100M NUSA (economic security)
//! - Governance participation rate > 30% (community engagement)
//! - Smart contract layer ready (on-chain execution)
//! - Foundation approval (controlled handoff)
//! ```
//!
//! ### ProposalType Enum (Jenis Proposal)
//!
//! Semua jenis proposal yang diizinkan dalam sistem governance:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                         PROPOSAL TYPE MATRIX                                │
//! ├─────────────────────────────────────────────────────────────────────────────┤
//! │                                                                             │
//! │  Type                      │ Description           │ Bootstrap Behavior    │
//! │  ────────────────────────────────────────────────────────────────────────  │
//! │  UpdateFeeParameter        │ Ubah fee constants    │ Preview only          │
//! │                            │ (BASE_OP_COST, dll)   │ Foundation executes   │
//! │  ────────────────────────────────────────────────────────────────────────  │
//! │  UpdateGasPrice            │ Ubah base gas price   │ Preview only          │
//! │                            │ per resource class    │ Foundation executes   │
//! │  ────────────────────────────────────────────────────────────────────────  │
//! │  UpdateNodeCostIndex       │ Ubah node multiplier  │ Preview only          │
//! │                            │ (premium/discount)    │ Foundation executes   │
//! │  ────────────────────────────────────────────────────────────────────────  │
//! │  ValidatorOnboarding       │ Approve validator     │ Preview only          │
//! │                            │ registration request  │ Foundation approves   │
//! │  ────────────────────────────────────────────────────────────────────────  │
//! │  ValidatorOffboarding      │ Remove validator      │ Preview only          │
//! │                            │ dari active set       │ Foundation executes   │
//! │  ────────────────────────────────────────────────────────────────────────  │
//! │  CompliancePointerRemoval  │ Remove illegal TX     │ Preview only          │
//! │                            │ pointer dari registry │ Foundation executes   │
//! │  ────────────────────────────────────────────────────────────────────────  │
//! │  EmergencyPause            │ Pause protocol        │ Preview only          │
//! │                            │ (security incident)   │ Foundation executes   │
//! │  ────────────────────────────────────────────────────────────────────────  │
//! │                                                                             │
//! └─────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! #### Apa yang BOLEH Dilakukan Proposal (Bootstrap Mode)
//!
//! ```text
//! ✅ DIIZINKAN:
//! - Submit proposal (siapapun dengan stake minimum)
//! - Vote dengan QV weight
//! - Reach quorum dan finalize status
//! - Signal community preference
//! - Discuss via on-chain metadata
//! ```
//!
//! #### Apa yang TIDAK BOLEH Dilakukan (Bootstrap Mode)
//!
//! ```text
//! ❌ DILARANG / TIDAK BERFUNGSI:
//! - Auto-execute parameter changes
//! - Force validator registration
//! - Bypass Foundation veto
//! - Modify governance rules
//! - Access treasury without Foundation approval
//! - Slash validators via proposal
//! ```
//!
//! ### Proposal Lifecycle
//!
//! State machine untuk proposal dari creation hingga finalization:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                        PROPOSAL LIFECYCLE DIAGRAM                           │
//! ├─────────────────────────────────────────────────────────────────────────────┤
//! │                                                                             │
//! │   [CREATE PROPOSAL]                                                         │
//! │          │                                                                  │
//! │          │ • Deposit MIN_PROPOSAL_DEPOSIT (1,000 NUSA)                     │
//! │          │ • proposal_count++                                               │
//! │          │ • status = Active                                                │
//! │          │ • voting_period_end = now + VOTING_PERIOD                       │
//! │          │                                                                  │
//! │          ▼                                                                  │
//! │   ┌──────────┐                                                             │
//! │   │  ACTIVE  │◄────────────────────────────────────┐                      │
//! │   └──────────┘                                      │                      │
//! │          │                                          │                      │
//! │          │ • Users submit votes                     │                      │
//! │          │ • QV weight calculated                   │                      │
//! │          │ • Tally updated on each vote             │                      │
//! │          │                                          │                      │
//! │          ▼                                          │                      │
//! │   [VOTING PERIOD ENDS]                              │                      │
//! │          │                                          │                      │
//! │          ├─────────► [Foundation Veto] ────────────┤                      │
//! │          │                  │                       │                      │
//! │          │                  ▼                       │                      │
//! │          │           ┌───────────┐                 │                      │
//! │          │           │  VETOED   │ (Terminal)      │                      │
//! │          │           └───────────┘                 │                      │
//! │          │                                          │                      │
//! │          ▼                                          │                      │
//! │   [Check Quorum & Threshold]                        │                      │
//! │          │                                          │                      │
//! │          ├──► Quorum not reached ─────────────────►│                      │
//! │          │              │                           │                      │
//! │          │              ▼                           │                      │
//! │          │       ┌──────────┐                      │                      │
//! │          │       │ EXPIRED  │ (Terminal)           │                      │
//! │          │       └──────────┘                      │                      │
//! │          │                                          │                      │
//! │          ├──► Yes < 50% ──────────────────────────►│                      │
//! │          │         │                                │                      │
//! │          │         ▼                                │                      │
//! │          │  ┌───────────┐                          │                      │
//! │          │  │ REJECTED  │ (Terminal)               │                      │
//! │          │  └───────────┘                          │                      │
//! │          │                                          │                      │
//! │          └──► Yes ≥ 50% ────────────────────────────┐                     │
//! │                     │                                │                     │
//! │                     ▼                                │                     │
//! │              ┌───────────┐                          │                     │
//! │              │  PASSED   │                          │                     │
//! │              └───────────┘                          │                     │
//! │                     │                                │                     │
//! │                     │ ⚠️ BOOTSTRAP MODE:            │                     │
//! │                     │    NO AUTO-EXECUTION          │                     │
//! │                     │                                │                     │
//! │                     ├─► Foundation Override ────────┘                     │
//! │                     │          (Optional)                                 │
//! │                     │                                                     │
//! │                     ▼                                                     │
//! │              [Foundation Review]                                          │
//! │                     │                                                     │
//! │                     ├─► Approve → [Execute Off-Chain]                    │
//! │                     │                                                     │
//! │                     └─► Reject  → Status stays PASSED (no execution)     │
//! │                                                                             │
//! └─────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! #### State Transition Rules
//!
//! ```text
//! ACTIVE → VETOED
//!     Trigger: Foundation calls veto_proposal()
//!     Effect:  Proposal terminates, deposit may be slashed
//!
//! ACTIVE → EXPIRED
//!     Trigger: block.timestamp > voting_period_end && quorum not reached
//!     Effect:  Proposal fails, deposit returned
//!
//! ACTIVE → REJECTED
//!     Trigger: voting_period_end reached, quorum OK, but yes_votes < threshold
//!     Effect:  Community rejected, deposit returned
//!
//! ACTIVE → PASSED
//!     Trigger: voting_period_end reached, quorum OK, yes_votes ≥ threshold
//!     Effect:  Community approved, awaiting Foundation execution
//!
//! PASSED → EXECUTED (RESERVED - not used in Bootstrap Mode)
//!     Trigger: N/A in Bootstrap Mode
//!     Effect:  Future: smart contract execution
//! ```
//!
//! ### Voting Mechanism (QV-based)
//!
//! Governance voting menggunakan Quadratic Voting untuk mengurangi whale dominance.
//!
//! #### Voting Power Calculation
//!
//! ```text
//! Individual Voting Power:
//!     voting_power = sqrt(locked_balance)
//!
//! Validator Combined Voting Power:
//!     validator_power = (0.8 * sqrt(validator_self_stake)) +
//!                       (0.2 * Σ sqrt(delegator_i_stake))
//! ```
//!
//! #### Vote Submission Flow
//!
//! ```text
//! 1. User calls vote_on_proposal(proposal_id, option, rationale)
//! 2. Check: proposal.status == Active
//! 3. Check: block.timestamp <= proposal.voting_period_end
//! 4. Calculate: weight = get_voting_power(voter)
//! 5. Record: proposal_votes[proposal_id][voter] = Vote { option, weight, timestamp }
//! 6. Update tally: proposal.yes_votes / no_votes / abstain_votes
//! 7. Persist to LMDB
//! 8. Include in state_root (#27 proposal_votes)
//! ```
//!
//! #### Voting Options
//!
//! ```text
//! YES      - Support proposal
//! NO       - Reject proposal
//! ABSTAIN  - Signal participation without preference (counts for quorum)
//! ```
//!
//! #### Quorum & Threshold
//!
//! ```text
//! Quorum Check:
//!     total_votes = yes_votes + no_votes + abstain_votes
//!     total_network_power = Σ all_validator_qv_weights
//!     quorum_reached = (total_votes / total_network_power) ≥ quorum_percentage
//!
//! Pass Threshold:
//!     pass = (yes_votes / (yes_votes + no_votes)) ≥ pass_threshold
//!     Note: Abstain votes do NOT count in pass calculation
//! ```
//!
//! #### Bootstrap Mode Constraints
//!
//! ```text
//! ⚠️ PENTING: Pada Bootstrap Mode, hasil voting adalah INFORMATIONAL ONLY.
//!
//! Meskipun proposal mencapai PASSED status, eksekusi tetap memerlukan:
//! - Foundation manual approval
//! - Off-chain parameter update
//! - Coordinated network upgrade (jika consensus-critical)
//!
//! Hal ini mencegah:
//! - Malicious proposals dari mengubah protokol
//! - Premature decentralization sebelum network mature
//! - Attack via governance (e.g., drain treasury)
//! ```
//!
//! ### Foundation Controls
//!
//! Foundation memiliki kontrol penuh pada Bootstrap Mode untuk keamanan protocol.
//!
//! #### Foundation Powers
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                       FOUNDATION AUTHORITY MATRIX                           │
//! ├─────────────────────────────────────────────────────────────────────────────┤
//! │                                                                             │
//! │  Action                     │ Authority Level    │ Justification           │
//! │  ────────────────────────────────────────────────────────────────────────  │
//! │  Veto Proposal              │ UNILATERAL         │ Malicious proposal      │
//! │                             │                    │ protection              │
//! │  ────────────────────────────────────────────────────────────────────────  │
//! │  Override Rejection         │ UNILATERAL         │ Community mistake       │
//! │                             │                    │ correction              │
//! │  ────────────────────────────────────────────────────────────────────────  │
//! │  Execute PASSED Proposal    │ REQUIRED           │ No auto-execution       │
//! │                             │                    │ in Bootstrap Mode       │
//! │  ────────────────────────────────────────────────────────────────────────  │
//! │  Update Governance Config   │ UNILATERAL         │ Parameter tuning        │
//! │                             │                    │ during testing          │
//! │  ────────────────────────────────────────────────────────────────────────  │
//! │  Emergency Pause            │ UNILATERAL         │ Security incident       │
//! │                             │                    │ response                │
//! │  ────────────────────────────────────────────────────────────────────────  │
//! │  Validator Onboarding       │ APPROVAL REQUIRED  │ KYC/compliance check    │
//! │  ────────────────────────────────────────────────────────────────────────  │
//! │  Treasury Access            │ APPROVAL REQUIRED  │ Fund security           │
//! │  ────────────────────────────────────────────────────────────────────────  │
//! │                                                                             │
//! └─────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! #### Foundation Address
//!
//! ```text
//! Hardcoded in codebase:
//!     FOUNDATION_ADDRESS = "0xF0000000000000000000000000000000000000F0"
//!
//! Dapat diupdate via:
//!     TxPayload::GovernanceAction::SetFoundationAddress
//!     Requires: sender == current foundation_address (self-signed)
//! ```
//!
//! #### Veto Mechanism
//!
//! ```text
//! Foundation dapat veto proposal dengan alasan:
//! - Security risk (e.g., drain treasury proposal)
//! - Illegal content (e.g., censorship resistance violation)
//! - Technical impossibility (e.g., invalid parameter range)
//! - Spam/abuse (e.g., proposal flooding)
//!
//! Veto effect:
//! - Proposal status → VETOED
//! - Deposit may be slashed (configurable)
//! - Rationale logged on-chain
//! ```
//!
//! #### Override Mechanism
//!
//! ```text
//! Foundation dapat override REJECTED proposal jika:
//! - Community vote was manipulated
//! - Critical security fix needed
//! - Emergency parameter adjustment
//!
//! Override effect:
//! - Proposal status → PASSED (forced)
//! - Foundation executes off-chain
//! - Rationale logged on-chain
//! ```
//!
//! #### Long-term Goal (Post-Bootstrap)
//!
//! ```text
//! Foundation power AKAN DICABUT setelah:
//! - Network sufficiently decentralized
//! - Smart contract governance ready
//! - Community proven governance capability
//! - Economic security established
//!
//! Transition mechanism:
//! - Gradual reduction of Foundation weight
//! - Introduction of multi-sig council
//! - Time-locked proposal execution
//! - On-chain arbitration system
//! ```
//!
//! ### NON-BINDING Behavior (Bootstrap Mode)
//!
//! Dokumentasi eksplisit tentang apa yang TIDAK TERJADI pada Bootstrap Mode.
//!
//! #### Apa yang TIDAK Terjadi Otomatis
//!
//! ```text
//! ❌ Proposal dengan status PASSED TIDAK akan:
//!
//! 1. Mengubah parameter on-chain secara otomatis
//!    - Fee constants tetap sama
//!    - Gas prices tidak berubah
//!    - Node cost index tidak terupdate
//!
//! 2. Mengubah validator set
//!    - Validator tidak ter-onboard otomatis
//!    - Validator tidak ter-offboard otomatis
//!
//! 3. Mengakses treasury
//!    - Treasury balance tidak berubah
//!    - Tidak ada transfer otomatis
//!
//! 4. Mengubah governance rules
//!    - Voting period tetap sama
//!    - Quorum threshold tidak berubah
//!
//! 5. Melakukan slashing
//!    - Validator stake tidak berkurang
//!    - Delegator stake tidak terpengaruh
//! ```
//!
//! #### Apa yang TERJADI (Metadata Only)
//!
//! ```text
//! ✅ Proposal dengan status PASSED AKAN:
//!
//! 1. Tercatat dalam state sebagai PASSED
//!    - proposals[id].status = ProposalStatus::Passed
//!    - Timestamp finalization tersimpan
//!
//! 2. Masuk dalam state_root computation
//!    - Termasuk dalam Merkle hash (#26 proposals)
//!    - Dapat diverifikasi oleh semua node
//!
//! 3. Dipersist ke LMDB
//!    - Bucket: proposals/{proposal_id}
//!    - Recoverable setelah restart
//!
//! 4. Queryable via RPC
//!    - get_proposal(id) → full proposal data
//!    - list_proposals() → semua proposal
//!
//! 5. Menjadi signal untuk Foundation
//!    - Foundation review off-chain
//!    - Manual execution jika approved
//! ```
//!
//! #### Execution Flow (Manual)
//!
//! ```text
//! Community Vote PASSED
//!        │
//!        ▼
//! Foundation Review Off-Chain
//!        │
//!        ├─► Approved
//!        │      │
//!        │      ▼
//!        │   Foundation Admin executes via:
//!        │   - Direct state modification (testing)
//!        │   - Coordinated network upgrade (consensus)
//!        │   - CLI admin command (parameter)
//!        │
//!        └─► Rejected
//!               │
//!               ▼
//!            Proposal stays PASSED
//!            (no execution, remains as historical record)
//! ```
//!
//! ### State Root Fields (Consensus-Critical)
//!
//! Governance state termasuk dalam state_root computation dengan ordering ketat.
//!
//! #### Governance Fields dalam State Root
//!
//! ```text
//! Position #26: proposals
//!     Format: HashMap<u64, Proposal>
//!     Sorting: Ascending by proposal_id (u64)
//!     Hashing: [proposal_id_bytes (8)] + [bincode_serialized_proposal]
//!
//! Position #27: proposal_votes
//!     Format: HashMap<u64, HashMap<Address, Vote>>
//!     Sorting: 
//!         - Level 1: Ascending by proposal_id (u64)
//!         - Level 2: Ascending by voter Address (canonical ordering)
//!     Hashing: [proposal_id (8)] + [voter_addr (20)] + [bincode_vote]
//!
//! Position #28: governance_config
//!     Format: GovernanceConfig struct
//!     Sorting: N/A (single struct)
//!     Hashing: bincode_serialized_governance_config
//!
//! Position #29: proposal_count
//!     Format: u64
//!     Sorting: N/A (single value)
//!     Hashing: u64_to_be_bytes (8 bytes)
//! ```
//!
//! #### Ordering Rules (WAJIB DIIKUTI)
//!
//! ```text
//! CRITICAL: Ordering harus PERSIS seperti internal_state_root.rs
//!
//! Urutan fields dalam state_root (existing fields 1-25, governance fields 26-29):
//!
//! 1. balances
//! 2. nonces
//! 3. locked
//! 4. validators
//! 5. validator_set
//! 6. delegations
//! 7. delegator_pool
//! 8. validator_stakes
//! 9. delegator_stakes
//! 10. delegator_to_validator
//! 11. validator_fee_pool
//! 12. storage_fee_pool
//! 13. compute_fee_pool
//! 14. pending_delegator_rewards
//! 15. delegator_reward_accrued
//! 16. delegator_last_epoch
//! 17. year_start_epoch
//! 18. pending_unstakes
//! 19. qv_weights
//! 20. validator_qv_weights
//! 21. liveness_records
//! 22. epoch_info
//! 23. node_cost_index
//! 24. node_earnings
//! 25. claimed_receipts
//! 26. proposals             ← Governance field 1
//! 27. proposal_votes        ← Governance field 2
//! 28. governance_config     ← Governance field 3
//! 29. proposal_count        ← Governance field 4
//! ```
//!
//! #### State Root Recomputation Triggers
//!
//! ```text
//! State root WAJIB dihitung ulang ketika:
//! - create_proposal() → proposal_count++, proposals updated
//! - vote_on_proposal() → proposal_votes updated
//! - finalize_proposal() → proposals.status updated
//! - veto_proposal() → proposals.status updated
//! - override_proposal() → proposals.status updated
//! - update_governance_config() → governance_config updated
//! ```
//!
//! #### Hard Fork Requirements
//!
//! ```text
//! ⚠️ PERINGATAN: Perubahan berikut MEMERLUKAN HARD FORK:
//!
//! 1. Menambah atau menghapus field dari Proposal struct
//! 2. Mengubah urutan fields dalam state_root (positions 26-29)
//! 3. Mengubah sorting algorithm (e.g., ascending → descending)
//! 4. Mengubah serialization format (e.g., bincode → JSON)
//! 5. Menambah governance field baru (akan menjadi position #30+)
//! 6. Mengubah ProposalStatus enum variants
//! 7. Mengubah VoteOption enum variants
//! ```
//!
//! ### LMDB Buckets (Persistence)
//!
//! Governance state dipersist ke LMDB untuk recovery setelah restart.
//!
//! #### Bucket: `proposals`
//!
//! ```text
//! Purpose: Store all proposals (active & historical)
//! Key:     proposal_id (u64, 8 bytes big-endian)
//! Value:   bincode serialized Proposal struct
//!
//! Example:
//!     Key:   0x0000000000000001 (proposal_id = 1)
//!     Value: [bincode bytes of Proposal]
//!
//! Operations:
//!     - put_proposal(id, proposal) → Result<()>
//!     - get_proposal(id) → Result<Option<Proposal>>
//!     - list_all_proposals() → Result<Vec<Proposal>>
//! ```
//!
//! #### Bucket: `proposal_votes`
//!
//! ```text
//! Purpose: Store all votes per proposal
//! Key:     composite: proposal_id (8 bytes) + voter_address (20 bytes)
//! Value:   bincode serialized Vote struct
//!
//! Example:
//!     Key:   [proposal_id: 0x0000000000000001] + [voter: 0xabcd...1234]
//!     Value: [bincode bytes of Vote]
//!
//! Operations:
//!     - put_vote(proposal_id, voter, vote) → Result<()>
//!     - get_vote(proposal_id, voter) → Result<Option<Vote>>
//!     - get_proposal_votes(proposal_id) → Result<HashMap<Address, Vote>>
//! ```
//!
//! #### Bucket: `gov_config`
//!
//! ```text
//! Purpose: Store governance configuration
//! Key:     static key: "config" (UTF-8 bytes)
//! Value:   bincode serialized GovernanceConfig struct
//!
//! Operations:
//!     - put_gov_config(config) → Result<()>
//!     - get_gov_config() → Result<Option<GovernanceConfig>>
//! ```
//!
//! #### Bucket: `proposal_count`
//!
//! ```text
//! Purpose: Store proposal counter for ID generation
//! Key:     static key: "count" (UTF-8 bytes)
//! Value:   u64 (8 bytes big-endian)
//!
//! Operations:
//!     - increment_proposal_count() → Result<u64>
//!     - get_proposal_count() → Result<u64>
//! ```
//!
//! #### Load & Export Flow
//!
//! ```text
//! Startup (load_from_state_layout):
//!     1. Load proposals from LMDB → state.proposals
//!     2. Load proposal_votes → state.proposal_votes
//!     3. Load gov_config → state.governance_config
//!     4. Load proposal_count → state.proposal_count
//!
//! Shutdown / Commit (export_to_state_layout):
//!     1. Serialize state.proposals → LMDB
//!     2. Serialize state.proposal_votes → LMDB
//!     3. Serialize state.governance_config → LMDB
//!     4. Serialize state.proposal_count → LMDB
//! ```
//!
//! ### CONSENSUS-CRITICAL NOTES
//!
//! Bagian ini mendokumentasikan komponen governance yang bersifat consensus-critical.
//!
//! #### Consensus-Critical Components
//!
//! ```text
//! ⚠️ PERINGATAN MUTLAK: Komponen berikut adalah CONSENSUS-CRITICAL.
//! Perubahan apa pun MEMERLUKAN HARD FORK dan koordinasi seluruh network.
//! ```
//!
//! ##### 1. Proposal Struct
//!
//! ```text
//! CRITICAL: Semua fields dan ordering dalam Proposal struct
//!
//! Proposal {
//!     proposal_id: u64,                  // CRITICAL: ID generation
//!     proposal_type: ProposalType,       // CRITICAL: Enum variants
//!     title: String,                     // CRITICAL: Max length enforcement
//!     description: String,               // CRITICAL: Max length enforcement
//!     proposer: Address,                 // CRITICAL: Creator identity
//!     created_at: u64,                   // CRITICAL: Timestamp format
//!     voting_period_end: u64,            // CRITICAL: Finalization trigger
//!     status: ProposalStatus,            // CRITICAL: State machine
//!     yes_votes: u128,                   // CRITICAL: QV weight accumulator
//!     no_votes: u128,                    // CRITICAL: QV weight accumulator
//!     abstain_votes: u128,               // CRITICAL: QV weight accumulator
//!     deposit: u128,                     // CRITICAL: Economic security
//!     metadata: Option<Vec<u8>>,         // CRITICAL: Proposal-specific data
//! }
//! ```
//!
//! ##### 2. Vote Struct
//!
//! ```text
//! CRITICAL: Vote weight snapshot dan option encoding
//!
//! Vote {
//!     voter: Address,                    // CRITICAL: Voter identity
//!     proposal_id: u64,                  // CRITICAL: Linkage
//!     option: VoteOption,                // CRITICAL: Yes/No/Abstain encoding
//!     weight: u128,                      // CRITICAL: QV snapshot at vote time
//!     timestamp: u64,                    // CRITICAL: Vote timing
//!     rationale: Option<String>,         // Non-critical: Optional metadata
//! }
//! ```
//!
//! ##### 3. ProposalStatus Enum
//!
//! ```text
//! CRITICAL: State machine transitions
//!
//! ProposalStatus {
//!     Active,      // Voting ongoing
//!     Passed,      // Reached quorum + threshold
//!     Rejected,    // Failed threshold
//!     Expired,     // Timeout without quorum
//!     Vetoed,      // Foundation veto
//!     Executed,    // Reserved for post-Bootstrap
//! }
//!
//! Perubahan:
//! - Menambah variant baru = OK (append only)
//! - Mengubah existing variant = HARD FORK
//! - Menghapus variant = HARD FORK
//! - Mengubah discriminant value = HARD FORK
//! ```
//!
//! ##### 4. VoteOption Enum
//!
//! ```text
//! CRITICAL: Voting choices
//!
//! VoteOption {
//!     Yes,      // Support
//!     No,       // Reject
//!     Abstain,  // Participate without preference
//! }
//!
//! Perubahan apa pun = HARD FORK
//! ```
//!
//! ##### 5. GovernanceConfig Struct
//!
//! ```text
//! CRITICAL: All configuration parameters
//!
//! GovernanceConfig {
//!     voting_period_seconds: u64,        // CRITICAL: 604,800 (7 days)
//!     quorum_percentage: u8,             // CRITICAL: 33%
//!     pass_threshold: u8,                // CRITICAL: 50%
//!     min_proposal_deposit: u128,        // CRITICAL: 1,000 NUSA
//!     foundation_address: Address,       // CRITICAL: Veto authority
//!     bootstrap_mode: bool,              // CRITICAL: Execution flag
//! }
//!
//! Perubahan nilai:
//! - Via governance_config field update = OK (part of state)
//! - Via hard-coded constants = HARD FORK
//! ```
//!
//! ##### 6. State Root Ordering
//!
//! ```text
//! CRITICAL: Positions 26-29 dalam compute_state_root()
//!
//! Ordering WAJIB:
//!     26. proposals (sorted by proposal_id asc)
//!     27. proposal_votes (sorted by proposal_id, then voter asc)
//!     28. governance_config (single struct)
//!     29. proposal_count (single u64)
//!
//! Perubahan ordering = HARD FORK
//! Perubahan sorting algorithm = HARD FORK
//! ```
//!
//! ##### 7. Quorum & Threshold Calculation
//!
//! ```text
//! CRITICAL: Math formulas
//!
//! quorum_reached = (total_votes / total_network_power) ≥ quorum_percentage
//! pass = (yes_votes / (yes_votes + no_votes)) ≥ pass_threshold
//!
//! Perubahan formula = HARD FORK
//! Perubahan rounding = HARD FORK
//! ```
//!
//! ##### 8. QV Weight Snapshot
//!
//! ```text
//! CRITICAL: Vote weight MUST be snapshot at vote submission time
//!
//! Behavior:
//! - User stakes 100 NUSA → weight = sqrt(100) = 10
//! - User votes YES with weight 10
//! - User stakes additional 900 NUSA (total 1000) → weight now sqrt(1000) = 31.6
//! - Vote weight REMAINS 10 (snapshot)
//!
//! Rationale: Prevents gaming by staking → voting → unstaking
//! Perubahan behavior = HARD FORK
//! ```
//!
//! #### Non-Consensus Components (Safe to Modify)
//!
//! ```text
//! ✅ AMAN untuk diubah tanpa hard fork:
//!
//! - RPC response format (JSON structure)
//! - CLI command syntax
//! - Logging messages
//! - Error messages (user-facing)
//! - Proposal rationale/description (non-critical metadata)
//! - UI/UX for governance dashboard
//! ```
//!
//! #### Migration Path (Jika Hard Fork Diperlukan)
//!
//! ```text
//! Jika perubahan consensus-critical diperlukan:
//!
//! 1. Create migration proposal (off-chain coordination)
//! 2. Announce hard fork date (minimum 30 days notice)
//! 3. Release new client version with fork logic
//! 4. At fork height:
//!    - Old nodes reject new format
//!    - New nodes migrate state
//! 5. Export old state → transform → import new state
//! 6. Recompute state_root with new rules
//! 7. Resume chain with new consensus
//! ```
//!
//! ### Testing Checklist
//!
//! Daftar tes yang WAJIB LULUS sebelum governance dianggap production-ready.
//!
//! #### Unit Tests (state/tests/governance_tests.rs)
//!
//! ```text
//! □ Create Proposal
//!     □ Valid proposal with sufficient deposit
//!     □ Invalid: insufficient deposit
//!     □ Invalid: malformed proposal_type
//!     □ proposal_count increments correctly
//!
//! □ Vote Submission
//!     □ Valid vote during active period
//!     □ Invalid: vote after voting_period_end
//!     □ Invalid: proposal not active
//!     □ Invalid: double vote (should overwrite)
//!     □ QV weight calculated correctly
//!
//! □ Finalization
//!     □ Quorum reached, yes > threshold → PASSED
//!     □ Quorum reached, yes < threshold → REJECTED
//!     □ Quorum not reached → EXPIRED
//!     □ Tally calculation correct
//!
//! □ Foundation Controls
//!     □ Veto sets status to VETOED
//!     □ Override sets status to PASSED
//!     □ Non-foundation cannot veto
//!     □ Non-foundation cannot override
//!
//! □ Bootstrap Mode
//!     □ PASSED proposal does NOT auto-execute
//!     □ Parameter changes require manual intervention
//!     □ Treasury not accessible via proposal
//! ```
//!
//! #### Integration Tests (e2e_tests/test_governance.rs)
//!
//! ```text
//! □ Full Lifecycle
//!     □ Create → Vote → Finalize → PASSED
//!     □ Create → Vote → Finalize → REJECTED
//!     □ Create → Timeout → EXPIRED
//!     □ Create → Foundation Veto → VETOED
//!
//! □ State Root
//!     □ proposals in state_root (#26)
//!     □ proposal_votes in state_root (#27)
//!     □ governance_config in state_root (#28)
//!     □ proposal_count in state_root (#29)
//!     □ State root changes on create/vote/finalize
//!
//! □ LMDB Persistence
//!     □ Proposals persist after restart
//!     □ Votes persist after restart
//!     □ Config persists after restart
//!     □ proposal_count persists after restart
//!
//! □ RPC Endpoints
//!     □ create_proposal() via RPC
//!     □ vote_on_proposal() via RPC
//!     □ get_proposal() returns correct data
//!     □ list_proposals() pagination works
//!     □ get_proposal_votes() returns all votes
//! ```
//!
//! #### CLI Tests (cli/tests/governance_cli_tests.rs)
//!
//! ```text
//! □ Proposal Commands
//!     □ governance propose --type UpdateFeeParameter --title "..." --deposit 1000
//!     □ governance vote --id 1 --option yes
//!     □ governance finalize --id 1
//!     □ governance list --status active
//!     □ governance get --id 1
//!
//! □ Foundation Commands
//!     □ governance veto --id 1 --rationale "security risk"
//!     □ governance override --id 1 --rationale "critical fix"
//!     □ governance set-foundation --address 0x...
//!
//! □ Query Commands
//!     □ governance status --id 1
//!     □ governance votes --id 1
//!     □ governance config
//! ```
//!
//! #### Security Tests (security/tests/governance_security.rs)
//!
//! ```text
//! □ Attack Vectors
//!     □ Spam proposals (rate limiting)
//!     □ Sybil voting (QV mitigation)
//!     □ Vote manipulation (weight snapshot)
//!     □ Proposal ID collision (counter overflow)
//!     □ Foundation key compromise (emergency procedures)
//!
//! □ Edge Cases
//!     □ Proposal at exact voting_period_end
//!     □ Simultaneous votes (race condition)
//!     □ Zero stake voting attempt
//!     □ Negative vote weight (underflow)
//! ```
//!
//! #### Performance Tests (bench/governance_bench.rs)
//!
//! ```text
//! □ Scalability
//!     □ 1,000 proposals in state
//!     □ 10,000 votes per proposal
//!     □ state_root computation time < 100ms
//!     □ LMDB write throughput > 1000 ops/s
//! ```
//!
//! #### Test Execution Commands
//!
//! ```bash
//! # Unit tests
//! cargo test governance_tests
//!
//! # Integration tests
//! cargo test test_governance --test e2e_tests
//!
//! # CLI tests
//! cargo test governance_cli_tests
//!
//! # Security tests
//! cargo test governance_security
//!
//! # All governance tests
//! cargo test governance --test-threads=1
//!
//! # With coverage
//! cargo tarpaulin --out Html --output-dir coverage -- governance
//! ```
//!
//! #### Acceptance Criteria
//!
//! ```text
//! Governance dianggap PRODUCTION-READY jika:
//! ✅ Semua unit tests PASS (100% pass rate)
//! ✅ Semua integration tests PASS
//! ✅ Code coverage ≥ 90% untuk governance module
//! ✅ Security audit completed (external)
//! ✅ Performance benchmarks meet targets
//! ✅ Documentation complete dan akurat
//! ✅ CLI commands tested end-to-end
//! ✅ RPC endpoints verified with Postman/curl
//! ✅ State root consistency verified across restarts
//! ✅ Foundation controls tested (veto/override)
//! ```
//!
//! ## 13.13.3 — Non-Binding Enforcement
//!
//! Guard eksplisit untuk memastikan governance TIDAK MENGEKSEKUSI perubahan
//! selama Bootstrap Mode aktif.
//!
//! ### Prinsip Non-Binding (CONSENSUS-SENSITIVE)
//!
//! ```text
//! ⚠️ PRINSIP MUTLAK:
//!
//! Semua proposal dengan status PASSED TIDAK MENJALANKAN perubahan apa pun
//! selama governance_config.bootstrap_mode == true.
//!
//! Ini adalah EXPLICIT GUARD, bukan implicit behavior.
//! Guard diimplementasikan via method try_execute_proposal().
//! ```
//!
//! ### Method Guard
//!
//! ```text
//! is_execution_allowed()
//!     Returns: !governance_config.bootstrap_mode
//!     Purpose: Check apakah execution diizinkan
//!
//! try_execute_proposal(proposal_id)
//!     Behavior:
//!         - Bootstrap mode ON  → Err(ExecutionDisabledBootstrapMode)
//!         - Bootstrap mode OFF → Err(ExecutionNotImplemented)
//!     Purpose: GUARD untuk mencegah execution
//!     Note:    Method ini SELALU GAGAL di versi saat ini
//!
//! get_bootstrap_mode_status()
//!     Returns: BootstrapModeInfo struct
//!     Purpose: Query status bootstrap mode untuk UI/audit
//! ```
//!
//! ### Error Variants
//!
//! ```text
//! ExecutionDisabledBootstrapMode
//!     - Digunakan KHUSUS saat execution dicoba di bootstrap mode
//!     - Tidak digunakan untuk error lain
//!
//! ExecutionNotImplemented
//!     - Reserved untuk future phase
//!     - Digunakan saat bootstrap_mode == false tapi execution belum ready
//! ```
//!
//! ### Transisi ke Full Governance (Future)
//!
//! ```text
//! Execution akan diimplementasikan di fase future setelah:
//! 1. Bootstrap mode dinonaktifkan via Foundation
//! 2. Smart contract execution layer ready
//! 3. Network sudah sufficiently decentralized
//! 4. Security audit completed
//!
//! Perubahan behavior execution adalah CONSENSUS-SENSITIVE.
//! ```
//!
//! ## 13.13.4 — Governance Event Logging
//!
//! Audit trail in-memory untuk governance actions.
//!
//! ### Tujuan
//!
//! ```text
//! Event logging menyediakan:
//! - Audit trail runtime untuk governance actions
//! - Monitoring realtime aktivitas governance
//! - Debugging capability untuk investigasi bug
//! - Transparansi aktivitas Foundation (veto/override)
//! ```
//!
//! ### Event yang Dicatat
//!
//! ```text
//! GovernanceEventType:
//!     ProposalCreated         → Proposal baru berhasil dibuat
//!     VoteCast                → Vote berhasil dicatat
//!     ProposalFinalized       → Proposal di-finalize (Passed/Rejected/Expired)
//!     ProposalVetoed          → Foundation melakukan veto
//!     ProposalOverridden      → Foundation melakukan override
//!     PreviewGenerated        → Preview proposal di-generate
//!     ExecutionAttemptBlocked → Eksekusi diblokir karena bootstrap mode
//! ```
//!
//! ### Karakteristik (PENTING)
//!
//! ```text
//! ⚠️ PERINGATAN:
//!
//! - Event TIDAK di-persist ke LMDB
//! - Event TIDAK masuk state_root computation
//! - Event TIDAK memengaruhi consensus
//! - Event hilang setelah node restart
//!
//! Ini adalah runtime audit trail, bukan consensus data.
//! ```
//!
//! ### Retention Policy
//!
//! ```text
//! - Maksimum: 1000 event (MAX_GOVERNANCE_EVENTS)
//! - Behavior: FIFO (First In, First Out)
//! - Saat buffer penuh, event tertua dihapus
//! ```
//!
//! ### Methods
//!
//! ```text
//! log_governance_event(event: GovernanceEvent)
//!     - Tambah event ke buffer
//!     - Enforce retention policy
//!
//! get_recent_governance_events(count: usize) -> Vec<GovernanceEvent>
//!     - Query N event terbaru
//!     - Urutan: oldest → newest
//!     - READ-ONLY, tidak mengubah state
//!
//! log_preview_generated(proposal_id, actor, timestamp)
//!     - Helper untuk log preview event
//! ```
//!
//! ### Penggunaan
//!
//! ```text
//! // Query 10 event terakhir untuk monitoring
//! let events = state.get_recent_governance_events(10);
//!
//! // Iterasi event untuk audit
//! for event in events {
//!     println!("{:?}: {} at {}", event.event_type, event.details, event.timestamp);
//! }
//! ```
//!
//! ## 13.13.7 — Payload Integration
//!
//! Integrasi governance logic ke TxPayload::GovernanceAction handling.
//!
//! ### Peran Payload Governance
//!
//! ```text
//! TxPayload::GovernanceAction adalah entry point untuk semua aksi governance:
//!
//! - CreateProposal  → Membuat proposal baru
//! - CastVote        → Memberikan vote pada proposal
//! - FinalizeProposal→ Finalisasi proposal setelah voting period
//! - FoundationVeto  → Foundation veto proposal (Bootstrap Mode)
//! - FoundationOverride → Foundation override hasil (Bootstrap Mode)
//!
//! Payload diproses di internal_payload.rs::apply_payload()
//! ```
//!
//! ### Urutan Eksekusi Payload Governance
//!
//! ```text
//! 1. CreateProposal:
//!    a. Validasi proposer stake
//!    b. Simpan proposal ke state
//!    c. Log ProposalCreated event
//!    d. Generate preview (READ-ONLY)
//!    e. Log PreviewGenerated event (jika sukses)
//!
//! 2. CastVote:
//!    a. Validasi voter eligibility
//!    b. Record vote dengan QV weight
//!    c. Log VoteCast event
//!
//! 3. FinalizeProposal:
//!    a. Check voting period sudah berakhir
//!    b. Hitung quorum dan result
//!    c. Update status proposal
//!    d. Log ProposalFinalized event
//!    e. CHECK BOOTSTRAP MODE:
//!       - Jika Passed DAN bootstrap_mode == true:
//!         → TIDAK ada eksekusi
//!         → Log ExecutionAttemptBlocked event
//!
//! 4. FoundationVeto:
//!    a. Validasi foundation address
//!    b. Set status = Vetoed
//!    c. Log ProposalVetoed event
//!
//! 5. FoundationOverride:
//!    a. Validasi foundation address
//!    b. Update status sesuai new_status
//!    c. Log ProposalOverridden event
//! ```
//!
//! ### Event Logging
//!
//! ```text
//! Event dicatat di titik-titik berikut:
//!
//! | Aksi | Event Type | Kondisi |
//! |------|------------|---------|
//! | CreateProposal | ProposalCreated | Selalu setelah sukses |
//! | CreateProposal | PreviewGenerated | Jika preview sukses |
//! | CastVote | VoteCast | Selalu setelah sukses |
//! | FinalizeProposal | ProposalFinalized | Selalu setelah sukses |
//! | FinalizeProposal | ExecutionAttemptBlocked | Jika Passed + bootstrap_mode |
//! | FoundationVeto | ProposalVetoed | Selalu setelah sukses |
//! | FoundationOverride | ProposalOverridden | Selalu setelah sukses |
//! ```
//!
//! ### Preview Generation
//!
//! ```text
//! ⚠️ PENTING: Preview ≠ Execution
//!
//! - Preview di-generate SETELAH proposal dibuat
//! - Preview adalah READ-ONLY operation
//! - Jika preview gagal, proposal TETAP valid
//! - Preview tidak mengubah state apapun
//! - Preview hanya untuk display/UI purposes
//! ```
//!
//! ### Bootstrap Mode Enforcement
//!
//! ```text
//! ⚠️ CRITICAL: Non-Binding Enforcement
//!
//! Di FinalizeProposal, jika:
//!   - status == ProposalStatus::Passed
//!   - DAN governance_config.bootstrap_mode == true
//!
//! Maka:
//!   - TIDAK ada eksekusi perubahan
//!   - Status tetap Passed (tercatat)
//!   - ExecutionAttemptBlocked event dicatat
//!
//! Ini adalah GUARD FINAL untuk memastikan
//! tidak ada eksekusi implisit di bootstrap mode.
//! ```
//!
//! ### Relationship: Payload ↔ Event Logging
//!
//! ```text
//! ┌─────────────────────┐
//! │ TxPayload::         │
//! │ GovernanceAction    │
//! └─────────┬───────────┘
//!           │
//!           ▼
//! ┌─────────────────────┐
//! │ apply_payload()     │
//! │ (internal_payload)  │
//! └─────────┬───────────┘
//!           │
//!     ┌─────┴─────┐
//!     │           │
//!     ▼           ▼
//! ┌───────┐  ┌─────────────┐
//! │ State │  │ Event Log   │
//! │ Change│  │ (in-memory) │
//! └───────┘  └─────────────┘
//!
//! State changes = consensus-critical
//! Event log = runtime audit trail (NOT persisted)
//! ```
//!
//! ## 13.13 — GOVERNANCE BOOTSTRAP MODE ENFORCEMENT
//!
//! Dokumentasi konsolidasi untuk seluruh mekanisme Governance Bootstrap Mode.
//! Section ini adalah **SOURCE OF TRUTH** untuk memahami non-binding governance.
//!
//! ### 13.13.1 — Bootstrap Mode Characteristics
//!
//! #### Definisi
//!
//! ```text
//! Governance Bootstrap Mode adalah fase awal governance di mana:
//! - Proposal DAPAT dibuat dan voting DAPAT dilakukan
//! - Hasil voting bersifat NON-BINDING (TIDAK mengeksekusi perubahan)
//! - Foundation memiliki full veto power dan override capability
//! - Preview system menyediakan simulasi perubahan tanpa eksekusi
//! ```
//!
//! #### Tujuan
//!
//! ```text
//! Bootstrap Mode dirancang untuk:
//! 1. Memungkinkan testing governance tanpa risiko
//! 2. Memberikan waktu untuk decentralization network
//! 3. Memastikan security audit selesai sebelum execution aktif
//! 4. Memberikan Foundation kontrol sementara untuk mitigasi risiko
//! ```
//!
//! #### Batasan Fundamental
//!
//! ```text
//! ⚠️ BATASAN MUTLAK:
//!
//! - TIDAK ADA perubahan parameter yang terjadi
//! - TIDAK ADA validator yang ter-onboard/offboard secara otomatis
//! - TIDAK ADA treasury yang berubah via proposal
//! - TIDAK ADA eksekusi implisit apapun
//!
//! Semua proposal tercatat dengan status final (Passed/Rejected/Expired/Vetoed)
//! tetapi TIDAK memicu perubahan state apa pun.
//! ```
//!
//! #### Proposal Types yang Diizinkan
//!
//! ```text
//! ProposalType               | Deskripsi                    | State Change
//! ---------------------------|------------------------------|------------------
//! UpdateFeeParameter         | Ubah fee parameter           | NON-BINDING
//! UpdateGasPrice             | Ubah base gas price          | NON-BINDING
//! UpdateNodeCostIndex        | Ubah node cost multiplier    | NON-BINDING
//! ValidatorOnboarding        | Onboard validator baru       | NON-BINDING
//! ValidatorOffboarding       | Offboard validator           | NON-BINDING
//! CompliancePointerRemoval   | Hapus compliance pointer     | NON-BINDING
//! EmergencyPause             | Emergency pause network      | NON-BINDING
//!
//! ⚠️ SEMUA proposal types di atas TIDAK MENJALANKAN STATE di Bootstrap Mode.
//! ```
//!
//! #### NON-BINDING Statement
//!
//! ```text
//! ════════════════════════════════════════════════════════════════════════════
//! PERNYATAAN RESMI:
//!
//! "Semua hasil proposal dalam Bootstrap Mode bersifat NON-BINDING."
//!
//! Definisi teknis NON-BINDING:
//! - Status proposal (Passed/Rejected) HANYA tercatat di state
//! - Execution payload TIDAK dijalankan
//! - Tidak ada perubahan pada: balances, validators, config, treasury
//! - Preview menunjukkan APA YANG AKAN TERJADI, bukan apa yang terjadi
//! ════════════════════════════════════════════════════════════════════════════
//! ```
//!
//! #### Foundation Powers
//!
//! ```text
//! Foundation (governance_config.foundation_address) memiliki:
//!
//! 1. VETO POWER
//!    - Method: veto_proposal(foundation_addr, proposal_id)
//!    - Effect: Set status = Vetoed, tidak dapat diubah
//!    - Restriction: Hanya untuk proposal Active
//!
//! 2. OVERRIDE POWER
//!    - Method: override_proposal_result(foundation_addr, proposal_id, new_status)
//!    - Effect: Mengubah status proposal Passed/Rejected ke status lain
//!    - Restriction: Tidak dapat override proposal Active
//!
//! 3. PREVIEW VISIBILITY
//!    - Foundation dapat melihat preview semua proposal
//!    - Preview menunjukkan dampak sebelum finalisasi
//!
//! 4. EXECUTION GUARD
//!    - Selama bootstrap_mode == true, eksekusi SELALU diblokir
//!    - Foundation dapat menonaktifkan bootstrap mode di future
//!
//! ⚠️ POWERS INI BERSIFAT SEMENTARA:
//! Akan dikurangi seiring network menjadi lebih decentralized.
//! ```
//!
//! ### 13.13.2 — Preview System
//!
//! #### Flow Preview Generation
//!
//! ```text
//! ┌──────────────────────┐
//! │   Proposal Created   │
//! │  (create_proposal)   │
//! └──────────┬───────────┘
//!            │
//!            ▼
//! ┌──────────────────────┐
//! │  Preview Generated   │
//! │(generate_proposal_   │
//! │      preview)        │
//! └──────────┬───────────┘
//!            │
//!     ┌──────┴──────┐
//!     │             │
//!     ▼             ▼
//! ┌────────┐   ┌────────┐
//! │  RPC   │   │  CLI   │
//! │ Query  │   │ Query  │
//! └────┬───┘   └────┬───┘
//!      │            │
//!      ▼            ▼
//! ┌─────────────────────┐
//! │ Client Visualization│
//! │  (Dashboard / UI)   │
//! └─────────────────────┘
//! ```
//!
//! #### Preview Methods
//!
//! ```text
//! | Layer | Method | Return Type |
//! |-------|--------|-------------|
//! | State | generate_proposal_preview(id) | Result<ProposalPreview, GovernanceError> |
//! | RPC | get_proposal_preview(id) | Result<ProposalPreviewRes, RpcError> |
//! | CLI | governance preview --proposal <ID> | Terminal output |
//! ```
//!
//! #### Struktur ProposalPreview
//!
//! ```text
//! ProposalPreview {
//!     proposal_id: u64,           // ID proposal yang di-preview
//!     preview_type: PreviewType,  // Jenis preview (sesuai ProposalType)
//!     simulated_changes: Vec<SimulatedChange>,  // Daftar perubahan
//!     affected_addresses: Vec<Address>,         // Address yang terpengaruh
//!     generated_at: u64,          // Timestamp generate
//! }
//!
//! SimulatedChange {
//!     field_path: String,         // "governance_config.base_gas_price"
//!     old_value_display: String,  // "100"
//!     new_value_display: String,  // "150"
//! }
//! ```
//!
//! #### Contoh Output Preview
//!
//! ```text
//! Preview untuk UpdateGasPrice proposal:
//!
//! simulated_changes:
//!   [0] field_path: "governance_config.base_gas_price"
//!       old_value:  "100"
//!       new_value:  "150"
//!
//! affected_addresses:
//!   - 0x0000000000000000000000000000000000000000 (treasury)
//!
//! Preview untuk ValidatorOnboarding proposal:
//!
//! simulated_changes:
//!   [0] field_path: "validator_set.validators"
//!       old_value:  "3 validators"
//!       new_value:  "4 validators (added: 0x1234...)"
//!   [1] field_path: "validator_set.total_stake"
//!       old_value:  "1,500,000 NUSA"
//!       new_value:  "2,000,000 NUSA"
//!
//! affected_addresses:
//!   - 0x1234567890abcdef... (new validator)
//! ```
//!
//! #### PREVIEW ≠ EXECUTION
//!
//! ```text
//! ════════════════════════════════════════════════════════════════════════════
//! ⚠️ PERBEDAAN FUNDAMENTAL:
//!
//! PREVIEW:
//! - READ-ONLY operation
//! - Tidak mengubah state apapun
//! - Dapat dipanggil berkali-kali dengan hasil sama
//! - Menunjukkan APA YANG AKAN terjadi JIKA execution aktif
//! - Safe untuk dipanggil oleh siapa saja
//!
//! EXECUTION:
//! - WRITE operation (mengubah state)
//! - Hanya terjadi sekali per proposal
//! - TIDAK AKTIF di Bootstrap Mode
//! - Akan mengubah state secara permanen
//! - Memerlukan consensus
//!
//! Di Bootstrap Mode, HANYA preview yang tersedia.
//! Execution SELALU diblokir dengan error ExecutionDisabledBootstrapMode.
//! ════════════════════════════════════════════════════════════════════════════
//! ```
//!
//! ### 13.13.3 — Non-Binding Enforcement
//!
//! #### Enforcement di Level State
//!
//! ```text
//! Enforcement dilakukan via explicit guards di ChainState:
//!
//! 1. is_execution_allowed() -> bool
//!    - Returns: !governance_config.bootstrap_mode
//!    - Simple check, tidak ada side-effect
//!
//! 2. try_execute_proposal(proposal_id) -> Result<(), GovernanceError>
//!    - SELALU GAGAL di versi saat ini
//!    - Bootstrap mode ON  → Err(ExecutionDisabledBootstrapMode)
//!    - Bootstrap mode OFF → Err(ExecutionNotImplemented)
//!
//! 3. Implicit guard di apply_payload():
//!    - Setelah finalize_proposal() dengan status Passed
//!    - Jika bootstrap_mode == true, log ExecutionAttemptBlocked
//!    - TIDAK ada eksekusi apapun
//! ```
//!
//! #### Error Types
//!
//! ```text
//! GovernanceError::ExecutionDisabledBootstrapMode
//!     - Digunakan KHUSUS saat execution dicoba di bootstrap mode
//!     - Message: "Execution disabled: bootstrap mode active"
//!     - Recovery: Tidak ada, harus menunggu bootstrap mode dinonaktifkan
//!
//! GovernanceError::ExecutionNotImplemented
//!     - Reserved untuk future phase
//!     - Digunakan saat bootstrap_mode == false tapi execution belum ready
//!     - Message: "Execution not yet implemented"
//! ```
//!
//! #### Catatan Execution
//!
//! ```text
//! ════════════════════════════════════════════════════════════════════════════
//! CATATAN RESMI:
//!
//! 1. Semua attempt execution SELALU GAGAL di Bootstrap Mode
//! 2. Error ExecutionDisabledBootstrapMode adalah expected behavior
//! 3. Proposal dengan status Passed tetap tercatat di state
//! 4. Execution akan diaktifkan di fase governance penuh (future)
//!
//! Kriteria aktivasi execution (future):
//! - Bootstrap mode dinonaktifkan via Foundation
//! - Smart contract execution layer ready
//! - Network sudah sufficiently decentralized
//! - Security audit completed
//! ════════════════════════════════════════════════════════════════════════════
//! ```
//!
//! ### 13.13.4 — Event Logging
//!
//! #### Event Types
//!
//! ```text
//! GovernanceEventType          | Trigger                        | Details
//! -----------------------------|--------------------------------|------------------
//! ProposalCreated              | create_proposal() sukses       | Title, proposer
//! VoteCast                     | cast_vote() sukses             | Vote option, weight
//! ProposalFinalized            | finalize_proposal() sukses     | Final status
//! ProposalVetoed               | veto_proposal() sukses         | Foundation addr
//! ProposalOverridden           | override_proposal_result()     | Old→New status
//! PreviewGenerated             | generate_proposal_preview()    | Preview type
//! ExecutionAttemptBlocked      | Passed + bootstrap_mode        | Block reason
//! ```
//!
//! #### Retention Policy
//!
//! ```text
//! - Storage: In-memory Vec<GovernanceEvent>
//! - Maximum: 1000 events (MAX_GOVERNANCE_EVENTS)
//! - Behavior: FIFO (First In, First Out)
//! - Saat buffer penuh: Event tertua dihapus otomatis
//!
//! ⚠️ Event HILANG setelah node restart!
//! ```
//!
//! #### Query Methods
//!
//! ```text
//! | Layer | Method | Parameters |
//! |-------|--------|------------|
//! | State | get_recent_governance_events(count) | count: usize |
//! | RPC | get_governance_events(count) | count: u64 |
//! | CLI | governance events --count <N> | N: optional (default 20) |
//!
//! Response berisi: event_type, proposal_id, actor, timestamp, details
//! Urutan: oldest → newest (chronological)
//! ```
//!
//! #### Karakteristik Event
//!
//! ```text
//! ════════════════════════════════════════════════════════════════════════════
//! ⚠️ PERINGATAN:
//!
//! - Event TIDAK di-persist ke LMDB
//! - Event TIDAK masuk state_root computation
//! - Event TIDAK memengaruhi consensus antar node
//! - Event adalah runtime audit trail LOKAL
//!
//! Untuk audit cross-node, gunakan on-chain data (proposals, votes).
//! ════════════════════════════════════════════════════════════════════════════
//! ```
//!
//! ### 13.13.5 — RPC & CLI Reference
//!
//! #### RPC Endpoints
//!
//! ```text
//! | Endpoint | Method | Parameters | Return |
//! |----------|--------|------------|--------|
//! | get_proposal_preview | GET | id: u64 | ProposalPreviewRes |
//! | get_bootstrap_mode_status | GET | - | BootstrapModeRes |
//! | get_governance_events | GET | count: u64 | Vec<GovernanceEventRes> |
//!
//! Semua endpoint adalah READ-ONLY dan tidak mengubah state.
//! ```
//!
//! #### CLI Commands
//!
//! ```text
//! | Command | Arguments | Description |
//! |---------|-----------|-------------|
//! | governance preview | --proposal <ID> | Preview proposal changes |
//! | governance bootstrap-status | - | Show bootstrap mode status |
//! | governance events | --count <N> | Show recent events (default: 20) |
//!
//! Semua command adalah READ-ONLY dan tidak mengirim transaksi.
//! ```
//!
//! #### Contoh Penggunaan RPC
//!
//! ```bash
//! # Preview proposal via curl
//! curl -X POST http://localhost:8545 \
//!   -H "Content-Type: application/json" \
//!   -d '{"method":"get_proposal_preview","params":[1],"id":1}'
//!
//! # Check bootstrap status
//! curl -X POST http://localhost:8545 \
//!   -H "Content-Type: application/json" \
//!   -d '{"method":"get_bootstrap_mode_status","params":[],"id":1}'
//!
//! # Get recent events
//! curl -X POST http://localhost:8545 \
//!   -H "Content-Type: application/json" \
//!   -d '{"method":"get_governance_events","params":[10],"id":1}'
//! ```
//!
//! #### Contoh Penggunaan CLI
//!
//! ```bash
//! # Preview proposal #1
//! dsdn governance preview --proposal 1
//!
//! # Output:
//! # ═══════════════════════════════════════════════════════════
//! # 🔍 PROPOSAL PREVIEW (READ-ONLY)
//! # ═══════════════════════════════════════════════════════════
//! # ⚠️  INI HANYA PREVIEW — TIDAK ADA EKSEKUSI
//! # ...
//!
//! # Check bootstrap status
//! dsdn governance bootstrap-status
//!
//! # Output:
//! # ═══════════════════════════════════════════════════════════
//! # 🏛️ BOOTSTRAP MODE STATUS
//! # ═══════════════════════════════════════════════════════════
//! #    Status: ⚠️  AKTIF (Non-Binding)
//! #    Execution: ❌ TIDAK DIIZINKAN
//! # ...
//!
//! # Get last 10 events
//! dsdn governance events --count 10
//! ```
//!
//! ## END OF GOVERNANCE DOCUMENTATION (13.12 + 13.13)
//!
//! ## 13.14 — SLASHING RULES (AUTOMATIC & NON-GOVERNANCE)
//!
//! ### 13.14.1 — Slashing Constants & Data Structures
//!
//! Tahap ini mendefinisikan fondasi ekonomi keamanan untuk DSDN slashing subsystem.
//! Semua konstanta dan struktur bersifat CONSENSUS-CRITICAL.
//!
//! #### Slashing Constants (Basis Points)
//!
//! ```text
//! | Constant                              | Value | Meaning              |
//! |---------------------------------------|-------|----------------------|
//! | NODE_LIVENESS_SLASH_PERCENT           | 50    | 0.5% slash           |
//! | NODE_DATA_CORRUPTION_SLASH_PERCENT    | 500   | 5% slash             |
//! | VALIDATOR_DOUBLE_SIGN_SLASH_PERCENT   | 1000  | 10% slash            |
//! | VALIDATOR_OFFLINE_SLASH_PERCENT       | 100   | 1% slash             |
//! | VALIDATOR_MALICIOUS_BLOCK_SLASH_PERCENT| 2000 | 20% slash            |
//! ```
//!
//! #### Time Constants
//!
//! ```text
//! | Constant                       | Value      | Meaning              |
//! |--------------------------------|------------|----------------------|
//! | NODE_LIVENESS_THRESHOLD_SECONDS| 43,200     | 12 hours             |
//! | FORCE_UNBOND_DELAY_SECONDS     | 2,592,000  | 30 days              |
//! ```
//!
//! #### Token Allocation
//!
//! ```text
//! | Constant               | Value | Meaning                    |
//! |------------------------|-------|----------------------------|
//! | SLASHING_TREASURY_RATIO| 50    | 50% to treasury            |
//! | SLASHING_BURN_RATIO    | 50    | 50% burned (deflation)     |
//! ```
//!
//! #### SlashingReason Enum
//!
//! ```text
//! SlashingReason:
//! - NodeLivenessFailure       → Node offline ≥ 12 jam
//! - NodeDataCorruption        → Data corruption 2x berturut
//! - NodeMaliciousBehavior     → Repeated malicious behavior
//! - ValidatorDoubleSign       → Double signing
//! - ValidatorProlongedOffline → Validator offline
//! - ValidatorMaliciousBlock   → Malicious block production
//! ```
//!
//! #### NodeLivenessRecord Struct
//!
//! ```text
//! NodeLivenessRecord {
//!     node_address: Address,
//!     last_seen_timestamp: u64,
//!     consecutive_failures: u32,
//!     data_corruption_count: u32,
//!     malicious_behavior_count: u32,
//!     force_unbond_until: Option<u64>,
//!     slashed: bool,
//! }
//! ```
//!
//! #### SlashingEvent Struct
//!
//! ```text
//! SlashingEvent {
//!     target: Address,
//!     reason: SlashingReason,
//!     amount_slashed: u128,
//!     amount_to_treasury: u128,
//!     amount_burned: u128,
//!     timestamp: u64,
//! }
//! ```
//!
//! #### Catatan Penting
//!
//! ```text
//! ⚠️ TAHAP 13.14.1 HANYA DEFINISI:
//! - Tidak ada logic slashing
//! - Tidak ada execution
//! - Tidak ada side effect
//! - Digunakan oleh slashing engine di fase berikutnya
//!
//! ⚠️ CONSENSUS-CRITICAL:
//! - Semua nilai konstanta memerlukan hard-fork untuk diubah
//! - Urutan enum variant tidak boleh diubah
//! - Urutan struct field tidak boleh diubah
//! ```
//! #### Lokasi File
//!
//! ```text
//! crates/chain/src/slashing.rs
//! ```
//!
//! ### 13.14.2 — Node Liveness Tracking
//!
//! Tahap ini menyediakan runtime tracking layer untuk storage/compute nodes.
//! Detection only — tidak ada slashing execution di tahap ini.
//!
//! #### Tujuan
//!
//! ```text
//! - Mencatat heartbeat dari nodes
//! - Mendeteksi node offline berkepanjangan (≥ 12 jam)
//! - Mendeteksi data corruption berulang (2x berturut)
//! - Mendeteksi malicious behavior
//! - Mendukung force-unbond mechanism
//! - Menghasilkan SlashingReason untuk tahap execution
//! ```
//!
//! #### State Fields Baru
//!
//! ```text
//! ChainState {
//!     node_liveness_records: HashMap<Address, NodeLivenessRecord>,
//!     slashing_events: Vec<SlashingEvent>,  // runtime-only
//! }
//! ```
//!
//! #### Methods Node Liveness
//!
//! ```text
//! | Method                    | Fungsi                                      |
//! |---------------------------|---------------------------------------------|
//! | record_node_heartbeat     | Catat heartbeat, reset consecutive_failures |
//! | check_node_liveness       | Deteksi offline → Option<SlashingReason>    |
//! | record_data_corruption    | Increment count → Option<SlashingReason>    |
//! | record_malicious_behavior | Increment count → Option<SlashingReason>    |
//! | is_node_force_unbonded    | Check force-unbond status                   |
//! ```
//!
//! #### Detection Logic
//!
//! ```text
//! Liveness Check:
//!   if (current_timestamp - last_seen_timestamp) >= NODE_LIVENESS_THRESHOLD_SECONDS:
//!     consecutive_failures++
//!     if consecutive_failures >= 1:
//!       return Some(NodeLivenessFailure)
//!
//! Data Corruption:
//!   data_corruption_count++
//!   if data_corruption_count >= 2:
//!     return Some(NodeDataCorruption)
//!
//! Malicious Behavior:
//!   malicious_behavior_count++
//!   if malicious_behavior_count >= 1:
//!     return Some(NodeMaliciousBehavior)
//!
//! Force Unbond Check:
//!   if force_unbond_until == Some(t) && current_timestamp < t:
//!     return true (still force-unbonded)
//! ```
//!
//! #### Catatan Penting
//!
//! ```text
//! ⚠️ TAHAP 13.14.2 HANYA DETECTION:
//! - Tidak ada slashing execution
//! - Tidak ada stake reduction
//! - Tidak ada treasury transfer
//! - Hanya signalling via SlashingReason
//!
//! ⚠️ DETERMINISTIC BEHAVIOR:
//! - Semua logic deterministik
//! - Tidak ada random/time-dependent behavior selain timestamp comparison
//! - Safe untuk consensus
//! ```
//!
//! #### Lokasi File
//!
//! ```text
//! crates/chain/src/state/mod.rs (fields)
//! crates/chain/src/state/internal_slash_adapter.rs (methods)
//! ```
//!
//! ### 13.14.3 — Validator Slashing Detection
//!
//! Tahap ini menyediakan detection layer untuk validator violations.
//! Detection only — tidak ada slashing execution di tahap ini.
//!
//! #### Jenis Pelanggaran Validator
//!
//! ```text
//! | Violation                | Trigger                          | Severity |
//! |--------------------------|----------------------------------|----------|
//! | ValidatorDoubleSign      | 2 signature berbeda untuk height | HIGHEST  |
//! | ValidatorMaliciousBlock  | Evidence malicious block         | HIGH     |
//! | ValidatorProlongedOffline| Offline ≥ threshold              | MEDIUM   |
//! ```
//!
//! #### Fields Baru di NodeLivenessRecord
//!
//! ```text
//! NodeLivenessRecord {
//!     ...existing fields...,
//!     double_sign_detected: bool,       // Double-sign flag
//!     malicious_block_detected: bool,   // Malicious block flag
//!     offline_since: Option<u64>,       // Timestamp mulai offline
//! }
//! ```
//!
//! #### Methods Validator Detection
//!
//! ```text
//! | Method                   | Fungsi                                   |
//! |--------------------------|------------------------------------------|
//! | detect_double_sign       | Deteksi signature berbeda → bool         |
//! | detect_prolonged_offline | Deteksi offline duration → bool          |
//! | detect_malicious_block   | Deteksi evidence malicious → bool        |
//! | get_validator_slash_reason| Get SlashingReason dengan priority      |
//! | reset_validator_offline  | Reset offline tracking                   |
//! ```
//!
//! #### Detection Logic
//!
//! ```text
//! Double-Sign:
//!   if signature1 != signature2:
//!     double_sign_detected = true
//!     return true
//!
//! Prolonged Offline:
//!   if offline_since == None:
//!     offline_since = current_timestamp
//!     return false
//!   else:
//!     if (current - offline_since) >= threshold:
//!       return true
//!
//! Malicious Block:
//!   if evidence.len() > 0:
//!     malicious_block_detected = true
//!     return true
//!
//! Get Slash Reason (PRIORITY ORDER):
//!   1. double_sign_detected → ValidatorDoubleSign
//!   2. malicious_block_detected → ValidatorMaliciousBlock
//!   3. offline detected → ValidatorProlongedOffline
//! ```
//!
//! #### Catatan Penting
//!
//! ```text
//! ⚠️ TAHAP 13.14.3 HANYA DETECTION:
//! - Tidak ada slashing execution
//! - Tidak ada stake reduction
//! - Tidak ada treasury transfer
//! - Hanya flagging dan return SlashingReason
//!
//! ⚠️ PRIORITY ORDER CONSENSUS-CRITICAL:
//! - Urutan priority tidak boleh diubah
//! - ValidatorDoubleSign selalu tertinggi
//! - ValidatorProlongedOffline selalu terendah
//!
//! ⚠️ DETERMINISTIC BEHAVIOR:
//! - Semua logic deterministik
//! - Verification dilakukan di layer lain
//! - Safe untuk consensus
//! ```
//!
//! #### Lokasi File
//!
//! ```text
//! crates/chain/src/slashing.rs (fields)
//! crates/chain/src/state/internal_slash_adapter.rs (methods)
//! ```
//! ### 13.14.4 — Automatic Slash Execution
//!
//! Tahap ini mengeksekusi slashing secara otomatis berdasarkan SlashingReason.
//! EXECUTION LAYER — stake benar-benar dipotong dan dana didistribusikan.
//!
//! #### Perbedaan Detection vs Execution
//!
//! ```text
//! DETECTION (13.14.2, 13.14.3):
//! - Hanya mendeteksi pelanggaran
//! - Return SlashingReason
//! - TIDAK mengubah stake
//! - TIDAK mendistribusikan dana
//!
//! EXECUTION (13.14.4):
//! - Menerima SlashingReason yang sudah divalidasi
//! - BENAR-BENAR memotong stake
//! - BENAR-BENAR mendistribusikan dana
//! - TIDAK DAPAT DIBATALKAN
//! ```
//!
//! #### Kapan Slashing Otomatis Terjadi
//!
//! ```text
//! Slashing otomatis dipicu TANPA governance ketika:
//! - Detection methods return SlashingReason
//! - Block-level hook memanggil execute_auto_slash_*
//! - TIDAK ADA voting atau approval required
//! ```
//!
//! #### Atomicity Guarantee
//!
//! ```text
//! SEMUA operasi slashing bersifat ATOMIC:
//! - Jika execute_auto_slash_* return Ok → semua state berubah
//! - Jika execute_auto_slash_* return Err → TIDAK ADA state berubah
//! - Tidak ada partial execution
//! ```
//!
//! #### Distribusi Slashed Funds
//!
//! ```text
//! Slashed Amount:
//! ├── 50% → Treasury (SLASHING_TREASURY_RATIO)
//! └── 50% → Burned (SLASHING_BURN_RATIO)
//!
//! Formula:
//!   to_treasury = amount * 50 / 100
//!   to_burn = amount - to_treasury (no rounding loss)
//! ```
//!
//! #### Force-Unbond Behavior
//!
//! ```text
//! Force-unbond diterapkan pada:
//! - NodeMaliciousBehavior → 30 days force-unbond
//! - ValidatorMaliciousBlock → 30 days force-unbond
//!
//! Selama force-unbond:
//! - Target tidak dapat berpartisipasi di network
//! - Stake tetap locked
//! - is_node_force_unbonded() return true
//! ```
//!
//! #### SlashError Enum
//!
//! ```text
//! SlashError:
//! - InsufficientStake    → Stake tidak cukup untuk di-slash
//! - AlreadySlashed       → Target sudah pernah di-slash
//! - InvalidReason        → Reason tidak valid untuk target type
//! - NodeNotFound         → Node tidak ditemukan
//! - ValidatorNotFound    → Validator tidak ditemukan
//! ```
//!
//! #### Methods Execution
//!
//! ```text
//! | Method                    | Fungsi                                      |
//! |---------------------------|---------------------------------------------|
//! | execute_auto_slash_node   | Slash node → Result<SlashingEvent, SlashError> |
//! | execute_auto_slash_validator | Slash validator → Result<SlashingEvent, SlashError> |
//! | apply_force_unbond        | Set force_unbond_until                      |
//! | allocate_slashed_amount   | Split ke treasury + burn                    |
//! ```
//!
//! #### Catatan Penting
//!
//! ```text
//! ⚠️ NON-GOVERNANCE:
//! - Slashing terjadi OTOMATIS
//! - Tidak melalui voting
//! - Tidak bisa di-veto
//! - Tidak bisa di-override
//!
//! ⚠️ DETERMINISTIC:
//! - Hasil slashing sama di semua node
//! - Safe untuk consensus
//!
//! ⚠️ TIDAK DAPAT DIBATALKAN:
//! - Setelah execute berhasil, tidak ada rollback
//! - Stake sudah dipotong permanen
//! - Burn sudah mengurangi total_supply
//! ```
//!
//! #### Lokasi File
//!
//! ```text
//! crates/chain/src/state/internal_slash_adapter.rs (execution methods)
//! crates/chain/src/tokenomics.rs (calculate_slash_allocation)
//! ```
//! //! ### 13.14.5 — Delegator Protection Mechanism
//!
//! Tahap ini mengimplementasikan PERLINDUNGAN EKONOMI untuk delegator.
//! PRINSIP UTAMA: Delegator TIDAK BOLEH terkena slashing kecuali pada kondisi ekstrem.
//!
//! #### Prinsip Perlindungan Delegator
//!
//! ```text
//! DEFAULT BEHAVIOR:
//! - Slashing HANYA mengenai validator/node stake
//! - Delegator stake tetap AMAN
//! - Trust ekonomi delegator terjaga
//!
//! DELEGATOR AMAN PADA:
//! - ValidatorDoubleSign
//! - ValidatorProlongedOffline
//! - NodeLivenessFailure
//! - NodeDataCorruption
//! - NodeMaliciousBehavior
//! ```
//!
//! #### Apa itu Protocol Failure Ekstrem
//!
//! ```text
//! Protocol failure adalah kondisi SANGAT JARANG dimana:
//! - Validator melakukan tindakan yang MERUSAK NETWORK
//! - Tindakan tersebut TERBUKTI dengan evidence
//! - Damage potential sangat tinggi
//!
//! SATU-SATUNYA Protocol Failure:
//! - ValidatorMaliciousBlock (dengan evidence)
//! ```
//!
//! #### Kapan Delegator Bisa Terkena Slash
//!
//! ```text
//! KONDISI WAJIB (SEMUA harus terpenuhi):
//! 1. reason == ValidatorMaliciousBlock
//! 2. validator_slash_percent > DELEGATOR_SLASH_THRESHOLD (20%)
//!
//! Jika SALAH SATU tidak terpenuhi → Delegator AMAN
//! ```
//!
//! #### DELEGATOR_SLASH_THRESHOLD
//!
//! ```text
//! Konstanta: DELEGATOR_SLASH_THRESHOLD = 2000 (20% basis points)
//!
//! Arti:
//! - Delegator HANYA di-slash jika validator loss > 20%
//! - Validator loss 10% (DoubleSign) → Delegator AMAN
//! - Validator loss 20% (MaliciousBlock) → Delegator MUNGKIN terkena
//!
//! Delegator Slash Calculation:
//!   delegator_slash = validator_slash_percent - DELEGATOR_SLASH_THRESHOLD
//!   Jika validator_slash = 2000 bp (20%)
//!   delegator_slash = 2000 - 2000 = 0% → Delegator AMAN
//!
//!   Jika validator_slash = 3000 bp (30%)
//!   delegator_slash = 3000 - 2000 = 1000 bp = 10%
//! ```
//!
//! #### Delegator Slash Constraints
//!
//! ```text
//! CONSTRAINTS (TIDAK DAPAT DILANGGAR):
//! 1. Delegator slash ≤ Validator slash (per delegator)
//! 2. Delegator slash SELALU proporsional ke stake
//! 3. Delegator TIDAK PERNAH di-slash 100%
//! 4. Delegator slash HANYA pada protocol failure
//! ```
//!
//! #### Methods Delegator Protection
//!
//! ```text
//! | Method                        | Fungsi                                |
//! |-------------------------------|---------------------------------------|
//! | is_protocol_failure_condition | Check apakah reason = protocol failure|
//! | slash_with_delegator_protection| Slash dengan protection guarantee    |
//! ```
//!
//! #### Catatan Penting
//!
//! ```text
//! ⚠️ SANGAT JARANG:
//! - Delegator di-slash hanya pada kondisi ekstrem
//! - Dalam operasi normal, delegator SELALU aman
//!
//! ⚠️ DETERMINISTIC:
//! - Logic protection sama di semua node
//! - Safe untuk consensus
//!
//! ⚠️ NON-GOVERNANCE:
//! - Protection tidak bisa di-override governance
//! - Threshold tidak bisa diubah tanpa hard-fork
//! ```
//!
//! #### Lokasi File
//!
//! ```text
//! crates/chain/src/state/internal_slash_adapter.rs
//! ```
//! //! ### 13.14.6 — Block-Level Slashing Hook
//!
//! Tahap ini mengintegrasikan automatic slashing ke dalam block execution pipeline.
//! CRITICAL INTEGRATION POINT untuk konsistensi slashing di semua node.
//!
//! #### Posisi Slashing dalam Block Lifecycle
//!
//! ```text
//! BLOCK EXECUTION FLOW:
//!
//! ┌─────────────────────────────────────────────────────────────┐
//! │ 1. Receive Block                                            │
//! │    └─ Validate header, signature, parent hash               │
//! ├─────────────────────────────────────────────────────────────┤
//! │ 2. Execute All Transactions                                 │
//! │    └─ apply_payload() untuk setiap TX                       │
//! │    └─ Fee distribution, state mutations                     │
//! ├─────────────────────────────────────────────────────────────┤
//! │ 3. AUTOMATIC SLASHING HOOK ← process_automatic_slashing()   │
//! │    └─ Scan node_liveness_records                            │
//! │    └─ Scan validator violations                             │
//! │    └─ Execute pending slashes                               │
//! │    └─ Update state (stakes, treasury, total_supply)         │
//! ├─────────────────────────────────────────────────────────────┤
//! │ 4. Compute State Root                                       │
//! │    └─ compute_state_root() includes slashing effects        │
//! ├─────────────────────────────────────────────────────────────┤
//! │ 5. Verify/Finalize Block                                    │
//! │    └─ Compare computed root with header                     │
//! │    └─ Atomic commit to LMDB                                 │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! #### Mengapa Slashing Harus Setelah TX
//!
//! ```text
//! ALASAN:
//! 1. TX dapat menambah violations (detect_double_sign, dll)
//! 2. TX dapat menambah stake yang akan di-slash
//! 3. TX harus final sebelum slashing dieksekusi
//! 4. Slashing effects harus masuk ke state_root
//!
//! JIKA SLASHING SEBELUM TX:
//! - Violations dari TX saat ini tidak terproses
//! - State_root tidak mencerminkan slashing
//! - Consensus divergence antar node
//!
//! JIKA SLASHING SETELAH STATE_ROOT:
//! - State_root tidak mencerminkan slashing
//! - Block header mismatch
//! - Block validation failure
//! ```
//!
//! #### Hubungan dengan State Root
//!
//! ```text
//! STATE_ROOT COMPUTATION ORDER:
//!
//! state_root = hash(
//!     balances,           // ← Updated by TX + slashing
//!     validators,         // ← Updated by slashing
//!     validator_stakes,   // ← Reduced by slashing
//!     treasury_balance,   // ← Increased by slashing
//!     total_supply,       // ← Decreased by burn
//!     slashing_events,    // ← New events added
//!     ...other fields
//! )
//!
//! Slashing effects HARUS tercermin di state_root:
//! - Stake reductions
//! - Treasury additions
//! - Supply burns
//! ```
//!
//! #### Jaminan Determinisme
//!
//! ```text
//! GUARANTEES:
//!
//! ✓ Ordered Iteration:
//!   - node_liveness_records diiterasi dengan urutan deterministik
//!   - Validator violations diproses setelah node violations
//!
//! ✓ Priority Order:
//!   - Node: MaliciousBehavior > DataCorruption > LivenessFailure
//!   - Validator: DoubleSign > MaliciousBlock > ProlongedOffline
//!
//! ✓ No Double-Slash:
//!   - Targets dengan slashed=true di-skip
//!   - Flag di-set sebelum execution
//!
//! ✓ Error Handling:
//!   - Errors di-log, tidak panic
//!   - Processing continues untuk remaining targets
//! ```
//!
//! #### Integration Points
//!
//! ```text
//! | Location                    | Function                         |
//! |-----------------------------|----------------------------------|
//! | lib.rs                      | apply_block_as_full_node()       |
//! | miner.rs                    | mine_block()                     |
//! | internal_slash_adapter.rs   | process_automatic_slashing()     |
//! ```
//!
//! #### Catatan Penting
//!
//! ```text
//! ⚠️ TIDAK BISA DI-SKIP:
//! - Slashing hook HARUS dipanggil di setiap block
//! - Skipping akan menyebabkan state_root mismatch
//!
//! ⚠️ TIDAK BISA DIULANG:
//! - Slashing dieksekusi TEPAT SEKALI per block
//! - Double-execution akan gagal (AlreadySlashed)
//!
//! ⚠️ TIDAK BISA DI-OVERRIDE:
//! - Governance tidak dapat melewati slashing hook
//! - Slashing terjadi otomatis tanpa human intervention
//! ```
//!
//! #### Lokasi File
//!
//! ```text
//! crates/chain/src/state/internal_slash_adapter.rs (process_automatic_slashing)
//! crates/chain/src/lib.rs (apply_block_as_full_node integration)
//! crates/chain/src/miner.rs (mine_block integration)
//! ```
//! //! ### 13.14.7 — Slashing Persistence (LMDB)
//!
//! Tahap ini menjadikan node liveness dan slashing state PERSISTEN di LMDB.
//! Semua data yang dipersist adalah CONSENSUS-CRITICAL.
//!
//! #### Mengapa Slashing State Harus Persisted
//!
//! ```text
//! ALASAN:
//! 1. Node restart tidak boleh menghapus slashing history
//! 2. Double-slash protection memerlukan persistent flags
//! 3. State_root harus konsisten setelah restart
//! 4. Semua full node harus memiliki state identik
//!
//! TANPA PERSISTENCE:
//! - Node restart = slashing state hilang
//! - Double-slash protection tidak berfungsi
//! - State_root mismatch setelah restart
//! - Consensus failure
//! ```
//!
//! #### Apa yang Dipersist
//!
//! ```text
//! DIPERSIST (LMDB bucket: node_liveness):
//!
//! NodeLivenessRecord {
//!     node_address: Address,
//!     last_seen_timestamp: u64,
//!     consecutive_failures: u32,
//!     data_corruption_count: u32,
//!     malicious_behavior_count: u32,
//!     force_unbond_until: Option<u64>,
//!     slashed: bool,
//!     double_sign_detected: bool,
//!     malicious_block_detected: bool,
//!     offline_since: Option<u64>,
//! }
//!
//! KEY FORMAT:
//! - node_address (20 bytes)
//!
//! VALUE FORMAT:
//! - bincode::serialize(NodeLivenessRecord)
//! ```
//!
//! #### Apa yang TIDAK Dipersist
//!
//! ```text
//! TIDAK DIPERSIST (runtime-only):
//!
//! - slashing_events: Vec<SlashingEvent>
//!   → Hanya untuk audit trail runtime
//!   → Tidak termasuk dalam state_root
//!   → Starts empty setelah restart
//! ```
//!
//! #### Hubungan dengan State Root
//!
//! ```text
//! STATE_ROOT POSITION #30:
//!
//! state_root = hash(
//!     ...existing fields #1-#29...,
//!     node_liveness_records,  // Position #30 (13.14.7)
//! )
//!
//! HASHING FORMAT:
//! - Sort by node_address ascending
//! - For each record:
//!   [node_address (20 bytes)] + [bincode(NodeLivenessRecord)]
//! ```
//!
//! #### Determinisme & Consensus Safety
//!
//! ```text
//! GUARANTEES:
//!
//! ✓ Deterministic Serialization:
//!   - bincode serialization is deterministic
//!   - Same record = same bytes on all nodes
//!
//! ✓ Sorted Iteration:
//!   - Records sorted by node_address
//!   - Same order on all nodes
//!
//! ✓ Roundtrip Validity:
//!   - export → restart → load → state identik
//!   - State_root tetap sama
//!
//! ✓ No Runtime-Only Leakage:
//!   - slashing_events tidak dipersist
//!   - Tidak memengaruhi consensus
//! ```
//!
//! #### Hard Fork Notice
//!
//! ```text
//! ⚠️ CONSENSUS-CRITICAL FORMAT:
//!
//! Perubahan berikut MEMERLUKAN HARD FORK:
//! - Mengubah key format (node_address encoding)
//! - Mengubah value format (NodeLivenessRecord fields)
//! - Mengubah posisi di state_root (#30)
//! - Mengubah sort order
//!
//! Format saat ini adalah FINAL untuk chain lifecycle ini.
//! ```
//!
//! #### LMDB Methods
//!
//! ```text
//! | Method                           | Fungsi                              |
//! |----------------------------------|-------------------------------------|
//! | put_node_liveness(node, record)  | Store record ke LMDB                |
//! | get_node_liveness(node)          | Get record by address               |
//! | delete_node_liveness(node)       | Delete record                       |
//! | load_all_node_liveness()         | Load semua records                  |
//! ```
//!
//! #### State Layout Methods
//!
//! ```text
//! | Method                           | Fungsi                              |
//! |----------------------------------|-------------------------------------|
//! | export_node_liveness_to_layout   | Export state → LMDB                 |
//! | load_node_liveness_from_layout   | Load LMDB → state                   |
//! ```
//!
//! #### Lokasi File
//!
//! ```text
//! crates/chain/src/db.rs (LMDB bucket & methods)
//! crates/chain/src/state/internal_state_layout.rs (export/load)
//! crates/chain/src/state/internal_state_root.rs (state_root position #30)
//! ```
//! //! ## 13.15 — Adaptive Economic & Deflation Controller
//!
//! ### Tujuan
//!
//! Mengimplementasikan mekanisme deflasi adaptif $NUSA sesuai whitepaper
//! (target 3–6% per tahun) tanpa mengganggu fase bootstrap jaringan.
//!
//! ### Overview
//!
//! ```text
//! Economic Controller bertanggung jawab untuk:
//! - Mengontrol burn rate treasury secara dinamis
//! - Menyesuaikan ekonomi berdasarkan RF, usage, treasury, velocity
//! - Target deflasi 3-6% per tahun (adaptif, tidak hard-coded)
//! - Melindungi treasury dengan minimum reserve
//! ```
//!
//! ### Aturan Dasar
//!
//! ```text
//! RF = 3 (Bootstrap Mode):
//! - Burn = 0% atau minimal
//! - Fokus akuisisi user
//! - EconomicMode::Bootstrap aktif
//!
//! RF > 3 (Active Mode):
//! - Burn aktif secara bertahap
//! - Target deflasi 3-6% tahunan
//! - EconomicMode::Active
//!
//! Governance Mode:
//! - Parameter diatur via on-chain governance
//! - Diaktifkan setelah network mature
//! ```
//!
//! ### Konstanta Deflasi (13.15.1)
//!
//! ```text
//! | Konstanta                    | Nilai     | Keterangan                    |
//! |------------------------------|-----------|-------------------------------|
//! | DEFLATION_TARGET_MIN_PERCENT | 300       | 3% (basis points, 10000=100%) |
//! | DEFLATION_TARGET_MAX_PERCENT | 600       | 6% (basis points)             |
//! | BOOTSTRAP_RF                 | 3         | RF fase bootstrap             |
//! | BURN_INTERVAL_EPOCHS         | 52        | 1x per minggu (epoch=1 hari)  |
//! | MIN_TREASURY_RESERVE         | 1_000_000 | Min treasury sebelum burn     |
//! | VELOCITY_SMOOTHING_FACTOR    | 80        | EMA smoothing 80% weight      |
//! | MAX_BURN_PER_EPOCH_PERCENT   | 50        | Max 0.5% supply per epoch     |
//!
//! ⚠️ Semua nilai dalam BASIS POINTS (10000 = 100%)
//! ⚠️ Perubahan konstanta memerlukan hard-fork
//! ```
//!
//! ### EconomicMode Enum (13.15.1)
//!
//! ```text
//! EconomicMode {
//!     Bootstrap,   // RF <= 3, burn minimal / 0
//!     Active,      // RF > 3, burn aktif
//!     Governance,  // parameter via governance
//! }
//!
//! Transisi mode:
//! - Bootstrap → Active: ketika RF > BOOTSTRAP_RF
//! - Active → Governance: via governance proposal
//! ```
//!
//! ### Data Structures (13.15.1)
//!
//! #### DeflationConfig
//!
//! ```text
//! DeflationConfig {
//!     target_min_percent: u128,        // 300 (3%)
//!     target_max_percent: u128,        // 600 (6%)
//!     burn_interval_epochs: u64,       // 52
//!     min_treasury_reserve: u128,      // 1_000_000
//!     max_burn_per_epoch_percent: u128,// 50 (0.5%)
//!     mode: EconomicMode,              // Bootstrap
//!     enabled: bool,                   // true
//! }
//!
//! Default: Bootstrap mode, enabled
//! new_bootstrap(): Sama dengan Default
//! ```
//!
//! #### EconomicMetrics
//!
//! ```text
//! EconomicMetrics {
//!     replication_factor: u8,          // RF saat ini
//!     storage_usage_bytes: u128,       // Total storage usage
//!     compute_cycles_used: u128,       // Total compute cycles
//!     active_nodes: u64,               // Node aktif
//!     active_validators: u64,          // Validator aktif
//!     token_velocity: u128,            // Transfer volume / time
//!     treasury_inflow_epoch: u128,     // Inflow dari fees
//!     slashing_inflow_epoch: u128,     // Inflow dari slashing
//!     last_updated_epoch: u64,         // Epoch terakhir update
//! }
//!
//! Default: RF = BOOTSTRAP_RF (3), semua numeric = 0
//! new(): Sama dengan Default
//! ```
//!
//! #### BurnEvent
//!
//! ```text
//! BurnEvent {
//!     epoch: u64,                      // Epoch saat burn
//!     amount_burned: u128,             // Jumlah di-burn
//!     treasury_before: u128,           // Treasury sebelum
//!     treasury_after: u128,            // Treasury sesudah
//!     total_supply_before: u128,       // Supply sebelum
//!     total_supply_after: u128,        // Supply sesudah
//!     burn_rate_applied: u128,         // Rate (basis points)
//!     timestamp: u64,                  // Unix timestamp
//! }
//!
//! Runtime-only, tidak dipersist ke LMDB
//! ```
//!
//! #### EconomicSnapshot
//!
//! ```text
//! EconomicSnapshot {
//!     epoch: u64,                      // Epoch snapshot
//!     metrics: EconomicMetrics,        // Metrics saat ini
//!     config: DeflationConfig,         // Config saat ini
//!     treasury_balance: u128,          // Treasury balance
//!     total_supply: u128,              // Total supply
//!     annual_burn_rate: u128,          // Rate aktual (bp)
//! }
//!
//! Digunakan untuk audit dan RPC query
//! ```
//!
//! ### Catatan Penting (13.15.1)
//!
//! ```text
//! ⚠️ TAHAP 13.15.1 HANYA DEFINISI:
//! - Tidak ada execution logic di tahap ini
//! - Tidak ada burn logic
//! - Tidak ada state mutation
//! - Ini adalah fondasi untuk controller tahap berikutnya
//!
//! ⚠️ CONSENSUS-CRITICAL:
//! - Semua konstanta memerlukan hard-fork untuk diubah
//! - Urutan enum variant tidak boleh diubah
//! - Urutan struct field tidak boleh diubah
//!
//! ```
//!
//! ### Lokasi File (13.15.1)
//!
//! ```text
//! crates/chain/src/economic.rs (konstanta, enum, structs)
//! ```
//!
//! ## 13.16 — Chain RPC (Final, Celestia-aware)
//!
//! ### Overview
//!
//! Tahap 13.16 adalah **final RPC layer** untuk blockchain DSDN yang menyediakan
//! interface standar untuk wallet, explorer, SDK, dan exchange. Semua endpoint
//! bersifat **read-only query** atau **transaction submission** tanpa logic
//! consensus. Layer ini adalah **Celestia-aware** untuk observability DA layer.
//!
//! ### RPC Endpoints
//!
//! | RPC Method | Tujuan | Request | Response |
//! |------------|--------|---------|----------|
//! | **Core Query** | | | |
//! | `get_balance` | Query saldo address | `address: String` | `BalanceRes` |
//! | `get_nonce` | Query nonce address | `address: String` | `NonceRes` |
//! | **Transaction** | | | |
//! | `submit_tx` | Submit signed transaction | `SubmitTxReq` | `SubmitTxRes` |
//! | `get_receipt_status` | Query receipt claim status | `receipt_id: String` | `ReceiptStatusRes` |
//! | **Staking** | | | |
//! | `get_stake_info` | Query stake info address | `address: String` | `StakeInfoRes` |
//! | `submit_stake` | Submit stake transaction | `StakeReq` | `StakingOpRes` |
//! | `submit_delegate` | Submit delegation tx | `DelegateReq` | `StakingOpRes` |
//! | `submit_unstake` | Submit unstake transaction | `UnstakeReq` | `StakingOpRes` |
//! | **Fee & Gas** | | | |
//! | `get_fee_split` | Calculate fee distribution | `resource_class, total_fee` | `FeeSplitRes` |
//! | `estimate_storage_cost` | Estimate storage gas | `bytes, node_address?` | `StorageCostRes` |
//! | `estimate_compute_cost` | Estimate compute gas | `cycles, node_address?` | `ComputeCostRes` |
//! | **Snapshot & DA** | | | |
//! | `get_snapshot` | Get state summary | (none) | `SnapshotRes` |
//! | `get_blob_height` | Get Celestia DA status | (none) | `BlobHeightRes` |
//!
//! ### Request / Response Structures
//!
//! ```text
//! Response Types:
//! - BalanceRes         { balance: String }
//! - NonceRes           { nonce: u64 }
//! - SubmitTxRes        { success: bool, txid: String, message: String }
//! - StakeInfoRes       { address, validator_stake, delegator_stake, pending_unstake, delegated_to }
//! - StakingOpRes       { success: bool, txid: String, message: String }
//! - FeeSplitRes        { resource_class, total_fee, node_share, validator_share, treasury_share }
//! - StorageCostRes     { bytes, base_cost, byte_cost, node_multiplier, total_gas, total_cost }
//! - ComputeCostRes     { cycles, base_cost, cycle_cost, node_multiplier, total_gas, total_cost }
//! - ReceiptStatusRes   { receipt_id, claimed, claimed_at?, claimed_by?, node_address?, amount? }
//! - SnapshotRes        { height, state_root, total_accounts, total_validators, total_supply, treasury_balance, epoch, timestamp }
//! - BlobHeightRes      { dsdn_height, celestia_height?, last_sync_timestamp?, sync_status }
//!
//! Request Types:
//! - SubmitTxReq        { tx_envelope_hex: String }
//! - StakeReq           { tx_envelope_hex: String }
//! - DelegateReq        { tx_envelope_hex: String }
//! - UnstakeReq         { tx_envelope_hex: String }
//!
//! ⚠️ PENTING: Semua nilai u128 diekspos sebagai String untuk menghindari
//! JSON integer overflow di client (JavaScript max safe integer: 2^53-1).
//! ```
//!
//! ### Celestia-awareness Notes
//!
//! ```text
//! DSDN blockchain dapat beroperasi dengan atau tanpa Celestia DA layer:
//!
//! ✓ Tanpa Celestia:
//!   - Chain berfungsi normal sebagai standalone blockchain
//!   - get_blob_height() returns: celestia_height = None, sync_status = "not_synced"
//!
//! ✓ Dengan Celestia:
//!   - get_blob_height() returns: celestia_height, last_sync_timestamp, sync_status
//!   - sync_status: "synced" (last sync < 5 min), "syncing", "not_synced"
//!
//! ⚠️ Field Celestia BUKAN consensus-critical:
//!   - Tidak masuk ke state_root computation
//!   - Hanya untuk observability & audit DA layer
//!   - Disimpan di Chain struct sebagai AtomicU64 (thread-safe)
//! ```
//!
//! ### Implementation Status (13.16)
//!
//! ```text
//! | Sub-tahap | Deskripsi                    | Status |
//! |-----------|------------------------------|--------|
//! | 13.16.1   | Core Query RPC               | ✅     |
//! | 13.16.2   | Transaction Submission RPC   | ✅     |
//! | 13.16.3   | Staking RPC                  | ✅     |
//! | 13.16.4   | Fee & Gas Estimation RPC     | ✅     |
//! | 13.16.5   | Receipt Status Enhancement   | ✅     |
//! | 13.16.6   | Snapshot & Celestia RPC      | ✅     |
//! | 13.16.7   | Documentation Update         | ✅     |
//! ```
//!
//! ### Lokasi File (13.16)
//!
//! ```text
//! crates/chain/src/rpc.rs       — RPC structs & methods
//! crates/chain/src/lib.rs       — Chain struct (Celestia tracking fields)
//! crates/chain/src/state/mod.rs — Gas estimation helpers
//! ```
//!
//! ## 13.17 — Wallet Integration
//!
//! ### Overview
//!
//! Wallet module menyediakan high-level API untuk manajemen identitas kriptografis
//! user di DSDN blockchain. Module ini adalah fondasi untuk semua operasi yang
//! memerlukan signing dan enkripsi.
//!
//! ### 13.17.1 — Wallet Module Foundation
//!
//! ```text
//! TUJUAN:
//! Menyediakan abstraksi aman untuk Ed25519 keypair management.
//!
//! STRUCT WALLET:
//! ┌────────────────────────────────────────────────────────────────┐
//! │ Wallet                                                         │
//! ├────────────────────────────────────────────────────────────────┤
//! │ keypair_bytes: [u8; 64]   // secret (32) + public (32)        │
//! │ public_key: [u8; 32]      // extracted from keypair            │
//! │ address: Address          // derived from public_key           │
//! └────────────────────────────────────────────────────────────────┘
//!
//! INVARIANTS (WAJIB TERJAGA):
//! - keypair_bytes[0..32]  = secret key
//! - keypair_bytes[32..64] = public key
//! - public_key == keypair_bytes[32..64]
//! - address = address_from_pubkey_bytes(public_key)
//! ```
//!
//! ### Wallet → Address → Chain Relationship
//!
//! ```text
//! ┌──────────┐     ┌────────────┐     ┌─────────────────┐
//! │  Wallet  │────►│ public_key │────►│    Address      │
//! │          │     │  (32 bytes)│     │   (20 bytes)    │
//! └──────────┘     └────────────┘     └────────┬────────┘
//!                                              │
//!                                              ▼
//!                                    ┌─────────────────┐
//!                                    │   ChainState    │
//!                                    ├─────────────────┤
//!                                    │ balances[addr]  │
//!                                    │ nonces[addr]    │
//!                                    │ locked[addr]    │
//!                                    └─────────────────┘
//! ```
//!
//! ### Constructor Methods
//!
//! ```text
//! | Method                | Input           | Output   | Description                    |
//! |-----------------------|-----------------|----------|--------------------------------|
//! | Wallet::generate()    | -               | Wallet   | Generate random keypair baru   |
//! | Wallet::from_secret_key(&[u8;32]) | secret | Wallet | Restore dari secret key |
//! | Wallet::from_bytes(&[u8;64])      | keypair| Wallet | Restore dari full keypair |
//! ```
//!
//! ### Getter Methods
//!
//! ```text
//! | Method        | Return         | Description                          |
//! |---------------|----------------|--------------------------------------|
//! | address()     | Address        | Blockchain address (copy)            |
//! | public_key()  | &[u8; 32]      | Public key reference                 |
//! | secret_key()  | &[u8; 32]      | Secret key reference (SENSITIVE!)    |
//! ```
//!
//! ### Export Methods
//!
//! ```text
//! | Method            | Return     | Description                          |
//! |-------------------|------------|--------------------------------------|
//! | export_keypair()  | [u8; 64]   | Full keypair untuk backup            |
//! | export_secret_hex()| String    | Secret key dalam hex (lowercase)     |
//! ```
//!
//! ### Security Guarantees
//!
//! ```text
//! ✅ DIJAMIN:
//! - NO PANIC: Semua error di-handle gracefully
//! - DETERMINISTIC: Same secret → same wallet
//! - CONSISTENT: Address derivation sama dengan chain
//! - SAFE DEBUG: Debug trait tidak pernah leak secret key
//!
//! ⚠️ TIDAK DIJAMIN:
//! - Memory zeroization setelah drop
//! - Protection dari memory dump
//! - Side-channel resistance
//!
//! 🔒 SECURITY RULES:
//! - secret_key() output TIDAK BOLEH di-log
//! - export_secret_hex() HANYA untuk backup
//! - keypair_bytes mengandung secret material
//! ```
//!
//! ### NOT Provided in 13.17.1-4 (Tahap Berikutnya)
//!
//! ```text
//! | Feature                    | Tahap    |
//! |----------------------------|----------|
//! | File encryption/decryption | 13.17.5  |
//! | DA blob commitment verify  | 13.17.6  |
//! | RPC & CLI integration      | 13.17.8  |
//! ```
//!
//! ### 13.17.2 — Transaction Signing
//!
//! ```text
//! TUJUAN:
//! Menyediakan API signing untuk message dan transaction di Wallet.
//!
//! SIGNING FLOW:
//! ┌──────────┐     ┌─────────────┐     ┌───────────┐     ┌────────────┐
//! │  Wallet  │────►│  TxEnvelope │────►│  Payload  │────►│ Signature  │
//! │          │     │ (unsigned)  │     │  (bytes)  │     │ (64 bytes) │
//! └──────────┘     └─────────────┘     └───────────┘     └────────────┘
//!       │                                                       │
//!       │                                                       ▼
//!       │                                              ┌────────────────┐
//!       └──────────────────────────────────────────────│  TxEnvelope    │
//!                                                      │  (signed)      │
//!                                                      │  + signature   │
//!                                                      │  + pubkey      │
//!                                                      └────────────────┘
//! ```
//!
//! ### Signing Methods
//!
//! ```text
//! | Method                              | Return                    | Description                |
//! |-------------------------------------|---------------------------|----------------------------|
//! | sign_message(&self, &[u8])          | Vec<u8>                   | Sign arbitrary bytes       |
//! | sign_tx(&self, &TxEnvelope)         | Result<TxEnvelope, Error> | Sign tx, return new env    |
//! | verify_signature(&self, &[u8], &[u8])| bool                     | Verify dengan pubkey sendiri|
//! ```
//!
//! ### WalletError
//!
//! ```text
//! pub enum WalletError {
//!     SigningFailed(String),      // Signing gagal
//!     InvalidKeyLength,           // Key bukan 32/64 bytes
//!     SerializationError(String), // Payload serialization gagal
//! }
//! ```
//!
//! ### Apa yang Di-Sign
//!
//! ```text
//! ⚠️ CRITICAL:
//! - HANYA payload yang di-sign, BUKAN seluruh envelope
//! - Payload di-serialize menggunakan tx.payload_bytes()
//! - Signature selalu 64 bytes (Ed25519)
//! - Public key di-inject ke envelope.pubkey
//!
//! FLOW sign_tx():
//! 1. payload_bytes = tx.payload_bytes()     // Serialize payload
//! 2. signature = sign(keypair, payload_bytes) // Sign
//! 3. new_tx.signature = signature           // Inject signature
//! 4. new_tx.pubkey = self.public_key        // Inject pubkey
//! 5. return new_tx                          // Return signed envelope
//! ```
//!
//! ### Verification
//!
//! ```text
//! WALLET VERIFICATION (verify_signature):
//! - Verify HANYA dengan public key milik wallet sendiri
//! - Digunakan untuk self-check setelah signing
//! - Return false jika signature invalid atau error
//!
//! CHAIN VERIFICATION (tx.verify_signature()):
//! - Dilakukan oleh chain saat memproses transaksi
//! - Wallet TIDAK melakukan chain verification
//! - Wallet TIDAK melakukan execution
//! ```
//!
//! ### Security Notes
//!
//! ```text
//! ✅ DIJAMIN:
//! - NO PANIC: Semua error di-handle via Result/Option
//! - DETERMINISTIC: Same input → same signature (Ed25519)
//! - IMMUTABLE: Input tx tidak dimodifikasi
//!
//! ⚠️ TIDAK DILAKUKAN WALLET:
//! - Hashing payload (sudah di-handle crypto module)
//! - Chain validation
//! - Execution
//! - State mutation
//! ```
//!
//! ### 13.17.3 — Storage Payment Schedule Data Structures
//!
//! ```text
//! TUJUAN:
//! Menyediakan data structures untuk storage contract management
//! dan payment scheduling.
//!
//! DATA STRUCTURES:
//! - StorageContract: Kontrak penyimpanan
//! - StorageContractStatus: Status lifecycle
//! - PaymentSchedule: Jadwal pembayaran
//! - StoragePaymentError: Error types
//! ```
//!
//! ### Storage Contract Model
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      StorageContract                            │
//! ├─────────────────────────────────────────────────────────────────┤
//! │ contract_id: Hash           // Unique identifier (64 bytes)     │
//! │ owner: Address              // User yang membayar               │
//! │ node_address: Address       // Storage node provider            │
//! │ storage_bytes: u64          // Ukuran data (bytes)              │
//! │ monthly_cost: u128          // Biaya per bulan (NUSA)           │
//! │ start_timestamp: u64        // Waktu mulai                      │
//! │ end_timestamp: u64          // Waktu berakhir                   │
//! │ last_payment_timestamp: u64 // Pembayaran terakhir              │
//! │ status: StorageContractStatus                                   │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ### Storage Contract Status
//!
//! ```text
//! ┌────────────┐     ┌─────────────┐     ┌─────────┐
//! │   Active   │────►│ GracePeriod │────►│ Expired │
//! └────────────┘     └─────────────┘     └─────────┘
//!       │                                      ▲
//!       │                                      │
//!       ▼                                      │
//! ┌────────────┐                               │
//! │ Cancelled  │───────────────────────────────┘
//! └────────────┘
//!
//! Status:
//! - Active      → Kontrak sehat, pembayaran lancar
//! - GracePeriod → Telat bayar, dalam masa tenggang (7 hari)
//! - Expired     → Kontrak berakhir, data akan dihapus
//! - Cancelled   → Dibatalkan oleh owner
//! ```
//!
//! ### Payment Schedule
//!
//! ```text
//! PaymentSchedule {
//!     next_due_timestamp: u64,      // Kapan jatuh tempo
//!     grace_period_seconds: u64,    // Default: 7 hari
//!     payments_made: u64,           // Jumlah pembayaran
//!     total_paid: u128,             // Total yang dibayar
//! }
//!
//! Constants:
//! - GRACE_PERIOD_SECONDS = 604,800 (7 hari)
//! - PAYMENT_INTERVAL_SECONDS = 2,592,000 (30 hari)
//! ```
//!
//! ### 13.17.4 — Storage Payment Logic
//!
//! ```text
//! TUJUAN:
//! Menyediakan logic pembayaran storage bulanan yang deterministik.
//!
//! FEE DISTRIBUTION (CONSENSUS-CRITICAL):
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    monthly_cost                                 │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  70% ─────────────────────────►  node_earnings[node]            │
//! │  20% ─────────────────────────►  validator_fee_pool             │
//! │  10% ─────────────────────────►  treasury_balance               │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ### Payment Flow
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │                 STORAGE PAYMENT FLOW                             │
//! ├──────────────────────────────────────────────────────────────────┤
//! │                                                                  │
//! │  1. CREATE CONTRACT (create_storage_contract)                    │
//! │     ├── Validate: owner.balance >= monthly_cost                  │
//! │     ├── Deduct: owner.balance -= monthly_cost                    │
//! │     ├── Distribute: 70/20/10 split                               │
//! │     └── Create: contract.status = Active                         │
//! │                                                                  │
//! │  2. MONTHLY PAYMENT (process_monthly_payment)                    │
//! │     ├── Check: is payment due?                                   │
//! │     ├── If balance >= cost:                                      │
//! │     │   ├── Deduct owner balance                                 │
//! │     │   ├── Distribute 70/20/10                                  │
//! │     │   └── Update last_payment_timestamp                        │
//! │     └── If balance < cost:                                       │
//! │         └── Set status = GracePeriod                             │
//! │                                                                  │
//! │  3. GRACE PERIOD CHECK (check_contract_status)                   │
//! │     ├── If in GracePeriod AND grace expired:                     │
//! │     │   └── Set status = Expired                                 │
//! │     └── If past end_timestamp:                                   │
//! │         └── Set status = Expired                                 │
//! │                                                                  │
//! │  4. CANCEL (cancel_storage_contract)                             │
//! │     ├── Validate: caller == owner                                │
//! │     └── Set status = Cancelled (NO REFUND)                       │
//! │                                                                  │
//! │  5. BATCH PROCESS (process_storage_payments)                     │
//! │     └── For all Active contracts: check & process payments       │
//! │                                                                  │
//! └──────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ### ChainState Methods (13.17.4)
//!
//! ```text
//! | Method                      | Description                            |
//! |-----------------------------|----------------------------------------|
//! | create_storage_contract()   | Create new contract + first payment    |
//! | process_monthly_payment()   | Process single contract payment        |
//! | check_contract_status()     | Check and update contract status       |
//! | cancel_storage_contract()   | Cancel contract (owner only, no refund)|
//! | process_storage_payments()  | Batch process all due payments         |
//! ```
//!
//! ### ChainState Fields (13.17.3)
//!
//! ```text
//! storage_contracts: HashMap<Hash, StorageContract>
//!     └── Sumber kebenaran utama untuk semua kontrak
//!
//! user_contracts: HashMap<Address, Vec<Hash>>
//!     └── Index untuk query cepat kontrak per user
//!
//! Kedua field adalah CONSENSUS-CRITICAL (in state_root).
//! ```
//!
//! ### Relationship
//!
//! ```text
//! User (Owner)                Storage Node
//!      │                           │
//!      │    StorageContract        │
//!      └──────────┬────────────────┘
//!                 │
//!                 ▼
//!          ChainState
//!          ├── storage_contracts[contract_id]
//!          └── user_contracts[owner] → [contract_id, ...]
//! ```
//!
//! ### Implementation Status (13.17)
//!
//! ```text
//! | Sub-tahap | Deskripsi                    | Status |
//! |-----------|------------------------------|--------|
//! | 13.17.1   | Wallet Module Foundation     | ✅     |
//! | 13.17.2   | Transaction Signing          | ✅     |
//! | 13.17.3   | Storage Payment Structures   | ✅     |
//! | 13.17.4   | Storage Payment Logic        | ✅     |
//! | 13.17.5   | File Encryption              | ⏳     |
//! | 13.17.6   | DA Blob Commitment           | ⏳     |
//! | 13.17.7   | LMDB Persistence             | ⏳     |
//! | 13.17.8   | RPC & CLI                    | ⏳     |
//! | 13.17.9   | Documentation Update         | ⏳     |
//! | 13.17.10  | E2E Testing                  | ⏳     |
//! ```
//!
//! ### Lokasi File (13.17)
//!
//! ```text
//! crates/chain/src/wallet.rs                         — Wallet struct & methods (13.17.1-2)
//! crates/chain/src/lib.rs                            — Module declaration & re-export
//! crates/chain/src/state/mod.rs                      — ChainState fields & wrapper methods
//! crates/chain/src/state/internal_storage_payment.rs — Storage payment structures & logic (13.17.3-4)
//! ```
//!
//! ════════════════════════════════════════════════════════════════════════════════
//! ## 13.18 — State Snapshots & Checkpoints
//! ════════════════════════════════════════════════════════════════════════════════
//!
//! ### Overview
//!
//! Snapshot system memungkinkan:
//! - **Fast Sync**: Node baru download snapshot, replay blocks setelahnya
//! - **Recovery**: Rollback ke checkpoint saat terjadi corruption
//! - **Audit**: Verifikasi state historis untuk compliance
//!
//! ### Arsitektur
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    SNAPSHOT SYSTEM                              │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                 │
//! │  AUTOMATIC TRIGGER                                              │
//! │  ──────────────────                                             │
//! │  Setiap N blocks (default 1000):                               │
//! │    1. Copy LMDB database                                        │
//! │    2. Write metadata.json                                       │
//! │    3. Cleanup old snapshots (FIFO)                             │
//! │                                                                 │
//! │  STORAGE LAYOUT                                                 │
//! │  ──────────────────                                             │
//! │  snapshots/                                                     │
//! │  ├── checkpoint_1000/                                           │
//! │  │   ├── data.mdb        ← LMDB database copy                  │
//! │  │   └── metadata.json   ← SnapshotMetadata                    │
//! │  ├── checkpoint_2000/                                           │
//! │  │   ├── data.mdb                                              │
//! │  │   └── metadata.json                                         │
//! │  └── ...                                                        │
//! │                                                                 │
//! │  FAST SYNC FLOW                                                 │
//! │  ──────────────────                                             │
//! │  1. Download snapshot dari peer                                 │
//! │  2. Validate: compute state_root == metadata.state_root        │
//! │  3. Replay blocks dari snapshot height ke tip                   │
//! │  4. Rebuild control-plane dari Celestia blobs                   │
//! │                                                                 │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ### 13.18.1 — Snapshot Types & Configuration
//!
//! Sub-tahap ini mendefinisikan tipe data fondasi untuk snapshot system.
//! **TIDAK ADA logic eksekusi** - hanya definisi tipe.
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    SNAPSHOT TYPES                               │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                 │
//! │  SnapshotConfig                                                 │
//! │  ─────────────────                                              │
//! │  - interval_blocks: u64    → Snapshot setiap N blocks          │
//! │  - path: String            → Direktori penyimpanan             │
//! │  - max_snapshots: u32      → Max snapshots (FIFO cleanup)      │
//! │                                                                 │
//! │  SnapshotMetadata                                               │
//! │  ─────────────────                                              │
//! │  - height: u64             → Block height snapshot             │
//! │  - state_root: Hash        → State root untuk verifikasi       │
//! │  - timestamp: u64          → Unix timestamp pembuatan          │
//! │  - block_hash: Hash        → Hash block untuk cross-ref        │
//! │                                                                 │
//! │  SnapshotStatus                                                 │
//! │  ─────────────────                                              │
//! │  - Creating                → Snapshot sedang dibuat            │
//! │  - Ready                   → Snapshot valid & siap pakai       │
//! │  - Corrupted               → Snapshot rusak / gagal verify     │
//! │                                                                 │
//! │  Constants                                                      │
//! │  ─────────────────                                              │
//! │  - DEFAULT_SNAPSHOT_INTERVAL = 1000 blocks                     │
//! │                                                                 │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ### 13.18.2 — Snapshot Creation (LMDB Copy)
//!
//! Sub-tahap ini mengimplementasikan pembuatan snapshot LMDB.
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                 SNAPSHOT CREATION FLOW                          │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                 │
//! │  1. CREATE FOLDER                                               │
//! │     └── {target_path}/checkpoint_{height}/                      │
//! │                                                                 │
//! │  2. COPY LMDB (ATOMIC)                                          │
//! │     └── env.copy_to_path() → data.mdb                          │
//! │     └── Read-only copy, tidak block writers                     │
//! │     └── Jika gagal → cleanup folder (rollback)                  │
//! │                                                                 │
//! │  3. WRITE METADATA                                              │
//! │     └── serialize(SnapshotMetadata) → metadata.json            │
//! │     └── Contains: height, state_root, timestamp, block_hash    │
//! │                                                                 │
//! │  RESULT                                                         │
//! │  ──────                                                         │
//! │  snapshots/checkpoint_{height}/                                 │
//! │  ├── data.mdb        ← Complete LMDB copy                      │
//! │  └── metadata.json   ← Verification data                       │
//! │                                                                 │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! #### ChainDb Methods (13.18.2)
//!
//! | Method | Signature | Description |
//! |--------|-----------|-------------|
//! | `create_snapshot` | `(&self, height: u64, target_path: &Path) -> Result<(), DbError>` | Copy LMDB ke folder snapshot |
//! | `write_snapshot_metadata` | `(&self, snapshot_path: &Path, metadata: &SnapshotMetadata) -> Result<(), DbError>` | Tulis metadata.json |
//!
//! #### DbError (13.18.2)
//!
//! Error type untuk snapshot operations:
//! - `DirectoryCreation` — Gagal buat folder
//! - `LmdbCopy` — Gagal copy database
//! - `MetadataWrite` — Gagal tulis metadata
//! - `Serialization` — Gagal serialize JSON
//! - `DirectoryNotFound` — Folder tidak ada
//! - `Cleanup` — Gagal rollback
//!
//! #### Atomicity & Crash Safety
//!
//! ```text
//! ⚠️ ATOMICITY GUARANTEE:
//!
//! - Jika LMDB copy gagal → folder dihapus
//! - Tidak ada snapshot parsial
//! - Snapshot yang sukses selalu lengkap
//!
//! ⚠️ CRASH SAFETY:
//!
//! - LMDB copy menggunakan internal transaction
//! - Copy bersifat read-only, tidak block writers
//! - Chain dapat terus berjalan saat snapshot dibuat
//! ```
//!
//! ### 13.18.3 — Snapshot Loading & Validation
//!
//! Sub-tahap ini mengimplementasikan loading dan validasi snapshot.
//! **ZERO-TRUST PRINCIPLE**: Snapshot TIDAK dipercaya secara default.
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                 SNAPSHOT VALIDATION FLOW                        │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                 │
//! │  STEP 1: READ METADATA                                          │
//! │  ──────────────────────                                         │
//! │  read_snapshot_metadata(path)                                   │
//! │    └── Parse metadata.json                                      │
//! │    └── Extract expected state_root                              │
//! │                                                                 │
//! │  STEP 2: LOAD SNAPSHOT                                          │
//! │  ──────────────────────                                         │
//! │  load_snapshot(path)                                            │
//! │    └── Verify data.mdb exists                                   │
//! │    └── Open LMDB environment (read-only)                        │
//! │    └── Return ChainDb instance                                  │
//! │                                                                 │
//! │  STEP 3: VALIDATE STATE ROOT                                    │
//! │  ──────────────────────                                         │
//! │  validate_snapshot(path)                                        │
//! │    └── Load state from LMDB                                     │
//! │    └── Compute state_root from state                            │
//! │    └── Compare: computed == expected?                           │
//! │        ├── YES → Ok(())                                        │
//! │        └── NO  → Err(SnapshotCorrupted)                        │
//! │                                                                 │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! #### ChainDb Methods (13.18.3)
//!
//! | Method | Signature | Description |
//! |--------|-----------|-------------|
//! | `load_snapshot` | `(path: &Path) -> Result<ChainDb, DbError>` | Load snapshot sebagai read-only ChainDb |
//! | `read_snapshot_metadata` | `(path: &Path) -> Result<SnapshotMetadata, DbError>` | Baca metadata.json |
//! | `validate_snapshot` | `(path: &Path) -> Result<(), DbError>` | Validasi state_root (CONSENSUS-GRADE) |
//! | `list_available_snapshots` | `(base: &Path) -> Result<Vec<SnapshotMetadata>, DbError>` | List semua snapshot valid |
//!
//! #### New DbError Variants (13.18.3)
//!
//! | Variant | Description |
//! |---------|-------------|
//! | `MetadataRead` | Gagal baca metadata.json |
//! | `MetadataInvalid` | JSON invalid atau field tidak lengkap |
//! | `DataNotFound` | data.mdb tidak ditemukan |
//! | `SnapshotOpenFailed` | Gagal buka LMDB environment |
//! | `SnapshotCorrupted` | state_root mismatch (expected vs computed) |
//! | `StateLoadFailed` | Gagal load state dari snapshot |
//!
//! #### Security Boundaries
//!
//! ```text
//! ⚠️ CONSENSUS-CRITICAL VALIDATION:
//!
//! 1. Snapshot TIDAK dipercaya secara default
//! 2. state_root WAJIB divalidasi sebelum boot
//! 3. Snapshot korup HARUS ditolak (SnapshotCorrupted error)
//! 4. Validasi via Merkle hash (deterministic & verifiable)
//!
//! PENTING:
//! - JANGAN skip validate_snapshot() saat recovery
//! - Snapshot tanpa metadata DITOLAK
//! - Snapshot parsial DITOLAK
//! - list_available_snapshots() bersifat read-only & safe
//! ```
//!
//! ### 13.18.4 — Block Replay After Snapshot
//!
//! Sub-tahap ini mengimplementasikan block replay untuk recovery dan fast sync.
//! **REPLAY ADALAH RE-EKSEKUSI KONSENSUS** — harus deterministik.
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    BLOCK REPLAY FLOW                            │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                 │
//! │  INPUT                                                          │
//! │  ─────                                                          │
//! │  - start_height: Height snapshot (replay dari start+1)          │
//! │  - end_height: Target height (tip)                              │
//! │  - progress: Optional callback                                  │
//! │                                                                 │
//! │  REPLAY LOOP (for each block)                                   │
//! │  ───────────────────────────                                    │
//! │  1. Verify block signature                                      │
//! │  2. Execute all transactions (apply_payload)                   │
//! │  3. Process automatic slashing (13.14.6)                       │
//! │  4. Process economic job (13.15.6)                             │
//! │  5. Compute state_root                                         │
//! │  6. VERIFY: computed == block.header.state_root                │
//! │     ├── MATCH → Continue to next block                         │
//! │     └── MISMATCH → Error (ChainError::StateRootMismatch)       │
//! │  7. Call progress callback if provided                          │
//! │                                                                 │
//! │  OUTPUT                                                         │
//! │  ──────                                                         │
//! │  - State di chain.state sudah di-update                        │
//! │  - Semua blocks terverifikasi                                   │
//! │  - Ready untuk normal operation                                 │
//! │                                                                 │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! #### Chain Methods (13.18.4)
//!
//! | Method | Signature | Description |
//! |--------|-----------|-------------|
//! | `replay_blocks_from` | `(&self, start: u64, end: u64, progress: Option<&dyn Fn(u64,u64)>) -> Result<(), ChainError>` | Replay blocks dari snapshot ke tip |
//! | `get_blocks_range` | `(&self, start: u64, end: u64) -> Result<Vec<Block>, ChainError>` | Fetch blocks dari DB |
//!
//! #### ChainError (13.18.4)
//!
//! | Variant | Description |
//! |---------|-------------|
//! | `BlockNotFound` | Block tidak ada di DB |
//! | `InvalidRange` | start > end |
//! | `StateRootMismatch` | computed != expected state_root |
//! | `SignatureVerificationFailed` | Block signature invalid |
//! | `TransactionError` | TX execution error |
//! | `DatabaseError` | DB access error |
//! | `ReplayInterrupted` | Replay dihentikan |
//!
//! #### StateReplayEngine Integration (sync.rs)
//!
//! | Method | Description |
//! |--------|-------------|
//! | `replay_using_chain` | Wrapper untuk Chain::replay_blocks_from |
//! | `fast_sync_from_snapshot` | Load snapshot → set state → replay |
//!
//! #### Consensus-Critical Notes
//!
//! ```text
//! ⚠️ REPLAY ADALAH KONSENSUS-GRADE:
//!
//! 1. Replay HARUS deterministik (same input → same output)
//! 2. state_root WAJIB diverifikasi setiap block
//! 3. Block TIDAK boleh di-skip
//! 4. Mismatch state_root = replay GAGAL TOTAL
//!
//! USE CASES:
//! - Fast sync: download snapshot → replay blocks → catch up
//! - Recovery: restore checkpoint → replay → rebuild state
//! - Audit: verify historical state transitions
//!
//! PENTING:
//! - Replay TIDAK broadcast blocks
//! - Replay TIDAK modify chain tip
//! - Replay HANYA execute dan verify
//! ```
//!
//! ### 13.18.5 — Celestia Control-Plane Rebuild
//!
//! Sub-tahap ini mengimplementasikan rebuild control-plane state dari Celestia DA.
//! **CONTROL-PLANE = SUMBER KEBENARAN KEDUA SETELAH SNAPSHOT**.
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │              CONTROL-PLANE REBUILD FLOW                         │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                 │
//! │  STEP 1: FETCH BLOBS                                            │
//! │  ─────────────────                                              │
//! │  client.fetch_control_plane_range(start_da, end_da)             │
//! │    └── Returns Vec<CelestiaBlob> sorted by (height, index)     │
//! │                                                                 │
//! │  STEP 2: PROCESS BLOBS (ordered)                                │
//! │  ───────────────────────────────                                │
//! │  for blob in blobs:                                             │
//! │      update = parse_blob_to_update(blob)                       │
//! │      match update:                                              │
//! │          ValidatorSetUpdate → update validator_set             │
//! │          EpochRotation → update epoch_info                     │
//! │          GovernanceProposal → restore proposal (NON-BINDING)   │
//! │          ReceiptBatch → skip (handled by ClaimReward tx)       │
//! │          ConfigUpdate → apply config                           │
//! │          Checkpoint → skip (verification only)                 │
//! │                                                                 │
//! │  CRITICAL INVARIANTS                                            │
//! │  ────────────────────                                           │
//! │  - Blobs HARUS diproses dalam urutan (height, index)           │
//! │  - Decode gagal = error keras (tidak boleh skip)               │
//! │  - Rebuild HARUS idempotent                                    │
//! │  - Governance proposals TIDAK dieksekusi                        │
//! │                                                                 │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! #### CelestiaClient Methods (13.18.5)
//!
//! | Method | Signature | Description |
//! |--------|-----------|-------------|
//! | `fetch_control_plane_range` | `(&self, start: u64, end: u64) -> Result<Vec<CelestiaBlob>, CelestiaError>` | Fetch blobs untuk range heights |
//! | `parse_blob_to_update` | `(&self, blob: &CelestiaBlob) -> Result<ControlPlaneUpdate, CelestiaError>` | Parse blob ke update |
//!
//! #### Chain Methods (13.18.5)
//!
//! | Method | Signature | Description |
//! |--------|-----------|-------------|
//! | `rebuild_control_plane` | `(&self, blobs: Vec<CelestiaBlob>) -> Result<(), ChainError>` | Apply blobs ke state |
//!
//! #### New Types (13.18.5)
//!
//! | Type | Description |
//! |------|-------------|
//! | `CelestiaBlob` | Blob struct dengan height, index, data, namespace |
//! | `CelestiaError` | Error enum untuk Celestia operations |
//! | `ControlPlaneUpdate::EpochRotation` | Epoch rotation notification |
//! | `ControlPlaneUpdate::GovernanceProposal` | Governance proposal restore |
//!
//! #### Control-Plane Update Types
//!
//! | Type | Tag | Action |
//! |------|-----|--------|
//! | ValidatorSetUpdate | 1 | Update validator registry |
//! | EpochRotation | 4 | Update epoch counter (no rewards) |
//! | GovernanceProposal | 5 | Restore proposal (NON-BINDING) |
//! | ReceiptBatch | 0 | Skip (handled by ClaimReward) |
//! | ConfigUpdate | 2 | Apply config change |
//! | Checkpoint | 3 | Skip (verification only) |
//!
//! #### Security Notes
//!
//! ```text
//! ⚠️ ZERO-TRUST TERHADAP CELESTIA BLOBS:
//!
//! 1. Blob ordering adalah SUMBER KEBENARAN
//! 2. Reorder atau skip = state divergence
//! 3. Decode gagal = FATAL ERROR (tidak boleh continue)
//! 4. GovernanceProposal TIDAK dieksekusi (NON-BINDING)
//!
//! KAPAN DIPANGGIL:
//! - Setelah snapshot restore
//! - Setelah block replay
//! - Sebelum node siap menerima transaksi baru
//!
//! TIDAK DILAKUKAN:
//! - Execute governance
//! - Trigger new transactions
//! - Modify block production
//! - Compute stake ulang
//! ```
//! ### Catatan Penting
//!
//! ```text
//! ⚠️ SNAPSHOT ADALAH CONSENSUS-CRITICAL UNTUK RECOVERY:
//!
//! 1. state_root di metadata HARUS match dengan computed state_root
//! 2. Snapshot yang corrupted HARUS dihapus, tidak boleh dipakai
//! 3. Fast sync HARUS verify state setelah replay
//! 4. Celestia control-plane HARUS di-rebuild untuk governance state
//!
//! KEGAGALAN MENGAKIBATKAN:
//! - Node tidak bisa sync
//! - State inconsistency
//! - Recovery gagal
//! ```
//! ### 13.18.6 — Automatic Checkpoint Trigger
//!
//! Sub-tahap ini mengimplementasikan automatic checkpoint system yang
//! membuat snapshot otomatis setiap N blocks dan cleanup snapshot lama.
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │              AUTOMATIC CHECKPOINT FLOW                          │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                 │
//! │  TRIGGER POINT (mine_block_and_apply)                           │
//! │  ────────────────────────────────────                           │
//! │  apply_block()                                                  │
//! │    └── state_root valid                                         │
//! │         └── epoch rotation                                      │
//! │              └── maybe_create_checkpoint(height) ← HOOK         │
//! │                   └── broadcast block                           │
//! │                        └── finalize                             │
//! │                                                                 │
//! │  CHECKPOINT LOGIC                                               │
//! │  ─────────────────                                              │
//! │  maybe_create_checkpoint(height):                               │
//! │    1. if interval == 0 → return (disabled)                      │
//! │    2. if height % interval != 0 → return (not checkpoint)       │
//! │    3. create_snapshot(height, path)                             │
//! │    4. write_snapshot_metadata(path, metadata)                   │
//! │    5. cleanup_old_snapshots(max_snapshots)                      │
//! │                                                                 │
//! │  CLEANUP LOGIC                                                  │
//! │  ─────────────                                                  │
//! │  cleanup_old_snapshots(keep_count):                             │
//! │    1. list_available_snapshots()                                │
//! │    2. sort by height ASCENDING                                  │
//! │    3. if count <= keep_count → return                           │
//! │    4. delete (count - keep_count) OLDEST snapshots              │
//! │    5. NEVER delete newest snapshot                              │
//! │                                                                 │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! #### Chain Fields (13.18.6)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `snapshot_config` | `SnapshotConfig` | Konfigurasi interval, path, retention |
//!
//! #### Chain Methods (13.18.6)
//!
//! | Method | Signature | Description |
//! |--------|-----------|-------------|
//! | `maybe_create_checkpoint` | `(&self, height: u64) -> Result<(), ChainError>` | Create checkpoint if interval match |
//! | `cleanup_old_snapshots` | `(&self, keep_count: usize) -> Result<(), ChainError>` | FIFO cleanup oldest snapshots |
//!
//! #### ChainError Variants (13.18.6)
//!
//! | Variant | Description |
//! |---------|-------------|
//! | `SnapshotCreationFailed { height, message }` | Snapshot creation error |
//! | `SnapshotCleanupFailed(String)` | Snapshot cleanup error |
//!
//! #### Behavior Notes
//!
//! ```text
//! CHECKPOINT TRIGGERING:
//! - Snapshot dibuat setiap (height % interval_blocks == 0)
//! - interval_blocks = 0 berarti snapshot DISABLED
//! - Snapshot dibuat SETELAH block final, SEBELUM broadcast
//! - Error checkpoint TIDAK menggagalkan block production
//!
//! CLEANUP POLICY:
//! - Cleanup berjalan SETELAH setiap snapshot baru
//! - Snapshot tertua dihapus dulu (FIFO)
//! - Minimum 1 snapshot selalu dipertahankan
//! - Snapshot terbaru TIDAK PERNAH dihapus
//!
//! TIDAK DIPANGGIL SAAT:
//! - Block replay (replay_blocks_from)
//! - Fast sync (fast_sync_from_snapshot)
//! - Recovery operations
//! ```
//! //! ### 13.18.7 — Fast Sync Integration (RPC & CLI)
//!
//! Sub-tahap ini menyediakan interface RPC dan CLI untuk mengakses
//! snapshot system dan melakukan fast sync.
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │              SNAPSHOT & FAST SYNC INTERFACE                     │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                 │
//! │  RPC ENDPOINTS                                                  │
//! │  ─────────────                                                  │
//! │  get_snapshot_list()           → List semua snapshot            │
//! │  get_snapshot_metadata(height) → Metadata snapshot spesifik     │
//! │  create_snapshot()             → Create snapshot di current tip │
//! │  fast_sync_from_snapshot(h)    → Fast sync dari snapshot        │
//! │                                                                 │
//! │  CLI COMMANDS                                                   │
//! │  ────────────                                                   │
//! │  snapshot list                 → List semua snapshot            │
//! │  snapshot create               → Create snapshot manual         │
//! │  snapshot info --height <h>    → Inspect snapshot metadata      │
//! │  sync fast --from-snapshot <h> → Fast sync dari snapshot        │
//! │                                                                 │
//! │  FAST SYNC FLOW                                                 │
//! │  ───────────────                                                │
//! │  1. Validate snapshot exists                                    │
//! │  2. Validate snapshot integrity (state_root match)              │
//! │  3. Load snapshot state                                         │
//! │  4. Replay blocks from snapshot to tip                          │
//! │  5. Rebuild control-plane dari Celestia (if configured)         │
//! │                                                                 │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! #### RPC Response Types (13.18.7)
//!
//! | Type | Fields | Description |
//! |------|--------|-------------|
//! | `SnapshotListRes` | `snapshots: Vec<SnapshotMetadataRes>` | List snapshot |
//! | `SnapshotMetadataRes` | `height, state_root, timestamp` | Metadata snapshot |
//! | `FastSyncStatusRes` | `started, from_height, message` | Fast sync status |
//!
//! #### Security Notes
//!
//! ```text
//! ZERO-TRUST TERHADAP USER INPUT:
//! - Snapshot height WAJIB divalidasi sebelum digunakan
//! - Snapshot integrity WAJIB di-check (state_root match)
//! - Fast sync TIDAK bypass consensus rules
//! - Invalid snapshot = explicit error (tidak ada fallback)
//! - Tidak ada auto-create atau implicit behavior
//!
//! CLI BEHAVIOR:
//! - Error messages jelas dan informatif
//! - Tidak ada silent failure
//! - Progress ditampilkan step-by-step
//! - Validasi dilakukan sebelum operasi berat
//! ```
//!
//! ### 13.18.8 — Snapshot System E2E Testing
//!
//! Sub-tahap ini menyediakan comprehensive E2E test coverage untuk
//! memvalidasi seluruh snapshot system sebelum production.
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │              SNAPSHOT E2E TEST COVERAGE                         │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                 │
//! │  TEST CASES                                                     │
//! │  ──────────                                                     │
//! │  test_snapshot_create      → Verifikasi pembuatan snapshot      │
//! │  test_snapshot_load        → Verifikasi loading snapshot        │
//! │  test_snapshot_validate    → Verifikasi validasi state_root     │
//! │  test_block_replay         → Verifikasi replay blocks           │
//! │  test_fast_sync_flow       → Verifikasi full fast sync          │
//! │  test_cleanup_old_snapshots → Verifikasi FIFO cleanup           │
//! │                                                                 │
//! │  CLI RUNNER                                                     │
//! │  ──────────                                                     │
//! │  dsdn-chain test --module snapshot                              │
//! │                                                                 │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! #### Testing Checklist
//!
//! | Test | Verifies | Pass Condition |
//! |------|----------|----------------|
//! | `test_snapshot_create` | Folder & metadata creation | Files exist, height correct, state_root non-zero |
//! | `test_snapshot_load` | State restoration | Balances & validators match original |
//! | `test_snapshot_validate` | Integrity check | Valid passes, corrupt fails |
//! | `test_block_replay` | Block re-execution | Final state_root matches original |
//! | `test_fast_sync_flow` | Complete recovery | State identical to normal chain |
//! | `test_cleanup_old_snapshots` | Retention policy | Oldest deleted, newest kept |
//!
//! #### Failure Conditions (MUST FAIL)
//!
//! ```text
//! SNAPSHOT CREATE:
//! - Folder tidak terbuat → FAIL
//! - metadata.json tidak ada → FAIL
//! - Height salah → FAIL
//! - State root kosong → FAIL
//!
//! SNAPSHOT LOAD:
//! - Balance tidak match → FAIL
//! - Validator set tidak match → FAIL
//!
//! SNAPSHOT VALIDATE:
//! - Valid snapshot return false → FAIL
//! - Corrupt snapshot return true → FAIL
//!
//! BLOCK REPLAY:
//! - Final state_root berbeda → FAIL
//!
//! FAST SYNC:
//! - Final state tidak identik → FAIL
//!
//! CLEANUP:
//! - Snapshot terbaru terhapus → FAIL
//! - Count tidak sesuai keep_count → FAIL
//! ```
//!
//! #### Regression Protection
//!
//! ```text
//! Test ini melindungi dari:
//! ✗ Silent snapshot corruption
//! ✗ State root calculation changes
//! ✗ Block replay divergence
//! ✗ Cleanup logic bugs
//! ✗ Metadata format changes
//! ✗ Fast sync state mismatch
//! ```
//!
//! #### Running Tests
//!
//! ```bash
//! # Run snapshot tests only
//! cargo test test_snapshot_e2e_runner -- --nocapture
//!
//! # Run via CLI
//! dsdn-chain test --module snapshot
//!
//! # Run all E2E tests including snapshot
//! dsdn-chain test --module all
//! ```
use crate::types::{Address, Hash};
use crate::gating::ServiceNodeRecord;
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};
use dsdn_common::receipt_dedup::ReceiptDedupTracker;
use dsdn_common::challenge_state::PendingChallenge;
use crate::slashing::{
    LivenessRecord,
    NodeLivenessRecord,
    SlashingEvent,
};
use crate::epoch::{EpochInfo, EpochConfig};
use crate::economic::{DeflationConfig, EconomicMetrics, BurnEvent};


// ════════════════════════════════════════════════════════════════════════════
// INTERNAL MODULES
// ════════════════════════════════════════════════════════════════════════════
//
// Logic dipindahkan dari file monolitik state.rs (~2680 baris) ke module-module
// terpisah untuk maintainability. Semua module bersifat private (tanpa `pub`)
// dan hanya diakses melalui ChainState methods.
//
// ════════════════════════════════════════════════════════════════════════════

/// Data structures: UnstakeEntry, Validator, ValidatorInfo, ValidatorSet, UNSTAKE_DELAY_SECONDS
mod internal_model;

/// Account management: create_account, get_balance, get_locked, get_nonce, increment_nonce, mint
mod internal_account; //RUSTS+ CODE

/// Staking lifecycle: bond, unbond, deposit_validator_stake, register_delegator_stake, dll
mod internal_staking;

/// Quadratic Voting weight caching: update_qv_weight, get_voting_power, compute_validator_weight
mod internal_qv_cache;

/// Fee pool management: validator_fee_pool, storage_fee_pool, compute_fee_pool, allocate_fee_to_pool
mod internal_fees;

/// Reward distribution: distribute_delegator_rewards, calculate_capped_reward (annual 1% cap)
mod internal_rewards;

/// Unstake queue processing: process_unstake_unlocks (7-day delay), cancel_pending_unstake
mod internal_unstake_queue;

/// Slashing adapter: apply_slash_to_validator, apply_slash_to_delegators, apply_full_slash
mod internal_slash_adapter;

/// LMDB state layout: get/set_stake_data, load/export_to_state_layout
mod internal_state_layout;

/// Transaction execution: apply_payload (handles all TxPayload types), is_self_dealing check
mod internal_payload;

/// State root computation: compute_state_root (Merkle hash of all state)
mod internal_state_root;

/// Miscellaneous: get_treasury_balance, get_epoch_info, maybe_rotate_epoch, is_validator_slashed
mod internal_misc;

/// Gas model constants & GasBreakdown type (13.9)
mod internal_gas;

/// Node cost index & per-node earnings accounting (13.9)
mod internal_node_cost;

/// Receipt claim tracking: is_receipt_claimed, mark_receipt_claimed (13.10)
mod internal_receipt;

/// Governance data structures: Proposal, Vote, GovernanceConfig (13.12)
mod internal_governance;

/// Economic metrics tracking: update RF, storage, compute, velocity, inflow (13.15)
mod internal_economic;

/// Storage payment schedule: StorageContract, StorageContractStatus, PaymentSchedule (13.17.3)
mod internal_storage_payment;

/// Snapshot types & configuration: SnapshotConfig, SnapshotMetadata, SnapshotStatus (13.18.1)
mod internal_snapshot;

// ════════════════════════════════════════════════════════════════════════════
// PUBLIC RE-EXPORTS
// ════════════════════════════════════════════════════════════════════════════
//
// Types yang di-export di sini adalah PUBLIC API dari module state.
// Signature dan behavior TIDAK BOLEH berubah tanpa mempertimbangkan
// backward compatibility.
//
// ════════════════════════════════════════════════════════════════════════════


// ============================================================
// RE-EXPORTS (PUBLIC API - TIDAK BOLEH BERUBAH)
// ============================================================
pub use internal_model::{
    // Entry untuk pending unstake dengan 7-day delay (13.8.G)
    // Fields: amount, unlock_ts, validator, is_validator_unstake
    UnstakeEntry,
    
    // Legacy validator struct (untuk backward compatibility)
    // Fields: address, stake, pubkey, active
    Validator, 
    
    // Extended validator info untuk DPoS Hybrid
    // Fields: address, pubkey, stake, active, moniker
    ValidatorInfo, 

    // Registry semua validators dengan helper methods
    // Methods: add_validator, update_stake, get_top_validators, etc
    ValidatorSet,
    
    // Konstanta delay unstake: 7 hari = 604,800 detik
    UNSTAKE_DELAY_SECONDS,
};
// Re-export db types untuk state layout (13.8.H)
// Types ini digunakan untuk serialisasi/deserialisasi ke LMDB
pub use crate::db::{StakeData, DelegatorData, QvWeightData, ValidatorMetadata};
// Checkpoint functions (13.11.4)
pub use internal_state_layout::{create_checkpoint, restore_from_checkpoint};

// ============================================================
// GOVERNANCE RE-EXPORTS (13.12)
// ============================================================
// Types untuk governance layer (Bootstrap Mode).
// Semua hasil voting bersifat NON-BINDING pada tahap ini.
// ============================================================
pub use internal_governance::{
    // Jenis proposal yang diizinkan
    ProposalType,
    // Status lifecycle proposal
    ProposalStatus,
    // Pilihan voting
    VoteOption,
    // Data lengkap proposal
    Proposal,
    // Record voting individual
    Vote,
// Konfigurasi governance
    GovernanceConfig,
    // Error types
    GovernanceError,
    // Bootstrap mode info (13.13.3)
    BootstrapModeInfo,
    // Event logging types (13.13.4)
    GovernanceEventType,
    GovernanceEvent,
    ProposalPreview,
    SimulatedChange,
    PreviewType,
    // Konstanta
    DEFAULT_VOTING_PERIOD,
    DEFAULT_QUORUM_PERCENTAGE,
    DEFAULT_PASS_THRESHOLD,
    MIN_PROPOSAL_DEPOSIT,
    FOUNDATION_ADDRESS,
    MAX_GOVERNANCE_EVENTS,
};
// ════════════════════════════════════════════════════════════════════════════
// GAS MODEL RE-EXPORTS (13.9 + 13.16.4)
// ════════════════════════════════════════════════════════════════════════════
// Constants for gas calculation used by RPC layer.
// These are CONSENSUS-CRITICAL and must not be changed without hard fork.
// ════════════════════════════════════════════════════════════════════════════
pub use internal_gas::{
    // Base gas costs per operation type
    BASE_OP_TRANSFER,
    BASE_OP_STORAGE_OP,
    BASE_OP_COMPUTE_OP,
    // Per-unit costs
    PER_BYTE_COST,
    PER_COMPUTE_CYCLE_COST,
    // Default node cost index
    DEFAULT_NODE_COST_INDEX,
    // Gas breakdown type
    GasBreakdown,
};

// ════════════════════════════════════════════════════════════════════════════
// STORAGE PAYMENT RE-EXPORTS (13.17.3 + 13.17.4)
// ════════════════════════════════════════════════════════════════════════════
// Data structures dan logic untuk storage contract management.
// Digunakan untuk tracking kontrak penyimpanan dan jadwal pembayaran.
// ════════════════════════════════════════════════════════════════════════════
pub use internal_storage_payment::{
    // Storage contract struct
    StorageContract,
    // Contract status enum
    StorageContractStatus,
    // Payment schedule struct
    PaymentSchedule,
    // Error type (13.17.4)
    StoragePaymentError,
    // Constants
    GRACE_PERIOD_SECONDS,
    PAYMENT_INTERVAL_SECONDS,
};

// ════════════════════════════════════════════════════════════════════════════
// SNAPSHOT RE-EXPORTS (13.18.1)
// ════════════════════════════════════════════════════════════════════════════
// Types untuk state snapshot & checkpoint system.
// Digunakan untuk fast sync dan recovery.
// ════════════════════════════════════════════════════════════════════════════
pub use internal_snapshot::{
    // Konfigurasi snapshot: interval, path, max count
    SnapshotConfig,
    // Metadata snapshot: height, state_root, timestamp, block_hash
    SnapshotMetadata,
    // Status snapshot: Creating, Ready, Corrupted
    SnapshotStatus,
    // Default interval: 1000 blocks
    DEFAULT_SNAPSHOT_INTERVAL,
};

// ════════════════════════════════════════════════════════════════════════════
// CHAINSTATE - STRUCT UTAMA
// ════════════════════════════════════════════════════════════════════════════
//
// ChainState adalah single source of truth untuk seluruh state blockchain.
// Struct ini di-serialize ke LMDB dan di-hash untuk compute_state_root().
//
// PENTING: Urutan fields mempengaruhi state_root hash!
// Jangan mengubah urutan tanpa migrasi data.
//
// ════════════════════════════════════════════════════════════════════════════

// # ChainState
//
// Struct utama yang menyimpan seluruh state blockchain DSDN.
// 
// ## Lifecycle
// 
// ```text
// 1. Genesis: ChainState::new() → mint() ke genesis account
// 2. Block Processing: apply_payload() untuk setiap transaksi
// 3. State Root: compute_state_root() untuk block header
// 4. Persistence: serialize ke LMDB via ChainDb
// 5. Recovery: deserialize dari LMDB + recalculate_all_qv_weights()
// ```
// 
// ## Thread Safety
// 
// ChainState TIDAK thread-safe. Gunakan `Arc<RwLock<ChainState>>` untuk
// concurrent access (lihat `lib.rs` Chain struct).
// 
// ## Serialization
// 
// Semua fields di-serialize dengan serde. HashMap ordering tidak deterministik,
// tapi `compute_state_root()` melakukan sorting sebelum hashing.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChainState {
    // ════════════════════════════════════════════════════════════════════
    // CORE ACCOUNT STATE
    // ════════════════════════════════════════════════════════════════════
    // State dasar untuk setiap account (address).
    // Diakses via: get_balance(), get_nonce(), get_locked()
    // ════════════════════════════════════════════════════════════════════
    
    /// Saldo liquid (dapat digunakan) per address
    /// - Berkurang saat: transfer, stake, pay fee
    /// - Bertambah saat: receive transfer, unstake complete, claim reward
    pub balances: HashMap<Address, u128>,
    
    /// Transaction nonce per address (replay protection)
    /// - Increment setiap transaksi dari address ini
    /// - Transaksi dengan nonce != expected akan ditolak
    pub nonces: HashMap<Address, u64>,
    
    /// Saldo terkunci (staked) per address
    /// - Tidak dapat digunakan untuk transfer
    /// - Berkontribusi ke voting power (QV)
    /// - Berkurang SEGERA saat unbond (security - voting power turun instant)
    pub locked: HashMap<Address, u128>,
    
    /// Total supply token yang beredar
    /// - Tidak boleh melebihi MAX_SUPPLY (defined in types.rs)
    /// - Hanya berubah via mint() atau burn (future)
    pub total_supply: u128,

    // ════════════════════════════════════════════════════════════════════
    // VALIDATOR REGISTRY
    // ════════════════════════════════════════════════════════════════════
    // Dua registry validator untuk backward compatibility:
    // 1. validators: HashMap legacy (simple)
    // 2. validator_set: ValidatorSet baru (DPoS Hybrid dengan methods)
    // 
    // KEDUA registry HARUS disinkronkan pada setiap operasi!
    // ════════════════════════════════════════════════════════════════════
    
    /// Legacy validator map (backward compatibility)
    /// Key: validator address, Value: Validator struct
    /// DEPRECATED: Gunakan validator_set untuk logic baru
    pub validators: HashMap<Address, Validator>,
    
    /// DPoS Hybrid validator registry (13.7.D)
    /// - Menyimpan ValidatorInfo dengan methods helper
    /// - get_top_validators() untuk proposer selection
    /// - active_count(), total_stake() untuk statistics
    pub validator_set: ValidatorSet,
    
    /// Validator liveness tracking (13.7.K)
    /// - Tracks missed blocks per validator
    /// - slashed flag untuk status slashing
    /// - Digunakan oleh crate::slashing untuk determine slash
    pub liveness_records: HashMap<Address, LivenessRecord>,

    // ════════════════════════════════════════════════════════════════════
    // EXPLICIT STAKE SEPARATION (13.8.A)
    // ════════════════════════════════════════════════════════════════════
    // Pemisahan eksplisit antara:
    // 1. validator_stakes: Stake milik validator sendiri
    // 2. delegator_stakes: Stake dari delegator
    // 
    // Ini BERBEDA dari validators.stake yang merupakan total keduanya.
    // Pemisahan ini penting untuk:
    // - QV calculation (80% self, 20% delegators)
    // - Slashing (slash self dan delegators terpisah)
    // - Reward distribution (validator commission vs delegator share)
    // ════════════════════════════════════════════════════════════════════
    
    /// Stake milik validator sendiri (bukan dari delegator)
    /// - Diset via deposit_validator_stake() saat ValidatorRegistration
    /// - Minimum: VALIDATOR_MIN_STAKE (50,000 NUSA)
    /// - Berkontribusi 80% ke validator voting weight
    pub validator_stakes: HashMap<Address, u128>,
    
    /// Total stake per delegator (untuk tracking individual)
    /// - Diset via register_delegator_stake()
    /// - Minimum per delegasi: DELEGATOR_MIN_STAKE (100,000 NUSA)
    pub delegator_stakes: HashMap<Address, u128>,
    
    /// Mapping delegator → validator yang didelegasikan
    /// - Setiap delegator hanya bisa delegate ke SATU validator
    /// - Untuk delegate ke validator lain, harus undelegate dulu
    pub delegator_to_validator: HashMap<Address, Address>,

    // ════════════════════════════════════════════════════════════════════
    // DELEGATION TRACKING (13.8.B)
    // ════════════════════════════════════════════════════════════════════
    // Struktur nested untuk track siapa delegate berapa ke siapa.
    // Format: validator_address → (delegator_address → amount)
    // 
    // Digunakan untuk:
    // - QV calculation (sum of delegator stakes)
    // - Reward distribution (proportional to stake)
    // - Slashing (proportional reduction)
    // ════════════════════════════════════════════════════════════════════
    
    /// Delegations: validator → (delegator → amount)
    /// - Tracks semua delegasi ke setiap validator
    /// - Termasuk self-delegation (validator ke dirinya sendiri)
    /// - Digunakan untuk calculate total stake dan QV
    pub delegations: HashMap<Address, HashMap<Address, u128>>,

    // ════════════════════════════════════════════════════════════════════
    // QUADRATIC VOTING WEIGHTS (13.8.C)
    // ════════════════════════════════════════════════════════════════════
    // QV weights di-cache untuk performa.
    // Formula: qv_weight = sqrt(stake)
    // 
    // Validator combined weight: 80% * sqrt(self_stake) + 20% * Σsqrt(delegator_i)
    // 
    // Cache di-update pada setiap:
    // - deposit_validator_stake / withdraw_validator_stake
    // - register_delegator_stake / withdraw_delegator_stake
    // - bond / unbond
    // - slashing
    // ════════════════════════════════════════════════════════════════════
    
    /// Individual QV weight per address
    /// - qv_weights[addr] = sqrt(locked[addr])
    /// - Untuk governance voting power individual
    pub qv_weights: HashMap<Address, u128>,
    
    /// Combined QV weight per validator (13.8.D)
    /// - Includes self stake (80%) + delegator influence (20%)
    /// - Digunakan untuk proposer selection weight
    /// - Digunakan untuk consensus voting weight
    pub validator_qv_weights: HashMap<Address, u128>,

    // ════════════════════════════════════════════════════════════════════
    // FEE POOLS (13.8.E + 13.9 Blueprint)
    // ════════════════════════════════════════════════════════════════════
    // Fee didistribusikan berdasarkan ResourceClass (Blueprint 70/20/10):
    // 
    // | ResourceClass | Node    | Validator | Treasury |
    // |---------------|---------|-----------|----------|
    // | Storage       | 70%     | 20%       | 10%      |
    // | Compute       | 70%     | 20%       | 10%      |
    // | Transfer      | 0%      | 100%      | 0%       |
    // | Governance    | 0%      | 100%      | 0%       |
    // | Stake         | 0%      | 100%      | 0%       |
    // 
    // Pool digunakan jika tidak ada specific node target.
    //
    
    /// Validator fee pool
    /// - Accumulated dari Transfer fees (100%)
    /// - Accumulated dari Governance fees (100%)
    /// - Accumulated dari Storage/Compute fees (20%)
    /// - Dapat di-claim via claim_validator_fee()
    pub validator_fee_pool: u128,
    
    /// Storage fee pool
    /// - Accumulated dari Storage tx fees jika tidak ada target node
    /// - Distribusi ke storage nodes via claim_storage_fee()
    pub storage_fee_pool: u128,
    
    /// Compute fee pool
    /// - Accumulated dari Compute tx fees jika tidak ada target node
    /// - Distribusi ke compute nodes via claim_compute_fee()
    pub compute_fee_pool: u128,
    
    /// Treasury balance (13.7.G + 13.9)
    /// - Accumulated dari Storage/Compute fees (10%)
    /// - Accumulated dari anti self-dealing node redirected fees (70%)
    /// - Accumulated dari anti self-dealing proposer redirected fees
    /// - Accumulated dari slashed amounts
    /// - Digunakan untuk protocol development, grants, etc
    pub treasury_balance: u128,

    // ════════════════════════════════════════════════════════════════════
    // REWARD SYSTEM (13.7.H, 13.8.F)
    // ════════════════════════════════════════════════════════════════════
    // Reward distribution flow:
    // 1. Fee masuk ke pool berdasarkan ResourceClass
    // 2. Delegator pool di-distribute ke delegators (proportional to stake)
    // 3. Validator mengambil 20% commission, delegators dapat 80%
    // 4. Annual cap: delegator max 1% dari stake per tahun
    // ════════════════════════════════════════════════════════════════════
    
    /// Global reward pool (legacy, untuk backward compatibility)
    pub reward_pool: u128,
    
    /// Delegator reward pool (13.7.H)
    /// - Accumulated dari 20% fee split
    /// - Distributed proportionally ke delegators
    pub delegator_pool: u128,
    
    /// Pending rewards per validator yang belum didistribusikan
    /// - Accumulated sampai distribute_delegator_rewards() dipanggil
    pub pending_delegator_rewards: HashMap<Address, u128>,
    
    /// Accrued rewards per delegator untuk tahun berjalan (13.8.F)
    /// - Untuk enforce annual 1% cap
    /// - Reset setiap EPOCHS_PER_YEAR
    pub delegator_reward_accrued: HashMap<Address, u128>,
    
    /// Last epoch saat delegator menerima reward
    /// - Untuk tracking reward timing
    pub delegator_last_epoch: HashMap<Address, u64>,
    
    /// Epoch awal tahun untuk annual cap reset
    /// - Ketika current_epoch >= year_start_epoch + EPOCHS_PER_YEAR,
    ///   semua delegator_reward_accrued di-reset
    pub year_start_epoch: u64,

    // ════════════════════════════════════════════════════════════════════
    // EPOCH MANAGEMENT (13.7.L)
    // ════════════════════════════════════════════════════════════════════
    // Epoch adalah periode waktu untuk:
    // - Validator set rotation
    // - Reward distribution
    // - Annual cap tracking
    // 
    // Rotasi terjadi setiap epoch_config.blocks_per_epoch blocks.
    // ════════════════════════════════════════════════════════════════════
    
    /// Current epoch information
    /// - epoch_number: sequential epoch ID
    /// - start_height: block height saat epoch dimulai
    /// - active_validators: jumlah validator aktif di epoch ini
    /// - total_stake: total stake di epoch ini
    pub epoch_info: EpochInfo,
    
    /// Epoch configuration
    /// - blocks_per_epoch: berapa block per epoch
    /// - Configurable untuk testnet vs mainnet
    pub epoch_config: EpochConfig,

    // ════════════════════════════════════════════════════════════════════
    // PENDING UNSTAKE QUEUE (13.8.G)
    // ════════════════════════════════════════════════════════════════════
    // Unstake memiliki 7-day delay untuk security:
    // 1. Voting power berkurang SEGERA (unbond_with_delay)
    // 2. Token dikunci di pending_unstakes
    // 3. Setelah 7 hari, token dapat di-release ke balance
    // 
    // Delay ini mencegah:
    // - Exit sebelum slashing dapat dieksekusi
    // - Manipulasi voting power jangka pendek
    // ════════════════════════════════════════════════════════════════════
    
    /// Pending unstake entries per address
    /// - Vec karena satu address bisa punya multiple pending unstakes
    /// - Diproses via process_unstake_unlocks() setiap block
    /// - Dapat dibatalkan via cancel_pending_unstake() sebelum unlock
    pub pending_unstakes: HashMap<Address, Vec<UnstakeEntry>>,

    // ════════════════════════════════════════════════════════════════════════════
    // NODE COST INDEX & EARNINGS (13.9)
    // ════════════════════════════════════════════════════════════════════════════
    // Per-node cost multiplier dan earnings tracking.
    // Digunakan untuk gas fee calculation dan node compensation.
    //
    // CONSENSUS-CRITICAL: Kedua field ini termasuk dalam state_root.
    // ════════════════════════════════════════════════════════════════════════════
    
    /// Node cost index multiplier per node address
    /// - Basis 100 = 1.0x multiplier
    /// - Digunakan untuk adjust gas fee berdasarkan node
    pub node_cost_index: HashMap<Address, u128>,
    
    /// Accumulated earnings per node address
    /// - Tracking per-node earnings dari fee payments
    /// - Dapat di-claim via claim_node_earning()
    pub node_earnings: HashMap<Address, u128>,

    // ════════════════════════════════════════════════════════════════════════════
    // CLAIMED RECEIPTS (13.10) — LMDB PERSISTENCE
    // ════════════════════════════════════════════════════════════════════════════
    // Tracking receipt yang sudah di-claim untuk mencegah double-claim.
    //
    // PERSISTENCE:
    // - Dipersist di LMDB bucket: claimed_receipts/{receipt_id}
    // - Key: receipt_id (Hash 64 bytes)
    // - Value: single byte marker (0x01)
    //
    // LIFECYCLE:
    // - Restore wajib saat startup via load_from_state_layout()
    // - Export via export_to_state_layout()
    // - Persist individual receipt via ChainDb::put_claimed_receipt()
    //
    // CONSENSUS-CRITICAL: Field ini termasuk dalam state_root.
    // ════════════════════════════════════════════════════════════════════════════
    
    /// Set of receipt IDs yang sudah di-claim
    /// - Digunakan untuk mencegah receipt replay attack
    /// - Receipt ID adalah Hash 64 bytes
    /// - Termasuk dalam lifecycle state snapshot
    pub claimed_receipts: HashSet<Hash>,

    // ════════════════════════════════════════════════════════════════════════════
    // GOVERNANCE (13.12) — BOOTSTRAP MODE
    // ════════════════════════════════════════════════════════════════════════════
    // Governance layer untuk proposal dan voting.
    // Pada Bootstrap Mode, semua hasil voting bersifat NON-BINDING.
    //
    // CONSENSUS-CRITICAL: Semua field termasuk dalam state_root.
    // ════════════════════════════════════════════════════════════════════════════

    /// Semua proposals yang pernah dibuat
    /// Key: proposal_id (auto-increment)
    /// Value: Proposal struct
    pub proposals: HashMap<u64, Proposal>,

    /// Counter untuk generate proposal_id
    /// - Increment setiap create_proposal()
    /// - Consensus-critical untuk deterministic ID generation
    pub proposal_count: u64,

    /// Votes per proposal per voter
    /// - Key level 1: proposal_id
    /// - Key level 2: voter address
    /// - Value: Vote struct dengan weight snapshot
    /// - Consensus-critical untuk voting tally
    pub proposal_votes: HashMap<u64, HashMap<Address, Vote>>,

/// Konfigurasi governance system
    /// - voting_period_seconds, quorum_percentage, pass_threshold
    /// - foundation_address dengan veto power
    /// - bootstrap_mode flag (TRUE = non-binding)
    pub governance_config: GovernanceConfig,
        /// Governance event log (13.13.4)
    /// Runtime-only audit trail
    #[serde(skip)]
    pub governance_events: Vec<GovernanceEvent>,

    // ════════════════════════════════════════════════════════════════════════════
    // NODE LIVENESS TRACKING (13.14.2)
    // ════════════════════════════════════════════════════════════════════════════
    // Tracking liveness untuk storage/compute nodes.
    // Digunakan untuk deteksi offline, data corruption, dan malicious behavior.
    //
    // node_liveness_records: Dipersist ke LMDB (future: 13.14.7)
    // slashing_events: Runtime-only audit trail (NOT persisted)
    // ════════════════════════════════════════════════════════════════════════════

    /// Node liveness records per node address
    /// - Tracks heartbeat, failures, corruption, malicious behavior
    /// - Digunakan untuk automatic slashing detection
    pub node_liveness_records: HashMap<Address, NodeLivenessRecord>,

/// Slashing event audit trail (13.14.2)
    /// Runtime-only, NOT persisted to LMDB, NOT in state_root
    #[serde(skip)]
    pub slashing_events: Vec<SlashingEvent>,

    // ════════════════════════════════════════════════════════════════════════════
    // ECONOMIC CONTROLLER (13.15)
    // ════════════════════════════════════════════════════════════════════════════
    // Adaptive deflation & treasury burn controller.
    // Target deflasi 3-6% per tahun, adaptif berdasarkan RF dan network metrics.
    //
    // deflation_config: CONSENSUS-CRITICAL (in state_root)
    // economic_metrics: CONSENSUS-CRITICAL (in state_root)
    // last_burn_epoch: CONSENSUS-CRITICAL (in state_root)
    // cumulative_burned: CONSENSUS-CRITICAL (in state_root)
    // economic_events: RUNTIME-ONLY (NOT in state_root)
    // ════════════════════════════════════════════════════════════════════════════

    /// Konfigurasi deflasi untuk economic controller (13.15)
    /// - Target min/max percent, burn interval, treasury reserve
    /// - Mode: Bootstrap / Active / Governance
    /// - CONSENSUS-CRITICAL: termasuk dalam state_root
    pub deflation_config: DeflationConfig,

    /// Metrics ekonomi terkini (13.15)
    /// - RF, storage usage, compute cycles, velocity
    /// - Treasury/slashing inflow per epoch
    /// - CONSENSUS-CRITICAL: termasuk dalam state_root
    pub economic_metrics: EconomicMetrics,

    /// Epoch terakhir burn dilakukan (13.15)
    /// - Digunakan untuk enforce burn interval
    /// - CONSENSUS-CRITICAL: termasuk dalam state_root
    pub last_burn_epoch: u64,

    /// Total token yang sudah di-burn sepanjang waktu (13.15)
    /// - Akumulasi dari semua burn events
    /// - CONSENSUS-CRITICAL: termasuk dalam state_root
    pub cumulative_burned: u128,

    /// Economic event audit trail (13.15)
    /// - Burn events untuk observability
    /// - RUNTIME-ONLY: NOT persisted, NOT in state_root
    #[serde(skip)]
    pub economic_events: Vec<BurnEvent>,

    // ════════════════════════════════════════════════════════════════════════════
    // STORAGE PAYMENT (13.17.3)
    // ════════════════════════════════════════════════════════════════════════════
    // Storage contract management untuk pembayaran periodik.
    //
    // storage_contracts: CONSENSUS-CRITICAL (in state_root)
    // user_contracts: CONSENSUS-CRITICAL (in state_root) - index untuk query
    // ════════════════════════════════════════════════════════════════════════════

    /// Storage contracts registry (13.17.3)
    /// - Key: contract_id (Hash 64 bytes)
    /// - Value: StorageContract struct
    /// - Sumber kebenaran utama untuk semua kontrak storage
    /// - CONSENSUS-CRITICAL: termasuk dalam state_root
    pub storage_contracts: HashMap<Hash, StorageContract>,

    /// User contracts index (13.17.3)
    /// - Key: owner address
    /// - Value: Vec of contract_ids yang dimiliki user
    /// - Index untuk query cepat kontrak per user
    /// - CONSENSUS-CRITICAL: termasuk dalam state_root
    pub user_contracts: HashMap<Address, Vec<Hash>>,

    // ════════════════════════════════════════════════════════════════════════════
    // SERVICE NODE REGISTRY (14B.11)
    // ════════════════════════════════════════════════════════════════════════════
    // On-chain registry untuk service nodes (Storage / Compute).
    // ServiceNodeRecord adalah SOURCE OF TRUTH untuk setiap service node.
    //
    // INVARIANTS (CONSENSUS-CRITICAL):
    // 1. Setiap entry di service_nodes HARUS punya entry di service_node_index.
    // 2. service_node_index[node_id] == operator_address.
    // 3. Tidak boleh ada dua operator_address dengan node_id sama.
    // 4. Tidak boleh ada dangling index (index tanpa record, atau record tanpa index).
    //
    // PERSISTENCE:
    // - Dipersist ke LMDB bersama seluruh ChainState.
    // - Termasuk dalam state_root computation.
    // ════════════════════════════════════════════════════════════════════════════

    /// Service node records keyed by operator address (14B.11)
    /// - Primary store: operator_address → ServiceNodeRecord
    /// - Source of truth untuk setiap service node on-chain
    /// - CONSENSUS-CRITICAL: termasuk dalam state_root
    pub service_nodes: HashMap<Address, ServiceNodeRecord>,

    /// Reverse index: node_id → operator_address (14B.11)
    /// - Enables O(1) lookup by node_id
    /// - MUST be kept in sync with service_nodes at all times
    /// - CONSENSUS-CRITICAL: termasuk dalam state_root
    pub service_node_index: HashMap<[u8; 32], Address>,

    // ════════════════════════════════════════════════════════════════════════════
    // RECEIPT CLAIM STATE (14C.A)
    // ════════════════════════════════════════════════════════════════════════════
    // Tracking receipt claims, challenge periods, dan economic counters.
    //
    // receipt_dedup_tracker: Anti double-claim (CONSENSUS-CRITICAL, in state_root)
    // pending_challenges: Challenge period tracking (CONSENSUS-CRITICAL, in state_root)
    // Counters: Economic statistics v1 (CONSENSUS-CRITICAL, in state_root)
    //
    // Thread safety: HashMap/ReceiptDedupTracker are NOT thread-safe.
    // Concurrency is controlled at the executor layer (single-threaded chain execution).
    // ════════════════════════════════════════════════════════════════════════════

    /// Dedup tracker for receipt claims (prevents double-claim).
    ///
    /// - Updated by: `internal_receipt` module during ClaimReward execution.
    /// - Invariant: every claimed receipt hash appears exactly once.
    /// - If corrupt: double-claim attacks become possible, economic loss.
    /// - CONSENSUS-CRITICAL: termasuk dalam state_root.
    #[serde(default)]
    pub receipt_dedup_tracker: ReceiptDedupTracker,

    /// Pending challenges for compute receipts.
    ///
    /// Key: `receipt_hash` (`[u8; 32]`).
    ///
    /// - Updated by: `internal_receipt` during ClaimReward (compute)
    ///   and during challenge resolution (fraud proof submit / clear / slash).
    /// - Invariant: entry exists only while challenge period is active
    ///   (`Pending`) or being disputed (`Challenged`). Cleared/Slashed
    ///   entries are removed after resolution.
    /// - If corrupt: rewards may be distributed before challenge period
    ///   ends, or fraud proofs may be lost.
    /// - Thread safety: `HashMap` is NOT thread-safe; concurrency
    ///   controlled at executor layer.
    /// - CONSENSUS-CRITICAL: termasuk dalam state_root.
    #[serde(default)]
    pub pending_challenges: HashMap<[u8; 32], PendingChallenge>,

    /// Counter: total receipts claimed across all time.
    ///
    /// - Updated by: `internal_receipt` on successful ClaimReward.
    /// - Invariant: monotonically increasing, never decremented.
    /// - If corrupt: economic statistics inaccurate (non-critical for consensus
    ///   correctness, but included in state_root for auditability).
    /// - CONSENSUS-CRITICAL: termasuk dalam state_root.
    #[serde(default)]
    pub total_receipts_claimed: u64,

    /// Counter: total rewards distributed (in base units) across all time.
    ///
    /// - Updated by: `internal_receipt` on reward distribution.
    /// - Invariant: monotonically increasing, never decremented.
    /// - If corrupt: economic statistics inaccurate.
    /// - CONSENSUS-CRITICAL: termasuk dalam state_root.
    #[serde(default)]
    pub total_rewards_distributed: u128,

    /// Counter: total challenges submitted across all time.
    ///
    /// - Updated by: `internal_receipt` on fraud proof submission.
    /// - Invariant: monotonically increasing, never decremented.
    /// - If corrupt: economic statistics inaccurate.
    /// - CONSENSUS-CRITICAL: termasuk dalam state_root.
    #[serde(default)]
    pub total_challenges_submitted: u64,

    /// Counter: total amount slashed from fraud proofs across all time.
    ///
    /// - Updated by: `internal_receipt` on successful fraud proof resolution.
    /// - Invariant: monotonically increasing, never decremented.
    /// - If corrupt: economic statistics inaccurate.
    /// - CONSENSUS-CRITICAL: termasuk dalam state_root.
    #[serde(default)]
    pub total_fraud_slashed: u128,
}

// ════════════════════════════════════════════════════════════════════════════
// CONSTRUCTOR
// ════════════════════════════════════════════════════════════════════════════

impl ChainState {
    /// Membuat ChainState baru dengan semua fields kosong/default.
    /// 
    /// ## Usage
    /// 
    /// ```ignore
    /// let mut state = ChainState::new();
    /// state.mint(&genesis_address, GENESIS_AMOUNT)?;
    /// ```
    /// 
    /// ## Note
    /// 
    /// Setelah new(), state masih kosong. Untuk genesis:
    /// 1. Call create_account() untuk genesis address
    /// 2. Call mint() untuk initial supply
    /// 3. Persist ke DB via ChainDb::persist_state()
    pub fn new() -> Self {
        Self {
            // Core account state
            balances: HashMap::new(),
            nonces: HashMap::new(),
            locked: HashMap::new(),
            total_supply: 0,
            
            // Validator registry
            validators: HashMap::new(),
            validator_set: ValidatorSet::new(),
            liveness_records: HashMap::new(),
            
            // Explicit stake separation (13.8.A)
            validator_stakes: HashMap::new(),
            delegator_stakes: HashMap::new(),
            delegator_to_validator: HashMap::new(),
            
            // Delegation tracking (13.8.B)
            delegations: HashMap::new(),
            
            // QV weights (13.8.C)
            qv_weights: HashMap::new(),
            validator_qv_weights: HashMap::new(),
            
            // Fee pools (13.8.E)
            validator_fee_pool: 0,
            storage_fee_pool: 0,
            compute_fee_pool: 0,
            treasury_balance: 0,
            
            // Reward system (13.7.H, 13.8.F)
            reward_pool: 0,
            delegator_pool: 0,
            pending_delegator_rewards: HashMap::new(),
            delegator_reward_accrued: HashMap::new(),
            delegator_last_epoch: HashMap::new(),
            year_start_epoch: 0,
            
            // Epoch management (13.7.L)
            epoch_info: EpochInfo::new(),
            epoch_config: EpochConfig::default(),
            
            // Pending unstake (13.8.G)
            pending_unstakes: HashMap::new(),
            
            // Node cost index & earnings (13.9)
            node_cost_index: HashMap::new(),
            node_earnings: HashMap::new(),
            
            // Claimed receipts (13.10)
            claimed_receipts: HashSet::new(),

            // GOVERNANCE (13.12) — BOOTSTRAP MODE
            proposals: HashMap::new(),
            proposal_count: 0,
            proposal_votes: HashMap::new(),
            governance_config: GovernanceConfig::default(),

            // GOVERNANCE EVENT LOGGING (13.13.4) — IN-MEMORY ONLY
            governance_events: Vec::new(),

            // NODE LIVENESS TRACKING (13.14.2)
            node_liveness_records: HashMap::new(),
            slashing_events: Vec::new(),

            // ECONOMIC CONTROLLER (13.15)
            deflation_config: DeflationConfig::new_bootstrap(),
            economic_metrics: EconomicMetrics::new(),
            last_burn_epoch: 0,
            cumulative_burned: 0,
            economic_events: Vec::new(),

            // STORAGE PAYMENT (13.17.3)
            storage_contracts: HashMap::new(),
            user_contracts: HashMap::new(),

            // SERVICE NODE REGISTRY (14B.11)
            service_nodes: HashMap::new(),
            service_node_index: HashMap::new(),

            // RECEIPT CLAIM STATE (14C.A)
            receipt_dedup_tracker: ReceiptDedupTracker::new(),
            pending_challenges: HashMap::new(),
            total_receipts_claimed: 0,
            total_rewards_distributed: 0,
            total_challenges_submitted: 0,
            total_fraud_slashed: 0,

        }
    }
    
    // ════════════════════════════════════════════════════════════════════
    // RECEIPT STATE HELPERS (14C.A)
    // ════════════════════════════════════════════════════════════════════

    /// Checks whether a receipt hash has an active pending challenge.
    ///
    /// ## Complexity
    ///
    /// O(1) — single `HashMap::contains_key` lookup.
    ///
    /// ## Determinism
    ///
    /// Deterministic. No side effects, no mutation, no allocation.
    #[must_use]
    #[inline]
    pub fn has_pending_challenge(&self, receipt_hash: &[u8; 32]) -> bool {
        self.pending_challenges.contains_key(receipt_hash)
    }

    /// Returns all receipt hashes whose challenge period has expired.
    ///
    /// Iterates `pending_challenges` and collects entries where
    /// `PendingChallenge::is_expired(now)` returns `true`.
    ///
    /// ## Complexity
    ///
    /// O(n) iteration + O(n log n) sort, where n = `pending_challenges.len()`.
    ///
    /// ## Determinism
    ///
    /// **Deterministic.** Results are sorted lexicographically by
    /// `receipt_hash` bytes to guarantee identical output regardless
    /// of `HashMap` iteration order. All validators produce the same
    /// result for the same state and `now` value.
    #[must_use]
    pub fn get_expired_challenges(&self, now: u64) -> Vec<[u8; 32]> {
        let mut expired: Vec<[u8; 32]> = self
            .pending_challenges
            .iter()
            .filter(|(_, challenge)| challenge.is_expired(now))
            .map(|(hash, _)| *hash)
            .collect();
        expired.sort();
        expired
    }

    // ════════════════════════════════════════════════════════════════════
    // DELEGATED METHODS
    // ════════════════════════════════════════════════════════════════════
    // Methods di bawah ini mendelegasikan ke internal modules.
    // Ini memungkinkan backward compatibility dengan code yang sudah ada
    // yang memanggil state.create_account(), state.get_balance(), dll.
    // ════════════════════════════════════════════════════════════════════

    /// Membuat account baru (inisialisasi balance, nonce, locked = 0)
    /// 
    /// Idempotent: aman dipanggil berkali-kali untuk address yang sama.
    #[inline]
    pub fn create_account(&mut self, addr: Address) {
        internal_account::create_account(self, addr)
    }

    /// Mendapatkan saldo liquid (dapat digunakan) untuk address
    /// 
    /// Returns 0 jika address tidak ditemukan.
    #[inline]
    pub fn get_balance(&self, addr: &Address) -> u128 {
        internal_account::get_balance(self, addr)
    }

    /// Mendapatkan saldo terkunci (staked) untuk address
    /// 
    /// Locked balance tidak dapat digunakan untuk transfer,
    /// tapi berkontribusi ke voting power.
    #[inline]
    pub fn get_locked(&self, addr: &Address) -> u128 {
        internal_account::get_locked(self, addr)
    }

    /// Mendapatkan nonce (transaction counter) untuk address
    /// 
    /// Nonce digunakan untuk replay protection.
    /// Setiap transaksi harus memiliki nonce == current_nonce.
    #[inline]
    pub fn get_nonce(&self, addr: &Address) -> u64 {
        internal_account::get_nonce(self, addr)
    }

    /// Increment nonce setelah transaksi berhasil dieksekusi
    #[inline]
    pub fn increment_nonce(&mut self, addr: &Address) {
        internal_account::increment_nonce(self, addr)
    }

    /// Mint token baru ke address (hanya untuk genesis/reward)
    /// 
    /// ## Errors
    /// 
    /// - Jika total_supply + amount > MAX_SUPPLY
    /// - Jika terjadi overflow
    #[inline]
    pub fn mint(&mut self, addr: &Address, amount: u128) -> anyhow::Result<()> {
        internal_account::mint(self, addr, amount)
    }

    // ════════════════════════════════════════════════════════════════════════════
    // STORAGE PAYMENT METHODS (13.17.4)
    // ════════════════════════════════════════════════════════════════════════════
    // Public wrappers untuk storage contract management.
    // Logic implementasi ada di internal_storage_payment.rs.
    //
    // FEE DISTRIBUTION:
    // - 70% → node_earnings[node_address]
    // - 20% → validator_fee_pool
    // - 10% → treasury_balance
    // ════════════════════════════════════════════════════════════════════════════

    /// Create a new storage contract with first month payment.
    /// 
    /// # Arguments
    /// * `owner` - Address paying for storage
    /// * `node` - Storage node providing service
    /// * `bytes` - Number of bytes to store
    /// * `monthly_cost` - Cost per month in NUSA
    /// * `duration_months` - Contract duration in months
    /// * `current_timestamp` - Current block timestamp
    /// 
    /// # Returns
    /// * `Ok(Hash)` - Contract ID on success
    /// * `Err(StoragePaymentError)` - On failure
    /// 
    /// # Fee Distribution
    /// First month payment is immediately distributed:
    /// - 70% → node_earnings
    /// - 20% → validator_fee_pool
    /// - 10% → treasury_balance
    #[inline]
    pub fn create_storage_contract(
        &mut self,
        owner: Address,
        node: Address,
        bytes: u64,
        monthly_cost: u128,
        duration_months: u64,
        current_timestamp: u64,
    ) -> Result<Hash, internal_storage_payment::StoragePaymentError> {
        internal_storage_payment::create_storage_contract(
            self, owner, node, bytes, monthly_cost, duration_months, current_timestamp
        )
    }

    /// Process monthly payment for a storage contract.
    /// 
    /// # Arguments
    /// * `contract_id` - Contract to process payment for
    /// * `current_timestamp` - Current block timestamp
    /// 
    /// # Returns
    /// * `Ok(())` - Payment processed successfully
    /// * `Err(StoragePaymentError)` - On failure
    /// 
    /// # Behavior
    /// - If balance insufficient → sets status to GracePeriod
    /// - If balance sufficient → deducts and distributes 70/20/10
    #[inline]
    pub fn process_monthly_payment(
        &mut self,
        contract_id: Hash,
        current_timestamp: u64,
    ) -> Result<(), internal_storage_payment::StoragePaymentError> {
        internal_storage_payment::process_monthly_payment(self, contract_id, current_timestamp)
    }

    /// Check and update contract status based on current timestamp.
    /// 
    /// # Arguments
    /// * `contract_id` - Contract to check
    /// * `current_timestamp` - Current block timestamp
    /// 
    /// # Returns
    /// * `Ok(StorageContractStatus)` - Current status after update
    /// * `Err(StoragePaymentError)` - If contract not found
    /// 
    /// # Behavior
    /// - If in GracePeriod and expired → sets to Expired
    /// - If past end_timestamp → sets to Expired
    #[inline]
    pub fn check_contract_status(
        &mut self,
        contract_id: Hash,
        current_timestamp: u64,
    ) -> Result<StorageContractStatus, internal_storage_payment::StoragePaymentError> {
        internal_storage_payment::check_contract_status(self, contract_id, current_timestamp)
    }

    /// Cancel a storage contract (owner only).
    /// 
    /// # Arguments
    /// * `contract_id` - Contract to cancel
    /// * `caller` - Address attempting to cancel (must be owner)
    /// 
    /// # Returns
    /// * `Ok(())` - Contract cancelled
    /// * `Err(StoragePaymentError)` - On failure
    /// 
    /// # Note
    /// NO REFUND is provided. Payments are non-refundable.
    #[inline]
    pub fn cancel_storage_contract(
        &mut self,
        contract_id: Hash,
        caller: Address,
    ) -> Result<(), internal_storage_payment::StoragePaymentError> {
        internal_storage_payment::cancel_contract(self, contract_id, caller)
    }

    /// Process all pending storage payments (batch processor).
    /// 
    /// # Arguments
    /// * `current_timestamp` - Current block timestamp
    /// 
    /// # Note
    /// This function does NOT return errors. It processes all contracts
    /// and updates their status accordingly.
    /// 
    /// # Usage
    /// Call this at the beginning of each block to process due payments.
    #[inline]
    pub fn process_storage_payments(&mut self, current_timestamp: u64) {
        internal_storage_payment::process_storage_payments(self, current_timestamp)
    }

    // ════════════════════════════════════════════════════════════════════════════
    // GAS ESTIMATION HELPER METHODS (13.16.4)
    // ════════════════════════════════════════════════════════════════════════════
    // Helper methods for RPC gas estimation.
    // READ-ONLY, DETERMINISTIC, NO STATE MUTATION.
    // Uses constants from internal_gas.rs.
    // NOTE: Node cost index methods are in internal_node_cost.rs
    // ════════════════════════════════════════════════════════════════════════════

    /// Estimate gas for storage operation
    /// 
    /// # Arguments
    /// * `bytes` - Number of bytes to store
    /// * `node_address` - Optional node address for cost index lookup
    /// 
    /// # Returns
    /// * (total_gas, node_multiplier) tuple
    /// 
    /// # Formula
    /// ```text
    /// base_cost = BASE_OP_STORAGE_OP (50,000)
    /// byte_cost = bytes * PER_BYTE_COST (16)
    /// total_gas = ceil((base_cost + byte_cost) * node_multiplier / 100)
    /// ```
    /// 
    /// # Notes
    /// - READ-ONLY: Does not modify state
    /// - Deterministic: Same input always produces same output
    pub fn estimate_storage_gas(&self, bytes: u64, node_address: Option<&Address>) -> (u128, u32) {
        let node_multiplier = match node_address {
            Some(addr) => self.get_node_cost_index(addr),
            None => internal_gas::DEFAULT_NODE_COST_INDEX,
        };

        let base_cost: u128 = internal_gas::BASE_OP_STORAGE_OP as u128;
        let byte_cost: u128 = (bytes as u128) * (internal_gas::PER_BYTE_COST as u128);
        let sum = base_cost + byte_cost;
        
        // Ceiling division: ceil(sum * multiplier / 100)
        let product = sum * node_multiplier;
        let total_gas = (product + 99) / 100;

        (total_gas, node_multiplier as u32)
    }

    /// Estimate gas for compute operation
    /// 
    /// # Arguments
    /// * `cycles` - Number of compute cycles
    /// * `node_address` - Optional node address for cost index lookup
    /// 
    /// # Returns
    /// * (total_gas, node_multiplier) tuple
    /// 
    /// # Formula
    /// ```text
    /// base_cost = BASE_OP_COMPUTE_OP (100,000)
    /// cycle_cost = cycles * PER_COMPUTE_CYCLE_COST (1)
    /// total_gas = ceil((base_cost + cycle_cost) * node_multiplier / 100)
    /// ```
    /// 
    /// # Notes
    /// - READ-ONLY: Does not modify state
    /// - Deterministic: Same input always produces same output
    pub fn estimate_compute_gas(&self, cycles: u64, node_address: Option<&Address>) -> (u128, u32) {
        let node_multiplier = match node_address {
            Some(addr) => self.get_node_cost_index(addr),
            None => internal_gas::DEFAULT_NODE_COST_INDEX,
        };

        let base_cost: u128 = internal_gas::BASE_OP_COMPUTE_OP as u128;
        let cycle_cost: u128 = (cycles as u128) * (internal_gas::PER_COMPUTE_CYCLE_COST as u128);
        let sum = base_cost + cycle_cost;
        
        // Ceiling division: ceil(sum * multiplier / 100)
        let product = sum * node_multiplier;
        let total_gas = (product + 99) / 100;

        (total_gas, node_multiplier as u32)
    }

    // ════════════════════════════════════════════════════════════════════════════
    // SERVICE NODE REGISTRY (14B.12)
    // ════════════════════════════════════════════════════════════════════════════
    // CRUD, query, and status management for service node registry.
    // Logic implemented in crate::gating::registry.
    // All methods preserve the bidirectional index invariant (14B.11).
    // ════════════════════════════════════════════════════════════════════════════

    /// Register a new service node in the on-chain registry.
    ///
    /// Validates that operator_address and node_id are unique, and that
    /// staked_amount > 0. Updates both `service_nodes` and `service_node_index`
    /// atomically.
    ///
    /// ## Errors
    /// - Operator address already registered
    /// - Node ID already registered
    /// - Staked amount is zero
    #[inline]
    pub fn register_service_node(
        &mut self,
        record: ServiceNodeRecord,
    ) -> Result<(), String> {
        crate::gating::registry::register_service_node(self, record)
    }

    /// Remove a service node from the on-chain registry.
    ///
    /// Removes from both `service_nodes` and `service_node_index`.
    /// Returns the removed record.
    ///
    /// ## Errors
    /// - Operator address not found
    #[inline]
    pub fn unregister_service_node(
        &mut self,
        operator: &Address,
    ) -> Result<ServiceNodeRecord, String> {
        crate::gating::registry::unregister_service_node(self, operator)
    }

    /// Look up a service node by operator address.
    #[inline]
    pub fn get_service_node(
        &self,
        operator: &Address,
    ) -> Option<&ServiceNodeRecord> {
        crate::gating::registry::get_service_node(self, operator)
    }

    /// Look up a service node by its 32-byte node ID.
    #[inline]
    pub fn get_service_node_by_node_id(
        &self,
        node_id: &[u8; 32],
    ) -> Option<&ServiceNodeRecord> {
        crate::gating::registry::get_service_node_by_node_id(self, node_id)
    }

    /// Update the status of a service node, enforcing valid state transitions.
    ///
    /// Uses `NodeStatus::can_transition_to()` to validate the transition.
    /// Updates `status` and `last_status_change_height` atomically.
    ///
    /// ## Errors
    /// - Operator address not found
    /// - Invalid state transition
    #[inline]
    pub fn update_service_node_status(
        &mut self,
        operator: &Address,
        new_status: dsdn_common::gating::NodeStatus,
        height: u64,
    ) -> Result<(), String> {
        crate::gating::registry::update_service_node_status(self, operator, new_status, height)
    }

    /// Return references to all service node records.
    ///
    /// Order is non-deterministic (HashMap iteration).
    #[inline]
    pub fn list_service_nodes(&self) -> Vec<&ServiceNodeRecord> {
        crate::gating::registry::list_service_nodes(self)
    }

     /// Count the number of service nodes with `NodeStatus::Active`.
     #[inline]
     pub fn count_active_service_nodes(&self) -> usize {
         crate::gating::registry::count_active_service_nodes(self)
     }

     // ══════════════════════════════════════════════════════════════════════════
     // SERVICE NODE STAKE QUERIES (14B.14)
     // ══════════════════════════════════════════════════════════════════════════
     // Read-only query methods for service node stake information.
     // Logic implemented in crate::gating::query.
     // All methods are &self — no mutation, no allocation, no side effects.
     // ══════════════════════════════════════════════════════════════════════════

     /// Get staked amount for a service node by operator address.
     ///
     /// Returns `Some(staked_amount)` if registered, `None` otherwise.
     #[inline]
     pub fn get_service_node_stake(&self, operator: &Address) -> Option<u128> {
         crate::gating::query::get_service_node_stake(self, operator)
     }

     /// Get staked amount for a service node by its 32-byte node ID.
     ///
     /// Lookup path: `service_node_index[node_id]` → `service_nodes[operator]`.
     /// Returns `Some(staked_amount)` if found, `None` otherwise.
     #[inline]
     pub fn get_service_node_stake_by_node_id(&self, node_id: &[u8; 32]) -> Option<u128> {
         crate::gating::query::get_service_node_stake_by_node_id(self, node_id)
     }

     /// Get composite stake information for a service node.
     ///
     /// Returns `ServiceNodeStakeInfo` with operator, staked_amount, class,
     /// and explicitly evaluated `meets_minimum` flag.
     /// Returns `None` if operator is not registered.
     pub fn get_stake_info(
          &self,
          operator: &Address,
      ) -> Option<crate::gating::query::ServiceNodeStakeInfo> {
          crate::gating::query::get_stake_info(self, operator)
      }

     // ══════════════════════════════════════════════════════════════════════════
     // SERVICE NODE CLASS, STATUS & SLASHING QUERIES (14B.15)
     // ══════════════════════════════════════════════════════════════════════════
     // Read-only query methods for node class, status, and slashing info.
     // Logic implemented in crate::gating::query.
     // All methods are &self — no mutation, no allocation, no side effects.
     // ══════════════════════════════════════════════════════════════════════════

     /// Get the `NodeClass` of a service node by operator address.
     ///
     /// Returns `Some(NodeClass)` if registered, `None` otherwise.
     #[inline]
     pub fn get_service_node_class(&self, operator: &Address) -> Option<dsdn_common::gating::NodeClass> {
         crate::gating::query::get_service_node_class(self, operator)
     }

     /// Get the `NodeStatus` of a service node by operator address.
     ///
     /// Returns `Some(NodeStatus)` if registered, `None` otherwise.
     #[inline]
     pub fn get_service_node_status(&self, operator: &Address) -> Option<dsdn_common::gating::NodeStatus> {
         crate::gating::query::get_service_node_status(self, operator)
     }

     /// Get composite slashing and cooldown information for a service node.
     ///
     /// Evaluates cooldown against `current_timestamp`.
     /// Returns `None` if operator is not registered.
     #[inline]
     pub fn get_service_node_slashing_status(
         &self,
         operator: &Address,
         current_timestamp: u64,
     ) -> Option<crate::gating::query::ServiceNodeSlashingInfo> {
         crate::gating::query::get_service_node_slashing_status(self, operator, current_timestamp)
     }

     /// Check whether a service node is currently in an active cooldown period.
     ///
     /// Returns `true` only if registered AND cooldown active at `current_timestamp`.
     /// Returns `false` for unregistered operators.
    pub fn is_service_node_in_cooldown(
          &self,
          operator: &Address,
          current_timestamp: u64,
      ) -> bool {
          crate::gating::query::is_service_node_in_cooldown(self, operator, current_timestamp)
      }

      // ══════════════════════════════════════════════════════════════════════════
      // SERVICE NODE SLASHING & COOLDOWN ENFORCEMENT (14B.16)
      // ══════════════════════════════════════════════════════════════════════════
      // Slashing, cooldown expiry, and activation methods.
      // Logic implemented in crate::gating::slashing.
      // ══════════════════════════════════════════════════════════════════════════

      /// Slash a registered service node.
      ///
      /// Deducts `amount` from stake, evaluates status (Quarantined if below
      /// minimum, Banned + cooldown if severe), and reduces locked balance.
      /// Returns `ServiceNodeSlashEvent` with FINAL state.
      ///
      /// ## Errors
      /// - Operator not registered
      /// - Amount is zero
      /// - Reason is empty
      /// - Insufficient staked amount
      #[inline]
      pub fn slash_service_node(
          &mut self,
          operator: &Address,
          amount: u128,
          reason: String,
          height: u64,
          timestamp: u64,
          severe: bool,
      ) -> Result<crate::gating::slashing::ServiceNodeSlashEvent, String> {
          crate::gating::slashing::slash_service_node(
              self, operator, amount, reason, height, timestamp, severe,
          )
      }

      /// Clear expired cooldowns and transition Banned → Pending.
      ///
      /// Iterates all service nodes. For each expired cooldown:
      /// cooldown set to None, and if Banned → Pending.
      #[inline]
      pub fn check_and_clear_expired_cooldowns(&mut self, current_timestamp: u64) {
          crate::gating::slashing::check_and_clear_expired_cooldowns(self, current_timestamp)
      }

      /// Activate a service node: Pending → Active.
      ///
      /// All gating checks must have already passed.
      ///
      /// ## Errors
      /// - Operator not registered
      /// - Status is not Pending
      #[inline]
      pub fn activate_service_node(
          &mut self,
          operator: &Address,
          height: u64,
      ) -> Result<(), String> {
          crate::gating::slashing::activate_service_node(self, operator, height)
      }
  }


// ════════════════════════════════════════════════════════════════════════════
// DEFAULT IMPLEMENTATION
// ════════════════════════════════════════════════════════════════════════════

impl Default for ChainState {
    fn default() -> Self {
        Self::new()
    }
}

// ════════════════════════════════════════════════════════════════════════════
// METHOD REFERENCE
// ════════════════════════════════════════════════════════════════════════════
//
// Semua method ChainState lainnya di-implement di internal modules.
// Method dipanggil langsung pada ChainState instance karena setiap
// internal module melakukan `impl ChainState { ... }`.
//
// ════════════════════════════════════════════════════════════════════════════
//
// ## internal_account.rs - Account Management
// 
// | Method | Description |
// |--------|-------------|
// | `create_account(addr)` | Initialize account dengan balance/nonce/locked = 0 |
// | `get_balance(addr)` | Get liquid balance |
// | `get_locked(addr)` | Get staked/locked balance |
// | `get_nonce(addr)` | Get transaction nonce |
// | `increment_nonce(addr)` | Increment nonce after tx |
// | `mint(addr, amount)` | Mint new tokens (genesis/reward) |
// | `transfer_raw(from, to, amount)` | Internal transfer tanpa fee/nonce |
//
// ════════════════════════════════════════════════════════════════════════════
//
// ## internal_staking.rs - Staking Lifecycle (13.8.A/B)
// 
// ### Validator Stake
// | Method | Description |
// |--------|-------------|
// | `deposit_validator_stake(addr, amount)` | Validator deposit own stake |
// | `withdraw_validator_stake(addr, amount)` | Validator withdraw own stake |
// | `get_validator_stake(addr)` | Get validator's own stake (bukan total) |
// | `validator_meets_minimum(addr)` | Check >= VALIDATOR_MIN_STAKE |
//
// ### Delegator Stake
// | Method | Description |
// |--------|-------------|
// | `register_delegator_stake(delegator, validator, amount)` | New delegation |
// | `withdraw_delegator_stake(delegator, validator, amount)` | Withdraw delegation |
// | `get_delegator_stake(addr)` | Get delegator's total stake |
// | `get_delegator_validator(delegator)` | Get validator yang didelegasikan |
// | `is_delegator(addr)` | Check if address is delegator |
// | `is_valid_delegation(delegator, validator)` | Validate delegation rules |
//
// ### Bond/Unbond
// | Method | Description |
// |--------|-------------|
// | `bond(delegator, validator, amount)` | Legacy bond (langsung) |
// | `unbond(delegator, validator, amount)` | Unbond dengan 7-day delay |
// | `unbond_with_delay(delegator, validator, amount, ts)` | Unbond dengan custom timestamp |
// | `unbond_immediate(delegator, validator, amount)` | Immediate unbond (slashing only) |
//
// ════════════════════════════════════════════════════════════════════════════
//
// ## internal_qv_cache.rs - Quadratic Voting (13.8.C/D)
// 
// ### Weight Management
// | Method | Description |
// |--------|-------------|
// | `update_qv_weight(addr)` | Recalculate individual QV weight |
// | `update_validator_qv_weight(validator)` | Recalculate combined validator weight |
// | `get_qv_weight(addr)` | Get cached individual weight |
// | `get_validator_qv_weight(validator)` | Get cached validator weight |
// | `recalculate_all_qv_weights()` | Full recalculation (migration/recovery) |
//
// ### Voting Power
// | Method | Description |
// |--------|-------------|
// | `get_voting_power(addr)` | Get voting power = sqrt(locked) |
// | `get_validator_total_power(validator)` | Get total power (self + delegators) |
// | `compute_validator_weight(validator)` | 80/20 weighted formula |
// | `get_validator_self_qv(validator)` | 80% component dari self stake |
// | `get_validator_delegator_qv(validator)` | 20% component dari delegators |
// | `get_validator_weight_breakdown(validator)` | Detailed breakdown tuple |
//
// ### Network Queries
// | Method | Description |
// |--------|-------------|
// | `get_validators_by_power()` | Sorted list (power desc) for proposer selection |
// | `get_total_network_power()` | Sum of all validator powers |
// | `get_validator_power_ratio(validator)` | (power, total) for probability |
//
// ════════════════════════════════════════════════════════════════════════════
//
// ## internal_fees.rs - Fee Pool Management (13.8.E)
// 
// | Method | Description |
// |--------|-------------|
// | `get_validator_fee_pool()` | Get accumulated validator fees |
// | `add_to_validator_fee_pool(amount)` | Add to validator pool |
// | `claim_validator_fee(validator, amount)` | Validator claims fee |
// | `get_storage_fee_pool()` | Get storage pool balance |
// | `get_compute_fee_pool()` | Get compute pool balance |
// | `allocate_fee_to_pool(class, fee, node, miner, sender)` | Route fee by ResourceClass |
// | `apply_fee_split(fee_split, class, node)` | Apply pre-calculated FeeSplit |
// | `claim_storage_fee(node, amount)` | Storage node claims |
// | `claim_compute_fee(node, amount)` | Compute node claims |
//
// ### Fee Split Rules (Blueprint 70/20/10)
// • FeeSplit mengikuti blueprint 70/20/10 untuk Storage/Compute.
// • Anti-self-dealing node diterapkan sebelum alokasi: jika service_node == sender
//   maka seluruh node_share dialihkan ke treasury.
// • allocate_fee_to_pool adalah wrapper dari alokasi terpusat di apply_payload.
// • Fungsi fee split berasal dari `crate::tokenomics::calculate_fee_by_resource_class`.
// • node_earnings diupdate ketika node menerima fee share.
//
// ════════════════════════════════════════════════════════════════════════════
//
// ## internal_rewards.rs - Reward Distribution (13.7.H, 13.8.F)
// 
// | Method | Description |
// |--------|-------------|
// | `distribute_delegator_rewards(validator)` | Distribute pending rewards |
// | `add_pending_delegator_reward(validator, amount)` | Add to pending |
// | `get_pending_delegator_rewards(validator)` | Get pending amount |
// | `get_delegator_accrued(delegator)` | Get year-to-date accrued |
// | `get_delegator_last_epoch(delegator)` | Get last reward epoch |
// | `maybe_reset_annual_cap()` | Check & reset if new year |
// | `calculate_capped_reward(delegator, base)` | Apply 1% annual cap |
// | `distribute_epoch_rewards_capped(validator)` | Distribute with cap |
// | `reset_delegator_reward_tracking(delegator)` | Reset on full unstake |
// | `get_delegator_cap_status(delegator)` | (stake, cap, accrued, remaining) |
// | `claim_reward(node, amount)` | Claim from reward_pool |
//
// ════════════════════════════════════════════════════════════════════════════
//
// ## internal_unstake_queue.rs - 7-Day Delay (13.8.G)
// 
// | Method | Description |
// |--------|-------------|
// | `process_unstake_unlocks(current_ts)` | Process matured unstakes → (count, amount) |
// | `cancel_pending_unstake(delegator, validator, amount, ts)` | Cancel & re-stake |
// | `get_pending_unstakes(addr)` | Get all pending for address |
// | `get_total_pending_unstake(addr)` | Sum of pending amounts |
// | `has_pending_unstake(addr)` | Check if has any pending |
// | `get_all_pending_unstakes()` | Get entire pending map (for DB) |
// | `set_pending_unstakes(map)` | Set from DB load |
//
// ════════════════════════════════════════════════════════════════════════════
//
// ## internal_slash_adapter.rs - Slashing (13.8.J)
// 
// | Method | Description |
// |--------|-------------|
// | `apply_slash_to_validator(validator, percent)` | Slash validator stake → amount |
// | `apply_slash_to_delegators(validator, percent)` | Slash all delegators → amount |
// | `apply_full_slash(validator, percent)` | Slash both → (val, del, total) |
// | `recalc_qv_weight(addr)` | Convenience wrapper for QV update |
//
// ════════════════════════════════════════════════════════════════════════════
//
// ## internal_state_layout.rs - LMDB Persistence (13.8.H)
// 
// | Method | Description |
// |--------|-------------|
// | `get_stake_data(addr)` | Get StakeData struct for DB |
// | `set_stake_data(data)` | Set from StakeData (updates multiple maps) |
// | `get_delegator_data(addr)` | Get DelegatorData for DB |
// | `set_delegator_data(data)` | Set from DelegatorData |
// | `get_qv_weight_data(addr)` | Get QvWeightData for DB |
// | `set_qv_weight_data(data)` | Set from QvWeightData |
// | `load_from_state_layout(validators, stakes, delegators, qv)` | Full load from DB |
// | `export_to_state_layout()` | Export to DB format |
//
// ════════════════════════════════════════════════════════════════════════════
//
// ## internal_payload.rs - Transaction Execution (13.7.E/F/G)
// 
// | Method | Description |
// |--------|-------------|
// | `is_self_dealing(validator, payload)` | Check anti self-dealing rule |
// | `get_target_node(payload)` | Extract target node from Storage/Compute tx |
// | `apply_payload(env, miner)` | Execute transaction → (gas_used, events) |
//
// ### apply_payload handles:
// - TxPayload::Transfer
// - TxPayload::Stake (bond/delegate)
// - TxPayload::Unstake (unbond)
// - TxPayload::ClaimReward → see Section 13.10 for full flow
// - TxPayload::StorageOperationPayment
// - TxPayload::ComputeExecutionPayment
// - TxPayload::ValidatorRegistration
// - TxPayload::GovernanceAction
// - TxPayload::Custom
// - Private TX relay (13.7.F)
// - Anti self-dealing (13.7.G)
//
// • apply_payload sekarang menggunakan internal_gas::compute_gas_for_payload untuk
//   menghitung gas_used dan GasBreakdown.
// • FeeSplit diterapkan penuh: node_share, validator_share, treasury_share.
// • Event tx mencakup gas_breakdown dan fee_split untuk keperluan audit.
// • node_earnings diupdate ketika node menerima fee share.
//
// ### ClaimReward Handling (13.10)
//
// ClaimReward dieksekusi secara terpisah dengan early return:
// 1. verify_receipt() → ReceiptError
// 2. Distribusi 70/20/10 dari reward_base
// 3. Anti-self-dealing enforcement
// 4. mark_receipt_claimed()
// 5. Fee deduction + Return gas_used
//
// ════════════════════════════════════════════════════════════════════════════
//
// ## internal_state_root.rs - State Root Computation
// 
// | Method | Description |
// |--------|-------------|
// | `compute_state_root()` | Compute Merkle hash of all state → Hash |
//
// ### State root includes (in order):
// 1. balances (sorted by address)
// 2. nonces (sorted)
// 3. locked (sorted)
// 4. validators (sorted)
// 5. validator_set (sorted)
// 6. delegations (sorted by validator, then delegator)
// 7. delegator_pool
// 8. validator_stakes (sorted)
// 9. delegator_stakes (sorted)
// 10. delegator_to_validator (sorted)
// 11. validator_fee_pool
// 12. storage_fee_pool
// 13. compute_fee_pool
// 14. pending_delegator_rewards (sorted)
// 15. delegator_reward_accrued (sorted)
// 16. delegator_last_epoch (sorted)
// 17. year_start_epoch
// 18. pending_unstakes (sorted)
// 19. qv_weights (sorted)
// 20. validator_qv_weights (sorted)
// 21. liveness_records (sorted)
// 22. epoch_info
// 23. node_cost_index (sorted)
// 24. node_earnings (sorted)
// 25. claimed_receipts (sorted)
//
// NOTE: NodeCostIndex, NodeEarnings, dan ClaimedReceipts termasuk dalam state_root (consensus-critical).
//
// ### CONSENSUS-CRITICAL WARNING (13.10)
//
// claimed_receipts adalah consensus-critical untuk proteksi replay receipt.
// Perubahan semantik, format hashing, atau urutan field ini membutuhkan hard-fork.
// Field ini di-hash dengan deterministic ordering:
// - Sorted ascending berdasarkan Hash bytes (canonical ordering)
// - Format: [receipt_id_bytes (64)] per entry
// ### CONSENSUS-CRITICAL WARNING (13.9)
//
// Perubahan pada node_cost_index dan node_earnings bersifat consensus-critical.
// Setiap perubahan semantik, format hashing, atau struktur field ini membutuhkan hard-fork.
//
// Field ini di-hash dengan deterministic ordering:
// - Sorted ascending berdasarkan Address (canonical ordering)
// - Value di-serialize sebagai big-endian bytes
// - Format: [address_bytes (20)] + [value_bytes (16)]
//
// ## internal_misc.rs - Miscellaneous Helpers
// 
// | Method | Description |
// |--------|-------------|
// | `get_treasury_balance()` | Get treasury balance |
// | `get_delegator_pool()` | Get delegator reward pool |
// | `get_liveness_record(addr)` | Get validator liveness record |
// | `is_validator_slashed(addr)` | Check if validator was slashed |
// | `get_current_epoch()` | Get current epoch number |
// | `get_epoch_info()` | Get full EpochInfo struct |
// | `set_epoch_config(config)` | Update epoch configuration |
// | `maybe_rotate_epoch(height)` | Check & rotate epoch if needed |
//
// ════════════════════════════════════════════════════════════════════════════
//
// ## internal_node_cost.rs - Node Cost Index & Earnings (13.9)
//
// | Method | Description |
// |--------|-------------|
// | `set_node_cost_index(addr, multiplier)` | Set cost multiplier for node |
// | `get_node_cost_index(addr)` | Get cost multiplier (or default 100) |
// | `remove_node_cost_index(addr)` | Remove custom multiplier → Option<u128> |
// | `list_node_cost_indexes()` | List all (addr, multiplier) sorted |
// | `credit_node_earning(addr, amount)` | Add earnings to node |
// | `claim_node_earning(addr)` | Claim all earnings → u128 |
//
// ### PENTING: Governance & Admin Access
//
// Node Cost Index dapat diperbarui melalui:
// - **Governance Action**: TxPayload::GovernanceAction dengan proposal yang disetujui
// - **Admin CLI**: `dsdn node-cost set/remove` command
//
// Perubahan `node_cost_index` adalah **consensus-critical** dan termasuk
// dalam `state_root` computation (item #23 dalam ordering).
//
// ### Impact pada Gas Calculation
//
// Node cost index mempengaruhi gas fee calculation:
// - Multiplier 100 = 1.0x (default, tidak ada perubahan)
// - Multiplier 150 = 1.5x (premium node, fee lebih tinggi)
// - Multiplier 50 = 0.5x (discounted node, fee lebih rendah)
//
// ════════════════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════════════════
//
// ## internal_economic.rs - Economic Metrics Tracking (13.15.3)
//
// | Method | Description |
// |--------|-------------|
// | `update_replication_factor(rf)` | Update RF, mode change Bootstrap → Active |
// | `record_storage_usage(bytes)` | Akumulasi storage usage (overflow-safe) |
// | `record_compute_usage(cycles)` | Akumulasi compute cycles (overflow-safe) |
// | `update_token_velocity(volume, epoch)` | EMA velocity calculation |
// | `record_treasury_inflow(amount, source)` | Track fee/slashing inflow |
// | `reset_epoch_metrics(new_epoch)` | Reset per-epoch counters |
// | `get_economic_mode()` | Get current economic mode |
// | `update_active_counts()` | Count active nodes/validators |
// | `get_economic_snapshot()` | Full economic snapshot |
//
// ### Karakteristik (CONSENSUS-CRITICAL)
//
// ```text
// ⚠️ Semua method deterministik:
// - Tidak menggunakan float
// - Tidak menggunakan random
// - Hasil identik di semua node
// - Safe untuk consensus
//
// ⚠️ Digunakan oleh:
// - Burn rate calculator (13.15.4)
// - Treasury burn executor (13.15.5)
// - Economic RPC/CLI (13.15.8)
// ```
//
// ### Mode Transition Logic
//
// ```text
// Bootstrap → Active:
//   Ketika RF > BOOTSTRAP_RF (3) DAN deflation enabled
//
// Active → Governance:
//   Via governance proposal (future)
//
// Mode Detection Priority:
//   1. disabled → Bootstrap
//   2. mode == Governance → Governance
//   3. RF > BOOTSTRAP_RF → Active
//   4. else → Bootstrap
// ```
//
// ### Velocity EMA Formula
//
// ```text
// new_velocity = (80 * transfer_volume + 20 * old_velocity) / 100
//
// VELOCITY_SMOOTHING_FACTOR = 80 (80% weight ke current)
// ```
//
// ## Burn Rate Algorithm (13.15.4)
//
// ### Tujuan
//
// Menghitung burn rate adaptif untuk deflasi token $NUSA.
// Target: 3-6% deflasi tahunan, disesuaikan berdasarkan kondisi jaringan.
//
// ### Input Metrics
//
// | Metric | Sumber | Pengaruh |
// |--------|--------|----------|
// | Replication Factor (RF) | `economic_metrics.replication_factor` | Higher RF → higher burn |
// | Token Velocity | `economic_metrics.token_velocity` | Higher velocity → lower burn |
// | Treasury Balance | `treasury_balance` | Must be above MIN_RESERVE |
// | Economic Mode | `get_economic_mode()` | Bootstrap → no burn |
//
// ### Algoritma Base Rate
//
// ```text
// 1. base_rate = (TARGET_MIN + TARGET_MAX) / 2 = (300 + 600) / 2 = 450 bp
// 2. adjusted = base_rate * rf_multiplier / 100
// 3. adjusted = adjusted * velocity_factor / 100
// 4. Treasury bonus: +30bp (5x reserve) atau +50bp (10x reserve)
// 5. Clamp to [300, 600] basis points
// ```
//
// ### RF Multiplier (basis 100)
//
// | RF | Multiplier | Effect |
// |----|------------|--------|
// | ≤3 | 100 | 1.0x (Bootstrap, no burn) |
// | 4 | 120 | 1.2x |
// | 5 | 140 | 1.4x |
// | ≥6 | 160 | 1.6x (max) |
//
// ### Velocity Factor (basis 100)
//
// | Velocity | Factor | Effect |
// |----------|--------|--------|
// | < 1M | 100 | No reduction |
// | 1M - 10M | 90 | 10% reduction |
// | ≥ 10M | 80 | 20% reduction |
//
// ### Treasury Safety Guard
//
// ```text
// - MIN_TREASURY_RESERVE = 1_000_000
// - Burn tidak boleh mengurangi treasury di bawah reserve
// - MAX_BURN_PER_EPOCH = 0.5% total_supply (50 basis points)
// ```
//
// ### Contoh Alur Perhitungan
//
// ```text
// Setup:
//   total_supply = 1_000_000_000
//   treasury = 10_000_000
//   RF = 5
//   velocity = 500_000 (low)
//
// Calculation:
//   1. base_rate = 450 bp
//   2. rf_multiplier = 140 → adjusted = 450 * 140 / 100 = 630
//   3. velocity_factor = 100 → adjusted = 630 * 100 / 100 = 630
//   4. treasury_ratio = 10 → adjusted = 630 + 50 = 680
//   5. clamp to 600 (max)
//
// Result: burn_rate = 600 bp (6%)
//
// Epoch Burn:
//   annual_burn = 1_000_000_000 * 600 / 10000 = 60_000_000
//   epoch_burn = 60_000_000 / 365 = 164_383
//   max_per_epoch = 1_000_000_000 * 50 / 10000 = 5_000_000
//   available = 10_000_000 - 1_000_000 = 9_000_000
//   final_burn = min(164_383, 5_000_000, 9_000_000) = 164_383
// ```
//
// ### Burn Rate Methods (13.15.4)
//
// | Method | Description |
// |--------|-------------|
// | `calculate_target_burn_rate()` | Calculate adaptive burn rate (basis points) |
// | `calculate_burn_amount(rate)` | Calculate epoch burn amount |
// | `should_burn(current_epoch)` | Check if burn conditions are met |
// | `get_rf_multiplier()` | Get RF-based multiplier |
// | `get_velocity_factor()` | Get velocity-based factor |
//
// ### Consensus-Critical Warning
//
// ```text
// ⚠️ SEMUA PERHITUNGAN ADALAH:
// - Integer-only (tidak ada float)
// - Deterministik (hasil identik di semua node)
// - Overflow-safe (saturating operations)
// - Tanpa side effect (pure calculation)
//
// ⚠️ PERUBAHAN ALGORITMA MEMERLUKAN HARD-FORK
// ```
//
// ### Velocity Thresholds (Constants)
//
// ```text
// VELOCITY_THRESHOLD_LOW = 1_000_000
// VELOCITY_THRESHOLD_HIGH = 10_000_000
// EPOCHS_PER_YEAR = 365
// ```
// ## Treasury Burn Execution (13.15.5)
//
// ### Overview
//
// Treasury Burn Execution adalah TITIK EKSEKUSI PERUBAHAN SUPPLY TOKEN.
// Ini adalah SATU-SATUNYA mekanisme di mana token $NUSA secara permanen
// dihapus dari sirkulasi.
//
// ### Alur Eksekusi Burn (Step-by-Step)
//
// ```text
// ┌─────────────────────────────────────────────────────────────────────────┐
// │                    EXECUTE TREASURY BURN FLOW                          │
// ├─────────────────────────────────────────────────────────────────────────┤
// │                                                                         │
//│  1. CHECK: should_burn(current_epoch) == true?                         │
// │     ├─ NO  → Return None (NO STATE CHANGE)                             │
// │     └─ YES → Continue                                                  │
// │                                                                         │
// │  2. CALCULATE: rate = calculate_target_burn_rate()                     │
// │     └─ Adaptive rate [300, 600] basis points                           │
// │                                                                         │
// │  3. CALCULATE: amount = calculate_burn_amount(rate)                    │
// │     └─ Clamped by treasury reserve & max per epoch                     │
// │                                                                         │
// │  4. CHECK: amount == 0?                                                │
// │     ├─ YES → Return None (NO STATE CHANGE)                             │
// │     └─ NO  → Continue                                                  │
// │                                                                         │
// │  5. SNAPSHOT: Capture before values                                    │
// │     ├─ treasury_before = treasury_balance                              │
// │     └─ total_supply_before = total_supply                              │
// │                                                                         │
// │  6. EXECUTE STATE MUTATIONS (URUTAN TIDAK BOLEH DIUBAH):              │
// │     ├─ treasury_balance -= amount                                      │
// │     ├─ total_supply -= amount                                          │
// │     ├─ cumulative_burned += amount                                     │
// │     └─ last_burn_epoch = current_epoch                                 │
// │                                                                         │
// │  7. CREATE: BurnEvent dengan audit trail lengkap                       │
// │                                                                         │
// │  8. RECORD: Push event ke economic_events                              │
// │                                                                         │
// │  9. RETURN: Some(event)                                                │
// │                                                                         │
// └─────────────────────────────────────────────────────────────────────────┘
// ```
//
// ### Kondisi Pre-Check (should_burn)
//
// | Kondisi | Harus |
// |---------|-------|
// | `deflation_config.enabled` | `true` |
// | `get_economic_mode()` | `!= Bootstrap` |
// | `current_epoch - last_burn_epoch` | `>= burn_interval_epochs` |
// | `treasury_balance` | `> MIN_TREASURY_RESERVE` |
//
// SEMUA kondisi harus terpenuhi untuk burn dilakukan.
//
// ### State Yang Berubah
//
// | Field | Perubahan | Catatan |
// |-------|-----------|---------|
// | `treasury_balance` | Dikurangi `amount` | Saturating subtraction |
// | `total_supply` | Dikurangi `amount` | Permanent removal |
// | `cumulative_burned` | Ditambah `amount` | Running total |
// | `last_burn_epoch` | Di-set ke `current_epoch` | Prevent double burn |
// | `economic_events` | Push `BurnEvent` | Audit trail |
//
// ### Hubungan dengan Burn Rate Calculation
//
// ```text
// ┌─────────────────────────────────────────────────────────────────────────┐
// │                        BURN RATE DEPENDENCIES                          │
// ├─────────────────────────────────────────────────────────────────────────┤
// │                                                                         │
// │  calculate_target_burn_rate()                                          │
// │    ├── get_economic_mode()        → Mode check                         │
// │    ├── get_rf_multiplier()        → RF-based adjustment [100-160]      │
// │    ├── get_velocity_factor()      → Velocity adjustment [80-100]       │
// │    └── Treasury ratio adjustment  → Up to +50 basis points             │
//`│                                                                         │
// │  calculate_burn_amount(rate)                                           │
// │    ├── Annual burn = supply × rate / 10000                             │
// │    ├── Epoch burn = annual / 365                                       │
// │    ├── Clamp to MAX_BURN_PER_EPOCH_PERCENT                             │
// │    └── Clamp to treasury - MIN_TREASURY_RESERVE                        │
// │                                                                         │
// └─────────────────────────────────────────────────────────────────────────┘
// ```
//
// ### BurnEvent Fields
//
// | Field | Type | Deskripsi |
// |-------|------|-----------|
// | `epoch` | `u64` | Epoch saat burn terjadi |
// | `amount_burned` | `u128` | Jumlah token yang di-burn |
// | `burn_rate_applied` | `u128` | Rate yang digunakan (basis points) |
// | `total_supply_before` | `u128` | Supply sebelum burn |
// | `total_supply_after` | `u128` | Supply setelah burn |
// | `treasury_before` | `u128` | Treasury sebelum burn |
// | `treasury_after` | `u128` | Treasury setelah burn |
// | `timestamp` | `u64` | Block timestamp |
//
// ### Safety Invariants
//
//```text
// ⚠️ CONSENSUS-CRITICAL INVARIANTS:
//
// 1. DETERMINISTIK
//    - Hasil identik di semua node
//    - Integer-only arithmetic
//    - Tidak menggunakan float / random
//
// 2. NO PANIC
//    - Semua operasi overflow-safe (saturating)
//    - Semua edge case di-handle
//
// 3. ATOMIC
//    - Jika gagal, state TIDAK berubah sama sekali
//    - Tidak ada partial state update
//
// 4. IDEMPOTENT (per interval)
//    - Double burn di epoch yang sama: tidak mungkin
//    - last_burn_epoch menjamin interval
//
// 5. AUDITABLE
//   - Setiap burn tercatat di economic_events
//   - Before/after values tersedia
// ```
//
// | Error | Kondisi | Recovery |
// |-------|---------|----------|
// | `InsufficientTreasury` | `treasury_balance < amount` | Wait for treasury inflow |
// | `BurnDisabled` | Deflation disabled / Bootstrap | Enable deflation / increase RF |
// | `InvalidAmount` | `amount == 0` | No action needed |
// | `NotYetDue` | Interval belum tercapai | Wait for more epochs |
//
// ### Methods Reference
//
// | Method | Signature | Deskripsi |
// |--------|-----------|-----------|
// | `execute_treasury_burn` | `(&mut self, epoch: u64, ts: u64) -> Option<BurnEvent>` | Main burn execution |
// | `burn_from_treasury` | `(&mut self, amount: u128) -> Result<(), EconomicError>` | Low-level manual burn |
//| `get_annual_burn_rate` | `(&self) -> u128` | Current annual rate (basis points) |
// | `get_burn_history` | `(&self) -> &[BurnEvent]` | Read-only access to events |
//
// ### TIDAK BOLEH
//
// ```text
// ❌ DILARANG KERAS:
//
// - Memanggil execute_treasury_burn sembarangan
// - Mengubah urutan state mutations
// - Menggunakan floating point
// - Burn di luar jadwal (bypass should_burn)
// - Menambah variant baru ke EconomicError
// - Mengubah algoritma burn rate di sini
// ```
// ## Block-Level Economic Job (13.15.6)
//
// ### Overview
//
//Economic job adalah proses ekonomi yang dijalankan pada setiap block untuk:
// - Memperbarui metrics (active nodes, active validators)
// - Mendeteksi epoch transition dan reset epoch metrics
// - Mengeksekusi treasury burn jika kondisi terpenuhi
//
// ### Posisi dalam Block Lifecycle
//
// ```text
// ┌────────────────────────────────────────────────────────────────┐
// │                    BLOCK PROCESSING PIPELINE                   │
// ├────────────────────────────────────────────────────────────────┤
// │  1. Execute all transactions                                   │
// │  2. process_automatic_slashing()                              │
// │  3. process_economic_job()  ← ECONOMIC JOB                    │
// │  4. compute_state_root()                                       │
// │  5. Verify state_root                                          │
// │  6. atomic_commit_block()                                      │
// └────────────────────────────────────────────────────────────────┘
// ```
//
// ### Hubungan dengan Slashing
//
// - Economic job HARUS dijalankan SETELAH slashing
// - Slashing dapat menambah treasury inflow (dari penalty)
// - Economic job menggunakan treasury_balance yang sudah diupdate
// - Urutan ini memastikan burn calculation memperhitungkan slashing inflow
//
// ### Hubungan dengan State Root
//
// - Economic job HARUS dijalankan SEBELUM state_root
// - Treasury burn memengaruhi:
//   - `treasury_balance` (dikurangi)
//  - `cumulative_burned` (ditambah)
//   - `last_burn_epoch` (diupdate)
//   - `economic_metrics` (active counts diupdate)
// - Semua perubahan ini WAJIB masuk ke state_root computation
//
// ### Jaminan Determinisme
//
//```text
// ⚠️ CONSENSUS-CRITICAL:
//
// - Semua node HARUS menjalankan economic job di titik yang SAMA
// - Urutan eksekusi TIDAK BOLEH berubah
// - Hasil HARUS identik di semua node
// - Tidak ada randomness, tidak ada float
// - Integer arithmetic dengan saturating ops
// ```
//
// ### Karakteristik
//
// | Aspek | Nilai |
// |-------|-------|
// | Skip | ❌ TIDAK BISA di-skip |
// | Manual call | ❌ TIDAK BISA dipanggil manual |
// | Consensus-critical | ✅ YA |
// | Deterministic | ✅ YA (integer-only) |
// | Panic-safe | ✅ YA (no unwrap/expect) |
//
// ### Method Signature
//
// ```rust,ignore
// pub fn process_economic_job(
//    &mut self,
//     block_height: u64,
//     timestamp: u64,
// ) -> Option<BurnEvent>
// ```
//
// ### Return Value
//
// - `Some(BurnEvent)` jika burn terjadi (semua kondisi terpenuhi)
// - `None` jika tidak ada burn (salah satu kondisi tidak terpenuhi)
//
// ### Execution Steps (URUTAN TIDAK BOLEH DIUBAH)
//
// 1. **Update active counts** - Hitung active nodes & validators
// 2. **Check epoch transition** - Reset metrics jika epoch berubah
// 3. **Check burn eligibility** - Validasi semua kondisi burn
// 4. **Execute burn** - Jalankan burn jika eligible
//
// ## Economic State Persistence (13.15.7)
//
// ### LMDB Buckets
//
// | Bucket | Key | Value |
// |--------|-----|-------|
// | `economic_metrics` | "metrics" | bincode(EconomicMetrics) |
// | `deflation_config` | "config" | bincode(DeflationConfig) |
// | `economic_metrics` | "last_burn_epoch" | u64 BE bytes |
// | `economic_metrics` | "cumulative_burned" | u128 BE bytes |
//
// ### State Root Positions
//
// Economic state memiliki posisi CONSENSUS-CRITICAL dalam state_root:
//
// | Position | Field | Format |
// |----------|-------|--------|
// | #31 | `deflation_config` | bincode(DeflationConfig) |
// | #32 | `economic_metrics` | bincode(EconomicMetrics) |
// | #33 | `last_burn_epoch` | u64 BE bytes |
// | #34 | `cumulative_burned` | u128 BE bytes |
//
// ### Persistence Methods
//
// | Method | Fungsi |
// |--------|--------|
// | `export_economic_state_to_layout` | Export ke LMDB |
// | `load_economic_state_from_layout` | Load dari LMDB |
//
// ### Runtime-Only Data (TIDAK Dipersist)
//
// ```text
// ⚠️ DATA BERIKUT TIDAK MASUK PERSISTENCE:
//
// - economic_events: Vec<BurnEvent>
//   Alasan: Runtime observability only
//   Start: Empty setiap restart
//
// Semua data lain WAJIB persisted:
// - deflation_config
// - economic_metrics
// - last_burn_epoch
// - cumulative_burned
// ```
//
// ### Consensus-Critical Warning
//
// ```text
// ⚠️ PERINGATAN:
//
// 1. Economic state memengaruhi state_root
// 2. Perubahan format memerlukan HARD FORK
// 3. Position ordering TIDAK BOLEH berubah (#31-#34)
// 4. Serialization format (bincode) TIDAK BOLEH berubah
// 5. Big-endian byte order TIDAK BOLEH berubah
// ```
// ════════════════════════════════════════════════════════════════════════════
//
// ## Testing Checklist for 13.9 (Gas Model & Fee Split)
// Tes wajib yang harus dijalankan untuk memverifikasi implementasi 13.9:
//
// ### Unit Tests (tokenomics/tests/fee_split_tests.rs)
// - [ ] Fee split (70/20/10) untuk Storage/Compute
// - [ ] Fee split (100% validator) untuk Transfer/Governance
// - [ ] Anti self-dealing node (node_share → treasury)
// - [ ] Edge cases (zero fee, rounding)
//
// ### Unit Tests (state/tests/gas_tests.rs)
// - [ ] Gas calculator breakdown (base_op_cost, data_cost, compute_cost)
// - [ ] Gas multiplier effect (2x multiplier → 2x gas)
// - [ ] Default multiplier digunakan ketika service_node = None
// - [ ] Byte cost calculation
//
// ### Integration Tests (e2e_tests/test_fee_allocation.rs)
// - [ ] Full apply_payload fee movement untuk Storage
// - [ ] Full apply_payload fee movement untuk Compute
// - [ ] Anti self-dealing dengan apply_payload
// - [ ] State root berubah ketika node_cost_index berubah
// - [ ] State root berubah ketika node_earnings berubah
// - [ ] State root deterministic ordering
//
// ### Menjalankan Tests
//
// ```bash
// # Unit tests fee split
// cargo test fee_split
//
// # Unit tests gas
// cargo test gas_tests
//
// # Integration tests fee allocation
// cargo test fee_allocation
//
// # Test state root dengan node_cost_index
// cargo test state_root_includes
//
// # Semua tests (jalankan satu per satu)
// cargo test fee_split
// cargo test gas_tests
// cargo test fee_allocation
//
// # Atau gunakan regex pattern untuk multiple tests
// cargo test -p dsdn-chain -- --test-threads=1 fee
// cargo test -p dsdn-chain -- --test-threads=1 gas
// ```
//
// ════════════════════════════════════════════════════════════════════════════════
// ## File Encryption & Secure Storage (13.17.5)
// ════════════════════════════════════════════════════════════════════════════════
//
// ### Overview
//
// Module encryption menyediakan file encryption system yang:
// - Terikat pada Wallet (key derivation dari wallet secret)
// - Aman secara kriptografi (AES-256-GCM authenticated encryption)
// - Mendukung sharing via key wrapping (X25519 ECDH)
// - Deterministik terhadap context (file_id → same key)
//
// ### Key Derivation Flow
//
// ```text
// ┌───────────────────────────────────────────────────────────────┐
// │                    KEY DERIVATION FLOW                        │
// ├───────────────────────────────────────────────────────────────┤
// │  wallet.secret_key (32 bytes)                                 │
// │           │                                                    │
// │           ├──────────────────┐                                │
// │           ▼                  ▼                                │
// │    ┌──────────────┐   ┌──────────────┐                       │
// │    │   context    │   │  file_id     │                       │
// │    │  (purpose)   │   │  (unique)    │                       │
// │    └──────────────┘   └──────────────┘                       │
// │           │                  │                                │
// │           ▼                  ▼                                │
// │    ┌─────────────────────────────────────┐                   │
// │    │  SHA3-256(secret_key || context)    │                   │
// │    └─────────────────────────────────────┘                   │
// │                      │                                        │
// │                      ▼                                        │
// │    ┌─────────────────────────────────────┐                   │
// │    │     Encryption Key (32 bytes)       │                   │
// │    └─────────────────────────────────────┘                   │
// └───────────────────────────────────────────────────────────────┘
// ```
//
// ### Wallet-Bound Encryption
//
// Setiap file dienkripsi dengan key yang derived dari:
// 1. Wallet's secret key (identity binding)
// 2. File ID (context separation)
//
// ```text
// key = SHA3-256(wallet.secret_key || file_id)
// ```
//
// Properti:
// - DETERMINISTIK: Same (wallet, file_id) → Same key
// - ISOLATED: Different file_id → Different key
// - BOUND: Different wallet → Different key
//
// ### AES-GCM Authenticated Encryption
//
// ```text
// ┌───────────────────────────────────────────────────────────────┐
// │                   ENCRYPTION STRUCTURE                        │
// ├───────────────────────────────────────────────────────────────┤
// │                                                               │
// │  ┌─────────────┐  ┌───────────────────┐  ┌─────────────────┐ │
// │  │   Nonce     │  │    Ciphertext     │  │  Auth Tag       │ │
// │  │  (12 bytes) │  │   (variable)      │  │  (16 bytes)     │ │
// │  └─────────────┘  └───────────────────┘  └─────────────────┘ │
// │                                                               │
// │  Nonce: Random per encryption (NEVER reuse with same key)    │
// │  Ciphertext: len(ciphertext) = len(plaintext)                │
// │  Tag: Authentication & integrity verification                │
// │                                                               │
// └───────────────────────────────────────────────────────────────┘
// ```
//
// ### File-Level Context Isolation
//
// Context (file_id) memberikan domain separation:
//
// ```text
// file_id: "user/docs/file001.pdf"  → Key A
// file_id: "user/docs/file002.pdf"  → Key B
// file_id: "user/images/photo.jpg"  → Key C
//
// Key A ≠ Key B ≠ Key C (dengan wallet yang sama)
// ```
//
// WAJIB: Setiap file memiliki file_id yang UNIQUE.
//
// ### Key Wrapping untuk Sharing
//
// ```text
// ┌───────────────────────────────────────────────────────────────┐
// │                   KEY WRAPPING FLOW                           │
// ├───────────────────────────────────────────────────────────────┤
// │                                                               │
// │  SENDER                              RECIPIENT                │
// │  ──────                              ─────────                │
// │                                                               │
// │  1. Generate ephemeral X25519 keypair                        │
// │                                                               │
// │  2. ECDH: shared_secret = ephemeral_secret × recipient_pk    │
// │                                                               │
// │  3. wrap_key = SHA3-256("dsdn_file_key_wrap_v1" || shared)   │
// │                                                               │
// │  4. encrypted_file_key = AES-GCM(wrap_key, file_key)         │
// │                                                               │
// │  5. Send: ephemeral_pk || encrypted_key || tag || nonce      │
// │           (32 bytes)      (32 bytes)    (16 bytes)(12 bytes) │
// │           ─────────────────────────────────────────────────  │
// │                         Total: 92 bytes                       │
// │                                                               │
// │  RECIPIENT unwrap:                                            │
// │  ─────────────────                                            │
// │  1. shared_secret = recipient_secret × ephemeral_pk          │
// │  2. wrap_key = SHA3-256("dsdn_file_key_wrap_v1" || shared)   │
// │  3. file_key = AES-GCM-Decrypt(wrap_key, encrypted_key)      │
// │                                                               │
// └───────────────────────────────────────────────────────────────┘
// ```
//
// ### Security Notes
//
// ```text
// ⚠️ CRITICAL SECURITY PROPERTIES:
//
// NONCE:
// - WAJIB 12 bytes (96-bit) per AES-GCM standard
// - WAJIB random untuk setiap enkripsi
// - TIDAK BOLEH reuse dengan key yang sama
// - Disimpan bersama ciphertext (tidak rahasia)
//
// AUTHENTICATION TAG:
// - WAJIB 16 bytes (128-bit)
// - WAJIB diverifikasi SEBELUM plaintext diterima
// - Mendeteksi tampering pada ciphertext
// - Mendeteksi wrong key
//
// CONTEXT (file_id):
// - WAJIB unique per file
// - WAJIB konsisten saat encrypt/decrypt
// - Memberikan key isolation antar file
//
// KEY WRAPPING:
// - Ephemeral keypair per wrap (forward secrecy)
// - X25519 untuk key exchange
// - AES-GCM untuk key encryption
// - Authentication tag untuk integrity
// ```
//
// ### API Reference
//
// | Method | Signature | Description |
// |--------|-----------|-------------|
// | `derive_encryption_key` | `(&self, context: &[u8]) -> [u8; 32]` | Derive key dari wallet |
// | `encrypt_file` | `(&self, plaintext: &[u8], file_id: &[u8]) -> Result<EncryptedFile>` | Encrypt file |
// | `decrypt_file` | `(&self, encrypted: &EncryptedFile, file_id: &[u8]) -> Result<Vec<u8>>` | Decrypt file |
// | `wrap_file_key` | `(&self, key: &[u8; 32], recipient: &[u8; 32]) -> Vec<u8>` | Wrap key for sharing |
// | `unwrap_file_key` | `(&self, wrapped: &[u8]) -> Result<[u8; 32]>` | Unwrap received key |
// | `x25519_public_key` | `(&self) -> [u8; 32]` | Get X25519 public key |
//
// ### Error Handling
//
// | Error | Cause |
// |-------|-------|
// | `EncryptionFailed` | AES-GCM encryption error |
// | `DecryptionFailed` | Cipher initialization error |
// | `InvalidCiphertext` | Wrong format/length |
// | `AuthenticationFailed` | Tag mismatch (tampering/wrong key) |
//
// ### Testing Checklist
//
// ```text
// Unit Tests:
// - [ ] derive_encryption_key determinism
// - [ ] derive_encryption_key context isolation
// - [ ] encrypt_file → decrypt_file roundtrip
// - [ ] decrypt with wrong file_id fails
// - [ ] decrypt tampered ciphertext fails
// - [ ] decrypt tampered tag fails
// - [ ] wrap_file_key → unwrap_file_key roundtrip
// - [ ] unwrap with wrong recipient fails
// - [ ] unwrap tampered wrapped key fails
// - [ ] empty plaintext handling
// - [ ] large file handling
// ```
//
// ════════════════════════════════════════════════════════════════════════════════
// ## Data Availability (DA) Blob Commitment Verification (13.17.6)
// ════════════════════════════════════════════════════════════════════════════════
//
// ### Overview
//
// Module ini menyediakan verifikasi kriptografis untuk Data Availability (DA).
// Memastikan blob data yang diterima sesuai dengan commitment yang dipublikasikan.
//
// ### Apa itu Blob Commitment?
//
// ```text
// Blob Commitment adalah hash deterministik dari blob data:
//
//     commitment = SHA3-256(blob_data)
//
// Properti:
// - DETERMINISTIK: Same data → same commitment
// - IRREVERSIBLE: Tidak bisa recover data dari commitment
// - COLLISION RESISTANT: Berbeda data → berbeda commitment
// ```
//
// ### Hubungan Data ↔ Commitment
//
// ```text
// ┌─────────────────────────────────────────────────────────────────┐
// │                   DATA AVAILABILITY FLOW                        │
// ├─────────────────────────────────────────────────────────────────┤
// │                                                                 │
// │  PUBLISHER                              VERIFIER                │
// │  ─────────                              ────────                │
// │                                                                 │
// │  1. blob_data (arbitrary bytes)                                 │
// │           │                                                     │
// │           ▼                                                     │
// │  2. commitment = SHA3-256(blob_data)                           │
// │           │                                                     │
// │           ▼                                                     │
// │  3. Submit to Celestia DA                                       │
// │     ├── blob_data stored at (height, index)                    │
// │     └── commitment published                                    │
// │                                                                 │
// │  ────────────────────────────────────────────────────────────  │
// │                                                                 │
// │                              4. Receive blob_data               │
// │                                        │                        │
// │                                        ▼                        │
// │                              5. Compute SHA3-256(blob_data)     │
// │                                        │                        │
// │                                        ▼                        │
// │                              6. Compare dengan expected         │
// │                                 commitment                      │
// │                                        │                        │
// │                               ┌────────┴────────┐               │
// │                               │                 │               │
// │                               ▼                 ▼               │
// │                            MATCH           MISMATCH             │
// │                         ✓ Accept           ✗ Reject             │
// │                                                                 │
// └─────────────────────────────────────────────────────────────────┘
// ```
//
// ### Peran SHA3-256
//
// ```text
// Mengapa SHA3-256:
// - Standardized (NIST FIPS 202)
// - 256-bit output = 32 bytes (ukuran commitment)
// - Collision resistant hingga 2^128 operations
// - Preimage resistant
// - Deterministic
//
// TIDAK menggunakan:
// - SHA-512 (output terlalu besar)
// - Blake2/3 (non-standard untuk Celestia)
// - Keccak256 (berbeda padding dari SHA3)
// ```
//
// ### Verifikasi Tanpa Trust ke Storage
//
// ```text
// ⚠️ TRUST MODEL:
//
// Verifier TIDAK perlu trust:
// - Storage provider (Celestia DA)
// - Network relay nodes
// - Any intermediary
//
// Verifier HANYA trust:
// - SHA3-256 algorithm (cryptographic assumption)
// - Commitment yang sudah di-publish (on-chain/DA layer)
//
// Karena:
// - Commitment tidak bisa di-forge tanpa data asli
// - Data palsu akan menghasilkan commitment berbeda
// - Verification dilakukan locally
// ```
//
// ### Peran Wallet sebagai Verifier
//
// ```text
// Wallet sebagai verifier:
//
// ┌──────────────────────────────────────────────────────────────┐
// │                     WALLET VERIFICATION                      │
// ├──────────────────────────────────────────────────────────────┤
// │                                                              │
// │  wallet.verify_da_commitment(data, commitment)               │
// │        │                                                     │
// │        ├── Compute SHA3-256(data)                           │
// │        │                                                     │
// │        ├── Compare dengan commitment.commitment              │
// │        │                                                     │
// │        └── Return true/false                                 │
// │                                                              │
// │  Keuntungan:                                                 │
// │  - Unified API untuk user                                    │
// │  - Consistent dengan wallet flow                             │
// │  - Tidak memerlukan secret key                               │
// │                                                              │
// └──────────────────────────────────────────────────────────────┘
// ```
//
// ### Batasan (BUKAN Fraud Proof)
//
// ```text
// ⚠️ BATASAN PENTING:
//
// Commitment verification BUKAN:
// - Fraud proof system
// - Validity proof
// - State transition proof
//
// Commitment verification HANYA:
// - Memverifikasi data == commitment
// - Mendeteksi data corruption/tampering
// - Memastikan data integrity
//
// Untuk fraud proof, diperlukan:
// - Merkle proof
// - State transition rules
// - Challenge-response protocol
// - Slashing mechanism
//
// Ini adalah BUILDING BLOCK untuk sistem yang lebih kompleks,
// BUKAN solusi lengkap untuk data availability problem.
// ```
//
// ### API Reference
//
// | Function/Method | Signature | Description |
// |-----------------|-----------|-------------|
// | `compute_blob_commitment` | `(blob_data: &[u8]) -> [u8; 32]` | Compute SHA3-256 hash |
// | `verify_blob_commitment` | `(blob_data: &[u8], expected: &[u8; 32]) -> bool` | Verify data matches commitment |
// | `CelestiaClient::get_blob_commitment` | `(&self, height: u64, index: u32) -> Result<BlobCommitment>` | Get commitment metadata |
// | `CelestiaClient::verify_blob_at_height` | `(&self, height: u64, index: u32, data: &[u8]) -> Result<bool>` | Verify blob at specific height |
// | `Wallet::verify_da_commitment` | `(&self, data: &[u8], commitment: &BlobCommitment) -> bool` | Wallet helper for verification |
//
// ### BlobCommitment Struct
//
// ```rust,ignore
// pub struct BlobCommitment {
//     pub commitment: [u8; 32],   // SHA3-256 hash
//     pub namespace: [u8; 29],    // Celestia namespace (v0)
//     pub height: u64,            // Celestia block height
//     pub index: u32,             // Blob index in block
// }
// ```
//
// ### Testing Checklist
//
// ```text
// Unit Tests:
// - [ ] compute_blob_commitment determinism
// - [ ] compute_blob_commitment different data → different hash
// - [ ] verify_blob_commitment true case
// - [ ] verify_blob_commitment false case (wrong data)
// - [ ] verify_blob_commitment empty data
// - [ ] BlobCommitment struct serialization
// - [ ] Wallet::verify_da_commitment wrapper
// - [ ] CelestiaClient::verify_blob_at_height flow
// ```
//
// ════════════════════════════════════════════════════════════════════════════════
// ## Storage Payment Persistence (13.17.7)
// ════════════════════════════════════════════════════════════════════════════════
//
// ### Overview
//
// Module ini menyediakan persistence layer untuk storage contracts di LMDB.
// Data storage contracts adalah consensus-critical dan mempengaruhi state_root.
//
// ### LMDB Bucket Layout
//
// ```text
// ┌────────────────────────────────────────────────────────────────────────────┐
// │                    STORAGE PAYMENT LMDB BUCKETS                            │
// ├────────────────────────────────────────────────────────────────────────────┤
// │                                                                            │
// │  Bucket: storage_contracts                                                 │
// │  ───────────────────────                                                   │
// │  Key:   contract_id (Hash, 64 bytes)                                       │
// │  Value: bincode serialized StorageContract                                 │
// │                                                                            │
// │  Purpose: Store individual storage contracts                               │
// │  Lookup:  O(1) by contract_id                                             │
// │                                                                            │
// │  ────────────────────────────────────────────────────────────────────────  │
// │                                                                            │
// │  Bucket: user_contracts                                                    │
// │  ──────────────────────                                                    │
// │  Key:   user_address (20 bytes)                                           │
// │  Value: bincode serialized Vec<Hash> (list of contract_ids)               │
// │                                                                            │
// │  Purpose: Index contracts by owner address                                │
// │  Lookup:  O(1) by address → list of contract_ids                          │
// │                                                                            │
// └────────────────────────────────────────────────────────────────────────────┘
// ```
//
// ### Key/Value Mapping
//
// | Bucket | Key Format | Value Format |
// |--------|------------|--------------|
// | `storage_contracts` | `contract_id.as_bytes()` (64 bytes) | `bincode(StorageContract)` |
// | `user_contracts` | `address.as_bytes()` (20 bytes) | `bincode(Vec<Hash>)` |
//
// ### Relasi storage_contracts vs user_contracts
//
// ```text
// ┌──────────────────────────────────────────────────────────────────────────┐
// │                     DATA RELATIONSHIP                                    │
// ├──────────────────────────────────────────────────────────────────────────┤
// │                                                                          │
// │  user_contracts[address] → Vec<contract_id>                              │
// │           │                                                              │
// │           ├── contract_id_1 ──→ storage_contracts[contract_id_1]        │
// │           │                              └── StorageContract { ... }     │
// │           │                                                              │
// │           ├── contract_id_2 ──→ storage_contracts[contract_id_2]        │
// │           │                              └── StorageContract { ... }     │
// │           │                                                              │
// │           └── contract_id_N ──→ storage_contracts[contract_id_N]        │
// │                                          └── StorageContract { ... }     │
// │                                                                          │
// │  Invariant:                                                              │
// │  - Setiap contract_id di user_contracts HARUS ada di storage_contracts  │
// │  - StorageContract.owner == address dari user_contracts entry           │
// │                                                                          │
// └──────────────────────────────────────────────────────────────────────────┘
// ```
//
// ### State Root Integration (Position #35)
//
// ```text
// ┌──────────────────────────────────────────────────────────────────────────┐
// │                  STATE ROOT ORDERING                                     │
// ├──────────────────────────────────────────────────────────────────────────┤
// │                                                                          │
// │  ... (positions #1-#30)                                                  │
// │  #31 — deflation_config                                                  │
// │  #32 — economic_metrics                                                  │
// │  #33 — last_burn_epoch                                                   │
// │  #34 — cumulative_burned                                                 │
// │  #35 — storage_contracts  ← NEW (13.17.7)                               │
// │                                                                          │
// │  Hash format untuk #35:                                                  │
// │  - Sort by contract_id ASC                                              │
// │  - For each: [contract_id (64 bytes)] + [bincode(StorageContract)]      │
// │                                                                          │
// └──────────────────────────────────────────────────────────────────────────┘
// ```
//
// ### Mengapa Ini Consensus-Critical
//
// ```text
// ⚠️ CONSENSUS-CRITICAL PROPERTIES:
//
// 1. State Root Dependency
//    - storage_contracts masuk ke state_root computation
//    - Perubahan contract → perubahan state_root
//    - Semua node HARUS memiliki storage_contracts identik
//
// 2. Deterministic Ordering
//    - Sort by contract_id ASC wajib
//    - Ordering berbeda = state_root berbeda = fork
//
// 3. Serialization Format
//    - bincode format TIDAK BOLEH berubah
//    - Perubahan format = state_root berbeda = hard fork required
//
// 4. Restart Safety
//    - Data HARUS survive restart
//    - export → restart → load → state identik
//
// PELANGGARAN MENGAKIBATKAN:
// - Node tidak bisa sync
// - State root mismatch antar validator
// - Chain fork permanent
// ```
//
// ### API Reference
//
// | Method | Signature | Description |
// |--------|-----------|-------------|
// | `ChainDb::put_storage_contract` | `(&self, contract_id: &Hash, contract: &StorageContract) -> Result<()>` | Store contract |
// | `ChainDb::get_storage_contract` | `(&self, contract_id: &Hash) -> Result<Option<StorageContract>>` | Get contract |
// | `ChainDb::delete_storage_contract` | `(&self, contract_id: &Hash) -> Result<()>` | Delete contract |
// | `ChainDb::get_user_contracts` | `(&self, address: &Address) -> Vec<Hash>` | Get user's contracts |
// | `ChainDb::load_all_storage_contracts` | `(&self) -> Result<HashMap<Hash, StorageContract>>` | Load all contracts |
// | `ChainState::export_storage_contracts_to_layout` | `(&self, db: &ChainDb) -> Result<()>` | Export to LMDB |
// | `ChainState::load_storage_contracts_from_layout` | `(&mut self, db: &ChainDb) -> Result<()>` | Load from LMDB |
//
// ### Testing Checklist
//
// ```text
// Unit Tests:
// - [ ] put_storage_contract → get_storage_contract roundtrip
// - [ ] delete_storage_contract success
// - [ ] get_storage_contract returns None for missing
// - [ ] put_user_contracts → get_user_contracts roundtrip
// - [ ] load_all_storage_contracts returns all contracts
// - [ ] export → load → state identik
// - [ ] state_root deterministic dengan storage_contracts
// - [ ] state_root berbeda dengan contract berbeda
// ```
//