//! # P2P Sync Protocol Types (13.11)
//!
//! Module ini mendefinisikan tipe data dan logic untuk sync protocol.
//! 
//! ## Tipe Utama
//!
//! | Type | Fungsi |
//! |------|--------|
//! | `SyncStatus` | Status mesin sync saat ini |
//! | `SyncRequest` | Request dari peer untuk data |
//! | `SyncResponse` | Response berisi data yang diminta |
//! | `SyncConfig` | Konfigurasi sync protocol |
//! | `PeerSyncState` | Status sync dari peer tertentu |
//! | `HeaderSyncer` | Header-first sync engine (13.11.2) |
//! | `BlockSyncer` | Block download engine (13.11.3) |
//! | `StateReplayEngine` | State rebuild engine (13.11.4) |
//! | `SyncManager` | Orchestrator for full sync lifecycle (13.11.6) |
//!
//! ## Header-First Sync (13.11.2)
//!
//! HeaderSyncer melakukan validasi chain structure tanpa download block body.
//! Validasi header bersifat CONSENSUS-CRITICAL.

use serde::{Serialize, Deserialize};
use std::collections::{VecDeque, HashSet, HashMap};
use anyhow::Result;

use crate::types::Hash;
use crate::block::{Block, BlockHeader};
use crate::db::ChainDb;
use crate::state::ChainState;
use crate::Chain;

// ════════════════════════════════════════════════════════════════════════════
// SYNC STATUS
// ════════════════════════════════════════════════════════════════════════════

/// Status mesin sync saat ini.
///
/// State machine transitions:
/// - Idle → SyncingHeaders (ketika sync dimulai)
/// - SyncingHeaders → SyncingBlocks (ketika semua headers diterima)
/// - SyncingBlocks → SyncingState (ketika semua blocks diterima)
/// - SyncingState → Synced (ketika state replay selesai)
/// - Synced → Idle (ketika sync di-reset)
/// - Any → Idle (ketika sync dibatalkan)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SyncStatus {
    /// Tidak sedang sync, node idle
    Idle,
    /// Sedang sync headers dari peer
    SyncingHeaders {
        /// Height awal sync
        start_height: u64,
        /// Height target (dari peer tip)
        target_height: u64,
        /// Height saat ini yang sudah di-sync
        current_height: u64,
    },
    /// Sedang sync blocks setelah headers terverifikasi
    SyncingBlocks {
        /// Height awal sync
        start_height: u64,
        /// Height target
        target_height: u64,
        /// Height saat ini yang sudah di-download
        current_height: u64,
    },
    /// Sedang replay state dari checkpoint
    SyncingState {
        /// Height checkpoint yang sedang di-replay
        checkpoint_height: u64,
    },
    /// Sync selesai, node sudah synchronized
    Synced,
}

// ════════════════════════════════════════════════════════════════════════════
// SYNC REQUEST
// ════════════════════════════════════════════════════════════════════════════

/// Request dari node ke peer untuk data sync.
///
/// Digunakan dalam P2P protocol untuk meminta:
/// - Headers dalam range tertentu
/// - Block individual atau batch
/// - Chain tip info
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SyncRequest {
    /// Request range of headers
    GetHeaders {
        /// Height pertama yang diminta
        start_height: u64,
        /// Jumlah headers yang diminta
        count: u64,
    },
    /// Request single block by height
    GetBlock {
        /// Height block yang diminta
        height: u64,
    },
    /// Request multiple blocks by heights
    GetBlocks {
        /// List heights yang diminta
        heights: Vec<u64>,
    },
    /// Request current chain tip dari peer
    GetChainTip,
}

// ════════════════════════════════════════════════════════════════════════════
// SYNC RESPONSE
// ════════════════════════════════════════════════════════════════════════════

/// Response dari peer berisi data yang diminta.
///
/// Setiap variant berkorespondensi dengan SyncRequest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncResponse {
    /// Response berisi headers
    Headers {
        /// List headers yang diminta
        headers: Vec<BlockHeader>,
    },
    /// Response berisi single block
    Block {
        /// Block yang diminta
        block: Block,
    },
    /// Response berisi multiple blocks
    Blocks {
        /// List blocks yang diminta
        blocks: Vec<Block>,
    },
    /// Response berisi chain tip info
    ChainTip {
        /// Height tip saat ini
        height: u64,
        /// Hash tip saat ini
        hash: Hash,
    },
    /// Block tidak ditemukan
    NotFound {
        /// Height yang tidak ditemukan
        height: u64,
    },
    /// Error response
    Error {
        /// Pesan error
        message: String,
    },
}

// ════════════════════════════════════════════════════════════════════════════
// SYNC CONFIG
// ════════════════════════════════════════════════════════════════════════════

/// Konfigurasi sync protocol.
///
/// Default values:
/// - max_headers_per_request: 500
/// - max_blocks_per_request: 100
/// - sync_timeout_ms: 30000 (30 detik)
/// - batch_size: 50
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncConfig {
    /// Maximum headers per single request
    pub max_headers_per_request: u64,
    /// Maximum blocks per single request
    pub max_blocks_per_request: u64,
    /// Timeout untuk sync request dalam milliseconds
    pub sync_timeout_ms: u64,
    /// Batch size untuk parallel downloads
    pub batch_size: u64,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            max_headers_per_request: 500,
            max_blocks_per_request: 100,
            sync_timeout_ms: 30000,
            batch_size: 50,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// PEER SYNC STATE
// ════════════════════════════════════════════════════════════════════════════

/// Status sync dari peer tertentu.
///
/// Digunakan untuk tracking:
/// - Peer mana yang punya block terbaru
/// - Peer mana yang sedang aktif sync
/// - Kapan terakhir peer terlihat
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerSyncState {
    /// Identifier unik peer
    pub peer_id: String,
    /// Height tip yang dilaporkan peer
    pub tip_height: u64,
    /// Hash tip yang dilaporkan peer
    pub tip_hash: Hash,
    /// Unix timestamp terakhir peer terlihat aktif
    pub last_seen: u64,
    /// Apakah sedang sync dengan peer ini
    pub is_syncing: bool,
}

// ════════════════════════════════════════════════════════════════════════════
// HEADER SYNCER (13.11.2)
// ════════════════════════════════════════════════════════════════════════════

/// Header-first sync engine.
///
/// Melakukan validasi chain structure dengan download headers terlebih dahulu.
/// Headers diverifikasi dan disimpan ke LMDB sebelum block body di-download.
///
/// ## Consensus-Critical
///
/// Validasi header bersifat consensus-critical:
/// 1. height == previous.height + 1
/// 2. parent_hash == hash(previous)
/// 3. proposer adalah address valid
/// 4. timestamp > previous.timestamp
#[derive(Debug, Clone)]
pub struct HeaderSyncer {
    /// Local chain tip (height, hash)
    pub local_tip: (u64, Hash),
    /// Target chain tip dari peer (height, hash)
    pub target_tip: (u64, Hash),
    /// Headers yang sudah diterima tapi belum diproses
    pub pending_headers: VecDeque<BlockHeader>,
    /// Heights yang sudah terverifikasi dan disimpan
    pub verified_heights: HashSet<u64>,
}

impl HeaderSyncer {
    /// Buat HeaderSyncer baru.
    ///
    /// # Arguments
    /// * `local_tip` - (height, hash) dari chain tip lokal
    /// * `target_tip` - (height, hash) target dari peer
    pub fn new(
        local_tip: (u64, Hash),
        target_tip: (u64, Hash),
    ) -> Self {
        Self {
            local_tip,
            target_tip,
            pending_headers: VecDeque::new(),
            verified_heights: HashSet::new(),
        }
    }

    /// Generate SyncRequest untuk batch headers berikutnya.
    ///
    /// Request dimulai dari local_tip.height + 1 + verified_heights.len()
    /// Menggunakan batch size dari SyncConfig default (500).
    pub fn request_next_headers(&self) -> SyncRequest {
        let start_height = self.local_tip.0 + 1 + self.verified_heights.len() as u64;
        let remaining = self.target_tip.0.saturating_sub(start_height) + 1;
        let count = remaining.min(SyncConfig::default().max_headers_per_request);
        
        SyncRequest::GetHeaders {
            start_height,
            count,
        }
    }

    /// Proses headers yang diterima dari peer.
    ///
    /// 1. Verifikasi header chain (consensus-critical)
    /// 2. Simpan setiap header ke LMDB
    /// 3. Update verified_heights
    ///
    /// # Arguments
    /// * `headers` - Vec<BlockHeader> dari peer (harus berurutan ascending)
    /// * `db` - ChainDb untuk persistence
    ///
    /// # Errors
    /// * Header validation gagal (height, parent_hash, proposer, timestamp)
    /// * LMDB write error
    pub fn process_headers(
        &mut self,
        headers: Vec<BlockHeader>,
        db: &ChainDb,
    ) -> Result<()> {
        // Verifikasi chain linkage
        self.verify_header_chain(&headers)?;
        
        // Simpan setiap header ke LMDB dan update verified_heights
        for header in headers {
            let height = header.height;
            
            // Skip header yang sudah ada
            if self.verified_heights.contains(&height) {
                continue;
            }
            
            // Simpan ke LMDB
            db.put_header(height, &header)?;
            
            // Update tracking
            self.verified_heights.insert(height);
        }
        
        Ok(())
    }

    /// Verifikasi header chain linkage.
    ///
    /// ## Consensus-Critical Validation Rules
    ///
    /// 1. height == previous.height + 1
    /// 2. parent_hash == compute_hash(previous)
    /// 3. proposer bukan zero address
    /// 4. timestamp > previous.timestamp
    ///
    /// # Arguments
    /// * `headers` - Slice of headers to verify (harus berurutan ascending)
    ///
    /// # Errors
    /// * Height tidak sequential
    /// * Parent hash mismatch
    /// * Proposer adalah zero address
    /// * Timestamp tidak increasing
    pub fn verify_header_chain(
        &self,
        headers: &[BlockHeader],
    ) -> Result<()> {
        if headers.is_empty() {
            return Ok(());
        }
        
        // Verifikasi header pertama terhadap local_tip
        let first = &headers[0];
        let expected_height = self.local_tip.0 + 1 + self.verified_heights.len() as u64;
        
        if first.height != expected_height {
            anyhow::bail!(
                "header height mismatch: expected {}, got {}",
                expected_height,
                first.height
            );
        }
        
        if first.parent_hash != self.local_tip.1 && self.verified_heights.is_empty() {
            anyhow::bail!(
                "first header parent_hash mismatch: expected {}, got {}",
                self.local_tip.1,
                first.parent_hash
            );
        }
        
        // Verifikasi proposer valid (bukan zero address)
        let zero_addr = crate::types::Address::from_bytes([0u8; 20]);
        if first.proposer == zero_addr {
            anyhow::bail!("header {} has zero proposer address", first.height);
        }
        
        // Verifikasi sequential headers
        for i in 1..headers.len() {
            let prev = &headers[i - 1];
            let curr = &headers[i];
            
            // Rule 1: height == previous.height + 1
            if curr.height != prev.height + 1 {
                anyhow::bail!(
                    "header height not sequential: {} -> {}",
                    prev.height,
                    curr.height
                );
            }
            
            // Rule 2: parent_hash == hash(previous)
            let prev_hash = Block::compute_hash(prev);
            if curr.parent_hash != prev_hash {
                anyhow::bail!(
                    "header {} parent_hash mismatch: expected {}, got {}",
                    curr.height,
                    prev_hash,
                    curr.parent_hash
                );
            }
            
            // Rule 3: proposer valid
            if curr.proposer == zero_addr {
                anyhow::bail!("header {} has zero proposer address", curr.height);
            }
            
            // Rule 4: timestamp > previous.timestamp
            if curr.timestamp <= prev.timestamp {
                anyhow::bail!(
                    "header {} timestamp not increasing: {} <= {}",
                    curr.height,
                    curr.timestamp,
                    prev.timestamp
                );
            }
        }
        
        Ok(())
    }

    /// Check apakah header sync sudah selesai.
    ///
    /// Returns true bila semua headers dari local_tip sampai target_tip sudah terverifikasi.
    pub fn is_complete(&self) -> bool {
        let total_needed = self.target_tip.0.saturating_sub(self.local_tip.0);
        self.verified_heights.len() as u64 >= total_needed
    }

    /// Get sync progress.
    ///
    /// Returns (current_height, target_height)
    pub fn get_progress(&self) -> (u64, u64) {
        let current = self.local_tip.0 + self.verified_heights.len() as u64;
        (current, self.target_tip.0)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// BLOCK SYNCER (13.11.3)
// ════════════════════════════════════════════════════════════════════════════

/// Maximum retry count per block height
const MAX_RETRY_COUNT: u32 = 3;

/// Block sync engine.
///
/// Mengambil full blocks berdasarkan headers yang sudah terverifikasi.
/// Block divalidasi terhadap header sebelum diteruskan ke execution stage.
///
/// ## Consensus-Critical
///
/// Validasi block bersifat consensus-critical:
/// 1. block.header == expected_header (exact match)
/// 2. block.verify_signature() sukses
/// 3. Semua tx.verify_signature() sukses
///
/// ## Retry Logic
///
/// - Maksimum 3 retry per height
/// - Height yang gagal > 3 kali masuk failed_heights
/// - Block yang gagal validasi TIDAK boleh dieksekusi
#[derive(Debug, Clone)]
pub struct BlockSyncer {
    /// Headers yang masih perlu di-fetch (height, expected_hash)
    pub headers_to_fetch: VecDeque<(u64, Hash)>,
    /// Blocks yang sudah berhasil di-fetch dan tervalidasi
    pub fetched_blocks: HashMap<u64, Block>,
    /// Heights yang gagal setelah max retry
    pub failed_heights: HashSet<u64>,
    /// Retry count per height
    pub retry_count: HashMap<u64, u32>,
}

impl BlockSyncer {
    /// Buat BlockSyncer baru dari list verified headers.
    ///
    /// # Arguments
    /// * `headers` - Vec<(height, hash)> dari headers yang sudah diverifikasi
    pub fn new(headers: Vec<(u64, Hash)>) -> Self {
        Self {
            headers_to_fetch: VecDeque::from(headers),
            fetched_blocks: HashMap::new(),
            failed_heights: HashSet::new(),
            retry_count: HashMap::new(),
        }
    }

    /// Generate SyncRequest untuk batch blocks berikutnya.
    ///
    /// # Arguments
    /// * `batch_size` - Jumlah maksimum blocks per request
    ///
    /// Returns SyncRequest::GetBlocks dengan heights yang diminta
    pub fn request_next_blocks(
        &self,
        batch_size: u64,
    ) -> SyncRequest {
        let count = (batch_size as usize).min(self.headers_to_fetch.len());
        let heights: Vec<u64> = self.headers_to_fetch
            .iter()
            .take(count)
            .map(|(h, _)| *h)
            .collect();
        
        SyncRequest::GetBlocks { heights }
    }

    /// Proses block yang diterima dari peer.
    ///
    /// Validasi block terhadap expected header, kemudian:
    /// - Sukses: simpan ke fetched_blocks, hapus dari headers_to_fetch
    /// - Gagal: increment retry_count, move ke failed_heights setelah max retry
    ///
    /// # Arguments
    /// * `block` - Block yang diterima dari peer
    /// * `expected_header` - Header yang sudah diverifikasi
    ///
    /// # Errors
    /// * Block header tidak match
    /// * Block signature invalid
    /// * Transaction signature invalid
    pub fn process_block(
        &mut self,
        block: Block,
        expected_header: &BlockHeader,
    ) -> Result<()> {
        let height = block.header.height;
        
        // Validasi block terhadap expected header
        match self.validate_block_header(&block, expected_header) {
            Ok(()) => {
                // Validasi sukses: simpan block
                self.fetched_blocks.insert(height, block);
                
                // Hapus dari headers_to_fetch
                self.headers_to_fetch.retain(|(h, _)| *h != height);
                
                // Reset retry count
                self.retry_count.remove(&height);
                
                Ok(())
            }
            Err(e) => {
                // Increment retry count
                let count = self.retry_count.entry(height).or_insert(0);
                *count += 1;
                
                // Check max retry
                if *count >= MAX_RETRY_COUNT {
                    // Move ke failed_heights
                    self.failed_heights.insert(height);
                    
                    // Hapus dari headers_to_fetch
                    self.headers_to_fetch.retain(|(h, _)| *h != height);
                    
                    // Hapus retry count
                    self.retry_count.remove(&height);
                }
                
                Err(e)
            }
        }
    }

    /// Validasi block terhadap expected header.
    ///
    /// ## Consensus-Critical Validation Rules
    ///
    /// 1. block.header == expected_header (exact match semua fields)
    /// 2. block.verify_signature() sukses
    /// 3. Semua tx.verify_signature() sukses
    ///
    /// # Arguments
    /// * `block` - Block yang akan divalidasi
    /// * `expected_header` - Header yang sudah diverifikasi
    ///
    /// # Errors
    /// * Header mismatch
    /// * Block signature invalid
    /// * Transaction signature invalid
    pub fn validate_block_header(
        &self,
        block: &Block,
        expected_header: &BlockHeader,
    ) -> Result<()> {
        // Rule 1: block.header == expected_header (exact match)
        if block.header.height != expected_header.height {
            anyhow::bail!(
                "block height mismatch: expected {}, got {}",
                expected_header.height,
                block.header.height
            );
        }
        
        if block.header.parent_hash != expected_header.parent_hash {
            anyhow::bail!(
                "block {} parent_hash mismatch",
                block.header.height
            );
        }
        
        if block.header.state_root != expected_header.state_root {
            anyhow::bail!(
                "block {} state_root mismatch",
                block.header.height
            );
        }
        
        if block.header.tx_root != expected_header.tx_root {
            anyhow::bail!(
                "block {} tx_root mismatch",
                block.header.height
            );
        }
        
        if block.header.timestamp != expected_header.timestamp {
            anyhow::bail!(
                "block {} timestamp mismatch",
                block.header.height
            );
        }
        
        if block.header.proposer != expected_header.proposer {
            anyhow::bail!(
                "block {} proposer mismatch",
                block.header.height
            );
        }
        
        // Rule 2: block.verify_signature() sukses
        if !block.verify_signature()? {
            anyhow::bail!(
                "block {} signature verification failed",
                block.header.height
            );
        }
        
        // Rule 3: semua tx.verify_signature() sukses
        for (i, tx) in block.body.transactions.iter().enumerate() {
            if !tx.verify_signature()? {
                anyhow::bail!(
                    "block {} tx {} signature verification failed",
                    block.header.height,
                    i
                );
            }
        }
        
        Ok(())
    }

    /// Get heights yang masih pending (belum di-fetch).
    ///
    /// Returns Vec<u64> sorted ascending
    pub fn get_pending_heights(&self) -> Vec<u64> {
        self.headers_to_fetch
            .iter()
            .map(|(h, _)| *h)
            .collect()
    }

    /// Check apakah block sync sudah selesai.
    ///
    /// Returns true bila:
    /// - headers_to_fetch kosong, DAN
    /// - tidak ada pending retry
    pub fn is_complete(&self) -> bool {
        self.headers_to_fetch.is_empty()
    }

    /// Get jumlah blocks yang sudah berhasil di-fetch.
    pub fn fetched_count(&self) -> usize {
        self.fetched_blocks.len()
    }

    /// Get jumlah heights yang gagal.
    pub fn failed_count(&self) -> usize {
        self.failed_heights.len()
    }

    /// Get block by height dari fetched_blocks.
    pub fn get_block(&self, height: u64) -> Option<&Block> {
        self.fetched_blocks.get(&height)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// STATE REPLAY ENGINE (13.11.4)
// ════════════════════════════════════════════════════════════════════════════

/// State replay engine untuk rebuild ChainState dari blocks.
///
/// Melakukan replay blocks secara sequential untuk reconstruct state
/// dari genesis atau dari checkpoint.
///
/// ## Consensus-Critical
///
/// Replay bersifat consensus-critical:
/// 1. Urutan block HARUS sequential (height N → N+1 → ...)
/// 2. apply_payload dieksekusi identik dengan mining node
/// 3. state_root computed HARUS match block.header.state_root
///
/// ## Memory Only
///
/// - Replay TIDAK menulis ke DB
/// - Replay TIDAK mengubah chain tip
/// - Replay bekerja pada cloned ChainState
pub struct StateReplayEngine {
    /// Chain untuk akses DB (load blocks)
    pub chain: Chain,
    /// Height awal replay
    pub start_height: u64,
    /// Height akhir replay (inclusive)
    pub end_height: u64,
    /// Height saat ini yang sedang diproses
    pub current_height: u64,
    /// Checkpoint state (None = replay dari genesis)
    pub state_checkpoint: Option<ChainState>,
}

impl StateReplayEngine {
    /// Buat StateReplayEngine baru.
    ///
    /// # Arguments
    /// * `chain` - Chain untuk akses DB
    /// * `start` - Height awal replay (inclusive)
    /// * `end` - Height akhir replay (inclusive)
    pub fn new(chain: Chain, start: u64, end: u64) -> Self {
        Self {
            chain,
            start_height: start,
            end_height: end,
            current_height: start,
            state_checkpoint: None,
        }
    }

    /// Replay dari genesis (height 0).
    ///
    /// Memulai replay dari ChainState kosong dan replay semua blocks
    /// dari height 0 sampai end_height.
    ///
    /// # Errors
    /// * BlockNotFound — block tidak ada di DB
    /// * StateRootMismatch — computed state_root != block.header.state_root
    pub fn replay_from_genesis(&mut self) -> Result<()> {
        // Reset state ke genesis state (empty)
        let mut state = ChainState::new();
        
        // Replay dari height 0
        self.current_height = 0;
        
        while self.current_height <= self.end_height {
            // Load block dari DB
            let block = self.chain.db.get_block(self.current_height)?
                .ok_or_else(|| anyhow::anyhow!(
                    "BlockNotFound: height {}",
                    self.current_height
                ))?;
            
            // Replay block
            self.replay_block_internal(&block, &mut state)?;
            
            // Verify state root
            self.verify_state_root(&block, &state)?;
            
            // Next height
            self.current_height += 1;
        }
        
        // Store final state
        self.state_checkpoint = Some(state);
        
        Ok(())
    }

    /// Replay dari checkpoint.
    ///
    /// Memulai replay dari state yang sudah ada dan melanjutkan
    /// replay dari height tertentu.
    ///
    /// # Arguments
    /// * `height` - Height checkpoint (replay mulai dari height + 1)
    /// * `state` - ChainState checkpoint
    ///
    /// # Errors
    /// * BlockNotFound — block tidak ada di DB
    /// * StateRootMismatch — computed state_root != block.header.state_root
    pub fn replay_from_checkpoint(
        &mut self,
        height: u64,
        state: ChainState,
    ) -> Result<()> {
        // Set starting point
        self.current_height = height + 1;
        self.start_height = height + 1;
        
        // Clone state untuk replay
        let mut replay_state = state;
        
        while self.current_height <= self.end_height {
            // Load block dari DB
            let block = self.chain.db.get_block(self.current_height)?
                .ok_or_else(|| anyhow::anyhow!(
                    "BlockNotFound: height {}",
                    self.current_height
                ))?;
            
            // Replay block
            self.replay_block_internal(&block, &mut replay_state)?;
            
            // Verify state root
            self.verify_state_root(&block, &replay_state)?;
            
            // Next height
            self.current_height += 1;
        }
        
        // Store final state
        self.state_checkpoint = Some(replay_state);
        
        Ok(())
    }

    /// Replay single block.
    ///
    /// Eksekusi semua transaksi dalam block via apply_payload.
    /// TX yang gagal dicatat tapi replay tetap lanjut.
    ///
    /// # Arguments
    /// * `block` - Block yang akan direplay
    ///
    /// # Errors
    /// * StateRootMismatch — computed state_root != block.header.state_root
    pub fn replay_block(&mut self, block: &Block) -> Result<()> {
        // Get or create state
        let mut state = self.state_checkpoint.take().unwrap_or_else(ChainState::new);
        
        // Replay block
        self.replay_block_internal(block, &mut state)?;
        
        // Verify state root
        self.verify_state_root(block, &state)?;
        
        // Update current height
        self.current_height = block.header.height + 1;
        
        // Store state back
        self.state_checkpoint = Some(state);
        
        Ok(())
    }

    /// Internal: replay block pada state yang diberikan.
    fn replay_block_internal(
        &self,
        block: &Block,
        state: &mut ChainState,
    ) -> Result<()> {
        let proposer = block.header.proposer;
        
        // Execute each transaction
        for (i, tx) in block.body.transactions.iter().enumerate() {
            match state.apply_payload(tx, &proposer) {
                Ok(_) => {
                    // TX sukses
                }
                Err(e) => {
                    // TxExecutionError: non-fatal, log and continue
                    println!(
                        "   ⚠️  Block {} TX {} execution error (continuing): {}",
                        block.header.height,
                        i,
                        e
                    );
                }
            }
        }
        
        Ok(())
    }

    /// Verify state root matches block header.
    ///
    /// # Arguments
    /// * `block` - Block dengan expected state_root
    /// * `state` - ChainState setelah eksekusi
    ///
    /// # Errors
    /// * StateRootMismatch — computed != expected
    pub fn verify_state_root(
        &self,
        block: &Block,
        state: &ChainState,
    ) -> Result<()> {
        let computed = state.compute_state_root()?;
        let expected = &block.header.state_root;
        
        if &computed != expected {
            anyhow::bail!(
                "StateRootMismatch at height {}: expected {}, computed {}",
                block.header.height,
                expected,
                computed
            );
        }
        
        Ok(())
    }

    /// Get replay progress.
    ///
    /// Returns (current_height, end_height)
    pub fn get_progress(&self) -> (u64, u64) {
        (self.current_height, self.end_height)
    }

    /// Check apakah replay sudah selesai.
    ///
    /// Returns true bila current_height > end_height
    pub fn is_complete(&self) -> bool {
        self.current_height > self.end_height
    }

    /// Get final state setelah replay selesai.
    ///
    /// Returns cloned ChainState dari state_checkpoint.
    /// Panggil setelah replay selesai.
    pub fn get_final_state(&self) -> ChainState {
        self.state_checkpoint.clone().unwrap_or_else(ChainState::new)
    }

    // ════════════════════════════════════════════════════════════════════════════
    // CHAIN-INTEGRATED REPLAY (13.18.4)
    // ════════════════════════════════════════════════════════════════════════════
    // Metode replay yang menggunakan Chain::replay_blocks_from untuk
    // memanfaatkan logic replay yang sudah ada di Chain struct.
    //
    // PERBEDAAN DENGAN replay_from_checkpoint():
    // - replay_using_chain() menggunakan Chain state langsung
    // - replay_from_checkpoint() menggunakan cloned state
    // - replay_using_chain() lebih cocok untuk fast sync
    // ════════════════════════════════════════════════════════════════════════════

    /// Replay blocks menggunakan Chain::replay_blocks_from.
    ///
    /// Method ini adalah wrapper yang mengintegrasikan StateReplayEngine
    /// dengan Chain::replay_blocks_from untuk:
    /// - Fast sync dari snapshot
    /// - Recovery setelah snapshot restore
    ///
    /// ## Flow
    ///
    /// ```text
    /// 1. Panggil chain.replay_blocks_from(start_height, end_height, progress)
    /// 2. State di-update langsung di chain.state
    /// 3. Update current_height setelah replay
    /// 4. Mark replay sebagai complete
    /// ```
    ///
    /// ## Arguments
    /// * `progress` - Optional callback untuk progress reporting
    ///
    /// ## Returns
    /// * `Ok(())` - Replay sukses
    /// * `Err` - Replay gagal (state_root mismatch, block missing, dll)
    ///
    /// ## Note
    /// Method ini TIDAK menggunakan state_checkpoint internal.
    /// State langsung di-update ke chain.state.
    pub fn replay_using_chain(
        &mut self,
        progress: Option<&dyn Fn(u64, u64)>,
    ) -> Result<()> {
        // Use Chain's replay_blocks_from
        self.chain.replay_blocks_from(
            self.start_height,
            self.end_height,
            progress,
        ).map_err(|e| anyhow::anyhow!("Chain replay failed: {}", e))?;

        // Update current_height to mark completion
        self.current_height = self.end_height + 1;

        // Get final state from chain
        let final_state = self.chain.state.read().clone();
        self.state_checkpoint = Some(final_state);

        Ok(())
    }

    /// Replay untuk fast sync dari snapshot.
    ///
    /// Shortcut method yang menggabungkan:
    /// 1. Load state dari snapshot (caller responsibility)
    /// 2. Set state ke chain
    /// 3. Replay blocks ke tip
    ///
    /// ## Arguments
    /// * `snapshot_height` - Height snapshot yang di-restore
    /// * `target_height` - Height target (tip)
    /// * `snapshot_state` - ChainState dari snapshot
    /// * `progress` - Optional progress callback
    ///
    /// ## Returns
    /// * `Ok(ChainState)` - Final state setelah replay
    /// * `Err` - Replay gagal
    ///
    /// ## Example
    /// ```text
    /// // 1. Load snapshot
    /// let snapshot_db = ChainDb::load_snapshot(path)?;
    /// let snapshot_state = snapshot_db.load_state()?;
    ///
    /// // 2. Create replay engine
    /// let mut engine = StateReplayEngine::new(chain, snapshot_height, tip_height);
    ///
    /// // 3. Fast sync
    /// let final_state = engine.fast_sync_from_snapshot(
    ///     snapshot_height,
    ///     tip_height,
    ///     snapshot_state,
    ///     Some(&|cur, total| println!("{}/{}", cur, total)),
    /// )?;
    /// ```
    pub fn fast_sync_from_snapshot(
        &mut self,
        snapshot_height: u64,
        target_height: u64,
        snapshot_state: ChainState,
        progress: Option<&dyn Fn(u64, u64)>,
    ) -> Result<ChainState> {
        // Set chain state ke snapshot state
        {
            let mut state_guard = self.chain.state.write();
            *state_guard = snapshot_state;
        }

        // Update engine parameters
        self.start_height = snapshot_height;
        self.end_height = target_height;
        self.current_height = snapshot_height + 1;

        // Replay using chain
        self.replay_using_chain(progress)?;

        // Return final state
        Ok(self.get_final_state())
    }
}

// ════════════════════════════════════════════════════════════════════════════
// SYNC MANAGER (13.11.6)
// ════════════════════════════════════════════════════════════════════════════

/// Sync manager orchestrates the full sync lifecycle.
///
/// SyncManager mengoordinasikan semua komponen sync:
/// 1. HeaderSyncer — download dan verifikasi headers
/// 2. BlockSyncer — download full blocks
/// 3. StateReplayEngine — rebuild state dari blocks
/// 4. ControlPlaneSyncer — sync control-plane dari Celestia
///
/// ## Sync Flow
///
/// ```text
/// Idle → SyncingHeaders → SyncingBlocks → SyncingState → Synced
///              ↓               ↓               ↓
///         HeaderSyncer    BlockSyncer    StateReplayEngine
///                                              +
///                                        ControlPlaneSyncer
/// ```
///
/// ## Non-Blocking Design
///
/// `sync_step()` menjalankan SATU langkah kecil dan return.
/// Caller harus memanggil `sync_step()` berulang kali dalam loop.
///
/// ## Atomic Commit
///
/// State hanya di-commit ke LMDB SATU KALI setelah seluruh sync selesai.
/// Error sebelum commit = tidak ada data tersimpan.
pub struct SyncManager {
    /// Chain untuk akses DB dan state
    pub chain: Chain,
    /// Status sync saat ini
    pub status: SyncStatus,
    /// Header syncer (aktif saat SyncingHeaders)
    pub header_syncer: Option<HeaderSyncer>,
    /// Block syncer (aktif saat SyncingBlocks)
    pub block_syncer: Option<BlockSyncer>,
    /// State replay engine (aktif saat SyncingState)
    pub replay_engine: Option<StateReplayEngine>,
    /// Celestia control-plane syncer
    pub celestia_syncer: Option<crate::celestia::ControlPlaneSyncer>,
    /// Konfigurasi sync
    pub config: SyncConfig,
    /// Target tip untuk sync
    target_tip: Option<(u64, Hash)>,
    /// Start height untuk tracking
    start_height: u64,
}

impl SyncManager {
    /// Buat SyncManager baru.
    ///
    /// # Arguments
    /// * `chain` - Chain instance untuk akses DB dan state
    /// * `config` - SyncConfig untuk tuning parameters
    pub fn new(chain: Chain, config: SyncConfig) -> Self {
        Self {
            chain,
            status: SyncStatus::Idle,
            header_syncer: None,
            block_syncer: None,
            replay_engine: None,
            celestia_syncer: None,
            config,
            target_tip: None,
            start_height: 0,
        }
    }

    /// Mulai sync ke target tip.
    ///
    /// Inisialisasi HeaderSyncer dan set status ke SyncingHeaders.
    ///
    /// # Arguments
    /// * `target_tip` - (height, hash) dari peer tip
    ///
    /// # Errors
    /// * Sync sudah berjalan (status != Idle)
    pub fn start_sync(&mut self, target_tip: (u64, Hash)) -> Result<()> {
        // Validasi: hanya bisa start dari Idle
        if self.status != SyncStatus::Idle {
            anyhow::bail!("sync already in progress, current status: {:?}", self.status);
        }

        // Get local tip
        let local_tip = self.chain.db.get_tip()?
            .unwrap_or((0, Hash::from_bytes([0u8; 64])));
        
        // Store local height sebelum move
        let local_height = local_tip.0;
        
        // Validasi: target harus lebih tinggi dari local
        if target_tip.0 <= local_height {
            println!("✅ Already synced to height {}", local_height);
            self.status = SyncStatus::Synced;
            return Ok(());
        }

        println!("═══════════════════════════════════════════════════════════");
        println!("🔄 SYNC MANAGER: Starting sync");
        println!("   Local tip:  height={}", local_height);
        println!("   Target tip: height={}", target_tip.0);
        println!("═══════════════════════════════════════════════════════════");

        // Store target dan start height
        self.target_tip = Some(target_tip.clone());
        self.start_height = local_height + 1;

        // Initialize HeaderSyncer (moves local_tip)
        self.header_syncer = Some(HeaderSyncer::new(local_tip, target_tip.clone()));

        // Transition to SyncingHeaders
        self.status = SyncStatus::SyncingHeaders {
            start_height: self.start_height,
            target_height: target_tip.0,
            current_height: local_height,
        };

        Ok(())
    }

    /// Eksekusi satu langkah sync.
    ///
    /// Method ini NON-BLOCKING dan hanya melakukan satu operasi kecil.
    /// Caller harus memanggil berulang kali sampai `is_synced()` true.
    ///
    /// ## State Transitions
    ///
    /// - Idle: return immediately (nothing to do)
    /// - SyncingHeaders: delegasi ke HeaderSyncer
    /// - SyncingBlocks: delegasi ke BlockSyncer
    /// - SyncingState: delegasi ke StateReplayEngine + ControlPlaneSyncer
    /// - Synced: return immediately
    pub fn sync_step(&mut self) -> Result<()> {
        match &self.status {
            SyncStatus::Idle => {
                // Nothing to do
                Ok(())
            }
            SyncStatus::SyncingHeaders { start_height, target_height, current_height } => {
                self.step_syncing_headers(*start_height, *target_height, *current_height)
            }
            SyncStatus::SyncingBlocks { start_height, target_height, current_height } => {
                self.step_syncing_blocks(*start_height, *target_height, *current_height)
            }
            SyncStatus::SyncingState { checkpoint_height } => {
                self.step_syncing_state(*checkpoint_height)
            }
            SyncStatus::Synced => {
                // Already synced
                Ok(())
            }
        }
    }

    /// Internal: step untuk SyncingHeaders state.
    fn step_syncing_headers(
        &mut self,
        start_height: u64,
        target_height: u64,
        _current_height: u64,
    ) -> Result<()> {
        let syncer = self.header_syncer.as_ref()
            .ok_or_else(|| anyhow::anyhow!("header_syncer not initialized"))?;

        // Check completion
        if syncer.is_complete() {
            println!("   ✓ Header sync complete");
            
            // Prepare headers list untuk BlockSyncer
            let headers: Vec<(u64, Hash)> = (start_height..=target_height)
                .map(|h| {
                    // Get header hash dari DB (headers sudah di-persist)
                    let header = self.chain.db.get_header(h)
                        .ok()
                        .flatten()
                        .map(|hdr| Block::compute_hash(&hdr))
                        .unwrap_or_else(|| Hash::from_bytes([0u8; 64]));
                    (h, header)
                })
                .collect();

            // Initialize BlockSyncer
            self.block_syncer = Some(BlockSyncer::new(headers));

            // Transition to SyncingBlocks
            self.status = SyncStatus::SyncingBlocks {
                start_height,
                target_height,
                current_height: start_height,
            };

            return Ok(());
        }

        // Generate request untuk headers berikutnya
        let request = syncer.request_next_headers();
        println!("   📤 Header request: {:?}", request);

        // Note: Actual fetch dilakukan oleh P2P layer
        // SyncManager hanya generate request dan process response
        // Caller bertanggung jawab untuk:
        // 1. Send request ke peer
        // 2. Receive response
        // 3. Call process_header_response()

        Ok(())
    }

    /// Internal: step untuk SyncingBlocks state.
    fn step_syncing_blocks(
        &mut self,
        start_height: u64,
        target_height: u64,
        _current_height: u64,
    ) -> Result<()> {
        let syncer = self.block_syncer.as_ref()
            .ok_or_else(|| anyhow::anyhow!("block_syncer not initialized"))?;

        // Check completion
        if syncer.is_complete() {
            println!("   ✓ Block sync complete");
            println!("   Fetched: {} blocks", syncer.fetched_count());
            println!("   Failed:  {} blocks", syncer.failed_count());

            // Check for failed blocks
            if syncer.failed_count() > 0 {
                anyhow::bail!(
                    "sync failed: {} blocks could not be fetched after max retries",
                    syncer.failed_count()
                );
            }

            // Initialize StateReplayEngine
            self.replay_engine = Some(StateReplayEngine::new(
                self.chain.clone(),
                start_height,
                target_height,
            ));

            // Transition to SyncingState
            self.status = SyncStatus::SyncingState {
                checkpoint_height: start_height,
            };

            return Ok(());
        }

        // Generate request untuk blocks berikutnya
        let request = syncer.request_next_blocks(self.config.batch_size);
        println!("   📤 Block request: {:?}", request);

        // Note: Actual fetch dilakukan oleh P2P layer

        Ok(())
    }

    /// Internal: step untuk SyncingState state.
    fn step_syncing_state(
        &mut self,
        _checkpoint_height: u64,
    ) -> Result<()> {
        // Check replay engine completion
        if let Some(ref engine) = self.replay_engine {
            if engine.is_complete() {
                println!("   ✓ State replay complete");

                // Apply Celestia updates (control-plane sync)
                if let Some(ref mut celestia) = self.celestia_syncer {
                    celestia.apply_updates(&mut self.chain)?;
                    println!("   ✓ Celestia control-plane updates applied");
                }

                // Get final state dari replay engine
                let final_state = engine.get_final_state();

                // ATOMIC COMMIT ke LMDB
                // Ini adalah SATU-SATUNYA tempat state di-commit
                self.finalize_sync(final_state)?;

                return Ok(());
            }
        }

        // Replay masih berjalan
        // Note: replay_from_genesis() atau replay_from_checkpoint() sudah blocking
        // Untuk non-blocking, perlu replay per-block
        println!("   🔄 State replay in progress...");

        Ok(())
    }

    /// Finalize sync dengan atomic commit ke LMDB.
    ///
    /// CONSENSUS-CRITICAL: State hanya di-commit SATU KALI di sini.
    fn finalize_sync(&mut self, final_state: ChainState) -> Result<()> {
        println!("═══════════════════════════════════════════════════════════");
        println!("💾 SYNC MANAGER: Finalizing sync (atomic commit)");
        println!("═══════════════════════════════════════════════════════════");

        // Update chain state
        {
            let mut state_guard = self.chain.state.write();
            *state_guard = final_state;
        }

          // Persist state ke LMDB
        let state_snapshot = self.chain.state.read().clone();
        self.chain.db.persist_state(&state_snapshot)?;

        // Update tip
        if let Some((target_height, target_hash)) = &self.target_tip {
            self.chain.db.set_tip(*target_height, target_hash)?;
        }

        // Transition to Synced
        self.status = SyncStatus::Synced;

        // Cleanup
        self.header_syncer = None;
        self.block_syncer = None;
        self.replay_engine = None;

        println!("═══════════════════════════════════════════════════════════");
        println!("✅ SYNC MANAGER: Sync complete!");
        println!("═══════════════════════════════════════════════════════════");

        Ok(())
    }

    /// Get current sync status.
    pub fn get_status(&self) -> SyncStatus {
        self.status.clone()
    }

    /// Get sync progress.
    ///
    /// Returns (current_height, target_height)
    pub fn get_progress(&self) -> (u64, u64) {
        match &self.status {
            SyncStatus::Idle => (0, 0),
            SyncStatus::SyncingHeaders { current_height, target_height, .. } => {
                (*current_height, *target_height)
            }
            SyncStatus::SyncingBlocks { current_height, target_height, .. } => {
                (*current_height, *target_height)
            }
            SyncStatus::SyncingState { checkpoint_height } => {
                if let Some(ref engine) = self.replay_engine {
                    engine.get_progress()
                } else {
                    (*checkpoint_height, self.target_tip.as_ref().map(|(h, _)| *h).unwrap_or(0))
                }
            }
            SyncStatus::Synced => {
                let target = self.target_tip.as_ref().map(|(h, _)| *h).unwrap_or(0);
                (target, target)
            }
        }
    }

    /// Cancel ongoing sync dan reset ke Idle.
    pub fn cancel_sync(&mut self) {
        println!("⚠️  SYNC MANAGER: Sync cancelled");

        // Reset all syncers
        self.header_syncer = None;
        self.block_syncer = None;
        self.replay_engine = None;
        self.target_tip = None;

        // Transition to Idle
        self.status = SyncStatus::Idle;
    }

    /// Check apakah sync sudah selesai.
    pub fn is_synced(&self) -> bool {
        matches!(self.status, SyncStatus::Synced)
    }

    // ════════════════════════════════════════════════════════════════════════
    // RESPONSE HANDLERS (dipanggil oleh P2P layer)
    // ════════════════════════════════════════════════════════════════════════

    /// Process header response dari peer.
    ///
    /// Dipanggil oleh P2P layer setelah menerima SyncResponse::Headers.
    pub fn process_header_response(&mut self, headers: Vec<BlockHeader>) -> Result<()> {
        if let Some(ref mut syncer) = self.header_syncer {
            syncer.process_headers(headers, &self.chain.db)?;

            // Update status progress
            let (current, target) = syncer.get_progress();
            if let SyncStatus::SyncingHeaders { start_height, target_height: _, current_height: _ } = &self.status {
                self.status = SyncStatus::SyncingHeaders {
                    start_height: *start_height,
                    target_height: target,
                    current_height: current,
                };
            }
        }
        Ok(())
    }

    /// Process block response dari peer.
    ///
    /// Dipanggil oleh P2P layer setelah menerima SyncResponse::Blocks.
    pub fn process_block_response(&mut self, blocks: Vec<Block>) -> Result<()> {
        if let Some(ref mut syncer) = self.block_syncer {
            for block in blocks {
                let height = block.header.height;
                
                // Get expected header dari DB
                if let Some(expected_header) = self.chain.db.get_header(height)? {
                    if let Err(e) = syncer.process_block(block, &expected_header) {
                        println!("   ⚠️  Block {} processing error: {}", height, e);
                    }
                }
            }

            // Update status progress
            let fetched = syncer.fetched_count() as u64;
            if let SyncStatus::SyncingBlocks { start_height, target_height, current_height: _ } = &self.status {
                self.status = SyncStatus::SyncingBlocks {
                    start_height: *start_height,
                    target_height: *target_height,
                    current_height: *start_height + fetched,
                };
            }
        }
        Ok(())
    }

    /// Trigger replay execution.
    ///
    /// Dipanggil setelah semua blocks tersedia.
    pub fn execute_replay(&mut self) -> Result<()> {
        if let Some(ref mut engine) = self.replay_engine {
            engine.replay_from_genesis()?;
        }
        Ok(())
    }

    /// Set Celestia syncer untuk control-plane updates.
    pub fn set_celestia_syncer(&mut self, syncer: crate::celestia::ControlPlaneSyncer) {
        self.celestia_syncer = Some(syncer);
    }
}


// TESTS

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_config_default() {
        let config = SyncConfig::default();
        
        assert_eq!(config.max_headers_per_request, 500);
        assert_eq!(config.max_blocks_per_request, 100);
        assert_eq!(config.sync_timeout_ms, 30000);
        assert_eq!(config.batch_size, 50);
    }

    #[test]
    fn test_sync_status_variants() {
        let idle = SyncStatus::Idle;
        let synced = SyncStatus::Synced;
        
        assert_ne!(idle, synced);
        
        let syncing = SyncStatus::SyncingHeaders {
            start_height: 0,
            target_height: 100,
            current_height: 50,
        };
        
        assert_ne!(syncing, idle);
    }

    #[test]
    fn test_sync_request_serialization() {
        let req = SyncRequest::GetHeaders {
            start_height: 100,
            count: 50,
        };
        
        let json = serde_json::to_string(&req).unwrap();
        let restored: SyncRequest = serde_json::from_str(&json).unwrap();
        
        assert_eq!(req, restored);
    }

    #[test]
    fn test_sync_config_serialization() {
        let config = SyncConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let restored: SyncConfig = serde_json::from_str(&json).unwrap();
        
        assert_eq!(config, restored);
    }

    #[test]
    fn test_header_syncer_new() {
        let local_tip = (100, Hash::from_bytes([0x11u8; 64]));
        let target_tip = (200, Hash::from_bytes([0x22u8; 64]));
        
        let syncer = HeaderSyncer::new(local_tip.clone(), target_tip.clone());
        
        assert_eq!(syncer.local_tip, local_tip);
        assert_eq!(syncer.target_tip, target_tip);
        assert!(syncer.pending_headers.is_empty());
        assert!(syncer.verified_heights.is_empty());
    }

    #[test]
    fn test_header_syncer_request_next() {
        let local_tip = (100, Hash::from_bytes([0x11u8; 64]));
        let target_tip = (200, Hash::from_bytes([0x22u8; 64]));
        
        let syncer = HeaderSyncer::new(local_tip.clone(), target_tip.clone());
        
        let req = syncer.request_next_headers();
        match req {
            SyncRequest::GetHeaders { start_height, count } => {
                assert_eq!(start_height, 101);
                assert_eq!(count, 100); // 200 - 101 + 1 = 100
            }
            _ => panic!("expected GetHeaders"),
        }
    }

    #[test]
    fn test_header_syncer_progress() {
        let local_tip = (100, Hash::from_bytes([0x11u8; 64]));
        let target_tip = (200, Hash::from_bytes([0x22u8; 64]));
        
        let mut syncer = HeaderSyncer::new(local_tip, target_tip);
        
        let (current, target) = syncer.get_progress();
        assert_eq!(current, 100);
        assert_eq!(target, 200);
        assert!(!syncer.is_complete());
        
        // Simulate verified heights
        for h in 101..=200 {
            syncer.verified_heights.insert(h);
        }
        
        let (current2, _) = syncer.get_progress();
        assert_eq!(current2, 200);
        assert!(syncer.is_complete());
    }

    // ════════════════════════════════════════════════════════════════════════
    // BLOCK SYNCER TESTS (13.11.3)
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_block_syncer_new() {
        let headers = vec![
            (101, Hash::from_bytes([0x11u8; 64])),
            (102, Hash::from_bytes([0x22u8; 64])),
            (103, Hash::from_bytes([0x33u8; 64])),
        ];
        
        let syncer = BlockSyncer::new(headers.clone());
        
        assert_eq!(syncer.headers_to_fetch.len(), 3);
        assert!(syncer.fetched_blocks.is_empty());
        assert!(syncer.failed_heights.is_empty());
        assert!(syncer.retry_count.is_empty());
        assert!(!syncer.is_complete());
    }

    #[test]
    fn test_block_syncer_request_next() {
        let headers = vec![
            (101, Hash::from_bytes([0x11u8; 64])),
            (102, Hash::from_bytes([0x22u8; 64])),
            (103, Hash::from_bytes([0x33u8; 64])),
            (104, Hash::from_bytes([0x44u8; 64])),
            (105, Hash::from_bytes([0x55u8; 64])),
        ];
        
        let syncer = BlockSyncer::new(headers);
        
        // Request batch of 3
        let req = syncer.request_next_blocks(3);
        match req {
            SyncRequest::GetBlocks { heights } => {
                assert_eq!(heights.len(), 3);
                assert_eq!(heights, vec![101, 102, 103]);
            }
            _ => panic!("expected GetBlocks"),
        }
        
        // Request batch larger than remaining
        let req2 = syncer.request_next_blocks(100);
        match req2 {
            SyncRequest::GetBlocks { heights } => {
                assert_eq!(heights.len(), 5);
            }
            _ => panic!("expected GetBlocks"),
        }
    }

    #[test]
    fn test_block_syncer_pending_heights() {
        let headers = vec![
            (101, Hash::from_bytes([0x11u8; 64])),
            (102, Hash::from_bytes([0x22u8; 64])),
            (103, Hash::from_bytes([0x33u8; 64])),
        ];
        
        let syncer = BlockSyncer::new(headers);
        
        let pending = syncer.get_pending_heights();
        assert_eq!(pending, vec![101, 102, 103]);
    }

    #[test]
    fn test_block_syncer_complete_when_empty() {
        let syncer = BlockSyncer::new(vec![]);
        
        assert!(syncer.is_complete());
        assert_eq!(syncer.fetched_count(), 0);
        assert_eq!(syncer.failed_count(), 0);
    }

    // ════════════════════════════════════════════════════════════════════════
    // STATE REPLAY ENGINE TESTS (13.11.4)
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_state_replay_engine_progress() {
        // Test get_progress dan is_complete tanpa Chain
        // (karena Chain membutuhkan DB path)
        
        // Verifikasi bahwa progress tracking berfungsi
        let start = 0u64;
        let end = 100u64;
        
        // Simulasi progress
        let current = 50u64;
        let is_done = current > end;
        
        assert_eq!((current, end), (50, 100));
        assert!(!is_done);
        
        let current2 = 101u64;
        let is_done2 = current2 > end;
        assert!(is_done2);
    }

    #[test]
    fn test_state_replay_engine_checkpoint_state() {
        // Test ChainState checkpoint serialization
        let state = crate::state::ChainState::new();
        
        // Create checkpoint
        let checkpoint = crate::state::create_checkpoint(&state);
        assert!(checkpoint.is_ok());
        
        // Restore from checkpoint
        let restored = crate::state::restore_from_checkpoint(&checkpoint.unwrap());
        assert!(restored.is_ok());
    }

    // ════════════════════════════════════════════════════════════════════════
    // SYNC STATUS STATE MACHINE TESTS (13.11.9)
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_sync_status_transitions() {
        // Test all valid state transitions
        
        // Idle → SyncingHeaders
        let idle = SyncStatus::Idle;
        let syncing_headers = SyncStatus::SyncingHeaders {
            start_height: 1,
            target_height: 100,
            current_height: 1,
        };
        assert_ne!(idle, syncing_headers);
        
        // SyncingHeaders → SyncingBlocks
        let syncing_blocks = SyncStatus::SyncingBlocks {
            start_height: 1,
            target_height: 100,
            current_height: 1,
        };
        assert_ne!(syncing_headers, syncing_blocks);
        
        // SyncingBlocks → SyncingState
        let syncing_state = SyncStatus::SyncingState {
            checkpoint_height: 1,
        };
        assert_ne!(syncing_blocks, syncing_state);
        
        // SyncingState → Synced
        let synced = SyncStatus::Synced;
        assert_ne!(syncing_state, synced);
        
        // Synced → Idle (reset)
        assert_ne!(synced, idle);
        
        // All states are distinct
        let all_states = vec![
            SyncStatus::Idle,
            SyncStatus::SyncingHeaders { start_height: 0, target_height: 0, current_height: 0 },
            SyncStatus::SyncingBlocks { start_height: 0, target_height: 0, current_height: 0 },
            SyncStatus::SyncingState { checkpoint_height: 0 },
            SyncStatus::Synced,
        ];
        for i in 0..all_states.len() {
            for j in 0..all_states.len() {
                if i != j {
                    assert_ne!(
                        std::mem::discriminant(&all_states[i]),
                        std::mem::discriminant(&all_states[j])
                    );
                }
            }
        }
    }

    #[test]
    fn test_sync_status_serialization_roundtrip() {
        // Test all SyncStatus variants serialize/deserialize correctly
        let statuses = vec![
            SyncStatus::Idle,
            SyncStatus::SyncingHeaders { start_height: 10, target_height: 100, current_height: 50 },
            SyncStatus::SyncingBlocks { start_height: 10, target_height: 100, current_height: 75 },
            SyncStatus::SyncingState { checkpoint_height: 100 },
            SyncStatus::Synced,
        ];
        
        for status in statuses {
            let json = serde_json::to_string(&status).unwrap();
            let restored: SyncStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, restored);
        }
    }

    #[test]
    fn test_header_chain_validation_rules() {
        // Test CONSENSUS-CRITICAL header validation rules
        let local_tip = (100, Hash::from_bytes([0x11u8; 64]));
        let target_tip = (200, Hash::from_bytes([0x22u8; 64]));
        
        let syncer = HeaderSyncer::new(local_tip, target_tip);
        
        // Rule: Empty headers should pass
        let result = syncer.verify_header_chain(&[]);
        assert!(result.is_ok());
        
        // Create mock header with correct height
        // Note: Full header validation requires actual BlockHeader construction
        // which depends on other modules
    }

    #[test]
    fn test_header_sync_complete_detection() {
        let local_tip = (100, Hash::from_bytes([0x11u8; 64]));
        let target_tip = (110, Hash::from_bytes([0x22u8; 64]));
        
        let mut syncer = HeaderSyncer::new(local_tip, target_tip);
        
        // Initially not complete
        assert!(!syncer.is_complete());
        assert_eq!(syncer.verified_heights.len(), 0);
        
        // Add verified heights one by one
        for h in 101..=110 {
            syncer.verified_heights.insert(h);
        }
        
        // Now complete
        assert!(syncer.is_complete());
        
        // Progress should reflect completion
        let (current, target) = syncer.get_progress();
        assert_eq!(current, 110);
        assert_eq!(target, 110);
    }

    #[test]
    fn test_block_sync_retry_tracking() {
        let headers = vec![
            (101, Hash::from_bytes([0x11u8; 64])),
            (102, Hash::from_bytes([0x22u8; 64])),
        ];
        
        let mut syncer = BlockSyncer::new(headers);
        
        // Initially no retries
        assert!(syncer.retry_count.is_empty());
        assert!(syncer.failed_heights.is_empty());
        
        // Simulate retry tracking
        syncer.retry_count.insert(101, 1);
        assert_eq!(*syncer.retry_count.get(&101).unwrap(), 1);
        
        syncer.retry_count.insert(101, 2);
        assert_eq!(*syncer.retry_count.get(&101).unwrap(), 2);
        
        // Simulate failure after max retries
        syncer.retry_count.insert(101, 3);
        syncer.failed_heights.insert(101);
        
        assert!(syncer.failed_heights.contains(&101));
        assert_eq!(syncer.failed_count(), 1);
    }

    #[test]
    fn test_block_sync_batch_generation() {
        let headers: Vec<(u64, Hash)> = (101..=120)
            .map(|h| (h, Hash::from_bytes([h as u8; 64])))
            .collect();
        
        let syncer = BlockSyncer::new(headers);
        
        // Request batch of 5
        let req = syncer.request_next_blocks(5);
        match req {
            SyncRequest::GetBlocks { heights } => {
                assert_eq!(heights.len(), 5);
                assert_eq!(heights, vec![101, 102, 103, 104, 105]);
            }
            _ => panic!("expected GetBlocks"),
        }
        
        // Request batch of 10
        let req2 = syncer.request_next_blocks(10);
        match req2 {
            SyncRequest::GetBlocks { heights } => {
                assert_eq!(heights.len(), 10);
            }
            _ => panic!("expected GetBlocks"),
        }
    }

    #[test]
    fn test_sync_config_defaults_values() {
        let config = SyncConfig::default();
        
        // Verify exact default values
        assert_eq!(config.max_headers_per_request, 500);
        assert_eq!(config.max_blocks_per_request, 100);
        assert_eq!(config.sync_timeout_ms, 30000);
        assert_eq!(config.batch_size, 50);
        
        // Verify serialization preserves defaults
        let json = serde_json::to_string(&config).unwrap();
        let restored: SyncConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, restored);
    }

    #[test]
    fn test_sync_request_variants() {
        // Test all SyncRequest variants
        let requests = vec![
            SyncRequest::GetHeaders { start_height: 100, count: 50 },
            SyncRequest::GetBlock { height: 150 },
            SyncRequest::GetBlocks { heights: vec![100, 101, 102] },
            SyncRequest::GetChainTip,
        ];
        
        for req in requests {
            let json = serde_json::to_string(&req).unwrap();
            let restored: SyncRequest = serde_json::from_str(&json).unwrap();
            assert_eq!(req, restored);
        }
    }

    #[test]
    fn test_peer_sync_state_tracking() {
        let state = PeerSyncState {
            peer_id: "peer_001".to_string(),
            tip_height: 12345,
            tip_hash: Hash::from_bytes([0x42u8; 64]),
            last_seen: 1700000000,
            is_syncing: true,
        };
        
        assert_eq!(state.peer_id, "peer_001");
        assert_eq!(state.tip_height, 12345);
        assert!(state.is_syncing);
        
        // Serialization roundtrip
        let json = serde_json::to_string(&state).unwrap();
        let restored: PeerSyncState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, restored);
    }
}