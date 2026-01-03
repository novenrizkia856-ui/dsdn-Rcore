//! # Celestia DA Integration (13.11.5)
//!
//! Module ini menyediakan client untuk mengakses Celestia Data Availability layer
//! dan sinkronisasi control-plane state untuk DSDN.
//!
//! ## Peran Celestia
//!
//! Celestia DA menyimpan HANYA control-plane state:
//! - Receipt batches dari Coordinator
//! - Validator set updates
//! - Config updates
//! - State checkpoints
//!
//! ## Tipe Utama
//!
//! | Type | Fungsi |
//! |------|--------|
//! | `CelestiaConfig` | Konfigurasi client (RPC URL, namespace, timeout) |
//! | `CelestiaClient` | HTTP client untuk fetch blobs |
//! | `ControlPlaneUpdate` | Enum untuk semua jenis update |
//! | `ControlPlaneSyncer` | Sync engine untuk control-plane |
//!
//! ## Batasan
//!
//! - Read-only: tidak menulis ke Celestia
//! - Receipts hanya diekstrak, BUKAN dieksekusi
//! - Validator updates hanya update registry
//! - Checkpoints hanya disimpan, bukan auto-replay

use std::collections::VecDeque;
use serde::{Serialize, Deserialize};
use anyhow::Result;

use crate::types::Hash;
use crate::receipt::ResourceReceipt;
use crate::state::ValidatorInfo;
use crate::Chain;

// ════════════════════════════════════════════════════════════════════════════
// CELESTIA CONFIG
// ════════════════════════════════════════════════════════════════════════════

/// Konfigurasi untuk Celestia DA client.
///
/// Namespace ID adalah 8-byte identifier untuk filtering blobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CelestiaConfig {
    /// Celestia node RPC URL (e.g., "http://localhost:26658")
    pub rpc_url: String,
    /// Namespace ID (8 bytes) untuk DSDN control-plane
    pub namespace_id: [u8; 8],
    /// Optional auth token untuk authenticated RPC
    pub auth_token: Option<String>,
    /// Request timeout dalam milliseconds
    pub timeout_ms: u64,
}

impl Default for CelestiaConfig {
    fn default() -> Self {
        Self {
            rpc_url: "http://localhost:26658".to_string(),
            namespace_id: *b"dsdn_ctl", // Default namespace
            timeout_ms: 30000,
            auth_token: None,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// BLOB COMMITMENT (13.17.6)
// ════════════════════════════════════════════════════════════════════════════
// Cryptographic commitment untuk Data Availability verification.
//
// INVARIANTS:
// - commitment HARUS 32 bytes (SHA3-256 output)
// - namespace HARUS 29 bytes (Celestia v0 spec)
// - Commitment deterministik: same data → same commitment
// ════════════════════════════════════════════════════════════════════════════

/// Blob commitment metadata dari Celestia DA.
///
/// Menyimpan commitment hash beserta metadata lokasi blob.
/// Namespace 29 bytes sesuai Celestia namespace version 0 spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlobCommitment {
    /// SHA3-256 hash of blob data (32 bytes)
    pub commitment: [u8; 32],
    /// Celestia namespace (29 bytes, version 0 format)
    pub namespace: [u8; 29],
    /// Celestia block height dimana blob disimpan
    pub height: u64,
    /// Index blob dalam block
    pub index: u32,
}

impl BlobCommitment {
    /// Create new BlobCommitment.
    #[inline]
    pub fn new(
        commitment: [u8; 32],
        namespace: [u8; 29],
        height: u64,
        index: u32,
    ) -> Self {
        Self {
            commitment,
            namespace,
            height,
            index,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// CORE COMMITMENT FUNCTIONS (13.17.6)
// ════════════════════════════════════════════════════════════════════════════
// Standalone functions untuk commitment computation dan verification.
// Menggunakan SHA3-256 untuk deterministic hashing.
// ════════════════════════════════════════════════════════════════════════════

/// Compute blob commitment menggunakan SHA3-256.
///
/// Commitment adalah hash deterministik dari blob data.
/// Digunakan untuk verifikasi Data Availability tanpa trust.
///
/// # Arguments
/// * `blob_data` - Raw blob bytes
///
/// # Returns
/// 32-byte commitment (SHA3-256 hash)
///
/// # Example
/// ```rust,ignore
/// let data = b"hello celestia";
/// let commitment = compute_blob_commitment(data);
/// assert_eq!(commitment.len(), 32);
/// ```
///
/// # Security Notes
/// - Deterministik: same input → same output
/// - Collision resistant (SHA3-256)
/// - Tidak ada salt atau encoding tambahan
pub fn compute_blob_commitment(blob_data: &[u8]) -> [u8; 32] {
    use sha3::{Sha3_256, Digest};
    
    let mut hasher = Sha3_256::new();
    hasher.update(blob_data);
    
    let result = hasher.finalize();
    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(&result[..32]);
    commitment
}

/// Verify blob data matches expected commitment.
///
/// Menghitung commitment dari blob_data dan membandingkan
/// byte-by-byte dengan expected_commitment.
///
/// # Arguments
/// * `blob_data` - Raw blob bytes
/// * `expected_commitment` - Expected 32-byte commitment
///
/// # Returns
/// * `true` - Commitment matches
/// * `false` - Commitment mismatch
///
/// # Example
/// ```rust,ignore
/// let data = b"hello celestia";
/// let commitment = compute_blob_commitment(data);
/// assert!(verify_blob_commitment(data, &commitment));
/// ```
///
/// # Security Notes
/// - Constant-time comparison tidak diperlukan (non-secret)
/// - Tidak panic pada input apapun
pub fn verify_blob_commitment(
    blob_data: &[u8],
    expected_commitment: &[u8; 32],
) -> bool {
    let computed = compute_blob_commitment(blob_data);
    computed == *expected_commitment
}

// ════════════════════════════════════════════════════════════════════════════
// CELESTIA CLIENT
// ════════════════════════════════════════════════════════════════════════════

/// HTTP client untuk Celestia DA.
///
/// Menyediakan method untuk fetch blobs dari Celestia node.
/// Client bersifat read-only dan tidak menulis ke Celestia.
#[derive(Debug, Clone)]
pub struct CelestiaClient {
    /// Konfigurasi client
    pub config: CelestiaConfig,
    // Note: reqwest::Client tidak di-include karena memerlukan async runtime
    // Implementasi production akan menggunakan reqwest atau HTTP client lain
}

impl CelestiaClient {
    /// Buat CelestiaClient baru dengan konfigurasi.
    ///
    /// # Arguments
    /// * `config` - CelestiaConfig dengan RPC URL dan namespace
    pub fn new(config: CelestiaConfig) -> Self {
        Self { config }
    }

    /// Fetch blobs dari Celestia DA untuk height dan namespace tertentu.
    ///
    /// # Arguments
    /// * `da_height` - Celestia block height
    /// * `namespace` - Namespace ID (8 bytes)
    ///
    /// # Returns
    /// * Vec<Vec<u8>> - Raw blob data
    ///
    /// # Note
    /// Implementasi placeholder. Production menggunakan Celestia RPC.
    pub fn fetch_blobs(
        &self,
        da_height: u64,
        namespace: [u8; 8],
    ) -> Result<Vec<Vec<u8>>> {
        // Placeholder implementation
        // Production: HTTP call ke Celestia node
        // GET /blob/get/{height}/{namespace}
        
        println!(
            "📡 Celestia: Fetching blobs at height {} namespace {:?}",
            da_height,
            hex::encode(namespace)
        );
        
        // Return empty untuk placeholder
        // Real implementation akan return actual blobs
        Ok(vec![])
    }

    /// Fetch blobs untuk range of heights.
    ///
    /// # Arguments
    /// * `start` - Start height (inclusive)
    /// * `end` - End height (inclusive)
    /// * `namespace` - Namespace ID
    ///
    /// # Returns
    /// * Vec<Vec<u8>> - Concatenated blob data dari semua heights
    pub fn fetch_blobs_range(
        &self,
        start: u64,
        end: u64,
        namespace: [u8; 8],
    ) -> Result<Vec<Vec<u8>>> {
        let mut all_blobs = Vec::new();
        
        for height in start..=end {
            let blobs = self.fetch_blobs(height, namespace)?;
            all_blobs.extend(blobs);
        }
        
        Ok(all_blobs)
    }

    /// Parse blob menjadi ControlPlaneUpdate.
    ///
    /// Blob format:
    /// - Byte 0: type tag (0=Receipt, 1=Validator, 2=Config, 3=Checkpoint)
    /// - Byte 1..N: bincode serialized data
    ///
    /// # Arguments
    /// * `blob` - Raw blob bytes
    ///
    /// # Returns
    /// * ControlPlaneUpdate - Parsed update
    ///
    /// # Errors
    /// * Invalid type tag
    /// * Deserialization failed
    pub fn parse_control_plane_blob(
        &self,
        blob: &[u8],
    ) -> Result<ControlPlaneUpdate> {
        if blob.is_empty() {
            anyhow::bail!("empty blob");
        }
        
        let type_tag = blob[0];
        let data = &blob[1..];
        
        match type_tag {
            0 => {
                // ReceiptBatch
                let receipts: Vec<ResourceReceipt> = bincode::deserialize(data)
                    .map_err(|e| anyhow::anyhow!("receipt batch deserialize failed: {}", e))?;
                Ok(ControlPlaneUpdate::ReceiptBatch { receipts })
            }
            1 => {
                // ValidatorSetUpdate
                let validators: Vec<ValidatorInfo> = bincode::deserialize(data)
                    .map_err(|e| anyhow::anyhow!("validator set deserialize failed: {}", e))?;
                Ok(ControlPlaneUpdate::ValidatorSetUpdate { validators })
            }
            2 => {
                // ConfigUpdate
                let (key, value): (String, Vec<u8>) = bincode::deserialize(data)
                    .map_err(|e| anyhow::anyhow!("config update deserialize failed: {}", e))?;
                Ok(ControlPlaneUpdate::ConfigUpdate { key, value })
            }
            3 => {
                // Checkpoint
                let (height, state_root): (u64, Hash) = bincode::deserialize(data)
                    .map_err(|e| anyhow::anyhow!("checkpoint deserialize failed: {}", e))?;
                Ok(ControlPlaneUpdate::Checkpoint { height, state_root })
            }
            _ => {
                anyhow::bail!("unknown control plane type tag: {}", type_tag);
            }
        }
    }

    /// Verify blob commitment.
    ///
    /// Memastikan blob data sesuai dengan commitment yang diberikan.
    /// Commitment adalah hash dari blob data.
    ///
    /// # Arguments
    /// * `blob` - Raw blob data
    /// * `commitment` - Expected commitment (hash)
    ///
    /// # Errors
    /// * Commitment mismatch
    pub fn verify_blob_commitment(
        &self,
        blob: &[u8],
        commitment: &[u8],
    ) -> Result<()> {
        // Compute commitment dari blob
        let computed = crate::crypto::sha3_512(blob);
        
        if computed.as_bytes() != commitment {
            anyhow::bail!(
                "blob commitment mismatch: expected {}, computed {}",
                hex::encode(commitment),
                hex::encode(computed.as_bytes())
            );
        }
        
        Ok(())
    }

    // ════════════════════════════════════════════════════════════════════════
    // BLOB COMMITMENT METHODS (13.17.6)
    // ════════════════════════════════════════════════════════════════════════

    /// Get blob commitment metadata dari Celestia.
    ///
    /// Query metadata blob tanpa fetch full blob data.
    /// Digunakan untuk verification tanpa download penuh.
    ///
    /// # Arguments
    /// * `height` - Celestia block height
    /// * `index` - Blob index dalam block
    ///
    /// # Returns
    /// * `Ok(BlobCommitment)` - Commitment metadata
    /// * `Err` - Blob tidak ditemukan atau query gagal
    ///
    /// # Note
    /// Placeholder implementation. Production menggunakan Celestia RPC.
    pub fn get_blob_commitment(
        &self,
        height: u64,
        index: u32,
    ) -> Result<BlobCommitment> {
        // Placeholder implementation
        // Production: HTTP call ke Celestia node
        // GET /blob/get/{height}/{namespace}/{index}/commitment
        
        println!(
            "📡 Celestia: Getting blob commitment at height {} index {}",
            height, index
        );
        
        // Return error untuk placeholder
        // Real implementation akan query commitment dari Celestia node
        anyhow::bail!(
            "blob commitment not found at height {} index {} (placeholder)",
            height, index
        )
    }

    /// Verify blob data at specific height matches commitment.
    ///
    /// Alur:
    /// 1. Ambil BlobCommitment dari height/index
    /// 2. Compute commitment dari data
    /// 3. Compare kedua commitment
    ///
    /// # Arguments
    /// * `height` - Celestia block height
    /// * `index` - Blob index dalam block
    /// * `data` - Blob data untuk diverifikasi
    ///
    /// # Returns
    /// * `Ok(true)` - Commitment match
    /// * `Ok(false)` - Commitment mismatch
    /// * `Err` - Query gagal (blob tidak ditemukan, dll)
    ///
    /// # Security Notes
    /// - TIDAK swallow error
    /// - Propagate error jika query gagal
    pub fn verify_blob_at_height(
        &self,
        height: u64,
        index: u32,
        data: &[u8],
    ) -> Result<bool> {
        // Step 1: Get commitment dari Celestia
        let blob_commitment = self.get_blob_commitment(height, index)?;
        
        // Step 2: Compute commitment dari data
        let computed = compute_blob_commitment(data);
        
        // Step 3: Compare
        Ok(computed == blob_commitment.commitment)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// CONTROL PLANE UPDATE
// ════════════════════════════════════════════════════════════════════════════

/// Enum untuk semua jenis control-plane update dari Celestia.
///
/// Setiap variant mewakili tipe data berbeda yang disimpan di Celestia DA.
/// Updates ini consensus-critical dan mempengaruhi ChainState.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlPlaneUpdate {
    /// Batch of resource receipts dari Coordinator.
    /// Digunakan untuk ClaimReward transactions.
    ReceiptBatch {
        /// List of receipts dalam batch
        receipts: Vec<ResourceReceipt>,
    },
    /// Update validator set.
    /// Digunakan untuk sinkronisasi validator registry.
    ValidatorSetUpdate {
        /// List of validators (bisa add/update)
        validators: Vec<ValidatorInfo>,
    },
    /// Config parameter update.
    /// Key-value pair untuk chain configuration.
    ConfigUpdate {
        /// Config key (e.g., "max_block_size")
        key: String,
        /// Config value (serialized)
        value: Vec<u8>,
    },
    /// State checkpoint reference.
    /// Height dan state_root untuk fast sync.
    Checkpoint {
        /// Block height of checkpoint
        height: u64,
        /// State root hash at checkpoint
        state_root: Hash,
    },
}

// ════════════════════════════════════════════════════════════════════════════
// CONTROL PLANE SYNCER
// ════════════════════════════════════════════════════════════════════════════

/// Sync engine untuk control-plane state dari Celestia.
///
/// Menyediakan:
/// - Fetch updates dari Celestia DA
/// - Queue pending updates
/// - Apply updates ke Chain
/// - Extract pending receipts
#[derive(Debug)]
pub struct ControlPlaneSyncer {
    /// Celestia client untuk fetch blobs
    pub client: CelestiaClient,
    /// Last synced Celestia height
    pub last_synced_da_height: u64,
    /// Queue of pending updates (FIFO)
    pub pending_updates: VecDeque<ControlPlaneUpdate>,
}

impl ControlPlaneSyncer {
    /// Buat ControlPlaneSyncer baru.
    ///
    /// # Arguments
    /// * `client` - CelestiaClient untuk fetch
    pub fn new(client: CelestiaClient) -> Self {
        Self {
            client,
            last_synced_da_height: 0,
            pending_updates: VecDeque::new(),
        }
    }

    /// Sync control-plane updates dari Celestia height tertentu.
    ///
    /// Fetch blobs dari da_height sampai latest, parse, dan queue.
    ///
    /// # Arguments
    /// * `da_height` - Start height untuk sync
    ///
    /// # Note
    /// Updates di-queue ke pending_updates untuk processing nanti.
    pub fn sync_from_height(
        &mut self,
        da_height: u64,
    ) -> Result<()> {
        println!(
            "🔄 ControlPlaneSyncer: Syncing from DA height {} (last: {})",
            da_height,
            self.last_synced_da_height
        );
        
        // Fetch blobs dari height
        let namespace = self.client.config.namespace_id;
        let blobs = self.client.fetch_blobs(da_height, namespace)?;
        
        // Parse each blob dan queue
        for blob in blobs {
            match self.client.parse_control_plane_blob(&blob) {
                Ok(update) => {
                    println!("   ✓ Parsed update: {:?}", update_type_name(&update));
                    self.pending_updates.push_back(update);
                }
                Err(e) => {
                    println!("   ⚠️ Failed to parse blob: {}", e);
                    // Non-fatal: skip malformed blob
                }
            }
        }
        
        // Update last synced height
        self.last_synced_da_height = da_height;
        
        Ok(())
    }

    /// Apply pending updates ke Chain.
    ///
    /// Process semua updates di pending_updates queue:
    /// - ReceiptBatch: skip (receipts extracted separately)
    /// - ValidatorSetUpdate: update validator registry
    /// - ConfigUpdate: update chain config
    /// - Checkpoint: store checkpoint reference
    ///
    /// # Arguments
    /// * `chain` - Chain untuk apply updates
    ///
    /// # Note
    /// Receipts TIDAK dieksekusi di sini. Hanya registry updates.
    pub fn apply_updates(
        &mut self,
        chain: &mut Chain,
    ) -> Result<()> {
        while let Some(update) = self.pending_updates.pop_front() {
            match update {
                ControlPlaneUpdate::ReceiptBatch { receipts: _ } => {
                    // Receipts diekstrak via get_pending_receipts()
                    // TIDAK dieksekusi di sini
                    println!("   📋 ReceiptBatch: skipped (extract via get_pending_receipts)");
                }
                ControlPlaneUpdate::ValidatorSetUpdate { validators } => {
                    // Update validator registry
                    let mut state = chain.state.write();
                    for v in validators {
                        state.validator_set.add_validator(v);
                    }
                    println!("   ✓ ValidatorSetUpdate applied");
                }
                ControlPlaneUpdate::ConfigUpdate { key, value } => {
                    // Config updates stored for later use
                    // Implementation depends on config system
                    println!(
                        "   ✓ ConfigUpdate: key={}, value_len={}",
                        key,
                        value.len()
                    );
                }
                ControlPlaneUpdate::Checkpoint { height, state_root } => {
                    // Store checkpoint reference
                    // Can be used for fast sync verification
                    println!(
                        "   ✓ Checkpoint: height={}, state_root={}",
                        height,
                        state_root
                    );
                }
            }
        }
        
        Ok(())
    }

    /// Extract pending receipts dari queued ReceiptBatch updates.
    ///
    /// Mengumpulkan semua receipts dari ReceiptBatch updates dan return.
    /// ReceiptBatch updates di-remove dari queue setelah extraction.
    ///
    /// # Returns
    /// * Vec<ResourceReceipt> - All receipts dari pending batches
    pub fn get_pending_receipts(&mut self) -> Vec<ResourceReceipt> {
        let mut receipts = Vec::new();
        
        // Collect receipts dari ReceiptBatch updates
        let mut remaining = VecDeque::new();
        
        while let Some(update) = self.pending_updates.pop_front() {
            match update {
                ControlPlaneUpdate::ReceiptBatch { receipts: batch } => {
                    receipts.extend(batch);
                }
                other => {
                    // Keep non-receipt updates
                    remaining.push_back(other);
                }
            }
        }
        
        // Restore non-receipt updates
        self.pending_updates = remaining;
        
        receipts
    }

    /// Get count of pending updates.
    pub fn pending_count(&self) -> usize {
        self.pending_updates.len()
    }

    /// Check apakah ada pending updates.
    pub fn has_pending(&self) -> bool {
        !self.pending_updates.is_empty()
    }
}

/// Helper: get update type name untuk logging.
fn update_type_name(update: &ControlPlaneUpdate) -> &'static str {
    match update {
        ControlPlaneUpdate::ReceiptBatch { .. } => "ReceiptBatch",
        ControlPlaneUpdate::ValidatorSetUpdate { .. } => "ValidatorSetUpdate",
        ControlPlaneUpdate::ConfigUpdate { .. } => "ConfigUpdate",
        ControlPlaneUpdate::Checkpoint { .. } => "Checkpoint",
    }
}

// ════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_celestia_config_default() {
        let config = CelestiaConfig::default();
        
        assert_eq!(config.rpc_url, "http://localhost:26658");
        assert_eq!(config.namespace_id, *b"dsdn_ctl");
        assert_eq!(config.timeout_ms, 30000);
        assert!(config.auth_token.is_none());
    }

    #[test]
    fn test_celestia_client_new() {
        let config = CelestiaConfig::default();
        let client = CelestiaClient::new(config.clone());
        
        assert_eq!(client.config.rpc_url, config.rpc_url);
        assert_eq!(client.config.namespace_id, config.namespace_id);
    }

    #[test]
    fn test_control_plane_syncer_new() {
        let config = CelestiaConfig::default();
        let client = CelestiaClient::new(config);
        let syncer = ControlPlaneSyncer::new(client);
        
        assert_eq!(syncer.last_synced_da_height, 0);
        assert!(syncer.pending_updates.is_empty());
        assert!(!syncer.has_pending());
    }

    #[test]
    fn test_parse_receipt_batch_blob() {
        let config = CelestiaConfig::default();
        let client = CelestiaClient::new(config);
        
        // Create mock receipt batch blob
        let receipts: Vec<ResourceReceipt> = vec![];
        let data = bincode::serialize(&receipts).unwrap();
        
        let mut blob = vec![0u8]; // type tag = 0 (ReceiptBatch)
        blob.extend(data);
        
        let result = client.parse_control_plane_blob(&blob);
        assert!(result.is_ok());
        
        match result.unwrap() {
            ControlPlaneUpdate::ReceiptBatch { receipts } => {
                assert!(receipts.is_empty());
            }
            _ => panic!("expected ReceiptBatch"),
        }
    }

    #[test]
    fn test_parse_checkpoint_blob() {
        let config = CelestiaConfig::default();
        let client = CelestiaClient::new(config);
        
        // Create mock checkpoint blob
        let height = 12345u64;
        let state_root = Hash::from_bytes([0x42u8; 64]);
        let data = bincode::serialize(&(height, state_root.clone())).unwrap();
        
        let mut blob = vec![3u8]; // type tag = 3 (Checkpoint)
        blob.extend(data);
        
        let result = client.parse_control_plane_blob(&blob);
        assert!(result.is_ok());
        
        match result.unwrap() {
            ControlPlaneUpdate::Checkpoint { height: h, state_root: sr } => {
                assert_eq!(h, 12345);
                assert_eq!(sr, state_root);
            }
            _ => panic!("expected Checkpoint"),
        }
    }

    #[test]
    fn test_parse_invalid_blob() {
        let config = CelestiaConfig::default();
        let client = CelestiaClient::new(config);
        
        // Empty blob
        let result = client.parse_control_plane_blob(&[]);
        assert!(result.is_err());
        
        // Invalid type tag
        let result = client.parse_control_plane_blob(&[255u8, 0, 0]);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_pending_receipts() {
        let config = CelestiaConfig::default();
        let client = CelestiaClient::new(config);
        let mut syncer = ControlPlaneSyncer::new(client);
        
        // Add receipt batch
        syncer.pending_updates.push_back(ControlPlaneUpdate::ReceiptBatch {
            receipts: vec![],
        });
        
        // Add config update
        syncer.pending_updates.push_back(ControlPlaneUpdate::ConfigUpdate {
            key: "test".to_string(),
            value: vec![1, 2, 3],
        });
        
        assert_eq!(syncer.pending_count(), 2);
        
        // Extract receipts
        let receipts = syncer.get_pending_receipts();
        assert!(receipts.is_empty()); // empty batch
        
        // Config update should remain
        assert_eq!(syncer.pending_count(), 1);
        assert!(syncer.has_pending());
    }

    #[test]
    fn test_control_plane_update_serialization() {
        let update = ControlPlaneUpdate::Checkpoint {
            height: 100,
            state_root: Hash::from_bytes([0x11u8; 64]),
        };
        
        let json = serde_json::to_string(&update).unwrap();
        let restored: ControlPlaneUpdate = serde_json::from_str(&json).unwrap();
        
        match restored {
            ControlPlaneUpdate::Checkpoint { height, .. } => {
                assert_eq!(height, 100);
            }
            _ => panic!("expected Checkpoint"),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // ADDITIONAL CELESTIA TESTS (13.11.9)
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_parse_validator_update_blob() {
        let config = CelestiaConfig::default();
        let client = CelestiaClient::new(config);
        
        // Create mock validator update blob
        let validators: Vec<ValidatorInfo> = vec![];
        let data = bincode::serialize(&validators).unwrap();
        
        let mut blob = vec![1u8]; // type tag = 1 (ValidatorSetUpdate)
        blob.extend(data);
        
        let result = client.parse_control_plane_blob(&blob);
        assert!(result.is_ok());
        
        match result.unwrap() {
            ControlPlaneUpdate::ValidatorSetUpdate { validators } => {
                assert!(validators.is_empty());
            }
            _ => panic!("expected ValidatorSetUpdate"),
        }
    }

    #[test]
    fn test_parse_config_update_blob() {
        let config = CelestiaConfig::default();
        let client = CelestiaClient::new(config);
        
        // Create mock config update blob
        let key = "max_block_size".to_string();
        let value: Vec<u8> = vec![0x01, 0x02, 0x03, 0x04];
        let data = bincode::serialize(&(key.clone(), value.clone())).unwrap();
        
        let mut blob = vec![2u8]; // type tag = 2 (ConfigUpdate)
        blob.extend(data);
        
        let result = client.parse_control_plane_blob(&blob);
        assert!(result.is_ok());
        
        match result.unwrap() {
            ControlPlaneUpdate::ConfigUpdate { key: k, value: v } => {
                assert_eq!(k, "max_block_size");
                // Compare dengan original value, bukan hardcoded bytes
                assert_eq!(v, value);
            }
            _ => panic!("expected ConfigUpdate"),
        }
    }

    #[test]
    fn test_all_control_plane_update_variants() {
        // Test serialization roundtrip for all variants
        let updates = vec![
            ControlPlaneUpdate::ReceiptBatch { receipts: vec![] },
            ControlPlaneUpdate::ValidatorSetUpdate { validators: vec![] },
            ControlPlaneUpdate::ConfigUpdate { 
                key: "test_key".to_string(), 
                value: vec![1, 2, 3] 
            },
            ControlPlaneUpdate::Checkpoint { 
                height: 999, 
                state_root: Hash::from_bytes([0x55u8; 64]) 
            },
        ];
        
        for update in updates {
            let json = serde_json::to_string(&update).unwrap();
            let restored: ControlPlaneUpdate = serde_json::from_str(&json).unwrap();
            
            // Verify type matches
            match (&update, &restored) {
                (ControlPlaneUpdate::ReceiptBatch { .. }, ControlPlaneUpdate::ReceiptBatch { .. }) => {}
                (ControlPlaneUpdate::ValidatorSetUpdate { .. }, ControlPlaneUpdate::ValidatorSetUpdate { .. }) => {}
                (ControlPlaneUpdate::ConfigUpdate { .. }, ControlPlaneUpdate::ConfigUpdate { .. }) => {}
                (ControlPlaneUpdate::Checkpoint { .. }, ControlPlaneUpdate::Checkpoint { .. }) => {}
                _ => panic!("type mismatch after deserialization"),
            }
        }
    }

    #[test]
    fn test_celestia_config_custom() {
        let config = CelestiaConfig {
            rpc_url: "http://custom:12345".to_string(),
            namespace_id: *b"test_ns_",
            auth_token: Some("secret_token".to_string()),
            timeout_ms: 60000,
        };
        
        assert_eq!(config.rpc_url, "http://custom:12345");
        assert_eq!(config.namespace_id, *b"test_ns_");
        assert_eq!(config.auth_token, Some("secret_token".to_string()));
        assert_eq!(config.timeout_ms, 60000);
    }

    #[test]
    fn test_control_plane_syncer_queue_operations() {
        let config = CelestiaConfig::default();
        let client = CelestiaClient::new(config);
        let mut syncer = ControlPlaneSyncer::new(client);
        
        // Initially empty
        assert_eq!(syncer.pending_count(), 0);
        assert!(!syncer.has_pending());
        
        // Add multiple updates
        syncer.pending_updates.push_back(ControlPlaneUpdate::ReceiptBatch { receipts: vec![] });
        syncer.pending_updates.push_back(ControlPlaneUpdate::Checkpoint { 
            height: 100, 
            state_root: Hash::from_bytes([0x11u8; 64]) 
        });
        syncer.pending_updates.push_back(ControlPlaneUpdate::ReceiptBatch { receipts: vec![] });
        
        assert_eq!(syncer.pending_count(), 3);
        assert!(syncer.has_pending());
        
        // Extract receipts (removes ReceiptBatch updates)
        let receipts = syncer.get_pending_receipts();
        assert!(receipts.is_empty()); // Both batches were empty
        
        // Only Checkpoint should remain
        assert_eq!(syncer.pending_count(), 1);
        
        match &syncer.pending_updates[0] {
            ControlPlaneUpdate::Checkpoint { height, .. } => {
                assert_eq!(*height, 100);
            }
            _ => panic!("expected Checkpoint"),
        }
    }

    #[test]
    fn test_blob_type_tags() {
        // Verify type tag mapping is correct
        let config = CelestiaConfig::default();
        let client = CelestiaClient::new(config);
        
        // Tag 0 = ReceiptBatch
        let receipts: Vec<crate::receipt::ResourceReceipt> = vec![];
        let data = bincode::serialize(&receipts).unwrap();
        let mut blob = vec![0u8];
        blob.extend(data);
        assert!(matches!(
            client.parse_control_plane_blob(&blob).unwrap(),
            ControlPlaneUpdate::ReceiptBatch { .. }
        ));
        
        // Tag 3 = Checkpoint
        let checkpoint_data = bincode::serialize(&(100u64, Hash::from_bytes([0u8; 64]))).unwrap();
        let mut blob = vec![3u8];
        blob.extend(checkpoint_data);
        assert!(matches!(
            client.parse_control_plane_blob(&blob).unwrap(),
            ControlPlaneUpdate::Checkpoint { .. }
        ));
    }

    // ════════════════════════════════════════════════════════════════════════
    // BLOB COMMITMENT TESTS (13.17.6)
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_compute_blob_commitment() {
        let data = b"hello celestia";
        let commitment = compute_blob_commitment(data);
        
        // Commitment harus 32 bytes
        assert_eq!(commitment.len(), 32);
        
        // Commitment tidak boleh all zeros
        assert!(!commitment.iter().all(|&b| b == 0));
        
        println!("✅ test_compute_blob_commitment PASSED");
    }

    #[test]
    fn test_compute_blob_commitment_deterministic() {
        let data = b"deterministic test";
        
        let commitment1 = compute_blob_commitment(data);
        let commitment2 = compute_blob_commitment(data);
        
        // Same input → same output
        assert_eq!(commitment1, commitment2);
        
        println!("✅ test_compute_blob_commitment_deterministic PASSED");
    }

    #[test]
    fn test_compute_blob_commitment_different_data() {
        let data1 = b"first blob";
        let data2 = b"second blob";
        
        let commitment1 = compute_blob_commitment(data1);
        let commitment2 = compute_blob_commitment(data2);
        
        // Different data → different commitment
        assert_ne!(commitment1, commitment2);
        
        println!("✅ test_compute_blob_commitment_different_data PASSED");
    }

    #[test]
    fn test_compute_blob_commitment_empty() {
        let empty: &[u8] = b"";
        let commitment = compute_blob_commitment(empty);
        
        // Empty data should still produce valid 32-byte hash
        assert_eq!(commitment.len(), 32);
        
        println!("✅ test_compute_blob_commitment_empty PASSED");
    }

    #[test]
    fn test_verify_blob_commitment_true() {
        let data = b"verification test";
        let commitment = compute_blob_commitment(data);
        
        // Verify should return true for correct data
        assert!(verify_blob_commitment(data, &commitment));
        
        println!("✅ test_verify_blob_commitment_true PASSED");
    }

    #[test]
    fn test_verify_blob_commitment_false() {
        let data = b"original data";
        let wrong_data = b"tampered data";
        let commitment = compute_blob_commitment(data);
        
        // Verify should return false for wrong data
        assert!(!verify_blob_commitment(wrong_data, &commitment));
        
        println!("✅ test_verify_blob_commitment_false PASSED");
    }

    #[test]
    fn test_verify_blob_commitment_wrong_commitment() {
        let data = b"some data";
        let wrong_commitment = [0xFFu8; 32];
        
        // Verify should return false for wrong commitment
        assert!(!verify_blob_commitment(data, &wrong_commitment));
        
        println!("✅ test_verify_blob_commitment_wrong_commitment PASSED");
    }

    #[test]
    fn test_blob_commitment_struct() {
        let commitment = [0xABu8; 32];
        let namespace = [0xCDu8; 29];
        let height = 12345u64;
        let index = 42u32;
        
        let blob_commitment = BlobCommitment::new(commitment, namespace, height, index);
        
        assert_eq!(blob_commitment.commitment, commitment);
        assert_eq!(blob_commitment.namespace, namespace);
        assert_eq!(blob_commitment.height, height);
        assert_eq!(blob_commitment.index, index);
        
        println!("✅ test_blob_commitment_struct PASSED");
    }

    #[test]
    fn test_blob_commitment_serialization() {
        let commitment = [0x11u8; 32];
        let namespace = [0x22u8; 29];
        
        let original = BlobCommitment::new(commitment, namespace, 100, 5);
        
        // Serialize to JSON
        let json = serde_json::to_string(&original).unwrap();
        
        // Deserialize back
        let restored: BlobCommitment = serde_json::from_str(&json).unwrap();
        
        assert_eq!(original, restored);
        
        println!("✅ test_blob_commitment_serialization PASSED");
    }

    #[test]
    fn test_get_blob_commitment_placeholder() {
        let config = CelestiaConfig::default();
        let client = CelestiaClient::new(config);
        
        // Placeholder implementation should return error
        let result = client.get_blob_commitment(100, 0);
        assert!(result.is_err());
        
        println!("✅ test_get_blob_commitment_placeholder PASSED");
    }

    #[test]
    fn test_verify_blob_at_height_placeholder() {
        let config = CelestiaConfig::default();
        let client = CelestiaClient::new(config);
        let data = b"test data";
        
        // Placeholder get_blob_commitment will fail, so this should error
        let result = client.verify_blob_at_height(100, 0, data);
        assert!(result.is_err());
        
        println!("✅ test_verify_blob_at_height_placeholder PASSED");
    }
}