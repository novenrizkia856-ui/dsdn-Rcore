//! # Receipt Data
//!
//! Module ini menyediakan `ReceiptData` struct yang merepresentasikan
//! data yang akan di-sign dalam sistem receipt DSDN.
//!
//! ## Struktur
//!
//! | Field | Type | Deskripsi |
//! |-------|------|-----------|
//! | `workload_id` | `WorkloadId` | Identifier workload/task |
//! | `blob_hash` | `[u8; 32]` | Hash dari blob data |
//! | `placement` | `Vec<NodeId>` | Daftar node placement |
//! | `timestamp` | `Timestamp` | Waktu pembuatan receipt |
//! | `sequence` | `u64` | Nomor urut receipt |
//! | `epoch` | `u64` | Nomor epoch |
//!
//! ## Hashing
//!
//! `receipt_data_hash()` menghasilkan hash SHA3-256 deterministik yang:
//! - Berubah jika ANY field berubah
//! - Urutan placement mempengaruhi hash
//! - Tidak tergantung alamat memori atau Vec capacity
//!
//! ## Encoding
//!
//! - `to_bytes()` / `from_bytes()` menggunakan bincode
//! - Roundtrip-safe
//! - Tidak ada silent truncation
//!
//! ## KRITIS
//!
//! Ini adalah MESSAGE YANG AKAN DISIGN.
//! Kesalahan hashing = kegagalan kriptografis sistem.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use super::{Timestamp, WorkloadId};

// ════════════════════════════════════════════════════════════════════════════════
// NODE ID TYPE
// ════════════════════════════════════════════════════════════════════════════════

/// Identifier unik untuk storage node.
///
/// 32-byte array yang mengidentifikasi node dalam placement.
pub type NodeId = [u8; 32];

// ════════════════════════════════════════════════════════════════════════════════
// DECODE ERROR
// ════════════════════════════════════════════════════════════════════════════════

/// Error type untuk decoding `ReceiptData`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Data input terlalu pendek.
    InsufficientData {
        /// Jumlah bytes yang diharapkan minimum.
        expected_min: usize,
        /// Jumlah bytes yang diterima.
        got: usize,
    },

    /// Error saat deserialize bincode.
    BincodeError(String),

    /// Format data tidak valid.
    InvalidFormat(String),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::InsufficientData { expected_min, got } => {
                write!(
                    f,
                    "insufficient data: expected at least {} bytes, got {}",
                    expected_min, got
                )
            }
            DecodeError::BincodeError(msg) => {
                write!(f, "bincode decode error: {}", msg)
            }
            DecodeError::InvalidFormat(msg) => {
                write!(f, "invalid format: {}", msg)
            }
        }
    }
}

impl std::error::Error for DecodeError {}

// ════════════════════════════════════════════════════════════════════════════════
// RECEIPT DATA
// ════════════════════════════════════════════════════════════════════════════════

/// Data yang akan di-sign untuk receipt.
///
/// `ReceiptData` merepresentasikan konten yang di-sign oleh coordinator
/// committee untuk menghasilkan receipt yang valid.
///
/// ## Immutability
///
/// Setelah construction, semua fields bersifat immutable.
/// Untuk mengubah data, buat instance baru.
///
/// ## Hash Determinism
///
/// `receipt_data_hash()` menghasilkan hash yang:
/// - Deterministik untuk data yang sama
/// - Berbeda untuk data yang berbeda
/// - Sensitif terhadap urutan placement
///
/// ## Contoh
///
/// ```rust,ignore
/// use dsdn_common::{ReceiptData, WorkloadId};
///
/// let receipt = ReceiptData::new(
///     WorkloadId::new([0x01; 32]),
///     [0x02; 32],              // blob_hash
///     vec![[0x03; 32]],        // placement
///     1700000000,              // timestamp
///     1,                       // sequence
///     1,                       // epoch
/// );
///
/// let hash = receipt.receipt_data_hash();
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptData {
    /// Identifier workload/task.
    workload_id: WorkloadId,

    /// Hash dari blob data (32 bytes).
    blob_hash: [u8; 32],

    /// Daftar node placement.
    placement: Vec<NodeId>,

    /// Timestamp pembuatan receipt (Unix seconds).
    timestamp: Timestamp,

    /// Nomor urut receipt.
    sequence: u64,

    /// Nomor epoch.
    epoch: u64,
}

impl ReceiptData {
    /// Membuat `ReceiptData` baru.
    ///
    /// # Arguments
    ///
    /// * `workload_id` - Identifier workload
    /// * `blob_hash` - Hash dari blob data
    /// * `placement` - Daftar node placement
    /// * `timestamp` - Timestamp pembuatan
    /// * `sequence` - Nomor urut
    /// * `epoch` - Nomor epoch
    ///
    /// # Returns
    ///
    /// `ReceiptData` baru dengan field yang diberikan.
    ///
    /// # Note
    ///
    /// Constructor TIDAK melakukan validasi implisit.
    /// Semua field di-assign langsung.
    #[must_use]
    pub fn new(
        workload_id: WorkloadId,
        blob_hash: [u8; 32],
        placement: Vec<NodeId>,
        timestamp: Timestamp,
        sequence: u64,
        epoch: u64,
    ) -> Self {
        Self {
            workload_id,
            blob_hash,
            placement,
            timestamp,
            sequence,
            epoch,
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // GETTERS
    // ────────────────────────────────────────────────────────────────────────────

    /// Mengembalikan reference ke workload ID.
    #[must_use]
    #[inline]
    pub const fn workload_id(&self) -> &WorkloadId {
        &self.workload_id
    }

    /// Mengembalikan reference ke blob hash.
    #[must_use]
    #[inline]
    pub const fn blob_hash(&self) -> &[u8; 32] {
        &self.blob_hash
    }

    /// Mengembalikan reference ke placement slice.
    #[must_use]
    #[inline]
    pub fn placement(&self) -> &[NodeId] {
        &self.placement
    }

    /// Mengembalikan timestamp.
    #[must_use]
    #[inline]
    pub const fn timestamp(&self) -> Timestamp {
        self.timestamp
    }

    /// Mengembalikan sequence number.
    #[must_use]
    #[inline]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Mengembalikan epoch number.
    #[must_use]
    #[inline]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    // ────────────────────────────────────────────────────────────────────────────
    // HASH COMPUTATION
    // ────────────────────────────────────────────────────────────────────────────

    /// Menghitung hash deterministik dari receipt data.
    ///
    /// Hash mencakup SEMUA fields dalam urutan:
    /// 1. workload_id (32 bytes)
    /// 2. blob_hash (32 bytes)
    /// 3. placement_count (8 bytes, little-endian)
    /// 4. placement nodes (32 bytes each, dalam urutan)
    /// 5. timestamp (8 bytes, little-endian)
    /// 6. sequence (8 bytes, little-endian)
    /// 7. epoch (8 bytes, little-endian)
    ///
    /// # Returns
    ///
    /// SHA3-256 hash (32 bytes).
    ///
    /// # Determinism
    ///
    /// - Hash sama untuk data yang sama
    /// - Hash berbeda untuk data yang berbeda
    /// - Urutan placement mempengaruhi hash
    /// - Tidak bergantung alamat memori atau Vec capacity
    ///
    /// # KRITIS
    ///
    /// Ini adalah message yang akan di-sign.
    /// Perubahan pada fungsi ini akan break signature verification.
    #[must_use]
    pub fn receipt_data_hash(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();

        // 1. workload_id (32 bytes)
        hasher.update(self.workload_id.as_bytes());

        // 2. blob_hash (32 bytes)
        hasher.update(&self.blob_hash);

        // 3. placement_count (8 bytes, little-endian)
        // Use u64 for consistent size regardless of platform
        let placement_count = self.placement.len() as u64;
        hasher.update(placement_count.to_le_bytes());

        // 4. placement nodes (32 bytes each, in order)
        for node_id in &self.placement {
            hasher.update(node_id);
        }

        // 5. timestamp (8 bytes, little-endian)
        hasher.update(self.timestamp.to_le_bytes());

        // 6. sequence (8 bytes, little-endian)
        hasher.update(self.sequence.to_le_bytes());

        // 7. epoch (8 bytes, little-endian)
        hasher.update(self.epoch.to_le_bytes());

        // Finalize and return
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    // ────────────────────────────────────────────────────────────────────────────
    // ENCODING
    // ────────────────────────────────────────────────────────────────────────────

    /// Serialize receipt data ke bytes.
    ///
    /// Menggunakan bincode untuk encoding stabil.
    ///
    /// # Returns
    ///
    /// Vec<u8> berisi serialized data.
    ///
    /// # Note
    ///
    /// Roundtrip-safe: `from_bytes(to_bytes())` == original
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        // bincode::serialize should not fail for valid ReceiptData
        // but we handle it gracefully anyway
        bincode::serialize(self).unwrap_or_else(|_| {
            // Fallback: manual encoding if bincode fails
            // This should never happen for valid data
            let mut bytes = Vec::new();
            bytes.extend_from_slice(self.workload_id.as_bytes());
            bytes.extend_from_slice(&self.blob_hash);
            bytes.extend_from_slice(&(self.placement.len() as u64).to_le_bytes());
            for node_id in &self.placement {
                bytes.extend_from_slice(node_id);
            }
            bytes.extend_from_slice(&self.timestamp.to_le_bytes());
            bytes.extend_from_slice(&self.sequence.to_le_bytes());
            bytes.extend_from_slice(&self.epoch.to_le_bytes());
            bytes
        })
    }

    /// Deserialize receipt data dari bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Serialized data
    ///
    /// # Errors
    ///
    /// - `DecodeError::InsufficientData` jika data terlalu pendek
    /// - `DecodeError::BincodeError` jika bincode decode gagal
    ///
    /// # Note
    ///
    /// Roundtrip-safe dengan `to_bytes()`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        // Minimum size check (rough estimate)
        // workload_id(32) + blob_hash(32) + timestamp(8) + sequence(8) + epoch(8) = 88
        // Plus placement length encoding
        if bytes.len() < 88 {
            return Err(DecodeError::InsufficientData {
                expected_min: 88,
                got: bytes.len(),
            });
        }

        bincode::deserialize(bytes).map_err(|e| DecodeError::BincodeError(e.to_string()))
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ────────────────────────────────────────────────────────────────────────────
    // HELPER FUNCTIONS
    // ────────────────────────────────────────────────────────────────────────────

    fn make_workload_id(byte: u8) -> WorkloadId {
        WorkloadId::new([byte; 32])
    }

    fn make_node_id(byte: u8) -> NodeId {
        [byte; 32]
    }

    fn make_receipt() -> ReceiptData {
        ReceiptData::new(
            make_workload_id(0x01),
            [0x02; 32],
            vec![make_node_id(0x03), make_node_id(0x04)],
            1700000000,
            1,
            1,
        )
    }

    // ────────────────────────────────────────────────────────────────────────────
    // DECODE ERROR TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_decode_error_insufficient_data_display() {
        let err = DecodeError::InsufficientData {
            expected_min: 88,
            got: 10,
        };
        let msg = err.to_string();
        assert!(msg.contains("88"));
        assert!(msg.contains("10"));
    }

    #[test]
    fn test_decode_error_bincode_error_display() {
        let err = DecodeError::BincodeError("test error".to_string());
        let msg = err.to_string();
        assert!(msg.contains("test error"));
    }

    #[test]
    fn test_decode_error_invalid_format_display() {
        let err = DecodeError::InvalidFormat("bad format".to_string());
        let msg = err.to_string();
        assert!(msg.contains("bad format"));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // CONSTRUCTOR TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_new_creates_receipt_data() {
        let receipt = make_receipt();

        assert_eq!(receipt.workload_id().as_bytes(), &[0x01; 32]);
        assert_eq!(receipt.blob_hash(), &[0x02; 32]);
        assert_eq!(receipt.placement().len(), 2);
        assert_eq!(receipt.timestamp(), 1700000000);
        assert_eq!(receipt.sequence(), 1);
        assert_eq!(receipt.epoch(), 1);
    }

    #[test]
    fn test_new_empty_placement() {
        let receipt = ReceiptData::new(
            make_workload_id(0x01),
            [0x02; 32],
            vec![],
            1700000000,
            1,
            1,
        );

        assert!(receipt.placement().is_empty());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // GETTER TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_getters_return_correct_values() {
        let receipt = make_receipt();

        assert_eq!(receipt.workload_id().as_bytes(), &[0x01; 32]);
        assert_eq!(receipt.blob_hash(), &[0x02; 32]);
        assert_eq!(receipt.placement()[0], make_node_id(0x03));
        assert_eq!(receipt.placement()[1], make_node_id(0x04));
        assert_eq!(receipt.timestamp(), 1700000000);
        assert_eq!(receipt.sequence(), 1);
        assert_eq!(receipt.epoch(), 1);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // HASH TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_receipt_data_hash_deterministic() {
        let receipt = make_receipt();

        let hash1 = receipt.receipt_data_hash();
        let hash2 = receipt.receipt_data_hash();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_receipt_data_hash_different_workload_id() {
        let receipt1 = make_receipt();
        let receipt2 = ReceiptData::new(
            make_workload_id(0xFF), // Different
            [0x02; 32],
            vec![make_node_id(0x03), make_node_id(0x04)],
            1700000000,
            1,
            1,
        );

        assert_ne!(receipt1.receipt_data_hash(), receipt2.receipt_data_hash());
    }

    #[test]
    fn test_receipt_data_hash_different_blob_hash() {
        let receipt1 = make_receipt();
        let receipt2 = ReceiptData::new(
            make_workload_id(0x01),
            [0xFF; 32], // Different
            vec![make_node_id(0x03), make_node_id(0x04)],
            1700000000,
            1,
            1,
        );

        assert_ne!(receipt1.receipt_data_hash(), receipt2.receipt_data_hash());
    }

    #[test]
    fn test_receipt_data_hash_different_placement() {
        let receipt1 = make_receipt();
        let receipt2 = ReceiptData::new(
            make_workload_id(0x01),
            [0x02; 32],
            vec![make_node_id(0xFF)], // Different
            1700000000,
            1,
            1,
        );

        assert_ne!(receipt1.receipt_data_hash(), receipt2.receipt_data_hash());
    }

    #[test]
    fn test_receipt_data_hash_placement_order_matters() {
        let receipt1 = ReceiptData::new(
            make_workload_id(0x01),
            [0x02; 32],
            vec![make_node_id(0x03), make_node_id(0x04)],
            1700000000,
            1,
            1,
        );
        let receipt2 = ReceiptData::new(
            make_workload_id(0x01),
            [0x02; 32],
            vec![make_node_id(0x04), make_node_id(0x03)], // Reversed order
            1700000000,
            1,
            1,
        );

        assert_ne!(receipt1.receipt_data_hash(), receipt2.receipt_data_hash());
    }

    #[test]
    fn test_receipt_data_hash_different_timestamp() {
        let receipt1 = make_receipt();
        let receipt2 = ReceiptData::new(
            make_workload_id(0x01),
            [0x02; 32],
            vec![make_node_id(0x03), make_node_id(0x04)],
            1700000001, // Different
            1,
            1,
        );

        assert_ne!(receipt1.receipt_data_hash(), receipt2.receipt_data_hash());
    }

    #[test]
    fn test_receipt_data_hash_different_sequence() {
        let receipt1 = make_receipt();
        let receipt2 = ReceiptData::new(
            make_workload_id(0x01),
            [0x02; 32],
            vec![make_node_id(0x03), make_node_id(0x04)],
            1700000000,
            2, // Different
            1,
        );

        assert_ne!(receipt1.receipt_data_hash(), receipt2.receipt_data_hash());
    }

    #[test]
    fn test_receipt_data_hash_different_epoch() {
        let receipt1 = make_receipt();
        let receipt2 = ReceiptData::new(
            make_workload_id(0x01),
            [0x02; 32],
            vec![make_node_id(0x03), make_node_id(0x04)],
            1700000000,
            1,
            2, // Different
        );

        assert_ne!(receipt1.receipt_data_hash(), receipt2.receipt_data_hash());
    }

    #[test]
    fn test_receipt_data_hash_empty_placement() {
        let receipt1 = ReceiptData::new(
            make_workload_id(0x01),
            [0x02; 32],
            vec![],
            1700000000,
            1,
            1,
        );
        let receipt2 = ReceiptData::new(
            make_workload_id(0x01),
            [0x02; 32],
            vec![make_node_id(0x03)],
            1700000000,
            1,
            1,
        );

        assert_ne!(receipt1.receipt_data_hash(), receipt2.receipt_data_hash());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // ENCODING TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_to_bytes_from_bytes_roundtrip() {
        let original = make_receipt();

        let bytes = original.to_bytes();
        let decoded = ReceiptData::from_bytes(&bytes).expect("decode");

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_to_bytes_from_bytes_roundtrip_empty_placement() {
        let original = ReceiptData::new(
            make_workload_id(0x01),
            [0x02; 32],
            vec![],
            1700000000,
            1,
            1,
        );

        let bytes = original.to_bytes();
        let decoded = ReceiptData::from_bytes(&bytes).expect("decode");

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_to_bytes_from_bytes_roundtrip_large_placement() {
        let placement: Vec<NodeId> = (0u8..10).map(make_node_id).collect();
        let original = ReceiptData::new(
            make_workload_id(0x01),
            [0x02; 32],
            placement,
            1700000000,
            1,
            1,
        );

        let bytes = original.to_bytes();
        let decoded = ReceiptData::from_bytes(&bytes).expect("decode");

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_from_bytes_insufficient_data() {
        let bytes = [0u8; 10]; // Too short

        let result = ReceiptData::from_bytes(&bytes);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DecodeError::InsufficientData { .. }
        ));
    }

    #[test]
    fn test_from_bytes_invalid_data() {
        let bytes = [0xFFu8; 100]; // Invalid bincode data

        let result = ReceiptData::from_bytes(&bytes);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DecodeError::BincodeError(_)));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SERIALIZATION TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_serde_json_roundtrip() {
        let original = make_receipt();

        let serialized = serde_json::to_string(&original).expect("serialize");
        let deserialized: ReceiptData = serde_json::from_str(&serialized).expect("deserialize");

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_serde_bincode_roundtrip() {
        let original = make_receipt();

        let serialized = bincode::serialize(&original).expect("serialize");
        let deserialized: ReceiptData = bincode::deserialize(&serialized).expect("deserialize");

        assert_eq!(original, deserialized);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // CLONE TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_clone() {
        let original = make_receipt();
        let cloned = original.clone();

        assert_eq!(original, cloned);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // DEBUG TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_debug() {
        let receipt = make_receipt();
        let debug = format!("{:?}", receipt);

        assert!(debug.contains("ReceiptData"));
        assert!(debug.contains("workload_id"));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SEND + SYNC TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<ReceiptData>();
        assert_send_sync::<DecodeError>();
    }

    // ────────────────────────────────────────────────────────────────────────────
    // HASH STABILITY TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_hash_independent_of_vec_capacity() {
        let mut placement1 = vec![make_node_id(0x03)];
        placement1.reserve(100); // Extra capacity

        let placement2 = vec![make_node_id(0x03)]; // Minimal capacity

        let receipt1 = ReceiptData::new(
            make_workload_id(0x01),
            [0x02; 32],
            placement1,
            1700000000,
            1,
            1,
        );
        let receipt2 = ReceiptData::new(
            make_workload_id(0x01),
            [0x02; 32],
            placement2,
            1700000000,
            1,
            1,
        );

        // Hash should be the same despite different Vec capacities
        assert_eq!(receipt1.receipt_data_hash(), receipt2.receipt_data_hash());
    }

    #[test]
    fn test_hash_same_after_clone() {
        let original = make_receipt();
        let cloned = original.clone();

        assert_eq!(original.receipt_data_hash(), cloned.receipt_data_hash());
    }

    #[test]
    fn test_hash_same_after_roundtrip() {
        let original = make_receipt();
        let hash_before = original.receipt_data_hash();

        let bytes = original.to_bytes();
        let decoded = ReceiptData::from_bytes(&bytes).expect("decode");
        let hash_after = decoded.receipt_data_hash();

        assert_eq!(hash_before, hash_after);
    }
}