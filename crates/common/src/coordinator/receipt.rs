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

use super::{CoordinatorId, Timestamp, WorkloadId};
use dsdn_tss::AggregateSignature;

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
// THRESHOLD RECEIPT
// ════════════════════════════════════════════════════════════════════════════════

/// Final threshold receipt dengan aggregate signature.
///
/// `ThresholdReceipt` adalah container lengkap yang membawa:
/// - `receipt_data`: Data yang di-sign
/// - `aggregate_signature`: Aggregate FROST signature
/// - `signers`: Daftar CoordinatorId yang sign
/// - `epoch`: Epoch number (dari receipt_data)
/// - `committee_hash`: Hash committee saat signing
///
/// ## Immutability
///
/// Setelah construction, semua fields bersifat immutable.
/// Untuk mengubah receipt, buat instance baru.
///
/// ## Serialization
///
/// Manual Serialize/Deserialize karena `AggregateSignature` tidak
/// memiliki derive serde. Menggunakan `to_bytes()`/`from_bytes()`.
///
/// ## Contoh
///
/// ```rust,ignore
/// use dsdn_common::{ThresholdReceipt, ReceiptData, CoordinatorId, WorkloadId};
/// use dsdn_tss::AggregateSignature;
///
/// let receipt = ThresholdReceipt::new(
///     receipt_data,
///     aggregate_signature,
///     signers,
///     committee_hash,
/// );
/// ```
#[derive(Debug, Clone)]
pub struct ThresholdReceipt {
    /// Data yang di-sign.
    receipt_data: ReceiptData,

    /// Aggregate FROST signature.
    aggregate_signature: AggregateSignature,

    /// Daftar coordinator IDs yang sign.
    signers: Vec<CoordinatorId>,

    /// Epoch number (copy dari receipt_data untuk akses cepat).
    epoch: u64,

    /// Hash committee saat signing.
    committee_hash: [u8; 32],
}

impl ThresholdReceipt {
    /// Membuat `ThresholdReceipt` baru.
    ///
    /// # Arguments
    ///
    /// * `receipt_data` - Data yang di-sign
    /// * `aggregate_signature` - Aggregate FROST signature
    /// * `signers` - Daftar coordinator IDs yang sign
    /// * `committee_hash` - Hash committee saat signing
    ///
    /// # Returns
    ///
    /// `ThresholdReceipt` baru dengan epoch diambil dari `receipt_data.epoch()`.
    ///
    /// # Note
    ///
    /// Constructor TIDAK melakukan validasi implisit.
    /// Tidak menyortir signers.
    /// epoch diambil LANGSUNG dari receipt_data.
    #[must_use]
    pub fn new(
        receipt_data: ReceiptData,
        aggregate_signature: AggregateSignature,
        signers: Vec<CoordinatorId>,
        committee_hash: [u8; 32],
    ) -> Self {
        let epoch = receipt_data.epoch();
        Self {
            receipt_data,
            aggregate_signature,
            signers,
            epoch,
            committee_hash,
        }
    }

    /// Constructor alternatif dengan semua parts eksplisit.
    ///
    /// Semantik IDENTIK dengan `new()`.
    ///
    /// # Note
    ///
    /// epoch tetap diambil dari `receipt_data.epoch()`, bukan parameter terpisah.
    #[must_use]
    pub fn from_parts(
        receipt_data: ReceiptData,
        aggregate_signature: AggregateSignature,
        signers: Vec<CoordinatorId>,
        committee_hash: [u8; 32],
    ) -> Self {
        Self::new(receipt_data, aggregate_signature, signers, committee_hash)
    }

    // ────────────────────────────────────────────────────────────────────────────
    // GETTERS
    // ────────────────────────────────────────────────────────────────────────────

    /// Mengembalikan reference ke receipt data.
    #[must_use]
    #[inline]
    pub const fn receipt_data(&self) -> &ReceiptData {
        &self.receipt_data
    }

    /// Mengembalikan reference ke aggregate signature.
    #[must_use]
    #[inline]
    pub const fn aggregate_signature(&self) -> &AggregateSignature {
        &self.aggregate_signature
    }

    /// Mengembalikan slice signers.
    #[must_use]
    #[inline]
    pub fn signers(&self) -> &[CoordinatorId] {
        &self.signers
    }

    /// Mengembalikan jumlah signers.
    #[must_use]
    #[inline]
    pub fn signer_count(&self) -> usize {
        self.signers.len()
    }

    /// Mengembalikan epoch number.
    #[must_use]
    #[inline]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Mengembalikan reference ke committee hash.
    #[must_use]
    #[inline]
    pub const fn committee_hash(&self) -> &[u8; 32] {
        &self.committee_hash
    }

    // ────────────────────────────────────────────────────────────────────────────
    // CONVENIENCE METHODS (DELEGASI LANGSUNG)
    // ────────────────────────────────────────────────────────────────────────────

    /// Mengembalikan reference ke workload ID.
    ///
    /// DELEGASI LANGSUNG ke `receipt_data.workload_id()`.
    #[must_use]
    #[inline]
    pub fn workload_id(&self) -> &WorkloadId {
        self.receipt_data.workload_id()
    }

    /// Mengembalikan reference ke blob hash.
    ///
    /// DELEGASI LANGSUNG ke `receipt_data.blob_hash()`.
    #[must_use]
    #[inline]
    pub fn blob_hash(&self) -> &[u8; 32] {
        self.receipt_data.blob_hash()
    }

    /// Mengembalikan reference ke placement slice.
    ///
    /// DELEGASI LANGSUNG ke `receipt_data.placement()`.
    #[must_use]
    #[inline]
    pub fn placement(&self) -> &[NodeId] {
        self.receipt_data.placement()
    }

    /// Mengembalikan timestamp.
    ///
    /// DELEGASI LANGSUNG ke `receipt_data.timestamp()`.
    #[must_use]
    #[inline]
    pub fn timestamp(&self) -> Timestamp {
        self.receipt_data.timestamp()
    }

    /// Mengembalikan sequence number.
    ///
    /// DELEGASI LANGSUNG ke `receipt_data.sequence()`.
    #[must_use]
    #[inline]
    pub fn sequence(&self) -> u64 {
        self.receipt_data.sequence()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// MANUAL TRAIT IMPLEMENTATIONS
// ════════════════════════════════════════════════════════════════════════════════

// PartialEq: Compare all fields including aggregate_signature via bytes
impl PartialEq for ThresholdReceipt {
    fn eq(&self, other: &Self) -> bool {
        // Compare receipt_data
        if self.receipt_data != other.receipt_data {
            return false;
        }

        // Compare aggregate_signature via to_bytes()
        if self.aggregate_signature.to_bytes() != other.aggregate_signature.to_bytes() {
            return false;
        }

        // Compare signers
        if self.signers != other.signers {
            return false;
        }

        // Compare epoch
        if self.epoch != other.epoch {
            return false;
        }

        // Compare committee_hash
        self.committee_hash == other.committee_hash
    }
}

impl Eq for ThresholdReceipt {}

// Custom Serialize: Store aggregate_signature as bytes
impl Serialize for ThresholdReceipt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("ThresholdReceipt", 5)?;
        state.serialize_field("receipt_data", &self.receipt_data)?;
        state.serialize_field("aggregate_signature_bytes", &self.aggregate_signature.to_bytes())?;
        state.serialize_field("signers", &self.signers)?;
        state.serialize_field("epoch", &self.epoch)?;
        state.serialize_field("committee_hash", &self.committee_hash)?;
        state.end()
    }
}

// Custom Deserialize: Reconstruct aggregate_signature from bytes
impl<'de> Deserialize<'de> for ThresholdReceipt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, SeqAccess, Visitor};

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            ReceiptData,
            AggregateSignatureBytes,
            Signers,
            Epoch,
            CommitteeHash,
        }

        struct ThresholdReceiptVisitor;

        impl<'de> Visitor<'de> for ThresholdReceiptVisitor {
            type Value = ThresholdReceipt;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct ThresholdReceipt")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<ThresholdReceipt, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let receipt_data = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;

                let agg_sig_bytes: Vec<u8> = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;

                let aggregate_signature = AggregateSignature::from_bytes(&agg_sig_bytes)
                    .map_err(|e| de::Error::custom(format!("invalid aggregate signature: {}", e)))?;

                let signers = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(2, &self))?;

                let epoch = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(3, &self))?;

                let committee_hash = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(4, &self))?;

                Ok(ThresholdReceipt {
                    receipt_data,
                    aggregate_signature,
                    signers,
                    epoch,
                    committee_hash,
                })
            }

            fn visit_map<V>(self, mut map: V) -> Result<ThresholdReceipt, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut receipt_data = None;
                let mut agg_sig_bytes: Option<Vec<u8>> = None;
                let mut signers = None;
                let mut epoch = None;
                let mut committee_hash = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::ReceiptData => {
                            if receipt_data.is_some() {
                                return Err(de::Error::duplicate_field("receipt_data"));
                            }
                            receipt_data = Some(map.next_value()?);
                        }
                        Field::AggregateSignatureBytes => {
                            if agg_sig_bytes.is_some() {
                                return Err(de::Error::duplicate_field("aggregate_signature_bytes"));
                            }
                            agg_sig_bytes = Some(map.next_value()?);
                        }
                        Field::Signers => {
                            if signers.is_some() {
                                return Err(de::Error::duplicate_field("signers"));
                            }
                            signers = Some(map.next_value()?);
                        }
                        Field::Epoch => {
                            if epoch.is_some() {
                                return Err(de::Error::duplicate_field("epoch"));
                            }
                            epoch = Some(map.next_value()?);
                        }
                        Field::CommitteeHash => {
                            if committee_hash.is_some() {
                                return Err(de::Error::duplicate_field("committee_hash"));
                            }
                            committee_hash = Some(map.next_value()?);
                        }
                    }
                }

                let receipt_data =
                    receipt_data.ok_or_else(|| de::Error::missing_field("receipt_data"))?;
                let agg_sig_bytes = agg_sig_bytes
                    .ok_or_else(|| de::Error::missing_field("aggregate_signature_bytes"))?;
                let signers = signers.ok_or_else(|| de::Error::missing_field("signers"))?;
                let epoch = epoch.ok_or_else(|| de::Error::missing_field("epoch"))?;
                let committee_hash =
                    committee_hash.ok_or_else(|| de::Error::missing_field("committee_hash"))?;

                let aggregate_signature = AggregateSignature::from_bytes(&agg_sig_bytes)
                    .map_err(|e| de::Error::custom(format!("invalid aggregate signature: {}", e)))?;

                Ok(ThresholdReceipt {
                    receipt_data,
                    aggregate_signature,
                    signers,
                    epoch,
                    committee_hash,
                })
            }
        }

        const FIELDS: &[&str] = &[
            "receipt_data",
            "aggregate_signature_bytes",
            "signers",
            "epoch",
            "committee_hash",
        ];
        deserializer.deserialize_struct("ThresholdReceipt", FIELDS, ThresholdReceiptVisitor)
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

    // ════════════════════════════════════════════════════════════════════════════
    // THRESHOLD RECEIPT TESTS
    // ════════════════════════════════════════════════════════════════════════════

    // Helper untuk membuat AggregateSignature untuk testing
    fn make_aggregate_signature() -> AggregateSignature {
        use dsdn_tss::{FrostSignature, SignerId};

        let sig = FrostSignature::from_bytes([0x42; 64]).expect("valid signature");
        let signers = vec![
            SignerId::from_bytes([0x01; 32]),
            SignerId::from_bytes([0x02; 32]),
        ];
        let message_hash = [0xAA; 32];

        AggregateSignature::new(sig, signers, message_hash)
    }

    fn make_coordinator_id(byte: u8) -> CoordinatorId {
        CoordinatorId::new([byte; 32])
    }

    fn make_threshold_receipt() -> ThresholdReceipt {
        let receipt_data = make_receipt();
        let aggregate_signature = make_aggregate_signature();
        let signers = vec![make_coordinator_id(0x01), make_coordinator_id(0x02)];
        let committee_hash = [0xCC; 32];

        ThresholdReceipt::new(receipt_data, aggregate_signature, signers, committee_hash)
    }

    // ────────────────────────────────────────────────────────────────────────────
    // THRESHOLD RECEIPT CONSTRUCTOR TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_threshold_receipt_new() {
        let receipt = make_threshold_receipt();

        assert_eq!(receipt.epoch(), 1); // From receipt_data
        assert_eq!(receipt.committee_hash(), &[0xCC; 32]);
        assert_eq!(receipt.signer_count(), 2);
    }

    #[test]
    fn test_threshold_receipt_from_parts_identical_to_new() {
        let receipt_data = make_receipt();
        let aggregate_signature = make_aggregate_signature();
        let signers = vec![make_coordinator_id(0x01), make_coordinator_id(0x02)];
        let committee_hash = [0xCC; 32];

        let via_new = ThresholdReceipt::new(
            receipt_data.clone(),
            aggregate_signature.clone(),
            signers.clone(),
            committee_hash,
        );
        let via_from_parts = ThresholdReceipt::from_parts(
            receipt_data,
            aggregate_signature,
            signers,
            committee_hash,
        );

        assert_eq!(via_new, via_from_parts);
    }

    #[test]
    fn test_threshold_receipt_epoch_from_receipt_data() {
        let receipt_data = ReceiptData::new(
            make_workload_id(0x01),
            [0x02; 32],
            vec![],
            1700000000,
            1,
            42, // epoch = 42
        );
        let aggregate_signature = make_aggregate_signature();
        let signers = vec![];
        let committee_hash = [0x00; 32];

        let receipt = ThresholdReceipt::new(receipt_data, aggregate_signature, signers, committee_hash);

        assert_eq!(receipt.epoch(), 42);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // THRESHOLD RECEIPT GETTER TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_threshold_receipt_getters() {
        let receipt = make_threshold_receipt();

        // Basic getters
        assert_eq!(receipt.epoch(), 1);
        assert_eq!(receipt.committee_hash(), &[0xCC; 32]);
        assert_eq!(receipt.signer_count(), 2);
        assert_eq!(receipt.signers().len(), 2);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // THRESHOLD RECEIPT CONVENIENCE METHOD TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_threshold_receipt_workload_id_delegates() {
        let receipt = make_threshold_receipt();
        assert_eq!(receipt.workload_id(), receipt.receipt_data().workload_id());
    }

    #[test]
    fn test_threshold_receipt_blob_hash_delegates() {
        let receipt = make_threshold_receipt();
        assert_eq!(receipt.blob_hash(), receipt.receipt_data().blob_hash());
    }

    #[test]
    fn test_threshold_receipt_placement_delegates() {
        let receipt = make_threshold_receipt();
        assert_eq!(receipt.placement(), receipt.receipt_data().placement());
    }

    #[test]
    fn test_threshold_receipt_timestamp_delegates() {
        let receipt = make_threshold_receipt();
        assert_eq!(receipt.timestamp(), receipt.receipt_data().timestamp());
    }

    #[test]
    fn test_threshold_receipt_sequence_delegates() {
        let receipt = make_threshold_receipt();
        assert_eq!(receipt.sequence(), receipt.receipt_data().sequence());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // THRESHOLD RECEIPT EQUALITY TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_threshold_receipt_eq_identical() {
        let receipt1 = make_threshold_receipt();
        let receipt2 = make_threshold_receipt();

        assert_eq!(receipt1, receipt2);
    }

    #[test]
    fn test_threshold_receipt_ne_different_committee_hash() {
        let receipt1 = make_threshold_receipt();

        let receipt_data = make_receipt();
        let aggregate_signature = make_aggregate_signature();
        let signers = vec![make_coordinator_id(0x01), make_coordinator_id(0x02)];
        let committee_hash = [0xFF; 32]; // Different

        let receipt2 = ThresholdReceipt::new(receipt_data, aggregate_signature, signers, committee_hash);

        assert_ne!(receipt1, receipt2);
    }

    #[test]
    fn test_threshold_receipt_ne_different_signers() {
        let receipt1 = make_threshold_receipt();

        let receipt_data = make_receipt();
        let aggregate_signature = make_aggregate_signature();
        let signers = vec![make_coordinator_id(0xFF)]; // Different
        let committee_hash = [0xCC; 32];

        let receipt2 = ThresholdReceipt::new(receipt_data, aggregate_signature, signers, committee_hash);

        assert_ne!(receipt1, receipt2);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // THRESHOLD RECEIPT SERIALIZATION TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_threshold_receipt_serde_json_roundtrip() {
        let original = make_threshold_receipt();

        let serialized = serde_json::to_string(&original).expect("serialize");
        let deserialized: ThresholdReceipt =
            serde_json::from_str(&serialized).expect("deserialize");

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_threshold_receipt_serde_bincode_roundtrip() {
        let original = make_threshold_receipt();

        let serialized = bincode::serialize(&original).expect("serialize");
        let deserialized: ThresholdReceipt =
            bincode::deserialize(&serialized).expect("deserialize");

        assert_eq!(original, deserialized);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // THRESHOLD RECEIPT CLONE TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_threshold_receipt_clone() {
        let original = make_threshold_receipt();
        let cloned = original.clone();

        assert_eq!(original, cloned);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // THRESHOLD RECEIPT DEBUG TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_threshold_receipt_debug() {
        let receipt = make_threshold_receipt();
        let debug = format!("{:?}", receipt);

        assert!(debug.contains("ThresholdReceipt"));
        assert!(debug.contains("receipt_data"));
        assert!(debug.contains("committee_hash"));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // THRESHOLD RECEIPT SEND + SYNC TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_threshold_receipt_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<ThresholdReceipt>();
    }
}