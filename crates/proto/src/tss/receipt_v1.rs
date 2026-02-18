//! # Receipt V1 Protocol Message (14C.A — P.2)
//!
//! Module ini mendefinisikan `ReceiptV1Proto`, generasi baru receipt yang menggabungkan:
//!
//! - Receipt data (workload_id, node_id, usage proof)
//! - Execution commitment (untuk compute receipts, basis fraud proof)
//! - Coordinator threshold signature (FROST aggregate)
//! - Node signature (Ed25519)
//!
//! ## Relasi dengan ThresholdReceiptProto
//!
//! `ThresholdReceiptProto` (di module `committee`) adalah format receipt storage-only
//! yang sudah ada. `ReceiptV1Proto` adalah generalisasi yang mendukung BAIK storage
//! maupun compute receipts:
//!
//! | Feature | ThresholdReceiptProto | ReceiptV1Proto |
//! |---------|----------------------|----------------|
//! | Storage | Yes | Yes (receipt_type=0) |
//! | Compute | No | Yes (receipt_type=1) |
//! | Execution Commitment | No | Yes (for compute) |
//! | Node Signature | No | Yes |
//! | Submitter Address | No | Yes |
//! | Reward Base | No | Yes |
//!
//! ## Receipt Type
//!
//! | Value | Type | Execution Commitment | Challenge Period |
//! |-------|------|----------------------|------------------|
//! | 0 | Storage | MUST be None | No (immediate reward) |
//! | 1 | Compute | MUST be Some | Yes (1 hour) |
//!
//! ## Hash Order (FIXED — consensus-critical)
//!
//! `compute_receipt_hash()` uses SHA3-256 with the following concatenation order:
//!
//! 1. `workload_id` (32 bytes)
//! 2. `node_id` (32 bytes)
//! 3. `receipt_type` (1 byte)
//! 4. `usage_proof_hash` (32 bytes)
//! 5. execution_commitment hash (32 bytes) — or 32 zero bytes if None
//! 6. coordinator_threshold_signature hash (32 bytes)
//! 7. `node_signature` (64 bytes)
//! 8. `submitter_address` (20 bytes)
//! 9. `reward_base` (16 bytes, big-endian)
//! 10. `timestamp` (8 bytes, big-endian)
//! 11. `epoch` (8 bytes, big-endian)
//!
//! Total: 281 bytes sebelum hashing. Tidak ada separator.
//! Perubahan urutan = breaking change = hard-fork.
//!
//! ## Encoding
//!
//! | Property | Value |
//! |----------|-------|
//! | Format | bincode |
//! | Byte Order | Little-endian |
//! | Hash Algorithm | SHA3-256 |
//! | Deterministic | Yes |

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::fmt;

use super::committee::ReceiptDataProto;
use super::execution::{ExecutionCommitmentError, ExecutionCommitmentProto};
use super::signing::{compute_aggregate_signature_hash, AggregateSignatureProto};

// ════════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════════

/// Expected size for workload_id field.
pub const WORKLOAD_ID_SIZE: usize = 32;

/// Expected size for node_id field.
pub const NODE_ID_SIZE: usize = 32;

/// Expected size for usage_proof_hash field.
pub const USAGE_PROOF_HASH_SIZE: usize = 32;

/// Expected size for node_signature field (Ed25519).
pub const NODE_SIGNATURE_SIZE: usize = 64;

/// Expected size for submitter_address field.
pub const SUBMITTER_ADDRESS_SIZE: usize = 20;

/// Receipt type value for storage.
pub const RECEIPT_TYPE_STORAGE: u8 = 0;

/// Receipt type value for compute.
pub const RECEIPT_TYPE_COMPUTE: u8 = 1;

/// Zero hash placeholder for absent execution commitment.
const ZERO_HASH_32: [u8; 32] = [0u8; 32];

// ════════════════════════════════════════════════════════════════════════════════
// ERROR TYPE
// ════════════════════════════════════════════════════════════════════════════════

/// Error type untuk validasi, hashing, dan konversi `ReceiptV1Proto`.
///
/// Setiap varian menjelaskan secara eksplisit field atau kondisi yang gagal.
/// Tidak ada string error generik.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptV1Error {
    /// Sebuah field memiliki panjang yang tidak sesuai.
    InvalidLength {
        field: &'static str,
        expected: usize,
        found: usize,
    },

    /// Nilai receipt_type tidak valid (harus 0 atau 1).
    InvalidReceiptType(u8),

    /// Compute receipt (type=1) tidak memiliki execution commitment.
    MissingExecutionCommitment,

    /// Storage receipt (type=0) memiliki execution commitment yang seharusnya tidak ada.
    UnexpectedExecutionCommitment,

    /// Hashing gagal.
    HashingFailed,

    /// Konversi antar tipe gagal.
    ConversionError(&'static str),

    /// Execution commitment validation gagal.
    ExecutionCommitmentInvalid(ExecutionCommitmentError),

    /// Coordinator threshold signature validation gagal.
    SignatureValidationFailed(String),
}

impl fmt::Display for ReceiptV1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReceiptV1Error::InvalidLength {
                field,
                expected,
                found,
            } => {
                write!(
                    f,
                    "invalid length for field '{}': expected {} bytes, found {} bytes",
                    field, expected, found
                )
            }
            ReceiptV1Error::InvalidReceiptType(t) => {
                write!(f, "invalid receipt_type: {} (must be 0 or 1)", t)
            }
            ReceiptV1Error::MissingExecutionCommitment => {
                write!(
                    f,
                    "compute receipt (type=1) requires execution_commitment but it is None"
                )
            }
            ReceiptV1Error::UnexpectedExecutionCommitment => {
                write!(
                    f,
                    "storage receipt (type=0) must not have execution_commitment"
                )
            }
            ReceiptV1Error::HashingFailed => {
                write!(f, "hashing failed")
            }
            ReceiptV1Error::ConversionError(reason) => {
                write!(f, "conversion error: {}", reason)
            }
            ReceiptV1Error::ExecutionCommitmentInvalid(e) => {
                write!(f, "execution commitment validation failed: {}", e)
            }
            ReceiptV1Error::SignatureValidationFailed(reason) => {
                write!(
                    f,
                    "coordinator threshold signature validation failed: {}",
                    reason
                )
            }
        }
    }
}

impl std::error::Error for ReceiptV1Error {}

impl From<ExecutionCommitmentError> for ReceiptV1Error {
    fn from(e: ExecutionCommitmentError) -> Self {
        ReceiptV1Error::ExecutionCommitmentInvalid(e)
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// RECEIPT V1 PROTO
// ════════════════════════════════════════════════════════════════════════════════

/// Proto message untuk Receipt V1 — generasi baru receipt.
///
/// `ReceiptV1Proto` menggabungkan receipt data, execution commitment,
/// coordinator threshold signature, dan node signature dalam satu message.
///
/// ## Receipt Types
///
/// - `receipt_type = 0` (Storage): immediate reward, `execution_commitment` MUST be None.
/// - `receipt_type = 1` (Compute): challenge period, `execution_commitment` MUST be Some.
///
/// ## Relasi dengan ThresholdReceiptProto
///
/// `ReceiptV1Proto` adalah superset dari `ThresholdReceiptProto`.
/// Storage receipts dapat dikonversi dari/ke `ReceiptDataProto` dengan
/// helper methods, namun informasi tambahan (node_signature, submitter_address,
/// reward_base) tidak tersedia di format lama.
///
/// ## Hash Computation
///
/// `compute_receipt_hash()` menghasilkan SHA3-256 dari konkatenasi semua field
/// dengan urutan FIXED (lihat module-level documentation).
/// Perubahan urutan = breaking change = hard-fork.
///
/// ## Field Sizes
///
/// | Field | Expected Size |
/// |-------|---------------|
/// | `workload_id` | 32 bytes |
/// | `node_id` | 32 bytes |
/// | `receipt_type` | 1 byte (0 or 1) |
/// | `usage_proof_hash` | 32 bytes |
/// | `execution_commitment` | Optional (validated if present) |
/// | `coordinator_threshold_signature` | Validated via AggregateSignatureProto |
/// | `node_signature` | 64 bytes (Ed25519) |
/// | `submitter_address` | 20 bytes |
/// | `reward_base` | u128 |
/// | `timestamp` | u64 |
/// | `epoch` | u64 |
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptV1Proto {
    /// Identifier unik workload yang dieksekusi (MUST be 32 bytes).
    pub workload_id: Vec<u8>,

    /// Identifier node yang melakukan kerja (MUST be 32 bytes).
    pub node_id: Vec<u8>,

    /// Tipe receipt: 0=Storage, 1=Compute.
    ///
    /// Menentukan apakah `execution_commitment` wajib ada dan
    /// apakah challenge period berlaku.
    pub receipt_type: u8,

    /// Hash dari usage proof yang diverifikasi coordinator (MUST be 32 bytes).
    pub usage_proof_hash: Vec<u8>,

    /// Execution commitment untuk compute receipts.
    ///
    /// - MUST be `Some` jika `receipt_type == 1` (Compute).
    /// - MUST be `None` jika `receipt_type == 0` (Storage).
    pub execution_commitment: Option<ExecutionCommitmentProto>,

    /// Coordinator threshold signature (FROST aggregate).
    ///
    /// Dihasilkan oleh committee coordinators via threshold signing protocol.
    pub coordinator_threshold_signature: AggregateSignatureProto,

    /// Ed25519 signature dari node atas receipt data (MUST be 64 bytes).
    pub node_signature: Vec<u8>,

    /// Address pihak yang submit ClaimReward transaction (MUST be 20 bytes).
    ///
    /// Digunakan untuk anti-self-dealing check.
    pub submitter_address: Vec<u8>,

    /// Reward dasar yang akan didistribusikan dengan split 70/20/10.
    pub reward_base: u128,

    /// Unix timestamp saat receipt dibuat.
    pub timestamp: u64,

    /// Epoch number saat receipt dibuat.
    pub epoch: u64,
}

impl ReceiptV1Proto {
    /// Validates all fields and invariants.
    ///
    /// # Validation Rules
    ///
    /// 1. `workload_id.len() == 32`
    /// 2. `node_id.len() == 32`
    /// 3. `receipt_type` is 0 or 1
    /// 4. `usage_proof_hash.len() == 32`
    /// 5. If `receipt_type == 1` (Compute): `execution_commitment` MUST be Some
    ///    and its `validate()` MUST pass.
    /// 6. If `receipt_type == 0` (Storage): `execution_commitment` MUST be None.
    /// 7. `coordinator_threshold_signature.validate()` MUST pass.
    /// 8. `node_signature.len() == 64`
    /// 9. `submitter_address.len() == 20`
    ///
    /// # Returns
    ///
    /// - `Ok(())` if all validations pass.
    /// - `Err(ReceiptV1Error)` with specific variant for the first failure.
    pub fn validate(&self) -> Result<(), ReceiptV1Error> {
        // 1. workload_id
        validate_field_length(&self.workload_id, "workload_id", WORKLOAD_ID_SIZE)?;

        // 2. node_id
        validate_field_length(&self.node_id, "node_id", NODE_ID_SIZE)?;

        // 3. receipt_type
        if self.receipt_type != RECEIPT_TYPE_STORAGE && self.receipt_type != RECEIPT_TYPE_COMPUTE {
            return Err(ReceiptV1Error::InvalidReceiptType(self.receipt_type));
        }

        // 4. usage_proof_hash
        validate_field_length(
            &self.usage_proof_hash,
            "usage_proof_hash",
            USAGE_PROOF_HASH_SIZE,
        )?;

        // 5 & 6. execution_commitment invariant
        match self.receipt_type {
            RECEIPT_TYPE_COMPUTE => {
                let ec = self
                    .execution_commitment
                    .as_ref()
                    .ok_or(ReceiptV1Error::MissingExecutionCommitment)?;
                ec.validate().map_err(ReceiptV1Error::ExecutionCommitmentInvalid)?;
            }
            RECEIPT_TYPE_STORAGE => {
                if self.execution_commitment.is_some() {
                    return Err(ReceiptV1Error::UnexpectedExecutionCommitment);
                }
            }
            // Unreachable due to check in step 3, but explicit for safety.
            _ => return Err(ReceiptV1Error::InvalidReceiptType(self.receipt_type)),
        }

        // 7. coordinator_threshold_signature
        self.coordinator_threshold_signature
            .validate()
            .map_err(|e| ReceiptV1Error::SignatureValidationFailed(e.to_string()))?;

        // 8. node_signature
        validate_field_length(&self.node_signature, "node_signature", NODE_SIGNATURE_SIZE)?;

        // 9. submitter_address
        validate_field_length(
            &self.submitter_address,
            "submitter_address",
            SUBMITTER_ADDRESS_SIZE,
        )?;

        Ok(())
    }

    /// Computes deterministic SHA3-256 hash of receipt.
    ///
    /// # Hash Order (FIXED — consensus-critical)
    ///
    /// Konkatenasi dalam urutan berikut, tanpa separator:
    ///
    /// 1. `workload_id` (32 bytes)
    /// 2. `node_id` (32 bytes)
    /// 3. `receipt_type` (1 byte)
    /// 4. `usage_proof_hash` (32 bytes)
    /// 5. execution_commitment hash (32 bytes) — `compute_hash()` jika Some,
    ///    32 zero bytes jika None
    /// 6. coordinator_threshold_signature hash (32 bytes) —
    ///    `compute_aggregate_signature_hash()`
    /// 7. `node_signature` (64 bytes)
    /// 8. `submitter_address` (20 bytes)
    /// 9. `reward_base` (16 bytes, big-endian)
    /// 10. `timestamp` (8 bytes, big-endian)
    /// 11. `epoch` (8 bytes, big-endian)
    ///
    /// Total input: 281 bytes → SHA3-256 → 32 bytes output.
    ///
    /// # Returns
    ///
    /// - `Ok([u8; 32])` — deterministic hash.
    /// - `Err(ReceiptV1Error)` — if `validate()` fails or EC hashing fails.
    ///
    /// # CRITICAL
    ///
    /// Hash order ini HARUS IDENTIK dengan implementasi di:
    /// - `dsdn_common::ReceiptV1::compute_receipt_hash()`
    /// - `dsdn_common::receipt_hash::compute_receipt_v1_hash()`
    ///
    /// Perubahan urutan = breaking change = hard-fork.
    pub fn compute_receipt_hash(&self) -> Result<[u8; 32], ReceiptV1Error> {
        // Validate all fields terlebih dahulu.
        self.validate()?;

        // 5. Execution commitment hash (32 bytes or zero hash).
        let ec_hash = match &self.execution_commitment {
            Some(ec) => ec
                .compute_hash()
                .map_err(ReceiptV1Error::ExecutionCommitmentInvalid)?,
            None => ZERO_HASH_32,
        };

        // 6. Coordinator threshold signature hash (32 bytes).
        let sig_hash = compute_aggregate_signature_hash(&self.coordinator_threshold_signature);

        // Pre-allocate buffer for all fields (281 bytes).
        let mut buf = Vec::with_capacity(281);

        // 1. workload_id (32 bytes)
        buf.extend_from_slice(&self.workload_id);

        // 2. node_id (32 bytes)
        buf.extend_from_slice(&self.node_id);

        // 3. receipt_type (1 byte)
        buf.push(self.receipt_type);

        // 4. usage_proof_hash (32 bytes)
        buf.extend_from_slice(&self.usage_proof_hash);

        // 5. execution_commitment hash (32 bytes)
        buf.extend_from_slice(&ec_hash);

        // 6. coordinator_threshold_signature hash (32 bytes)
        buf.extend_from_slice(&sig_hash);

        // 7. node_signature (64 bytes)
        buf.extend_from_slice(&self.node_signature);

        // 8. submitter_address (20 bytes)
        buf.extend_from_slice(&self.submitter_address);

        // 9. reward_base (16 bytes, big-endian)
        buf.extend_from_slice(&self.reward_base.to_be_bytes());

        // 10. timestamp (8 bytes, big-endian)
        buf.extend_from_slice(&self.timestamp.to_be_bytes());

        // 11. epoch (8 bytes, big-endian)
        buf.extend_from_slice(&self.epoch.to_be_bytes());

        // Hash the concatenated buffer.
        let mut hasher = Sha3_256::new();
        hasher.update(&buf);
        let result = hasher.finalize();

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        Ok(hash)
    }

    /// Returns true jika receipt_type adalah Storage (0).
    #[must_use]
    #[inline]
    pub fn is_storage(&self) -> bool {
        self.receipt_type == RECEIPT_TYPE_STORAGE
    }

    /// Returns true jika receipt_type adalah Compute (1).
    #[must_use]
    #[inline]
    pub fn is_compute(&self) -> bool {
        self.receipt_type == RECEIPT_TYPE_COMPUTE
    }

    /// Returns true jika receipt memerlukan challenge period.
    /// Hanya Compute receipts yang memerlukan challenge period.
    #[must_use]
    #[inline]
    pub fn requires_challenge_period(&self) -> bool {
        self.is_compute()
    }

    /// Returns true jika execution_commitment ada.
    #[must_use]
    #[inline]
    pub fn has_execution_commitment(&self) -> bool {
        self.execution_commitment.is_some()
    }

    /// Encode ke bytes via bincode (little-endian, deterministic).
    pub fn encode(&self) -> Result<Vec<u8>, ReceiptV1Error> {
        bincode::serialize(self).map_err(|_| ReceiptV1Error::HashingFailed)
    }

    /// Decode dari bytes via bincode.
    pub fn decode(data: &[u8]) -> Result<Self, ReceiptV1Error> {
        bincode::deserialize(data).map_err(|_| ReceiptV1Error::HashingFailed)
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// BACKWARD COMPATIBILITY: TryFrom<ReceiptDataProto> for ReceiptV1Proto
// ════════════════════════════════════════════════════════════════════════════════

/// Konversi dari `ReceiptDataProto` ke `ReceiptV1Proto`.
///
/// Konversi ini SELALU GAGAL karena `ReceiptDataProto` tidak mengandung
/// informasi yang cukup untuk membentuk `ReceiptV1Proto` yang valid:
/// - Tidak ada `node_id`
/// - Tidak ada `node_signature`
/// - Tidak ada `submitter_address`
/// - Tidak ada `coordinator_threshold_signature`
/// - Tidak ada `reward_base`
///
/// Gunakan `ReceiptV1Proto::from_receipt_data_with_context()` sebagai
/// alternatif yang menerima data tambahan.
impl TryFrom<ReceiptDataProto> for ReceiptV1Proto {
    type Error = ReceiptV1Error;

    fn try_from(_value: ReceiptDataProto) -> Result<Self, Self::Error> {
        Err(ReceiptV1Error::ConversionError(
            "ReceiptDataProto does not contain sufficient fields for ReceiptV1Proto: \
             missing node_id, node_signature, submitter_address, \
             coordinator_threshold_signature, reward_base",
        ))
    }
}

/// Konversi dari `ReceiptV1Proto` ke `ReceiptDataProto`.
///
/// Konversi ini hanya berhasil untuk Storage receipts dan bersifat LOSSY:
/// field-field yang tidak ada di `ReceiptDataProto` (node_signature,
/// submitter_address, reward_base, dll.) akan hilang.
///
/// # Rules
///
/// - Hanya Storage receipts (receipt_type=0) yang dapat dikonversi.
/// - Compute receipts ditolak karena `ReceiptDataProto` tidak mendukung
///   execution commitment.
/// - `workload_id` → `workload_id`
/// - `usage_proof_hash` → `blob_hash`
/// - `placement` di-set ke empty (tidak tersedia di ReceiptV1Proto)
/// - `sequence` di-set ke 0 (tidak tersedia di ReceiptV1Proto)
/// - `timestamp` → `timestamp`
/// - `epoch` → `epoch`
impl TryFrom<ReceiptV1Proto> for ReceiptDataProto {
    type Error = ReceiptV1Error;

    fn try_from(value: ReceiptV1Proto) -> Result<Self, Self::Error> {
        if value.receipt_type != RECEIPT_TYPE_STORAGE {
            return Err(ReceiptV1Error::ConversionError(
                "only storage receipts (type=0) can be converted to ReceiptDataProto; \
                 compute receipts have execution_commitment which cannot be represented",
            ));
        }

        Ok(ReceiptDataProto {
            workload_id: value.workload_id,
            blob_hash: value.usage_proof_hash,
            placement: Vec::new(),
            timestamp: value.timestamp,
            sequence: 0,
            epoch: value.epoch,
        })
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// STANDALONE FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════════

/// Encode `ReceiptV1Proto` ke bytes.
#[must_use]
pub fn encode_receipt_v1(receipt: &ReceiptV1Proto) -> Vec<u8> {
    bincode::serialize(receipt).unwrap_or_else(|_| Vec::new())
}

/// Decode bytes ke `ReceiptV1Proto`.
pub fn decode_receipt_v1(bytes: &[u8]) -> Result<ReceiptV1Proto, ReceiptV1Error> {
    bincode::deserialize(bytes).map_err(|_| ReceiptV1Error::HashingFailed)
}

/// Compute SHA3-256 hash dari `ReceiptV1Proto`.
pub fn compute_receipt_v1_hash(receipt: &ReceiptV1Proto) -> Result<[u8; 32], ReceiptV1Error> {
    receipt.compute_receipt_hash()
}

// ════════════════════════════════════════════════════════════════════════════════
// INTERNAL HELPERS
// ════════════════════════════════════════════════════════════════════════════════

/// Validate field length.
fn validate_field_length(
    field_data: &[u8],
    field_name: &'static str,
    expected: usize,
) -> Result<(), ReceiptV1Error> {
    if field_data.len() != expected {
        return Err(ReceiptV1Error::InvalidLength {
            field: field_name,
            expected,
            found: field_data.len(),
        });
    }
    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::execution::ExecutionCommitmentProto;

    /// Helper: build valid AggregateSignatureProto.
    fn make_aggregate_sig() -> AggregateSignatureProto {
        AggregateSignatureProto {
            signature: vec![0xAA; 64],
            signer_ids: vec![vec![0x01; 32], vec![0x02; 32]],
            message_hash: vec![0xBB; 32],
            aggregated_at: 1_700_000_000,
        }
    }

    /// Helper: build valid ExecutionCommitmentProto.
    fn make_execution_commitment() -> ExecutionCommitmentProto {
        ExecutionCommitmentProto {
            workload_id: vec![0x10; 32],
            input_hash: vec![0x11; 32],
            output_hash: vec![0x12; 32],
            state_root_before: vec![0x13; 32],
            state_root_after: vec![0x14; 32],
            execution_trace_merkle_root: vec![0x15; 32],
        }
    }

    /// Helper: build valid storage ReceiptV1Proto.
    fn make_storage_receipt() -> ReceiptV1Proto {
        ReceiptV1Proto {
            workload_id: vec![0x01; 32],
            node_id: vec![0x02; 32],
            receipt_type: RECEIPT_TYPE_STORAGE,
            usage_proof_hash: vec![0x03; 32],
            execution_commitment: None,
            coordinator_threshold_signature: make_aggregate_sig(),
            node_signature: vec![0x04; 64],
            submitter_address: vec![0x05; 20],
            reward_base: 1_000_000,
            timestamp: 1_700_000_000,
            epoch: 1,
        }
    }

    /// Helper: build valid compute ReceiptV1Proto.
    fn make_compute_receipt() -> ReceiptV1Proto {
        ReceiptV1Proto {
            workload_id: vec![0x01; 32],
            node_id: vec![0x02; 32],
            receipt_type: RECEIPT_TYPE_COMPUTE,
            usage_proof_hash: vec![0x03; 32],
            execution_commitment: Some(make_execution_commitment()),
            coordinator_threshold_signature: make_aggregate_sig(),
            node_signature: vec![0x04; 64],
            submitter_address: vec![0x05; 20],
            reward_base: 500_000,
            timestamp: 1_700_000_000,
            epoch: 2,
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // VALIDATE: STORAGE RECEIPT
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_validate_storage_receipt_valid() {
        let receipt = make_storage_receipt();
        assert!(receipt.validate().is_ok());
    }

    #[test]
    fn test_validate_storage_with_execution_commitment_rejected() {
        let mut receipt = make_storage_receipt();
        receipt.execution_commitment = Some(make_execution_commitment());
        let err = receipt.validate().unwrap_err();
        assert_eq!(err, ReceiptV1Error::UnexpectedExecutionCommitment);
    }

    // ────────────────────────────────────────────────────────────────────────
    // VALIDATE: COMPUTE RECEIPT
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_validate_compute_receipt_valid() {
        let receipt = make_compute_receipt();
        assert!(receipt.validate().is_ok());
    }

    #[test]
    fn test_validate_compute_without_execution_commitment_rejected() {
        let mut receipt = make_compute_receipt();
        receipt.execution_commitment = None;
        let err = receipt.validate().unwrap_err();
        assert_eq!(err, ReceiptV1Error::MissingExecutionCommitment);
    }

    #[test]
    fn test_validate_compute_with_invalid_execution_commitment() {
        let mut receipt = make_compute_receipt();
        let mut ec = make_execution_commitment();
        ec.workload_id = vec![0x10; 16]; // Invalid: not 32 bytes
        receipt.execution_commitment = Some(ec);
        let err = receipt.validate().unwrap_err();
        match err {
            ReceiptV1Error::ExecutionCommitmentInvalid(_) => {}
            other => panic!("expected ExecutionCommitmentInvalid, got {:?}", other),
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // VALIDATE: FIELD LENGTHS
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_validate_invalid_workload_id() {
        let mut receipt = make_storage_receipt();
        receipt.workload_id = vec![0x01; 16];
        let err = receipt.validate().unwrap_err();
        assert_eq!(
            err,
            ReceiptV1Error::InvalidLength {
                field: "workload_id",
                expected: 32,
                found: 16,
            }
        );
    }

    #[test]
    fn test_validate_invalid_node_id() {
        let mut receipt = make_storage_receipt();
        receipt.node_id = vec![0x02; 10];
        let err = receipt.validate().unwrap_err();
        assert_eq!(
            err,
            ReceiptV1Error::InvalidLength {
                field: "node_id",
                expected: 32,
                found: 10,
            }
        );
    }

    #[test]
    fn test_validate_invalid_usage_proof_hash() {
        let mut receipt = make_storage_receipt();
        receipt.usage_proof_hash = vec![0x03; 48];
        let err = receipt.validate().unwrap_err();
        assert_eq!(
            err,
            ReceiptV1Error::InvalidLength {
                field: "usage_proof_hash",
                expected: 32,
                found: 48,
            }
        );
    }

    #[test]
    fn test_validate_invalid_node_signature() {
        let mut receipt = make_storage_receipt();
        receipt.node_signature = vec![0x04; 32]; // Should be 64
        let err = receipt.validate().unwrap_err();
        assert_eq!(
            err,
            ReceiptV1Error::InvalidLength {
                field: "node_signature",
                expected: 64,
                found: 32,
            }
        );
    }

    #[test]
    fn test_validate_invalid_submitter_address() {
        let mut receipt = make_storage_receipt();
        receipt.submitter_address = vec![0x05; 32]; // Should be 20
        let err = receipt.validate().unwrap_err();
        assert_eq!(
            err,
            ReceiptV1Error::InvalidLength {
                field: "submitter_address",
                expected: 20,
                found: 32,
            }
        );
    }

    #[test]
    fn test_validate_invalid_receipt_type() {
        let mut receipt = make_storage_receipt();
        receipt.receipt_type = 2;
        let err = receipt.validate().unwrap_err();
        assert_eq!(err, ReceiptV1Error::InvalidReceiptType(2));
    }

    #[test]
    fn test_validate_receipt_type_255() {
        let mut receipt = make_storage_receipt();
        receipt.receipt_type = 255;
        let err = receipt.validate().unwrap_err();
        assert_eq!(err, ReceiptV1Error::InvalidReceiptType(255));
    }

    // ────────────────────────────────────────────────────────────────────────
    // COMPUTE HASH: DETERMINISM
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_hash_storage_deterministic() {
        let receipt = make_storage_receipt();
        let h1 = receipt.compute_receipt_hash().expect("h1");
        let h2 = receipt.compute_receipt_hash().expect("h2");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_compute_deterministic() {
        let receipt = make_compute_receipt();
        let h1 = receipt.compute_receipt_hash().expect("h1");
        let h2 = receipt.compute_receipt_hash().expect("h2");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_storage_vs_compute_different() {
        let storage = make_storage_receipt();
        let compute = make_compute_receipt();
        let h1 = storage.compute_receipt_hash().expect("h1");
        let h2 = compute.compute_receipt_hash().expect("h2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hash_different_workload_id() {
        let r1 = make_storage_receipt();
        let mut r2 = make_storage_receipt();
        r2.workload_id = vec![0xFF; 32];
        assert_ne!(
            r1.compute_receipt_hash().expect("h1"),
            r2.compute_receipt_hash().expect("h2"),
        );
    }

    #[test]
    fn test_hash_different_node_id() {
        let r1 = make_storage_receipt();
        let mut r2 = make_storage_receipt();
        r2.node_id = vec![0xFF; 32];
        assert_ne!(
            r1.compute_receipt_hash().expect("h1"),
            r2.compute_receipt_hash().expect("h2"),
        );
    }

    #[test]
    fn test_hash_different_reward_base() {
        let r1 = make_storage_receipt();
        let mut r2 = make_storage_receipt();
        r2.reward_base = 999_999;
        assert_ne!(
            r1.compute_receipt_hash().expect("h1"),
            r2.compute_receipt_hash().expect("h2"),
        );
    }

    #[test]
    fn test_hash_different_timestamp() {
        let r1 = make_storage_receipt();
        let mut r2 = make_storage_receipt();
        r2.timestamp = 1_700_000_001;
        assert_ne!(
            r1.compute_receipt_hash().expect("h1"),
            r2.compute_receipt_hash().expect("h2"),
        );
    }

    #[test]
    fn test_hash_different_epoch() {
        let r1 = make_storage_receipt();
        let mut r2 = make_storage_receipt();
        r2.epoch = 99;
        assert_ne!(
            r1.compute_receipt_hash().expect("h1"),
            r2.compute_receipt_hash().expect("h2"),
        );
    }

    #[test]
    fn test_hash_different_submitter_address() {
        let r1 = make_storage_receipt();
        let mut r2 = make_storage_receipt();
        r2.submitter_address = vec![0xFF; 20];
        assert_ne!(
            r1.compute_receipt_hash().expect("h1"),
            r2.compute_receipt_hash().expect("h2"),
        );
    }

    #[test]
    fn test_hash_different_node_signature() {
        let r1 = make_storage_receipt();
        let mut r2 = make_storage_receipt();
        r2.node_signature = vec![0xFF; 64];
        assert_ne!(
            r1.compute_receipt_hash().expect("h1"),
            r2.compute_receipt_hash().expect("h2"),
        );
    }

    #[test]
    fn test_hash_rejects_invalid_receipt() {
        let mut receipt = make_storage_receipt();
        receipt.workload_id = vec![0x01; 10]; // Invalid
        assert!(receipt.compute_receipt_hash().is_err());
    }

    #[test]
    fn test_hash_output_32_bytes() {
        let receipt = make_storage_receipt();
        let hash = receipt.compute_receipt_hash().expect("hash");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_hash_not_all_zeros() {
        let receipt = make_storage_receipt();
        let hash = receipt.compute_receipt_hash().expect("hash");
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_hash_determinism_1000_runs() {
        let receipt = make_compute_receipt();
        let reference = receipt.compute_receipt_hash().expect("ref");
        for _ in 0..1000 {
            assert_eq!(receipt.compute_receipt_hash().expect("run"), reference);
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // ENCODE/DECODE
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_encode_decode_storage_roundtrip() {
        let receipt = make_storage_receipt();
        let bytes = encode_receipt_v1(&receipt);
        let decoded = decode_receipt_v1(&bytes).expect("decode");
        assert_eq!(receipt, decoded);
    }

    #[test]
    fn test_encode_decode_compute_roundtrip() {
        let receipt = make_compute_receipt();
        let bytes = encode_receipt_v1(&receipt);
        let decoded = decode_receipt_v1(&bytes).expect("decode");
        assert_eq!(receipt, decoded);
    }

    #[test]
    fn test_method_encode_decode_roundtrip() {
        let receipt = make_compute_receipt();
        let bytes = receipt.encode().expect("encode");
        let decoded = ReceiptV1Proto::decode(&bytes).expect("decode");
        assert_eq!(receipt, decoded);
    }

    #[test]
    fn test_decode_invalid_bytes() {
        assert!(decode_receipt_v1(&[0xFF, 0x01, 0x02]).is_err());
    }

    #[test]
    fn test_decode_empty_bytes() {
        assert!(decode_receipt_v1(&[]).is_err());
    }

    #[test]
    fn test_encode_decode_preserves_hash() {
        let receipt = make_compute_receipt();
        let hash_before = receipt.compute_receipt_hash().expect("before");
        let bytes = encode_receipt_v1(&receipt);
        let decoded = decode_receipt_v1(&bytes).expect("decode");
        let hash_after = decoded.compute_receipt_hash().expect("after");
        assert_eq!(hash_before, hash_after);
    }

    // ────────────────────────────────────────────────────────────────────────
    // STANDALONE FUNCTION
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_compute_receipt_v1_hash_fn() {
        let receipt = make_storage_receipt();
        let h_method = receipt.compute_receipt_hash().expect("method");
        let h_fn = compute_receipt_v1_hash(&receipt).expect("fn");
        assert_eq!(h_method, h_fn);
    }

    // ────────────────────────────────────────────────────────────────────────
    // HELPER METHODS
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_is_storage() {
        let receipt = make_storage_receipt();
        assert!(receipt.is_storage());
        assert!(!receipt.is_compute());
        assert!(!receipt.requires_challenge_period());
    }

    #[test]
    fn test_is_compute() {
        let receipt = make_compute_receipt();
        assert!(receipt.is_compute());
        assert!(!receipt.is_storage());
        assert!(receipt.requires_challenge_period());
    }

    #[test]
    fn test_has_execution_commitment() {
        assert!(!make_storage_receipt().has_execution_commitment());
        assert!(make_compute_receipt().has_execution_commitment());
    }

    // ────────────────────────────────────────────────────────────────────────
    // TRYFROM CONVERSIONS
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_try_from_receipt_data_proto_always_fails() {
        let data = ReceiptDataProto {
            workload_id: vec![0x01; 32],
            blob_hash: vec![0x02; 32],
            placement: vec![vec![0x03; 32]],
            timestamp: 1_700_000_000,
            sequence: 1,
            epoch: 1,
        };
        let result = ReceiptV1Proto::try_from(data);
        assert!(result.is_err());
        match result.unwrap_err() {
            ReceiptV1Error::ConversionError(_) => {}
            other => panic!("expected ConversionError, got {:?}", other),
        }
    }

    #[test]
    fn test_try_from_receipt_v1_to_data_proto_storage() {
        let receipt = make_storage_receipt();
        let data = ReceiptDataProto::try_from(receipt.clone()).expect("conversion");
        assert_eq!(data.workload_id, receipt.workload_id);
        assert_eq!(data.blob_hash, receipt.usage_proof_hash);
        assert!(data.placement.is_empty());
        assert_eq!(data.timestamp, receipt.timestamp);
        assert_eq!(data.sequence, 0);
        assert_eq!(data.epoch, receipt.epoch);
    }

    #[test]
    fn test_try_from_receipt_v1_to_data_proto_compute_fails() {
        let receipt = make_compute_receipt();
        let result = ReceiptDataProto::try_from(receipt);
        assert!(result.is_err());
        match result.unwrap_err() {
            ReceiptV1Error::ConversionError(_) => {}
            other => panic!("expected ConversionError, got {:?}", other),
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // ERROR DISPLAY
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_error_display_invalid_length() {
        let err = ReceiptV1Error::InvalidLength {
            field: "node_id",
            expected: 32,
            found: 10,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("node_id"));
        assert!(msg.contains("32"));
        assert!(msg.contains("10"));
    }

    #[test]
    fn test_error_display_invalid_receipt_type() {
        let msg = format!("{}", ReceiptV1Error::InvalidReceiptType(5));
        assert!(msg.contains("5"));
    }

    #[test]
    fn test_error_display_missing_ec() {
        let msg = format!("{}", ReceiptV1Error::MissingExecutionCommitment);
        assert!(msg.contains("compute"));
    }

    #[test]
    fn test_error_display_unexpected_ec() {
        let msg = format!("{}", ReceiptV1Error::UnexpectedExecutionCommitment);
        assert!(msg.contains("storage"));
    }

    #[test]
    fn test_error_display_conversion() {
        let msg = format!("{}", ReceiptV1Error::ConversionError("test reason"));
        assert!(msg.contains("test reason"));
    }

    // ────────────────────────────────────────────────────────────────────────
    // CONSTANTS
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_constants() {
        assert_eq!(WORKLOAD_ID_SIZE, 32);
        assert_eq!(NODE_ID_SIZE, 32);
        assert_eq!(USAGE_PROOF_HASH_SIZE, 32);
        assert_eq!(NODE_SIGNATURE_SIZE, 64);
        assert_eq!(SUBMITTER_ADDRESS_SIZE, 20);
        assert_eq!(RECEIPT_TYPE_STORAGE, 0);
        assert_eq!(RECEIPT_TYPE_COMPUTE, 1);
    }
}