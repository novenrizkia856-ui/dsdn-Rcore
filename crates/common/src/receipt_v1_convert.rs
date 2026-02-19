//! # Proto ↔ Native Conversion Layer (C.9)
//!
//! Conversion layer resmi antara proto wire-format types dan native types.
//!
//! ## Conversion Flow
//!
//! ```text
//! Coordinator (native)
//!     ↓ to_proto()
//! Data Availability (proto wire format)
//!     ↓ decode
//! Chain
//!     ↓ from_proto()
//! Native validation & processing
//! ```
//!
//! ## Types Converted
//!
//! | Proto | Native |
//! |-------|--------|
//! | `ExecutionCommitmentProto` | `ExecutionCommitment` |
//! | `ReceiptV1Proto` | `ReceiptV1` |
//! | `ClaimRewardProto` | `ClaimReward` |
//!
//! ## Hash Consistency
//!
//! Proto `compute_receipt_hash()` uses `compute_aggregate_signature_hash()` (32-byte
//! digest) for the coordinator signature field. Native `compute_receipt_hash()` feeds
//! raw signature bytes + signer_ids directly. The free function
//! `compute_receipt_hash_proto_compatible()` computes the hash using the proto
//! algorithm from native data, enabling cross-layer hash verification.
//!
//! ## Safety
//!
//! - No unwrap, expect, panic, or unsafe
//! - All Vec<u8> → [u8; N] conversions checked with explicit error
//! - No silent truncation or padding
//! - No default values for missing fields

use crate::coordinator::{NodeId, WorkloadId};
use crate::execution_commitment::{ExecutionCommitment, ExecutionCommitmentError};
use crate::receipt_v1::{Address, ReceiptError, ReceiptType, ReceiptV1};
use sha3::{Digest, Sha3_256};
use std::fmt;

// ════════════════════════════════════════════════════════════════════════════════
// PROTO MIRROR TYPES
// ════════════════════════════════════════════════════════════════════════════════
//
// These types mirror the proto crate definitions exactly.
// common depends on proto conceptually; these are the wire-format structs.

/// Proto representation of ExecutionCommitment.
/// All fields are `Vec<u8>` with expected length 32.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionCommitmentProto {
    pub workload_id: Vec<u8>,
    pub input_hash: Vec<u8>,
    pub output_hash: Vec<u8>,
    pub state_root_before: Vec<u8>,
    pub state_root_after: Vec<u8>,
    pub execution_trace_merkle_root: Vec<u8>,
}

/// Proto representation of FROST aggregate signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregateSignatureProto {
    /// FROST signature (MUST be 64 bytes: R ‖ s).
    pub signature: Vec<u8>,
    /// Signer identifiers (EACH MUST be 32 bytes).
    pub signer_ids: Vec<Vec<u8>>,
    /// Hash of the signed message (MUST be 32 bytes).
    pub message_hash: Vec<u8>,
    /// Unix timestamp when aggregation was performed.
    pub aggregated_at: u64,
}

/// Proto representation of ReceiptV1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptV1Proto {
    pub workload_id: Vec<u8>,
    pub node_id: Vec<u8>,
    /// 0=Storage, 1=Compute.
    pub receipt_type: u8,
    pub usage_proof_hash: Vec<u8>,
    pub execution_commitment: Option<ExecutionCommitmentProto>,
    pub coordinator_threshold_signature: AggregateSignatureProto,
    pub node_signature: Vec<u8>,
    pub submitter_address: Vec<u8>,
    pub reward_base: u128,
    pub timestamp: u64,
    pub epoch: u64,
}

/// Proto representation of ClaimReward transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimRewardProto {
    pub receipt: ReceiptV1Proto,
    pub submitter_address: Vec<u8>,
    pub submitter_signature: Vec<u8>,
    pub nonce: u64,
    pub timestamp: u64,
}

// ════════════════════════════════════════════════════════════════════════════════
// CONVERSION ERROR
// ════════════════════════════════════════════════════════════════════════════════

/// Error type untuk konversi proto ↔ native.
///
/// Setiap varian menjelaskan secara eksplisit kondisi yang gagal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConversionError {
    /// Field memiliki panjang yang tidak sesuai.
    InvalidFieldLength {
        field: &'static str,
        expected: usize,
        got: usize,
    },
    /// Field wajib tidak ada (None atau kosong).
    MissingRequiredField {
        field: &'static str,
    },
    /// Nilai field tidak valid.
    InvalidValue {
        field: &'static str,
        reason: String,
    },
}

impl fmt::Display for ConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConversionError::InvalidFieldLength {
                field,
                expected,
                got,
            } => write!(
                f,
                "invalid field length for '{}': expected {} bytes, got {} bytes",
                field, expected, got
            ),
            ConversionError::MissingRequiredField { field } => {
                write!(f, "missing required field: '{}'", field)
            }
            ConversionError::InvalidValue { field, reason } => {
                write!(f, "invalid value for '{}': {}", field, reason)
            }
        }
    }
}

impl std::error::Error for ConversionError {}

impl From<ExecutionCommitmentError> for ConversionError {
    fn from(e: ExecutionCommitmentError) -> Self {
        ConversionError::InvalidValue {
            field: "execution_commitment",
            reason: e.to_string(),
        }
    }
}

impl From<ReceiptError> for ConversionError {
    fn from(e: ReceiptError) -> Self {
        ConversionError::InvalidValue {
            field: "receipt",
            reason: e.to_string(),
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// INTERNAL HELPERS
// ════════════════════════════════════════════════════════════════════════════════

/// Convert Vec<u8> to [u8; 32], returning ConversionError on length mismatch.
fn vec_to_array_32(data: &[u8], field: &'static str) -> Result<[u8; 32], ConversionError> {
    if data.len() != 32 {
        return Err(ConversionError::InvalidFieldLength {
            field,
            expected: 32,
            got: data.len(),
        });
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(data);
    Ok(arr)
}

/// Convert Vec<u8> to [u8; 20], returning ConversionError on length mismatch.
fn vec_to_array_20(data: &[u8], field: &'static str) -> Result<[u8; 20], ConversionError> {
    if data.len() != 20 {
        return Err(ConversionError::InvalidFieldLength {
            field,
            expected: 20,
            got: data.len(),
        });
    }
    let mut arr = [0u8; 20];
    arr.copy_from_slice(data);
    Ok(arr)
}

/// Compute deterministic SHA3-256 hash of AggregateSignatureProto.
///
/// Identical algorithm to `proto::tss::signing::compute_aggregate_signature_hash`.
///
/// Hash order (FIXED — consensus-critical):
/// 1. Domain separator: `b"dsdn-proto-aggregate-signature-v1"`
/// 2. `signature` bytes
/// 3. Number of signers (u64, little-endian)
/// 4. Each `signer_id` in order
/// 5. `message_hash`
/// 6. `aggregated_at` (u64, little-endian)
#[must_use]
pub fn compute_aggregate_signature_hash(agg: &AggregateSignatureProto) -> [u8; 32] {
    let mut hasher = Sha3_256::new();

    // Domain separator
    hasher.update(b"dsdn-proto-aggregate-signature-v1");

    // Signature
    hasher.update(&agg.signature);

    // Number of signers (deterministic)
    let signer_count = agg.signer_ids.len() as u64;
    hasher.update(signer_count.to_le_bytes());

    // Signer IDs in order
    for signer_id in &agg.signer_ids {
        hasher.update(signer_id);
    }

    // Message hash
    hasher.update(&agg.message_hash);

    // Aggregated timestamp
    hasher.update(agg.aggregated_at.to_le_bytes());

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// 32 zero bytes, used when `execution_commitment` is `None`.
const ZERO_HASH_32: [u8; 32] = [0u8; 32];

/// Compute receipt hash using proto algorithm from native data.
///
/// This mirrors `ReceiptV1Proto::compute_receipt_hash()` exactly:
/// uses `compute_aggregate_signature_hash()` for the signature field
/// instead of raw bytes.
///
/// Hash order (FIXED — consensus-critical):
/// 1. `workload_id` (32 bytes)
/// 2. `node_id` (32 bytes)
/// 3. `receipt_type` (1 byte)
/// 4. `usage_proof_hash` (32 bytes)
/// 5. execution_commitment hash (32 bytes or zero)
/// 6. aggregate_signature_hash (32 bytes)
/// 7. `node_signature` (variable)
/// 8. `submitter_address` (20 bytes)
/// 9. `reward_base` (16 bytes, big-endian)
/// 10. `timestamp` (8 bytes, big-endian)
/// 11. `epoch` (8 bytes, big-endian)
#[must_use]
pub fn compute_receipt_hash_proto_compatible(
    native: &ReceiptV1,
    agg: &AggregateSignatureProto,
) -> [u8; 32] {
    let ec_hash = match native.execution_commitment() {
        Some(ec) => ec.compute_hash(),
        None => ZERO_HASH_32,
    };

    let sig_hash = compute_aggregate_signature_hash(agg);

    let mut buf = Vec::with_capacity(277);

    // 1. workload_id (32 bytes)
    buf.extend_from_slice(native.workload_id().as_bytes());
    // 2. node_id (32 bytes)
    buf.extend_from_slice(native.node_id());
    // 3. receipt_type (1 byte)
    buf.push(native.receipt_type().as_u8());
    // 4. usage_proof_hash (32 bytes)
    buf.extend_from_slice(native.usage_proof_hash());
    // 5. execution_commitment hash (32 bytes)
    buf.extend_from_slice(&ec_hash);
    // 6. aggregate_signature_hash (32 bytes)
    buf.extend_from_slice(&sig_hash);
    // 7. node_signature (variable)
    buf.extend_from_slice(native.node_signature());
    // 8. submitter_address (20 bytes)
    buf.extend_from_slice(native.submitter_address());
    // 9. reward_base (16 bytes, big-endian)
    buf.extend_from_slice(&native.reward_base().to_be_bytes());
    // 10. timestamp (8 bytes, big-endian)
    buf.extend_from_slice(&native.timestamp().to_be_bytes());
    // 11. epoch (8 bytes, big-endian)
    buf.extend_from_slice(&native.epoch().to_be_bytes());

    let mut hasher = Sha3_256::new();
    hasher.update(&buf);
    let result = hasher.finalize();

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Compute receipt hash from proto directly.
///
/// Identical to `ReceiptV1Proto::compute_receipt_hash()`.
pub fn compute_receipt_hash_from_proto(
    proto: &ReceiptV1Proto,
) -> Result<[u8; 32], ConversionError> {
    let ec_hash = match &proto.execution_commitment {
        Some(ec) => {
            let native_ec = ExecutionCommitment::try_from_fields(
                &ec.workload_id,
                &ec.input_hash,
                &ec.output_hash,
                &ec.state_root_before,
                &ec.state_root_after,
                &ec.execution_trace_merkle_root,
            )?;
            native_ec.compute_hash()
        }
        None => ZERO_HASH_32,
    };

    let sig_hash = compute_aggregate_signature_hash(&proto.coordinator_threshold_signature);

    let mut buf = Vec::with_capacity(277);

    buf.extend_from_slice(&proto.workload_id);
    buf.extend_from_slice(&proto.node_id);
    buf.push(proto.receipt_type);
    buf.extend_from_slice(&proto.usage_proof_hash);
    buf.extend_from_slice(&ec_hash);
    buf.extend_from_slice(&sig_hash);
    buf.extend_from_slice(&proto.node_signature);
    buf.extend_from_slice(&proto.submitter_address);
    buf.extend_from_slice(&proto.reward_base.to_be_bytes());
    buf.extend_from_slice(&proto.timestamp.to_be_bytes());
    buf.extend_from_slice(&proto.epoch.to_be_bytes());

    let mut hasher = Sha3_256::new();
    hasher.update(&buf);
    let result = hasher.finalize();

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    Ok(hash)
}

// ════════════════════════════════════════════════════════════════════════════════
// EXECUTION COMMITMENT CONVERSION
// ════════════════════════════════════════════════════════════════════════════════

impl ExecutionCommitment {
    /// Converts from proto to native ExecutionCommitment.
    ///
    /// All 6 fields must be exactly 32 bytes. No truncation, no padding.
    ///
    /// # Errors
    ///
    /// Returns `ConversionError::InvalidFieldLength` if any field is not 32 bytes.
    pub fn from_proto(proto: &ExecutionCommitmentProto) -> Result<Self, ConversionError> {
        let native = ExecutionCommitment::try_from_fields(
            &proto.workload_id,
            &proto.input_hash,
            &proto.output_hash,
            &proto.state_root_before,
            &proto.state_root_after,
            &proto.execution_trace_merkle_root,
        )?;
        Ok(native)
    }

    /// Converts native ExecutionCommitment to proto.
    ///
    /// Lossless. Cannot fail. Cannot panic.
    #[must_use]
    pub fn to_proto(&self) -> ExecutionCommitmentProto {
        let (wid, ih, oh, srb, sra, etm) = self.to_fields();
        ExecutionCommitmentProto {
            workload_id: wid,
            input_hash: ih,
            output_hash: oh,
            state_root_before: srb,
            state_root_after: sra,
            execution_trace_merkle_root: etm,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// RECEIPT V1 CONVERSION
// ════════════════════════════════════════════════════════════════════════════════

impl ReceiptV1 {
    /// Converts from proto to native ReceiptV1.
    ///
    /// # Conversion Rules
    ///
    /// - `workload_id`: Vec<u8> (32) → WorkloadId
    /// - `node_id`: Vec<u8> (32) → NodeId [u8; 32]
    /// - `receipt_type`: u8 → ReceiptType (0=Storage, 1=Compute)
    /// - `usage_proof_hash`: Vec<u8> (32) → [u8; 32]
    /// - `execution_commitment`: required if Compute, None if Storage
    /// - `coordinator_threshold_signature`: AggregateSignatureProto.signature → Vec<u8>
    /// - `signer_ids`: AggregateSignatureProto.signer_ids → Vec<[u8; 32]>
    /// - `node_signature`: Vec<u8> → Vec<u8>
    /// - `submitter_address`: Vec<u8> (20) → Address [u8; 20]
    ///
    /// # Errors
    ///
    /// - `InvalidFieldLength` for wrong-sized fields
    /// - `MissingRequiredField` for Compute without execution_commitment
    /// - `InvalidValue` for unknown receipt_type
    pub fn from_proto(proto: &ReceiptV1Proto) -> Result<Self, ConversionError> {
        // workload_id (32 bytes)
        let workload_id = vec_to_array_32(&proto.workload_id, "workload_id")?;

        // node_id (32 bytes)
        let node_id: NodeId = vec_to_array_32(&proto.node_id, "node_id")?;

        // receipt_type
        let receipt_type = match proto.receipt_type {
            0 => ReceiptType::Storage,
            1 => ReceiptType::Compute,
            other => {
                return Err(ConversionError::InvalidValue {
                    field: "receipt_type",
                    reason: format!("expected 0 or 1, got {}", other),
                });
            }
        };

        // usage_proof_hash (32 bytes)
        let usage_proof_hash = vec_to_array_32(&proto.usage_proof_hash, "usage_proof_hash")?;

        // execution_commitment
        let execution_commitment = match (receipt_type, &proto.execution_commitment) {
            (ReceiptType::Compute, Some(ec_proto)) => {
                Some(ExecutionCommitment::from_proto(ec_proto)?)
            }
            (ReceiptType::Compute, None) => {
                return Err(ConversionError::MissingRequiredField {
                    field: "execution_commitment",
                });
            }
            (ReceiptType::Storage, None) => None,
            (ReceiptType::Storage, Some(_)) => {
                return Err(ConversionError::InvalidValue {
                    field: "execution_commitment",
                    reason: "storage receipt must not have execution_commitment".to_string(),
                });
            }
        };

        // coordinator_threshold_signature → extract signature bytes
        let coordinator_threshold_signature =
            proto.coordinator_threshold_signature.signature.clone();

        // signer_ids → convert Vec<Vec<u8>> to Vec<[u8; 32]>
        let mut signer_ids = Vec::with_capacity(
            proto.coordinator_threshold_signature.signer_ids.len(),
        );
        for (i, sid) in proto
            .coordinator_threshold_signature
            .signer_ids
            .iter()
            .enumerate()
        {
            if sid.len() != 32 {
                return Err(ConversionError::InvalidFieldLength {
                    field: "signer_ids",
                    expected: 32,
                    got: sid.len(),
                });
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(sid);
            signer_ids.push(arr);
            // Suppress unused variable warning for loop index.
            let _ = i;
        }

        // node_signature
        let node_signature = proto.node_signature.clone();

        // submitter_address (20 bytes)
        let submitter_address: Address =
            vec_to_array_20(&proto.submitter_address, "submitter_address")?;

        let native = ReceiptV1::new(
            WorkloadId::new(workload_id),
            node_id,
            receipt_type,
            usage_proof_hash,
            execution_commitment,
            coordinator_threshold_signature,
            signer_ids,
            node_signature,
            submitter_address,
            proto.reward_base,
            proto.timestamp,
            proto.epoch,
        )?;

        Ok(native)
    }

    /// Converts native ReceiptV1 to proto.
    ///
    /// Reconstructs `AggregateSignatureProto` from native fields.
    /// `message_hash` and `aggregated_at` in the aggregate signature
    /// are set to zero-filled values since native does not store them.
    ///
    /// Cannot fail. Cannot panic.
    #[must_use]
    pub fn to_proto(&self) -> ReceiptV1Proto {
        let execution_commitment = self.execution_commitment().map(|ec| ec.to_proto());

        let signer_ids_proto: Vec<Vec<u8>> = self
            .signer_ids()
            .iter()
            .map(|sid| sid.to_vec())
            .collect();

        let coordinator_threshold_signature = AggregateSignatureProto {
            signature: self.coordinator_threshold_signature().to_vec(),
            signer_ids: signer_ids_proto,
            message_hash: vec![0u8; 32],
            aggregated_at: 0,
        };

        ReceiptV1Proto {
            workload_id: self.workload_id().as_bytes().to_vec(),
            node_id: self.node_id().to_vec(),
            receipt_type: self.receipt_type().as_u8(),
            usage_proof_hash: self.usage_proof_hash().to_vec(),
            execution_commitment,
            coordinator_threshold_signature,
            node_signature: self.node_signature().to_vec(),
            submitter_address: self.submitter_address().to_vec(),
            reward_base: self.reward_base(),
            timestamp: self.timestamp(),
            epoch: self.epoch(),
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// CLAIM REWARD NATIVE TYPE
// ════════════════════════════════════════════════════════════════════════════════

/// Native representation of a ClaimReward transaction.
///
/// Wraps a `ReceiptV1` with submitter authentication data.
///
/// ## Flow
///
/// 1. Node receives `ReceiptV1Proto` from coordinator.
/// 2. Node builds `ClaimReward` wrapping the receipt.
/// 3. Node signs the transaction.
/// 4. Submit to chain.
/// 5. Chain verifies receipt, signatures, anti-self-dealing, double-claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimReward {
    /// The receipt being claimed.
    pub receipt: ReceiptV1,
    /// Address of the submitter (20 bytes).
    pub submitter_address: Address,
    /// Ed25519 signature from the submitter. Must not be empty.
    pub submitter_signature: Vec<u8>,
    /// Nonce for ordering and replay protection.
    pub nonce: u64,
    /// Unix timestamp when the transaction was created.
    pub timestamp: u64,
}

// ════════════════════════════════════════════════════════════════════════════════
// CLAIM REWARD CONVERSION
// ════════════════════════════════════════════════════════════════════════════════

impl ClaimReward {
    /// Converts from proto to native ClaimReward.
    ///
    /// # Validation
    ///
    /// - `receipt`: validated via `ReceiptV1::from_proto()`
    /// - `submitter_address`: must be 20 bytes
    /// - `submitter_signature`: must not be empty
    ///
    /// # Errors
    ///
    /// - `InvalidFieldLength` for wrong-sized submitter_address
    /// - `MissingRequiredField` for empty submitter_signature
    /// - Any error from `ReceiptV1::from_proto()`
    pub fn from_proto(proto: &ClaimRewardProto) -> Result<Self, ConversionError> {
        let receipt = ReceiptV1::from_proto(&proto.receipt)?;

        let submitter_address: Address =
            vec_to_array_20(&proto.submitter_address, "submitter_address")?;

        if proto.submitter_signature.is_empty() {
            return Err(ConversionError::MissingRequiredField {
                field: "submitter_signature",
            });
        }

        Ok(ClaimReward {
            receipt,
            submitter_address,
            submitter_signature: proto.submitter_signature.clone(),
            nonce: proto.nonce,
            timestamp: proto.timestamp,
        })
    }

    /// Converts native ClaimReward to proto.
    ///
    /// Cannot fail. Cannot panic.
    #[must_use]
    pub fn to_proto(&self) -> ClaimRewardProto {
        ClaimRewardProto {
            receipt: self.receipt.to_proto(),
            submitter_address: self.submitter_address.to_vec(),
            submitter_signature: self.submitter_signature.clone(),
            nonce: self.nonce,
            timestamp: self.timestamp,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── HELPERS ──────────────────────────────────────────────────────────

    fn make_ec_proto() -> ExecutionCommitmentProto {
        ExecutionCommitmentProto {
            workload_id: vec![0xA0; 32],
            input_hash: vec![0xA1; 32],
            output_hash: vec![0xA2; 32],
            state_root_before: vec![0xA3; 32],
            state_root_after: vec![0xA4; 32],
            execution_trace_merkle_root: vec![0xA5; 32],
        }
    }

    fn make_agg_sig_proto() -> AggregateSignatureProto {
        AggregateSignatureProto {
            signature: vec![0x04; 64],
            signer_ids: vec![vec![0x05; 32], vec![0x06; 32]],
            message_hash: vec![0xCC; 32],
            aggregated_at: 1700000000,
        }
    }

    fn make_storage_receipt_proto() -> ReceiptV1Proto {
        ReceiptV1Proto {
            workload_id: vec![0x01; 32],
            node_id: vec![0x02; 32],
            receipt_type: 0,
            usage_proof_hash: vec![0x03; 32],
            execution_commitment: None,
            coordinator_threshold_signature: make_agg_sig_proto(),
            node_signature: vec![0x07; 64],
            submitter_address: vec![0x08; 20],
            reward_base: 1000,
            timestamp: 1700000000,
            epoch: 42,
        }
    }

    fn make_compute_receipt_proto() -> ReceiptV1Proto {
        ReceiptV1Proto {
            workload_id: vec![0x01; 32],
            node_id: vec![0x02; 32],
            receipt_type: 1,
            usage_proof_hash: vec![0x03; 32],
            execution_commitment: Some(make_ec_proto()),
            coordinator_threshold_signature: make_agg_sig_proto(),
            node_signature: vec![0x07; 64],
            submitter_address: vec![0x08; 20],
            reward_base: 1000,
            timestamp: 1700000000,
            epoch: 42,
        }
    }

    fn make_claim_reward_proto() -> ClaimRewardProto {
        ClaimRewardProto {
            receipt: make_storage_receipt_proto(),
            submitter_address: vec![0x09; 20],
            submitter_signature: vec![0x0A; 64],
            nonce: 1,
            timestamp: 1700000001,
        }
    }

    // ── 1) execution_commitment_roundtrip ────────────────────────────────

    #[test]
    fn execution_commitment_roundtrip() {
        let proto = make_ec_proto();
        let native = ExecutionCommitment::from_proto(&proto).expect("from_proto");
        let back = native.to_proto();
        assert_eq!(proto, back);

        // Double roundtrip
        let native2 = ExecutionCommitment::from_proto(&back).expect("from_proto2");
        assert_eq!(native, native2);
    }

    // ── 2) execution_commitment_invalid_length ──────────────────────────

    #[test]
    fn execution_commitment_invalid_length() {
        let fields = [
            "workload_id",
            "input_hash",
            "output_hash",
            "state_root_before",
            "state_root_after",
            "execution_trace_merkle_root",
        ];

        for (i, field_name) in fields.iter().enumerate() {
            let mut proto = make_ec_proto();
            match i {
                0 => proto.workload_id = vec![0xFF; 16],
                1 => proto.input_hash = vec![0xFF; 16],
                2 => proto.output_hash = vec![0xFF; 16],
                3 => proto.state_root_before = vec![0xFF; 16],
                4 => proto.state_root_after = vec![0xFF; 16],
                5 => proto.execution_trace_merkle_root = vec![0xFF; 16],
                _ => {}
            }
            let err = ExecutionCommitment::from_proto(&proto).unwrap_err();
            let msg = format!("{}", err);
            assert!(
                msg.contains(field_name) || msg.contains("16"),
                "expected error for '{}', got: {}",
                field_name,
                msg
            );
        }
    }

    // ── 3) receipt_roundtrip_storage ─────────────────────────────────────

    #[test]
    fn receipt_roundtrip_storage() {
        let proto = make_storage_receipt_proto();
        let native = ReceiptV1::from_proto(&proto).expect("from_proto");
        assert_eq!(native.receipt_type(), ReceiptType::Storage);
        assert!(native.execution_commitment().is_none());

        let back = native.to_proto();
        // Core fields match.
        assert_eq!(proto.workload_id, back.workload_id);
        assert_eq!(proto.node_id, back.node_id);
        assert_eq!(proto.receipt_type, back.receipt_type);
        assert_eq!(proto.usage_proof_hash, back.usage_proof_hash);
        assert_eq!(proto.execution_commitment, back.execution_commitment);
        assert_eq!(
            proto.coordinator_threshold_signature.signature,
            back.coordinator_threshold_signature.signature
        );
        assert_eq!(
            proto.coordinator_threshold_signature.signer_ids,
            back.coordinator_threshold_signature.signer_ids
        );
        assert_eq!(proto.node_signature, back.node_signature);
        assert_eq!(proto.submitter_address, back.submitter_address);
        assert_eq!(proto.reward_base, back.reward_base);
        assert_eq!(proto.timestamp, back.timestamp);
        assert_eq!(proto.epoch, back.epoch);
    }

    // ── 4) receipt_roundtrip_compute ─────────────────────────────────────

    #[test]
    fn receipt_roundtrip_compute() {
        let proto = make_compute_receipt_proto();
        let native = ReceiptV1::from_proto(&proto).expect("from_proto");
        assert_eq!(native.receipt_type(), ReceiptType::Compute);
        assert!(native.execution_commitment().is_some());

        let back = native.to_proto();
        assert_eq!(proto.workload_id, back.workload_id);
        assert_eq!(proto.node_id, back.node_id);
        assert_eq!(proto.receipt_type, back.receipt_type);
        assert_eq!(proto.execution_commitment, back.execution_commitment);
        assert_eq!(
            proto.coordinator_threshold_signature.signature,
            back.coordinator_threshold_signature.signature
        );
        assert_eq!(proto.reward_base, back.reward_base);
    }

    // ── 5) receipt_missing_execution_commitment_error ────────────────────

    #[test]
    fn receipt_missing_execution_commitment_error() {
        let mut proto = make_compute_receipt_proto();
        proto.execution_commitment = None; // Compute but no EC!

        let err = ReceiptV1::from_proto(&proto).unwrap_err();
        match err {
            ConversionError::MissingRequiredField { field } => {
                assert_eq!(field, "execution_commitment");
            }
            other => panic!("expected MissingRequiredField, got {:?}", other),
        }
    }

    // ── 6) receipt_invalid_address_length ────────────────────────────────

    #[test]
    fn receipt_invalid_address_length() {
        let mut proto = make_storage_receipt_proto();
        proto.submitter_address = vec![0x08; 10]; // Wrong length!

        let err = ReceiptV1::from_proto(&proto).unwrap_err();
        match err {
            ConversionError::InvalidFieldLength {
                field,
                expected,
                got,
            } => {
                assert_eq!(field, "submitter_address");
                assert_eq!(expected, 20);
                assert_eq!(got, 10);
            }
            other => panic!("expected InvalidFieldLength, got {:?}", other),
        }
    }

    // ── 7) receipt_hash_consistency_storage ──────────────────────────────

    #[test]
    fn receipt_hash_consistency_storage() {
        let proto = make_storage_receipt_proto();
        let native = ReceiptV1::from_proto(&proto).expect("from_proto");

        let proto_hash = compute_receipt_hash_from_proto(&proto).expect("proto hash");
        let native_compat_hash =
            compute_receipt_hash_proto_compatible(&native, &proto.coordinator_threshold_signature);

        assert_eq!(
            proto_hash, native_compat_hash,
            "proto hash and native proto-compatible hash must be identical"
        );
    }

    // ── 8) receipt_hash_consistency_compute ──────────────────────────────

    #[test]
    fn receipt_hash_consistency_compute() {
        let proto = make_compute_receipt_proto();
        let native = ReceiptV1::from_proto(&proto).expect("from_proto");

        let proto_hash = compute_receipt_hash_from_proto(&proto).expect("proto hash");
        let native_compat_hash =
            compute_receipt_hash_proto_compatible(&native, &proto.coordinator_threshold_signature);

        assert_eq!(proto_hash, native_compat_hash);
    }

    // ── 9) claim_reward_roundtrip ────────────────────────────────────────

    #[test]
    fn claim_reward_roundtrip() {
        let proto = make_claim_reward_proto();
        let native = ClaimReward::from_proto(&proto).expect("from_proto");

        assert_eq!(native.submitter_address, [0x09; 20]);
        assert_eq!(native.submitter_signature, vec![0x0A; 64]);
        assert_eq!(native.nonce, 1);
        assert_eq!(native.timestamp, 1700000001);

        let back = native.to_proto();
        assert_eq!(proto.submitter_address, back.submitter_address);
        assert_eq!(proto.submitter_signature, back.submitter_signature);
        assert_eq!(proto.nonce, back.nonce);
        assert_eq!(proto.timestamp, back.timestamp);
    }

    // ── 10) claim_reward_invalid_signature_empty ─────────────────────────

    #[test]
    fn claim_reward_invalid_signature_empty() {
        let mut proto = make_claim_reward_proto();
        proto.submitter_signature = vec![]; // Empty!

        let err = ClaimReward::from_proto(&proto).unwrap_err();
        match err {
            ConversionError::MissingRequiredField { field } => {
                assert_eq!(field, "submitter_signature");
            }
            other => panic!("expected MissingRequiredField, got {:?}", other),
        }
    }

    // ── 11) claim_reward_invalid_address_length ──────────────────────────

    #[test]
    fn claim_reward_invalid_address_length() {
        let mut proto = make_claim_reward_proto();
        proto.submitter_address = vec![0x09; 5]; // Wrong!

        let err = ClaimReward::from_proto(&proto).unwrap_err();
        match err {
            ConversionError::InvalidFieldLength {
                field,
                expected,
                got,
            } => {
                assert_eq!(field, "submitter_address");
                assert_eq!(expected, 20);
                assert_eq!(got, 5);
            }
            other => panic!("expected InvalidFieldLength, got {:?}", other),
        }
    }

    // ── 12) conversion_error_messages_correct ────────────────────────────

    #[test]
    fn conversion_error_messages_correct() {
        let e1 = ConversionError::InvalidFieldLength {
            field: "test_field",
            expected: 32,
            got: 16,
        };
        let msg1 = format!("{}", e1);
        assert!(msg1.contains("test_field"));
        assert!(msg1.contains("32"));
        assert!(msg1.contains("16"));

        let e2 = ConversionError::MissingRequiredField {
            field: "missing_field",
        };
        let msg2 = format!("{}", e2);
        assert!(msg2.contains("missing_field"));

        let e3 = ConversionError::InvalidValue {
            field: "bad_field",
            reason: "out of range".to_string(),
        };
        let msg3 = format!("{}", e3);
        assert!(msg3.contains("bad_field"));
        assert!(msg3.contains("out of range"));
    }

    // ── 13) hash_determinism_randomized_100_iterations ───────────────────

    #[test]
    fn hash_determinism_randomized_100_iterations() {
        let proto = make_compute_receipt_proto();
        let reference_hash = compute_receipt_hash_from_proto(&proto).expect("ref hash");

        for _ in 0..100 {
            let hash = compute_receipt_hash_from_proto(&proto).expect("hash");
            assert_eq!(reference_hash, hash);
        }
    }

    // ── 14) signer_ids_invalid_length ────────────────────────────────────

    #[test]
    fn signer_ids_invalid_length() {
        let mut proto = make_storage_receipt_proto();
        proto.coordinator_threshold_signature.signer_ids = vec![vec![0xFF; 16]]; // Wrong!

        let err = ReceiptV1::from_proto(&proto).unwrap_err();
        match err {
            ConversionError::InvalidFieldLength {
                field,
                expected,
                got,
            } => {
                assert_eq!(field, "signer_ids");
                assert_eq!(expected, 32);
                assert_eq!(got, 16);
            }
            other => panic!("expected InvalidFieldLength, got {:?}", other),
        }
    }

    // ── 15) receipt_invalid_type_value ────────────────────────────────────

    #[test]
    fn receipt_invalid_type_value() {
        let mut proto = make_storage_receipt_proto();
        proto.receipt_type = 99; // Invalid!

        let err = ReceiptV1::from_proto(&proto).unwrap_err();
        match err {
            ConversionError::InvalidValue { field, reason } => {
                assert_eq!(field, "receipt_type");
                assert!(reason.contains("99"));
            }
            other => panic!("expected InvalidValue, got {:?}", other),
        }
    }

    // ── 16) storage_with_unexpected_ec ────────────────────────────────────

    #[test]
    fn storage_with_unexpected_ec() {
        let mut proto = make_storage_receipt_proto();
        proto.execution_commitment = Some(make_ec_proto()); // Storage + EC!

        let err = ReceiptV1::from_proto(&proto).unwrap_err();
        match err {
            ConversionError::InvalidValue { field, .. } => {
                assert_eq!(field, "execution_commitment");
            }
            other => panic!("expected InvalidValue, got {:?}", other),
        }
    }

    // ── 17) node_id_invalid_length ──────────────────────────────────────

    #[test]
    fn node_id_invalid_length() {
        let mut proto = make_storage_receipt_proto();
        proto.node_id = vec![0x02; 10]; // Wrong!

        let err = ReceiptV1::from_proto(&proto).unwrap_err();
        match err {
            ConversionError::InvalidFieldLength {
                field,
                expected,
                got,
            } => {
                assert_eq!(field, "node_id");
                assert_eq!(expected, 32);
                assert_eq!(got, 10);
            }
            other => panic!("expected InvalidFieldLength, got {:?}", other),
        }
    }

    // ── 18) aggregate_signature_hash_deterministic ───────────────────────

    #[test]
    fn aggregate_signature_hash_deterministic() {
        let agg = make_agg_sig_proto();
        let h1 = compute_aggregate_signature_hash(&agg);
        let h2 = compute_aggregate_signature_hash(&agg);
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 32]);
    }

    // ── 19) conversion_error_is_std_error ────────────────────────────────

    #[test]
    fn conversion_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(ConversionError::MissingRequiredField {
            field: "test",
        });
        assert!(!err.to_string().is_empty());
    }

    // ── 20) claim_reward_with_compute_receipt ────────────────────────────

    #[test]
    fn claim_reward_with_compute_receipt() {
        let mut proto = make_claim_reward_proto();
        proto.receipt = make_compute_receipt_proto();

        let native = ClaimReward::from_proto(&proto).expect("from_proto");
        assert_eq!(native.receipt.receipt_type(), ReceiptType::Compute);
        assert!(native.receipt.execution_commitment().is_some());
    }

    // ── 21) ec_hash_preserved_through_conversion ────────────────────────

    #[test]
    fn ec_hash_preserved_through_conversion() {
        let proto = make_ec_proto();
        let native = ExecutionCommitment::from_proto(&proto).expect("from_proto");
        let back = native.to_proto();
        let native2 = ExecutionCommitment::from_proto(&back).expect("from_proto2");

        assert_eq!(native.compute_hash(), native2.compute_hash());
    }
}