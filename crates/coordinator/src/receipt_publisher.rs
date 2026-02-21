//! # Receipt DA Publication (CO.6)
//!
//! Publishes assembled `ReceiptV1Proto` to a Data Availability (DA) layer
//! as blobs and retrieves them back by reference.
//!
//! ## Architecture
//!
//! ```text
//! ReceiptV1Proto (assembled, CO.5)
//!     │
//!     ▼
//! ReceiptPublisher::publish_receipt()
//!     │
//!     ├── 1. Encode receipt → deterministic bytes
//!     ├── 2. Submit blob via DAClient trait
//!     └── 3. Return DABlobRef (height, namespace, commitment)
//!             │
//!             ▼
//!         DA Layer (Celestia or mock)
//!
//! DABlobRef
//!     │
//!     ▼
//! ReceiptPublisher::retrieve_receipt()
//!     │
//!     ├── 1. Validate namespace match
//!     ├── 2. Get blob bytes via DAClient trait
//!     ├── 3. Decode bytes → ReceiptV1Proto
//!     ├── 4. Validate receipt
//!     └── 5. Return ReceiptV1Proto
//! ```
//!
//! ## Celestia Namespace Convention
//!
//! The `namespace` is a fixed byte sequence set at construction time.
//! It identifies this publisher's blobs within the DA layer.
//! The namespace MUST NOT change during the `ReceiptPublisher` lifetime.
//!
//! Typical convention: `b"dsdn_receipts_v1"` or a SHA3-256-derived
//! namespace from the chain ID.
//!
//! ## Blob Format
//!
//! Blobs contain a deterministic binary encoding of `ReceiptV1Proto`
//! with no additional wrapper. The encoding uses:
//!
//! - Little-endian byte order for all integers.
//! - Length-prefixed byte fields (`u32 LE` length + raw bytes).
//! - Presence flag (`u8`: 0=None, 1=Some) for `Option` fields.
//! - Fixed field order matching `ReceiptV1Proto` struct declaration.
//!
//! See [`encode_receipt`] and [`decode_receipt`] for the exact specification.
//!
//! ## Why DAClient Is a Trait
//!
//! - **Testability**: Unit tests use `MockDAClient` without a running DA node.
//! - **Decoupling**: No compile-time dependency on Celestia SDK.
//! - **Portability**: Allows swapping DA backends (Celestia, Avail, EigenDA).
//!
//! ## Safety
//!
//! - No panic, unwrap, expect, todo, unreachable.
//! - No mutation of receipt during publish.
//! - Namespace immutable after construction.
//! - Receipt validated on retrieval before return.
//! - Fully deterministic encoding: same receipt → same bytes.

use dsdn_common::receipt_v1_convert::{
    AggregateSignatureProto, ExecutionCommitmentProto, ReceiptV1Proto,
};
use crate::multi::receipt_assembler::validate_receipt_proto;

use std::fmt;
use std::future::Future;
use std::pin::Pin;

// ════════════════════════════════════════════════════════════════════════════════
// DA ERROR
// ════════════════════════════════════════════════════════════════════════════════

/// Error type for DA layer operations.
///
/// Returned by [`DAClient`] methods to indicate transport or storage failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DAError {
    /// Human-readable error description.
    pub message: String,
}

impl fmt::Display for DAError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DA error: {}", self.message)
    }
}

impl std::error::Error for DAError {}

// ════════════════════════════════════════════════════════════════════════════════
// DA BLOB REF
// ════════════════════════════════════════════════════════════════════════════════

/// Reference to a blob stored in the DA layer.
///
/// Returned by [`DAClient::submit_blob`] and used to retrieve the blob later.
/// Contains enough information to uniquely identify and locate the blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DABlobRef {
    /// DA layer block height where the blob was included.
    pub height: u64,
    /// Namespace the blob was submitted under.
    pub namespace: Vec<u8>,
    /// Blob commitment (DA-layer-specific, opaque to the coordinator).
    pub commitment: Vec<u8>,
}

// ════════════════════════════════════════════════════════════════════════════════
// DA CLIENT TRAIT
// ════════════════════════════════════════════════════════════════════════════════

/// Abstract interface for Data Availability layer operations.
///
/// Implementations handle the actual communication with a DA node
/// (e.g., Celestia, Avail). The coordinator only interacts through
/// this trait, enabling testability and backend portability.
///
/// ## Thread Safety
///
/// Implementations MUST be `Send + Sync` to support async runtimes
/// with work-stealing schedulers.
///
/// ## Object Safety
///
/// Methods return `Pin<Box<dyn Future>>` to support `&dyn DAClient`.
pub trait DAClient: Send + Sync {
    /// Submits a blob to the DA layer under the given namespace.
    ///
    /// Returns a `DABlobRef` that can be used to retrieve the blob later.
    fn submit_blob(
        &self,
        namespace: &[u8],
        data: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<DABlobRef, DAError>> + Send + '_>>;

    /// Retrieves blob data from the DA layer by reference.
    ///
    /// Returns the raw bytes that were originally submitted.
    fn get_blob(
        &self,
        blob_ref: &DABlobRef,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, DAError>> + Send + '_>>;
}

// ════════════════════════════════════════════════════════════════════════════════
// PUBLISH ERROR
// ════════════════════════════════════════════════════════════════════════════════

/// Error type for receipt publication failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishError {
    /// Failed to encode receipt to binary format.
    EncodeFailed(String),
    /// DA layer rejected or failed the blob submission.
    DASubmitFailed(DAError),
}

impl fmt::Display for PublishError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PublishError::EncodeFailed(reason) => {
                write!(f, "receipt encoding failed: {}", reason)
            }
            PublishError::DASubmitFailed(err) => {
                write!(f, "DA blob submission failed: {}", err)
            }
        }
    }
}

impl std::error::Error for PublishError {}

// ════════════════════════════════════════════════════════════════════════════════
// RETRIEVE ERROR
// ════════════════════════════════════════════════════════════════════════════════

/// Error type for receipt retrieval failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetrieveError {
    /// The blob reference's namespace does not match the publisher's namespace.
    NamespaceMismatch {
        expected: Vec<u8>,
        found: Vec<u8>,
    },
    /// DA layer failed to return the blob.
    DAGetFailed(DAError),
    /// Failed to decode blob bytes into a `ReceiptV1Proto`.
    DecodeFailed(String),
    /// The decoded receipt failed structural validation.
    ValidationFailed(String),
}

impl fmt::Display for RetrieveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RetrieveError::NamespaceMismatch { expected, found } => {
                write!(
                    f,
                    "namespace mismatch: expected {} bytes, found {} bytes",
                    expected.len(),
                    found.len()
                )
            }
            RetrieveError::DAGetFailed(err) => {
                write!(f, "DA blob retrieval failed: {}", err)
            }
            RetrieveError::DecodeFailed(reason) => {
                write!(f, "receipt decoding failed: {}", reason)
            }
            RetrieveError::ValidationFailed(reason) => {
                write!(f, "receipt validation failed: {}", reason)
            }
        }
    }
}

impl std::error::Error for RetrieveError {}

// ════════════════════════════════════════════════════════════════════════════════
// RECEIPT PUBLISHER
// ════════════════════════════════════════════════════════════════════════════════

/// Publishes and retrieves `ReceiptV1Proto` blobs to/from a DA layer.
///
/// ## Namespace Immutability
///
/// The `namespace` is set at construction time and never changes.
/// All blobs published by this instance use the same namespace.
///
/// ## Thread Safety
///
/// `ReceiptPublisher` is `Send + Sync` (no interior mutability).
/// The `DAClient` implementation handles its own concurrency.
#[derive(Debug, Clone)]
pub struct ReceiptPublisher {
    namespace: Vec<u8>,
}

impl ReceiptPublisher {
    /// Creates a new `ReceiptPublisher` with the given namespace.
    ///
    /// The namespace identifies this publisher's blobs within the DA layer.
    /// Typically set to `b"dsdn_receipts_v1"` or derived from the chain ID.
    #[must_use]
    pub fn new(namespace: Vec<u8>) -> Self {
        Self { namespace }
    }

    /// Returns the publisher's namespace.
    #[must_use]
    pub fn namespace(&self) -> &[u8] {
        &self.namespace
    }

    /// Publishes a signed receipt to the DA layer.
    ///
    /// ## Steps
    ///
    /// 1. Encode `receipt` to deterministic binary format via [`encode_receipt`].
    /// 2. Submit the encoded blob to the DA layer via `da_client.submit_blob()`.
    /// 3. Return the resulting `DABlobRef`.
    ///
    /// ## Arguments
    ///
    /// * `receipt` — Immutable reference to the assembled receipt.
    /// * `da_client` — DA layer client implementation.
    ///
    /// ## Errors
    ///
    /// * `PublishError::EncodeFailed` — Receipt encoding failed.
    /// * `PublishError::DASubmitFailed` — DA layer rejected the blob.
    pub async fn publish_receipt(
        &self,
        receipt: &ReceiptV1Proto,
        da_client: &dyn DAClient,
    ) -> Result<DABlobRef, PublishError> {
        // Step 1: Encode.
        let blob_data = encode_receipt(receipt)
            .map_err(PublishError::EncodeFailed)?;

        // Step 2: Submit.
        let blob_ref = da_client
            .submit_blob(&self.namespace, &blob_data)
            .await
            .map_err(PublishError::DASubmitFailed)?;

        // Step 3: Return.
        Ok(blob_ref)
    }

    /// Retrieves and validates a receipt from the DA layer.
    ///
    /// ## Steps
    ///
    /// 1. Validate that `blob_ref.namespace` matches `self.namespace`.
    /// 2. Retrieve blob bytes via `da_client.get_blob()`.
    /// 3. Decode bytes to `ReceiptV1Proto` via [`decode_receipt`].
    /// 4. Validate the decoded receipt via [`validate_receipt_proto`].
    /// 5. Return the validated receipt.
    ///
    /// ## Errors
    ///
    /// * `RetrieveError::NamespaceMismatch` — Blob ref namespace differs.
    /// * `RetrieveError::DAGetFailed` — DA layer failed to return the blob.
    /// * `RetrieveError::DecodeFailed` — Blob bytes could not be decoded.
    /// * `RetrieveError::ValidationFailed` — Decoded receipt failed validation.
    pub async fn retrieve_receipt(
        &self,
        blob_ref: &DABlobRef,
        da_client: &dyn DAClient,
    ) -> Result<ReceiptV1Proto, RetrieveError> {
        // Step 1: Namespace check.
        if blob_ref.namespace != self.namespace {
            return Err(RetrieveError::NamespaceMismatch {
                expected: self.namespace.clone(),
                found: blob_ref.namespace.clone(),
            });
        }

        // Step 2: Get blob.
        let blob_data = da_client
            .get_blob(blob_ref)
            .await
            .map_err(RetrieveError::DAGetFailed)?;

        // Step 3: Decode.
        let receipt = decode_receipt(&blob_data)
            .map_err(RetrieveError::DecodeFailed)?;

        // Step 4: Validate.
        validate_receipt_proto(&receipt)
            .map_err(RetrieveError::ValidationFailed)?;

        // Step 5: Return.
        Ok(receipt)
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// DETERMINISTIC BINARY ENCODING
// ════════════════════════════════════════════════════════════════════════════════

/// Magic bytes identifying the encoding format.
/// Prevents misinterpretation of arbitrary data as a receipt.
const MAGIC: [u8; 4] = [0x44, 0x53, 0x44, 0x4E]; // "DSDN"

/// Encoding version. Increment on format changes.
const ENCODING_VERSION: u8 = 1;

/// Encodes a `ReceiptV1Proto` into a deterministic binary format.
///
/// ## Wire Format (version 1)
///
/// ```text
/// [0..4]    Magic: b"DSDN"
/// [4]       Version: 0x01
/// [5..]     Fields in declaration order:
///
///   workload_id:            len_u32_le + bytes
///   node_id:                len_u32_le + bytes
///   receipt_type:           u8
///   usage_proof_hash:       len_u32_le + bytes
///   execution_commitment:   presence_u8 + (if 1: 6 × len_u32_le + bytes)
///   coordinator_threshold_signature:
///     signature:            len_u32_le + bytes
///     signer_ids:           count_u32_le + (count × len_u32_le + bytes)
///     message_hash:         len_u32_le + bytes
///     aggregated_at:        u64_le
///   node_signature:         len_u32_le + bytes
///   submitter_address:      len_u32_le + bytes
///   reward_base:            u128_le
///   timestamp:              u64_le
///   epoch:                  u64_le
/// ```
///
/// ## Determinism
///
/// Same `ReceiptV1Proto` → same bytes. No randomness, no padding.
#[must_use]
pub fn encode_receipt(receipt: &ReceiptV1Proto) -> Result<Vec<u8>, String> {
    let mut buf = Vec::with_capacity(512);

    // Header.
    buf.extend_from_slice(&MAGIC);
    buf.push(ENCODING_VERSION);

    // workload_id.
    write_bytes(&mut buf, &receipt.workload_id);

    // node_id.
    write_bytes(&mut buf, &receipt.node_id);

    // receipt_type.
    buf.push(receipt.receipt_type);

    // usage_proof_hash.
    write_bytes(&mut buf, &receipt.usage_proof_hash);

    // execution_commitment (optional).
    match &receipt.execution_commitment {
        None => buf.push(0),
        Some(ec) => {
            buf.push(1);
            write_bytes(&mut buf, &ec.workload_id);
            write_bytes(&mut buf, &ec.input_hash);
            write_bytes(&mut buf, &ec.output_hash);
            write_bytes(&mut buf, &ec.state_root_before);
            write_bytes(&mut buf, &ec.state_root_after);
            write_bytes(&mut buf, &ec.execution_trace_merkle_root);
        }
    }

    // coordinator_threshold_signature.
    let agg = &receipt.coordinator_threshold_signature;
    write_bytes(&mut buf, &agg.signature);

    // signer_ids: count + each.
    let count = agg.signer_ids.len();
    if count > u32::MAX as usize {
        return Err("signer_ids count exceeds u32::MAX".to_string());
    }
    buf.extend_from_slice(&(count as u32).to_le_bytes());
    for signer_id in &agg.signer_ids {
        write_bytes(&mut buf, signer_id);
    }

    write_bytes(&mut buf, &agg.message_hash);
    buf.extend_from_slice(&agg.aggregated_at.to_le_bytes());

    // node_signature.
    write_bytes(&mut buf, &receipt.node_signature);

    // submitter_address.
    write_bytes(&mut buf, &receipt.submitter_address);

    // reward_base.
    buf.extend_from_slice(&receipt.reward_base.to_le_bytes());

    // timestamp.
    buf.extend_from_slice(&receipt.timestamp.to_le_bytes());

    // epoch.
    buf.extend_from_slice(&receipt.epoch.to_le_bytes());

    Ok(buf)
}

/// Decodes a `ReceiptV1Proto` from deterministic binary format.
///
/// Inverse of [`encode_receipt`]. Returns an error if the data is
/// malformed, truncated, or has an incompatible version.
pub fn decode_receipt(data: &[u8]) -> Result<ReceiptV1Proto, String> {
    let mut cursor = Cursor::new(data);

    // Header.
    let magic = cursor.read_fixed::<4>("magic")?;
    if magic != MAGIC {
        return Err(format!(
            "invalid magic: expected {:?}, got {:?}",
            MAGIC, magic
        ));
    }

    let version = cursor.read_u8("version")?;
    if version != ENCODING_VERSION {
        return Err(format!(
            "unsupported encoding version: expected {}, got {}",
            ENCODING_VERSION, version
        ));
    }

    // Fields.
    let workload_id = cursor.read_bytes("workload_id")?;
    let node_id = cursor.read_bytes("node_id")?;
    let receipt_type = cursor.read_u8("receipt_type")?;
    let usage_proof_hash = cursor.read_bytes("usage_proof_hash")?;

    // execution_commitment (optional).
    let ec_flag = cursor.read_u8("execution_commitment.presence")?;
    let execution_commitment = if ec_flag == 1 {
        Some(ExecutionCommitmentProto {
            workload_id: cursor.read_bytes("ec.workload_id")?,
            input_hash: cursor.read_bytes("ec.input_hash")?,
            output_hash: cursor.read_bytes("ec.output_hash")?,
            state_root_before: cursor.read_bytes("ec.state_root_before")?,
            state_root_after: cursor.read_bytes("ec.state_root_after")?,
            execution_trace_merkle_root: cursor.read_bytes("ec.execution_trace_merkle_root")?,
        })
    } else if ec_flag == 0 {
        None
    } else {
        return Err(format!(
            "invalid execution_commitment presence flag: expected 0 or 1, got {}",
            ec_flag
        ));
    };

    // coordinator_threshold_signature.
    let agg_signature = cursor.read_bytes("agg.signature")?;

    let signer_count = cursor.read_u32("agg.signer_count")?;
    let mut signer_ids = Vec::with_capacity(signer_count as usize);
    for i in 0..signer_count {
        signer_ids.push(cursor.read_bytes(&format!("agg.signer_ids[{}]", i))?);
    }

    let message_hash = cursor.read_bytes("agg.message_hash")?;
    let aggregated_at = cursor.read_u64("agg.aggregated_at")?;

    let coordinator_threshold_signature = AggregateSignatureProto {
        signature: agg_signature,
        signer_ids,
        message_hash,
        aggregated_at,
    };

    // Remaining fields.
    let node_signature = cursor.read_bytes("node_signature")?;
    let submitter_address = cursor.read_bytes("submitter_address")?;
    let reward_base = cursor.read_u128("reward_base")?;
    let timestamp = cursor.read_u64("timestamp")?;
    let epoch = cursor.read_u64("epoch")?;

    Ok(ReceiptV1Proto {
        workload_id,
        node_id,
        receipt_type,
        usage_proof_hash,
        execution_commitment,
        coordinator_threshold_signature,
        node_signature,
        submitter_address,
        reward_base,
        timestamp,
        epoch,
    })
}

// ════════════════════════════════════════════════════════════════════════════════
// ENCODING HELPERS
// ════════════════════════════════════════════════════════════════════════════════

/// Write a length-prefixed byte field: `u32 LE length` + raw bytes.
fn write_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    // Length is guaranteed to fit u32 for any reasonable field (< 4GB).
    // In practice, receipt fields are < 1KB.
    let len = data.len() as u32;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(data);
}

/// Read cursor over a byte slice. Tracks position for error reporting.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Read exactly `N` bytes as a fixed-size array.
    fn read_fixed<const N: usize>(&mut self, field: &str) -> Result<[u8; N], String> {
        if self.pos + N > self.data.len() {
            return Err(format!(
                "unexpected EOF reading {}: need {} bytes at offset {}, have {}",
                field,
                N,
                self.pos,
                self.data.len()
            ));
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(&self.data[self.pos..self.pos + N]);
        self.pos += N;
        Ok(arr)
    }

    /// Read a single `u8`.
    fn read_u8(&mut self, field: &str) -> Result<u8, String> {
        let arr = self.read_fixed::<1>(field)?;
        Ok(arr[0])
    }

    /// Read a `u32` in little-endian.
    fn read_u32(&mut self, field: &str) -> Result<u32, String> {
        let arr = self.read_fixed::<4>(field)?;
        Ok(u32::from_le_bytes(arr))
    }

    /// Read a `u64` in little-endian.
    fn read_u64(&mut self, field: &str) -> Result<u64, String> {
        let arr = self.read_fixed::<8>(field)?;
        Ok(u64::from_le_bytes(arr))
    }

    /// Read a `u128` in little-endian.
    fn read_u128(&mut self, field: &str) -> Result<u128, String> {
        let arr = self.read_fixed::<16>(field)?;
        Ok(u128::from_le_bytes(arr))
    }

    /// Read a length-prefixed byte field: `u32 LE length` + raw bytes.
    fn read_bytes(&mut self, field: &str) -> Result<Vec<u8>, String> {
        let len = self.read_u32(&format!("{}.len", field))? as usize;
        if self.pos + len > self.data.len() {
            return Err(format!(
                "unexpected EOF reading {} data: need {} bytes at offset {}, have {}",
                field,
                len,
                self.pos,
                self.data.len()
            ));
        }
        let bytes = self.data[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(bytes)
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// MOCK DA CLIENT
// ════════════════════════════════════════════════════════════════════════════════

/// In-memory mock implementation of [`DAClient`] for testing.
///
/// Stores blobs in a `Vec` and returns sequential heights.
/// Thread-safe via `std::sync::Mutex`.
#[cfg(test)]
pub struct MockDAClient {
    blobs: std::sync::Mutex<Vec<(Vec<u8>, Vec<u8>)>>, // (namespace, data)
    fail_submit: std::sync::Mutex<bool>,
    fail_get: std::sync::Mutex<bool>,
}

#[cfg(test)]
impl MockDAClient {
    fn new() -> Self {
        Self {
            blobs: std::sync::Mutex::new(Vec::new()),
            fail_submit: std::sync::Mutex::new(false),
            fail_get: std::sync::Mutex::new(false),
        }
    }

    fn set_fail_submit(&self, fail: bool) {
        if let Ok(mut f) = self.fail_submit.lock() {
            *f = fail;
        }
    }

    fn set_fail_get(&self, fail: bool) {
        if let Ok(mut f) = self.fail_get.lock() {
            *f = fail;
        }
    }
}

#[cfg(test)]
impl DAClient for MockDAClient {
    fn submit_blob(
        &self,
        namespace: &[u8],
        data: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<DABlobRef, DAError>> + Send + '_>> {
        let namespace = namespace.to_vec();
        let data = data.to_vec();
        Box::pin(async move {
            if let Ok(f) = self.fail_submit.lock() {
                if *f {
                    return Err(DAError {
                        message: "mock submit failure".to_string(),
                    });
                }
            }

            let height = if let Ok(mut blobs) = self.blobs.lock() {
                let h = blobs.len() as u64 + 1;
                blobs.push((namespace.clone(), data));
                h
            } else {
                return Err(DAError {
                    message: "lock poisoned".to_string(),
                });
            };

            Ok(DABlobRef {
                height,
                namespace,
                commitment: vec![0xCC; 32], // Mock commitment.
            })
        })
    }

    fn get_blob(
        &self,
        blob_ref: &DABlobRef,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, DAError>> + Send + '_>> {
        let height = blob_ref.height;
        Box::pin(async move {
            if let Ok(f) = self.fail_get.lock() {
                if *f {
                    return Err(DAError {
                        message: "mock get failure".to_string(),
                    });
                }
            }

            if let Ok(blobs) = self.blobs.lock() {
                let idx = height as usize;
                if idx == 0 || idx > blobs.len() {
                    return Err(DAError {
                        message: format!("blob not found at height {}", height),
                    });
                }
                Ok(blobs[idx - 1].1.clone())
            } else {
                Err(DAError {
                    message: "lock poisoned".to_string(),
                })
            }
        })
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ──────────────────────────────────────────────────────────

    fn make_agg_sig() -> AggregateSignatureProto {
        AggregateSignatureProto {
            signature: vec![0xAA; 64],
            signer_ids: vec![vec![0x0A; 32], vec![0x0B; 32]],
            message_hash: vec![0xBB; 32],
            aggregated_at: 1_700_000_000,
        }
    }

    fn make_ec_proto() -> ExecutionCommitmentProto {
        ExecutionCommitmentProto {
            workload_id: vec![0x01; 32],
            input_hash: vec![0x02; 32],
            output_hash: vec![0x03; 32],
            state_root_before: vec![0x04; 32],
            state_root_after: vec![0x05; 32],
            execution_trace_merkle_root: vec![0x06; 32],
        }
    }

    fn make_storage_receipt() -> ReceiptV1Proto {
        ReceiptV1Proto {
            workload_id: vec![0x01; 32],
            node_id: vec![0x02; 32],
            receipt_type: 0,
            usage_proof_hash: vec![0x03; 32],
            execution_commitment: None,
            coordinator_threshold_signature: make_agg_sig(),
            node_signature: vec![0x07; 64],
            submitter_address: vec![0x08; 20],
            reward_base: 1000,
            timestamp: 1_700_000_000,
            epoch: 42,
        }
    }

    fn make_compute_receipt() -> ReceiptV1Proto {
        ReceiptV1Proto {
            workload_id: vec![0x01; 32],
            node_id: vec![0x02; 32],
            receipt_type: 1,
            usage_proof_hash: vec![0x03; 32],
            execution_commitment: Some(make_ec_proto()),
            coordinator_threshold_signature: make_agg_sig(),
            node_signature: vec![0x07; 64],
            submitter_address: vec![0x08; 20],
            reward_base: 2000,
            timestamp: 1_700_000_000,
            epoch: 42,
        }
    }

    // ── Encode/Decode Roundtrip ─────────────────────────────────────────

    #[test]
    fn roundtrip_storage_receipt() {
        let receipt = make_storage_receipt();
        let encoded = encode_receipt(&receipt).expect("encode");
        let decoded = decode_receipt(&encoded).expect("decode");
        assert_eq!(receipt, decoded);
    }

    #[test]
    fn roundtrip_compute_receipt() {
        let receipt = make_compute_receipt();
        let encoded = encode_receipt(&receipt).expect("encode");
        let decoded = decode_receipt(&encoded).expect("decode");
        assert_eq!(receipt, decoded);
    }

    #[test]
    fn encode_deterministic() {
        let receipt = make_storage_receipt();
        let e1 = encode_receipt(&receipt).expect("encode");
        let e2 = encode_receipt(&receipt).expect("encode");
        assert_eq!(e1, e2);
    }

    #[test]
    fn encode_deterministic_100_iterations() {
        let receipt = make_compute_receipt();
        let reference = encode_receipt(&receipt).expect("encode");
        for _ in 0..100 {
            assert_eq!(encode_receipt(&receipt).expect("encode"), reference);
        }
    }

    #[test]
    fn encode_starts_with_magic() {
        let receipt = make_storage_receipt();
        let encoded = encode_receipt(&receipt).expect("encode");
        assert_eq!(&encoded[0..4], &MAGIC);
        assert_eq!(encoded[4], ENCODING_VERSION);
    }

    #[test]
    fn decode_invalid_magic() {
        let mut encoded = encode_receipt(&make_storage_receipt()).expect("encode");
        encoded[0] = 0xFF; // Corrupt magic.
        let result = decode_receipt(&encoded);
        assert!(result.is_err());
        assert!(result.err().map_or(false, |s| s.contains("magic")));
    }

    #[test]
    fn decode_invalid_version() {
        let mut encoded = encode_receipt(&make_storage_receipt()).expect("encode");
        encoded[4] = 99; // Unknown version.
        let result = decode_receipt(&encoded);
        assert!(result.is_err());
        assert!(result.err().map_or(false, |s| s.contains("version")));
    }

    #[test]
    fn decode_truncated_data() {
        let encoded = encode_receipt(&make_storage_receipt()).expect("encode");
        let truncated = &encoded[..10]; // Way too short.
        let result = decode_receipt(truncated);
        assert!(result.is_err());
        assert!(result.err().map_or(false, |s| s.contains("EOF")));
    }

    #[test]
    fn decode_empty_data() {
        let result = decode_receipt(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn different_receipts_different_encoding() {
        let s = encode_receipt(&make_storage_receipt()).expect("encode");
        let c = encode_receipt(&make_compute_receipt()).expect("encode");
        assert_ne!(s, c);
    }

    // ── Publisher ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn publish_and_retrieve_storage() {
        let publisher = ReceiptPublisher::new(b"test_ns".to_vec());
        let client = MockDAClient::new();
        let receipt = make_storage_receipt();

        let blob_ref = publisher
            .publish_receipt(&receipt, &client)
            .await
            .expect("publish");

        assert_eq!(blob_ref.namespace, b"test_ns");
        assert_eq!(blob_ref.height, 1);

        let retrieved = publisher
            .retrieve_receipt(&blob_ref, &client)
            .await
            .expect("retrieve");

        assert_eq!(receipt, retrieved);
    }

    #[tokio::test]
    async fn publish_and_retrieve_compute() {
        let publisher = ReceiptPublisher::new(b"test_ns".to_vec());
        let client = MockDAClient::new();
        let receipt = make_compute_receipt();

        let blob_ref = publisher
            .publish_receipt(&receipt, &client)
            .await
            .expect("publish");

        let retrieved = publisher
            .retrieve_receipt(&blob_ref, &client)
            .await
            .expect("retrieve");

        assert_eq!(receipt, retrieved);
    }

    #[tokio::test]
    async fn publish_da_failure() {
        let publisher = ReceiptPublisher::new(b"test_ns".to_vec());
        let client = MockDAClient::new();
        client.set_fail_submit(true);

        let result = publisher
            .publish_receipt(&make_storage_receipt(), &client)
            .await;

        assert!(matches!(result, Err(PublishError::DASubmitFailed(_))));
    }

    #[tokio::test]
    async fn retrieve_namespace_mismatch() {
        let publisher = ReceiptPublisher::new(b"correct_ns".to_vec());
        let blob_ref = DABlobRef {
            height: 1,
            namespace: b"wrong_ns".to_vec(),
            commitment: vec![0xCC; 32],
        };
        let client = MockDAClient::new();

        let result = publisher.retrieve_receipt(&blob_ref, &client).await;
        assert!(matches!(
            result,
            Err(RetrieveError::NamespaceMismatch { .. })
        ));
    }

    #[tokio::test]
    async fn retrieve_da_failure() {
        let publisher = ReceiptPublisher::new(b"test_ns".to_vec());
        let client = MockDAClient::new();

        // Publish first.
        let blob_ref = publisher
            .publish_receipt(&make_storage_receipt(), &client)
            .await
            .expect("publish");

        // Then fail retrieval.
        client.set_fail_get(true);
        let result = publisher.retrieve_receipt(&blob_ref, &client).await;
        assert!(matches!(result, Err(RetrieveError::DAGetFailed(_))));
    }

    #[tokio::test]
    async fn retrieve_corrupt_data() {
        let publisher = ReceiptPublisher::new(b"test_ns".to_vec());
        let client = MockDAClient::new();

        // Publish first.
        let blob_ref = publisher
            .publish_receipt(&make_storage_receipt(), &client)
            .await
            .expect("publish");

        // Corrupt the stored data.
        if let Ok(mut blobs) = client.blobs.lock() {
            blobs[0].1 = vec![0xFF; 10]; // Garbage.
        }

        let result = publisher.retrieve_receipt(&blob_ref, &client).await;
        assert!(matches!(result, Err(RetrieveError::DecodeFailed(_))));
    }

    #[tokio::test]
    async fn multiple_publishes_sequential_heights() {
        let publisher = ReceiptPublisher::new(b"test_ns".to_vec());
        let client = MockDAClient::new();

        let r1 = publisher
            .publish_receipt(&make_storage_receipt(), &client)
            .await
            .expect("publish 1");
        let r2 = publisher
            .publish_receipt(&make_compute_receipt(), &client)
            .await
            .expect("publish 2");

        assert_eq!(r1.height, 1);
        assert_eq!(r2.height, 2);
    }

    #[tokio::test]
    async fn publish_does_not_mutate_receipt() {
        let publisher = ReceiptPublisher::new(b"test_ns".to_vec());
        let client = MockDAClient::new();
        let receipt = make_storage_receipt();
        let receipt_clone = receipt.clone();

        let _ = publisher.publish_receipt(&receipt, &client).await;
        assert_eq!(receipt, receipt_clone);
    }

    // ── Publisher Namespace ──────────────────────────────────────────────

    #[test]
    fn publisher_namespace_getter() {
        let publisher = ReceiptPublisher::new(b"my_namespace".to_vec());
        assert_eq!(publisher.namespace(), b"my_namespace");
    }

    // ── Error Display ────────────────────────────────────────────────────

    #[test]
    fn publish_error_display() {
        let e1 = PublishError::EncodeFailed("bad".to_string());
        assert!(format!("{}", e1).contains("bad"));

        let e2 = PublishError::DASubmitFailed(DAError {
            message: "timeout".to_string(),
        });
        assert!(format!("{}", e2).contains("timeout"));
    }

    #[test]
    fn retrieve_error_display() {
        let e1 = RetrieveError::NamespaceMismatch {
            expected: vec![1],
            found: vec![2],
        };
        assert!(format!("{}", e1).contains("mismatch"));

        let e2 = RetrieveError::DAGetFailed(DAError {
            message: "timeout".to_string(),
        });
        assert!(format!("{}", e2).contains("timeout"));

        let e3 = RetrieveError::DecodeFailed("bad".to_string());
        assert!(format!("{}", e3).contains("bad"));

        let e4 = RetrieveError::ValidationFailed("bad".to_string());
        assert!(format!("{}", e4).contains("bad"));
    }

    #[test]
    fn da_error_display() {
        let e = DAError {
            message: "connection refused".to_string(),
        };
        assert!(format!("{}", e).contains("connection refused"));
    }

    #[test]
    fn error_implements_std_error() {
        fn assert_error<E: std::error::Error>() {}
        assert_error::<DAError>();
        assert_error::<PublishError>();
        assert_error::<RetrieveError>();
    }
}