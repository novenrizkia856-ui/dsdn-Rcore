//! # ReceiptV1 — Native Receipt Type (Flow Baru)
//!
//! `ReceiptV1` adalah representasi native receipt untuk flow baru.
//!
//! ## Lifecycle
//!
//! 1. Node menghasilkan receipt
//! 2. Coordinator meng-aggregate threshold signature
//! 3. Receipt disubmit ke chain
//! 4. Jika Compute → challenge period aktif
//!
//! ## Perbedaan dengan `ReceiptV1Proto`
//!
//! | Aspek | Proto (crate proto) | Native (crate ini) |
//! |-------|--------------------|--------------------|
//! | Field types | `Vec<u8>`, `AggregateSignatureProto` | `WorkloadId`, `NodeId`, `Address`, fixed arrays |
//! | Validation | `.validate()` runtime | Constructor enforced |
//! | Use case | Wire format, serialization | Internal logic, chain, coordinator |
//!
//! ## Receipt Types
//!
//! | Value | Type | ExecutionCommitment | Challenge Period |
//! |-------|------|--------------------:|:----------------:|
//! | 0 | Storage | MUST be None | No |
//! | 1 | Compute | MUST be Some | Yes |
//!
//! ## Hash Order (consensus-critical)
//!
//! `compute_receipt_hash()` uses SHA3-256 with the following concatenation order:
//!
//! 1. `workload_id` (32 bytes)
//! 2. `node_id` (32 bytes)
//! 3. `receipt_type` (1 byte: 0=Storage, 1=Compute)
//! 4. `usage_proof_hash` (32 bytes)
//! 5. execution_commitment hash (32 bytes) — or 32 zero bytes if None
//! 6. `coordinator_threshold_signature` (variable bytes)
//! 7. `signer_ids` (concatenated as-is, each 32 bytes)
//! 8. `node_signature` (variable bytes)
//! 9. `submitter_address` (20 bytes)
//! 10. `reward_base` (16 bytes, big-endian)
//! 11. `timestamp` (8 bytes, big-endian)
//! 12. `epoch` (8 bytes, big-endian)
//!
//! `compute_receipt_hash()` HARUS identik dengan
//! `ReceiptV1Proto::compute_receipt_hash()` untuk menjamin
//! hash consistency cross-crate.

use crate::coordinator::WorkloadId;
use crate::coordinator::NodeId;
use crate::execution_commitment::ExecutionCommitment;
use sha3::{Digest, Sha3_256};
use std::fmt;

// ════════════════════════════════════════════════════════════════════════════════
// TYPE ALIASES
// ════════════════════════════════════════════════════════════════════════════════

/// Address is 20 bytes (first 20 bytes of SHA3-512(pubkey)).
///
/// Kompatibel dengan `chain::types::Address`.
pub type Address = [u8; 20];

// ════════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════════

/// 32 zero bytes, digunakan saat `execution_commitment` is `None`.
const ZERO_HASH_32: [u8; 32] = [0u8; 32];

// ════════════════════════════════════════════════════════════════════════════════
// RECEIPT TYPE
// ════════════════════════════════════════════════════════════════════════════════

/// Tipe receipt: Storage (0) atau Compute (1).
///
/// Menentukan apakah `execution_commitment` wajib dan
/// apakah challenge period berlaku.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptType {
    /// Storage receipt (0). Tidak memerlukan execution commitment.
    /// Tidak memerlukan challenge period.
    Storage,
    /// Compute receipt (1). Memerlukan execution commitment.
    /// Challenge period aktif.
    Compute,
}

impl ReceiptType {
    /// Mengkonversi ke u8 untuk hashing dan serialization.
    ///
    /// - `Storage` → 0
    /// - `Compute` → 1
    #[must_use]
    #[inline]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Storage => 0,
            Self::Compute => 1,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// ERROR
// ════════════════════════════════════════════════════════════════════════════════

/// Error saat konstruksi `ReceiptV1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptError {
    /// `receipt_type == Compute` tetapi `execution_commitment` is `None`.
    MissingExecutionCommitment,
    /// `receipt_type == Storage` tetapi `execution_commitment` is `Some`.
    UnexpectedExecutionCommitment,
    /// `coordinator_threshold_signature` kosong (len == 0).
    EmptyCoordinatorSignature,
    /// `node_signature` kosong (len == 0).
    EmptyNodeSignature,
}

impl fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingExecutionCommitment => {
                write!(
                    f,
                    "compute receipt requires execution_commitment (must be Some)"
                )
            }
            Self::UnexpectedExecutionCommitment => {
                write!(
                    f,
                    "storage receipt must not have execution_commitment (must be None)"
                )
            }
            Self::EmptyCoordinatorSignature => {
                write!(f, "coordinator_threshold_signature must not be empty")
            }
            Self::EmptyNodeSignature => {
                write!(f, "node_signature must not be empty")
            }
        }
    }
}

impl std::error::Error for ReceiptError {}

// ════════════════════════════════════════════════════════════════════════════════
// STRUCT
// ════════════════════════════════════════════════════════════════════════════════

/// ReceiptV1 adalah representasi native receipt untuk flow baru.
///
/// ## Lifecycle
///
/// 1. Node menghasilkan receipt
/// 2. Coordinator meng-aggregate threshold signature
/// 3. Receipt disubmit ke chain
/// 4. Jika Compute → challenge period aktif
///
/// ## Invariants
///
/// - Jika `receipt_type == Compute` → `execution_commitment` MUST be `Some`
/// - Jika `receipt_type == Storage` → `execution_commitment` MUST be `None`
/// - `coordinator_threshold_signature` MUST NOT be empty
/// - `node_signature` MUST NOT be empty
///
/// Invariants ini ditegakkan oleh constructor. Tidak ada cara lain
/// untuk membuat `ReceiptV1` selain melalui `new()`.
///
/// ## Hash Consistency
///
/// `compute_receipt_hash()` HARUS identik dengan proto layer
/// untuk menjamin hash consistency cross-crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptV1 {
    workload_id: WorkloadId,
    node_id: NodeId,
    receipt_type: ReceiptType,
    usage_proof_hash: [u8; 32],
    execution_commitment: Option<ExecutionCommitment>,
    coordinator_threshold_signature: Vec<u8>,
    signer_ids: Vec<[u8; 32]>,
    node_signature: Vec<u8>,
    submitter_address: Address,
    reward_base: u128,
    timestamp: u64,
    epoch: u64,
}

impl ReceiptV1 {
    // ────────────────────────────────────────────────────────────────────────
    // CONSTRUCTOR
    // ────────────────────────────────────────────────────────────────────────

    /// Membuat `ReceiptV1` baru dengan validasi invariants.
    ///
    /// ## Validasi
    ///
    /// - Jika `receipt_type == Compute` → `execution_commitment` MUST be `Some`
    /// - Jika `receipt_type == Storage` → `execution_commitment` MUST be `None`
    /// - `coordinator_threshold_signature` MUST NOT be empty
    /// - `node_signature` MUST NOT be empty
    ///
    /// ## Errors
    ///
    /// Mengembalikan `ReceiptError` jika salah satu validasi gagal.
    /// Tidak bisa panic.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        workload_id: WorkloadId,
        node_id: NodeId,
        receipt_type: ReceiptType,
        usage_proof_hash: [u8; 32],
        execution_commitment: Option<ExecutionCommitment>,
        coordinator_threshold_signature: Vec<u8>,
        signer_ids: Vec<[u8; 32]>,
        node_signature: Vec<u8>,
        submitter_address: Address,
        reward_base: u128,
        timestamp: u64,
        epoch: u64,
    ) -> Result<Self, ReceiptError> {
        // Validasi execution_commitment consistency dengan receipt_type.
        match receipt_type {
            ReceiptType::Compute => {
                if execution_commitment.is_none() {
                    return Err(ReceiptError::MissingExecutionCommitment);
                }
            }
            ReceiptType::Storage => {
                if execution_commitment.is_some() {
                    return Err(ReceiptError::UnexpectedExecutionCommitment);
                }
            }
        }

        // Validasi signature fields tidak kosong.
        if coordinator_threshold_signature.is_empty() {
            return Err(ReceiptError::EmptyCoordinatorSignature);
        }
        if node_signature.is_empty() {
            return Err(ReceiptError::EmptyNodeSignature);
        }

        Ok(Self {
            workload_id,
            node_id,
            receipt_type,
            usage_proof_hash,
            execution_commitment,
            coordinator_threshold_signature,
            signer_ids,
            node_signature,
            submitter_address,
            reward_base,
            timestamp,
            epoch,
        })
    }

    // ────────────────────────────────────────────────────────────────────────
    // GETTERS (return reference, bukan clone)
    // ────────────────────────────────────────────────────────────────────────

    /// Workload identifier (32 bytes).
    #[must_use]
    #[inline]
    pub fn workload_id(&self) -> &WorkloadId {
        &self.workload_id
    }

    /// Node identifier (32 bytes).
    #[must_use]
    #[inline]
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// Receipt type (Storage atau Compute).
    #[must_use]
    #[inline]
    pub fn receipt_type(&self) -> ReceiptType {
        self.receipt_type
    }

    /// Hash dari usage proof yang diverifikasi coordinator (32 bytes).
    #[must_use]
    #[inline]
    pub fn usage_proof_hash(&self) -> &[u8; 32] {
        &self.usage_proof_hash
    }

    /// Execution commitment (Some untuk Compute, None untuk Storage).
    #[must_use]
    #[inline]
    pub fn execution_commitment(&self) -> Option<&ExecutionCommitment> {
        self.execution_commitment.as_ref()
    }

    /// Coordinator threshold signature (FROST aggregate).
    #[must_use]
    #[inline]
    pub fn coordinator_threshold_signature(&self) -> &[u8] {
        &self.coordinator_threshold_signature
    }

    /// Signer IDs yang berpartisipasi dalam threshold signing.
    #[must_use]
    #[inline]
    pub fn signer_ids(&self) -> &[[u8; 32]] {
        &self.signer_ids
    }

    /// Ed25519 signature dari node atas receipt data.
    #[must_use]
    #[inline]
    pub fn node_signature(&self) -> &[u8] {
        &self.node_signature
    }

    /// Address pihak yang submit ClaimReward transaction (20 bytes).
    #[must_use]
    #[inline]
    pub fn submitter_address(&self) -> &Address {
        &self.submitter_address
    }

    /// Reward dasar yang akan didistribusikan.
    #[must_use]
    #[inline]
    pub fn reward_base(&self) -> u128 {
        self.reward_base
    }

    /// Unix timestamp saat receipt dibuat.
    #[must_use]
    #[inline]
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Epoch number saat receipt dibuat.
    #[must_use]
    #[inline]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    // ────────────────────────────────────────────────────────────────────────
    // HASH
    // ────────────────────────────────────────────────────────────────────────

    /// Menghitung SHA3-256 receipt hash deterministik.
    ///
    /// ## Hash Order (FIXED — consensus-critical)
    ///
    /// 1. `workload_id` (32 bytes)
    /// 2. `node_id` (32 bytes)
    /// 3. `receipt_type` (1 byte: 0=Storage, 1=Compute)
    /// 4. `usage_proof_hash` (32 bytes)
    /// 5. execution_commitment hash (32 bytes) — or 32 zero bytes if None
    /// 6. `coordinator_threshold_signature` (variable bytes)
    /// 7. `signer_ids` (concatenated as-is, each 32 bytes)
    /// 8. `node_signature` (variable bytes)
    /// 9. `submitter_address` (20 bytes)
    /// 10. `reward_base` (16 bytes, big-endian)
    /// 11. `timestamp` (8 bytes, big-endian)
    /// 12. `epoch` (8 bytes, big-endian)
    ///
    /// Tidak ada separator. Tidak bisa gagal. Tidak bisa panic.
    #[must_use]
    pub fn compute_receipt_hash(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();

        // 1. workload_id (32 bytes)
        hasher.update(self.workload_id.as_bytes());

        // 2. node_id (32 bytes)
        hasher.update(&self.node_id);

        // 3. receipt_type (1 byte)
        hasher.update([self.receipt_type.as_u8()]);

        // 4. usage_proof_hash (32 bytes)
        hasher.update(&self.usage_proof_hash);

        // 5. execution_commitment hash (32 bytes or zero)
        let ec_hash = match &self.execution_commitment {
            Some(ec) => ec.compute_hash(),
            None => ZERO_HASH_32,
        };
        hasher.update(&ec_hash);

        // 6. coordinator_threshold_signature (variable bytes)
        hasher.update(&self.coordinator_threshold_signature);

        // 7. signer_ids (concatenated, each 32 bytes)
        for signer_id in &self.signer_ids {
            hasher.update(signer_id);
        }

        // 8. node_signature (variable bytes)
        hasher.update(&self.node_signature);

        // 9. submitter_address (20 bytes)
        hasher.update(&self.submitter_address);

        // 10. reward_base (16 bytes, big-endian)
        hasher.update(self.reward_base.to_be_bytes());

        // 11. timestamp (8 bytes, big-endian)
        hasher.update(self.timestamp.to_be_bytes());

        // 12. epoch (8 bytes, big-endian)
        hasher.update(self.epoch.to_be_bytes());

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    // ────────────────────────────────────────────────────────────────────────
    // HELPER METHODS
    // ────────────────────────────────────────────────────────────────────────

    /// Return `true` jika receipt_type == Compute.
    ///
    /// Compute receipt memerlukan challenge period sebelum reward
    /// dapat diklaim, untuk memungkinkan fraud proof.
    #[must_use]
    #[inline]
    pub fn requires_challenge_period(&self) -> bool {
        self.receipt_type == ReceiptType::Compute
    }

    /// Return `true` jika execution_commitment is Some.
    #[must_use]
    #[inline]
    pub fn has_execution_commitment(&self) -> bool {
        self.execution_commitment.is_some()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ec() -> ExecutionCommitment {
        ExecutionCommitment::new(
            WorkloadId::new([0xA0; 32]),
            [0xA1; 32],
            [0xA2; 32],
            [0xA3; 32],
            [0xA4; 32],
            [0xA5; 32],
        )
    }

    fn make_storage_receipt() -> ReceiptV1 {
        ReceiptV1::new(
            WorkloadId::new([0x01; 32]),
            [0x02; 32],
            ReceiptType::Storage,
            [0x03; 32],
            None,
            vec![0x04; 64],
            vec![[0x05; 32], [0x06; 32]],
            vec![0x07; 64],
            [0x08; 20],
            1000,
            1700000000,
            42,
        )
        .expect("valid storage receipt")
    }

    fn make_compute_receipt() -> ReceiptV1 {
        ReceiptV1::new(
            WorkloadId::new([0x01; 32]),
            [0x02; 32],
            ReceiptType::Compute,
            [0x03; 32],
            Some(make_ec()),
            vec![0x04; 64],
            vec![[0x05; 32], [0x06; 32]],
            vec![0x07; 64],
            [0x08; 20],
            1000,
            1700000000,
            42,
        )
        .expect("valid compute receipt")
    }

    // ── RECEIPT TYPE ────────────────────────────────────────────────────

    #[test]
    fn receipt_type_as_u8() {
        assert_eq!(ReceiptType::Storage.as_u8(), 0);
        assert_eq!(ReceiptType::Compute.as_u8(), 1);
    }

    #[test]
    fn receipt_type_is_copy() {
        let t = ReceiptType::Compute;
        let t2 = t;
        assert_eq!(t, t2);
    }

    // ── CONSTRUCTOR VALIDATION ──────────────────────────────────────────

    #[test]
    fn storage_valid() {
        let r = make_storage_receipt();
        assert_eq!(r.receipt_type(), ReceiptType::Storage);
        assert!(r.execution_commitment().is_none());
    }

    #[test]
    fn compute_valid() {
        let r = make_compute_receipt();
        assert_eq!(r.receipt_type(), ReceiptType::Compute);
        assert!(r.execution_commitment().is_some());
    }

    #[test]
    fn compute_missing_ec() {
        let result = ReceiptV1::new(
            WorkloadId::new([0x01; 32]),
            [0x02; 32],
            ReceiptType::Compute,
            [0x03; 32],
            None,
            vec![0x04; 64],
            vec![],
            vec![0x07; 64],
            [0x08; 20],
            1000, 1700000000, 42,
        );
        assert_eq!(result, Err(ReceiptError::MissingExecutionCommitment));
    }

    #[test]
    fn storage_unexpected_ec() {
        let result = ReceiptV1::new(
            WorkloadId::new([0x01; 32]),
            [0x02; 32],
            ReceiptType::Storage,
            [0x03; 32],
            Some(make_ec()),
            vec![0x04; 64],
            vec![],
            vec![0x07; 64],
            [0x08; 20],
            1000, 1700000000, 42,
        );
        assert_eq!(result, Err(ReceiptError::UnexpectedExecutionCommitment));
    }

    #[test]
    fn empty_coordinator_signature() {
        let result = ReceiptV1::new(
            WorkloadId::new([0x01; 32]),
            [0x02; 32],
            ReceiptType::Storage,
            [0x03; 32],
            None,
            vec![],
            vec![],
            vec![0x07; 64],
            [0x08; 20],
            1000, 1700000000, 42,
        );
        assert_eq!(result, Err(ReceiptError::EmptyCoordinatorSignature));
    }

    #[test]
    fn empty_node_signature() {
        let result = ReceiptV1::new(
            WorkloadId::new([0x01; 32]),
            [0x02; 32],
            ReceiptType::Storage,
            [0x03; 32],
            None,
            vec![0x04; 64],
            vec![],
            vec![],
            [0x08; 20],
            1000, 1700000000, 42,
        );
        assert_eq!(result, Err(ReceiptError::EmptyNodeSignature));
    }

    // ── VALIDATION ORDER (first error wins) ─────────────────────────────

    #[test]
    fn validation_ec_checked_before_signatures() {
        let result = ReceiptV1::new(
            WorkloadId::new([0x01; 32]),
            [0x02; 32],
            ReceiptType::Compute,
            [0x03; 32],
            None,
            vec![], vec![], vec![],
            [0x08; 20],
            1000, 1700000000, 42,
        );
        assert_eq!(result, Err(ReceiptError::MissingExecutionCommitment));
    }

    #[test]
    fn validation_coordinator_sig_before_node_sig() {
        let result = ReceiptV1::new(
            WorkloadId::new([0x01; 32]),
            [0x02; 32],
            ReceiptType::Storage,
            [0x03; 32],
            None,
            vec![], vec![], vec![],
            [0x08; 20],
            1000, 1700000000, 42,
        );
        assert_eq!(result, Err(ReceiptError::EmptyCoordinatorSignature));
    }

    // ── GETTERS ─────────────────────────────────────────────────────────

    #[test]
    fn getters_storage() {
        let r = make_storage_receipt();
        assert_eq!(r.workload_id().as_bytes(), &[0x01; 32]);
        assert_eq!(r.node_id(), &[0x02; 32]);
        assert_eq!(r.receipt_type(), ReceiptType::Storage);
        assert_eq!(r.usage_proof_hash(), &[0x03; 32]);
        assert!(r.execution_commitment().is_none());
        assert_eq!(r.coordinator_threshold_signature(), &[0x04; 64]);
        assert_eq!(r.signer_ids().len(), 2);
        assert_eq!(r.signer_ids()[0], [0x05; 32]);
        assert_eq!(r.signer_ids()[1], [0x06; 32]);
        assert_eq!(r.node_signature(), &[0x07; 64]);
        assert_eq!(r.submitter_address(), &[0x08; 20]);
        assert_eq!(r.reward_base(), 1000);
        assert_eq!(r.timestamp(), 1700000000);
        assert_eq!(r.epoch(), 42);
    }

    #[test]
    fn getters_compute() {
        let r = make_compute_receipt();
        assert_eq!(r.receipt_type(), ReceiptType::Compute);
        assert!(r.execution_commitment().is_some());
    }

    // ── HELPER METHODS ──────────────────────────────────────────────────

    #[test]
    fn requires_challenge_period_compute() {
        assert!(make_compute_receipt().requires_challenge_period());
    }

    #[test]
    fn requires_challenge_period_storage() {
        assert!(!make_storage_receipt().requires_challenge_period());
    }

    #[test]
    fn has_execution_commitment_compute() {
        assert!(make_compute_receipt().has_execution_commitment());
    }

    #[test]
    fn has_execution_commitment_storage() {
        assert!(!make_storage_receipt().has_execution_commitment());
    }

    // ── HASH DETERMINISM ────────────────────────────────────────────────

    #[test]
    fn hash_deterministic_same_instance() {
        let r = make_storage_receipt();
        assert_eq!(r.compute_receipt_hash(), r.compute_receipt_hash());
    }

    #[test]
    fn hash_deterministic_identical_instances() {
        assert_eq!(
            make_storage_receipt().compute_receipt_hash(),
            make_storage_receipt().compute_receipt_hash()
        );
    }

    #[test]
    fn hash_not_zero() {
        assert_ne!(make_storage_receipt().compute_receipt_hash(), [0u8; 32]);
    }

    #[test]
    fn hash_output_32_bytes() {
        assert_eq!(make_storage_receipt().compute_receipt_hash().len(), 32);
    }

    #[test]
    fn hash_differs_storage_vs_compute() {
        assert_ne!(
            make_storage_receipt().compute_receipt_hash(),
            make_compute_receipt().compute_receipt_hash()
        );
    }

    // ── HASH SENSITIVITY (setiap field mengubah hash) ───────────────────

    #[test]
    fn hash_differs_workload_id() {
        let r2 = ReceiptV1::new(
            WorkloadId::new([0xFF; 32]),
            [0x02; 32], ReceiptType::Storage, [0x03; 32], None,
            vec![0x04; 64], vec![[0x05; 32], [0x06; 32]], vec![0x07; 64],
            [0x08; 20], 1000, 1700000000, 42,
        ).expect("valid");
        assert_ne!(make_storage_receipt().compute_receipt_hash(), r2.compute_receipt_hash());
    }

    #[test]
    fn hash_differs_node_id() {
        let r2 = ReceiptV1::new(
            WorkloadId::new([0x01; 32]),
            [0xFF; 32], ReceiptType::Storage, [0x03; 32], None,
            vec![0x04; 64], vec![[0x05; 32], [0x06; 32]], vec![0x07; 64],
            [0x08; 20], 1000, 1700000000, 42,
        ).expect("valid");
        assert_ne!(make_storage_receipt().compute_receipt_hash(), r2.compute_receipt_hash());
    }

    #[test]
    fn hash_differs_usage_proof_hash() {
        let r2 = ReceiptV1::new(
            WorkloadId::new([0x01; 32]),
            [0x02; 32], ReceiptType::Storage, [0xFF; 32], None,
            vec![0x04; 64], vec![[0x05; 32], [0x06; 32]], vec![0x07; 64],
            [0x08; 20], 1000, 1700000000, 42,
        ).expect("valid");
        assert_ne!(make_storage_receipt().compute_receipt_hash(), r2.compute_receipt_hash());
    }

    #[test]
    fn hash_differs_coordinator_sig() {
        let r2 = ReceiptV1::new(
            WorkloadId::new([0x01; 32]),
            [0x02; 32], ReceiptType::Storage, [0x03; 32], None,
            vec![0xFF; 64], vec![[0x05; 32], [0x06; 32]], vec![0x07; 64],
            [0x08; 20], 1000, 1700000000, 42,
        ).expect("valid");
        assert_ne!(make_storage_receipt().compute_receipt_hash(), r2.compute_receipt_hash());
    }

    #[test]
    fn hash_differs_signer_ids() {
        let r2 = ReceiptV1::new(
            WorkloadId::new([0x01; 32]),
            [0x02; 32], ReceiptType::Storage, [0x03; 32], None,
            vec![0x04; 64], vec![[0xFF; 32], [0x06; 32]], vec![0x07; 64],
            [0x08; 20], 1000, 1700000000, 42,
        ).expect("valid");
        assert_ne!(make_storage_receipt().compute_receipt_hash(), r2.compute_receipt_hash());
    }

    #[test]
    fn hash_differs_node_signature() {
        let r2 = ReceiptV1::new(
            WorkloadId::new([0x01; 32]),
            [0x02; 32], ReceiptType::Storage, [0x03; 32], None,
            vec![0x04; 64], vec![[0x05; 32], [0x06; 32]], vec![0xFF; 64],
            [0x08; 20], 1000, 1700000000, 42,
        ).expect("valid");
        assert_ne!(make_storage_receipt().compute_receipt_hash(), r2.compute_receipt_hash());
    }

    #[test]
    fn hash_differs_submitter_address() {
        let r2 = ReceiptV1::new(
            WorkloadId::new([0x01; 32]),
            [0x02; 32], ReceiptType::Storage, [0x03; 32], None,
            vec![0x04; 64], vec![[0x05; 32], [0x06; 32]], vec![0x07; 64],
            [0xFF; 20], 1000, 1700000000, 42,
        ).expect("valid");
        assert_ne!(make_storage_receipt().compute_receipt_hash(), r2.compute_receipt_hash());
    }

    #[test]
    fn hash_differs_reward_base() {
        let r2 = ReceiptV1::new(
            WorkloadId::new([0x01; 32]),
            [0x02; 32], ReceiptType::Storage, [0x03; 32], None,
            vec![0x04; 64], vec![[0x05; 32], [0x06; 32]], vec![0x07; 64],
            [0x08; 20], 9999, 1700000000, 42,
        ).expect("valid");
        assert_ne!(make_storage_receipt().compute_receipt_hash(), r2.compute_receipt_hash());
    }

    #[test]
    fn hash_differs_timestamp() {
        let r2 = ReceiptV1::new(
            WorkloadId::new([0x01; 32]),
            [0x02; 32], ReceiptType::Storage, [0x03; 32], None,
            vec![0x04; 64], vec![[0x05; 32], [0x06; 32]], vec![0x07; 64],
            [0x08; 20], 1000, 9999999999, 42,
        ).expect("valid");
        assert_ne!(make_storage_receipt().compute_receipt_hash(), r2.compute_receipt_hash());
    }

    #[test]
    fn hash_differs_epoch() {
        let r2 = ReceiptV1::new(
            WorkloadId::new([0x01; 32]),
            [0x02; 32], ReceiptType::Storage, [0x03; 32], None,
            vec![0x04; 64], vec![[0x05; 32], [0x06; 32]], vec![0x07; 64],
            [0x08; 20], 1000, 1700000000, 99,
        ).expect("valid");
        assert_ne!(make_storage_receipt().compute_receipt_hash(), r2.compute_receipt_hash());
    }

    #[test]
    fn hash_differs_execution_commitment() {
        let ec2 = ExecutionCommitment::new(
            WorkloadId::new([0xB0; 32]),
            [0xB1; 32], [0xB2; 32], [0xB3; 32], [0xB4; 32], [0xB5; 32],
        );
        let r1 = ReceiptV1::new(
            WorkloadId::new([0x01; 32]),
            [0x02; 32], ReceiptType::Compute, [0x03; 32], Some(make_ec()),
            vec![0x04; 64], vec![[0x05; 32]], vec![0x07; 64],
            [0x08; 20], 1000, 1700000000, 42,
        ).expect("valid");
        let r2 = ReceiptV1::new(
            WorkloadId::new([0x01; 32]),
            [0x02; 32], ReceiptType::Compute, [0x03; 32], Some(ec2),
            vec![0x04; 64], vec![[0x05; 32]], vec![0x07; 64],
            [0x08; 20], 1000, 1700000000, 42,
        ).expect("valid");
        assert_ne!(r1.compute_receipt_hash(), r2.compute_receipt_hash());
    }

    // ── ERROR TYPE ──────────────────────────────────────────────────────

    #[test]
    fn error_display_missing_ec() {
        let msg = format!("{}", ReceiptError::MissingExecutionCommitment);
        assert!(msg.contains("execution_commitment"));
        assert!(msg.contains("Some"));
    }

    #[test]
    fn error_display_unexpected_ec() {
        let msg = format!("{}", ReceiptError::UnexpectedExecutionCommitment);
        assert!(msg.contains("execution_commitment"));
        assert!(msg.contains("None"));
    }

    #[test]
    fn error_display_empty_coordinator_sig() {
        let msg = format!("{}", ReceiptError::EmptyCoordinatorSignature);
        assert!(msg.contains("coordinator_threshold_signature"));
    }

    #[test]
    fn error_display_empty_node_sig() {
        let msg = format!("{}", ReceiptError::EmptyNodeSignature);
        assert!(msg.contains("node_signature"));
    }

    #[test]
    fn error_implements_std_error() {
        let err: Box<dyn std::error::Error> =
            Box::new(ReceiptError::MissingExecutionCommitment);
        assert!(!err.to_string().is_empty());
    }

    // ── EQ / CLONE / DEBUG ──────────────────────────────────────────────

    #[test]
    fn eq_reflexive() {
        let r = make_storage_receipt();
        assert_eq!(r, r);
    }

    #[test]
    fn clone_produces_equal() {
        let r = make_compute_receipt();
        let r2 = r.clone();
        assert_eq!(r, r2);
        assert_eq!(r.compute_receipt_hash(), r2.compute_receipt_hash());
    }

    #[test]
    fn debug_format_not_empty() {
        let dbg = format!("{:?}", make_storage_receipt());
        assert!(!dbg.is_empty());
        assert!(dbg.contains("ReceiptV1"));
    }

    // ── EDGE CASES ──────────────────────────────────────────────────────

    #[test]
    fn empty_signer_ids_allowed() {
        let result = ReceiptV1::new(
            WorkloadId::new([0x01; 32]),
            [0x02; 32], ReceiptType::Storage, [0x03; 32], None,
            vec![0x04; 64], vec![], vec![0x07; 64],
            [0x08; 20], 1000, 1700000000, 42,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn zero_reward_and_epoch_allowed() {
        let result = ReceiptV1::new(
            WorkloadId::new([0x01; 32]),
            [0x02; 32], ReceiptType::Storage, [0x03; 32], None,
            vec![0x04; 64], vec![], vec![0x07; 64],
            [0x08; 20], 0, 0, 0,
        );
        assert!(result.is_ok());
    }
}