//! # ExecutionCommitment — Native Fixed-Size Type
//!
//! `ExecutionCommitment` merepresentasikan hasil deterministik eksekusi workload.
//! Digunakan sebagai basis fraud proof dalam sistem DSDN.
//!
//! ## Perbedaan dengan `ExecutionCommitmentProto`
//!
//! | Aspek | Proto (crate proto) | Native (crate ini) |
//! |-------|--------------------|--------------------|
//! | Field types | `Vec<u8>` | `[u8; 32]` / `WorkloadId` |
//! | Validation | Runtime (`.validate()`) | Compile-time (fixed-size) |
//! | Copy | No (heap-allocated) | Yes (stack-only, 192 bytes) |
//! | Use case | Wire format, serialization | Internal logic, chain, coordinator |
//!
//! ## Hash Order (FIXED — consensus-critical, immutable)
//!
//! ```text
//! workload_id (32) → input_hash (32) → output_hash (32)
//! → state_root_before (32) → state_root_after (32)
//! → execution_trace_merkle_root (32)
//! Total: 192 bytes → SHA3-256 → 32 bytes
//! ```
//!
//! ## Proto Conversion
//!
//! Karena `dsdn-proto` depends on `dsdn-common` (bukan sebaliknya),
//! `TryFrom<ExecutionCommitmentProto>` dan `From<ExecutionCommitment>`
//! HARUS diimplementasikan **di crate proto**, menggunakan:
//!
//! - [`ExecutionCommitment::try_from_fields`] untuk proto → native
//! - [`ExecutionCommitment::to_fields`] untuk native → proto
//!
//! Contoh implementasi di proto:
//!
//! ```rust,ignore
//! // Di crate proto:
//! impl TryFrom<ExecutionCommitmentProto> for ExecutionCommitment {
//!     type Error = ExecutionCommitmentError;
//!     fn try_from(p: ExecutionCommitmentProto) -> Result<Self, Self::Error> {
//!         ExecutionCommitment::try_from_fields(
//!             &p.workload_id, &p.input_hash, &p.output_hash,
//!             &p.state_root_before, &p.state_root_after,
//!             &p.execution_trace_merkle_root,
//!         )
//!     }
//! }
//!
//! impl From<ExecutionCommitment> for ExecutionCommitmentProto {
//!     fn from(ec: ExecutionCommitment) -> Self {
//!         let (wid, ih, oh, srb, sra, etm) = ec.to_fields();
//!         Self {
//!             workload_id: wid, input_hash: ih, output_hash: oh,
//!             state_root_before: srb, state_root_after: sra,
//!             execution_trace_merkle_root: etm,
//!         }
//!     }
//! }
//! ```

use crate::coordinator::WorkloadId;
use sha3::{Digest, Sha3_256};
use std::fmt;

// ════════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════════

/// Expected byte length per field.
const FIELD_SIZE: usize = 32;

// ════════════════════════════════════════════════════════════════════════════════
// ERROR
// ════════════════════════════════════════════════════════════════════════════════

/// Error saat konversi dari dynamic-length fields ke `ExecutionCommitment`.
///
/// Digunakan oleh [`ExecutionCommitment::try_from_fields`] dan oleh
/// `TryFrom<ExecutionCommitmentProto>` di crate proto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionCommitmentError {
    /// Sebuah field memiliki panjang yang tidak sesuai (expected 32 bytes).
    ///
    /// - `field`: nama field yang gagal validasi.
    /// - `found`: panjang aktual yang ditemukan.
    InvalidLength {
        field: &'static str,
        found: usize,
    },
}

impl fmt::Display for ExecutionCommitmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { field, found } => {
                write!(
                    f,
                    "invalid length for {}: expected {} bytes, found {}",
                    field, FIELD_SIZE, found
                )
            }
        }
    }
}

impl std::error::Error for ExecutionCommitmentError {}

// ════════════════════════════════════════════════════════════════════════════════
// STRUCT
// ════════════════════════════════════════════════════════════════════════════════

/// ExecutionCommitment merepresentasikan hasil deterministik eksekusi workload.
/// Digunakan sebagai basis fraud proof.
///
/// Semua field immutable setelah construction (private fields, getter-only API).
/// Struct ini sepenuhnya stack-allocated (192 bytes), Copy, dan thread-safe.
///
/// Hash order (consensus-critical, immutable):
/// workload_id → input_hash → output_hash → state_root_before
/// → state_root_after → execution_trace_merkle_root
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExecutionCommitment {
    workload_id: WorkloadId,
    input_hash: [u8; 32],
    output_hash: [u8; 32],
    state_root_before: [u8; 32],
    state_root_after: [u8; 32],
    execution_trace_merkle_root: [u8; 32],
}

impl ExecutionCommitment {
    // ────────────────────────────────────────────────────────────────────────
    // CONSTRUCTOR
    // ────────────────────────────────────────────────────────────────────────

    /// Membuat `ExecutionCommitment` baru dari semua field.
    ///
    /// Tidak ada validasi runtime — semua field sudah fixed-size.
    /// Tidak bisa panic.
    #[must_use]
    #[inline]
    pub const fn new(
        workload_id: WorkloadId,
        input_hash: [u8; 32],
        output_hash: [u8; 32],
        state_root_before: [u8; 32],
        state_root_after: [u8; 32],
        execution_trace_merkle_root: [u8; 32],
    ) -> Self {
        Self {
            workload_id,
            input_hash,
            output_hash,
            state_root_before,
            state_root_after,
            execution_trace_merkle_root,
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // GETTERS (return reference, bukan clone)
    // ────────────────────────────────────────────────────────────────────────

    /// Workload identifier (32 bytes).
    #[must_use]
    #[inline]
    pub const fn workload_id(&self) -> &WorkloadId {
        &self.workload_id
    }

    /// Hash dari input data sebelum eksekusi (32 bytes).
    #[must_use]
    #[inline]
    pub const fn input_hash(&self) -> &[u8; 32] {
        &self.input_hash
    }

    /// Hash dari output data setelah eksekusi (32 bytes).
    #[must_use]
    #[inline]
    pub const fn output_hash(&self) -> &[u8; 32] {
        &self.output_hash
    }

    /// State root sebelum eksekusi dimulai (32 bytes).
    #[must_use]
    #[inline]
    pub const fn state_root_before(&self) -> &[u8; 32] {
        &self.state_root_before
    }

    /// State root setelah eksekusi selesai (32 bytes).
    #[must_use]
    #[inline]
    pub const fn state_root_after(&self) -> &[u8; 32] {
        &self.state_root_after
    }

    /// Merkle root dari execution trace (32 bytes).
    #[must_use]
    #[inline]
    pub const fn execution_trace_merkle_root(&self) -> &[u8; 32] {
        &self.execution_trace_merkle_root
    }

    // ────────────────────────────────────────────────────────────────────────
    // HASH
    // ────────────────────────────────────────────────────────────────────────

    /// Menghitung SHA3-256 hash deterministik dari semua field.
    ///
    /// ## Hash Order (FIXED — consensus-critical, immutable)
    ///
    /// 1. `workload_id` (32 bytes)
    /// 2. `input_hash` (32 bytes)
    /// 3. `output_hash` (32 bytes)
    /// 4. `state_root_before` (32 bytes)
    /// 5. `state_root_after` (32 bytes)
    /// 6. `execution_trace_merkle_root` (32 bytes)
    ///
    /// Total: 192 bytes → SHA3-256 → 32 bytes.
    ///
    /// Tidak ada separator. Tidak ada length prefix.
    /// Tidak ada alokasi heap. Tidak bisa gagal. Tidak bisa panic.
    #[must_use]
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();

        hasher.update(self.workload_id.as_bytes());
        hasher.update(&self.input_hash);
        hasher.update(&self.output_hash);
        hasher.update(&self.state_root_before);
        hasher.update(&self.state_root_after);
        hasher.update(&self.execution_trace_merkle_root);

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    // ────────────────────────────────────────────────────────────────────────
    // PROTO CONVERSION HELPERS
    // ────────────────────────────────────────────────────────────────────────

    /// Membuat `ExecutionCommitment` dari raw byte slices (proto format).
    ///
    /// Setiap field HARUS exactly 32 bytes. Jika tidak, mengembalikan
    /// `ExecutionCommitmentError::InvalidLength` dengan field name pertama
    /// yang gagal (fail-fast).
    ///
    /// Validasi order:
    /// `workload_id → input_hash → output_hash → state_root_before
    /// → state_root_after → execution_trace_merkle_root`
    ///
    /// Digunakan oleh `TryFrom<ExecutionCommitmentProto>` di crate proto.
    pub fn try_from_fields(
        workload_id: &[u8],
        input_hash: &[u8],
        output_hash: &[u8],
        state_root_before: &[u8],
        state_root_after: &[u8],
        execution_trace_merkle_root: &[u8],
    ) -> Result<Self, ExecutionCommitmentError> {
        let wid = try_to_array(workload_id, "workload_id")?;
        let ih = try_to_array(input_hash, "input_hash")?;
        let oh = try_to_array(output_hash, "output_hash")?;
        let srb = try_to_array(state_root_before, "state_root_before")?;
        let sra = try_to_array(state_root_after, "state_root_after")?;
        let etm = try_to_array(execution_trace_merkle_root, "execution_trace_merkle_root")?;

        Ok(Self {
            workload_id: WorkloadId::new(wid),
            input_hash: ih,
            output_hash: oh,
            state_root_before: srb,
            state_root_after: sra,
            execution_trace_merkle_root: etm,
        })
    }

    /// Mengkonversi ke tuple of `Vec<u8>` untuk proto construction.
    ///
    /// Return order: `(workload_id, input_hash, output_hash,
    /// state_root_before, state_root_after, execution_trace_merkle_root)`
    ///
    /// Konversi ini lossless. Tidak bisa gagal. Tidak bisa panic.
    ///
    /// Digunakan oleh `From<ExecutionCommitment> for ExecutionCommitmentProto`
    /// di crate proto.
    #[must_use]
    pub fn to_fields(
        &self,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        (
            self.workload_id.as_bytes().to_vec(),
            self.input_hash.to_vec(),
            self.output_hash.to_vec(),
            self.state_root_before.to_vec(),
            self.state_root_after.to_vec(),
            self.execution_trace_merkle_root.to_vec(),
        )
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// INTERNAL HELPERS
// ════════════════════════════════════════════════════════════════════════════════

/// Konversi slice → `[u8; 32]` dengan structured error reporting.
fn try_to_array(
    slice: &[u8],
    field: &'static str,
) -> Result<[u8; 32], ExecutionCommitmentError> {
    if slice.len() != FIELD_SIZE {
        return Err(ExecutionCommitmentError::InvalidLength {
            field,
            found: slice.len(),
        });
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(slice);
    Ok(arr)
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ec() -> ExecutionCommitment {
        ExecutionCommitment::new(
            WorkloadId::new([0x01; 32]),
            [0x02; 32],
            [0x03; 32],
            [0x04; 32],
            [0x05; 32],
            [0x06; 32],
        )
    }

    // ── CONSTRUCTOR / GETTERS ───────────────────────────────────────────

    #[test]
    fn new_and_getters() {
        let ec = make_ec();
        assert_eq!(ec.workload_id().as_bytes(), &[0x01; 32]);
        assert_eq!(ec.input_hash(), &[0x02; 32]);
        assert_eq!(ec.output_hash(), &[0x03; 32]);
        assert_eq!(ec.state_root_before(), &[0x04; 32]);
        assert_eq!(ec.state_root_after(), &[0x05; 32]);
        assert_eq!(ec.execution_trace_merkle_root(), &[0x06; 32]);
    }

    // ── COPY TRAIT ──────────────────────────────────────────────────────

    #[test]
    fn is_copy() {
        let ec1 = make_ec();
        let ec2 = ec1; // Copy, not move
        assert_eq!(ec1, ec2); // ec1 still valid — proves Copy
    }

    // ── HASH DETERMINISM ────────────────────────────────────────────────

    #[test]
    fn hash_deterministic_same_instance() {
        let ec = make_ec();
        assert_eq!(ec.compute_hash(), ec.compute_hash());
    }

    #[test]
    fn hash_deterministic_identical_instances() {
        assert_eq!(make_ec().compute_hash(), make_ec().compute_hash());
    }

    #[test]
    fn hash_not_zero() {
        assert_ne!(make_ec().compute_hash(), [0u8; 32]);
    }

    #[test]
    fn hash_output_32_bytes() {
        assert_eq!(make_ec().compute_hash().len(), 32);
    }

    // ── HASH SENSITIVITY (setiap field harus mengubah hash) ─────────────

    #[test]
    fn hash_differs_workload_id() {
        let ec2 = ExecutionCommitment::new(
            WorkloadId::new([0xFF; 32]),
            [0x02; 32], [0x03; 32], [0x04; 32], [0x05; 32], [0x06; 32],
        );
        assert_ne!(make_ec().compute_hash(), ec2.compute_hash());
    }

    #[test]
    fn hash_differs_input_hash() {
        let ec2 = ExecutionCommitment::new(
            WorkloadId::new([0x01; 32]),
            [0xFF; 32], [0x03; 32], [0x04; 32], [0x05; 32], [0x06; 32],
        );
        assert_ne!(make_ec().compute_hash(), ec2.compute_hash());
    }

    #[test]
    fn hash_differs_output_hash() {
        let ec2 = ExecutionCommitment::new(
            WorkloadId::new([0x01; 32]),
            [0x02; 32], [0xFF; 32], [0x04; 32], [0x05; 32], [0x06; 32],
        );
        assert_ne!(make_ec().compute_hash(), ec2.compute_hash());
    }

    #[test]
    fn hash_differs_state_root_before() {
        let ec2 = ExecutionCommitment::new(
            WorkloadId::new([0x01; 32]),
            [0x02; 32], [0x03; 32], [0xFF; 32], [0x05; 32], [0x06; 32],
        );
        assert_ne!(make_ec().compute_hash(), ec2.compute_hash());
    }

    #[test]
    fn hash_differs_state_root_after() {
        let ec2 = ExecutionCommitment::new(
            WorkloadId::new([0x01; 32]),
            [0x02; 32], [0x03; 32], [0x04; 32], [0xFF; 32], [0x06; 32],
        );
        assert_ne!(make_ec().compute_hash(), ec2.compute_hash());
    }

    #[test]
    fn hash_differs_trace_merkle_root() {
        let ec2 = ExecutionCommitment::new(
            WorkloadId::new([0x01; 32]),
            [0x02; 32], [0x03; 32], [0x04; 32], [0x05; 32], [0xFF; 32],
        );
        assert_ne!(make_ec().compute_hash(), ec2.compute_hash());
    }

    // ── TRY_FROM_FIELDS (proto → native) ────────────────────────────────

    #[test]
    fn try_from_fields_valid() {
        let result = ExecutionCommitment::try_from_fields(
            &[0x01; 32], &[0x02; 32], &[0x03; 32],
            &[0x04; 32], &[0x05; 32], &[0x06; 32],
        );
        assert!(result.is_ok());
        if let Ok(ec) = result {
            assert_eq!(ec, make_ec());
        }
    }

    #[test]
    fn try_from_fields_invalid_workload_id() {
        let result = ExecutionCommitment::try_from_fields(
            &[0x01; 16], &[0x02; 32], &[0x03; 32],
            &[0x04; 32], &[0x05; 32], &[0x06; 32],
        );
        assert!(matches!(
            result,
            Err(ExecutionCommitmentError::InvalidLength { field: "workload_id", found: 16 })
        ));
    }

    #[test]
    fn try_from_fields_invalid_input_hash() {
        let result = ExecutionCommitment::try_from_fields(
            &[0x01; 32], &[0x02; 10], &[0x03; 32],
            &[0x04; 32], &[0x05; 32], &[0x06; 32],
        );
        assert!(matches!(
            result,
            Err(ExecutionCommitmentError::InvalidLength { field: "input_hash", found: 10 })
        ));
    }

    #[test]
    fn try_from_fields_invalid_output_hash() {
        let result = ExecutionCommitment::try_from_fields(
            &[0x01; 32], &[0x02; 32], &[],
            &[0x04; 32], &[0x05; 32], &[0x06; 32],
        );
        assert!(matches!(
            result,
            Err(ExecutionCommitmentError::InvalidLength { field: "output_hash", found: 0 })
        ));
    }

    #[test]
    fn try_from_fields_invalid_state_root_before() {
        let result = ExecutionCommitment::try_from_fields(
            &[0x01; 32], &[0x02; 32], &[0x03; 32],
            &[0x04; 64], &[0x05; 32], &[0x06; 32],
        );
        assert!(matches!(
            result,
            Err(ExecutionCommitmentError::InvalidLength { field: "state_root_before", found: 64 })
        ));
    }

    #[test]
    fn try_from_fields_invalid_state_root_after() {
        let result = ExecutionCommitment::try_from_fields(
            &[0x01; 32], &[0x02; 32], &[0x03; 32],
            &[0x04; 32], &[0x05; 5], &[0x06; 32],
        );
        assert!(matches!(
            result,
            Err(ExecutionCommitmentError::InvalidLength { field: "state_root_after", found: 5 })
        ));
    }

    #[test]
    fn try_from_fields_invalid_trace_merkle_root() {
        let result = ExecutionCommitment::try_from_fields(
            &[0x01; 32], &[0x02; 32], &[0x03; 32],
            &[0x04; 32], &[0x05; 32], &[0x06; 48],
        );
        assert!(matches!(
            result,
            Err(ExecutionCommitmentError::InvalidLength {
                field: "execution_trace_merkle_root", found: 48
            })
        ));
    }

    #[test]
    fn try_from_fields_first_invalid_reported() {
        let result = ExecutionCommitment::try_from_fields(
            &[0x01; 10], &[0x02; 32], &[0x03; 5],
            &[0x04; 32], &[0x05; 32], &[0x06; 32],
        );
        assert!(matches!(
            result,
            Err(ExecutionCommitmentError::InvalidLength { field: "workload_id", .. })
        ));
    }

    // ── TO_FIELDS (native → proto, roundtrip) ───────────────────────────

    #[test]
    fn to_fields_roundtrip() {
        let ec = make_ec();
        let (wid, ih, oh, srb, sra, etm) = ec.to_fields();
        let result = ExecutionCommitment::try_from_fields(&wid, &ih, &oh, &srb, &sra, &etm);
        assert!(result.is_ok());
        if let Ok(restored) = result {
            assert_eq!(ec, restored);
        }
    }

    #[test]
    fn to_fields_preserves_hash() {
        let ec = make_ec();
        let hash_before = ec.compute_hash();
        let (wid, ih, oh, srb, sra, etm) = ec.to_fields();
        if let Ok(restored) = ExecutionCommitment::try_from_fields(
            &wid, &ih, &oh, &srb, &sra, &etm,
        ) {
            assert_eq!(hash_before, restored.compute_hash());
        }
    }

    #[test]
    fn to_fields_vec_lengths_all_32() {
        let (wid, ih, oh, srb, sra, etm) = make_ec().to_fields();
        assert_eq!(wid.len(), 32);
        assert_eq!(ih.len(), 32);
        assert_eq!(oh.len(), 32);
        assert_eq!(srb.len(), 32);
        assert_eq!(sra.len(), 32);
        assert_eq!(etm.len(), 32);
    }

    // ── ERROR TYPE ──────────────────────────────────────────────────────

    #[test]
    fn error_display_contains_field_and_lengths() {
        let err = ExecutionCommitmentError::InvalidLength {
            field: "input_hash",
            found: 10,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("input_hash"));
        assert!(msg.contains("32"));
        assert!(msg.contains("10"));
    }

    #[test]
    fn error_implements_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(
            ExecutionCommitmentError::InvalidLength { field: "test", found: 0 },
        );
        assert!(!err.to_string().is_empty());
    }

    // ── EQ / HASH / DEBUG TRAITS ────────────────────────────────────────

    #[test]
    fn eq_reflexive() {
        let ec = make_ec();
        assert_eq!(ec, ec);
    }

    #[test]
    fn ne_different_field() {
        let ec2 = ExecutionCommitment::new(
            WorkloadId::new([0xFF; 32]),
            [0x02; 32], [0x03; 32], [0x04; 32], [0x05; 32], [0x06; 32],
        );
        assert_ne!(make_ec(), ec2);
    }

    #[test]
    fn hash_trait_consistent_with_eq() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let ec1 = make_ec();
        let ec2 = make_ec();
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        ec1.hash(&mut h1);
        ec2.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn debug_format_not_empty() {
        let dbg = format!("{:?}", make_ec());
        assert!(!dbg.is_empty());
        assert!(dbg.contains("ExecutionCommitment"));
    }
}