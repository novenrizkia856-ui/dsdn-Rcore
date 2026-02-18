//! # Execution Commitment Protocol Message (14C.A — P.1)
//!
//! Module ini mendefinisikan `ExecutionCommitmentProto`, proto message yang
//! merepresentasikan execution commitment untuk basis fraud proof dalam
//! sistem DSDN.
//!
//! ## Tujuan
//!
//! `ExecutionCommitmentProto` merekam state transition yang terjadi saat
//! sebuah workload dieksekusi oleh compute node. Data ini memungkinkan
//! verifier untuk menantang (challenge) hasil eksekusi jika dicurigai
//! ada kecurangan, dengan membandingkan merkle root dari execution trace.
//!
//! ## Hash Order (FIXED — TIDAK BOLEH BERUBAH)
//!
//! `compute_hash()` menghasilkan SHA3-256 hash dengan urutan konkatenasi:
//!
//! 1. `workload_id` (32 bytes)
//! 2. `input_hash` (32 bytes)
//! 3. `output_hash` (32 bytes)
//! 4. `state_root_before` (32 bytes)
//! 5. `state_root_after` (32 bytes)
//! 6. `execution_trace_merkle_root` (32 bytes)
//!
//! Total: 192 bytes sebelum hashing. Tidak ada separator.
//! Urutan ini adalah consensus-critical dan perubahan memerlukan hard-fork.
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

// ════════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════════

/// Expected size for all hash fields in `ExecutionCommitmentProto`.
/// Semua field harus tepat 32 bytes.
pub const EXECUTION_FIELD_SIZE: usize = 32;

/// Total byte count sebelum hashing (6 fields × 32 bytes).
const HASH_INPUT_SIZE: usize = EXECUTION_FIELD_SIZE * 6;

// ════════════════════════════════════════════════════════════════════════════════
// ERROR TYPE
// ════════════════════════════════════════════════════════════════════════════════

/// Error type untuk validasi dan hashing `ExecutionCommitmentProto`.
///
/// Setiap varian menjelaskan secara eksplisit field mana yang gagal
/// dan apa yang diharapkan vs ditemukan. Tidak ada string error generik.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionCommitmentError {
    /// Sebuah field memiliki panjang yang tidak sesuai.
    ///
    /// - `field`: nama field yang gagal validasi.
    /// - `expected`: panjang yang diharapkan (selalu 32).
    /// - `found`: panjang aktual yang ditemukan.
    InvalidLength {
        field: &'static str,
        expected: usize,
        found: usize,
    },

    /// Hashing gagal (seharusnya tidak terjadi dengan input valid,
    /// tapi disediakan untuk forward compatibility).
    HashingFailed,
}

impl fmt::Display for ExecutionCommitmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecutionCommitmentError::InvalidLength {
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
            ExecutionCommitmentError::HashingFailed => {
                write!(f, "hashing failed")
            }
        }
    }
}

impl std::error::Error for ExecutionCommitmentError {}

// ════════════════════════════════════════════════════════════════════════════════
// EXECUTION COMMITMENT PROTO
// ════════════════════════════════════════════════════════════════════════════════

/// Proto message untuk Execution Commitment.
///
/// `ExecutionCommitmentProto` adalah representasi serializable dari
/// execution commitment yang digunakan sebagai basis fraud proof
/// dalam sistem reward compute DSDN.
///
/// ## Fraud Proof Basis
///
/// Struct ini merekam snapshot state sebelum dan sesudah eksekusi workload,
/// beserta merkle root dari execution trace. Jika ada pihak yang menantang
/// hasil eksekusi, mereka dapat membuktikan fraud dengan menunjukkan bahwa
/// `execution_trace_merkle_root` tidak konsisten dengan `state_root_after`
/// yang diklaim.
///
/// ## Field Invariants
///
/// Semua field HARUS tepat 32 bytes. Validasi dilakukan oleh `validate()`.
///
/// ## Hash Computation
///
/// `compute_hash()` menghasilkan SHA3-256 dari konkatenasi semua field
/// dengan urutan FIXED (lihat module-level documentation).
/// Perubahan urutan hash = breaking change = hard-fork.
///
/// ## Field Sizes
///
/// | Field | Expected Size |
/// |-------|---------------|
/// | `workload_id` | 32 bytes |
/// | `input_hash` | 32 bytes |
/// | `output_hash` | 32 bytes |
/// | `state_root_before` | 32 bytes |
/// | `state_root_after` | 32 bytes |
/// | `execution_trace_merkle_root` | 32 bytes |
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionCommitmentProto {
    /// Identifier unik workload yang dieksekusi (MUST be 32 bytes).
    ///
    /// Sama dengan `workload_id` pada `ReceiptDataProto` dan `ReceiptV1Proto`.
    pub workload_id: Vec<u8>,

    /// Hash dari input data yang diberikan ke workload (MUST be 32 bytes).
    ///
    /// Dihitung sebelum eksekusi dimulai. Digunakan untuk memverifikasi
    /// bahwa input yang diklaim sesuai dengan input aktual.
    pub input_hash: Vec<u8>,

    /// Hash dari output data yang dihasilkan workload (MUST be 32 bytes).
    ///
    /// Dihitung setelah eksekusi selesai. Challenger dapat membandingkan
    /// output_hash ini dengan hasil re-execution mereka.
    pub output_hash: Vec<u8>,

    /// State root sebelum eksekusi dimulai (MUST be 32 bytes).
    ///
    /// Merkle root dari seluruh state yang relevan sebelum workload
    /// mengubah state apapun. Diperlukan untuk reproduce eksekusi.
    pub state_root_before: Vec<u8>,

    /// State root setelah eksekusi selesai (MUST be 32 bytes).
    ///
    /// Merkle root dari seluruh state setelah workload selesai.
    /// Perbedaan antara `state_root_before` dan `state_root_after`
    /// merepresentasikan efek eksekusi.
    pub state_root_after: Vec<u8>,

    /// Merkle root dari execution trace (MUST be 32 bytes).
    ///
    /// Execution trace adalah urutan langkah-langkah eksekusi yang
    /// direkam selama workload berjalan. Merkle root memungkinkan
    /// fraud proof yang efisien: challenger hanya perlu menunjukkan
    /// satu langkah yang salah, bukan seluruh trace.
    ///
    /// Ini adalah field kunci untuk fraud proof mechanism.
    pub execution_trace_merkle_root: Vec<u8>,
}

impl ExecutionCommitmentProto {
    /// Validates all field lengths.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if all fields are exactly 32 bytes.
    /// - `Err(ExecutionCommitmentError::InvalidLength)` if any field
    ///   does not have the expected length.
    ///
    /// # Validation Rules
    ///
    /// - `workload_id.len() == 32`
    /// - `input_hash.len() == 32`
    /// - `output_hash.len() == 32`
    /// - `state_root_before.len() == 32`
    /// - `state_root_after.len() == 32`
    /// - `execution_trace_merkle_root.len() == 32`
    ///
    /// Semua field dicek secara eksplisit. Tidak ada short-circuit
    /// selain early return pada field pertama yang gagal.
    pub fn validate(&self) -> Result<(), ExecutionCommitmentError> {
        validate_field_length(&self.workload_id, "workload_id")?;
        validate_field_length(&self.input_hash, "input_hash")?;
        validate_field_length(&self.output_hash, "output_hash")?;
        validate_field_length(&self.state_root_before, "state_root_before")?;
        validate_field_length(&self.state_root_after, "state_root_after")?;
        validate_field_length(
            &self.execution_trace_merkle_root,
            "execution_trace_merkle_root",
        )?;
        Ok(())
    }

    /// Computes deterministic SHA3-256 hash of execution commitment.
    ///
    /// # Hash Order (FIXED — consensus-critical)
    ///
    /// Konkatenasi dalam urutan berikut, tanpa separator:
    ///
    /// 1. `workload_id` (32 bytes)
    /// 2. `input_hash` (32 bytes)
    /// 3. `output_hash` (32 bytes)
    /// 4. `state_root_before` (32 bytes)
    /// 5. `state_root_after` (32 bytes)
    /// 6. `execution_trace_merkle_root` (32 bytes)
    ///
    /// Total input: 192 bytes → SHA3-256 → 32 bytes output.
    ///
    /// # Returns
    ///
    /// - `Ok([u8; 32])` — deterministic hash.
    /// - `Err(ExecutionCommitmentError::InvalidLength)` — if `validate()` fails.
    ///
    /// # Guarantees
    ///
    /// - Deterministik: input yang sama selalu menghasilkan hash yang sama.
    /// - Urutan FIXED: perubahan urutan mengubah hash.
    /// - Tidak ada separator antar field.
    ///
    /// # CRITICAL
    ///
    /// Hash order ini HARUS IDENTIK dengan implementasi di:
    /// - `dsdn_common::ExecutionCommitment::compute_hash()`
    /// - `dsdn_common::receipt_hash::compute_execution_commitment_hash()`
    ///
    /// Perubahan urutan = breaking change = hard-fork.
    pub fn compute_hash(&self) -> Result<[u8; 32], ExecutionCommitmentError> {
        // Validate all fields sebelum hashing.
        self.validate()?;

        let mut hasher = Sha3_256::new();

        // Pre-allocate buffer for all fields (192 bytes).
        let mut buf = Vec::with_capacity(HASH_INPUT_SIZE);

        // 1. workload_id (32 bytes)
        buf.extend_from_slice(&self.workload_id);

        // 2. input_hash (32 bytes)
        buf.extend_from_slice(&self.input_hash);

        // 3. output_hash (32 bytes)
        buf.extend_from_slice(&self.output_hash);

        // 4. state_root_before (32 bytes)
        buf.extend_from_slice(&self.state_root_before);

        // 5. state_root_after (32 bytes)
        buf.extend_from_slice(&self.state_root_after);

        // 6. execution_trace_merkle_root (32 bytes)
        buf.extend_from_slice(&self.execution_trace_merkle_root);

        // Hash the concatenated buffer.
        hasher.update(&buf);
        let result = hasher.finalize();

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        Ok(hash)
    }

    /// Encode ke bytes via bincode (little-endian, deterministic).
    ///
    /// # Returns
    ///
    /// - `Ok(Vec<u8>)` — encoded bytes.
    /// - `Err(ExecutionCommitmentError::HashingFailed)` — if serialization fails.
    pub fn encode(&self) -> Result<Vec<u8>, ExecutionCommitmentError> {
        bincode::serialize(self).map_err(|_| ExecutionCommitmentError::HashingFailed)
    }

    /// Decode dari bytes via bincode.
    ///
    /// # Returns
    ///
    /// - `Ok(Self)` — decoded proto.
    /// - `Err(ExecutionCommitmentError::HashingFailed)` — if deserialization fails.
    pub fn decode(data: &[u8]) -> Result<Self, ExecutionCommitmentError> {
        bincode::deserialize(data).map_err(|_| ExecutionCommitmentError::HashingFailed)
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// INTERNAL HELPERS
// ════════════════════════════════════════════════════════════════════════════════

/// Validate bahwa sebuah field memiliki panjang tepat `EXECUTION_FIELD_SIZE` (32 bytes).
///
/// # Arguments
///
/// - `field_data` — data field yang akan divalidasi.
/// - `field_name` — nama field untuk pesan error.
///
/// # Returns
///
/// - `Ok(())` if length is exactly 32.
/// - `Err(ExecutionCommitmentError::InvalidLength)` otherwise.
fn validate_field_length(
    field_data: &[u8],
    field_name: &'static str,
) -> Result<(), ExecutionCommitmentError> {
    if field_data.len() != EXECUTION_FIELD_SIZE {
        return Err(ExecutionCommitmentError::InvalidLength {
            field: field_name,
            expected: EXECUTION_FIELD_SIZE,
            found: field_data.len(),
        });
    }
    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// STANDALONE FUNCTIONS (mengikuti pattern existing di crate)
// ════════════════════════════════════════════════════════════════════════════════

/// Encode `ExecutionCommitmentProto` ke bytes.
///
/// Mengikuti pattern `encode_committee()`, `encode_receipt()` di crate ini.
#[must_use]
pub fn encode_execution_commitment(commitment: &ExecutionCommitmentProto) -> Vec<u8> {
    bincode::serialize(commitment).unwrap_or_else(|_| Vec::new())
}

/// Decode bytes ke `ExecutionCommitmentProto`.
///
/// Mengikuti pattern `decode_committee()`, `decode_receipt()` di crate ini.
pub fn decode_execution_commitment(
    bytes: &[u8],
) -> Result<ExecutionCommitmentProto, ExecutionCommitmentError> {
    let proto: ExecutionCommitmentProto =
        bincode::deserialize(bytes).map_err(|_| ExecutionCommitmentError::HashingFailed)?;

    // Validate setelah decode.
    proto.validate()?;

    Ok(proto)
}

/// Compute SHA3-256 hash dari `ExecutionCommitmentProto`.
///
/// Convenience wrapper di atas `ExecutionCommitmentProto::compute_hash()`.
///
/// # Returns
///
/// 32-byte SHA3-256 hash, atau error jika validasi gagal.
pub fn compute_execution_commitment_hash(
    commitment: &ExecutionCommitmentProto,
) -> Result<[u8; 32], ExecutionCommitmentError> {
    commitment.compute_hash()
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: buat valid ExecutionCommitmentProto untuk testing.
    fn make_valid_commitment() -> ExecutionCommitmentProto {
        ExecutionCommitmentProto {
            workload_id: vec![0x01; 32],
            input_hash: vec![0x02; 32],
            output_hash: vec![0x03; 32],
            state_root_before: vec![0x04; 32],
            state_root_after: vec![0x05; 32],
            execution_trace_merkle_root: vec![0x06; 32],
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // VALIDATE TESTS
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_validate_valid_commitment() {
        let commitment = make_valid_commitment();
        assert!(commitment.validate().is_ok());
    }

    #[test]
    fn test_validate_invalid_workload_id_too_short() {
        let mut commitment = make_valid_commitment();
        commitment.workload_id = vec![0x01; 16];
        let err = commitment.validate().unwrap_err();
        assert_eq!(
            err,
            ExecutionCommitmentError::InvalidLength {
                field: "workload_id",
                expected: 32,
                found: 16,
            }
        );
    }

    #[test]
    fn test_validate_invalid_workload_id_too_long() {
        let mut commitment = make_valid_commitment();
        commitment.workload_id = vec![0x01; 64];
        let err = commitment.validate().unwrap_err();
        assert_eq!(
            err,
            ExecutionCommitmentError::InvalidLength {
                field: "workload_id",
                expected: 32,
                found: 64,
            }
        );
    }

    #[test]
    fn test_validate_invalid_workload_id_empty() {
        let mut commitment = make_valid_commitment();
        commitment.workload_id = Vec::new();
        let err = commitment.validate().unwrap_err();
        assert_eq!(
            err,
            ExecutionCommitmentError::InvalidLength {
                field: "workload_id",
                expected: 32,
                found: 0,
            }
        );
    }

    #[test]
    fn test_validate_invalid_input_hash() {
        let mut commitment = make_valid_commitment();
        commitment.input_hash = vec![0x02; 31];
        let err = commitment.validate().unwrap_err();
        assert_eq!(
            err,
            ExecutionCommitmentError::InvalidLength {
                field: "input_hash",
                expected: 32,
                found: 31,
            }
        );
    }

    #[test]
    fn test_validate_invalid_output_hash() {
        let mut commitment = make_valid_commitment();
        commitment.output_hash = vec![0x03; 33];
        let err = commitment.validate().unwrap_err();
        assert_eq!(
            err,
            ExecutionCommitmentError::InvalidLength {
                field: "output_hash",
                expected: 32,
                found: 33,
            }
        );
    }

    #[test]
    fn test_validate_invalid_state_root_before() {
        let mut commitment = make_valid_commitment();
        commitment.state_root_before = vec![0x04; 1];
        let err = commitment.validate().unwrap_err();
        assert_eq!(
            err,
            ExecutionCommitmentError::InvalidLength {
                field: "state_root_before",
                expected: 32,
                found: 1,
            }
        );
    }

    #[test]
    fn test_validate_invalid_state_root_after() {
        let mut commitment = make_valid_commitment();
        commitment.state_root_after = vec![0x05; 0];
        let err = commitment.validate().unwrap_err();
        assert_eq!(
            err,
            ExecutionCommitmentError::InvalidLength {
                field: "state_root_after",
                expected: 32,
                found: 0,
            }
        );
    }

    #[test]
    fn test_validate_invalid_execution_trace_merkle_root() {
        let mut commitment = make_valid_commitment();
        commitment.execution_trace_merkle_root = vec![0x06; 48];
        let err = commitment.validate().unwrap_err();
        assert_eq!(
            err,
            ExecutionCommitmentError::InvalidLength {
                field: "execution_trace_merkle_root",
                expected: 32,
                found: 48,
            }
        );
    }

    #[test]
    fn test_validate_first_invalid_field_reported() {
        // Jika multiple fields invalid, field pertama (workload_id) yang dilaporkan.
        let commitment = ExecutionCommitmentProto {
            workload_id: vec![0x01; 10],
            input_hash: vec![0x02; 10],
            output_hash: vec![0x03; 10],
            state_root_before: vec![0x04; 10],
            state_root_after: vec![0x05; 10],
            execution_trace_merkle_root: vec![0x06; 10],
        };
        let err = commitment.validate().unwrap_err();
        match err {
            ExecutionCommitmentError::InvalidLength { field, .. } => {
                assert_eq!(field, "workload_id");
            }
            _ => panic!("expected InvalidLength"),
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // COMPUTE HASH TESTS
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_compute_hash_deterministic() {
        let commitment = make_valid_commitment();
        let hash1 = commitment.compute_hash().expect("hash1");
        let hash2 = commitment.compute_hash().expect("hash2");
        assert_eq!(hash1, hash2, "hash must be deterministic");
    }

    #[test]
    fn test_compute_hash_deterministic_across_clones() {
        let commitment1 = make_valid_commitment();
        let commitment2 = commitment1.clone();
        let hash1 = commitment1.compute_hash().expect("hash1");
        let hash2 = commitment2.compute_hash().expect("hash2");
        assert_eq!(hash1, hash2, "cloned commitment must produce same hash");
    }

    #[test]
    fn test_compute_hash_different_workload_id() {
        let mut c1 = make_valid_commitment();
        let mut c2 = make_valid_commitment();
        c2.workload_id = vec![0xFF; 32];
        let h1 = c1.compute_hash().expect("h1");
        let h2 = c2.compute_hash().expect("h2");
        assert_ne!(h1, h2, "different workload_id must produce different hash");
    }

    #[test]
    fn test_compute_hash_different_input_hash() {
        let c1 = make_valid_commitment();
        let mut c2 = make_valid_commitment();
        c2.input_hash = vec![0xFF; 32];
        let h1 = c1.compute_hash().expect("h1");
        let h2 = c2.compute_hash().expect("h2");
        assert_ne!(h1, h2, "different input_hash must produce different hash");
    }

    #[test]
    fn test_compute_hash_different_output_hash() {
        let c1 = make_valid_commitment();
        let mut c2 = make_valid_commitment();
        c2.output_hash = vec![0xFF; 32];
        assert_ne!(
            c1.compute_hash().expect("h1"),
            c2.compute_hash().expect("h2"),
        );
    }

    #[test]
    fn test_compute_hash_different_state_root_before() {
        let c1 = make_valid_commitment();
        let mut c2 = make_valid_commitment();
        c2.state_root_before = vec![0xFF; 32];
        assert_ne!(
            c1.compute_hash().expect("h1"),
            c2.compute_hash().expect("h2"),
        );
    }

    #[test]
    fn test_compute_hash_different_state_root_after() {
        let c1 = make_valid_commitment();
        let mut c2 = make_valid_commitment();
        c2.state_root_after = vec![0xFF; 32];
        assert_ne!(
            c1.compute_hash().expect("h1"),
            c2.compute_hash().expect("h2"),
        );
    }

    #[test]
    fn test_compute_hash_different_execution_trace_merkle_root() {
        let c1 = make_valid_commitment();
        let mut c2 = make_valid_commitment();
        c2.execution_trace_merkle_root = vec![0xFF; 32];
        assert_ne!(
            c1.compute_hash().expect("h1"),
            c2.compute_hash().expect("h2"),
        );
    }

    #[test]
    fn test_compute_hash_rejects_invalid() {
        let mut commitment = make_valid_commitment();
        commitment.workload_id = vec![0x01; 16]; // invalid
        let result = commitment.compute_hash();
        assert!(result.is_err());
    }

    #[test]
    fn test_compute_hash_output_is_32_bytes() {
        let commitment = make_valid_commitment();
        let hash = commitment.compute_hash().expect("hash");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_compute_hash_not_all_zeros() {
        let commitment = make_valid_commitment();
        let hash = commitment.compute_hash().expect("hash");
        assert_ne!(hash, [0u8; 32], "hash should not be all zeros");
    }

    #[test]
    fn test_compute_hash_field_order_matters() {
        // Swap input_hash and output_hash — hash MUST differ.
        let c1 = make_valid_commitment();
        let c2 = ExecutionCommitmentProto {
            workload_id: vec![0x01; 32],
            input_hash: vec![0x03; 32],  // was 0x02, now swapped with output
            output_hash: vec![0x02; 32], // was 0x03, now swapped with input
            state_root_before: vec![0x04; 32],
            state_root_after: vec![0x05; 32],
            execution_trace_merkle_root: vec![0x06; 32],
        };
        assert_ne!(
            c1.compute_hash().expect("h1"),
            c2.compute_hash().expect("h2"),
            "swapping field values must produce different hash"
        );
    }

    // ────────────────────────────────────────────────────────────────────────
    // ENCODE/DECODE TESTS
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_encode_decode_roundtrip() {
        let commitment = make_valid_commitment();
        let bytes = encode_execution_commitment(&commitment);
        let decoded = decode_execution_commitment(&bytes).expect("decode");
        assert_eq!(commitment, decoded);
    }

    #[test]
    fn test_encode_decode_method_roundtrip() {
        let commitment = make_valid_commitment();
        let bytes = commitment.encode().expect("encode");
        let decoded = ExecutionCommitmentProto::decode(&bytes).expect("decode");
        assert_eq!(commitment, decoded);
    }

    #[test]
    fn test_decode_invalid_bytes() {
        let result = decode_execution_commitment(&[0xFF, 0xFF, 0xFF]);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_empty_bytes() {
        let result = decode_execution_commitment(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_decode_preserves_hash() {
        let commitment = make_valid_commitment();
        let hash_before = commitment.compute_hash().expect("hash_before");
        let bytes = encode_execution_commitment(&commitment);
        let decoded = decode_execution_commitment(&bytes).expect("decode");
        let hash_after = decoded.compute_hash().expect("hash_after");
        assert_eq!(hash_before, hash_after, "hash must survive encode/decode roundtrip");
    }

    // ────────────────────────────────────────────────────────────────────────
    // STANDALONE FUNCTION TESTS
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_compute_execution_commitment_hash_fn() {
        let commitment = make_valid_commitment();
        let hash_method = commitment.compute_hash().expect("method");
        let hash_fn = compute_execution_commitment_hash(&commitment).expect("fn");
        assert_eq!(hash_method, hash_fn, "standalone fn must match method");
    }

    // ────────────────────────────────────────────────────────────────────────
    // ERROR DISPLAY TESTS
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_error_display_invalid_length() {
        let err = ExecutionCommitmentError::InvalidLength {
            field: "workload_id",
            expected: 32,
            found: 16,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("workload_id"));
        assert!(msg.contains("32"));
        assert!(msg.contains("16"));
    }

    #[test]
    fn test_error_display_hashing_failed() {
        let err = ExecutionCommitmentError::HashingFailed;
        let msg = format!("{}", err);
        assert!(msg.contains("hashing failed"));
    }

    // ────────────────────────────────────────────────────────────────────────
    // EDGE CASE TESTS
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_all_zeros_valid() {
        let commitment = ExecutionCommitmentProto {
            workload_id: vec![0x00; 32],
            input_hash: vec![0x00; 32],
            output_hash: vec![0x00; 32],
            state_root_before: vec![0x00; 32],
            state_root_after: vec![0x00; 32],
            execution_trace_merkle_root: vec![0x00; 32],
        };
        assert!(commitment.validate().is_ok());
        assert!(commitment.compute_hash().is_ok());
    }

    #[test]
    fn test_all_ff_valid() {
        let commitment = ExecutionCommitmentProto {
            workload_id: vec![0xFF; 32],
            input_hash: vec![0xFF; 32],
            output_hash: vec![0xFF; 32],
            state_root_before: vec![0xFF; 32],
            state_root_after: vec![0xFF; 32],
            execution_trace_merkle_root: vec![0xFF; 32],
        };
        assert!(commitment.validate().is_ok());
        let hash = commitment.compute_hash().expect("hash");
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_hash_determinism_1000_runs() {
        let commitment = make_valid_commitment();
        let reference_hash = commitment.compute_hash().expect("reference");
        for _ in 0..1000 {
            let hash = commitment.compute_hash().expect("hash");
            assert_eq!(hash, reference_hash, "hash must be deterministic across runs");
        }
    }

    #[test]
    fn test_constant_execution_field_size() {
        assert_eq!(EXECUTION_FIELD_SIZE, 32);
    }
}