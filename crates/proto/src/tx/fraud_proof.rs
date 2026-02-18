//! # Fraud Proof Challenge Transaction Message (14C.A — P.4)
//!
//! Module ini mendefinisikan `FraudProofChallengeProto`, transaction message yang
//! digunakan challenger untuk menantang compute receipt dalam challenge window.
//!
//! ## Challenge Flow
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Fraud Proof Challenge Flow                    │
//! └─────────────────────────────────────────────────────────────────┘
//!
//!   Challenger                Chain                     Node
//!       │                      │                          │
//!       │  1. Observe compute  │                          │
//!       │     receipt on chain │                          │
//!       │                      │                          │
//!       │  2. Re-execute       │                          │
//!       │     workload         │                          │
//!       │                      │                          │
//!       │  3. Detect mismatch  │                          │
//!       │     at step N        │                          │
//!       │                      │                          │
//!       │──4. Submit challenge─▶│                          │
//!       │   (within 1hr        │                          │
//!       │    window)           │                          │
//!       │                      │──5. Verify:              │
//!       │                      │   - challenger sig       │
//!       │                      │   - trace segment        │
//!       │                      │   - output mismatch      │
//!       │                      │                          │
//!       │                      │   6a. Fraud proven:      │
//!       │                      │   → receipt cancelled    │
//!       │                      │   → node slashed ───────▶│
//!       │                      │                          │
//!       │                      │   6b. Fraud not proven:  │
//!       │◀── challenger slash──│                          │
//!       │                      │                          │
//! ```
//!
//! ## Challenge Window
//!
//! Fraud proof challenge HANYA boleh dikirim dalam window 1 jam
//! setelah compute receipt disubmit ke chain. Challenge di luar
//! window HARUS ditolak oleh chain.
//!
//! ## Chain Verification
//!
//! Saat menerima challenge, chain HARUS memverifikasi:
//!
//! 1. **Challenger signature valid** — Ed25519 signature dari challenger.
//! 2. **Trace segment valid** — merkle proof segment yang menunjukkan
//!    langkah eksekusi yang disengketakan.
//! 3. **Output mismatch** — `expected_output_hash` dari challenger
//!    tidak cocok dengan output dalam receipt's execution commitment.
//!
//! ## Consequences
//!
//! - **Fraud terbukti**: Receipt dibatalkan, reward tidak didistribusikan,
//!   node bisa di-slash sesuai slashing policy.
//! - **Fraud tidak terbukti**: Challenger bisa di-slash karena challenge
//!   yang tidak valid (frivolous challenge deterrence).
//!
//! ## Hash Order (FIXED — consensus-critical)
//!
//! `compute_challenge_hash()` uses SHA3-256 with the following concatenation order:
//!
//! 1. `receipt_hash` (32 bytes)
//! 2. `challenger_address` (20 bytes)
//! 3. `challenger_signature` (64 bytes)
//! 4. `execution_trace_segment` (variable length)
//! 5. `disputed_step_index` (8 bytes, big-endian)
//! 6. `expected_output_hash` (32 bytes)
//! 7. `timestamp` (8 bytes, big-endian)
//!
//! Tidak ada separator. Perubahan urutan = breaking change = hard-fork.
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

/// Expected size for receipt_hash field.
pub const RECEIPT_HASH_SIZE: usize = 32;

/// Expected size for challenger_address field.
pub const CHALLENGER_ADDRESS_SIZE: usize = 20;

/// Expected size for challenger_signature field (Ed25519).
pub const CHALLENGER_SIGNATURE_SIZE: usize = 64;

/// Expected size for expected_output_hash field.
pub const EXPECTED_OUTPUT_HASH_SIZE: usize = 32;

// ════════════════════════════════════════════════════════════════════════════════
// ERROR TYPE
// ════════════════════════════════════════════════════════════════════════════════

/// Error type untuk validasi dan hashing `FraudProofChallengeProto`.
///
/// Setiap varian menjelaskan secara eksplisit kondisi yang gagal.
/// Tidak ada string error generik.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FraudProofError {
    /// Sebuah field memiliki panjang yang tidak sesuai.
    InvalidLength {
        field: &'static str,
        expected: usize,
        found: usize,
    },

    /// Execution trace segment kosong.
    EmptyTraceSegment,

    /// Hashing gagal.
    HashingFailed,
}

impl fmt::Display for FraudProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FraudProofError::InvalidLength {
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
            FraudProofError::EmptyTraceSegment => {
                write!(f, "execution_trace_segment must not be empty")
            }
            FraudProofError::HashingFailed => {
                write!(f, "hashing failed")
            }
        }
    }
}

impl std::error::Error for FraudProofError {}

// ════════════════════════════════════════════════════════════════════════════════
// FRAUD PROOF CHALLENGE PROTO
// ════════════════════════════════════════════════════════════════════════════════

/// Proto message untuk Fraud Proof Challenge transaction.
///
/// `FraudProofChallengeProto` digunakan oleh challenger untuk menantang
/// compute receipt yang dicurigai mengandung hasil eksekusi yang tidak benar.
///
/// ## Invariants
///
/// - `receipt_hash` MUST be 32 bytes — hash dari receipt yang ditantang.
/// - `challenger_address` MUST be 20 bytes — address challenger.
/// - `challenger_signature` MUST be 64 bytes — Ed25519 signature.
/// - `execution_trace_segment` MUST NOT be empty — merkle proof segment.
/// - `expected_output_hash` MUST be 32 bytes — hash output yang diharapkan challenger.
/// - `disputed_step_index` — index langkah eksekusi yang disengketakan (0 valid).
/// - `timestamp` — waktu challenge dibuat (0 allowed for test environment).
///
/// ## Challenge Window
///
/// Challenge HANYA valid dalam 1 jam setelah receipt disubmit.
/// Enforcement dilakukan di chain layer, bukan di proto layer.
///
/// ## Field Sizes
///
/// | Field | Expected Size |
/// |-------|---------------|
/// | `receipt_hash` | 32 bytes |
/// | `challenger_address` | 20 bytes |
/// | `challenger_signature` | 64 bytes (Ed25519) |
/// | `execution_trace_segment` | Variable (>0) |
/// | `disputed_step_index` | u64 |
/// | `expected_output_hash` | 32 bytes |
/// | `timestamp` | u64 |
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FraudProofChallengeProto {
    /// Hash dari receipt yang ditantang (MUST be 32 bytes).
    ///
    /// Ini adalah `compute_receipt_hash()` dari `ReceiptV1Proto` target.
    pub receipt_hash: Vec<u8>,

    /// Address challenger (MUST be 20 bytes).
    ///
    /// Challenger harus memiliki stake yang cukup untuk submit challenge.
    /// Jika challenge gagal, stake challenger bisa di-slash.
    pub challenger_address: Vec<u8>,

    /// Ed25519 signature dari challenger (MUST be 64 bytes).
    ///
    /// Membuktikan bahwa challenger yang sah mengirim challenge ini.
    pub challenger_signature: Vec<u8>,

    /// Merkle proof segment dari execution trace (MUST NOT be empty).
    ///
    /// Berisi bukti merkle yang menunjukkan langkah eksekusi mana yang
    /// menghasilkan output berbeda dari yang diklaim dalam receipt.
    /// Panjang variabel tergantung kedalaman merkle tree.
    pub execution_trace_segment: Vec<u8>,

    /// Index langkah eksekusi yang disengketakan.
    ///
    /// Menunjukkan pada step mana dalam execution trace challenger
    /// menemukan perbedaan. Nilai 0 valid (step pertama).
    pub disputed_step_index: u64,

    /// Hash output yang diharapkan challenger di step yang disengketakan (MUST be 32 bytes).
    ///
    /// Jika hash ini berbeda dari output dalam receipt's execution commitment
    /// DAN trace segment valid, maka fraud terbukti.
    pub expected_output_hash: Vec<u8>,

    /// Unix timestamp saat challenge dibuat.
    ///
    /// Nilai 0 diperbolehkan (test environment).
    /// Chain layer yang menentukan apakah timestamp masih dalam challenge window.
    pub timestamp: u64,
}

impl FraudProofChallengeProto {
    /// Validates all fields and invariants.
    ///
    /// # Validation Rules
    ///
    /// 1. `receipt_hash.len() == 32`
    /// 2. `challenger_address.len() == 20`
    /// 3. `challenger_signature.len() == 64`
    /// 4. `expected_output_hash.len() == 32`
    /// 5. `execution_trace_segment` MUST NOT be empty.
    /// 6. `disputed_step_index` — no restriction (0 valid).
    /// 7. `timestamp` — no restriction (0 valid).
    ///
    /// # Returns
    ///
    /// - `Ok(())` if all validations pass.
    /// - `Err(FraudProofError)` with specific variant for the first failure.
    pub fn validate(&self) -> Result<(), FraudProofError> {
        // 1. receipt_hash
        validate_field_length(&self.receipt_hash, "receipt_hash", RECEIPT_HASH_SIZE)?;

        // 2. challenger_address
        validate_field_length(
            &self.challenger_address,
            "challenger_address",
            CHALLENGER_ADDRESS_SIZE,
        )?;

        // 3. challenger_signature
        validate_field_length(
            &self.challenger_signature,
            "challenger_signature",
            CHALLENGER_SIGNATURE_SIZE,
        )?;

        // 4. expected_output_hash
        validate_field_length(
            &self.expected_output_hash,
            "expected_output_hash",
            EXPECTED_OUTPUT_HASH_SIZE,
        )?;

        // 5. execution_trace_segment must not be empty
        if self.execution_trace_segment.is_empty() {
            return Err(FraudProofError::EmptyTraceSegment);
        }

        // 6. disputed_step_index — no restriction
        // 7. timestamp — no restriction

        Ok(())
    }

    /// Computes deterministic SHA3-256 challenge hash.
    ///
    /// Hash ini digunakan untuk:
    /// - **Mempool deduplication**: mencegah challenge duplikat masuk mempool.
    /// - **Replay protection**: memastikan challenge yang sama tidak diproses ulang.
    /// - **Consensus determinism**: semua node menghasilkan hash yang sama
    ///   untuk challenge yang sama.
    ///
    /// # Hash Order (FIXED — consensus-critical)
    ///
    /// Konkatenasi dalam urutan berikut, tanpa separator:
    ///
    /// 1. `receipt_hash` (32 bytes)
    /// 2. `challenger_address` (20 bytes)
    /// 3. `challenger_signature` (64 bytes)
    /// 4. `execution_trace_segment` (variable length)
    /// 5. `disputed_step_index` (8 bytes, big-endian)
    /// 6. `expected_output_hash` (32 bytes)
    /// 7. `timestamp` (8 bytes, big-endian)
    ///
    /// # Returns
    ///
    /// - `Ok([u8; 32])` — deterministic hash.
    /// - `Err(FraudProofError)` — if `validate()` fails.
    ///
    /// # CRITICAL
    ///
    /// Perubahan urutan hash = breaking change = hard-fork.
    /// Hash order HARUS IDENTIK di semua implementasi (proto, common, chain).
    pub fn compute_challenge_hash(&self) -> Result<[u8; 32], FraudProofError> {
        // Validate all fields terlebih dahulu.
        self.validate()?;

        // Calculate buffer capacity:
        // 32 + 20 + 64 + variable + 8 + 32 + 8 = 164 + trace_len
        let buf_capacity = 164 + self.execution_trace_segment.len();
        let mut buf = Vec::with_capacity(buf_capacity);

        // 1. receipt_hash (32 bytes)
        buf.extend_from_slice(&self.receipt_hash);

        // 2. challenger_address (20 bytes)
        buf.extend_from_slice(&self.challenger_address);

        // 3. challenger_signature (64 bytes)
        buf.extend_from_slice(&self.challenger_signature);

        // 4. execution_trace_segment (variable length)
        buf.extend_from_slice(&self.execution_trace_segment);

        // 5. disputed_step_index (8 bytes, big-endian)
        buf.extend_from_slice(&self.disputed_step_index.to_be_bytes());

        // 6. expected_output_hash (32 bytes)
        buf.extend_from_slice(&self.expected_output_hash);

        // 7. timestamp (8 bytes, big-endian)
        buf.extend_from_slice(&self.timestamp.to_be_bytes());

        // Hash the concatenated buffer.
        let mut hasher = Sha3_256::new();
        hasher.update(&buf);
        let result = hasher.finalize();

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        Ok(hash)
    }

    /// Encode ke bytes via bincode (little-endian, deterministic).
    pub fn encode(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Decode dari bytes via bincode (tanpa validasi).
    ///
    /// Gunakan `decode_validated()` jika perlu decode + validate sekaligus.
    pub fn decode(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }

    /// Decode dari bytes via bincode, lalu validate.
    ///
    /// Validates setelah decode. Jika hasil decode tidak valid, error dikembalikan.
    pub fn decode_validated(bytes: &[u8]) -> Result<Self, FraudProofError> {
        let proto: Self =
            bincode::deserialize(bytes).map_err(|_| FraudProofError::HashingFailed)?;

        proto.validate()?;

        Ok(proto)
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// STANDALONE FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════════

/// Encode `FraudProofChallengeProto` ke bytes.
#[must_use]
pub fn encode_fraud_proof(challenge: &FraudProofChallengeProto) -> Vec<u8> {
    bincode::serialize(challenge).unwrap_or_else(|_| Vec::new())
}

/// Decode bytes ke `FraudProofChallengeProto`.
///
/// Validates setelah decode.
pub fn decode_fraud_proof(bytes: &[u8]) -> Result<FraudProofChallengeProto, FraudProofError> {
    let proto: FraudProofChallengeProto =
        bincode::deserialize(bytes).map_err(|_| FraudProofError::HashingFailed)?;

    proto.validate()?;

    Ok(proto)
}

/// Compute SHA3-256 challenge hash dari `FraudProofChallengeProto`.
pub fn compute_fraud_proof_hash(
    challenge: &FraudProofChallengeProto,
) -> Result<[u8; 32], FraudProofError> {
    challenge.compute_challenge_hash()
}

// ════════════════════════════════════════════════════════════════════════════════
// INTERNAL HELPERS
// ════════════════════════════════════════════════════════════════════════════════

/// Validate field length.
fn validate_field_length(
    field_data: &[u8],
    field_name: &'static str,
    expected: usize,
) -> Result<(), FraudProofError> {
    if field_data.len() != expected {
        return Err(FraudProofError::InvalidLength {
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

    /// Helper: build valid FraudProofChallengeProto.
    fn make_valid_challenge() -> FraudProofChallengeProto {
        FraudProofChallengeProto {
            receipt_hash: vec![0x01; 32],
            challenger_address: vec![0x02; 20],
            challenger_signature: vec![0x03; 64],
            execution_trace_segment: vec![0xAA; 128],
            disputed_step_index: 42,
            expected_output_hash: vec![0x04; 32],
            timestamp: 1_700_000_000,
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // VALIDATE
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_validate_valid() {
        assert!(make_valid_challenge().validate().is_ok());
    }

    #[test]
    fn test_validate_invalid_receipt_hash_too_short() {
        let mut c = make_valid_challenge();
        c.receipt_hash = vec![0x01; 16];
        let err = c.validate().unwrap_err();
        assert_eq!(
            err,
            FraudProofError::InvalidLength {
                field: "receipt_hash",
                expected: 32,
                found: 16,
            }
        );
    }

    #[test]
    fn test_validate_invalid_receipt_hash_too_long() {
        let mut c = make_valid_challenge();
        c.receipt_hash = vec![0x01; 64];
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_validate_invalid_receipt_hash_empty() {
        let mut c = make_valid_challenge();
        c.receipt_hash = Vec::new();
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_validate_invalid_challenger_address() {
        let mut c = make_valid_challenge();
        c.challenger_address = vec![0x02; 32];
        let err = c.validate().unwrap_err();
        assert_eq!(
            err,
            FraudProofError::InvalidLength {
                field: "challenger_address",
                expected: 20,
                found: 32,
            }
        );
    }

    #[test]
    fn test_validate_invalid_challenger_address_empty() {
        let mut c = make_valid_challenge();
        c.challenger_address = Vec::new();
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_validate_invalid_challenger_signature_too_short() {
        let mut c = make_valid_challenge();
        c.challenger_signature = vec![0x03; 32];
        let err = c.validate().unwrap_err();
        assert_eq!(
            err,
            FraudProofError::InvalidLength {
                field: "challenger_signature",
                expected: 64,
                found: 32,
            }
        );
    }

    #[test]
    fn test_validate_invalid_challenger_signature_too_long() {
        let mut c = make_valid_challenge();
        c.challenger_signature = vec![0x03; 128];
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_validate_invalid_expected_output_hash() {
        let mut c = make_valid_challenge();
        c.expected_output_hash = vec![0x04; 48];
        let err = c.validate().unwrap_err();
        assert_eq!(
            err,
            FraudProofError::InvalidLength {
                field: "expected_output_hash",
                expected: 32,
                found: 48,
            }
        );
    }

    #[test]
    fn test_validate_invalid_expected_output_hash_empty() {
        let mut c = make_valid_challenge();
        c.expected_output_hash = Vec::new();
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_validate_empty_trace_segment() {
        let mut c = make_valid_challenge();
        c.execution_trace_segment = Vec::new();
        let err = c.validate().unwrap_err();
        assert_eq!(err, FraudProofError::EmptyTraceSegment);
    }

    #[test]
    fn test_validate_trace_segment_single_byte() {
        let mut c = make_valid_challenge();
        c.execution_trace_segment = vec![0xFF];
        assert!(c.validate().is_ok());
    }

    #[test]
    fn test_validate_disputed_step_index_zero() {
        let mut c = make_valid_challenge();
        c.disputed_step_index = 0;
        assert!(c.validate().is_ok());
    }

    #[test]
    fn test_validate_disputed_step_index_max() {
        let mut c = make_valid_challenge();
        c.disputed_step_index = u64::MAX;
        assert!(c.validate().is_ok());
    }

    #[test]
    fn test_validate_timestamp_zero() {
        let mut c = make_valid_challenge();
        c.timestamp = 0;
        assert!(c.validate().is_ok());
    }

    #[test]
    fn test_validate_timestamp_max() {
        let mut c = make_valid_challenge();
        c.timestamp = u64::MAX;
        assert!(c.validate().is_ok());
    }

    #[test]
    fn test_validate_first_invalid_field_reported() {
        let c = FraudProofChallengeProto {
            receipt_hash: vec![0x01; 10],           // Invalid
            challenger_address: vec![0x02; 5],      // Also invalid
            challenger_signature: vec![0x03; 64],
            execution_trace_segment: vec![0xAA; 128],
            disputed_step_index: 0,
            expected_output_hash: vec![0x04; 32],
            timestamp: 0,
        };
        let err = c.validate().unwrap_err();
        match err {
            FraudProofError::InvalidLength { field, .. } => {
                assert_eq!(field, "receipt_hash");
            }
            _ => panic!("expected InvalidLength for receipt_hash"),
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // COMPUTE HASH
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_hash_deterministic() {
        let c = make_valid_challenge();
        let h1 = c.compute_challenge_hash().expect("h1");
        let h2 = c.compute_challenge_hash().expect("h2");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_deterministic_across_clones() {
        let c1 = make_valid_challenge();
        let c2 = c1.clone();
        assert_eq!(
            c1.compute_challenge_hash().expect("h1"),
            c2.compute_challenge_hash().expect("h2"),
        );
    }

    #[test]
    fn test_hash_different_receipt_hash() {
        let c1 = make_valid_challenge();
        let mut c2 = make_valid_challenge();
        c2.receipt_hash = vec![0xFF; 32];
        assert_ne!(
            c1.compute_challenge_hash().expect("h1"),
            c2.compute_challenge_hash().expect("h2"),
        );
    }

    #[test]
    fn test_hash_different_challenger_address() {
        let c1 = make_valid_challenge();
        let mut c2 = make_valid_challenge();
        c2.challenger_address = vec![0xFF; 20];
        assert_ne!(
            c1.compute_challenge_hash().expect("h1"),
            c2.compute_challenge_hash().expect("h2"),
        );
    }

    #[test]
    fn test_hash_different_challenger_signature() {
        let c1 = make_valid_challenge();
        let mut c2 = make_valid_challenge();
        c2.challenger_signature = vec![0xFF; 64];
        assert_ne!(
            c1.compute_challenge_hash().expect("h1"),
            c2.compute_challenge_hash().expect("h2"),
        );
    }

    #[test]
    fn test_hash_different_trace_segment() {
        let c1 = make_valid_challenge();
        let mut c2 = make_valid_challenge();
        c2.execution_trace_segment = vec![0xBB; 256];
        assert_ne!(
            c1.compute_challenge_hash().expect("h1"),
            c2.compute_challenge_hash().expect("h2"),
        );
    }

    #[test]
    fn test_hash_different_disputed_step_index() {
        let c1 = make_valid_challenge();
        let mut c2 = make_valid_challenge();
        c2.disputed_step_index = 999;
        assert_ne!(
            c1.compute_challenge_hash().expect("h1"),
            c2.compute_challenge_hash().expect("h2"),
        );
    }

    #[test]
    fn test_hash_different_expected_output_hash() {
        let c1 = make_valid_challenge();
        let mut c2 = make_valid_challenge();
        c2.expected_output_hash = vec![0xFF; 32];
        assert_ne!(
            c1.compute_challenge_hash().expect("h1"),
            c2.compute_challenge_hash().expect("h2"),
        );
    }

    #[test]
    fn test_hash_different_timestamp() {
        let c1 = make_valid_challenge();
        let mut c2 = make_valid_challenge();
        c2.timestamp = 1_700_999_999;
        assert_ne!(
            c1.compute_challenge_hash().expect("h1"),
            c2.compute_challenge_hash().expect("h2"),
        );
    }

    #[test]
    fn test_hash_rejects_invalid() {
        let mut c = make_valid_challenge();
        c.receipt_hash = vec![0x01; 10]; // Invalid
        assert!(c.compute_challenge_hash().is_err());
    }

    #[test]
    fn test_hash_output_32_bytes() {
        let hash = make_valid_challenge().compute_challenge_hash().expect("hash");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_hash_not_all_zeros() {
        let hash = make_valid_challenge().compute_challenge_hash().expect("hash");
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_hash_determinism_1000_runs() {
        let c = make_valid_challenge();
        let reference = c.compute_challenge_hash().expect("ref");
        for _ in 0..1000 {
            assert_eq!(c.compute_challenge_hash().expect("run"), reference);
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // ENCODE / DECODE
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_encode_decode_roundtrip() {
        let c = make_valid_challenge();
        let bytes = c.encode().expect("encode");
        let decoded = FraudProofChallengeProto::decode(&bytes).expect("decode");
        assert_eq!(c, decoded);
    }

    #[test]
    fn test_standalone_encode_decode_roundtrip() {
        let c = make_valid_challenge();
        let bytes = encode_fraud_proof(&c);
        let decoded = decode_fraud_proof(&bytes).expect("decode");
        assert_eq!(c, decoded);
    }

    #[test]
    fn test_decode_invalid_bytes() {
        assert!(FraudProofChallengeProto::decode(&[0xFF, 0x01]).is_err());
    }

    #[test]
    fn test_decode_empty_bytes() {
        assert!(FraudProofChallengeProto::decode(&[]).is_err());
    }

    #[test]
    fn test_encode_decode_preserves_hash() {
        let c = make_valid_challenge();
        let hash_before = c.compute_challenge_hash().expect("before");
        let bytes = c.encode().expect("encode");
        let decoded = FraudProofChallengeProto::decode(&bytes).expect("decode");
        let hash_after = decoded.compute_challenge_hash().expect("after");
        assert_eq!(hash_before, hash_after);
    }

    // ────────────────────────────────────────────────────────────────────────
    // STANDALONE FUNCTION
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_compute_fraud_proof_hash_fn() {
        let c = make_valid_challenge();
        let h_method = c.compute_challenge_hash().expect("method");
        let h_fn = compute_fraud_proof_hash(&c).expect("fn");
        assert_eq!(h_method, h_fn);
    }

    // ────────────────────────────────────────────────────────────────────────
    // ERROR DISPLAY
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_error_display_invalid_length() {
        let err = FraudProofError::InvalidLength {
            field: "receipt_hash",
            expected: 32,
            found: 16,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("receipt_hash"));
        assert!(msg.contains("32"));
        assert!(msg.contains("16"));
    }

    #[test]
    fn test_error_display_empty_trace() {
        let msg = format!("{}", FraudProofError::EmptyTraceSegment);
        assert!(msg.contains("empty"));
    }

    #[test]
    fn test_error_display_hashing_failed() {
        let msg = format!("{}", FraudProofError::HashingFailed);
        assert!(msg.contains("hashing"));
    }

    // ────────────────────────────────────────────────────────────────────────
    // CONSTANTS
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_constants() {
        assert_eq!(RECEIPT_HASH_SIZE, 32);
        assert_eq!(CHALLENGER_ADDRESS_SIZE, 20);
        assert_eq!(CHALLENGER_SIGNATURE_SIZE, 64);
        assert_eq!(EXPECTED_OUTPUT_HASH_SIZE, 32);
    }

    // ════════════════════════════════════════════════════════════════════════
    // P.8 — ENCODE/DECODE INTEGRATION TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_p8_encode_decode_encode_deterministic() {
        let challenge = make_valid_challenge();
        let bytes1 = challenge.encode().expect("encode1");
        let decoded = FraudProofChallengeProto::decode(&bytes1).expect("decode");
        let bytes2 = decoded.encode().expect("encode2");
        assert_eq!(bytes1, bytes2, "encode→decode→encode must produce identical bytes");
    }

    #[test]
    fn test_p8_decode_returns_bincode_error() {
        let result = FraudProofChallengeProto::decode(&[0xFF, 0xFF]);
        assert!(result.is_err());
    }

    #[test]
    fn test_p8_decode_validated_valid() {
        let challenge = make_valid_challenge();
        let bytes = challenge.encode().expect("encode");
        let decoded = FraudProofChallengeProto::decode_validated(&bytes).expect("validated");
        assert_eq!(challenge, decoded);
    }

    #[test]
    fn test_p8_decode_validated_rejects_invalid_bytes() {
        assert!(FraudProofChallengeProto::decode_validated(&[0xFF, 0x01]).is_err());
    }

    #[test]
    fn test_p8_method_and_standalone_same_bytes() {
        let challenge = make_valid_challenge();
        let bytes_method = challenge.encode().expect("method");
        let bytes_standalone = encode_fraud_proof(&challenge);
        assert_eq!(bytes_method, bytes_standalone);
    }

    #[test]
    fn test_p8_roundtrip_1000() {
        let challenge = make_valid_challenge();
        let reference = challenge.encode().expect("ref");
        for _ in 0..1000 {
            let decoded = FraudProofChallengeProto::decode(&reference).expect("dec");
            let re_encoded = decoded.encode().expect("enc");
            assert_eq!(reference, re_encoded);
        }
    }
}