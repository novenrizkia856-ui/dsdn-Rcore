//! # ClaimReward Transaction Message (14C.A — P.3)
//!
//! Module ini mendefinisikan `ClaimRewardProto`, transaction message yang digunakan
//! node untuk claim reward berdasarkan `ReceiptV1Proto`.
//!
//! ## Transaction Flow
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    ClaimReward Transaction Flow                  │
//! └─────────────────────────────────────────────────────────────────┘
//!
//!   Node                    Mempool                    Chain
//!     │                       │                          │
//!     │  1. Receive receipt   │                          │
//!     │     (from coordinator │                          │
//!     │      after threshold  │                          │
//!     │      signing)         │                          │
//!     │                       │                          │
//!     │  2. Build ClaimReward │                          │
//!     │     (embed receipt,   │                          │
//!     │      sign tx)         │                          │
//!     │                       │                          │
//!     │──3. Submit tx────────▶│                          │
//!     │                       │──4. Dedup via tx_hash───▶│
//!     │                       │                          │
//!     │                       │     5. Chain verifies:   │
//!     │                       │     - receipt validity   │
//!     │                       │     - threshold sig      │
//!     │                       │     - submitter sig      │
//!     │                       │     - anti-self-dealing  │
//!     │                       │     - not double-claim   │
//!     │                       │                          │
//!     │                       │     6. Storage: reward   │
//!     │                       │        Compute: start    │
//!     │                       │        challenge period  │
//!     │                       │                          │
//! ```
//!
//! ## Deduplication
//!
//! `compute_tx_hash()` menghasilkan SHA3-256 hash deterministik yang digunakan
//! oleh mempool untuk dedup dan indexing. Dua ClaimRewardProto dengan
//! konten identik HARUS menghasilkan tx_hash yang sama.
//!
//! ## Hash Order (FIXED — consensus-critical)
//!
//! `compute_tx_hash()` uses SHA3-256 with the following concatenation order:
//!
//! 1. `receipt.compute_receipt_hash()` (32 bytes)
//! 2. `submitter_address` (20 bytes)
//! 3. `submitter_signature` (64 bytes)
//! 4. `nonce` (8 bytes, big-endian)
//! 5. `timestamp` (8 bytes, big-endian)
//!
//! Total: 132 bytes sebelum hashing. Tidak ada separator.
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

use crate::tss::receipt_v1::{ReceiptV1Error, ReceiptV1Proto};

// ════════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════════

/// Expected size for submitter_address field.
pub const SUBMITTER_ADDRESS_SIZE: usize = 20;

/// Expected size for submitter_signature field (Ed25519).
pub const SUBMITTER_SIGNATURE_SIZE: usize = 64;

// ════════════════════════════════════════════════════════════════════════════════
// ERROR TYPE
// ════════════════════════════════════════════════════════════════════════════════

/// Error type untuk validasi, hashing, dan encoding `ClaimRewardProto`.
///
/// Setiap varian menjelaskan secara eksplisit kondisi yang gagal.
/// Tidak ada string error generik.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimRewardError {
    /// Sebuah field memiliki panjang yang tidak sesuai.
    InvalidLength {
        field: &'static str,
        expected: usize,
        found: usize,
    },

    /// Embedded receipt gagal validasi.
    ReceiptInvalid,

    /// Hashing gagal.
    HashingFailed,

    /// Encoding (serialization) gagal.
    EncodeFailed,

    /// Decoding (deserialization) gagal.
    DecodeFailed,
}

impl fmt::Display for ClaimRewardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClaimRewardError::InvalidLength {
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
            ClaimRewardError::ReceiptInvalid => {
                write!(f, "embedded receipt failed validation")
            }
            ClaimRewardError::HashingFailed => {
                write!(f, "hashing failed")
            }
            ClaimRewardError::EncodeFailed => {
                write!(f, "encoding (serialization) failed")
            }
            ClaimRewardError::DecodeFailed => {
                write!(f, "decoding (deserialization) failed")
            }
        }
    }
}

impl std::error::Error for ClaimRewardError {}

impl From<ReceiptV1Error> for ClaimRewardError {
    fn from(_: ReceiptV1Error) -> Self {
        ClaimRewardError::ReceiptInvalid
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// CLAIM REWARD PROTO
// ════════════════════════════════════════════════════════════════════════════════

/// Proto message untuk ClaimReward transaction.
///
/// `ClaimRewardProto` adalah transaction message yang digunakan node untuk
/// claim reward berdasarkan receipt yang sudah di-threshold-sign oleh coordinator.
///
/// ## Flow
///
/// 1. Node menerima `ReceiptV1Proto` dari coordinator setelah threshold signing.
/// 2. Node membangun `ClaimRewardProto` yang membawa receipt lengkap.
/// 3. Node menandatangani transaction dengan Ed25519 key.
/// 4. Node submit transaction ke chain via RPC.
/// 5. Chain memverifikasi: receipt validity, threshold signature,
///    submitter signature, anti-self-dealing, double-claim check.
///
/// ## Deduplication
///
/// `compute_tx_hash()` menghasilkan hash deterministik yang digunakan oleh
/// mempool untuk deduplication dan indexing. Dua transaksi identik HARUS
/// menghasilkan tx_hash yang sama.
///
/// ## Field Sizes
///
/// | Field | Expected Size |
/// |-------|---------------|
/// | `receipt` | Validated via ReceiptV1Proto::validate() |
/// | `submitter_address` | 20 bytes |
/// | `submitter_signature` | 64 bytes (Ed25519) |
/// | `nonce` | u64 |
/// | `timestamp` | u64 |
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimRewardProto {
    /// Receipt V1 lengkap yang menjadi basis claim.
    ///
    /// WAJIB valid — `validate()` akan memanggil `receipt.validate()`.
    pub receipt: ReceiptV1Proto,

    /// Address submitter (MUST be 20 bytes).
    ///
    /// Harus sesuai dengan signer dari `submitter_signature`.
    /// Digunakan untuk verifikasi anti-self-dealing.
    pub submitter_address: Vec<u8>,

    /// Ed25519 signature dari submitter atas transaction data (MUST be 64 bytes).
    ///
    /// Membuktikan bahwa submitter yang sah mengirim transaction ini.
    pub submitter_signature: Vec<u8>,

    /// Nonce untuk ordering dan replay protection.
    ///
    /// Nilai 0 diperbolehkan. Uniqueness enforcement dilakukan di chain layer.
    pub nonce: u64,

    /// Unix timestamp saat transaction dibuat.
    ///
    /// Nilai 0 diperbolehkan (genesis case).
    pub timestamp: u64,
}

impl ClaimRewardProto {
    /// Validates all fields and invariants.
    ///
    /// # Validation Rules
    ///
    /// 1. `receipt.validate()` MUST pass.
    /// 2. `submitter_address.len() == 20`
    /// 3. `submitter_signature.len() == 64`
    /// 4. `nonce` — no restriction (0 allowed).
    /// 5. `timestamp` — no restriction (0 allowed for genesis case).
    ///
    /// # Returns
    ///
    /// - `Ok(())` if all validations pass.
    /// - `Err(ClaimRewardError)` with specific variant for the first failure.
    pub fn validate(&self) -> Result<(), ClaimRewardError> {
        // 1. receipt
        self.receipt
            .validate()
            .map_err(|_| ClaimRewardError::ReceiptInvalid)?;

        // 2. submitter_address
        validate_field_length(
            &self.submitter_address,
            "submitter_address",
            SUBMITTER_ADDRESS_SIZE,
        )?;

        // 3. submitter_signature
        validate_field_length(
            &self.submitter_signature,
            "submitter_signature",
            SUBMITTER_SIGNATURE_SIZE,
        )?;

        // 4. nonce — no restriction
        // 5. timestamp — no restriction

        Ok(())
    }

    /// Computes deterministic SHA3-256 transaction hash.
    ///
    /// Hash ini digunakan oleh mempool untuk deduplication dan indexing.
    ///
    /// # Hash Order (FIXED — consensus-critical)
    ///
    /// Konkatenasi dalam urutan berikut, tanpa separator:
    ///
    /// 1. `receipt.compute_receipt_hash()` (32 bytes)
    /// 2. `submitter_address` (20 bytes)
    /// 3. `submitter_signature` (64 bytes)
    /// 4. `nonce` (8 bytes, big-endian)
    /// 5. `timestamp` (8 bytes, big-endian)
    ///
    /// Total input: 132 bytes → SHA3-256 → 32 bytes output.
    ///
    /// # Returns
    ///
    /// - `Ok([u8; 32])` — deterministic hash.
    /// - `Err(ClaimRewardError)` — if `validate()` or receipt hashing fails.
    ///
    /// # CRITICAL
    ///
    /// Perubahan urutan hash = breaking change = hard-fork.
    /// Hash order HARUS IDENTIK di semua implementasi (proto, common, chain).
    pub fn compute_tx_hash(&self) -> Result<[u8; 32], ClaimRewardError> {
        // Validate all fields terlebih dahulu.
        self.validate()?;

        // 1. receipt hash (32 bytes).
        let receipt_hash = self
            .receipt
            .compute_receipt_hash()
            .map_err(|_| ClaimRewardError::HashingFailed)?;

        // Pre-allocate buffer for all fields (132 bytes).
        let mut buf = Vec::with_capacity(132);

        // 1. receipt hash (32 bytes)
        buf.extend_from_slice(&receipt_hash);

        // 2. submitter_address (20 bytes)
        buf.extend_from_slice(&self.submitter_address);

        // 3. submitter_signature (64 bytes)
        buf.extend_from_slice(&self.submitter_signature);

        // 4. nonce (8 bytes, big-endian)
        buf.extend_from_slice(&self.nonce.to_be_bytes());

        // 5. timestamp (8 bytes, big-endian)
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
    /// Setelah decode, `validate()` dipanggil secara otomatis.
    /// Jika hasil decode tidak valid, error dikembalikan.
    ///
    /// # Returns
    ///
    /// - `Ok(Self)` — valid decoded proto.
    /// - `Err(ClaimRewardError::DecodeFailed)` — if deserialization fails.
    /// - `Err(ClaimRewardError)` — if validation fails setelah decode.
    pub fn decode_validated(bytes: &[u8]) -> Result<Self, ClaimRewardError> {
        let proto: Self =
            bincode::deserialize(bytes).map_err(|_| ClaimRewardError::DecodeFailed)?;

        proto.validate()?;

        Ok(proto)
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// STANDALONE FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════════

/// Encode `ClaimRewardProto` ke bytes.
#[must_use]
pub fn encode_claim_reward(claim: &ClaimRewardProto) -> Vec<u8> {
    bincode::serialize(claim).unwrap_or_else(|_| Vec::new())
}

/// Decode bytes ke `ClaimRewardProto`.
///
/// Validates setelah decode. Mengembalikan error jika invalid.
pub fn decode_claim_reward(bytes: &[u8]) -> Result<ClaimRewardProto, ClaimRewardError> {
    let proto: ClaimRewardProto =
        bincode::deserialize(bytes).map_err(|_| ClaimRewardError::DecodeFailed)?;

    // Validate setelah decode.
    proto.validate()?;

    Ok(proto)
}

/// Compute SHA3-256 transaction hash dari `ClaimRewardProto`.
pub fn compute_claim_reward_hash(
    claim: &ClaimRewardProto,
) -> Result<[u8; 32], ClaimRewardError> {
    claim.compute_tx_hash()
}

// ════════════════════════════════════════════════════════════════════════════════
// INTERNAL HELPERS
// ════════════════════════════════════════════════════════════════════════════════

/// Validate field length.
fn validate_field_length(
    field_data: &[u8],
    field_name: &'static str,
    expected: usize,
) -> Result<(), ClaimRewardError> {
    if field_data.len() != expected {
        return Err(ClaimRewardError::InvalidLength {
            field: field_name,
            expected,
            found: field_data.len(),
        });
    }
    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// REWARD DISTRIBUTION ERROR (14C.A — P.6)
// ════════════════════════════════════════════════════════════════════════════════

/// Expected size for receipt_hash in RewardDistributionProto.
pub const REWARD_RECEIPT_HASH_SIZE: usize = 32;

/// Error type untuk validasi `RewardDistributionProto`.
///
/// Setiap varian menjelaskan secara eksplisit kondisi yang gagal.
/// Tidak ada string error generik.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RewardDistributionError {
    /// Sebuah field memiliki panjang yang tidak sesuai.
    InvalidLength {
        field: &'static str,
        expected: usize,
        found: usize,
    },

    /// Overflow terjadi saat menjumlahkan reward components.
    ArithmeticOverflow,

    /// Total tidak cocok dengan jumlah node_reward + validator_reward + treasury_reward.
    TotalMismatch {
        /// Nilai `total` yang disimpan dalam struct.
        expected: u128,
        /// Nilai yang dihitung dari `node_reward + validator_reward + treasury_reward`.
        computed: u128,
    },
}

impl fmt::Display for RewardDistributionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RewardDistributionError::InvalidLength {
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
            RewardDistributionError::ArithmeticOverflow => {
                write!(
                    f,
                    "arithmetic overflow when summing reward components"
                )
            }
            RewardDistributionError::TotalMismatch { expected, computed } => {
                write!(
                    f,
                    "total mismatch: stored total is {} but computed sum is {}",
                    expected, computed
                )
            }
        }
    }
}

impl std::error::Error for RewardDistributionError {}

// ════════════════════════════════════════════════════════════════════════════════
// REWARD DISTRIBUTION PROTO (14C.A — P.6)
// ════════════════════════════════════════════════════════════════════════════════

/// Proto message untuk hasil distribusi reward dari chain.
///
/// `RewardDistributionProto` adalah response yang dihasilkan chain setelah
/// `ClaimRewardProto` diproses dan divalidasi. Struct ini merepresentasikan
/// hasil final pembagian reward — BUKAN yang menghitung pembagian.
///
/// ## Mapping ke FeeSplit (chain/tokenomics.rs)
///
/// | Component | Percentage | Field |
/// |-----------|-----------|-------|
/// | Node | 70% | `node_reward` |
/// | Validator | 20% | `validator_reward` |
/// | Treasury | 10% | `treasury_reward` |
/// | **Total** | **100%** | `total` |
///
/// ## Important Notes
///
/// - Struct ini **TIDAK menghitung** pembagian persentase.
///   Chain layer yang menghitung berdasarkan `reward_base` dari receipt.
/// - Struct ini **HANYA merepresentasikan** hasil final.
/// - `total` HARUS SAMA DENGAN `node_reward + validator_reward + treasury_reward`.
/// - Semua reward boleh 0 (misalnya jika reward_base = 0), tetapi total
///   harus tetap konsisten.
///
/// ## Anti-Self-Dealing
///
/// `anti_self_dealing_applied` bernilai `true` jika node address sama
/// dengan submitter address dan aturan penalti diterapkan oleh chain.
/// Dalam kasus ini, reward mungkin di-reduce atau di-redistribute.
///
/// ## Challenge Period
///
/// `challenge_period_active` bernilai `true` jika receipt adalah compute
/// receipt dan challenge period belum cleared. Reward belum final dan
/// masih bisa dibatalkan jika fraud terbukti.
///
/// ## Field Sizes
///
/// | Field | Type |
/// |-------|------|
/// | `receipt_hash` | 32 bytes |
/// | `node_reward` | u128 |
/// | `validator_reward` | u128 |
/// | `treasury_reward` | u128 |
/// | `total` | u128 |
/// | `anti_self_dealing_applied` | bool |
/// | `challenge_period_active` | bool |
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewardDistributionProto {
    /// Hash dari receipt yang reward-nya didistribusikan (MUST be 32 bytes).
    pub receipt_hash: Vec<u8>,

    /// Reward untuk node yang melakukan kerja (70% dari reward_base).
    pub node_reward: u128,

    /// Reward untuk validator yang memvalidasi (20% dari reward_base).
    pub validator_reward: u128,

    /// Reward untuk treasury (10% dari reward_base).
    pub treasury_reward: u128,

    /// Total reward = node_reward + validator_reward + treasury_reward.
    ///
    /// HARUS konsisten — validation akan gagal jika mismatch.
    pub total: u128,

    /// True jika anti-self-dealing rule diterapkan.
    ///
    /// Terjadi ketika node address == submitter address.
    pub anti_self_dealing_applied: bool,

    /// True jika compute receipt dan challenge period belum cleared.
    ///
    /// Reward belum final — masih bisa dibatalkan jika fraud terbukti.
    pub challenge_period_active: bool,
}

impl RewardDistributionProto {
    /// Validates all fields and invariants.
    ///
    /// # Validation Rules
    ///
    /// 1. `receipt_hash.len() == 32`
    /// 2. `node_reward + validator_reward + treasury_reward` MUST NOT overflow.
    /// 3. `total` MUST EQUAL `node_reward + validator_reward + treasury_reward`.
    /// 4. Semua reward boleh 0 — tapi total harus konsisten.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if all validations pass.
    /// - `Err(RewardDistributionError)` with specific variant for the first failure.
    pub fn validate(&self) -> Result<(), RewardDistributionError> {
        // 1. receipt_hash length
        if self.receipt_hash.len() != REWARD_RECEIPT_HASH_SIZE {
            return Err(RewardDistributionError::InvalidLength {
                field: "receipt_hash",
                expected: REWARD_RECEIPT_HASH_SIZE,
                found: self.receipt_hash.len(),
            });
        }

        // 2. Overflow check via checked_add
        let sum = self
            .node_reward
            .checked_add(self.validator_reward)
            .and_then(|s| s.checked_add(self.treasury_reward))
            .ok_or(RewardDistributionError::ArithmeticOverflow)?;

        // 3. Total mismatch check
        if self.total != sum {
            return Err(RewardDistributionError::TotalMismatch {
                expected: self.total,
                computed: sum,
            });
        }

        Ok(())
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
    pub fn decode_validated(bytes: &[u8]) -> Result<Self, RewardDistributionError> {
        let proto: Self = bincode::deserialize(bytes)
            .map_err(|_| RewardDistributionError::ArithmeticOverflow)?;

        proto.validate()?;

        Ok(proto)
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tss::execution::ExecutionCommitmentProto;
    use crate::tss::receipt_v1::{RECEIPT_TYPE_COMPUTE, RECEIPT_TYPE_STORAGE};
    use crate::tss::signing::AggregateSignatureProto;

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

    /// Helper: build valid ClaimRewardProto with storage receipt.
    fn make_storage_claim() -> ClaimRewardProto {
        ClaimRewardProto {
            receipt: make_storage_receipt(),
            submitter_address: vec![0x05; 20],
            submitter_signature: vec![0xCC; 64],
            nonce: 1,
            timestamp: 1_700_000_100,
        }
    }

    /// Helper: build valid ClaimRewardProto with compute receipt.
    fn make_compute_claim() -> ClaimRewardProto {
        ClaimRewardProto {
            receipt: make_compute_receipt(),
            submitter_address: vec![0x05; 20],
            submitter_signature: vec![0xCC; 64],
            nonce: 2,
            timestamp: 1_700_000_200,
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // VALIDATE
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_validate_storage_claim_valid() {
        assert!(make_storage_claim().validate().is_ok());
    }

    #[test]
    fn test_validate_compute_claim_valid() {
        assert!(make_compute_claim().validate().is_ok());
    }

    #[test]
    fn test_validate_invalid_submitter_address_too_short() {
        let mut claim = make_storage_claim();
        claim.submitter_address = vec![0x05; 10];
        let err = claim.validate().unwrap_err();
        assert_eq!(
            err,
            ClaimRewardError::InvalidLength {
                field: "submitter_address",
                expected: 20,
                found: 10,
            }
        );
    }

    #[test]
    fn test_validate_invalid_submitter_address_too_long() {
        let mut claim = make_storage_claim();
        claim.submitter_address = vec![0x05; 32];
        let err = claim.validate().unwrap_err();
        assert_eq!(
            err,
            ClaimRewardError::InvalidLength {
                field: "submitter_address",
                expected: 20,
                found: 32,
            }
        );
    }

    #[test]
    fn test_validate_invalid_submitter_address_empty() {
        let mut claim = make_storage_claim();
        claim.submitter_address = Vec::new();
        let err = claim.validate().unwrap_err();
        assert_eq!(
            err,
            ClaimRewardError::InvalidLength {
                field: "submitter_address",
                expected: 20,
                found: 0,
            }
        );
    }

    #[test]
    fn test_validate_invalid_submitter_signature_too_short() {
        let mut claim = make_storage_claim();
        claim.submitter_signature = vec![0xCC; 32];
        let err = claim.validate().unwrap_err();
        assert_eq!(
            err,
            ClaimRewardError::InvalidLength {
                field: "submitter_signature",
                expected: 64,
                found: 32,
            }
        );
    }

    #[test]
    fn test_validate_invalid_submitter_signature_too_long() {
        let mut claim = make_storage_claim();
        claim.submitter_signature = vec![0xCC; 128];
        let err = claim.validate().unwrap_err();
        assert_eq!(
            err,
            ClaimRewardError::InvalidLength {
                field: "submitter_signature",
                expected: 64,
                found: 128,
            }
        );
    }

    #[test]
    fn test_validate_invalid_receipt_propagates() {
        let mut claim = make_storage_claim();
        claim.receipt.workload_id = vec![0x01; 10]; // Invalid receipt
        let err = claim.validate().unwrap_err();
        assert_eq!(err, ClaimRewardError::ReceiptInvalid);
    }

    #[test]
    fn test_validate_nonce_zero_allowed() {
        let mut claim = make_storage_claim();
        claim.nonce = 0;
        assert!(claim.validate().is_ok());
    }

    #[test]
    fn test_validate_nonce_max_allowed() {
        let mut claim = make_storage_claim();
        claim.nonce = u64::MAX;
        assert!(claim.validate().is_ok());
    }

    #[test]
    fn test_validate_timestamp_zero_allowed() {
        let mut claim = make_storage_claim();
        claim.timestamp = 0;
        assert!(claim.validate().is_ok());
    }

    #[test]
    fn test_validate_timestamp_max_allowed() {
        let mut claim = make_storage_claim();
        claim.timestamp = u64::MAX;
        assert!(claim.validate().is_ok());
    }

    // ────────────────────────────────────────────────────────────────────────
    // COMPUTE TX HASH
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_hash_deterministic() {
        let claim = make_storage_claim();
        let h1 = claim.compute_tx_hash().expect("h1");
        let h2 = claim.compute_tx_hash().expect("h2");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_compute_receipt_deterministic() {
        let claim = make_compute_claim();
        let h1 = claim.compute_tx_hash().expect("h1");
        let h2 = claim.compute_tx_hash().expect("h2");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_storage_vs_compute_different() {
        let h1 = make_storage_claim().compute_tx_hash().expect("h1");
        let h2 = make_compute_claim().compute_tx_hash().expect("h2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hash_different_submitter_address() {
        let c1 = make_storage_claim();
        let mut c2 = make_storage_claim();
        c2.submitter_address = vec![0xFF; 20];
        assert_ne!(
            c1.compute_tx_hash().expect("h1"),
            c2.compute_tx_hash().expect("h2"),
        );
    }

    #[test]
    fn test_hash_different_submitter_signature() {
        let c1 = make_storage_claim();
        let mut c2 = make_storage_claim();
        c2.submitter_signature = vec![0xFF; 64];
        assert_ne!(
            c1.compute_tx_hash().expect("h1"),
            c2.compute_tx_hash().expect("h2"),
        );
    }

    #[test]
    fn test_hash_different_nonce() {
        let c1 = make_storage_claim();
        let mut c2 = make_storage_claim();
        c2.nonce = 999;
        assert_ne!(
            c1.compute_tx_hash().expect("h1"),
            c2.compute_tx_hash().expect("h2"),
        );
    }

    #[test]
    fn test_hash_different_timestamp() {
        let c1 = make_storage_claim();
        let mut c2 = make_storage_claim();
        c2.timestamp = 1_700_999_999;
        assert_ne!(
            c1.compute_tx_hash().expect("h1"),
            c2.compute_tx_hash().expect("h2"),
        );
    }

    #[test]
    fn test_hash_rejects_invalid_claim() {
        let mut claim = make_storage_claim();
        claim.submitter_address = vec![0x05; 10]; // Invalid
        assert!(claim.compute_tx_hash().is_err());
    }

    #[test]
    fn test_hash_output_32_bytes() {
        let hash = make_storage_claim().compute_tx_hash().expect("hash");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_hash_not_all_zeros() {
        let hash = make_storage_claim().compute_tx_hash().expect("hash");
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_hash_determinism_1000_runs() {
        let claim = make_compute_claim();
        let reference = claim.compute_tx_hash().expect("ref");
        for _ in 0..1000 {
            assert_eq!(claim.compute_tx_hash().expect("run"), reference);
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // ENCODE / DECODE
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_encode_decode_storage_roundtrip() {
        let claim = make_storage_claim();
        let bytes = claim.encode().expect("encode");
        let decoded = ClaimRewardProto::decode(&bytes).expect("decode");
        assert_eq!(claim, decoded);
    }

    #[test]
    fn test_encode_decode_compute_roundtrip() {
        let claim = make_compute_claim();
        let bytes = claim.encode().expect("encode");
        let decoded = ClaimRewardProto::decode(&bytes).expect("decode");
        assert_eq!(claim, decoded);
    }

    #[test]
    fn test_standalone_encode_decode_roundtrip() {
        let claim = make_storage_claim();
        let bytes = encode_claim_reward(&claim);
        let decoded = decode_claim_reward(&bytes).expect("decode");
        assert_eq!(claim, decoded);
    }

    #[test]
    fn test_decode_invalid_bytes() {
        assert!(ClaimRewardProto::decode(&[0xFF, 0x01, 0x02]).is_err());
    }

    #[test]
    fn test_decode_empty_bytes() {
        assert!(ClaimRewardProto::decode(&[]).is_err());
    }

    #[test]
    fn test_decode_rejects_invalid_content() {
        // Encode a claim with valid structure but then corrupt the receipt inside.
        let claim = make_storage_claim();
        let mut bytes = claim.encode().expect("encode");
        // Corrupt first few bytes (workload_id length in bincode)
        // to create an invalid deserialized struct.
        // Since bincode serializes Vec length first, truncating should cause error.
        bytes.truncate(10);
        assert!(ClaimRewardProto::decode(&bytes).is_err());
    }

    #[test]
    fn test_encode_decode_preserves_hash() {
        let claim = make_compute_claim();
        let hash_before = claim.compute_tx_hash().expect("before");
        let bytes = claim.encode().expect("encode");
        let decoded = ClaimRewardProto::decode(&bytes).expect("decode");
        let hash_after = decoded.compute_tx_hash().expect("after");
        assert_eq!(hash_before, hash_after);
    }

    // ────────────────────────────────────────────────────────────────────────
    // STANDALONE FUNCTION
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_compute_claim_reward_hash_fn() {
        let claim = make_storage_claim();
        let h_method = claim.compute_tx_hash().expect("method");
        let h_fn = compute_claim_reward_hash(&claim).expect("fn");
        assert_eq!(h_method, h_fn);
    }

    // ────────────────────────────────────────────────────────────────────────
    // ERROR DISPLAY
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_error_display_invalid_length() {
        let err = ClaimRewardError::InvalidLength {
            field: "submitter_address",
            expected: 20,
            found: 10,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("submitter_address"));
        assert!(msg.contains("20"));
        assert!(msg.contains("10"));
    }

    #[test]
    fn test_error_display_receipt_invalid() {
        let msg = format!("{}", ClaimRewardError::ReceiptInvalid);
        assert!(msg.contains("receipt"));
    }

    #[test]
    fn test_error_display_hashing_failed() {
        let msg = format!("{}", ClaimRewardError::HashingFailed);
        assert!(msg.contains("hashing"));
    }

    #[test]
    fn test_error_display_encode_failed() {
        let msg = format!("{}", ClaimRewardError::EncodeFailed);
        assert!(msg.contains("encoding"));
    }

    #[test]
    fn test_error_display_decode_failed() {
        let msg = format!("{}", ClaimRewardError::DecodeFailed);
        assert!(msg.contains("decoding"));
    }

    // ────────────────────────────────────────────────────────────────────────
    // CONSTANTS
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_constants() {
        assert_eq!(SUBMITTER_ADDRESS_SIZE, 20);
        assert_eq!(SUBMITTER_SIGNATURE_SIZE, 64);
    }

    // ════════════════════════════════════════════════════════════════════════
    // P.6 — REWARD DISTRIBUTION PROTO TESTS
    // ════════════════════════════════════════════════════════════════════════

    /// Helper: build valid RewardDistributionProto.
    fn make_valid_distribution() -> RewardDistributionProto {
        RewardDistributionProto {
            receipt_hash: vec![0x01; 32],
            node_reward: 700_000,
            validator_reward: 200_000,
            treasury_reward: 100_000,
            total: 1_000_000,
            anti_self_dealing_applied: false,
            challenge_period_active: false,
        }
    }

    // ── VALIDATE ────────────────────────────────────────────────────────

    #[test]
    fn test_rd_validate_valid() {
        assert!(make_valid_distribution().validate().is_ok());
    }

    #[test]
    fn test_rd_validate_all_zeros_valid() {
        let d = RewardDistributionProto {
            receipt_hash: vec![0x00; 32],
            node_reward: 0,
            validator_reward: 0,
            treasury_reward: 0,
            total: 0,
            anti_self_dealing_applied: false,
            challenge_period_active: false,
        };
        assert!(d.validate().is_ok());
    }

    #[test]
    fn test_rd_validate_with_anti_self_dealing() {
        let mut d = make_valid_distribution();
        d.anti_self_dealing_applied = true;
        assert!(d.validate().is_ok());
    }

    #[test]
    fn test_rd_validate_with_challenge_period_active() {
        let mut d = make_valid_distribution();
        d.challenge_period_active = true;
        assert!(d.validate().is_ok());
    }

    #[test]
    fn test_rd_validate_invalid_receipt_hash_too_short() {
        let mut d = make_valid_distribution();
        d.receipt_hash = vec![0x01; 16];
        let err = d.validate().unwrap_err();
        assert_eq!(
            err,
            RewardDistributionError::InvalidLength {
                field: "receipt_hash",
                expected: 32,
                found: 16,
            }
        );
    }

    #[test]
    fn test_rd_validate_invalid_receipt_hash_too_long() {
        let mut d = make_valid_distribution();
        d.receipt_hash = vec![0x01; 64];
        assert!(d.validate().is_err());
    }

    #[test]
    fn test_rd_validate_invalid_receipt_hash_empty() {
        let mut d = make_valid_distribution();
        d.receipt_hash = Vec::new();
        assert!(d.validate().is_err());
    }

    #[test]
    fn test_rd_validate_total_mismatch() {
        let mut d = make_valid_distribution();
        d.total = 999_999; // Wrong: should be 1_000_000
        let err = d.validate().unwrap_err();
        assert_eq!(
            err,
            RewardDistributionError::TotalMismatch {
                expected: 999_999,
                computed: 1_000_000,
            }
        );
    }

    #[test]
    fn test_rd_validate_total_zero_but_rewards_nonzero() {
        let mut d = make_valid_distribution();
        d.total = 0; // Wrong: rewards sum to 1_000_000
        let err = d.validate().unwrap_err();
        assert_eq!(
            err,
            RewardDistributionError::TotalMismatch {
                expected: 0,
                computed: 1_000_000,
            }
        );
    }

    #[test]
    fn test_rd_validate_overflow_node_plus_validator() {
        let d = RewardDistributionProto {
            receipt_hash: vec![0x01; 32],
            node_reward: u128::MAX,
            validator_reward: 1,
            treasury_reward: 0,
            total: 0,
            anti_self_dealing_applied: false,
            challenge_period_active: false,
        };
        let err = d.validate().unwrap_err();
        assert_eq!(err, RewardDistributionError::ArithmeticOverflow);
    }

    #[test]
    fn test_rd_validate_overflow_sum_plus_treasury() {
        let d = RewardDistributionProto {
            receipt_hash: vec![0x01; 32],
            node_reward: u128::MAX - 1,
            validator_reward: 1,
            treasury_reward: 1,
            total: 0,
            anti_self_dealing_applied: false,
            challenge_period_active: false,
        };
        let err = d.validate().unwrap_err();
        assert_eq!(err, RewardDistributionError::ArithmeticOverflow);
    }

    #[test]
    fn test_rd_validate_max_no_overflow() {
        // u128::MAX / 3 for each — no overflow
        let third = u128::MAX / 3;
        let remainder = u128::MAX - third * 2;
        let d = RewardDistributionProto {
            receipt_hash: vec![0x01; 32],
            node_reward: third,
            validator_reward: third,
            treasury_reward: remainder,
            total: third + third + remainder,
            anti_self_dealing_applied: false,
            challenge_period_active: false,
        };
        assert!(d.validate().is_ok());
    }

    #[test]
    fn test_rd_validate_only_node_reward() {
        let d = RewardDistributionProto {
            receipt_hash: vec![0x01; 32],
            node_reward: 500,
            validator_reward: 0,
            treasury_reward: 0,
            total: 500,
            anti_self_dealing_applied: false,
            challenge_period_active: false,
        };
        assert!(d.validate().is_ok());
    }

    // ── ENCODE / DECODE ─────────────────────────────────────────────────

    #[test]
    fn test_rd_encode_decode_roundtrip() {
        let d = make_valid_distribution();
        let bytes = d.encode().expect("encode");
        let decoded = RewardDistributionProto::decode(&bytes).expect("decode");
        assert_eq!(d, decoded);
    }

    #[test]
    fn test_rd_encode_decode_with_flags() {
        let mut d = make_valid_distribution();
        d.anti_self_dealing_applied = true;
        d.challenge_period_active = true;
        let bytes = d.encode().expect("encode");
        let decoded = RewardDistributionProto::decode(&bytes).expect("decode");
        assert_eq!(d, decoded);
    }

    #[test]
    fn test_rd_decode_invalid_bytes() {
        assert!(RewardDistributionProto::decode(&[0xFF, 0x01]).is_err());
    }

    #[test]
    fn test_rd_decode_empty_bytes() {
        assert!(RewardDistributionProto::decode(&[]).is_err());
    }

    // ── ERROR DISPLAY ───────────────────────────────────────────────────

    #[test]
    fn test_rd_error_display_invalid_length() {
        let err = RewardDistributionError::InvalidLength {
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
    fn test_rd_error_display_overflow() {
        let msg = format!("{}", RewardDistributionError::ArithmeticOverflow);
        assert!(msg.contains("overflow"));
    }

    #[test]
    fn test_rd_error_display_total_mismatch() {
        let err = RewardDistributionError::TotalMismatch {
            expected: 100,
            computed: 200,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("100"));
        assert!(msg.contains("200"));
    }

    // ── CONSTANTS ───────────────────────────────────────────────────────

    #[test]
    fn test_rd_constants() {
        assert_eq!(REWARD_RECEIPT_HASH_SIZE, 32);
    }

    // ════════════════════════════════════════════════════════════════════════
    // P.8 — ENCODE/DECODE INTEGRATION TESTS
    // ════════════════════════════════════════════════════════════════════════

    // ── ClaimRewardProto ────────────────────────────────────────────────

    #[test]
    fn test_p8_claim_encode_decode_encode_deterministic() {
        let claim = make_storage_claim();
        let bytes1 = claim.encode().expect("encode1");
        let decoded = ClaimRewardProto::decode(&bytes1).expect("decode");
        let bytes2 = decoded.encode().expect("encode2");
        assert_eq!(bytes1, bytes2, "encode→decode→encode must produce identical bytes");
    }

    #[test]
    fn test_p8_claim_compute_encode_decode_encode_deterministic() {
        let claim = make_compute_claim();
        let bytes1 = claim.encode().expect("encode1");
        let decoded = ClaimRewardProto::decode(&bytes1).expect("decode");
        let bytes2 = decoded.encode().expect("encode2");
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn test_p8_claim_method_and_standalone_same_bytes() {
        let claim = make_storage_claim();
        let bytes_method = claim.encode().expect("method");
        let bytes_standalone = encode_claim_reward(&claim);
        assert_eq!(bytes_method, bytes_standalone);
    }

    #[test]
    fn test_p8_claim_decode_returns_bincode_error() {
        let result = ClaimRewardProto::decode(&[0xFF, 0xFF]);
        assert!(result.is_err());
    }

    #[test]
    fn test_p8_claim_decode_validated_storage() {
        let claim = make_storage_claim();
        let bytes = claim.encode().expect("encode");
        let decoded = ClaimRewardProto::decode_validated(&bytes).expect("validated");
        assert_eq!(claim, decoded);
    }

    #[test]
    fn test_p8_claim_decode_validated_compute() {
        let claim = make_compute_claim();
        let bytes = claim.encode().expect("encode");
        let decoded = ClaimRewardProto::decode_validated(&bytes).expect("validated");
        assert_eq!(claim, decoded);
    }

    #[test]
    fn test_p8_claim_decode_validated_rejects_invalid_bytes() {
        assert!(ClaimRewardProto::decode_validated(&[0xFF, 0x01]).is_err());
    }

    #[test]
    fn test_p8_claim_roundtrip_1000() {
        let claim = make_compute_claim();
        let reference = claim.encode().expect("ref");
        for _ in 0..1000 {
            let decoded = ClaimRewardProto::decode(&reference).expect("dec");
            let re_encoded = decoded.encode().expect("enc");
            assert_eq!(reference, re_encoded);
        }
    }

    // ── RewardDistributionProto ─────────────────────────────────────────

    #[test]
    fn test_p8_rd_encode_decode_encode_deterministic() {
        let rd = make_valid_distribution();
        let bytes1 = rd.encode().expect("encode1");
        let decoded = RewardDistributionProto::decode(&bytes1).expect("decode");
        let bytes2 = decoded.encode().expect("encode2");
        assert_eq!(bytes1, bytes2, "encode→decode→encode must produce identical bytes");
    }

    #[test]
    fn test_p8_rd_decode_returns_bincode_error() {
        let result = RewardDistributionProto::decode(&[0xFF, 0xFF]);
        assert!(result.is_err());
    }

    #[test]
    fn test_p8_rd_decode_validated_valid() {
        let rd = make_valid_distribution();
        let bytes = rd.encode().expect("encode");
        let decoded = RewardDistributionProto::decode_validated(&bytes).expect("validated");
        assert_eq!(rd, decoded);
    }

    #[test]
    fn test_p8_rd_decode_validated_rejects_invalid_bytes() {
        assert!(RewardDistributionProto::decode_validated(&[0xFF, 0x01]).is_err());
    }

    #[test]
    fn test_p8_rd_roundtrip_1000() {
        let rd = make_valid_distribution();
        let reference = rd.encode().expect("ref");
        for _ in 0..1000 {
            let decoded = RewardDistributionProto::decode(&reference).expect("dec");
            let re_encoded = decoded.encode().expect("enc");
            assert_eq!(reference, re_encoded);
        }
    }
}