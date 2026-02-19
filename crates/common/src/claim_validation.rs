//! # ClaimReward Validation Types
//!
//! Shared validation types untuk proses ClaimReward yang digunakan
//! oleh chain, coordinator, dan node-side logic.
//!
//! ## Decision Tree
//!
//! ```text
//! ClaimReward TX
//!   ├─ Validasi gagal → ClaimValidationError
//!   └─ Validasi sukses
//!       ├─ Storage receipt → ImmediateReward
//!       └─ Compute receipt → ChallengePeriodStarted
//! ```
//!
//! ## Economic Invariant
//!
//! `RewardDistribution` menjamin:
//! `node_reward + validator_reward + treasury_reward == reward_base`
//!
//! Treasury menyerap sisa pembulatan integer division.

use crate::anti_self_dealing::SelfDealingViolation;
use crate::economic_constants::{
    REWARD_NODE_PERCENT, REWARD_TOTAL_PERCENT, REWARD_TREASURY_PERCENT,
    REWARD_VALIDATOR_PERCENT,
};
use std::fmt;

// ════════════════════════════════════════════════════════════════════════════════
// CLAIM VALIDATION ERROR
// ════════════════════════════════════════════════════════════════════════════════

/// Error yang mungkin terjadi saat validasi ClaimReward transaction.
///
/// Setiap variant merepresentasikan satu alasan penolakan.
/// Chain layer menggunakan error ini untuk menolak transaksi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimValidationError {
    /// Threshold signature dari coordinator tidak valid.
    InvalidThresholdSignature,
    /// Ed25519 signature dari node tidak valid.
    InvalidNodeSignature,
    /// Receipt sudah pernah diklaim sebelumnya.
    ReceiptAlreadyClaimed {
        /// Hash dari receipt yang sudah diklaim.
        receipt_hash: [u8; 32],
    },
    /// Receipt sudah expired (melebihi MAX_RECEIPT_AGE_SECS).
    ReceiptExpired {
        /// Usia receipt dalam detik.
        age_secs: u64,
        /// Batas usia maksimum dalam detik.
        max_secs: u64,
    },
    /// Terdeteksi self-dealing antara node dan submitter.
    SelfDealingDetected {
        /// Jenis pelanggaran yang terdeteksi.
        violation: SelfDealingViolation,
    },
    /// Compute receipt tidak memiliki execution commitment.
    MissingExecutionCommitment,
    /// Execution commitment tidak valid (hash mismatch).
    InvalidExecutionCommitment,
    /// Stake node tidak mencukupi untuk klaim reward.
    InsufficientStake {
        /// Stake minimum yang diperlukan.
        required: u128,
        /// Stake aktual node.
        actual: u128,
    },
    /// Reward base di luar range yang valid.
    InvalidRewardBase {
        /// Nilai reward_base yang tidak valid.
        value: u128,
    },
    /// Epoch receipt tidak sesuai dengan epoch saat ini.
    EpochMismatch {
        /// Epoch pada receipt.
        receipt_epoch: u64,
        /// Epoch chain saat ini.
        current_epoch: u64,
    },
}

impl fmt::Display for ClaimValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidThresholdSignature => {
                write!(f, "Invalid threshold signature.")
            }
            Self::InvalidNodeSignature => {
                write!(f, "Invalid node signature.")
            }
            Self::ReceiptAlreadyClaimed { receipt_hash } => {
                write!(
                    f,
                    "Receipt already claimed: hash {}.",
                    hex_display(receipt_hash)
                )
            }
            Self::ReceiptExpired { age_secs, max_secs } => {
                write!(
                    f,
                    "Receipt expired: age {}s exceeds maximum {}s.",
                    age_secs, max_secs
                )
            }
            Self::SelfDealingDetected { violation } => {
                write!(f, "Self-dealing detected: {:?}.", violation)
            }
            Self::MissingExecutionCommitment => {
                write!(f, "Missing execution commitment for compute receipt.")
            }
            Self::InvalidExecutionCommitment => {
                write!(f, "Invalid execution commitment.")
            }
            Self::InsufficientStake { required, actual } => {
                write!(
                    f,
                    "Insufficient stake: required {} but have {}.",
                    required, actual
                )
            }
            Self::InvalidRewardBase { value } => {
                write!(f, "Invalid reward base: {}.", value)
            }
            Self::EpochMismatch {
                receipt_epoch,
                current_epoch,
            } => {
                write!(
                    f,
                    "Epoch mismatch: receipt epoch {} vs current epoch {}.",
                    receipt_epoch, current_epoch
                )
            }
        }
    }
}

impl std::error::Error for ClaimValidationError {}

// ════════════════════════════════════════════════════════════════════════════════
// REWARD DISTRIBUTION
// ════════════════════════════════════════════════════════════════════════════════

/// Distribusi reward berdasarkan split ekonomi DSDN.
///
/// ## Economic Invariant
///
/// `node_reward + validator_reward + treasury_reward == reward_base`
///
/// Treasury menyerap sisa pembulatan integer division
/// untuk menjamin invariant ini selalu terpenuhi.
///
/// ## Normal Split (70/20/10)
///
/// - Node: 70% (`REWARD_NODE_PERCENT`)
/// - Validator: 20% (`REWARD_VALIDATOR_PERCENT`)
/// - Treasury: 10% (`REWARD_TREASURY_PERCENT`)
///
/// ## Anti-Self-Dealing Split (0/20/80)
///
/// - Node: 0% (penalty: reward dialihkan)
/// - Validator: 20% (`REWARD_VALIDATOR_PERCENT`)
/// - Treasury: 80% (`REWARD_NODE_PERCENT + REWARD_TREASURY_PERCENT`)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RewardDistribution {
    /// Reward untuk node yang melakukan kerja.
    pub node_reward: u128,
    /// Reward untuk validator yang memverifikasi.
    pub validator_reward: u128,
    /// Reward untuk treasury.
    pub treasury_reward: u128,
}

impl RewardDistribution {
    /// Menghitung distribusi reward normal (70/20/10).
    ///
    /// Menggunakan constant dari `economic_constants`.
    /// Treasury menyerap sisa pembulatan integer division.
    ///
    /// ## Invariant
    ///
    /// `node_reward + validator_reward + treasury_reward == reward_base`
    ///
    /// ## Caller Contract
    ///
    /// `reward_base` sudah tervalidasi upstream (dalam range valid).
    /// Checked arithmetic digunakan untuk safety.
    /// Jika overflow (seharusnya tidak terjadi dengan input valid),
    /// komponen yang overflow di-set ke 0.
    #[must_use]
    pub fn compute(reward_base: u128) -> Self {
        let node_reward = reward_base
            .checked_mul(REWARD_NODE_PERCENT)
            .and_then(|v| v.checked_div(REWARD_TOTAL_PERCENT))
            .unwrap_or(0);

        let validator_reward = reward_base
            .checked_mul(REWARD_VALIDATOR_PERCENT)
            .and_then(|v| v.checked_div(REWARD_TOTAL_PERCENT))
            .unwrap_or(0);

        // Treasury absorbs remainder to guarantee sum == reward_base.
        let treasury_reward = reward_base - node_reward - validator_reward;

        debug_assert_eq!(
            node_reward + validator_reward + treasury_reward,
            reward_base,
            "reward split invariant violated"
        );

        Self {
            node_reward,
            validator_reward,
            treasury_reward,
        }
    }

    /// Menghitung distribusi reward dengan anti-self-dealing penalty.
    ///
    /// Node reward dialihkan ke treasury.
    ///
    /// ## Split
    ///
    /// - Node: 0%
    /// - Validator: 20% (`REWARD_VALIDATOR_PERCENT`)
    /// - Treasury: 80% (`REWARD_NODE_PERCENT + REWARD_TREASURY_PERCENT`)
    ///
    /// Treasury menyerap sisa pembulatan.
    ///
    /// ## Invariant
    ///
    /// `validator_reward + treasury_reward == reward_base`
    #[must_use]
    pub fn with_anti_self_dealing(reward_base: u128) -> Self {
        let validator_reward = reward_base
            .checked_mul(REWARD_VALIDATOR_PERCENT)
            .and_then(|v| v.checked_div(REWARD_TOTAL_PERCENT))
            .unwrap_or(0);

        // Treasury absorbs node share + treasury share + remainder.
        let treasury_reward = reward_base - validator_reward;

        debug_assert_eq!(
            validator_reward + treasury_reward,
            reward_base,
            "anti-self-dealing split invariant violated"
        );

        Self {
            node_reward: 0,
            validator_reward,
            treasury_reward,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// CLAIM VALIDATION RESULT
// ════════════════════════════════════════════════════════════════════════════════

/// Hasil validasi ClaimReward yang sukses.
///
/// ## Decision Tree
///
/// - Storage receipt → `ImmediateReward`: reward langsung didistribusikan.
/// - Compute receipt → `ChallengePeriodStarted`: reward ditahan sampai
///   challenge period berakhir tanpa fraud proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimValidationResult {
    /// Storage receipt: reward langsung didistribusikan.
    ImmediateReward {
        /// Distribusi reward (70/20/10 atau 0/20/80).
        distribution: RewardDistribution,
    },
    /// Compute receipt: challenge period dimulai.
    ChallengePeriodStarted {
        /// Hash dari receipt yang di-challenge.
        receipt_hash: [u8; 32],
        /// Unix timestamp berakhirnya challenge period.
        challenge_end: u64,
        /// Distribusi reward yang akan diterapkan jika tidak ada fraud proof.
        pending_distribution: RewardDistribution,
    },
}

// ════════════════════════════════════════════════════════════════════════════════
// INTERNAL HELPERS
// ════════════════════════════════════════════════════════════════════════════════

/// Hex display helper for [u8; 32] tanpa dependency tambahan.
fn hex_display(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── 1. COMPUTE SPLIT CORRECT ────────────────────────────────────────

    #[test]
    fn test_compute_split_correct() {
        let d = RewardDistribution::compute(1000);
        assert_eq!(d.node_reward, 700);
        assert_eq!(d.validator_reward, 200);
        assert_eq!(d.treasury_reward, 100);
    }

    // ── 2. COMPUTE SPLIT SUM EQUALS BASE ────────────────────────────────

    #[test]
    fn test_compute_split_sum_equals_base() {
        for base in [0, 1, 2, 3, 7, 10, 99, 100, 101, 999, 1000, 10_000, 1_000_000] {
            let d = RewardDistribution::compute(base);
            assert_eq!(
                d.node_reward + d.validator_reward + d.treasury_reward,
                base,
                "sum invariant failed for base={}",
                base
            );
        }
    }

    // ── 3. ANTI-SELF-DEALING SPLIT CORRECT ──────────────────────────────

    #[test]
    fn test_with_anti_self_dealing_split_correct() {
        let d = RewardDistribution::with_anti_self_dealing(1000);
        assert_eq!(d.node_reward, 0);
        assert_eq!(d.validator_reward, 200);
        assert_eq!(d.treasury_reward, 800);
    }

    // ── 4. ANTI-SELF-DEALING SUM EQUALS BASE ────────────────────────────

    #[test]
    fn test_with_anti_self_dealing_sum_equals_base() {
        for base in [0, 1, 2, 3, 7, 10, 99, 100, 101, 999, 1000, 10_000, 1_000_000] {
            let d = RewardDistribution::with_anti_self_dealing(base);
            assert_eq!(
                d.node_reward + d.validator_reward + d.treasury_reward,
                base,
                "anti-self-dealing sum invariant failed for base={}",
                base
            );
            assert_eq!(d.node_reward, 0, "node must be 0 for base={}", base);
        }
    }

    // ── 5. ZERO REWARD BASE ─────────────────────────────────────────────

    #[test]
    fn test_zero_reward_base() {
        let d = RewardDistribution::compute(0);
        assert_eq!(d.node_reward, 0);
        assert_eq!(d.validator_reward, 0);
        assert_eq!(d.treasury_reward, 0);

        let d = RewardDistribution::with_anti_self_dealing(0);
        assert_eq!(d.node_reward, 0);
        assert_eq!(d.validator_reward, 0);
        assert_eq!(d.treasury_reward, 0);
    }

    // ── 6. LARGE REWARD BASE ────────────────────────────────────────────

    #[test]
    fn test_large_reward_base_near_max() {
        // MAX_REWARD_BASE from economic_constants
        let base: u128 = 1_000_000_000_000;
        let d = RewardDistribution::compute(base);
        assert_eq!(d.node_reward, 700_000_000_000);
        assert_eq!(d.validator_reward, 200_000_000_000);
        assert_eq!(d.treasury_reward, 100_000_000_000);
        assert_eq!(d.node_reward + d.validator_reward + d.treasury_reward, base);

        let d = RewardDistribution::with_anti_self_dealing(base);
        assert_eq!(d.node_reward, 0);
        assert_eq!(d.validator_reward, 200_000_000_000);
        assert_eq!(d.treasury_reward, 800_000_000_000);
        assert_eq!(d.node_reward + d.validator_reward + d.treasury_reward, base);
    }

    // ── 7. DISPLAY FORMAT — RECEIPT EXPIRED ─────────────────────────────

    #[test]
    fn test_display_error_format_receipt_expired() {
        let err = ClaimValidationError::ReceiptExpired {
            age_secs: 90000,
            max_secs: 86400,
        };
        let msg = format!("{}", err);
        assert_eq!(msg, "Receipt expired: age 90000s exceeds maximum 86400s.");
    }

    // ── 8. DISPLAY FORMAT — SELF DEALING ────────────────────────────────

    #[test]
    fn test_display_error_format_self_dealing() {
        let err = ClaimValidationError::SelfDealingDetected {
            violation: SelfDealingViolation::DirectMatch,
        };
        let msg = format!("{}", err);
        assert_eq!(msg, "Self-dealing detected: DirectMatch.");
    }

    // ── ADDITIONAL TESTS ────────────────────────────────────────────────

    #[test]
    fn test_display_all_variants() {
        let cases: Vec<ClaimValidationError> = vec![
            ClaimValidationError::InvalidThresholdSignature,
            ClaimValidationError::InvalidNodeSignature,
            ClaimValidationError::ReceiptAlreadyClaimed {
                receipt_hash: [0xAB; 32],
            },
            ClaimValidationError::ReceiptExpired {
                age_secs: 100,
                max_secs: 50,
            },
            ClaimValidationError::SelfDealingDetected {
                violation: SelfDealingViolation::WalletAffinityMatch,
            },
            ClaimValidationError::MissingExecutionCommitment,
            ClaimValidationError::InvalidExecutionCommitment,
            ClaimValidationError::InsufficientStake {
                required: 1000,
                actual: 500,
            },
            ClaimValidationError::InvalidRewardBase { value: 0 },
            ClaimValidationError::EpochMismatch {
                receipt_epoch: 10,
                current_epoch: 12,
            },
        ];

        for err in &cases {
            let msg = format!("{}", err);
            assert!(!msg.is_empty(), "display must not be empty");
            assert!(
                !msg.contains('\n'),
                "display must not contain newline: {}",
                msg
            );
        }
    }

    #[test]
    fn test_rounding_remainder_goes_to_treasury() {
        // 7 * 70 / 100 = 4 (truncated from 4.9)
        // 7 * 20 / 100 = 1 (truncated from 1.4)
        // treasury = 7 - 4 - 1 = 2 (absorbs 0.3 remainder)
        let d = RewardDistribution::compute(7);
        assert_eq!(d.node_reward, 4);
        assert_eq!(d.validator_reward, 1);
        assert_eq!(d.treasury_reward, 2);
        assert_eq!(d.node_reward + d.validator_reward + d.treasury_reward, 7);
    }

    #[test]
    fn test_anti_self_dealing_rounding() {
        // 7 * 20 / 100 = 1
        // treasury = 7 - 1 = 6
        let d = RewardDistribution::with_anti_self_dealing(7);
        assert_eq!(d.node_reward, 0);
        assert_eq!(d.validator_reward, 1);
        assert_eq!(d.treasury_reward, 6);
        assert_eq!(d.node_reward + d.validator_reward + d.treasury_reward, 7);
    }

    #[test]
    fn test_reward_distribution_is_copy() {
        let d = RewardDistribution::compute(1000);
        let d2 = d;
        assert_eq!(d, d2);
    }

    #[test]
    fn test_claim_validation_result_variants() {
        let dist = RewardDistribution::compute(1000);

        let r1 = ClaimValidationResult::ImmediateReward {
            distribution: dist,
        };
        let dbg = format!("{:?}", r1);
        assert!(dbg.contains("ImmediateReward"));

        let r2 = ClaimValidationResult::ChallengePeriodStarted {
            receipt_hash: [0x01; 32],
            challenge_end: 4600,
            pending_distribution: dist,
        };
        let dbg = format!("{:?}", r2);
        assert!(dbg.contains("ChallengePeriodStarted"));
    }

    #[test]
    fn test_error_implements_std_error() {
        let err: Box<dyn std::error::Error> =
            Box::new(ClaimValidationError::InvalidThresholdSignature);
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn test_display_insufficient_stake() {
        let err = ClaimValidationError::InsufficientStake {
            required: 1000,
            actual: 500,
        };
        let msg = format!("{}", err);
        assert_eq!(msg, "Insufficient stake: required 1000 but have 500.");
    }

    #[test]
    fn test_display_epoch_mismatch() {
        let err = ClaimValidationError::EpochMismatch {
            receipt_epoch: 10,
            current_epoch: 12,
        };
        let msg = format!("{}", err);
        assert_eq!(
            msg,
            "Epoch mismatch: receipt epoch 10 vs current epoch 12."
        );
    }
}