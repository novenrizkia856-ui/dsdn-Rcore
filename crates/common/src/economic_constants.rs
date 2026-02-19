//! # Economic Constants & Challenge Period
//!
//! Modul ini adalah **single source of truth** untuk konstanta ekonomi
//! lintas crate dalam DSDN.
//!
//! Semua crate (chain, coordinator, proto) HARUS mereferensikan
//! konstanta dari modul ini, bukan mendefinisikan ulang.

// ════════════════════════════════════════════════════════════════════════════════
// REWARD DISTRIBUTION
// ════════════════════════════════════════════════════════════════════════════════

/// Reward distribution constants.
/// Harus identik dengan chain/tokenomics.rs.
/// REWARD_TOTAL_PERCENT harus selalu 100.
/// Perubahan di sini harus sinkron dengan chain layer.
/// Referensi: Spec 13.9 (Reward Flow)

/// Persentase reward untuk node yang melakukan kerja (70%).
pub const REWARD_NODE_PERCENT: u128 = 70;

/// Persentase reward untuk validator yang memverifikasi (20%).
pub const REWARD_VALIDATOR_PERCENT: u128 = 20;

/// Persentase reward untuk treasury (10%).
pub const REWARD_TREASURY_PERCENT: u128 = 10;

/// Total persentase reward. HARUS selalu 100.
pub const REWARD_TOTAL_PERCENT: u128 = 100;

// ════════════════════════════════════════════════════════════════════════════════
// CHALLENGE PERIOD
// ════════════════════════════════════════════════════════════════════════════════

/// Challenge period constants.
/// Compute receipt memiliki 1-hour fraud window.
/// Referensi: Spec 13.10 (Fraud Proof & Challenge)

/// Durasi challenge period dalam detik (1 jam = 3600 detik).
pub const CHALLENGE_PERIOD_SECS: u64 = 3600;

/// Durasi challenge period dalam jumlah block (~10 detik per block).
pub const CHALLENGE_PERIOD_BLOCKS: u64 = 360;

// ════════════════════════════════════════════════════════════════════════════════
// RECEIPT CONSTRAINTS
// ════════════════════════════════════════════════════════════════════════════════

/// Receipt constraints.
/// Membatasi replay dan overflow.
/// Spec 13.9.4

/// Usia maksimum receipt yang valid dalam detik (24 jam = 86400 detik).
pub const MAX_RECEIPT_AGE_SECS: u64 = 86400;

/// Nilai minimum reward_base yang valid.
pub const MIN_REWARD_BASE: u128 = 1;

/// Nilai maksimum reward_base yang valid.
pub const MAX_REWARD_BASE: u128 = 1_000_000_000_000;

// ════════════════════════════════════════════════════════════════════════════════
// ANTI-SELF-DEALING
// ════════════════════════════════════════════════════════════════════════════════

/// Anti-self-dealing.
/// Digunakan untuk mendeteksi wallet affinity.
/// Spec 13.11

/// Jumlah block lookback untuk deteksi wallet affinity.
pub const WALLET_AFFINITY_LOOKBACK: u64 = 100;

// ════════════════════════════════════════════════════════════════════════════════
// FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════════

/// Menghitung waktu berakhirnya challenge period.
///
/// `start + CHALLENGE_PERIOD_SECS`.
///
/// Jika terjadi overflow, mengembalikan `start` (tidak panic).
///
/// # Arguments
///
/// * `start` - Unix timestamp awal challenge period.
///
/// # Returns
///
/// Unix timestamp akhir challenge period, atau `start` jika overflow.
#[must_use]
#[inline]
pub const fn challenge_end_time(start: u64) -> u64 {
    match start.checked_add(CHALLENGE_PERIOD_SECS) {
        Some(end) => end,
        None => start,
    }
}

/// Memeriksa apakah challenge period sudah expired.
///
/// Expired jika `now >= challenge_end_time(start)`.
///
/// Deterministik. Tidak panic. Tidak unwrap.
///
/// # Arguments
///
/// * `start` - Unix timestamp awal challenge period.
/// * `now` - Unix timestamp saat ini.
///
/// # Returns
///
/// `true` jika challenge period sudah berakhir.
#[must_use]
#[inline]
pub const fn is_challenge_expired(start: u64, now: u64) -> bool {
    now >= challenge_end_time(start)
}

/// Memeriksa apakah receipt sudah expired berdasarkan usianya.
///
/// Expired jika `now >= receipt_ts + MAX_RECEIPT_AGE_SECS`.
///
/// Jika `receipt_ts + MAX_RECEIPT_AGE_SECS` overflow, dianggap expired.
///
/// Tidak boleh asumsi timestamp valid. Tidak boleh silent overflow.
///
/// # Arguments
///
/// * `receipt_ts` - Unix timestamp saat receipt dibuat.
/// * `now` - Unix timestamp saat ini.
///
/// # Returns
///
/// `true` jika receipt sudah melewati batas usia maksimum.
#[must_use]
#[inline]
pub const fn is_receipt_expired(receipt_ts: u64, now: u64) -> bool {
    match receipt_ts.checked_add(MAX_RECEIPT_AGE_SECS) {
        Some(expiry) => now >= expiry,
        None => true, // overflow → dianggap expired
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── CONSTANT VALUES ─────────────────────────────────────────────────

    #[test]
    fn reward_percentages_sum_to_100() {
        assert_eq!(
            REWARD_NODE_PERCENT + REWARD_VALIDATOR_PERCENT + REWARD_TREASURY_PERCENT,
            REWARD_TOTAL_PERCENT
        );
    }

    #[test]
    fn reward_total_is_100() {
        assert_eq!(REWARD_TOTAL_PERCENT, 100);
    }

    #[test]
    fn reward_node_is_70() {
        assert_eq!(REWARD_NODE_PERCENT, 70);
    }

    #[test]
    fn reward_validator_is_20() {
        assert_eq!(REWARD_VALIDATOR_PERCENT, 20);
    }

    #[test]
    fn reward_treasury_is_10() {
        assert_eq!(REWARD_TREASURY_PERCENT, 10);
    }

    #[test]
    fn challenge_period_secs_is_3600() {
        assert_eq!(CHALLENGE_PERIOD_SECS, 3600);
    }

    #[test]
    fn challenge_period_blocks_is_360() {
        assert_eq!(CHALLENGE_PERIOD_BLOCKS, 360);
    }

    #[test]
    fn max_receipt_age_is_86400() {
        assert_eq!(MAX_RECEIPT_AGE_SECS, 86400);
    }

    #[test]
    fn min_reward_base_is_1() {
        assert_eq!(MIN_REWARD_BASE, 1);
    }

    #[test]
    fn max_reward_base_is_1_trillion() {
        assert_eq!(MAX_REWARD_BASE, 1_000_000_000_000);
    }

    #[test]
    fn wallet_affinity_lookback_is_100() {
        assert_eq!(WALLET_AFFINITY_LOOKBACK, 100);
    }

    // ── challenge_end_time ──────────────────────────────────────────────

    #[test]
    fn challenge_end_time_normal() {
        assert_eq!(challenge_end_time(1000), 1000 + CHALLENGE_PERIOD_SECS);
    }

    #[test]
    fn challenge_end_time_zero() {
        assert_eq!(challenge_end_time(0), CHALLENGE_PERIOD_SECS);
    }

    #[test]
    fn challenge_end_time_overflow_returns_start() {
        assert_eq!(challenge_end_time(u64::MAX), u64::MAX);
    }

    #[test]
    fn challenge_end_time_near_max_no_overflow() {
        let start = u64::MAX - CHALLENGE_PERIOD_SECS;
        assert_eq!(challenge_end_time(start), u64::MAX);
    }

    #[test]
    fn challenge_end_time_near_max_overflow() {
        let start = u64::MAX - CHALLENGE_PERIOD_SECS + 1;
        assert_eq!(challenge_end_time(start), start);
    }

    // ── is_challenge_expired ────────────────────────────────────────────

    #[test]
    fn challenge_not_expired_before_end() {
        assert!(!is_challenge_expired(1000, 1000 + CHALLENGE_PERIOD_SECS - 1));
    }

    #[test]
    fn challenge_expired_at_end() {
        assert!(is_challenge_expired(1000, 1000 + CHALLENGE_PERIOD_SECS));
    }

    #[test]
    fn challenge_expired_after_end() {
        assert!(is_challenge_expired(1000, 1000 + CHALLENGE_PERIOD_SECS + 1));
    }

    #[test]
    fn challenge_not_expired_at_start() {
        assert!(!is_challenge_expired(1000, 1000));
    }

    #[test]
    fn challenge_overflow_start_is_expired_at_max() {
        // overflow → end = start → now (u64::MAX) >= start → expired
        assert!(is_challenge_expired(u64::MAX, u64::MAX));
    }

    // ── is_receipt_expired ──────────────────────────────────────────────

    #[test]
    fn receipt_not_expired_within_age() {
        assert!(!is_receipt_expired(1000, 1000 + MAX_RECEIPT_AGE_SECS - 1));
    }

    #[test]
    fn receipt_expired_at_age_limit() {
        assert!(is_receipt_expired(1000, 1000 + MAX_RECEIPT_AGE_SECS));
    }

    #[test]
    fn receipt_expired_past_age_limit() {
        assert!(is_receipt_expired(1000, 1000 + MAX_RECEIPT_AGE_SECS + 1));
    }

    #[test]
    fn receipt_not_expired_same_timestamp() {
        assert!(!is_receipt_expired(1000, 1000));
    }

    #[test]
    fn receipt_overflow_is_expired() {
        assert!(is_receipt_expired(u64::MAX, u64::MAX));
    }

    #[test]
    fn receipt_overflow_near_max() {
        assert!(is_receipt_expired(u64::MAX - 1, 0));
    }

    #[test]
    fn receipt_zero_timestamps() {
        assert!(!is_receipt_expired(0, 0));
    }

    #[test]
    fn receipt_zero_ts_expired_at_max_age() {
        assert!(is_receipt_expired(0, MAX_RECEIPT_AGE_SECS));
    }
}