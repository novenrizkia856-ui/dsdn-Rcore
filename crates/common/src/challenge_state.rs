//! # Challenge Period State Types
//!
//! Shared state types untuk tracking Challenge Period pada Compute receipt.
//!
//! ## State Machine
//!
//! ```text
//! Pending
//!   ├──(no challenge + expired)→ Cleared
//!   └──(fraud proof submitted)→ Challenged
//!                                   └──(fraud proven)→ Slashed
//! ```
//!
//! ## Valid Transitions
//!
//! | From | To | Trigger |
//! |------|----|---------|
//! | Pending | Cleared | Challenge period expired tanpa fraud proof |
//! | Pending | Challenged | Fraud proof submitted |
//! | Challenged | Slashed | Fraud terbukti valid |
//!
//! ## Invalid Transitions (ditolak)
//!
//! - Cleared → anything
//! - Slashed → anything
//! - Challenged → Cleared
//! - Pending → Slashed (langsung, tanpa Challenged)
//!
//! ## Usage
//!
//! - Storage receipt TIDAK menggunakan challenge period.
//! - Compute receipt menggunakan `PendingChallenge`.

use crate::claim_validation::RewardDistribution;
use crate::coordinator::NodeId;
use crate::economic_constants::CHALLENGE_PERIOD_SECS;
use crate::receipt_v1::Address;

// ════════════════════════════════════════════════════════════════════════════════
// CHALLENGE STATUS
// ════════════════════════════════════════════════════════════════════════════════

/// Status dari challenge period.
///
/// Merepresentasikan node di state machine:
///
/// ```text
/// Pending → Cleared
/// Pending → Challenged → Slashed
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeStatus {
    /// Challenge period aktif, belum ada fraud proof.
    Pending,
    /// Fraud proof telah disubmit, menunggu resolusi.
    Challenged,
    /// Challenge period berakhir tanpa fraud proof. Reward dapat diklaim.
    Cleared,
    /// Fraud terbukti valid. Node reward di-slash.
    Slashed,
}

// ════════════════════════════════════════════════════════════════════════════════
// PENDING CHALLENGE
// ════════════════════════════════════════════════════════════════════════════════

/// State tracking untuk satu challenge period pada Compute receipt.
///
/// Dibuat saat ClaimReward transaction untuk Compute receipt berhasil divalidasi.
/// Reward ditahan sampai challenge period berakhir atau fraud proof diajukan.
///
/// ## Invariants
///
/// - `challenge_end == challenge_start + CHALLENGE_PERIOD_SECS`
/// - `status` hanya dapat bertransisi sesuai state machine
/// - `challenger` hanya di-set saat transisi Pending → Challenged
/// - `reward_distribution` tidak berubah setelah konstruksi
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingChallenge {
    /// Hash dari receipt yang sedang di-challenge.
    pub receipt_hash: [u8; 32],
    /// Node yang melakukan kerja.
    pub node_id: NodeId,
    /// Distribusi reward yang akan diterapkan jika cleared.
    pub reward_distribution: RewardDistribution,
    /// Unix timestamp saat challenge period dimulai.
    pub challenge_start: u64,
    /// Unix timestamp saat challenge period berakhir.
    pub challenge_end: u64,
    /// Status challenge saat ini.
    pub status: ChallengeStatus,
    /// Address pihak yang mengajukan fraud proof (jika ada).
    pub challenger: Option<Address>,
}

impl PendingChallenge {
    /// Membuat `PendingChallenge` baru.
    ///
    /// - `challenge_end` dihitung dari `start + CHALLENGE_PERIOD_SECS`.
    /// - Menggunakan `checked_add` untuk overflow safety.
    /// - Jika overflow, `challenge_end` di-set ke `start` (sama behavior
    ///   dengan `challenge_end_time()` di `economic_constants`).
    /// - Initial status: `Pending`, challenger: `None`.
    ///
    /// # Arguments
    ///
    /// * `receipt_hash` - Hash dari receipt
    /// * `node_id` - Node identifier
    /// * `distribution` - Distribusi reward yang sudah dihitung
    /// * `start` - Unix timestamp awal challenge period
    #[must_use]
    pub fn new(
        receipt_hash: [u8; 32],
        node_id: NodeId,
        distribution: RewardDistribution,
        start: u64,
    ) -> Self {
        let challenge_end = start.checked_add(CHALLENGE_PERIOD_SECS).unwrap_or(start);

        debug_assert!(
            challenge_end >= start,
            "challenge_end must be >= start"
        );

        Self {
            receipt_hash,
            node_id,
            reward_distribution: distribution,
            challenge_start: start,
            challenge_end,
            status: ChallengeStatus::Pending,
            challenger: None,
        }
    }

    /// Memeriksa apakah challenge period sudah expired.
    ///
    /// Return `true` jika `now >= challenge_end`.
    ///
    /// Deterministik. Tidak panic.
    #[must_use]
    #[inline]
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.challenge_end
    }

    /// Memeriksa apakah challenge masih bisa diajukan.
    ///
    /// Return `true` hanya jika:
    /// - `status == Pending`
    /// - `now < challenge_end` (belum expired)
    ///
    /// Deterministik. Tidak panic.
    #[must_use]
    #[inline]
    pub fn can_be_challenged(&self, now: u64) -> bool {
        self.status == ChallengeStatus::Pending && now < self.challenge_end
    }

    /// Transisi: Pending → Challenged.
    ///
    /// Set status menjadi `Challenged` dan menyimpan address challenger.
    ///
    /// ## Precondition
    ///
    /// `status` HARUS `Pending`. Jika bukan `Pending`,
    /// transisi ditolak (no-op).
    pub fn mark_challenged(&mut self, challenger_address: Address) {
        if self.status != ChallengeStatus::Pending {
            return;
        }

        self.status = ChallengeStatus::Challenged;
        self.challenger = Some(challenger_address);
    }

    /// Transisi: Pending → Cleared.
    ///
    /// Challenge period berakhir tanpa fraud proof.
    /// Reward dapat didistribusikan ke node.
    ///
    /// ## Precondition
    ///
    /// `status` HARUS `Pending`. Jika bukan `Pending`,
    /// transisi ditolak (no-op).
    pub fn mark_cleared(&mut self) {
        if self.status != ChallengeStatus::Pending {
            return;
        }

        self.status = ChallengeStatus::Cleared;
    }

    /// Transisi: Challenged → Slashed.
    ///
    /// Fraud proof terbukti valid. Node reward di-slash.
    ///
    /// ## Precondition
    ///
    /// `status` HARUS `Challenged`. Jika bukan `Challenged`,
    /// transisi ditolak (no-op).
    pub fn mark_slashed(&mut self) {
        if self.status != ChallengeStatus::Challenged {
            return;
        }

        self.status = ChallengeStatus::Slashed;
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_HASH: [u8; 32] = [0xAB; 32];
    const TEST_NODE: NodeId = [0x01; 32];
    const TEST_CHALLENGER: Address = [0x02; 20];
    const START: u64 = 1_700_000_000;

    fn make_pending() -> PendingChallenge {
        let dist = RewardDistribution::compute(1000);
        PendingChallenge::new(TEST_HASH, TEST_NODE, dist, START)
    }

    // ── 1. NEW SETS CORRECT END TIME ────────────────────────────────────

    #[test]
    fn test_new_sets_correct_end_time() {
        let pc = make_pending();
        assert_eq!(pc.challenge_start, START);
        assert_eq!(pc.challenge_end, START + CHALLENGE_PERIOD_SECS);
        assert_eq!(pc.status, ChallengeStatus::Pending);
        assert_eq!(pc.challenger, None);
        assert_eq!(pc.receipt_hash, TEST_HASH);
        assert_eq!(pc.node_id, TEST_NODE);
    }

    // ── 2. IS_EXPIRED FALSE BEFORE END ──────────────────────────────────

    #[test]
    fn test_is_expired_false_before_end() {
        let pc = make_pending();
        assert!(!pc.is_expired(START));
        assert!(!pc.is_expired(START + CHALLENGE_PERIOD_SECS - 1));
    }

    // ── 3. IS_EXPIRED TRUE AFTER END ────────────────────────────────────

    #[test]
    fn test_is_expired_true_after_end() {
        let pc = make_pending();
        assert!(pc.is_expired(START + CHALLENGE_PERIOD_SECS));
        assert!(pc.is_expired(START + CHALLENGE_PERIOD_SECS + 1));
        assert!(pc.is_expired(u64::MAX));
    }

    // ── 4. CAN BE CHALLENGED WHEN PENDING AND NOT EXPIRED ──────────────

    #[test]
    fn test_can_be_challenged_true_when_pending_and_not_expired() {
        let pc = make_pending();
        assert!(pc.can_be_challenged(START));
        assert!(pc.can_be_challenged(START + CHALLENGE_PERIOD_SECS - 1));
    }

    // ── 5. CAN BE CHALLENGED FALSE WHEN EXPIRED ────────────────────────

    #[test]
    fn test_can_be_challenged_false_when_expired() {
        let pc = make_pending();
        assert!(!pc.can_be_challenged(START + CHALLENGE_PERIOD_SECS));
        assert!(!pc.can_be_challenged(START + CHALLENGE_PERIOD_SECS + 1));
    }

    // ── 6. PENDING → CHALLENGED ─────────────────────────────────────────

    #[test]
    fn test_pending_to_challenged_transition() {
        let mut pc = make_pending();
        assert_eq!(pc.status, ChallengeStatus::Pending);
        assert_eq!(pc.challenger, None);

        pc.mark_challenged(TEST_CHALLENGER);

        assert_eq!(pc.status, ChallengeStatus::Challenged);
        assert_eq!(pc.challenger, Some(TEST_CHALLENGER));
    }

    // ── 7. PENDING → CLEARED ────────────────────────────────────────────

    #[test]
    fn test_pending_to_cleared_transition() {
        let mut pc = make_pending();
        assert_eq!(pc.status, ChallengeStatus::Pending);

        pc.mark_cleared();

        assert_eq!(pc.status, ChallengeStatus::Cleared);
        assert_eq!(pc.challenger, None);
    }

    // ── 8. CHALLENGED → SLASHED ─────────────────────────────────────────

    #[test]
    fn test_challenged_to_slashed_transition() {
        let mut pc = make_pending();
        pc.mark_challenged(TEST_CHALLENGER);
        assert_eq!(pc.status, ChallengeStatus::Challenged);

        pc.mark_slashed();

        assert_eq!(pc.status, ChallengeStatus::Slashed);
        assert_eq!(pc.challenger, Some(TEST_CHALLENGER));
    }

    // ── 9. INVALID: PENDING → SLASHED (DIRECT) ─────────────────────────

    #[test]
    fn test_invalid_transition_pending_to_slashed_rejected() {
        let mut pc = make_pending();
        assert_eq!(pc.status, ChallengeStatus::Pending);

        pc.mark_slashed(); // Invalid: Pending → Slashed

        // Status must remain Pending (transition rejected).
        assert_eq!(pc.status, ChallengeStatus::Pending);
    }

    // ── 10. INVALID: CLEARED → NO FURTHER TRANSITION ────────────────────

    #[test]
    fn test_invalid_transition_cleared_no_further_transition() {
        let mut pc = make_pending();
        pc.mark_cleared();
        assert_eq!(pc.status, ChallengeStatus::Cleared);

        // Try all transitions from Cleared — all must be rejected.
        pc.mark_challenged(TEST_CHALLENGER);
        assert_eq!(pc.status, ChallengeStatus::Cleared);
        assert_eq!(pc.challenger, None);

        pc.mark_cleared();
        assert_eq!(pc.status, ChallengeStatus::Cleared);

        pc.mark_slashed();
        assert_eq!(pc.status, ChallengeStatus::Cleared);
    }

    // ── ADDITIONAL: SLASHED → NO FURTHER TRANSITION ─────────────────────

    #[test]
    fn test_slashed_no_further_transition() {
        let mut pc = make_pending();
        pc.mark_challenged(TEST_CHALLENGER);
        pc.mark_slashed();
        assert_eq!(pc.status, ChallengeStatus::Slashed);

        pc.mark_challenged([0xFF; 20]);
        assert_eq!(pc.status, ChallengeStatus::Slashed);
        assert_eq!(pc.challenger, Some(TEST_CHALLENGER)); // Not overwritten.

        pc.mark_cleared();
        assert_eq!(pc.status, ChallengeStatus::Slashed);

        pc.mark_slashed();
        assert_eq!(pc.status, ChallengeStatus::Slashed);
    }

    // ── ADDITIONAL: CHALLENGED → CLEARED REJECTED ───────────────────────

    #[test]
    fn test_challenged_to_cleared_rejected() {
        let mut pc = make_pending();
        pc.mark_challenged(TEST_CHALLENGER);
        assert_eq!(pc.status, ChallengeStatus::Challenged);

        pc.mark_cleared(); // Invalid: Challenged → Cleared

        assert_eq!(pc.status, ChallengeStatus::Challenged);
    }

    // ── ADDITIONAL: CAN'T BE CHALLENGED WHEN NOT PENDING ────────────────

    #[test]
    fn test_can_be_challenged_false_when_not_pending() {
        let mut pc = make_pending();
        pc.mark_challenged(TEST_CHALLENGER);
        assert!(!pc.can_be_challenged(START));

        let mut pc2 = make_pending();
        pc2.mark_cleared();
        assert!(!pc2.can_be_challenged(START));
    }

    // ── ADDITIONAL: OVERFLOW IN CONSTRUCTOR ──────────────────────────────

    #[test]
    fn test_new_overflow_challenge_end() {
        let dist = RewardDistribution::compute(1000);
        let pc = PendingChallenge::new(TEST_HASH, TEST_NODE, dist, u64::MAX);
        // Overflow → challenge_end == start
        assert_eq!(pc.challenge_end, u64::MAX);
        assert_eq!(pc.challenge_start, u64::MAX);
    }

    // ── ADDITIONAL: DISTRIBUTION NOT MODIFIED ───────────────────────────

    #[test]
    fn test_distribution_preserved() {
        let dist = RewardDistribution::compute(1000);
        let mut pc = PendingChallenge::new(TEST_HASH, TEST_NODE, dist, START);

        assert_eq!(pc.reward_distribution, dist);

        pc.mark_challenged(TEST_CHALLENGER);
        assert_eq!(pc.reward_distribution, dist);

        pc.mark_slashed();
        assert_eq!(pc.reward_distribution, dist);
    }

    // ── ADDITIONAL: CHALLENGER NOT OVERWRITTEN ──────────────────────────

    #[test]
    fn test_challenger_not_overwritten_on_second_call() {
        let mut pc = make_pending();
        pc.mark_challenged(TEST_CHALLENGER);
        assert_eq!(pc.challenger, Some(TEST_CHALLENGER));

        // Second call is no-op (status is Challenged, not Pending).
        pc.mark_challenged([0xFF; 20]);
        assert_eq!(pc.challenger, Some(TEST_CHALLENGER));
    }

    // ── ADDITIONAL: CLONE AND DEBUG ─────────────────────────────────────

    #[test]
    fn test_clone_and_debug() {
        let pc = make_pending();
        let pc2 = pc.clone();
        assert_eq!(pc, pc2);

        let dbg = format!("{:?}", pc);
        assert!(dbg.contains("PendingChallenge"));
        assert!(dbg.contains("Pending"));
    }

    // ── ADDITIONAL: CHALLENGE STATUS COPY ───────────────────────────────

    #[test]
    fn test_challenge_status_copy() {
        let s = ChallengeStatus::Pending;
        let s2 = s;
        assert_eq!(s, s2);
    }
}