//! # Receipt Dedup Helper
//!
//! Helper untuk mendeteksi reuse/double-claim Receipt.
//!
//! Memastikan satu `receipt_hash` hanya bisa diklaim SATU kali.
//! Double claim langsung ditolak dengan error deterministik.
//!
//! ## Thread Safety
//!
//! - Chain state saat ini single-threaded.
//! - Jika digunakan di multi-threaded context,
//!   harus dibungkus dalam `Mutex` atau `RwLock`.
//! - `HashSet` sendiri tidak thread-safe untuk concurrent mutation.
//! - Tidak ada interior mutability.
//!
//! ## Memory Consideration
//!
//! - `HashSet` growth O(n) terhadap jumlah receipt yang diklaim.
//! - Receipt prune penting untuk mencegah unbounded memory growth.
//! - Expected lifetime bounded oleh `MAX_RECEIPT_AGE_SECS` (24 jam).
//! - Caller bertanggung jawab memanggil `prune_before()` secara periodik.

use std::collections::HashSet;

use crate::claim_validation::ClaimValidationError;

// ════════════════════════════════════════════════════════════════════════════════
// STRUCT
// ════════════════════════════════════════════════════════════════════════════════

/// Tracker untuk mendeteksi double-claim receipt.
///
/// Menyimpan set `receipt_hash` yang sudah diklaim.
/// Menolak duplikat dengan `ClaimValidationError::ReceiptAlreadyClaimed`.
///
/// ## Invariants
///
/// - Setiap `receipt_hash` hanya bisa ada satu kali dalam set.
/// - `mark_claimed()` menambah size tepat 1 jika sukses.
/// - `mark_claimed()` tidak mengubah size jika duplicate.
/// - Tidak ada silent overwrite.
#[derive(Debug, Clone)]
pub struct ReceiptDedupTracker {
    claimed: HashSet<[u8; 32]>,
}

impl ReceiptDedupTracker {
    /// Membuat tracker baru yang kosong.
    ///
    /// Set langsung diinisialisasi (tidak lazy-init, tidak Option).
    #[must_use]
    pub fn new() -> Self {
        Self {
            claimed: HashSet::new(),
        }
    }

    /// Memeriksa apakah `receipt_hash` sudah pernah diklaim.
    ///
    /// Return `true` jika sudah ada di set.
    ///
    /// Tidak clone. Tidak panic. Tidak unwrap.
    #[must_use]
    #[inline]
    pub fn is_claimed(&self, receipt_hash: &[u8; 32]) -> bool {
        self.claimed.contains(receipt_hash)
    }

    /// Menandai `receipt_hash` sebagai sudah diklaim.
    ///
    /// ## Success
    ///
    /// Jika `receipt_hash` belum ada: insert ke set, return `Ok(())`.
    ///
    /// ## Error
    ///
    /// Jika `receipt_hash` sudah ada: return
    /// `Err(ClaimValidationError::ReceiptAlreadyClaimed { receipt_hash })`.
    ///
    /// Tidak ada overwrite. Tidak ada silent ignore. Tidak panic.
    pub fn mark_claimed(
        &mut self,
        receipt_hash: [u8; 32],
    ) -> Result<(), ClaimValidationError> {
        if !self.claimed.insert(receipt_hash) {
            return Err(ClaimValidationError::ReceiptAlreadyClaimed {
                receipt_hash,
            });
        }
        Ok(())
    }

    /// Jumlah receipt yang sudah diklaim.
    #[must_use]
    #[inline]
    pub fn claimed_count(&self) -> usize {
        self.claimed.len()
    }

    /// Menghapus receipt hash yang termasuk dalam `cutoff_hashes`.
    ///
    /// Retain hanya hash yang TIDAK ada dalam `cutoff_hashes`.
    ///
    /// `cutoff_hashes` dianggap authoritative external source
    /// (misalnya hash yang sudah melewati `MAX_RECEIPT_AGE_SECS`).
    /// Tracker tidak tahu timestamp internal.
    ///
    /// Tidak panic. Tidak unwrap.
    pub fn prune_before(&mut self, cutoff_hashes: &HashSet<[u8; 32]>) {
        self.claimed.retain(|h| !cutoff_hashes.contains(h));
    }
}

impl Default for ReceiptDedupTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    const HASH_A: [u8; 32] = [0x01; 32];
    const HASH_B: [u8; 32] = [0x02; 32];
    const HASH_C: [u8; 32] = [0x03; 32];

    // ── 1. NEW TRACKER IS EMPTY ─────────────────────────────────────────

    #[test]
    fn test_new_tracker_is_empty() {
        let tracker = ReceiptDedupTracker::new();
        assert_eq!(tracker.claimed_count(), 0);
        assert!(!tracker.is_claimed(&HASH_A));
    }

    // ── 2. MARK CLAIMED SUCCESS ─────────────────────────────────────────

    #[test]
    fn test_mark_claimed_success() {
        let mut tracker = ReceiptDedupTracker::new();
        let result = tracker.mark_claimed(HASH_A);
        assert!(result.is_ok());
        assert!(tracker.is_claimed(&HASH_A));
    }

    // ── 3. MARK CLAIMED DUPLICATE RETURNS ERROR ─────────────────────────

    #[test]
    fn test_mark_claimed_duplicate_returns_error() {
        let mut tracker = ReceiptDedupTracker::new();
        tracker.mark_claimed(HASH_A).expect("first insert");

        let result = tracker.mark_claimed(HASH_A);
        assert!(result.is_err());

        match result {
            Err(ClaimValidationError::ReceiptAlreadyClaimed { receipt_hash }) => {
                assert_eq!(receipt_hash, HASH_A);
            }
            _ => panic!("expected ReceiptAlreadyClaimed"),
        }
    }

    // ── 4. IS CLAIMED TRUE AFTER INSERT ─────────────────────────────────

    #[test]
    fn test_is_claimed_true_after_insert() {
        let mut tracker = ReceiptDedupTracker::new();
        tracker.mark_claimed(HASH_A).expect("insert");
        assert!(tracker.is_claimed(&HASH_A));
    }

    // ── 5. IS CLAIMED FALSE WHEN NOT INSERTED ───────────────────────────

    #[test]
    fn test_is_claimed_false_when_not_inserted() {
        let tracker = ReceiptDedupTracker::new();
        assert!(!tracker.is_claimed(&HASH_A));
        assert!(!tracker.is_claimed(&HASH_B));
    }

    // ── 6. CLAIMED COUNT INCREASES CORRECTLY ────────────────────────────

    #[test]
    fn test_claimed_count_increases_correctly() {
        let mut tracker = ReceiptDedupTracker::new();
        assert_eq!(tracker.claimed_count(), 0);

        tracker.mark_claimed(HASH_A).expect("a");
        assert_eq!(tracker.claimed_count(), 1);

        tracker.mark_claimed(HASH_B).expect("b");
        assert_eq!(tracker.claimed_count(), 2);

        tracker.mark_claimed(HASH_C).expect("c");
        assert_eq!(tracker.claimed_count(), 3);
    }

    // ── 7. CLAIMED COUNT NOT INCREASE ON DUPLICATE ──────────────────────

    #[test]
    fn test_claimed_count_not_increase_on_duplicate() {
        let mut tracker = ReceiptDedupTracker::new();
        tracker.mark_claimed(HASH_A).expect("first");
        assert_eq!(tracker.claimed_count(), 1);

        let _ = tracker.mark_claimed(HASH_A); // duplicate
        assert_eq!(tracker.claimed_count(), 1);
    }

    // ── 8. PRUNE REMOVES HASH ───────────────────────────────────────────

    #[test]
    fn test_prune_removes_hash() {
        let mut tracker = ReceiptDedupTracker::new();
        tracker.mark_claimed(HASH_A).expect("a");
        tracker.mark_claimed(HASH_B).expect("b");
        assert_eq!(tracker.claimed_count(), 2);

        let mut cutoff = HashSet::new();
        cutoff.insert(HASH_A);
        tracker.prune_before(&cutoff);

        assert_eq!(tracker.claimed_count(), 1);
        assert!(!tracker.is_claimed(&HASH_A));
        assert!(tracker.is_claimed(&HASH_B));
    }

    // ── 9. PRUNE DOES NOT REMOVE UNLISTED HASH ─────────────────────────

    #[test]
    fn test_prune_does_not_remove_unlisted_hash() {
        let mut tracker = ReceiptDedupTracker::new();
        tracker.mark_claimed(HASH_A).expect("a");
        tracker.mark_claimed(HASH_B).expect("b");

        let mut cutoff = HashSet::new();
        cutoff.insert(HASH_C); // not in tracker
        tracker.prune_before(&cutoff);

        assert_eq!(tracker.claimed_count(), 2);
        assert!(tracker.is_claimed(&HASH_A));
        assert!(tracker.is_claimed(&HASH_B));
    }

    // ── 10. MULTIPLE INSERT AND PRUNE SCENARIO ──────────────────────────

    #[test]
    fn test_multiple_insert_and_prune_scenario() {
        let mut tracker = ReceiptDedupTracker::new();

        // Insert 3 hashes.
        tracker.mark_claimed(HASH_A).expect("a");
        tracker.mark_claimed(HASH_B).expect("b");
        tracker.mark_claimed(HASH_C).expect("c");
        assert_eq!(tracker.claimed_count(), 3);

        // Prune A and C.
        let mut cutoff = HashSet::new();
        cutoff.insert(HASH_A);
        cutoff.insert(HASH_C);
        tracker.prune_before(&cutoff);

        assert_eq!(tracker.claimed_count(), 1);
        assert!(!tracker.is_claimed(&HASH_A));
        assert!(tracker.is_claimed(&HASH_B));
        assert!(!tracker.is_claimed(&HASH_C));

        // Re-insert A (should succeed after prune).
        let result = tracker.mark_claimed(HASH_A);
        assert!(result.is_ok());
        assert_eq!(tracker.claimed_count(), 2);
    }

    // ── ADDITIONAL: PRUNE EMPTY TRACKER ─────────────────────────────────

    #[test]
    fn test_prune_empty_tracker() {
        let mut tracker = ReceiptDedupTracker::new();
        let mut cutoff = HashSet::new();
        cutoff.insert(HASH_A);
        tracker.prune_before(&cutoff); // Must not panic.
        assert_eq!(tracker.claimed_count(), 0);
    }

    // ── ADDITIONAL: PRUNE WITH EMPTY CUTOFF ─────────────────────────────

    #[test]
    fn test_prune_with_empty_cutoff() {
        let mut tracker = ReceiptDedupTracker::new();
        tracker.mark_claimed(HASH_A).expect("a");

        let cutoff = HashSet::new();
        tracker.prune_before(&cutoff); // Empty cutoff → nothing removed.

        assert_eq!(tracker.claimed_count(), 1);
        assert!(tracker.is_claimed(&HASH_A));
    }

    // ── ADDITIONAL: DEFAULT IMPL ────────────────────────────────────────

    #[test]
    fn test_default_is_empty() {
        let tracker = ReceiptDedupTracker::default();
        assert_eq!(tracker.claimed_count(), 0);
    }

    // ── ADDITIONAL: CLONE ───────────────────────────────────────────────

    #[test]
    fn test_clone_independence() {
        let mut tracker = ReceiptDedupTracker::new();
        tracker.mark_claimed(HASH_A).expect("a");

        let mut clone = tracker.clone();
        clone.mark_claimed(HASH_B).expect("b");

        // Original unaffected.
        assert_eq!(tracker.claimed_count(), 1);
        assert_eq!(clone.claimed_count(), 2);
    }

    // ── ADDITIONAL: DEBUG ───────────────────────────────────────────────

    #[test]
    fn test_debug_format() {
        let tracker = ReceiptDedupTracker::new();
        let dbg = format!("{:?}", tracker);
        assert!(dbg.contains("ReceiptDedupTracker"));
    }
}