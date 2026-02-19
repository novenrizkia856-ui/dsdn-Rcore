//! # Anti-Self-Dealing Detection
//!
//! Anti-self-dealing detection logic.
//! Level 1: Direct wallet match.
//! Level 2: Node owner match.
//! Level 3: Wallet affinity (future extension).
//!
//! Penalty (di chain layer):
//! node reward dialihkan ke treasury.
//! Modul ini hanya DETECTION, bukan penalty executor.
//! Referensi: Spec 13.11
//!
//! ## Check Order
//!
//! `run_all_checks()` menjalankan deteksi dalam urutan strict:
//!
//! 1. Direct address match (node_address == submitter_address)
//! 2. Owner match (node_owner_address == submitter_address)
//! 3. Wallet affinity (stub v1, selalu None)
//!
//! Return FIRST violation yang ditemukan.
//!
//! ## Determinism
//!
//! Semua method deterministik, tidak memiliki side-effect,
//! tidak bergantung pada state eksternal.

use crate::receipt_v1::Address;

// ════════════════════════════════════════════════════════════════════════════════
// VIOLATION TYPE
// ════════════════════════════════════════════════════════════════════════════════

/// Jenis pelanggaran anti-self-dealing yang terdeteksi.
///
/// Digunakan oleh chain layer untuk menentukan penalty.
/// Modul ini hanya mendeteksi, tidak mengeksekusi penalty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfDealingViolation {
    /// Direct address match: node_address == submitter_address,
    /// atau node_owner_address == submitter_address.
    DirectMatch,
    /// Wallet affinity match berdasarkan analisis lookback data.
    /// Belum diimplementasikan di v1 (stub).
    WalletAffinityMatch,
}

// ════════════════════════════════════════════════════════════════════════════════
// CHECK STRUCT
// ════════════════════════════════════════════════════════════════════════════════

/// Parameter untuk anti-self-dealing check.
///
/// Berisi address-address yang akan diperiksa untuk mendeteksi
/// apakah submitter memiliki hubungan ekonomi langsung dengan node.
pub struct AntiSelfDealingCheck {
    /// Address dari node yang melakukan kerja.
    pub node_address: Address,
    /// Address pihak yang submit ClaimReward transaction.
    pub submitter_address: Address,
    /// Address pemilik node (jika diketahui).
    pub node_owner_address: Option<Address>,
}

impl AntiSelfDealingCheck {
    /// Membuat instance baru `AntiSelfDealingCheck`.
    ///
    /// Tidak melakukan validasi — semua address diterima apa adanya.
    /// Validasi address dilakukan di layer yang membangun parameter ini.
    #[must_use]
    #[inline]
    pub const fn new(
        node_address: Address,
        submitter_address: Address,
        node_owner_address: Option<Address>,
    ) -> Self {
        Self {
            node_address,
            submitter_address,
            node_owner_address,
        }
    }

    /// Level 1: Direct address match.
    ///
    /// Memeriksa apakah `node_address == submitter_address`.
    ///
    /// Jika match → `Some(SelfDealingViolation::DirectMatch)`.
    /// Jika tidak → `None`.
    ///
    /// Deterministik. Tidak panic.
    #[must_use]
    #[inline]
    pub fn check_direct_match(&self) -> Option<SelfDealingViolation> {
        if self.node_address == self.submitter_address {
            Some(SelfDealingViolation::DirectMatch)
        } else {
            None
        }
    }

    /// Level 2: Owner match.
    ///
    /// Memeriksa apakah `node_owner_address` is `Some`
    /// DAN `node_owner_address == submitter_address`.
    ///
    /// Owner match diperlakukan sebagai direct economic violation
    /// (`SelfDealingViolation::DirectMatch`).
    ///
    /// Jika match → `Some(SelfDealingViolation::DirectMatch)`.
    /// Jika tidak → `None`.
    ///
    /// Deterministik. Tidak panic.
    #[must_use]
    #[inline]
    pub fn check_owner_match(&self) -> Option<SelfDealingViolation> {
        match self.node_owner_address {
            Some(owner) if owner == self.submitter_address => {
                Some(SelfDealingViolation::DirectMatch)
            }
            _ => None,
        }
    }

    /// Level 3: Wallet affinity (stub v1).
    ///
    /// Stub implementation untuk v1. Selalu return `None`.
    ///
    /// Parameter `_lookback_data` tidak diinspeksi di v1.
    /// Akan diimplementasikan di versi mendatang menggunakan
    /// `WALLET_AFFINITY_LOOKBACK` dari `economic_constants`.
    ///
    /// Deterministik. Tidak panic. Tidak inspect data.
    #[must_use]
    #[inline]
    pub fn check_wallet_affinity(
        &self,
        _lookback_data: &[u8],
    ) -> Option<SelfDealingViolation> {
        None
    }

    /// Menjalankan semua check dalam urutan strict.
    ///
    /// ## Urutan
    ///
    /// 1. `check_direct_match()`
    /// 2. `check_owner_match()`
    /// 3. `check_wallet_affinity(lookback_data)`
    ///
    /// Return FIRST violation yang ditemukan.
    /// Tidak lanjut jika violation sudah ditemukan.
    ///
    /// Deterministik. Tidak panic.
    #[must_use]
    pub fn run_all_checks(
        &self,
        lookback_data: &[u8],
    ) -> Option<SelfDealingViolation> {
        if let Some(v) = self.check_direct_match() {
            return Some(v);
        }
        if let Some(v) = self.check_owner_match() {
            return Some(v);
        }
        self.check_wallet_affinity(lookback_data)
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    const ADDR_A: Address = [0x01; 20];
    const ADDR_B: Address = [0x02; 20];
    const ADDR_C: Address = [0x03; 20];

    // ── LEVEL 1: DIRECT MATCH ───────────────────────────────────────────

    #[test]
    fn direct_match_same_address() {
        let check = AntiSelfDealingCheck::new(ADDR_A, ADDR_A, None);
        assert_eq!(
            check.check_direct_match(),
            Some(SelfDealingViolation::DirectMatch)
        );
    }

    #[test]
    fn direct_match_different_address() {
        let check = AntiSelfDealingCheck::new(ADDR_A, ADDR_B, None);
        assert_eq!(check.check_direct_match(), None);
    }

    // ── LEVEL 2: OWNER MATCH ────────────────────────────────────────────

    #[test]
    fn owner_match_submitter_equals_owner() {
        let check = AntiSelfDealingCheck::new(ADDR_A, ADDR_B, Some(ADDR_B));
        assert_eq!(
            check.check_owner_match(),
            Some(SelfDealingViolation::DirectMatch)
        );
    }

    #[test]
    fn owner_match_submitter_not_owner() {
        let check = AntiSelfDealingCheck::new(ADDR_A, ADDR_B, Some(ADDR_C));
        assert_eq!(check.check_owner_match(), None);
    }

    #[test]
    fn owner_match_no_owner() {
        let check = AntiSelfDealingCheck::new(ADDR_A, ADDR_B, None);
        assert_eq!(check.check_owner_match(), None);
    }

    // ── LEVEL 3: WALLET AFFINITY (STUB) ─────────────────────────────────

    #[test]
    fn wallet_affinity_always_none() {
        let check = AntiSelfDealingCheck::new(ADDR_A, ADDR_B, None);
        assert_eq!(check.check_wallet_affinity(&[]), None);
    }

    #[test]
    fn wallet_affinity_with_data_still_none() {
        let check = AntiSelfDealingCheck::new(ADDR_A, ADDR_B, None);
        assert_eq!(check.check_wallet_affinity(&[0xFF; 1024]), None);
    }

    // ── RUN ALL CHECKS ──────────────────────────────────────────────────

    #[test]
    fn run_all_no_violation() {
        let check = AntiSelfDealingCheck::new(ADDR_A, ADDR_B, Some(ADDR_C));
        assert_eq!(check.run_all_checks(&[]), None);
    }

    #[test]
    fn run_all_direct_match_first() {
        let check = AntiSelfDealingCheck::new(ADDR_A, ADDR_A, Some(ADDR_A));
        // Both direct and owner would match, but direct is returned first.
        assert_eq!(
            check.run_all_checks(&[]),
            Some(SelfDealingViolation::DirectMatch)
        );
    }

    #[test]
    fn run_all_owner_match_when_no_direct() {
        let check = AntiSelfDealingCheck::new(ADDR_A, ADDR_B, Some(ADDR_B));
        assert_eq!(
            check.run_all_checks(&[]),
            Some(SelfDealingViolation::DirectMatch)
        );
    }

    #[test]
    fn run_all_no_owner_no_direct() {
        let check = AntiSelfDealingCheck::new(ADDR_A, ADDR_B, None);
        assert_eq!(check.run_all_checks(&[]), None);
    }

    // ── VIOLATION ENUM ──────────────────────────────────────────────────

    #[test]
    fn violation_copy_trait() {
        let v = SelfDealingViolation::DirectMatch;
        let v2 = v;
        assert_eq!(v, v2);
    }

    #[test]
    fn violation_debug() {
        let dbg = format!("{:?}", SelfDealingViolation::DirectMatch);
        assert!(dbg.contains("DirectMatch"));
    }

    #[test]
    fn violation_wallet_affinity_debug() {
        let dbg = format!("{:?}", SelfDealingViolation::WalletAffinityMatch);
        assert!(dbg.contains("WalletAffinityMatch"));
    }

    // ── DETERMINISM ─────────────────────────────────────────────────────

    #[test]
    fn deterministic_multiple_calls() {
        let check = AntiSelfDealingCheck::new(ADDR_A, ADDR_A, Some(ADDR_A));
        let r1 = check.run_all_checks(&[]);
        let r2 = check.run_all_checks(&[]);
        assert_eq!(r1, r2);
    }

    // ── EDGE CASES ──────────────────────────────────────────────────────

    #[test]
    fn all_zero_addresses() {
        let zero = [0u8; 20];
        let check = AntiSelfDealingCheck::new(zero, zero, Some(zero));
        assert_eq!(
            check.run_all_checks(&[]),
            Some(SelfDealingViolation::DirectMatch)
        );
    }

    #[test]
    fn owner_equals_node_but_not_submitter() {
        let check = AntiSelfDealingCheck::new(ADDR_A, ADDR_B, Some(ADDR_A));
        assert_eq!(check.check_owner_match(), None);
    }
}