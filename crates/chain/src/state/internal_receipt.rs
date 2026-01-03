//! # Receipt Claim Tracking & Verification (13.10)
//!
//! Module ini menyediakan:
//! - Tracking receipt yang sudah di-claim (anti double-claim)
//! - Verifikasi receipt sebelum reward diproses
//!
//! ## Methods
//!
//! | Method | Description |
//! |--------|-------------|
//! | `is_receipt_claimed(receipt_id)` | Check apakah receipt sudah di-claim |
//! | `mark_receipt_claimed(receipt_id)` | Tandai receipt sebagai sudah di-claim |
//! | `get_claimed_receipt_count()` | Jumlah receipt yang sudah di-claim |
//! | `verify_receipt(receipt, sender)` | Verifikasi receipt sebelum claim |
//!
//! ## Verification Order (CONSENSUS-CRITICAL)
//!
//! 1. Coordinator signature (Ed25519)
//! 2. Double-claim check
//! 3. Node address match
//! 4. Anti-self-dealing flag
//! 5. Timestamp validity

use crate::types::{Address, Hash};
use crate::receipt::ResourceReceipt;
use super::ChainState;

// ════════════════════════════════════════════════════════════════════════════
// RECEIPT ERROR
// ════════════════════════════════════════════════════════════════════════════

/// Error yang terjadi saat verifikasi receipt.
/// Digunakan oleh verify_receipt() untuk mengembalikan error deterministik.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptError {
    /// Coordinator signature tidak valid (Ed25519 verification failed)
    InvalidSignature,
    /// Receipt sudah pernah di-claim sebelumnya
    AlreadyClaimed,
    /// Sender tidak sama dengan node_address di receipt
    NodeMismatch,
    /// Receipt anti_self_dealing_flag adalah false (violation)
    AntiSelfDealingViolation,
    /// Receipt timestamp adalah 0 (invalid)
    InvalidTimestamp,
}

// ════════════════════════════════════════════════════════════════════════════
// CHAINSTATE IMPLEMENTATION
// ════════════════════════════════════════════════════════════════════════════

impl ChainState {
    /// Check apakah receipt dengan ID tertentu sudah di-claim.
    ///
    /// Returns `true` bila receipt sudah ada di claimed_receipts.
    /// Returns `false` bila receipt belum pernah di-claim.
    #[inline]
    pub fn is_receipt_claimed(&self, receipt_id: &Hash) -> bool {
        self.claimed_receipts.contains(receipt_id)
    }

    /// Tandai receipt sebagai sudah di-claim.
    ///
    /// Menambahkan receipt_id ke claimed_receipts HashSet.
    /// Idempotent: aman dipanggil berkali-kali untuk receipt_id yang sama.
    #[inline]
    pub fn mark_receipt_claimed(&mut self, receipt_id: Hash) {
        self.claimed_receipts.insert(receipt_id);
    }

    /// Mendapatkan jumlah receipt yang sudah di-claim.
    ///
    /// Returns jumlah entries di claimed_receipts HashSet.
    #[inline]
    pub fn get_claimed_receipt_count(&self) -> usize {
        self.claimed_receipts.len()
    }

    /// Verifikasi receipt sebelum reward diproses.
    ///
    /// Urutan verifikasi (CONSENSUS-CRITICAL, tidak boleh diubah):
    /// 1. Coordinator signature valid (Ed25519)
    /// 2. Receipt belum pernah di-claim
    /// 3. Sender sama dengan node_address di receipt
    /// 4. Anti-self-dealing flag adalah true
    /// 5. Timestamp lebih dari 0
    ///
    /// Returns `Ok(())` bila semua verifikasi lolos.
    /// Returns `Err(ReceiptError)` bila ada verifikasi yang gagal.
    ///
    /// Method ini TIDAK menandai receipt sebagai claimed.
    /// Method ini TIDAK memiliki side effect.
    pub fn verify_receipt(
        &self,
        receipt: &ResourceReceipt,
        sender: &Address,
    ) -> Result<(), ReceiptError> {
        // 1. Verifikasi coordinator signature (Ed25519)
        if !receipt.verify_coordinator_signature() {
            return Err(ReceiptError::InvalidSignature);
        }

        // 2. Check apakah receipt sudah pernah di-claim
        if self.is_receipt_claimed(&receipt.receipt_id) {
            return Err(ReceiptError::AlreadyClaimed);
        }

        // 3. Check apakah sender sama dengan node_address
        if receipt.node_address != *sender {
            return Err(ReceiptError::NodeMismatch);
        }

        // 4. Check anti-self-dealing flag harus true
        if !receipt.anti_self_dealing_flag {
            return Err(ReceiptError::AntiSelfDealingViolation);
        }

        // 5. Check timestamp harus lebih dari 0
        if receipt.timestamp == 0 {
            return Err(ReceiptError::InvalidTimestamp);
        }

        Ok(())
    }
}