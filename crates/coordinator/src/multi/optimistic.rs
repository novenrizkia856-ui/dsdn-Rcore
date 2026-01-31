//! OptimisticReceipt Implementation (14A.2B.2.19)
//!
//! Module ini mengimplementasikan OptimisticReceipt sebagai low-latency receipt
//! berbasis single-signature yang dapat di-upgrade ke ThresholdReceipt.
//!
//! # Properties
//!
//! - **BUKAN final** - Dapat di-challenge selama window
//! - **BUKAN trustless** - Bergantung pada single coordinator
//! - **Challengeable** - Selama challenge window belum expired
//! - **Verifiable** - Signature dapat diverifikasi secara lokal
//! - **Upgradeable** - Dapat di-upgrade ke ThresholdReceipt SATU KALI
//!
//! # Invariants
//!
//! - `receipt_data` IMMUTABLE setelah dibuat
//! - `upgraded` hanya bisa berubah false → true SATU KALI
//! - `coordinator_pubkey` HARUS cocok dengan `coordinator_id`
//! - `issued_at` HARUS monotonic
//!
//! # Usage
//!
//! ```ignore
//! use dsdn_coordinator::multi::OptimisticReceipt;
//! use std::time::Duration;
//!
//! // Create optimistic receipt
//! let receipt = OptimisticReceipt::new(
//!     data,
//!     signature,
//!     coordinator_id,
//!     pubkey,
//!     Duration::from_secs(300), // 5 minute challenge window
//! );
//!
//! // Verify signature
//! if receipt.verify_signature() {
//!     // Check if still challengeable
//!     if receipt.is_challengeable(now_ms) {
//!         // Can be challenged
//!     }
//! }
//!
//! // Upgrade to threshold receipt
//! let threshold = receipt.upgrade_to_threshold(threshold_receipt)?;
//! ```

use std::fmt;
use std::time::Duration;

use sha3::{Digest, Sha3_256};

use dsdn_common::coordinator::{ReceiptData, ThresholdReceipt};

use super::CoordinatorId;

// ════════════════════════════════════════════════════════════════════════════════
// OPTIMISTIC RECEIPT ERROR
// ════════════════════════════════════════════════════════════════════════════════

/// Error type untuk OptimisticReceipt operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OptimisticReceiptError {
    /// Receipt sudah di-upgrade sebelumnya.
    AlreadyUpgraded,

    /// Receipt data tidak cocok dengan threshold receipt.
    DataMismatch {
        /// Field yang tidak cocok.
        field: String,
    },

    /// Coordinator bukan anggota committee.
    NotCommitteeMember {
        /// CoordinatorId yang bukan member.
        coordinator: CoordinatorId,
    },

    /// Signature tidak valid.
    InvalidSignature,

    /// Challenge window sudah expired.
    ChallengeWindowExpired {
        /// Deadline yang sudah lewat.
        deadline: u64,
        /// Waktu saat ini.
        now: u64,
    },

    /// Overflow saat menghitung deadline.
    DeadlineOverflow,
}

impl fmt::Display for OptimisticReceiptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OptimisticReceiptError::AlreadyUpgraded => {
                write!(f, "optimistic receipt already upgraded")
            }
            OptimisticReceiptError::DataMismatch { field } => {
                write!(f, "data mismatch in field: {}", field)
            }
            OptimisticReceiptError::NotCommitteeMember { coordinator } => {
                write!(
                    f,
                    "coordinator {:?} is not a committee member",
                    coordinator.as_bytes()
                )
            }
            OptimisticReceiptError::InvalidSignature => {
                write!(f, "invalid signature")
            }
            OptimisticReceiptError::ChallengeWindowExpired { deadline, now } => {
                write!(
                    f,
                    "challenge window expired: deadline={}, now={}",
                    deadline, now
                )
            }
            OptimisticReceiptError::DeadlineOverflow => {
                write!(f, "deadline calculation overflow")
            }
        }
    }
}

impl std::error::Error for OptimisticReceiptError {}

// ════════════════════════════════════════════════════════════════════════════════
// OPTIMISTIC RECEIPT
// ════════════════════════════════════════════════════════════════════════════════

/// Low-latency receipt berbasis single-signature.
///
/// OptimisticReceipt memberikan konfirmasi cepat dari satu coordinator,
/// yang dapat di-challenge selama window tertentu dan di-upgrade ke
/// ThresholdReceipt untuk finalitas penuh.
///
/// # Security Model
///
/// - Trust: Single coordinator (optimistic assumption)
/// - Finality: Setelah challenge window atau upgrade
/// - Challenge: Dapat di-challenge dengan bukti fraud
///
/// # Lifecycle
///
/// ```text
/// Created → Challengeable → [Upgraded | Expired]
///              ↓
///           Challenged (fraud proof)
/// ```
#[derive(Clone, Debug)]
pub struct OptimisticReceipt {
    /// Receipt data yang di-sign.
    receipt_data: ReceiptData,

    /// Single signature (Ed25519, 64 bytes).
    single_signature: [u8; 64],

    /// ID coordinator yang menandatangani.
    coordinator_id: CoordinatorId,

    /// Public key coordinator (Ed25519, 32 bytes).
    coordinator_pubkey: [u8; 32],

    /// Timestamp saat receipt dibuat (milliseconds).
    issued_at: u64,

    /// Challenge window duration.
    challenge_window: Duration,

    /// Flag apakah sudah di-upgrade ke ThresholdReceipt.
    upgraded: bool,
}

impl OptimisticReceipt {
    /// Membuat OptimisticReceipt baru.
    ///
    /// # Arguments
    ///
    /// * `data` - ReceiptData yang di-sign
    /// * `signature` - Ed25519 signature (64 bytes)
    /// * `coordinator` - CoordinatorId penandatangan
    /// * `pubkey` - Public key coordinator (32 bytes)
    /// * `challenge_window` - Duration challenge window
    ///
    /// # Returns
    ///
    /// OptimisticReceipt baru dengan `upgraded = false`.
    ///
    /// # Note
    ///
    /// - `issued_at` di-set ke timestamp saat creation
    /// - Tidak ada validasi implisit di constructor
    #[must_use]
    pub fn new(
        data: ReceiptData,
        signature: [u8; 64],
        coordinator: CoordinatorId,
        pubkey: [u8; 32],
        challenge_window: Duration,
    ) -> Self {
        // Get current timestamp
        let issued_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        Self {
            receipt_data: data,
            single_signature: signature,
            coordinator_id: coordinator,
            coordinator_pubkey: pubkey,
            issued_at,
            challenge_window,
            upgraded: false,
        }
    }

    /// Membuat OptimisticReceipt dengan timestamp eksplisit.
    ///
    /// Untuk testing atau reconstruct dari storage.
    #[must_use]
    pub fn with_timestamp(
        data: ReceiptData,
        signature: [u8; 64],
        coordinator: CoordinatorId,
        pubkey: [u8; 32],
        challenge_window: Duration,
        issued_at: u64,
    ) -> Self {
        Self {
            receipt_data: data,
            single_signature: signature,
            coordinator_id: coordinator,
            coordinator_pubkey: pubkey,
            issued_at,
            challenge_window,
            upgraded: false,
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // GETTERS
    // ────────────────────────────────────────────────────────────────────────────

    /// Mengembalikan reference ke receipt_data.
    #[must_use]
    #[inline]
    pub fn receipt_data(&self) -> &ReceiptData {
        &self.receipt_data
    }

    /// Mengembalikan reference ke signature.
    #[must_use]
    #[inline]
    pub const fn signature(&self) -> &[u8; 64] {
        &self.single_signature
    }

    /// Mengembalikan reference ke coordinator_id.
    #[must_use]
    #[inline]
    pub const fn coordinator_id(&self) -> &CoordinatorId {
        &self.coordinator_id
    }

    /// Mengembalikan reference ke coordinator_pubkey.
    #[must_use]
    #[inline]
    pub const fn coordinator_pubkey(&self) -> &[u8; 32] {
        &self.coordinator_pubkey
    }

    /// Mengembalikan issued_at timestamp.
    #[must_use]
    #[inline]
    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }

    /// Mengembalikan challenge_window duration.
    #[must_use]
    #[inline]
    pub const fn challenge_window(&self) -> Duration {
        self.challenge_window
    }

    /// Memeriksa apakah receipt sudah di-upgrade.
    #[must_use]
    #[inline]
    pub const fn is_upgraded(&self) -> bool {
        self.upgraded
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SIGNATURE VERIFICATION
    // ────────────────────────────────────────────────────────────────────────────

    /// Memverifikasi signature terhadap receipt data.
    ///
    /// # Algorithm
    ///
    /// 1. Hash message: `SHA3-256(receipt_data || issued_at || coordinator_id)`
    /// 2. Verify Ed25519 signature against hash using coordinator_pubkey
    ///
    /// # Returns
    ///
    /// - `true` jika signature valid
    /// - `false` jika signature tidak valid
    ///
    /// # Note
    ///
    /// Tidak panic. Jika verifikasi gagal karena alasan apapun,
    /// return false.
    #[must_use]
    pub fn verify_signature(&self) -> bool {
        // Build message to verify
        let message = self.build_signing_message();

        // Verify Ed25519 signature
        // Note: This is a placeholder implementation
        // Real implementation would use ed25519-dalek or similar
        self.verify_ed25519(&message, &self.single_signature, &self.coordinator_pubkey)
    }

    /// Build the message that was signed.
    ///
    /// Format: `SHA3-256(receipt_data || issued_at || coordinator_id)`
    fn build_signing_message(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();

        // Hash receipt data fields
        hasher.update(self.receipt_data.workload_id().as_bytes());
        hasher.update(self.receipt_data.blob_hash());
        hasher.update(&self.receipt_data.timestamp().to_le_bytes());
        hasher.update(&self.receipt_data.sequence().to_le_bytes());
        hasher.update(&self.receipt_data.epoch().to_le_bytes());

        // Hash issued_at
        hasher.update(&self.issued_at.to_le_bytes());

        // Hash coordinator_id
        hasher.update(self.coordinator_id.as_bytes());

        let hash = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        result
    }

    /// Verify Ed25519 signature.
    ///
    /// # Note
    ///
    /// This is a placeholder implementation that performs basic validation.
    /// Real implementation should use ed25519-dalek crate.
    fn verify_ed25519(&self, message: &[u8; 32], signature: &[u8; 64], pubkey: &[u8; 32]) -> bool {
        // Basic validation: signature and pubkey must not be all zeros
        if signature.iter().all(|&b| b == 0) {
            return false;
        }
        if pubkey.iter().all(|&b| b == 0) {
            return false;
        }

        // Placeholder: In real implementation, use ed25519-dalek to verify
        // For now, we do a deterministic check that can be replaced
        // The signature should "relate" to the message and pubkey
        
        // Create expected signature prefix from message and pubkey
        let mut hasher = Sha3_256::new();
        hasher.update(b"ED25519_VERIFY_PLACEHOLDER");
        hasher.update(message);
        hasher.update(pubkey);
        let expected_prefix = hasher.finalize();

        // Check if signature starts with expected pattern
        // This is a PLACEHOLDER - real Ed25519 verification would be cryptographically secure
        signature[0..8] == expected_prefix[0..8]
    }

    // ────────────────────────────────────────────────────────────────────────────
    // CHALLENGE WINDOW
    // ────────────────────────────────────────────────────────────────────────────

    /// Menghitung challenge deadline.
    ///
    /// # Returns
    ///
    /// - `Ok(deadline)` - `issued_at + challenge_window` dalam milliseconds
    /// - `Err(DeadlineOverflow)` - Jika overflow
    ///
    /// # Note
    ///
    /// Overflow-safe calculation.
    pub fn challenge_deadline(&self) -> Result<u64, OptimisticReceiptError> {
        let window_ms = self.challenge_window.as_millis() as u64;
        self.issued_at
            .checked_add(window_ms)
            .ok_or(OptimisticReceiptError::DeadlineOverflow)
    }

    /// Memeriksa apakah receipt masih dapat di-challenge.
    ///
    /// # Arguments
    ///
    /// * `now` - Timestamp saat ini dalam milliseconds
    ///
    /// # Returns
    ///
    /// - `true` jika `now <= challenge_deadline` DAN belum upgraded
    /// - `false` jika expired atau sudah upgraded atau overflow
    ///
    /// # Note
    ///
    /// Deterministic dan tidak panic.
    #[must_use]
    pub fn is_challengeable(&self, now: u64) -> bool {
        // Already upgraded = not challengeable
        if self.upgraded {
            return false;
        }

        // Calculate deadline safely
        match self.challenge_deadline() {
            Ok(deadline) => now <= deadline,
            Err(_) => false, // Overflow = treat as expired
        }
    }

    /// Memeriksa apakah challenge window sudah expired.
    ///
    /// # Arguments
    ///
    /// * `now` - Timestamp saat ini dalam milliseconds
    ///
    /// # Returns
    ///
    /// - `true` jika `now > challenge_deadline`
    /// - `false` jika masih dalam window atau overflow
    #[must_use]
    pub fn is_expired(&self, now: u64) -> bool {
        match self.challenge_deadline() {
            Ok(deadline) => now > deadline,
            Err(_) => false, // Overflow = treat as not expired (safer)
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // UPGRADE
    // ────────────────────────────────────────────────────────────────────────────

    /// Upgrade ke ThresholdReceipt.
    ///
    /// # Arguments
    ///
    /// * `threshold_receipt` - ThresholdReceipt untuk upgrade
    ///
    /// # Returns
    ///
    /// - `Ok(ThresholdReceipt)` jika upgrade berhasil
    /// - `Err(OptimisticReceiptError)` jika validasi gagal
    ///
    /// # Rules
    ///
    /// 1. `upgraded` HARUS `false`
    /// 2. `threshold_receipt.receipt_data` HARUS IDENTIK
    /// 3. `coordinator_id` HARUS anggota committee (dalam signers)
    ///
    /// # Side Effects
    ///
    /// - Jika sukses: `upgraded = true`
    /// - Jika gagal: state tidak berubah
    pub fn upgrade_to_threshold(
        &mut self,
        threshold_receipt: ThresholdReceipt,
    ) -> Result<ThresholdReceipt, OptimisticReceiptError> {
        // 1. Check not already upgraded
        if self.upgraded {
            return Err(OptimisticReceiptError::AlreadyUpgraded);
        }

        // 2. Verify receipt_data is IDENTICAL
        self.verify_data_match(&threshold_receipt)?;

        // 3. Verify coordinator_id is in signers
        self.verify_committee_membership(&threshold_receipt)?;

        // All validations passed - set upgraded flag
        self.upgraded = true;

        Ok(threshold_receipt)
    }

    /// Verify receipt_data matches threshold_receipt.
    fn verify_data_match(
        &self,
        threshold_receipt: &ThresholdReceipt,
    ) -> Result<(), OptimisticReceiptError> {
        let our_data = &self.receipt_data;
        let their_data = threshold_receipt.receipt_data();

        // Compare workload_id
        if our_data.workload_id().as_bytes() != their_data.workload_id().as_bytes() {
            return Err(OptimisticReceiptError::DataMismatch {
                field: "workload_id".to_string(),
            });
        }

        // Compare blob_hash
        if our_data.blob_hash() != their_data.blob_hash() {
            return Err(OptimisticReceiptError::DataMismatch {
                field: "blob_hash".to_string(),
            });
        }

        // Compare timestamp
        if our_data.timestamp() != their_data.timestamp() {
            return Err(OptimisticReceiptError::DataMismatch {
                field: "timestamp".to_string(),
            });
        }

        // Compare size
        if our_data.sequence() != their_data.sequence() {
            return Err(OptimisticReceiptError::DataMismatch {
                field: "sequence".to_string(),
            });
        }

        // Compare epoch
        if our_data.epoch() != their_data.epoch() {
            return Err(OptimisticReceiptError::DataMismatch {
                field: "epoch".to_string(),
            });
        }

        Ok(())
    }

    /// Verify coordinator_id is in threshold_receipt signers.
    fn verify_committee_membership(
        &self,
        threshold_receipt: &ThresholdReceipt,
    ) -> Result<(), OptimisticReceiptError> {
        let our_id_bytes = self.coordinator_id.as_bytes();

        // Check if our coordinator_id is in the signers list
        let is_member = threshold_receipt
            .signers()
            .iter()
            .any(|signer| signer.as_bytes() == our_id_bytes);

        if !is_member {
            return Err(OptimisticReceiptError::NotCommitteeMember {
                coordinator: self.coordinator_id.clone(),
            });
        }

        Ok(())
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════════

/// Create a placeholder signature for testing.
///
/// Creates a signature that will pass the placeholder verification.
#[must_use]
pub fn create_placeholder_signature(
    receipt_data: &ReceiptData,
    issued_at: u64,
    coordinator_id: &CoordinatorId,
    pubkey: &[u8; 32],
) -> [u8; 64] {
    // Build message hash
    let mut hasher = Sha3_256::new();
    hasher.update(receipt_data.workload_id().as_bytes());
    hasher.update(receipt_data.blob_hash());
    hasher.update(&receipt_data.timestamp().to_le_bytes());
    hasher.update(&receipt_data.sequence().to_le_bytes());
    hasher.update(&receipt_data.epoch().to_le_bytes());
    hasher.update(&issued_at.to_le_bytes());
    hasher.update(coordinator_id.as_bytes());
    let message_hash = hasher.finalize();

    // Build expected prefix
    let mut hasher2 = Sha3_256::new();
    hasher2.update(b"ED25519_VERIFY_PLACEHOLDER");
    hasher2.update(&message_hash);
    hasher2.update(pubkey);
    let expected = hasher2.finalize();

    // Create signature with correct prefix
    let mut signature = [0u8; 64];
    signature[0..32].copy_from_slice(&expected);
    signature[32..64].copy_from_slice(&message_hash);

    signature
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use dsdn_common::coordinator::WorkloadId as CommonWorkloadId;
    use dsdn_tss::AggregateSignature;

    fn make_coord_id(seed: u8) -> CoordinatorId {
        CoordinatorId::new([seed; 32])
    }

    fn make_common_coord_id(seed: u8) -> dsdn_common::coordinator::CoordinatorId {
        dsdn_common::coordinator::CoordinatorId::new([seed; 32])
    }

    fn make_receipt_data(seed: u8) -> ReceiptData {
        ReceiptData::new(
            CommonWorkloadId::new([seed; 32]),
            [seed; 32],
            vec![],
            1700000000,
            1024,
            1,
        )
    }

    fn make_pubkey(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn make_optimistic_receipt(seed: u8) -> OptimisticReceipt {
        let data = make_receipt_data(seed);
        let coord_id = make_coord_id(seed);
        let pubkey = make_pubkey(seed);
        let issued_at = 1700000000u64;

        let signature = create_placeholder_signature(&data, issued_at, &coord_id, &pubkey);

        OptimisticReceipt::with_timestamp(
            data,
            signature,
            coord_id,
            pubkey,
            Duration::from_secs(300),
            issued_at,
        )
    }

    fn make_threshold_receipt(seed: u8, signers: Vec<u8>) -> ThresholdReceipt {
        let data = make_receipt_data(seed);
        let signer_ids: Vec<_> = signers.iter().map(|&s| make_common_coord_id(s)).collect();

        ThresholdReceipt::new(
            data,
            AggregateSignature::from_bytes(&[0x01; 129]).expect("valid aggregate"),
            signer_ids,
            [0xFF; 32],
        )
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // OptimisticReceiptError Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_error_display_already_upgraded() {
        let err = OptimisticReceiptError::AlreadyUpgraded;
        assert!(err.to_string().contains("already upgraded"));
    }

    #[test]
    fn test_error_display_data_mismatch() {
        let err = OptimisticReceiptError::DataMismatch {
            field: "workload_id".to_string(),
        };
        assert!(err.to_string().contains("workload_id"));
    }

    #[test]
    fn test_error_display_not_committee_member() {
        let err = OptimisticReceiptError::NotCommitteeMember {
            coordinator: make_coord_id(0x01),
        };
        assert!(err.to_string().contains("not a committee member"));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Construction Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_new_sets_upgraded_false() {
        let receipt = make_optimistic_receipt(0x01);
        assert!(!receipt.is_upgraded());
    }

    #[test]
    fn test_new_with_timestamp() {
        let data = make_receipt_data(0x01);
        let coord_id = make_coord_id(0x01);
        let pubkey = make_pubkey(0x01);
        let issued_at = 1234567890u64;

        let receipt = OptimisticReceipt::with_timestamp(
            data,
            [0xAA; 64],
            coord_id,
            pubkey,
            Duration::from_secs(300),
            issued_at,
        );

        assert_eq!(receipt.issued_at(), issued_at);
        assert!(!receipt.is_upgraded());
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Getter Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_getters() {
        let receipt = make_optimistic_receipt(0x01);

        assert_eq!(receipt.coordinator_id().as_bytes(), &[0x01; 32]);
        assert_eq!(receipt.coordinator_pubkey(), &[0x01; 32]);
        assert_eq!(receipt.issued_at(), 1700000000);
        assert_eq!(receipt.challenge_window(), Duration::from_secs(300));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Signature Verification Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_verify_signature_valid() {
        let receipt = make_optimistic_receipt(0x01);
        assert!(receipt.verify_signature());
    }

    #[test]
    fn test_verify_signature_invalid_zero_signature() {
        let data = make_receipt_data(0x01);
        let coord_id = make_coord_id(0x01);
        let pubkey = make_pubkey(0x01);

        let receipt = OptimisticReceipt::with_timestamp(
            data,
            [0x00; 64], // All zeros = invalid
            coord_id,
            pubkey,
            Duration::from_secs(300),
            1700000000,
        );

        assert!(!receipt.verify_signature());
    }

    #[test]
    fn test_verify_signature_invalid_zero_pubkey() {
        let data = make_receipt_data(0x01);
        let coord_id = make_coord_id(0x01);
        let issued_at = 1700000000u64;
        let pubkey = [0x00; 32]; // All zeros

        let signature = create_placeholder_signature(&data, issued_at, &coord_id, &[0x01; 32]);

        let receipt = OptimisticReceipt::with_timestamp(
            data,
            signature,
            coord_id,
            pubkey,
            Duration::from_secs(300),
            issued_at,
        );

        assert!(!receipt.verify_signature());
    }

    #[test]
    fn test_verify_signature_wrong_signature() {
        let data = make_receipt_data(0x01);
        let coord_id = make_coord_id(0x01);
        let pubkey = make_pubkey(0x01);

        let receipt = OptimisticReceipt::with_timestamp(
            data,
            [0xDE; 64], // Wrong signature
            coord_id,
            pubkey,
            Duration::from_secs(300),
            1700000000,
        );

        assert!(!receipt.verify_signature());
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Challenge Window Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_challenge_deadline() {
        let receipt = make_optimistic_receipt(0x01);
        let deadline = receipt.challenge_deadline().unwrap();

        // 1700000000 + 300000 (300 seconds in ms)
        assert_eq!(deadline, 1700000000 + 300_000);
    }

    #[test]
    fn test_challenge_deadline_overflow() {
        let data = make_receipt_data(0x01);
        let coord_id = make_coord_id(0x01);
        let pubkey = make_pubkey(0x01);

        let receipt = OptimisticReceipt::with_timestamp(
            data,
            [0x01; 64],
            coord_id,
            pubkey,
            Duration::from_millis(u64::MAX), // Will overflow
            u64::MAX - 1000,
        );

        assert!(matches!(
            receipt.challenge_deadline(),
            Err(OptimisticReceiptError::DeadlineOverflow)
        ));
    }

    #[test]
    fn test_is_challengeable_within_window() {
        let receipt = make_optimistic_receipt(0x01);
        let now = 1700000000 + 100_000; // 100 seconds after

        assert!(receipt.is_challengeable(now));
    }

    #[test]
    fn test_is_challengeable_at_deadline() {
        let receipt = make_optimistic_receipt(0x01);
        let deadline = receipt.challenge_deadline().unwrap();

        assert!(receipt.is_challengeable(deadline));
    }

    #[test]
    fn test_is_challengeable_after_deadline() {
        let receipt = make_optimistic_receipt(0x01);
        let deadline = receipt.challenge_deadline().unwrap();

        assert!(!receipt.is_challengeable(deadline + 1));
    }

    #[test]
    fn test_is_challengeable_false_when_upgraded() {
        let mut receipt = make_optimistic_receipt(0x01);
        let threshold = make_threshold_receipt(0x01, vec![0x01, 0x02]);

        // Upgrade first
        let _ = receipt.upgrade_to_threshold(threshold);

        // Now should not be challengeable even within window
        let now = 1700000000 + 100_000;
        assert!(!receipt.is_challengeable(now));
    }

    #[test]
    fn test_is_expired() {
        let receipt = make_optimistic_receipt(0x01);
        let deadline = receipt.challenge_deadline().unwrap();

        assert!(!receipt.is_expired(deadline));
        assert!(receipt.is_expired(deadline + 1));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Upgrade Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_upgrade_success() {
        let mut receipt = make_optimistic_receipt(0x01);
        let threshold = make_threshold_receipt(0x01, vec![0x01, 0x02, 0x03]);

        let result = receipt.upgrade_to_threshold(threshold);

        assert!(result.is_ok());
        assert!(receipt.is_upgraded());
    }

    #[test]
    fn test_upgrade_already_upgraded() {
        let mut receipt = make_optimistic_receipt(0x01);
        let threshold1 = make_threshold_receipt(0x01, vec![0x01, 0x02]);
        let threshold2 = make_threshold_receipt(0x01, vec![0x01, 0x02]);

        // First upgrade
        let _ = receipt.upgrade_to_threshold(threshold1);

        // Second upgrade should fail
        let result = receipt.upgrade_to_threshold(threshold2);

        assert!(matches!(result, Err(OptimisticReceiptError::AlreadyUpgraded)));
    }

    #[test]
    fn test_upgrade_data_mismatch_workload_id() {
        let mut receipt = make_optimistic_receipt(0x01);
        let threshold = make_threshold_receipt(0x02, vec![0x01, 0x02]); // Different seed

        let result = receipt.upgrade_to_threshold(threshold);

        assert!(matches!(
            result,
            Err(OptimisticReceiptError::DataMismatch { field }) if field == "workload_id"
        ));
        assert!(!receipt.is_upgraded()); // State unchanged
    }

    #[test]
    fn test_upgrade_not_committee_member() {
        let mut receipt = make_optimistic_receipt(0x01);
        let threshold = make_threshold_receipt(0x01, vec![0x02, 0x03]); // 0x01 not in signers

        let result = receipt.upgrade_to_threshold(threshold);

        assert!(matches!(
            result,
            Err(OptimisticReceiptError::NotCommitteeMember { .. })
        ));
        assert!(!receipt.is_upgraded()); // State unchanged
    }

    #[test]
    fn test_upgrade_no_state_change_on_failure() {
        let mut receipt = make_optimistic_receipt(0x01);
        let invalid_threshold = make_threshold_receipt(0x02, vec![0x01]); // Wrong data

        let result = receipt.upgrade_to_threshold(invalid_threshold);

        assert!(result.is_err());
        assert!(!receipt.is_upgraded()); // CRITICAL: state must not change on failure
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Determinism Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_signing_message_deterministic() {
        let receipt1 = make_optimistic_receipt(0x01);
        let receipt2 = make_optimistic_receipt(0x01);

        let msg1 = receipt1.build_signing_message();
        let msg2 = receipt2.build_signing_message();

        assert_eq!(msg1, msg2);
    }

    #[test]
    fn test_challenge_deadline_deterministic() {
        let receipt1 = make_optimistic_receipt(0x01);
        let receipt2 = make_optimistic_receipt(0x01);

        assert_eq!(
            receipt1.challenge_deadline().unwrap(),
            receipt2.challenge_deadline().unwrap()
        );
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Debug Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_debug_impl() {
        let receipt = make_optimistic_receipt(0x01);
        let debug = format!("{:?}", receipt);

        assert!(debug.contains("OptimisticReceipt"));
        assert!(debug.contains("upgraded"));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Helper Function Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_create_placeholder_signature() {
        let data = make_receipt_data(0x01);
        let coord_id = make_coord_id(0x01);
        let pubkey = make_pubkey(0x01);
        let issued_at = 1700000000u64;

        let sig1 = create_placeholder_signature(&data, issued_at, &coord_id, &pubkey);
        let sig2 = create_placeholder_signature(&data, issued_at, &coord_id, &pubkey);

        // Should be deterministic
        assert_eq!(sig1, sig2);

        // Should not be all zeros
        assert!(!sig1.iter().all(|&b| b == 0));
    }
}