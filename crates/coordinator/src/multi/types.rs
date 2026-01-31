//! Multi-Coordinator Base Types (14A.2B.2.11)
//!
//! Module ini mendefinisikan base types untuk sistem multi-coordinator.
//!
//! # Types
//!
//! | Type | Fungsi |
//! |------|--------|
//! | `CoordinatorId` | Identifier unik untuk coordinator instance |
//! | `KeyShare` | Key share untuk threshold signing |
//! | `SessionId` | Identifier unik untuk signing session |
//! | `WorkloadId` | Identifier unik untuk workload/task |
//! | `Vote` | Vote dari coordinator untuk receipt approval |
//! | `PendingReceipt` | Receipt yang menunggu voting dari coordinators |
//!
//! # Invariants
//!
//! - Semua ID types adalah 32 bytes
//! - SessionId generation menggunakan SHA3-256 hash untuk uniqueness
//! - Vote signature adalah Ed25519 (64 bytes)

use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

// Import ReceiptData dari dsdn_common
use dsdn_common::coordinator::ReceiptData;

// ════════════════════════════════════════════════════════════════════════════════
// SERDE MODULE FOR [u8; 64]
// ════════════════════════════════════════════════════════════════════════════════

/// Custom serde module untuk arrays > 32 bytes.
mod serde_signature {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(data: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize as array of bytes
        data.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec: Vec<u8> = Vec::deserialize(deserializer)?;
        if vec.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "expected 64 bytes, got {}",
                vec.len()
            )));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&vec);
        Ok(arr)
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// COORDINATOR ID
// ════════════════════════════════════════════════════════════════════════════════

/// Identifier unik untuk coordinator instance.
///
/// 32-byte array yang mengidentifikasi coordinator dalam sistem multi-coordinator.
///
/// # Example
///
/// ```ignore
/// let id = CoordinatorId::new([0x01; 32]);
/// let bytes = id.as_bytes();
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinatorId([u8; 32]);

impl CoordinatorId {
    /// Membuat CoordinatorId baru dari array 32 bytes.
    #[must_use]
    #[inline]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Mengembalikan reference ke inner bytes.
    #[must_use]
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consume self dan mengembalikan inner bytes.
    #[must_use]
    #[inline]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl Hash for CoordinatorId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl From<[u8; 32]> for CoordinatorId {
    fn from(bytes: [u8; 32]) -> Self {
        Self::new(bytes)
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// KEY SHARE
// ════════════════════════════════════════════════════════════════════════════════

/// Key share untuk threshold signing dalam multi-coordinator setup.
///
/// Setiap coordinator memegang satu key share yang digunakan untuk
/// berpartisipasi dalam threshold signature scheme.
///
/// # Fields
///
/// - `index` - Index share dalam threshold scheme (1-indexed)
/// - `share` - Encrypted key share bytes
/// - `pubkey` - Public key untuk share ini
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyShare {
    /// Index share dalam threshold scheme (1-indexed).
    pub index: u8,

    /// Encrypted key share bytes.
    pub share: Vec<u8>,

    /// Public key untuk share ini (32 bytes).
    pub pubkey: [u8; 32],
}

impl KeyShare {
    /// Membuat KeyShare baru.
    #[must_use]
    pub fn new(index: u8, share: Vec<u8>, pubkey: [u8; 32]) -> Self {
        Self {
            index,
            share,
            pubkey,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// SESSION ID
// ════════════════════════════════════════════════════════════════════════════════

/// Identifier unik untuk signing session.
///
/// SessionId digunakan untuk mengidentifikasi satu sesi threshold signing
/// secara unik. Setiap session memiliki ID yang berbeda untuk mencegah
/// replay attacks dan memastikan freshness.
///
/// # Uniqueness
///
/// SessionId di-generate menggunakan SHA3-256 hash dari kombinasi:
/// - Timestamp dalam nanoseconds
/// - Atomic counter (monotonically increasing)
/// - Thread ID
/// - Stack pointer address (pseudo-random)
///
/// Ini menjamin uniqueness dengan probabilitas collision yang sangat rendah.
///
/// # Example
///
/// ```ignore
/// let session_id = SessionId::generate();
/// let bytes = session_id.as_bytes();
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionId([u8; 32]);

impl SessionId {
    /// Membuat SessionId dari array 32 bytes yang sudah ada.
    ///
    /// Gunakan method ini untuk deserialize atau reconstruct SessionId.
    /// Untuk membuat SessionId baru yang unik, gunakan `generate()`.
    #[must_use]
    #[inline]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Generate SessionId baru yang unik.
    ///
    /// Menggunakan kombinasi timestamp dan counter untuk menjamin
    /// uniqueness, kemudian di-hash dengan SHA3-256.
    ///
    /// # Returns
    ///
    /// SessionId baru yang unik. Fungsi ini tidak akan gagal.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let session_id = SessionId::generate();
    /// ```
    #[must_use]
    pub fn generate() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        
        // Static counter untuk tambahan uniqueness
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        
        let mut hasher = Sha3_256::new();
        
        // Input 1: timestamp dalam nanoseconds
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        hasher.update(timestamp.to_le_bytes());
        
        // Input 2: atomic counter (monotonically increasing)
        let counter = COUNTER.fetch_add(1, Ordering::SeqCst);
        hasher.update(counter.to_le_bytes());
        
        // Input 3: thread id untuk additional entropy
        let thread_id = std::thread::current().id();
        hasher.update(format!("{:?}", thread_id).as_bytes());
        
        // Input 4: pointer address sebagai pseudo-random
        let stack_var = 0u8;
        let ptr_val = &stack_var as *const u8 as u64;
        hasher.update(ptr_val.to_le_bytes());
        
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        
        Self(bytes)
    }

    /// Mengembalikan reference ke inner bytes.
    #[must_use]
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consume self dan mengembalikan inner bytes.
    #[must_use]
    #[inline]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl Hash for SessionId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl From<[u8; 32]> for SessionId {
    fn from(bytes: [u8; 32]) -> Self {
        Self::new(bytes)
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// WORKLOAD ID
// ════════════════════════════════════════════════════════════════════════════════

/// Identifier unik untuk workload/task.
///
/// 32-byte array yang mengidentifikasi workload dalam sistem DSDN.
///
/// # Example
///
/// ```ignore
/// let workload_id = WorkloadId::new([0x01; 32]);
/// let bytes = workload_id.as_bytes();
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadId([u8; 32]);

impl WorkloadId {
    /// Membuat WorkloadId baru dari array 32 bytes.
    #[must_use]
    #[inline]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Mengembalikan reference ke inner bytes.
    #[must_use]
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consume self dan mengembalikan inner bytes.
    #[must_use]
    #[inline]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl Hash for WorkloadId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl From<[u8; 32]> for WorkloadId {
    fn from(bytes: [u8; 32]) -> Self {
        Self::new(bytes)
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// VOTE
// ════════════════════════════════════════════════════════════════════════════════

/// Vote dari coordinator untuk receipt approval.
///
/// Setiap coordinator dalam multi-coordinator setup memberikan vote
/// untuk menyetujui atau menolak receipt. Vote ditandatangani dengan
/// Ed25519 untuk membuktikan authenticity.
///
/// # Fields
///
/// - `approve` - true jika menyetujui, false jika menolak
/// - `timestamp` - Unix timestamp saat vote di-cast
/// - `signature` - Ed25519 signature (64 bytes) atas receipt data hash
///
/// # Verification
///
/// Vote valid jika:
/// 1. Signature valid terhadap public key coordinator
/// 2. Timestamp dalam acceptable range (tidak terlalu lama)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vote {
    /// Keputusan: true = approve, false = reject.
    pub approve: bool,

    /// Unix timestamp saat vote di-cast.
    pub timestamp: u64,

    /// Ed25519 signature (64 bytes) atas receipt data hash.
    #[serde(with = "serde_signature")]
    pub signature: [u8; 64],
}

impl Vote {
    /// Membuat Vote baru.
    #[must_use]
    pub const fn new(approve: bool, timestamp: u64, signature: [u8; 64]) -> Self {
        Self {
            approve,
            timestamp,
            signature,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// PENDING RECEIPT
// ════════════════════════════════════════════════════════════════════════════════

/// Receipt yang menunggu voting dari coordinators.
///
/// PendingReceipt menyimpan receipt data beserta votes yang sudah
/// dikumpulkan dari berbagai coordinator. Setelah threshold votes
/// tercapai, receipt dapat di-finalize.
///
/// # Fields
///
/// - `workload_id` - Identifier workload yang terkait
/// - `data` - Receipt data yang akan di-sign
/// - `received_at` - Unix timestamp saat receipt diterima
/// - `votes` - Map dari CoordinatorId ke Vote
///
/// # Lifecycle
///
/// 1. Receipt dibuat dan ditambahkan ke pending queue
/// 2. Coordinators memberikan votes
/// 3. Setelah threshold tercapai, receipt di-finalize
/// 4. Jika timeout, receipt di-expire
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingReceipt {
    /// Identifier workload yang terkait.
    pub workload_id: WorkloadId,

    /// Receipt data yang akan di-sign.
    pub data: ReceiptData,

    /// Unix timestamp saat receipt diterima.
    pub received_at: u64,

    /// Map dari CoordinatorId ke Vote.
    pub votes: HashMap<CoordinatorId, Vote>,
}

impl PendingReceipt {
    /// Membuat PendingReceipt baru tanpa votes.
    #[must_use]
    pub fn new(workload_id: WorkloadId, data: ReceiptData, received_at: u64) -> Self {
        Self {
            workload_id,
            data,
            received_at,
            votes: HashMap::new(),
        }
    }

    /// Menambahkan vote dari coordinator.
    ///
    /// Jika coordinator sudah pernah vote, vote lama akan di-replace.
    pub fn add_vote(&mut self, coordinator_id: CoordinatorId, vote: Vote) {
        self.votes.insert(coordinator_id, vote);
    }

    /// Menghitung jumlah approval votes.
    #[must_use]
    pub fn approval_count(&self) -> usize {
        self.votes.values().filter(|v| v.approve).count()
    }

    /// Menghitung jumlah rejection votes.
    #[must_use]
    pub fn rejection_count(&self) -> usize {
        self.votes.values().filter(|v| !v.approve).count()
    }

    /// Memeriksa apakah threshold approval tercapai.
    #[must_use]
    pub fn has_quorum(&self, threshold: usize) -> bool {
        self.approval_count() >= threshold
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coordinator_id_new_and_getters() {
        let bytes = [0x42u8; 32];
        let id = CoordinatorId::new(bytes);

        assert_eq!(id.as_bytes(), &bytes);
        assert_eq!(id.into_bytes(), bytes);
    }

    #[test]
    fn test_coordinator_id_hash() {
        use std::collections::HashSet;

        let id1 = CoordinatorId::new([0x01; 32]);
        let id2 = CoordinatorId::new([0x02; 32]);
        let id3 = CoordinatorId::new([0x01; 32]);

        let mut set = HashSet::new();
        set.insert(id1.clone());
        set.insert(id2);
        set.insert(id3);

        assert_eq!(set.len(), 2); // id1 and id3 are equal
    }

    #[test]
    fn test_coordinator_id_from() {
        let bytes = [0x33u8; 32];
        let id: CoordinatorId = bytes.into();

        assert_eq!(id.as_bytes(), &bytes);
    }

    #[test]
    fn test_key_share_new() {
        let share = KeyShare::new(1, vec![0x01, 0x02, 0x03], [0x44; 32]);

        assert_eq!(share.index, 1);
        assert_eq!(share.share, vec![0x01, 0x02, 0x03]);
        assert_eq!(share.pubkey, [0x44; 32]);
    }

    #[test]
    fn test_session_id_generate_unique() {
        let id1 = SessionId::generate();
        let id2 = SessionId::generate();

        // Two generated IDs should be different
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_session_id_new_and_getters() {
        let bytes = [0x55u8; 32];
        let id = SessionId::new(bytes);

        assert_eq!(id.as_bytes(), &bytes);
        assert_eq!(id.into_bytes(), bytes);
    }

    #[test]
    fn test_session_id_hash() {
        use std::collections::HashSet;

        let id1 = SessionId::new([0x01; 32]);
        let id2 = SessionId::new([0x02; 32]);

        let mut set = HashSet::new();
        set.insert(id1);
        set.insert(id2);

        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_workload_id_new_and_getters() {
        let bytes = [0x66u8; 32];
        let id = WorkloadId::new(bytes);

        assert_eq!(id.as_bytes(), &bytes);
        assert_eq!(id.into_bytes(), bytes);
    }

    #[test]
    fn test_workload_id_hash() {
        use std::collections::HashSet;

        let id1 = WorkloadId::new([0x01; 32]);
        let id2 = WorkloadId::new([0x01; 32]);

        let mut set = HashSet::new();
        set.insert(id1);
        set.insert(id2);

        assert_eq!(set.len(), 1); // Same bytes = same hash
    }

    #[test]
    fn test_vote_new() {
        let vote = Vote::new(true, 1700000000, [0x77; 64]);

        assert!(vote.approve);
        assert_eq!(vote.timestamp, 1700000000);
        assert_eq!(vote.signature, [0x77; 64]);
    }

    #[test]
    fn test_pending_receipt_add_vote() {
        use dsdn_common::coordinator::WorkloadId as CommonWorkloadId;

        let workload_id = WorkloadId::new([0x01; 32]);
        let common_workload_id = CommonWorkloadId::new([0x01; 32]);
        let receipt_data = ReceiptData::new(
            common_workload_id,
            [0x02; 32],
            vec![],
            1700000000,
            1,
            1,
        );

        let mut pending = PendingReceipt::new(workload_id, receipt_data, 1700000000);

        assert_eq!(pending.votes.len(), 0);
        assert_eq!(pending.approval_count(), 0);
        assert_eq!(pending.rejection_count(), 0);

        // Add approval vote
        let coord1 = CoordinatorId::new([0x10; 32]);
        let vote1 = Vote::new(true, 1700000001, [0xAA; 64]);
        pending.add_vote(coord1, vote1);

        assert_eq!(pending.votes.len(), 1);
        assert_eq!(pending.approval_count(), 1);
        assert_eq!(pending.rejection_count(), 0);

        // Add rejection vote
        let coord2 = CoordinatorId::new([0x20; 32]);
        let vote2 = Vote::new(false, 1700000002, [0xBB; 64]);
        pending.add_vote(coord2, vote2);

        assert_eq!(pending.votes.len(), 2);
        assert_eq!(pending.approval_count(), 1);
        assert_eq!(pending.rejection_count(), 1);
    }

    #[test]
    fn test_pending_receipt_has_quorum() {
        use dsdn_common::coordinator::WorkloadId as CommonWorkloadId;

        let workload_id = WorkloadId::new([0x01; 32]);
        let common_workload_id = CommonWorkloadId::new([0x01; 32]);
        let receipt_data = ReceiptData::new(
            common_workload_id,
            [0x02; 32],
            vec![],
            1700000000,
            1,
            1,
        );

        let mut pending = PendingReceipt::new(workload_id, receipt_data, 1700000000);

        // Threshold 2, currently 0 approvals
        assert!(!pending.has_quorum(2));

        // Add 1 approval
        pending.add_vote(
            CoordinatorId::new([0x10; 32]),
            Vote::new(true, 1700000001, [0xAA; 64]),
        );
        assert!(!pending.has_quorum(2));

        // Add 1 rejection (doesn't count)
        pending.add_vote(
            CoordinatorId::new([0x20; 32]),
            Vote::new(false, 1700000002, [0xBB; 64]),
        );
        assert!(!pending.has_quorum(2));

        // Add another approval
        pending.add_vote(
            CoordinatorId::new([0x30; 32]),
            Vote::new(true, 1700000003, [0xCC; 64]),
        );
        assert!(pending.has_quorum(2)); // Now 2 approvals >= threshold
    }

    #[test]
    fn test_pending_receipt_replace_vote() {
        use dsdn_common::coordinator::WorkloadId as CommonWorkloadId;

        let workload_id = WorkloadId::new([0x01; 32]);
        let common_workload_id = CommonWorkloadId::new([0x01; 32]);
        let receipt_data = ReceiptData::new(
            common_workload_id,
            [0x02; 32],
            vec![],
            1700000000,
            1,
            1,
        );

        let mut pending = PendingReceipt::new(workload_id, receipt_data, 1700000000);

        let coord = CoordinatorId::new([0x10; 32]);

        // Initial rejection
        pending.add_vote(coord.clone(), Vote::new(false, 1700000001, [0xAA; 64]));
        assert_eq!(pending.rejection_count(), 1);
        assert_eq!(pending.approval_count(), 0);

        // Replace with approval
        pending.add_vote(coord, Vote::new(true, 1700000002, [0xBB; 64]));
        assert_eq!(pending.votes.len(), 1); // Still 1 vote
        assert_eq!(pending.rejection_count(), 0);
        assert_eq!(pending.approval_count(), 1);
    }
}