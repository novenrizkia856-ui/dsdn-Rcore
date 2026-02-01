//! CoordinatorAccountability — audit trail untuk coordinator decisions (14A.2B.2.29).
//!
//! Accountability logging yang deterministik, dapat diverifikasi,
//! dan dapat dijadikan bukti dispute.
//!
//! ## Design Principles
//!
//! - Semua keputusan coordinator tercatat permanen
//! - Dapat diverifikasi ulang (Merkle proof)
//! - Deterministic di semua node
//! - Tidak ada akses state eksternal
//! - Tidak ada IO / network / randomness
//!
//! ## Usage Flow
//!
//! ```text
//! 1. CoordinatorAccountability::new(id, epoch)
//! 2. accountability.log_decision(decision)           // append ke audit log
//! 3. accountability.verify_decision(&decision)       // verifikasi Merkle proof
//! 4. accountability.generate_proof(workload_id)      // generate AccountabilityProof
//! 5. accountability.get_decisions_in_range(from, to) // query by block_height
//! ```

use dsdn_common::coordinator::{CoordinatorId, DAMerkleProof, ReceiptData, WorkloadId};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

// ════════════════════════════════════════════════════════════════════════════════
// ACCOUNTABLE DECISION
// ════════════════════════════════════════════════════════════════════════════════

/// Satu keputusan coordinator yang tercatat dalam audit trail.
///
/// Setiap decision menyimpan:
/// - Workload apa yang diproses (`workload_id`)
/// - Data keputusan (`decision` — ReceiptData)
/// - Bukti DA commitment (`merkle_proof`)
/// - Kapan (`timestamp`) dan di block mana (`block_height`)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountableDecision {
    workload_id: WorkloadId,
    decision: ReceiptData,
    merkle_proof: DAMerkleProof,
    timestamp: u64,
    block_height: u64,
}

impl AccountableDecision {
    /// Membuat `AccountableDecision` baru.
    ///
    /// Semua field wajib diisi. Tidak ada validasi implisit —
    /// data disimpan apa adanya.
    #[must_use]
    pub fn new(
        workload_id: WorkloadId,
        decision: ReceiptData,
        merkle_proof: DAMerkleProof,
        timestamp: u64,
        block_height: u64,
    ) -> Self {
        Self {
            workload_id,
            decision,
            merkle_proof,
            timestamp,
            block_height,
        }
    }

    /// Workload ID yang diproses.
    #[must_use]
    #[inline]
    pub fn workload_id(&self) -> &WorkloadId {
        &self.workload_id
    }

    /// Receipt data keputusan.
    #[must_use]
    #[inline]
    pub fn decision(&self) -> &ReceiptData {
        &self.decision
    }

    /// Merkle proof dari DA layer.
    #[must_use]
    #[inline]
    pub fn merkle_proof(&self) -> &DAMerkleProof {
        &self.merkle_proof
    }

    /// Timestamp pembuatan keputusan (Unix seconds).
    #[must_use]
    #[inline]
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Block height saat keputusan tercatat.
    #[must_use]
    #[inline]
    pub fn block_height(&self) -> u64 {
        self.block_height
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// ACCOUNTABILITY PROOF
// ════════════════════════════════════════════════════════════════════════════════

/// Bukti accountability untuk satu coordinator decision.
///
/// `proof_hash` dihitung secara deterministik:
/// ```text
/// SHA3-256(coordinator_id ‖ epoch ‖ workload_id ‖ receipt_data_hash ‖ block_height)
/// ```
///
/// Proof ini dapat diverifikasi oleh siapapun tanpa akses ke state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountabilityProof {
    coordinator_id: CoordinatorId,
    epoch: u64,
    decision: AccountableDecision,
    proof_hash: [u8; 32],
}

impl AccountabilityProof {
    /// Coordinator yang membuat keputusan.
    #[must_use]
    #[inline]
    pub fn coordinator_id(&self) -> &CoordinatorId {
        &self.coordinator_id
    }

    /// Epoch saat keputusan dibuat.
    #[must_use]
    #[inline]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Decision yang dibuktikan.
    #[must_use]
    #[inline]
    pub fn decision(&self) -> &AccountableDecision {
        &self.decision
    }

    /// Hash bukti — SHA3-256 deterministik dari semua komponen.
    #[must_use]
    #[inline]
    pub fn proof_hash(&self) -> &[u8; 32] {
        &self.proof_hash
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// COORDINATOR ACCOUNTABILITY
// ════════════════════════════════════════════════════════════════════════════════

/// Accountability log untuk satu coordinator dalam satu epoch.
///
/// Menyimpan semua keputusan secara append-only.
/// Insertion order dipertahankan untuk determinism.
///
/// ## Guarantees
///
/// - `new()`: empty decisions, no implicit validation
/// - `log_decision()`: append-only, preserves insertion order
/// - `verify_decision()`: pure Merkle verification, no state access
/// - `generate_proof()`: deterministic, picks EARLIEST match
/// - `get_decisions_in_range()`: preserves insertion order, no clone
pub struct CoordinatorAccountability {
    coordinator_id: CoordinatorId,
    epoch: u64,
    decisions: Vec<AccountableDecision>,
}

impl CoordinatorAccountability {
    /// Membuat accountability log baru untuk coordinator di epoch tertentu.
    ///
    /// `decisions` diinisialisasi kosong.
    /// Tidak ada validasi implisit pada `epoch`.
    #[must_use]
    pub fn new(coordinator_id: CoordinatorId, epoch: u64) -> Self {
        Self {
            coordinator_id,
            epoch,
            decisions: Vec::new(),
        }
    }

    /// Mencatat keputusan ke audit log.
    ///
    /// Decision disimpan apa adanya, append-only.
    /// Urutan insertion deterministik (push ke akhir Vec).
    /// Duplicate `workload_id` diperbolehkan — ini adalah audit log,
    /// bukan state container.
    pub fn log_decision(&mut self, decision: AccountableDecision) {
        self.decisions.push(decision);
    }

    /// Verifikasi Merkle proof terhadap decision data.
    ///
    /// PURE: tidak mengakses state eksternal, deterministik.
    ///
    /// ## Verification Steps
    ///
    /// 1. Compute leaf hash dari `decision.decision` via `receipt_data_hash()`
    /// 2. Traverse `merkle_proof.path` menggunakan `merkle_proof.index` bits
    ///    - bit 0: current adalah LEFT child → SHA3-256(current ‖ sibling)
    ///    - bit 1: current adalah RIGHT child → SHA3-256(sibling ‖ current)
    /// 3. Bandingkan computed root dengan `merkle_proof.root`
    ///
    /// ## Returns
    ///
    /// `true` jika proof valid, `false` jika invalid atau tidak bisa diverifikasi.
    #[must_use]
    pub fn verify_decision(&self, decision: &AccountableDecision) -> bool {
        // Step 1: Compute leaf hash dari ReceiptData
        let leaf = decision.decision.receipt_data_hash();

        // Step 2: Verify Merkle proof
        verify_merkle_proof_sha3_256(&leaf, &decision.merkle_proof)
    }

    /// Generate accountability proof untuk workload tertentu.
    ///
    /// Jika ada lebih dari satu decision untuk `workload_id`,
    /// ambil yang **PALING AWAL** (index terkecil = insertion pertama).
    ///
    /// `proof_hash` dihitung deterministik:
    /// ```text
    /// SHA3-256(coordinator_id ‖ epoch ‖ workload_id ‖ receipt_data_hash ‖ block_height)
    /// ```
    ///
    /// ## Returns
    ///
    /// `Some(AccountabilityProof)` jika decision ditemukan, `None` jika tidak ada.
    #[must_use]
    pub fn generate_proof(
        &self,
        workload_id: WorkloadId,
    ) -> Option<AccountabilityProof> {
        // Find FIRST (paling awal) decision untuk workload_id
        let decision = self
            .decisions
            .iter()
            .find(|d| d.workload_id == workload_id)?;

        // Compute proof_hash: SHA3-256(coordinator_id || epoch || workload_id || decision || block_height)
        let proof_hash = compute_proof_hash(
            &self.coordinator_id,
            self.epoch,
            &decision.workload_id,
            &decision.decision,
            decision.block_height,
        );

        Some(AccountabilityProof {
            coordinator_id: self.coordinator_id,
            epoch: self.epoch,
            decision: decision.clone(),
            proof_hash,
        })
    }

    /// Query decisions berdasarkan range block_height.
    ///
    /// Filter: `from <= block_height <= to` (inclusive both ends).
    /// Output order SAMA dengan urutan insertion (deterministic).
    /// Tidak melakukan clone — mengembalikan references.
    #[must_use]
    pub fn get_decisions_in_range(&self, from: u64, to: u64) -> Vec<&AccountableDecision> {
        self.decisions
            .iter()
            .filter(|d| d.block_height >= from && d.block_height <= to)
            .collect()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// PRIVATE — MERKLE PROOF VERIFICATION
// ════════════════════════════════════════════════════════════════════════════════

/// Verify Merkle proof menggunakan SHA3-256.
///
/// Algorithm sesuai `DAMerkleProof` documentation:
/// 1. Start dari leaf hash
/// 2. Untuk setiap sibling di `path`:
///    - bit 0 dari index → current = LEFT child → SHA3-256(current ‖ sibling)
///    - bit 1 dari index → current = RIGHT child → SHA3-256(sibling ‖ current)
///    - shift index right
/// 3. Hasil akhir harus sama dengan `root`
///
/// Edge case: path kosong → leaf harus sama dengan root (single-element tree).
fn verify_merkle_proof_sha3_256(leaf: &[u8; 32], proof: &DAMerkleProof) -> bool {
    // Edge case: empty path means leaf IS the root
    if proof.path.is_empty() {
        return *leaf == proof.root;
    }

    let mut current = *leaf;
    let mut index = proof.index;

    for sibling in &proof.path {
        // Determine position berdasarkan bit terkecil dari index
        if index & 1 == 0 {
            // Current is LEFT child → hash(current || sibling)
            current = sha3_256_pair(&current, sibling);
        } else {
            // Current is RIGHT child → hash(sibling || current)
            current = sha3_256_pair(sibling, &current);
        }

        // Move to parent level
        index >>= 1;
    }

    // Compare computed root dengan expected root
    current == proof.root
}

// ════════════════════════════════════════════════════════════════════════════════
// PRIVATE — HASH HELPERS
// ════════════════════════════════════════════════════════════════════════════════

/// SHA3-256(left ‖ right) — parent node hash computation.
///
/// Input: 64 bytes (32 + 32).
/// Output: 32 bytes.
fn sha3_256_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(left);
    hasher.update(right);

    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Compute proof_hash per kontrak:
/// ```text
/// SHA3-256(coordinator_id ‖ epoch ‖ workload_id ‖ decision ‖ block_height)
/// ```
///
/// Input breakdown:
/// - `coordinator_id`: 32 bytes
/// - `epoch`: 8 bytes (u64 little-endian)
/// - `workload_id`: 32 bytes
/// - `decision`: 32 bytes (via `receipt_data_hash()` — SHA3-256 of ReceiptData)
/// - `block_height`: 8 bytes (u64 little-endian)
///
/// Total input: 112 bytes → output: 32 bytes SHA3-256.
fn compute_proof_hash(
    coordinator_id: &CoordinatorId,
    epoch: u64,
    workload_id: &WorkloadId,
    decision: &ReceiptData,
    block_height: u64,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();

    // 1. coordinator_id (32 bytes)
    hasher.update(coordinator_id.as_bytes());

    // 2. epoch (8 bytes, little-endian)
    hasher.update(epoch.to_le_bytes());

    // 3. workload_id (32 bytes)
    hasher.update(workload_id.as_bytes());

    // 4. decision — receipt_data_hash() for deterministic fixed-size representation (32 bytes)
    hasher.update(decision.receipt_data_hash());

    // 5. block_height (8 bytes, little-endian)
    hasher.update(block_height.to_le_bytes());

    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Test helpers ─────────────────────────────────────────────

    fn test_coordinator_id() -> CoordinatorId {
        CoordinatorId::new([0xAA; 32])
    }

    fn test_workload_id(seed: u8) -> WorkloadId {
        WorkloadId::new([seed; 32])
    }

    fn test_receipt_data(seed: u8) -> ReceiptData {
        ReceiptData::new(
            test_workload_id(seed),
            [seed; 32],       // blob_hash
            vec![[seed; 32]], // placement (1 node)
            1000 + u64::from(seed),
            1,
            42,
        )
    }

    /// Build a valid Merkle proof for a single leaf using SHA3-256.
    /// Tree: root = SHA3-256(leaf || sibling)
    fn build_simple_merkle_proof(leaf: &[u8; 32]) -> DAMerkleProof {
        let sibling = [0xBB; 32];
        let root = sha3_256_pair(leaf, &sibling);
        DAMerkleProof {
            root,
            path: vec![sibling],
            index: 0, // leaf is left child
        }
    }

    fn test_decision(seed: u8, block_height: u64) -> AccountableDecision {
        let receipt = test_receipt_data(seed);
        let leaf = receipt.receipt_data_hash();
        let proof = build_simple_merkle_proof(&leaf);

        AccountableDecision::new(
            test_workload_id(seed),
            receipt,
            proof,
            1000 + u64::from(seed),
            block_height,
        )
    }

    // ── new() ───────────────────────────────────────────────────

    #[test]
    fn test_new_creates_empty_decisions() {
        let acc = CoordinatorAccountability::new(test_coordinator_id(), 42);
        assert!(acc.decisions.is_empty());
        assert_eq!(acc.epoch, 42);
    }

    // ── log_decision() ──────────────────────────────────────────

    #[test]
    fn test_log_decision_appends() {
        let mut acc = CoordinatorAccountability::new(test_coordinator_id(), 1);

        acc.log_decision(test_decision(0x01, 100));
        acc.log_decision(test_decision(0x02, 101));
        acc.log_decision(test_decision(0x03, 102));

        assert_eq!(acc.decisions.len(), 3);
    }

    #[test]
    fn test_log_decision_preserves_insertion_order() {
        let mut acc = CoordinatorAccountability::new(test_coordinator_id(), 1);

        acc.log_decision(test_decision(0x01, 100));
        acc.log_decision(test_decision(0x02, 101));
        acc.log_decision(test_decision(0x03, 102));

        assert_eq!(acc.decisions[0].block_height, 100);
        assert_eq!(acc.decisions[1].block_height, 101);
        assert_eq!(acc.decisions[2].block_height, 102);
    }

    #[test]
    fn test_log_decision_allows_duplicate_workload_id() {
        let mut acc = CoordinatorAccountability::new(test_coordinator_id(), 1);

        acc.log_decision(test_decision(0x01, 100));
        acc.log_decision(test_decision(0x01, 101)); // same workload, different block

        assert_eq!(acc.decisions.len(), 2);
    }

    // ── verify_decision() ───────────────────────────────────────

    #[test]
    fn test_verify_decision_valid_proof() {
        let acc = CoordinatorAccountability::new(test_coordinator_id(), 1);
        let decision = test_decision(0x01, 100);

        assert!(acc.verify_decision(&decision));
    }

    #[test]
    fn test_verify_decision_invalid_root() {
        let acc = CoordinatorAccountability::new(test_coordinator_id(), 1);
        let mut decision = test_decision(0x01, 100);

        // Tamper with root
        decision.merkle_proof.root = [0xFF; 32];

        assert!(!acc.verify_decision(&decision));
    }

    #[test]
    fn test_verify_decision_invalid_path() {
        let acc = CoordinatorAccountability::new(test_coordinator_id(), 1);
        let mut decision = test_decision(0x01, 100);

        // Tamper with path
        if let Some(first) = decision.merkle_proof.path.first_mut() {
            *first = [0xFF; 32];
        }

        assert!(!acc.verify_decision(&decision));
    }

    #[test]
    fn test_verify_decision_wrong_index() {
        let acc = CoordinatorAccountability::new(test_coordinator_id(), 1);
        let mut decision = test_decision(0x01, 100);

        // Flip index (was 0/left, now 1/right)
        decision.merkle_proof.index = 1;

        assert!(!acc.verify_decision(&decision));
    }

    #[test]
    fn test_verify_decision_empty_path_leaf_equals_root() {
        let acc = CoordinatorAccountability::new(test_coordinator_id(), 1);
        let receipt = test_receipt_data(0x01);
        let leaf = receipt.receipt_data_hash();

        let decision = AccountableDecision::new(
            test_workload_id(0x01),
            receipt,
            DAMerkleProof {
                root: leaf, // root == leaf for single-element tree
                path: vec![],
                index: 0,
            },
            1000,
            100,
        );

        assert!(acc.verify_decision(&decision));
    }

    #[test]
    fn test_verify_decision_empty_path_leaf_not_root() {
        let acc = CoordinatorAccountability::new(test_coordinator_id(), 1);
        let receipt = test_receipt_data(0x01);

        let decision = AccountableDecision::new(
            test_workload_id(0x01),
            receipt,
            DAMerkleProof {
                root: [0xFF; 32], // root != leaf
                path: vec![],
                index: 0,
            },
            1000,
            100,
        );

        assert!(!acc.verify_decision(&decision));
    }

    #[test]
    fn test_verify_decision_right_child() {
        let acc = CoordinatorAccountability::new(test_coordinator_id(), 1);
        let receipt = test_receipt_data(0x01);
        let leaf = receipt.receipt_data_hash();

        // Build proof where leaf is RIGHT child (index = 1)
        let sibling = [0xCC; 32];
        let root = sha3_256_pair(&sibling, &leaf); // hash(sibling || leaf)

        let decision = AccountableDecision::new(
            test_workload_id(0x01),
            receipt,
            DAMerkleProof {
                root,
                path: vec![sibling],
                index: 1, // right child
            },
            1000,
            100,
        );

        assert!(acc.verify_decision(&decision));
    }

    #[test]
    fn test_verify_decision_two_level_tree() {
        let acc = CoordinatorAccountability::new(test_coordinator_id(), 1);
        let receipt = test_receipt_data(0x01);
        let leaf = receipt.receipt_data_hash();

        // Build 2-level tree: leaf at index 2 (binary: 10)
        // Level 0: sibling_0 at index 3
        // Level 1: sibling_1 at index 0-1 subtree
        let sibling_0 = [0xDD; 32];
        let sibling_1 = [0xEE; 32];

        // Level 0: leaf is left (index bit 0 = 0) → parent = hash(leaf || sibling_0)
        let parent_0 = sha3_256_pair(&leaf, &sibling_0);
        // Level 1: parent is right (index bit 1 = 1) → root = hash(sibling_1 || parent_0)
        let root = sha3_256_pair(&sibling_1, &parent_0);

        let decision = AccountableDecision::new(
            test_workload_id(0x01),
            receipt,
            DAMerkleProof {
                root,
                path: vec![sibling_0, sibling_1],
                index: 2, // binary 10: bit0=0 (left), bit1=1 (right)
            },
            1000,
            100,
        );

        assert!(acc.verify_decision(&decision));
    }

    // ── generate_proof() ────────────────────────────────────────

    #[test]
    fn test_generate_proof_found() {
        let mut acc = CoordinatorAccountability::new(test_coordinator_id(), 42);
        acc.log_decision(test_decision(0x01, 100));

        let proof = acc.generate_proof(test_workload_id(0x01));
        assert!(proof.is_some());

        if let Some(ref p) = proof {
            assert_eq!(*p.coordinator_id(), test_coordinator_id());
            assert_eq!(p.epoch(), 42);
            assert_eq!(p.decision().block_height(), 100);

            // proof_hash must not be all zeros
            assert_ne!(*p.proof_hash(), [0u8; 32]);
        }
    }

    #[test]
    fn test_generate_proof_not_found() {
        let acc = CoordinatorAccountability::new(test_coordinator_id(), 1);
        assert!(acc.generate_proof(test_workload_id(0xFF)).is_none());
    }

    #[test]
    fn test_generate_proof_picks_earliest() {
        let mut acc = CoordinatorAccountability::new(test_coordinator_id(), 1);

        // Same workload_id, different block heights
        acc.log_decision(test_decision(0x01, 200)); // first inserted
        acc.log_decision(test_decision(0x01, 100)); // second inserted

        let proof = acc.generate_proof(test_workload_id(0x01));
        assert!(proof.is_some());

        if let Some(ref p) = proof {
            // Should pick the FIRST inserted (block_height=200), not the lower block_height
            assert_eq!(p.decision().block_height(), 200);
        }
    }

    #[test]
    fn test_generate_proof_deterministic() {
        let mut acc = CoordinatorAccountability::new(test_coordinator_id(), 42);
        acc.log_decision(test_decision(0x01, 100));

        let proof1 = acc.generate_proof(test_workload_id(0x01));
        let proof2 = acc.generate_proof(test_workload_id(0x01));

        assert_eq!(
            proof1.as_ref().map(|p| *p.proof_hash()),
            proof2.as_ref().map(|p| *p.proof_hash()),
        );
    }

    #[test]
    fn test_generate_proof_hash_composition() {
        let coord_id = test_coordinator_id();
        let epoch = 42u64;
        let mut acc = CoordinatorAccountability::new(coord_id, epoch);

        let decision = test_decision(0x01, 100);
        let wid = *decision.workload_id();
        let rdh = decision.decision().receipt_data_hash();
        let bh = decision.block_height();

        acc.log_decision(decision);

        let proof = acc.generate_proof(wid);
        assert!(proof.is_some());

        if let Some(ref p) = proof {
            // Manually compute expected proof_hash
            let mut hasher = Sha3_256::new();
            hasher.update(coord_id.as_bytes());
            hasher.update(epoch.to_le_bytes());
            hasher.update(wid.as_bytes());
            hasher.update(rdh);
            hasher.update(bh.to_le_bytes());
            let result = hasher.finalize();
            let mut expected = [0u8; 32];
            expected.copy_from_slice(&result);

            assert_eq!(*p.proof_hash(), expected);
        }
    }

    // ── get_decisions_in_range() ────────────────────────────────

    #[test]
    fn test_get_decisions_in_range_inclusive() {
        let mut acc = CoordinatorAccountability::new(test_coordinator_id(), 1);

        acc.log_decision(test_decision(0x01, 100));
        acc.log_decision(test_decision(0x02, 150));
        acc.log_decision(test_decision(0x03, 200));
        acc.log_decision(test_decision(0x04, 250));

        let range = acc.get_decisions_in_range(100, 200);
        assert_eq!(range.len(), 3);
        assert_eq!(range[0].block_height(), 100); // from is inclusive
        assert_eq!(range[1].block_height(), 150);
        assert_eq!(range[2].block_height(), 200); // to is inclusive
    }

    #[test]
    fn test_get_decisions_in_range_empty() {
        let mut acc = CoordinatorAccountability::new(test_coordinator_id(), 1);
        acc.log_decision(test_decision(0x01, 100));

        let range = acc.get_decisions_in_range(200, 300);
        assert!(range.is_empty());
    }

    #[test]
    fn test_get_decisions_in_range_preserves_insertion_order() {
        let mut acc = CoordinatorAccountability::new(test_coordinator_id(), 1);

        // Insert in non-ascending block_height order
        acc.log_decision(test_decision(0x01, 200));
        acc.log_decision(test_decision(0x02, 100));
        acc.log_decision(test_decision(0x03, 150));

        let range = acc.get_decisions_in_range(100, 200);
        assert_eq!(range.len(), 3);

        // Order MUST match insertion order, NOT sorted by block_height
        assert_eq!(range[0].block_height(), 200);
        assert_eq!(range[1].block_height(), 100);
        assert_eq!(range[2].block_height(), 150);
    }

    #[test]
    fn test_get_decisions_in_range_no_clone() {
        let mut acc = CoordinatorAccountability::new(test_coordinator_id(), 1);
        acc.log_decision(test_decision(0x01, 100));

        let range = acc.get_decisions_in_range(100, 100);
        assert_eq!(range.len(), 1);

        // Verify we get references, not clones
        let ptr_range: *const AccountableDecision = range[0];
        let ptr_direct: *const AccountableDecision = &acc.decisions[0];
        assert_eq!(ptr_range, ptr_direct);
    }

    #[test]
    fn test_get_decisions_in_range_single_block() {
        let mut acc = CoordinatorAccountability::new(test_coordinator_id(), 1);

        acc.log_decision(test_decision(0x01, 100));
        acc.log_decision(test_decision(0x02, 100)); // same block
        acc.log_decision(test_decision(0x03, 101));

        let range = acc.get_decisions_in_range(100, 100);
        assert_eq!(range.len(), 2);
    }
}