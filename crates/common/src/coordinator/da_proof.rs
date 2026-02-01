//! DA Merkle Proof type for coordinator dispute evidence.
//!
//! Struct ini merepresentasikan bukti Merkle dari Data Availability layer
//! yang digunakan dalam dispute resolution on-chain.

use serde::{Deserialize, Serialize};

// ════════════════════════════════════════════════════════════════════════════════
// DA MERKLE PROOF
// ════════════════════════════════════════════════════════════════════════════════

/// Bukti Merkle dari Data Availability layer.
///
/// Digunakan untuk membuktikan bahwa data tertentu telah di-commit
/// ke DA layer pada posisi tertentu dalam Merkle tree.
///
/// ## Verification
///
/// Untuk memverifikasi proof:
/// - Mulai dari leaf hash
/// - Iterasi `path` dari index 0 ke atas
/// - Gunakan bit di `index` untuk menentukan posisi (left/right)
///   - Bit = 0: node adalah LEFT child → hash(current ‖ sibling)
///   - Bit = 1: node adalah RIGHT child → hash(sibling ‖ current)
/// - Hasil akhir harus sama dengan `root`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DAMerkleProof {
    /// Merkle root hash (32 bytes).
    pub root: [u8; 32],

    /// Sibling hashes dari leaf ke root.
    pub path: Vec<[u8; 32]>,

    /// Leaf index dalam tree.
    pub index: u64,
}