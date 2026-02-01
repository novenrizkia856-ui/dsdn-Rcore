//! CoordinatorDispute types (14A.2B.2.27)
//!
//! Dispute types untuk coordinator misbehavior yang dapat di-submit on-chain.
//! Module ini HANYA mendefinisikan TYPE, ENUM, dan STRUCT.
//! TIDAK ada logika eksekusi, verifikasi runtime, atau resolution logic.

use dsdn_common::coordinator::{
    CoordinatorCommittee, CoordinatorId, DAMerkleProof, ThresholdReceipt, WorkloadId,
};
use serde::{Deserialize, Serialize};

use crate::types::Address;

// ════════════════════════════════════════════════════════════════════════════════
// COORDINATOR DISPUTE
// ════════════════════════════════════════════════════════════════════════════════

/// Dispute types untuk coordinator misbehavior on-chain.
///
/// Setiap variant merepresentasikan satu jenis pelanggaran
/// yang dapat dibuktikan secara deterministik dengan evidence.
///
/// ## Variants
///
/// | Variant | Deskripsi |
/// |---------|-----------|
/// | `InconsistentScheduling` | Dua receipt berbeda untuk workload yang sama |
/// | `InvalidSignature` | Receipt dengan signature tidak valid |
/// | `MissingReceipt` | Workload tidak mendapat receipt dalam waktu yang ditentukan |
/// | `UnauthorizedSigner` | Receipt ditandatangani oleh non-member |
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum CoordinatorDispute {
    /// Dua receipt berbeda untuk workload yang sama.
    ///
    /// Bukti: dua `ThresholdReceipt` yang saling bertentangan
    /// untuk workload yang sama, didukung oleh DA proof.
    InconsistentScheduling {
        /// Receipt pertama.
        receipt_a: ThresholdReceipt,
        /// Receipt kedua (bertentangan dengan receipt_a).
        receipt_b: ThresholdReceipt,
        /// Bukti Merkle dari DA layer.
        da_proof: DAMerkleProof,
    },

    /// Receipt dengan signature tidak valid terhadap committee.
    ///
    /// Bukti: receipt yang gagal verifikasi terhadap
    /// committee yang diharapkan.
    InvalidSignature {
        /// Receipt yang signature-nya tidak valid.
        receipt: ThresholdReceipt,
        /// Committee yang seharusnya memvalidasi receipt.
        expected_committee: CoordinatorCommittee,
    },

    /// Workload tidak mendapat receipt dalam waktu yang ditentukan.
    ///
    /// Bukti: workload ID, DA proof, dan timeout proof
    /// yang menunjukkan bahwa committee gagal merespons.
    MissingReceipt {
        /// Workload ID yang diharapkan mendapat receipt.
        expected_workload_id: WorkloadId,
        /// Bukti Merkle dari DA layer bahwa workload ada.
        da_proof: DAMerkleProof,
        /// Bukti bahwa timeout telah tercapai.
        timeout_proof: TimeoutProof,
    },

    /// Receipt ditandatangani oleh coordinator yang bukan member committee.
    ///
    /// Bukti: receipt dan ID signer yang tidak dikenal.
    UnauthorizedSigner {
        /// Receipt yang mengandung signer tidak valid.
        receipt: ThresholdReceipt,
        /// ID coordinator yang bukan member committee.
        invalid_signer: CoordinatorId,
    },
}

// ════════════════════════════════════════════════════════════════════════════════
// TIMEOUT PROOF
// ════════════════════════════════════════════════════════════════════════════════

/// Bukti bahwa workload telah melewati batas waktu tanpa receipt.
///
/// Digunakan dalam `MissingReceipt` dispute untuk membuktikan
/// bahwa committee gagal merespons dalam waktu yang ditentukan.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimeoutProof {
    /// Workload ID yang timeout.
    pub workload_id: WorkloadId,
    /// Timestamp saat request dibuat (Unix seconds).
    pub requested_at: u64,
    /// Timestamp saat timeout tercapai (Unix seconds).
    pub timeout_at: u64,
    /// Daftar coordinator witnesses yang mengonfirmasi timeout.
    pub witnesses: Vec<CoordinatorId>,
}

// ════════════════════════════════════════════════════════════════════════════════
// DISPUTE EVIDENCE
// ════════════════════════════════════════════════════════════════════════════════

/// Evidence container untuk dispute submission on-chain.
///
/// Wrapper opaque yang membawa raw evidence bytes
/// beserta metadata submission.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisputeEvidence {
    /// Tipe dispute sebagai string eksplisit.
    pub dispute_type: String,
    /// Raw evidence bytes (opaque, tidak diinterpretasi di sini).
    pub raw_evidence: Vec<u8>,
    /// Address yang men-submit dispute.
    pub submitted_by: Address,
    /// Timestamp saat dispute di-submit (Unix seconds).
    pub submitted_at: u64,
}