//! Coordinator dispute types dan resolution logic.
//!
//! ## Tahap
//!
//! - **14A.2B.2.27**: Type definitions (`CoordinatorDispute`, `TimeoutProof`, `DisputeEvidence`)
//! - **14A.2B.2.28**: Resolution logic (`DisputeResolver`, `DisputeResult`, `apply_slashing`)
//!
//! ## Design Principles
//!
//! - `validate_dispute()` dan `resolve()` adalah **PURE** — tidak mengakses state,
//!   tidak melakukan side effects, deterministic.
//! - `apply_slashing()` adalah **STATE MUTATION** — memodifikasi `ChainState`.
//! - Semua logic audit-friendly: setiap keputusan dapat di-trace dari input ke output.

use std::collections::HashMap;

use dsdn_common::coordinator::{
    CoordinatorCommittee, CoordinatorId, DAMerkleProof, ThresholdReceipt, WorkloadId,
};
use serde::{Deserialize, Serialize};

use crate::state::ChainState;
use crate::types::Address;

// ════════════════════════════════════════════════════════════════════════════════
// COORDINATOR DISPUTE (14A.2B.2.27)
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
// TIMEOUT PROOF (14A.2B.2.27)
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
// DISPUTE EVIDENCE (14A.2B.2.27)
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

// ════════════════════════════════════════════════════════════════════════════════
// DISPUTE RESULT (14A.2B.2.28)
// ════════════════════════════════════════════════════════════════════════════════

/// Hasil resolusi dispute — deterministik dari input.
///
/// ## Variants
///
/// | Variant | Arti | Aksi |
/// |---------|------|------|
/// | `Valid` | Misbehavior terbukti | Slash offenders |
/// | `Invalid` | Tidak ada misbehavior | Tidak ada aksi |
/// | `Inconclusive` | Evidence tidak cukup | Perlu investigasi lanjut |
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DisputeResult {
    /// Dispute valid — misbehavior terbukti secara deterministik.
    Valid {
        /// Coordinator IDs yang terbukti melanggar.
        offenders: Vec<CoordinatorId>,
        /// Jumlah slash per offender (NUSA base units).
        slash_amount: u128,
    },

    /// Dispute invalid — evidence menunjukkan tidak ada misbehavior.
    Invalid {
        /// Alasan dispute ditolak.
        reason: String,
    },

    /// Evidence tidak cukup untuk penentuan definitif.
    Inconclusive {
        /// Alasan ketidakpastian.
        reason: String,
    },
}

// ════════════════════════════════════════════════════════════════════════════════
// SLASHING ERROR (14A.2B.2.28)
// ════════════════════════════════════════════════════════════════════════════════

/// Error types untuk operasi slashing.
///
/// Setiap variant merepresentasikan satu kegagalan spesifik
/// yang mencegah slashing dari dieksekusi.
#[derive(Clone, Debug)]
pub enum SlashingError {
    /// CoordinatorId tidak dapat di-map ke Address on-chain.
    /// Coordinator mungkin belum terdaftar atau mapping belum tersedia.
    UnknownCoordinator(CoordinatorId),

    /// Target tidak memiliki cukup stake untuk di-slash.
    InsufficientStake {
        /// Address target yang akan di-slash.
        target: Address,
        /// Jumlah yang diminta untuk di-slash.
        required: u128,
        /// Jumlah stake yang tersedia.
        available: u128,
    },

    /// DisputeResult bukan `Valid` — tidak ada yang perlu di-slash.
    NothingToSlash,
}

impl std::fmt::Display for SlashingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownCoordinator(id) => {
                write!(f, "Unknown coordinator: {:?}", id)
            }
            Self::InsufficientStake {
                target,
                required,
                available,
            } => {
                write!(
                    f,
                    "Insufficient stake for {:?}: required={}, available={}",
                    target, required, available
                )
            }
            Self::NothingToSlash => {
                write!(f, "DisputeResult is not Valid — nothing to slash")
            }
        }
    }
}

impl std::error::Error for SlashingError {}

// ════════════════════════════════════════════════════════════════════════════════
// DISPUTE CONFIG (14A.2B.2.28)
// ════════════════════════════════════════════════════════════════════════════════

/// Konfigurasi threshold untuk dispute resolution.
///
/// Setiap field mendefinisikan slash amount untuk kategori
/// dispute tertentu. Semua dalam NUSA base units.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisputeConfig {
    /// Slash amount untuk `InconsistentScheduling` (NUSA base units).
    /// Biasanya paling besar karena equivocation adalah pelanggaran serius.
    pub slash_amount_inconsistent: u128,

    /// Slash amount untuk `InvalidSignature` (NUSA base units).
    pub slash_amount_invalid_sig: u128,

    /// Slash amount untuk `MissingReceipt` (NUSA base units).
    /// Biasanya lebih kecil karena bisa disebabkan oleh downtime.
    pub slash_amount_missing: u128,

    /// Slash amount untuk `UnauthorizedSigner` (NUSA base units).
    pub slash_amount_unauthorized: u128,

    /// Minimum jumlah timeout witnesses untuk `MissingReceipt`.
    /// Mencegah single-reporter fabrication.
    pub min_timeout_witnesses: usize,
}

// ════════════════════════════════════════════════════════════════════════════════
// SLASHING SUMMARY (14A.2B.2.28)
// ════════════════════════════════════════════════════════════════════════════════

/// Ringkasan eksekusi slashing — audit trail.
///
/// Dikembalikan oleh `apply_slashing()` setelah mutasi state berhasil.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlashingSummary {
    /// Detail per-address yang berhasil di-slash.
    pub slashed: Vec<SlashedEntry>,
    /// Total amount yang berhasil dideduct dari semua offenders.
    pub total_slashed: u128,
    /// Total amount yang masuk ke treasury.
    pub to_treasury: u128,
}

/// Detail slashing untuk satu address.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlashedEntry {
    /// Address on-chain yang di-slash.
    pub address: Address,
    /// Jumlah aktual yang dideduct (mungkin kurang dari requested
    /// jika stake tidak cukup — capped di available).
    pub amount_deducted: u128,
}

// ════════════════════════════════════════════════════════════════════════════════
// DISPUTE RESOLVER (14A.2B.2.28)
// ════════════════════════════════════════════════════════════════════════════════

/// Deterministic dispute resolver untuk coordinator misbehavior.
///
/// ## Usage Flow
///
/// ```text
/// 1. validate_dispute(&dispute)  → bool (structural check)
/// 2. resolve(&dispute, committee) → DisputeResult (pure logic)
/// 3. apply_slashing(&result, state, mapping) → SlashingSummary (state mutation)
/// ```
///
/// ## Purity Guarantees
///
/// - `validate_dispute()`: PURE — no state, no side effects
/// - `resolve()`: PURE — no state, no side effects, deterministic
/// - `apply_slashing()`: STATE MUTATION — modifies ChainState
pub struct DisputeResolver {
    config: DisputeConfig,
}

impl DisputeResolver {
    /// Membuat DisputeResolver baru dengan konfigurasi yang diberikan.
    #[must_use]
    pub fn new(config: DisputeConfig) -> Self {
        Self { config }
    }

    /// Mengembalikan referensi ke konfigurasi aktif.
    #[must_use]
    pub fn config(&self) -> &DisputeConfig {
        &self.config
    }

    // ══════════════════════════════════════════════════════════════════
    // 1. STRUCTURAL VALIDATION (PURE)
    // ══════════════════════════════════════════════════════════════════

    /// Validasi integritas struktural dispute submission.
    ///
    /// Mengecek apakah dispute well-formed dan layak untuk di-resolve.
    /// Ini adalah pre-check ringan sebelum `resolve()` yang lebih mahal.
    ///
    /// PURE: tidak mengakses state, tidak ada side effects.
    ///
    /// # Returns
    ///
    /// `true` jika dispute structurally valid, `false` jika malformed.
    #[must_use]
    pub fn validate_dispute(&self, dispute: &CoordinatorDispute) -> bool {
        match dispute {
            CoordinatorDispute::InconsistentScheduling {
                receipt_a,
                receipt_b,
                da_proof,
            } => {
                // Kedua receipt harus punya signers
                !receipt_a.signers().is_empty()
                    && !receipt_b.signers().is_empty()
                    // DA proof harus punya non-zero root
                    && da_proof.root != [0u8; 32]
            }

            CoordinatorDispute::InvalidSignature {
                receipt,
                expected_committee,
            } => {
                // Receipt harus punya signers, committee harus punya members
                !receipt.signers().is_empty() && expected_committee.member_count() > 0
            }

            CoordinatorDispute::MissingReceipt {
                expected_workload_id: _,
                da_proof,
                timeout_proof,
            } => {
                // DA proof non-zero root
                da_proof.root != [0u8; 32]
                    // Timeout harus setelah request
                    && timeout_proof.timeout_at > timeout_proof.requested_at
                    // Minimum witnesses terpenuhi
                    && timeout_proof.witnesses.len() >= self.config.min_timeout_witnesses
            }

            CoordinatorDispute::UnauthorizedSigner {
                receipt,
                invalid_signer: _,
            } => {
                // Receipt harus punya signers
                !receipt.signers().is_empty()
            }
        }
    }

    // ══════════════════════════════════════════════════════════════════
    // 2. DISPUTE RESOLUTION (PURE)
    // ══════════════════════════════════════════════════════════════════

    /// Resolve dispute dan tentukan outcome secara deterministik.
    ///
    /// PURE: tidak mengakses state, tidak melakukan side effects.
    /// Same input SELALU menghasilkan same output.
    ///
    /// # Arguments
    ///
    /// * `dispute` — Dispute yang akan di-resolve.
    /// * `epoch_committee` — Committee context untuk epoch terkait.
    ///   **Wajib** untuk `MissingReceipt` dan `UnauthorizedSigner`.
    ///   Jika `None` untuk variant tersebut, akan return `Inconclusive`.
    #[must_use]
    pub fn resolve(
        &self,
        dispute: &CoordinatorDispute,
        epoch_committee: Option<&CoordinatorCommittee>,
    ) -> DisputeResult {
        match dispute {
            CoordinatorDispute::InconsistentScheduling {
                receipt_a,
                receipt_b,
                ..
            } => self.resolve_inconsistent(receipt_a, receipt_b),

            CoordinatorDispute::InvalidSignature {
                receipt,
                expected_committee,
            } => self.resolve_invalid_sig(receipt, expected_committee),

            CoordinatorDispute::MissingReceipt {
                expected_workload_id,
                timeout_proof,
                ..
            } => self.resolve_missing(expected_workload_id, timeout_proof, epoch_committee),

            CoordinatorDispute::UnauthorizedSigner {
                receipt,
                invalid_signer,
            } => self.resolve_unauthorized(receipt, invalid_signer, epoch_committee),
        }
    }

    // ══════════════════════════════════════════════════════════════════
    // 3. SLASHING EXECUTION (STATE MUTATION)
    // ══════════════════════════════════════════════════════════════════

    /// Apply slashing berdasarkan dispute result.
    ///
    /// **STATE MUTATION**: memodifikasi `ChainState` —
    /// mengurangi `locked` dan `validator_stakes`, menambah `treasury_balance`.
    ///
    /// # Arguments
    ///
    /// * `result` — Hasil dari `resolve()`. Harus `Valid`, otherwise return error.
    /// * `state` — Mutable reference ke `ChainState` untuk mutasi.
    /// * `id_to_address` — Mapping `CoordinatorId` → `Address` on-chain.
    ///
    /// # Errors
    ///
    /// - `SlashingError::NothingToSlash` jika result bukan `Valid`.
    /// - `SlashingError::UnknownCoordinator` jika coordinator tidak ada di mapping.
    /// - `SlashingError::InsufficientStake` jika target punya 0 stake.
    ///
    /// # Slashing Mechanics
    ///
    /// Untuk setiap offender:
    /// 1. Lookup `Address` via `id_to_address`
    /// 2. Cap `actual_slash = min(slash_amount, available_locked)`
    /// 3. Deduct dari `state.locked[address]`
    /// 4. Deduct dari `state.validator_stakes[address]` (jika ada)
    /// 5. Add ke `state.treasury_balance`
    pub fn apply_slashing(
        &self,
        result: &DisputeResult,
        state: &mut ChainState,
        id_to_address: &HashMap<CoordinatorId, Address>,
    ) -> Result<SlashingSummary, SlashingError> {
        let (offenders, slash_amount) = match result {
            DisputeResult::Valid {
                offenders,
                slash_amount,
            } => (offenders, *slash_amount),
            DisputeResult::Invalid { .. } | DisputeResult::Inconclusive { .. } => {
                return Err(SlashingError::NothingToSlash);
            }
        };

        let mut summary = SlashingSummary {
            slashed: Vec::with_capacity(offenders.len()),
            total_slashed: 0,
            to_treasury: 0,
        };

        for coordinator_id in offenders {
            let address = id_to_address
                .get(coordinator_id)
                .ok_or(SlashingError::UnknownCoordinator(*coordinator_id))?;

            // Determine available stake (locked amount)
            let available = *state.locked.get(address).unwrap_or(&0);

            if available == 0 {
                return Err(SlashingError::InsufficientStake {
                    target: *address,
                    required: slash_amount,
                    available: 0,
                });
            }

            // Cap slash at available stake — NEVER slash more than staked
            let actual_slash = slash_amount.min(available);

            // ── Mutate state ────────────────────────────────────────

            // 1. Deduct from locked (voting power reduction — immediate)
            if let Some(locked) = state.locked.get_mut(address) {
                *locked = locked.saturating_sub(actual_slash);
            }

            // 2. Deduct from validator_stakes if present (maintain consistency)
            if let Some(vstake) = state.validator_stakes.get_mut(address) {
                *vstake = vstake.saturating_sub(actual_slash);
            }

            // 3. Add to treasury
            state.treasury_balance = state.treasury_balance.saturating_add(actual_slash);

            // ── Record ──────────────────────────────────────────────

            summary.slashed.push(SlashedEntry {
                address: *address,
                amount_deducted: actual_slash,
            });
            summary.total_slashed = summary.total_slashed.saturating_add(actual_slash);
            summary.to_treasury = summary.to_treasury.saturating_add(actual_slash);
        }

        Ok(summary)
    }

    // ══════════════════════════════════════════════════════════════════
    // PRIVATE — RESOLUTION METHODS
    // ══════════════════════════════════════════════════════════════════

    /// Resolve InconsistentScheduling dispute.
    ///
    /// Dua receipt untuk workload yang sama HARUS memiliki data berbeda
    /// untuk membuktikan equivocation. Semua signers dari kedua receipt
    /// di-union dan di-slash.
    fn resolve_inconsistent(
        &self,
        receipt_a: &ThresholdReceipt,
        receipt_b: &ThresholdReceipt,
    ) -> DisputeResult {
        // Step 1: Kedua receipt harus untuk workload yang sama
        if receipt_a.workload_id() != receipt_b.workload_id() {
            return DisputeResult::Invalid {
                reason: "Receipts are for different workloads — not equivocation".into(),
            };
        }

        // Step 2: Receipt data harus BERBEDA (inconsistent)
        if receipt_a.receipt_data().receipt_data_hash()
            == receipt_b.receipt_data().receipt_data_hash()
        {
            return DisputeResult::Invalid {
                reason: "Receipts have identical data hash — no inconsistency".into(),
            };
        }

        // Step 3: Valid equivocation — collect union of all signers
        let mut offenders: Vec<CoordinatorId> = Vec::new();
        for signer in receipt_a.signers() {
            if !offenders.contains(signer) {
                offenders.push(*signer);
            }
        }
        for signer in receipt_b.signers() {
            if !offenders.contains(signer) {
                offenders.push(*signer);
            }
        }

        DisputeResult::Valid {
            offenders,
            slash_amount: self.config.slash_amount_inconsistent,
        }
    }

    /// Resolve InvalidSignature dispute.
    ///
    /// Jika `receipt.verify(committee)` returns `true`, berarti signature
    /// valid dan dispute TIDAK valid. Jika returns `false`, semua signers
    /// di receipt di-slash.
    fn resolve_invalid_sig(
        &self,
        receipt: &ThresholdReceipt,
        expected_committee: &CoordinatorCommittee,
    ) -> DisputeResult {
        // Step 1: Verify signature against committee
        if receipt.verify(expected_committee) {
            // Signature valid → dispute invalid (no violation)
            return DisputeResult::Invalid {
                reason: "Signature verified successfully against committee — no violation".into(),
            };
        }

        // Step 2: Signature invalid → slash all signers
        let offenders: Vec<CoordinatorId> = receipt.signers().to_vec();

        DisputeResult::Valid {
            offenders,
            slash_amount: self.config.slash_amount_invalid_sig,
        }
    }

    /// Resolve MissingReceipt dispute.
    ///
    /// Membutuhkan `epoch_committee` untuk menentukan siapa yang bertanggung
    /// jawab. Jika committee tidak tersedia, return `Inconclusive`.
    /// Jika valid, SEMUA committee members di-slash karena kolektif gagal
    /// memproduksi receipt.
    fn resolve_missing(
        &self,
        expected_workload_id: &WorkloadId,
        timeout_proof: &TimeoutProof,
        epoch_committee: Option<&CoordinatorCommittee>,
    ) -> DisputeResult {
        // Step 1: Timeout proof workload harus match expected
        if &timeout_proof.workload_id != expected_workload_id {
            return DisputeResult::Invalid {
                reason: "Timeout proof workload_id does not match expected workload".into(),
            };
        }

        // Step 2: Timeout window harus valid
        if timeout_proof.timeout_at <= timeout_proof.requested_at {
            return DisputeResult::Invalid {
                reason: "Invalid timeout window: timeout_at <= requested_at".into(),
            };
        }

        // Step 3: Minimum witnesses terpenuhi
        if timeout_proof.witnesses.len() < self.config.min_timeout_witnesses {
            return DisputeResult::Inconclusive {
                reason: format!(
                    "Insufficient timeout witnesses: {} < {} required",
                    timeout_proof.witnesses.len(),
                    self.config.min_timeout_witnesses,
                ),
            };
        }

        // Step 4: Committee context diperlukan untuk identifikasi offenders
        let committee = match epoch_committee {
            Some(c) => c,
            None => {
                return DisputeResult::Inconclusive {
                    reason: "Committee context required to identify responsible members".into(),
                };
            }
        };

        // Step 5: Valid — semua committee members bertanggung jawab
        // Committee secara kolektif gagal memproduksi receipt
        let offenders = committee.member_ids();
        if offenders.is_empty() {
            return DisputeResult::Inconclusive {
                reason: "Committee has no members — cannot determine offenders".into(),
            };
        }

        DisputeResult::Valid {
            offenders,
            slash_amount: self.config.slash_amount_missing,
        }
    }

    /// Resolve UnauthorizedSigner dispute.
    ///
    /// Membutuhkan `epoch_committee` untuk verifikasi membership.
    /// Jika signer IS member → dispute invalid.
    /// Jika signer NOT member → signer di-slash.
    fn resolve_unauthorized(
        &self,
        _receipt: &ThresholdReceipt,
        invalid_signer: &CoordinatorId,
        epoch_committee: Option<&CoordinatorCommittee>,
    ) -> DisputeResult {
        // Step 1: Committee context diperlukan
        let committee = match epoch_committee {
            Some(c) => c,
            None => {
                return DisputeResult::Inconclusive {
                    reason: "Committee context required to verify membership".into(),
                };
            }
        };

        // Step 2: Check membership
        if committee.is_member(invalid_signer) {
            // Signer IS a member → dispute invalid
            return DisputeResult::Invalid {
                reason: "Signer is a valid committee member — no violation".into(),
            };
        }

        // Step 3: Signer NOT a member → valid, slash unauthorized signer
        DisputeResult::Valid {
            offenders: vec![*invalid_signer],
            slash_amount: self.config.slash_amount_unauthorized,
        }
    }
}