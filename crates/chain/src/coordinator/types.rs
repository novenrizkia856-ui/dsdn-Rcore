//! Chain-layer coordinator types (14A.2B.2.21)
//!
//! Type definitions untuk integrasi coordinator ↔ chain layer.
//! Module ini HANYA mendefinisikan types. TIDAK ada logic.

use dsdn_common::coordinator::CoordinatorCommittee;
use serde::{Deserialize, Serialize};

// ════════════════════════════════════════════════════════════════════════════════
// CommitteeStatus
// ════════════════════════════════════════════════════════════════════════════════

/// Status committee dari perspektif chain layer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommitteeStatus {
    /// Committee aktif dan dapat memproses receipts.
    Active,
    /// Committee sedang menunggu rotasi ke epoch berikutnya.
    PendingRotation,
    /// Committee sedang dalam proses handoff antar epoch.
    InHandoff,
    /// Committee tidak aktif.
    Inactive,
}

// ════════════════════════════════════════════════════════════════════════════════
// CommitteeTransition
// ════════════════════════════════════════════════════════════════════════════════

/// Data transisi committee antar epoch dari perspektif chain layer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeTransition {
    /// Committee epoch lama.
    pub old_committee: CoordinatorCommittee,
    /// Committee epoch baru.
    pub new_committee: CoordinatorCommittee,
    /// Block height dimana transisi terjadi.
    pub transition_height: u64,
    /// Block height mulai handoff.
    pub handoff_start: u64,
    /// Block height selesai handoff.
    pub handoff_end: u64,
}

// ════════════════════════════════════════════════════════════════════════════════
// EpochConfig
// ════════════════════════════════════════════════════════════════════════════════

/// Konfigurasi epoch untuk coordinator committee rotation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochConfig {
    /// Durasi epoch dalam jumlah blocks.
    pub epoch_duration_blocks: u64,
    /// Durasi handoff dalam jumlah blocks.
    pub handoff_duration_blocks: u64,
    /// Timeout DKG dalam jumlah blocks.
    pub dkg_timeout_blocks: u64,
}