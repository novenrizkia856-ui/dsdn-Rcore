//! # Coordinator Committee Module
//!
//! Module ini menyediakan types dan abstractions untuk sistem multi-coordinator
//! DSDN dengan Threshold Signature Scheme (TSS) support.
//!
//! ## Overview
//!
//! DSDN menggunakan committee of coordinators untuk threshold signing.
//! Committee beroperasi dalam epoch-based rotation dengan handoff mechanism
//! untuk menjamin continuity dan availability.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                     Coordinator Committee System                     │
//! └─────────────────────────────────────────────────────────────────────┘
//!
//!    ┌──────────────┐      ┌──────────────┐      ┌──────────────┐
//!    │ Coordinator  │      │ Coordinator  │      │ Coordinator  │
//!    │     ID A     │      │     ID B     │      │     ID C     │
//!    └──────┬───────┘      └──────┬───────┘      └──────┬───────┘
//!           │                     │                     │
//!           └─────────────────────┼─────────────────────┘
//!                                 │
//!                    ┌────────────▼────────────┐
//!                    │  CoordinatorCommittee   │
//!                    │  (threshold t-of-n)     │
//!                    │  epoch: N               │
//!                    │  group_pubkey: PK       │
//!                    └────────────┬────────────┘
//!                                 │
//!               ┌─────────────────┼─────────────────┐
//!               │                 │                 │
//!      ┌────────▼────────┐ ┌──────▼──────┐ ┌───────▼───────┐
//!      │   ReceiptData   │ │  Threshold  │ │   Committee   │
//!      │  (message hash) │ │   Receipt   │ │   Transition  │
//!      └─────────────────┘ │ (aggregate  │ │ (epoch N→N+1) │
//!                          │  signature) │ └───────────────┘
//!                          └─────────────┘
//! ```
//!
//! ## Components
//!
//! | Component | Type | Description |
//! |-----------|------|-------------|
//! | `CoordinatorId` | Identifier | 32-byte unique identifier untuk coordinator |
//! | `ValidatorId` | Identifier | 32-byte unique identifier untuk validator backing |
//! | `WorkloadId` | Identifier | 32-byte unique identifier untuk workload/task |
//! | `CoordinatorMember` | Struct | Member dengan ID, pubkey, dan stake |
//! | `CoordinatorCommittee` | Struct | Committee dengan threshold, epoch, dan group pubkey |
//! | `ReceiptData` | Struct | Data yang di-sign (workload, blob hash, placement) |
//! | `ThresholdReceipt` | Struct | Receipt dengan aggregate signature |
//! | `CommitteeTransition` | Struct | Transisi epoch dengan handoff period |
//! | `CommitteeStatus` | Enum | Lifecycle status: Active, InHandoff, Expired, Initializing |
//!
//! ## Epoch Lifecycle
//!
//! Committee lifecycle mengikuti state machine berikut:
//!
//! ```text
//! ┌─────────────────┐
//! │  Initializing   │ ─── DKG in progress
//! └────────┬────────┘
//!          │ Activate
//!          ▼
//! ┌─────────────────┐
//! │     Active      │ ─── Committee operational, dapat sign receipts
//! └────────┬────────┘
//!          │ StartHandoff
//!          ▼
//! ┌─────────────────┐
//! │   InHandoff     │ ─── Dual validity period
//! │                 │     (current & next committee valid)
//! └────────┬────────┘
//!          │ CompleteHandoff
//!          ▼
//! ┌─────────────────┐
//! │  Active (N+1)   │ ─── New committee operational
//! └─────────────────┘
//!
//! Any state → Expire → Expired
//! Any state → Reset → Initializing
//! ```
//!
//! ### Phase 1: Active
//!
//! Committee aktif dan dapat memproses receipts. Semua signing requests
//! ditangani oleh committee epoch N.
//!
//! ### Phase 2: Handoff (Dual Validity)
//!
//! Selama handoff period (`handoff_start` hingga `handoff_end`):
//! - Current committee (epoch N) tetap valid untuk signing
//! - Next committee (epoch N+1) sudah siap
//! - Receipts yang dibuat oleh current committee tetap valid
//!
//! ### Phase 3: New Active
//!
//! Setelah `handoff_end`:
//! - Next committee (epoch N+1) menjadi current committee
//! - Old committee (epoch N) tidak lagi menerima requests baru
//! - Receipts dari old committee masih valid untuk verifikasi
//!
//! ## Receipt Verification
//!
//! `ThresholdReceipt` diverifikasi terhadap committee dengan langkah:
//!
//! 1. **verify_committee_hash**: Hash committee harus cocok
//! 2. **verify_epoch**: Epoch receipt harus cocok dengan committee
//! 3. **verify_signers**: Semua signer harus member committee, tidak ada duplicate
//! 4. **verify_threshold**: Jumlah signer >= threshold
//! 5. **verify_signature**: Cryptographic signature valid via TSS
//!
//! ## Example Usage
//!
//! ```rust,ignore
//! use dsdn_common::{
//!     CoordinatorCommittee, CoordinatorMember, CoordinatorId, ValidatorId,
//!     ReceiptData, ThresholdReceipt, CommitteeStatus, WorkloadId,
//! };
//! use dsdn_tss::{GroupPublicKey, ParticipantPublicKey, AggregateSignature};
//!
//! // Create committee members
//! let member1 = CoordinatorMember::new(
//!     CoordinatorId::new([0x01; 32]),
//!     ValidatorId::new([0x01; 32]),
//!     pubkey1,
//!     1000, // stake
//! );
//!
//! // Create committee
//! let committee = CoordinatorCommittee::new(
//!     vec![member1, member2, member3],
//!     2,           // threshold (2-of-3)
//!     1,           // epoch
//!     1700000000,  // epoch_start
//!     3600,        // epoch_duration_secs
//!     group_pubkey,
//! )?;
//!
//! // Create receipt data
//! let receipt_data = ReceiptData::new(
//!     workload_id,
//!     blob_hash,
//!     placement,
//!     timestamp,
//!     sequence,
//!     epoch,
//! );
//!
//! // Create threshold receipt with aggregate signature
//! let receipt = ThresholdReceipt::new(
//!     receipt_data,
//!     aggregate_signature,
//!     signers,
//!     committee.committee_hash(),
//! );
//!
//! // Verify receipt
//! if receipt.verify(&committee) {
//!     // Receipt valid
//! }
//!
//! // Or with detailed errors
//! match receipt.verify_detailed(&committee) {
//!     Ok(()) => { /* valid */ }
//!     Err(e) => { /* handle specific error */ }
//! }
//! ```
//!
//! ## Thread Safety
//!
//! All types in this module are:
//! - `Send + Sync`
//! - Immutable after construction
//! - Safe for concurrent access
//!
//! ## Submodules
//!
//! | Module | Description |
//! |--------|-------------|
//! | `ids` | Identifier types (CoordinatorId, ValidatorId, WorkloadId, Timestamp) |
//! | `member` | CoordinatorMember struct untuk committee membership |
//! | `committee` | CoordinatorCommittee struct dengan threshold signing support |
//! | `receipt` | ReceiptData dan ThresholdReceipt untuk signed receipt data |
//! | `transition` | CommitteeTransition untuk epoch rotation dengan handoff |
//! | `status` | CommitteeStatus enum untuk lifecycle tracking |
//!
//! ## Re-exports
//!
//! All public types are re-exported for convenient access:
//!
//! ```rust,ignore
//! use dsdn_common::{
//!     // Identifiers
//!     CoordinatorId, ValidatorId, WorkloadId, Timestamp, ParseError,
//!     // Member & Committee
//!     CoordinatorMember, CoordinatorCommittee, CommitteeError,
//!     // Receipt
//!     ReceiptData, ThresholdReceipt, NodeId, DecodeError, ReceiptVerificationError,
//!     // Transition
//!     CommitteeTransition, TransitionError,
//!     // Status
//!     CommitteeStatus, CommitteeStatusTransition, StatusTransitionError,
//! };
//! ```

pub mod ids;
pub mod member;
pub mod committee;
pub mod receipt;
pub mod transition;
pub mod status;

#[cfg(test)]
mod tests;

pub use ids::*;
pub use member::CoordinatorMember;
pub use committee::{CoordinatorCommittee, CommitteeError};
pub use receipt::{DecodeError, NodeId, ReceiptData, ReceiptVerificationError, ThresholdReceipt};
pub use transition::{CommitteeTransition, TransitionError};
pub use status::{CommitteeStatus, CommitteeStatusTransition, StatusTransitionError};