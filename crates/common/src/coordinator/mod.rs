//! # Coordinator Module
//!
//! Module ini menyediakan types untuk sistem multi-coordinator DSDN.
//!
//! ## Submodules
//!
//! | Module | Deskripsi |
//! |--------|-----------|
//! | `ids` | Identifier types (CoordinatorId, ValidatorId, WorkloadId, Timestamp) |
//! | `member` | CoordinatorMember struct untuk committee membership |
//! | `committee` | CoordinatorCommittee struct untuk committee management |
//! | `receipt` | ReceiptData dan ThresholdReceipt untuk signed receipt data |
//!
//! ## Re-exports
//!
//! Semua public types dari submodules di-re-export untuk kemudahan akses:
//!
//! ```rust,ignore
//! use dsdn_common::{CoordinatorId, ValidatorId, WorkloadId, Timestamp, ParseError};
//! use dsdn_common::CoordinatorMember;
//! use dsdn_common::{CoordinatorCommittee, CommitteeError};
//! use dsdn_common::{ReceiptData, ThresholdReceipt, NodeId, DecodeError};
//! ```

pub mod ids;
pub mod member;
pub mod committee;
pub mod receipt;

pub use ids::*;
pub use member::CoordinatorMember;
pub use committee::{CoordinatorCommittee, CommitteeError};
pub use receipt::{DecodeError, NodeId, ReceiptData, ThresholdReceipt};