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
//!
//! ## Re-exports
//!
//! Semua public types dari submodules di-re-export untuk kemudahan akses:
//!
//! ```rust,ignore
//! use dsdn_common::{CoordinatorId, ValidatorId, WorkloadId, Timestamp, ParseError};
//! use dsdn_common::CoordinatorMember;
//! use dsdn_common::{CoordinatorCommittee, CommitteeError};
//! ```

pub mod ids;
pub mod member;
pub mod committee;

pub use ids::*;
pub use member::CoordinatorMember;
pub use committee::{CoordinatorCommittee, CommitteeError};