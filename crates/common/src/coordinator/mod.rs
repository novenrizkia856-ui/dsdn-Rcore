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
//!
//! ## Re-exports
//!
//! Semua public types dari submodules di-re-export untuk kemudahan akses:
//!
//! ```rust,ignore
//! use dsdn_common::{CoordinatorId, ValidatorId, WorkloadId, Timestamp, ParseError};
//! use dsdn_common::CoordinatorMember;
//! ```

pub mod ids;
pub mod member;

pub use ids::*;
pub use member::CoordinatorMember;