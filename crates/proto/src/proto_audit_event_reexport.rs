//! # Audit Log Event Types (Re-export)
//!
//! Actual definitions live in `dsdn_common::audit_event`.
//! This module re-exports them for backward compatibility.
//!
//! ## Why Re-export?
//!
//! `proto` depends on `common`, and `common` needs audit event types
//! for the audit log writer pipeline. To avoid circular dependency
//! (common → proto → common), the types live in common and are
//! re-exported here.

pub use dsdn_common::audit_event::*;