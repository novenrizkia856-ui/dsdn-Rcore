//! # Audit Log Writer Trait (Tahap 15.13)
//!
//! High-level writer interface combining WORM storage + DA mirror + hash chain.
//!
//! This is the main interface all crates use to write audit events.
//! `DefaultAuditLogWriter` (15.14) is the production implementation.
//!
//! ## Thread Safety
//!
//! `AuditLogWriter: Send + Sync + 'static` — safe to share via `Arc<dyn AuditLogWriter>`.

use crate::audit_log_error::AuditLogError;

// ════════════════════════════════════════════════════════════════════════════════
// AUDIT LOG WRITER TRAIT
// ════════════════════════════════════════════════════════════════════════════════

/// High-level audit log writer combining WORM + DA mirror + hash chain.
///
/// # Contract
///
/// - `write_event`: Encode event → build `AuditLogEntry` with hash chain →
///   write to WORM → buffer to DA mirror → return sequence.
/// - `flush_da`: Flush DA mirror buffer to DA layer.
/// - `last_sequence`: Return current sequence (0 if empty).
/// - `verify_chain`: Verify hash chain integrity for `[start, end)`.
///
/// # No Default Implementations
///
/// This trait defines interface only — no default method bodies.
pub trait AuditLogWriter: Send + Sync + 'static {
    /// Write an audit event to WORM storage and buffer to DA mirror.
    ///
    /// Builds `AuditLogEntry` with hash chain, encodes, persists, buffers.
    /// Returns the assigned monotonic sequence number.
    ///
    /// # Errors
    ///
    /// Returns `AuditLogError` on encoding, write, or buffer failure.
    fn write_event(
        &self,
        event: dsdn_proto::audit_event::AuditLogEvent,
    ) -> Result<u64, AuditLogError>;

    /// Flush DA mirror buffer to DA layer.
    ///
    /// Returns number of entries flushed. Returns 0 if buffer is empty.
    ///
    /// # Errors
    ///
    /// Returns `AuditLogError::DaPublishFailed` on failure.
    fn flush_da(&self) -> Result<usize, AuditLogError>;

    /// Return the last assigned sequence number. Returns 0 if empty.
    fn last_sequence(&self) -> u64;

    /// Verify hash chain integrity for range `[start, end)`.
    ///
    /// Reads entries from WORM, decodes, checks:
    /// 1. `entry[i].prev_hash == entry[i-1].entry_hash`
    /// 2. `entry[i].sequence == entry[i-1].sequence + 1`
    /// 3. `entry[i].entry_hash == entry[i].compute_entry_hash()`
    ///
    /// Returns `Ok(true)` if valid, `Ok(false)` if broken.
    fn verify_chain(&self, start: u64, end: u64) -> Result<bool, AuditLogError>;
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn audit_writer_trait_object_safe() {
        fn _takes_writer(_w: &dyn AuditLogWriter) {}
        fn _takes_arc(_w: Arc<dyn AuditLogWriter>) {}
    }

    #[test]
    fn audit_writer_send_sync() {
        fn assert_bounds<T: Send + Sync + 'static>() {}
        assert_bounds::<Box<dyn AuditLogWriter>>();
    }
}