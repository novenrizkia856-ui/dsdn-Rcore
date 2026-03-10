//! # Coordinator Audit Logging Helpers (Tahap 15.1.1)
//!
//! Stateless helper functions for emitting audit events from the coordinator crate.
//!
//! Each helper builds an `AuditLogEvent` variant, calls `writer.write_event()`,
//! and propagates errors to the caller. No state, no caching, no retry.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use dsdn_common::audit_event::{AuditLogEvent, DaFallbackAction, GovernanceStatus};
use dsdn_common::{AuditLogError, AuditLogWriter};

// ════════════════════════════════════════════════════════════════════════════════
// TIMESTAMP
// ════════════════════════════════════════════════════════════════════════════════

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ════════════════════════════════════════════════════════════════════════════════
// DA FALLBACK EVENTS
// ════════════════════════════════════════════════════════════════════════════════

/// Emit `DaFallbackEvent` with action `Activated`.
pub fn emit_da_fallback_activated(
    writer: &Arc<dyn AuditLogWriter>,
    previous_source: &str,
    new_source: &str,
    reason: &str,
    celestia_last_height: u64,
) -> Result<(), AuditLogError> {
    let event = AuditLogEvent::DaFallbackEvent {
        version: 1,
        timestamp_ms: now_ms(),
        action: DaFallbackAction::Activated,
        previous_source: previous_source.to_string(),
        new_source: new_source.to_string(),
        reason: reason.to_string(),
        celestia_last_height,
    };
    writer.write_event(event).map(|_| ())
}

/// Emit `DaFallbackEvent` with action `Deactivated`.
pub fn emit_da_fallback_deactivated(
    writer: &Arc<dyn AuditLogWriter>,
    previous_source: &str,
    new_source: &str,
    reason: &str,
    celestia_last_height: u64,
) -> Result<(), AuditLogError> {
    let event = AuditLogEvent::DaFallbackEvent {
        version: 1,
        timestamp_ms: now_ms(),
        action: DaFallbackAction::Deactivated,
        previous_source: previous_source.to_string(),
        new_source: new_source.to_string(),
        reason: reason.to_string(),
        celestia_last_height,
    };
    writer.write_event(event).map(|_| ())
}

// ════════════════════════════════════════════════════════════════════════════════
// COMMITTEE ROTATION EVENT
// ════════════════════════════════════════════════════════════════════════════════

/// Emit `CommitteeRotationEvent`. Producer active after Tahap 20 — hook installed now.
pub fn emit_committee_rotation(
    writer: &Arc<dyn AuditLogWriter>,
    old_epoch: u64,
    new_epoch: u64,
    old_hash: [u8; 32],
    new_hash: [u8; 32],
    member_count: u32,
    threshold: u32,
) -> Result<(), AuditLogError> {
    let event = AuditLogEvent::CommitteeRotationEvent {
        version: 1,
        timestamp_ms: now_ms(),
        old_epoch,
        new_epoch,
        old_committee_hash: old_hash,
        new_committee_hash: new_hash,
        member_count,
        threshold,
    };
    writer.write_event(event).map(|_| ())
}

// ════════════════════════════════════════════════════════════════════════════════
// DA SYNC SEQUENCE EVENT
// ════════════════════════════════════════════════════════════════════════════════

/// Emit `DaSyncSequenceUpdate` when coordinator processes a new DA sequence.
pub fn emit_da_sync_sequence(
    writer: &Arc<dyn AuditLogWriter>,
    da_source: &str,
    sequence_number: u64,
    previous_sequence: u64,
    blob_count: u64,
) -> Result<(), AuditLogError> {
    let event = AuditLogEvent::DaSyncSequenceUpdate {
        version: 1,
        timestamp_ms: now_ms(),
        da_source: da_source.to_string(),
        sequence_number,
        previous_sequence,
        blob_count,
    };
    writer.write_event(event).map(|_| ())
}

// ════════════════════════════════════════════════════════════════════════════════
// GOVERNANCE PROPOSAL EVENT
// ════════════════════════════════════════════════════════════════════════════════

/// Emit `GovernanceProposalEvent` for proposal lifecycle changes.
pub fn emit_governance_proposal(
    writer: &Arc<dyn AuditLogWriter>,
    proposal_id: &str,
    proposer: &str,
    proposal_type: &str,
    delay_window: u64,
    status: GovernanceStatus,
) -> Result<(), AuditLogError> {
    let event = AuditLogEvent::GovernanceProposalEvent {
        version: 1,
        timestamp_ms: now_ms(),
        proposal_id: proposal_id.to_string(),
        proposer_address: proposer.to_string(),
        proposal_type: proposal_type.to_string(),
        delay_window_secs: delay_window,
        status,
    };
    writer.write_event(event).map(|_| ())
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use dsdn_common::MockAuditLogWriter;

    fn make_writer() -> (Arc<MockAuditLogWriter>, Arc<dyn AuditLogWriter>) {
        let mock = Arc::new(MockAuditLogWriter::new());
        let writer: Arc<dyn AuditLogWriter> = Arc::clone(&mock) as Arc<dyn AuditLogWriter>;
        (mock, writer)
    }

    #[test]
    fn test_emit_da_fallback_activated() {
        let (mock, writer) = make_writer();
        let result = emit_da_fallback_activated(&writer, "celestia", "quorum", "timeout", 100);
        assert!(result.is_ok());
        assert_eq!(mock.event_count(), 1);
        let events = mock.recorded_events();
        match &events[0] {
            AuditLogEvent::DaFallbackEvent { action, previous_source, new_source, .. } => {
                assert_eq!(*action, DaFallbackAction::Activated);
                assert_eq!(previous_source, "celestia");
                assert_eq!(new_source, "quorum");
            }
            other => assert!(false, "wrong variant: {:?}", other),
        }
    }

    #[test]
    fn test_emit_da_fallback_deactivated() {
        let (mock, writer) = make_writer();
        let result = emit_da_fallback_deactivated(&writer, "quorum", "celestia", "recovered", 200);
        assert!(result.is_ok());
        assert_eq!(mock.event_count(), 1);
        let events = mock.recorded_events();
        match &events[0] {
            AuditLogEvent::DaFallbackEvent { action, .. } => {
                assert_eq!(*action, DaFallbackAction::Deactivated);
            }
            other => assert!(false, "wrong variant: {:?}", other),
        }
    }

    #[test]
    fn test_emit_committee_rotation() {
        let (mock, writer) = make_writer();
        let result = emit_committee_rotation(&writer, 1, 2, [0xAA; 32], [0xBB; 32], 5, 3);
        assert!(result.is_ok());
        assert_eq!(mock.event_count(), 1);
        let events = mock.recorded_events();
        match &events[0] {
            AuditLogEvent::CommitteeRotationEvent { old_epoch, new_epoch, member_count, threshold, .. } => {
                assert_eq!(*old_epoch, 1);
                assert_eq!(*new_epoch, 2);
                assert_eq!(*member_count, 5);
                assert_eq!(*threshold, 3);
            }
            other => assert!(false, "wrong variant: {:?}", other),
        }
    }

    #[test]
    fn test_emit_da_sync_sequence() {
        let (mock, writer) = make_writer();
        let result = emit_da_sync_sequence(&writer, "celestia", 100, 99, 5);
        assert!(result.is_ok());
        assert_eq!(mock.event_count(), 1);
        let events = mock.recorded_events();
        match &events[0] {
            AuditLogEvent::DaSyncSequenceUpdate { da_source, sequence_number, previous_sequence, blob_count, .. } => {
                assert_eq!(da_source, "celestia");
                assert_eq!(*sequence_number, 100);
                assert_eq!(*previous_sequence, 99);
                assert_eq!(*blob_count, 5);
            }
            other => assert!(false, "wrong variant: {:?}", other),
        }
    }

    #[test]
    fn test_emit_governance_proposal() {
        let (mock, writer) = make_writer();
        let result = emit_governance_proposal(&writer, "p-1", "addr", "param", 3600, GovernanceStatus::Submitted);
        assert!(result.is_ok());
        assert_eq!(mock.event_count(), 1);
        let events = mock.recorded_events();
        match &events[0] {
            AuditLogEvent::GovernanceProposalEvent { proposal_id, status, .. } => {
                assert_eq!(proposal_id, "p-1");
                assert_eq!(*status, GovernanceStatus::Submitted);
            }
            other => assert!(false, "wrong variant: {:?}", other),
        }
    }

    #[test]
    fn test_governance_all_statuses() {
        let (mock, writer) = make_writer();
        let statuses = [
            GovernanceStatus::Submitted,
            GovernanceStatus::Approved,
            GovernanceStatus::Rejected,
            GovernanceStatus::Executed,
            GovernanceStatus::Expired,
        ];
        for s in statuses {
            let r = emit_governance_proposal(&writer, "p", "a", "t", 0, s);
            assert!(r.is_ok());
        }
        assert_eq!(mock.event_count(), 5);
    }

    #[test]
    fn test_multiple_events_sequence() {
        let (mock, writer) = make_writer();
        let _ = emit_da_fallback_activated(&writer, "a", "b", "r", 1);
        let _ = emit_da_sync_sequence(&writer, "c", 10, 9, 1);
        let _ = emit_committee_rotation(&writer, 1, 2, [0; 32], [1; 32], 3, 2);
        let _ = emit_governance_proposal(&writer, "p", "a", "t", 0, GovernanceStatus::Submitted);
        let _ = emit_da_fallback_deactivated(&writer, "b", "a", "r", 2);
        assert_eq!(mock.event_count(), 5);
    }

    #[test]
    fn test_timestamp_nonzero() {
        let ts = now_ms();
        assert!(ts > 0);
    }

    #[test]
    fn test_event_fields_correct() {
        let (mock, writer) = make_writer();
        let _ = emit_da_fallback_activated(&writer, "celestia", "quorum", "primary_down", 42);
        let events = mock.recorded_events();
        match &events[0] {
            AuditLogEvent::DaFallbackEvent {
                version, action, previous_source, new_source, reason, celestia_last_height, ..
            } => {
                assert_eq!(*version, 1u8);
                assert_eq!(*action, DaFallbackAction::Activated);
                assert_eq!(previous_source, "celestia");
                assert_eq!(new_source, "quorum");
                assert_eq!(reason, "primary_down");
                assert_eq!(*celestia_last_height, 42);
            }
            other => assert!(false, "wrong variant: {:?}", other),
        }
    }
}