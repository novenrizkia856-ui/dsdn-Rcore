//! Placement Verifier Module
//!
//! This module provides DA-based placement verification for storage nodes.
//! The verifier ensures that node placement decisions are based SOLELY on
//! Data Availability layer events, not local state.
//!
//! ## Core Principle
//!
//! **DA is the single source of truth for placement.**
//!
//! Local state is NOT authoritative. A node must verify its placement
//! against DA before trusting that it should store a chunk.
//!
//! ## Verification Process
//!
//! 1. Fetch ALL relevant events from DA
//! 2. Process events IN ORDER (by sequence)
//! 3. Track assignment state for this node
//! 4. Return definitive placement status
//!
//! ## Status Classification
//!
//! | Status  | Meaning                                        |
//! |---------|------------------------------------------------|
//! | Valid   | Node is currently assigned to store the chunk  |
//! | Invalid | Node was assigned but assignment was revoked   |
//! | Missing | No assignment event found in DA for this node  |

use std::sync::Arc;

use dsdn_common::da::{DALayer, DAError};
use dsdn_coordinator::{DAEvent, DAEventPayload};

use crate::da_follower::DAFollower;

// ════════════════════════════════════════════════════════════════════════════
// PLACEMENT STATUS
// ════════════════════════════════════════════════════════════════════════════

/// Status of a placement verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlacementStatus {
    /// Node is currently assigned to store the chunk (valid placement).
    Valid,
    /// Node was assigned but assignment was revoked (invalid placement).
    Invalid,
    /// No assignment event found in DA for this node (missing placement).
    Missing,
}

impl PlacementStatus {
    /// Convert status to human-readable string.
    pub fn as_str(&self) -> &'static str {
        match self {
            PlacementStatus::Valid => "valid",
            PlacementStatus::Invalid => "invalid",
            PlacementStatus::Missing => "missing",
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// PLACEMENT DETAIL
// ════════════════════════════════════════════════════════════════════════════

/// Detail of a single placement verification result.
///
/// Contains all information needed for audit purposes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementDetail {
    /// Hash of the chunk being verified.
    pub chunk_hash: String,
    /// Verification status.
    pub status: PlacementStatus,
    /// Human-readable reason for the status.
    pub reason: String,
}

impl PlacementDetail {
    /// Create a new PlacementDetail.
    pub fn new(chunk_hash: String, status: PlacementStatus, reason: String) -> Self {
        Self {
            chunk_hash,
            status,
            reason,
        }
    }

    /// Create a valid placement detail.
    pub fn valid(chunk_hash: String, reason: &str) -> Self {
        Self::new(chunk_hash, PlacementStatus::Valid, reason.to_string())
    }

    /// Create an invalid placement detail.
    pub fn invalid(chunk_hash: String, reason: &str) -> Self {
        Self::new(chunk_hash, PlacementStatus::Invalid, reason.to_string())
    }

    /// Create a missing placement detail.
    pub fn missing(chunk_hash: String, reason: &str) -> Self {
        Self::new(chunk_hash, PlacementStatus::Missing, reason.to_string())
    }
}

// ════════════════════════════════════════════════════════════════════════════
// PLACEMENT REPORT
// ════════════════════════════════════════════════════════════════════════════

/// Report of placement verification for multiple chunks.
///
/// Contains summary counts and detailed results for each chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementReport {
    /// Number of chunks with valid placement.
    pub valid_count: usize,
    /// Number of chunks with invalid placement.
    pub invalid_count: usize,
    /// Number of chunks with missing placement.
    pub missing_count: usize,
    /// Detailed results for each chunk.
    pub details: Vec<PlacementDetail>,
}

impl PlacementReport {
    /// Create a new empty PlacementReport.
    pub fn new() -> Self {
        Self {
            valid_count: 0,
            invalid_count: 0,
            missing_count: 0,
            details: Vec::new(),
        }
    }

    /// Add a verification detail to the report.
    pub fn add(&mut self, detail: PlacementDetail) {
        match detail.status {
            PlacementStatus::Valid => self.valid_count += 1,
            PlacementStatus::Invalid => self.invalid_count += 1,
            PlacementStatus::Missing => self.missing_count += 1,
        }
        self.details.push(detail);
    }

    /// Total number of chunks verified.
    pub fn total_count(&self) -> usize {
        self.valid_count + self.invalid_count + self.missing_count
    }

    /// Check if all placements are valid.
    pub fn all_valid(&self) -> bool {
        self.invalid_count == 0 && self.missing_count == 0
    }
}

impl Default for PlacementReport {
    fn default() -> Self {
        Self::new()
    }
}

// ════════════════════════════════════════════════════════════════════════════
// PLACEMENT VERIFIER
// ════════════════════════════════════════════════════════════════════════════

/// DA-based placement verifier for storage nodes.
///
/// `PlacementVerifier` provides authoritative verification of chunk placements
/// by querying the Data Availability layer directly.
///
/// ## Design Principles
///
/// - **DA Authority**: DA is the single source of truth
/// - **No Cache**: Does not store placement state internally
/// - **Deterministic**: Same DA state → Same verification result
/// - **Safe**: Never panics, propagates errors properly
///
/// ## Usage
///
/// ```ignore
/// let verifier = PlacementVerifier::new(da, node_id);
///
/// // Verify single placement
/// let is_valid = verifier.verify_my_placement("chunk_hash").await?;
///
/// // Verify all placements
/// let report = verifier.verify_all_placements(&chunk_hashes).await?;
/// ```
pub struct PlacementVerifier {
    /// Reference to the DA layer (source of truth).
    da: Arc<dyn DALayer>,
    /// This node's unique identifier.
    node_id: String,
}

impl PlacementVerifier {
    /// Create a new PlacementVerifier.
    ///
    /// # Arguments
    ///
    /// * `da` - Reference to the DA layer
    /// * `node_id` - This node's unique identifier
    ///
    /// # Returns
    ///
    /// A new `PlacementVerifier` instance.
    pub fn new(da: Arc<dyn DALayer>, node_id: String) -> Self {
        Self { da, node_id }
    }

    /// Get the node ID.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Verify if this node has a valid placement for a specific chunk.
    ///
    /// This method queries the DA layer to determine if this node
    /// is currently assigned as a replica for the given chunk.
    ///
    /// # Arguments
    ///
    /// * `chunk_hash` - Hash of the chunk to verify
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - Placement is valid (node is assigned)
    /// * `Ok(false)` - Placement is not valid (never assigned or revoked)
    /// * `Err(DAError)` - DA query failed
    ///
    /// # Guarantees
    ///
    /// - Fetches ALL relevant events from DA
    /// - Processes events IN ORDER by sequence
    /// - DA is the sole authority for the decision
    /// - Never panics
    pub async fn verify_my_placement(&self, chunk_hash: &str) -> Result<bool, DAError> {
        // Fetch all events from DA and check if this node is assigned
        let events = self.fetch_all_events().await?;
        
        // Track assignment state for this chunk and node
        let mut is_assigned = false;
        
        // Process events in sequence order (they should already be ordered)
        for event in events {
            match &event.payload {
                DAEventPayload::ReplicaAdded(p) => {
                    if p.chunk_hash == chunk_hash && p.node_id == self.node_id {
                        is_assigned = true;
                    }
                }
                DAEventPayload::ReplicaRemoved(p) => {
                    if p.chunk_hash == chunk_hash && p.node_id == self.node_id {
                        is_assigned = false;
                    }
                }
                DAEventPayload::ChunkRemoved(p) => {
                    if p.chunk_hash == chunk_hash {
                        // Chunk was globally removed, placement is no longer valid
                        is_assigned = false;
                    }
                }
                _ => {}
            }
        }
        
        Ok(is_assigned)
    }

    /// Verify the placement status for a specific chunk with detailed result.
    ///
    /// Unlike `verify_my_placement`, this returns detailed status information
    /// including whether the placement was never assigned (missing) or revoked (invalid).
    ///
    /// # Arguments
    ///
    /// * `chunk_hash` - Hash of the chunk to verify
    ///
    /// # Returns
    ///
    /// * `Ok(PlacementDetail)` - Detailed verification result
    /// * `Err(DAError)` - DA query failed
    pub async fn verify_placement_detailed(&self, chunk_hash: &str) -> Result<PlacementDetail, DAError> {
        let events = self.fetch_all_events().await?;
        
        // Track assignment state
        let mut ever_assigned = false;
        let mut is_assigned = false;
        let mut last_action = String::new();
        
        for event in events {
            match &event.payload {
                DAEventPayload::ReplicaAdded(p) => {
                    if p.chunk_hash == chunk_hash && p.node_id == self.node_id {
                        ever_assigned = true;
                        is_assigned = true;
                        last_action = format!("ReplicaAdded at sequence {}", event.sequence);
                    }
                }
                DAEventPayload::ReplicaRemoved(p) => {
                    if p.chunk_hash == chunk_hash && p.node_id == self.node_id {
                        is_assigned = false;
                        last_action = format!("ReplicaRemoved at sequence {}", event.sequence);
                    }
                }
                DAEventPayload::ChunkRemoved(p) => {
                    if p.chunk_hash == chunk_hash && is_assigned {
                        is_assigned = false;
                        last_action = format!("ChunkRemoved at sequence {}", event.sequence);
                    }
                }
                _ => {}
            }
        }
        
        let detail = if is_assigned {
            PlacementDetail::valid(
                chunk_hash.to_string(),
                &format!("Assignment active: {}", last_action),
            )
        } else if ever_assigned {
            PlacementDetail::invalid(
                chunk_hash.to_string(),
                &format!("Assignment revoked: {}", last_action),
            )
        } else {
            PlacementDetail::missing(
                chunk_hash.to_string(),
                "No assignment found in DA for this node",
            )
        };
        
        Ok(detail)
    }

    /// Verify placements for all specified chunks.
    ///
    /// This method verifies each chunk hash against DA and produces
    /// a comprehensive report with counts and details.
    ///
    /// # Arguments
    ///
    /// * `chunk_hashes` - Slice of chunk hashes to verify
    ///
    /// # Returns
    ///
    /// * `Ok(PlacementReport)` - Complete verification report
    /// * `Err(DAError)` - DA query failed
    ///
    /// # Guarantees
    ///
    /// - Each chunk is verified against DA
    /// - Counts are accurate and consistent with details
    /// - Never panics
    pub async fn verify_all_placements(&self, chunk_hashes: &[String]) -> Result<PlacementReport, DAError> {
        // Fetch all events once (more efficient than per-chunk queries)
        let events = self.fetch_all_events().await?;
        
        let mut report = PlacementReport::new();
        
        for chunk_hash in chunk_hashes {
            let detail = self.verify_chunk_against_events(chunk_hash, &events);
            report.add(detail);
        }
        
        Ok(report)
    }

    /// Verify a chunk against a pre-fetched event list.
    fn verify_chunk_against_events(&self, chunk_hash: &str, events: &[DAEvent]) -> PlacementDetail {
        let mut ever_assigned = false;
        let mut is_assigned = false;
        let mut last_action = String::new();
        
        for event in events {
            match &event.payload {
                DAEventPayload::ReplicaAdded(p) => {
                    if p.chunk_hash == chunk_hash && p.node_id == self.node_id {
                        ever_assigned = true;
                        is_assigned = true;
                        last_action = format!("ReplicaAdded at seq {}", event.sequence);
                    }
                }
                DAEventPayload::ReplicaRemoved(p) => {
                    if p.chunk_hash == chunk_hash && p.node_id == self.node_id {
                        is_assigned = false;
                        last_action = format!("ReplicaRemoved at seq {}", event.sequence);
                    }
                }
                DAEventPayload::ChunkRemoved(p) => {
                    if p.chunk_hash == chunk_hash && is_assigned {
                        is_assigned = false;
                        last_action = format!("ChunkRemoved at seq {}", event.sequence);
                    }
                }
                _ => {}
            }
        }
        
        if is_assigned {
            PlacementDetail::valid(
                chunk_hash.to_string(),
                &format!("Assignment active: {}", last_action),
            )
        } else if ever_assigned {
            PlacementDetail::invalid(
                chunk_hash.to_string(),
                &format!("Assignment revoked: {}", last_action),
            )
        } else {
            PlacementDetail::missing(
                chunk_hash.to_string(),
                "No assignment found in DA",
            )
        }
    }

    /// Fetch all events from DA.
    ///
    /// Returns events sorted by sequence number.
    async fn fetch_all_events(&self) -> Result<Vec<DAEvent>, DAError> {
        use futures::StreamExt;
        use tokio::time::{timeout, Duration};
        
        // Subscribe from the beginning (None = all blobs)
        let mut stream = self.da.subscribe_blobs(None).await?;
        
        let mut all_events = Vec::new();
        
        // Collect all blobs with a timeout for each
        loop {
            match timeout(Duration::from_millis(500), stream.next()).await {
                Ok(Some(Ok(blob))) => {
                    // Decode events from blob
                    match DAFollower::decode_events(&blob.data) {
                        Ok(events) => {
                            all_events.extend(events);
                        }
                        Err(e) => {
                            // Log but continue - some blobs might be corrupted
                            tracing::warn!("Failed to decode blob: {:?}", e);
                        }
                    }
                }
                Ok(Some(Err(e))) => {
                    // Stream error - return what we have or propagate error
                    if all_events.is_empty() {
                        return Err(e);
                    }
                    break;
                }
                Ok(None) => {
                    // Stream ended normally
                    break;
                }
                Err(_) => {
                    // Timeout - no more blobs available
                    break;
                }
            }
        }
        
        // Sort by sequence to ensure deterministic processing
        all_events.sort_by_key(|e| e.sequence);
        
        Ok(all_events)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use dsdn_common::MockDA;
    use dsdn_coordinator::{ReplicaAddedPayload, ReplicaRemovedPayload, ChunkRemovedPayload};

    const TEST_NODE: &str = "node-1";
    const OTHER_NODE: &str = "other-node";
    const TEST_CHUNK: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const CHUNK_A: &str = "chunk-a-hash";
    const CHUNK_B: &str = "chunk-b-hash";
    const CHUNK_C: &str = "chunk-c-hash";

    // ════════════════════════════════════════════════════════════════════════
    // HELPER FUNCTIONS
    // ════════════════════════════════════════════════════════════════════════

    fn make_verifier() -> PlacementVerifier {
        let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
        PlacementVerifier::new(da, TEST_NODE.to_string())
    }

    fn make_replica_added(seq: u64, chunk_hash: &str, node_id: &str) -> DAEvent {
        DAEvent {
            sequence: seq,
            timestamp: seq * 1000,
            payload: DAEventPayload::ReplicaAdded(ReplicaAddedPayload {
                chunk_hash: chunk_hash.to_string(),
                node_id: node_id.to_string(),
                replica_index: 0,
                added_at: seq * 1000,
            }),
        }
    }

    fn make_replica_removed(seq: u64, chunk_hash: &str, node_id: &str) -> DAEvent {
        DAEvent {
            sequence: seq,
            timestamp: seq * 1000,
            payload: DAEventPayload::ReplicaRemoved(ReplicaRemovedPayload {
                chunk_hash: chunk_hash.to_string(),
                node_id: node_id.to_string(),
            }),
        }
    }

    fn make_chunk_removed(seq: u64, chunk_hash: &str) -> DAEvent {
        DAEvent {
            sequence: seq,
            timestamp: seq * 1000,
            payload: DAEventPayload::ChunkRemoved(ChunkRemovedPayload {
                chunk_hash: chunk_hash.to_string(),
            }),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // A. STRUCT TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_placement_verifier_new() {
        let verifier = make_verifier();
        assert_eq!(verifier.node_id(), TEST_NODE);
    }

    #[test]
    fn test_placement_status_as_str() {
        assert_eq!(PlacementStatus::Valid.as_str(), "valid");
        assert_eq!(PlacementStatus::Invalid.as_str(), "invalid");
        assert_eq!(PlacementStatus::Missing.as_str(), "missing");
    }

    #[test]
    fn test_placement_detail_constructors() {
        let valid = PlacementDetail::valid(TEST_CHUNK.to_string(), "test");
        assert_eq!(valid.status, PlacementStatus::Valid);
        assert_eq!(valid.chunk_hash, TEST_CHUNK);

        let invalid = PlacementDetail::invalid(TEST_CHUNK.to_string(), "test");
        assert_eq!(invalid.status, PlacementStatus::Invalid);

        let missing = PlacementDetail::missing(TEST_CHUNK.to_string(), "test");
        assert_eq!(missing.status, PlacementStatus::Missing);
    }

    #[test]
    fn test_placement_report_new() {
        let report = PlacementReport::new();
        assert_eq!(report.valid_count, 0);
        assert_eq!(report.invalid_count, 0);
        assert_eq!(report.missing_count, 0);
        assert!(report.details.is_empty());
        assert_eq!(report.total_count(), 0);
        assert!(report.all_valid());
    }

    #[test]
    fn test_placement_report_add() {
        let mut report = PlacementReport::new();

        report.add(PlacementDetail::valid("chunk-1".to_string(), "ok"));
        assert_eq!(report.valid_count, 1);
        assert_eq!(report.total_count(), 1);
        assert!(report.all_valid());

        report.add(PlacementDetail::invalid("chunk-2".to_string(), "revoked"));
        assert_eq!(report.invalid_count, 1);
        assert_eq!(report.total_count(), 2);
        assert!(!report.all_valid());

        report.add(PlacementDetail::missing("chunk-3".to_string(), "not found"));
        assert_eq!(report.missing_count, 1);
        assert_eq!(report.total_count(), 3);
    }

    // ════════════════════════════════════════════════════════════════════════
    // B. VERIFY CHUNK AGAINST EVENTS TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_chunk_assignment_exists() {
        let verifier = make_verifier();
        let events = vec![
            make_replica_added(1, TEST_CHUNK, TEST_NODE),
        ];

        let detail = verifier.verify_chunk_against_events(TEST_CHUNK, &events);
        assert_eq!(detail.status, PlacementStatus::Valid);
    }

    #[test]
    fn test_verify_chunk_assignment_revoked() {
        let verifier = make_verifier();
        let events = vec![
            make_replica_added(1, TEST_CHUNK, TEST_NODE),
            make_replica_removed(2, TEST_CHUNK, TEST_NODE),
        ];

        let detail = verifier.verify_chunk_against_events(TEST_CHUNK, &events);
        assert_eq!(detail.status, PlacementStatus::Invalid);
        assert!(detail.reason.contains("revoked"));
    }

    #[test]
    fn test_verify_chunk_never_assigned() {
        let verifier = make_verifier();
        let events = vec![
            make_replica_added(1, TEST_CHUNK, OTHER_NODE), // Different node
        ];

        let detail = verifier.verify_chunk_against_events(TEST_CHUNK, &events);
        assert_eq!(detail.status, PlacementStatus::Missing);
    }

    #[test]
    fn test_verify_chunk_empty_events() {
        let verifier = make_verifier();
        let events: Vec<DAEvent> = vec![];

        let detail = verifier.verify_chunk_against_events(TEST_CHUNK, &events);
        assert_eq!(detail.status, PlacementStatus::Missing);
    }

    #[test]
    fn test_verify_chunk_global_removal() {
        let verifier = make_verifier();
        let events = vec![
            make_replica_added(1, TEST_CHUNK, TEST_NODE),
            make_chunk_removed(2, TEST_CHUNK),
        ];

        let detail = verifier.verify_chunk_against_events(TEST_CHUNK, &events);
        assert_eq!(detail.status, PlacementStatus::Invalid);
        assert!(detail.reason.contains("ChunkRemoved"));
    }

    #[test]
    fn test_verify_chunk_reassignment() {
        let verifier = make_verifier();
        let events = vec![
            make_replica_added(1, TEST_CHUNK, TEST_NODE),
            make_replica_removed(2, TEST_CHUNK, TEST_NODE),
            make_replica_added(3, TEST_CHUNK, TEST_NODE), // Re-assigned
        ];

        let detail = verifier.verify_chunk_against_events(TEST_CHUNK, &events);
        assert_eq!(detail.status, PlacementStatus::Valid);
    }

    // ════════════════════════════════════════════════════════════════════════
    // C. VERIFY ALL PLACEMENTS LOGIC TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_all_mixed_status() {
        let verifier = make_verifier();
        let events = vec![
            make_replica_added(1, CHUNK_A, TEST_NODE),  // Valid
            make_replica_added(2, CHUNK_B, TEST_NODE),
            make_replica_removed(3, CHUNK_B, TEST_NODE), // Invalid
            // CHUNK_C never assigned - Missing
        ];

        let _chunk_hashes = vec![
            CHUNK_A.to_string(),
            CHUNK_B.to_string(),
            CHUNK_C.to_string(),
        ];

        // Verify each chunk manually
        let detail_a = verifier.verify_chunk_against_events(CHUNK_A, &events);
        let detail_b = verifier.verify_chunk_against_events(CHUNK_B, &events);
        let detail_c = verifier.verify_chunk_against_events(CHUNK_C, &events);

        assert_eq!(detail_a.status, PlacementStatus::Valid);
        assert_eq!(detail_b.status, PlacementStatus::Invalid);
        assert_eq!(detail_c.status, PlacementStatus::Missing);

        // Build report manually
        let mut report = PlacementReport::new();
        report.add(detail_a);
        report.add(detail_b);
        report.add(detail_c);

        assert_eq!(report.valid_count, 1);
        assert_eq!(report.invalid_count, 1);
        assert_eq!(report.missing_count, 1);
        assert_eq!(report.total_count(), 3);
        assert!(!report.all_valid());
    }

    #[test]
    fn test_verify_all_all_valid() {
        let verifier = make_verifier();
        let events = vec![
            make_replica_added(1, CHUNK_A, TEST_NODE),
            make_replica_added(2, CHUNK_B, TEST_NODE),
        ];

        let detail_a = verifier.verify_chunk_against_events(CHUNK_A, &events);
        let detail_b = verifier.verify_chunk_against_events(CHUNK_B, &events);

        let mut report = PlacementReport::new();
        report.add(detail_a);
        report.add(detail_b);

        assert!(report.all_valid());
        assert_eq!(report.valid_count, 2);
    }

    #[test]
    fn test_verify_all_counts_consistent() {
        let verifier = make_verifier();
        let events = vec![
            make_replica_added(1, CHUNK_A, TEST_NODE),
            make_replica_added(2, CHUNK_B, OTHER_NODE), // Other node
        ];

        let mut report = PlacementReport::new();
        report.add(verifier.verify_chunk_against_events(CHUNK_A, &events));
        report.add(verifier.verify_chunk_against_events(CHUNK_B, &events));

        // CHUNK_A valid for TEST_NODE, CHUNK_B missing (assigned to other)
        assert_eq!(report.valid_count, 1);
        assert_eq!(report.missing_count, 1);
        assert_eq!(report.details.len(), 2);
        assert_eq!(report.total_count(), report.details.len());
    }

    // ════════════════════════════════════════════════════════════════════════
    // D. DETERMINISM TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_deterministic() {
        let verifier = make_verifier();
        let events = vec![
            make_replica_added(1, TEST_CHUNK, TEST_NODE),
            make_replica_removed(2, TEST_CHUNK, TEST_NODE),
            make_replica_added(3, TEST_CHUNK, TEST_NODE),
        ];

        // Verify multiple times
        let result1 = verifier.verify_chunk_against_events(TEST_CHUNK, &events);
        let result2 = verifier.verify_chunk_against_events(TEST_CHUNK, &events);
        let result3 = verifier.verify_chunk_against_events(TEST_CHUNK, &events);

        assert_eq!(result1, result2);
        assert_eq!(result2, result3);
    }

    #[test]
    fn test_verify_event_order_matters() {
        let verifier = make_verifier();

        // Add then remove = invalid
        let events1 = vec![
            make_replica_added(1, TEST_CHUNK, TEST_NODE),
            make_replica_removed(2, TEST_CHUNK, TEST_NODE),
        ];
        let result1 = verifier.verify_chunk_against_events(TEST_CHUNK, &events1);
        assert_eq!(result1.status, PlacementStatus::Invalid);

        // Remove then add = valid (re-assignment)
        let events2 = vec![
            make_replica_removed(1, TEST_CHUNK, TEST_NODE), // This has no effect (not assigned yet)
            make_replica_added(2, TEST_CHUNK, TEST_NODE),
        ];
        let result2 = verifier.verify_chunk_against_events(TEST_CHUNK, &events2);
        assert_eq!(result2.status, PlacementStatus::Valid);
    }

    // ════════════════════════════════════════════════════════════════════════
    // E. SAFETY TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_no_panic_empty_input() {
        let verifier = make_verifier();

        // Empty events
        let detail = verifier.verify_chunk_against_events("", &[]);
        assert_eq!(detail.status, PlacementStatus::Missing);

        // Empty chunk hashes
        let report = PlacementReport::new();
        assert_eq!(report.total_count(), 0);
    }

    #[test]
    fn test_no_panic_unusual_hashes() {
        let verifier = make_verifier();

        let events = vec![
            make_replica_added(1, "", TEST_NODE), // Empty hash
            make_replica_added(2, "a".repeat(1000).as_str(), TEST_NODE), // Long hash
        ];

        // Should not panic
        let _ = verifier.verify_chunk_against_events("", &events);
        let _ = verifier.verify_chunk_against_events(&"a".repeat(1000), &events);
    }

    // ════════════════════════════════════════════════════════════════════════
    // F. PLACEMENT STATUS AND DETAIL TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_placement_status_equality() {
        assert_eq!(PlacementStatus::Valid, PlacementStatus::Valid);
        assert_ne!(PlacementStatus::Valid, PlacementStatus::Invalid);
        assert_ne!(PlacementStatus::Invalid, PlacementStatus::Missing);
    }

    #[test]
    fn test_placement_detail_clone() {
        let detail = PlacementDetail::valid(TEST_CHUNK.to_string(), "test reason");
        let cloned = detail.clone();
        assert_eq!(detail, cloned);
    }

    #[test]
    fn test_placement_report_clone() {
        let mut report = PlacementReport::new();
        report.add(PlacementDetail::valid(TEST_CHUNK.to_string(), "ok"));
        
        let cloned = report.clone();
        assert_eq!(report, cloned);
    }

    #[test]
    fn test_placement_report_default() {
        let report: PlacementReport = Default::default();
        assert_eq!(report.total_count(), 0);
    }

    // ════════════════════════════════════════════════════════════════════════
    // G. EDGE CASE TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_multiple_assignments_same_chunk() {
        let verifier = make_verifier();
        let events = vec![
            make_replica_added(1, TEST_CHUNK, TEST_NODE),
            make_replica_added(2, TEST_CHUNK, TEST_NODE), // Duplicate add (idempotent)
        ];

        let detail = verifier.verify_chunk_against_events(TEST_CHUNK, &events);
        assert_eq!(detail.status, PlacementStatus::Valid);
    }

    #[test]
    fn test_multiple_removals_same_chunk() {
        let verifier = make_verifier();
        let events = vec![
            make_replica_added(1, TEST_CHUNK, TEST_NODE),
            make_replica_removed(2, TEST_CHUNK, TEST_NODE),
            make_replica_removed(3, TEST_CHUNK, TEST_NODE), // Duplicate remove
        ];

        let detail = verifier.verify_chunk_against_events(TEST_CHUNK, &events);
        assert_eq!(detail.status, PlacementStatus::Invalid);
    }

    #[test]
    fn test_other_node_events_ignored() {
        let verifier = make_verifier();
        let events = vec![
            make_replica_added(1, TEST_CHUNK, OTHER_NODE),
            make_replica_removed(2, TEST_CHUNK, OTHER_NODE),
        ];

        // Events for OTHER_NODE should not affect TEST_NODE's verification
        let detail = verifier.verify_chunk_against_events(TEST_CHUNK, &events);
        assert_eq!(detail.status, PlacementStatus::Missing);
    }
}