//! Event Processor Module for Node
//!
//! This module provides the `NodeEventProcessor` component that translates
//! DA events into node-specific actions.
//!
//! ## Role
//!
//! The event processor is the "brain" of node logic:
//!
//! - Determines if an event is relevant to this node
//! - Translates events into `NodeAction`
//! - Does NOT modify state
//! - Does NOT perform IO
//! - Does NOT execute actions
//! - Only PRODUCES DECISIONS
//!
//! ## Safety Guarantees
//!
//! - Pure function logic only
//! - Deterministic behavior
//! - No panics
//! - No side effects
//!
//! ## Event Relevance
//!
//! Node ONLY reacts to events that:
//! - Directly reference this node's `node_id`
//! - Affect `my_chunks` or local status
//!
//! All other events result in `NodeAction::NoAction`.

use std::sync::Arc;

use parking_lot::RwLock;
use thiserror::Error;
use tracing::{info, warn};

use dsdn_coordinator::{DAEvent, DAEventPayload, ReplicaAddedPayload, ReplicaRemovedPayload};

use crate::da_follower::NodeDerivedState;
use crate::multi_da_source::DASourceType;

// ════════════════════════════════════════════════════════════════════════════
// PROCESS ERROR
// ════════════════════════════════════════════════════════════════════════════

/// Errors that can occur during event processing.
///
/// Note: Events that are not relevant to this node are NOT errors.
/// They result in `NodeAction::NoAction` instead.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ProcessError {
    /// Event data is malformed or invalid.
    #[error("Malformed event: {0}")]
    MalformedEvent(String),

    /// State is inconsistent with event.
    #[error("Inconsistent state: {0}")]
    InconsistentState(String),
}

// ════════════════════════════════════════════════════════════════════════════
// NODE ACTION
// ════════════════════════════════════════════════════════════════════════════

/// Actions that a node should take in response to DA events.
///
/// This enum describes WHAT action to take, not HOW to execute it.
/// The actual execution is handled by separate components.
///
/// ## Variants
///
/// - `NoAction`: Event is not relevant to this node
/// - `StoreChunk`: Node should store a new chunk
/// - `DeleteChunk`: Node should delete a chunk
/// - `UpdateReplicaStatus`: Node should update verification status
/// - `SyncFromPeer`: Node should sync chunk data from another node
/// - `SwitchToFallback`: Node should switch to fallback DA source (14A.1A.45)
/// - `SwitchToPrimary`: Node should switch back to primary DA source (14A.1A.45)
/// - `VerifyReconciliation`: Node should verify local state consistency (14A.1A.45)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeAction {
    /// No action required. Event is not relevant to this node.
    NoAction,

    /// Store a new chunk assigned to this node.
    StoreChunk {
        /// Hash of the chunk to store
        hash: String,
        /// Node to fetch chunk data from (if not uploader)
        source_node: String,
    },

    /// Delete a chunk that is no longer assigned to this node.
    DeleteChunk {
        /// Hash of the chunk to delete
        hash: String,
    },

    /// Update the verification status of a replica.
    UpdateReplicaStatus {
        /// Hash of the chunk
        hash: String,
        /// Whether the replica is verified
        verified: bool,
    },

    /// Sync chunk data from a peer node.
    SyncFromPeer {
        /// Hash of the chunk to sync
        hash: String,
        /// Peer node to sync from
        peer_node: String,
    },

    /// Switch to fallback DA source (14A.1A.45).
    ///
    /// Triggered when primary DA becomes unavailable and fallback is activated.
    /// The executor should:
    /// 1. Update local fallback status flag
    /// 2. Log the switch explicitly
    /// 3. Continue event processing with new source
    SwitchToFallback {
        /// Previous DA source before switch
        from_source: DASourceType,
        /// Target fallback DA source
        to_source: DASourceType,
        /// Reason for the switch
        reason: String,
    },

    /// Switch back to primary DA source (14A.1A.45).
    ///
    /// Triggered when primary DA becomes available again.
    /// The executor should:
    /// 1. Clear local fallback status flag
    /// 2. Log the switch explicitly
    /// 3. Continue event processing with primary
    SwitchToPrimary {
        /// Previous fallback source
        from_source: DASourceType,
    },

    /// Verify local state consistency after reconciliation (14A.1A.45).
    ///
    /// Triggered after source switch to verify no events were missed.
    /// The executor should:
    /// 1. Compare local sequence/height against expected
    /// 2. Report any gaps found
    /// 3. Trigger resync if needed
    VerifyReconciliation {
        /// Expected last sequence number
        expected_sequence: u64,
        /// Expected last height
        expected_height: u64,
        /// Local sequence at time of check
        local_sequence: u64,
        /// Local height at time of check
        local_height: u64,
    },
}

// ════════════════════════════════════════════════════════════════════════════
// NODE EVENT PROCESSOR
// ════════════════════════════════════════════════════════════════════════════

/// Event processor for translating DA events into node actions.
///
/// `NodeEventProcessor` is the decision-making core of a storage node.
/// It examines incoming DA events and determines what action (if any)
/// the node should take.
///
/// ## Design Principles
///
/// - **Pure Logic**: No side effects, no IO, no state mutation
/// - **Deterministic**: Same inputs always produce same outputs
/// - **Safe**: Never panics, handles all edge cases gracefully
/// - **Selective**: Only produces actions for relevant events
///
/// ## Usage
///
/// ```ignore
/// let processor = NodeEventProcessor::new(node_id, state);
/// let action = processor.process_event(&event)?;
/// // Execute action separately...
/// ```
pub struct NodeEventProcessor {
    /// This node's unique identifier
    node_id: String,
    /// Reference to node's derived state (read-only access)
    state: Arc<RwLock<NodeDerivedState>>,
}

impl NodeEventProcessor {
    /// Create a new NodeEventProcessor.
    ///
    /// # Arguments
    ///
    /// * `node_id` - Unique identifier for this node
    /// * `state` - Reference to node's derived state
    ///
    /// # Returns
    ///
    /// A new `NodeEventProcessor` instance.
    pub fn new(node_id: String, state: Arc<RwLock<NodeDerivedState>>) -> Self {
        Self { node_id, state }
    }

    /// Get the node ID.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Process a DA event and determine the appropriate action.
    ///
    /// This method examines the event and returns a `NodeAction` describing
    /// what this node should do in response.
    ///
    /// # Arguments
    ///
    /// * `event` - The DA event to process
    ///
    /// # Returns
    ///
    /// * `Ok(NodeAction)` - The action to take (may be `NoAction`)
    /// * `Err(ProcessError)` - Event is malformed or state is inconsistent
    ///
    /// # Guarantees
    ///
    /// - Pure function: no side effects
    /// - No IO operations
    /// - No state mutation
    /// - No panics
    /// - Deterministic behavior
    ///
    /// # Relevance Rules
    ///
    /// Events are only relevant if they directly reference this node's ID
    /// or affect chunks assigned to this node. All other events return
    /// `NodeAction::NoAction` (not an error).
    pub fn process_event(&self, event: &DAEvent) -> Result<NodeAction, ProcessError> {
        match &event.payload {
            DAEventPayload::ReplicaAdded(payload) => {
                self.process_replica_added(payload)
            }
            DAEventPayload::ReplicaRemoved(payload) => {
                self.process_replica_removed(payload)
            }
            DAEventPayload::NodeRegistered(_) => {
                // Node registration events are not directly actionable for this node
                Ok(NodeAction::NoAction)
            }
            DAEventPayload::NodeUnregistered(payload) => {
                // Check if this is our own unregistration
                if payload.node_id == self.node_id {
                    // Node is being unregistered - no specific action
                    // (cleanup would be handled at higher level)
                    Ok(NodeAction::NoAction)
                } else {
                    Ok(NodeAction::NoAction)
                }
            }
            DAEventPayload::ChunkDeclared(_) => {
                // Chunk declaration doesn't directly affect node
                // Node waits for ReplicaAdded to know it's assigned
                Ok(NodeAction::NoAction)
            }
            DAEventPayload::ChunkRemoved(payload) => {
                // Check if we have this chunk
                let state = self.state.read();
                if state.my_chunks.contains_key(&payload.chunk_hash) {
                    // We have this chunk but it's being removed globally
                    // This means we should delete it
                    Ok(NodeAction::DeleteChunk {
                        hash: payload.chunk_hash.clone(),
                    })
                } else {
                    Ok(NodeAction::NoAction)
                }
            }
            DAEventPayload::ZoneAssigned(_) => {
                // Zone assignments don't directly affect node operations
                Ok(NodeAction::NoAction)
            }
            DAEventPayload::ZoneUnassigned(_) => {
                // Zone unassignments don't directly affect node operations
                Ok(NodeAction::NoAction)
            }
        }
    }

    /// Process a ReplicaAdded event.
    fn process_replica_added(&self, payload: &ReplicaAddedPayload) -> Result<NodeAction, ProcessError> {
        // Check if this replica is for our node
        if payload.node_id != self.node_id {
            return Ok(NodeAction::NoAction);
        }

        // Validate payload
        if payload.chunk_hash.is_empty() {
            return Err(ProcessError::MalformedEvent(
                "ReplicaAdded has empty chunk_hash".to_string(),
            ));
        }

        // Check if we already have this chunk (idempotency)
        let state = self.state.read();
        if state.my_chunks.contains_key(&payload.chunk_hash) {
            // Already have this chunk - no action needed
            return Ok(NodeAction::NoAction);
        }

        // Determine source node for fetching chunk data
        // For replica_index 0, we typically sync from uploader
        // For other indices, we sync from existing replica holders
        // Since we don't have uploader info here, we use a placeholder
        // Real implementation would look up chunk metadata
        let source_node = if payload.replica_index == 0 {
            // Primary replica - source would be uploader (not known here)
            // In real implementation, coordinator would provide this
            String::new() // Empty means "from original source"
        } else {
            // Secondary replica - would sync from existing replica holder
            // In real implementation, we'd look up existing replicas
            String::new()
        };

        Ok(NodeAction::StoreChunk {
            hash: payload.chunk_hash.clone(),
            source_node,
        })
    }

    /// Process a ReplicaRemoved event.
    fn process_replica_removed(&self, payload: &ReplicaRemovedPayload) -> Result<NodeAction, ProcessError> {
        // Check if this replica removal is for our node
        if payload.node_id != self.node_id {
            return Ok(NodeAction::NoAction);
        }

        // Validate payload
        if payload.chunk_hash.is_empty() {
            return Err(ProcessError::MalformedEvent(
                "ReplicaRemoved has empty chunk_hash".to_string(),
            ));
        }

        // Return delete action regardless of current state
        // The executor will handle idempotency (deleting non-existent chunk is safe)
        Ok(NodeAction::DeleteChunk {
            hash: payload.chunk_hash.clone(),
        })
    }

    /// Check if an event is relevant to this node.
    ///
    /// This is a utility method for external use (e.g., filtering).
    pub fn is_relevant(&self, event: &DAEvent) -> bool {
        match &event.payload {
            DAEventPayload::ReplicaAdded(p) => p.node_id == self.node_id,
            DAEventPayload::ReplicaRemoved(p) => p.node_id == self.node_id,
            DAEventPayload::ChunkRemoved(p) => {
                self.state.read().my_chunks.contains_key(&p.chunk_hash)
            }
            DAEventPayload::NodeUnregistered(p) => p.node_id == self.node_id,
            _ => false,
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // FALLBACK DETECTION METHODS (14A.1A.45)
    // ════════════════════════════════════════════════════════════════════════════

    /// Handle fallback activation (14A.1A.45).
    ///
    /// Called when DAFollower detects that MultiDASource has switched
    /// from Primary to a fallback source (Secondary or Emergency).
    ///
    /// ## Arguments
    ///
    /// * `from_source` - The previous DA source (should be Primary)
    /// * `to_source` - The fallback DA source being activated
    /// * `reason` - Human-readable reason for the switch
    ///
    /// ## Returns
    ///
    /// `NodeAction::SwitchToFallback` with all relevant information.
    ///
    /// ## Guarantees
    ///
    /// - Always logs the event explicitly
    /// - Deterministic output
    /// - No state mutation
    /// - No panic
    /// - Thread-safe (only reads state)
    pub fn handle_fallback_activated(
        &self,
        from_source: DASourceType,
        to_source: DASourceType,
        reason: &str,
    ) -> NodeAction {
        info!(
            "Fallback ACTIVATED for node {}: {:?} -> {:?}, reason: {}",
            self.node_id, from_source, to_source, reason
        );

        NodeAction::SwitchToFallback {
            from_source,
            to_source,
            reason: reason.to_string(),
        }
    }

    /// Handle fallback deactivation (14A.1A.45).
    ///
    /// Called when DAFollower detects that MultiDASource has switched
    /// back to Primary from a fallback source.
    ///
    /// ## Arguments
    ///
    /// * `from_source` - The fallback source being deactivated
    ///
    /// ## Returns
    ///
    /// `NodeAction::SwitchToPrimary` with the previous source.
    ///
    /// ## Guarantees
    ///
    /// - Always logs the event explicitly
    /// - Deterministic output
    /// - No state mutation
    /// - No panic
    /// - Thread-safe (only reads state)
    pub fn handle_fallback_deactivated(&self, from_source: DASourceType) -> NodeAction {
        info!(
            "Fallback DEACTIVATED for node {}: {:?} -> Primary",
            self.node_id, from_source
        );

        NodeAction::SwitchToPrimary { from_source }
    }

    /// Handle reconciliation completed (14A.1A.45).
    ///
    /// Called after a source switch to verify local state consistency.
    /// This method checks if there are any gaps between local state
    /// and expected state.
    ///
    /// ## Arguments
    ///
    /// * `expected_sequence` - Expected last sequence after reconciliation
    /// * `expected_height` - Expected last height after reconciliation
    ///
    /// ## Returns
    ///
    /// * `Ok(NodeAction::VerifyReconciliation)` - Action with comparison data
    /// * `Err(ProcessError::InconsistentState)` - If gap is detected and explicit error needed
    ///
    /// ## Guarantees
    ///
    /// - Always logs the verification attempt
    /// - Explicit error if inconsistency detected (no silent ignore)
    /// - Deterministic output
    /// - No state mutation
    /// - No panic
    /// - Thread-safe (only reads state)
    ///
    /// ## Gap Handling
    ///
    /// - If local_sequence < expected_sequence: potential missing events (returns error)
    /// - If local_sequence > expected_sequence: local ahead (logged as warning, returns action)
    /// - If local_sequence == expected_sequence: consistent (returns action)
    pub fn handle_reconciliation_completed(
        &self,
        expected_sequence: u64,
        expected_height: u64,
    ) -> Result<NodeAction, ProcessError> {
        // Read local state (thread-safe via RwLock)
        let state = self.state.read();
        let local_sequence = state.last_sequence;
        let local_height = state.last_height;
        // Release lock immediately after reading
        drop(state);

        info!(
            "Reconciliation check for node {}: local(seq={}, h={}) vs expected(seq={}, h={})",
            self.node_id, local_sequence, local_height, expected_sequence, expected_height
        );

        // Check for sequence gap (local behind expected)
        if local_sequence < expected_sequence {
            let gap = expected_sequence - local_sequence;
            warn!(
                "Sequence GAP detected for node {}: local {} < expected {}, gap = {}",
                self.node_id, local_sequence, expected_sequence, gap
            );
            // Return explicit error - caller must handle this gap
            return Err(ProcessError::InconsistentState(format!(
                "Sequence gap: local={}, expected={}, gap={}",
                local_sequence, expected_sequence, gap
            )));
        }

        // Check if local is ahead (suspicious but not necessarily error)
        if local_sequence > expected_sequence {
            warn!(
                "Local sequence {} AHEAD of expected {} for node {} (may be normal if events processed before reconciliation)",
                local_sequence, expected_sequence, self.node_id
            );
        }

        // Check height consistency
        if local_height < expected_height {
            warn!(
                "Height mismatch for node {}: local {} < expected {}",
                self.node_id, local_height, expected_height
            );
        }

        // Return verification action with all data for executor to decide
        Ok(NodeAction::VerifyReconciliation {
            expected_sequence,
            expected_height,
            local_sequence,
            local_height,
        })
    }

    /// Check if a source switch represents fallback activation.
    ///
    /// Utility method to determine if switching from one source to another
    /// represents activating a fallback (moving away from Primary).
    ///
    /// ## Arguments
    ///
    /// * `from` - Previous DA source
    /// * `to` - New DA source
    ///
    /// ## Returns
    ///
    /// * `true` - If this is fallback activation (from Primary to Secondary/Emergency)
    /// * `false` - Otherwise
    #[must_use]
    pub fn is_fallback_activation(from: DASourceType, to: DASourceType) -> bool {
        matches!(from, DASourceType::Primary)
            && matches!(to, DASourceType::Secondary | DASourceType::Emergency)
    }

    /// Check if a source switch represents fallback deactivation.
    ///
    /// Utility method to determine if switching from one source to another
    /// represents deactivating a fallback (returning to Primary).
    ///
    /// ## Arguments
    ///
    /// * `from` - Previous DA source
    /// * `to` - New DA source
    ///
    /// ## Returns
    ///
    /// * `true` - If this is fallback deactivation (from Secondary/Emergency to Primary)
    /// * `false` - Otherwise
    #[must_use]
    pub fn is_fallback_deactivation(from: DASourceType, to: DASourceType) -> bool {
        matches!(from, DASourceType::Secondary | DASourceType::Emergency)
            && matches!(to, DASourceType::Primary)
    }

    /// Check if currently in fallback mode based on source type.
    ///
    /// ## Arguments
    ///
    /// * `current_source` - Current DA source type
    ///
    /// ## Returns
    ///
    /// * `true` - If using fallback source (Secondary or Emergency)
    /// * `false` - If using Primary
    #[must_use]
    pub fn is_in_fallback_mode(current_source: DASourceType) -> bool {
        !matches!(current_source, DASourceType::Primary)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use dsdn_coordinator::{
        NodeRegisteredPayload, NodeUnregisteredPayload,
        ChunkDeclaredPayload, ChunkRemovedPayload,
        ZoneAssignedPayload, ZoneUnassignedPayload,
    };
    use crate::da_follower::ChunkAssignment;

    const TEST_NODE: &str = "node-1";
    const OTHER_NODE: &str = "node-2";
    const TEST_CHUNK: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn make_processor() -> NodeEventProcessor {
        let state = Arc::new(RwLock::new(NodeDerivedState::new()));
        NodeEventProcessor::new(TEST_NODE.to_string(), state)
    }

    fn make_processor_with_chunk(chunk_hash: &str) -> NodeEventProcessor {
        let state = Arc::new(RwLock::new(NodeDerivedState::new()));
        {
            let mut s = state.write();
            s.my_chunks.insert(chunk_hash.to_string(), ChunkAssignment {
                hash: chunk_hash.to_string(),
                replica_index: 0,
                assigned_at: 1000,
                verified: false,
                size_bytes: 1024,
            });
        }
        NodeEventProcessor::new(TEST_NODE.to_string(), state)
    }

    fn make_replica_added(node_id: &str, chunk_hash: &str, index: u8) -> DAEvent {
        DAEvent {
            sequence: 1,
            timestamp: 1000,
            payload: DAEventPayload::ReplicaAdded(ReplicaAddedPayload {
                chunk_hash: chunk_hash.to_string(),
                node_id: node_id.to_string(),
                replica_index: index,
                added_at: 1000,
            }),
        }
    }

    fn make_replica_removed(node_id: &str, chunk_hash: &str) -> DAEvent {
        DAEvent {
            sequence: 2,
            timestamp: 2000,
            payload: DAEventPayload::ReplicaRemoved(ReplicaRemovedPayload {
                chunk_hash: chunk_hash.to_string(),
                node_id: node_id.to_string(),
            }),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // A. EVENT NOT RELEVANT TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_replica_added_other_node_no_action() {
        let processor = make_processor();
        let event = make_replica_added(OTHER_NODE, TEST_CHUNK, 0);

        let action = processor.process_event(&event).unwrap();
        assert_eq!(action, NodeAction::NoAction);
    }

    #[test]
    fn test_replica_removed_other_node_no_action() {
        let processor = make_processor();
        let event = make_replica_removed(OTHER_NODE, TEST_CHUNK);

        let action = processor.process_event(&event).unwrap();
        assert_eq!(action, NodeAction::NoAction);
    }

    #[test]
    fn test_node_registered_no_action() {
        let processor = make_processor();
        let event = DAEvent {
            sequence: 1,
            timestamp: 1000,
            payload: DAEventPayload::NodeRegistered(NodeRegisteredPayload {
                node_id: OTHER_NODE.to_string(),
                zone: "zone-a".to_string(),
                addr: "other:7001".to_string(),
                capacity_gb: 100,
            }),
        };

        let action = processor.process_event(&event).unwrap();
        assert_eq!(action, NodeAction::NoAction);
    }

    #[test]
    fn test_node_unregistered_other_no_action() {
        let processor = make_processor();
        let event = DAEvent {
            sequence: 1,
            timestamp: 1000,
            payload: DAEventPayload::NodeUnregistered(NodeUnregisteredPayload {
                node_id: OTHER_NODE.to_string(),
            }),
        };

        let action = processor.process_event(&event).unwrap();
        assert_eq!(action, NodeAction::NoAction);
    }

    #[test]
    fn test_chunk_declared_no_action() {
        let processor = make_processor();
        let event = DAEvent {
            sequence: 1,
            timestamp: 1000,
            payload: DAEventPayload::ChunkDeclared(ChunkDeclaredPayload {
                chunk_hash: TEST_CHUNK.to_string(),
                size_bytes: 1024,
                replication_factor: 3,
                uploader_id: "uploader".to_string(),
                da_commitment: [0u8; 32],
            }),
        };

        let action = processor.process_event(&event).unwrap();
        assert_eq!(action, NodeAction::NoAction);
    }

    #[test]
    fn test_zone_assigned_no_action() {
        let processor = make_processor();
        let event = DAEvent {
            sequence: 1,
            timestamp: 1000,
            payload: DAEventPayload::ZoneAssigned(ZoneAssignedPayload {
                zone_id: "zone-a".to_string(),
                node_id: TEST_NODE.to_string(),
            }),
        };

        let action = processor.process_event(&event).unwrap();
        assert_eq!(action, NodeAction::NoAction);
    }

    #[test]
    fn test_zone_unassigned_no_action() {
        let processor = make_processor();
        let event = DAEvent {
            sequence: 1,
            timestamp: 1000,
            payload: DAEventPayload::ZoneUnassigned(ZoneUnassignedPayload {
                zone_id: "zone-a".to_string(),
                node_id: TEST_NODE.to_string(),
            }),
        };

        let action = processor.process_event(&event).unwrap();
        assert_eq!(action, NodeAction::NoAction);
    }

    // ════════════════════════════════════════════════════════════════════════
    // B. STORE CHUNK TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_replica_added_this_node_store_chunk() {
        let processor = make_processor();
        let event = make_replica_added(TEST_NODE, TEST_CHUNK, 0);

        let action = processor.process_event(&event).unwrap();

        match action {
            NodeAction::StoreChunk { hash, .. } => {
                assert_eq!(hash, TEST_CHUNK);
            }
            _ => panic!("Expected StoreChunk action"),
        }
    }

    #[test]
    fn test_replica_added_this_node_secondary_replica() {
        let processor = make_processor();
        let event = make_replica_added(TEST_NODE, TEST_CHUNK, 1);

        let action = processor.process_event(&event).unwrap();

        match action {
            NodeAction::StoreChunk { hash, .. } => {
                assert_eq!(hash, TEST_CHUNK);
            }
            _ => panic!("Expected StoreChunk action"),
        }
    }

    #[test]
    fn test_replica_added_already_have_chunk_no_action() {
        let processor = make_processor_with_chunk(TEST_CHUNK);
        let event = make_replica_added(TEST_NODE, TEST_CHUNK, 0);

        let action = processor.process_event(&event).unwrap();
        assert_eq!(action, NodeAction::NoAction);
    }

    // ════════════════════════════════════════════════════════════════════════
    // C. DELETE CHUNK TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_replica_removed_this_node_delete_chunk() {
        let processor = make_processor_with_chunk(TEST_CHUNK);
        let event = make_replica_removed(TEST_NODE, TEST_CHUNK);

        let action = processor.process_event(&event).unwrap();

        match action {
            NodeAction::DeleteChunk { hash } => {
                assert_eq!(hash, TEST_CHUNK);
            }
            _ => panic!("Expected DeleteChunk action"),
        }
    }

    #[test]
    fn test_replica_removed_dont_have_chunk_still_delete() {
        let processor = make_processor();
        let event = make_replica_removed(TEST_NODE, TEST_CHUNK);

        let action = processor.process_event(&event).unwrap();

        // Still returns DeleteChunk - executor handles idempotency
        match action {
            NodeAction::DeleteChunk { hash } => {
                assert_eq!(hash, TEST_CHUNK);
            }
            _ => panic!("Expected DeleteChunk action"),
        }
    }

    #[test]
    fn test_chunk_removed_global_delete() {
        let processor = make_processor_with_chunk(TEST_CHUNK);
        let event = DAEvent {
            sequence: 1,
            timestamp: 1000,
            payload: DAEventPayload::ChunkRemoved(ChunkRemovedPayload {
                chunk_hash: TEST_CHUNK.to_string(),
            }),
        };

        let action = processor.process_event(&event).unwrap();

        match action {
            NodeAction::DeleteChunk { hash } => {
                assert_eq!(hash, TEST_CHUNK);
            }
            _ => panic!("Expected DeleteChunk action"),
        }
    }

    #[test]
    fn test_chunk_removed_global_no_have_no_action() {
        let processor = make_processor();
        let event = DAEvent {
            sequence: 1,
            timestamp: 1000,
            payload: DAEventPayload::ChunkRemoved(ChunkRemovedPayload {
                chunk_hash: TEST_CHUNK.to_string(),
            }),
        };

        let action = processor.process_event(&event).unwrap();
        assert_eq!(action, NodeAction::NoAction);
    }

    // ════════════════════════════════════════════════════════════════════════
    // D. IDEMPOTENCY TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_process_same_event_twice_same_action() {
        let processor = make_processor();
        let event = make_replica_added(TEST_NODE, TEST_CHUNK, 0);

        let action1 = processor.process_event(&event).unwrap();
        let action2 = processor.process_event(&event).unwrap();

        assert_eq!(action1, action2);
    }

    #[test]
    fn test_process_delete_twice_same_action() {
        let processor = make_processor();
        let event = make_replica_removed(TEST_NODE, TEST_CHUNK);

        let action1 = processor.process_event(&event).unwrap();
        let action2 = processor.process_event(&event).unwrap();

        assert_eq!(action1, action2);
    }

    // ════════════════════════════════════════════════════════════════════════
    // E. ERROR HANDLING TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_malformed_replica_added_empty_hash() {
        let processor = make_processor();
        let event = DAEvent {
            sequence: 1,
            timestamp: 1000,
            payload: DAEventPayload::ReplicaAdded(ReplicaAddedPayload {
                chunk_hash: String::new(), // Empty!
                node_id: TEST_NODE.to_string(),
                replica_index: 0,
                added_at: 1000,
            }),
        };

        let result = processor.process_event(&event);
        assert!(matches!(result, Err(ProcessError::MalformedEvent(_))));
    }

    #[test]
    fn test_malformed_replica_removed_empty_hash() {
        let processor = make_processor();
        let event = DAEvent {
            sequence: 1,
            timestamp: 1000,
            payload: DAEventPayload::ReplicaRemoved(ReplicaRemovedPayload {
                chunk_hash: String::new(), // Empty!
                node_id: TEST_NODE.to_string(),
            }),
        };

        let result = processor.process_event(&event);
        assert!(matches!(result, Err(ProcessError::MalformedEvent(_))));
    }

    // ════════════════════════════════════════════════════════════════════════
    // F. SAFETY TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_no_panic_on_unusual_event() {
        let processor = make_processor();

        // Very long chunk hash
        let long_hash = "a".repeat(1000);
        let event = make_replica_added(TEST_NODE, &long_hash, 0);
        let _ = processor.process_event(&event); // Should not panic

        // Very long node id
        let long_node = "n".repeat(1000);
        let event = make_replica_added(&long_node, TEST_CHUNK, 0);
        let _ = processor.process_event(&event); // Should not panic
    }

    #[test]
    fn test_no_panic_on_max_replica_index() {
        let processor = make_processor();
        let event = make_replica_added(TEST_NODE, TEST_CHUNK, u8::MAX);
        let _ = processor.process_event(&event); // Should not panic
    }

    // ════════════════════════════════════════════════════════════════════════
    // G. IS_RELEVANT TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_is_relevant_replica_added_this_node() {
        let processor = make_processor();
        let event = make_replica_added(TEST_NODE, TEST_CHUNK, 0);
        assert!(processor.is_relevant(&event));
    }

    #[test]
    fn test_is_relevant_replica_added_other_node() {
        let processor = make_processor();
        let event = make_replica_added(OTHER_NODE, TEST_CHUNK, 0);
        assert!(!processor.is_relevant(&event));
    }

    #[test]
    fn test_is_relevant_replica_removed_this_node() {
        let processor = make_processor();
        let event = make_replica_removed(TEST_NODE, TEST_CHUNK);
        assert!(processor.is_relevant(&event));
    }

    #[test]
    fn test_is_relevant_chunk_removed_have_chunk() {
        let processor = make_processor_with_chunk(TEST_CHUNK);
        let event = DAEvent {
            sequence: 1,
            timestamp: 1000,
            payload: DAEventPayload::ChunkRemoved(ChunkRemovedPayload {
                chunk_hash: TEST_CHUNK.to_string(),
            }),
        };
        assert!(processor.is_relevant(&event));
    }

    #[test]
    fn test_is_relevant_chunk_removed_no_chunk() {
        let processor = make_processor();
        let event = DAEvent {
            sequence: 1,
            timestamp: 1000,
            payload: DAEventPayload::ChunkRemoved(ChunkRemovedPayload {
                chunk_hash: TEST_CHUNK.to_string(),
            }),
        };
        assert!(!processor.is_relevant(&event));
    }

    #[test]
    fn test_is_relevant_node_registered() {
        let processor = make_processor();
        let event = DAEvent {
            sequence: 1,
            timestamp: 1000,
            payload: DAEventPayload::NodeRegistered(NodeRegisteredPayload {
                node_id: TEST_NODE.to_string(),
                zone: "zone".to_string(),
                addr: "addr".to_string(),
                capacity_gb: 100,
            }),
        };
        assert!(!processor.is_relevant(&event));
    }

    // ════════════════════════════════════════════════════════════════════════
    // H. NODE ACTION STRUCT TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_node_action_clone() {
        let action = NodeAction::StoreChunk {
            hash: "abc".to_string(),
            source_node: "node".to_string(),
        };
        let cloned = action.clone();
        assert_eq!(action, cloned);
    }

    #[test]
    fn test_node_action_debug() {
        let action = NodeAction::NoAction;
        let debug_str = format!("{:?}", action);
        assert!(!debug_str.is_empty());
    }

    #[test]
    fn test_process_error_display() {
        let err = ProcessError::MalformedEvent("test".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Malformed"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // I. FALLBACK DETECTION TESTS (14A.1A.45)
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_handle_fallback_activated_primary_to_secondary() {
        let processor = make_processor();

        let action = processor.handle_fallback_activated(
            DASourceType::Primary,
            DASourceType::Secondary,
            "Primary unavailable",
        );

        match action {
            NodeAction::SwitchToFallback { from_source, to_source, reason } => {
                assert_eq!(from_source, DASourceType::Primary);
                assert_eq!(to_source, DASourceType::Secondary);
                assert_eq!(reason, "Primary unavailable");
            }
            _ => panic!("Expected SwitchToFallback action"),
        }
    }

    #[test]
    fn test_handle_fallback_activated_primary_to_emergency() {
        let processor = make_processor();

        let action = processor.handle_fallback_activated(
            DASourceType::Primary,
            DASourceType::Emergency,
            "All sources failing",
        );

        match action {
            NodeAction::SwitchToFallback { from_source, to_source, reason } => {
                assert_eq!(from_source, DASourceType::Primary);
                assert_eq!(to_source, DASourceType::Emergency);
                assert_eq!(reason, "All sources failing");
            }
            _ => panic!("Expected SwitchToFallback action"),
        }
    }

    #[test]
    fn test_handle_fallback_activated_secondary_to_emergency() {
        let processor = make_processor();

        let action = processor.handle_fallback_activated(
            DASourceType::Secondary,
            DASourceType::Emergency,
            "Secondary also unavailable",
        );

        match action {
            NodeAction::SwitchToFallback { from_source, to_source, reason } => {
                assert_eq!(from_source, DASourceType::Secondary);
                assert_eq!(to_source, DASourceType::Emergency);
                assert_eq!(reason, "Secondary also unavailable");
            }
            _ => panic!("Expected SwitchToFallback action"),
        }
    }

    #[test]
    fn test_handle_fallback_deactivated_secondary_to_primary() {
        let processor = make_processor();

        let action = processor.handle_fallback_deactivated(DASourceType::Secondary);

        match action {
            NodeAction::SwitchToPrimary { from_source } => {
                assert_eq!(from_source, DASourceType::Secondary);
            }
            _ => panic!("Expected SwitchToPrimary action"),
        }
    }

    #[test]
    fn test_handle_fallback_deactivated_emergency_to_primary() {
        let processor = make_processor();

        let action = processor.handle_fallback_deactivated(DASourceType::Emergency);

        match action {
            NodeAction::SwitchToPrimary { from_source } => {
                assert_eq!(from_source, DASourceType::Emergency);
            }
            _ => panic!("Expected SwitchToPrimary action"),
        }
    }

    #[test]
    fn test_handle_reconciliation_completed_consistent() {
        // Create processor with state at sequence 100, height 50
        let state = Arc::new(RwLock::new(NodeDerivedState::new()));
        {
            let mut s = state.write();
            s.last_sequence = 100;
            s.last_height = 50;
        }
        let processor = NodeEventProcessor::new(TEST_NODE.to_string(), state);

        // Expected matches local
        let result = processor.handle_reconciliation_completed(100, 50);
        assert!(result.is_ok());

        match result {
            Ok(NodeAction::VerifyReconciliation {
                expected_sequence,
                expected_height,
                local_sequence,
                local_height,
            }) => {
                assert_eq!(expected_sequence, 100);
                assert_eq!(expected_height, 50);
                assert_eq!(local_sequence, 100);
                assert_eq!(local_height, 50);
            }
            _ => panic!("Expected VerifyReconciliation action"),
        }
    }

    #[test]
    fn test_handle_reconciliation_completed_local_ahead() {
        // Create processor with state ahead of expected
        let state = Arc::new(RwLock::new(NodeDerivedState::new()));
        {
            let mut s = state.write();
            s.last_sequence = 150; // Local ahead
            s.last_height = 60;
        }
        let processor = NodeEventProcessor::new(TEST_NODE.to_string(), state);

        // Expected behind local (not an error, just logged)
        let result = processor.handle_reconciliation_completed(100, 50);
        assert!(result.is_ok());

        match result {
            Ok(NodeAction::VerifyReconciliation {
                expected_sequence,
                expected_height,
                local_sequence,
                local_height,
            }) => {
                assert_eq!(expected_sequence, 100);
                assert_eq!(expected_height, 50);
                assert_eq!(local_sequence, 150);
                assert_eq!(local_height, 60);
            }
            _ => panic!("Expected VerifyReconciliation action"),
        }
    }

    #[test]
    fn test_handle_reconciliation_completed_gap_detected() {
        // Create processor with state behind expected (gap)
        let state = Arc::new(RwLock::new(NodeDerivedState::new()));
        {
            let mut s = state.write();
            s.last_sequence = 50; // Local behind!
            s.last_height = 30;
        }
        let processor = NodeEventProcessor::new(TEST_NODE.to_string(), state);

        // Expected ahead of local (gap detected)
        let result = processor.handle_reconciliation_completed(100, 50);
        assert!(result.is_err());

        match result {
            Err(ProcessError::InconsistentState(msg)) => {
                assert!(msg.contains("gap"));
                assert!(msg.contains("50")); // local
                assert!(msg.contains("100")); // expected
            }
            _ => panic!("Expected InconsistentState error"),
        }
    }

    #[test]
    fn test_is_fallback_activation_primary_to_secondary() {
        assert!(NodeEventProcessor::is_fallback_activation(
            DASourceType::Primary,
            DASourceType::Secondary
        ));
    }

    #[test]
    fn test_is_fallback_activation_primary_to_emergency() {
        assert!(NodeEventProcessor::is_fallback_activation(
            DASourceType::Primary,
            DASourceType::Emergency
        ));
    }

    #[test]
    fn test_is_fallback_activation_secondary_to_emergency_false() {
        // Secondary to Emergency is NOT activation (already in fallback)
        assert!(!NodeEventProcessor::is_fallback_activation(
            DASourceType::Secondary,
            DASourceType::Emergency
        ));
    }

    #[test]
    fn test_is_fallback_activation_secondary_to_primary_false() {
        // Going to Primary is never activation
        assert!(!NodeEventProcessor::is_fallback_activation(
            DASourceType::Secondary,
            DASourceType::Primary
        ));
    }

    #[test]
    fn test_is_fallback_deactivation_secondary_to_primary() {
        assert!(NodeEventProcessor::is_fallback_deactivation(
            DASourceType::Secondary,
            DASourceType::Primary
        ));
    }

    #[test]
    fn test_is_fallback_deactivation_emergency_to_primary() {
        assert!(NodeEventProcessor::is_fallback_deactivation(
            DASourceType::Emergency,
            DASourceType::Primary
        ));
    }

    #[test]
    fn test_is_fallback_deactivation_primary_to_secondary_false() {
        // Going from Primary is never deactivation
        assert!(!NodeEventProcessor::is_fallback_deactivation(
            DASourceType::Primary,
            DASourceType::Secondary
        ));
    }

    #[test]
    fn test_is_fallback_deactivation_secondary_to_emergency_false() {
        // Going to Emergency is not deactivation
        assert!(!NodeEventProcessor::is_fallback_deactivation(
            DASourceType::Secondary,
            DASourceType::Emergency
        ));
    }

    #[test]
    fn test_is_in_fallback_mode_primary() {
        assert!(!NodeEventProcessor::is_in_fallback_mode(DASourceType::Primary));
    }

    #[test]
    fn test_is_in_fallback_mode_secondary() {
        assert!(NodeEventProcessor::is_in_fallback_mode(DASourceType::Secondary));
    }

    #[test]
    fn test_is_in_fallback_mode_emergency() {
        assert!(NodeEventProcessor::is_in_fallback_mode(DASourceType::Emergency));
    }

    // ════════════════════════════════════════════════════════════════════════
    // J. NEW NODE ACTION VARIANTS TESTS (14A.1A.45)
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_node_action_switch_to_fallback_clone() {
        let action = NodeAction::SwitchToFallback {
            from_source: DASourceType::Primary,
            to_source: DASourceType::Secondary,
            reason: "test".to_string(),
        };
        let cloned = action.clone();
        assert_eq!(action, cloned);
    }

    #[test]
    fn test_node_action_switch_to_primary_clone() {
        let action = NodeAction::SwitchToPrimary {
            from_source: DASourceType::Secondary,
        };
        let cloned = action.clone();
        assert_eq!(action, cloned);
    }

    #[test]
    fn test_node_action_verify_reconciliation_clone() {
        let action = NodeAction::VerifyReconciliation {
            expected_sequence: 100,
            expected_height: 50,
            local_sequence: 100,
            local_height: 50,
        };
        let cloned = action.clone();
        assert_eq!(action, cloned);
    }

    #[test]
    fn test_node_action_switch_to_fallback_debug() {
        let action = NodeAction::SwitchToFallback {
            from_source: DASourceType::Primary,
            to_source: DASourceType::Secondary,
            reason: "test".to_string(),
        };
        let debug_str = format!("{:?}", action);
        assert!(debug_str.contains("SwitchToFallback"));
        assert!(debug_str.contains("Primary"));
        assert!(debug_str.contains("Secondary"));
    }

    #[test]
    fn test_node_action_switch_to_primary_debug() {
        let action = NodeAction::SwitchToPrimary {
            from_source: DASourceType::Emergency,
        };
        let debug_str = format!("{:?}", action);
        assert!(debug_str.contains("SwitchToPrimary"));
        assert!(debug_str.contains("Emergency"));
    }

    #[test]
    fn test_node_action_verify_reconciliation_debug() {
        let action = NodeAction::VerifyReconciliation {
            expected_sequence: 100,
            expected_height: 50,
            local_sequence: 100,
            local_height: 50,
        };
        let debug_str = format!("{:?}", action);
        assert!(debug_str.contains("VerifyReconciliation"));
        assert!(debug_str.contains("100"));
        assert!(debug_str.contains("50"));
    }
}