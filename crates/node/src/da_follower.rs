//! DA Follower Module
//!
//! This module provides the `DAFollower` component for DSDN storage nodes.
//! A node acts as a DA follower - it does NOT determine state independently,
//! but follows events from the Data Availability layer.
//!
//! ## Role
//!
//! `DAFollower` subscribes to DA events and maintains node-relevant derived state.
//! The node's state is:
//!
//! - **Derived**: Built entirely from DA events
//! - **Node-scoped**: Contains only data relevant to this specific node
//! - **Non-authoritative**: The DA layer is the source of truth
//! - **Rebuildable**: Can be reconstructed from DA at any time
//!
//! ## Difference from Coordinator
//!
//! - Coordinator: Maintains full network state, makes placement decisions
//! - Node: Maintains subset of state relevant to its assigned chunks
//!
//! ## Current Status
//!
//! This module defines structure, state, and constructor only.
//! Event processing will be implemented in subsequent stages.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;

use dsdn_common::da::{DALayer, BlobStream};
use dsdn_coordinator::DADerivedState;

// ════════════════════════════════════════════════════════════════════════════
// CHUNK ASSIGNMENT (placeholder)
// ════════════════════════════════════════════════════════════════════════════

/// Assignment of a chunk to this node.
///
/// This struct represents the assignment metadata for chunks that
/// this node is responsible for storing.
///
/// Fields will be defined in a subsequent stage.
#[derive(Debug, Clone)]
pub struct ChunkAssignment {
    /// Hash of the assigned chunk
    pub chunk_hash: String,
    /// Replica index for this node's copy
    pub replica_index: u8,
    /// Timestamp when assignment was made
    pub assigned_at: u64,
}

// ════════════════════════════════════════════════════════════════════════════
// NODE DERIVED STATE
// ════════════════════════════════════════════════════════════════════════════

/// State derived from DA events, scoped to this node.
///
/// `NodeDerivedState` contains only the state relevant to this specific node:
///
/// - Chunks assigned to this node
/// - A subset of coordinator state for local decisions
/// - Sequence tracking for consistency
///
/// ## Non-Authoritative
///
/// This state is NOT authoritative. The DA layer is the single source of truth.
/// This state can be fully reconstructed by replaying DA events.
#[derive(Debug)]
pub struct NodeDerivedState {
    /// Chunks assigned to this node: chunk_hash -> assignment info
    pub my_chunks: HashMap<String, ChunkAssignment>,
    /// Subset of coordinator state for local decisions (non-authoritative)
    pub coordinator_state: DADerivedState,
    /// Last sequence number processed by this node
    pub last_sequence: u64,
}

impl NodeDerivedState {
    /// Create a new empty node derived state.
    ///
    /// # Returns
    ///
    /// A new `NodeDerivedState` with:
    /// - Empty chunk assignments
    /// - Empty coordinator state
    /// - Sequence at 0
    pub fn new() -> Self {
        Self {
            my_chunks: HashMap::new(),
            coordinator_state: DADerivedState::new(),
            last_sequence: 0,
        }
    }
}

impl Default for NodeDerivedState {
    fn default() -> Self {
        Self::new()
    }
}

// ════════════════════════════════════════════════════════════════════════════
// DA FOLLOWER
// ════════════════════════════════════════════════════════════════════════════

/// DA Follower for storage nodes.
///
/// `DAFollower` enables a node to follow events from the Data Availability layer
/// and maintain derived state relevant to its operation.
///
/// ## Design Principles
///
/// - Node does NOT determine state independently
/// - Node FOLLOWS events from DA
/// - Node maintains derived state that is:
///   - Relevant to this node only
///   - Fully derived from DA events
///   - Non-authoritative
///   - Rebuildable from DA
///
/// ## Lifecycle
///
/// 1. Create with `new(da, node_id)`
/// 2. Start subscription (future stage)
/// 3. Process events and update state (future stage)
/// 4. Query local state for operations
pub struct DAFollower {
    /// Reference to the DA layer
    da: Arc<dyn DALayer>,
    /// This node's unique identifier
    node_id: String,
    /// Node-scoped derived state
    state: Arc<RwLock<NodeDerivedState>>,
    /// Active blob subscription (None until started)
    subscription: Option<BlobStream>,
}

impl DAFollower {
    /// Create a new DAFollower instance.
    ///
    /// # Arguments
    ///
    /// * `da` - Reference to the DA layer implementation
    /// * `node_id` - Unique identifier for this node
    ///
    /// # Returns
    ///
    /// A new `DAFollower` instance with:
    /// - Empty derived state
    /// - No active subscription
    /// - Sequence at 0
    ///
    /// # Guarantees
    ///
    /// - Does NOT subscribe to DA (subscription is None)
    /// - Does NOT spawn any tasks
    /// - Does NOT perform IO
    /// - Does NOT panic
    /// - State is empty, consistent, and deterministic
    pub fn new(da: Arc<dyn DALayer>, node_id: String) -> Self {
        Self {
            da,
            node_id,
            state: Arc::new(RwLock::new(NodeDerivedState::new())),
            subscription: None,
        }
    }

    /// Get the node ID.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Get a reference to the DA layer.
    pub fn da(&self) -> &Arc<dyn DALayer> {
        &self.da
    }

    /// Get a reference to the state.
    pub fn state(&self) -> &Arc<RwLock<NodeDerivedState>> {
        &self.state
    }

    /// Check if subscription is active.
    pub fn is_subscribed(&self) -> bool {
        self.subscription.is_some()
    }
}

// ════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use dsdn_common::MockDA;

    #[test]
    fn test_node_derived_state_new() {
        let state = NodeDerivedState::new();

        assert!(state.my_chunks.is_empty());
        assert!(state.coordinator_state.node_registry.is_empty());
        assert_eq!(state.last_sequence, 0);
    }

    #[test]
    fn test_da_follower_new() {
        let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
        let follower = DAFollower::new(da, "node-1".to_string());

        assert_eq!(follower.node_id(), "node-1");
        assert!(!follower.is_subscribed());
    }

    #[test]
    fn test_da_follower_state_empty() {
        let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
        let follower = DAFollower::new(da, "node-2".to_string());

        let state = follower.state().read();
        assert!(state.my_chunks.is_empty());
        assert_eq!(state.last_sequence, 0);
    }

    #[test]
    fn test_da_follower_subscription_none() {
        let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
        let follower = DAFollower::new(da, "node-3".to_string());

        assert!(!follower.is_subscribed());
    }

    #[test]
    fn test_chunk_assignment_struct() {
        let assignment = ChunkAssignment {
            chunk_hash: "abc123".to_string(),
            replica_index: 0,
            assigned_at: 1000,
        };

        assert_eq!(assignment.chunk_hash, "abc123");
        assert_eq!(assignment.replica_index, 0);
        assert_eq!(assignment.assigned_at, 1000);
    }
}