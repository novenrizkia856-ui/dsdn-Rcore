//! DA Consumer Module
//!
//! This module provides the `DAConsumer` component responsible for consuming
//! events from the Data Availability layer and building derived state.
//!
//! ## Role
//!
//! `DAConsumer` acts as the bridge between the DA layer and the Coordinator's
//! state machine. It:
//!
//! - Consumes blob events from `DALayer` via subscription
//! - Interprets events to build `DADerivedState`
//! - Maintains sequence tracking for consistency
//!
//! ## Relationship
//!
//! - **DALayer**: Provides the event stream via `subscribe_blobs`
//! - **Coordinator**: Uses derived state for placement and scheduling decisions
//!
//! ## Current Status
//!
//! This module defines the structure and data models. Event processing
//! logic will be implemented in subsequent stages.

use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use parking_lot::RwLock;

use dsdn_common::da::{DALayer, BlobStream};

use crate::NodeInfo;

// ════════════════════════════════════════════════════════════════════════════
// FORWARD-COMPATIBLE TYPE DEFINITIONS
// ════════════════════════════════════════════════════════════════════════════

/// Metadata for a stored chunk.
///
/// Represents information about a data chunk in the storage network.
#[derive(Debug, Clone)]
pub struct ChunkMeta {
    /// Content hash of the chunk
    pub hash: String,
    /// Size in bytes
    pub size: u64,
    /// Owner or creator identifier
    pub owner: String,
}

/// Information about a replica of a chunk.
///
/// Tracks where replicas are stored and their status.
#[derive(Debug, Clone)]
pub struct ReplicaInfo {
    /// Node ID where replica is stored
    pub node_id: String,
    /// Whether replica is confirmed healthy
    pub confirmed: bool,
    /// Timestamp when replica was created
    pub created_at: u64,
}

// ════════════════════════════════════════════════════════════════════════════
// DA DERIVED STATE
// ════════════════════════════════════════════════════════════════════════════

/// State derived from DA layer events.
///
/// `DADerivedState` contains all state built by interpreting events
/// from the Data Availability layer. This state is used by the Coordinator
/// for placement decisions and network coordination.
///
/// All fields are initialized empty and populated as events are processed.
#[derive(Debug)]
pub struct DADerivedState {
    /// Registry of nodes: node_id -> NodeInfo
    pub node_registry: HashMap<String, NodeInfo>,
    /// Chunk metadata: chunk_hash -> ChunkMeta
    pub chunk_map: HashMap<String, ChunkMeta>,
    /// Replica locations: chunk_hash -> list of ReplicaInfo
    pub replica_map: HashMap<String, Vec<ReplicaInfo>>,
    /// Zone membership: zone_id -> list of node_ids
    pub zone_map: HashMap<String, Vec<String>>,
    /// Monotonic sequence number for ordering
    pub sequence: u64,
    /// Unix timestamp (ms) of last state update
    pub last_updated: u64,
}

impl DADerivedState {
    /// Create a new empty derived state.
    ///
    /// All collections are empty, sequence starts at 0.
    pub fn new() -> Self {
        Self {
            node_registry: HashMap::new(),
            chunk_map: HashMap::new(),
            replica_map: HashMap::new(),
            zone_map: HashMap::new(),
            sequence: 0,
            last_updated: 0,
        }
    }
}

impl Default for DADerivedState {
    fn default() -> Self {
        Self::new()
    }
}

// ════════════════════════════════════════════════════════════════════════════
// DA CONSUMER
// ════════════════════════════════════════════════════════════════════════════

/// Consumer for DA layer events.
///
/// `DAConsumer` subscribes to the DA layer and processes events to build
/// derived state. It maintains:
///
/// - Connection to the DA layer
/// - Derived state from processed events
/// - Tracking of last processed height
/// - Optional subscription stream
///
/// # Thread Safety
///
/// - `da`: Shared reference to DA layer (thread-safe via trait bounds)
/// - `state`: Protected by `RwLock` for concurrent access
/// - `last_processed`: Atomic for lock-free reads
/// - `subscription`: Only accessed by consumer task
pub struct DAConsumer {
    /// Reference to the DA layer implementation
    da: Arc<dyn DALayer>,
    /// Derived state built from DA events
    state: Arc<RwLock<DADerivedState>>,
    /// Height of the last processed blob
    last_processed: AtomicU64,
    /// Active subscription stream (if any)
    subscription: Option<BlobStream>,
}

impl DAConsumer {
    /// Create a new DAConsumer with the given DA layer.
    ///
    /// Initializes the consumer with:
    /// - Empty derived state
    /// - `last_processed` set to 0
    /// - No active subscription
    ///
    /// # Arguments
    ///
    /// * `da` - Arc reference to a DALayer implementation
    ///
    /// # Returns
    ///
    /// A new `DAConsumer` instance ready for subscription.
    ///
    /// # Note
    ///
    /// This constructor does NOT start the subscription. Call the
    /// appropriate method to begin consuming events.
    pub fn new(da: Arc<dyn DALayer>) -> Self {
        Self {
            da,
            state: Arc::new(RwLock::new(DADerivedState::new())),
            last_processed: AtomicU64::new(0),
            subscription: None,
        }
    }

    /// Get a reference to the derived state.
    ///
    /// Returns an Arc to the RwLock-protected state for read access.
    pub fn state(&self) -> Arc<RwLock<DADerivedState>> {
        Arc::clone(&self.state)
    }

    /// Get the last processed height.
    ///
    /// Returns the height of the most recently processed blob.
    pub fn last_processed_height(&self) -> u64 {
        self.last_processed.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Check if subscription is active.
    ///
    /// Returns true if there is an active subscription stream.
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
    fn test_da_derived_state_new() {
        let state = DADerivedState::new();

        assert!(state.node_registry.is_empty());
        assert!(state.chunk_map.is_empty());
        assert!(state.replica_map.is_empty());
        assert!(state.zone_map.is_empty());
        assert_eq!(state.sequence, 0);
        assert_eq!(state.last_updated, 0);
    }

    #[test]
    fn test_da_consumer_new() {
        let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
        let consumer = DAConsumer::new(da);

        // Verify initial state
        assert_eq!(consumer.last_processed_height(), 0);
        assert!(!consumer.is_subscribed());

        // Verify derived state is empty
        let state = consumer.state();
        let state_guard = state.read();
        assert!(state_guard.node_registry.is_empty());
        assert!(state_guard.chunk_map.is_empty());
        assert!(state_guard.replica_map.is_empty());
        assert!(state_guard.zone_map.is_empty());
        assert_eq!(state_guard.sequence, 0);
    }

    #[test]
    fn test_da_consumer_state_access() {
        let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
        let consumer = DAConsumer::new(da);

        // Get state reference
        let state1 = consumer.state();
        let state2 = consumer.state();

        // Both should point to same state
        assert!(Arc::ptr_eq(&state1, &state2));
    }

    #[test]
    fn test_chunk_meta_creation() {
        let meta = ChunkMeta {
            hash: "abc123".to_string(),
            size: 1024,
            owner: "user1".to_string(),
        };

        assert_eq!(meta.hash, "abc123");
        assert_eq!(meta.size, 1024);
        assert_eq!(meta.owner, "user1");
    }

    #[test]
    fn test_replica_info_creation() {
        let replica = ReplicaInfo {
            node_id: "node1".to_string(),
            confirmed: true,
            created_at: 1234567890,
        };

        assert_eq!(replica.node_id, "node1");
        assert!(replica.confirmed);
        assert_eq!(replica.created_at, 1234567890);
    }
}