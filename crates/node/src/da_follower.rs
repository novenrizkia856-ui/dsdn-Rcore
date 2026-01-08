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
//! ## Event Filtering
//!
//! Node ONLY processes events relevant to this node:
//! - `ReplicaAdded` where `node_id` matches this node
//! - `ReplicaRemoved` where `node_id` matches this node
//!
//! All other events are ignored (not an error).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use parking_lot::RwLock;
use tokio::sync::Notify;
use tracing::{debug, warn, error};

use dsdn_common::da::{DALayer, DAError, Blob};
use dsdn_coordinator::{
    DADerivedState, DAEvent, DAEventPayload,
    NodeRegisteredPayload, NodeUnregisteredPayload,
    ChunkDeclaredPayload, ChunkRemovedPayload,
    ReplicaAddedPayload, ReplicaRemovedPayload,
    ZoneAssignedPayload, ZoneUnassignedPayload,
};

// ════════════════════════════════════════════════════════════════════════════
// CHUNK ASSIGNMENT
// ════════════════════════════════════════════════════════════════════════════

/// Assignment of a chunk to this node.
///
/// This struct represents the assignment metadata for chunks that
/// this node is responsible for storing.
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
    /// Last height processed from DA
    pub last_height: u64,
}

impl NodeDerivedState {
    /// Create a new empty node derived state.
    pub fn new() -> Self {
        Self {
            my_chunks: HashMap::new(),
            coordinator_state: DADerivedState::new(),
            last_sequence: 0,
            last_height: 0,
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
/// 2. Call `start()` to subscribe and spawn background task
/// 3. Events are processed automatically
/// 4. Call `stop()` for graceful shutdown
/// 5. Use `sync_to_latest()` for initial sync or recovery
pub struct DAFollower {
    /// Reference to the DA layer
    da: Arc<dyn DALayer>,
    /// This node's unique identifier
    node_id: String,
    /// Node-scoped derived state
    state: Arc<RwLock<NodeDerivedState>>,
    /// Flag indicating if background task is running
    running: Arc<AtomicBool>,
    /// Notify for shutdown coordination
    shutdown_notify: Arc<Notify>,
    /// Last processed height (for reconnection)
    last_height: Arc<AtomicU64>,
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
    /// - Does NOT subscribe to DA
    /// - Does NOT spawn any tasks
    /// - Does NOT perform IO
    /// - Does NOT panic
    pub fn new(da: Arc<dyn DALayer>, node_id: String) -> Self {
        Self {
            da,
            node_id,
            state: Arc::new(RwLock::new(NodeDerivedState::new())),
            running: Arc::new(AtomicBool::new(false)),
            shutdown_notify: Arc::new(Notify::new()),
            last_height: Arc::new(AtomicU64::new(0)),
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

    /// Check if background task is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Start the DA follower.
    ///
    /// Subscribes to DA blob stream and spawns a background task
    /// to process events.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Successfully started
    /// * `Err(DAError)` - Already running
    ///
    /// # Guarantees
    ///
    /// - Will not spawn duplicate tasks if called multiple times
    /// - Events are filtered to only process node-relevant events
    /// - Background task handles reconnection on stream errors
    /// - Does NOT panic
    pub fn start(&mut self) -> Result<(), DAError> {
        // Check if already running
        if self.running.swap(true, Ordering::SeqCst) {
            return Err(DAError::Other("DAFollower already running".to_string()));
        }

        debug!("DAFollower starting for node {}", self.node_id);

        // Spawn background task
        let da = Arc::clone(&self.da);
        let node_id = self.node_id.clone();
        let state = Arc::clone(&self.state);
        let running = Arc::clone(&self.running);
        let shutdown = Arc::clone(&self.shutdown_notify);
        let last_height = Arc::clone(&self.last_height);

        tokio::spawn(async move {
            Self::background_task(da, node_id, state, running, shutdown, last_height).await;
        });

        Ok(())
    }

    /// Background task for processing DA events.
    ///
    /// Handles subscription, event processing, and reconnection.
    async fn background_task(
        da: Arc<dyn DALayer>,
        node_id: String,
        state: Arc<RwLock<NodeDerivedState>>,
        running: Arc<AtomicBool>,
        shutdown: Arc<Notify>,
        last_height: Arc<AtomicU64>,
    ) {
        debug!("Background task started for node {}", node_id);

        while running.load(Ordering::SeqCst) {
            // Get from_height for subscription
            let from_height = {
                let h = last_height.load(Ordering::SeqCst);
                if h == 0 { None } else { Some(h + 1) }
            };

            // Try to subscribe
            let subscribe_result = da.subscribe_blobs(from_height).await;

            match subscribe_result {
                Ok(mut stream) => {
                    debug!("Subscribed to DA stream for node {} from height {:?}", node_id, from_height);

                    // Process blobs from stream
                    loop {
                        tokio::select! {
                            _ = shutdown.notified() => {
                                debug!("Shutdown signal received for node {}", node_id);
                                running.store(false, Ordering::SeqCst);
                                return;
                            }
                            blob_result = Self::next_blob(&mut stream) => {
                                match blob_result {
                                    Some(Ok(blob)) => {
                                        // Decode events from blob
                                        match Self::decode_events(&blob.data) {
                                            Ok(events) => {
                                                // Process events
                                                for event in events {
                                                    if Self::is_relevant_event(&event, &node_id) {
                                                        Self::apply_event(&state, &event, &node_id);
                                                    }
                                                    Self::update_sequence(&state, event.sequence);
                                                }
                                                // Update last height
                                                last_height.store(blob.ref_.height, Ordering::SeqCst);
                                                state.write().last_height = blob.ref_.height;
                                            }
                                            Err(e) => {
                                                warn!("Failed to decode blob for node {}: {:?}", node_id, e);
                                            }
                                        }
                                    }
                                    Some(Err(e)) => {
                                        warn!("Stream error for node {}: {:?}", node_id, e);
                                        // Break inner loop to reconnect
                                        break;
                                    }
                                    None => {
                                        debug!("Stream ended for node {}", node_id);
                                        // Break inner loop to reconnect
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to subscribe for node {}: {:?}", node_id, e);
                    // Wait before retry
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
            }

            // Check if we should stop before reconnecting
            if !running.load(Ordering::SeqCst) {
                break;
            }

            debug!("Reconnecting DA stream for node {}", node_id);
        }

        debug!("Background task stopped for node {}", node_id);
    }

    /// Get next blob from stream.
    async fn next_blob(stream: &mut dsdn_common::da::BlobStream) -> Option<Result<Blob, DAError>> {
        use futures::StreamExt;
        stream.next().await
    }

    /// Decode events from blob data.
    ///
    /// Format:
    /// - 4 bytes: event count (u32 big-endian)
    /// - For each event:
    ///   - 8 bytes: sequence (u64 big-endian)
    ///   - 8 bytes: timestamp (u64 big-endian)
    ///   - 1 byte: event type discriminant
    ///   - Variable: payload
    pub fn decode_events(data: &[u8]) -> Result<Vec<DAEvent>, DAError> {
        if data.len() < 4 {
            return Ok(Vec::new());
        }

        let count = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let mut events = Vec::with_capacity(count);
        let mut offset = 4;

        for _ in 0..count {
            if offset + 17 > data.len() {
                return Err(DAError::Other("Truncated event data".to_string()));
            }

            // Read sequence
            let sequence = u64::from_be_bytes([
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
                data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
            ]);
            offset += 8;

            // Read timestamp
            let timestamp = u64::from_be_bytes([
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
                data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
            ]);
            offset += 8;

            // Read type discriminant
            let type_byte = data[offset];
            offset += 1;

            // Decode payload based on type
            let payload = match type_byte {
                0x01 => {
                    // NodeRegistered
                    let (node_id, new_offset) = Self::decode_string(data, offset)?;
                    offset = new_offset;
                    let (zone, new_offset) = Self::decode_string(data, offset)?;
                    offset = new_offset;
                    let (addr, new_offset) = Self::decode_string(data, offset)?;
                    offset = new_offset;
                    if offset + 8 > data.len() {
                        return Err(DAError::Other("Truncated NodeRegistered".to_string()));
                    }
                    let capacity_gb = u64::from_be_bytes([
                        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
                        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
                    ]);
                    offset += 8;
                    DAEventPayload::NodeRegistered(NodeRegisteredPayload {
                        node_id,
                        zone,
                        addr,
                        capacity_gb,
                    })
                }
                0x02 => {
                    // NodeUnregistered
                    let (node_id, new_offset) = Self::decode_string(data, offset)?;
                    offset = new_offset;
                    DAEventPayload::NodeUnregistered(NodeUnregisteredPayload { node_id })
                }
                0x03 => {
                    // ChunkDeclared
                    let (chunk_hash, new_offset) = Self::decode_string(data, offset)?;
                    offset = new_offset;
                    if offset + 8 > data.len() {
                        return Err(DAError::Other("Truncated ChunkDeclared size".to_string()));
                    }
                    let size_bytes = u64::from_be_bytes([
                        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
                        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
                    ]);
                    offset += 8;
                    if offset + 1 > data.len() {
                        return Err(DAError::Other("Truncated ChunkDeclared rf".to_string()));
                    }
                    let replication_factor = data[offset];
                    offset += 1;
                    let (uploader_id, new_offset) = Self::decode_string(data, offset)?;
                    offset = new_offset;
                    if offset + 32 > data.len() {
                        return Err(DAError::Other("Truncated ChunkDeclared commitment".to_string()));
                    }
                    let mut da_commitment = [0u8; 32];
                    da_commitment.copy_from_slice(&data[offset..offset + 32]);
                    offset += 32;
                    DAEventPayload::ChunkDeclared(ChunkDeclaredPayload {
                        chunk_hash,
                        size_bytes,
                        replication_factor,
                        uploader_id,
                        da_commitment,
                    })
                }
                0x04 => {
                    // ChunkRemoved
                    let (chunk_hash, new_offset) = Self::decode_string(data, offset)?;
                    offset = new_offset;
                    DAEventPayload::ChunkRemoved(ChunkRemovedPayload { chunk_hash })
                }
                0x05 => {
                    // ReplicaAdded
                    let (chunk_hash, new_offset) = Self::decode_string(data, offset)?;
                    offset = new_offset;
                    let (node_id, new_offset) = Self::decode_string(data, offset)?;
                    offset = new_offset;
                    if offset + 1 > data.len() {
                        return Err(DAError::Other("Truncated ReplicaAdded index".to_string()));
                    }
                    let replica_index = data[offset];
                    offset += 1;
                    if offset + 8 > data.len() {
                        return Err(DAError::Other("Truncated ReplicaAdded added_at".to_string()));
                    }
                    let added_at = u64::from_be_bytes([
                        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
                        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
                    ]);
                    offset += 8;
                    DAEventPayload::ReplicaAdded(ReplicaAddedPayload {
                        chunk_hash,
                        node_id,
                        replica_index,
                        added_at,
                    })
                }
                0x06 => {
                    // ReplicaRemoved
                    let (chunk_hash, new_offset) = Self::decode_string(data, offset)?;
                    offset = new_offset;
                    let (node_id, new_offset) = Self::decode_string(data, offset)?;
                    offset = new_offset;
                    DAEventPayload::ReplicaRemoved(ReplicaRemovedPayload {
                        chunk_hash,
                        node_id,
                    })
                }
                0x07 => {
                    // ZoneAssigned
                    let (zone_id, new_offset) = Self::decode_string(data, offset)?;
                    offset = new_offset;
                    let (node_id, new_offset) = Self::decode_string(data, offset)?;
                    offset = new_offset;
                    DAEventPayload::ZoneAssigned(ZoneAssignedPayload { zone_id, node_id })
                }
                0x08 => {
                    // ZoneUnassigned
                    let (zone_id, new_offset) = Self::decode_string(data, offset)?;
                    offset = new_offset;
                    let (node_id, new_offset) = Self::decode_string(data, offset)?;
                    offset = new_offset;
                    DAEventPayload::ZoneUnassigned(ZoneUnassignedPayload { zone_id, node_id })
                }
                _ => {
                    return Err(DAError::Other(format!("Unknown event type: {}", type_byte)));
                }
            };

            events.push(DAEvent {
                sequence,
                timestamp,
                payload,
            });
        }

        Ok(events)
    }

    /// Decode a length-prefixed string.
    fn decode_string(data: &[u8], offset: usize) -> Result<(String, usize), DAError> {
        if offset + 4 > data.len() {
            return Err(DAError::Other("Truncated string length".to_string()));
        }
        let len = u32::from_be_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        ]) as usize;
        let new_offset = offset + 4;
        if new_offset + len > data.len() {
            return Err(DAError::Other("Truncated string data".to_string()));
        }
        let s = String::from_utf8(data[new_offset..new_offset + len].to_vec())
            .map_err(|e| DAError::Other(format!("Invalid UTF-8: {}", e)))?;
        Ok((s, new_offset + len))
    }

    /// Check if an event is relevant to this node.
    ///
    /// Node ONLY processes:
    /// - `ReplicaAdded` where `node_id` matches
    /// - `ReplicaRemoved` where `node_id` matches
    fn is_relevant_event(event: &DAEvent, node_id: &str) -> bool {
        match &event.payload {
            DAEventPayload::ReplicaAdded(p) => p.node_id == node_id,
            DAEventPayload::ReplicaRemoved(p) => p.node_id == node_id,
            _ => false,
        }
    }

    /// Apply a relevant event to node state.
    fn apply_event(
        state: &Arc<RwLock<NodeDerivedState>>,
        event: &DAEvent,
        node_id: &str,
    ) {
        let mut state_guard = state.write();

        match &event.payload {
            DAEventPayload::ReplicaAdded(p) => {
                if p.node_id == node_id {
                    // Check for idempotency
                    if state_guard.my_chunks.contains_key(&p.chunk_hash) {
                        debug!("Replica already assigned: {}", p.chunk_hash);
                        return;
                    }

                    // Add chunk assignment
                    let assignment = ChunkAssignment {
                        chunk_hash: p.chunk_hash.clone(),
                        replica_index: p.replica_index,
                        assigned_at: p.added_at,
                    };
                    state_guard.my_chunks.insert(p.chunk_hash.clone(), assignment);
                    debug!(
                        "Node {} assigned chunk {} (index {})",
                        node_id, p.chunk_hash, p.replica_index
                    );
                }
            }
            DAEventPayload::ReplicaRemoved(p) => {
                if p.node_id == node_id {
                    if state_guard.my_chunks.remove(&p.chunk_hash).is_some() {
                        debug!("Node {} removed chunk {}", node_id, p.chunk_hash);
                    }
                }
            }
            _ => {}
        }
    }

    /// Update sequence number in state.
    fn update_sequence(state: &Arc<RwLock<NodeDerivedState>>, sequence: u64) {
        let mut state_guard = state.write();
        if sequence > state_guard.last_sequence {
            state_guard.last_sequence = sequence;
        }
    }

    /// Stop the DA follower.
    ///
    /// Gracefully stops the background task.
    ///
    /// # Guarantees
    ///
    /// - Idempotent: safe to call multiple times
    /// - Graceful: signals background task to stop
    /// - Does NOT panic
    /// - Does NOT drop state
    pub fn stop(&mut self) {
        if self.running.load(Ordering::SeqCst) {
            debug!("Stopping DAFollower for node {}", self.node_id);
            self.running.store(false, Ordering::SeqCst);
            self.shutdown_notify.notify_one();
        }
    }

    /// Sync state to latest DA height.
    ///
    /// Fetches all events from `last_height` to latest and applies them in order.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Successfully synced
    /// * `Err(DAError)` - Sync failed
    ///
    /// # Guarantees
    ///
    /// - Events processed in sequence order
    /// - Only relevant events update my_chunks
    /// - Sequence updated for ALL events seen
    /// - Idempotent: safe to call multiple times
    pub async fn sync_to_latest(&mut self) -> Result<(), DAError> {
        debug!("Syncing to latest for node {}", self.node_id);

        let from_height = {
            let state = self.state.read();
            if state.last_height == 0 { None } else { Some(state.last_height + 1) }
        };

        // Subscribe to get events
        let mut stream = self.da.subscribe_blobs(from_height).await?;

        // Process available blobs with timeout
        use futures::StreamExt;
        use tokio::time::{timeout, Duration};

        loop {
            match timeout(Duration::from_millis(500), stream.next()).await {
                Ok(Some(Ok(blob))) => {
                    // Decode and process events
                    match Self::decode_events(&blob.data) {
                        Ok(events) => {
                            // Sort by sequence
                            let mut sorted_events = events;
                            sorted_events.sort_by_key(|e| e.sequence);

                            for event in &sorted_events {
                                if Self::is_relevant_event(event, &self.node_id) {
                                    Self::apply_event(&self.state, event, &self.node_id);
                                }
                                Self::update_sequence(&self.state, event.sequence);
                            }

                            // Update last height
                            self.last_height.store(blob.ref_.height, Ordering::SeqCst);
                            self.state.write().last_height = blob.ref_.height;
                        }
                        Err(e) => {
                            warn!("Failed to decode blob during sync: {:?}", e);
                        }
                    }
                }
                Ok(Some(Err(e))) => {
                    warn!("Stream error during sync: {:?}", e);
                    return Err(e);
                }
                Ok(None) => {
                    // Stream ended
                    break;
                }
                Err(_) => {
                    // Timeout - no more blobs available
                    break;
                }
            }
        }

        debug!(
            "Sync complete for node {}: sequence {}, height {}",
            self.node_id,
            self.state.read().last_sequence,
            self.state.read().last_height
        );

        Ok(())
    }

    /// Get the last processed sequence number.
    pub fn last_sequence(&self) -> u64 {
        self.state.read().last_sequence
    }

    /// Get the number of chunks assigned to this node.
    pub fn chunk_count(&self) -> usize {
        self.state.read().my_chunks.len()
    }

    /// Check if a chunk is assigned to this node.
    pub fn has_chunk(&self, chunk_hash: &str) -> bool {
        self.state.read().my_chunks.contains_key(chunk_hash)
    }

    /// Get chunk assignment info if assigned to this node.
    pub fn get_chunk(&self, chunk_hash: &str) -> Option<ChunkAssignment> {
        self.state.read().my_chunks.get(chunk_hash).cloned()
    }

    /// Get all chunk hashes assigned to this node.
    pub fn chunk_hashes(&self) -> Vec<String> {
        self.state.read().my_chunks.keys().cloned().collect()
    }
}

// ════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use dsdn_common::MockDA;

    const TEST_CHUNK: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    // ════════════════════════════════════════════════════════════════════════
    // A. BASIC STATE TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_node_derived_state_new() {
        let state = NodeDerivedState::new();

        assert!(state.my_chunks.is_empty());
        assert!(state.coordinator_state.node_registry.is_empty());
        assert_eq!(state.last_sequence, 0);
        assert_eq!(state.last_height, 0);
    }

    #[test]
    fn test_da_follower_new() {
        let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
        let follower = DAFollower::new(da, "node-1".to_string());

        assert_eq!(follower.node_id(), "node-1");
        assert!(!follower.is_running());
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

    // ════════════════════════════════════════════════════════════════════════
    // B. EVENT FILTERING TESTS
    // ════════════════════════════════════════════════════════════════════════

    fn make_replica_added(seq: u64, chunk_hash: &str, node_id: &str, index: u8) -> DAEvent {
        DAEvent {
            sequence: seq,
            timestamp: seq * 1000,
            payload: DAEventPayload::ReplicaAdded(ReplicaAddedPayload {
                chunk_hash: chunk_hash.to_string(),
                node_id: node_id.to_string(),
                replica_index: index,
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

    #[test]
    fn test_is_relevant_event_replica_added_match() {
        let event = make_replica_added(1, TEST_CHUNK, "node-1", 0);
        assert!(DAFollower::is_relevant_event(&event, "node-1"));
    }

    #[test]
    fn test_is_relevant_event_replica_added_no_match() {
        let event = make_replica_added(1, TEST_CHUNK, "node-2", 0);
        assert!(!DAFollower::is_relevant_event(&event, "node-1"));
    }

    #[test]
    fn test_is_relevant_event_replica_removed_match() {
        let event = make_replica_removed(1, TEST_CHUNK, "node-1");
        assert!(DAFollower::is_relevant_event(&event, "node-1"));
    }

    #[test]
    fn test_is_relevant_event_replica_removed_no_match() {
        let event = make_replica_removed(1, TEST_CHUNK, "node-2");
        assert!(!DAFollower::is_relevant_event(&event, "node-1"));
    }

    #[test]
    fn test_is_relevant_event_other_types() {
        let event = DAEvent {
            sequence: 1,
            timestamp: 1000,
            payload: DAEventPayload::NodeRegistered(NodeRegisteredPayload {
                node_id: "node-1".to_string(),
                zone: "zone-a".to_string(),
                addr: "node-1:7001".to_string(),
                capacity_gb: 100,
            }),
        };

        // NodeRegistered is NOT relevant to node follower
        assert!(!DAFollower::is_relevant_event(&event, "node-1"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // C. APPLY EVENT TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_apply_event_replica_added() {
        let state = Arc::new(RwLock::new(NodeDerivedState::new()));
        let event = make_replica_added(1, TEST_CHUNK, "node-1", 0);

        DAFollower::apply_event(&state, &event, "node-1");

        let state_guard = state.read();
        assert!(state_guard.my_chunks.contains_key(TEST_CHUNK));
        assert_eq!(state_guard.my_chunks.get(TEST_CHUNK).unwrap().replica_index, 0);
    }

    #[test]
    fn test_apply_event_replica_removed() {
        let state = Arc::new(RwLock::new(NodeDerivedState::new()));

        // First add
        let add_event = make_replica_added(1, TEST_CHUNK, "node-1", 0);
        DAFollower::apply_event(&state, &add_event, "node-1");
        assert!(state.read().my_chunks.contains_key(TEST_CHUNK));

        // Then remove
        let remove_event = make_replica_removed(2, TEST_CHUNK, "node-1");
        DAFollower::apply_event(&state, &remove_event, "node-1");
        assert!(!state.read().my_chunks.contains_key(TEST_CHUNK));
    }

    #[test]
    fn test_apply_event_idempotent_add() {
        let state = Arc::new(RwLock::new(NodeDerivedState::new()));
        let event = make_replica_added(1, TEST_CHUNK, "node-1", 0);

        // Apply twice
        DAFollower::apply_event(&state, &event, "node-1");
        DAFollower::apply_event(&state, &event, "node-1");

        // Should still have only one entry
        assert_eq!(state.read().my_chunks.len(), 1);
    }

    #[test]
    fn test_apply_event_idempotent_remove() {
        let state = Arc::new(RwLock::new(NodeDerivedState::new()));

        // Add first
        let add_event = make_replica_added(1, TEST_CHUNK, "node-1", 0);
        DAFollower::apply_event(&state, &add_event, "node-1");

        // Remove twice
        let remove_event = make_replica_removed(2, TEST_CHUNK, "node-1");
        DAFollower::apply_event(&state, &remove_event, "node-1");
        DAFollower::apply_event(&state, &remove_event, "node-1");

        // Should be empty
        assert!(state.read().my_chunks.is_empty());
    }

    // ════════════════════════════════════════════════════════════════════════
    // D. SEQUENCE UPDATE TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_update_sequence_increases() {
        let state = Arc::new(RwLock::new(NodeDerivedState::new()));

        DAFollower::update_sequence(&state, 5);
        assert_eq!(state.read().last_sequence, 5);

        DAFollower::update_sequence(&state, 10);
        assert_eq!(state.read().last_sequence, 10);
    }

    #[test]
    fn test_update_sequence_no_decrease() {
        let state = Arc::new(RwLock::new(NodeDerivedState::new()));

        DAFollower::update_sequence(&state, 10);
        DAFollower::update_sequence(&state, 5);

        assert_eq!(state.read().last_sequence, 10);
    }

    // ════════════════════════════════════════════════════════════════════════
    // E. STOP IDEMPOTENCY TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_stop_idempotent() {
        let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
        let mut follower = DAFollower::new(da, "node-1".to_string());

        // Stop multiple times
        follower.stop();
        follower.stop();
        follower.stop();

        assert!(!follower.is_running());
    }

    #[test]
    fn test_stop_before_start() {
        let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
        let mut follower = DAFollower::new(da, "node-1".to_string());

        follower.stop();
        assert!(!follower.is_running());
    }

    // ════════════════════════════════════════════════════════════════════════
    // F. HELPER METHOD TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_chunk_count() {
        let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
        let follower = DAFollower::new(da, "node-1".to_string());

        assert_eq!(follower.chunk_count(), 0);

        {
            let mut state = follower.state().write();
            state.my_chunks.insert(TEST_CHUNK.to_string(), ChunkAssignment {
                chunk_hash: TEST_CHUNK.to_string(),
                replica_index: 0,
                assigned_at: 1000,
            });
        }

        assert_eq!(follower.chunk_count(), 1);
    }

    #[test]
    fn test_has_chunk() {
        let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
        let follower = DAFollower::new(da, "node-1".to_string());

        assert!(!follower.has_chunk(TEST_CHUNK));

        {
            let mut state = follower.state().write();
            state.my_chunks.insert(TEST_CHUNK.to_string(), ChunkAssignment {
                chunk_hash: TEST_CHUNK.to_string(),
                replica_index: 0,
                assigned_at: 1000,
            });
        }

        assert!(follower.has_chunk(TEST_CHUNK));
        assert!(!follower.has_chunk("nonexistent"));
    }

    #[test]
    fn test_get_chunk() {
        let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
        let follower = DAFollower::new(da, "node-1".to_string());

        assert!(follower.get_chunk(TEST_CHUNK).is_none());

        {
            let mut state = follower.state().write();
            state.my_chunks.insert(TEST_CHUNK.to_string(), ChunkAssignment {
                chunk_hash: TEST_CHUNK.to_string(),
                replica_index: 2,
                assigned_at: 5000,
            });
        }

        let assignment = follower.get_chunk(TEST_CHUNK).unwrap();
        assert_eq!(assignment.replica_index, 2);
        assert_eq!(assignment.assigned_at, 5000);
    }

    #[test]
    fn test_chunk_hashes() {
        let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
        let follower = DAFollower::new(da, "node-1".to_string());

        assert!(follower.chunk_hashes().is_empty());

        {
            let mut state = follower.state().write();
            state.my_chunks.insert("chunk1".to_string(), ChunkAssignment {
                chunk_hash: "chunk1".to_string(),
                replica_index: 0,
                assigned_at: 1000,
            });
            state.my_chunks.insert("chunk2".to_string(), ChunkAssignment {
                chunk_hash: "chunk2".to_string(),
                replica_index: 1,
                assigned_at: 2000,
            });
        }

        let hashes = follower.chunk_hashes();
        assert_eq!(hashes.len(), 2);
        assert!(hashes.contains(&"chunk1".to_string()));
        assert!(hashes.contains(&"chunk2".to_string()));
    }

    #[test]
    fn test_last_sequence() {
        let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
        let follower = DAFollower::new(da, "node-1".to_string());

        assert_eq!(follower.last_sequence(), 0);

        DAFollower::update_sequence(&follower.state, 42);

        assert_eq!(follower.last_sequence(), 42);
    }

    // ════════════════════════════════════════════════════════════════════════
    // G. DECODE TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_decode_empty() {
        let result = DAFollower::decode_events(&[]);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_decode_zero_events() {
        let data = 0u32.to_be_bytes();
        let result = DAFollower::decode_events(&data);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_decode_string_helper() {
        let mut data = Vec::new();
        let s = "hello";
        data.extend_from_slice(&(s.len() as u32).to_be_bytes());
        data.extend_from_slice(s.as_bytes());

        let (decoded, offset) = DAFollower::decode_string(&data, 0).unwrap();
        assert_eq!(decoded, "hello");
        assert_eq!(offset, 4 + 5);
    }

    // ════════════════════════════════════════════════════════════════════════
    // H. FILTERING COMPLETE SCENARIO
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_filtering_complete_scenario() {
        let state = Arc::new(RwLock::new(NodeDerivedState::new()));
        let node_id = "my-node";

        // Event for this node
        let event1 = make_replica_added(1, "chunk-a", node_id, 0);
        // Event for another node (should be ignored)
        let event2 = make_replica_added(2, "chunk-b", "other-node", 0);
        // Another event for this node
        let event3 = make_replica_added(3, "chunk-c", node_id, 1);

        // Process all events
        if DAFollower::is_relevant_event(&event1, node_id) {
            DAFollower::apply_event(&state, &event1, node_id);
        }
        DAFollower::update_sequence(&state, event1.sequence);

        if DAFollower::is_relevant_event(&event2, node_id) {
            DAFollower::apply_event(&state, &event2, node_id);
        }
        DAFollower::update_sequence(&state, event2.sequence);

        if DAFollower::is_relevant_event(&event3, node_id) {
            DAFollower::apply_event(&state, &event3, node_id);
        }
        DAFollower::update_sequence(&state, event3.sequence);

        // Verify state
        let state_guard = state.read();
        assert_eq!(state_guard.my_chunks.len(), 2);
        assert!(state_guard.my_chunks.contains_key("chunk-a"));
        assert!(!state_guard.my_chunks.contains_key("chunk-b")); // Not ours
        assert!(state_guard.my_chunks.contains_key("chunk-c"));
        assert_eq!(state_guard.last_sequence, 3);
    }
}