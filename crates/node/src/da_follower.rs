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
use thiserror::Error;
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
// STATE ERROR
// ════════════════════════════════════════════════════════════════════════════

/// Errors that can occur during state derivation.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum StateError {
    /// Event data is malformed or invalid.
    #[error("Malformed event: {0}")]
    MalformedEvent(String),

    /// State is inconsistent with event.
    #[error("Inconsistent state: {0}")]
    InconsistentState(String),
}

// ════════════════════════════════════════════════════════════════════════════
// CHUNK ASSIGNMENT
// ════════════════════════════════════════════════════════════════════════════

/// Assignment of a chunk to this node.
///
/// This struct represents the assignment metadata for chunks that
/// this node is responsible for storing.
///
/// ## Fields
///
/// - `hash`: Unique identifier of the chunk
/// - `replica_index`: Position of this replica (0 = primary)
/// - `assigned_at`: Timestamp when assignment was made
/// - `verified`: Local verification status
/// - `size_bytes`: Size of the chunk data
///
/// ## Derived State
///
/// All fields are derived from DA events:
/// - `hash`, `replica_index`, `assigned_at` from ReplicaAdded
/// - `verified` updated by verification events
/// - `size_bytes` from chunk metadata
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkAssignment {
    /// Hash identifier of the assigned chunk
    pub hash: String,
    /// Replica index for this node's copy (0 = primary)
    pub replica_index: u8,
    /// Timestamp when assignment was made (from DA event)
    pub assigned_at: u64,
    /// Whether this replica has been locally verified
    pub verified: bool,
    /// Size of the chunk in bytes
    pub size_bytes: u64,
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
///
/// ## Determinism
///
/// All state mutations are deterministic:
/// - Same events → Same state
/// - No random values
/// - No local timestamps
#[derive(Debug)]
pub struct NodeDerivedState {
    /// Chunks assigned to this node: hash -> assignment info
    pub my_chunks: HashMap<String, ChunkAssignment>,
    /// Subset of coordinator state for local decisions (non-authoritative)
    pub coordinator_state: DADerivedState,
    /// Last sequence number processed by this node
    pub last_sequence: u64,
    /// Last height processed from DA
    pub last_height: u64,
    /// Chunk metadata cache: hash -> size_bytes (from ChunkDeclared events)
    chunk_sizes: HashMap<String, u64>,
}

impl NodeDerivedState {
    /// Create a new empty node derived state.
    pub fn new() -> Self {
        Self {
            my_chunks: HashMap::new(),
            coordinator_state: DADerivedState::new(),
            last_sequence: 0,
            last_height: 0,
            chunk_sizes: HashMap::new(),
        }
    }

    /// Apply a DA event to this node's state.
    ///
    /// # Arguments
    ///
    /// * `event` - The DA event to apply
    /// * `node_id` - This node's identifier for filtering
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Event applied (or ignored if not relevant)
    /// * `Err(StateError)` - Event was malformed
    ///
    /// # Guarantees
    ///
    /// - Pure state mutation (no IO, no async)
    /// - Deterministic behavior
    /// - Idempotent for same event
    /// - Never panics
    /// - Irrelevant events are NO-OP (not error)
    pub fn apply_event(&mut self, event: &DAEvent, node_id: &str) -> Result<(), StateError> {
        match &event.payload {
            DAEventPayload::ReplicaAdded(p) => {
                // Only process if this node is the target
                if p.node_id != node_id {
                    return Ok(()); // NO-OP for other nodes
                }

                // Idempotency: skip if already assigned
                if self.my_chunks.contains_key(&p.chunk_hash) {
                    debug!("Replica already assigned: {}", p.chunk_hash);
                    return Ok(());
                }

                // Get size from cached chunk metadata (default 0 if not known)
                let size_bytes = self.chunk_sizes.get(&p.chunk_hash).copied().unwrap_or(0);

                // Add chunk assignment
                let assignment = ChunkAssignment {
                    hash: p.chunk_hash.clone(),
                    replica_index: p.replica_index,
                    assigned_at: p.added_at,
                    verified: false, // New assignments start unverified
                    size_bytes,
                };
                self.my_chunks.insert(p.chunk_hash.clone(), assignment);
                debug!(
                    "Node {} assigned chunk {} (index {})",
                    node_id, p.chunk_hash, p.replica_index
                );
            }
            DAEventPayload::ReplicaRemoved(p) => {
                // Only process if this node is the target
                if p.node_id != node_id {
                    return Ok(()); // NO-OP for other nodes
                }

                // Remove chunk assignment (idempotent)
                if self.my_chunks.remove(&p.chunk_hash).is_some() {
                    debug!("Node {} removed chunk {}", node_id, p.chunk_hash);
                }
            }
            DAEventPayload::ChunkDeclared(p) => {
                // Cache chunk size for future ReplicaAdded events
                self.chunk_sizes.insert(p.chunk_hash.clone(), p.size_bytes);
                
                // Also update existing assignment if we have it
                if let Some(assignment) = self.my_chunks.get_mut(&p.chunk_hash) {
                    assignment.size_bytes = p.size_bytes;
                }
            }
            DAEventPayload::ChunkRemoved(p) => {
                // Remove from cache
                self.chunk_sizes.remove(&p.chunk_hash);
                
                // If we have this chunk, it should be removed
                // (ReplicaRemoved should come first, but handle gracefully)
                if self.my_chunks.remove(&p.chunk_hash).is_some() {
                    debug!("Chunk {} globally removed, cleaned from node state", p.chunk_hash);
                }
            }
            // Other events are NO-OP for node state
            DAEventPayload::NodeRegistered(_) => {}
            DAEventPayload::NodeUnregistered(_) => {}
            DAEventPayload::ZoneAssigned(_) => {}
            DAEventPayload::ZoneUnassigned(_) => {}
        }

        Ok(())
    }

    /// Get all chunk assignments for this node.
    ///
    /// # Returns
    ///
    /// Vector of references to all chunk assignments.
    /// Order is not guaranteed (HashMap iteration order).
    pub fn get_my_chunks(&self) -> Vec<&ChunkAssignment> {
        self.my_chunks.values().collect()
    }

    /// Get a specific chunk assignment by hash.
    ///
    /// # Arguments
    ///
    /// * `hash` - The chunk hash to look up
    ///
    /// # Returns
    ///
    /// * `Some(&ChunkAssignment)` - If chunk is assigned to this node
    /// * `None` - If chunk is not assigned
    pub fn get_chunk_assignment(&self, hash: &str) -> Option<&ChunkAssignment> {
        self.my_chunks.get(hash)
    }

    /// Determine if this node should store a chunk.
    ///
    /// A node should store a chunk if:
    /// - The chunk is assigned to this node (via ReplicaAdded)
    /// - The chunk is not yet verified (needs to be fetched/stored)
    ///
    /// # Arguments
    ///
    /// * `chunk_hash` - Hash of the chunk to check
    ///
    /// # Returns
    ///
    /// * `true` - Node should store this chunk
    /// * `false` - Node should NOT store (not assigned or already verified)
    pub fn should_store(&self, chunk_hash: &str) -> bool {
        match self.my_chunks.get(chunk_hash) {
            Some(assignment) => !assignment.verified,
            None => false, // Not assigned, don't store
        }
    }

    /// Determine if this node should delete a chunk.
    ///
    /// A node should delete a chunk if:
    /// - The chunk is NOT assigned to this node
    /// - (The chunk was previously assigned but ReplicaRemoved was received)
    ///
    /// # Arguments
    ///
    /// * `chunk_hash` - Hash of the chunk to check
    ///
    /// # Returns
    ///
    /// * `true` - Node should delete this chunk (not assigned)
    /// * `false` - Node should NOT delete (still assigned)
    pub fn should_delete(&self, chunk_hash: &str) -> bool {
        !self.my_chunks.contains_key(chunk_hash)
    }

    /// Mark a chunk as verified.
    ///
    /// Called after successful storage/verification of chunk data.
    ///
    /// # Arguments
    ///
    /// * `chunk_hash` - Hash of the verified chunk
    ///
    /// # Returns
    ///
    /// * `true` - Chunk was found and marked verified
    /// * `false` - Chunk not assigned to this node
    pub fn set_verified(&mut self, chunk_hash: &str, verified: bool) -> bool {
        if let Some(assignment) = self.my_chunks.get_mut(chunk_hash) {
            assignment.verified = verified;
            true
        } else {
            false
        }
    }

    /// Update sequence number.
    ///
    /// Only increases, never decreases (monotonic).
    pub fn update_sequence(&mut self, sequence: u64) {
        if sequence > self.last_sequence {
            self.last_sequence = sequence;
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
                                                let mut state_guard = state.write();
                                                for event in events {
                                                    // Apply event (handles filtering internally)
                                                    if let Err(e) = state_guard.apply_event(&event, &node_id) {
                                                        warn!("Failed to apply event: {:?}", e);
                                                    }
                                                    state_guard.update_sequence(event.sequence);
                                                }
                                                // Update last height
                                                last_height.store(blob.ref_.height, Ordering::SeqCst);
                                                state_guard.last_height = blob.ref_.height;
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
    pub fn is_relevant_event(event: &DAEvent, node_id: &str) -> bool {
        match &event.payload {
            DAEventPayload::ReplicaAdded(p) => p.node_id == node_id,
            DAEventPayload::ReplicaRemoved(p) => p.node_id == node_id,
            _ => false,
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

                            let mut state_guard = self.state.write();
                            for event in &sorted_events {
                                if let Err(e) = state_guard.apply_event(event, &self.node_id) {
                                    warn!("Failed to apply event during sync: {:?}", e);
                                }
                                state_guard.update_sequence(event.sequence);
                            }

                            // Update last height
                            self.last_height.store(blob.ref_.height, Ordering::SeqCst);
                            state_guard.last_height = blob.ref_.height;
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

    const TEST_NODE: &str = "node-1";
    const OTHER_NODE: &str = "other-node";
    const TEST_CHUNK: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    // ════════════════════════════════════════════════════════════════════════
    // HELPER FUNCTIONS
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

    fn make_chunk_declared(seq: u64, chunk_hash: &str, size: u64) -> DAEvent {
        DAEvent {
            sequence: seq,
            timestamp: seq * 1000,
            payload: DAEventPayload::ChunkDeclared(ChunkDeclaredPayload {
                chunk_hash: chunk_hash.to_string(),
                size_bytes: size,
                replication_factor: 3,
                uploader_id: "uploader".to_string(),
                da_commitment: [0u8; 32],
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
    // A. CHUNK ASSIGNMENT STRUCT TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_chunk_assignment_struct_fields() {
        let assignment = ChunkAssignment {
            hash: "abc123".to_string(),
            replica_index: 0,
            assigned_at: 1000,
            verified: false,
            size_bytes: 4096,
        };

        assert_eq!(assignment.hash, "abc123");
        assert_eq!(assignment.replica_index, 0);
        assert_eq!(assignment.assigned_at, 1000);
        assert!(!assignment.verified);
        assert_eq!(assignment.size_bytes, 4096);
    }

    #[test]
    fn test_chunk_assignment_clone() {
        let assignment = ChunkAssignment {
            hash: TEST_CHUNK.to_string(),
            replica_index: 2,
            assigned_at: 5000,
            verified: true,
            size_bytes: 1024,
        };

        let cloned = assignment.clone();
        assert_eq!(assignment, cloned);
    }

    // ════════════════════════════════════════════════════════════════════════
    // B. ASSIGNMENT LIFECYCLE TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_replica_added_creates_assignment() {
        let mut state = NodeDerivedState::new();
        let event = make_replica_added(1, TEST_CHUNK, TEST_NODE, 0);

        let result = state.apply_event(&event, TEST_NODE);
        assert!(result.is_ok());

        assert!(state.my_chunks.contains_key(TEST_CHUNK));
        let assignment = state.get_chunk_assignment(TEST_CHUNK).unwrap();
        assert_eq!(assignment.hash, TEST_CHUNK);
        assert_eq!(assignment.replica_index, 0);
        assert!(!assignment.verified);
    }

    #[test]
    fn test_replica_removed_deletes_assignment() {
        let mut state = NodeDerivedState::new();

        // First add
        let add_event = make_replica_added(1, TEST_CHUNK, TEST_NODE, 0);
        state.apply_event(&add_event, TEST_NODE).unwrap();
        assert!(state.my_chunks.contains_key(TEST_CHUNK));

        // Then remove
        let remove_event = make_replica_removed(2, TEST_CHUNK, TEST_NODE);
        state.apply_event(&remove_event, TEST_NODE).unwrap();
        assert!(!state.my_chunks.contains_key(TEST_CHUNK));
    }

    #[test]
    fn test_chunk_declared_before_replica_added() {
        let mut state = NodeDerivedState::new();

        // ChunkDeclared first
        let declare_event = make_chunk_declared(1, TEST_CHUNK, 8192);
        state.apply_event(&declare_event, TEST_NODE).unwrap();

        // Then ReplicaAdded
        let add_event = make_replica_added(2, TEST_CHUNK, TEST_NODE, 0);
        state.apply_event(&add_event, TEST_NODE).unwrap();

        // Should have size from ChunkDeclared
        let assignment = state.get_chunk_assignment(TEST_CHUNK).unwrap();
        assert_eq!(assignment.size_bytes, 8192);
    }

    #[test]
    fn test_chunk_declared_after_replica_added() {
        let mut state = NodeDerivedState::new();

        // ReplicaAdded first (size unknown)
        let add_event = make_replica_added(1, TEST_CHUNK, TEST_NODE, 0);
        state.apply_event(&add_event, TEST_NODE).unwrap();
        assert_eq!(state.get_chunk_assignment(TEST_CHUNK).unwrap().size_bytes, 0);

        // Then ChunkDeclared
        let declare_event = make_chunk_declared(2, TEST_CHUNK, 4096);
        state.apply_event(&declare_event, TEST_NODE).unwrap();

        // Should be updated
        let assignment = state.get_chunk_assignment(TEST_CHUNK).unwrap();
        assert_eq!(assignment.size_bytes, 4096);
    }

    // ════════════════════════════════════════════════════════════════════════
    // C. VERIFICATION TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_set_verified_true() {
        let mut state = NodeDerivedState::new();
        let event = make_replica_added(1, TEST_CHUNK, TEST_NODE, 0);
        state.apply_event(&event, TEST_NODE).unwrap();

        assert!(!state.get_chunk_assignment(TEST_CHUNK).unwrap().verified);

        let result = state.set_verified(TEST_CHUNK, true);
        assert!(result);
        assert!(state.get_chunk_assignment(TEST_CHUNK).unwrap().verified);
    }

    #[test]
    fn test_set_verified_false() {
        let mut state = NodeDerivedState::new();
        let event = make_replica_added(1, TEST_CHUNK, TEST_NODE, 0);
        state.apply_event(&event, TEST_NODE).unwrap();

        state.set_verified(TEST_CHUNK, true);
        state.set_verified(TEST_CHUNK, false);

        assert!(!state.get_chunk_assignment(TEST_CHUNK).unwrap().verified);
    }

    #[test]
    fn test_set_verified_unknown_chunk() {
        let mut state = NodeDerivedState::new();
        let result = state.set_verified("unknown", true);
        assert!(!result);
    }

    // ════════════════════════════════════════════════════════════════════════
    // D. IRRELEVANT EVENT TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_replica_added_other_node_no_effect() {
        let mut state = NodeDerivedState::new();
        let event = make_replica_added(1, TEST_CHUNK, OTHER_NODE, 0);

        let result = state.apply_event(&event, TEST_NODE);
        assert!(result.is_ok());
        assert!(state.my_chunks.is_empty());
    }

    #[test]
    fn test_replica_removed_other_node_no_effect() {
        let mut state = NodeDerivedState::new();

        // Add for our node
        let add_event = make_replica_added(1, TEST_CHUNK, TEST_NODE, 0);
        state.apply_event(&add_event, TEST_NODE).unwrap();

        // Remove for other node
        let remove_event = make_replica_removed(2, TEST_CHUNK, OTHER_NODE);
        state.apply_event(&remove_event, TEST_NODE).unwrap();

        // Our chunk should still be there
        assert!(state.my_chunks.contains_key(TEST_CHUNK));
    }

    #[test]
    fn test_node_registered_no_effect() {
        let mut state = NodeDerivedState::new();
        let event = DAEvent {
            sequence: 1,
            timestamp: 1000,
            payload: DAEventPayload::NodeRegistered(NodeRegisteredPayload {
                node_id: TEST_NODE.to_string(),
                zone: "zone-a".to_string(),
                addr: "addr".to_string(),
                capacity_gb: 100,
            }),
        };

        state.apply_event(&event, TEST_NODE).unwrap();
        assert!(state.my_chunks.is_empty());
    }

    #[test]
    fn test_zone_assigned_no_effect() {
        let mut state = NodeDerivedState::new();
        let event = DAEvent {
            sequence: 1,
            timestamp: 1000,
            payload: DAEventPayload::ZoneAssigned(ZoneAssignedPayload {
                zone_id: "zone-a".to_string(),
                node_id: TEST_NODE.to_string(),
            }),
        };

        state.apply_event(&event, TEST_NODE).unwrap();
        assert!(state.my_chunks.is_empty());
    }

    // ════════════════════════════════════════════════════════════════════════
    // E. SHOULD_STORE / SHOULD_DELETE TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_should_store_assigned_unverified() {
        let mut state = NodeDerivedState::new();
        let event = make_replica_added(1, TEST_CHUNK, TEST_NODE, 0);
        state.apply_event(&event, TEST_NODE).unwrap();

        assert!(state.should_store(TEST_CHUNK));
    }

    #[test]
    fn test_should_store_assigned_verified() {
        let mut state = NodeDerivedState::new();
        let event = make_replica_added(1, TEST_CHUNK, TEST_NODE, 0);
        state.apply_event(&event, TEST_NODE).unwrap();
        state.set_verified(TEST_CHUNK, true);

        // Already verified, no need to store again
        assert!(!state.should_store(TEST_CHUNK));
    }

    #[test]
    fn test_should_store_not_assigned() {
        let state = NodeDerivedState::new();
        assert!(!state.should_store(TEST_CHUNK));
    }

    #[test]
    fn test_should_delete_not_assigned() {
        let state = NodeDerivedState::new();
        assert!(state.should_delete(TEST_CHUNK));
    }

    #[test]
    fn test_should_delete_assigned() {
        let mut state = NodeDerivedState::new();
        let event = make_replica_added(1, TEST_CHUNK, TEST_NODE, 0);
        state.apply_event(&event, TEST_NODE).unwrap();

        assert!(!state.should_delete(TEST_CHUNK));
    }

    #[test]
    fn test_should_delete_after_removal() {
        let mut state = NodeDerivedState::new();

        let add_event = make_replica_added(1, TEST_CHUNK, TEST_NODE, 0);
        state.apply_event(&add_event, TEST_NODE).unwrap();
        assert!(!state.should_delete(TEST_CHUNK));

        let remove_event = make_replica_removed(2, TEST_CHUNK, TEST_NODE);
        state.apply_event(&remove_event, TEST_NODE).unwrap();
        assert!(state.should_delete(TEST_CHUNK));
    }

    // ════════════════════════════════════════════════════════════════════════
    // F. IDEMPOTENCY TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_replica_added_idempotent() {
        let mut state = NodeDerivedState::new();
        let event = make_replica_added(1, TEST_CHUNK, TEST_NODE, 0);

        state.apply_event(&event, TEST_NODE).unwrap();
        state.apply_event(&event, TEST_NODE).unwrap();
        state.apply_event(&event, TEST_NODE).unwrap();

        assert_eq!(state.my_chunks.len(), 1);
    }

    #[test]
    fn test_replica_removed_idempotent() {
        let mut state = NodeDerivedState::new();

        let add_event = make_replica_added(1, TEST_CHUNK, TEST_NODE, 0);
        state.apply_event(&add_event, TEST_NODE).unwrap();

        let remove_event = make_replica_removed(2, TEST_CHUNK, TEST_NODE);
        state.apply_event(&remove_event, TEST_NODE).unwrap();
        state.apply_event(&remove_event, TEST_NODE).unwrap();
        state.apply_event(&remove_event, TEST_NODE).unwrap();

        assert!(state.my_chunks.is_empty());
    }

    #[test]
    fn test_same_events_same_state() {
        let events = vec![
            make_chunk_declared(1, "chunk-a", 1024),
            make_replica_added(2, "chunk-a", TEST_NODE, 0),
            make_chunk_declared(3, "chunk-b", 2048),
            make_replica_added(4, "chunk-b", TEST_NODE, 1),
            make_replica_removed(5, "chunk-a", TEST_NODE),
        ];

        // Apply to first state
        let mut state1 = NodeDerivedState::new();
        for event in &events {
            state1.apply_event(event, TEST_NODE).unwrap();
        }

        // Apply to second state
        let mut state2 = NodeDerivedState::new();
        for event in &events {
            state2.apply_event(event, TEST_NODE).unwrap();
        }

        // States should be identical
        assert_eq!(state1.my_chunks.len(), state2.my_chunks.len());
        for (k, v) in &state1.my_chunks {
            let v2 = state2.my_chunks.get(k).unwrap();
            assert_eq!(v, v2);
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // G. QUERY METHOD TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_get_my_chunks_empty() {
        let state = NodeDerivedState::new();
        assert!(state.get_my_chunks().is_empty());
    }

    #[test]
    fn test_get_my_chunks_multiple() {
        let mut state = NodeDerivedState::new();

        state.apply_event(&make_replica_added(1, "chunk-a", TEST_NODE, 0), TEST_NODE).unwrap();
        state.apply_event(&make_replica_added(2, "chunk-b", TEST_NODE, 1), TEST_NODE).unwrap();
        state.apply_event(&make_replica_added(3, "chunk-c", TEST_NODE, 2), TEST_NODE).unwrap();

        let chunks = state.get_my_chunks();
        assert_eq!(chunks.len(), 3);
    }

    #[test]
    fn test_get_chunk_assignment_exists() {
        let mut state = NodeDerivedState::new();
        state.apply_event(&make_replica_added(1, TEST_CHUNK, TEST_NODE, 0), TEST_NODE).unwrap();

        let assignment = state.get_chunk_assignment(TEST_CHUNK);
        assert!(assignment.is_some());
        assert_eq!(assignment.unwrap().hash, TEST_CHUNK);
    }

    #[test]
    fn test_get_chunk_assignment_not_exists() {
        let state = NodeDerivedState::new();
        assert!(state.get_chunk_assignment(TEST_CHUNK).is_none());
    }

    // ════════════════════════════════════════════════════════════════════════
    // H. SEQUENCE UPDATE TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_update_sequence_increases() {
        let mut state = NodeDerivedState::new();

        state.update_sequence(5);
        assert_eq!(state.last_sequence, 5);

        state.update_sequence(10);
        assert_eq!(state.last_sequence, 10);
    }

    #[test]
    fn test_update_sequence_no_decrease() {
        let mut state = NodeDerivedState::new();

        state.update_sequence(10);
        state.update_sequence(5);

        assert_eq!(state.last_sequence, 10);
    }

    // ════════════════════════════════════════════════════════════════════════
    // I. CHUNK REMOVED GLOBAL TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_chunk_removed_clears_assignment() {
        let mut state = NodeDerivedState::new();

        state.apply_event(&make_replica_added(1, TEST_CHUNK, TEST_NODE, 0), TEST_NODE).unwrap();
        assert!(state.my_chunks.contains_key(TEST_CHUNK));

        state.apply_event(&make_chunk_removed(2, TEST_CHUNK), TEST_NODE).unwrap();
        assert!(!state.my_chunks.contains_key(TEST_CHUNK));
    }

    #[test]
    fn test_chunk_removed_no_assignment_no_effect() {
        let mut state = NodeDerivedState::new();
        state.apply_event(&make_chunk_removed(1, TEST_CHUNK), TEST_NODE).unwrap();
        assert!(state.my_chunks.is_empty());
    }

    // ════════════════════════════════════════════════════════════════════════
    // J. DA FOLLOWER TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_da_follower_new() {
        let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
        let follower = DAFollower::new(da, TEST_NODE.to_string());

        assert_eq!(follower.node_id(), TEST_NODE);
        assert!(!follower.is_running());
        assert_eq!(follower.chunk_count(), 0);
    }

    #[test]
    fn test_da_follower_state_empty() {
        let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
        let follower = DAFollower::new(da, TEST_NODE.to_string());

        let state = follower.state().read();
        assert!(state.my_chunks.is_empty());
        assert_eq!(state.last_sequence, 0);
    }

    #[test]
    fn test_da_follower_stop_idempotent() {
        let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
        let mut follower = DAFollower::new(da, TEST_NODE.to_string());

        follower.stop();
        follower.stop();
        follower.stop();

        assert!(!follower.is_running());
    }

    #[test]
    fn test_da_follower_stop_before_start() {
        let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
        let mut follower = DAFollower::new(da, TEST_NODE.to_string());

        follower.stop();
        assert!(!follower.is_running());
    }

    #[test]
    fn test_is_relevant_event_replica_added_match() {
        let event = make_replica_added(1, TEST_CHUNK, TEST_NODE, 0);
        assert!(DAFollower::is_relevant_event(&event, TEST_NODE));
    }

    #[test]
    fn test_is_relevant_event_replica_added_no_match() {
        let event = make_replica_added(1, TEST_CHUNK, OTHER_NODE, 0);
        assert!(!DAFollower::is_relevant_event(&event, TEST_NODE));
    }

    #[test]
    fn test_is_relevant_event_replica_removed_match() {
        let event = make_replica_removed(1, TEST_CHUNK, TEST_NODE);
        assert!(DAFollower::is_relevant_event(&event, TEST_NODE));
    }

    #[test]
    fn test_is_relevant_event_other_types() {
        let event = DAEvent {
            sequence: 1,
            timestamp: 1000,
            payload: DAEventPayload::NodeRegistered(NodeRegisteredPayload {
                node_id: TEST_NODE.to_string(),
                zone: "zone-a".to_string(),
                addr: "addr".to_string(),
                capacity_gb: 100,
            }),
        };
        assert!(!DAFollower::is_relevant_event(&event, TEST_NODE));
    }

    // ════════════════════════════════════════════════════════════════════════
    // K. DECODE TESTS
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
    // L. STATE ERROR TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_state_error_display() {
        let err = StateError::MalformedEvent("test".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Malformed"));
    }

    #[test]
    fn test_state_error_clone() {
        let err = StateError::InconsistentState("test".to_string());
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }
}