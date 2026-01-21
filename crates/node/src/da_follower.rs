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

use crate::multi_da_source::DASourceType;

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
// REPLICA STATUS
// ════════════════════════════════════════════════════════════════════════════

/// Status of a replica on this node.
///
/// Tracks the lifecycle of each chunk assigned to this node,
/// from assignment through verification.
///
/// ## Status Flow
///
/// ```text
/// ReplicaAdded → Pending → Stored → Verified
///                   │          │
///                   └─→ Missing └─→ Corrupted
/// ```
///
/// ## Semantics
///
/// | Status    | Meaning                                        |
/// |-----------|------------------------------------------------|
/// | Pending   | Assigned via DA, not yet in local storage      |
/// | Stored    | Data exists in local storage                   |
/// | Verified  | Data verified (hash check / challenge passed)  |
/// | Missing   | Should exist but not found locally             |
/// | Corrupted | Data exists but failed verification            |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReplicaStatus {
    /// Assigned via DA, not yet stored locally.
    Pending,
    /// Data exists in local storage.
    Stored,
    /// Data verified successfully.
    Verified,
    /// Should exist but not found locally.
    Missing,
    /// Data exists but failed verification.
    Corrupted,
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
/// - Fallback tracking for multi-source DA (14A.1A.46)
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
///
/// ## Fallback State Invariants (14A.1A.46)
///
/// The following invariants MUST hold:
/// - If `fallback_active == false`, then `fallback_since == None`
/// - If `fallback_active == true`, then `fallback_since.is_some()`
/// - If `fallback_active == true`, then `current_da_source != Primary`
/// - `events_from_fallback` only increments, never decreases
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
    /// Replica status for each chunk: hash -> status
    pub replica_status: HashMap<String, ReplicaStatus>,

    // ════════════════════════════════════════════════════════════════════════
    // FALLBACK TRACKING FIELDS (14A.1A.46)
    // ════════════════════════════════════════════════════════════════════════

    /// Whether fallback mode is currently active.
    ///
    /// - `true`: Node is reading from a fallback DA source (Secondary/Emergency)
    /// - `false`: Node is reading from Primary DA source
    ///
    /// Invariant: If false, `fallback_since` MUST be None.
    pub fallback_active: bool,

    /// Timestamp when fallback was activated.
    ///
    /// - `Some(timestamp)`: Fallback is active, activated at this timestamp
    /// - `None`: Fallback is not active
    ///
    /// Invariant: Must be Some iff `fallback_active == true`.
    pub fallback_since: Option<u64>,

    /// Current DA source type being used.
    ///
    /// Tracks which DA source is currently being read from.
    /// Updated atomically with fallback_active.
    pub current_da_source: DASourceType,

    /// Count of events processed from fallback sources.
    ///
    /// Only increments when events are processed from non-Primary sources.
    /// Uses saturating arithmetic to prevent overflow.
    pub events_from_fallback: u64,

    /// Last sequence number after reconciliation completed.
    ///
    /// - `Some(seq)`: Reconciliation completed at this sequence
    /// - `None`: No reconciliation has occurred
    ///
    /// Used to verify state consistency after source switches.
    pub last_reconciliation_sequence: Option<u64>,
}

impl NodeDerivedState {
    /// Create a new empty node derived state.
    ///
    /// ## Initial State (14A.1A.46)
    ///
    /// - `fallback_active`: false (not in fallback mode)
    /// - `fallback_since`: None (no fallback timestamp)
    /// - `current_da_source`: Primary (default source)
    /// - `events_from_fallback`: 0 (no fallback events yet)
    /// - `last_reconciliation_sequence`: None (no reconciliation yet)
    ///
    /// All invariants are satisfied in the initial state.
    pub fn new() -> Self {
        Self {
            my_chunks: HashMap::new(),
            coordinator_state: DADerivedState::new(),
            last_sequence: 0,
            last_height: 0,
            chunk_sizes: HashMap::new(),
            replica_status: HashMap::new(),
            // Fallback fields (14A.1A.46) - initial state
            fallback_active: false,
            fallback_since: None,
            current_da_source: DASourceType::Primary,
            events_from_fallback: 0,
            last_reconciliation_sequence: None,
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
                
                // Set initial replica status to Pending
                self.replica_status.insert(p.chunk_hash.clone(), ReplicaStatus::Pending);
                
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
                
                // Remove replica status
                self.replica_status.remove(&p.chunk_hash);
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
                
                // Remove replica status
                self.replica_status.remove(&p.chunk_hash);
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

    /// Update the status of a replica.
    ///
    /// This method updates the status of a specific replica assigned to this node.
    /// It is a pure state mutation with no IO or async operations.
    ///
    /// # Arguments
    ///
    /// * `hash` - The chunk hash to update status for
    /// * `status` - The new status to set
    ///
    /// # Behavior
    ///
    /// - If the hash is assigned to this node: updates the status
    /// - If the hash is NOT assigned: NO-OP (does not create assignment)
    /// - Never panics
    ///
    /// # Note
    ///
    /// Status can only be set for chunks that have been assigned via ReplicaAdded.
    /// This ensures status is always tied to a valid DA assignment.
    pub fn update_replica_status(&mut self, hash: &str, status: ReplicaStatus) {
        // Only update status for assigned chunks
        if self.my_chunks.contains_key(hash) {
            self.replica_status.insert(hash.to_string(), status);
        }
        // If not assigned, NO-OP (do not create orphan status)
    }

    /// Get all chunks with Pending status.
    ///
    /// Returns chunk hashes that are assigned but not yet stored locally.
    /// These are chunks that need to be fetched from the network.
    ///
    /// # Returns
    ///
    /// Vector of chunk hashes with Pending status.
    /// Order is not guaranteed (deterministic but arbitrary).
    ///
    /// # Guarantees
    ///
    /// - Only returns chunks assigned to this node
    /// - Only returns chunks with exactly Pending status
    /// - Never panics
    pub fn get_pending_replicas(&self) -> Vec<String> {
        self.replica_status
            .iter()
            .filter(|(_, status)| **status == ReplicaStatus::Pending)
            .map(|(hash, _)| hash.clone())
            .collect()
    }

    /// Get all chunks with Missing status.
    ///
    /// Returns chunk hashes that should exist locally but are not found.
    /// These are chunks that need repair or re-fetch.
    ///
    /// # Returns
    ///
    /// Vector of chunk hashes with Missing status.
    /// Order is not guaranteed (deterministic but arbitrary).
    ///
    /// # Guarantees
    ///
    /// - Only returns chunks assigned to this node
    /// - Only returns chunks with exactly Missing status
    /// - Never panics
    pub fn get_missing_replicas(&self) -> Vec<String> {
        self.replica_status
            .iter()
            .filter(|(_, status)| **status == ReplicaStatus::Missing)
            .map(|(hash, _)| hash.clone())
            .collect()
    }

    /// Get the status of a specific replica.
    ///
    /// # Arguments
    ///
    /// * `hash` - The chunk hash to check
    ///
    /// # Returns
    ///
    /// * `Some(status)` - If the chunk has a status
    /// * `None` - If the chunk has no status (not assigned)
    pub fn get_replica_status(&self, hash: &str) -> Option<ReplicaStatus> {
        self.replica_status.get(hash).copied()
    }

    // ════════════════════════════════════════════════════════════════════════════
    // FALLBACK STATE TRANSITION METHODS (14A.1A.46)
    // ════════════════════════════════════════════════════════════════════════════

    /// Activate fallback mode.
    ///
    /// Transitions the state to fallback mode atomically.
    /// All related fields are updated together to maintain invariants.
    ///
    /// ## Arguments
    ///
    /// * `timestamp` - Timestamp of fallback activation (from event or system)
    /// * `source` - The fallback DA source being activated (must NOT be Primary)
    ///
    /// ## State Changes
    ///
    /// - `fallback_active` → `true`
    /// - `fallback_since` → `Some(timestamp)`
    /// - `current_da_source` → `source`
    ///
    /// ## Invariants Maintained
    ///
    /// - If already in fallback mode, updates source but preserves `fallback_since`
    /// - `fallback_active` and `fallback_since` are always consistent
    ///
    /// ## Guarantees
    ///
    /// - Atomic update (all fields updated together)
    /// - No partial state
    /// - Never panics
    /// - Thread-safe (caller must hold write lock)
    pub fn activate_fallback(&mut self, timestamp: u64, source: DASourceType) {
        // Update source regardless
        self.current_da_source = source;

        // Only set fallback_since if not already in fallback mode
        // This preserves the original activation timestamp
        if !self.fallback_active {
            self.fallback_active = true;
            self.fallback_since = Some(timestamp);
        }
        // If already active, just update source (e.g., Secondary → Emergency)
    }

    /// Deactivate fallback mode.
    ///
    /// Transitions the state back to primary mode atomically.
    /// Clears all fallback-related state.
    ///
    /// ## State Changes
    ///
    /// - `fallback_active` → `false`
    /// - `fallback_since` → `None`
    /// - `current_da_source` → `Primary`
    ///
    /// ## Invariants Maintained
    ///
    /// - `fallback_active == false` implies `fallback_since == None`
    /// - `current_da_source` is always Primary when not in fallback
    ///
    /// ## Guarantees
    ///
    /// - Atomic update (all fields updated together)
    /// - Idempotent (safe to call when already deactivated)
    /// - No partial state
    /// - Never panics
    /// - Thread-safe (caller must hold write lock)
    pub fn deactivate_fallback(&mut self) {
        self.fallback_active = false;
        self.fallback_since = None;
        self.current_da_source = DASourceType::Primary;
    }

    /// Record that an event was processed from a fallback source.
    ///
    /// Increments the `events_from_fallback` counter.
    /// Uses saturating arithmetic to prevent overflow.
    ///
    /// ## State Changes
    ///
    /// - `events_from_fallback` → `events_from_fallback + 1` (saturating)
    ///
    /// ## Guarantees
    ///
    /// - Never overflows (uses saturating_add)
    /// - Never panics
    /// - Thread-safe (caller must hold write lock)
    ///
    /// ## Usage
    ///
    /// Should be called for each event processed when `current_da_source != Primary`.
    pub fn record_fallback_event(&mut self) {
        self.events_from_fallback = self.events_from_fallback.saturating_add(1);
    }

    /// Record reconciliation completion.
    ///
    /// Updates `last_reconciliation_sequence` to record when reconciliation
    /// was successfully completed.
    ///
    /// ## Arguments
    ///
    /// * `sequence` - The sequence number at reconciliation completion
    ///
    /// ## State Changes
    ///
    /// - `last_reconciliation_sequence` → `Some(sequence)`
    ///
    /// ## Guarantees
    ///
    /// - Atomic update
    /// - Never panics
    /// - Thread-safe (caller must hold write lock)
    ///
    /// ## Usage
    ///
    /// Called after successful reconciliation to record the state checkpoint.
    pub fn record_reconciliation(&mut self, sequence: u64) {
        self.last_reconciliation_sequence = Some(sequence);
    }

    /// Check if fallback mode is currently active.
    ///
    /// ## Returns
    ///
    /// * `true` - Currently in fallback mode
    /// * `false` - Using primary DA source
    #[must_use]
    pub fn is_fallback_active(&self) -> bool {
        self.fallback_active
    }

    /// Get the duration of current fallback (if active).
    ///
    /// ## Arguments
    ///
    /// * `current_timestamp` - Current timestamp for duration calculation
    ///
    /// ## Returns
    ///
    /// * `Some(duration)` - Fallback is active, returns duration in same units as timestamp
    /// * `None` - Fallback is not active
    ///
    /// ## Guarantees
    ///
    /// - Returns None if not in fallback mode
    /// - Uses saturating subtraction to prevent underflow
    /// - Never panics
    #[must_use]
    pub fn get_fallback_duration(&self, current_timestamp: u64) -> Option<u64> {
        self.fallback_since.map(|since| current_timestamp.saturating_sub(since))
    }

    /// Validate fallback state invariants.
    ///
    /// Checks that all fallback-related fields are in a consistent state.
    ///
    /// ## Returns
    ///
    /// * `true` - All invariants hold
    /// * `false` - State is inconsistent (should never happen in correct code)
    ///
    /// ## Invariants Checked
    ///
    /// 1. If `fallback_active == false`, then `fallback_since == None`
    /// 2. If `fallback_active == true`, then `fallback_since.is_some()`
    /// 3. If `fallback_active == false`, then `current_da_source == Primary`
    ///
    /// ## Usage
    ///
    /// Can be used in debug builds or tests to verify state consistency.
    #[must_use]
    pub fn validate_fallback_invariants(&self) -> bool {
        // Invariant 1 & 2: fallback_active and fallback_since must be consistent
        let since_consistent = if self.fallback_active {
            self.fallback_since.is_some()
        } else {
            self.fallback_since.is_none()
        };

        // Invariant 3: If not in fallback, source must be Primary
        let source_consistent = if !self.fallback_active {
            matches!(self.current_da_source, DASourceType::Primary)
        } else {
            true // Any source is valid when in fallback
        };

        since_consistent && source_consistent
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

    // ════════════════════════════════════════════════════════════════════════════
    // M. REPLICA STATUS ENUM TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_replica_status_variants() {
        // Verify all variants exist and are distinct
        let pending = ReplicaStatus::Pending;
        let stored = ReplicaStatus::Stored;
        let verified = ReplicaStatus::Verified;
        let missing = ReplicaStatus::Missing;
        let corrupted = ReplicaStatus::Corrupted;

        assert_ne!(pending, stored);
        assert_ne!(stored, verified);
        assert_ne!(verified, missing);
        assert_ne!(missing, corrupted);
        assert_ne!(corrupted, pending);
    }

    #[test]
    fn test_replica_status_clone() {
        let status = ReplicaStatus::Stored;
        let cloned = status.clone();
        assert_eq!(status, cloned);
    }

    #[test]
    fn test_replica_status_copy() {
        let status = ReplicaStatus::Verified;
        let copied = status; // Copy, not move
        assert_eq!(status, copied);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // N. STATUS LIFECYCLE TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_status_pending_on_replica_added() {
        let mut state = NodeDerivedState::new();
        let event = make_replica_added(1, TEST_CHUNK, TEST_NODE, 0);

        state.apply_event(&event, TEST_NODE).unwrap();

        // Status should be Pending after ReplicaAdded
        assert_eq!(
            state.get_replica_status(TEST_CHUNK),
            Some(ReplicaStatus::Pending)
        );
    }

    #[test]
    fn test_status_pending_to_stored() {
        let mut state = NodeDerivedState::new();
        let event = make_replica_added(1, TEST_CHUNK, TEST_NODE, 0);
        state.apply_event(&event, TEST_NODE).unwrap();

        // Update to Stored
        state.update_replica_status(TEST_CHUNK, ReplicaStatus::Stored);

        assert_eq!(
            state.get_replica_status(TEST_CHUNK),
            Some(ReplicaStatus::Stored)
        );
    }

    #[test]
    fn test_status_stored_to_verified() {
        let mut state = NodeDerivedState::new();
        let event = make_replica_added(1, TEST_CHUNK, TEST_NODE, 0);
        state.apply_event(&event, TEST_NODE).unwrap();

        state.update_replica_status(TEST_CHUNK, ReplicaStatus::Stored);
        state.update_replica_status(TEST_CHUNK, ReplicaStatus::Verified);

        assert_eq!(
            state.get_replica_status(TEST_CHUNK),
            Some(ReplicaStatus::Verified)
        );
    }

    #[test]
    fn test_status_pending_to_missing() {
        let mut state = NodeDerivedState::new();
        let event = make_replica_added(1, TEST_CHUNK, TEST_NODE, 0);
        state.apply_event(&event, TEST_NODE).unwrap();

        // Chunk not found locally
        state.update_replica_status(TEST_CHUNK, ReplicaStatus::Missing);

        assert_eq!(
            state.get_replica_status(TEST_CHUNK),
            Some(ReplicaStatus::Missing)
        );
    }

    #[test]
    fn test_status_stored_to_corrupted() {
        let mut state = NodeDerivedState::new();
        let event = make_replica_added(1, TEST_CHUNK, TEST_NODE, 0);
        state.apply_event(&event, TEST_NODE).unwrap();

        state.update_replica_status(TEST_CHUNK, ReplicaStatus::Stored);
        // Verification failed
        state.update_replica_status(TEST_CHUNK, ReplicaStatus::Corrupted);

        assert_eq!(
            state.get_replica_status(TEST_CHUNK),
            Some(ReplicaStatus::Corrupted)
        );
    }

    // ════════════════════════════════════════════════════════════════════════════
    // O. UPDATE_REPLICA_STATUS SAFETY TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_update_status_unknown_hash_no_panic() {
        let mut state = NodeDerivedState::new();

        // Should not panic, should be NO-OP
        state.update_replica_status("unknown-hash", ReplicaStatus::Stored);

        // Should not create orphan status
        assert!(state.get_replica_status("unknown-hash").is_none());
        assert!(state.replica_status.is_empty());
    }

    #[test]
    fn test_update_status_after_removal_no_effect() {
        let mut state = NodeDerivedState::new();

        // Add then remove
        let add_event = make_replica_added(1, TEST_CHUNK, TEST_NODE, 0);
        state.apply_event(&add_event, TEST_NODE).unwrap();

        let remove_event = make_replica_removed(2, TEST_CHUNK, TEST_NODE);
        state.apply_event(&remove_event, TEST_NODE).unwrap();

        // Try to update status - should be NO-OP
        state.update_replica_status(TEST_CHUNK, ReplicaStatus::Stored);

        // Status should not exist
        assert!(state.get_replica_status(TEST_CHUNK).is_none());
    }

    #[test]
    fn test_status_removed_on_replica_removed() {
        let mut state = NodeDerivedState::new();

        let event = make_replica_added(1, TEST_CHUNK, TEST_NODE, 0);
        state.apply_event(&event, TEST_NODE).unwrap();
        assert!(state.get_replica_status(TEST_CHUNK).is_some());

        let remove_event = make_replica_removed(2, TEST_CHUNK, TEST_NODE);
        state.apply_event(&remove_event, TEST_NODE).unwrap();

        // Status should be removed
        assert!(state.get_replica_status(TEST_CHUNK).is_none());
    }

    #[test]
    fn test_status_removed_on_chunk_removed() {
        let mut state = NodeDerivedState::new();

        let event = make_replica_added(1, TEST_CHUNK, TEST_NODE, 0);
        state.apply_event(&event, TEST_NODE).unwrap();
        assert!(state.get_replica_status(TEST_CHUNK).is_some());

        let chunk_removed = make_chunk_removed(2, TEST_CHUNK);
        state.apply_event(&chunk_removed, TEST_NODE).unwrap();

        // Status should be removed
        assert!(state.get_replica_status(TEST_CHUNK).is_none());
    }

    // ════════════════════════════════════════════════════════════════════════════
    // P. GET_PENDING_REPLICAS TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_get_pending_replicas_empty() {
        let state = NodeDerivedState::new();
        assert!(state.get_pending_replicas().is_empty());
    }

    #[test]
    fn test_get_pending_replicas_only_pending() {
        let mut state = NodeDerivedState::new();

        // Add three chunks
        let event1 = make_replica_added(1, "chunk-1", TEST_NODE, 0);
        let event2 = make_replica_added(2, "chunk-2", TEST_NODE, 1);
        let event3 = make_replica_added(3, "chunk-3", TEST_NODE, 2);

        state.apply_event(&event1, TEST_NODE).unwrap();
        state.apply_event(&event2, TEST_NODE).unwrap();
        state.apply_event(&event3, TEST_NODE).unwrap();

        // Update some to non-Pending
        state.update_replica_status("chunk-2", ReplicaStatus::Stored);
        state.update_replica_status("chunk-3", ReplicaStatus::Verified);

        // Only chunk-1 should be pending
        let pending = state.get_pending_replicas();
        assert_eq!(pending.len(), 1);
        assert!(pending.contains(&"chunk-1".to_string()));
    }

    #[test]
    fn test_get_pending_replicas_excludes_other_status() {
        let mut state = NodeDerivedState::new();

        let event = make_replica_added(1, TEST_CHUNK, TEST_NODE, 0);
        state.apply_event(&event, TEST_NODE).unwrap();

        // Start with Pending
        assert_eq!(state.get_pending_replicas().len(), 1);

        // Change to Stored
        state.update_replica_status(TEST_CHUNK, ReplicaStatus::Stored);
        assert!(state.get_pending_replicas().is_empty());

        // Change to Missing
        state.update_replica_status(TEST_CHUNK, ReplicaStatus::Missing);
        assert!(state.get_pending_replicas().is_empty());

        // Change to Corrupted
        state.update_replica_status(TEST_CHUNK, ReplicaStatus::Corrupted);
        assert!(state.get_pending_replicas().is_empty());

        // Change to Verified
        state.update_replica_status(TEST_CHUNK, ReplicaStatus::Verified);
        assert!(state.get_pending_replicas().is_empty());
    }

    // ════════════════════════════════════════════════════════════════════════════
    // Q. GET_MISSING_REPLICAS TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_get_missing_replicas_empty() {
        let state = NodeDerivedState::new();
        assert!(state.get_missing_replicas().is_empty());
    }

    #[test]
    fn test_get_missing_replicas_only_missing() {
        let mut state = NodeDerivedState::new();

        // Add three chunks
        let event1 = make_replica_added(1, "chunk-1", TEST_NODE, 0);
        let event2 = make_replica_added(2, "chunk-2", TEST_NODE, 1);
        let event3 = make_replica_added(3, "chunk-3", TEST_NODE, 2);

        state.apply_event(&event1, TEST_NODE).unwrap();
        state.apply_event(&event2, TEST_NODE).unwrap();
        state.apply_event(&event3, TEST_NODE).unwrap();

        // Mark some as Missing
        state.update_replica_status("chunk-1", ReplicaStatus::Missing);
        state.update_replica_status("chunk-3", ReplicaStatus::Missing);
        // chunk-2 stays Pending

        // Should return chunk-1 and chunk-3
        let missing = state.get_missing_replicas();
        assert_eq!(missing.len(), 2);
        assert!(missing.contains(&"chunk-1".to_string()));
        assert!(missing.contains(&"chunk-3".to_string()));
        assert!(!missing.contains(&"chunk-2".to_string()));
    }

    #[test]
    fn test_get_missing_replicas_excludes_other_status() {
        let mut state = NodeDerivedState::new();

        let event = make_replica_added(1, TEST_CHUNK, TEST_NODE, 0);
        state.apply_event(&event, TEST_NODE).unwrap();

        // Start with Pending - not missing
        assert!(state.get_missing_replicas().is_empty());

        // Change to Stored - not missing
        state.update_replica_status(TEST_CHUNK, ReplicaStatus::Stored);
        assert!(state.get_missing_replicas().is_empty());

        // Change to Missing - IS missing
        state.update_replica_status(TEST_CHUNK, ReplicaStatus::Missing);
        assert_eq!(state.get_missing_replicas().len(), 1);

        // Change to Corrupted - not missing
        state.update_replica_status(TEST_CHUNK, ReplicaStatus::Corrupted);
        assert!(state.get_missing_replicas().is_empty());
    }

    // ════════════════════════════════════════════════════════════════════════════
    // R. IDEMPOTENCY TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_update_status_same_status_idempotent() {
        let mut state = NodeDerivedState::new();

        let event = make_replica_added(1, TEST_CHUNK, TEST_NODE, 0);
        state.apply_event(&event, TEST_NODE).unwrap();

        // Update to Stored twice
        state.update_replica_status(TEST_CHUNK, ReplicaStatus::Stored);
        state.update_replica_status(TEST_CHUNK, ReplicaStatus::Stored);

        // Should still be Stored
        assert_eq!(
            state.get_replica_status(TEST_CHUNK),
            Some(ReplicaStatus::Stored)
        );
    }

    #[test]
    fn test_replica_added_idempotent_preserves_status() {
        let mut state = NodeDerivedState::new();

        let event = make_replica_added(1, TEST_CHUNK, TEST_NODE, 0);
        state.apply_event(&event, TEST_NODE).unwrap();

        // Update status to Stored
        state.update_replica_status(TEST_CHUNK, ReplicaStatus::Stored);

        // Try to add again (idempotent)
        state.apply_event(&event, TEST_NODE).unwrap();

        // Status should still be Stored (not reset to Pending)
        assert_eq!(
            state.get_replica_status(TEST_CHUNK),
            Some(ReplicaStatus::Stored)
        );
    }

    // ════════════════════════════════════════════════════════════════════════════
    // S. DETERMINISM TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_status_deterministic() {
        let mut state1 = NodeDerivedState::new();
        let mut state2 = NodeDerivedState::new();

        // Apply same events
        let event1 = make_replica_added(1, "chunk-1", TEST_NODE, 0);
        let event2 = make_replica_added(2, "chunk-2", TEST_NODE, 1);

        state1.apply_event(&event1, TEST_NODE).unwrap();
        state1.apply_event(&event2, TEST_NODE).unwrap();
        state1.update_replica_status("chunk-1", ReplicaStatus::Stored);

        state2.apply_event(&event1, TEST_NODE).unwrap();
        state2.apply_event(&event2, TEST_NODE).unwrap();
        state2.update_replica_status("chunk-1", ReplicaStatus::Stored);

        // States should be identical
        assert_eq!(state1.get_replica_status("chunk-1"), state2.get_replica_status("chunk-1"));
        assert_eq!(state1.get_replica_status("chunk-2"), state2.get_replica_status("chunk-2"));
    }

    // ════════════════════════════════════════════════════════════════════════════
    // T. FALLBACK STATE FIELDS TESTS (14A.1A.46)
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_fallback_fields_initial_state() {
        let state = NodeDerivedState::new();

        // Verify all fallback fields are initialized correctly
        assert!(!state.fallback_active);
        assert!(state.fallback_since.is_none());
        assert_eq!(state.current_da_source, DASourceType::Primary);
        assert_eq!(state.events_from_fallback, 0);
        assert!(state.last_reconciliation_sequence.is_none());

        // Invariants should hold
        assert!(state.validate_fallback_invariants());
    }

    #[test]
    fn test_activate_fallback_from_primary() {
        let mut state = NodeDerivedState::new();

        // Activate fallback to Secondary
        state.activate_fallback(1000, DASourceType::Secondary);

        assert!(state.fallback_active);
        assert_eq!(state.fallback_since, Some(1000));
        assert_eq!(state.current_da_source, DASourceType::Secondary);

        // Invariants should hold
        assert!(state.validate_fallback_invariants());
    }

    #[test]
    fn test_activate_fallback_to_emergency() {
        let mut state = NodeDerivedState::new();

        // Activate fallback directly to Emergency
        state.activate_fallback(2000, DASourceType::Emergency);

        assert!(state.fallback_active);
        assert_eq!(state.fallback_since, Some(2000));
        assert_eq!(state.current_da_source, DASourceType::Emergency);

        // Invariants should hold
        assert!(state.validate_fallback_invariants());
    }

    #[test]
    fn test_activate_fallback_secondary_to_emergency() {
        let mut state = NodeDerivedState::new();

        // First activate to Secondary
        state.activate_fallback(1000, DASourceType::Secondary);
        assert_eq!(state.fallback_since, Some(1000));

        // Then switch to Emergency (should preserve original timestamp)
        state.activate_fallback(2000, DASourceType::Emergency);

        assert!(state.fallback_active);
        assert_eq!(state.fallback_since, Some(1000)); // Original timestamp preserved
        assert_eq!(state.current_da_source, DASourceType::Emergency); // Source updated

        // Invariants should hold
        assert!(state.validate_fallback_invariants());
    }

    #[test]
    fn test_deactivate_fallback() {
        let mut state = NodeDerivedState::new();

        // Activate fallback
        state.activate_fallback(1000, DASourceType::Secondary);
        assert!(state.fallback_active);

        // Deactivate
        state.deactivate_fallback();

        assert!(!state.fallback_active);
        assert!(state.fallback_since.is_none());
        assert_eq!(state.current_da_source, DASourceType::Primary);

        // Invariants should hold
        assert!(state.validate_fallback_invariants());
    }

    #[test]
    fn test_deactivate_fallback_idempotent() {
        let mut state = NodeDerivedState::new();

        // Deactivate when already inactive (idempotent)
        state.deactivate_fallback();

        assert!(!state.fallback_active);
        assert!(state.fallback_since.is_none());
        assert_eq!(state.current_da_source, DASourceType::Primary);

        // Invariants should hold
        assert!(state.validate_fallback_invariants());
    }

    #[test]
    fn test_record_fallback_event() {
        let mut state = NodeDerivedState::new();

        assert_eq!(state.events_from_fallback, 0);

        state.record_fallback_event();
        assert_eq!(state.events_from_fallback, 1);

        state.record_fallback_event();
        assert_eq!(state.events_from_fallback, 2);

        state.record_fallback_event();
        assert_eq!(state.events_from_fallback, 3);
    }

    #[test]
    fn test_record_fallback_event_saturating() {
        let mut state = NodeDerivedState::new();

        // Set to max - 1
        state.events_from_fallback = u64::MAX - 1;

        state.record_fallback_event();
        assert_eq!(state.events_from_fallback, u64::MAX);

        // Should saturate, not overflow
        state.record_fallback_event();
        assert_eq!(state.events_from_fallback, u64::MAX);
    }

    #[test]
    fn test_record_reconciliation() {
        let mut state = NodeDerivedState::new();

        assert!(state.last_reconciliation_sequence.is_none());

        state.record_reconciliation(100);
        assert_eq!(state.last_reconciliation_sequence, Some(100));

        // Can update to new value
        state.record_reconciliation(200);
        assert_eq!(state.last_reconciliation_sequence, Some(200));
    }

    #[test]
    fn test_is_fallback_active() {
        let mut state = NodeDerivedState::new();

        assert!(!state.is_fallback_active());

        state.activate_fallback(1000, DASourceType::Secondary);
        assert!(state.is_fallback_active());

        state.deactivate_fallback();
        assert!(!state.is_fallback_active());
    }

    #[test]
    fn test_get_fallback_duration() {
        let mut state = NodeDerivedState::new();

        // No duration when not in fallback
        assert!(state.get_fallback_duration(2000).is_none());

        // Activate fallback at timestamp 1000
        state.activate_fallback(1000, DASourceType::Secondary);

        // Duration at timestamp 1500 should be 500
        assert_eq!(state.get_fallback_duration(1500), Some(500));

        // Duration at timestamp 2000 should be 1000
        assert_eq!(state.get_fallback_duration(2000), Some(1000));

        // Duration at same timestamp should be 0
        assert_eq!(state.get_fallback_duration(1000), Some(0));
    }

    #[test]
    fn test_get_fallback_duration_saturating() {
        let mut state = NodeDerivedState::new();

        // Activate at high timestamp
        state.activate_fallback(1000, DASourceType::Secondary);

        // Query with lower timestamp (should saturate to 0, not underflow)
        assert_eq!(state.get_fallback_duration(500), Some(0));
    }

    #[test]
    fn test_validate_fallback_invariants_valid() {
        let mut state = NodeDerivedState::new();

        // Initial state should be valid
        assert!(state.validate_fallback_invariants());

        // After activation should be valid
        state.activate_fallback(1000, DASourceType::Secondary);
        assert!(state.validate_fallback_invariants());

        // After deactivation should be valid
        state.deactivate_fallback();
        assert!(state.validate_fallback_invariants());
    }

    #[test]
    fn test_validate_fallback_invariants_invalid_since_without_active() {
        let mut state = NodeDerivedState::new();

        // Manually create invalid state (should not happen in normal code)
        state.fallback_active = false;
        state.fallback_since = Some(1000); // Invalid: since without active

        assert!(!state.validate_fallback_invariants());
    }

    #[test]
    fn test_validate_fallback_invariants_invalid_active_without_since() {
        let mut state = NodeDerivedState::new();

        // Manually create invalid state (should not happen in normal code)
        state.fallback_active = true;
        state.fallback_since = None; // Invalid: active without since

        assert!(!state.validate_fallback_invariants());
    }

    #[test]
    fn test_validate_fallback_invariants_invalid_source_when_inactive() {
        let mut state = NodeDerivedState::new();

        // Manually create invalid state (should not happen in normal code)
        state.fallback_active = false;
        state.fallback_since = None;
        state.current_da_source = DASourceType::Secondary; // Invalid: non-primary when inactive

        assert!(!state.validate_fallback_invariants());
    }

    #[test]
    fn test_fallback_full_cycle() {
        let mut state = NodeDerivedState::new();

        // Initial state
        assert!(state.validate_fallback_invariants());
        assert!(!state.is_fallback_active());
        assert_eq!(state.events_from_fallback, 0);

        // Activate fallback
        state.activate_fallback(1000, DASourceType::Secondary);
        assert!(state.validate_fallback_invariants());
        assert!(state.is_fallback_active());

        // Record some events
        state.record_fallback_event();
        state.record_fallback_event();
        assert_eq!(state.events_from_fallback, 2);

        // Switch to Emergency
        state.activate_fallback(2000, DASourceType::Emergency);
        assert!(state.validate_fallback_invariants());
        assert_eq!(state.current_da_source, DASourceType::Emergency);
        assert_eq!(state.fallback_since, Some(1000)); // Original timestamp

        // Record more events
        state.record_fallback_event();
        assert_eq!(state.events_from_fallback, 3);

        // Record reconciliation
        state.record_reconciliation(500);
        assert_eq!(state.last_reconciliation_sequence, Some(500));

        // Deactivate fallback
        state.deactivate_fallback();
        assert!(state.validate_fallback_invariants());
        assert!(!state.is_fallback_active());
        assert_eq!(state.current_da_source, DASourceType::Primary);

        // Events count preserved
        assert_eq!(state.events_from_fallback, 3);
        // Reconciliation sequence preserved
        assert_eq!(state.last_reconciliation_sequence, Some(500));
    }

    #[test]
    fn test_fallback_fields_with_debug_format() {
        let mut state = NodeDerivedState::new();
        state.activate_fallback(1000, DASourceType::Secondary);
        state.record_fallback_event();
        state.record_reconciliation(100);

        // Debug format should include all fields
        let debug_str = format!("{:?}", state);
        assert!(debug_str.contains("fallback_active"));
        assert!(debug_str.contains("fallback_since"));
        assert!(debug_str.contains("current_da_source"));
        assert!(debug_str.contains("events_from_fallback"));
        assert!(debug_str.contains("last_reconciliation_sequence"));
    }
}