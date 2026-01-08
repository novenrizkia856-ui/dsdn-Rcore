//! Delete Handler Module
//!
//! This module provides safe handling of delete requests from DA events.
//!
//! ## Core Principles
//!
//! - **Pointer Removal Only**: Delete in DSDN means pointer removal, not physical deletion
//! - **DA Immutability**: Data in DA remains immutable
//! - **Grace Period**: Deletions are delayed by a configurable grace period
//! - **No Physical Deletion**: This handler only marks for deletion; GC executes later
//!
//! ## Delete Flow
//!
//! ```text
//! DeleteRequestedEvent → Validate Grace Period → Mark Pending → (GC later)
//! ```
//!
//! ## Safety Guarantees
//!
//! - Never deletes data physically
//! - Always respects grace period
//! - Deletion is auditable
//! - Deletion can be implicitly canceled (grace period)

use std::sync::Arc;

use parking_lot::RwLock;
use thiserror::Error;

use crate::da_follower::NodeDerivedState;

// ════════════════════════════════════════════════════════════════════════════
// DELETE ERROR
// ════════════════════════════════════════════════════════════════════════════

/// Errors that can occur during delete request processing.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum DeleteError {
    /// The delete request event is malformed.
    #[error("Malformed delete request: {0}")]
    MalformedRequest(String),

    /// Storage operation failed.
    #[error("Storage error: {0}")]
    StorageError(String),
}

// ════════════════════════════════════════════════════════════════════════════
// DELETE REQUESTED EVENT
// ════════════════════════════════════════════════════════════════════════════

/// Event representing a delete request from DA.
///
/// This event signals that a chunk should be marked for deletion
/// after the grace period expires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteRequestedEvent {
    /// Hash of the chunk to delete.
    pub chunk_hash: String,
    /// Timestamp when the delete was requested (milliseconds).
    pub requested_at: u64,
    /// Grace period in milliseconds before deletion is allowed.
    pub grace_period_ms: u64,
}

// ════════════════════════════════════════════════════════════════════════════
// PENDING DELETE
// ════════════════════════════════════════════════════════════════════════════

/// A pending delete request awaiting grace period expiration.
///
/// This struct tracks delete requests that have been received but
/// not yet executed by the garbage collector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingDelete {
    /// Hash of the chunk pending deletion.
    pub chunk_hash: String,
    /// Timestamp when deletion was requested (milliseconds).
    pub requested_at: u64,
    /// Timestamp after which deletion is allowed (milliseconds).
    /// Calculated as: requested_at + grace_period_ms
    pub delete_after: u64,
}

impl PendingDelete {
    /// Create a new PendingDelete from a delete request event.
    pub fn from_event(event: &DeleteRequestedEvent) -> Self {
        Self {
            chunk_hash: event.chunk_hash.clone(),
            requested_at: event.requested_at,
            delete_after: event.requested_at.saturating_add(event.grace_period_ms),
        }
    }

    /// Check if the delete is ready to be executed.
    ///
    /// # Arguments
    ///
    /// * `current_time_ms` - Current timestamp in milliseconds
    ///
    /// # Returns
    ///
    /// `true` if current_time_ms >= delete_after
    pub fn is_ready(&self, current_time_ms: u64) -> bool {
        current_time_ms >= self.delete_after
    }
}

// ════════════════════════════════════════════════════════════════════════════
// STORAGE TRAIT
// ════════════════════════════════════════════════════════════════════════════

/// Abstraction for local storage operations.
///
/// This trait provides the interface for storage operations needed
/// by the delete handler. It does NOT include physical deletion methods
/// as those are handled by the garbage collector.
pub trait Storage: Send + Sync {
    /// Check if a chunk exists in local storage.
    fn has_chunk(&self, chunk_hash: &str) -> bool;

    /// Mark a chunk for deletion with timing information.
    ///
    /// This does NOT physically delete the data. It only marks the chunk
    /// so that the garbage collector knows to delete it later.
    ///
    /// # Arguments
    ///
    /// * `chunk_hash` - Hash of the chunk to mark
    /// * `requested_at` - When the deletion was requested
    /// * `delete_after` - When deletion is allowed (after grace period)
    fn mark_for_deletion(
        &self,
        chunk_hash: &str,
        requested_at: u64,
        delete_after: u64,
    ) -> Result<(), String>;

    /// Check if a chunk is marked for deletion.
    fn is_marked_for_deletion(&self, chunk_hash: &str) -> bool;

    /// Get all pending delete requests from storage.
    ///
    /// Returns tuples of (chunk_hash, requested_at, delete_after).
    fn get_pending_deletes(&self) -> Vec<(String, u64, u64)>;

    /// Remove a pending delete entry (after GC execution).
    fn remove_pending_delete(&self, chunk_hash: &str) -> bool;
}

// ════════════════════════════════════════════════════════════════════════════
// DELETE HANDLER
// ════════════════════════════════════════════════════════════════════════════

/// Handler for delete requests from DA events.
///
/// `DeleteHandler` processes delete requests safely, ensuring:
///
/// - Grace period is always respected
/// - No physical deletion occurs (only marking)
/// - All delete requests are tracked as pending
/// - GC is responsible for actual deletion
///
/// ## Design Principles
///
/// - **No Physical Deletion**: Never deletes data directly
/// - **Grace Period Enforcement**: Always waits for grace period
/// - **Deterministic**: Same events → Same pending state
/// - **Safe**: Never panics
pub struct DeleteHandler {
    /// Reference to node's derived state.
    state: Arc<RwLock<NodeDerivedState>>,
    /// Reference to storage abstraction.
    storage: Arc<dyn Storage>,
}

impl DeleteHandler {
    /// Create a new DeleteHandler.
    ///
    /// # Arguments
    ///
    /// * `state` - Reference to node's derived state
    /// * `storage` - Reference to storage abstraction
    pub fn new(state: Arc<RwLock<NodeDerivedState>>, storage: Arc<dyn Storage>) -> Self {
        Self { state, storage }
    }

    /// Process a delete request event.
    ///
    /// This method handles a delete request by:
    ///
    /// 1. Calculating delete_after timestamp
    /// 2. Checking if this node stores the chunk
    /// 3. Recording the request as pending
    /// 4. Marking the chunk for deletion (if stored)
    ///
    /// # Arguments
    ///
    /// * `event` - The delete request event from DA
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Request processed successfully
    /// * `Err(DeleteError)` - Processing failed
    ///
    /// # Guarantees
    ///
    /// - NEVER deletes data physically
    /// - ALWAYS respects grace period
    /// - NO-OP if node doesn't store the chunk
    /// - Never panics
    pub fn process_delete_request(&self, event: &DeleteRequestedEvent) -> Result<(), DeleteError> {
        // Step 1: Calculate delete_after with grace period
        let delete_after = event.requested_at.saturating_add(event.grace_period_ms);

        // Step 2: Check if this node stores the chunk
        let state_guard = self.state.read();
        let stores_chunk = state_guard.my_chunks.contains_key(&event.chunk_hash);
        drop(state_guard);

        // Step 3: If node doesn't store the chunk, NO-OP (not an error)
        if !stores_chunk {
            return Ok(());
        }

        // Step 4: Mark chunk for deletion in storage (does NOT physically delete)
        // This also records the pending delete information
        self.storage
            .mark_for_deletion(&event.chunk_hash, event.requested_at, delete_after)
            .map_err(DeleteError::StorageError)?;

        Ok(())
    }

    /// Get all pending delete requests.
    ///
    /// Returns all delete requests that have been received but not yet
    /// executed by the garbage collector.
    ///
    /// # Returns
    ///
    /// Vector of all pending deletes. Order is not guaranteed.
    ///
    /// # Guarantees
    ///
    /// - Deterministic (same state → same result, modulo ordering)
    /// - Never panics
    pub fn get_pending_deletes(&self) -> Vec<PendingDelete> {
        self.storage
            .get_pending_deletes()
            .into_iter()
            .map(|(chunk_hash, requested_at, delete_after)| PendingDelete {
                chunk_hash,
                requested_at,
                delete_after,
            })
            .collect()
    }

    /// Get pending deletes that are ready for execution.
    ///
    /// Returns delete requests where current_time_ms >= delete_after.
    ///
    /// # Arguments
    ///
    /// * `current_time_ms` - Current timestamp in milliseconds
    ///
    /// # Returns
    ///
    /// Vector of pending deletes ready for GC execution.
    pub fn get_ready_deletes(&self, current_time_ms: u64) -> Vec<PendingDelete> {
        self.get_pending_deletes()
            .into_iter()
            .filter(|pd| pd.is_ready(current_time_ms))
            .collect()
    }

    /// Get pending deletes that are NOT yet ready for execution.
    ///
    /// Returns delete requests where current_time_ms < delete_after.
    ///
    /// # Arguments
    ///
    /// * `current_time_ms` - Current timestamp in milliseconds
    ///
    /// # Returns
    ///
    /// Vector of pending deletes still in grace period.
    pub fn get_pending_in_grace_period(&self, current_time_ms: u64) -> Vec<PendingDelete> {
        self.get_pending_deletes()
            .into_iter()
            .filter(|pd| !pd.is_ready(current_time_ms))
            .collect()
    }

    /// Remove a pending delete after GC execution.
    ///
    /// Called by garbage collector after successful deletion.
    ///
    /// # Arguments
    ///
    /// * `chunk_hash` - Hash of the deleted chunk
    ///
    /// # Returns
    ///
    /// `true` if the pending delete was removed, `false` if not found.
    pub fn acknowledge_deletion(&self, chunk_hash: &str) -> bool {
        self.storage.remove_pending_delete(chunk_hash)
    }

    /// Check if a chunk has a pending delete request.
    pub fn has_pending_delete(&self, chunk_hash: &str) -> bool {
        self.storage.is_marked_for_deletion(chunk_hash)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, Ordering};

    const TEST_CHUNK: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const CHUNK_A: &str = "chunk-a-hash";
    const CHUNK_B: &str = "chunk-b-hash";

    // ════════════════════════════════════════════════════════════════════════
    // MOCK STORAGE
    // ════════════════════════════════════════════════════════════════════════

    struct MockStorage {
        chunks: RwLock<std::collections::HashSet<String>>,
        pending_deletes: RwLock<HashMap<String, (u64, u64)>>, // hash -> (requested_at, delete_after)
        fail_mark: AtomicBool,
    }

    impl MockStorage {
        fn new() -> Self {
            Self {
                chunks: RwLock::new(std::collections::HashSet::new()),
                pending_deletes: RwLock::new(HashMap::new()),
                fail_mark: AtomicBool::new(false),
            }
        }

        fn add_chunk(&self, hash: &str) {
            self.chunks.write().insert(hash.to_string());
        }

        fn set_fail_mark(&self, fail: bool) {
            self.fail_mark.store(fail, Ordering::SeqCst);
        }
    }

    impl Storage for MockStorage {
        fn has_chunk(&self, chunk_hash: &str) -> bool {
            self.chunks.read().contains(chunk_hash)
        }

        fn mark_for_deletion(
            &self,
            chunk_hash: &str,
            requested_at: u64,
            delete_after: u64,
        ) -> Result<(), String> {
            if self.fail_mark.load(Ordering::SeqCst) {
                return Err("Mock storage failure".to_string());
            }
            self.pending_deletes
                .write()
                .insert(chunk_hash.to_string(), (requested_at, delete_after));
            Ok(())
        }

        fn is_marked_for_deletion(&self, chunk_hash: &str) -> bool {
            self.pending_deletes.read().contains_key(chunk_hash)
        }

        fn get_pending_deletes(&self) -> Vec<(String, u64, u64)> {
            self.pending_deletes
                .read()
                .iter()
                .map(|(hash, (req, del))| (hash.clone(), *req, *del))
                .collect()
        }

        fn remove_pending_delete(&self, chunk_hash: &str) -> bool {
            self.pending_deletes.write().remove(chunk_hash).is_some()
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // HELPER FUNCTIONS
    // ════════════════════════════════════════════════════════════════════════

    fn make_state_with_chunk(chunk_hash: &str) -> Arc<RwLock<NodeDerivedState>> {
        use crate::da_follower::ChunkAssignment;

        let mut state = NodeDerivedState::new();
        state.my_chunks.insert(
            chunk_hash.to_string(),
            ChunkAssignment {
                hash: chunk_hash.to_string(),
                replica_index: 0,
                assigned_at: 1000,
                verified: false,
                size_bytes: 1024,
            },
        );
        Arc::new(RwLock::new(state))
    }

    fn make_empty_state() -> Arc<RwLock<NodeDerivedState>> {
        Arc::new(RwLock::new(NodeDerivedState::new()))
    }

    fn make_delete_event(chunk_hash: &str, requested_at: u64, grace_period_ms: u64) -> DeleteRequestedEvent {
        DeleteRequestedEvent {
            chunk_hash: chunk_hash.to_string(),
            requested_at,
            grace_period_ms,
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // A. PENDING DELETE STRUCT TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_pending_delete_from_event() {
        let event = make_delete_event(TEST_CHUNK, 1000, 5000);
        let pending = PendingDelete::from_event(&event);

        assert_eq!(pending.chunk_hash, TEST_CHUNK);
        assert_eq!(pending.requested_at, 1000);
        assert_eq!(pending.delete_after, 6000); // 1000 + 5000
    }

    #[test]
    fn test_pending_delete_delete_after_calculation() {
        // Test various grace periods
        let event1 = make_delete_event(TEST_CHUNK, 0, 1000);
        assert_eq!(PendingDelete::from_event(&event1).delete_after, 1000);

        let event2 = make_delete_event(TEST_CHUNK, 5000, 3000);
        assert_eq!(PendingDelete::from_event(&event2).delete_after, 8000);

        // Test overflow protection
        let event3 = make_delete_event(TEST_CHUNK, u64::MAX - 100, 200);
        assert_eq!(PendingDelete::from_event(&event3).delete_after, u64::MAX);
    }

    #[test]
    fn test_pending_delete_is_ready() {
        let event = make_delete_event(TEST_CHUNK, 1000, 5000);
        let pending = PendingDelete::from_event(&event);

        // Before grace period
        assert!(!pending.is_ready(0));
        assert!(!pending.is_ready(1000));
        assert!(!pending.is_ready(5999));

        // At grace period end
        assert!(pending.is_ready(6000));

        // After grace period
        assert!(pending.is_ready(6001));
        assert!(pending.is_ready(10000));
    }

    #[test]
    fn test_pending_delete_clone() {
        let event = make_delete_event(TEST_CHUNK, 1000, 5000);
        let pending = PendingDelete::from_event(&event);
        let cloned = pending.clone();

        assert_eq!(pending, cloned);
    }

    // ════════════════════════════════════════════════════════════════════════
    // B. GRACE PERIOD ENFORCEMENT TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_grace_period_before_expiry() {
        let state = make_state_with_chunk(TEST_CHUNK);
        let storage = Arc::new(MockStorage::new());
        storage.add_chunk(TEST_CHUNK);
        let handler = DeleteHandler::new(state, storage.clone());

        let event = make_delete_event(TEST_CHUNK, 1000, 5000);
        handler.process_delete_request(&event).unwrap();

        // Pending should be recorded
        let pending = handler.get_pending_deletes();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].requested_at, 1000);
        assert_eq!(pending[0].delete_after, 6000);

        // Before grace period, should NOT be ready
        assert!(handler.get_ready_deletes(5999).is_empty());
        assert_eq!(handler.get_pending_in_grace_period(5999).len(), 1);
    }

    #[test]
    fn test_grace_period_after_expiry() {
        let state = make_state_with_chunk(TEST_CHUNK);
        let storage = Arc::new(MockStorage::new());
        storage.add_chunk(TEST_CHUNK);
        let handler = DeleteHandler::new(state, storage.clone());

        let event = make_delete_event(TEST_CHUNK, 1000, 5000);
        handler.process_delete_request(&event).unwrap();

        // After grace period, should be ready
        assert_eq!(handler.get_ready_deletes(6000).len(), 1);
        assert!(handler.get_pending_in_grace_period(6000).is_empty());
    }

    #[test]
    fn test_grace_period_exact_boundary() {
        let state = make_state_with_chunk(TEST_CHUNK);
        let storage = Arc::new(MockStorage::new());
        storage.add_chunk(TEST_CHUNK);
        let handler = DeleteHandler::new(state, storage.clone());

        let event = make_delete_event(TEST_CHUNK, 1000, 5000);
        handler.process_delete_request(&event).unwrap();

        // At exact boundary (6000), should be ready
        let ready = handler.get_ready_deletes(6000);
        assert_eq!(ready.len(), 1);
        assert!(ready[0].is_ready(6000));
    }

    // ════════════════════════════════════════════════════════════════════════
    // C. NODE DOES NOT STORE CHUNK TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_delete_request_node_not_storing() {
        let state = make_empty_state(); // No chunks in state
        let storage = Arc::new(MockStorage::new());
        let handler = DeleteHandler::new(state, storage.clone());

        let event = make_delete_event(TEST_CHUNK, 1000, 5000);
        let result = handler.process_delete_request(&event);

        // Should succeed (NO-OP, not error)
        assert!(result.is_ok());

        // Should NOT be recorded as pending (node doesn't store it)
        assert!(!handler.has_pending_delete(TEST_CHUNK));
        assert!(handler.get_pending_deletes().is_empty());
    }

    #[test]
    fn test_delete_request_different_chunk() {
        let state = make_state_with_chunk(CHUNK_A); // Has CHUNK_A in state
        let storage = Arc::new(MockStorage::new());
        storage.add_chunk(CHUNK_A);
        let handler = DeleteHandler::new(state, storage.clone());

        // Request delete for CHUNK_B (not in state)
        let event = make_delete_event(CHUNK_B, 1000, 5000);
        let result = handler.process_delete_request(&event);

        // Should succeed (NO-OP)
        assert!(result.is_ok());

        // CHUNK_A should NOT be affected
        assert!(!storage.is_marked_for_deletion(CHUNK_A));
        // CHUNK_B should NOT be marked (not in state)
        assert!(!storage.is_marked_for_deletion(CHUNK_B));
    }

    // ════════════════════════════════════════════════════════════════════════
    // D. STORAGE MARKING TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_chunk_marked_for_deletion() {
        let state = make_state_with_chunk(TEST_CHUNK);
        let storage = Arc::new(MockStorage::new());
        storage.add_chunk(TEST_CHUNK);
        let handler = DeleteHandler::new(state, storage.clone());

        let event = make_delete_event(TEST_CHUNK, 1000, 5000);
        handler.process_delete_request(&event).unwrap();

        // Storage should be marked
        assert!(storage.is_marked_for_deletion(TEST_CHUNK));
    }

    #[test]
    fn test_storage_error_propagates() {
        let state = make_state_with_chunk(TEST_CHUNK);
        let storage = Arc::new(MockStorage::new());
        storage.add_chunk(TEST_CHUNK);
        storage.set_fail_mark(true);
        let handler = DeleteHandler::new(state, storage);

        let event = make_delete_event(TEST_CHUNK, 1000, 5000);
        let result = handler.process_delete_request(&event);

        assert!(matches!(result, Err(DeleteError::StorageError(_))));
    }

    // ════════════════════════════════════════════════════════════════════════
    // E. GET_PENDING_DELETES TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_get_pending_deletes_empty() {
        let state = make_empty_state();
        let storage = Arc::new(MockStorage::new());
        let handler = DeleteHandler::new(state, storage);

        assert!(handler.get_pending_deletes().is_empty());
    }

    #[test]
    fn test_get_pending_deletes_multiple() {
        let mut state_inner = NodeDerivedState::new();
        state_inner.my_chunks.insert(
            CHUNK_A.to_string(),
            crate::da_follower::ChunkAssignment {
                hash: CHUNK_A.to_string(),
                replica_index: 0,
                assigned_at: 1000,
                verified: false,
                size_bytes: 1024,
            },
        );
        state_inner.my_chunks.insert(
            CHUNK_B.to_string(),
            crate::da_follower::ChunkAssignment {
                hash: CHUNK_B.to_string(),
                replica_index: 1,
                assigned_at: 2000,
                verified: false,
                size_bytes: 2048,
            },
        );
        let state = Arc::new(RwLock::new(state_inner));

        let storage = Arc::new(MockStorage::new());
        storage.add_chunk(CHUNK_A);
        storage.add_chunk(CHUNK_B);
        let handler = DeleteHandler::new(state, storage);

        let event_a = make_delete_event(CHUNK_A, 1000, 5000);
        let event_b = make_delete_event(CHUNK_B, 2000, 3000);

        handler.process_delete_request(&event_a).unwrap();
        handler.process_delete_request(&event_b).unwrap();

        let pending = handler.get_pending_deletes();
        assert_eq!(pending.len(), 2);

        // Verify both are present
        let hashes: std::collections::HashSet<_> = pending.iter().map(|p| p.chunk_hash.as_str()).collect();
        assert!(hashes.contains(CHUNK_A));
        assert!(hashes.contains(CHUNK_B));
    }

    #[test]
    fn test_get_pending_deletes_correct_timestamps() {
        let state = make_state_with_chunk(TEST_CHUNK);
        let storage = Arc::new(MockStorage::new());
        storage.add_chunk(TEST_CHUNK);
        let handler = DeleteHandler::new(state, storage);

        let event = make_delete_event(TEST_CHUNK, 12345, 67890);
        handler.process_delete_request(&event).unwrap();

        let pending = handler.get_pending_deletes();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].requested_at, 12345);
        assert_eq!(pending[0].delete_after, 12345 + 67890);
    }

    // ════════════════════════════════════════════════════════════════════════
    // F. ACKNOWLEDGE DELETION TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_acknowledge_deletion() {
        let state = make_state_with_chunk(TEST_CHUNK);
        let storage = Arc::new(MockStorage::new());
        storage.add_chunk(TEST_CHUNK);
        let handler = DeleteHandler::new(state, storage);

        let event = make_delete_event(TEST_CHUNK, 1000, 5000);
        handler.process_delete_request(&event).unwrap();

        assert!(handler.has_pending_delete(TEST_CHUNK));

        // Acknowledge
        let removed = handler.acknowledge_deletion(TEST_CHUNK);
        assert!(removed);

        // Should be gone
        assert!(!handler.has_pending_delete(TEST_CHUNK));
    }

    #[test]
    fn test_acknowledge_deletion_not_found() {
        let state = make_empty_state();
        let storage = Arc::new(MockStorage::new());
        let handler = DeleteHandler::new(state, storage);

        let removed = handler.acknowledge_deletion("nonexistent");
        assert!(!removed);
    }

    // ════════════════════════════════════════════════════════════════════════
    // G. DETERMINISM TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_deterministic_same_event() {
        let state1 = make_state_with_chunk(TEST_CHUNK);
        let state2 = make_state_with_chunk(TEST_CHUNK);
        let storage1 = Arc::new(MockStorage::new());
        let storage2 = Arc::new(MockStorage::new());
        storage1.add_chunk(TEST_CHUNK);
        storage2.add_chunk(TEST_CHUNK);

        let handler1 = DeleteHandler::new(state1, storage1);
        let handler2 = DeleteHandler::new(state2, storage2);

        let event = make_delete_event(TEST_CHUNK, 1000, 5000);

        handler1.process_delete_request(&event).unwrap();
        handler2.process_delete_request(&event).unwrap();

        let pending1 = handler1.get_pending_deletes();
        let pending2 = handler2.get_pending_deletes();

        assert_eq!(pending1.len(), 1);
        assert_eq!(pending2.len(), 1);
        assert_eq!(pending1[0].requested_at, pending2[0].requested_at);
        assert_eq!(pending1[0].delete_after, pending2[0].delete_after);
    }

    #[test]
    fn test_idempotent_same_request() {
        let state = make_state_with_chunk(TEST_CHUNK);
        let storage = Arc::new(MockStorage::new());
        storage.add_chunk(TEST_CHUNK);
        let handler = DeleteHandler::new(state, storage);

        let event = make_delete_event(TEST_CHUNK, 1000, 5000);

        // Process twice
        handler.process_delete_request(&event).unwrap();
        handler.process_delete_request(&event).unwrap();

        // Should only have one pending (HashMap overwrites)
        let pending = handler.get_pending_deletes();
        assert_eq!(pending.len(), 1);
    }

    // ════════════════════════════════════════════════════════════════════════
    // H. SAFETY TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_no_panic_empty_hash() {
        let state = make_empty_state();
        let storage = Arc::new(MockStorage::new());
        let handler = DeleteHandler::new(state, storage);

        let event = make_delete_event("", 1000, 5000);
        let result = handler.process_delete_request(&event);

        // Should not panic
        assert!(result.is_ok());
    }

    #[test]
    fn test_no_panic_zero_grace_period() {
        let state = make_state_with_chunk(TEST_CHUNK);
        let storage = Arc::new(MockStorage::new());
        storage.add_chunk(TEST_CHUNK);
        let handler = DeleteHandler::new(state, storage);

        let event = make_delete_event(TEST_CHUNK, 1000, 0);
        let result = handler.process_delete_request(&event);

        // Should not panic, immediately ready
        assert!(result.is_ok());
        let ready = handler.get_ready_deletes(1000);
        assert_eq!(ready.len(), 1);
    }

    #[test]
    fn test_no_panic_large_values() {
        let state = make_state_with_chunk(TEST_CHUNK);
        let storage = Arc::new(MockStorage::new());
        storage.add_chunk(TEST_CHUNK);
        let handler = DeleteHandler::new(state, storage);

        let event = make_delete_event(TEST_CHUNK, u64::MAX - 1000, 500);
        let result = handler.process_delete_request(&event);

        // Should not panic
        assert!(result.is_ok());
    }

    // ════════════════════════════════════════════════════════════════════════
    // I. DELETE ERROR TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_delete_error_display() {
        let err = DeleteError::MalformedRequest("test".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Malformed"));

        let err2 = DeleteError::StorageError("test".to_string());
        let display2 = format!("{}", err2);
        assert!(display2.contains("Storage"));
    }

    #[test]
    fn test_delete_error_clone() {
        let err = DeleteError::StorageError("test".to_string());
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    // ════════════════════════════════════════════════════════════════════════
    // J. DELETE REQUESTED EVENT TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_delete_requested_event_clone() {
        let event = make_delete_event(TEST_CHUNK, 1000, 5000);
        let cloned = event.clone();
        assert_eq!(event, cloned);
    }

    // ════════════════════════════════════════════════════════════════════════
    // K. DELETE HANDLER STRUCT TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_delete_handler_new() {
        let state = make_empty_state();
        let storage = Arc::new(MockStorage::new());
        let handler = DeleteHandler::new(state, storage);

        // Should start empty
        assert!(handler.get_pending_deletes().is_empty());
    }
}