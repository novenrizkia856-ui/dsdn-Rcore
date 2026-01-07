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
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::sync::Arc;

use futures::StreamExt;
use parking_lot::RwLock;
use tracing::{debug, warn};

use dsdn_common::da::{DALayer, DAError, BlobStream};

use crate::NodeInfo;

// ════════════════════════════════════════════════════════════════════════════
// FORWARD-COMPATIBLE TYPE DEFINITIONS
// ════════════════════════════════════════════════════════════════════════════

/// Metadata for a stored chunk.
///
/// This struct represents the authoritative metadata for a chunk as declared
/// on the DA layer. It is the primary identity for data in the storage network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkMeta {
    /// Content hash of the chunk (hex-encoded, primary identifier)
    pub hash: String,
    /// Size of the chunk in bytes
    pub size_bytes: u64,
    /// Target replication factor (desired number of replicas)
    pub replication_factor: u8,
    /// ID of the uploader who declared the chunk
    pub uploader_id: String,
    /// Timestamp when the chunk was declared (from DA event)
    pub declared_at: u64,
    /// DA layer commitment (32 bytes, e.g., Celestia blob commitment)
    pub da_commitment: [u8; 32],
    /// Current replication factor (derived field, initially 0)
    pub current_rf: u8,
}

/// Information about a replica of a chunk.
///
/// Tracks where replicas are stored and their status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicaInfo {
    /// Node ID where replica is stored
    pub node_id: String,
    /// Replica index (unique per chunk)
    pub replica_index: u8,
    /// Timestamp when replica was added (from DA event)
    pub added_at: u64,
    /// Whether replica has been verified
    pub verified: bool,
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
/// - `last_processed`: Arc<AtomicU64> for lock-free reads and sharing with background task
/// - `subscription`: Only accessed by consumer task
pub struct DAConsumer {
    /// Reference to the DA layer implementation
    da: Arc<dyn DALayer>,
    /// Derived state built from DA events
    state: Arc<RwLock<DADerivedState>>,
    /// Height of the last processed blob (shareable with background task)
    last_processed: Arc<AtomicU64>,
    /// Active subscription stream (if any)
    subscription: Option<BlobStream>,
    /// Shutdown signal for background task
    shutdown: Arc<AtomicBool>,
    /// Flag indicating if consumer is running
    running: Arc<AtomicBool>,
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
            last_processed: Arc::new(AtomicU64::new(0)),
            subscription: None,
            shutdown: Arc::new(AtomicBool::new(false)),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Start the DA consumer subscription.
    ///
    /// Subscribes to the DA layer blob stream and spawns a background task
    /// to process incoming events.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Consumer started successfully
    /// * `Err(DAError)` - Failed to start subscription
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Consumer is already running
    /// - DA layer subscription fails
    ///
    /// # Note
    ///
    /// This method is idempotent - calling it when already running returns an error.
    pub async fn start(&mut self) -> Result<(), DAError> {
        // Check if already running - prevent double spawn
        if self.running.load(Ordering::SeqCst) {
            return Err(DAError::Other("Consumer already running".to_string()));
        }

        // Reset shutdown flag
        self.shutdown.store(false, Ordering::SeqCst);

        // Subscribe to DA layer
        debug!("Starting DA consumer subscription");
        let stream = self.da.subscribe_blobs(None).await?;

        // Mark as running
        self.running.store(true, Ordering::SeqCst);

        // Clone shared state for background task
        let state = Arc::clone(&self.state);
        let shutdown = Arc::clone(&self.shutdown);
        let running = Arc::clone(&self.running);
        let last_processed = Arc::clone(&self.last_processed);

        // Spawn background task
        tokio::spawn(async move {
            Self::background_task(stream, state, shutdown, running, last_processed).await;
        });

        debug!("DA consumer started successfully");
        Ok(())
    }

    /// Background task for processing blob events.
    ///
    /// Runs until shutdown signal or stream ends.
    async fn background_task(
        mut stream: BlobStream,
        state: Arc<RwLock<DADerivedState>>,
        shutdown: Arc<AtomicBool>,
        running: Arc<AtomicBool>,
        last_processed: Arc<AtomicU64>,
    ) {
        debug!("Background task started");

        loop {
            // Check shutdown signal
            if shutdown.load(Ordering::SeqCst) {
                debug!("Shutdown signal received, stopping background task");
                break;
            }

            // Poll stream with timeout to allow checking shutdown
            let poll_result = tokio::time::timeout(
                std::time::Duration::from_millis(100),
                stream.next(),
            )
            .await;

            match poll_result {
                Ok(Some(Ok(blob))) => {
                    // Successfully received a blob
                    let height = blob.ref_.height;
                    debug!(height, "Received blob from DA layer");

                    // Update last_processed atomically
                    last_processed.store(height, Ordering::SeqCst);

                    // Update state sequence (minimal processing per spec)
                    {
                        let mut state_guard = state.write();
                        state_guard.sequence = height;
                        state_guard.last_updated = Self::current_time_ms();
                    }
                }
                Ok(Some(Err(e))) => {
                    // Stream yielded an error
                    warn!(error = %e, "Error from DA stream");
                    // Continue processing - don't terminate on transient errors
                }
                Ok(None) => {
                    // Stream ended
                    debug!("DA stream ended");
                    break;
                }
                Err(_) => {
                    // Timeout - continue loop to check shutdown
                    continue;
                }
            }
        }

        // Mark as not running
        running.store(false, Ordering::SeqCst);
        debug!("Background task stopped");
    }

    /// Get current time in milliseconds.
    fn current_time_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    /// Stop the DA consumer gracefully.
    ///
    /// Signals the background task to stop and cleans up resources.
    /// This method is idempotent - safe to call multiple times.
    ///
    /// # Behavior
    ///
    /// - Sets shutdown signal for background task
    /// - Clears subscription reference
    /// - Syncs sequence from state to last_processed atomic
    /// - Does NOT panic
    pub fn stop(&mut self) {
        debug!("Stopping DA consumer");

        // Signal shutdown
        self.shutdown.store(true, Ordering::SeqCst);

        // Clear subscription
        self.subscription = None;

        // Sync sequence from state to atomic last_processed
        {
            let state_guard = self.state.read();
            self.last_processed.store(state_guard.sequence, Ordering::SeqCst);
        }

        // Note: running flag will be set to false by the background task
        // We don't force it here to allow graceful completion

        debug!("DA consumer stop signal sent");
    }

    /// Get the last processed sequence number.
    ///
    /// Returns the sequence number of the most recently processed blob.
    /// This value is read atomically without locking state.
    ///
    /// # Returns
    ///
    /// The last processed sequence number (0 if no events processed yet).
    pub fn get_last_processed_sequence(&self) -> u64 {
        self.last_processed.load(Ordering::SeqCst)
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
        self.last_processed.load(Ordering::SeqCst)
    }

    /// Check if subscription is active.
    ///
    /// Returns true if the consumer is currently running.
    pub fn is_subscribed(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Check if consumer is running.
    ///
    /// Returns true if background task is active.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use dsdn_common::MockDA;

    // ════════════════════════════════════════════════════════════════════════
    // A. BASIC STRUCTURE TESTS
    // ════════════════════════════════════════════════════════════════════════

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
        assert!(!consumer.is_running());
        assert_eq!(consumer.get_last_processed_sequence(), 0);

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
            size_bytes: 1024,
            replication_factor: 3,
            uploader_id: "user1".to_string(),
            declared_at: 1234567890,
            da_commitment: [0u8; 32],
            current_rf: 0,
        };

        assert_eq!(meta.hash, "abc123");
        assert_eq!(meta.size_bytes, 1024);
        assert_eq!(meta.replication_factor, 3);
        assert_eq!(meta.uploader_id, "user1");
        assert_eq!(meta.declared_at, 1234567890);
        assert_eq!(meta.da_commitment, [0u8; 32]);
        assert_eq!(meta.current_rf, 0);
    }

    #[test]
    fn test_replica_info_creation() {
        let replica = ReplicaInfo {
            node_id: "node1".to_string(),
            replica_index: 0,
            added_at: 1234567890,
            verified: true,
        };

        assert_eq!(replica.node_id, "node1");
        assert_eq!(replica.replica_index, 0);
        assert_eq!(replica.added_at, 1234567890);
        assert!(replica.verified);
    }

    // ════════════════════════════════════════════════════════════════════════
    // B. START() TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_start_returns_error_via_trait() {
        // NOTE: subscribe_blobs via dyn DALayer returns error due to lifetime constraints
        // This test verifies that error is properly propagated
        let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
        let mut consumer = DAConsumer::new(da);

        let result = consumer.start().await;

        // Expected to fail because subscribe_blobs via trait returns error
        assert!(result.is_err());
        assert!(!consumer.is_running());
    }

    #[tokio::test]
    async fn test_start_no_panic() {
        let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
        let mut consumer = DAConsumer::new(da);

        // Should not panic regardless of result
        let _ = consumer.start().await;
    }

    // ════════════════════════════════════════════════════════════════════════
    // C. STOP() TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_stop_without_start() {
        let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
        let mut consumer = DAConsumer::new(da);

        // stop() should be safe to call even without start()
        consumer.stop();

        // Should not panic and should remain in stopped state
        assert!(!consumer.is_running());
    }

    #[test]
    fn test_stop_idempotent() {
        let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
        let mut consumer = DAConsumer::new(da);

        // Multiple stop() calls should be safe
        consumer.stop();
        consumer.stop();
        consumer.stop();

        // Should not panic
        assert!(!consumer.is_running());
    }

    #[tokio::test]
    async fn test_stop_after_failed_start() {
        let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
        let mut consumer = DAConsumer::new(da);

        // Start fails (expected with MockDA via trait)
        let _ = consumer.start().await;

        // Stop should still be safe
        consumer.stop();

        assert!(!consumer.is_running());
    }

    // ════════════════════════════════════════════════════════════════════════
    // D. LAST_PROCESSED_SEQUENCE TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_last_processed_sequence_initial() {
        let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
        let consumer = DAConsumer::new(da);

        assert_eq!(consumer.get_last_processed_sequence(), 0);
    }

    #[test]
    fn test_last_processed_sequence_after_stop() {
        let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
        let mut consumer = DAConsumer::new(da);

        // Manually set state sequence to simulate processing
        {
            let mut state = consumer.state.write();
            state.sequence = 42;
        }

        // Stop should sync to atomic
        consumer.stop();

        assert_eq!(consumer.get_last_processed_sequence(), 42);
    }

    #[test]
    fn test_last_processed_direct_atomic_update() {
        let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
        let consumer = DAConsumer::new(da);

        // Directly update the atomic (simulating background task behavior)
        consumer.last_processed.store(100, Ordering::SeqCst);

        assert_eq!(consumer.get_last_processed_sequence(), 100);
    }

    #[test]
    fn test_last_processed_sequence_no_lock() {
        let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
        let consumer = DAConsumer::new(da);

        // Should be able to read while holding state lock
        let _state_guard = consumer.state.read();
        let seq = consumer.get_last_processed_sequence();
        
        // Should not deadlock
        assert_eq!(seq, 0);
    }

    // ════════════════════════════════════════════════════════════════════════
    // E. ERROR HANDLING TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_error_handling_no_panic() {
        let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
        let mut consumer = DAConsumer::new(da);

        // Multiple operations that might fail - none should panic
        for _ in 0..5 {
            let _ = consumer.start().await;
            consumer.stop();
        }

        // Should complete without panic
        assert!(!consumer.is_running());
    }

    #[tokio::test]
    async fn test_consumer_remains_usable_after_error() {
        let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
        let mut consumer = DAConsumer::new(da);

        // Start fails
        let _ = consumer.start().await;

        // Consumer should still be usable
        assert_eq!(consumer.get_last_processed_sequence(), 0);
        
        let state = consumer.state();
        let state_guard = state.read();
        assert_eq!(state_guard.sequence, 0);
    }

    // ════════════════════════════════════════════════════════════════════════
    // F. CONCURRENT ACCESS TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_concurrent_sequence_reads() {
        // Create consumer and extract shareable atomic
        let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
        let consumer = DAConsumer::new(da);
        
        // Get the shared last_processed atomic
        let last_processed = Arc::clone(&consumer.last_processed);

        let mut handles = Vec::new();

        // Spawn multiple readers on the shared atomic
        for _ in 0..10 {
            let lp = Arc::clone(&last_processed);
            handles.push(std::thread::spawn(move || {
                for _ in 0..100 {
                    let _ = lp.load(Ordering::SeqCst);
                }
            }));
        }

        // All should complete without panic
        for handle in handles {
            handle.join().expect("thread should not panic");
        }

        // Verify consumer still works after concurrent reads
        assert_eq!(consumer.get_last_processed_sequence(), 0);
    }

    #[test]
    fn test_concurrent_state_access() {
        // Create consumer and extract shareable state
        let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
        let consumer = DAConsumer::new(da);
        
        // Get the shared state
        let state = consumer.state();

        let mut handles = Vec::new();

        // Spawn readers on the shared state
        for _ in 0..5 {
            let s = Arc::clone(&state);
            handles.push(std::thread::spawn(move || {
                for _ in 0..50 {
                    let _guard = s.read();
                }
            }));
        }

        // All should complete without deadlock
        for handle in handles {
            handle.join().expect("thread should not panic");
        }

        // Verify state is still accessible
        let binding = consumer.state();
        let state_guard = binding.read();
        assert_eq!(state_guard.sequence, 0);
    }
}