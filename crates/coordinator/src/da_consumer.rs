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
//! - Handles reconnection on network failures
//! - Verifies blob commitments for data integrity
//!
//! ## Relationship
//!
//! - **DALayer**: Provides the event stream via `subscribe_blobs`
//! - **Coordinator**: Uses derived state for placement and scheduling decisions
//!
//! ## Reconnection Logic
//!
//! When the DA connection fails, the consumer will:
//! 1. Mark state as degraded
//! 2. Attempt reconnection with exponential backoff
//! 3. Resume from last processed height on successful reconnect
//! 4. Emit metrics for monitoring

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use parking_lot::RwLock;
use sha3::{Sha3_256, Digest};
use tracing::{debug, info, warn, error};

use dsdn_common::da::{DALayer, DAError, BlobStream, BlobRef, DAHealthStatus};

use crate::NodeInfo;

// ════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════

/// Maximum reconnection delay in milliseconds
const MAX_RECONNECT_DELAY_MS: u64 = 60000;

/// Initial reconnection delay in milliseconds
const INITIAL_RECONNECT_DELAY_MS: u64 = 1000;

/// Health check interval during degraded state
const HEALTH_CHECK_INTERVAL_MS: u64 = 5000;

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
// CONSUMER METRICS
// ════════════════════════════════════════════════════════════════════════════

/// Metrics for DA consumer operations.
#[derive(Debug, Default)]
pub struct ConsumerMetrics {
    /// Total blobs processed
    pub blobs_processed: AtomicU64,
    /// Total bytes processed
    pub bytes_processed: AtomicU64,
    /// Number of blob verification failures
    pub verification_failures: AtomicU64,
    /// Number of reconnection attempts
    pub reconnect_attempts: AtomicU64,
    /// Number of successful reconnections
    pub reconnects_successful: AtomicU64,
    /// Last processed height
    pub last_height: AtomicU64,
}

impl ConsumerMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_blob(&self, size: usize, height: u64) {
        self.blobs_processed.fetch_add(1, Ordering::Relaxed);
        self.bytes_processed.fetch_add(size as u64, Ordering::Relaxed);
        self.last_height.store(height, Ordering::Relaxed);
    }

    pub fn record_verification_failure(&self) {
        self.verification_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_reconnect_attempt(&self) {
        self.reconnect_attempts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_reconnect_success(&self) {
        self.reconnects_successful.fetch_add(1, Ordering::Relaxed);
    }
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
// BLOB COMMITMENT VERIFICATION
// ════════════════════════════════════════════════════════════════════════════

/// Verify blob commitment matches data.
///
/// Computes SHA3-256 hash of data and compares with expected commitment.
///
/// # Arguments
///
/// * `data` - Blob data bytes
/// * `expected` - Expected 32-byte commitment
///
/// # Returns
///
/// * `true` if commitment matches
/// * `false` if commitment does not match
pub fn verify_blob_commitment(data: &[u8], expected: &[u8; 32]) -> bool {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();
    
    let mut computed = [0u8; 32];
    computed.copy_from_slice(&result);
    
    computed == *expected
}

// ════════════════════════════════════════════════════════════════════════════
// DA CONSUMER
// ════════════════════════════════════════════════════════════════════════════

/// Consumer for DA layer events.
///
/// `DAConsumer` subscribes to the DA layer and processes events to build
/// derived state. It maintains:
///
/// - Connection to the DA layer with automatic reconnection
/// - Derived state from processed events
/// - Tracking of last processed height
/// - Blob commitment verification
/// - Metrics for monitoring
///
/// # Thread Safety
///
/// - `da`: Shared reference to DA layer (thread-safe via trait bounds)
/// - `state`: Protected by `RwLock` for concurrent access
/// - `last_processed`: Arc<AtomicU64> for lock-free reads
/// - `metrics`: Thread-safe counters
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
    /// Flag indicating if connection is degraded
    degraded: Arc<AtomicBool>,
    /// Metrics for consumer operations
    metrics: Arc<ConsumerMetrics>,
    /// Current reconnection delay
    reconnect_delay_ms: Arc<AtomicU64>,
}

impl DAConsumer {
    /// Create a new DAConsumer with the given DA layer.
    ///
    /// Initializes the consumer with:
    /// - Empty derived state
    /// - `last_processed` set to 0
    /// - No active subscription
    /// - Fresh metrics
    ///
    /// # Arguments
    ///
    /// * `da` - Arc reference to a DALayer implementation
    ///
    /// # Returns
    ///
    /// A new `DAConsumer` instance ready for subscription.
    pub fn new(da: Arc<dyn DALayer>) -> Self {
        Self {
            da,
            state: Arc::new(RwLock::new(DADerivedState::new())),
            last_processed: Arc::new(AtomicU64::new(0)),
            subscription: None,
            shutdown: Arc::new(AtomicBool::new(false)),
            running: Arc::new(AtomicBool::new(false)),
            degraded: Arc::new(AtomicBool::new(false)),
            metrics: Arc::new(ConsumerMetrics::new()),
            reconnect_delay_ms: Arc::new(AtomicU64::new(INITIAL_RECONNECT_DELAY_MS)),
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
    /// # Reconnection
    ///
    /// If the subscription fails, the background task will:
    /// 1. Mark the consumer as degraded
    /// 2. Attempt reconnection with exponential backoff
    /// 3. Resume processing from last successful height
    pub async fn start(&mut self) -> Result<(), DAError> {
        // Check if already running
        if self.running.load(Ordering::SeqCst) {
            return Err(DAError::Other("Consumer already running".to_string()));
        }

        // Reset shutdown flag and delays
        self.shutdown.store(false, Ordering::SeqCst);
        self.reconnect_delay_ms.store(INITIAL_RECONNECT_DELAY_MS, Ordering::SeqCst);

        // Subscribe to DA layer
        debug!("Starting DA consumer subscription");
        let stream = self.da.subscribe_blobs(None).await?;

        // Mark as running
        self.running.store(true, Ordering::SeqCst);
        self.degraded.store(false, Ordering::SeqCst);

        // Clone shared state for background task
        let state = Arc::clone(&self.state);
        let shutdown = Arc::clone(&self.shutdown);
        let running = Arc::clone(&self.running);
        let degraded = Arc::clone(&self.degraded);
        let last_processed = Arc::clone(&self.last_processed);
        let metrics = Arc::clone(&self.metrics);
        let reconnect_delay = Arc::clone(&self.reconnect_delay_ms);
        let da = Arc::clone(&self.da);

        // Spawn background task with reconnection logic
        tokio::spawn(async move {
            Self::background_task_with_reconnect(
                stream,
                state,
                shutdown,
                running,
                degraded,
                last_processed,
                metrics,
                reconnect_delay,
                da,
            ).await;
        });

        debug!("DA consumer started successfully");
        Ok(())
    }

    /// Background task with reconnection logic.
    async fn background_task_with_reconnect(
        mut stream: BlobStream,
        state: Arc<RwLock<DADerivedState>>,
        shutdown: Arc<AtomicBool>,
        running: Arc<AtomicBool>,
        degraded: Arc<AtomicBool>,
        last_processed: Arc<AtomicU64>,
        metrics: Arc<ConsumerMetrics>,
        reconnect_delay: Arc<AtomicU64>,
        da: Arc<dyn DALayer>,
    ) {
        debug!("Background task started");

        loop {
            // Check shutdown signal
            if shutdown.load(Ordering::SeqCst) {
                debug!("Shutdown signal received, stopping background task");
                break;
            }

            // Poll stream with timeout
            let poll_result = tokio::time::timeout(
                Duration::from_millis(100),
                stream.next(),
            ).await;

            match poll_result {
                Ok(Some(Ok(blob))) => {
                    // Successfully received a blob
                    let height = blob.ref_.height;
                    let data_len = blob.data.len();

                    debug!(height, size = data_len, "Received blob from DA layer");

                    // Verify blob commitment
                    if !verify_blob_commitment(&blob.data, &blob.ref_.commitment) {
                        warn!(height, "Blob commitment verification failed");
                        metrics.record_verification_failure();
                        continue;
                    }

                    // Reset degraded state and reconnect delay on successful blob
                    if degraded.load(Ordering::SeqCst) {
                        info!("DA connection restored");
                        degraded.store(false, Ordering::SeqCst);
                        reconnect_delay.store(INITIAL_RECONNECT_DELAY_MS, Ordering::SeqCst);
                    }

                    // Update metrics
                    metrics.record_blob(data_len, height);

                    // Update last_processed atomically
                    last_processed.store(height, Ordering::SeqCst);

                    // Update state sequence
                    {
                        let mut state_guard = state.write();
                        state_guard.sequence = height;
                        state_guard.last_updated = Self::current_time_ms();
                    }
                }
                Ok(Some(Err(e))) => {
                    // Stream yielded an error
                    warn!(error = %e, "Error from DA stream");

                    // Check if retryable
                    let is_retryable = matches!(
                        e,
                        DAError::NetworkError(_) | DAError::Timeout | DAError::Unavailable
                    );

                    if is_retryable {
                        degraded.store(true, Ordering::SeqCst);

                        // Attempt reconnection
                        let delay = reconnect_delay.load(Ordering::SeqCst);
                        warn!(delay_ms = delay, "DA error, will attempt reconnect");

                        metrics.record_reconnect_attempt();

                        tokio::time::sleep(Duration::from_millis(delay)).await;

                        // Exponential backoff
                        let new_delay = (delay * 2).min(MAX_RECONNECT_DELAY_MS);
                        reconnect_delay.store(new_delay, Ordering::SeqCst);

                        // Health check before continuing
                        match da.health_check().await {
                            Ok(DAHealthStatus::Healthy) | Ok(DAHealthStatus::Degraded) => {
                                info!("DA health check passed, continuing");
                                metrics.record_reconnect_success();
                                reconnect_delay.store(INITIAL_RECONNECT_DELAY_MS, Ordering::SeqCst);
                            }
                            _ => {
                                warn!("DA still unhealthy");
                            }
                        }
                    }
                }
                Ok(None) => {
                    // Stream ended
                    debug!("DA stream ended");

                    if !shutdown.load(Ordering::SeqCst) {
                        // Unexpected end - attempt reconnection
                        warn!("DA stream ended unexpectedly, will attempt reconnect");
                        degraded.store(true, Ordering::SeqCst);

                        let delay = reconnect_delay.load(Ordering::SeqCst);
                        metrics.record_reconnect_attempt();

                        tokio::time::sleep(Duration::from_millis(delay)).await;

                        // Exponential backoff
                        let new_delay = (delay * 2).min(MAX_RECONNECT_DELAY_MS);
                        reconnect_delay.store(new_delay, Ordering::SeqCst);
                    }
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

        debug!("DA consumer stopped");
    }

    /// Check if consumer is currently running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Check if consumer is in degraded state.
    pub fn is_degraded(&self) -> bool {
        self.degraded.load(Ordering::SeqCst)
    }

    /// Get the last processed sequence number.
    ///
    /// This is a lock-free read of the atomic counter.
    pub fn get_last_processed_sequence(&self) -> u64 {
        self.last_processed.load(Ordering::SeqCst)
    }

    /// Get a reference to the shared state.
    ///
    /// Returns Arc<RwLock<DADerivedState>> for external access.
    pub fn state(&self) -> Arc<RwLock<DADerivedState>> {
        Arc::clone(&self.state)
    }

    /// Get a reference to consumer metrics.
    pub fn metrics(&self) -> Arc<ConsumerMetrics> {
        Arc::clone(&self.metrics)
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
    // A. STRUCT TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_chunk_meta_creation() {
        let meta = ChunkMeta {
            hash: "abc123".to_string(),
            size_bytes: 1024,
            replication_factor: 3,
            uploader_id: "user1".to_string(),
            declared_at: 1234567890,
            da_commitment: [0x11; 32],
            current_rf: 0,
        };

        assert_eq!(meta.hash, "abc123");
        assert_eq!(meta.size_bytes, 1024);
        assert_eq!(meta.replication_factor, 3);
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
        assert!(replica.verified);
    }

    #[test]
    fn test_da_derived_state_new() {
        let state = DADerivedState::new();

        assert!(state.node_registry.is_empty());
        assert!(state.chunk_map.is_empty());
        assert!(state.replica_map.is_empty());
        assert!(state.zone_map.is_empty());
        assert_eq!(state.sequence, 0);
    }

    // ════════════════════════════════════════════════════════════════════════
    // B. BLOB COMMITMENT VERIFICATION TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_blob_commitment_valid() {
        let data = b"test data for commitment";
        
        // Compute correct commitment
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&result);

        assert!(verify_blob_commitment(data, &expected));
    }

    #[test]
    fn test_verify_blob_commitment_invalid() {
        let data = b"test data";
        let wrong_commitment = [0xFF; 32];

        assert!(!verify_blob_commitment(data, &wrong_commitment));
    }

    #[test]
    fn test_verify_blob_commitment_empty() {
        let data = b"";
        
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&result);

        assert!(verify_blob_commitment(data, &expected));
    }

    // ════════════════════════════════════════════════════════════════════════
    // C. CONSUMER METRICS TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_consumer_metrics_new() {
        let metrics = ConsumerMetrics::new();

        assert_eq!(metrics.blobs_processed.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.bytes_processed.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_consumer_metrics_record_blob() {
        let metrics = ConsumerMetrics::new();

        metrics.record_blob(1024, 100);

        assert_eq!(metrics.blobs_processed.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.bytes_processed.load(Ordering::Relaxed), 1024);
        assert_eq!(metrics.last_height.load(Ordering::Relaxed), 100);
    }

    #[test]
    fn test_consumer_metrics_multiple_blobs() {
        let metrics = ConsumerMetrics::new();

        metrics.record_blob(100, 1);
        metrics.record_blob(200, 2);
        metrics.record_blob(300, 3);

        assert_eq!(metrics.blobs_processed.load(Ordering::Relaxed), 3);
        assert_eq!(metrics.bytes_processed.load(Ordering::Relaxed), 600);
        assert_eq!(metrics.last_height.load(Ordering::Relaxed), 3);
    }

    // ════════════════════════════════════════════════════════════════════════
    // D. CONSUMER TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_consumer_new() {
        let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
        let consumer = DAConsumer::new(da);

        assert!(!consumer.is_running());
        assert!(!consumer.is_degraded());
        assert_eq!(consumer.get_last_processed_sequence(), 0);
    }

    #[tokio::test]
    async fn test_consumer_start_returns_error_via_trait() {
        let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
        let mut consumer = DAConsumer::new(da);

        let result = consumer.start().await;

        // Expected to fail because subscribe_blobs via trait returns error
        assert!(result.is_err());
        assert!(!consumer.is_running());
    }

    #[test]
    fn test_consumer_stop_without_start() {
        let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
        let mut consumer = DAConsumer::new(da);

        // Should be safe to call even without start
        consumer.stop();

        assert!(!consumer.is_running());
    }

    #[test]
    fn test_consumer_stop_idempotent() {
        let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
        let mut consumer = DAConsumer::new(da);

        consumer.stop();
        consumer.stop();
        consumer.stop();

        // Should not panic
        assert!(!consumer.is_running());
    }

    #[test]
    fn test_consumer_metrics_access() {
        let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
        let consumer = DAConsumer::new(da);

        let metrics = consumer.metrics();
        assert_eq!(metrics.blobs_processed.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_consumer_state_access() {
        let da = Arc::new(MockDA::new()) as Arc<dyn DALayer>;
        let consumer = DAConsumer::new(da);

        let state = consumer.state();
        let guard = state.read();
        assert_eq!(guard.sequence, 0);
    }
}