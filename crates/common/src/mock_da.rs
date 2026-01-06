//! Mock DA Backend Implementation for Testing
//!
//! This module provides a mock Data Availability layer implementation
//! for testing purposes. MockDA is fully in-memory and does not perform
//! any network calls.
//!
//! # Features
//!
//! - Deterministic behavior for reproducible tests
//! - Configurable latency simulation (async, non-blocking)
//! - Configurable failure rate simulation
//! - Test helpers for blob injection and state clearing
//!
//! # Example
//!
//! ```ignore
//! use dsdn_common::MockDA;
//!
//! let mock_da = MockDA::new();
//! let blob_ref = mock_da.inject_blob(b"test data".to_vec());
//! let data = mock_da.get_blob(&blob_ref).await.unwrap();
//! assert_eq!(data, b"test data");
//! ```

use crate::da::{Blob, BlobRef, BlobStream, DAError, DAHealthStatus};
use rand::Rng;
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::RwLock;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, warn};

// ════════════════════════════════════════════════════════════════════════════
// MOCK DA STRUCT
// ════════════════════════════════════════════════════════════════════════════

/// Mock Data Availability layer for testing.
///
/// MockDA provides a fully in-memory implementation of the DA layer
/// that can be used for unit and integration testing without requiring
/// a running Celestia node.
///
/// # Fields (exact as specified)
///
/// - `blobs`: RwLock<HashMap<BlobRef, Vec<u8>>> - In-memory blob storage
/// - `next_height`: AtomicU64 - Next height counter
/// - `next_index`: AtomicU32 - Next index counter within height
/// - `namespace`: [u8; 29] - Namespace for this instance
/// - `latency_ms`: u64 - Simulated latency in milliseconds
/// - `failure_rate`: f64 - Failure rate (0.0 - 1.0)
pub struct MockDA {
    /// In-memory blob storage: BlobRef -> blob data
    blobs: RwLock<HashMap<BlobRef, Vec<u8>>>,
    /// Next height counter for blob references
    next_height: AtomicU64,
    /// Next index counter within a height
    next_index: AtomicU32,
    /// Namespace for this MockDA instance (29 bytes)
    namespace: [u8; 29],
    /// Simulated latency in milliseconds
    latency_ms: u64,
    /// Failure rate (0.0 - 1.0) for simulating errors
    failure_rate: f64,
}

impl std::fmt::Debug for MockDA {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockDA")
            .field("blobs_count", &self.blobs.read().unwrap().len())
            .field("next_height", &self.next_height.load(Ordering::SeqCst))
            .field("next_index", &self.next_index.load(Ordering::SeqCst))
            .field("namespace", &hex::encode(&self.namespace[..8]))
            .field("latency_ms", &self.latency_ms)
            .field("failure_rate", &self.failure_rate)
            .finish()
    }
}

// ════════════════════════════════════════════════════════════════════════════
// CONSTRUCTORS & BUILDERS
// ════════════════════════════════════════════════════════════════════════════

impl MockDA {
    /// Create a new MockDA instance with default settings.
    ///
    /// Default settings:
    /// - namespace: [0x01; 29] (default test namespace)
    /// - latency_ms: 0 (no simulated latency)
    /// - failure_rate: 0.0 (no simulated failures)
    /// - next_height: 1
    /// - next_index: 0
    ///
    /// # Returns
    ///
    /// A clean MockDA instance with deterministic initial state.
    pub fn new() -> Self {
        Self {
            blobs: RwLock::new(HashMap::new()),
            next_height: AtomicU64::new(1),
            next_index: AtomicU32::new(0),
            namespace: [0x01; 29],
            latency_ms: 0,
            failure_rate: 0.0,
        }
    }

    /// Create a new MockDA instance with specified latency.
    ///
    /// # Arguments
    ///
    /// * `ms` - Latency in milliseconds to simulate on each operation
    ///
    /// # Returns
    ///
    /// A MockDA instance configured with the specified latency.
    /// All other settings are default.
    pub fn with_latency(ms: u64) -> Self {
        Self {
            blobs: RwLock::new(HashMap::new()),
            next_height: AtomicU64::new(1),
            next_index: AtomicU32::new(0),
            namespace: [0x01; 29],
            latency_ms: ms,
            failure_rate: 0.0,
        }
    }

    /// Create a new MockDA instance with specified failure rate.
    ///
    /// # Arguments
    ///
    /// * `rate` - Failure rate between 0.0 (never fail) and 1.0 (always fail)
    ///
    /// # Returns
    ///
    /// A MockDA instance configured with the specified failure rate.
    /// All other settings are default. Invalid rates are clamped to [0.0, 1.0].
    pub fn with_failure_rate(rate: f64) -> Self {
        let clamped_rate = rate.clamp(0.0, 1.0);
        Self {
            blobs: RwLock::new(HashMap::new()),
            next_height: AtomicU64::new(1),
            next_index: AtomicU32::new(0),
            namespace: [0x01; 29],
            latency_ms: 0,
            failure_rate: clamped_rate,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// TESTING HELPERS
// ════════════════════════════════════════════════════════════════════════════

impl MockDA {
    /// Inject a blob directly into the mock storage.
    ///
    /// This is a testing helper that bypasses the normal post_blob flow,
    /// allowing tests to set up specific states without latency/failure simulation.
    ///
    /// # Arguments
    ///
    /// * `data` - The blob data to inject
    ///
    /// # Returns
    ///
    /// A valid BlobRef that can be used to retrieve the blob.
    ///
    /// # Side Effects
    ///
    /// - Increments next_height
    /// - Increments next_index
    /// - Stores blob in internal HashMap
    pub fn inject_blob(&self, data: Vec<u8>) -> BlobRef {
        let height = self.next_height.fetch_add(1, Ordering::SeqCst);
        let _index = self.next_index.fetch_add(1, Ordering::SeqCst);

        // Compute commitment using SHA3-256
        let commitment = Self::compute_commitment(&data);

        let blob_ref = BlobRef {
            height,
            commitment,
            namespace: self.namespace,
        };

        // Store blob
        self.blobs.write().unwrap().insert(blob_ref.clone(), data);

        debug!(
            height,
            commitment = ?hex::encode(&commitment[..8]),
            "MockDA: injected blob"
        );

        blob_ref
    }

    /// Clear all blobs and reset internal state.
    ///
    /// This is a testing helper that resets the MockDA to its initial state.
    ///
    /// # Side Effects
    ///
    /// - All blobs are removed from storage
    /// - next_height is reset to 1
    /// - next_index is reset to 0
    pub fn clear(&self) {
        self.blobs.write().unwrap().clear();
        self.next_height.store(1, Ordering::SeqCst);
        self.next_index.store(0, Ordering::SeqCst);

        debug!("MockDA: cleared all state");
    }

    /// Get the number of stored blobs.
    ///
    /// # Returns
    ///
    /// The count of blobs currently stored in memory.
    pub fn blob_count(&self) -> usize {
        self.blobs.read().unwrap().len()
    }

    /// Compute SHA3-256 commitment for blob data.
    fn compute_commitment(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let result = hasher.finalize();

        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&result);
        commitment
    }

    /// Simulate latency if configured (async, non-blocking).
    async fn simulate_latency(&self) {
        if self.latency_ms > 0 {
            tokio::time::sleep(Duration::from_millis(self.latency_ms)).await;
        }
    }

    /// Check if operation should fail based on failure_rate.
    ///
    /// # Returns
    ///
    /// - `true` if operation should fail
    /// - `false` if operation should succeed
    fn should_fail(&self) -> bool {
        if self.failure_rate <= 0.0 {
            return false;
        }
        if self.failure_rate >= 1.0 {
            return true;
        }
        let mut rng = rand::thread_rng();
        rng.gen::<f64>() < self.failure_rate
    }

    /// Get current timestamp in milliseconds.
    fn current_time_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

// ════════════════════════════════════════════════════════════════════════════
// DA LAYER IMPLEMENTATION
// ════════════════════════════════════════════════════════════════════════════

impl MockDA {
    /// Post a blob to the mock DA layer.
    ///
    /// This method stores the blob in memory and returns a BlobRef.
    /// Simulates latency (async) and failure rate as configured.
    ///
    /// # Arguments
    ///
    /// * `data` - The blob data to store
    ///
    /// # Returns
    ///
    /// * `Ok(BlobRef)` - Reference to the stored blob
    /// * `Err(DAError::Unavailable)` - If simulated failure occurs
    ///
    /// # Behavior
    ///
    /// - Applies simulated latency (non-blocking async sleep)
    /// - Checks failure_rate probabilistically
    /// - Increments height and index counters
    /// - Computes SHA3-256 commitment
    /// - Stores blob in RwLock-protected HashMap
    pub async fn post_blob(&self, data: &[u8]) -> Result<BlobRef, DAError> {
        // Simulate latency (async, non-blocking)
        self.simulate_latency().await;

        // Check for simulated failure
        if self.should_fail() {
            warn!("MockDA: simulated failure on post_blob");
            return Err(DAError::Unavailable);
        }

        let height = self.next_height.fetch_add(1, Ordering::SeqCst);
        let _index = self.next_index.fetch_add(1, Ordering::SeqCst);

        // Compute commitment
        let commitment = Self::compute_commitment(data);

        let blob_ref = BlobRef {
            height,
            commitment,
            namespace: self.namespace,
        };

        // Store blob
        self.blobs
            .write()
            .unwrap()
            .insert(blob_ref.clone(), data.to_vec());

        debug!(
            height,
            commitment = ?hex::encode(&commitment[..8]),
            "MockDA: posted blob"
        );

        Ok(blob_ref)
    }

    /// Get a blob from the mock DA layer.
    ///
    /// # Arguments
    ///
    /// * `ref_` - Reference to the blob to retrieve
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The blob data
    /// * `Err(DAError::BlobNotFound)` - If blob doesn't exist
    /// * `Err(DAError::Unavailable)` - If simulated failure occurs
    ///
    /// # Behavior
    ///
    /// - Applies simulated latency (non-blocking async sleep)
    /// - Checks failure_rate probabilistically
    /// - Retrieves blob from RwLock-protected HashMap
    pub async fn get_blob(&self, ref_: &BlobRef) -> Result<Vec<u8>, DAError> {
        // Simulate latency (async, non-blocking)
        self.simulate_latency().await;

        // Check for simulated failure
        if self.should_fail() {
            warn!("MockDA: simulated failure on get_blob");
            return Err(DAError::Unavailable);
        }

        // Retrieve blob
        let blobs = self.blobs.read().unwrap();
        match blobs.get(ref_) {
            Some(data) => {
                debug!(
                    height = ref_.height,
                    commitment = ?hex::encode(&ref_.commitment[..8]),
                    "MockDA: retrieved blob"
                );
                Ok(data.clone())
            }
            None => {
                debug!(
                    height = ref_.height,
                    commitment = ?hex::encode(&ref_.commitment[..8]),
                    "MockDA: blob not found"
                );
                Err(DAError::BlobNotFound(ref_.clone()))
            }
        }
    }

    /// Subscribe to blobs from the mock DA layer.
    ///
    /// Returns a stream that yields blobs matching the specified namespace
    /// in (height, index) order.
    ///
    /// # Arguments
    ///
    /// * `namespace` - The 29-byte namespace to filter blobs
    ///
    /// # Returns
    ///
    /// A BlobStream that yields blobs matching the namespace in order.
    ///
    /// # Behavior
    ///
    /// - Yields blobs in (height, index) order
    /// - Filters by namespace (exact match)
    /// - Never terminates (keeps polling)
    /// - Respects latency simulation
    pub fn subscribe_blobs(self: &Arc<Self>, namespace: &[u8; 29]) -> BlobStream {
        use futures::stream::unfold;
        use std::collections::HashSet;

        let da = Arc::clone(self);
        let target_namespace = *namespace;

        struct SubscriptionState {
            da: Arc<MockDA>,
            namespace: [u8; 29],
            yielded_refs: HashSet<BlobRef>,
        }

        let initial_state = SubscriptionState {
            da,
            namespace: target_namespace,
            yielded_refs: HashSet::new(),
        };

        Box::pin(unfold(initial_state, |mut state| async move {
            loop {
                // Simulate latency
                state.da.simulate_latency().await;

                // Check for simulated failure
                if state.da.should_fail() {
                    return Some((Err(DAError::Unavailable), state));
                }

                // Get matching blobs in a separate scope to ensure guard is dropped before await
                let matching: Vec<(BlobRef, Vec<u8>)> = {
                    let blobs_guard = state.da.blobs.read().unwrap();
                    let mut result: Vec<(BlobRef, Vec<u8>)> = blobs_guard
                        .iter()
                        .filter(|(ref_, _)| {
                            ref_.namespace == state.namespace && !state.yielded_refs.contains(*ref_)
                        })
                        .map(|(ref_, data)| (ref_.clone(), data.clone()))
                        .collect();
                    // Sort by height for ordering
                    result.sort_by_key(|(ref_, _)| ref_.height);
                    result
                    // blobs_guard is dropped here at end of scope
                };

                if let Some((blob_ref, data)) = matching.first() {
                    state.yielded_refs.insert(blob_ref.clone());

                    // Create Blob with correct structure
                    let blob = Blob {
                        ref_: blob_ref.clone(),
                        data: data.clone(),
                        received_at: MockDA::current_time_ms(),
                    };

                    return Some((Ok(blob), state));
                }

                // No new blobs, wait before next poll
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }))
    }

    /// Perform a health check on the mock DA layer.
    ///
    /// Returns status based on configured failure_rate and latency_ms.
    ///
    /// # Returns
    ///
    /// * `DAHealthStatus::Healthy` - Normal operation (failure_rate = 0, latency <= 500ms)
    /// * `DAHealthStatus::Degraded` - High latency (latency_ms > 500)
    /// * `DAHealthStatus::Unavailable` - Simulated failure (based on failure_rate)
    ///
    /// # Behavior
    ///
    /// - Applies simulated latency (non-blocking)
    /// - Checks failure_rate probabilistically
    /// - Never panics
    pub async fn health_check(&self) -> DAHealthStatus {
        // Simulate latency
        self.simulate_latency().await;

        // Check for simulated failure
        if self.should_fail() {
            warn!("MockDA: simulated failure on health_check");
            return DAHealthStatus::Unavailable;
        }

        // Check for degraded status based on latency
        if self.latency_ms > 500 {
            return DAHealthStatus::Degraded;
        }

        DAHealthStatus::Healthy
    }

    /// Get the namespace for this MockDA instance.
    ///
    /// # Returns
    ///
    /// Reference to the 29-byte namespace.
    pub fn namespace(&self) -> &[u8; 29] {
        &self.namespace
    }

    /// Get the current last height (for testing).
    pub fn last_height(&self) -> u64 {
        self.next_height.load(Ordering::SeqCst).saturating_sub(1)
    }
}

impl Default for MockDA {
    fn default() -> Self {
        Self::new()
    }
}

// ════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    // ════════════════════════════════════════════════════════════════════════
    // A. BASIC DALAYER BEHAVIOR TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_post_blob_get_blob_roundtrip() {
        let mock_da = MockDA::new();
        let test_data = b"hello mock da".to_vec();

        let blob_ref = mock_da.post_blob(&test_data).await.unwrap();
        let retrieved = mock_da.get_blob(&blob_ref).await.unwrap();

        assert_eq!(retrieved, test_data);
    }

    #[tokio::test]
    async fn test_post_blob_returns_valid_ref() {
        let mock_da = MockDA::new();
        let test_data = b"test data".to_vec();

        let blob_ref = mock_da.post_blob(&test_data).await.unwrap();

        assert!(blob_ref.height >= 1);
        assert_eq!(blob_ref.namespace, *mock_da.namespace());
        assert_ne!(blob_ref.commitment, [0u8; 32]);
    }

    #[tokio::test]
    async fn test_namespace_consistency() {
        let mock_da = MockDA::new();
        let blob_ref = mock_da.post_blob(b"test").await.unwrap();

        assert_eq!(blob_ref.namespace, *mock_da.namespace());
    }

    #[tokio::test]
    async fn test_blob_not_found() {
        let mock_da = MockDA::new();

        let fake_ref = BlobRef {
            height: 999,
            commitment: [0xFF; 32],
            namespace: *mock_da.namespace(),
        };

        let result = mock_da.get_blob(&fake_ref).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DAError::BlobNotFound(_)));
    }

    #[tokio::test]
    async fn test_multiple_blobs() {
        let mock_da = MockDA::new();

        let data1 = b"blob one".to_vec();
        let data2 = b"blob two".to_vec();
        let data3 = b"blob three".to_vec();

        let ref1 = mock_da.post_blob(&data1).await.unwrap();
        let ref2 = mock_da.post_blob(&data2).await.unwrap();
        let ref3 = mock_da.post_blob(&data3).await.unwrap();

        // Each should have unique height
        assert_ne!(ref1.height, ref2.height);
        assert_ne!(ref2.height, ref3.height);

        // All should be retrievable
        assert_eq!(mock_da.get_blob(&ref1).await.unwrap(), data1);
        assert_eq!(mock_da.get_blob(&ref2).await.unwrap(), data2);
        assert_eq!(mock_da.get_blob(&ref3).await.unwrap(), data3);
    }

    #[tokio::test]
    async fn test_commitment_deterministic() {
        let data = b"test data";
        let c1 = MockDA::compute_commitment(data);
        let c2 = MockDA::compute_commitment(data);

        assert_eq!(c1, c2);
    }

    #[tokio::test]
    async fn test_commitment_different_for_different_data() {
        let c1 = MockDA::compute_commitment(b"data1");
        let c2 = MockDA::compute_commitment(b"data2");

        assert_ne!(c1, c2);
    }

    // ════════════════════════════════════════════════════════════════════════
    // B. FAILURE SIMULATION TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_failure_rate_always_fail() {
        let mock_da = MockDA::with_failure_rate(1.0);

        // Should always fail
        for _ in 0..10 {
            let result = mock_da.post_blob(b"test").await;
            assert!(result.is_err());
            assert!(matches!(result.unwrap_err(), DAError::Unavailable));
        }
    }

    #[tokio::test]
    async fn test_failure_rate_never_fail() {
        let mock_da = MockDA::with_failure_rate(0.0);

        // Should never fail
        for _ in 0..10 {
            let result = mock_da.post_blob(b"test").await;
            assert!(result.is_ok());
        }
    }

    #[tokio::test]
    async fn test_failure_rate_get_blob_always_fail() {
        let mock_da = MockDA::with_failure_rate(1.0);

        // Create a blob ref manually and insert it
        let data = b"test".to_vec();
        let blob_ref = BlobRef {
            height: 1,
            commitment: MockDA::compute_commitment(&data),
            namespace: *mock_da.namespace(),
        };
        mock_da.blobs.write().unwrap().insert(blob_ref.clone(), data);

        // get_blob should fail due to failure_rate
        let result = mock_da.get_blob(&blob_ref).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DAError::Unavailable));
    }

    #[tokio::test]
    async fn test_failure_rate_clamped() {
        // Rate > 1.0 should be clamped to 1.0
        let mock_da = MockDA::with_failure_rate(2.0);
        assert!(mock_da.post_blob(b"test").await.is_err());

        // Rate < 0.0 should be clamped to 0.0
        let mock_da2 = MockDA::with_failure_rate(-1.0);
        assert!(mock_da2.post_blob(b"test").await.is_ok());
    }

    // ════════════════════════════════════════════════════════════════════════
    // C. LATENCY SIMULATION TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_latency_simulation() {
        let mock_da = MockDA::with_latency(100);

        let start = std::time::Instant::now();
        let _ = mock_da.post_blob(b"test").await;
        let elapsed = start.elapsed();

        // Should have taken at least ~100ms (allow some margin)
        assert!(
            elapsed.as_millis() >= 90,
            "Expected at least 90ms, got {}ms",
            elapsed.as_millis()
        );
    }

    #[tokio::test]
    async fn test_latency_non_blocking() {
        let mock_da = Arc::new(MockDA::with_latency(50));

        // Run multiple operations concurrently
        let mock_da1 = Arc::clone(&mock_da);
        let mock_da2 = Arc::clone(&mock_da);

        let start = std::time::Instant::now();

        let (r1, r2) = tokio::join!(
            async move { mock_da1.post_blob(b"test1").await },
            async move { mock_da2.post_blob(b"test2").await }
        );

        let elapsed = start.elapsed();

        assert!(r1.is_ok());
        assert!(r2.is_ok());

        // Should complete in roughly 50ms (concurrent), not 100ms (sequential)
        assert!(
            elapsed.as_millis() < 150,
            "Expected concurrent execution, got {}ms",
            elapsed.as_millis()
        );
    }

    #[tokio::test]
    async fn test_zero_latency() {
        let mock_da = MockDA::with_latency(0);

        let start = std::time::Instant::now();
        let _ = mock_da.post_blob(b"test").await;
        let elapsed = start.elapsed();

        // Should be very fast
        assert!(
            elapsed.as_millis() < 50,
            "Zero latency should be fast, got {}ms",
            elapsed.as_millis()
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    // D. INJECT_BLOB & CLEAR TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_inject_blob_success() {
        let mock_da = MockDA::new();
        let test_data = b"injected blob".to_vec();

        let blob_ref = mock_da.inject_blob(test_data.clone());
        let retrieved = mock_da.get_blob(&blob_ref).await.unwrap();

        assert_eq!(retrieved, test_data);
    }

    #[tokio::test]
    async fn test_inject_blob_increments_height() {
        let mock_da = MockDA::new();

        let ref1 = mock_da.inject_blob(b"blob1".to_vec());
        let ref2 = mock_da.inject_blob(b"blob2".to_vec());
        let ref3 = mock_da.inject_blob(b"blob3".to_vec());

        assert!(ref2.height > ref1.height);
        assert!(ref3.height > ref2.height);
    }

    #[tokio::test]
    async fn test_clear_removes_all_blobs() {
        let mock_da = MockDA::new();

        // Add some blobs
        let ref1 = mock_da.inject_blob(b"blob1".to_vec());
        let ref2 = mock_da.inject_blob(b"blob2".to_vec());

        assert_eq!(mock_da.blob_count(), 2);

        // Clear
        mock_da.clear();

        assert_eq!(mock_da.blob_count(), 0);

        // Blobs should not be found (BlobNotFound)
        assert!(matches!(
            mock_da.get_blob(&ref1).await.unwrap_err(),
            DAError::BlobNotFound(_)
        ));
        assert!(matches!(
            mock_da.get_blob(&ref2).await.unwrap_err(),
            DAError::BlobNotFound(_)
        ));
    }

    #[tokio::test]
    async fn test_clear_resets_counters() {
        let mock_da = MockDA::new();

        // Add blobs to increment counters
        mock_da.inject_blob(b"blob1".to_vec());
        mock_da.inject_blob(b"blob2".to_vec());

        assert!(mock_da.last_height() >= 2);

        // Clear
        mock_da.clear();

        // Next injection should start from height 1
        let new_ref = mock_da.inject_blob(b"new blob".to_vec());
        assert_eq!(new_ref.height, 1);
    }

    // ════════════════════════════════════════════════════════════════════════
    // E. SUBSCRIBE_BLOBS TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_subscribe_blobs_yields_matching_namespace() {
        let mock_da = Arc::new(MockDA::new());
        let namespace = *mock_da.namespace();

        // Inject blobs
        mock_da.inject_blob(b"blob1".to_vec());
        mock_da.inject_blob(b"blob2".to_vec());

        let mut stream = mock_da.subscribe_blobs(&namespace);

        // Get first blob
        let result = tokio::time::timeout(Duration::from_secs(1), stream.next()).await;

        assert!(result.is_ok());
        if let Ok(Some(Ok(blob))) = result {
            assert_eq!(blob.ref_.namespace, namespace);
        }
    }

    #[tokio::test]
    async fn test_subscribe_blobs_ordering() {
        let mock_da = Arc::new(MockDA::new());
        let namespace = *mock_da.namespace();

        // Inject blobs in specific order
        mock_da.inject_blob(b"first".to_vec());
        mock_da.inject_blob(b"second".to_vec());
        mock_da.inject_blob(b"third".to_vec());

        let mut stream = mock_da.subscribe_blobs(&namespace);

        // Collect blobs
        let mut received_heights = Vec::new();
        for _ in 0..3 {
            let result = tokio::time::timeout(Duration::from_secs(1), stream.next()).await;
            if let Ok(Some(Ok(blob))) = result {
                received_heights.push(blob.ref_.height);
            }
        }

        // Should be in height order (ascending)
        assert_eq!(received_heights.len(), 3);
        for i in 1..received_heights.len() {
            assert!(
                received_heights[i] > received_heights[i - 1],
                "Heights should be in ascending order"
            );
        }
    }

    #[tokio::test]
    async fn test_subscribe_blobs_filters_different_namespace() {
        let mock_da = Arc::new(MockDA::new());
        let other_namespace = [0xFF; 29];

        // Inject blob with different namespace directly
        let data = b"other namespace blob".to_vec();
        let commitment = MockDA::compute_commitment(&data);
        let blob_ref = BlobRef {
            height: 1,
            commitment,
            namespace: other_namespace,
        };
        mock_da.blobs.write().unwrap().insert(blob_ref, data);

        // Subscribe with MockDA's default namespace
        let target_namespace = *mock_da.namespace();
        let mut stream = mock_da.subscribe_blobs(&target_namespace);

        // Should timeout because no matching blobs
        let result = tokio::time::timeout(Duration::from_millis(300), stream.next()).await;

        // Should timeout (no matching namespace blobs)
        assert!(result.is_err(), "Should timeout with no matching blobs");
    }

    // ════════════════════════════════════════════════════════════════════════
    // F. HEALTH_CHECK TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_health_check_healthy() {
        let mock_da = MockDA::new();

        let status = mock_da.health_check().await;

        assert_eq!(status, DAHealthStatus::Healthy);
    }

    #[tokio::test]
    async fn test_health_check_unavailable_with_failure() {
        let mock_da = MockDA::with_failure_rate(1.0);

        let status = mock_da.health_check().await;

        assert_eq!(status, DAHealthStatus::Unavailable);
    }

    #[tokio::test]
    async fn test_health_check_degraded_with_high_latency() {
        let mock_da = MockDA::with_latency(600); // > 500ms threshold

        let status = mock_da.health_check().await;

        assert_eq!(status, DAHealthStatus::Degraded);
    }

    #[tokio::test]
    async fn test_health_check_no_panic() {
        let mock_da = MockDA::with_failure_rate(0.5);

        // Run multiple health checks - should never panic
        for _ in 0..20 {
            let _ = mock_da.health_check().await;
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // ADDITIONAL TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_default_impl() {
        let mock_da = MockDA::default();
        assert_eq!(mock_da.blob_count(), 0);
        assert_eq!(mock_da.failure_rate, 0.0);
        assert_eq!(mock_da.latency_ms, 0);
    }

    #[tokio::test]
    async fn test_blob_isolation_between_instances() {
        let mock_da1 = MockDA::new();
        let mock_da2 = MockDA::new();

        let ref1 = mock_da1.post_blob(b"blob for da1").await.unwrap();

        // Should not be found in da2
        let result = mock_da2.get_blob(&ref1).await;
        assert!(matches!(result.unwrap_err(), DAError::BlobNotFound(_)));
    }

    #[tokio::test]
    async fn test_last_height() {
        let mock_da = MockDA::new();

        assert_eq!(mock_da.last_height(), 0);

        mock_da.inject_blob(b"blob1".to_vec());
        assert_eq!(mock_da.last_height(), 1);

        mock_da.inject_blob(b"blob2".to_vec());
        assert_eq!(mock_da.last_height(), 2);
    }

    #[tokio::test]
    async fn test_state_not_leak_between_tests() {
        // Create fresh instance
        let mock_da = MockDA::new();

        // Should start clean
        assert_eq!(mock_da.blob_count(), 0);
        assert_eq!(mock_da.last_height(), 0);

        // Add blob
        mock_da.inject_blob(b"test".to_vec());
        assert_eq!(mock_da.blob_count(), 1);
    }

    #[tokio::test]
    async fn test_concurrent_writes_safe() {
        let mock_da = Arc::new(MockDA::new());

        let mut handles = Vec::new();
        for i in 0..10 {
            let da = Arc::clone(&mock_da);
            handles.push(tokio::spawn(async move {
                da.post_blob(format!("blob {}", i).as_bytes()).await
            }));
        }

        for handle in handles {
            assert!(handle.await.unwrap().is_ok());
        }

        assert_eq!(mock_da.blob_count(), 10);
    }
}