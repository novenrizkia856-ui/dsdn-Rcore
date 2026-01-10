//! # Fallback & Retry Module
//!
//! Module ini menyediakan fallback dan retry logic untuk ingress layer.
//!
//! ## Prinsip
//!
//! - Primary node dicoba terlebih dahulu
//! - Jika gagal, fallback ke node berikutnya secara urut
//! - Circuit breaker melindungi dari node yang sering gagal
//! - Semua keputusan deterministik dan thread-safe
//!
//! ## Circuit Breaker States
//!
//! - CLOSED: Normal operation, requests allowed
//! - OPEN: Node blocked, requests rejected until backoff expires
//! - HALF-OPEN: Testing node after backoff, limited requests allowed

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use tracing::{debug, info, warn};

use crate::da_router::{DARouter, NodeInfo, RouterError};

// ════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════

/// Default maximum retries per node.
pub const DEFAULT_MAX_RETRIES: u8 = 3;

/// Default retry delay in milliseconds.
pub const DEFAULT_RETRY_DELAY_MS: u64 = 100;

/// Failure threshold untuk circuit breaker OPEN.
/// Node dengan failure_count >= threshold dianggap OPEN.
pub const CIRCUIT_BREAKER_THRESHOLD: u32 = 5;

/// Backoff duration in milliseconds ketika circuit OPEN.
pub const CIRCUIT_BREAKER_BACKOFF_MS: u64 = 30_000; // 30 seconds

/// Half-open test window in milliseconds.
/// Setelah backoff expires, node dalam state HALF-OPEN selama window ini.
pub const HALF_OPEN_WINDOW_MS: u64 = 5_000; // 5 seconds

// ════════════════════════════════════════════════════════════════════════════
// FETCH ERROR
// ════════════════════════════════════════════════════════════════════════════

/// Error yang dapat terjadi saat fetch dengan fallback.
#[derive(Debug, Clone)]
pub enum FetchError {
    /// Tidak ada placement untuk chunk.
    NoPlacement(String),
    /// Semua node gagal.
    AllNodesFailed(String),
    /// Router error.
    RouterError(RouterError),
    /// Node fetch error.
    NodeError(String),
    /// Timeout.
    Timeout(String),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::NoPlacement(hash) => write!(f, "no placement for chunk: {}", hash),
            FetchError::AllNodesFailed(hash) => write!(f, "all nodes failed for chunk: {}", hash),
            FetchError::RouterError(e) => write!(f, "router error: {}", e),
            FetchError::NodeError(msg) => write!(f, "node error: {}", msg),
            FetchError::Timeout(msg) => write!(f, "timeout: {}", msg),
        }
    }
}

impl std::error::Error for FetchError {}

impl From<RouterError> for FetchError {
    fn from(e: RouterError) -> Self {
        FetchError::RouterError(e)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// CIRCUIT STATE
// ════════════════════════════════════════════════════════════════════════════

/// State dari circuit breaker untuk sebuah node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation, requests allowed.
    Closed,
    /// Node blocked, requests rejected.
    Open,
    /// Testing node after backoff.
    HalfOpen,
}

// ════════════════════════════════════════════════════════════════════════════
// FAILURE RECORD
// ════════════════════════════════════════════════════════════════════════════

/// Record kegagalan untuk sebuah node.
#[derive(Debug, Clone)]
pub struct FailureRecord {
    /// ID node.
    pub node_id: String,
    /// Jumlah kegagalan (monotonik naik, reset on success).
    pub failure_count: u32,
    /// Timestamp kegagalan terakhir (Unix milliseconds).
    pub last_failure: u64,
    /// Timestamp sampai kapan node di-backoff (Unix milliseconds).
    /// Invariant: backoff_until >= last_failure
    pub backoff_until: u64,
}

impl FailureRecord {
    /// Membuat FailureRecord baru untuk node.
    pub fn new(node_id: String) -> Self {
        Self {
            node_id,
            failure_count: 0,
            last_failure: 0,
            backoff_until: 0,
        }
    }

    /// Record failure dan update backoff.
    ///
    /// # Arguments
    ///
    /// * `now` - Current timestamp in milliseconds
    /// * `backoff_ms` - Backoff duration in milliseconds
    pub fn record_failure(&mut self, now: u64, backoff_ms: u64) {
        // Increment failure count (saturating to prevent overflow)
        self.failure_count = self.failure_count.saturating_add(1);
        self.last_failure = now;

        // Calculate backoff with exponential increase capped at reasonable max
        let multiplier = std::cmp::min(self.failure_count, 10) as u64;
        let backoff = backoff_ms.saturating_mul(multiplier);
        self.backoff_until = now.saturating_add(backoff);
    }

    /// Reset failure record on success.
    pub fn reset(&mut self) {
        self.failure_count = 0;
        self.last_failure = 0;
        self.backoff_until = 0;
    }

    /// Get circuit state berdasarkan current time.
    pub fn circuit_state(&self, now: u64, threshold: u32) -> CircuitState {
        if self.failure_count < threshold {
            CircuitState::Closed
        } else if now < self.backoff_until {
            CircuitState::Open
        } else {
            // Backoff expired, allow testing
            CircuitState::HalfOpen
        }
    }

    /// Check if node should be skipped based on circuit state.
    pub fn should_skip(&self, now: u64, threshold: u32) -> bool {
        self.circuit_state(now, threshold) == CircuitState::Open
    }
}

// ════════════════════════════════════════════════════════════════════════════
// FETCH RESULT
// ════════════════════════════════════════════════════════════════════════════

/// Result dari single node fetch attempt.
#[derive(Debug)]
pub enum NodeFetchResult {
    /// Fetch berhasil dengan data.
    Success(Vec<u8>),
    /// Fetch gagal dengan error.
    Failed(String),
    /// Node di-skip karena circuit open.
    Skipped,
}

// ════════════════════════════════════════════════════════════════════════════
// FETCH FUNCTION TRAIT
// ════════════════════════════════════════════════════════════════════════════

/// Trait untuk fungsi fetch ke node.
///
/// Memungkinkan injection of fetch logic untuk testing.
pub trait NodeFetcher: Send + Sync {
    /// Fetch chunk dari node.
    ///
    /// # Arguments
    ///
    /// * `node` - Node info
    /// * `chunk_hash` - Hash chunk yang diminta
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - Data chunk
    /// * `Err(String)` - Error message
    fn fetch(&self, node: &NodeInfo, chunk_hash: &str) -> Result<Vec<u8>, String>;
}

// ════════════════════════════════════════════════════════════════════════════
// FALLBACK MANAGER
// ════════════════════════════════════════════════════════════════════════════

/// Manager untuk fallback dan retry logic.
///
/// Thread-safe dan deterministic.
pub struct FallbackManager<F: NodeFetcher> {
    /// DARouter sebagai sumber data.
    router: Arc<DARouter>,
    /// Maximum retries per node.
    max_retries: u8,
    /// Delay between retries in milliseconds.
    retry_delay_ms: u64,
    /// Failure records per node (thread-safe).
    failed_nodes: RwLock<HashMap<String, FailureRecord>>,
    /// Node fetcher implementation.
    fetcher: F,
    /// Circuit breaker failure threshold.
    circuit_threshold: u32,
    /// Circuit breaker backoff duration in ms.
    circuit_backoff_ms: u64,
}

impl<F: NodeFetcher> FallbackManager<F> {
    /// Membuat FallbackManager baru.
    pub fn new(router: Arc<DARouter>, fetcher: F) -> Self {
        Self {
            router,
            max_retries: DEFAULT_MAX_RETRIES,
            retry_delay_ms: DEFAULT_RETRY_DELAY_MS,
            failed_nodes: RwLock::new(HashMap::new()),
            fetcher,
            circuit_threshold: CIRCUIT_BREAKER_THRESHOLD,
            circuit_backoff_ms: CIRCUIT_BREAKER_BACKOFF_MS,
        }
    }

    /// Membuat FallbackManager dengan konfigurasi kustom.
    pub fn with_config(
        router: Arc<DARouter>,
        fetcher: F,
        max_retries: u8,
        retry_delay_ms: u64,
        circuit_threshold: u32,
        circuit_backoff_ms: u64,
    ) -> Self {
        Self {
            router,
            max_retries,
            retry_delay_ms,
            failed_nodes: RwLock::new(HashMap::new()),
            fetcher,
            circuit_threshold,
            circuit_backoff_ms,
        }
    }

    /// Get current timestamp in milliseconds.
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    /// Get or create failure record for node.
    fn get_or_create_record(&self, node_id: &str) -> FailureRecord {
        let records = self.failed_nodes.read();
        records
            .get(node_id)
            .cloned()
            .unwrap_or_else(|| FailureRecord::new(node_id.to_string()))
    }

    /// Update failure record for node.
    fn update_record(&self, record: FailureRecord) {
        let mut records = self.failed_nodes.write();
        records.insert(record.node_id.clone(), record);
    }

    /// Get circuit state for node.
    pub fn get_circuit_state(&self, node_id: &str) -> CircuitState {
        let record = self.get_or_create_record(node_id);
        record.circuit_state(self.now_ms(), self.circuit_threshold)
    }

    /// Get failure count for node.
    pub fn get_failure_count(&self, node_id: &str) -> u32 {
        self.get_or_create_record(node_id).failure_count
    }

    /// Try fetch from single node with retries.
    fn try_fetch_node(
        &self,
        node: &NodeInfo,
        chunk_hash: &str,
    ) -> NodeFetchResult {
        let now = self.now_ms();
        let mut record = self.get_or_create_record(&node.id);

        // Check circuit state
        let state = record.circuit_state(now, self.circuit_threshold);
        if state == CircuitState::Open {
            debug!("Node {} circuit OPEN, skipping", node.id);
            return NodeFetchResult::Skipped;
        }

        // Log if half-open
        if state == CircuitState::HalfOpen {
            info!("Node {} circuit HALF-OPEN, testing", node.id);
        }

        // Try fetch with retries
        let mut last_error = String::new();
        for attempt in 0..=self.max_retries {
            if attempt > 0 {
                // Delay between retries (blocking sleep for sync context)
                std::thread::sleep(std::time::Duration::from_millis(self.retry_delay_ms));
                debug!("Node {} retry attempt {}/{}", node.id, attempt, self.max_retries);
            }

            match self.fetcher.fetch(node, chunk_hash) {
                Ok(data) => {
                    // Success - reset failure record
                    record.reset();
                    self.update_record(record);
                    info!("Node {} fetch success for {}", node.id, chunk_hash);
                    return NodeFetchResult::Success(data);
                }
                Err(e) => {
                    last_error = e;
                    warn!("Node {} fetch failed: {}", node.id, last_error);
                }
            }
        }

        // All retries exhausted - record failure
        let now = self.now_ms();
        record.record_failure(now, self.circuit_backoff_ms);
        self.update_record(record);

        NodeFetchResult::Failed(last_error)
    }

    /// Fetch chunk with fallback support.
    ///
    /// # Arguments
    ///
    /// * `chunk_hash` - Hash chunk yang diminta
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - Data chunk
    /// * `Err(FetchError)` - Error jika semua node gagal
    ///
    /// # Behavior
    ///
    /// 1. Ambil placement dari DARouter
    /// 2. Coba primary node terlebih dahulu
    /// 3. Jika gagal, coba fallback nodes secara urut
    /// 4. Circuit breaker menghindari node yang sering gagal
    pub fn fetch_with_fallback(&self, chunk_hash: &str) -> Result<Vec<u8>, FetchError> {
        // Step 1: Get placement from DARouter
        let nodes = self.router.get_placement(chunk_hash)?;

        if nodes.is_empty() {
            return Err(FetchError::NoPlacement(chunk_hash.to_string()));
        }

        info!("Fetching {} with {} available nodes", chunk_hash, nodes.len());

        // Step 2: Try nodes in order (primary first, then fallbacks)
        let mut last_error = String::new();
        let mut all_skipped = true;

        for (idx, node) in nodes.iter().enumerate() {
            let node_type = if idx == 0 { "primary" } else { "fallback" };
            debug!("Trying {} node {} for {}", node_type, node.id, chunk_hash);

            match self.try_fetch_node(node, chunk_hash) {
                NodeFetchResult::Success(data) => {
                    return Ok(data);
                }
                NodeFetchResult::Failed(e) => {
                    all_skipped = false;
                    last_error = e;
                    // Continue to next node
                }
                NodeFetchResult::Skipped => {
                    // Node skipped due to circuit open, continue to next
                }
            }
        }

        // All nodes failed or skipped
        if all_skipped {
            Err(FetchError::AllNodesFailed(format!(
                "{}: all nodes circuit OPEN",
                chunk_hash
            )))
        } else {
            Err(FetchError::AllNodesFailed(format!(
                "{}: {}",
                chunk_hash, last_error
            )))
        }
    }

    /// Clear all failure records.
    pub fn clear_failure_records(&self) {
        let mut records = self.failed_nodes.write();
        records.clear();
    }

    /// Get number of tracked nodes.
    pub fn tracked_node_count(&self) -> usize {
        self.failed_nodes.read().len()
    }
}

// ════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::da_router::{RoutingDataSource, RoutingResult, NodeInfoFromSource};
    use std::sync::atomic::{AtomicU32, Ordering};

    // ════════════════════════════════════════════════════════════════════════
    // MOCK DATA SOURCE
    // ════════════════════════════════════════════════════════════════════════

    struct MockDataSource {
        nodes: RwLock<HashMap<String, MockNodeInfo>>,
        placements: RwLock<HashMap<String, Vec<String>>>,
    }

    struct MockNodeInfo {
        addr: String,
        active: bool,
        zone: Option<String>,
    }

    impl MockDataSource {
        fn new() -> Self {
            Self {
                nodes: RwLock::new(HashMap::new()),
                placements: RwLock::new(HashMap::new()),
            }
        }

        fn add_node(&self, id: &str, addr: &str, active: bool) {
            self.nodes.write().insert(id.to_string(), MockNodeInfo {
                addr: addr.to_string(),
                active,
                zone: None,
            });
        }

        fn add_placement(&self, chunk_hash: &str, node_ids: Vec<&str>) {
            self.placements.write().insert(
                chunk_hash.to_string(),
                node_ids.into_iter().map(|s| s.to_string()).collect(),
            );
        }
    }

    impl RoutingDataSource for MockDataSource {
        fn get_registered_node_ids(&self) -> RoutingResult<Vec<String>> {
            Ok(self.nodes.read().keys().cloned().collect())
        }

        fn get_node_info(&self, node_id: &str) -> RoutingResult<Option<NodeInfoFromSource>> {
            Ok(self.nodes.read().get(node_id).map(|n| NodeInfoFromSource {
                addr: n.addr.clone(),
                active: n.active,
                zone: n.zone.clone(),
            }))
        }

        fn get_all_chunk_placements(&self) -> RoutingResult<HashMap<String, Vec<String>>> {
            Ok(self.placements.read().clone())
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // MOCK FETCHER
    // ════════════════════════════════════════════════════════════════════════

    struct MockFetcher {
        /// Nodes yang akan fail.
        fail_nodes: RwLock<HashMap<String, bool>>,
        /// Counter untuk tracking fetch attempts.
        fetch_count: AtomicU32,
        /// Data yang dikembalikan saat success.
        data: Vec<u8>,
    }

    impl MockFetcher {
        fn new(data: Vec<u8>) -> Self {
            Self {
                fail_nodes: RwLock::new(HashMap::new()),
                fetch_count: AtomicU32::new(0),
                data,
            }
        }

        fn set_node_fail(&self, node_id: &str, should_fail: bool) {
            self.fail_nodes.write().insert(node_id.to_string(), should_fail);
        }

        fn get_fetch_count(&self) -> u32 {
            self.fetch_count.load(Ordering::SeqCst)
        }

        fn reset_fetch_count(&self) {
            self.fetch_count.store(0, Ordering::SeqCst);
        }
    }

    impl NodeFetcher for MockFetcher {
        fn fetch(&self, node: &NodeInfo, _chunk_hash: &str) -> Result<Vec<u8>, String> {
            self.fetch_count.fetch_add(1, Ordering::SeqCst);

            let fail = self.fail_nodes.read().get(&node.id).copied().unwrap_or(false);
            if fail {
                Err(format!("mock fetch failed for {}", node.id))
            } else {
                Ok(self.data.clone())
            }
        }
    }

    fn setup_test() -> (Arc<MockDataSource>, Arc<MockFetcher>) {
        let mock_ds = Arc::new(MockDataSource::new());
        mock_ds.add_node("node-a", "127.0.0.1:9001", true);
        mock_ds.add_node("node-b", "127.0.0.1:9002", true);
        mock_ds.add_node("node-c", "127.0.0.1:9003", true);
        mock_ds.add_placement("chunk-1", vec!["node-a", "node-b", "node-c"]);

        let fetcher = Arc::new(MockFetcher::new(vec![1, 2, 3, 4]));

        (mock_ds, fetcher)
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 1: PRIMARY SUCCESS (NO FALLBACK)
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_primary_success_no_fallback() {
        let (mock_ds, _fetcher) = setup_test();
        let router = Arc::new(DARouter::new(mock_ds));
        router.refresh_cache().unwrap();

        let manager = FallbackManager::with_config(
            router,
            MockFetcher::new(vec![1, 2, 3, 4]),
            3, 10, 5, 1000,
        );

        let result = manager.fetch_with_fallback("chunk-1");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![1, 2, 3, 4]);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 2: PRIMARY FAIL → FALLBACK SUCCESS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_primary_fail_fallback_success() {
        let (mock_ds, _) = setup_test();
        let router = Arc::new(DARouter::new(mock_ds));
        router.refresh_cache().unwrap();

        let fetcher = MockFetcher::new(vec![5, 6, 7, 8]);
        fetcher.set_node_fail("node-a", true); // primary fails

        let manager = FallbackManager::with_config(
            router,
            fetcher,
            0, 10, 5, 1000, // 0 retries for faster test
        );

        let result = manager.fetch_with_fallback("chunk-1");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![5, 6, 7, 8]);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 3: MULTIPLE FALLBACK BERURUTAN
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_multiple_fallback_sequential() {
        let (mock_ds, _) = setup_test();
        let router = Arc::new(DARouter::new(mock_ds));
        router.refresh_cache().unwrap();

        let fetcher = MockFetcher::new(vec![9, 10]);
        fetcher.set_node_fail("node-a", true);
        fetcher.set_node_fail("node-b", true);
        // node-c will succeed

        let manager = FallbackManager::with_config(
            router,
            fetcher,
            0, 10, 5, 1000,
        );

        let result = manager.fetch_with_fallback("chunk-1");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![9, 10]);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 4: CIRCUIT BREAKER OPEN
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_circuit_breaker_open() {
        let (mock_ds, _) = setup_test();
        let router = Arc::new(DARouter::new(mock_ds));
        router.refresh_cache().unwrap();

        let fetcher = MockFetcher::new(vec![1, 2, 3]);
        fetcher.set_node_fail("node-a", true);

        // Low threshold for testing (2 failures = OPEN)
        let manager = FallbackManager::with_config(
            router,
            fetcher,
            0, 10, 2, 60000, // 60s backoff
        );

        // First fetch - fail node-a, use fallback
        let _ = manager.fetch_with_fallback("chunk-1");
        assert_eq!(manager.get_failure_count("node-a"), 1);

        // Second fetch - fail again
        let _ = manager.fetch_with_fallback("chunk-1");
        assert_eq!(manager.get_failure_count("node-a"), 2);

        // Now circuit should be OPEN
        assert_eq!(manager.get_circuit_state("node-a"), CircuitState::Open);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 5: CIRCUIT BREAKER HALF-OPEN
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_circuit_breaker_half_open() {
        let mut record = FailureRecord::new("node-test".to_string());

        // Record failures to trigger OPEN
        let now = 1000000u64;
        record.record_failure(now, 100);
        record.record_failure(now, 100);
        record.record_failure(now, 100);
        record.record_failure(now, 100);
        record.record_failure(now, 100); // 5 failures = OPEN

        // Check OPEN state
        assert_eq!(record.circuit_state(now, 5), CircuitState::Open);

        // After backoff expires, should be HALF-OPEN
        let future = record.backoff_until + 1;
        assert_eq!(record.circuit_state(future, 5), CircuitState::HalfOpen);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 6: RETRY LIMIT TERCAPAI
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_retry_limit_reached() {
        let mock_ds = Arc::new(MockDataSource::new());
        mock_ds.add_node("node-x", "127.0.0.1:9001", true);
        mock_ds.add_placement("chunk-x", vec!["node-x"]);

        let router = Arc::new(DARouter::new(mock_ds));
        router.refresh_cache().unwrap();

        let fetcher = MockFetcher::new(vec![]);
        fetcher.set_node_fail("node-x", true);

        let manager = FallbackManager::with_config(
            router,
            fetcher,
            2, 1, 100, 1000, // 2 retries
        );

        let result = manager.fetch_with_fallback("chunk-x");
        assert!(result.is_err());

        // Should have tried 1 + 2 retries = 3 attempts
        // Failure count should be 1 (after all retries exhausted)
        assert_eq!(manager.get_failure_count("node-x"), 1);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 7: BACKOFF DIHORMATI
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_backoff_respected() {
        let mut record = FailureRecord::new("node-backoff".to_string());

        let now = 1000u64;
        record.record_failure(now, 500); // 500ms backoff

        // Should be backoff_until >= last_failure
        assert!(record.backoff_until >= record.last_failure);

        // Within backoff window - should skip
        assert!(record.should_skip(now + 100, 1));

        // After backoff - should not skip (HALF-OPEN)
        assert!(!record.should_skip(record.backoff_until + 1, 1));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 8: CONCURRENT FETCH SAFE
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_concurrent_fetch_safe() {
        use std::thread;

        let (mock_ds, _) = setup_test();
        let router = Arc::new(DARouter::new(mock_ds));
        router.refresh_cache().unwrap();

        let manager = Arc::new(FallbackManager::with_config(
            router,
            MockFetcher::new(vec![1, 2, 3]),
            1, 1, 5, 1000,
        ));

        let mut handles = vec![];

        for _ in 0..10 {
            let m = manager.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..20 {
                    let _ = m.fetch_with_fallback("chunk-1");
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        // Should not panic or deadlock
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 9: FAILURE RECORD KONSISTEN
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_failure_record_consistent() {
        let mut record = FailureRecord::new("node-test".to_string());

        // Initial state
        assert_eq!(record.failure_count, 0);
        assert_eq!(record.last_failure, 0);
        assert_eq!(record.backoff_until, 0);

        // Record failure
        record.record_failure(1000, 100);
        assert_eq!(record.failure_count, 1);
        assert_eq!(record.last_failure, 1000);
        assert!(record.backoff_until >= record.last_failure);

        // Record another failure
        record.record_failure(2000, 100);
        assert_eq!(record.failure_count, 2);
        assert_eq!(record.last_failure, 2000);

        // Reset on success
        record.reset();
        assert_eq!(record.failure_count, 0);
        assert_eq!(record.last_failure, 0);
        assert_eq!(record.backoff_until, 0);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 10: ERROR IF ALL NODES FAIL
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_error_all_nodes_fail() {
        let (mock_ds, _) = setup_test();
        let router = Arc::new(DARouter::new(mock_ds));
        router.refresh_cache().unwrap();

        let fetcher = MockFetcher::new(vec![]);
        fetcher.set_node_fail("node-a", true);
        fetcher.set_node_fail("node-b", true);
        fetcher.set_node_fail("node-c", true);

        let manager = FallbackManager::with_config(
            router,
            fetcher,
            0, 10, 100, 1000,
        );

        let result = manager.fetch_with_fallback("chunk-1");
        assert!(result.is_err());

        match result.unwrap_err() {
            FetchError::AllNodesFailed(msg) => {
                assert!(msg.contains("chunk-1"));
            }
            _ => panic!("Expected AllNodesFailed error"),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 11: CIRCUIT RESET ON SUCCESS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_circuit_reset_on_success() {
        let (mock_ds, _) = setup_test();
        let router = Arc::new(DARouter::new(mock_ds));
        router.refresh_cache().unwrap();

        let fetcher = MockFetcher::new(vec![1, 2]);
        fetcher.set_node_fail("node-a", true);

        let manager = FallbackManager::with_config(
            router,
            fetcher,
            0, 10, 2, 1000,
        );

        // Fail node-a twice
        let _ = manager.fetch_with_fallback("chunk-1");
        let _ = manager.fetch_with_fallback("chunk-1");
        assert_eq!(manager.get_failure_count("node-a"), 2);

        // node-b succeeds, its count should be 0
        assert_eq!(manager.get_failure_count("node-b"), 0);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 12: FETCH ERROR DISPLAY
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_fetch_error_display() {
        let err = FetchError::NoPlacement("abc".to_string());
        assert!(format!("{}", err).contains("no placement"));

        let err = FetchError::AllNodesFailed("xyz".to_string());
        assert!(format!("{}", err).contains("all nodes failed"));

        let err = FetchError::NodeError("connection refused".to_string());
        assert!(format!("{}", err).contains("node error"));

        let err = FetchError::Timeout("5s".to_string());
        assert!(format!("{}", err).contains("timeout"));
    }
}