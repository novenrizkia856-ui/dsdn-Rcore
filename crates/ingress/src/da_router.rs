//! # DA-Aware Routing Module
//!
//! Routing layer yang sadar DA (DA-derived routing).
//!
//! ## Prinsip
//!
//! - Ingress TIDAK menyimpan state authoritative
//! - Semua keputusan routing berdasarkan state turunan dari DA
//! - Cache hanya untuk performa, BUKAN sumber kebenaran
//!
//! ## Invariant
//!
//! - `da` adalah satu-satunya sumber kebenaran
//! - `state_cache` hanya cache, BUKAN authoritative
//! - Refresh adalah atomic (all-or-nothing)
//!
//! ## Note
//!
//! Module ini menggunakan trait `RoutingDataSource` sebagai abstraksi
//! untuk sumber data routing. Implementasi konkret bisa:
//! - Decode blobs dari DA layer untuk extract routing info
//! - Query coordinator untuk node/placement info
//! - Kombinasi keduanya

// Infrastructure code - akan digunakan ketika DA layer connected
#![allow(dead_code)]

use std::collections::HashMap;
use std::fmt::{self, Debug};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use tokio::sync::watch;
use tracing::{debug, info, warn};

// ════════════════════════════════════════════════════════════════════════════
// ROUTING DATA SOURCE TRAIT
// ════════════════════════════════════════════════════════════════════════════

/// Result type untuk RoutingDataSource operations.
pub type RoutingResult<T> = Result<T, RoutingError>;

/// Error dari routing data source operations.
#[derive(Debug, Clone)]
pub struct RoutingError(pub String);

impl std::fmt::Display for RoutingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "routing error: {}", self.0)
    }
}

impl std::error::Error for RoutingError {}

/// Info node dari data source.
#[derive(Debug, Clone)]
pub struct NodeInfoFromSource {
    /// Alamat node (host:port).
    pub addr: String,
    /// Apakah node aktif.
    pub active: bool,
}

/// Trait untuk sumber data routing.
///
/// Trait ini mendefinisikan interface untuk mengambil data routing
/// (node registry dan chunk placements). Implementasi konkret bisa:
/// - Decode blobs dari DA layer
/// - Query coordinator API
/// - Kombinasi keduanya
///
/// # Thread Safety
///
/// Trait ini memerlukan `Send + Sync` untuk digunakan dalam async context.
pub trait RoutingDataSource: Send + Sync {
    /// Get list of registered node IDs.
    fn get_registered_node_ids(&self) -> RoutingResult<Vec<String>>;

    /// Get info for a specific node.
    fn get_node_info(&self, node_id: &str) -> RoutingResult<Option<NodeInfoFromSource>>;

    /// Get all chunk placements (chunk_hash -> list of node_ids).
    fn get_all_chunk_placements(&self) -> RoutingResult<HashMap<String, Vec<String>>>;
}

// ════════════════════════════════════════════════════════════════════════════
// DA ERROR
// ════════════════════════════════════════════════════════════════════════════

/// Error yang dapat terjadi pada operasi DA routing.
#[derive(Debug)]
pub enum DAError {
    /// Error saat fetch dari DA.
    FetchError(String),
    /// Error lainnya.
    Other(String),
}

impl std::fmt::Display for DAError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DAError::FetchError(msg) => write!(f, "DA fetch error: {}", msg),
            DAError::Other(msg) => write!(f, "DA error: {}", msg),
        }
    }
}

impl std::error::Error for DAError {}

// ════════════════════════════════════════════════════════════════════════════
// NODE INFO
// ════════════════════════════════════════════════════════════════════════════

/// Informasi node dari DA registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeInfo {
    /// ID unik node.
    pub id: String,
    /// Alamat node (host:port).
    pub addr: String,
    /// Apakah node aktif.
    pub active: bool,
}

impl NodeInfo {
    /// Membuat NodeInfo baru.
    pub fn new(id: String, addr: String, active: bool) -> Self {
        Self { id, addr, active }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// CACHED ROUTING STATE
// ════════════════════════════════════════════════════════════════════════════

/// State routing yang di-cache dari DA.
///
/// # Fields (PERSIS sesuai spesifikasi)
///
/// - `node_registry`: Snapshot node aktif dari DA
/// - `chunk_placements`: Mapping chunk_hash → node_id list
/// - `last_updated`: Timestamp cache di-refresh (Unix milliseconds)
///
/// # Note
///
/// State ini adalah CACHE, bukan authoritative.
#[derive(Debug, Clone, Default)]
pub struct CachedRoutingState {
    /// Registry node aktif dari DA.
    pub node_registry: HashMap<String, NodeInfo>,
    /// Mapping chunk_hash → list of node_ids.
    pub chunk_placements: HashMap<String, Vec<String>>,
    /// Timestamp terakhir di-update (Unix milliseconds).
    pub last_updated: u64,
}

impl CachedRoutingState {
    /// Membuat state kosong tapi valid.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check apakah cache sudah expired.
    pub fn is_expired(&self, ttl_ms: u64) -> bool {
        let now = current_timestamp_ms();
        now.saturating_sub(self.last_updated) > ttl_ms
    }

    /// Check apakah cache kosong.
    pub fn is_empty(&self) -> bool {
        self.node_registry.is_empty() && self.chunk_placements.is_empty()
    }

    /// Get node by ID.
    pub fn get_node(&self, node_id: &str) -> Option<&NodeInfo> {
        self.node_registry.get(node_id)
    }

    /// Get placement untuk chunk hash.
    pub fn get_placement(&self, chunk_hash: &str) -> Option<&Vec<String>> {
        self.chunk_placements.get(chunk_hash)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// DA ROUTER
// ════════════════════════════════════════════════════════════════════════════

/// Default cache TTL: 30 detik (30000 ms).
pub const DEFAULT_CACHE_TTL_MS: u64 = 30_000;

/// DA-aware router untuk ingress.
///
/// # Fields (PERSIS sesuai spesifikasi)
///
/// - `da`: Satu-satunya sumber kebenaran (routing data source)
/// - `state_cache`: Cache routing state (derived, bukan authoritative)
/// - `cache_ttl_ms`: Time-to-live untuk cache invalidation
///
/// # Invariant
///
/// - `da` adalah sumber kebenaran
/// - `state_cache` hanya cache, BUKAN authoritative
pub struct DARouter {
    /// Routing data source - source of truth.
    da: Arc<dyn RoutingDataSource>,
    /// Cached routing state (derived, not authoritative).
    state_cache: RwLock<CachedRoutingState>,
    /// Cache TTL dalam milliseconds.
    cache_ttl_ms: u64,
}

impl Debug for DARouter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DARouter")
            .field("da", &"<RoutingDataSource>")
            .field("cache_ttl_ms", &self.cache_ttl_ms)
            .finish()
    }
}

impl DARouter {
    /// Membuat DARouter baru.
    ///
    /// # Arguments
    ///
    /// * `da` - Routing data source (source of truth)
    ///
    /// # Returns
    ///
    /// DARouter dengan cache kosong tapi valid dan default TTL (30 detik).
    ///
    /// # Note
    ///
    /// Constructor TIDAK melakukan network call.
    pub fn new(da: Arc<dyn RoutingDataSource>) -> Self {
        Self {
            da,
            state_cache: RwLock::new(CachedRoutingState::new()),
            cache_ttl_ms: DEFAULT_CACHE_TTL_MS,
        }
    }

    /// Membuat DARouter dengan custom TTL.
    pub fn with_ttl(da: Arc<dyn RoutingDataSource>, cache_ttl_ms: u64) -> Self {
        Self {
            da,
            state_cache: RwLock::new(CachedRoutingState::new()),
            cache_ttl_ms,
        }
    }

    /// Get cache TTL.
    pub fn cache_ttl_ms(&self) -> u64 {
        self.cache_ttl_ms
    }

    /// Get current cache state (read-only snapshot).
    pub fn get_cache(&self) -> CachedRoutingState {
        self.state_cache.read().clone()
    }

    /// Check if cache is expired.
    pub fn is_cache_expired(&self) -> bool {
        self.state_cache.read().is_expired(self.cache_ttl_ms)
    }

    /// Check if cache is empty.
    pub fn is_cache_empty(&self) -> bool {
        self.state_cache.read().is_empty()
    }

    // ════════════════════════════════════════════════════════════════════════
    // CACHE REFRESH
    // ════════════════════════════════════════════════════════════════════════

    /// Refresh cache dari data source.
    ///
    /// # Returns
    ///
    /// - `Ok(())`: Cache berhasil di-refresh
    /// - `Err(DAError)`: Error saat fetch
    ///
    /// # Behavior
    ///
    /// - Fetch node registry
    /// - Fetch chunk placements
    /// - Update cache SECARA ATOMIK (all-or-nothing)
    /// - Update last_updated timestamp
    ///
    /// # Invariant
    ///
    /// - Tidak panic
    /// - Tidak partial update
    /// - Tidak menggabungkan data lama & baru
    pub fn refresh_cache(&self) -> Result<(), DAError> {
        debug!("DARouter: refreshing cache from data source");

        // Fetch node registry
        let node_registry = self.fetch_node_registry()?;

        // Fetch chunk placements
        let chunk_placements = self.fetch_chunk_placements()?;

        // Create new state (all-or-nothing)
        let new_state = CachedRoutingState {
            node_registry,
            chunk_placements,
            last_updated: current_timestamp_ms(),
        };

        // Atomic update - replace entire cache
        *self.state_cache.write() = new_state;

        info!(
            "DARouter: cache refreshed, {} nodes, {} placements",
            self.state_cache.read().node_registry.len(),
            self.state_cache.read().chunk_placements.len()
        );

        Ok(())
    }

    /// Fetch node registry.
    fn fetch_node_registry(&self) -> Result<HashMap<String, NodeInfo>, DAError> {
        let node_ids = self.da.get_registered_node_ids()
            .map_err(|e| DAError::FetchError(format!("Failed to get node IDs: {}", e)))?;

        let mut registry = HashMap::new();
        for node_id in node_ids {
            if let Some(info) = self.da.get_node_info(&node_id)
                .map_err(|e| DAError::FetchError(format!("Failed to get node info: {}", e)))?
            {
                registry.insert(node_id.clone(), NodeInfo {
                    id: node_id,
                    addr: info.addr,
                    active: info.active,
                });
            }
        }

        Ok(registry)
    }

    /// Fetch chunk placements.
    fn fetch_chunk_placements(&self) -> Result<HashMap<String, Vec<String>>, DAError> {
        let placements = self.da.get_all_chunk_placements()
            .map_err(|e| DAError::FetchError(format!("Failed to get placements: {}", e)))?;

        Ok(placements)
    }

    // ════════════════════════════════════════════════════════════════════════
    // ROUTING QUERIES
    // ════════════════════════════════════════════════════════════════════════

    /// Get nodes untuk chunk hash.
    pub fn get_nodes_for_chunk(&self, chunk_hash: &str) -> Vec<NodeInfo> {
        let cache = self.state_cache.read();

        match cache.get_placement(chunk_hash) {
            Some(node_ids) => {
                node_ids
                    .iter()
                    .filter_map(|id| cache.get_node(id).cloned())
                    .filter(|n| n.active)
                    .collect()
            }
            None => Vec::new(),
        }
    }

    /// Get node by ID.
    pub fn get_node(&self, node_id: &str) -> Option<NodeInfo> {
        self.state_cache.read().get_node(node_id).cloned()
    }

    // ════════════════════════════════════════════════════════════════════════
    // BACKGROUND REFRESH TASK
    // ════════════════════════════════════════════════════════════════════════

    /// Start background cache refresh task.
    ///
    /// # Arguments
    ///
    /// * `router` - Arc<DARouter> to refresh
    /// * `shutdown_rx` - watch::Receiver for shutdown signal
    ///
    /// # Returns
    ///
    /// JoinHandle untuk task.
    ///
    /// # Behavior
    ///
    /// - Periodically refresh cache berdasarkan cache_ttl_ms
    /// - Safe terhadap failure, timeout, data source unavailable
    /// - Tidak panic
    /// - Tidak memblokir main thread
    /// - Berhenti saat menerima shutdown signal
    pub fn start_background_refresh(
        router: Arc<DARouter>,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        let ttl = router.cache_ttl_ms;
        let interval = std::time::Duration::from_millis(ttl);

        tokio::spawn(async move {
            info!("DARouter: background refresh task started (interval: {}ms)", ttl);

            loop {
                tokio::select! {
                    _ = tokio::time::sleep(interval) => {
                        // Time to refresh
                    }
                    result = shutdown_rx.changed() => {
                        if result.is_err() || *shutdown_rx.borrow() {
                            info!("DARouter: background refresh task shutting down");
                            break;
                        }
                    }
                }

                // Refresh cache - safe against errors
                match router.refresh_cache() {
                    Ok(()) => {
                        debug!("DARouter: background refresh successful");
                    }
                    Err(e) => {
                        warn!("DARouter: background refresh failed: {}", e);
                        // Continue running - cache remains valid but stale
                    }
                }
            }

            info!("DARouter: background refresh task stopped");
        })
    }
}

// ════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════

/// Get current timestamp in Unix milliseconds.
fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    // ════════════════════════════════════════════════════════════════════════
    // MOCK DATA SOURCE
    // ════════════════════════════════════════════════════════════════════════

    struct MockDataSource {
        nodes: RwLock<HashMap<String, MockNodeInfo>>,
        placements: RwLock<HashMap<String, Vec<String>>>,
        should_fail: AtomicBool,
    }

    struct MockNodeInfo {
        addr: String,
        active: bool,
    }

    impl MockDataSource {
        fn new() -> Self {
            Self {
                nodes: RwLock::new(HashMap::new()),
                placements: RwLock::new(HashMap::new()),
                should_fail: AtomicBool::new(false),
            }
        }

        fn add_node(&self, id: &str, addr: &str, active: bool) {
            self.nodes.write().insert(id.to_string(), MockNodeInfo {
                addr: addr.to_string(),
                active,
            });
        }

        fn add_placement(&self, chunk_hash: &str, node_ids: Vec<&str>) {
            self.placements.write().insert(
                chunk_hash.to_string(),
                node_ids.into_iter().map(|s| s.to_string()).collect(),
            );
        }

        fn set_should_fail(&self, should_fail: bool) {
            self.should_fail.store(should_fail, Ordering::SeqCst);
        }
    }

    impl RoutingDataSource for MockDataSource {
        fn get_registered_node_ids(&self) -> RoutingResult<Vec<String>> {
            if self.should_fail.load(Ordering::SeqCst) {
                return Err(RoutingError("mock failure".to_string()));
            }
            Ok(self.nodes.read().keys().cloned().collect())
        }

        fn get_node_info(&self, node_id: &str) -> RoutingResult<Option<NodeInfoFromSource>> {
            if self.should_fail.load(Ordering::SeqCst) {
                return Err(RoutingError("mock failure".to_string()));
            }
            Ok(self.nodes.read().get(node_id).map(|n| NodeInfoFromSource {
                addr: n.addr.clone(),
                active: n.active,
            }))
        }

        fn get_all_chunk_placements(&self) -> RoutingResult<HashMap<String, Vec<String>>> {
            if self.should_fail.load(Ordering::SeqCst) {
                return Err(RoutingError("mock failure".to_string()));
            }
            Ok(self.placements.read().clone())
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 1: CACHE EMPTY → REFRESH → FILLED
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_cache_empty_refresh_filled() {
        let mock = Arc::new(MockDataSource::new());
        mock.add_node("node-1", "127.0.0.1:9001", true);
        mock.add_node("node-2", "127.0.0.1:9002", true);
        mock.add_placement("chunk-abc", vec!["node-1"]);

        let router = DARouter::new(mock);

        // Initially empty
        assert!(router.is_cache_empty());

        // Refresh
        router.refresh_cache().unwrap();

        // Now filled
        assert!(!router.is_cache_empty());

        let cache = router.get_cache();
        assert_eq!(cache.node_registry.len(), 2);
        assert_eq!(cache.chunk_placements.len(), 1);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 2: REFRESH FAILURE → CACHE NOT CORRUPTED
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_refresh_failure_cache_not_corrupted() {
        let mock = Arc::new(MockDataSource::new());
        mock.add_node("node-1", "127.0.0.1:9001", true);

        let router = DARouter::new(mock.clone());

        // Initial successful refresh
        router.refresh_cache().unwrap();
        assert_eq!(router.get_cache().node_registry.len(), 1);

        // Set to fail
        mock.set_should_fail(true);

        // Refresh should fail
        let result = router.refresh_cache();
        assert!(result.is_err());

        // Cache should remain intact (old data)
        assert_eq!(router.get_cache().node_registry.len(), 1);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 3: TTL EXPIRED CHECK
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_ttl_expired_check() {
        let mock = Arc::new(MockDataSource::new());
        mock.add_node("node-1", "127.0.0.1:9001", true);

        let router = DARouter::with_ttl(mock, 10); // 10ms TTL

        // Refresh
        router.refresh_cache().unwrap();

        // Immediately after refresh, not expired
        assert!(!router.is_cache_expired());

        // Wait for TTL to expire
        std::thread::sleep(std::time::Duration::from_millis(20));

        // Now should be expired
        assert!(router.is_cache_expired());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 4: CONCURRENT READ + REFRESH SAFE
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_concurrent_read_refresh_safe() {
        use std::thread;

        let mock = Arc::new(MockDataSource::new());
        for i in 0..10 {
            mock.add_node(&format!("node-{}", i), &format!("127.0.0.1:900{}", i), true);
        }

        let router = Arc::new(DARouter::new(mock));
        router.refresh_cache().unwrap();

        let mut handles = vec![];

        // Spawn readers
        for _ in 0..5 {
            let r = router.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    let _ = r.get_cache();
                    let _ = r.is_cache_expired();
                }
            }));
        }

        // Spawn refresher
        let r = router.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..10 {
                let _ = r.refresh_cache();
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }));

        for h in handles {
            h.join().unwrap();
        }

        // Should not panic
        assert!(!router.is_cache_empty());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 5: NO PANIC ON DA ERROR
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_no_panic_on_da_error() {
        let mock = Arc::new(MockDataSource::new());
        mock.set_should_fail(true);

        let router = DARouter::new(mock);

        // Should not panic, just return error
        let result = router.refresh_cache();
        assert!(result.is_err());

        // Cache should remain empty but valid
        assert!(router.is_cache_empty());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 6: GET NODES FOR CHUNK
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_get_nodes_for_chunk() {
        let mock = Arc::new(MockDataSource::new());
        mock.add_node("node-1", "127.0.0.1:9001", true);
        mock.add_node("node-2", "127.0.0.1:9002", true);
        mock.add_placement("chunk-abc", vec!["node-1", "node-2"]);

        let router = DARouter::new(mock);
        router.refresh_cache().unwrap();

        let nodes = router.get_nodes_for_chunk("chunk-abc");
        assert_eq!(nodes.len(), 2);

        let nonexistent = router.get_nodes_for_chunk("nonexistent");
        assert!(nonexistent.is_empty());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 7: INACTIVE NODES FILTERED
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_inactive_nodes_filtered() {
        let mock = Arc::new(MockDataSource::new());
        mock.add_node("node-1", "127.0.0.1:9001", true);
        mock.add_node("node-2", "127.0.0.1:9002", false); // inactive
        mock.add_placement("chunk-abc", vec!["node-1", "node-2"]);

        let router = DARouter::new(mock);
        router.refresh_cache().unwrap();

        let nodes = router.get_nodes_for_chunk("chunk-abc");
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].id, "node-1");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 8: CACHED ROUTING STATE METHODS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_cached_routing_state_methods() {
        let mut state = CachedRoutingState::new();
        assert!(state.is_empty());

        state.node_registry.insert("node-1".to_string(), NodeInfo::new(
            "node-1".to_string(),
            "127.0.0.1:9001".to_string(),
            true,
        ));
        state.chunk_placements.insert("chunk-1".to_string(), vec!["node-1".to_string()]);
        state.last_updated = current_timestamp_ms();

        assert!(!state.is_empty());
        assert!(state.get_node("node-1").is_some());
        assert!(state.get_placement("chunk-1").is_some());
        assert!(!state.is_expired(60000));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 9: DA ERROR DISPLAY
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_da_error_display() {
        let err = DAError::FetchError("connection refused".to_string());
        assert!(format!("{}", err).contains("connection refused"));

        let err = DAError::Other("unknown".to_string());
        assert!(format!("{}", err).contains("unknown"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 10: BACKGROUND REFRESH (ASYNC)
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_background_refresh_task() {
        let mock = Arc::new(MockDataSource::new());
        mock.add_node("node-1", "127.0.0.1:9001", true);

        let router = Arc::new(DARouter::with_ttl(mock, 50)); // 50ms TTL

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let handle = DARouter::start_background_refresh(router.clone(), shutdown_rx);

        // Wait for first refresh
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Cache should be filled
        assert!(!router.is_cache_empty());

        // Signal shutdown
        shutdown_tx.send(true).unwrap();
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Task should complete
        handle.await.unwrap();
    }
}