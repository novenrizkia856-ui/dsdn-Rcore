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
    /// Apakah node aktif (healthy).
    pub active: bool,
    /// Zone node (untuk zone affinity).
    pub zone: Option<String>,
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
// DA EVENTS
// ════════════════════════════════════════════════════════════════════════════

/// DA events yang memicu cache invalidation.
///
/// Setiap event memiliki semantik invalidation yang spesifik.
#[derive(Debug, Clone)]
pub enum DAEvent {
    /// Replica ditambahkan ke chunk.
    /// Aksi: Update placement cache untuk chunk.
    ReplicaAdded {
        chunk_hash: String,
        node_id: String,
    },
    /// Replica dihapus dari chunk.
    /// Aksi: Update placement cache untuk chunk.
    ReplicaRemoved {
        chunk_hash: String,
        node_id: String,
    },
    /// Node terdaftar (baru atau update).
    /// Aksi: Update node registry cache.
    NodeRegistered {
        node_id: String,
        addr: String,
        active: bool,
        zone: Option<String>,
    },
    /// Node di-unregister.
    /// Aksi: Remove dari node registry cache.
    NodeUnregistered {
        node_id: String,
    },
    /// Chunk deletion requested.
    /// Aksi: HAPUS TOTAL placement cache untuk chunk.
    DeleteRequested {
        chunk_hash: String,
    },
}

// ════════════════════════════════════════════════════════════════════════════
// ROUTER ERROR
// ════════════════════════════════════════════════════════════════════════════

/// Error yang dapat terjadi pada operasi placement query.
#[derive(Debug, Clone)]
pub enum RouterError {
    /// Chunk tidak ditemukan di placement registry.
    ChunkNotFound(String),
    /// Tidak ada node yang tersedia untuk chunk.
    NoAvailableNodes(String),
    /// Error saat mengakses data source.
    DataSourceError(String),
    /// Data inkonsisten (misalnya node_id ada di placement tapi tidak di registry).
    InconsistentData(String),
}

impl std::fmt::Display for RouterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RouterError::ChunkNotFound(hash) => {
                write!(f, "chunk not found: {}", hash)
            }
            RouterError::NoAvailableNodes(hash) => {
                write!(f, "no available nodes for chunk: {}", hash)
            }
            RouterError::DataSourceError(msg) => {
                write!(f, "data source error: {}", msg)
            }
            RouterError::InconsistentData(msg) => {
                write!(f, "inconsistent data: {}", msg)
            }
        }
    }
}

impl std::error::Error for RouterError {}

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
    /// Apakah node aktif (healthy).
    pub active: bool,
    /// Zone node (untuk zone affinity).
    pub zone: Option<String>,
}

impl NodeInfo {
    /// Membuat NodeInfo baru.
    pub fn new(id: String, addr: String, active: bool) -> Self {
        Self { id, addr, active, zone: None }
    }

    /// Membuat NodeInfo baru dengan zone.
    pub fn with_zone(id: String, addr: String, active: bool, zone: Option<String>) -> Self {
        Self { id, addr, active, zone }
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
    /// Chunks yang di-invalidate (soft invalidation).
    /// Key = chunk_hash, Value = timestamp invalidation.
    invalidated_chunks: HashMap<String, u64>,
    /// Nodes yang di-invalidate (soft invalidation).
    /// Key = node_id, Value = timestamp invalidation.
    invalidated_nodes: HashMap<String, u64>,
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

    /// Check apakah chunk di-invalidate (soft expiry).
    pub fn is_chunk_invalidated(&self, chunk_hash: &str) -> bool {
        self.invalidated_chunks.contains_key(chunk_hash)
    }

    /// Check apakah node di-invalidate (soft expiry).
    pub fn is_node_invalidated(&self, node_id: &str) -> bool {
        self.invalidated_nodes.contains_key(node_id)
    }

    /// Mark chunk sebagai invalidated.
    pub fn mark_chunk_invalidated(&mut self, chunk_hash: &str) {
        self.invalidated_chunks.insert(chunk_hash.to_string(), current_timestamp_ms());
    }

    /// Mark node sebagai invalidated.
    pub fn mark_node_invalidated(&mut self, node_id: &str) {
        self.invalidated_nodes.insert(node_id.to_string(), current_timestamp_ms());
    }

    /// Clear invalidation flag untuk chunk.
    pub fn clear_chunk_invalidation(&mut self, chunk_hash: &str) {
        self.invalidated_chunks.remove(chunk_hash);
    }

    /// Clear invalidation flag untuk node.
    pub fn clear_node_invalidation(&mut self, node_id: &str) {
        self.invalidated_nodes.remove(node_id);
    }

    /// Clear semua invalidation flags.
    pub fn clear_all_invalidations(&mut self) {
        self.invalidated_chunks.clear();
        self.invalidated_nodes.clear();
    }

    /// Check apakah ada invalidation pending.
    pub fn has_pending_invalidations(&self) -> bool {
        !self.invalidated_chunks.is_empty() || !self.invalidated_nodes.is_empty()
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
            invalidated_chunks: HashMap::new(),
            invalidated_nodes: HashMap::new(),
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
                    zone: info.zone,
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
    // PLACEMENT QUERY (14A.52)
    // ════════════════════════════════════════════════════════════════════════

    /// Get placement untuk chunk hash.
    ///
    /// # Arguments
    ///
    /// * `chunk_hash` - Hash dari chunk yang dicari
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<NodeInfo>)` - List node yang menyimpan chunk (hanya active nodes)
    /// * `Err(RouterError)` - Error jika chunk tidak ditemukan atau data inkonsisten
    ///
    /// # Behavior
    ///
    /// 1. Check cache terlebih dahulu
    /// 2. Jika cache stale/miss, fetch dari DA
    /// 3. Resolve node_ids ke NodeInfo
    /// 4. Filter hanya node yang active (healthy)
    ///
    /// # Thread Safety
    ///
    /// Method ini thread-safe menggunakan RwLock.
    pub fn get_placement(&self, chunk_hash: &str) -> Result<Vec<NodeInfo>, RouterError> {
        // Check if cache needs refresh (stale or empty)
        let needs_refresh = {
            let cache = self.state_cache.read();
            cache.is_empty() || cache.is_expired(self.cache_ttl_ms)
        };

        // Refresh cache if needed
        if needs_refresh {
            self.refresh_cache()
                .map_err(|e| RouterError::DataSourceError(e.to_string()))?;
        }

        // Read from cache
        let cache = self.state_cache.read();

        // Check if chunk exists in placements
        let node_ids = cache.get_placement(chunk_hash)
            .ok_or_else(|| RouterError::ChunkNotFound(chunk_hash.to_string()))?;

        // Resolve node_ids to NodeInfo, filter active only
        let mut nodes: Vec<NodeInfo> = Vec::new();
        for node_id in node_ids {
            match cache.get_node(node_id) {
                Some(node) if node.active => {
                    nodes.push(node.clone());
                }
                Some(_) => {
                    // Node exists but inactive (unhealthy) - skip silently
                }
                None => {
                    // Node ID in placement but not in registry - inconsistent data
                    return Err(RouterError::InconsistentData(
                        format!("node {} in placement but not in registry", node_id)
                    ));
                }
            }
        }

        // Check if we have any available nodes
        if nodes.is_empty() {
            return Err(RouterError::NoAvailableNodes(chunk_hash.to_string()));
        }

        Ok(nodes)
    }

    /// Get best node untuk chunk hash.
    ///
    /// # Arguments
    ///
    /// * `chunk_hash` - Hash dari chunk yang dicari
    /// * `client_zone` - Zone client (untuk zone affinity)
    ///
    /// # Returns
    ///
    /// * `Ok(NodeInfo)` - Node terbaik yang dipilih
    /// * `Err(RouterError)` - Error jika tidak ada node tersedia
    ///
    /// # Selection Priority (URUTAN TIDAK BOLEH DIUBAH)
    ///
    /// 1. Zone affinity: prefer node dengan zone sama dengan client
    /// 2. Node health: node unhealthy (active=false) TIDAK BOLEH dipilih
    /// 3. Tie-breaker: deterministik by node ID (sorted ascending)
    ///
    /// # Thread Safety
    ///
    /// Method ini thread-safe.
    pub fn get_best_node(
        &self,
        chunk_hash: &str,
        client_zone: Option<&str>,
    ) -> Result<NodeInfo, RouterError> {
        // Step 1: Get all available nodes (already filtered by health/active)
        let nodes = self.get_placement(chunk_hash)?;

        // Nodes is guaranteed non-empty by get_placement

        // Step 2: Apply zone affinity if client_zone is provided
        if let Some(zone) = client_zone {
            // Separate nodes into same-zone and different-zone
            let (same_zone, diff_zone): (Vec<_>, Vec<_>) = nodes
                .into_iter()
                .partition(|n| n.zone.as_deref() == Some(zone));

            // Prefer same-zone nodes if any
            let candidates = if !same_zone.is_empty() {
                same_zone
            } else {
                diff_zone
            };

            // Step 3: Deterministik selection by node ID (sorted ascending)
            return Self::select_deterministic(candidates, chunk_hash);
        }

        // No zone affinity - just deterministic selection
        Self::select_deterministic(nodes, chunk_hash)
    }

    /// Deterministic node selection.
    ///
    /// Sorts nodes by ID ascending and returns the first one.
    /// This ensures consistent selection across calls.
    fn select_deterministic(
        mut nodes: Vec<NodeInfo>,
        chunk_hash: &str,
    ) -> Result<NodeInfo, RouterError> {
        if nodes.is_empty() {
            return Err(RouterError::NoAvailableNodes(chunk_hash.to_string()));
        }

        // Sort by node ID for deterministic selection
        nodes.sort_by(|a, b| a.id.cmp(&b.id));

        // Return first node (lowest ID)
        Ok(nodes.into_iter().next().expect("nodes is non-empty"))
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

    // ════════════════════════════════════════════════════════════════════════
    // CACHE INVALIDATION (14A.58)
    // ════════════════════════════════════════════════════════════════════════

    /// Subscribe ke DA event stream untuk cache invalidation.
    ///
    /// # Returns
    ///
    /// - `Ok(())`: Subscription berhasil
    /// - `Err(DAError)`: Subscription gagal
    ///
    /// # Behavior
    ///
    /// - Subscribe ke DA event stream
    /// - Proses events secara thread-safe
    /// - Tidak memblokir routing path
    ///
    /// # Note
    ///
    /// Saat ini method ini placeholder yang selalu berhasil.
    /// Implementasi konkret akan connect ke DA event stream.
    #[allow(dead_code)]
    pub fn subscribe_invalidations(&self) -> Result<(), DAError> {
        info!("DARouter: subscribing to DA invalidation events");
        // Placeholder - actual implementation would connect to DA event stream
        // For now, we rely on:
        // 1. TTL-based soft expiry
        // 2. Manual invalidation via invalidate_chunk/invalidate_node
        Ok(())
    }

    /// Invalidate chunk placement dari cache.
    ///
    /// # Arguments
    ///
    /// * `chunk_hash` - Hash chunk yang akan di-invalidate
    ///
    /// # Behavior
    ///
    /// - HAPUS entry chunk dari placement cache
    /// - Thread-safe (menggunakan write lock)
    /// - Tidak panic jika chunk tidak ada
    /// - Tidak mempengaruhi node registry
    ///
    /// # Use Cases
    ///
    /// - `ReplicaAdded`: Invalidate untuk force refresh dari DA
    /// - `ReplicaRemoved`: Invalidate untuk force refresh dari DA
    /// - `DeleteRequested`: Hapus total placement
    pub fn invalidate_chunk(&self, chunk_hash: &str) {
        debug!("DARouter: invalidating chunk placement: {}", chunk_hash);
        let mut cache = self.state_cache.write();
        cache.chunk_placements.remove(chunk_hash);
    }

    /// Invalidate node dari cache.
    ///
    /// # Arguments
    ///
    /// * `node_id` - ID node yang akan di-invalidate
    ///
    /// # Behavior
    ///
    /// - HAPUS entry node dari node registry
    /// - Thread-safe (menggunakan write lock)
    /// - Tidak panic jika node tidak ada
    /// - Tidak mempengaruhi placement cache
    ///
    /// # Note
    ///
    /// Setelah invalidate node, placement yang reference node tersebut
    /// akan mendapat InconsistentData error saat query.
    /// Caller harus juga refresh placement atau invalidate related chunks.
    pub fn invalidate_node(&self, node_id: &str) {
        debug!("DARouter: invalidating node: {}", node_id);
        let mut cache = self.state_cache.write();
        cache.node_registry.remove(node_id);
    }

    /// Invalidate seluruh cache.
    ///
    /// # Behavior
    ///
    /// - Clear node registry
    /// - Clear chunk placements
    /// - Reset last_updated ke 0
    /// - Thread-safe
    ///
    /// # Use Case
    ///
    /// - Full cache reset saat DA state tidak sinkron
    /// - Recovery dari inconsistent state
    pub fn invalidate_all(&self) {
        debug!("DARouter: invalidating all cache");
        let mut cache = self.state_cache.write();
        cache.node_registry.clear();
        cache.chunk_placements.clear();
        cache.last_updated = 0;
    }

    /// Process DA event untuk cache invalidation.
    ///
    /// # Arguments
    ///
    /// * `event` - DA event yang akan diproses
    ///
    /// # Returns
    ///
    /// - `Ok(())`: Event berhasil diproses
    /// - `Err(DAError)`: Error saat proses event (jika perlu refresh dari DA)
    ///
    /// # Event Handling (PERSIS sesuai spec)
    ///
    /// - `ReplicaAdded`: Update placement cache untuk chunk
    /// - `ReplicaRemoved`: Update placement cache untuk chunk  
    /// - `NodeRegistered`: Update node cache
    /// - `DeleteRequested`: HAPUS TOTAL placement cache untuk chunk
    ///
    /// # Thread Safety
    ///
    /// Method ini thread-safe. Semua updates atomic.
    pub fn process_da_event(&self, event: DAEvent) -> Result<(), DAError> {
        match event {
            DAEvent::ReplicaAdded { chunk_hash, node_id } => {
                info!(
                    "DARouter: processing ReplicaAdded event: chunk={}, node={}",
                    chunk_hash, node_id
                );
                // Update placement: add node to chunk's placement list
                let mut cache = self.state_cache.write();
                cache
                    .chunk_placements
                    .entry(chunk_hash)
                    .or_insert_with(Vec::new)
                    .push(node_id);
                Ok(())
            }

            DAEvent::ReplicaRemoved { chunk_hash, node_id } => {
                info!(
                    "DARouter: processing ReplicaRemoved event: chunk={}, node={}",
                    chunk_hash, node_id
                );
                // Update placement: remove node from chunk's placement list
                let mut cache = self.state_cache.write();
                if let Some(nodes) = cache.chunk_placements.get_mut(&chunk_hash) {
                    nodes.retain(|n| n != &node_id);
                    // Remove chunk entry if no nodes left
                    if nodes.is_empty() {
                        cache.chunk_placements.remove(&chunk_hash);
                    }
                }
                Ok(())
            }

            DAEvent::NodeRegistered { node_id, addr, active, zone } => {
                info!(
                    "DARouter: processing NodeRegistered event: node={}, active={}",
                    node_id, active
                );
                // Update node registry
                let mut cache = self.state_cache.write();
                cache.node_registry.insert(
                    node_id.clone(),
                    NodeInfo {
                        id: node_id,
                        addr,
                        active,
                        zone,
                    },
                );
                Ok(())
            }

            DAEvent::DeleteRequested { chunk_hash } => {
                info!(
                    "DARouter: processing DeleteRequested event: chunk={}",
                    chunk_hash
                );
                // HAPUS TOTAL placement untuk chunk
                let mut cache = self.state_cache.write();
                cache.chunk_placements.remove(&chunk_hash);
                Ok(())
            }

            DAEvent::NodeUnregistered { node_id } => {
                info!(
                    "DARouter: processing NodeUnregistered event: node={}",
                    node_id
                );
                // Remove node dari registry
                let mut cache = self.state_cache.write();
                cache.node_registry.remove(&node_id);
                Ok(())
            }
        }
    }

    /// Check if cache is in soft-expired state.
    ///
    /// Soft expiry means:
    /// - Cache can still be read
    /// - But should be refreshed soon
    ///
    /// # Returns
    ///
    /// - `true` if cache is past TTL but still readable
    /// - `false` if cache is fresh or empty
    pub fn is_soft_expired(&self) -> bool {
        let cache = self.state_cache.read();
        if cache.last_updated == 0 {
            return false; // Never filled, not "soft expired"
        }
        cache.is_expired(self.cache_ttl_ms)
    }

    /// Get cache age in milliseconds.
    ///
    /// # Returns
    ///
    /// - Age in ms since last update
    /// - u64::MAX if cache never updated
    pub fn get_cache_age_ms(&self) -> u64 {
        let cache = self.state_cache.read();
        if cache.last_updated == 0 {
            return u64::MAX;
        }
        current_timestamp_ms().saturating_sub(cache.last_updated)
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
        zone: Option<String>,
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
                zone: None,
            });
        }

        fn add_node_with_zone(&self, id: &str, addr: &str, active: bool, zone: Option<&str>) {
            self.nodes.write().insert(id.to_string(), MockNodeInfo {
                addr: addr.to_string(),
                active,
                zone: zone.map(|s| s.to_string()),
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
                zone: n.zone.clone(),
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

    // ════════════════════════════════════════════════════════════════════════
    // TEST 11: GET_PLACEMENT CACHE HIT (NO FETCH)
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_get_placement_cache_hit_no_fetch() {
        let mock = Arc::new(MockDataSource::new());
        mock.add_node("node-1", "127.0.0.1:9001", true);
        mock.add_placement("chunk-abc", vec!["node-1"]);

        let router = DARouter::new(mock.clone());

        // Pre-fill cache
        router.refresh_cache().unwrap();

        // Now set mock to fail - if get_placement fetches, it will error
        mock.set_should_fail(true);

        // get_placement should succeed (cache hit, no fetch)
        let result = router.get_placement("chunk-abc");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 12: GET_PLACEMENT CACHE MISS → FETCH → UPDATE
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_get_placement_cache_miss_fetch_update() {
        let mock = Arc::new(MockDataSource::new());
        mock.add_node("node-1", "127.0.0.1:9001", true);
        mock.add_placement("chunk-abc", vec!["node-1"]);

        let router = DARouter::new(mock);

        // Cache is empty - should trigger fetch
        assert!(router.is_cache_empty());

        // get_placement should fetch and update cache
        let result = router.get_placement("chunk-abc");
        assert!(result.is_ok());

        // Cache should now be filled
        assert!(!router.is_cache_empty());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 13: GET_PLACEMENT CHUNK NOT FOUND
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_get_placement_chunk_not_found() {
        let mock = Arc::new(MockDataSource::new());
        mock.add_node("node-1", "127.0.0.1:9001", true);

        let router = DARouter::new(mock);
        router.refresh_cache().unwrap();

        // Query non-existent chunk
        let result = router.get_placement("nonexistent-chunk");
        assert!(result.is_err());

        match result.unwrap_err() {
            RouterError::ChunkNotFound(hash) => {
                assert_eq!(hash, "nonexistent-chunk");
            }
            _ => panic!("Expected ChunkNotFound error"),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14: GET_BEST_NODE ZONE AFFINITY PRIORITIZED
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_get_best_node_zone_affinity_prioritized() {
        let mock = Arc::new(MockDataSource::new());
        mock.add_node_with_zone("node-1", "127.0.0.1:9001", true, Some("zone-a"));
        mock.add_node_with_zone("node-2", "127.0.0.1:9002", true, Some("zone-b"));
        mock.add_node_with_zone("node-3", "127.0.0.1:9003", true, Some("zone-a"));
        mock.add_placement("chunk-abc", vec!["node-1", "node-2", "node-3"]);

        let router = DARouter::new(mock);
        router.refresh_cache().unwrap();

        // Client in zone-a should get node from zone-a
        let result = router.get_best_node("chunk-abc", Some("zone-a"));
        assert!(result.is_ok());
        let node = result.unwrap();
        assert_eq!(node.zone, Some("zone-a".to_string()));

        // Client in zone-b should get node from zone-b
        let result = router.get_best_node("chunk-abc", Some("zone-b"));
        assert!(result.is_ok());
        let node = result.unwrap();
        assert_eq!(node.id, "node-2"); // Only node in zone-b
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 15: GET_BEST_NODE UNHEALTHY NODES NOT SELECTED
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_get_best_node_unhealthy_not_selected() {
        let mock = Arc::new(MockDataSource::new());
        mock.add_node_with_zone("node-1", "127.0.0.1:9001", false, Some("zone-a")); // unhealthy
        mock.add_node_with_zone("node-2", "127.0.0.1:9002", true, Some("zone-a"));  // healthy
        mock.add_placement("chunk-abc", vec!["node-1", "node-2"]);

        let router = DARouter::new(mock);
        router.refresh_cache().unwrap();

        // Should select node-2 (healthy), not node-1 (unhealthy)
        let result = router.get_best_node("chunk-abc", Some("zone-a"));
        assert!(result.is_ok());
        let node = result.unwrap();
        assert_eq!(node.id, "node-2");
        assert!(node.active);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 16: GET_BEST_NODE DETERMINISTIC SELECTION (SORTED BY ID)
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_get_best_node_deterministic_selection() {
        let mock = Arc::new(MockDataSource::new());
        // Add nodes in non-sorted order
        mock.add_node("node-z", "127.0.0.1:9003", true);
        mock.add_node("node-a", "127.0.0.1:9001", true);
        mock.add_node("node-m", "127.0.0.1:9002", true);
        mock.add_placement("chunk-abc", vec!["node-z", "node-a", "node-m"]);

        let router = DARouter::new(mock);
        router.refresh_cache().unwrap();

        // Should deterministically select node-a (lowest ID)
        let result1 = router.get_best_node("chunk-abc", None);
        assert!(result1.is_ok());
        assert_eq!(result1.unwrap().id, "node-a");

        // Call again - should be same result (deterministic)
        let result2 = router.get_best_node("chunk-abc", None);
        assert!(result2.is_ok());
        assert_eq!(result2.unwrap().id, "node-a");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 17: CONCURRENT READ + GET_PLACEMENT SAFE
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_concurrent_read_get_placement_safe() {
        use std::thread;

        let mock = Arc::new(MockDataSource::new());
        for i in 0..5 {
            mock.add_node(&format!("node-{}", i), &format!("127.0.0.1:900{}", i), true);
        }
        mock.add_placement("chunk-abc", vec!["node-0", "node-1", "node-2"]);

        let router = Arc::new(DARouter::new(mock));
        router.refresh_cache().unwrap();

        let mut handles = vec![];

        // Spawn readers using get_placement
        for _ in 0..5 {
            let r = router.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    let result = r.get_placement("chunk-abc");
                    assert!(result.is_ok());
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
    // TEST 18: GET_PLACEMENT ALL NODES UNHEALTHY → ERROR
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_get_placement_all_nodes_unhealthy() {
        let mock = Arc::new(MockDataSource::new());
        mock.add_node("node-1", "127.0.0.1:9001", false); // unhealthy
        mock.add_node("node-2", "127.0.0.1:9002", false); // unhealthy
        mock.add_placement("chunk-abc", vec!["node-1", "node-2"]);

        let router = DARouter::new(mock);
        router.refresh_cache().unwrap();

        // Should return error (no available nodes)
        let result = router.get_placement("chunk-abc");
        assert!(result.is_err());

        match result.unwrap_err() {
            RouterError::NoAvailableNodes(hash) => {
                assert_eq!(hash, "chunk-abc");
            }
            _ => panic!("Expected NoAvailableNodes error"),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 19: GET_BEST_NODE NO ZONE MATCH → FALLBACK DETERMINISTIC
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_get_best_node_no_zone_match_fallback() {
        let mock = Arc::new(MockDataSource::new());
        mock.add_node_with_zone("node-b", "127.0.0.1:9002", true, Some("zone-x"));
        mock.add_node_with_zone("node-a", "127.0.0.1:9001", true, Some("zone-x"));
        mock.add_placement("chunk-abc", vec!["node-b", "node-a"]);

        let router = DARouter::new(mock);
        router.refresh_cache().unwrap();

        // Client in zone-y (no match) - should fallback to deterministic (node-a, lowest ID)
        let result = router.get_best_node("chunk-abc", Some("zone-y"));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().id, "node-a");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 20: ROUTER ERROR DISPLAY
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_router_error_display() {
        let err = RouterError::ChunkNotFound("abc123".to_string());
        assert!(format!("{}", err).contains("chunk not found"));
        assert!(format!("{}", err).contains("abc123"));

        let err = RouterError::NoAvailableNodes("def456".to_string());
        assert!(format!("{}", err).contains("no available nodes"));

        let err = RouterError::DataSourceError("connection failed".to_string());
        assert!(format!("{}", err).contains("data source error"));

        let err = RouterError::InconsistentData("node missing".to_string());
        assert!(format!("{}", err).contains("inconsistent data"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 21: INVALIDATION ON REPLICA ADDED
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_invalidation_on_replica_added() {
        let mock = Arc::new(MockDataSource::new());
        mock.add_node("node-1", "127.0.0.1:9001", true);
        mock.add_node("node-2", "127.0.0.1:9002", true);
        mock.add_placement("chunk-abc", vec!["node-1"]);

        let router = DARouter::new(mock);
        router.refresh_cache().unwrap();

        // Initially only node-1
        let cache = router.get_cache();
        assert_eq!(cache.chunk_placements.get("chunk-abc").unwrap().len(), 1);

        // Process ReplicaAdded event
        let event = DAEvent::ReplicaAdded {
            chunk_hash: "chunk-abc".to_string(),
            node_id: "node-2".to_string(),
        };
        router.process_da_event(event).unwrap();

        // Now should have 2 nodes
        let cache = router.get_cache();
        let nodes = cache.chunk_placements.get("chunk-abc").unwrap();
        assert_eq!(nodes.len(), 2);
        assert!(nodes.contains(&"node-1".to_string()));
        assert!(nodes.contains(&"node-2".to_string()));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 22: INVALIDATION ON REPLICA REMOVED
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_invalidation_on_replica_removed() {
        let mock = Arc::new(MockDataSource::new());
        mock.add_node("node-1", "127.0.0.1:9001", true);
        mock.add_node("node-2", "127.0.0.1:9002", true);
        mock.add_placement("chunk-abc", vec!["node-1", "node-2"]);

        let router = DARouter::new(mock);
        router.refresh_cache().unwrap();

        // Initially 2 nodes
        let cache = router.get_cache();
        assert_eq!(cache.chunk_placements.get("chunk-abc").unwrap().len(), 2);

        // Process ReplicaRemoved event
        let event = DAEvent::ReplicaRemoved {
            chunk_hash: "chunk-abc".to_string(),
            node_id: "node-2".to_string(),
        };
        router.process_da_event(event).unwrap();

        // Now should have only 1 node
        let cache = router.get_cache();
        let nodes = cache.chunk_placements.get("chunk-abc").unwrap();
        assert_eq!(nodes.len(), 1);
        assert!(nodes.contains(&"node-1".to_string()));
        assert!(!nodes.contains(&"node-2".to_string()));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 23: INVALIDATION ON NODE REGISTERED
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_invalidation_on_node_registered() {
        let mock = Arc::new(MockDataSource::new());
        mock.add_node("node-1", "127.0.0.1:9001", true);

        let router = DARouter::new(mock);
        router.refresh_cache().unwrap();

        // Initially 1 node
        let cache = router.get_cache();
        assert_eq!(cache.node_registry.len(), 1);

        // Process NodeRegistered event for new node
        let event = DAEvent::NodeRegistered {
            node_id: "node-2".to_string(),
            addr: "127.0.0.1:9002".to_string(),
            active: true,
            zone: Some("zone-a".to_string()),
        };
        router.process_da_event(event).unwrap();

        // Now should have 2 nodes
        let cache = router.get_cache();
        assert_eq!(cache.node_registry.len(), 2);
        let node2 = cache.node_registry.get("node-2").unwrap();
        assert_eq!(node2.addr, "127.0.0.1:9002");
        assert!(node2.active);
        assert_eq!(node2.zone, Some("zone-a".to_string()));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 24: REMOVAL CACHE ON DELETE REQUESTED
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_removal_cache_on_delete_requested() {
        let mock = Arc::new(MockDataSource::new());
        mock.add_node("node-1", "127.0.0.1:9001", true);
        mock.add_placement("chunk-abc", vec!["node-1"]);
        mock.add_placement("chunk-xyz", vec!["node-1"]);

        let router = DARouter::new(mock);
        router.refresh_cache().unwrap();

        // Initially 2 placements
        let cache = router.get_cache();
        assert_eq!(cache.chunk_placements.len(), 2);
        assert!(cache.chunk_placements.contains_key("chunk-abc"));

        // Process DeleteRequested event
        let event = DAEvent::DeleteRequested {
            chunk_hash: "chunk-abc".to_string(),
        };
        router.process_da_event(event).unwrap();

        // Now should have only 1 placement
        let cache = router.get_cache();
        assert_eq!(cache.chunk_placements.len(), 1);
        assert!(!cache.chunk_placements.contains_key("chunk-abc"));
        assert!(cache.chunk_placements.contains_key("chunk-xyz"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 25: TTL SOFT EXPIRY BEHAVIOR
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_ttl_soft_expiry_behavior() {
        let mock = Arc::new(MockDataSource::new());
        mock.add_node("node-1", "127.0.0.1:9001", true);
        mock.add_placement("chunk-abc", vec!["node-1"]);

        let router = DARouter::with_ttl(mock, 10); // 10ms TTL
        
        // Before refresh - not soft expired (never filled)
        assert!(!router.is_soft_expired());
        
        // Refresh cache
        router.refresh_cache().unwrap();
        
        // Immediately after refresh - not soft expired
        assert!(!router.is_soft_expired());
        
        // Cache should still be readable
        let cache = router.get_cache();
        assert_eq!(cache.node_registry.len(), 1);
        
        // Wait for TTL to expire
        std::thread::sleep(std::time::Duration::from_millis(20));
        
        // Now should be soft expired
        assert!(router.is_soft_expired());
        
        // But cache should still be readable (soft expiry)
        let cache = router.get_cache();
        assert_eq!(cache.node_registry.len(), 1);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 26: THREAD-SAFETY INVALIDATION
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_thread_safety_invalidation() {
        use std::thread;

        let mock = Arc::new(MockDataSource::new());
        for i in 0..10 {
            mock.add_node(&format!("node-{}", i), &format!("127.0.0.1:900{}", i), true);
            mock.add_placement(&format!("chunk-{}", i), vec![&format!("node-{}", i)]);
        }

        let router = Arc::new(DARouter::new(mock));
        router.refresh_cache().unwrap();

        let mut handles = vec![];

        // Spawn readers
        for _ in 0..5 {
            let r = router.clone();
            handles.push(thread::spawn(move || {
                for i in 0..100 {
                    let _ = r.get_cache();
                    let _ = r.get_nodes_for_chunk(&format!("chunk-{}", i % 10));
                }
            }));
        }

        // Spawn invalidators
        for _ in 0..3 {
            let r = router.clone();
            handles.push(thread::spawn(move || {
                for i in 0..50 {
                    r.invalidate_chunk(&format!("chunk-{}", i % 10));
                    let event = DAEvent::ReplicaAdded {
                        chunk_hash: format!("chunk-{}", i % 10),
                        node_id: format!("node-{}", i % 10),
                    };
                    let _ = r.process_da_event(event);
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        // Should not panic or deadlock
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 27: NO STALE PLACEMENT AFTER EVENT
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_no_stale_placement_after_event() {
        let mock = Arc::new(MockDataSource::new());
        mock.add_node("node-1", "127.0.0.1:9001", true);
        mock.add_node("node-2", "127.0.0.1:9002", true);
        mock.add_placement("chunk-abc", vec!["node-1"]);

        let router = DARouter::new(mock);
        router.refresh_cache().unwrap();

        // Get initial placement
        let nodes = router.get_nodes_for_chunk("chunk-abc");
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].id, "node-1");

        // Process ReplicaAdded event
        let event = DAEvent::ReplicaAdded {
            chunk_hash: "chunk-abc".to_string(),
            node_id: "node-2".to_string(),
        };
        router.process_da_event(event).unwrap();

        // Get placement again - should reflect update
        let nodes = router.get_nodes_for_chunk("chunk-abc");
        assert_eq!(nodes.len(), 2);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 28: NO PANIC ON INVALIDATE NONEXISTENT
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_no_panic_on_invalidate_nonexistent() {
        let mock = Arc::new(MockDataSource::new());
        mock.add_node("node-1", "127.0.0.1:9001", true);

        let router = DARouter::new(mock);
        router.refresh_cache().unwrap();

        // Invalidate non-existent chunk - should not panic
        router.invalidate_chunk("nonexistent-chunk");

        // Invalidate non-existent node - should not panic
        router.invalidate_node("nonexistent-node");

        // Process event for non-existent chunk - should not panic
        let event = DAEvent::ReplicaRemoved {
            chunk_hash: "nonexistent-chunk".to_string(),
            node_id: "node-1".to_string(),
        };
        router.process_da_event(event).unwrap();

        // Cache should remain valid
        assert_eq!(router.get_cache().node_registry.len(), 1);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 29: INVALIDATE ALL
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_invalidate_all() {
        let mock = Arc::new(MockDataSource::new());
        mock.add_node("node-1", "127.0.0.1:9001", true);
        mock.add_node("node-2", "127.0.0.1:9002", true);
        mock.add_placement("chunk-abc", vec!["node-1"]);
        mock.add_placement("chunk-xyz", vec!["node-2"]);

        let router = DARouter::new(mock);
        router.refresh_cache().unwrap();

        // Verify cache is filled
        let cache = router.get_cache();
        assert_eq!(cache.node_registry.len(), 2);
        assert_eq!(cache.chunk_placements.len(), 2);
        assert!(cache.last_updated > 0);

        // Invalidate all
        router.invalidate_all();

        // Cache should be empty
        let cache = router.get_cache();
        assert_eq!(cache.node_registry.len(), 0);
        assert_eq!(cache.chunk_placements.len(), 0);
        assert_eq!(cache.last_updated, 0);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 30: SUBSCRIBE INVALIDATIONS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_subscribe_invalidations() {
        let mock = Arc::new(MockDataSource::new());
        let router = DARouter::new(mock);

        // Should succeed (placeholder implementation)
        let result = router.subscribe_invalidations();
        assert!(result.is_ok());
    }
}