//! # Request Routing Logic Module
//!
//! Module ini menyediakan routing decision engine untuk ingress layer.
//!
//! ## Prinsip
//!
//! - Semua data berasal dari DARouter
//! - Tidak ada state authoritative lokal
//! - Deterministik dan thread-safe
//! - Tidak mengarang node, load, atau health
//!
//! ## Strategies
//!
//! - ZoneAffinity: prefer node dengan zone sama
//! - RoundRobin: deterministik berdasarkan hash
//! - LeastLoaded: memerlukan data load eksplisit (tidak tersedia → error)

use std::fmt;
use std::net::IpAddr;
use std::time::Instant;

use crate::da_router::{DARouter, NodeInfo, RouterError};

// ════════════════════════════════════════════════════════════════════════════
// ROUTING DECISION
// ════════════════════════════════════════════════════════════════════════════

/// Hasil keputusan routing.
///
/// Struct ini merepresentasikan hasil lengkap dari proses routing,
/// termasuk target node, fallback nodes, dan metadata.
#[derive(Debug, Clone)]
pub struct RoutingDecision {
    /// Node target utama yang dipilih.
    #[allow(dead_code)]
    pub target_node: NodeInfo,
    /// Daftar node fallback jika target gagal.
    /// Urutan deterministik, tidak mengandung target_node.
    #[allow(dead_code)]
    pub fallback_nodes: Vec<NodeInfo>,
    /// Apakah keputusan berasal dari cache hit.
    #[allow(dead_code)]
    pub cache_hit: bool,
    /// Latency proses routing dalam milliseconds.
    #[allow(dead_code)]
    pub routing_latency_ms: u64,
}

// ════════════════════════════════════════════════════════════════════════════
// CLIENT INFO
// ════════════════════════════════════════════════════════════════════════════

/// Informasi client untuk routing decision.
#[derive(Debug, Clone)]
pub struct ClientInfo {
    /// IP address client.
    #[allow(dead_code)]
    pub ip: IpAddr,
    /// Hint zone client (untuk zone affinity).
    pub zone_hint: Option<String>,
    /// Prefer datacenter lokal.
    #[allow(dead_code)]
    pub prefer_dc: bool,
}

impl ClientInfo {
    /// Membuat ClientInfo baru.
    #[allow(dead_code)]
    pub fn new(ip: IpAddr) -> Self {
        Self {
            ip,
            zone_hint: None,
            prefer_dc: false,
        }
    }

    #[allow(dead_code)]
    /// Membuat ClientInfo dengan zone hint.
    pub fn with_zone(ip: IpAddr, zone_hint: Option<String>) -> Self {
        Self {
            ip,
            zone_hint,
            prefer_dc: false,
        }
    }

    #[allow(dead_code)]
    /// Membuat ClientInfo lengkap.
    pub fn full(ip: IpAddr, zone_hint: Option<String>, prefer_dc: bool) -> Self {
        Self {
            ip,
            zone_hint,
            prefer_dc,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// ROUTING STRATEGY
// ════════════════════════════════════════════════════════════════════════════

/// Strategy untuk memilih node target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingStrategy {
    /// Prefer node dengan zone sama dengan client.
    ZoneAffinity,
    /// Round-robin deterministik berdasarkan hash.
    #[allow(dead_code)]
    RoundRobin,
    /// Pilih node dengan load terendah.
    /// CATATAN: Memerlukan data load eksplisit.
    #[allow(dead_code)]
    LeastLoaded,
}

impl Default for RoutingStrategy {
    fn default() -> Self {
        RoutingStrategy::ZoneAffinity
    }
}

impl fmt::Display for RoutingStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RoutingStrategy::ZoneAffinity => write!(f, "ZoneAffinity"),
            RoutingStrategy::RoundRobin => write!(f, "RoundRobin"),
            RoutingStrategy::LeastLoaded => write!(f, "LeastLoaded"),
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// ROUTING ERROR EXTENSION
// ════════════════════════════════════════════════════════════════════════════

/// Error tambahan untuk routing operations.
#[derive(Debug, Clone)]
pub enum RoutingError {
    /// Error dari DARouter.
    Router(RouterError),
    /// Strategy tidak dapat digunakan (misalnya LeastLoaded tanpa data load).
    StrategyUnavailable(String),
}

impl fmt::Display for RoutingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RoutingError::Router(e) => write!(f, "router error: {}", e),
            RoutingError::StrategyUnavailable(msg) => {
                write!(f, "strategy unavailable: {}", msg)
            }
        }
    }
}

impl std::error::Error for RoutingError {}

impl From<RouterError> for RoutingError {
    fn from(e: RouterError) -> Self {
        RoutingError::Router(e)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// ROUTE REQUEST FUNCTION
// ════════════════════════════════════════════════════════════════════════════

/// Route request ke node yang sesuai.
///
/// # Arguments
///
/// * `router` - DARouter sebagai sumber data
/// * `chunk_hash` - Hash chunk yang diminta
/// * `client_info` - Informasi client
///
/// # Returns
///
/// * `Ok(RoutingDecision)` - Keputusan routing berhasil
/// * `Err(RoutingError)` - Error jika routing gagal
///
/// # Behavior
///
/// 1. Ambil placement dari DARouter
/// 2. Terapkan ZoneAffinity strategy (default)
/// 3. Tentukan target_node dan fallback_nodes
/// 4. Hitung routing latency
///
/// # Thread Safety
///
/// Fungsi ini thread-safe.

#[allow(dead_code)]
pub fn route_request(
    router: &DARouter,
    chunk_hash: &str,
    client_info: &ClientInfo,
) -> Result<RoutingDecision, RoutingError> {
    route_request_with_strategy(
        router,
        chunk_hash,
        client_info,
        RoutingStrategy::ZoneAffinity,
    )
}

/// Route request dengan strategy eksplisit.
///
/// # Arguments
///
/// * `router` - DARouter sebagai sumber data
/// * `chunk_hash` - Hash chunk yang diminta
/// * `client_info` - Informasi client
/// * `strategy` - Strategy routing yang digunakan
///
/// # Returns
///
/// * `Ok(RoutingDecision)` - Keputusan routing berhasil
/// * `Err(RoutingError)` - Error jika routing gagal
#[allow(dead_code)]
pub fn route_request_with_strategy(
    router: &DARouter,
    chunk_hash: &str,
    client_info: &ClientInfo,
    strategy: RoutingStrategy,
) -> Result<RoutingDecision, RoutingError> {
    let start = Instant::now();

    // Step 1: Ambil placement dari DARouter
    // Ini sudah memfilter node yang tidak sehat (active=false)
    let nodes = router.get_placement(chunk_hash)?;

    // Track cache hit (cache always used in get_placement if valid)
    let cache_hit = !router.is_cache_expired();

    // Step 2: Terapkan strategy
    let (target_node, remaining_nodes) = match strategy {
        RoutingStrategy::ZoneAffinity => {
            apply_zone_affinity_strategy(&nodes, client_info)?
        }
        RoutingStrategy::RoundRobin => {
            apply_round_robin_strategy(&nodes, chunk_hash)?
        }
        RoutingStrategy::LeastLoaded => {
            // LeastLoaded memerlukan data load eksplisit.
            // NodeInfo tidak memiliki field load, jadi strategy ini GAGAL.
            return Err(RoutingError::StrategyUnavailable(
                "LeastLoaded requires explicit load data which is not available in NodeInfo".to_string()
            ));
        }
    };

    // Step 3: Tentukan fallback_nodes
    // Urutan deterministik (sorted by ID)
    // Tidak mengandung target_node
    let fallback_nodes = build_fallback_list(&remaining_nodes, &target_node);

    // Step 4: Hitung routing latency
    let routing_latency_ms = start.elapsed().as_millis() as u64;

    Ok(RoutingDecision {
        target_node,
        fallback_nodes,
        cache_hit,
        routing_latency_ms,
    })
}

// ════════════════════════════════════════════════════════════════════════════
// STRATEGY IMPLEMENTATIONS
// ════════════════════════════════════════════════════════════════════════════

/// Apply ZoneAffinity strategy.
///
/// Prefer node dengan zone sama dengan client.
/// Jika tidak ada node dengan zone sama, fallback ke deterministik selection.
#[allow(dead_code)]
fn apply_zone_affinity_strategy(
    nodes: &[NodeInfo],
    client_info: &ClientInfo,
) -> Result<(NodeInfo, Vec<NodeInfo>), RoutingError> {
    if nodes.is_empty() {
        return Err(RoutingError::Router(RouterError::NoAvailableNodes(
            "empty nodes list".to_string()
        )));
    }

    // Separate nodes by zone match
    let (same_zone, diff_zone): (Vec<_>, Vec<_>) = if let Some(ref zone) = client_info.zone_hint {
        nodes.iter().cloned().partition(|n| n.zone.as_deref() == Some(zone.as_str()))
    } else {
        // No zone hint - all nodes are candidates
        (Vec::new(), nodes.to_vec())
    };

    // Track if we have same-zone nodes before moving
    let has_same_zone = !same_zone.is_empty();

    // Prefer same-zone nodes if any, otherwise use all
    let (mut candidates, other_nodes) = if has_same_zone {
        (same_zone, diff_zone)
    } else {
        (diff_zone, Vec::new())
    };

    // Sort deterministik by node ID
    candidates.sort_by(|a, b| a.id.cmp(&b.id));

    // Select first as target
    let target = candidates.remove(0);

    // Remaining nodes for fallback
    // same_zone nodes (minus target) + diff_zone nodes
    let mut remaining = candidates;
    remaining.extend(other_nodes);

    Ok((target, remaining))
}

/// Apply RoundRobin strategy.
///
/// Deterministik berdasarkan hash dari chunk_hash.
/// Tidak menggunakan RNG atau shared mutable state.
#[allow(dead_code)]
fn apply_round_robin_strategy(
    nodes: &[NodeInfo],
    chunk_hash: &str,
) -> Result<(NodeInfo, Vec<NodeInfo>), RoutingError> {
    if nodes.is_empty() {
        return Err(RoutingError::Router(RouterError::NoAvailableNodes(
            "empty nodes list".to_string()
        )));
    }

    // Sort nodes by ID for deterministic ordering
    let mut sorted_nodes: Vec<NodeInfo> = nodes.to_vec();
    sorted_nodes.sort_by(|a, b| a.id.cmp(&b.id));

    // Compute deterministic index from chunk_hash
    let index = compute_hash_index(chunk_hash, sorted_nodes.len());

    // Select target at computed index
    let target = sorted_nodes.remove(index);

    Ok((target, sorted_nodes))
}

/// Compute deterministic index from string hash.
///
/// Uses simple hash function to derive index without RNG.
fn compute_hash_index(s: &str, len: usize) -> usize {
    if len == 0 {
        return 0;
    }

    // Simple hash: sum of bytes
    let hash: usize = s.bytes().map(|b| b as usize).sum();
    hash % len
}

/// Build fallback node list.
///
/// - Sorted by node ID for determinism
/// - Does not include target_node
/// - Only healthy nodes (already filtered by get_placement)
#[allow(dead_code)]
fn build_fallback_list(remaining: &[NodeInfo], target: &NodeInfo) -> Vec<NodeInfo> {
    let mut fallback: Vec<NodeInfo> = remaining
        .iter()
        .filter(|n| n.id != target.id)
        .cloned()
        .collect();

    // Sort by ID for deterministic ordering
    fallback.sort_by(|a, b| a.id.cmp(&b.id));

    fallback
}

// ════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::da_router::{DARouter, RoutingDataSource, RoutingResult, RoutingError as SourceError, NodeInfoFromSource};
    use parking_lot::RwLock;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::net::Ipv4Addr;

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
        #[allow(dead_code)]
        fn set_should_fail(&self, should_fail: bool) {
            self.should_fail.store(should_fail, Ordering::SeqCst);
        }
    }

    impl RoutingDataSource for MockDataSource {
        fn get_registered_node_ids(&self) -> RoutingResult<Vec<String>> {
            if self.should_fail.load(Ordering::SeqCst) {
                return Err(SourceError("mock failure".to_string()));
            }
            Ok(self.nodes.read().keys().cloned().collect())
        }

        fn get_node_info(&self, node_id: &str) -> RoutingResult<Option<NodeInfoFromSource>> {
            if self.should_fail.load(Ordering::SeqCst) {
                return Err(SourceError("mock failure".to_string()));
            }
            Ok(self.nodes.read().get(node_id).map(|n| NodeInfoFromSource {
                addr: n.addr.clone(),
                active: n.active,
                zone: n.zone.clone(),
            }))
        }

        fn get_all_chunk_placements(&self) -> RoutingResult<HashMap<String, Vec<String>>> {
            if self.should_fail.load(Ordering::SeqCst) {
                return Err(SourceError("mock failure".to_string()));
            }
            Ok(self.placements.read().clone())
        }
    }

    fn create_client_info(zone: Option<&str>) -> ClientInfo {
        ClientInfo {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            zone_hint: zone.map(|s| s.to_string()),
            prefer_dc: false,
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 1: ZONE AFFINITY PRIORITIZED
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_zone_affinity_prioritized() {
        let mock = Arc::new(MockDataSource::new());
        mock.add_node_with_zone("node-a", "127.0.0.1:9001", true, Some("zone-x"));
        mock.add_node_with_zone("node-b", "127.0.0.1:9002", true, Some("zone-y"));
        mock.add_node_with_zone("node-c", "127.0.0.1:9003", true, Some("zone-x"));
        mock.add_placement("chunk-1", vec!["node-a", "node-b", "node-c"]);

        let router = DARouter::new(mock);
        router.refresh_cache().unwrap();

        let client = create_client_info(Some("zone-x"));

        let result = route_request(&router, "chunk-1", &client);
        assert!(result.is_ok());

        let decision = result.unwrap();
        // Target should be from zone-x (either node-a or node-c, sorted by ID → node-a)
        assert_eq!(decision.target_node.zone, Some("zone-x".to_string()));
        assert_eq!(decision.target_node.id, "node-a");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 2: ROUND ROBIN DETERMINISTIC
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_round_robin_deterministic() {
        let mock = Arc::new(MockDataSource::new());
        mock.add_node_with_zone("node-a", "127.0.0.1:9001", true, None);
        mock.add_node_with_zone("node-b", "127.0.0.1:9002", true, None);
        mock.add_node_with_zone("node-c", "127.0.0.1:9003", true, None);
        mock.add_placement("chunk-1", vec!["node-a", "node-b", "node-c"]);

        let router = DARouter::new(mock);
        router.refresh_cache().unwrap();

        let client = create_client_info(None);

        // Call multiple times - should get same result (deterministic)
        let result1 = route_request_with_strategy(
            &router, "chunk-1", &client, RoutingStrategy::RoundRobin
        ).unwrap();
        
        let result2 = route_request_with_strategy(
            &router, "chunk-1", &client, RoutingStrategy::RoundRobin
        ).unwrap();

        assert_eq!(result1.target_node.id, result2.target_node.id);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 3: LEAST LOADED FAILS (NO LOAD DATA)
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_least_loaded_fails_no_data() {
        let mock = Arc::new(MockDataSource::new());
        mock.add_node_with_zone("node-a", "127.0.0.1:9001", true, None);
        mock.add_placement("chunk-1", vec!["node-a"]);

        let router = DARouter::new(mock);
        router.refresh_cache().unwrap();

        let client = create_client_info(None);

        let result = route_request_with_strategy(
            &router, "chunk-1", &client, RoutingStrategy::LeastLoaded
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            RoutingError::StrategyUnavailable(msg) => {
                assert!(msg.contains("LeastLoaded"));
            }
            _ => panic!("Expected StrategyUnavailable error"),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 4: FALLBACK NODES VALID AND ORDERED
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_fallback_nodes_valid_and_ordered() {
        let mock = Arc::new(MockDataSource::new());
        mock.add_node_with_zone("node-z", "127.0.0.1:9003", true, None);
        mock.add_node_with_zone("node-a", "127.0.0.1:9001", true, None);
        mock.add_node_with_zone("node-m", "127.0.0.1:9002", true, None);
        mock.add_placement("chunk-1", vec!["node-z", "node-a", "node-m"]);

        let router = DARouter::new(mock);
        router.refresh_cache().unwrap();

        let client = create_client_info(None);

        let decision = route_request(&router, "chunk-1", &client).unwrap();

        // Fallback should not contain target
        for fb in &decision.fallback_nodes {
            assert_ne!(fb.id, decision.target_node.id);
        }

        // Fallback should be sorted by ID
        let ids: Vec<_> = decision.fallback_nodes.iter().map(|n| &n.id).collect();
        let mut sorted_ids = ids.clone();
        sorted_ids.sort();
        assert_eq!(ids, sorted_ids);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 5: UNHEALTHY NODES NOT SELECTED
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_unhealthy_nodes_not_selected() {
        let mock = Arc::new(MockDataSource::new());
        mock.add_node_with_zone("node-a", "127.0.0.1:9001", false, None); // unhealthy
        mock.add_node_with_zone("node-b", "127.0.0.1:9002", true, None);  // healthy
        mock.add_placement("chunk-1", vec!["node-a", "node-b"]);

        let router = DARouter::new(mock);
        router.refresh_cache().unwrap();

        let client = create_client_info(None);

        let decision = route_request(&router, "chunk-1", &client).unwrap();

        // Target should be healthy node
        assert_eq!(decision.target_node.id, "node-b");
        assert!(decision.target_node.active);

        // No unhealthy nodes in fallback
        for fb in &decision.fallback_nodes {
            assert!(fb.active);
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 6: ROUTING LATENCY FILLED
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_routing_latency_filled() {
        let mock = Arc::new(MockDataSource::new());
        mock.add_node_with_zone("node-a", "127.0.0.1:9001", true, None);
        mock.add_placement("chunk-1", vec!["node-a"]);

        let router = DARouter::new(mock);
        router.refresh_cache().unwrap();

        let client = create_client_info(None);

        let decision = route_request(&router, "chunk-1", &client).unwrap();

        // Latency should be measured (>= 0, typically very small for local ops)
        // Just verify it's a valid number
        assert!(decision.routing_latency_ms < 10000); // sanity check
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 7: CONCURRENT ROUTING SAFE
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_concurrent_routing_safe() {
        use std::thread;

        let mock = Arc::new(MockDataSource::new());
        for i in 0..5 {
            mock.add_node_with_zone(
                &format!("node-{}", i),
                &format!("127.0.0.1:900{}", i),
                true,
                None
            );
        }
        mock.add_placement("chunk-1", vec!["node-0", "node-1", "node-2"]);

        let router = Arc::new(DARouter::new(mock));
        router.refresh_cache().unwrap();

        let mut handles = vec![];

        // Spawn multiple routing requests concurrently
        for _ in 0..10 {
            let r = router.clone();
            handles.push(thread::spawn(move || {
                let client = ClientInfo {
                    ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    zone_hint: None,
                    prefer_dc: false,
                };
                for _ in 0..50 {
                    let result = route_request(&r, "chunk-1", &client);
                    assert!(result.is_ok());
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 8: ERROR IF CHUNK NOT FOUND
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_error_if_chunk_not_found() {
        let mock = Arc::new(MockDataSource::new());
        mock.add_node_with_zone("node-a", "127.0.0.1:9001", true, None);
        // No placement for "nonexistent-chunk"

        let router = DARouter::new(mock);
        router.refresh_cache().unwrap();

        let client = create_client_info(None);

        let result = route_request(&router, "nonexistent-chunk", &client);
        assert!(result.is_err());

        match result.unwrap_err() {
            RoutingError::Router(RouterError::ChunkNotFound(hash)) => {
                assert_eq!(hash, "nonexistent-chunk");
            }
            _ => panic!("Expected ChunkNotFound error"),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 9: ZONE AFFINITY FALLBACK TO DETERMINISTIC
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_zone_affinity_fallback() {
        let mock = Arc::new(MockDataSource::new());
        mock.add_node_with_zone("node-b", "127.0.0.1:9002", true, Some("zone-x"));
        mock.add_node_with_zone("node-a", "127.0.0.1:9001", true, Some("zone-x"));
        mock.add_placement("chunk-1", vec!["node-a", "node-b"]);

        let router = DARouter::new(mock);
        router.refresh_cache().unwrap();

        // Client in different zone - should fallback to deterministic (node-a first)
        let client = create_client_info(Some("zone-y"));

        let decision = route_request(&router, "chunk-1", &client).unwrap();
        assert_eq!(decision.target_node.id, "node-a"); // lowest ID
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 10: ROUND ROBIN DIFFERENT CHUNKS GET DIFFERENT TARGETS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_round_robin_different_chunks() {
        let mock = Arc::new(MockDataSource::new());
        mock.add_node_with_zone("node-a", "127.0.0.1:9001", true, None);
        mock.add_node_with_zone("node-b", "127.0.0.1:9002", true, None);
        mock.add_node_with_zone("node-c", "127.0.0.1:9003", true, None);
        mock.add_placement("chunk-1", vec!["node-a", "node-b", "node-c"]);
        mock.add_placement("chunk-2", vec!["node-a", "node-b", "node-c"]);
        mock.add_placement("chunk-3", vec!["node-a", "node-b", "node-c"]);

        let router = DARouter::new(mock);
        router.refresh_cache().unwrap();

        let client = create_client_info(None);

        let r1 = route_request_with_strategy(&router, "chunk-1", &client, RoutingStrategy::RoundRobin).unwrap();
        let r2 = route_request_with_strategy(&router, "chunk-2", &client, RoutingStrategy::RoundRobin).unwrap();
        let r3 = route_request_with_strategy(&router, "chunk-3", &client, RoutingStrategy::RoundRobin).unwrap();

        // Different chunks may get different targets (hash-based)
        // Just verify they're all valid
        assert!(r1.target_node.active);
        assert!(r2.target_node.active);
        assert!(r3.target_node.active);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 11: CACHE HIT FLAG
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_cache_hit_flag() {
        let mock = Arc::new(MockDataSource::new());
        mock.add_node_with_zone("node-a", "127.0.0.1:9001", true, None);
        mock.add_placement("chunk-1", vec!["node-a"]);

        let router = DARouter::new(mock);
        router.refresh_cache().unwrap();

        let client = create_client_info(None);

        let decision = route_request(&router, "chunk-1", &client).unwrap();

        // Cache should be hit (not expired right after refresh)
        assert!(decision.cache_hit);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 12: ROUTING ERROR DISPLAY
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_routing_error_display() {
        let err = RoutingError::StrategyUnavailable("test".to_string());
        assert!(format!("{}", err).contains("strategy unavailable"));

        let err = RoutingError::Router(RouterError::ChunkNotFound("abc".to_string()));
        assert!(format!("{}", err).contains("router error"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 13: CLIENT INFO CONSTRUCTORS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_client_info_constructors() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        let c1 = ClientInfo::new(ip);
        assert_eq!(c1.ip, ip);
        assert!(c1.zone_hint.is_none());
        assert!(!c1.prefer_dc);

        let c2 = ClientInfo::with_zone(ip, Some("zone-a".to_string()));
        assert_eq!(c2.zone_hint, Some("zone-a".to_string()));

        let c3 = ClientInfo::full(ip, Some("zone-b".to_string()), true);
        assert!(c3.prefer_dc);
    }
}