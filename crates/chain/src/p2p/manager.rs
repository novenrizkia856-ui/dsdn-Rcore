//! # Peer Manager
//!
//! Central orchestrator untuk semua P2P peer lifecycle.
//! PeerManager menggabungkan semua komponen:
//! - PeerStore (persistence)
//! - PeerScorer (scoring)
//! - Handshake validation
//! - PEX rate limiting
//! - Bootstrap fallback chain
//!
//! ## Thread Safety
//!
//! PeerManager di-wrap dalam `Arc<RwLock<>>` saat digunakan di Chain.
//! Semua method mengambil `&self` atau `&mut self` secara explicit.
//!
//! ## Bootstrap Flow
//!
//! ```text
//! 1. load peers.dat → connect to cached peers
//! 2. if no cached peers → try static IPs
//! 3. if no static IPs → DNS resolve seeds
//! 4. if all fail → retry with exponential backoff
//! ```

use std::collections::HashSet;
use std::net::SocketAddr;
use std::str::FromStr;

use super::identity::{NetworkId, NodeId, CURRENT_PROTOCOL_VERSION};
use super::types::*;
use super::config::BootstrapConfig;
use super::scoring::PeerScorer;
use super::store::PeerStore;
use super::handshake::{self, HandshakeMessage, HandshakeResult};
use super::pex::{PexRateLimiter, PexConfig, PexRequest, PexResponse, PexPeerInfo};

// ════════════════════════════════════════════════════════════════════════════
// BOOTSTRAP STATE
// ════════════════════════════════════════════════════════════════════════════

/// Status bootstrap process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapState {
    /// Belum dimulai
    NotStarted,
    /// Sedang load dari peers.dat
    LoadingCache,
    /// Sedang coba static IP
    TryingStaticPeers,
    /// Sedang resolve DNS seeds
    ResolvingDns,
    /// Semua sumber gagal, retry
    Retrying { attempt: u32 },
    /// Bootstrap selesai, peer ditemukan
    Completed,
    /// Bootstrap gagal total (semua retry habis)
    Failed,
}

// ════════════════════════════════════════════════════════════════════════════
// PEER MANAGER
// ════════════════════════════════════════════════════════════════════════════

/// Central orchestrator untuk P2P peer lifecycle.
pub struct PeerManager {
    /// Network identity
    pub network_id: NetworkId,
    /// Node ID kita sendiri
    pub our_node_id: NodeId,
    /// Bootstrap configuration
    pub config: BootstrapConfig,
    /// Persistent peer store
    pub store: PeerStore,
    /// PEX rate limiter
    pub pex_limiter: PexRateLimiter,
    /// PEX configuration
    pub pex_config: PexConfig,
    /// Set of currently connected node IDs (untuk handshake validation)
    connected_node_ids: HashSet<NodeId>,
    /// Bootstrap state
    pub bootstrap_state: BootstrapState,
    /// Service type yang kita iklankan
    pub our_service_type: ServiceType,
    /// Port yang kita listen
    pub listen_port: u16,
}

impl PeerManager {
    /// Buat PeerManager baru.
    ///
    /// Setelah construct, panggil `initialize()` untuk load peers.dat.
    pub fn new(
        network_id: NetworkId,
        our_node_id: NodeId,
        config: BootstrapConfig,
        service_type: ServiceType,
    ) -> Self {
        let pex_limiter = PexRateLimiter::new(config.pex_interval_secs);
        let store = PeerStore::new(
            &config.peers_file,
            network_id,
            config.limits.clone(),
        );
        let listen_port = network_id.default_port();

        Self {
            network_id,
            our_node_id,
            config,
            store,
            pex_limiter,
            pex_config: PexConfig::default(),
            connected_node_ids: HashSet::new(),
            bootstrap_state: BootstrapState::NotStarted,
            our_service_type: service_type,
            listen_port,
        }
    }

    /// Initialize: load peers.dat dan prepare for bootstrap.
    pub fn initialize(&mut self) -> Result<(), anyhow::Error> {
        println!("🌐 P2P: Initializing peer manager for {}", self.network_id);
        println!("   Node ID: {}", self.our_node_id);
        println!("   Service: {}", self.our_service_type);

        // Load persistent cache
        self.bootstrap_state = BootstrapState::LoadingCache;
        let loaded = self.store.load()?;

        if loaded > 0 {
            println!("   ✓ Loaded {} cached peers", loaded);
        }

        // Validate config
        let warnings = self.config.validate();
        for w in &warnings {
            println!("   ⚠️ {}", w);
        }

        println!("   Seeds: {} DNS + {} static",
            self.config.dns_seeds.len(),
            self.config.static_peers.len(),
        );

        self.bootstrap_state = BootstrapState::NotStarted;
        Ok(())
    }

    // ════════════════════════════════════════════════════════════════════════
    // BOOTSTRAP
    // ════════════════════════════════════════════════════════════════════════

    /// Start bootstrap process (synchronous/step-based).
    ///
    /// Returned peers zijn ready voor connectie.
    /// Actual TCP/QUIC transport is NOT implemented here —
    /// caller (node runtime) is verantwoordelijk voor de feitelijke verbinding.
    ///
    /// ## Fallback Order
    ///
    /// 1. peers.dat → sorted by score, try best peers first
    /// 2. static IPs from config
    /// 3. DNS seeds (placeholder — actual resolve at Tahap 28)
    /// 4. retry
    pub fn get_bootstrap_peers(&mut self) -> Vec<PeerEntry> {
        let mut candidates = vec![];

        // Phase 1: From peers.dat (cached peers)
        self.bootstrap_state = BootstrapState::LoadingCache;
        let cached = self.store.get_connectable();
        if !cached.is_empty() {
            println!("   📋 Bootstrap phase 1: {} cached peers available", cached.len());
            for p in &cached {
                candidates.push((*p).clone());
            }
        }

        // Phase 2: From static IPs in config
        self.bootstrap_state = BootstrapState::TryingStaticPeers;
        for static_peer in &self.config.static_peers {
            let key = static_peer.addr.to_string();
            if !self.store.contains(&key) {
                let entry = PeerEntry::new(
                    static_peer.addr,
                    self.network_id,
                    PeerSource::StaticConfig,
                );
                candidates.push(entry);
            }
        }
        if !self.config.static_peers.is_empty() {
            println!("   📋 Bootstrap phase 2: {} static peers", self.config.static_peers.len());
        }

        // Phase 3: DNS seeds (placeholder)
        // Actual DNS resolution will be implemented at Tahap 28.
        // For now, DNS seeds are recorded but not resolved.
        self.bootstrap_state = BootstrapState::ResolvingDns;
        if !self.config.dns_seeds.is_empty() {
            println!(
                "   📋 Bootstrap phase 3: {} DNS seeds configured (resolution pending Tahap 28)",
                self.config.dns_seeds.len(),
            );
            // At Tahap 28 this will be:
            // for seed in &self.config.dns_seeds {
            //     let ips = dns_resolve(&seed.hostname, seed.port).await?;
            //     for ip in ips {
            //         let entry = PeerEntry::new(ip, self.network_id, PeerSource::DnsSeed);
            //         candidates.push(entry);
            //     }
            // }
        }

        if candidates.is_empty() {
            println!("   ⚠️ Bootstrap: no peer candidates found from any source");
            self.bootstrap_state = BootstrapState::Failed;
        } else {
            self.bootstrap_state = BootstrapState::Completed;
        }

        // Sort by score descending
        candidates.sort_by(|a, b| b.score.cmp(&a.score));

        // Limit to max outbound
        let max = self.config.limits.max_outbound as usize;
        candidates.truncate(max);

        candidates
    }

    // ════════════════════════════════════════════════════════════════════════
    // PEER LIFECYCLE
    // ════════════════════════════════════════════════════════════════════════

    /// Add peer manual (via CLI/RPC).
    pub fn add_peer_manual(&mut self, addr_str: &str) -> Result<(), anyhow::Error> {
        let addr: SocketAddr = addr_str.parse()
            .map_err(|e| anyhow::anyhow!("invalid address '{}': {}", addr_str, e))?;

        let entry = PeerEntry::new(addr, self.network_id, PeerSource::Manual);
        self.store.upsert(entry);
        println!("   ✓ Manual peer added: {}", addr);
        Ok(())
    }

    /// Handle successful handshake with peer.
    ///
    /// Called after transport layer establishes connection and handshake succeeds.
    pub fn on_handshake_success(
        &mut self,
        addr: SocketAddr,
        node_id: NodeId,
        service_type: ServiceType,
        chain_height: u64,
    ) {
        let key = addr.to_string();

        // Update or create entry
        if let Some(peer) = self.store.get_mut(&key) {
            peer.node_id = node_id.clone();
            peer.service_type = service_type;
            peer.record_success();
        } else {
            let mut entry = PeerEntry::new(addr, self.network_id, PeerSource::Inbound);
            entry.node_id = node_id.clone();
            entry.service_type = service_type;
            entry.record_success();
            self.store.upsert(entry);
        }

        // Track connected node ID
        self.connected_node_ids.insert(node_id.clone());

        println!("   ✓ Peer connected: {} (node={}, type={}, height={})",
            addr, node_id, service_type, chain_height);
    }

    /// Handle peer disconnection.
    pub fn on_peer_disconnected(&mut self, addr: &SocketAddr) {
        let key = addr.to_string();
        if let Some(peer) = self.store.get_mut(&key) {
            self.connected_node_ids.remove(&peer.node_id);
            peer.mark_disconnected();
        }
    }

    /// Handle failed connection attempt.
    pub fn on_connect_failure(&mut self, addr: &SocketAddr) {
        let key = addr.to_string();
        if let Some(peer) = self.store.get_mut(&key) {
            peer.record_failure();
        }
    }

    /// Ban a peer.
    pub fn ban_peer(&mut self, addr: &SocketAddr, duration_secs: u64) {
        let key = addr.to_string();
        if let Some(peer) = self.store.get_mut(&key) {
            self.connected_node_ids.remove(&peer.node_id);
            peer.ban(duration_secs);
            println!("   🔨 Peer banned: {} for {}s", addr, duration_secs);
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // HANDSHAKE
    // ════════════════════════════════════════════════════════════════════════

    /// Build Hello message untuk kirim ke peer.
    pub fn build_hello(&self, chain_height: u64) -> HandshakeMessage {
        handshake::build_hello(
            self.network_id,
            self.our_node_id.clone(),
            self.listen_port,
            self.our_service_type,
            chain_height,
        )
    }

    /// Validate incoming Hello message dari peer.
    pub fn validate_hello(&self, msg: &HandshakeMessage) -> HandshakeResult {
        let max_conn = (self.config.limits.max_inbound + self.config.limits.max_outbound) as usize;
        handshake::validate_hello(
            msg,
            self.network_id,
            &self.our_node_id,
            &self.connected_node_ids,
            self.connected_node_ids.len(),
            max_conn,
        )
    }

    // ════════════════════════════════════════════════════════════════════════
    // PEX
    // ════════════════════════════════════════════════════════════════════════

    /// Build PEX request.
    pub fn build_pex_request(&self, service_filter: Option<ServiceType>) -> PexRequest {
        PexRequest::GetPeers {
            network_id: self.network_id,
            service_type_filter: service_filter,
            max_count: self.pex_config.max_peers_per_response,
        }
    }

    /// Handle incoming PEX request from peer.
    pub fn handle_pex_request(
        &mut self,
        request: &PexRequest,
        requester_addr: &str,
    ) -> PexResponse {
        // Rate limit check
        if !self.pex_limiter.is_allowed(requester_addr) {
            let retry = self.pex_limiter.retry_after(requester_addr);
            return PexResponse::Rejected {
                reason: "rate_limited".to_string(),
                retry_after_secs: retry,
            };
        }

        self.pex_limiter.record_request(requester_addr);

        // Build response from store
        let peers: Vec<PeerEntry> = self.store.get_all_sorted()
            .into_iter()
            .cloned()
            .collect();

        super::pex::build_pex_response(
            &peers,
            request,
            requester_addr,
            &self.pex_config,
        )
    }

    /// Process PEX response — add newly discovered peers.
    pub fn process_pex_response(&mut self, response: &PexResponse) -> usize {
        match response {
            PexResponse::Peers { peers, total_known } => {
                let mut added = 0;
                for info in peers {
                    let key = info.addr.to_string();
                    if !self.store.contains(&key) {
                        let mut entry = PeerEntry::new(
                            info.addr,
                            self.network_id,
                            PeerSource::PeerExchange,
                        );
                        entry.node_id = info.node_id.clone();
                        entry.service_type = info.service_type;
                        self.store.upsert(entry);
                        added += 1;
                    }
                }
                if added > 0 {
                    println!("   📬 PEX: discovered {} new peers (remote knows {})",
                        added, total_known);
                }
                added
            }
            PexResponse::Rejected { reason, retry_after_secs } => {
                println!("   ℹ PEX rejected: {} (retry in {}s)", reason, retry_after_secs);
                0
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // QUERIES
    // ════════════════════════════════════════════════════════════════════════

    /// Get best N peers for outbound connections.
    pub fn get_best_peers(&self, n: usize) -> Vec<&PeerEntry> {
        let connectable = self.store.get_connectable();
        connectable.into_iter().take(n).collect()
    }

    /// Get connected peers.
    pub fn get_connected_peers(&self) -> Vec<&PeerEntry> {
        self.store.get_connected()
    }

    /// Get peers by service type.
    pub fn get_peers_by_type(&self, service_type: ServiceType) -> Vec<&PeerEntry> {
        self.store.get_by_service_type(service_type)
    }

    /// Count connected peers.
    pub fn connected_count(&self) -> usize {
        self.connected_node_ids.len()
    }

    /// Count total known peers.
    pub fn known_count(&self) -> usize {
        self.store.count()
    }

    /// Check source diversity of connected peers.
    /// Returns (total, unique_sources). Unique > 1 is healthy.
    pub fn source_diversity(&self) -> (usize, usize) {
        let all: Vec<PeerEntry> = self.store.get_connected()
            .into_iter().cloned().collect();
        PeerScorer::check_source_diversity(&all)
    }

    // ════════════════════════════════════════════════════════════════════════
    // MAINTENANCE
    // ════════════════════════════════════════════════════════════════════════

    /// Periodic maintenance tick. Call this every ~60 seconds.
    ///
    /// - Recompute all scores
    /// - Run garbage collection
    /// - Save peers.dat
    /// - Cleanup PEX rate limiter
    pub fn maintenance_tick(&mut self) -> Result<(), anyhow::Error> {
        self.store.recompute_all_scores();
        self.store.garbage_collect();
        self.store.save()?;
        self.pex_limiter.cleanup();
        Ok(())
    }

    /// Force save peers.dat.
    pub fn save(&mut self) -> Result<(), anyhow::Error> {
        self.store.save()
    }

    /// Force clear all peers and re-bootstrap.
    pub fn reset(&mut self) -> Result<(), anyhow::Error> {
        println!("   ⚠️ P2P: Resetting peer store");
        self.connected_node_ids.clear();
        self.bootstrap_state = BootstrapState::NotStarted;

        // Recreate empty store
        self.store = PeerStore::new(
            &self.config.peers_file,
            self.network_id,
            self.config.limits.clone(),
        );

        // Delete peers.dat
        let path = std::path::Path::new(&self.config.peers_file);
        if path.exists() {
            std::fs::remove_file(path)?;
        }

        Ok(())
    }

    /// Get comprehensive status for observability.
    pub fn status_summary(&self) -> String {
        let stats = self.store.stats();
        format!(
            "P2P Status [{}] node={} bootstrap={:?}\n  {}",
            self.network_id,
            self.our_node_id,
            self.bootstrap_state,
            stats,
        )
    }
}

// ════════════════════════════════════════════════════════════════════════════
// BRIDGE: PeerManager → Legacy BroadcastManager
// ════════════════════════════════════════════════════════════════════════════

/// Konversi PeerEntry ke format yang kompatibel dengan BroadcastManager.
///
/// Ini adalah bridge sementara agar PeerManager bisa bekerja bersama
/// legacy BroadcastManager tanpa breaking changes.
///
/// Di Tahap 28, BroadcastManager akan di-replace sepenuhnya.
impl PeerEntry {
    /// Convert ke format URL yang diharapkan BroadcastManager.
    /// Format: "http://IP:RPC_PORT" (RPC port = listen_port + 1 by convention)
    pub fn to_broadcast_url(&self) -> String {
        let rpc_port = self.addr.port() + 1;
        format!("http://{}:{}", self.addr.ip(), rpc_port)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_manager() -> PeerManager {
        let node_id = NodeId::from_bytes([0xAAu8; 32]);
        let config = BootstrapConfig::development();
        PeerManager::new(
            NetworkId::Devnet,
            node_id,
            config,
            ServiceType::Chain,
        )
    }

    #[test]
    fn test_manager_creation() {
        let mgr = make_manager();
        assert_eq!(mgr.network_id, NetworkId::Devnet);
        assert_eq!(mgr.connected_count(), 0);
        assert_eq!(mgr.known_count(), 0);
    }

    #[test]
    fn test_add_peer_manual() {
        let mut mgr = make_manager();
        mgr.add_peer_manual("10.0.0.1:45831").unwrap();
        assert_eq!(mgr.known_count(), 1);
    }

    #[test]
    fn test_add_peer_manual_invalid() {
        let mut mgr = make_manager();
        assert!(mgr.add_peer_manual("not-valid").is_err());
    }

    #[test]
    fn test_handshake_lifecycle() {
        let mut mgr = make_manager();
        let addr: SocketAddr = "10.0.0.1:45831".parse().unwrap();
        let peer_node = NodeId::from_bytes([0xBBu8; 32]);

        // Handshake success
        mgr.on_handshake_success(addr, peer_node.clone(), ServiceType::Chain, 100);
        assert_eq!(mgr.connected_count(), 1);
        assert_eq!(mgr.known_count(), 1);

        // Disconnect
        mgr.on_peer_disconnected(&addr);
        assert_eq!(mgr.connected_count(), 0);
    }

    #[test]
    fn test_pex_roundtrip() {
        let mut mgr = make_manager();

        // Add some peers
        for i in 1..=5 {
            let addr: SocketAddr = format!("10.0.0.{}:45831", i).parse().unwrap();
            let node = NodeId::from_bytes([i; 32]);
            mgr.on_handshake_success(addr, node, ServiceType::Chain, 100);
        }

        // Build and handle PEX request
        let request = mgr.build_pex_request(None);
        let response = mgr.handle_pex_request(&request, "10.0.0.99:45831");

        if let PexResponse::Peers { peers, .. } = &response {
            assert!(!peers.is_empty());
        } else {
            panic!("expected Peers response");
        }
    }

    #[test]
    fn test_pex_rate_limiting() {
        let mut mgr = make_manager();

        let request = mgr.build_pex_request(None);

        // First request: OK
        let r1 = mgr.handle_pex_request(&request, "10.0.0.1:45831");
        assert!(matches!(r1, PexResponse::Peers { .. }));

        // Second request: rate limited
        let r2 = mgr.handle_pex_request(&request, "10.0.0.1:45831");
        assert!(matches!(r2, PexResponse::Rejected { .. }));
    }

    #[test]
    fn test_bootstrap_with_static_peers() {
        let mut config = BootstrapConfig::development();
        config.add_static_peer("10.0.0.1:45831").unwrap();
        config.add_static_peer("10.0.0.2:45831").unwrap();

        let node_id = NodeId::from_bytes([0xAAu8; 32]);
        let mut mgr = PeerManager::new(
            NetworkId::Devnet, node_id, config, ServiceType::Chain,
        );

        let candidates = mgr.get_bootstrap_peers();
        assert_eq!(candidates.len(), 2);
        assert_eq!(mgr.bootstrap_state, BootstrapState::Completed);
    }

    #[test]
    fn test_bootstrap_empty_config() {
        let mut mgr = make_manager();
        let candidates = mgr.get_bootstrap_peers();
        assert!(candidates.is_empty());
        assert_eq!(mgr.bootstrap_state, BootstrapState::Failed);
    }

    #[test]
    fn test_validate_hello_valid() {
        let mgr = make_manager();
        let peer_id = NodeId::from_bytes([0xBBu8; 32]);
        let hello = handshake::build_hello(
            NetworkId::Devnet, peer_id, 30305, ServiceType::Chain, 50,
        );
        let result = mgr.validate_hello(&hello);
        assert!(result.is_accepted());
    }

    #[test]
    fn test_validate_hello_wrong_network() {
        let mgr = make_manager();
        let peer_id = NodeId::from_bytes([0xBBu8; 32]);
        let hello = handshake::build_hello(
            NetworkId::Mainnet, peer_id, 45831, ServiceType::Chain, 50,
        );
        let result = mgr.validate_hello(&hello);
        assert!(!result.is_accepted());
    }

    #[test]
    fn test_ban_peer() {
        let mut mgr = make_manager();
        let addr: SocketAddr = "10.0.0.1:45831".parse().unwrap();
        let peer_node = NodeId::from_bytes([0xBBu8; 32]);

        mgr.on_handshake_success(addr, peer_node, ServiceType::Chain, 100);
        assert_eq!(mgr.connected_count(), 1);

        mgr.ban_peer(&addr, 3600);
        assert_eq!(mgr.connected_count(), 0);

        // Banned peer should not be in connectable list
        let connectable = mgr.get_best_peers(10);
        assert!(connectable.is_empty());
    }

    #[test]
    fn test_reset() {
        let mut mgr = make_manager();
        mgr.add_peer_manual("10.0.0.1:45831").unwrap();
        assert_eq!(mgr.known_count(), 1);

        mgr.reset().unwrap();
        assert_eq!(mgr.known_count(), 0);
        assert_eq!(mgr.connected_count(), 0);
    }

    #[test]
    fn test_process_pex_response_adds_new() {
        let mut mgr = make_manager();

        let response = PexResponse::Peers {
            peers: vec![
                PexPeerInfo {
                    addr: "10.0.0.1:45831".parse().unwrap(),
                    node_id: NodeId::from_bytes([0x11u8; 32]),
                    service_type: ServiceType::Chain,
                    last_success: current_unix_time(),
                },
                PexPeerInfo {
                    addr: "10.0.0.2:45831".parse().unwrap(),
                    node_id: NodeId::from_bytes([0x22u8; 32]),
                    service_type: ServiceType::Storage,
                    last_success: current_unix_time(),
                },
            ],
            total_known: 50,
        };

        let added = mgr.process_pex_response(&response);
        assert_eq!(added, 2);
        assert_eq!(mgr.known_count(), 2);
    }

    #[test]
    fn test_status_summary() {
        let mgr = make_manager();
        let summary = mgr.status_summary();
        assert!(summary.contains("devnet"));
        assert!(summary.contains("P2P Status"));
    }
}