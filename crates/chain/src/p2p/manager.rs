//! # Peer Manager
//!
//! Central orchestrator untuk semua P2P peer lifecycle.
//! PeerManager menggabungkan semua komponen:
//! - PeerStore (persistence)
//! - PeerScorer (scoring with role_bonus + class_bonus)
//! - Handshake validation (role + class)
//! - Role-based peer filtering (RoleDependencyMatrix)
//! - PEX rate limiting (role-aware)
//! - Bootstrap fallback chain
//!
//! ## Role-Based Architecture (sesuai Whitepaper DSDN)
//!
//! Blockchain Nusantara embedded di semua node — bukan role terpisah.
//! Roles: StorageCompute (Reguler/DataCenter), Validator, Coordinator.
//! Setiap role punya dependency matrix yang menentukan peer mana yang
//! REQUIRED vs OPTIONAL vs SKIP.
//!
//! ## Thread Safety
//!
//! PeerManager di-wrap dalam `Arc<RwLock<>>` saat digunakan di node runtime.
//! Semua method mengambil `&self` atau `&mut self` secara explicit.
//!
//! ## Bootstrap Flow
//!
//! ```text
//! 1. load peers.dat → filter by REQUIRED roles → connect
//! 2. if no cached peers → try static IPs → handshake → filter
//! 3. if no static IPs → DNS resolve → handshake → filter
//! 4. if all fail → retry with exponential backoff
//! 5. cross-role PEX: connect to any role → PEX → find needed roles
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
// POST-HANDSHAKE ACTION
// ════════════════════════════════════════════════════════════════════════════

/// Keputusan setelah handshake berdasarkan RoleDependencyMatrix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostHandshakeAction {
    /// Keep connection — role dibutuhkan (REQUIRED atau OPTIONAL)
    KeepConnection,
    /// Disconnect setelah PEX — role tidak dibutuhkan langsung
    /// tapi kita bisa minta PEX untuk menemukan role yang dibutuhkan
    PexThenDisconnect,
    /// Disconnect langsung — role tidak relevan
    Disconnect { reason: DisconnectReason },
}

// ════════════════════════════════════════════════════════════════════════════
// PEER MANAGER
// ════════════════════════════════════════════════════════════════════════════

/// Central orchestrator untuk P2P peer lifecycle.
///
/// ## Role Awareness
///
/// PeerManager tahu role node ini (dari BootstrapConfig) dan menggunakan
/// RoleDependencyMatrix untuk menentukan peer mana yang harus di-keep
/// vs di-disconnect setelah handshake.
pub struct PeerManager {
    /// Network identity
    pub network_id: NetworkId,
    /// Node ID kita sendiri
    pub our_node_id: NodeId,
    /// Bootstrap configuration (includes role + class)
    pub config: BootstrapConfig,
    /// Persistent peer store (role-aware scoring)
    pub store: PeerStore,
    /// PEX rate limiter
    pub pex_limiter: PexRateLimiter,
    /// PEX configuration
    pub pex_config: PexConfig,
    /// Set of currently connected node IDs (untuk handshake validation)
    connected_node_ids: HashSet<NodeId>,
    /// Bootstrap state
    pub bootstrap_state: BootstrapState,
    /// Role operasional node ini (dari config)
    pub our_role: NodeRole,
    /// Kelas node ini (dari config, Some hanya untuk StorageCompute)
    pub our_node_class: Option<NodeClass>,
    /// Port yang kita listen (selalu 45831)
    pub listen_port: u16,
}

impl PeerManager {
    /// Buat PeerManager baru.
    ///
    /// Role dan class diambil dari BootstrapConfig.
    /// Setelah construct, panggil `initialize()` untuk load peers.dat.
    pub fn new(
        network_id: NetworkId,
        our_node_id: NodeId,
        config: BootstrapConfig,
    ) -> Self {
        let pex_limiter = PexRateLimiter::new(config.pex_interval_secs);
        let our_role = config.role;
        let our_node_class = config.node_class;
        let listen_port = config.port;
        let store = PeerStore::new(
            &config.peers_file,
            network_id,
            our_role,
            config.limits.clone(),
        );

        Self {
            network_id,
            our_node_id,
            config,
            store,
            pex_limiter,
            pex_config: PexConfig::default(),
            connected_node_ids: HashSet::new(),
            bootstrap_state: BootstrapState::NotStarted,
            our_role,
            our_node_class,
            listen_port,
        }
    }

    /// Initialize: load peers.dat dan prepare for bootstrap.
    pub fn initialize(&mut self) -> Result<(), anyhow::Error> {
        println!("🌐 P2P: Initializing peer manager for {}", self.network_id);
        println!("   Node ID: {}", self.our_node_id);
        println!("   Role:    {}", self.config.role_display());
        println!("   Port:    {}", self.listen_port);

        // Load persistent cache
        self.bootstrap_state = BootstrapState::LoadingCache;
        let loaded = self.store.load()?;

        if loaded > 0 {
            println!("   ✓ Loaded {} cached peers", loaded);
            // Show role breakdown
            let stats = self.store.stats();
            println!("     By role: sc={} (reg={}, dc={}) val={} coord={} boot={}",
                stats.role_storage_compute, stats.class_reguler, stats.class_datacenter,
                stats.role_validator, stats.role_coordinator, stats.role_bootstrap);
        }

        // Validate config
        let warnings = self.config.validate();
        for w in &warnings {
            println!("   ⚠️ {}", w);
        }

        // Show required roles
        let required = required_roles(self.our_role);
        let required_str: Vec<&str> = required.iter().map(|r| r.as_str()).collect();
        println!("   Required peers: {:?}", required_str);

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
    /// Returns peer candidates sorted by score (role_bonus included).
    /// Actual TCP/QUIC transport NOT implemented here —
    /// caller (node runtime) handles the actual connection.
    ///
    /// ## Fallback Order
    ///
    /// 1. peers.dat → sorted by score (REQUIRED roles get +20 bonus)
    /// 2. static IPs from config
    /// 3. DNS seeds (placeholder — actual resolve at Tahap 28)
    /// 4. retry
    pub fn get_bootstrap_peers(&mut self) -> Vec<PeerEntry> {
        let mut candidates = vec![];

        // Phase 1: From peers.dat (cached peers)
        // Score sudah termasuk role_bonus, jadi REQUIRED role peers akan
        // otomatis di-prioritaskan
        self.bootstrap_state = BootstrapState::LoadingCache;
        let cached = self.store.get_connectable();
        if !cached.is_empty() {
            println!("   📋 Bootstrap phase 1: {} cached peers available", cached.len());
            for p in &cached {
                candidates.push((*p).clone());
            }
        }

        // Phase 2: From static IPs in config
        // Role belum diketahui — semua di-add, filter setelah handshake
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
        self.bootstrap_state = BootstrapState::ResolvingDns;
        if !self.config.dns_seeds.is_empty() {
            println!(
                "   📋 Bootstrap phase 3: {} DNS seeds configured (resolution pending)",
                self.config.dns_seeds.len(),
            );
        }

        if candidates.is_empty() {
            println!("   ⚠️ Bootstrap: no peer candidates found from any source");
            self.bootstrap_state = BootstrapState::Failed;
        } else {
            self.bootstrap_state = BootstrapState::Completed;
        }

        // Sort by score descending (role_bonus sudah termasuk di score)
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
    /// Now records role + class from handshake.
    pub fn on_handshake_success(
        &mut self,
        addr: SocketAddr,
        node_id: NodeId,
        role: NodeRole,
        node_class: Option<NodeClass>,
        chain_height: u64,
    ) {
        let key = addr.to_string();

        // Update or create entry
        if let Some(peer) = self.store.get_mut(&key) {
            peer.node_id = node_id.clone();
            peer.update_role(role, node_class);
            peer.record_success();
        } else {
            let mut entry = PeerEntry::new(addr, self.network_id, PeerSource::Inbound);
            entry.node_id = node_id.clone();
            entry.update_role(role, node_class);
            entry.record_success();
            self.store.upsert(entry);
        }

        // Track connected node ID
        self.connected_node_ids.insert(node_id.clone());

        println!("   ✓ Peer connected: {} (node={}, role={}, class={:?}, height={})",
            addr, node_id, role,
            node_class.map(|c| c.as_str()).unwrap_or("-"),
            chain_height);
    }

    /// Determine what to do after handshake based on RoleDependencyMatrix.
    ///
    /// Returns:
    /// - KeepConnection: peer role is REQUIRED or OPTIONAL and we need more
    /// - PexThenDisconnect: peer role is SKIP but we can PEX first
    /// - Disconnect: peer is invalid or we have enough
    pub fn decide_post_handshake(
        &self,
        peer_role: NodeRole,
        peer_class: Option<NodeClass>,
    ) -> PostHandshakeAction {
        // Validate role+class consistency
        match peer_role {
            NodeRole::StorageCompute => {
                if peer_class.is_none() {
                    return PostHandshakeAction::Disconnect {
                        reason: DisconnectReason::InvalidHandshake,
                    };
                }
            }
            NodeRole::Validator | NodeRole::Coordinator | NodeRole::Bootstrap => {
                if peer_class.is_some() {
                    return PostHandshakeAction::Disconnect {
                        reason: DisconnectReason::InvalidHandshake,
                    };
                }
            }
        }

        let dep = role_dependency(self.our_role, peer_role);

        match dep {
            RoleDependency::Required => PostHandshakeAction::KeepConnection,
            RoleDependency::Optional => {
                // Keep jika belum terlalu banyak peer
                let total_connected = self.connected_count();
                let max = self.config.limits.max_outbound as usize;
                if total_connected < max {
                    PostHandshakeAction::KeepConnection
                } else {
                    PostHandshakeAction::PexThenDisconnect
                }
            }
            RoleDependency::Skip => PostHandshakeAction::PexThenDisconnect,
        }
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
    /// Menyertakan role dan class node ini.
    pub fn build_hello(&self, chain_height: u64) -> HandshakeMessage {
        handshake::build_hello(
            self.network_id,
            self.our_node_id.clone(),
            self.listen_port,
            self.our_role,
            self.our_node_class,
            chain_height,
        )
    }

    /// Validate incoming Hello message dari peer.
    /// Termasuk validasi role + class consistency.
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

    /// Build PEX request — optionally filter by roles yang dibutuhkan.
    pub fn build_pex_request(&self, role_filter: Option<Vec<NodeRole>>) -> PexRequest {
        PexRequest::GetPeers {
            network_id: self.network_id,
            role_filter,
            max_count: self.pex_config.max_peers_per_response,
        }
    }

    /// Build PEX request untuk roles yang masih REQUIRED tapi belum ada peer-nya.
    pub fn build_pex_request_for_missing_roles(&self) -> PexRequest {
        let missing = self.missing_required_roles();
        let filter = if missing.is_empty() {
            None // sudah lengkap, minta semua
        } else {
            Some(missing)
        };
        self.build_pex_request(filter)
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

    /// Process PEX response — add newly discovered peers with role+class.
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
                        entry.update_role(info.role, info.node_class);
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

    /// Get best N peers for outbound connections (score includes role_bonus).
    pub fn get_best_peers(&self, n: usize) -> Vec<&PeerEntry> {
        let connectable = self.store.get_connectable();
        connectable.into_iter().take(n).collect()
    }

    /// Get best N peers by specific role.
    pub fn get_best_peers_by_role(&self, role: NodeRole, n: usize) -> Vec<&PeerEntry> {
        self.store.get_connectable_by_role(role)
            .into_iter()
            .take(n)
            .collect()
    }

    /// Get connected peers.
    pub fn get_connected_peers(&self) -> Vec<&PeerEntry> {
        self.store.get_connected()
    }

    /// Get connected peers by role.
    pub fn get_connected_by_role(&self, role: NodeRole) -> Vec<&PeerEntry> {
        self.store.get_connected_by_role(role)
    }

    /// Get peers by role.
    pub fn get_peers_by_role(&self, role: NodeRole) -> Vec<&PeerEntry> {
        self.store.get_by_role(role)
    }

    /// Get peers by role + class.
    pub fn get_peers_by_role_class(&self, role: NodeRole, class: NodeClass) -> Vec<&PeerEntry> {
        self.store.get_by_role_class(role, class)
    }

    /// Count connected peers.
    pub fn connected_count(&self) -> usize {
        self.connected_node_ids.len()
    }

    /// Count connected peers by role.
    pub fn connected_count_by_role(&self, role: NodeRole) -> usize {
        self.store.count_connected_by_role(role)
    }

    /// Count total known peers.
    pub fn known_count(&self) -> usize {
        self.store.count()
    }

    /// Check source diversity of connected peers.
    pub fn source_diversity(&self) -> (usize, usize) {
        let all: Vec<PeerEntry> = self.store.get_connected()
            .into_iter().cloned().collect();
        PeerScorer::check_source_diversity(&all)
    }

    // ════════════════════════════════════════════════════════════════════════
    // ROLE HEALTH
    // ════════════════════════════════════════════════════════════════════════

    /// Check apakah semua REQUIRED roles sudah terpenuhi (minimal 1 connected peer).
    pub fn all_required_roles_met(&self) -> bool {
        self.missing_required_roles().is_empty()
    }

    /// Get list of REQUIRED roles yang belum ada connected peer-nya.
    pub fn missing_required_roles(&self) -> Vec<NodeRole> {
        required_roles(self.our_role)
            .into_iter()
            .filter(|&role| self.store.count_connected_by_role(role) == 0)
            .collect()
    }

    /// Get role health summary.
    ///
    /// Returns map of: role → (dependency_level, connected_count)
    pub fn role_health(&self) -> Vec<(NodeRole, RoleDependency, usize)> {
        let all_roles = [
            NodeRole::StorageCompute,
            NodeRole::Validator,
            NodeRole::Coordinator,
        ];

        all_roles.iter()
            .map(|&role| {
                let dep = role_dependency(self.our_role, role);
                let count = self.store.count_connected_by_role(role);
                (role, dep, count)
            })
            .collect()
    }

    // ════════════════════════════════════════════════════════════════════════
    // MAINTENANCE
    // ════════════════════════════════════════════════════════════════════════

    /// Periodic maintenance tick. Call this every ~60 seconds.
    ///
    /// - Recompute all scores (including role_bonus)
    /// - Run garbage collection
    /// - Save peers.dat
    /// - Cleanup PEX rate limiter
    /// - Log role health warnings
    pub fn maintenance_tick(&mut self) -> Result<(), anyhow::Error> {
        self.store.recompute_all_scores();
        self.store.garbage_collect();
        self.store.save()?;
        self.pex_limiter.cleanup();

        // Log warning jika REQUIRED role belum terpenuhi
        let missing = self.missing_required_roles();
        if !missing.is_empty() {
            let names: Vec<&str> = missing.iter().map(|r| r.as_str()).collect();
            println!("   ⚠️ Missing REQUIRED role peers: {:?}", names);
        }

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

        // Recreate empty store (with our_role for scoring)
        self.store = PeerStore::new(
            &self.config.peers_file,
            self.network_id,
            self.our_role,
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
        let missing = self.missing_required_roles();
        let health = if missing.is_empty() {
            "healthy".to_string()
        } else {
            let names: Vec<&str> = missing.iter().map(|r| r.as_str()).collect();
            format!("MISSING: {:?}", names)
        };
        format!(
            "P2P Status [{}] node={} role={} bootstrap={:?} health={}\n  {}",
            self.network_id,
            self.our_node_id,
            self.config.role_display(),
            self.bootstrap_state,
            health,
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
        let config = BootstrapConfig::development(); // StorageCompute Reguler
        PeerManager::new(NetworkId::Devnet, node_id, config)
    }

    fn make_manager_with_role(role: NodeRole, class: Option<NodeClass>) -> PeerManager {
        let node_id = NodeId::from_bytes([0xAAu8; 32]);
        let mut config = BootstrapConfig::development();
        config.role = role;
        config.node_class = class;
        PeerManager::new(NetworkId::Devnet, node_id, config)
    }

    #[test]
    fn test_manager_creation() {
        let mgr = make_manager();
        assert_eq!(mgr.network_id, NetworkId::Devnet);
        assert_eq!(mgr.our_role, NodeRole::StorageCompute);
        assert_eq!(mgr.our_node_class, Some(NodeClass::Reguler));
        assert_eq!(mgr.connected_count(), 0);
        assert_eq!(mgr.known_count(), 0);
    }

    #[test]
    fn test_manager_validator_role() {
        let mgr = make_manager_with_role(NodeRole::Validator, None);
        assert_eq!(mgr.our_role, NodeRole::Validator);
        assert_eq!(mgr.our_node_class, None);
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

        // Handshake success with role+class
        mgr.on_handshake_success(
            addr, peer_node.clone(),
            NodeRole::StorageCompute, Some(NodeClass::DataCenter),
            100,
        );
        assert_eq!(mgr.connected_count(), 1);
        assert_eq!(mgr.known_count(), 1);

        // Verify role stored
        let peer = mgr.store.get("10.0.0.1:45831").unwrap();
        assert_eq!(peer.role, NodeRole::StorageCompute);
        assert_eq!(peer.node_class, Some(NodeClass::DataCenter));

        // Disconnect
        mgr.on_peer_disconnected(&addr);
        assert_eq!(mgr.connected_count(), 0);
    }

    // ── Role-based filtering tests ──

    #[test]
    fn test_post_handshake_required_role() {
        // StorageCompute needs Coordinator → REQUIRED → KeepConnection
        let mgr = make_manager(); // StorageCompute
        let action = mgr.decide_post_handshake(NodeRole::Coordinator, None);
        assert_eq!(action, PostHandshakeAction::KeepConnection);
    }

    #[test]
    fn test_post_handshake_optional_role() {
        // StorageCompute needs Validator → OPTIONAL → KeepConnection (we have room)
        let mgr = make_manager();
        let action = mgr.decide_post_handshake(NodeRole::Validator, None);
        assert_eq!(action, PostHandshakeAction::KeepConnection);
    }

    #[test]
    fn test_post_handshake_skip_role() {
        // StorageCompute needs Bootstrap → SKIP → PexThenDisconnect
        let mgr = make_manager();
        let action = mgr.decide_post_handshake(NodeRole::Bootstrap, None);
        assert_eq!(action, PostHandshakeAction::PexThenDisconnect);
    }

    #[test]
    fn test_post_handshake_invalid_validator_with_class() {
        let mgr = make_manager();
        // Validator TIDAK boleh punya class → invalid
        let action = mgr.decide_post_handshake(
            NodeRole::Validator,
            Some(NodeClass::DataCenter),
        );
        assert_eq!(action, PostHandshakeAction::Disconnect {
            reason: DisconnectReason::InvalidHandshake,
        });
    }

    #[test]
    fn test_post_handshake_invalid_storage_without_class() {
        let mgr = make_manager();
        // StorageCompute HARUS punya class → invalid
        let action = mgr.decide_post_handshake(
            NodeRole::StorageCompute,
            None,
        );
        assert_eq!(action, PostHandshakeAction::Disconnect {
            reason: DisconnectReason::InvalidHandshake,
        });
    }

    // ── Role health tests ──

    #[test]
    fn test_missing_required_roles_initial() {
        let mgr = make_manager(); // StorageCompute
        let missing = mgr.missing_required_roles();
        // StorageCompute needs: StorageCompute (REQUIRED) + Coordinator (REQUIRED)
        assert!(missing.contains(&NodeRole::StorageCompute));
        assert!(missing.contains(&NodeRole::Coordinator));
        assert!(!missing.contains(&NodeRole::Validator)); // OPTIONAL
    }

    #[test]
    fn test_all_required_roles_met() {
        let mut mgr = make_manager(); // StorageCompute

        // Initially not met
        assert!(!mgr.all_required_roles_met());

        // Connect a StorageCompute peer
        let addr1: SocketAddr = "10.0.0.1:45831".parse().unwrap();
        mgr.on_handshake_success(
            addr1, NodeId::from_bytes([0xBBu8; 32]),
            NodeRole::StorageCompute, Some(NodeClass::Reguler), 100,
        );

        // Still missing Coordinator
        assert!(!mgr.all_required_roles_met());
        let missing = mgr.missing_required_roles();
        assert_eq!(missing, vec![NodeRole::Coordinator]);

        // Connect a Coordinator peer
        let addr2: SocketAddr = "10.0.0.2:45831".parse().unwrap();
        mgr.on_handshake_success(
            addr2, NodeId::from_bytes([0xCCu8; 32]),
            NodeRole::Coordinator, None, 100,
        );

        // Now all met
        assert!(mgr.all_required_roles_met());
    }

    #[test]
    fn test_role_health() {
        let mgr = make_manager(); // StorageCompute
        let health = mgr.role_health();

        // Should have 3 entries (StorageCompute, Validator, Coordinator)
        assert_eq!(health.len(), 3);

        // StorageCompute: REQUIRED, 0 connected
        let sc = health.iter().find(|(r, _, _)| *r == NodeRole::StorageCompute).unwrap();
        assert_eq!(sc.1, RoleDependency::Required);
        assert_eq!(sc.2, 0);

        // Validator: OPTIONAL for StorageCompute
        let val = health.iter().find(|(r, _, _)| *r == NodeRole::Validator).unwrap();
        assert_eq!(val.1, RoleDependency::Optional);
    }

    // ── Coordinator perspective ──

    #[test]
    fn test_coordinator_needs_all_roles() {
        let mgr = make_manager_with_role(NodeRole::Coordinator, None);
        let missing = mgr.missing_required_roles();
        // Coordinator needs: Coordinator + StorageCompute + Validator (all REQUIRED)
        assert_eq!(missing.len(), 3);
        assert!(missing.contains(&NodeRole::Coordinator));
        assert!(missing.contains(&NodeRole::StorageCompute));
        assert!(missing.contains(&NodeRole::Validator));
    }

    // ── PEX tests ──

    #[test]
    fn test_pex_roundtrip() {
        let mut mgr = make_manager();

        for i in 1..=5 {
            let addr: SocketAddr = format!("10.0.0.{}:45831", i).parse().unwrap();
            let node = NodeId::from_bytes([i; 32]);
            mgr.on_handshake_success(
                addr, node,
                NodeRole::StorageCompute, Some(NodeClass::Reguler),
                100,
            );
        }

        let request = mgr.build_pex_request(None);
        let response = mgr.handle_pex_request(&request, "10.0.0.99:45831");

        if let PexResponse::Peers { peers, .. } = &response {
            assert!(!peers.is_empty());
            // Check PEX includes role+class
            for p in peers {
                assert_eq!(p.role, NodeRole::StorageCompute);
                assert_eq!(p.node_class, Some(NodeClass::Reguler));
            }
        } else {
            panic!("expected Peers response");
        }
    }

    #[test]
    fn test_pex_request_for_missing_roles() {
        let mut mgr = make_manager(); // StorageCompute

        // Connect a StorageCompute peer
        let addr: SocketAddr = "10.0.0.1:45831".parse().unwrap();
        mgr.on_handshake_success(
            addr, NodeId::from_bytes([0xBBu8; 32]),
            NodeRole::StorageCompute, Some(NodeClass::Reguler), 100,
        );

        // PEX request should filter for missing Coordinator
        let request = mgr.build_pex_request_for_missing_roles();
        if let PexRequest::GetPeers { role_filter, .. } = &request {
            let filter = role_filter.as_ref().unwrap();
            assert!(filter.contains(&NodeRole::Coordinator));
            assert!(!filter.contains(&NodeRole::StorageCompute)); // already have one
        }
    }

    #[test]
    fn test_pex_rate_limiting() {
        let mut mgr = make_manager();

        let request = mgr.build_pex_request(None);

        let r1 = mgr.handle_pex_request(&request, "10.0.0.1:45831");
        assert!(matches!(r1, PexResponse::Peers { .. }));

        let r2 = mgr.handle_pex_request(&request, "10.0.0.1:45831");
        assert!(matches!(r2, PexResponse::Rejected { .. }));
    }

    #[test]
    fn test_bootstrap_with_static_peers() {
        let mut config = BootstrapConfig::development();
        config.add_static_peer("10.0.0.1:45831").unwrap();
        config.add_static_peer("10.0.0.2:45831").unwrap();

        let node_id = NodeId::from_bytes([0xAAu8; 32]);
        let mut mgr = PeerManager::new(NetworkId::Devnet, node_id, config);

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
    fn test_validate_hello_valid_storage() {
        let mgr = make_manager();
        let peer_id = NodeId::from_bytes([0xBBu8; 32]);
        let hello = handshake::build_hello(
            NetworkId::Devnet, peer_id, 45831,
            NodeRole::StorageCompute, Some(NodeClass::Reguler),
            50,
        );
        let result = mgr.validate_hello(&hello);
        assert!(result.is_accepted());
    }

    #[test]
    fn test_validate_hello_valid_validator() {
        let mgr = make_manager();
        let peer_id = NodeId::from_bytes([0xBBu8; 32]);
        let hello = handshake::build_hello(
            NetworkId::Devnet, peer_id, 45831,
            NodeRole::Validator, None,
            50,
        );
        let result = mgr.validate_hello(&hello);
        assert!(result.is_accepted());
    }

    #[test]
    fn test_validate_hello_wrong_network() {
        let mgr = make_manager();
        let peer_id = NodeId::from_bytes([0xBBu8; 32]);
        let hello = handshake::build_hello(
            NetworkId::Mainnet, peer_id, 45831,
            NodeRole::Validator, None,
            50,
        );
        let result = mgr.validate_hello(&hello);
        assert!(!result.is_accepted());
    }

    #[test]
    fn test_validate_hello_invalid_role_class() {
        let mgr = make_manager();
        let peer_id = NodeId::from_bytes([0xBBu8; 32]);
        // Validator with class = INVALID
        let hello = handshake::build_hello(
            NetworkId::Devnet, peer_id, 45831,
            NodeRole::Validator, Some(NodeClass::DataCenter),
            50,
        );
        let result = mgr.validate_hello(&hello);
        assert!(!result.is_accepted());
    }

    #[test]
    fn test_ban_peer() {
        let mut mgr = make_manager();
        let addr: SocketAddr = "10.0.0.1:45831".parse().unwrap();
        let peer_node = NodeId::from_bytes([0xBBu8; 32]);

        mgr.on_handshake_success(
            addr, peer_node,
            NodeRole::StorageCompute, Some(NodeClass::Reguler),
            100,
        );
        assert_eq!(mgr.connected_count(), 1);

        mgr.ban_peer(&addr, 3600);
        assert_eq!(mgr.connected_count(), 0);

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
    fn test_process_pex_response_adds_new_with_role() {
        let mut mgr = make_manager();

        let response = PexResponse::Peers {
            peers: vec![
                PexPeerInfo {
                    addr: "10.0.0.1:45831".parse().unwrap(),
                    node_id: NodeId::from_bytes([0x11u8; 32]),
                    role: NodeRole::StorageCompute,
                    node_class: Some(NodeClass::Reguler),
                    last_success: current_unix_time(),
                },
                PexPeerInfo {
                    addr: "10.0.0.2:45831".parse().unwrap(),
                    node_id: NodeId::from_bytes([0x22u8; 32]),
                    role: NodeRole::Coordinator,
                    node_class: None,
                    last_success: current_unix_time(),
                },
            ],
            total_known: 50,
        };

        let added = mgr.process_pex_response(&response);
        assert_eq!(added, 2);
        assert_eq!(mgr.known_count(), 2);

        // Verify roles stored
        let p1 = mgr.store.get("10.0.0.1:45831").unwrap();
        assert_eq!(p1.role, NodeRole::StorageCompute);
        assert_eq!(p1.node_class, Some(NodeClass::Reguler));

        let p2 = mgr.store.get("10.0.0.2:45831").unwrap();
        assert_eq!(p2.role, NodeRole::Coordinator);
        assert_eq!(p2.node_class, None);
    }

    #[test]
    fn test_get_peers_by_role() {
        let mut mgr = make_manager();

        // Add mixed-role peers
        mgr.on_handshake_success(
            "10.0.0.1:45831".parse().unwrap(),
            NodeId::from_bytes([0x01u8; 32]),
            NodeRole::StorageCompute, Some(NodeClass::Reguler), 100,
        );
        mgr.on_handshake_success(
            "10.0.0.2:45831".parse().unwrap(),
            NodeId::from_bytes([0x02u8; 32]),
            NodeRole::Validator, None, 100,
        );
        mgr.on_handshake_success(
            "10.0.0.3:45831".parse().unwrap(),
            NodeId::from_bytes([0x03u8; 32]),
            NodeRole::StorageCompute, Some(NodeClass::DataCenter), 100,
        );

        let sc_peers = mgr.get_peers_by_role(NodeRole::StorageCompute);
        assert_eq!(sc_peers.len(), 2);

        let val_peers = mgr.get_peers_by_role(NodeRole::Validator);
        assert_eq!(val_peers.len(), 1);

        let dc_peers = mgr.get_peers_by_role_class(NodeRole::StorageCompute, NodeClass::DataCenter);
        assert_eq!(dc_peers.len(), 1);

        assert_eq!(mgr.connected_count_by_role(NodeRole::StorageCompute), 2);
        assert_eq!(mgr.connected_count_by_role(NodeRole::Validator), 1);
        assert_eq!(mgr.connected_count_by_role(NodeRole::Coordinator), 0);
    }

    #[test]
    fn test_status_summary() {
        let mgr = make_manager();
        let summary = mgr.status_summary();
        assert!(summary.contains("devnet"));
        assert!(summary.contains("P2P Status"));
        assert!(summary.contains("storage-compute"));
        assert!(summary.contains("MISSING")); // no peers yet
    }

    #[test]
    fn test_status_summary_healthy() {
        let mut mgr = make_manager();

        // Connect all required roles
        mgr.on_handshake_success(
            "10.0.0.1:45831".parse().unwrap(),
            NodeId::from_bytes([0x01u8; 32]),
            NodeRole::StorageCompute, Some(NodeClass::Reguler), 100,
        );
        mgr.on_handshake_success(
            "10.0.0.2:45831".parse().unwrap(),
            NodeId::from_bytes([0x02u8; 32]),
            NodeRole::Coordinator, None, 100,
        );

        let summary = mgr.status_summary();
        assert!(summary.contains("healthy"));
    }
}