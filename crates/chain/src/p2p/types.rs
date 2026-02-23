//! # P2P Types
//!
//! Tipe data inti untuk peer management. PeerEntry adalah representasi
//! lengkap sebuah peer termasuk metadata scoring, source, dan status.
//!
//! ## Roles (sesuai Whitepaper DSDN)
//!
//! - **StorageCompute**: Full node (storage + compute), ada 2 kelas: Reguler & DataCenter
//! - **Validator**: Governance, compliance, PoS consensus blockchain Nusantara
//! - **Coordinator**: Metadata, scheduling, job queue, Celestia blob replay
//! - **Bootstrap**: Dedicated peer discovery node (non-operational)
//!
//! Blockchain Nusantara berjalan embedded di semua node — bukan role terpisah.

use serde::{Serialize, Deserialize};
use std::fmt;
use std::net::SocketAddr;
use super::identity::NodeId;
use super::identity::NetworkId;

// ════════════════════════════════════════════════════════════════════════════
// NODE ROLE
// ════════════════════════════════════════════════════════════════════════════

/// Role operasional node di jaringan DSDN.
///
/// Sesuai whitepaper: blockchain Nusantara embedded di semua node.
/// Validator menjalankan PoS consensus, node lain sync block sebagai client.
/// Tidak ada role "Chain" terpisah.
///
/// Saat handshake dan PEX, node mengiklankan role-nya.
/// Ini memungkinkan node menemukan komponen spesifik yang dibutuhkan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeRole {
    /// Full node: storage + compute.
    /// Kelas (Reguler/DataCenter) menentukan kapasitas dan stake requirement.
    /// Reguler: stake 500 $NUSA, DataCenter: stake 5,000 $NUSA.
    StorageCompute,

    /// Validator: governance, compliance, PoS consensus blockchain Nusantara.
    /// Memproduksi block, memfinalisasi transaksi, governance voting.
    /// Stake: 50,000 $NUSA.
    Validator,

    /// Coordinator: metadata global, scheduling, job queue, Celestia blob replay.
    /// Stateless scheduler — semua keputusan bisa direkonstruksi dari DA log.
    Coordinator,

    /// Dedicated bootstrap node (peer discovery only, non-operational).
    /// Hanya melayani handshake dan PEX, tidak ikut storage/compute/consensus.
    Bootstrap,
}

impl NodeRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            NodeRole::StorageCompute => "storage-compute",
            NodeRole::Validator => "validator",
            NodeRole::Coordinator => "coordinator",
            NodeRole::Bootstrap => "bootstrap",
        }
    }

    pub fn from_str_role(s: &str) -> Option<Self> {
        match s.to_lowercase().replace('_', "-").as_str() {
            "storage-compute" | "storagecompute" | "storage" | "compute" => Some(NodeRole::StorageCompute),
            "validator" => Some(NodeRole::Validator),
            "coordinator" => Some(NodeRole::Coordinator),
            "bootstrap" => Some(NodeRole::Bootstrap),
            _ => None,
        }
    }

    /// Bitmask representation untuk compact encoding di wire protocol.
    pub fn to_bitmask(&self) -> u8 {
        match self {
            NodeRole::StorageCompute => 0x01,
            NodeRole::Validator => 0x02,
            NodeRole::Coordinator => 0x04,
            NodeRole::Bootstrap => 0x08,
        }
    }

    pub fn from_bitmask(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(NodeRole::StorageCompute),
            0x02 => Some(NodeRole::Validator),
            0x04 => Some(NodeRole::Coordinator),
            0x08 => Some(NodeRole::Bootstrap),
            _ => None,
        }
    }

    /// Apakah role ini operational (bukan bootstrap)?
    pub fn is_operational(&self) -> bool {
        !matches!(self, NodeRole::Bootstrap)
    }

    /// Apakah role ini punya node_class?
    /// Hanya StorageCompute yang punya class (Reguler/DataCenter).
    pub fn has_node_class(&self) -> bool {
        matches!(self, NodeRole::StorageCompute)
    }
}

impl fmt::Display for NodeRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ════════════════════════════════════════════════════════════════════════════
// NODE CLASS
// ════════════════════════════════════════════════════════════════════════════

/// Kelas node, khusus untuk role StorageCompute.
///
/// Sesuai whitepaper DSDN:
/// - Reguler: partisipasi publik, kapasitas terbatas (stake 500 $NUSA)
/// - DataCenter: kapasitas besar, GPU, SLA tinggi (stake 5,000 $NUSA)
///
/// Validator dan Coordinator TIDAK punya kelas — node_class harus None.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeClass {
    /// Full Node Reguler: CPU 4-8 vCPU, RAM 8-32 GiB, Storage 512GB-2TB.
    /// Stake: 500 $NUSA.
    Reguler,

    /// Full Node Data Center: CPU 32-64 vCPU, RAM 128-256 GiB, Storage 4-16TB, GPU.
    /// Stake: 5,000 $NUSA.
    DataCenter,
}

impl NodeClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            NodeClass::Reguler => "reguler",
            NodeClass::DataCenter => "datacenter",
        }
    }

    pub fn from_str_class(s: &str) -> Option<Self> {
        match s.to_lowercase().replace('_', "").replace('-', "").as_str() {
            "reguler" | "regular" => Some(NodeClass::Reguler),
            "datacenter" | "dc" => Some(NodeClass::DataCenter),
            _ => None,
        }
    }

    pub fn to_bitmask(&self) -> u8 {
        match self {
            NodeClass::Reguler => 0x01,
            NodeClass::DataCenter => 0x02,
        }
    }

    pub fn from_bitmask(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(NodeClass::Reguler),
            0x02 => Some(NodeClass::DataCenter),
            _ => None,
        }
    }
}

impl fmt::Display for NodeClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ════════════════════════════════════════════════════════════════════════════
// ROLE DEPENDENCY
// ════════════════════════════════════════════════════════════════════════════

/// Tingkat kebutuhan koneksi terhadap role tertentu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleDependency {
    /// HARUS punya minimal 1 peer dengan role ini.
    Required,
    /// Bagus jika ada, tapi tidak blocking.
    Optional,
    /// Tidak dibutuhkan — disconnect setelah handshake, tapi cache di peers.dat.
    Skip,
}

/// Role Dependency Matrix — menentukan siapa butuh siapa.
///
/// Sesuai Tahap 21 v2:
/// ```text
/// StorageCompute butuh:
///   StorageCompute → REQUIRED (data replication)
///   Coordinator    → REQUIRED (register, terima task)
///   Validator      → OPTIONAL (governance reads via blockchain)
///
/// Validator butuh:
///   Validator      → REQUIRED (PoS consensus, block production)
///   Coordinator    → REQUIRED (koordinasi, status)
///   StorageCompute → OPTIONAL (monitoring, compliance)
///
/// Coordinator butuh:
///   Coordinator    → REQUIRED (multi-coordinator sync, TSS/FROST)
///   StorageCompute → REQUIRED (task dispatch, node management)
///   Validator      → REQUIRED (stake verification, governance)
/// ```
pub fn role_dependency(our_role: NodeRole, peer_role: NodeRole) -> RoleDependency {
    match (our_role, peer_role) {
        // ── StorageCompute dependencies ──
        (NodeRole::StorageCompute, NodeRole::StorageCompute) => RoleDependency::Required,
        (NodeRole::StorageCompute, NodeRole::Coordinator)    => RoleDependency::Required,
        (NodeRole::StorageCompute, NodeRole::Validator)      => RoleDependency::Optional,

        // ── Validator dependencies ──
        (NodeRole::Validator, NodeRole::Validator)      => RoleDependency::Required,
        (NodeRole::Validator, NodeRole::Coordinator)    => RoleDependency::Required,
        (NodeRole::Validator, NodeRole::StorageCompute) => RoleDependency::Optional,

        // ── Coordinator dependencies ──
        (NodeRole::Coordinator, NodeRole::Coordinator)    => RoleDependency::Required,
        (NodeRole::Coordinator, NodeRole::StorageCompute) => RoleDependency::Required,
        (NodeRole::Coordinator, NodeRole::Validator)      => RoleDependency::Required,

        // ── Bootstrap: semua role Skip karena bootstrap bukan operational ──
        (NodeRole::Bootstrap, _) => RoleDependency::Skip,

        // ── Semua role terhadap Bootstrap: Skip (tapi PEX dulu sebelum disconnect) ──
        (_, NodeRole::Bootstrap) => RoleDependency::Skip,
    }
}

/// Get daftar role yang REQUIRED untuk role tertentu.
pub fn required_roles(our_role: NodeRole) -> Vec<NodeRole> {
    let all_roles = [NodeRole::StorageCompute, NodeRole::Validator, NodeRole::Coordinator];
    all_roles.iter()
        .filter(|&&r| role_dependency(our_role, r) == RoleDependency::Required)
        .cloned()
        .collect()
}

/// Get daftar role yang OPTIONAL untuk role tertentu.
pub fn optional_roles(our_role: NodeRole) -> Vec<NodeRole> {
    let all_roles = [NodeRole::StorageCompute, NodeRole::Validator, NodeRole::Coordinator];
    all_roles.iter()
        .filter(|&&r| role_dependency(our_role, r) == RoleDependency::Optional)
        .cloned()
        .collect()
}

// ════════════════════════════════════════════════════════════════════════════
// DISCONNECT REASON
// ════════════════════════════════════════════════════════════════════════════

/// Alasan disconnect dari peer setelah handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DisconnectReason {
    /// Role tidak dibutuhkan oleh node ini (SKIP di RoleDependencyMatrix)
    RoleNotNeeded,
    /// Sudah cukup peer — max connections reached
    TooManyPeers,
    /// Network ID berbeda (mainnet vs testnet)
    NetworkIdMismatch,
    /// Protocol version tidak kompatibel
    ProtocolIncompatible,
    /// Handshake data invalid (misal: Validator kirim node_class = DataCenter)
    InvalidHandshake,
    /// Handshake timeout
    Timeout,
    /// Peer di-ban
    Banned,
    /// Node sedang shutdown
    Shutdown,
}

impl DisconnectReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            DisconnectReason::RoleNotNeeded => "role_not_needed",
            DisconnectReason::TooManyPeers => "too_many_peers",
            DisconnectReason::NetworkIdMismatch => "network_id_mismatch",
            DisconnectReason::ProtocolIncompatible => "protocol_incompatible",
            DisconnectReason::InvalidHandshake => "invalid_handshake",
            DisconnectReason::Timeout => "timeout",
            DisconnectReason::Banned => "banned",
            DisconnectReason::Shutdown => "shutdown",
        }
    }
}

impl fmt::Display for DisconnectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ════════════════════════════════════════════════════════════════════════════
// PEER SOURCE
// ════════════════════════════════════════════════════════════════════════════

/// Dari mana peer ditemukan.
///
/// Penting untuk anti-eclipse attack: node HARUS punya peer dari
/// BERBAGAI sumber, bukan satu sumber saja.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PeerSource {
    /// Dari DNS seed resolution
    DnsSeed,
    /// Dari static IP di config
    StaticConfig,
    /// Dari Peer Exchange (PEX) — peer memberi tahu peer lain
    PeerExchange,
    /// Dari inbound connection (peer connect ke kita)
    Inbound,
    /// Manual add oleh operator via CLI/RPC
    Manual,
    /// Dari peers.dat (loaded saat startup)
    PeerCache,
}

impl PeerSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            PeerSource::DnsSeed => "dns_seed",
            PeerSource::StaticConfig => "static_config",
            PeerSource::PeerExchange => "peer_exchange",
            PeerSource::Inbound => "inbound",
            PeerSource::Manual => "manual",
            PeerSource::PeerCache => "peer_cache",
        }
    }
}

impl fmt::Display for PeerSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ════════════════════════════════════════════════════════════════════════════
// PEER STATUS
// ════════════════════════════════════════════════════════════════════════════

/// Status koneksi peer saat ini.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PeerStatus {
    /// Peer diketahui tapi belum pernah di-contact
    Discovered,
    /// Sedang proses handshake
    Connecting,
    /// Handshake berhasil, peer aktif
    Connected,
    /// Peer terputus (bisa reconnect)
    Disconnected,
    /// Peer di-ban (tidak boleh reconnect untuk durasi tertentu)
    Banned {
        /// Unix timestamp kapan ban expire
        until: u64,
    },
}

// ════════════════════════════════════════════════════════════════════════════
// PEER ENTRY
// ════════════════════════════════════════════════════════════════════════════

/// Representasi lengkap sebuah peer dalam DSDN network.
///
/// Ini adalah "source of truth" untuk sebuah peer, disimpan di
/// PeerStore (peers.dat) dan digunakan oleh PeerManager.
///
/// ## Field Groups
///
/// - **Identity**: addr, node_id, network_id
/// - **Role**: role, node_class
/// - **Metadata**: source, status
/// - **Timestamps**: first_seen, last_seen, last_success, last_failure
/// - **Counters**: success_count, failure_count, consecutive_failures
/// - **Scoring**: score (computed by PeerScorer)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerEntry {
    // ── Identity ──────────────────────────────────────────
    /// Socket address (IP:Port, selalu port 45831)
    pub addr: SocketAddr,
    /// Node ID (Ed25519 pubkey) — bisa unknown sebelum handshake
    pub node_id: NodeId,
    /// Network yang dilaporkan peer (verified saat handshake)
    pub network_id: NetworkId,

    // ── Role & Class (diketahui setelah handshake) ───────
    /// Role operasional peer
    pub role: NodeRole,
    /// Kelas node — hanya relevan jika role == StorageCompute.
    /// None untuk Validator, Coordinator, dan Bootstrap.
    pub node_class: Option<NodeClass>,

    // ── Metadata ──────────────────────────────────────────
    /// Dari mana peer ini ditemukan
    pub source: PeerSource,
    /// Status koneksi saat ini
    pub status: PeerStatus,

    // ── Timestamps (Unix epoch seconds) ──────────────────
    /// Pertama kali peer ditemukan
    pub first_seen: u64,
    /// Terakhir kali ada interaksi (apapun) dengan peer
    pub last_seen: u64,
    /// Terakhir kali koneksi berhasil
    pub last_success: u64,
    /// Terakhir kali koneksi gagal
    pub last_failure: u64,

    // ── Counters ─────────────────────────────────────────
    /// Total koneksi berhasil sepanjang waktu
    pub success_count: u32,
    /// Total koneksi gagal sepanjang waktu
    pub failure_count: u32,
    /// Kegagalan berturut-turut (reset saat sukses)
    pub consecutive_failures: u32,

    // ── Scoring (computed) ───────────────────────────────
    /// Skor peer (dihitung oleh PeerScorer, bukan di-set manual)
    pub score: i64,
}

impl PeerEntry {
    /// Buat PeerEntry baru dengan defaults yang wajar.
    /// Role = StorageCompute (default, akan di-update setelah handshake).
    pub fn new(addr: SocketAddr, network_id: NetworkId, source: PeerSource) -> Self {
        let now = current_unix_time();
        Self {
            addr,
            node_id: NodeId::zero(),
            network_id,
            role: NodeRole::StorageCompute, // default, updated after handshake
            node_class: None,               // unknown until handshake
            source,
            status: PeerStatus::Discovered,
            first_seen: now,
            last_seen: now,
            last_success: 0,
            last_failure: 0,
            success_count: 0,
            failure_count: 0,
            consecutive_failures: 0,
            score: 0,
        }
    }

    /// Record successful connection.
    pub fn record_success(&mut self) {
        let now = current_unix_time();
        self.last_seen = now;
        self.last_success = now;
        self.success_count = self.success_count.saturating_add(1);
        self.consecutive_failures = 0;
        self.status = PeerStatus::Connected;
    }

    /// Record failed connection.
    pub fn record_failure(&mut self) {
        let now = current_unix_time();
        self.last_seen = now;
        self.last_failure = now;
        self.failure_count = self.failure_count.saturating_add(1);
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.status = PeerStatus::Disconnected;
    }

    /// Mark peer as disconnected.
    pub fn mark_disconnected(&mut self) {
        self.status = PeerStatus::Disconnected;
        self.last_seen = current_unix_time();
    }

    /// Ban peer untuk durasi tertentu (dalam detik).
    pub fn ban(&mut self, duration_secs: u64) {
        let until = current_unix_time() + duration_secs;
        self.status = PeerStatus::Banned { until };
    }

    /// Check apakah peer sedang di-ban.
    pub fn is_banned(&self) -> bool {
        match self.status {
            PeerStatus::Banned { until } => current_unix_time() < until,
            _ => false,
        }
    }

    /// Check apakah peer "suspicious" (gagal 10x berturut-turut).
    pub fn is_suspicious(&self) -> bool {
        self.consecutive_failures >= 10
    }

    /// Check apakah peer "stale" (tidak terlihat > N hari).
    pub fn is_stale(&self, max_age_secs: u64) -> bool {
        let now = current_unix_time();
        now.saturating_sub(self.last_seen) > max_age_secs
    }

    /// Unique key untuk peer di store: "IP:Port".
    pub fn store_key(&self) -> String {
        self.addr.to_string()
    }

    /// Update role dan class setelah handshake.
    pub fn update_role(&mut self, role: NodeRole, node_class: Option<NodeClass>) {
        self.role = role;
        self.node_class = node_class;
    }

    /// Validasi konsistensi role + class.
    /// - StorageCompute HARUS punya node_class.
    /// - Validator/Coordinator/Bootstrap HARUS node_class = None.
    pub fn is_role_class_valid(&self) -> bool {
        match self.role {
            NodeRole::StorageCompute => self.node_class.is_some(),
            NodeRole::Validator | NodeRole::Coordinator | NodeRole::Bootstrap => {
                self.node_class.is_none()
            }
        }
    }

    /// Human-readable role + class string (e.g. "storage-compute:datacenter").
    pub fn role_display(&self) -> String {
        match self.node_class {
            Some(class) => format!("{}:{}", self.role, class),
            None => self.role.to_string(),
        }
    }
}

impl fmt::Display for PeerEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Peer({} node={} role={} src={} score={} ok/fail={}/{})",
            self.addr,
            self.node_id,
            self.role_display(),
            self.source,
            self.score,
            self.success_count,
            self.failure_count,
        )
    }
}

// ════════════════════════════════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════════════════════════════════

/// Get current unix timestamp in seconds.
pub fn current_unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::str::FromStr;

    fn make_peer() -> PeerEntry {
        let addr = SocketAddr::from_str("192.168.1.1:45831").unwrap();
        PeerEntry::new(addr, NetworkId::Devnet, PeerSource::Manual)
    }

    #[test]
    fn test_peer_entry_new_defaults() {
        let peer = make_peer();
        assert_eq!(peer.status, PeerStatus::Discovered);
        assert_eq!(peer.success_count, 0);
        assert_eq!(peer.failure_count, 0);
        assert!(peer.node_id.is_zero());
        assert_eq!(peer.role, NodeRole::StorageCompute);
        assert_eq!(peer.node_class, None);
    }

    #[test]
    fn test_peer_record_success_resets_failures() {
        let mut peer = make_peer();
        peer.record_failure();
        peer.record_failure();
        assert_eq!(peer.consecutive_failures, 2);

        peer.record_success();
        assert_eq!(peer.consecutive_failures, 0);
        assert_eq!(peer.success_count, 1);
        assert_eq!(peer.failure_count, 2);
        assert_eq!(peer.status, PeerStatus::Connected);
    }

    #[test]
    fn test_peer_suspicious_threshold() {
        let mut peer = make_peer();
        for _ in 0..9 {
            peer.record_failure();
        }
        assert!(!peer.is_suspicious());
        peer.record_failure();
        assert!(peer.is_suspicious());
    }

    #[test]
    fn test_peer_ban_and_expiry() {
        let mut peer = make_peer();
        peer.ban(3600);
        assert!(peer.is_banned());

        if let PeerStatus::Banned { ref mut until } = peer.status {
            *until = 0; // expired
        }
        assert!(!peer.is_banned());
    }

    #[test]
    fn test_node_role_bitmask_roundtrip() {
        let roles = [
            NodeRole::StorageCompute,
            NodeRole::Validator,
            NodeRole::Coordinator,
            NodeRole::Bootstrap,
        ];
        for role in roles {
            let mask = role.to_bitmask();
            let restored = NodeRole::from_bitmask(mask).unwrap();
            assert_eq!(role, restored);
        }
    }

    #[test]
    fn test_node_class_bitmask_roundtrip() {
        let classes = [NodeClass::Reguler, NodeClass::DataCenter];
        for class in classes {
            let mask = class.to_bitmask();
            let restored = NodeClass::from_bitmask(mask).unwrap();
            assert_eq!(class, restored);
        }
    }

    #[test]
    fn test_role_class_validation() {
        let mut peer = make_peer();

        // StorageCompute tanpa class → invalid
        peer.role = NodeRole::StorageCompute;
        peer.node_class = None;
        assert!(!peer.is_role_class_valid());

        // StorageCompute dengan class → valid
        peer.node_class = Some(NodeClass::Reguler);
        assert!(peer.is_role_class_valid());

        // Validator dengan class → invalid
        peer.role = NodeRole::Validator;
        peer.node_class = Some(NodeClass::DataCenter);
        assert!(!peer.is_role_class_valid());

        // Validator tanpa class → valid
        peer.node_class = None;
        assert!(peer.is_role_class_valid());

        // Coordinator tanpa class → valid
        peer.role = NodeRole::Coordinator;
        assert!(peer.is_role_class_valid());
    }

    #[test]
    fn test_role_dependency_matrix() {
        // StorageCompute dependencies
        assert_eq!(role_dependency(NodeRole::StorageCompute, NodeRole::StorageCompute), RoleDependency::Required);
        assert_eq!(role_dependency(NodeRole::StorageCompute, NodeRole::Coordinator), RoleDependency::Required);
        assert_eq!(role_dependency(NodeRole::StorageCompute, NodeRole::Validator), RoleDependency::Optional);

        // Validator dependencies
        assert_eq!(role_dependency(NodeRole::Validator, NodeRole::Validator), RoleDependency::Required);
        assert_eq!(role_dependency(NodeRole::Validator, NodeRole::Coordinator), RoleDependency::Required);
        assert_eq!(role_dependency(NodeRole::Validator, NodeRole::StorageCompute), RoleDependency::Optional);

        // Coordinator dependencies
        assert_eq!(role_dependency(NodeRole::Coordinator, NodeRole::Coordinator), RoleDependency::Required);
        assert_eq!(role_dependency(NodeRole::Coordinator, NodeRole::StorageCompute), RoleDependency::Required);
        assert_eq!(role_dependency(NodeRole::Coordinator, NodeRole::Validator), RoleDependency::Required);

        // Bootstrap: semua skip
        assert_eq!(role_dependency(NodeRole::Bootstrap, NodeRole::Validator), RoleDependency::Skip);
        assert_eq!(role_dependency(NodeRole::StorageCompute, NodeRole::Bootstrap), RoleDependency::Skip);
    }

    #[test]
    fn test_required_roles() {
        let sc_required = required_roles(NodeRole::StorageCompute);
        assert!(sc_required.contains(&NodeRole::StorageCompute));
        assert!(sc_required.contains(&NodeRole::Coordinator));
        assert!(!sc_required.contains(&NodeRole::Validator));

        let coord_required = required_roles(NodeRole::Coordinator);
        assert_eq!(coord_required.len(), 3); // semua required
    }

    #[test]
    fn test_role_display() {
        let mut peer = make_peer();
        peer.role = NodeRole::StorageCompute;
        peer.node_class = Some(NodeClass::DataCenter);
        assert_eq!(peer.role_display(), "storage-compute:datacenter");

        peer.role = NodeRole::Validator;
        peer.node_class = None;
        assert_eq!(peer.role_display(), "validator");
    }

    #[test]
    fn test_disconnect_reason_display() {
        assert_eq!(DisconnectReason::RoleNotNeeded.as_str(), "role_not_needed");
        assert_eq!(DisconnectReason::InvalidHandshake.as_str(), "invalid_handshake");
    }
}