//! # P2P Types
//!
//! Tipe data inti untuk peer management. PeerEntry adalah representasi
//! lengkap sebuah peer termasuk metadata scoring, source, dan status.

use serde::{Serialize, Deserialize};
use std::fmt;
use std::net::SocketAddr;
use super::identity::NodeId;
use super::identity::NetworkId;

// ════════════════════════════════════════════════════════════════════════════
// SERVICE TYPE
// ════════════════════════════════════════════════════════════════════════════

/// Tipe layanan yang disediakan oleh node.
///
/// Saat handshake dan PEX, node mengiklankan service type-nya.
/// Ini memungkinkan node menemukan komponen spesifik yang dibutuhkan.
/// Misal: validator hanya perlu chain node dan coordinator, bukan storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ServiceType {
    /// Chain node (block production, state management)
    Chain,
    /// Storage node (data storage — reguler)
    Storage,
    /// Storage node (data center class)
    StorageDC,
    /// Coordinator (workload coordination, TSS/FROST)
    Coordinator,
    /// Validator (consensus & validation)
    Validator,
    /// Ingress (HTTP gateway)
    Ingress,
    /// Dedicated bootstrap node (peer discovery only)
    Bootstrap,
    /// Unknown / belum teridentifikasi
    Unknown,
}

impl ServiceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ServiceType::Chain => "chain",
            ServiceType::Storage => "storage",
            ServiceType::StorageDC => "storage_dc",
            ServiceType::Coordinator => "coordinator",
            ServiceType::Validator => "validator",
            ServiceType::Ingress => "ingress",
            ServiceType::Bootstrap => "bootstrap",
            ServiceType::Unknown => "unknown",
        }
    }

    pub fn from_str_type(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "chain" => ServiceType::Chain,
            "storage" => ServiceType::Storage,
            "storage_dc" | "storagedc" => ServiceType::StorageDC,
            "coordinator" => ServiceType::Coordinator,
            "validator" => ServiceType::Validator,
            "ingress" => ServiceType::Ingress,
            "bootstrap" => ServiceType::Bootstrap,
            _ => ServiceType::Unknown,
        }
    }

    /// Bitmask representation untuk compact encoding di wire protocol.
    pub fn to_bitmask(&self) -> u8 {
        match self {
            ServiceType::Chain => 0x01,
            ServiceType::Storage => 0x02,
            ServiceType::StorageDC => 0x04,
            ServiceType::Coordinator => 0x08,
            ServiceType::Validator => 0x10,
            ServiceType::Ingress => 0x20,
            ServiceType::Bootstrap => 0x40,
            ServiceType::Unknown => 0x00,
        }
    }

    pub fn from_bitmask(b: u8) -> Self {
        match b {
            0x01 => ServiceType::Chain,
            0x02 => ServiceType::Storage,
            0x04 => ServiceType::StorageDC,
            0x08 => ServiceType::Coordinator,
            0x10 => ServiceType::Validator,
            0x20 => ServiceType::Ingress,
            0x40 => ServiceType::Bootstrap,
            _ => ServiceType::Unknown,
        }
    }
}

impl fmt::Display for ServiceType {
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
/// - **Metadata**: service_type, source, status
/// - **Timestamps**: first_seen, last_seen, last_success, last_failure
/// - **Counters**: success_count, failure_count, consecutive_failures
/// - **Scoring**: score (computed by PeerScorer)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerEntry {
    // ── Identity ──────────────────────────────────────────
    /// Socket address (IP:Port)
    pub addr: SocketAddr,
    /// Node ID (Ed25519 pubkey) — bisa unknown sebelum handshake
    pub node_id: NodeId,
    /// Network yang dilaporkan peer (verified saat handshake)
    pub network_id: NetworkId,

    // ── Metadata ──────────────────────────────────────────
    /// Tipe layanan yang disediakan peer
    pub service_type: ServiceType,
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
    pub fn new(addr: SocketAddr, network_id: NetworkId, source: PeerSource) -> Self {
        let now = current_unix_time();
        Self {
            addr,
            node_id: NodeId::zero(),
            network_id,
            service_type: ServiceType::Unknown,
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
    /// Suspicious peer mendapat prioritas rendah tapi belum di-ban.
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
}

impl fmt::Display for PeerEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Peer({} node={} type={} src={} score={} ok/fail={}/{})",
            self.addr,
            self.node_id,
            self.service_type,
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
        assert_eq!(peer.service_type, ServiceType::Unknown);
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
        peer.ban(3600); // ban 1 hour
        assert!(peer.is_banned());

        // Simulate expired ban
        if let PeerStatus::Banned { ref mut until } = peer.status {
            *until = 0; // expired
        }
        assert!(!peer.is_banned());
    }

    #[test]
    fn test_service_type_bitmask_roundtrip() {
        let types = [
            ServiceType::Chain,
            ServiceType::Storage,
            ServiceType::StorageDC,
            ServiceType::Coordinator,
            ServiceType::Validator,
            ServiceType::Ingress,
            ServiceType::Bootstrap,
        ];
        for st in types {
            let mask = st.to_bitmask();
            let restored = ServiceType::from_bitmask(mask);
            assert_eq!(st, restored);
        }
    }
}