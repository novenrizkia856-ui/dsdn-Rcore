//! # Peer Exchange (PEX) Protocol
//!
//! Setelah terhubung ke peer, node bisa minta peer list dari peer lain.
//! Ini memungkinkan jaringan tumbuh secara organik tanpa bergantung DNS.
//!
//! ## Flow
//!
//! ```text
//! Node A ────── GetPeers ──────> Node B
//! Node A <───── Peers(list) ──── Node B
//! Node A: filter → validate → connect ke peer baru
//! ```
//!
//! ## Rate Limiting
//!
//! - Max 1 PEX request per peer per 15 menit
//! - Max 1000 peer entries per response
//! - Banned peers tidak di-share

use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::net::SocketAddr;

use super::identity::{NetworkId, NodeId};
use super::types::{ServiceType, current_unix_time};

// ════════════════════════════════════════════════════════════════════════════
// PEX CONFIG
// ════════════════════════════════════════════════════════════════════════════

/// Konfigurasi PEX protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PexConfig {
    /// Max peer entries per PEX response
    pub max_peers_per_response: usize,
    /// Rate limit: minimum interval antar request ke peer yang sama (detik)
    pub rate_limit_secs: u64,
    /// Hanya share peer yang terakhir sukses connect < N detik lalu
    pub max_last_success_age_secs: u64,
}

impl Default for PexConfig {
    fn default() -> Self {
        Self {
            max_peers_per_response: 1000,
            rate_limit_secs: 900, // 15 menit
            max_last_success_age_secs: 86400, // 24 jam
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// PEX MESSAGES
// ════════════════════════════════════════════════════════════════════════════

/// PEX request dari node ke peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PexRequest {
    /// Request daftar peer yang diketahui
    GetPeers {
        /// Network ID — hanya return peer dari network yang sama
        network_id: NetworkId,
        /// Optional: filter by service type
        service_type_filter: Option<ServiceType>,
        /// Max entries yang diminta
        max_count: usize,
    },
}

/// Entry peer di PEX response.
/// Ini BUKAN full PeerEntry — hanya info yang aman untuk di-share.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PexPeerInfo {
    /// Socket address (IP:Port)
    pub addr: SocketAddr,
    /// Node ID (Ed25519 pubkey)
    pub node_id: NodeId,
    /// Service type
    pub service_type: ServiceType,
    /// Terakhir kali peer ini berhasil di-contact oleh sender
    pub last_success: u64,
}

/// PEX response dari peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PexResponse {
    /// Daftar peer yang diketahui
    Peers {
        /// List peer info
        peers: Vec<PexPeerInfo>,
        /// Total known peers (mungkin lebih dari yang di-share)
        total_known: usize,
    },
    /// PEX ditolak (rate limited, dll)
    Rejected {
        reason: String,
        /// Retry setelah N detik
        retry_after_secs: u64,
    },
}

// ════════════════════════════════════════════════════════════════════════════
// PEX RATE LIMITER
// ════════════════════════════════════════════════════════════════════════════

/// Rate limiter untuk PEX requests.
/// Track kapan terakhir kali setiap peer kirim PEX request.
pub struct PexRateLimiter {
    /// Last request timestamp per peer (keyed by addr string)
    last_request: HashMap<String, u64>,
    /// Minimum interval antar request (detik)
    interval_secs: u64,
}

impl PexRateLimiter {
    pub fn new(interval_secs: u64) -> Self {
        Self {
            last_request: HashMap::new(),
            interval_secs,
        }
    }

    /// Check apakah peer boleh kirim PEX request.
    pub fn is_allowed(&self, peer_addr: &str) -> bool {
        let now = current_unix_time();
        match self.last_request.get(peer_addr) {
            Some(&last) => now.saturating_sub(last) >= self.interval_secs,
            None => true,
        }
    }

    /// Record bahwa peer telah kirim PEX request.
    pub fn record_request(&mut self, peer_addr: &str) {
        self.last_request.insert(peer_addr.to_string(), current_unix_time());
    }

    /// Sisa waktu sebelum peer boleh request lagi (dalam detik).
    pub fn retry_after(&self, peer_addr: &str) -> u64 {
        let now = current_unix_time();
        match self.last_request.get(peer_addr) {
            Some(&last) => {
                let elapsed = now.saturating_sub(last);
                if elapsed >= self.interval_secs {
                    0
                } else {
                    self.interval_secs - elapsed
                }
            }
            None => 0,
        }
    }

    /// Cleanup entries yang sudah expired.
    pub fn cleanup(&mut self) {
        let now = current_unix_time();
        self.last_request.retain(|_, &mut last| {
            now.saturating_sub(last) < self.interval_secs * 2
        });
    }
}

// ════════════════════════════════════════════════════════════════════════════
// PEX HANDLER
// ════════════════════════════════════════════════════════════════════════════

/// Build PEX response dari PeerStore data.
///
/// Filtering rules:
/// 1. Hanya peer dari network_id yang diminta
/// 2. Hanya peer yang last_success < max_age (tidak share dead peer)
/// 3. Tidak share banned peers
/// 4. Tidak share peer yang request (no echo)
/// 5. Optional: filter by service_type
/// 6. Limit max_count
pub fn build_pex_response(
    peers: &[super::types::PeerEntry],
    request: &PexRequest,
    requester_addr: &str,
    config: &PexConfig,
) -> PexResponse {
    let PexRequest::GetPeers { network_id, service_type_filter, max_count } = request;

    let now = current_unix_time();
    let max_age = config.max_last_success_age_secs;

    let mut result: Vec<PexPeerInfo> = peers.iter()
        .filter(|p| {
            // Filter: same network
            p.network_id == *network_id
            // Filter: not banned
            && !p.is_banned()
            // Filter: has been successfully contacted recently
            && p.last_success > 0
            && now.saturating_sub(p.last_success) < max_age
            // Filter: not the requester
            && p.store_key() != requester_addr
            // Filter: not zero node_id
            && !p.node_id.is_zero()
        })
        .filter(|p| {
            // Optional service type filter
            match service_type_filter {
                Some(st) => p.service_type == *st,
                None => true,
            }
        })
        .take(*max_count.min(&config.max_peers_per_response))
        .map(|p| PexPeerInfo {
            addr: p.addr,
            node_id: p.node_id.clone(),
            service_type: p.service_type,
            last_success: p.last_success,
        })
        .collect();

    let total_known = peers.len();

    PexResponse::Peers {
        peers: result,
        total_known,
    }
}

// ════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::types::*;
    use std::str::FromStr;

    fn make_peer(ip: &str, success: bool) -> PeerEntry {
        let addr = SocketAddr::from_str(ip).unwrap();
        let mut p = PeerEntry::new(addr, NetworkId::Devnet, PeerSource::Manual);
        p.node_id = NodeId::from_bytes([ip.as_bytes()[0]; 32]);
        p.service_type = ServiceType::Chain;
        if success {
            p.record_success();
        }
        p
    }

    #[test]
    fn test_pex_rate_limiter() {
        let mut rl = PexRateLimiter::new(900);
        assert!(rl.is_allowed("10.0.0.1:45831"));
        rl.record_request("10.0.0.1:45831");
        assert!(!rl.is_allowed("10.0.0.1:45831"));
        assert!(rl.retry_after("10.0.0.1:45831") > 0);
    }

    #[test]
    fn test_pex_response_filters_banned() {
        let mut banned = make_peer("10.0.0.1:45831", true);
        banned.ban(3600);
        let good = make_peer("10.0.0.2:45831", true);

        let peers = vec![banned, good];
        let request = PexRequest::GetPeers {
            network_id: NetworkId::Devnet,
            service_type_filter: None,
            max_count: 100,
        };

        let response = build_pex_response(&peers, &request, "10.0.0.3:45831", &PexConfig::default());
        if let PexResponse::Peers { peers: result, .. } = response {
            assert_eq!(result.len(), 1);
            assert_eq!(result[0].addr.to_string(), "10.0.0.2:45831");
        } else {
            panic!("expected Peers response");
        }
    }

    #[test]
    fn test_pex_response_filters_requester() {
        let me = make_peer("10.0.0.1:45831", true);
        let other = make_peer("10.0.0.2:45831", true);

        let peers = vec![me, other];
        let request = PexRequest::GetPeers {
            network_id: NetworkId::Devnet,
            service_type_filter: None,
            max_count: 100,
        };

        let response = build_pex_response(&peers, &request, "10.0.0.1:45831", &PexConfig::default());
        if let PexResponse::Peers { peers: result, .. } = response {
            // Should not include the requester
            assert!(result.iter().all(|p| p.addr.to_string() != "10.0.0.1:45831"));
        }
    }

    #[test]
    fn test_pex_service_type_filter() {
        let mut chain = make_peer("10.0.0.1:45831", true);
        chain.service_type = ServiceType::Chain;

        let mut storage = make_peer("10.0.0.2:45831", true);
        storage.service_type = ServiceType::Storage;

        let peers = vec![chain, storage];
        let request = PexRequest::GetPeers {
            network_id: NetworkId::Devnet,
            service_type_filter: Some(ServiceType::Chain),
            max_count: 100,
        };

        let response = build_pex_response(&peers, &request, "10.0.0.3:45831", &PexConfig::default());
        if let PexResponse::Peers { peers: result, .. } = response {
            assert_eq!(result.len(), 1);
            assert_eq!(result[0].service_type, ServiceType::Chain);
        }
    }

    #[test]
    fn test_pex_response_respects_max_count() {
        let peers: Vec<PeerEntry> = (1..=50)
            .map(|i| make_peer(&format!("10.0.0.{}:45831", i), true))
            .collect();

        let request = PexRequest::GetPeers {
            network_id: NetworkId::Devnet,
            service_type_filter: None,
            max_count: 5,
        };

        let response = build_pex_response(&peers, &request, "10.0.0.100:45831", &PexConfig::default());
        if let PexResponse::Peers { peers: result, .. } = response {
            assert_eq!(result.len(), 5);
        }
    }
}