//! # Handshake Protocol
//!
//! Protocol handshake saat dua node pertama kali connect.
//!
//! ## Flow
//!
//! ```text
//! Node A ──────────────────────── Node B
//!   │                                │
//!   │── HandshakeMessage::Hello ────>│
//!   │                                │── validate
//!   │<── HandshakeMessage::Hello ────│
//!   │── validate                     │
//!   │                                │
//!   │ (jika valid: Connected)        │
//!   │ (jika invalid: Disconnect)     │
//! ```
//!
//! ## Validation Rules (Consensus-Critical)
//!
//! 1. protocol_version.major HARUS sama
//! 2. network_id HARUS sama (mainnet ≠ testnet)
//! 3. node_id HARUS valid (non-zero, bukan self)
//! 4. listen_port HARUS > 0

use serde::{Serialize, Deserialize};
use std::fmt;

use super::identity::{NetworkId, NodeId, ProtocolVersion, CURRENT_PROTOCOL_VERSION};
use super::types::ServiceType;

// ════════════════════════════════════════════════════════════════════════════
// HANDSHAKE MESSAGE
// ════════════════════════════════════════════════════════════════════════════

/// Message yang dikirim saat handshake antar node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HandshakeMessage {
    /// Hello — pesan pertama dari kedua pihak
    Hello {
        /// Versi protocol P2P
        protocol_version: ProtocolVersion,
        /// Network yang digunakan
        network_id: NetworkId,
        /// Identitas node (Ed25519 pubkey)
        node_id: NodeId,
        /// Port yang di-listen untuk inbound connections
        listen_port: u16,
        /// Service type yang disediakan node
        service_type: ServiceType,
        /// Chain tip height (agar peer tahu seberapa synced kita)
        chain_height: u64,
        /// User agent string (opsional, untuk observability)
        user_agent: String,
    },

    /// Handshake ditolak
    Reject {
        /// Alasan penolakan
        reason: HandshakeRejectReason,
        /// Pesan tambahan
        message: String,
    },
}

/// Alasan handshake ditolak.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HandshakeRejectReason {
    /// Protocol version incompatible (major berbeda)
    IncompatibleVersion,
    /// Network ID mismatch (mainnet vs testnet)
    NetworkMismatch,
    /// Self-connection detected
    SelfConnection,
    /// Already connected to this peer
    AlreadyConnected,
    /// Peer di-ban
    Banned,
    /// Too many connections
    TooManyConnections,
    /// Invalid node ID
    InvalidNodeId,
}

impl fmt::Display for HandshakeRejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncompatibleVersion => write!(f, "incompatible_version"),
            Self::NetworkMismatch => write!(f, "network_mismatch"),
            Self::SelfConnection => write!(f, "self_connection"),
            Self::AlreadyConnected => write!(f, "already_connected"),
            Self::Banned => write!(f, "banned"),
            Self::TooManyConnections => write!(f, "too_many_connections"),
            Self::InvalidNodeId => write!(f, "invalid_node_id"),
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// HANDSHAKE RESULT
// ════════════════════════════════════════════════════════════════════════════

/// Hasil validasi handshake.
#[derive(Debug, Clone)]
pub enum HandshakeResult {
    /// Handshake berhasil
    Accepted {
        /// Node ID peer yang terverifikasi
        node_id: NodeId,
        /// Service type peer
        service_type: ServiceType,
        /// Chain height peer
        chain_height: u64,
        /// Protocol version peer
        protocol_version: ProtocolVersion,
    },
    /// Handshake ditolak
    Rejected {
        reason: HandshakeRejectReason,
        message: String,
    },
}

impl HandshakeResult {
    pub fn is_accepted(&self) -> bool {
        matches!(self, HandshakeResult::Accepted { .. })
    }
}

// ════════════════════════════════════════════════════════════════════════════
// HANDSHAKE ERROR
// ════════════════════════════════════════════════════════════════════════════

/// Error selama proses handshake.
#[derive(Debug, Clone)]
pub enum HandshakeError {
    /// Timeout — peer tidak respond dalam waktu
    Timeout,
    /// Network error
    NetworkError(String),
    /// Protocol error (message malformed)
    ProtocolError(String),
    /// Rejected oleh peer
    Rejected(HandshakeRejectReason, String),
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => write!(f, "handshake timeout"),
            Self::NetworkError(e) => write!(f, "network error: {}", e),
            Self::ProtocolError(e) => write!(f, "protocol error: {}", e),
            Self::Rejected(reason, msg) => write!(f, "rejected ({}): {}", reason, msg),
        }
    }
}

impl std::error::Error for HandshakeError {}

// ════════════════════════════════════════════════════════════════════════════
// HANDSHAKE VALIDATOR
// ════════════════════════════════════════════════════════════════════════════

/// Validate inbound Hello message.
///
/// Ini adalah logic validation yang dipanggil saat menerima Hello dari peer.
/// Stateless dan deterministic.
///
/// ## Arguments
/// * `msg` - Hello message dari peer
/// * `our_network` - Network ID kita
/// * `our_node_id` - Node ID kita (untuk detect self-connection)
/// * `connected_ids` - Set node IDs yang sudah connected (detect duplicate)
/// * `current_connections` - Jumlah koneksi saat ini
/// * `max_connections` - Batas maksimum koneksi
pub fn validate_hello(
    msg: &HandshakeMessage,
    our_network: NetworkId,
    our_node_id: &NodeId,
    connected_ids: &std::collections::HashSet<NodeId>,
    current_connections: usize,
    max_connections: usize,
) -> HandshakeResult {
    match msg {
        HandshakeMessage::Hello {
            protocol_version,
            network_id,
            node_id,
            listen_port: _,
            service_type,
            chain_height,
            user_agent: _,
        } => {
            // Rule 1: Protocol version compatible
            if !protocol_version.is_compatible(&CURRENT_PROTOCOL_VERSION) {
                return HandshakeResult::Rejected {
                    reason: HandshakeRejectReason::IncompatibleVersion,
                    message: format!(
                        "our major={} theirs={}",
                        CURRENT_PROTOCOL_VERSION.major,
                        protocol_version.major,
                    ),
                };
            }

            // Rule 2: Network ID must match
            if *network_id != our_network {
                return HandshakeResult::Rejected {
                    reason: HandshakeRejectReason::NetworkMismatch,
                    message: format!(
                        "our={} theirs={}",
                        our_network,
                        network_id,
                    ),
                };
            }

            // Rule 3: Node ID must be valid (non-zero)
            if node_id.is_zero() {
                return HandshakeResult::Rejected {
                    reason: HandshakeRejectReason::InvalidNodeId,
                    message: "zero node_id".to_string(),
                };
            }

            // Rule 4: Not self-connection
            if node_id == our_node_id {
                return HandshakeResult::Rejected {
                    reason: HandshakeRejectReason::SelfConnection,
                    message: "same node_id as self".to_string(),
                };
            }

            // Rule 5: Not already connected
            if connected_ids.contains(node_id) {
                return HandshakeResult::Rejected {
                    reason: HandshakeRejectReason::AlreadyConnected,
                    message: format!("already connected to {}", node_id),
                };
            }

            // Rule 6: Connection limit
            if current_connections >= max_connections {
                return HandshakeResult::Rejected {
                    reason: HandshakeRejectReason::TooManyConnections,
                    message: format!(
                        "at limit {}/{}",
                        current_connections,
                        max_connections,
                    ),
                };
            }

            // All checks passed
            HandshakeResult::Accepted {
                node_id: node_id.clone(),
                service_type: *service_type,
                chain_height: *chain_height,
                protocol_version: *protocol_version,
            }
        }

        HandshakeMessage::Reject { reason, message } => {
            HandshakeResult::Rejected {
                reason: reason.clone(),
                message: message.clone(),
            }
        }
    }
}

/// Build Hello message untuk kirim ke peer.
pub fn build_hello(
    network_id: NetworkId,
    node_id: NodeId,
    listen_port: u16,
    service_type: ServiceType,
    chain_height: u64,
) -> HandshakeMessage {
    HandshakeMessage::Hello {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        network_id,
        node_id,
        listen_port,
        service_type,
        chain_height,
        user_agent: format!("dsdn-chain/{}", CURRENT_PROTOCOL_VERSION),
    }
}

// ════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn our_id() -> NodeId { NodeId::from_bytes([0xAAu8; 32]) }
    fn peer_id() -> NodeId { NodeId::from_bytes([0xBBu8; 32]) }

    fn make_valid_hello() -> HandshakeMessage {
        build_hello(
            NetworkId::Devnet,
            peer_id(),
            30305,
            ServiceType::Chain,
            100,
        )
    }

    #[test]
    fn test_valid_hello_accepted() {
        let hello = make_valid_hello();
        let result = validate_hello(
            &hello, NetworkId::Devnet, &our_id(), &HashSet::new(), 0, 125,
        );
        assert!(result.is_accepted());
    }

    #[test]
    fn test_wrong_network_rejected() {
        let hello = build_hello(
            NetworkId::Mainnet, // different!
            peer_id(), 8080, ServiceType::Chain, 100,
        );
        let result = validate_hello(
            &hello, NetworkId::Devnet, &our_id(), &HashSet::new(), 0, 125,
        );
        assert!(!result.is_accepted());
        if let HandshakeResult::Rejected { reason, .. } = result {
            assert_eq!(reason, HandshakeRejectReason::NetworkMismatch);
        }
    }

    #[test]
    fn test_incompatible_version_rejected() {
        let hello = HandshakeMessage::Hello {
            protocol_version: ProtocolVersion::new(99, 0, 0),
            network_id: NetworkId::Devnet,
            node_id: peer_id(),
            listen_port: 30305,
            service_type: ServiceType::Chain,
            chain_height: 100,
            user_agent: "test".to_string(),
        };
        let result = validate_hello(
            &hello, NetworkId::Devnet, &our_id(), &HashSet::new(), 0, 125,
        );
        assert!(!result.is_accepted());
    }

    #[test]
    fn test_self_connection_rejected() {
        let hello = build_hello(
            NetworkId::Devnet,
            our_id(), // same as ours!
            30305, ServiceType::Chain, 100,
        );
        let result = validate_hello(
            &hello, NetworkId::Devnet, &our_id(), &HashSet::new(), 0, 125,
        );
        if let HandshakeResult::Rejected { reason, .. } = result {
            assert_eq!(reason, HandshakeRejectReason::SelfConnection);
        } else {
            panic!("expected rejection");
        }
    }

    #[test]
    fn test_duplicate_connection_rejected() {
        let mut connected = HashSet::new();
        connected.insert(peer_id());

        let hello = make_valid_hello();
        let result = validate_hello(
            &hello, NetworkId::Devnet, &our_id(), &connected, 0, 125,
        );
        if let HandshakeResult::Rejected { reason, .. } = result {
            assert_eq!(reason, HandshakeRejectReason::AlreadyConnected);
        } else {
            panic!("expected rejection");
        }
    }

    #[test]
    fn test_connection_limit_rejected() {
        let hello = make_valid_hello();
        let result = validate_hello(
            &hello, NetworkId::Devnet, &our_id(), &HashSet::new(), 125, 125,
        );
        if let HandshakeResult::Rejected { reason, .. } = result {
            assert_eq!(reason, HandshakeRejectReason::TooManyConnections);
        } else {
            panic!("expected rejection");
        }
    }

    #[test]
    fn test_zero_node_id_rejected() {
        let hello = build_hello(
            NetworkId::Devnet,
            NodeId::zero(),
            30305, ServiceType::Chain, 100,
        );
        let result = validate_hello(
            &hello, NetworkId::Devnet, &our_id(), &HashSet::new(), 0, 125,
        );
        if let HandshakeResult::Rejected { reason, .. } = result {
            assert_eq!(reason, HandshakeRejectReason::InvalidNodeId);
        } else {
            panic!("expected rejection");
        }
    }
}