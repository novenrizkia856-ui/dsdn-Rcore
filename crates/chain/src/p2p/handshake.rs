//! # Handshake Protocol
//!
//! Protocol handshake saat dua node pertama kali connect.
//! Setelah handshake, kedua node saling tahu role dan class masing-masing.
//!
//! ## Flow
//!
//! ```text
//! Node A ──────────────────────── Node B
//!   │                                │
//!   │── HandshakeMessage::Hello ────>│  (kirim role + class)
//!   │                                │── validate (role, class, network, version)
//!   │<── HandshakeMessage::Hello ────│  (kirim role + class)
//!   │── validate                     │
//!   │                                │
//!   │ (role check via RoleDependencyMatrix)
//!   │ (REQUIRED → keep, SKIP → PEX lalu disconnect)
//! ```
//!
//! ## Validation Rules
//!
//! 1. protocol_version.major HARUS sama
//! 2. network_id HARUS sama (mainnet ≠ testnet)
//! 3. node_id HARUS valid (non-zero, bukan self)
//! 4. listen_port HARUS > 0
//! 5. role + node_class HARUS konsisten:
//!    - StorageCompute → node_class HARUS Some(Reguler|DataCenter)
//!    - Validator/Coordinator/Bootstrap → node_class HARUS None

use serde::{Serialize, Deserialize};
use std::fmt;

use super::identity::{NetworkId, NodeId, ProtocolVersion, CURRENT_PROTOCOL_VERSION};
use super::types::{NodeRole, NodeClass, DisconnectReason};

// ════════════════════════════════════════════════════════════════════════════
// HANDSHAKE MESSAGE
// ════════════════════════════════════════════════════════════════════════════

/// Message yang dikirim saat handshake antar node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HandshakeMessage {
    /// Hello — pesan pertama dari kedua pihak.
    /// Menyertakan role dan class untuk role-based peer filtering.
    Hello {
        /// Versi protocol P2P
        protocol_version: ProtocolVersion,
        /// Network yang digunakan (mainnet/testnet/devnet)
        network_id: NetworkId,
        /// Identitas node (Ed25519 pubkey)
        node_id: NodeId,
        /// Port yang di-listen untuk inbound connections (selalu 45831)
        listen_port: u16,
        /// Role operasional node
        role: NodeRole,
        /// Kelas node — hanya untuk StorageCompute (Reguler/DataCenter).
        /// None untuk Validator, Coordinator, Bootstrap.
        node_class: Option<NodeClass>,
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
    /// Invalid node ID (zero)
    InvalidNodeId,
    /// Role + Class tidak konsisten (misal: Validator kirim class=DataCenter)
    InvalidRoleClass,
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
            Self::InvalidRoleClass => write!(f, "invalid_role_class"),
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// HANDSHAKE RESULT
// ════════════════════════════════════════════════════════════════════════════

/// Hasil validasi handshake.
#[derive(Debug, Clone)]
pub enum HandshakeResult {
    /// Handshake berhasil — role dan class terverifikasi
    Accepted {
        /// Node ID peer yang terverifikasi
        node_id: NodeId,
        /// Role peer
        role: NodeRole,
        /// Class peer (Some untuk StorageCompute, None untuk lainnya)
        node_class: Option<NodeClass>,
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
// ROLE + CLASS VALIDATION
// ════════════════════════════════════════════════════════════════════════════

/// Validasi konsistensi role + node_class.
///
/// Rules:
/// - StorageCompute HARUS punya node_class (Reguler atau DataCenter)
/// - Validator, Coordinator, Bootstrap HARUS node_class = None
fn validate_role_class(role: &NodeRole, node_class: &Option<NodeClass>) -> bool {
    match role {
        NodeRole::StorageCompute => node_class.is_some(),
        NodeRole::Validator | NodeRole::Coordinator | NodeRole::Bootstrap => node_class.is_none(),
    }
}

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
            role,
            node_class,
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

            // Rule 7: Role + Class consistency
            if !validate_role_class(role, node_class) {
                return HandshakeResult::Rejected {
                    reason: HandshakeRejectReason::InvalidRoleClass,
                    message: format!(
                        "invalid role+class: role={} class={:?}",
                        role, node_class,
                    ),
                };
            }

            // All checks passed
            HandshakeResult::Accepted {
                node_id: node_id.clone(),
                role: *role,
                node_class: *node_class,
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
    role: NodeRole,
    node_class: Option<NodeClass>,
    chain_height: u64,
) -> HandshakeMessage {
    HandshakeMessage::Hello {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        network_id,
        node_id,
        listen_port,
        role,
        node_class,
        chain_height,
        user_agent: format!("dsdn-node/{}", CURRENT_PROTOCOL_VERSION),
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

    fn make_valid_hello_storage() -> HandshakeMessage {
        build_hello(
            NetworkId::Devnet,
            peer_id(),
            45831,
            NodeRole::StorageCompute,
            Some(NodeClass::Reguler),
            100,
        )
    }

    fn make_valid_hello_validator() -> HandshakeMessage {
        build_hello(
            NetworkId::Devnet,
            peer_id(),
            45831,
            NodeRole::Validator,
            None,
            100,
        )
    }

    #[test]
    fn test_valid_hello_storage_accepted() {
        let hello = make_valid_hello_storage();
        let result = validate_hello(
            &hello, NetworkId::Devnet, &our_id(), &HashSet::new(), 0, 125,
        );
        assert!(result.is_accepted());
        if let HandshakeResult::Accepted { role, node_class, .. } = result {
            assert_eq!(role, NodeRole::StorageCompute);
            assert_eq!(node_class, Some(NodeClass::Reguler));
        }
    }

    #[test]
    fn test_valid_hello_validator_accepted() {
        let hello = make_valid_hello_validator();
        let result = validate_hello(
            &hello, NetworkId::Devnet, &our_id(), &HashSet::new(), 0, 125,
        );
        assert!(result.is_accepted());
        if let HandshakeResult::Accepted { role, node_class, .. } = result {
            assert_eq!(role, NodeRole::Validator);
            assert_eq!(node_class, None);
        }
    }

    #[test]
    fn test_wrong_network_rejected() {
        let hello = build_hello(
            NetworkId::Mainnet,
            peer_id(), 45831, NodeRole::Validator, None, 100,
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
            listen_port: 45831,
            role: NodeRole::Validator,
            node_class: None,
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
            our_id(),
            45831, NodeRole::Validator, None, 100,
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

        let hello = make_valid_hello_validator();
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
        let hello = make_valid_hello_validator();
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
            45831, NodeRole::Validator, None, 100,
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

    // ── NEW: Role + Class validation tests ──

    #[test]
    fn test_validator_with_class_rejected() {
        // Validator TIDAK boleh punya node_class
        let hello = build_hello(
            NetworkId::Devnet,
            peer_id(),
            45831,
            NodeRole::Validator,
            Some(NodeClass::DataCenter), // INVALID!
            100,
        );
        let result = validate_hello(
            &hello, NetworkId::Devnet, &our_id(), &HashSet::new(), 0, 125,
        );
        if let HandshakeResult::Rejected { reason, .. } = result {
            assert_eq!(reason, HandshakeRejectReason::InvalidRoleClass);
        } else {
            panic!("expected rejection for Validator with class");
        }
    }

    #[test]
    fn test_coordinator_with_class_rejected() {
        let hello = build_hello(
            NetworkId::Devnet,
            peer_id(),
            45831,
            NodeRole::Coordinator,
            Some(NodeClass::Reguler), // INVALID!
            100,
        );
        let result = validate_hello(
            &hello, NetworkId::Devnet, &our_id(), &HashSet::new(), 0, 125,
        );
        if let HandshakeResult::Rejected { reason, .. } = result {
            assert_eq!(reason, HandshakeRejectReason::InvalidRoleClass);
        } else {
            panic!("expected rejection for Coordinator with class");
        }
    }

    #[test]
    fn test_storage_without_class_rejected() {
        // StorageCompute HARUS punya node_class
        let hello = build_hello(
            NetworkId::Devnet,
            peer_id(),
            45831,
            NodeRole::StorageCompute,
            None, // INVALID! StorageCompute needs class
            100,
        );
        let result = validate_hello(
            &hello, NetworkId::Devnet, &our_id(), &HashSet::new(), 0, 125,
        );
        if let HandshakeResult::Rejected { reason, .. } = result {
            assert_eq!(reason, HandshakeRejectReason::InvalidRoleClass);
        } else {
            panic!("expected rejection for StorageCompute without class");
        }
    }

    #[test]
    fn test_storage_datacenter_accepted() {
        let hello = build_hello(
            NetworkId::Devnet,
            peer_id(),
            45831,
            NodeRole::StorageCompute,
            Some(NodeClass::DataCenter),
            100,
        );
        let result = validate_hello(
            &hello, NetworkId::Devnet, &our_id(), &HashSet::new(), 0, 125,
        );
        assert!(result.is_accepted());
        if let HandshakeResult::Accepted { role, node_class, .. } = result {
            assert_eq!(role, NodeRole::StorageCompute);
            assert_eq!(node_class, Some(NodeClass::DataCenter));
        }
    }

    #[test]
    fn test_bootstrap_role_accepted() {
        let hello = build_hello(
            NetworkId::Devnet,
            peer_id(),
            45831,
            NodeRole::Bootstrap,
            None,
            0,
        );
        let result = validate_hello(
            &hello, NetworkId::Devnet, &our_id(), &HashSet::new(), 0, 125,
        );
        assert!(result.is_accepted());
    }
}