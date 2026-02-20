//! # Network Identity
//!
//! Identitas jaringan DSDN: NetworkId, NodeId, ProtocolVersion.
//! Tanpa ini, node dari network berbeda bisa saling connect (fatal).

use serde::{Serialize, Deserialize};
use std::fmt;

// ════════════════════════════════════════════════════════════════════════════
// PROTOCOL VERSION
// ════════════════════════════════════════════════════════════════════════════

/// Versi protocol P2P saat ini.
/// Rule: MAJOR harus sama (reject handshake jika beda), MINOR boleh beda.
pub const CURRENT_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion {
    major: 1,
    minor: 0,
    patch: 0,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl ProtocolVersion {
    pub fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self { major, minor, patch }
    }

    /// Compatible jika MAJOR version sama.
    pub fn is_compatible(&self, other: &ProtocolVersion) -> bool {
        self.major == other.major
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// NETWORK ID
// ════════════════════════════════════════════════════════════════════════════

/// Isolasi jaringan. Node dari network berbeda TIDAK BOLEH saling connect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkId {
    Mainnet,
    Testnet,
    Devnet,
}

impl NetworkId {
    /// 4 bytes magic untuk early rejection di wire protocol.
    pub fn magic_bytes(&self) -> [u8; 4] {
        match self {
            NetworkId::Mainnet => [0xD5, 0xD4, 0x4E, 0x01],
            NetworkId::Testnet => [0xD5, 0xD4, 0x4E, 0x02],
            NetworkId::Devnet  => [0xD5, 0xD4, 0x4E, 0xFF],
        }
    }

    pub fn default_port(&self) -> u16 {
        match self {
            NetworkId::Mainnet => 30303,
            NetworkId::Testnet => 30304,
            NetworkId::Devnet  => 30305,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            NetworkId::Mainnet => "mainnet",
            NetworkId::Testnet => "testnet",
            NetworkId::Devnet  => "devnet",
        }
    }

    pub fn from_str_id(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "mainnet" => Some(NetworkId::Mainnet),
            "testnet" => Some(NetworkId::Testnet),
            "devnet" | "dev" => Some(NetworkId::Devnet),
            _ => None,
        }
    }
}

impl fmt::Display for NetworkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ════════════════════════════════════════════════════════════════════════════
// NODE ID
// ════════════════════════════════════════════════════════════════════════════

/// Identitas unik node (Ed25519 public key, 32 bytes).
/// BERBEDA dari Address (20 bytes) — ini identitas P2P, bukan on-chain.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    pub fn from_bytes(b: [u8; 32]) -> Self { NodeId(b) }
    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, anyhow::Error> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            anyhow::bail!("invalid NodeId length: expected 32, got {}", bytes.len());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(NodeId(arr))
    }

    pub fn from_ed25519_pubkey(pubkey: &[u8]) -> Result<Self, anyhow::Error> {
        if pubkey.len() != 32 {
            anyhow::bail!("invalid Ed25519 pubkey length: expected 32, got {}", pubkey.len());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(pubkey);
        Ok(NodeId(arr))
    }

    /// Short hex untuk logging: "abcd..ef01"
    pub fn short_hex(&self) -> String {
        let full = self.to_hex();
        format!("{}..{}", &full[..4], &full[full.len()-4..])
    }

    /// Zero NodeId — digunakan sebagai placeholder saat node belum punya identity.
    pub fn zero() -> Self {
        NodeId([0u8; 32])
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.short_hex())
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("NodeId").field(&self.short_hex()).finish()
    }
}

// ════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_version_compatibility() {
        let v1 = ProtocolVersion::new(1, 0, 0);
        let v1_1 = ProtocolVersion::new(1, 1, 0);
        let v2 = ProtocolVersion::new(2, 0, 0);

        assert!(v1.is_compatible(&v1_1));
        assert!(!v1.is_compatible(&v2));
    }

    #[test]
    fn test_network_id_magic_bytes_unique() {
        let m = NetworkId::Mainnet.magic_bytes();
        let t = NetworkId::Testnet.magic_bytes();
        let d = NetworkId::Devnet.magic_bytes();
        assert_ne!(m, t);
        assert_ne!(m, d);
        assert_ne!(t, d);
    }

    #[test]
    fn test_network_id_roundtrip() {
        for net in [NetworkId::Mainnet, NetworkId::Testnet, NetworkId::Devnet] {
            let parsed = NetworkId::from_str_id(net.as_str()).unwrap();
            assert_eq!(net, parsed);
        }
    }

    #[test]
    fn test_node_id_hex_roundtrip() {
        let id = NodeId::from_bytes([0x42u8; 32]);
        let restored = NodeId::from_hex(&id.to_hex()).unwrap();
        assert_eq!(id, restored);
    }

    #[test]
    fn test_node_id_zero() {
        let z = NodeId::zero();
        assert!(z.is_zero());
        assert!(!NodeId::from_bytes([1u8; 32]).is_zero());
    }
}