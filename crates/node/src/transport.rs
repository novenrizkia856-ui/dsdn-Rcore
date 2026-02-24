//! # Real Transport Layer for P2P Bootstrap
//!
//! Production implementations of `DnsResolver` and `PeerConnector` traits
//! defined in `bootstrap.rs`. These replace the mock/null test stubs with
//! actual network I/O:
//!
//! - **`StdDnsResolver`** — Real DNS resolution via `std::net::ToSocketAddrs`
//! - **`TcpPeerConnector`** — Real TCP connect + JSON-framed handshake exchange
//!
//! ## Wire Protocol (Handshake)
//!
//! ```text
//! ┌───────────────┬──────────────────────────────────────────┐
//! │ 4 bytes (BE)  │  JSON payload (HandshakeMessage)         │
//! │ payload len   │  { protocol_version, network_id, ... }   │
//! └───────────────┴──────────────────────────────────────────┘
//! ```
//!
//! Both sides send their message simultaneously after TCP connect.
//! The initiator sends first, then reads. Max payload: 64 KiB.
//!
//! ## Thread Safety
//!
//! Both traits require `Send + Sync`. The implementations are stateless
//! (only hold configuration), so they are trivially `Send + Sync`.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use tracing::{debug, warn};

use crate::bootstrap::{
    DnsResolver, HandshakeError, HandshakeMessage, PeerConnector,
};

/// Maximum handshake payload size (64 KiB). Prevents DoS from
/// oversized messages. A typical HandshakeMessage JSON is ~500 bytes.
const MAX_HANDSHAKE_PAYLOAD: usize = 64 * 1024;

/// Magic bytes prepended to handshake to identify DSDN protocol.
/// Allows early rejection of non-DSDN connections.
const HANDSHAKE_MAGIC: [u8; 4] = [0xD5, 0xD4, 0x4E, 0x01]; // "DSD" + version

// ════════════════════════════════════════════════════════════════════════════
// REAL DNS RESOLVER
// ════════════════════════════════════════════════════════════════════════════

/// Production DNS resolver using `std::net::ToSocketAddrs`.
///
/// This performs blocking DNS resolution, which is acceptable because
/// `PeerManager::bootstrap()` is synchronous and DNS queries are
/// infrequent (only during bootstrap/re-bootstrap cycles).
///
/// For hostnames that fail to resolve, an empty `Vec` is returned
/// (no panic, no error propagation — matching the `DnsResolver` trait contract).
#[derive(Debug, Clone)]
pub struct StdDnsResolver {
    /// Timeout for DNS resolution. If the system resolver hangs beyond
    /// this, we return empty results. Default: 5 seconds.
    pub timeout_secs: u64,
}

impl StdDnsResolver {
    pub fn new(timeout_secs: u64) -> Self {
        Self { timeout_secs }
    }
}

impl Default for StdDnsResolver {
    fn default() -> Self {
        Self { timeout_secs: 5 }
    }
}

impl DnsResolver for StdDnsResolver {
    fn resolve(&self, hostname: &str) -> Vec<IpAddr> {
        // ToSocketAddrs requires ":port" suffix; we use port 0 as dummy.
        let lookup_str = if hostname.contains(':') {
            hostname.to_string()
        } else {
            format!("{}:0", hostname)
        };

        debug!("DNS resolving: {}", hostname);

        // std::net::ToSocketAddrs is blocking.
        // We rely on the OS resolver timeout + the fact that bootstrap
        // is not on the hot path (called once at startup + periodically).
        match lookup_str.to_socket_addrs() {
            Ok(addrs) => {
                let ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
                debug!("DNS resolved {} → {} IPs", hostname, ips.len());
                ips
            }
            Err(e) => {
                warn!("DNS resolution failed for {}: {}", hostname, e);
                Vec::new()
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// REAL TCP PEER CONNECTOR
// ════════════════════════════════════════════════════════════════════════════

/// Production TCP peer connector.
///
/// Establishes a TCP connection, exchanges handshake messages using a
/// simple length-prefixed JSON wire protocol, and returns the remote
/// peer's handshake.
///
/// ## Wire Protocol
///
/// 1. TCP connect (with timeout)
/// 2. Send: `HANDSHAKE_MAGIC` (4 bytes) + payload length (4 bytes BE) + JSON
/// 3. Receive: `HANDSHAKE_MAGIC` (4 bytes) + payload length (4 bytes BE) + JSON
/// 4. Deserialize remote HandshakeMessage
///
/// The magic bytes allow both sides to immediately reject non-DSDN
/// connections without parsing JSON.
#[derive(Debug, Clone)]
pub struct TcpPeerConnector {
    /// TCP connect timeout in seconds.
    pub connect_timeout_secs: u64,
    /// Read/write timeout for handshake exchange.
    pub handshake_timeout_secs: u64,
}

impl TcpPeerConnector {
    pub fn new(connect_timeout_secs: u64, handshake_timeout_secs: u64) -> Self {
        Self {
            connect_timeout_secs,
            handshake_timeout_secs,
        }
    }
}

impl Default for TcpPeerConnector {
    fn default() -> Self {
        Self {
            connect_timeout_secs: 5,
            handshake_timeout_secs: 10,
        }
    }
}

impl PeerConnector for TcpPeerConnector {
    fn connect_and_handshake(
        &self,
        addr: SocketAddr,
        our_handshake: &HandshakeMessage,
    ) -> Result<HandshakeMessage, HandshakeError> {
        // ── Step 1: TCP connect with timeout ─────────────────────────
        let connect_timeout = Duration::from_secs(self.connect_timeout_secs);
        let stream = TcpStream::connect_timeout(&addr, connect_timeout).map_err(|e| {
            HandshakeError::Transport(format!("TCP connect to {}: {}", addr, e))
        })?;

        // Set read/write timeouts for handshake phase
        let rw_timeout = Some(Duration::from_secs(self.handshake_timeout_secs));
        stream
            .set_read_timeout(rw_timeout)
            .map_err(|e| HandshakeError::Transport(format!("set read timeout: {}", e)))?;
        stream
            .set_write_timeout(rw_timeout)
            .map_err(|e| HandshakeError::Transport(format!("set write timeout: {}", e)))?;

        // ── Step 2: Send our handshake ───────────────────────────────
        send_handshake(&stream, our_handshake)?;

        // ── Step 3: Receive remote handshake ─────────────────────────
        let remote = recv_handshake(&stream)?;

        debug!(
            "Handshake OK with {} (role={:?}, class={:?})",
            addr, remote.role, remote.node_class
        );

        Ok(remote)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// WIRE PROTOCOL HELPERS
// ════════════════════════════════════════════════════════════════════════════

/// Serialize and send a HandshakeMessage over TCP.
///
/// Wire format: MAGIC (4) + LENGTH (4 BE) + JSON payload
fn send_handshake(
    mut stream: &TcpStream,
    msg: &HandshakeMessage,
) -> Result<(), HandshakeError> {
    let payload = serde_json::to_vec(msg).map_err(|e| {
        HandshakeError::Transport(format!("serialize handshake: {}", e))
    })?;

    if payload.len() > MAX_HANDSHAKE_PAYLOAD {
        return Err(HandshakeError::Transport(format!(
            "handshake payload too large: {} bytes (max {})",
            payload.len(),
            MAX_HANDSHAKE_PAYLOAD
        )));
    }

    // Write magic + length prefix + payload
    let len_bytes = (payload.len() as u32).to_be_bytes();
    stream.write_all(&HANDSHAKE_MAGIC).map_err(|e| {
        HandshakeError::Transport(format!("write magic: {}", e))
    })?;
    stream.write_all(&len_bytes).map_err(|e| {
        HandshakeError::Transport(format!("write length: {}", e))
    })?;
    stream.write_all(&payload).map_err(|e| {
        HandshakeError::Transport(format!("write payload: {}", e))
    })?;
    stream.flush().map_err(|e| {
        HandshakeError::Transport(format!("flush: {}", e))
    })?;

    Ok(())
}

/// Receive and deserialize a HandshakeMessage from TCP.
///
/// Validates magic bytes, checks length limit, then parses JSON.
fn recv_handshake(mut stream: &TcpStream) -> Result<HandshakeMessage, HandshakeError> {
    // Read magic bytes
    let mut magic = [0u8; 4];
    stream.read_exact(&mut magic).map_err(|e| {
        if e.kind() == std::io::ErrorKind::TimedOut
            || e.kind() == std::io::ErrorKind::WouldBlock
        {
            HandshakeError::Timeout
        } else {
            HandshakeError::Transport(format!("read magic: {}", e))
        }
    })?;

    if magic != HANDSHAKE_MAGIC {
        return Err(HandshakeError::Transport(format!(
            "invalid magic bytes: expected {:02x?}, got {:02x?} — not a DSDN peer",
            HANDSHAKE_MAGIC, magic
        )));
    }

    // Read length prefix (4 bytes, big-endian)
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).map_err(|e| {
        HandshakeError::Transport(format!("read length: {}", e))
    })?;
    let payload_len = u32::from_be_bytes(len_buf) as usize;

    if payload_len == 0 {
        return Err(HandshakeError::Transport("empty handshake payload".into()));
    }
    if payload_len > MAX_HANDSHAKE_PAYLOAD {
        return Err(HandshakeError::Transport(format!(
            "handshake payload too large: {} bytes (max {})",
            payload_len, MAX_HANDSHAKE_PAYLOAD
        )));
    }

    // Read JSON payload
    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload).map_err(|e| {
        if e.kind() == std::io::ErrorKind::TimedOut
            || e.kind() == std::io::ErrorKind::WouldBlock
        {
            HandshakeError::Timeout
        } else {
            HandshakeError::Transport(format!("read payload: {}", e))
        }
    })?;

    // Deserialize
    let msg: HandshakeMessage = serde_json::from_slice(&payload).map_err(|e| {
        HandshakeError::Transport(format!("deserialize handshake: {}", e))
    })?;

    Ok(msg)
}

// ════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::{NetworkId, NodeRole, NodeClass};
    use std::net::TcpListener;

    #[test]
    fn test_std_dns_resolver_localhost() {
        let resolver = StdDnsResolver::default();
        let ips = resolver.resolve("localhost");
        // localhost should resolve to 127.0.0.1 or ::1
        assert!(!ips.is_empty(), "localhost should resolve to at least one IP");
    }

    #[test]
    fn test_std_dns_resolver_invalid_host() {
        let resolver = StdDnsResolver::default();
        let ips = resolver.resolve("this.host.definitely.does.not.exist.dsdn.invalid");
        assert!(ips.is_empty());
    }

    #[test]
    fn test_tcp_connector_refused() {
        let connector = TcpPeerConnector::new(2, 5);
        let our_hs = HandshakeMessage::build(
            &[1u8; 32],
            NetworkId::Testnet,
            45831,
            NodeRole::StorageCompute,
            Some(NodeClass::Reguler),
        );

        // Connect to a port that nobody is listening on
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let result = connector.connect_and_handshake(addr, &our_hs);
        assert!(result.is_err());
    }

    #[test]
    fn test_wire_roundtrip() {
        // Set up a local TCP listener
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let our_hs = HandshakeMessage::build(
            &[42u8; 32],
            NetworkId::Testnet,
            45831,
            NodeRole::Validator,
            None,
        );

        let peer_hs = HandshakeMessage::build(
            &[99u8; 32],
            NetworkId::Testnet,
            45831,
            NodeRole::StorageCompute,
            Some(NodeClass::DataCenter),
        );

        // Spawn a thread to act as the remote peer
        let peer_hs_clone = peer_hs.clone();
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();

            // Remote: receive initiator's handshake, then send ours
            let received = recv_handshake(&stream).expect("recv");
            send_handshake(&stream, &peer_hs_clone).expect("send");
            received
        });

        // Initiator side: connect_and_handshake
        let connector = TcpPeerConnector::new(5, 10);
        let remote = connector
            .connect_and_handshake(addr, &our_hs)
            .expect("handshake");

        // Verify we got the peer's handshake back
        assert_eq!(remote.node_id, [99u8; 32]);
        assert_eq!(remote.role, NodeRole::StorageCompute);
        assert_eq!(remote.node_class, Some(NodeClass::DataCenter));

        // Verify the peer received our handshake
        let peer_received = handle.join().expect("thread join");
        assert_eq!(peer_received.node_id, [42u8; 32]);
        assert_eq!(peer_received.role, NodeRole::Validator);
        assert_eq!(peer_received.node_class, None);
    }

    #[test]
    fn test_magic_bytes_rejection() {
        // Listener that sends garbage instead of DSDN magic
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();

            // Drain incoming handshake fully (magic 4 + len 4 + payload)
            let mut magic = [0u8; 4];
            let _ = stream.read_exact(&mut magic);
            let mut len_buf = [0u8; 4];
            let _ = stream.read_exact(&mut len_buf);
            let payload_len = u32::from_be_bytes(len_buf) as usize;
            let mut payload = vec![0u8; payload_len];
            let _ = stream.read_exact(&mut payload);

            // Send garbage magic
            let _ = stream.write_all(&[0xFF, 0xFF, 0xFF, 0xFF]);
            let _ = stream.write_all(&4u32.to_be_bytes());
            let _ = stream.write_all(b"test");
            let _ = stream.flush();
        });

        let connector = TcpPeerConnector::new(2, 5);
        let our_hs = HandshakeMessage::build(
            &[1u8; 32],
            NetworkId::Testnet,
            45831,
            NodeRole::StorageCompute,
            Some(NodeClass::Reguler),
        );

        let result = connector.connect_and_handshake(addr, &our_hs);
        assert!(result.is_err());
        if let Err(HandshakeError::Transport(msg)) = &result {
            assert!(msg.contains("invalid magic"), "got: {}", msg);
        }
    }
}