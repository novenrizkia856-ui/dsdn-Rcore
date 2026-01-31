//! Coordinator Network Abstraction (14A.2B.2.14)
//!
//! Module ini menyediakan abstraction layer untuk komunikasi antar coordinator.
//!
//! # Types
//!
//! | Type | Fungsi |
//! |------|--------|
//! | `CoordinatorNetwork` | Async trait untuk network operations |
//! | `NetworkError` | Error type untuk network failures |
//! | `MockNetwork` | In-memory mock implementation untuk testing |
//!
//! # Thread Safety
//!
//! - `CoordinatorNetwork` requires `Send + Sync`
//! - All methods use `&self` with interior mutability
//! - `MockNetwork` is thread-safe via `tokio::sync::Mutex` and `parking_lot`
//!
//! # Object Safety
//!
//! `CoordinatorNetwork` is object-safe and can be used as `dyn CoordinatorNetwork`.
//!
//! # Usage
//!
//! ```ignore
//! use dsdn_coordinator::multi::{CoordinatorNetwork, MockNetwork, CoordinatorId};
//!
//! // Create mock network for testing
//! let network = MockNetwork::new(CoordinatorId::new([0x01; 32]));
//!
//! // Add peers
//! network.add_peer(CoordinatorId::new([0x02; 32]));
//!
//! // Send message
//! let ping = CoordinatorMessage::ping_now();
//! network.broadcast(ping).await?;
//! ```

use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use parking_lot::{Mutex, RwLock};
use tokio::sync::Mutex as TokioMutex;

use super::{CoordinatorId, CoordinatorMessage};

// ════════════════════════════════════════════════════════════════════════════════
// NETWORK ERROR
// ════════════════════════════════════════════════════════════════════════════════

/// Error type untuk network operations.
///
/// Semua network failures direpresentasikan melalui enum ini.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkError {
    /// Koneksi ke peer gagal.
    ConnectionFailed {
        /// Deskripsi penyebab kegagalan.
        reason: String,
    },

    /// Operasi timeout.
    Timeout {
        /// Durasi timeout dalam milliseconds.
        duration_ms: u64,
    },

    /// Peer tidak ditemukan.
    PeerNotFound {
        /// CoordinatorId yang tidak ditemukan.
        peer_id: CoordinatorId,
    },

    /// Encoding/decoding message gagal.
    EncodingError {
        /// Deskripsi error.
        reason: String,
    },

    /// Network sudah shutdown.
    Shutdown,
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkError::ConnectionFailed { reason } => {
                write!(f, "connection failed: {}", reason)
            }
            NetworkError::Timeout { duration_ms } => {
                write!(f, "operation timed out after {}ms", duration_ms)
            }
            NetworkError::PeerNotFound { peer_id } => {
                write!(f, "peer not found: {:?}", peer_id.as_bytes())
            }
            NetworkError::EncodingError { reason } => {
                write!(f, "encoding error: {}", reason)
            }
            NetworkError::Shutdown => {
                write!(f, "network has been shut down")
            }
        }
    }
}

impl std::error::Error for NetworkError {}

// ════════════════════════════════════════════════════════════════════════════════
// COORDINATOR NETWORK TRAIT
// ════════════════════════════════════════════════════════════════════════════════

/// Async trait untuk komunikasi antar coordinator.
///
/// Trait ini mendefinisikan interface untuk network layer yang digunakan
/// oleh coordinator untuk berkomunikasi satu sama lain.
///
/// # Object Safety
///
/// Trait ini object-safe dan dapat digunakan sebagai `dyn CoordinatorNetwork`.
///
/// # Thread Safety
///
/// Implementasi HARUS `Send + Sync`. Semua methods menggunakan `&self`
/// dengan interior mutability pattern untuk thread-safety.
///
/// # Error Handling
///
/// Semua operasi mengembalikan `Result<_, NetworkError>`.
/// Tidak ada silent failure atau panic.
#[async_trait]
pub trait CoordinatorNetwork: Send + Sync {
    /// Broadcast message ke semua connected peers.
    ///
    /// # Arguments
    ///
    /// * `msg` - Message yang akan di-broadcast
    ///
    /// # Returns
    ///
    /// - `Ok(())` jika broadcast berhasil ke setidaknya satu peer
    /// - `Err(NetworkError::Shutdown)` jika network sudah shutdown
    /// - `Err(NetworkError::EncodingError)` jika encoding gagal
    ///
    /// # Note
    ///
    /// Broadcast adalah best-effort. Tidak ada jaminan delivery ke semua peers.
    async fn broadcast(&self, msg: CoordinatorMessage) -> Result<(), NetworkError>;

    /// Kirim message ke specific peer.
    ///
    /// # Arguments
    ///
    /// * `target` - CoordinatorId peer tujuan
    /// * `msg` - Message yang akan dikirim
    ///
    /// # Returns
    ///
    /// - `Ok(())` jika message berhasil dikirim
    /// - `Err(NetworkError::PeerNotFound)` jika peer tidak terhubung
    /// - `Err(NetworkError::Shutdown)` jika network sudah shutdown
    /// - `Err(NetworkError::ConnectionFailed)` jika koneksi gagal
    async fn send_to(
        &self,
        target: CoordinatorId,
        msg: CoordinatorMessage,
    ) -> Result<(), NetworkError>;

    /// Terima message dari peer manapun.
    ///
    /// # Returns
    ///
    /// - `Ok((sender_id, message))` jika ada message yang diterima
    /// - `Err(NetworkError::Shutdown)` jika network sudah shutdown
    /// - `Err(NetworkError::Timeout)` jika tidak ada message dalam waktu tertentu
    ///
    /// # Note
    ///
    /// Method ini menggunakan `&self` dengan interior mutability.
    /// Implementasi bertanggung jawab untuk thread-safety internal.
    async fn receive(&self) -> Result<(CoordinatorId, CoordinatorMessage), NetworkError>;

    /// Mendapatkan daftar peer yang terhubung.
    ///
    /// # Returns
    ///
    /// Vector berisi CoordinatorId dari semua peer yang terhubung.
    fn connected_peers(&self) -> Vec<CoordinatorId>;
}

// ════════════════════════════════════════════════════════════════════════════════
// MOCK NETWORK
// ════════════════════════════════════════════════════════════════════════════════

/// In-memory mock implementation untuk testing.
///
/// `MockNetwork` menyediakan implementasi `CoordinatorNetwork` yang:
/// - Tidak menggunakan real network/socket
/// - Deterministic
/// - Thread-safe
/// - Dapat di-inspect untuk testing
///
/// # Thread Safety
///
/// - `inbox` dilindungi oleh `tokio::sync::Mutex` (async-aware)
/// - `peers` dilindungi oleh `parking_lot::RwLock`
/// - `outbox` dilindungi oleh `parking_lot::Mutex`
/// - `shutdown` adalah `AtomicBool`
///
/// # Testing Helpers
///
/// - `inject_message()` - Inject message ke inbox untuk testing
/// - `drain_outbox()` - Ambil semua sent messages untuk verification
/// - `add_peer()` / `remove_peer()` - Manage connected peers
pub struct MockNetwork {
    /// Own coordinator ID.
    self_id: CoordinatorId,

    /// Connected peers (protected by RwLock for concurrent reads).
    peers: RwLock<Vec<CoordinatorId>>,

    /// Incoming message queue (async mutex for await-safe access).
    inbox: TokioMutex<VecDeque<(CoordinatorId, CoordinatorMessage)>>,

    /// Outbox for testing - stores (target, message).
    /// None target means broadcast.
    outbox: Mutex<Vec<(Option<CoordinatorId>, CoordinatorMessage)>>,

    /// Shutdown flag.
    shutdown: AtomicBool,
}

impl MockNetwork {
    /// Membuat MockNetwork baru.
    ///
    /// # Arguments
    ///
    /// * `self_id` - CoordinatorId untuk network ini
    #[must_use]
    pub fn new(self_id: CoordinatorId) -> Self {
        Self {
            self_id,
            peers: RwLock::new(Vec::new()),
            inbox: TokioMutex::new(VecDeque::new()),
            outbox: Mutex::new(Vec::new()),
            shutdown: AtomicBool::new(false),
        }
    }

    /// Mendapatkan own coordinator ID.
    #[must_use]
    pub fn self_id(&self) -> &CoordinatorId {
        &self.self_id
    }

    /// Menambahkan peer ke connected peers.
    ///
    /// Idempotent: tidak error jika peer sudah ada.
    pub fn add_peer(&self, peer_id: CoordinatorId) {
        let mut peers = self.peers.write();
        if !peers.contains(&peer_id) {
            peers.push(peer_id);
        }
    }

    /// Menghapus peer dari connected peers.
    ///
    /// Idempotent: tidak error jika peer tidak ada.
    pub fn remove_peer(&self, peer_id: &CoordinatorId) {
        let mut peers = self.peers.write();
        peers.retain(|p| p != peer_id);
    }

    /// Inject message ke inbox untuk testing.
    ///
    /// # Arguments
    ///
    /// * `from` - Sender CoordinatorId
    /// * `msg` - Message yang di-inject
    ///
    /// # Returns
    ///
    /// - `Ok(())` jika berhasil
    /// - `Err(NetworkError::Shutdown)` jika network sudah shutdown
    pub async fn inject_message(
        &self,
        from: CoordinatorId,
        msg: CoordinatorMessage,
    ) -> Result<(), NetworkError> {
        if self.shutdown.load(Ordering::SeqCst) {
            return Err(NetworkError::Shutdown);
        }

        let mut inbox = self.inbox.lock().await;
        inbox.push_back((from, msg));
        Ok(())
    }

    /// Drain semua messages dari outbox untuk testing verification.
    ///
    /// Returns vector of (target, message) where target is None for broadcasts.
    #[must_use]
    pub fn drain_outbox(&self) -> Vec<(Option<CoordinatorId>, CoordinatorMessage)> {
        let mut outbox = self.outbox.lock();
        std::mem::take(&mut *outbox)
    }

    /// Peek outbox tanpa drain.
    #[must_use]
    pub fn peek_outbox(&self) -> Vec<(Option<CoordinatorId>, CoordinatorMessage)> {
        let outbox = self.outbox.lock();
        outbox.clone()
    }

    /// Shutdown network.
    ///
    /// Setelah shutdown, semua operasi akan return `NetworkError::Shutdown`.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Memeriksa apakah network sudah shutdown.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// Reset network state untuk reuse dalam testing.
    pub async fn reset(&self) {
        self.shutdown.store(false, Ordering::SeqCst);
        self.peers.write().clear();
        self.inbox.lock().await.clear();
        self.outbox.lock().clear();
    }
}

impl fmt::Debug for MockNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MockNetwork")
            .field("self_id", &self.self_id)
            .field("peers", &*self.peers.read())
            .field("shutdown", &self.shutdown.load(Ordering::SeqCst))
            .finish()
    }
}

#[async_trait]
impl CoordinatorNetwork for MockNetwork {
    async fn broadcast(&self, msg: CoordinatorMessage) -> Result<(), NetworkError> {
        if self.shutdown.load(Ordering::SeqCst) {
            return Err(NetworkError::Shutdown);
        }

        // Store in outbox with None target (broadcast)
        {
            let mut outbox = self.outbox.lock();
            outbox.push((None, msg));
        }

        Ok(())
    }

    async fn send_to(
        &self,
        target: CoordinatorId,
        msg: CoordinatorMessage,
    ) -> Result<(), NetworkError> {
        if self.shutdown.load(Ordering::SeqCst) {
            return Err(NetworkError::Shutdown);
        }

        // Check if peer is connected
        {
            let peers = self.peers.read();
            if !peers.contains(&target) {
                return Err(NetworkError::PeerNotFound {
                    peer_id: target,
                });
            }
        }

        // Store in outbox with specific target
        {
            let mut outbox = self.outbox.lock();
            outbox.push((Some(target), msg));
        }

        Ok(())
    }

    async fn receive(&self) -> Result<(CoordinatorId, CoordinatorMessage), NetworkError> {
        if self.shutdown.load(Ordering::SeqCst) {
            return Err(NetworkError::Shutdown);
        }

        let mut inbox = self.inbox.lock().await;

        // Check shutdown again after acquiring lock
        if self.shutdown.load(Ordering::SeqCst) {
            return Err(NetworkError::Shutdown);
        }

        inbox.pop_front().ok_or(NetworkError::Timeout {
            duration_ms: 0, // Immediate timeout for mock
        })
    }

    fn connected_peers(&self) -> Vec<CoordinatorId> {
        self.peers.read().clone()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_coord_id(seed: u8) -> CoordinatorId {
        CoordinatorId::new([seed; 32])
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // NetworkError Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_network_error_display_connection_failed() {
        let err = NetworkError::ConnectionFailed {
            reason: "test".to_string(),
        };
        let display = err.to_string();
        assert!(display.contains("connection failed"));
        assert!(display.contains("test"));
    }

    #[test]
    fn test_network_error_display_timeout() {
        let err = NetworkError::Timeout { duration_ms: 5000 };
        let display = err.to_string();
        assert!(display.contains("timed out"));
        assert!(display.contains("5000"));
    }

    #[test]
    fn test_network_error_display_peer_not_found() {
        let err = NetworkError::PeerNotFound {
            peer_id: make_coord_id(0x01),
        };
        let display = err.to_string();
        assert!(display.contains("peer not found"));
    }

    #[test]
    fn test_network_error_display_encoding() {
        let err = NetworkError::EncodingError {
            reason: "invalid".to_string(),
        };
        let display = err.to_string();
        assert!(display.contains("encoding error"));
        assert!(display.contains("invalid"));
    }

    #[test]
    fn test_network_error_display_shutdown() {
        let err = NetworkError::Shutdown;
        let display = err.to_string();
        assert!(display.contains("shut down"));
    }

    #[test]
    fn test_network_error_clone() {
        let err1 = NetworkError::Timeout { duration_ms: 100 };
        let err2 = err1.clone();
        assert_eq!(err1, err2);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // MockNetwork Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_mock_network_new() {
        let id = make_coord_id(0x01);
        let network = MockNetwork::new(id.clone());

        assert_eq!(network.self_id(), &id);
        assert!(network.connected_peers().is_empty());
        assert!(!network.is_shutdown());
    }

    #[test]
    fn test_mock_network_add_peer() {
        let network = MockNetwork::new(make_coord_id(0x01));

        network.add_peer(make_coord_id(0x02));
        network.add_peer(make_coord_id(0x03));

        let peers = network.connected_peers();
        assert_eq!(peers.len(), 2);
        assert!(peers.contains(&make_coord_id(0x02)));
        assert!(peers.contains(&make_coord_id(0x03)));
    }

    #[test]
    fn test_mock_network_add_peer_idempotent() {
        let network = MockNetwork::new(make_coord_id(0x01));

        network.add_peer(make_coord_id(0x02));
        network.add_peer(make_coord_id(0x02)); // Duplicate

        assert_eq!(network.connected_peers().len(), 1);
    }

    #[test]
    fn test_mock_network_remove_peer() {
        let network = MockNetwork::new(make_coord_id(0x01));

        network.add_peer(make_coord_id(0x02));
        network.add_peer(make_coord_id(0x03));
        network.remove_peer(&make_coord_id(0x02));

        let peers = network.connected_peers();
        assert_eq!(peers.len(), 1);
        assert!(!peers.contains(&make_coord_id(0x02)));
        assert!(peers.contains(&make_coord_id(0x03)));
    }

    #[test]
    fn test_mock_network_remove_peer_idempotent() {
        let network = MockNetwork::new(make_coord_id(0x01));

        // Remove non-existent peer - should not panic
        network.remove_peer(&make_coord_id(0x99));

        assert!(network.connected_peers().is_empty());
    }

    #[test]
    fn test_mock_network_shutdown() {
        let network = MockNetwork::new(make_coord_id(0x01));

        assert!(!network.is_shutdown());
        network.shutdown();
        assert!(network.is_shutdown());
    }

    #[test]
    fn test_mock_network_debug() {
        let network = MockNetwork::new(make_coord_id(0x01));
        let debug = format!("{:?}", network);
        assert!(debug.contains("MockNetwork"));
        assert!(debug.contains("self_id"));
    }

    #[tokio::test]
    async fn test_mock_network_broadcast() {
        let network = MockNetwork::new(make_coord_id(0x01));

        let msg = CoordinatorMessage::Ping { timestamp: 123 };
        let result = network.broadcast(msg.clone()).await;

        assert!(result.is_ok());

        let outbox = network.drain_outbox();
        assert_eq!(outbox.len(), 1);
        assert_eq!(outbox[0].0, None); // Broadcast has no target
        assert_eq!(outbox[0].1, msg);
    }

    #[tokio::test]
    async fn test_mock_network_send_to() {
        let network = MockNetwork::new(make_coord_id(0x01));
        let target = make_coord_id(0x02);

        network.add_peer(target.clone());

        let msg = CoordinatorMessage::Ping { timestamp: 456 };
        let result = network.send_to(target.clone(), msg.clone()).await;

        assert!(result.is_ok());

        let outbox = network.drain_outbox();
        assert_eq!(outbox.len(), 1);
        assert_eq!(outbox[0].0, Some(target));
        assert_eq!(outbox[0].1, msg);
    }

    #[tokio::test]
    async fn test_mock_network_send_to_peer_not_found() {
        let network = MockNetwork::new(make_coord_id(0x01));
        let target = make_coord_id(0x02);

        // Don't add peer

        let msg = CoordinatorMessage::Ping { timestamp: 789 };
        let result = network.send_to(target.clone(), msg).await;

        assert!(matches!(result, Err(NetworkError::PeerNotFound { peer_id }) if peer_id == target));
    }

    #[tokio::test]
    async fn test_mock_network_receive_empty() {
        let network = MockNetwork::new(make_coord_id(0x01));

        let result = network.receive().await;

        assert!(matches!(result, Err(NetworkError::Timeout { .. })));
    }

    #[tokio::test]
    async fn test_mock_network_inject_and_receive() {
        let network = MockNetwork::new(make_coord_id(0x01));
        let sender = make_coord_id(0x02);
        let msg = CoordinatorMessage::Ping { timestamp: 111 };

        network.inject_message(sender.clone(), msg.clone()).await.unwrap();

        let result = network.receive().await;
        assert!(result.is_ok());

        let (recv_sender, recv_msg) = result.unwrap();
        assert_eq!(recv_sender, sender);
        assert_eq!(recv_msg, msg);
    }

    #[tokio::test]
    async fn test_mock_network_receive_fifo_order() {
        let network = MockNetwork::new(make_coord_id(0x01));

        let msg1 = CoordinatorMessage::Ping { timestamp: 1 };
        let msg2 = CoordinatorMessage::Ping { timestamp: 2 };
        let msg3 = CoordinatorMessage::Ping { timestamp: 3 };

        network.inject_message(make_coord_id(0x02), msg1.clone()).await.unwrap();
        network.inject_message(make_coord_id(0x03), msg2.clone()).await.unwrap();
        network.inject_message(make_coord_id(0x04), msg3.clone()).await.unwrap();

        let (_, recv1) = network.receive().await.unwrap();
        let (_, recv2) = network.receive().await.unwrap();
        let (_, recv3) = network.receive().await.unwrap();

        assert_eq!(recv1, msg1);
        assert_eq!(recv2, msg2);
        assert_eq!(recv3, msg3);
    }

    #[tokio::test]
    async fn test_mock_network_shutdown_broadcast() {
        let network = MockNetwork::new(make_coord_id(0x01));
        network.shutdown();

        let result = network.broadcast(CoordinatorMessage::Ping { timestamp: 0 }).await;
        assert!(matches!(result, Err(NetworkError::Shutdown)));
    }

    #[tokio::test]
    async fn test_mock_network_shutdown_send_to() {
        let network = MockNetwork::new(make_coord_id(0x01));
        network.add_peer(make_coord_id(0x02));
        network.shutdown();

        let result = network
            .send_to(make_coord_id(0x02), CoordinatorMessage::Ping { timestamp: 0 })
            .await;
        assert!(matches!(result, Err(NetworkError::Shutdown)));
    }

    #[tokio::test]
    async fn test_mock_network_shutdown_receive() {
        let network = MockNetwork::new(make_coord_id(0x01));
        network.shutdown();

        let result = network.receive().await;
        assert!(matches!(result, Err(NetworkError::Shutdown)));
    }

    #[tokio::test]
    async fn test_mock_network_shutdown_inject() {
        let network = MockNetwork::new(make_coord_id(0x01));
        network.shutdown();

        let result = network
            .inject_message(make_coord_id(0x02), CoordinatorMessage::Ping { timestamp: 0 })
            .await;
        assert!(matches!(result, Err(NetworkError::Shutdown)));
    }

    #[tokio::test]
    async fn test_mock_network_reset() {
        let network = MockNetwork::new(make_coord_id(0x01));

        network.add_peer(make_coord_id(0x02));
        network.inject_message(make_coord_id(0x02), CoordinatorMessage::Ping { timestamp: 0 }).await.unwrap();
        network.broadcast(CoordinatorMessage::Ping { timestamp: 1 }).await.unwrap();
        network.shutdown();

        network.reset().await;

        assert!(!network.is_shutdown());
        assert!(network.connected_peers().is_empty());
        assert!(network.drain_outbox().is_empty());
        assert!(matches!(network.receive().await, Err(NetworkError::Timeout { .. })));
    }

    #[tokio::test]
    async fn test_mock_network_peek_outbox() {
        let network = MockNetwork::new(make_coord_id(0x01));

        let msg = CoordinatorMessage::Ping { timestamp: 123 };
        network.broadcast(msg.clone()).await.unwrap();

        // Peek should not drain
        let peek1 = network.peek_outbox();
        let peek2 = network.peek_outbox();
        assert_eq!(peek1.len(), 1);
        assert_eq!(peek2.len(), 1);

        // Drain should clear
        let drained = network.drain_outbox();
        assert_eq!(drained.len(), 1);
        assert!(network.peek_outbox().is_empty());
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Object Safety Test
    // ─────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_trait_object_safety() {
        let network = MockNetwork::new(make_coord_id(0x01));
        network.add_peer(make_coord_id(0x02));

        // Use as dyn trait object
        let dyn_network: &dyn CoordinatorNetwork = &network;

        // All methods should work through trait object
        assert_eq!(dyn_network.connected_peers().len(), 1);

        let result = dyn_network.broadcast(CoordinatorMessage::Ping { timestamp: 0 }).await;
        assert!(result.is_ok());
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Send + Sync Test
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_mock_network_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<MockNetwork>();
        assert_send_sync::<NetworkError>();
    }
}