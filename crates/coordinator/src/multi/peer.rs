//! Peer Connection Management (14A.2B.2.12)
//!
//! Module ini menyediakan sistem tracking koneksi peer coordinator.
//!
//! # Types
//!
//! | Type | Fungsi |
//! |------|--------|
//! | `ConnectionState` | State koneksi peer (Connected/Disconnected/Connecting/Failed) |
//! | `PeerConnection` | Data koneksi untuk satu peer |
//! | `PeerConfig` | Konfigurasi untuk peer management |
//! | `PeerManager` | Manager untuk semua peer connections |
//!
//! # Time Unit
//!
//! **SEMUA timestamp dalam module ini menggunakan MILLISECONDS.**
//! - `last_seen`: Unix timestamp dalam milliseconds
//! - `timeout_ms`: Timeout dalam milliseconds
//! - `health_check_interval_ms`: Interval health check dalam milliseconds
//!
//! # State Transitions
//!
//! ```text
//! ┌─────────────┐
//! │ Disconnected│◀──────────────────────────────────────┐
//! └──────┬──────┘                                       │
//!        │ (implicit initial state)                     │
//!        │                                              │
//!        ▼                                              │
//! ┌─────────────┐     mark_seen()      ┌───────────┐   │
//! │ Connecting  │─────────────────────▶│ Connected │   │
//! └──────┬──────┘                      └─────┬─────┘   │
//!        │                                   │         │
//!        │ mark_failed()                     │ mark_failed()
//!        │ (attempts < max)                  │ (attempts < max)
//!        │                                   │         │
//!        ▼                                   ▼         │
//! ┌─────────────┐◀────────────────────────────┘        │
//! │ Disconnected│                                      │
//! └──────┬──────┘                                      │
//!        │                                             │
//!        │ mark_failed() (attempts >= max)             │
//!        ▼                                             │
//! ┌─────────────┐                                      │
//! │   Failed    │──────────────────────────────────────┘
//! └─────────────┘       mark_seen() (reset)

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::CoordinatorId;

// ════════════════════════════════════════════════════════════════════════════════
// TIME UTILITIES
// ════════════════════════════════════════════════════════════════════════════════

/// Mendapatkan timestamp sekarang dalam milliseconds sejak Unix epoch.
///
/// Returns 0 jika SystemTime gagal (tidak panic).
#[inline]
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ════════════════════════════════════════════════════════════════════════════════
// CONNECTION STATE
// ════════════════════════════════════════════════════════════════════════════════

/// State koneksi peer coordinator.
///
/// # Variants
///
/// - `Connected` - Peer aktif dan responsif
/// - `Disconnected` - Peer tidak terhubung (initial state atau setelah failure ringan)
/// - `Connecting` - Sedang dalam proses koneksi
/// - `Failed` - Peer gagal setelah melebihi max retries
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    /// Peer aktif dan responsif.
    Connected,
    /// Peer tidak terhubung.
    Disconnected,
    /// Sedang dalam proses koneksi.
    Connecting,
    /// Peer gagal setelah melebihi max retries.
    Failed,
}

// ════════════════════════════════════════════════════════════════════════════════
// PEER CONNECTION
// ════════════════════════════════════════════════════════════════════════════════

/// Data koneksi untuk satu peer coordinator.
///
/// # Fields
///
/// - `id` - Identifier unik peer
/// - `addr` - Network address peer
/// - `state` - State koneksi saat ini
/// - `last_seen` - Timestamp terakhir peer terlihat (milliseconds sejak epoch)
/// - `failed_attempts` - Jumlah consecutive failed attempts
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerConnection {
    /// Identifier unik peer.
    pub id: CoordinatorId,
    /// Network address peer (e.g., "192.168.1.1:8080").
    pub addr: String,
    /// State koneksi saat ini.
    pub state: ConnectionState,
    /// Timestamp terakhir peer terlihat (milliseconds sejak Unix epoch).
    pub last_seen: u64,
    /// Jumlah consecutive failed attempts.
    pub failed_attempts: u32,
}

impl PeerConnection {
    /// Membuat PeerConnection baru dengan state Disconnected.
    ///
    /// # Arguments
    ///
    /// * `id` - CoordinatorId peer
    /// * `addr` - Network address peer
    ///
    /// # Returns
    ///
    /// PeerConnection baru dengan:
    /// - state = Disconnected
    /// - last_seen = 0
    /// - failed_attempts = 0
    #[must_use]
    pub fn new(id: CoordinatorId, addr: String) -> Self {
        Self {
            id,
            addr,
            state: ConnectionState::Disconnected,
            last_seen: 0,
            failed_attempts: 0,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// PEER CONFIG ERROR
// ════════════════════════════════════════════════════════════════════════════════

/// Error type untuk PeerConfig validation failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerConfigError {
    /// Deskripsi penyebab kegagalan validasi.
    pub reason: String,
}

impl fmt::Display for PeerConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "peer config validation failed: {}", self.reason)
    }
}

impl std::error::Error for PeerConfigError {}

// ════════════════════════════════════════════════════════════════════════════════
// PEER CONFIG
// ════════════════════════════════════════════════════════════════════════════════

/// Konfigurasi untuk peer connection management.
///
/// # Fields
///
/// - `timeout_ms` - Timeout untuk menganggap peer unhealthy (milliseconds)
/// - `max_retries` - Maksimum retry sebelum peer dianggap Failed
/// - `health_check_interval_ms` - Interval antar health check (milliseconds)
///
/// # Validation
///
/// - `timeout_ms` HARUS > 0
/// - `health_check_interval_ms` HARUS > 0
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerConfig {
    /// Timeout dalam milliseconds.
    /// Peer dianggap unhealthy jika (now - last_seen) > timeout_ms.
    pub timeout_ms: u64,
    /// Maksimum failed attempts sebelum state menjadi Failed.
    pub max_retries: u32,
    /// Interval health check dalam milliseconds.
    pub health_check_interval_ms: u64,
}

impl PeerConfig {
    /// Membuat PeerConfig baru dengan validasi.
    ///
    /// # Arguments
    ///
    /// * `timeout_ms` - Timeout dalam milliseconds (HARUS > 0)
    /// * `max_retries` - Maksimum retry attempts
    /// * `health_check_interval_ms` - Interval health check (HARUS > 0)
    ///
    /// # Errors
    ///
    /// Returns `PeerConfigError` jika:
    /// - `timeout_ms == 0`
    /// - `health_check_interval_ms == 0`
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config = PeerConfig::new(5000, 3, 1000)?;
    /// ```
    pub fn new(
        timeout_ms: u64,
        max_retries: u32,
        health_check_interval_ms: u64,
    ) -> Result<Self, PeerConfigError> {
        if timeout_ms == 0 {
            return Err(PeerConfigError {
                reason: "timeout_ms must be > 0".to_string(),
            });
        }
        if health_check_interval_ms == 0 {
            return Err(PeerConfigError {
                reason: "health_check_interval_ms must be > 0".to_string(),
            });
        }
        Ok(Self {
            timeout_ms,
            max_retries,
            health_check_interval_ms,
        })
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// PEER MANAGER
// ════════════════════════════════════════════════════════════════════════════════

/// Manager untuk peer connections.
///
/// Menyimpan dan mengelola koneksi ke semua peer coordinator.
///
/// # Invariants
///
/// - Semua state transitions eksplisit via method calls
/// - Tidak ada implicit auto-heal atau retry otomatis
/// - Semua operasi synchronous dan deterministic
#[derive(Debug, Serialize, Deserialize)]
pub struct PeerManager {
    /// Map dari CoordinatorId ke PeerConnection.
    peers: HashMap<CoordinatorId, PeerConnection>,
    /// Konfigurasi peer management.
    config: PeerConfig,
}

impl PeerManager {
    /// Membuat PeerManager baru dengan config yang sudah tervalidasi.
    ///
    /// # Arguments
    ///
    /// * `config` - PeerConfig yang sudah tervalidasi
    ///
    /// # Returns
    ///
    /// PeerManager baru dengan peers kosong.
    #[must_use]
    pub fn new(config: PeerConfig) -> Self {
        Self {
            peers: HashMap::new(),
            config,
        }
    }

    /// Mengembalikan reference ke config.
    #[must_use]
    #[inline]
    pub fn config(&self) -> &PeerConfig {
        &self.config
    }

    /// Mengembalikan jumlah peers yang terdaftar.
    #[must_use]
    #[inline]
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Mendapatkan reference ke PeerConnection jika ada.
    #[must_use]
    pub fn get_peer(&self, id: &CoordinatorId) -> Option<&PeerConnection> {
        self.peers.get(id)
    }

    /// Menambahkan peer baru atau overwrite peer yang sudah ada.
    ///
    /// # Arguments
    ///
    /// * `id` - CoordinatorId peer
    /// * `addr` - Network address peer
    ///
    /// # Behavior
    ///
    /// - Inisialisasi: state = Disconnected, failed_attempts = 0, last_seen = 0
    /// - Jika peer sudah ada: overwrite dengan data baru (deterministik)
    pub fn add_peer(&mut self, id: CoordinatorId, addr: String) {
        let connection = PeerConnection::new(id.clone(), addr);
        self.peers.insert(id, connection);
    }

    /// Menghapus peer dari manager.
    ///
    /// # Arguments
    ///
    /// * `id` - CoordinatorId peer yang akan dihapus
    ///
    /// # Behavior
    ///
    /// - Idempotent: tidak error jika peer tidak ada
    pub fn remove_peer(&mut self, id: &CoordinatorId) {
        self.peers.remove(id);
    }

    /// Menandai peer sebagai terlihat (aktif).
    ///
    /// # Arguments
    ///
    /// * `id` - CoordinatorId peer
    ///
    /// # Behavior
    ///
    /// - Update last_seen ke waktu sekarang (milliseconds)
    /// - Reset failed_attempts ke 0
    /// - Set state ke Connected
    /// - Jika peer tidak ada: no-op (tidak panic)
    pub fn mark_seen(&mut self, id: &CoordinatorId) {
        if let Some(peer) = self.peers.get_mut(id) {
            peer.last_seen = now_ms();
            peer.failed_attempts = 0;
            peer.state = ConnectionState::Connected;
        }
        // Peer tidak ada: no-op (explicit ignore)
    }

    /// Menandai peer sebagai gagal.
    ///
    /// # Arguments
    ///
    /// * `id` - CoordinatorId peer
    ///
    /// # Behavior
    ///
    /// - Increment failed_attempts
    /// - Jika failed_attempts >= max_retries: state = Failed
    /// - Else: state = Disconnected
    /// - Jika peer tidak ada: no-op (tidak panic)
    pub fn mark_failed(&mut self, id: &CoordinatorId) {
        if let Some(peer) = self.peers.get_mut(id) {
            peer.failed_attempts = peer.failed_attempts.saturating_add(1);
            if peer.failed_attempts >= self.config.max_retries {
                peer.state = ConnectionState::Failed;
            } else {
                peer.state = ConnectionState::Disconnected;
            }
        }
        // Peer tidak ada: no-op (explicit ignore)
    }

    /// Mendapatkan daftar peer yang healthy.
    ///
    /// # Criteria (ALL must be true)
    ///
    /// 1. `state == Connected`
    /// 2. `(now - last_seen) <= timeout_ms`
    /// 3. `failed_attempts < max_retries`
    ///
    /// # Returns
    ///
    /// Vector of references ke PeerConnection yang healthy.
    ///
    /// # Note
    ///
    /// Method ini TIDAK memutasi state.
    /// Timestamp diambil saat method dipanggil.
    #[must_use]
    pub fn get_healthy_peers(&self) -> Vec<&PeerConnection> {
        let now = now_ms();
        self.peers
            .values()
            .filter(|peer| {
                // Criteria 1: state must be Connected
                if peer.state != ConnectionState::Connected {
                    return false;
                }
                // Criteria 2: not timed out
                // Handle overflow: if now < last_seen, consider unhealthy
                let elapsed = now.saturating_sub(peer.last_seen);
                if elapsed > self.config.timeout_ms {
                    return false;
                }
                // Criteria 3: failed_attempts below threshold
                if peer.failed_attempts >= self.config.max_retries {
                    return false;
                }
                true
            })
            .collect()
    }

    /// Mendapatkan semua peers terlepas dari state.
    #[must_use]
    pub fn all_peers(&self) -> Vec<&PeerConnection> {
        self.peers.values().collect()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config() -> PeerConfig {
        PeerConfig::new(5000, 3, 1000).expect("valid config")
    }

    fn make_coord_id(seed: u8) -> CoordinatorId {
        CoordinatorId::new([seed; 32])
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // ConnectionState Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_connection_state_eq() {
        assert_eq!(ConnectionState::Connected, ConnectionState::Connected);
        assert_ne!(ConnectionState::Connected, ConnectionState::Disconnected);
        assert_ne!(ConnectionState::Connecting, ConnectionState::Failed);
    }

    #[test]
    fn test_connection_state_clone() {
        let state = ConnectionState::Connecting;
        let cloned = state.clone();
        assert_eq!(state, cloned);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // PeerConnection Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_peer_connection_new() {
        let id = make_coord_id(0x01);
        let conn = PeerConnection::new(id.clone(), "127.0.0.1:8080".to_string());

        assert_eq!(conn.id, id);
        assert_eq!(conn.addr, "127.0.0.1:8080");
        assert_eq!(conn.state, ConnectionState::Disconnected);
        assert_eq!(conn.last_seen, 0);
        assert_eq!(conn.failed_attempts, 0);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // PeerConfig Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_peer_config_valid() {
        let config = PeerConfig::new(5000, 3, 1000);
        assert!(config.is_ok());
        let config = config.unwrap();
        assert_eq!(config.timeout_ms, 5000);
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.health_check_interval_ms, 1000);
    }

    #[test]
    fn test_peer_config_zero_timeout() {
        let config = PeerConfig::new(0, 3, 1000);
        assert!(config.is_err());
        let err = config.unwrap_err();
        assert!(err.reason.contains("timeout_ms"));
    }

    #[test]
    fn test_peer_config_zero_health_interval() {
        let config = PeerConfig::new(5000, 3, 0);
        assert!(config.is_err());
        let err = config.unwrap_err();
        assert!(err.reason.contains("health_check_interval_ms"));
    }

    #[test]
    fn test_peer_config_error_display() {
        let err = PeerConfigError {
            reason: "test error".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("test error"));
        assert!(msg.contains("peer config validation failed"));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // PeerManager Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_peer_manager_new() {
        let config = make_config();
        let manager = PeerManager::new(config.clone());

        assert_eq!(manager.peer_count(), 0);
        assert_eq!(manager.config().timeout_ms, config.timeout_ms);
    }

    #[test]
    fn test_peer_manager_add_peer() {
        let mut manager = PeerManager::new(make_config());
        let id = make_coord_id(0x01);

        manager.add_peer(id.clone(), "127.0.0.1:8080".to_string());

        assert_eq!(manager.peer_count(), 1);
        let peer = manager.get_peer(&id).expect("peer exists");
        assert_eq!(peer.state, ConnectionState::Disconnected);
        assert_eq!(peer.last_seen, 0);
        assert_eq!(peer.failed_attempts, 0);
    }

    #[test]
    fn test_peer_manager_add_peer_overwrite() {
        let mut manager = PeerManager::new(make_config());
        let id = make_coord_id(0x01);

        manager.add_peer(id.clone(), "old_addr".to_string());
        manager.mark_seen(&id); // Change state

        // Overwrite
        manager.add_peer(id.clone(), "new_addr".to_string());

        let peer = manager.get_peer(&id).expect("peer exists");
        assert_eq!(peer.addr, "new_addr");
        assert_eq!(peer.state, ConnectionState::Disconnected); // Reset
        assert_eq!(peer.last_seen, 0); // Reset
    }

    #[test]
    fn test_peer_manager_remove_peer() {
        let mut manager = PeerManager::new(make_config());
        let id = make_coord_id(0x01);

        manager.add_peer(id.clone(), "addr".to_string());
        assert_eq!(manager.peer_count(), 1);

        manager.remove_peer(&id);
        assert_eq!(manager.peer_count(), 0);
        assert!(manager.get_peer(&id).is_none());
    }

    #[test]
    fn test_peer_manager_remove_peer_idempotent() {
        let mut manager = PeerManager::new(make_config());
        let id = make_coord_id(0x01);

        // Remove non-existent peer - should not panic
        manager.remove_peer(&id);
        manager.remove_peer(&id);

        assert_eq!(manager.peer_count(), 0);
    }

    #[test]
    fn test_peer_manager_mark_seen() {
        let mut manager = PeerManager::new(make_config());
        let id = make_coord_id(0x01);

        manager.add_peer(id.clone(), "addr".to_string());
        manager.mark_seen(&id);

        let peer = manager.get_peer(&id).expect("peer exists");
        assert_eq!(peer.state, ConnectionState::Connected);
        assert!(peer.last_seen > 0); // Should be updated
        assert_eq!(peer.failed_attempts, 0);
    }

    #[test]
    fn test_peer_manager_mark_seen_resets_failed_attempts() {
        let mut manager = PeerManager::new(make_config());
        let id = make_coord_id(0x01);

        manager.add_peer(id.clone(), "addr".to_string());
        manager.mark_failed(&id);
        manager.mark_failed(&id);

        let peer = manager.get_peer(&id).expect("peer exists");
        assert_eq!(peer.failed_attempts, 2);

        manager.mark_seen(&id);

        let peer = manager.get_peer(&id).expect("peer exists");
        assert_eq!(peer.failed_attempts, 0);
        assert_eq!(peer.state, ConnectionState::Connected);
    }

    #[test]
    fn test_peer_manager_mark_seen_nonexistent() {
        let mut manager = PeerManager::new(make_config());
        let id = make_coord_id(0x01);

        // Should not panic
        manager.mark_seen(&id);

        assert_eq!(manager.peer_count(), 0);
    }

    #[test]
    fn test_peer_manager_mark_failed() {
        let mut manager = PeerManager::new(make_config());
        let id = make_coord_id(0x01);

        manager.add_peer(id.clone(), "addr".to_string());

        // First failure
        manager.mark_failed(&id);
        let peer = manager.get_peer(&id).expect("peer exists");
        assert_eq!(peer.failed_attempts, 1);
        assert_eq!(peer.state, ConnectionState::Disconnected);

        // Second failure
        manager.mark_failed(&id);
        let peer = manager.get_peer(&id).expect("peer exists");
        assert_eq!(peer.failed_attempts, 2);
        assert_eq!(peer.state, ConnectionState::Disconnected);

        // Third failure (max_retries = 3)
        manager.mark_failed(&id);
        let peer = manager.get_peer(&id).expect("peer exists");
        assert_eq!(peer.failed_attempts, 3);
        assert_eq!(peer.state, ConnectionState::Failed);
    }

    #[test]
    fn test_peer_manager_mark_failed_nonexistent() {
        let mut manager = PeerManager::new(make_config());
        let id = make_coord_id(0x01);

        // Should not panic
        manager.mark_failed(&id);

        assert_eq!(manager.peer_count(), 0);
    }

    #[test]
    fn test_peer_manager_get_healthy_peers_connected() {
        let mut manager = PeerManager::new(make_config());
        let id1 = make_coord_id(0x01);
        let id2 = make_coord_id(0x02);

        manager.add_peer(id1.clone(), "addr1".to_string());
        manager.add_peer(id2.clone(), "addr2".to_string());

        manager.mark_seen(&id1);
        // id2 remains Disconnected

        let healthy = manager.get_healthy_peers();
        assert_eq!(healthy.len(), 1);
        assert_eq!(healthy[0].id, id1);
    }

    #[test]
    fn test_peer_manager_get_healthy_peers_failed_excluded() {
        let config = PeerConfig::new(5000, 2, 1000).expect("valid");
        let mut manager = PeerManager::new(config);
        let id = make_coord_id(0x01);

        manager.add_peer(id.clone(), "addr".to_string());
        manager.mark_seen(&id);

        // Before failure: healthy
        assert_eq!(manager.get_healthy_peers().len(), 1);

        // Fail twice (max_retries = 2)
        manager.mark_failed(&id);
        manager.mark_failed(&id);

        // After failure: not healthy
        assert_eq!(manager.get_healthy_peers().len(), 0);
    }

    #[test]
    fn test_peer_manager_all_peers() {
        let mut manager = PeerManager::new(make_config());

        manager.add_peer(make_coord_id(0x01), "addr1".to_string());
        manager.add_peer(make_coord_id(0x02), "addr2".to_string());
        manager.add_peer(make_coord_id(0x03), "addr3".to_string());

        let all = manager.all_peers();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_failed_attempts_saturating() {
        let config = PeerConfig::new(5000, u32::MAX, 1000).expect("valid");
        let mut manager = PeerManager::new(config);
        let id = make_coord_id(0x01);

        manager.add_peer(id.clone(), "addr".to_string());

        // Set failed_attempts to near max
        if let Some(peer) = manager.peers.get_mut(&id) {
            peer.failed_attempts = u32::MAX - 1;
        }

        // Should not overflow
        manager.mark_failed(&id);
        manager.mark_failed(&id);

        let peer = manager.get_peer(&id).expect("peer exists");
        assert_eq!(peer.failed_attempts, u32::MAX);
    }
}