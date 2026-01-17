//! # DA Health Monitor (14A.1A.11)
//!
//! Thread-safe, lock-safe monitoring untuk kesehatan Celestia DA.
//!
//! ## Thread Safety
//!
//! Komponen ini dirancang untuk:
//! - Lock-free reads untuk metrics monitoring
//! - Minimal lock duration untuk state kompleks
//! - Bebas race condition dan deadlock
//!
//! ## Memory Ordering
//!
//! - `Relaxed` ordering untuk metrics (eventual consistency)
//! - `Acquire/Release` ordering untuk state transitions
//!
//! ## Usage
//!
//! ```rust,ignore
//! let config = DAConfig::default();
//! let monitor = DAHealthMonitor::new(config);
//!
//! // Check status (lock-free for boolean)
//! if monitor.is_fallback_active() {
//!     println!("Fallback is active!");
//! }
//!
//! // Get full status (requires brief read lock)
//! let status = monitor.status();
//! ```

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::RwLock;

use crate::da::{DAHealthStatus, DAConfig};

// ════════════════════════════════════════════════════════════════════════════════
// DA HEALTH MONITOR STRUCT
// ════════════════════════════════════════════════════════════════════════════════

/// Thread-safe monitor untuk kesehatan Celestia DA.
///
/// Komponen ini menyediakan:
/// - Tracking latency dan height Celestia
/// - Status fallback
/// - Thread-safe read/write untuk semua metrics
///
/// ## Thread Safety
///
/// - Field numerik menggunakan `AtomicU64/AtomicBool` untuk lock-free updates
/// - Field kompleks menggunakan `RwLock` untuk concurrent read access
/// - Semua operasi bersifat non-blocking atau minimal blocking
///
/// ## Memory Ordering
///
/// Field atomik menggunakan ordering yang sesuai:
/// - `celestia_latency_ms`: `Relaxed` (monitoring, eventual consistency)
/// - `celestia_last_blob_height`: `Relaxed` (monitoring)
/// - `celestia_last_success`: `Relaxed` (monitoring)
/// - `fallback_active`: `Acquire/Release` (state transition requires ordering)
///
/// ## Invariants
///
/// - `config` bersifat immutable setelah konstruksi
/// - `fallback_reason` hanya Some ketika `fallback_active` true
/// - Tidak ada lock inversion (RwLock hanya diakses secara independen)
pub struct DAHealthMonitor {
    /// Latency terakhir dari request ke Celestia (milliseconds).
    ///
    /// Atomic untuk lock-free monitoring reads.
    /// Updated setiap kali ada request ke Celestia.
    celestia_latency_ms: AtomicU64,

    /// Height blob terakhir yang berhasil diambil dari Celestia.
    ///
    /// Atomic untuk lock-free monitoring reads.
    /// Updated setiap kali blob berhasil diambil.
    celestia_last_blob_height: AtomicU64,

    /// Unix timestamp (seconds since epoch) dari keberhasilan terakhir ke Celestia.
    ///
    /// Atomic untuk lock-free monitoring reads.
    /// Updated setiap kali ada operasi Celestia yang berhasil.
    celestia_last_success: AtomicU64,

    /// Flag apakah fallback mode sedang aktif.
    ///
    /// AtomicBool untuk lock-free state checks.
    /// Uses Acquire/Release ordering untuk proper synchronization
    /// dengan `fallback_reason` updates.
    fallback_active: AtomicBool,

    /// Alasan fallback diaktifkan (jika aktif).
    ///
    /// RwLock karena:
    /// - String membutuhkan heap allocation
    /// - Multiple readers (monitoring) vs single writer (state change)
    /// - Akses relatif jarang (hanya saat state change)
    ///
    /// Invariant: Some hanya ketika fallback_active == true
    fallback_reason: RwLock<Option<String>>,

    /// Status kesehatan DA terkini.
    ///
    /// RwLock karena:
    /// - DAHealthStatus mungkin kompleks (enum dengan data)
    /// - Multiple readers (monitoring) vs single writer (health check)
    /// - Copy semantics membutuhkan Clone
    current_status: RwLock<DAHealthStatus>,

    /// Konfigurasi monitoring.
    ///
    /// Immutable setelah konstruksi.
    /// Tidak memerlukan synchronization karena read-only.
    config: DAConfig,
}

// ════════════════════════════════════════════════════════════════════════════════
// IMPLEMENTATION
// ════════════════════════════════════════════════════════════════════════════════

impl DAHealthMonitor {
    /// Membuat instance baru `DAHealthMonitor` dengan konfigurasi yang diberikan.
    ///
    /// # Arguments
    ///
    /// * `config` - Konfigurasi untuk monitoring DA health
    ///
    /// # Returns
    ///
    /// Instance baru dengan:
    /// - Semua atomic terinisialisasi ke 0 / false
    /// - `fallback_reason` = None
    /// - `current_status` = `DAHealthStatus::Healthy`
    ///
    /// # Guarantees
    ///
    /// - Tidak membaca waktu sistem implisit
    /// - Tidak melakukan I/O
    /// - Tidak panic
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let config = DAConfig::default();
    /// let monitor = DAHealthMonitor::new(config);
    /// ```
    #[must_use]
    pub fn new(config: DAConfig) -> Self {
        Self {
            celestia_latency_ms: AtomicU64::new(0),
            celestia_last_blob_height: AtomicU64::new(0),
            celestia_last_success: AtomicU64::new(0),
            fallback_active: AtomicBool::new(false),
            fallback_reason: RwLock::new(None),
            current_status: RwLock::new(DAHealthStatus::Healthy),
            config,
        }
    }

    /// Mendapatkan snapshot status kesehatan DA terkini.
    ///
    /// # Returns
    ///
    /// Clone dari `DAHealthStatus` terkini.
    ///
    /// # Thread Safety
    ///
    /// - Mengambil read lock pada `current_status`
    /// - Lock duration minimal (hanya untuk clone)
    /// - Multiple concurrent readers diizinkan
    ///
    /// # Guarantees
    ///
    /// - Tidak mengembalikan reference (owned value)
    /// - Tidak panic (RwLock poisoning di-handle)
    /// - Tidak deadlock (single lock, no nesting)
    ///
    /// # Note
    ///
    /// Jika RwLock poisoned (karena panic di writer thread),
    /// fungsi ini tetap mengembalikan value dengan mengabaikan poison.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let status = monitor.status();
    /// match status {
    ///     DAHealthStatus::Healthy => println!("All good!"),
    ///     DAHealthStatus::Degraded => println!("Some issues..."),
    ///     // ...
    /// }
    /// ```
    #[must_use]
    pub fn status(&self) -> DAHealthStatus {
        // Menggunakan read() untuk minimal lock
        // Jika poisoned, tetap akses data dengan into_inner()
        match self.current_status.read() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Memeriksa apakah fallback mode sedang aktif.
    ///
    /// # Returns
    ///
    /// `true` jika fallback aktif, `false` jika tidak.
    ///
    /// # Thread Safety
    ///
    /// - Lock-free atomic read
    /// - Menggunakan `Acquire` ordering untuk proper synchronization
    ///   dengan writes yang menggunakan `Release`
    ///
    /// # Guarantees
    ///
    /// - Deterministik
    /// - Tidak panic
    /// - O(1) constant time
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// if monitor.is_fallback_active() {
    ///     // Handle fallback mode
    /// }
    /// ```
    #[inline]
    #[must_use]
    pub fn is_fallback_active(&self) -> bool {
        self.fallback_active.load(Ordering::Acquire)
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Additional accessor methods (read-only, lock-free)
    // ────────────────────────────────────────────────────────────────────────────

    /// Mendapatkan latency terakhir ke Celestia dalam milliseconds.
    ///
    /// # Returns
    ///
    /// Latency dalam milliseconds. 0 jika belum ada request.
    #[inline]
    #[must_use]
    pub fn celestia_latency_ms(&self) -> u64 {
        self.celestia_latency_ms.load(Ordering::Relaxed)
    }

    /// Mendapatkan height blob terakhir dari Celestia.
    ///
    /// # Returns
    ///
    /// Height blob terakhir. 0 jika belum ada blob.
    #[inline]
    #[must_use]
    pub fn celestia_last_blob_height(&self) -> u64 {
        self.celestia_last_blob_height.load(Ordering::Relaxed)
    }

    /// Mendapatkan timestamp keberhasilan terakhir ke Celestia.
    ///
    /// # Returns
    ///
    /// Unix timestamp (seconds). 0 jika belum ada keberhasilan.
    #[inline]
    #[must_use]
    pub fn celestia_last_success(&self) -> u64 {
        self.celestia_last_success.load(Ordering::Relaxed)
    }

    /// Mendapatkan alasan fallback aktif.
    ///
    /// # Returns
    ///
    /// `Some(reason)` jika fallback aktif, `None` jika tidak.
    ///
    /// # Thread Safety
    ///
    /// Mengambil read lock pada `fallback_reason`.
    #[must_use]
    pub fn fallback_reason(&self) -> Option<String> {
        match self.fallback_reason.read() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Mendapatkan reference ke konfigurasi.
    ///
    /// # Returns
    ///
    /// Reference ke `DAConfig` yang immutable.
    #[inline]
    #[must_use]
    pub fn config(&self) -> &DAConfig {
        &self.config
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Update methods (for internal use by health checking components)
    // ────────────────────────────────────────────────────────────────────────────

    /// Update latency Celestia.
    ///
    /// # Arguments
    ///
    /// * `latency_ms` - Latency baru dalam milliseconds
    #[inline]
    pub fn set_celestia_latency_ms(&self, latency_ms: u64) {
        self.celestia_latency_ms.store(latency_ms, Ordering::Relaxed);
    }

    /// Update height blob terakhir.
    ///
    /// # Arguments
    ///
    /// * `height` - Height baru
    #[inline]
    pub fn set_celestia_last_blob_height(&self, height: u64) {
        self.celestia_last_blob_height.store(height, Ordering::Relaxed);
    }

    /// Update timestamp keberhasilan terakhir.
    ///
    /// # Arguments
    ///
    /// * `timestamp` - Unix timestamp baru (seconds)
    #[inline]
    pub fn set_celestia_last_success(&self, timestamp: u64) {
        self.celestia_last_success.store(timestamp, Ordering::Relaxed);
    }

    /// Update status kesehatan DA.
    ///
    /// # Arguments
    ///
    /// * `status` - Status baru
    ///
    /// # Thread Safety
    ///
    /// Mengambil write lock pada `current_status`.
    pub fn set_status(&self, status: DAHealthStatus) {
        match self.current_status.write() {
            Ok(mut guard) => *guard = status,
            Err(poisoned) => *poisoned.into_inner() = status,
        }
    }

    /// Aktivasi fallback mode.
    ///
    /// # Arguments
    ///
    /// * `reason` - Alasan aktivasi fallback
    ///
    /// # Thread Safety
    ///
    /// - Mengambil write lock pada `fallback_reason`
    /// - Menggunakan `Release` ordering pada atomic write
    pub fn activate_fallback(&self, reason: String) {
        // Set reason first (before setting flag)
        match self.fallback_reason.write() {
            Ok(mut guard) => *guard = Some(reason),
            Err(poisoned) => *poisoned.into_inner() = Some(reason),
        }
        // Then set flag with Release ordering
        self.fallback_active.store(true, Ordering::Release);
    }

    /// Deaktivasi fallback mode.
    ///
    /// # Thread Safety
    ///
    /// - Menggunakan `Release` ordering pada atomic write
    /// - Mengambil write lock pada `fallback_reason`
    pub fn deactivate_fallback(&self) {
        // Clear flag first with Release ordering
        self.fallback_active.store(false, Ordering::Release);
        // Then clear reason
        match self.fallback_reason.write() {
            Ok(mut guard) => *guard = None,
            Err(poisoned) => *poisoned.into_inner() = None,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TRAIT IMPLEMENTATIONS
// ════════════════════════════════════════════════════════════════════════════════

// Note: DAHealthMonitor is automatically Send + Sync because:
// - AtomicU64 is Send + Sync
// - AtomicBool is Send + Sync
// - RwLock<T> is Send + Sync when T is Send + Sync
// - DAConfig is assumed to be Send + Sync
// - DAHealthStatus is assumed to be Send + Sync

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    // ────────────────────────────────────────────────────────────────────────────
    // Construction tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_new_initializes_atomics_to_zero() {
        let config = DAConfig::default();
        let monitor = DAHealthMonitor::new(config);

        assert_eq!(monitor.celestia_latency_ms(), 0);
        assert_eq!(monitor.celestia_last_blob_height(), 0);
        assert_eq!(monitor.celestia_last_success(), 0);
    }

    #[test]
    fn test_new_initializes_fallback_inactive() {
        let config = DAConfig::default();
        let monitor = DAHealthMonitor::new(config);

        assert!(!monitor.is_fallback_active());
    }

    #[test]
    fn test_new_initializes_fallback_reason_none() {
        let config = DAConfig::default();
        let monitor = DAHealthMonitor::new(config);

        assert!(monitor.fallback_reason().is_none());
    }

    #[test]
    fn test_new_initializes_status_healthy() {
        let config = DAConfig::default();
        let monitor = DAHealthMonitor::new(config);

        let status = monitor.status();
        assert_eq!(status, DAHealthStatus::Healthy);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Basic operation tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_is_fallback_active_returns_correct_value() {
        let config = DAConfig::default();
        let monitor = DAHealthMonitor::new(config);

        assert!(!monitor.is_fallback_active());

        monitor.activate_fallback(String::from("test reason"));
        assert!(monitor.is_fallback_active());

        monitor.deactivate_fallback();
        assert!(!monitor.is_fallback_active());
    }

    #[test]
    fn test_status_returns_clone_not_reference() {
        let config = DAConfig::default();
        let monitor = DAHealthMonitor::new(config);

        let status1 = monitor.status();
        let status2 = monitor.status();

        // Both should be equal (same value)
        assert_eq!(status1, status2);
    }

    #[test]
    fn test_set_and_get_latency() {
        let config = DAConfig::default();
        let monitor = DAHealthMonitor::new(config);

        monitor.set_celestia_latency_ms(100);
        assert_eq!(monitor.celestia_latency_ms(), 100);

        monitor.set_celestia_latency_ms(200);
        assert_eq!(monitor.celestia_latency_ms(), 200);
    }

    #[test]
    fn test_set_and_get_blob_height() {
        let config = DAConfig::default();
        let monitor = DAHealthMonitor::new(config);

        monitor.set_celestia_last_blob_height(12345);
        assert_eq!(monitor.celestia_last_blob_height(), 12345);
    }

    #[test]
    fn test_set_and_get_last_success() {
        let config = DAConfig::default();
        let monitor = DAHealthMonitor::new(config);

        monitor.set_celestia_last_success(1704067200);
        assert_eq!(monitor.celestia_last_success(), 1704067200);
    }

    #[test]
    fn test_activate_and_deactivate_fallback() {
        let config = DAConfig::default();
        let monitor = DAHealthMonitor::new(config);

        // Activate
        monitor.activate_fallback(String::from("celestia_timeout"));
        assert!(monitor.is_fallback_active());
        assert_eq!(monitor.fallback_reason(), Some(String::from("celestia_timeout")));

        // Deactivate
        monitor.deactivate_fallback();
        assert!(!monitor.is_fallback_active());
        assert!(monitor.fallback_reason().is_none());
    }

    #[test]
    fn test_config_accessor() {
        let config = DAConfig::default();
        let monitor = DAHealthMonitor::new(config.clone());

        let retrieved_config = monitor.config();
        assert_eq!(*retrieved_config, config);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Thread safety tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_concurrent_atomic_reads() {
        let config = DAConfig::default();
        let monitor = Arc::new(DAHealthMonitor::new(config));

        // Set initial values
        monitor.set_celestia_latency_ms(50);
        monitor.set_celestia_last_blob_height(1000);
        monitor.set_celestia_last_success(1704067200);

        let mut handles = vec![];

        // Spawn multiple reader threads
        for _ in 0..10 {
            let monitor_clone = Arc::clone(&monitor);
            let handle = thread::spawn(move || {
                for _ in 0..100 {
                    let _ = monitor_clone.celestia_latency_ms();
                    let _ = monitor_clone.celestia_last_blob_height();
                    let _ = monitor_clone.celestia_last_success();
                    let _ = monitor_clone.is_fallback_active();
                }
            });
            handles.push(handle);
        }

        // All threads should complete without panic
        for handle in handles {
            let result = handle.join();
            assert!(result.is_ok(), "Thread should not panic");
        }
    }

    #[test]
    fn test_concurrent_atomic_writes() {
        let config = DAConfig::default();
        let monitor = Arc::new(DAHealthMonitor::new(config));

        let mut handles = vec![];

        // Spawn multiple writer threads
        for i in 0..10 {
            let monitor_clone = Arc::clone(&monitor);
            let handle = thread::spawn(move || {
                for j in 0..100 {
                    let value = (i * 100 + j) as u64;
                    monitor_clone.set_celestia_latency_ms(value);
                    monitor_clone.set_celestia_last_blob_height(value);
                    monitor_clone.set_celestia_last_success(value);
                }
            });
            handles.push(handle);
        }

        // All threads should complete without panic
        for handle in handles {
            let result = handle.join();
            assert!(result.is_ok(), "Thread should not panic");
        }

        // Values should be one of the written values (not corrupted)
        let latency = monitor.celestia_latency_ms();
        assert!(latency < 1000, "Value should be within expected range");
    }

    #[test]
    fn test_concurrent_fallback_toggle() {
        let config = DAConfig::default();
        let monitor = Arc::new(DAHealthMonitor::new(config));

        let mut handles = vec![];

        // Spawn threads that toggle fallback
        for i in 0..5 {
            let monitor_clone = Arc::clone(&monitor);
            let handle = thread::spawn(move || {
                for j in 0..50 {
                    let reason = format!("reason_{}_{}", i, j);
                    monitor_clone.activate_fallback(reason);
                    let _ = monitor_clone.is_fallback_active();
                    let _ = monitor_clone.fallback_reason();
                    monitor_clone.deactivate_fallback();
                }
            });
            handles.push(handle);
        }

        // All threads should complete without panic or deadlock
        for handle in handles {
            let result = handle.join();
            assert!(result.is_ok(), "Thread should not panic");
        }
    }

    #[test]
    fn test_concurrent_status_read_write() {
        let config = DAConfig::default();
        let monitor = Arc::new(DAHealthMonitor::new(config));

        let mut handles = vec![];

        // Spawn reader threads
        for _ in 0..5 {
            let monitor_clone = Arc::clone(&monitor);
            let handle = thread::spawn(move || {
                for _ in 0..100 {
                    let _ = monitor_clone.status();
                }
            });
            handles.push(handle);
        }

        // Spawn writer threads
        for _ in 0..3 {
            let monitor_clone = Arc::clone(&monitor);
            let handle = thread::spawn(move || {
                for _ in 0..50 {
                    monitor_clone.set_status(DAHealthStatus::Healthy);
                }
            });
            handles.push(handle);
        }

        // All threads should complete without panic or deadlock
        for handle in handles {
            let result = handle.join();
            assert!(result.is_ok(), "Thread should not panic");
        }
    }

    #[test]
    fn test_concurrent_mixed_operations() {
        let config = DAConfig::default();
        let monitor = Arc::new(DAHealthMonitor::new(config));

        let mut handles = vec![];

        // Mixed operation threads
        for i in 0..8 {
            let monitor_clone = Arc::clone(&monitor);
            let handle = thread::spawn(move || {
                for j in 0..100 {
                    match (i + j) % 4 {
                        0 => {
                            monitor_clone.set_celestia_latency_ms(j as u64);
                        }
                        1 => {
                            let _ = monitor_clone.status();
                        }
                        2 => {
                            let _ = monitor_clone.is_fallback_active();
                        }
                        3 => {
                            if j % 2 == 0 {
                                monitor_clone.activate_fallback(format!("test_{}", j));
                            } else {
                                monitor_clone.deactivate_fallback();
                            }
                        }
                        _ => unreachable!(),
                    }
                }
            });
            handles.push(handle);
        }

        // All threads should complete without panic or deadlock
        for handle in handles {
            let result = handle.join();
            assert!(result.is_ok(), "Thread should not panic");
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Determinism tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_is_fallback_active_determinism() {
        let config = DAConfig::default();
        let monitor = DAHealthMonitor::new(config);

        // Multiple reads should return same value
        let v1 = monitor.is_fallback_active();
        let v2 = monitor.is_fallback_active();
        let v3 = monitor.is_fallback_active();

        assert_eq!(v1, v2);
        assert_eq!(v2, v3);
    }

    #[test]
    fn test_status_determinism() {
        let config = DAConfig::default();
        let monitor = DAHealthMonitor::new(config);

        // Multiple reads should return equal values
        let s1 = monitor.status();
        let s2 = monitor.status();

        assert_eq!(s1, s2);
    }

    #[test]
    fn test_atomic_reads_determinism() {
        let config = DAConfig::default();
        let monitor = DAHealthMonitor::new(config);

        monitor.set_celestia_latency_ms(42);
        monitor.set_celestia_last_blob_height(1000);
        monitor.set_celestia_last_success(1704067200);

        // Multiple reads should return same values
        for _ in 0..100 {
            assert_eq!(monitor.celestia_latency_ms(), 42);
            assert_eq!(monitor.celestia_last_blob_height(), 1000);
            assert_eq!(monitor.celestia_last_success(), 1704067200);
        }
    }
}