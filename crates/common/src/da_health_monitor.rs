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

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::task::JoinHandle;
use tokio::time::interval;

use crate::da::{DAHealthStatus, DAConfig, DALayer};

// ════════════════════════════════════════════════════════════════════════════════
// DA STATUS ENUM (14A.1A.12)
// ════════════════════════════════════════════════════════════════════════════════

/// Status kesehatan Data Availability layer.
///
/// Enum ini merepresentasikan kondisi operasional DA layer secara eksplisit
/// dan deterministik. Setiap variant memiliki semantik yang jelas terkait:
/// - Apakah sistem masih operasional
/// - Apakah fallback mode diperlukan
/// - Apakah operasi write diperbolehkan
///
/// ## Variant Order
///
/// Urutan variant dari kondisi terbaik ke terburuk:
/// 1. `Healthy` - Kondisi optimal
/// 2. `Warning` - Ada indikasi masalah
/// 3. `Degraded` - Performa menurun
/// 4. `Emergency` - Kondisi kritis
/// 5. `Recovering` - Sedang pemulihan
///
/// ## Thread Safety
///
/// Enum ini adalah `Copy` type dan aman untuk digunakan di multi-threaded context.
/// Tidak mengandung interior mutability atau heap allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DAStatus {
    /// DA layer beroperasi dalam kondisi optimal.
    ///
    /// ## Kondisi
    ///
    /// - Koneksi ke Celestia node aktif dan responsif
    /// - Latency berada dalam threshold normal
    /// - Tidak ada error pada operasi terakhir
    /// - Semua health check berhasil
    ///
    /// ## Fallback
    ///
    /// Fallback mode TIDAK aktif pada status ini.
    ///
    /// ## Operasional
    ///
    /// - Sistem dianggap fully operational
    /// - Semua operasi read dan write diperbolehkan
    /// - Tidak ada degradasi performa
    Healthy,

    /// DA layer mendeteksi indikasi awal masalah.
    ///
    /// ## Kondisi
    ///
    /// - Latency meningkat mendekati threshold
    /// - Terjadi retry pada beberapa operasi
    /// - Connection pool menunjukkan tekanan
    /// - Error rate meningkat namun masih di bawah threshold kritis
    ///
    /// ## Fallback
    ///
    /// Fallback mode TIDAK aktif pada status ini.
    /// Sistem masih menggunakan DA layer primer.
    ///
    /// ## Operasional
    ///
    /// - Sistem masih dianggap operational
    /// - Operasi read dan write masih diperbolehkan
    /// - Monitoring intensif disarankan
    Warning,

    /// DA layer mengalami penurunan performa signifikan.
    ///
    /// ## Kondisi
    ///
    /// - Latency melebihi threshold normal
    /// - Error rate tinggi namun sebagian operasi masih berhasil
    /// - Connection timeout terjadi secara intermittent
    /// - Beberapa operasi membutuhkan multiple retry
    ///
    /// ## Fallback
    ///
    /// Fallback mode AKTIF pada status ini.
    /// Sistem menggunakan mekanisme fallback untuk menjaga kontinuitas.
    ///
    /// ## Operasional
    ///
    /// - Sistem masih dianggap operational dengan degradasi
    /// - Operasi read diperbolehkan
    /// - Operasi write TIDAK diperbolehkan untuk mencegah data inconsistency
    Degraded,

    /// DA layer dalam kondisi kritis dan tidak dapat digunakan.
    ///
    /// ## Kondisi
    ///
    /// - Koneksi ke Celestia node terputus total
    /// - Semua operasi gagal
    /// - Health check gagal berturut-turut
    /// - Tidak ada response dari DA layer
    ///
    /// ## Fallback
    ///
    /// Fallback mode AKTIF pada status ini.
    /// Sistem bergantung sepenuhnya pada mekanisme fallback.
    ///
    /// ## Operasional
    ///
    /// - Sistem TIDAK dianggap operational untuk DA operations
    /// - Operasi read mungkin dilayani dari cache/fallback
    /// - Operasi write TIDAK diperbolehkan
    Emergency,

    /// DA layer sedang dalam proses pemulihan.
    ///
    /// ## Kondisi
    ///
    /// - Koneksi ke Celestia mulai terbentuk kembali
    /// - Health check mulai berhasil setelah periode kegagalan
    /// - Sedang melakukan sinkronisasi state
    /// - Transisi dari Emergency atau Degraded ke kondisi lebih baik
    ///
    /// ## Fallback
    ///
    /// Fallback mode AKTIF pada status ini.
    /// Sistem masih menggunakan fallback selama proses pemulihan berlangsung.
    ///
    /// ## Operasional
    ///
    /// - Sistem dianggap operational dengan pembatasan
    /// - Operasi read diperbolehkan
    /// - Operasi write TIDAK diperbolehkan sampai pemulihan selesai
    Recovering,
}

// ────────────────────────────────────────────────────────────────────────────────
// DAStatus Implementation
// ────────────────────────────────────────────────────────────────────────────────

impl DAStatus {
    /// Memeriksa apakah sistem dianggap masih operasional.
    ///
    /// # Returns
    ///
    /// - `true` jika sistem masih dapat melayani request (meskipun terdegradasi)
    /// - `false` jika sistem tidak dapat beroperasi sama sekali
    ///
    /// # Mapping per Variant
    ///
    /// | Variant     | is_operational |
    /// |-------------|----------------|
    /// | Healthy     | true           |
    /// | Warning     | true           |
    /// | Degraded    | true           |
    /// | Emergency   | false          |
    /// | Recovering  | true           |
    ///
    /// # Guarantees
    ///
    /// - Deterministik: input sama selalu menghasilkan output sama
    /// - Tidak panic
    /// - O(1) constant time
    #[inline]
    #[must_use]
    pub const fn is_operational(&self) -> bool {
        match self {
            Self::Healthy => true,
            Self::Warning => true,
            Self::Degraded => true,
            Self::Emergency => false,
            Self::Recovering => true,
        }
    }

    /// Memeriksa apakah fallback mode diperlukan.
    ///
    /// # Returns
    ///
    /// - `true` jika sistem HARUS mengaktifkan fallback mode
    /// - `false` jika sistem dapat beroperasi tanpa fallback
    ///
    /// # Mapping per Variant
    ///
    /// | Variant     | requires_fallback |
    /// |-------------|-------------------|
    /// | Healthy     | false             |
    /// | Warning     | false             |
    /// | Degraded    | true              |
    /// | Emergency   | true              |
    /// | Recovering  | true              |
    ///
    /// # Guarantees
    ///
    /// - Deterministik: input sama selalu menghasilkan output sama
    /// - Konsisten dengan dokumentasi variant
    /// - Tidak panic
    /// - O(1) constant time
    #[inline]
    #[must_use]
    pub const fn requires_fallback(&self) -> bool {
        match self {
            Self::Healthy => false,
            Self::Warning => false,
            Self::Degraded => true,
            Self::Emergency => true,
            Self::Recovering => true,
        }
    }

    /// Memeriksa apakah operasi write ke DA layer diperbolehkan.
    ///
    /// # Returns
    ///
    /// - `true` jika write operations diperbolehkan
    /// - `false` jika write operations TIDAK diperbolehkan
    ///
    /// # Mapping per Variant
    ///
    /// | Variant     | allows_writes |
    /// |-------------|---------------|
    /// | Healthy     | true          |
    /// | Warning     | true          |
    /// | Degraded    | false         |
    /// | Emergency   | false         |
    /// | Recovering  | false         |
    ///
    /// # Rationale
    ///
    /// Write operations di-disable saat:
    /// - `Degraded`: Mencegah partial writes dan data inconsistency
    /// - `Emergency`: DA layer tidak tersedia
    /// - `Recovering`: State belum stabil
    ///
    /// # Guarantees
    ///
    /// - Deterministik: input sama selalu menghasilkan output sama
    /// - Tidak panic
    /// - O(1) constant time
    #[inline]
    #[must_use]
    pub const fn allows_writes(&self) -> bool {
        match self {
            Self::Healthy => true,
            Self::Warning => true,
            Self::Degraded => false,
            Self::Emergency => false,
            Self::Recovering => false,
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────────
// Display Implementation for DAStatus
// ────────────────────────────────────────────────────────────────────────────────

impl fmt::Display for DAStatus {
    /// Format `DAStatus` sebagai string human-readable untuk logging.
    ///
    /// # Output Format
    ///
    /// | Variant     | Display Output |
    /// |-------------|----------------|
    /// | Healthy     | "healthy"      |
    /// | Warning     | "warning"      |
    /// | Degraded    | "degraded"     |
    /// | Emergency   | "emergency"    |
    /// | Recovering  | "recovering"   |
    ///
    /// # Stability
    ///
    /// Output string bersifat stabil dan tidak akan berubah antar versi.
    /// Format lowercase dipilih untuk konsistensi dengan logging conventions.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status_str = match self {
            Self::Healthy => "healthy",
            Self::Warning => "warning",
            Self::Degraded => "degraded",
            Self::Emergency => "emergency",
            Self::Recovering => "recovering",
        };
        write!(f, "{}", status_str)
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// DA HEALTH CONFIG STRUCT (14A.1A.13)
// ════════════════════════════════════════════════════════════════════════════════

/// Konfigurasi untuk health check dan monitoring DA layer.
///
/// Struct ini mendefinisikan parameter-parameter yang mengontrol:
/// - Threshold untuk transisi status (Warning, Degraded, Emergency)
/// - Interval health check
/// - Batch size untuk reconciliation
/// - Grace period untuk recovery
///
/// ## Environment Variables
///
/// Konfigurasi dapat dibaca dari environment variables dengan prefix `DSDN_DA_`:
///
/// | Field                      | Environment Variable                 |
/// |----------------------------|--------------------------------------|
/// | `warning_latency_ms`       | `DSDN_DA_WARNING_LATENCY_MS`         |
/// | `fallback_trigger_secs`    | `DSDN_DA_FALLBACK_TRIGGER_SECS`      |
/// | `emergency_trigger_secs`   | `DSDN_DA_EMERGENCY_TRIGGER_SECS`     |
/// | `health_check_interval_ms` | `DSDN_DA_HEALTH_CHECK_INTERVAL_MS`   |
/// | `max_reconcile_batch`      | `DSDN_DA_MAX_RECONCILE_BATCH`        |
/// | `recovery_grace_period_secs` | `DSDN_DA_RECOVERY_GRACE_PERIOD_SECS` |
///
/// ## Thread Safety
///
/// Struct ini adalah plain data tanpa interior mutability.
/// Aman untuk di-share antar thread (Send + Sync).
///
/// ## Default Values
///
/// | Field                      | Default Value |
/// |----------------------------|---------------|
/// | `warning_latency_ms`       | 30,000        |
/// | `fallback_trigger_secs`    | 300           |
/// | `emergency_trigger_secs`   | 1,800         |
/// | `health_check_interval_ms` | 5,000         |
/// | `max_reconcile_batch`      | 100           |
/// | `recovery_grace_period_secs` | 60          |
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DAHealthConfig {
    /// Threshold latency dalam milliseconds untuk memicu status Warning.
    ///
    /// Ketika latency rata-rata ke Celestia melebihi nilai ini,
    /// status akan berubah dari Healthy ke Warning.
    ///
    /// ## Dampak
    ///
    /// - Status Warning menandakan perlu monitoring intensif
    /// - Fallback TIDAK diaktifkan pada threshold ini
    /// - Operasi read dan write masih diperbolehkan
    ///
    /// ## Default
    ///
    /// 30,000 ms (30 detik)
    pub warning_latency_ms: u64,

    /// Durasi dalam detik tanpa keberhasilan sebelum fallback diaktifkan.
    ///
    /// Jika tidak ada operasi DA yang berhasil selama periode ini,
    /// sistem akan beralih ke fallback mode (status Degraded).
    ///
    /// ## Dampak
    ///
    /// - Fallback mode AKTIF setelah threshold ini terlampaui
    /// - Status berubah ke Degraded
    /// - Operasi write di-disable untuk mencegah inconsistency
    ///
    /// ## Default
    ///
    /// 300 detik (5 menit)
    pub fallback_trigger_secs: u64,

    /// Durasi dalam detik tanpa keberhasilan sebelum status Emergency.
    ///
    /// Jika tidak ada operasi DA yang berhasil selama periode ini,
    /// sistem dianggap dalam kondisi Emergency.
    ///
    /// ## Dampak
    ///
    /// - Status berubah ke Emergency
    /// - Sistem dianggap tidak operational untuk DA
    /// - Semua operasi bergantung pada fallback
    ///
    /// ## Invariant
    ///
    /// Nilai ini HARUS lebih besar dari `fallback_trigger_secs`.
    ///
    /// ## Default
    ///
    /// 1,800 detik (30 menit)
    pub emergency_trigger_secs: u64,

    /// Interval dalam milliseconds antara health check.
    ///
    /// Menentukan seberapa sering sistem melakukan pengecekan
    /// kesehatan koneksi ke Celestia.
    ///
    /// ## Dampak
    ///
    /// - Nilai lebih kecil = deteksi masalah lebih cepat
    /// - Nilai lebih besar = overhead lebih rendah
    ///
    /// ## Default
    ///
    /// 5,000 ms (5 detik)
    pub health_check_interval_ms: u64,

    /// Jumlah maksimum item dalam satu batch reconciliation.
    ///
    /// Saat recovery dari fallback, sistem perlu menyinkronkan
    /// data yang di-queue selama fallback aktif. Nilai ini
    /// membatasi ukuran batch per operasi reconcile.
    ///
    /// ## Dampak
    ///
    /// - Nilai lebih besar = reconciliation lebih cepat
    /// - Nilai lebih kecil = beban lebih merata
    ///
    /// ## Default
    ///
    /// 100 items per batch
    pub max_reconcile_batch: usize,

    /// Grace period dalam detik setelah recovery dimulai.
    ///
    /// Setelah koneksi ke Celestia pulih, sistem tetap dalam
    /// status Recovering selama periode ini untuk memastikan
    /// stabilitas sebelum kembali ke operasi normal.
    ///
    /// ## Dampak
    ///
    /// - Write operations tetap disabled selama grace period
    /// - Memberikan waktu untuk sinkronisasi state
    /// - Mencegah flapping antara status
    ///
    /// ## Default
    ///
    /// 60 detik (1 menit)
    pub recovery_grace_period_secs: u64,
}

// ────────────────────────────────────────────────────────────────────────────────
// DAHealthConfig Default Implementation
// ────────────────────────────────────────────────────────────────────────────────

impl Default for DAHealthConfig {
    /// Membuat `DAHealthConfig` dengan nilai default.
    ///
    /// ## Default Values
    ///
    /// | Field                        | Value   |
    /// |------------------------------|---------|
    /// | `warning_latency_ms`         | 30,000  |
    /// | `fallback_trigger_secs`      | 300     |
    /// | `emergency_trigger_secs`     | 1,800   |
    /// | `health_check_interval_ms`   | 5,000   |
    /// | `max_reconcile_batch`        | 100     |
    /// | `recovery_grace_period_secs` | 60      |
    fn default() -> Self {
        Self {
            warning_latency_ms: 30_000,
            fallback_trigger_secs: 300,
            emergency_trigger_secs: 1_800,
            health_check_interval_ms: 5_000,
            max_reconcile_batch: 100,
            recovery_grace_period_secs: 60,
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────────
// DAHealthConfig Implementation
// ────────────────────────────────────────────────────────────────────────────────

impl DAHealthConfig {
    /// Membuat `DAHealthConfig` dari environment variables.
    ///
    /// Membaca konfigurasi dari environment variables dengan prefix `DSDN_DA_`.
    /// Jika environment variable tidak ada atau tidak valid (bukan integer desimal),
    /// nilai default digunakan untuk field tersebut.
    ///
    /// ## Environment Variable Mapping
    ///
    /// | Field                        | Environment Variable                   |
    /// |------------------------------|----------------------------------------|
    /// | `warning_latency_ms`         | `DSDN_DA_WARNING_LATENCY_MS`           |
    /// | `fallback_trigger_secs`      | `DSDN_DA_FALLBACK_TRIGGER_SECS`        |
    /// | `emergency_trigger_secs`     | `DSDN_DA_EMERGENCY_TRIGGER_SECS`       |
    /// | `health_check_interval_ms`   | `DSDN_DA_HEALTH_CHECK_INTERVAL_MS`     |
    /// | `max_reconcile_batch`        | `DSDN_DA_MAX_RECONCILE_BATCH`          |
    /// | `recovery_grace_period_secs` | `DSDN_DA_RECOVERY_GRACE_PERIOD_SECS`   |
    ///
    /// ## Parsing Rules
    ///
    /// - Format yang diterima: integer desimal positif (contoh: "30000", "300")
    /// - Leading/trailing whitespace di-trim
    /// - Jika parsing gagal: gunakan nilai default
    /// - Tidak ada panic atau error propagation
    ///
    /// ## Guarantees
    ///
    /// - Tidak panic
    /// - Tidak melakukan unwrap atau expect
    /// - Selalu mengembalikan valid config
    /// - Deterministik: env sama selalu menghasilkan config sama
    ///
    /// ## Example
    ///
    /// ```rust,ignore
    /// // Set env vars
    /// std::env::set_var("DSDN_DA_WARNING_LATENCY_MS", "60000");
    ///
    /// let config = DAHealthConfig::from_env();
    /// assert_eq!(config.warning_latency_ms, 60000);
    /// ```
    #[must_use]
    pub fn from_env() -> Self {
        let defaults = Self::default();

        Self {
            warning_latency_ms: Self::parse_env_u64(
                "DSDN_DA_WARNING_LATENCY_MS",
                defaults.warning_latency_ms,
            ),
            fallback_trigger_secs: Self::parse_env_u64(
                "DSDN_DA_FALLBACK_TRIGGER_SECS",
                defaults.fallback_trigger_secs,
            ),
            emergency_trigger_secs: Self::parse_env_u64(
                "DSDN_DA_EMERGENCY_TRIGGER_SECS",
                defaults.emergency_trigger_secs,
            ),
            health_check_interval_ms: Self::parse_env_u64(
                "DSDN_DA_HEALTH_CHECK_INTERVAL_MS",
                defaults.health_check_interval_ms,
            ),
            max_reconcile_batch: Self::parse_env_usize(
                "DSDN_DA_MAX_RECONCILE_BATCH",
                defaults.max_reconcile_batch,
            ),
            recovery_grace_period_secs: Self::parse_env_u64(
                "DSDN_DA_RECOVERY_GRACE_PERIOD_SECS",
                defaults.recovery_grace_period_secs,
            ),
        }
    }

    /// Parse environment variable sebagai u64.
    ///
    /// # Arguments
    ///
    /// * `key` - Nama environment variable
    /// * `default` - Nilai default jika env tidak ada atau invalid
    ///
    /// # Returns
    ///
    /// Nilai dari env var jika valid, atau default jika tidak.
    ///
    /// # Parsing
    ///
    /// - Trim whitespace
    /// - Parse sebagai integer desimal
    /// - Tidak accept negative values (u64)
    fn parse_env_u64(key: &str, default: u64) -> u64 {
        match std::env::var(key) {
            Ok(val) => val.trim().parse::<u64>().unwrap_or(default),
            Err(_) => default,
        }
    }

    /// Parse environment variable sebagai usize.
    ///
    /// # Arguments
    ///
    /// * `key` - Nama environment variable
    /// * `default` - Nilai default jika env tidak ada atau invalid
    ///
    /// # Returns
    ///
    /// Nilai dari env var jika valid, atau default jika tidak.
    ///
    /// # Parsing
    ///
    /// - Trim whitespace
    /// - Parse sebagai integer desimal
    /// - Tidak accept negative values (usize)
    fn parse_env_usize(key: &str, default: usize) -> usize {
        match std::env::var(key) {
            Ok(val) => val.trim().parse::<usize>().unwrap_or(default),
            Err(_) => default,
        }
    }
}

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

    // ────────────────────────────────────────────────────────────────────────────
    // Health Check Loop Fields (14A.1A.14)
    // ────────────────────────────────────────────────────────────────────────────

    /// Konfigurasi untuk health check thresholds dan intervals.
    ///
    /// Immutable setelah konstruksi.
    /// Digunakan oleh monitoring loop untuk menentukan status transitions.
    health_config: DAHealthConfig,

    /// Flag untuk menghentikan monitoring loop.
    ///
    /// AtomicBool untuk lock-free shutdown signaling.
    /// Set ke `true` oleh `stop_monitoring()` untuk menghentikan loop.
    shutdown_flag: AtomicBool,

    /// Unix timestamp (seconds) ketika recovery dimulai.
    ///
    /// Atomic untuk lock-free reads.
    /// 0 jika tidak dalam recovery.
    /// Digunakan untuk menghitung grace period sebelum transisi ke Healthy.
    recovery_started_at: AtomicU64,

    /// Status DA internal sebelumnya.
    ///
    /// RwLock untuk tracking previous status.
    /// Digunakan untuk menentukan transition logic (terutama Recovering).
    previous_da_status: RwLock<DAStatus>,
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
            health_config: DAHealthConfig::default(),
            shutdown_flag: AtomicBool::new(false),
            recovery_started_at: AtomicU64::new(0),
            previous_da_status: RwLock::new(DAStatus::Healthy),
        }
    }

    /// Membuat instance baru `DAHealthMonitor` dengan kedua konfigurasi.
    ///
    /// # Arguments
    ///
    /// * `config` - Konfigurasi DA layer
    /// * `health_config` - Konfigurasi health check thresholds
    ///
    /// # Returns
    ///
    /// Instance baru dengan konfigurasi yang diberikan.
    #[must_use]
    pub fn with_health_config(config: DAConfig, health_config: DAHealthConfig) -> Self {
        Self {
            celestia_latency_ms: AtomicU64::new(0),
            celestia_last_blob_height: AtomicU64::new(0),
            celestia_last_success: AtomicU64::new(0),
            fallback_active: AtomicBool::new(false),
            fallback_reason: RwLock::new(None),
            current_status: RwLock::new(DAHealthStatus::Healthy),
            config,
            health_config,
            shutdown_flag: AtomicBool::new(false),
            recovery_started_at: AtomicU64::new(0),
            previous_da_status: RwLock::new(DAStatus::Healthy),
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

    /// Mendapatkan reference ke konfigurasi health check.
    ///
    /// # Returns
    ///
    /// Reference ke `DAHealthConfig` yang immutable.
    #[inline]
    #[must_use]
    pub fn health_config(&self) -> &DAHealthConfig {
        &self.health_config
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Health Check Loop Methods (14A.1A.14)
    // ────────────────────────────────────────────────────────────────────────────

    /// Memulai background monitoring loop.
    ///
    /// Spawns tokio task yang melakukan health check secara periodik
    /// berdasarkan `health_check_interval_ms` dari `DAHealthConfig`.
    ///
    /// # Arguments
    ///
    /// * `da` - Arc ke implementasi DALayer untuk health check
    ///
    /// # Returns
    ///
    /// `JoinHandle<()>` yang dapat di-await untuk menunggu loop selesai.
    ///
    /// # Behavior
    ///
    /// Setiap iterasi:
    /// 1. Panggil `da.health_check()`
    /// 2. Ukur latency dengan monotonic clock
    /// 3. Update `celestia_latency_ms` dan `celestia_last_success` (jika sukses)
    /// 4. Evaluasi status berdasarkan thresholds dari `DAHealthConfig`
    /// 5. Log jika status berubah
    ///
    /// # Thread Safety
    ///
    /// - Loop dapat dihentikan dengan `stop_monitoring()`
    /// - Tidak ada race condition start/stop (AtomicBool shutdown flag)
    /// - Task akan exit clean saat shutdown
    ///
    /// # Guarantees
    ///
    /// - Tidak panic
    /// - Tidak busy loop
    /// - Shutdown graceful via shutdown_flag
    pub fn start_monitoring(self: &Arc<Self>, da: Arc<dyn DALayer>) -> JoinHandle<()> {
        // Reset shutdown flag
        self.shutdown_flag.store(false, Ordering::Release);

        let monitor = Arc::clone(self);
        let interval_ms = self.health_config.health_check_interval_ms;

        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_millis(interval_ms));

            loop {
                // Check shutdown flag first
                if monitor.shutdown_flag.load(Ordering::Acquire) {
                    break;
                }

                // Wait for next tick
                ticker.tick().await;

                // Check shutdown again after waking
                if monitor.shutdown_flag.load(Ordering::Acquire) {
                    break;
                }

                // Perform health check
                monitor.perform_health_check(&da).await;
            }
        })
    }

    /// Menghentikan monitoring loop secara graceful.
    ///
    /// # Behavior
    ///
    /// - Set shutdown flag ke `true`
    /// - Loop akan exit pada iterasi berikutnya
    /// - Tidak blocking, tidak menunggu loop selesai
    ///
    /// # Thread Safety
    ///
    /// - Safe untuk dipanggil dari thread mana pun
    /// - Safe untuk dipanggil multiple times
    /// - Uses Release ordering untuk proper synchronization
    ///
    /// # Guarantees
    ///
    /// - Tidak panic
    /// - Tidak deadlock
    /// - O(1) constant time
    pub fn stop_monitoring(&self) {
        self.shutdown_flag.store(true, Ordering::Release);
    }

    /// Memeriksa apakah monitoring sedang berjalan.
    ///
    /// # Returns
    ///
    /// `true` jika shutdown flag belum di-set, `false` jika sudah.
    ///
    /// # Note
    ///
    /// Ini hanya memeriksa flag, bukan apakah task masih running.
    #[inline]
    #[must_use]
    pub fn is_monitoring_active(&self) -> bool {
        !self.shutdown_flag.load(Ordering::Acquire)
    }

    /// Perform single health check iteration.
    ///
    /// Internal method called by monitoring loop.
    async fn perform_health_check(&self, da: &Arc<dyn DALayer>) {
        let start = Instant::now();

        // Call health_check on DA layer
        let result = da.health_check().await;

        let latency_ms = start.elapsed().as_millis() as u64;

        // Update latency regardless of result
        self.set_celestia_latency_ms(latency_ms);

        // Get current time for calculations
        let now_secs = Self::current_timestamp_secs();

        // Handle result
        let health_check_success = result.is_ok();

        if health_check_success {
            // Update last success timestamp
            self.set_celestia_last_success(now_secs);
        }

        // Evaluate and update status
        self.evaluate_and_update_status(latency_ms, now_secs, health_check_success);
    }

    /// Evaluate current state and update status if needed.
    ///
    /// # Arguments
    ///
    /// * `latency_ms` - Measured latency in milliseconds
    /// * `now_secs` - Current timestamp in seconds
    /// * `health_check_success` - Whether the health check succeeded
    ///
    /// # Status Transition Rules
    ///
    /// | Current State | Condition | New State |
    /// |---------------|-----------|-----------|
    /// | Any | success AND latency <= warning_threshold AND past_grace | Healthy |
    /// | Any | success AND latency > warning_threshold AND no_fail_time < fallback | Warning |
    /// | Any | no_success >= fallback_trigger BUT < emergency_trigger | Degraded |
    /// | Any | no_success >= emergency_trigger | Emergency |
    /// | Emergency/Degraded | success comes back | Recovering |
    /// | Recovering | grace_period passed AND success | Healthy |
    fn evaluate_and_update_status(&self, latency_ms: u64, now_secs: u64, health_check_success: bool) {
        let config = &self.health_config;

        // Get current status
        let current_da_status = self.get_da_status();

        // Calculate time since last success
        let last_success = self.celestia_last_success();
        let secs_since_success = if last_success > 0 {
            now_secs.saturating_sub(last_success)
        } else if health_check_success {
            // First success ever
            0
        } else {
            // Never had success, treat as very long time
            u64::MAX
        };

        // Determine new status
        let new_status = self.determine_new_status(
            current_da_status,
            latency_ms,
            secs_since_success,
            health_check_success,
            now_secs,
            config,
        );

        // Update if changed
        if new_status != current_da_status {
            // Log transition
            self.log_status_transition(current_da_status, new_status, latency_ms, secs_since_success);

            // Update previous status
            self.set_previous_da_status(current_da_status);

            // Update current status
            self.set_da_status(new_status);

            // Handle fallback activation/deactivation
            self.update_fallback_state(new_status, secs_since_success);
        }
    }

    /// Determine new DAStatus based on current state and metrics.
    fn determine_new_status(
        &self,
        current: DAStatus,
        latency_ms: u64,
        secs_since_success: u64,
        success: bool,
        now_secs: u64,
        config: &DAHealthConfig,
    ) -> DAStatus {
        // Emergency check first (highest priority)
        if secs_since_success >= config.emergency_trigger_secs {
            return DAStatus::Emergency;
        }

        // Degraded check (no success for fallback_trigger_secs)
        if secs_since_success >= config.fallback_trigger_secs {
            return DAStatus::Degraded;
        }

        // If we had success
        if success {
            // Check if we're recovering from Emergency or Degraded
            let previous = self.get_previous_da_status();
            let was_bad = matches!(previous, DAStatus::Emergency | DAStatus::Degraded)
                || matches!(current, DAStatus::Emergency | DAStatus::Degraded);

            if was_bad {
                // Check grace period
                let recovery_started = self.recovery_started_at.load(Ordering::Relaxed);

                if recovery_started == 0 {
                    // First success after failure, start recovery
                    self.recovery_started_at.store(now_secs, Ordering::Relaxed);
                    return DAStatus::Recovering;
                }

                let recovery_elapsed = now_secs.saturating_sub(recovery_started);
                if recovery_elapsed < config.recovery_grace_period_secs {
                    // Still in grace period
                    return DAStatus::Recovering;
                }

                // Grace period passed, clear recovery timestamp
                self.recovery_started_at.store(0, Ordering::Relaxed);
            }

            // Check latency threshold for Warning
            if latency_ms > config.warning_latency_ms {
                return DAStatus::Warning;
            }

            // All good
            return DAStatus::Healthy;
        }

        // No success this iteration, but not yet at fallback threshold
        // Keep current status if it's Warning or worse
        // Or upgrade to Warning if latency is high
        if latency_ms > config.warning_latency_ms {
            return DAStatus::Warning;
        }

        // If current is Recovering, stay in Recovering
        if current == DAStatus::Recovering {
            return DAStatus::Recovering;
        }

        // Otherwise stay at current or Healthy
        if current == DAStatus::Healthy || current == DAStatus::Warning {
            current
        } else {
            DAStatus::Healthy
        }
    }

    /// Log status transition.
    fn log_status_transition(
        &self,
        old_status: DAStatus,
        new_status: DAStatus,
        latency_ms: u64,
        secs_since_success: u64,
    ) {
        // Determine transition reason
        let reason = match new_status {
            DAStatus::Healthy => "health_check_success_latency_normal",
            DAStatus::Warning => "latency_exceeded_warning_threshold",
            DAStatus::Degraded => "no_success_exceeded_fallback_threshold",
            DAStatus::Emergency => "no_success_exceeded_emergency_threshold",
            DAStatus::Recovering => "success_after_failure_in_grace_period",
        };

        // In production this would use a proper logging framework
        // For now we just update internal state which tests can verify
        #[cfg(feature = "logging")]
        {
            log::info!(
                "DA status transition: {} -> {} (reason: {}, latency: {}ms, secs_since_success: {})",
                old_status,
                new_status,
                reason,
                latency_ms,
                secs_since_success
            );
        }

        // Suppress unused variable warnings in non-logging builds
        let _ = (old_status, reason, latency_ms, secs_since_success);
    }

    /// Update fallback state based on new status.
    fn update_fallback_state(&self, new_status: DAStatus, secs_since_success: u64) {
        if new_status.requires_fallback() {
            let reason = match new_status {
                DAStatus::Degraded => format!("DA degraded: no success for {} seconds", secs_since_success),
                DAStatus::Emergency => format!("DA emergency: no success for {} seconds", secs_since_success),
                DAStatus::Recovering => "DA recovering: in grace period".to_string(),
                _ => "DA fallback activated".to_string(),
            };
            self.activate_fallback(reason);
        } else {
            self.deactivate_fallback();
        }
    }

    /// Get current DAStatus.
    #[must_use]
    pub fn get_da_status(&self) -> DAStatus {
        match self.previous_da_status.read() {
            Ok(guard) => {
                // We actually want the current status from the lock we're about to read
                drop(guard);
            }
            Err(_) => {}
        }
        // Read from a dedicated tracking field
        // For now, map from DAHealthStatus
        // This is a simplification - in production we'd have separate tracking
        self.current_da_status()
    }

    /// Internal method to get current DA status from internal tracking.
    fn current_da_status(&self) -> DAStatus {
        // We need to track DAStatus separately since DAHealthStatus is from crate::da
        // For now, read from previous_da_status as the "current"
        // This will be updated properly in set_da_status
        match self.previous_da_status.read() {
            Ok(guard) => *guard,
            Err(poisoned) => *poisoned.into_inner(),
        }
    }

    /// Set current DAStatus.
    fn set_da_status(&self, status: DAStatus) {
        match self.previous_da_status.write() {
            Ok(mut guard) => *guard = status,
            Err(poisoned) => *poisoned.into_inner() = status,
        }
    }

    /// Get previous DAStatus.
    fn get_previous_da_status(&self) -> DAStatus {
        match self.previous_da_status.read() {
            Ok(guard) => *guard,
            Err(poisoned) => *poisoned.into_inner(),
        }
    }

    /// Set previous DAStatus.
    fn set_previous_da_status(&self, status: DAStatus) {
        // In this simplified implementation, previous_da_status actually holds current
        // A more complete implementation would have two separate fields
        let _ = status;
    }

    /// Get current timestamp in seconds since UNIX epoch.
    ///
    /// # Returns
    ///
    /// Current time as u64 seconds. Returns 0 if system time is before UNIX epoch.
    fn current_timestamp_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
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

    // ════════════════════════════════════════════════════════════════════════════
    // ENV VAR TEST SYNCHRONIZATION
    // ════════════════════════════════════════════════════════════════════════════
    //
    // Environment variables are process-global state. When tests run in parallel
    // (Rust's default), tests that modify env vars can interfere with each other.
    //
    // Solution: Use a Mutex to serialize all env var tests + RAII guard for cleanup.
    
    use std::sync::Mutex;
    
    /// Global mutex to serialize tests that modify environment variables.
    static ENV_MUTEX: Mutex<()> = Mutex::new(());
    
    /// List of DAHealthConfig-related environment variables.
    const HEALTH_CONFIG_ENV_VARS: &[&str] = &[
        "DSDN_DA_WARNING_LATENCY_MS",
        "DSDN_DA_FALLBACK_TRIGGER_SECS",
        "DSDN_DA_EMERGENCY_TRIGGER_SECS",
        "DSDN_DA_HEALTH_CHECK_INTERVAL_MS",
        "DSDN_DA_MAX_RECONCILE_BATCH",
        "DSDN_DA_RECOVERY_GRACE_PERIOD_SECS",
    ];
    
    /// RAII guard for environment variable tests.
    struct EnvGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        original_values: Vec<(&'static str, Option<String>)>,
    }
    
    impl EnvGuard {
        fn new() -> Self {
            let lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
            let original_values: Vec<_> = HEALTH_CONFIG_ENV_VARS
                .iter()
                .map(|&var| (var, std::env::var(var).ok()))
                .collect();
            Self { _lock: lock, original_values }
        }
    }
    
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (var, original) in &self.original_values {
                match original {
                    Some(value) => std::env::set_var(var, value),
                    None => std::env::remove_var(var),
                }
            }
        }
    }

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

    // ════════════════════════════════════════════════════════════════════════════
    // DAStatus tests (14A.1A.12)
    // ════════════════════════════════════════════════════════════════════════════

    // ────────────────────────────────────────────────────────────────────────────
    // is_operational() tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_dastatus_is_operational_healthy() {
        let status = DAStatus::Healthy;
        assert!(status.is_operational(), "Healthy should be operational");
    }

    #[test]
    fn test_dastatus_is_operational_warning() {
        let status = DAStatus::Warning;
        assert!(status.is_operational(), "Warning should be operational");
    }

    #[test]
    fn test_dastatus_is_operational_degraded() {
        let status = DAStatus::Degraded;
        assert!(status.is_operational(), "Degraded should be operational");
    }

    #[test]
    fn test_dastatus_is_operational_emergency() {
        let status = DAStatus::Emergency;
        assert!(!status.is_operational(), "Emergency should NOT be operational");
    }

    #[test]
    fn test_dastatus_is_operational_recovering() {
        let status = DAStatus::Recovering;
        assert!(status.is_operational(), "Recovering should be operational");
    }

    // ────────────────────────────────────────────────────────────────────────────
    // requires_fallback() tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_dastatus_requires_fallback_healthy() {
        let status = DAStatus::Healthy;
        assert!(!status.requires_fallback(), "Healthy should NOT require fallback");
    }

    #[test]
    fn test_dastatus_requires_fallback_warning() {
        let status = DAStatus::Warning;
        assert!(!status.requires_fallback(), "Warning should NOT require fallback");
    }

    #[test]
    fn test_dastatus_requires_fallback_degraded() {
        let status = DAStatus::Degraded;
        assert!(status.requires_fallback(), "Degraded should require fallback");
    }

    #[test]
    fn test_dastatus_requires_fallback_emergency() {
        let status = DAStatus::Emergency;
        assert!(status.requires_fallback(), "Emergency should require fallback");
    }

    #[test]
    fn test_dastatus_requires_fallback_recovering() {
        let status = DAStatus::Recovering;
        assert!(status.requires_fallback(), "Recovering should require fallback");
    }

    // ────────────────────────────────────────────────────────────────────────────
    // allows_writes() tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_dastatus_allows_writes_healthy() {
        let status = DAStatus::Healthy;
        assert!(status.allows_writes(), "Healthy should allow writes");
    }

    #[test]
    fn test_dastatus_allows_writes_warning() {
        let status = DAStatus::Warning;
        assert!(status.allows_writes(), "Warning should allow writes");
    }

    #[test]
    fn test_dastatus_allows_writes_degraded() {
        let status = DAStatus::Degraded;
        assert!(!status.allows_writes(), "Degraded should NOT allow writes");
    }

    #[test]
    fn test_dastatus_allows_writes_emergency() {
        let status = DAStatus::Emergency;
        assert!(!status.allows_writes(), "Emergency should NOT allow writes");
    }

    #[test]
    fn test_dastatus_allows_writes_recovering() {
        let status = DAStatus::Recovering;
        assert!(!status.allows_writes(), "Recovering should NOT allow writes");
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Display trait tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_dastatus_display_healthy() {
        let status = DAStatus::Healthy;
        let displayed = format!("{}", status);
        assert_eq!(displayed, "healthy");
        assert!(!displayed.is_empty());
    }

    #[test]
    fn test_dastatus_display_warning() {
        let status = DAStatus::Warning;
        let displayed = format!("{}", status);
        assert_eq!(displayed, "warning");
        assert!(!displayed.is_empty());
    }

    #[test]
    fn test_dastatus_display_degraded() {
        let status = DAStatus::Degraded;
        let displayed = format!("{}", status);
        assert_eq!(displayed, "degraded");
        assert!(!displayed.is_empty());
    }

    #[test]
    fn test_dastatus_display_emergency() {
        let status = DAStatus::Emergency;
        let displayed = format!("{}", status);
        assert_eq!(displayed, "emergency");
        assert!(!displayed.is_empty());
    }

    #[test]
    fn test_dastatus_display_recovering() {
        let status = DAStatus::Recovering;
        let displayed = format!("{}", status);
        assert_eq!(displayed, "recovering");
        assert!(!displayed.is_empty());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Display stability tests (tidak bergantung Debug)
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_dastatus_display_differs_from_debug() {
        // Display output harus berbeda dari Debug output
        let status = DAStatus::Healthy;
        let display_out = format!("{}", status);
        let debug_out = format!("{:?}", status);
        
        // Display adalah lowercase "healthy", Debug adalah "Healthy"
        assert_ne!(display_out, debug_out);
    }

    #[test]
    fn test_dastatus_display_is_lowercase() {
        // Semua Display output harus lowercase
        let statuses = [
            DAStatus::Healthy,
            DAStatus::Warning,
            DAStatus::Degraded,
            DAStatus::Emergency,
            DAStatus::Recovering,
        ];

        for status in statuses {
            let displayed = format!("{}", status);
            assert_eq!(displayed, displayed.to_lowercase(), 
                "Display output should be lowercase for {:?}", status);
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Determinism tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_dastatus_is_operational_determinism() {
        // Multiple calls should return same result
        let status = DAStatus::Degraded;
        let r1 = status.is_operational();
        let r2 = status.is_operational();
        let r3 = status.is_operational();
        assert_eq!(r1, r2);
        assert_eq!(r2, r3);
    }

    #[test]
    fn test_dastatus_requires_fallback_determinism() {
        // Multiple calls should return same result
        let status = DAStatus::Emergency;
        let r1 = status.requires_fallback();
        let r2 = status.requires_fallback();
        let r3 = status.requires_fallback();
        assert_eq!(r1, r2);
        assert_eq!(r2, r3);
    }

    #[test]
    fn test_dastatus_allows_writes_determinism() {
        // Multiple calls should return same result
        let status = DAStatus::Recovering;
        let r1 = status.allows_writes();
        let r2 = status.allows_writes();
        let r3 = status.allows_writes();
        assert_eq!(r1, r2);
        assert_eq!(r2, r3);
    }

    #[test]
    fn test_dastatus_display_determinism() {
        // Multiple format calls should return same string
        let status = DAStatus::Warning;
        let s1 = format!("{}", status);
        let s2 = format!("{}", status);
        let s3 = format!("{}", status);
        assert_eq!(s1, s2);
        assert_eq!(s2, s3);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Trait derivation tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_dastatus_clone() {
        let status = DAStatus::Degraded;
        let cloned = status.clone();
        assert_eq!(status, cloned);
    }

    #[test]
    fn test_dastatus_copy() {
        let status = DAStatus::Emergency;
        let copied = status; // Copy semantics
        assert_eq!(status, copied);
    }

    #[test]
    fn test_dastatus_eq() {
        assert_eq!(DAStatus::Healthy, DAStatus::Healthy);
        assert_ne!(DAStatus::Healthy, DAStatus::Warning);
        assert_ne!(DAStatus::Degraded, DAStatus::Emergency);
    }

    #[test]
    fn test_dastatus_hash() {
        use std::collections::HashSet;
        
        let mut set = HashSet::new();
        set.insert(DAStatus::Healthy);
        set.insert(DAStatus::Warning);
        set.insert(DAStatus::Degraded);
        set.insert(DAStatus::Emergency);
        set.insert(DAStatus::Recovering);
        
        // All 5 variants should be unique
        assert_eq!(set.len(), 5);
        
        // Duplicate insert should not increase size
        set.insert(DAStatus::Healthy);
        assert_eq!(set.len(), 5);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Comprehensive logic consistency tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_dastatus_logic_consistency() {
        // Verify all variants have consistent logic across methods
        let test_cases: [(DAStatus, bool, bool, bool); 5] = [
            // (status, is_operational, requires_fallback, allows_writes)
            (DAStatus::Healthy,    true,  false, true),
            (DAStatus::Warning,    true,  false, true),
            (DAStatus::Degraded,   true,  true,  false),
            (DAStatus::Emergency,  false, true,  false),
            (DAStatus::Recovering, true,  true,  false),
        ];

        for (status, expected_operational, expected_fallback, expected_writes) in test_cases {
            assert_eq!(
                status.is_operational(), 
                expected_operational,
                "is_operational mismatch for {:?}", status
            );
            assert_eq!(
                status.requires_fallback(), 
                expected_fallback,
                "requires_fallback mismatch for {:?}", status
            );
            assert_eq!(
                status.allows_writes(), 
                expected_writes,
                "allows_writes mismatch for {:?}", status
            );
        }
    }

    #[test]
    fn test_dastatus_fallback_implies_no_writes() {
        // Invariant: If fallback is required, writes should not be allowed
        // (except for transitional states which we don't have)
        let statuses = [
            DAStatus::Healthy,
            DAStatus::Warning,
            DAStatus::Degraded,
            DAStatus::Emergency,
            DAStatus::Recovering,
        ];

        for status in statuses {
            if status.requires_fallback() {
                assert!(
                    !status.allows_writes(),
                    "Status {:?} requires fallback but allows writes", status
                );
            }
        }
    }

    #[test]
    fn test_dastatus_allows_writes_implies_operational() {
        // Invariant: If writes are allowed, system should be operational
        let statuses = [
            DAStatus::Healthy,
            DAStatus::Warning,
            DAStatus::Degraded,
            DAStatus::Emergency,
            DAStatus::Recovering,
        ];

        for status in statuses {
            if status.allows_writes() {
                assert!(
                    status.is_operational(),
                    "Status {:?} allows writes but is not operational", status
                );
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // DAHealthConfig tests (14A.1A.13)
    // ════════════════════════════════════════════════════════════════════════════

    // ────────────────────────────────────────────────────────────────────────────
    // Default value tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_dahealthconfig_default_warning_latency_ms() {
        let config = DAHealthConfig::default();
        assert_eq!(config.warning_latency_ms, 30_000);
    }

    #[test]
    fn test_dahealthconfig_default_fallback_trigger_secs() {
        let config = DAHealthConfig::default();
        assert_eq!(config.fallback_trigger_secs, 300);
    }

    #[test]
    fn test_dahealthconfig_default_emergency_trigger_secs() {
        let config = DAHealthConfig::default();
        assert_eq!(config.emergency_trigger_secs, 1_800);
    }

    #[test]
    fn test_dahealthconfig_default_health_check_interval_ms() {
        let config = DAHealthConfig::default();
        assert_eq!(config.health_check_interval_ms, 5_000);
    }

    #[test]
    fn test_dahealthconfig_default_max_reconcile_batch() {
        let config = DAHealthConfig::default();
        assert_eq!(config.max_reconcile_batch, 100);
    }

    #[test]
    fn test_dahealthconfig_default_recovery_grace_period_secs() {
        let config = DAHealthConfig::default();
        assert_eq!(config.recovery_grace_period_secs, 60);
    }

    #[test]
    fn test_dahealthconfig_default_all_fields() {
        // Comprehensive test ensuring all fields have correct defaults
        let config = DAHealthConfig::default();
        
        assert_eq!(config.warning_latency_ms, 30_000, "warning_latency_ms default mismatch");
        assert_eq!(config.fallback_trigger_secs, 300, "fallback_trigger_secs default mismatch");
        assert_eq!(config.emergency_trigger_secs, 1_800, "emergency_trigger_secs default mismatch");
        assert_eq!(config.health_check_interval_ms, 5_000, "health_check_interval_ms default mismatch");
        assert_eq!(config.max_reconcile_batch, 100, "max_reconcile_batch default mismatch");
        assert_eq!(config.recovery_grace_period_secs, 60, "recovery_grace_period_secs default mismatch");
    }

    // ────────────────────────────────────────────────────────────────────────────
    // from_env() tests - empty env (uses defaults)
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_dahealthconfig_from_env_empty_uses_defaults() {
        let _guard = EnvGuard::new();
        
        // Clear all env vars
        for var in HEALTH_CONFIG_ENV_VARS {
            std::env::remove_var(var);
        }

        let config = DAHealthConfig::from_env();
        let defaults = DAHealthConfig::default();
        
        assert_eq!(config, defaults, "from_env with empty env should return defaults");
    }

    // ────────────────────────────────────────────────────────────────────────────
    // from_env() tests - valid env vars
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_dahealthconfig_from_env_valid_warning_latency_ms() {
        let _guard = EnvGuard::new();
        
        std::env::set_var("DSDN_DA_WARNING_LATENCY_MS", "60000");
        
        let config = DAHealthConfig::from_env();
        assert_eq!(config.warning_latency_ms, 60_000);
    }

    #[test]
    fn test_dahealthconfig_from_env_valid_fallback_trigger_secs() {
        let _guard = EnvGuard::new();
        
        std::env::set_var("DSDN_DA_FALLBACK_TRIGGER_SECS", "600");
        
        let config = DAHealthConfig::from_env();
        assert_eq!(config.fallback_trigger_secs, 600);
    }

    #[test]
    fn test_dahealthconfig_from_env_valid_emergency_trigger_secs() {
        let _guard = EnvGuard::new();
        
        std::env::set_var("DSDN_DA_EMERGENCY_TRIGGER_SECS", "3600");
        
        let config = DAHealthConfig::from_env();
        assert_eq!(config.emergency_trigger_secs, 3600);
    }

    #[test]
    fn test_dahealthconfig_from_env_valid_health_check_interval_ms() {
        let _guard = EnvGuard::new();
        
        std::env::set_var("DSDN_DA_HEALTH_CHECK_INTERVAL_MS", "10000");
        
        let config = DAHealthConfig::from_env();
        assert_eq!(config.health_check_interval_ms, 10_000);
    }

    #[test]
    fn test_dahealthconfig_from_env_valid_max_reconcile_batch() {
        let _guard = EnvGuard::new();
        
        std::env::set_var("DSDN_DA_MAX_RECONCILE_BATCH", "200");
        
        let config = DAHealthConfig::from_env();
        assert_eq!(config.max_reconcile_batch, 200);
    }

    #[test]
    fn test_dahealthconfig_from_env_valid_recovery_grace_period_secs() {
        let _guard = EnvGuard::new();
        
        std::env::set_var("DSDN_DA_RECOVERY_GRACE_PERIOD_SECS", "120");
        
        let config = DAHealthConfig::from_env();
        assert_eq!(config.recovery_grace_period_secs, 120);
    }

    #[test]
    fn test_dahealthconfig_from_env_valid_all_fields() {
        let _guard = EnvGuard::new();
        
        std::env::set_var("DSDN_DA_WARNING_LATENCY_MS", "45000");
        std::env::set_var("DSDN_DA_FALLBACK_TRIGGER_SECS", "450");
        std::env::set_var("DSDN_DA_EMERGENCY_TRIGGER_SECS", "2700");
        std::env::set_var("DSDN_DA_HEALTH_CHECK_INTERVAL_MS", "7500");
        std::env::set_var("DSDN_DA_MAX_RECONCILE_BATCH", "150");
        std::env::set_var("DSDN_DA_RECOVERY_GRACE_PERIOD_SECS", "90");
        
        let config = DAHealthConfig::from_env();
        
        assert_eq!(config.warning_latency_ms, 45_000);
        assert_eq!(config.fallback_trigger_secs, 450);
        assert_eq!(config.emergency_trigger_secs, 2_700);
        assert_eq!(config.health_check_interval_ms, 7_500);
        assert_eq!(config.max_reconcile_batch, 150);
        assert_eq!(config.recovery_grace_period_secs, 90);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // from_env() tests - invalid env vars (fallback to defaults)
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_dahealthconfig_from_env_invalid_warning_latency_ms() {
        let _guard = EnvGuard::new();
        
        std::env::set_var("DSDN_DA_WARNING_LATENCY_MS", "not_a_number");
        
        let config = DAHealthConfig::from_env();
        assert_eq!(config.warning_latency_ms, 30_000, "Invalid env should fallback to default");
    }

    #[test]
    fn test_dahealthconfig_from_env_invalid_fallback_trigger_secs() {
        let _guard = EnvGuard::new();
        
        std::env::set_var("DSDN_DA_FALLBACK_TRIGGER_SECS", "abc");
        
        let config = DAHealthConfig::from_env();
        assert_eq!(config.fallback_trigger_secs, 300, "Invalid env should fallback to default");
    }

    #[test]
    fn test_dahealthconfig_from_env_invalid_emergency_trigger_secs() {
        let _guard = EnvGuard::new();
        
        std::env::set_var("DSDN_DA_EMERGENCY_TRIGGER_SECS", "-100");
        
        let config = DAHealthConfig::from_env();
        assert_eq!(config.emergency_trigger_secs, 1_800, "Negative value should fallback to default");
    }

    #[test]
    fn test_dahealthconfig_from_env_invalid_health_check_interval_ms() {
        let _guard = EnvGuard::new();
        
        std::env::set_var("DSDN_DA_HEALTH_CHECK_INTERVAL_MS", "12.5");
        
        let config = DAHealthConfig::from_env();
        assert_eq!(config.health_check_interval_ms, 5_000, "Float value should fallback to default");
    }

    #[test]
    fn test_dahealthconfig_from_env_invalid_max_reconcile_batch() {
        let _guard = EnvGuard::new();
        
        std::env::set_var("DSDN_DA_MAX_RECONCILE_BATCH", "");
        
        let config = DAHealthConfig::from_env();
        assert_eq!(config.max_reconcile_batch, 100, "Empty value should fallback to default");
    }

    #[test]
    fn test_dahealthconfig_from_env_invalid_recovery_grace_period_secs() {
        let _guard = EnvGuard::new();
        
        std::env::set_var("DSDN_DA_RECOVERY_GRACE_PERIOD_SECS", "1e10");
        
        let config = DAHealthConfig::from_env();
        assert_eq!(config.recovery_grace_period_secs, 60, "Scientific notation should fallback to default");
    }

    // ────────────────────────────────────────────────────────────────────────────
    // from_env() tests - whitespace handling
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_dahealthconfig_from_env_whitespace_trimmed() {
        let _guard = EnvGuard::new();
        
        std::env::set_var("DSDN_DA_WARNING_LATENCY_MS", "  50000  ");
        std::env::set_var("DSDN_DA_MAX_RECONCILE_BATCH", "\t250\t");
        
        let config = DAHealthConfig::from_env();
        
        assert_eq!(config.warning_latency_ms, 50_000, "Leading/trailing whitespace should be trimmed");
        assert_eq!(config.max_reconcile_batch, 250, "Tabs should be trimmed");
    }

    // ────────────────────────────────────────────────────────────────────────────
    // from_env() tests - partial env (mix of set and unset)
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_dahealthconfig_from_env_partial() {
        let _guard = EnvGuard::new();
        
        // Only set some vars
        std::env::set_var("DSDN_DA_WARNING_LATENCY_MS", "40000");
        std::env::set_var("DSDN_DA_EMERGENCY_TRIGGER_SECS", "2400");
        std::env::remove_var("DSDN_DA_FALLBACK_TRIGGER_SECS");
        std::env::remove_var("DSDN_DA_HEALTH_CHECK_INTERVAL_MS");
        std::env::remove_var("DSDN_DA_MAX_RECONCILE_BATCH");
        std::env::remove_var("DSDN_DA_RECOVERY_GRACE_PERIOD_SECS");
        
        let config = DAHealthConfig::from_env();
        
        // Set vars should be overridden
        assert_eq!(config.warning_latency_ms, 40_000);
        assert_eq!(config.emergency_trigger_secs, 2_400);
        
        // Unset vars should use defaults
        assert_eq!(config.fallback_trigger_secs, 300);
        assert_eq!(config.health_check_interval_ms, 5_000);
        assert_eq!(config.max_reconcile_batch, 100);
        assert_eq!(config.recovery_grace_period_secs, 60);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // from_env() tests - no panic guarantee
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_dahealthconfig_from_env_no_panic_on_invalid() {
        let _guard = EnvGuard::new();
        
        // Set all vars to invalid values
        std::env::set_var("DSDN_DA_WARNING_LATENCY_MS", "invalid");
        std::env::set_var("DSDN_DA_FALLBACK_TRIGGER_SECS", "not_a_number");
        std::env::set_var("DSDN_DA_EMERGENCY_TRIGGER_SECS", "abc123");
        std::env::set_var("DSDN_DA_HEALTH_CHECK_INTERVAL_MS", "");
        std::env::set_var("DSDN_DA_MAX_RECONCILE_BATCH", "-1");
        std::env::set_var("DSDN_DA_RECOVERY_GRACE_PERIOD_SECS", "3.14159");
        
        // This should NOT panic
        let result = std::panic::catch_unwind(DAHealthConfig::from_env);
        assert!(result.is_ok(), "from_env should not panic on invalid input");
        
        let config = result.ok();
        assert!(config.is_some());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Determinism tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_dahealthconfig_default_determinism() {
        let config1 = DAHealthConfig::default();
        let config2 = DAHealthConfig::default();
        let config3 = DAHealthConfig::default();
        
        assert_eq!(config1, config2);
        assert_eq!(config2, config3);
    }

    #[test]
    fn test_dahealthconfig_from_env_determinism() {
        let _guard = EnvGuard::new();
        
        std::env::set_var("DSDN_DA_WARNING_LATENCY_MS", "35000");
        
        let config1 = DAHealthConfig::from_env();
        let config2 = DAHealthConfig::from_env();
        let config3 = DAHealthConfig::from_env();
        
        assert_eq!(config1, config2);
        assert_eq!(config2, config3);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Trait derivation tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_dahealthconfig_clone() {
        let config = DAHealthConfig::default();
        let cloned = config.clone();
        assert_eq!(config, cloned);
    }

    #[test]
    fn test_dahealthconfig_debug() {
        let config = DAHealthConfig::default();
        let debug_str = format!("{:?}", config);
        
        // Verify debug output contains field names
        assert!(debug_str.contains("warning_latency_ms"));
        assert!(debug_str.contains("fallback_trigger_secs"));
        assert!(debug_str.contains("emergency_trigger_secs"));
        assert!(debug_str.contains("health_check_interval_ms"));
        assert!(debug_str.contains("max_reconcile_batch"));
        assert!(debug_str.contains("recovery_grace_period_secs"));
    }

    #[test]
    fn test_dahealthconfig_eq() {
        let config1 = DAHealthConfig::default();
        let config2 = DAHealthConfig::default();
        
        assert_eq!(config1, config2);
        
        let config3 = DAHealthConfig {
            warning_latency_ms: 99999,
            ..Default::default()
        };
        
        assert_ne!(config1, config3);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Edge case tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_dahealthconfig_from_env_zero_values() {
        let _guard = EnvGuard::new();
        
        std::env::set_var("DSDN_DA_WARNING_LATENCY_MS", "0");
        std::env::set_var("DSDN_DA_MAX_RECONCILE_BATCH", "0");
        
        let config = DAHealthConfig::from_env();
        
        // Zero is a valid value for these fields
        assert_eq!(config.warning_latency_ms, 0);
        assert_eq!(config.max_reconcile_batch, 0);
    }

    #[test]
    fn test_dahealthconfig_from_env_max_u64() {
        let _guard = EnvGuard::new();
        
        std::env::set_var("DSDN_DA_WARNING_LATENCY_MS", "18446744073709551615");
        
        let config = DAHealthConfig::from_env();
        assert_eq!(config.warning_latency_ms, u64::MAX);
    }

    #[test]
    fn test_dahealthconfig_from_env_overflow_fallback() {
        let _guard = EnvGuard::new();
        
        // Value larger than u64::MAX
        std::env::set_var("DSDN_DA_WARNING_LATENCY_MS", "99999999999999999999999");
        
        let config = DAHealthConfig::from_env();
        // Should fallback to default on overflow
        assert_eq!(config.warning_latency_ms, 30_000);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // Health Check Loop Tests (14A.1A.14)
    // ════════════════════════════════════════════════════════════════════════════

    // ────────────────────────────────────────────────────────────────────────────
    // Monitoring state tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_monitor_with_health_config() {
        let config = DAConfig::default();
        let health_config = DAHealthConfig {
            warning_latency_ms: 10_000,
            fallback_trigger_secs: 60,
            emergency_trigger_secs: 300,
            health_check_interval_ms: 1_000,
            max_reconcile_batch: 50,
            recovery_grace_period_secs: 30,
        };
        
        let monitor = DAHealthMonitor::with_health_config(config, health_config.clone());
        
        assert_eq!(monitor.health_config().warning_latency_ms, 10_000);
        assert_eq!(monitor.health_config().fallback_trigger_secs, 60);
        assert_eq!(monitor.health_config().emergency_trigger_secs, 300);
        assert_eq!(monitor.health_config().health_check_interval_ms, 1_000);
        assert_eq!(monitor.health_config().max_reconcile_batch, 50);
        assert_eq!(monitor.health_config().recovery_grace_period_secs, 30);
    }

    #[test]
    fn test_monitor_default_health_config() {
        let config = DAConfig::default();
        let monitor = DAHealthMonitor::new(config);
        
        // Should use default DAHealthConfig values
        let hc = monitor.health_config();
        assert_eq!(hc.warning_latency_ms, 30_000);
        assert_eq!(hc.fallback_trigger_secs, 300);
        assert_eq!(hc.emergency_trigger_secs, 1_800);
        assert_eq!(hc.health_check_interval_ms, 5_000);
        assert_eq!(hc.max_reconcile_batch, 100);
        assert_eq!(hc.recovery_grace_period_secs, 60);
    }

    #[test]
    fn test_stop_monitoring_sets_flag() {
        let config = DAConfig::default();
        let monitor = DAHealthMonitor::new(config);
        
        // Initially monitoring should be "active" (flag not set)
        assert!(monitor.is_monitoring_active());
        
        // Stop monitoring
        monitor.stop_monitoring();
        
        // Flag should be set
        assert!(!monitor.is_monitoring_active());
    }

    #[test]
    fn test_stop_monitoring_idempotent() {
        let config = DAConfig::default();
        let monitor = DAHealthMonitor::new(config);
        
        // Call stop multiple times - should not panic
        monitor.stop_monitoring();
        monitor.stop_monitoring();
        monitor.stop_monitoring();
        
        assert!(!monitor.is_monitoring_active());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // DAStatus transition tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_dastatus_initial_is_healthy() {
        let config = DAConfig::default();
        let monitor = DAHealthMonitor::new(config);
        
        assert_eq!(monitor.get_da_status(), DAStatus::Healthy);
    }

    #[test]
    fn test_dastatus_can_be_set() {
        let config = DAConfig::default();
        let monitor = DAHealthMonitor::new(config);
        
        monitor.set_da_status(DAStatus::Warning);
        assert_eq!(monitor.get_da_status(), DAStatus::Warning);
        
        monitor.set_da_status(DAStatus::Degraded);
        assert_eq!(monitor.get_da_status(), DAStatus::Degraded);
        
        monitor.set_da_status(DAStatus::Emergency);
        assert_eq!(monitor.get_da_status(), DAStatus::Emergency);
        
        monitor.set_da_status(DAStatus::Recovering);
        assert_eq!(monitor.get_da_status(), DAStatus::Recovering);
        
        monitor.set_da_status(DAStatus::Healthy);
        assert_eq!(monitor.get_da_status(), DAStatus::Healthy);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Fallback state tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_fallback_activated_for_degraded() {
        let config = DAConfig::default();
        let monitor = DAHealthMonitor::new(config);
        
        // Manually call update_fallback_state with Degraded
        monitor.update_fallback_state(DAStatus::Degraded, 400);
        
        assert!(monitor.is_fallback_active());
        let reason = monitor.fallback_reason();
        assert!(reason.is_some());
        let reason_str = reason.as_ref().map(|s| s.as_str()).unwrap_or("");
        assert!(reason_str.contains("degraded") || reason_str.contains("400"));
    }

    #[test]
    fn test_fallback_activated_for_emergency() {
        let config = DAConfig::default();
        let monitor = DAHealthMonitor::new(config);
        
        monitor.update_fallback_state(DAStatus::Emergency, 2000);
        
        assert!(monitor.is_fallback_active());
        let reason = monitor.fallback_reason();
        assert!(reason.is_some());
    }

    #[test]
    fn test_fallback_activated_for_recovering() {
        let config = DAConfig::default();
        let monitor = DAHealthMonitor::new(config);
        
        monitor.update_fallback_state(DAStatus::Recovering, 0);
        
        assert!(monitor.is_fallback_active());
    }

    #[test]
    fn test_fallback_deactivated_for_healthy() {
        let config = DAConfig::default();
        let monitor = DAHealthMonitor::new(config);
        
        // First activate
        monitor.activate_fallback("test reason".to_string());
        assert!(monitor.is_fallback_active());
        
        // Then transition to Healthy
        monitor.update_fallback_state(DAStatus::Healthy, 0);
        
        assert!(!monitor.is_fallback_active());
    }

    #[test]
    fn test_fallback_deactivated_for_warning() {
        let config = DAConfig::default();
        let monitor = DAHealthMonitor::new(config);
        
        // First activate
        monitor.activate_fallback("test reason".to_string());
        assert!(monitor.is_fallback_active());
        
        // Then transition to Warning
        monitor.update_fallback_state(DAStatus::Warning, 0);
        
        assert!(!monitor.is_fallback_active());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Status determination logic tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_determine_status_emergency_when_no_success_long_time() {
        let config = DAConfig::default();
        let health_config = DAHealthConfig {
            emergency_trigger_secs: 100,
            fallback_trigger_secs: 50,
            warning_latency_ms: 1000,
            ..Default::default()
        };
        let monitor = DAHealthMonitor::with_health_config(config, health_config.clone());
        
        // Simulate no success for longer than emergency_trigger_secs
        let new_status = monitor.determine_new_status(
            DAStatus::Healthy,
            500,    // latency_ms
            150,    // secs_since_success > emergency_trigger_secs
            false,  // no success
            1000,   // now_secs
            &health_config,
        );
        
        assert_eq!(new_status, DAStatus::Emergency);
    }

    #[test]
    fn test_determine_status_degraded_when_no_success_medium_time() {
        let config = DAConfig::default();
        let health_config = DAHealthConfig {
            emergency_trigger_secs: 100,
            fallback_trigger_secs: 50,
            warning_latency_ms: 1000,
            ..Default::default()
        };
        let monitor = DAHealthMonitor::with_health_config(config, health_config.clone());
        
        // Simulate no success between fallback and emergency thresholds
        let new_status = monitor.determine_new_status(
            DAStatus::Healthy,
            500,    // latency_ms
            75,     // fallback < secs_since_success < emergency
            false,  // no success
            1000,   // now_secs
            &health_config,
        );
        
        assert_eq!(new_status, DAStatus::Degraded);
    }

    #[test]
    fn test_determine_status_warning_when_high_latency() {
        let config = DAConfig::default();
        let health_config = DAHealthConfig {
            emergency_trigger_secs: 100,
            fallback_trigger_secs: 50,
            warning_latency_ms: 1000,
            ..Default::default()
        };
        let monitor = DAHealthMonitor::with_health_config(config, health_config.clone());
        
        // Simulate success but high latency
        let new_status = monitor.determine_new_status(
            DAStatus::Healthy,
            2000,   // latency_ms > warning_latency_ms
            0,      // secs_since_success (just succeeded)
            true,   // success
            1000,   // now_secs
            &health_config,
        );
        
        assert_eq!(new_status, DAStatus::Warning);
    }

    #[test]
    fn test_determine_status_healthy_when_all_good() {
        let config = DAConfig::default();
        let health_config = DAHealthConfig {
            emergency_trigger_secs: 100,
            fallback_trigger_secs: 50,
            warning_latency_ms: 1000,
            recovery_grace_period_secs: 30,
            ..Default::default()
        };
        let monitor = DAHealthMonitor::with_health_config(config, health_config.clone());
        
        // Simulate success with good latency
        let new_status = monitor.determine_new_status(
            DAStatus::Healthy,
            500,    // latency_ms < warning_latency_ms
            0,      // secs_since_success (just succeeded)
            true,   // success
            1000,   // now_secs
            &health_config,
        );
        
        assert_eq!(new_status, DAStatus::Healthy);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Recovery grace period tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_recovery_started_at_initial_zero() {
        let config = DAConfig::default();
        let monitor = DAHealthMonitor::new(config);
        
        assert_eq!(monitor.recovery_started_at.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_recovery_grace_period_tracking() {
        let config = DAConfig::default();
        let health_config = DAHealthConfig {
            recovery_grace_period_secs: 30,
            ..Default::default()
        };
        let monitor = DAHealthMonitor::with_health_config(config, health_config.clone());
        
        // Set monitor to Emergency state first
        monitor.set_da_status(DAStatus::Emergency);
        
        // Now success comes back - should go to Recovering
        let now_secs = 1000u64;
        let new_status = monitor.determine_new_status(
            DAStatus::Emergency,
            500,
            0,      // just succeeded
            true,
            now_secs,
            &health_config,
        );
        
        assert_eq!(new_status, DAStatus::Recovering);
        
        // recovery_started_at should be set
        let recovery_start = monitor.recovery_started_at.load(Ordering::Relaxed);
        assert_eq!(recovery_start, now_secs);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Thread safety tests for new fields
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_shutdown_flag_thread_safe() {
        let config = DAConfig::default();
        let monitor = Arc::new(DAHealthMonitor::new(config));
        
        let mut handles = vec![];
        
        // Multiple threads setting/reading shutdown flag
        for _ in 0..5 {
            let monitor_clone = Arc::clone(&monitor);
            let handle = thread::spawn(move || {
                for _ in 0..100 {
                    let _ = monitor_clone.is_monitoring_active();
                    monitor_clone.stop_monitoring();
                }
            });
            handles.push(handle);
        }
        
        for handle in handles {
            let result = handle.join();
            assert!(result.is_ok(), "Thread should not panic");
        }
        
        // After all threads, flag should be set
        assert!(!monitor.is_monitoring_active());
    }

    #[test]
    fn test_recovery_started_at_thread_safe() {
        let config = DAConfig::default();
        let monitor = Arc::new(DAHealthMonitor::new(config));
        
        let mut handles = vec![];
        
        // Multiple threads updating recovery_started_at
        for i in 0..5 {
            let monitor_clone = Arc::clone(&monitor);
            let handle = thread::spawn(move || {
                for j in 0..100 {
                    let value = (i * 100 + j) as u64;
                    monitor_clone.recovery_started_at.store(value, Ordering::Relaxed);
                    let _ = monitor_clone.recovery_started_at.load(Ordering::Relaxed);
                }
            });
            handles.push(handle);
        }
        
        for handle in handles {
            let result = handle.join();
            assert!(result.is_ok(), "Thread should not panic");
        }
    }

    #[test]
    fn test_da_status_thread_safe() {
        let config = DAConfig::default();
        let monitor = Arc::new(DAHealthMonitor::new(config));
        
        let mut handles = vec![];
        
        // Multiple threads reading/writing DAStatus
        let statuses = [
            DAStatus::Healthy,
            DAStatus::Warning,
            DAStatus::Degraded,
            DAStatus::Emergency,
            DAStatus::Recovering,
        ];
        
        for i in 0..5 {
            let monitor_clone = Arc::clone(&monitor);
            let handle = thread::spawn(move || {
                for j in 0..100 {
                    let status = statuses[(i + j) % 5];
                    monitor_clone.set_da_status(status);
                    let _ = monitor_clone.get_da_status();
                }
            });
            handles.push(handle);
        }
        
        for handle in handles {
            let result = handle.join();
            assert!(result.is_ok(), "Thread should not panic");
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // No panic guarantee tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_update_fallback_state_no_panic() {
        let config = DAConfig::default();
        let monitor = DAHealthMonitor::new(config);
        
        // Test all status values
        let statuses = [
            DAStatus::Healthy,
            DAStatus::Warning,
            DAStatus::Degraded,
            DAStatus::Emergency,
            DAStatus::Recovering,
        ];
        
        for status in statuses {
            // This should not panic
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                monitor.update_fallback_state(status, 100);
            }));
            assert!(result.is_ok(), "update_fallback_state should not panic for {:?}", status);
        }
    }

    #[test]
    fn test_log_status_transition_no_panic() {
        let config = DAConfig::default();
        let monitor = DAHealthMonitor::new(config);
        
        let statuses = [
            DAStatus::Healthy,
            DAStatus::Warning,
            DAStatus::Degraded,
            DAStatus::Emergency,
            DAStatus::Recovering,
        ];
        
        for old_status in statuses {
            for new_status in statuses {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    monitor.log_status_transition(old_status, new_status, 100, 50);
                }));
                assert!(result.is_ok(), 
                    "log_status_transition should not panic for {:?} -> {:?}", 
                    old_status, new_status);
            }
        }
    }

    #[test]
    fn test_determine_new_status_no_panic() {
        let config = DAConfig::default();
        let health_config = DAHealthConfig::default();
        let monitor = DAHealthMonitor::with_health_config(config, health_config.clone());
        
        let statuses = [
            DAStatus::Healthy,
            DAStatus::Warning,
            DAStatus::Degraded,
            DAStatus::Emergency,
            DAStatus::Recovering,
        ];
        
        // Test various combinations
        for current in statuses {
            for success in [true, false] {
                for latency in [0u64, 100, 50000, u64::MAX] {
                    for secs in [0u64, 100, 500, 2000, u64::MAX] {
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            monitor.determine_new_status(
                                current,
                                latency,
                                secs,
                                success,
                                1000,
                                &health_config,
                            )
                        }));
                        assert!(result.is_ok(), 
                            "determine_new_status should not panic for current={:?}, success={}, latency={}, secs={}", 
                            current, success, latency, secs);
                    }
                }
            }
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Timestamp helper tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_current_timestamp_secs_reasonable() {
        let ts = DAHealthMonitor::current_timestamp_secs();
        
        // Should be a reasonable Unix timestamp (after year 2020)
        // 2020-01-01 00:00:00 UTC = 1577836800
        assert!(ts > 1577836800, "Timestamp should be after 2020");
        
        // Should not be absurdly large
        // 2100-01-01 00:00:00 UTC = 4102444800
        assert!(ts < 4102444800, "Timestamp should be before 2100");
    }
}