use serde::Serialize;
use crate::FallbackHealthInfo;

// ════════════════════════════════════════════════════════════════════════════
// INGRESS HEALTH STRUCT
// ════════════════════════════════════════════════════════════════════════════

/// Health status ingress yang DA-aware.
///
/// Semua field merepresentasikan state real, bukan asumsi.
///
/// ## Field Groups
///
/// ### Core Health (existing)
/// - `da_connected`, `da_last_sequence`: DA layer connectivity
/// - `cached_nodes`, `cached_placements`, `cache_age_ms`: Cache state
/// - `coordinator_reachable`: Coordinator connectivity
/// - `healthy_nodes`, `total_nodes`: Node registry state
///
/// ### Fallback Status (14A.1A.62)
/// - `fallback_active`: Apakah fallback mode sedang aktif
/// - `fallback_status`: Detail lengkap status fallback (jika tersedia)
/// - `da_primary_healthy`: Kesehatan primary DA (Celestia)
/// - `da_secondary_healthy`: Kesehatan secondary DA (jika dikonfigurasi)
/// - `da_emergency_healthy`: Kesehatan emergency DA (jika dikonfigurasi)
///
/// ## JSON Serialization
///
/// Semua field diserialisasi dengan nama yang sama (snake_case).
/// Option<T> menjadi `null` jika None.
#[derive(Debug, Clone, Serialize)]
pub struct IngressHealth {
    // ────────────────────────────────────────────────────────────────────────
    // Core Health Fields (existing)
    // ────────────────────────────────────────────────────────────────────────

    /// Apakah DA layer terhubung.
    pub da_connected: bool,

    /// Sequence terakhir dari DA (0 jika tidak tersedia).
    pub da_last_sequence: u64,

    /// Jumlah node dalam cache.
    pub cached_nodes: usize,

    /// Jumlah placement dalam cache.
    pub cached_placements: usize,

    /// Umur cache dalam milliseconds.
    pub cache_age_ms: u64,

    /// Apakah coordinator dapat dijangkau.
    pub coordinator_reachable: bool,

    /// Jumlah node sehat (active).
    pub healthy_nodes: usize,

    /// Total node dalam registry.
    pub total_nodes: usize,

    // ────────────────────────────────────────────────────────────────────────
    // Fallback Status Fields (14A.1A.62)
    // ────────────────────────────────────────────────────────────────────────

    /// Apakah fallback mode sedang aktif.
    ///
    /// `true` jika sistem menggunakan fallback DA karena primary tidak tersedia.
    /// `false` jika sistem menggunakan primary DA (normal operation).
    pub fallback_active: bool,

    /// Detail lengkap status fallback.
    ///
    /// `Some(info)` jika data fallback tersedia dari DAHealthMonitor.
    /// `None` jika DAHealthMonitor tidak dikonfigurasi atau data tidak tersedia.
    pub fallback_status: Option<FallbackHealthInfo>,

    /// Kesehatan primary DA layer (Celestia).
    ///
    /// `true` jika primary DA responsif dan operasional.
    /// `false` jika primary DA tidak tersedia atau degraded.
    pub da_primary_healthy: bool,

    /// Kesehatan secondary DA layer (jika dikonfigurasi).
    ///
    /// `Some(true)` jika secondary DA sehat.
    /// `Some(false)` jika secondary DA tidak sehat.
    /// `None` jika secondary DA tidak dikonfigurasi.
    pub da_secondary_healthy: Option<bool>,

    /// Kesehatan emergency DA layer (jika dikonfigurasi).
    ///
    /// `Some(true)` jika emergency DA sehat.
    /// `Some(false)` jika emergency DA tidak sehat.
    /// `None` jika emergency DA tidak dikonfigurasi.
    pub da_emergency_healthy: Option<bool>,

    // ────────────────────────────────────────────────────────────────────────
    // Aggregate Status Fields (14A.1A.64)
    // ────────────────────────────────────────────────────────────────────────

    /// Status DA agregat.
    ///
    /// Merepresentasikan status DA secara keseluruhan:
    /// - `Some("healthy")` - primary DA operasional
    /// - `Some("degraded")` - menggunakan fallback
    /// - `Some("emergency")` - menggunakan emergency DA
    /// - `Some("recovering")` - primary sedang recovery
    /// - `Some("warning")` - primary ada tanda masalah
    /// - `None` - status tidak tersedia
    ///
    /// Nilai diambil langsung dari `fallback_status.status` jika tersedia.
    /// Tidak ada inferensi atau asumsi.
    pub da_status: Option<String>,

    /// Warning message jika kondisi DEGRADED terpenuhi.
    ///
    /// Hanya diisi jika DAN HANYA JIKA:
    /// - `fallback_active == true` DAN
    /// - Salah satu kondisi berikut:
    ///   a) fallback aktif > 10 menit (600 detik)
    ///   b) pending_reconcile > 1000
    ///
    /// `None` jika kondisi tidak terpenuhi atau data tidak tersedia.
    /// Field ini TIDAK pernah diisi dengan placeholder atau default.
    pub warning: Option<String>,
}

impl Default for IngressHealth {
    /// Default state untuk IngressHealth.
    ///
    /// ## Prinsip Default
    ///
    /// - Merepresentasikan state AMAN dan EKSPLISIT
    /// - Tidak mengasumsikan fallback aktif
    /// - Tidak mengasumsikan DA layer sehat tanpa verifikasi
    /// - Semua Option adalah None (data tidak tersedia)
    fn default() -> Self {
        Self {
            // Core health fields
            da_connected: false,
            da_last_sequence: 0,
            cached_nodes: 0,
            cached_placements: 0,
            cache_age_ms: u64::MAX, // Indicates cache never filled
            coordinator_reachable: false,
            healthy_nodes: 0,
            total_nodes: 0,
            // Fallback status fields (14A.1A.62)
            fallback_active: false,
            fallback_status: None,
            da_primary_healthy: false,
            da_secondary_healthy: None,
            da_emergency_healthy: None,
            // Aggregate status fields (14A.1A.64)
            da_status: None,
            warning: None,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// FALLBACK STATUS RESPONSE (14A.1A.65)
// ════════════════════════════════════════════════════════════════════════════

/// Response untuk endpoint GET /fallback/status.
///
/// Endpoint ini adalah SOURCE OF TRUTH untuk status fallback.
/// Semua data diambil dari sumber aktual, tidak ada fabrication.
///
/// ## Field Groups
///
/// ### Core Fallback Info
/// - `info`: FallbackHealthInfo lengkap dari DARouter
///
/// ### Detailed Metrics
/// - `time_since_last_primary_contact_secs`: Waktu sejak kontak primary terakhir
/// - `reconciliation_queue_depth`: Kedalaman queue reconciliation
/// - `events_processed`: Event yang diproses per source (jika tersedia)
///
/// ## JSON Serialization
///
/// Semua field diserialisasi dengan nama yang sama (snake_case).
/// Option<T> menjadi `null` jika None.
#[derive(Debug, Clone, Serialize)]
pub struct FallbackStatusResponse {
    /// FallbackHealthInfo lengkap.
    ///
    /// Berisi semua informasi fallback dari DAHealthMonitor.
    pub info: FallbackHealthInfo,

    /// Waktu sejak kontak primary terakhir dalam detik.
    ///
    /// Dihitung eksplisit dari `info.last_celestia_contact`:
    /// - Jika `last_celestia_contact` ada: `current_time - last_celestia_contact`
    /// - Jika tidak ada: `None`
    ///
    /// Tidak boleh overflow (menggunakan saturating arithmetic).
    /// Tidak boleh negative.
    pub time_since_last_primary_contact_secs: Option<u64>,

    /// Kedalaman queue reconciliation.
    ///
    /// Diambil langsung dari `info.pending_reconcile`.
    /// Angka aktual dari sistem, bukan estimasi.
    pub reconciliation_queue_depth: u64,

    /// Event yang diproses per source.
    ///
    /// Struktur:
    /// - `primary`: Event dari primary DA
    /// - `secondary`: Event dari secondary DA
    /// - `emergency`: Event dari emergency DA
    ///
    /// `None` jika data tidak tersedia dari DARouter.
    /// Field ini TIDAK di-fabricate atau di-hardcode.
    pub events_processed: Option<EventsProcessedBySource>,
}

/// Event yang diproses per DA source.
///
/// Semua field adalah jumlah event yang telah diproses
/// dari masing-masing DA source.
#[derive(Debug, Clone, Serialize)]
pub struct EventsProcessedBySource {
    /// Event dari primary DA (Celestia).
    pub primary: Option<u64>,
    /// Event dari secondary DA.
    pub secondary: Option<u64>,
    /// Event dari emergency DA.
    pub emergency: Option<u64>,
}

// ════════════════════════════════════════════════════════════════════════════
// READY STATUS (14A.1A.66)
// ════════════════════════════════════════════════════════════════════════════

/// Status readiness untuk endpoint /ready.
///
/// Membedakan tiga kondisi:
/// - `Ready`: Sistem siap menerima traffic (HTTP 200)
/// - `ReadyDegraded`: Sistem siap tapi dalam kondisi degraded (HTTP 200 + X-Warning)
/// - `NotReady`: Sistem tidak siap (HTTP 503)
///
/// ## Degraded vs NotReady
///
/// DEGRADED terjadi ketika:
/// - Sistem masih operasional via fallback DA
/// - Tapi ada kondisi warning (fallback > 10 menit atau pending_reconcile > 1000)
///
/// NOT READY terjadi ketika:
/// - Coordinator tidak reachable
/// - ATAU tidak ada DA source yang tersedia (primary/secondary/emergency)
#[derive(Debug, Clone, PartialEq)]
pub enum ReadyStatus {
    /// Sistem siap menerima traffic (normal operation).
    Ready,

    /// Sistem siap tapi dalam kondisi degraded.
    ///
    /// String berisi warning message yang akan diset ke X-Warning header.
    ReadyDegraded(String),

    /// Sistem tidak siap menerima traffic.
    ///
    /// String berisi alasan tidak ready (untuk logging).
    NotReady(String),
}

/// Threshold constants untuk DEGRADED detection (14A.1A.66).
///
/// Nilai diambil dari spesifikasi:
/// - DEGRADED jika fallback aktif > 10 menit (600 detik)
/// - DEGRADED jika pending_reconcile > 1000
pub mod ready_thresholds {
    /// Threshold durasi fallback aktif dalam detik.
    /// Jika fallback aktif lebih lama dari ini → DEGRADED.
    pub const FALLBACK_DURATION_THRESHOLD_SECS: u64 = 600;

    /// Threshold jumlah pending reconciliation.
    /// Jika pending_reconcile lebih dari ini → DEGRADED.
    pub const PENDING_RECONCILE_THRESHOLD: u64 = 1000;
}