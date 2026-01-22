//! # Storage Events Module
//!
//! Modul ini menyediakan mekanisme emisi event storage untuk:
//! - Logging
//! - Monitoring
//! - Metrics
//! - Debugging
//! - Audit trail
//!
//! ## Prinsip Kunci
//!
//! - Event HANYA untuk observability
//! - Event TIDAK mengubah perilaku sistem
//! - Event TIDAK authoritative
//! - Event TIDAK mempengaruhi correctness
//!
//! ## Event vs Command vs State
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │  EVENT ≠ COMMAND                                                │
//! │  EVENT ≠ STATE                                                  │
//! │  EVENT = Passive observation of what happened                   │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Invariant
//!
//! - Event listener TIDAK BOLEH mengubah state storage
//! - Event listener TIDAK BOLEH panic
//! - Event listener TIDAK BOLEH block

use std::fmt::{self, Display};
use std::sync::Arc;

use tracing::{debug, info, warn};

// ════════════════════════════════════════════════════════════════════════════
// DA SOURCE TYPE
// ════════════════════════════════════════════════════════════════════════════

/// Sumber Data Availability untuk fallback cache.
///
/// Merepresentasikan dari mana data blob berasal saat
/// fallback mode aktif.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DASourceType {
    /// Data berasal dari Celestia.
    Celestia,
    /// Data berasal dari Avail.
    Avail,
    /// Data berasal dari EigenDA.
    EigenDA,
    /// Data berasal dari local storage sebagai fallback terakhir.
    LocalFallback,
}

impl Display for DASourceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DASourceType::Celestia => write!(f, "Celestia"),
            DASourceType::Avail => write!(f, "Avail"),
            DASourceType::EigenDA => write!(f, "EigenDA"),
            DASourceType::LocalFallback => write!(f, "LocalFallback"),
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// EVICTION REASON
// ════════════════════════════════════════════════════════════════════════════

/// Alasan eviction dari fallback cache.
///
/// Menjelaskan mengapa suatu entry di-evict dari cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvictionReason {
    /// Cache penuh, entry tertua di-evict (LRU policy).
    CacheFull,
    /// Entry sudah expired berdasarkan TTL.
    Expired,
    /// Entry di-evict karena sudah berhasil di-reconcile ke DA layer.
    Reconciled,
    /// Eviction manual oleh operator atau sistem.
    Manual {
        /// Deskripsi alasan manual eviction.
        description: String,
    },
    /// Eviction karena memory pressure.
    MemoryPressure {
        /// Persentase memory usage saat eviction.
        memory_usage_percent: u8,
    },
}

impl Display for EvictionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvictionReason::CacheFull => write!(f, "CacheFull"),
            EvictionReason::Expired => write!(f, "Expired"),
            EvictionReason::Reconciled => write!(f, "Reconciled"),
            EvictionReason::Manual { description } => {
                write!(f, "Manual({})", description)
            }
            EvictionReason::MemoryPressure { memory_usage_percent } => {
                write!(f, "MemoryPressure({}%)", memory_usage_percent)
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// STORAGE EVENT ENUM
// ════════════════════════════════════════════════════════════════════════════

/// Event yang terjadi pada storage.
///
/// Event ini bersifat observability saja, tidak mempengaruhi
/// perilaku sistem atau state storage.
///
/// # Variants
///
/// ## Chunk Events
/// - `ChunkStored`: Chunk berhasil disimpan
/// - `ChunkDeleted`: Chunk dihapus
/// - `VerificationPassed`: Chunk lolos verifikasi
/// - `VerificationFailed`: Chunk gagal verifikasi
/// - `RecoveryStarted`: Recovery chunk dimulai
/// - `RecoveryCompleted`: Recovery chunk selesai
/// - `GCCompleted`: Garbage collection selesai
///
/// ## Fallback Cache Events
/// - `FallbackCacheHit`: Cache hit saat fallback aktif
/// - `FallbackCacheMiss`: Cache miss saat fallback aktif
/// - `FallbackCacheStore`: Blob disimpan ke fallback cache
/// - `FallbackCacheEviction`: Entry di-evict dari cache
///
/// ## Fallback Reconcile Events
/// - `FallbackReconcileStart`: Batch reconcile dimulai
/// - `FallbackReconcileComplete`: Sequence berhasil di-reconcile
/// - `FallbackReconcileFailed`: Sequence gagal di-reconcile
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageEvent {
    // ════════════════════════════════════════════════════════════════════════
    // CHUNK EVENTS
    // ════════════════════════════════════════════════════════════════════════

    /// Chunk berhasil disimpan.
    ChunkStored {
        /// Hash chunk.
        hash: String,
        /// Ukuran chunk dalam bytes.
        size: u64,
        /// Durasi penyimpanan dalam milliseconds.
        duration_ms: u64,
    },

    /// Chunk dihapus.
    ChunkDeleted {
        /// Hash chunk.
        hash: String,
        /// Alasan penghapusan.
        reason: String,
    },

    /// Chunk lolos verifikasi.
    VerificationPassed {
        /// Hash chunk.
        hash: String,
    },

    /// Chunk gagal verifikasi.
    VerificationFailed {
        /// Hash chunk.
        hash: String,
        /// Alasan kegagalan.
        reason: String,
    },

    /// Recovery chunk dimulai.
    RecoveryStarted {
        /// Hash chunk.
        hash: String,
        /// Node sumber data.
        source_node: String,
    },

    /// Recovery chunk selesai.
    RecoveryCompleted {
        /// Hash chunk.
        hash: String,
    },

    /// Garbage collection selesai.
    GCCompleted {
        /// Bytes yang berhasil di-reclaim.
        reclaimed_bytes: u64,
        /// Jumlah chunk yang dihapus.
        chunk_count: usize,
    },

    // ════════════════════════════════════════════════════════════════════════
    // FALLBACK CACHE EVENTS
    // ════════════════════════════════════════════════════════════════════════

    /// Fallback cache hit.
    ///
    /// Di-emit HANYA saat:
    /// - Fallback mode aktif
    /// - Blob ditemukan di cache
    ///
    /// TIDAK di-emit saat fallback non-aktif.
    FallbackCacheHit {
        /// Sequence number blob yang di-hit.
        sequence: u64,
        /// Sumber DA dari mana blob awalnya berasal.
        source: DASourceType,
    },

    /// Fallback cache miss.
    ///
    /// Di-emit saat:
    /// - Fallback mode aktif
    /// - Blob TIDAK ditemukan di cache
    ///
    /// TIDAK di-emit saat fallback non-aktif.
    FallbackCacheMiss {
        /// Sequence number blob yang tidak ditemukan.
        sequence: u64,
    },

    /// Blob disimpan ke fallback cache.
    ///
    /// Di-emit saat blob berhasil disimpan ke FallbackCache.
    FallbackCacheStore {
        /// Sequence number blob yang disimpan.
        sequence: u64,
        /// Ukuran blob dalam bytes.
        bytes: u64,
    },

    /// Entry di-evict dari fallback cache.
    ///
    /// Di-emit saat eviction benar-benar terjadi,
    /// BUKAN saat eviction direncanakan.
    FallbackCacheEviction {
        /// Sequence number blob yang di-evict.
        sequence: u64,
        /// Alasan eviction.
        reason: EvictionReason,
    },

    // ════════════════════════════════════════════════════════════════════════
    // FALLBACK RECONCILE EVENTS
    // ════════════════════════════════════════════════════════════════════════

    /// Batch reconcile dimulai.
    ///
    /// Di-emit SEKALI per batch reconcile operation.
    /// TIDAK di-emit per-item.
    FallbackReconcileStart {
        /// Jumlah blob yang akan di-reconcile dalam batch ini.
        count: usize,
    },

    /// Sequence berhasil di-reconcile.
    ///
    /// Di-emit per sequence yang sukses di-reconcile ke DA layer.
    FallbackReconcileComplete {
        /// Sequence number yang berhasil di-reconcile.
        sequence: u64,
    },

    /// Sequence gagal di-reconcile.
    ///
    /// Di-emit per sequence yang gagal di-reconcile.
    FallbackReconcileFailed {
        /// Sequence number yang gagal di-reconcile.
        sequence: u64,
        /// Pesan error yang informatif.
        /// TIDAK BOLEH kosong atau generic.
        error: String,
    },
}

impl StorageEvent {
    /// Get event name.
    pub fn name(&self) -> &'static str {
        match self {
            StorageEvent::ChunkStored { .. } => "ChunkStored",
            StorageEvent::ChunkDeleted { .. } => "ChunkDeleted",
            StorageEvent::VerificationPassed { .. } => "VerificationPassed",
            StorageEvent::VerificationFailed { .. } => "VerificationFailed",
            StorageEvent::RecoveryStarted { .. } => "RecoveryStarted",
            StorageEvent::RecoveryCompleted { .. } => "RecoveryCompleted",
            StorageEvent::GCCompleted { .. } => "GCCompleted",
            StorageEvent::FallbackCacheHit { .. } => "FallbackCacheHit",
            StorageEvent::FallbackCacheMiss { .. } => "FallbackCacheMiss",
            StorageEvent::FallbackCacheStore { .. } => "FallbackCacheStore",
            StorageEvent::FallbackCacheEviction { .. } => "FallbackCacheEviction",
            StorageEvent::FallbackReconcileStart { .. } => "FallbackReconcileStart",
            StorageEvent::FallbackReconcileComplete { .. } => "FallbackReconcileComplete",
            StorageEvent::FallbackReconcileFailed { .. } => "FallbackReconcileFailed",
        }
    }

    /// Check if event is error-related.
    pub fn is_error(&self) -> bool {
        matches!(
            self,
            StorageEvent::VerificationFailed { .. } | StorageEvent::FallbackReconcileFailed { .. }
        )
    }

    /// Get chunk hash if applicable.
    ///
    /// Returns `None` for events that don't have a chunk hash
    /// (e.g., GCCompleted, Fallback events yang menggunakan sequence).
    pub fn chunk_hash(&self) -> Option<&str> {
        match self {
            StorageEvent::ChunkStored { hash, .. } => Some(hash),
            StorageEvent::ChunkDeleted { hash, .. } => Some(hash),
            StorageEvent::VerificationPassed { hash } => Some(hash),
            StorageEvent::VerificationFailed { hash, .. } => Some(hash),
            StorageEvent::RecoveryStarted { hash, .. } => Some(hash),
            StorageEvent::RecoveryCompleted { hash } => Some(hash),
            StorageEvent::GCCompleted { .. } => None,
            // Fallback events menggunakan sequence, bukan hash
            StorageEvent::FallbackCacheHit { .. } => None,
            StorageEvent::FallbackCacheMiss { .. } => None,
            StorageEvent::FallbackCacheStore { .. } => None,
            StorageEvent::FallbackCacheEviction { .. } => None,
            StorageEvent::FallbackReconcileStart { .. } => None,
            StorageEvent::FallbackReconcileComplete { .. } => None,
            StorageEvent::FallbackReconcileFailed { .. } => None,
        }
    }

    /// Get sequence number if applicable.
    ///
    /// Returns sequence number untuk fallback-related events.
    /// Returns `None` untuk chunk events dan GC.
    pub fn sequence(&self) -> Option<u64> {
        match self {
            StorageEvent::FallbackCacheHit { sequence, .. } => Some(*sequence),
            StorageEvent::FallbackCacheMiss { sequence } => Some(*sequence),
            StorageEvent::FallbackCacheStore { sequence, .. } => Some(*sequence),
            StorageEvent::FallbackCacheEviction { sequence, .. } => Some(*sequence),
            StorageEvent::FallbackReconcileComplete { sequence } => Some(*sequence),
            StorageEvent::FallbackReconcileFailed { sequence, .. } => Some(*sequence),
            // Events tanpa sequence
            StorageEvent::ChunkStored { .. } => None,
            StorageEvent::ChunkDeleted { .. } => None,
            StorageEvent::VerificationPassed { .. } => None,
            StorageEvent::VerificationFailed { .. } => None,
            StorageEvent::RecoveryStarted { .. } => None,
            StorageEvent::RecoveryCompleted { .. } => None,
            StorageEvent::GCCompleted { .. } => None,
            StorageEvent::FallbackReconcileStart { .. } => None,
        }
    }

    /// Check if event is fallback-related.
    pub fn is_fallback_event(&self) -> bool {
        matches!(
            self,
            StorageEvent::FallbackCacheHit { .. }
                | StorageEvent::FallbackCacheMiss { .. }
                | StorageEvent::FallbackCacheStore { .. }
                | StorageEvent::FallbackCacheEviction { .. }
                | StorageEvent::FallbackReconcileStart { .. }
                | StorageEvent::FallbackReconcileComplete { .. }
                | StorageEvent::FallbackReconcileFailed { .. }
        )
    }
}

impl Display for StorageEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageEvent::ChunkStored { hash, size, duration_ms } => {
                write!(
                    f,
                    "ChunkStored: {} ({} bytes, {}ms)",
                    hash, size, duration_ms
                )
            }
            StorageEvent::ChunkDeleted { hash, reason } => {
                write!(f, "ChunkDeleted: {} (reason: {})", hash, reason)
            }
            StorageEvent::VerificationPassed { hash } => {
                write!(f, "VerificationPassed: {}", hash)
            }
            StorageEvent::VerificationFailed { hash, reason } => {
                write!(f, "VerificationFailed: {} (reason: {})", hash, reason)
            }
            StorageEvent::RecoveryStarted { hash, source_node } => {
                write!(f, "RecoveryStarted: {} from {}", hash, source_node)
            }
            StorageEvent::RecoveryCompleted { hash } => {
                write!(f, "RecoveryCompleted: {}", hash)
            }
            StorageEvent::GCCompleted { reclaimed_bytes, chunk_count } => {
                write!(
                    f,
                    "GCCompleted: {} chunks, {} bytes reclaimed",
                    chunk_count, reclaimed_bytes
                )
            }
            // Fallback cache events
            StorageEvent::FallbackCacheHit { sequence, source } => {
                write!(
                    f,
                    "FallbackCacheHit: seq={} source={}",
                    sequence, source
                )
            }
            StorageEvent::FallbackCacheMiss { sequence } => {
                write!(f, "FallbackCacheMiss: seq={}", sequence)
            }
            StorageEvent::FallbackCacheStore { sequence, bytes } => {
                write!(
                    f,
                    "FallbackCacheStore: seq={} ({} bytes)",
                    sequence, bytes
                )
            }
            StorageEvent::FallbackCacheEviction { sequence, reason } => {
                write!(
                    f,
                    "FallbackCacheEviction: seq={} reason={}",
                    sequence, reason
                )
            }
            // Fallback reconcile events
            StorageEvent::FallbackReconcileStart { count } => {
                write!(f, "FallbackReconcileStart: {} blobs", count)
            }
            StorageEvent::FallbackReconcileComplete { sequence } => {
                write!(f, "FallbackReconcileComplete: seq={}", sequence)
            }
            StorageEvent::FallbackReconcileFailed { sequence, error } => {
                write!(
                    f,
                    "FallbackReconcileFailed: seq={} error={}",
                    sequence, error
                )
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// STORAGE EVENT LISTENER TRAIT
// ════════════════════════════════════════════════════════════════════════════

/// Trait untuk menerima storage events.
///
/// # Aturan
///
/// - Sink only, tidak return value
/// - Tidak async
/// - TIDAK BOLEH panic
/// - TIDAK BOLEH mengubah state storage
///
/// # Example
///
/// ```rust,ignore
/// struct MyListener;
///
/// impl StorageEventListener for MyListener {
///     fn on_event(&self, event: StorageEvent) {
///         println!("Event: {}", event);
///     }
/// }
/// ```
pub trait StorageEventListener: Send + Sync {
    /// Handle storage event.
    ///
    /// # Arguments
    ///
    /// * `event` - Storage event yang terjadi
    ///
    /// # Note
    ///
    /// Method ini TIDAK BOLEH panic dan TIDAK BOLEH block.
    fn on_event(&self, event: StorageEvent);
}

// ════════════════════════════════════════════════════════════════════════════
// LOGGING LISTENER
// ════════════════════════════════════════════════════════════════════════════

/// Logging listener yang menggunakan tracing.
///
/// Output human-readable log untuk setiap event.
/// Satu event = satu log entry.
#[derive(Debug, Clone, Default)]
pub struct LoggingListener {
    /// Prefix untuk log message.
    prefix: String,
}

impl LoggingListener {
    /// Membuat LoggingListener baru tanpa prefix.
    pub fn new() -> Self {
        Self::default()
    }

    /// Membuat LoggingListener dengan prefix.
    pub fn with_prefix(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
        }
    }
}

impl StorageEventListener for LoggingListener {
    fn on_event(&self, event: StorageEvent) {
        let prefix = if self.prefix.is_empty() {
            String::new()
        } else {
            format!("[{}] ", self.prefix)
        };

        match &event {
            StorageEvent::ChunkStored { hash, size, duration_ms } => {
                info!(
                    "{}ChunkStored: hash={}, size={}, duration_ms={}",
                    prefix, hash, size, duration_ms
                );
            }
            StorageEvent::ChunkDeleted { hash, reason } => {
                info!("{}ChunkDeleted: hash={}, reason={}", prefix, hash, reason);
            }
            StorageEvent::VerificationPassed { hash } => {
                debug!("{}VerificationPassed: hash={}", prefix, hash);
            }
            StorageEvent::VerificationFailed { hash, reason } => {
                warn!(
                    "{}VerificationFailed: hash={}, reason={}",
                    prefix, hash, reason
                );
            }
            StorageEvent::RecoveryStarted { hash, source_node } => {
                info!(
                    "{}RecoveryStarted: hash={}, source={}",
                    prefix, hash, source_node
                );
            }
            StorageEvent::RecoveryCompleted { hash } => {
                info!("{}RecoveryCompleted: hash={}", prefix, hash);
            }
            StorageEvent::GCCompleted { reclaimed_bytes, chunk_count } => {
                info!(
                    "{}GCCompleted: chunks={}, reclaimed_bytes={}",
                    prefix, chunk_count, reclaimed_bytes
                );
            }
            // Fallback cache events
            StorageEvent::FallbackCacheHit { sequence, source } => {
                debug!(
                    "{}FallbackCacheHit: seq={}, source={}",
                    prefix, sequence, source
                );
            }
            StorageEvent::FallbackCacheMiss { sequence } => {
                debug!("{}FallbackCacheMiss: seq={}", prefix, sequence);
            }
            StorageEvent::FallbackCacheStore { sequence, bytes } => {
                debug!(
                    "{}FallbackCacheStore: seq={}, bytes={}",
                    prefix, sequence, bytes
                );
            }
            StorageEvent::FallbackCacheEviction { sequence, reason } => {
                info!(
                    "{}FallbackCacheEviction: seq={}, reason={}",
                    prefix, sequence, reason
                );
            }
            // Fallback reconcile events
            StorageEvent::FallbackReconcileStart { count } => {
                info!("{}FallbackReconcileStart: count={}", prefix, count);
            }
            StorageEvent::FallbackReconcileComplete { sequence } => {
                info!("{}FallbackReconcileComplete: seq={}", prefix, sequence);
            }
            StorageEvent::FallbackReconcileFailed { sequence, error } => {
                warn!(
                    "{}FallbackReconcileFailed: seq={}, error={}",
                    prefix, sequence, error
                );
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// NO-OP LISTENER
// ════════════════════════════════════════════════════════════════════════════

/// No-op listener yang tidak melakukan apa-apa.
///
/// Berguna untuk testing atau ketika event handling tidak diperlukan.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoOpListener;

impl NoOpListener {
    /// Membuat NoOpListener baru.
    pub fn new() -> Self {
        Self
    }
}

impl StorageEventListener for NoOpListener {
    fn on_event(&self, _event: StorageEvent) {
        // Intentionally empty
    }
}

// ════════════════════════════════════════════════════════════════════════════
// COMPOSITE LISTENER
// ════════════════════════════════════════════════════════════════════════════

/// Composite listener yang mengirim event ke multiple listeners.
pub struct CompositeListener {
    listeners: Vec<Arc<dyn StorageEventListener>>,
}

impl CompositeListener {
    /// Membuat CompositeListener baru.
    pub fn new() -> Self {
        Self {
            listeners: Vec::new(),
        }
    }

    /// Tambah listener.
    pub fn add_listener(&mut self, listener: Arc<dyn StorageEventListener>) {
        self.listeners.push(listener);
    }

    /// Get jumlah listeners.
    pub fn listener_count(&self) -> usize {
        self.listeners.len()
    }
}

impl Default for CompositeListener {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageEventListener for CompositeListener {
    fn on_event(&self, event: StorageEvent) {
        for listener in &self.listeners {
            listener.on_event(event.clone());
        }
    }
}

impl std::fmt::Debug for CompositeListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompositeListener")
            .field("listener_count", &self.listeners.len())
            .finish()
    }
}

// ════════════════════════════════════════════════════════════════════════════
// EVENT EMITTER
// ════════════════════════════════════════════════════════════════════════════

/// Event emitter untuk mengirim events ke listeners.
pub struct EventEmitter {
    listener: Arc<dyn StorageEventListener>,
}

impl EventEmitter {
    /// Membuat EventEmitter baru dengan listener.
    pub fn new(listener: Arc<dyn StorageEventListener>) -> Self {
        Self { listener }
    }

    /// Membuat EventEmitter dengan NoOpListener.
    pub fn noop() -> Self {
        Self {
            listener: Arc::new(NoOpListener),
        }
    }

    /// Emit event.
    pub fn emit(&self, event: StorageEvent) {
        self.listener.on_event(event);
    }

    // ════════════════════════════════════════════════════════════════════════
    // CHUNK EVENT EMITTERS
    // ════════════════════════════════════════════════════════════════════════

    /// Emit ChunkStored event.
    pub fn chunk_stored(&self, hash: String, size: u64, duration_ms: u64) {
        self.emit(StorageEvent::ChunkStored {
            hash,
            size,
            duration_ms,
        });
    }

    /// Emit ChunkDeleted event.
    pub fn chunk_deleted(&self, hash: String, reason: String) {
        self.emit(StorageEvent::ChunkDeleted { hash, reason });
    }

    /// Emit VerificationPassed event.
    pub fn verification_passed(&self, hash: String) {
        self.emit(StorageEvent::VerificationPassed { hash });
    }

    /// Emit VerificationFailed event.
    pub fn verification_failed(&self, hash: String, reason: String) {
        self.emit(StorageEvent::VerificationFailed { hash, reason });
    }

    /// Emit RecoveryStarted event.
    pub fn recovery_started(&self, hash: String, source_node: String) {
        self.emit(StorageEvent::RecoveryStarted { hash, source_node });
    }

    /// Emit RecoveryCompleted event.
    pub fn recovery_completed(&self, hash: String) {
        self.emit(StorageEvent::RecoveryCompleted { hash });
    }

    /// Emit GCCompleted event.
    pub fn gc_completed(&self, reclaimed_bytes: u64, chunk_count: usize) {
        self.emit(StorageEvent::GCCompleted {
            reclaimed_bytes,
            chunk_count,
        });
    }

    // ════════════════════════════════════════════════════════════════════════
    // FALLBACK CACHE EVENT EMITTERS
    // ════════════════════════════════════════════════════════════════════════

    /// Emit FallbackCacheHit event.
    ///
    /// HANYA dipanggil saat:
    /// - Fallback mode aktif
    /// - Cache HIT untuk sequence tersebut
    ///
    /// # Arguments
    ///
    /// * `sequence` - Sequence number blob yang di-hit
    /// * `source` - Sumber DA dari mana blob awalnya berasal
    pub fn fallback_cache_hit(&self, sequence: u64, source: DASourceType) {
        self.emit(StorageEvent::FallbackCacheHit { sequence, source });
    }

    /// Emit FallbackCacheMiss event.
    ///
    /// HANYA dipanggil saat:
    /// - Fallback mode aktif
    /// - Cache MISS untuk sequence tersebut
    ///
    /// # Arguments
    ///
    /// * `sequence` - Sequence number blob yang tidak ditemukan
    pub fn fallback_cache_miss(&self, sequence: u64) {
        self.emit(StorageEvent::FallbackCacheMiss { sequence });
    }

    /// Emit FallbackCacheStore event.
    ///
    /// Dipanggil saat blob berhasil disimpan ke FallbackCache.
    ///
    /// # Arguments
    ///
    /// * `sequence` - Sequence number blob yang disimpan
    /// * `bytes` - Ukuran blob dalam bytes (HARUS ukuran aktual)
    pub fn fallback_cache_store(&self, sequence: u64, bytes: u64) {
        self.emit(StorageEvent::FallbackCacheStore { sequence, bytes });
    }

    /// Emit FallbackCacheEviction event.
    ///
    /// Dipanggil saat eviction BENAR-BENAR terjadi.
    ///
    /// # Arguments
    ///
    /// * `sequence` - Sequence number blob yang di-evict
    /// * `reason` - Alasan eviction (HARUS sesuai kebijakan eviction)
    pub fn fallback_cache_eviction(&self, sequence: u64, reason: EvictionReason) {
        self.emit(StorageEvent::FallbackCacheEviction { sequence, reason });
    }

    // ════════════════════════════════════════════════════════════════════════
    // FALLBACK RECONCILE EVENT EMITTERS
    // ════════════════════════════════════════════════════════════════════════

    /// Emit FallbackReconcileStart event.
    ///
    /// HANYA dipanggil SEKALI per batch reconcile.
    ///
    /// # Arguments
    ///
    /// * `count` - Jumlah blob yang akan di-reconcile dalam batch
    pub fn fallback_reconcile_start(&self, count: usize) {
        self.emit(StorageEvent::FallbackReconcileStart { count });
    }

    /// Emit FallbackReconcileComplete event.
    ///
    /// Dipanggil per sequence yang sukses di-reconcile.
    ///
    /// # Arguments
    ///
    /// * `sequence` - Sequence number yang berhasil di-reconcile
    pub fn fallback_reconcile_complete(&self, sequence: u64) {
        self.emit(StorageEvent::FallbackReconcileComplete { sequence });
    }

    /// Emit FallbackReconcileFailed event.
    ///
    /// Dipanggil per sequence yang gagal di-reconcile.
    ///
    /// # Arguments
    ///
    /// * `sequence` - Sequence number yang gagal
    /// * `error` - Pesan error (TIDAK BOLEH kosong)
    ///
    /// # Panics
    ///
    /// Tidak panic. Jika error kosong, akan diisi dengan default message.
    pub fn fallback_reconcile_failed(&self, sequence: u64, error: String) {
        // Pastikan error tidak kosong
        let error = if error.is_empty() {
            "Unknown reconcile error".to_string()
        } else {
            error
        };
        self.emit(StorageEvent::FallbackReconcileFailed { sequence, error });
    }
}

impl std::fmt::Debug for EventEmitter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventEmitter").finish()
    }
}

impl Default for EventEmitter {
    fn default() -> Self {
        Self::noop()
    }
}

// ════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // ════════════════════════════════════════════════════════════════════════
    // DA SOURCE TYPE TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_da_source_type_display() {
        assert_eq!(format!("{}", DASourceType::Celestia), "Celestia");
        assert_eq!(format!("{}", DASourceType::Avail), "Avail");
        assert_eq!(format!("{}", DASourceType::EigenDA), "EigenDA");
        assert_eq!(format!("{}", DASourceType::LocalFallback), "LocalFallback");
    }

    #[test]
    fn test_da_source_type_equality() {
        assert_eq!(DASourceType::Celestia, DASourceType::Celestia);
        assert_ne!(DASourceType::Celestia, DASourceType::Avail);
    }

    #[test]
    fn test_da_source_type_clone() {
        let source = DASourceType::EigenDA;
        let cloned = source;
        assert_eq!(source, cloned);
    }

    // ════════════════════════════════════════════════════════════════════════
    // EVICTION REASON TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_eviction_reason_display() {
        assert_eq!(format!("{}", EvictionReason::CacheFull), "CacheFull");
        assert_eq!(format!("{}", EvictionReason::Expired), "Expired");
        assert_eq!(format!("{}", EvictionReason::Reconciled), "Reconciled");
        assert_eq!(
            format!("{}", EvictionReason::Manual {
                description: "admin request".to_string()
            }),
            "Manual(admin request)"
        );
        assert_eq!(
            format!("{}", EvictionReason::MemoryPressure {
                memory_usage_percent: 95
            }),
            "MemoryPressure(95%)"
        );
    }

    #[test]
    fn test_eviction_reason_equality() {
        assert_eq!(EvictionReason::CacheFull, EvictionReason::CacheFull);
        assert_ne!(EvictionReason::CacheFull, EvictionReason::Expired);

        let manual1 = EvictionReason::Manual {
            description: "test".to_string(),
        };
        let manual2 = EvictionReason::Manual {
            description: "test".to_string(),
        };
        let manual3 = EvictionReason::Manual {
            description: "different".to_string(),
        };
        assert_eq!(manual1, manual2);
        assert_ne!(manual1, manual3);
    }

    // ════════════════════════════════════════════════════════════════════════
    // CHUNK EVENT CREATION TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_chunk_stored_event() {
        let event = StorageEvent::ChunkStored {
            hash: "abc123".to_string(),
            size: 1024,
            duration_ms: 50,
        };

        assert_eq!(event.name(), "ChunkStored");
        assert_eq!(event.chunk_hash(), Some("abc123"));
        assert!(!event.is_error());
        assert!(!event.is_fallback_event());
        assert_eq!(event.sequence(), None);

        let display = format!("{}", event);
        assert!(display.contains("abc123"));
        assert!(display.contains("1024"));
    }

    #[test]
    fn test_chunk_deleted_event() {
        let event = StorageEvent::ChunkDeleted {
            hash: "def456".to_string(),
            reason: "expired".to_string(),
        };

        assert_eq!(event.name(), "ChunkDeleted");
        assert_eq!(event.chunk_hash(), Some("def456"));
        assert!(!event.is_error());

        let display = format!("{}", event);
        assert!(display.contains("def456"));
        assert!(display.contains("expired"));
    }

    #[test]
    fn test_verification_passed_event() {
        let event = StorageEvent::VerificationPassed {
            hash: "hash123".to_string(),
        };

        assert_eq!(event.name(), "VerificationPassed");
        assert_eq!(event.chunk_hash(), Some("hash123"));
        assert!(!event.is_error());
    }

    #[test]
    fn test_verification_failed_event() {
        let event = StorageEvent::VerificationFailed {
            hash: "badhash".to_string(),
            reason: "commitment mismatch".to_string(),
        };

        assert_eq!(event.name(), "VerificationFailed");
        assert_eq!(event.chunk_hash(), Some("badhash"));
        assert!(event.is_error()); // This is an error event

        let display = format!("{}", event);
        assert!(display.contains("badhash"));
        assert!(display.contains("commitment mismatch"));
    }

    #[test]
    fn test_recovery_started_event() {
        let event = StorageEvent::RecoveryStarted {
            hash: "recoverme".to_string(),
            source_node: "peer-1".to_string(),
        };

        assert_eq!(event.name(), "RecoveryStarted");
        assert_eq!(event.chunk_hash(), Some("recoverme"));

        let display = format!("{}", event);
        assert!(display.contains("peer-1"));
    }

    #[test]
    fn test_recovery_completed_event() {
        let event = StorageEvent::RecoveryCompleted {
            hash: "recovered".to_string(),
        };

        assert_eq!(event.name(), "RecoveryCompleted");
        assert_eq!(event.chunk_hash(), Some("recovered"));
    }

    #[test]
    fn test_gc_completed_event() {
        let event = StorageEvent::GCCompleted {
            reclaimed_bytes: 1048576,
            chunk_count: 10,
        };

        assert_eq!(event.name(), "GCCompleted");
        assert_eq!(event.chunk_hash(), None); // GC has no single chunk

        let display = format!("{}", event);
        assert!(display.contains("10 chunks"));
        assert!(display.contains("1048576"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // FALLBACK CACHE EVENT TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_fallback_cache_hit_event() {
        let event = StorageEvent::FallbackCacheHit {
            sequence: 12345,
            source: DASourceType::Celestia,
        };

        assert_eq!(event.name(), "FallbackCacheHit");
        assert_eq!(event.chunk_hash(), None);
        assert_eq!(event.sequence(), Some(12345));
        assert!(event.is_fallback_event());
        assert!(!event.is_error());

        let display = format!("{}", event);
        assert!(display.contains("12345"));
        assert!(display.contains("Celestia"));
    }

    #[test]
    fn test_fallback_cache_miss_event() {
        let event = StorageEvent::FallbackCacheMiss { sequence: 67890 };

        assert_eq!(event.name(), "FallbackCacheMiss");
        assert_eq!(event.chunk_hash(), None);
        assert_eq!(event.sequence(), Some(67890));
        assert!(event.is_fallback_event());
        assert!(!event.is_error());

        let display = format!("{}", event);
        assert!(display.contains("67890"));
    }

    #[test]
    fn test_fallback_cache_store_event() {
        let event = StorageEvent::FallbackCacheStore {
            sequence: 11111,
            bytes: 4096,
        };

        assert_eq!(event.name(), "FallbackCacheStore");
        assert_eq!(event.sequence(), Some(11111));
        assert!(event.is_fallback_event());

        let display = format!("{}", event);
        assert!(display.contains("11111"));
        assert!(display.contains("4096"));
    }

    #[test]
    fn test_fallback_cache_eviction_event() {
        let event = StorageEvent::FallbackCacheEviction {
            sequence: 22222,
            reason: EvictionReason::CacheFull,
        };

        assert_eq!(event.name(), "FallbackCacheEviction");
        assert_eq!(event.sequence(), Some(22222));
        assert!(event.is_fallback_event());

        let display = format!("{}", event);
        assert!(display.contains("22222"));
        assert!(display.contains("CacheFull"));
    }

    #[test]
    fn test_fallback_cache_eviction_with_memory_pressure() {
        let event = StorageEvent::FallbackCacheEviction {
            sequence: 33333,
            reason: EvictionReason::MemoryPressure {
                memory_usage_percent: 92,
            },
        };

        let display = format!("{}", event);
        assert!(display.contains("33333"));
        assert!(display.contains("MemoryPressure(92%)"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // FALLBACK RECONCILE EVENT TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_fallback_reconcile_start_event() {
        let event = StorageEvent::FallbackReconcileStart { count: 50 };

        assert_eq!(event.name(), "FallbackReconcileStart");
        assert_eq!(event.sequence(), None); // Start event has no sequence
        assert!(event.is_fallback_event());
        assert!(!event.is_error());

        let display = format!("{}", event);
        assert!(display.contains("50"));
    }

    #[test]
    fn test_fallback_reconcile_complete_event() {
        let event = StorageEvent::FallbackReconcileComplete { sequence: 44444 };

        assert_eq!(event.name(), "FallbackReconcileComplete");
        assert_eq!(event.sequence(), Some(44444));
        assert!(event.is_fallback_event());
        assert!(!event.is_error());

        let display = format!("{}", event);
        assert!(display.contains("44444"));
    }

    #[test]
    fn test_fallback_reconcile_failed_event() {
        let event = StorageEvent::FallbackReconcileFailed {
            sequence: 55555,
            error: "DA layer unreachable: connection timeout after 30s".to_string(),
        };

        assert_eq!(event.name(), "FallbackReconcileFailed");
        assert_eq!(event.sequence(), Some(55555));
        assert!(event.is_fallback_event());
        assert!(event.is_error()); // This IS an error event

        let display = format!("{}", event);
        assert!(display.contains("55555"));
        assert!(display.contains("DA layer unreachable"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // LOGGING LISTENER TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_logging_listener_no_panic() {
        let listener = LoggingListener::new();

        // All events should not panic
        listener.on_event(StorageEvent::ChunkStored {
            hash: "h1".to_string(),
            size: 100,
            duration_ms: 10,
        });

        listener.on_event(StorageEvent::ChunkDeleted {
            hash: "h2".to_string(),
            reason: "gc".to_string(),
        });

        listener.on_event(StorageEvent::VerificationPassed {
            hash: "h3".to_string(),
        });

        listener.on_event(StorageEvent::VerificationFailed {
            hash: "h4".to_string(),
            reason: "corrupt".to_string(),
        });

        listener.on_event(StorageEvent::RecoveryStarted {
            hash: "h5".to_string(),
            source_node: "node1".to_string(),
        });

        listener.on_event(StorageEvent::RecoveryCompleted {
            hash: "h6".to_string(),
        });

        listener.on_event(StorageEvent::GCCompleted {
            reclaimed_bytes: 1000,
            chunk_count: 5,
        });

        // If we reach here, no panic occurred
    }

    #[test]
    fn test_logging_listener_fallback_events_no_panic() {
        let listener = LoggingListener::new();

        // All fallback events should not panic
        listener.on_event(StorageEvent::FallbackCacheHit {
            sequence: 1,
            source: DASourceType::Celestia,
        });

        listener.on_event(StorageEvent::FallbackCacheMiss { sequence: 2 });

        listener.on_event(StorageEvent::FallbackCacheStore {
            sequence: 3,
            bytes: 1024,
        });

        listener.on_event(StorageEvent::FallbackCacheEviction {
            sequence: 4,
            reason: EvictionReason::Expired,
        });

        listener.on_event(StorageEvent::FallbackReconcileStart { count: 10 });

        listener.on_event(StorageEvent::FallbackReconcileComplete { sequence: 5 });

        listener.on_event(StorageEvent::FallbackReconcileFailed {
            sequence: 6,
            error: "test error".to_string(),
        });

        // If we reach here, no panic occurred
    }

    #[test]
    fn test_logging_listener_with_prefix() {
        let listener = LoggingListener::with_prefix("TEST");

        // Should not panic
        listener.on_event(StorageEvent::ChunkStored {
            hash: "test".to_string(),
            size: 50,
            duration_ms: 5,
        });

        listener.on_event(StorageEvent::FallbackCacheHit {
            sequence: 100,
            source: DASourceType::Avail,
        });
    }

    // ════════════════════════════════════════════════════════════════════════
    // NO-OP LISTENER TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_noop_listener() {
        let listener = NoOpListener::new();

        // Should not panic and do nothing
        listener.on_event(StorageEvent::ChunkStored {
            hash: "x".to_string(),
            size: 1,
            duration_ms: 1,
        });

        listener.on_event(StorageEvent::FallbackCacheHit {
            sequence: 1,
            source: DASourceType::LocalFallback,
        });
    }

    // ════════════════════════════════════════════════════════════════════════
    // TRAIT OBJECT TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_trait_object_polymorphic() {
        let listeners: Vec<Arc<dyn StorageEventListener>> = vec![
            Arc::new(LoggingListener::new()),
            Arc::new(NoOpListener::new()),
        ];

        let event = StorageEvent::ChunkStored {
            hash: "poly".to_string(),
            size: 100,
            duration_ms: 10,
        };

        // All listeners should handle event polymorphically
        for listener in &listeners {
            listener.on_event(event.clone());
        }
    }

    #[test]
    fn test_trait_object_fallback_events() {
        let listeners: Vec<Arc<dyn StorageEventListener>> = vec![
            Arc::new(LoggingListener::new()),
            Arc::new(NoOpListener::new()),
        ];

        let event = StorageEvent::FallbackCacheHit {
            sequence: 999,
            source: DASourceType::EigenDA,
        };

        for listener in &listeners {
            listener.on_event(event.clone());
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // COMPOSITE LISTENER TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_composite_listener() {
        let counter = Arc::new(AtomicUsize::new(0));

        struct CountingListener {
            counter: Arc<AtomicUsize>,
        }

        impl StorageEventListener for CountingListener {
            fn on_event(&self, _event: StorageEvent) {
                self.counter.fetch_add(1, Ordering::SeqCst);
            }
        }

        let mut composite = CompositeListener::new();
        composite.add_listener(Arc::new(CountingListener {
            counter: counter.clone(),
        }));
        composite.add_listener(Arc::new(CountingListener {
            counter: counter.clone(),
        }));

        assert_eq!(composite.listener_count(), 2);

        composite.on_event(StorageEvent::ChunkStored {
            hash: "test".to_string(),
            size: 100,
            duration_ms: 10,
        });

        // Both listeners should have been called
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_composite_listener_fallback_events() {
        let counter = Arc::new(AtomicUsize::new(0));

        struct CountingListener {
            counter: Arc<AtomicUsize>,
        }

        impl StorageEventListener for CountingListener {
            fn on_event(&self, _event: StorageEvent) {
                self.counter.fetch_add(1, Ordering::SeqCst);
            }
        }

        let mut composite = CompositeListener::new();
        composite.add_listener(Arc::new(CountingListener {
            counter: counter.clone(),
        }));
        composite.add_listener(Arc::new(CountingListener {
            counter: counter.clone(),
        }));

        composite.on_event(StorageEvent::FallbackReconcileStart { count: 5 });

        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    // ════════════════════════════════════════════════════════════════════════
    // EVENT EMITTER TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_event_emitter() {
        let counter = Arc::new(AtomicUsize::new(0));

        struct CountingListener {
            counter: Arc<AtomicUsize>,
        }

        impl StorageEventListener for CountingListener {
            fn on_event(&self, _event: StorageEvent) {
                self.counter.fetch_add(1, Ordering::SeqCst);
            }
        }

        let emitter = EventEmitter::new(Arc::new(CountingListener {
            counter: counter.clone(),
        }));

        emitter.chunk_stored("h1".to_string(), 100, 10);
        emitter.chunk_deleted("h2".to_string(), "gc".to_string());
        emitter.verification_passed("h3".to_string());
        emitter.verification_failed("h4".to_string(), "bad".to_string());
        emitter.recovery_started("h5".to_string(), "peer".to_string());
        emitter.recovery_completed("h6".to_string());
        emitter.gc_completed(1000, 5);

        assert_eq!(counter.load(Ordering::SeqCst), 7);
    }

    #[test]
    fn test_event_emitter_fallback_events() {
        let counter = Arc::new(AtomicUsize::new(0));

        struct CountingListener {
            counter: Arc<AtomicUsize>,
        }

        impl StorageEventListener for CountingListener {
            fn on_event(&self, _event: StorageEvent) {
                self.counter.fetch_add(1, Ordering::SeqCst);
            }
        }

        let emitter = EventEmitter::new(Arc::new(CountingListener {
            counter: counter.clone(),
        }));

        emitter.fallback_cache_hit(1, DASourceType::Celestia);
        emitter.fallback_cache_miss(2);
        emitter.fallback_cache_store(3, 2048);
        emitter.fallback_cache_eviction(4, EvictionReason::CacheFull);
        emitter.fallback_reconcile_start(10);
        emitter.fallback_reconcile_complete(5);
        emitter.fallback_reconcile_failed(6, "test error".to_string());

        assert_eq!(counter.load(Ordering::SeqCst), 7);
    }

    #[test]
    fn test_event_emitter_fallback_reconcile_failed_empty_error() {
        let received_events = Arc::new(std::sync::Mutex::new(Vec::new()));

        struct CapturingListener {
            events: Arc<std::sync::Mutex<Vec<StorageEvent>>>,
        }

        impl StorageEventListener for CapturingListener {
            fn on_event(&self, event: StorageEvent) {
                if let Ok(mut events) = self.events.lock() {
                    events.push(event);
                }
            }
        }

        let emitter = EventEmitter::new(Arc::new(CapturingListener {
            events: received_events.clone(),
        }));

        // Empty error should be replaced with default message
        emitter.fallback_reconcile_failed(100, String::new());

        let events = received_events.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(events.len(), 1);

        if let StorageEvent::FallbackReconcileFailed { sequence, error } = &events[0] {
            assert_eq!(*sequence, 100);
            assert!(!error.is_empty());
            assert_eq!(error, "Unknown reconcile error");
        } else {
            panic!("Expected FallbackReconcileFailed event");
        }
    }

    #[test]
    fn test_event_emitter_noop() {
        let emitter = EventEmitter::noop();

        // Should not panic
        emitter.chunk_stored("test".to_string(), 100, 10);
        emitter.fallback_cache_hit(1, DASourceType::Avail);
        emitter.fallback_reconcile_failed(2, "error".to_string());
    }

    // ════════════════════════════════════════════════════════════════════════
    // EVENT NO SIDE EFFECT TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_event_clone_no_side_effect() {
        let event1 = StorageEvent::ChunkStored {
            hash: "original".to_string(),
            size: 100,
            duration_ms: 10,
        };

        let event2 = event1.clone();

        // Cloning should produce equal events
        assert_eq!(event1, event2);

        // Original should be unchanged
        assert_eq!(event1.chunk_hash(), Some("original"));
    }

    #[test]
    fn test_fallback_event_clone_no_side_effect() {
        let event1 = StorageEvent::FallbackCacheHit {
            sequence: 12345,
            source: DASourceType::Celestia,
        };

        let event2 = event1.clone();

        assert_eq!(event1, event2);
        assert_eq!(event1.sequence(), Some(12345));
    }

    #[test]
    fn test_event_equality() {
        let event1 = StorageEvent::VerificationPassed {
            hash: "same".to_string(),
        };

        let event2 = StorageEvent::VerificationPassed {
            hash: "same".to_string(),
        };

        let event3 = StorageEvent::VerificationPassed {
            hash: "different".to_string(),
        };

        assert_eq!(event1, event2);
        assert_ne!(event1, event3);
    }

    #[test]
    fn test_fallback_event_equality() {
        let event1 = StorageEvent::FallbackCacheHit {
            sequence: 100,
            source: DASourceType::Celestia,
        };

        let event2 = StorageEvent::FallbackCacheHit {
            sequence: 100,
            source: DASourceType::Celestia,
        };

        let event3 = StorageEvent::FallbackCacheHit {
            sequence: 100,
            source: DASourceType::Avail,
        };

        let event4 = StorageEvent::FallbackCacheHit {
            sequence: 200,
            source: DASourceType::Celestia,
        };

        assert_eq!(event1, event2);
        assert_ne!(event1, event3);
        assert_ne!(event1, event4);
    }

    #[test]
    fn test_event_debug() {
        let event = StorageEvent::GCCompleted {
            reclaimed_bytes: 500,
            chunk_count: 3,
        };

        let debug = format!("{:?}", event);
        assert!(debug.contains("GCCompleted"));
        assert!(debug.contains("500"));
        assert!(debug.contains("3"));
    }

    #[test]
    fn test_fallback_event_debug() {
        let event = StorageEvent::FallbackCacheEviction {
            sequence: 777,
            reason: EvictionReason::MemoryPressure {
                memory_usage_percent: 85,
            },
        };

        let debug = format!("{:?}", event);
        assert!(debug.contains("FallbackCacheEviction"));
        assert!(debug.contains("777"));
        assert!(debug.contains("MemoryPressure"));
        assert!(debug.contains("85"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // LISTENER RECEIVES ALL FALLBACK EVENTS WITHOUT PANIC
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_listener_receives_all_fallback_events_without_panic() {
        struct StrictListener;

        impl StorageEventListener for StrictListener {
            fn on_event(&self, event: StorageEvent) {
                // Explicitly handle all variants to ensure exhaustiveness
                match event {
                    StorageEvent::ChunkStored { .. } => {}
                    StorageEvent::ChunkDeleted { .. } => {}
                    StorageEvent::VerificationPassed { .. } => {}
                    StorageEvent::VerificationFailed { .. } => {}
                    StorageEvent::RecoveryStarted { .. } => {}
                    StorageEvent::RecoveryCompleted { .. } => {}
                    StorageEvent::GCCompleted { .. } => {}
                    StorageEvent::FallbackCacheHit { .. } => {}
                    StorageEvent::FallbackCacheMiss { .. } => {}
                    StorageEvent::FallbackCacheStore { .. } => {}
                    StorageEvent::FallbackCacheEviction { .. } => {}
                    StorageEvent::FallbackReconcileStart { .. } => {}
                    StorageEvent::FallbackReconcileComplete { .. } => {}
                    StorageEvent::FallbackReconcileFailed { .. } => {}
                }
            }
        }

        let listener = StrictListener;

        // All events - no panic expected
        listener.on_event(StorageEvent::ChunkStored {
            hash: "h".to_string(),
            size: 1,
            duration_ms: 1,
        });
        listener.on_event(StorageEvent::FallbackCacheHit {
            sequence: 1,
            source: DASourceType::Celestia,
        });
        listener.on_event(StorageEvent::FallbackCacheMiss { sequence: 2 });
        listener.on_event(StorageEvent::FallbackCacheStore {
            sequence: 3,
            bytes: 100,
        });
        listener.on_event(StorageEvent::FallbackCacheEviction {
            sequence: 4,
            reason: EvictionReason::Reconciled,
        });
        listener.on_event(StorageEvent::FallbackReconcileStart { count: 1 });
        listener.on_event(StorageEvent::FallbackReconcileComplete { sequence: 5 });
        listener.on_event(StorageEvent::FallbackReconcileFailed {
            sequence: 6,
            error: "test".to_string(),
        });
    }

    // ════════════════════════════════════════════════════════════════════════
    // EMIT CONDITIONS VERIFICATION TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_fallback_cache_hit_has_correct_source() {
        let event = StorageEvent::FallbackCacheHit {
            sequence: 100,
            source: DASourceType::Avail,
        };

        if let StorageEvent::FallbackCacheHit { source, .. } = event {
            assert_eq!(source, DASourceType::Avail);
        } else {
            panic!("Wrong event type");
        }
    }

    #[test]
    fn test_fallback_cache_store_has_actual_bytes() {
        let event = StorageEvent::FallbackCacheStore {
            sequence: 200,
            bytes: 8192, // Actual blob size
        };

        if let StorageEvent::FallbackCacheStore { bytes, .. } = event {
            assert!(bytes > 0, "bytes must be actual blob size, not zero");
            assert_eq!(bytes, 8192);
        } else {
            panic!("Wrong event type");
        }
    }

    #[test]
    fn test_fallback_reconcile_failed_has_meaningful_error() {
        let event = StorageEvent::FallbackReconcileFailed {
            sequence: 300,
            error: "Celestia node returned HTTP 503: Service Unavailable".to_string(),
        };

        if let StorageEvent::FallbackReconcileFailed { error, .. } = event {
            assert!(!error.is_empty(), "error must not be empty");
            assert!(
                error.len() > 10,
                "error should be informative, not generic"
            );
        } else {
            panic!("Wrong event type");
        }
    }

    #[test]
    fn test_fallback_reconcile_start_has_correct_count() {
        let event = StorageEvent::FallbackReconcileStart { count: 42 };

        if let StorageEvent::FallbackReconcileStart { count } = event {
            assert_eq!(count, 42);
        } else {
            panic!("Wrong event type");
        }
    }

    #[test]
    fn test_eviction_reason_matches_policy() {
        // Verify each eviction reason can be properly constructed
        let reasons = vec![
            EvictionReason::CacheFull,
            EvictionReason::Expired,
            EvictionReason::Reconciled,
            EvictionReason::Manual {
                description: "Operator requested cleanup".to_string(),
            },
            EvictionReason::MemoryPressure {
                memory_usage_percent: 90,
            },
        ];

        for reason in reasons {
            let event = StorageEvent::FallbackCacheEviction {
                sequence: 1,
                reason: reason.clone(),
            };

            if let StorageEvent::FallbackCacheEviction {
                reason: event_reason,
                ..
            } = event
            {
                assert_eq!(event_reason, reason);
            }
        }
    }
}