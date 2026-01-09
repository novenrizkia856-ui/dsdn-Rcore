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
//! ┌─────────────────────────────────────────────────────────────┐
//! │  EVENT ≠ COMMAND                                            │
//! │  EVENT ≠ STATE                                              │
//! │  EVENT = Passive observation of what happened               │
//! └─────────────────────────────────────────────────────────────┘
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
// STORAGE EVENT ENUM
// ════════════════════════════════════════════════════════════════════════════

/// Event yang terjadi pada storage.
///
/// Event ini bersifat observability saja, tidak mempengaruhi
/// perilaku sistem atau state storage.
///
/// # Variants
///
/// - `ChunkStored`: Chunk berhasil disimpan
/// - `ChunkDeleted`: Chunk dihapus
/// - `VerificationPassed`: Chunk lolos verifikasi
/// - `VerificationFailed`: Chunk gagal verifikasi
/// - `RecoveryStarted`: Recovery chunk dimulai
/// - `RecoveryCompleted`: Recovery chunk selesai
/// - `GCCompleted`: Garbage collection selesai
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageEvent {
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
        }
    }

    /// Check if event is error-related.
    pub fn is_error(&self) -> bool {
        matches!(self, StorageEvent::VerificationFailed { .. })
    }

    /// Get chunk hash if applicable.
    pub fn chunk_hash(&self) -> Option<&str> {
        match self {
            StorageEvent::ChunkStored { hash, .. } => Some(hash),
            StorageEvent::ChunkDeleted { hash, .. } => Some(hash),
            StorageEvent::VerificationPassed { hash } => Some(hash),
            StorageEvent::VerificationFailed { hash, .. } => Some(hash),
            StorageEvent::RecoveryStarted { hash, .. } => Some(hash),
            StorageEvent::RecoveryCompleted { hash } => Some(hash),
            StorageEvent::GCCompleted { .. } => None,
        }
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
    // EVENT CREATION TESTS
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
    fn test_logging_listener_with_prefix() {
        let listener = LoggingListener::with_prefix("TEST");

        // Should not panic
        listener.on_event(StorageEvent::ChunkStored {
            hash: "test".to_string(),
            size: 50,
            duration_ms: 5,
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
    fn test_event_emitter_noop() {
        let emitter = EventEmitter::noop();

        // Should not panic
        emitter.chunk_stored("test".to_string(), 100, 10);
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
}