//! # DSDN Storage Crate (14A)
//!
//! Storage layer untuk DSDN dengan DA awareness dan Multi-DA fallback support.
//!
//! ## Modules
//!
//! - `store`: Storage trait dan basic implementations
//! - `localfs`: Local filesystem storage
//! - `chunker`: File chunking utilities
//! - `rpc`: gRPC client/server untuk chunk transfer
//! - `da_storage`: DA-aware storage wrapper
//! - `storage_proof`: Proof generation untuk challenges
//! - `gc`: Garbage collection
//! - `recovery`: Chunk recovery dari peers
//! - `metrics`: Storage health metrics
//! - `events`: Storage event emission
//! - `fallback_cache`: Fallback blob caching for Multi-DA support (14A.1A.51)
//!
//! # Architecture Overview
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                        DAStorage                             │
//! ├─────────────────────────────────────────────────────────────┤
//! │  ┌───────────────┐  ┌─────────────────────────────────────┐ │
//! │  │ LocalStorage  │  │          FallbackCache              │ │
//! │  └───────────────┘  │  ┌─────────┐ ┌──────────────────┐  │ │
//! │                      │  │  blob   │ │    eviction      │  │ │
//! │                      │  ├─────────┤ ├──────────────────┤  │ │
//! │                      │  │ metrics │ │  reconciliation  │  │ │
//! │                      │  ├─────────┤ ├──────────────────┤  │ │
//! │                      │  │validation│ │   persistence   │  │ │
//! │                      │  └─────────┘ └──────────────────┘  │ │
//! │                      └─────────────────────────────────────┘ │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## LocalStorage vs FallbackCache
//!
//! ### LocalStorage
//!
//! `LocalStorage` adalah primary storage untuk chunk data.
//! - Menyimpan chunk data yang sudah diverifikasi dan committed ke DA layer
//! - Bersifat persistent dan durable
//! - Source of truth untuk chunk yang sudah di-commit
//! - Digunakan untuk operasi normal (non-fallback)
//!
//! ### FallbackCache
//!
//! `FallbackCache` adalah secondary storage yang digunakan HANYA saat
//! primary DA layer tidak tersedia. FallbackCache adalah **fallback**,
//! **bukan pengganti** primary storage.
//!
//! Karakteristik FallbackCache:
//! - **Temporary**: Data di cache bersifat sementara hingga reconciliation
//! - **Non-authoritative**: Cache TIDAK menjadi source of truth
//! - **Fallback-only**: Cache HANYA aktif saat DA layer down
//! - **Best-effort**: Tidak ada jaminan durability seperti primary storage
//!
//! ## FallbackCache Components
//!
//! ### Blob Storage
//!
//! Menyimpan blob data sementara dengan metadata:
//! - Sequence number untuk ordering
//! - Source DA type untuk reconciliation target
//! - Timestamp untuk eviction policy
//!
//! ### Eviction
//!
//! Kebijakan penghapusan entry dari cache:
//! - `CacheFull`: LRU eviction saat capacity tercapai
//! - `Expired`: TTL-based eviction
//! - `Reconciled`: Entry dihapus setelah sukses reconcile ke DA
//! - `MemoryPressure`: Eviction saat memory usage tinggi
//!
//! Eviction policy dikonfigurasi via [`EvictionPolicy`].
//!
//! ### Metrics
//!
//! [`CacheMetrics`] menyediakan observability:
//! - Hit/miss ratio
//! - Cache size (entries dan bytes)
//! - Eviction counts per reason
//! - Reconciliation pending count
//!
//! Metrik bersifat read-only dan tidak mempengaruhi behavior.
//!
//! ### Validation
//!
//! [`ValidationReport`] memvalidasi integritas cache:
//! - Blob integrity check
//! - Metadata consistency check
//! - Orphaned entry detection
//!
//! Validation bersifat diagnostic, tidak auto-fix.
//!
//! ### Reconciliation
//!
//! Proses memindahkan data dari FallbackCache ke primary DA layer:
//! - Batch-based untuk efisiensi
//! - Per-sequence tracking untuk reliability
//! - Retry dengan exponential backoff
//! - Event emission untuk observability
//!
//! Reconciliation terjadi HANYA saat DA layer kembali available.
//!
//! ### Persistence
//!
//! [`PersistentFallbackCache`] menyediakan durability untuk cache:
//! - Disk-backed storage
//! - Crash recovery
//! - Configurable sync policy
//!
//! Persistence adalah **optional** dan dapat dimatikan.
//!
//! ## Configuration
//!
//! Semua komponen FallbackCache dikonfigurasi via [`FallbackCacheConfig`]:
//! - `enabled`: Master switch untuk seluruh fallback system
//! - `max_size_bytes`: Maximum cache size
//! - `eviction_policy`: Kebijakan eviction
//! - `persistence_enabled`: Toggle untuk persistent cache
//! - `reconcile_batch_size`: Batch size untuk reconciliation
//!
//! ## Key Invariants
//!
//! 1. FallbackCache TIDAK aktif saat DA layer healthy
//! 2. FallbackCache TIDAK mengubah behavior normal storage
//! 3. Semua data di FallbackCache HARUS di-reconcile ke DA layer
//! 4. Semua komponen fallback dapat di-disable tanpa breaking changes
//! 5. Chunk metadata dapat direkonstruksi dari DA layer
//!
//! ## DA Integration (Legacy Diagram)
//!
//! ```text
//! ┌─────────────────────────────────────┐
//! │           DAStorage                  │
//! ├─────────────────────────────────────┤
//! │  ┌───────────────┐  ┌────────────┐ │
//! │  │ LocalStorage  │  │ DA Client  │ │
//! │  └───────────────┘  └────────────┘ │
//! │          │                 │        │
//! │          ▼                 ▼        │
//! │  ┌───────────────────────────────┐ │
//! │  │      Chunk Metadata           │ │
//! │  │   (derived from DA events)    │ │
//! │  └───────────────────────────────┘ │
//! └─────────────────────────────────────┘
//! ```
//!
//! ## Storage Proof
//!
//! `StorageProof` digunakan untuk challenge-response verification.
//! Node dapat membuktikan bahwa ia benar-benar menyimpan chunk
//! tertentu tanpa mengirimkan seluruh data.
//!
//! ```text
//! Proof Scheme: response = SHA3-256(chunk_data || challenge_seed)
//! ```
//!
//! ## Garbage Collection
//!
//! `GarbageCollector` menghapus data berdasarkan DA events:
//! - **Deleted**: Chunks dengan DeleteRequested event + grace period habis
//! - **Orphaned**: Chunks yang tidak assigned ke node ini
//! - **Corrupted**: Chunks dengan commitment mismatch
//!
//! GC beroperasi dalam 2 tahap:
//! 1. `scan()` - Menemukan chunks yang boleh dihapus
//! 2. `collect()` - Menghapus berdasarkan hasil scan
//!
//! Tidak ada auto-delete tanpa scan terlebih dahulu.
//!
//! ## Storage Metrics
//!
//! `StorageMetrics` menyediakan observability untuk monitoring:
//! - Total chunks dan bytes
//! - Status verifikasi (verified/pending/failed)
//! - Orphaned chunks
//! - GC pending bytes
//! - DA sync lag
//!
//! Metrik read-only, tidak memodifikasi state.
//!
//! ## Storage Recovery
//!
//! `StorageRecovery` memulihkan chunk yang hilang berdasarkan DA state:
//! - Recovery HANYA untuk chunk yang sah (assigned via DA)
//! - Data diverifikasi sebelum disimpan
//! - Tidak ada overwrite chunk yang sudah ada
//!
//! Recovery berbasis DA, bukan auto-magic.
//!
//! ## Storage Events
//!
//! `StorageEvent` menyediakan event emission untuk observability:
//! - Events HANYA untuk logging, monitoring, debugging
//! - Events TIDAK authoritative, TIDAK mempengaruhi correctness
//! - Events TIDAK mengubah perilaku sistem
//!
//! ### Fallback Events (14A.1A.59)
//!
//! Event tambahan untuk fallback awareness:
//! - `FallbackCacheHit`: Cache hit saat fallback aktif
//! - `FallbackCacheMiss`: Cache miss saat fallback aktif
//! - `FallbackCacheStore`: Blob disimpan ke cache
//! - `FallbackCacheEviction`: Entry di-evict dari cache
//! - `FallbackReconcileStart`: Batch reconcile dimulai
//! - `FallbackReconcileComplete`: Sequence berhasil di-reconcile
//! - `FallbackReconcileFailed`: Sequence gagal di-reconcile

pub mod chunker;
pub mod store;
pub mod localfs;
pub mod da_storage;
pub mod storage_proof;
pub mod gc;
pub mod metrics;
pub mod recovery;
pub mod events;
pub mod rpc;
pub mod fallback_cache;

// hasil generate dari tonic_build (OUT_DIR/api.rs)
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/dsdn.api.rs"));
}

pub use crate::store::Storage;
pub use crate::localfs::LocalFsStorage;
pub use crate::da_storage::{
    DAStorage,
    DAChunkMeta,
    ChunkDeclaredEvent,
    StorageError,
    CommitmentReport,
    ReplicaInfo,
    ReplicaAddedEvent,
    ReplicaRemovedEvent,
};
pub use crate::storage_proof::{
    StorageProof,
    generate_proof,
    verify_proof,
    verify_proof_with_data,
    compute_da_commitment,
};
pub use crate::gc::{
    GarbageCollector,
    GCScanResult,
    GCError,
    DeleteRequestedEvent,
};
pub use crate::metrics::{
    StorageMetrics,
    MetricsCollector,
};
pub use crate::recovery::{
    StorageRecovery,
    SimpleStorageRecovery,
    RecoveryReport,
    RecoveryDetail,
    RecoveryError,
    PeerFetcher,
};
pub use crate::events::{
    StorageEvent,
    StorageEventListener,
    LoggingListener,
    NoOpListener,
    CompositeListener,
    EventEmitter,
};
pub use crate::fallback_cache::{
    FallbackCache,
    FallbackCacheConfig,
    CachedBlob,
    CacheMetrics,
    EvictionPolicy,
    ValidationReport,
};
pub use crate::fallback_cache::persistence::PersistentFallbackCache;