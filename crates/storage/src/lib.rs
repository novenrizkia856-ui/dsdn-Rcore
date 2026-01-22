//! # DSDN Storage Crate (14A)
//!
//! Storage layer untuk DSDN dengan DA awareness.
//!
//! ## Modules
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
//! ## DA Integration
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
//! ## Key Invariant
//! Semua chunk metadata dapat direkonstruksi dari DA.
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
pub use crate::fallback_cache::FallbackCache;