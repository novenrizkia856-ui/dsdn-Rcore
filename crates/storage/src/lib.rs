//! dsdn-storage
//!
//! Crate ini mengatur chunking, penyimpanan lokal, dan RPC antar node.
//!
//! ## Modules
//!
//! - `chunker`: Chunking logic untuk memecah data
//! - `store`: Storage trait abstraction
//! - `localfs`: Local filesystem storage implementation
//! - `da_storage`: DA-aware storage wrapper
//! - `rpc`: RPC services untuk komunikasi antar node
//!
//! ## DA-Aware Storage
//!
//! `DAStorage` adalah wrapper yang menambahkan awareness terhadap
//! Data Availability layer. Storage tetap menjadi sumber kebenaran
//! untuk keberadaan data, sementara metadata DA digunakan untuk
//! tracking dan verifikasi.
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │              DAStorage                       │
//! ├─────────────────────────────────────────────┤
//! │  inner (Storage) ──► Data (authoritative)   │
//! │  chunk_metadata  ──► DA tracking (derived)  │
//! └─────────────────────────────────────────────┘
//! ```

pub mod chunker;
pub mod store;
pub mod localfs;
pub mod da_storage;
pub mod rpc;

// hasil generate dari tonic_build (OUT_DIR/api.rs)
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/dsdn.api.rs"));
}

pub use crate::store::Storage;
pub use crate::localfs::LocalFsStorage;
pub use crate::da_storage::{DAStorage, DAChunkMeta};