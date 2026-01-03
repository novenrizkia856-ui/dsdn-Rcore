//! dsdn-storage
//!
//! Crate ini mengatur chunking, penyimpanan lokal, dan RPC antar node.

pub mod chunker;
pub mod store;
pub mod localfs;
pub mod rpc;

// hasil generate dari tonic_build (OUT_DIR/api.rs)
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/dsdn.api.rs"));
}

pub use crate::store::Storage;
pub use crate::localfs::LocalFsStorage;
