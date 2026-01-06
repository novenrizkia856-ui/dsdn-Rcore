//! dsdn-common
//! Common utilities.
//!
//! This crate provides shared utilities and abstractions used across
//! the DSDN system, including:
//!
//! - `crypto` - Cryptographic primitives and utilities
//! - `cid` - Content ID helpers based on SHA-256. Exposes deterministic hex string representation.
//! - `config` - Configuration management
//! - `consistent_hash` - Consistent hashing implementation
//! - `da` - Data Availability layer abstraction trait
//! - `celestia_da` - Celestia DA backend implementation
//! - `mock_da` - Mock DA backend for testing

pub mod crypto;
pub mod cid;
pub mod config;
pub mod consistent_hash;
pub mod da;
pub mod celestia_da;
pub mod mock_da;

pub use da::{DALayer, DAError, DAHealthStatus, BlobRef, Blob, BlobStream, DAConfig};
pub use celestia_da::CelestiaDA;
pub use mock_da::MockDA;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;