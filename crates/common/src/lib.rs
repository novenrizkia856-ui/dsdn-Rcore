//! # DSDN Common Crate (14A)
//!
//! Common utilities dan DA Abstraction Layer.
//!
//! ## Modules
//! - `da`: DALayer trait definition
//! - `celestia_da`: Celestia implementation
//! - `mock_da`: Mock implementation for testing
//! - `crypto`: Cryptographic utilities
//! - `cid`: Content addressing utilities
//! - `config`: Configuration management
//! - `consistent_hash`: Consistent hashing for placement
//! - `da_health_monitor`: Thread-safe DA health monitoring (14A.1A.11)
//!
//! ## DA Layer Architecture
//! ```text
//! ┌─────────────────┐
//! │    DALayer      │  <- Abstract trait
//! └────────┬────────┘
//!          │
//!    ┌─────┴─────┐
//!    │           │
//! ┌──▼──┐    ┌───▼───┐
//! │Celestia│  │MockDA │
//! └──────┘    └───────┘
//! ```
//!
//! ## Usage
//! ```rust,ignore
//! let da = CelestiaDA::from_env()?;
//! let blob_ref = da.post_blob(data).await?;
//! let blob = da.get_blob(&blob_ref).await?;
//! ```

pub mod crypto;
pub mod cid;
pub mod config;
pub mod consistent_hash;
pub mod da;
pub mod celestia_da;
pub mod mock_da;
pub mod da_health_monitor;

pub use da::{DALayer, DAError, DAHealthStatus, BlobRef, Blob, BlobStream, DAConfig};
pub use celestia_da::CelestiaDA;
pub use mock_da::MockDA;
pub use da_health_monitor::DAHealthMonitor;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;