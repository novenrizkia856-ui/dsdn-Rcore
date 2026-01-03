//! dsdn-common
//! Common utilities.

pub mod crypto;
pub mod cid;
pub mod config;
pub mod consistent_hash;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
