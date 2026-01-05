//! # DSDN Proto Crate (14A)
//!
//! Definisi schema untuk Data Availability events.
//!
//! ## Modules
//! - `da_event`: DAEvent enum dan semua event types
//! - `da_health`: DAHealthStatus dan DAError types
//!
//! ## Event Types
//! - NodeRegistered: Node bergabung ke network
//! - ChunkDeclared: Chunk baru dideklarasikan
//! - ReplicaAdded: Replica ditambahkan ke node
//! - ReplicaRemoved: Replica dihapus dari node
//! - DeleteRequested: Request penghapusan chunk
//!
//! ## Serialization
//! Semua event menggunakan bincode untuk deterministic encoding.

pub mod da_event;
pub mod da_health;

pub use da_health::{DAHealthStatus, DAError};

pub const PROTO_VERSION: &str = "0.1";