//! # DSDN Node Crate (14A)
//!
//! Storage node untuk DSDN network.
//!
//! ## Architecture
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │                   Node                       │
//! ├─────────────────────────────────────────────┤
//! │  ┌─────────────┐    ┌──────────────────┐   │
//! │  │ DAFollower  │───▶│ NodeDerivedState │   │
//! │  └─────────────┘    └──────────────────┘   │
//! │         │                    │              │
//! │         ▼                    ▼              │
//! │  ┌─────────────┐    ┌──────────────────┐   │
//! │  │EventProcessor│   │  Local Storage   │   │
//! │  └─────────────┘    └──────────────────┘   │
//! └─────────────────────────────────────────────┘
//!                      │
//!                      ▼
//!              ┌───────────────┐
//!              │  Celestia DA  │
//!              └───────────────┘
//! ```
//!
//! ## Modules
//! - `da_follower`: DA subscription dan event processing
//! - `event_processor`: Event handling logic
//! - `placement_verifier`: Placement verification
//! - `delete_handler`: Delete request handling
//! - `state_sync`: State synchronization
//! - `health`: Health reporting
//! - `multi_da_source`: Multi-DA source abstraction for fallback (14A.1A.41)
//!
//! ## Key Invariant
//! Node TIDAK menerima instruksi dari Coordinator via RPC.
//! Semua perintah datang via DA events.

pub mod da_follower;
pub mod delete_handler;
pub mod event_processor;
pub mod health;
pub mod multi_da_source;
pub mod placement_verifier;
pub mod state_sync;

pub use da_follower::{DAFollower, NodeDerivedState, ChunkAssignment, StateError, ReplicaStatus};
pub use delete_handler::{DeleteHandler, DeleteError, DeleteRequestedEvent, PendingDelete, Storage};
pub use event_processor::{NodeEventProcessor, NodeAction, ProcessError};
pub use health::{NodeHealth, HealthStorage, DAInfo, HealthResponse, health_endpoint, DA_LAG_THRESHOLD};
pub use multi_da_source::{MultiDASource, MultiDAConfig, DASourceType};
pub use placement_verifier::{PlacementVerifier, PlacementReport, PlacementDetail, PlacementStatus};
pub use state_sync::{StateSync, ConsistencyReport, SyncError, SyncStorage};