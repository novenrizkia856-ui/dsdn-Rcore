//! # DSDN Node Crate
//!
//! This crate provides the storage node implementation for DSDN (Decentralized
//! Storage and Data Network). A node acts as a **DA Follower** - it does not
//! determine state independently but follows events from the Data Availability layer.
//!
//! ## Node vs Coordinator
//!
//! | Aspect | Coordinator | Node |
//! |--------|-------------|------|
//! | State scope | Full network | Node-relevant only |
//! | Authority | Authoritative | Non-authoritative |
//! | Role | Orchestration | Storage & execution |
//! | State source | DA events | DA events (subset) |
//!
//! ## Key Principles
//!
//! - **DA Follower**: Node follows events from DA, does not create authoritative state
//! - **Derived State**: All node state is derived from DA events
//! - **Rebuildable**: Node state can be fully reconstructed from DA at any time
//! - **Non-authoritative**: The DA layer is the single source of truth
//!
//! ## Modules
//!
//! - **da_follower**: DA event subscription and node-scoped state management
//! - **delete_handler**: Safe handling of delete requests with grace period
//! - **event_processor**: Event-to-action translation (pure logic)
//! - **placement_verifier**: DA-based placement verification
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                           NODE                                  │
//! │                                                                 │
//! │  ┌─────────────────┐         ┌─────────────────────────────┐   │
//! │  │   DAFollower    │────────▶│    NodeDerivedState         │   │
//! │  │ (Event Follow)  │         │  - my_chunks                │   │
//! │  └────────┬────────┘         │  - coordinator_state (copy) │   │
//! │           │                  │  - last_sequence            │   │
//! │           │                  └──────────────┬──────────────┘   │
//! │           │ subscribe                       │                   │
//! │           │                  ┌──────────────▼──────────────┐   │
//! │  ┌────────┴────────┐         │   NodeEventProcessor        │   │
//! │  │    DALayer      │         │  - process_event()          │   │
//! │  │  (Celestia)     │         │  - Returns NodeAction       │   │
//! │  └─────────────────┘         └─────────────────────────────┘   │
//! │                                                                 │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## State Characteristics
//!
//! - `my_chunks`: Only chunks assigned to this specific node
//! - `coordinator_state`: A non-authoritative copy for local decisions
//! - `last_sequence`: Tracks event processing progress
//!
//! All state can be rebuilt from DA by replaying events.

pub mod da_follower;
pub mod delete_handler;
pub mod event_processor;
pub mod placement_verifier;

pub use da_follower::{DAFollower, NodeDerivedState, ChunkAssignment, StateError, ReplicaStatus};
pub use delete_handler::{DeleteHandler, DeleteError, DeleteRequestedEvent, PendingDelete, Storage};
pub use event_processor::{NodeEventProcessor, NodeAction, ProcessError};
pub use placement_verifier::{PlacementVerifier, PlacementReport, PlacementDetail, PlacementStatus};