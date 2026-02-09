//! # Gating System — On-Chain State (14B)
//!
//! This module provides on-chain state management for the DSDN service
//! node gating system.
//!
//! ## Modules
//!
//! - `service_node`: `ServiceNodeRecord` struct — on-chain source of truth (14B.11)
//! - `registry`: CRUD, query, and status management for service node registry (14B.12)
//! - `query`: Read-only stake query API — `get_stake_info`, `ServiceNodeStakeInfo` (14B.14)
//!
//! ## Relationship with `dsdn_common::gating`
//!
//! - `common` = validation logic (NodeClass, NodeStatus, CooldownPeriod, etc.)
//! - `chain::gating` = on-chain state & enforcement (ServiceNodeRecord, registry ops)

pub mod service_node;
pub mod registry;
pub mod query;

pub use service_node::ServiceNodeRecord;
pub use query::ServiceNodeStakeInfo;