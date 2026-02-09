//! # Gating System — On-Chain State (14B)
//!
//! This module provides on-chain state management for the DSDN service
//! node gating system.
//!
//! ## Modules
//!
//! - `service_node`: `ServiceNodeRecord` struct — on-chain source of truth (14B.11)
//! - `registry`: CRUD, query, and status management for service node registry (14B.12)
//! - `query`: Read-only query API (14B.14, 14B.15)
//!   - Stake queries: `get_service_node_stake`, `get_stake_info`, `ServiceNodeStakeInfo`
//!   - Class/status: `get_service_node_class`, `get_service_node_status`
//!   - Slashing: `get_service_node_slashing_status`, `is_service_node_in_cooldown`, `ServiceNodeSlashingInfo`
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
pub use query::ServiceNodeSlashingInfo;