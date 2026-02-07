//! # Gating System — On-Chain State (14B)
//!
//! This module provides on-chain state management for the DSDN service
//! node gating system.
//!
//! ## Modules
//!
//! - `service_node`: `ServiceNodeRecord` struct — on-chain source of truth (14B.11)
//! - `registry`: CRUD, query, and status management for service node registry (14B.12)
//!
//! ## Relationship with `dsdn_common::gating`
//!
//! - `common` = validation logic (NodeClass, NodeStatus, CooldownPeriod, etc.)
//! - `chain::gating` = on-chain state & enforcement (ServiceNodeRecord, registry ops)

pub mod service_node;
pub mod registry;

pub use service_node::ServiceNodeRecord;