//! # ServiceNodeRecord — On-Chain Service Node State
//!
//! This module defines `ServiceNodeRecord`, the on-chain source of truth for
//! every registered service node in the DSDN network.
//!
//! ## Purpose
//!
//! `ServiceNodeRecord` stores all state that the chain needs to track for a
//! service node: operator identity, node identity, class, status, stake,
//! registration height, cooldown, TLS fingerprint, and metadata.
//!
//! ## Relationship with `dsdn_common::gating`
//!
//! - `dsdn_common::gating` defines **validation logic** and **type definitions**
//!   (`NodeClass`, `NodeStatus`, `CooldownPeriod`).
//! - This module defines **on-chain state** that references those types.
//! - `common` = validation logic. `chain` = state & enforcement.
//!
//! ## Invariants
//!
//! - Every `ServiceNodeRecord` stored in `ChainState::service_nodes` MUST have
//!   a corresponding entry in `ChainState::service_node_index`.
//! - `service_node_index[record.node_id] == record.operator_address`.
//! - No two operators may share the same `node_id`.
//! - No dangling index entries.
//!
//! ## Serialization
//!
//! All fields are serialized via serde. No custom serialization.
//! HashMap ordering is non-deterministic; `compute_state_root()` handles
//! deterministic hashing via sorting.

use crate::types::Address;
use dsdn_common::gating::{NodeClass, NodeStatus, CooldownPeriod};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

// ════════════════════════════════════════════════════════════════════════════════
// SERVICE NODE RECORD
// ════════════════════════════════════════════════════════════════════════════════

/// On-chain record for a registered DSDN service node.
///
/// This struct is the **single source of truth** for a service node's state
/// on the blockchain. It is stored in `ChainState::service_nodes` keyed by
/// `operator_address`.
///
/// ## Fields
///
/// - `operator_address`: The wallet address of the node operator. This is the
///   primary key in `ChainState::service_nodes`.
/// - `node_id`: 32-byte Ed25519 public key uniquely identifying the node.
///   This is the key in `ChainState::service_node_index`.
/// - `class`: The node's role classification (`Storage` or `Compute`).
/// - `status`: The node's lifecycle status (`Pending`, `Active`, `Quarantined`, `Banned`).
/// - `staked_amount`: The amount of NUSA staked by this node (in smallest unit).
/// - `registered_height`: The block height at which the node was first registered.
/// - `last_status_change_height`: The block height at which the node's status
///   was last changed.
/// - `cooldown`: Optional cooldown period if the node has been banned or penalized.
/// - `tls_fingerprint`: Optional SHA-256 fingerprint of the node's TLS certificate.
/// - `metadata`: Arbitrary key-value metadata for extensibility.
///
/// ## Derives
///
/// - `Clone`: Required for state snapshots and cloning.
/// - `Debug`: Required for logging and diagnostics.
/// - `Serialize`, `Deserialize`: Required for LMDB persistence and state root.
/// - `PartialEq`: Safe because all fields implement `PartialEq`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ServiceNodeRecord {
    /// Wallet address of the node operator (primary key).
    pub operator_address: Address,

    /// Ed25519 public key uniquely identifying the node.
    pub node_id: [u8; 32],

    /// Node role classification (Storage or Compute).
    pub class: NodeClass,

    /// Current lifecycle status of the node.
    pub status: NodeStatus,

    /// Amount of NUSA staked by this node (smallest unit, not human-readable).
    pub staked_amount: u128,

    /// Block height at which this node was first registered.
    pub registered_height: u64,

    /// Block height at which the node's status was last changed.
    pub last_status_change_height: u64,

    /// Optional cooldown period (set when node is banned/penalized).
    pub cooldown: Option<CooldownPeriod>,

    /// Optional SHA-256 fingerprint of the node's TLS certificate (DER-encoded).
    pub tls_fingerprint: Option<[u8; 32]>,

    /// Arbitrary key-value metadata for extensibility.
    pub metadata: HashMap<String, String>,
}