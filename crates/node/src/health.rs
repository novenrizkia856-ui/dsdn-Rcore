//! Node Health Reporting Module
//!
//! This module provides health reporting mechanisms for DSDN storage nodes.
//! Health reports are based on DA connectivity, state consistency, and storage status.
//!
//! ## Core Principles
//!
//! - **Honest Reporting**: Health is computed from actual state, never optimistic
//! - **DA-Based**: Health reflects DA connectivity and synchronization status
//! - **Auditable**: All health metrics are deterministic and verifiable
//! - **No Silent Failures**: All issues are surfaced in health reports
//!
//! ## Health Check Flow
//!
//! ```text
//! DA Layer ──────┐
//!                │
//! Local State ───┼──▶ NodeHealth::check() ──▶ NodeHealth
//!                │
//! Storage ───────┘
//! ```
//!
//! ## Healthy Node Criteria
//!
//! A node is considered healthy if and only if:
//! - DA is connected
//! - No chunks are missing
//! - DA lag is within acceptable threshold
//! - Storage is not overflowing
//!
//! ## Identity Extension (14B.48)
//!
//! `NodeHealth` carries optional identity/gating fields populated by
//! [`health_endpoint_extended`]. These fields (`node_id_hex`,
//! `operator_address_hex`, `node_class`, `gating_status`, `tls_valid`,
//! `tls_expires_at`, `staked_amount`) are all `Option<T>` with
//! `#[serde(skip_serializing_if)]`, so they are omitted from JSON
//! when absent. This preserves backward compatibility: old consumers
//! see no unknown fields, and old JSON without these fields still
//! deserializes correctly via `#[serde(default)]`.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use dsdn_common::gating::{NodeClass, NodeStatus};

use crate::da_follower::{NodeDerivedState, ReplicaStatus};
use crate::identity_manager::NodeIdentityManager;
use crate::multi_da_source::DASourceType;
use crate::tls_manager::TLSCertManager;

// ════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════

/// Maximum acceptable DA lag (in sequence numbers) before node is considered unhealthy.
/// This threshold allows for brief network delays while catching significant sync issues.
pub const DA_LAG_THRESHOLD: u64 = 100;

/// Maximum duration (in milliseconds) in fallback mode before health is degraded.
/// 5 minutes = 300,000 milliseconds.
///
/// If a node has been in fallback mode longer than this, it is considered degraded.
/// This threshold is chosen to allow for brief primary outages while detecting
/// extended fallback situations that may indicate infrastructure issues.
pub const FALLBACK_DEGRADATION_THRESHOLD_MS: u64 = 300_000;

// ════════════════════════════════════════════════════════════════════════════
// HEALTH STORAGE TRAIT
// ════════════════════════════════════════════════════════════════════════════

/// Abstraction for storage metrics needed by health reporting.
///
/// This trait provides storage usage information for health checks.
pub trait HealthStorage: Send + Sync {
    /// Get the current storage usage in bytes.
    fn storage_used_bytes(&self) -> u64;

    /// Get the total storage capacity in bytes.
    fn storage_capacity_bytes(&self) -> u64;
}

// ════════════════════════════════════════════════════════════════════════════
// DA INFO TRAIT
// ════════════════════════════════════════════════════════════════════════════

/// Abstraction for DA layer information needed by health reporting.
///
/// This trait provides DA connectivity and sequence information for health checks.
pub trait DAInfo: Send + Sync {
    /// Check if DA layer is connected and reachable.
    fn is_connected(&self) -> bool;

    /// Get the latest known sequence number from DA.
    fn latest_sequence(&self) -> u64;
}

// ════════════════════════════════════════════════════════════════════════════
// NODE HEALTH STRUCT
// ════════════════════════════════════════════════════════════════════════════

/// Health report for a DSDN storage node.
///
/// This struct contains all metrics necessary to assess node health.
/// All fields are computed from actual state, never estimated.
///
/// ## Field Definitions
///
/// | Field | Description |
/// |-------|-------------|
/// | node_id | Unique identifier of the node |
/// | da_connected | Whether DA layer is reachable |
/// | da_last_sequence | Last sequence processed by node |
/// | da_behind_by | Gap between node and DA latest |
/// | chunks_stored | Replicas successfully stored |
/// | chunks_pending | Replicas assigned but not yet stored |
/// | chunks_missing | Replicas that should exist but don't |
/// | storage_used_gb | Current storage usage in GB |
/// | storage_capacity_gb | Total storage capacity in GB |
/// | last_check | Timestamp of this health check |
/// | fallback_active | Whether node is in fallback mode (14A.1A.47) |
/// | da_source | Current DA source type as string (14A.1A.47) |
/// | events_from_fallback | Count of events from fallback sources (14A.1A.47) |
/// | last_primary_contact | Timestamp of last primary contact (14A.1A.47) |
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeHealth {
    /// Unique identifier of the node.
    pub node_id: String,
    /// Whether DA layer is connected and reachable.
    pub da_connected: bool,
    /// Last sequence number processed by the node.
    pub da_last_sequence: u64,
    /// Number of sequences behind DA latest.
    pub da_behind_by: u64,
    /// Number of chunks successfully stored locally.
    pub chunks_stored: usize,
    /// Number of chunks assigned but not yet stored (pending fetch).
    pub chunks_pending: usize,
    /// Number of chunks that should exist but are missing or corrupted.
    pub chunks_missing: usize,
    /// Storage space used in gigabytes.
    pub storage_used_gb: f64,
    /// Total storage capacity in gigabytes.
    pub storage_capacity_gb: f64,
    /// Unix timestamp (milliseconds) of this health check.
    pub last_check: u64,

    // ════════════════════════════════════════════════════════════════════════
    // FALLBACK AWARENESS FIELDS (14A.1A.47)
    // ════════════════════════════════════════════════════════════════════════

    /// Whether the node is currently in fallback mode.
    ///
    /// `true` indicates the node is reading from a fallback DA source
    /// (Secondary or Emergency) instead of Primary.
    pub fallback_active: bool,

    /// Current DA source type as a string.
    ///
    /// Possible values: "Primary", "Secondary", "Emergency".
    /// Always reflects the actual source being used.
    pub da_source: String,

    /// Total count of events processed from fallback sources.
    ///
    /// Monotonically increasing counter. Helps track how much data
    /// was read from fallback sources over time.
    pub events_from_fallback: u64,

    /// Unix timestamp (milliseconds) of last contact with primary DA.
    ///
    /// `Some(timestamp)` - Last time primary was successfully used
    /// `None` - Primary has never been successfully contacted or data unavailable
    ///
    /// This is computed from fallback_since: if fallback is active,
    /// last_primary_contact = fallback_since (when we left primary).
    /// If fallback is not active, last_primary_contact = last_check (now).
    pub last_primary_contact: Option<u64>,

    // ════════════════════════════════════════════════════════════════════════
    // IDENTITY EXTENSION FIELDS (14B.48)
    // ════════════════════════════════════════════════════════════════════════

    /// Ed25519 public key as 64-character lowercase hex string.
    /// Populated by [`set_identity_context`] when a [`NodeIdentityManager`]
    /// is available. No `0x` prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id_hex: Option<String>,

    /// Operator address as 40-character lowercase hex string.
    /// Derived from `node_id[12..32]`. No `0x` prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_address_hex: Option<String>,

    /// Node class: "Storage" or "Compute".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_class: Option<String>,

    /// Gating status: "Active", "Pending", "Quarantined", or "Banned".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gating_status: Option<String>,

    /// Whether the TLS certificate is valid at the check timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_valid: Option<bool>,

    /// TLS certificate expiry timestamp (seconds since Unix epoch).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_expires_at: Option<u64>,

    /// Staked amount as a decimal string (u128 via `to_string()`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub staked_amount: Option<String>,
}

impl NodeHealth {
    /// Perform a health check and return the current health status.
    ///
    /// This method queries DA, state, and storage to build an accurate
    /// health report.
    ///
    /// # Arguments
    ///
    /// * `node_id` - Unique identifier of this node
    /// * `da` - DA layer info provider
    /// * `state` - Node's derived state
    /// * `storage` - Storage metrics provider
    ///
    /// # Returns
    ///
    /// A `NodeHealth` struct with current health metrics.
    ///
    /// # Guarantees
    ///
    /// - Never panics
    /// - All fields are computed from actual state
    /// - If DA is unreachable, da_connected = false but other fields are still filled
    /// - Fallback fields are populated from NodeDerivedState (14A.1A.47)
    pub fn check(
        node_id: &str,
        da: &dyn DAInfo,
        state: &NodeDerivedState,
        storage: &dyn HealthStorage,
    ) -> Self {
        // Query DA status
        let da_connected = da.is_connected();
        let da_latest = da.latest_sequence();
        let da_last_sequence = state.last_sequence;

        // Calculate lag (handle case where local is ahead due to timing)
        let da_behind_by = if da_latest > da_last_sequence {
            da_latest - da_last_sequence
        } else {
            0
        };

        // Count chunks by status
        let (chunks_stored, chunks_pending, chunks_missing) = Self::count_chunk_status(state);

        // Get storage metrics
        let storage_used_bytes = storage.storage_used_bytes();
        let storage_capacity_bytes = storage.storage_capacity_bytes();

        // Convert to GB (1 GB = 1024^3 bytes)
        const GB: f64 = 1024.0 * 1024.0 * 1024.0;
        let storage_used_gb = storage_used_bytes as f64 / GB;
        let storage_capacity_gb = storage_capacity_bytes as f64 / GB;

        // Get current timestamp
        let last_check = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        // ════════════════════════════════════════════════════════════════════════
        // FALLBACK AWARENESS (14A.1A.47)
        // ════════════════════════════════════════════════════════════════════════

        // Get fallback status from state
        let fallback_active = state.fallback_active;

        // Convert DA source type to string
        let da_source = Self::da_source_to_string(state.current_da_source);

        // Get events from fallback counter
        let events_from_fallback = state.events_from_fallback;

        // Compute last_primary_contact:
        // - If not in fallback: primary is currently active, so last contact is now
        // - If in fallback: last primary contact was when fallback started (fallback_since)
        let last_primary_contact = if fallback_active {
            // In fallback mode: use fallback_since as last primary contact
            state.fallback_since
        } else {
            // Not in fallback: primary is active now
            Some(last_check)
        };

        Self {
            node_id: node_id.to_string(),
            da_connected,
            da_last_sequence,
            da_behind_by,
            chunks_stored,
            chunks_pending,
            chunks_missing,
            storage_used_gb,
            storage_capacity_gb,
            last_check,
            // Fallback fields (14A.1A.47)
            fallback_active,
            da_source,
            events_from_fallback,
            last_primary_contact,
            // Identity extension fields (14B.48) — None until set_identity_context
            node_id_hex: None,
            operator_address_hex: None,
            node_class: None,
            gating_status: None,
            tls_valid: None,
            tls_expires_at: None,
            staked_amount: None,
        }
    }

    /// Convert DASourceType to string representation.
    ///
    /// This is a deterministic mapping, never panics.
    fn da_source_to_string(source: DASourceType) -> String {
        match source {
            DASourceType::Primary => "Primary".to_string(),
            DASourceType::Secondary => "Secondary".to_string(),
            DASourceType::Emergency => "Emergency".to_string(),
        }
    }

    /// Populates identity, gating, TLS, and stake fields from optional context.
    ///
    /// Called after `check()` to enrich the health report with identity
    /// information. All parameters are optional — `None` inputs leave
    /// the corresponding fields as `None`.
    ///
    /// ## Parameters
    ///
    /// - `identity`: Populates `node_id_hex` (64-char hex) and
    ///   `operator_address_hex` (40-char hex).
    /// - `tls`: Populates `tls_valid` and `tls_expires_at`.
    /// - `gating_status`: Populates `gating_status` as exact string.
    /// - `node_class`: Populates `node_class` as exact string.
    /// - `staked_amount`: Populates `staked_amount` as decimal string.
    /// - `tls_check_timestamp`: Unix timestamp (seconds) for TLS validity.
    ///
    /// ## Security
    ///
    /// Only public identity information is exposed (public key, operator
    /// address). Secret key material is never accessed or stored.
    pub fn set_identity_context(
        &mut self,
        identity: Option<&NodeIdentityManager>,
        tls: Option<&TLSCertManager>,
        gating_status: Option<NodeStatus>,
        node_class: Option<NodeClass>,
        staked_amount: Option<u128>,
        tls_check_timestamp: u64,
    ) {
        if let Some(mgr) = identity {
            self.node_id_hex = Some(bytes_to_lower_hex(mgr.node_id()));
            self.operator_address_hex = Some(bytes_to_lower_hex(mgr.operator_address()));
        }

        if let Some(tls_mgr) = tls {
            self.tls_valid = Some(tls_mgr.is_valid(tls_check_timestamp));
            self.tls_expires_at = Some(tls_mgr.cert_info().not_after);
        }

        if let Some(status) = gating_status {
            self.gating_status = Some(node_status_to_string(status));
        }

        if let Some(class) = node_class {
            self.node_class = Some(node_class_to_string(class));
        }

        if let Some(stake) = staked_amount {
            self.staked_amount = Some(stake.to_string());
        }
    }

    /// Count chunks by status category.
    ///
    /// Returns (stored, pending, missing) counts.
    fn count_chunk_status(state: &NodeDerivedState) -> (usize, usize, usize) {
        let mut stored = 0usize;
        let mut pending = 0usize;
        let mut missing = 0usize;

        for status in state.replica_status.values() {
            match status {
                ReplicaStatus::Stored | ReplicaStatus::Verified => {
                    stored += 1;
                }
                ReplicaStatus::Pending => {
                    pending += 1;
                }
                ReplicaStatus::Missing | ReplicaStatus::Corrupted => {
                    missing += 1;
                }
            }
        }

        (stored, pending, missing)
    }

    /// Check if the node is healthy.
    ///
    /// A node is considered healthy if and only if:
    /// - DA is connected
    /// - No chunks are missing
    /// - DA lag is within acceptable threshold (< 100 sequences)
    /// - Storage is not overflowing
    /// - Not in extended fallback (> 5 minutes) (14A.1A.47)
    ///
    /// # Returns
    ///
    /// `true` if all health criteria are met, `false` otherwise.
    pub fn is_healthy(&self) -> bool {
        // Criterion 1: DA must be connected
        if !self.da_connected {
            return false;
        }

        // Criterion 2: No missing chunks
        if self.chunks_missing > 0 {
            return false;
        }

        // Criterion 3: DA lag within threshold
        if self.da_behind_by >= DA_LAG_THRESHOLD {
            return false;
        }

        // Criterion 4: Storage not overflowing
        if self.storage_used_gb > self.storage_capacity_gb {
            return false;
        }

        // Criterion 5 (14A.1A.47): Not in extended fallback
        if self.is_fallback_degraded() {
            return false;
        }

        true
    }

    /// Check if node is degraded due to extended fallback.
    ///
    /// A node is considered degraded if it has been in fallback mode
    /// for longer than FALLBACK_DEGRADATION_THRESHOLD_MS.
    ///
    /// # Returns
    ///
    /// `true` if in extended fallback, `false` otherwise.
    ///
    /// # Guarantees
    ///
    /// - Deterministic: same inputs always give same output
    /// - No flip-flop: consistent with fallback_active and last_primary_contact
    /// - Never panics
    pub fn is_fallback_degraded(&self) -> bool {
        // Not degraded if not in fallback
        if !self.fallback_active {
            return false;
        }

        // Check if we have last_primary_contact to compute duration
        let Some(last_primary) = self.last_primary_contact else {
            // If no last_primary_contact but fallback is active,
            // we cannot determine duration - treat as not degraded
            // to avoid false positives
            return false;
        };

        // Compute duration in fallback (current time - last primary contact)
        // Use saturating subtraction to prevent underflow
        let fallback_duration = self.last_check.saturating_sub(last_primary);

        // Degraded if in fallback longer than threshold
        fallback_duration >= FALLBACK_DEGRADATION_THRESHOLD_MS
    }

    /// Convert health report to JSON string.
    ///
    /// # Returns
    ///
    /// A valid JSON string representing the health report.
    ///
    /// # Guarantees
    ///
    /// - Output is always valid JSON
    /// - All fields are represented
    /// - Deterministic (same input → same output)
    /// - Never panics
    pub fn to_json(&self) -> String {
        // Use serde_json for reliable serialization
        // Fall back to manual JSON if serde fails (should never happen)
        serde_json::to_string(self).unwrap_or_else(|_| self.to_json_manual())
    }

    /// Convert health report to pretty-printed JSON string.
    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| self.to_json_manual())
    }

    /// Manual JSON serialization fallback.
    ///
    /// Covers core fields only. Identity extension fields (14B.48) are
    /// omitted in this fallback path since serde_json is the primary
    /// serializer and this path is only reached on serialization failure.
    fn to_json_manual(&self) -> String {
        // Handle Option<u64> for last_primary_contact
        let last_primary_str = match self.last_primary_contact {
            Some(ts) => ts.to_string(),
            None => "null".to_string(),
        };

        format!(
            r#"{{"node_id":"{}","da_connected":{},"da_last_sequence":{},"da_behind_by":{},"chunks_stored":{},"chunks_pending":{},"chunks_missing":{},"storage_used_gb":{},"storage_capacity_gb":{},"last_check":{},"fallback_active":{},"da_source":"{}","events_from_fallback":{},"last_primary_contact":{}}}"#,
            self.node_id,
            self.da_connected,
            self.da_last_sequence,
            self.da_behind_by,
            self.chunks_stored,
            self.chunks_pending,
            self.chunks_missing,
            self.storage_used_gb,
            self.storage_capacity_gb,
            self.last_check,
            self.fallback_active,
            self.da_source,
            self.events_from_fallback,
            last_primary_str
        )
    }

    /// Get a summary of health issues (if any).
    ///
    /// # Returns
    ///
    /// A vector of strings describing each health issue.
    /// Empty if node is healthy.
    pub fn health_issues(&self) -> Vec<String> {
        let mut issues = Vec::new();

        if !self.da_connected {
            issues.push("DA layer disconnected".to_string());
        }

        if self.chunks_missing > 0 {
            issues.push(format!("{} chunks missing", self.chunks_missing));
        }

        if self.da_behind_by >= DA_LAG_THRESHOLD {
            issues.push(format!(
                "DA lag too high: {} sequences behind (threshold: {})",
                self.da_behind_by, DA_LAG_THRESHOLD
            ));
        }

        if self.storage_used_gb > self.storage_capacity_gb {
            issues.push(format!(
                "Storage overflow: {:.2} GB used / {:.2} GB capacity",
                self.storage_used_gb, self.storage_capacity_gb
            ));
        }

        // Fallback-related issues (14A.1A.47)
        if self.is_fallback_degraded() {
            let duration_ms = self.last_primary_contact
                .map(|lp| self.last_check.saturating_sub(lp))
                .unwrap_or(0);
            let duration_min = duration_ms / 60_000;
            issues.push(format!(
                "Extended fallback: in {} mode for {} minutes (threshold: {} minutes)",
                self.da_source,
                duration_min,
                FALLBACK_DEGRADATION_THRESHOLD_MS / 60_000
            ));
        } else if self.fallback_active {
            // Fallback is active but not yet degraded - informational
            // Not adding to issues since it's not unhealthy yet
        }

        issues
    }
}

impl Default for NodeHealth {
    fn default() -> Self {
        Self {
            node_id: String::new(),
            da_connected: false,
            da_last_sequence: 0,
            da_behind_by: 0,
            chunks_stored: 0,
            chunks_pending: 0,
            chunks_missing: 0,
            storage_used_gb: 0.0,
            storage_capacity_gb: 0.0,
            last_check: 0,
            // Fallback fields (14A.1A.47)
            fallback_active: false,
            da_source: "Primary".to_string(),
            events_from_fallback: 0,
            last_primary_contact: None,
            // Identity extension fields (14B.48)
            node_id_hex: None,
            operator_address_hex: None,
            node_class: None,
            gating_status: None,
            tls_valid: None,
            tls_expires_at: None,
            staked_amount: None,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// HEALTH ENDPOINT
// ════════════════════════════════════════════════════════════════════════════

/// HTTP response for health endpoint.
///
/// Contains the health report and appropriate HTTP metadata.
#[derive(Debug, Clone)]
pub struct HealthResponse {
    /// HTTP status code (200 for healthy, 503 for unhealthy).
    pub status_code: u16,
    /// Content-Type header value.
    pub content_type: &'static str,
    /// Response body (JSON).
    pub body: String,
}

impl HealthResponse {
    /// Create a new health response from a NodeHealth report.
    pub fn from_health(health: &NodeHealth) -> Self {
        let status_code = if health.is_healthy() { 200 } else { 503 };

        Self {
            status_code,
            content_type: "application/json",
            body: health.to_json(),
        }
    }
}

/// Handler for the /health endpoint.
///
/// This function performs a health check and returns a response
/// suitable for HTTP serving.
///
/// # Arguments
///
/// * `node_id` - Unique identifier of this node
/// * `da` - DA layer info provider
/// * `state` - Node's derived state
/// * `storage` - Storage metrics provider
///
/// # Returns
///
/// A `HealthResponse` containing the HTTP response.
///
/// # Guarantees
///
/// - Read-only (does not modify state)
/// - Never panics
/// - Always returns a valid response
pub fn health_endpoint(
    node_id: &str,
    da: &dyn DAInfo,
    state: &NodeDerivedState,
    storage: &dyn HealthStorage,
) -> HealthResponse {
    let health = NodeHealth::check(node_id, da, state, storage);
    HealthResponse::from_health(&health)
}

/// Extended health endpoint with identity, gating, TLS, and stake context.
///
/// Performs a standard health check via [`NodeHealth::check`], then enriches
/// the result with optional identity-related information via
/// [`NodeHealth::set_identity_context`].
///
/// # Backward Compatibility
///
/// All identity fields are `Option<T>` with `skip_serializing_if`.
/// When all optional parameters are `None`, the JSON output is identical
/// to [`health_endpoint`]. Old consumers are unaffected.
///
/// # Guarantees
///
/// - Read-only (does not modify any input)
/// - Never panics
/// - Deterministic: same inputs → same JSON
pub fn health_endpoint_extended(
    node_id: &str,
    da: &dyn DAInfo,
    state: &NodeDerivedState,
    storage: &dyn HealthStorage,
    identity: Option<&NodeIdentityManager>,
    tls: Option<&TLSCertManager>,
    gating_status: Option<NodeStatus>,
    node_class: Option<NodeClass>,
    staked_amount: Option<u128>,
    tls_check_timestamp: u64,
) -> HealthResponse {
    let mut health = NodeHealth::check(node_id, da, state, storage);
    health.set_identity_context(
        identity,
        tls,
        gating_status,
        node_class,
        staked_amount,
        tls_check_timestamp,
    );
    HealthResponse::from_health(&health)
}

// ════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS — IDENTITY EXTENSION (14B.48)
// ════════════════════════════════════════════════════════════════════════════

/// Lowercase hex digit lookup table.
const HEX_CHARS: [u8; 16] = *b"0123456789abcdef";

/// Converts a byte slice to a lowercase hex string.
///
/// No `0x` prefix. No separators. Deterministic.
fn bytes_to_lower_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        hex.push(HEX_CHARS[(b >> 4) as usize] as char);
        hex.push(HEX_CHARS[(b & 0x0F) as usize] as char);
    }
    hex
}

/// Converts a `NodeStatus` to its exact string representation.
fn node_status_to_string(status: NodeStatus) -> String {
    match status {
        NodeStatus::Active => "Active".to_string(),
        NodeStatus::Pending => "Pending".to_string(),
        NodeStatus::Quarantined => "Quarantined".to_string(),
        NodeStatus::Banned => "Banned".to_string(),
    }
}

/// Converts a `NodeClass` to its exact string representation.
fn node_class_to_string(class: NodeClass) -> String {
    match class {
        NodeClass::Storage => "Storage".to_string(),
        NodeClass::Compute => "Compute".to_string(),
    }
}

// ════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::da_follower::ChunkAssignment;

    const TEST_NODE: &str = "test-node-1";

    const TEST_SEED: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    ];

    /// Helper: build a default NodeHealth, then apply overrides.
    fn base_health(overrides: impl FnOnce(&mut NodeHealth)) -> NodeHealth {
        let mut h = NodeHealth::default();
        overrides(&mut h);
        h
    }

    // ════════════════════════════════════════════════════════════════════════
    // MOCK DA INFO
    // ════════════════════════════════════════════════════════════════════════

    struct MockDAInfo {
        connected: bool,
        latest_seq: u64,
    }

    impl MockDAInfo {
        fn new(connected: bool, latest_seq: u64) -> Self {
            Self {
                connected,
                latest_seq,
            }
        }
    }

    impl DAInfo for MockDAInfo {
        fn is_connected(&self) -> bool {
            self.connected
        }

        fn latest_sequence(&self) -> u64 {
            self.latest_seq
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // MOCK HEALTH STORAGE
    // ════════════════════════════════════════════════════════════════════════

    struct MockHealthStorage {
        used_bytes: u64,
        capacity_bytes: u64,
    }

    impl MockHealthStorage {
        fn new(used_bytes: u64, capacity_bytes: u64) -> Self {
            Self {
                used_bytes,
                capacity_bytes,
            }
        }
    }

    impl HealthStorage for MockHealthStorage {
        fn storage_used_bytes(&self) -> u64 {
            self.used_bytes
        }

        fn storage_capacity_bytes(&self) -> u64 {
            self.capacity_bytes
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // HELPER FUNCTIONS
    // ════════════════════════════════════════════════════════════════════════

    fn make_state_with_replicas(
        last_sequence: u64,
        stored: usize,
        pending: usize,
        missing: usize,
    ) -> NodeDerivedState {
        let mut state = NodeDerivedState::new();
        state.last_sequence = last_sequence;

        let mut counter = 0;

        // Add stored chunks
        for i in 0..stored {
            let hash = format!("stored-chunk-{}", i);
            state.my_chunks.insert(
                hash.clone(),
                ChunkAssignment {
                    hash: hash.clone(),
                    replica_index: counter,
                    assigned_at: 1000,
                    verified: true,
                    size_bytes: 1024,
                },
            );
            state.replica_status.insert(hash, ReplicaStatus::Stored);
            counter += 1;
        }

        // Add pending chunks
        for i in 0..pending {
            let hash = format!("pending-chunk-{}", i);
            state.my_chunks.insert(
                hash.clone(),
                ChunkAssignment {
                    hash: hash.clone(),
                    replica_index: counter,
                    assigned_at: 1000,
                    verified: false,
                    size_bytes: 1024,
                },
            );
            state.replica_status.insert(hash, ReplicaStatus::Pending);
            counter += 1;
        }

        // Add missing chunks
        for i in 0..missing {
            let hash = format!("missing-chunk-{}", i);
            state.my_chunks.insert(
                hash.clone(),
                ChunkAssignment {
                    hash: hash.clone(),
                    replica_index: counter,
                    assigned_at: 1000,
                    verified: false,
                    size_bytes: 1024,
                },
            );
            state.replica_status.insert(hash, ReplicaStatus::Missing);
            counter += 1;
        }

        state
    }

    fn make_empty_state() -> NodeDerivedState {
        NodeDerivedState::new()
    }

    // 100 GB in bytes
    const GB_100: u64 = 100 * 1024 * 1024 * 1024;
    const GB_50: u64 = 50 * 1024 * 1024 * 1024;

    // ════════════════════════════════════════════════════════════════════════
    // A. HEALTHY NODE TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_healthy_node() {
        let da = MockDAInfo::new(true, 100);
        let state = make_state_with_replicas(100, 10, 0, 0);
        let storage = MockHealthStorage::new(GB_50, GB_100);

        let health = NodeHealth::check(TEST_NODE, &da, &state, &storage);

        assert!(health.is_healthy());
        assert!(health.da_connected);
        assert_eq!(health.da_last_sequence, 100);
        assert_eq!(health.da_behind_by, 0);
        assert_eq!(health.chunks_stored, 10);
        assert_eq!(health.chunks_pending, 0);
        assert_eq!(health.chunks_missing, 0);
    }

    #[test]
    fn test_healthy_node_with_pending() {
        let da = MockDAInfo::new(true, 100);
        let state = make_state_with_replicas(100, 5, 3, 0);
        let storage = MockHealthStorage::new(GB_50, GB_100);

        let health = NodeHealth::check(TEST_NODE, &da, &state, &storage);

        // Pending chunks don't make node unhealthy
        assert!(health.is_healthy());
        assert_eq!(health.chunks_stored, 5);
        assert_eq!(health.chunks_pending, 3);
        assert_eq!(health.chunks_missing, 0);
    }

    #[test]
    fn test_healthy_node_with_small_lag() {
        let da = MockDAInfo::new(true, 150);
        let state = make_state_with_replicas(100, 10, 0, 0);
        let storage = MockHealthStorage::new(GB_50, GB_100);

        let health = NodeHealth::check(TEST_NODE, &da, &state, &storage);

        // 50 sequences behind is within threshold
        assert!(health.is_healthy());
        assert_eq!(health.da_behind_by, 50);
    }

    // ════════════════════════════════════════════════════════════════════════
    // B. DA DISCONNECTED TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_da_disconnected() {
        let da = MockDAInfo::new(false, 0);
        let state = make_state_with_replicas(100, 10, 0, 0);
        let storage = MockHealthStorage::new(GB_50, GB_100);

        let health = NodeHealth::check(TEST_NODE, &da, &state, &storage);

        assert!(!health.is_healthy());
        assert!(!health.da_connected);

        let issues = health.health_issues();
        assert!(issues.iter().any(|i| i.contains("disconnected")));
    }

    #[test]
    fn test_da_disconnected_other_fields_valid() {
        let da = MockDAInfo::new(false, 0);
        let state = make_state_with_replicas(50, 5, 2, 1);
        let storage = MockHealthStorage::new(GB_50, GB_100);

        let health = NodeHealth::check(TEST_NODE, &da, &state, &storage);

        // Other fields should still be computed correctly
        assert_eq!(health.da_last_sequence, 50);
        assert_eq!(health.chunks_stored, 5);
        assert_eq!(health.chunks_pending, 2);
        assert_eq!(health.chunks_missing, 1);
    }

    // ════════════════════════════════════════════════════════════════════════
    // C. MISSING CHUNKS TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_missing_chunks() {
        let da = MockDAInfo::new(true, 100);
        let state = make_state_with_replicas(100, 10, 0, 3);
        let storage = MockHealthStorage::new(GB_50, GB_100);

        let health = NodeHealth::check(TEST_NODE, &da, &state, &storage);

        assert!(!health.is_healthy());
        assert_eq!(health.chunks_missing, 3);

        let issues = health.health_issues();
        assert!(issues.iter().any(|i| i.contains("missing")));
    }

    #[test]
    fn test_corrupted_chunks_count_as_missing() {
        let mut state = make_state_with_replicas(100, 5, 0, 0);

        // Add corrupted chunk
        let hash = "corrupted-chunk";
        state.my_chunks.insert(
            hash.to_string(),
            ChunkAssignment {
                hash: hash.to_string(),
                replica_index: 10,
                assigned_at: 1000,
                verified: false,
                size_bytes: 1024,
            },
        );
        state.replica_status.insert(hash.to_string(), ReplicaStatus::Corrupted);

        let da = MockDAInfo::new(true, 100);
        let storage = MockHealthStorage::new(GB_50, GB_100);

        let health = NodeHealth::check(TEST_NODE, &da, &state, &storage);

        // Corrupted counts as missing
        assert!(!health.is_healthy());
        assert_eq!(health.chunks_missing, 1);
    }

    // ════════════════════════════════════════════════════════════════════════
    // D. STORAGE OVERFLOW TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_storage_overflow() {
        let da = MockDAInfo::new(true, 100);
        let state = make_state_with_replicas(100, 10, 0, 0);
        // Used > Capacity
        let storage = MockHealthStorage::new(GB_100 + 1024, GB_100);

        let health = NodeHealth::check(TEST_NODE, &da, &state, &storage);

        assert!(!health.is_healthy());
        assert!(health.storage_used_gb > health.storage_capacity_gb);

        let issues = health.health_issues();
        assert!(issues.iter().any(|i| i.contains("overflow")));
    }

    #[test]
    fn test_storage_at_capacity() {
        let da = MockDAInfo::new(true, 100);
        let state = make_state_with_replicas(100, 10, 0, 0);
        // Used == Capacity (exactly at limit, still healthy)
        let storage = MockHealthStorage::new(GB_100, GB_100);

        let health = NodeHealth::check(TEST_NODE, &da, &state, &storage);

        // At capacity but not over - should be healthy
        assert!(health.is_healthy());
    }

    // ════════════════════════════════════════════════════════════════════════
    // E. DA LAG TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_da_lag_at_threshold() {
        let da = MockDAInfo::new(true, 200);
        let state = make_state_with_replicas(100, 10, 0, 0);
        let storage = MockHealthStorage::new(GB_50, GB_100);

        let health = NodeHealth::check(TEST_NODE, &da, &state, &storage);

        // Exactly at threshold (100) - unhealthy
        assert!(!health.is_healthy());
        assert_eq!(health.da_behind_by, 100);

        let issues = health.health_issues();
        assert!(issues.iter().any(|i| i.contains("lag")));
    }

    #[test]
    fn test_da_lag_below_threshold() {
        let da = MockDAInfo::new(true, 199);
        let state = make_state_with_replicas(100, 10, 0, 0);
        let storage = MockHealthStorage::new(GB_50, GB_100);

        let health = NodeHealth::check(TEST_NODE, &da, &state, &storage);

        // Just below threshold (99) - healthy
        assert!(health.is_healthy());
        assert_eq!(health.da_behind_by, 99);
    }

    #[test]
    fn test_da_local_ahead() {
        let da = MockDAInfo::new(true, 50);
        let state = make_state_with_replicas(100, 10, 0, 0);
        let storage = MockHealthStorage::new(GB_50, GB_100);

        let health = NodeHealth::check(TEST_NODE, &da, &state, &storage);

        // Local ahead of DA (shouldn't happen but handled gracefully)
        assert!(health.is_healthy());
        assert_eq!(health.da_behind_by, 0);
    }

    // ════════════════════════════════════════════════════════════════════════
    // F. JSON VALIDITY TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_to_json_valid() {
        let da = MockDAInfo::new(true, 100);
        let state = make_state_with_replicas(100, 10, 2, 1);
        let storage = MockHealthStorage::new(GB_50, GB_100);

        let health = NodeHealth::check(TEST_NODE, &da, &state, &storage);
        let json = health.to_json();

        // Should be parseable
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&json);
        assert!(parsed.is_ok());

        if let Ok(value) = parsed {
            assert_eq!(value["node_id"], TEST_NODE);
            assert_eq!(value["da_connected"], true);
            assert_eq!(value["chunks_stored"], 10);
            assert_eq!(value["chunks_pending"], 2);
            assert_eq!(value["chunks_missing"], 1);
            // Identity fields absent when None (14B.48)
            assert!(value.get("node_id_hex").is_none());
            assert!(value.get("gating_status").is_none());
        }
    }

    #[test]
    fn test_to_json_all_fields_present() {
        let health = NodeHealth::default();
        let json = health.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json)
            .expect("test: parse JSON");

        // All fields must be present
        assert!(parsed.get("node_id").is_some());
        assert!(parsed.get("da_connected").is_some());
        assert!(parsed.get("da_last_sequence").is_some());
        assert!(parsed.get("da_behind_by").is_some());
        assert!(parsed.get("chunks_stored").is_some());
        assert!(parsed.get("chunks_pending").is_some());
        assert!(parsed.get("chunks_missing").is_some());
        assert!(parsed.get("storage_used_gb").is_some());
        assert!(parsed.get("storage_capacity_gb").is_some());
        assert!(parsed.get("last_check").is_some());
    }

    #[test]
    fn test_to_json_deterministic() {
        let da = MockDAInfo::new(true, 100);
        let state = make_state_with_replicas(100, 10, 0, 0);
        let storage = MockHealthStorage::new(GB_50, GB_100);

        let health = NodeHealth::check(TEST_NODE, &da, &state, &storage);

        let json1 = health.to_json();
        let json2 = health.to_json();

        // Should be identical
        assert_eq!(json1, json2);
    }

    // ════════════════════════════════════════════════════════════════════════
    // G. HEALTH ENDPOINT TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_health_endpoint_healthy() {
        let da = MockDAInfo::new(true, 100);
        let state = make_state_with_replicas(100, 10, 0, 0);
        let storage = MockHealthStorage::new(GB_50, GB_100);

        let response = health_endpoint(TEST_NODE, &da, &state, &storage);

        assert_eq!(response.status_code, 200);
        assert_eq!(response.content_type, "application/json");
        assert!(!response.body.is_empty());
    }

    #[test]
    fn test_health_endpoint_unhealthy() {
        let da = MockDAInfo::new(false, 100);
        let state = make_state_with_replicas(100, 10, 0, 0);
        let storage = MockHealthStorage::new(GB_50, GB_100);

        let response = health_endpoint(TEST_NODE, &da, &state, &storage);

        assert_eq!(response.status_code, 503);
        assert_eq!(response.content_type, "application/json");
    }

    // ════════════════════════════════════════════════════════════════════════
    // H. EMPTY STATE TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_empty_state_healthy() {
        let da = MockDAInfo::new(true, 0);
        let state = make_empty_state();
        let storage = MockHealthStorage::new(0, GB_100);

        let health = NodeHealth::check(TEST_NODE, &da, &state, &storage);

        // Empty state with DA connected should be healthy
        assert!(health.is_healthy());
        assert_eq!(health.chunks_stored, 0);
        assert_eq!(health.chunks_pending, 0);
        assert_eq!(health.chunks_missing, 0);
    }

    // ════════════════════════════════════════════════════════════════════════
    // I. VERIFIED CHUNKS TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_verified_chunks_count_as_stored() {
        let mut state = make_state_with_replicas(100, 0, 0, 0);

        // Add verified chunk
        let hash = "verified-chunk";
        state.my_chunks.insert(
            hash.to_string(),
            ChunkAssignment {
                hash: hash.to_string(),
                replica_index: 0,
                assigned_at: 1000,
                verified: true,
                size_bytes: 1024,
            },
        );
        state.replica_status.insert(hash.to_string(), ReplicaStatus::Verified);

        let da = MockDAInfo::new(true, 100);
        let storage = MockHealthStorage::new(GB_50, GB_100);

        let health = NodeHealth::check(TEST_NODE, &da, &state, &storage);

        // Verified counts as stored
        assert_eq!(health.chunks_stored, 1);
    }

    // ════════════════════════════════════════════════════════════════════════
    // J. HEALTH ISSUES TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_health_issues_empty_when_healthy() {
        let da = MockDAInfo::new(true, 100);
        let state = make_state_with_replicas(100, 10, 0, 0);
        let storage = MockHealthStorage::new(GB_50, GB_100);

        let health = NodeHealth::check(TEST_NODE, &da, &state, &storage);

        assert!(health.health_issues().is_empty());
    }

    #[test]
    fn test_health_issues_multiple() {
        let da = MockDAInfo::new(false, 300);
        let state = make_state_with_replicas(100, 5, 0, 3);
        let storage = MockHealthStorage::new(GB_100 + 1024, GB_100);

        let health = NodeHealth::check(TEST_NODE, &da, &state, &storage);

        let issues = health.health_issues();
        // Should have 4 issues: disconnected, missing, DA lag (200 >= 100), overflow
        assert_eq!(issues.len(), 4);
    }

    // ════════════════════════════════════════════════════════════════════════
    // K. STORAGE CONVERSION TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_storage_gb_conversion() {
        let da = MockDAInfo::new(true, 100);
        let state = make_empty_state();
        // Exactly 1 GB
        let one_gb = 1024 * 1024 * 1024;
        let storage = MockHealthStorage::new(one_gb, one_gb * 10);

        let health = NodeHealth::check(TEST_NODE, &da, &state, &storage);

        assert!((health.storage_used_gb - 1.0).abs() < 0.01);
        assert!((health.storage_capacity_gb - 10.0).abs() < 0.01);
    }

    // ════════════════════════════════════════════════════════════════════════
    // L. DEFAULT TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_default_health() {
        let health = NodeHealth::default();

        assert_eq!(health.node_id, "");
        assert!(!health.da_connected);
        assert_eq!(health.da_last_sequence, 0);
        assert_eq!(health.da_behind_by, 0);
        assert_eq!(health.chunks_stored, 0);
        assert_eq!(health.chunks_pending, 0);
        assert_eq!(health.chunks_missing, 0);
        assert_eq!(health.storage_used_gb, 0.0);
        assert_eq!(health.storage_capacity_gb, 0.0);
        assert_eq!(health.last_check, 0);

        // Fallback fields (14A.1A.47)
        assert!(!health.fallback_active);
        assert_eq!(health.da_source, "Primary");
        assert_eq!(health.events_from_fallback, 0);
        assert!(health.last_primary_contact.is_none());

        // Identity extension fields (14B.48)
        assert!(health.node_id_hex.is_none());
        assert!(health.operator_address_hex.is_none());
        assert!(health.node_class.is_none());
        assert!(health.gating_status.is_none());
        assert!(health.tls_valid.is_none());
        assert!(health.tls_expires_at.is_none());
        assert!(health.staked_amount.is_none());

        // Default is unhealthy (DA not connected)
        assert!(!health.is_healthy());
    }

    // ════════════════════════════════════════════════════════════════════════
    // M. NODE ID TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_node_id_preserved() {
        let da = MockDAInfo::new(true, 100);
        let state = make_empty_state();
        let storage = MockHealthStorage::new(0, GB_100);

        let health = NodeHealth::check("custom-node-id-123", &da, &state, &storage);

        assert_eq!(health.node_id, "custom-node-id-123");
    }

    // ════════════════════════════════════════════════════════════════════════
    // N. SAFETY TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_no_panic_zero_capacity() {
        let da = MockDAInfo::new(true, 100);
        let state = make_empty_state();
        let storage = MockHealthStorage::new(1000, 0); // Zero capacity

        // Should not panic
        let health = NodeHealth::check(TEST_NODE, &da, &state, &storage);

        // With zero capacity, any usage is overflow
        assert!(!health.is_healthy());
    }

    #[test]
    fn test_no_panic_large_values() {
        let da = MockDAInfo::new(true, u64::MAX);
        let state = make_state_with_replicas(u64::MAX - 50, 10, 0, 0);
        let storage = MockHealthStorage::new(u64::MAX, u64::MAX);

        // Should not panic
        let health = NodeHealth::check(TEST_NODE, &da, &state, &storage);

        assert_eq!(health.da_behind_by, 50);
    }

    // ════════════════════════════════════════════════════════════════════════
    // O. HEALTH RESPONSE TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_health_response_from_health() {
        let health = base_health(|h| {
            h.node_id = TEST_NODE.to_string();
            h.da_connected = true;
            h.da_last_sequence = 100;
            h.chunks_stored = 10;
            h.storage_used_gb = 50.0;
            h.storage_capacity_gb = 100.0;
            h.last_check = 12345;
            h.last_primary_contact = Some(12345);
        });

        let response = HealthResponse::from_health(&health);

        assert_eq!(response.status_code, 200);
        assert!(response.body.contains("test-node-1"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // P. FALLBACK AWARENESS TESTS (14A.1A.47)
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_health_includes_fallback_info_primary() {
        let da = MockDAInfo::new(true, 100);
        let state = make_empty_state();
        let storage = MockHealthStorage::new(0, GB_100);

        let health = NodeHealth::check(TEST_NODE, &da, &state, &storage);

        // Default state: not in fallback
        assert!(!health.fallback_active);
        assert_eq!(health.da_source, "Primary");
        assert_eq!(health.events_from_fallback, 0);
        // last_primary_contact should be approximately last_check
        assert!(health.last_primary_contact.is_some());
    }

    #[test]
    fn test_health_includes_fallback_info_secondary() {
        let da = MockDAInfo::new(true, 100);
        let mut state = make_empty_state();

        // Activate fallback to Secondary
        state.activate_fallback(1000, crate::multi_da_source::DASourceType::Secondary);
        state.record_fallback_event();
        state.record_fallback_event();

        let storage = MockHealthStorage::new(0, GB_100);

        let health = NodeHealth::check(TEST_NODE, &da, &state, &storage);

        assert!(health.fallback_active);
        assert_eq!(health.da_source, "Secondary");
        assert_eq!(health.events_from_fallback, 2);
        assert_eq!(health.last_primary_contact, Some(1000));
    }

    #[test]
    fn test_health_includes_fallback_info_emergency() {
        let da = MockDAInfo::new(true, 100);
        let mut state = make_empty_state();

        // Activate fallback to Emergency
        state.activate_fallback(2000, crate::multi_da_source::DASourceType::Emergency);
        state.record_fallback_event();

        let storage = MockHealthStorage::new(0, GB_100);

        let health = NodeHealth::check(TEST_NODE, &da, &state, &storage);

        assert!(health.fallback_active);
        assert_eq!(health.da_source, "Emergency");
        assert_eq!(health.events_from_fallback, 1);
        assert_eq!(health.last_primary_contact, Some(2000));
    }

    #[test]
    fn test_health_serialization_includes_fallback_fields() {
        let health = base_health(|h| {
            h.node_id = TEST_NODE.to_string();
            h.da_connected = true;
            h.da_last_sequence = 100;
            h.chunks_stored = 5;
            h.chunks_pending = 2;
            h.storage_used_gb = 10.0;
            h.storage_capacity_gb = 100.0;
            h.last_check = 50000;
            h.fallback_active = true;
            h.da_source = "Secondary".to_string();
            h.events_from_fallback = 42;
            h.last_primary_contact = Some(10000);
        });

        let json = health.to_json();

        assert!(json.contains("\"fallback_active\":true"));
        assert!(json.contains("\"da_source\":\"Secondary\""));
        assert!(json.contains("\"events_from_fallback\":42"));
        assert!(json.contains("\"last_primary_contact\":10000"));
    }

    #[test]
    fn test_health_serialization_null_last_primary_contact() {
        let health = base_health(|h| {
            h.node_id = TEST_NODE.to_string();
            h.da_connected = true;
            h.da_last_sequence = 100;
            h.storage_capacity_gb = 100.0;
            h.last_check = 50000;
        });

        let json = health.to_json();

        assert!(json.contains("\"last_primary_contact\":null"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // Q. FALLBACK DEGRADATION TESTS (14A.1A.47)
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_not_degraded_when_not_in_fallback() {
        let health = base_health(|h| {
            h.da_connected = true;
            h.da_last_sequence = 100;
            h.chunks_stored = 10;
            h.storage_used_gb = 50.0;
            h.storage_capacity_gb = 100.0;
            h.last_check = 1_000_000;
            h.last_primary_contact = Some(1_000_000);
        });

        assert!(!health.is_fallback_degraded());
        assert!(health.is_healthy());
    }

    #[test]
    fn test_not_degraded_when_fallback_short_duration() {
        let health = base_health(|h| {
            h.da_connected = true;
            h.da_last_sequence = 100;
            h.chunks_stored = 10;
            h.storage_used_gb = 50.0;
            h.storage_capacity_gb = 100.0;
            h.last_check = 60_000;
            h.fallback_active = true;
            h.da_source = "Secondary".to_string();
            h.events_from_fallback = 10;
            h.last_primary_contact = Some(0);
        });

        // 60 seconds < 5 minutes threshold
        assert!(!health.is_fallback_degraded());
        assert!(health.is_healthy());
    }

    #[test]
    fn test_degraded_when_fallback_exceeds_threshold() {
        let health = base_health(|h| {
            h.da_connected = true;
            h.da_last_sequence = 100;
            h.chunks_stored = 10;
            h.storage_used_gb = 50.0;
            h.storage_capacity_gb = 100.0;
            h.last_check = 360_000;
            h.fallback_active = true;
            h.da_source = "Secondary".to_string();
            h.events_from_fallback = 100;
            h.last_primary_contact = Some(0);
        });

        // 6 minutes > 5 minutes threshold
        assert!(health.is_fallback_degraded());
        assert!(!health.is_healthy());
    }

    #[test]
    fn test_degraded_exactly_at_threshold() {
        let health = base_health(|h| {
            h.da_connected = true;
            h.da_last_sequence = 100;
            h.chunks_stored = 10;
            h.storage_used_gb = 50.0;
            h.storage_capacity_gb = 100.0;
            h.last_check = FALLBACK_DEGRADATION_THRESHOLD_MS;
            h.fallback_active = true;
            h.da_source = "Secondary".to_string();
            h.events_from_fallback = 50;
            h.last_primary_contact = Some(0);
        });

        // Exactly at threshold = degraded (>=)
        assert!(health.is_fallback_degraded());
        assert!(!health.is_healthy());
    }

    #[test]
    fn test_degraded_with_emergency_source() {
        let health = base_health(|h| {
            h.da_connected = true;
            h.da_last_sequence = 100;
            h.chunks_stored = 10;
            h.storage_used_gb = 50.0;
            h.storage_capacity_gb = 100.0;
            h.last_check = 600_000;
            h.fallback_active = true;
            h.da_source = "Emergency".to_string();
            h.events_from_fallback = 200;
            h.last_primary_contact = Some(0);
        });

        assert!(health.is_fallback_degraded());
        assert!(!health.is_healthy());
    }

    #[test]
    fn test_health_issues_includes_extended_fallback() {
        let health = base_health(|h| {
            h.da_connected = true;
            h.da_last_sequence = 100;
            h.chunks_stored = 10;
            h.storage_used_gb = 50.0;
            h.storage_capacity_gb = 100.0;
            h.last_check = 600_000;
            h.fallback_active = true;
            h.da_source = "Secondary".to_string();
            h.events_from_fallback = 100;
            h.last_primary_contact = Some(0);
        });

        let issues = health.health_issues();

        assert!(!issues.is_empty());
        assert!(issues.iter().any(|i| i.contains("Extended fallback")));
        assert!(issues.iter().any(|i| i.contains("Secondary")));
    }

    #[test]
    fn test_health_issues_no_fallback_issue_when_short() {
        let health = base_health(|h| {
            h.da_connected = true;
            h.da_last_sequence = 100;
            h.chunks_stored = 10;
            h.storage_used_gb = 50.0;
            h.storage_capacity_gb = 100.0;
            h.last_check = 60_000;
            h.fallback_active = true;
            h.da_source = "Secondary".to_string();
            h.events_from_fallback = 10;
            h.last_primary_contact = Some(0);
        });

        let issues = health.health_issues();

        // Short fallback should not produce issues
        assert!(issues.is_empty());
    }

    #[test]
    fn test_fallback_degraded_no_last_primary_contact() {
        let health = base_health(|h| {
            h.da_connected = true;
            h.da_last_sequence = 100;
            h.chunks_stored = 10;
            h.storage_used_gb = 50.0;
            h.storage_capacity_gb = 100.0;
            h.last_check = 1_000_000;
            h.fallback_active = true;
            h.da_source = "Secondary".to_string();
            h.events_from_fallback = 50;
        });

        // Cannot determine duration, so not degraded
        assert!(!health.is_fallback_degraded());
    }

    #[test]
    fn test_healthy_after_fallback_deactivated() {
        let da = MockDAInfo::new(true, 100);
        let mut state = make_empty_state();

        // Set last_sequence to match DA to avoid lag-based unhealthy status
        state.last_sequence = 100;

        // Activate then deactivate fallback
        state.activate_fallback(1000, crate::multi_da_source::DASourceType::Secondary);
        state.record_fallback_event();
        state.deactivate_fallback();

        let storage = MockHealthStorage::new(0, GB_100);

        let health = NodeHealth::check(TEST_NODE, &da, &state, &storage);

        assert!(!health.fallback_active);
        assert_eq!(health.da_source, "Primary");
        // events_from_fallback preserves count
        assert_eq!(health.events_from_fallback, 1);
        // last_primary_contact is now (primary is active)
        assert!(health.last_primary_contact.is_some());
        // da_behind_by = 0, so should be healthy
        assert_eq!(health.da_behind_by, 0);
        assert!(health.is_healthy());
    }

    // ════════════════════════════════════════════════════════════════════════
    // R. IDENTITY EXTENSION TESTS (14B.48)
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_set_identity_context_full() {
        let id_mgr = NodeIdentityManager::from_keypair(TEST_SEED)
            .expect("test setup: from_keypair");
        let tls_mgr = TLSCertManager::generate_self_signed("test.dsdn.local", 365)
            .expect("test setup: TLS");

        let mut health = NodeHealth::default();
        health.set_identity_context(
            Some(&id_mgr),
            Some(&tls_mgr),
            Some(NodeStatus::Active),
            Some(NodeClass::Storage),
            Some(1_000_000_000_000_000_000),
            1_700_000_000,
        );

        // node_id_hex: 64 lowercase hex chars
        assert!(health.node_id_hex.is_some());
        if let Some(ref hex) = health.node_id_hex {
            assert_eq!(hex.len(), 64);
            assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
            assert_eq!(hex, &hex.to_lowercase());
        }

        // operator_address_hex: 40 lowercase hex chars
        assert!(health.operator_address_hex.is_some());
        if let Some(ref hex) = health.operator_address_hex {
            assert_eq!(hex.len(), 40);
            assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
        }

        assert_eq!(health.gating_status, Some("Active".to_string()));
        assert_eq!(health.node_class, Some("Storage".to_string()));
        assert_eq!(health.staked_amount, Some("1000000000000000000".to_string()));
        assert!(health.tls_valid.is_some());
        assert!(health.tls_expires_at.is_some());
    }

    #[test]
    fn test_set_identity_context_none_inputs() {
        let mut health = NodeHealth::default();
        health.set_identity_context(None, None, None, None, None, 0);

        assert!(health.node_id_hex.is_none());
        assert!(health.operator_address_hex.is_none());
        assert!(health.gating_status.is_none());
        assert!(health.node_class.is_none());
        assert!(health.tls_valid.is_none());
        assert!(health.tls_expires_at.is_none());
        assert!(health.staked_amount.is_none());
    }

    #[test]
    fn test_set_identity_context_partial() {
        let id_mgr = NodeIdentityManager::from_keypair(TEST_SEED)
            .expect("test setup");

        let mut health = NodeHealth::default();
        health.set_identity_context(
            Some(&id_mgr), None, Some(NodeStatus::Quarantined), None, None, 0,
        );

        assert!(health.node_id_hex.is_some());
        assert!(health.operator_address_hex.is_some());
        assert_eq!(health.gating_status, Some("Quarantined".to_string()));
        assert!(health.node_class.is_none());
        assert!(health.tls_valid.is_none());
        assert!(health.staked_amount.is_none());
    }

    #[test]
    fn test_gating_status_mapping_all_variants() {
        let cases = [
            (NodeStatus::Active, "Active"),
            (NodeStatus::Pending, "Pending"),
            (NodeStatus::Quarantined, "Quarantined"),
            (NodeStatus::Banned, "Banned"),
        ];
        for (status, expected) in cases {
            let mut h = NodeHealth::default();
            h.set_identity_context(None, None, Some(status), None, None, 0);
            assert_eq!(h.gating_status, Some(expected.to_string()));
        }
    }

    #[test]
    fn test_node_class_mapping_all_variants() {
        let mut h1 = NodeHealth::default();
        h1.set_identity_context(None, None, None, Some(NodeClass::Storage), None, 0);
        assert_eq!(h1.node_class, Some("Storage".to_string()));

        let mut h2 = NodeHealth::default();
        h2.set_identity_context(None, None, None, Some(NodeClass::Compute), None, 0);
        assert_eq!(h2.node_class, Some("Compute".to_string()));
    }

    #[test]
    fn test_staked_amount_format() {
        let mut h1 = NodeHealth::default();
        h1.set_identity_context(None, None, None, None, Some(0), 0);
        assert_eq!(h1.staked_amount, Some("0".to_string()));

        let mut h2 = NodeHealth::default();
        h2.set_identity_context(None, None, None, None, Some(u128::MAX), 0);
        assert_eq!(h2.staked_amount, Some(u128::MAX.to_string()));
    }

    #[test]
    fn test_identity_fields_in_json_when_set() {
        let id_mgr = NodeIdentityManager::from_keypair(TEST_SEED)
            .expect("test setup");
        let mut health = NodeHealth::default();
        health.set_identity_context(
            Some(&id_mgr), None, Some(NodeStatus::Active),
            Some(NodeClass::Storage), Some(42), 0,
        );

        let json = health.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json)
            .expect("test: parse JSON");

        assert!(parsed.get("node_id_hex").is_some());
        assert!(parsed.get("operator_address_hex").is_some());
        assert_eq!(parsed["gating_status"], "Active");
        assert_eq!(parsed["node_class"], "Storage");
        assert_eq!(parsed["staked_amount"], "42");
        // TLS not set → absent
        assert!(parsed.get("tls_valid").is_none());
        assert!(parsed.get("tls_expires_at").is_none());
    }

    #[test]
    fn test_identity_fields_absent_from_json_when_none() {
        let health = NodeHealth::default();
        let json = health.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json)
            .expect("test: parse JSON");

        assert!(parsed.get("node_id_hex").is_none());
        assert!(parsed.get("operator_address_hex").is_none());
        assert!(parsed.get("node_class").is_none());
        assert!(parsed.get("gating_status").is_none());
        assert!(parsed.get("tls_valid").is_none());
        assert!(parsed.get("tls_expires_at").is_none());
        assert!(parsed.get("staked_amount").is_none());
    }

    #[test]
    fn test_backward_compat_deserialization() {
        // Old JSON without identity fields should still deserialize
        let old_json = r#"{
            "node_id":"test","da_connected":true,"da_last_sequence":100,
            "da_behind_by":0,"chunks_stored":5,"chunks_pending":0,
            "chunks_missing":0,"storage_used_gb":50.0,"storage_capacity_gb":100.0,
            "last_check":12345,"fallback_active":false,"da_source":"Primary",
            "events_from_fallback":0,"last_primary_contact":12345
        }"#;

        let parsed: Result<NodeHealth, _> = serde_json::from_str(old_json);
        assert!(parsed.is_ok());
        if let Ok(h) = parsed {
            assert_eq!(h.node_id, "test");
            assert!(h.da_connected);
            assert!(h.node_id_hex.is_none());
            assert!(h.gating_status.is_none());
        }
    }

    #[test]
    fn test_health_endpoint_extended_with_identity() {
        let da = MockDAInfo::new(true, 100);
        let state = make_state_with_replicas(100, 10, 0, 0);
        let storage = MockHealthStorage::new(GB_50, GB_100);
        let id_mgr = NodeIdentityManager::from_keypair(TEST_SEED)
            .expect("test setup");

        let response = health_endpoint_extended(
            TEST_NODE, &da, &state, &storage,
            Some(&id_mgr), None,
            Some(NodeStatus::Active), Some(NodeClass::Storage),
            Some(1000), 1_700_000_000,
        );

        assert_eq!(response.status_code, 200);
        assert!(response.body.contains("node_id_hex"));
        assert!(response.body.contains("Active"));
        assert!(response.body.contains("Storage"));
    }

    #[test]
    fn test_health_endpoint_extended_no_identity() {
        let da = MockDAInfo::new(true, 100);
        let state = make_state_with_replicas(100, 10, 0, 0);
        let storage = MockHealthStorage::new(GB_50, GB_100);

        let response = health_endpoint_extended(
            TEST_NODE, &da, &state, &storage,
            None, None, None, None, None, 0,
        );

        assert_eq!(response.status_code, 200);
        // Identity fields absent
        assert!(!response.body.contains("node_id_hex"));
        assert!(!response.body.contains("gating_status"));
    }

    #[test]
    fn test_hex_encoding_correctness() {
        let id_mgr = NodeIdentityManager::from_keypair(TEST_SEED)
            .expect("test setup");
        let hex = bytes_to_lower_hex(id_mgr.node_id());
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!hex.starts_with("0x"));
        assert_eq!(hex, hex.to_lowercase());

        let op_hex = bytes_to_lower_hex(id_mgr.operator_address());
        assert_eq!(op_hex.len(), 40);
    }

    #[test]
    fn test_set_identity_context_deterministic() {
        let id_mgr = NodeIdentityManager::from_keypair(TEST_SEED)
            .expect("test setup");

        let mut h1 = NodeHealth::default();
        h1.set_identity_context(
            Some(&id_mgr), None, Some(NodeStatus::Active),
            Some(NodeClass::Storage), Some(42), 1000,
        );

        let mut h2 = NodeHealth::default();
        h2.set_identity_context(
            Some(&id_mgr), None, Some(NodeStatus::Active),
            Some(NodeClass::Storage), Some(42), 1000,
        );

        assert_eq!(h1.node_id_hex, h2.node_id_hex);
        assert_eq!(h1.operator_address_hex, h2.operator_address_hex);
        assert_eq!(h1.gating_status, h2.gating_status);
        assert_eq!(h1.node_class, h2.node_class);
        assert_eq!(h1.staked_amount, h2.staked_amount);
    }

    #[test]
    fn test_node_id_hex_matches_identity_bytes() {
        let id_mgr = NodeIdentityManager::from_keypair(TEST_SEED)
            .expect("test setup");
        let mut health = NodeHealth::default();
        health.set_identity_context(Some(&id_mgr), None, None, None, None, 0);

        let expected = bytes_to_lower_hex(id_mgr.node_id());
        assert_eq!(health.node_id_hex, Some(expected));

        let expected_op = bytes_to_lower_hex(id_mgr.operator_address());
        assert_eq!(health.operator_address_hex, Some(expected_op));
    }

    #[test]
    fn test_check_leaves_identity_fields_none() {
        let da = MockDAInfo::new(true, 100);
        let state = make_state_with_replicas(100, 10, 0, 0);
        let storage = MockHealthStorage::new(GB_50, GB_100);

        let health = NodeHealth::check(TEST_NODE, &da, &state, &storage);

        assert!(health.node_id_hex.is_none());
        assert!(health.operator_address_hex.is_none());
        assert!(health.gating_status.is_none());
        assert!(health.node_class.is_none());
        assert!(health.tls_valid.is_none());
        assert!(health.tls_expires_at.is_none());
        assert!(health.staked_amount.is_none());
    }
}