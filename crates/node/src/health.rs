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

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::da_follower::{NodeDerivedState, ReplicaStatus};

// ════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════

/// Maximum acceptable DA lag (in sequence numbers) before node is considered unhealthy.
/// This threshold allows for brief network delays while catching significant sync issues.
pub const DA_LAG_THRESHOLD: u64 = 100;

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

        true
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
    fn to_json_manual(&self) -> String {
        format!(
            r#"{{"node_id":"{}","da_connected":{},"da_last_sequence":{},"da_behind_by":{},"chunks_stored":{},"chunks_pending":{},"chunks_missing":{},"storage_used_gb":{},"storage_capacity_gb":{},"last_check":{}}}"#,
            self.node_id,
            self.da_connected,
            self.da_last_sequence,
            self.da_behind_by,
            self.chunks_stored,
            self.chunks_pending,
            self.chunks_missing,
            self.storage_used_gb,
            self.storage_capacity_gb,
            self.last_check
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

// ════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use crate::da_follower::ChunkAssignment;

    const TEST_NODE: &str = "test-node-1";

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

        let value = parsed.unwrap();
        assert_eq!(value["node_id"], TEST_NODE);
        assert_eq!(value["da_connected"], true);
        assert_eq!(value["chunks_stored"], 10);
        assert_eq!(value["chunks_pending"], 2);
        assert_eq!(value["chunks_missing"], 1);
    }

    #[test]
    fn test_to_json_all_fields_present() {
        let health = NodeHealth::default();
        let json = health.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

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
        let health = NodeHealth {
            node_id: TEST_NODE.to_string(),
            da_connected: true,
            da_last_sequence: 100,
            da_behind_by: 0,
            chunks_stored: 10,
            chunks_pending: 0,
            chunks_missing: 0,
            storage_used_gb: 50.0,
            storage_capacity_gb: 100.0,
            last_check: 12345,
        };

        let response = HealthResponse::from_health(&health);

        assert_eq!(response.status_code, 200);
        assert!(response.body.contains("test-node-1"));
    }
}