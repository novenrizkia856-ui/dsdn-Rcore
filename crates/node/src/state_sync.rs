//! State Sync & Verification Module
//!
//! This module provides state synchronization and verification mechanisms
//! to ensure node state consistency with the DA layer.
//!
//! ## Core Principles
//!
//! - **DA is Truth**: The DA layer is the single source of truth
//! - **Verification**: Local state must always be verifiable against DA
//! - **Detection**: Inconsistencies are detected, reported, and repairable
//! - **No Silent Corruption**: All divergence is visible and addressable
//!
//! ## Consistency Check Flow
//!
//! ```text
//! DA State ──┐
//!            ├──▶ Compare ──▶ ConsistencyReport
//! Local State ─┘
//! ```
//!
//! ## Report Categories
//!
//! | Category | Meaning |
//! |----------|---------|
//! | missing_in_local | Should exist per DA, but not in local storage |
//! | extra_in_local | In local storage, but NOT valid per DA |
//! | corrupted | Exists physically, but failed verification |

use std::collections::HashSet;
use std::sync::Arc;

use parking_lot::RwLock;
use thiserror::Error;

use dsdn_common::da::DALayer;
use crate::da_follower::NodeDerivedState;

// ════════════════════════════════════════════════════════════════════════════
// SYNC ERROR
// ════════════════════════════════════════════════════════════════════════════

/// Errors that can occur during state synchronization.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum SyncError {
    /// DA layer operation failed.
    #[error("DA error: {0}")]
    DAError(String),

    /// Storage operation failed.
    #[error("Storage error: {0}")]
    StorageError(String),

    /// Fetch operation failed.
    #[error("Fetch error: {0}")]
    FetchError(String),

    /// Verification failed.
    #[error("Verification error: {0}")]
    VerificationError(String),
}

// ════════════════════════════════════════════════════════════════════════════
// SYNC STORAGE TRAIT
// ════════════════════════════════════════════════════════════════════════════

/// Extended storage abstraction for state synchronization.
///
/// This trait provides the interface for storage operations needed
/// by the state sync module, including verification and repair operations.
pub trait SyncStorage: Send + Sync {
    /// Check if a chunk exists in local storage.
    fn has_chunk(&self, chunk_hash: &str) -> bool;

    /// Verify chunk integrity (hash check).
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - Chunk exists and is valid
    /// * `Ok(false)` - Chunk exists but is corrupted
    /// * `Err` - Check failed
    fn verify_chunk(&self, chunk_hash: &str) -> Result<bool, String>;

    /// Get all chunk hashes currently in storage.
    fn get_all_chunks(&self) -> Vec<String>;

    /// Store chunk data.
    ///
    /// # Arguments
    ///
    /// * `chunk_hash` - Hash of the chunk
    /// * `data` - Chunk data bytes
    fn store_chunk(&self, chunk_hash: &str, data: &[u8]) -> Result<(), String>;

    /// Delete chunk from storage.
    ///
    /// This is a physical deletion operation.
    fn delete_chunk(&self, chunk_hash: &str) -> Result<(), String>;

    /// Fetch chunk data from peers or external source.
    ///
    /// # Arguments
    ///
    /// * `chunk_hash` - Hash of the chunk to fetch
    ///
    /// # Returns
    ///
    /// * `Ok(data)` - Fetched chunk data
    /// * `Err` - Fetch failed
    fn fetch_chunk(&self, chunk_hash: &str) -> Result<Vec<u8>, String>;
}

// ════════════════════════════════════════════════════════════════════════════
// CONSISTENCY REPORT
// ════════════════════════════════════════════════════════════════════════════

/// Report of state consistency verification.
///
/// This struct contains the results of comparing local state against DA.
///
/// ## Semantics
///
/// - `missing_in_local`: Chunks that should exist per DA but are not in local storage
/// - `extra_in_local`: Chunks in local storage that are NOT valid per DA
/// - `corrupted`: Chunks that exist physically but failed verification
/// - `consistent`: `true` ONLY if all three vectors above are empty
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsistencyReport {
    /// Chunks that should exist per DA but not in local storage.
    pub missing_in_local: Vec<String>,
    /// Chunks in local storage that are NOT valid per DA.
    pub extra_in_local: Vec<String>,
    /// Chunks that exist physically but failed verification.
    pub corrupted: Vec<String>,
    /// True ONLY if all inconsistency vectors are empty.
    pub consistent: bool,
}

impl ConsistencyReport {
    /// Create a new empty consistency report.
    pub fn new() -> Self {
        Self {
            missing_in_local: Vec::new(),
            extra_in_local: Vec::new(),
            corrupted: Vec::new(),
            consistent: true,
        }
    }

    /// Check if the report indicates full consistency.
    ///
    /// Returns true only if no inconsistencies were found.
    pub fn is_consistent(&self) -> bool {
        self.missing_in_local.is_empty()
            && self.extra_in_local.is_empty()
            && self.corrupted.is_empty()
    }

    /// Get total number of issues found.
    pub fn issue_count(&self) -> usize {
        self.missing_in_local.len() + self.extra_in_local.len() + self.corrupted.len()
    }

    /// Finalize the report by setting consistent flag.
    fn finalize(&mut self) {
        self.consistent = self.is_consistent();
    }
}

impl Default for ConsistencyReport {
    fn default() -> Self {
        Self::new()
    }
}

// ════════════════════════════════════════════════════════════════════════════
// STATE SYNC
// ════════════════════════════════════════════════════════════════════════════

/// State synchronization and verification handler.
///
/// `StateSync` verifies local node state against DA and can repair
/// inconsistencies when detected.
///
/// ## Design Principles
///
/// - **DA Authority**: DA is the single source of truth
/// - **Detection**: All inconsistencies are detected and classified
/// - **Repair**: Inconsistencies can be repaired safely
/// - **Deterministic**: Same inputs → same outputs
/// - **Safe**: Never panics, propagates errors
pub struct StateSync {
    /// Reference to DA layer (source of truth).
    da: Arc<dyn DALayer>,
    /// Reference to node's derived state.
    state: Arc<RwLock<NodeDerivedState>>,
    /// Reference to storage abstraction.
    storage: Arc<dyn SyncStorage>,
}

impl StateSync {
    /// Create a new StateSync instance.
    ///
    /// # Arguments
    ///
    /// * `da` - Reference to DA layer
    /// * `state` - Reference to node's derived state
    /// * `storage` - Reference to storage abstraction
    pub fn new(
        da: Arc<dyn DALayer>,
        state: Arc<RwLock<NodeDerivedState>>,
        storage: Arc<dyn SyncStorage>,
    ) -> Self {
        Self { da, state, storage }
    }

    /// Verify consistency between DA state and local state.
    ///
    /// This method compares:
    /// - What DA says this node should have (authoritative)
    /// - What NodeDerivedState thinks we have (may be stale)
    /// - What Storage actually has (physical reality)
    ///
    /// # Returns
    ///
    /// * `Ok(ConsistencyReport)` - Verification completed
    /// * `Err(SyncError)` - Verification failed
    ///
    /// # Guarantees
    ///
    /// - DA is the authority
    /// - Local state is NOT trusted without verification
    /// - Never panics
    /// - Deterministic
    pub fn verify_consistency(&self) -> Result<ConsistencyReport, SyncError> {
        let mut report = ConsistencyReport::new();

        // Step 1: Get what DA says we should have
        // This comes from NodeDerivedState which is derived from DA events
        let state_guard = self.state.read();
        let da_assigned_chunks: HashSet<String> = state_guard
            .my_chunks
            .keys()
            .cloned()
            .collect();
        drop(state_guard);

        // Step 2: Get what storage actually has
        let storage_chunks: HashSet<String> = self.storage
            .get_all_chunks()
            .into_iter()
            .collect();

        // Step 3: Find missing chunks (in DA assignment but not in storage)
        for chunk_hash in &da_assigned_chunks {
            if !storage_chunks.contains(chunk_hash) {
                report.missing_in_local.push(chunk_hash.clone());
            }
        }

        // Step 4: Find extra chunks (in storage but not in DA assignment)
        for chunk_hash in &storage_chunks {
            if !da_assigned_chunks.contains(chunk_hash) {
                report.extra_in_local.push(chunk_hash.clone());
            }
        }

        // Step 5: Verify integrity of chunks that should exist
        for chunk_hash in &da_assigned_chunks {
            if storage_chunks.contains(chunk_hash) {
                // Chunk exists, verify integrity
                match self.storage.verify_chunk(chunk_hash) {
                    Ok(true) => {
                        // Chunk is valid
                    }
                    Ok(false) => {
                        // Chunk is corrupted
                        report.corrupted.push(chunk_hash.clone());
                    }
                    Err(e) => {
                        // Verification failed, treat as corrupted
                        report.corrupted.push(chunk_hash.clone());
                        tracing::warn!("Chunk {} verification error: {}", chunk_hash, e);
                    }
                }
            }
        }

        // Step 6: Sort vectors for determinism
        report.missing_in_local.sort();
        report.extra_in_local.sort();
        report.corrupted.sort();

        // Step 7: Finalize consistent flag
        report.finalize();

        Ok(report)
    }

    /// Repair inconsistencies found in a consistency report.
    ///
    /// This method repairs:
    ///
    /// 1. `missing_in_local`: Fetch chunk from peers, store locally
    /// 2. `corrupted`: Re-fetch chunk, overwrite local data
    /// 3. `extra_in_local`: Delete chunk from local storage
    ///
    /// # Arguments
    ///
    /// * `report` - The consistency report to repair
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All repairs completed successfully
    /// * `Err(SyncError)` - A repair operation failed
    ///
    /// # Guarantees
    ///
    /// - Never deletes valid data
    /// - Never adds data without DA basis
    /// - Idempotent (can be called multiple times safely)
    /// - Fails fast on first error
    pub fn repair_inconsistencies(&self, report: &ConsistencyReport) -> Result<(), SyncError> {
        // If already consistent, nothing to do
        if report.consistent {
            return Ok(());
        }

        // Step 1: Repair missing chunks (fetch and store)
        for chunk_hash in &report.missing_in_local {
            self.repair_missing_chunk(chunk_hash)?;
        }

        // Step 2: Repair corrupted chunks (re-fetch and overwrite)
        for chunk_hash in &report.corrupted {
            self.repair_corrupted_chunk(chunk_hash)?;
        }

        // Step 3: Remove extra chunks (delete from storage)
        for chunk_hash in &report.extra_in_local {
            self.remove_extra_chunk(chunk_hash)?;
        }

        Ok(())
    }

    /// Repair a missing chunk by fetching and storing it.
    fn repair_missing_chunk(&self, chunk_hash: &str) -> Result<(), SyncError> {
        // Fetch chunk data from peers
        let data = self.storage
            .fetch_chunk(chunk_hash)
            .map_err(|e| SyncError::FetchError(format!("Failed to fetch {}: {}", chunk_hash, e)))?;

        // Store chunk locally
        self.storage
            .store_chunk(chunk_hash, &data)
            .map_err(|e| SyncError::StorageError(format!("Failed to store {}: {}", chunk_hash, e)))?;

        // Update local state - mark as stored
        let mut state_guard = self.state.write();
        if let Some(assignment) = state_guard.my_chunks.get_mut(chunk_hash) {
            assignment.verified = false; // Needs verification
        }
        state_guard.update_replica_status(chunk_hash, crate::da_follower::ReplicaStatus::Stored);
        drop(state_guard);

        Ok(())
    }

    /// Repair a corrupted chunk by re-fetching and overwriting.
    fn repair_corrupted_chunk(&self, chunk_hash: &str) -> Result<(), SyncError> {
        // Fetch fresh chunk data from peers
        let data = self.storage
            .fetch_chunk(chunk_hash)
            .map_err(|e| SyncError::FetchError(format!("Failed to fetch {}: {}", chunk_hash, e)))?;

        // Overwrite corrupted data
        self.storage
            .store_chunk(chunk_hash, &data)
            .map_err(|e| SyncError::StorageError(format!("Failed to store {}: {}", chunk_hash, e)))?;

        // Update local state - mark as stored (needs re-verification)
        let mut state_guard = self.state.write();
        if let Some(assignment) = state_guard.my_chunks.get_mut(chunk_hash) {
            assignment.verified = false; // Needs re-verification
        }
        state_guard.update_replica_status(chunk_hash, crate::da_follower::ReplicaStatus::Stored);
        drop(state_guard);

        Ok(())
    }

    /// Remove an extra chunk that is not valid per DA.
    fn remove_extra_chunk(&self, chunk_hash: &str) -> Result<(), SyncError> {
        // Delete from storage
        self.storage
            .delete_chunk(chunk_hash)
            .map_err(|e| SyncError::StorageError(format!("Failed to delete {}: {}", chunk_hash, e)))?;

        // Note: We don't update NodeDerivedState here because
        // the chunk was never in my_chunks (that's why it's "extra")

        Ok(())
    }

    /// Get a reference to the DA layer.
    pub fn da(&self) -> &Arc<dyn DALayer> {
        &self.da
    }

    /// Get a reference to the node state.
    pub fn state(&self) -> &Arc<RwLock<NodeDerivedState>> {
        &self.state
    }

    /// Get a reference to the storage.
    pub fn storage(&self) -> &Arc<dyn SyncStorage> {
        &self.storage
    }
}

// ════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, Ordering};

    use dsdn_common::MockDA;
    use crate::da_follower::ChunkAssignment;

    #[allow(dead_code)]
    const TEST_NODE: &str = "node-1";
    const CHUNK_A: &str = "chunk-a-hash";
    const CHUNK_B: &str = "chunk-b-hash";
    const CHUNK_C: &str = "chunk-c-hash";
    const CHUNK_D: &str = "chunk-d-hash";

    // ════════════════════════════════════════════════════════════════════════
    // MOCK SYNC STORAGE
    // ════════════════════════════════════════════════════════════════════════

    struct MockSyncStorage {
        chunks: RwLock<HashMap<String, Vec<u8>>>,
        corrupted_chunks: RwLock<HashSet<String>>,
        fail_verify: AtomicBool,
        fail_fetch: AtomicBool,
        fail_store: AtomicBool,
        fail_delete: AtomicBool,
        fetch_data: RwLock<HashMap<String, Vec<u8>>>,
    }

    impl MockSyncStorage {
        fn new() -> Self {
            Self {
                chunks: RwLock::new(HashMap::new()),
                corrupted_chunks: RwLock::new(HashSet::new()),
                fail_verify: AtomicBool::new(false),
                fail_fetch: AtomicBool::new(false),
                fail_store: AtomicBool::new(false),
                fail_delete: AtomicBool::new(false),
                fetch_data: RwLock::new(HashMap::new()),
            }
        }

        fn add_chunk(&self, hash: &str, data: Vec<u8>) {
            self.chunks.write().insert(hash.to_string(), data);
        }

        fn mark_corrupted(&self, hash: &str) {
            self.corrupted_chunks.write().insert(hash.to_string());
        }

        fn set_fetch_data(&self, hash: &str, data: Vec<u8>) {
            self.fetch_data.write().insert(hash.to_string(), data);
        }

        fn set_fail_fetch(&self, fail: bool) {
            self.fail_fetch.store(fail, Ordering::SeqCst);
        }

        fn set_fail_store(&self, fail: bool) {
            self.fail_store.store(fail, Ordering::SeqCst);
        }

        fn set_fail_delete(&self, fail: bool) {
            self.fail_delete.store(fail, Ordering::SeqCst);
        }
    }

    impl SyncStorage for MockSyncStorage {
        fn has_chunk(&self, chunk_hash: &str) -> bool {
            self.chunks.read().contains_key(chunk_hash)
        }

        fn verify_chunk(&self, chunk_hash: &str) -> Result<bool, String> {
            if self.fail_verify.load(Ordering::SeqCst) {
                return Err("Mock verification failure".to_string());
            }
            if self.corrupted_chunks.read().contains(chunk_hash) {
                return Ok(false);
            }
            Ok(self.chunks.read().contains_key(chunk_hash))
        }

        fn get_all_chunks(&self) -> Vec<String> {
            self.chunks.read().keys().cloned().collect()
        }

        fn store_chunk(&self, chunk_hash: &str, data: &[u8]) -> Result<(), String> {
            if self.fail_store.load(Ordering::SeqCst) {
                return Err("Mock store failure".to_string());
            }
            self.chunks.write().insert(chunk_hash.to_string(), data.to_vec());
            // Clear corrupted flag on store
            self.corrupted_chunks.write().remove(chunk_hash);
            Ok(())
        }

        fn delete_chunk(&self, chunk_hash: &str) -> Result<(), String> {
            if self.fail_delete.load(Ordering::SeqCst) {
                return Err("Mock delete failure".to_string());
            }
            self.chunks.write().remove(chunk_hash);
            Ok(())
        }

        fn fetch_chunk(&self, chunk_hash: &str) -> Result<Vec<u8>, String> {
            if self.fail_fetch.load(Ordering::SeqCst) {
                return Err("Mock fetch failure".to_string());
            }
            self.fetch_data
                .read()
                .get(chunk_hash)
                .cloned()
                .ok_or_else(|| format!("No fetch data for {}", chunk_hash))
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // HELPER FUNCTIONS
    // ════════════════════════════════════════════════════════════════════════

    fn make_state_with_chunks(chunks: &[&str]) -> Arc<RwLock<NodeDerivedState>> {
        let mut state = NodeDerivedState::new();
        for (i, chunk) in chunks.iter().enumerate() {
            state.my_chunks.insert(
                chunk.to_string(),
                ChunkAssignment {
                    hash: chunk.to_string(),
                    replica_index: i as u8,
                    assigned_at: 1000 + i as u64,
                    verified: false,
                    size_bytes: 1024,
                },
            );
        }
        Arc::new(RwLock::new(state))
    }

    fn make_empty_state() -> Arc<RwLock<NodeDerivedState>> {
        Arc::new(RwLock::new(NodeDerivedState::new()))
    }

    // ════════════════════════════════════════════════════════════════════════
    // A. CONSISTENCY REPORT STRUCT TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_consistency_report_new() {
        let report = ConsistencyReport::new();
        assert!(report.missing_in_local.is_empty());
        assert!(report.extra_in_local.is_empty());
        assert!(report.corrupted.is_empty());
        assert!(report.consistent);
    }

    #[test]
    fn test_consistency_report_is_consistent() {
        let mut report = ConsistencyReport::new();
        assert!(report.is_consistent());

        report.missing_in_local.push("chunk".to_string());
        assert!(!report.is_consistent());
    }

    #[test]
    fn test_consistency_report_issue_count() {
        let mut report = ConsistencyReport::new();
        assert_eq!(report.issue_count(), 0);

        report.missing_in_local.push("a".to_string());
        report.extra_in_local.push("b".to_string());
        report.corrupted.push("c".to_string());
        assert_eq!(report.issue_count(), 3);
    }

    #[test]
    fn test_consistency_report_finalize() {
        let mut report = ConsistencyReport::new();
        report.missing_in_local.push("chunk".to_string());
        report.consistent = true; // Wrong value

        report.finalize();
        assert!(!report.consistent); // Should be corrected
    }

    // ════════════════════════════════════════════════════════════════════════
    // B. VERIFY CONSISTENCY - FULLY CONSISTENT
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_fully_consistent() {
        let da = Arc::new(MockDA::new());
        let state = make_state_with_chunks(&[CHUNK_A, CHUNK_B]);
        let storage = Arc::new(MockSyncStorage::new());

        // Storage has exactly what state says
        storage.add_chunk(CHUNK_A, vec![1, 2, 3]);
        storage.add_chunk(CHUNK_B, vec![4, 5, 6]);

        let sync = StateSync::new(da, state, storage);
        let report = sync.verify_consistency().unwrap();

        assert!(report.consistent);
        assert!(report.missing_in_local.is_empty());
        assert!(report.extra_in_local.is_empty());
        assert!(report.corrupted.is_empty());
    }

    #[test]
    fn test_verify_empty_state_empty_storage() {
        let da = Arc::new(MockDA::new());
        let state = make_empty_state();
        let storage = Arc::new(MockSyncStorage::new());

        let sync = StateSync::new(da, state, storage);
        let report = sync.verify_consistency().unwrap();

        assert!(report.consistent);
    }

    // ════════════════════════════════════════════════════════════════════════
    // C. VERIFY CONSISTENCY - MISSING
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_missing_in_local() {
        let da = Arc::new(MockDA::new());
        let state = make_state_with_chunks(&[CHUNK_A, CHUNK_B]);
        let storage = Arc::new(MockSyncStorage::new());

        // Storage only has CHUNK_A, missing CHUNK_B
        storage.add_chunk(CHUNK_A, vec![1, 2, 3]);

        let sync = StateSync::new(da, state, storage);
        let report = sync.verify_consistency().unwrap();

        assert!(!report.consistent);
        assert_eq!(report.missing_in_local, vec![CHUNK_B.to_string()]);
        assert!(report.extra_in_local.is_empty());
        assert!(report.corrupted.is_empty());
    }

    #[test]
    fn test_verify_all_missing() {
        let da = Arc::new(MockDA::new());
        let state = make_state_with_chunks(&[CHUNK_A, CHUNK_B]);
        let storage = Arc::new(MockSyncStorage::new());

        // Storage is empty
        let sync = StateSync::new(da, state, storage);
        let report = sync.verify_consistency().unwrap();

        assert!(!report.consistent);
        assert_eq!(report.missing_in_local.len(), 2);
    }

    // ════════════════════════════════════════════════════════════════════════
    // D. VERIFY CONSISTENCY - EXTRA
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_extra_in_local() {
        let da = Arc::new(MockDA::new());
        let state = make_state_with_chunks(&[CHUNK_A]);
        let storage = Arc::new(MockSyncStorage::new());

        // Storage has CHUNK_A (valid) and CHUNK_B (extra)
        storage.add_chunk(CHUNK_A, vec![1, 2, 3]);
        storage.add_chunk(CHUNK_B, vec![4, 5, 6]);

        let sync = StateSync::new(da, state, storage);
        let report = sync.verify_consistency().unwrap();

        assert!(!report.consistent);
        assert!(report.missing_in_local.is_empty());
        assert_eq!(report.extra_in_local, vec![CHUNK_B.to_string()]);
        assert!(report.corrupted.is_empty());
    }

    #[test]
    fn test_verify_all_extra() {
        let da = Arc::new(MockDA::new());
        let state = make_empty_state(); // No assignments
        let storage = Arc::new(MockSyncStorage::new());

        // Storage has chunks that shouldn't be there
        storage.add_chunk(CHUNK_A, vec![1, 2, 3]);
        storage.add_chunk(CHUNK_B, vec![4, 5, 6]);

        let sync = StateSync::new(da, state, storage);
        let report = sync.verify_consistency().unwrap();

        assert!(!report.consistent);
        assert_eq!(report.extra_in_local.len(), 2);
    }

    // ════════════════════════════════════════════════════════════════════════
    // E. VERIFY CONSISTENCY - CORRUPTED
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_corrupted() {
        let da = Arc::new(MockDA::new());
        let state = make_state_with_chunks(&[CHUNK_A, CHUNK_B]);
        let storage = Arc::new(MockSyncStorage::new());

        // Both chunks exist, but CHUNK_B is corrupted
        storage.add_chunk(CHUNK_A, vec![1, 2, 3]);
        storage.add_chunk(CHUNK_B, vec![4, 5, 6]);
        storage.mark_corrupted(CHUNK_B);

        let sync = StateSync::new(da, state, storage);
        let report = sync.verify_consistency().unwrap();

        assert!(!report.consistent);
        assert!(report.missing_in_local.is_empty());
        assert!(report.extra_in_local.is_empty());
        assert_eq!(report.corrupted, vec![CHUNK_B.to_string()]);
    }

    // ════════════════════════════════════════════════════════════════════════
    // F. VERIFY CONSISTENCY - MIXED
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_mixed_issues() {
        let da = Arc::new(MockDA::new());
        let state = make_state_with_chunks(&[CHUNK_A, CHUNK_B, CHUNK_C]);
        let storage = Arc::new(MockSyncStorage::new());

        // CHUNK_A: valid
        // CHUNK_B: missing
        // CHUNK_C: corrupted
        // CHUNK_D: extra
        storage.add_chunk(CHUNK_A, vec![1, 2, 3]);
        storage.add_chunk(CHUNK_C, vec![7, 8, 9]);
        storage.mark_corrupted(CHUNK_C);
        storage.add_chunk(CHUNK_D, vec![10, 11, 12]);

        let sync = StateSync::new(da, state, storage);
        let report = sync.verify_consistency().unwrap();

        assert!(!report.consistent);
        assert_eq!(report.missing_in_local, vec![CHUNK_B.to_string()]);
        assert_eq!(report.extra_in_local, vec![CHUNK_D.to_string()]);
        assert_eq!(report.corrupted, vec![CHUNK_C.to_string()]);
    }

    // ════════════════════════════════════════════════════════════════════════
    // G. REPAIR - MISSING
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_repair_missing_chunk() {
        let da = Arc::new(MockDA::new());
        let state = make_state_with_chunks(&[CHUNK_A]);
        let storage = Arc::new(MockSyncStorage::new());

        // CHUNK_A is missing from storage
        storage.set_fetch_data(CHUNK_A, vec![1, 2, 3]);

        let sync = StateSync::new(da, state.clone(), storage.clone());

        // Verify first
        let report = sync.verify_consistency().unwrap();
        assert!(!report.consistent);
        assert_eq!(report.missing_in_local.len(), 1);

        // Repair
        sync.repair_inconsistencies(&report).unwrap();

        // Verify again - should be consistent
        let report2 = sync.verify_consistency().unwrap();
        assert!(report2.consistent);
        assert!(storage.has_chunk(CHUNK_A));
    }

    // ════════════════════════════════════════════════════════════════════════
    // H. REPAIR - CORRUPTED
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_repair_corrupted_chunk() {
        let da = Arc::new(MockDA::new());
        let state = make_state_with_chunks(&[CHUNK_A]);
        let storage = Arc::new(MockSyncStorage::new());

        // CHUNK_A exists but is corrupted
        storage.add_chunk(CHUNK_A, vec![99, 99, 99]); // Bad data
        storage.mark_corrupted(CHUNK_A);
        storage.set_fetch_data(CHUNK_A, vec![1, 2, 3]); // Good data from fetch

        let sync = StateSync::new(da, state.clone(), storage.clone());

        // Verify first
        let report = sync.verify_consistency().unwrap();
        assert!(!report.consistent);
        assert_eq!(report.corrupted.len(), 1);

        // Repair
        sync.repair_inconsistencies(&report).unwrap();

        // Verify again - should be consistent
        let report2 = sync.verify_consistency().unwrap();
        assert!(report2.consistent);
    }

    // ════════════════════════════════════════════════════════════════════════
    // I. REPAIR - EXTRA
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_repair_extra_chunk() {
        let da = Arc::new(MockDA::new());
        let state = make_empty_state(); // No assignments
        let storage = Arc::new(MockSyncStorage::new());

        // Storage has chunk that shouldn't be there
        storage.add_chunk(CHUNK_A, vec![1, 2, 3]);

        let sync = StateSync::new(da, state, storage.clone());

        // Verify first
        let report = sync.verify_consistency().unwrap();
        assert!(!report.consistent);
        assert_eq!(report.extra_in_local.len(), 1);

        // Repair
        sync.repair_inconsistencies(&report).unwrap();

        // Verify again - should be consistent
        let report2 = sync.verify_consistency().unwrap();
        assert!(report2.consistent);
        assert!(!storage.has_chunk(CHUNK_A));
    }

    // ════════════════════════════════════════════════════════════════════════
    // J. REPAIR - ALL ISSUES
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_repair_all_issues() {
        let da = Arc::new(MockDA::new());
        let state = make_state_with_chunks(&[CHUNK_A, CHUNK_B]);
        let storage = Arc::new(MockSyncStorage::new());

        // CHUNK_A: missing
        // CHUNK_B: corrupted
        // CHUNK_C: extra
        storage.add_chunk(CHUNK_B, vec![99, 99, 99]);
        storage.mark_corrupted(CHUNK_B);
        storage.add_chunk(CHUNK_C, vec![7, 8, 9]);

        storage.set_fetch_data(CHUNK_A, vec![1, 2, 3]);
        storage.set_fetch_data(CHUNK_B, vec![4, 5, 6]);

        let sync = StateSync::new(da, state, storage.clone());

        // Verify first
        let report = sync.verify_consistency().unwrap();
        assert!(!report.consistent);
        assert_eq!(report.issue_count(), 3);

        // Repair
        sync.repair_inconsistencies(&report).unwrap();

        // Verify again
        let report2 = sync.verify_consistency().unwrap();
        assert!(report2.consistent);
    }

    // ════════════════════════════════════════════════════════════════════════
    // K. DETERMINISM TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_deterministic() {
        let da = Arc::new(MockDA::new());
        let state = make_state_with_chunks(&[CHUNK_A, CHUNK_B, CHUNK_C]);
        let storage = Arc::new(MockSyncStorage::new());

        storage.add_chunk(CHUNK_A, vec![1, 2, 3]);
        storage.add_chunk(CHUNK_C, vec![7, 8, 9]);
        storage.mark_corrupted(CHUNK_C);
        storage.add_chunk(CHUNK_D, vec![10, 11, 12]);

        let sync = StateSync::new(da, state, storage);

        // Run verify twice
        let report1 = sync.verify_consistency().unwrap();
        let report2 = sync.verify_consistency().unwrap();

        assert_eq!(report1, report2);
    }

    #[test]
    fn test_repair_idempotent() {
        let da = Arc::new(MockDA::new());
        let state = make_state_with_chunks(&[CHUNK_A]);
        let storage = Arc::new(MockSyncStorage::new());

        storage.set_fetch_data(CHUNK_A, vec![1, 2, 3]);

        let sync = StateSync::new(da, state, storage.clone());

        // Get initial report
        let report = sync.verify_consistency().unwrap();
        assert!(!report.consistent);

        // Repair twice
        sync.repair_inconsistencies(&report).unwrap();
        sync.repair_inconsistencies(&report).unwrap();

        // Should still be consistent
        let final_report = sync.verify_consistency().unwrap();
        assert!(final_report.consistent);
    }

    // ════════════════════════════════════════════════════════════════════════
    // L. ERROR HANDLING TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_repair_fetch_error_propagates() {
        let da = Arc::new(MockDA::new());
        let state = make_state_with_chunks(&[CHUNK_A]);
        let storage = Arc::new(MockSyncStorage::new());

        // No fetch data available, so fetch will fail
        storage.set_fail_fetch(true);

        let sync = StateSync::new(da, state, storage);

        let report = sync.verify_consistency().unwrap();
        let result = sync.repair_inconsistencies(&report);

        assert!(matches!(result, Err(SyncError::FetchError(_))));
    }

    #[test]
    fn test_repair_store_error_propagates() {
        let da = Arc::new(MockDA::new());
        let state = make_state_with_chunks(&[CHUNK_A]);
        let storage = Arc::new(MockSyncStorage::new());

        storage.set_fetch_data(CHUNK_A, vec![1, 2, 3]);
        storage.set_fail_store(true);

        let sync = StateSync::new(da, state, storage);

        let report = sync.verify_consistency().unwrap();
        let result = sync.repair_inconsistencies(&report);

        assert!(matches!(result, Err(SyncError::StorageError(_))));
    }

    #[test]
    fn test_repair_delete_error_propagates() {
        let da = Arc::new(MockDA::new());
        let state = make_empty_state();
        let storage = Arc::new(MockSyncStorage::new());

        storage.add_chunk(CHUNK_A, vec![1, 2, 3]);
        storage.set_fail_delete(true);

        let sync = StateSync::new(da, state, storage);

        let report = sync.verify_consistency().unwrap();
        let result = sync.repair_inconsistencies(&report);

        assert!(matches!(result, Err(SyncError::StorageError(_))));
    }

    // ════════════════════════════════════════════════════════════════════════
    // M. SAFETY TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_no_panic_empty_report() {
        let da = Arc::new(MockDA::new());
        let state = make_empty_state();
        let storage = Arc::new(MockSyncStorage::new());

        let sync = StateSync::new(da, state, storage);

        // Empty report should be safe
        let report = ConsistencyReport::new();
        let result = sync.repair_inconsistencies(&report);

        assert!(result.is_ok());
    }

    #[test]
    fn test_consistent_report_no_op() {
        let da = Arc::new(MockDA::new());
        let state = make_state_with_chunks(&[CHUNK_A]);
        let storage = Arc::new(MockSyncStorage::new());

        storage.add_chunk(CHUNK_A, vec![1, 2, 3]);

        let sync = StateSync::new(da, state, storage);

        let report = sync.verify_consistency().unwrap();
        assert!(report.consistent);

        // Repair on consistent report should be no-op
        let result = sync.repair_inconsistencies(&report);
        assert!(result.is_ok());
    }

    // ════════════════════════════════════════════════════════════════════════
    // N. SYNC ERROR TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_sync_error_display() {
        let err = SyncError::DAError("test".to_string());
        assert!(format!("{}", err).contains("DA error"));

        let err2 = SyncError::StorageError("test".to_string());
        assert!(format!("{}", err2).contains("Storage error"));

        let err3 = SyncError::FetchError("test".to_string());
        assert!(format!("{}", err3).contains("Fetch error"));

        let err4 = SyncError::VerificationError("test".to_string());
        assert!(format!("{}", err4).contains("Verification error"));
    }

    #[test]
    fn test_sync_error_clone() {
        let err = SyncError::DAError("test".to_string());
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    // ════════════════════════════════════════════════════════════════════════
    // O. STATE SYNC STRUCT TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_state_sync_new() {
        let da: Arc<dyn DALayer> = Arc::new(MockDA::new());
        let state = make_empty_state();
        let storage = Arc::new(MockSyncStorage::new());

        let sync = StateSync::new(da.clone(), state.clone(), storage.clone());

        // Verify accessors work
        assert!(Arc::ptr_eq(sync.da(), &da));
        assert!(Arc::ptr_eq(sync.state(), &state));
    }

    // ════════════════════════════════════════════════════════════════════════
    // P. REPLICA STATUS UPDATE TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_repair_updates_replica_status() {
        let da = Arc::new(MockDA::new());
        let state = make_state_with_chunks(&[CHUNK_A]);
        let storage = Arc::new(MockSyncStorage::new());

        storage.set_fetch_data(CHUNK_A, vec![1, 2, 3]);

        let sync = StateSync::new(da, state.clone(), storage);

        let report = sync.verify_consistency().unwrap();
        sync.repair_inconsistencies(&report).unwrap();

        // Check that replica status was updated
        let state_guard = state.read();
        let status = state_guard.get_replica_status(CHUNK_A);
        assert_eq!(status, Some(crate::da_follower::ReplicaStatus::Stored));
    }
}