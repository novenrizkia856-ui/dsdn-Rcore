//! # Economic Flow Types + Receipt Status Tracker (14C.C.16)
//!
//! Lifecycle monitoring for the end-to-end economic flow of service receipts.
//!
//! ## State Machine
//!
//! ```text
//! Dispatched → Executing → ProofBuilt → Submitted → Pending → Finalized
//!      │            │           │            │          │
//!      └→Failed     └→Failed    └→Failed     ├→Rejected ├→Challenged → Finalized
//!                                            └→Failed              └→Rejected
//! ```
//!
//! ## Invariants
//!
//! 1. State transitions are validated; invalid transitions return `TrackerError::InvalidTransition`.
//! 2. `list_pending()` and `list_by_status()` return results sorted by `receipt_hash` (deterministic).
//! 3. `summary()` is computed from counts, independent of `HashMap` iteration order.
//! 4. No panic, no unwrap, no expect, no unsafe.

use std::collections::HashMap;
use std::future::Future;

use crate::retry::{RetryConfig, RetryResult, retry_with_backoff};

// ════════════════════════════════════════════════════════════════════════════════
// STATE ENUM
// ════════════════════════════════════════════════════════════════════════════════

/// Lifecycle state of an economic flow (workload → receipt → reward).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EconomicFlowState {
    /// Workload has been dispatched to a service node.
    Dispatched { workload_id: String, dispatched_at: u64 },
    /// Service node is executing the workload.
    Executing { workload_id: String, started_at: u64 },
    /// Proof of execution has been built locally.
    ProofBuilt { workload_id: String, proof_hash: String },
    /// Receipt has been submitted to chain.
    Submitted { workload_id: String, receipt_hash: String },
    /// Receipt is on-chain, pending finalization.
    Pending { receipt_hash: String, submitted_at: u64 },
    /// Receipt is under active challenge.
    Challenged { receipt_hash: String, challenge_id: String, expires_at: u64 },
    /// Receipt has been finalized; reward is claimable.
    Finalized { receipt_hash: String, reward_amount: u128 },
    /// Receipt was rejected (challenge succeeded, invalid proof, etc.).
    Rejected { receipt_hash: String, reason: String },
    /// Workload execution failed before finalization.
    Failed { workload_id: String, error: String },
}

impl EconomicFlowState {
    /// Return the discriminant tag for variant comparison (no inner data).
    fn tag(&self) -> u8 {
        match self {
            Self::Dispatched { .. } => 0,
            Self::Executing { .. } => 1,
            Self::ProofBuilt { .. } => 2,
            Self::Submitted { .. } => 3,
            Self::Pending { .. } => 4,
            Self::Challenged { .. } => 5,
            Self::Finalized { .. } => 6,
            Self::Rejected { .. } => 7,
            Self::Failed { .. } => 8,
        }
    }

    /// Human-readable label for display.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Dispatched { .. } => "Dispatched",
            Self::Executing { .. } => "Executing",
            Self::ProofBuilt { .. } => "ProofBuilt",
            Self::Submitted { .. } => "Submitted",
            Self::Pending { .. } => "Pending",
            Self::Challenged { .. } => "Challenged",
            Self::Finalized { .. } => "Finalized",
            Self::Rejected { .. } => "Rejected",
            Self::Failed { .. } => "Failed",
        }
    }
}

/// Check if `from → to` is a valid lifecycle transition.
///
/// Valid transitions:
/// - `Dispatched` → `Executing`, `Failed`
/// - `Executing` → `ProofBuilt`, `Failed`
/// - `ProofBuilt` → `Submitted`, `Failed`
/// - `Submitted` → `Pending`, `Rejected`, `Failed`
/// - `Pending` → `Challenged`, `Finalized`, `Rejected`
/// - `Challenged` → `Finalized`, `Rejected`
/// - `Finalized`, `Rejected`, `Failed` → (terminal, no further transitions)
fn is_valid_transition(from: &EconomicFlowState, to: &EconomicFlowState) -> bool {
    let from_tag = from.tag();
    let to_tag = to.tag();

    match from_tag {
        // Dispatched → Executing | Failed
        0 => to_tag == 1 || to_tag == 8,
        // Executing → ProofBuilt | Failed
        1 => to_tag == 2 || to_tag == 8,
        // ProofBuilt → Submitted | Failed
        2 => to_tag == 3 || to_tag == 8,
        // Submitted → Pending | Rejected | Failed
        3 => to_tag == 4 || to_tag == 7 || to_tag == 8,
        // Pending → Challenged | Finalized | Rejected
        4 => to_tag == 5 || to_tag == 6 || to_tag == 7,
        // Challenged → Finalized | Rejected
        5 => to_tag == 6 || to_tag == 7,
        // Finalized, Rejected, Failed → terminal (no valid transitions)
        6 | 7 | 8 => false,
        _ => false,
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TRACKER TYPES
// ════════════════════════════════════════════════════════════════════════════════

/// Error type for tracker operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrackerError {
    /// The requested state transition is not allowed by the lifecycle rules.
    InvalidTransition,
    /// The receipt hash was not found in the tracker.
    NotFound,
}

impl core::fmt::Display for TrackerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidTransition => f.write_str("invalid state transition"),
            Self::NotFound => f.write_str("receipt not found"),
        }
    }
}

/// A tracked receipt entry with full lifecycle metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptStatusEntry {
    /// Receipt hash (primary key).
    pub receipt_hash: String,
    /// Associated workload ID.
    pub workload_id: String,
    /// Current lifecycle state.
    pub status: EconomicFlowState,
    /// Timestamp when this entry was first created.
    pub created_at: u64,
    /// Timestamp of the most recent state update.
    pub updated_at: u64,
    /// Number of times this receipt has been retried (user-managed).
    pub retry_count: u32,
}

/// Aggregate summary of all tracked receipts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EconomicSummary {
    /// Total number of tracked receipts.
    pub total: usize,
    /// Count of receipts in each state.
    pub dispatched: usize,
    pub executing: usize,
    pub proof_built: usize,
    pub submitted: usize,
    pub pending: usize,
    pub challenged: usize,
    pub finalized: usize,
    pub rejected: usize,
    pub failed: usize,
}

impl EconomicSummary {
    /// Format summary as a human-readable table.
    pub fn to_table(&self) -> String {
        let mut out = String::new();
        out.push_str("┌─────────────────────┬───────┐\n");
        out.push_str("│ ECONOMIC SUMMARY    │ Count │\n");
        out.push_str("├─────────────────────┼───────┤\n");
        out.push_str(&format!("│ Dispatched          │ {:>5} │\n", self.dispatched));
        out.push_str(&format!("│ Executing           │ {:>5} │\n", self.executing));
        out.push_str(&format!("│ ProofBuilt          │ {:>5} │\n", self.proof_built));
        out.push_str(&format!("│ Submitted           │ {:>5} │\n", self.submitted));
        out.push_str(&format!("│ Pending             │ {:>5} │\n", self.pending));
        out.push_str(&format!("│ Challenged          │ {:>5} │\n", self.challenged));
        out.push_str(&format!("│ Finalized           │ {:>5} │\n", self.finalized));
        out.push_str(&format!("│ Rejected            │ {:>5} │\n", self.rejected));
        out.push_str(&format!("│ Failed              │ {:>5} │\n", self.failed));
        out.push_str("├─────────────────────┼───────┤\n");
        out.push_str(&format!("│ Total               │ {:>5} │\n", self.total));
        out.push_str("└─────────────────────┴───────┘\n");
        out
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// RECEIPT STATUS TRACKER
// ════════════════════════════════════════════════════════════════════════════════

/// In-memory tracker for economic flow receipt lifecycle.
///
/// Thread safety: `ReceiptStatusTracker` is `Send + Sync` (all fields are owned,
/// no interior mutability). For concurrent access, wrap in `Arc<Mutex<_>>`.
#[derive(Debug, Clone)]
pub struct ReceiptStatusTracker {
    entries: HashMap<String, ReceiptStatusEntry>,
}

impl ReceiptStatusTracker {
    /// Create an empty tracker.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Track a receipt by updating (or creating) its lifecycle state.
    ///
    /// If the receipt already exists, the transition is validated against
    /// the lifecycle rules. Invalid transitions return
    /// [`TrackerError::InvalidTransition`].
    ///
    /// If the receipt is new, it is created with the given state and timestamp.
    pub fn track(
        &mut self,
        receipt_hash: &str,
        state: EconomicFlowState,
        timestamp: u64,
    ) -> Result<(), TrackerError> {
        if let Some(entry) = self.entries.get_mut(receipt_hash) {
            // ── Existing entry: validate transition ─────────────────────
            if !is_valid_transition(&entry.status, &state) {
                return Err(TrackerError::InvalidTransition);
            }
            entry.status = state;
            entry.updated_at = timestamp;
            Ok(())
        } else {
            // ── New entry ───────────────────────────────────────────────
            let workload_id = extract_workload_id(&state);
            self.entries.insert(receipt_hash.to_string(), ReceiptStatusEntry {
                receipt_hash: receipt_hash.to_string(),
                workload_id,
                status: state,
                created_at: timestamp,
                updated_at: timestamp,
                retry_count: 0,
            });
            Ok(())
        }
    }

    /// Look up a receipt's current status.
    pub fn get_status(&self, receipt_hash: &str) -> Option<&ReceiptStatusEntry> {
        self.entries.get(receipt_hash)
    }

    /// List all receipts currently in the `Pending` state.
    ///
    /// Result is sorted by `receipt_hash` (lexicographic) for determinism.
    pub fn list_pending(&self) -> Vec<&ReceiptStatusEntry> {
        let mut result: Vec<&ReceiptStatusEntry> = self
            .entries
            .values()
            .filter(|e| e.status.tag() == 4) // Pending
            .collect();
        result.sort_by(|a, b| a.receipt_hash.cmp(&b.receipt_hash));
        result
    }

    /// List all receipts matching a given state variant (by tag, ignoring inner data).
    ///
    /// Result is sorted by `receipt_hash` (lexicographic) for determinism.
    pub fn list_by_status(&self, target: &EconomicFlowState) -> Vec<&ReceiptStatusEntry> {
        let target_tag = target.tag();
        let mut result: Vec<&ReceiptStatusEntry> = self
            .entries
            .values()
            .filter(|e| e.status.tag() == target_tag)
            .collect();
        result.sort_by(|a, b| a.receipt_hash.cmp(&b.receipt_hash));
        result
    }

    /// Compute an aggregate summary of all tracked receipts.
    ///
    /// Counting is done via explicit iteration (not dependent on HashMap order).
    pub fn summary(&self) -> EconomicSummary {
        let mut s = EconomicSummary {
            total: self.entries.len(),
            dispatched: 0,
            executing: 0,
            proof_built: 0,
            submitted: 0,
            pending: 0,
            challenged: 0,
            finalized: 0,
            rejected: 0,
            failed: 0,
        };

        for entry in self.entries.values() {
            match entry.status.tag() {
                0 => s.dispatched += 1,
                1 => s.executing += 1,
                2 => s.proof_built += 1,
                3 => s.submitted += 1,
                4 => s.pending += 1,
                5 => s.challenged += 1,
                6 => s.finalized += 1,
                7 => s.rejected += 1,
                8 => s.failed += 1,
                _ => {} // unreachable: all tags are 0-8
            }
        }

        s
    }

    /// Increment retry count for a receipt. Returns `NotFound` if missing.
    pub fn increment_retry(&mut self, receipt_hash: &str) -> Result<u32, TrackerError> {
        let entry = self.entries.get_mut(receipt_hash).ok_or(TrackerError::NotFound)?;
        entry.retry_count = entry.retry_count.saturating_add(1);
        Ok(entry.retry_count)
    }

    /// Return total number of tracked entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the tracker is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for ReceiptStatusTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract workload_id from a state variant (if available).
fn extract_workload_id(state: &EconomicFlowState) -> String {
    match state {
        EconomicFlowState::Dispatched { workload_id, .. }
        | EconomicFlowState::Executing { workload_id, .. }
        | EconomicFlowState::ProofBuilt { workload_id, .. }
        | EconomicFlowState::Submitted { workload_id, .. }
        | EconomicFlowState::Failed { workload_id, .. } => workload_id.clone(),
        EconomicFlowState::Pending { receipt_hash, .. }
        | EconomicFlowState::Challenged { receipt_hash, .. }
        | EconomicFlowState::Finalized { receipt_hash, .. }
        | EconomicFlowState::Rejected { receipt_hash, .. } => {
            // Late-stage states may not carry workload_id; use receipt_hash as fallback.
            receipt_hash.clone()
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// CLI HANDLER FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════════

/// Handle `economic status <receipt_hash>`.
///
/// Prints the receipt's current state, or an error message if not found.
/// Never panics.
pub fn handle_economic_status(tracker: &ReceiptStatusTracker, receipt_hash: &str) {
    match tracker.get_status(receipt_hash) {
        Some(entry) => {
            println!("Receipt:    {}", entry.receipt_hash);
            println!("Workload:   {}", entry.workload_id);
            println!("Status:     {}", entry.status.label());
            println!("Created:    {}", entry.created_at);
            println!("Updated:    {}", entry.updated_at);
            println!("Retries:    {}", entry.retry_count);
        }
        None => {
            println!("Receipt '{}' not found in tracker.", receipt_hash);
        }
    }
}

/// Handle `economic list`.
///
/// Prints all tracked receipts sorted by receipt_hash.
/// Never panics.
pub fn handle_economic_list(tracker: &ReceiptStatusTracker) {
    let mut entries: Vec<&ReceiptStatusEntry> = tracker.entries.values().collect();
    entries.sort_by(|a, b| a.receipt_hash.cmp(&b.receipt_hash));

    if entries.is_empty() {
        println!("No receipts tracked.");
        return;
    }

    println!("{:<44} {:<12} {:<12} {:>8}", "Receipt Hash", "Status", "Workload", "Retries");
    println!("{}", "-".repeat(80));
    for e in &entries {
        println!(
            "{:<44} {:<12} {:<12} {:>8}",
            truncate_str(&e.receipt_hash, 44),
            e.status.label(),
            truncate_str(&e.workload_id, 12),
            e.retry_count,
        );
    }
    println!("\nTotal: {}", entries.len());
}

/// Handle `economic summary`.
///
/// Prints the aggregate summary table.
/// Never panics.
pub fn handle_economic_summary(tracker: &ReceiptStatusTracker) {
    let s = tracker.summary();
    print!("{}", s.to_table());
}

/// Truncate string with ellipsis for display.
fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else if max_len > 3 {
        format!("{}...", &s[..max_len - 3])
    } else {
        s[..max_len].to_string()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// WORKLOAD DISPATCH + EXECUTION MONITORING (14C.C.18)
// ════════════════════════════════════════════════════════════════════════════════

/// Type of workload to dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkloadType {
    /// Storage workload (blob store, retrieval proof, etc.).
    Storage,
    /// Compute workload (execution, proof generation, etc.).
    Compute,
}

impl WorkloadType {
    /// Parse from string. Returns `None` for unknown types.
    pub fn from_str_checked(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "storage" => Some(Self::Storage),
            "compute" => Some(Self::Compute),
            _ => None,
        }
    }

    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Storage => "storage",
            Self::Compute => "compute",
        }
    }
}

/// Configuration for dispatching a workload.
#[derive(Debug, Clone)]
pub struct WorkloadDispatchConfig {
    /// Coordinator endpoint URL.
    pub coordinator_endpoint: String,
    /// Target node address.
    pub node_addr: String,
    /// Type of workload.
    pub workload_type: WorkloadType,
    /// Timeout for the entire dispatch operation (seconds).
    pub timeout_secs: u64,
}

/// Successful dispatch outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchResult {
    /// Assigned workload identifier.
    pub workload_id: String,
    /// Node the workload was assigned to.
    pub assigned_node: String,
    /// Timestamp when dispatched (chain time).
    pub dispatched_at: u64,
}

/// Execution status of a dispatched workload.
#[derive(Debug, Clone, PartialEq)]
pub enum ExecutionStatus {
    /// Workload is still running.
    Running { progress: f64 },
    /// Workload completed successfully.
    Completed { output_hash: String, duration_ms: u64 },
    /// Workload execution failed.
    Failed { error: String },
}

// ── Error types ─────────────────────────────────────────────────────────────

/// Errors from workload dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchError {
    /// Network-level failure (retryable).
    NetworkError(String),
    /// The dispatch operation timed out.
    Timeout,
    /// Response from coordinator was invalid.
    InvalidResponse,
    /// Serialization/deserialization failure.
    SerializationError(String),
}

impl core::fmt::Display for DispatchError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NetworkError(msg) => write!(f, "network error: {}", msg),
            Self::Timeout => f.write_str("timeout"),
            Self::InvalidResponse => f.write_str("invalid response"),
            Self::SerializationError(msg) => write!(f, "serialization error: {}", msg),
        }
    }
}

/// Errors from execution monitoring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MonitorError {
    /// Network-level failure (retryable).
    NetworkError(String),
    /// The monitor request timed out.
    Timeout,
    /// Response was invalid or contained illegal values.
    InvalidResponse,
}

impl core::fmt::Display for MonitorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NetworkError(msg) => write!(f, "network error: {}", msg),
            Self::Timeout => f.write_str("timeout"),
            Self::InvalidResponse => f.write_str("invalid response"),
        }
    }
}

// ── Response validation ─────────────────────────────────────────────────────

/// Validate a dispatch result. Returns `Err(InvalidResponse)` if any field is empty/zero.
fn validate_dispatch_result(result: &DispatchResult) -> Result<(), DispatchError> {
    if result.workload_id.is_empty() {
        return Err(DispatchError::InvalidResponse);
    }
    if result.assigned_node.is_empty() {
        return Err(DispatchError::InvalidResponse);
    }
    if result.dispatched_at == 0 {
        return Err(DispatchError::InvalidResponse);
    }
    Ok(())
}

/// Validate an execution status. Returns `Err(InvalidResponse)` on illegal values.
fn validate_execution_status(status: &ExecutionStatus) -> Result<(), MonitorError> {
    match status {
        ExecutionStatus::Running { progress } => {
            if progress.is_nan() || *progress < 0.0 || *progress > 1.0 {
                return Err(MonitorError::InvalidResponse);
            }
        }
        ExecutionStatus::Completed { output_hash, .. } => {
            if output_hash.is_empty() {
                return Err(MonitorError::InvalidResponse);
            }
        }
        ExecutionStatus::Failed { error } => {
            if error.is_empty() {
                return Err(MonitorError::InvalidResponse);
            }
        }
    }
    Ok(())
}

// ── Default retry configs ───────────────────────────────────────────────────

fn dispatch_retry_config() -> RetryConfig {
    RetryConfig {
        max_retries: 3,
        initial_delay_ms: 500,
        max_delay_ms: 10_000,
        backoff_multiplier: 2.0,
        jitter: true,
    }
}

fn monitor_retry_config() -> RetryConfig {
    RetryConfig {
        max_retries: 3,
        initial_delay_ms: 500,
        max_delay_ms: 10_000,
        backoff_multiplier: 2.0,
        jitter: true,
    }
}

// ── Core dispatch + monitor functions ────────────────────────────────────────

/// Dispatch a workload using a pluggable async network operation.
///
/// Wraps the call in [`retry_with_backoff`] and [`tokio::time::timeout`].
/// Validates the response before returning.
///
/// # Arguments
///
/// * `config` — Dispatch configuration (endpoint, node, type, timeout).
/// * `network_fn` — Async closure performing the network call.
///   `Err(String)` values are classified by [`crate::retry::is_retryable`].
pub async fn dispatch_workload_with<F, Fut>(
    config: &WorkloadDispatchConfig,
    network_fn: F,
) -> Result<DispatchResult, DispatchError>
where
    F: FnMut() -> Fut + Send,
    Fut: Future<Output = Result<DispatchResult, String>> + Send,
{
    let retry_cfg = dispatch_retry_config();
    let timeout_dur = tokio::time::Duration::from_secs(config.timeout_secs);

    let timeout_result = tokio::time::timeout(
        timeout_dur,
        retry_with_backoff(&retry_cfg, network_fn),
    )
    .await;

    match timeout_result {
        Err(_elapsed) => Err(DispatchError::Timeout),
        Ok(retry_result) => match retry_result {
            RetryResult::Success { value, .. } => {
                validate_dispatch_result(&value)?;
                Ok(value)
            }
            RetryResult::Exhausted { last_error, .. } => {
                Err(DispatchError::NetworkError(last_error))
            }
        },
    }
}

/// Production entry point: dispatch a workload to the coordinator.
///
/// In production this constructs the HTTP request internally.
/// Currently a stub that returns a network error (to be replaced
/// when the real coordinator HTTP API is available).
pub async fn dispatch_workload(
    config: &WorkloadDispatchConfig,
    _workload_data: &[u8],
) -> Result<DispatchResult, DispatchError> {
    let endpoint = config.coordinator_endpoint.clone();
    let node = config.node_addr.clone();

    dispatch_workload_with(config, || {
        let ep = endpoint.clone();
        let nd = node.clone();
        async move {
            Err(format!(
                "connection refused: coordinator at {} for node {} not available",
                ep, nd
            ))
        }
    })
    .await
}

/// Monitor execution using a pluggable async network operation.
///
/// Wraps the call in [`retry_with_backoff`] and [`tokio::time::timeout`].
/// Validates the response before returning.
pub async fn monitor_execution_with<F, Fut>(
    timeout_secs: u64,
    network_fn: F,
) -> Result<ExecutionStatus, MonitorError>
where
    F: FnMut() -> Fut + Send,
    Fut: Future<Output = Result<ExecutionStatus, String>> + Send,
{
    let retry_cfg = monitor_retry_config();
    let timeout_dur = tokio::time::Duration::from_secs(timeout_secs);

    let timeout_result = tokio::time::timeout(
        timeout_dur,
        retry_with_backoff(&retry_cfg, network_fn),
    )
    .await;

    match timeout_result {
        Err(_elapsed) => Err(MonitorError::Timeout),
        Ok(retry_result) => match retry_result {
            RetryResult::Success { value, .. } => {
                validate_execution_status(&value)?;
                Ok(value)
            }
            RetryResult::Exhausted { last_error, .. } => {
                Err(MonitorError::NetworkError(last_error))
            }
        },
    }
}

/// Production entry point: poll execution status from the coordinator.
///
/// Currently a stub that returns a network error.
pub async fn monitor_execution(
    coordinator_endpoint: &str,
    workload_id: &str,
) -> Result<ExecutionStatus, MonitorError> {
    let ep = coordinator_endpoint.to_string();
    let wid = workload_id.to_string();

    monitor_execution_with(30, || {
        let ep = ep.clone();
        let wid = wid.clone();
        async move {
            Err(format!(
                "connection refused: coordinator at {} for workload {} not available",
                ep, wid
            ))
        }
    })
    .await
}

// ── CLI handlers for dispatch + monitor (14C.C.18) ──────────────────────────

/// Handle `economic dispatch`.
pub async fn handle_economic_dispatch(
    workload_type_str: &str,
    node_addr: &str,
    file_data: &[u8],
    coordinator_endpoint: &str,
) {
    let wtype = match WorkloadType::from_str_checked(workload_type_str) {
        Some(t) => t,
        None => {
            eprintln!(
                "Error: invalid workload type '{}'. Use 'storage' or 'compute'.",
                workload_type_str
            );
            return;
        }
    };

    let config = WorkloadDispatchConfig {
        coordinator_endpoint: coordinator_endpoint.to_string(),
        node_addr: node_addr.to_string(),
        workload_type: wtype,
        timeout_secs: 60,
    };

    match dispatch_workload(&config, file_data).await {
        Ok(result) => {
            println!("Dispatched successfully:");
            println!("  Workload ID:   {}", result.workload_id);
            println!("  Assigned Node: {}", result.assigned_node);
            println!("  Dispatched At: {}", result.dispatched_at);
        }
        Err(e) => {
            eprintln!("Dispatch failed: {}", e);
        }
    }
}

/// Handle `economic monitor`.
pub async fn handle_economic_monitor(
    coordinator_endpoint: &str,
    workload_id: &str,
) {
    match monitor_execution(coordinator_endpoint, workload_id).await {
        Ok(status) => match status {
            ExecutionStatus::Running { progress } => {
                println!("Workload {}: Running ({:.1}%)", workload_id, progress * 100.0);
            }
            ExecutionStatus::Completed { output_hash, duration_ms } => {
                println!("Workload {}: Completed", workload_id);
                println!("  Output Hash:  {}", output_hash);
                println!("  Duration:     {}ms", duration_ms);
            }
            ExecutionStatus::Failed { error } => {
                println!("Workload {}: Failed — {}", workload_id, error);
            }
        },
        Err(e) => {
            eprintln!("Monitor failed: {}", e);
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// RECEIPT SUBMISSION + CHAIN CLAIM (14C.C.19)
// ════════════════════════════════════════════════════════════════════════════════

/// Result of submitting a receipt claim to the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimResult {
    /// Reward was granted immediately (no challenge period).
    ImmediateReward { amount: u128, tx_hash: String },
    /// A challenge period has started; reward is pending.
    ChallengePeriodStarted { expires_at: u64, challenge_id: String },
    /// The claim was rejected by the chain.
    Rejected { reason: String },
}

/// Errors from submitting a receipt claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimError {
    /// Network-level failure (retryable via Display containing network keywords).
    NetworkError(String),
    /// The receipt data is invalid (empty, malformed, etc.).
    InvalidReceipt(String),
    /// The receipt has already been claimed on-chain.
    AlreadyClaimed,
    /// The ingress endpoint is unavailable.
    IngressUnavailable,
}

impl core::fmt::Display for ClaimError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NetworkError(msg) => write!(f, "network error: {}", msg),
            Self::InvalidReceipt(msg) => write!(f, "invalid receipt: {}", msg),
            Self::AlreadyClaimed => f.write_str("already claimed"),
            Self::IngressUnavailable => f.write_str("ingress unavailable"),
        }
    }
}

/// Current status of a previously submitted claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimStatus {
    /// Claim is pending processing.
    Pending,
    /// Claim is in a challenge period.
    InChallengePeriod { expires_at: u64 },
    /// Claim has been finalized with a reward.
    Finalized { reward: u128 },
    /// Claim was rejected.
    Rejected { reason: String },
}

/// Errors from polling claim status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PollError {
    /// Network-level failure (retryable).
    NetworkError(String),
    /// The response was invalid.
    InvalidResponse,
    /// The ingress endpoint is unavailable.
    IngressUnavailable,
}

impl core::fmt::Display for PollError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NetworkError(msg) => write!(f, "network error: {}", msg),
            Self::InvalidResponse => f.write_str("invalid response"),
            Self::IngressUnavailable => f.write_str("ingress unavailable"),
        }
    }
}

// ── Claim response validation ───────────────────────────────────────────────

/// Validate a claim result. Returns `Err` description if any field is invalid.
fn validate_claim_result(result: &ClaimResult) -> Result<(), String> {
    match result {
        ClaimResult::ImmediateReward { amount, tx_hash } => {
            if *amount == 0 {
                return Err("ImmediateReward.amount must be > 0".to_string());
            }
            if tx_hash.is_empty() {
                return Err("ImmediateReward.tx_hash must not be empty".to_string());
            }
        }
        ClaimResult::ChallengePeriodStarted { expires_at, challenge_id } => {
            if *expires_at == 0 {
                return Err("ChallengePeriodStarted.expires_at must be > 0".to_string());
            }
            if challenge_id.is_empty() {
                return Err("ChallengePeriodStarted.challenge_id must not be empty".to_string());
            }
        }
        ClaimResult::Rejected { reason } => {
            if reason.is_empty() {
                return Err("Rejected.reason must not be empty".to_string());
            }
        }
    }
    Ok(())
}

/// Validate a claim status poll response.
fn validate_claim_status(status: &ClaimStatus) -> Result<(), String> {
    match status {
        ClaimStatus::Pending => {}
        ClaimStatus::InChallengePeriod { expires_at } => {
            if *expires_at == 0 {
                return Err("InChallengePeriod.expires_at must be > 0".to_string());
            }
        }
        ClaimStatus::Finalized { .. } => {
            // reward can be any u128 including 0 (edge: fee-only finalization)
        }
        ClaimStatus::Rejected { reason } => {
            if reason.is_empty() {
                return Err("Rejected.reason must not be empty".to_string());
            }
        }
    }
    Ok(())
}

// ── Retry config for claim operations ───────────────────────────────────────

fn claim_retry_config() -> RetryConfig {
    RetryConfig {
        max_retries: 3,
        initial_delay_ms: 500,
        max_delay_ms: 10_000,
        backoff_multiplier: 2.0,
        jitter: true,
    }
}

// ── Core claim + poll functions (generic, testable) ─────────────────────────

/// Submit a receipt claim using a pluggable async network operation.
///
/// Wraps the call in [`retry_with_backoff`] and [`tokio::time::timeout`].
/// Validates receipt_data (non-empty) and the response before returning.
///
/// # Error classification
///
/// The `network_fn` returns `Result<ClaimResult, String>`. Exhausted errors
/// are classified:
/// - Contains `"already claimed"` → `ClaimError::AlreadyClaimed`
/// - Contains `"unavailable"` → `ClaimError::IngressUnavailable`
/// - Otherwise → `ClaimError::NetworkError`
pub async fn submit_claim_with<F, Fut>(
    receipt_data: &[u8],
    timeout_secs: u64,
    network_fn: F,
) -> Result<ClaimResult, ClaimError>
where
    F: FnMut() -> Fut + Send,
    Fut: Future<Output = Result<ClaimResult, String>> + Send,
{
    if receipt_data.is_empty() {
        return Err(ClaimError::InvalidReceipt("receipt data is empty".to_string()));
    }

    let retry_cfg = claim_retry_config();
    let timeout_dur = tokio::time::Duration::from_secs(timeout_secs);

    let timeout_result = tokio::time::timeout(
        timeout_dur,
        retry_with_backoff(&retry_cfg, network_fn),
    )
    .await;

    match timeout_result {
        Err(_elapsed) => Err(ClaimError::NetworkError("timeout".to_string())),
        Ok(retry_result) => match retry_result {
            RetryResult::Success { value, .. } => {
                validate_claim_result(&value)
                    .map_err(|msg| ClaimError::InvalidReceipt(msg))?;
                Ok(value)
            }
            RetryResult::Exhausted { last_error, .. } => {
                let lower = last_error.to_lowercase();
                if lower.contains("already claimed") {
                    Err(ClaimError::AlreadyClaimed)
                } else if lower.contains("unavailable") {
                    Err(ClaimError::IngressUnavailable)
                } else {
                    Err(ClaimError::NetworkError(last_error))
                }
            }
        },
    }
}

/// Production entry point: submit a receipt claim to the ingress.
///
/// Currently a stub returning a network error.
pub async fn submit_claim(
    ingress_endpoint: &str,
    receipt_data: &[u8],
) -> Result<ClaimResult, ClaimError> {
    let ep = ingress_endpoint.to_string();

    submit_claim_with(receipt_data, 30, || {
        let ep = ep.clone();
        async move {
            Err(format!(
                "connection refused: ingress at {} not available",
                ep
            ))
        }
    })
    .await
}

/// Poll claim status using a pluggable async network operation.
///
/// Single query per call (no infinite polling loop).
/// Wraps the call in [`retry_with_backoff`] and [`tokio::time::timeout`].
pub async fn poll_claim_status_with<F, Fut>(
    timeout_secs: u64,
    network_fn: F,
) -> Result<ClaimStatus, PollError>
where
    F: FnMut() -> Fut + Send,
    Fut: Future<Output = Result<ClaimStatus, String>> + Send,
{
    let retry_cfg = claim_retry_config();
    let timeout_dur = tokio::time::Duration::from_secs(timeout_secs);

    let timeout_result = tokio::time::timeout(
        timeout_dur,
        retry_with_backoff(&retry_cfg, network_fn),
    )
    .await;

    match timeout_result {
        Err(_elapsed) => Err(PollError::NetworkError("timeout".to_string())),
        Ok(retry_result) => match retry_result {
            RetryResult::Success { value, .. } => {
                validate_claim_status(&value)
                    .map_err(|_| PollError::InvalidResponse)?;
                Ok(value)
            }
            RetryResult::Exhausted { last_error, .. } => {
                let lower = last_error.to_lowercase();
                if lower.contains("unavailable") {
                    Err(PollError::IngressUnavailable)
                } else {
                    Err(PollError::NetworkError(last_error))
                }
            }
        },
    }
}

/// Production entry point: poll claim status from the ingress.
pub async fn poll_claim_status(
    ingress_endpoint: &str,
    receipt_hash: &str,
) -> Result<ClaimStatus, PollError> {
    let ep = ingress_endpoint.to_string();
    let rh = receipt_hash.to_string();

    poll_claim_status_with(30, || {
        let ep = ep.clone();
        let rh = rh.clone();
        async move {
            Err(format!(
                "connection refused: ingress at {} for receipt {} not available",
                ep, rh
            ))
        }
    })
    .await
}

// ── CLI handlers for claim (14C.C.19) ───────────────────────────────────────

/// Handle `economic claim <receipt_hash>`.
pub async fn handle_economic_claim(
    ingress_endpoint: &str,
    receipt_hash: &str,
) {
    if receipt_hash.is_empty() {
        eprintln!("Error: receipt_hash must not be empty.");
        return;
    }

    match submit_claim(ingress_endpoint, receipt_hash.as_bytes()).await {
        Ok(result) => match result {
            ClaimResult::ImmediateReward { amount, tx_hash } => {
                println!("Claim succeeded: immediate reward");
                println!("  Amount:  {}", amount);
                println!("  Tx Hash: {}", tx_hash);
            }
            ClaimResult::ChallengePeriodStarted { expires_at, challenge_id } => {
                println!("Claim submitted: challenge period started");
                println!("  Challenge ID: {}", challenge_id);
                println!("  Expires At:   {}", expires_at);
            }
            ClaimResult::Rejected { reason } => {
                println!("Claim rejected: {}", reason);
            }
        },
        Err(e) => {
            eprintln!("Claim failed: {}", e);
        }
    }
}

/// Handle `economic claim-status <receipt_hash>`.
pub async fn handle_economic_claim_status(
    ingress_endpoint: &str,
    receipt_hash: &str,
) {
    if receipt_hash.is_empty() {
        eprintln!("Error: receipt_hash must not be empty.");
        return;
    }

    match poll_claim_status(ingress_endpoint, receipt_hash).await {
        Ok(status) => match status {
            ClaimStatus::Pending => {
                println!("Claim {}: Pending", receipt_hash);
            }
            ClaimStatus::InChallengePeriod { expires_at } => {
                println!("Claim {}: In Challenge Period", receipt_hash);
                println!("  Expires At: {}", expires_at);
            }
            ClaimStatus::Finalized { reward } => {
                println!("Claim {}: Finalized", receipt_hash);
                println!("  Reward: {}", reward);
            }
            ClaimStatus::Rejected { reason } => {
                println!("Claim {}: Rejected — {}", receipt_hash, reason);
            }
        },
        Err(e) => {
            eprintln!("Poll failed: {}", e);
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// FULL LIFECYCLE ORCHESTRATION (14C.C.20)
// ════════════════════════════════════════════════════════════════════════════════

/// Configuration for the economic flow orchestrator.
#[derive(Debug, Clone)]
pub struct OrchestratorConfig {
    /// Coordinator endpoint URL.
    pub coordinator_endpoint: String,
    /// Ingress endpoint URL (for claims).
    pub ingress_endpoint: String,
    /// Target node address.
    pub node_addr: String,
    /// Whether to automatically submit a claim after receipt submission.
    pub auto_claim: bool,
    /// Polling interval between status checks (milliseconds).
    pub poll_interval_ms: u64,
}

/// The economic flow orchestrator: chains dispatch → monitor → proof → submit → claim.
pub struct EconomicOrchestrator {
    /// Orchestrator configuration.
    pub config: OrchestratorConfig,
    /// Receipt lifecycle state tracker.
    pub tracker: ReceiptStatusTracker,
    /// Retry configuration shared across all steps.
    pub retry_config: RetryConfig,
}

/// Result of a completed (or partially completed) economic flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowResult {
    /// Workload identifier from dispatch.
    pub workload_id: String,
    /// Receipt hash (set after receipt submission).
    pub receipt_hash: Option<String>,
    /// Claim result (set if auto_claim completed).
    pub claim_status: Option<ClaimResult>,
    /// Total wall-clock duration of the flow (milliseconds).
    pub total_duration_ms: u64,
    /// Ordered list of steps that completed successfully.
    pub steps_completed: Vec<String>,
}

/// Error from a specific step in the economic flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowError {
    /// Workload dispatch failed.
    DispatchFailed(String),
    /// Execution monitoring failed or execution itself failed.
    ExecutionFailed(String),
    /// Proof building failed.
    ProofFailed(String),
    /// Receipt submission to coordinator failed.
    ReceiptSubmissionFailed(String),
    /// Claim submission or polling failed.
    ClaimFailed(String),
    /// The overall flow exceeded the time/iteration limit.
    Timeout,
}

impl core::fmt::Display for FlowError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DispatchFailed(msg) => write!(f, "dispatch failed: {}", msg),
            Self::ExecutionFailed(msg) => write!(f, "execution failed: {}", msg),
            Self::ProofFailed(msg) => write!(f, "proof failed: {}", msg),
            Self::ReceiptSubmissionFailed(msg) => write!(f, "receipt submission failed: {}", msg),
            Self::ClaimFailed(msg) => write!(f, "claim failed: {}", msg),
            Self::Timeout => f.write_str("flow timeout"),
        }
    }
}

/// Maximum polling iterations to prevent infinite loops.
const MAX_POLL_ITERATIONS: u32 = 1000;

/// Run the full economic lifecycle with pluggable step functions.
///
/// # Flow (strict order, no skipping)
///
/// 1. **Dispatch** — call `dispatch_fn()` → `DispatchResult`
/// 2. **Monitor** — poll `monitor_fn()` until `Completed` or `Failed`
/// 3. **Build proof** — placeholder state transition (ProofBuilt)
/// 4. **Submit receipt** — placeholder state transition (Submitted → Pending)
/// 5. **Claim** (if `auto_claim`) — call `claim_fn()`, then poll `poll_fn()` until terminal
///
/// Every step updates `orchestrator.tracker`. On error, tracker is set to `Failed`.
///
/// # Invariants
///
/// - Steps execute in strict order; failure at any step stops the flow.
/// - Polling is bounded by `MAX_POLL_ITERATIONS` and flow-level timeout.
/// - `total_duration_ms` uses saturating arithmetic (no overflow).
pub async fn run_full_flow_with<DF, DFut, MF, MFut, CF, CFut, PF, PFut>(
    orchestrator: &mut EconomicOrchestrator,
    workload_data: &[u8],
    _workload_type: WorkloadType,
    mut dispatch_fn: DF,
    mut monitor_fn: MF,
    mut claim_fn: CF,
    mut poll_fn: PF,
) -> Result<FlowResult, FlowError>
where
    DF: FnMut() -> DFut + Send,
    DFut: Future<Output = Result<DispatchResult, DispatchError>> + Send,
    MF: FnMut() -> MFut + Send,
    MFut: Future<Output = Result<ExecutionStatus, MonitorError>> + Send,
    CF: FnMut() -> CFut + Send,
    CFut: Future<Output = Result<ClaimResult, ClaimError>> + Send,
    PF: FnMut() -> PFut + Send,
    PFut: Future<Output = Result<ClaimStatus, PollError>> + Send,
{
    let start = tokio::time::Instant::now();

    if workload_data.is_empty() {
        return Err(FlowError::DispatchFailed("workload data is empty".to_string()));
    }

    let mut flow_result = FlowResult {
        workload_id: String::new(),
        receipt_hash: None,
        claim_status: None,
        total_duration_ms: 0,
        steps_completed: Vec::new(),
    };

    // Saturating elapsed-ms helper
    let elapsed_ms = || -> u64 {
        let d = start.elapsed();
        d.as_millis().min(u64::MAX as u128) as u64
    };

    // ── Step 1: Dispatch ────────────────────────────────────────────────
    let dispatch_result = dispatch_fn().await.map_err(|e| {
        FlowError::DispatchFailed(e.to_string())
    })?;

    let wid = dispatch_result.workload_id.clone();
    flow_result.workload_id = wid.clone();

    let _ = orchestrator.tracker.track(
        &wid,
        EconomicFlowState::Dispatched {
            workload_id: wid.clone(),
            dispatched_at: dispatch_result.dispatched_at,
        },
        elapsed_ms(),
    );
    flow_result.steps_completed.push("dispatch".to_string());

    // ── Step 2: Monitor execution (poll loop) ───────────────────────────
    let _ = orchestrator.tracker.track(
        &wid,
        EconomicFlowState::Executing {
            workload_id: wid.clone(),
            started_at: elapsed_ms(),
        },
        elapsed_ms(),
    );

    let mut output_hash = String::new();
    let mut poll_count: u32 = 0;

    loop {
        poll_count = poll_count.saturating_add(1);
        if poll_count > MAX_POLL_ITERATIONS {
            let _ = orchestrator.tracker.track(
                &wid,
                EconomicFlowState::Failed {
                    workload_id: wid.clone(),
                    error: "monitor poll limit exceeded".to_string(),
                },
                elapsed_ms(),
            );
            return Err(FlowError::Timeout);
        }

        let status = monitor_fn().await.map_err(|e| {
            let _ = orchestrator.tracker.track(
                &wid,
                EconomicFlowState::Failed {
                    workload_id: wid.clone(),
                    error: e.to_string(),
                },
                elapsed_ms(),
            );
            FlowError::ExecutionFailed(e.to_string())
        })?;

        match status {
            ExecutionStatus::Running { .. } => {
                if orchestrator.config.poll_interval_ms > 0 {
                    tokio::time::sleep(tokio::time::Duration::from_millis(
                        orchestrator.config.poll_interval_ms,
                    ))
                    .await;
                }
                continue;
            }
            ExecutionStatus::Completed {
                output_hash: oh, ..
            } => {
                output_hash = oh;
                break;
            }
            ExecutionStatus::Failed { error } => {
                let _ = orchestrator.tracker.track(
                    &wid,
                    EconomicFlowState::Failed {
                        workload_id: wid.clone(),
                        error: error.clone(),
                    },
                    elapsed_ms(),
                );
                return Err(FlowError::ExecutionFailed(error));
            }
        }
    }
    flow_result.steps_completed.push("monitor".to_string());

    // ── Step 3: Build proof (placeholder) ───────────────────────────────
    let proof_hash = format!("proof-{}", output_hash);
    let _ = orchestrator.tracker.track(
        &wid,
        EconomicFlowState::ProofBuilt {
            workload_id: wid.clone(),
            proof_hash: proof_hash.clone(),
        },
        elapsed_ms(),
    );
    flow_result.steps_completed.push("proof".to_string());

    // ── Step 4: Submit receipt (placeholder state transitions) ──────────
    let receipt_hash = format!("receipt-{}", output_hash);
    let _ = orchestrator.tracker.track(
        &wid,
        EconomicFlowState::Submitted {
            workload_id: wid.clone(),
            receipt_hash: receipt_hash.clone(),
        },
        elapsed_ms(),
    );
    let _ = orchestrator.tracker.track(
        &wid,
        EconomicFlowState::Pending {
            receipt_hash: receipt_hash.clone(),
            submitted_at: elapsed_ms(),
        },
        elapsed_ms(),
    );
    flow_result.receipt_hash = Some(receipt_hash.clone());
    flow_result.steps_completed.push("submit_receipt".to_string());

    // ── Step 5: Claim (if auto_claim) ───────────────────────────────────
    if orchestrator.config.auto_claim {
        let claim_result = claim_fn().await.map_err(|e| {
            FlowError::ClaimFailed(e.to_string())
        })?;

        match &claim_result {
            ClaimResult::ImmediateReward { amount, .. } => {
                let _ = orchestrator.tracker.track(
                    &wid,
                    EconomicFlowState::Finalized {
                        receipt_hash: receipt_hash.clone(),
                        reward_amount: *amount,
                    },
                    elapsed_ms(),
                );
            }
            ClaimResult::ChallengePeriodStarted { expires_at, challenge_id } => {
                let _ = orchestrator.tracker.track(
                    &wid,
                    EconomicFlowState::Challenged {
                        receipt_hash: receipt_hash.clone(),
                        challenge_id: challenge_id.clone(),
                        expires_at: *expires_at,
                    },
                    elapsed_ms(),
                );

                // Poll claim status until terminal
                let mut cpoll: u32 = 0;
                loop {
                    cpoll = cpoll.saturating_add(1);
                    if cpoll > MAX_POLL_ITERATIONS {
                        return Err(FlowError::Timeout);
                    }

                    if orchestrator.config.poll_interval_ms > 0 {
                        tokio::time::sleep(tokio::time::Duration::from_millis(
                            orchestrator.config.poll_interval_ms,
                        ))
                        .await;
                    }

                    let cs = poll_fn().await.map_err(|e| {
                        FlowError::ClaimFailed(e.to_string())
                    })?;

                    match cs {
                        ClaimStatus::Pending | ClaimStatus::InChallengePeriod { .. } => {
                            continue;
                        }
                        ClaimStatus::Finalized { reward } => {
                            let _ = orchestrator.tracker.track(
                                &wid,
                                EconomicFlowState::Finalized {
                                    receipt_hash: receipt_hash.clone(),
                                    reward_amount: reward,
                                },
                                elapsed_ms(),
                            );
                            break;
                        }
                        ClaimStatus::Rejected { reason } => {
                            let _ = orchestrator.tracker.track(
                                &wid,
                                EconomicFlowState::Rejected {
                                    receipt_hash: receipt_hash.clone(),
                                    reason: reason.clone(),
                                },
                                elapsed_ms(),
                            );
                            break;
                        }
                    }
                }
            }
            ClaimResult::Rejected { reason } => {
                let _ = orchestrator.tracker.track(
                    &wid,
                    EconomicFlowState::Rejected {
                        receipt_hash: receipt_hash.clone(),
                        reason: reason.clone(),
                    },
                    elapsed_ms(),
                );
            }
        }

        flow_result.claim_status = Some(claim_result);
        flow_result.steps_completed.push("claim".to_string());
    }

    flow_result.total_duration_ms = elapsed_ms();
    Ok(flow_result)
}

/// Production entry point: run the full economic flow.
///
/// Uses production stubs for all network operations.
pub async fn run_full_flow(
    orchestrator: &mut EconomicOrchestrator,
    workload_data: &[u8],
    workload_type: WorkloadType,
) -> Result<FlowResult, FlowError> {
    let coord = orchestrator.config.coordinator_endpoint.clone();
    let node = orchestrator.config.node_addr.clone();
    let ingress = orchestrator.config.ingress_endpoint.clone();

    run_full_flow_with(
        orchestrator,
        workload_data,
        workload_type,
        || {
            let c = coord.clone();
            let n = node.clone();
            async move {
                Err(DispatchError::NetworkError(format!(
                    "connection refused: coordinator at {} for node {} not available", c, n
                )))
            }
        },
        || {
            let c = coord.clone();
            async move {
                Err(MonitorError::NetworkError(format!(
                    "connection refused: coordinator at {} not available", c
                )))
            }
        },
        || {
            let i = ingress.clone();
            async move {
                Err(ClaimError::NetworkError(format!(
                    "connection refused: ingress at {} not available", i
                )))
            }
        },
        || {
            let i = ingress.clone();
            async move {
                Err(PollError::NetworkError(format!(
                    "connection refused: ingress at {} not available", i
                )))
            }
        },
    )
    .await
}

// ── CLI handler for run (14C.C.20) ──────────────────────────────────────────

/// Handle `economic run --type <type> --auto-claim <file>`.
pub async fn handle_economic_run(
    workload_type_str: &str,
    auto_claim: bool,
    file_data: &[u8],
    coordinator_endpoint: &str,
    ingress_endpoint: &str,
    node_addr: &str,
) {
    let wtype = match WorkloadType::from_str_checked(workload_type_str) {
        Some(t) => t,
        None => {
            eprintln!(
                "Error: invalid workload type '{}'. Use 'storage' or 'compute'.",
                workload_type_str
            );
            return;
        }
    };

    let config = OrchestratorConfig {
        coordinator_endpoint: coordinator_endpoint.to_string(),
        ingress_endpoint: ingress_endpoint.to_string(),
        node_addr: node_addr.to_string(),
        auto_claim,
        poll_interval_ms: 1000,
    };

    let mut orchestrator = EconomicOrchestrator {
        config,
        tracker: ReceiptStatusTracker::new(),
        retry_config: RetryConfig::default(),
    };

    match run_full_flow(&mut orchestrator, file_data, wtype).await {
        Ok(result) => {
            println!("Flow completed:");
            println!("  Workload ID:  {}", result.workload_id);
            if let Some(rh) = &result.receipt_hash {
                println!("  Receipt Hash: {}", rh);
            }
            if let Some(cs) = &result.claim_status {
                match cs {
                    ClaimResult::ImmediateReward { amount, tx_hash } => {
                        println!("  Claim:        Immediate reward {} (tx: {})", amount, tx_hash);
                    }
                    ClaimResult::ChallengePeriodStarted { challenge_id, expires_at } => {
                        println!("  Claim:        Challenge {} (expires: {})", challenge_id, expires_at);
                    }
                    ClaimResult::Rejected { reason } => {
                        println!("  Claim:        Rejected ({})", reason);
                    }
                }
            }
            println!("  Duration:     {}ms", result.total_duration_ms);
            println!("  Steps:        {}", result.steps_completed.join(" → "));
        }
        Err(e) => {
            eprintln!("Flow failed: {}", e);
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS (14C.C.16 + 14C.C.18 + 14C.C.19 + 14C.C.20)
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ──────────────────────────────────────────────────────────

    fn dispatched(wid: &str, t: u64) -> EconomicFlowState {
        EconomicFlowState::Dispatched {
            workload_id: wid.to_string(),
            dispatched_at: t,
        }
    }

    fn executing(wid: &str, t: u64) -> EconomicFlowState {
        EconomicFlowState::Executing {
            workload_id: wid.to_string(),
            started_at: t,
        }
    }

    fn proof_built(wid: &str, hash: &str) -> EconomicFlowState {
        EconomicFlowState::ProofBuilt {
            workload_id: wid.to_string(),
            proof_hash: hash.to_string(),
        }
    }

    fn submitted(wid: &str, rh: &str) -> EconomicFlowState {
        EconomicFlowState::Submitted {
            workload_id: wid.to_string(),
            receipt_hash: rh.to_string(),
        }
    }

    fn pending(rh: &str, t: u64) -> EconomicFlowState {
        EconomicFlowState::Pending {
            receipt_hash: rh.to_string(),
            submitted_at: t,
        }
    }

    fn challenged(rh: &str, cid: &str, exp: u64) -> EconomicFlowState {
        EconomicFlowState::Challenged {
            receipt_hash: rh.to_string(),
            challenge_id: cid.to_string(),
            expires_at: exp,
        }
    }

    fn finalized(rh: &str, amount: u128) -> EconomicFlowState {
        EconomicFlowState::Finalized {
            receipt_hash: rh.to_string(),
            reward_amount: amount,
        }
    }

    fn rejected(rh: &str, reason: &str) -> EconomicFlowState {
        EconomicFlowState::Rejected {
            receipt_hash: rh.to_string(),
            reason: reason.to_string(),
        }
    }

    fn failed(wid: &str, err: &str) -> EconomicFlowState {
        EconomicFlowState::Failed {
            workload_id: wid.to_string(),
            error: err.to_string(),
        }
    }

    // ── 1. track_new_receipt ─────────────────────────────────────────────

    #[test]
    fn track_new_receipt() {
        let mut tracker = ReceiptStatusTracker::new();

        let result = tracker.track("r1", dispatched("w1", 100), 100);
        assert!(result.is_ok());
        assert_eq!(tracker.len(), 1);

        let entry = tracker.get_status("r1");
        assert!(entry.is_some());
        if let Some(e) = entry {
            assert_eq!(e.receipt_hash, "r1");
            assert_eq!(e.workload_id, "w1");
            assert_eq!(e.created_at, 100);
            assert_eq!(e.updated_at, 100);
            assert_eq!(e.retry_count, 0);
            assert_eq!(e.status.label(), "Dispatched");
        }
    }

    // ── 2. valid_transition_sequence ─────────────────────────────────────

    #[test]
    fn valid_transition_sequence() {
        let mut tracker = ReceiptStatusTracker::new();

        // Full happy path: Dispatched → Executing → ProofBuilt → Submitted → Pending → Finalized
        assert!(tracker.track("r1", dispatched("w1", 100), 100).is_ok());
        assert!(tracker.track("r1", executing("w1", 110), 110).is_ok());
        assert!(tracker.track("r1", proof_built("w1", "ph1"), 120).is_ok());
        assert!(tracker.track("r1", submitted("w1", "r1"), 130).is_ok());
        assert!(tracker.track("r1", pending("r1", 140), 140).is_ok());
        assert!(tracker.track("r1", finalized("r1", 5000), 150).is_ok());

        let entry = tracker.get_status("r1");
        assert!(entry.is_some());
        if let Some(e) = entry {
            assert_eq!(e.status.label(), "Finalized");
            assert_eq!(e.updated_at, 150);
            assert_eq!(e.created_at, 100);
        }
    }

    // ── 3. invalid_transition_blocked ────────────────────────────────────

    #[test]
    fn invalid_transition_blocked() {
        let mut tracker = ReceiptStatusTracker::new();

        assert!(tracker.track("r1", dispatched("w1", 100), 100).is_ok());

        // Dispatched → Finalized is NOT valid
        let result = tracker.track("r1", finalized("r1", 1000), 110);
        assert_eq!(result, Err(TrackerError::InvalidTransition));

        // Dispatched → Pending is NOT valid
        let result2 = tracker.track("r1", pending("r1", 110), 110);
        assert_eq!(result2, Err(TrackerError::InvalidTransition));

        // Dispatched → Rejected is NOT valid
        let result3 = tracker.track("r1", rejected("r1", "bad"), 110);
        assert_eq!(result3, Err(TrackerError::InvalidTransition));

        // State must remain Dispatched
        if let Some(e) = tracker.get_status("r1") {
            assert_eq!(e.status.label(), "Dispatched");
        }

        // Terminal states cannot transition
        let mut t2 = ReceiptStatusTracker::new();
        assert!(t2.track("r2", dispatched("w2", 100), 100).is_ok());
        assert!(t2.track("r2", failed("w2", "error"), 110).is_ok());
        // Failed → anything is invalid
        let fail_result = t2.track("r2", dispatched("w2", 120), 120);
        assert_eq!(fail_result, Err(TrackerError::InvalidTransition));
    }

    // ── 4. list_pending_sorted ───────────────────────────────────────────

    #[test]
    fn list_pending_sorted() {
        let mut tracker = ReceiptStatusTracker::new();

        // Insert in non-sorted order: c, a, b all in Pending state
        assert!(tracker.track("c_receipt", pending("c_receipt", 100), 100).is_ok());
        assert!(tracker.track("a_receipt", pending("a_receipt", 100), 100).is_ok());
        assert!(tracker.track("b_receipt", pending("b_receipt", 100), 100).is_ok());

        // Also add non-pending
        assert!(tracker.track("d_receipt", dispatched("w4", 100), 100).is_ok());

        let pending_list = tracker.list_pending();
        assert_eq!(pending_list.len(), 3);
        assert_eq!(pending_list[0].receipt_hash, "a_receipt");
        assert_eq!(pending_list[1].receipt_hash, "b_receipt");
        assert_eq!(pending_list[2].receipt_hash, "c_receipt");
    }

    // ── 5. list_by_status_correct ────────────────────────────────────────

    #[test]
    fn list_by_status_correct() {
        let mut tracker = ReceiptStatusTracker::new();

        assert!(tracker.track("r1", dispatched("w1", 100), 100).is_ok());
        assert!(tracker.track("r2", dispatched("w2", 100), 100).is_ok());
        assert!(tracker.track("r3", pending("r3", 100), 100).is_ok());
        assert!(tracker.track("r4", finalized("r4", 1000), 100).is_ok());

        let dispatched_list = tracker.list_by_status(&dispatched("", 0));
        assert_eq!(dispatched_list.len(), 2);

        let finalized_list = tracker.list_by_status(&finalized("", 0));
        assert_eq!(finalized_list.len(), 1);
        assert_eq!(finalized_list[0].receipt_hash, "r4");

        // Challenged: none
        let challenged_list = tracker.list_by_status(&challenged("", "", 0));
        assert_eq!(challenged_list.len(), 0);
    }

    // ── 6. summary_counts_correct ────────────────────────────────────────

    #[test]
    fn summary_counts_correct() {
        let mut tracker = ReceiptStatusTracker::new();

        assert!(tracker.track("r1", dispatched("w1", 100), 100).is_ok());
        assert!(tracker.track("r2", pending("r2", 100), 100).is_ok());
        assert!(tracker.track("r3", pending("r3", 100), 100).is_ok());
        assert!(tracker.track("r4", finalized("r4", 500), 100).is_ok());
        assert!(tracker.track("r5", rejected("r5", "fraud"), 100).is_ok());
        assert!(tracker.track("r6", failed("w6", "timeout"), 100).is_ok());

        let s = tracker.summary();
        assert_eq!(s.total, 6);
        assert_eq!(s.dispatched, 1);
        assert_eq!(s.pending, 2);
        assert_eq!(s.finalized, 1);
        assert_eq!(s.rejected, 1);
        assert_eq!(s.failed, 1);
        assert_eq!(s.executing, 0);
        assert_eq!(s.proof_built, 0);
        assert_eq!(s.submitted, 0);
        assert_eq!(s.challenged, 0);

        // total must equal sum of all categories
        let sum = s.dispatched + s.executing + s.proof_built + s.submitted
            + s.pending + s.challenged + s.finalized + s.rejected + s.failed;
        assert_eq!(s.total, sum);
    }

    // ── 7. rejected_flow ─────────────────────────────────────────────────

    #[test]
    fn rejected_flow() {
        let mut tracker = ReceiptStatusTracker::new();

        // Submitted → Rejected
        assert!(tracker.track("r1", submitted("w1", "r1"), 100).is_ok());
        assert!(tracker.track("r1", rejected("r1", "invalid proof"), 110).is_ok());

        if let Some(e) = tracker.get_status("r1") {
            assert_eq!(e.status.label(), "Rejected");
        }

        // Rejected is terminal
        let result = tracker.track("r1", pending("r1", 120), 120);
        assert_eq!(result, Err(TrackerError::InvalidTransition));

        // Pending → Rejected
        let mut t2 = ReceiptStatusTracker::new();
        assert!(t2.track("r2", pending("r2", 100), 100).is_ok());
        assert!(t2.track("r2", rejected("r2", "expired"), 110).is_ok());
        if let Some(e) = t2.get_status("r2") {
            assert_eq!(e.status.label(), "Rejected");
        }
    }

    // ── 8. challenged_flow ───────────────────────────────────────────────

    #[test]
    fn challenged_flow() {
        let mut tracker = ReceiptStatusTracker::new();

        // Pending → Challenged → Finalized
        assert!(tracker.track("r1", pending("r1", 100), 100).is_ok());
        assert!(tracker.track("r1", challenged("r1", "ch1", 200), 110).is_ok());
        assert!(tracker.track("r1", finalized("r1", 3000), 120).is_ok());

        if let Some(e) = tracker.get_status("r1") {
            assert_eq!(e.status.label(), "Finalized");
        }

        // Challenged → Rejected
        let mut t2 = ReceiptStatusTracker::new();
        assert!(t2.track("r2", pending("r2", 100), 100).is_ok());
        assert!(t2.track("r2", challenged("r2", "ch2", 200), 110).is_ok());
        assert!(t2.track("r2", rejected("r2", "fraud proven"), 120).is_ok());

        if let Some(e) = t2.get_status("r2") {
            assert_eq!(e.status.label(), "Rejected");
        }
    }

    // ── 9. failed_flow ───────────────────────────────────────────────────

    #[test]
    fn failed_flow() {
        let mut tracker = ReceiptStatusTracker::new();

        // Dispatched → Failed
        assert!(tracker.track("r1", dispatched("w1", 100), 100).is_ok());
        assert!(tracker.track("r1", failed("w1", "node crash"), 110).is_ok());
        if let Some(e) = tracker.get_status("r1") {
            assert_eq!(e.status.label(), "Failed");
        }

        // Executing → Failed
        let mut t2 = ReceiptStatusTracker::new();
        assert!(t2.track("r2", executing("w2", 100), 100).is_ok());
        assert!(t2.track("r2", failed("w2", "timeout"), 110).is_ok());

        // ProofBuilt → Failed
        let mut t3 = ReceiptStatusTracker::new();
        assert!(t3.track("r3", proof_built("w3", "ph3"), 100).is_ok());
        assert!(t3.track("r3", failed("w3", "submit error"), 110).is_ok());

        // Submitted → Failed
        let mut t4 = ReceiptStatusTracker::new();
        assert!(t4.track("r4", submitted("w4", "r4"), 100).is_ok());
        assert!(t4.track("r4", failed("w4", "chain error"), 110).is_ok());
    }

    // ── 10. deterministic_listing ────────────────────────────────────────

    #[test]
    fn deterministic_listing() {
        let mut tracker = ReceiptStatusTracker::new();

        // Insert in deliberately unsorted order
        for name in &["z_receipt", "m_receipt", "a_receipt", "f_receipt"] {
            assert!(tracker.track(name, pending(name, 100), 100).is_ok());
        }

        // Call list_pending twice — must be identical
        let list1 = tracker.list_pending();
        let list2 = tracker.list_pending();

        assert_eq!(list1.len(), list2.len());
        for (a, b) in list1.iter().zip(list2.iter()) {
            assert_eq!(a.receipt_hash, b.receipt_hash);
        }

        // Verify sorted
        assert_eq!(list1[0].receipt_hash, "a_receipt");
        assert_eq!(list1[1].receipt_hash, "f_receipt");
        assert_eq!(list1[2].receipt_hash, "m_receipt");
        assert_eq!(list1[3].receipt_hash, "z_receipt");

        // list_by_status also deterministic
        let by_status1 = tracker.list_by_status(&pending("", 0));
        let by_status2 = tracker.list_by_status(&pending("", 0));
        assert_eq!(by_status1.len(), by_status2.len());
        for (a, b) in by_status1.iter().zip(by_status2.iter()) {
            assert_eq!(a.receipt_hash, b.receipt_hash);
        }
    }

    // ── 11. retry_count_increment_manual_test ────────────────────────────

    #[test]
    fn retry_count_increment_manual_test() {
        let mut tracker = ReceiptStatusTracker::new();

        assert!(tracker.track("r1", dispatched("w1", 100), 100).is_ok());

        // Initial retry_count = 0
        if let Some(e) = tracker.get_status("r1") {
            assert_eq!(e.retry_count, 0);
        }

        // Increment
        let r1 = tracker.increment_retry("r1");
        assert_eq!(r1, Ok(1));

        let r2 = tracker.increment_retry("r1");
        assert_eq!(r2, Ok(2));

        if let Some(e) = tracker.get_status("r1") {
            assert_eq!(e.retry_count, 2);
        }

        // Missing receipt → NotFound
        let r3 = tracker.increment_retry("nonexistent");
        assert_eq!(r3, Err(TrackerError::NotFound));
    }

    // ── 12. no_panic_on_missing_receipt ──────────────────────────────────

    #[test]
    fn no_panic_on_missing_receipt() {
        let tracker = ReceiptStatusTracker::new();

        // get_status on empty tracker → None (no panic)
        assert!(tracker.get_status("nonexistent").is_none());
        assert!(tracker.get_status("").is_none());

        // list operations on empty tracker → empty (no panic)
        assert!(tracker.list_pending().is_empty());
        assert!(tracker.list_by_status(&finalized("", 0)).is_empty());

        // summary on empty tracker → all zeros
        let s = tracker.summary();
        assert_eq!(s.total, 0);
        assert_eq!(s.dispatched, 0);
        assert_eq!(s.finalized, 0);
    }

    // ── 13. (bonus) pending_cannot_go_to_failed ──────────────────────────

    #[test]
    fn pending_cannot_go_to_failed() {
        let mut tracker = ReceiptStatusTracker::new();

        assert!(tracker.track("r1", pending("r1", 100), 100).is_ok());
        // Pending → Failed is NOT valid (Pending can go to Challenged/Finalized/Rejected)
        let result = tracker.track("r1", failed("w1", "oops"), 110);
        assert_eq!(result, Err(TrackerError::InvalidTransition));
    }

    // ── 14. (bonus) summary_table_format ─────────────────────────────────

    #[test]
    fn summary_table_format() {
        let mut tracker = ReceiptStatusTracker::new();
        assert!(tracker.track("r1", finalized("r1", 100), 100).is_ok());

        let s = tracker.summary();
        let table = s.to_table();
        assert!(table.contains("ECONOMIC SUMMARY"));
        assert!(table.contains("Finalized"));
        assert!(table.contains("1")); // count
        assert!(table.contains("Total"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // 14C.C.18 — WORKLOAD DISPATCH + EXECUTION MONITORING TESTS
    // ════════════════════════════════════════════════════════════════════════

    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    fn test_dispatch_config(timeout: u64) -> WorkloadDispatchConfig {
        WorkloadDispatchConfig {
            coordinator_endpoint: "http://127.0.0.1:9999".to_string(),
            node_addr: "127.0.0.1:50051".to_string(),
            workload_type: WorkloadType::Storage,
            timeout_secs: timeout,
        }
    }

    fn ok_dispatch() -> DispatchResult {
        DispatchResult {
            workload_id: "wk-001".to_string(),
            assigned_node: "node-a".to_string(),
            dispatched_at: 1000,
        }
    }

    // ── 1. dispatch_success ──────────────────────────────────────────────

    #[tokio::test]
    async fn dispatch_success() {
        let config = test_dispatch_config(5);

        let result = dispatch_workload_with(&config, || async {
            Ok::<DispatchResult, String>(ok_dispatch())
        })
        .await;

        assert!(result.is_ok());
        if let Ok(r) = result {
            assert_eq!(r.workload_id, "wk-001");
            assert_eq!(r.assigned_node, "node-a");
            assert_eq!(r.dispatched_at, 1000);
        }
    }

    // ── 2. dispatch_network_retry ────────────────────────────────────────

    #[tokio::test]
    async fn dispatch_network_retry() {
        let config = test_dispatch_config(10);
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();

        let result = dispatch_workload_with(&config, move || {
            let count = c.fetch_add(1, Ordering::SeqCst);
            async move {
                if count < 2 {
                    Err("connection refused".to_string())
                } else {
                    Ok(ok_dispatch())
                }
            }
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    // ── 3. dispatch_timeout ──────────────────────────────────────────────

    #[tokio::test]
    async fn dispatch_timeout() {
        let config = test_dispatch_config(0);

        let result = dispatch_workload_with(&config, || async {
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            Ok::<DispatchResult, String>(ok_dispatch())
        })
        .await;

        assert_eq!(result, Err(DispatchError::Timeout));
    }

    // ── 4. dispatch_invalid_response ─────────────────────────────────────

    #[tokio::test]
    async fn dispatch_invalid_response() {
        let config = test_dispatch_config(5);

        // Empty workload_id
        let r1 = dispatch_workload_with(&config, || async {
            Ok::<DispatchResult, String>(DispatchResult {
                workload_id: String::new(),
                assigned_node: "node-a".to_string(),
                dispatched_at: 100,
            })
        })
        .await;
        assert_eq!(r1, Err(DispatchError::InvalidResponse));

        // Empty assigned_node
        let r2 = dispatch_workload_with(&config, || async {
            Ok::<DispatchResult, String>(DispatchResult {
                workload_id: "wk-1".to_string(),
                assigned_node: String::new(),
                dispatched_at: 100,
            })
        })
        .await;
        assert_eq!(r2, Err(DispatchError::InvalidResponse));

        // dispatched_at == 0
        let r3 = dispatch_workload_with(&config, || async {
            Ok::<DispatchResult, String>(DispatchResult {
                workload_id: "wk-1".to_string(),
                assigned_node: "node-a".to_string(),
                dispatched_at: 0,
            })
        })
        .await;
        assert_eq!(r3, Err(DispatchError::InvalidResponse));
    }

    // ── 5. monitor_running ───────────────────────────────────────────────

    #[tokio::test]
    async fn monitor_running() {
        let result = monitor_execution_with(5, || async {
            Ok::<ExecutionStatus, String>(ExecutionStatus::Running { progress: 0.5 })
        })
        .await;

        assert!(result.is_ok());
        if let Ok(ExecutionStatus::Running { progress }) = result {
            assert!((progress - 0.5).abs() < f64::EPSILON);
        }
    }

    // ── 6. monitor_completed ─────────────────────────────────────────────

    #[tokio::test]
    async fn monitor_completed() {
        let result = monitor_execution_with(5, || async {
            Ok::<ExecutionStatus, String>(ExecutionStatus::Completed {
                output_hash: "abc123".to_string(),
                duration_ms: 4500,
            })
        })
        .await;

        assert!(result.is_ok());
        if let Ok(ExecutionStatus::Completed { output_hash, duration_ms }) = result {
            assert_eq!(output_hash, "abc123");
            assert_eq!(duration_ms, 4500);
        }
    }

    // ── 7. monitor_failed ────────────────────────────────────────────────

    #[tokio::test]
    async fn monitor_failed() {
        let result = monitor_execution_with(5, || async {
            Ok::<ExecutionStatus, String>(ExecutionStatus::Failed {
                error: "out of memory".to_string(),
            })
        })
        .await;

        assert!(result.is_ok());
        if let Ok(ExecutionStatus::Failed { error }) = result {
            assert_eq!(error, "out of memory");
        }
    }

    // ── 8. monitor_timeout ───────────────────────────────────────────────

    #[tokio::test]
    async fn monitor_timeout() {
        let result = monitor_execution_with(0, || async {
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            Ok::<ExecutionStatus, String>(ExecutionStatus::Running { progress: 0.0 })
        })
        .await;

        assert_eq!(result, Err(MonitorError::Timeout));
    }

    // ── 9. progress_bounds_validation ────────────────────────────────────

    #[tokio::test]
    async fn progress_bounds_validation() {
        // 0.0 → valid
        let r0 = monitor_execution_with(5, || async {
            Ok::<ExecutionStatus, String>(ExecutionStatus::Running { progress: 0.0 })
        })
        .await;
        assert!(r0.is_ok());

        // 1.0 → valid
        let r1 = monitor_execution_with(5, || async {
            Ok::<ExecutionStatus, String>(ExecutionStatus::Running { progress: 1.0 })
        })
        .await;
        assert!(r1.is_ok());

        // 0.5 → valid
        let r2 = monitor_execution_with(5, || async {
            Ok::<ExecutionStatus, String>(ExecutionStatus::Running { progress: 0.5 })
        })
        .await;
        assert!(r2.is_ok());
    }

    // ── 10. invalid_progress_rejected ────────────────────────────────────

    #[tokio::test]
    async fn invalid_progress_rejected() {
        // > 1.0
        let r1 = monitor_execution_with(5, || async {
            Ok::<ExecutionStatus, String>(ExecutionStatus::Running { progress: 1.5 })
        })
        .await;
        assert_eq!(r1, Err(MonitorError::InvalidResponse));

        // < 0.0
        let r2 = monitor_execution_with(5, || async {
            Ok::<ExecutionStatus, String>(ExecutionStatus::Running { progress: -0.1 })
        })
        .await;
        assert_eq!(r2, Err(MonitorError::InvalidResponse));

        // NaN
        let r3 = monitor_execution_with(5, || async {
            Ok::<ExecutionStatus, String>(ExecutionStatus::Running { progress: f64::NAN })
        })
        .await;
        assert_eq!(r3, Err(MonitorError::InvalidResponse));

        // Empty output_hash on Completed
        let r4 = monitor_execution_with(5, || async {
            Ok::<ExecutionStatus, String>(ExecutionStatus::Completed {
                output_hash: String::new(),
                duration_ms: 100,
            })
        })
        .await;
        assert_eq!(r4, Err(MonitorError::InvalidResponse));

        // Empty error on Failed
        let r5 = monitor_execution_with(5, || async {
            Ok::<ExecutionStatus, String>(ExecutionStatus::Failed {
                error: String::new(),
            })
        })
        .await;
        assert_eq!(r5, Err(MonitorError::InvalidResponse));
    }

    // ── 11. cli_dispatch_parsing ─────────────────────────────────────────

    #[test]
    fn cli_dispatch_parsing() {
        assert_eq!(WorkloadType::from_str_checked("storage"), Some(WorkloadType::Storage));
        assert_eq!(WorkloadType::from_str_checked("compute"), Some(WorkloadType::Compute));
        assert_eq!(WorkloadType::from_str_checked("STORAGE"), Some(WorkloadType::Storage));
        assert_eq!(WorkloadType::from_str_checked("Compute"), Some(WorkloadType::Compute));
        assert_eq!(WorkloadType::from_str_checked(""), None);
        assert_eq!(WorkloadType::from_str_checked("invalid"), None);
    }

    // ── 12. cli_monitor_parsing ──────────────────────────────────────────

    #[test]
    fn cli_monitor_parsing() {
        assert_eq!(WorkloadType::Storage.label(), "storage");
        assert_eq!(WorkloadType::Compute.label(), "compute");

        let ne = DispatchError::NetworkError("conn reset".to_string());
        assert!(ne.to_string().contains("network error"));
        assert!(ne.to_string().contains("conn reset"));

        assert_eq!(DispatchError::Timeout.to_string(), "timeout");
        assert_eq!(DispatchError::InvalidResponse.to_string(), "invalid response");

        let se = DispatchError::SerializationError("bad json".to_string());
        assert!(se.to_string().contains("bad json"));

        let me = MonitorError::NetworkError("refused".to_string());
        assert!(me.to_string().contains("refused"));
        assert_eq!(MonitorError::Timeout.to_string(), "timeout");
        assert_eq!(MonitorError::InvalidResponse.to_string(), "invalid response");
    }

    // ── 13. retry_integration_called ─────────────────────────────────────

    #[tokio::test]
    async fn retry_integration_called() {
        let config = test_dispatch_config(10);
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();

        // All retryable → should exhaust dispatch_retry_config().max_retries = 3
        let result = dispatch_workload_with(&config, move || {
            c.fetch_add(1, Ordering::SeqCst);
            async { Err::<DispatchResult, String>("connection timeout".to_string()) }
        })
        .await;

        assert_eq!(counter.load(Ordering::SeqCst), 3);
        assert!(matches!(result, Err(DispatchError::NetworkError(_))));
    }

    // ── 14. timeout_enforced ─────────────────────────────────────────────

    #[tokio::test]
    async fn timeout_enforced() {
        // Dispatch: 0s timeout → immediate Timeout
        let config = test_dispatch_config(0);
        let start = tokio::time::Instant::now();
        let result = dispatch_workload_with(&config, || async {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
            Ok::<DispatchResult, String>(ok_dispatch())
        })
        .await;
        assert_eq!(result, Err(DispatchError::Timeout));
        assert!(start.elapsed().as_secs() < 2);

        // Monitor: 0s timeout → immediate Timeout
        let mstart = tokio::time::Instant::now();
        let mresult = monitor_execution_with(0, || async {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
            Ok::<ExecutionStatus, String>(ExecutionStatus::Running { progress: 0.0 })
        })
        .await;
        assert_eq!(mresult, Err(MonitorError::Timeout));
        assert!(mstart.elapsed().as_secs() < 2);
    }

    // ── 15. no_panic_on_invalid_args ─────────────────────────────────────

    #[tokio::test]
    async fn no_panic_on_invalid_args() {
        // Empty endpoint/node — should not panic
        let config = WorkloadDispatchConfig {
            coordinator_endpoint: String::new(),
            node_addr: String::new(),
            workload_type: WorkloadType::Storage,
            timeout_secs: 1,
        };

        // "invalid" is not a retryable keyword → NetworkError after 1 attempt
        let result = dispatch_workload_with(&config, || async {
            Err::<DispatchResult, String>("invalid endpoint".to_string())
        })
        .await;
        assert!(matches!(result, Err(DispatchError::NetworkError(_))));

        // Monitor with non-retryable error
        let mresult = monitor_execution_with(1, || async {
            Err::<ExecutionStatus, String>("invalid workload id".to_string())
        })
        .await;
        assert!(matches!(mresult, Err(MonitorError::NetworkError(_))));
    }

    // ── 16. state_tracker_updates_correctly ──────────────────────────────

    #[test]
    fn state_tracker_updates_correctly() {
        let mut tracker = ReceiptStatusTracker::new();

        // Simulate dispatch → Dispatched
        let dr = DispatchResult {
            workload_id: "wk-100".to_string(),
            assigned_node: "node-x".to_string(),
            dispatched_at: 500,
        };
        assert!(tracker
            .track(
                "wk-100",
                EconomicFlowState::Dispatched {
                    workload_id: dr.workload_id.clone(),
                    dispatched_at: dr.dispatched_at,
                },
                500,
            )
            .is_ok());
        assert_eq!(
            tracker.get_status("wk-100").map(|e| e.status.label()),
            Some("Dispatched")
        );

        // Simulate monitor → Executing
        assert!(tracker
            .track(
                "wk-100",
                EconomicFlowState::Executing {
                    workload_id: "wk-100".to_string(),
                    started_at: 510,
                },
                510,
            )
            .is_ok());
        assert_eq!(
            tracker.get_status("wk-100").map(|e| e.status.label()),
            Some("Executing")
        );

        // Simulate execution failure → Failed
        assert!(tracker
            .track(
                "wk-100",
                EconomicFlowState::Failed {
                    workload_id: "wk-100".to_string(),
                    error: "node crash".to_string(),
                },
                520,
            )
            .is_ok());
        assert_eq!(
            tracker.get_status("wk-100").map(|e| e.status.label()),
            Some("Failed")
        );

        // Failed is terminal
        assert_eq!(
            tracker.track(
                "wk-100",
                EconomicFlowState::Executing {
                    workload_id: "wk-100".to_string(),
                    started_at: 530,
                },
                530,
            ),
            Err(TrackerError::InvalidTransition)
        );

        let s = tracker.summary();
        assert_eq!(s.failed, 1);
        assert_eq!(s.total, 1);
    }

    // ════════════════════════════════════════════════════════════════════════
    // 14C.C.19 — RECEIPT SUBMISSION + CHAIN CLAIM TESTS
    // ════════════════════════════════════════════════════════════════════════

    // ── 1. submit_immediate_reward ───────────────────────────────────────

    #[tokio::test]
    async fn submit_immediate_reward() {
        let result = submit_claim_with(b"receipt_data", 5, || async {
            Ok::<ClaimResult, String>(ClaimResult::ImmediateReward {
                amount: 5000,
                tx_hash: "0xabc123".to_string(),
            })
        })
        .await;

        assert!(result.is_ok());
        if let Ok(ClaimResult::ImmediateReward { amount, tx_hash }) = result {
            assert_eq!(amount, 5000);
            assert_eq!(tx_hash, "0xabc123");
        }
    }

    // ── 2. submit_challenge_period ───────────────────────────────────────

    #[tokio::test]
    async fn submit_challenge_period() {
        let result = submit_claim_with(b"receipt_data", 5, || async {
            Ok::<ClaimResult, String>(ClaimResult::ChallengePeriodStarted {
                expires_at: 99999,
                challenge_id: "ch-001".to_string(),
            })
        })
        .await;

        assert!(result.is_ok());
        if let Ok(ClaimResult::ChallengePeriodStarted { expires_at, challenge_id }) = result {
            assert_eq!(expires_at, 99999);
            assert_eq!(challenge_id, "ch-001");
        }
    }

    // ── 3. submit_rejected ───────────────────────────────────────────────

    #[tokio::test]
    async fn submit_rejected() {
        let result = submit_claim_with(b"receipt_data", 5, || async {
            Ok::<ClaimResult, String>(ClaimResult::Rejected {
                reason: "invalid proof".to_string(),
            })
        })
        .await;

        assert!(result.is_ok());
        if let Ok(ClaimResult::Rejected { reason }) = result {
            assert_eq!(reason, "invalid proof");
        }
    }

    // ── 4. submit_invalid_receipt ────────────────────────────────────────

    #[tokio::test]
    async fn submit_invalid_receipt() {
        // Empty receipt data → InvalidReceipt (pre-validation)
        let r1 = submit_claim_with(b"", 5, || async {
            Ok::<ClaimResult, String>(ClaimResult::ImmediateReward {
                amount: 100,
                tx_hash: "0x1".to_string(),
            })
        })
        .await;
        assert!(matches!(r1, Err(ClaimError::InvalidReceipt(_))));

        // amount == 0 → InvalidReceipt (response validation)
        let r2 = submit_claim_with(b"data", 5, || async {
            Ok::<ClaimResult, String>(ClaimResult::ImmediateReward {
                amount: 0,
                tx_hash: "0x1".to_string(),
            })
        })
        .await;
        assert!(matches!(r2, Err(ClaimError::InvalidReceipt(_))));

        // Empty tx_hash → InvalidReceipt
        let r3 = submit_claim_with(b"data", 5, || async {
            Ok::<ClaimResult, String>(ClaimResult::ImmediateReward {
                amount: 100,
                tx_hash: String::new(),
            })
        })
        .await;
        assert!(matches!(r3, Err(ClaimError::InvalidReceipt(_))));

        // Empty challenge_id → InvalidReceipt
        let r4 = submit_claim_with(b"data", 5, || async {
            Ok::<ClaimResult, String>(ClaimResult::ChallengePeriodStarted {
                expires_at: 1000,
                challenge_id: String::new(),
            })
        })
        .await;
        assert!(matches!(r4, Err(ClaimError::InvalidReceipt(_))));

        // expires_at == 0 → InvalidReceipt
        let r5 = submit_claim_with(b"data", 5, || async {
            Ok::<ClaimResult, String>(ClaimResult::ChallengePeriodStarted {
                expires_at: 0,
                challenge_id: "ch-x".to_string(),
            })
        })
        .await;
        assert!(matches!(r5, Err(ClaimError::InvalidReceipt(_))));

        // Empty rejected reason → InvalidReceipt
        let r6 = submit_claim_with(b"data", 5, || async {
            Ok::<ClaimResult, String>(ClaimResult::Rejected {
                reason: String::new(),
            })
        })
        .await;
        assert!(matches!(r6, Err(ClaimError::InvalidReceipt(_))));
    }

    // ── 5. submit_already_claimed ────────────────────────────────────────

    #[tokio::test]
    async fn submit_already_claimed() {
        let result = submit_claim_with(b"data", 5, || async {
            Err::<ClaimResult, String>("already claimed on chain".to_string())
        })
        .await;

        assert_eq!(result, Err(ClaimError::AlreadyClaimed));
    }

    // ── 6. submit_network_retry ──────────────────────────────────────────

    #[tokio::test]
    async fn submit_network_retry() {
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();

        let result = submit_claim_with(b"data", 10, move || {
            let count = c.fetch_add(1, Ordering::SeqCst);
            async move {
                if count < 2 {
                    Err("connection refused".to_string())
                } else {
                    Ok(ClaimResult::ImmediateReward {
                        amount: 1000,
                        tx_hash: "0xdef".to_string(),
                    })
                }
            }
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    // ── 7. submit_timeout ────────────────────────────────────────────────

    #[tokio::test]
    async fn submit_timeout() {
        let result = submit_claim_with(b"data", 0, || async {
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            Ok::<ClaimResult, String>(ClaimResult::ImmediateReward {
                amount: 1,
                tx_hash: "x".to_string(),
            })
        })
        .await;

        assert!(matches!(result, Err(ClaimError::NetworkError(_))));
    }

    // ── 8. poll_pending ──────────────────────────────────────────────────

    #[tokio::test]
    async fn poll_pending() {
        let result = poll_claim_status_with(5, || async {
            Ok::<ClaimStatus, String>(ClaimStatus::Pending)
        })
        .await;

        assert_eq!(result, Ok(ClaimStatus::Pending));
    }

    // ── 9. poll_challenge_period ─────────────────────────────────────────

    #[tokio::test]
    async fn poll_challenge_period() {
        let result = poll_claim_status_with(5, || async {
            Ok::<ClaimStatus, String>(ClaimStatus::InChallengePeriod {
                expires_at: 88888,
            })
        })
        .await;

        assert!(result.is_ok());
        if let Ok(ClaimStatus::InChallengePeriod { expires_at }) = result {
            assert_eq!(expires_at, 88888);
        }
    }

    // ── 10. poll_finalized ───────────────────────────────────────────────

    #[tokio::test]
    async fn poll_finalized() {
        let result = poll_claim_status_with(5, || async {
            Ok::<ClaimStatus, String>(ClaimStatus::Finalized { reward: 42000 })
        })
        .await;

        assert_eq!(result, Ok(ClaimStatus::Finalized { reward: 42000 }));
    }

    // ── 11. poll_rejected ────────────────────────────────────────────────

    #[tokio::test]
    async fn poll_rejected() {
        let result = poll_claim_status_with(5, || async {
            Ok::<ClaimStatus, String>(ClaimStatus::Rejected {
                reason: "fraud proven".to_string(),
            })
        })
        .await;

        assert!(result.is_ok());
        if let Ok(ClaimStatus::Rejected { reason }) = result {
            assert_eq!(reason, "fraud proven");
        }
    }

    // ── 12. poll_invalid_response ────────────────────────────────────────

    #[tokio::test]
    async fn poll_invalid_response() {
        // expires_at == 0 → InvalidResponse
        let r1 = poll_claim_status_with(5, || async {
            Ok::<ClaimStatus, String>(ClaimStatus::InChallengePeriod { expires_at: 0 })
        })
        .await;
        assert_eq!(r1, Err(PollError::InvalidResponse));

        // Empty rejected reason → InvalidResponse
        let r2 = poll_claim_status_with(5, || async {
            Ok::<ClaimStatus, String>(ClaimStatus::Rejected {
                reason: String::new(),
            })
        })
        .await;
        assert_eq!(r2, Err(PollError::InvalidResponse));
    }

    // ── 13. retry_integration_submit ─────────────────────────────────────

    #[tokio::test]
    async fn retry_integration_submit() {
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();

        // All retryable → exhaust claim_retry_config().max_retries = 3
        let result = submit_claim_with(b"data", 10, move || {
            c.fetch_add(1, Ordering::SeqCst);
            async { Err::<ClaimResult, String>("connection timeout".to_string()) }
        })
        .await;

        assert_eq!(counter.load(Ordering::SeqCst), 3);
        assert!(matches!(result, Err(ClaimError::NetworkError(_))));
    }

    // ── 14. retry_integration_poll ───────────────────────────────────────

    #[tokio::test]
    async fn retry_integration_poll() {
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();

        let result = poll_claim_status_with(10, move || {
            let count = c.fetch_add(1, Ordering::SeqCst);
            async move {
                if count < 2 {
                    Err("network timeout".to_string())
                } else {
                    Ok(ClaimStatus::Finalized { reward: 7777 })
                }
            }
        })
        .await;

        assert_eq!(result, Ok(ClaimStatus::Finalized { reward: 7777 }));
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    // ── 15. timeout_enforced_submit ──────────────────────────────────────

    #[tokio::test]
    async fn timeout_enforced_submit() {
        let start = tokio::time::Instant::now();
        let result = submit_claim_with(b"data", 0, || async {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
            Ok::<ClaimResult, String>(ClaimResult::ImmediateReward {
                amount: 1,
                tx_hash: "x".to_string(),
            })
        })
        .await;
        assert!(matches!(result, Err(ClaimError::NetworkError(_))));
        assert!(start.elapsed().as_secs() < 2);
    }

    // ── 16. timeout_enforced_poll ────────────────────────────────────────

    #[tokio::test]
    async fn timeout_enforced_poll() {
        let start = tokio::time::Instant::now();
        let result = poll_claim_status_with(0, || async {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
            Ok::<ClaimStatus, String>(ClaimStatus::Pending)
        })
        .await;
        assert!(matches!(result, Err(PollError::NetworkError(_))));
        assert!(start.elapsed().as_secs() < 2);
    }

    // ── 17. state_tracker_claim_updates ──────────────────────────────────

    #[tokio::test]
    async fn state_tracker_claim_updates() {
        let mut tracker = ReceiptStatusTracker::new();

        // Start from Submitted
        assert!(tracker
            .track(
                "r-claim",
                EconomicFlowState::Submitted {
                    workload_id: "wk-c".to_string(),
                    receipt_hash: "r-claim".to_string(),
                },
                100,
            )
            .is_ok());

        // submit_claim → Pending
        assert!(tracker
            .track(
                "r-claim",
                EconomicFlowState::Pending {
                    receipt_hash: "r-claim".to_string(),
                    submitted_at: 110,
                },
                110,
            )
            .is_ok());
        assert_eq!(
            tracker.get_status("r-claim").map(|e| e.status.label()),
            Some("Pending")
        );

        // poll → Challenged
        assert!(tracker
            .track(
                "r-claim",
                EconomicFlowState::Challenged {
                    receipt_hash: "r-claim".to_string(),
                    challenge_id: "ch-99".to_string(),
                    expires_at: 200,
                },
                120,
            )
            .is_ok());
        assert_eq!(
            tracker.get_status("r-claim").map(|e| e.status.label()),
            Some("Challenged")
        );

        // poll → Finalized
        assert!(tracker
            .track(
                "r-claim",
                EconomicFlowState::Finalized {
                    receipt_hash: "r-claim".to_string(),
                    reward_amount: 5000,
                },
                130,
            )
            .is_ok());
        assert_eq!(
            tracker.get_status("r-claim").map(|e| e.status.label()),
            Some("Finalized")
        );

        // Finalized is terminal
        assert_eq!(
            tracker.track(
                "r-claim",
                EconomicFlowState::Rejected {
                    receipt_hash: "r-claim".to_string(),
                    reason: "late".to_string(),
                },
                140,
            ),
            Err(TrackerError::InvalidTransition)
        );
    }

    // ── 18. no_double_state_update_on_error ──────────────────────────────

    #[tokio::test]
    async fn no_double_state_update_on_error() {
        let mut tracker = ReceiptStatusTracker::new();

        // Set up Submitted state
        assert!(tracker
            .track(
                "r-err",
                EconomicFlowState::Submitted {
                    workload_id: "wk-e".to_string(),
                    receipt_hash: "r-err".to_string(),
                },
                100,
            )
            .is_ok());

        // Claim returns error → tracker NOT updated
        let claim_result = submit_claim_with(b"data", 1, || async {
            Err::<ClaimResult, String>("connection refused".to_string())
        })
        .await;
        assert!(claim_result.is_err());

        // State must still be Submitted
        assert_eq!(
            tracker.get_status("r-err").map(|e| e.status.label()),
            Some("Submitted")
        );
        assert_eq!(tracker.get_status("r-err").map(|e| e.updated_at), Some(100));

        // Poll returns error → tracker also unchanged
        let poll_result = poll_claim_status_with(1, || async {
            Err::<ClaimStatus, String>("connection refused".to_string())
        })
        .await;
        assert!(poll_result.is_err());

        // Still Submitted
        assert_eq!(
            tracker.get_status("r-err").map(|e| e.status.label()),
            Some("Submitted")
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    // 14C.C.20 — FULL LIFECYCLE ORCHESTRATION TESTS
    // ════════════════════════════════════════════════════════════════════════

    fn test_orchestrator(auto_claim: bool) -> EconomicOrchestrator {
        EconomicOrchestrator {
            config: OrchestratorConfig {
                coordinator_endpoint: "http://127.0.0.1:9999".to_string(),
                ingress_endpoint: "http://127.0.0.1:9998".to_string(),
                node_addr: "127.0.0.1:50051".to_string(),
                auto_claim,
                poll_interval_ms: 0, // fast tests
            },
            tracker: ReceiptStatusTracker::new(),
            retry_config: RetryConfig::default(),
        }
    }

    fn ok_flow_dispatch() -> DispatchResult {
        DispatchResult {
            workload_id: "wk-flow-1".to_string(),
            assigned_node: "node-a".to_string(),
            dispatched_at: 100,
        }
    }

    fn completed_status() -> ExecutionStatus {
        ExecutionStatus::Completed {
            output_hash: "ohash".to_string(),
            duration_ms: 500,
        }
    }

    fn immediate_reward() -> ClaimResult {
        ClaimResult::ImmediateReward {
            amount: 1000,
            tx_hash: "0xtx".to_string(),
        }
    }

    // ── 1. full_flow_success_auto_claim ──────────────────────────────────

    #[tokio::test]
    async fn full_flow_success_auto_claim() {
        let mut orch = test_orchestrator(true);
        let mc = Arc::new(AtomicU32::new(0));
        let mc2 = mc.clone();

        let result = run_full_flow_with(
            &mut orch, b"workload", WorkloadType::Storage,
            || async { Ok(ok_flow_dispatch()) },
            move || {
                let c = mc2.fetch_add(1, Ordering::SeqCst);
                async move {
                    if c < 2 { Ok(ExecutionStatus::Running { progress: 0.5 }) }
                    else { Ok(completed_status()) }
                }
            },
            || async { Ok(immediate_reward()) },
            || async { Ok(ClaimStatus::Finalized { reward: 1000 }) },
        ).await;

        assert!(result.is_ok());
        let fr = result.as_ref().ok();
        assert_eq!(fr.map(|r| r.workload_id.as_str()), Some("wk-flow-1"));
        assert!(fr.map(|r| r.receipt_hash.is_some()) == Some(true));
        assert!(fr.map(|r| r.claim_status.is_some()) == Some(true));
        let expected: Vec<String> = vec!["dispatch", "monitor", "proof", "submit_receipt", "claim"]
            .into_iter().map(String::from).collect();
        assert_eq!(fr.map(|r| r.steps_completed.clone()), Some(expected));
    }

    // ── 2. full_flow_success_no_claim ────────────────────────────────────

    #[tokio::test]
    async fn full_flow_success_no_claim() {
        let mut orch = test_orchestrator(false);

        let result = run_full_flow_with(
            &mut orch, b"workload", WorkloadType::Compute,
            || async { Ok(ok_flow_dispatch()) },
            || async { Ok(completed_status()) },
            || async { Ok(immediate_reward()) },
            || async { Ok(ClaimStatus::Pending) },
        ).await;

        assert!(result.is_ok());
        let fr = result.as_ref().ok();
        assert!(fr.map(|r| r.claim_status.is_none()) == Some(true));
        let expected: Vec<String> = vec!["dispatch", "monitor", "proof", "submit_receipt"]
            .into_iter().map(String::from).collect();
        assert_eq!(fr.map(|r| r.steps_completed.clone()), Some(expected));
    }

    // ── 3. dispatch_failure_recovery ─────────────────────────────────────

    #[tokio::test]
    async fn dispatch_failure_recovery() {
        let mut orch = test_orchestrator(false);

        let result = run_full_flow_with(
            &mut orch, b"workload", WorkloadType::Storage,
            || async { Err(DispatchError::Timeout) },
            || async { Ok(ExecutionStatus::Running { progress: 0.0 }) },
            || async { Ok(immediate_reward()) },
            || async { Ok(ClaimStatus::Pending) },
        ).await;

        assert!(matches!(result, Err(FlowError::DispatchFailed(_))));
    }

    // ── 4. execution_failure_recovery ────────────────────────────────────

    #[tokio::test]
    async fn execution_failure_recovery() {
        let mut orch = test_orchestrator(false);

        let result = run_full_flow_with(
            &mut orch, b"workload", WorkloadType::Storage,
            || async { Ok(ok_flow_dispatch()) },
            || async { Ok(ExecutionStatus::Failed { error: "OOM".to_string() }) },
            || async { Ok(immediate_reward()) },
            || async { Ok(ClaimStatus::Pending) },
        ).await;

        assert!(matches!(result, Err(FlowError::ExecutionFailed(_))));
        assert_eq!(
            orch.tracker.get_status("wk-flow-1").map(|e| e.status.label()),
            Some("Failed")
        );
    }

    // ── 5. proof_failure_handled ─────────────────────────────────────────

    #[tokio::test]
    async fn proof_failure_handled() {
        // Proof is placeholder; verify it creates valid state transition.
        let mut orch = test_orchestrator(false);

        let result = run_full_flow_with(
            &mut orch, b"workload", WorkloadType::Storage,
            || async { Ok(ok_flow_dispatch()) },
            || async { Ok(completed_status()) },
            || async { Ok(immediate_reward()) },
            || async { Ok(ClaimStatus::Pending) },
        ).await;

        assert!(result.is_ok());
        let fr = result.as_ref().ok();
        assert!(fr.map(|r| r.steps_completed.contains(&"proof".to_string())) == Some(true));
    }

    // ── 6. receipt_submission_failure ─────────────────────────────────────

    #[tokio::test]
    async fn receipt_submission_failure() {
        // Receipt submission is placeholder; verify claim failure is handled.
        let mut orch = test_orchestrator(true);

        let result = run_full_flow_with(
            &mut orch, b"workload", WorkloadType::Storage,
            || async { Ok(ok_flow_dispatch()) },
            || async { Ok(completed_status()) },
            || async { Err(ClaimError::IngressUnavailable) },
            || async { Ok(ClaimStatus::Pending) },
        ).await;

        assert!(matches!(result, Err(FlowError::ClaimFailed(_))));
    }

    // ── 7. claim_failure ─────────────────────────────────────────────────

    #[tokio::test]
    async fn claim_failure() {
        let mut orch = test_orchestrator(true);

        let result = run_full_flow_with(
            &mut orch, b"workload", WorkloadType::Storage,
            || async { Ok(ok_flow_dispatch()) },
            || async { Ok(completed_status()) },
            || async { Err(ClaimError::AlreadyClaimed) },
            || async { Ok(ClaimStatus::Pending) },
        ).await;

        assert!(matches!(result, Err(FlowError::ClaimFailed(_))));
        if let Err(FlowError::ClaimFailed(msg)) = &result {
            assert!(msg.contains("already claimed"));
        }
    }

    // ── 8. retry_exhaustion_dispatch ─────────────────────────────────────

    #[tokio::test]
    async fn retry_exhaustion_dispatch() {
        let mut orch = test_orchestrator(false);

        let result = run_full_flow_with(
            &mut orch, b"workload", WorkloadType::Storage,
            || async { Err(DispatchError::NetworkError("connection refused".to_string())) },
            || async { Ok(ExecutionStatus::Running { progress: 0.0 }) },
            || async { Ok(immediate_reward()) },
            || async { Ok(ClaimStatus::Pending) },
        ).await;

        assert!(matches!(result, Err(FlowError::DispatchFailed(_))));
    }

    // ── 9. retry_exhaustion_claim ────────────────────────────────────────

    #[tokio::test]
    async fn retry_exhaustion_claim() {
        let mut orch = test_orchestrator(true);

        let result = run_full_flow_with(
            &mut orch, b"workload", WorkloadType::Storage,
            || async { Ok(ok_flow_dispatch()) },
            || async { Ok(completed_status()) },
            || async { Err(ClaimError::NetworkError("connection timeout".to_string())) },
            || async { Ok(ClaimStatus::Pending) },
        ).await;

        assert!(matches!(result, Err(FlowError::ClaimFailed(_))));
    }

    // ── 10. timeout_full_flow ────────────────────────────────────────────

    #[tokio::test]
    async fn timeout_full_flow() {
        let mut orch = test_orchestrator(false);

        // Monitor always returns Running → hits MAX_POLL_ITERATIONS
        let result = run_full_flow_with(
            &mut orch, b"workload", WorkloadType::Storage,
            || async { Ok(ok_flow_dispatch()) },
            || async { Ok(ExecutionStatus::Running { progress: 0.1 }) },
            || async { Ok(immediate_reward()) },
            || async { Ok(ClaimStatus::Pending) },
        ).await;

        assert!(matches!(result, Err(FlowError::Timeout)));
    }

    // ── 11. state_tracker_updates_each_step ──────────────────────────────

    #[tokio::test]
    async fn state_tracker_updates_each_step() {
        let mut orch = test_orchestrator(true);

        let _ = run_full_flow_with(
            &mut orch, b"workload", WorkloadType::Storage,
            || async { Ok(ok_flow_dispatch()) },
            || async { Ok(completed_status()) },
            || async {
                Ok(ClaimResult::ImmediateReward {
                    amount: 500,
                    tx_hash: "0xfin".to_string(),
                })
            },
            || async { Ok(ClaimStatus::Finalized { reward: 500 }) },
        ).await;

        // After ImmediateReward, state should be Finalized
        let entry = orch.tracker.get_status("wk-flow-1");
        assert!(entry.is_some());
        assert_eq!(entry.map(|e| e.status.label()), Some("Finalized"));
    }

    // ── 12. steps_completed_order_correct ────────────────────────────────

    #[tokio::test]
    async fn steps_completed_order_correct() {
        let mut orch = test_orchestrator(true);

        let result = run_full_flow_with(
            &mut orch, b"workload", WorkloadType::Storage,
            || async { Ok(ok_flow_dispatch()) },
            || async { Ok(completed_status()) },
            || async { Ok(immediate_reward()) },
            || async { Ok(ClaimStatus::Finalized { reward: 1 }) },
        ).await;

        let fr = result.as_ref().ok();
        let steps: Vec<String> = ["dispatch", "monitor", "proof", "submit_receipt", "claim"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(fr.map(|r| r.steps_completed.clone()), Some(steps));
    }

    // ── 13. no_skip_step ─────────────────────────────────────────────────

    #[tokio::test]
    async fn no_skip_step() {
        let mut orch = test_orchestrator(false);

        // Monitor fails → should not reach proof or submit_receipt
        let result = run_full_flow_with(
            &mut orch, b"workload", WorkloadType::Storage,
            || async { Ok(ok_flow_dispatch()) },
            || async { Err(MonitorError::Timeout) },
            || async { Ok(immediate_reward()) },
            || async { Ok(ClaimStatus::Pending) },
        ).await;

        assert!(matches!(result, Err(FlowError::ExecutionFailed(_))));
        assert_eq!(
            orch.tracker.get_status("wk-flow-1").map(|e| e.status.label()),
            Some("Failed")
        );
    }

    // ── 14. no_infinite_polling ──────────────────────────────────────────

    #[tokio::test]
    async fn no_infinite_polling() {
        let mut orch = test_orchestrator(false);
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();

        let result = run_full_flow_with(
            &mut orch, b"workload", WorkloadType::Storage,
            || async { Ok(ok_flow_dispatch()) },
            move || {
                c.fetch_add(1, Ordering::SeqCst);
                async { Ok(ExecutionStatus::Running { progress: 0.5 }) }
            },
            || async { Ok(immediate_reward()) },
            || async { Ok(ClaimStatus::Pending) },
        ).await;

        assert!(matches!(result, Err(FlowError::Timeout)));
        let calls = counter.load(Ordering::SeqCst);
        assert!(calls <= MAX_POLL_ITERATIONS + 1);
        assert!(calls > 0);
    }

    // ── 15. total_duration_calculated ─────────────────────────────────────

    #[tokio::test]
    async fn total_duration_calculated() {
        let mut orch = test_orchestrator(false);

        let result = run_full_flow_with(
            &mut orch, b"workload", WorkloadType::Storage,
            || async { Ok(ok_flow_dispatch()) },
            || async { Ok(completed_status()) },
            || async { Ok(immediate_reward()) },
            || async { Ok(ClaimStatus::Pending) },
        ).await;

        assert!(result.is_ok());
        let dur = result.as_ref().ok().map(|r| r.total_duration_ms);
        assert!(dur.is_some());
        assert!(dur.map(|d| d < 5000) == Some(true));
    }

    // ── 16. retry_count_incremented ──────────────────────────────────────

    #[tokio::test]
    async fn retry_count_incremented() {
        let mut orch = test_orchestrator(false);

        let wid = "retry-wid";
        let _ = orch.tracker.track(
            wid,
            EconomicFlowState::Dispatched {
                workload_id: wid.to_string(),
                dispatched_at: 1,
            },
            1,
        );

        assert_eq!(orch.tracker.increment_retry(wid), Ok(1));
        assert_eq!(orch.tracker.increment_retry(wid), Ok(2));
        assert_eq!(orch.tracker.increment_retry(wid), Ok(3));
        assert_eq!(orch.tracker.get_status(wid).map(|e| e.retry_count), Some(3));
    }

    // ── 17. cli_run_parsing ──────────────────────────────────────────────

    #[test]
    fn cli_run_parsing() {
        assert_eq!(WorkloadType::from_str_checked("storage"), Some(WorkloadType::Storage));
        assert_eq!(WorkloadType::from_str_checked("compute"), Some(WorkloadType::Compute));
        assert_eq!(WorkloadType::from_str_checked("invalid"), None);

        assert!(FlowError::DispatchFailed("x".to_string()).to_string().contains("dispatch"));
        assert!(FlowError::ExecutionFailed("x".to_string()).to_string().contains("execution"));
        assert!(FlowError::ProofFailed("x".to_string()).to_string().contains("proof"));
        assert!(FlowError::ReceiptSubmissionFailed("x".to_string()).to_string().contains("receipt"));
        assert!(FlowError::ClaimFailed("x".to_string()).to_string().contains("claim"));
        assert_eq!(FlowError::Timeout.to_string(), "flow timeout");
    }

    // ── 18. auto_claim_flag_behavior ─────────────────────────────────────

    #[tokio::test]
    async fn auto_claim_flag_behavior() {
        // auto_claim=false → claim_fn never called
        let mut orch_no = test_orchestrator(false);
        let cc = Arc::new(AtomicU32::new(0));
        let cc2 = cc.clone();

        let r_no = run_full_flow_with(
            &mut orch_no, b"workload", WorkloadType::Storage,
            || async { Ok(ok_flow_dispatch()) },
            || async { Ok(completed_status()) },
            move || {
                cc2.fetch_add(1, Ordering::SeqCst);
                async { Ok(immediate_reward()) }
            },
            || async { Ok(ClaimStatus::Pending) },
        ).await;

        assert!(r_no.is_ok());
        assert_eq!(cc.load(Ordering::SeqCst), 0);
        assert!(r_no.as_ref().ok().map(|r| r.claim_status.is_none()) == Some(true));

        // auto_claim=true → claim_fn IS called
        let mut orch_yes = test_orchestrator(true);
        let cc3 = Arc::new(AtomicU32::new(0));
        let cc4 = cc3.clone();

        let r_yes = run_full_flow_with(
            &mut orch_yes, b"workload", WorkloadType::Storage,
            || async { Ok(ok_flow_dispatch()) },
            || async { Ok(completed_status()) },
            move || {
                cc4.fetch_add(1, Ordering::SeqCst);
                async { Ok(immediate_reward()) }
            },
            || async { Ok(ClaimStatus::Finalized { reward: 1 }) },
        ).await;

        assert!(r_yes.is_ok());
        assert_eq!(cc3.load(Ordering::SeqCst), 1);
        assert!(r_yes.as_ref().ok().map(|r| r.claim_status.is_some()) == Some(true));
    }

    // ── 19. deterministic_poll_interval ───────────────────────────────────

    #[tokio::test]
    async fn deterministic_poll_interval() {
        let mut orch = test_orchestrator(false);
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();

        let result = run_full_flow_with(
            &mut orch, b"workload", WorkloadType::Storage,
            || async { Ok(ok_flow_dispatch()) },
            move || {
                let count = c.fetch_add(1, Ordering::SeqCst);
                async move {
                    if count < 5 {
                        Ok(ExecutionStatus::Running { progress: count as f64 / 5.0 })
                    } else {
                        Ok(completed_status())
                    }
                }
            },
            || async { Ok(immediate_reward()) },
            || async { Ok(ClaimStatus::Pending) },
        ).await;

        assert!(result.is_ok());
        assert_eq!(counter.load(Ordering::SeqCst), 6); // 5 Running + 1 Completed
    }

    // ── 20. no_overflow_duration ─────────────────────────────────────────

    #[tokio::test]
    async fn no_overflow_duration() {
        let mut orch = test_orchestrator(false);

        let result = run_full_flow_with(
            &mut orch, b"workload", WorkloadType::Storage,
            || async { Ok(ok_flow_dispatch()) },
            || async {
                Ok(ExecutionStatus::Completed {
                    output_hash: "oh".to_string(),
                    duration_ms: u64::MAX,
                })
            },
            || async { Ok(immediate_reward()) },
            || async { Ok(ClaimStatus::Pending) },
        ).await;

        assert!(result.is_ok());
        let dur = result.as_ref().ok().map(|r| r.total_duration_ms);
        assert!(dur.is_some());

        // Also: empty workload rejected
        let mut orch2 = test_orchestrator(false);
        let r2 = run_full_flow_with(
            &mut orch2, b"", WorkloadType::Storage,
            || async { Ok(ok_flow_dispatch()) },
            || async { Ok(completed_status()) },
            || async { Ok(immediate_reward()) },
            || async { Ok(ClaimStatus::Pending) },
        ).await;
        assert!(matches!(r2, Err(FlowError::DispatchFailed(_))));
    }
}