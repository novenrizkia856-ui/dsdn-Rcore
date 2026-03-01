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
// UNIT TESTS
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
}