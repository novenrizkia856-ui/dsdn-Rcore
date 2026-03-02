//! # Economic Flow Tests (14C.C.22)
//!
//! Deterministic tests for the DSDN agent economic subsystem.
//! All tests are self-contained with mock types — no network, no real sleep,
//! no SystemTime, no unwrap, no panic.

// ════════════════════════════════════════════════════════════════════════════
// MOCK TYPES — mirror real API surface for isolated testing
// ════════════════════════════════════════════════════════════════════════════

use std::collections::BTreeMap;

/// Receipt lifecycle state (mirrors cmd_economic::ReceiptState).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ReceiptState {
    Pending,
    Dispatched,
    Executing,
    ReceiptSubmitted,
    Claimed,
    Failed,
}

impl std::fmt::Display for ReceiptState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ReceiptState::Pending => "Pending",
            ReceiptState::Dispatched => "Dispatched",
            ReceiptState::Executing => "Executing",
            ReceiptState::ReceiptSubmitted => "ReceiptSubmitted",
            ReceiptState::Claimed => "Claimed",
            ReceiptState::Failed => "Failed",
        };
        write!(f, "{}", s)
    }
}

/// Tracked receipt entry.
#[derive(Debug, Clone)]
struct TrackedReceipt {
    receipt_hash: String,
    state: ReceiptState,
}

/// Mock ReceiptStatusTracker — deterministic, in-memory.
#[derive(Debug)]
struct ReceiptStatusTracker {
    /// BTreeMap for deterministic iteration order (sorted by receipt_hash).
    entries: BTreeMap<String, TrackedReceipt>,
}

impl ReceiptStatusTracker {
    fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Insert or update a receipt. Returns Ok on success, Err on invalid transition.
    fn set_state(
        &mut self,
        receipt_hash: &str,
        new_state: ReceiptState,
    ) -> Result<(), String> {
        let entry = self
            .entries
            .entry(receipt_hash.to_string())
            .or_insert_with(|| TrackedReceipt {
                receipt_hash: receipt_hash.to_string(),
                state: ReceiptState::Pending,
            });
        // Validate transition: cannot go backwards except to Failed
        if new_state == ReceiptState::Failed {
            entry.state = new_state;
            return Ok(());
        }
        // Simple forward-only check via discriminant ordering
        let old_ord = state_ordinal(entry.state);
        let new_ord = state_ordinal(new_state);
        if new_ord <= old_ord && entry.state != ReceiptState::Pending {
            return Err(format!(
                "invalid transition: {} -> {}",
                entry.state, new_state
            ));
        }
        entry.state = new_state;
        Ok(())
    }

    fn get_state(&self, receipt_hash: &str) -> Option<ReceiptState> {
        self.entries.get(receipt_hash).map(|e| e.state)
    }

    /// List receipts filtered by state. Order is deterministic (BTreeMap).
    fn list_by_status(&self, state: ReceiptState) -> Vec<String> {
        self.entries
            .iter()
            .filter(|(_, e)| e.state == state)
            .map(|(k, _)| k.clone())
            .collect()
    }

    fn all_hashes_sorted(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
    }
}

fn state_ordinal(s: ReceiptState) -> u8 {
    match s {
        ReceiptState::Pending => 0,
        ReceiptState::Dispatched => 1,
        ReceiptState::Executing => 2,
        ReceiptState::ReceiptSubmitted => 3,
        ReceiptState::Claimed => 4,
        ReceiptState::Failed => 5,
    }
}

// ────────────────────────────────────────
// Retry config mock
// ────────────────────────────────────────

/// Mirror of retry::RetryConfig.
#[derive(Debug, Clone)]
struct RetryConfig {
    max_retries: u32,
    initial_delay_ms: u64,
    max_delay_ms: u64,
    backoff_multiplier: f64,
    jitter: bool,
}

impl RetryConfig {
    /// Compute delay for attempt n (0-indexed), without jitter,
    /// capped at max_delay_ms. Pure function — no sleep.
    fn delay_ms_for_attempt(&self, attempt: u32) -> u64 {
        let mut delay = self.initial_delay_ms as f64;
        for _ in 0..attempt {
            delay *= self.backoff_multiplier;
        }
        let capped = if (delay as u64) > self.max_delay_ms {
            self.max_delay_ms
        } else {
            delay as u64
        };
        capped
    }
}

/// Error classification (mirrors retry::is_retryable).
#[derive(Debug, Clone, PartialEq, Eq)]
enum RetryableError {
    Network(String),
    Validation(String),
    AlreadyClaimed,
}

fn is_retryable(err: &RetryableError) -> bool {
    matches!(err, RetryableError::Network(_))
}

// ────────────────────────────────────────
// Dispatch / Claim mocks
// ────────────────────────────────────────

#[derive(Debug, Clone)]
struct DispatchResult {
    workload_id: String,
    accepted: bool,
}

#[derive(Debug, Clone)]
struct ClaimResult {
    receipt_hash: String,
    tx_hash: String,
    amount: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ClaimError {
    AlreadyClaimed,
    NetworkError(String),
    ValidationError(String),
}

/// Mock dispatcher — records calls, returns predetermined results.
struct MockDispatcher {
    results: Vec<Result<DispatchResult, String>>,
    call_count: usize,
}

impl MockDispatcher {
    fn new(results: Vec<Result<DispatchResult, String>>) -> Self {
        Self {
            results,
            call_count: 0,
        }
    }

    fn dispatch(&mut self, _workload_type: &str, _node: &str, _data: &[u8]) -> Result<DispatchResult, String> {
        let idx = self.call_count;
        self.call_count = idx.saturating_add(1);
        if idx < self.results.len() {
            self.results[idx].clone()
        } else {
            Err("no more mock results".to_string())
        }
    }
}

/// Mock claimer — tracks claimed hashes, rejects duplicates.
struct MockClaimer {
    claimed: std::collections::HashSet<String>,
    tx_counter: u64,
}

impl MockClaimer {
    fn new() -> Self {
        Self {
            claimed: std::collections::HashSet::new(),
            tx_counter: 0,
        }
    }

    fn submit_claim(&mut self, receipt_hash: &str, amount: u64) -> Result<ClaimResult, ClaimError> {
        if self.claimed.contains(receipt_hash) {
            return Err(ClaimError::AlreadyClaimed);
        }
        if amount == 0 {
            return Err(ClaimError::ValidationError("amount must be > 0".to_string()));
        }
        self.claimed.insert(receipt_hash.to_string());
        self.tx_counter = self.tx_counter.saturating_add(1);
        Ok(ClaimResult {
            receipt_hash: receipt_hash.to_string(),
            tx_hash: format!("0x{:064x}", self.tx_counter),
            amount,
        })
    }
}

// ────────────────────────────────────────
// EconomicMetrics mock
// ────────────────────────────────────────

/// Mirror of economic_metrics::EconomicMetrics.
#[derive(Debug, Clone)]
struct EconomicMetrics {
    dispatch_count: u64,
    claim_count: u64,
    failure_count: u64,
    total_revenue: u128,
    completed_flows: u64,
    total_flow_duration_ms: u128,
}

impl EconomicMetrics {
    fn new() -> Self {
        Self {
            dispatch_count: 0,
            claim_count: 0,
            failure_count: 0,
            total_revenue: 0,
            completed_flows: 0,
            total_flow_duration_ms: 0,
        }
    }

    fn record_dispatch(&mut self) {
        self.dispatch_count = self.dispatch_count.checked_add(1).unwrap_or(u64::MAX);
    }

    fn record_claim(&mut self, revenue: u64) {
        self.claim_count = self.claim_count.checked_add(1).unwrap_or(u64::MAX);
        self.total_revenue = self
            .total_revenue
            .checked_add(u128::from(revenue))
            .unwrap_or(u128::MAX);
    }

    fn record_failure(&mut self) {
        self.failure_count = self.failure_count.checked_add(1).unwrap_or(u64::MAX);
    }

    fn record_flow_completion(&mut self, duration_ms: u64) {
        self.completed_flows = self.completed_flows.checked_add(1).unwrap_or(u64::MAX);
        self.total_flow_duration_ms = self
            .total_flow_duration_ms
            .checked_add(u128::from(duration_ms))
            .unwrap_or(u128::MAX);
    }

    /// Average flow duration — integer division, zero when no completions.
    fn average_flow_duration_ms(&self) -> u64 {
        if self.completed_flows == 0 {
            return 0;
        }
        // Safe: completed_flows > 0
        (self.total_flow_duration_ms / u128::from(self.completed_flows)) as u64
    }

    /// Prometheus exposition format.
    fn to_prometheus(&self) -> String {
        let mut out = String::new();
        out.push_str("# HELP dsdn_economic_dispatch_total Total dispatched workloads\n");
        out.push_str("# TYPE dsdn_economic_dispatch_total counter\n");
        out.push_str(&format!(
            "dsdn_economic_dispatch_total {}\n",
            self.dispatch_count
        ));
        out.push_str("# HELP dsdn_economic_claim_total Total successful claims\n");
        out.push_str("# TYPE dsdn_economic_claim_total counter\n");
        out.push_str(&format!(
            "dsdn_economic_claim_total {}\n",
            self.claim_count
        ));
        out.push_str("# HELP dsdn_economic_failure_total Total failures\n");
        out.push_str("# TYPE dsdn_economic_failure_total counter\n");
        out.push_str(&format!(
            "dsdn_economic_failure_total {}\n",
            self.failure_count
        ));
        out.push_str("# HELP dsdn_economic_revenue_total Total revenue (smallest unit)\n");
        out.push_str("# TYPE dsdn_economic_revenue_total counter\n");
        out.push_str(&format!(
            "dsdn_economic_revenue_total {}\n",
            self.total_revenue
        ));
        out.push_str(
            "# HELP dsdn_economic_avg_flow_duration_ms Average flow duration in milliseconds\n",
        );
        out.push_str("# TYPE dsdn_economic_avg_flow_duration_ms gauge\n");
        out.push_str(&format!(
            "dsdn_economic_avg_flow_duration_ms {}\n",
            self.average_flow_duration_ms()
        ));
        out
    }

    /// JSON representation.
    fn to_json(&self) -> Result<String, String> {
        // Manual serialisation — no serde dependency in test crate.
        let json = format!(
            concat!(
                "{{",
                "\"dispatch_count\":{},",
                "\"claim_count\":{},",
                "\"failure_count\":{},",
                "\"total_revenue\":{},",
                "\"completed_flows\":{},",
                "\"average_flow_duration_ms\":{}",
                "}}"
            ),
            self.dispatch_count,
            self.claim_count,
            self.failure_count,
            self.total_revenue,
            self.completed_flows,
            self.average_flow_duration_ms(),
        );
        Ok(json)
    }
}

// ────────────────────────────────────────
// Orchestrator mock
// ────────────────────────────────────────

/// Orchestrator step — tracks execution order.
#[derive(Debug, Clone, PartialEq, Eq)]
enum OrchestratorStep {
    Dispatch,
    Monitor,
    Proof,
    SubmitReceipt,
    Claim,
}

/// Run a mocked full-lifecycle orchestration.
/// Returns (steps_executed, retry_count, final_tracker_state).
fn orchestrate_mock(
    dispatcher: &mut MockDispatcher,
    claimer: &mut MockClaimer,
    tracker: &mut ReceiptStatusTracker,
    receipt_hash: &str,
    auto_claim: bool,
    max_poll_iterations: u32,
) -> Result<(Vec<OrchestratorStep>, u32), String> {
    let mut steps: Vec<OrchestratorStep> = Vec::new();
    let mut retry_count: u32 = 0;

    // Step 1: Dispatch
    tracker
        .set_state(receipt_hash, ReceiptState::Dispatched)
        .map_err(|e| format!("tracker error: {}", e))?;

    let dispatch_result = dispatcher.dispatch("storage", "127.0.0.1:50051", b"mock_data");
    match dispatch_result {
        Ok(ref r) if r.accepted => {
            steps.push(OrchestratorStep::Dispatch);
        }
        Ok(_) => {
            tracker
                .set_state(receipt_hash, ReceiptState::Failed)
                .map_err(|e| format!("tracker error: {}", e))?;
            return Err("dispatch rejected".to_string());
        }
        Err(e) => {
            retry_count = retry_count.saturating_add(1);
            // Second attempt
            let retry_result =
                dispatcher.dispatch("storage", "127.0.0.1:50051", b"mock_data");
            match retry_result {
                Ok(ref r) if r.accepted => {
                    steps.push(OrchestratorStep::Dispatch);
                }
                _ => {
                    tracker
                        .set_state(receipt_hash, ReceiptState::Failed)
                        .map_err(|er| format!("tracker error: {}", er))?;
                    return Err(format!("dispatch failed after retry: {}", e));
                }
            }
        }
    }

    // Step 2: Monitor (simulate polling)
    tracker
        .set_state(receipt_hash, ReceiptState::Executing)
        .map_err(|e| format!("tracker error: {}", e))?;
    let mut poll_count: u32 = 0;
    let execution_complete = loop {
        if poll_count >= max_poll_iterations {
            break false;
        }
        poll_count = poll_count.saturating_add(1);
        // Mock: complete after 2 polls
        if poll_count >= 2 {
            break true;
        }
    };
    if !execution_complete {
        tracker
            .set_state(receipt_hash, ReceiptState::Failed)
            .map_err(|e| format!("tracker error: {}", e))?;
        return Err("execution poll exhausted".to_string());
    }
    steps.push(OrchestratorStep::Monitor);

    // Step 3: Proof (mock — always succeeds)
    steps.push(OrchestratorStep::Proof);

    // Step 4: Submit receipt
    tracker
        .set_state(receipt_hash, ReceiptState::ReceiptSubmitted)
        .map_err(|e| format!("tracker error: {}", e))?;
    steps.push(OrchestratorStep::SubmitReceipt);

    // Step 5: Claim (if auto_claim)
    if auto_claim {
        let claim_result = claimer.submit_claim(receipt_hash, 1000);
        match claim_result {
            Ok(_) => {
                tracker
                    .set_state(receipt_hash, ReceiptState::Claimed)
                    .map_err(|e| format!("tracker error: {}", e))?;
                steps.push(OrchestratorStep::Claim);
            }
            Err(ClaimError::AlreadyClaimed) => {
                // Not a failure — idempotent
                tracker
                    .set_state(receipt_hash, ReceiptState::Claimed)
                    .map_err(|e| format!("tracker error: {}", e))?;
                steps.push(OrchestratorStep::Claim);
            }
            Err(e) => {
                tracker
                    .set_state(receipt_hash, ReceiptState::Failed)
                    .map_err(|e2| format!("tracker error: {}", e2))?;
                return Err(format!("claim failed: {:?}", e));
            }
        }
    }

    Ok((steps, retry_count))
}

// ════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════

// ────────────────────────────────────────
// TEST 1: receipt_status_tracker_lifecycle
// ────────────────────────────────────────

#[test]
fn receipt_status_tracker_lifecycle() {
    let mut tracker = ReceiptStatusTracker::new();
    let hash = "abc123";

    // Pending (implicit on first set_state)
    assert!(tracker.get_state(hash).is_none());

    // Pending → Dispatched
    assert!(tracker.set_state(hash, ReceiptState::Dispatched).is_ok());
    assert_eq!(tracker.get_state(hash), Some(ReceiptState::Dispatched));

    // Dispatched → Executing
    assert!(tracker.set_state(hash, ReceiptState::Executing).is_ok());
    assert_eq!(tracker.get_state(hash), Some(ReceiptState::Executing));

    // Executing → ReceiptSubmitted
    assert!(tracker
        .set_state(hash, ReceiptState::ReceiptSubmitted)
        .is_ok());
    assert_eq!(
        tracker.get_state(hash),
        Some(ReceiptState::ReceiptSubmitted)
    );

    // ReceiptSubmitted → Claimed
    assert!(tracker.set_state(hash, ReceiptState::Claimed).is_ok());
    assert_eq!(tracker.get_state(hash), Some(ReceiptState::Claimed));

    // Backward transition is rejected
    assert!(tracker.set_state(hash, ReceiptState::Dispatched).is_err());

    // Failed is always allowed
    assert!(tracker.set_state(hash, ReceiptState::Failed).is_ok());
    assert_eq!(tracker.get_state(hash), Some(ReceiptState::Failed));
}

// ────────────────────────────────────────
// TEST 2: retry_exponential_backoff_delays
// ────────────────────────────────────────

#[test]
fn retry_exponential_backoff_delays() {
    let config = RetryConfig {
        max_retries: 5,
        initial_delay_ms: 100,
        max_delay_ms: 5000,
        backoff_multiplier: 2.0,
        jitter: false,
    };

    // attempt 0: 100ms
    assert_eq!(config.delay_ms_for_attempt(0), 100);
    // attempt 1: 100 * 2.0 = 200ms
    assert_eq!(config.delay_ms_for_attempt(1), 200);
    // attempt 2: 100 * 2.0 * 2.0 = 400ms
    assert_eq!(config.delay_ms_for_attempt(2), 400);
    // attempt 3: 100 * 8 = 800ms
    assert_eq!(config.delay_ms_for_attempt(3), 800);
    // attempt 4: 100 * 16 = 1600ms
    assert_eq!(config.delay_ms_for_attempt(4), 1600);

    // Verify cap at max_delay_ms
    // attempt 6: 100 * 64 = 6400 → capped to 5000
    assert_eq!(config.delay_ms_for_attempt(6), 5000);
}

// ────────────────────────────────────────
// TEST 3: retry_max_retries_exhausted
// ────────────────────────────────────────

#[test]
fn retry_max_retries_exhausted() {
    let config = RetryConfig {
        max_retries: 3,
        initial_delay_ms: 50,
        max_delay_ms: 1000,
        backoff_multiplier: 2.0,
        jitter: false,
    };

    let mut attempts: u32 = 0;
    let mut last_err: Option<RetryableError> = None;

    // Simulate retry loop — all attempts fail with retryable error
    for attempt in 0..=config.max_retries {
        let err = RetryableError::Network(format!("timeout attempt {}", attempt));
        if !is_retryable(&err) {
            break;
        }
        attempts = attempts.saturating_add(1);
        last_err = Some(err);
        // In real code: sleep(delay_ms_for_attempt(attempt))
        let _delay = config.delay_ms_for_attempt(attempt);
    }

    // max_retries = 3, so we do attempts 0,1,2,3 = 4 total attempts
    assert_eq!(attempts, config.max_retries.saturating_add(1));
    assert!(last_err.is_some());
}

// ────────────────────────────────────────
// TEST 4: retry_immediate_success_no_delay
// ────────────────────────────────────────

#[test]
fn retry_immediate_success_no_delay() {
    let config = RetryConfig {
        max_retries: 5,
        initial_delay_ms: 1000,
        max_delay_ms: 30000,
        backoff_multiplier: 2.0,
        jitter: false,
    };

    let mut attempts: u32 = 0;
    let mut total_delay: u64 = 0;

    // Simulate: first attempt succeeds
    for attempt in 0..=config.max_retries {
        let success = attempt == 0; // immediate success
        if success {
            attempts = attempts.saturating_add(1);
            break;
        }
        total_delay = total_delay.saturating_add(config.delay_ms_for_attempt(attempt));
        attempts = attempts.saturating_add(1);
    }

    assert_eq!(attempts, 1);
    assert_eq!(total_delay, 0);
}

// ────────────────────────────────────────
// TEST 5: dispatch_workload_and_track
// ────────────────────────────────────────

#[test]
fn dispatch_workload_and_track() {
    let mut dispatcher = MockDispatcher::new(vec![Ok(DispatchResult {
        workload_id: "wl-001".to_string(),
        accepted: true,
    })]);

    let mut tracker = ReceiptStatusTracker::new();
    let hash = "receipt-dispatch-001";

    // Set initial state
    assert!(tracker.set_state(hash, ReceiptState::Pending).is_ok());

    // Dispatch
    let result = dispatcher.dispatch("storage", "127.0.0.1:50051", b"test_data");
    assert!(result.is_ok());
    let dr = result.ok();
    assert!(dr.is_some());
    let dr = dr.unwrap_or_else(|| DispatchResult {
        workload_id: String::new(),
        accepted: false,
    });
    assert_eq!(dr.workload_id, "wl-001");
    assert!(dr.accepted);

    // Update tracker
    assert!(tracker.set_state(hash, ReceiptState::Dispatched).is_ok());
    assert_eq!(tracker.get_state(hash), Some(ReceiptState::Dispatched));
    assert_eq!(dispatcher.call_count, 1);
}

// ────────────────────────────────────────
// TEST 6: claim_submission_success
// ────────────────────────────────────────

#[test]
fn claim_submission_success() {
    let mut claimer = MockClaimer::new();
    let hash = "receipt-claim-001";

    let result = claimer.submit_claim(hash, 5000);
    assert!(result.is_ok());
    let cr = match result {
        Ok(v) => v,
        Err(_) => {
            assert!(false, "expected Ok");
            return;
        }
    };

    assert_eq!(cr.receipt_hash, hash);
    assert_eq!(cr.amount, 5000);
    assert!(!cr.tx_hash.is_empty());
    // tx_hash should be a valid hex string
    assert!(cr.tx_hash.starts_with("0x"));
}

// ────────────────────────────────────────
// TEST 7: claim_already_claimed_error
// ────────────────────────────────────────

#[test]
fn claim_already_claimed_error() {
    let mut claimer = MockClaimer::new();
    let hash = "receipt-double-claim";

    // First claim succeeds
    let first = claimer.submit_claim(hash, 1000);
    assert!(first.is_ok());

    // Second claim returns AlreadyClaimed
    let second = claimer.submit_claim(hash, 1000);
    assert!(second.is_err());
    match second {
        Err(ClaimError::AlreadyClaimed) => {} // expected
        other => {
            assert!(
                false,
                "expected AlreadyClaimed, got: {:?}",
                other
            );
        }
    }

    // AlreadyClaimed is not retryable
    let err = RetryableError::AlreadyClaimed;
    assert!(!is_retryable(&err));
}

// ────────────────────────────────────────
// TEST 8: orchestrator_full_flow_mock
// ────────────────────────────────────────

#[test]
fn orchestrator_full_flow_mock() {
    let mut dispatcher = MockDispatcher::new(vec![Ok(DispatchResult {
        workload_id: "wl-full-001".to_string(),
        accepted: true,
    })]);
    let mut claimer = MockClaimer::new();
    let mut tracker = ReceiptStatusTracker::new();
    let hash = "receipt-full-001";

    let result = orchestrate_mock(
        &mut dispatcher,
        &mut claimer,
        &mut tracker,
        hash,
        true, // auto_claim
        10,   // max_poll_iterations
    );

    assert!(result.is_ok());
    let (steps, retry_count) = match result {
        Ok(v) => v,
        Err(_) => {
            assert!(false, "expected Ok");
            return;
        }
    };

    // Validate step order: Dispatch → Monitor → Proof → SubmitReceipt → Claim
    assert_eq!(steps.len(), 5);
    assert_eq!(steps[0], OrchestratorStep::Dispatch);
    assert_eq!(steps[1], OrchestratorStep::Monitor);
    assert_eq!(steps[2], OrchestratorStep::Proof);
    assert_eq!(steps[3], OrchestratorStep::SubmitReceipt);
    assert_eq!(steps[4], OrchestratorStep::Claim);

    // No retries needed
    assert_eq!(retry_count, 0);

    // Final state = Claimed
    assert_eq!(tracker.get_state(hash), Some(ReceiptState::Claimed));
}

// ────────────────────────────────────────
// TEST 9: orchestrator_retry_on_failure
// ────────────────────────────────────────

#[test]
fn orchestrator_retry_on_failure() {
    // First dispatch fails, second succeeds
    let mut dispatcher = MockDispatcher::new(vec![
        Err("connection refused".to_string()),
        Ok(DispatchResult {
            workload_id: "wl-retry-001".to_string(),
            accepted: true,
        }),
    ]);
    let mut claimer = MockClaimer::new();
    let mut tracker = ReceiptStatusTracker::new();
    let hash = "receipt-retry-001";

    let result = orchestrate_mock(
        &mut dispatcher,
        &mut claimer,
        &mut tracker,
        hash,
        true,
        10,
    );

    assert!(result.is_ok());
    let (steps, retry_count) = match result {
        Ok(v) => v,
        Err(_) => {
            assert!(false, "expected Ok");
            return;
        }
    };

    // Dispatch succeeded after retry
    assert!(steps.contains(&OrchestratorStep::Dispatch));
    // Retry count incremented
    assert_eq!(retry_count, 1);
    // Dispatcher was called twice
    assert_eq!(dispatcher.call_count, 2);
    // Final state = Claimed
    assert_eq!(tracker.get_state(hash), Some(ReceiptState::Claimed));
}

// ────────────────────────────────────────
// TEST 10: economic_metrics_recording
// ────────────────────────────────────────

#[test]
fn economic_metrics_recording() {
    let mut metrics = EconomicMetrics::new();

    // Initial state
    assert_eq!(metrics.dispatch_count, 0);
    assert_eq!(metrics.claim_count, 0);
    assert_eq!(metrics.failure_count, 0);
    assert_eq!(metrics.total_revenue, 0);
    assert_eq!(metrics.average_flow_duration_ms(), 0);

    // Record dispatches
    metrics.record_dispatch();
    metrics.record_dispatch();
    metrics.record_dispatch();
    assert_eq!(metrics.dispatch_count, 3);

    // Record claims with revenue
    metrics.record_claim(1000);
    metrics.record_claim(2500);
    assert_eq!(metrics.claim_count, 2);
    assert_eq!(metrics.total_revenue, 3500);

    // Record failure
    metrics.record_failure();
    assert_eq!(metrics.failure_count, 1);

    // Record flow completions and validate average
    metrics.record_flow_completion(100);
    metrics.record_flow_completion(200);
    metrics.record_flow_completion(300);
    assert_eq!(metrics.completed_flows, 3);
    // Average: (100 + 200 + 300) / 3 = 200
    assert_eq!(metrics.average_flow_duration_ms(), 200);
}

// ────────────────────────────────────────
// TEST 11: economic_metrics_prometheus_format
// ────────────────────────────────────────

#[test]
fn economic_metrics_prometheus_format() {
    let mut metrics = EconomicMetrics::new();
    metrics.record_dispatch();
    metrics.record_dispatch();
    metrics.record_claim(500);
    metrics.record_failure();
    metrics.record_flow_completion(1500);

    let prom = metrics.to_prometheus();

    // Validate exact Prometheus exposition lines
    assert!(prom.contains("# HELP dsdn_economic_dispatch_total Total dispatched workloads"));
    assert!(prom.contains("# TYPE dsdn_economic_dispatch_total counter"));
    assert!(prom.contains("dsdn_economic_dispatch_total 2"));

    assert!(prom.contains("# HELP dsdn_economic_claim_total Total successful claims"));
    assert!(prom.contains("# TYPE dsdn_economic_claim_total counter"));
    assert!(prom.contains("dsdn_economic_claim_total 1"));

    assert!(prom.contains("# HELP dsdn_economic_failure_total Total failures"));
    assert!(prom.contains("dsdn_economic_failure_total 1"));

    assert!(prom.contains("dsdn_economic_revenue_total 500"));
    assert!(prom.contains("dsdn_economic_avg_flow_duration_ms 1500"));

    // Validate JSON is parseable (manual check since no serde in tests/)
    let json_result = metrics.to_json();
    assert!(json_result.is_ok());
    let json = match json_result {
        Ok(v) => v,
        Err(_) => {
            assert!(false, "expected Ok");
            return;
        }
    };
    // Basic structural validation
    assert!(json.starts_with('{'));
    assert!(json.ends_with('}'));
    assert!(json.contains("\"dispatch_count\":2"));
    assert!(json.contains("\"claim_count\":1"));
    assert!(json.contains("\"total_revenue\":500"));
}

// ────────────────────────────────────────
// TEST 12: receipt_status_list_by_status
// ────────────────────────────────────────

#[test]
fn receipt_status_list_by_status() {
    let mut tracker = ReceiptStatusTracker::new();

    // Insert multiple receipts in various states
    assert!(tracker.set_state("hash-a", ReceiptState::Dispatched).is_ok());
    assert!(tracker.set_state("hash-b", ReceiptState::Dispatched).is_ok());
    assert!(tracker.set_state("hash-c", ReceiptState::Executing).is_ok());
    assert!(tracker.set_state("hash-d", ReceiptState::Failed).is_ok());
    assert!(tracker.set_state("hash-e", ReceiptState::Dispatched).is_ok());

    // List dispatched — should be deterministic BTreeMap order
    let dispatched = tracker.list_by_status(ReceiptState::Dispatched);
    assert_eq!(dispatched, vec!["hash-a", "hash-b", "hash-e"]);

    // List executing
    let executing = tracker.list_by_status(ReceiptState::Executing);
    assert_eq!(executing, vec!["hash-c"]);

    // List failed
    let failed = tracker.list_by_status(ReceiptState::Failed);
    assert_eq!(failed, vec!["hash-d"]);

    // List claimed — should be empty
    let claimed = tracker.list_by_status(ReceiptState::Claimed);
    assert!(claimed.is_empty());

    // All hashes sorted
    let all = tracker.all_hashes_sorted();
    assert_eq!(all, vec!["hash-a", "hash-b", "hash-c", "hash-d", "hash-e"]);
}

// ────────────────────────────────────────
// TEST 13 (BONUS): retry_non_retryable_short_circuit
// ────────────────────────────────────────

#[test]
fn retry_non_retryable_short_circuit() {
    // Validation errors should not be retried
    let validation_err = RetryableError::Validation("invalid field".to_string());
    assert!(!is_retryable(&validation_err));

    let already_claimed = RetryableError::AlreadyClaimed;
    assert!(!is_retryable(&already_claimed));

    // Only network errors are retryable
    let network_err = RetryableError::Network("timeout".to_string());
    assert!(is_retryable(&network_err));
}

// ────────────────────────────────────────
// TEST 14 (BONUS): economic_metrics_overflow_safety
// ────────────────────────────────────────

#[test]
fn economic_metrics_overflow_safety() {
    let mut metrics = EconomicMetrics {
        dispatch_count: u64::MAX - 1,
        claim_count: u64::MAX,
        failure_count: 0,
        total_revenue: u128::MAX - 10,
        completed_flows: 0,
        total_flow_duration_ms: 0,
    };

    // dispatch_count: MAX-1 + 1 = MAX (checked_add succeeds)
    metrics.record_dispatch();
    assert_eq!(metrics.dispatch_count, u64::MAX);

    // dispatch_count: MAX + 1 = saturates to MAX
    metrics.record_dispatch();
    assert_eq!(metrics.dispatch_count, u64::MAX);

    // claim_count already at MAX — should saturate
    metrics.record_claim(100);
    assert_eq!(metrics.claim_count, u64::MAX);

    // total_revenue: MAX-10 + 100 → saturates to MAX
    assert_eq!(metrics.total_revenue, u128::MAX);

    // average_flow_duration with zero completed_flows = 0
    assert_eq!(metrics.average_flow_duration_ms(), 0);
}