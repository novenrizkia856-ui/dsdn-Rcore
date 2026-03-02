//! # Economic Metrics + Logging (14C.C.21)
//!
//! Observability module for the agent's economic lifecycle.
//!
//! ## Invariants
//!
//! 1. All counter increments use `checked_add`; overflow returns `MetricsError::Overflow`.
//! 2. `average_flow_duration_ms` = `total_duration_sum / workloads_completed` (integer division).
//!    If `workloads_completed == 0`, average = 0.
//! 3. All output formats (`to_table`, `to_json`, `to_prometheus`) are deterministic.
//! 4. No panic, no unwrap, no expect, no unsafe, no TODO.

use std::fmt;

// ════════════════════════════════════════════════════════════════════════════════
// ERROR TYPE
// ════════════════════════════════════════════════════════════════════════════════

/// Error type for metrics operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetricsError {
    /// An arithmetic overflow would have occurred.
    Overflow,
}

impl fmt::Display for MetricsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Overflow => f.write_str("metrics counter overflow"),
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// ECONOMIC METRICS STRUCT
// ════════════════════════════════════════════════════════════════════════════════

/// Aggregate economic metrics for the agent.
///
/// Thread safety: wrap in `Arc<Mutex<EconomicMetrics>>` for concurrent access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EconomicMetrics {
    /// Number of workloads dispatched.
    pub workloads_dispatched: u64,
    /// Number of workloads that completed successfully.
    pub workloads_completed: u64,
    /// Number of workloads that failed.
    pub workloads_failed: u64,
    /// Number of receipts submitted to chain.
    pub receipts_submitted: u64,
    /// Number of claims that succeeded.
    pub claims_successful: u64,
    /// Number of claims that were rejected.
    pub claims_rejected: u64,
    /// Total rewards earned (sum of all reward amounts).
    pub total_rewards_earned: u128,
    /// Total retry attempts across all operations.
    pub retry_attempts: u64,
    /// Average flow duration in milliseconds (computed from sum / completed count).
    pub average_flow_duration_ms: u64,
    /// Internal: sum of all completion durations for average computation.
    /// Not exposed in output formats.
    total_duration_sum: u128,
}

impl EconomicMetrics {
    /// Create a new `EconomicMetrics` with all counters at zero.
    pub fn new() -> Self {
        Self {
            workloads_dispatched: 0,
            workloads_completed: 0,
            workloads_failed: 0,
            receipts_submitted: 0,
            claims_successful: 0,
            claims_rejected: 0,
            total_rewards_earned: 0,
            retry_attempts: 0,
            average_flow_duration_ms: 0,
            total_duration_sum: 0,
        }
    }

    /// Record a workload dispatch event.
    pub fn record_dispatch(&mut self) -> Result<(), MetricsError> {
        self.workloads_dispatched = self
            .workloads_dispatched
            .checked_add(1)
            .ok_or(MetricsError::Overflow)?;
        Ok(())
    }

    /// Record a workload completion event with its duration in milliseconds.
    ///
    /// Updates `workloads_completed`, `total_duration_sum`, and recomputes
    /// `average_flow_duration_ms`.
    pub fn record_completion(&mut self, duration_ms: u64) -> Result<(), MetricsError> {
        let new_completed = self
            .workloads_completed
            .checked_add(1)
            .ok_or(MetricsError::Overflow)?;
        let new_sum = self
            .total_duration_sum
            .checked_add(u128::from(duration_ms))
            .ok_or(MetricsError::Overflow)?;
        // Both checks passed; commit the updates atomically.
        self.workloads_completed = new_completed;
        self.total_duration_sum = new_sum;
        // Safe: new_completed > 0 after the increment above.
        let avg = self.total_duration_sum / u128::from(self.workloads_completed);
        self.average_flow_duration_ms = if avg > u128::from(u64::MAX) {
            u64::MAX
        } else {
            avg as u64
        };
        Ok(())
    }

    /// Record a workload failure event.
    pub fn record_failure(&mut self) -> Result<(), MetricsError> {
        self.workloads_failed = self
            .workloads_failed
            .checked_add(1)
            .ok_or(MetricsError::Overflow)?;
        Ok(())
    }

    /// Record a receipt submission event.
    pub fn record_receipt_submission(&mut self) -> Result<(), MetricsError> {
        self.receipts_submitted = self
            .receipts_submitted
            .checked_add(1)
            .ok_or(MetricsError::Overflow)?;
        Ok(())
    }

    /// Record the result of a claim attempt.
    ///
    /// * `success = true` increments `claims_successful`
    /// * `success = false` increments `claims_rejected`
    pub fn record_claim_result(&mut self, success: bool) -> Result<(), MetricsError> {
        if success {
            self.claims_successful = self
                .claims_successful
                .checked_add(1)
                .ok_or(MetricsError::Overflow)?;
        } else {
            self.claims_rejected = self
                .claims_rejected
                .checked_add(1)
                .ok_or(MetricsError::Overflow)?;
        }
        Ok(())
    }

    /// Record a reward amount earned.
    pub fn record_reward(&mut self, amount: u128) -> Result<(), MetricsError> {
        self.total_rewards_earned = self
            .total_rewards_earned
            .checked_add(amount)
            .ok_or(MetricsError::Overflow)?;
        Ok(())
    }

    /// Record a retry attempt.
    pub fn record_retry(&mut self) -> Result<(), MetricsError> {
        self.retry_attempts = self
            .retry_attempts
            .checked_add(1)
            .ok_or(MetricsError::Overflow)?;
        Ok(())
    }

    /// Format metrics as a human-readable table.
    ///
    /// Deterministic ordering. Never panics.
    pub fn to_table(&self) -> String {
        let mut out = String::new();
        out.push_str("┌──────────────────────────────┬────────────────────┐\n");
        out.push_str("│ ECONOMIC METRICS             │              Value │\n");
        out.push_str("├──────────────────────────────┼────────────────────┤\n");
        out.push_str(&format!(
            "│ Workloads Dispatched         │ {:>18} │\n",
            self.workloads_dispatched
        ));
        out.push_str(&format!(
            "│ Workloads Completed          │ {:>18} │\n",
            self.workloads_completed
        ));
        out.push_str(&format!(
            "│ Workloads Failed             │ {:>18} │\n",
            self.workloads_failed
        ));
        out.push_str(&format!(
            "│ Receipts Submitted           │ {:>18} │\n",
            self.receipts_submitted
        ));
        out.push_str(&format!(
            "│ Claims Successful            │ {:>18} │\n",
            self.claims_successful
        ));
        out.push_str(&format!(
            "│ Claims Rejected              │ {:>18} │\n",
            self.claims_rejected
        ));
        out.push_str(&format!(
            "│ Total Rewards Earned         │ {:>18} │\n",
            self.total_rewards_earned
        ));
        out.push_str(&format!(
            "│ Retry Attempts               │ {:>18} │\n",
            self.retry_attempts
        ));
        out.push_str(&format!(
            "│ Avg Flow Duration (ms)       │ {:>18} │\n",
            self.average_flow_duration_ms
        ));
        out.push_str("└──────────────────────────────┴────────────────────┘\n");
        out
    }

    /// Format metrics as valid JSON with deterministic field ordering.
    ///
    /// Fields are written in fixed order. Never panics.
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        out.push_str("{\n");
        out.push_str(&format!(
            "  \"workloads_dispatched\": {},\n",
            self.workloads_dispatched
        ));
        out.push_str(&format!(
            "  \"workloads_completed\": {},\n",
            self.workloads_completed
        ));
        out.push_str(&format!(
            "  \"workloads_failed\": {},\n",
            self.workloads_failed
        ));
        out.push_str(&format!(
            "  \"receipts_submitted\": {},\n",
            self.receipts_submitted
        ));
        out.push_str(&format!(
            "  \"claims_successful\": {},\n",
            self.claims_successful
        ));
        out.push_str(&format!(
            "  \"claims_rejected\": {},\n",
            self.claims_rejected
        ));
        out.push_str(&format!(
            "  \"total_rewards_earned\": {},\n",
            self.total_rewards_earned
        ));
        out.push_str(&format!(
            "  \"retry_attempts\": {},\n",
            self.retry_attempts
        ));
        out.push_str(&format!(
            "  \"average_flow_duration_ms\": {}\n",
            self.average_flow_duration_ms
        ));
        out.push('}');
        out
    }

    /// Format metrics in Prometheus exposition format.
    ///
    /// Deterministic ordering. No trailing invalid characters. Never panics.
    pub fn to_prometheus(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "economic_workloads_dispatched {}\n",
            self.workloads_dispatched
        ));
        out.push_str(&format!(
            "economic_workloads_completed {}\n",
            self.workloads_completed
        ));
        out.push_str(&format!(
            "economic_workloads_failed {}\n",
            self.workloads_failed
        ));
        out.push_str(&format!(
            "economic_receipts_submitted {}\n",
            self.receipts_submitted
        ));
        out.push_str(&format!(
            "economic_claims_successful {}\n",
            self.claims_successful
        ));
        out.push_str(&format!(
            "economic_claims_rejected {}\n",
            self.claims_rejected
        ));
        out.push_str(&format!(
            "economic_total_rewards_earned {}\n",
            self.total_rewards_earned
        ));
        out.push_str(&format!(
            "economic_retry_attempts {}\n",
            self.retry_attempts
        ));
        out.push_str(&format!(
            "economic_average_flow_duration_ms {}\n",
            self.average_flow_duration_ms
        ));
        out
    }
}

impl Default for EconomicMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// STRUCTURED LOGGING
// ════════════════════════════════════════════════════════════════════════════════

/// Format a dispatch log line.
///
/// Output: `[ECONOMIC] DISPATCH workload_id=<id> node=<node>`
pub fn log_dispatch(workload_id: &str, node: &str) -> String {
    format!(
        "[ECONOMIC] DISPATCH workload_id={} node={}",
        workload_id, node
    )
}

/// Format an execution log line.
///
/// Output: `[ECONOMIC] EXECUTE workload_id=<id> status=completed duration=<ms>`
pub fn log_execute(workload_id: &str, status: &str, duration_ms: u64) -> String {
    format!(
        "[ECONOMIC] EXECUTE workload_id={} status={} duration={}",
        workload_id, status, duration_ms
    )
}

/// Format a claim log line.
///
/// Output: `[ECONOMIC] CLAIM receipt=<hash> status=success amount=<amount>`
pub fn log_claim(receipt_hash: &str, status: &str, amount: u128) -> String {
    format!(
        "[ECONOMIC] CLAIM receipt={} status={} amount={}",
        receipt_hash, status, amount
    )
}

// ════════════════════════════════════════════════════════════════════════════════
// CLI HANDLER
// ════════════════════════════════════════════════════════════════════════════════

/// Handle `economic metrics` and `economic metrics --json`.
///
/// Never panics.
pub fn handle_economic_metrics(metrics: &EconomicMetrics, json: bool) {
    if json {
        println!("{}", metrics.to_json());
    } else {
        print!("{}", metrics.to_table());
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS (22 tests, requirement >= 18)
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── 1. metrics_initial_zero ─────────────────────────────────────────

    #[test]
    fn metrics_initial_zero() {
        let m = EconomicMetrics::new();
        assert_eq!(m.workloads_dispatched, 0);
        assert_eq!(m.workloads_completed, 0);
        assert_eq!(m.workloads_failed, 0);
        assert_eq!(m.receipts_submitted, 0);
        assert_eq!(m.claims_successful, 0);
        assert_eq!(m.claims_rejected, 0);
        assert_eq!(m.total_rewards_earned, 0);
        assert_eq!(m.retry_attempts, 0);
        assert_eq!(m.average_flow_duration_ms, 0);
    }

    // ── 2. record_dispatch_increments ───────────────────────────────────

    #[test]
    fn record_dispatch_increments() {
        let mut m = EconomicMetrics::new();
        assert!(m.record_dispatch().is_ok());
        assert_eq!(m.workloads_dispatched, 1);
        assert!(m.record_dispatch().is_ok());
        assert_eq!(m.workloads_dispatched, 2);
    }

    // ── 3. record_completion_updates_average ────────────────────────────

    #[test]
    fn record_completion_updates_average() {
        let mut m = EconomicMetrics::new();
        // One completion with 100ms
        assert!(m.record_completion(100).is_ok());
        assert_eq!(m.workloads_completed, 1);
        assert_eq!(m.average_flow_duration_ms, 100);

        // Second completion with 200ms: avg = (100 + 200) / 2 = 150
        assert!(m.record_completion(200).is_ok());
        assert_eq!(m.workloads_completed, 2);
        assert_eq!(m.average_flow_duration_ms, 150);

        // Third completion with 300ms: avg = (100 + 200 + 300) / 3 = 200
        assert!(m.record_completion(300).is_ok());
        assert_eq!(m.workloads_completed, 3);
        assert_eq!(m.average_flow_duration_ms, 200);
    }

    // ── 4. record_failure_increments ────────────────────────────────────

    #[test]
    fn record_failure_increments() {
        let mut m = EconomicMetrics::new();
        assert!(m.record_failure().is_ok());
        assert_eq!(m.workloads_failed, 1);
        assert!(m.record_failure().is_ok());
        assert_eq!(m.workloads_failed, 2);
    }

    // ── 5. record_receipt_submission ────────────────────────────────────

    #[test]
    fn record_receipt_submission() {
        let mut m = EconomicMetrics::new();
        assert!(m.record_receipt_submission().is_ok());
        assert_eq!(m.receipts_submitted, 1);
        assert!(m.record_receipt_submission().is_ok());
        assert_eq!(m.receipts_submitted, 2);
    }

    // ── 6. record_claim_success ─────────────────────────────────────────

    #[test]
    fn record_claim_success() {
        let mut m = EconomicMetrics::new();
        assert!(m.record_claim_result(true).is_ok());
        assert_eq!(m.claims_successful, 1);
        assert_eq!(m.claims_rejected, 0);
    }

    // ── 7. record_claim_rejected ────────────────────────────────────────

    #[test]
    fn record_claim_rejected() {
        let mut m = EconomicMetrics::new();
        assert!(m.record_claim_result(false).is_ok());
        assert_eq!(m.claims_rejected, 1);
        assert_eq!(m.claims_successful, 0);
    }

    // ── 8. record_reward_accumulates ────────────────────────────────────

    #[test]
    fn record_reward_accumulates() {
        let mut m = EconomicMetrics::new();
        assert!(m.record_reward(1000).is_ok());
        assert_eq!(m.total_rewards_earned, 1000);
        assert!(m.record_reward(2500).is_ok());
        assert_eq!(m.total_rewards_earned, 3500);
        assert!(m.record_reward(0).is_ok());
        assert_eq!(m.total_rewards_earned, 3500);
    }

    // ── 9. record_retry_increment ───────────────────────────────────────

    #[test]
    fn record_retry_increment() {
        let mut m = EconomicMetrics::new();
        assert!(m.record_retry().is_ok());
        assert_eq!(m.retry_attempts, 1);
        assert!(m.record_retry().is_ok());
        assert!(m.record_retry().is_ok());
        assert_eq!(m.retry_attempts, 3);
    }

    // ── 10. overflow_protection_u64 ─────────────────────────────────────

    #[test]
    fn overflow_protection_u64() {
        let mut m = EconomicMetrics::new();
        m.workloads_dispatched = u64::MAX;
        assert_eq!(m.record_dispatch(), Err(MetricsError::Overflow));
        assert_eq!(m.workloads_dispatched, u64::MAX);

        let mut m2 = EconomicMetrics::new();
        m2.workloads_failed = u64::MAX;
        assert_eq!(m2.record_failure(), Err(MetricsError::Overflow));

        let mut m3 = EconomicMetrics::new();
        m3.receipts_submitted = u64::MAX;
        assert_eq!(m3.record_receipt_submission(), Err(MetricsError::Overflow));

        let mut m4 = EconomicMetrics::new();
        m4.retry_attempts = u64::MAX;
        assert_eq!(m4.record_retry(), Err(MetricsError::Overflow));

        let mut m5 = EconomicMetrics::new();
        m5.claims_successful = u64::MAX;
        assert_eq!(m5.record_claim_result(true), Err(MetricsError::Overflow));

        let mut m6 = EconomicMetrics::new();
        m6.claims_rejected = u64::MAX;
        assert_eq!(m6.record_claim_result(false), Err(MetricsError::Overflow));
    }

    // ── 11. overflow_protection_u128 ────────────────────────────────────

    #[test]
    fn overflow_protection_u128() {
        let mut m = EconomicMetrics::new();
        m.total_rewards_earned = u128::MAX;
        assert_eq!(m.record_reward(1), Err(MetricsError::Overflow));
        assert_eq!(m.total_rewards_earned, u128::MAX);

        // Duration sum overflow: total_duration_sum is private, set via completions.
        // We simulate by recording max completion first.
        let mut m2 = EconomicMetrics::new();
        m2.total_duration_sum = u128::MAX;
        assert_eq!(m2.record_completion(1), Err(MetricsError::Overflow));
    }

    // ── 12. average_zero_when_no_completion ──────────────────────────────

    #[test]
    fn average_zero_when_no_completion() {
        let m = EconomicMetrics::new();
        assert_eq!(m.average_flow_duration_ms, 0);
        assert_eq!(m.workloads_completed, 0);

        // After dispatches and failures, average should still be 0.
        let mut m2 = EconomicMetrics::new();
        let _ = m2.record_dispatch();
        let _ = m2.record_dispatch();
        let _ = m2.record_failure();
        assert_eq!(m2.average_flow_duration_ms, 0);
    }

    // ── 13. json_output_valid ───────────────────────────────────────────

    #[test]
    fn json_output_valid() {
        let mut m = EconomicMetrics::new();
        let _ = m.record_dispatch();
        let _ = m.record_completion(500);
        let _ = m.record_reward(1000);

        let json = m.to_json();

        // Verify it parses as valid JSON.
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("to_json must produce valid JSON");

        assert_eq!(parsed["workloads_dispatched"], 1);
        assert_eq!(parsed["workloads_completed"], 1);
        assert_eq!(parsed["workloads_failed"], 0);
        assert_eq!(parsed["receipts_submitted"], 0);
        assert_eq!(parsed["claims_successful"], 0);
        assert_eq!(parsed["claims_rejected"], 0);
        assert_eq!(parsed["total_rewards_earned"], 1000);
        assert_eq!(parsed["retry_attempts"], 0);
        assert_eq!(parsed["average_flow_duration_ms"], 500);
    }

    // ── 14. prometheus_output_valid ─────────────────────────────────────

    #[test]
    fn prometheus_output_valid() {
        let mut m = EconomicMetrics::new();
        let _ = m.record_dispatch();
        let _ = m.record_dispatch();
        let _ = m.record_completion(100);
        let _ = m.record_reward(5000);

        let prom = m.to_prometheus();

        assert!(prom.contains("economic_workloads_dispatched 2\n"));
        assert!(prom.contains("economic_workloads_completed 1\n"));
        assert!(prom.contains("economic_workloads_failed 0\n"));
        assert!(prom.contains("economic_receipts_submitted 0\n"));
        assert!(prom.contains("economic_claims_successful 0\n"));
        assert!(prom.contains("economic_claims_rejected 0\n"));
        assert!(prom.contains("economic_total_rewards_earned 5000\n"));
        assert!(prom.contains("economic_retry_attempts 0\n"));
        assert!(prom.contains("economic_average_flow_duration_ms 100\n"));

        // Calling twice yields same output.
        let prom2 = m.to_prometheus();
        assert_eq!(prom, prom2);

        // Verify all lines are valid prometheus format.
        for line in prom.lines() {
            let parts: Vec<&str> = line.split(' ').collect();
            assert_eq!(parts.len(), 2, "each prometheus line must be 'metric value'");
            assert!(
                parts[1].parse::<u128>().is_ok(),
                "value must be a valid number"
            );
        }
    }

    // ── 15. table_output_deterministic ───────────────────────────────────

    #[test]
    fn table_output_deterministic() {
        let mut m = EconomicMetrics::new();
        let _ = m.record_dispatch();
        let _ = m.record_completion(200);
        let _ = m.record_failure();
        let _ = m.record_receipt_submission();
        let _ = m.record_claim_result(true);
        let _ = m.record_reward(999);
        let _ = m.record_retry();

        let t1 = m.to_table();
        let t2 = m.to_table();
        assert_eq!(t1, t2, "table output must be deterministic");

        assert!(t1.contains("ECONOMIC METRICS"));
        assert!(t1.contains("Workloads Dispatched"));
        assert!(t1.contains("Workloads Completed"));
        assert!(t1.contains("Workloads Failed"));
        assert!(t1.contains("Receipts Submitted"));
        assert!(t1.contains("Claims Successful"));
        assert!(t1.contains("Claims Rejected"));
        assert!(t1.contains("Total Rewards Earned"));
        assert!(t1.contains("Retry Attempts"));
        assert!(t1.contains("Avg Flow Duration"));
    }

    // ── 16. logging_format_exact ────────────────────────────────────────

    #[test]
    fn logging_format_exact() {
        let dispatch_log = log_dispatch("wk-001", "node-a");
        assert_eq!(
            dispatch_log,
            "[ECONOMIC] DISPATCH workload_id=wk-001 node=node-a"
        );

        let execute_log = log_execute("wk-001", "completed", 1500);
        assert_eq!(
            execute_log,
            "[ECONOMIC] EXECUTE workload_id=wk-001 status=completed duration=1500"
        );

        let claim_log = log_claim("0xabc", "success", 5000);
        assert_eq!(
            claim_log,
            "[ECONOMIC] CLAIM receipt=0xabc status=success amount=5000"
        );

        // Empty fields should not panic.
        let empty_dispatch = log_dispatch("", "");
        assert_eq!(empty_dispatch, "[ECONOMIC] DISPATCH workload_id= node=");

        let empty_claim = log_claim("", "", 0);
        assert_eq!(empty_claim, "[ECONOMIC] CLAIM receipt= status= amount=0");
    }

    // ── 17. no_panic_on_zero_state ──────────────────────────────────────

    #[test]
    fn no_panic_on_zero_state() {
        let m = EconomicMetrics::new();

        // All output methods must not panic on zero state.
        let _table = m.to_table();
        let _json = m.to_json();
        let _prom = m.to_prometheus();

        // Verify JSON is valid even when all zeros.
        let parsed: serde_json::Value = serde_json::from_str(&m.to_json())
            .expect("zero-state JSON must be valid");
        assert_eq!(parsed["workloads_dispatched"], 0);
        assert_eq!(parsed["average_flow_duration_ms"], 0);

        // Display handler must not panic.
        handle_economic_metrics(&m, false);
        handle_economic_metrics(&m, true);
    }

    // ── 18. integration_with_orchestrator ────────────────────────────────

    #[test]
    fn integration_with_orchestrator() {
        // Simulate a full economic flow lifecycle with metrics recording.
        let mut m = EconomicMetrics::new();

        // Step 1: dispatch
        assert!(m.record_dispatch().is_ok());
        let _log = log_dispatch("wk-flow-1", "node-a");

        // Step 2: execution completed
        assert!(m.record_completion(1500).is_ok());
        let _log = log_execute("wk-flow-1", "completed", 1500);

        // Step 3: receipt submitted
        assert!(m.record_receipt_submission().is_ok());

        // Step 4: claim succeeded
        assert!(m.record_claim_result(true).is_ok());
        assert!(m.record_reward(5000).is_ok());
        let _log = log_claim("receipt-001", "success", 5000);

        // Step 5: second workload dispatched, fails, retry
        assert!(m.record_dispatch().is_ok());
        assert!(m.record_retry().is_ok());
        assert!(m.record_failure().is_ok());

        // Step 6: third workload dispatched, completes
        assert!(m.record_dispatch().is_ok());
        assert!(m.record_completion(2500).is_ok());
        assert!(m.record_receipt_submission().is_ok());
        assert!(m.record_claim_result(false).is_ok());

        // Validate final state.
        assert_eq!(m.workloads_dispatched, 3);
        assert_eq!(m.workloads_completed, 2);
        assert_eq!(m.workloads_failed, 1);
        assert_eq!(m.receipts_submitted, 2);
        assert_eq!(m.claims_successful, 1);
        assert_eq!(m.claims_rejected, 1);
        assert_eq!(m.total_rewards_earned, 5000);
        assert_eq!(m.retry_attempts, 1);
        // avg = (1500 + 2500) / 2 = 2000
        assert_eq!(m.average_flow_duration_ms, 2000);

        // All output formats must work.
        let json = m.to_json();
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("integration JSON must be valid");
        assert_eq!(parsed["workloads_dispatched"], 3);
        assert_eq!(parsed["average_flow_duration_ms"], 2000);

        let prom = m.to_prometheus();
        assert!(prom.contains("economic_workloads_dispatched 3\n"));
        assert!(prom.contains("economic_average_flow_duration_ms 2000\n"));

        let table = m.to_table();
        assert!(table.contains("ECONOMIC METRICS"));
    }

    // ── 19. default_trait ───────────────────────────────────────────────

    #[test]
    fn default_trait() {
        let m = EconomicMetrics::default();
        assert_eq!(m, EconomicMetrics::new());
    }

    // ── 20. metrics_error_display ───────────────────────────────────────

    #[test]
    fn metrics_error_display() {
        let err = MetricsError::Overflow;
        assert_eq!(err.to_string(), "metrics counter overflow");
    }

    // ── 21. json_field_ordering_deterministic ───────────────────────────

    #[test]
    fn json_field_ordering_deterministic() {
        let mut m = EconomicMetrics::new();
        let _ = m.record_dispatch();
        let _ = m.record_reward(42);

        let json1 = m.to_json();
        let json2 = m.to_json();
        assert_eq!(json1, json2);

        // Verify field order: workloads_dispatched comes before total_rewards_earned.
        let pos_dispatched = json1.find("workloads_dispatched");
        let pos_rewards = json1.find("total_rewards_earned");
        assert!(pos_dispatched.is_some());
        assert!(pos_rewards.is_some());
        assert!(
            pos_dispatched < pos_rewards,
            "fields must appear in deterministic order"
        );
    }

    // ── 22. average_integer_truncation ──────────────────────────────────

    #[test]
    fn average_integer_truncation() {
        let mut m = EconomicMetrics::new();
        // 10 / 3 = 3 (integer truncation, not 3.33)
        let _ = m.record_completion(10);
        let _ = m.record_completion(0);
        let _ = m.record_completion(0);
        // avg = 10 / 3 = 3
        assert_eq!(m.average_flow_duration_ms, 3);
    }
}