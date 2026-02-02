//! # Gating Decision & Report (14B.8)
//!
//! Defines the final output types of the gating evaluation process:
//! `GatingDecision` (approved or rejected), `CheckResult` (individual
//! check outcome), and `GatingReport` (full audit trail).
//!
//! ## Overview
//!
//! After all gating checks have been evaluated, the admission engine
//! produces a `GatingReport` containing:
//! - The evaluated node's identity
//! - A deterministic `GatingDecision` (Approved or Rejected with errors)
//! - An ordered list of `CheckResult` entries (one per check run)
//! - The evaluation timestamp (caller-provided, not system clock)
//! - The evaluator identifier (e.g., "coordinator", "scheduler", "cli")
//!
//! ## Determinism
//!
//! - No system clock access — the timestamp is an input parameter.
//! - No random number generation.
//! - Checks are stored in caller-provided order — no reordering.
//! - Errors are preserved exactly as provided — no filtering or merging.
//! - `summary()` output is deterministic for the same input.
//! - `to_json()` serializes the entire struct without modification.
//!
//! ## Safety Properties
//!
//! - All types are value types: `Clone`, `Debug`, `PartialEq`, `Eq`.
//! - No interior mutability, no global state.
//! - `errors()` returns a borrowed slice — no allocation.
//! - No panics in any method.

use serde::{Deserialize, Serialize};

use super::error::GatingError;
use super::identity::NodeIdentity;

// ════════════════════════════════════════════════════════════════════════════════
// GATING DECISION
// ════════════════════════════════════════════════════════════════════════════════

/// The final decision of a gating evaluation.
///
/// `Approved` means the node passed all gating checks and is eligible
/// for admission. `Rejected` means one or more checks failed — the
/// `Vec<GatingError>` contains every failure reason, preserving order.
///
/// ## Invariants
///
/// - `Rejected` always contains at least one error in well-formed usage.
///   However, the type does not enforce this at the struct level to
///   avoid panicking constructors.
/// - Errors are never filtered, merged, or reordered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GatingDecision {
    /// The node passed all gating checks.
    Approved,
    /// The node failed one or more gating checks.
    /// Contains every failure reason in evaluation order.
    Rejected(Vec<GatingError>),
}

impl GatingDecision {
    /// Returns `true` if the decision is `Approved`.
    ///
    /// This is a **pure function** — deterministic, no side effects.
    #[must_use]
    #[inline]
    pub fn is_approved(&self) -> bool {
        matches!(self, GatingDecision::Approved)
    }

    /// Returns the errors associated with the decision.
    ///
    /// - `Approved` → empty slice `&[]` (no allocation).
    /// - `Rejected(errs)` → borrowed reference to the error vector.
    ///
    /// This method **never allocates**. It returns a reference to
    /// existing data or a static empty slice.
    #[must_use]
    #[inline]
    pub fn errors(&self) -> &[GatingError] {
        match self {
            GatingDecision::Approved => &[],
            GatingDecision::Rejected(errs) => errs,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// CHECK RESULT
// ════════════════════════════════════════════════════════════════════════════════

/// The outcome of a single gating check.
///
/// Each `CheckResult` records whether a specific check passed or failed,
/// along with an optional detail message for diagnostics.
///
/// ## Fields
///
/// - `check_name`: A descriptive name for the check (e.g., `"stake_check"`,
///   `"tls_validation"`, `"identity_proof"`, `"cooldown_check"`).
/// - `passed`: `true` if the check succeeded, `false` if it failed.
/// - `detail`: Optional detail message. Should be `Some(...)` if the
///   check failed or if there is relevant diagnostic information.
///   `None` if the check passed without notable information.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckResult {
    /// Descriptive name of the check (e.g., "stake_check").
    pub check_name: String,
    /// Whether this check passed (`true`) or failed (`false`).
    pub passed: bool,
    /// Optional detail message for diagnostics.
    pub detail: Option<String>,
}

// ════════════════════════════════════════════════════════════════════════════════
// GATING REPORT
// ════════════════════════════════════════════════════════════════════════════════

/// A complete audit report for a gating evaluation.
///
/// `GatingReport` captures the full context of a node's admission
/// evaluation: who was evaluated, what the result was, which checks
/// were run (in order), when it happened, and who performed the
/// evaluation.
///
/// ## Fields
///
/// - `node_identity`: The identity of the node that was evaluated.
/// - `decision`: The final gating decision (Approved or Rejected).
/// - `checks`: Ordered list of individual check results. The order
///   reflects the evaluation sequence — no reordering is performed.
/// - `timestamp`: Unix timestamp (seconds) of the evaluation. This
///   is a caller-provided input, not derived from the system clock.
/// - `evaluated_by`: Identifier of the entity that performed the
///   evaluation (e.g., `"coordinator"`, `"scheduler"`, `"cli"`).
///
/// ## Serialization
///
/// The entire struct is serializable via `serde`. Use `to_json()` to
/// produce a JSON representation for logging, audit trails, or API
/// responses.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatingReport {
    /// The identity of the evaluated node.
    pub node_identity: NodeIdentity,
    /// The final gating decision.
    pub decision: GatingDecision,
    /// Ordered list of individual check results.
    pub checks: Vec<CheckResult>,
    /// Unix timestamp (seconds) of the evaluation (caller-provided).
    pub timestamp: u64,
    /// Identifier of the evaluator (e.g., "coordinator", "scheduler").
    pub evaluated_by: String,
}

impl GatingReport {
    /// Returns a single-line, human-readable summary of the report.
    ///
    /// The summary includes:
    /// - Node ID (first 4 bytes as hex, 8 hex chars)
    /// - Decision status ("approved" or "rejected")
    /// - Number of checks performed
    /// - If rejected: number of errors
    ///
    /// ## Examples (illustrative, not contractual format)
    ///
    /// ```text
    /// node 0102030405060708: approved (4 checks)
    /// node aabbccdd01020304: rejected (5 checks, 2 errors)
    /// ```
    ///
    /// This is a **pure function** — deterministic for the same input.
    #[must_use]
    pub fn summary(&self) -> String {
        // Format first 4 bytes of node_id as lowercase hex (8 chars)
        let id_prefix = format!(
            "{:02x}{:02x}{:02x}{:02x}",
            self.node_identity.node_id[0],
            self.node_identity.node_id[1],
            self.node_identity.node_id[2],
            self.node_identity.node_id[3],
        );

        let check_count = self.checks.len();

        match &self.decision {
            GatingDecision::Approved => {
                format!(
                    "node {}: approved ({} checks)",
                    id_prefix, check_count
                )
            }
            GatingDecision::Rejected(errs) => {
                format!(
                    "node {}: rejected ({} checks, {} errors)",
                    id_prefix, check_count, errs.len()
                )
            }
        }
    }

    /// Serializes the entire report to a JSON string.
    ///
    /// Uses `serde_json::to_string`. The struct is serialized as-is
    /// with no modification, filtering, or field removal. The error
    /// from `serde_json` is returned directly without wrapping.
    ///
    /// This is a **pure function** — deterministic for the same input.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ──────────────────────────────────────────────────────────────────────
    // HELPERS
    // ──────────────────────────────────────────────────────────────────────

    fn make_identity() -> NodeIdentity {
        NodeIdentity {
            node_id: [0xAA; 32],
            operator_address: [0xBB; 20],
            tls_cert_fingerprint: [0xCC; 32],
        }
    }

    fn make_identity_with_prefix(b0: u8, b1: u8, b2: u8, b3: u8) -> NodeIdentity {
        let mut node_id = [0u8; 32];
        node_id[0] = b0;
        node_id[1] = b1;
        node_id[2] = b2;
        node_id[3] = b3;
        NodeIdentity {
            node_id,
            operator_address: [0; 20],
            tls_cert_fingerprint: [0; 32],
        }
    }

    fn make_check(name: &str, passed: bool, detail: Option<&str>) -> CheckResult {
        CheckResult {
            check_name: name.to_string(),
            passed,
            detail: detail.map(|s| s.to_string()),
        }
    }

    fn make_approved_report() -> GatingReport {
        GatingReport {
            node_identity: make_identity(),
            decision: GatingDecision::Approved,
            checks: vec![
                make_check("stake_check", true, None),
                make_check("tls_validation", true, None),
                make_check("identity_proof", true, None),
                make_check("cooldown_check", true, None),
            ],
            timestamp: 1_700_000_000,
            evaluated_by: "coordinator".to_string(),
        }
    }

    fn make_rejected_report() -> GatingReport {
        use super::super::identity::NodeClass;
        GatingReport {
            node_identity: make_identity(),
            decision: GatingDecision::Rejected(vec![
                GatingError::ZeroStake,
                GatingError::InsufficientStake {
                    required: 5000,
                    actual: 0,
                    class: NodeClass::Storage,
                },
            ]),
            checks: vec![
                make_check("stake_check", false, Some("zero stake detected")),
                make_check("tls_validation", true, None),
                make_check("identity_proof", false, Some("signature invalid")),
            ],
            timestamp: 1_700_000_000,
            evaluated_by: "scheduler".to_string(),
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // GatingDecision — BASIC
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_decision_approved_is_approved() {
        let d = GatingDecision::Approved;
        assert!(d.is_approved());
    }

    #[test]
    fn test_decision_rejected_is_not_approved() {
        let d = GatingDecision::Rejected(vec![GatingError::ZeroStake]);
        assert!(!d.is_approved());
    }

    #[test]
    fn test_decision_rejected_empty_is_not_approved() {
        // Even an empty Rejected vec is still "rejected"
        let d = GatingDecision::Rejected(vec![]);
        assert!(!d.is_approved());
    }

    #[test]
    fn test_decision_approved_errors_empty() {
        let d = GatingDecision::Approved;
        assert!(d.errors().is_empty());
    }

    #[test]
    fn test_decision_rejected_errors_returns_slice() {
        let errs = vec![GatingError::ZeroStake, GatingError::NodeNotRegistered];
        let d = GatingDecision::Rejected(errs.clone());
        assert_eq!(d.errors(), &errs[..]);
    }

    #[test]
    fn test_decision_rejected_errors_preserves_order() {
        let errs = vec![
            GatingError::NodeNotRegistered,
            GatingError::ZeroStake,
            GatingError::NodeBanned { until_timestamp: 100 },
        ];
        let d = GatingDecision::Rejected(errs.clone());
        let result = d.errors();
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], GatingError::NodeNotRegistered);
        assert_eq!(result[1], GatingError::ZeroStake);
        assert_eq!(result[2], GatingError::NodeBanned { until_timestamp: 100 });
    }

    #[test]
    fn test_decision_errors_no_allocation() {
        // Verify errors() returns a reference, not a new Vec.
        // The slice's data pointer should match the internal Vec's.
        let errs = vec![GatingError::ZeroStake];
        let d = GatingDecision::Rejected(errs);
        let slice1 = d.errors();
        let slice2 = d.errors();
        // Both calls return the same pointer (no allocation)
        assert_eq!(slice1.as_ptr(), slice2.as_ptr());
    }

    // ──────────────────────────────────────────────────────────────────────
    // GatingDecision — TRAITS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_decision_clone() {
        let d = GatingDecision::Rejected(vec![GatingError::ZeroStake]);
        let cloned = d.clone();
        assert_eq!(d, cloned);
    }

    #[test]
    fn test_decision_debug() {
        let d = GatingDecision::Approved;
        let debug = format!("{:?}", d);
        assert!(debug.contains("Approved"));
    }

    #[test]
    fn test_decision_eq() {
        assert_eq!(GatingDecision::Approved, GatingDecision::Approved);
    }

    #[test]
    fn test_decision_ne() {
        assert_ne!(
            GatingDecision::Approved,
            GatingDecision::Rejected(vec![])
        );
    }

    #[test]
    fn test_decision_serde_approved() {
        let d = GatingDecision::Approved;
        let json = serde_json::to_string(&d).expect("serialize");
        let back: GatingDecision = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(d, back);
    }

    #[test]
    fn test_decision_serde_rejected() {
        let d = GatingDecision::Rejected(vec![
            GatingError::ZeroStake,
            GatingError::NodeNotRegistered,
        ]);
        let json = serde_json::to_string(&d).expect("serialize");
        let back: GatingDecision = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(d, back);
    }

    // ──────────────────────────────────────────────────────────────────────
    // CheckResult — BASIC
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_check_result_passed_no_detail() {
        let cr = make_check("stake_check", true, None);
        assert_eq!(cr.check_name, "stake_check");
        assert!(cr.passed);
        assert!(cr.detail.is_none());
    }

    #[test]
    fn test_check_result_failed_with_detail() {
        let cr = make_check("tls_validation", false, Some("cert expired"));
        assert_eq!(cr.check_name, "tls_validation");
        assert!(!cr.passed);
        assert_eq!(cr.detail.as_deref(), Some("cert expired"));
    }

    #[test]
    fn test_check_result_passed_with_detail() {
        // A passing check with informational detail is valid
        let cr = make_check("cooldown_check", true, Some("3600s remaining"));
        assert!(cr.passed);
        assert!(cr.detail.is_some());
    }

    // ──────────────────────────────────────────────────────────────────────
    // CheckResult — TRAITS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_check_result_clone() {
        let cr = make_check("test", true, Some("info"));
        let cloned = cr.clone();
        assert_eq!(cr, cloned);
    }

    #[test]
    fn test_check_result_debug() {
        let cr = make_check("test", false, Some("detail"));
        let debug = format!("{:?}", cr);
        assert!(debug.contains("CheckResult"));
        assert!(debug.contains("test"));
    }

    #[test]
    fn test_check_result_eq() {
        let a = make_check("x", true, None);
        let b = make_check("x", true, None);
        assert_eq!(a, b);
    }

    #[test]
    fn test_check_result_ne_name() {
        let a = make_check("x", true, None);
        let b = make_check("y", true, None);
        assert_ne!(a, b);
    }

    #[test]
    fn test_check_result_ne_passed() {
        let a = make_check("x", true, None);
        let b = make_check("x", false, None);
        assert_ne!(a, b);
    }

    #[test]
    fn test_check_result_ne_detail() {
        let a = make_check("x", true, None);
        let b = make_check("x", true, Some("info"));
        assert_ne!(a, b);
    }

    #[test]
    fn test_check_result_serde() {
        let cr = make_check("stake_check", false, Some("insufficient"));
        let json = serde_json::to_string(&cr).expect("serialize");
        let back: CheckResult = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cr, back);
    }

    // ──────────────────────────────────────────────────────────────────────
    // GatingReport — summary()
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_summary_approved() {
        let report = make_approved_report();
        let s = report.summary();
        // node_id = [0xAA; 32] → prefix = "aaaaaaaa"
        assert!(s.contains("aaaaaaaa"), "missing node id prefix: {}", s);
        assert!(s.contains("approved"), "missing 'approved': {}", s);
        assert!(s.contains("4 checks"), "missing check count: {}", s);
        // Should NOT contain "error"
        assert!(!s.contains("error"), "approved summary has error: {}", s);
    }

    #[test]
    fn test_summary_rejected() {
        let report = make_rejected_report();
        let s = report.summary();
        assert!(s.contains("aaaaaaaa"), "missing node id prefix: {}", s);
        assert!(s.contains("rejected"), "missing 'rejected': {}", s);
        assert!(s.contains("3 checks"), "missing check count: {}", s);
        assert!(s.contains("2 errors"), "missing error count: {}", s);
    }

    #[test]
    fn test_summary_hex_prefix_format() {
        let report = GatingReport {
            node_identity: make_identity_with_prefix(0x01, 0x23, 0x45, 0x67),
            decision: GatingDecision::Approved,
            checks: vec![],
            timestamp: 0,
            evaluated_by: "test".to_string(),
        };
        let s = report.summary();
        assert!(s.contains("01234567"), "hex prefix mismatch: {}", s);
    }

    #[test]
    fn test_summary_zero_checks() {
        let report = GatingReport {
            node_identity: make_identity(),
            decision: GatingDecision::Approved,
            checks: vec![],
            timestamp: 0,
            evaluated_by: "test".to_string(),
        };
        let s = report.summary();
        assert!(s.contains("0 checks"), "missing zero checks: {}", s);
    }

    #[test]
    fn test_summary_single_line() {
        let report = make_approved_report();
        let s = report.summary();
        assert!(!s.contains('\n'), "summary must be single line: {:?}", s);
    }

    #[test]
    fn test_summary_deterministic() {
        let report = make_rejected_report();
        let s1 = report.summary();
        let s2 = report.summary();
        let s3 = report.summary();
        assert_eq!(s1, s2);
        assert_eq!(s2, s3);
    }

    #[test]
    fn test_summary_does_not_hide_status() {
        // Rejected report must say "rejected", never "approved"
        let report = make_rejected_report();
        let s = report.summary();
        assert!(s.contains("rejected"), "must show rejected: {}", s);
        assert!(!s.contains("approved"), "must not show approved: {}", s);
    }

    // ──────────────────────────────────────────────────────────────────────
    // GatingReport — to_json()
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_to_json_approved() {
        let report = make_approved_report();
        let json = report.to_json();
        assert!(json.is_ok());
        let json_str = json.unwrap();
        assert!(json_str.contains("Approved"));
        assert!(json_str.contains("stake_check"));
        assert!(json_str.contains("coordinator"));
    }

    #[test]
    fn test_to_json_rejected() {
        let report = make_rejected_report();
        let json = report.to_json();
        assert!(json.is_ok());
        let json_str = json.unwrap();
        assert!(json_str.contains("Rejected"));
        assert!(json_str.contains("ZeroStake"));
    }

    #[test]
    fn test_to_json_roundtrip() {
        let report = make_approved_report();
        let json_str = report.to_json().expect("serialize");
        let back: GatingReport =
            serde_json::from_str(&json_str).expect("deserialize");
        assert_eq!(report, back);
    }

    #[test]
    fn test_to_json_rejected_roundtrip() {
        let report = make_rejected_report();
        let json_str = report.to_json().expect("serialize");
        let back: GatingReport =
            serde_json::from_str(&json_str).expect("deserialize");
        assert_eq!(report, back);
    }

    #[test]
    fn test_to_json_preserves_all_fields() {
        let report = make_rejected_report();
        let json_str = report.to_json().expect("serialize");
        let back: GatingReport =
            serde_json::from_str(&json_str).expect("deserialize");
        assert_eq!(back.node_identity, report.node_identity);
        assert_eq!(back.decision, report.decision);
        assert_eq!(back.checks, report.checks);
        assert_eq!(back.timestamp, report.timestamp);
        assert_eq!(back.evaluated_by, report.evaluated_by);
    }

    #[test]
    fn test_to_json_deterministic() {
        let report = make_approved_report();
        let j1 = report.to_json().expect("s1");
        let j2 = report.to_json().expect("s2");
        assert_eq!(j1, j2);
    }

    // ──────────────────────────────────────────────────────────────────────
    // GatingReport — TRAITS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_report_clone() {
        let report = make_approved_report();
        let cloned = report.clone();
        assert_eq!(report, cloned);
    }

    #[test]
    fn test_report_debug() {
        let report = make_approved_report();
        let debug = format!("{:?}", report);
        assert!(debug.contains("GatingReport"));
        assert!(debug.contains("Approved"));
    }

    #[test]
    fn test_report_eq() {
        let a = make_approved_report();
        let b = make_approved_report();
        assert_eq!(a, b);
    }

    #[test]
    fn test_report_ne_decision() {
        let a = make_approved_report();
        let b = make_rejected_report();
        assert_ne!(a, b);
    }

    #[test]
    fn test_report_ne_timestamp() {
        let a = make_approved_report();
        let mut b = make_approved_report();
        b.timestamp = 999;
        assert_ne!(a, b);
    }

    #[test]
    fn test_report_ne_evaluated_by() {
        let a = make_approved_report();
        let mut b = make_approved_report();
        b.evaluated_by = "cli".to_string();
        assert_ne!(a, b);
    }

    #[test]
    fn test_report_serde_roundtrip() {
        let report = make_approved_report();
        let json = serde_json::to_string(&report).expect("serialize");
        let back: GatingReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(report, back);
    }

    // ──────────────────────────────────────────────────────────────────────
    // SEND + SYNC
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<GatingDecision>();
        assert_send_sync::<CheckResult>();
        assert_send_sync::<GatingReport>();
    }

    // ──────────────────────────────────────────────────────────────────────
    // EDGE CASES
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_rejected_with_many_errors() {
        let errs: Vec<GatingError> = (0..100)
            .map(|i| GatingError::NodeBanned { until_timestamp: i })
            .collect();
        let d = GatingDecision::Rejected(errs.clone());
        assert!(!d.is_approved());
        assert_eq!(d.errors().len(), 100);
    }

    #[test]
    fn test_report_empty_checks_empty_evaluator() {
        let report = GatingReport {
            node_identity: make_identity(),
            decision: GatingDecision::Approved,
            checks: vec![],
            timestamp: 0,
            evaluated_by: String::new(),
        };
        // Should serialize without panic
        let json = report.to_json();
        assert!(json.is_ok());
        // Summary should still work
        let s = report.summary();
        assert!(s.contains("approved"));
    }

    #[test]
    fn test_report_checks_order_preserved() {
        let checks = vec![
            make_check("first", true, None),
            make_check("second", false, Some("fail")),
            make_check("third", true, None),
        ];
        let report = GatingReport {
            node_identity: make_identity(),
            decision: GatingDecision::Approved,
            checks: checks.clone(),
            timestamp: 0,
            evaluated_by: "test".to_string(),
        };
        assert_eq!(report.checks[0].check_name, "first");
        assert_eq!(report.checks[1].check_name, "second");
        assert_eq!(report.checks[2].check_name, "third");

        // Roundtrip preserves order
        let json_str = report.to_json().expect("serialize");
        let back: GatingReport =
            serde_json::from_str(&json_str).expect("deserialize");
        assert_eq!(back.checks, checks);
    }
}