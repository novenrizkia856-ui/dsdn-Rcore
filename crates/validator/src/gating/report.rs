//! # Gating Report Generator (14B.28)
//!
//! Stateless generator for deterministic gating audit reports.
//!
//! ## Overview
//!
//! `ReportGenerator` produces [`GatingReport`] instances and renders
//! them in two deterministic formats:
//!
//! - **Table** ([`to_table`](ReportGenerator::to_table)): Human-readable
//!   fixed-width table for CLI output and operator dashboards.
//! - **JSON** ([`to_json`](ReportGenerator::to_json)): Machine-readable
//!   JSON string for logging, audit trails, and API responses.
//!
//! ## Design Properties
//!
//! - **Stateless**: `ReportGenerator` has no fields, no cache, no
//!   interior mutability. It is a zero-sized type.
//! - **Deterministic**: Same inputs always produce the same output.
//!   No system clock, no randomness, no environment dependency.
//! - **Pure**: No side effects, no I/O, no allocation beyond return values.
//! - **Safe**: No panic, no unwrap, no silent failure.
//!
//! ## Report Accuracy
//!
//! The [`generate`](ReportGenerator::generate) method copies all inputs
//! into a `GatingReport` without transformation. Check order is preserved
//! exactly. The decision is stored as-is — no re-evaluation is performed.
//! The report faithfully reflects the inputs provided by the caller.
//!
//! ## Edge Cases
//!
//! - Empty `checks` vector: Accepted. Table and JSON render zero rows.
//! - `Approved` with empty checks: Valid (e.g., permissive policy).
//! - `Rejected` with many errors: All errors rendered in order.
//! - Minimal identity (all-zero bytes): Rendered as hex `"00000000"`.

use std::fmt::Write as FmtWrite;

use dsdn_common::gating::{
    CheckResult,
    GatingDecision,
    GatingReport,
    NodeIdentity,
};

// ════════════════════════════════════════════════════════════════════════════════
// REPORT GENERATOR
// ════════════════════════════════════════════════════════════════════════════════

/// Stateless generator for gating audit reports.
///
/// `ReportGenerator` is a zero-sized type with no fields. All methods
/// are associated functions that operate purely on their inputs.
///
/// ## Usage
///
/// ```ignore
/// let report = ReportGenerator::generate(&identity, decision, checks, timestamp);
/// let table = ReportGenerator::to_table(&report);
/// let json = ReportGenerator::to_json(&report);
/// ```
pub struct ReportGenerator;

impl ReportGenerator {
    /// Generate a [`GatingReport`] from evaluation outputs.
    ///
    /// All inputs are copied or moved into the report without
    /// transformation. The check order is preserved exactly as
    /// provided. The decision is stored as-is — no re-evaluation
    /// or consistency check is performed by this method.
    ///
    /// ## Arguments
    ///
    /// - `identity`: The evaluated node's identity. Cloned into the
    ///   report (the original is not consumed).
    /// - `decision`: The final gating decision (`Approved` or `Rejected`).
    ///   Moved into the report.
    /// - `checks`: Ordered list of individual check results. Moved
    ///   into the report. Order is preserved exactly.
    /// - `timestamp`: Unix timestamp (seconds) of the evaluation.
    ///   Stored as-is, not validated or transformed.
    ///
    /// ## Returns
    ///
    /// A `GatingReport` containing all provided data. The
    /// `evaluated_by` field is set to `"ReportGenerator"`.
    ///
    /// ## Properties
    ///
    /// - Deterministic: same inputs → identical `GatingReport`.
    /// - No panic, no unwrap, no I/O.
    /// - `identity` is cloned; `decision` and `checks` are moved.
    #[must_use]
    pub fn generate(
        identity: &NodeIdentity,
        decision: GatingDecision,
        checks: Vec<CheckResult>,
        timestamp: u64,
    ) -> GatingReport {
        GatingReport {
            node_identity: identity.clone(),
            decision,
            checks,
            timestamp,
            evaluated_by: String::from("ReportGenerator"),
        }
    }

    /// Render a [`GatingReport`] as a human-readable table.
    ///
    /// The table has fixed-width columns and deterministic output.
    /// It contains:
    ///
    /// 1. Header with identity summary (hex prefix, no private data).
    /// 2. Timestamp.
    /// 3. Per-check rows: name, pass/fail, detail.
    /// 4. Final decision line.
    /// 5. Error details (if `Rejected`).
    ///
    /// ## Determinism
    ///
    /// - Column widths are computed from the report data (not random).
    /// - Check order matches `report.checks` exactly.
    /// - Error order matches `decision.errors()` exactly.
    /// - No environment dependency, no system clock, no randomness.
    ///
    /// ## Properties
    ///
    /// - No panic, no unwrap.
    /// - Uses `write!` to `String` which is infallible.
    /// - Returns owned `String`.
    #[must_use]
    pub fn to_table(report: &GatingReport) -> String {
        let mut out = String::new();

        // ── Identity & Timestamp ──────────────────────────────────────
        let identity_display = format!("{}", report.node_identity);
        let _ = writeln!(out, "Gating Report");
        let _ = writeln!(out, "═══════════════════════════════════════════════════");
        let _ = writeln!(out, "  Identity  : {identity_display}");
        let _ = writeln!(out, "  Timestamp : {}", report.timestamp);
        let _ = writeln!(out, "  Evaluated : {}", report.evaluated_by);
        let _ = writeln!(out, "═══════════════════════════════════════════════════");

        // ── Checks Table ──────────────────────────────────────────────
        // Compute column widths for deterministic alignment.
        // Minimum widths: name=10, status=6, detail=6.
        let name_width = report
            .checks
            .iter()
            .map(|c| c.check_name.len())
            .max()
            .unwrap_or(0)
            .max(10);

        let detail_width = report
            .checks
            .iter()
            .map(|c| {
                c.detail
                    .as_ref()
                    .map_or(1, |d| d.len())
            })
            .max()
            .unwrap_or(0)
            .max(6);

        // Header
        let _ = writeln!(
            out,
            "  {:<name_width$}  {:<6}  {:<detail_width$}",
            "Check", "Status", "Detail",
            name_width = name_width,
            detail_width = detail_width,
        );

        // Separator
        let _ = writeln!(
            out,
            "  {:-<name_width$}  {:-<6}  {:-<detail_width$}",
            "", "", "",
            name_width = name_width,
            detail_width = detail_width,
        );

        // Check rows
        for check in &report.checks {
            let status = if check.passed { "PASS" } else { "FAIL" };
            let detail = check
                .detail
                .as_deref()
                .unwrap_or("-");

            let _ = writeln!(
                out,
                "  {:<name_width$}  {:<6}  {:<detail_width$}",
                check.check_name,
                status,
                detail,
                name_width = name_width,
                detail_width = detail_width,
            );
        }

        if report.checks.is_empty() {
            let _ = writeln!(out, "  (no checks executed)");
        }

        let _ = writeln!(out, "═══════════════════════════════════════════════════");

        // ── Decision ──────────────────────────────────────────────────
        let decision_label = if report.decision.is_approved() {
            "APPROVED"
        } else {
            "REJECTED"
        };
        let _ = writeln!(out, "  Decision  : {decision_label}");

        // ── Error Details (Rejected only) ─────────────────────────────
        let errors = report.decision.errors();
        if !errors.is_empty() {
            let _ = writeln!(out, "───────────────────────────────────────────────────");
            let _ = writeln!(out, "  Errors ({}):", errors.len());
            for (i, err) in errors.iter().enumerate() {
                let _ = writeln!(out, "    {}. {}", i + 1, err);
            }
        }

        let _ = writeln!(out, "═══════════════════════════════════════════════════");

        out
    }

    /// Render a [`GatingReport`] as a JSON string.
    ///
    /// Serializes the entire `GatingReport` struct via `serde_json`.
    /// No fields are omitted, transformed, or reordered beyond what
    /// `serde_json` produces for the struct's derive order.
    ///
    /// ## Determinism
    ///
    /// `serde_json::to_string` produces deterministic output for the
    /// same input when the struct derives `Serialize` (field order is
    /// declaration order, which is fixed).
    ///
    /// ## Error Handling
    ///
    /// `GatingReport` and all its transitive fields derive `Serialize`.
    /// Serialization of value types (`String`, `u64`, `bool`, `Vec`,
    /// `Option`, enums) never fails in `serde_json`. Therefore,
    /// `serde_json::to_string` is guaranteed to succeed for this input.
    ///
    /// In the theoretical case of a serialization failure (e.g., a
    /// future serde_json bug), a valid JSON error object is returned
    /// instead of panicking.
    ///
    /// ## Properties
    ///
    /// - Always returns valid JSON.
    /// - No panic, no unwrap.
    /// - Deterministic for the same input.
    /// - No fields silently omitted.
    #[must_use]
    pub fn to_json(report: &GatingReport) -> String {
        match serde_json::to_string(report) {
            Ok(json) => json,
            Err(e) => {
                // This branch is unreachable for GatingReport (all fields
                // are infallibly serializable). Included for safety — no
                // panic, no silent failure. Returns valid JSON with error.
                format!(
                    r#"{{"error":"serialization_failed","detail":"{}"}}"#,
                    e
                )
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use dsdn_common::gating::GatingError;

    // ── Helpers ───────────────────────────────────────────────────────

    /// Creates a minimal `NodeIdentity` with deterministic bytes.
    fn make_identity() -> NodeIdentity {
        NodeIdentity {
            node_id: [0xAB; 32],
            operator_address: [0xCD; 20],
            tls_cert_fingerprint: [0xEF; 32],
        }
    }

    /// Creates a zero-identity (all bytes 0x00).
    fn make_zero_identity() -> NodeIdentity {
        NodeIdentity {
            node_id: [0x00; 32],
            operator_address: [0x00; 20],
            tls_cert_fingerprint: [0x00; 32],
        }
    }

    /// Creates a `CheckResult`.
    fn make_check(name: &str, passed: bool, detail: Option<&str>) -> CheckResult {
        CheckResult {
            check_name: name.to_string(),
            passed,
            detail: detail.map(|s| s.to_string()),
        }
    }

    // ══════════════════════════════════════════════════════════════════
    // generate() — BASIC
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn test_generate_approved_basic() {
        let identity = make_identity();
        let checks = vec![
            make_check("stake_check", true, None),
            make_check("tls_validation", true, Some("cert valid")),
        ];
        let report = ReportGenerator::generate(
            &identity,
            GatingDecision::Approved,
            checks.clone(),
            1_700_000_000,
        );

        assert_eq!(report.node_identity, identity);
        assert!(report.decision.is_approved());
        assert_eq!(report.checks.len(), 2);
        assert_eq!(report.checks[0].check_name, "stake_check");
        assert_eq!(report.checks[1].check_name, "tls_validation");
        assert_eq!(report.timestamp, 1_700_000_000);
        assert_eq!(report.evaluated_by, "ReportGenerator");
    }

    #[test]
    fn test_generate_rejected_basic() {
        let identity = make_identity();
        let checks = vec![
            make_check("stake_check", false, Some("insufficient stake")),
        ];
        let errors = vec![GatingError::ZeroStake];
        let report = ReportGenerator::generate(
            &identity,
            GatingDecision::Rejected(errors.clone()),
            checks,
            1_700_000_000,
        );

        assert!(!report.decision.is_approved());
        assert_eq!(report.decision.errors().len(), 1);
        assert_eq!(report.decision.errors()[0], GatingError::ZeroStake);
    }

    #[test]
    fn test_generate_preserves_check_order() {
        let identity = make_identity();
        let checks = vec![
            make_check("alpha", true, None),
            make_check("beta", false, Some("fail")),
            make_check("gamma", true, Some("ok")),
            make_check("delta", false, Some("error")),
        ];
        let report = ReportGenerator::generate(
            &identity,
            GatingDecision::Approved,
            checks,
            100,
        );

        assert_eq!(report.checks[0].check_name, "alpha");
        assert_eq!(report.checks[1].check_name, "beta");
        assert_eq!(report.checks[2].check_name, "gamma");
        assert_eq!(report.checks[3].check_name, "delta");
    }

    #[test]
    fn test_generate_timestamp_stored_as_is() {
        let identity = make_identity();
        // Edge: zero timestamp
        let report = ReportGenerator::generate(
            &identity,
            GatingDecision::Approved,
            vec![],
            0,
        );
        assert_eq!(report.timestamp, 0);

        // Edge: max timestamp
        let report = ReportGenerator::generate(
            &identity,
            GatingDecision::Approved,
            vec![],
            u64::MAX,
        );
        assert_eq!(report.timestamp, u64::MAX);
    }

    #[test]
    fn test_generate_identity_cloned() {
        let identity = make_identity();
        let report = ReportGenerator::generate(
            &identity,
            GatingDecision::Approved,
            vec![],
            100,
        );
        // Original identity is not consumed and matches report.
        assert_eq!(report.node_identity, identity);
    }

    // ══════════════════════════════════════════════════════════════════
    // generate() — EDGE CASES
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn test_generate_empty_checks() {
        let identity = make_identity();
        let report = ReportGenerator::generate(
            &identity,
            GatingDecision::Approved,
            vec![],
            100,
        );
        assert!(report.checks.is_empty());
        assert!(report.decision.is_approved());
    }

    #[test]
    fn test_generate_approved_empty_checks() {
        // Valid scenario: permissive policy with no checks.
        let identity = make_zero_identity();
        let report = ReportGenerator::generate(
            &identity,
            GatingDecision::Approved,
            vec![],
            0,
        );
        assert!(report.decision.is_approved());
        assert!(report.checks.is_empty());
    }

    #[test]
    fn test_generate_rejected_many_errors() {
        let identity = make_identity();
        let checks = vec![
            make_check("stake", false, Some("zero")),
            make_check("class", false, Some("invalid")),
            make_check("tls", false, Some("expired")),
            make_check("cooldown", false, Some("active")),
        ];
        let errors = vec![
            GatingError::ZeroStake,
            GatingError::InvalidNodeClass("overclaimed".to_string()),
            GatingError::NodeNotRegistered,
            GatingError::NodeBanned { until_timestamp: 999 },
        ];
        let report = ReportGenerator::generate(
            &identity,
            GatingDecision::Rejected(errors),
            checks,
            500,
        );

        assert_eq!(report.decision.errors().len(), 4);
        assert_eq!(report.checks.len(), 4);
    }

    #[test]
    fn test_generate_zero_identity() {
        let identity = make_zero_identity();
        let report = ReportGenerator::generate(
            &identity,
            GatingDecision::Approved,
            vec![make_check("test", true, None)],
            100,
        );
        assert_eq!(report.node_identity.node_id, [0x00; 32]);
        assert_eq!(report.node_identity.operator_address, [0x00; 20]);
    }

    // ══════════════════════════════════════════════════════════════════
    // generate() — DETERMINISM
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn test_generate_deterministic() {
        let identity = make_identity();
        let checks1 = vec![
            make_check("a", true, Some("ok")),
            make_check("b", false, Some("fail")),
        ];
        let checks2 = vec![
            make_check("a", true, Some("ok")),
            make_check("b", false, Some("fail")),
        ];
        let r1 = ReportGenerator::generate(
            &identity,
            GatingDecision::Approved,
            checks1,
            100,
        );
        let r2 = ReportGenerator::generate(
            &identity,
            GatingDecision::Approved,
            checks2,
            100,
        );
        assert_eq!(r1, r2);
    }

    // ══════════════════════════════════════════════════════════════════
    // to_table() — BASIC
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn test_to_table_approved() {
        let identity = make_identity();
        let report = ReportGenerator::generate(
            &identity,
            GatingDecision::Approved,
            vec![
                make_check("stake_check", true, Some("5000 >= 5000")),
                make_check("tls_validation", true, Some("cert valid")),
            ],
            1_700_000_000,
        );
        let table = ReportGenerator::to_table(&report);

        assert!(table.contains("Gating Report"));
        assert!(table.contains("APPROVED"));
        assert!(table.contains("stake_check"));
        assert!(table.contains("tls_validation"));
        assert!(table.contains("PASS"));
        assert!(table.contains("1700000000"));
        // Identity display uses hex prefix
        assert!(table.contains("abababab"));
    }

    #[test]
    fn test_to_table_rejected_with_errors() {
        let identity = make_identity();
        let report = ReportGenerator::generate(
            &identity,
            GatingDecision::Rejected(vec![GatingError::ZeroStake]),
            vec![make_check("stake_check", false, Some("zero stake"))],
            100,
        );
        let table = ReportGenerator::to_table(&report);

        assert!(table.contains("REJECTED"));
        assert!(table.contains("FAIL"));
        assert!(table.contains("zero stake"));
        assert!(table.contains("Errors (1)"));
    }

    #[test]
    fn test_to_table_empty_checks() {
        let identity = make_identity();
        let report = ReportGenerator::generate(
            &identity,
            GatingDecision::Approved,
            vec![],
            100,
        );
        let table = ReportGenerator::to_table(&report);

        assert!(table.contains("no checks executed"));
        assert!(table.contains("APPROVED"));
    }

    #[test]
    fn test_to_table_check_detail_none() {
        let identity = make_identity();
        let report = ReportGenerator::generate(
            &identity,
            GatingDecision::Approved,
            vec![make_check("test", true, None)],
            100,
        );
        let table = ReportGenerator::to_table(&report);

        // None detail renders as "-"
        assert!(table.contains("-"));
        assert!(table.contains("PASS"));
    }

    // ══════════════════════════════════════════════════════════════════
    // to_table() — DETERMINISM
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn test_to_table_deterministic() {
        let identity = make_identity();
        let r1 = ReportGenerator::generate(
            &identity,
            GatingDecision::Approved,
            vec![make_check("a", true, Some("ok"))],
            100,
        );
        let r2 = ReportGenerator::generate(
            &identity,
            GatingDecision::Approved,
            vec![make_check("a", true, Some("ok"))],
            100,
        );
        let t1 = ReportGenerator::to_table(&r1);
        let t2 = ReportGenerator::to_table(&r2);
        assert_eq!(t1, t2);
    }

    // ══════════════════════════════════════════════════════════════════
    // to_json() — BASIC
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn test_to_json_approved() {
        let identity = make_identity();
        let report = ReportGenerator::generate(
            &identity,
            GatingDecision::Approved,
            vec![make_check("stake", true, None)],
            1_700_000_000,
        );
        let json = ReportGenerator::to_json(&report);

        // Must be valid JSON
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("must be valid JSON");
        assert!(parsed.is_object());

        // Must contain expected fields
        assert!(json.contains("Approved"));
        assert!(json.contains("stake"));
        assert!(json.contains("1700000000"));
    }

    #[test]
    fn test_to_json_rejected() {
        let identity = make_identity();
        let report = ReportGenerator::generate(
            &identity,
            GatingDecision::Rejected(vec![GatingError::ZeroStake]),
            vec![make_check("stake", false, Some("zero"))],
            100,
        );
        let json = ReportGenerator::to_json(&report);

        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("must be valid JSON");
        assert!(parsed.is_object());
        assert!(json.contains("Rejected"));
        assert!(json.contains("ZeroStake"));
    }

    #[test]
    fn test_to_json_roundtrip() {
        let identity = make_identity();
        let report = ReportGenerator::generate(
            &identity,
            GatingDecision::Approved,
            vec![
                make_check("a", true, Some("ok")),
                make_check("b", false, Some("fail")),
            ],
            999,
        );
        let json = ReportGenerator::to_json(&report);
        let back: GatingReport =
            serde_json::from_str(&json).expect("roundtrip must succeed");
        assert_eq!(report, back);
    }

    #[test]
    fn test_to_json_roundtrip_rejected() {
        let identity = make_identity();
        let report = ReportGenerator::generate(
            &identity,
            GatingDecision::Rejected(vec![
                GatingError::ZeroStake,
                GatingError::NodeNotRegistered,
            ]),
            vec![
                make_check("stake", false, Some("zero")),
                make_check("reg", false, Some("not found")),
            ],
            500,
        );
        let json = ReportGenerator::to_json(&report);
        let back: GatingReport =
            serde_json::from_str(&json).expect("roundtrip must succeed");
        assert_eq!(report, back);
    }

    #[test]
    fn test_to_json_empty_checks() {
        let identity = make_identity();
        let report = ReportGenerator::generate(
            &identity,
            GatingDecision::Approved,
            vec![],
            0,
        );
        let json = ReportGenerator::to_json(&report);
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("must be valid JSON");

        // checks field must be present as empty array
        let checks = parsed.get("checks").expect("checks field must exist");
        assert!(checks.is_array());
        assert_eq!(checks.as_array().expect("is array").len(), 0);
    }

    // ══════════════════════════════════════════════════════════════════
    // to_json() — DETERMINISM
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn test_to_json_deterministic() {
        let identity = make_identity();
        let r1 = ReportGenerator::generate(
            &identity,
            GatingDecision::Approved,
            vec![make_check("a", true, Some("ok"))],
            100,
        );
        let r2 = ReportGenerator::generate(
            &identity,
            GatingDecision::Approved,
            vec![make_check("a", true, Some("ok"))],
            100,
        );
        let j1 = ReportGenerator::to_json(&r1);
        let j2 = ReportGenerator::to_json(&r2);
        assert_eq!(j1, j2);
    }

    // ══════════════════════════════════════════════════════════════════
    // to_json() — NO FIELD OMISSION
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn test_to_json_all_fields_present() {
        let identity = make_identity();
        let report = ReportGenerator::generate(
            &identity,
            GatingDecision::Approved,
            vec![make_check("test", true, None)],
            100,
        );
        let json = ReportGenerator::to_json(&report);
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("valid JSON");

        // All GatingReport fields must be present
        assert!(parsed.get("node_identity").is_some(), "node_identity missing");
        assert!(parsed.get("decision").is_some(), "decision missing");
        assert!(parsed.get("checks").is_some(), "checks missing");
        assert!(parsed.get("timestamp").is_some(), "timestamp missing");
        assert!(parsed.get("evaluated_by").is_some(), "evaluated_by missing");
    }

    #[test]
    fn test_to_json_check_fields_present() {
        let identity = make_identity();
        let report = ReportGenerator::generate(
            &identity,
            GatingDecision::Approved,
            vec![make_check("test", true, Some("detail"))],
            100,
        );
        let json = ReportGenerator::to_json(&report);
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("valid JSON");

        let checks = parsed.get("checks").expect("checks");
        let first = &checks.as_array().expect("array")[0];
        assert!(first.get("check_name").is_some(), "check_name missing");
        assert!(first.get("passed").is_some(), "passed missing");
        assert!(first.get("detail").is_some(), "detail missing");
    }

    // ══════════════════════════════════════════════════════════════════
    // TRAIT TESTS
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn test_report_generator_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ReportGenerator>();
    }

    #[test]
    fn test_report_generator_zero_size() {
        assert_eq!(std::mem::size_of::<ReportGenerator>(), 0);
    }

    // ══════════════════════════════════════════════════════════════════
    // EDGE: REJECTED WITH MANY ERRORS
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn test_to_table_many_errors() {
        let identity = make_identity();
        let errors: Vec<GatingError> = (0..10)
            .map(|i| GatingError::NodeBanned { until_timestamp: i })
            .collect();
        let checks: Vec<CheckResult> = (0..10)
            .map(|i| make_check(&format!("check_{i}"), false, Some(&format!("err_{i}"))))
            .collect();
        let report = ReportGenerator::generate(
            &identity,
            GatingDecision::Rejected(errors),
            checks,
            100,
        );
        let table = ReportGenerator::to_table(&report);

        assert!(table.contains("REJECTED"));
        assert!(table.contains("Errors (10)"));
        assert!(table.contains("check_0"));
        assert!(table.contains("check_9"));
    }

    #[test]
    fn test_to_json_many_errors_roundtrip() {
        let identity = make_identity();
        let errors: Vec<GatingError> = (0..10)
            .map(|i| GatingError::NodeBanned { until_timestamp: i })
            .collect();
        let checks: Vec<CheckResult> = (0..10)
            .map(|i| make_check(&format!("check_{i}"), false, Some(&format!("err_{i}"))))
            .collect();
        let report = ReportGenerator::generate(
            &identity,
            GatingDecision::Rejected(errors),
            checks,
            100,
        );
        let json = ReportGenerator::to_json(&report);
        let back: GatingReport =
            serde_json::from_str(&json).expect("roundtrip must succeed");
        assert_eq!(report, back);
    }

    // ══════════════════════════════════════════════════════════════════
    // EDGE: ZERO IDENTITY
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn test_to_table_zero_identity() {
        let identity = make_zero_identity();
        let report = ReportGenerator::generate(
            &identity,
            GatingDecision::Approved,
            vec![],
            0,
        );
        let table = ReportGenerator::to_table(&report);

        // Zero identity renders hex prefix as 00000000
        assert!(table.contains("00000000"));
    }

    #[test]
    fn test_to_json_zero_identity_roundtrip() {
        let identity = make_zero_identity();
        let report = ReportGenerator::generate(
            &identity,
            GatingDecision::Approved,
            vec![],
            0,
        );
        let json = ReportGenerator::to_json(&report);
        let back: GatingReport =
            serde_json::from_str(&json).expect("roundtrip");
        assert_eq!(report, back);
    }
}