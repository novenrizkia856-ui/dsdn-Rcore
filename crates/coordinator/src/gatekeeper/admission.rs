//! # Node Admission Filter (14B.32)
//!
//! Provides [`AdmissionRequest`], [`AdmissionResponse`], and the
//! [`GateKeeper::process_admission`] method for evaluating service node
//! join requests against the gating engine.
//!
//! ## Admission Flow
//!
//! 1. Caller constructs an [`AdmissionRequest`] with the node's identity,
//!    claimed class, identity proof, and TLS certificate info.
//! 2. [`GateKeeper::process_admission`] runs the full [`GatingEngine`]
//!    evaluation pipeline (stake → class → identity → TLS → cooldown).
//! 3. A [`GatingReport`] is generated for audit trail.
//! 4. If approved, the node is inserted into the local registry with
//!    status `Pending` (or `Active` if `auto_activate_on_pass` is set).
//! 5. If rejected due to identity spoof, `assigned_status` is `Banned`.
//!
//! ## Determinism
//!
//! All logic is deterministic: same inputs produce identical outputs.
//! No system clock, no randomness, no network I/O.
//!
//! ## Safety
//!
//! - No `panic!`, `unwrap()`, `expect()`.
//! - No silent failure — every path produces a complete response.
//! - Registry updates are atomic (single `HashMap::insert`).

use dsdn_common::gating::{
    CheckResult, CooldownPeriod, GatingDecision, GatingError,
    NodeClass, NodeIdentity, NodeRegistryEntry, NodeStatus,
    IdentityProof, TLSCertInfo,
};
use dsdn_validator::gating::report::ReportGenerator;
use dsdn_validator::gating::GatingEngine;

use super::GateKeeper;

// ════════════════════════════════════════════════════════════════════════════════
// REQUEST / RESPONSE TYPES
// ════════════════════════════════════════════════════════════════════════════════

/// A node join request submitted for admission evaluation.
///
/// Contains all information required by the [`GatingEngine`] to perform
/// a full admission check. The caller is responsible for sourcing these
/// values (e.g., from a network handshake or RPC submission).
#[derive(Clone, Debug)]
pub struct AdmissionRequest {
    /// The node's cryptographic identity (Ed25519 pubkey + operator + TLS fingerprint).
    pub identity: NodeIdentity,
    /// The node class the applicant claims to qualify for.
    pub claimed_class: NodeClass,
    /// Ed25519 identity proof (challenge-response signature).
    pub identity_proof: IdentityProof,
    /// TLS certificate metadata for secure channel verification.
    pub tls_cert_info: TLSCertInfo,
}

/// The result of an admission evaluation.
///
/// Contains the boolean verdict, the full [`GatingDecision`] (with error
/// details if rejected), the assigned [`NodeStatus`], and a complete
/// [`GatingReport`] for audit purposes.
#[derive(Clone, Debug)]
pub struct AdmissionResponse {
    /// `true` if the node passed all gating checks.
    pub approved: bool,
    /// The full gating decision (Approved or Rejected with error list).
    pub decision: GatingDecision,
    /// The status assigned to the node after evaluation:
    /// - Approved + auto_activate_on_pass → `Active`
    /// - Approved (default) → `Pending`
    /// - Rejected (identity spoof) → `Banned`
    /// - Rejected (other) → `Pending` (safe default, node not inserted)
    pub assigned_status: NodeStatus,
    /// Complete audit report capturing identity, decision, checks, timestamp.
    pub report: dsdn_common::gating::GatingReport,
}

// ════════════════════════════════════════════════════════════════════════════════
// GATEKEEPER ADMISSION METHODS
// ════════════════════════════════════════════════════════════════════════════════

impl GateKeeper {
    /// Evaluates a node join request against the full gating pipeline.
    ///
    /// ## Parameters
    ///
    /// - `request`: The admission request containing identity, class, proof, and TLS info.
    /// - `stake`: The node's current on-chain stake (caller-provided, not fetched).
    /// - `slashing_status`: Optional active cooldown period (caller-provided).
    /// - `current_timestamp`: Unix timestamp in seconds for this evaluation.
    ///   Used by TLS validity checks, cooldown checks, report generation,
    ///   and registry timestamps. No system clock is accessed internally.
    ///
    /// ## Evaluation Steps
    ///
    /// 1. Reconstruct [`GatingEngine`] with `current_timestamp` for time-sensitive checks.
    /// 2. Run `engine.evaluate()` — all checks execute (no short-circuit).
    /// 3. Derive [`CheckResult`] entries from the decision for the audit report.
    /// 4. Generate [`GatingReport`] via [`ReportGenerator`].
    /// 5. If approved: insert [`NodeRegistryEntry`] into local registry.
    /// 6. If rejected: do NOT modify registry.
    ///
    /// ## Determinism
    ///
    /// Same `(request, stake, slashing_status, current_timestamp)` always
    /// produces the same `AdmissionResponse`. No side effects beyond
    /// the local registry update on approval.
    ///
    /// ## Registry Key
    ///
    /// Nodes are keyed by the lowercase hex encoding of `identity.node_id`
    /// (64-character string for 32-byte key). An existing entry with the
    /// same key will be overwritten on re-admission (intentional: allows
    /// re-registration after ban expiry or status reset).
    pub fn process_admission(
        &mut self,
        request: AdmissionRequest,
        stake: u128,
        slashing_status: Option<CooldownPeriod>,
        current_timestamp: u64,
    ) -> AdmissionResponse {
        // Step 1: Rebuild engine with correct timestamp for this evaluation.
        // The engine is stateless — reconstructing it is safe and deterministic.
        self.gating_engine = GatingEngine::new(
            self.config.policy.clone(),
            current_timestamp,
        );

        // Step 2: Run the full gating evaluation pipeline.
        // Order: Stake → Class → Identity → TLS → Cooldown (consensus-critical).
        // All checks run; no short-circuit on first error.
        let decision = self.gating_engine.evaluate(
            &request.identity,
            &request.claimed_class,
            stake,
            slashing_status.as_ref(),
            Some(&request.tls_cert_info),
            Some(&request.identity_proof),
        );

        // Step 3: Derive check results from the decision for the report.
        let checks = derive_checks_from_decision(&decision);

        // Step 4: Generate the audit report.
        let report = ReportGenerator::generate(
            &request.identity,
            decision.clone(),
            checks,
            current_timestamp,
        );

        // Step 5: Determine approval, status, and registry update.
        match &decision {
            GatingDecision::Approved => {
                let status = if self.config.auto_activate_on_pass {
                    NodeStatus::Active
                } else {
                    NodeStatus::Pending
                };

                // Insert into local registry (single atomic insertion).
                let node_id_hex = node_id_to_hex(&request.identity.node_id);
                let entry = NodeRegistryEntry {
                    identity: request.identity,
                    class: request.claimed_class,
                    status: status.clone(),
                    stake,
                    registered_at: current_timestamp,
                    last_status_change: current_timestamp,
                    cooldown: slashing_status,
                    tls_info: Some(request.tls_cert_info),
                };
                self.registry.insert(node_id_hex, entry);

                AdmissionResponse {
                    approved: true,
                    decision,
                    assigned_status: status,
                    report,
                }
            }
            GatingDecision::Rejected(errors) => {
                // Do NOT insert into registry on rejection.
                let assigned_status = if is_identity_spoof(errors) {
                    // Identity spoof: binding/signature verification failed.
                    NodeStatus::Banned
                } else {
                    // Non-spoof rejection: safe default status.
                    // Node is not inserted — this status is informational only.
                    NodeStatus::Pending
                };

                AdmissionResponse {
                    approved: false,
                    decision,
                    assigned_status,
                    report,
                }
            }
        }
    }

    /// Checks whether a node is currently in the local registry.
    ///
    /// Performs a deterministic lookup by converting the 32-byte node ID
    /// to a lowercase hex string and checking the registry HashMap.
    ///
    /// ## Returns
    ///
    /// `true` if the node ID exists as a key in the registry, `false` otherwise.
    pub fn is_node_registered(&self, node_id: &[u8; 32]) -> bool {
        let hex = node_id_to_hex(node_id);
        self.registry.contains_key(&hex)
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS (module-private)
// ════════════════════════════════════════════════════════════════════════════════

/// Determines whether any errors indicate identity spoofing.
///
/// Identity spoof is defined as:
/// - `IdentityVerificationFailed`: Ed25519 signature verification failed.
/// - `IdentityMismatch`: Node ID does not match operator binding.
///
/// Both indicate the node is not who it claims to be.
fn is_identity_spoof(errors: &[GatingError]) -> bool {
    errors.iter().any(|e| {
        matches!(
            e,
            GatingError::IdentityVerificationFailed(_) | GatingError::IdentityMismatch { .. }
        )
    })
}

/// Converts a 32-byte node ID to a lowercase hex string (64 characters).
///
/// Used as the registry HashMap key. Deterministic: same bytes always
/// produce the same string.
fn node_id_to_hex(node_id: &[u8; 32]) -> String {
    node_id.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Derives [`CheckResult`] entries from a [`GatingDecision`] for report generation.
///
/// - `Approved`: Single check result indicating all checks passed.
/// - `Rejected`: One check result per error, labeled by check type.
///
/// This provides audit-friendly check records without requiring access
/// to the engine's internal per-verifier results.
fn derive_checks_from_decision(decision: &GatingDecision) -> Vec<CheckResult> {
    match decision {
        GatingDecision::Approved => {
            vec![CheckResult {
                check_name: String::from("admission_evaluation"),
                passed: true,
                detail: Some(String::from("all gating checks passed")),
            }]
        }
        GatingDecision::Rejected(errors) => {
            errors
                .iter()
                .map(|error| CheckResult {
                    check_name: String::from(error_to_check_name(error)),
                    passed: false,
                    detail: Some(format!("{:?}", error)),
                })
                .collect()
        }
    }
}

/// Maps a [`GatingError`] variant to its corresponding check name string.
///
/// Used by [`derive_checks_from_decision`] to label check results consistently
/// with the naming conventions used by individual verifiers.
fn error_to_check_name(error: &GatingError) -> &'static str {
    match error {
        GatingError::ZeroStake | GatingError::InsufficientStake { .. } => "stake_check",
        GatingError::IdentityVerificationFailed(_) => "identity_proof",
        GatingError::IdentityMismatch { .. } => "identity_binding",
        GatingError::TLSInvalid(_) => "tls_check",
        GatingError::SlashingCooldownActive { .. } => "cooldown_check",
        GatingError::NodeBanned { .. } => "ban_check",
        GatingError::NodeQuarantined { .. } => "quarantine_check",
        GatingError::NodeNotRegistered => "registration_check",
        // Catch-all for variants not explicitly listed (e.g., InvalidNodeClass).
        // Uses a generic label to maintain forward compatibility.
        _ => "gating_check",
    }
}