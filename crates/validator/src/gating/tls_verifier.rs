//! # TLS Verifier (14B.23)
//!
//! Verifier for TLS certificate validity, fingerprint binding, and
//! subject CN presence in the DSDN gating system.
//!
//! ## Design
//!
//! `TLSVerifier` holds a single `current_timestamp` field. It does NOT
//! access system clocks — the timestamp is provided at construction.
//! All verification logic is deterministic for the same inputs.
//!
//! ## Verification Logic (`verify`)
//!
//! 1. **Time validity**: `tls_info.is_valid_at(current_timestamp)`
//!    - If expired (`timestamp > not_after`) → `TLSInvalid(Expired)`
//!    - If not yet valid (`timestamp < not_before`) → `TLSInvalid(NotYetValid)`
//! 2. **Fingerprint match**: `tls_info.matches_identity(identity)`
//!    - If mismatch → `TLSInvalid(FingerprintMismatch)`
//! 3. **Subject CN**: Must be non-empty after trimming whitespace.
//!    - If empty → `TLSInvalid(EmptySubject)`
//! 4. All checks pass → `Ok(CheckResult { passed: true, .. })`
//!
//! ## Static Method (`verify_fingerprint`)
//!
//! Computes SHA-256 of DER bytes and compares against expected fingerprint.
//! Uses constant-time comparison via `[u8; 32]` equality.
//!
//! ## Properties
//!
//! - **Deterministic**: Same inputs always produce the same output.
//! - **No panic**: No `unwrap()`, `expect()`, or index access.
//! - **No system clock**: Timestamp is an explicit field, set at construction.

use dsdn_common::gating::{
    CheckResult,
    GatingError,
    NodeIdentity,
    TLSCertInfo,
    TLSValidationError,
};

// ════════════════════════════════════════════════════════════════════════════
// TLS VERIFIER
// ════════════════════════════════════════════════════════════════════════════

/// TLS certificate verifier for gating.
///
/// `TLSVerifier` holds a `current_timestamp` used for time-based validity
/// checks. It does NOT access system clocks — the timestamp is provided
/// at construction and never modified.
///
/// ## Usage
///
/// ```rust,ignore
/// use dsdn_validator::gating::TLSVerifier;
///
/// let verifier = TLSVerifier::new(1_700_000_000);
/// let result = verifier.verify(&tls_info, &identity);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TLSVerifier {
    /// Unix timestamp (seconds) for time-based validity checks.
    /// Provided at construction, never derived from system clock.
    current_timestamp: u64,
}

impl TLSVerifier {
    /// Creates a new `TLSVerifier` with the given timestamp.
    ///
    /// The timestamp is stored immutably and used for all subsequent
    /// `verify()` calls. It is NEVER derived from the system clock.
    #[must_use]
    #[inline]
    pub fn new(current_timestamp: u64) -> Self {
        Self { current_timestamp }
    }

    /// Returns the timestamp used by this verifier.
    #[must_use]
    #[inline]
    pub fn current_timestamp(&self) -> u64 {
        self.current_timestamp
    }

    /// Verify a TLS certificate against a node identity.
    ///
    /// ## Execution Order (STRICT — DO NOT REORDER)
    ///
    /// 1. **Time validity**: `tls_info.is_valid_at(self.current_timestamp)`
    ///    - If `self.current_timestamp > tls_info.not_after` →
    ///      `Err(GatingError::TLSInvalid(TLSValidationError::Expired))`
    ///    - If `self.current_timestamp < tls_info.not_before` →
    ///      `Err(GatingError::TLSInvalid(TLSValidationError::NotYetValid))`
    /// 2. **Fingerprint match**: `tls_info.matches_identity(identity)`
    ///    - If false →
    ///      `Err(GatingError::TLSInvalid(TLSValidationError::FingerprintMismatch))`
    /// 3. **Subject CN**: `tls_info.subject_cn.trim()` must be non-empty.
    ///    - If empty →
    ///      `Err(GatingError::TLSInvalid(TLSValidationError::EmptySubject))`
    /// 4. All checks pass →
    ///    `Ok(CheckResult { check_name: "tls_check", passed: true, .. })`
    ///
    /// ## Properties
    ///
    /// - Deterministic for same `(tls_info, identity, current_timestamp)`.
    /// - No panic, no unwrap, no side effects.
    pub fn verify(
        &self,
        tls_info: &TLSCertInfo,
        identity: &NodeIdentity,
    ) -> Result<CheckResult, GatingError> {
        // CHECK 1: Time validity
        if !tls_info.is_valid_at(self.current_timestamp) {
            // Distinguish expired vs not-yet-valid for precise error
            if self.current_timestamp > tls_info.not_after {
                return Err(GatingError::TLSInvalid(TLSValidationError::Expired));
            } else {
                // self.current_timestamp < tls_info.not_before
                return Err(GatingError::TLSInvalid(TLSValidationError::NotYetValid));
            }
        }

        // CHECK 2: Fingerprint match
        if !tls_info.matches_identity(identity) {
            return Err(GatingError::TLSInvalid(
                TLSValidationError::FingerprintMismatch,
            ));
        }

        // CHECK 3: Subject CN non-empty (after trimming whitespace)
        if tls_info.subject_cn.trim().is_empty() {
            return Err(GatingError::TLSInvalid(TLSValidationError::EmptySubject));
        }

        // All checks passed
        Ok(CheckResult {
            check_name: "tls_check".to_string(),
            passed: true,
            detail: Some(format!(
                "TLS certificate valid: subject={}, fingerprint={}, valid at timestamp {}",
                tls_info.subject_cn,
                hex::encode(&tls_info.fingerprint[..4]),
                self.current_timestamp,
            )),
        })
    }

    /// Compute SHA-256 of DER bytes and compare against expected fingerprint.
    ///
    /// This is a **pure function** — stateless, deterministic, no side effects.
    /// Delegates hashing to `TLSCertInfo::compute_fingerprint`.
    ///
    /// ## Arguments
    ///
    /// * `cert_der` — Raw DER-encoded certificate bytes.
    /// * `expected` — Expected SHA-256 fingerprint (32 bytes).
    ///
    /// ## Returns
    ///
    /// `true` if `SHA-256(cert_der) == expected`, `false` otherwise.
    ///
    /// ## Note
    ///
    /// Empty `cert_der` is NOT rejected — SHA-256 of empty input is a
    /// well-defined value. The caller is responsible for rejecting empty
    /// DER data if that is a policy requirement.
    #[must_use]
    pub fn verify_fingerprint(cert_der: &[u8], expected: &[u8; 32]) -> bool {
        let computed = TLSCertInfo::compute_fingerprint(cert_der);
        computed == *expected
    }
}

// ════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ────────────────────────────────────────────────────────────
    // HELPERS
    // ────────────────────────────────────────────────────────────

    fn make_cert(fingerprint: [u8; 32]) -> TLSCertInfo {
        TLSCertInfo {
            fingerprint,
            subject_cn: "node.dsdn.example".to_string(),
            not_before: 1000,
            not_after: 2000,
            issuer: "DSDN Test CA".to_string(),
        }
    }

    fn make_identity(fingerprint: [u8; 32]) -> NodeIdentity {
        NodeIdentity {
            node_id: [0x01; 32],
            operator_address: [0x02; 20],
            tls_cert_fingerprint: fingerprint,
        }
    }

    fn matching_pair() -> (TLSCertInfo, NodeIdentity) {
        let fp = [0xAA; 32];
        (make_cert(fp), make_identity(fp))
    }

    // ════════════════════════════════════════════════════════════
    // verify — ALL CHECKS PASS
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_all_pass() {
        let (cert, identity) = matching_pair();
        let v = TLSVerifier::new(1500); // within [1000, 2000]
        let result = v.verify(&cert, &identity);
        assert!(result.is_ok());
        let cr = result.unwrap();
        assert_eq!(cr.check_name, "tls_check");
        assert!(cr.passed);
        assert!(cr.detail.is_some());
    }

    #[test]
    fn test_verify_at_not_before_boundary() {
        let (cert, identity) = matching_pair();
        let v = TLSVerifier::new(1000); // exactly not_before (inclusive)
        let result = v.verify(&cert, &identity);
        assert!(result.is_ok());
        assert!(result.unwrap().passed);
    }

    #[test]
    fn test_verify_at_not_after_boundary() {
        let (cert, identity) = matching_pair();
        let v = TLSVerifier::new(2000); // exactly not_after (inclusive)
        let result = v.verify(&cert, &identity);
        assert!(result.is_ok());
        assert!(result.unwrap().passed);
    }

    #[test]
    fn test_verify_deterministic() {
        let (cert, identity) = matching_pair();
        let v = TLSVerifier::new(1500);
        let r1 = v.verify(&cert, &identity);
        let r2 = v.verify(&cert, &identity);
        assert_eq!(r1, r2);
    }

    // ════════════════════════════════════════════════════════════
    // verify — CHECK 1: TIME VALIDITY
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_expired() {
        let (cert, identity) = matching_pair();
        let v = TLSVerifier::new(2001); // past not_after
        let result = v.verify(&cert, &identity);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            GatingError::TLSInvalid(TLSValidationError::Expired)
        );
    }

    #[test]
    fn test_verify_not_yet_valid() {
        let (cert, identity) = matching_pair();
        let v = TLSVerifier::new(999); // before not_before
        let result = v.verify(&cert, &identity);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            GatingError::TLSInvalid(TLSValidationError::NotYetValid)
        );
    }

    #[test]
    fn test_verify_expired_far_future() {
        let (cert, identity) = matching_pair();
        let v = TLSVerifier::new(u64::MAX);
        let result = v.verify(&cert, &identity);
        assert_eq!(
            result.unwrap_err(),
            GatingError::TLSInvalid(TLSValidationError::Expired)
        );
    }

    #[test]
    fn test_verify_not_yet_valid_at_zero() {
        let (cert, identity) = matching_pair();
        let v = TLSVerifier::new(0);
        let result = v.verify(&cert, &identity);
        assert_eq!(
            result.unwrap_err(),
            GatingError::TLSInvalid(TLSValidationError::NotYetValid)
        );
    }

    // ════════════════════════════════════════════════════════════
    // verify — CHECK 2: FINGERPRINT MISMATCH
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_fingerprint_mismatch() {
        let cert = make_cert([0xAA; 32]);
        let identity = make_identity([0xBB; 32]); // different fingerprint
        let v = TLSVerifier::new(1500);
        let result = v.verify(&cert, &identity);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            GatingError::TLSInvalid(TLSValidationError::FingerprintMismatch)
        );
    }

    #[test]
    fn test_verify_fingerprint_one_byte_diff() {
        let mut fp2 = [0xAA; 32];
        fp2[31] = 0xAB; // single byte difference
        let cert = make_cert([0xAA; 32]);
        let identity = make_identity(fp2);
        let v = TLSVerifier::new(1500);
        let result = v.verify(&cert, &identity);
        assert_eq!(
            result.unwrap_err(),
            GatingError::TLSInvalid(TLSValidationError::FingerprintMismatch)
        );
    }

    // ════════════════════════════════════════════════════════════
    // verify — CHECK 3: EMPTY SUBJECT CN
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_empty_subject_cn() {
        let fp = [0xAA; 32];
        let mut cert = make_cert(fp);
        cert.subject_cn = String::new();
        let identity = make_identity(fp);
        let v = TLSVerifier::new(1500);
        let result = v.verify(&cert, &identity);
        assert_eq!(
            result.unwrap_err(),
            GatingError::TLSInvalid(TLSValidationError::EmptySubject)
        );
    }

    #[test]
    fn test_verify_whitespace_only_subject_cn() {
        let fp = [0xAA; 32];
        let mut cert = make_cert(fp);
        cert.subject_cn = "   \t\n  ".to_string();
        let identity = make_identity(fp);
        let v = TLSVerifier::new(1500);
        let result = v.verify(&cert, &identity);
        assert_eq!(
            result.unwrap_err(),
            GatingError::TLSInvalid(TLSValidationError::EmptySubject)
        );
    }

    // ════════════════════════════════════════════════════════════
    // verify — CHECK ORDER ENFORCEMENT
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_check_order_time_before_fingerprint() {
        // Expired + fingerprint mismatch → should get Expired (check 1 first)
        let cert = make_cert([0xAA; 32]);
        let identity = make_identity([0xBB; 32]);
        let v = TLSVerifier::new(2001);
        let result = v.verify(&cert, &identity);
        assert_eq!(
            result.unwrap_err(),
            GatingError::TLSInvalid(TLSValidationError::Expired)
        );
    }

    #[test]
    fn test_check_order_fingerprint_before_subject() {
        // Valid time + fingerprint mismatch + empty CN → should get FingerprintMismatch (check 2 first)
        let mut cert = make_cert([0xAA; 32]);
        cert.subject_cn = String::new();
        let identity = make_identity([0xBB; 32]);
        let v = TLSVerifier::new(1500);
        let result = v.verify(&cert, &identity);
        assert_eq!(
            result.unwrap_err(),
            GatingError::TLSInvalid(TLSValidationError::FingerprintMismatch)
        );
    }

    #[test]
    fn test_check_order_time_before_subject() {
        // Expired + empty CN → should get Expired (check 1 first)
        let fp = [0xAA; 32];
        let mut cert = make_cert(fp);
        cert.subject_cn = String::new();
        let identity = make_identity(fp);
        let v = TLSVerifier::new(2001);
        let result = v.verify(&cert, &identity);
        assert_eq!(
            result.unwrap_err(),
            GatingError::TLSInvalid(TLSValidationError::Expired)
        );
    }

    // ════════════════════════════════════════════════════════════
    // verify — DETAIL MESSAGE
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_detail_contains_subject() {
        let (cert, identity) = matching_pair();
        let v = TLSVerifier::new(1500);
        let cr = v.verify(&cert, &identity).unwrap();
        let detail = cr.detail.unwrap();
        assert!(detail.contains("node.dsdn.example"));
    }

    #[test]
    fn test_verify_detail_contains_timestamp() {
        let (cert, identity) = matching_pair();
        let v = TLSVerifier::new(1500);
        let cr = v.verify(&cert, &identity).unwrap();
        let detail = cr.detail.unwrap();
        assert!(detail.contains("1500"));
    }

    // ════════════════════════════════════════════════════════════
    // verify_fingerprint — STATIC METHOD
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_fingerprint_match() {
        let der = b"test certificate DER bytes";
        let expected = TLSCertInfo::compute_fingerprint(der);
        assert!(TLSVerifier::verify_fingerprint(der, &expected));
    }

    #[test]
    fn test_verify_fingerprint_mismatch_static() {
        let der = b"test certificate DER bytes";
        let wrong = [0xFF; 32];
        assert!(!TLSVerifier::verify_fingerprint(der, &wrong));
    }

    #[test]
    fn test_verify_fingerprint_empty_der() {
        // SHA-256 of empty input is well-defined
        let expected = TLSCertInfo::compute_fingerprint(b"");
        assert!(TLSVerifier::verify_fingerprint(b"", &expected));
        // But should NOT match arbitrary expected
        assert!(!TLSVerifier::verify_fingerprint(b"", &[0x00; 32]));
    }

    #[test]
    fn test_verify_fingerprint_deterministic() {
        let der = b"determinism test";
        let expected = TLSCertInfo::compute_fingerprint(der);
        let r1 = TLSVerifier::verify_fingerprint(der, &expected);
        let r2 = TLSVerifier::verify_fingerprint(der, &expected);
        assert_eq!(r1, r2);
        assert!(r1);
    }

    #[test]
    fn test_verify_fingerprint_single_byte_change() {
        let der_a = b"certificate bytes A";
        let der_b = b"certificate bytes B"; // single char diff
        let fp_a = TLSCertInfo::compute_fingerprint(der_a);
        assert!(TLSVerifier::verify_fingerprint(der_a, &fp_a));
        assert!(!TLSVerifier::verify_fingerprint(der_b, &fp_a));
    }

    // ════════════════════════════════════════════════════════════
    // STRUCT PROPERTIES
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_tls_verifier_clone() {
        let v1 = TLSVerifier::new(1000);
        let v2 = v1.clone();
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_tls_verifier_debug() {
        let v = TLSVerifier::new(1000);
        let debug = format!("{:?}", v);
        assert!(debug.contains("TLSVerifier"));
        assert!(debug.contains("1000"));
    }

    #[test]
    fn test_tls_verifier_timestamp_accessor() {
        let v = TLSVerifier::new(42);
        assert_eq!(v.current_timestamp(), 42);
    }

    // ════════════════════════════════════════════════════════════
    // SEND + SYNC
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_tls_verifier_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<TLSVerifier>();
    }

    // ════════════════════════════════════════════════════════════
    // BOUNDARY SWEEP
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_boundary_sweep() {
        let (cert, identity) = matching_pair(); // valid [1000, 2000]

        let cases: &[(u64, bool)] = &[
            (0, false),       // not yet valid
            (999, false),     // one before not_before
            (1000, true),     // at not_before (inclusive)
            (1001, true),     // one after not_before
            (1500, true),     // midpoint
            (1999, true),     // one before not_after
            (2000, true),     // at not_after (inclusive)
            (2001, false),    // one after not_after (expired)
        ];

        for &(ts, should_pass) in cases {
            let v = TLSVerifier::new(ts);
            let result = v.verify(&cert, &identity);
            assert_eq!(
                result.is_ok(), should_pass,
                "verify at timestamp {} should_pass={}, got is_ok={}",
                ts, should_pass, result.is_ok()
            );
        }
    }
}