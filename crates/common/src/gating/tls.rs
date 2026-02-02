//! # TLS Certificate Types (14B.5)
//!
//! Defines types and deterministic logic for TLS certificate validation
//! in the DSDN gating system. TLS certificates bind a node's transport
//! layer to its cryptographic identity, preventing MITM and cert spoofing.
//!
//! ## Overview
//!
//! Each node presents a TLS certificate during transport setup. The
//! certificate's SHA-256 fingerprint must match the `tls_cert_fingerprint`
//! stored in the node's [`NodeIdentity`]. This module provides the types
//! to capture certificate metadata and verify the binding.
//!
//! ## Scope
//!
//! This module does **NOT** perform full X.509 parsing or ASN.1 decoding.
//! It operates on pre-extracted metadata (subject CN, issuer, validity
//! timestamps) and raw DER bytes (for fingerprinting). Full certificate
//! parsing is the responsibility of the transport layer.
//!
//! ## Validation
//!
//! - **Time validity**: [`TLSCertInfo::is_valid_at`] checks whether a
//!   timestamp falls within the certificate's `[not_before, not_after]`
//!   window (both boundaries inclusive).
//!
//! - **Expiry check**: [`TLSCertInfo::is_expired`] checks whether a
//!   timestamp is strictly past the certificate's `not_after`.
//!
//! - **Fingerprint match**: [`TLSCertInfo::matches_identity`] performs
//!   strict byte-level comparison of the certificate's SHA-256 fingerprint
//!   against the `tls_cert_fingerprint` in a [`NodeIdentity`].
//!
//! - **Fingerprint computation**: [`TLSCertInfo::compute_fingerprint`]
//!   computes SHA-256 over raw DER bytes. Empty input handling is the
//!   caller's responsibility.
//!
//! ## Safety Properties
//!
//! - All methods are pure functions: deterministic, no side effects.
//! - No system clock access — timestamps are always caller-provided.
//! - No fallback to CN or issuer for identity matching.
//! - Valid TLS certificate does NOT automatically make a node Active.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::identity::NodeIdentity;

// ════════════════════════════════════════════════════════════════════════════════
// TLS CERT INFO
// ════════════════════════════════════════════════════════════════════════════════

/// Metadata extracted from a node's TLS certificate.
///
/// `TLSCertInfo` captures the fields needed for gating validation:
/// fingerprint matching against [`NodeIdentity`], time-based validity
/// checks, and audit-relevant metadata (subject CN, issuer).
///
/// ## Fields
///
/// - `fingerprint`: SHA-256 hash of the DER-encoded certificate bytes.
/// - `subject_cn`: Common Name from the certificate's Subject field.
/// - `not_before`: Unix timestamp (seconds) — certificate validity start.
/// - `not_after`: Unix timestamp (seconds) — certificate validity end.
/// - `issuer`: Issuer string from the certificate.
///
/// ## Note
///
/// This struct stores pre-extracted metadata. It does NOT parse X.509
/// or ASN.1. The transport layer is responsible for extracting these
/// fields from the raw certificate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TLSCertInfo {
    /// SHA-256 fingerprint of the DER-encoded certificate.
    pub fingerprint: [u8; 32],
    /// Common Name from the certificate Subject.
    pub subject_cn: String,
    /// Certificate validity start (Unix timestamp, seconds).
    pub not_before: u64,
    /// Certificate validity end (Unix timestamp, seconds).
    pub not_after: u64,
    /// Certificate issuer string.
    pub issuer: String,
}

impl TLSCertInfo {
    /// Returns whether the certificate is valid at the given timestamp.
    ///
    /// A certificate is valid when:
    /// ```text
    /// not_before <= timestamp <= not_after
    /// ```
    ///
    /// Both boundaries are **inclusive**.
    ///
    /// This is a **pure function** — deterministic, no side effects,
    /// no system clock access.
    ///
    /// ## Arguments
    ///
    /// * `timestamp` — Unix timestamp (seconds), provided by the caller.
    #[must_use]
    #[inline]
    pub fn is_valid_at(&self, timestamp: u64) -> bool {
        self.not_before <= timestamp && timestamp <= self.not_after
    }

    /// Returns whether the certificate has expired at the given timestamp.
    ///
    /// A certificate is expired when:
    /// ```text
    /// timestamp > not_after
    /// ```
    ///
    /// At `not_after` itself, the certificate is NOT expired (still valid).
    ///
    /// This is a **pure function**.
    ///
    /// ## Arguments
    ///
    /// * `timestamp` — Unix timestamp (seconds), provided by the caller.
    #[must_use]
    #[inline]
    pub fn is_expired(&self, timestamp: u64) -> bool {
        timestamp > self.not_after
    }

    /// Computes the SHA-256 fingerprint of raw DER-encoded certificate bytes.
    ///
    /// This is a **pure function** — same input always produces the same
    /// output. The hash is computed over the raw bytes as-is, with no
    /// preprocessing or normalization.
    ///
    /// ## Arguments
    ///
    /// * `der_bytes` — Raw DER-encoded certificate bytes. The caller is
    ///   responsible for ensuring this is non-empty and valid DER data.
    ///
    /// ## Returns
    ///
    /// The SHA-256 hash as a 32-byte array.
    #[must_use]
    pub fn compute_fingerprint(der_bytes: &[u8]) -> [u8; 32] {
        let result = Sha256::digest(der_bytes);
        result.into()
    }

    /// Returns whether this certificate's fingerprint matches the
    /// `tls_cert_fingerprint` in the given [`NodeIdentity`].
    ///
    /// Performs **strict byte-level comparison** — all 32 bytes must
    /// match exactly. There is no fallback to subject CN, issuer, or
    /// any other field.
    ///
    /// This is a **pure function**.
    ///
    /// ## Arguments
    ///
    /// * `identity` — The node identity to match against.
    #[must_use]
    #[inline]
    pub fn matches_identity(&self, identity: &NodeIdentity) -> bool {
        self.fingerprint == identity.tls_cert_fingerprint
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TLS VALIDATION ERROR
// ════════════════════════════════════════════════════════════════════════════════

/// Error type for TLS certificate validation failures.
///
/// Each variant represents a specific, unambiguous validation failure.
/// These are used by upper-layer gating logic to determine why a
/// certificate was rejected.
///
/// ## Variants
///
/// - `Expired`: `timestamp > not_after` — the certificate's validity
///   period has ended.
/// - `NotYetValid`: `timestamp < not_before` — the certificate's
///   validity period has not started.
/// - `FingerprintMismatch`: The certificate's SHA-256 fingerprint does
///   not match the `tls_cert_fingerprint` in [`NodeIdentity`].
/// - `EmptySubject`: The certificate's `subject_cn` is empty.
/// - `MissingCert`: No certificate was provided by the caller.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TLSValidationError {
    /// The certificate has expired (`timestamp > not_after`).
    Expired,
    /// The certificate is not yet valid (`timestamp < not_before`).
    NotYetValid,
    /// The certificate fingerprint does not match the node identity.
    FingerprintMismatch,
    /// The certificate subject CN is empty.
    EmptySubject,
    /// No certificate was provided for validation.
    MissingCert,
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

    /// Creates a TLSCertInfo with default test values.
    /// Valid window: [1000, 2000]
    fn make_cert() -> TLSCertInfo {
        TLSCertInfo {
            fingerprint: [0xAA; 32],
            subject_cn: "node.dsdn.example".to_string(),
            not_before: 1000,
            not_after: 2000,
            issuer: "DSDN Test CA".to_string(),
        }
    }

    /// Creates a NodeIdentity with the given tls_cert_fingerprint.
    fn make_identity(tls_fp: [u8; 32]) -> NodeIdentity {
        NodeIdentity {
            node_id: [0x01; 32],
            operator_address: [0x02; 20],
            tls_cert_fingerprint: tls_fp,
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // TLSCertInfo TRAIT TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_tls_cert_info_clone() {
        let cert = make_cert();
        let cloned = cert.clone();
        assert_eq!(cert, cloned);
    }

    #[test]
    fn test_tls_cert_info_debug() {
        let cert = make_cert();
        let debug = format!("{:?}", cert);
        assert!(debug.contains("TLSCertInfo"));
        assert!(debug.contains("node.dsdn.example"));
        assert!(debug.contains("DSDN Test CA"));
    }

    #[test]
    fn test_tls_cert_info_eq() {
        let a = make_cert();
        let b = make_cert();
        assert_eq!(a, b);
    }

    #[test]
    fn test_tls_cert_info_ne_fingerprint() {
        let a = make_cert();
        let mut b = make_cert();
        b.fingerprint = [0xBB; 32];
        assert_ne!(a, b);
    }

    #[test]
    fn test_tls_cert_info_ne_subject() {
        let a = make_cert();
        let mut b = make_cert();
        b.subject_cn = "other.node".to_string();
        assert_ne!(a, b);
    }

    #[test]
    fn test_tls_cert_info_ne_not_before() {
        let a = make_cert();
        let mut b = make_cert();
        b.not_before = 999;
        assert_ne!(a, b);
    }

    #[test]
    fn test_tls_cert_info_ne_not_after() {
        let a = make_cert();
        let mut b = make_cert();
        b.not_after = 3000;
        assert_ne!(a, b);
    }

    #[test]
    fn test_tls_cert_info_ne_issuer() {
        let a = make_cert();
        let mut b = make_cert();
        b.issuer = "Other CA".to_string();
        assert_ne!(a, b);
    }

    #[test]
    fn test_tls_cert_info_serde_roundtrip() {
        let cert = make_cert();
        let json = serde_json::to_string(&cert).expect("serialize");
        let back: TLSCertInfo = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cert, back);
    }

    #[test]
    fn test_tls_cert_info_serde_preserves_fields() {
        let cert = make_cert();
        let json = serde_json::to_string(&cert).expect("serialize");
        let back: TLSCertInfo = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.fingerprint, [0xAA; 32]);
        assert_eq!(back.subject_cn, "node.dsdn.example");
        assert_eq!(back.not_before, 1000);
        assert_eq!(back.not_after, 2000);
        assert_eq!(back.issuer, "DSDN Test CA");
    }

    // ──────────────────────────────────────────────────────────────────────
    // is_valid_at() TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_is_valid_at_before_not_before() {
        let cert = make_cert(); // [1000, 2000]
        assert!(!cert.is_valid_at(999));
        assert!(!cert.is_valid_at(0));
    }

    #[test]
    fn test_is_valid_at_exactly_not_before() {
        let cert = make_cert();
        assert!(cert.is_valid_at(1000)); // inclusive
    }

    #[test]
    fn test_is_valid_at_during_validity() {
        let cert = make_cert();
        assert!(cert.is_valid_at(1001));
        assert!(cert.is_valid_at(1500));
        assert!(cert.is_valid_at(1999));
    }

    #[test]
    fn test_is_valid_at_exactly_not_after() {
        let cert = make_cert();
        assert!(cert.is_valid_at(2000)); // inclusive
    }

    #[test]
    fn test_is_valid_at_after_not_after() {
        let cert = make_cert();
        assert!(!cert.is_valid_at(2001));
        assert!(!cert.is_valid_at(u64::MAX));
    }

    #[test]
    fn test_is_valid_at_zero_window() {
        // not_before == not_after → valid only at that exact timestamp
        let cert = TLSCertInfo {
            fingerprint: [0; 32],
            subject_cn: "z".to_string(),
            not_before: 500,
            not_after: 500,
            issuer: "i".to_string(),
        };
        assert!(!cert.is_valid_at(499));
        assert!(cert.is_valid_at(500));
        assert!(!cert.is_valid_at(501));
    }

    #[test]
    fn test_is_valid_at_inverted_window() {
        // not_before > not_after → never valid (inverted / malformed)
        let cert = TLSCertInfo {
            fingerprint: [0; 32],
            subject_cn: "inv".to_string(),
            not_before: 2000,
            not_after: 1000,
            issuer: "i".to_string(),
        };
        // not_before(2000) <= ts && ts <= not_after(1000) can never be true
        assert!(!cert.is_valid_at(0));
        assert!(!cert.is_valid_at(1000));
        assert!(!cert.is_valid_at(1500));
        assert!(!cert.is_valid_at(2000));
        assert!(!cert.is_valid_at(u64::MAX));
    }

    #[test]
    fn test_is_valid_at_full_range() {
        // not_before=0, not_after=u64::MAX → valid for all timestamps
        let cert = TLSCertInfo {
            fingerprint: [0; 32],
            subject_cn: "all".to_string(),
            not_before: 0,
            not_after: u64::MAX,
            issuer: "i".to_string(),
        };
        assert!(cert.is_valid_at(0));
        assert!(cert.is_valid_at(1));
        assert!(cert.is_valid_at(u64::MAX / 2));
        assert!(cert.is_valid_at(u64::MAX));
    }

    #[test]
    fn test_is_valid_at_deterministic() {
        let cert = make_cert();
        let r1 = cert.is_valid_at(1500);
        let r2 = cert.is_valid_at(1500);
        let r3 = cert.is_valid_at(1500);
        assert_eq!(r1, r2);
        assert_eq!(r2, r3);
    }

    // ──────────────────────────────────────────────────────────────────────
    // is_expired() TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_is_expired_before_not_after() {
        let cert = make_cert(); // not_after = 2000
        assert!(!cert.is_expired(0));
        assert!(!cert.is_expired(1999));
    }

    #[test]
    fn test_is_expired_at_not_after() {
        let cert = make_cert();
        assert!(!cert.is_expired(2000)); // at boundary → NOT expired
    }

    #[test]
    fn test_is_expired_after_not_after() {
        let cert = make_cert();
        assert!(cert.is_expired(2001));
        assert!(cert.is_expired(u64::MAX));
    }

    #[test]
    fn test_is_expired_not_after_zero() {
        let cert = TLSCertInfo {
            fingerprint: [0; 32],
            subject_cn: "z".to_string(),
            not_before: 0,
            not_after: 0,
            issuer: "i".to_string(),
        };
        assert!(!cert.is_expired(0)); // at boundary → NOT expired
        assert!(cert.is_expired(1));  // strictly past → expired
    }

    #[test]
    fn test_is_expired_not_after_max() {
        let cert = TLSCertInfo {
            fingerprint: [0; 32],
            subject_cn: "m".to_string(),
            not_before: 0,
            not_after: u64::MAX,
            issuer: "i".to_string(),
        };
        // Can never be expired since no timestamp > u64::MAX
        assert!(!cert.is_expired(0));
        assert!(!cert.is_expired(u64::MAX));
    }

    #[test]
    fn test_is_expired_deterministic() {
        let cert = make_cert();
        let r1 = cert.is_expired(2001);
        let r2 = cert.is_expired(2001);
        assert_eq!(r1, r2);
    }

    // ──────────────────────────────────────────────────────────────────────
    // is_valid_at() ↔ is_expired() CONSISTENCY
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_valid_and_expired_mutually_exclusive_during_validity() {
        let cert = make_cert(); // [1000, 2000]
        // During valid window: valid=true, expired=false
        for ts in [1000, 1500, 2000] {
            assert!(cert.is_valid_at(ts), "ts={}", ts);
            assert!(!cert.is_expired(ts), "ts={}", ts);
        }
    }

    #[test]
    fn test_after_expiry_not_valid_and_expired() {
        let cert = make_cert();
        // After window: valid=false, expired=true
        for ts in [2001, 3000, u64::MAX] {
            assert!(!cert.is_valid_at(ts), "ts={}", ts);
            assert!(cert.is_expired(ts), "ts={}", ts);
        }
    }

    #[test]
    fn test_before_start_not_valid_and_not_expired() {
        let cert = make_cert();
        // Before window: valid=false, expired=false
        for ts in [0, 500, 999] {
            assert!(!cert.is_valid_at(ts), "ts={}", ts);
            assert!(!cert.is_expired(ts), "ts={}", ts);
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // compute_fingerprint() TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_compute_fingerprint_known_vector_empty() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let expected: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
            0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
            0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
        ];
        let result = TLSCertInfo::compute_fingerprint(b"");
        assert_eq!(result, expected);
    }

    #[test]
    fn test_compute_fingerprint_known_vector_abc() {
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let expected: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
            0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
            0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
        ];
        let result = TLSCertInfo::compute_fingerprint(b"abc");
        assert_eq!(result, expected);
    }

    #[test]
    fn test_compute_fingerprint_deterministic() {
        let data = b"deterministic test input";
        let r1 = TLSCertInfo::compute_fingerprint(data);
        let r2 = TLSCertInfo::compute_fingerprint(data);
        let r3 = TLSCertInfo::compute_fingerprint(data);
        assert_eq!(r1, r2);
        assert_eq!(r2, r3);
    }

    #[test]
    fn test_compute_fingerprint_different_input_different_output() {
        let a = TLSCertInfo::compute_fingerprint(b"input A");
        let b = TLSCertInfo::compute_fingerprint(b"input B");
        assert_ne!(a, b);
    }

    #[test]
    fn test_compute_fingerprint_single_byte() {
        // SHA-256(0x00) is a valid deterministic hash
        let result = TLSCertInfo::compute_fingerprint(&[0x00]);
        assert_eq!(result.len(), 32);
        // Different from empty hash
        let empty_hash = TLSCertInfo::compute_fingerprint(b"");
        assert_ne!(result, empty_hash);
    }

    #[test]
    fn test_compute_fingerprint_large_input() {
        let data = vec![0xFFu8; 65536];
        let result = TLSCertInfo::compute_fingerprint(&data);
        assert_eq!(result.len(), 32);
        // Deterministic
        let result2 = TLSCertInfo::compute_fingerprint(&data);
        assert_eq!(result, result2);
    }

    // ──────────────────────────────────────────────────────────────────────
    // matches_identity() TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_matches_identity_exact_match() {
        let cert = make_cert(); // fingerprint = [0xAA; 32]
        let identity = make_identity([0xAA; 32]);
        assert!(cert.matches_identity(&identity));
    }

    #[test]
    fn test_matches_identity_mismatch() {
        let cert = make_cert(); // fingerprint = [0xAA; 32]
        let identity = make_identity([0xBB; 32]);
        assert!(!cert.matches_identity(&identity));
    }

    #[test]
    fn test_matches_identity_single_byte_diff() {
        let cert = make_cert(); // [0xAA; 32]
        let mut fp = [0xAA; 32];
        fp[31] = 0xAB; // last byte differs
        let identity = make_identity(fp);
        assert!(!cert.matches_identity(&identity));
    }

    #[test]
    fn test_matches_identity_first_byte_diff() {
        let cert = make_cert();
        let mut fp = [0xAA; 32];
        fp[0] = 0x00; // first byte differs
        let identity = make_identity(fp);
        assert!(!cert.matches_identity(&identity));
    }

    #[test]
    fn test_matches_identity_all_zeros() {
        let cert = TLSCertInfo {
            fingerprint: [0x00; 32],
            subject_cn: "zero".to_string(),
            not_before: 0,
            not_after: 0,
            issuer: "i".to_string(),
        };
        let identity = make_identity([0x00; 32]);
        assert!(cert.matches_identity(&identity));
    }

    #[test]
    fn test_matches_identity_all_ones() {
        let cert = TLSCertInfo {
            fingerprint: [0xFF; 32],
            subject_cn: "ones".to_string(),
            not_before: 0,
            not_after: 0,
            issuer: "i".to_string(),
        };
        let identity = make_identity([0xFF; 32]);
        assert!(cert.matches_identity(&identity));
    }

    #[test]
    fn test_matches_identity_ignores_other_identity_fields() {
        // Two identities with same tls_cert_fingerprint but different
        // node_id and operator_address should both match
        let cert = make_cert();

        let id1 = NodeIdentity {
            node_id: [0x01; 32],
            operator_address: [0x01; 20],
            tls_cert_fingerprint: [0xAA; 32],
        };
        let id2 = NodeIdentity {
            node_id: [0xFF; 32],
            operator_address: [0xFF; 20],
            tls_cert_fingerprint: [0xAA; 32],
        };

        assert!(cert.matches_identity(&id1));
        assert!(cert.matches_identity(&id2));
    }

    #[test]
    fn test_matches_identity_deterministic() {
        let cert = make_cert();
        let identity = make_identity([0xAA; 32]);
        let r1 = cert.matches_identity(&identity);
        let r2 = cert.matches_identity(&identity);
        assert_eq!(r1, r2);
    }

    // ──────────────────────────────────────────────────────────────────────
    // compute_fingerprint() ↔ matches_identity() INTEGRATION
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_fingerprint_roundtrip_match() {
        // Compute fingerprint from DER bytes, store in cert and identity,
        // verify they match
        let der_bytes = b"mock DER certificate data";
        let fp = TLSCertInfo::compute_fingerprint(der_bytes);

        let cert = TLSCertInfo {
            fingerprint: fp,
            subject_cn: "test.node".to_string(),
            not_before: 0,
            not_after: u64::MAX,
            issuer: "Test CA".to_string(),
        };
        let identity = make_identity(fp);

        assert!(cert.matches_identity(&identity));
    }

    #[test]
    fn test_fingerprint_roundtrip_mismatch() {
        let der_cert_a = b"certificate A";
        let der_cert_b = b"certificate B";

        let fp_a = TLSCertInfo::compute_fingerprint(der_cert_a);
        let fp_b = TLSCertInfo::compute_fingerprint(der_cert_b);

        let cert = TLSCertInfo {
            fingerprint: fp_a,
            subject_cn: "a".to_string(),
            not_before: 0,
            not_after: 0,
            issuer: "i".to_string(),
        };
        let identity = make_identity(fp_b);

        assert!(!cert.matches_identity(&identity));
    }

    // ──────────────────────────────────────────────────────────────────────
    // TLSValidationError TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_tls_error_expired() {
        let err = TLSValidationError::Expired;
        assert_eq!(err, TLSValidationError::Expired);
    }

    #[test]
    fn test_tls_error_not_yet_valid() {
        let err = TLSValidationError::NotYetValid;
        assert_eq!(err, TLSValidationError::NotYetValid);
    }

    #[test]
    fn test_tls_error_fingerprint_mismatch() {
        let err = TLSValidationError::FingerprintMismatch;
        assert_eq!(err, TLSValidationError::FingerprintMismatch);
    }

    #[test]
    fn test_tls_error_empty_subject() {
        let err = TLSValidationError::EmptySubject;
        assert_eq!(err, TLSValidationError::EmptySubject);
    }

    #[test]
    fn test_tls_error_missing_cert() {
        let err = TLSValidationError::MissingCert;
        assert_eq!(err, TLSValidationError::MissingCert);
    }

    #[test]
    fn test_tls_error_clone() {
        let err = TLSValidationError::FingerprintMismatch;
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn test_tls_error_debug() {
        let err = TLSValidationError::Expired;
        let debug = format!("{:?}", err);
        assert!(debug.contains("Expired"));
    }

    #[test]
    fn test_tls_error_ne() {
        assert_ne!(TLSValidationError::Expired, TLSValidationError::NotYetValid);
        assert_ne!(
            TLSValidationError::FingerprintMismatch,
            TLSValidationError::EmptySubject
        );
        assert_ne!(
            TLSValidationError::MissingCert,
            TLSValidationError::Expired
        );
    }

    #[test]
    fn test_tls_error_all_variants_distinct() {
        let variants = [
            TLSValidationError::Expired,
            TLSValidationError::NotYetValid,
            TLSValidationError::FingerprintMismatch,
            TLSValidationError::EmptySubject,
            TLSValidationError::MissingCert,
        ];

        for i in 0..variants.len() {
            for j in (i + 1)..variants.len() {
                assert_ne!(
                    variants[i], variants[j],
                    "variants[{}] == variants[{}]",
                    i, j
                );
            }
        }
    }

    #[test]
    fn test_tls_error_serde_roundtrip_all_variants() {
        let variants = [
            TLSValidationError::Expired,
            TLSValidationError::NotYetValid,
            TLSValidationError::FingerprintMismatch,
            TLSValidationError::EmptySubject,
            TLSValidationError::MissingCert,
        ];

        for err in &variants {
            let json = serde_json::to_string(err).expect("serialize");
            let back: TLSValidationError =
                serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, back);
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // SEND + SYNC TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<TLSCertInfo>();
        assert_send_sync::<TLSValidationError>();
    }

    // ──────────────────────────────────────────────────────────────────────
    // COMPREHENSIVE BOUNDARY SWEEP
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_is_valid_at_boundary_sweep() {
        let cert = make_cert(); // [1000, 2000]

        let cases: &[(u64, bool)] = &[
            (0, false),        // far before
            (999, false),      // one before not_before
            (1000, true),      // at not_before (inclusive)
            (1001, true),      // one after not_before
            (1500, true),      // midpoint
            (1999, true),      // one before not_after
            (2000, true),      // at not_after (inclusive)
            (2001, false),     // one after not_after
            (u64::MAX, false), // far after
        ];

        for &(ts, expected) in cases {
            assert_eq!(
                cert.is_valid_at(ts),
                expected,
                "is_valid_at({}) should be {}",
                ts,
                expected
            );
        }
    }

    #[test]
    fn test_is_expired_boundary_sweep() {
        let cert = make_cert(); // not_after = 2000

        let cases: &[(u64, bool)] = &[
            (0, false),        // far before
            (1999, false),     // one before not_after
            (2000, false),     // at not_after (NOT expired)
            (2001, true),      // one after not_after
            (u64::MAX, true),  // far after
        ];

        for &(ts, expected) in cases {
            assert_eq!(
                cert.is_expired(ts),
                expected,
                "is_expired({}) should be {}",
                ts,
                expected
            );
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // REALISTIC SCENARIO
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_realistic_cert_lifecycle() {
        // Simulate a 1-year certificate
        let issued = 1_700_000_000_u64;  // ~Nov 2023
        let one_year = 365 * 24 * 60 * 60; // 31,536,000 seconds

        let der_bytes = b"realistic DER certificate bytes";
        let fp = TLSCertInfo::compute_fingerprint(der_bytes);

        let cert = TLSCertInfo {
            fingerprint: fp,
            subject_cn: "storage-01.dsdn.network".to_string(),
            not_before: issued,
            not_after: issued + one_year,
            issuer: "DSDN Network CA".to_string(),
        };

        let identity = make_identity(fp);

        // At issuance: valid, not expired, matches identity
        assert!(cert.is_valid_at(issued));
        assert!(!cert.is_expired(issued));
        assert!(cert.matches_identity(&identity));

        // Mid-lifetime: valid, not expired
        assert!(cert.is_valid_at(issued + one_year / 2));
        assert!(!cert.is_expired(issued + one_year / 2));

        // At expiry boundary: still valid, not expired
        assert!(cert.is_valid_at(issued + one_year));
        assert!(!cert.is_expired(issued + one_year));

        // One second past expiry: not valid, expired
        assert!(!cert.is_valid_at(issued + one_year + 1));
        assert!(cert.is_expired(issued + one_year + 1));

        // Before issuance: not valid, not expired
        assert!(!cert.is_valid_at(issued - 1));
        assert!(!cert.is_expired(issued - 1));
    }

    #[test]
    fn test_realistic_fingerprint_mismatch_detection() {
        let real_der = b"the real certificate DER bytes";
        let fake_der = b"a forged certificate DER bytes";

        let real_fp = TLSCertInfo::compute_fingerprint(real_der);
        let fake_fp = TLSCertInfo::compute_fingerprint(fake_der);

        // Node identity stores the real fingerprint
        let identity = make_identity(real_fp);

        // Cert with real fingerprint matches
        let real_cert = TLSCertInfo {
            fingerprint: real_fp,
            subject_cn: "node.dsdn".to_string(),
            not_before: 0,
            not_after: u64::MAX,
            issuer: "CA".to_string(),
        };
        assert!(real_cert.matches_identity(&identity));

        // Cert with fake fingerprint does NOT match
        let fake_cert = TLSCertInfo {
            fingerprint: fake_fp,
            subject_cn: "node.dsdn".to_string(), // same CN
            not_before: 0,
            not_after: u64::MAX,
            issuer: "CA".to_string(),             // same issuer
        };
        assert!(!fake_cert.matches_identity(&identity));
    }
}