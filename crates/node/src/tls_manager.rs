//! # TLS Certificate Manager (14B.42)
//!
//! Provides [`TLSCertManager`] for loading, generating, and inspecting
//! TLS certificates on the node side. Bridges the gap between raw X.509
//! data and the [`TLSCertInfo`] type expected by the coordinator's
//! `TLSVerifier` (14B.23) during admission gating.
//!
//! ## Purpose
//!
//! A DSDN service node must present a TLS certificate whose SHA-256
//! fingerprint matches the `tls_cert_fingerprint` in its [`NodeIdentity`].
//! `TLSCertManager` handles:
//!
//! - Loading certificates from PEM files (`from_pem_file`)
//! - Loading certificates from raw DER bytes (`from_der`)
//! - Generating self-signed certificates for development/testing
//!   (`generate_self_signed`)
//! - Exposing pre-computed `TLSCertInfo` for admission requests
//! - Time-based validity checking against explicit timestamps
//!
//! ## Fingerprint Computation
//!
//! The fingerprint is `SHA-256(cert_der)` — the hash of the complete
//! DER-encoded certificate bytes. This is computed once during
//! construction and stored in `TLSCertInfo::fingerprint`. The
//! `fingerprint()` accessor returns a zero-copy reference.
//!
//! The same computation is used by `TLSCertInfo::compute_fingerprint`
//! in `dsdn_common` and by `TLSVerifier` (14B.23) on the coordinator
//! side, guaranteeing consistency.
//!
//! ## Certificate Parsing
//!
//! X.509 parsing uses the `x509-parser` crate (ASN.1/DER parser).
//! PEM decoding uses the same crate's PEM module. No manual string
//! or ASN.1 parsing is performed.
//!
//! ## Self-Signed Generation
//!
//! Self-signed certificates use the `rcgen` crate. The generated
//! certificate's private key is **not** stored in `TLSCertManager` —
//! only the certificate (public) bytes are retained.
//!
//! ## Safety
//!
//! - No `panic!`, `unwrap()`, `expect()`.
//! - No private key storage — `TLSCertManager` holds only the
//!   certificate (public) DER bytes and derived metadata.
//! - `fingerprint()` and `cert_info()` return references without allocation.
//! - No `unsafe` code.
//! - All types are `Send + Sync`.
//!
//! ## Determinism
//!
//! - `from_pem_file` / `from_der`: Fully deterministic — same input
//!   bytes always produce the same `TLSCertInfo`.
//! - `fingerprint()`: Deterministic (SHA-256 is a pure function).
//! - `is_valid(timestamp)`: Deterministic (pure comparison).
//! - `generate_self_signed`: Non-deterministic (generates a fresh
//!   keypair and uses the system clock for validity start).

use std::fmt;
use std::path::Path;

use dsdn_common::gating::TLSCertInfo;
use sha2::{Digest, Sha256};

// ════════════════════════════════════════════════════════════════════════════════
// ERROR TYPE
// ════════════════════════════════════════════════════════════════════════════════

/// Error type for TLS certificate management operations.
///
/// All variants are safe to log — no key material is included.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TLSError {
    /// Certificate data could not be parsed (invalid PEM, DER, or X.509).
    ParseError,
    /// The certificate has expired relative to the checked timestamp.
    ExpiredCert,
    /// Input format is invalid (e.g., empty common name, empty file).
    InvalidFormat,
    /// Self-signed certificate generation failed.
    GenerationFailed,
}

impl fmt::Display for TLSError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TLSError::ParseError => write!(f, "TLS certificate parse error"),
            TLSError::ExpiredCert => write!(f, "TLS certificate has expired"),
            TLSError::InvalidFormat => write!(f, "invalid TLS certificate format"),
            TLSError::GenerationFailed => write!(f, "TLS self-signed certificate generation failed"),
        }
    }
}

impl std::error::Error for TLSError {}

// ════════════════════════════════════════════════════════════════════════════════
// TLS CERT MANAGER
// ════════════════════════════════════════════════════════════════════════════════

/// Manages a node's TLS certificate: loading, fingerprint, and metadata.
///
/// Holds the DER-encoded certificate bytes and pre-computed [`TLSCertInfo`].
/// Does NOT store any private key material.
///
/// ## Thread Safety
///
/// `TLSCertManager` is `Send + Sync`. All fields are owned values
/// with no interior mutability.
#[derive(Clone, Debug)]
pub struct TLSCertManager {
    /// Pre-computed certificate metadata including SHA-256 fingerprint.
    cert_info: TLSCertInfo,
    /// Raw DER-encoded certificate bytes.
    cert_der: Vec<u8>,
}

impl TLSCertManager {
    /// Loads a TLS certificate from a PEM-encoded file.
    ///
    /// Reads the file at `path`, decodes the PEM envelope, extracts
    /// the DER certificate bytes, and parses X.509 metadata.
    ///
    /// ## Parameters
    ///
    /// - `path`: Filesystem path to a PEM-encoded certificate file.
    ///
    /// ## Errors
    ///
    /// - `TLSError::ParseError` — File cannot be read, PEM is invalid,
    ///   or X.509 parsing fails.
    /// - `TLSError::InvalidFormat` — File is empty or contains no
    ///   certificate data.
    pub fn from_pem_file(path: &Path) -> Result<Self, TLSError> {
        let file_bytes = std::fs::read(path).map_err(|_| TLSError::ParseError)?;

        if file_bytes.is_empty() {
            return Err(TLSError::InvalidFormat);
        }

        let (_, pem) = x509_parser::pem::parse_x509_pem(&file_bytes)
            .map_err(|_| TLSError::ParseError)?;

        Self::from_der(pem.contents)
    }

    /// Constructs a `TLSCertManager` from raw DER-encoded certificate bytes.
    ///
    /// Parses the DER data as an X.509 certificate, extracts subject CN,
    /// issuer, validity timestamps, and computes the SHA-256 fingerprint.
    ///
    /// ## Parameters
    ///
    /// - `der`: Raw DER-encoded X.509 certificate bytes. Consumed by value.
    ///
    /// ## Errors
    ///
    /// - `TLSError::ParseError` — DER data is invalid or not a valid
    ///   X.509 certificate.
    /// - `TLSError::InvalidFormat` — DER data is empty.
    pub fn from_der(der: Vec<u8>) -> Result<Self, TLSError> {
        if der.is_empty() {
            return Err(TLSError::InvalidFormat);
        }

        let cert_info = parse_der_to_cert_info(&der)?;

        Ok(Self { cert_info, cert_der: der })
    }

    /// Generates a self-signed TLS certificate.
    ///
    /// Creates a new keypair, issues a self-signed X.509 certificate
    /// with the given `common_name` as Subject CN, and sets the
    /// validity period to `validity_days` from the current system time.
    ///
    /// The generated private key is **not** retained — only the
    /// certificate (public) bytes are stored in the returned manager.
    ///
    /// ## Parameters
    ///
    /// - `common_name`: Subject CN for the certificate. Must not be empty.
    /// - `validity_days`: Number of days the certificate is valid for.
    ///   Must be greater than 0.
    ///
    /// ## Non-Determinism
    ///
    /// This method uses the system clock (`OffsetDateTime::now_utc()`)
    /// for the certificate's `not_before` and OS entropy for keypair
    /// generation. Subsequent operations on the returned manager are
    /// deterministic.
    ///
    /// ## Errors
    ///
    /// - `TLSError::InvalidFormat` — `common_name` is empty.
    /// - `TLSError::GenerationFailed` — `validity_days` is 0, keypair
    ///   generation failed, certificate signing failed, or validity
    ///   period overflows.
    pub fn generate_self_signed(common_name: &str, validity_days: u32) -> Result<Self, TLSError> {
        if common_name.is_empty() {
            return Err(TLSError::InvalidFormat);
        }
        if validity_days == 0 {
            return Err(TLSError::GenerationFailed);
        }

        let der = generate_self_signed_der(common_name, validity_days)?;
        Self::from_der(der)
    }

    /// Returns a reference to the 32-byte SHA-256 fingerprint.
    ///
    /// Computed once during construction from the DER-encoded certificate
    /// bytes. Identical to the output of `TLSCertInfo::compute_fingerprint`.
    ///
    /// ## Performance
    ///
    /// Zero-allocation: returns a reference to the stored byte array.
    #[inline]
    pub fn fingerprint(&self) -> &[u8; 32] {
        &self.cert_info.fingerprint
    }

    /// Returns a reference to the pre-computed [`TLSCertInfo`].
    ///
    /// Contains fingerprint, subject CN, issuer, and validity timestamps.
    /// Suitable for inclusion in admission requests and gating evaluation.
    #[inline]
    pub fn cert_info(&self) -> &TLSCertInfo {
        &self.cert_info
    }

    /// Returns whether the certificate is valid at the given timestamp.
    ///
    /// A certificate is valid when:
    /// ```text
    /// not_before <= timestamp <= not_after
    /// ```
    ///
    /// Both boundaries are inclusive. This matches the convention in
    /// `TLSCertInfo::is_valid_at` (14B.5).
    ///
    /// ## Parameters
    ///
    /// - `timestamp`: Unix timestamp in seconds. Caller-provided,
    ///   never from system clock.
    ///
    /// ## Determinism
    ///
    /// Pure function: same `(cert, timestamp)` always returns the same result.
    #[inline]
    pub fn is_valid(&self, timestamp: u64) -> bool {
        self.cert_info.is_valid_at(timestamp)
    }

    /// Returns a reference to the raw DER-encoded certificate bytes.
    ///
    /// Useful for transport-layer TLS setup and fingerprint verification.
    #[inline]
    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// INTERNAL HELPERS (module-private)
// ════════════════════════════════════════════════════════════════════════════════

/// Parses DER bytes into a [`TLSCertInfo`].
///
/// Extracts subject CN, issuer, validity timestamps, and computes
/// the SHA-256 fingerprint. Uses `x509-parser` for X.509 parsing.
fn parse_der_to_cert_info(der: &[u8]) -> Result<TLSCertInfo, TLSError> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|_| TLSError::ParseError)?;

    // Extract Subject CN — use first CN found, or empty string.
    let subject_cn = match cert.subject().iter_common_name().next() {
        Some(attr) => match attr.as_str() {
            Ok(s) => s.to_string(),
            Err(_) => String::new(),
        },
        None => String::new(),
    };

    // Extract Issuer — use first CN found, or full DN string.
    let issuer = match cert.issuer().iter_common_name().next() {
        Some(attr) => match attr.as_str() {
            Ok(s) => s.to_string(),
            Err(_) => cert.issuer().to_string(),
        },
        None => cert.issuer().to_string(),
    };

    // Extract validity timestamps as Unix epoch seconds.
    // ASN1Time::timestamp() returns i64. Negative (pre-1970) is clamped to 0.
    let nb_i64 = cert.validity().not_before.timestamp();
    let na_i64 = cert.validity().not_after.timestamp();
    let not_before = if nb_i64 >= 0 { nb_i64 as u64 } else { 0 };
    let not_after = if na_i64 >= 0 { na_i64 as u64 } else { 0 };

    // Compute SHA-256 fingerprint over raw DER bytes.
    let fingerprint_bytes = Sha256::digest(der);
    let fingerprint: [u8; 32] = fingerprint_bytes.into();

    Ok(TLSCertInfo {
        fingerprint,
        subject_cn,
        not_before,
        not_after,
        issuer,
    })
}

/// Generates a self-signed certificate DER using `rcgen`.
///
/// The private key is created internally and discarded after signing.
/// Only the DER-encoded certificate (public) bytes are returned.
fn generate_self_signed_der(common_name: &str, validity_days: u32) -> Result<Vec<u8>, TLSError> {
    use rcgen::{CertificateParams, DnType, DnValue, KeyPair};

    let now = time::OffsetDateTime::now_utc();
    let duration = time::Duration::days(i64::from(validity_days));
    let not_after = now.checked_add(duration).ok_or(TLSError::GenerationFailed)?;

    let mut params = CertificateParams::default();
    params.not_before = now;
    params.not_after = not_after;
    params.distinguished_name.push(
        DnType::CommonName,
        DnValue::Utf8String(common_name.to_string()),
    );

    let key_pair = KeyPair::generate().map_err(|_| TLSError::GenerationFailed)?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|_| TLSError::GenerationFailed)?;

    Ok(cert.der().to_vec())
}

// ════════════════════════════════════════════════════════════════════════════════
// COMPILE-TIME ASSERTIONS
// ════════════════════════════════════════════════════════════════════════════════

/// Compile-time assertion: `TLSCertManager` is `Send`.
const _: () = {
    fn assert_send<T: Send>() {}
    fn check() {
        assert_send::<TLSCertManager>();
    }
    let _ = check;
};

/// Compile-time assertion: `TLSCertManager` is `Sync`.
const _: () = {
    fn assert_sync<T: Sync>() {}
    fn check() {
        assert_sync::<TLSCertManager>();
    }
    let _ = check;
};

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // ──────────────────────────────────────────────────────────────────
    // SELF-SIGNED GENERATION
    // ──────────────────────────────────────────────────────────────────

    /// `generate_self_signed` produces a valid manager.
    #[test]
    fn test_generate_self_signed_valid() {
        let mgr = TLSCertManager::generate_self_signed("test-node.dsdn.io", 365);
        assert!(mgr.is_ok());
        if let Ok(m) = mgr {
            assert_eq!(m.cert_info().subject_cn, "test-node.dsdn.io");
            assert_eq!(m.fingerprint().len(), 32);
            assert!(!m.cert_der().is_empty());
        }
    }

    /// Empty common name returns `InvalidFormat`.
    #[test]
    fn test_generate_self_signed_empty_cn() {
        let result = TLSCertManager::generate_self_signed("", 365);
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e, TLSError::InvalidFormat);
        }
    }

    /// Zero validity days returns `GenerationFailed`.
    #[test]
    fn test_generate_self_signed_zero_days() {
        let result = TLSCertManager::generate_self_signed("test.dsdn.io", 0);
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e, TLSError::GenerationFailed);
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // FINGERPRINT
    // ──────────────────────────────────────────────────────────────────

    /// Fingerprint is SHA-256 of DER bytes.
    #[test]
    fn test_fingerprint_matches_sha256_of_der() {
        let mgr = TLSCertManager::generate_self_signed("fp-test.dsdn.io", 30);
        assert!(mgr.is_ok());
        if let Ok(m) = mgr {
            let expected = Sha256::digest(m.cert_der());
            let expected_arr: [u8; 32] = expected.into();
            assert_eq!(*m.fingerprint(), expected_arr);
        }
    }

    /// Fingerprint is consistent: same DER → same fingerprint.
    #[test]
    fn test_fingerprint_deterministic_from_der() {
        let mgr1 = TLSCertManager::generate_self_signed("det-test.dsdn.io", 30);
        assert!(mgr1.is_ok());
        if let Ok(m1) = mgr1 {
            let der = m1.cert_der().to_vec();
            let mgr2 = TLSCertManager::from_der(der);
            assert!(mgr2.is_ok());
            if let Ok(m2) = mgr2 {
                assert_eq!(m1.fingerprint(), m2.fingerprint());
                assert_eq!(m1.cert_info().subject_cn, m2.cert_info().subject_cn);
                assert_eq!(m1.cert_info().not_before, m2.cert_info().not_before);
                assert_eq!(m1.cert_info().not_after, m2.cert_info().not_after);
            }
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // FROM DER
    // ──────────────────────────────────────────────────────────────────

    /// Empty DER returns `InvalidFormat`.
    #[test]
    fn test_from_der_empty() {
        let result = TLSCertManager::from_der(vec![]);
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e, TLSError::InvalidFormat);
        }
    }

    /// Garbage DER returns `ParseError`.
    #[test]
    fn test_from_der_garbage() {
        let result = TLSCertManager::from_der(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e, TLSError::ParseError);
        }
    }

    /// Round-trip: generate → DER → from_der → same metadata.
    #[test]
    fn test_from_der_roundtrip() {
        let original = TLSCertManager::generate_self_signed("roundtrip.dsdn.io", 90);
        assert!(original.is_ok());
        if let Ok(orig) = original {
            let der = orig.cert_der().to_vec();
            let reloaded = TLSCertManager::from_der(der);
            assert!(reloaded.is_ok());
            if let Ok(rl) = reloaded {
                assert_eq!(orig.cert_info(), rl.cert_info());
            }
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // FROM PEM FILE
    // ──────────────────────────────────────────────────────────────────

    /// Round-trip: generate → DER → PEM file → from_pem_file → same fingerprint.
    #[test]
    fn test_from_pem_file_roundtrip() {
        use base64::Engine;

        let mgr = TLSCertManager::generate_self_signed("pem-test.dsdn.io", 60);
        assert!(mgr.is_ok());
        if let Ok(m) = mgr {
            // Convert DER to PEM manually.
            let b64 = base64::engine::general_purpose::STANDARD.encode(m.cert_der());
            let mut pem_str = String::from("-----BEGIN CERTIFICATE-----\n");
            for chunk in b64.as_bytes().chunks(64) {
                if let Ok(s) = std::str::from_utf8(chunk) {
                    pem_str.push_str(s);
                    pem_str.push('\n');
                }
            }
            pem_str.push_str("-----END CERTIFICATE-----\n");

            // Write to temp file.
            let dir = std::env::temp_dir();
            let path = dir.join("dsdn_test_cert_14b42.pem");
            let write_result = std::fs::File::create(&path)
                .and_then(|mut f| f.write_all(pem_str.as_bytes()));
            assert!(write_result.is_ok());

            // Load from PEM file.
            let loaded = TLSCertManager::from_pem_file(&path);
            // Clean up.
            let _ = std::fs::remove_file(&path);

            assert!(loaded.is_ok());
            if let Ok(l) = loaded {
                assert_eq!(*m.fingerprint(), *l.fingerprint());
                assert_eq!(m.cert_info().subject_cn, l.cert_info().subject_cn);
            }
        }
    }

    /// Nonexistent file returns `ParseError`.
    #[test]
    fn test_from_pem_file_nonexistent() {
        let result = TLSCertManager::from_pem_file(Path::new("/nonexistent/cert.pem"));
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e, TLSError::ParseError);
        }
    }

    /// Empty PEM file returns `InvalidFormat`.
    #[test]
    fn test_from_pem_file_empty() {
        let dir = std::env::temp_dir();
        let path = dir.join("dsdn_test_empty_14b42.pem");
        let write_result = std::fs::File::create(&path)
            .and_then(|mut f| f.write_all(b""));
        assert!(write_result.is_ok());

        let result = TLSCertManager::from_pem_file(&path);
        let _ = std::fs::remove_file(&path);

        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e, TLSError::InvalidFormat);
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // IS_VALID
    // ──────────────────────────────────────────────────────────────────

    /// Timestamp within [not_before, not_after] → valid.
    #[test]
    fn test_is_valid_within_range() {
        let mgr = TLSCertManager::generate_self_signed("valid-test.dsdn.io", 365);
        assert!(mgr.is_ok());
        if let Ok(m) = mgr {
            let mid = m.cert_info().not_before + 1;
            assert!(m.is_valid(mid));
        }
    }

    /// Timestamp before not_before → invalid.
    #[test]
    fn test_is_valid_before_not_before() {
        let mgr = TLSCertManager::generate_self_signed("early-test.dsdn.io", 365);
        assert!(mgr.is_ok());
        if let Ok(m) = mgr {
            let nb = m.cert_info().not_before;
            if nb > 0 {
                assert!(!m.is_valid(nb - 1));
            }
        }
    }

    /// Timestamp after not_after → invalid.
    #[test]
    fn test_is_valid_after_not_after() {
        let mgr = TLSCertManager::generate_self_signed("late-test.dsdn.io", 1);
        assert!(mgr.is_ok());
        if let Ok(m) = mgr {
            let na = m.cert_info().not_after;
            assert!(!m.is_valid(na + 1));
        }
    }

    /// Timestamp exactly at not_before → valid (inclusive).
    #[test]
    fn test_is_valid_at_not_before() {
        let mgr = TLSCertManager::generate_self_signed("boundary-nb.dsdn.io", 30);
        assert!(mgr.is_ok());
        if let Ok(m) = mgr {
            assert!(m.is_valid(m.cert_info().not_before));
        }
    }

    /// Timestamp exactly at not_after → valid (inclusive).
    #[test]
    fn test_is_valid_at_not_after() {
        let mgr = TLSCertManager::generate_self_signed("boundary-na.dsdn.io", 30);
        assert!(mgr.is_ok());
        if let Ok(m) = mgr {
            assert!(m.is_valid(m.cert_info().not_after));
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // VALIDITY PERIOD
    // ──────────────────────────────────────────────────────────────────

    /// Certificate validity span matches requested days.
    #[test]
    fn test_validity_span_matches_days() {
        let days: u32 = 90;
        let mgr = TLSCertManager::generate_self_signed("span-test.dsdn.io", days);
        assert!(mgr.is_ok());
        if let Ok(m) = mgr {
            let span = m.cert_info().not_after - m.cert_info().not_before;
            let expected_secs = u64::from(days) * 86400;
            // Allow ±2 seconds tolerance for clock drift during generation.
            assert!(
                span >= expected_secs - 2 && span <= expected_secs + 2,
                "expected ~{expected_secs}s, got {span}s"
            );
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // ERROR TYPE
    // ──────────────────────────────────────────────────────────────────

    /// TLSError variants have distinct Display output.
    #[test]
    fn test_tls_error_display() {
        let e1 = TLSError::ParseError;
        let e2 = TLSError::ExpiredCert;
        let e3 = TLSError::InvalidFormat;
        let e4 = TLSError::GenerationFailed;

        let s1 = format!("{}", e1);
        let s2 = format!("{}", e2);
        let s3 = format!("{}", e3);
        let s4 = format!("{}", e4);

        assert!(!s1.is_empty());
        assert_ne!(s1, s2);
        assert_ne!(s2, s3);
        assert_ne!(s3, s4);
    }

    /// TLSError implements std::error::Error.
    #[test]
    fn test_tls_error_is_error() {
        let e: Box<dyn std::error::Error> = Box::new(TLSError::ParseError);
        let _ = format!("{}", e);
    }

    // ──────────────────────────────────────────────────────────────────
    // ISSUER
    // ──────────────────────────────────────────────────────────────────

    /// Self-signed cert: issuer equals subject CN.
    #[test]
    fn test_self_signed_issuer_matches_cn() {
        let mgr = TLSCertManager::generate_self_signed("issuer-test.dsdn.io", 30);
        assert!(mgr.is_ok());
        if let Ok(m) = mgr {
            assert_eq!(m.cert_info().issuer, "issuer-test.dsdn.io");
        }
    }
}