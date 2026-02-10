//! # Identity Verifier (14B.22)
//!
//! Stateless cryptographic verifier for:
//! - Proving node_id ownership via Ed25519 challenge–response (`verify_proof`)
//! - Verifying node_id ↔ operator_address binding (`verify_binding`)
//!
//! ## Design
//!
//! `IdentityVerifier` is a zero-sized unit struct with no fields and no
//! mutable state. All configuration (timestamps, max age) is passed
//! explicitly as parameters. The verifier never accesses system clocks,
//! external state, or I/O.
//!
//! ## Verification Logic
//!
//! ### `verify_proof`
//!
//! 1. Validate timestamp: `current_timestamp - challenge.timestamp <= max_age_secs`
//! 2. Verify Ed25519 signature over `challenge.nonce` using `node_identity.node_id`
//! 3. Return `CheckResult` or `GatingError`
//!
//! ### `verify_binding`
//!
//! 1. Delegate to `NodeIdentity::verify_operator_binding(signature)`
//! 2. Return `CheckResult` or `GatingError`
//!
//! ## Properties
//!
//! - **Stateless**: Zero fields, no interior mutability.
//! - **Deterministic**: Same inputs always produce the same output.
//! - **No panic**: No `unwrap()`, `expect()`, or index access.
//! - **No implicit time**: Timestamp is an explicit parameter.

use dsdn_common::gating::{
    CheckResult,
    GatingError,
    IdentityProof,
    NodeIdentity,
};

// ════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════

/// Default maximum age (in seconds) for an identity challenge timestamp.
///
/// If `current_timestamp - challenge.timestamp > DEFAULT_MAX_AGE_SECS`,
/// the proof is considered expired.
///
/// Value: 300 seconds (5 minutes).
pub const DEFAULT_MAX_AGE_SECS: u64 = 300;

// ════════════════════════════════════════════════════════════════════════════
// IDENTITY VERIFIER
// ════════════════════════════════════════════════════════════════════════════

/// Stateless cryptographic verifier for node identity proofs and bindings.
///
/// `IdentityVerifier` has no fields — it is a zero-sized unit struct.
/// All inputs (timestamps, signatures, max age) are passed explicitly
/// as parameters. No system clock, no I/O, no cache, no side effects.
///
/// ## Usage
///
/// ```rust,ignore
/// use dsdn_validator::gating::IdentityVerifier;
/// use dsdn_validator::gating::identity_verifier::DEFAULT_MAX_AGE_SECS;
///
/// let result = IdentityVerifier::verify_proof(
///     &proof,
///     current_timestamp,
///     DEFAULT_MAX_AGE_SECS,
/// );
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityVerifier;

impl IdentityVerifier {
    /// Verify an identity proof: timestamp freshness + Ed25519 signature.
    ///
    /// ## Execution Order (STRICT — DO NOT REORDER)
    ///
    /// 1. Validate timestamp freshness:
    ///    - If `current_timestamp < challenge.timestamp` → expired (clock skew / replay)
    ///    - If `current_timestamp - challenge.timestamp > max_age_secs` → expired
    /// 2. Verify Ed25519 signature via `proof.verify()`:
    ///    - Public key: `proof.node_identity.node_id`
    ///    - Message: `proof.challenge.nonce` (raw 32 bytes, no prefix)
    ///    - Signature: `proof.signature` (64 bytes)
    ///    - Method: `ed25519_dalek::VerifyingKey::verify_strict`
    /// 3. If signature valid → `Ok(CheckResult { passed: true, .. })`
    /// 4. If signature invalid → `Err(GatingError::IdentityVerificationFailed(..))`
    ///
    /// ## Parameters
    ///
    /// * `proof` — The identity proof containing challenge, signature, and node identity.
    /// * `current_timestamp` — Caller-provided Unix timestamp (seconds). Not from system clock.
    /// * `max_age_secs` — Maximum allowed age of the challenge timestamp. Use
    ///   [`DEFAULT_MAX_AGE_SECS`] (300) for the protocol default.
    ///
    /// ## Errors
    ///
    /// * `GatingError::IdentityVerificationFailed` — Proof expired or signature invalid.
    pub fn verify_proof(
        proof: &IdentityProof,
        current_timestamp: u64,
        max_age_secs: u64,
    ) -> Result<CheckResult, GatingError> {
        let challenge_ts = proof.challenge.timestamp;

        // Step 1: Timestamp freshness check
        //
        // Case A: current_timestamp < challenge.timestamp → future-dated challenge
        //   This indicates clock skew or a forged timestamp. Reject as expired.
        // Case B: current_timestamp - challenge.timestamp > max_age_secs → too old
        let expired = if current_timestamp < challenge_ts {
            // Future-dated challenge is always considered expired (conservative)
            true
        } else {
            current_timestamp - challenge_ts > max_age_secs
        };

        if expired {
            return Err(GatingError::IdentityVerificationFailed(
                format!(
                    "proof expired: challenge timestamp {} is not within {} seconds of current timestamp {}",
                    challenge_ts, max_age_secs, current_timestamp,
                ),
            ));
        }

        // Step 2: Ed25519 signature verification
        // Delegates to IdentityProof::verify() which uses verify_strict
        // and returns false (never panics) on any crypto failure.
        let sig_valid = proof.verify();

        // Steps 3 & 4: Produce result
        if sig_valid {
            Ok(CheckResult {
                check_name: "identity_proof".to_string(),
                passed: true,
                detail: Some(format!(
                    "identity proof valid: node_id {} verified at timestamp {}",
                    hex::encode(&proof.node_identity.node_id[..4]),
                    current_timestamp,
                )),
            })
        } else {
            Err(GatingError::IdentityVerificationFailed(
                "Ed25519 signature verification failed for identity proof".to_string(),
            ))
        }
    }

    /// Verify operator binding: node_id ↔ operator_address.
    ///
    /// ## Execution Order (STRICT — DO NOT REORDER)
    ///
    /// 1. Call `identity.verify_operator_binding(binding_signature)`.
    /// 2. If `Ok(true)` → `Ok(CheckResult { passed: true, .. })`
    /// 3. If `Ok(false)` → `Err(GatingError::IdentityMismatch { .. })`
    /// 4. If `Err(IdentityError)` → `Err(GatingError::IdentityVerificationFailed(..))`
    ///
    /// ## Parameters
    ///
    /// * `identity` — The node identity to verify.
    /// * `binding_signature` — Ed25519 signature over the binding message.
    ///   Must be exactly 64 bytes.
    ///
    /// ## Errors
    ///
    /// * `GatingError::IdentityMismatch` — Signature is well-formed but does not
    ///   match the binding.
    /// * `GatingError::IdentityVerificationFailed` — Structural error (wrong
    ///   signature length, invalid public key, unparseable signature).
    pub fn verify_binding(
        identity: &NodeIdentity,
        binding_signature: &[u8],
    ) -> Result<CheckResult, GatingError> {
        // Step 1: Delegate to NodeIdentity::verify_operator_binding
        let binding_result = identity.verify_operator_binding(binding_signature)
            .map_err(|e| GatingError::IdentityVerificationFailed(
                format!("operator binding verification error: {}", e),
            ))?;

        // Steps 2 & 3: Produce result based on verification outcome
        if binding_result {
            Ok(CheckResult {
                check_name: "identity_binding".to_string(),
                passed: true,
                detail: Some(format!(
                    "operator binding verified: node {} bound to operator {}",
                    hex::encode(&identity.node_id[..4]),
                    hex::encode(&identity.operator_address[..4]),
                )),
            })
        } else {
            Err(GatingError::IdentityMismatch {
                node_id: identity.node_id,
                operator: identity.operator_address,
            })
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use dsdn_common::gating::{IdentityChallenge, NodeIdentity};
    use ed25519_dalek::{Signer, SigningKey};

    // ────────────────────────────────────────────────────────────
    // HELPERS
    // ────────────────────────────────────────────────────────────

    /// Deterministic seed for reproducible tests.
    const TEST_SEED: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    ];

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&TEST_SEED)
    }

    fn test_identity(signing_key: &SigningKey) -> NodeIdentity {
        NodeIdentity {
            node_id: signing_key.verifying_key().to_bytes(),
            operator_address: [0xBB; 20],
            tls_cert_fingerprint: [0xCC; 32],
        }
    }

    fn make_valid_proof(challenge_ts: u64) -> IdentityProof {
        let sk = test_signing_key();
        let nonce = [0x42; 32];
        let sig = sk.sign(&nonce);
        IdentityProof {
            challenge: IdentityChallenge {
                nonce,
                timestamp: challenge_ts,
                challenger: "coordinator".to_string(),
            },
            signature: sig.to_bytes(),
            node_identity: test_identity(&sk),
        }
    }

    fn sign_binding(identity: &NodeIdentity, sk: &SigningKey) -> Vec<u8> {
        let mut message = Vec::with_capacity(25 + 32 + 20);
        message.extend_from_slice(b"DSDN:operator_binding:v1:");
        message.extend_from_slice(&identity.node_id);
        message.extend_from_slice(&identity.operator_address);
        let sig = sk.sign(&message);
        sig.to_bytes().to_vec()
    }

    // ════════════════════════════════════════════════════════════
    // verify_proof — VALID CASES
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_proof_valid() {
        let proof = make_valid_proof(1000);
        let result = IdentityVerifier::verify_proof(&proof, 1100, DEFAULT_MAX_AGE_SECS);
        assert!(result.is_ok());
        let cr = result.unwrap();
        assert_eq!(cr.check_name, "identity_proof");
        assert!(cr.passed);
        assert!(cr.detail.is_some());
    }

    #[test]
    fn test_verify_proof_exact_max_age_passes() {
        // current - challenge = exactly max_age_secs → NOT expired (uses >)
        let proof = make_valid_proof(1000);
        let result = IdentityVerifier::verify_proof(&proof, 1300, DEFAULT_MAX_AGE_SECS);
        assert!(result.is_ok());
        assert!(result.unwrap().passed);
    }

    #[test]
    fn test_verify_proof_zero_age_passes() {
        // current == challenge timestamp → valid
        let proof = make_valid_proof(5000);
        let result = IdentityVerifier::verify_proof(&proof, 5000, DEFAULT_MAX_AGE_SECS);
        assert!(result.is_ok());
        assert!(result.unwrap().passed);
    }

    #[test]
    fn test_verify_proof_deterministic() {
        let proof = make_valid_proof(1000);
        let r1 = IdentityVerifier::verify_proof(&proof, 1100, DEFAULT_MAX_AGE_SECS);
        let r2 = IdentityVerifier::verify_proof(&proof, 1100, DEFAULT_MAX_AGE_SECS);
        assert_eq!(r1, r2);
    }

    // ════════════════════════════════════════════════════════════
    // verify_proof — TIMESTAMP EXPIRY
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_proof_expired() {
        // current - challenge = 301 > 300 → expired
        let proof = make_valid_proof(1000);
        let result = IdentityVerifier::verify_proof(&proof, 1301, DEFAULT_MAX_AGE_SECS);
        assert!(result.is_err());
        let err = result.unwrap_err();
        match &err {
            GatingError::IdentityVerificationFailed(msg) => {
                assert!(msg.contains("expired"), "error should mention expired: {}", msg);
            }
            other => panic!("expected IdentityVerificationFailed, got: {:?}", other),
        }
    }

    #[test]
    fn test_verify_proof_future_timestamp_rejected() {
        // challenge.timestamp > current_timestamp → future-dated → rejected
        let proof = make_valid_proof(5000);
        let result = IdentityVerifier::verify_proof(&proof, 4000, DEFAULT_MAX_AGE_SECS);
        assert!(result.is_err());
        match result.unwrap_err() {
            GatingError::IdentityVerificationFailed(msg) => {
                assert!(msg.contains("expired"));
            }
            other => panic!("expected IdentityVerificationFailed, got: {:?}", other),
        }
    }

    #[test]
    fn test_verify_proof_custom_max_age() {
        let proof = make_valid_proof(1000);
        // max_age = 10, current = 1011 → 11 > 10 → expired
        let result = IdentityVerifier::verify_proof(&proof, 1011, 10);
        assert!(result.is_err());
        // max_age = 10, current = 1010 → 10 = 10 → NOT expired (uses >)
        let result2 = IdentityVerifier::verify_proof(&proof, 1010, 10);
        assert!(result2.is_ok());
    }

    #[test]
    fn test_verify_proof_max_age_zero() {
        let proof = make_valid_proof(1000);
        // max_age = 0 → only exact same timestamp passes
        let result = IdentityVerifier::verify_proof(&proof, 1000, 0);
        assert!(result.is_ok());
        let result2 = IdentityVerifier::verify_proof(&proof, 1001, 0);
        assert!(result2.is_err());
    }

    // ════════════════════════════════════════════════════════════
    // verify_proof — SIGNATURE FAILURES
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_proof_wrong_signature() {
        let mut proof = make_valid_proof(1000);
        proof.signature[0] ^= 0x01; // tamper
        let result = IdentityVerifier::verify_proof(&proof, 1100, DEFAULT_MAX_AGE_SECS);
        assert!(result.is_err());
        match result.unwrap_err() {
            GatingError::IdentityVerificationFailed(msg) => {
                assert!(msg.contains("signature verification failed"));
            }
            other => panic!("expected IdentityVerificationFailed, got: {:?}", other),
        }
    }

    #[test]
    fn test_verify_proof_wrong_node_id() {
        let mut proof = make_valid_proof(1000);
        let other_seed: [u8; 32] = [0xFF; 32];
        let other_key = SigningKey::from_bytes(&other_seed);
        proof.node_identity.node_id = other_key.verifying_key().to_bytes();
        let result = IdentityVerifier::verify_proof(&proof, 1100, DEFAULT_MAX_AGE_SECS);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_proof_zero_signature() {
        let mut proof = make_valid_proof(1000);
        proof.signature = [0u8; 64];
        let result = IdentityVerifier::verify_proof(&proof, 1100, DEFAULT_MAX_AGE_SECS);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_proof_zero_node_id() {
        let mut proof = make_valid_proof(1000);
        proof.node_identity.node_id = [0u8; 32];
        let result = IdentityVerifier::verify_proof(&proof, 1100, DEFAULT_MAX_AGE_SECS);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_proof_tampered_nonce() {
        let mut proof = make_valid_proof(1000);
        proof.challenge.nonce[0] ^= 0x01;
        let result = IdentityVerifier::verify_proof(&proof, 1100, DEFAULT_MAX_AGE_SECS);
        assert!(result.is_err());
    }

    // ════════════════════════════════════════════════════════════
    // verify_proof — TIMESTAMP CHECKED BEFORE SIGNATURE
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_proof_expired_with_valid_sig_still_rejected() {
        // Valid signature but expired → should fail on timestamp first
        let proof = make_valid_proof(1000);
        let result = IdentityVerifier::verify_proof(&proof, 2000, DEFAULT_MAX_AGE_SECS);
        assert!(result.is_err());
        match result.unwrap_err() {
            GatingError::IdentityVerificationFailed(msg) => {
                assert!(msg.contains("expired"));
            }
            other => panic!("expected expired error, got: {:?}", other),
        }
    }

    // ════════════════════════════════════════════════════════════
    // verify_binding — VALID CASES
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_binding_valid() {
        let sk = test_signing_key();
        let identity = test_identity(&sk);
        let sig = sign_binding(&identity, &sk);
        let result = IdentityVerifier::verify_binding(&identity, &sig);
        assert!(result.is_ok());
        let cr = result.unwrap();
        assert_eq!(cr.check_name, "identity_binding");
        assert!(cr.passed);
        assert!(cr.detail.is_some());
    }

    #[test]
    fn test_verify_binding_deterministic() {
        let sk = test_signing_key();
        let identity = test_identity(&sk);
        let sig = sign_binding(&identity, &sk);
        let r1 = IdentityVerifier::verify_binding(&identity, &sig);
        let r2 = IdentityVerifier::verify_binding(&identity, &sig);
        assert_eq!(r1, r2);
    }

    // ════════════════════════════════════════════════════════════
    // verify_binding — INVALID CASES
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_binding_wrong_operator() {
        let sk = test_signing_key();
        let identity = test_identity(&sk);
        let sig = sign_binding(&identity, &sk);

        // Change operator address after signing
        let mut tampered_identity = identity;
        tampered_identity.operator_address = [0x99; 20];
        let result = IdentityVerifier::verify_binding(&tampered_identity, &sig);
        assert!(result.is_err());
        match result.unwrap_err() {
            GatingError::IdentityMismatch { node_id, operator } => {
                assert_eq!(node_id, tampered_identity.node_id);
                assert_eq!(operator, tampered_identity.operator_address);
            }
            other => panic!("expected IdentityMismatch, got: {:?}", other),
        }
    }

    #[test]
    fn test_verify_binding_wrong_signature() {
        let sk = test_signing_key();
        let identity = test_identity(&sk);
        let mut sig = sign_binding(&identity, &sk);
        sig[0] ^= 0x01; // tamper
        let result = IdentityVerifier::verify_binding(&identity, &sig);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_binding_signature_too_short() {
        let sk = test_signing_key();
        let identity = test_identity(&sk);
        let short_sig = vec![0u8; 32];
        let result = IdentityVerifier::verify_binding(&identity, &short_sig);
        assert!(result.is_err());
        match result.unwrap_err() {
            GatingError::IdentityVerificationFailed(msg) => {
                assert!(msg.contains("error"), "msg: {}", msg);
            }
            other => panic!("expected IdentityVerificationFailed, got: {:?}", other),
        }
    }

    #[test]
    fn test_verify_binding_empty_signature() {
        let sk = test_signing_key();
        let identity = test_identity(&sk);
        let result = IdentityVerifier::verify_binding(&identity, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_binding_zero_node_id() {
        let identity = NodeIdentity {
            node_id: [0u8; 32],
            operator_address: [0xBB; 20],
            tls_cert_fingerprint: [0xCC; 32],
        };
        let garbage_sig = [0xAB; 64];
        let result = IdentityVerifier::verify_binding(&identity, &garbage_sig);
        // Should be an error (invalid pubkey or mismatch), never Ok with passed=true
        match result {
            Ok(cr) => assert!(!cr.passed, "garbage sig on zero pubkey must not pass"),
            Err(_) => {} // acceptable
        }
    }

    // ════════════════════════════════════════════════════════════
    // verify_binding — DETAIL MESSAGES
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_binding_detail_contains_node_and_operator() {
        let sk = test_signing_key();
        let identity = test_identity(&sk);
        let sig = sign_binding(&identity, &sk);
        let cr = IdentityVerifier::verify_binding(&identity, &sig).unwrap();
        let detail = cr.detail.unwrap();
        assert!(detail.contains(&hex::encode(&identity.node_id[..4])));
        assert!(detail.contains(&hex::encode(&identity.operator_address[..4])));
    }

    // ════════════════════════════════════════════════════════════
    // STRUCT PROPERTIES
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_identity_verifier_is_zero_sized() {
        assert_eq!(std::mem::size_of::<IdentityVerifier>(), 0);
    }

    #[test]
    fn test_identity_verifier_clone() {
        let v1 = IdentityVerifier;
        let v2 = v1.clone();
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_identity_verifier_debug() {
        let v = IdentityVerifier;
        let debug = format!("{:?}", v);
        assert!(debug.contains("IdentityVerifier"));
    }

    // ════════════════════════════════════════════════════════════
    // SEND + SYNC
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_identity_verifier_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<IdentityVerifier>();
    }
}