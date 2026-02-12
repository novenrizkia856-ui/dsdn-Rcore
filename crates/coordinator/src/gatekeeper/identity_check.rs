//! # Identity Check Hook (14B.34)
//!
//! Provides [`IdentityCheckHook`], a stateless validation-only hook for:
//!
//! - Verifying identity proofs during node join (`check_on_join`)
//! - Verifying TLS certificate matches identity (`check_tls_match`)
//! - Detecting node ID spoofing against the local registry (`check_node_id_not_spoofed`)
//!
//! ## Design
//!
//! `IdentityCheckHook` is a zero-sized unit struct — no fields, no internal
//! state, no mutable data. All methods take `&self` with explicit parameters.
//! The hook delegates to `IdentityVerifier` from the validator crate for
//! cryptographic verification and uses `TLSCertInfo` methods for certificate
//! checks.
//!
//! ## Safety
//!
//! - No `panic!`, `unwrap()`, `expect()`.
//! - No mutation of any input (registry, proofs, certificates).
//! - No network calls, no system clock access.
//! - Deterministic: same inputs always produce the same result.

use std::collections::HashMap;

use dsdn_common::gating::{
    GatingError, IdentityProof, NodeIdentity, NodeRegistryEntry,
    TLSCertInfo, TLSValidationError,
};
use dsdn_validator::gating::identity_verifier::{IdentityVerifier, DEFAULT_MAX_AGE_SECS};

// ════════════════════════════════════════════════════════════════════════════════
// IDENTITY CHECK HOOK
// ════════════════════════════════════════════════════════════════════════════════

/// Stateless identity validation hook for node admission gating.
///
/// Zero-sized unit struct — no fields, no interior mutability. All
/// verification logic delegates to existing verifiers from the
/// validator crate and common crate types.
///
/// ## Thread Safety
///
/// `IdentityCheckHook` is `Send + Sync + Copy` — it contains no data
/// and all methods are pure functions.
#[derive(Default, Debug, Clone, Copy)]
pub struct IdentityCheckHook;

impl IdentityCheckHook {
    /// Verifies an identity proof during node join.
    ///
    /// Delegates to [`IdentityVerifier::verify_proof`] from the validator
    /// crate, which performs:
    ///
    /// 1. **Timestamp freshness**: rejects future-dated challenges and
    ///    challenges older than [`DEFAULT_MAX_AGE_SECS`] (300 seconds).
    /// 2. **Ed25519 signature verification**: uses `verify_strict` over
    ///    the challenge nonce.
    ///
    /// ## Parameters
    ///
    /// - `proof`: The identity proof containing challenge + signature + node identity.
    /// - `timestamp`: Caller-provided Unix timestamp (seconds). No system clock accessed.
    ///
    /// ## Returns
    ///
    /// - `Ok(())` if the proof is fresh and cryptographically valid.
    /// - `Err(GatingError::IdentityVerificationFailed(..))` if expired or invalid.
    pub fn check_on_join(
        &self,
        proof: &IdentityProof,
        timestamp: u64,
    ) -> Result<(), GatingError> {
        // Delegate to IdentityVerifier's verify_proof.
        // On success, discard the CheckResult — we only need pass/fail.
        IdentityVerifier::verify_proof(proof, timestamp, DEFAULT_MAX_AGE_SECS)?;
        Ok(())
    }

    /// Verifies that a TLS certificate matches a node's identity and is
    /// temporally valid.
    ///
    /// ## Check Order (matches TLSVerifier convention)
    ///
    /// 1. **Time validity**: certificate must be valid at `current_timestamp`.
    ///    - `timestamp > tls_info.not_after` → `TLSInvalid(Expired)`
    ///    - `timestamp < tls_info.not_before` → `TLSInvalid(NotYetValid)`
    /// 2. **Fingerprint match**: `tls_info.fingerprint == identity.tls_cert_fingerprint`.
    ///    - Mismatch → `TLSInvalid(FingerprintMismatch)`
    ///
    /// ## Parameters
    ///
    /// - `identity`: The node's cryptographic identity.
    /// - `tls_info`: TLS certificate metadata to validate.
    /// - `current_timestamp`: Caller-provided Unix timestamp (seconds).
    ///   Required for temporal validity checks. No system clock accessed.
    ///
    /// ## Deviation from Spec
    ///
    /// The `current_timestamp` parameter is not in the original spec signature
    /// but is **required for correctness**: `TLSCertInfo::is_expired()` and
    /// `TLSCertInfo::is_valid_at()` both require a timestamp argument. Without
    /// it, temporal validation is impossible.
    ///
    /// ## Returns
    ///
    /// - `Ok(())` if the certificate is temporally valid and fingerprint matches.
    /// - `Err(GatingError::TLSInvalid(..))` with the specific failure reason.
    pub fn check_tls_match(
        &self,
        identity: &NodeIdentity,
        tls_info: &TLSCertInfo,
        current_timestamp: u64,
    ) -> Result<(), GatingError> {
        // Step 1: Time validity (check order: expired before not-yet-valid)
        if tls_info.is_expired(current_timestamp) {
            return Err(GatingError::TLSInvalid(TLSValidationError::Expired));
        }
        if !tls_info.is_valid_at(current_timestamp) {
            // is_valid_at checks not_before <= ts <= not_after.
            // If not expired (checked above) but not valid, then ts < not_before.
            return Err(GatingError::TLSInvalid(TLSValidationError::NotYetValid));
        }

        // Step 2: Fingerprint match
        if !tls_info.matches_identity(identity) {
            return Err(GatingError::TLSInvalid(TLSValidationError::FingerprintMismatch));
        }

        Ok(())
    }

    /// Checks whether a claimed node ID is already registered in the local
    /// registry, indicating a potential spoofing attempt.
    ///
    /// ## Logic
    ///
    /// 1. Convert `claimed_id` to lowercase hex string (registry key format).
    /// 2. Look up in `existing_registry`.
    /// 3. If found → the node ID is already claimed by another entity.
    ///    Returns `Err(GatingError::IdentityMismatch)` with the existing
    ///    entry's node ID and operator address.
    /// 4. If not found → `Ok(())` (ID is available).
    ///
    /// ## Note
    ///
    /// This is a conservative check: if a node ID already exists in the
    /// registry, any new registration attempt is treated as a potential
    /// spoof. Re-registration of an existing node should go through
    /// [`GateKeeper::process_admission`](super::GateKeeper::process_admission)
    /// which handles registry overwrite.
    ///
    /// ## Parameters
    ///
    /// - `claimed_id`: The 32-byte Ed25519 public key the applicant claims.
    /// - `existing_registry`: Immutable reference to the node registry.
    ///
    /// ## Returns
    ///
    /// - `Ok(())` if the ID is not in the registry.
    /// - `Err(GatingError::IdentityMismatch { .. })` if the ID is already registered.
    pub fn check_node_id_not_spoofed(
        &self,
        claimed_id: &[u8; 32],
        existing_registry: &HashMap<String, NodeRegistryEntry>,
    ) -> Result<(), GatingError> {
        let hex_key = claimed_id
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

        match existing_registry.get(&hex_key) {
            Some(existing) => {
                // Node ID already registered — potential spoof.
                Err(GatingError::IdentityMismatch {
                    node_id: existing.identity.node_id,
                    operator: existing.identity.operator_address,
                })
            }
            None => Ok(()),
        }
    }
}