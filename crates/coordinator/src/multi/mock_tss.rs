//! # Mock TSS Interface (CO.7)
//!
//! Deterministic mock Threshold Signature Scheme for testing receipt signing
//! flows without a real FROST library.
//!
//! # ⚠️ WARNING: NEVER USE IN PRODUCTION ⚠️
//!
//! This module is **not cryptographically secure**. It produces deterministic
//! outputs derived from SHA3-256 hashes of the inputs. A real attacker can
//! forge signatures trivially. This exists solely for:
//!
//! - Receipt signing flow tests
//! - Assembly tests
//! - Threshold behavior simulation
//! - Integration test pipelines
//!
//! # Availability
//!
//! This module is only compiled when:
//!
//! - `#[cfg(test)]` — running `cargo test`
//! - `feature = "mock-tss"` — explicitly enabled feature flag
//!
//! It is **never** available in a default production build.
//!
//! # Determinism
//!
//! All outputs are deterministic: same inputs → same outputs.
//!
//! - No randomness (`OsRng`, `thread_rng`, etc.).
//! - No system time (`SystemTime::now`, `Instant::now`).
//! - No thread-local or global mutable state.
//! - All values derived from `SHA3-256(domain ‖ inputs)`.
//!
//! # Safety
//!
//! - No panic, unwrap, expect, todo, unreachable.
//! - No unsafe.
//! - No global state.

use sha3::{Digest, Sha3_256};
use dsdn_proto::tss::signing::{PartialSignatureProto, SigningCommitmentProto};
use super::SessionId;

// ════════════════════════════════════════════════════════════════════════════════
// DOMAIN SEPARATORS
// ════════════════════════════════════════════════════════════════════════════════

/// Domain separator for mock group public key derivation.
const DOMAIN_GROUP_PUBKEY: &[u8] = b"DSDN:mock_tss:group_pubkey:v1:";

/// Domain separator for mock commitment hiding nonce.
const DOMAIN_HIDING: &[u8] = b"DSDN:mock_tss:hiding:v1:";

/// Domain separator for mock commitment binding nonce.
const DOMAIN_BINDING: &[u8] = b"DSDN:mock_tss:binding:v1:";

/// Domain separator for mock signer ID derivation.
const DOMAIN_SIGNER_ID: &[u8] = b"DSDN:mock_tss:signer_id:v1:";

/// Domain separator for mock partial signature share.
const DOMAIN_SIGNATURE_SHARE: &[u8] = b"DSDN:mock_tss:sig_share:v1:";

/// Domain separator for mock aggregate signature.
const DOMAIN_AGGREGATE: &[u8] = b"DSDN:mock_tss:aggregate:v1:";

// ════════════════════════════════════════════════════════════════════════════════
// MOCK TSS
// ════════════════════════════════════════════════════════════════════════════════

/// Deterministic mock Threshold Signature Scheme.
///
/// Produces structurally valid but **cryptographically insecure** signing
/// artifacts for testing purposes only.
///
/// # ⚠️ NEVER USE IN PRODUCTION ⚠️
///
/// All outputs are derived from `SHA3-256(domain ‖ threshold ‖ group_pubkey ‖ inputs)`.
/// An attacker who knows the threshold and group_pubkey can trivially forge
/// signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockTSS {
    /// Threshold required for signing quorum.
    threshold: u8,
    /// Deterministic mock group public key (32 bytes).
    group_pubkey: [u8; 32],
}

impl MockTSS {
    /// Creates a new `MockTSS` with the given threshold.
    ///
    /// The `group_pubkey` is derived deterministically:
    /// `SHA3-256(DOMAIN_GROUP_PUBKEY ‖ threshold_byte)`.
    ///
    /// Same threshold → same group_pubkey. No randomness.
    #[must_use]
    pub fn new(threshold: u8) -> Self {
        let group_pubkey = hash_domain_u8(DOMAIN_GROUP_PUBKEY, threshold);
        Self {
            threshold,
            group_pubkey,
        }
    }

    /// Returns the threshold.
    #[must_use]
    #[inline]
    pub const fn threshold(&self) -> u8 {
        self.threshold
    }

    /// Returns the mock group public key.
    #[must_use]
    #[inline]
    pub const fn group_pubkey(&self) -> &[u8; 32] {
        &self.group_pubkey
    }

    /// Generates a deterministic `SigningCommitmentProto` for the given session.
    ///
    /// All fields are derived from `SHA3-256(domain ‖ group_pubkey ‖ session_id)`:
    ///
    /// - `session_id`: from the input `session_id`.
    /// - `signer_id`: `SHA3-256(DOMAIN_SIGNER_ID ‖ group_pubkey ‖ session_id)`.
    /// - `hiding`: `SHA3-256(DOMAIN_HIDING ‖ group_pubkey ‖ session_id)`.
    /// - `binding`: `SHA3-256(DOMAIN_BINDING ‖ group_pubkey ‖ session_id)`.
    /// - `timestamp`: 0 (deterministic, no system time).
    ///
    /// Same session_id → same commitment. No randomness.
    #[must_use]
    pub fn generate_commitment(
        &self,
        session_id: &SessionId,
    ) -> SigningCommitmentProto {
        let sid_bytes = session_id.as_bytes();

        let signer_id = hash_domain_two(DOMAIN_SIGNER_ID, &self.group_pubkey, sid_bytes);
        let hiding = hash_domain_two(DOMAIN_HIDING, &self.group_pubkey, sid_bytes);
        let binding = hash_domain_two(DOMAIN_BINDING, &self.group_pubkey, sid_bytes);

        SigningCommitmentProto {
            session_id: sid_bytes.to_vec(),
            signer_id: signer_id.to_vec(),
            hiding: hiding.to_vec(),
            binding: binding.to_vec(),
            timestamp: 0,
        }
    }

    /// Generates a deterministic `PartialSignatureProto` for the given session
    /// and message.
    ///
    /// - `commitment`: generated via [`generate_commitment`] (same session_id).
    /// - `signature_share`: `SHA3-256(DOMAIN_SIGNATURE_SHARE ‖ group_pubkey ‖ session_id ‖ message)`.
    ///
    /// Same (session_id, message) → same partial. No randomness.
    #[must_use]
    pub fn generate_partial(
        &self,
        session_id: &SessionId,
        message: &[u8],
    ) -> PartialSignatureProto {
        let commitment = self.generate_commitment(session_id);
        let sid_bytes = session_id.as_bytes();

        let signature_share = hash_domain_three(
            DOMAIN_SIGNATURE_SHARE,
            &self.group_pubkey,
            sid_bytes,
            message,
        );

        PartialSignatureProto {
            session_id: sid_bytes.to_vec(),
            signer_id: commitment.signer_id.clone(),
            commitment,
            signature_share: signature_share.to_vec(),
        }
    }

    /// Computes the deterministic mock aggregate signature for a message.
    ///
    /// This is the expected signature that [`verify_aggregate`] checks against.
    ///
    /// `SHA3-256(DOMAIN_AGGREGATE ‖ group_pubkey ‖ threshold ‖ message)`.
    #[must_use]
    pub fn compute_aggregate(&self, message: &[u8]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(DOMAIN_AGGREGATE);
        hasher.update(self.group_pubkey);
        hasher.update([self.threshold]);
        hasher.update(message);
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    /// Verifies a mock aggregate signature.
    ///
    /// Returns `true` if `signature` matches the deterministic mock aggregate
    /// for the given `message`. Returns `false` otherwise.
    ///
    /// This is NOT real cryptographic verification. It checks:
    /// `signature == SHA3-256(DOMAIN_AGGREGATE ‖ group_pubkey ‖ threshold ‖ message)`.
    ///
    /// # ⚠️ NEVER USE IN PRODUCTION ⚠️
    #[must_use]
    pub fn verify_aggregate(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        let expected = self.compute_aggregate(message);
        // Constant-length check first (mock doesn't need constant-time compare).
        if signature.len() != 32 {
            return false;
        }
        signature == expected.as_slice()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// HASHING HELPERS
// ════════════════════════════════════════════════════════════════════════════════

/// `SHA3-256(domain ‖ single_byte)` → `[u8; 32]`.
fn hash_domain_u8(domain: &[u8], value: u8) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(domain);
    hasher.update([value]);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// `SHA3-256(domain ‖ a ‖ b)` → `[u8; 32]`.
fn hash_domain_two(domain: &[u8], a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(domain);
    hasher.update(a);
    hasher.update(b);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// `SHA3-256(domain ‖ a ‖ b ‖ c)` → `[u8; 32]`.
fn hash_domain_three(domain: &[u8], a: &[u8], b: &[u8], c: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(domain);
    hasher.update(a);
    hasher.update(b);
    hasher.update(c);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(byte: u8) -> SessionId {
        SessionId::new([byte; 32])
    }

    // ── Constructor ─────────────────────────────────────────────────────

    #[test]
    fn new_deterministic() {
        let a = MockTSS::new(2);
        let b = MockTSS::new(2);
        assert_eq!(a, b);
        assert_eq!(a.group_pubkey(), b.group_pubkey());
    }

    #[test]
    fn different_threshold_different_pubkey() {
        let a = MockTSS::new(2);
        let b = MockTSS::new(3);
        assert_ne!(a.group_pubkey(), b.group_pubkey());
    }

    #[test]
    fn threshold_getter() {
        let tss = MockTSS::new(5);
        assert_eq!(tss.threshold(), 5);
    }

    #[test]
    fn group_pubkey_not_zero() {
        let tss = MockTSS::new(2);
        assert_ne!(tss.group_pubkey(), &[0u8; 32]);
    }

    // ── generate_commitment ─────────────────────────────────────────────

    #[test]
    fn commitment_deterministic() {
        let tss = MockTSS::new(2);
        let c1 = tss.generate_commitment(&sid(0x01));
        let c2 = tss.generate_commitment(&sid(0x01));
        assert_eq!(c1.session_id, c2.session_id);
        assert_eq!(c1.signer_id, c2.signer_id);
        assert_eq!(c1.hiding, c2.hiding);
        assert_eq!(c1.binding, c2.binding);
        assert_eq!(c1.timestamp, c2.timestamp);
    }

    #[test]
    fn commitment_deterministic_100_iterations() {
        let tss = MockTSS::new(2);
        let reference = tss.generate_commitment(&sid(0x42));
        for _ in 0..100 {
            assert_eq!(tss.generate_commitment(&sid(0x42)), reference);
        }
    }

    #[test]
    fn commitment_different_sessions() {
        let tss = MockTSS::new(2);
        let c1 = tss.generate_commitment(&sid(0x01));
        let c2 = tss.generate_commitment(&sid(0x02));
        assert_ne!(c1.signer_id, c2.signer_id);
        assert_ne!(c1.hiding, c2.hiding);
        assert_ne!(c1.binding, c2.binding);
    }

    #[test]
    fn commitment_session_id_matches_input() {
        let tss = MockTSS::new(2);
        let session = sid(0x42);
        let c = tss.generate_commitment(&session);
        assert_eq!(c.session_id, session.as_bytes().to_vec());
    }

    #[test]
    fn commitment_fields_are_32_bytes() {
        let tss = MockTSS::new(2);
        let c = tss.generate_commitment(&sid(0x01));
        assert_eq!(c.signer_id.len(), 32);
        assert_eq!(c.hiding.len(), 32);
        assert_eq!(c.binding.len(), 32);
        assert_eq!(c.session_id.len(), 32);
    }

    #[test]
    fn commitment_hiding_binding_different() {
        let tss = MockTSS::new(2);
        let c = tss.generate_commitment(&sid(0x01));
        assert_ne!(c.hiding, c.binding);
    }

    #[test]
    fn commitment_timestamp_zero() {
        let tss = MockTSS::new(2);
        let c = tss.generate_commitment(&sid(0x01));
        assert_eq!(c.timestamp, 0);
    }

    // ── generate_partial ────────────────────────────────────────────────

    #[test]
    fn partial_deterministic() {
        let tss = MockTSS::new(2);
        let msg = b"test message";
        let p1 = tss.generate_partial(&sid(0x01), msg);
        let p2 = tss.generate_partial(&sid(0x01), msg);
        assert_eq!(p1.session_id, p2.session_id);
        assert_eq!(p1.signer_id, p2.signer_id);
        assert_eq!(p1.signature_share, p2.signature_share);
        assert_eq!(p1.commitment, p2.commitment);
    }

    #[test]
    fn partial_deterministic_100_iterations() {
        let tss = MockTSS::new(2);
        let msg = b"determinism test";
        let reference = tss.generate_partial(&sid(0x42), msg);
        for _ in 0..100 {
            assert_eq!(tss.generate_partial(&sid(0x42), msg), reference);
        }
    }

    #[test]
    fn partial_different_messages() {
        let tss = MockTSS::new(2);
        let p1 = tss.generate_partial(&sid(0x01), b"msg_a");
        let p2 = tss.generate_partial(&sid(0x01), b"msg_b");
        assert_ne!(p1.signature_share, p2.signature_share);
    }

    #[test]
    fn partial_different_sessions() {
        let tss = MockTSS::new(2);
        let msg = b"same message";
        let p1 = tss.generate_partial(&sid(0x01), msg);
        let p2 = tss.generate_partial(&sid(0x02), msg);
        assert_ne!(p1.signature_share, p2.signature_share);
        assert_ne!(p1.signer_id, p2.signer_id);
    }

    #[test]
    fn partial_commitment_matches_generate_commitment() {
        let tss = MockTSS::new(2);
        let session = sid(0x01);
        let commitment = tss.generate_commitment(&session);
        let partial = tss.generate_partial(&session, b"msg");
        assert_eq!(partial.commitment, commitment);
    }

    #[test]
    fn partial_signature_share_is_32_bytes() {
        let tss = MockTSS::new(2);
        let p = tss.generate_partial(&sid(0x01), b"msg");
        assert_eq!(p.signature_share.len(), 32);
    }

    // ── verify_aggregate ────────────────────────────────────────────────

    #[test]
    fn verify_correct_aggregate() {
        let tss = MockTSS::new(2);
        let msg = b"receipt data";
        let sig = tss.compute_aggregate(msg);
        assert!(tss.verify_aggregate(msg, &sig));
    }

    #[test]
    fn verify_wrong_signature_rejected() {
        let tss = MockTSS::new(2);
        let msg = b"receipt data";
        let bad_sig = [0xFFu8; 32];
        assert!(!tss.verify_aggregate(msg, &bad_sig));
    }

    #[test]
    fn verify_wrong_message_rejected() {
        let tss = MockTSS::new(2);
        let sig = tss.compute_aggregate(b"message_a");
        assert!(!tss.verify_aggregate(b"message_b", &sig));
    }

    #[test]
    fn verify_wrong_length_rejected() {
        let tss = MockTSS::new(2);
        let msg = b"test";
        assert!(!tss.verify_aggregate(msg, &[0xAA; 64])); // Too long.
        assert!(!tss.verify_aggregate(msg, &[0xAA; 16])); // Too short.
        assert!(!tss.verify_aggregate(msg, &[])); // Empty.
    }

    #[test]
    fn verify_different_threshold_different_signature() {
        let tss_a = MockTSS::new(2);
        let tss_b = MockTSS::new(3);
        let msg = b"same message";
        let sig_a = tss_a.compute_aggregate(msg);
        let sig_b = tss_b.compute_aggregate(msg);
        assert_ne!(sig_a, sig_b);
        assert!(!tss_b.verify_aggregate(msg, &sig_a));
        assert!(!tss_a.verify_aggregate(msg, &sig_b));
    }

    #[test]
    fn compute_aggregate_deterministic() {
        let tss = MockTSS::new(2);
        let msg = b"test";
        let s1 = tss.compute_aggregate(msg);
        let s2 = tss.compute_aggregate(msg);
        assert_eq!(s1, s2);
    }

    #[test]
    fn compute_aggregate_deterministic_100_iterations() {
        let tss = MockTSS::new(2);
        let msg = b"determinism";
        let reference = tss.compute_aggregate(msg);
        for _ in 0..100 {
            assert_eq!(tss.compute_aggregate(msg), reference);
        }
    }

    // ── Debug & Clone ───────────────────────────────────────────────────

    #[test]
    fn debug_not_empty() {
        let tss = MockTSS::new(2);
        let dbg = format!("{:?}", tss);
        assert!(dbg.contains("MockTSS"));
    }

    #[test]
    fn clone_eq() {
        let tss = MockTSS::new(2);
        let cloned = tss.clone();
        assert_eq!(tss, cloned);
    }
}