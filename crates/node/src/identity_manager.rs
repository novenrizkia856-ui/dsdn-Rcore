//! # Node Identity Manager (14B.41)
//!
//! Provides [`NodeIdentityManager`] for managing a service node's
//! Ed25519 keypair, cryptographic identity, challenge signing, and
//! identity proof construction.
//!
//! ## Purpose
//!
//! A DSDN service node must prove its identity to the coordinator's
//! GateKeeper during admission. The `NodeIdentityManager` encapsulates
//! the node's Ed25519 keypair and provides methods for:
//!
//! - Generating a fresh random keypair (`generate`)
//! - Loading a keypair from a 32-byte secret (`from_keypair`)
//! - Exposing the node's public identity (`node_id`, `operator_address`)
//! - Signing challenge nonces for identity proof (`sign_challenge`)
//! - Constructing a complete `IdentityProof` for coordinator submission
//!   (`create_identity_proof`)
//!
//! ## Identity Derivation
//!
//! Given an Ed25519 keypair, the following identity fields are derived:
//!
//! | Field | Source | Size |
//! |-------|--------|------|
//! | `node_id` | Ed25519 public key (verifying key) bytes | 32 bytes |
//! | `operator_address` | `node_id[12..32]` (last 20 bytes of public key) | 20 bytes |
//! | `tls_cert_fingerprint` | Zeroed (placeholder, set when TLS cert configured) | 32 bytes |
//!
//! ### Operator Address Derivation
//!
//! `operator_address` is derived as the **last 20 bytes** of the 32-byte
//! Ed25519 public key (`node_id[12..32]`). This approach:
//!
//! - Requires no additional cryptographic dependencies (no hash function).
//! - Is deterministic: same keypair always produces the same address.
//! - Provides 160 bits of the public key's entropy.
//! - Follows the blockchain convention of using trailing bytes for
//!   address derivation.
//!
//! In production deployments where the operator's wallet address differs
//! from the node key, the operator binding mechanism
//! (`NodeIdentity::verify_operator_binding`) provides cryptographic proof
//! that the node key holder authorized a specific operator address.
//!
//! ## Cryptographic Signing Convention
//!
//! The `sign_challenge` method signs the **raw 32-byte nonce** (no prefix,
//! no suffix) using Ed25519 via `ed25519_dalek::SigningKey::sign`. This
//! matches the verification convention in `IdentityVerifier::verify_proof`
//! (14B.22) and `IdentityProof::verify()`, which use
//! `VerifyingKey::verify_strict(&challenge.nonce, &signature)`.
//!
//! ## Safety
//!
//! - No `panic!`, `unwrap()`, `expect()`.
//! - Private key bytes are never exposed via any public method.
//! - `node_id()` and `operator_address()` return references without allocation.
//! - `SigningKey` is held as an owned field; cloning is intentional and
//!   minimal (only when constructing the manager, never in accessor methods).
//! - No `unsafe` code.
//! - All types are `Send + Sync` (no interior mutability, no `Rc`, no raw pointers).
//!
//! ## Determinism
//!
//! - `from_keypair`: Fully deterministic — same 32-byte secret always
//!   produces the same `NodeIdentityManager` with identical `node_id`,
//!   `operator_address`, and signing behavior.
//! - `generate`: Non-deterministic (uses OS-provided randomness via `OsRng`).
//!   All subsequent operations on the resulting manager are deterministic.
//! - `sign_challenge`: Deterministic for the same `(keypair, nonce)` pair.
//!   Ed25519 signing is deterministic (RFC 8032).

use std::fmt;

use dsdn_common::gating::{IdentityChallenge, IdentityProof, NodeIdentity};
use ed25519_dalek::{Signer, SigningKey};

// ════════════════════════════════════════════════════════════════════════════════
// ERROR TYPE
// ════════════════════════════════════════════════════════════════════════════════

/// Error type for node identity management operations.
///
/// All variants carry no sensitive key material — error messages are
/// safe to log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityError {
    /// Random key generation failed (OS entropy source unavailable).
    KeyGenerationFailed,
    /// The provided 32-byte secret key is invalid.
    ///
    /// Note: In ed25519-dalek v2, all 32-byte arrays are technically
    /// valid Ed25519 secret keys. This variant exists for forward
    /// compatibility and external validation requirements.
    InvalidSecretKey,
    /// A signing operation failed.
    ///
    /// Note: Ed25519 signing with a valid `SigningKey` is infallible
    /// in ed25519-dalek. This variant exists for forward compatibility
    /// and alternative signing backends.
    SigningFailed,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityError::KeyGenerationFailed => {
                write!(f, "Ed25519 key generation failed: OS entropy source unavailable")
            }
            IdentityError::InvalidSecretKey => {
                write!(f, "invalid Ed25519 secret key")
            }
            IdentityError::SigningFailed => {
                write!(f, "Ed25519 signing operation failed")
            }
        }
    }
}

impl std::error::Error for IdentityError {}

// ════════════════════════════════════════════════════════════════════════════════
// NODE IDENTITY MANAGER
// ════════════════════════════════════════════════════════════════════════════════

/// Manages a service node's Ed25519 keypair and cryptographic identity.
///
/// Holds the Ed25519 signing key (private) and the derived [`NodeIdentity`]
/// (public). Provides methods for signing challenge nonces and constructing
/// identity proofs for coordinator admission.
///
/// ## Security
///
/// The `SigningKey` is never exposed via any public method. The struct
/// intentionally does NOT implement `Serialize`, `Clone` for the signing
/// key field, or any method that returns key material.
///
/// ## Thread Safety
///
/// `NodeIdentityManager` is `Send + Sync`. All fields are owned values
/// with no interior mutability.
pub struct NodeIdentityManager {
    /// Ed25519 signing key (private). Never exposed publicly.
    signing_key: SigningKey,
    /// Derived public identity: node_id, operator_address, tls_cert_fingerprint.
    identity: NodeIdentity,
}

impl NodeIdentityManager {
    /// Generates a new `NodeIdentityManager` with a random Ed25519 keypair.
    ///
    /// Uses `OsRng` for cryptographically secure random number generation.
    /// The resulting keypair is unique with overwhelming probability.
    ///
    /// ## Returns
    ///
    /// - `Ok(Self)` with a freshly generated keypair and derived identity.
    /// - `Err(IdentityError::KeyGenerationFailed)` if the OS entropy source
    ///   is unavailable (extremely rare on modern systems).
    ///
    /// ## Non-Determinism
    ///
    /// This method is intentionally non-deterministic — each call produces
    /// a unique keypair. For deterministic construction from a known secret,
    /// use [`from_keypair`](Self::from_keypair).
    pub fn generate() -> Result<Self, IdentityError> {
        let mut rng = rand::rngs::OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let identity = derive_identity(&signing_key);
        Ok(Self {
            signing_key,
            identity,
        })
    }

    /// Constructs a `NodeIdentityManager` from a 32-byte Ed25519 secret key.
    ///
    /// The public key, `node_id`, and `operator_address` are derived
    /// deterministically from the secret. Same 32-byte input always
    /// produces the same manager state.
    ///
    /// ## Parameters
    ///
    /// - `secret`: 32-byte Ed25519 secret key (seed). The caller is
    ///   responsible for securely sourcing this value (e.g., from an
    ///   encrypted keystore or secure enclave). The array is consumed
    ///   by value — the caller's copy may be zeroed after this call.
    ///
    /// ## Returns
    ///
    /// - `Ok(Self)` with the keypair and derived identity.
    /// - `Err(IdentityError::InvalidSecretKey)` is reserved for future
    ///   validation requirements. In ed25519-dalek v2, all 32-byte
    ///   arrays are valid secret keys.
    ///
    /// ## Determinism
    ///
    /// Fully deterministic: same `secret` always produces identical
    /// `node_id`, `operator_address`, and signing behavior.
    pub fn from_keypair(secret: [u8; 32]) -> Result<Self, IdentityError> {
        let signing_key = SigningKey::from_bytes(&secret);
        let identity = derive_identity(&signing_key);
        Ok(Self {
            signing_key,
            identity,
        })
    }

    /// Returns a reference to the 32-byte Ed25519 public key (node ID).
    ///
    /// This is the same value stored in `NodeIdentity::node_id` and used
    /// as the registry key (hex-encoded) in the coordinator's GateKeeper.
    ///
    /// ## Performance
    ///
    /// Zero-allocation: returns a reference to the stored byte array.
    #[inline]
    pub fn node_id(&self) -> &[u8; 32] {
        &self.identity.node_id
    }

    /// Returns a reference to the 20-byte operator address.
    ///
    /// Derived from `node_id[12..32]` (last 20 bytes of the public key).
    /// See module-level documentation for derivation details.
    ///
    /// ## Performance
    ///
    /// Zero-allocation: returns a reference to the stored byte array.
    #[inline]
    pub fn operator_address(&self) -> &[u8; 20] {
        &self.identity.operator_address
    }

    /// Returns a reference to the full [`NodeIdentity`].
    ///
    /// Useful when constructing an [`AdmissionRequest`] or any other
    /// structure that requires the complete identity.
    #[inline]
    pub fn identity(&self) -> &NodeIdentity {
        &self.identity
    }

    /// Signs a 32-byte challenge nonce using the node's Ed25519 private key.
    ///
    /// The signature is computed over the **raw nonce bytes** (no prefix,
    /// no suffix, no domain separator). This matches the verification
    /// convention in `IdentityVerifier::verify_proof` (14B.22) and
    /// `IdentityProof::verify()`.
    ///
    /// ## Parameters
    ///
    /// - `nonce`: The 32-byte challenge nonce to sign.
    ///
    /// ## Returns
    ///
    /// A 64-byte Ed25519 signature. Ed25519 signing is deterministic
    /// (RFC 8032): the same `(key, nonce)` pair always produces the
    /// same signature.
    ///
    /// ## Infallibility
    ///
    /// Ed25519 signing with a valid `SigningKey` never fails in
    /// ed25519-dalek. This method returns the signature directly
    /// (not wrapped in `Result`) because construction ensures the
    /// signing key is always valid.
    pub fn sign_challenge(&self, nonce: &[u8; 32]) -> [u8; 64] {
        let signature = self.signing_key.sign(nonce);
        signature.to_bytes()
    }

    /// Signs an arbitrary-length message using the node's Ed25519 private key.
    ///
    /// Unlike [`sign_challenge`] which only accepts 32-byte nonces, this
    /// method signs messages of any length. Used by `UsageProofBuilder`
    /// to sign the 148-byte usage proof message.
    ///
    /// ## Parameters
    ///
    /// - `message`: Byte slice to sign (any length).
    ///
    /// ## Returns
    ///
    /// A 64-byte Ed25519 signature. Deterministic per RFC 8032:
    /// same `(key, message)` always produces the same signature.
    pub fn sign_message(&self, message: &[u8]) -> [u8; 64] {
        let signature = self.signing_key.sign(message);
        signature.to_bytes()
    }

    /// Creates a complete [`IdentityProof`] for coordinator admission.
    ///
    /// Signs the challenge nonce and packages the signature with the
    /// challenge and the node's public identity into an `IdentityProof`
    /// ready for submission to the coordinator's `GateKeeper`.
    ///
    /// ## Parameters
    ///
    /// - `challenge`: The identity challenge received from the coordinator.
    ///   Contains a nonce, timestamp, and challenger identifier.
    ///   Consumed by value (moved into the proof).
    ///
    /// ## Returns
    ///
    /// A complete `IdentityProof` containing:
    /// - The original challenge (moved).
    /// - The Ed25519 signature over `challenge.nonce`.
    /// - A clone of this manager's `NodeIdentity`.
    ///
    /// ## Verification
    ///
    /// The returned proof can be verified by `IdentityProof::verify()`
    /// or `IdentityVerifier::verify_proof()`. Both use
    /// `VerifyingKey::verify_strict(&challenge.nonce, &signature)`.
    pub fn create_identity_proof(&self, challenge: IdentityChallenge) -> IdentityProof {
        let signature = self.sign_challenge(&challenge.nonce);
        IdentityProof {
            challenge,
            signature,
            node_identity: self.identity.clone(),
        }
    }
}

// Manual Debug implementation: never print the signing key.
impl fmt::Debug for NodeIdentityManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeIdentityManager")
            .field("identity", &self.identity)
            .field("signing_key", &"[REDACTED]")
            .finish()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS (module-private)
// ════════════════════════════════════════════════════════════════════════════════

/// Derives a [`NodeIdentity`] from an Ed25519 signing key.
///
/// ## Derivation
///
/// - `node_id`: 32-byte Ed25519 public key (`verifying_key.to_bytes()`).
/// - `operator_address`: Last 20 bytes of `node_id` (`node_id[12..32]`).
/// - `tls_cert_fingerprint`: Zeroed `[0u8; 32]` (placeholder — to be
///   updated when TLS certificate is configured).
///
/// ## Determinism
///
/// Same `signing_key` always produces the same `NodeIdentity`.
fn derive_identity(signing_key: &SigningKey) -> NodeIdentity {
    let verifying_key = signing_key.verifying_key();
    let node_id = verifying_key.to_bytes();

    // Operator address: last 20 bytes of the public key.
    // Uses a fixed-size array copy to avoid any allocation.
    let mut operator_address = [0u8; 20];
    operator_address.copy_from_slice(&node_id[12..32]);

    NodeIdentity {
        node_id,
        operator_address,
        tls_cert_fingerprint: [0u8; 32],
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// COMPILE-TIME ASSERTIONS
// ════════════════════════════════════════════════════════════════════════════════

/// Compile-time assertion: `NodeIdentityManager` is `Send`.
const _: () = {
    fn assert_send<T: Send>() {}
    fn check() {
        assert_send::<NodeIdentityManager>();
    }
    let _ = check;
};

/// Compile-time assertion: `NodeIdentityManager` is `Sync`.
const _: () = {
    fn assert_sync<T: Sync>() {}
    fn check() {
        assert_sync::<NodeIdentityManager>();
    }
    let _ = check;
};

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic test seed for reproducible tests.
    const TEST_SEED: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    ];

    /// Fixed timestamp for test determinism.
    const TEST_TS: u64 = 1_700_000_000;

    // ──────────────────────────────────────────────────────────────────
    // CONSTRUCTION
    // ──────────────────────────────────────────────────────────────────

    /// `generate()` produces a valid manager.
    #[test]
    fn test_generate_produces_valid_manager() {
        let mgr = NodeIdentityManager::generate();
        assert!(mgr.is_ok());
        if let Ok(m) = mgr {
            // node_id is 32 bytes (always true for [u8; 32]).
            assert_eq!(m.node_id().len(), 32);
            // operator_address is 20 bytes.
            assert_eq!(m.operator_address().len(), 20);
        }
    }

    /// `from_keypair` is deterministic: same seed → same identity.
    #[test]
    fn test_from_keypair_deterministic() {
        let mgr1 = NodeIdentityManager::from_keypair(TEST_SEED);
        let mgr2 = NodeIdentityManager::from_keypair(TEST_SEED);
        assert!(mgr1.is_ok());
        assert!(mgr2.is_ok());
        if let (Ok(m1), Ok(m2)) = (mgr1, mgr2) {
            assert_eq!(m1.node_id(), m2.node_id());
            assert_eq!(m1.operator_address(), m2.operator_address());
            assert_eq!(m1.identity(), m2.identity());
        }
    }

    /// Two different seeds produce different identities.
    #[test]
    fn test_different_seeds_different_identities() {
        let seed2 = [0xFFu8; 32];
        let mgr1 = NodeIdentityManager::from_keypair(TEST_SEED);
        let mgr2 = NodeIdentityManager::from_keypair(seed2);
        assert!(mgr1.is_ok());
        assert!(mgr2.is_ok());
        if let (Ok(m1), Ok(m2)) = (mgr1, mgr2) {
            assert_ne!(m1.node_id(), m2.node_id());
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // IDENTITY DERIVATION
    // ──────────────────────────────────────────────────────────────────

    /// `node_id` equals the Ed25519 public key bytes.
    #[test]
    fn test_node_id_is_public_key() {
        let signing_key = SigningKey::from_bytes(&TEST_SEED);
        let expected_pubkey = signing_key.verifying_key().to_bytes();

        let mgr = NodeIdentityManager::from_keypair(TEST_SEED);
        assert!(mgr.is_ok());
        if let Ok(m) = mgr {
            assert_eq!(*m.node_id(), expected_pubkey);
        }
    }

    /// `operator_address` equals `node_id[12..32]`.
    #[test]
    fn test_operator_address_derivation() {
        let mgr = NodeIdentityManager::from_keypair(TEST_SEED);
        assert!(mgr.is_ok());
        if let Ok(m) = mgr {
            let node_id = m.node_id();
            let op_addr = m.operator_address();
            assert_eq!(&node_id[12..32], op_addr.as_slice());
        }
    }

    /// `tls_cert_fingerprint` is zeroed (placeholder).
    #[test]
    fn test_tls_fingerprint_zeroed() {
        let mgr = NodeIdentityManager::from_keypair(TEST_SEED);
        assert!(mgr.is_ok());
        if let Ok(m) = mgr {
            assert_eq!(m.identity().tls_cert_fingerprint, [0u8; 32]);
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // SIGNING
    // ──────────────────────────────────────────────────────────────────

    /// `sign_challenge` produces a 64-byte signature.
    #[test]
    fn test_sign_challenge_length() {
        let mgr = NodeIdentityManager::from_keypair(TEST_SEED);
        assert!(mgr.is_ok());
        if let Ok(m) = mgr {
            let nonce = [0x42u8; 32];
            let sig = m.sign_challenge(&nonce);
            assert_eq!(sig.len(), 64);
        }
    }

    /// `sign_challenge` is deterministic: same (key, nonce) → same signature.
    #[test]
    fn test_sign_challenge_deterministic() {
        let mgr1 = NodeIdentityManager::from_keypair(TEST_SEED);
        let mgr2 = NodeIdentityManager::from_keypair(TEST_SEED);
        assert!(mgr1.is_ok());
        assert!(mgr2.is_ok());
        if let (Ok(m1), Ok(m2)) = (mgr1, mgr2) {
            let nonce = [0x42u8; 32];
            let sig1 = m1.sign_challenge(&nonce);
            let sig2 = m2.sign_challenge(&nonce);
            assert_eq!(sig1, sig2);
        }
    }

    /// Signature is verifiable using `IdentityProof::verify()`.
    #[test]
    fn test_sign_challenge_verifiable() {
        let mgr = NodeIdentityManager::from_keypair(TEST_SEED);
        assert!(mgr.is_ok());
        if let Ok(m) = mgr {
            let nonce = [0x42u8; 32];
            let sig_bytes = m.sign_challenge(&nonce);

            // Manually verify using ed25519-dalek.
            let pubkey = ed25519_dalek::VerifyingKey::from_bytes(m.node_id());
            assert!(pubkey.is_ok());
            if let Ok(pk) = pubkey {
                let sig = ed25519_dalek::Signature::from_slice(&sig_bytes);
                assert!(sig.is_ok());
                if let Ok(s) = sig {
                    let result = pk.verify_strict(&nonce, &s);
                    assert!(result.is_ok());
                }
            }
        }
    }

    /// Different nonces produce different signatures.
    #[test]
    fn test_different_nonces_different_signatures() {
        let mgr = NodeIdentityManager::from_keypair(TEST_SEED);
        assert!(mgr.is_ok());
        if let Ok(m) = mgr {
            let nonce1 = [0x42u8; 32];
            let nonce2 = [0x43u8; 32];
            let sig1 = m.sign_challenge(&nonce1);
            let sig2 = m.sign_challenge(&nonce2);
            assert_ne!(sig1, sig2);
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // IDENTITY PROOF
    // ──────────────────────────────────────────────────────────────────

    /// `create_identity_proof` produces a valid, verifiable proof.
    #[test]
    fn test_create_identity_proof_valid() {
        let mgr = NodeIdentityManager::from_keypair(TEST_SEED);
        assert!(mgr.is_ok());
        if let Ok(m) = mgr {
            let challenge = IdentityChallenge {
                nonce: [0x42u8; 32],
                timestamp: TEST_TS,
                challenger: "coordinator".to_string(),
            };

            let proof = m.create_identity_proof(challenge);

            // Proof should be verifiable via IdentityProof::verify().
            assert!(proof.verify());

            // Proof fields should match.
            assert_eq!(proof.challenge.nonce, [0x42u8; 32]);
            assert_eq!(proof.challenge.timestamp, TEST_TS);
            assert_eq!(proof.challenge.challenger, "coordinator");
            assert_eq!(proof.node_identity.node_id, *m.node_id());
            assert_eq!(proof.node_identity.operator_address, *m.operator_address());
        }
    }

    /// Identity proof signature matches `sign_challenge` output.
    #[test]
    fn test_identity_proof_signature_consistency() {
        let mgr = NodeIdentityManager::from_keypair(TEST_SEED);
        assert!(mgr.is_ok());
        if let Ok(m) = mgr {
            let nonce = [0x42u8; 32];
            let direct_sig = m.sign_challenge(&nonce);

            let challenge = IdentityChallenge {
                nonce,
                timestamp: TEST_TS,
                challenger: "test".to_string(),
            };
            let proof = m.create_identity_proof(challenge);

            assert_eq!(proof.signature, direct_sig);
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // ERROR TYPE
    // ──────────────────────────────────────────────────────────────────

    /// IdentityError variants have distinct Display output.
    #[test]
    fn test_identity_error_display() {
        let e1 = IdentityError::KeyGenerationFailed;
        let e2 = IdentityError::InvalidSecretKey;
        let e3 = IdentityError::SigningFailed;

        let s1 = format!("{}", e1);
        let s2 = format!("{}", e2);
        let s3 = format!("{}", e3);

        assert!(!s1.is_empty());
        assert!(!s2.is_empty());
        assert!(!s3.is_empty());
        assert_ne!(s1, s2);
        assert_ne!(s2, s3);
    }

    /// IdentityError implements std::error::Error.
    #[test]
    fn test_identity_error_is_error() {
        let e: Box<dyn std::error::Error> = Box::new(IdentityError::KeyGenerationFailed);
        // If this compiles, the trait is implemented correctly.
        let _ = format!("{}", e);
    }

    // ──────────────────────────────────────────────────────────────────
    // DEBUG SAFETY
    // ──────────────────────────────────────────────────────────────────

    /// Debug output does NOT contain private key material.
    #[test]
    fn test_debug_redacts_key() {
        let mgr = NodeIdentityManager::from_keypair(TEST_SEED);
        assert!(mgr.is_ok());
        if let Ok(m) = mgr {
            let debug_str = format!("{:?}", m);
            assert!(debug_str.contains("REDACTED"));
            // Ensure the raw seed bytes are not in the debug output.
            // Check for hex representation of the first few seed bytes.
            let seed_hex = "0102030405060708";
            assert!(!debug_str.contains(seed_hex));
        }
    }
}