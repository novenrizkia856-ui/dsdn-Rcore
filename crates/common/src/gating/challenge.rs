//! # Identity Challenge–Response (14B.9)
//!
//! Defines the challenge–response mechanism for verifying cryptographic
//! ownership of a node identity. A challenger issues an `IdentityChallenge`
//! containing a random nonce, and the node produces an `IdentityProof`
//! by signing the raw nonce with its Ed25519 private key.
//!
//! ## Verification
//!
//! `IdentityProof::verify()` performs strict Ed25519 signature verification:
//!
//! - **Public key**: `node_identity.node_id` (32 bytes)
//! - **Message**: `challenge.nonce` (32 bytes, raw, no prefix or suffix)
//! - **Signature**: `signature` (64 bytes)
//! - **Method**: `ed25519_dalek::VerifyingKey::verify_strict`
//!
//! The verification rejects weak keys, small-order points, and
//! non-canonical signatures. There is no implicit trust — a valid
//! proof only confirms that the signer possesses the private key
//! corresponding to `node_identity.node_id`.
//!
//! ## Safety Properties
//!
//! - No nonce generation inside this module — the nonce is an opaque input.
//! - No system clock access — the timestamp is a caller-provided input.
//! - No modification of the challenge during verification.
//! - No panics — all crypto failures return `false`.
//! - No logging, no error swallowing, no side effects.

use serde::{Deserialize, Serialize};

use super::identity::NodeIdentity;

// ════════════════════════════════════════════════════════════════════════════════
// SERDE HELPER — [u8; 64]
// ════════════════════════════════════════════════════════════════════════════════

/// Custom serde module for `[u8; 64]` arrays.
///
/// `serde` only implements `Serialize`/`Deserialize` for arrays up to
/// 32 elements by default. This module bridges the gap for Ed25519
/// signatures (64 bytes) without adding external dependencies.
mod serde_signature {
    use serde::de::{self, Deserializer, SeqAccess, Visitor};
    use serde::ser::{SerializeTuple, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_tuple(64)?;
        for b in bytes.iter() {
            seq.serialize_element(b)?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 64], D::Error> {
        struct ArrayVisitor;

        impl<'de> Visitor<'de> for ArrayVisitor {
            type Value = [u8; 64];

            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "an array of 64 bytes")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<[u8; 64], A::Error> {
                let mut arr = [0u8; 64];
                for (i, byte) in arr.iter_mut().enumerate() {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(i, &self))?;
                }
                Ok(arr)
            }
        }

        deserializer.deserialize_tuple(64, ArrayVisitor)
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// IDENTITY CHALLENGE
// ════════════════════════════════════════════════════════════════════════════════

/// A challenge issued to a node to prove ownership of its identity.
///
/// The challenger generates a random nonce and sends it to the node.
/// The node signs the raw nonce with its Ed25519 private key and
/// returns an [`IdentityProof`].
///
/// ## Fields
///
/// - `nonce`: 32 bytes of opaque challenge data. Must be generated
///   externally (e.g., by the coordinator) and is never modified
///   by this module.
/// - `timestamp`: Unix timestamp (seconds) when the challenge was
///   issued. Caller-provided, not derived from the system clock.
/// - `challenger`: Identifier of the entity that issued the challenge
///   (e.g., `"coordinator"`, `"registry"`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityChallenge {
    /// 32 bytes of opaque challenge data (generated externally).
    pub nonce: [u8; 32],
    /// Unix timestamp (seconds) when the challenge was issued.
    pub timestamp: u64,
    /// Identifier of the challenger (e.g., "coordinator").
    pub challenger: String,
}

// ════════════════════════════════════════════════════════════════════════════════
// IDENTITY PROOF
// ════════════════════════════════════════════════════════════════════════════════

/// A node's response to an [`IdentityChallenge`], proving ownership
/// of its Ed25519 private key.
///
/// The proof contains the original challenge, the Ed25519 signature
/// over the raw nonce, and the node's identity (which includes the
/// public key to verify against).
///
/// ## Verification
///
/// Call [`verify()`](IdentityProof::verify) to perform strict Ed25519
/// verification. The signature is verified against the raw `challenge.nonce`
/// bytes (no prefix, no suffix, no domain separator) using the public
/// key from `node_identity.node_id`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityProof {
    /// The original challenge that was signed.
    pub challenge: IdentityChallenge,
    /// Ed25519 signature (64 bytes) over `challenge.nonce`.
    #[serde(with = "serde_signature")]
    pub signature: [u8; 64],
    /// The node identity containing the public key for verification.
    pub node_identity: NodeIdentity,
}

impl IdentityProof {
    /// Verifies the identity proof using Ed25519 strict verification.
    ///
    /// ## Verification Steps
    ///
    /// 1. Parse `node_identity.node_id` as an Ed25519 public key.
    /// 2. Parse `signature` as an Ed25519 signature.
    /// 3. Verify the signature against `challenge.nonce` (raw 32 bytes,
    ///    no prefix or suffix).
    ///
    /// ## Returns
    ///
    /// - `true` if the signature is valid for the given public key
    ///   and nonce.
    /// - `false` if any step fails: invalid public key, invalid
    ///   signature encoding, or signature mismatch.
    ///
    /// ## Safety
    ///
    /// - Uses `verify_strict` which rejects weak keys, small-order
    ///   points, and non-canonical signatures.
    /// - Never panics — all crypto errors are caught and return `false`.
    /// - Does not modify the challenge or any field.
    /// - No logging, no side effects.
    #[must_use]
    pub fn verify(&self) -> bool {
        // Step 1: Parse the public key from node_id
        let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(
            &self.node_identity.node_id,
        ) {
            Ok(key) => key,
            Err(_) => return false,
        };

        // Step 2: Parse the signature bytes
        let sig = match ed25519_dalek::Signature::from_slice(&self.signature) {
            Ok(s) => s,
            Err(_) => return false,
        };

        // Step 3: Verify signature against raw nonce (no prefix/suffix)
        verifying_key.verify_strict(&self.challenge.nonce, &sig).is_ok()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    // ──────────────────────────────────────────────────────────────────────
    // HELPERS
    // ──────────────────────────────────────────────────────────────────────

    fn make_challenge() -> IdentityChallenge {
        IdentityChallenge {
            nonce: [0x42; 32],
            timestamp: 1_700_000_000,
            challenger: "coordinator".to_string(),
        }
    }

    /// Creates a valid IdentityProof using a real Ed25519 keypair.
    fn make_valid_proof() -> (IdentityProof, SigningKey) {
        // Deterministic seed for reproducible tests
        let seed: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
        ];
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        let challenge = make_challenge();

        // Sign the RAW NONCE (no prefix, no suffix)
        let sig = signing_key.sign(&challenge.nonce);

        let node_identity = NodeIdentity {
            node_id: verifying_key.to_bytes(),
            operator_address: [0xBB; 20],
            tls_cert_fingerprint: [0xCC; 32],
        };

        let proof = IdentityProof {
            challenge,
            signature: sig.to_bytes(),
            node_identity,
        };

        (proof, signing_key)
    }

    // ──────────────────────────────────────────────────────────────────────
    // IdentityChallenge — BASIC
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_challenge_fields() {
        let ch = make_challenge();
        assert_eq!(ch.nonce, [0x42; 32]);
        assert_eq!(ch.timestamp, 1_700_000_000);
        assert_eq!(ch.challenger, "coordinator");
    }

    // ──────────────────────────────────────────────────────────────────────
    // IdentityChallenge — TRAITS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_challenge_clone() {
        let ch = make_challenge();
        let cloned = ch.clone();
        assert_eq!(ch, cloned);
    }

    #[test]
    fn test_challenge_debug() {
        let ch = make_challenge();
        let debug = format!("{:?}", ch);
        assert!(debug.contains("IdentityChallenge"));
        assert!(debug.contains("coordinator"));
    }

    #[test]
    fn test_challenge_eq() {
        let a = make_challenge();
        let b = make_challenge();
        assert_eq!(a, b);
    }

    #[test]
    fn test_challenge_ne_nonce() {
        let a = make_challenge();
        let mut b = make_challenge();
        b.nonce = [0xFF; 32];
        assert_ne!(a, b);
    }

    #[test]
    fn test_challenge_ne_timestamp() {
        let a = make_challenge();
        let mut b = make_challenge();
        b.timestamp = 999;
        assert_ne!(a, b);
    }

    #[test]
    fn test_challenge_ne_challenger() {
        let a = make_challenge();
        let mut b = make_challenge();
        b.challenger = "registry".to_string();
        assert_ne!(a, b);
    }

    #[test]
    fn test_challenge_serde() {
        let ch = make_challenge();
        let json = serde_json::to_string(&ch).expect("serialize");
        let back: IdentityChallenge =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ch, back);
    }

    // ──────────────────────────────────────────────────────────────────────
    // IdentityProof — VERIFY (VALID)
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_verify_valid_proof() {
        let (proof, _) = make_valid_proof();
        assert!(proof.verify());
    }

    #[test]
    fn test_verify_deterministic() {
        let (proof, _) = make_valid_proof();
        let r1 = proof.verify();
        let r2 = proof.verify();
        let r3 = proof.verify();
        assert_eq!(r1, r2);
        assert_eq!(r2, r3);
        assert!(r1);
    }

    // ──────────────────────────────────────────────────────────────────────
    // IdentityProof — VERIFY (INVALID)
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_verify_wrong_public_key() {
        let (mut proof, _) = make_valid_proof();
        // Replace node_id with a different (valid) key
        let other_seed: [u8; 32] = [0xFF; 32];
        let other_key = SigningKey::from_bytes(&other_seed);
        proof.node_identity.node_id = other_key.verifying_key().to_bytes();
        assert!(!proof.verify());
    }

    #[test]
    fn test_verify_tampered_nonce() {
        let (mut proof, _) = make_valid_proof();
        // Change one byte of the nonce
        proof.challenge.nonce[0] ^= 0x01;
        assert!(!proof.verify());
    }

    #[test]
    fn test_verify_tampered_signature() {
        let (mut proof, _) = make_valid_proof();
        // Flip one bit in the signature
        proof.signature[0] ^= 0x01;
        assert!(!proof.verify());
    }

    #[test]
    fn test_verify_zero_signature() {
        let (mut proof, _) = make_valid_proof();
        proof.signature = [0u8; 64];
        assert!(!proof.verify());
    }

    #[test]
    fn test_verify_zero_public_key() {
        let (mut proof, _) = make_valid_proof();
        proof.node_identity.node_id = [0u8; 32];
        // [0; 32] is not a valid Ed25519 public key
        assert!(!proof.verify());
    }

    #[test]
    fn test_verify_wrong_key_right_nonce() {
        // Sign with key A, verify with key B → must fail
        let (proof_a, _) = make_valid_proof();

        let other_seed: [u8; 32] = [0x99; 32];
        let other_signing = SigningKey::from_bytes(&other_seed);

        let mut proof_b = proof_a;
        proof_b.node_identity.node_id = other_signing.verifying_key().to_bytes();
        assert!(!proof_b.verify());
    }

    #[test]
    fn test_verify_signature_for_different_nonce() {
        // Sign nonce A, present with nonce B → must fail
        let seed: [u8; 32] = [0x01; 32];
        let signing_key = SigningKey::from_bytes(&seed);

        let nonce_a = [0xAA; 32];
        let nonce_b = [0xBB; 32];

        let sig = signing_key.sign(&nonce_a);

        let proof = IdentityProof {
            challenge: IdentityChallenge {
                nonce: nonce_b, // Different nonce than what was signed
                timestamp: 1_000,
                challenger: "test".to_string(),
            },
            signature: sig.to_bytes(),
            node_identity: NodeIdentity {
                node_id: signing_key.verifying_key().to_bytes(),
                operator_address: [0; 20],
                tls_cert_fingerprint: [0; 32],
            },
        };
        assert!(!proof.verify());
    }

    // ──────────────────────────────────────────────────────────────────────
    // IdentityProof — VERIFY IGNORES NON-CRYPTO FIELDS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_verify_ignores_timestamp() {
        let (mut proof, _) = make_valid_proof();
        proof.challenge.timestamp = 0;
        // Timestamp does not affect signature verification
        assert!(proof.verify());
    }

    #[test]
    fn test_verify_ignores_challenger() {
        let (mut proof, _) = make_valid_proof();
        proof.challenge.challenger = "different".to_string();
        // Challenger does not affect signature verification
        assert!(proof.verify());
    }

    #[test]
    fn test_verify_ignores_operator_address() {
        let (mut proof, _) = make_valid_proof();
        proof.node_identity.operator_address = [0xFF; 20];
        // operator_address not used in verify
        assert!(proof.verify());
    }

    #[test]
    fn test_verify_ignores_tls_fingerprint() {
        let (mut proof, _) = make_valid_proof();
        proof.node_identity.tls_cert_fingerprint = [0xFF; 32];
        // tls_cert_fingerprint not used in verify
        assert!(proof.verify());
    }

    // ──────────────────────────────────────────────────────────────────────
    // IdentityProof — TRAITS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_proof_clone() {
        let (proof, _) = make_valid_proof();
        let cloned = proof.clone();
        assert_eq!(proof, cloned);
    }

    #[test]
    fn test_proof_debug() {
        let (proof, _) = make_valid_proof();
        let debug = format!("{:?}", proof);
        assert!(debug.contains("IdentityProof"));
    }

    #[test]
    fn test_proof_eq() {
        let (a, _) = make_valid_proof();
        let (b, _) = make_valid_proof();
        assert_eq!(a, b);
    }

    #[test]
    fn test_proof_ne() {
        let (a, _) = make_valid_proof();
        let mut b = a.clone();
        b.signature[0] ^= 0x01;
        assert_ne!(a, b);
    }

    #[test]
    fn test_proof_serde() {
        let (proof, _) = make_valid_proof();
        let json = serde_json::to_string(&proof).expect("serialize");
        let back: IdentityProof =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(proof, back);
    }

    #[test]
    fn test_proof_serde_roundtrip_still_verifies() {
        let (proof, _) = make_valid_proof();
        let json = serde_json::to_string(&proof).expect("serialize");
        let back: IdentityProof =
            serde_json::from_str(&json).expect("deserialize");
        assert!(back.verify());
    }

    // ──────────────────────────────────────────────────────────────────────
    // SEND + SYNC
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<IdentityChallenge>();
        assert_send_sync::<IdentityProof>();
    }
}