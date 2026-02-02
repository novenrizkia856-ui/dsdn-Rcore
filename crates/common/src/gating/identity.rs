//! # Node Identity & Class Types (14B.1)
//!
//! Foundation types for the DSDN Gating System.
//!
//! ## Overview
//!
//! This module defines the core identity and classification types that serve
//! as the foundation for the entire DSDN gating system. Every subsequent
//! gating component depends on these types.
//!
//! ## Types
//!
//! | Type | Purpose |
//! |------|---------|
//! | `NodeIdentity` | Cryptographic identity binding node key, operator wallet, and TLS cert |
//! | `NodeClass` | Classification determining node capabilities and stake requirements |
//! | `IdentityError` | Structured error type for identity verification operations |
//!
//! ## Operator Binding Verification
//!
//! `NodeIdentity::verify_operator_binding` verifies that an operator wallet address
//! is cryptographically bound to a node's Ed25519 public key. The signed message
//! is constructed deterministically:
//!
//! ```text
//! message = b"DSDN:operator_binding:v1:" || node_id (32 bytes) || operator_address (20 bytes)
//! ```
//!
//! The signature is verified using Ed25519 `verify_strict` against the `node_id`
//! public key. This proves the holder of the node's private key authorized the
//! binding to the specified operator address.
//!
//! ## Stake Requirements
//!
//! | Class | Minimum Stake |
//! |-------|---------------|
//! | Storage | 5000 NUSA |
//! | Compute | 500 NUSA |
//!
//! Values returned by `NodeClass::min_stake()` are in NUSA token units.
//! On-chain smallest-unit conversion (e.g., multiplying by 10^18 for
//! decimal precision) is handled by `StakeRequirement` (14B.3).
//!
//! ## Security
//!
//! - Operator binding uses domain-separated, versioned message format
//! - Ed25519 `verify_strict` rejects weak keys and small-order points
//! - All errors are explicit and structured; no silent failures
//! - No `panic!`, `unwrap()`, or `expect()` in any code path

use serde::{Deserialize, Serialize};
use std::fmt;
use std::hash::{Hash, Hasher};

// ════════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════════

/// Domain separator for operator binding signature verification.
///
/// The binding message is constructed as:
///
/// ```text
/// b"DSDN:operator_binding:v1:" || node_id[0..32] || operator_address[0..20]
/// ```
///
/// Properties:
/// - **Domain-separated**: Prevents cross-protocol signature replay attacks.
///   A signature valid for operator binding cannot be replayed in a different
///   DSDN subsystem or an external protocol.
/// - **Versioned**: The `v1` tag allows future format evolution without
///   ambiguity. A `v2` message will never collide with `v1`.
/// - **Fixed-length components**: `node_id` (32 bytes) + `operator_address` (20 bytes).
///   The concatenation is unambiguous because both lengths are fixed.
/// - **Total message length**: 25 + 32 + 20 = 77 bytes.
const OPERATOR_BINDING_DOMAIN: &[u8] = b"DSDN:operator_binding:v1:";

/// Minimum stake for Storage class nodes, in NUSA token units.
///
/// Value: 5000 NUSA.
///
/// This is the human-readable NUSA amount. On-chain representation with
/// decimal precision (e.g., 5000 × 10^18 for 18-decimal tokens) is
/// handled by `StakeRequirement` in tahap 14B.3.
const STORAGE_MIN_STAKE_NUSA: u128 = 5_000;

/// Minimum stake for Compute class nodes, in NUSA token units.
///
/// Value: 500 NUSA.
///
/// See `STORAGE_MIN_STAKE_NUSA` for unit documentation.
const COMPUTE_MIN_STAKE_NUSA: u128 = 500;

// ════════════════════════════════════════════════════════════════════════════════
// ERROR TYPE
// ════════════════════════════════════════════════════════════════════════════════

/// Error type for identity verification operations.
///
/// All variants carry structured context for diagnostics.
/// Implements `std::error::Error` and `Display`.
///
/// ## Error Semantics
///
/// | Variant | Meaning | Recoverability |
/// |---------|---------|----------------|
/// | `InvalidSignatureLength` | Input signature has wrong byte count | Fix input |
/// | `InvalidPublicKey` | `node_id` is not a valid Ed25519 point | Fix identity |
/// | `VerificationFailed` | Signature bytes could not be parsed | Fix input |
///
/// Note: A cryptographically valid signature that does not match the binding
/// message is NOT an error — it returns `Ok(false)`.
#[derive(Debug, Clone)]
pub enum IdentityError {
    /// The provided signature has an invalid length.
    /// Ed25519 signatures must be exactly 64 bytes.
    InvalidSignatureLength {
        /// Actual length of the signature provided.
        got: usize,
        /// Expected signature length (always 64).
        expected: usize,
    },

    /// The `node_id` field is not a valid Ed25519 public key.
    ///
    /// This occurs when the 32-byte value does not represent a valid
    /// point on the Ed25519 curve, or represents a prohibited point
    /// (e.g., identity element, small-order point).
    InvalidPublicKey(String),

    /// Signature verification encountered a processing error.
    ///
    /// This is distinct from a valid-but-non-matching signature (which
    /// returns `Ok(false)`). This variant indicates the signature bytes
    /// could not be parsed or processed by the Ed25519 library.
    VerificationFailed(String),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityError::InvalidSignatureLength { got, expected } => {
                write!(
                    f,
                    "invalid Ed25519 signature length: got {} bytes, expected {}",
                    got, expected
                )
            }
            IdentityError::InvalidPublicKey(reason) => {
                write!(f, "invalid Ed25519 public key (node_id): {}", reason)
            }
            IdentityError::VerificationFailed(reason) => {
                write!(f, "signature verification failed: {}", reason)
            }
        }
    }
}

impl std::error::Error for IdentityError {}

// ════════════════════════════════════════════════════════════════════════════════
// NODE IDENTITY
// ════════════════════════════════════════════════════════════════════════════════

/// Cryptographic identity of a DSDN service node.
///
/// `NodeIdentity` binds three components into a single verifiable identity:
///
/// 1. **`node_id`** ([u8; 32]) — Ed25519 public key uniquely identifying the node.
///    The corresponding private key is held by the node operator and used to
///    prove ownership via signature verification.
///
/// 2. **`operator_address`** ([u8; 20]) — Wallet address of the operator who
///    controls the node. Used for on-chain stake lookups and reward distribution.
///
/// 3. **`tls_cert_fingerprint`** ([u8; 32]) — SHA-256 fingerprint of the node's
///    DER-encoded TLS certificate. Used to verify that the transport-layer identity
///    matches the declared node identity, preventing TLS certificate spoofing.
///
/// ## Operator Binding
///
/// The `verify_operator_binding` method verifies that the operator address is
/// cryptographically bound to the node's Ed25519 key. The message format is:
///
/// ```text
/// message = b"DSDN:operator_binding:v1:" || node_id[0..32] || operator_address[0..20]
/// ```
///
/// The signature must be produced by the Ed25519 private key corresponding to `node_id`.
///
/// ## Spoofing Resistance
///
/// - **Node ID spoofing**: An attacker cannot claim another node's ID because
///   they lack the private key needed to produce a valid operator binding signature.
/// - **Operator spoofing**: An attacker cannot bind their operator address to a
///   node they don't control, again due to the signature requirement.
/// - **TLS spoofing**: The `tls_cert_fingerprint` field allows upper layers to
///   verify that the TLS certificate presented during connection matches the
///   declared identity. Validation is performed by `TLSVerifier` (14B.5/14B.23).
///
/// ## Immutability
///
/// All fields are public for construction, but identity changes require creating
/// a new `NodeIdentity` instance and re-binding via a fresh signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeIdentity {
    /// Ed25519 public key identifying this node (32 bytes).
    ///
    /// Must be a valid point on the Ed25519 curve. Invalid keys will cause
    /// `verify_operator_binding` to return `Err(IdentityError::InvalidPublicKey)`.
    pub node_id: [u8; 32],

    /// Operator wallet address (20 bytes).
    ///
    /// Used for on-chain stake lookups and reward distribution.
    /// No format validation is performed at this layer; address format
    /// is enforced by the chain layer.
    pub operator_address: [u8; 20],

    /// SHA-256 fingerprint of the node's DER-encoded TLS certificate (32 bytes).
    ///
    /// Computed as: `SHA-256(DER_encoded_certificate)`.
    /// Fingerprint validation against the actual TLS connection is handled
    /// by `TLSVerifier` (14B.5/14B.23).
    pub tls_cert_fingerprint: [u8; 32],
}

// Manual Hash implementation because [u8; 20] does not derive Hash via #[derive(Hash)]
// when struct contains multiple array fields of different sizes.
impl Hash for NodeIdentity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.node_id.hash(state);
        self.operator_address.hash(state);
        self.tls_cert_fingerprint.hash(state);
    }
}

impl fmt::Display for NodeIdentity {
    /// Display a compact, deterministic representation of the identity.
    ///
    /// Format: `NodeIdentity(node=<first 8 hex chars>..., op=<first 8 hex chars>...)`
    ///
    /// Full key material and addresses are NOT exposed in the display string
    /// to prevent accidental leakage in logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NodeIdentity(node={}..., op={}...)",
            hex::encode(&self.node_id[..4]),
            hex::encode(&self.operator_address[..4]),
        )
    }
}

impl NodeIdentity {
    /// Verify that the operator address is cryptographically bound to this node's identity.
    ///
    /// This method verifies an Ed25519 signature over a deterministic binding message:
    ///
    /// ```text
    /// message = b"DSDN:operator_binding:v1:" || node_id[0..32] || operator_address[0..20]
    /// ```
    ///
    /// The signature must be produced by the Ed25519 private key corresponding
    /// to `self.node_id`.
    ///
    /// ## Arguments
    ///
    /// * `signature` — Ed25519 signature bytes (must be exactly 64 bytes).
    ///
    /// ## Returns
    ///
    /// * `Ok(true)` — Signature is valid; operator binding is verified.
    /// * `Ok(false)` — Signature is well-formed but does not match the binding
    ///   message. The operator is NOT proven to own this node.
    /// * `Err(IdentityError::InvalidSignatureLength)` — Signature is not 64 bytes.
    /// * `Err(IdentityError::InvalidPublicKey)` — `node_id` is not a valid Ed25519 public key.
    /// * `Err(IdentityError::VerificationFailed)` — Signature bytes could not be parsed.
    ///
    /// ## Security Properties
    ///
    /// - **Domain separation**: The `DSDN:operator_binding:v1:` prefix prevents
    ///   cross-protocol replay attacks.
    /// - **Strict verification**: `verify_strict` is used, which rejects weak keys
    ///   and small-order point components (cofactored verification).
    /// - **Deterministic**: Same inputs always produce the same verification result.
    /// - **No external assumptions**: Verification is purely Ed25519 over explicit bytes.
    ///   No wallet-specific behavior or external key derivation is assumed.
    pub fn verify_operator_binding(&self, signature: &[u8]) -> Result<bool, IdentityError> {
        // Step 1: Validate signature length — Ed25519 signatures are exactly 64 bytes.
        if signature.len() != 64 {
            return Err(IdentityError::InvalidSignatureLength {
                got: signature.len(),
                expected: 64,
            });
        }

        // Step 2: Parse node_id as Ed25519 public key.
        // This validates that the 32-byte value is a valid curve point.
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&self.node_id)
            .map_err(|e| IdentityError::InvalidPublicKey(e.to_string()))?;

        // Step 3: Parse signature bytes into Ed25519 Signature struct.
        let sig = ed25519_dalek::Signature::from_slice(signature)
            .map_err(|e| IdentityError::VerificationFailed(
                format!("failed to parse signature bytes: {}", e),
            ))?;

        // Step 4: Construct the deterministic binding message.
        //
        // Layout (77 bytes total):
        //   [0..25]  = b"DSDN:operator_binding:v1:"   (domain separator)
        //   [25..57] = node_id                         (Ed25519 public key, 32 bytes)
        //   [57..77] = operator_address                (wallet address, 20 bytes)
        let mut message = Vec::with_capacity(
            OPERATOR_BINDING_DOMAIN.len() + self.node_id.len() + self.operator_address.len(),
        );
        message.extend_from_slice(OPERATOR_BINDING_DOMAIN);
        message.extend_from_slice(&self.node_id);
        message.extend_from_slice(&self.operator_address);

        // Step 5: Verify using strict mode.
        //
        // verify_strict performs cofactored verification which rejects:
        // - Signatures involving small-order components
        // - Weak or torsion public keys contributing to the verification equation
        //
        // A failed verification is NOT an error — it means the signature does not
        // match the binding message. Only structural/parsing failures are errors.
        match verifying_key.verify_strict(&message, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// NODE CLASS
// ════════════════════════════════════════════════════════════════════════════════

/// Classification of a DSDN service node.
///
/// Each class has a different minimum stake requirement, reflecting the
/// resources and trust level required for that role.
///
/// | Class | Min Stake | Role |
/// |-------|-----------|------|
/// | `Storage` | 5000 NUSA | Persistent data storage and retrieval |
/// | `Compute` | 500 NUSA | Computation and processing tasks |
///
/// ## Stake as Security Gate
///
/// Stake requirements serve ONLY as a security gate at this stage — they
/// filter out unqualified or potentially malicious nodes. Stake does NOT
/// function as an economic signal, reward multiplier, or governance weight.
///
/// ## Design Rationale
///
/// - **Storage > Compute**: Storage nodes bear greater data custody responsibility.
///   Higher stake requirement provides stronger economic deterrent against
///   data loss or withholding attacks.
/// - **Hardcoded values**: Not configurable at this stage. Future governance
///   proposals (14B.7+) may introduce configurable thresholds.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeClass {
    /// Storage node: responsible for persistent data storage and retrieval.
    ///
    /// Minimum stake: 5000 NUSA.
    Storage,

    /// Compute node: responsible for computation and processing tasks.
    ///
    /// Minimum stake: 500 NUSA.
    Compute,
}

impl fmt::Display for NodeClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeClass::Storage => write!(f, "Storage"),
            NodeClass::Compute => write!(f, "Compute"),
        }
    }
}

impl NodeClass {
    /// Returns the minimum stake required for this node class, in NUSA token units.
    ///
    /// ## Values
    ///
    /// - `Storage` → 5000 NUSA
    /// - `Compute` → 500 NUSA
    ///
    /// These values are hardcoded and not configurable at this stage.
    /// On-chain smallest-unit conversion (e.g., multiplying by 10^18 for
    /// 18-decimal tokens) is handled by `StakeRequirement` (14B.3).
    ///
    /// ## Returns
    ///
    /// Minimum stake in NUSA token units as `u128`.
    #[must_use]
    #[inline]
    pub const fn min_stake(&self) -> u128 {
        match self {
            NodeClass::Storage => STORAGE_MIN_STAKE_NUSA,
            NodeClass::Compute => COMPUTE_MIN_STAKE_NUSA,
        }
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
    // TEST HELPERS
    // ──────────────────────────────────────────────────────────────────────

    /// Generate a valid NodeIdentity backed by a real Ed25519 keypair.
    fn make_test_identity() -> (NodeIdentity, SigningKey) {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let verifying_key = signing_key.verifying_key();
        let node_id = verifying_key.to_bytes();
        let operator_address = [0x42u8; 20];
        let tls_cert_fingerprint = [0xAAu8; 32];

        let identity = NodeIdentity {
            node_id,
            operator_address,
            tls_cert_fingerprint,
        };

        (identity, signing_key)
    }

    /// Sign the operator binding message using the same deterministic format
    /// as `verify_operator_binding`.
    fn sign_binding(identity: &NodeIdentity, signing_key: &SigningKey) -> Vec<u8> {
        let mut message = Vec::with_capacity(
            OPERATOR_BINDING_DOMAIN.len() + 32 + 20,
        );
        message.extend_from_slice(OPERATOR_BINDING_DOMAIN);
        message.extend_from_slice(&identity.node_id);
        message.extend_from_slice(&identity.operator_address);

        let sig = signing_key.sign(&message);
        sig.to_bytes().to_vec()
    }

    // ──────────────────────────────────────────────────────────────────────
    // NodeClass TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_node_class_min_stake_storage() {
        assert_eq!(NodeClass::Storage.min_stake(), 5_000);
    }

    #[test]
    fn test_node_class_min_stake_compute() {
        assert_eq!(NodeClass::Compute.min_stake(), 500);
    }

    #[test]
    fn test_node_class_storage_greater_than_compute() {
        assert!(NodeClass::Storage.min_stake() > NodeClass::Compute.min_stake());
    }

    #[test]
    fn test_node_class_display_storage() {
        assert_eq!(format!("{}", NodeClass::Storage), "Storage");
    }

    #[test]
    fn test_node_class_display_compute() {
        assert_eq!(format!("{}", NodeClass::Compute), "Compute");
    }

    #[test]
    fn test_node_class_copy() {
        let class = NodeClass::Storage;
        let copy = class;
        assert_eq!(class, copy);
    }

    #[test]
    fn test_node_class_clone() {
        let class = NodeClass::Compute;
        #[allow(clippy::clone_on_copy)]
        let cloned = class.clone();
        assert_eq!(class, cloned);
    }

    #[test]
    fn test_node_class_eq() {
        assert_eq!(NodeClass::Storage, NodeClass::Storage);
        assert_eq!(NodeClass::Compute, NodeClass::Compute);
        assert_ne!(NodeClass::Storage, NodeClass::Compute);
    }

    #[test]
    fn test_node_class_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(NodeClass::Storage);
        set.insert(NodeClass::Compute);
        set.insert(NodeClass::Storage); // duplicate
        assert_eq!(set.len(), 2);
        assert!(set.contains(&NodeClass::Storage));
        assert!(set.contains(&NodeClass::Compute));
    }

    #[test]
    fn test_node_class_debug() {
        let debug = format!("{:?}", NodeClass::Storage);
        assert_eq!(debug, "Storage");
    }

    #[test]
    fn test_node_class_serde_roundtrip_storage() {
        let class = NodeClass::Storage;
        let json = serde_json::to_string(&class).expect("serialize");
        let back: NodeClass = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(class, back);
    }

    #[test]
    fn test_node_class_serde_roundtrip_compute() {
        let class = NodeClass::Compute;
        let json = serde_json::to_string(&class).expect("serialize");
        let back: NodeClass = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(class, back);
    }

    // ──────────────────────────────────────────────────────────────────────
    // NodeIdentity BASIC TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_node_identity_clone() {
        let (identity, _) = make_test_identity();
        let cloned = identity.clone();
        assert_eq!(identity, cloned);
    }

    #[test]
    fn test_node_identity_eq() {
        let (id1, _) = make_test_identity();
        let id2 = id1.clone();
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_node_identity_ne_different_keys() {
        let (id1, _) = make_test_identity();
        let (id2, _) = make_test_identity();
        // Two different keypairs → different identities (overwhelmingly likely)
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_node_identity_hash_consistent() {
        use std::collections::HashSet;
        let (id1, _) = make_test_identity();
        let id2 = id1.clone();
        let mut set = HashSet::new();
        set.insert(id1.clone());
        assert!(set.contains(&id2));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_node_identity_display_truncated() {
        let (identity, _) = make_test_identity();
        let display = format!("{}", identity);
        assert!(display.starts_with("NodeIdentity("));
        assert!(display.contains("node="));
        assert!(display.contains("op="));
        assert!(display.contains("..."));
    }

    #[test]
    fn test_node_identity_display_no_full_key_leak() {
        let (identity, _) = make_test_identity();
        let display = format!("{}", identity);
        // Full node_id hex (64 chars) must NOT appear in display
        let full_node_hex = hex::encode(identity.node_id);
        assert!(
            !display.contains(&full_node_hex),
            "display must not contain full node_id"
        );
        // Full operator_address hex (40 chars) must NOT appear in display
        let full_op_hex = hex::encode(identity.operator_address);
        assert!(
            !display.contains(&full_op_hex),
            "display must not contain full operator_address"
        );
    }

    #[test]
    fn test_node_identity_display_deterministic() {
        let (identity, _) = make_test_identity();
        let d1 = format!("{}", identity);
        let d2 = format!("{}", identity);
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_node_identity_serde_roundtrip() {
        let (identity, _) = make_test_identity();
        let json = serde_json::to_string(&identity).expect("serialize");
        let back: NodeIdentity = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(identity, back);
    }

    #[test]
    fn test_node_identity_serde_preserves_all_fields() {
        let (identity, _) = make_test_identity();
        let json = serde_json::to_string(&identity).expect("serialize");
        let back: NodeIdentity = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(identity.node_id, back.node_id);
        assert_eq!(identity.operator_address, back.operator_address);
        assert_eq!(identity.tls_cert_fingerprint, back.tls_cert_fingerprint);
    }

    // ──────────────────────────────────────────────────────────────────────
    // verify_operator_binding TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_verify_binding_valid_signature() {
        let (identity, signing_key) = make_test_identity();
        let signature = sign_binding(&identity, &signing_key);
        let result = identity.verify_operator_binding(&signature);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_binding_wrong_signing_key() {
        let (identity, _correct_key) = make_test_identity();
        // Sign with a different key — signature will not match
        let (_other_identity, other_key) = make_test_identity();
        let signature = sign_binding(&identity, &other_key);
        let result = identity.verify_operator_binding(&signature);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_verify_binding_tampered_operator_address() {
        let (mut identity, signing_key) = make_test_identity();
        // Sign with original operator address
        let signature = sign_binding(&identity, &signing_key);
        // Tamper with operator address after signing
        identity.operator_address = [0x99u8; 20];
        let result = identity.verify_operator_binding(&signature);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_verify_binding_different_operator_addresses() {
        // Same node, two different operator addresses → different messages → different signatures
        let (identity_a, signing_key) = make_test_identity();
        let mut identity_b = identity_a.clone();
        identity_b.operator_address = [0xFF; 20];

        let sig_a = sign_binding(&identity_a, &signing_key);
        let sig_b = sign_binding(&identity_b, &signing_key);

        // Each signature validates only for its own identity
        assert!(identity_a.verify_operator_binding(&sig_a).unwrap());
        assert!(!identity_a.verify_operator_binding(&sig_b).unwrap());
        assert!(identity_b.verify_operator_binding(&sig_b).unwrap());
        assert!(!identity_b.verify_operator_binding(&sig_a).unwrap());
    }

    #[test]
    fn test_verify_binding_signature_too_short() {
        let (identity, _) = make_test_identity();
        let short_sig = vec![0u8; 32];
        let result = identity.verify_operator_binding(&short_sig);
        assert!(result.is_err());
        match result.unwrap_err() {
            IdentityError::InvalidSignatureLength { got, expected } => {
                assert_eq!(got, 32);
                assert_eq!(expected, 64);
            }
            other => panic!("expected InvalidSignatureLength, got: {:?}", other),
        }
    }

    #[test]
    fn test_verify_binding_signature_too_long() {
        let (identity, _) = make_test_identity();
        let long_sig = vec![0u8; 128];
        let result = identity.verify_operator_binding(&long_sig);
        assert!(result.is_err());
        match result.unwrap_err() {
            IdentityError::InvalidSignatureLength { got, expected } => {
                assert_eq!(got, 128);
                assert_eq!(expected, 64);
            }
            other => panic!("expected InvalidSignatureLength, got: {:?}", other),
        }
    }

    #[test]
    fn test_verify_binding_empty_signature() {
        let (identity, _) = make_test_identity();
        let result = identity.verify_operator_binding(&[]);
        assert!(result.is_err());
        match result.unwrap_err() {
            IdentityError::InvalidSignatureLength { got, expected } => {
                assert_eq!(got, 0);
                assert_eq!(expected, 64);
            }
            other => panic!("expected InvalidSignatureLength, got: {:?}", other),
        }
    }

    #[test]
    fn test_verify_binding_non_keypair_node_id_no_panic() {
        // node_id values that are NOT derived from a real keypair.
        // Each should either return an error or Ok(false), but NEVER panic or Ok(true).
        for byte_val in [0x00u8, 0x01, 0xDE, 0xFF] {
            let identity = NodeIdentity {
                node_id: [byte_val; 32],
                operator_address: [0x42; 20],
                tls_cert_fingerprint: [0xAA; 32],
            };
            let garbage_sig = [0xAB; 64];
            let result = identity.verify_operator_binding(&garbage_sig);
            match result {
                Ok(true) => panic!(
                    "garbage signature must not verify for node_id=[{:#04x}; 32]",
                    byte_val
                ),
                Ok(false) | Err(_) => {} // Both acceptable
            }
        }
    }

    #[test]
    fn test_verify_binding_deterministic_signature() {
        // Ed25519 signatures from ed25519-dalek are deterministic (RFC 8032).
        // Same keypair + same message → same signature.
        let (identity, signing_key) = make_test_identity();
        let sig1 = sign_binding(&identity, &signing_key);
        let sig2 = sign_binding(&identity, &signing_key);
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_verify_binding_deterministic_result() {
        let (identity, signing_key) = make_test_identity();
        let signature = sign_binding(&identity, &signing_key);
        // Same inputs → same result
        let r1 = identity.verify_operator_binding(&signature);
        let r2 = identity.verify_operator_binding(&signature);
        assert_eq!(r1.is_ok(), r2.is_ok());
        if r1.is_ok() {
            assert_eq!(r1.unwrap(), r2.unwrap());
        }
    }

    #[test]
    fn test_verify_binding_zero_signature_bytes() {
        // 64 zero bytes is a structurally valid signature length but
        // should not verify against any legitimate binding.
        let (identity, _) = make_test_identity();
        let zero_sig = [0u8; 64];
        let result = identity.verify_operator_binding(&zero_sig);
        // Must not return Ok(true)
        match result {
            Ok(true) => panic!("zero signature must not verify"),
            Ok(false) | Err(_) => {} // Both acceptable
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // IdentityError TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_identity_error_display_signature_length() {
        let err = IdentityError::InvalidSignatureLength {
            got: 32,
            expected: 64,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("32"));
        assert!(msg.contains("64"));
        assert!(msg.contains("signature length"));
    }

    #[test]
    fn test_identity_error_display_invalid_pubkey() {
        let err = IdentityError::InvalidPublicKey("test reason".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("test reason"));
        assert!(msg.contains("public key"));
    }

    #[test]
    fn test_identity_error_display_verification_failed() {
        let err = IdentityError::VerificationFailed("parse error".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("parse error"));
        assert!(msg.contains("verification failed"));
    }

    #[test]
    fn test_identity_error_implements_std_error() {
        fn assert_error<E: std::error::Error>() {}
        assert_error::<IdentityError>();
    }

    #[test]
    fn test_identity_error_implements_display() {
        fn assert_display<E: fmt::Display>() {}
        assert_display::<IdentityError>();
    }

    #[test]
    fn test_identity_error_implements_debug() {
        fn assert_debug<E: fmt::Debug>() {}
        assert_debug::<IdentityError>();
    }

    #[test]
    fn test_identity_error_clone() {
        let err = IdentityError::InvalidSignatureLength {
            got: 32,
            expected: 64,
        };
        let cloned = err.clone();
        assert_eq!(format!("{}", err), format!("{}", cloned));
    }

    // ──────────────────────────────────────────────────────────────────────
    // SEND + SYNC TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NodeIdentity>();
        assert_send_sync::<NodeClass>();
        assert_send_sync::<IdentityError>();
    }
}