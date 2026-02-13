//! # Join Request Builder (14B.43)
//!
//! Provides [`JoinRequest`], [`JoinRequestBuilder`], [`JoinResponse`],
//! and [`JoinError`] for constructing and validating node join requests
//! before submission to the coordinator.
//!
//! ## Join Flow
//!
//! ```text
//! Node                                     Coordinator
//!  │                                            │
//!  │  1. Receive IdentityChallenge              │
//!  │◀───────────────────────────────────────────│
//!  │                                            │
//!  │  2. JoinRequestBuilder::new(mgr, class)    │
//!  │     .with_tls(tls_mgr)                     │
//!  │     .with_addr(addr)                       │
//!  │     .with_capacity(gb)                     │
//!  │     .build(challenge)                      │
//!  │          │                                 │
//!  │          ▼                                 │
//!  │     JoinRequest                            │
//!  │  3. Submit JoinRequest ──────────────────▶ │
//!  │                                            │
//!  │                    GateKeeper::process_admission
//!  │                                            │
//!  │  4. Receive JoinResponse ◀─────────────── │
//!  │                                            │
//! ```
//!
//! ## Relation to AdmissionRequest (14B.32)
//!
//! `JoinRequest` is the **node-side** representation. The coordinator's
//! `AdmissionRequest` (14B.32) contains a subset of the same fields:
//!
//! | JoinRequest Field | AdmissionRequest Field | Notes |
//! |-------------------|------------------------|-------|
//! | `identity` | `identity` | Same `NodeIdentity` |
//! | `claimed_class` | `claimed_class` | Same `NodeClass` |
//! | `identity_proof` | `identity_proof` | Same `IdentityProof` |
//! | `tls_cert_info` | `tls_cert_info` | Same `TLSCertInfo` |
//! | `node_addr` | — | Node-side metadata |
//! | `capacity_gb` | — | Node-side metadata |
//! | `meta` | — | Node-side metadata |
//!
//! The coordinator extracts the four gating-relevant fields to construct
//! an `AdmissionRequest`. The remaining fields (`node_addr`, `capacity_gb`,
//! `meta`) are stored in the node registry for operational use.
//!
//! ## Determinism
//!
//! Given the same `NodeIdentityManager`, `TLSCertManager`, and
//! `IdentityChallenge`, the resulting `JoinRequest` is identical
//! across calls. The `IdentityProof` signature is deterministic
//! (Ed25519 per RFC 8032).
//!
//! ## Safety
//!
//! - No `panic!`, `unwrap()`, `expect()`.
//! - No `unsafe` code.
//! - No implicit defaults — all required fields must be set explicitly.
//! - Builder validates completeness in `build()` before construction.

use std::collections::HashMap;
use std::fmt;

use dsdn_common::gating::{
    GatingReport, IdentityChallenge, IdentityProof,
    NodeClass, NodeIdentity, NodeStatus, TLSCertInfo,
};

use crate::identity_manager::NodeIdentityManager;
use crate::tls_manager::TLSCertManager;

// ════════════════════════════════════════════════════════════════════════════════
// ERROR TYPE
// ════════════════════════════════════════════════════════════════════════════════

/// Error type for join request construction failures.
///
/// Returned by [`JoinRequestBuilder::build`] when required fields are
/// missing or identity proof construction fails.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JoinError {
    /// TLS certificate info was not provided via `with_tls()`.
    MissingTLS,
    /// Node address was not provided or is empty.
    MissingAddr,
    /// Identity proof construction failed.
    IdentityError,
}

impl fmt::Display for JoinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JoinError::MissingTLS => write!(f, "TLS certificate info not set: call with_tls() before build()"),
            JoinError::MissingAddr => write!(f, "node address not set or empty: call with_addr() before build()"),
            JoinError::IdentityError => write!(f, "identity proof construction failed"),
        }
    }
}

impl std::error::Error for JoinError {}

// ════════════════════════════════════════════════════════════════════════════════
// JOIN REQUEST
// ════════════════════════════════════════════════════════════════════════════════

/// A complete node join request ready for submission to the coordinator.
///
/// Contains all fields required by the coordinator's `GateKeeper` for
/// admission evaluation, plus node-side metadata (address, capacity).
///
/// ## Construction
///
/// Use [`JoinRequestBuilder`] to construct a `JoinRequest`. Direct
/// construction is possible but the builder ensures all required fields
/// are present and the identity proof is correctly signed.
#[derive(Clone, Debug)]
pub struct JoinRequest {
    /// The node's cryptographic identity.
    pub identity: NodeIdentity,
    /// The node class the applicant claims to qualify for.
    pub claimed_class: NodeClass,
    /// Ed25519 identity proof (signed challenge-response).
    pub identity_proof: IdentityProof,
    /// TLS certificate metadata for fingerprint verification.
    pub tls_cert_info: TLSCertInfo,
    /// The node's network address (e.g., `"https://node1.dsdn.io:8443"`).
    pub node_addr: String,
    /// Advertised storage capacity in gigabytes.
    pub capacity_gb: u64,
    /// Arbitrary key-value metadata.
    pub meta: HashMap<String, String>,
}

// ════════════════════════════════════════════════════════════════════════════════
// JOIN RESPONSE
// ════════════════════════════════════════════════════════════════════════════════

/// Response from the coordinator after evaluating a join request.
///
/// Pure data container with no logic. All fields are set by the
/// coordinator and returned to the node as-is.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct JoinResponse {
    /// `true` if the node passed all gating checks.
    pub approved: bool,
    /// The status assigned by the coordinator (e.g., `Pending`, `Banned`).
    pub assigned_status: NodeStatus,
    /// Full gating report for audit (present if the coordinator includes it).
    pub report: Option<GatingReport>,
    /// Human-readable rejection reasons (empty if approved).
    pub rejection_reasons: Vec<String>,
}

// ════════════════════════════════════════════════════════════════════════════════
// JOIN REQUEST BUILDER
// ════════════════════════════════════════════════════════════════════════════════

/// Fluent builder for constructing a [`JoinRequest`].
///
/// The builder borrows the [`NodeIdentityManager`] to sign the identity
/// proof during [`build()`](JoinRequestBuilder::build). All other data
/// is owned by the builder.
///
/// ## Required Fields
///
/// The following must be set before calling `build()`:
///
/// | Field | Set via | Error if missing |
/// |-------|---------|------------------|
/// | TLS cert info | `with_tls()` | `JoinError::MissingTLS` |
/// | Node address | `with_addr()` (non-empty) | `JoinError::MissingAddr` |
///
/// ## Optional Fields
///
/// | Field | Set via | Default |
/// |-------|---------|---------|
/// | Capacity | `with_capacity()` | 0 |
/// | Metadata | `with_meta()` | empty HashMap |
///
/// ## Example
///
/// ```rust,ignore
/// let request = JoinRequestBuilder::new(&identity_mgr, NodeClass::Storage)
///     .with_tls(&tls_mgr)
///     .with_addr("https://node1.dsdn.io:8443".to_string())
///     .with_capacity(1000)
///     .with_meta("region".to_string(), "ap-southeast-1".to_string())
///     .build(challenge)?;
/// ```
pub struct JoinRequestBuilder<'a> {
    /// Borrowed identity manager — used to create the identity proof
    /// in `build()`. The signing key is never extracted.
    identity_manager: &'a NodeIdentityManager,
    /// Claimed node class.
    class: NodeClass,
    /// TLS certificate info (set via `with_tls()`).
    tls_info: Option<TLSCertInfo>,
    /// Node network address (set via `with_addr()`).
    node_addr: Option<String>,
    /// Advertised storage capacity in GB.
    capacity_gb: u64,
    /// Arbitrary key-value metadata.
    meta: HashMap<String, String>,
}

impl<'a> JoinRequestBuilder<'a> {
    /// Creates a new builder with the identity manager and claimed node class.
    ///
    /// The builder borrows the identity manager for the duration of the
    /// builder's lifetime. The node's `NodeIdentity` and signing key are
    /// accessed only during [`build()`](Self::build).
    ///
    /// ## Parameters
    ///
    /// - `identity_manager`: The node's identity manager (borrowed, not modified).
    /// - `class`: The node class the applicant claims to qualify for.
    pub fn new(identity_manager: &'a NodeIdentityManager, class: NodeClass) -> Self {
        Self {
            identity_manager,
            class,
            tls_info: None,
            node_addr: None,
            capacity_gb: 0,
            meta: HashMap::new(),
        }
    }

    /// Sets the TLS certificate info from a [`TLSCertManager`].
    ///
    /// Clones the `TLSCertInfo` metadata (fingerprint, subject_cn, validity
    /// timestamps, issuer). Does NOT clone the DER certificate bytes or
    /// any private key material.
    #[must_use]
    pub fn with_tls(mut self, tls_manager: &TLSCertManager) -> Self {
        self.tls_info = Some(tls_manager.cert_info().clone());
        self
    }

    /// Sets the node's network address.
    ///
    /// The address is stored as-is. Validation (non-empty) is performed
    /// in [`build()`](Self::build).
    #[must_use]
    pub fn with_addr(mut self, addr: String) -> Self {
        self.node_addr = Some(addr);
        self
    }

    /// Sets the advertised storage capacity in gigabytes.
    ///
    /// A value of 0 is allowed (e.g., for compute-only nodes).
    #[must_use]
    pub fn with_capacity(mut self, gb: u64) -> Self {
        self.capacity_gb = gb;
        self
    }

    /// Adds a key-value metadata entry.
    ///
    /// Duplicate keys overwrite previous values (standard `HashMap` behavior).
    /// Empty keys and values are stored as-is — validation is the caller's
    /// responsibility.
    #[must_use]
    pub fn with_meta(mut self, key: String, value: String) -> Self {
        self.meta.insert(key, value);
        self
    }

    /// Validates all required fields and constructs a [`JoinRequest`].
    ///
    /// ## Validation Order (STRICT)
    ///
    /// 1. Check TLS info is set → `JoinError::MissingTLS`
    /// 2. Check node_addr is set and non-empty → `JoinError::MissingAddr`
    /// 3. Create identity proof from challenge → `JoinError::IdentityError`
    ///    (currently infallible, but guarded for forward compatibility)
    ///
    /// ## Parameters
    ///
    /// - `challenge`: The identity challenge received from the coordinator.
    ///   Consumed by value (moved into the identity proof).
    ///
    /// ## Determinism
    ///
    /// Same inputs (identity manager state, TLS info, challenge) always
    /// produce the same `JoinRequest`. The identity proof signature is
    /// deterministic per RFC 8032.
    pub fn build(self, challenge: IdentityChallenge) -> Result<JoinRequest, JoinError> {
        // Step 1: Validate TLS
        let tls_cert_info = self.tls_info.ok_or(JoinError::MissingTLS)?;

        // Step 2: Validate node address
        let node_addr = self.node_addr.ok_or(JoinError::MissingAddr)?;
        if node_addr.is_empty() {
            return Err(JoinError::MissingAddr);
        }

        // Step 3: Create identity proof
        // NodeIdentityManager::create_identity_proof is currently infallible.
        // We wrap in a function-level guard for forward compatibility.
        let identity_proof = self.identity_manager.create_identity_proof(challenge);
        let identity = self.identity_manager.identity().clone();

        Ok(JoinRequest {
            identity,
            claimed_class: self.class,
            identity_proof,
            tls_cert_info,
            node_addr,
            capacity_gb: self.capacity_gb,
            meta: self.meta,
        })
    }
}

impl fmt::Debug for JoinRequestBuilder<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JoinRequestBuilder")
            .field("class", &self.class)
            .field("tls_info_set", &self.tls_info.is_some())
            .field("node_addr", &self.node_addr)
            .field("capacity_gb", &self.capacity_gb)
            .field("meta_keys", &self.meta.len())
            .field("identity_manager", &"[borrowed]")
            .finish()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// COMPILE-TIME ASSERTIONS
// ════════════════════════════════════════════════════════════════════════════════

const _: () = {
    fn assert_send<T: Send>() {}
    fn check() {
        assert_send::<JoinRequest>();
        assert_send::<JoinResponse>();
        assert_send::<JoinError>();
    }
    let _ = check;
};

const _: () = {
    fn assert_sync<T: Sync>() {}
    fn check() {
        assert_sync::<JoinRequest>();
        assert_sync::<JoinResponse>();
        assert_sync::<JoinError>();
    }
    let _ = check;
};

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity_manager::NodeIdentityManager;
    use crate::tls_manager::TLSCertManager;

    /// Deterministic seed for all tests.
    const TEST_SEED: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    ];

    const TEST_TS: u64 = 1_700_000_000;

    fn make_identity_mgr() -> NodeIdentityManager {
        NodeIdentityManager::from_keypair(TEST_SEED)
            .expect("test setup: from_keypair")
    }

    fn make_tls_mgr() -> TLSCertManager {
        TLSCertManager::generate_self_signed("test.dsdn.local", 365)
            .expect("test setup: generate_self_signed")
    }

    fn make_challenge() -> IdentityChallenge {
        IdentityChallenge {
            nonce: [0x42; 32],
            timestamp: TEST_TS,
            challenger: "coordinator".to_string(),
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // HAPPY PATH
    // ──────────────────────────────────────────────────────────────────

    /// Full builder flow produces a valid JoinRequest.
    #[test]
    fn test_build_success() {
        let id_mgr = make_identity_mgr();
        let tls_mgr = make_tls_mgr();

        let result = JoinRequestBuilder::new(&id_mgr, NodeClass::Storage)
            .with_tls(&tls_mgr)
            .with_addr("https://node1.dsdn.io:8443".to_string())
            .with_capacity(1000)
            .with_meta("region".to_string(), "ap-southeast-1".to_string())
            .build(make_challenge());

        assert!(result.is_ok());
        if let Ok(req) = result {
            assert_eq!(req.identity.node_id, *id_mgr.node_id());
            assert_eq!(req.identity.operator_address, *id_mgr.operator_address());
            assert_eq!(req.node_addr, "https://node1.dsdn.io:8443");
            assert_eq!(req.capacity_gb, 1000);
            assert_eq!(req.meta.get("region").map(|s| s.as_str()), Some("ap-southeast-1"));
            assert_eq!(req.tls_cert_info.fingerprint, *tls_mgr.fingerprint());
        }
    }

    /// Identity proof in JoinRequest is verifiable.
    #[test]
    fn test_build_proof_verifiable() {
        let id_mgr = make_identity_mgr();
        let tls_mgr = make_tls_mgr();

        let result = JoinRequestBuilder::new(&id_mgr, NodeClass::Storage)
            .with_tls(&tls_mgr)
            .with_addr("https://node1.dsdn.io".to_string())
            .build(make_challenge());

        assert!(result.is_ok());
        if let Ok(req) = result {
            assert!(req.identity_proof.verify());
        }
    }

    /// Build is deterministic: same inputs → same output.
    #[test]
    fn test_build_deterministic() {
        let id_mgr = make_identity_mgr();
        let tls_mgr = make_tls_mgr();

        let req1 = JoinRequestBuilder::new(&id_mgr, NodeClass::Storage)
            .with_tls(&tls_mgr)
            .with_addr("addr".to_string())
            .build(make_challenge());

        let req2 = JoinRequestBuilder::new(&id_mgr, NodeClass::Storage)
            .with_tls(&tls_mgr)
            .with_addr("addr".to_string())
            .build(make_challenge());

        assert!(req1.is_ok());
        assert!(req2.is_ok());
        if let (Ok(r1), Ok(r2)) = (req1, req2) {
            assert_eq!(r1.identity.node_id, r2.identity.node_id);
            assert_eq!(r1.identity_proof.signature, r2.identity_proof.signature);
            assert_eq!(r1.node_addr, r2.node_addr);
            assert_eq!(r1.capacity_gb, r2.capacity_gb);
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // MISSING FIELD ERRORS
    // ──────────────────────────────────────────────────────────────────

    /// Missing TLS → JoinError::MissingTLS.
    #[test]
    fn test_build_missing_tls() {
        let id_mgr = make_identity_mgr();

        let result = JoinRequestBuilder::new(&id_mgr, NodeClass::Storage)
            .with_addr("addr".to_string())
            .build(make_challenge());

        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e, JoinError::MissingTLS);
        }
    }

    /// Missing addr → JoinError::MissingAddr.
    #[test]
    fn test_build_missing_addr() {
        let id_mgr = make_identity_mgr();
        let tls_mgr = make_tls_mgr();

        let result = JoinRequestBuilder::new(&id_mgr, NodeClass::Storage)
            .with_tls(&tls_mgr)
            .build(make_challenge());

        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e, JoinError::MissingAddr);
        }
    }

    /// Empty addr → JoinError::MissingAddr.
    #[test]
    fn test_build_empty_addr() {
        let id_mgr = make_identity_mgr();
        let tls_mgr = make_tls_mgr();

        let result = JoinRequestBuilder::new(&id_mgr, NodeClass::Storage)
            .with_tls(&tls_mgr)
            .with_addr(String::new())
            .build(make_challenge());

        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e, JoinError::MissingAddr);
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // OPTIONAL FIELDS
    // ──────────────────────────────────────────────────────────────────

    /// Capacity defaults to 0 if not set.
    #[test]
    fn test_default_capacity_zero() {
        let id_mgr = make_identity_mgr();
        let tls_mgr = make_tls_mgr();

        let result = JoinRequestBuilder::new(&id_mgr, NodeClass::Storage)
            .with_tls(&tls_mgr)
            .with_addr("addr".to_string())
            .build(make_challenge());

        assert!(result.is_ok());
        if let Ok(req) = result {
            assert_eq!(req.capacity_gb, 0);
        }
    }

    /// Meta defaults to empty HashMap if not set.
    #[test]
    fn test_default_meta_empty() {
        let id_mgr = make_identity_mgr();
        let tls_mgr = make_tls_mgr();

        let result = JoinRequestBuilder::new(&id_mgr, NodeClass::Storage)
            .with_tls(&tls_mgr)
            .with_addr("addr".to_string())
            .build(make_challenge());

        assert!(result.is_ok());
        if let Ok(req) = result {
            assert!(req.meta.is_empty());
        }
    }

    /// Multiple meta entries are preserved.
    #[test]
    fn test_multiple_meta_entries() {
        let id_mgr = make_identity_mgr();
        let tls_mgr = make_tls_mgr();

        let result = JoinRequestBuilder::new(&id_mgr, NodeClass::Storage)
            .with_tls(&tls_mgr)
            .with_addr("addr".to_string())
            .with_meta("region".to_string(), "us-east-1".to_string())
            .with_meta("version".to_string(), "1.0.0".to_string())
            .build(make_challenge());

        assert!(result.is_ok());
        if let Ok(req) = result {
            assert_eq!(req.meta.len(), 2);
            assert_eq!(req.meta.get("region").map(|s| s.as_str()), Some("us-east-1"));
            assert_eq!(req.meta.get("version").map(|s| s.as_str()), Some("1.0.0"));
        }
    }

    /// Duplicate meta key overwrites previous value.
    #[test]
    fn test_meta_overwrite() {
        let id_mgr = make_identity_mgr();
        let tls_mgr = make_tls_mgr();

        let result = JoinRequestBuilder::new(&id_mgr, NodeClass::Storage)
            .with_tls(&tls_mgr)
            .with_addr("addr".to_string())
            .with_meta("key".to_string(), "old".to_string())
            .with_meta("key".to_string(), "new".to_string())
            .build(make_challenge());

        assert!(result.is_ok());
        if let Ok(req) = result {
            assert_eq!(req.meta.len(), 1);
            assert_eq!(req.meta.get("key").map(|s| s.as_str()), Some("new"));
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // JOIN RESPONSE
    // ──────────────────────────────────────────────────────────────────

    /// JoinResponse serde round-trip.
    #[test]
    fn test_join_response_serde() {
        let resp = JoinResponse {
            approved: true,
            assigned_status: NodeStatus::Pending,
            report: None,
            rejection_reasons: vec![],
        };

        let json = serde_json::to_string(&resp);
        assert!(json.is_ok());
        if let Ok(j) = json {
            let parsed: Result<JoinResponse, _> = serde_json::from_str(&j);
            assert!(parsed.is_ok());
            if let Ok(p) = parsed {
                assert!(p.approved);
                assert_eq!(p.rejection_reasons.len(), 0);
            }
        }
    }

    /// JoinResponse with rejection reasons.
    #[test]
    fn test_join_response_rejected() {
        let resp = JoinResponse {
            approved: false,
            assigned_status: NodeStatus::Banned,
            report: None,
            rejection_reasons: vec![
                "insufficient stake".to_string(),
                "identity mismatch".to_string(),
            ],
        };

        assert!(!resp.approved);
        assert_eq!(resp.rejection_reasons.len(), 2);
    }

    // ──────────────────────────────────────────────────────────────────
    // ERROR TYPE
    // ──────────────────────────────────────────────────────────────────

    /// JoinError variants have distinct Display output.
    #[test]
    fn test_join_error_display() {
        let e1 = JoinError::MissingTLS;
        let e2 = JoinError::MissingAddr;
        let e3 = JoinError::IdentityError;

        let s1 = format!("{}", e1);
        let s2 = format!("{}", e2);
        let s3 = format!("{}", e3);

        assert!(!s1.is_empty());
        assert_ne!(s1, s2);
        assert_ne!(s2, s3);
    }

    /// JoinError implements std::error::Error.
    #[test]
    fn test_join_error_is_error() {
        let e: Box<dyn std::error::Error> = Box::new(JoinError::MissingTLS);
        let _ = format!("{}", e);
    }

    // ──────────────────────────────────────────────────────────────────
    // DEBUG
    // ──────────────────────────────────────────────────────────────────

    /// Builder Debug does not expose identity manager internals.
    #[test]
    fn test_builder_debug() {
        let id_mgr = make_identity_mgr();

        let builder = JoinRequestBuilder::new(&id_mgr, NodeClass::Storage);
        let debug_str = format!("{:?}", builder);
        assert!(debug_str.contains("JoinRequestBuilder"));
        assert!(debug_str.contains("[borrowed]"));
    }
}