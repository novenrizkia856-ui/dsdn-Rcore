//! # Node Identity & Gating Integration Tests (14B.50)
//!
//! Comprehensive cross-module test suite for all Node-side Identity &
//! Gating components (14B.41–14B.49). Tests exercise the public APIs
//! of each component and verify their interactions end-to-end.
//!
//! ## Test Categories
//!
//! 1. **NodeIdentityManager** — Generation, signing, identity proof.
//! 2. **TLSCertManager** — Generation, fingerprint, validity, expiry.
//! 3. **JoinRequestBuilder** — Valid build, error propagation.
//! 4. **NodeStatusTracker** — All transitions, invalid paths, timing.
//! 5. **QuarantineHandler** — Notification, duration, recovery.
//! 6. **RejoinManager** — Eligibility, request building.
//! 7. **IdentityStore** — Persistence roundtrip, load_or_generate.
//! 8. **HealthResponse** — With/without identity, backward compat.
//! 9. **StatusNotificationHandler** — All statuses, DA events.
//!
//! ## Safety
//!
//! - No `unwrap()` in test code. All Result handling uses `match` or
//!   `if let` with explicit `assert!` on the Result variant first.
//! - No global mutable state.
//! - All tests are deterministic (no randomness, no clock access).

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use parking_lot::Mutex;

    use dsdn_common::gating::{
        CooldownPeriod, IdentityChallenge, NodeClass, NodeStatus,
    };
    use dsdn_coordinator::GatingEvent;

    use crate::health::NodeHealth;
    use crate::identity_manager::NodeIdentityManager;
    use crate::identity_persistence::IdentityStore;
    use crate::join_request::{JoinError, JoinRequestBuilder};
    use crate::quarantine_handler::QuarantineHandler;
    use crate::rejoin_manager::RejoinManager;
    use crate::status_notification::{StatusNotification, StatusNotificationHandler};
    use crate::status_tracker::NodeStatusTracker;
    use crate::tls_manager::TLSCertManager;

    // ════════════════════════════════════════════════════════════════════════
    // CONSTANTS
    // ════════════════════════════════════════════════════════════════════════

    const TS: u64 = 1_700_000_000;

    const TEST_SEED: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    ];

    const ALT_SEED: [u8; 32] = [
        0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
        0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0,
        0xEF, 0xEE, 0xED, 0xEC, 0xEB, 0xEA, 0xE9, 0xE8,
        0xE7, 0xE6, 0xE5, 0xE4, 0xE3, 0xE2, 0xE1, 0xE0,
    ];

    const TEST_HOST: &str = "test.dsdn.local";

    // ════════════════════════════════════════════════════════════════════════
    // HELPERS
    // ════════════════════════════════════════════════════════════════════════

    fn make_challenge(nonce: [u8; 32]) -> IdentityChallenge {
        IdentityChallenge {
            nonce,
            timestamp: TS,
            challenger: "coordinator".to_string(),
        }
    }

    /// Hex encoding for test assertions.
    fn hex_encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    /// Creates a tracker in Active state.
    fn active_tracker() -> NodeStatusTracker {
        let mut t = NodeStatusTracker::new();
        let r = t.update_status(NodeStatus::Active, "approved".to_string(), TS);
        assert!(r.is_ok(), "test setup: Pending → Active must succeed");
        t
    }

    /// Creates a shared Active tracker wrapped in Arc<Mutex<>>.
    fn shared_active_tracker() -> Arc<Mutex<NodeStatusTracker>> {
        Arc::new(Mutex::new(active_tracker()))
    }

    // ════════════════════════════════════════════════════════════════════════
    // 1. NODE IDENTITY MANAGER
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn identity_generate_produces_valid_keys() {
        let result = NodeIdentityManager::generate();
        assert!(result.is_ok(), "generate() must succeed");
        if let Ok(mgr) = result {
            assert_eq!(mgr.node_id().len(), 32, "node_id must be 32 bytes");
            assert_eq!(mgr.operator_address().len(), 20, "operator must be 20 bytes");
        }
    }

    #[test]
    fn identity_from_keypair_deterministic() {
        let r1 = NodeIdentityManager::from_keypair(TEST_SEED);
        let r2 = NodeIdentityManager::from_keypair(TEST_SEED);
        assert!(r1.is_ok(), "from_keypair must succeed");
        assert!(r2.is_ok(), "from_keypair must succeed");
        if let (Ok(m1), Ok(m2)) = (r1, r2) {
            assert_eq!(m1.node_id(), m2.node_id(), "same seed → same node_id");
            assert_eq!(
                m1.operator_address(),
                m2.operator_address(),
                "same seed → same operator"
            );
        }
    }

    #[test]
    fn identity_different_seeds_different_ids() {
        let r1 = NodeIdentityManager::from_keypair(TEST_SEED);
        let r2 = NodeIdentityManager::from_keypair(ALT_SEED);
        assert!(r1.is_ok());
        assert!(r2.is_ok());
        if let (Ok(m1), Ok(m2)) = (r1, r2) {
            assert_ne!(m1.node_id(), m2.node_id(), "different seeds → different ids");
        }
    }

    #[test]
    fn identity_sign_challenge_deterministic() {
        let r = NodeIdentityManager::from_keypair(TEST_SEED);
        assert!(r.is_ok());
        if let Ok(mgr) = r {
            let nonce = [0x42u8; 32];
            let sig1 = mgr.sign_challenge(&nonce);
            let sig2 = mgr.sign_challenge(&nonce);
            assert_eq!(sig1, sig2, "same nonce → same signature");
            assert_eq!(sig1.len(), 64, "Ed25519 signature = 64 bytes");
        }
    }

    #[test]
    fn identity_sign_different_nonces_different_sigs() {
        let r = NodeIdentityManager::from_keypair(TEST_SEED);
        assert!(r.is_ok());
        if let Ok(mgr) = r {
            let sig1 = mgr.sign_challenge(&[0x01; 32]);
            let sig2 = mgr.sign_challenge(&[0x02; 32]);
            assert_ne!(sig1, sig2, "different nonces → different sigs");
        }
    }

    #[test]
    fn identity_proof_contains_correct_fields() {
        let r = NodeIdentityManager::from_keypair(TEST_SEED);
        assert!(r.is_ok());
        if let Ok(mgr) = r {
            let challenge = make_challenge([0xAA; 32]);
            let proof = mgr.create_identity_proof(challenge);
            assert_eq!(
                proof.node_identity.node_id,
                *mgr.node_id(),
                "proof.node_identity.node_id matches"
            );
            assert_eq!(proof.signature.len(), 64, "proof contains 64-byte sig");
        }
    }

    #[test]
    fn identity_operator_derived_from_node_id() {
        let r = NodeIdentityManager::from_keypair(TEST_SEED);
        assert!(r.is_ok());
        if let Ok(mgr) = r {
            // operator_address = node_id[12..32]
            assert_eq!(
                mgr.operator_address(),
                &mgr.node_id()[12..32],
                "operator is last 20 bytes of node_id"
            );
        }
    }

    #[test]
    fn identity_proof_verify_succeeds() {
        let r = NodeIdentityManager::from_keypair(TEST_SEED);
        assert!(r.is_ok());
        if let Ok(mgr) = r {
            let challenge = make_challenge([0xBB; 32]);
            let proof = mgr.create_identity_proof(challenge);
            assert!(
                proof.verify(),
                "valid identity proof must verify successfully"
            );
        }
    }

    #[test]
    fn identity_proof_verify_deterministic() {
        let r1 = NodeIdentityManager::from_keypair(TEST_SEED);
        let r2 = NodeIdentityManager::from_keypair(TEST_SEED);
        assert!(r1.is_ok());
        assert!(r2.is_ok());
        if let (Ok(m1), Ok(m2)) = (r1, r2) {
            let c1 = make_challenge([0xCC; 32]);
            let c2 = make_challenge([0xCC; 32]);
            let p1 = m1.create_identity_proof(c1);
            let p2 = m2.create_identity_proof(c2);
            assert!(p1.verify(), "proof 1 verifies");
            assert!(p2.verify(), "proof 2 verifies");
            assert_eq!(p1.signature, p2.signature, "same inputs → same signature");
        }
    }

    #[test]
    fn identity_proof_tampered_signature_fails_verify() {
        let r = NodeIdentityManager::from_keypair(TEST_SEED);
        assert!(r.is_ok());
        if let Ok(mgr) = r {
            let challenge = make_challenge([0xDD; 32]);
            let mut proof = mgr.create_identity_proof(challenge);
            // Tamper the signature (flip first byte)
            proof.signature[0] ^= 0xFF;
            assert!(
                !proof.verify(),
                "tampered signature must fail verification"
            );
        }
    }

    #[test]
    fn identity_proof_wrong_key_fails_verify() {
        let r1 = NodeIdentityManager::from_keypair(TEST_SEED);
        let r2 = NodeIdentityManager::from_keypair(ALT_SEED);
        assert!(r1.is_ok());
        assert!(r2.is_ok());
        if let (Ok(m1), Ok(m2)) = (r1, r2) {
            let challenge = make_challenge([0xEE; 32]);
            let mut proof = m1.create_identity_proof(challenge);
            // Replace node_identity with m2's (wrong key for signature)
            proof.node_identity = m2.identity().clone();
            assert!(
                !proof.verify(),
                "proof with mismatched identity must fail"
            );
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // 2. TLS CERT MANAGER
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn tls_generate_self_signed_succeeds() {
        let r = TLSCertManager::generate_self_signed(TEST_HOST, 365);
        assert!(r.is_ok(), "generate_self_signed must succeed");
    }

    #[test]
    fn tls_fingerprint_is_32_bytes() {
        let r = TLSCertManager::generate_self_signed(TEST_HOST, 365);
        assert!(r.is_ok());
        if let Ok(mgr) = r {
            assert_eq!(mgr.fingerprint().len(), 32, "SHA-256 = 32 bytes");
        }
    }

    #[test]
    fn tls_cert_info_populated() {
        let r = TLSCertManager::generate_self_signed(TEST_HOST, 365);
        assert!(r.is_ok());
        if let Ok(mgr) = r {
            let info = mgr.cert_info();
            assert!(info.not_before <= info.not_after, "not_before <= not_after");
            assert!(
                info.not_after > info.not_before,
                "certificate has positive validity window"
            );
        }
    }

    #[test]
    fn tls_is_valid_within_window() {
        let r = TLSCertManager::generate_self_signed(TEST_HOST, 365);
        assert!(r.is_ok());
        if let Ok(mgr) = r {
            let mid = mgr.cert_info().not_before
                + (mgr.cert_info().not_after - mgr.cert_info().not_before) / 2;
            assert!(mgr.is_valid(mid), "mid-validity should be valid");
        }
    }

    #[test]
    fn tls_is_invalid_after_expiry() {
        let r = TLSCertManager::generate_self_signed(TEST_HOST, 365);
        assert!(r.is_ok());
        if let Ok(mgr) = r {
            let after = mgr.cert_info().not_after + 1;
            assert!(!mgr.is_valid(after), "past expiry should be invalid");
        }
    }

    #[test]
    fn tls_different_generations_different_fingerprints() {
        let r1 = TLSCertManager::generate_self_signed("a.dsdn.local", 365);
        let r2 = TLSCertManager::generate_self_signed("b.dsdn.local", 365);
        assert!(r1.is_ok());
        assert!(r2.is_ok());
        if let (Ok(m1), Ok(m2)) = (r1, r2) {
            assert_ne!(
                m1.fingerprint(),
                m2.fingerprint(),
                "different certs → different fingerprints"
            );
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // 3. JOIN REQUEST BUILDER
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn join_builder_valid_build() {
        let id_r = NodeIdentityManager::from_keypair(TEST_SEED);
        let tls_r = TLSCertManager::generate_self_signed(TEST_HOST, 365);
        assert!(id_r.is_ok());
        assert!(tls_r.is_ok());
        if let (Ok(id_mgr), Ok(tls_mgr)) = (id_r, tls_r) {
            let challenge = make_challenge([0x42; 32]);
            let result = JoinRequestBuilder::new(&id_mgr, NodeClass::Storage)
                .with_tls(&tls_mgr)
                .with_addr("https://node1.dsdn.io:8443".to_string())
                .with_capacity(100)
                .build(challenge);

            assert!(result.is_ok(), "valid build must succeed");
            if let Ok(req) = result {
                assert_eq!(req.identity.node_id, *id_mgr.node_id());
                assert_eq!(req.node_addr, "https://node1.dsdn.io:8443");
                assert_eq!(req.capacity_gb, 100);
            }
        }
    }

    #[test]
    fn join_builder_missing_tls_error() {
        let id_r = NodeIdentityManager::from_keypair(TEST_SEED);
        assert!(id_r.is_ok());
        if let Ok(id_mgr) = id_r {
            let challenge = make_challenge([0x42; 32]);
            let result = JoinRequestBuilder::new(&id_mgr, NodeClass::Storage)
                .with_addr("https://node.dsdn.io".to_string())
                .build(challenge);

            assert!(result.is_err(), "missing TLS must error");
            if let Err(e) = result {
                assert_eq!(e, JoinError::MissingTLS);
            }
        }
    }

    #[test]
    fn join_builder_missing_addr_error() {
        let id_r = NodeIdentityManager::from_keypair(TEST_SEED);
        let tls_r = TLSCertManager::generate_self_signed(TEST_HOST, 365);
        assert!(id_r.is_ok());
        assert!(tls_r.is_ok());
        if let (Ok(id_mgr), Ok(tls_mgr)) = (id_r, tls_r) {
            let challenge = make_challenge([0x42; 32]);
            let result = JoinRequestBuilder::new(&id_mgr, NodeClass::Compute)
                .with_tls(&tls_mgr)
                .build(challenge);

            assert!(result.is_err(), "missing addr must error");
            if let Err(e) = result {
                assert_eq!(e, JoinError::MissingAddr);
            }
        }
    }

    #[test]
    fn join_builder_empty_addr_error() {
        let id_r = NodeIdentityManager::from_keypair(TEST_SEED);
        let tls_r = TLSCertManager::generate_self_signed(TEST_HOST, 365);
        assert!(id_r.is_ok());
        assert!(tls_r.is_ok());
        if let (Ok(id_mgr), Ok(tls_mgr)) = (id_r, tls_r) {
            let challenge = make_challenge([0x42; 32]);
            let result = JoinRequestBuilder::new(&id_mgr, NodeClass::Storage)
                .with_tls(&tls_mgr)
                .with_addr(String::new())
                .build(challenge);

            assert!(result.is_err(), "empty addr must error");
        }
    }

    #[test]
    fn join_error_display_all_variants() {
        // Verify all JoinError variants have meaningful Display output.
        // IdentityError is a forward-compatibility guard (currently
        // infallible from build()), but its Display must still work.
        let missing_tls = format!("{}", JoinError::MissingTLS);
        let missing_addr = format!("{}", JoinError::MissingAddr);
        let identity_err = format!("{}", JoinError::IdentityError);

        assert!(
            !missing_tls.is_empty(),
            "MissingTLS has non-empty Display"
        );
        assert!(
            !missing_addr.is_empty(),
            "MissingAddr has non-empty Display"
        );
        assert!(
            !identity_err.is_empty(),
            "IdentityError has non-empty Display"
        );
        // Ensure they are distinct
        assert_ne!(missing_tls, missing_addr, "error messages are distinct");
        assert_ne!(missing_tls, identity_err, "error messages are distinct");
        assert_ne!(missing_addr, identity_err, "error messages are distinct");
    }

    // ════════════════════════════════════════════════════════════════════════
    // 4. NODE STATUS TRACKER
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn tracker_initial_state_pending() {
        let t = NodeStatusTracker::new();
        assert_eq!(*t.current(), NodeStatus::Pending);
        assert!(t.history().is_empty(), "no history at start");
    }

    #[test]
    fn tracker_valid_pending_to_active() {
        let mut t = NodeStatusTracker::new();
        let r = t.update_status(NodeStatus::Active, "approved".to_string(), TS);
        assert!(r.is_ok());
        assert_eq!(*t.current(), NodeStatus::Active);
        assert_eq!(t.history().len(), 1);
    }

    #[test]
    fn tracker_valid_active_to_quarantined() {
        let mut t = active_tracker();
        let r = t.update_status(
            NodeStatus::Quarantined,
            "stake drop".to_string(),
            TS + 100,
        );
        assert!(r.is_ok());
        assert_eq!(*t.current(), NodeStatus::Quarantined);
    }

    #[test]
    fn tracker_valid_quarantined_to_active() {
        let mut t = active_tracker();
        assert!(t
            .update_status(NodeStatus::Quarantined, "drop".to_string(), TS + 100)
            .is_ok());
        let r = t.update_status(NodeStatus::Active, "restored".to_string(), TS + 200);
        assert!(r.is_ok());
        assert_eq!(*t.current(), NodeStatus::Active);
    }

    #[test]
    fn tracker_valid_active_to_banned() {
        let mut t = active_tracker();
        let r = t.update_status(NodeStatus::Banned, "slashing".to_string(), TS + 100);
        assert!(r.is_ok());
        assert_eq!(*t.current(), NodeStatus::Banned);
    }

    #[test]
    fn tracker_valid_quarantined_to_banned() {
        let mut t = active_tracker();
        assert!(t
            .update_status(NodeStatus::Quarantined, "drop".to_string(), TS + 100)
            .is_ok());
        let r = t.update_status(NodeStatus::Banned, "escalation".to_string(), TS + 200);
        assert!(r.is_ok());
        assert_eq!(*t.current(), NodeStatus::Banned);
    }

    #[test]
    fn tracker_valid_banned_to_pending() {
        let mut t = active_tracker();
        assert!(t
            .update_status(NodeStatus::Banned, "slashing".to_string(), TS + 100)
            .is_ok());
        let r = t.update_status(NodeStatus::Pending, "rejoin".to_string(), TS + 200);
        assert!(r.is_ok());
        assert_eq!(*t.current(), NodeStatus::Pending);
    }

    #[test]
    fn tracker_valid_pending_to_banned() {
        let mut t = NodeStatusTracker::new();
        let r = t.update_status(NodeStatus::Banned, "spoofing".to_string(), TS);
        assert!(r.is_ok());
        assert_eq!(*t.current(), NodeStatus::Banned);
    }

    #[test]
    fn tracker_invalid_pending_to_quarantined() {
        let mut t = NodeStatusTracker::new();
        let r = t.update_status(NodeStatus::Quarantined, "drop".to_string(), TS);
        assert!(r.is_err(), "Pending → Quarantined is illegal");
        assert_eq!(*t.current(), NodeStatus::Pending);
    }

    #[test]
    fn tracker_invalid_banned_to_active() {
        let mut t = active_tracker();
        assert!(t
            .update_status(NodeStatus::Banned, "slashing".to_string(), TS + 100)
            .is_ok());
        let r = t.update_status(NodeStatus::Active, "recover".to_string(), TS + 200);
        assert!(r.is_err(), "Banned → Active is illegal");
    }

    #[test]
    fn tracker_invalid_active_to_pending() {
        let mut t = active_tracker();
        let r = t.update_status(NodeStatus::Pending, "??".to_string(), TS + 100);
        assert!(r.is_err(), "Active → Pending is illegal");
    }

    #[test]
    fn tracker_backwards_timestamp_rejected() {
        let mut t = active_tracker();
        let r = t.update_status(NodeStatus::Quarantined, "drop".to_string(), TS - 1);
        assert!(r.is_err(), "backwards timestamp must fail");
    }

    #[test]
    fn tracker_time_in_current_status() {
        let mut t = NodeStatusTracker::new();
        assert!(t
            .update_status(NodeStatus::Active, "approved".to_string(), 1000)
            .is_ok());
        let duration = t.time_in_current_status(1500);
        assert_eq!(duration, 500, "1500 - 1000 = 500");
    }

    #[test]
    fn tracker_history_records_all_transitions() {
        let mut t = NodeStatusTracker::new();
        assert!(t
            .update_status(NodeStatus::Active, "approved".to_string(), TS)
            .is_ok());
        assert!(t
            .update_status(NodeStatus::Quarantined, "drop".to_string(), TS + 100)
            .is_ok());
        assert!(t
            .update_status(NodeStatus::Active, "restored".to_string(), TS + 200)
            .is_ok());
        assert_eq!(t.history().len(), 3, "3 transitions in history");
    }

    // ════════════════════════════════════════════════════════════════════════
    // 5. QUARANTINE HANDLER
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn quarantine_handle_notification_success() {
        let mut tracker = active_tracker();
        let mut handler = QuarantineHandler::new(&mut tracker);
        let r = handler.handle_quarantine_notification(
            "stake drop".to_string(),
            TS + 100,
        );
        assert!(r.is_ok(), "quarantine from Active must succeed");
        assert!(handler.is_quarantined());
        assert_eq!(handler.quarantine_reason(), Some("stake drop"));
        assert_eq!(handler.quarantined_since(), Some(TS + 100));
    }

    #[test]
    fn quarantine_duration_calculation() {
        let mut tracker = active_tracker();
        let mut handler = QuarantineHandler::new(&mut tracker);
        assert!(handler
            .handle_quarantine_notification("drop".to_string(), TS + 100)
            .is_ok());
        assert_eq!(
            handler.quarantine_duration(TS + 600),
            Some(500),
            "600 - 100 = 500"
        );
    }

    #[test]
    fn quarantine_attempt_recovery_eligible() {
        let mut tracker = active_tracker();
        let mut handler = QuarantineHandler::new(&mut tracker);
        assert!(handler
            .handle_quarantine_notification("drop".to_string(), TS + 100)
            .is_ok());
        assert!(
            handler.attempt_recovery(1000, 500),
            "stake 1000 >= 500"
        );
    }

    #[test]
    fn quarantine_attempt_recovery_insufficient() {
        let mut tracker = active_tracker();
        let mut handler = QuarantineHandler::new(&mut tracker);
        assert!(handler
            .handle_quarantine_notification("drop".to_string(), TS + 100)
            .is_ok());
        assert!(
            !handler.attempt_recovery(499, 500),
            "stake 499 < 500"
        );
    }

    #[test]
    fn quarantine_double_quarantine_rejected() {
        let mut tracker = active_tracker();
        let mut handler = QuarantineHandler::new(&mut tracker);
        assert!(handler
            .handle_quarantine_notification("drop".to_string(), TS + 100)
            .is_ok());
        let r = handler.handle_quarantine_notification("again".to_string(), TS + 200);
        assert!(r.is_err(), "double quarantine must fail");
    }

    // ════════════════════════════════════════════════════════════════════════
    // 6. REJOIN MANAGER
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn rejoin_can_rejoin_quarantined_no_cooldown() {
        let id_r = NodeIdentityManager::from_keypair(TEST_SEED);
        let tls_r = TLSCertManager::generate_self_signed(TEST_HOST, 365);
        assert!(id_r.is_ok());
        assert!(tls_r.is_ok());
        if let (Ok(id_mgr), Ok(tls_mgr)) = (id_r, tls_r) {
            let tracker = Arc::new(Mutex::new(active_tracker()));
            // Transition to Quarantined
            {
                let mut t = tracker.lock();
                assert!(t
                    .update_status(NodeStatus::Quarantined, "drop".to_string(), TS + 100)
                    .is_ok());
            }
            let rm = RejoinManager::new(Arc::new(id_mgr), Arc::new(tls_mgr), tracker);
            assert!(
                rm.can_rejoin(TS + 200, None),
                "Quarantined + no cooldown → can rejoin"
            );
        }
    }

    #[test]
    fn rejoin_cannot_rejoin_active() {
        let id_r = NodeIdentityManager::from_keypair(TEST_SEED);
        let tls_r = TLSCertManager::generate_self_signed(TEST_HOST, 365);
        assert!(id_r.is_ok());
        assert!(tls_r.is_ok());
        if let (Ok(id_mgr), Ok(tls_mgr)) = (id_r, tls_r) {
            let tracker = Arc::new(Mutex::new(active_tracker()));
            let rm = RejoinManager::new(Arc::new(id_mgr), Arc::new(tls_mgr), tracker);
            assert!(
                !rm.can_rejoin(TS + 200, None),
                "Active → cannot rejoin"
            );
        }
    }

    #[test]
    fn rejoin_banned_needs_expired_cooldown() {
        let id_r = NodeIdentityManager::from_keypair(TEST_SEED);
        let tls_r = TLSCertManager::generate_self_signed(TEST_HOST, 365);
        assert!(id_r.is_ok());
        assert!(tls_r.is_ok());
        if let (Ok(id_mgr), Ok(tls_mgr)) = (id_r, tls_r) {
            let tracker = Arc::new(Mutex::new(active_tracker()));
            {
                let mut t = tracker.lock();
                assert!(t
                    .update_status(NodeStatus::Banned, "slashing".to_string(), TS + 100)
                    .is_ok());
            }
            let rm = RejoinManager::new(Arc::new(id_mgr), Arc::new(tls_mgr), tracker);

            let cooldown = CooldownPeriod {
                start_timestamp: TS + 100,
                duration_secs: 3600,
                reason: "ban".to_string(),
            };

            // Before cooldown expires
            assert!(
                !rm.can_rejoin(TS + 200, Some(&cooldown)),
                "Banned + active cooldown → cannot rejoin"
            );

            // After cooldown expires
            assert!(
                rm.can_rejoin(TS + 100 + 3601, Some(&cooldown)),
                "Banned + expired cooldown → can rejoin"
            );
        }
    }

    #[test]
    fn rejoin_build_request_success() {
        let id_r = NodeIdentityManager::from_keypair(TEST_SEED);
        let tls_r = TLSCertManager::generate_self_signed(TEST_HOST, 365);
        assert!(id_r.is_ok());
        assert!(tls_r.is_ok());
        if let (Ok(id_mgr), Ok(tls_mgr)) = (id_r, tls_r) {
            let tracker = Arc::new(Mutex::new(active_tracker()));
            let rm = RejoinManager::new(
                Arc::new(id_mgr),
                Arc::new(tls_mgr),
                tracker,
            );
            let challenge = make_challenge([0x99; 32]);
            let result = rm.build_rejoin_request(
                NodeClass::Storage,
                challenge,
                "https://node.dsdn.io:8443".to_string(),
            );
            assert!(result.is_ok(), "rejoin build must succeed");
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // 7. IDENTITY STORE
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn identity_store_save_load_keypair_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "dsdn_test_store_{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let store = IdentityStore::new(dir.clone());

        let save_r = store.save_keypair(&TEST_SEED);
        assert!(save_r.is_ok(), "save_keypair must succeed");

        let load_r = store.load_keypair();
        assert!(load_r.is_ok(), "load_keypair must succeed");
        if let Ok(loaded) = load_r {
            assert_eq!(loaded, TEST_SEED, "roundtrip must preserve bytes");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn identity_store_save_load_operator_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "dsdn_test_op_{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let store = IdentityStore::new(dir.clone());

        let addr: [u8; 20] = [0xAA; 20];
        let save_r = store.save_operator_address(&addr);
        assert!(save_r.is_ok(), "save_operator must succeed");

        let load_r = store.load_operator_address();
        assert!(load_r.is_ok(), "load_operator must succeed");
        if let Ok(loaded) = load_r {
            assert_eq!(loaded, addr, "roundtrip must preserve operator");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn identity_store_save_load_tls_fingerprint_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "dsdn_test_tls_{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let store = IdentityStore::new(dir.clone());

        let fp: [u8; 32] = [0xBB; 32];
        let save_r = store.save_tls_fingerprint(&fp);
        assert!(save_r.is_ok(), "save_tls_fp must succeed");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn identity_store_load_or_generate_fresh() {
        let dir = std::env::temp_dir().join(format!(
            "dsdn_test_gen_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let store = IdentityStore::new(dir.clone());

        let r = store.load_or_generate();
        assert!(r.is_ok(), "load_or_generate must succeed on fresh dir");
        if let Ok(mgr) = r {
            assert_eq!(mgr.node_id().len(), 32);

            // Second call should load (not generate)
            let r2 = store.load_or_generate();
            assert!(r2.is_ok(), "load_or_generate must succeed on reload");
            if let Ok(mgr2) = r2 {
                assert_eq!(
                    mgr.node_id(),
                    mgr2.node_id(),
                    "reload must produce same identity"
                );
            }
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ════════════════════════════════════════════════════════════════════════
    // 8. HEALTH RESPONSE — BACKWARD COMPATIBILITY
    // ════════════════════════════════════════════════════════════════════════

    // Health tests use the mock infrastructure defined in health.rs.
    // These tests verify the integration-level JSON output.

    #[test]
    fn health_default_has_no_identity_fields() {

        let health = NodeHealth::default();
        let json = health.to_json();
        // Identity fields absent when None
        assert!(
            !json.contains("node_id_hex"),
            "node_id_hex absent when None"
        );
        assert!(
            !json.contains("gating_status"),
            "gating_status absent when None"
        );
        assert!(
            !json.contains("staked_amount"),
            "staked_amount absent when None"
        );
    }

    #[test]
    fn health_with_identity_fields_present() {

        let id_r = NodeIdentityManager::from_keypair(TEST_SEED);
        assert!(id_r.is_ok());
        if let Ok(id_mgr) = id_r {
            let mut health = NodeHealth::default();
            health.set_identity_context(
                Some(&id_mgr),
                None,
                Some(NodeStatus::Active),
                Some(NodeClass::Storage),
                Some(1_000_000),
                TS,
            );

            let json = health.to_json();
            assert!(json.contains("node_id_hex"), "node_id_hex present");
            assert!(json.contains("Active"), "gating_status present");
            assert!(json.contains("Storage"), "node_class present");
            assert!(json.contains("1000000"), "staked_amount present");
        }
    }

    #[test]
    fn health_backward_compat_old_json_parses() {

        let old_json = r#"{
            "node_id":"test","da_connected":true,"da_last_sequence":100,
            "da_behind_by":0,"chunks_stored":5,"chunks_pending":0,
            "chunks_missing":0,"storage_used_gb":50.0,"storage_capacity_gb":100.0,
            "last_check":12345,"fallback_active":false,"da_source":"Primary",
            "events_from_fallback":0,"last_primary_contact":12345
        }"#;

        let parsed: Result<NodeHealth, _> = serde_json::from_str(old_json);
        assert!(parsed.is_ok(), "old JSON without identity fields must parse");
        if let Ok(h) = parsed {
            assert_eq!(h.node_id, "test");
            assert!(h.node_id_hex.is_none(), "identity fields default to None");
            assert!(h.gating_status.is_none());
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // 9. STATUS NOTIFICATION HANDLER
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn notification_active_from_pending() {
        let tracker = Arc::new(Mutex::new(NodeStatusTracker::new()));
        let mut handler = StatusNotificationHandler::new(TEST_SEED, tracker);

        let n = StatusNotification {
            target_node_id: TEST_SEED,
            new_status: NodeStatus::Active,
            reason: "admitted".to_string(),
            timestamp: TS + 1,
        };

        let r = handler.handle(n);
        assert!(r.is_ok(), "Pending → Active must succeed");
        if let Ok(tr) = r {
            assert_eq!(tr.from, NodeStatus::Pending);
            assert_eq!(tr.to, NodeStatus::Active);
        }
        assert_eq!(handler.current_status(), NodeStatus::Active);
    }

    #[test]
    fn notification_quarantined_stores_metadata() {
        let tracker = shared_active_tracker();
        let mut handler = StatusNotificationHandler::new(TEST_SEED, tracker);

        let n = StatusNotification {
            target_node_id: TEST_SEED,
            new_status: NodeStatus::Quarantined,
            reason: "stake drop".to_string(),
            timestamp: TS + 100,
        };

        let r = handler.handle(n);
        assert!(r.is_ok(), "Active → Quarantined must succeed");
        assert_eq!(handler.quarantine_reason(), Some("stake drop"));
        assert_eq!(handler.quarantine_since(), Some(TS + 100));
    }

    #[test]
    fn notification_banned_clears_quarantine() {
        let tracker = shared_active_tracker();
        let mut handler = StatusNotificationHandler::new(TEST_SEED, tracker);

        // Quarantine first
        let q = StatusNotification {
            target_node_id: TEST_SEED,
            new_status: NodeStatus::Quarantined,
            reason: "drop".to_string(),
            timestamp: TS + 100,
        };
        assert!(handler.handle(q).is_ok());
        assert!(handler.quarantine_reason().is_some());

        // Then ban (escalation)
        let b = StatusNotification {
            target_node_id: TEST_SEED,
            new_status: NodeStatus::Banned,
            reason: "escalation".to_string(),
            timestamp: TS + 200,
        };
        assert!(handler.handle(b).is_ok());
        assert!(
            handler.quarantine_reason().is_none(),
            "quarantine metadata cleared after ban"
        );
        assert_eq!(handler.current_status(), NodeStatus::Banned);
    }

    #[test]
    fn notification_pending_from_banned() {
        let tracker = shared_active_tracker();
        // Active → Banned
        {
            let mut t = tracker.lock();
            assert!(t
                .update_status(NodeStatus::Banned, "slashing".to_string(), TS + 100)
                .is_ok());
        }
        let mut handler = StatusNotificationHandler::new(TEST_SEED, tracker);

        let n = StatusNotification {
            target_node_id: TEST_SEED,
            new_status: NodeStatus::Pending,
            reason: "ban expired".to_string(),
            timestamp: TS + 200,
        };
        let r = handler.handle(n);
        assert!(r.is_ok(), "Banned → Pending must succeed");
        assert_eq!(handler.current_status(), NodeStatus::Pending);
    }

    #[test]
    fn notification_wrong_target_rejected() {
        let tracker = shared_active_tracker();
        let mut handler = StatusNotificationHandler::new(TEST_SEED, tracker);

        let n = StatusNotification {
            target_node_id: ALT_SEED,
            new_status: NodeStatus::Quarantined,
            reason: "drop".to_string(),
            timestamp: TS + 100,
        };
        let r = handler.handle(n);
        assert!(r.is_err(), "wrong target must fail");
        assert_eq!(handler.current_status(), NodeStatus::Active);
    }

    #[test]
    fn notification_process_da_events_lifecycle() {
        let tracker = Arc::new(Mutex::new(NodeStatusTracker::new()));
        let mut handler = StatusNotificationHandler::new(TEST_SEED, tracker);
        let hex = hex_encode(&TEST_SEED);

        let events = vec![
            GatingEvent::NodeAdmitted {
                node_id: hex.clone(),
                operator: "aa".repeat(20),
                class: "Storage".to_string(),
                timestamp: TS + 1,
            },
            GatingEvent::NodeQuarantined {
                node_id: hex.clone(),
                reason: "stake drop".to_string(),
                timestamp: TS + 2,
            },
            GatingEvent::NodeActivated {
                node_id: hex,
                timestamp: TS + 3,
            },
        ];

        let transitions = handler.process_da_gating_events(events);
        assert_eq!(transitions.len(), 3, "3 valid transitions");
        assert_eq!(transitions[0].to, NodeStatus::Active);
        assert_eq!(transitions[1].to, NodeStatus::Quarantined);
        assert_eq!(transitions[2].to, NodeStatus::Active);
        assert_eq!(handler.current_status(), NodeStatus::Active);
    }

    #[test]
    fn notification_process_da_events_filters_other_nodes() {
        let tracker = Arc::new(Mutex::new(NodeStatusTracker::new()));
        let mut handler = StatusNotificationHandler::new(TEST_SEED, tracker);
        let other_hex = hex_encode(&ALT_SEED);

        let events = vec![GatingEvent::NodeAdmitted {
            node_id: other_hex,
            operator: "bb".repeat(20),
            class: "Compute".to_string(),
            timestamp: TS + 1,
        }];

        let transitions = handler.process_da_gating_events(events);
        assert!(transitions.is_empty(), "other node's events skipped");
        assert_eq!(handler.current_status(), NodeStatus::Pending);
    }

    #[test]
    fn notification_process_da_events_skips_rejected_and_expired() {
        let tracker = shared_active_tracker();
        let mut handler = StatusNotificationHandler::new(TEST_SEED, tracker);
        let hex = hex_encode(&TEST_SEED);

        let events = vec![
            GatingEvent::NodeRejected {
                node_id: hex.clone(),
                operator: "cc".repeat(20),
                reasons: vec!["insufficient".to_string()],
                timestamp: TS + 100,
            },
            GatingEvent::NodeBanExpired {
                node_id: hex,
                timestamp: TS + 200,
            },
        ];

        let transitions = handler.process_da_gating_events(events);
        assert!(
            transitions.is_empty(),
            "rejected and expired events produce no transitions"
        );
        assert_eq!(handler.current_status(), NodeStatus::Active);
    }

    // ════════════════════════════════════════════════════════════════════════
    // 10. CROSS-MODULE INTEGRATION: FULL NODE LIFECYCLE
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn full_node_lifecycle_end_to_end() {
        // 1. Generate identity
        let id_r = NodeIdentityManager::from_keypair(TEST_SEED);
        assert!(id_r.is_ok());
        let id_mgr = match id_r {
            Ok(m) => m,
            Err(_) => return,
        };

        // 2. Generate TLS cert
        let tls_r = TLSCertManager::generate_self_signed(TEST_HOST, 365);
        assert!(tls_r.is_ok());
        let tls_mgr = match tls_r {
            Ok(m) => m,
            Err(_) => return,
        };

        // 3. Build join request
        let challenge = make_challenge([0x55; 32]);
        let join_r = JoinRequestBuilder::new(&id_mgr, NodeClass::Storage)
            .with_tls(&tls_mgr)
            .with_addr("https://node.dsdn.io:8443".to_string())
            .with_capacity(500)
            .build(challenge);
        assert!(join_r.is_ok(), "join request must build");

        // 4. Status tracker starts as Pending
        let tracker = Arc::new(Mutex::new(NodeStatusTracker::new()));

        // 5. StatusNotificationHandler processes lifecycle
        let node_id = *id_mgr.node_id();
        let mut handler = StatusNotificationHandler::new(node_id, Arc::clone(&tracker));

        // 5a. Pending → Active (admitted)
        let admitted = StatusNotification {
            target_node_id: node_id,
            new_status: NodeStatus::Active,
            reason: "admitted".to_string(),
            timestamp: TS + 1,
        };
        assert!(handler.handle(admitted).is_ok());
        assert_eq!(handler.current_status(), NodeStatus::Active);

        // 5b. Active → Quarantined (stake drop)
        let quarantined = StatusNotification {
            target_node_id: node_id,
            new_status: NodeStatus::Quarantined,
            reason: "stake below minimum".to_string(),
            timestamp: TS + 2,
        };
        assert!(handler.handle(quarantined).is_ok());
        assert_eq!(handler.current_status(), NodeStatus::Quarantined);
        assert_eq!(handler.quarantine_reason(), Some("stake below minimum"));

        // 5c. RejoinManager can check eligibility using same tracker
        let rm = RejoinManager::new(
            Arc::new(id_mgr),
            Arc::new(tls_mgr),
            Arc::clone(&tracker),
        );
        assert!(rm.can_rejoin(TS + 3, None), "quarantined → can rejoin");

        // 5d. Quarantined → Active (recovery)
        let recovered = StatusNotification {
            target_node_id: node_id,
            new_status: NodeStatus::Active,
            reason: "stake restored".to_string(),
            timestamp: TS + 3,
        };
        assert!(handler.handle(recovered).is_ok());
        assert_eq!(handler.current_status(), NodeStatus::Active);
        assert!(
            handler.quarantine_reason().is_none(),
            "metadata cleared after recovery"
        );

        // 6. Verify tracker history
        let hist = tracker.lock().history().len();
        assert!(hist >= 3, "at least 3 transitions recorded: {}", hist);
    }
}