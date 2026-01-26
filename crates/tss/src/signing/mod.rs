//! # Signing Module
//!
//! Module ini menyediakan types dan state machine untuk FROST threshold signing.
//!
//! ## Komponen
//!
//! - `SigningState`: State machine untuk signing lifecycle
//! - `SigningSession`: Session controller untuk mengelola signing process
//! - `PartialSignature`: Partial signature dari satu signer
//! - `AggregateSignature`: Aggregate signature hasil FROST
//! - `SigningCommitmentExt`: Extension trait untuk SigningCommitment
//!
//! ## Alur Protocol
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                        FROST Signing Protocol                                │
//! └─────────────────────────────────────────────────────────────────────────────┘
//!
//!   Phase 1: Commitment Collection
//!   ──────────────────────────────
//!   1. Coordinator creates SigningSession dengan message dan signer list
//!   2. Signers generate nonce pairs (hiding, binding) dan send commitments
//!   3. Coordinator collects commitments sampai threshold terpenuhi
//!   4. finalize_commitments() transitions to SigningPhase
//!
//!   Phase 2: Partial Signature Collection
//!   ────────────────────────────────────
//!   1. Coordinator broadcasts all commitments ke signers
//!   2. Signers compute dan send partial signatures
//!   3. Coordinator collects partial signatures sampai threshold terpenuhi
//!   4. Coordinator aggregates partial signatures
//!
//!   Phase 3: Completion
//!   ──────────────────
//!   1. complete() dengan aggregate signature
//!   2. Session transitions ke Completed state
//! ```
//!
//! ## Contoh Penggunaan
//!
//! ```rust
//! use dsdn_tss::signing::{SigningSession, SigningState};
//! use dsdn_tss::{SessionId, SignerId};
//!
//! // Create session
//! let session_id = SessionId::new();
//! let signers = vec![SignerId::new(), SignerId::new(), SignerId::new()];
//! let message = b"message to sign".to_vec();
//!
//! let session = SigningSession::new(session_id, message, signers, 2);
//! assert!(session.is_ok());
//! ```

pub mod commitment;
pub mod partial;
pub mod session;
pub mod state;

pub use commitment::SigningCommitmentExt;
pub use partial::{
    compute_binding_factor, compute_challenge, compute_group_commitment, PartialSignature,
};
pub use session::SigningSession;
pub use state::SigningState;

// Re-export SigningCommitment dari primitives untuk kemudahan
pub use crate::primitives::SigningCommitment;

use crate::primitives::FrostSignature;

// ════════════════════════════════════════════════════════════════════════════════
// AGGREGATE SIGNATURE
// ════════════════════════════════════════════════════════════════════════════════

/// Aggregate signature hasil FROST threshold signing.
///
/// `AggregateSignature` adalah hasil akhir dari proses signing
/// setelah partial signatures di-aggregate.
///
/// ## Format
///
/// Sama dengan `FrostSignature`: (R || s) = 64 bytes.
#[derive(Debug, Clone)]
pub struct AggregateSignature {
    /// Inner FROST signature.
    signature: FrostSignature,
}

impl AggregateSignature {
    /// Membuat `AggregateSignature` dari `FrostSignature`.
    #[must_use]
    pub fn new(signature: FrostSignature) -> Self {
        Self { signature }
    }

    /// Mengembalikan reference ke inner signature.
    #[must_use]
    pub fn signature(&self) -> &FrostSignature {
        &self.signature
    }

    /// Mengembalikan signature bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 64] {
        self.signature.as_bytes()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::FrostSignatureShare;
    use crate::types::SignerId;

    #[test]
    fn test_partial_signature_new() {
        let signer_id = SignerId::from_bytes([0xAA; 32]);
        let share = FrostSignatureShare::from_bytes([0x01; 32]).unwrap();
        let commitment = SigningCommitment::from_parts([0x02; 32], [0x03; 32]).unwrap();
        let partial = PartialSignature::new(signer_id.clone(), share, commitment);

        assert_eq!(partial.signer_id(), &signer_id);
    }

    #[test]
    fn test_aggregate_signature_new() {
        let sig = FrostSignature::from_bytes([0x01; 64]).unwrap();
        let aggregate = AggregateSignature::new(sig.clone());

        assert_eq!(aggregate.as_bytes(), sig.as_bytes());
    }

    #[test]
    fn test_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PartialSignature>();
        assert_send_sync::<AggregateSignature>();
    }
}